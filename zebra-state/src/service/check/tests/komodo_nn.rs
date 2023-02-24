//! tests for komodo notarisation code

use std::ops::Range;
use std::sync::Arc;
use hex::FromHex;

use zebra_chain::serialization::ZcashDeserializeInto;
use zebra_chain::block::{self, Block};

use zebra_chain::parameters::Network::Testnet;
use zebra_chain::transparent::OutPoint;
use zebra_chain::amount::Amount;

use crate::{Config, CommitBlockError, PreparedBlock};
use crate::service::StateService;
use crate::{ValidateContextError, FinalizedBlock};
use crate::arbitrary::Prepare;
use lazy_static::lazy_static;

/// pubkey which is a not a test notary
const NON_NOTARY_P2PK: &str = "2102c50c23b6578f6a688f9868efca41bddd33b4225583474bb6183ff3ddf593ae01ac";

struct SampleChain<'a> {
    pub genesis: &'a str, 
    pub node_1: &'a str, 
    pub node_2: &'a str, 
    pub finalized: usize,   // last height stored in the finalized state
    pub fork: usize,        // fork ht
    pub branch_1: &'a [usize],  // heights to load in branch 1
    pub branch_2: &'a [usize],  // heights to load in branch 2
}

const SAMPLE_CHAIN_A: SampleChain<'static> = SampleChain { 
    genesis: include_str!("./testnet_a_genesis.hex"), 
    // no nota before fork
    node_1: include_str!("./testnet_a_node_1.hex"),
    node_2: include_str!("./testnet_a_node_2.hex"), // branch with the nota at ht=136, last notarised ht=134
    finalized: 126,
    fork:  127, 
    branch_1: &[136], // stop heights in branch_1
    branch_2: &[140], // stop heights in branch_2
};

lazy_static! {
    static ref CHAIN_A_BLOCK_HASH_WITH_NOTA: block::Hash = block::Hash::from_hex("00e5a0b985d58cd3be4c6b580f30de57d041a56589d61e98b85a0fe20f76383f").expect("valid hex");
    static ref CHAIN_A_BLOCK_HASH_TO_FAIL: block::Hash = block::Hash::from_hex("009b7faa4fffb879db787dec6acafe02767297158a867361ad82a699c6c8839c").expect("valid hex");
    static ref CHAIN_A_EXPECTED_FORK_HT: block::Height = block::Height(127);
    static ref CHAIN_A_EXPECTED_LAST_NTZ_HT: block::Height = block::Height(128);
}

const SAMPLE_CHAIN_B: SampleChain<'static> = SampleChain { 
    genesis: include_str!("./testnet_b_genesis.hex"), 
    // first nota at ht=127, last notarised ht=126
    node_1: include_str!("./testnet_b_node_2.hex"), // no nota in this branch
    node_2: include_str!("./testnet_b_node_1.hex"), // branch with the second nota at ht=136, last notarised ht=134
    finalized: 127,
    fork:  128, 
    branch_1: &[139], 
    branch_2: &[140],
};

const SAMPLE_CHAIN_C: SampleChain<'static> = SampleChain { 
    genesis: include_str!("./testnet_b_genesis.hex"), 
    // first nota at ht=127, last notarised ht=126
    node_1: include_str!("./testnet_b_node_1.hex"), // no nota in this branch
    node_2: include_str!("./testnet_b_node_2.hex"), // branch with the second nota at ht=136, last notarised ht=134
    finalized: 127,
    fork:  128, 
    branch_1: &[139],
    branch_2: &[140],
};

lazy_static! {
    static ref CHAIN_C_BLOCK_HASH_TO_FAIL: block::Hash = block::Hash::from_hex("014bbdb306f24d9303514a50478d9c6dda1e02085331a86ff03286a5de1b8623").expect("valid hex");
    static ref CHAIN_C_EXPECTED_FORK_HT: block::Height = block::Height(128);
    static ref CHAIN_C_EXPECTED_LAST_NTZ_HT: block::Height = block::Height(134);
}

const SAMPLE_CHAIN_D: SampleChain<'static> = SampleChain { 
    genesis: include_str!("./testnet_b_genesis.hex"), 
    // first nota at ht=127, last notarised ht=126
    node_1: include_str!("./testnet_b_node_2.hex"), // no nota in this branch
    node_2: include_str!("./testnet_b_node_1.hex"), // branch with the second nota at ht=136, last notarised ht=134
    finalized: 127,
    fork:  128, 
    branch_1: &[136, 137],
    branch_2: &[136],
};

lazy_static! {
    static ref CHAIN_D_BLOCK_HASH_TO_FAIL: block::Hash = block::Hash::from_hex("01544989840a5632601b8ab8e78d089c187fa09995b14060ae26f7887c10a30e").expect("valid hex");
    static ref CHAIN_D_EXPECTED_FORK_HT: block::Height = block::Height(128);
    static ref CHAIN_D_EXPECTED_LAST_NTZ_HT: block::Height = block::Height(134);
}

/// Contextual validation test helper to load and commit test blocks of a small forked chain with 2 branches
/// calls passed modifier function (for test purposes block transactions can be modified before committing as contextual validation does net check merkle root)
/// calls commit result checker to assert or continue block loading
/// chain_desc contains heights for blocks saved into the finalized state, the rest blocks go into non finalized state,
/// chain_desc also has a fork height and stop points in both branches to test various test cases in a forked chain
fn komodo_load_testnet_both_branches<M, C>(chain_desc: SampleChain, modify_block: M, check_commit_result: C)
    where 
        M: Fn(&mut Block),
        C: Fn(&PreparedBlock, &Result<(), CommitBlockError>)->bool,  // continue if true
{
    let (mut state, _, _, _) = StateService::new(Config::ephemeral(), Testnet);

    assert!(chain_desc.fork >= chain_desc.finalized);

    // load genesis
    let genesis_bin = Vec::from_hex(chain_desc.genesis.trim()).expect("invalid genesis hex");
    let genesis = genesis_bin.zcash_deserialize_into::<Arc<Block>>()
        .expect("block should deserialize");
    let genesis_fin = FinalizedBlock::from(genesis);
    state
        .disk
        .commit_finalized_direct(genesis_fin.clone(), "test")
        .expect("unexpected invalid genesis block test vector");

    let blocks_node1_hex = chain_desc.node_1.split("\n").collect::<Vec<_>>();
    let blocks_node2_hex = chain_desc.node_2.split("\n").collect::<Vec<_>>();

    let mut take_1 = chain_desc.finalized;

    // load finalized chain from node 1
    for block_hex in blocks_node1_hex.iter().take(take_1)   {   // one off is genesis
        if block_hex.trim().is_empty() { break; }
        let block_bin = Vec::from_hex(block_hex.trim()).expect("invalid block hex");
        let block = block_bin.zcash_deserialize_into::<Block>().expect("could not deserialise block");

        let block_fin = FinalizedBlock::from(Arc::new(block));
        let commit_result = state.disk.commit_finalized_direct(block_fin.clone(), "test");
        assert!(commit_result.is_ok());
    }

    // we need to call this to find latest nota in finalized blocks as simplified state loading is used
    state.komodo_init_last_nota(); 

    let mut prev_1 = chain_desc.finalized;
    take_1 = chain_desc.fork - chain_desc.finalized;

    if take_1 > 0 {
        // load shared chain part till the fork height
        for block_hex in blocks_node1_hex.iter().skip(prev_1).take(take_1)   {    
            if block_hex.trim().is_empty() { break; }
            let block_bin = Vec::from_hex(block_hex.trim()).expect("invalid block hex");
            let mut block = block_bin.zcash_deserialize_into::<Block>().expect("could not deserialise block");

            modify_block(&mut block);   // allow to change block for different test cases
            let block = Arc::new(block);
            let block_prepared = block.prepare();

            let commit_result = state.validate_and_commit(block_prepared.clone());
            if !check_commit_result(&block_prepared, &commit_result) { break; }  // check results
        }
        prev_1 = chain_desc.fork;
    }

    let mut prev_2 = prev_1; // start loading since the next block after fork

    // load branches, switching at stop points
    for i in 0..std::cmp::max(chain_desc.branch_1.len(), chain_desc.branch_2.len()) {

        // load part of the first branch
        if i < chain_desc.branch_1.len() {
            let take_1 = chain_desc.branch_1[i] - prev_1;
            // load remaining part of the second branch with the nota from the block after finalized to 136 to memory
            for block_hex in blocks_node1_hex.iter().skip(prev_1).take(take_1)   {   
                if block_hex.trim().is_empty() { break; }
                let block_bin = Vec::from_hex(block_hex.trim()).expect("invalid block hex");
                let mut block = block_bin.zcash_deserialize_into::<Block>().expect("could not deserialise block");

                modify_block(&mut block);   // allow to change block for different test cases
                let block = Arc::new(block);
                let block_prepared = block.prepare();
                // println!("loading node 1 height {}", block_prepared.height.0);  
                let commit_result = state.validate_and_commit(block_prepared.clone());
                if !check_commit_result(&block_prepared, &commit_result) { break; }  // check results
            }
            prev_1 = chain_desc.branch_1[i];
        }

        // load part of the second branch 
        if i < chain_desc.branch_2.len() {
            let take_2 = chain_desc.branch_2[i] - prev_2;

            for block_hex in blocks_node2_hex.iter().skip(prev_2).take(take_2)   {     // start a branch from block 128
                if block_hex.trim().is_empty() { break; }
                let block_bin = Vec::from_hex(block_hex.trim()).expect("invalid block hex");
                let mut block = block_bin.zcash_deserialize_into::<Block>().expect("could not deserialise block");

                modify_block(&mut block);
                let block = Arc::new(block);
                let block_prepared = block.prepare();
                // println!("loading node 2 height {}", block_prepared.height.0);  
                let commit_result = state.validate_and_commit(block_prepared.clone());
                if !check_commit_result(&block_prepared, &commit_result) { break; }  // check results
            }
            prev_2 = chain_desc.branch_2[i];
        }
    }
}

/// a helper to replace pubkeys in fake nota's inputs to a non-notary pubkey
fn replace_nota_input_pubkey(block: &mut Block, r: Range<usize>)   {
    let replace_script = <Vec<u8>>::from_hex(NON_NOTARY_P2PK).expect("valid hex");

    // clone inputs:
    let nota_inputs = block.transactions[ 2 ].inputs().into_iter().map(|i| i.clone()).collect::<Vec<_>>();

    let prev_tx = Arc::get_mut(&mut block.transactions[ 1 ]).unwrap();  // notaries' funding outputs
    let prev_tx_hash = prev_tx.hash();
    let prev_tx_outputs = prev_tx.outputs_mut();
    for i in r {
        assert!(nota_inputs[i].outpoint().unwrap().hash == prev_tx_hash, "bad nota prev tx");
        prev_tx_outputs[nota_inputs[i].outpoint().unwrap().index as usize].lock_script = zebra_chain::transparent::Script::new(&replace_script);
    }

    let prev_tx = Arc::get_mut(&mut block.transactions[ 1 ]).unwrap();  // notaries' funding outputs
    let new_prev_tx_hash = prev_tx.hash();
    let nota_inputs = Arc::get_mut(&mut block.transactions[ 2 ]).unwrap().inputs_mut();

    // Note for rust learners: do not use 'prev_tx' after 'nota_inputs' as it would be the second mutable borrow for 'block':
    // let nota_inputs = Arc::get_mut(&mut block.transactions[ 2 ]).unwrap().inputs_mut();
    // let new_prev_tx_hash = prev_tx.hash();

    for i in 0..nota_inputs.len() {
        // for rust learners:
        // we need a extra step to do immutable borrow inside this statement:
        let outpoint = nota_inputs[i].outpoint().unwrap();  
        nota_inputs[i].set_outpoint(OutPoint{hash: new_prev_tx_hash, index: outpoint.index});   // mutable borrow inside this statement 
        // So we cannot do this looking more compact: 
        // inputs[i].set_outpoint(OutPoint{hash: new_prev_tx_hash, index: inputs[i].outpoint().unwrap().index}); 
        // as it would be both mutable and immutable borrows
    }
}

/// komodo test contextual validation to reject blocks forked below the last notarised height stored in a notarisation transaction
/// use komodo testnet blocks
#[test]
fn komodo_reject_fork_from_below_last_notarised_height_1() {
    let _init_guard = zebra_test::init();

    // test invalid fork from ht < ntz_ht 
    komodo_load_testnet_both_branches(
        SAMPLE_CHAIN_A,
        |_| {}, 
        |prepared, commit_result| {
            // println!("commit_result={:?}", commit_result);
            // TODO: update this: forked chain must become invalid at height CHAIN_A_EXPECTED_FORK_HT+1
            if prepared.hash == *CHAIN_A_BLOCK_HASH_TO_FAIL {
                assert_eq!( 
                    *commit_result, 
                    Err(ValidateContextError::KomodoInvalidNotarisedChain(*CHAIN_A_BLOCK_HASH_TO_FAIL, *CHAIN_A_EXPECTED_FORK_HT, *CHAIN_A_EXPECTED_LAST_NTZ_HT).into())
                );
                return false; // end of test
            } 
            return true;
        }
    );
}

/// komodo test contextual validation to reject blocks forked below the last notarised height stored in a notarisation transaction
/// yet another case with first nota below the fork and the second nota in the node_2
#[test]
fn komodo_reject_fork_from_below_last_notarised_height_2() {
    let _init_guard = zebra_test::init();

    // test invalid fork from ht < ntz_ht 
    komodo_load_testnet_both_branches(
        SAMPLE_CHAIN_C,
        |_| {}, 
        |prepared, commit_result| {
            // println!("commit_result={:?}", commit_result);
            // TODO: update this: forked chain must become invalid at height CHAIN_A_EXPECTED_FORK_HT+1
            if prepared.hash == *CHAIN_C_BLOCK_HASH_TO_FAIL {
                assert_eq!( 
                    *commit_result, 
                    Err(ValidateContextError::KomodoInvalidNotarisedChain(*CHAIN_C_BLOCK_HASH_TO_FAIL, *CHAIN_C_EXPECTED_FORK_HT, *CHAIN_C_EXPECTED_LAST_NTZ_HT).into())
                );
                return false; // end of test
            } 
            return true;
        }
    );
}

// test that branch with no nota cannot grow more that notarised branch
#[test]
fn komodo_reject_fork_from_below_last_notarised_height_3() {
    let _init_guard = zebra_test::init();

    komodo_load_testnet_both_branches(
        SAMPLE_CHAIN_D,
        |_| {}, 
        |prepared, commit_result| {
            // println!("commit_result={:?}", commit_result);
            // TODO: forked chain must become invalid at block CHAIN_D_BLOCK_HASH_TO_FAIL
            if prepared.hash == *CHAIN_D_BLOCK_HASH_TO_FAIL {
                assert_eq!( 
                    *commit_result, 
                    Err(ValidateContextError::KomodoInvalidNotarisedChain(*CHAIN_D_BLOCK_HASH_TO_FAIL, *CHAIN_D_EXPECTED_FORK_HT, *CHAIN_D_EXPECTED_LAST_NTZ_HT).into())
                );
                return false; // end of test
            }
            return true;
        }
    );
}

/// komodo test for a valid forked branch containing a nota
#[test]
fn komodo_valid_fork_with_nota() {
    let _init_guard = zebra_test::init();

    // branch with nota is always valid 
    komodo_load_testnet_both_branches(
        SAMPLE_CHAIN_B,
        |_| {}, 
        |_prepared, commit_result| {

            assert_eq!( 
                *commit_result, 
                Ok(()) 
            );
            return true;
        }
    );
}

/// test low notary signed inputs number for the notarised transaction  
#[test]
fn komodo_too_few_notary_inputs() {
    let _init_guard = zebra_test::init();
    komodo_load_testnet_both_branches(
        SAMPLE_CHAIN_A,
        |block|{ 
            if block.hash() == *CHAIN_A_BLOCK_HASH_WITH_NOTA {
                let prev_outputs = block.transactions[1].outputs().to_owned();  // funding tx
                let inputs = Arc::get_mut(&mut block.transactions[2]).unwrap().inputs_mut();    // notarisation tx
                let mut removed_amount = Amount::zero();
                // remove inputs to make them fewer than min ratify (actually this makes no nota in the chain):
                while inputs.len() > 6 { 
                    let popped = inputs.pop().unwrap(); 
                    removed_amount = (removed_amount + prev_outputs[popped.outpoint().unwrap().index as usize].value).unwrap(); 
                } 
                let outputs = Arc::get_mut(&mut block.transactions[2]).unwrap().outputs_mut();
                outputs[0].value = (outputs[0].value() - removed_amount).unwrap(); // decrease output value for the removed inputs total
            }
        }, 
        |_prepared, commit_result| {
            // all forked chain becomes valid if no valid nota
            assert_eq!( 
                *commit_result, 
                Ok(()) 
            );
            return true;
        }
    );
}

/// test when signed notaries number reduced for the min ratify number nota is still valid
#[test]
fn komodo_min_notary_inputs() {
    let _init_guard = zebra_test::init();
    komodo_load_testnet_both_branches(
        SAMPLE_CHAIN_A,
        |block|{ 
            if block.hash() == *CHAIN_A_BLOCK_HASH_WITH_NOTA {
                let prev_outputs = block.transactions[1].outputs().to_owned();  // funding tx
                let inputs = Arc::get_mut(&mut block.transactions[2]).unwrap().inputs_mut();    // notarisation tx
                let mut removed_amount = Amount::zero();
                // remove inputs to make their number equal to min ratify:
                while inputs.len() > 7 { 
                    let popped = inputs.pop().unwrap(); 
                    removed_amount = (removed_amount + prev_outputs[popped.outpoint().unwrap().index as usize].value).unwrap(); 
                } 
                let outputs = Arc::get_mut(&mut block.transactions[2]).unwrap().outputs_mut();
                outputs[0].value = (outputs[0].value() - removed_amount).unwrap(); // decrease output value for the removed inputs total
            }
        }, 
        |prepared, commit_result| {
            // still have valid nota in the chain and error is generated
            if prepared.hash == *CHAIN_A_BLOCK_HASH_TO_FAIL {
                assert_eq!( 
                    *commit_result, 
                    Err(ValidateContextError::KomodoInvalidNotarisedChain(*CHAIN_A_BLOCK_HASH_TO_FAIL, *CHAIN_A_EXPECTED_FORK_HT, *CHAIN_A_EXPECTED_LAST_NTZ_HT).into())
                );
                return false; // end of test
            } else {
                assert_eq!( 
                    *commit_result, 
                    Ok(()) 
                );
            }
            return true;
        }
    );
}

/// test non-notary signers for the notarised transaction 
/// (then nota does not exist in the chain) 
#[test]
fn komodo_not_notary_inputs() {
    let _init_guard = zebra_test::init();
    komodo_load_testnet_both_branches(
        SAMPLE_CHAIN_A,
        |block|{ 
            if block.hash() == *CHAIN_A_BLOCK_HASH_WITH_NOTA {
                // replace pubkey in 6+ inputs to a non-notary pubkey
                replace_nota_input_pubkey(block, 6..block.transactions[2].inputs().len());
            }
        }, 
        |_prepared, commit_result| {
            // all forked blocks become valid if nota does not contain enough notary inputs
            assert_eq!( 
                *commit_result, 
                Ok(()) 
            );
            return true;
        }
    );
}
