//! tests for komodo notarisation code

use std::ops::Range;
use std::sync::Arc;
use hex::FromHex;

use zebra_chain::serialization::ZcashDeserializeInto;
use zebra_chain::block::{self, Block, Height};

use zebra_chain::parameters::Network::Testnet;
use zebra_chain::transparent::OutPoint;
use zebra_chain::amount::Amount;

use crate::{Config, CommitBlockError, PreparedBlock};
use crate::service::StateService;
use crate::{ValidateContextError, FinalizedBlock};
use crate::arbitrary::Prepare;

const CHAIN_A_BLOCK_HASH_WITH_NOTA: &str = "00e5a0b985d58cd3be4c6b580f30de57d041a56589d61e98b85a0fe20f76383f";
const CHAIN_A_BLOCK_HASH_TO_FAIL: &str = "009b7faa4fffb879db787dec6acafe02767297158a867361ad82a699c6c8839c";
const NON_NOTARY_P2PK: &str = "2102c50c23b6578f6a688f9868efca41bddd33b4225583474bb6183ff3ddf593ae01ac";

struct SampleChain<'a> {
    pub genesis: &'a str, 
    pub node_1: &'a str, 
    pub node_2: &'a str, 
    pub fork: usize,    // not including genesis
    pub tip_1: usize,
    pub tip_2: usize,
}

const SAMPLE_CHAIN_A: SampleChain<'static> = SampleChain { 
    genesis: include_str!("./testnet_a_genesis.hex"), 
    node_1: include_str!("./testnet_a_node_1.hex"),
    node_2: include_str!("./testnet_a_node_2.hex"), // branch with the nota
    fork:  127, 
    tip_1: 136,
    tip_2: 140,
};

const SAMPLE_CHAIN_B: SampleChain<'static> = SampleChain { 
    genesis: include_str!("./testnet_b_genesis.hex"), 
    node_1: include_str!("./testnet_b_node_2.hex"), // no nota in this branch
    node_2: include_str!("./testnet_b_node_1.hex"), // branch with the extra nota
    fork:  128,
    tip_1: 139,
    tip_2: 140,
};

/// Contextual validation tests helper to load test blocks and modify them if needed
/// it also calls result checker to assert or continue block loading (for non finalised part from ht=127)
/// For testing blocks transactions can be modified before committing as contextual validation does net check merkle root
fn komodo_load_testnet_both_branches<M, C>(chain_desc: SampleChain, modify_block: M, check_commit_result: C)
    where 
        M: Fn(&mut Block),
        C: Fn(&PreparedBlock, &Result<(), CommitBlockError>)->bool,  // continue if true
{
   
    let (mut state, _, _, _) = StateService::new(Config::ephemeral(), Testnet);

    let genesis_bin = Vec::from_hex(chain_desc.genesis.trim()).expect("invalid genesis hex");
    let genesis = genesis_bin.zcash_deserialize_into::<Arc<Block>>()
        .expect("block should deserialize");
    let genesis_fin = FinalizedBlock::from(genesis);
    state
        .disk
        .commit_finalized_direct(genesis_fin.clone(), "test")
        .expect("unexpected invalid genesis block test vector");

    let blocks_node1_hex = chain_desc.node_1.split("\n").collect::<Vec<_>>();

    
    let finalized = chain_desc.fork - 1; // add some blocks below the fork to finalized 
    let remained_1 = chain_desc.tip_1 - finalized; // how many to add after finalized (minus genesis) 
    let remained_2 = chain_desc.tip_2 - chain_desc.fork; // how many to add after fork (minus genesis)
    for block_hex in blocks_node1_hex.iter().take(finalized)   {   // one off is genesis
        if block_hex.trim().is_empty() { break; }
        let block_bin = Vec::from_hex(block_hex.trim()).expect("invalid block hex");
        let block = block_bin.zcash_deserialize_into::<Block>().expect("could not deserialise block");

        let block_fin = FinalizedBlock::from(Arc::new(block));
        let commit_result = state.disk.commit_finalized_direct(block_fin.clone(), "test");
        assert!(commit_result.is_ok());
    }

    // fork is othe last common block for both branches
    // load remaining part of the second branch with the nota from the block after finalized to 136 to memory
    for block_hex in blocks_node1_hex.iter().skip(finalized).take(remained_1)   {     // load 136 blocks, less than blocks num in the second branch
        if block_hex.trim().is_empty() { break; }
        let block_bin = Vec::from_hex(block_hex.trim()).expect("invalid block hex");
        let mut block = block_bin.zcash_deserialize_into::<Block>().expect("could not deserialise block");

        modify_block(&mut block);   // allow to change block for different test cases
        let block = Arc::new(block);
        let block_prepared = block.prepare();

        let commit_result = state.validate_and_commit(block_prepared.clone());
        if !check_commit_result(&block_prepared, &commit_result) { break; }  // check results
    }

    let blocks_node2_hex = chain_desc.node_2.split("\n").collect::<Vec<_>>();

    // load second branch from the block after fork to tip_2
    for block_hex in blocks_node2_hex.iter().skip(chain_desc.fork).take(remained_2)   {     // start a branch from block 128
        if block_hex.trim().is_empty() { break; }
        let block_bin = Vec::from_hex(block_hex.trim()).expect("invalid block hex");
        let mut block = block_bin.zcash_deserialize_into::<Block>().expect("could not deserialise block");

        modify_block(&mut block);
        let block = Arc::new(block);
        let block_prepared = block.prepare();

        let commit_result = state.validate_and_commit(block_prepared.clone());
        if !check_commit_result(&block_prepared, &commit_result) { break; }  // check results
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
fn komodo_reject_fork_from_below_last_notarised_height() {
    let _init_guard = zebra_test::init();

    // test invalid fork from ht < ntz_ht 
    komodo_load_testnet_both_branches(
        SAMPLE_CHAIN_A,
        |_| {}, 
        |prepared, commit_result| {
            // forked chain must become invalid at height 137 (where it becomes the best chain)
            let bad_block_hash = block::Hash::from_hex(CHAIN_A_BLOCK_HASH_TO_FAIL).expect("valid hex");
            if prepared.hash == bad_block_hash {
                assert_eq!( 
                    *commit_result, 
                    Err(
                        ValidateContextError::KomodoInvalidNotarisedChain(
                            bad_block_hash, Height(127), Height(128)
                        )
                        .into()
                    ) 
                );
                return false; // end of test
            } 
            return true;
        }
    );
}

/// komodo test nota validation
#[test]
fn komodo_valid_fork_from_below_last_notarised_height() {
    let _init_guard = zebra_test::init();

    // test invalid fork from ht < ntz_ht 
    komodo_load_testnet_both_branches(
        SAMPLE_CHAIN_B,
        |_| {}, 
        |_prepared, commit_result| {
            if commit_result.is_err()   {
                println!("commit_result1={}", commit_result.as_ref().unwrap_err());
                //println!("commit_result2={:?}", commit_result.as_ref().unwrap_err());
            }
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
            if block.hash() == block::Hash::from_hex(CHAIN_A_BLOCK_HASH_WITH_NOTA).expect("valid hex") {
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

/// test if signed notaries number reduced for the min ratify number 
#[test]
fn komodo_min_notary_inputs() {
    let _init_guard = zebra_test::init();
    komodo_load_testnet_both_branches(
        SAMPLE_CHAIN_A,
        |block|{ 
            if block.hash() == block::Hash::from_hex(CHAIN_A_BLOCK_HASH_WITH_NOTA).expect("valid hex") {
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
            // still have nota in the chain
            // forked chain must become invalid at height 137
            let bad_block_hash = block::Hash::from_hex(CHAIN_A_BLOCK_HASH_TO_FAIL).expect("valid hex");
            if prepared.hash == bad_block_hash {
                assert_eq!( 
                    *commit_result, 
                    Err(
                        ValidateContextError::KomodoInvalidNotarisedChain(
                            bad_block_hash, Height(127), Height(128)
                        )
                        .into()
                    ) 
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
#[test]
fn komodo_not_notary_inputs() {
    let _init_guard = zebra_test::init();
    //let lock_script = <Vec<u8>>::from_hex(NON_NOTARY_P2PK).expect("valid hex");
    komodo_load_testnet_both_branches(
        SAMPLE_CHAIN_A,
        |block|{ 
            if block.hash() == block::Hash::from_hex(CHAIN_A_BLOCK_HASH_WITH_NOTA).expect("valid hex") {
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
