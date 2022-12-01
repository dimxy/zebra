//! tests for komodo notarisation code

use std::sync::Arc;
use hex::FromHex;

use zebra_chain::serialization::ZcashDeserializeInto;
use zebra_chain::block::{self, Block, Height};

use zebra_chain::parameters::Network::Testnet;
use zebra_chain::transparent::OutPoint;

use crate::{Config, CommitBlockError, PreparedBlock};
use crate::service::StateService;
use crate::{ValidateContextError, FinalizedBlock};
use crate::arbitrary::Prepare;

const BLOCK_HASH_WITH_NOTA: &str = "005bfe85a4fcb35f2294e2a5482cdc8a94d21857bd7d7fba91eb4e7bdb4749f1";
const BLOCK_HASH_TO_FAIL: &str = "00d0f218547ec5b41a42b1a8937013cfb76f37cd94f2535a1203f45e94c7fce7";
const NON_NOTARY_P2PK: &str = "2102c50c23b6578f6a688f9868efca41bddd33b4225583474bb6183ff3ddf593ae01ac";

/// Contextual validation tests helper to load test blocks and modify them if needed
/// it also calls result checker to assert or continue block loading (for non finalised part from ht=127)
/// For testing blocks transactions can be modified before committing as contextual validation does net check merkle root
fn komodo_load_testnet_blocks<M, C>(modify_block: M, check_commit_result: C)
    where 
        M: Fn(&mut Block),
        C: Fn(&PreparedBlock, &Result<(), CommitBlockError>)->bool,  // continue if true
{
   
    let (mut state, _, _, _) = StateService::new(Config::ephemeral(), Testnet);

    let genesis_bin = Vec::from_hex(include_str!("./testnet-genesis.hex").trim()).expect("invalid genesis hex");
    let genesis = genesis_bin.zcash_deserialize_into::<Arc<Block>>()
        .expect("block should deserialize");
    let genesis_fin = FinalizedBlock::from(genesis);
    state
        .disk
        .commit_finalized_direct(genesis_fin.clone(), "test")
        .expect("unexpected invalid genesis block test vector");

    let blocks_node1_hex = include_str!("./testnet-node-1.hex").split("\n").collect::<Vec<_>>();

    // add valid branch to disk before one down before the notarised height
    for block_hex in blocks_node1_hex.iter().take(126)   {   
        if block_hex.trim().is_empty() { break; }
        let block_bin = Vec::from_hex(block_hex.trim()).expect("invalid block hex");
        let block = block_bin.zcash_deserialize_into::<Block>().expect("could not deserialise block");

        let block_fin = FinalizedBlock::from(Arc::new(block));
        let commit_result = state.disk.commit_finalized_direct(block_fin.clone(), "test");
        assert!(commit_result.is_ok());
    }

    // add the rest valid branch from block 127 to mem
    for block_hex in blocks_node1_hex.iter().skip(126)   {   
        if block_hex.trim().is_empty() { break; }
        let block_bin = Vec::from_hex(block_hex.trim()).expect("invalid block hex");
        let mut block = block_bin.zcash_deserialize_into::<Block>().expect("could not deserialise block");

        modify_block(&mut block);   // allow to change block for different test cases
        let block = Arc::new(block);
        let block_prepared = block.prepare();

        let commit_result = state.validate_and_commit(block_prepared.clone());
        //if commit_result.is_err() { println!("commit_result={:?}", commit_result); }
        if !check_commit_result(&block_prepared, &commit_result) { break; }  // check results
    }

    let blocks_node2_hex = include_str!("./testnet-node-2.hex").split("\n").collect::<Vec<_>>();

    // add forked branch from block 128
    for block_hex in blocks_node2_hex.iter().skip(127)   {     // start a branch from block 128
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

/// komodo test contextual validation to reject blocks forked below the last notarised height stored in a notarisation transaction
/// use komodo testnet blocks
#[test]
fn komodo_reject_fork_from_below_last_notarised_height() {
    let _init_guard = zebra_test::init();

    // test invalid fork from ht < ntz_ht 
    komodo_load_testnet_blocks(
        |_| {}, 
        |prepared, commit_result| {
            // forked chain must become invalid at height 132
            let bad_block_hash = block::Hash::from_hex(BLOCK_HASH_TO_FAIL).expect("valid hex");
            if prepared.hash == bad_block_hash {
                assert_eq!( 
                    *commit_result, 
                    Err(
                        ValidateContextError::InvalidNotarisedChain(
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

/// test low notary signed inputs number for the notarised transaction  
#[test]
fn komodo_too_few_notary_inputs() {
    let _init_guard = zebra_test::init();
    komodo_load_testnet_blocks(
        |block|{ 
            if block.hash() == block::Hash::from_hex(BLOCK_HASH_WITH_NOTA).expect("valid hex") {
                let inputs = Arc::get_mut(&mut block.transactions[2]).unwrap().inputs_mut();    // notarisation tx
                while inputs.len() > 6 { inputs.pop(); } // remove inputs to make them fewer than min ratify (actually this creates no nota in the chain)
            }
        }, 
        |_prepared, commit_result| {
            // all forked blocks are valid if no valid nota
            assert_eq!( 
                *commit_result, 
                Ok(()) 
            );
            return true;
        }
    );
}

/// test if signed notaries number reduced for the min ratify  
#[test]
fn komodo_min_notary_inputs() {
    let _init_guard = zebra_test::init();
    komodo_load_testnet_blocks(
        |block|{ 
            if block.hash() == block::Hash::from_hex(BLOCK_HASH_WITH_NOTA).expect("valid hex") {
                let inputs = Arc::get_mut(&mut block.transactions[2]).unwrap().inputs_mut();    // notarisation tx
                while inputs.len() > 7 { inputs.pop(); } // remove inputs to make them fewer than min ratify (actually this creates no nota in the chain)
            }
        }, 
        |prepared, commit_result| {
            // forked chain must become invalid at height 132
            let bad_block_hash = block::Hash::from_hex(BLOCK_HASH_TO_FAIL).expect("valid hex");
            if prepared.hash == bad_block_hash {
                assert_eq!( 
                    *commit_result, 
                    Err(
                        ValidateContextError::InvalidNotarisedChain(
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

/// test invalid signers for the notarised transaction  
#[test]
fn komodo_not_notary_inputs() {
    let _init_guard = zebra_test::init();
    let lock_script = <Vec<u8>>::from_hex(NON_NOTARY_P2PK).expect("valid hex");
    komodo_load_testnet_blocks(
        |block|{ 
            if block.hash() == block::Hash::from_hex(BLOCK_HASH_WITH_NOTA).expect("valid hex") {
                let outputs = Arc::get_mut(&mut block.transactions[1]).unwrap().outputs_mut();  // notaries' funding outputs
                for i in 7..outputs.len() {  
                    outputs[i].lock_script = zebra_chain::transparent::Script::new(&lock_script); // change pubkey to a non notary pubkey for outputs over 6th
                }
                let new_prev_tx_hash = block.transactions[1].hash();
                // fix inputs for the changed prev_tx_hash:
                let inputs = Arc::get_mut(&mut block.transactions[2]).unwrap().inputs_mut();
                for i in 0..inputs.len() {
                    let outpoint = inputs[i].outpoint().unwrap();  // immutable borrow inside this statement
                    inputs[i].set_outpoint(OutPoint{hash: new_prev_tx_hash, index: outpoint.index});    // mutable borrow inside this statement 
                    // so we cannot do this: 
                    // inputs[i].set_outpoint(OutPoint{hash: new_prev_tx_hash, index: inputs[i].outpoint().unwrap().index}); 
                    // as it would be both mutable and immutable borrows
                }
            }
        }, 
        |_prepared, commit_result| {
            // all forked blocks are valid if no valid nota
            assert_eq!( 
                *commit_result, 
                Ok(()) 
            );
            return true;
        }
    );
}
