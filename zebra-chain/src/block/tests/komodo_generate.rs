//! komodo test helper to create blocks with nota

use std::{sync::Arc, collections::HashMap};
use crate::{
    fmt::SummaryDebug, transparent::{self, Script, CoinbaseData, GENESIS_COINBASE_DATA}, 
    parameters::{Network, GENESIS_PREVIOUS_BLOCK_HASH}, 
    block::{Height, arbitrary::fix_generated_transaction, Block, merkle::Root}, 
    value_balance::ValueBalance, 
    amount::NonNegative};
use crate::{
    serialization::{ZcashDeserializeInto, ZcashDeserialize, ZcashSerialize}
};
use crate::komodo_nota::BackNotarisationData;

/// helper to create partial chain
pub fn komodo_create_partial_chain<F, T, E>( 
    branch_id: &str, 
    start_blocks: &Vec<Arc<Block>>, 
    chain_value_pools_in: ValueBalance<NonNegative>,
    utxos_in: HashMap<transparent::OutPoint, transparent::OrderedUtxo>,
    start_height: Height,       
    block_count: u32,
    block_with_nota: bool,
    check_transparent_coinbase_spend: F,
) -> SummaryDebug<Vec<Arc<Block>>>
where
F: Fn(
        Network,
        transparent::OutPoint,
        transparent::CoinbaseSpendRestriction,
        transparent::OrderedUtxo,
    ) -> Result<T, E>
    + Copy
    + 'static,
{
    //println!("start_height {:?} block_count {} block_with_nota {}", start_height, block_count, block_with_nota);
    let block_cb: Block = zebra_test::komodo_vectors::BLOCK_KMDTESTNET_0000126_BYTES.zcash_deserialize_into().expect("block is structurally valid"); 
    let block_nota: Block = zebra_test::komodo_vectors::BLOCK_KMDTESTNET_0000127_BYTES.zcash_deserialize_into().expect("block is structurally valid"); 

    let mut vec = Vec::with_capacity(block_count.try_into().unwrap());


    // add prev blocks
    for (ht, block) in start_blocks.iter().enumerate() {
        vec.push((ht as u32, block.as_ref().clone()));
    }

    // add new blocks
    for ht in start_height.0..start_height.0+block_count {
        let block = if block_with_nota { block_nota.clone() } else { block_cb.clone() };
        vec.push((ht, block));
    }

    let mut chain_value_pools = chain_value_pools_in;
    let mut utxos = utxos_in;
    //let mut history_tree: Option<HistoryTree> = None;

    for i in start_height.0 as usize..vec.len() {  // skip blocks before start_height which are already in chain

        let height = vec[i].0;

        let previous_block = if i > 0 {
            Some(vec[i-1].1.clone())
        } else {
            None
        };

        // find block 2 blocks below to claim it is notarised
        let previous_block_2 = if i > 1 {
            Some(vec[i-2].1.clone())
        } else {
            None
        };

        let block = &mut vec[i].1;

        let mut new_transactions = Vec::new();
        for (tx_index_in_block, transaction) in block.transactions.drain(..).enumerate() {

            let mut tx = (*transaction).clone();
            if tx_index_in_block == 0 {
                // fix coinbase input
                let data = match (height, &tx.inputs()[0]) {
                    (0, _) => CoinbaseData(GENESIS_COINBASE_DATA.to_vec()),
                    (_, transparent::Input::Coinbase { height: _, data, sequence: _ }) => CoinbaseData([data.clone().0, branch_id.as_bytes().to_vec()].concat()),
                    (_,_) => unreachable!("test tx[0] not a coinbase"),
                };
                let input = transparent::Input::Coinbase {
                    height: Height(height),
                    data,    // change block hash
                    sequence: u32::MAX,
                };
                *tx.inputs_mut() = vec![ input ];
                //println!("fixed coinbase {} {:?}", tx.is_coinbase(), tx.inputs()[0]);
            }

            if tx_index_in_block == 1 && previous_block.is_some() {
                // fix funding notaries tx
                // do nothing
            }

            if tx_index_in_block >= 2 {
                // fix nota inputs and last notarised height:
                if let Some(last) = tx.outputs().last() {
                    if let Ok(mut nota) = BackNotarisationData::zcash_deserialize(last.lock_script.as_raw_bytes()) {

                        let mut new_last = last.clone();
                        let mut new_opret = Vec::new();
                        if let Some(previous_block_off_2) = previous_block_2.clone() { // nota points to ht-2 
                            nota.notarised_height = Height(height - 2);
                            nota.notarised_block_hash = previous_block_off_2.hash();
                            nota.zcash_serialize(&mut new_opret).expect("nota serialization okay");
                            new_last.lock_script = Script::new(&new_opret);
                            *tx.outputs_mut().last_mut().unwrap() = new_last;
                            //println!("fixed nota in tx output {:?} height={:?}", tx.outputs().last(), height);
                        }
                    }
                }
            }
    
            if let Some(fixed_transaction) = fix_generated_transaction(
                Network::Testnet,
                tx,
                tx_index_in_block,
                Height(height),
                if let Some(previous_block) = previous_block.clone() { Some(previous_block.header.time) } else { None },
                &mut chain_value_pools,
                &mut utxos,
                check_transparent_coinbase_spend,
            ) {
                //println!("fixed tx_pos {} tx {:?} at height {}", tx_index_in_block, fixed_transaction.hash(), height);
                new_transactions.push(Arc::new(fixed_transaction));
            } else {
                println!("could not fix tx {} at height {}", tx_index_in_block, height);
            }
        }
        
        // delete invalid transactions
        block.transactions = new_transactions;

        // update merkle root
        Arc::make_mut(&mut block.header).merkle_root = block.transactions.iter().collect::<Root>();

        // fixup the previous block hash and this block time
        if height > 0 {            
            if let Some(previous_block) = previous_block.clone() {
                Arc::make_mut(&mut block.header).previous_block_hash = previous_block.hash();
                Arc::make_mut(&mut block.header).time = previous_block.header.time + chrono::Duration::seconds(60); // Komodo update block time (cant be random). TODO: make range 0..MAX_FUTURE_BLOCK_TIME
                //println!("i {} height {:?} fixed previous_block_hash {}", i, height, previous_block.hash());
            } else {
                assert!(false, "could not fix previous_block_hash i {} height {:?}", i, height);
            }              
        } else {
            Arc::make_mut(&mut block.header).previous_block_hash = GENESIS_PREVIOUS_BLOCK_HASH;
            //println!("fixed previous_block_hash genesis i {} height {:?}", i, height);
        }
    }
    SummaryDebug(
        vec.into_iter()
            .skip(start_height.0 as usize) // return only new blocks
            .map(|(_height, block)| Arc::new(block))
            .collect(),
    )

}