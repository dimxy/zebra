//! komodo test helpers to get testnet blocks etc

use std::sync::Arc;
use hex::FromHex;

use zebra_chain::serialization::ZcashDeserializeInto;
use zebra_chain::block::Block;

// Load komodo sample net blocks helper fn for other tests
pub fn komodo_load_testnet_a_node_1() -> Vec<Arc<Block>> {
    
    let genesis_bin = Vec::from_hex(include_str!("./service/non_finalized_state/tests/testnet_a_genesis.hex").trim()).expect("invalid genesis hex");
    let genesis = genesis_bin.zcash_deserialize_into::<Arc<Block>>()
        .expect("block should deserialize");
    let mut blocks: Vec<Arc<Block>> = vec![genesis.clone()];

    let blocks_node1_hex = include_str!("./service/non_finalized_state/tests/testnet_a_node_1.hex").split("\n").collect::<Vec<_>>();

    // add valid branch to disk before one down before the notarised height
    for block_hex in blocks_node1_hex.iter().take(126)   {   
        if block_hex.trim().is_empty() { break; }
        let block_bin = Vec::from_hex(block_hex.trim()).expect("invalid block hex");
        let block = block_bin.zcash_deserialize_into::<Arc<Block>>().expect("could not deserialise block");
        blocks.push(block.clone());
    }
    blocks
}