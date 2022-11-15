/// Komodo helpers for working with state service

use std::collections::HashMap;
use zebra_chain::transparent::{self, OrderedUtxo};

use super::finalized_state::ZebraDb;


/// read transactions for block spends and construct OrderedUtxos
pub fn komodo_transparent_spend_finalized(
    prepared: &crate::PreparedBlock,
    finalized_state: &ZebraDb,
) -> HashMap<transparent::OutPoint, transparent::OrderedUtxo> {
    let mut block_spends = HashMap::new();

    for (spend_tx_index_in_block, transaction) in prepared.block.transactions.iter().enumerate() {
        // Coinbase inputs represent new coins,
        // so there are no UTXOs to mark as spent.
        let spends = transaction
            .inputs()
            .iter()
            .filter_map(transparent::Input::outpoint);

        info!("spends found {:?}", spends);
        for spend in spends {

            if let Some((tx, height)) = finalized_state.transaction(spend.hash)  {
                //let output = transparent::Output::new();
                let output = tx.outputs().get(spend.index as usize).unwrap().clone();
                let utxo = OrderedUtxo::new(output, height, 0);

                info!("ordered utxo found {:?}", utxo);
    
                block_spends.insert(spend, utxo);
            }
        }
    }

    block_spends
}