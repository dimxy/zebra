//! Komodo helpers for state service for transparent outputs

use std::collections::HashMap;
use zebra_chain::transparent;

use super::finalized_state::ZebraDb;


/// read transactions for block spends and construct OrderedUtxos
pub fn komodo_transparent_spend_finalized(
    prepared: &crate::PreparedBlock,
    finalized_state: &ZebraDb,
) -> HashMap<transparent::OutPoint, transparent::Output> {
    let mut block_spends = HashMap::new();

    for (_, transaction) in prepared.block.transactions.iter().enumerate() {
        let spends = transaction
            .inputs()
            .iter()
            .filter_map(transparent::Input::outpoint);

        for spend in spends {

            if let Some((tx, _)) = finalized_state.transaction(spend.hash)  {
                let output = tx.outputs().get(spend.index as usize).unwrap().clone();    
                block_spends.insert(spend, output);
            }
        }
    }

    block_spends
}