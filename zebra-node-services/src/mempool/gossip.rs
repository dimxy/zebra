//! Representation of a gossiped transaction to send to the mempool.

use zebra_chain::transaction::{UnminedTx, UnminedTxId, UnminedTxWithMempoolParams};

/// A gossiped transaction, which can be the transaction itself or just its ID.
#[derive(Debug, Eq, PartialEq)]
pub enum Gossip {
    /// Just the ID of an unmined transaction.
    Id(UnminedTxId),

    /// The full contents of an unmined transaction.
    /// komodo changed to UnminedTxWithMempoolParams with check_low_fee and reject_absurd_fee booleans
    Tx(UnminedTxWithMempoolParams),
}

impl Gossip {
    /// Return the [`UnminedTxId`] of a gossiped transaction.
    pub fn id(&self) -> UnminedTxId {
        match self {
            Gossip::Id(txid) => *txid,
            Gossip::Tx(tx, ..) => tx.transaction.id,
        }
    }
}

impl From<UnminedTxId> for Gossip {
    fn from(txid: UnminedTxId) -> Self {
        Gossip::Id(txid)
    }
}

impl From<UnminedTxWithMempoolParams> for Gossip {
    fn from(tx: UnminedTxWithMempoolParams) -> Self {
        Gossip::Tx(tx)
    }
}
