use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use tokio::sync::broadcast;

use zebra_chain::block::{self, Block};

use crate::{BoxError, Response};

#[derive(Debug, Default)]
pub struct PendingBlocks(HashMap<block::Hash, broadcast::Sender<Option<Arc<Block>>>>);

impl PendingBlocks {
    /// Returns a future that will resolve to the `Block` pointed
    /// to by the given `Hash` when it is available.
    pub fn queue(
        &mut self,
        block_hash: block::Hash,
    ) -> impl Future<Output = Result<Response, BoxError>> {
        tracing::trace!("queued BLOCK {:?}", block_hash);
        let mut receiver = self
            .0
            .entry(block_hash)
            .or_insert_with(|| {
                let (sender, _) = broadcast::channel(1);
                sender
            })
            .subscribe();

        async move {
            receiver
                .recv()
                .await
                .map(Response::Block)
                .map_err(BoxError::from)
        }
    }

    /// Notify all requests waiting for the [`Block`] pointed to by
    /// the given [`block::Hash`] that the [`Block`] has
    /// arrived.
    pub fn respond(&mut self, block: Arc<Block>) {
        if let Some(sender) = self.0.remove(&block.hash()) {
            // Adding the outpoint as a field lets us cross-reference
            // with the trace of the verification that made the request.
            tracing::trace!("found pending BLOCK {:?}", block.hash());
            let _ = sender.send(Some(block.clone()));
        }
    }

    /// Scan the set of waiting block requests for channels where all receivers
    /// have been dropped and remove the corresponding sender.
    pub fn prune(&mut self) {
        self.0.retain(|_, chan| chan.receiver_count() > 0);
    }
}
