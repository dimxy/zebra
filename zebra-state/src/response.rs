//! State [`tower::Service`] response types.

use std::{collections::BTreeMap, sync::Arc};

use chrono::{DateTime, Utc};
use zebra_chain::{
    amount::{Amount, NonNegative},
    block::{self, Block},
    orchard, sapling,
    transaction::{self, Transaction},
    transparent,
};

// Allow *only* this unused import, so that rustdoc link resolution
// will work with inline links.
#[allow(unused_imports)]
use crate::Request;

use crate::{service::read::AddressUtxos, TransactionLocation};

#[derive(Clone, Debug, PartialEq, Eq)]
/// A response to a [`StateService`][1] [`Request`][2].
///
/// [1]: crate::service::StateService
/// [2]: crate::Request
pub enum Response {
    /// Response to [`Request::CommitBlock`] indicating that a block was
    /// successfully committed to the state.
    Committed(block::Hash),

    /// Response to [`Request::Depth`] with the depth of the specified block.
    Depth(Option<u32>),

    /// Response to [`Request::Tip`] with the current best chain tip.
    Tip(Option<(block::Height, block::Hash)>),

    /// Response to [`Request::BlockLocator`] with a block locator object.
    BlockLocator(Vec<block::Hash>),

    /// Response to [`Request::Transaction`] with the specified transaction.
    Transaction(Option<Arc<Transaction>>),

    /// Response to [`Request::UnspentBestChainUtxo`] with the UTXO
    UnspentBestChainUtxo(Option<transparent::Utxo>),

    /// Response to [`Request::Block`] with the specified block.
    Block(Option<Arc<Block>>),

    /// The response to a `AwaitUtxo` request.
    Utxo(transparent::Utxo),

    /// The response to a `FindBlockHashes` request.
    BlockHashes(Vec<block::Hash>),

    /// The response to a `FindBlockHeaders` request.
    BlockHeaders(Vec<block::CountedHeader>),

    /// The response to a `GetMedianTimePast` request.
    MedianTimePast(Option<DateTime<Utc>>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// A response to a read-only
/// [`ReadStateService`](crate::service::ReadStateService)'s
/// [`ReadRequest`](crate::ReadRequest).
pub enum ReadResponse {
    /// Response to [`ReadRequest::Tip`] with the current best chain tip.
    Tip(Option<(block::Height, block::Hash)>),

    /// Response to [`ReadRequest::Depth`] with the depth of the specified block.
    Depth(Option<u32>),

    /// Response to [`ReadRequest::Block`](crate::ReadRequest::Block) with the
    /// specified block.
    Block(Option<Arc<Block>>),

    /// Response to
    /// [`ReadRequest::Transaction`](crate::ReadRequest::Transaction) with the
    /// specified transaction.
    Transaction(Option<(Arc<Transaction>, block::Height)>),

    /// Response to
    /// [`ReadRequest::SaplingTree`](crate::ReadRequest::SaplingTree) with the
    /// specified Sapling note commitment tree.
    SaplingTree(Option<Arc<sapling::tree::NoteCommitmentTree>>),

    /// Response to
    /// [`ReadRequest::OrchardTree`](crate::ReadRequest::OrchardTree) with the
    /// specified Orchard note commitment tree.
    OrchardTree(Option<Arc<orchard::tree::NoteCommitmentTree>>),

    /// Response to
    /// [`ReadRequest::AddressBalance`](crate::ReadRequest::AddressBalance) with
    /// the total balance of the addresses.
    AddressBalance(Amount<NonNegative>),

    /// Response to
    /// [`ReadRequest::TransactionIdsByAddresses`](crate::ReadRequest::TransactionIdsByAddresses)
    /// with the obtained transaction ids, in the order they appear in blocks.
    AddressesTransactionIds(BTreeMap<TransactionLocation, transaction::Hash>),

    /// Response to [`ReadRequest::UtxosByAddresses`] with found utxos and transaction data.
    AddressUtxos(AddressUtxos),

    /// Response to [`ReadRequest::BlockLocator`] with a block locator object.
    BlockLocator(Vec<block::Hash>),

    /// The response to a `FindBlockHashes` request.
    BlockHashes(Vec<block::Hash>),

    /// The response to a `FindBlockHeaders` request.
    BlockHeaders(Vec<block::CountedHeader>),

    /// The response to a `UnspentBestChainUtxo` request, from verified blocks in the
    /// _best_ non-finalized chain, or the finalized chain.
    UnspentBestChainUtxo(Option<transparent::Utxo>),

    /// The response to an `AnyChainUtxo` request, from verified blocks in
    /// _any_ non-finalized chain, or the finalized chain.
    ///
    /// This response is purely informational, there is no guarantee that
    /// the UTXO remains unspent in the best chain.
    AnyChainUtxo(Option<transparent::Utxo>),

    /// Komodo added response to [`ReadRequest::BestChainBlocks`](crate::ReadRequest::BestChainBlocks).
    ///
    /// with found blocks.
    BestChainBlocks(Vec<Arc<Block>>),

    /// The response to a `GetMedianTimePast` request.
    MedianTimePast(Option<DateTime<Utc>>),
}

/// Conversion from read-only [`ReadResponse`]s to read-write [`Response`]s.
///
/// Used to return read requests concurrently from the [`StateService`](crate::service::StateService).
impl TryFrom<ReadResponse> for Response {
    type Error = &'static str;

    fn try_from(response: ReadResponse) -> Result<Response, Self::Error> {
        match response {
            ReadResponse::Tip(height_and_hash) => Ok(Response::Tip(height_and_hash)),
            ReadResponse::Depth(depth) => Ok(Response::Depth(depth)),
            ReadResponse::Block(block) => Ok(Response::Block(block)),
            ReadResponse::Transaction(tx_info) => {
                Ok(Response::Transaction(tx_info.map(|tx_info| tx_info.0)))
            }
            ReadResponse::UnspentBestChainUtxo(utxo) => Ok(Response::UnspentBestChainUtxo(utxo)),

            ReadResponse::AnyChainUtxo(_) => Err("ReadService does not track pending UTXOs. \
                                                  Manually unwrap the response, and handle pending UTXOs."),

            ReadResponse::BlockLocator(hashes) => Ok(Response::BlockLocator(hashes)),
            ReadResponse::BlockHashes(hashes) => Ok(Response::BlockHashes(hashes)),
            ReadResponse::BlockHeaders(headers) => Ok(Response::BlockHeaders(headers)),

            ReadResponse::SaplingTree(_)
            | ReadResponse::OrchardTree(_)
            | ReadResponse::AddressBalance(_)
            | ReadResponse::AddressesTransactionIds(_)
            | ReadResponse::AddressUtxos(_) => {
                Err("there is no corresponding Response for this ReadResponse")
            }

            #[cfg(feature = "getblocktemplate-rpcs")]
            ReadResponse::ValidBlockProposal => Ok(Response::ValidBlockProposal),

            #[cfg(feature = "getblocktemplate-rpcs")]
            ReadResponse::ChainInfo(_) | ReadResponse::SolutionRate(_) => {
                Err("there is no corresponding Response for this ReadResponse")
            }
            ReadResponse::BestChainBlocks(_) => Err("there is no corresponding Response for this ReadResponse"),
            ReadResponse::MedianTimePast(mtp) => Ok(Response::MedianTimePast(mtp)),
        }
    }
}