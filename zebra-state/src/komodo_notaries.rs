use std::borrow::Borrow;
use std::sync::MutexGuard;

use chrono::{Utc, DateTime, NaiveDateTime, Duration};
use zebra_chain::parameters::{Network, NetworkUpgrade, MAINNET_MAX_FUTURE_BLOCK_TIME, MAINNET_HF22_NOTARIES_PRIORITY_ROTATE_DELTA};
//use crate::ValidateContextError;
//use zebra_chain::block::Height;
use zebra_chain::block::{Block, Height};

use zebra_chain::komodo_hardfork::*;
use zebra_chain::komodo_utils::*;

//use secp256k1::PublicKey;
use tracing::error;
use thiserror::Error;

pub const NN_LAST_BLOCK_DEPTH: usize = 65;

#[allow(dead_code, missing_docs)]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum NotaryValidateContextError {

    #[error("special notary block height {0:?}, hash {1:?} not valid ({2:?})")]
    NotaryBlockInvalid(zebra_chain::block::Height, zebra_chain::block::Hash, String),

    #[error("notary pubkey data error")]
    NotaryPubkeysError(#[from] NotaryDataError),

    #[error("this notary {1:?} already mined recently for this height {0:?}")]
    NotaryAlreadyMinedError(zebra_chain::block::Height, i32),

    #[error("notary internal error: {0:?}")]
    NotaryInternalError(String),

    #[error("notary internal error: must be checkpont validation")]
    NotaryMustCheckpointValidate(),
}


/// check notary is unique for depth of 'NN_LAST_BLOCK_DEPTH' blocks (it's currently the actual rules, since height >= 82000)
fn komodo_check_last_65_blocks_for_dups<C>(height: Height, relevant_chain: &Vec<Block>, notary_id: i32) -> Result<(), NotaryValidateContextError> 
{
    tracing::debug!("komodo_check_last_65_blocks_for_dups enterred for height={:?}", height);
    if height >= Height(82000) {
        if relevant_chain.len() < NN_LAST_BLOCK_DEPTH { return Err(NotaryValidateContextError::NotaryInternalError(String::from("relevant chain too small"))); }
        tracing::debug!("komodo_check_last_65_blocks_for_dups relevant_chain heights={:?}", relevant_chain.iter().map(|b| b.hash()).collect::<Vec<_>>());

        let mut has_duplicates = false;
        for block in relevant_chain.into_iter() {
            if let Some(block_pk) = komodo_get_block_pubkey(&block) {
                let block_notary_id = komodo_get_notary_id_for_height(&height, &block_pk)?;    
                if notary_id == block_notary_id {
                    has_duplicates = true;
                    break;
                }
            }
        }

        if height > Height(792000) {
            if has_duplicates {
                return Err(NotaryValidateContextError::NotaryAlreadyMinedError(height, notary_id));
            }
        }
    }
    else {
        return Err(NotaryValidateContextError::NotaryMustCheckpointValidate());
    }

    Ok(())
}

fn komodo_check_notary_blocktime<C>(height: Height, relevant_chain: &Vec<Block>, block: &Block) -> Result<(), NotaryValidateContextError> 
{
    let tip_block = relevant_chain
    .get(0)
    .expect("state must contain tip block to do contextual validation");

    let blocktime = block.header.time;
    let tip_blocktime = tip_block.borrow().header.time;
    let time_0 = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc);
    let duration_57 = Duration::seconds(57);

    if blocktime != time_0 && tip_blocktime != time_0 && blocktime < tip_blocktime + duration_57   {
        if height > Height(807000)  {
            return Err(NotaryValidateContextError::NotaryBlockInvalid(height, block.hash(), String::from("invalid blocktime")));
        }
    }
    Ok(())
}

/// check if a notary_id is in priority list part allowed for second block mining
fn is_second_block_allowed(notary_id: i32, blocktime: DateTime<Utc>, threshold: DateTime<Utc>, delta: i32, v_priority_list: &Vec<i32>) -> Result<bool, NotaryValidateContextError>
{
    if v_priority_list.len() != 64 {
        return Err(NotaryValidateContextError::NotaryInternalError(String::from("invalid priority list")));
    }
    if blocktime >= threshold && delta > 0 && notary_id >= 0    {
        if let Ok(pos) = usize::try_from((blocktime - threshold).num_seconds() / delta as i64) {
            if pos < v_priority_list.len()  {
                // if nodeid found in current range of priority -> allow it
                if v_priority_list.iter().take(pos + 1).any(|mid| *mid == notary_id) {
                    return Ok(true);
                }
            }
            else {
                return Ok(true); // if time is bigger than the biggest range -> all nodes allowed
            }
        }
    }
    Ok(false)
}

fn komodo_check_if_second_block_allowed<C>(notary_id: i32, height: Height, relevant_chain: &Vec<Block>, block: &Block) -> Result<(), NotaryValidateContextError> 
{

    let mut v_priority_list: Vec<i32> = (0..64).collect();
    for block in relevant_chain.iter().rev() {
        if let Some(block_pk) = komodo_get_block_pubkey(&block) {
            let block_notary_id = komodo_get_notary_id_for_height(&height, &block_pk)?;  
            if block_notary_id >= 0 {
                if let Some(pos) = v_priority_list.iter().position(|&mid| mid == block_notary_id) {
                    if pos + 1 < v_priority_list.len()  {
                        v_priority_list[pos..].rotate_left(1);
                    }
                }
            }
        }
    }

    let blocktime = block.header.time;
    let tip_blocktime = relevant_chain[0].header.time;
    let max_gap_allowed = MAINNET_MAX_FUTURE_BLOCK_TIME + 1;
    let threshold = tip_blocktime + Duration::seconds(max_gap_allowed);

    if is_second_block_allowed(notary_id, blocktime, threshold, MAINNET_HF22_NOTARIES_PRIORITY_ROTATE_DELTA, &v_priority_list)? {
        tracing::debug!("komodo notary hf22 second block allowed for ht={:?}", height);
        return Ok(());
    }
    error!("invalid second block generated for notary_id={} block.header={:?}", notary_id, block.header);
    Err(NotaryValidateContextError::NotaryBlockInvalid(height, block.hash(), String::from("invalid second block after gap")))
}


/// check if block is notary special and valid for notary new rules for ht >= 84000 for KMD mainnet, 
/// if the block is special and valid then returns true
/// if the block is not special then returns false
/// if the block is special and invalid then throws a error
pub fn is_kmd_special_notary_block<C>(
    block: &Block,
    height: Height,
    network: Network,
//    finalized_tip_height: Option<Height>,
//    relevant_chain: &Vec<Block>,
    relevant_chain: C,
) -> Result<bool, NotaryValidateContextError>
where
    //C: IntoIterator<Item = Borrow<Block>>,
    C: IntoIterator,
    C::Item: Borrow<Block>,
    C::IntoIter: ExactSizeIterator,
    //<C as IntoIterator>::Item: ExactSizeIterator,
{
    if height > Height(34000) {

        if let Some(block_pk) = komodo_get_block_pubkey(block) {
        
            let notary_id = komodo_get_notary_id_for_height(&height, &block_pk)?;  // low-level error converted to NotaryValidateContextError
            if notary_id >= 0 {

                // convert to Vec of block refs for convenience:
                let relevant_chain: Vec<_> = relevant_chain
                .into_iter()
                .map(|b| b.borrow().to_owned())
                .collect::<Vec<Block>>();

                let check_last_65_result = komodo_check_last_65_blocks_for_dups::<C>(height, &relevant_chain, notary_id);  // do not return error here

                komodo_check_notary_blocktime::<C>(height, &relevant_chain, block)?;  // returns error if blocktime invalid

                if check_last_65_result.is_err() {
                    if NetworkUpgrade::komodo_is_gap_after_second_block_allowed(network, height) {
                        komodo_check_if_second_block_allowed::<C>(notary_id, height, &relevant_chain, block)?;  // returns error if second block invalid
                    } else {
                        return Err(check_last_65_result.err().unwrap()); // return error
                    }
                }

                return Ok(true);
            }
        }
    } else {
        return Err(NotaryValidateContextError::NotaryMustCheckpointValidate());
    }

    Ok(false)  // not a special notary block
}