use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};

use chrono::{Utc, DateTime, NaiveDateTime, Duration};
use zebra_chain::parameters::{Network, NetworkUpgrade, MAINNET_MAX_FUTURE_BLOCK_TIME, MAINNET_HF22_NOTARIES_PRIORITY_ROTATE_DELTA};
use zebra_chain::transparent::Script;
use zebra_chain::{
    transparent, 
    //primitives::transparent_output_address,
};
//use crate::ValidateContextError;
//use zebra_chain::block::Height;
use zebra_chain::block::{Block, Height};
use zebra_chain::block;
use zebra_chain::transaction;


use zebra_chain::komodo_hardfork::*;
use zebra_chain::komodo_utils::*;

//use secp256k1::PublicKey;
use tracing::error;
use thiserror::Error;

pub const NN_LAST_BLOCK_DEPTH: usize = 65;

/// temp opcodes for parsing nota in opreturn
/// hope we will have complete opcode list in librustzcash and have it public
enum OpCode {
    // push value
    PushData1 = 0x4c,
    PushData2 = 0x4d,
    PushData4 = 0x4e,

    // stack ops
    Dup = 0x76,

    // bit logic
    Equal = 0x87,
    EqualVerify = 0x88,

    // crypto
    Hash160 = 0xa9,
    CheckSig = 0xac,
    OpReturn = 0x6a,
}

/// Special, notary node generated block errors
#[allow(dead_code, missing_docs)]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum NotaryValidateContextError {

    #[error("special notary block height {0:?}, hash {1:?} not valid ({2:?})")]
    NotaryBlockInvalid(zebra_chain::block::Height, zebra_chain::block::Hash, String),

    #[error("notary pubkey data error")]
    NotaryPubkeysError(#[from] NotaryDataError),

    #[error("this notary {1:?} already mined recently for this height {0:?}")]
    NotaryAlreadyMinedError(zebra_chain::block::Height, NotaryId),

    #[error("notary internal error: {0:?}")]
    NotaryInternalError(String),

    #[error("notary internal error: must be checkpont validation")]
    NotaryMustCheckpointValidate(),
}


/// check notary is unique for depth of 'NN_LAST_BLOCK_DEPTH' blocks (it's currently the actual rules, since height >= 82000)
fn komodo_check_last_65_blocks_for_dups<C>(height: Height, relevant_chain: &Vec<Block>, notary_id: NotaryId) -> Result<(), NotaryValidateContextError> 
{
    tracing::debug!("komodo_check_last_65_blocks_for_dups enterred for height={:?}", height);
    if height >= Height(82000) {
        if relevant_chain.len() < NN_LAST_BLOCK_DEPTH { return Err(NotaryValidateContextError::NotaryInternalError(String::from("relevant chain too small"))); }
        tracing::debug!("komodo_check_last_65_blocks_for_dups relevant_chain heights={:?}", relevant_chain.iter().map(|b| b.hash()).collect::<Vec<_>>());

        let mut has_duplicates = false;
        for block in relevant_chain.into_iter() {
            if let Some(block_pk) = komodo_get_block_pubkey(&block) {
                if let Some(block_notary_id) = komodo_get_notary_id_for_height(&height, &block_pk)? {   
                    if notary_id == block_notary_id {
                        has_duplicates = true;
                        break;
                    }
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
fn is_second_block_allowed(notary_id: NotaryId, blocktime: DateTime<Utc>, threshold: DateTime<Utc>, delta: i32, v_priority_list: &Vec<u32>) -> Result<bool, NotaryValidateContextError>
{
    if v_priority_list.len() != 64 {
        return Err(NotaryValidateContextError::NotaryInternalError(String::from("invalid priority list")));
    }
    if blocktime >= threshold && delta > 0   {
        if let Ok(pos) = usize::try_from((blocktime - threshold).num_seconds() / delta as i64) {
            if pos < v_priority_list.len()  {
                // if nodeid found in current range of priority -> allow it
                if v_priority_list.iter().take(pos + 1).any(|mid| *mid == notary_id as u32) {
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

fn komodo_check_if_second_block_allowed<C>(notary_id: NotaryId, height: Height, relevant_chain: &Vec<Block>, block: &Block) -> Result<(), NotaryValidateContextError> 
{

    let mut v_priority_list: Vec<u32> = (0..64).collect();
    for block in relevant_chain.iter().rev() {
        if let Some(block_pk) = komodo_get_block_pubkey(&block) {
            if let Some(block_notary_id) = komodo_get_notary_id_for_height(&height, &block_pk)?  {
                if let Some(pos) = v_priority_list.iter().position(|&mid| mid == block_notary_id as u32) {
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
        tracing::info!("komodo notary hf22 second block allowed for ht={:?}", height);
        return Ok(());
    }
    error!("komodo invalid second block generated for notary_id={} block.header={:?}", notary_id, block.header);
    Err(NotaryValidateContextError::NotaryBlockInvalid(height, block.hash(), String::from("invalid second block after gap")))
}


/// check if block is notary special and valid for notary new rules for ht >= 84000 for KMD mainnet, 
/// if the block is special and valid then returns true
/// if the block is not special then returns false
/// if the block is special and invalid then throws a error
pub fn komodo_is_special_notary_block<C>(
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

    if network != Network::Mainnet {
        return Ok(false);
    }

    if height > Height(34000) {

        if let Some(block_pk) = komodo_get_block_pubkey(block) {
        
            if let Some(notary_id) = komodo_get_notary_id_for_height(&height, &block_pk)? {  // low-level error converted to NotaryValidateContextError
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
        error!("komodo_is_special_notary_block {:?} returns error NotaryMustCheckpointValidate", height);
        return Err(NotaryValidateContextError::NotaryMustCheckpointValidate());
    }

    Ok(false)  // not a special notary block
}



/// Notarisation transaction validation errors
#[allow(dead_code, missing_docs)]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum NotarisationTxError {

    #[error("notarisation transaction invalid")]
    NotarisationTxInvalid,
}

/// kmd back notarisation data 
#[derive(Debug)]
pub struct BackNotarisationData {
    block_hash: block::Hash,
    notarised_height: Height,
    tx_hash: transaction::Hash,
    symbol: String,

    // assets chains data:
    // mom: block::Root,
    // momom: block::Root,
    // ccid: u16,
    // mom_depth: u32,
}


pub fn komodo_block_has_notarisation_tx(block: &Block, spent_utxos: &HashMap<transparent::OutPoint, transparent::OrderedUtxo>, height: &Height)
{

    for tx in &block.transactions {
        
        let mut signedmask: u64 = 0;
        signedmask |= if *height < Height(91400) { 1 } else { 0 };
        for input in tx.inputs() {
            let ordered_utxo = spent_utxos.get(&input.outpoint().unwrap()).unwrap();
            //if let Some(prev_address) = transparent_output_address(&ordered_utxo.utxo.output, Network::Mainnet) {
            //    if 
            //}
            if let Some(n_id) = komodo_get_notary_id_for_spent_output(height, &ordered_utxo.utxo.output) {
                signedmask |= 1 << n_id;
            }
        }

        let numbits = {
            let mut n: i32 = 0;
            while signedmask > 0 {
                n += (signedmask & 0x1) as i32;
                signedmask >>= 1;
            }
            n
        };

        if numbits >= komodo_minratify(height) {
            for output in tx.outputs() {
                let _ =parse_kmd_back_notarisation_tx_opreturn(&output.lock_script);
            }
        }
    }
}

/// parse notarisation tx opreturn with data which height is notarisation 
fn parse_kmd_back_notarisation_tx_opreturn(script: &Script) -> Option<BackNotarisationData> {

    let bytes = script.as_raw_bytes();

    if bytes.len() < 1 { return None; }

    if bytes[0] != OpCode::OpReturn as u8 { return None; }

    let mut off: usize;
    if bytes.len() > 3 && bytes[1] < OpCode::PushData1 as u8 { off = 2; }
    else if bytes.len() > 5 && bytes[1] == OpCode::PushData1 as u8 { off = 4; }
    else { return None; }

    let mut nota = BackNotarisationData{     
        block_hash: block::Hash([0; 32]),
        notarised_height: Height(0),
        tx_hash: transaction::Hash([0; 32]),
        symbol: String::default(),
    };

    if off + 32 >= bytes.len() { return None; }
    let hash_arr: [u8;32] = bytes[off..off+32].try_into().unwrap();
    nota.block_hash = block::Hash::from(hash_arr);
    off += 32;

    if off + 4 >= bytes.len() { return None; }
    let ht = u32::from_le_bytes(bytes[off..off+4].try_into().unwrap());
    nota.notarised_height = Height(ht);
    off += 4;

    if off + 32 >= bytes.len() { return None; }
    let hash_arr: [u8;32] = bytes[off..off+32].try_into().unwrap();
    nota.tx_hash = transaction::Hash::from(hash_arr);
    off += 32;

    if off >= bytes.len() { return None; }
    if let Ok(symbol) = String::from_utf8(bytes[off..bytes.len()].to_vec()) { 
        nota.symbol = symbol;
    }
    else {
        return None;
    }
    if nota.symbol != "KMD" { return None; }

    info!("dimxyyy found nota {:?}", nota);
    Some(nota)
}