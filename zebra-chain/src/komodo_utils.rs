//! Utils lib for komodo code development, particularly transparent scripts parsing 

use crate::{block::{Block}, transparent::Script};
use secp256k1::PublicKey;

/// Parse p2pk script pubkey and return pubkey or None 
pub fn parse_p2pk(lock_script: &Script) -> Option<PublicKey>
{
    let spk_raw = lock_script.as_raw_bytes();
    if spk_raw.len() == 35 && spk_raw[0] == 0x21 && spk_raw[34] == 0xac {
        let pk_raw = &spk_raw[1..34];
        if let Ok(pk) = PublicKey::from_slice(pk_raw) {
            return Some(pk);
        }
    }
    None
}

/// get pubkey from coinbase p2pk output.0
pub fn komodo_get_block_pubkey(block: &Block) -> Option<PublicKey> {
    
    if block.transactions.len() > 0 {
        if block.transactions[0].outputs().len() > 0 {
            return parse_p2pk(&block.transactions[0].outputs()[0].lock_script);
        }
    }
    None
}