use zebra_chain::block::Height;

use zebra_chain::komodo_hardfork::NNDATA;
use secp256k1::PublicKey;
use tracing::error;

// # Check if passed pk at height corresponding to KMD notary node
//
pub fn is_notary_node(height: &Height, pk: &PublicKey) -> bool {
    // println!("height = {:?}, pubkey = {:02x?}", *height, pk);

    if let Ok(nndata) = NNDATA.lock() {
        nndata.is_notary_pubkey_for_height(height, pk).unwrap() // panics if it is an invalid season
    } else {
        error!("no notary pubkeys initialised");
        false
    }
}