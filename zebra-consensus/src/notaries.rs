use zebra_chain::block::Height;

// # Check if passed pk at height corresponding to KMD notary node
//
// for now it's just a stub
pub fn is_notary_node(height: &Height, pk: &[u8]) -> bool {
    // println!("height = {:?}, pubkey = {:02x?}", *height, pk);
    true
}