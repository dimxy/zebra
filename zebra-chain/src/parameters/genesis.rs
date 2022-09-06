//! Genesis consensus parameters for each Zcash network.

use crate::{block, parameters::Network};

/// The previous block hash for the genesis block.
///
/// All known networks use the Bitcoin `null` value for the parent of the
/// genesis block. (In Bitcoin, `null` is `[0; 32]`.)
pub const GENESIS_PREVIOUS_BLOCK_HASH: block::Hash = block::Hash([0; 32]);

/// Returns the hash for the genesis block in `network`.
pub fn genesis_hash(network: Network) -> block::Hash {
    match network {
        // zcash-cli getblockhash 0
        Network::Mainnet => "027e3758c3a65b12aa1046462b486d0a63bfa1beae327897f56c5cfb7daaae71",
        // zcash-cli -testnet getblockhash 0
        Network::Testnet => "05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38",
        // komodo-cli -testnet getblockhash 0
        Network::Kmdtestnet => "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08", // "e46e999d6de5ef95427ea51b8242ef7949de22b340b6a484ff154b9991ec9452",
    }
    .parse()
    .expect("hard-coded hash parses")
}
