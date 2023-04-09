//! Komodo added impl for Peer Statistics (for getpeerinfo rpc)

use std::{net::SocketAddr, collections::HashMap, time::SystemTime, sync::Arc};

use crate::{meta_addr::{MetaAddr, MetaAddrChange}, PeerAddrState};
use zebra_chain::parameters::Network;
use thiserror::Error;
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};

use crate::{
    BoxError, Config,
};

/// Peer stat data collected from network requests
#[derive(Copy, Debug, Clone)]
pub struct PeerNetStat {

    pub connection_time: SystemTime,

    pub last_attempt_time: SystemTime,
}

impl PeerNetStat {
    fn new() -> Self {
        let now = SystemTime::now();
        Self {
            connection_time: now,
            last_attempt_time: now,
        }
    } 
}

/// Stat data for one peer
#[derive(Copy, Debug, Clone)]
pub struct PeerStatData {

    /// peer address with its network status
    pub meta_addr: MetaAddr,

    /// peer network stat values
    pub net_stat: PeerNetStat,

    /// inbound or outbound connection
    pub is_inbound: bool,
}

/// Live peers' statistics list
#[derive(Debug, Clone)]
pub struct PeerStats {
    /// Connected peer addresses,
    by_addr: HashMap<SocketAddr, PeerStatData>,

    /// The configured Zcash network.
    network: Network,
}

impl PeerStats {
    /// create holding peers statistics object
    pub fn new(network: Network) -> PeerStats {
        let new_list = PeerStats {
            by_addr: HashMap::new(),
            network,
        };

        new_list
    }

    /// update inbound conns with change
    #[allow(clippy::unwrap_in_result)]
    pub fn update(&mut self, change: MetaAddrChange) -> Option<PeerStatData> {
        let previous = self.by_addr.remove(&change.addr());

        let previous_meta_addr = if let Some(previous) = previous { Some(previous.meta_addr) } else { None };

        let updated_meta_addr = change.apply_to_meta_addr(previous_meta_addr);

        trace!(
            ?change,
            ?updated_meta_addr,
            ?previous,
            total_peers = self.by_addr.len(),
            "calculated updated PeerStats entry",
        );

        println!("got updated_meta_addr={:?}", updated_meta_addr);

        if let Some(updated_meta_addr) = updated_meta_addr {

            // add only active peers to stat: 
            if updated_meta_addr.last_connection_state == PeerAddrState::Responded ||
                updated_meta_addr.last_connection_state == PeerAddrState::AttemptPending {

                let mut updated_net_stat;
                if let Some(previous) = previous {
                    updated_net_stat = previous.net_stat;
                    updated_net_stat.last_attempt_time = SystemTime::now();
                } else {
                    updated_net_stat = PeerNetStat::new();
                }

                let updated = PeerStatData { 
                    meta_addr: updated_meta_addr, 
                    net_stat: updated_net_stat,
                    is_inbound: !updated_meta_addr.address_is_valid_for_outbound(self.network),
                };

                self.by_addr.insert(
                    updated_meta_addr.addr, 
                    updated,
                );

                debug!(
                    ?change,
                    ?updated_meta_addr,
                    ?previous,
                    total_peers = self.by_addr.len(),
                    "updated PeerStats entry",
                );

                println!("added updated_meta_addr={:?}", updated_meta_addr);
                return Some(updated);
            }
        }

        None
    }

    /// Look up `addr` in the peer stats, and return its [`PeerStatData`].
    ///
    /// Converts `addr` to a canonical address before looking it up.
    /*pub fn get(&mut self, addr: &SocketAddr) -> Option<PeerStatData> {
        let addr = canonical_socket_addr(*addr);

        self.by_addr.get(&addr).copied()
    }*/

    /// Return an iterator over peers stats.
    ///
    /// Returns peers stats.
    pub fn peers(&'_ self) -> impl Iterator<Item = PeerStatData> + '_ {
        self.by_addr.values().cloned()
    }

}

