//! komodo transaction fee in mempool validation
 
use chrono::{DateTime, Utc, NaiveDateTime};
use zebra_chain::{amount::{Amount, NegativeAllowed}, transaction::{Transaction}, serialization::{ZcashSerialize}};
use lazy_static::lazy_static;
use std::sync::{Mutex};

pub const DEFAULT_MIN_RELAY_TX_FEE: u64 = 100;

lazy_static! {
    /// load low fee tx rate limiter
    pub static ref TX_RATE_LIMITER: Mutex<FeeRateLimiter> = Mutex::new(FeeRateLimiter::new());   
}

/// min tx fee calculator
#[derive(Debug, Clone)]
pub struct FeeRate {
    /// fee in sat per kilobyte
    satoshi_per_kb: Amount,
}

impl FeeRate {
    /// new FeeRate initialized with fee per 1 kb
    pub fn new(satoshi_per_kb: Amount) -> Self {
        Self {
            satoshi_per_kb
        }
    }

    /// calculate fee rate for tx size
    pub fn get_fee(&self, tx_size: usize) -> Amount {
        let mut fee = ((self.satoshi_per_kb * tx_size as u64).expect("valid satoshi_per_kb") / 1000u64).expect("valid min tx fee");

        if fee == Amount::<NegativeAllowed>::zero() && self.satoshi_per_kb > Amount::<NegativeAllowed>::zero()  {
            fee = self.satoshi_per_kb;
        }
        fee
    }
}

/// komodo free fee tx limiter based on exp function of time
#[derive(Debug, Clone)]
pub struct FeeRateLimiter {

    /// last time when a tx with free fee received 
    last_time: Option<DateTime<Utc>>,

    /// max value of free tx function
    max_free_count: f64,

    /// current value of free tx function
    cur_free_count: f64,
}

impl FeeRateLimiter {

    /// -limitfreerelay unit is thousand-bytes-per-minute
    /// At default rate it would take over a month to fill 1GB
    const DEFAULT_LIMIT_10KB_PER_MIN: u64 = 15;

    /// new FeeRate initialized with fee per 1 kb
    pub fn new() -> Self {
        Self {
            last_time: None,
            max_free_count: (FeeRateLimiter::DEFAULT_LIMIT_10KB_PER_MIN * 10 * 1000) as f64,
            cur_free_count: 0f64,
        }
    }

    /// check if rate limit is not over and update the new limit value
    pub fn check_rate_limit(&mut self, tx: &Transaction, now: DateTime<Utc>) -> bool {

        if let Ok(tx_size) = tx.zcash_serialized_size() {
            let last_time = if let Some(last_time) = self.last_time { last_time } else { DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc)  };

            // Use an exponentially decaying ~10-minute window:
            let free_delta = f64::powf(1.0 - 1.0/600.0, (now - last_time).num_seconds() as f64);
            if self.cur_free_count * free_delta >= self.max_free_count  {
                return false;
            }
            self.cur_free_count *= free_delta;
            self.cur_free_count += tx_size as f64;
            self.last_time = Some(now);
            return true;
        }
        false
    }
}
