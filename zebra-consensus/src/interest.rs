use chrono::{DateTime, Utc, Duration};
use zebra_chain::{block::Height, amount::{Amount, NonNegative, COIN}, transaction::LockTime};

/// komodo_interest - calc interest for passed params
/// 
/// `tx_height` - height of block at which input utxo (tx.vin[i].prevout.hash:tx.vin[i].prevout.n) was created
/// 
/// `value`     - input utxo value
/// 
/// `lock_time` - nLockTime of transaction in which input utxo was createad
/// 
/// `tip_time`  - time of a block or other time moment against interest is calculated,
///               if None passed interest will be zero (!)
/// 
pub fn komodo_interest(tx_height: Height, value: Amount<NonNegative>, 
                    lock_time: LockTime, tip_time: Option<DateTime<Utc>>) -> Amount<NonNegative> 
{
    /// this fn should be used only for case if tx_height >= 1_000_000 (equialent of _komodo_interestnew call)

    const KOMODO_ENDOFERA: u32 = 7_777_777;
    const _ACTIVATION: u32 = 1491350400; // Wed Apr 05 2017 00:00:00 GMT+0000
    const KOMODO_MAXMEMPOOLTIME: i64 = 3600;

    let mut interest = Amount::zero();

    if let LockTime::Time(lock_time) = lock_time {
        if let Some(tip_time) = tip_time {
            if tx_height < Height(KOMODO_ENDOFERA) && 
               lock_time < tip_time && 
               value >= Amount::<NonNegative>::try_from(10 * COIN).unwrap() 
            {
                let mut elapsed = tip_time - lock_time;
                if elapsed > Duration::minutes(KOMODO_MAXMEMPOOLTIME / 60) {
                    if elapsed > Duration::days(365) {
                        elapsed = Duration::days(365);
                    }
                    if tx_height > Height(1_000_000) && elapsed > Duration::days(31) {
                        elapsed = Duration::days(31);
                    }
                    elapsed = elapsed - (Duration::minutes(KOMODO_MAXMEMPOOLTIME/60) - Duration::minutes(1));
                    interest = (value / 10_512_000).expect("division on zero here never occured");
                    let multiplier = elapsed.num_minutes().try_into().expect("convert positive i64 to u64 should pass");
                    interest = (interest * multiplier).expect("multiply on max 31*24*60 min. shouldn't cause overflow");
                }
            }
        }
    }

    interest
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interest_test_1() {
        zebra_test::init();
        // here should be some dimxy's tests from komodod
    }
}

