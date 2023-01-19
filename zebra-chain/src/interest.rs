use core::num;

use chrono::{DateTime, Utc, Duration, NaiveDateTime};
use crate::{block::Height, amount::{Amount, NonNegative, COIN}, transaction::LockTime};

pub const KOMODO_ENDOFERA: u32 = 7_777_777;
const ACTIVATION: i64 = 1491350400; // Wed Apr 05 2017 00:00:00 GMT+0000

/// max duration in secs tx can stay in mempool, counted for tx.locktime till tip's MTP
pub const KOMODO_MAXMEMPOOLTIME: i64 = 3600; 
const KOMODO_INTEREST: u64 = 5000000;

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
    let mut interest = Amount::zero();

    if let LockTime::Time(lock_time) = lock_time {
        if let Some(tip_time) = tip_time
        {
            if tx_height < Height(KOMODO_ENDOFERA) &&
               lock_time < tip_time &&
               value >= Amount::<NonNegative>::try_from(10 * COIN).unwrap()
            {
                let mut elapsed = tip_time - lock_time;
                if elapsed >= Duration::minutes(60) {
                    if elapsed > Duration::days(365) {
                        elapsed = Duration::days(365);
                    }
                    if tx_height > Height(250_000) {
                        elapsed = elapsed - Duration::minutes(59);
                    }
                    let mut denominator: i64 = 365 * 24 * 60 / elapsed.num_minutes();
                    if denominator == 0 {
                        denominator = 1; // max KOMODO_INTEREST per transfer, do it at least annually!
                    }
                    if value > Amount::<NonNegative>::try_from(25_000 * COIN).unwrap() {
                        let mut exception: bool = false;
                        if tx_height < Height(155_949) {
                            let height_value_exceptions:[(u32, i64); 12] = [(116607, 2502721100000), (126891, 2879650000000), (129510, 3000000000000),
                                                                            (141549, 3500000000000), (154473, 3983399350000), (154736, 3983406748175),
                                                                            (155013, 3983414006565), (155492, 3983427592291), (155613, 9997409999999797),
                                                                            (157927, 9997410667451072), (155613, 2590000000000), (155949, 4000000000000)];

                            exception = height_value_exceptions.iter()
                                    .map(|(i_height, i_value)| (Height(*i_height), Amount::<NonNegative>::try_from(*i_value).unwrap()))
                                    .any(|hve_tuple| {
                                        hve_tuple.0 == tx_height && hve_tuple.1 == value
                                    });
                            if exception {
                                tracing::info!(?exception, ?tx_height, ?value, ?lock_time, ?tip_time, "exception");
                            }
                        }
                        if !exception {
                            let numerator = (value / 20).expect("div to non-zero should be ok"); // assumes 5%
                            if tx_height < Height(250_000) {
                                interest = (numerator / denominator as u64).expect("div to non-zero should be ok");
                            } else if tx_height < Height(1_000_000) {
                                // interest = (numerator * elapsed.num_minutes() as u64).expect("mul should be ok");
                                // interest = (interest / (365 * 24 * 60)).expect("div to non-zero should be ok");

                                // (a) we should avoid multiplication overflow due to max_money, so we will calc in u64 and only then transform to amount
                                let a = u64::from(numerator).overflowing_mul(elapsed.num_minutes() as u64).0 / (365 * 24 * 60);
                                interest = Amount::<NonNegative>::try_from(a).expect("conversion should be ok");

                                let interestnew = _komodo_interestnew(tx_height, value, LockTime::Time(lock_time), Some(tip_time));
                                if interest < interestnew {
                                    tracing::info!(?interest, ?interestnew, ?tx_height, ?value, ?lock_time, ?tip_time, "pathA");
                                }
                            } else {
                                interest = _komodo_interestnew(tx_height, value, LockTime::Time(lock_time), Some(tip_time));
                            }
                        } else if tx_height <= Height(1_000_000) { // exception
                            // let numerator: u64 = u64::from(value) * KOMODO_INTEREST;
                            let numerator: u64 = u64::from( value).overflowing_mul(KOMODO_INTEREST).0; /* allow overflowing multiply to match komodod */

                            // interest = Amount::<NonNegative>::try_from(numerator / denominator as u64).expect("div should be ok");
                            // interest = (interest / COIN as u64).expect("div should be ok");

                            // here we also trying to avoid max_money constraint as in (a)
                            let a = numerator / denominator as u64 / COIN as u64;
                            interest = Amount::<NonNegative>::try_from(a).expect("conversion should be ok");

                            let interestnew = _komodo_interestnew(tx_height, value, LockTime::Time(lock_time), Some(tip_time));
                            if interest < interestnew {
                                tracing::info!(?interest, ?interestnew, ?tx_height, ?value, ?lock_time, ?tip_time, "pathB");
                            }
                        } else {
                            interest = _komodo_interestnew(tx_height, value, LockTime::Time(lock_time), Some(tip_time));
                        }
                    } else {
                        // value <= 25_000 * COIN
                        let numerator: u64 = u64::from(value).overflowing_mul(KOMODO_INTEREST).0;
                        if tx_height < Height(250_000) ||
                            tip_time < DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(ACTIVATION, 0), Utc) {
                            if tx_height < Height(250_000) ||
                                (numerator.overflowing_mul(elapsed.num_minutes() as u64).0) < 365 * 24 * 60 {
                                    interest = Amount::<NonNegative>::try_from(numerator / denominator as u64 / COIN as u64).expect("div should be ok");
                            } else
                            {
                                    let mut interest_value = numerator.overflowing_mul(elapsed.num_minutes() as u64).0;
                                    interest_value = interest_value / (365 * 24 * 60);
                                    interest_value = interest_value / COIN as u64;
                                    interest = Amount::<NonNegative>::try_from(interest_value).expect("conversion expect ok");
                            }
                        } else if tx_height < Height(1_000_000) {
                            let numerator = u64::from(value) / 20; // assumes 5%
                            let product = numerator.overflowing_mul(elapsed.num_minutes() as u64).0;
                            interest = Amount::<NonNegative>::try_from(product / (365 * 24 * 60)).expect("conversion should be ok");
                            let interestnew = _komodo_interestnew(tx_height, value, LockTime::Time(lock_time), Some(tip_time));
                            if interest < interestnew {
                                tracing::info!(?interest, ?interestnew, ?tx_height, ?value, ?lock_time, ?tip_time, "pathC");
                            }
                        } else {
                            interest = _komodo_interestnew(tx_height, value, LockTime::Time(lock_time), Some(tip_time));
                        }
                    }
                }
            }
        }
    }

    interest
}

/// uint64_t _komodo_interestnew(int32_t txheight,uint64_t nValue,uint32_t nLockTime,uint32_t tiptime)
pub fn _komodo_interestnew(tx_height: Height, value: Amount<NonNegative>,
    lock_time: LockTime, tip_time: Option<DateTime<Utc>>) -> Amount<NonNegative> {

        let mut interest = Amount::zero();

        if tx_height < Height(KOMODO_ENDOFERA) && value >= Amount::<NonNegative>::try_from(10 * COIN).unwrap()
        {
            if let LockTime::Time(lock_time) = lock_time {
                if let Some(tip_time) = tip_time
                {
                    if tip_time > lock_time {
                        let mut elapsed = tip_time - lock_time;
                        if elapsed >= Duration::minutes(KOMODO_MAXMEMPOOLTIME / 60) {
                            if elapsed > Duration::days(365) {
                                elapsed = Duration::days(365);
                            }
                            if tx_height >= Height(1_000_000) && elapsed > Duration::days(31) {
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
        }
        interest
}

#[cfg(test)]
mod tests {

    use super::*;

    const MIN_TIMESTAMP_MINUS_1: i64 = LockTime::MIN_TIMESTAMP - 1;

    #[test]
    // check komodo_interestnew calculations
    fn test_komodo_interestnew() {
        zebra_test::init();

        let arguments = [
            (1, 1000u64, 1, 1), // some not working values
            (1000000, 10u64*COIN as u64, 1663839248, 1663839248 + (31 * 24 * 60 - 1) * 60 + 3600 /*KOMODO_MAXMEMPOOLTIME*/), // time lower than cut off month time limit
            (7777777-1, 10u64*COIN as u64, 1663839248, 1663839248 + (31 * 24 * 60 - 1) * 60 + 3600), // end of interest era
            (7777777, 10u64*COIN as u64, 1663839248, 1663839248 + (31 * 24 * 60 - 1) * 60 + 3600),
            (1000000, 10u64*COIN as u64-1, 1663839248, 1663839248 + (31 * 24 * 60 - 1) * 60 + 3600), // value less than limit
            (1000000, 10u64*COIN as u64-1, 1663839248, 1663839248 - 1), // tip less than nLockTime
            (1000000, 10u64*COIN as u64-1, 400000000, 400000000 + 30 * 24 * 60 * 60 + 3600), // not timestamp value
            (1000000-1, 10u64*COIN as u64, 1663839248, 1663839248 + (365 * 24 * 60 - 1) * 60 + 3600), // time close to cut off year time limit
            (1000000-1, 10u64*COIN as u64, 1663839248, 1663839248 + (365 * 24 * 60 - 1) * 60 + 3600 + 60), // time over cut off year time limit
            (1000000-1, 10u64*COIN as u64, 1663839248, 1663839248 + (365 * 24 * 60 - 1) * 60 + 3600 + 30 * 24 * 60),

        ];
        let results = [
            0,
            10u64*COIN as u64/10512000 * (31*24*60 - 59),
            10u64*COIN as u64/10512000 * (31*24*60 - 59),
            0,
            0,
            0,
            0,
            10u64*COIN as u64/10512000 * (365*24*60 - 59),
            10u64*COIN as u64/10512000 * (365*24*60 - 59),
            10u64*COIN as u64/10512000 * (365*24*60 - 59),

        ];
        assert!(arguments.len() == results.len());

        let iter = arguments.iter().zip(results.iter());
        for it in iter {
            let lock_time = match it.0.2 {
                0..=MIN_TIMESTAMP_MINUS_1 => LockTime::Height(Height(it.0.2 as u32)),
                LockTime::MIN_TIMESTAMP .. => LockTime::Time(DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(it.0.2, 0), Utc)),
                _ => unimplemented!()
            };

            let calculated = _komodo_interestnew(Height(it.0.0),
                    Amount::<NonNegative>::try_from(it.0.1).expect("amount conversion should be valid"),
                          lock_time,
                Some(DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(it.0.3, 0), Utc)));
            let predefined = Amount::<NonNegative>::try_from(*it.1).expect("amount conversion should be valid");
            assert_eq!(calculated, predefined);
        }

    }

    #[test]
    fn test_komodo_interest() {
        zebra_test::init();

        // nValue <= 25000LL*COIN and nValue >= 25000LL*COIN
        // txheight >= 1000000
        // should be routed to komodo_interestnew
        for n_value in [10u64*COIN as u64, 25001u64*COIN as u64] {
            let arguments = [
                    (1000000, n_value, 1663839248, 1663839248 + (31 * 24 * 60 - 1) * 60 + 3600), // time lower than cut off month time limit
                    (7777777-1, n_value, 1663839248, 1663839248 + (31 * 24 * 60 - 1) * 60 + 3600), // end of interest era
                    (7777777 /*KOMODO_ENDOFERA*/, n_value, 1663839248, 1663839248 + (31 * 24 * 60 - 1) * 60 + 3600),
                    (1000000, n_value-1, 1663839248, 1663839248 - 1), // tip less than nLockTime
                    (1000000, n_value-1, 400000000, 400000000 + 30 * 24 * 60 * 60 + 3600), // not timestamp value
                    (1000000, n_value, 1663839248, 1663839248 + 3600 - 1), // too small period
                    (1000000, n_value, 1663839248, 1663839248 + 31 * 24 * 60 * 60 + 3600+1), // time over cut off month time limit
                    (1000000, n_value, 1663839248, 1663839248 + 32 * 24 * 60 * 60 + 3600),
                    (1000000, 10u64*COIN as u64 - 1, 1663839248, 1663839248 + (31 * 24 * 60 - 1) * 60 + 3600), // value less than limit
                ];

            let results = [
                n_value/10512000 * (31*24*60 - 59),
                n_value/10512000 * (31*24*60 - 59),
                0,
                0,
                0,
                0,
                n_value/10512000 * (31*24*60 - 59),
                n_value/10512000 * (31*24*60 - 59),
                0,
            ];
            assert!(arguments.len() == results.len());

            let iter = arguments.iter().zip(results.iter());
            for it in iter {
                let lock_time = match it.0.2 {
                    0..=MIN_TIMESTAMP_MINUS_1 => LockTime::Height(Height(it.0.2 as u32)),
                    LockTime::MIN_TIMESTAMP .. => LockTime::Time(DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(it.0.2, 0), Utc)),
                    _ => unimplemented!()
                };

                let calculated = komodo_interest(Height(it.0.0),
                        Amount::<NonNegative>::try_from(it.0.1).expect("amount conversion should be valid"),
                              lock_time,
                    Some(DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(it.0.3, 0), Utc)));
                let predefined = Amount::<NonNegative>::try_from(*it.1).expect("amount conversion should be valid");
                assert_eq!(calculated, predefined);
            }
        }

        for days in [1, 10, 365, 365*2, 365*3] {
            let mut minutes = days * 24 * 60;
            if (minutes > 365 * 24 * 60) {
                minutes = 365 * 24 * 60;
            }

            let calc_closure = |it: (u32, i64, i64, i64)| -> Amount<NonNegative> {

                let lock_time = match it.2 {
                    0..=MIN_TIMESTAMP_MINUS_1 => LockTime::Height(Height(it.2 as u32)),
                    LockTime::MIN_TIMESTAMP .. => LockTime::Time(DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(it.2, 0), Utc)),
                    _ => unimplemented!()
                };

                komodo_interest(Height(it.0),
                        Amount::<NonNegative>::try_from(it.1).expect("amount conversion should be valid"),
                              lock_time,
                    Some(DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(it.3, 0), Utc)))
            };

            // nValue <= 25000LL*COIN
            // txheight < 1000000

            let numerator = 10u64*COIN as u64 / 20; // assumes 5%!
            let predefined = Amount::<NonNegative>::try_from(numerator * (minutes - 59) / (365 * 24 * 60)).expect("amount conversion should be valid");
            assert_eq!(calc_closure((1000000-1, 10 * COIN, 1663839248, (1663839248 + minutes * 60) as i64 )), predefined);

            // nValue <= 25000LL*COIN
            // txheight < 250000

            let numerator = (10u64*COIN as u64 * KOMODO_INTEREST);
            let locktime = ACTIVATION - 2 * days as i64 * 24 * 60 * 60;
            let tiptime = locktime + minutes as i64 * 60;
            assert!(tiptime < ACTIVATION);
            let mut denominator = (365 * 24 * 60) / minutes;
            if denominator == 0 {
                denominator = 1;
            }
            let predefined = Amount::<NonNegative>::try_from(numerator / denominator / COIN as u64).expect("amount conversion should be valid");
            assert_eq!(calc_closure((250000-1, 10 * COIN, locktime, tiptime)), predefined);

            // !exception
            // nValue > 25000LL*COIN
            // txheight < 250000

            let numerator = (25000 * COIN + 1) / 20; // assumes 5%!
            let mut denominator = 365 * 24 * 60 / minutes; // no minutes-59 adjustment
            if denominator == 0 {
                denominator = 1;
            }
            let predefined = Amount::<NonNegative>::try_from(numerator as u64 / denominator).expect("amount conversion should be valid");
            assert_eq!(calc_closure((250000-1, 25000 * COIN + 1, 1663839248, 1663839248 + minutes as i64 * 60)), predefined);

            // !exception
            // nValue > 25000LL*COIN
            // txheight < 1000000

            let numerator = (25000 * COIN + 1) / 20; // assumes 5%!
            let minutes_adj = minutes - 59; // adjusted since ht=250000
            let predefined = Amount::<NonNegative>::try_from(numerator * minutes_adj as i64 / (365 * 24 * 60)).expect("amount conversion should be valid");
            assert_eq!(calc_closure((1000000-1, 25000 * COIN + 1, 1663839248, 1663839248 + minutes as i64 * 60)), predefined);

            // exception
            // nValue > 25000LL*COIN
            // txheight < 1000000

            let htvals: [(u32, i64); 12] = [(116607, 2502721100000), (126891, 2879650000000), (129510, 3000000000000), (141549, 3500000000000),
                (154473, 3983399350000), // mul overflow
                (154736, 3983406748175),
                (155013, 3983414006565),
                (155492, 3983427592291), (155613, 9997409999999797), (157927, 9997410667451072), (155613, 2590000000000),
                (155949, 4000000000000)];

            for htval in htvals {
                let txheight = htval.0;
                let n_value = htval.1;

                //let numerator: u64 = n_value as u64 * KOMODO_INTEREST;
                let numerator: u64 = (n_value as u64).overflowing_mul(KOMODO_INTEREST).0; /* allow overflowing multiply to match komodod */

                let locktime = 1484490069; // close to real tx locktime
                let tiptime = locktime + minutes * 60;
                let mut denominator = (365 * 24 * 60) / minutes;
                if denominator == 0 {
                    denominator = 1;
                }
                if txheight < 155949 {
                    let predefined = Amount::<NonNegative>::try_from(numerator / denominator / COIN as u64).expect("amount conversion should be valid");
                    assert_eq!(calc_closure((txheight, n_value, locktime as i64, tiptime as i64)), predefined);
                }
            }
        }

    }

    #[test]
    /// test a specific overflow case  
    fn test_komodo_interest_overflow_path_C() {
        zebra_test::init();

        let tip_time = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(1491350400 + 1, 0), Utc);
        let tx_lock_time = tip_time - Duration::minutes(59 + 49);

        let calc_value = komodo_interest(Height(250002), Amount::<NonNegative>::try_from(233539804500u64).expect("conversion must be okay"), LockTime::Time(tx_lock_time), Some(tip_time));
        let overflow_value = Amount::<NonNegative>::try_from(1088608).expect("conversion must be okay");
        assert_eq!(calc_value, overflow_value);
    }

    #[test]
    /// test a specific overflow case  
    fn test_komodo_interest_overflow_before_activation() {
        zebra_test::init();
        let tip_time = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(1491350400 - 1, 0), Utc);
        let tx_lock_time = tip_time - Duration::minutes(59 + 49);

        let calc_value = komodo_interest(Height(250002), Amount::<NonNegative>::try_from(233539804500u64).expect("conversion must be okay"), LockTime::Time(tx_lock_time), Some(tip_time));
        let overflow_value = Amount::<NonNegative>::try_from(35711).expect("conversion must be okay");
        assert_eq!(calc_value, overflow_value);
    }

    #[test]
    /// test bug zero _komodo_interestnew comparison to max mempool time (kmd tx b973476fe0df4214ebd1d21d6aee6e2454a85c24be3a83a14d56771dcdfd4349) 
    fn test_komodo_tx_b973_interest_bug() {
        zebra_test::init();
        let tip_time = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(1660056383, 0), Utc);
        let tx_lock_time = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(1660052783, 0), Utc);

        let calc_value = komodo_interest(Height(3025991), Amount::<NonNegative>::try_from(25840270178u64).expect("conversion must be okay"), LockTime::Time(tx_lock_time), Some(tip_time));
        let check_value = Amount::<NonNegative>::try_from(2458).expect("conversion must be okay");
        assert_eq!(calc_value, check_value);
    }
}

