use core::num;

use chrono::{DateTime, Utc, Duration, NaiveDateTime};
use zebra_chain::{block::Height, amount::{Amount, NonNegative, COIN}, transaction::LockTime};

const KOMODO_ENDOFERA: u32 = 7_777_777;
const ACTIVATION: i64 = 1491350400; // Wed Apr 05 2017 00:00:00 GMT+0000
const KOMODO_MAXMEMPOOLTIME: i64 = 3600;
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
                                interest = (numerator * elapsed.num_minutes() as u64).expect("mul should be ok");
                                interest = (interest / (365 * 24 * 60)).expect("div to non-zero should be ok");

                                let interestnew = _komodo_interestnew(tx_height, value, LockTime::Time(lock_time), Some(tip_time));
                                if interest < interestnew {
                                    tracing::info!(?interest, ?interestnew, ?tx_height, ?value, ?lock_time, ?tip_time, "pathA");
                                }
                            } else {
                                interest = _komodo_interestnew(tx_height, value, LockTime::Time(lock_time), Some(tip_time));
                            }
                        } else if tx_height <= Height(1_000_000) { // exception
                            let numerator: u64 = u64::from(value) * KOMODO_INTEREST;
                            interest = Amount::<NonNegative>::try_from(numerator / denominator as u64).expect("div should be ok");
                            interest = (interest / COIN as u64).expect("div should be ok");

                            let interestnew = _komodo_interestnew(tx_height, value, LockTime::Time(lock_time), Some(tip_time));
                            if interest < interestnew {
                                tracing::info!(?interest, ?interestnew, ?tx_height, ?value, ?lock_time, ?tip_time, "pathB");
                            }
                        } else {
                            interest = _komodo_interestnew(tx_height, value, LockTime::Time(lock_time), Some(tip_time));
                        }
                    } else {
                        // value <= 25_000 * COIN
                        let numerator: u64 = u64::from(value) * KOMODO_INTEREST;
                        if tx_height < Height(250_000) ||
                            tip_time < DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(ACTIVATION, 0), Utc) {
                            if tx_height < Height(250_000) ||
                                (numerator * elapsed.num_minutes() as u64) < 365 * 24 * 60 {
                                    interest = Amount::<NonNegative>::try_from(numerator / denominator as u64).expect("div should be ok");
                                    interest = (interest / COIN as u64).expect("div should be ok");
                            } else
                            {
                                    let mut interest_value = numerator * elapsed.num_minutes() as u64;
                                    interest_value = interest_value / (365 * 24 * 60);
                                    interest_value = interest_value / COIN as u64;
                                    interest = Amount::<NonNegative>::try_from(interest_value).expect("conversion expect ok");
                            }
                        } else if tx_height < Height(1_000_000) {
                            let numerator = (value / 20).expect("div to non-zero should be ok"); // assumes 5%
                            interest = (numerator * elapsed.num_minutes() as u64).expect("mul should be ok");
                            interest = (interest / (365 * 24 * 60)).expect("div to non-zero should be ok");
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
                        if elapsed > Duration::minutes(KOMODO_MAXMEMPOOLTIME / 60) {
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

        for n_value in [10u64*COIN as u64, 25001u64*COIN as u64] {
            let arguments = [
                    (1000000, n_value, 1663839248, 1663839248 + (31 * 24 * 60 - 1) * 60 + 3600),
                ];

            let results = [
                n_value/10512000 * (31*24*60 - 59),
            ];

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

    }
}

