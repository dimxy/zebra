//! Transaction checks.
//!
//! Code in this file can freely assume that no pre-V4 transactions are present.

use std::{borrow::Cow, collections::{HashSet, HashMap}, convert::TryFrom, hash::Hash};

use chrono::{DateTime, Utc};

use zebra_chain::{
    amount::{Amount, NonNegative, Error as AmountError, COIN},
    block::{Height, self},
    orchard::Flags,
    parameters::{Network, NetworkUpgrade},
    primitives::zcash_note_encryption,
    transaction::{LockTime, Transaction, self},
    transparent, komodo_utils::parse_p2pk, work::difficulty::{ExpandedDifficulty, CompactDifficulty},
};

use zebra_chain::komodo_hardfork::NN;

use crate::error::TransactionError;

use super::LastTxDataVerify;

/// Checks if the transaction's lock time allows this transaction to be included in a block.
///
/// Consensus rule:
///
/// > The transaction must be finalized: either its locktime must be in the past (or less
/// > than or equal to the current block height), or all of its sequence numbers must be
/// > 0xffffffff.
///
/// [`Transaction::lock_time`] validates the transparent input sequence numbers, returning [`None`]
/// if they indicate that the transaction is finalized by them. Otherwise, this function validates
/// if the lock time is in the past.
/// (this function is not used in komodo, see is_final_tx_komodo() instead)
pub fn lock_time_has_passed(
    network: Network,
    tx: &Transaction,
    block_height: Height,
    block_time: DateTime<Utc>,
) -> Result<(), TransactionError> {
    match tx.lock_time() {
        Some(LockTime::Height(unlock_height)) => {
            // > The transaction can be added to any block which has a greater height.
            // The Bitcoin documentation is wrong or outdated here,
            // so this code is based on the `zcashd` implementation at:
            // https://github.com/zcash/zcash/blob/1a7c2a3b04bcad6549be6d571bfdff8af9a2c814/src/main.cpp#L722
            if block_height > unlock_height {
                Ok(())
            } else {
                Err(TransactionError::LockedUntilAfterBlockHeight(unlock_height))
            }
        }
        Some(LockTime::Time(unlock_time)) => {
            // > The transaction can be added to any block whose block time is greater than the locktime.
            // https://developer.bitcoin.org/devguide/transactions.html#locktime-and-sequence-number
            if block_time > unlock_time {
                Ok(())
            } else {
                Err(TransactionError::LockedUntilAfterBlockTime(unlock_time))
            }
        }
        None => Ok(()),
    }
}


/// This function should match `komodod` function here: https://github.com/KomodoPlatform/komodo/blob/master/src/main.cpp#L924
///
/// Main rules:
///
/// 1. If nLockTime tx field set to 0 - it's final.
/// 2. If nLockTime < nBlockHeight or nBlockTime (consider "apples are apples", mean that nLockTime represented the Height compare only
///    with Height, and nLockTime represented Time, compare only with Time values) - tx is also considered to be final.
/// 3. If all vins have 0xFFFFFFFF sequence tx is considered to be final regardless of nLockTime fields.
/// 4. And finally, there is a some historical Komodo exceptions for vins with sequence == 0xFFFFFFFE, depends on komodo_hardfork_active.

pub fn is_final_tx_komodo(
    network: Network,
    tx: &Transaction,
    block_height: Height,
    block_time: DateTime<Utc>,
) -> Result<(), TransactionError> {

    if let Some(lock_time) = tx.raw_lock_time() {

        if lock_time == LockTime::unlocked() {
            return Ok(());
        }

        match lock_time {
            LockTime::Height(unlock_height) => {
                if unlock_height < block_height {
                    return Ok(())
                }
            },
            LockTime::Time(unlock_time) => {
                if unlock_time < block_time {
                    return Ok(())
                }
            }
        }

        // in `komodod` HF check is implemented in komodo_hardfork_active function, but for KMD coin
        // this check is implemented like chainActive.Height() > nDecemberHardforkHeight), where
        // chain.Tip() ? chain.Tip()->nHeight : -1. In other words, it always compared with the
        // height of a last tip (!), i.e. one block before block being validated.

        let validation_height = block_height - 1;
        let hf_active = if let Some(ht) = validation_height {
            NN::komodo_s1_december_hardfork_active(network, &ht)
        } else {
            false
        };

        // now let's analyze tx vins
        let tx_is_non_final = tx
            .inputs()
            .iter()
            .map(transparent::Input::sequence)
            .any(|sequence_number| {

                // this closure should return true if vin is "non-final" (it's sequence != u32::MAX
                // and it doesn't satisfied other komodo exceptions)

                // f_exception is true, when nLockTime > (nBlockTime or nBlockHeight)
                let f_exception = match lock_time {
                    LockTime::Height(unlock_height) => unlock_height > block_height,
                    LockTime::Time(unlock_time) => unlock_time > block_time
                };

                if !hf_active && sequence_number == u32::MAX - 1 && f_exception
                {
                    false
                } else if hf_active && sequence_number == u32::MAX - 1 && !f_exception
                {
                    false
                } else {
                    sequence_number != u32::MAX
                }
            });

        if tx_is_non_final {
            return match lock_time {
                LockTime::Height(unlock_height) => Err(TransactionError::LockedUntilAfterBlockHeight(unlock_height)),
                LockTime::Time(unlock_time) => Err(TransactionError::LockedUntilAfterBlockTime(unlock_time)),
            };
        }
    }

    // if tx.raw_lock_time() returned None it means that tx.lock_time == LockTime::unlocked(), i.e.
    // LockTime::Height(block::Height(0)), and in this case tx also considered to be final.

    Ok(())

}

/// Checks that the transaction has inputs and outputs.
///
/// # Consensus
///
/// For `Transaction::V4`:
///
/// > [Sapling onward] If effectiveVersion < 5, then at least one of
/// > tx_in_count, nSpendsSapling, and nJoinSplit MUST be nonzero.
///
/// > [Sapling onward] If effectiveVersion < 5, then at least one of
/// > tx_out_count, nOutputsSapling, and nJoinSplit MUST be nonzero.
///
/// For `Transaction::V5`:
///
/// > [NU5 onward] If effectiveVersion >= 5 then this condition MUST hold:
/// > tx_in_count > 0 or nSpendsSapling > 0 or (nActionsOrchard > 0 and enableSpendsOrchard = 1).
///
/// > [NU5 onward] If effectiveVersion >= 5 then this condition MUST hold:
/// > tx_out_count > 0 or nOutputsSapling > 0 or (nActionsOrchard > 0 and enableOutputsOrchard = 1).
///
/// <https://zips.z.cash/protocol/protocol.pdf#txnconsensus>
///
/// This check counts both `Coinbase` and `PrevOut` transparent inputs.
pub fn has_inputs_and_outputs(tx: &Transaction) -> Result<(), TransactionError> {
    if !tx.has_transparent_or_shielded_inputs() {
        Err(TransactionError::NoInputs)
    } else if !tx.has_transparent_or_shielded_outputs() {
        Err(TransactionError::NoOutputs)
    } else {
        Ok(())
    }
}

/// Checks that the transaction has enough orchard flags.
///
/// # Consensus
///
/// For `Transaction::V5` only:
///
/// > [NU5 onward] If effectiveVersion >= 5 and nActionsOrchard > 0, then at least one of enableSpendsOrchard and enableOutputsOrchard MUST be 1.
///
/// <https://zips.z.cash/protocol/protocol.pdf#txnconsensus>
pub fn has_enough_orchard_flags(tx: &Transaction) -> Result<(), TransactionError> {
    if !tx.has_enough_orchard_flags() {
        return Err(TransactionError::NotEnoughFlags);
    }
    Ok(())
}

/// Check that a coinbase transaction has no PrevOut inputs, JoinSplits, or spends.
///
/// # Consensus
///
/// > A coinbase transaction MUST NOT have any JoinSplit descriptions.
///
/// > A coinbase transaction MUST NOT have any Spend descriptions.
///
/// > [NU5 onward] In a version 5 coinbase transaction, the enableSpendsOrchard flag MUST be 0.
///
/// This check only counts `PrevOut` transparent inputs.
///
/// > [Pre-Heartwood] A coinbase transaction also MUST NOT have any Output descriptions.
///
/// Zebra does not validate this last rule explicitly because we checkpoint until Canopy activation.
///
/// <https://zips.z.cash/protocol/protocol.pdf#txnconsensus>
pub fn coinbase_tx_no_prevout_joinsplit_spend(tx: &Transaction) -> Result<(), TransactionError> {
    if tx.is_coinbase() {
        if tx.joinsplit_count() > 0 {
            return Err(TransactionError::CoinbaseHasJoinSplit);
        } else if tx.sapling_spends_per_anchor().count() > 0 {
            return Err(TransactionError::CoinbaseHasSpend);
        }

        if let Some(orchard_shielded_data) = tx.orchard_shielded_data() {
            if orchard_shielded_data.flags.contains(Flags::ENABLE_SPENDS) {
                return Err(TransactionError::CoinbaseHasEnableSpendsOrchard);
            }
        }
    }

    Ok(())
}
/// Combined `komodo_check_deposit` and `komodo_checkopret` implementation.
///
/// - <https://github.com/KomodoPlatform/komodo/blob/master/src/main.cpp#L5273>
/// - <https://github.com/KomodoPlatform/komodo/blob/master/src/main.cpp#L5144-L5157>
///
/// Take into account that banned tx check distinquished into a separate check: `tx_has_banned_inputs` and
/// not a part of `komodo_check_deposit_and_opret`.
pub fn komodo_check_deposit_and_opret(tx: &Transaction, spent_utxos: &HashMap<transparent::OutPoint, transparent::Utxo>,
                            last_tx_verify_data: &LastTxDataVerify, network: Network, req_height: Height) -> Result<(), TransactionError> {
    let activation = block::Height(235_300);

    let mut not_matched: bool = false;
    let mut nn_id: Option<u32> = None;
    let mut notary_pk = None;

    let (coinbase, req_nbits, merkle_opret) = last_tx_verify_data;

    // as we have coinbase passed, then tx - is a last tx of a block here,
    // first vout of last have 0.00005 KMD value and it's produced from single vin
    if tx.outputs().first().map_or(false, |out| i64::from(out.value) == 5000)
        && tx.inputs().len() == 1
    {
        if let Some(vin) = tx.inputs().first() {

            let prev_output = match vin {
                transparent::Input::PrevOut { outpoint, .. } => {
                    spent_utxos.get(outpoint).map(|utxo| &utxo.output)
                },
                _ => None
            };

            if let Some(prev_out) = prev_output {
                if coinbase.outputs().first().map_or(false, |coinbase_vout_0| coinbase_vout_0.lock_script == prev_out.lock_script) {
                    not_matched = true;
                    notary_pk = parse_p2pk(&prev_out.lock_script);
                }
            }

            nn_id = notary_pk.and_then(|nn_pk| NN::komodo_get_notary_id(network, &req_height, &nn_pk).map_or(None, |id| id));
        }
    }

    let sapling_activation_height = NetworkUpgrade::Sapling
        .activation_height(network)
        .expect("Sapling activation height is specified");

    if req_height >= sapling_activation_height {

        // coinbase vouts check ... yes, kind of strange to do these checks on the last tx in the block check, but as
        // the result depends on not_matched value, which could be calculated only on verify of last tx in a block, we
        // will do these checks here

        let strangeout = coinbase.outputs().iter().skip(2).filter(|out| {
            let raw_script = out.lock_script.as_raw_bytes();
            !raw_script.is_empty() && raw_script[0] != 0x6a && i64::from(out.value) < 5000
        }).count();

        // let total = coinbase.outputs().iter().skip(1).fold(Amount::zero(), |acc, out| (acc + out.value).expect("sum of coinbase outputs should be ok"));
        let mut overflow = false;
        let total: Amount<NonNegative> = coinbase
            .outputs()
            .iter()
            .skip(1)
            .map(|o| o.value())
            .sum::<Result<Amount<NonNegative>, AmountError>>()
            .unwrap_or_else(|_| {
                overflow = true;
                Amount::zero()
            });

        let tx_hash = tx.hash();
        let pubkey_hash = notary_pk.map(|v| v.serialize().iter().map(|b| format!("{:02x}", b).to_string()).collect::<Vec<String>>().join(""));
        tracing::debug!(?tx_hash, ?not_matched, ?nn_id, ?pubkey_hash, ?total, "komodo_check_deposit_and_opret");

        if overflow || i64::from(total) > COIN/10 {
            if req_height > activation {
                //illegal nonz output
                return Err(TransactionError::IllegalCoinbaseOutput {
                    block_height: req_height,
                    coinbase_hash: coinbase.hash(),
                });
            }
        } else {
            let mindiff = ExpandedDifficulty::target_difficulty_limit(network).to_compact(); // 0x200f0f0f for mainnet
            // https://github.com/KomodoPlatform/komodo/blob/master/src/komodo_gateway.cpp#L773
            if *req_nbits == mindiff && i64::from(total) > 0 && NN::komodo_notaries_height1_reached(network, &req_height) {
                // "deal with fee stealing" komodod rule, actually it's incorrect, bcz block.nBits == KOMODO_MINDIFF_NBITS
                // rule doesn't mean notary mined block, it was a mistake, but it's in history now.
                return Err(TransactionError::IllegalCoinbaseOutput {
                    block_height: req_height,
                    coinbase_hash: coinbase.hash(),
                });
            }
        }

        // TODO: simplify checking code below based on the following conditions (at present it's just line-by-line repeats komodod sources)
        //
        // 1. strangeouts in coinbase not allowed when ht. > 1_000_000
        // 2. if notaryproof tx vin lock_script matches coinbase lock_script - it's Ok anytime
        // 3. if notaryproof tx vin lock_script not match coinbase lock_script and is notary mined block, and height > 1_000_000 - it's illegal

        if strangeout != 0 || not_matched {
            if req_height > block::Height(1_000_000) && strangeout != 0 {
                return Err(TransactionError::CoinbaseStrangeOutput {
                    block_height: req_height,
                    coinbase_hash: coinbase.hash(),
                });
            }
        } else if req_height > block::Height(814_000) {
            // strangeout == 0 && not_matched == false case
            if nn_id.is_some() && req_height > block::Height(1_000_000) {
                return Err(TransactionError:: NotaryProofNotMatched {
                    block_height: req_height,
                    transaction_hash: tx.hash(),
                    coinbase_hash: coinbase.hash(),
                });
            }
        }
    }

    // https://github.com/KomodoPlatform/komodo/blob/master/src/main.cpp#L5144-L5157
    //
    // Consensus rule for easy-mined (notary-mined) blocks:
    //
    // Notaryvin spend transactions beginning at a certain block height should include an OP_RETURN
    // with a merkleroot composed of the hash of the previous block and the hashes of all the transactions
    // in this notary-mined (easy-mined) block, excluding the notaryvin spend transaction itself.

    if NN::komodo_s1_december_hardfork_active(network, &req_height) {
        if let Some(notaryid) = nn_id {
            if notaryid > 0 || (notaryid == 0 && NN::komodo_s5_hardfork_active(network, &req_height)) {
                // komodo_checkopret - https://github.com/KomodoPlatform/komodo/blob/master/src/komodo_bitcoind.cpp#L638-L642

                let mut merkle_raw_bytes = [0u8; 32];
                let mut merkle_in_tx = block::merkle::Root(merkle_raw_bytes);

                let lock_script_valid = tx.outputs().last().map_or(false, |out| {
                    let lsr = out.lock_script.as_raw_bytes(); // lock script raw
                    if lsr.len() == 34 && lsr[0] == 0x6A && lsr[1] == 32 {

                        merkle_raw_bytes.clone_from_slice(&lsr[2..34]);
                        merkle_in_tx = block::merkle::Root(merkle_raw_bytes);

                        *merkle_opret == merkle_in_tx

                    } else {
                        false
                    }
                });

                // println!("ht.{:?} tx.{:?} - expected_root.{:?}, opret_root.{:?} -> lock_script_valid.{:?}", req_height, tx.hash(), merkle_opret, merkle_in_tx, lock_script_valid);
                if !lock_script_valid {
                    // failed-merkle-opret-in-easy-mined
                    return Err(
                        TransactionError::FailedMerkleOpretInEasyMined { block_height: req_height, transaction_hash: tx.hash(), expected_root: *merkle_opret, opret_root: merkle_in_tx }
                    );
                }
            }
        }
    }

    Ok(())
}

/// Check if tx has banned inputs, see CheckTransaction and komodo_bannedset + komodo_checkvout calls.
///
/// <https://github.com/KomodoPlatform/komodo/blob/master/src/main.cpp#L1362>

pub fn tx_has_banned_inputs(tx: &Transaction) -> Result<(), TransactionError> {

    let banned_txids_1: Vec<transaction::Hash> = [
        "78cb4e21245c26b015b888b14c4f5096e18137d2741a6de9734d62b07014dfca", // vout1 only 233559
        "00697be658e05561febdee1aafe368b821ca33fbb89b7027365e3d77b5dfede5", //234172
        "e909465788b32047c472d73e882d79a92b0d550f90be008f76e1edaee6d742ea", //234187
        "f56c6873748a327d0b92b8108f8ec8505a2843a541b1926022883678fb24f9dc", //234188
        "abf08be07d8f5b3a433ddcca7ef539e79a3571632efd6d0294ec0492442a0204", //234213
        "3b854b996cc982fba8c06e76cf507ae7eed52ab92663f4c0d7d10b3ed879c3b0", //234367
        "fa9e474c2cda3cb4127881a40eb3f682feaba3f3328307d518589024a6032cc4", //234635
        "ca746fa13e0113c4c0969937ea2c66de036d20274efad4ce114f6b699f1bc0f3", //234662
        "43ce88438de4973f21b1388ffe66e68fda592da38c6ef939be10bb1b86387041", //234697
        "0aeb748de82f209cd5ff7d3a06f65543904c4c17387c9d87c65fd44b14ad8f8c", //234899
        "bbd3a3d9b14730991e1066bd7c626ca270acac4127131afe25f877a5a886eb25", //235252
        "fa9943525f2e6c32cbc243294b08187e314d83a2870830180380c3c12a9fd33c", //235253
        "a01671c8775328a41304e31a6693bbd35e9acbab28ab117f729eaba9cb769461", //235265
        "2ef49d2d27946ad7c5d5e4ab5c089696762ff04e855f8ab48e83bdf0cc68726d", //235295
        "c85dcffb16d5a45bd239021ad33443414d60224760f11d535ae2063e5709efee",
    ].iter().map(|str| str.parse::<transaction::Hash>().expect("hash should parse correctly")).collect();

    let banned_txids_all: Vec<transaction::Hash> = [
        "c4ea1462c207547cd6fb6a4155ca6d042b22170d29801a465db5c09fec55b19d", //246748
        "305dc96d8bc23a69d3db955e03a6a87c1832673470c32fe25473a46cc473c7d1", //247204
    ].iter().map(|str| str.parse::<transaction::Hash>().expect("hash should parse correctly")).collect();

    // check if tx contains banned inputs
    if tx.inputs().iter().any(|input| {
        if let Some(vin) = input.outpoint() {
            (banned_txids_1.contains(&vin.hash) && vin.index == 1) || banned_txids_all.contains(&vin.hash)
        } else {
            false
        }
    }) {
        return Err(TransactionError::BannedInputs);
    };

    Ok(())
}

/// Check if JoinSplits in the transaction have one of its v_{pub} values equal
/// to zero.
///
/// <https://zips.z.cash/protocol/protocol.pdf#joinsplitdesc>
pub fn joinsplit_has_vpub_zero(tx: &Transaction) -> Result<(), TransactionError> {
    let zero = Amount::<NonNegative>::try_from(0).expect("an amount of 0 is always valid");

    let vpub_pairs = tx
        .output_values_to_sprout()
        .zip(tx.input_values_from_sprout());
    for (vpub_old, vpub_new) in vpub_pairs {
        // # Consensus
        //
        // > Either v_{pub}^{old} or v_{pub}^{new} MUST be zero.
        //
        // https://zips.z.cash/protocol/protocol.pdf#joinsplitdesc
        if *vpub_old != zero && *vpub_new != zero {
            return Err(TransactionError::BothVPubsNonZero);
        }
    }

    Ok(())
}

/// Check if a transaction is adding to the sprout pool after Canopy
/// network upgrade given a block height and a network.
///
/// <https://zips.z.cash/zip-0211>
/// <https://zips.z.cash/protocol/protocol.pdf#joinsplitdesc>
pub fn disabled_add_to_sprout_pool(
    tx: &Transaction,
    height: Height,
    network: Network,
) -> Result<(), TransactionError> {
    let canopy_activation_height = NetworkUpgrade::Canopy
        .activation_height(network)
        .expect("Canopy activation height must be present for both networks");

    // # Consensus
    //
    // > [Canopy onward]: `vpub_old` MUST be zero.
    //
    // https://zips.z.cash/protocol/protocol.pdf#joinsplitdesc
    if height >= canopy_activation_height {
        let zero = Amount::<NonNegative>::try_from(0).expect("an amount of 0 is always valid");

        let tx_sprout_pool = tx.output_values_to_sprout();
        for vpub_old in tx_sprout_pool {
            if *vpub_old != zero {
                return Err(TransactionError::DisabledAddToSproutPool);
            }
        }
    }

    Ok(())
}

/// Check if a transaction has any internal spend conflicts.
///
/// An internal spend conflict happens if the transaction spends a UTXO more than once or if it
/// reveals a nullifier more than once.
///
/// Consensus rules:
///
/// "each output of a particular transaction
/// can only be used as an input once in the block chain.
/// Any subsequent reference is a forbidden double spend-
/// an attempt to spend the same satoshis twice."
///
/// <https://developer.bitcoin.org/devguide/block_chain.html#introduction>
///
/// A _nullifier_ *MUST NOT* repeat either within a _transaction_, or across _transactions_ in a
/// _valid blockchain_ . *Sprout* and *Sapling* and *Orchard* _nulliers_ are considered disjoint,
/// even if they have the same bit pattern.
///
/// <https://zips.z.cash/protocol/protocol.pdf#nullifierset>
pub fn spend_conflicts(transaction: &Transaction) -> Result<(), TransactionError> {
    use crate::error::TransactionError::*;

    let transparent_outpoints = transaction.spent_outpoints().map(Cow::Owned);
    let sprout_nullifiers = transaction.sprout_nullifiers().map(Cow::Borrowed);
    let sapling_nullifiers = transaction.sapling_nullifiers().map(Cow::Borrowed);
    let orchard_nullifiers = transaction.orchard_nullifiers().map(Cow::Borrowed);

    check_for_duplicates(transparent_outpoints, DuplicateTransparentSpend)?;
    check_for_duplicates(sprout_nullifiers, DuplicateSproutNullifier)?;
    check_for_duplicates(sapling_nullifiers, DuplicateSaplingNullifier)?;
    check_for_duplicates(orchard_nullifiers, DuplicateOrchardNullifier)?;

    Ok(())
}

/// Check for duplicate items in a collection.
///
/// Each item should be wrapped by a [`Cow`] instance so that this helper function can properly
/// handle borrowed items and owned items.
///
/// If a duplicate is found, an error created by the `error_wrapper` is returned.
fn check_for_duplicates<'t, T>(
    items: impl IntoIterator<Item = Cow<'t, T>>,
    error_wrapper: impl FnOnce(T) -> TransactionError,
) -> Result<(), TransactionError>
where
    T: Clone + Eq + Hash + 't,
{
    let mut hash_set = HashSet::new();

    for item in items {
        if let Some(duplicate) = hash_set.replace(item) {
            return Err(error_wrapper(duplicate.into_owned()));
        }
    }

    Ok(())
}

/// Checks compatibility with [ZIP-212] shielded Sapling and Orchard coinbase output decryption
///
/// Pre-Heartwood: returns `Ok`.
/// Heartwood-onward: returns `Ok` if all Sapling or Orchard outputs, if any, decrypt successfully with
/// an all-zeroes outgoing viewing key. Returns `Err` otherwise.
///
/// This is used to validate coinbase transactions:
///
/// # Consensus
///
/// > [Heartwood onward] All Sapling and Orchard outputs in coinbase transactions MUST decrypt to a note
/// > plaintext, i.e. the procedure in § 4.19.3 ‘Decryption using a Full Viewing Key ( Sapling and Orchard )’ on p. 67
/// > does not return ⊥, using a sequence of 32 zero bytes as the outgoing viewing key. (This implies that before
/// > Canopy activation, Sapling outputs of a coinbase transaction MUST have note plaintext lead byte equal to
/// > 0x01.)
///
/// > [Canopy onward] Any Sapling or Orchard output of a coinbase transaction decrypted to a note plaintext
/// > according to the preceding rule MUST have note plaintext lead byte equal to 0x02. (This applies even during
/// > the "grace period" specified in [ZIP-212].)
///
/// <https://zips.z.cash/protocol/protocol.pdf#txnconsensus>
///
/// [ZIP-212]: https://zips.z.cash/zip-0212#consensus-rule-change-for-coinbase-transactions
///
/// TODO: Currently, a 0x01 lead byte is allowed in the "grace period" mentioned since we're
/// using `librustzcash` to implement this and it doesn't currently allow changing that behavior.
/// <https://github.com/ZcashFoundation/zebra/issues/3027>
pub fn coinbase_outputs_are_decryptable(
    transaction: &Transaction,
    network: Network,
    height: Height,
) -> Result<(), TransactionError> {
    // The consensus rule only applies to Heartwood onward.
    if height
        < NetworkUpgrade::Heartwood
            .activation_height(network)
            .expect("Heartwood height is known")
    {
        return Ok(());
    }

    if !zcash_note_encryption::decrypts_successfully(transaction, network, height) {
        return Err(TransactionError::CoinbaseOutputsNotDecryptable);
    }

    Ok(())
}

/// Returns `Ok(())` if the expiry height for the coinbase transaction is valid
/// according to specifications [7.1] and [ZIP-203].
///
/// [7.1]: https://zips.z.cash/protocol/protocol.pdf#txnencodingandconsensus
/// [ZIP-203]: https://zips.z.cash/zip-0203
pub fn coinbase_expiry_height(
    block_height: &Height,
    coinbase: &Transaction,
    network: Network,
) -> Result<(), TransactionError> {
    let expiry_height = coinbase.expiry_height();

    // TODO: replace `if let` with `expect` after NU5 mainnet activation
    if let Some(nu5_activation_height) = NetworkUpgrade::Nu5.activation_height(network) {
        // # Consensus
        //
        // > [NU5 onward] The nExpiryHeight field of a coinbase transaction
        // > MUST be equal to its block height.
        //
        // <https://zips.z.cash/protocol/protocol.pdf#txnconsensus>
        if *block_height >= nu5_activation_height {
            if expiry_height != Some(*block_height) {
                return Err(TransactionError::CoinbaseExpiryBlockHeight {
                    expiry_height,
                    block_height: *block_height,
                    transaction_hash: coinbase.hash(),
                });
            } else {
                return Ok(());
            }
        }
    }

    // # Consensus
    //
    // > [Overwinter to Canopy inclusive, pre-NU5] nExpiryHeight MUST be less than
    // > or equal to 499999999.
    //
    // <https://zips.z.cash/protocol/protocol.pdf#txnconsensus>
    validate_expiry_height_max(expiry_height, true, block_height, coinbase)
}

/// Returns `Ok(())` if the expiry height for a non coinbase transaction is
/// valid according to specifications [7.1] and [ZIP-203].
///
/// [7.1]: https://zips.z.cash/protocol/protocol.pdf#txnencodingandconsensus
/// [ZIP-203]: https://zips.z.cash/zip-0203
pub fn non_coinbase_expiry_height(
    block_height: &Height,
    transaction: &Transaction,
) -> Result<(), TransactionError> {
    if transaction.is_overwintered() {
        let expiry_height = transaction.expiry_height();

        // # Consensus
        //
        // > [Overwinter to Canopy inclusive, pre-NU5] nExpiryHeight MUST be
        // > less than or equal to 499999999.
        //
        // > [NU5 onward] nExpiryHeight MUST be less than or equal to 499999999
        // > for non-coinbase transactions.
        //
        // <https://zips.z.cash/protocol/protocol.pdf#txnconsensus>
        validate_expiry_height_max(expiry_height, false, block_height, transaction)?;

        // # Consensus
        //
        // > [Overwinter onward] If a transaction is not a coinbase transaction and its
        // > nExpiryHeight field is nonzero, then it MUST NOT be mined at a block
        // > height greater than its nExpiryHeight.
        //
        // <https://zips.z.cash/protocol/protocol.pdf#txnconsensus>
        validate_expiry_height_mined(expiry_height, block_height, transaction)?;
    }
    Ok(())
}

/// Checks that the expiry height of a transaction does not exceed the maximal
/// value.
///
/// Only the `expiry_height` parameter is used for the check. The
/// remaining parameters are used to give details about the error when the check
/// fails.
fn validate_expiry_height_max(
    expiry_height: Option<Height>,
    is_coinbase: bool,
    block_height: &Height,
    transaction: &Transaction,
) -> Result<(), TransactionError> {
    if let Some(expiry_height) = expiry_height {
        if expiry_height > Height::MAX_EXPIRY_HEIGHT {
            return Err(TransactionError::MaximumExpiryHeight {
                expiry_height,
                is_coinbase,
                block_height: *block_height,
                transaction_hash: transaction.hash(),
            })?;
        }
    }

    Ok(())
}

/// Checks that a transaction does not exceed its expiry height.
///
/// The `transaction` parameter is only used to give details about the error
/// when the check fails.
fn validate_expiry_height_mined(
    expiry_height: Option<Height>,
    block_height: &Height,
    transaction: &Transaction,
) -> Result<(), TransactionError> {
    if let Some(expiry_height) = expiry_height {
        if *block_height > expiry_height {
            return Err(TransactionError::ExpiredTransaction {
                expiry_height,
                block_height: *block_height,
                transaction_hash: transaction.hash(),
            })?;
        }
    }

    Ok(())
}
