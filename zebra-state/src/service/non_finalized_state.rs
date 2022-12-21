//! Non-finalized chain state management as defined by [RFC0005]
//!
//! [RFC0005]: https://zebra.zfnd.org/dev/rfcs/0005-state-updates.html

use std::{
    collections::{BTreeSet, HashMap},
    mem,
    sync::Arc,
};

use zebra_chain::{
    block::{self, Block},
    history_tree::HistoryTree,
    orchard,
    parameters::Network,
    sapling, sprout, transparent::{self, outputs_from_utxos, utxos_from_ordered_utxos},
};

use crate::komodo_notaries::{BackNotarisationData, komodo_block_has_notarisation_tx};

use crate::{
    request::ContextuallyValidBlock,
    service::{check, finalized_state::ZebraDb},
    FinalizedBlock, PreparedBlock, ValidateContextError
};

mod chain;
mod queued_blocks;

#[cfg(test)]
mod tests;

pub use queued_blocks::QueuedBlocks;

pub(crate) use chain::Chain;

/// The state of the chains in memory, including queued blocks.
#[derive(Debug, Clone)]
pub struct NonFinalizedState {
    /// Verified, non-finalized chains, in ascending order.
    ///
    /// The best chain is `chain_set.last()` or `chain_set.iter().next_back()`.
    pub chain_set: BTreeSet<Arc<Chain>>,

    /// The configured Zcash network.
    //
    // Note: this field is currently unused, but it's useful for debugging.
    pub network: Network,

    pub last_nota: Option<BackNotarisationData>,
}

impl NonFinalizedState {
    /// Returns a new non-finalized state for `network`.
    pub fn new(network: Network) -> NonFinalizedState {
        NonFinalizedState {
            chain_set: Default::default(),
            network,
            last_nota: None,
        }
    }

    /// Is the internal state of `self` the same as `other`?
    ///
    /// [`Chain`] has a custom [`Eq`] implementation based on proof of work,
    /// which is used to select the best chain. So we can't derive [`Eq`] for [`NonFinalizedState`].
    ///
    /// Unlike the custom trait impl, this method returns `true` if the entire internal state
    /// of two non-finalized states is equal.
    ///
    /// If the internal states are different, it returns `false`,
    /// even if the chains and blocks are equal.
    #[cfg(test)]
    pub(crate) fn eq_internal_state(&self, other: &NonFinalizedState) -> bool {
        // this method must be updated every time a field is added to NonFinalizedState

        self.chain_set.len() == other.chain_set.len()
            && self
                .chain_set
                .iter()
                .zip(other.chain_set.iter())
                .all(|(self_chain, other_chain)| self_chain.eq_internal_state(other_chain))
            && self.network == other.network
    }

    /// Finalize the lowest height block in the non-finalized portion of the best
    /// chain and update all side-chains to match.
    pub fn finalize(&mut self) -> FinalizedBlock {
        // Chain::cmp uses the partial cumulative work, and the hash of the tip block.
        // Neither of these fields has interior mutability.
        // (And when the tip block is dropped for a chain, the chain is also dropped.)
        #[allow(clippy::mutable_key_type)]
        let chains = mem::take(&mut self.chain_set);
        let mut chains = chains.into_iter();

        // extract best chain
        let mut best_chain = chains.next_back().expect("there's at least one chain");
        // clone if required
        let write_best_chain = Arc::make_mut(&mut best_chain);

        // extract the rest into side_chains so they can be mutated
        let side_chains = chains;

        // remove the lowest height block from the best_chain to be finalized
        let finalizing = write_best_chain.pop_root();

        // add best_chain back to `self.chain_set`
        if !best_chain.is_empty() {
            self.chain_set.insert(best_chain);
        }

        // for each remaining chain in side_chains
        for mut chain in side_chains {
            if chain.non_finalized_root_hash() != finalizing.hash {
                // If we popped the root, the chain would be empty or orphaned,
                // so just drop it now.
                drop(chain);

                continue;
            }

            // otherwise, the popped root block is the same as the finalizing block

            // clone if required
            let write_chain = Arc::make_mut(&mut chain);

            // remove the first block from `chain`
            let chain_start = write_chain.pop_root();
            assert_eq!(chain_start.hash, finalizing.hash);

            // add the chain back to `self.chain_set`
            self.chain_set.insert(chain);
        }

        self.update_metrics_for_chains();

        finalizing.into()
    }

    /// Commit block to the non-finalized state, on top of:
    /// - an existing chain's tip, or
    /// - a newly forked chain.
    #[tracing::instrument(level = "debug", skip(self, finalized_state, prepared))]
    pub fn commit_block(
        &mut self,
        prepared: PreparedBlock,
        finalized_state: &ZebraDb,
    ) -> Result<(), ValidateContextError> {
        let parent_hash = prepared.block.header.previous_block_hash;
        let (height, hash) = (prepared.height, prepared.hash);

        let parent_chain = self.parent_chain(
            parent_hash,
            finalized_state.sprout_note_commitment_tree(),
            finalized_state.sapling_note_commitment_tree(),
            finalized_state.orchard_note_commitment_tree(),
            finalized_state.history_tree(),
        )?;

        // If the block is invalid, return the error,
        // and drop the cloned parent Arc, or newly created chain fork.
        let modified_chain = self.validate_and_commit(parent_chain, prepared, finalized_state)?;

        self.komodo_check_fork_is_valid(&modified_chain)?;

        // If the block is valid:
        // - add the new chain fork or updated chain to the set of recent chains
        // - remove the parent chain, if it was in the chain set
        //   (if it was a newly created fork, it won't be in the chain set)
        self.chain_set.insert(modified_chain);
        self.chain_set
            .retain(|chain| chain.non_finalized_tip_hash() != parent_hash);

        self.update_metrics_for_committed_block(height, hash);

        Ok(())
    }

    /// Commit block to the non-finalized state as a new chain where its parent
    /// is the finalized tip.
    #[tracing::instrument(level = "debug", skip(self, finalized_state, prepared))]
    pub fn commit_new_chain(
        &mut self,
        prepared: PreparedBlock,
        finalized_state: &ZebraDb,
    ) -> Result<(), ValidateContextError> {
        let chain = Chain::new(
            self.network,
            finalized_state.sprout_note_commitment_tree(),
            finalized_state.sapling_note_commitment_tree(),
            finalized_state.orchard_note_commitment_tree(),
            finalized_state.history_tree(),
            finalized_state.finalized_value_pool(),
        );
        let (height, hash) = (prepared.height, prepared.hash);

        // If the block is invalid, return the error, and drop the newly created chain fork
        let chain = self.validate_and_commit(Arc::new(chain), prepared, finalized_state)?;

        self.komodo_check_fork_is_valid(&chain)?;

        // If the block is valid, add the new chain fork to the set of recent chains.
        self.chain_set.insert(chain);
        self.update_metrics_for_committed_block(height, hash);

        Ok(())
    }

    /// Contextually validate `prepared` using `finalized_state`.
    /// If validation succeeds, push `prepared` onto `new_chain`.
    ///
    /// `new_chain` should start as a clone of the parent chain fork,
    /// or the finalized tip.
    #[tracing::instrument(level = "debug", skip(self, finalized_state, new_chain))]
    fn validate_and_commit(
        &mut self,  // TODO remove mut when last_nota moved to channel
        new_chain: Arc<Chain>,
        prepared: PreparedBlock,
        finalized_state: &ZebraDb,
    ) -> Result<Arc<Chain>, ValidateContextError> {
        // Reads from disk
        //
        let last_block_time = if let Some(tip) = new_chain.tip_block() { Some(tip.block.header.time) } else { None };
        // TODO: if these disk reads show up in profiles, run them in parallel, using std::thread::spawn()
        let spent_utxos = check::utxo::transparent_spend(
            new_chain.network(),
            &prepared,
            last_block_time,
            &new_chain.unspent_utxos(),
            &new_chain.spent_utxos,
            finalized_state,
        )?;

        // Reads from disk
        check::anchors::sapling_orchard_anchors_refer_to_final_treestates(
            finalized_state,
            &new_chain,
            &prepared,
        )?;

        // Reads from disk
        let sprout_final_treestates =
            check::anchors::fetch_sprout_final_treestates(finalized_state, &new_chain, &prepared);

        // Quick check that doesn't read from disk
        let contextual = ContextuallyValidBlock::with_block_and_spent_utxos(
            new_chain.network(),
            prepared.clone(),
            last_block_time,
            spent_utxos.clone(),
        )
        .map_err(|value_balance_error| {
            ValidateContextError::CalculateBlockChainValueChange {
                value_balance_error,
                height: prepared.height,
                block_hash: prepared.hash,
                transaction_count: prepared.block.transactions.len(),
                spent_utxo_count: spent_utxos.len(),
            }
        })?;

        let spent_outputs = outputs_from_utxos(utxos_from_ordered_utxos(spent_utxos));
        self.komodo_find_block_nota_and_update_last(&prepared.block, &spent_outputs, &prepared.height);

        Self::validate_and_update_parallel(new_chain, contextual, sprout_final_treestates)
    }

    /// Validate `contextual` and update `new_chain`, doing CPU-intensive work in parallel batches.
    #[allow(clippy::unwrap_in_result)]
    #[tracing::instrument(skip(new_chain, sprout_final_treestates))]
    fn validate_and_update_parallel(
        new_chain: Arc<Chain>,
        contextual: ContextuallyValidBlock,
        sprout_final_treestates: HashMap<sprout::tree::Root, Arc<sprout::tree::NoteCommitmentTree>>,
    ) -> Result<Arc<Chain>, ValidateContextError> {
        let mut block_commitment_result = None;
        let mut sprout_anchor_result = None;
        let mut chain_push_result = None;

        // Clone function arguments for different threads
        let block = contextual.block.clone();
        let network = new_chain.network();
        let history_tree = new_chain.history_tree.clone();

        let block2 = contextual.block.clone();
        let height = contextual.height;
        let transaction_hashes = contextual.transaction_hashes.clone();

        rayon::in_place_scope_fifo(|scope| {
            scope.spawn_fifo(|_scope| {
                block_commitment_result = Some(check::block_commitment_is_valid_for_chain_history(
                    block,
                    network,
                    &history_tree,
                ));
            });

            scope.spawn_fifo(|_scope| {
                sprout_anchor_result = Some(check::anchors::sprout_anchors_refer_to_treestates(
                    sprout_final_treestates,
                    block2,
                    height,
                    transaction_hashes,
                ));
            });

            // We're pretty sure the new block is valid,
            // so clone the inner chain if needed, then add the new block.
            //
            // Pushing a block onto a Chain can launch additional parallel batches.
            // TODO: should we pass _scope into Chain::push()?
            scope.spawn_fifo(|_scope| {
                let new_chain = Arc::try_unwrap(new_chain)
                    .unwrap_or_else(|shared_chain| (*shared_chain).clone());
                chain_push_result = Some(new_chain.push(contextual).map(Arc::new));
            });
        });

        // Don't return the updated Chain unless all the parallel results were Ok
        block_commitment_result.expect("scope has finished")?;
        sprout_anchor_result.expect("scope has finished")?;

        chain_push_result.expect("scope has finished")
    }

    /// Returns the length of the non-finalized portion of the current best chain.
    pub fn best_chain_len(&self) -> u32 {
        self.best_chain()
            .expect("only called after inserting a block")
            .blocks
            .len() as u32
    }

    /// Returns `true` if `hash` is contained in the non-finalized portion of any
    /// known chain.
    pub fn any_chain_contains(&self, hash: &block::Hash) -> bool {
        self.chain_set
            .iter()
            .rev()
            .any(|chain| chain.height_by_hash.contains_key(hash))
    }

    /// Removes and returns the first chain satisfying the given predicate.
    ///
    /// If multiple chains satisfy the predicate, returns the chain with the highest difficulty.
    /// (Using the tip block hash tie-breaker.)
    fn find_chain<P>(&mut self, mut predicate: P) -> Option<&Arc<Chain>>
    where
        P: FnMut(&Chain) -> bool,
    {
        // Reverse the iteration order, to find highest difficulty chains first.
        self.chain_set.iter().rev().find(|chain| predicate(chain))
    }

    /// Returns the [`transparent::Utxo`] pointed to by the given
    /// [`transparent::OutPoint`] if it is present in any chain.
    pub fn any_utxo(&self, outpoint: &transparent::OutPoint) -> Option<transparent::Utxo> {
        for chain in self.chain_set.iter().rev() {
            if let Some(utxo) = chain.created_utxos.get(outpoint) {
                return Some(utxo.utxo.clone());
            }
        }

        None
    }

    /// Returns the `block` with the given hash in any chain.
    pub fn any_block_by_hash(&self, hash: block::Hash) -> Option<Arc<Block>> {
        for chain in self.chain_set.iter().rev() {
            if let Some(prepared) = chain
                .height_by_hash
                .get(&hash)
                .and_then(|height| chain.blocks.get(height))
            {
                return Some(prepared.block.clone());
            }
        }

        None
    }

    /// Returns the hash for a given `block::Height` if it is present in the best chain.
    pub fn best_hash(&self, height: block::Height) -> Option<block::Hash> {
        self.best_chain()?
            .blocks
            .get(&height)
            .map(|prepared| prepared.hash)
    }

    /// Returns the tip of the best chain.
    pub fn best_tip(&self) -> Option<(block::Height, block::Hash)> {
        let best_chain = self.best_chain()?;
        let height = best_chain.non_finalized_tip_height();
        let hash = best_chain.non_finalized_tip_hash();

        Some((height, hash))
    }

    /// Returns the block at the tip of the best chain.
    #[allow(dead_code)]
    pub fn best_tip_block(&self) -> Option<&ContextuallyValidBlock> {
        let best_chain = self.best_chain()?;

        best_chain.tip_block()
    }

    /// Returns the height of `hash` in the best chain.
    pub fn best_height_by_hash(&self, hash: block::Hash) -> Option<block::Height> {
        let best_chain = self.best_chain()?;
        let height = *best_chain.height_by_hash.get(&hash)?;
        Some(height)
    }

    /// Returns the height of `hash` in any chain.
    pub fn any_height_by_hash(&self, hash: block::Hash) -> Option<block::Height> {
        for chain in self.chain_set.iter().rev() {
            if let Some(height) = chain.height_by_hash.get(&hash) {
                return Some(*height);
            }
        }

        None
    }

    /// Returns `true` if the best chain contains `sprout_nullifier`.
    #[cfg(test)]
    pub fn best_contains_sprout_nullifier(&self, sprout_nullifier: &sprout::Nullifier) -> bool {
        self.best_chain()
            .map(|best_chain| best_chain.sprout_nullifiers.contains(sprout_nullifier))
            .unwrap_or(false)
    }

    /// Returns `true` if the best chain contains `sapling_nullifier`.
    #[cfg(test)]
    pub fn best_contains_sapling_nullifier(&self, sapling_nullifier: &sapling::Nullifier) -> bool {
        self.best_chain()
            .map(|best_chain| best_chain.sapling_nullifiers.contains(sapling_nullifier))
            .unwrap_or(false)
    }

    /// Returns `true` if the best chain contains `orchard_nullifier`.
    #[cfg(test)]
    pub fn best_contains_orchard_nullifier(&self, orchard_nullifier: &orchard::Nullifier) -> bool {
        self.best_chain()
            .map(|best_chain| best_chain.orchard_nullifiers.contains(orchard_nullifier))
            .unwrap_or(false)
    }

    /// Return the non-finalized portion of the current best chain.
    pub(crate) fn best_chain(&self) -> Option<&Arc<Chain>> {
        self.chain_set.iter().next_back()
    }

    /// Return the chain whose tip block hash is `parent_hash`.
    ///
    /// The chain can be an existing chain in the non-finalized state or a freshly
    /// created fork, if needed.
    ///
    /// The trees must be the trees of the finalized tip.
    /// They are used to recreate the trees if a fork is needed.
    #[allow(clippy::unwrap_in_result)]
    fn parent_chain(
        &mut self,
        parent_hash: block::Hash,
        sprout_note_commitment_tree: Arc<sprout::tree::NoteCommitmentTree>,
        sapling_note_commitment_tree: Arc<sapling::tree::NoteCommitmentTree>,
        orchard_note_commitment_tree: Arc<orchard::tree::NoteCommitmentTree>,
        history_tree: Arc<HistoryTree>,
    ) -> Result<Arc<Chain>, ValidateContextError> {
        match self.find_chain(|chain| chain.non_finalized_tip_hash() == parent_hash) {
            // Clone the existing Arc<Chain> in the non-finalized state
            Some(chain) => Ok(chain.clone()),
            // Create a new fork
            None => {
                // Check the lowest difficulty chains first,
                // because the fork could be closer to their tip.
                let fork_chain = self
                    .chain_set
                    .iter()
                    .find_map(|chain| {
                        chain
                            .fork(
                                parent_hash,
                                sprout_note_commitment_tree.clone(),
                                sapling_note_commitment_tree.clone(),
                                orchard_note_commitment_tree.clone(),
                                history_tree.clone(),
                            )
                            .transpose()
                    })
                    .expect(
                        "commit_block is only called with blocks that are ready to be committed",
                    )?;

                Ok(Arc::new(fork_chain))
            }
        }
    }

    /// Update the metrics after `block` is committed
    fn update_metrics_for_committed_block(&self, height: block::Height, hash: block::Hash) {
        metrics::counter!("state.memory.committed.block.count", 1);
        metrics::gauge!("state.memory.committed.block.height", height.0 as f64);

        if self
            .best_chain()
            .unwrap()
            .blocks
            .iter()
            .next_back()
            .unwrap()
            .1
            .hash
            == hash
        {
            metrics::counter!("state.memory.best.committed.block.count", 1);
            metrics::gauge!("state.memory.best.committed.block.height", height.0 as f64);
        }

        self.update_metrics_for_chains();
    }

    /// Update the metrics after `self.chain_set` is modified
    fn update_metrics_for_chains(&self) {
        metrics::gauge!("state.memory.chain.count", self.chain_set.len() as f64);
        metrics::gauge!(
            "state.memory.best.chain.length",
            self.best_chain_len() as f64,
        );
    }

    /// check if block has a back KMD nota and update latest nota in the mem state
    fn komodo_find_block_nota_and_update_last(&mut self, block: &Block, spent_outputs: &HashMap<transparent::OutPoint, transparent::Output>, height: &block::Height) {
        match (komodo_block_has_notarisation_tx(self.network, block, spent_outputs, height), self.last_nota.as_ref()) {
            (Some(found_nota), Some(last_nota)) => {
                if last_nota.notarised_height < found_nota.notarised_height {
                    info!("found update nota last notarised height={:?}", found_nota.notarised_height);
                    self.last_nota = Some(found_nota);
                }
            },
            (Some(found_nota), None) =>  {
                info!("found new nota last notarised height={:?}", found_nota.notarised_height);
                self.last_nota = Some(found_nota);
            },
            (None, _) => (),
        }
    }

    /// check if new chain is notarised and allowed to fork
    /// it should not fork below last notarised block
    pub fn komodo_check_fork_is_valid(&self, chain_with_new_block: &Chain) -> Result<(), ValidateContextError> {

        if let Some(last_nota) = &self.last_nota {
            info!("komodo_check_fork_is_valid chain_new height={:?} hash={:?} last_nota.height={:?}", chain_with_new_block.non_finalized_tip_height(), chain_with_new_block.non_finalized_tip_hash(), last_nota.notarised_height);
            if let Some(best_chain) = self.best_chain() {

                info!("komodo_check_fork_is_valid best_chain.tip={:?} hash={:?}", best_chain.non_finalized_tip_height(), best_chain.non_finalized_tip_hash());
                //info!("dimxyyy chain_with_new_block={:?}", chain_with_new_block.blocks.iter().map(|p| (p.0, p.1.hash)).collect::<Vec<_>>());
                //info!("dimxyyy best_chain={:?}", best_chain.blocks.iter().map(|p| (p.0, p.1.hash)).collect::<Vec<_>>());

                // find the fork point
                // I think it is important to start search from the tip (in rev order) 
                // as the bottom part of the chain has many common blocks with the best_chain because both grow from the finalized tip
                if let Some(fork) = chain_with_new_block.blocks.iter().rev().find(|pair| best_chain.height_by_hash.contains_key(&pair.1.hash) ) {

                    // truncate the new chain's bottom blocks below the fork point (and leave only block hashes in the top part):
                    let block_hashes_truncated = chain_with_new_block.blocks.iter()
                        .skip_while(|e| e.1 != fork.1)
                        .map(|p| (p.0, p.1.hash))
                        .collect::<Vec<_>>();
                    info!("block_hashes_truncated={:?}", block_hashes_truncated);

                    let new_has_nota = block_hashes_truncated.iter().find(|pair| pair.1 == last_nota.block_hash).is_some();
                    
                    /*
                    // suggested new algo change:
                    // if the new chain has the last nota but the best chain does not 
                    // then mark the best chain as bad and allow the new block to add
                    if new_has_nota {

                        if best_chain.blocks.iter()
                            .skip_while(|e| e.1 != fork.1)
                            .skip(1)
                            .find(|pair| pair.1.hash == last_nota.block_hash).is_some()    {
                            info!("best chain does not contain nota, marking it as bad");

                            let modified_chain = Arc::try_unwrap(new_chain)
                                .unwrap_or_else(|shared_chain| (*shared_chain).clone());
                            modified_chain.set_as_bad();  
                            self.chain_set
                                .retain(|chain| chain.non_finalized_tip_hash() != parent_hash);
                            self.chain_set.insert(modified_chain);
                            ...
                            return Ok(());
                        }
                    }
                    */


                    info!(
                        chain_with_new_block_non_fin_height = chain_with_new_block.non_finalized_tip_height().0,
                        best_chain_non_fin_height = best_chain.non_finalized_tip_height().0,
                        new_chain_has_last_nota = chain_with_new_block.height_by_hash.contains_key(&last_nota.block_hash),
                        blocks_truncated_has_last_nota = new_has_nota,
                        best_chain_tip_height_over_notarised_height = best_chain.non_finalized_tip_height() > last_nota.notarised_height,
                        is_fork_below_notarised_height = fork.0 < &last_nota.notarised_height,
                        best_chain_root_height = best_chain.non_finalized_tip_height().0,
                        fork_height = fork.0.0,
                        last_notarised_height = last_nota.notarised_height.0,
                        new_chain_has_more_power = chain_with_new_block > best_chain,
                        "komodo checking notarised height for new chain:"
                    );

                    // The condition for forks below the last notarised height:
                    // if chain_with_new_block has more work than best_chain (that is, a new best chain candidate)
                    // and chain_with_new_block does not contain the last nota
                    // and fork.height < last_nota.height
                    // and best_chain.height > last_nota.height 
                    // then do not allow this block and this fork:

                    if chain_with_new_block > best_chain &&  // new chain has more work
                        // ensure the new chain does not have nota and it is the best chain which has it
                        // !chain_with_new_block.height_by_hash.contains_key(&last_nota.block_hash)  && // this is dimxy addition to fork checking, komodod does not have this
                        best_chain.non_finalized_tip_height() > last_nota.notarised_height && // not sure why this condition is needed as assumed best chain could not exist without notas
                        fork.0 < &last_nota.notarised_height {  
                        return Err(ValidateContextError::InvalidNotarisedChain(chain_with_new_block.non_finalized_tip_hash(), chain_with_new_block.non_finalized_root().1, last_nota.notarised_height));
                    }
                }
                else {
                    // this should not happen actually
                    error!("komodo internal error: could not find fork point for chain {:?}", chain_with_new_block);
                }
            }
        }
        Ok(())
    }
}
