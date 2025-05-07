//! Gadget to enforce the integrity of the transaction data

use std::marker::PhantomData;

use ark_ff::PrimeField;
use chain_gang::{
    messages::Tx,
    script::Script,
    transaction::sighash::{SigHashCache, sighash},
};

pub mod constraints;
pub mod utils;

/// Configuration of the Transaction Integrity scheme
pub trait TransactionIntegrityConfig {
    /// The length of the locking script used to construct the sighash
    const LEN_PREV_LOCK_SCRIPT: usize;
    /// The index of the input for which we construct the sighash
    const N_INPUT: usize;
    /// The sighash flag used to construct the sighash
    const SIGHASH_FLAG: u8;
}

/// The Transaction Integrity Scheme
pub struct TransactionIntegrityScheme<P: TransactionIntegrityConfig> {
    _ti_structure: PhantomData<P>,
}

/// The Transaction Integrity Tag
#[derive(Clone, Debug, Eq, Default)]
pub struct TransactionIntegrityTag {
    pub inner: [u8; 32],
}

impl PartialEq for TransactionIntegrityTag {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl<F: PrimeField> From<TransactionIntegrityTag> for Vec<F> {
    fn from(value: TransactionIntegrityTag) -> Self {
        vec![F::from_le_bytes_mod_order(&value.inner)]
    }
}

impl<P: TransactionIntegrityConfig> TransactionIntegrityScheme<P> {
    /// Generate a tag
    pub fn commit(
        tx: &Tx,
        prev_lock_script: &Script,
        prev_amount: u64,
        sighash_cache: &mut SigHashCache,
    ) -> TransactionIntegrityTag {
        // Validate data against the configuration
        assert_eq!(
            prev_lock_script.0.len(),
            P::LEN_PREV_LOCK_SCRIPT,
            "The length of the previous locking script: {} is different from the one set in the parameters: P::LEN_PREV_LOCK_SCRIPT = {}",
            prev_lock_script.0.len(),
            P::LEN_PREV_LOCK_SCRIPT
        );

        let sighash = sighash(
            tx,
            P::N_INPUT,
            &prev_lock_script.0,
            prev_amount as i64,
            P::SIGHASH_FLAG,
            sighash_cache,
        )
        .unwrap();

        TransactionIntegrityTag { inner: sighash.0 }
    }

    /// Verify the validity of a tag
    pub fn verify(
        tx: &Tx,
        prev_lock_script: &Script,
        prev_amount: u64,
        sighash_cache: &mut SigHashCache,
        tag: TransactionIntegrityTag,
    ) -> bool {
        TransactionIntegrityScheme::<P>::commit(tx, prev_lock_script, prev_amount, sighash_cache)
            == tag
    }
}
