use std::borrow::Borrow;

use ark_crypto_primitives::crh::sha256::constraints::DigestVar;
use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, prelude::AllocationMode};
use ark_relations::r1cs::{Namespace, SynthesisError};
use chain_gang::transaction::sighash::SigHashCache;

/// R1CS version of [SigHashCache]
#[derive(Debug, Clone)]
pub struct SigHashCacheVar<F: PrimeField> {
    pub hash_prevouts: Option<DigestVar<F>>,
    pub hash_sequence: Option<DigestVar<F>>,
    pub hash_outputs: Option<DigestVar<F>>,
}

impl<F: PrimeField> Default for SigHashCacheVar<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField> SigHashCacheVar<F> {
    pub fn new() -> Self {
        SigHashCacheVar::<F> {
            hash_prevouts: None,
            hash_sequence: None,
            hash_outputs: None,
        }
    }
}

impl<F: PrimeField> AllocVar<SigHashCache, F> for SigHashCacheVar<F> {
    fn new_variable<T: Borrow<SigHashCache>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let sighash_cache: SigHashCache = f().map(|cache| {
            let mut sighash_cache = SigHashCache::new();
            if cache.borrow().hash_prevouts().is_some() {
                sighash_cache.set_hash_prevouts(*cache.borrow().hash_prevouts().unwrap());
            }
            if cache.borrow().hash_sequence().is_some() {
                sighash_cache.set_hash_sequence(*cache.borrow().hash_sequence().unwrap());
            }
            if cache.borrow().hash_outputs().is_some() {
                sighash_cache.set_hash_outputs(*cache.borrow().hash_outputs().unwrap());
            }
            sighash_cache
        })?;

        let hash_prevouts: Option<DigestVar<F>> = match sighash_cache.hash_prevouts() {
            Some(hash_prevouts) => Some(DigestVar::<F>::new_variable(
                cs.clone(),
                || Ok(hash_prevouts.0.to_vec()),
                mode,
            )?),
            None => None,
        };
        let hash_sequence: Option<DigestVar<F>> = match sighash_cache.hash_sequence() {
            Some(hash_sequence) => Some(DigestVar::<F>::new_variable(
                cs.clone(),
                || Ok(hash_sequence.0.to_vec()),
                mode,
            )?),
            None => None,
        };
        let hash_outputs: Option<DigestVar<F>> = match sighash_cache.hash_outputs() {
            Some(hash_outputs) => Some(DigestVar::<F>::new_variable(
                cs.clone(),
                || Ok(hash_outputs.0.to_vec()),
                mode,
            )?),
            None => None,
        };

        Ok(Self {
            hash_prevouts,
            hash_sequence,
            hash_outputs,
        })
    }
}
