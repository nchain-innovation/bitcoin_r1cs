//! Implement [BitcoinUnit], to be used as a variable in Bitcoin Predicates
use std::borrow::Borrow;
use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, prelude::AllocationMode};
use ark_relations::r1cs::{Namespace, SynthesisError};

use crate::constraints::tx::TxVarConfig;

#[derive(Clone)]
pub struct BitcoinUnit<F: PrimeField, P: TxVarConfig + Clone> {
    _field: PhantomData<F>,
    _config: PhantomData<P>,
}

pub struct BitcoinUnitVar<F: PrimeField, P: TxVarConfig + Clone> {
    _field: PhantomData<F>,
    _config: PhantomData<P>,
}

impl<F: PrimeField, P: TxVarConfig + Clone> From<BitcoinUnit<F, P>> for Vec<F> {
    fn from(_value: BitcoinUnit<F, P>) -> Self {
        Vec::<F>::new()
    }
}

impl<F: PrimeField, P: TxVarConfig + Clone> Default for BitcoinUnit<F, P> {
    fn default() -> Self {
        Self {
            _field: PhantomData,
            _config: PhantomData,
        }
    }
}

impl<F: PrimeField, P: TxVarConfig + Clone> Default for BitcoinUnitVar<F, P> {
    fn default() -> Self {
        Self {
            _field: PhantomData,
            _config: PhantomData,
        }
    }
}

impl<F: PrimeField, P: TxVarConfig + Clone> AllocVar<BitcoinUnit<F, P>, F>
    for BitcoinUnitVar<F, P>
{
    fn new_variable<T: Borrow<BitcoinUnit<F, P>>>(
        _cs: impl Into<Namespace<F>>,
        _f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Ok(BitcoinUnitVar::default())
    }
}
