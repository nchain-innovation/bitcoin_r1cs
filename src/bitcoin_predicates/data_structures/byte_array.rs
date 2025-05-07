//! Implement [ByteArray], to be used as a variable in Bitcoin Predicates
use std::borrow::Borrow;
use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, prelude::AllocationMode, uint8::UInt8};
use ark_relations::r1cs::{Namespace, SynthesisError};

use crate::constraints::tx::TxVarConfig;

#[derive(Clone)]
pub struct ByteArray<const N: usize, F: PrimeField, P: TxVarConfig + Clone> {
    pub bytes: [u8; N],
    _field: PhantomData<F>,
    _config: PhantomData<P>,
}

impl<const N: usize, F: PrimeField, P: TxVarConfig + Clone> From<ByteArray<N, F, P>> for Vec<F> {
    fn from(value: ByteArray<N, F, P>) -> Self {
        value
            .bytes
            .iter()
            .map(|byte| F::from_le_bytes_mod_order(&[*byte]))
            .collect::<Vec<F>>()
    }
}

pub struct ByteArrayVar<const N: usize, F: PrimeField, P: TxVarConfig + Clone> {
    pub bytes: [UInt8<F>; N],
    _config: PhantomData<P>,
}

impl<const N: usize, F: PrimeField, P: TxVarConfig + Clone> Default for ByteArray<N, F, P> {
    fn default() -> Self {
        Self {
            bytes: [0; N],
            _field: PhantomData,
            _config: PhantomData,
        }
    }
}

impl<const N: usize, F: PrimeField, P: TxVarConfig + Clone> ByteArray<N, F, P> {
    pub fn new(bytes: [u8; N]) -> Self {
        Self {
            bytes,
            _field: PhantomData,
            _config: PhantomData,
        }
    }
}

impl<const N: usize, F: PrimeField, P: TxVarConfig + Clone> AllocVar<ByteArray<N, F, P>, F>
    for ByteArrayVar<N, F, P>
{
    fn new_variable<T: Borrow<ByteArray<N, F, P>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let data: ByteArray<N, F, P> = f().map(|data| data.borrow().clone())?;
        let mut bytes: Vec<UInt8<F>> = Vec::new();

        for byte in data.bytes.iter() {
            bytes.push(UInt8::<F>::new_variable(cs.clone(), || Ok(byte), mode)?);
        }

        Ok(Self {
            bytes: bytes.try_into().expect("The length of `bytes` is wrong"),
            _config: PhantomData,
        })
    }
}
