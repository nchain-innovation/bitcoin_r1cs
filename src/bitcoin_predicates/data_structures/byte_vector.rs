//! Implement `ByteVector`, to be used as a variable in Bitcoin Predicates
use std::borrow::Borrow;
use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, prelude::AllocationMode, uint8::UInt8};
use ark_relations::r1cs::{Namespace, SynthesisError};

use crate::constraints::tx::TxVarConfig;

#[derive(Clone)]
pub struct ByteVector<const N: usize, F: PrimeField, P: TxVarConfig + Clone> {
    pub bytes: [u8; N],
    _field: PhantomData<F>,
    _config: PhantomData<P>,
}

pub struct ByteVectorVar<const N: usize, F: PrimeField, P: TxVarConfig + Clone> {
    pub bytes: [UInt8<F>; N],
    _config: PhantomData<P>,
}

impl<const N: usize, F: PrimeField, P: TxVarConfig + Clone> Default for ByteVector<N, F, P> {
    fn default() -> Self {
        Self {
            bytes: [0; N],
            _field: PhantomData,
            _config: PhantomData,
        }
    }
}

impl<const N: usize, F: PrimeField, P: TxVarConfig + Clone> ByteVector<N, F, P> {
    pub fn new(bytes: [u8; N]) -> Self {
        Self {
            bytes,
            _field: PhantomData,
            _config: PhantomData,
        }
    }
}

impl<const N: usize, F: PrimeField, P: TxVarConfig + Clone> AllocVar<ByteVector<N, F, P>, F>
    for ByteVectorVar<N, F, P>
{
    fn new_variable<T: Borrow<ByteVector<N, F, P>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let data: ByteVector<N, F, P> = f().map(|data| data.borrow().clone())?;
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
