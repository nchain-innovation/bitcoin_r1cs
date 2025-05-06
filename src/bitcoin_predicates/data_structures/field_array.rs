//! Implement [FieldArray], to be used as a variable in Bitcoin Predicates
use std::borrow::Borrow;
use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::AllocationMode};
use ark_relations::r1cs::{Namespace, SynthesisError};

use crate::constraints::tx::TxVarConfig;

#[derive(Clone)]
pub struct FieldArray<const N: usize, F: PrimeField, P: TxVarConfig + Clone> {
    pub elements: [F; N],
    _config: PhantomData<P>,
}

impl<const N: usize, F: PrimeField, P: TxVarConfig + Clone> From<FieldArray<N, F, P>> for Vec<F> {
    fn from(value: FieldArray<N, F, P>) -> Self {
        value.elements.into()
    }
}

pub struct FieldArrayVar<const N: usize, F: PrimeField, P: TxVarConfig + Clone> {
    pub elements: [FpVar<F>; N],
    _config: PhantomData<P>,
}

impl<const N: usize, F: PrimeField, P: TxVarConfig + Clone> Default for FieldArray<N, F, P> {
    fn default() -> Self {
        Self {
            elements: [F::zero(); N],
            _config: PhantomData,
        }
    }
}

impl<const N: usize, F: PrimeField, P: TxVarConfig + Clone> FieldArray<N, F, P> {
    pub fn new(elements: [F; N]) -> Self {
        Self {
            elements,
            _config: PhantomData,
        }
    }
}

impl<const N: usize, F: PrimeField, P: TxVarConfig + Clone> AllocVar<FieldArray<N, F, P>, F>
    for FieldArrayVar<N, F, P>
{
    fn new_variable<T: Borrow<FieldArray<N, F, P>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let data: FieldArray<N, F, P> = f().map(|data| data.borrow().clone())?;
        let mut elements = Vec::<FpVar<F>>::new();

        for element in data.elements.iter() {
            elements.push(FpVar::<F>::new_variable(cs.clone(), || Ok(element), mode)?);
        }

        Ok(Self {
            elements: elements
                .try_into()
                .expect("The length of `elements` is wrong"),
            _config: PhantomData,
        })
    }
}
