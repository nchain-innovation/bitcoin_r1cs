//! Implement [BitcoinProof], to be used as a variable in Bitcoin Predicates
use std::{borrow::Borrow, marker::PhantomData};

use ark_crypto_primitives::{SNARK, SNARKGadget};
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_relations::r1cs::{Namespace, SynthesisError};

use crate::constraints::tx::TxVarConfig;

pub struct BitcoinProof<F: PrimeField, P: TxVarConfig + Clone, ConstraintF: PrimeField, S: SNARK<F>>
{
    pub proof: S::Proof,
    _field: PhantomData<ConstraintF>,
    _config: PhantomData<P>,
}

impl<F, P, ConstraintF, S> Clone for BitcoinProof<F, P, ConstraintF, S>
where
    F: PrimeField,
    P: TxVarConfig + Clone,
    ConstraintF: PrimeField,
    S: SNARK<F>,
{
    fn clone(&self) -> Self {
        Self {
            proof: self.proof.clone(),
            _field: PhantomData,
            _config: PhantomData,
        }
    }
}

impl<F, P, ConstraintF, S> BitcoinProof<F, P, ConstraintF, S>
where
    F: PrimeField,
    P: TxVarConfig + Clone,
    ConstraintF: PrimeField,
    S: SNARK<F>,
{
    pub fn new(proof: &S::Proof) -> Self {
        Self {
            proof: proof.clone(),
            _field: PhantomData,
            _config: PhantomData,
        }
    }
}

pub struct BitcoinProofVar<
    F: PrimeField,
    P: TxVarConfig + Clone,
    ConstraintF: PrimeField,
    S: SNARK<F>,
    SGadget: SNARKGadget<F, ConstraintF, S>,
> {
    pub proof: SGadget::ProofVar,
    _config: PhantomData<P>,
}

impl<F, P, ConstraintF, S, SGadget> AllocVar<BitcoinProof<F, P, ConstraintF, S>, ConstraintF>
    for BitcoinProofVar<F, P, ConstraintF, S, SGadget>
where
    F: PrimeField,
    P: TxVarConfig + Clone,
    ConstraintF: PrimeField,
    S: SNARK<F>,
    SGadget: SNARKGadget<F, ConstraintF, S>,
{
    fn new_variable<T: Borrow<BitcoinProof<F, P, ConstraintF, S>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let proof: BitcoinProof<F, P, ConstraintF, S> = f().map(|proof| proof.borrow().clone())?;
        let proof_var = SGadget::ProofVar::new_variable(cs.clone(), || Ok(proof.proof), mode)?;

        Ok(Self {
            proof: proof_var,
            _config: PhantomData,
        })
    }
}
