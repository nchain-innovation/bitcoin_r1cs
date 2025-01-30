//! R1CS implemenation of double Sha256
use std::marker::PhantomData;

use ark_crypto_primitives::crh::sha256::constraints::DigestVar;
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_ff::PrimeField;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::Result;

/// Gadget for calculating two rounds of Sha256
pub struct Hash256Gadget<F: PrimeField>(PhantomData<F>);

impl<F: PrimeField> Hash256Gadget<F> {
    pub fn evaluate(data: &[UInt8<F>]) -> Result<DigestVar<F>> {
        Sha256Gadget::digest(Sha256Gadget::digest(data)?.0.as_slice())
    }
}
