//! Implementation of [OutPointVar], R1CS version of a Bitcoin [OutPoint]
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    prelude::{AllocationMode, ToBytesGadget},
    uint8::UInt8,
    uint32::UInt32,
};

use ark_crypto_primitives::crh::sha256::constraints::DigestVar;

use crate::traits::PreSigHashSerialise;
use ark_relations::r1cs::{Namespace, SynthesisError};
use chain_gang::messages::OutPoint;
use chain_gang::util::Hash256;
use std::borrow::Borrow;

use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;

use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::ConstraintSystemRef;

// R1CS version of [OutPoint]
#[derive(Debug, Clone)]
pub struct OutPointVar<F: PrimeField> {
    /// The previous transaction ID
    pub prev_tx: DigestVar<F>,
    /// The previous index: held as a big-endian number
    pub prev_index: UInt32<F>,
}

impl<F: PrimeField> AllocVar<OutPoint, F> for OutPointVar<F> {
    fn new_variable<T: Borrow<OutPoint>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let outpoint: OutPoint = f().map(|out| out.borrow().clone())?;
        let txid: Hash256 = outpoint.clone().hash;
        let prev_tx = DigestVar::<F>::new_variable(cs.clone(), || Ok(txid.0.to_vec()), mode)?;
        let prev_index = UInt32::<F>::new_variable(cs.clone(), || Ok(outpoint.index), mode)?;

        Ok(Self {
            prev_tx,
            prev_index,
        })
    }
}

impl<F: PrimeField> EqGadget<F> for OutPointVar<F> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        Boolean::<F>::kary_and(&[
            self.prev_tx.is_eq(&other.prev_tx)?,
            self.prev_index.is_eq(&other.prev_index)?,
        ])
    }
}

impl<F: PrimeField> ToBytesGadget<F> for OutPointVar<F> {
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        self.pre_sighash_serialise()
    }
}

impl<F: PrimeField> R1CSVar<F> for OutPointVar<F> {
    type Value = OutPoint;

    fn cs(&self) -> ConstraintSystemRef<F> {
        let mut result = ConstraintSystemRef::None;
        result = self.prev_tx.cs().or(result);
        result = self.prev_index.cs().or(result);
        result
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(OutPoint {
            hash: Hash256(self.prev_tx.value()?),
            index: self.prev_index.value()?,
        })
    }
}

impl<F: PrimeField> PreSigHashSerialise<F> for OutPointVar<F> {
    /// Compute the serialisation of [OutPointVar] for pre_sighash calculation:
    ///
    /// `OutPointVar.prev_tx || OutPointVar.prev_index`
    fn pre_sighash_serialise(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        let mut ser: Vec<UInt8<F>> = vec![UInt8::<F>::constant(0); 36];
        let index_le = self.prev_index.to_bytes()?;
        // The method to_bytes_le() for DigestVar<F> returns the 32 bytes without reversing them
        ser[..32].clone_from_slice(self.prev_tx.to_bytes()?.as_slice());
        ser[32..].clone_from_slice(index_le.as_slice());
        Ok(ser)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use ark_bls12_381::Fq as F;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;
    use chain_gang::util::{Hash256, Serializable};

    #[test]
    fn outpoint_serialisation() {
        let mut v = Vec::new();
        // OutPoint decodes the hash as a little-endian number
        let t = OutPoint {
            hash: Hash256::decode(
                "123412345678567890ab90abcdefcdef123412345678567890ab90abcdefcdef",
            )
            .unwrap(),
            index: 0,
        };
        // Write writes the outpoint as held in memory (so the little-endian version of the hex we see above)
        t.write(&mut v).unwrap();

        let cs = ConstraintSystem::<F>::new_ref();
        let outpoint: OutPointVar<F> = OutPointVar::<F>::new_input(cs.clone(), || Ok(t)).unwrap();

        for (b1, b2) in outpoint
            .pre_sighash_serialise()
            .unwrap()
            .iter()
            .zip(v.iter())
        {
            assert_eq!(b1.value().unwrap(), *b2);
        }
    }

    #[test]
    fn test_is_eq() {
        let outpoint1 = OutPoint {
            hash: Hash256::decode(
                "123412345678567890ab90abcdefcdef123412345678567890ab90abcdefcdef",
            )
            .unwrap(),
            index: 0,
        };
        let outpoint2 = OutPoint {
            hash: Hash256::decode(
                "123412345678567890ab90abcdefcdef123412345678567890ab90abcdefcdef",
            )
            .unwrap(),
            index: 0,
        };

        let cs = ConstraintSystem::<F>::new_ref();
        let outpoint1: OutPointVar<F> =
            OutPointVar::<F>::new_input(cs.clone(), || Ok(outpoint1)).unwrap();
        let outpoint2: OutPointVar<F> =
            OutPointVar::<F>::new_input(cs.clone(), || Ok(outpoint2)).unwrap();

        assert!(outpoint1.is_eq(&outpoint2).unwrap().value().unwrap());
    }

    #[test]
    fn test_to_bytes_gadget() {
        let outpoint = OutPoint {
            hash: Hash256::decode(
                "123412345678567890ab90abcdefcdef123412345678567890ab90abcdefcdef",
            )
            .unwrap(),
            index: 0,
        };
        let mut outpoint_bytes: Vec<u8> = Vec::new();
        outpoint.write(&mut outpoint_bytes).unwrap();

        let cs = ConstraintSystem::<F>::new_ref();
        let outpoint_gadget: OutPointVar<F> =
            OutPointVar::<F>::new_input(cs.clone(), || Ok(outpoint)).unwrap();
        let outpoint_gadget_bytes = outpoint_gadget.to_bytes().unwrap().value().unwrap();

        assert_eq!(outpoint_bytes, outpoint_gadget_bytes);
    }
}
