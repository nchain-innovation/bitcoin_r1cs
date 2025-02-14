//! Implementation of [TxInVar], R1CS version of a Bitcoin [TxIn]
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    prelude::{AllocationMode, ToBytesGadget},
    uint8::UInt8,
    uint32::UInt32,
    uint64::UInt64,
};

use ark_relations::r1cs::{Namespace, SynthesisError};
use std::borrow::Borrow;

use crate::constraints::{outpoint::OutPointVar, script::ScriptVar};
use crate::traits::PreSigHashSerialise;
use chain_gang::messages::TxIn;

use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;

use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::ConstraintSystemRef;

/// R1CS version of [TxIn]
#[derive(Debug, Clone)]
pub struct TxInVar<F: PrimeField> {
    /// OutPoint being spent
    pub prev_output: OutPointVar<F>,
    /// Unlocking script
    pub unlock_script: ScriptVar<F>,
    /// Sequence
    pub sequence: UInt32<F>,
}

impl<F: PrimeField> AllocVar<TxIn, F> for TxInVar<F> {
    fn new_variable<T: Borrow<TxIn>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let txin: TxIn = f().map(|txin| txin.borrow().clone())?;

        let prev_output: OutPointVar<F> =
            OutPointVar::<F>::new_variable(cs.clone(), || Ok(txin.prev_output), mode)?;
        let unlock_script: ScriptVar<F> =
            ScriptVar::<F>::new_variable(cs.clone(), || Ok(txin.unlock_script), mode)?;
        let sequence: UInt32<F> =
            UInt32::<F>::new_variable(cs.clone(), || Ok(txin.sequence), mode)?;

        Ok(Self {
            prev_output,
            unlock_script,
            sequence,
        })
    }
}

impl<F: PrimeField> EqGadget<F> for TxInVar<F> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        Boolean::<F>::kary_and(&[
            self.prev_output.is_eq(&other.prev_output)?,
            self.unlock_script.is_eq(&other.unlock_script)?,
            self.sequence.is_eq(&other.sequence)?,
        ])
    }
}

impl<F: PrimeField> ToBytesGadget<F> for TxInVar<F> {
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        let mut ser: Vec<UInt8<F>> = Vec::new();
        ser.extend_from_slice(self.prev_output.to_bytes()?.as_slice());
        ser.extend_from_slice(self.unlock_script.pre_sighash_serialise()?.as_slice());
        ser.extend_from_slice(self.sequence.to_bytes()?.as_slice());
        Ok(ser)
    }
}

impl<F: PrimeField> R1CSVar<F> for TxInVar<F> {
    type Value = TxIn;

    fn cs(&self) -> ConstraintSystemRef<F> {
        let mut result = ConstraintSystemRef::None;
        result = self.prev_output.cs().or(result);
        result = self.unlock_script.cs().or(result);
        result = self.sequence.cs().or(result);
        result
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(TxIn {
            prev_output: self.prev_output.value()?,
            unlock_script: self.unlock_script.value()?,
            sequence: self.sequence.value()?,
        })
    }
}

impl<F: PrimeField> TxInVar<F> {
    /// Allocate vectors of [TxIn]s
    pub fn new_variable_vec<T: Borrow<Vec<TxIn>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Vec<Self>, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let txins: Vec<TxIn> = f().map(|txin| txin.borrow().clone())?;

        let mut pre_sighash_txins: Vec<TxInVar<F>> = Vec::with_capacity(txins.len());
        for txin in txins.iter() {
            pre_sighash_txins.push(TxInVar::<F>::new_variable(cs.clone(), || Ok(txin), mode)?);
        }

        Ok(pre_sighash_txins)
    }

    /// Compute the serialisation of [TxInVar] for pre_sighash calculation:
    ///
    /// `TxInVar.prev_output || unlock_script || satoshis || TxInVar.sequence`
    ///
    /// **NOTE**: this function assumes that `prev_lock_script` has already been modified to handle `OP_CODESEPARATOR`.
    pub fn pre_sighash_serialise(
        &self,
        prev_lock_script: &ScriptVar<F>,
        satoshis: &UInt64<F>,
    ) -> Result<Vec<UInt8<F>>, SynthesisError> {
        let ser_prev_output = self.prev_output.pre_sighash_serialise()?;
        let ser_prev_lock_script = prev_lock_script.pre_sighash_serialise()?;
        let ser_satoshis = satoshis.to_bytes()?;
        let ser_sequence = self.sequence.to_bytes()?;

        let mut ser: Vec<UInt8<F>> =
            Vec::with_capacity(ser_prev_output.len() + ser_prev_lock_script.len() + 12);
        ser.extend_from_slice(ser_prev_output.as_slice());
        ser.extend_from_slice(ser_prev_lock_script.as_slice());
        ser.extend_from_slice(ser_satoshis.as_slice());
        ser.extend_from_slice(ser_sequence.as_slice());

        Ok(ser)
    }
}

#[cfg(test)]
mod tests {
    use crate::util::usize_to_var_int;

    use super::*;
    use ark_bls12_381::Fq as F;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;
    use byteorder::{LittleEndian, WriteBytesExt};
    use chain_gang::messages::{OutPoint, TxIn};
    use chain_gang::script::Script;
    use chain_gang::util::{Hash256, Serializable};
    use std::io::Write;

    #[test]
    fn txin_serialisation() {
        let txin = TxIn {
            prev_output: OutPoint {
                hash: Hash256::decode(
                    "bf6c1139ea01ca054b8d00aa0a088daaeab4f3b8e111626c6be7d603a9dd8dff",
                )
                .unwrap(),
                index: 0,
            },
            unlock_script: Script(vec![]),
            sequence: 0xffffffff,
        };
        let unlock_script = Script(vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 100, 99, 98, 97, 96, 100, 99, 98, 97, 96, 100, 99, 98, 97,
            96, 100,
        ]);
        let satoshis: u64 = 40000;
        let mut s = Vec::new();
        txin.prev_output.write(&mut s).unwrap();
        s.write_all(usize_to_var_int(unlock_script.0.len()).unwrap().as_slice())
            .unwrap();
        s.write_all(unlock_script.0.as_slice()).unwrap();
        s.write_u64::<LittleEndian>(satoshis.clone()).unwrap();
        s.write_u32::<LittleEndian>(txin.sequence.clone()).unwrap();

        let cs = ConstraintSystem::<F>::new_ref();
        let txin_var: TxInVar<F> = TxInVar::<F>::new_input(cs.clone(), || Ok(txin)).unwrap();

        for (b1, b2) in txin_var
            .pre_sighash_serialise(
                &ScriptVar::<F>::new_input(cs.clone(), || Ok(unlock_script)).unwrap(),
                &UInt64::<F>::new_input(cs.clone(), || Ok(satoshis)).unwrap(),
            )
            .unwrap()
            .iter()
            .zip(s.iter())
        {
            assert_eq!(b1.value().unwrap(), *b2);
        }
    }

    #[test]
    fn test_is_eq() {
        let txin1 = TxIn {
            prev_output: OutPoint {
                hash: Hash256::decode(
                    "bf6c1139ea01ca054b8d00aa0a088daaeab4f3b8e111626c6be7d603a9dd8dff",
                )
                .unwrap(),
                index: 0,
            },
            unlock_script: Script(vec![]),
            sequence: 0xffffffff,
        };
        let txin2 = TxIn {
            prev_output: OutPoint {
                hash: Hash256::decode(
                    "bf6c1139ea01ca054b8d00aa0a088daaeab4f3b8e111626c6be7d603a9dd8dff",
                )
                .unwrap(),
                index: 0,
            },
            unlock_script: Script(vec![]),
            sequence: 0xffffffff,
        };

        let cs = ConstraintSystem::<F>::new_ref();
        let txin1: TxInVar<F> = TxInVar::<F>::new_input(cs.clone(), || Ok(txin1)).unwrap();
        let txin2: TxInVar<F> = TxInVar::<F>::new_input(cs.clone(), || Ok(txin2)).unwrap();

        assert!(txin1.is_eq(&txin2).unwrap().value().unwrap());
    }

    #[test]
    fn test_to_bytes_gadget() {
        let txin = TxIn {
            prev_output: OutPoint {
                hash: Hash256::decode(
                    "bf6c1139ea01ca054b8d00aa0a088daaeab4f3b8e111626c6be7d603a9dd8dff",
                )
                .unwrap(),
                index: 0,
            },
            unlock_script: Script(vec![]),
            sequence: 0xffffffff,
        };
        let mut txin_bytes: Vec<u8> = Vec::new();
        txin.write(&mut txin_bytes).unwrap();

        let cs = ConstraintSystem::<F>::new_ref();
        let txin_gadget: TxInVar<F> = TxInVar::<F>::new_input(cs.clone(), || Ok(txin)).unwrap();
        let txin_gadget_bytes = txin_gadget.to_bytes().unwrap().value().unwrap();

        assert_eq!(txin_bytes, txin_gadget_bytes);
    }
}
