//! Implementation of [TxOutVar], R1CS version of a Bitcoin [TxOut]
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    prelude::{AllocationMode, ToBytesGadget},
    uint8::UInt8,
    uint64::UInt64,
};

use crate::constraints::script::ScriptVar;
use crate::traits::PreSigHashSerialise;
use ark_relations::r1cs::{Namespace, SynthesisError};
use chain_gang::messages::TxOut;
use std::borrow::Borrow;

use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;

use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::ConstraintSystemRef;

/// R1CS version of [TxOut]
#[derive(Debug, Clone)]
pub struct TxOutVar<F: PrimeField> {
    /// Amount
    pub satoshis: UInt64<F>,
    /// Locking script
    pub lock_script: ScriptVar<F>,
}

impl<F: PrimeField> AllocVar<TxOut, F> for TxOutVar<F> {
    fn new_variable<T: Borrow<TxOut>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let txout: TxOut = f().map(|txout| txout.borrow().clone())?;

        let satoshis: UInt64<F> =
            UInt64::<F>::new_variable(cs.clone(), || Ok(txout.satoshis as u64), mode)?;
        let lock_script: ScriptVar<F> =
            ScriptVar::<F>::new_variable(cs.clone(), || Ok(txout.lock_script), mode)?;

        Ok(Self {
            satoshis,
            lock_script,
        })
    }
}

impl<F: PrimeField> EqGadget<F> for TxOutVar<F> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        Boolean::<F>::kary_and(&[
            self.satoshis.is_eq(&other.satoshis)?,
            self.lock_script.is_eq(&other.lock_script)?,
        ])
    }
}

impl<F: PrimeField> ToBytesGadget<F> for TxOutVar<F> {
    fn to_bytes_le(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        self.pre_sighash_serialise()
    }
}

impl<F: PrimeField> R1CSVar<F> for TxOutVar<F> {
    type Value = TxOut;

    fn cs(&self) -> ConstraintSystemRef<F> {
        let mut result = ConstraintSystemRef::None;
        result = self.satoshis.cs().or(result);
        result = self.lock_script.cs().or(result);
        result
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(TxOut {
            satoshis: self.satoshis.value()? as i64,
            lock_script: self.lock_script.value()?,
        })
    }
}

impl<F: PrimeField> TxOutVar<F> {
    /// Allocate vectors of [TxOut]s
    pub fn new_variable_vec<T: Borrow<Vec<TxOut>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Vec<Self>, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let txouts: Vec<TxOut> = f().map(|txin| txin.borrow().clone())?;

        let mut allocated_txouts: Vec<TxOutVar<F>> = Vec::with_capacity(txouts.len());
        for txout in txouts.iter() {
            allocated_txouts.push(TxOutVar::<F>::new_variable(cs.clone(), || Ok(txout), mode)?);
        }

        Ok(allocated_txouts)
    }
}

impl<F: PrimeField> PreSigHashSerialise<F> for TxOutVar<F> {
    /// Compute the serialisation of [TxOutVar] for pre_sighash calculation:
    ///
    /// `TxOutVar.amount || TxOutVar.lock_script`
    fn pre_sighash_serialise(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        let ser_satoshis = self.satoshis.to_bytes_le()?;
        let ser_lock_script = self.lock_script.pre_sighash_serialise()?;

        let mut ser: Vec<UInt8<F>> = Vec::with_capacity(ser_satoshis.len() + ser_lock_script.len());
        ser.extend_from_slice(ser_satoshis.as_slice());
        ser.extend_from_slice(ser_lock_script.as_slice());

        Ok(ser)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fq as F;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;
    use chain_gang::script::Script;
    use chain_gang::util::Serializable;

    #[test]
    fn txout_serialisation() {
        let mut v = Vec::new();
        let t = TxOut {
            satoshis: 4400044000,
            lock_script: Script(vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 100, 99, 98, 97, 96, 100, 99, 98, 97, 96, 100, 99, 98,
                97, 96, 100,
            ]),
        };
        t.write(&mut v).unwrap();

        let cs = ConstraintSystem::<F>::new_ref();
        let txout: TxOutVar<F> = TxOutVar::<F>::new_input(cs.clone(), || Ok(t)).unwrap();

        for (b1, b2) in txout.pre_sighash_serialise().unwrap().iter().zip(v.iter()) {
            assert_eq!(b1.value().unwrap(), *b2);
        }
    }

    #[test]
    fn test_is_eq() {
        let txout1 = TxOut {
            satoshis: 4400044000,
            lock_script: Script(vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 100, 99, 98, 97, 96, 100, 99, 98, 97, 96, 100, 99, 98,
                97, 96, 100,
            ]),
        };
        let txout2 = TxOut {
            satoshis: 4400044000,
            lock_script: Script(vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 100, 99, 98, 97, 96, 100, 99, 98, 97, 96, 100, 99, 98,
                97, 96, 100,
            ]),
        };

        let cs = ConstraintSystem::<F>::new_ref();
        let txout1: TxOutVar<F> = TxOutVar::<F>::new_input(cs.clone(), || Ok(txout1)).unwrap();
        let txout2: TxOutVar<F> = TxOutVar::<F>::new_input(cs.clone(), || Ok(txout2)).unwrap();

        assert!(txout1.is_eq(&txout2).unwrap().value().unwrap())
    }

    #[test]
    fn test_to_bytes_gadget() {
        let txout = TxOut {
            satoshis: 4400044000,
            lock_script: Script(vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 100, 99, 98, 97, 96, 100, 99, 98, 97, 96, 100, 99, 98,
                97, 96, 100,
            ]),
        };
        let mut txout_bytes: Vec<u8> = Vec::new();
        txout.write(&mut txout_bytes).unwrap();

        let cs = ConstraintSystem::<F>::new_ref();
        let txout_gadget: TxOutVar<F> = TxOutVar::<F>::new_input(cs.clone(), || Ok(txout)).unwrap();
        let txout_gadget_bytes = txout_gadget.to_bytes_le().unwrap().value().unwrap();

        assert_eq!(txout_bytes, txout_gadget_bytes);
    }
}
