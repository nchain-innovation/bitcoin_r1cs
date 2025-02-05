//! Implementation of [ScriptVar], R1CS version of a Bitcoin [Script]
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    prelude::{AllocationMode, ToBytesGadget},
    uint8::UInt8,
};

use chain_gang::script::Script;

use crate::traits::PreSigHashSerialise;

use ark_relations::r1cs::{Namespace, SynthesisError};
use std::{borrow::Borrow, vec::Vec};

use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;

use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::ConstraintSystemRef;

use std::io::Result as IoResult;

use crate::util::u64_to_var_int;

/// R1CS version of a [Script]
#[derive(Debug, Clone)]
pub struct ScriptVar<F: PrimeField>(pub Vec<UInt8<F>>);

impl<F: PrimeField> ScriptVar<F> {
    /// Computes var_int length of `self`.
    /// It allocates the elements of the length as constants.
    /// This is ok because the size of the script (unlocking or locking script) is fixed in a circuit.
    pub fn size(&self) -> IoResult<Vec<UInt8<F>>> {
        Ok(u64_to_var_int(self.0.len())?
            .into_iter()
            .map(|el| UInt8::<F>::constant(el))
            .collect::<Vec<UInt8<F>>>())
    }
}

impl<F: PrimeField> AllocVar<Script, F> for ScriptVar<F> {
    fn new_variable<T: Borrow<Script>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into(); // NameSpace
        let cs = ns.cs(); // ConstraintSystem

        // Get the script
        let script_value: Script = f().map(|s| s.borrow().clone())?;

        // Allocate the script as a vector of bytes
        let mut allocated_script: Vec<UInt8<F>> = Vec::new();
        for byte in script_value.0.iter() {
            allocated_script.push(UInt8::<F>::new_variable(cs.clone(), || Ok(byte), mode)?);
        }

        // Return the ScriptVar
        Ok(Self(allocated_script))
    }
}

impl<F: PrimeField> EqGadget<F> for ScriptVar<F> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        if self.0.is_empty() && other.0.is_empty() {
            Ok(Boolean::<F>::TRUE)
        } else {
            self.0.is_eq(&other.0)
        }
    }
}

impl<F: PrimeField> ToBytesGadget<F> for ScriptVar<F> {
    fn to_bytes(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        self.0.to_bytes()
    }
}

impl<F: PrimeField> R1CSVar<F> for ScriptVar<F> {
    type Value = Script;

    fn cs(&self) -> ConstraintSystemRef<F> {
        let mut result = ConstraintSystemRef::None;
        for var in &self.0 {
            result = var.cs().or(result);
        }
        result
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(Script(self.0.value()?))
    }
}

impl<F: PrimeField> PreSigHashSerialise<F> for ScriptVar<F> {
    /// Computes the serialisation of [ScriptVar] for pre_sighash calculation:
    ///
    /// `var_int_len(ScripVar) || ScriptVar`
    fn pre_sighash_serialise(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        // var_int length
        let script_size: Vec<UInt8<F>> =
            self.size().map_err(|_| SynthesisError::AssignmentMissing)?;
        // serialised script
        let ser_script = self.to_bytes()?;
        // finalised serialisation
        let mut ser: Vec<UInt8<F>> = Vec::with_capacity(script_size.len() + ser_script.len());
        ser.extend_from_slice(&script_size);
        ser.extend_from_slice(&ser_script);

        Ok(ser)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fq as F;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;
    use chain_gang::script::op_codes::*;

    #[test]
    fn script_serialisation() {
        let mut script = Script::new();
        script.append_slice(&[
            OP_10,
            OP_5,
            OP_DIV,
            OP_10,
            OP_5,
            OP_DIV,
            OP_10,
            OP_5,
            OP_DIV,
            OP_10,
            OP_5,
            OP_DIV,
            OP_CHECKSIG,
            OP_5,
            OP_CHECKSIGVERIFY,
            OP_10,
            OP_MAX,
            OP_DIV,
            OP_MOD,
            OP_5,
            OP_0NOTEQUAL,
            OP_10,
            OP_5,
            OP_DIV,
            OP_GREATERTHANOREQUAL,
        ]);

        let cs = ConstraintSystem::<F>::new_ref();
        let allocated_script =
            ScriptVar::<F>::new_input(cs.clone(), || Ok(script.clone())).unwrap();
        let ser_allocated_script = allocated_script.to_bytes().unwrap();

        for (allocated_byte, byte) in ser_allocated_script.iter().zip(script.0.iter()) {
            assert_eq!(allocated_byte.value().unwrap(), *byte)
        }
    }

    #[test]
    fn test_is_eq() {
        let mut script1 = Script::new();
        script1.append_slice(&[OP_10, OP_5]);
        let mut script2 = Script::new();
        script2.append_slice(&[OP_10, OP_5]);

        let cs = ConstraintSystem::<F>::new_ref();
        let allocated_script1 =
            ScriptVar::<F>::new_input(cs.clone(), || Ok(script1.clone())).unwrap();
        let allocated_script2 =
            ScriptVar::<F>::new_input(cs.clone(), || Ok(script2.clone())).unwrap();

        assert!(
            allocated_script1
                .is_eq(&allocated_script2)
                .unwrap()
                .value()
                .unwrap()
        );
    }

    #[test]
    fn test_to_bytes_gadget() {
        let mut script = Script::new();
        script.append_slice(&[OP_10, OP_5]);

        let cs = ConstraintSystem::<F>::new_ref();
        let allocated_script =
            ScriptVar::<F>::new_input(cs.clone(), || Ok(script.clone())).unwrap();
        let allocated_script_bytes = allocated_script.to_bytes().unwrap().value().unwrap();

        assert_eq!(script.0, allocated_script_bytes)
    }
}
