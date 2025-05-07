use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, prelude::Boolean, uint8::UInt8};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::constraints::tx::{TxVar, TxVarConfig};

/// Serialisation according to Bitcoin software specification for PreSigHash calculation
pub trait PreSigHashSerialise<F: Field> {
    fn pre_sighash_serialise(&self) -> Result<Vec<UInt8<F>>, SynthesisError>;
}

/// Predicate to enforce conditions of the form `C((l_out, u_stx, stx), w) = 1`
pub trait BitcoinPredicate<F: PrimeField, P: TxVarConfig + Clone> {
    type LockingData: Clone + Into<Vec<F>>;
    type UnlockingData: Clone + Into<Vec<F>>;
    type Witness: Clone;

    type LockingDataVar: AllocVar<Self::LockingData, F>;
    type UnlockingDataVar: AllocVar<Self::UnlockingData, F>;
    type WitnessVar: AllocVar<Self::Witness, F>;

    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        locking_data: &Self::LockingDataVar,
        unlocking_data: &Self::UnlockingDataVar,
        spending_data: &TxVar<F, P>,
        witness: &Self::WitnessVar,
    ) -> Result<Boolean<F>, SynthesisError>;

    fn enforce_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        locking_data: &Self::LockingDataVar,
        unlocking_data: &Self::UnlockingDataVar,
        spending_data: &TxVar<F, P>,
        witness: &Self::WitnessVar,
    ) -> Result<(), SynthesisError> {
        self.generate_constraints(
            cs.clone(),
            locking_data,
            unlocking_data,
            spending_data,
            witness,
        )?
        .enforce_equal(&Boolean::<F>::TRUE)
    }
}
