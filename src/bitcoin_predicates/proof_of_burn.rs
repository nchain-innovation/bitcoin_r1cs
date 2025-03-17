use std::marker::PhantomData;

use crate::{
    bitcoin_predicates::data_structures::{
        field_array::{FieldArray, FieldArrayVar},
        proof::{BitcoinProof, BitcoinProofVar},
        unit::{BitcoinUnit, BitcoinUnitVar},
    },
    constraints::tx::TxVarConfig,
    traits::BitcoinPredicate,
};

use ark_crypto_primitives::SNARK;
use ark_pcd::{ec_cycle_pcd::ECCyclePCDConfig, variable_length_crh::VariableLengthCRH};
use ark_r1cs_std::prelude::Boolean;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use chain_gang::script::{
    Script,
    op_codes::{OP_0, OP_RETURN},
};

use super::{fixed_lock_script::FixedLockScript, universal_pay_to_utxo::UniversalPayToUTXO};

use ark_ff::PrimeField;

/// Proof of burn
pub struct ProofOfBurn<MainField: PrimeField, HelpField: PrimeField, IC: ECCyclePCDConfig<MainField, HelpField>, P: TxVarConfig + Clone> {
    // Parameters of the CRH
    pub crh_params: <<IC as ECCyclePCDConfig<MainField, HelpField>>::CRH as VariableLengthCRH<MainField>>::Parameters,
    // VK of the HelpCircuit
    pub vk: <<IC as ECCyclePCDConfig<MainField, HelpField>>::HelpSNARK as SNARK<HelpField>>::VerifyingKey,
    // Index of the input to be burnt
    pub index: usize,
    // Phantom
    _config: PhantomData<P>
}

impl<MainField, HelpField, IC, P> Clone for ProofOfBurn<MainField, HelpField, IC, P>
where
    MainField: PrimeField,
    HelpField: PrimeField,
    IC: ECCyclePCDConfig<MainField, HelpField>,
    P: TxVarConfig + Clone,
{
    fn clone(&self) -> Self {
        Self {
            crh_params: self.crh_params.clone(),
            vk: self.vk.clone(),
            index: self.index,
            _config: PhantomData,
        }
    }
}

impl<MainField, HelpField, IC, P> ProofOfBurn<MainField, HelpField, IC, P>
where
    MainField: PrimeField,
    HelpField: PrimeField,
    IC: ECCyclePCDConfig<MainField, HelpField>,
    P: TxVarConfig + Clone,
{
    pub fn new(
        crh_params: &<<IC as ECCyclePCDConfig<MainField, HelpField>>::CRH as VariableLengthCRH<
            MainField,
        >>::Parameters,
        vk: &<<IC as ECCyclePCDConfig<MainField, HelpField>>::HelpSNARK as SNARK<HelpField>>::VerifyingKey,
        index: usize,
    ) -> Self {
        Self {
            crh_params: crh_params.clone(),
            vk: vk.clone(),
            index,
            _config: PhantomData,
        }
    }
}

impl<MainField, HelpField, IC, P> BitcoinPredicate<MainField, P>
    for ProofOfBurn<MainField, HelpField, IC, P>
where
    MainField: PrimeField,
    HelpField: PrimeField,
    IC: ECCyclePCDConfig<MainField, HelpField>,
    P: TxVarConfig + Clone,
{
    type LockingData = FieldArray<1, MainField, P>;
    type UnlockingData = BitcoinUnit<MainField, P>;
    type Witness = BitcoinProof<HelpField, P, MainField, IC::HelpSNARK>;

    type LockingDataVar = FieldArrayVar<1, MainField, P>;
    type UnlockingDataVar = BitcoinUnitVar<MainField, P>;
    type WitnessVar = BitcoinProofVar<HelpField, P, MainField, IC::HelpSNARK, IC::HelpSNARKGadget>;

    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<MainField>,
        locking_data: &Self::LockingDataVar,
        unlocking_data: &Self::UnlockingDataVar,
        spending_data: &crate::constraints::tx::TxVar<MainField, P>,
        witness: &Self::WitnessVar,
    ) -> Result<Boolean<MainField>, SynthesisError> {
        // Associated P2UTXO - it enforces that the input at position `index` is in a TCP with the hard-coded genesis
        let pay2utxo = UniversalPayToUTXO::<MainField, HelpField, IC, P>::new(
            &self.crh_params,
            &self.vk,
            self.index,
        );
        let is_pay2utxo_satisfied = pay2utxo.generate_constraints(
            cs.clone(),
            locking_data,
            unlocking_data,
            spending_data,
            witness,
        );

        // Associated FixedLockingScript
        let is_burnt = FixedLockScript::<MainField, P>::new(Script(vec![OP_0, OP_RETURN]), 0)
            .generate_constraints(
                cs.clone(),
                &BitcoinUnitVar::default(),
                &BitcoinUnitVar::default(),
                spending_data,
                &BitcoinUnitVar::default(),
            );

        Boolean::<MainField>::kary_and(&[is_pay2utxo_satisfied?, is_burnt?])
    }
}
