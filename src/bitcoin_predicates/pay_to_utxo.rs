use std::marker::PhantomData;

use ark_crypto_primitives::{SNARK, SNARKGadget, snark::FromFieldElementsGadget};
use ark_ff::PrimeField;
use ark_pcd::{
    ec_cycle_pcd::ECCyclePCDConfig,
    variable_length_crh::{VariableLengthCRH, constraints::VariableLengthCRHGadget},
};
use ark_r1cs_std::{
    R1CSVar, ToBytesGadget,
    prelude::{AllocVar, Boolean},
    uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::{constraints::tx::TxVarConfig, traits::BitcoinPredicate};

use super::data_structures::{
    proof::{BitcoinProof, BitcoinProofVar},
    unit::{BitcoinUnit, BitcoinUnitVar},
};

pub struct PayToUTXO<MainField: PrimeField, HelpField: PrimeField, IC: ECCyclePCDConfig<MainField, HelpField>, P: TxVarConfig + Clone> {
    // Parameters of the CRH
    pub crh_params: <<IC as ECCyclePCDConfig<MainField, HelpField>>::CRH as VariableLengthCRH<MainField>>::Parameters,
    // VK of the HelpCircuit
    pub vk: <<IC as ECCyclePCDConfig<MainField, HelpField>>::HelpSNARK as SNARK<HelpField>>::VerifyingKey,
    // Index of the input
    pub index: usize,
    // Phantom
    _config: PhantomData<P>
}

impl<MainField, HelpField, IC, P> Clone for PayToUTXO<MainField, HelpField, IC, P>
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

impl<MainField, HelpField, IC, P> PayToUTXO<MainField, HelpField, IC, P>
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
    for PayToUTXO<MainField, HelpField, IC, P>
where
    MainField: PrimeField,
    HelpField: PrimeField,
    IC: ECCyclePCDConfig<MainField, HelpField>,
    P: TxVarConfig + Clone,
{
    type LockingData = BitcoinUnit<MainField, P>;
    type UnlockingData = BitcoinUnit<MainField, P>;
    type Witness = BitcoinProof<HelpField, P, MainField, IC::HelpSNARK>;

    type LockingDataVar = BitcoinUnitVar<MainField, P>;
    type UnlockingDataVar = BitcoinUnitVar<MainField, P>;
    type WitnessVar = BitcoinProofVar<HelpField, P, MainField, IC::HelpSNARK, IC::HelpSNARKGadget>;

    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<MainField>,
        _locking_data: &Self::LockingDataVar,
        _unlocking_data: &Self::UnlockingDataVar,
        spending_data: &crate::constraints::tx::TxVar<MainField, P>,
        witness: &Self::WitnessVar,
    ) -> Result<Boolean<MainField>, SynthesisError> {
        // Hard-code vk
        let vk =
            <<IC as ECCyclePCDConfig<MainField, HelpField>>::HelpSNARKGadget as SNARKGadget<
                HelpField,
                MainField,
                IC::HelpSNARK,
            >>::VerifyingKeyVar::new_constant(cs.clone(), self.vk.clone())?;

        // Hard-code parameters of the CRH
        let crh_params = <<IC as ECCyclePCDConfig<MainField, HelpField>>::CRHGadget as VariableLengthCRHGadget<IC::CRH, MainField>>::ParametersVar::new_constant(cs.clone(), self.crh_params.clone())?;

        // Compute the hash of vk - this is for free as vk is a constant
        let vk_hashed = <<IC as ECCyclePCDConfig<MainField, HelpField>>::CRHGadget as VariableLengthCRHGadget<IC::CRH, MainField>>::check_evaluation_gadget(&crh_params, &vk.to_bytes()?)?;

        // Fetch the input
        let input = spending_data.inputs[self.index].prev_output.clone();

        // Compute CRH( CRH(vk) || input) )
        let mut committed_input: Vec<UInt8<MainField>> = Vec::new();
        for byte in vk_hashed.to_bytes()? {
            committed_input.push(byte.clone());
        }
        for byte in &input.to_bytes()? {
            committed_input.push(byte.clone());
        }

        let input_hash = <<IC as ECCyclePCDConfig<MainField, HelpField>>::CRHGadget as VariableLengthCRHGadget<IC::CRH, MainField>>::check_evaluation_gadget(&crh_params, &committed_input)?;
        let input_hash_as_fp_elements = <<IC as ECCyclePCDConfig<MainField, HelpField>>::CRHGadget as VariableLengthCRHGadget<IC::CRH, MainField>>::convert_output_to_field_gadgets(&input_hash)?;

        // Now we need to convert `input_hash_as_fp_elements` into a `Vec<HelpField>`. To do it, we need to call
        // `value()` on it. However, at setup this will raise an error. So, we build a default
        let mut default_input_hash: Vec<MainField> = Vec::new();
        for _ in 0..input_hash_as_fp_elements.len() {
            default_input_hash.push(MainField::zero());
        }

        // Convert `input_hash_as_fp_elements` into a `Vec<HelpField>`
        let help_input =
            <<IC as ECCyclePCDConfig<MainField, HelpField>>::MainSNARKGadget as SNARKGadget<
                MainField,
                HelpField,
                IC::MainSNARK,
            >>::InputVar::repack_input(
                &input_hash_as_fp_elements
                    .value()
                    .unwrap_or(default_input_hash),
            );

        let help_input_gadget =
            <<IC as ECCyclePCDConfig<MainField, HelpField>>::HelpSNARKGadget as SNARKGadget<
                HelpField,
                MainField,
                IC::HelpSNARK,
            >>::InputVar::new_witness(cs.clone(), || Ok(help_input))?;

        // Verify the proof
        // Using `vk` or its processed version doesn't make a difference in this case as `vk` is a constant
        // and thus computations on it don't add constraints
        <<IC as ECCyclePCDConfig<MainField, HelpField>>::HelpSNARKGadget as SNARKGadget<
            HelpField,
            MainField,
            IC::HelpSNARK,
        >>::verify(&vk, &help_input_gadget, &witness.proof)
    }
}
