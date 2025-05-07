//! Macros used to combine BitcoinPredicates
//!
//! # Examples
//!
//! ```ignore
//! use ark_bls12_381::Fr as F;
//! use bitcoin_r1cs::bitcoin_predicates::fixed_lock_script::FixedLockScript;
//! use bitcoin_r1cs::and_combine_predicates;
//! use chain_gang::script::Script;
//!
//! and_combine_predicates!(
//!     AndFixTwoOutputsLockingData, // The name of the LockingData struct for the new predicate
//!     AndFixTwoOutputsUnlockingData, // The name of the UnlockingData struct for the new predicate
//!     AndFixTwoOutputsWitness, // The name of the Witness struct for the new predicate
//!     AndFixTwoOutputsLockingDataVar, // The name of the LockingDataVar struct for the new predicate
//!     AndFixTwoOutputsUnlockingDataVar, // The name of the UnlockingDataVar struct for the new predicate
//!     AndFixTwoOutputsWitnessDataVar, // The name of the WitnessVar struct for the new predicate,
//!     AndFixTwoOutputs, // The name of the new predicate
//!     (FixedLockScript<F,P>, 1), // The first predicate to AND combine; the integer is used to distinguish between copies of the same predicate
//!     (FixedLockScript<F,P>, 2), // The first predicate to AND combine
//! );
//!
//! use bitcoin_r1cs::constraints::tx::{TxVar, TxVarConfig};
//!
//! #[derive(Clone)]
//! struct Config;
//! impl TxVarConfig for Config {
//!    const N_INPUTS: usize = 0;
//!    const N_OUTPUTS: usize = 2;
//!    const LEN_UNLOCK_SCRIPTS: &[usize] = &[];
//!    const LEN_LOCK_SCRIPTS: &[usize] = &[1, 1];
//! }
//!
//! let fix_one = FixedLockScript::<F, Config>::new(Script(vec![0]), 0); // One instance of the FixedLockScript predicate
//! let fix_two = FixedLockScript::<F, Config>::new(Script(vec![1]), 1); // Another instance of the FixedLockScript predicate
//! let fix_combined = AndFixTwoOutputs::<F, Config>::new(fix_one, fix_two); // Create instance of the AND combination
//! ```

/// Private macro used to combine different Bitcoin Predicates
/// The macro assumes that the Bitcoin Predicates involved only depend on two generics:
/// F: PrimeField, P: TxVarConfig + Clone.
macro_rules! _combine_predicates {
    (
        $logical_condition:expr,
        $combined_locking_data:ident,
        $combined_unlocking_data:ident,
        $combined_witness:ident,
        $combined_locking_data_var:ident,
        $combined_unlocking_data_var:ident,
        $combined_witness_var:ident,
        $output:ident,
        $( ($type:ident < $($gen:tt),* >, $n:expr) ),+
        $(,)?
    ) => {

        paste::paste! {
            // Generate the SpentData struct
            combine_bp_structs!(
                LockingData,
                $combined_locking_data,
                $( ($type < $($gen),* >, $n) ),+
            );

            // Generate the UnlockingData struct
            combine_bp_structs!(
                UnlockingData,
                $combined_unlocking_data,
                $( ($type < $($gen),* >, $n) ),+
            );

            // Generate the Witness struct
            combine_witness_structs!(
                Witness,
                $combined_witness,
                $( ($type < $($gen),* >, $n) ),+
            );

            // Generate the SpentDataVar struct
            combine_bp_vars!(
                LockingDataVar,
                $combined_locking_data,
                $combined_locking_data_var,
                $( ($type < $($gen),* >, $n) ),+
            );

            // Generate the UnlockingDataVar struct
            combine_bp_vars!(
                UnlockingDataVar,
                $combined_unlocking_data,
                $combined_unlocking_data_var,
                $( ($type < $($gen),* >, $n) ),+
            );

            // Generate the WitnessVar struct
            combine_bp_vars!(
                WitnessVar,
                $combined_witness,
                $combined_witness_var,
                $( ($type < $($gen),* >, $n) ),+
            );

            // Generate the output struct
            struct $output<F: PrimeField, P: TxVarConfig + Clone> {
                $(
                    pub [<$type:snake _$n>]: $type<F,P>,
                )+
            }

            impl<F: PrimeField, P: TxVarConfig + Clone> $output<F, P> {
                pub fn new(
                    $(
                        [<$type:snake _$n>]: $type<F,P>,
                    )+
                ) -> Self {
                    Self {
                        $(
                            [<$type:snake _$n>]: [<$type:snake _$n>],
                        )+
                    }
                }
            }

            // Implement the BitcoinPredicate trait
            impl<F: PrimeField, P: TxVarConfig + Clone> BitcoinPredicate<F,P> for $output<F, P> {
                type LockingData = $combined_locking_data<F,P>;
                type UnlockingData = $combined_unlocking_data<F,P>;
                type Witness = $combined_witness<F,P>;

                type LockingDataVar = $combined_locking_data_var<F,P>;
                type UnlockingDataVar = $combined_unlocking_data_var<F,P>;
                type WitnessVar = $combined_witness_var<F,P>;

                fn generate_constraints(
                    &self,
                    cs: ark_relations::r1cs::ConstraintSystemRef<F>,
                    locking_data: &Self::LockingDataVar,
                    unlocking_data: &Self::UnlockingDataVar,
                    spending_data: &TxVar<F, P>,
                    witness: &Self::WitnessVar,
                ) -> Result<ark_r1cs_std::prelude::Boolean<F>, ark_relations::r1cs::SynthesisError> {
                    if $logical_condition {
                        ark_r1cs_std::prelude::Boolean::<F>::kary_and(&[
                            $(
                                self.[<$type:snake _$n>].generate_constraints(
                                    cs.clone(),
                                    &locking_data.[<$type:snake _$n>],
                                    &unlocking_data.[<$type:snake _$n>],
                                    &spending_data,
                                    &witness.[<$type:snake _$n>],
                                )?,
                            )+
                        ])
                    } else {
                        ark_r1cs_std::prelude::Boolean::<F>::kary_or(&[
                            $(
                                self.[<$type:snake _$n>].generate_constraints(
                                    cs.clone(),
                                    &locking_data.[<$type:snake _$n>],
                                    &unlocking_data.[<$type:snake _$n>],
                                    &spending_data,
                                    &witness.[<$type:snake _$n>],
                                )?,
                            )+
                        ])
                    }
                }
            }
        }
    };
}

#[macro_export]
macro_rules! combine_bp_structs {
    (
        $bp_type: ident,
        $combined_struct: ident,
        $( ($type:ident < $($gen:tt),* >, $n:expr) ),+
        $(,)?
    ) => {
        paste::paste! {
            // Generate the combined struct
            struct $combined_struct<F: PrimeField, P: TxVarConfig + Clone> {
                $(
                    pub [<$type:snake _$n>]: <$type<F,P> as BitcoinPredicate<F,P>>::$bp_type,
                )+
            }

            impl<F: PrimeField, P: TxVarConfig + Clone> Clone for $combined_struct<F, P> {
                fn clone(&self) -> Self {
                    Self {
                        $(
                            [<$type:snake _$n>]: self.[<$type:snake _$n>].clone(),
                        )+
                    }
                }
            }

            impl<F: PrimeField, P: TxVarConfig + Clone> $combined_struct<F, P> {
                pub fn new(
                    $(
                        [<$type:snake _$n>]: <$type<F,P> as BitcoinPredicate<F,P>>::$bp_type,
                    )+
                ) -> Self {
                    Self {
                        $(
                            [<$type:snake _$n>]: [<$type:snake _$n>],
                        )+
                    }
                }
            }

            impl<F: PrimeField, P: TxVarConfig + Clone> From<$combined_struct<F, P>> for Vec<F> {
                fn from(data: $combined_struct<F, P>) -> Vec<F> {
                    let mut out = Vec::<F>::new();
                        $(
                            out.extend_from_slice(&Into::<Vec<F>>::into(data.[<$type:snake _$n>]));
                        )+
                    out
                }
            }
        }
    }
}

#[macro_export]
macro_rules! combine_witness_structs {
    (
        $bp_type: ident,
        $combined_struct: ident,
        $( ($type:ident < $($gen:tt),* >, $n:expr) ),+
        $(,)?
    ) => {
        paste::paste! {
            // Generate the combined struct
            struct $combined_struct<F: PrimeField, P: TxVarConfig + Clone> {
                $(
                    pub [<$type:snake _$n>]: <$type<F,P> as BitcoinPredicate<F,P>>::$bp_type,
                )+
            }

            impl<F: PrimeField, P: TxVarConfig + Clone> Clone for $combined_struct<F, P> {
                fn clone(&self) -> Self {
                    Self {
                        $(
                            [<$type:snake _$n>]: self.[<$type:snake _$n>].clone(),
                        )+
                    }
                }
            }

            impl<F: PrimeField, P: TxVarConfig + Clone> $combined_struct<F, P> {
                pub fn new(
                    $(
                        [<$type:snake _$n>]: <$type<F,P> as BitcoinPredicate<F,P>>::$bp_type,
                    )+
                ) -> Self {
                    Self {
                        $(
                            [<$type:snake _$n>]: [<$type:snake _$n>],
                        )+
                    }
                }
            }
        }
    }
}

#[macro_export]
macro_rules! combine_bp_vars {
    (
        $bp_type: ident,
        $combined_struct: ident,
        $combined_var: ident,
        $(($type:ident < $($gen:tt),* >, $n:expr)),+
        $(,)?
    ) => {
        paste::paste! {
            // Generate the combined struct
            struct $combined_var<F: PrimeField, P: TxVarConfig + Clone> {
                $(
                    pub [<$type:snake _$n>]: <$type<F,P> as BitcoinPredicate<F,P>>::$bp_type,
                )+
            }

            impl<F: PrimeField, P: TxVarConfig + Clone> ark_r1cs_std::prelude::AllocVar<$combined_struct<F,P>, F> for $combined_var<F,P> {
                fn new_variable<T: std::borrow::Borrow<$combined_struct<F,P>>>(
                    cs: impl Into<ark_relations::r1cs::Namespace<F>>,
                    f: impl FnOnce() -> Result<T, ark_relations::r1cs::SynthesisError>,
                    mode: ark_r1cs_std::prelude::AllocationMode,
                ) -> Result<Self, ark_relations::r1cs::SynthesisError> {
                        let ns = cs.into();
                        let cs = ns.cs();
                        let struct_data: $combined_struct<F,P> = f().map(|data| data.borrow().clone())?;
                        Ok($combined_var {
                            $(
                                [<$type:snake _$n>]: <$type<F,P> as BitcoinPredicate<F,P>>::$bp_type::new_variable(cs.clone(), || Ok(struct_data.[<$type:snake _$n>]), mode)?,
                            )+
                        })
                    }
                }
            }
    }
}

#[macro_export]
macro_rules! and_combine_predicates {
    (
        $combined_locking_data:ident,
        $combined_unlocking_data:ident,
        $combined_witness:ident,
        $combined_locking_data_var:ident,
        $combined_unlocking_data_var:ident,
        $combined_witness_var:ident,
        $output:ident,
        $(($type:ident < $($gen:tt),* >, $n:expr)),+
        $(,)?
    ) => {
        _combine_predicates!(
            true,
            $combined_locking_data,
            $combined_unlocking_data,
            $combined_witness,
            $combined_locking_data_var,
            $combined_unlocking_data_var,
            $combined_witness_var,
            $output,
            $( ($type < $($gen),* >, $n) ),+
        );
    }
}

#[macro_export]
macro_rules! or_combine_predicates {
    (
        $combined_spent_data:ident,
        $combined_unlocking_data:ident,
        $combined_witness:ident,
        $combined_spent_data_var:ident,
        $combined_unlocking_data_var:ident,
        $combined_witness_var:ident,
        $output:ident,
        $(($type:ident < $($gen:tt),* >, $n:expr)),+
        $(,)?
    ) => {
        _combine_predicates!(
            false,
            $combined_spent_data,
            $combined_unlocking_data,
            $combined_witness,
            $combined_spent_data_var,
            $combined_unlocking_data_var,
            $combined_witness_var,
            $output,
            $( ($type < $($gen),* >, $n) ),+
        );
    }
}

#[cfg(test)]
mod test {
    use ark_bls12_381::Fr as F;
    use ark_ff::PrimeField;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_relations::r1cs::ConstraintSystem;
    use chain_gang::{
        messages::{Tx, TxOut},
        script::Script,
    };

    use crate::bitcoin_predicates::fixed_lock_script::FixedLockScript;
    use crate::traits::BitcoinPredicate;
    use crate::{
        bitcoin_predicates::data_structures::unit::BitcoinUnit,
        constraints::tx::{TxVar, TxVarConfig},
    };

    #[derive(Clone)]
    struct Config;
    impl TxVarConfig for Config {
        const N_INPUTS: usize = 0;
        const N_OUTPUTS: usize = 2;
        const LEN_UNLOCK_SCRIPTS: &[usize] = &[];
        const LEN_LOCK_SCRIPTS: &[usize] = &[1, 1];
    }

    and_combine_predicates!(
        AndFixTwoOutputsLockingData,
        AndFixTwoOutputsUnlockingData,
        AndFixTwoOutputsWitness,
        AndFixTwoOutputsLockingDataVar,
        AndFixTwoOutputsUnlockingDataVar,
        AndFixTwoOutputsWitnessVar,
        AndFixTwoOutputs,
        (FixedLockScript<F,P>, 1),
        (FixedLockScript<F,P>, 2),
    );

    or_combine_predicates!(
        OrFixTwoOutputsLockingData,
        OrFixTwoOutputsUnlockingData,
        OrFixTwoOutputsWitness,
        OrFixTwoOutputsLockingDataVar,
        OrFixTwoOutputsUnlockingDataVar,
        OrFixTwoOutputsWitnessVar,
        OrFixTwoOutputs,
        (FixedLockScript<F,P>, 1),
        (FixedLockScript<F,P>, 2),
    );

    fn test_combine_predicates(
        is_and: bool,
        lock_script_one: Script,
        lock_script_two: Script,
        expected: bool,
    ) {
        let tx = Tx {
            version: 2,
            inputs: vec![],
            outputs: vec![
                TxOut {
                    satoshis: 100,
                    lock_script: lock_script_one,
                },
                TxOut {
                    satoshis: 259899900,
                    lock_script: lock_script_two,
                },
            ],
            lock_time: 0,
        };

        let cs = ConstraintSystem::<F>::new_ref();
        let tx_var = TxVar::<F, Config>::new_input(cs.clone(), || Ok(tx)).unwrap();

        if is_and {
            let fix_one = FixedLockScript::<F, Config>::new(Script(vec![0]), 0);
            let fix_two = FixedLockScript::<F, Config>::new(Script(vec![1]), 1);
            let fix_combined = AndFixTwoOutputs::<F, Config>::new(fix_one, fix_two);
            let dummy = BitcoinUnit::<F, Config>::default();
            let dummy_spent = AndFixTwoOutputsLockingData::new(dummy.clone(), dummy.clone());
            let dummy_unlock = AndFixTwoOutputsUnlockingData::new(dummy.clone(), dummy.clone());
            let dummy_wit = AndFixTwoOutputsWitness::new(dummy.clone(), dummy.clone());
            let spent_var =
                AndFixTwoOutputsLockingDataVar::new_input(cs.clone(), || Ok(dummy_spent)).unwrap();
            let unlock_var =
                AndFixTwoOutputsUnlockingDataVar::new_input(cs.clone(), || Ok(dummy_unlock))
                    .unwrap();
            let wit_var =
                AndFixTwoOutputsWitnessVar::new_input(cs.clone(), || Ok(dummy_wit)).unwrap();

            fix_combined
                .enforce_constraints(cs.clone(), &spent_var, &unlock_var, &tx_var, &wit_var)
                .unwrap();
        } else {
            let fix_one = FixedLockScript::<F, Config>::new(Script(vec![0]), 0);
            let fix_two = FixedLockScript::<F, Config>::new(Script(vec![1]), 1);
            let fix_combined = OrFixTwoOutputs::<F, Config>::new(fix_one, fix_two);
            let dummy = BitcoinUnit::<F, Config>::default();
            let dummy_spent = OrFixTwoOutputsLockingData::new(dummy.clone(), dummy.clone());
            let dummy_unlock = OrFixTwoOutputsUnlockingData::new(dummy.clone(), dummy.clone());
            let dummy_wit = OrFixTwoOutputsWitness::new(dummy.clone(), dummy.clone());
            let spent_var =
                OrFixTwoOutputsLockingDataVar::new_input(cs.clone(), || Ok(dummy_spent)).unwrap();
            let unlock_var =
                OrFixTwoOutputsUnlockingDataVar::new_input(cs.clone(), || Ok(dummy_unlock))
                    .unwrap();
            let wit_var =
                OrFixTwoOutputsWitnessVar::new_input(cs.clone(), || Ok(dummy_wit)).unwrap();

            fix_combined
                .enforce_constraints(cs.clone(), &spent_var, &unlock_var, &tx_var, &wit_var)
                .unwrap();
        }

        assert_eq!(cs.is_satisfied().unwrap(), expected);
    }

    #[test]
    fn test_and_is_ok() {
        test_combine_predicates(true, Script(vec![0]), Script(vec![1]), true);
    }

    #[test]
    fn test_and_fails() {
        test_combine_predicates(true, Script(vec![0]), Script(vec![0]), false);
    }

    #[test]
    fn test_or_is_ok() {
        test_combine_predicates(false, Script(vec![0]), Script(vec![0]), true);

        test_combine_predicates(false, Script(vec![1]), Script(vec![1]), true);
    }

    #[test]
    fn test_or_fails() {
        test_combine_predicates(false, Script(vec![1]), Script(vec![2]), false);
    }
}
