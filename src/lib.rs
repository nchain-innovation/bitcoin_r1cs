//! This library provides the implementation of R1CS versions of Bitcoin structures, e.g. transactions, and functions, e.g. TxID calculation, sighash calculation, etcetera.
//!
//! Bitcoin structures are taken from the library [chain_gang], while the R1CS variables are built using the framework provided by the [ark_r1cs_std] library.
//!
//! # Example
//! The code below allocates in the constraint system a new input of type [ScriptVar](crate::constraints::script::ScriptVar), which is the R1CS version of [Script](chain_gang::script::Script),
//! and then checks that it is equal to itself.
//!
//! ```
//! use ark_bls12_381::Fr as ScalarField;
//! use ark_r1cs_std::alloc::AllocVar;
//! use ark_r1cs_std::eq::EqGadget;
//! use ark_relations::r1cs::ConstraintSystem;
//! use bitcoin_r1cs::constraints::script::ScriptVar;
//! use chain_gang::script::Script;
//! use chain_gang::script::op_codes::*;
//!
//!
//! let script = Script(vec![OP_1, OP_DUP]);
//! let cs = ConstraintSystem::<ScalarField>::new_ref();
//! let script_var = ScriptVar::<ScalarField>::new_input(cs.clone(), || Ok(script)).unwrap();
//! script_var.enforce_equal(&script_var);
//! assert!(cs.is_satisfied().unwrap());
//! ```

/// R1CS version of Bitcoin structures
pub mod constraints;

pub mod traits;
pub mod util;
