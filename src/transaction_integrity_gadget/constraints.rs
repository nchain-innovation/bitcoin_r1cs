//! Gadget to enforce the integrity of the transaction data

use std::borrow::Borrow;
use std::marker::PhantomData;
use std::result::Result;

use ark_crypto_primitives::crh::sha256::constraints::DigestVar;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::{Boolean, ToBytesGadget},
    uint8::UInt8,
    uint64::UInt64,
};
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};

use crate::constraints::{
    script::ScriptVar,
    sighash_cache::SigHashCacheVar,
    tx::{TxVar, TxVarConfig},
};
use crate::transaction_integrity_gadget::utils::{get_chunk_size, to_fp_chunks};
use crate::transaction_integrity_gadget::{TransactionIntegrityConfig, TransactionIntegrityTag};

/// The R1CS version [TransactionIntegrityTag]
/// It is a a vector because the tag needs to be chunked according to
/// the bit size of the modulus over which F is defined
pub struct TransactionIntegrityTagVar<F: PrimeField> {
    pub inner: Vec<FpVar<F>>,
}

/// The gadget version of [TransactionIntegrityScheme](crate::transaction_integrity_gadget::TransactionIntegrityScheme)
pub struct TransactionIntegrityGadget<F: PrimeField, P: TransactionIntegrityConfig> {
    _ti_structure: PhantomData<P>,
    _field: PhantomData<F>,
}

impl<F: PrimeField> TransactionIntegrityTagVar<F> {
    /// Convert the FpVar elements of the tag into their little endian byte representation
    pub fn to_bytes(&self) -> Result<Vec<Vec<UInt8<F>>>, SynthesisError> {
        let chunk_size = get_chunk_size::<F>();
        let mut result: Vec<Vec<UInt8<F>>> = Vec::new();
        for fp in self.inner.iter() {
            result.push(fp.to_bytes_le()?[..chunk_size].to_vec());
        }

        Ok(result)
    }
}

impl<F: PrimeField> AllocVar<TransactionIntegrityTag, F> for TransactionIntegrityTagVar<F> {
    fn new_variable<T: Borrow<TransactionIntegrityTag>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let tag: TransactionIntegrityTag = f().map(|t| t.borrow().clone())?;
        let mut inner: Vec<FpVar<F>> = Vec::new();
        for chunk in to_fp_chunks(&tag.inner).iter() {
            inner.push(FpVar::<F>::new_variable(cs.clone(), || Ok(chunk), mode)?);
        }

        Ok(Self { inner })
    }
}

impl<F: PrimeField> EqGadget<F> for TransactionIntegrityTagVar<F> {
    fn is_eq(&self, other: &Self) -> std::result::Result<Boolean<F>, SynthesisError> {
        self.inner.is_eq(&other.inner)
    }
}

impl<F: PrimeField, P: TransactionIntegrityConfig + TxVarConfig + Clone>
    TransactionIntegrityGadget<F, P>
{
    /// Verify the integrity of a tag
    pub fn verify(
        _cs: ConstraintSystemRef<F>,
        tx: &TxVar<F, P>,
        prev_lock_script: &ScriptVar<F>,
        prev_amount: &UInt64<F>,
        sighash_cache: &mut SigHashCacheVar<F>,
        tag: &TransactionIntegrityTagVar<F>,
    ) -> Result<(), SynthesisError> {
        // Validate data against the configuration
        assert_eq!(
            prev_lock_script.0.len(),
            P::LEN_PREV_LOCK_SCRIPT,
            "The length of the previous locking script: {} is different from the one set in the parameters: P::LEN_PREV_LOCK_SCRIPT = {}",
            prev_lock_script.0.len(),
            P::LEN_PREV_LOCK_SCRIPT
        );
        // Compute the tag from `tx`, `prev_lock_script` and `prev_amount`
        let computed_tag: DigestVar<F> = tx.sighash(
            P::N_INPUT,
            prev_lock_script,
            prev_amount,
            &P::SIGHASH_FLAG,
            sighash_cache,
        )?;

        let chunk_size = get_chunk_size::<F>();
        let mut is_valid_tag: Vec<Boolean<F>> = Vec::new();
        for (public, computed) in tag
            .to_bytes()?
            .iter()
            .zip(computed_tag.0.chunks_exact(chunk_size))
        {
            is_valid_tag.push(public.is_eq(&computed.to_vec())?);
        }

        Boolean::<F>::kary_and(&is_valid_tag)?.enforce_equal(&Boolean::<F>::TRUE)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_gang::address::addr_decode;
    use chain_gang::transaction::sighash::{SIGHASH_ALL, SIGHASH_FORKID, SigHashCache};

    use chain_gang::messages::{OutPoint, Tx, TxIn, TxOut};
    use chain_gang::network::Network;
    use chain_gang::transaction::p2pkh;
    use hex;

    use ark_bls12_381::Fq as F;

    use ark_relations::r1cs::ConstraintSystem;

    use chain_gang::script::Script;
    use chain_gang::util::Hash256;

    use crate::transaction_integrity_gadget::{
        TransactionIntegrityConfig, TransactionIntegrityScheme,
    };

    #[derive(Clone)]
    struct Config;
    impl TxVarConfig for Config {
        const N_INPUTS: usize = 1;
        const N_OUTPUTS: usize = 2;
        const LEN_UNLOCK_SCRIPTS: &[usize] = &[0];
        const LEN_LOCK_SCRIPTS: &[usize] = &[0x19, 0x19];
    }

    impl TransactionIntegrityConfig for Config {
        const N_INPUT: usize = 0;
        const LEN_PREV_LOCK_SCRIPT: usize = 0x19;
        const SIGHASH_FLAG: u8 = SIGHASH_ALL | SIGHASH_FORKID;
    }

    fn test_ti_verify(prev_amount_tag: u64, prev_amount_allocated: u64) -> ConstraintSystemRef<F> {
        let prev_lock_script =
            Script(hex::decode("76a91402b74813b047606b4b3fbdfb1a6e8e053fdb8dab88ac").unwrap());
        let addr = "mfmKD4cP6Na7T8D87XRSiR7shA1HNGSaec";
        let hash160 = addr_decode(addr, Network::BSV_Testnet).unwrap().0;
        let tx = Tx {
            version: 2,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    hash: Hash256::decode(
                        "f671dc000ad12795e86b59b27e0c367d9b026bbd4141c227b9285867a53bb6f7",
                    )
                    .unwrap(),
                    index: 0,
                },
                unlock_script: Script(vec![]),
                sequence: 0,
            }],
            outputs: vec![
                TxOut {
                    satoshis: 100,
                    lock_script: p2pkh::create_lock_script(&hash160),
                },
                TxOut {
                    satoshis: 259899900,
                    lock_script: p2pkh::create_lock_script(&hash160),
                },
            ],
            lock_time: 0,
        };
        let mut cache = SigHashCache::new();

        // TI tag
        let tag = TransactionIntegrityScheme::<Config>::commit(
            &tx,
            &prev_lock_script,
            prev_amount_tag,
            &mut cache,
        );

        let cs = ConstraintSystem::<F>::new_ref();
        let allocated_tag =
            TransactionIntegrityTagVar::<F>::new_input(cs.clone(), || Ok(tag)).unwrap();
        let allocated_tx = TxVar::<F, Config>::new_input(cs.clone(), || Ok(tx)).unwrap();
        let allocated_prev_lock_script =
            ScriptVar::<F>::new_input(cs.clone(), || Ok(prev_lock_script)).unwrap();
        let allocated_prev_amount =
            UInt64::<F>::new_input(cs.clone(), || Ok(prev_amount_allocated)).unwrap();
        let mut allocated_cache = SigHashCacheVar::<F>::new();
        TransactionIntegrityGadget::<F, Config>::verify(
            cs.clone(),
            &allocated_tx,
            &allocated_prev_lock_script,
            &allocated_prev_amount,
            &mut allocated_cache,
            &allocated_tag,
        )
        .unwrap();

        let is_verified = cs.is_satisfied().unwrap();
        assert!(is_verified);

        cs
    }

    #[test]
    fn test_ti_verify_is_ok() {
        test_ti_verify(2600000, 2600000);
    }

    #[test]
    #[should_panic]
    fn test_ti_verify_fails() {
        test_ti_verify(2600000, 26);
    }

    #[test]
    fn print_constraints() {
        let cs = test_ti_verify(2600000, 2600000);
        dbg!(
            "The number of constaints for the TI gadget are: {}",
            cs.num_constraints()
        );
    }
}
