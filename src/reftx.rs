use ark_ff::PrimeField;
use ark_r1cs_std::{alloc::AllocVar, uint64::UInt64};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use chain_gang::{messages::Tx, script::Script, transaction::sighash::SigHashCache};

use crate::{
    constraints::{
        script::ScriptVar,
        sighash_cache::SigHashCacheVar,
        tx::{TxVar, TxVarConfig},
    },
    traits::BitcoinPredicate,
    transaction_integrity_gadget::{
        TransactionIntegrityConfig, TransactionIntegrityTag,
        constraints::{TransactionIntegrityGadget, TransactionIntegrityTagVar},
    },
    util::default_tx,
};

pub struct RefTxCircuit<
    B: BitcoinPredicate<F, P>,
    F: PrimeField + Clone,
    P: TxVarConfig + TransactionIntegrityConfig + Clone,
> {
    /// Public inputs
    pub locking_data: B::LockingData,
    pub integrity_tag: Option<TransactionIntegrityTag>,
    pub unlocking_data: B::UnlockingData,
    /// Witness values
    pub witness: B::Witness,
    pub spending_data: Option<Tx>,
    pub prev_lock_script: Option<Script>,
    pub prev_amount: Option<u64>,
    pub sighash_cache: Option<SigHashCache>,
    /// Predicate
    pub predicate: B,
}

impl<B, F, P> RefTxCircuit<B, F, P>
where
    B: BitcoinPredicate<F, P>,
    F: PrimeField + Clone,
    P: TxVarConfig + TransactionIntegrityConfig + Clone,
{
    pub fn public_input(&self) -> Vec<F> {
        let mut input = Vec::<F>::new();
        input.extend_from_slice(&self.locking_data.clone().into());
        input.extend_from_slice(&Into::<Vec<F>>::into(
            self.integrity_tag.clone().unwrap_or_default(),
        ));
        input.extend_from_slice(&self.unlocking_data.clone().into());

        input
    }
}
impl<B, F, P> ConstraintSynthesizer<F> for RefTxCircuit<B, F, P>
where
    B: BitcoinPredicate<F, P>,
    F: PrimeField + Clone,
    P: TxVarConfig + TransactionIntegrityConfig + Clone,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Allocate the inputs
        let locking_data: B::LockingDataVar =
            B::LockingDataVar::new_input(cs.clone(), || Ok(self.locking_data))?;
        let integrity_tag: TransactionIntegrityTagVar<F> =
            TransactionIntegrityTagVar::<F>::new_input(cs.clone(), || {
                Ok(self.integrity_tag.unwrap_or_default())
            })?;
        let unlocking_data: B::UnlockingDataVar =
            B::UnlockingDataVar::new_input(cs.clone(), || Ok(self.unlocking_data))?;
        // Allocate the witnesses
        let witness: B::WitnessVar = B::WitnessVar::new_witness(cs.clone(), || Ok(self.witness))?;
        let spending_data: TxVar<F, P> = TxVar::<F, P>::new_witness(cs.clone(), || {
            Ok(self.spending_data.unwrap_or(default_tx::<P>()))
        })?;
        let default_prev_lock_script = Script(vec![0; P::LEN_PREV_LOCK_SCRIPT]);
        let prev_lock_script: ScriptVar<F> = ScriptVar::<F>::new_witness(cs.clone(), || {
            Ok(self.prev_lock_script.unwrap_or(default_prev_lock_script))
        })?;
        let prev_amount: UInt64<F> =
            UInt64::<F>::new_witness(cs.clone(), || Ok(self.prev_amount.unwrap_or(0)))?;
        let mut sighash_cache: SigHashCacheVar<F> =
            SigHashCacheVar::<F>::new_witness(cs.clone(), || {
                Ok(self.sighash_cache.unwrap_or_default())
            })?;

        // Enforce the integrity of the tag
        TransactionIntegrityGadget::<F, P>::verify(
            cs.clone(),
            &spending_data,
            &prev_lock_script,
            &prev_amount,
            &mut sighash_cache,
            &integrity_tag,
        )?;

        // Enforce the predicate
        self.predicate.enforce_constraints(
            cs.clone(),
            &locking_data,
            &unlocking_data,
            &spending_data,
            &witness,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ark_bls12_381::Fr as F;

    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use chain_gang::address::addr_decode;
    use chain_gang::script::Script;
    use chain_gang::transaction::sighash::{SIGHASH_ALL, SIGHASH_FORKID, SigHashCache};

    use chain_gang::messages::{OutPoint, Tx, TxIn, TxOut};
    use chain_gang::network::Network;
    use chain_gang::transaction::p2pkh;
    use chain_gang::util::Hash256;

    use crate::bitcoin_predicates::data_structures::unit::BitcoinUnit;
    use crate::bitcoin_predicates::fixed_lock_script::FixedLockScript;
    use crate::constraints::tx::TxVarConfig;
    use crate::transaction_integrity_gadget::{
        TransactionIntegrityConfig, TransactionIntegrityScheme,
    };

    use super::RefTxCircuit;

    type TestPredicate = FixedLockScript<F, Config>;

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
        const LEN_PREV_LOCK_SCRIPT: usize = 0x00;
        const SIGHASH_FLAG: u8 = SIGHASH_ALL | SIGHASH_FORKID;
    }

    fn test_reftx(addr: &str, lock_script: Script, expected: bool) {
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
                    lock_script,
                },
                TxOut {
                    satoshis: 259899900,
                    lock_script: p2pkh::create_lock_script(&hash160),
                },
            ],
            lock_time: 0,
        };
        let mut cache = SigHashCache::new();

        let tag = TransactionIntegrityScheme::<Config>::commit(
            &tx.clone(),
            &Script(vec![]),
            260000,
            &mut cache,
        );
        let test_predicate = TestPredicate::new(p2pkh::create_lock_script(&hash160), 0);
        let test_circuit = RefTxCircuit::<TestPredicate, F, Config> {
            locking_data: BitcoinUnit::default(),
            integrity_tag: Some(tag),
            unlocking_data: BitcoinUnit::default(),
            witness: BitcoinUnit::default(),
            spending_data: Some(tx),
            prev_lock_script: Some(Script(vec![])),
            prev_amount: Some(260000),
            sighash_cache: None,
            predicate: test_predicate,
        };

        let cs = ConstraintSystem::<F>::new_ref();
        test_circuit.generate_constraints(cs.clone()).unwrap();
        let is_satisfied = cs.is_satisfied().unwrap();

        assert_eq!(is_satisfied, expected);
    }

    #[test]
    fn test_reftx_is_ok() {
        let addr = "mfmKD4cP6Na7T8D87XRSiR7shA1HNGSaec";
        let hash160 = addr_decode(addr, Network::BSV_Testnet).unwrap().0;
        let lock_script = p2pkh::create_lock_script(&hash160);
        test_reftx(addr, lock_script, true);
    }

    #[test]
    fn test_reftx_fails() {
        let addr = "mfmKD4cP6Na7T8D87XRSiR7shA1HNGSaec";
        let wrong_addr = "mzXd2pQG2dbgK9trYAZcpKycWDEfjVbeMz";
        let hash160 = addr_decode(wrong_addr, Network::BSV_Testnet).unwrap().0;
        let lock_script = p2pkh::create_lock_script(&hash160);
        test_reftx(addr, lock_script, false);
    }
}
