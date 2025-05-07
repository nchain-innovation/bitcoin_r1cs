use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    eq::EqGadget,
    prelude::{AllocVar, Boolean},
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use chain_gang::script::Script;

use crate::bitcoin_predicates::data_structures::unit::{BitcoinUnit, BitcoinUnitVar};
use crate::constraints::{
    script::ScriptVar,
    tx::{TxVar, TxVarConfig},
};
use crate::traits::BitcoinPredicate;

/// Bitcoin Predicate to enforce that the output of the transaction at `index`
/// has locking script equal to `lock_script`
pub struct FixedLockScript<F: PrimeField, P: TxVarConfig + Clone> {
    pub lock_script: Script,
    pub index: usize,
    _phantom_field: PhantomData<F>,
    _phantom_config: PhantomData<P>,
}

impl<F: PrimeField, P: TxVarConfig + Clone> FixedLockScript<F, P> {
    pub fn new(lock_script: Script, index: usize) -> Self {
        Self {
            lock_script,
            index,
            _phantom_field: PhantomData,
            _phantom_config: PhantomData,
        }
    }
}

impl<F: PrimeField, P: TxVarConfig + Clone> BitcoinPredicate<F, P> for FixedLockScript<F, P> {
    type LockingData = BitcoinUnit<F, P>;
    type UnlockingData = BitcoinUnit<F, P>;
    type Witness = BitcoinUnit<F, P>;

    type LockingDataVar = BitcoinUnitVar<F, P>;
    type UnlockingDataVar = BitcoinUnitVar<F, P>;
    type WitnessVar = BitcoinUnitVar<F, P>;

    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
        _locking_data: &Self::LockingDataVar,
        _unlocking_data: &Self::UnlockingDataVar,
        spending_data: &TxVar<F, P>,
        _witness: &Self::WitnessVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        // Validate input
        assert!(
            self.index <= spending_data.outputs.len(),
            "Index: {} is larger the the number of outputs: {}",
            self.index,
            spending_data.outputs.len()
        );

        // Enforce that output at index `self.index` has the correct locking script
        spending_data.outputs[self.index]
            .lock_script
            .is_eq(&ScriptVar::<F>::new_constant(
                cs.clone(),
                self.lock_script.clone(),
            )?)
    }
}

#[cfg(test)]
mod test {

    use ark_bls12_381::Fr as F;

    use ark_r1cs_std::alloc::AllocVar;

    use ark_relations::r1cs::ConstraintSystem;
    use chain_gang::address::addr_decode;
    use chain_gang::script::Script;

    use chain_gang::messages::{OutPoint, Tx, TxIn, TxOut};
    use chain_gang::network::Network;
    use chain_gang::transaction::p2pkh;
    use chain_gang::util::Hash256;

    use crate::bitcoin_predicates::data_structures::unit::BitcoinUnitVar;
    use crate::constraints::tx::TxVar;

    use crate::{constraints::tx::TxVarConfig, traits::BitcoinPredicate};

    use super::FixedLockScript;

    #[derive(Clone)]
    struct Config;
    impl TxVarConfig for Config {
        const N_INPUTS: usize = 1;
        const N_OUTPUTS: usize = 2;
        const LEN_UNLOCK_SCRIPTS: &[usize] = &[0];
        const LEN_LOCK_SCRIPTS: &[usize] = &[0x19, 0x19];
    }

    fn test_predicate(addr: &str, lock_script: Script, index: usize, expected: bool) {
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
                    lock_script: lock_script.clone(),
                },
                TxOut {
                    satoshis: 259899900,
                    lock_script: p2pkh::create_lock_script(&hash160),
                },
            ],
            lock_time: 0,
        };

        let predicate = FixedLockScript::<F, Config>::new(lock_script, index);

        let cs = ConstraintSystem::<F>::new_ref();
        let tx_var = TxVar::<F, Config>::new_input(cs.clone(), || Ok(tx)).unwrap();
        predicate
            .enforce_constraints(
                cs.clone(),
                &BitcoinUnitVar::default(),
                &BitcoinUnitVar::default(),
                &tx_var,
                &BitcoinUnitVar::default(),
            )
            .unwrap();
        assert_eq!(cs.is_satisfied().unwrap(), expected);
    }

    #[test]
    fn test_predicate_is_ok() {
        let addr = "mfmKD4cP6Na7T8D87XRSiR7shA1HNGSaec";
        let hash160 = addr_decode(addr, Network::BSV_Testnet).unwrap().0;
        let lock_script = p2pkh::create_lock_script(&hash160);
        test_predicate(addr, lock_script, 0, true);
    }

    #[test]
    fn test_predicate_fails() {
        let addr = "mfmKD4cP6Na7T8D87XRSiR7shA1HNGSaec";
        let wrong_addr = "mzXd2pQG2dbgK9trYAZcpKycWDEfjVbeMz";
        let hash160 = addr_decode(addr, Network::BSV_Testnet).unwrap().0;
        let lock_script = p2pkh::create_lock_script(&hash160);
        test_predicate(wrong_addr, lock_script, 1, false);
    }
}
