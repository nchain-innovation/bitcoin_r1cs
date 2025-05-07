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
/// has locking script equal to `lock_script` between bytes `start` and `end`
/// **Note**: Even though only a sub locking script is enforced, the total length of
/// the locking script is fixed by `P`
pub struct FixedSubLockScript<F: PrimeField, P: TxVarConfig + Clone> {
    pub lock_script: Script,
    pub index: usize,
    pub start: usize,
    pub end: usize,
    _phantom_field: PhantomData<F>,
    _phantom_config: PhantomData<P>,
}

impl<F: PrimeField, P: TxVarConfig + Clone> FixedSubLockScript<F, P> {
    pub fn new(lock_script: Script, index: usize, start: usize, end: usize) -> Self {
        Self {
            lock_script,
            index,
            start,
            end,
            _phantom_field: PhantomData,
            _phantom_config: PhantomData,
        }
    }
}

impl<F: PrimeField, P: TxVarConfig + Clone> BitcoinPredicate<F, P> for FixedSubLockScript<F, P> {
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

        assert!(
            self.end <= spending_data.outputs[self.index].lock_script.0.len(),
            "End index: {} is larger the the size of the locking script: {}",
            self.end,
            spending_data.outputs[self.index].lock_script.0.len()
        );

        // Enforce that output at index `self.index` has the correct sub locking script
        let fixed_sub_lock = ScriptVar::<F>::new_constant(cs.clone(), self.lock_script.clone())?;
        spending_data.outputs[self.index].lock_script.0[self.start..self.end]
            .is_eq(&fixed_sub_lock.0)
    }
}

#[cfg(test)]
mod test {

    use ark_bls12_381::Fr as F;

    use ark_r1cs_std::alloc::AllocVar;

    use ark_relations::r1cs::ConstraintSystem;
    use chain_gang::address::addr_decode;
    use chain_gang::script::Script;
    use chain_gang::script::op_codes::{OP_0, OP_1};

    use chain_gang::messages::{OutPoint, Tx, TxIn, TxOut};
    use chain_gang::network::Network;
    use chain_gang::transaction::p2pkh;
    use chain_gang::util::Hash256;

    use crate::bitcoin_predicates::data_structures::unit::BitcoinUnitVar;
    use crate::constraints::tx::TxVar;

    use crate::{constraints::tx::TxVarConfig, traits::BitcoinPredicate};

    use super::FixedSubLockScript;

    #[derive(Clone)]
    struct Config;
    impl TxVarConfig for Config {
        const N_INPUTS: usize = 1;
        const N_OUTPUTS: usize = 2;
        const LEN_UNLOCK_SCRIPTS: &[usize] = &[0];
        const LEN_LOCK_SCRIPTS: &[usize] = &[0x1c, 0x19];
    }

    fn test_predicate(
        addr: &str,
        lock_script: Script,
        index: usize,
        start: usize,
        end: usize,
        expected: bool,
    ) {
        let hash160 = addr_decode(addr, Network::BSV_Testnet).unwrap().0;
        let mut extended_lock_script = lock_script.clone();
        extended_lock_script.append_slice(&[OP_0, OP_0, OP_1]);
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
                    lock_script: extended_lock_script,
                },
                TxOut {
                    satoshis: 259899900,
                    lock_script: p2pkh::create_lock_script(&hash160),
                },
            ],
            lock_time: 0,
        };

        let predicate = FixedSubLockScript::<F, Config>::new(lock_script, index, start, end);

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
        test_predicate(addr, lock_script, 0, 0, 0x19, true);
    }

    #[test]
    fn test_predicate_is_ok_2() {
        let addr = "mfmKD4cP6Na7T8D87XRSiR7shA1HNGSaec";
        let hash160 = addr_decode(addr, Network::BSV_Testnet).unwrap().0;
        let lock_script = p2pkh::create_lock_script(&hash160);
        test_predicate(addr, lock_script, 1, 0, 0x19, true);
    }

    #[test]
    fn test_predicate_fails() {
        let addr = "mfmKD4cP6Na7T8D87XRSiR7shA1HNGSaec";
        let wrong_addr = "mzXd2pQG2dbgK9trYAZcpKycWDEfjVbeMz";
        let hash160 = addr_decode(addr, Network::BSV_Testnet).unwrap().0;
        let lock_script = p2pkh::create_lock_script(&hash160);
        test_predicate(wrong_addr, lock_script, 1, 0, 0x19, false);
    }

    #[test]
    fn test_predicate_fails_2() {
        let addr = "mfmKD4cP6Na7T8D87XRSiR7shA1HNGSaec";
        let hash160 = addr_decode(addr, Network::BSV_Testnet).unwrap().0;
        let lock_script = p2pkh::create_lock_script(&hash160);
        test_predicate(addr, lock_script, 0, 1, 0x1a, false);
    }
}
