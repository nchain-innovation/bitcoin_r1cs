use anyhow::Result;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::prelude::Boolean;
use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::constraints::tx::TxVar;
use crate::{constraints::tx::TxVarConfig, traits::BitcoinPredicate};

use crate::bitcoin_predicates::data_structures::{
    unit::{BitcoinUnit, BitcoinUnitVar},
    byte_array::{ByteArray, ByteArrayVar},
};

/// Bitcoin Predicate that prevents replay attacks
/// When used in conjunction with another predicate, it modifies the circuit `C` so that
/// it attests to the satisfiability of `C` and the fact that the data of length `N`, held in the output at position
/// `index`, and starting a position `data_start_index` in the locking script, is equal to the data passed as witness.
/// While this information is not secret, adding this predicate makes it impossible to replay the proof in
/// a transaction with different data. For example, the data could be a Bitcoin address
pub struct PreventReplayAttack<const N: usize, F: PrimeField, P: TxVarConfig + Clone> {
    pub index: usize,
    pub data_start_index: usize,
    _phantom_field: PhantomData<F>,
    _phantom_config: PhantomData<P>,
}

impl<const N: usize, F: PrimeField, P: TxVarConfig + Clone> PreventReplayAttack<N, F, P> {
    pub fn new(index: usize, data_start_index: usize) -> Result<Self> {
        Ok(Self {
            index,
            data_start_index,
            _phantom_field: PhantomData,
            _phantom_config: PhantomData,
        })
    }
}

impl<const N: usize, F: PrimeField, P: TxVarConfig + Clone> BitcoinPredicate<F, P>
    for PreventReplayAttack<N, F, P>
{
    type LockingData = BitcoinUnit<F, P>;
    type UnlockingData = BitcoinUnit<F, P>;
    type Witness = ByteArray<N, F, P>;

    type LockingDataVar = BitcoinUnitVar<F, P>;
    type UnlockingDataVar = BitcoinUnitVar<F, P>;
    type WitnessVar = ByteArrayVar<N, F, P>;

    fn generate_constraints(
        &self,
        _cs: ConstraintSystemRef<F>,
        _locking_data: &Self::LockingDataVar,
        _unlocking_data: &Self::UnlockingDataVar,
        spending_data: &TxVar<F, P>,
        witness: &Self::WitnessVar,
    ) -> Result<Boolean<F>, SynthesisError> {
        // Validate input
        assert!(
            self.index <= spending_data.outputs.len(),
            "Index: {} is larger the the number of outputs: {}",
            self.index,
            spending_data.outputs.len()
        );

        // Verify the data against the witness
        let mut is_data_correct: Vec<Boolean<F>> = Vec::new();
        for (data, wit) in spending_data.outputs[self.index].lock_script.0
            [self.data_start_index..(self.data_start_index + N)]
            .iter()
            .zip(witness.bytes.iter())
        {
            is_data_correct.push(data.is_eq(wit)?);
        }

        Boolean::<F>::kary_and(&is_data_correct)
    }
}

#[cfg(test)]
mod test {
    use crate::traits::BitcoinPredicate;
    use crate::{
        bitcoin_predicates::data_structures::{
            unit::BitcoinUnitVar,
            byte_array::{ByteArray, ByteArrayVar},
        },
        constraints::tx::{TxVar, TxVarConfig},
    };
    use ark_bls12_381::Fr as F;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_relations::r1cs::ConstraintSystem;
    use chain_gang::{
        address::addr_decode,
        messages::{OutPoint, Tx, TxIn, TxOut},
        network::Network,
        script::Script,
        transaction::p2pkh,
        util::Hash256,
    };

    #[derive(Clone)]
    struct Config;
    impl TxVarConfig for Config {
        const N_INPUTS: usize = 1;
        const N_OUTPUTS: usize = 1;
        const LEN_UNLOCK_SCRIPTS: &[usize] = &[0];
        const LEN_LOCK_SCRIPTS: &[usize] = &[0x19];
    }

    use super::PreventReplayAttack;

    type TestPredicate = PreventReplayAttack<20, F, Config>;

    fn test_predicate(addr: &str, hash: [u8; 20], expected: bool) {
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
            outputs: vec![TxOut {
                satoshis: 259899900,
                lock_script: p2pkh::create_lock_script(&hash160),
            }],
            lock_time: 0,
        };

        let predicate = TestPredicate::new(0, 3).unwrap();

        let cs = ConstraintSystem::<F>::new_ref();
        let tx_var = TxVar::<F, Config>::new_input(cs.clone(), || Ok(tx)).unwrap();
        let wit_var =
            ByteArrayVar::<20, F, Config>::new_input(cs.clone(), || Ok(ByteArray::new(hash)))
                .unwrap();
        predicate
            .enforce_constraints(
                cs.clone(),
                &BitcoinUnitVar::default(),
                &BitcoinUnitVar::default(),
                &tx_var,
                &wit_var,
            )
            .unwrap();
        assert_eq!(cs.is_satisfied().unwrap(), expected);
    }

    #[test]
    fn test_predicate_is_ok() {
        let addr = "mfmKD4cP6Na7T8D87XRSiR7shA1HNGSaec";
        let hash160 = addr_decode(addr, Network::BSV_Testnet).unwrap().0;

        test_predicate(addr, hash160.0, true);
    }

    #[test]
    fn test_predicate_fails() {
        let addr = "mfmKD4cP6Na7T8D87XRSiR7shA1HNGSaec";
        let wrong_addr = "mzXd2pQG2dbgK9trYAZcpKycWDEfjVbeMz";

        let hash160 = addr_decode(addr, Network::BSV_Testnet).unwrap().0;

        test_predicate(wrong_addr, hash160.0, false);
    }
}
