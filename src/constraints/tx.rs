//! Implementation of [TxVar], R1CS version of a Bitcoin [Tx]
use ark_crypto_primitives::crh::sha256::constraints::DigestVar;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    R1CSVar,
    alloc::AllocVar,
    prelude::{AllocationMode, ToBytesGadget},
    uint8::UInt8,
    uint32::UInt32,
    uint64::UInt64,
};

use crate::constraints::{script::ScriptVar, txin::TxInVar, txout::TxOutVar};
use crate::traits::PreSigHashSerialise;
use crate::util::usize_to_var_int;
use chain_gang::messages::Tx;

use ark_relations::r1cs::{Namespace, SynthesisError};
use std::{borrow::Borrow, marker::PhantomData};

use crate::constraints::hash256::Hash256Gadget;
use crate::constraints::sighash_cache::SigHashCacheVar;

use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;

use ark_relations::r1cs::ConstraintSystemRef;

use chain_gang::transaction::sighash::{
    SIGHASH_ANYONECANPAY, SIGHASH_FORKID, SIGHASH_NONE, SIGHASH_SINGLE,
};

/// Configuration trait for [TxVar]: it specifies the structure of the transaction that is going to be allocated in the circuit
///
/// **NOTE**:
/// The trait forces the user to explicitly define the structure of the transaction.
/// This is useful when the circuits are used in SNARKs with a circuit specific setup, as it makes it easier to detect errors due to the use of proving/verifying
/// keys incompatible with a given transaction structure.
pub trait TxVarConfig {
    /// Number of inputs
    const N_INPUTS: usize;
    /// Number of outputs
    const N_OUTPUTS: usize;
    /// Length of unlocking scripts
    const LEN_UNLOCK_SCRIPTS: &[usize];
    /// Length of locking scripts
    const LEN_LOCK_SCRIPTS: &[usize];
    /// Length of script_code for sighash calculation
    const LEN_PREV_LOCK_SCRIPT: Option<usize>;
    /// Index of the input for which we compute the pre_sighash
    const PRE_SIGHASH_N_INPUT: Option<usize>;
}

/// R1CS version of [Tx]
#[derive(Debug)]
pub struct TxVar<F: PrimeField, P: TxVarConfig + Clone> {
    _config: PhantomData<P>,
    pub version: UInt32<F>,
    pub inputs: Vec<TxInVar<F>>,
    pub outputs: Vec<TxOutVar<F>>,
    pub lock_time: UInt32<F>,
}

impl<F: PrimeField, P: TxVarConfig + Clone> Clone for TxVar<F, P> {
    fn clone(&self) -> Self {
        Self {
            _config: PhantomData,
            version: self.version.clone(),
            inputs: self.inputs.clone(),
            outputs: self.outputs.clone(),
            lock_time: self.lock_time.clone(),
        }
    }
}

impl<F: PrimeField, P: TxVarConfig + Clone> TxVar<F, P> {
    /// Calculate the txid of `Self`
    pub fn txid(&self) -> Result<DigestVar<F>, SynthesisError> {
        Hash256Gadget::<F>::evaluate(self.to_bytes_le()?.as_slice())
    }
    /// Compute the serialisation of [Tx] for `pre_sighash` calculation.
    /// See [Message Digest Algorithm](https://github.com/bitcoin-sv/bitcoin-sv/blob/master/doc/abc/replay-protected-sighash.md#digest-algorithm) for a description of the algorithm.
    ///
    /// **Note**: The function assumes that `prev_lock_script` has already been modified to handle `OP_CODESEPARATOR`.
    pub fn pre_sighash_serialise(
        &self,
        prev_lock_script: &ScriptVar<F>,
        satoshis: &UInt64<F>,
        sighash_flags: &u8,
        cache: &mut SigHashCacheVar<F>,
    ) -> Result<Vec<UInt8<F>>, SynthesisError> {
        /*
         *
         * Validate configuration
         *
         */

        // Check that P::PRE_SIGHASH_N_INPUT is set
        assert!(
            P::PRE_SIGHASH_N_INPUT.is_some(),
            "P::PRE_SIGHASH_N_INPUT must be set when computing the pre_sighash"
        );
        assert!(
            P::LEN_PREV_LOCK_SCRIPT.is_some(),
            "P::LEN_PREV_LOCK_SCRIPT must be set when computing the pre_sighash"
        );

        let len_prev_lock_script = P::LEN_PREV_LOCK_SCRIPT.unwrap();
        // Check that prev_lock_script has the correct length
        assert_eq!(
            prev_lock_script.0.len(),
            len_prev_lock_script,
            "The previous locking script has length: {}, different from P::LEN_PREV_LOCK_SCRIPT: {}",
            prev_lock_script.0.len(),
            len_prev_lock_script,
        );

        // n_input for indexing
        let n_input_usize = P::PRE_SIGHASH_N_INPUT.unwrap();

        // Handle sighash flags
        let base_flags = sighash_flags & 31;
        let anyone_can_pay = sighash_flags & SIGHASH_ANYONECANPAY != 0;

        // 1. Serialised version
        let version: Vec<UInt8<F>> = self.version.to_bytes_le()?;
        // 2. HashPrevOut
        // The first condition to be checked is that the cache is None.
        // If it is, then we either compute or set the value. Otherwise, we do nothing.
        if cache.hash_prevouts.is_none() {
            if !anyone_can_pay {
                let mut s: Vec<UInt8<F>> = Vec::new();
                for input in self.inputs.iter() {
                    s.extend_from_slice(input.prev_output.pre_sighash_serialise()?.as_slice());
                }
                cache.set_hash_prevouts(Hash256Gadget::<F>::evaluate(&s)?);
            } else {
                cache.set_hash_prevouts(DigestVar(vec![UInt8::<F>::constant(0); 32]));
            }
        };
        // 3. HashSequence
        // The first condition to be checked is that the cache is None.
        // If it is, then we either compute or set the value. Otherwise, we do nothing.
        if cache.hash_sequence.is_none() {
            if !anyone_can_pay && base_flags != SIGHASH_SINGLE && base_flags != SIGHASH_NONE {
                let mut s: Vec<UInt8<F>> = Vec::new();
                for input in self.inputs.iter() {
                    s.extend_from_slice(input.sequence.to_bytes_le()?.as_slice());
                }
                cache.set_hash_sequence(Hash256Gadget::<F>::evaluate(&s)?);
            } else {
                cache.set_hash_sequence(DigestVar(vec![UInt8::<F>::constant(0); 32]));
            }
        };
        // 4. Input specific part
        let input_specific_serialisation =
            self.inputs[n_input_usize].pre_sighash_serialise(prev_lock_script, satoshis)?;
        // 5. HashOutputs
        // The first condition to be checked is that the cache is None.
        // If it is, then we either compute or set the value. Otherwise, we do nothing.
        if cache.hash_outputs.is_none() {
            if base_flags != SIGHASH_SINGLE && base_flags != SIGHASH_NONE {
                let mut s: Vec<UInt8<F>> = Vec::new();
                for output in self.outputs.iter() {
                    s.extend_from_slice(output.pre_sighash_serialise()?.as_slice());
                }
                cache.set_hash_outputs(Hash256Gadget::<F>::evaluate(&s)?);
            } else if base_flags == SIGHASH_SINGLE && n_input_usize < self.outputs.len() {
                cache.set_hash_outputs(Hash256Gadget::<F>::evaluate(
                    &self.outputs[n_input_usize].pre_sighash_serialise()?,
                )?);
            } else {
                cache.set_hash_outputs(DigestVar(vec![UInt8::<F>::constant(0); 32]));
            }
        };
        // 6. Locktime
        let lock_time = self.lock_time.to_bytes_le()?;

        let mut ser: Vec<UInt8<F>> = Vec::new();
        ser.extend_from_slice(version.as_slice());
        ser.extend_from_slice(cache.hash_prevouts().unwrap().to_bytes_le()?.as_slice());
        ser.extend_from_slice(cache.hash_sequence().unwrap().to_bytes_le()?.as_slice());
        ser.extend_from_slice(input_specific_serialisation.as_slice());
        ser.extend_from_slice(cache.hash_outputs().unwrap().to_bytes_le()?.as_slice());
        ser.extend_from_slice(lock_time.as_slice());
        ser.extend_from_slice(
            UInt32::<F>::constant((SIGHASH_FORKID | sighash_flags) as u32)
                .to_bytes_le()?
                .as_slice(),
        );

        Ok(ser)
    }
    /// Sighash calculation
    pub fn sighash(
        &self,
        prev_lock_script: &ScriptVar<F>,
        satoshis: &UInt64<F>,
        sighash_flags: &u8,
        cache: &mut SigHashCacheVar<F>,
    ) -> Result<DigestVar<F>, SynthesisError> {
        let pre_sighash =
            self.pre_sighash_serialise(prev_lock_script, satoshis, sighash_flags, cache)?;
        Hash256Gadget::<F>::evaluate(&pre_sighash)
    }
}

impl<F: PrimeField, P: TxVarConfig + Clone> AllocVar<Tx, F> for TxVar<F, P> {
    fn new_variable<T: Borrow<Tx>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();

        let tx: Tx = f().map(|tx| tx.borrow().clone())?;

        /*
         *
         * Validate configuration
         *
         */

        // Check that the number of inputs is the correct one
        assert_eq!(
            tx.inputs.len(),
            P::N_INPUTS,
            "The number of inputs: {} is different from the one set in the parameters: {}",
            tx.inputs.len(),
            P::N_INPUTS
        );
        // Check that the number of outputs is the correct one
        assert_eq!(
            tx.outputs.len(),
            P::N_OUTPUTS,
            "The number of outputs: {} is different from the one set in the parameters: {}",
            tx.outputs.len(),
            P::N_OUTPUTS
        );
        // Check that there are as many unlocking script lengths as required
        let len_unlock_script = P::LEN_UNLOCK_SCRIPTS.len();
        assert_eq!(
            len_unlock_script,
            tx.inputs.len(),
            "The number of inputs: {} is different from P::LEN_UNLOCK_SCRIPTS.len(): {}",
            len_unlock_script,
            tx.inputs.len(),
        );
        // Check that there are as many locking script lengths as required
        let len_lock_scripts = P::LEN_LOCK_SCRIPTS.len();
        assert_eq!(
            tx.outputs.len(),
            len_lock_scripts,
            "The number of outputs: {} is different from P::LEN_LOCK_SCRIPTS.len(): {}",
            len_lock_scripts,
            tx.outputs.len(),
        );
        // Check that the unlocking scripts have the correct length
        for i in 0..len_unlock_script {
            assert_eq!(
                tx.inputs[i].unlock_script.0.len(),
                P::LEN_UNLOCK_SCRIPTS[i],
                "tx.inputs[{}].len() is different from the one set in the parameters: {}",
                i,
                P::LEN_UNLOCK_SCRIPTS[i]
            );
        }
        // Check that the locking scripts have the correct length
        for i in 0..len_lock_scripts {
            assert_eq!(
                tx.outputs[i].lock_script.0.len(),
                P::LEN_LOCK_SCRIPTS[i],
                "P::LEN_LOCK_SCRIPT[{}].len() is different from the one set in the parameters: {}",
                i,
                P::LEN_LOCK_SCRIPTS[i]
            );
        }

        /*
         *
         * Allocation
         *
         */

        // Version
        let version: UInt32<F> = UInt32::<F>::new_variable(cs.clone(), || Ok(tx.version), mode)?;
        // TxIns
        let inputs: Vec<TxInVar<F>> =
            TxInVar::new_variable_vec(cs.clone(), || Ok(tx.inputs), mode)?;
        // TxOuts
        let outputs: Vec<TxOutVar<F>> =
            TxOutVar::new_variable_vec(cs.clone(), || Ok(tx.outputs), mode)?;
        // Locktime
        let lock_time: UInt32<F> =
            UInt32::<F>::new_variable(cs.clone(), || Ok(tx.lock_time), mode)?;

        Ok(Self {
            _config: PhantomData,
            version,
            inputs,
            outputs,
            lock_time,
        })
    }
}

impl<F: PrimeField, P: TxVarConfig + Clone> EqGadget<F> for TxVar<F, P> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        Boolean::<F>::kary_and(&[
            self.version.is_eq(&other.version)?,
            self.inputs.is_eq(&other.inputs)?,
            self.outputs.is_eq(&other.outputs)?,
            self.lock_time.is_eq(&other.lock_time)?,
        ])
    }
}

impl<F: PrimeField, P: TxVarConfig + Clone> ToBytesGadget<F> for TxVar<F, P> {
    /// Serialise `Self` for TxID calculation
    fn to_bytes_le(&self) -> Result<Vec<UInt8<F>>, SynthesisError> {
        // Var Int length of inputs, outputs, and locking scripts
        let var_int_n_inputs = usize_to_var_int(P::N_INPUTS).unwrap();
        let var_int_n_outputs = usize_to_var_int(P::N_OUTPUTS).unwrap();

        // Serialisation
        let mut ser: Vec<UInt8<F>> = Vec::new();
        ser.extend_from_slice(self.version.to_bytes_le()?.as_slice());
        ser.extend_from_slice(
            var_int_n_inputs
                .iter()
                .map(|el| UInt8::<F>::constant(*el))
                .collect::<Vec<UInt8<F>>>()
                .as_slice(),
        );
        for input in self.inputs.iter() {
            ser.extend_from_slice(input.to_bytes_le()?.as_slice());
        }
        ser.extend_from_slice(
            var_int_n_outputs
                .iter()
                .map(|el| UInt8::<F>::constant(*el))
                .collect::<Vec<UInt8<F>>>()
                .as_slice(),
        );
        for output in self.outputs.iter() {
            ser.extend_from_slice(output.to_bytes_le()?.as_slice());
        }
        ser.extend_from_slice(self.lock_time.to_bytes_le()?.as_slice());
        Ok(ser)
    }
}

impl<F: PrimeField, P: TxVarConfig + Clone> R1CSVar<F> for TxVar<F, P> {
    type Value = Tx;

    fn cs(&self) -> ConstraintSystemRef<F> {
        let mut result = ConstraintSystemRef::None;
        result = self.version.cs().or(result);
        result = self.inputs.cs().or(result);
        result = self.outputs.cs().or(result);
        result = self.lock_time.cs().or(result);
        result
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(Tx {
            version: self.version.value()?,
            inputs: self.inputs.value()?,
            outputs: self.outputs.value()?,
            lock_time: self.lock_time.value()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_gang::address::addr_decode;
    use chain_gang::transaction::sighash::{
        SIGHASH_ALL, SIGHASH_FORKID, SigHashCache, sig_hash_preimage,
    };
    use chain_gang::wallet::create_sighash;

    use chain_gang::messages::{OutPoint, TxIn, TxOut};
    use chain_gang::network::Network;
    use chain_gang::transaction::p2pkh;
    use hex;

    use ark_bls12_381::Fq as F;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;

    use chain_gang::script::Script;
    use chain_gang::util::{Hash256, Serializable};

    #[derive(Clone)]
    struct Config;
    impl TxVarConfig for Config {
        const N_INPUTS: usize = 1;
        const N_OUTPUTS: usize = 2;
        const LEN_UNLOCK_SCRIPTS: &[usize] = &[0];
        const LEN_LOCK_SCRIPTS: &[usize] = &[0x19, 0x19]; // len P2PKH
        const LEN_PREV_LOCK_SCRIPT: Option<usize> = Some(0x19);
        const PRE_SIGHASH_N_INPUT: Option<usize> = Some(0usize);
    }

    fn test_pre_sighash_serialisation(sighash_flags: u8) -> () {
        let lock_script =
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
        let pre_sighash =
            sig_hash_preimage(&tx, 0, &lock_script.0, 260000000, sighash_flags, &mut cache)
                .unwrap();

        let cs = ConstraintSystem::<F>::new_ref();
        let tx_var = TxVar::<F, Config>::new_input(cs.clone(), || Ok(tx)).unwrap();
        let mut cache_var = SigHashCacheVar::<F>::new();
        let pre_sighash_var = tx_var
            .pre_sighash_serialise(
                &ScriptVar::<F>::new_input(cs.clone(), || Ok(lock_script)).unwrap(),
                &UInt64::<F>::new_input(cs.clone(), || Ok(260000000)).unwrap(),
                &sighash_flags,
                &mut cache_var,
            )
            .unwrap();

        assert_eq!(pre_sighash.len(), pre_sighash_var.len());
        for (b1, b2) in pre_sighash_var.iter().zip(pre_sighash.iter()) {
            assert_eq!(b1.value().unwrap(), *b2);
        }
    }

    #[test]
    fn test_pre_sighash_all_serialisation() {
        test_pre_sighash_serialisation(SIGHASH_ALL | SIGHASH_FORKID);
    }

    #[test]
    fn test_pre_sighash_none_serialisation() {
        test_pre_sighash_serialisation(SIGHASH_NONE | SIGHASH_FORKID);
    }

    #[test]
    fn test_pre_sighash_single_serialisation() {
        test_pre_sighash_serialisation(SIGHASH_SINGLE | SIGHASH_FORKID);
    }

    #[test]
    fn test_pre_sighash_anyone_can_pay_serialisation() {
        test_pre_sighash_serialisation(SIGHASH_ALL | SIGHASH_ANYONECANPAY | SIGHASH_FORKID);
    }

    #[test]
    fn test_sighash_calculation() {
        let lock_script =
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
        let sighash_type = SIGHASH_ALL | SIGHASH_FORKID;
        let sighash = create_sighash(&tx, 0, &lock_script, 260000000, sighash_type).unwrap();

        let cs = ConstraintSystem::<F>::new_ref();
        let tx_var = TxVar::<F, Config>::new_input(cs.clone(), || Ok(tx)).unwrap();
        let mut cache_var = SigHashCacheVar::<F>::new();
        let sighash_var = tx_var
            .sighash(
                &ScriptVar::<F>::new_input(cs.clone(), || Ok(lock_script)).unwrap(),
                &UInt64::<F>::new_input(cs.clone(), || Ok(260000000)).unwrap(),
                &sighash_type,
                &mut cache_var,
            )
            .unwrap();

        for (b1, b2) in sighash_var.value().unwrap().iter().zip(sighash.0.iter()) {
            assert_eq!(b1, b2);
        }
    }

    #[test]
    fn test_is_eq() {
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

        let cs = ConstraintSystem::<F>::new_ref();
        let tx_var1 = TxVar::<F, Config>::new_input(cs.clone(), || Ok(tx)).unwrap();
        let tx_var2 = tx_var1.clone();

        assert!(tx_var1.is_eq(&tx_var2).unwrap().value().unwrap());
    }

    #[test]
    fn test_to_bytes_gadget() {
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
        let mut tx_bytes: Vec<u8> = Vec::new();
        tx.write(&mut tx_bytes).unwrap();

        let cs = ConstraintSystem::<F>::new_ref();
        let tx_var = TxVar::<F, Config>::new_input(cs.clone(), || Ok(tx)).unwrap();
        let tx_var_bytes = tx_var.to_bytes_le().unwrap().value().unwrap();

        assert_eq!(tx_bytes, tx_var_bytes);
    }

    #[test]
    fn test_txid() {
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
        let txid = tx.hash();

        let cs = ConstraintSystem::<F>::new_ref();
        let tx_var = TxVar::<F, Config>::new_input(cs.clone(), || Ok(tx)).unwrap();
        let txid_var = tx_var.txid().unwrap().value().unwrap();

        assert_eq!(txid.0, txid_var);
    }
}
