use anyhow::anyhow;
use std::{
    fs::File,
    io::{Cursor, Read, Result as IoResult},
};

use ark_groth16::{Groth16, Proof, VerifyingKey, constraints::Groth16VerifierGadget};
use ark_mnt4_753::{Fq as ScalarFieldMNT6, Fr as ScalarFieldMNT4};
use ark_mnt6_753::g1::Parameters as ShortWeierstrassParameters;

use ark_mnt4_753::{MNT4_753, constraints::PairingVar as MNT4PairingVar};
use ark_mnt6_753::{MNT6_753, constraints::PairingVar as MNT6PairingVar};

use ark_pcd::{
    ec_cycle_pcd::ECCyclePCDConfig,
    variable_length_crh::{
        injective_map::{
            VariableLengthPedersenCRHCompressor,
            constraints::VariableLengthPedersenCRHCompressorGadget,
        },
        pedersen::VariableLengthPedersenParameters,
    },
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalDeserialize;
use bitcoin_r1cs::{
    bitcoin_predicates::{
        data_structures::{proof::BitcoinProof, unit::BitcoinUnit},
        pay_to_utxo::PayToUTXO,
    },
    constraints::tx::TxVarConfig,
    reftx::RefTxCircuit,
    transaction_integrity_gadget::{TransactionIntegrityConfig, TransactionIntegrityScheme},
};
use chain_gang::{
    messages::{OutPoint, Tx, TxIn, TxOut},
    script::Script,
    transaction::sighash::{SIGHASH_ALL, SIGHASH_FORKID, SigHashCache},
    util::Serializable,
};
use rand_chacha::ChaChaRng;

pub struct PCDGroth16Mnt4;
impl ECCyclePCDConfig<ScalarFieldMNT4, ScalarFieldMNT6> for PCDGroth16Mnt4 {
    type CRH = VariableLengthPedersenCRHCompressor<ChaChaRng, ShortWeierstrassParameters>;
    type CRHGadget =
        VariableLengthPedersenCRHCompressorGadget<ChaChaRng, ShortWeierstrassParameters>;
    type MainSNARK = Groth16<MNT4_753>;
    type HelpSNARK = Groth16<MNT6_753>;
    type MainSNARKGadget = Groth16VerifierGadget<MNT4_753, MNT4PairingVar>;
    type HelpSNARKGadget = Groth16VerifierGadget<MNT6_753, MNT6PairingVar>;
}

#[derive(Clone)]
pub struct Config;
impl TxVarConfig for Config {
    const N_INPUTS: usize = 2;
    const N_OUTPUTS: usize = 1;
    const LEN_UNLOCK_SCRIPTS: &[usize] = &[0, 0];
    const LEN_LOCK_SCRIPTS: &[usize] = &[0x19];
}
impl TransactionIntegrityConfig for Config {
    const LEN_PREV_LOCK_SCRIPT: usize = 0;
    const N_INPUT: usize = 1;
    const SIGHASH_FLAG: u8 = SIGHASH_ALL | SIGHASH_FORKID;
}

type TestPayToUTXO = PayToUTXO<ScalarFieldMNT4, ScalarFieldMNT6, PCDGroth16Mnt4, Config>;

// Test transactions, they form a transaction chain at index 0
fn test_transactions() -> [Tx; 3] {
    let tx1 = "0100000001588e94b6f6c0a2a925b0d8072b7fb6b4aae70a7487f002495c865748032d7da52c0000006b483045022100ba9a71fa3d68ecb4d65f6977c76f852dd7e8b1418343718338f2217e7ba8acae022003d93a3694848e9f8af0d7c9a36a6d91475a6d2771864e8f1439ee7e28f4462841210292acdb57c788c1e8c83cdb0ae8f23e079139ba7ba1bccf67b31653c7af12c4b4ffffffff0140860100000000001976a914f51d82a8b11bdaeef7cc0362b0e9e58d238abdb388ac00000000";
    let tx2 = "01000000014c4c27fd556c7637abd44e1c4376ac9722e2177f35bdcbfc0d1c7ca1517e31f4000000006b483045022100bccd62705d77bade0c7b7a4885a66125a105a79a0d32cb64302d273e01604241022028ac797b4188d8975b3409ed3733a89e58ed8e07139ac49acf32154537fd689f41210347f8c3cd8be488072efbf2a04744040546849b849362e8468708b89dfecaf70b00000000013e860100000000001976a914f51d82a8b11bdaeef7cc0362b0e9e58d238abdb388ac00000000";
    let tx3 = "0100000001218d064948771fad7bb48d65312a812c36310d0f2c0f2e3ab20d377a176c18c7000000006b4830450221008145a2eb63e10fabe329eeb5de61006b1f9bb1073b65c8688f85b82777845b04022016ccb03c6024250a8aa4041e2943fc7f00da4c663c2d2023b104b64a54903f4041210347f8c3cd8be488072efbf2a04744040546849b849362e8468708b89dfecaf70b00000000013c860100000000001976a914f51d82a8b11bdaeef7cc0362b0e9e58d238abdb388ac00000000";
    [
        Tx::read(&mut Cursor::new(&hex::decode(tx1).unwrap())).unwrap(), // Genesis
        Tx::read(&mut Cursor::new(&hex::decode(tx2).unwrap())).unwrap(), // First tx
        Tx::read(&mut Cursor::new(&hex::decode(tx3).unwrap())).unwrap(), // Second tx
    ]
}

// Generate test transactions starting from an input tx
// The output tx is has the same outpoint in the first two positions
// and copies the first output from the input tx with 100 satoshis
fn generate_test_transaction(tx: Tx) -> Tx {
    let outpoint = OutPoint {
        hash: tx.hash(),
        index: 0,
    };
    let input = TxIn {
        prev_output: outpoint,
        unlock_script: Script(vec![]),
        sequence: 0,
    };
    let output = TxOut {
        lock_script: tx.outputs[0].lock_script.clone(),
        satoshis: 100,
    };
    Tx {
        version: 1,
        inputs: [input.clone(), input.clone()].to_vec(),
        outputs: [output].to_vec(),
        lock_time: 0,
    }
}

#[test]
fn test_pay_to_utxo() {
    // These parameters have been generated using [transaction_chain_proof](https://github.com/nchain-innovation/transaction_chain_proof)
    // The genesis transaction is: `f4317e51a17c1c0dfccbbd357f17e22297ac76431c4ed4ab37766c55fd274c4c` and the index of the chain is: 0
    // The snark used is tcp_snark
    let crh_pp_seed_bytes = read_from_file("tests/data/crh_pp_seed.bin")
        .map_err(|e| anyhow!("Failed to read crh_pp. Error: {}", e))
        .unwrap();
    let help_vk_bytes = read_from_file("tests/data/help_vk.bin")
        .map_err(|e: std::io::Error| anyhow!("Failed to read help_vk. Error: {}", e))
        .unwrap();

    let crh_pp = VariableLengthPedersenParameters {
        seed: crh_pp_seed_bytes,
    };
    let help_vk = VerifyingKey::<MNT6_753>::deserialize_unchecked(help_vk_bytes.as_slice())
        .map_err(|e| anyhow!("Failed to deserialize help_vk. Error: {}", e))
        .unwrap();

    // Bitcoin predicate
    let pay2utxo = TestPayToUTXO::new(&crh_pp, &help_vk, 0);

    // RefTx on genesis
    let proof_base_case = load_proof("tests/data/proof_base_case.bin", "base case");
    let test_tx = generate_test_transaction(test_transactions()[0].clone());
    let tag = TransactionIntegrityScheme::<Config>::commit(
        &test_tx,
        &Script(vec![]),
        100,
        &mut SigHashCache::new(),
    );
    let reftx_pay2utxo = RefTxCircuit::<TestPayToUTXO, ScalarFieldMNT4, Config> {
        locking_data: BitcoinUnit::default(),
        integrity_tag: Some(tag),
        unlocking_data: BitcoinUnit::default(),
        witness: BitcoinProof::new(&proof_base_case),
        spending_data: Some(test_tx),
        prev_lock_script: Some(Script(vec![])),
        prev_amount: Some(100),
        sighash_cache: None,
        predicate: pay2utxo.clone(),
    };

    let cs = ConstraintSystem::<ScalarFieldMNT4>::new_ref();
    reftx_pay2utxo.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());

    println!("Base case satisfied.");

    // RefTx on first tx
    let proof_first_recursive_step = load_proof(
        "tests/data/proof_recursive_first_step.bin",
        "first recursive case",
    );
    let test_tx = generate_test_transaction(test_transactions()[1].clone());
    let tag = TransactionIntegrityScheme::<Config>::commit(
        &test_tx,
        &Script(vec![]),
        100,
        &mut SigHashCache::new(),
    );
    let reftx_pay2utxo = RefTxCircuit::<TestPayToUTXO, ScalarFieldMNT4, Config> {
        locking_data: BitcoinUnit::default(),
        integrity_tag: Some(tag),
        unlocking_data: BitcoinUnit::default(),
        witness: BitcoinProof::new(&proof_first_recursive_step),
        spending_data: Some(test_tx),
        prev_lock_script: Some(Script(vec![])),
        prev_amount: Some(100),
        sighash_cache: None,
        predicate: pay2utxo.clone(),
    };

    let cs = ConstraintSystem::<ScalarFieldMNT4>::new_ref();
    reftx_pay2utxo.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());

    println!("First recursive case satisfied.");

    // RefTx on second tx
    let proof_second_recursive_step = load_proof(
        "tests/data/proof_recursive_second_step.bin",
        "second recursive case",
    );
    let test_tx = generate_test_transaction(test_transactions()[2].clone());
    let tag = TransactionIntegrityScheme::<Config>::commit(
        &test_tx,
        &Script(vec![]),
        100,
        &mut SigHashCache::new(),
    );
    let reftx_pay2utxo = RefTxCircuit::<TestPayToUTXO, ScalarFieldMNT4, Config> {
        locking_data: BitcoinUnit::default(),
        integrity_tag: Some(tag),
        unlocking_data: BitcoinUnit::default(),
        witness: BitcoinProof::new(&proof_second_recursive_step),
        spending_data: Some(test_tx),
        prev_lock_script: Some(Script(vec![])),
        prev_amount: Some(100),
        sighash_cache: None,
        predicate: pay2utxo,
    };

    let cs = ConstraintSystem::<ScalarFieldMNT4>::new_ref();
    reftx_pay2utxo.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());

    println!("Second recursive case satisfied.");
}

fn read_from_file(file_path: &str) -> IoResult<Vec<u8>> {
    let mut file = File::open(file_path)?;
    let mut len_bytes = [0u8; 8];
    file.read_exact(&mut len_bytes)?;

    let len = u64::from_le_bytes(len_bytes) as usize;

    let mut vec = vec![0; len];
    file.read_exact(&mut vec)?;
    Ok(vec)
}

fn load_proof(file_path: &str, case: &str) -> Proof<MNT6_753> {
    let proof_bytes = read_from_file(file_path)
        .map_err(|e| anyhow!("Failed to read proof {}. Error: {}", case, e))
        .unwrap();
    Proof::<MNT6_753>::deserialize_unchecked(proof_bytes.as_slice())
        .map_err(|e| anyhow!("Failed to deserialize proof {}. Error: {}", case, e))
        .unwrap()
}
