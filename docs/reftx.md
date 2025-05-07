# REFTX

REFTX is a technique that allows to enforce conditions on a Bitcoin transaction using zero-knowledge proofs.
More precisely, if we want to enforce the condition _"This UTXO can only be spent to pay Alice"_, then, instead of writing a Bitcoin script, we construct a circuit that enforces this condition, and we lock the UTXO with a zkSNARK verifier that can only be unlocked with a proof that the condition is verified.

Write `spending_utxo` for an output that is being spent, and `tx` for the transaction that is spending it at index `0`.
Then, a miner will accept `tx` only if there is no double spending, and if
```bash
BitcoinScriptEngine(tx.in[0].unlock, spending_utxo.lock) = 1
```
where `BitcoinScriptEngine(-,-)` denotes the execution of a pair of unlocking/locking script.

We use the following notation:
- `locking_data` is the data contained in `spending_utxo.lock` (e.g., a public key)
- `unlocking_data` is the data contained in `tx.in[0].unlock` (e.g., a signature)
- `spending_tx` is the data contained in `tx`, disregarding unlocking scripts
A spending condition can be interpreted as a circuit `C` on inputs `(locking_data, unlocking_data, spending_tx)`.

**Example:** `P2PK` is `C(locking_data, unlocking_data, spending_tx) = <unlocking_data> <locking_data> OP_CHECKSIG`.

We think of REFTX as a transformation:
```bash
C --> C_reftx
```
that given a circuit `C(locking_data, unlocking_data, spending_tx)`, it returns a circuit `C_reftx(locking_data, unlocking_data, integrity_tag)` where `spending_tx` is replaced by an _integrity tag_, i.e., a commitment to `spending_tx`.
Thanks to this transformation, we can deploy a ZK verifier on-chain that can be only unlocked with a proof `pi` that attests to the fact that `C(locking_data, unlocking_data, spending_tx) = 1`.


## Bitcoin Predicates

The code equivalent of a circuit `C(locking_data, unlocking_data, spending_tx)` is a structure implementing the [`BitcoinPredicate`](../src/traits.rs#L13) trait.
We generalise the circuit `C` to also account for a private witness `w`.

Examples of Bitcoin Predicates can be found in [`bitcoin_predicate`](../src/bitcoin_predicates), e.g., [`FixedLockScript`](../src/bitcoin_predicates/fixed_lock_script.rs#L21) corresponds to the circuit that enforces the locking script of an output of `tx` to have a specific structure.

### Combining Bitcoin Predicates

The macros [`and_combine_predicates`](../src/macros.rs#L306) and [`or_combine_predicates`](../src/macros.rs#L333) can be used to combine Bitcoin Predicates.
As of now, they only allow combination of predicates that depend on two generics: `F: PrimeField` and `P: TxVarConfig + Clone`.
Below is an example:

```rust
use ark_bls12_381::Fr as F;
use bitcoin_r1cs::bitcoin_predicates::fixed_lock_script::FixedLockScript;
use bitcoin_r1cs::and_combine_predicates;
use chain_gang::script::Script;

and_combine_predicates!(
    AndFixTwoOutputsLockingData, // The name of the LockingData struct for the new predicate
    AndFixTwoOutputsUnlockingData, // The name of the UnlockingData struct for the new predicate
    AndFixTwoOutputsWitness, // The name of the Witness struct for the new predicate
    AndFixTwoOutputsLockingDataVar, // The name of the LockingDataVar struct for the new predicate
    AndFixTwoOutputsUnlockingDataVar, // The name of the UnlockingDataVar struct for the new predicate
    AndFixTwoOutputsWitnessDataVar, // The name of the WitnessVar struct for the new predicate,
    AndFixTwoOutputs, // The name of the new predicate
    (FixedLockScript<F,P>, 1), // The first predicate to AND combine; the integer is used to distinguish between copies of the same predicate
    (FixedLockScript<F,P>, 2), // The first predicate to AND combine
);

use bitcoin_r1cs::constraints::tx::{TxVar, TxVarConfig};

#[derive(Clone)]
struct Config;
impl TxVarConfig for Config {
    const N_INPUTS: usize = 0;
    const N_OUTPUTS: usize = 2;
    const LEN_UNLOCK_SCRIPTS: &[usize] = &[];
    const LEN_LOCK_SCRIPTS: &[usize] = &[1, 1];
}

let fix_one = FixedLockScript::<F, Config>::new(Script(vec![0]), 0); // One instance of the FixedLockScript predicate
let fix_two = FixedLockScript::<F, Config>::new(Script(vec![1]), 1); // Another instance of the FixedLockScript predicate
let fix_combined = AndFixTwoOutputs::<F, Config>::new(fix_one, fix_two); // Create instance of the AND combination
```

## Getting started

To deploy on-chain a ZK verifier leveraging REFTX the only thing required is defining the Bitcoin Predicate that encodes the spending conditions.
Then, the predicate can be passed to [`RefTxCircuit`](../src/reftx.rs#L20) as a generic, and the rest is handled by the codebase.