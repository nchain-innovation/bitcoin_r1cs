# TxVar

[`TxVar`](../src/constraints/tx.rs#L56) is the struct representing the R1CS version of a Bitcoin transaction.
It implements the `AllocVar` trait from [`ark_r1cs_std`](https://github.com/arkworks-rs/r1cs-std) for generics `T` that can be borrowed as [`Tx`](https://github.com/nchain-innovation/chain-gang/blob/a960d330bb3114d3cdc6f7f3ebfffc3fd28b4244/src/messages/tx.rs#L19).

The struct `TxVar` depends on two generics:
- `P`, which implements the traits `TxVarConfig` and `Clone`
- `F`, which implements the trait `PrimeField` from [`ark_ff`](https://github.com/arkworks-rs/algebra/tree/master/ff)

The trait [`TxVarConfig`](../src/constraints/tx.rs#L39) specifies the structure of the transaction being allocated in the circuit.
This trait is especially useful when the circuits are used in SNARKs with a circuit-specific setup, as it makes it easier to detect errors due to the use of proving/verifying keys incompatible with a given transaction structure.

`TxVarConfig` requires the user to set six constants:
- `N_INPUTS: usize`: the number of inputs in the transaction
- `N_OUTPUTS: usize`: the number of outputs in the transaction
- `LEN_UNLOCK_SCRIPTS: &[usize]`: the lengths of the unlocking scripts
- `LEN_LOCK_SCRIPTS: &[usize]`: the lengths of the locking scripts
- `LEN_PREV_LOCK_SCRIPT: Option<usize>`: the length of the previous locking script, used for the calculation of the [`pre_sighash`](../src/constraints/tx.rs#L86)
- `PRE_SIGHASH_N_INPUT: Option<usize>`: the index of the input for which the pre_sighash is computed

Below we give some example implementations of `TxVarConfig` for a series of circuits.

# Examples

## `pre_sighash` is not calculated

If the circuit `C` computes the TxID of `TxVar` but not the pre_sighash, then `LEN_PREV_LOCK_SCRIPT` and `PRE_SIGHASH_N_INPUT` should be set to `None`, as they will not be used inside `C`. If `TxVar` had `1` input coming from a P2PKH outpoint and `1` P2PKH output, then `TxVarConfig` would be implemented as follows
```rust
#[derive(Clone)]
struct Config;

impl TxVarConfig for Config {
    const N_INPUTS: usize = 1;
    const N_OUTPUTS: usize = 1;
    const LEN_UNLOCK_SCRIPTS: &[usize] = &[0x6b]; // r.len = 33, s.len = 32
    const LEN_LOCK_SCRIPTS: &[usize] = &[0x19]; // len P2PKH
    const LEN_PREV_LOCK_SCRIPT: Option<usize> = None,
    const PRE_SIGHASH_N_INPUT: Option<usize> = None,
}
```

## `pre_sighash` is calculated

If the circuit `C` computes the pre_sighash of `TxVar`, then `LEN_PREV_LOCK_SCRIPT` and `PRE_SIGHASH_N_INPUT` should be set, as they will be used inside `C`. If `TxVar` had `1` input coming from a P2PKH outpoint, `1` P2PKH output, and we wanted to compute the `pre_sighash` for the first input, then `TxVarConfig` would be implemented as follows
```rust
#[derive(Clone)]
struct Config;

impl TxVarConfig for Config {
    const N_INPUTS: usize = 1;
    const N_OUTPUTS: usize = 1;
    const LEN_UNLOCK_SCRIPTS: &[usize] = &[0x6b]; // r.len = 33, s.len = 32
    const LEN_LOCK_SCRIPTS: &[usize] = &[0x19]; // len P2PKH
    const LEN_PREV_LOCK_SCRIPT: Option<usize> = Some(0x19), \\ len P2PKH
    const PRE_SIGHASH_N_INPUT: Option<usize> = Some(0),
}
```
