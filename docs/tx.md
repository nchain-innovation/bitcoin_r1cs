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

The `TxVarConfig` trait is used to generate default transactions at setup time.
More precisely, the function [default_tx](../src/util/mod.rs#L29) takes a generic `P : TxVarConfig` and returns a transaction with the structure specified by `P` (albeit filled with meaningless data).
In this way, we can safely complete the SNARK setup using a dummy transaction with the specified structure. 