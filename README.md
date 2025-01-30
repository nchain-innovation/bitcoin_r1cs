# bitcoin_r1cs

This library provides the implementation of R1CS versions of Bitcoin structures, e.g. transactions, and functions, e.g. TxID calculation, sighash calculation, etcetera.

Bitcoin structures are taken from the library [`chain_gang`](https://github.com/nchain-innovation/chain-gang), while the R1CS variables are built using the framework provided by the [`ark_r1cs_std`](https://github.com/arkworks-rs/r1cs-std) library.
 
## Example

The code below allocates in the constraint system a new input of type [`ScriptVar`](./src/constraints/script.rs#L27), which is the R1CS version of [`Script`](https://github.com/nchain-innovation/chain-gang/blob/a960d330bb3114d3cdc6f7f3ebfffc3fd28b4244/src/script/mod.rs#L37),
and then checks that it is equal to itself.
 
```rust
use ark_bls12_381::Fr as ScalarField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_relations::r1cs::ConstraintSystem;
use bitcoin_r1cs::constraints::script::ScriptVar;
use chain_gang::script::Script;
use chain_gang::script::op_codes::*;


let script = Script(vec![OP_1, OP_DUP]);
let cs = ConstraintSystem::<ScalarField>::new_ref();
let script_var = ScriptVar::<ScalarField>::new_input(cs.clone(), || Ok(script)).unwrap();
script_var.enforce_equal(&script_var);
assert!(cs.is_satisfied().unwrap());
```

## R1CS variables

The library implements the following R1CS variables:
- [`ScriptVar`](./src/constraints/script.rs#L27): the R1CS version of a Bitcoin Script
- [`OutPointVar`](./src/constraints/outpoint.rs#L25): the R1CS version of an Outpoint (TxID + index)
- [`TxInVar`](./src/constraints/txin.rs#L28): the R1CS version of an input (TxID of parent + index + unlocking script + sequence)
- [`TxOutVar`](./src/constraints/txout.rs#L25): the R1CS version of an output (amount + locking script)
- [`TxVar`](./src/constraints/tx.rs#L49): the R1CS version of a transaction (version + inputs + outputs + locktime)

### Implemented Traits

All the above variables implement useful traits from the [`ark_r1cs_std`](https://github.com/arkworks-rs/r1cs-std) library: `EqGadget`, `ToBytesGadget`, `R1CSVar`.

Furthermore, all the variables implement the trait [`PreSighashSerialise`](./src/traits.rs#L6), which is used to construct the [`pre_sighash`](https://github.com/bitcoin-sv/bitcoin-sv/blob/master/doc/abc/replay-protected-sighash.md#digest-algorithm) of a transaction.

For more information on `TxVar`, have a look [here](./docs/tx.md).

## Getting started

The library compiles on the nightly toolchain of the Rust compiler. To install the latest version of Rust, first install rustup by following the instructions here, or via your platform's package manager. Once rustup is installed, install the Rust toolchain by invoking:

```bash
rustup install nightly
```

After that, you can clone and test the library by using `cargo`

```bash
git clone https://github.com/nchain-innovation/bitcoin_r1cs
cd bitcoin_r1cs
cargo test
```

## Further documentation

For further documentation on the structures and function implemented in the library, use `cargo`

```bash
cargo doc --open
```

## Disclaimer

The code and resources within this repository are intended for research and educational purposes only.

Please note:

- No guarantees are provided regarding the security or the performance of the code.
- Users are responsible for validating the code and understanding its implications before using it in any capacity.
- There may be edge cases causing bugs or unexpected behaviours. Please contact us if you find any bug.

## License

The code is released under the attached [LICENSE](./LICENSE.txt).

