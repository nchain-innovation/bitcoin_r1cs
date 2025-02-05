use byteorder::{LittleEndian, WriteBytesExt};
use chain_gang::messages::{OutPoint, Tx, TxIn, TxOut};
use chain_gang::script::Script;
use chain_gang::util::Hash256;
use std::io::Result as IoResult;

use crate::constraints::tx::TxVarConfig;

/// Convert u64 to var_int
pub fn u64_to_var_int(length: usize) -> IoResult<Vec<u8>> {
    let mut s: Vec<u8> = Vec::new();
    if length <= 252 {
        s.write_u8(length as u8)?;
    } else if length <= 0xffff {
        s.write_u8(0xfd)?;
        s.write_u16::<LittleEndian>(length as u16)?;
    } else if length <= 0xffffffff {
        s.write_u8(0xfe)?;
        s.write_u32::<LittleEndian>(length as u32)?;
    } else {
        s.write_u8(0xff)?;
        s.write_u64::<LittleEndian>(length as u64)?;
    }

    Ok(s)
}

/// Generate default Tx according to TxVarConfig
pub fn default_tx<P: TxVarConfig>() -> Tx {
    let version: u32 = 0;
    let mut inputs: Vec<TxIn> = Vec::with_capacity(P::N_INPUTS);
    for i in 0..P::N_INPUTS {
        inputs.push(TxIn {
            prev_output: OutPoint {
                hash: Hash256([0; 32]),
                index: 0,
            },
            unlock_script: Script(vec![0; P::LEN_UNLOCK_SCRIPTS[i]]),
            sequence: 0,
        })
    }
    let mut outputs: Vec<TxOut> = Vec::with_capacity(P::N_OUTPUTS);
    for i in 0..P::N_OUTPUTS {
        outputs.push(TxOut {
            satoshis: 0,
            lock_script: Script(vec![0; P::LEN_LOCK_SCRIPTS[i]]),
        })
    }
    let lock_time: u32 = 0;
    Tx {
        version,
        inputs,
        outputs,
        lock_time,
    }
}

#[cfg(test)]
mod tests {
    use crate::constraints::tx::TxVarConfig;

    use super::default_tx;

    #[derive(Clone)]
    struct Config;
    impl TxVarConfig for Config {
        const N_INPUTS: usize = 1;
        const N_OUTPUTS: usize = 1;
        const LEN_UNLOCK_SCRIPTS: &[usize] = &[0x6b];
        const LEN_LOCK_SCRIPTS: &[usize] = &[0x19];
        const LEN_PREV_LOCK_SCRIPT: Option<usize> = None;
        const PRE_SIGHASH_N_INPUT: Option<usize> = None;
    }

    #[test]
    fn test_default_tx() {
        let test_tx = default_tx::<Config>();
        assert_eq!(test_tx.inputs.len(), 1);
        assert_eq!(test_tx.outputs.len(), 1);
        assert_eq!(test_tx.inputs[0].unlock_script.0.len(), 0x6b);
        assert_eq!(test_tx.outputs[0].lock_script.0.len(), 0x19);
    }
}
