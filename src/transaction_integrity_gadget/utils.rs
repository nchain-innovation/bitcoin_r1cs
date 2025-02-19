use ark_ff::PrimeField;

/// Converts a slice of [`u8`] to [`Vec<F>`].
/// This is used to convert public inputs / witnesses into their R1CS counterparts
/// It leverages [get_chunk_size] below
pub fn to_fp_chunks<F: PrimeField>(data: &[u8]) -> Vec<F> {
    data.chunks_exact(get_chunk_size::<F>())
        .map(|bytes| F::from_le_bytes_mod_order(bytes))
        .collect::<Vec<F>>()
}

/// Get the size of the chunks the data should be split into
/// Used in [to_fp_chunks]
pub fn get_chunk_size<F: PrimeField>() -> usize {
    if F::MODULUS_BIT_SIZE > 256 {
        32
    } else if F::MODULUS_BIT_SIZE > 128 {
        16
    } else if F::MODULUS_BIT_SIZE > 64 {
        8
    } else if F::MODULUS_BIT_SIZE > 32 {
        4
    } else if F::MODULUS_BIT_SIZE > 16 {
        2
    } else {
        1
    }
}
