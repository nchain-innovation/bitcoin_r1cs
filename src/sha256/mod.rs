use ark_crypto_primitives::Error;
use ark_crypto_primitives::crh::{CRH, TwoToOneCRH};

use ark_std::rand::Rng;

// Re-export the RustCrypto Sha256 type and its associated traits
pub use sha2::{Sha256, digest};

#[derive(Default)]
pub struct Sha256Wrapper {
    pub inner: Sha256,
}

impl Sha256Wrapper {
    pub fn update(&mut self, input: &[u8]) {
        self.inner.update(input);
    }
}

mod r1cs_utils;

pub mod constraints;

// Implement the CRH traits for SHA-256
use sha2::digest::Digest;

impl CRH for Sha256Wrapper {
    const INPUT_SIZE_BITS: usize = 256; // Dummy - need to have it because of the CRH definition

    // This is always 32 bytes. It has to be a Vec to impl CanonicalSerialize
    type Output = Vec<u8>;
    // There are no parameters for SHA256
    type Parameters = ();

    // There are no parameters for SHA256
    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    // Evaluates SHA256(input)
    fn evaluate(_parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        Ok(Sha256::digest(input).to_vec())
    }
}

impl TwoToOneCRH for Sha256Wrapper {
    const LEFT_INPUT_SIZE_BITS: usize = 256; // Dummy
    const RIGHT_INPUT_SIZE_BITS: usize = 256; // Dummy

    // This is always 32 bytes. It has to be a Vec to impl CanonicalSerialize
    type Output = Vec<u8>;
    // There are no parameters for SHA256
    type Parameters = ();

    // There are no parameters for SHA256
    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    // Evaluates SHA256(left_input || right_input)
    fn evaluate(
        _parameters: &Self::Parameters,
        left_input: &[u8],
        right_input: &[u8],
    ) -> Result<Self::Output, Error> {
        // Process the left input then the right input
        let mut h = Sha256::default();
        h.update(left_input);
        h.update(right_input);
        Ok(h.finalize().to_vec())
    }
}
