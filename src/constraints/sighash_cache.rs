use ark_crypto_primitives::crh::sha256::constraints::DigestVar;
use ark_ff::PrimeField;

/// R1CS version of [SigHashCache](chain_gang::transaction::sighash::SigHashCache)
#[derive(Debug, Clone)]
pub struct SigHashCacheVar<F: PrimeField> {
    pub hash_prevouts: Option<DigestVar<F>>,
    pub hash_sequence: Option<DigestVar<F>>,
    pub hash_outputs: Option<DigestVar<F>>,
}

impl<F: PrimeField> Default for SigHashCacheVar<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField> SigHashCacheVar<F> {
    pub fn new() -> Self {
        SigHashCacheVar::<F> {
            hash_prevouts: None,
            hash_sequence: None,
            hash_outputs: None,
        }
    }
    //getter/setter/clear hash_prevouts
    pub fn hash_prevouts(&self) -> Option<&DigestVar<F>> {
        self.hash_prevouts.as_ref()
    }

    pub fn set_hash_prevouts(&mut self, hash: DigestVar<F>) {
        self.hash_prevouts = Some(hash);
    }

    pub fn clear_hash_prevouts(&mut self) {
        self.hash_prevouts = None;
    }
    //getter/setter/clear hash_sequence
    pub fn hash_sequence(&self) -> Option<&DigestVar<F>> {
        self.hash_sequence.as_ref()
    }

    pub fn set_hash_sequence(&mut self, hash: DigestVar<F>) {
        self.hash_sequence = Some(hash);
    }

    pub fn clear_hash_sequence(&mut self) {
        self.hash_sequence = None;
    }

    //getter/setter/clear hash_outputs
    pub fn hash_outputs(&self) -> Option<&DigestVar<F>> {
        self.hash_outputs.as_ref()
    }

    pub fn set_hash_outputs(&mut self, hash: DigestVar<F>) {
        self.hash_outputs = Some(hash)
    }

    pub fn clear_hash_outputs(&mut self) {
        self.hash_outputs = None;
    }
}
