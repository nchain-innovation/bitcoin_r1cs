use ark_ff::Field;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::SynthesisError;

// Serialisation according to Bitcoin software specification for PreSigHash calculation
pub trait PreSigHashSerialise<F: Field> {
    fn pre_sighash_serialise(&self) -> Result<Vec<UInt8<F>>, SynthesisError>;
}
