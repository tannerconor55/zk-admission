//! Native Groth16 nullifier proving.
//!
//! The circuit, setup and low-level proving live in the arkworks-only
//! `zk-admission-groth16-circuit` crate; this module re-exports them.
pub use zk_admission_groth16_circuit::{
    deserialize_proof, deserialize_proving_key, deserialize_verifying_key, prove, serialize_proof,
    serialize_proving_key, serialize_verifying_key, setup, verify, verifying_key_fingerprint,
    Groth16Proof, Groth16ProvingKey, Groth16VerifyingKey, NullifierPublicInputs,
};
