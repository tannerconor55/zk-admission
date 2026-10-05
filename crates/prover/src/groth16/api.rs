//! Native Groth16 nullifier proving.
//!
//! The circuit, setup and proving live in the arkworks-only
//! `zk-admission-groth16-circuit` crate; this module re-exports them.
//!
//! Production use:
//!
//! - deployment: `generate_key_material` (or the `nullifier_groth16_setup`
//!   binary) once, pinning the verifying key in the DNA properties;
//! - proving: `NullifierProvingKeyV1::load` + `prove_statement`.
pub use zk_admission_groth16_circuit::{
    deserialize_proof, deserialize_proving_key, deserialize_verifying_key, generate_key_material,
    prove, serialize_proof, serialize_proving_key, serialize_verifying_key, setup, verify,
    verifying_key_fingerprint, Groth16Proof, Groth16ProvingKey, Groth16VerifyingKey,
    NullifierKeyMaterialV1, NullifierProvingKeyV1, NullifierPublicInputs,
};
