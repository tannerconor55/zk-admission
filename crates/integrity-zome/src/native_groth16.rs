use hdi::prelude::*;

use zk_admission_groth16_verifier::{
    verify_statement_nullifier_proof, PinnedNullifierVerifyingKey,
};
use zk_admission_protocol::{AdmissionConfigV1, ProtocolError, ZkProofEntryV1};

/// Verify the native nullifier Groth16 proof of an entry.
///
/// Security boundary:
///
/// - The verifying key comes only from DNA properties, and its bytes must
///   hash to the DNA-pinned fingerprint. The proof's `verifying_key_id` is
///   compared against that fingerprint and is never used to select a key.
/// - Public inputs are derived from `entry.statement`, whose
///   `deployment_id` has already been checked against the DNA hash by
///   `validate_admission_bindings`.
///
/// This proves knowledge of the credential secret behind
/// `statement.nullifier` for `statement.deployment_id`/`statement.domain`
/// only. It does not bind `prover` or `statement_nonce`; the capability
/// signature and the SP1 proof do.
pub fn check_native_nullifier_proof(
    entry: &ZkProofEntryV1,
    config: &AdmissionConfigV1,
) -> Result<(), ProtocolError> {
    let pinned = PinnedNullifierVerifyingKey::from_config(
        &config.nullifier_groth16_vk,
        &config.nullifier_groth16_vk_fingerprint,
    )?;

    verify_statement_nullifier_proof(&pinned, &entry.statement, &entry.nullifier_proof)
}

pub fn verify_native_nullifier_proof(
    entry: &ZkProofEntryV1,
    config: &AdmissionConfigV1,
) -> ExternResult<()> {
    check_native_nullifier_proof(entry, config)
        .map_err(|err| wasm_error!(WasmErrorInner::Guest(err.to_string())))
}
