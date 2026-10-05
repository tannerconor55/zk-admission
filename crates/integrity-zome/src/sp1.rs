use hdi::prelude::*;

use zk_admission_protocol::{
    encoding::encode_statement, AdmissionConfigV1, ProtocolError, ZkProofEntryV1,
};

use sp1_verifier::{Groth16Verifier, GROTH16_VK_BYTES};

/// Normal non-TEE SP1 Groth16 encoding:
///
/// 4 bytes  - Groth16 verifier-key hash prefix
/// 32 bytes - exit code
/// 32 bytes - recursion VK root
/// 32 bytes - proof nonce
/// 256 bytes - raw BN254 Groth16 proof
const SP1_GROTH16_PROOF_LEN: usize = 356;

/// Verify the SP1 Groth16 proof against the canonical V1 statement.
///
/// Security boundary:
///
/// DNA properties authenticate the SP1 program verifying-key hash.
/// The statement must bind to exactly that hash.
/// The canonical statement bytes are the SP1 public values.
///
/// The verifier therefore establishes:
///
/// ```text
/// Groth16 proof
///   -> SP1 program vkey
///   -> SP1 public values
///   -> canonical ZkStatementV1
///   -> entry.statement
/// ```
pub fn verify_sp1_groth16(proof: &ZkProofEntryV1, config: &AdmissionConfigV1) -> ExternResult<()> {
    // V1 accepts only the normal non-TEE SP1 Groth16 encoding.
    //
    // The SDK's TEE form has an additional prefix and is intentionally
    // outside this protocol version.
    if proof.groth16_proof.len() != SP1_GROTH16_PROOF_LEN {
        return Err(protocol_error(ProtocolError::InvalidSp1Groth16Proof));
    }

    // The program identifier in the statement is not trusted by itself.
    // It must equal the SP1 program authenticated by DNA properties.
    if proof.statement.program_id != config.sp1_program_vkey_hash {
        return Err(protocol_error(ProtocolError::Sp1ProgramVkeyMismatch));
    }

    // SP1 expects the program vkey hash in its textual 0x-prefixed
    // 32-byte hexadecimal representation.
    let program_vkey_hash = format!("0x{}", hex::encode(config.sp1_program_vkey_hash));

    // These bytes are exactly the public values committed by the SP1
    // guest. The guest is responsible for committing canonical statement
    // bytes; the host independently reproduces those bytes here.
    let canonical_statement = encode_statement(&proof.statement);

    Groth16Verifier::verify(
        &proof.groth16_proof,
        &canonical_statement,
        &program_vkey_hash,
        &GROTH16_VK_BYTES,
    )
    .map_err(|_| protocol_error(ProtocolError::Sp1Groth16VerificationFailed))
}

fn protocol_error(err: ProtocolError) -> WasmError {
    wasm_error!(WasmErrorInner::Guest(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AdmissionConfigV1 {
        AdmissionConfigV1 {
            admission_root_key: [0; 32],
            admission_root_key_id: [0; 32],
            issuer_root_key: [0; 32],
            issuer_root_key_id: [0; 32],
            sp1_program_vkey_hash: [7; 32],
        }
    }

    #[test]
    fn rejects_wrong_sp1_program_before_verifier() {
        let mut statement = zk_admission_protocol::ZkStatementV1 {
            deployment_id: [1; 32],
            protocol_version: zk_admission_protocol::ZkStatementV1::PROTOCOL_VERSION,
            domain: [2; 32],
            program_id: [3; 32],
            prover: zk_admission_protocol::ProverKeyV1(vec![4]),
            issuer_id: [5; 32],
            issuer_key_id: [6; 32],
            credential_epoch: 7,
            statement_nonce: [8; 32],
            eligibility: true,
            nullifier: [9; 32],
        };

        let proof = ZkProofEntryV1 {
            statement: statement.clone(),
            admission: zk_admission_protocol::AdmissionV1 {
                delegation: zk_admission_protocol::AdmissionDelegationV1 {
                    root_key_id: [0; 32],
                    op_key_id: [0; 32],
                    op_public_key: [0; 32],
                    policy_id: [0; 32],
                    allowed_resource_classes: 0,
                    epoch_start: 0,
                    epoch_end: 0,
                    delegation_id: [0; 32],
                    root_signature: zk_admission_protocol::SignatureV1([0; 64]),
                },
                capability: zk_admission_protocol::AdmissionCapabilityV1 {
                    capability_id: [0; 32],
                    delegation_id: [0; 32],
                    deployment_id: [0; 32],
                    prover: zk_admission_protocol::ProverKeyV1(vec![4]),
                    policy_id: [0; 32],
                    statement_hash: [0; 32],
                    statement_nonce: [0; 32],
                    resource_class: 0,
                    admission_epoch: 0,
                    seq_start: 0,
                    seq_end_exclusive: 1,
                    op_key_id: [0; 32],
                    op_signature: zk_admission_protocol::SignatureV1([0; 64]),
                },
            },
            groth16_proof: vec![0; SP1_GROTH16_PROOF_LEN],
        };

        let err = verify_sp1_groth16(&proof, &test_config()).unwrap_err();
        assert!(err
            .to_string()
            .contains("SP1 program verifying-key hash mismatch"));

        statement.program_id = [7; 32];
        let _ = statement;
    }

    #[test]
    fn rejects_nonstandard_proof_length() {
        let config = test_config();

        // This test only needs a structurally valid proof entry far enough
        // to exercise the length guard. The program ID is intentionally
        // correct so the length check is the first failure.
        let statement = zk_admission_protocol::ZkStatementV1 {
            deployment_id: [1; 32],
            protocol_version: zk_admission_protocol::ZkStatementV1::PROTOCOL_VERSION,
            domain: [2; 32],
            program_id: config.sp1_program_vkey_hash,
            prover: zk_admission_protocol::ProverKeyV1(vec![4]),
            issuer_id: [5; 32],
            issuer_key_id: [6; 32],
            credential_epoch: 7,
            statement_nonce: [8; 32],
            eligibility: true,
            nullifier: [9; 32],
        };

        let proof = ZkProofEntryV1 {
            statement,
            admission: zk_admission_protocol::AdmissionV1 {
                delegation: zk_admission_protocol::AdmissionDelegationV1 {
                    root_key_id: [0; 32],
                    op_key_id: [0; 32],
                    op_public_key: [0; 32],
                    policy_id: [0; 32],
                    allowed_resource_classes: 0,
                    epoch_start: 0,
                    epoch_end: 0,
                    delegation_id: [0; 32],
                    root_signature: zk_admission_protocol::SignatureV1([0; 64]),
                },
                capability: zk_admission_protocol::AdmissionCapabilityV1 {
                    capability_id: [0; 32],
                    delegation_id: [0; 32],
                    deployment_id: [0; 32],
                    prover: zk_admission_protocol::ProverKeyV1(vec![4]),
                    policy_id: [0; 32],
                    statement_hash: [0; 32],
                    statement_nonce: [0; 32],
                    resource_class: 0,
                    admission_epoch: 0,
                    seq_start: 0,
                    seq_end_exclusive: 1,
                    op_key_id: [0; 32],
                    op_signature: zk_admission_protocol::SignatureV1([0; 64]),
                },
            },
            groth16_proof: vec![0; SP1_GROTH16_PROOF_LEN - 1],
        };

        let err = verify_sp1_groth16(&proof, &config).unwrap_err();
        assert!(err
            .to_string()
            .contains("invalid SP1 Groth16 proof encoding"));
    }
}
