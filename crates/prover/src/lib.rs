#![forbid(unsafe_code)]
pub mod groth16;

use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient, SP1Stdin};
use sp1_sdk::{include_elf, HashableKey, ProvingKey};

use zk_admission_protocol::{hashes::nullifier, ZkProofEntryV1, ZkStatementV1};

const ELF: sp1_sdk::blocking::Elf = include_elf!("zk-admission-sp1-guest");

/// Return the raw 32-byte SP1 verifying-key hash for the embedded guest ELF.
///
/// This is the exact representation expected in `ZkStatementV1::program_id`.
pub fn program_vkey_hash() -> Result<[u8; 32], String> {
    let client = ProverClient::builder().cpu().build();

    let pk = client
        .setup(ELF)
        .map_err(|err| format!("SP1 setup failed: {err}"))?;

    Ok(pk.verifying_key().bytes32_raw())
}

/// Generate a Groth16 proof for the canonical statement.
///
/// The statement's `program_id` must already equal the actual SP1
/// verifying-key hash of the embedded guest ELF.
pub fn prove(statement: ZkStatementV1, credential_secret: Vec<u8>) -> Result<Vec<u8>, String> {
    let client = ProverClient::builder().cpu().build();

    let pk = client
        .setup(ELF)
        .map_err(|err| format!("SP1 setup failed: {err}"))?;

    let actual_program_id = pk.verifying_key().bytes32_raw();

    if statement.program_id != actual_program_id {
        return Err("statement program_id does not match SP1 guest verifying key".into());
    }

    let expected_nullifier = nullifier(
        &credential_secret,
        &statement.deployment_id,
        &statement.domain,
        statement.protocol_version,
    );

    if statement.nullifier != expected_nullifier {
        return Err("statement nullifier does not match credential secret".into());
    }

    let mut stdin = SP1Stdin::new();
    stdin.write(&statement);
    stdin.write(&credential_secret);

    let proof = client
        .prove(&pk, stdin)
        .groth16()
        .run()
        .map_err(|err| format!("SP1 Groth16 proving failed: {err}"))?;

    let proof_bytes = proof.bytes();

    if proof_bytes.len() != 356 {
        return Err(format!(
            "unexpected SP1 Groth16 proof length: {}",
            proof_bytes.len()
        ));
    }

    Ok(proof_bytes)
}

/// Construct the complete immutable Holochain proof entry.
///
/// Generates both mandatory proofs for the same statement:
///
/// - the native nullifier Groth16 proof, from the deployment's persisted
///   proving key (checked against its pinned verifying-key fingerprint when
///   loaded); this is generated first because it is fast and fails early
///   on a wrong secret or key;
/// - the SP1 Groth16 proof of the full canonical statement.
///
/// The native circuit requires a 32-byte `credential_secret`.
pub fn prove_entry(
    statement: ZkStatementV1,
    admission: zk_admission_protocol::AdmissionV1,
    credential_secret: Vec<u8>,
    nullifier_proving_key: &groth16::api::NullifierProvingKeyV1,
) -> Result<ZkProofEntryV1, String> {
    let nullifier_proof = nullifier_proving_key.prove_statement(&statement, &credential_secret)?;

    let groth16_proof = prove(statement.clone(), credential_secret)?;

    Ok(ZkProofEntryV1 {
        statement,
        admission,
        groth16_proof,
        nullifier_proof,
    })
}
