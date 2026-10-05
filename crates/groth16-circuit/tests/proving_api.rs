//! Tests of the production proving API: persisted keys, pinning, and
//! statement-derived public inputs.

use std::sync::OnceLock;

use zk_admission_groth16_circuit::{
    generate_key_material, NullifierKeyMaterialV1, NullifierProvingKeyV1,
};
use zk_admission_groth16_verifier::{
    verify_statement_nullifier_proof, verifying_key_bytes_fingerprint, PinnedNullifierVerifyingKey,
};
use zk_admission_protocol::{hashes::nullifier, ProverKeyV1, ZkStatementV1};

const SECRET: [u8; 32] = [0x11; 32];

fn material() -> &'static NullifierKeyMaterialV1 {
    static KEYS: OnceLock<NullifierKeyMaterialV1> = OnceLock::new();
    KEYS.get_or_init(|| generate_key_material().unwrap())
}

fn other_material() -> &'static NullifierKeyMaterialV1 {
    static KEYS: OnceLock<NullifierKeyMaterialV1> = OnceLock::new();
    KEYS.get_or_init(|| generate_key_material().unwrap())
}

fn proving_key() -> NullifierProvingKeyV1 {
    NullifierProvingKeyV1::from_bytes(
        &material().proving_key_bytes,
        &material().verifying_key_fingerprint,
    )
    .unwrap()
}

fn pinned() -> PinnedNullifierVerifyingKey {
    PinnedNullifierVerifyingKey::from_config(
        &material().verifying_key_bytes,
        &material().verifying_key_fingerprint,
    )
    .unwrap()
}

fn statement() -> ZkStatementV1 {
    let deployment_id = [0x22; 32];
    let domain = [0x33; 32];

    ZkStatementV1 {
        deployment_id,
        protocol_version: ZkStatementV1::PROTOCOL_VERSION,
        domain,
        program_id: [3; 32],
        prover: ProverKeyV1(vec![4, 5, 6]),
        issuer_id: [7; 32],
        issuer_key_id: [8; 32],
        credential_epoch: 42,
        statement_nonce: [9; 32],
        eligibility: true,
        nullifier: nullifier(
            &SECRET,
            &deployment_id,
            &domain,
            ZkStatementV1::PROTOCOL_VERSION,
        ),
    }
}

#[test]
fn key_material_is_self_consistent() {
    let material = material();

    assert_eq!(
        verifying_key_bytes_fingerprint(&material.verifying_key_bytes),
        material.verifying_key_fingerprint
    );
    assert_eq!(
        proving_key().verifying_key_id(),
        &material.verifying_key_fingerprint
    );
}

#[test]
fn proof_from_persisted_key_verifies_against_pinned_key() {
    let statement = statement();
    let proof = proving_key().prove_statement(&statement, &SECRET).unwrap();

    assert_eq!(proof.verifying_key_id, material().verifying_key_fingerprint);
    assert_eq!(
        verify_statement_nullifier_proof(&pinned(), &statement, &proof),
        Ok(())
    );
}

#[test]
fn proofs_are_randomised() {
    let statement = statement();
    let key = proving_key();

    let first = key.prove_statement(&statement, &SECRET).unwrap();
    let second = key.prove_statement(&statement, &SECRET).unwrap();

    assert_ne!(first.proof, second.proof);
    assert_eq!(
        verify_statement_nullifier_proof(&pinned(), &statement, &second),
        Ok(())
    );
}

#[test]
fn proving_key_must_match_pinned_fingerprint() {
    let mut fingerprint = material().verifying_key_fingerprint;
    fingerprint[0] ^= 1;

    assert!(
        NullifierProvingKeyV1::from_bytes(&material().proving_key_bytes, &fingerprint).is_err()
    );

    // A genuine proving key from another setup is not accepted under this
    // deployment's fingerprint.
    assert!(NullifierProvingKeyV1::from_bytes(
        &other_material().proving_key_bytes,
        &material().verifying_key_fingerprint
    )
    .is_err());
}

#[test]
fn malformed_proving_key_is_rejected() {
    let fingerprint = material().verifying_key_fingerprint;
    let bytes = &material().proving_key_bytes;

    let mut trailing = bytes.clone();
    trailing.push(0);

    assert!(NullifierProvingKeyV1::from_bytes(&trailing, &fingerprint).is_err());
    assert!(NullifierProvingKeyV1::from_bytes(&bytes[..bytes.len() - 1], &fingerprint).is_err());
    assert!(NullifierProvingKeyV1::from_bytes(&[], &fingerprint).is_err());
}

#[test]
fn prover_rejects_wrong_secret_length_and_value() {
    let statement = statement();
    let key = proving_key();

    assert!(key.prove_statement(&statement, &SECRET[..31]).is_err());
    assert!(key.prove_statement(&statement, &[0x11; 33]).is_err());
    assert!(key.prove_statement(&statement, &[0x12; 32]).is_err());
}

#[test]
fn prover_rejects_unsupported_protocol_version() {
    let mut statement = statement();
    statement.protocol_version = 2;
    statement.nullifier = nullifier(&SECRET, &statement.deployment_id, &statement.domain, 2);

    assert!(proving_key().prove_statement(&statement, &SECRET).is_err());
}

#[test]
fn load_reads_persisted_key() {
    let dir =
        std::env::temp_dir().join(format!("zk-admission-groth16-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("pk.bin");
    std::fs::write(&path, &material().proving_key_bytes).unwrap();

    let key = NullifierProvingKeyV1::load(&path, &material().verifying_key_fingerprint).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();

    assert!(key.prove_statement(&statement(), &SECRET).is_ok());
}
