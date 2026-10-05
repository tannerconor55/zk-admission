use std::fs;
use std::time::Instant;
use zk_admission_protocol::hashes::nullifier;
use zk_admission_prover::groth16::api::{
    deserialize_proof, deserialize_proving_key, deserialize_verifying_key, prove, serialize_proof,
    serialize_proving_key, serialize_verifying_key, setup, verify, NullifierPublicInputs,
};

fn main() {
    let credential_secret = [0x11u8; 32];
    let deployment_id = [0x22u8; 32];
    let domain = [0x33u8; 32];
    let protocol_version = 1u16;

    let expected_nullifier = nullifier(
        &credential_secret,
        &deployment_id,
        &domain,
        protocol_version,
    );

    let statement = NullifierPublicInputs {
        deployment_id,
        domain,
        expected_nullifier,
    };

    let setup_start = Instant::now();

    let (proving_key, verifying_key) = setup(protocol_version).expect("setup failed");

    println!("setup_seconds = {:.3}", setup_start.elapsed().as_secs_f64());

    let proving_key_bytes =
        serialize_proving_key(&proving_key).expect("failed to serialize proving key");

    let key_dir = "target/groth16";
    fs::create_dir_all(key_dir).expect("failed to create Groth16 key directory");

    fs::write(format!("{key_dir}/proving_key.bin"), &proving_key_bytes)
        .expect("failed to write proving key");

    let decoded_proving_key_bytes =
        fs::read(format!("{key_dir}/proving_key.bin")).expect("failed to read proving key");

    let decoded_proving_key = deserialize_proving_key(&decoded_proving_key_bytes)
        .expect("failed to deserialize proving key");

    let prove_start = Instant::now();

    let proof = prove(
        &decoded_proving_key,
        credential_secret,
        statement,
        protocol_version,
    )
    .expect("prove failed");

    println!("prove_seconds = {:.3}", prove_start.elapsed().as_secs_f64());

    let proof_bytes = serialize_proof(&proof).expect("failed to serialize proof");

    let proving_key_size = proving_key_bytes.len();

    let verifying_key_bytes =
        serialize_verifying_key(&verifying_key).expect("failed to serialize verifying key");

    fs::write(format!("{key_dir}/verifying_key.bin"), &verifying_key_bytes)
        .expect("failed to write verifying key");

    let decoded_verifying_key_bytes =
        fs::read(format!("{key_dir}/verifying_key.bin")).expect("failed to read verifying key");

    let decoded_verifying_key = deserialize_verifying_key(&decoded_verifying_key_bytes)
        .expect("failed to deserialize verifying key");

    let decoded_proof = deserialize_proof(&proof_bytes).expect("failed to deserialize proof");

    let verify_start = Instant::now();

    let verified = verify(
        &decoded_verifying_key,
        &NullifierPublicInputs {
            deployment_id,
            domain,
            expected_nullifier,
        },
        &decoded_proof,
    )
    .expect("verify failed");

    println!(
        "verify_seconds = {:.6}",
        verify_start.elapsed().as_secs_f64()
    );
    println!("verified = {verified}");
    println!("proof_wire_bytes = {}", proof_bytes.len());
    println!("proving_key_compressed_bytes = {proving_key_size}");
    println!(
        "verifying_key_compressed_bytes = {}",
        verifying_key_bytes.len()
    );
}

#[test]
fn malformed_proof_is_rejected() {
    use zk_admission_prover::groth16::api::deserialize_proof;

    assert!(deserialize_proof(&[]).is_err());
    assert!(deserialize_proof(&[0u8; 127]).is_err());
}

#[test]
fn malformed_verifying_key_is_rejected() {
    use zk_admission_prover::groth16::api::deserialize_verifying_key;

    assert!(deserialize_verifying_key(&[]).is_err());
    assert!(deserialize_verifying_key(&[0u8; 455]).is_err());
}

#[test]
fn versioned_proof_format_is_enforced() {
    use zk_admission_prover::groth16::api::deserialize_proof;

    assert!(deserialize_proof(b"ZKGP\x01").is_err());
    assert!(deserialize_proof(b"BAD!\x01").is_err());
    assert!(deserialize_proof(b"ZKGP\x02").is_err());
    assert!(deserialize_proof(&[0u8; 128]).is_err());
}
