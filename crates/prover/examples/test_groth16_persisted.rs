use std::fs;

use zk_admission_protocol::hashes::nullifier;
use zk_admission_prover::groth16::api::{
    deserialize_proof, deserialize_proving_key, deserialize_verifying_key, prove, serialize_proof,
    verify, verifying_key_fingerprint, NullifierPublicInputs,
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

    let proving_key_bytes =
        fs::read("target/groth16/proving_key.bin").expect("failed to read persisted proving key");

    let verifying_key_bytes = fs::read("target/groth16/verifying_key.bin")
        .expect("failed to read persisted verifying key");

    let proving_key = deserialize_proving_key(&proving_key_bytes)
        .expect("failed to deserialize persisted proving key");

    let verifying_key = deserialize_verifying_key(&verifying_key_bytes)
        .expect("failed to deserialize persisted verifying key");

    let fingerprint =
        verifying_key_fingerprint(&verifying_key).expect("failed to fingerprint verifying key");

    let expected_fingerprint =
        hex::decode("c15ec289a32f962e86b6dd8b15dad739af4a9c56ce6687aabe324a727c121cae")
            .expect("invalid expected verifying-key fingerprint");

    assert_eq!(
        fingerprint.as_slice(),
        expected_fingerprint.as_slice(),
        "persisted verifying key fingerprint does not match expected key"
    );

    println!("verifying_key_fingerprint = {}", hex::encode(fingerprint));

    let proof =
        prove(&proving_key, credential_secret, statement, protocol_version).expect("prove failed");

    let proof_bytes = serialize_proof(&proof).expect("failed to serialize proof");

    let decoded_proof = deserialize_proof(&proof_bytes).expect("failed to deserialize proof");

    let verified = verify(
        &verifying_key,
        &NullifierPublicInputs {
            deployment_id,
            domain,
            expected_nullifier,
        },
        &decoded_proof,
    )
    .expect("verify failed");

    println!("proving_key_bytes = {}", proving_key_bytes.len());
    println!("verifying_key_bytes = {}", verifying_key_bytes.len());
    println!("proof_wire_bytes = {}", proof_bytes.len());
    println!("verified = {verified}");

    let wrong_deployment = NullifierPublicInputs {
        deployment_id: [0x44u8; 32],
        domain,
        expected_nullifier,
    };

    let wrong_deployment_verified = verify(&verifying_key, &wrong_deployment, &decoded_proof)
        .expect("wrong-deployment verification failed unexpectedly");

    println!("wrong_deployment_verified = {wrong_deployment_verified}");

    let wrong_domain = NullifierPublicInputs {
        deployment_id,
        domain: [0x55u8; 32],
        expected_nullifier,
    };

    let wrong_domain_verified = verify(&verifying_key, &wrong_domain, &decoded_proof)
        .expect("wrong-domain verification failed unexpectedly");

    println!("wrong_domain_verified = {wrong_domain_verified}");

    let wrong_nullifier = NullifierPublicInputs {
        deployment_id,
        domain,
        expected_nullifier: [0x66u8; 32],
    };

    let wrong_nullifier_verified = verify(&verifying_key, &wrong_nullifier, &decoded_proof)
        .expect("wrong-nullifier verification failed unexpectedly");

    println!("wrong_nullifier_verified = {wrong_nullifier_verified}");

    let protocol_version_2 = 2u16;

    let protocol_version_2_nullifier = nullifier(
        &credential_secret,
        &deployment_id,
        &domain,
        protocol_version_2,
    );

    let protocol_version_2_statement = NullifierPublicInputs {
        deployment_id,
        domain,
        expected_nullifier: protocol_version_2_nullifier,
    };

    let protocol_version_2_verified = verify(
        &verifying_key,
        &protocol_version_2_statement,
        &decoded_proof,
    )
    .expect("protocol-version-2 verification failed unexpectedly");

    println!("protocol_version_2_verified = {protocol_version_2_verified}");
}
