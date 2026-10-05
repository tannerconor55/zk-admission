use zk_admission_protocol::hashes::nullifier;
use zk_admission_prover::groth16::api::{prove, setup, verify, NullifierPublicInputs};

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

    let (proving_key, verifying_key) = setup(protocol_version).expect("setup failed");

    let proof = prove(
        &proving_key,
        credential_secret,
        NullifierPublicInputs {
            deployment_id: statement.deployment_id,
            domain: statement.domain,
            expected_nullifier: statement.expected_nullifier,
        },
        protocol_version,
    )
    .expect("prove failed");

    let valid = verify(&verifying_key, &statement, &proof).expect("valid verification failed");

    println!("valid = {valid}");

    let mut wrong_deployment = statement.deployment_id;
    wrong_deployment[0] ^= 1;

    let wrong_deployment_statement = NullifierPublicInputs {
        deployment_id: wrong_deployment,
        domain: statement.domain,
        expected_nullifier: statement.expected_nullifier,
    };

    let deployment_result = verify(&verifying_key, &wrong_deployment_statement, &proof)
        .expect("deployment verification operation failed");

    println!("wrong_deployment = {deployment_result}");

    let mut wrong_domain = statement.domain;
    wrong_domain[0] ^= 1;

    let wrong_domain_statement = NullifierPublicInputs {
        deployment_id: statement.deployment_id,
        domain: wrong_domain,
        expected_nullifier: statement.expected_nullifier,
    };

    let domain_result = verify(&verifying_key, &wrong_domain_statement, &proof)
        .expect("domain verification operation failed");

    println!("wrong_domain = {domain_result}");

    let mut wrong_nullifier = statement.expected_nullifier;
    wrong_nullifier[0] ^= 1;

    let wrong_nullifier_statement = NullifierPublicInputs {
        deployment_id: statement.deployment_id,
        domain: statement.domain,
        expected_nullifier: wrong_nullifier,
    };

    let nullifier_result = verify(&verifying_key, &wrong_nullifier_statement, &proof)
        .expect("nullifier verification operation failed");

    println!("wrong_nullifier = {nullifier_result}");
}
