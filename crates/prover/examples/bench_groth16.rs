use std::time::Instant;

use zk_admission_protocol::{hashes::nullifier, ProverKeyV1, ZkStatementV1};

fn main() {
    let credential_secret = b"zk-admission-benchmark-secret-v1".to_vec();

    let deployment_id = [1u8; 32];
    let domain = [2u8; 32];

    let statement = ZkStatementV1 {
        deployment_id,
        protocol_version: ZkStatementV1::PROTOCOL_VERSION,
        domain,
        program_id: hex::decode("003f9649923b9dc13669ce8bac70548312746d2dd3fd10b4f8949c60b7974197")
            .expect("invalid program id")
            .try_into()
            .expect("program id must be 32 bytes"),
        prover: ProverKeyV1(vec![4, 5, 6]),
        issuer_id: [7u8; 32],
        issuer_key_id: [8u8; 32],
        credential_epoch: 42,
        statement_nonce: [9u8; 32],
        eligibility: true,
        nullifier: nullifier(
            &credential_secret,
            &deployment_id,
            &domain,
            ZkStatementV1::PROTOCOL_VERSION,
        ),
    };

    println!("Starting Groth16 proof benchmark...");
    println!("Setup is included in this timing because prove() currently performs setup.");

    let started = Instant::now();

    let proof =
        zk_admission_prover::prove(statement, credential_secret).expect("Groth16 proving failed");

    let elapsed = started.elapsed();

    println!("proof_bytes = {}", proof.len());
    println!("total_time = {:.2?}", elapsed);
}
