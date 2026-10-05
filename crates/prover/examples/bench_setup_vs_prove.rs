use std::time::Instant;

use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient, SP1Stdin};
use sp1_sdk::{include_elf, HashableKey, ProvingKey};

use zk_admission_protocol::{hashes::nullifier, ProverKeyV1, ZkStatementV1};

const ELF: sp1_sdk::blocking::Elf = include_elf!("zk-admission-sp1-guest");

fn make_statement() -> (ZkStatementV1, Vec<u8>) {
    let credential_secret = b"zk-admission-benchmark-secret-v1".to_vec();

    let deployment_id = [1u8; 32];
    let domain = [2u8; 32];

    let client = ProverClient::builder().cpu().build();

    let pk = client.setup(ELF).expect("SP1 setup failed");

    let program_id = pk.verifying_key().bytes32_raw();

    let statement = ZkStatementV1 {
        deployment_id,
        protocol_version: ZkStatementV1::PROTOCOL_VERSION,
        domain,
        program_id,
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

    (statement, credential_secret)
}

fn main() {
    println!("Starting setup-vs-prove benchmark...");

    let client = ProverClient::builder().cpu().build();

    println!("Running setup...");
    let setup_started = Instant::now();

    let pk = client.setup(ELF).expect("SP1 setup failed");

    let setup_elapsed = setup_started.elapsed();

    println!("setup_time = {:.2?}", setup_elapsed);
    println!(
        "program_vkey_hash = {}",
        hex::encode(pk.verifying_key().bytes32_raw())
    );

    let credential_secret = b"zk-admission-benchmark-secret-v1".to_vec();

    let deployment_id = [1u8; 32];
    let domain = [2u8; 32];

    let statement = ZkStatementV1 {
        deployment_id,
        protocol_version: ZkStatementV1::PROTOCOL_VERSION,
        domain,
        program_id: pk.verifying_key().bytes32_raw(),
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

    let mut stdin = SP1Stdin::new();
    stdin.write(&statement);
    stdin.write(&credential_secret);

    println!("Running Groth16 proving...");
    let prove_started = Instant::now();

    let proof = client
        .prove(&pk, stdin)
        .groth16()
        .run()
        .expect("SP1 Groth16 proving failed");

    let prove_elapsed = prove_started.elapsed();

    println!("proof_bytes = {}", proof.bytes().len());
    println!("prove_time = {:.2?}", prove_elapsed);
    println!(
        "total_setup_plus_prove = {:.2?}",
        setup_elapsed + prove_elapsed
    );

    let _ = make_statement;
}
