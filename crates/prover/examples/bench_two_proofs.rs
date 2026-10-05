use std::time::Instant;

use sp1_sdk::blocking::{ProveRequest, Prover, ProverClient, SP1Stdin};
use sp1_sdk::{include_elf, HashableKey, ProvingKey};

use zk_admission_protocol::{hashes::nullifier, ProverKeyV1, ZkStatementV1};

const ELF: sp1_sdk::blocking::Elf = include_elf!("zk-admission-sp1-guest");

fn make_statement(program_id: [u8; 32], nonce: u8) -> (ZkStatementV1, Vec<u8>) {
    let credential_secret = b"zk-admission-benchmark-secret-v1".to_vec();

    let deployment_id = [1u8; 32];
    let domain = [2u8; 32];

    let statement = ZkStatementV1 {
        deployment_id,
        protocol_version: ZkStatementV1::PROTOCOL_VERSION,
        domain,
        program_id,
        prover: ProverKeyV1(vec![4, 5, 6]),
        issuer_id: [7u8; 32],
        issuer_key_id: [8u8; 32],
        credential_epoch: 42,
        statement_nonce: [nonce; 32],
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

fn prove_once<P: Prover>(
    client: &P,
    pk: &P::ProvingKey,
    statement: ZkStatementV1,
    credential_secret: Vec<u8>,
) -> std::time::Duration {
    let mut stdin = SP1Stdin::new();
    stdin.write(&statement);
    stdin.write(&credential_secret);

    let started = Instant::now();

    let proof = client
        .prove(pk, stdin)
        .groth16()
        .run()
        .expect("SP1 Groth16 proving failed");

    let elapsed = started.elapsed();

    assert_eq!(proof.bytes().len(), 356);

    elapsed
}

fn main() {
    println!("Starting two-proof benchmark...");

    let client = ProverClient::builder().cpu().build();

    println!("Running setup...");
    let setup_started = Instant::now();

    let pk = client.setup(ELF).expect("SP1 setup failed");

    println!("setup_time = {:.2?}", setup_started.elapsed());

    let program_id = pk.verifying_key().bytes32_raw();

    println!("program_vkey_hash = {}", hex::encode(program_id));

    let (statement1, secret1) = make_statement(program_id, 9);
    let (statement2, secret2) = make_statement(program_id, 10);

    println!("Running proof #1...");
    let proof1_time = prove_once(&client, &pk, statement1, secret1);
    println!("proof_1_time = {:.2?}", proof1_time);

    println!("Running proof #2...");
    let proof2_time = prove_once(&client, &pk, statement2, secret2);
    println!("proof_2_time = {:.2?}", proof2_time);

    let (statement3, secret3) = make_statement(program_id, 11);

    println!("Running proof #3...");
    let proof3_time = prove_once(&client, &pk, statement3, secret3);
    println!("proof_3_time = {:.2?}", proof3_time);

    println!("All three proofs completed.");
}
