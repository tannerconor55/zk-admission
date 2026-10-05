//! Load persisted native nullifier keys, prove a sample statement and
//! verify it exactly as the integrity zome does.
//!
//! ```text
//! cargo run --release -p zk-admission-groth16-circuit \
//!     --example nullifier_groth16_roundtrip -- <pk.bin> <vk.bin> <fingerprint-hex>
//! ```

use std::time::Instant;

use zk_admission_groth16_circuit::NullifierProvingKeyV1;
use zk_admission_groth16_verifier::{
    verify_statement_nullifier_proof, PinnedNullifierVerifyingKey,
};
use zk_admission_protocol::{hashes::nullifier, ProverKeyV1, ZkStatementV1};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [pk_path, vk_path, fingerprint_hex] = args.as_slice() else {
        panic!("usage: nullifier_groth16_roundtrip <pk.bin> <vk.bin> <fingerprint-hex>");
    };

    let fingerprint: [u8; 32] = hex::decode(fingerprint_hex)
        .expect("fingerprint must be hex")
        .try_into()
        .expect("fingerprint must be 32 bytes");

    let started = Instant::now();
    let proving_key = NullifierProvingKeyV1::load(pk_path, &fingerprint).unwrap();
    println!("load_proving_key = {:.2?}", started.elapsed());

    let vk_bytes = std::fs::read(vk_path).expect("failed to read verifying key");
    let started = Instant::now();
    let pinned = PinnedNullifierVerifyingKey::from_config(&vk_bytes, &fingerprint).unwrap();
    println!("load_pinned_verifying_key = {:.2?}", started.elapsed());

    let secret = [0x11u8; 32];
    let deployment_id = [0x22u8; 32];
    let domain = [0x33u8; 32];
    let statement = ZkStatementV1 {
        deployment_id,
        protocol_version: ZkStatementV1::PROTOCOL_VERSION,
        domain,
        program_id: [0; 32],
        prover: ProverKeyV1(vec![0; 32]),
        issuer_id: [0; 32],
        issuer_key_id: [0; 32],
        credential_epoch: 0,
        statement_nonce: [0; 32],
        eligibility: true,
        nullifier: nullifier(&secret, &deployment_id, &domain, 1),
    };

    let started = Instant::now();
    let proof = proving_key.prove_statement(&statement, &secret).unwrap();
    println!("prove_and_self_verify = {:.2?}", started.elapsed());

    let started = Instant::now();
    verify_statement_nullifier_proof(&pinned, &statement, &proof).unwrap();
    println!("verify = {:.2?}", started.elapsed());

    println!("verifying_key_bytes = {}", vk_bytes.len());
    println!("proof_wire_bytes = {}", proof.proof.len());
    println!("verified = true");
}
