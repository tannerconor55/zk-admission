#![no_main]
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use zk_admission_protocol::{
    encoding::encode_statement,
    hashes::nullifier,
    ZkStatementV1,
};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let statement: ZkStatementV1 = sp1_zkvm::io::read();
    let credential_secret: Vec<u8> = sp1_zkvm::io::read();

    // The guest enforces the protocol version and eligibility itself.
    // These are security-relevant statement fields and therefore cannot
    // be trusted merely because the host supplied them.
    assert_eq!(
        statement.protocol_version,
        ZkStatementV1::PROTOCOL_VERSION
    );
    assert!(statement.eligibility);

    let expected_nullifier = nullifier(
        &credential_secret,
        &statement.deployment_id,
        &statement.domain,
        statement.protocol_version,
    );

    assert_eq!(statement.nullifier, expected_nullifier);

    // The canonical statement is the complete SP1 public value.
    //
    // The Holochain host verifier independently supplies these exact bytes
    // to Groth16Verifier, binding every security-relevant statement field
    // to the proof.
    let canonical_statement = encode_statement(&statement);
    sp1_zkvm::io::commit_slice(&canonical_statement);
}
