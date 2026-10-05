use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::{
    admission::{AdmissionCapabilityV1, AdmissionDelegationV1},
    encoding::{
        encode_capability_identity, encode_delegation_identity, encode_nullifier_input,
        encode_statement, CAPABILITY_DOMAIN, DELEGATION_DOMAIN, STATEMENT_DOMAIN,
    },
    statement::ZkStatementV1,
};

type HmacSha256 = Hmac<Sha256>;

pub fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(input);

    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);

    output
}

pub fn statement_hash(statement: &ZkStatementV1) -> [u8; 32] {
    let mut input = Vec::new();

    input.extend_from_slice(STATEMENT_DOMAIN);
    input.extend_from_slice(&encode_statement(statement));

    sha256_bytes(&input)
}

pub fn delegation_id(delegation: &AdmissionDelegationV1) -> [u8; 32] {
    let mut input = Vec::new();

    input.extend_from_slice(DELEGATION_DOMAIN);
    input.extend_from_slice(&encode_delegation_identity(delegation));

    sha256_bytes(&input)
}

pub fn capability_id(capability: &AdmissionCapabilityV1) -> [u8; 32] {
    let mut input = Vec::new();

    input.extend_from_slice(CAPABILITY_DOMAIN);
    input.extend_from_slice(&encode_capability_identity(capability));

    sha256_bytes(&input)
}

/// V1:
///
/// HMAC-SHA256(
///     credential_secret,
///     "HOLOCHAIN-ZK-NULLIFIER-V1"
///       || deployment_id
///       || domain
///       || u16_be(protocol_version)
/// )
///
/// `credential_secret` is private SP1 witness material.
pub fn nullifier(
    credential_secret: &[u8],
    deployment_id: &[u8; 32],
    domain: &[u8; 32],
    protocol_version: u16,
) -> [u8; 32] {
    let input = encode_nullifier_input(deployment_id, domain, protocol_version);

    let mut mac =
        HmacSha256::new_from_slice(credential_secret).expect("HMAC accepts arbitrary key length");

    mac.update(&input);

    let result = mac.finalize().into_bytes();

    let mut output = [0u8; 32];
    output.copy_from_slice(&result);

    output
}
