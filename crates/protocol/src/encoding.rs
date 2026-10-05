use crate::{
    admission::{AdmissionCapabilityV1, AdmissionDelegationV1},
    statement::ZkStatementV1,
};

pub const STATEMENT_DOMAIN: &[u8] = b"HOLOCHAIN-ZK-STATEMENT-V1";

pub const NULLIFIER_DOMAIN: &[u8] = b"HOLOCHAIN-ZK-NULLIFIER-V1";

pub const DELEGATION_DOMAIN: &[u8] = b"HOLOCHAIN-ZK-DELEGATION-V1";

pub const CAPABILITY_DOMAIN: &[u8] = b"HOLOCHAIN-ZK-CAPABILITY-V1";

fn push_u16_be(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u32_be(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u64_be(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_bool(out: &mut Vec<u8>, value: bool) {
    out.push(u8::from(value));
}

fn push_fixed<const N: usize>(out: &mut Vec<u8>, value: &[u8; N]) {
    out.extend_from_slice(value);
}

/// Canonical V1 statement encoding.
///
/// IMPORTANT:
/// This is protocol encoding, not Holochain MsgPack.
pub fn encode_statement(statement: &ZkStatementV1) -> Vec<u8> {
    let mut out = Vec::new();

    push_fixed(&mut out, &statement.deployment_id);
    push_u16_be(&mut out, statement.protocol_version);
    push_fixed(&mut out, &statement.domain);
    push_fixed(&mut out, &statement.program_id);

    push_u32_be(&mut out, statement.prover.0.len() as u32);
    out.extend_from_slice(&statement.prover.0);

    push_fixed(&mut out, &statement.issuer_id);
    push_fixed(&mut out, &statement.issuer_key_id);
    push_u64_be(&mut out, statement.credential_epoch);
    push_fixed(&mut out, &statement.statement_nonce);
    push_bool(&mut out, statement.eligibility);
    push_fixed(&mut out, &statement.nullifier);

    out
}

/// Canonical delegation identity body.
///
/// `delegation_id` and `root_signature` are excluded.
pub fn encode_delegation_identity(delegation: &AdmissionDelegationV1) -> Vec<u8> {
    let mut out = Vec::new();

    push_fixed(&mut out, &delegation.root_key_id);
    push_fixed(&mut out, &delegation.op_key_id);
    push_fixed(&mut out, &delegation.op_public_key);
    push_fixed(&mut out, &delegation.policy_id);
    push_u64_be(&mut out, delegation.allowed_resource_classes);
    push_u64_be(&mut out, delegation.epoch_start);
    push_u64_be(&mut out, delegation.epoch_end);

    out
}

/// Canonical capability identity body.
///
/// `capability_id` and `op_signature` are excluded.
pub fn encode_capability_identity(capability: &AdmissionCapabilityV1) -> Vec<u8> {
    let mut out = Vec::new();

    push_fixed(&mut out, &capability.delegation_id);
    push_fixed(&mut out, &capability.deployment_id);

    push_u32_be(&mut out, capability.prover.0.len() as u32);
    out.extend_from_slice(&capability.prover.0);

    push_fixed(&mut out, &capability.policy_id);
    push_fixed(&mut out, &capability.statement_hash);
    push_fixed(&mut out, &capability.statement_nonce);

    push_u16_be(&mut out, capability.resource_class);
    push_u64_be(&mut out, capability.admission_epoch);
    push_u32_be(&mut out, capability.seq_start);
    push_u32_be(&mut out, capability.seq_end_exclusive);
    push_fixed(&mut out, &capability.op_key_id);

    out
}

pub fn encode_nullifier_input(
    deployment_id: &[u8; 32],
    domain: &[u8; 32],
    protocol_version: u16,
) -> Vec<u8> {
    let mut out = Vec::new();

    out.extend_from_slice(NULLIFIER_DOMAIN);
    push_fixed(&mut out, deployment_id);
    push_fixed(&mut out, domain);
    push_u16_be(&mut out, protocol_version);

    out
}
