use serde::{Deserialize, Serialize};

use crate::{statement::ProverKeyV1, types::SignatureV1};

/// DNA-authenticated admission trust configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionConfigV1 {
    pub admission_root_key: [u8; 32],
    pub admission_root_key_id: [u8; 32],

    pub issuer_root_key: [u8; 32],
    pub issuer_root_key_id: [u8; 32],

    /// Raw 32-byte SP1 program verifying-key hash.
    ///
    /// This is the big-endian representation corresponding to
    /// `SP1VerifyingKey::bytes32_raw()`.
    pub sp1_program_vkey_hash: [u8; 32],
}

/// Signed delegation from the deployment admission root to an operational
/// admission key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionDelegationV1 {
    pub root_key_id: [u8; 32],
    pub op_key_id: [u8; 32],
    pub op_public_key: [u8; 32],
    pub policy_id: [u8; 32],
    pub allowed_resource_classes: u64,
    pub epoch_start: u64,
    pub epoch_end: u64,
    pub delegation_id: [u8; 32],
    pub root_signature: SignatureV1,
}

/// Signed, bounded admission capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionCapabilityV1 {
    pub capability_id: [u8; 32],
    pub delegation_id: [u8; 32],
    pub deployment_id: [u8; 32],
    pub prover: ProverKeyV1,
    pub policy_id: [u8; 32],
    pub statement_hash: [u8; 32],
    pub statement_nonce: [u8; 32],
    pub resource_class: u16,
    pub admission_epoch: u64,
    pub seq_start: u32,
    pub seq_end_exclusive: u32,
    pub op_key_id: [u8; 32],
    pub op_signature: SignatureV1,
}

/// Complete self-contained admission object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionV1 {
    pub delegation: AdmissionDelegationV1,
    pub capability: AdmissionCapabilityV1,
}
