use serde::{Deserialize, Serialize};

/// Protocol-owned representation of the Holochain author key.
///
/// The exact conversion to/from Holochain AgentPubKey will be defined when
/// the exact HDI/HDK version is pinned.
///
/// This wrapper deliberately does not define the cryptographic meaning of
/// AgentPubKey; it only provides a stable protocol boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverKeyV1(pub Vec<u8>);

/// Public statement bound into the SP1 proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkStatementV1 {
    pub deployment_id: [u8; 32],
    pub protocol_version: u16,
    pub domain: [u8; 32],
    pub program_id: [u8; 32],
    pub prover: ProverKeyV1,
    pub issuer_id: [u8; 32],
    pub issuer_key_id: [u8; 32],
    pub credential_epoch: u64,
    pub statement_nonce: [u8; 32],
    pub eligibility: bool,
    pub nullifier: [u8; 32],
}

impl ZkStatementV1 {
    pub const PROTOCOL_VERSION: u16 = 1;

    pub fn is_eligible(&self) -> bool {
        self.eligibility
    }
}
