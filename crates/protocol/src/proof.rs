use holochain_serialized_bytes::prelude::SerializedBytes;
use serde::{Deserialize, Serialize};

use crate::{admission::AdmissionV1, statement::ZkStatementV1};

/// Name of the native nullifier relation proven by `NullifierGroth16ProofV1`:
///
/// ```text
/// nullifier == HMAC-SHA256(
///     credential_secret,
///     "HOLOCHAIN-ZK-NULLIFIER-V1" || deployment_id || domain || u16_be(1)
/// )
/// ```
///
/// over BN254 Groth16 with public inputs (deployment_id, domain, nullifier)
/// and a private 32-byte `credential_secret`.
pub const NULLIFIER_GROTH16_CIRCUIT_ID_V1: &str = "HOLOCHAIN-ZK-NULLIFIER-GROTH16-BN254-V1";

/// The protocol version compiled into the nullifier circuit as a constant.
///
/// A verifying key produced by setup for this circuit only accepts proofs
/// of nullifiers derived with this version.
pub const NULLIFIER_GROTH16_PROTOCOL_VERSION: u16 = ZkStatementV1::PROTOCOL_VERSION;

/// Native Groth16 proof of the credential-secret/nullifier relation.
///
/// This deliberately carries no statement. Its public inputs are always
/// derived from the enclosing entry's `ZkStatementV1` (`deployment_id`,
/// `domain`, `nullifier`), so there is no second copy that could disagree
/// with the statement bound by the capability and the SP1 proof.
///
/// The proof only establishes knowledge of a credential secret for those
/// three values. It is NOT bound to the remaining statement fields
/// (`prover`, `statement_nonce`, issuer, epoch, program); those are bound by
/// the capability signature and the SP1 proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierGroth16ProofV1 {
    /// SHA-256 of the canonical compressed verifying key the proof claims to
    /// target. Untrusted: validation requires it to equal the DNA-pinned
    /// fingerprint, and verification always uses the DNA-pinned key.
    pub verifying_key_id: [u8; 32],

    /// `"ZKGP" || 0x01 || arkworks-compressed BN254 Groth16 proof`.
    pub proof: Vec<u8>,
}

/// Immutable V1 proof-bearing application entry.
///
/// The admission object is self-contained and carries the bounded
/// source-chain sequence window used by integrity validation.
///
/// The Groth16 proof bytes are opaque at the protocol layer; the
/// integrity-zome will later verify them against the pinned verifier
/// artifacts and the canonical statement public inputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, SerializedBytes)]
pub struct ZkProofEntryV1 {
    pub statement: ZkStatementV1,
    pub admission: AdmissionV1,
    pub groth16_proof: Vec<u8>,
}
