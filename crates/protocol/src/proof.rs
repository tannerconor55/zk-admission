use holochain_serialized_bytes::prelude::SerializedBytes;
use serde::{Deserialize, Serialize};

use crate::{admission::AdmissionV1, statement::ZkStatementV1};

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
