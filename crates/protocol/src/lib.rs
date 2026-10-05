#![forbid(unsafe_code)]

pub mod admission;
pub mod capability;
pub mod encoding;
pub mod error;
pub mod hashes;
pub mod proof;
pub mod sequence;
pub mod statement;
pub mod types;
pub mod validation;

pub use admission::{AdmissionCapabilityV1, AdmissionConfigV1, AdmissionDelegationV1, AdmissionV1};

pub use error::ProtocolError;

pub use sequence::{SequenceWindowV1, WINDOW_MAX};

pub use statement::{ProverKeyV1, ZkStatementV1};

pub use types::SignatureV1;

pub use capability::{
    recompute_capability_id, recompute_delegation_id, verify_capability_id, verify_delegation_id,
};
pub use validation::{validate_admission_bindings, AdmissionContextV1};

pub use proof::{
    NullifierGroth16ProofV1, ZkProofEntryV1, NULLIFIER_GROTH16_CIRCUIT_ID_V1,
    NULLIFIER_GROTH16_PROTOCOL_VERSION,
};
