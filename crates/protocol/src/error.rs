use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ProtocolError {
    #[error("invalid protocol version")]
    InvalidProtocolVersion,

    #[error("statement eligibility must be true")]
    IneligibleStatement,

    #[error("invalid sequence window")]
    InvalidSequenceWindow,

    #[error("sequence arithmetic overflow or underflow")]
    SequenceArithmetic,

    #[error("sequence window exceeds WINDOW_MAX")]
    WindowTooLarge,

    #[error("resource class must be less than 64")]
    InvalidResourceClass,

    #[error("resource class is not authorized")]
    ResourceClassNotAuthorized,

    #[error("admission epoch is outside delegation range")]
    AdmissionEpochOutOfRange,

    #[error("deployment binding mismatch")]
    DeploymentMismatch,

    #[error("prover binding mismatch")]
    ProverMismatch,

    #[error("SP1 program verifying-key hash mismatch")]
    Sp1ProgramVkeyMismatch,

    #[error("invalid SP1 Groth16 proof encoding")]
    InvalidSp1Groth16Proof,

    #[error("SP1 Groth16 verification failed")]
    Sp1Groth16VerificationFailed,

    #[error("invalid native nullifier Groth16 proof encoding")]
    InvalidNullifierProof,

    #[error("native nullifier verifying-key fingerprint mismatch")]
    NullifierVerifyingKeyMismatch,

    #[error("invalid pinned native nullifier verifying key")]
    InvalidNullifierVerifyingKey,

    #[error("native nullifier Groth16 verification failed")]
    NullifierProofVerificationFailed,

    #[error("statement hash mismatch")]
    StatementHashMismatch,

    #[error("delegation id mismatch")]
    DelegationIdMismatch,

    #[error("capability id mismatch")]
    CapabilityIdMismatch,

    #[error("invalid key id")]
    InvalidKeyId,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("canonical encoding error")]
    CanonicalEncoding,

    #[error("required source-chain activity is unresolved or incomplete")]
    UnresolvedDependencies,

    #[error("source-chain activity author mismatch")]
    ActivityAuthorMismatch,

    #[error("source-chain activity sequence mismatch")]
    ActivitySequenceMismatch,

    #[error("source-chain activity branch mismatch")]
    ActivityBranchMismatch,

    #[error("a prior proof-bearing action exists in the required branch")]
    PriorProofAction,
}
