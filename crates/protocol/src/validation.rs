use crate::{
    admission::AdmissionV1,
    capability::{verify_capability_id, verify_delegation_id},
    error::ProtocolError,
    hashes::statement_hash,
    sequence::SequenceWindowV1,
    statement::ZkStatementV1,
};

/// Inputs supplied by the Holochain validation layer.
///
/// Cryptographic signatures are deliberately handled separately until the
/// exact Ed25519 representation/implementation is frozen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionContextV1<'a> {
    pub deployment_id: &'a [u8; 32],
    pub author: &'a [u8],
    pub candidate_sequence: u32,
}

/// Validate all deterministic admission bindings.
///
/// This function does NOT:
/// - verify Ed25519 signatures;
/// - verify the SP1 proof;
/// - query Holochain activity;
/// - establish branch-local rate limits.
///
/// Those are separate validation layers.
pub fn validate_admission_bindings(
    statement: &ZkStatementV1,
    admission: &AdmissionV1,
    context: AdmissionContextV1<'_>,
) -> Result<(), ProtocolError> {
    if statement.protocol_version != ZkStatementV1::PROTOCOL_VERSION {
        return Err(ProtocolError::InvalidProtocolVersion);
    }

    if !statement.is_eligible() {
        return Err(ProtocolError::IneligibleStatement);
    }

    if statement.deployment_id != *context.deployment_id {
        return Err(ProtocolError::DeploymentMismatch);
    }

    if statement.prover.0.as_slice() != context.author {
        return Err(ProtocolError::ProverMismatch);
    }

    let capability = &admission.capability;
    let delegation = &admission.delegation;

    verify_delegation_id(delegation)?;
    verify_capability_id(capability)?;

    if capability.deployment_id != *context.deployment_id {
        return Err(ProtocolError::DeploymentMismatch);
    }

    if capability.prover.0.as_slice() != context.author {
        return Err(ProtocolError::ProverMismatch);
    }

    if capability.prover != statement.prover {
        return Err(ProtocolError::ProverMismatch);
    }

    if capability.delegation_id != delegation.delegation_id {
        return Err(ProtocolError::DelegationIdMismatch);
    }

    if capability.policy_id != delegation.policy_id {
        return Err(ProtocolError::DelegationIdMismatch);
    }

    if capability.statement_hash != statement_hash(statement) {
        return Err(ProtocolError::StatementHashMismatch);
    }

    if capability.statement_nonce != statement.statement_nonce {
        return Err(ProtocolError::CapabilityIdMismatch);
    }

    if capability.op_key_id != delegation.op_key_id {
        return Err(ProtocolError::InvalidKeyId);
    }

    if capability.admission_epoch < delegation.epoch_start
        || capability.admission_epoch > delegation.epoch_end
    {
        return Err(ProtocolError::AdmissionEpochOutOfRange);
    }

    if capability.resource_class >= 64 {
        return Err(ProtocolError::InvalidResourceClass);
    }

    let resource_bit = 1u64 << capability.resource_class;

    if delegation.allowed_resource_classes & resource_bit == 0 {
        return Err(ProtocolError::ResourceClassNotAuthorized);
    }

    let window = SequenceWindowV1::new(capability.seq_start, capability.seq_end_exclusive)?;

    if !window.contains(context.candidate_sequence) {
        return Err(ProtocolError::InvalidSequenceWindow);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        admission::{AdmissionCapabilityV1, AdmissionDelegationV1, AdmissionV1},
        statement::{ProverKeyV1, ZkStatementV1},
        types::SignatureV1,
    };

    fn statement() -> ZkStatementV1 {
        ZkStatementV1 {
            deployment_id: [1u8; 32],
            protocol_version: ZkStatementV1::PROTOCOL_VERSION,
            domain: [2u8; 32],
            program_id: [3u8; 32],
            prover: ProverKeyV1(vec![4, 5, 6]),
            issuer_id: [7u8; 32],
            issuer_key_id: [8u8; 32],
            credential_epoch: 42,
            statement_nonce: [9u8; 32],
            eligibility: true,
            nullifier: [10u8; 32],
        }
    }

    fn admission(statement: &ZkStatementV1) -> AdmissionV1 {
        let mut delegation = AdmissionDelegationV1 {
            root_key_id: [11u8; 32],
            op_key_id: [12u8; 32],
            op_public_key: [13u8; 32],
            policy_id: [14u8; 32],
            allowed_resource_classes: 1u64 << 3,
            epoch_start: 100,
            epoch_end: 200,
            delegation_id: [0u8; 32],
            root_signature: SignatureV1([16u8; 64]),
        };

        delegation.delegation_id = crate::hashes::delegation_id(&delegation);

        let mut capability = AdmissionCapabilityV1 {
            capability_id: [0u8; 32],
            delegation_id: delegation.delegation_id,
            deployment_id: statement.deployment_id,
            prover: statement.prover.clone(),
            policy_id: delegation.policy_id,
            statement_hash: crate::hashes::statement_hash(statement),
            statement_nonce: statement.statement_nonce,
            resource_class: 3,
            admission_epoch: 150,
            seq_start: 7,
            seq_end_exclusive: 10,
            op_key_id: delegation.op_key_id,
            op_signature: SignatureV1([18u8; 64]),
        };

        capability.capability_id = crate::hashes::capability_id(&capability);

        AdmissionV1 {
            delegation,
            capability,
        }
    }

    fn context<'a>(
        deployment_id: &'a [u8; 32],
        author: &'a [u8],
        sequence: u32,
    ) -> AdmissionContextV1<'a> {
        AdmissionContextV1 {
            deployment_id,
            author,
            candidate_sequence: sequence,
        }
    }

    #[test]
    fn valid_bindings_are_accepted() {
        let statement = statement();
        let admission = admission(&statement);

        let deployment = [1u8; 32];
        let author = [4u8, 5, 6];

        assert_eq!(
            validate_admission_bindings(&statement, &admission, context(&deployment, &author, 8),),
            Ok(())
        );
    }

    #[test]
    fn wrong_delegation_id_is_rejected() {
        let statement = statement();
        let mut admission = admission(&statement);
        admission.delegation.delegation_id[0] ^= 1;

        let deployment = [1u8; 32];
        let author = [4u8, 5, 6];

        assert_eq!(
            validate_admission_bindings(&statement, &admission, context(&deployment, &author, 8),),
            Err(ProtocolError::DelegationIdMismatch)
        );
    }

    #[test]
    fn wrong_capability_id_is_rejected() {
        let statement = statement();
        let mut admission = admission(&statement);
        admission.capability.capability_id[0] ^= 1;

        let deployment = [1u8; 32];
        let author = [4u8, 5, 6];

        assert_eq!(
            validate_admission_bindings(&statement, &admission, context(&deployment, &author, 8),),
            Err(ProtocolError::CapabilityIdMismatch)
        );
    }

    #[test]
    fn ineligible_statement_is_rejected() {
        let mut statement = statement();
        statement.eligibility = false;

        let admission = admission(&statement);

        let deployment = [1u8; 32];
        let author = [4u8, 5, 6];

        assert_eq!(
            validate_admission_bindings(&statement, &admission, context(&deployment, &author, 8),),
            Err(ProtocolError::IneligibleStatement)
        );
    }

    #[test]
    fn wrong_deployment_is_rejected() {
        let statement = statement();
        let admission = admission(&statement);

        let wrong_deployment = [99u8; 32];
        let author = [4u8, 5, 6];

        assert_eq!(
            validate_admission_bindings(
                &statement,
                &admission,
                context(&wrong_deployment, &author, 8),
            ),
            Err(ProtocolError::DeploymentMismatch)
        );
    }

    #[test]
    fn wrong_author_is_rejected() {
        let statement = statement();
        let admission = admission(&statement);

        let deployment = [1u8; 32];
        let wrong_author = [99u8, 98, 97];

        assert_eq!(
            validate_admission_bindings(
                &statement,
                &admission,
                context(&deployment, &wrong_author, 8),
            ),
            Err(ProtocolError::ProverMismatch)
        );
    }

    #[test]
    fn capability_statement_binding_is_required() {
        let statement = statement();
        let mut admission = admission(&statement);

        admission.capability.statement_nonce = [99u8; 32];

        let deployment = [1u8; 32];
        let author = [4u8, 5, 6];

        assert_eq!(
            validate_admission_bindings(&statement, &admission, context(&deployment, &author, 8),),
            Err(ProtocolError::CapabilityIdMismatch)
        );
    }

    #[test]
    fn unauthorized_resource_class_is_rejected() {
        let statement = statement();
        let mut admission = admission(&statement);

        admission.capability.resource_class = 4;
        admission.capability.capability_id = crate::hashes::capability_id(&admission.capability);

        let deployment = [1u8; 32];
        let author = [4u8, 5, 6];

        assert_eq!(
            validate_admission_bindings(&statement, &admission, context(&deployment, &author, 8),),
            Err(ProtocolError::ResourceClassNotAuthorized)
        );
    }

    #[test]
    fn resource_class_64_is_rejected_before_shift() {
        let statement = statement();
        let mut admission = admission(&statement);

        admission.capability.resource_class = 64;
        admission.capability.capability_id = crate::hashes::capability_id(&admission.capability);

        let deployment = [1u8; 32];
        let author = [4u8, 5, 6];

        assert_eq!(
            validate_admission_bindings(&statement, &admission, context(&deployment, &author, 8),),
            Err(ProtocolError::InvalidResourceClass)
        );
    }

    #[test]
    fn epoch_outside_delegation_is_rejected() {
        let statement = statement();
        let mut admission = admission(&statement);

        admission.capability.admission_epoch = 201;
        admission.capability.capability_id = crate::hashes::capability_id(&admission.capability);

        let deployment = [1u8; 32];
        let author = [4u8, 5, 6];

        assert_eq!(
            validate_admission_bindings(&statement, &admission, context(&deployment, &author, 8),),
            Err(ProtocolError::AdmissionEpochOutOfRange)
        );
    }

    #[test]
    fn sequence_before_window_is_rejected() {
        let statement = statement();
        let admission = admission(&statement);

        let deployment = [1u8; 32];
        let author = [4u8, 5, 6];

        assert_eq!(
            validate_admission_bindings(&statement, &admission, context(&deployment, &author, 6),),
            Err(ProtocolError::InvalidSequenceWindow)
        );
    }

    #[test]
    fn sequence_at_window_end_is_rejected() {
        let statement = statement();
        let admission = admission(&statement);

        let deployment = [1u8; 32];
        let author = [4u8, 5, 6];

        assert_eq!(
            validate_admission_bindings(&statement, &admission, context(&deployment, &author, 10),),
            Err(ProtocolError::InvalidSequenceWindow)
        );
    }

    #[test]
    fn oversized_window_is_rejected() {
        let statement = statement();
        let mut admission = admission(&statement);

        admission.capability.seq_start = 0;
        admission.capability.seq_end_exclusive = 1025;
        admission.capability.capability_id = crate::hashes::capability_id(&admission.capability);

        let deployment = [1u8; 32];
        let author = [4u8, 5, 6];

        assert_eq!(
            validate_admission_bindings(&statement, &admission, context(&deployment, &author, 10),),
            Err(ProtocolError::WindowTooLarge)
        );
    }
}
