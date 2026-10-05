use hdi::prelude::*;
use zk_admission_protocol::{
    encoding::{
        encode_capability_identity, encode_delegation_identity, CAPABILITY_DOMAIN,
        DELEGATION_DOMAIN,
    },
    AdmissionConfigV1, AdmissionDelegationV1, AdmissionV1, ProtocolError,
};

fn protocol_error(err: ProtocolError) -> WasmError {
    wasm_error!(WasmErrorInner::Guest(err.to_string()))
}

fn admission_root_key(config: &AdmissionConfigV1) -> AgentPubKey {
    AgentPubKey::from_raw_32(config.admission_root_key.to_vec())
}

fn operational_key(delegation: &AdmissionDelegationV1) -> AgentPubKey {
    AgentPubKey::from_raw_32(delegation.op_public_key.to_vec())
}

pub fn verify_admission_signatures(
    admission: &AdmissionV1,
    config: &AdmissionConfigV1,
) -> ExternResult<()> {
    let delegation = &admission.delegation;
    let capability = &admission.capability;

    if delegation.root_key_id != config.admission_root_key_id {
        return Err(protocol_error(ProtocolError::InvalidKeyId));
    }

    let delegation_message = {
        let mut bytes = Vec::with_capacity(
            DELEGATION_DOMAIN.len() + encode_delegation_identity(delegation).len(),
        );
        bytes.extend_from_slice(DELEGATION_DOMAIN);
        bytes.extend_from_slice(&encode_delegation_identity(delegation));
        bytes
    };

    let root_signature = Signature::from(delegation.root_signature.0);

    let root_valid = verify_signature_raw(
        admission_root_key(config),
        root_signature,
        delegation_message,
    )?;

    if !root_valid {
        return Err(protocol_error(ProtocolError::InvalidSignature));
    }

    if capability.op_key_id != delegation.op_key_id {
        return Err(protocol_error(ProtocolError::InvalidKeyId));
    }

    let capability_message = {
        let mut bytes = Vec::with_capacity(
            CAPABILITY_DOMAIN.len() + encode_capability_identity(capability).len(),
        );
        bytes.extend_from_slice(CAPABILITY_DOMAIN);
        bytes.extend_from_slice(&encode_capability_identity(capability));
        bytes
    };

    let op_signature = Signature::from(capability.op_signature.0);

    let op_valid = verify_signature_raw(
        operational_key(delegation),
        op_signature,
        capability_message,
    )?;

    if !op_valid {
        return Err(protocol_error(ProtocolError::InvalidSignature));
    }

    Ok(())
}
