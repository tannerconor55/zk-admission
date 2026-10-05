use crate::{
    admission::{AdmissionCapabilityV1, AdmissionDelegationV1},
    error::ProtocolError,
    hashes::{capability_id, delegation_id},
};

pub fn recompute_delegation_id(delegation: &AdmissionDelegationV1) -> [u8; 32] {
    delegation_id(delegation)
}

pub fn verify_delegation_id(delegation: &AdmissionDelegationV1) -> Result<(), ProtocolError> {
    if recompute_delegation_id(delegation) == delegation.delegation_id {
        Ok(())
    } else {
        Err(ProtocolError::DelegationIdMismatch)
    }
}

pub fn recompute_capability_id(capability: &AdmissionCapabilityV1) -> [u8; 32] {
    capability_id(capability)
}

pub fn verify_capability_id(capability: &AdmissionCapabilityV1) -> Result<(), ProtocolError> {
    if recompute_capability_id(capability) == capability.capability_id {
        Ok(())
    } else {
        Err(ProtocolError::CapabilityIdMismatch)
    }
}
