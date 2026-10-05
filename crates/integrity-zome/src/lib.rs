#![forbid(unsafe_code)]

use hdi::prelude::*;

use zk_admission_protocol::{
    validation::{validate_admission_bindings, AdmissionContextV1},
    AdmissionConfigV1, SequenceWindowV1,
};

mod activity;
mod crypto;
mod sp1;

#[dna_properties]
pub struct DnaPropertiesV1 {
    pub admission_root_key: [u8; 32],
    pub admission_root_key_id: [u8; 32],
    pub issuer_root_key: [u8; 32],
    pub issuer_root_key_id: [u8; 32],
    pub sp1_program_vkey_hash: [u8; 32],
}

impl From<DnaPropertiesV1> for AdmissionConfigV1 {
    fn from(properties: DnaPropertiesV1) -> Self {
        Self {
            admission_root_key: properties.admission_root_key,
            admission_root_key_id: properties.admission_root_key_id,
            issuer_root_key: properties.issuer_root_key,
            issuer_root_key_id: properties.issuer_root_key_id,
            sp1_program_vkey_hash: properties.sp1_program_vkey_hash,
        }
    }
}

fn protocol_error(err: zk_admission_protocol::ProtocolError) -> WasmError {
    wasm_error!(WasmErrorInner::Guest(err.to_string()))
}

#[hdk_extern]
pub fn entry_defs(_: ()) -> ExternResult<EntryDefsCallbackResult> {
    Ok(vec![EntryDef {
        id: activity::PROOF_ENTRY_ID_V1.into(),
        visibility: EntryVisibility::Public,
        required_validations: RequiredValidations(5),
        cache_at_agent_activity: true,
    }]
    .into())
}

#[hdk_extern]
pub fn validate(op: Op) -> ExternResult<ValidateCallbackResult> {
    // Only Create actions can introduce a new proof entry.
    let candidate = match activity::create_action_from_op(&op) {
        Some(action) => action,
        None => return Ok(ValidateCallbackResult::Valid),
    };

    // Determine the exact proof entry type for this zome.
    let zome_index = zome_info()?.id;
    let proof_entry_type = activity::proof_entry_type_v1(zome_index);

    // A Create action that is not our zk_proof_v1 entry is outside
    // the proof-specific validation path.
    let proof =
        match activity::proof_entry_from_op(&op, proof_entry_type).map_err(protocol_error)? {
            Some(proof) => proof,
            None => return Ok(ValidateCallbackResult::Valid),
        };

    // The DNA hash is the authenticated deployment identity.
    let dna_hash = dna_info()?.hash;
    let deployment_id_bytes = dna_hash.get_raw_32();
    let deployment_id: &[u8; 32] = deployment_id_bytes.try_into().map_err(|_| {
        wasm_error!(WasmErrorInner::Guest(
            "DNA hash must be exactly 32 bytes".into()
        ))
    })?;

    // DNA properties are the authenticated trust configuration.
    let config: AdmissionConfigV1 = DnaPropertiesV1::try_from_dna_properties()?.into();

    // Deterministic statement/capability/delegation bindings.
    validate_admission_bindings(
        &proof.statement,
        &proof.admission,
        AdmissionContextV1 {
            deployment_id,
            author: candidate.author().get_raw_32(),
            candidate_sequence: candidate.action_seq(),
        },
    )
    .map_err(protocol_error)?;

    // Branch-local sequence and rate-limit validation.
    let capability = &proof.admission.capability;
    let window = SequenceWindowV1::new(capability.seq_start, capability.seq_end_exclusive)
        .map_err(protocol_error)?;

    activity::validate_prior_activity_from_chain(candidate, window, proof_entry_type)?;

    // Authenticate the admission delegation against the DNA-rooted key,
    // then authenticate the operational capability against the delegated key.
    crypto::verify_admission_signatures(&proof.admission, &config)?;

    // Verify the SP1 Groth16 proof against the canonical statement and
    // the SP1 program authenticated by DNA properties.
    sp1::verify_sp1_groth16(&proof, &config)?;

    Ok(ValidateCallbackResult::Valid)
}
