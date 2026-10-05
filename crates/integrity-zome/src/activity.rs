use hdi::prelude::*;

use zk_admission_protocol::{error::ProtocolError, sequence::SequenceWindowV1, ZkProofEntryV1};

/// Configuration identifying the exact V1 proof entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofEntryTypeV1 {
    pub zome_index: ZomeIndex,
    pub entry_index: EntryDefIndex,
}

/// Stable entry-definition ID for the V1 proof entry.
pub const PROOF_ENTRY_ID_V1: &str = "zk_proof_v1";

/// Construct the exact V1 proof entry type for this integrity zome.
pub fn proof_entry_type_v1(zome_index: ZomeIndex) -> ProofEntryTypeV1 {
    ProofEntryTypeV1 {
        zome_index,
        entry_index: EntryDefIndex(0),
    }
}

/// Validate the branch-local source-chain activity required by the
/// admission sequence window.
pub fn validate_prior_activity_v1(
    candidate: &Action,
    window: SequenceWindowV1,
    prior_activity: &[AgentActivity],
    proof_entry_type: ProofEntryTypeV1,
) -> Result<(), ProtocolError> {
    let candidate_seq = candidate.action_seq();

    if !window.contains(candidate_seq) {
        return Err(ProtocolError::InvalidSequenceWindow);
    }

    let prior_len = window.prior_len(candidate_seq)?;

    if prior_len == 0 {
        if !prior_activity.is_empty() {
            return Err(ProtocolError::InvalidSequenceWindow);
        }
        return Ok(());
    }

    if prior_activity.len() != prior_len as usize {
        return Err(ProtocolError::UnresolvedDependencies);
    }

    let candidate_prev = candidate
        .prev_action()
        .ok_or(ProtocolError::InvalidSequenceWindow)?;

    for (index, activity) in prior_activity.iter().enumerate() {
        let action = &activity.action.hashed.content;

        let expected_seq = candidate_seq
            .checked_sub(index as u32 + 1)
            .ok_or(ProtocolError::SequenceArithmetic)?;

        // I31: every historical action belongs to the same agent.
        if action.author() != candidate.author() {
            return Err(ProtocolError::ActivityAuthorMismatch);
        }

        // I32: exact descending sequence.
        if action.action_seq() != expected_seq {
            return Err(ProtocolError::ActivitySequenceMismatch);
        }

        // I30 / I33: verify explicit chain continuity backwards in time.
        if index == 0 {
            // The first returned item must be the candidate's predecessor.
            if activity.action.as_hash() != candidate_prev {
                return Err(ProtocolError::ActivityBranchMismatch);
            }
        } else {
            // The newer action must point to this older action.
            let newer_action = &prior_activity[index - 1].action.hashed.content;
            let expected_prev_hash = activity.action.as_hash();

            if newer_action.prev_action() != Some(&expected_prev_hash) {
                return Err(ProtocolError::ActivityBranchMismatch);
            }
        }

        // I35: no prior proof-bearing action may exist in the
        // required branch-local history.
        if is_proof_create_v1(action, proof_entry_type) {
            return Err(ProtocolError::PriorProofAction);
        }
    }

    // The final returned action must be exactly the start of the
    // configured sequence window.
    let final_action = &prior_activity[prior_activity.len() - 1]
        .action
        .hashed
        .content;

    if final_action.action_seq() != window.seq_start {
        return Err(ProtocolError::ActivitySequenceMismatch);
    }

    Ok(())
}

/// Return true only for an immutable V1 proof-bearing Create action.
///
/// The explicit ActionData::Create match is intentional: I35/I43 require
/// that only an exact Create action for the configured proof entry counts.
/// An Update or another action carrying an entry type must not be treated
/// as a prior proof action.
fn is_proof_create_v1(action: &Action, proof_entry_type: ProofEntryTypeV1) -> bool {
    match &action.data {
        ActionData::Create(create) => match &create.entry_type {
            EntryType::App(app) => {
                app.zome_index == proof_entry_type.zome_index
                    && app.entry_index == proof_entry_type.entry_index
            }
            _ => false,
        },
        _ => false,
    }
}

/// Fetch and validate the branch-local activity immediately preceding
/// the candidate action.
///
/// The caller must supply the admission-derived sequence window.
/// A zero-length predecessor range is handled without calling
/// ChainFilter::take(0), which is invalid in pinned HDI 0.8.0.
pub fn validate_prior_activity_from_chain(
    candidate: &Action,
    window: SequenceWindowV1,
    proof_entry_type: ProofEntryTypeV1,
) -> ExternResult<()> {
    let prior_len = window
        .prior_len(candidate.action_seq())
        .map_err(|err| wasm_error!(WasmErrorInner::Guest(err.to_string())))?;

    if prior_len == 0 {
        return validate_prior_activity_v1(candidate, window, &[], proof_entry_type)
            .map_err(|err| wasm_error!(WasmErrorInner::Guest(err.to_string())));
    }

    let candidate_prev = candidate.prev_action().ok_or_else(|| {
        wasm_error!(WasmErrorInner::Guest(
            "candidate action is missing prev_action".to_string(),
        ))
    })?;

    let prior_activity = must_get_agent_activity(
        candidate.author().clone(),
        ChainFilter::take(candidate_prev.clone(), prior_len),
    )?;

    validate_prior_activity_v1(candidate, window, &prior_activity, proof_entry_type)
        .map_err(|err| wasm_error!(WasmErrorInner::Guest(err.to_string())))
}

/// Extract the action from an op when it is an immutable Create action.
///
/// Updates and all non-entry action types return `None`.
pub fn create_action_from_op<'a>(op: &'a Op) -> Option<&'a Action> {
    let action = match op {
        Op::CreateRecord(record) => &record.record.signed_action.hashed.content,
        Op::CreateEntry(create_entry) => &create_entry.action.hashed.content,
        Op::AgentActivity(activity) => &activity.action.hashed.content,
        Op::Update(_) | Op::Delete(_) | Op::CreateLink(_) | Op::DeleteLink(_) => return None,
    };

    match &action.data {
        ActionData::Create(_) => Some(action),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk_admission_protocol::{
        AdmissionCapabilityV1, AdmissionDelegationV1, AdmissionV1, ProverKeyV1, SignatureV1,
        ZkStatementV1,
    };

    fn agent(byte: u8) -> AgentPubKey {
        let mut raw = vec![0u8; 39];
        raw[0..3].copy_from_slice(&[0x84, 0x20, 0x24]);
        raw[3..].fill(byte);
        AgentPubKey::from_raw_39(raw)
    }

    fn action_hash(byte: u8) -> ActionHash {
        ActionHash::from_raw_36(vec![byte; 36])
    }

    fn entry_hash(byte: u8) -> EntryHash {
        EntryHash::from_raw_36(vec![byte; 36])
    }

    fn action(
        author: AgentPubKey,
        seq: u32,
        prev_action: Option<ActionHash>,
        proof_create: bool,
    ) -> SignedHashed<Action> {
        let entry_type = if proof_create {
            EntryType::App(AppEntryDef::new(
                EntryDefIndex(0),
                ZomeIndex(0),
                EntryVisibility::Public,
            ))
        } else {
            EntryType::App(AppEntryDef::new(
                EntryDefIndex(1),
                ZomeIndex(0),
                EntryVisibility::Public,
            ))
        };

        let content = Action {
            header: ActionHeader {
                author,
                timestamp: Timestamp(seq as i64),
                action_seq: seq,
                prev_action,
            },
            data: ActionData::Create(CreateData {
                entry_type,
                entry_hash: entry_hash(seq as u8),
            }),
        };

        SignedHashed::with_presigned(
            HoloHashed::from_content_sync(content),
            Signature([0u8; SIGNATURE_BYTES]),
        )
    }

    fn activity(action: SignedHashed<Action>) -> AgentActivity {
        AgentActivity {
            action,
            cached_entry: None,
        }
    }

    fn window(start: u32, end: u32) -> SequenceWindowV1 {
        SequenceWindowV1::new(start, end).unwrap()
    }

    fn proof_entry() -> ZkProofEntryV1 {
        ZkProofEntryV1 {
            statement: ZkStatementV1 {
                deployment_id: [1u8; 32],
                protocol_version: ZkStatementV1::PROTOCOL_VERSION,
                domain: [2u8; 32],
                program_id: [3u8; 32],
                prover: ProverKeyV1(vec![4u8; 32]),
                issuer_id: [5u8; 32],
                issuer_key_id: [6u8; 32],
                credential_epoch: 7,
                statement_nonce: [8u8; 32],
                eligibility: true,
                nullifier: [9u8; 32],
            },
            admission: AdmissionV1 {
                delegation: AdmissionDelegationV1 {
                    root_key_id: [10u8; 32],
                    op_key_id: [11u8; 32],
                    op_public_key: [12u8; 32],
                    policy_id: [13u8; 32],
                    allowed_resource_classes: 1,
                    epoch_start: 1,
                    epoch_end: 10,
                    delegation_id: [14u8; 32],
                    root_signature: SignatureV1([15u8; 64]),
                },
                capability: AdmissionCapabilityV1 {
                    capability_id: [16u8; 32],
                    delegation_id: [14u8; 32],
                    deployment_id: [1u8; 32],
                    prover: ProverKeyV1(vec![4u8; 32]),
                    policy_id: [13u8; 32],
                    statement_hash: [17u8; 32],
                    statement_nonce: [8u8; 32],
                    resource_class: 0,
                    admission_epoch: 2,
                    seq_start: 7,
                    seq_end_exclusive: 9,
                    op_key_id: [11u8; 32],
                    op_signature: SignatureV1([18u8; 64]),
                },
            },
            groth16_proof: vec![19u8; 32],
        }
    }

    fn proof_entry_bytes(entry: &ZkProofEntryV1) -> Entry {
        let serialized =
            holochain_serialized_bytes::prelude::SerializedBytes::try_from(entry).unwrap();

        Entry::App(AppEntryBytes::try_from(serialized).unwrap())
    }

    fn proof_entry_action(author: AgentPubKey) -> SignedHashed<Action> {
        action(author, 7, Some(action_hash(6)), true)
    }

    #[test]
    fn proof_entry_from_create_record_decodes_v1() {
        let author = agent(1);
        let signed_action = proof_entry_action(author);
        let entry = proof_entry_bytes(&proof_entry());

        let record = Record::new(signed_action, RecordEntry::Present(entry));

        let op = Op::CreateRecord(CreateRecord { record });

        assert_eq!(
            proof_entry_from_op(&op, proof_entry_type_v1(ZomeIndex(0))),
            Ok(Some(proof_entry()))
        );
    }

    #[test]
    fn proof_entry_from_create_entry_decodes_v1() {
        let author = agent(1);
        let signed_action = proof_entry_action(author);
        let entry = proof_entry_bytes(&proof_entry());

        let op = Op::CreateEntry(CreateEntry {
            action: signed_action,
            entry,
        });

        assert_eq!(
            proof_entry_from_op(&op, proof_entry_type_v1(ZomeIndex(0))),
            Ok(Some(proof_entry()))
        );
    }

    #[test]
    fn proof_entry_from_agent_activity_without_cached_entry_is_none() {
        let signed_action = proof_entry_action(agent(1));
        let op = Op::AgentActivity(AgentActivity {
            action: signed_action,
            cached_entry: None,
        });

        assert_eq!(
            proof_entry_from_op(&op, proof_entry_type_v1(ZomeIndex(0))),
            Ok(None)
        );
    }

    #[test]
    fn proof_entry_from_wrong_entry_type_is_none() {
        let signed_action = action(agent(1), 7, Some(action_hash(6)), false);
        let entry = proof_entry_bytes(&proof_entry());

        let op = Op::CreateEntry(CreateEntry {
            action: signed_action,
            entry,
        });

        assert_eq!(
            proof_entry_from_op(&op, proof_entry_type_v1(ZomeIndex(0))),
            Ok(None)
        );
    }

    #[test]
    fn proof_entry_from_malformed_matching_entry_is_canonical_encoding_error() {
        let signed_action = proof_entry_action(agent(1));

        let malformed = Entry::App(
            AppEntryBytes::try_from(holochain_serialized_bytes::prelude::SerializedBytes::from(
                holochain_serialized_bytes::prelude::UnsafeBytes::from(vec![
                    0xde, 0xad, 0xbe, 0xef,
                ]),
            ))
            .unwrap(),
        );

        let op = Op::CreateEntry(CreateEntry {
            action: signed_action,
            entry: malformed,
        });

        assert_eq!(
            proof_entry_from_op(&op, proof_entry_type_v1(ZomeIndex(0))),
            Err(ProtocolError::CanonicalEncoding)
        );
    }

    #[test]
    fn proof_entry_from_non_create_is_none() {
        let author = agent(1);

        let update_action = Action {
            header: ActionHeader {
                author,
                timestamp: Timestamp(7),
                action_seq: 7,
                prev_action: Some(action_hash(6)),
            },
            data: ActionData::Update(UpdateData {
                original_action_address: action_hash(5),
                original_entry_address: entry_hash(5),
                entry_hash: entry_hash(7),
                entry_type: EntryType::App(AppEntryDef::new(
                    EntryDefIndex(0),
                    ZomeIndex(0),
                    EntryVisibility::Public,
                )),
            }),
        };

        let signed_action = SignedHashed::with_presigned(
            HoloHashed::from_content_sync(update_action),
            Signature([0u8; SIGNATURE_BYTES]),
        );

        let op = Op::AgentActivity(AgentActivity {
            action: signed_action,
            cached_entry: Some(proof_entry_bytes(&proof_entry())),
        });

        assert_eq!(
            proof_entry_from_op(&op, proof_entry_type_v1(ZomeIndex(0))),
            Ok(None)
        );
    }

    #[test]
    fn prior_len_zero_accepts_empty_activity() {
        let author = agent(1);
        let candidate = action(author.clone(), 7, Some(action_hash(6)), false);

        let result = validate_prior_activity_v1(
            &candidate.hashed.content,
            window(7, 8),
            &[],
            proof_entry_type_v1(ZomeIndex(0)),
        );

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn prior_len_zero_rejects_unexpected_activity() {
        let author = agent(1);
        let candidate = action(author.clone(), 7, Some(action_hash(6)), false);
        let unexpected = activity(action(author, 6, None, false));

        let result = validate_prior_activity_v1(
            &candidate.hashed.content,
            window(7, 8),
            &[unexpected],
            proof_entry_type_v1(ZomeIndex(0)),
        );

        assert_eq!(result, Err(ProtocolError::InvalidSequenceWindow));
    }

    #[test]
    fn complete_history_is_required() {
        let author = agent(1);
        let first = action(author.clone(), 7, Some(action_hash(6)), false);
        let second = action(author.clone(), 8, Some(first.as_hash().clone()), false);
        let candidate = action(author.clone(), 9, Some(second.as_hash().clone()), false);

        let history = vec![activity(second), activity(first)];

        assert_eq!(
            validate_prior_activity_v1(
                &candidate.hashed.content,
                window(7, 10),
                &history,
                proof_entry_type_v1(ZomeIndex(0)),
            ),
            Ok(())
        );
    }

    #[test]
    fn incomplete_history_is_unresolved() {
        let author = agent(1);
        let first = action(author.clone(), 7, Some(action_hash(6)), false);
        let candidate = action(author.clone(), 9, Some(action_hash(8)), false);

        let history = vec![activity(first)];

        assert_eq!(
            validate_prior_activity_v1(
                &candidate.hashed.content,
                window(7, 10),
                &history,
                proof_entry_type_v1(ZomeIndex(0)),
            ),
            Err(ProtocolError::UnresolvedDependencies)
        );
    }

    #[test]
    fn wrong_author_is_rejected() {
        let candidate_author = agent(1);
        let other_author = agent(2);

        let prior = action(other_author, 7, Some(action_hash(6)), false);
        let candidate = action(candidate_author, 8, Some(prior.as_hash().clone()), false);

        assert_eq!(
            validate_prior_activity_v1(
                &candidate.hashed.content,
                window(7, 9),
                &[activity(prior)],
                proof_entry_type_v1(ZomeIndex(0)),
            ),
            Err(ProtocolError::ActivityAuthorMismatch)
        );
    }

    #[test]
    fn wrong_sequence_is_rejected() {
        let author = agent(1);
        let prior = action(author.clone(), 6, Some(action_hash(5)), false);
        let candidate = action(author, 8, Some(prior.as_hash().clone()), false);

        assert_eq!(
            validate_prior_activity_v1(
                &candidate.hashed.content,
                window(7, 9),
                &[activity(prior)],
                proof_entry_type_v1(ZomeIndex(0)),
            ),
            Err(ProtocolError::ActivitySequenceMismatch)
        );
    }

    #[test]
    fn candidate_predecessor_must_match() {
        let author = agent(1);
        let prior = action(author.clone(), 7, Some(action_hash(6)), false);
        let candidate = action(author, 8, Some(action_hash(99)), false);

        assert_eq!(
            validate_prior_activity_v1(
                &candidate.hashed.content,
                window(7, 9),
                &[activity(prior)],
                proof_entry_type_v1(ZomeIndex(0)),
            ),
            Err(ProtocolError::ActivityBranchMismatch)
        );
    }

    #[test]
    fn historical_prev_action_must_match() {
        let author = agent(1);
        let first = action(author.clone(), 7, Some(action_hash(6)), false);
        let second = action(author.clone(), 8, Some(action_hash(99)), false);
        let candidate = action(author, 9, Some(second.as_hash().clone()), false);

        assert_eq!(
            validate_prior_activity_v1(
                &candidate.hashed.content,
                window(7, 10),
                &[activity(second), activity(first)],
                proof_entry_type_v1(ZomeIndex(0)),
            ),
            Err(ProtocolError::ActivityBranchMismatch)
        );
    }

    #[test]
    fn prior_proof_create_is_rejected() {
        let author = agent(1);
        let prior = action(author.clone(), 7, Some(action_hash(6)), true);
        let candidate = action(author, 8, Some(prior.as_hash().clone()), false);

        assert_eq!(
            validate_prior_activity_v1(
                &candidate.hashed.content,
                window(7, 9),
                &[activity(prior)],
                proof_entry_type_v1(ZomeIndex(0)),
            ),
            Err(ProtocolError::PriorProofAction)
        );
    }

    #[test]
    fn non_create_same_entry_type_is_not_prior_proof() {
        let author = agent(1);

        let update_action = Action {
            header: ActionHeader {
                author: author.clone(),
                timestamp: Timestamp(7),
                action_seq: 7,
                prev_action: Some(action_hash(6)),
            },
            data: ActionData::Update(UpdateData {
                original_action_address: action_hash(5),
                original_entry_address: entry_hash(5),
                entry_hash: EntryHash::from_raw_36(vec![7u8; 36]),
                entry_type: EntryType::App(AppEntryDef::new(
                    EntryDefIndex(0),
                    ZomeIndex(0),
                    EntryVisibility::Public,
                )),
            }),
        };

        let prior = SignedHashed::with_presigned(
            HoloHashed::from_content_sync(update_action),
            Signature([0u8; SIGNATURE_BYTES]),
        );

        let candidate = action(author, 8, Some(prior.as_hash().clone()), false);

        assert_eq!(
            validate_prior_activity_v1(
                &candidate.hashed.content,
                window(7, 9),
                &[activity(prior)],
                proof_entry_type_v1(ZomeIndex(0)),
            ),
            Ok(())
        );
    }

    #[test]
    fn sibling_branch_is_rejected() {
        let author = agent(1);

        let branch_a = action(author.clone(), 7, Some(action_hash(6)), false);

        let branch_b = action(author.clone(), 7, Some(action_hash(66)), false);

        let candidate = action(author, 8, Some(branch_b.as_hash().clone()), false);

        assert_eq!(
            validate_prior_activity_v1(
                &candidate.hashed.content,
                window(7, 9),
                &[activity(branch_a)],
                proof_entry_type_v1(ZomeIndex(0)),
            ),
            Err(ProtocolError::ActivityBranchMismatch)
        );
    }
}

/// Extract the V1 proof entry payload from an op when the op carries
/// the actual immutable Create entry.
///
/// No DHT lookup is performed here. Historical classification must use
/// only entry bytes already supplied by the validation operation/activity.
pub fn proof_entry_from_op(
    op: &Op,
    proof_entry_type: ProofEntryTypeV1,
) -> Result<Option<ZkProofEntryV1>, ProtocolError> {
    let (action, entry) = match op {
        Op::CreateRecord(record) => (
            &record.record.signed_action.hashed.content,
            record
                .record
                .entry
                .as_option()
                .ok_or(ProtocolError::CanonicalEncoding)?,
        ),

        Op::CreateEntry(create_entry) => (&create_entry.action.hashed.content, &create_entry.entry),

        Op::AgentActivity(activity) => {
            let entry = match activity.cached_entry.as_ref() {
                Some(entry) => entry,
                None => return Ok(None),
            };

            (&activity.action.hashed.content, entry)
        }

        Op::Update(_) | Op::Delete(_) | Op::CreateLink(_) | Op::DeleteLink(_) => return Ok(None),
    };

    let create = match &action.data {
        ActionData::Create(create) => create,
        _ => return Ok(None),
    };

    let entry_type_matches = match &create.entry_type {
        EntryType::App(app) => {
            app.zome_index == proof_entry_type.zome_index
                && app.entry_index == proof_entry_type.entry_index
        }
        _ => false,
    };

    if !entry_type_matches {
        return Ok(None);
    }

    let app_entry = entry
        .as_app_entry()
        .ok_or(ProtocolError::CanonicalEncoding)?;

    ZkProofEntryV1::try_from(app_entry.as_ref().clone())
        .map(Some)
        .map_err(|_| ProtocolError::CanonicalEncoding)
}
