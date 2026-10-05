//! Negative tests for the native nullifier Groth16 verifier, using real
//! proofs from the real circuit.
//!
//! Every rejection below is of a proof that is structurally well-formed
//! (valid curve points, canonical encoding) unless the test is explicitly
//! about encoding, so these show the verifier checks the relation rather
//! than merely the proof's shape.

use std::sync::OnceLock;

use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::rngs::OsRng;
use zk_admission_groth16_circuit::{
    prove, serialize_proof, serialize_verifying_key, setup, verifying_key_fingerprint,
    Groth16Proof, Groth16ProvingKey, Groth16VerifyingKey, NullifierCircuit, NullifierPublicInputs,
};
use zk_admission_groth16_verifier::{
    statement_public_inputs, verify_statement_nullifier_proof, verifying_key_bytes_fingerprint,
    PinnedNullifierVerifyingKey,
};
use zk_admission_protocol::{
    hashes::nullifier, NullifierGroth16ProofV1, ProtocolError, ProverKeyV1, ZkStatementV1,
};

const V1: u16 = ZkStatementV1::PROTOCOL_VERSION;
const SECRET: [u8; 32] = [0x11; 32];
const OTHER_SECRET: [u8; 32] = [0x12; 32];
const DEPLOYMENT_A: [u8; 32] = [0x22; 32];
const DEPLOYMENT_B: [u8; 32] = [0x44; 32];
const DOMAIN: [u8; 32] = [0x33; 32];
const OTHER_DOMAIN: [u8; 32] = [0x55; 32];

struct Keys {
    proving_key: Groth16ProvingKey,
    verifying_key: Groth16VerifyingKey,
    verifying_key_bytes: Vec<u8>,
    fingerprint: [u8; 32],
}

impl Keys {
    fn generate(protocol_version: u16) -> Self {
        let (proving_key, verifying_key) = setup(protocol_version).unwrap();
        let verifying_key_bytes = serialize_verifying_key(&verifying_key).unwrap();
        let fingerprint = verifying_key_fingerprint(&verifying_key).unwrap();

        Self {
            proving_key,
            verifying_key,
            verifying_key_bytes,
            fingerprint,
        }
    }

    fn pinned(&self) -> PinnedNullifierVerifyingKey {
        PinnedNullifierVerifyingKey::from_config(&self.verifying_key_bytes, &self.fingerprint)
            .unwrap()
    }

    fn prove(&self, secret: [u8; 32], statement: &ZkStatementV1) -> NullifierGroth16ProofV1 {
        let proof = prove(
            &self.proving_key,
            secret,
            statement_public_inputs(statement),
            V1,
        )
        .unwrap();

        self.wire(&proof)
    }

    fn wire(&self, proof: &Groth16Proof) -> NullifierGroth16ProofV1 {
        NullifierGroth16ProofV1 {
            verifying_key_id: self.fingerprint,
            proof: serialize_proof(proof).unwrap(),
        }
    }
}

/// The deployment's pinned V1 key.
fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| Keys::generate(V1))
}

/// An independent V1 setup (a different deployment's or attacker's key).
fn other_keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| Keys::generate(V1))
}

/// A setup whose circuit constant is protocol version 2.
fn v2_keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| Keys::generate(2))
}

fn statement_for(secret: &[u8; 32], deployment_id: [u8; 32], domain: [u8; 32]) -> ZkStatementV1 {
    ZkStatementV1 {
        deployment_id,
        protocol_version: V1,
        domain,
        program_id: [3; 32],
        prover: ProverKeyV1(vec![4, 5, 6]),
        issuer_id: [7; 32],
        issuer_key_id: [8; 32],
        credential_epoch: 42,
        statement_nonce: [9; 32],
        eligibility: true,
        nullifier: nullifier(secret, &deployment_id, &domain, V1),
    }
}

fn statement() -> ZkStatementV1 {
    statement_for(&SECRET, DEPLOYMENT_A, DOMAIN)
}

fn valid_proof() -> &'static NullifierGroth16ProofV1 {
    static PROOF: OnceLock<NullifierGroth16ProofV1> = OnceLock::new();
    PROOF.get_or_init(|| keys().prove(SECRET, &statement()))
}

fn verify(statement: &ZkStatementV1, proof: &NullifierGroth16ProofV1) -> Result<(), ProtocolError> {
    verify_statement_nullifier_proof(&keys().pinned(), statement, proof)
}

/// Prove an arbitrary (possibly unsatisfied) assignment, bypassing the
/// `prove()` pre-check. Arkworks does not check satisfiability, so this is
/// how a cheating prover would produce a well-formed but false proof.
fn forced_proof(
    keys: &Keys,
    secret: [u8; 32],
    public: &NullifierPublicInputs,
    protocol_version: u16,
) -> NullifierGroth16ProofV1 {
    let proof = Groth16::<Bn254>::prove(
        &keys.proving_key,
        NullifierCircuit {
            credential_secret: secret,
            deployment_id: public.deployment_id,
            domain: public.domain,
            protocol_version,
            expected_nullifier: public.expected_nullifier,
        },
        &mut OsRng,
    )
    .unwrap();

    keys.wire(&proof)
}

const FAILED: Result<(), ProtocolError> = Err(ProtocolError::NullifierProofVerificationFailed);

#[test]
fn valid_proof_verifies() {
    assert_eq!(verify(&statement(), valid_proof()), Ok(()));
    assert_eq!(valid_proof().proof.len(), 133);
}

#[test]
fn proof_survives_entry_serialization() {
    let bytes = holochain_serialized_bytes::encode(valid_proof()).unwrap();
    let decoded: NullifierGroth16ProofV1 = holochain_serialized_bytes::decode(&bytes).unwrap();

    assert_eq!(&decoded, valid_proof());
    assert_eq!(verify(&statement(), &decoded), Ok(()));
}

// --- credential secret -------------------------------------------------

#[test]
fn prover_refuses_wrong_credential_secret() {
    let err = prove(
        &keys().proving_key,
        OTHER_SECRET,
        statement_public_inputs(&statement()),
        V1,
    )
    .unwrap_err();

    assert!(err.contains("does not match credential secret"));
}

#[test]
fn forced_proof_with_wrong_credential_secret_is_rejected() {
    let statement = statement();
    let proof = forced_proof(
        keys(),
        OTHER_SECRET,
        &statement_public_inputs(&statement),
        V1,
    );

    assert_eq!(verify(&statement, &proof), FAILED);
}

// --- public inputs -----------------------------------------------------

#[test]
fn changed_deployment_id_is_rejected() {
    let mut statement = statement();
    statement.deployment_id = DEPLOYMENT_B;

    assert_eq!(verify(&statement, valid_proof()), FAILED);
}

#[test]
fn changed_domain_is_rejected() {
    let mut statement = statement();
    statement.domain = OTHER_DOMAIN;

    assert_eq!(verify(&statement, valid_proof()), FAILED);
}

#[test]
fn changed_nullifier_is_rejected() {
    let mut statement = statement();
    statement.nullifier[31] ^= 1;

    assert_eq!(verify(&statement, valid_proof()), FAILED);
}

#[test]
fn every_single_bit_of_every_public_input_is_bound() {
    let base = statement();

    for byte in 0..32 {
        for bit in 0..8 {
            let mask = 1u8 << bit;

            let mut s = base.clone();
            s.deployment_id[byte] ^= mask;
            assert_eq!(verify(&s, valid_proof()), FAILED, "deployment {byte}:{bit}");

            let mut s = base.clone();
            s.domain[byte] ^= mask;
            assert_eq!(verify(&s, valid_proof()), FAILED, "domain {byte}:{bit}");

            let mut s = base.clone();
            s.nullifier[byte] ^= mask;
            assert_eq!(verify(&s, valid_proof()), FAILED, "nullifier {byte}:{bit}");
        }
    }
}

#[test]
fn mismatched_public_input_order_is_rejected() {
    // Same three values, deployment and domain swapped.
    let mut swapped = statement();
    swapped.deployment_id = DOMAIN;
    swapped.domain = DEPLOYMENT_A;

    assert_eq!(verify(&swapped, valid_proof()), FAILED);
}

#[test]
fn proof_for_one_statement_is_rejected_for_another_consistent_statement() {
    // The second statement is fully self-consistent: its nullifier is the
    // correct HMAC of the same secret for its own domain. Only the proof
    // belongs to the first statement.
    let other = statement_for(&SECRET, DEPLOYMENT_A, OTHER_DOMAIN);

    assert_eq!(verify(&other, valid_proof()), FAILED);
    assert_eq!(verify(&other, &keys().prove(SECRET, &other)), Ok(()));
}

#[test]
fn proof_from_a_different_deployment_is_rejected() {
    let deployment_b = statement_for(&SECRET, DEPLOYMENT_B, DOMAIN);

    assert_eq!(verify(&deployment_b, valid_proof()), FAILED);
}

#[test]
fn statement_fields_outside_the_circuit_are_not_bound_by_this_proof() {
    // Documents the scope of the native proof: prover/nonce/issuer/epoch/
    // program are bound by the capability signature and SP1, not here.
    let mut statement = statement();
    statement.prover = ProverKeyV1(vec![0xee; 32]);
    statement.statement_nonce = [0xee; 32];
    statement.issuer_id = [0xee; 32];
    statement.credential_epoch += 1;
    statement.program_id = [0xee; 32];

    assert_eq!(verify(&statement, valid_proof()), Ok(()));
}

// --- protocol version --------------------------------------------------

#[test]
fn statement_protocol_version_must_match_circuit_constant() {
    let mut statement = statement();
    statement.protocol_version = 2;

    assert_eq!(
        verify(&statement, valid_proof()),
        Err(ProtocolError::InvalidProtocolVersion)
    );
}

#[test]
fn version_2_nullifier_cannot_be_proven_under_version_1_key() {
    let mut statement = statement();
    statement.nullifier = nullifier(&SECRET, &DEPLOYMENT_A, &DOMAIN, 2);
    let public = statement_public_inputs(&statement);

    assert!(prove(&keys().proving_key, SECRET, public, V1).is_err());

    let forced = forced_proof(keys(), SECRET, &statement_public_inputs(&statement), V1);
    assert_eq!(verify(&statement, &forced), FAILED);
}

#[test]
fn proof_from_version_2_circuit_is_rejected_by_version_1_key() {
    let mut statement = statement();
    statement.nullifier = nullifier(&SECRET, &DEPLOYMENT_A, &DOMAIN, 2);

    let v2_proof = prove(
        &v2_keys().proving_key,
        SECRET,
        statement_public_inputs(&statement),
        2,
    )
    .unwrap();

    // Honest key id: rejected by the pinned fingerprint.
    assert_eq!(
        verify(&statement, &v2_keys().wire(&v2_proof)),
        Err(ProtocolError::NullifierVerifyingKeyMismatch)
    );

    // Forged key id: rejected by the pairing check.
    assert_eq!(verify(&statement, &keys().wire(&v2_proof)), FAILED);
}

// --- verifying key -----------------------------------------------------

#[test]
fn proof_under_another_setup_is_rejected() {
    let statement = statement();
    let foreign = other_keys().prove(SECRET, &statement);
    assert_ne!(other_keys().fingerprint, keys().fingerprint);

    assert_eq!(
        verify(&statement, &foreign),
        Err(ProtocolError::NullifierVerifyingKeyMismatch)
    );

    let relabelled = NullifierGroth16ProofV1 {
        verifying_key_id: keys().fingerprint,
        proof: foreign.proof,
    };
    assert_eq!(verify(&statement, &relabelled), FAILED);
}

#[test]
fn valid_proof_is_rejected_under_a_different_pinned_key() {
    let pinned = other_keys().pinned();
    let proof = NullifierGroth16ProofV1 {
        verifying_key_id: other_keys().fingerprint,
        proof: valid_proof().proof.clone(),
    };

    assert_eq!(
        verify_statement_nullifier_proof(&pinned, &statement(), &proof),
        FAILED
    );
}

#[test]
fn wrong_verifying_key_id_in_proof_is_rejected() {
    let mut proof = valid_proof().clone();
    proof.verifying_key_id[0] ^= 1;

    assert_eq!(
        verify(&statement(), &proof),
        Err(ProtocolError::NullifierVerifyingKeyMismatch)
    );
}

#[test]
fn pinned_key_with_wrong_fingerprint_is_rejected() {
    let mut fingerprint = keys().fingerprint;
    fingerprint[0] ^= 1;

    assert!(matches!(
        PinnedNullifierVerifyingKey::from_config(&keys().verifying_key_bytes, &fingerprint),
        Err(ProtocolError::InvalidNullifierVerifyingKey)
    ));

    // Another valid key under this key's fingerprint.
    assert!(matches!(
        PinnedNullifierVerifyingKey::from_config(
            &other_keys().verifying_key_bytes,
            &keys().fingerprint
        ),
        Err(ProtocolError::InvalidNullifierVerifyingKey)
    ));
}

#[test]
fn malformed_pinned_key_is_rejected_even_with_matching_fingerprint() {
    let mut truncated = keys().verifying_key_bytes.clone();
    truncated.pop();

    let mut trailing = keys().verifying_key_bytes.clone();
    trailing.push(0);

    let mut corrupted = keys().verifying_key_bytes.clone();
    corrupted[40] ^= 0xff;

    for bytes in [truncated, trailing, corrupted, vec![]] {
        assert!(matches!(
            PinnedNullifierVerifyingKey::from_config(
                &bytes,
                &verifying_key_bytes_fingerprint(&bytes)
            ),
            Err(ProtocolError::InvalidNullifierVerifyingKey)
        ));
    }
}

#[test]
fn pinned_key_with_wrong_public_input_count_is_rejected() {
    let mut verifying_key = keys().verifying_key.clone();
    verifying_key.gamma_abc_g1.pop();

    let bytes = serialize_verifying_key(&verifying_key).unwrap();

    assert!(matches!(
        PinnedNullifierVerifyingKey::from_config(&bytes, &verifying_key_bytes_fingerprint(&bytes)),
        Err(ProtocolError::InvalidNullifierVerifyingKey)
    ));
}

// --- proof bytes -------------------------------------------------------

#[test]
fn every_single_byte_corruption_of_the_proof_is_rejected() {
    let statement = statement();

    for index in 0..valid_proof().proof.len() {
        for mask in [0x01u8, 0x80] {
            let mut proof = valid_proof().clone();
            proof.proof[index] ^= mask;

            assert!(
                verify(&statement, &proof).is_err(),
                "byte {index} mask {mask:#x} accepted"
            );
        }
    }
}

#[test]
fn malformed_proofs_are_rejected_as_encoding_errors() {
    let valid = &valid_proof().proof;

    let mut wrong_magic = valid.clone();
    wrong_magic[..4].copy_from_slice(b"ZKGQ");

    let mut unsupported_version = valid.clone();
    unsupported_version[4] = 2;

    let mut trailing = valid.clone();
    trailing.push(0);

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("header only", valid[..5].to_vec()),
        ("truncated by one", valid[..valid.len() - 1].to_vec()),
        ("truncated mid-point", valid[..70].to_vec()),
        ("wrong magic", wrong_magic),
        ("unsupported version", unsupported_version),
        ("trailing byte", trailing),
        ("all zero", vec![0; valid.len()]),
        ("all 0xff", vec![0xff; valid.len()]),
    ];

    for (name, bytes) in cases {
        let proof = NullifierGroth16ProofV1 {
            verifying_key_id: keys().fingerprint,
            proof: bytes,
        };

        assert_eq!(
            verify(&statement(), &proof),
            Err(ProtocolError::InvalidNullifierProof),
            "{name}"
        );
    }
}

#[test]
fn structurally_valid_non_proof_is_rejected() {
    let fake = Groth16Proof {
        a: G1Affine::generator(),
        b: G2Affine::generator(),
        c: G1Affine::generator(),
    };

    assert_eq!(verify(&statement(), &keys().wire(&fake)), FAILED);
}
