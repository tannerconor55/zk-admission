#![forbid(unsafe_code)]

use ark_bn254::{Bn254, Fr};
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
use ark_relations::r1cs::ToConstraintField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use sha2::{Digest, Sha256};

pub type Groth16Proof = Proof<Bn254>;
pub type Groth16VerifyingKey = VerifyingKey<Bn254>;

/// Magic prefix of the native nullifier Groth16 proof wire format.
pub const PROOF_MAGIC: &[u8; 4] = b"ZKGP";

/// Proof wire-format version following `PROOF_MAGIC`.
pub const PROOF_FORMAT_VERSION: u8 = 1;

/// Arkworks compressed BN254 Groth16 proof: A (G1) || B (G2) || C (G1).
pub const COMPRESSED_PROOF_LEN: usize = 32 + 64 + 32;

/// Complete wire length: magic || version || compressed proof.
pub const PROOF_WIRE_LEN: usize = PROOF_MAGIC.len() + 1 + COMPRESSED_PROOF_LEN;

/// Number of BN254 scalar-field public inputs of the nullifier circuit.
///
/// Order is fixed: deployment_id (2), domain (2), nullifier (2).
pub const NULLIFIER_PUBLIC_INPUT_LEN: usize = 6;

pub struct NullifierPublicInputs {
    pub deployment_id: [u8; 32],
    pub domain: [u8; 32],
    pub expected_nullifier: [u8; 32],
}

/// Pack the public inputs exactly as `UInt8::new_input_vec` does in the
/// circuit: each 32-byte value becomes two field elements (31 + 1 bytes).
pub fn public_inputs(statement: &NullifierPublicInputs) -> Vec<Fr> {
    let mut inputs = Vec::with_capacity(NULLIFIER_PUBLIC_INPUT_LEN);

    inputs.extend(
        ToConstraintField::<Fr>::to_field_elements(statement.deployment_id.as_slice())
            .expect("32-byte deployment_id must pack into field elements"),
    );
    inputs.extend(
        ToConstraintField::<Fr>::to_field_elements(statement.domain.as_slice())
            .expect("32-byte domain must pack into field elements"),
    );
    inputs.extend(
        ToConstraintField::<Fr>::to_field_elements(statement.expected_nullifier.as_slice())
            .expect("32-byte nullifier must pack into field elements"),
    );

    debug_assert_eq!(inputs.len(), NULLIFIER_PUBLIC_INPUT_LEN);
    inputs
}

pub fn verify(
    verifying_key: &Groth16VerifyingKey,
    statement: &NullifierPublicInputs,
    proof: &Groth16Proof,
) -> Result<bool, String> {
    // A key for a different circuit shape must never be used, even if
    // arkworks would reject the input length on its own.
    if verifying_key.gamma_abc_g1.len() != NULLIFIER_PUBLIC_INPUT_LEN + 1 {
        return Err("verifying key has the wrong number of public inputs".into());
    }

    let prepared_vk = prepare_verifying_key(verifying_key);

    Groth16::<Bn254>::verify_with_processed_vk(&prepared_vk, &public_inputs(statement), proof)
        .map_err(|err| format!("Groth16 verification failed: {err}"))
}

pub fn serialize_proof(proof: &Groth16Proof) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(PROOF_WIRE_LEN);

    bytes.extend_from_slice(PROOF_MAGIC);
    bytes.push(PROOF_FORMAT_VERSION);

    proof
        .serialize_compressed(&mut bytes)
        .map_err(|err| format!("failed to serialize Groth16 proof: {err}"))?;

    debug_assert_eq!(bytes.len(), PROOF_WIRE_LEN);
    Ok(bytes)
}

/// Decode a proof, accepting only the exact canonical encoding.
///
/// Arkworks reads from a slice without rejecting trailing bytes and
/// tolerates some non-canonical flag encodings, so the decoded proof is
/// re-encoded and must reproduce the input byte-for-byte.
pub fn deserialize_proof(bytes: &[u8]) -> Result<Groth16Proof, String> {
    if bytes.len() < PROOF_MAGIC.len() + 1 {
        return Err("Groth16 proof is too short".into());
    }

    if &bytes[..4] != PROOF_MAGIC {
        return Err("invalid Groth16 proof magic".into());
    }

    if bytes[4] != PROOF_FORMAT_VERSION {
        return Err("unsupported Groth16 proof format version".into());
    }

    if bytes.len() != PROOF_WIRE_LEN {
        return Err("invalid Groth16 proof length".into());
    }

    let proof = Groth16Proof::deserialize_compressed(&bytes[5..])
        .map_err(|err| format!("failed to deserialize proof: {err}"))?;

    if serialize_proof(&proof)? != bytes {
        return Err("non-canonical Groth16 proof encoding".into());
    }

    Ok(proof)
}

pub fn serialize_verifying_key(verifying_key: &Groth16VerifyingKey) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(verifying_key.compressed_size());

    verifying_key
        .serialize_compressed(&mut bytes)
        .map_err(|err| format!("failed to serialize Groth16 verifying key: {err}"))?;

    Ok(bytes)
}

/// Decode a verifying key, accepting only the exact canonical encoding.
pub fn deserialize_verifying_key(bytes: &[u8]) -> Result<Groth16VerifyingKey, String> {
    let verifying_key = Groth16VerifyingKey::deserialize_compressed(bytes)
        .map_err(|err| format!("failed to deserialize verifying key: {err}"))?;

    if serialize_verifying_key(&verifying_key)? != bytes {
        return Err("non-canonical Groth16 verifying key encoding".into());
    }

    Ok(verifying_key)
}

/// SHA-256 over the canonical compressed verifying-key bytes.
pub fn verifying_key_bytes_fingerprint(verifying_key_bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(verifying_key_bytes);

    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&digest);

    fingerprint
}

/// SHA-256 fingerprint of a verifying key's canonical encoding.
pub fn verifying_key_fingerprint(verifying_key: &Groth16VerifyingKey) -> Result<[u8; 32], String> {
    Ok(verifying_key_bytes_fingerprint(&serialize_verifying_key(
        verifying_key,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{G1Affine, G2Affine};
    use ark_ec::AffineRepr;

    fn generator_proof() -> Groth16Proof {
        Groth16Proof {
            a: G1Affine::generator(),
            b: G2Affine::generator(),
            c: G1Affine::generator(),
        }
    }

    #[test]
    fn malformed_proof_is_rejected() {
        assert!(deserialize_proof(&[]).is_err());
        assert!(deserialize_proof(&[0u8; 127]).is_err());
    }

    #[test]
    fn malformed_verifying_key_is_rejected() {
        assert!(deserialize_verifying_key(&[]).is_err());
        assert!(deserialize_verifying_key(&[0u8; 455]).is_err());
    }

    #[test]
    fn versioned_proof_format_is_enforced() {
        assert!(deserialize_proof(b"ZKGP\x01").is_err());
        assert!(deserialize_proof(b"BAD!\x01").is_err());
        assert!(deserialize_proof(b"ZKGP\x02").is_err());
        assert!(deserialize_proof(&[0u8; 128]).is_err());
    }

    #[test]
    fn proof_wire_format_round_trips() {
        let bytes = serialize_proof(&generator_proof()).unwrap();

        assert_eq!(bytes.len(), PROOF_WIRE_LEN);
        assert_eq!(&bytes[..4], PROOF_MAGIC);
        assert_eq!(bytes[4], PROOF_FORMAT_VERSION);
        assert_eq!(deserialize_proof(&bytes).unwrap(), generator_proof());
    }

    #[test]
    fn trailing_proof_bytes_are_rejected() {
        let mut bytes = serialize_proof(&generator_proof()).unwrap();
        bytes.push(0);

        assert!(deserialize_proof(&bytes).is_err());
    }

    #[test]
    fn truncated_proof_is_rejected() {
        let bytes = serialize_proof(&generator_proof()).unwrap();

        for len in 0..bytes.len() {
            assert!(deserialize_proof(&bytes[..len]).is_err(), "len {len}");
        }
    }

    #[test]
    fn wrong_magic_and_version_are_rejected_on_well_formed_body() {
        let bytes = serialize_proof(&generator_proof()).unwrap();

        let mut wrong_magic = bytes.clone();
        wrong_magic[0] ^= 1;
        assert_eq!(
            deserialize_proof(&wrong_magic).unwrap_err(),
            "invalid Groth16 proof magic"
        );

        let mut wrong_version = bytes;
        wrong_version[4] = 2;
        assert_eq!(
            deserialize_proof(&wrong_version).unwrap_err(),
            "unsupported Groth16 proof format version"
        );
    }

    #[test]
    fn fingerprint_is_sha256_of_bytes() {
        assert_eq!(
            verifying_key_bytes_fingerprint(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
    }
}
