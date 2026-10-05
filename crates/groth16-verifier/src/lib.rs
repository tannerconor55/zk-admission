#![forbid(unsafe_code)]

use ark_bn254::{Bn254, Fr};
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
use ark_relations::r1cs::ToConstraintField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;

pub type Groth16Proof = Proof<Bn254>;
pub type Groth16VerifyingKey = VerifyingKey<Bn254>;

pub struct NullifierPublicInputs {
    pub deployment_id: [u8; 32],
    pub domain: [u8; 32],
    pub expected_nullifier: [u8; 32],
}

fn public_inputs(statement: &NullifierPublicInputs) -> Vec<Fr> {
    let mut inputs = Vec::with_capacity(6);

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

    debug_assert_eq!(inputs.len(), 6);
    inputs
}

pub fn verify(
    verifying_key: &Groth16VerifyingKey,
    statement: &NullifierPublicInputs,
    proof: &Groth16Proof,
) -> Result<bool, String> {
    let prepared_vk = prepare_verifying_key(verifying_key);

    Groth16::<Bn254>::verify_with_processed_vk(&prepared_vk, &public_inputs(statement), proof)
        .map_err(|err| format!("Groth16 verification failed: {err}"))
}

pub fn serialize_proof(proof: &Groth16Proof) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(5 + proof.compressed_size());

    bytes.extend_from_slice(b"ZKGP");
    bytes.push(1);

    proof
        .serialize_compressed(&mut bytes)
        .map_err(|err| format!("failed to serialize Groth16 proof: {err}"))?;

    Ok(bytes)
}

pub fn deserialize_proof(bytes: &[u8]) -> Result<Groth16Proof, String> {
    if bytes.len() < 5 {
        return Err("Groth16 proof is too short".into());
    }

    if &bytes[..4] != b"ZKGP" {
        return Err("invalid Groth16 proof magic".into());
    }

    if bytes[4] != 1 {
        return Err("unsupported Groth16 proof format version".into());
    }

    Groth16Proof::deserialize_compressed(&bytes[5..])
        .map_err(|err| format!("failed to deserialize proof: {err}"))
}

pub fn serialize_verifying_key(verifying_key: &Groth16VerifyingKey) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(verifying_key.compressed_size());

    verifying_key
        .serialize_compressed(&mut bytes)
        .map_err(|err| format!("failed to serialize Groth16 verifying key: {err}"))?;

    Ok(bytes)
}

pub fn deserialize_verifying_key(bytes: &[u8]) -> Result<Groth16VerifyingKey, String> {
    Groth16VerifyingKey::deserialize_compressed(bytes)
        .map_err(|err| format!("failed to deserialize verifying key: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
