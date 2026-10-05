use ark_bn254::Bn254;
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zk_admission_groth16_verifier as verifier;
use zk_admission_protocol::hashes::nullifier;

use super::nullifier::NullifierCircuit;

pub type Groth16ProvingKey = ProvingKey<Bn254>;
pub type Groth16VerifyingKey = verifier::Groth16VerifyingKey;
pub type Groth16Proof = verifier::Groth16Proof;

pub use verifier::NullifierPublicInputs;

fn circuit(
    credential_secret: [u8; 32],
    statement: &NullifierPublicInputs,
    protocol_version: u16,
) -> NullifierCircuit {
    NullifierCircuit {
        credential_secret,
        deployment_id: statement.deployment_id,
        domain: statement.domain,
        protocol_version,
        expected_nullifier: statement.expected_nullifier,
    }
}

pub fn setup(protocol_version: u16) -> Result<(Groth16ProvingKey, Groth16VerifyingKey), String> {
    let credential_secret = [0u8; 32];
    let deployment_id = [0u8; 32];
    let domain = [0u8; 32];

    let expected_nullifier = nullifier(
        &credential_secret,
        &deployment_id,
        &domain,
        protocol_version,
    );

    let statement = NullifierPublicInputs {
        deployment_id,
        domain,
        expected_nullifier,
    };

    let mut rng = OsRng;

    Groth16::<Bn254>::circuit_specific_setup(
        circuit(credential_secret, &statement, protocol_version),
        &mut rng,
    )
    .map_err(|err| format!("Groth16 setup failed: {err}"))
}

pub fn prove(
    proving_key: &Groth16ProvingKey,
    credential_secret: [u8; 32],
    statement: NullifierPublicInputs,
    protocol_version: u16,
) -> Result<Groth16Proof, String> {
    let expected_nullifier = nullifier(
        &credential_secret,
        &statement.deployment_id,
        &statement.domain,
        protocol_version,
    );

    if statement.expected_nullifier != expected_nullifier {
        return Err("expected_nullifier does not match credential secret".into());
    }

    let mut rng = OsRng;

    Groth16::<Bn254>::prove(
        proving_key,
        circuit(credential_secret, &statement, protocol_version),
        &mut rng,
    )
    .map_err(|err| format!("Groth16 proving failed: {err}"))
}

pub fn verify(
    verifying_key: &Groth16VerifyingKey,
    statement: &NullifierPublicInputs,
    proof: &Groth16Proof,
) -> Result<bool, String> {
    verifier::verify(verifying_key, statement, proof)
}

pub fn serialize_proof(proof: &Groth16Proof) -> Result<Vec<u8>, String> {
    verifier::serialize_proof(proof)
}

pub fn deserialize_proof(bytes: &[u8]) -> Result<Groth16Proof, String> {
    verifier::deserialize_proof(bytes)
}

pub fn serialize_verifying_key(verifying_key: &Groth16VerifyingKey) -> Result<Vec<u8>, String> {
    verifier::serialize_verifying_key(verifying_key)
}

pub fn deserialize_verifying_key(bytes: &[u8]) -> Result<Groth16VerifyingKey, String> {
    verifier::deserialize_verifying_key(bytes)
}

pub fn serialize_proving_key(proving_key: &Groth16ProvingKey) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(proving_key.compressed_size());

    proving_key
        .serialize_compressed(&mut bytes)
        .map_err(|err| format!("failed to serialize Groth16 proving key: {err}"))?;

    Ok(bytes)
}

pub fn deserialize_proving_key(bytes: &[u8]) -> Result<Groth16ProvingKey, String> {
    Groth16ProvingKey::deserialize_compressed(bytes)
        .map_err(|err| format!("failed to deserialize Groth16 proving key: {err}"))
}

pub fn verifying_key_fingerprint(verifying_key: &Groth16VerifyingKey) -> Result<[u8; 32], String> {
    let bytes = serialize_verifying_key(verifying_key)?;

    let digest = Sha256::digest(&bytes);

    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&digest);

    Ok(fingerprint)
}
