#![forbid(unsafe_code)]

//! Native BN254 Groth16 circuit for the V1 nullifier relation:
//!
//! ```text
//! nullifier == HMAC-SHA256(
//!     credential_secret,
//!     "HOLOCHAIN-ZK-NULLIFIER-V1" || deployment_id || domain || u16_be(protocol_version)
//! )
//! ```
//!
//! Private input: 32-byte `credential_secret`.
//! Public inputs, in this order: `deployment_id`, `domain`, `nullifier`
//! (each packed into two BN254 scalars).
//! `protocol_version` is a circuit constant fixed at setup time.
//!
//! Setup is a deployment-time key-generation operation; it is never run by
//! the proving path.

pub mod nullifier;

use ark_bn254::Bn254;
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::OsRng;
use zk_admission_groth16_verifier as verifier;
use zk_admission_protocol::hashes::nullifier;

pub use nullifier::NullifierCircuit;
pub use verifier::{Groth16Proof, Groth16VerifyingKey, NullifierPublicInputs};

pub type Groth16ProvingKey = ProvingKey<Bn254>;

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

/// Circuit-specific Groth16 setup using `OsRng`.
///
/// Whoever runs this learns the setup trapdoor only transiently (arkworks
/// drops it on return), but a malicious setup party could keep it and
/// forge proofs. Run it once per deployment, by the deployment authority.
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

/// Prove the nullifier relation using `OsRng`.
///
/// Refuses to prove when the secret does not produce `expected_nullifier`;
/// arkworks would otherwise silently emit an invalid proof.
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

pub fn verifying_key_fingerprint(verifying_key: &Groth16VerifyingKey) -> Result<[u8; 32], String> {
    verifier::verifying_key_fingerprint(verifying_key)
}

pub fn serialize_proving_key(proving_key: &Groth16ProvingKey) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(proving_key.compressed_size());

    proving_key
        .serialize_compressed(&mut bytes)
        .map_err(|err| format!("failed to serialize Groth16 proving key: {err}"))?;

    Ok(bytes)
}

/// Decode a compressed proving key, rejecting trailing bytes.
pub fn deserialize_proving_key(bytes: &[u8]) -> Result<Groth16ProvingKey, String> {
    let mut reader = bytes;

    let proving_key = Groth16ProvingKey::deserialize_compressed(&mut reader)
        .map_err(|err| format!("failed to deserialize Groth16 proving key: {err}"))?;

    if !reader.is_empty() {
        return Err("trailing bytes after Groth16 proving key".into());
    }

    Ok(proving_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use zk_admission_protocol::{encoding::NULLIFIER_DOMAIN, ZkStatementV1};

    fn is_satisfied(
        credential_secret: [u8; 32],
        statement: &NullifierPublicInputs,
        protocol_version: u16,
    ) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();

        circuit(credential_secret, statement, protocol_version)
            .generate_constraints(cs.clone())
            .unwrap();

        cs.is_satisfied().unwrap()
    }

    fn statement(credential_secret: &[u8; 32], protocol_version: u16) -> NullifierPublicInputs {
        let deployment_id = [0x22; 32];
        let domain = [0x33; 32];

        NullifierPublicInputs {
            deployment_id,
            domain,
            expected_nullifier: nullifier(
                credential_secret,
                &deployment_id,
                &domain,
                protocol_version,
            ),
        }
    }

    #[test]
    fn nullifier_domain_separator_is_unchanged() {
        assert_eq!(NULLIFIER_DOMAIN, b"HOLOCHAIN-ZK-NULLIFIER-V1");
    }

    #[test]
    fn circuit_matches_protocol_nullifier() {
        let secret = [0x11; 32];
        let version = ZkStatementV1::PROTOCOL_VERSION;

        assert!(is_satisfied(secret, &statement(&secret, version), version));
    }

    #[test]
    fn circuit_rejects_wrong_secret() {
        let secret = [0x11; 32];
        let version = ZkStatementV1::PROTOCOL_VERSION;

        assert!(!is_satisfied(
            [0x12; 32],
            &statement(&secret, version),
            version
        ));
    }

    #[test]
    fn circuit_rejects_nullifier_for_other_protocol_version() {
        let secret = [0x11; 32];

        assert!(!is_satisfied(
            secret,
            &statement(&secret, 2),
            ZkStatementV1::PROTOCOL_VERSION
        ));
    }
}
