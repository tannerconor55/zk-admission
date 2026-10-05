//! Production-shaped native nullifier proving.
//!
//! Key generation (`generate_key_material`) is an explicit deployment
//! operation. The proving path only ever loads a persisted proving key and
//! never runs setup.

use std::path::Path;

use zk_admission_groth16_verifier::{
    statement_public_inputs, verify_statement_nullifier_proof, PinnedNullifierVerifyingKey,
};
use zk_admission_protocol::{
    NullifierGroth16ProofV1, ZkStatementV1, NULLIFIER_GROTH16_PROTOCOL_VERSION,
};

use crate::{
    deserialize_proving_key, prove, serialize_proof, serialize_proving_key,
    serialize_verifying_key, setup, verifying_key_fingerprint, Groth16ProvingKey,
};

/// Output of a deployment's native nullifier key generation.
///
/// `verifying_key_bytes` and `verifying_key_fingerprint` go into the DNA
/// properties. `proving_key_bytes` is distributed to provers; it is not
/// secret, but it must be the key generated alongside the pinned
/// verifying key.
pub struct NullifierKeyMaterialV1 {
    pub proving_key_bytes: Vec<u8>,
    pub verifying_key_bytes: Vec<u8>,
    pub verifying_key_fingerprint: [u8; 32],
}

/// Run the circuit-specific Groth16 setup for the V1 nullifier relation.
///
/// Uses `OsRng`. The setup trapdoor exists only in memory during this call;
/// anyone who retained it could forge nullifier proofs for this key, so
/// this must be run by (and trusted as much as) the deployment authority.
pub fn generate_key_material() -> Result<NullifierKeyMaterialV1, String> {
    let (proving_key, verifying_key) = setup(NULLIFIER_GROTH16_PROTOCOL_VERSION)?;

    Ok(NullifierKeyMaterialV1 {
        proving_key_bytes: serialize_proving_key(&proving_key)?,
        verifying_key_bytes: serialize_verifying_key(&verifying_key)?,
        verifying_key_fingerprint: verifying_key_fingerprint(&verifying_key)?,
    })
}

/// A persisted proving key, checked against the deployment's pinned
/// verifying-key fingerprint when loaded.
pub struct NullifierProvingKeyV1 {
    proving_key: Groth16ProvingKey,
    pinned: PinnedNullifierVerifyingKey,
}

impl NullifierProvingKeyV1 {
    /// Decode a compressed proving key and require that the verifying key
    /// embedded in it has `expected_verifying_key_fingerprint`.
    pub fn from_bytes(
        proving_key_bytes: &[u8],
        expected_verifying_key_fingerprint: &[u8; 32],
    ) -> Result<Self, String> {
        let proving_key = deserialize_proving_key(proving_key_bytes)?;

        let verifying_key_bytes = serialize_verifying_key(&proving_key.vk)?;

        let pinned = PinnedNullifierVerifyingKey::from_config(
            &verifying_key_bytes,
            expected_verifying_key_fingerprint,
        )
        .map_err(|_| {
            "proving key does not match the pinned verifying-key fingerprint".to_string()
        })?;

        Ok(Self {
            proving_key,
            pinned,
        })
    }

    pub fn load(
        path: impl AsRef<Path>,
        expected_verifying_key_fingerprint: &[u8; 32],
    ) -> Result<Self, String> {
        let path = path.as_ref();

        let bytes = std::fs::read(path)
            .map_err(|err| format!("failed to read proving key {}: {err}", path.display()))?;

        Self::from_bytes(&bytes, expected_verifying_key_fingerprint)
    }

    pub fn verifying_key_id(&self) -> &[u8; 32] {
        self.pinned.fingerprint()
    }

    /// Prove the nullifier relation for `statement`.
    ///
    /// Public inputs are taken from the statement exactly as the integrity
    /// zome derives them. The proof is verified against the pinned key
    /// before it is returned.
    pub fn prove_statement(
        &self,
        statement: &ZkStatementV1,
        credential_secret: &[u8],
    ) -> Result<NullifierGroth16ProofV1, String> {
        if statement.protocol_version != NULLIFIER_GROTH16_PROTOCOL_VERSION {
            return Err(
                "statement protocol version is not supported by the nullifier circuit".into(),
            );
        }

        // HMAC zero-pads keys up to the 64-byte block, so a 32-byte secret
        // yields the same nullifier as `hashes::nullifier`; the circuit has
        // a fixed 32-byte secret input.
        let credential_secret: [u8; 32] = credential_secret
            .try_into()
            .map_err(|_| "native nullifier circuit requires a 32-byte credential secret")?;

        let proof = prove(
            &self.proving_key,
            credential_secret,
            statement_public_inputs(statement),
            NULLIFIER_GROTH16_PROTOCOL_VERSION,
        )?;

        let proof = NullifierGroth16ProofV1 {
            verifying_key_id: *self.verifying_key_id(),
            proof: serialize_proof(&proof)?,
        };

        verify_statement_nullifier_proof(&self.pinned, statement, &proof)
            .map_err(|err| format!("generated nullifier proof failed self-verification: {err}"))?;

        Ok(proof)
    }
}
