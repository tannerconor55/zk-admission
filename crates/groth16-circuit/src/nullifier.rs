use ark_bn254::Fr;
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_r1cs_std::{prelude::*, uint8::UInt8};
use ark_relations::r1cs::SynthesisError;
use std::ops::Not;
use zk_admission_protocol::encoding::NULLIFIER_DOMAIN;

const HMAC_BLOCK_SIZE: usize = 64;
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

// The domain separator comes from the protocol crate so the circuit and
// `zk_admission_protocol::hashes::nullifier` cannot drift apart.
const NULLIFIER_MESSAGE_LEN: usize = NULLIFIER_DOMAIN.len() + 32 + 32 + 2;

fn xor_byte(a: &UInt8<Fr>, b: u8) -> Result<UInt8<Fr>, SynthesisError> {
    let a_bits = a.to_bits_le()?;

    let bits = a_bits
        .into_iter()
        .enumerate()
        .map(|(i, bit)| {
            if ((b >> i) & 1) == 0 {
                Ok(bit)
            } else {
                Ok(bit.not())
            }
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(UInt8::from_bits_le(&bits))
}

fn hmac_sha256(key: &[UInt8<Fr>], message: &[UInt8<Fr>]) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    assert_eq!(key.len(), 32);

    let mut key_block = Vec::with_capacity(HMAC_BLOCK_SIZE);
    key_block.extend_from_slice(key);
    key_block.extend((key.len()..HMAC_BLOCK_SIZE).map(|_| UInt8::constant(0)));

    let ipad_block = key_block
        .iter()
        .map(|byte| xor_byte(byte, IPAD))
        .collect::<Result<Vec<_>, _>>()?;

    let opad_block = key_block
        .iter()
        .map(|byte| xor_byte(byte, OPAD))
        .collect::<Result<Vec<_>, _>>()?;

    let mut inner_input = ipad_block;
    inner_input.extend_from_slice(message);

    let inner_digest = Sha256Gadget::<Fr>::digest(&inner_input)?;

    let mut outer_input = opad_block;
    outer_input.extend_from_slice(&inner_digest.0);

    let outer_digest = Sha256Gadget::<Fr>::digest(&outer_input)?;

    Ok(outer_digest.0)
}

pub fn build_nullifier_circuit(
    cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    credential_secret: &[u8; 32],
    deployment_id: &[u8; 32],
    domain: &[u8; 32],
    protocol_version: u16,
    expected_nullifier: &[u8; 32],
) -> Result<(), SynthesisError> {
    let secret_vars = credential_secret
        .iter()
        .map(|byte| UInt8::new_witness(cs.clone(), || Ok(*byte)))
        .collect::<Result<Vec<_>, _>>()?;

    let deployment_vars = UInt8::new_input_vec(cs.clone(), deployment_id)?;
    let domain_vars = UInt8::new_input_vec(cs.clone(), domain)?;
    let nullifier_vars = UInt8::new_input_vec(cs.clone(), expected_nullifier)?;

    let version_bytes = protocol_version.to_be_bytes();

    let mut message = Vec::with_capacity(NULLIFIER_MESSAGE_LEN);
    message.extend(NULLIFIER_DOMAIN.iter().copied().map(UInt8::constant));
    message.extend_from_slice(&deployment_vars);
    message.extend_from_slice(&domain_vars);
    message.push(UInt8::constant(version_bytes[0]));
    message.push(UInt8::constant(version_bytes[1]));

    let computed = hmac_sha256(&secret_vars, &message)?;

    for (computed_byte, expected_byte) in computed.iter().zip(nullifier_vars.iter()) {
        computed_byte.enforce_equal(expected_byte)?;
    }

    Ok(())
}

pub struct NullifierCircuit {
    pub credential_secret: [u8; 32],
    pub deployment_id: [u8; 32],
    pub domain: [u8; 32],
    pub protocol_version: u16,
    pub expected_nullifier: [u8; 32],
}

impl ark_relations::r1cs::ConstraintSynthesizer<Fr> for NullifierCircuit {
    fn generate_constraints(
        self,
        cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
        build_nullifier_circuit(
            cs,
            &self.credential_secret,
            &self.deployment_id,
            &self.domain,
            self.protocol_version,
            &self.expected_nullifier,
        )
    }
}
