use ark_bn254::{Bn254, Fr};
use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::ToConstraintField;
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use std::time::Instant;
use zk_admission_protocol::hashes::nullifier;
use zk_admission_prover::groth16::nullifier::NullifierCircuit;

fn main() {
    let credential_secret = [0x11u8; 32];
    let deployment_id = [0x22u8; 32];
    let domain = [0x33u8; 32];
    let protocol_version = 1u16;

    let expected_nullifier = nullifier(
        &credential_secret,
        &deployment_id,
        &domain,
        protocol_version,
    );

    let circuit = NullifierCircuit {
        credential_secret,
        deployment_id,
        domain,
        protocol_version,
        expected_nullifier,
    };

    let setup_start = Instant::now();

    let mut rng = StdRng::seed_from_u64(0x5a17_2026);

    let (pk, vk): (ProvingKey<Bn254>, VerifyingKey<Bn254>) =
        Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng).expect("Groth16 setup failed");

    println!("setup_seconds = {:.3}", setup_start.elapsed().as_secs_f64());

    let circuit = NullifierCircuit {
        credential_secret,
        deployment_id,
        domain,
        protocol_version,
        expected_nullifier,
    };

    let prove_start = Instant::now();

    let proof: Proof<Bn254> =
        Groth16::<Bn254>::prove(&pk, circuit, &mut rng).expect("Groth16 proving failed");

    println!("prove_seconds = {:.3}", prove_start.elapsed().as_secs_f64());

    let verify_start = Instant::now();

    let prepared_vk = prepare_verifying_key(&vk);

    let mut public_inputs = Vec::new();
    public_inputs.extend(
        ToConstraintField::<Fr>::to_field_elements(deployment_id.as_slice())
            .expect("failed to pack deployment_id"),
    );
    public_inputs.extend(
        ToConstraintField::<Fr>::to_field_elements(domain.as_slice())
            .expect("failed to pack domain"),
    );
    public_inputs.extend(
        ToConstraintField::<Fr>::to_field_elements(expected_nullifier.as_slice())
            .expect("failed to pack expected_nullifier"),
    );

    assert_eq!(public_inputs.len(), 6);

    let verified = Groth16::<Bn254>::verify_with_processed_vk(&prepared_vk, &public_inputs, &proof)
        .expect("Groth16 verification failed");

    println!(
        "verify_seconds = {:.6}",
        verify_start.elapsed().as_secs_f64()
    );
    println!("verified = {verified}");
}
