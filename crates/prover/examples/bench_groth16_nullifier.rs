use ark_bn254::Fr;
use ark_relations::r1cs::ConstraintSystem;
use zk_admission_protocol::hashes::nullifier;

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

    let cs = ConstraintSystem::<Fr>::new_ref();

    zk_admission_prover::groth16::nullifier::build_nullifier_circuit(
        cs.clone(),
        &credential_secret,
        &deployment_id,
        &domain,
        protocol_version,
        &expected_nullifier,
    )
    .expect("failed to build nullifier circuit");

    println!("constraints = {}", cs.num_constraints());
    println!("public_inputs = {}", cs.num_instance_variables());
    println!("witness_variables = {}", cs.num_witness_variables());
    println!(
        "satisfied = {}",
        cs.is_satisfied().expect("constraint check failed")
    );
}
