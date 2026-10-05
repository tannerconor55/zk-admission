use ark_bn254::Fr;
use ark_relations::r1cs::ToConstraintField;

fn main() {
    let deployment_id = [0x22u8; 32];
    let domain = [0x33u8; 32];
    let nullifier = [0x44u8; 32];

    for (name, bytes) in [
        ("deployment_id", deployment_id.as_slice()),
        ("domain", domain.as_slice()),
        ("nullifier", nullifier.as_slice()),
    ] {
        let fields =
            ToConstraintField::<Fr>::to_field_elements(bytes).expect("failed to pack bytes");

        println!("{name}:");
        for (i, field) in fields.iter().enumerate() {
            println!("  [{i}] = {}", field);
        }
    }
}
