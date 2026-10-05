fn main() {
    let hash = zk_admission_prover::program_vkey_hash()
        .expect("failed to obtain SP1 program verifying-key hash");

    println!("program_vkey_hash = {}", hex::encode(hash));
}
