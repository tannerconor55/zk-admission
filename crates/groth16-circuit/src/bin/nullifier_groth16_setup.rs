//! Deployment key generation for the native nullifier Groth16 circuit.
//!
//! ```text
//! cargo run --release -p zk-admission-groth16-circuit \
//!     --bin nullifier_groth16_setup -- <output-dir>
//! ```
//!
//! Writes `nullifier_groth16_pk.bin` and `nullifier_groth16_vk.bin` into
//! `<output-dir>` (refusing to overwrite) and prints the values to pin in
//! the DNA properties. Uses `OsRng`; run once per deployment, by the
//! deployment authority.

use std::{fs::OpenOptions, io::Write, path::Path, process::ExitCode};

use zk_admission_groth16_circuit::generate_key_material;
use zk_admission_protocol::{NULLIFIER_GROTH16_CIRCUIT_ID_V1, NULLIFIER_GROTH16_PROTOCOL_VERSION};

const PROVING_KEY_FILE: &str = "nullifier_groth16_pk.bin";
const VERIFYING_KEY_FILE: &str = "nullifier_groth16_vk.bin";

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|err| format!("failed to create {}: {err}", path.display()))?;

    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|err| format!("failed to write {}: {err}", path.display()))
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);

    let (Some(output_dir), None) = (args.next(), args.next()) else {
        return Err("usage: nullifier_groth16_setup <output-dir>".into());
    };

    let output_dir = Path::new(&output_dir);
    std::fs::create_dir_all(output_dir)
        .map_err(|err| format!("failed to create {}: {err}", output_dir.display()))?;

    let proving_key_path = output_dir.join(PROVING_KEY_FILE);
    let verifying_key_path = output_dir.join(VERIFYING_KEY_FILE);

    for path in [&proving_key_path, &verifying_key_path] {
        if path.exists() {
            return Err(format!("refusing to overwrite {}", path.display()));
        }
    }

    let keys = generate_key_material()?;

    write_new(&verifying_key_path, &keys.verifying_key_bytes)?;
    write_new(&proving_key_path, &keys.proving_key_bytes)?;

    println!("circuit_id = {NULLIFIER_GROTH16_CIRCUIT_ID_V1}");
    println!("protocol_version = {NULLIFIER_GROTH16_PROTOCOL_VERSION}");
    println!("proving_key = {}", proving_key_path.display());
    println!("verifying_key = {}", verifying_key_path.display());
    println!(
        "verifying_key_fingerprint = {}",
        hex::encode(keys.verifying_key_fingerprint)
    );
    println!();
    println!("# DNA properties (byte arrays):");
    println!(
        "nullifier_groth16_vk: {:?}",
        keys.verifying_key_bytes.as_slice()
    );
    println!(
        "nullifier_groth16_vk_fingerprint: {:?}",
        keys.verifying_key_fingerprint
    );

    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
