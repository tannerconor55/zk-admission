//! Deployment key generation for the native nullifier Groth16 circuit.
//!
//! ```text
//! cargo run --release -p zk-admission-groth16-circuit \
//!     --bin nullifier_groth16_setup -- <output-dir>
//! ```
//!
//! Creates `<output-dir>` only after both key files have been generated,
//! synchronized and atomically published as a complete key pair. The output
//! directory must not already exist. Prints the values to pin in the DNA
//! properties. Uses `OsRng`; run once per deployment, by the deployment
//! authority.

use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
};

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

fn unique_temp_dir(output_dir: &Path) -> Result<PathBuf, String> {
    for attempt in 0..100 {
        let candidate = output_dir.with_extension(format!("setup-tmp-{attempt}"));
        match std::fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(format!(
                    "failed to create temporary setup directory {}: {err}",
                    candidate.display()
                ))
            }
        }
    }

    Err(format!(
        "could not allocate a temporary setup directory near {}",
        output_dir.display()
    ))
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);

    let (Some(output_dir_arg), None) = (args.next(), args.next()) else {
        return Err("usage: nullifier_groth16_setup <output-dir>".into());
    };

    let output_dir = PathBuf::from(output_dir_arg);

    if output_dir.exists() {
        return Err(format!(
            "refusing to overwrite existing output directory {}",
            output_dir.display()
        ));
    }

    let parent = output_dir.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|err| {
        format!(
            "failed to create parent directory {}: {err}",
            parent.display()
        )
    })?;

    let temp_dir = unique_temp_dir(&output_dir)?;

    let result = (|| -> Result<(), String> {
        let proving_key_path = temp_dir.join(PROVING_KEY_FILE);
        let verifying_key_path = temp_dir.join(VERIFYING_KEY_FILE);

        let keys = generate_key_material()?;

        write_new(&verifying_key_path, &keys.verifying_key_bytes)?;
        write_new(&proving_key_path, &keys.proving_key_bytes)?;

        let temp_dir_handle = std::fs::File::open(&temp_dir)
            .map_err(|err| format!("failed to open temporary setup directory: {err}"))?;

        temp_dir_handle
            .sync_all()
            .map_err(|err| format!("failed to sync temporary setup directory: {err}"))?;

        std::fs::rename(&temp_dir, &output_dir).map_err(|err| {
            format!(
                "failed to publish generated key pair as {}: {err}",
                output_dir.display()
            )
        })?;

        let parent_handle = std::fs::File::open(parent)
            .map_err(|err| format!("failed to open parent directory: {err}"))?;

        parent_handle
            .sync_all()
            .map_err(|err| format!("failed to sync parent directory: {err}"))?;

        println!("circuit_id = {NULLIFIER_GROTH16_CIRCUIT_ID_V1}");
        println!("protocol_version = {NULLIFIER_GROTH16_PROTOCOL_VERSION}");
        println!(
            "proving_key = {}",
            output_dir.join(PROVING_KEY_FILE).display()
        );
        println!(
            "verifying_key = {}",
            output_dir.join(VERIFYING_KEY_FILE).display()
        );
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
    })();

    if result.is_err() {
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    result
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
