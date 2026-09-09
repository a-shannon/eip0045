//! Read-only, pinned retained-assumption byte comparison; no proof verification.

use anyhow::{Context as _, Result, ensure};
use clap::Parser;
use eip_0045_candidate_generator::recursive_oracle::{
    AssumptionByteIdentity, RECURSIVE_ORACLE_MAX_BYTES, compare_retained_assumption_bytes,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::{fs::File, io::{Read, Write as _}, path::{Path, PathBuf}, process::ExitCode};

#[derive(Debug, Parser)]
#[command(about = "Compare complete retained assumption bytes; does not verify proofs or provenance")]
struct Args {
    #[arg(long)]
    resolve_oracle: PathBuf,
    #[arg(long, value_parser = parse_length)]
    resolve_bytes: usize,
    #[arg(long, value_parser = parse_digest)]
    resolve_sha256: [u8; 32],
    #[arg(long)]
    join_oracle: PathBuf,
    #[arg(long, value_parser = parse_length)]
    join_bytes: usize,
    #[arg(long, value_parser = parse_digest)]
    join_sha256: [u8; 32],
    #[arg(long, value_parser = parse_length)]
    original_bytes: usize,
    #[arg(long, value_parser = parse_digest)]
    original_sha256: [u8; 32],
}

fn parse_length(value: &str) -> std::result::Result<usize, String> {
    let length = value.parse::<usize>().map_err(|_| "length must be an unsigned integer".to_owned())?;
    if (1..=RECURSIVE_ORACLE_MAX_BYTES).contains(&length) {
        Ok(length)
    } else {
        Err("length must be between 1 and 33554432 bytes".to_owned())
    }
}

fn parse_digest(value: &str) -> std::result::Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("SHA-256 must be exactly 64 lowercase hexadecimal characters".to_owned());
    }
    let mut digest = [0u8; 32];
    hex::decode_to_slice(value, &mut digest).map_err(|_| "invalid SHA-256".to_owned())?;
    Ok(digest)
}

fn validate_pin(pin: AssumptionByteIdentity) -> Result<()> {
    ensure!((1..=RECURSIVE_ORACLE_MAX_BYTES).contains(&pin.bytes), "file pin length outside bound");
    Ok(())
}

fn read_pinned_stream(reader: &mut impl Read, pin: AssumptionByteIdentity) -> Result<Vec<u8>> {
    validate_pin(pin)?;
    let mut bytes = Vec::new();
    reader.take(pin.bytes as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() == pin.bytes, "retained file length differs from pin");
    ensure!(<[u8; 32]>::from(Sha256::digest(&bytes)) == pin.sha256,
        "retained file SHA-256 differs from pin");
    Ok(bytes)
}

/// Checks opened regular-file contents only. Opening may follow links; these
/// measurements do not establish inode identity, no-follow behavior or custody.
fn read_pinned(path: &Path, pin: AssumptionByteIdentity) -> Result<Vec<u8>> {
    validate_pin(pin)?;
    let mut file = File::open(path).context("cannot open retained input")?;
    let metadata = file.metadata().context("cannot inspect opened retained input")?;
    ensure!(metadata.is_file(), "retained input is not an opened regular file");
    ensure!(metadata.len() == pin.bytes as u64, "retained file metadata length differs from pin");
    read_pinned_stream(&mut file, pin)
}

#[derive(Serialize)]
struct IdentityJson { bytes: usize, sha256: String }

#[derive(Serialize)]
struct Report {
    scope: &'static str,
    identity: IdentityJson,
    proof_verified: bool,
    provenance_authenticated: bool,
}

fn execute(args: Args) -> Result<Report> {
    let resolve = AssumptionByteIdentity { bytes: args.resolve_bytes, sha256: args.resolve_sha256 };
    let join = AssumptionByteIdentity { bytes: args.join_bytes, sha256: args.join_sha256 };
    let original = AssumptionByteIdentity { bytes: args.original_bytes, sha256: args.original_sha256 };
    // Validate the complete argument closure before any file is opened, including
    // programmatically constructed Args used by tests.
    for pin in [resolve, join, original] { validate_pin(pin)?; }
    let resolve_bytes = read_pinned(&args.resolve_oracle, resolve)?;
    let join_bytes = read_pinned(&args.join_oracle, join)?;
    let identity = compare_retained_assumption_bytes(&resolve_bytes, &join_bytes, original)?;
    Ok(Report {
        scope: "retained-assumption-byte-comparison",
        identity: IdentityJson { bytes: identity.bytes, sha256: hex::encode(identity.sha256) },
        proof_verified: false,
        provenance_authenticated: false,
    })
}

fn run() -> Result<()> {
    let report = execute(Args::parse())?;
    let mut encoded = serde_json::to_vec(&report)?;
    encoded.push(b'\n');
    let mut output = std::io::stdout().lock();
    output.write_all(&encoded)?;
    output.flush()?;
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("retained assumption comparison failed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(bytes: &[u8]) -> AssumptionByteIdentity {
        AssumptionByteIdentity { bytes: bytes.len(), sha256: Sha256::digest(bytes).into() }
    }

    fn cli() -> Vec<String> {
        ["eip-0045-ancestry-pair", "--resolve-oracle", "resolve.borsh", "--resolve-bytes", "3",
            "--resolve-sha256", &"00".repeat(32), "--join-oracle", "join.borsh", "--join-bytes", "3",
            "--join-sha256", &"00".repeat(32), "--original-bytes", "3", "--original-sha256", &"00".repeat(32)]
            .into_iter().map(str::to_owned).collect()
    }

    #[test]
    fn positive_regular_file_read_and_exact_content_pins() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("retained");
        std::fs::write(&path, b"abc").unwrap();
        assert_eq!(read_pinned(&path, pin(b"abc")).unwrap(), b"abc");
        assert!(read_pinned(&path, pin(b"ab")).is_err());
        assert_eq!(read_pinned(&path, pin(b"abd")).unwrap_err().to_string(),
            "retained file SHA-256 differs from pin");
        assert!(read_pinned(root.path(), pin(b"abc")).is_err());
    }

    #[test]
    fn trailing_and_short_streams_fail_before_hash_comparison() {
        let mut growing = std::io::Cursor::new(b"abcdef");
        assert_eq!(read_pinned_stream(&mut growing, pin(b"abc")).unwrap_err().to_string(),
            "retained file length differs from pin");
        assert_eq!(growing.position(), 4);
        assert!(read_pinned_stream(&mut std::io::Cursor::new(b"ab"), pin(b"abc")).is_err());
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("trailing");
        std::fs::write(&path, b"abcd").unwrap();
        assert!(read_pinned(&path, pin(b"abc")).is_err());
    }

    #[test]
    fn bounds_and_digest_shapes_are_closed() {
        assert_eq!(parse_length("1").unwrap(), 1);
        assert_eq!(parse_length("33554432").unwrap(), RECURSIVE_ORACLE_MAX_BYTES);
        for value in ["0", "33554433", "-1", "", "abc", "184467440737095516160"] {
            assert!(parse_length(value).is_err());
        }
        assert_eq!(parse_digest(&"af".repeat(32)).unwrap(), [0xaf; 32]);
        for value in ["AF".repeat(32), "00".repeat(31), "00".repeat(33), "gg".repeat(32)] {
            assert!(parse_digest(&value).is_err());
        }
        for length in [0, RECURSIVE_ORACLE_MAX_BYTES + 1, usize::MAX] {
            let mut source = std::io::Cursor::new(b"abc");
            assert!(read_pinned_stream(&mut source, AssumptionByteIdentity { bytes: length, sha256: [0; 32] }).is_err());
            assert_eq!(source.position(), 0);
        }
    }

    #[test]
    fn cli_requires_all_exact_pins_and_rejects_selectors() {
        let args = cli();
        let parsed = Args::try_parse_from(&args).unwrap();
        assert_eq!(parsed.resolve_oracle, PathBuf::from("resolve.borsh"));
        assert_eq!(parsed.join_oracle, PathBuf::from("join.borsh"));
        for position in (1..args.len()).step_by(2) {
            let mut missing = args.clone(); missing.drain(position..position + 2);
            assert!(Args::try_parse_from(missing).is_err());
        }
        for option in ["--output", "--prove", "--profile", "--dev-mode", "--campaign"] {
            let mut changed = args.clone(); changed.push(option.to_owned());
            assert!(Args::try_parse_from(changed).is_err());
        }
        for position in [4, 10, 14] {
            let mut changed = args.clone(); changed[position] = "0".to_owned();
            assert!(Args::try_parse_from(changed).is_err());
        }
        for position in [6, 12, 16] {
            let mut changed = args.clone(); changed[position] = "AA".repeat(32);
            assert!(Args::try_parse_from(changed).is_err());
        }
    }

    #[test]
    fn programmatic_original_bound_fails_before_opening_missing_inputs() {
        let mut args = Args::try_parse_from(cli()).unwrap();
        args.original_bytes = 0;
        assert_eq!(execute(args).err().unwrap().to_string(), "file pin length outside bound");
    }
}
