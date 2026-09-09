//! Opt-in retained-byte conversion fixture; no proving or campaign acceptance.

use anyhow::{Context as _, Result, ensure};
use eip_0045_candidate_generator::local_case9_oracle_extraction::{
    Case9DirectOracles, extract_case9_direct_oracles,
};
use eip_0045_reproduction::receipt_oracle_codec::RECEIPT_ORACLE_MAX_BYTES;
use sha2::{Digest as _, Sha256};
use std::{fs, io::{Read, Write}, path::{Path, PathBuf}};

const INPUTS: [(&str, usize, &str); 3] = [
    ("candidate-recursive-oracle.borsh", 1114777,
     "02464e12e4564866e0a423502b89cba98183dbbb9cd09ce544018d6fe0e0cccf"),
    ("reproduction/schema/b4-corpus-v1.candidate/positive/terminal-resolve-explicit-root/candidate-ancestry-assumption-raw-seal.bin",
     222668, "d610316c61f0c8d3f15e54b4816f2a9d2c4166dfd8cda049eb8859f2e7258b8b"),
    ("candidate-raw-seal.bin", 222668,
     "d8f52964fe28215f2dcd54c2925264cddbb0ebd4962ab166fe5869fa1a74b4d9"),
];
const OUTPUTS: [&str; 2] = ["case9-assumption.receipt-oracle.bincode",
    "case9-final-resolve.receipt-oracle.bincode"];

// Admission identifies exact opened bytes only, not inode custody or provenance.
fn read_pinned(path: &Path, length: usize, digest: &str) -> Result<Vec<u8>> {
    ensure!((1..=2 * 1024 * 1024).contains(&length), "retained input length bound");
    let mut file = fs::File::open(path).context("cannot open retained input")?;
    let meta = file.metadata()?;
    ensure!(meta.is_file() && meta.len() == length as u64, "retained input file/size");
    let mut bytes = Vec::new();
    (&mut file).take(length as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() == length && hex::encode(Sha256::digest(&bytes)) == digest,
        "retained input content pin");
    Ok(bytes)
}

fn require_empty_output(output: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(output)?;
    ensure!(output.is_absolute() && meta.is_dir() && !meta.file_type().is_symlink(),
        "output must be an absolute ordinary directory");
    ensure!(fs::read_dir(output)?.next().is_none(), "output directory is occupied");
    Ok(())
}

// Each file is flushed and published without replacement. A failed second
// publication may leave the first complete file; such a pair is not accepted.
fn publish_one(output: &Path, leaf: &str, bytes: &[u8]) -> Result<()> {
    let mut staged = tempfile::NamedTempFile::new_in(output)?;
    staged.write_all(bytes)?;
    staged.as_file().sync_all()?;
    let published = staged.persist_noclobber(output.join(leaf))
        .map_err(|error| anyhow::anyhow!("create-only oracle publication failed: {}", error.error))?;
    published.sync_all()?;
    Ok(())
}

fn publish_pair(output: &Path, pair: &Case9DirectOracles) -> Result<()> {
    require_empty_output(output)?;
    let payloads = [&pair.assumption_oracle, &pair.final_resolve_oracle];
    for bytes in payloads {
        ensure!((1..=RECEIPT_ORACLE_MAX_BYTES).contains(&bytes.len()), "direct oracle output bound");
    }
    for (leaf, bytes) in OUTPUTS.iter().zip(payloads) {
        publish_one(output, leaf, bytes)?;
    }
    // Verify the complete two-file result, not only successful writes.
    ensure!(fs::read_dir(output)?.count() == 2, "output inventory differs");
    for (leaf, bytes) in OUTPUTS.iter().zip(payloads) {
        ensure!(read_pinned(&output.join(leaf), bytes.len(),
            &hex::encode(Sha256::digest(bytes)))? == *bytes, "published oracle differs");
    }
    Ok(())
}

#[test]
fn opened_input_pins_reject_each_size_and_digest_fault() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("input");
    fs::write(&path, b"abc").unwrap();
    let digest = hex::encode(Sha256::digest(b"abc"));
    assert_eq!(read_pinned(&path, 3, &digest).unwrap(), b"abc");
    assert!(read_pinned(&path, 2, &digest).is_err());
    assert!(read_pinned(&path, 4, &digest).is_err());
    assert!(read_pinned(&path, 3, &"00".repeat(32)).is_err());
    assert!(read_pinned(root.path(), 3, &digest).is_err());
    assert!(read_pinned(&path, 0, &digest).is_err());
    assert!(read_pinned(&path, 2 * 1024 * 1024 + 1, &digest).is_err());
}

#[test]
fn pair_publication_is_exact_and_refuses_occupied_or_invalid_outputs() {
    let root = tempfile::tempdir().unwrap();
    let pair = Case9DirectOracles { assumption_oracle: b"one".to_vec(),
        final_resolve_oracle: b"two".to_vec() };
    publish_pair(root.path(), &pair).unwrap();
    assert_eq!(fs::read(root.path().join(OUTPUTS[0])).unwrap(), b"one");
    assert_eq!(fs::read(root.path().join(OUTPUTS[1])).unwrap(), b"two");
    assert!(publish_pair(root.path(), &pair).is_err());
    assert_eq!(fs::read(root.path().join(OUTPUTS[0])).unwrap(), b"one");
    let other = tempfile::tempdir().unwrap();
    fs::write(other.path().join("foreign"), b"keep").unwrap();
    assert!(publish_pair(other.path(), &pair).is_err());
    assert_eq!(fs::read_dir(other.path()).unwrap().count(), 1);
    let empty = tempfile::tempdir().unwrap();
    for pair in [
        Case9DirectOracles { assumption_oracle: vec![], final_resolve_oracle: vec![1] },
        Case9DirectOracles { assumption_oracle: vec![1], final_resolve_oracle: vec![] },
        Case9DirectOracles { assumption_oracle: vec![1], final_resolve_oracle: vec![0; RECEIPT_ORACLE_MAX_BYTES + 1] },
    ] {
        assert!(publish_pair(empty.path(), &pair).is_err());
        assert_eq!(fs::read_dir(empty.path()).unwrap().count(), 0);
    }
}

#[test]
fn competing_file_publications_have_one_complete_winner() {
    let root = tempfile::tempdir().unwrap();
    let mut writers = Vec::new();
    for bytes in [b"first".to_vec(), b"second".to_vec()] {
        let path = root.path().to_owned();
        writers.push(std::thread::spawn(move || publish_one(&path, OUTPUTS[0], &bytes).is_ok()));
    }
    let outcomes = writers.into_iter().map(|writer| writer.join().unwrap()).collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|success| **success).count(), 1);
    let bytes = fs::read(root.path().join(OUTPUTS[0])).unwrap();
    assert!(bytes == b"first" || bytes == b"second");
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
}

#[test]
#[ignore = "requires the exact retained Case9 source and a fresh empty output directory; conversion only"]
fn extract_retained_case9_oracles() {
    let source = PathBuf::from(std::env::var_os("EIP0045_CASE9_RETAINED_ROOT")
        .expect("retained Case9 root required"));
    let output = PathBuf::from(std::env::var_os("EIP0045_CASE9_EXTRACTION_OUT")
        .expect("fresh Case9 extraction output required"));
    assert!(source.is_absolute());
    require_empty_output(&output).unwrap();
    let inputs = INPUTS.iter().map(|(leaf, bytes, sha)|
        read_pinned(&source.join(leaf), *bytes, sha).unwrap()).collect::<Vec<_>>();
    let pair = extract_case9_direct_oracles(&inputs[0], &inputs[1], &inputs[2]).unwrap();
    publish_pair(&output, &pair).unwrap();
    let report = serde_json::json!({
        "scope": "retained-case9-direct-oracle-conversion",
        "source_sha256": INPUTS[0].2,
        "outputs": OUTPUTS.iter().zip([&pair.assumption_oracle, &pair.final_resolve_oracle])
            .map(|(path, bytes)| serde_json::json!({"path":path,"bytes":bytes.len(),
                "sha256":hex::encode(Sha256::digest(bytes))})).collect::<Vec<_>>(),
        "proof_verified": false,
        "provenance_authenticated": false,
    });
    println!("case9OracleExtraction={report}");
}

