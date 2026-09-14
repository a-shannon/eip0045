//! Test-only transport of exact local ancestry replay inputs, not campaign evidence.
//!
//! Each row contains the neutral three-file input and the separately observed
//! Rust output. Row labels and observations are never part of verifier input.
//! This codec checks byte bindings, not proofs, execution or source provenance.

use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path},
};

use anyhow::{Context, Result, ensure};
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::{
    b4_negative_io::{
        B4_NEGATIVE_VERIFIER_INPUT_FORMAT, B4_NEGATIVE_VERIFIER_INPUT_FORMAT_VERSION,
        B4NegativeFileEncoding, B4NegativeNamedIdentityV1, Eip0045B4NegativeVerifierInputV1,
    },
    b4_plan::{B4MaterializationDomain, B4NegativeExecutionSurface},
    canonical::canonical_json_bytes,
};

const MANIFEST: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin");
const MAX_SUBJECT: usize = 8 * 1024 * 1024;
const MAX_PACKET: usize = 64 * 1024 * 1024;
const MAX_SUBJECT_TOTAL: usize = MAX_PACKET / 2 - 65_536;
const ROW_COUNT: usize = 15;

pub(crate) type ReplayRow = (usize, Vec<u8>, Vec<u8>);

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn identity(role: &str, path: &str, bytes: &[u8]) -> B4NegativeNamedIdentityV1 {
    B4NegativeNamedIdentityV1 {
        role: role.into(),
        path: path.into(),
        byte_length: bytes.len() as u64,
        sha256: sha256(bytes),
        encoding: B4NegativeFileEncoding::RawBytes,
    }
}

fn neutral_source(subject: &[u8]) -> Result<Vec<u8>> {
    Eip0045B4NegativeVerifierInputV1 {
        format: B4_NEGATIVE_VERIFIER_INPUT_FORMAT.into(),
        format_version: B4_NEGATIVE_VERIFIER_INPUT_FORMAT_VERSION,
        materialization_domain: B4MaterializationDomain::VerifierInput,
        validation_surface: B4NegativeExecutionSurface::AncestryReplay,
        subject: identity("subject", "subject.bin", subject),
        context: vec![identity("context-00", "context/00.bin", MANIFEST)],
    }
    .to_canonical_jcs()
}

fn check_budget(lengths: impl IntoIterator<Item = usize>) -> Result<()> {
    let mut total = 0usize;
    for length in lengths {
        ensure!(
            (1..=MAX_SUBJECT).contains(&length),
            "local replay subject exceeds bounds"
        );
        total = total
            .checked_add(length)
            .context("local replay subject total overflow")?;
        ensure!(
            total <= MAX_SUBJECT_TOTAL,
            "local replay aggregate exceeds bound"
        );
    }
    Ok(())
}

fn require_observation(index: usize, subject: &[u8], input: &[u8], actual: &[u8]) -> Result<()> {
    let stage = match index {
        141..=143 => "claim-edge",
        144..=148 => "resolve-explicit-semantics",
        149..=152 => "resolve-zero-root-semantics",
        153..=155 => "resolve-assumption-inventory",
        _ => anyhow::bail!("local replay row outside fixed fifteen"),
    };
    // Literal wire oracle, independent of the production observation serializer.
    let expected = format!(
        concat!(
            "{{\"format\":\"Eip0045B4NegativeObservationV1\",\"formatVersion\":1,",
            "\"materializationDomain\":\"verifier-input\",\"negativeInputSha256\":\"{}\",",
            "\"rejection\":{{\"class\":\"ancestry-replay-mismatch\",\"stage\":\"{}\"}},",
            "\"subjectByteLength\":{},\"subjectSha256\":\"{}\",",
            "\"validationSurface\":\"ancestry-replay\",\"verdict\":\"reject\"}}"
        ),
        sha256(input),
        stage,
        subject.len(),
        sha256(subject)
    );
    ensure!(
        actual == expected.as_bytes(),
        "local replay observation differs from exact row/input binding"
    );
    Ok(())
}

pub(crate) fn encode_rows(rows: &[ReplayRow]) -> Result<Vec<u8>> {
    ensure!(
        rows.len() == ROW_COUNT,
        "local replay requires exactly fifteen rows"
    );
    ensure!(
        rows.iter()
            .enumerate()
            .all(|(position, row)| row.0 == 141 + position),
        "local replay row order differs"
    );
    check_budget(rows.iter().map(|row| row.1.len()))?;
    let mut encoded = Vec::with_capacity(ROW_COUNT);
    for (index, subject, observation) in rows {
        let input = neutral_source(subject)?;
        require_observation(*index, subject, &input, observation)?;
        encoded.push(json!({"row": index, "negativeInputHex": hex::encode(input),
            "subjectHex": hex::encode(subject), "contextHex": hex::encode(MANIFEST),
            "rustObservationHex": hex::encode(observation)}));
    }
    let result = canonical_json_bytes(&json!({
        "format": "Eip0045LocalAncestryReplayInputsV1", "formatVersion": 1,
        "scope": "local-replay-inputs-only", "rows": encoded,
    }))?;
    ensure!(
        result.len() <= MAX_PACKET,
        "local replay packet exceeds bound"
    );
    Ok(result)
}

fn redirected(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

/// Preserve a fully validated local packet without replacing any existing file.
/// This convenience writer does not establish authenticated filesystem custody.
pub(crate) fn write_new(path: &Path, rows: &[ReplayRow]) -> Result<()> {
    let bytes = encode_rows(rows)?; // Reject incomplete/private results before any filesystem mutation.
    ensure!(
        path.is_absolute() && !path.components().any(|p| p == Component::ParentDir),
        "local replay output requires an absolute normalized path"
    );
    let parent = path.parent().context("local replay output has no parent")?;
    for ancestor in parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        ensure!(
            metadata.is_dir() && !redirected(&metadata),
            "local replay output parent is redirected"
        );
    }
    match fs::symlink_metadata(path) {
        Ok(_) => anyhow::bail!("local replay output already exists"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary.as_file_mut().seek(SeekFrom::Start(0))?;
    let mut readback = Vec::new();
    temporary
        .as_file_mut()
        .take(MAX_PACKET as u64 + 1)
        .read_to_end(&mut readback)?;
    ensure!(readback == bytes, "local replay temporary readback differs");
    let file = temporary
        .persist_noclobber(path)
        .context("cannot preserve create-only local replay packet")?;
    ensure!(
        file.metadata()?.len() == bytes.len() as u64,
        "local replay preserved length differs"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<ReplayRow> {
        // Synthetic byte-transport tests, not genuine ancestry/proof execution.
        let stages = [
            "claim-edge",
            "claim-edge",
            "claim-edge",
            "resolve-explicit-semantics",
            "resolve-explicit-semantics",
            "resolve-explicit-semantics",
            "resolve-explicit-semantics",
            "resolve-explicit-semantics",
            "resolve-zero-root-semantics",
            "resolve-zero-root-semantics",
            "resolve-zero-root-semantics",
            "resolve-zero-root-semantics",
            "resolve-assumption-inventory",
            "resolve-assumption-inventory",
            "resolve-assumption-inventory",
        ];
        stages
            .iter()
            .enumerate()
            .map(|(position, stage)| {
                let index = 141 + position;
                let subject = vec![u8::try_from(index).unwrap(); 3];
                let input = neutral_source(&subject).unwrap();
                let observation = canonical_json_bytes(&json!({
                "format": "Eip0045B4NegativeObservationV1", "formatVersion": 1,
                "materializationDomain": "verifier-input", "negativeInputSha256": sha256(&input),
                "rejection": {"class": "ancestry-replay-mismatch", "stage": stage},
                "subjectByteLength": subject.len(), "subjectSha256": sha256(&subject),
                "validationSurface": "ancestry-replay", "verdict": "reject",
            })).unwrap();
                (index, subject, observation)
            })
            .collect()
    }

    #[test]
    fn exact_fifteen_rows_are_serialized_without_changing_subject_bytes() {
        let rows = fixture();
        let bytes = encode_rows(&rows).expect("exact local rows must be representable");
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(canonical_json_bytes(&value).unwrap(), bytes);
        assert_eq!(value["scope"], "local-replay-inputs-only");
        assert_eq!(value.as_object().unwrap().len(), 4);
        assert_eq!(value["rows"].as_array().unwrap().len(), 15);
        for (position, (index, subject, observation)) in rows.iter().enumerate() {
            let row = &value["rows"][position];
            assert_eq!(row.as_object().unwrap().len(), 5);
            assert_eq!(row["row"], *index);
            assert_eq!(
                hex::decode(row["subjectHex"].as_str().unwrap()).unwrap(),
                *subject
            );
            assert_eq!(
                hex::decode(row["contextHex"].as_str().unwrap()).unwrap(),
                MANIFEST
            );
            assert_eq!(
                hex::decode(row["rustObservationHex"].as_str().unwrap()).unwrap(),
                *observation
            );
            let input = hex::decode(row["negativeInputHex"].as_str().unwrap()).unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&input).unwrap();
            assert_eq!(parsed["subject"]["sha256"], sha256(subject));
            assert_eq!(parsed["context"][0]["sha256"], sha256(MANIFEST));
            assert_eq!(parsed.as_object().unwrap().len(), 6);
            assert!(parsed.get("row").is_none() && parsed.get("rejection").is_none());
        }
    }

    #[test]
    fn missing_extra_duplicate_reordered_and_out_of_range_rows_reject() {
        for fault in 0..5 {
            let mut rows = fixture();
            match fault {
                0 => {
                    rows.pop();
                }
                1 => rows.push(rows[0].clone()),
                2 => rows[1] = rows[0].clone(),
                3 => rows.swap(0, 1),
                4 => rows[0].0 = 140,
                _ => unreachable!(),
            }
            assert!(encode_rows(&rows).is_err(), "row fault {fault}");
        }
    }

    #[test]
    fn private_and_cross_bound_observations_reject() {
        for fault in 0..9 {
            let mut rows = fixture();
            let mut observation: serde_json::Value = serde_json::from_slice(&rows[0].2).unwrap();
            match fault {
                0 => rows[0].2.clear(),
                1 => rows[0].2.push(b'\n'),
                2 => rows[0].2 = rows[1].2.clone(),
                3 => rows[0].1[0] ^= 1,
                4 => observation["rejection"]["stage"] = json!("resolve-explicit-semantics"),
                5 => observation["rejection"]["class"] = json!("cryptographic-rejection"),
                6 => observation["negativeInputSha256"] = json!("0".repeat(64)),
                7 => observation["subjectByteLength"] = json!(4),
                8 => observation["verdict"] = json!("accept"),
                _ => unreachable!(),
            }
            if fault >= 4 {
                rows[0].2 = canonical_json_bytes(&observation).unwrap();
            }
            assert_eq!(
                encode_rows(&rows).unwrap_err().to_string(),
                "local replay observation differs from exact row/input binding",
                "observation fault {fault}"
            );
        }
    }

    #[test]
    fn exact_subject_and_aggregate_bounds_are_checked_before_encoding() {
        assert!(check_budget([1, MAX_SUBJECT]).is_ok());
        assert!(check_budget([0]).is_err());
        assert!(check_budget([MAX_SUBJECT + 1]).is_err());
        let remainder = MAX_SUBJECT_TOTAL - 3 * MAX_SUBJECT;
        assert!(check_budget([MAX_SUBJECT, MAX_SUBJECT, MAX_SUBJECT, remainder]).is_ok());
        assert!(check_budget([MAX_SUBJECT, MAX_SUBJECT, MAX_SUBJECT, remainder + 1]).is_err());
    }

    #[test]
    fn create_only_writer_preserves_exact_complete_bytes() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("replay.json");
        let rows = fixture();
        write_new(&path, &rows).unwrap();
        assert_eq!(fs::read(&path).unwrap(), encode_rows(&rows).unwrap());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
        assert!(write_new(&path, &rows).is_err());
        assert_eq!(fs::read(&path).unwrap(), encode_rows(&rows).unwrap());
    }

    #[test]
    fn incomplete_or_failed_rows_leave_no_output_or_temporary_file() {
        for fault in 0..2 {
            let root = tempfile::tempdir().unwrap();
            let mut rows = fixture();
            if fault == 0 {
                rows.pop();
            } else {
                rows[14].2.clear();
            }
            assert!(write_new(&root.path().join("replay.json"), &rows).is_err());
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn existing_file_directory_and_relative_output_are_not_replaced() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("existing");
        fs::write(&path, b"retained").unwrap();
        let rows = fixture();
        assert!(write_new(&path, &rows).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"retained");
        assert!(write_new(root.path(), &rows).is_err());
        assert!(write_new(Path::new("relative-replay.json"), &rows).is_err());
        assert!(write_new(&root.path().join("missing/replay.json"), &rows).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn parent_and_leaf_redirects_are_not_followed() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let physical = root.path().join("physical");
        fs::create_dir(&physical).unwrap();
        let alias = root.path().join("alias");
        symlink(&physical, &alias).unwrap();
        let leaf = root.path().join("leaf");
        symlink(physical.join("absent.json"), &leaf).unwrap();
        let rows = fixture();
        assert!(write_new(&alias.join("replay.json"), &rows).is_err());
        assert!(write_new(&leaf, &rows).is_err());
        assert_eq!(fs::read_dir(&physical).unwrap().count(), 0);
    }
}
