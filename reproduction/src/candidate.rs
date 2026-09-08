//! Candidate-artifact quarantine and completeness checks.

use std::fs::{self, File, Metadata};
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonical::validate_canonical_json_source;

/// Required byte-level encoding for one candidate artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateEncoding {
    /// Opaque bytes with no additional serialization constraint.
    RawBytes,
    /// Exact UTF-8 RFC 8785 JSON Canonicalization Scheme bytes.
    Rfc8785Jcs,
}

/// One candidate artifact committed by the candidate-corpus manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateArtifact {
    /// Required byte encoding, checked independently of the digest.
    pub encoding: CandidateEncoding,
    /// Canonical repository-relative path.
    pub path: String,
    /// Lowercase hexadecimal SHA-256 of the exact artifact bytes.
    pub sha256: String,
}

/// Evidence-only candidate inventory. It is never a final reproduction schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateCorpusManifest {
    /// Complete, canonically ordered inventory of files below the quarantine root.
    pub artifacts: Vec<CandidateArtifact>,
}

/// Enforce the boundary between candidate material and final-looking artifacts.
///
/// `quarantine_root` is a canonical repository-relative directory such as
/// `reproduction/schema`. Every regular file below it must be listed exactly
/// once in `manifest`, while the manifest itself remains outside quarantine.
/// The guard also rejects final reproduction records during the candidate phase
/// and scans final-looking files for candidate path or digest references.
///
/// # Errors
///
/// Returns an error for an unsafe repository layout, an incomplete or invalid
/// candidate manifest, any final artifact present during the candidate phase,
/// or any candidate material leaked into a final-looking location.
pub fn validate_candidate_quarantine(
    repository_root: impl AsRef<Path>,
    quarantine_root: &str,
    manifest: &CandidateCorpusManifest,
) -> Result<()> {
    let repository_root = repository_root.as_ref();
    require_ordinary_directory(repository_root, "repository root")?;
    validate_relative_path(quarantine_root)
        .context("candidate quarantine root is not canonical")?;
    let quarantine_path = repository_root.join(path_from_posix(quarantine_root));
    require_ordinary_directory(&quarantine_path, "candidate quarantine root")?;

    validate_candidate_manifest(repository_root, quarantine_root, manifest)?;
    require_complete_candidate_manifest(repository_root, &quarantine_path, manifest)?;
    reject_reserved_final_artifacts(repository_root, &quarantine_path)?;
    reject_candidate_references_in_final_files(repository_root, &quarantine_path, manifest)?;
    Ok(())
}

fn require_complete_candidate_manifest(
    repository_root: &Path,
    quarantine_path: &Path,
    manifest: &CandidateCorpusManifest,
) -> Result<()> {
    let mut actual = Vec::new();
    collect_candidate_files(repository_root, quarantine_path, &mut actual)?;
    actual.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

    let expected = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect::<Vec<_>>();
    let mut expected_index = 0;
    for actual_path in &actual {
        while expected_index < expected.len()
            && expected[expected_index].as_bytes() < actual_path.as_bytes()
        {
            expected_index += 1;
        }
        if expected.get(expected_index).copied() != Some(actual_path.as_str()) {
            bail!("unlisted candidate artifact below quarantine root: {actual_path}");
        }
        expected_index += 1;
    }

    if actual.len() != expected.len() {
        bail!(
            "candidate corpus manifest is not closed over the quarantine root: expected {} entries, found {} files",
            expected.len(),
            actual.len()
        );
    }
    Ok(())
}

fn collect_candidate_files(
    repository_root: &Path,
    directory: &Path,
    output: &mut Vec<String>,
) -> Result<()> {
    let metadata = fs::symlink_metadata(directory)
        .with_context(|| format!("cannot inspect candidate path {}", directory.display()))?;
    reject_link_or_reparse(directory, &metadata)?;
    if !metadata.file_type().is_dir() {
        bail!(
            "candidate traversal root is not a directory: {}",
            directory.display()
        );
    }

    let mut children = fs::read_dir(directory)
        .with_context(|| format!("cannot read candidate directory {}", directory.display()))?
        .map(|entry| {
            entry.with_context(|| format!("cannot enumerate directory {}", directory.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    for child in children {
        let path = child.path();
        let relative = repository_relative(repository_root, &path)?;
        validate_relative_path(&relative)
            .with_context(|| format!("invalid candidate quarantine path {relative:?}"))?;
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("cannot inspect candidate entry {}", path.display()))?;
        reject_link_or_reparse(&path, &metadata)?;
        if metadata.file_type().is_dir() {
            collect_candidate_files(repository_root, &path, output)?;
        } else if metadata.file_type().is_file() {
            output.push(relative);
        } else {
            bail!(
                "candidate entry is neither a directory nor a regular file: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn validate_candidate_manifest(
    repository_root: &Path,
    quarantine_root: &str,
    manifest: &CandidateCorpusManifest,
) -> Result<()> {
    let required_prefix = format!("{quarantine_root}/");
    let mut previous: Option<&str> = None;
    for (index, artifact) in manifest.artifacts.iter().enumerate() {
        validate_relative_path(&artifact.path)
            .with_context(|| format!("invalid candidate path at index {index}"))?;
        validate_sha256(&artifact.sha256)
            .with_context(|| format!("invalid candidate digest for {}", artifact.path))?;
        if !artifact.path.starts_with(&required_prefix) {
            bail!(
                "candidate artifact escapes quarantine root {quarantine_root}: {}",
                artifact.path
            );
        }
        if let Some(previous) = previous
            && previous.as_bytes() >= artifact.path.as_bytes()
        {
            bail!(
                "candidate artifact paths are not in strict unsigned-ASCII order at index {index}: {previous} then {}",
                artifact.path
            );
        }
        previous = Some(&artifact.path);

        let path = repository_root.join(path_from_posix(&artifact.path));
        let metadata = fs::symlink_metadata(&path).with_context(|| {
            format!(
                "candidate artifact is missing or unreadable: {}",
                artifact.path
            )
        })?;
        reject_link_or_reparse(&path, &metadata)?;
        if !metadata.file_type().is_file() {
            bail!(
                "candidate artifact is not a regular file: {}",
                artifact.path
            );
        }
        let actual = sha256_file(&path)?;
        if actual != artifact.sha256 {
            bail!(
                "candidate artifact digest mismatch for {}: expected {}, actual {}",
                artifact.path,
                artifact.sha256,
                actual
            );
        }
        if artifact.encoding == CandidateEncoding::Rfc8785Jcs {
            let bytes = fs::read(&path)
                .with_context(|| format!("cannot read canonical candidate {}", artifact.path))?;
            validate_canonical_json_source(&bytes).with_context(|| {
                format!(
                    "candidate artifact is not exact RFC 8785 JCS: {}",
                    artifact.path
                )
            })?;
        }
    }
    Ok(())
}

fn reject_reserved_final_artifacts(repository_root: &Path, quarantine_path: &Path) -> Result<()> {
    let reproduction = repository_root.join("reproduction");
    if !reproduction.exists() {
        return Ok(());
    }

    let mut files = Vec::new();
    collect_regular_files(repository_root, &reproduction, quarantine_path, &mut files)?;
    files.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    for (relative, _) in files {
        if let Some(kind) = reserved_final_kind(&relative) {
            bail!("candidate phase forbids {kind}: {relative}");
        }
    }
    Ok(())
}

fn reject_candidate_references_in_final_files(
    repository_root: &Path,
    quarantine_path: &Path,
    manifest: &CandidateCorpusManifest,
) -> Result<()> {
    let mut references = manifest
        .artifacts
        .iter()
        .flat_map(|artifact| {
            [
                ("candidate path", artifact.path.to_ascii_lowercase()),
                ("candidate digest", artifact.sha256.clone()),
            ]
        })
        .collect::<Vec<_>>();
    references.sort_by(|left, right| left.1.as_bytes().cmp(right.1.as_bytes()));
    references.dedup_by(|left, right| left.1 == right.1);

    let mut final_files = Vec::new();
    for relative_root in FINAL_LOOKING_ROOTS {
        let root = repository_root.join(path_from_posix(relative_root));
        if root.exists() && !root.starts_with(quarantine_path) {
            collect_regular_files(repository_root, &root, quarantine_path, &mut final_files)?;
        }
    }
    for exact_file in FINAL_LOOKING_FILES {
        let path = repository_root.join(path_from_posix(exact_file));
        if path.exists() && !path.starts_with(quarantine_path) {
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("cannot inspect final-looking file {exact_file}"))?;
            reject_link_or_reparse(&path, &metadata)?;
            if metadata.file_type().is_file() {
                final_files.push(((*exact_file).to_owned(), path));
            }
        }
    }
    final_files.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    final_files.dedup_by(|left, right| left.0 == right.0);

    for (relative, path) in final_files {
        let final_digest = sha256_file(&path)?;
        if let Some(candidate) = manifest
            .artifacts
            .iter()
            .find(|candidate| candidate.sha256 == final_digest)
        {
            bail!(
                "candidate artifact bytes promoted into final-looking file {relative}: {}",
                candidate.path
            );
        }
        let bytes = fs::read(&path)
            .with_context(|| format!("cannot scan final-looking file {relative}"))?;
        for candidate in &manifest.artifacts {
            let raw_digest = hex::decode(&candidate.sha256)
                .context("validated candidate digest failed to decode")?;
            if contains_bytes(&bytes, &raw_digest) {
                bail!(
                    "raw candidate digest leaked into final-looking file {relative}: {}",
                    candidate.path
                );
            }
        }
        let lowercase = ascii_lowercase(&bytes);
        for (kind, reference) in &references {
            if contains_bytes(&lowercase, reference.as_bytes()) {
                bail!(
                    "forbidden {kind} reference leaked into final-looking file {relative}: {reference}"
                );
            }
        }
    }
    Ok(())
}

const FINAL_LOOKING_ROOTS: &[&str] = &[
    "activation",
    "contracts",
    "evidence/b7-freshness",
    "methods",
    "profiles",
    "reproduction/frozen",
    "vectors",
];

const FINAL_LOOKING_FILES: &[&str] = &["reproduction/LOCK.json", "reproduction/schema-v1.json"];

fn reserved_final_kind(relative: &str) -> Option<&'static str> {
    let lower = relative.to_ascii_lowercase();
    if lower == "reproduction/lock.json" {
        return Some("final reproduction lock");
    }
    if lower == "reproduction/schema-v1.json" {
        return Some("final reproduction schema");
    }
    if lower.starts_with("reproduction/runs/") {
        let name = lower.rsplit('/').next().unwrap_or_default();
        return match name {
            "runprecommitv1.json" => Some("final run precommit"),
            "runevidencev1.json" => Some("final run evidence"),
            "runevidencev1.sig" => Some("final run evidence signature"),
            _ => None,
        };
    }
    None
}

fn collect_regular_files(
    repository_root: &Path,
    directory: &Path,
    quarantine_path: &Path,
    output: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    if directory.starts_with(quarantine_path) {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(directory)
        .with_context(|| format!("cannot inspect repository path {}", directory.display()))?;
    reject_link_or_reparse(directory, &metadata)?;
    if metadata.file_type().is_file() {
        output.push((
            repository_relative(repository_root, directory)?,
            directory.to_owned(),
        ));
        return Ok(());
    }
    if !metadata.file_type().is_dir() {
        bail!(
            "repository path is neither a directory nor a regular file: {}",
            directory.display()
        );
    }

    let mut children = fs::read_dir(directory)
        .with_context(|| format!("cannot read repository directory {}", directory.display()))?
        .map(|entry| {
            entry.with_context(|| format!("cannot enumerate directory {}", directory.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    for child in children {
        let path = child.path();
        if path.starts_with(quarantine_path) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("cannot inspect repository entry {}", path.display()))?;
        reject_link_or_reparse(&path, &metadata)?;
        if metadata.file_type().is_dir() {
            collect_regular_files(repository_root, &path, quarantine_path, output)?;
        } else if metadata.file_type().is_file() {
            output.push((repository_relative(repository_root, &path)?, path));
        } else {
            bail!(
                "repository entry is neither a directory nor a regular file: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let file = File::open(path)
        .with_context(|| format!("cannot open candidate artifact {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("cannot inspect candidate artifact {}", path.display()))?;
    reject_link_or_reparse(path, &metadata)?;
    if !metadata.file_type().is_file() {
        bail!(
            "candidate artifact is not a regular file: {}",
            path.display()
        );
    }

    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .with_context(|| format!("cannot hash candidate artifact {}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn repository_relative(repository_root: &Path, path: &Path) -> Result<String> {
    let relative = path.strip_prefix(repository_root).with_context(|| {
        format!(
            "repository path {} is outside root {}",
            path.display(),
            repository_root.display()
        )
    })?;
    let mut segments = Vec::new();
    for component in relative.components() {
        let std::path::Component::Normal(segment) = component else {
            bail!("noncanonical repository path: {}", relative.display());
        };
        let segment = segment
            .to_str()
            .with_context(|| format!("non-UTF-8 repository path: {}", relative.display()))?;
        segments.push(segment);
    }
    Ok(segments.join("/"))
}

fn validate_relative_path(path: &str) -> Result<()> {
    if path.is_empty() || !path.is_ascii() || path.starts_with('/') || path.contains('\\') {
        bail!("path is not canonical repository-relative ASCII: {path:?}");
    }
    for segment in path.split('/') {
        let bytes = segment.as_bytes();
        if bytes.is_empty()
            || !matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9')
            || !bytes
                .iter()
                .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
        {
            bail!("path contains an unsafe segment: {path:?}");
        }
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        bail!("digest is not lowercase 32-byte hexadecimal: {value:?}");
    }
    Ok(())
}

fn path_from_posix(path: &str) -> PathBuf {
    path.split('/').collect()
}

fn ascii_lowercase(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(u8::to_ascii_lowercase).collect()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn require_ordinary_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "{label} does not exist or cannot be inspected: {}",
            path.display()
        )
    })?;
    reject_link_or_reparse(path, &metadata)?;
    if !metadata.file_type().is_dir() {
        bail!("{label} is not a directory: {}", path.display());
    }
    Ok(())
}

fn reject_link_or_reparse(path: &Path, metadata: &Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || is_windows_reparse_point(metadata) {
        bail!("symlink or reparse point is forbidden: {}", path.display());
    }
    Ok(())
}

#[cfg(windows)]
fn is_windows_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_windows_reparse_point(_metadata: &Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn artifact(path: &str, bytes: &[u8]) -> CandidateArtifact {
        CandidateArtifact {
            encoding: CandidateEncoding::RawBytes,
            path: path.to_owned(),
            sha256: hex::encode(Sha256::digest(bytes)),
        }
    }

    fn setup_repository() -> tempfile::TempDir {
        let temp = tempdir().unwrap();
        for directory in [
            "activation",
            "contracts",
            "methods",
            "profiles",
            "reproduction",
            "reproduction/schema",
            "vectors",
        ] {
            fs::create_dir_all(temp.path().join(path_from_posix(directory))).unwrap();
        }
        temp
    }

    #[test]
    fn accepts_sorted_digest_bound_candidate_artifacts_in_quarantine() {
        let repo = setup_repository();
        let first_path = "reproduction/schema/run-a/archive.bin";
        let second_path = "reproduction/schema/run-a/generated.bin";
        fs::create_dir_all(repo.path().join("reproduction/schema/run-a")).unwrap();
        fs::write(repo.path().join(path_from_posix(first_path)), b"archive").unwrap();
        fs::write(repo.path().join(path_from_posix(second_path)), b"generated").unwrap();
        fs::write(
            repo.path().join("reproduction/candidate-corpus.json"),
            b"{}",
        )
        .unwrap();
        let manifest = CandidateCorpusManifest {
            artifacts: vec![
                artifact(first_path, b"archive"),
                artifact(second_path, b"generated"),
            ],
        };

        validate_candidate_quarantine(repo.path(), "reproduction/schema", &manifest).unwrap();
    }

    #[test]
    fn rejects_candidate_artifact_outside_quarantine() {
        let repo = setup_repository();
        let path = "vectors/candidate.bin";
        fs::write(repo.path().join(path_from_posix(path)), b"candidate").unwrap();
        let manifest = CandidateCorpusManifest {
            artifacts: vec![artifact(path, b"candidate")],
        };

        let error = validate_candidate_quarantine(repo.path(), "reproduction/schema", &manifest)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "candidate artifact escapes quarantine root reproduction/schema: vectors/candidate.bin"
        );
    }

    #[test]
    fn rejects_unlisted_file_below_quarantine_root() {
        let repo = setup_repository();
        fs::write(
            repo.path()
                .join("reproduction/schema/schema-v1.candidate.json"),
            b"{}",
        )
        .unwrap();
        let manifest = CandidateCorpusManifest { artifacts: vec![] };

        let error = validate_candidate_quarantine(repo.path(), "reproduction/schema", &manifest)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "unlisted candidate artifact below quarantine root: reproduction/schema/schema-v1.candidate.json"
        );
    }

    #[test]
    fn rejects_noncanonical_json_when_candidate_encoding_requires_jcs() {
        for invalid in [
            br#"{"a":1}
"#
            .as_slice(),
            br#"{"a":1,"a":2}"#.as_slice(),
        ] {
            let repo = setup_repository();
            let path = "reproduction/schema/schema-v1.candidate.json";
            fs::write(repo.path().join(path_from_posix(path)), invalid).unwrap();
            let mut candidate = artifact(path, invalid);
            candidate.encoding = CandidateEncoding::Rfc8785Jcs;
            let manifest = CandidateCorpusManifest {
                artifacts: vec![candidate],
            };

            let error =
                validate_candidate_quarantine(repo.path(), "reproduction/schema", &manifest)
                    .unwrap_err();
            assert!(format!("{error:#}").contains("candidate artifact is not exact RFC 8785 JCS"));
        }
    }

    #[test]
    fn rejects_final_schema_during_candidate_phase() {
        let repo = setup_repository();
        fs::write(repo.path().join("reproduction/schema-v1.json"), b"{}").unwrap();
        let manifest = CandidateCorpusManifest { artifacts: vec![] };

        let error = validate_candidate_quarantine(repo.path(), "reproduction/schema", &manifest)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "candidate phase forbids final reproduction schema: reproduction/schema-v1.json"
        );
    }

    #[test]
    fn rejects_final_run_artifact_during_candidate_phase() {
        let repo = setup_repository();
        fs::create_dir_all(repo.path().join("reproduction/runs/run-a")).unwrap();
        fs::write(
            repo.path()
                .join("reproduction/runs/run-a/RunEvidenceV1.json"),
            b"{}",
        )
        .unwrap();
        let manifest = CandidateCorpusManifest { artifacts: vec![] };

        let error = validate_candidate_quarantine(repo.path(), "reproduction/schema", &manifest)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "candidate phase forbids final run evidence: reproduction/runs/run-a/RunEvidenceV1.json"
        );
    }

    #[test]
    fn rejects_lock_precommit_and_run_signature_during_candidate_phase() {
        for (relative, expected_kind) in [
            ("reproduction/LOCK.json", "final reproduction lock"),
            (
                "reproduction/runs/run-a/RunPrecommitV1.json",
                "final run precommit",
            ),
            (
                "reproduction/runs/run-a/RunEvidenceV1.sig",
                "final run evidence signature",
            ),
        ] {
            let repo = setup_repository();
            let path = repo.path().join(path_from_posix(relative));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"{}").unwrap();
            let manifest = CandidateCorpusManifest { artifacts: vec![] };

            let error =
                validate_candidate_quarantine(repo.path(), "reproduction/schema", &manifest)
                    .unwrap_err()
                    .to_string();
            assert_eq!(
                error,
                format!("candidate phase forbids {expected_kind}: {relative}")
            );
        }
    }

    #[test]
    fn rejects_candidate_path_and_digest_leaks_in_final_looking_files() {
        let repo = setup_repository();
        let candidate_path = "reproduction/schema/run-a/seal.bin";
        let bytes = b"candidate seal";
        fs::create_dir_all(repo.path().join("reproduction/schema/run-a")).unwrap();
        fs::write(repo.path().join(path_from_posix(candidate_path)), bytes).unwrap();
        let candidate = artifact(candidate_path, bytes);
        let manifest = CandidateCorpusManifest {
            artifacts: vec![candidate.clone()],
        };

        fs::write(
            repo.path().join("vectors/manifest.json"),
            format!("{{\"source\":\"{}\"}}", candidate.path),
        )
        .unwrap();
        let path_error =
            validate_candidate_quarantine(repo.path(), "reproduction/schema", &manifest)
                .unwrap_err()
                .to_string();
        assert_eq!(
            path_error,
            format!(
                "forbidden candidate path reference leaked into final-looking file vectors/manifest.json: {}",
                candidate.path
            )
        );

        fs::write(
            repo.path().join("vectors/manifest.json"),
            format!("{{\"sha256\":\"{}\"}}", candidate.sha256),
        )
        .unwrap();
        let digest_error =
            validate_candidate_quarantine(repo.path(), "reproduction/schema", &manifest)
                .unwrap_err()
                .to_string();
        assert_eq!(
            digest_error,
            format!(
                "forbidden candidate digest reference leaked into final-looking file vectors/manifest.json: {}",
                candidate.sha256
            )
        );
    }

    #[test]
    fn rejects_candidate_bytes_promoted_under_a_different_final_name() {
        let repo = setup_repository();
        let candidate_path = "reproduction/schema/run-a/seal.bin";
        let bytes = b"candidate seal";
        fs::create_dir_all(repo.path().join("reproduction/schema/run-a")).unwrap();
        fs::write(repo.path().join(path_from_posix(candidate_path)), bytes).unwrap();
        fs::write(repo.path().join("vectors/final-vector.bin"), bytes).unwrap();
        let manifest = CandidateCorpusManifest {
            artifacts: vec![artifact(candidate_path, bytes)],
        };

        let error = validate_candidate_quarantine(repo.path(), "reproduction/schema", &manifest)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "candidate artifact bytes promoted into final-looking file vectors/final-vector.bin: reproduction/schema/run-a/seal.bin"
        );
    }

    #[test]
    fn rejects_raw_candidate_digest_embedded_in_a_final_binary() {
        let repo = setup_repository();
        let candidate_path = "reproduction/schema/run-a/seal.bin";
        let bytes = b"candidate seal";
        fs::create_dir_all(repo.path().join("reproduction/schema/run-a")).unwrap();
        fs::write(repo.path().join(path_from_posix(candidate_path)), bytes).unwrap();
        let candidate = artifact(candidate_path, bytes);
        let raw_digest = hex::decode(&candidate.sha256).unwrap();
        let mut final_bytes = b"binary-prefix".to_vec();
        final_bytes.extend_from_slice(&raw_digest);
        final_bytes.extend_from_slice(b"binary-suffix");
        fs::write(repo.path().join("vectors/final-vector.bin"), final_bytes).unwrap();
        let manifest = CandidateCorpusManifest {
            artifacts: vec![candidate],
        };

        let error = validate_candidate_quarantine(repo.path(), "reproduction/schema", &manifest)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "raw candidate digest leaked into final-looking file vectors/final-vector.bin: reproduction/schema/run-a/seal.bin"
        );
    }

    #[test]
    fn rejects_wrong_candidate_digest_deterministically() {
        let repo = setup_repository();
        let path = "reproduction/schema/run-a/seal.bin";
        fs::create_dir_all(repo.path().join("reproduction/schema/run-a")).unwrap();
        fs::write(repo.path().join(path_from_posix(path)), b"actual").unwrap();
        let manifest = CandidateCorpusManifest {
            artifacts: vec![CandidateArtifact {
                encoding: CandidateEncoding::RawBytes,
                path: path.to_owned(),
                sha256: "00".repeat(32),
            }],
        };

        let error = validate_candidate_quarantine(repo.path(), "reproduction/schema", &manifest)
            .unwrap_err()
            .to_string();
        assert!(error.starts_with(&format!(
            "candidate artifact digest mismatch for {path}: expected {}",
            "00".repeat(32)
        )));
    }
}
