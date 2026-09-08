//! Byte-exact proof-output manifest construction and validation.
//!
//! The tree is hashed twice to detect accidental additions, substitutions, or
//! same-length mutations during capture. B7 operators must still give the tool
//! exclusive access to a sealed export tree; this module is not a security
//! boundary against a malicious process racing path resolution on the same
//! host.

use std::fs::{self, File, Metadata};
use std::io::{BufReader, Read};
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One canonical entry in a `proof-output/` generation manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    /// Canonical POSIX path relative to the proof-output root.
    pub path: String,
    /// Canonical unsigned decimal byte length (`"0"` or no leading zero).
    pub length: String,
    /// Lowercase hexadecimal SHA-256 of the exact file bytes.
    pub sha256: String,
}

/// Canonically ordered inventory of regular proof-output files.
pub type ProofOutputManifest = Vec<ManifestEntry>;

/// Require the reserved generation root to exist as an ordinary, empty directory.
///
/// Even an empty child directory makes the root nonempty. This is deliberately
/// stricter than checking whether a generated file manifest would be empty.
///
/// # Errors
///
/// Returns an error if the root is missing, is not an ordinary directory, or
/// contains any entry.
pub fn require_empty_before_generation(root: impl AsRef<Path>) -> Result<()> {
    let root = root.as_ref();
    require_ordinary_directory(root, "proof-output root")?;

    let mut names = fs::read_dir(root)
        .with_context(|| format!("cannot read proof-output root {}", root.display()))?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .with_context(|| format!("cannot enumerate proof-output root {}", root.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    names.sort();

    if let Some(name) = names.first() {
        bail!(
            "proof-output root is not empty: contains {}",
            display_os_name(name)
        );
    }
    Ok(())
}

/// Build the canonical manifest of every regular file below `root`.
///
/// Directories are traversal containers and are not entries. Traversal never
/// follows symlinks or Windows reparse points.
///
/// # Errors
///
/// Returns an error for an unreadable or unsafe tree, a noncanonical path, a
/// special file, or a file that changes length while it is hashed.
pub fn build_proof_output_manifest(root: impl AsRef<Path>) -> Result<ProofOutputManifest> {
    let root = root.as_ref();
    require_ordinary_directory(root, "proof-output root")?;

    let first = build_manifest_snapshot(root)?;
    let second = build_manifest_snapshot(root)?;
    if first != second {
        bail!("proof-output tree changed between consecutive manifest snapshots");
    }
    Ok(second)
}

fn build_manifest_snapshot(root: &Path) -> Result<ProofOutputManifest> {
    let mut entries = Vec::new();
    collect_directory(root, root, &mut entries)?;
    entries.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    validate_manifest_shape(&entries)?;
    Ok(entries)
}

/// Rebuild and compare a proof-output manifest byte-for-byte at the field level.
///
/// # Errors
///
/// Returns an error when the expected manifest is malformed, the output tree
/// is unsafe, or any rebuilt entry differs from the expected entry.
pub fn validate_proof_output_manifest(
    root: impl AsRef<Path>,
    expected: &[ManifestEntry],
) -> Result<()> {
    validate_manifest_shape(expected)?;
    let actual = build_proof_output_manifest(root)?;

    if actual.len() != expected.len() {
        bail!(
            "proof-output manifest entry count mismatch: expected {}, actual {}",
            expected.len(),
            actual.len()
        );
    }
    for (index, (expected_entry, actual_entry)) in expected.iter().zip(&actual).enumerate() {
        if expected_entry != actual_entry {
            bail!(
                "proof-output manifest mismatch at index {index}: expected {expected_entry:?}, actual {actual_entry:?}"
            );
        }
    }
    Ok(())
}

/// Validate canonical field encodings, uniqueness, and strict ASCII path order.
///
/// # Errors
///
/// Returns an error for an unsafe path, noncanonical decimal or digest, or
/// entries that are duplicated or not strictly sorted.
pub fn validate_manifest_shape(entries: &[ManifestEntry]) -> Result<()> {
    let mut previous: Option<&str> = None;
    for (index, entry) in entries.iter().enumerate() {
        validate_relative_path(&entry.path)
            .with_context(|| format!("invalid manifest path at index {index}"))?;
        validate_decimal_u64(&entry.length)
            .with_context(|| format!("invalid byte length for {}", entry.path))?;
        validate_sha256(&entry.sha256)
            .with_context(|| format!("invalid SHA-256 for {}", entry.path))?;

        if let Some(previous) = previous
            && previous.as_bytes() >= entry.path.as_bytes()
        {
            bail!(
                "manifest paths are not in strict unsigned-ASCII order at index {index}: {previous} then {}",
                entry.path
            );
        }
        previous = Some(&entry.path);
    }
    Ok(())
}

fn collect_directory(root: &Path, directory: &Path, output: &mut Vec<ManifestEntry>) -> Result<()> {
    let mut children = fs::read_dir(directory)
        .with_context(|| format!("cannot read directory {}", directory.display()))?
        .map(|entry| {
            entry.with_context(|| format!("cannot enumerate directory {}", directory.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    children.sort_by_key(std::fs::DirEntry::file_name);

    for child in children {
        let file_name = child.file_name();
        let segment = file_name.to_str().with_context(|| {
            format!(
                "proof-output path contains a non-UTF-8 segment below {}",
                relative_parent(root, directory)
            )
        })?;
        validate_path_segment(segment).with_context(|| {
            format!(
                "unsafe proof-output path segment {segment:?} below {}",
                relative_parent(root, directory)
            )
        })?;

        let path = child.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("cannot inspect proof-output entry {}", path.display()))?;
        reject_link_or_reparse(&path, &metadata)?;

        if metadata.file_type().is_dir() {
            collect_directory(root, &path, output)?;
        } else if metadata.file_type().is_file() {
            let relative = canonical_relative_path(root, &path)?;
            let (length, sha256) = hash_regular_file(&path)?;
            output.push(ManifestEntry {
                path: relative,
                length: length.to_string(),
                sha256,
            });
        } else {
            bail!(
                "proof-output entry is neither a directory nor a regular file: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn hash_regular_file(path: &Path) -> Result<(u64, String)> {
    let file = File::open(path)
        .with_context(|| format!("cannot open proof-output file {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("cannot inspect open proof-output file {}", path.display()))?;
    reject_link_or_reparse(path, &metadata)?;
    if !metadata.file_type().is_file() {
        bail!(
            "proof-output entry is not a regular file: {}",
            path.display()
        );
    }

    let expected_length = metadata.len();
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut observed_length = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .with_context(|| format!("cannot hash proof-output file {}", path.display()))?;
        if count == 0 {
            break;
        }
        observed_length = observed_length
            .checked_add(count as u64)
            .context("proof-output file length overflow")?;
        hasher.update(&buffer[..count]);
    }
    if observed_length != expected_length {
        bail!(
            "proof-output file changed while hashing {}: metadata length {}, read length {}",
            path.display(),
            expected_length,
            observed_length
        );
    }
    Ok((observed_length, hex::encode(hasher.finalize())))
}

fn canonical_relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path.strip_prefix(root).with_context(|| {
        format!(
            "proof-output entry {} is outside root {}",
            path.display(),
            root.display()
        )
    })?;
    let mut segments = Vec::new();
    for component in relative.components() {
        let std::path::Component::Normal(segment) = component else {
            bail!("noncanonical proof-output path: {}", relative.display());
        };
        let segment = segment
            .to_str()
            .with_context(|| format!("non-UTF-8 proof-output path: {}", relative.display()))?;
        validate_path_segment(segment)?;
        segments.push(segment);
    }
    let canonical = segments.join("/");
    validate_relative_path(&canonical)?;
    Ok(canonical)
}

fn validate_relative_path(path: &str) -> Result<()> {
    if path.is_empty() {
        bail!("relative path is empty");
    }
    if !path.is_ascii() {
        bail!("relative path is not ASCII: {path:?}");
    }
    if path.starts_with('/') || path.contains('\\') {
        bail!("relative path uses an absolute or backslash form: {path:?}");
    }
    for segment in path.split('/') {
        validate_path_segment(segment)?;
    }
    Ok(())
}

fn validate_path_segment(segment: &str) -> Result<()> {
    let bytes = segment.as_bytes();
    if bytes.is_empty() {
        bail!("path segment is empty");
    }
    if !matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9') {
        bail!("path segment must start with lowercase ASCII or a digit: {segment:?}");
    }
    if !bytes
        .iter()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
    {
        bail!("path segment contains an unsafe byte: {segment:?}");
    }
    Ok(())
}

fn validate_decimal_u64(value: &str) -> Result<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("value is not an unsigned decimal string: {value:?}");
    }
    if value.len() > 1 && value.starts_with('0') {
        bail!("value has a leading zero: {value:?}");
    }
    value
        .parse::<u64>()
        .with_context(|| format!("value is outside u64 range: {value:?}"))
}

fn validate_sha256(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        bail!("value is not a lowercase 32-byte hexadecimal digest: {value:?}");
    }
    Ok(())
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

fn relative_parent(root: &Path, directory: &Path) -> String {
    match directory.strip_prefix(root) {
        Ok(relative) if relative.as_os_str().is_empty() => ".".to_owned(),
        Ok(relative) => relative.to_string_lossy().replace('\\', "/"),
        Err(_) => directory.display().to_string(),
    }
}

fn display_os_name(name: &std::ffi::OsStr) -> String {
    name.to_str()
        .map_or_else(|| "<non-UTF-8-name>".to_owned(), |name| format!("{name:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::tempdir;

    #[test]
    fn builds_nested_manifest_in_ascii_order() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("proof-output");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("po2-15")).unwrap();
        fs::write(root.join("z.bin"), []).unwrap();
        fs::write(root.join("po2-15").join("seal.bin"), b"abc").unwrap();

        let manifest = build_proof_output_manifest(&root).unwrap();
        assert_eq!(
            manifest,
            vec![
                ManifestEntry {
                    path: "po2-15/seal.bin".to_owned(),
                    length: "3".to_owned(),
                    sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                        .to_owned(),
                },
                ManifestEntry {
                    path: "z.bin".to_owned(),
                    length: "0".to_owned(),
                    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        .to_owned(),
                },
            ]
        );
        validate_proof_output_manifest(&root, &manifest).unwrap();
    }

    #[test]
    fn empty_before_generation_rejects_even_empty_child_directory() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("proof-output");
        fs::create_dir(&root).unwrap();
        require_empty_before_generation(&root).unwrap();

        fs::create_dir(root.join("empty-child")).unwrap();
        let error = require_empty_before_generation(&root)
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            "proof-output root is not empty: contains \"empty-child\""
        );
    }

    #[test]
    fn rejects_unsafe_path_segment() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("proof-output");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("Upper.bin"), b"x").unwrap();

        let error = build_proof_output_manifest(&root).unwrap_err().to_string();
        assert!(error.contains("unsafe proof-output path segment \"Upper.bin\""));
    }

    #[test]
    fn rejects_noncanonical_manifest_fields_and_order() {
        let digest = "00".repeat(32);
        let bad_length = vec![ManifestEntry {
            path: "a.bin".to_owned(),
            length: "01".to_owned(),
            sha256: digest.clone(),
        }];
        assert!(
            validate_manifest_shape(&bad_length)
                .unwrap_err()
                .to_string()
                .contains("invalid byte length")
        );

        let bad_order = vec![
            ManifestEntry {
                path: "b.bin".to_owned(),
                length: "0".to_owned(),
                sha256: digest.clone(),
            },
            ManifestEntry {
                path: "a.bin".to_owned(),
                length: "0".to_owned(),
                sha256: digest,
            },
        ];
        assert!(
            validate_manifest_shape(&bad_order)
                .unwrap_err()
                .to_string()
                .contains("strict unsigned-ASCII order")
        );
    }

    #[test]
    fn consecutive_snapshots_detect_same_length_mutation_and_new_files() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("proof-output");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("seal.bin"), b"abc").unwrap();
        let first = build_manifest_snapshot(&root).unwrap();

        fs::write(root.join("seal.bin"), b"xyz").unwrap();
        fs::write(root.join("receipt.bin"), b"new").unwrap();
        let second = build_manifest_snapshot(&root).unwrap();

        assert_ne!(first, second);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let root = temp.path().join("proof-output");
        fs::create_dir(&root).unwrap();
        let outside = temp.path().join("outside.bin");
        fs::write(&outside, b"secret").unwrap();
        symlink(&outside, root.join("seal.bin")).unwrap();

        let error = build_proof_output_manifest(&root).unwrap_err().to_string();
        assert!(error.contains("symlink or reparse point is forbidden"));
    }
}
