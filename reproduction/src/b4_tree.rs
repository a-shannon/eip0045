//! Closed tree manifest and terminal lock for an EIP-0045 B4 corpus.
//!
//! The tree manifest inventories every directory and regular file below one
//! corpus root except its own exact file and the terminal lock. The lock is
//! generated last and binds that manifest plus the expanded registry and
//! semantic report. The serializable lock is structural only at this phase.
//! Its production authority/finalizer constructor remains unavailable until
//! the semantic report is backed by opaque physical-run authorities.
//!
//! The legacy raw-report lock helpers are deliberately absent from production:
//!
//! ```compile_fail
//! use eip_0045_reproduction::b4_tree::{create_b4_lock, verify_b4_lock};
//! ```
//!
//! File hashing rejects every Windows reparse point. On Unix it additionally
//! binds `dev+ino` across path/open/post-read observations and requires a link
//! count of one. Rust's stable Windows metadata API does not expose an
//! equivalent file index or link count; concurrent-writer and Windows hard-link
//! exclusion therefore belong to the separate controlled-staging finalizer.

use std::collections::BTreeSet;
use std::fs::{self, File, Metadata};
use std::io::{BufReader, Read};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::canonical::{canonical_json_bytes, validate_canonical_json_source};

/// Exact tree-manifest format discriminator.
pub const B4_TREE_MANIFEST_FORMAT: &str = "Eip0045B4TreeManifestV1";
/// Exact tree-manifest format version.
pub const B4_TREE_MANIFEST_FORMAT_VERSION: u8 = 1;
/// Exact terminal-lock format discriminator.
pub const B4_LOCK_FORMAT: &str = "Eip0045B4LockV1";
/// Exact terminal-lock format version.
pub const B4_LOCK_FORMAT_VERSION: u8 = 1;
/// Reserved manifest path relative to the corpus root.
pub const B4_TREE_MANIFEST_PATH: &str = "tree-manifest.json";
/// Reserved lock path relative to the corpus root.
pub const B4_LOCK_PATH: &str = "LOCK.json";

const MAX_TREE_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_LOCK_BYTES: usize = 64 * 1024;
const MAX_TREE_ENTRIES: usize = 16 * 1024;
const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_TOTAL_FILE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 512;
const HASH_BUFFER_BYTES: usize = 64 * 1024;
const CORPUS_ID_DOMAIN: &[u8] = b"EIP0045_B4_CORPUS_V1\0";

/// One exact entry in the closed corpus tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "entryType",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum B4TreeEntryV1 {
    /// An ordinary directory. The corpus root itself is implicit.
    Directory {
        /// Canonical path relative to the corpus root.
        path: String,
    },
    /// An ordinary regular file bound by length and SHA-256.
    File {
        /// Exact byte length.
        byte_length: u64,
        /// Canonical path relative to the corpus root.
        path: String,
        /// Lowercase SHA-256 of the exact file bytes.
        sha256: String,
    },
}

impl B4TreeEntryV1 {
    fn path(&self) -> &str {
        match self {
            Self::Directory { path } | Self::File { path, .. } => path,
        }
    }
}

/// Exact, non-self-referential inventory of a B4 corpus tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Eip0045B4TreeManifestV1 {
    /// Exact format discriminator.
    pub format: String,
    /// Exact format version.
    pub format_version: u8,
    /// Strictly ordered complete entry inventory.
    pub entries: Vec<B4TreeEntryV1>,
    /// Exact number of directory entries.
    pub directory_count: u32,
    /// Exact number of regular-file entries.
    pub file_count: u32,
    /// Checked sum of every regular-file byte length.
    pub total_file_bytes: u64,
}

impl Eip0045B4TreeManifestV1 {
    /// Parse exact RFC 8785 JCS and validate internal tree-manifest closure.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, noncanonical, duplicate-key,
    /// unknown-field, unsafe, incorrectly ordered, or inconsistent input.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            source.len() <= MAX_TREE_MANIFEST_BYTES,
            "B4 tree manifest exceeds its canonical-byte bound"
        );
        let value = validate_canonical_json_source(source)
            .context("B4 tree manifest is not exact RFC 8785 JCS")?;
        let manifest: Self =
            serde_json::from_value(value).context("invalid B4 tree-manifest shape")?;
        manifest.validate()?;
        ensure!(
            manifest.to_canonical_jcs()? == source,
            "B4 tree manifest does not round-trip byte-exactly"
        );
        Ok(manifest)
    }

    /// Serialize this manifest to exact RFC 8785 JCS bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid or oversized manifest.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value = serde_json::to_value(self).context("cannot serialize B4 tree manifest")?;
        let bytes = canonical_json_bytes(&value)?;
        ensure!(
            bytes.len() <= MAX_TREE_MANIFEST_BYTES,
            "B4 tree manifest exceeds its canonical-byte bound"
        );
        Ok(bytes)
    }

    /// Validate ordering, paths, identities, census, and arithmetic.
    ///
    /// # Errors
    ///
    /// Returns an error for any internal V1 invariant violation.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == B4_TREE_MANIFEST_FORMAT,
            "wrong B4 tree-manifest format label"
        );
        ensure!(
            self.format_version == B4_TREE_MANIFEST_FORMAT_VERSION,
            "wrong B4 tree-manifest format version"
        );
        ensure!(
            !self.entries.is_empty() && self.entries.len() <= MAX_TREE_ENTRIES,
            "B4 tree-manifest entry count is outside the V1 bound"
        );

        let mut previous: Option<&str> = None;
        let mut casefolded = BTreeSet::new();
        let mut directories = 0_u32;
        let mut files = 0_u32;
        let mut total = 0_u64;
        let mut known_directories = BTreeSet::new();
        for (index, entry) in self.entries.iter().enumerate() {
            let path = entry.path();
            validate_relative_path(path)?;
            reject_reserved_tree_path(path)?;
            if let Some(previous) = previous {
                ensure!(
                    previous.as_bytes() < path.as_bytes(),
                    "B4 tree paths are duplicate or unsorted at index {index}"
                );
            }
            previous = Some(path);
            ensure!(
                casefolded.insert(path.to_ascii_lowercase()),
                "B4 tree contains an ASCII-case-fold path collision at index {index}"
            );

            if let Some(parent) = parent_path(path) {
                ensure!(
                    known_directories.contains(parent),
                    "B4 tree entry appears before or without its parent directory: {path}"
                );
            }
            match entry {
                B4TreeEntryV1::Directory { .. } => {
                    directories = directories
                        .checked_add(1)
                        .context("B4 directory census overflows u32")?;
                    ensure!(
                        known_directories.insert(path),
                        "duplicate B4 directory path"
                    );
                }
                B4TreeEntryV1::File {
                    byte_length,
                    sha256,
                    ..
                } => {
                    ensure!(
                        *byte_length <= MAX_FILE_BYTES,
                        "B4 tree file exceeds the per-file byte bound: {path}"
                    );
                    validate_digest(sha256, "B4 tree file SHA-256")?;
                    files = files
                        .checked_add(1)
                        .context("B4 file census overflows u32")?;
                    total = total
                        .checked_add(*byte_length)
                        .context("B4 total file bytes overflow u64")?;
                    ensure!(
                        total <= MAX_TOTAL_FILE_BYTES,
                        "B4 tree exceeds the total-file-byte bound"
                    );
                }
            }
        }
        ensure!(
            directories == self.directory_count,
            "B4 tree directoryCount differs from its entries"
        );
        ensure!(
            files == self.file_count,
            "B4 tree fileCount differs from its entries"
        );
        ensure!(
            total == self.total_file_bytes,
            "B4 tree totalFileBytes differs from its entries"
        );
        Ok(())
    }
}

/// Exact identity of one lock-owned canonical artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4LockArtifactIdentityV1 {
    /// Exact byte length.
    pub byte_length: u64,
    /// Canonical path relative to the corpus root.
    pub path: String,
    /// Lowercase SHA-256 of the exact bytes.
    pub sha256: String,
}

impl B4LockArtifactIdentityV1 {
    /// Construct one lock binding from an exact relative path and bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe path, empty/oversized bytes, or length
    /// conversion failure.
    pub fn from_bytes(path: &str, bytes: &[u8]) -> Result<Self> {
        let identity = Self {
            byte_length: u64::try_from(bytes.len())
                .context("lock artifact length does not fit u64")?,
            path: path.to_owned(),
            sha256: sha256_hex(bytes),
        };
        identity.validate(false)?;
        Ok(identity)
    }

    fn validate(&self, allow_manifest_path: bool) -> Result<()> {
        validate_relative_path(&self.path)?;
        if allow_manifest_path {
            ensure!(
                self.path == B4_TREE_MANIFEST_PATH,
                "tree-manifest lock binding has the wrong path"
            );
        } else {
            reject_reserved_tree_path(&self.path)?;
        }
        ensure!(
            (1..=MAX_FILE_BYTES).contains(&self.byte_length),
            "lock artifact length is outside the V1 bound"
        );
        validate_digest(&self.sha256, "lock artifact SHA-256")
    }
}

/// Structural terminal-lock format for a B4 corpus.
///
/// A value of this type is not campaign authority. Production construction
/// remains fail-closed until the finalizer can consume an authoritative
/// semantic report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Eip0045B4LockV1 {
    /// Exact format discriminator.
    pub format: String,
    /// Exact format version.
    pub format_version: u8,
    /// Domain-separated identity of this structural lock preimage.
    pub corpus_id: String,
    /// Exact expanded registry binding.
    pub expanded_registry: B4LockArtifactIdentityV1,
    /// Exact guest image/program ID.
    pub program_id: String,
    /// Exact initial profile ID.
    pub profile_id: String,
    /// Exact semantic-report byte binding; this does not authenticate semantics.
    pub semantic_report: B4LockArtifactIdentityV1,
    /// SHA-256 of the exact shared `ErgoStatementV1` bytes.
    pub statement_sha256: String,
    /// Exact tree-manifest binding. The manifest excludes this lock and itself.
    pub tree_manifest: B4LockArtifactIdentityV1,
    /// Manifest directory census copied into the lock.
    pub tree_directory_count: u32,
    /// Manifest entry census copied into the lock.
    pub tree_entry_count: u32,
    /// Manifest file census copied into the lock.
    pub tree_file_count: u32,
    /// Manifest total-file-byte census copied into the lock.
    pub tree_total_file_bytes: u64,
}

impl Eip0045B4LockV1 {
    /// Parse exact RFC 8785 JCS and validate internal lock invariants.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, noncanonical, duplicate-key,
    /// unknown-field, malformed, or internally inconsistent bytes.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            source.len() <= MAX_LOCK_BYTES,
            "B4 lock exceeds its canonical-byte bound"
        );
        let value =
            validate_canonical_json_source(source).context("B4 lock is not exact RFC 8785 JCS")?;
        let lock: Self = serde_json::from_value(value).context("invalid B4 lock shape")?;
        lock.validate()?;
        ensure!(
            lock.to_canonical_jcs()? == source,
            "B4 lock does not round-trip byte-exactly"
        );
        Ok(lock)
    }

    /// Serialize this lock to exact RFC 8785 JCS bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid or oversized lock.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value = serde_json::to_value(self).context("cannot serialize B4 lock")?;
        let bytes = canonical_json_bytes(&value)?;
        ensure!(
            bytes.len() <= MAX_LOCK_BYTES,
            "B4 lock exceeds its canonical-byte bound"
        );
        Ok(bytes)
    }

    /// Validate internal lock identities, census, and corpus ID.
    ///
    /// # Errors
    ///
    /// Returns an error for any V1 identity, path, count, or digest drift.
    pub fn validate(&self) -> Result<()> {
        ensure!(self.format == B4_LOCK_FORMAT, "wrong B4 lock format label");
        ensure!(
            self.format_version == B4_LOCK_FORMAT_VERSION,
            "wrong B4 lock format version"
        );
        validate_digest(&self.corpus_id, "B4 corpus ID")?;
        validate_digest(&self.program_id, "B4 program ID")?;
        validate_digest(&self.profile_id, "B4 profile ID")?;
        validate_digest(&self.statement_sha256, "B4 statement SHA-256")?;
        self.expanded_registry.validate(false)?;
        self.semantic_report.validate(false)?;
        self.tree_manifest.validate(true)?;
        ensure!(
            self.expanded_registry.path != self.semantic_report.path,
            "registry and semantic report use the same path"
        );
        ensure!(
            self.tree_entry_count
                == self
                    .tree_directory_count
                    .checked_add(self.tree_file_count)
                    .context("B4 lock tree census overflows u32")?,
            "B4 lock entry count differs from directory+file counts"
        );
        ensure!(
            self.tree_file_count > 0 && self.tree_total_file_bytes > 0,
            "B4 lock cannot bind an empty corpus"
        );
        ensure!(
            self.corpus_id == derive_corpus_id(self),
            "B4 lock corpus ID differs from its exact preimage"
        );
        Ok(())
    }
}

/// Derive a manifest from two identical physical tree snapshots.
///
/// The exact `tree-manifest.json` and `LOCK.json` paths are excluded to avoid
/// self-reference. Any case alias of either reserved name is rejected.
///
/// # Errors
///
/// Returns an error for a missing/non-directory root, unsafe path, symlink,
/// Windows reparse point, Unix hard link, special node, bound overflow,
/// detected read race, or unequal snapshot.
pub fn derive_b4_tree_manifest(corpus_root: impl AsRef<Path>) -> Result<Eip0045B4TreeManifestV1> {
    let root = corpus_root.as_ref();
    require_ordinary_directory(root, "B4 corpus root")?;
    let root = fs::canonicalize(root).context("cannot canonicalize B4 corpus root")?;
    let first = derive_tree_snapshot(&root)?;
    let second = derive_tree_snapshot(&root)?;
    ensure!(
        first == second,
        "B4 corpus tree changed between consecutive snapshots"
    );
    first.validate()?;
    Ok(first)
}

/// Verify canonical manifest bytes against a fresh double physical snapshot.
///
/// # Errors
///
/// Returns an error for invalid source bytes, a physical-tree defect, or any
/// missing, extra, changed, reordered, or retyped entry.
pub fn verify_b4_tree_manifest(
    source: &[u8],
    corpus_root: impl AsRef<Path>,
) -> Result<Eip0045B4TreeManifestV1> {
    let supplied = Eip0045B4TreeManifestV1::from_canonical_jcs(source)?;
    let derived = derive_b4_tree_manifest(corpus_root)?;
    ensure!(
        supplied == derived,
        "B4 tree manifest differs from the complete physical tree"
    );
    Ok(supplied)
}

/// Test-only legacy constructor for the structural terminal lock.
///
/// This proves internal inclusion only. It does not authenticate the semantic
/// report and therefore is unavailable in production.
///
/// # Errors
///
/// Returns an error for invalid canonical manifest bytes, unsafe/missing lock
/// bindings, identity drift, or census overflow.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) fn create_b4_lock(
    tree_manifest_source: &[u8],
    expanded_registry_path: &str,
    expanded_registry_source: &[u8],
    semantic_report_path: &str,
    semantic_report_source: &[u8],
    profile_id: &str,
    program_id: &str,
    statement_sha256: &str,
) -> Result<Eip0045B4LockV1> {
    let manifest = Eip0045B4TreeManifestV1::from_canonical_jcs(tree_manifest_source)?;
    validate_digest(profile_id, "B4 profile ID")?;
    validate_digest(program_id, "B4 program ID")?;
    validate_digest(statement_sha256, "B4 statement SHA-256")?;
    let expanded_registry =
        B4LockArtifactIdentityV1::from_bytes(expanded_registry_path, expanded_registry_source)?;
    let semantic_report =
        B4LockArtifactIdentityV1::from_bytes(semantic_report_path, semantic_report_source)?;
    let tree_manifest = B4LockArtifactIdentityV1 {
        byte_length: u64::try_from(tree_manifest_source.len())
            .context("tree manifest length does not fit u64")?,
        path: B4_TREE_MANIFEST_PATH.to_owned(),
        sha256: sha256_hex(tree_manifest_source),
    };
    tree_manifest.validate(true)?;
    require_file_entry(&manifest, &expanded_registry)?;
    require_file_entry(&manifest, &semantic_report)?;
    let tree_entry_count =
        u32::try_from(manifest.entries.len()).context("B4 tree entry count does not fit u32")?;
    let mut lock = Eip0045B4LockV1 {
        format: B4_LOCK_FORMAT.to_owned(),
        format_version: B4_LOCK_FORMAT_VERSION,
        corpus_id: "00".repeat(32),
        expanded_registry,
        program_id: program_id.to_owned(),
        profile_id: profile_id.to_owned(),
        semantic_report,
        statement_sha256: statement_sha256.to_owned(),
        tree_manifest,
        tree_directory_count: manifest.directory_count,
        tree_entry_count,
        tree_file_count: manifest.file_count,
        tree_total_file_bytes: manifest.total_file_bytes,
    };
    lock.corpus_id = derive_corpus_id(&lock);
    lock.validate()?;
    Ok(lock)
}

/// Test-only legacy rebind of a structural lock to a physical tree.
///
/// This does not authenticate the semantic report and therefore is
/// unavailable in production.
///
/// # Errors
///
/// Returns an error for any lock, manifest, physical-tree, identity, census,
/// or corpus-ID drift.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) fn verify_b4_lock(
    lock_source: &[u8],
    tree_manifest_source: &[u8],
    expanded_registry_source: &[u8],
    semantic_report_source: &[u8],
    corpus_root: impl AsRef<Path>,
    profile_id: &str,
    program_id: &str,
    statement_sha256: &str,
) -> Result<Eip0045B4LockV1> {
    let supplied = Eip0045B4LockV1::from_canonical_jcs(lock_source)?;
    require_reserved_source(corpus_root.as_ref(), B4_LOCK_PATH, lock_source)?;
    require_reserved_source(
        corpus_root.as_ref(),
        B4_TREE_MANIFEST_PATH,
        tree_manifest_source,
    )?;
    verify_b4_tree_manifest(tree_manifest_source, corpus_root)?;
    let rebuilt = create_b4_lock(
        tree_manifest_source,
        &supplied.expanded_registry.path,
        expanded_registry_source,
        &supplied.semantic_report.path,
        semantic_report_source,
        profile_id,
        program_id,
        statement_sha256,
    )?;
    ensure!(
        supplied == rebuilt,
        "B4 lock differs from exact independently rebuilt bindings"
    );
    Ok(supplied)
}

fn derive_tree_snapshot(root: &Path) -> Result<Eip0045B4TreeManifestV1> {
    let mut entries = Vec::new();
    collect_tree_entries(root, root, &mut entries)?;
    entries.sort_by(|left, right| left.path().as_bytes().cmp(right.path().as_bytes()));
    let directory_count = u32::try_from(
        entries
            .iter()
            .filter(|entry| matches!(entry, B4TreeEntryV1::Directory { .. }))
            .count(),
    )
    .context("B4 directory count does not fit u32")?;
    let file_count = u32::try_from(
        entries
            .iter()
            .filter(|entry| matches!(entry, B4TreeEntryV1::File { .. }))
            .count(),
    )
    .context("B4 file count does not fit u32")?;
    let total_file_bytes = entries.iter().try_fold(0_u64, |total, entry| match entry {
        B4TreeEntryV1::Directory { .. } => Ok(total),
        B4TreeEntryV1::File { byte_length, .. } => total
            .checked_add(*byte_length)
            .context("B4 tree total bytes overflow u64"),
    })?;
    let manifest = Eip0045B4TreeManifestV1 {
        format: B4_TREE_MANIFEST_FORMAT.to_owned(),
        format_version: B4_TREE_MANIFEST_FORMAT_VERSION,
        entries,
        directory_count,
        file_count,
        total_file_bytes,
    };
    manifest.validate()?;
    Ok(manifest)
}

fn collect_tree_entries(
    root: &Path,
    directory: &Path,
    entries: &mut Vec<B4TreeEntryV1>,
) -> Result<()> {
    ensure!(
        entries.len() <= MAX_TREE_ENTRIES,
        "B4 tree exceeds the entry-count bound"
    );
    let metadata = fs::symlink_metadata(directory)
        .with_context(|| format!("cannot inspect B4 tree directory {}", directory.display()))?;
    reject_link_or_reparse(directory, &metadata)?;
    ensure!(
        metadata.file_type().is_dir(),
        "B4 tree traversal target is not a directory: {}",
        directory.display()
    );

    let mut children = fs::read_dir(directory)
        .with_context(|| format!("cannot enumerate B4 tree directory {}", directory.display()))?
        .map(|entry| {
            entry.with_context(|| {
                format!("cannot enumerate B4 tree directory {}", directory.display())
            })
        })
        .collect::<Result<Vec<_>>>()?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    for child in children {
        let path = child.path();
        let relative = repository_relative(root, &path)?;
        validate_relative_path(&relative)?;
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("cannot inspect B4 tree entry {}", path.display()))?;
        reject_link_or_reparse(&path, &metadata)?;
        let folded = relative.to_ascii_lowercase();
        if folded == B4_TREE_MANIFEST_PATH.to_ascii_lowercase()
            || folded == B4_LOCK_PATH.to_ascii_lowercase()
        {
            ensure!(
                relative == B4_TREE_MANIFEST_PATH || relative == B4_LOCK_PATH,
                "reserved B4 tree path has a noncanonical case alias: {relative}"
            );
            ensure!(
                metadata.file_type().is_file(),
                "reserved B4 tree path is not a regular file: {relative}"
            );
            continue;
        }
        if metadata.file_type().is_dir() {
            entries.push(B4TreeEntryV1::Directory {
                path: relative.clone(),
            });
            collect_tree_entries(root, &path, entries)?;
        } else if metadata.file_type().is_file() {
            let (byte_length, sha256) = hash_regular_file(&path)?;
            entries.push(B4TreeEntryV1::File {
                byte_length,
                path: relative,
                sha256,
            });
        } else {
            bail!(
                "B4 tree entry is neither a directory nor a regular file: {}",
                path.display()
            );
        }
        ensure!(
            entries.len() <= MAX_TREE_ENTRIES,
            "B4 tree exceeds the entry-count bound"
        );
    }
    Ok(())
}

fn hash_regular_file(path: &Path) -> Result<(u64, String)> {
    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect B4 tree file {}", path.display()))?;
    reject_link_or_reparse(path, &path_metadata)?;
    ensure!(
        path_metadata.file_type().is_file(),
        "B4 tree path is not a regular file: {}",
        path.display()
    );
    ensure!(
        path_metadata.len() <= MAX_FILE_BYTES,
        "B4 tree file exceeds the per-file byte bound: {}",
        path.display()
    );
    #[cfg(unix)]
    require_single_link(path, &path_metadata)?;
    #[cfg(unix)]
    let path_identity = stable_file_identity(&path_metadata)?;
    let file =
        File::open(path).with_context(|| format!("cannot open B4 tree file {}", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("cannot inspect open B4 tree file {}", path.display()))?;
    reject_link_or_reparse(path, &opened)?;
    ensure!(
        opened.file_type().is_file() && opened.len() == path_metadata.len(),
        "B4 tree file changed before hashing: {}",
        path.display()
    );
    #[cfg(unix)]
    require_single_link(path, &opened)?;
    #[cfg(unix)]
    ensure!(
        stable_file_identity(&opened)? == path_identity,
        "B4 tree path resolved to a different file while opening: {}",
        path.display()
    );
    let read_limit = opened
        .len()
        .checked_add(1)
        .context("B4 tree file read bound overflows u64")?;
    let mut reader = BufReader::new(file.take(read_limit));
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    let mut observed = 0_u64;
    loop {
        let count = reader
            .read(&mut buffer)
            .with_context(|| format!("cannot hash B4 tree file {}", path.display()))?;
        if count == 0 {
            break;
        }
        observed = observed
            .checked_add(u64::try_from(count)?)
            .context("B4 tree observed length overflows u64")?;
        ensure!(
            observed <= opened.len(),
            "B4 tree file grew while hashing: {}",
            path.display()
        );
        hasher.update(&buffer[..count]);
    }
    ensure!(
        observed == opened.len(),
        "B4 tree file changed length while hashing: {}",
        path.display()
    );
    let opened_after = reader
        .get_ref()
        .get_ref()
        .metadata()
        .with_context(|| format!("cannot re-inspect open B4 tree file {}", path.display()))?;
    reject_link_or_reparse(path, &opened_after)?;
    #[cfg(unix)]
    require_single_link(path, &opened_after)?;
    #[cfg(unix)]
    let opened_identity_is_stable = stable_file_identity(&opened_after)? == path_identity;
    #[cfg(not(unix))]
    let opened_identity_is_stable = true;
    ensure!(
        opened_after.file_type().is_file()
            && opened_after.len() == opened.len()
            && opened_identity_is_stable,
        "open B4 tree file changed while hashing: {}",
        path.display()
    );
    let after = fs::symlink_metadata(path)
        .with_context(|| format!("cannot re-inspect B4 tree file {}", path.display()))?;
    reject_link_or_reparse(path, &after)?;
    #[cfg(unix)]
    require_single_link(path, &after)?;
    #[cfg(unix)]
    let path_identity_is_stable = stable_file_identity(&after)? == path_identity;
    #[cfg(not(unix))]
    let path_identity_is_stable = true;
    ensure!(
        after.file_type().is_file() && after.len() == opened.len() && path_identity_is_stable,
        "B4 tree file changed after hashing: {}",
        path.display()
    );
    Ok((observed, hex::encode(hasher.finalize())))
}

#[cfg(test)]
fn require_file_entry(
    manifest: &Eip0045B4TreeManifestV1,
    identity: &B4LockArtifactIdentityV1,
) -> Result<()> {
    let matches = manifest
        .entries
        .iter()
        .filter(|entry| entry.path() == identity.path)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "lock-owned artifact is absent or duplicated in the tree manifest: {}",
        identity.path
    );
    ensure!(
        matches[0]
            == &B4TreeEntryV1::File {
                byte_length: identity.byte_length,
                path: identity.path.clone(),
                sha256: identity.sha256.clone(),
            },
        "lock-owned artifact identity differs from its tree-manifest entry: {}",
        identity.path
    );
    Ok(())
}

#[cfg(test)]
fn require_reserved_source(root: &Path, relative: &str, source: &[u8]) -> Result<()> {
    let path = root.join(relative);
    let (byte_length, sha256) = hash_regular_file(&path)
        .with_context(|| format!("cannot bind reserved B4 corpus file {relative}"))?;
    ensure!(
        byte_length == u64::try_from(source.len())? && sha256 == sha256_hex(source),
        "reserved B4 corpus file differs from supplied bytes: {relative}"
    );
    Ok(())
}

fn derive_corpus_id(lock: &Eip0045B4LockV1) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CORPUS_ID_DOMAIN);
    for digest in [
        &lock.tree_manifest.sha256,
        &lock.expanded_registry.sha256,
        &lock.semantic_report.sha256,
        &lock.profile_id,
        &lock.program_id,
        &lock.statement_sha256,
    ] {
        let bytes = hex::decode(digest).expect("validated digest must decode");
        hasher.update(bytes);
    }
    hex::encode(hasher.finalize())
}

fn parent_path(path: &str) -> Option<&str> {
    path.rsplit_once('/').map(|(parent, _)| parent)
}

fn validate_relative_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty() && path.len() <= MAX_PATH_BYTES,
        "B4 tree path is empty or too long"
    );
    ensure!(
        path.bytes().all(|byte| (0x21..=0x7e).contains(&byte)),
        "B4 tree path is not printable space-free ASCII"
    );
    ensure!(
        !path.starts_with('/')
            && !path.ends_with('/')
            && !path.contains('\\')
            && !path.contains(':'),
        "B4 tree path is not canonical repository-relative POSIX"
    );
    ensure!(
        path.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && !component.ends_with('.')
                && !component.ends_with(' ')
                && !is_windows_device_component(component)
        }),
        "B4 tree path contains an ambiguous component"
    );
    Ok(())
}

fn reject_reserved_tree_path(path: &str) -> Result<()> {
    let folded = path.to_ascii_lowercase();
    ensure!(
        folded != B4_TREE_MANIFEST_PATH.to_ascii_lowercase()
            && folded != B4_LOCK_PATH.to_ascii_lowercase(),
        "B4 tree manifest entries cannot include the manifest or lock"
    );
    Ok(())
}

fn repository_relative(root: &Path, path: &Path) -> Result<String> {
    let relative = path.strip_prefix(root).with_context(|| {
        format!(
            "B4 tree path {} escapes root {}",
            path.display(),
            root.display()
        )
    })?;
    let mut components = Vec::new();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            bail!("B4 tree path is not normal: {}", relative.display());
        };
        let component = component
            .to_str()
            .with_context(|| format!("B4 tree path is not UTF-8: {}", relative.display()))?;
        components.push(component);
    }
    Ok(components.join("/"))
}

fn require_ordinary_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("{label} is missing: {}", path.display()))?;
    reject_link_or_reparse(path, &metadata)?;
    ensure!(
        metadata.file_type().is_dir(),
        "{label} is not a directory: {}",
        path.display()
    );
    Ok(())
}

fn is_windows_device_component(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
    {
        return true;
    }
    let bytes = stem.as_bytes();
    bytes.len() == 4
        && (stem[..3].eq_ignore_ascii_case("COM") || stem[..3].eq_ignore_ascii_case("LPT"))
        && (b'1'..=b'9').contains(&bytes[3])
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StableFileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn stable_file_identity(metadata: &Metadata) -> Result<StableFileIdentity> {
    use std::os::unix::fs::MetadataExt;

    Ok(StableFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn hard_link_count(metadata: &Metadata) -> Result<u64> {
    use std::os::unix::fs::MetadataExt;

    Ok(metadata.nlink())
}

#[cfg(unix)]
fn require_single_link(path: &Path, metadata: &Metadata) -> Result<()> {
    ensure!(
        hard_link_count(metadata)? == 1,
        "hard-linked B4 tree file is forbidden: {}",
        path.display()
    );
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

fn validate_digest(value: &str, label: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} is not exactly 32 lowercase hexadecimal bytes"
    );
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{TempDir, tempdir};

    fn fixture_tree() -> TempDir {
        let temp = tempdir().unwrap();
        fs::create_dir_all(temp.path().join("negative").join("case-a")).unwrap();
        fs::create_dir_all(temp.path().join("positive")).unwrap();
        fs::write(temp.path().join("expanded-registry.json"), b"{\"v\":1}").unwrap();
        fs::write(temp.path().join("semantic-report.json"), b"{\"ok\":true}").unwrap();
        fs::write(
            temp.path()
                .join("negative")
                .join("case-a")
                .join("rust.json"),
            b"{\"reject\":true}",
        )
        .unwrap();
        fs::write(temp.path().join("positive").join("seal.bin"), b"seal").unwrap();
        temp
    }

    #[test]
    fn double_snapshot_manifest_round_trips_and_detects_missing_extra_and_changed_entries() {
        let temp = fixture_tree();
        let manifest = derive_b4_tree_manifest(temp.path()).unwrap();
        let source = manifest.to_canonical_jcs().unwrap();
        verify_b4_tree_manifest(&source, temp.path()).unwrap();

        fs::remove_file(temp.path().join("positive").join("seal.bin")).unwrap();
        assert!(verify_b4_tree_manifest(&source, temp.path()).is_err());
        fs::write(temp.path().join("positive").join("seal.bin"), b"seal").unwrap();
        fs::write(temp.path().join("extra.bin"), b"extra").unwrap();
        assert!(verify_b4_tree_manifest(&source, temp.path()).is_err());
        fs::remove_file(temp.path().join("extra.bin")).unwrap();
        fs::write(temp.path().join("positive").join("seal.bin"), b"drift").unwrap();
        assert!(verify_b4_tree_manifest(&source, temp.path()).is_err());
    }

    #[test]
    fn reserved_manifest_and_lock_are_excluded_but_case_aliases_reject() {
        let temp = fixture_tree();
        fs::write(temp.path().join(B4_TREE_MANIFEST_PATH), b"manifest").unwrap();
        fs::write(temp.path().join(B4_LOCK_PATH), b"lock").unwrap();
        let manifest = derive_b4_tree_manifest(temp.path()).unwrap();
        assert!(
            manifest
                .entries
                .iter()
                .all(|entry| entry.path() != B4_TREE_MANIFEST_PATH && entry.path() != B4_LOCK_PATH)
        );
        fs::remove_file(temp.path().join(B4_LOCK_PATH)).unwrap();
        fs::write(temp.path().join("lock.json"), b"alias").unwrap();
        assert!(derive_b4_tree_manifest(temp.path()).is_err());
    }

    #[test]
    fn reserved_paths_must_be_regular_files_not_directories() {
        let temp = fixture_tree();
        fs::create_dir(temp.path().join(B4_LOCK_PATH)).unwrap();
        assert!(derive_b4_tree_manifest(temp.path()).is_err());
    }

    #[test]
    fn test_only_lock_rebinds_opaque_report_and_structural_identities() {
        let temp = fixture_tree();
        let manifest = derive_b4_tree_manifest(temp.path()).unwrap();
        let manifest_source = manifest.to_canonical_jcs().unwrap();
        let registry = fs::read(temp.path().join("expanded-registry.json")).unwrap();
        let report = fs::read(temp.path().join("semantic-report.json")).unwrap();
        let lock = create_b4_lock(
            &manifest_source,
            "expanded-registry.json",
            &registry,
            "semantic-report.json",
            &report,
            &"11".repeat(32),
            &"22".repeat(32),
            &"33".repeat(32),
        )
        .unwrap();
        let source = lock.to_canonical_jcs().unwrap();
        assert!(
            !serde_json::to_value(&lock)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("treeOmissionSweepCount")
        );
        let mut legacy_lock = serde_json::to_value(&lock).unwrap();
        legacy_lock.as_object_mut().unwrap().insert(
            "treeOmissionSweepCount".to_owned(),
            serde_json::Value::from(lock.tree_entry_count),
        );
        assert!(
            Eip0045B4LockV1::from_canonical_jcs(&canonical_json_bytes(&legacy_lock).unwrap())
                .is_err()
        );
        fs::write(temp.path().join(B4_TREE_MANIFEST_PATH), &manifest_source).unwrap();
        fs::write(temp.path().join(B4_LOCK_PATH), &source).unwrap();
        verify_b4_lock(
            &source,
            &manifest_source,
            &registry,
            &report,
            temp.path(),
            &"11".repeat(32),
            &"22".repeat(32),
            &"33".repeat(32),
        )
        .unwrap();

        let mut changed_report = report.clone();
        changed_report.push(b' ');
        assert!(
            verify_b4_lock(
                &source,
                &manifest_source,
                &registry,
                &changed_report,
                temp.path(),
                &"11".repeat(32),
                &"22".repeat(32),
                &"33".repeat(32),
            )
            .is_err()
        );
    }

    #[test]
    fn manifest_parser_rejects_unknown_fields_bad_counts_and_casefold_collisions() {
        let temp = fixture_tree();
        let manifest = derive_b4_tree_manifest(temp.path()).unwrap();
        let mut value = serde_json::to_value(&manifest).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), serde_json::Value::Bool(true));
        let unknown = canonical_json_bytes(&value).unwrap();
        assert!(Eip0045B4TreeManifestV1::from_canonical_jcs(&unknown).is_err());

        let mut bad_count = manifest.clone();
        bad_count.file_count += 1;
        assert!(bad_count.validate().is_err());

        let mut collision = manifest;
        collision.entries.push(B4TreeEntryV1::File {
            byte_length: 1,
            path: "Positive/seal.bin".to_owned(),
            sha256: "00".repeat(32),
        });
        collision
            .entries
            .sort_by(|left, right| left.path().as_bytes().cmp(right.path().as_bytes()));
        collision.file_count += 1;
        collision.total_file_bytes += 1;
        assert!(collision.validate().is_err());
    }

    #[test]
    fn windows_device_components_are_rejected_portably() {
        for path in [
            "CON",
            "con.txt",
            "dir/PRN.json",
            "AUX",
            "nul.bin",
            "COM1",
            "com9.log",
            "LPT1",
            "lpt9.txt",
            "CONIN$",
            "conout$.txt",
        ] {
            assert!(
                validate_relative_path(path).is_err(),
                "Windows device path unexpectedly accepted: {path}"
            );
        }
        for path in ["console", "com0", "com10", "lpt0", "lpt10"] {
            assert!(
                validate_relative_path(path).is_ok(),
                "ordinary path unexpectedly rejected: {path}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn hard_link_is_rejected_as_a_path_alias() {
        let temp = fixture_tree();
        fs::hard_link(
            temp.path().join("positive").join("seal.bin"),
            temp.path().join("positive").join("seal-alias.bin"),
        )
        .unwrap();
        assert!(derive_b4_tree_manifest(temp.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn stable_file_identity_distinguishes_distinct_files() {
        let temp = fixture_tree();
        let registry = fs::symlink_metadata(temp.path().join("expanded-registry.json")).unwrap();
        let report = fs::symlink_metadata(temp.path().join("semantic-report.json")).unwrap();
        assert_ne!(
            stable_file_identity(&registry).unwrap(),
            stable_file_identity(&report).unwrap()
        );
    }

    #[cfg(windows)]
    #[test]
    fn directory_junction_is_rejected_without_following_it() {
        use std::process::Command;

        let temp = fixture_tree();
        let outside = temp.path().with_extension("junction-target");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("outside.bin"), b"outside").unwrap();
        let junction = temp.path().join("junction");
        let status = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&outside)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "could not create the junction test fixture"
        );
        assert!(derive_b4_tree_manifest(temp.path()).is_err());
        fs::remove_dir(&junction).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_is_rejected_without_following_it() {
        use std::os::unix::fs::symlink;

        let temp = fixture_tree();
        let outside = temp.path().with_extension("outside");
        fs::write(&outside, b"outside").unwrap();
        symlink(&outside, temp.path().join("linked.bin")).unwrap();
        assert!(derive_b4_tree_manifest(temp.path()).is_err());
        fs::remove_file(outside).unwrap();
    }
}
