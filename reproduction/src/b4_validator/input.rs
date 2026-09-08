// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Closed, bounded filesystem input for one B4 positive verification.
//!
//! The verifier accepts exactly seven direct regular files. The canonical
//! `verifier-input.json` document names no caller-selected path: all six data
//! paths are fixed by the V1 grammar. Every data file is measured from an open
//! handle after its declared length has passed a hard bound, read to the exact
//! declared length, checked for EOF, and re-inspected before use.

#[cfg(feature = "validator")]
use std::{
    collections::BTreeSet,
    fs::{self, File, Metadata},
    io::Read as _,
    path::Path,
};

#[cfg(feature = "validator")]
use anyhow::bail;
use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    canonical::{canonical_json_bytes, validate_canonical_json_source},
    constants::{MANIFEST_BYTES, MAX_STATEMENT_BYTES, PROOF_BYTES, STATEMENT_PREFIX_BYTES},
};

/// Canonical positive verifier-input filename.
#[cfg(feature = "validator")]
pub const POSITIVE_INPUT_FILE: &str = "verifier-input.json";
/// Fixed Manifest V1 filename.
pub const PROFILE_MANIFEST_FILE: &str = "profile-manifest.bin";
/// Fixed B1 normative-algorithm filename.
pub const PROFILE_ALGORITHM_FILE: &str = "profile-algorithm.txt";
/// Fixed B2 normative-constants filename.
pub const PROFILE_CONSTANTS_FILE: &str = "profile-constants.bin";
/// Fixed encoded RISC Zero program filename.
pub const GUEST_ELF_FILE: &str = "guest.elf";
/// Fixed `ErgoStatementV1` filename.
pub const STATEMENT_FILE: &str = "statement.bin";
/// Fixed raw succinct-seal filename.
pub const RAW_SEAL_FILE: &str = "raw-seal.bin";

const POSITIVE_INPUT_FORMAT: &str = "Eip0045B4PositiveVerifierInputV1";
const POSITIVE_INPUT_FORMAT_VERSION: u8 = 1;
const POSITIVE_INPUT_MAX_BYTES: u64 = 65_536;
const PROFILE_MANIFEST_SHA256: &str =
    "deffb2cb231f98a348cbd166d5f1c43315661ccd8bd212099f16f238d0fe8946";
const PROFILE_ALGORITHM_BYTES: u64 = 29_773;
const PROFILE_ALGORITHM_SHA256: &str =
    "90a884da420a09f2c1108d7388c2ac74db8dbdb195de704206e2bf8ec1ad0bee";
const PROFILE_CONSTANTS_BYTES: u64 = 65_119;
const PROFILE_CONSTANTS_SHA256: &str =
    "8c4a92b7d354890481eefdef233d4ca43f6bcd9f7cb00e4dd9e709da47789ef3";
const MAX_GUEST_ELF_BYTES: u64 = 4_194_304;
#[cfg(feature = "validator")]
const FIXED_ROOT_FILES: [&str; 7] = [
    GUEST_ELF_FILE,
    PROFILE_ALGORITHM_FILE,
    PROFILE_CONSTANTS_FILE,
    PROFILE_MANIFEST_FILE,
    RAW_SEAL_FILE,
    STATEMENT_FILE,
    POSITIVE_INPUT_FILE,
];

/// Closed physical encoding used by every positive verifier data file.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4PositiveFileEncoding {
    /// Opaque bytes interpreted only after identity authentication.
    RawBytes,
}

/// Exact physical identity of one fixed positive verifier file.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4PositiveFileIdentityV1 {
    /// Fixed direct-child path under the isolated verifier root.
    pub path: String,
    /// Exact physical byte length.
    pub byte_length: u64,
    /// Lowercase SHA-256 of the exact physical bytes.
    pub sha256: String,
    /// Closed physical encoding.
    pub encoding: B4PositiveFileEncoding,
}

impl B4PositiveFileIdentityV1 {
    fn validate(
        &self,
        expected_path: &str,
        minimum: u64,
        maximum: u64,
        fixed_sha256: Option<&str>,
    ) -> Result<()> {
        ensure!(
            self.path == expected_path,
            "positive verifier identity has the wrong fixed path for {expected_path}"
        );
        ensure!(
            (minimum..=maximum).contains(&self.byte_length),
            "{expected_path} byte length is outside its V1 bound"
        );
        validate_digest(&self.sha256, expected_path)?;
        if let Some(expected) = fixed_sha256 {
            ensure!(
                self.sha256 == expected,
                "{expected_path} SHA-256 differs from the frozen V1 identity"
            );
        }
        ensure!(
            self.encoding == B4PositiveFileEncoding::RawBytes,
            "{expected_path} has the wrong physical encoding"
        );
        Ok(())
    }
}

/// Canonical authority-minimal descriptor for the six verifier data files.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Eip0045B4PositiveVerifierInputV1 {
    /// Exact V1 format discriminator.
    pub format: String,
    /// Exact V1 format version.
    pub format_version: u8,
    /// Frozen Manifest V1 identity.
    pub profile_manifest: B4PositiveFileIdentityV1,
    /// Frozen B1 identity.
    pub profile_algorithm: B4PositiveFileIdentityV1,
    /// Frozen B2 identity.
    pub profile_constants: B4PositiveFileIdentityV1,
    /// Case-specific encoded program identity.
    pub guest_elf: B4PositiveFileIdentityV1,
    /// Case-specific `ErgoStatementV1` identity.
    pub statement: B4PositiveFileIdentityV1,
    /// Case-specific raw-seal identity.
    pub raw_seal: B4PositiveFileIdentityV1,
}

impl Eip0045B4PositiveVerifierInputV1 {
    /// Parse exact RFC 8785 JCS and enforce the complete closed V1 grammar.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, duplicate-key, noncanonical,
    /// unknown-field, oversized, wrongly named, or wrongly bound input.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            u64::try_from(source.len())? <= POSITIVE_INPUT_MAX_BYTES,
            "B4 positive verifier input exceeds its canonical-byte bound"
        );
        let value = validate_canonical_json_source(source)
            .context("B4 positive verifier input is not exact RFC 8785 JCS")?;
        let input: Self =
            serde_json::from_value(value).context("invalid B4 positive verifier-input shape")?;
        input.validate()?;
        ensure!(
            input.to_canonical_jcs()? == source,
            "B4 positive verifier input does not round-trip byte-exactly"
        );
        Ok(input)
    }

    /// Serialize a validated descriptor to exact RFC 8785 JCS.
    ///
    /// # Errors
    ///
    /// Returns an error if any identity violates the V1 schema or if canonical
    /// serialization exceeds the input byte bound.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value =
            serde_json::to_value(self).context("cannot serialize B4 positive verifier input")?;
        let bytes = canonical_json_bytes(&value)?;
        ensure!(
            u64::try_from(bytes.len())? <= POSITIVE_INPUT_MAX_BYTES,
            "B4 positive verifier input exceeds its canonical-byte bound"
        );
        Ok(bytes)
    }

    /// Validate every fixed identity and case-specific size/digest bound.
    ///
    /// # Errors
    ///
    /// Returns an error at the first format or identity mismatch.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == POSITIVE_INPUT_FORMAT,
            "wrong B4 positive verifier-input format label"
        );
        ensure!(
            self.format_version == POSITIVE_INPUT_FORMAT_VERSION,
            "wrong B4 positive verifier-input format version"
        );
        self.profile_manifest.validate(
            PROFILE_MANIFEST_FILE,
            u64::try_from(MANIFEST_BYTES)?,
            u64::try_from(MANIFEST_BYTES)?,
            Some(PROFILE_MANIFEST_SHA256),
        )?;
        self.profile_algorithm.validate(
            PROFILE_ALGORITHM_FILE,
            PROFILE_ALGORITHM_BYTES,
            PROFILE_ALGORITHM_BYTES,
            Some(PROFILE_ALGORITHM_SHA256),
        )?;
        self.profile_constants.validate(
            PROFILE_CONSTANTS_FILE,
            PROFILE_CONSTANTS_BYTES,
            PROFILE_CONSTANTS_BYTES,
            Some(PROFILE_CONSTANTS_SHA256),
        )?;
        self.guest_elf
            .validate(GUEST_ELF_FILE, 1, MAX_GUEST_ELF_BYTES, None)?;
        self.statement.validate(
            STATEMENT_FILE,
            u64::try_from(STATEMENT_PREFIX_BYTES)?,
            u64::try_from(MAX_STATEMENT_BYTES)?,
            None,
        )?;
        self.raw_seal.validate(
            RAW_SEAL_FILE,
            u64::try_from(PROOF_BYTES)?,
            u64::try_from(PROOF_BYTES)?,
            None,
        )
    }
}

/// Bytes measured from one fixed path and checked against its descriptor.
#[derive(Clone, Debug)]
pub(super) struct B4MeasuredPositiveFile {
    bytes: Vec<u8>,
    sha256: [u8; 32],
}

impl B4MeasuredPositiveFile {
    /// Exact bytes read from the re-inspected open handle.
    #[must_use]
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// SHA-256 of the exact returned bytes.
    #[must_use]
    pub(super) const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

/// Complete seven-file positive verifier root after physical authentication.
#[derive(Clone, Debug)]
pub(super) struct B4PositiveVerifierRoot {
    profile_manifest: B4MeasuredPositiveFile,
    profile_algorithm: B4MeasuredPositiveFile,
    profile_constants: B4MeasuredPositiveFile,
    guest_elf: B4MeasuredPositiveFile,
    statement: B4MeasuredPositiveFile,
    raw_seal: B4MeasuredPositiveFile,
}

/// Exact positional byte views of one closed positive verifier root.
///
/// This is the filesystem-free counterpart of the seven fixed root files. It
/// exists for negative consumers which must replay a positive producer from
/// already measured, immutable bytes. The descriptor remains the authority for
/// all six data-file identities.
#[derive(Clone, Copy, Debug)]
pub(crate) struct B4PositiveVerifierRootSources<'a> {
    pub(crate) verifier_input: &'a [u8],
    pub(crate) profile_manifest: &'a [u8],
    pub(crate) profile_algorithm: &'a [u8],
    pub(crate) profile_constants: &'a [u8],
    pub(crate) guest_elf: &'a [u8],
    pub(crate) statement: &'a [u8],
    pub(crate) raw_seal: &'a [u8],
}

impl B4PositiveVerifierRoot {
    /// Authenticated Manifest V1 file.
    #[must_use]
    pub(super) const fn profile_manifest(&self) -> &B4MeasuredPositiveFile {
        &self.profile_manifest
    }

    /// Authenticated B1 normative algorithm file.
    #[must_use]
    pub(super) const fn profile_algorithm(&self) -> &B4MeasuredPositiveFile {
        &self.profile_algorithm
    }

    /// Authenticated B2 normative constants file.
    #[must_use]
    pub(super) const fn profile_constants(&self) -> &B4MeasuredPositiveFile {
        &self.profile_constants
    }

    /// Authenticated encoded RISC Zero program.
    #[must_use]
    pub(super) const fn guest_elf(&self) -> &B4MeasuredPositiveFile {
        &self.guest_elf
    }

    /// Authenticated `ErgoStatementV1` file.
    #[must_use]
    pub(super) const fn statement(&self) -> &B4MeasuredPositiveFile {
        &self.statement
    }

    /// Authenticated raw succinct seal.
    #[must_use]
    pub(super) const fn raw_seal(&self) -> &B4MeasuredPositiveFile {
        &self.raw_seal
    }
}

/// Authenticate one closed seven-file positive verifier root.
///
/// Directory closure is checked before the input is parsed and again after all
/// six data files have been read. This detects additions, removals, aliases,
/// and type changes during verification. Each file is independently
/// re-inspected around its bounded open-handle read.
///
/// # Errors
///
/// Returns an error for a linked/reparse root, any missing or additional
/// direct child, any non-regular child, input grammar drift, file-identity
/// mismatch, short read, trailing byte, hash mismatch, or observed mutation.
#[cfg(feature = "validator")]
pub(super) fn load_positive_verifier_root(root: &Path) -> Result<B4PositiveVerifierRoot> {
    validate_root_inventory(root)?;

    let input_bytes = read_fixed_file(
        &root.join(POSITIVE_INPUT_FILE),
        u64::try_from(1usize)?,
        POSITIVE_INPUT_MAX_BYTES,
        None,
        POSITIVE_INPUT_FILE,
    )?;
    let input = Eip0045B4PositiveVerifierInputV1::from_canonical_jcs(input_bytes.bytes())?;
    let profile_manifest = read_declared_file(root, &input.profile_manifest)?;
    let profile_algorithm = read_declared_file(root, &input.profile_algorithm)?;
    let profile_constants = read_declared_file(root, &input.profile_constants)?;
    let guest_elf = read_declared_file(root, &input.guest_elf)?;
    let statement = read_declared_file(root, &input.statement)?;
    let raw_seal = read_declared_file(root, &input.raw_seal)?;

    validate_root_inventory(root)?;
    Ok(B4PositiveVerifierRoot {
        profile_manifest,
        profile_algorithm,
        profile_constants,
        guest_elf,
        statement,
        raw_seal,
    })
}

/// Authenticate one positive verifier root from exact immutable byte views.
///
/// The same canonical descriptor, fixed paths, size bounds, frozen B1/B2/B3
/// identities, and case-specific SHA-256 bindings used by the filesystem
/// loader are enforced here. No path, expected observation, or caller-selected
/// identity is accepted.
pub(super) fn load_positive_verifier_root_from_sources(
    sources: B4PositiveVerifierRootSources<'_>,
) -> Result<B4PositiveVerifierRoot> {
    ensure!(
        (1..=usize::try_from(POSITIVE_INPUT_MAX_BYTES)?).contains(&sources.verifier_input.len()),
        "B4 positive verifier input byte view is outside its bound"
    );
    let input = Eip0045B4PositiveVerifierInputV1::from_canonical_jcs(sources.verifier_input)?;
    Ok(B4PositiveVerifierRoot {
        profile_manifest: measure_declared_bytes(
            sources.profile_manifest,
            &input.profile_manifest,
        )?,
        profile_algorithm: measure_declared_bytes(
            sources.profile_algorithm,
            &input.profile_algorithm,
        )?,
        profile_constants: measure_declared_bytes(
            sources.profile_constants,
            &input.profile_constants,
        )?,
        guest_elf: measure_declared_bytes(sources.guest_elf, &input.guest_elf)?,
        statement: measure_declared_bytes(sources.statement, &input.statement)?,
        raw_seal: measure_declared_bytes(sources.raw_seal, &input.raw_seal)?,
    })
}

/// Synthesize the exact canonical V1 descriptor for immutable positive bytes.
///
/// All paths, the format discriminator, the version, the encoding, the byte
/// lengths, and the SHA-256 identities are derived here. Callers choose no
/// descriptor metadata.
///
/// # Errors
///
/// Returns an error if any byte length exceeds the V1 integer domain, a frozen
/// profile artifact differs from its exact V1 identity, a case-specific input
/// violates its V1 size bound, or canonical serialization fails.
#[cfg(any(
    feature = "materializer-replay",
    feature = "b4-terminal-evidence-packet",
))]
pub(crate) fn synthesize_positive_verifier_input_v1(
    profile_manifest: &[u8],
    profile_algorithm: &[u8],
    profile_constants: &[u8],
    guest_elf: &[u8],
    statement: &[u8],
    raw_seal: &[u8],
) -> Result<Vec<u8>> {
    Eip0045B4PositiveVerifierInputV1 {
        format: POSITIVE_INPUT_FORMAT.to_owned(),
        format_version: POSITIVE_INPUT_FORMAT_VERSION,
        profile_manifest: positive_file_identity(PROFILE_MANIFEST_FILE, profile_manifest)?,
        profile_algorithm: positive_file_identity(PROFILE_ALGORITHM_FILE, profile_algorithm)?,
        profile_constants: positive_file_identity(PROFILE_CONSTANTS_FILE, profile_constants)?,
        guest_elf: positive_file_identity(GUEST_ELF_FILE, guest_elf)?,
        statement: positive_file_identity(STATEMENT_FILE, statement)?,
        raw_seal: positive_file_identity(RAW_SEAL_FILE, raw_seal)?,
    }
    .to_canonical_jcs()
}

#[cfg(any(
    feature = "materializer-replay",
    feature = "b4-terminal-evidence-packet",
))]
fn positive_file_identity(path: &str, bytes: &[u8]) -> Result<B4PositiveFileIdentityV1> {
    Ok(B4PositiveFileIdentityV1 {
        path: path.to_owned(),
        byte_length: u64::try_from(bytes.len())?,
        sha256: hex::encode(Sha256::digest(bytes)),
        encoding: B4PositiveFileEncoding::RawBytes,
    })
}

fn measure_declared_bytes(
    bytes: &[u8],
    identity: &B4PositiveFileIdentityV1,
) -> Result<B4MeasuredPositiveFile> {
    ensure!(
        u64::try_from(bytes.len())? == identity.byte_length,
        "{} byte view length differs from its descriptor",
        identity.path
    );
    let sha256: [u8; 32] = Sha256::digest(bytes).into();
    ensure!(
        hex::encode(sha256) == identity.sha256,
        "{} byte view SHA-256 differs from its descriptor",
        identity.path
    );
    Ok(B4MeasuredPositiveFile {
        bytes: bytes.to_vec(),
        sha256,
    })
}

#[cfg(feature = "validator")]
fn read_declared_file(
    root: &Path,
    identity: &B4PositiveFileIdentityV1,
) -> Result<B4MeasuredPositiveFile> {
    read_fixed_file(
        &root.join(&identity.path),
        identity.byte_length,
        identity.byte_length,
        Some(&identity.sha256),
        &identity.path,
    )
}

#[cfg(feature = "validator")]
fn validate_root_inventory(root: &Path) -> Result<()> {
    let root_metadata = fs::symlink_metadata(root)
        .with_context(|| format!("cannot inspect positive verifier root {}", root.display()))?;
    reject_link_or_reparse(root, &root_metadata)?;
    ensure!(
        root_metadata.file_type().is_dir(),
        "positive verifier root is not an ordinary directory"
    );

    let mut observed = BTreeSet::new();
    for entry in fs::read_dir(root)
        .with_context(|| format!("cannot enumerate positive verifier root {}", root.display()))?
    {
        let entry = entry.context("cannot enumerate one positive verifier root entry")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("positive verifier root entry name is not UTF-8"))?;
        ensure!(
            FIXED_ROOT_FILES.binary_search(&name.as_str()).is_ok(),
            "unexpected positive verifier root entry: {name}"
        );
        ensure!(
            observed.insert(name.clone()),
            "duplicate positive verifier root entry: {name}"
        );
        let metadata = fs::symlink_metadata(entry.path())
            .with_context(|| format!("cannot inspect positive verifier root entry {name}"))?;
        reject_link_or_reparse(&entry.path(), &metadata)?;
        ensure!(
            metadata.file_type().is_file(),
            "positive verifier root entry is not a regular file: {name}"
        );
        #[cfg(unix)]
        ensure!(
            hard_link_count(&metadata) == 1,
            "hard-linked positive verifier file is forbidden: {name}"
        );
    }
    let expected = FIXED_ROOT_FILES.into_iter().collect::<BTreeSet<_>>();
    let observed_refs = observed.iter().map(String::as_str).collect::<BTreeSet<_>>();
    ensure!(
        observed_refs == expected,
        "positive verifier root does not contain exactly the seven V1 files"
    );
    Ok(())
}

#[cfg(feature = "validator")]
fn read_fixed_file(
    path: &Path,
    minimum: u64,
    maximum: u64,
    expected_sha256: Option<&str>,
    label: &str,
) -> Result<B4MeasuredPositiveFile> {
    ensure!(
        minimum <= maximum,
        "{label} has an inconsistent internal read bound"
    );
    let before = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect positive verifier file {label}"))?;
    validate_regular_file(path, &before, minimum, maximum, label)?;
    #[cfg(unix)]
    let before_identity = stable_file_identity(&before);

    let mut file =
        File::open(path).with_context(|| format!("cannot open positive verifier file {label}"))?;
    let opened = file
        .metadata()
        .with_context(|| format!("cannot inspect open positive verifier file {label}"))?;
    validate_regular_file(path, &opened, minimum, maximum, label)?;
    ensure!(
        opened.len() == before.len(),
        "positive verifier file {label} changed length while opening"
    );
    #[cfg(unix)]
    ensure!(
        stable_file_identity(&opened) == before_identity,
        "positive verifier file {label} changed identity while opening"
    );

    let exact_length = usize::try_from(opened.len())
        .with_context(|| format!("positive verifier file {label} length exceeds usize"))?;
    let mut bytes = vec![0_u8; exact_length];
    file.read_exact(&mut bytes)
        .with_context(|| format!("positive verifier file {label} ended before declared length"))?;
    let mut trailing = [0_u8; 1];
    ensure!(
        file.read(&mut trailing)
            .with_context(|| format!("cannot check EOF for positive verifier file {label}"))?
            == 0,
        "positive verifier file {label} has trailing bytes"
    );

    let handle_after = file
        .metadata()
        .with_context(|| format!("cannot re-inspect open positive verifier file {label}"))?;
    validate_regular_file(path, &handle_after, minimum, maximum, label)?;
    ensure!(
        handle_after.len() == opened.len(),
        "positive verifier file {label} changed length while reading"
    );
    #[cfg(unix)]
    ensure!(
        stable_file_identity(&handle_after) == before_identity,
        "positive verifier file {label} changed identity while reading"
    );

    let path_after = fs::symlink_metadata(path)
        .with_context(|| format!("cannot re-inspect positive verifier file {label}"))?;
    validate_regular_file(path, &path_after, minimum, maximum, label)?;
    ensure!(
        path_after.len() == opened.len(),
        "positive verifier file {label} changed length after reading"
    );
    #[cfg(unix)]
    ensure!(
        stable_file_identity(&path_after) == before_identity,
        "positive verifier file {label} changed identity after reading"
    );

    let sha256: [u8; 32] = Sha256::digest(&bytes).into();
    if let Some(expected) = expected_sha256 {
        ensure!(
            hex::encode(sha256) == expected,
            "positive verifier file {label} SHA-256 differs from its descriptor"
        );
    }
    Ok(B4MeasuredPositiveFile { bytes, sha256 })
}

#[cfg(feature = "validator")]
fn validate_regular_file(
    path: &Path,
    metadata: &Metadata,
    minimum: u64,
    maximum: u64,
    label: &str,
) -> Result<()> {
    reject_link_or_reparse(path, metadata)?;
    ensure!(
        metadata.file_type().is_file(),
        "positive verifier path is not a regular file: {label}"
    );
    ensure!(
        (minimum..=maximum).contains(&metadata.len()),
        "positive verifier file {label} length is outside its bound"
    );
    #[cfg(unix)]
    ensure!(
        hard_link_count(metadata) == 1,
        "hard-linked positive verifier file is forbidden: {label}"
    );
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} SHA-256 is not exact lowercase hex"
    );
    Ok(())
}

#[cfg(feature = "validator")]
fn reject_link_or_reparse(path: &Path, metadata: &Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || is_windows_reparse_point(metadata) {
        bail!("symlink or reparse point is forbidden: {}", path.display());
    }
    Ok(())
}

#[cfg(all(feature = "validator", windows))]
fn is_windows_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(all(feature = "validator", not(windows)))]
fn is_windows_reparse_point(_metadata: &Metadata) -> bool {
    false
}

#[cfg(all(feature = "validator", unix))]
fn hard_link_count(metadata: &Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt as _;

    metadata.nlink()
}

#[cfg(all(feature = "validator", unix))]
fn stable_file_identity(metadata: &Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt as _;

    (metadata.dev(), metadata.ino())
}

#[cfg(all(test, feature = "validator"))]
mod tests {
    use super::*;

    const B1: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/algorithm.txt");
    const B2: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/constants.bin");
    const MANIFEST: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");

    fn sha256(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn identity(path: &str, bytes: &[u8]) -> B4PositiveFileIdentityV1 {
        B4PositiveFileIdentityV1 {
            path: path.to_owned(),
            byte_length: u64::try_from(bytes.len()).unwrap(),
            sha256: sha256(bytes),
            encoding: B4PositiveFileEncoding::RawBytes,
        }
    }

    fn fixture(root: &Path) -> (Eip0045B4PositiveVerifierInputV1, Vec<u8>, Vec<u8>, Vec<u8>) {
        let guest = b"g".to_vec();
        let statement = vec![0x11; STATEMENT_PREFIX_BYTES];
        let seal = vec![0_u8; PROOF_BYTES];
        let input = Eip0045B4PositiveVerifierInputV1 {
            format: POSITIVE_INPUT_FORMAT.to_owned(),
            format_version: POSITIVE_INPUT_FORMAT_VERSION,
            profile_manifest: identity(PROFILE_MANIFEST_FILE, MANIFEST),
            profile_algorithm: identity(PROFILE_ALGORITHM_FILE, B1),
            profile_constants: identity(PROFILE_CONSTANTS_FILE, B2),
            guest_elf: identity(GUEST_ELF_FILE, &guest),
            statement: identity(STATEMENT_FILE, &statement),
            raw_seal: identity(RAW_SEAL_FILE, &seal),
        };
        fs::write(root.join(PROFILE_MANIFEST_FILE), MANIFEST).unwrap();
        fs::write(root.join(PROFILE_ALGORITHM_FILE), B1).unwrap();
        fs::write(root.join(PROFILE_CONSTANTS_FILE), B2).unwrap();
        fs::write(root.join(GUEST_ELF_FILE), &guest).unwrap();
        fs::write(root.join(STATEMENT_FILE), &statement).unwrap();
        fs::write(root.join(RAW_SEAL_FILE), &seal).unwrap();
        fs::write(
            root.join(POSITIVE_INPUT_FILE),
            input.to_canonical_jcs().unwrap(),
        )
        .unwrap();
        (input, guest, statement, seal)
    }

    #[test]
    fn exact_closed_root_loads_and_remeasures_every_identity() {
        let temp = crate::test_support::tempdir().unwrap();
        let (_, guest, statement, seal) = fixture(temp.path());
        let loaded = load_positive_verifier_root(temp.path()).unwrap();
        assert_eq!(loaded.profile_manifest().bytes(), MANIFEST);
        assert_eq!(loaded.profile_algorithm().bytes(), B1);
        assert_eq!(loaded.profile_constants().bytes(), B2);
        assert_eq!(loaded.guest_elf().bytes(), guest);
        assert_eq!(loaded.statement().bytes(), statement);
        assert_eq!(loaded.raw_seal().bytes(), seal);
    }

    #[test]
    fn exact_byte_views_replay_the_same_closed_descriptor() {
        let temp = crate::test_support::tempdir().unwrap();
        let (input, guest, statement, seal) = fixture(temp.path());
        let input_source = input.to_canonical_jcs().unwrap();
        let sources = B4PositiveVerifierRootSources {
            verifier_input: &input_source,
            profile_manifest: MANIFEST,
            profile_algorithm: B1,
            profile_constants: B2,
            guest_elf: &guest,
            statement: &statement,
            raw_seal: &seal,
        };
        let loaded = load_positive_verifier_root_from_sources(sources).unwrap();
        assert_eq!(loaded.profile_manifest().bytes(), MANIFEST);
        assert_eq!(loaded.profile_algorithm().bytes(), B1);
        assert_eq!(loaded.profile_constants().bytes(), B2);
        assert_eq!(loaded.guest_elf().bytes(), guest);
        assert_eq!(loaded.statement().bytes(), statement);
        assert_eq!(loaded.raw_seal().bytes(), seal);

        let mut changed_statement = statement.clone();
        changed_statement[0] ^= 1;
        assert!(
            load_positive_verifier_root_from_sources(B4PositiveVerifierRootSources {
                statement: &changed_statement,
                ..sources
            })
            .is_err()
        );
    }

    #[test]
    fn extra_missing_and_nonregular_root_entries_are_rejected() {
        let extra = crate::test_support::tempdir().unwrap();
        fixture(extra.path());
        fs::write(extra.path().join("case-label.txt"), b"forbidden").unwrap();
        assert!(load_positive_verifier_root(extra.path()).is_err());

        let missing = crate::test_support::tempdir().unwrap();
        fixture(missing.path());
        fs::remove_file(missing.path().join(RAW_SEAL_FILE)).unwrap();
        assert!(load_positive_verifier_root(missing.path()).is_err());

        let directory = crate::test_support::tempdir().unwrap();
        fixture(directory.path());
        fs::remove_file(directory.path().join(STATEMENT_FILE)).unwrap();
        fs::create_dir(directory.path().join(STATEMENT_FILE)).unwrap();
        assert!(load_positive_verifier_root(directory.path()).is_err());
    }

    #[test]
    fn duplicate_unknown_noncanonical_and_trailing_json_are_rejected() {
        let temp = crate::test_support::tempdir().unwrap();
        let (input, _, _, _) = fixture(temp.path());
        let canonical = input.to_canonical_jcs().unwrap();

        let duplicate = canonical
            .strip_suffix(b"}")
            .unwrap()
            .iter()
            .copied()
            .chain(br#","format":"Eip0045B4PositiveVerifierInputV1"}"#.iter().copied())
            .collect::<Vec<_>>();
        assert!(Eip0045B4PositiveVerifierInputV1::from_canonical_jcs(&duplicate).is_err());

        let mut value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        value["caseLabel"] = serde_json::Value::String("forbidden".to_owned());
        let unknown = canonical_json_bytes(&value).unwrap();
        assert!(Eip0045B4PositiveVerifierInputV1::from_canonical_jcs(&unknown).is_err());

        let pretty = serde_json::to_vec_pretty(&value).unwrap();
        assert!(Eip0045B4PositiveVerifierInputV1::from_canonical_jcs(&pretty).is_err());

        let mut trailing = canonical;
        trailing.push(b'\n');
        assert!(Eip0045B4PositiveVerifierInputV1::from_canonical_jcs(&trailing).is_err());
    }

    #[test]
    fn fixed_and_case_specific_identity_drift_is_rejected() {
        let temp = crate::test_support::tempdir().unwrap();
        let (mut input, _, _, _) = fixture(temp.path());

        input.profile_algorithm.sha256 = "00".repeat(32);
        assert!(input.validate().is_err());

        let (mut input, _, _, _) = fixture(temp.path());
        input.profile_constants.byte_length -= 1;
        assert!(input.validate().is_err());

        let (mut input, _, _, _) = fixture(temp.path());
        input.guest_elf.path = "alternate.elf".to_owned();
        assert!(input.validate().is_err());

        let (mut input, _, _, _) = fixture(temp.path());
        input.raw_seal.byte_length -= 1;
        assert!(input.validate().is_err());
    }

    #[test]
    fn declared_hash_and_physical_length_are_enforced_before_use() {
        let wrong_hash = crate::test_support::tempdir().unwrap();
        let (mut input, _, _, _) = fixture(wrong_hash.path());
        input.statement.sha256 = "00".repeat(32);
        fs::write(
            wrong_hash.path().join(POSITIVE_INPUT_FILE),
            input.to_canonical_jcs().unwrap(),
        )
        .unwrap();
        assert!(load_positive_verifier_root(wrong_hash.path()).is_err());

        let short = crate::test_support::tempdir().unwrap();
        fixture(short.path());
        fs::write(
            short.path().join(RAW_SEAL_FILE),
            vec![0_u8; PROOF_BYTES - 1],
        )
        .unwrap();
        assert!(load_positive_verifier_root(short.path()).is_err());

        let long = crate::test_support::tempdir().unwrap();
        fixture(long.path());
        fs::write(long.path().join(RAW_SEAL_FILE), vec![0_u8; PROOF_BYTES + 1]).unwrap();
        assert!(load_positive_verifier_root(long.path()).is_err());
    }

    #[test]
    fn read_helper_rejects_empty_input_and_does_not_accept_a_directory() {
        let temp = crate::test_support::tempdir().unwrap();
        fs::write(temp.path().join("empty"), []).unwrap();
        assert!(read_fixed_file(&temp.path().join("empty"), 1, 8, None, "empty").is_err());
        fs::create_dir(temp.path().join("directory")).unwrap();
        assert!(read_fixed_file(&temp.path().join("directory"), 1, 8, None, "directory").is_err());
    }
}

#[cfg(all(test, feature = "materializer-replay"))]
mod materializer_input_tests {
    use super::*;

    const PROFILE_ALGORITHM: &[u8] =
        include_bytes!("../../../profiles/risc0-v3-succinct/algorithm.txt");
    const PROFILE_CONSTANTS: &[u8] =
        include_bytes!("../../../profiles/risc0-v3-succinct/constants.bin");
    const PROFILE_MANIFEST: &[u8] =
        include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");

    #[test]
    fn synthesized_descriptor_has_exact_identities_and_canonical_roundtrip() {
        let guest_elf = b"bounded guest fixture";
        let statement = vec![0x11; STATEMENT_PREFIX_BYTES];
        let raw_seal = vec![0x22; PROOF_BYTES];

        let source = synthesize_positive_verifier_input_v1(
            PROFILE_MANIFEST,
            PROFILE_ALGORITHM,
            PROFILE_CONSTANTS,
            guest_elf,
            &statement,
            &raw_seal,
        )
        .unwrap();
        let parsed = Eip0045B4PositiveVerifierInputV1::from_canonical_jcs(&source).unwrap();
        let expected = [
            (
                &parsed.profile_manifest,
                PROFILE_MANIFEST_FILE,
                PROFILE_MANIFEST,
            ),
            (
                &parsed.profile_algorithm,
                PROFILE_ALGORITHM_FILE,
                PROFILE_ALGORITHM,
            ),
            (
                &parsed.profile_constants,
                PROFILE_CONSTANTS_FILE,
                PROFILE_CONSTANTS,
            ),
            (&parsed.guest_elf, GUEST_ELF_FILE, guest_elf.as_slice()),
            (&parsed.statement, STATEMENT_FILE, statement.as_slice()),
            (&parsed.raw_seal, RAW_SEAL_FILE, raw_seal.as_slice()),
        ];
        for (identity, path, bytes) in expected {
            assert_eq!(identity.path, path);
            assert_eq!(identity.byte_length, u64::try_from(bytes.len()).unwrap());
            assert_eq!(identity.sha256, hex::encode(Sha256::digest(bytes)));
            assert_eq!(identity.encoding, B4PositiveFileEncoding::RawBytes);
        }
        assert_eq!(parsed.to_canonical_jcs().unwrap(), source);
        assert!(!source.ends_with(b"\n"));
    }
}
