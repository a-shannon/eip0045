// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Deterministic B3 profile-manifest construction and package verification.
//!
//! This module has no embedded final B1 digest or `profileId`. It derives both
//! from the supplied `algorithm.txt` and the already authenticated B2 bytes.
//! Producing checked-in B3 outputs therefore remains an explicit release step
//! after B1 has passed its independent freeze review.

use std::{fs, io::Write as _, path::Path};

use anyhow::{Context, Result, bail, ensure};
use eip_0045_reproduction::{
    canonical::{canonical_json_bytes, validate_canonical_json_source},
    constants::{
        ALGORITHM_ARTIFACT_KIND, BINARY_DATA_ARTIFACT_KIND, DIGEST_BYTES, MANIFEST_BYTES,
        MANIFEST_FORMAT_VERSION, MAX_APPLICATION_PAYLOAD_BYTES, PROFILE_ARTIFACT_DOMAIN,
        PROFILE_ID_PREIMAGE_BYTES, PROOF_BYTES, PROOF_CHUNK_LENGTHS, RISC0_INNER_CONTROL_ROOT_HEX,
        RISC0_JOIN_CONTROL_ID_HEX, RISC0_NORMAL_LIFT_CONTROL_IDS_HEX, RISC0_OUTER_PO2,
        RISC0_RESOLVE_CONTROL_ID_HEX, SUPPORTED_SEGMENT_PO2, TERMINAL_CONTROL_KIND_JOIN,
        TERMINAL_CONTROL_KIND_LIFT, TERMINAL_CONTROL_KIND_RESOLVE, validate_pinned_invariants,
    },
    profile_manifest::{
        ProfileArtifactReference, ProfileArtifacts, StarkProfileManifestV1, TerminalControl,
        profile_artifact_digest, validate_profile_package_v1,
    },
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::constants_artifact;

/// Normative B1 filename.
pub const ALGORITHM_FILE: &str = "algorithm.txt";
/// Normative B2 filename.
pub const BINARY_DATA_FILE: &str = "constants.bin";
/// Consensus-authoritative Manifest V1 bytes.
pub const MANIFEST_FILE: &str = "manifest.bin";
/// Canonical, derived human/tooling view of `manifest.bin`.
pub const MANIFEST_JSON_FILE: &str = "manifest.json";
/// Exact preimage committed by the algorithm-artifact reference.
pub const ALGORITHM_PREIMAGE_FILE: &str = "algorithm-artifact-preimage.bin";
/// Exact preimage committed by the binary-data-artifact reference.
pub const BINARY_DATA_PREIMAGE_FILE: &str = "binary-data-artifact-preimage.bin";
/// Exact 485-byte preimage hashed to obtain the profile ID.
pub const PROFILE_ID_PREIMAGE_FILE: &str = "profile-id-preimage.bin";
/// Raw 32-byte BLAKE2b-256 profile ID.
pub const PROFILE_ID_FILE: &str = "profile-id.bin";

const MAX_ALGORITHM_BYTES: usize = 1024 * 1024;
const EXPECTED_BINARY_ARTIFACT_DIGEST_HEX: &str =
    "dd8528a8621edc8dd24aadeed7bd7a2f0c1afd88dd563c5ec8f51cc7f75df0b1";

/// Complete deterministic B3 output set held in memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileFreezeBundle {
    manifest: [u8; MANIFEST_BYTES],
    manifest_json: Vec<u8>,
    algorithm_preimage: Vec<u8>,
    binary_data_preimage: Vec<u8>,
    profile_id_preimage: [u8; PROFILE_ID_PREIMAGE_BYTES],
    profile_id: [u8; DIGEST_BYTES],
}

impl ProfileFreezeBundle {
    /// Raw Manifest V1 bytes.
    #[must_use]
    pub const fn manifest(&self) -> &[u8; MANIFEST_BYTES] {
        &self.manifest
    }

    /// RFC 8785 canonical derived JSON view.
    #[must_use]
    pub fn manifest_json(&self) -> &[u8] {
        &self.manifest_json
    }

    /// Exact algorithm-artifact digest preimage.
    #[must_use]
    pub fn algorithm_preimage(&self) -> &[u8] {
        &self.algorithm_preimage
    }

    /// Exact binary-data-artifact digest preimage.
    #[must_use]
    pub fn binary_data_preimage(&self) -> &[u8] {
        &self.binary_data_preimage
    }

    /// Exact profile-ID digest preimage.
    #[must_use]
    pub const fn profile_id_preimage(&self) -> &[u8; PROFILE_ID_PREIMAGE_BYTES] {
        &self.profile_id_preimage
    }

    /// Raw profile ID.
    #[must_use]
    pub const fn profile_id(&self) -> &[u8; DIGEST_BYTES] {
        &self.profile_id
    }
}

/// Read and validate the two normative artifacts from `profile_dir`.
///
/// # Errors
///
/// Returns an error for a missing, linked, oversized, or malformed artifact.
pub fn read_profile_artifacts(profile_dir: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    let algorithm =
        read_regular_bounded(&profile_dir.join(ALGORITHM_FILE), 1, MAX_ALGORITHM_BYTES)?;
    let binary_data = read_regular_bounded(
        &profile_dir.join(BINARY_DATA_FILE),
        constants_artifact::ARTIFACT_BYTES,
        constants_artifact::ARTIFACT_BYTES,
    )?;
    Ok((algorithm, binary_data))
}

/// Derive the complete B3 output set from exact B1 and B2 bytes.
///
/// # Errors
///
/// Returns an error unless B1 has canonical text bytes, B2 is the exact
/// authenticated artifact, all selected construction invariants hold, and the
/// existing Manifest V1 model accepts and round-trips the result.
pub fn build_profile_freeze_bundle(
    algorithm: &[u8],
    binary_data: &[u8],
) -> Result<ProfileFreezeBundle> {
    validate_pinned_invariants().context("selected profile invariants are inconsistent")?;
    let bundle = build_unchecked_bundle(algorithm, binary_data)?;

    let manifest = StarkProfileManifestV1::decode(&bundle.manifest)?;
    ensure!(
        manifest.encode()? == bundle.manifest,
        "manifest did not round-trip"
    );
    validate_profile_package_v1(
        &bundle.manifest,
        ProfileArtifacts {
            algorithm,
            binary_data,
        },
        &bundle.profile_id,
    )?;
    validate_canonical_json_source(&bundle.manifest_json)?;
    verify_profile_freeze_bundle(algorithm, binary_data, &bundle)?;
    Ok(bundle)
}

/// Verify every supplied B3 output against exact B1 and B2 bytes.
///
/// # Errors
///
/// Returns an error for any byte substitution, non-canonical JSON, invalid
/// manifest, artifact-envelope mismatch, or profile-ID mismatch.
pub fn verify_profile_freeze_bundle(
    algorithm: &[u8],
    binary_data: &[u8],
    supplied: &ProfileFreezeBundle,
) -> Result<()> {
    let expected = build_unchecked_bundle(algorithm, binary_data)?;
    ensure!(
        supplied.manifest == expected.manifest,
        "manifest.bin mismatch"
    );
    ensure!(
        supplied.manifest_json == expected.manifest_json,
        "manifest.json mismatch"
    );
    ensure!(
        supplied.algorithm_preimage == expected.algorithm_preimage,
        "algorithm artifact preimage mismatch"
    );
    ensure!(
        supplied.binary_data_preimage == expected.binary_data_preimage,
        "binary-data artifact preimage mismatch"
    );
    ensure!(
        supplied.profile_id_preimage == expected.profile_id_preimage,
        "profile-ID preimage mismatch"
    );
    ensure!(
        supplied.profile_id == expected.profile_id,
        "profile ID mismatch"
    );
    Ok(())
}

/// Generate all B3 outputs into a new directory without overwriting files.
///
/// # Errors
///
/// Returns an error unless the output parent already exists and `output_dir`
/// does not. Inputs are fully validated before the directory is created.
pub fn write_profile_freeze_bundle(
    profile_dir: &Path,
    output_dir: &Path,
) -> Result<ProfileFreezeBundle> {
    let (algorithm, binary_data) = read_profile_artifacts(profile_dir)?;
    let bundle = build_profile_freeze_bundle(&algorithm, &binary_data)?;
    ensure!(
        !output_dir.exists(),
        "refusing to overwrite {}",
        output_dir.display()
    );
    let parent = output_dir
        .parent()
        .context("B3 output directory has no parent")?;
    let metadata = fs::metadata(parent)
        .with_context(|| format!("cannot inspect output parent {}", parent.display()))?;
    ensure!(metadata.is_dir(), "B3 output parent is not a directory");
    fs::create_dir(output_dir)
        .with_context(|| format!("cannot create {}", output_dir.display()))?;
    for (name, bytes) in bundle_files(&bundle) {
        write_new(&output_dir.join(name), bytes)?;
    }
    verify_profile_freeze_directory(profile_dir, output_dir)?;
    Ok(bundle)
}

/// Install all B3 outputs next to B1 and B2 without overwriting any path.
///
/// This release-only operation validates and materializes the complete bundle
/// in memory before its first write. Every destination is preflighted before
/// writing, and an interrupted partial installation remains visibly
/// incomplete and cannot be silently resumed over existing bytes.
///
/// # Errors
///
/// Returns an error unless `profile_dir` is a regular non-link directory and
/// all six output paths are absent, or for any construction/write/verification
/// failure.
pub fn install_profile_freeze_bundle(profile_dir: &Path) -> Result<ProfileFreezeBundle> {
    let metadata = fs::symlink_metadata(profile_dir)
        .with_context(|| format!("cannot inspect profile directory {}", profile_dir.display()))?;
    ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "profile directory is not a regular non-link directory: {}",
        profile_dir.display()
    );
    let (algorithm, binary_data) = read_profile_artifacts(profile_dir)?;
    let bundle = build_profile_freeze_bundle(&algorithm, &binary_data)?;
    for (name, _) in bundle_files(&bundle) {
        preflight_absent(&profile_dir.join(name))?;
    }
    for (name, bytes) in bundle_files(&bundle) {
        write_new(&profile_dir.join(name), bytes)?;
    }
    verify_profile_freeze_directory(profile_dir, profile_dir)?;
    Ok(bundle)
}

/// Verify B3 files from disk against the profile directory's exact B1/B2.
///
/// # Errors
///
/// Returns an error for linked, missing, oversized, malformed, or substituted
/// files, or for any derivation mismatch.
pub fn verify_profile_freeze_directory(profile_dir: &Path, bundle_dir: &Path) -> Result<()> {
    let (algorithm, binary_data) = read_profile_artifacts(profile_dir)?;
    let supplied = ProfileFreezeBundle {
        manifest: read_exact_array(&bundle_dir.join(MANIFEST_FILE))?,
        manifest_json: read_regular_bounded(&bundle_dir.join(MANIFEST_JSON_FILE), 1, 64 * 1024)?,
        algorithm_preimage: read_regular_bounded(
            &bundle_dir.join(ALGORITHM_PREIMAGE_FILE),
            1,
            MAX_ALGORITHM_BYTES + 64,
        )?,
        binary_data_preimage: read_regular_bounded(
            &bundle_dir.join(BINARY_DATA_PREIMAGE_FILE),
            1,
            constants_artifact::ARTIFACT_BYTES + 64,
        )?,
        profile_id_preimage: read_exact_array(&bundle_dir.join(PROFILE_ID_PREIMAGE_FILE))?,
        profile_id: read_exact_array(&bundle_dir.join(PROFILE_ID_FILE))?,
    };
    validate_canonical_json_source(&supplied.manifest_json)?;
    let decoded = StarkProfileManifestV1::decode(&supplied.manifest)?;
    decoded.validate_initial_profile_target()?;
    validate_profile_package_v1(
        &supplied.manifest,
        ProfileArtifacts {
            algorithm: &algorithm,
            binary_data: &binary_data,
        },
        &supplied.profile_id,
    )?;
    verify_profile_freeze_bundle(&algorithm, &binary_data, &supplied)
}

fn build_unchecked_bundle(algorithm: &[u8], binary_data: &[u8]) -> Result<ProfileFreezeBundle> {
    validate_algorithm_bytes(algorithm)?;
    let decoded_b2 = constants_artifact::verify_canonical(binary_data)
        .context("B2 is not the exact authenticated constants artifact")?;
    ensure!(decoded_b2.stark.queries == 50, "B2 query count is not 50");
    ensure!(
        PROOF_CHUNK_LENGTHS == [65_535, 65_535, 65_535, 26_063],
        "canonical proof chunk partition changed"
    );

    let algorithm_reference =
        ProfileArtifactReference::from_artifact(ALGORITHM_ARTIFACT_KIND, algorithm)?;
    let binary_reference =
        ProfileArtifactReference::from_artifact(BINARY_DATA_ARTIFACT_KIND, binary_data)?;
    ensure!(
        hex::encode(binary_reference.artifact_digest()) == EXPECTED_BINARY_ARTIFACT_DIGEST_HEX,
        "B2 domain-separated artifact digest changed"
    );
    ensure!(
        profile_artifact_digest(ALGORITHM_ARTIFACT_KIND, algorithm)?
            == algorithm_reference.artifact_digest(),
        "algorithm artifact digest construction disagrees"
    );
    ensure!(
        profile_artifact_digest(BINARY_DATA_ARTIFACT_KIND, binary_data)?
            == binary_reference.artifact_digest(),
        "binary-data artifact digest construction disagrees"
    );

    let manifest = StarkProfileManifestV1::new(
        u32::try_from(PROOF_BYTES).context("proof length does not fit u32")?,
        u32::try_from(MAX_APPLICATION_PAYLOAD_BYTES).context("payload limit does not fit u32")?,
        RISC0_OUTER_PO2,
        decode_digest(RISC0_INNER_CONTROL_ROOT_HEX)?,
        initial_terminal_controls()?,
        algorithm_reference,
        binary_reference,
    )?;
    manifest.validate_initial_profile_target()?;
    manifest.validate_artifact_package(algorithm, binary_data)?;
    let manifest_bytes = manifest.encode()?;
    let algorithm_preimage = artifact_preimage(ALGORITHM_ARTIFACT_KIND, algorithm)?;
    let binary_data_preimage = artifact_preimage(BINARY_DATA_ARTIFACT_KIND, binary_data)?;
    let profile_id_preimage = manifest.profile_id_preimage()?;
    let profile_id = manifest.profile_id()?;
    let manifest_json = build_manifest_json(
        &manifest,
        &manifest_bytes,
        &algorithm_preimage,
        &binary_data_preimage,
        &profile_id_preimage,
        &profile_id,
    )?;
    Ok(ProfileFreezeBundle {
        manifest: manifest_bytes,
        manifest_json,
        algorithm_preimage,
        binary_data_preimage,
        profile_id_preimage,
        profile_id,
    })
}

fn validate_algorithm_bytes(bytes: &[u8]) -> Result<()> {
    ensure!(!bytes.is_empty(), "B1 is empty");
    ensure!(bytes.len() <= MAX_ALGORITHM_BYTES, "B1 exceeds one MiB");
    ensure!(
        !bytes.starts_with(&[0xef, 0xbb, 0xbf]),
        "B1 has a UTF-8 BOM"
    );
    ensure!(!bytes.contains(&0), "B1 contains a NUL byte");
    ensure!(!bytes.contains(&b'\r'), "B1 contains a CR byte");
    ensure!(bytes.is_ascii(), "B1 is not exact ASCII");
    ensure!(bytes.ends_with(b"\n"), "B1 does not end in LF");
    ensure!(!bytes.ends_with(b"\n\n"), "B1 has more than one final LF");
    Ok(())
}

fn artifact_preimage(kind: u16, bytes: &[u8]) -> Result<Vec<u8>> {
    let length = u32::try_from(bytes.len()).context("profile artifact exceeds u32")?;
    let capacity = PROFILE_ARTIFACT_DOMAIN
        .len()
        .checked_add(1 + 2 + 4)
        .and_then(|value| value.checked_add(bytes.len()))
        .context("artifact preimage length overflow")?;
    let mut preimage = Vec::with_capacity(capacity);
    preimage.extend_from_slice(PROFILE_ARTIFACT_DOMAIN);
    preimage.push(0);
    preimage.extend_from_slice(&kind.to_le_bytes());
    preimage.extend_from_slice(&length.to_le_bytes());
    preimage.extend_from_slice(bytes);
    ensure!(
        preimage.len() == capacity,
        "artifact preimage length mismatch"
    );
    Ok(preimage)
}

fn initial_terminal_controls() -> Result<[TerminalControl; 10]> {
    let mut controls = SUPPORTED_SEGMENT_PO2
        .iter()
        .copied()
        .zip(RISC0_NORMAL_LIFT_CONTROL_IDS_HEX.iter().copied())
        .map(|(po2, digest)| {
            Ok(TerminalControl::new(
                TERMINAL_CONTROL_KIND_LIFT,
                po2,
                decode_digest(digest)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    controls.push(TerminalControl::new(
        TERMINAL_CONTROL_KIND_JOIN,
        0,
        decode_digest(RISC0_JOIN_CONTROL_ID_HEX)?,
    ));
    controls.push(TerminalControl::new(
        TERMINAL_CONTROL_KIND_RESOLVE,
        0,
        decode_digest(RISC0_RESOLVE_CONTROL_ID_HEX)?,
    ));
    controls
        .try_into()
        .map_err(|_| anyhow::anyhow!("initial terminal-control table is not exactly ten entries"))
}

fn decode_digest(value: &str) -> Result<[u8; DIGEST_BYTES]> {
    let mut digest = [0u8; DIGEST_BYTES];
    hex::decode_to_slice(value, &mut digest).context("embedded digest is not exact 32-byte hex")?;
    Ok(digest)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ManifestJson<'a> {
    artifacts: [ArtifactJson<'a>; 2],
    exact_proof_bytes: u32,
    format: &'static str,
    format_version: u8,
    inner_control_root: String,
    manifest_bytes: usize,
    manifest_sha256: String,
    max_application_payload_bytes: u32,
    outer_po2: u8,
    profile_id: String,
    profile_id_file: &'static str,
    profile_id_preimage_bytes: usize,
    profile_id_preimage_file: &'static str,
    profile_id_preimage_sha256: String,
    terminal_controls: Vec<TerminalControlJson>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactJson<'a> {
    artifact_digest: String,
    artifact_kind: u16,
    artifact_length: u32,
    artifact_preimage_file: &'static str,
    artifact_preimage_sha256: String,
    file: &'static str,
    role: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TerminalControlJson {
    control_id: String,
    control_kind: u8,
    parameter: u8,
}

fn build_manifest_json(
    manifest: &StarkProfileManifestV1,
    manifest_bytes: &[u8; MANIFEST_BYTES],
    algorithm_preimage: &[u8],
    binary_data_preimage: &[u8],
    profile_id_preimage: &[u8; PROFILE_ID_PREIMAGE_BYTES],
    profile_id: &[u8; DIGEST_BYTES],
) -> Result<Vec<u8>> {
    let algorithm = manifest.algorithm_artifact();
    let binary = manifest.binary_data_artifact();
    let view = ManifestJson {
        artifacts: [
            ArtifactJson {
                artifact_digest: hex::encode(algorithm.artifact_digest()),
                artifact_kind: algorithm.artifact_kind(),
                artifact_length: algorithm.artifact_length(),
                artifact_preimage_file: ALGORITHM_PREIMAGE_FILE,
                artifact_preimage_sha256: sha256_hex(algorithm_preimage),
                file: ALGORITHM_FILE,
                role: "normative-algorithm",
            },
            ArtifactJson {
                artifact_digest: hex::encode(binary.artifact_digest()),
                artifact_kind: binary.artifact_kind(),
                artifact_length: binary.artifact_length(),
                artifact_preimage_file: BINARY_DATA_PREIMAGE_FILE,
                artifact_preimage_sha256: sha256_hex(binary_data_preimage),
                file: BINARY_DATA_FILE,
                role: "normative-binary-data",
            },
        ],
        exact_proof_bytes: manifest.exact_proof_bytes(),
        format: "StarkProfileManifestV1",
        format_version: MANIFEST_FORMAT_VERSION,
        inner_control_root: hex::encode(manifest.inner_control_root()),
        manifest_bytes: MANIFEST_BYTES,
        manifest_sha256: sha256_hex(manifest_bytes),
        max_application_payload_bytes: manifest.max_application_payload_bytes(),
        outer_po2: manifest.outer_po2(),
        profile_id: hex::encode(profile_id),
        profile_id_file: PROFILE_ID_FILE,
        profile_id_preimage_bytes: PROFILE_ID_PREIMAGE_BYTES,
        profile_id_preimage_file: PROFILE_ID_PREIMAGE_FILE,
        profile_id_preimage_sha256: sha256_hex(profile_id_preimage),
        terminal_controls: manifest
            .terminal_controls()
            .iter()
            .copied()
            .map(|control| TerminalControlJson {
                control_id: hex::encode(control.control_id()),
                control_kind: control.control_kind(),
                parameter: control.parameter(),
            })
            .collect(),
    };
    let value = serde_json::to_value(view).context("cannot serialize manifest JSON view")?;
    canonical_json_bytes(&value)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn bundle_files(bundle: &ProfileFreezeBundle) -> [(&'static str, &[u8]); 6] {
    [
        (MANIFEST_FILE, &bundle.manifest),
        (MANIFEST_JSON_FILE, &bundle.manifest_json),
        (ALGORITHM_PREIMAGE_FILE, &bundle.algorithm_preimage),
        (BINARY_DATA_PREIMAGE_FILE, &bundle.binary_data_preimage),
        (PROFILE_ID_PREIMAGE_FILE, &bundle.profile_id_preimage),
        (PROFILE_ID_FILE, &bundle.profile_id),
    ]
}

fn read_regular_bounded(path: &Path, minimum: usize, maximum: usize) -> Result<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("cannot inspect {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "input is not a regular non-link file: {}",
        path.display()
    );
    let physical = usize::try_from(metadata.len()).context("file length does not fit usize")?;
    ensure!(
        (minimum..=maximum).contains(&physical),
        "{} has {physical} bytes, expected {minimum}..={maximum}",
        path.display()
    );
    let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    ensure!(
        bytes.len() == physical,
        "file changed while being read: {}",
        path.display()
    );
    Ok(bytes)
}

fn read_exact_array<const N: usize>(path: &Path) -> Result<[u8; N]> {
    read_regular_bounded(path, N, N)?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!("{} has {} bytes, expected {N}", path.display(), bytes.len())
        })
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("refusing to overwrite {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("cannot write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("cannot sync {}", path.display()))?;
    Ok(())
}

fn preflight_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!("refusing to overwrite {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("cannot inspect {}", path.display())),
    }
}

/// Read-only summary returned by the CLI after verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileFreezeSummary {
    /// Exact profile ID as lowercase hex.
    pub profile_id_hex: String,
    /// Exact manifest SHA-256 as lowercase hex.
    pub manifest_sha256: String,
}

/// Verify a disk bundle and return its stable identities.
///
/// # Errors
///
/// Returns any strict directory-verification error.
pub fn verified_summary(profile_dir: &Path, bundle_dir: &Path) -> Result<ProfileFreezeSummary> {
    verify_profile_freeze_directory(profile_dir, bundle_dir)?;
    let profile_id = read_exact_array::<DIGEST_BYTES>(&bundle_dir.join(PROFILE_ID_FILE))?;
    let manifest = read_exact_array::<MANIFEST_BYTES>(&bundle_dir.join(MANIFEST_FILE))?;
    Ok(ProfileFreezeSummary {
        profile_id_hex: hex::encode(profile_id),
        manifest_sha256: sha256_hex(&manifest),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const B1: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/algorithm.txt");
    const B2: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/constants.bin");

    #[test]
    fn current_inputs_build_twice_byte_for_byte_without_freezing_an_identity() {
        let first = build_profile_freeze_bundle(B1, B2).unwrap();
        let second = build_profile_freeze_bundle(B1, B2).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.manifest().len(), MANIFEST_BYTES);
        assert_eq!(first.profile_id_preimage().len(), PROFILE_ID_PREIMAGE_BYTES);
        assert_eq!(first.profile_id().len(), DIGEST_BYTES);
        assert!(!first.manifest_json().ends_with(b"\n"));

        let json: serde_json::Value = serde_json::from_slice(first.manifest_json()).unwrap();
        assert!(json.get("controls").is_none());
        let terminal_controls = json["terminalControls"].as_array().unwrap();
        assert_eq!(terminal_controls.len(), 10);
        assert_eq!(terminal_controls[0]["controlKind"], 1);
        assert_eq!(terminal_controls[0]["parameter"], 15);
        assert_eq!(terminal_controls[8]["controlKind"], 2);
        assert_eq!(terminal_controls[8]["parameter"], 0);
        assert_eq!(terminal_controls[8]["controlId"], RISC0_JOIN_CONTROL_ID_HEX);
        assert_eq!(terminal_controls[9]["controlKind"], 3);
        assert_eq!(terminal_controls[9]["parameter"], 0);
        assert_eq!(
            terminal_controls[9]["controlId"],
            RISC0_RESOLVE_CONTROL_ID_HEX
        );
    }

    #[test]
    fn exact_artifact_and_profile_preimage_envelopes_are_visible() {
        let bundle = build_profile_freeze_bundle(B1, B2).unwrap();
        let prefix = [PROFILE_ARTIFACT_DOMAIN, &[0]].concat();
        assert!(bundle.algorithm_preimage().starts_with(&prefix));
        assert_eq!(
            &bundle.algorithm_preimage()[prefix.len()..prefix.len() + 2],
            &ALGORITHM_ARTIFACT_KIND.to_le_bytes()
        );
        assert_eq!(
            &bundle.binary_data_preimage()[prefix.len()..prefix.len() + 2],
            &BINARY_DATA_ARTIFACT_KIND.to_le_bytes()
        );
        assert_eq!(&bundle.profile_id_preimage()[27..], bundle.manifest());
    }

    #[test]
    fn a_valid_b1_byte_change_changes_both_commitments() {
        let original = build_profile_freeze_bundle(B1, B2).unwrap();
        let mut changed_b1 = B1.to_vec();
        let index = changed_b1.iter().position(|byte| *byte == b'a').unwrap();
        changed_b1[index] = b'A';
        let changed = build_profile_freeze_bundle(&changed_b1, B2).unwrap();
        assert_ne!(original.algorithm_preimage(), changed.algorithm_preimage());
        assert_ne!(original.manifest(), changed.manifest());
        assert_ne!(original.profile_id(), changed.profile_id());
    }

    #[test]
    fn malformed_or_substituted_normative_artifacts_are_rejected() {
        for malformed in [
            b"missing-final-lf".as_slice(),
            b"double-final-lf\n\n".as_slice(),
            b"contains\r\ncrlf\n".as_slice(),
            b"contains\0nul\n".as_slice(),
            b"\xef\xbb\xbfhas-bom\n".as_slice(),
        ] {
            assert!(build_profile_freeze_bundle(malformed, B2).is_err());
        }
        let mut changed_b2 = B2.to_vec();
        changed_b2[100] ^= 1;
        assert!(build_profile_freeze_bundle(B1, &changed_b2).is_err());
    }

    #[test]
    fn every_derived_output_is_bound_byte_for_byte() {
        let bundle = build_profile_freeze_bundle(B1, B2).unwrap();

        let mut changed = bundle.clone();
        changed.manifest[0] ^= 1;
        assert!(verify_profile_freeze_bundle(B1, B2, &changed).is_err());

        let mut changed = bundle.clone();
        changed.manifest_json[0] ^= 1;
        assert!(verify_profile_freeze_bundle(B1, B2, &changed).is_err());

        let mut changed = bundle.clone();
        changed.algorithm_preimage[0] ^= 1;
        assert!(verify_profile_freeze_bundle(B1, B2, &changed).is_err());

        let mut changed = bundle.clone();
        changed.binary_data_preimage[0] ^= 1;
        assert!(verify_profile_freeze_bundle(B1, B2, &changed).is_err());

        let mut changed = bundle.clone();
        changed.profile_id_preimage[0] ^= 1;
        assert!(verify_profile_freeze_bundle(B1, B2, &changed).is_err());

        let mut changed = bundle;
        changed.profile_id[0] ^= 1;
        assert!(verify_profile_freeze_bundle(B1, B2, &changed).is_err());
    }
}
