// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Create-only construction and strict verification of the reference statement bundle.

use std::{
    collections::BTreeSet,
    fs::{self, Metadata},
    io::Write as _,
    path::Path,
};

use anyhow::{Context, Result, ensure};
use eip_0045_reproduction::{
    canonical::{canonical_json_bytes, validate_canonical_json_source},
    claim::{ReceiptClaimDigests, ok_receipt_claim_digests},
    constants::{DIGEST_BYTES, ERGO_STATEMENT_DOMAIN, MAX_APPLICATION_PAYLOAD_BYTES},
    profile::{contract_id, ergo_statement_v1},
};
use risc0_zkvm::compute_image_id;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::profile_freeze::{
    build_profile_freeze_bundle, read_profile_artifacts, verify_profile_freeze_directory,
};

/// Maximum canonical Ergo proposition length accepted by this builder.
pub const MAX_PROPOSITION_BYTES: usize = 4096;
/// Maximum guest ELF size accepted by the reference statement builder.
pub const MAX_GUEST_ELF_BYTES: usize = 4 * 1024 * 1024;

/// Exact chain-domain input copied into the self-contained bundle.
pub const CHAIN_DOMAIN_ID_FILE: &str = "chain-domain-id.bin";
/// Exact profile ID derived from the verified B3 package.
pub const PROFILE_ID_FILE: &str = "profile-id.bin";
/// Exact RISC Zero guest image ID.
pub const PROGRAM_ID_FILE: &str = "program-id.bin";
/// Canonical `SELF.propositionBytes` used to derive the contract ID.
pub const PROPOSITION_FILE: &str = "proposition.bin";
/// Exact application payload committed by the statement.
pub const APPLICATION_PAYLOAD_FILE: &str = "application-payload.bin";
/// Raw `BLAKE2b-256(SELF.propositionBytes)`.
pub const CONTRACT_ID_FILE: &str = "contract-id.bin";
/// Exact `ErgoStatementV1` journal bytes.
pub const STATEMENT_FILE: &str = "statement.bin";
/// Raw SHA-256 journal digest.
pub const JOURNAL_DIGEST_FILE: &str = "journal-digest.bin";
/// Raw RISC Zero post-state digest.
pub const POST_DIGEST_FILE: &str = "post-digest.bin";
/// Raw RISC Zero output digest.
pub const OUTPUT_DIGEST_FILE: &str = "output-digest.bin";
/// Raw expected RISC Zero receipt-claim digest.
pub const CLAIM_DIGEST_FILE: &str = "claim-digest.bin";
/// Canonical JSON identity and artifact manifest.
pub const STATEMENT_MANIFEST_FILE: &str = "statement-manifest.json";

const STATEMENT_FORMAT: &str = "ErgoStatementBundleV1";
const STATEMENT_FORMAT_VERSION: u8 = 1;
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const REFERENCE_CHAIN_DOMAIN_ID_HEX: &str =
    "b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b";
const REFERENCE_PROFILE_ID_HEX: &str =
    "23c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383";
const REFERENCE_PROGRAM_ID_HEX: &str =
    "9490a07414919c7eca0176d4ff9614523beecc8746ae7ffd4916f29b2edb9fe5";
const REFERENCE_PROPOSITION_SHA256: &str =
    "a3df052fa7d25dfd9eed6370d9f60db6aee7ef5cc8124c59f52fc171ed16ddd0";
const REFERENCE_CONTRACT_ID_HEX: &str =
    "f3582418f41ba6920c83758e56ac4475bf6084a039f91a762388e774258a6c61";
const REFERENCE_TREE_PREFIX: [u8; 5] = [0x1c, 0x53, 0x02, 0x0e, 0x20];
const REFERENCE_SECOND_CONSTANT_PREFIX: [u8; 2] = [0x0e, 0x20];
const REFERENCE_TREE_EXPRESSION: [u8; 14] = [
    0xd1, 0xb9, 0xe4, 0xe3, 0x00, 0x1a, 0xe4, 0xe3, 0x01, 0x0e, 0x73, 0x00, 0x73, 0x01,
];

const CLOSED_FILE_SET: [&str; 12] = [
    APPLICATION_PAYLOAD_FILE,
    CHAIN_DOMAIN_ID_FILE,
    CLAIM_DIGEST_FILE,
    CONTRACT_ID_FILE,
    JOURNAL_DIGEST_FILE,
    OUTPUT_DIGEST_FILE,
    POST_DIGEST_FILE,
    PROFILE_ID_FILE,
    PROGRAM_ID_FILE,
    PROPOSITION_FILE,
    STATEMENT_FILE,
    STATEMENT_MANIFEST_FILE,
];

/// Complete deterministic reference statement bundle held in memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementBundle {
    chain_domain_id: [u8; DIGEST_BYTES],
    profile_id: [u8; DIGEST_BYTES],
    program_id: [u8; DIGEST_BYTES],
    proposition: Vec<u8>,
    application_payload: Vec<u8>,
    contract_id: [u8; DIGEST_BYTES],
    statement: Vec<u8>,
    claim: ReceiptClaimDigests,
    manifest: Vec<u8>,
}

impl StatementBundle {
    /// Exact statement bytes committed as the receipt journal.
    #[must_use]
    pub fn statement(&self) -> &[u8] {
        &self.statement
    }

    /// Contract ID derived from the exact proposition bytes.
    #[must_use]
    pub const fn contract_id(&self) -> &[u8; DIGEST_BYTES] {
        &self.contract_id
    }

    /// Profile ID derived from the verified B3 package.
    #[must_use]
    pub const fn profile_id(&self) -> &[u8; DIGEST_BYTES] {
        &self.profile_id
    }

    /// Canonical statement-bundle manifest bytes.
    #[must_use]
    pub fn manifest(&self) -> &[u8] {
        &self.manifest
    }

    /// Receipt claim digests derived from the exact statement and program ID.
    #[must_use]
    pub const fn claim(&self) -> &ReceiptClaimDigests {
        &self.claim
    }
}

/// Independently serialize the fixed v4 reference contract from its two constants.
///
/// This is a narrow byte-level serializer for exactly:
/// `VerifyStark(GetVar(0).get, GetVar(1).get, programId, profileId).toSigmaProp`
/// with constant segregation. It intentionally does not call `SigmaState` and is
/// compared byte-for-byte with the SigmaState-generated golden proposition.
///
/// # Errors
///
/// Returns an error if the independently derived fixed length changes.
pub fn reference_contract_proposition_bytes(
    program_id: &[u8; DIGEST_BYTES],
    profile_id: &[u8; DIGEST_BYTES],
) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(85);
    bytes.extend_from_slice(&REFERENCE_TREE_PREFIX);
    bytes.extend_from_slice(program_id);
    bytes.extend_from_slice(&REFERENCE_SECOND_CONSTANT_PREFIX);
    bytes.extend_from_slice(profile_id);
    bytes.extend_from_slice(&REFERENCE_TREE_EXPRESSION);
    ensure!(
        bytes.len() == 85,
        "independent reference proposition length changed"
    );
    Ok(bytes)
}

/// Build a complete deterministic statement bundle from already authenticated inputs.
///
/// # Errors
///
/// Returns an error for an empty or oversized proposition, an oversized payload,
/// a failed statement or claim construction, or non-canonical manifest output.
pub fn build_statement_bundle(
    chain_domain_id: [u8; DIGEST_BYTES],
    profile_id: [u8; DIGEST_BYTES],
    program_id: [u8; DIGEST_BYTES],
    proposition: &[u8],
    application_payload: &[u8],
) -> Result<StatementBundle> {
    ensure!(!proposition.is_empty(), "proposition bytes are empty");
    ensure!(
        proposition.len() <= MAX_PROPOSITION_BYTES,
        "proposition has {} bytes, maximum is {MAX_PROPOSITION_BYTES}",
        proposition.len()
    );
    ensure!(
        application_payload.len() <= MAX_APPLICATION_PAYLOAD_BYTES,
        "application payload has {} bytes, maximum is {MAX_APPLICATION_PAYLOAD_BYTES}",
        application_payload.len()
    );
    ensure!(
        chain_domain_id == decode_digest(REFERENCE_CHAIN_DOMAIN_ID_HEX)?,
        "chain domain ID is not the frozen mainnet reference value"
    );
    ensure!(
        profile_id == decode_digest(REFERENCE_PROFILE_ID_HEX)?,
        "profile ID is not the current B3 reference value"
    );
    ensure!(
        program_id == decode_digest(REFERENCE_PROGRAM_ID_HEX)?,
        "program ID is not the frozen reference guest image ID"
    );
    let expected_payload: Vec<u8> = (0_u8..32).collect();
    ensure!(
        application_payload == expected_payload,
        "application payload is not the frozen 00..1f reference value"
    );
    let independently_serialized = reference_contract_proposition_bytes(&program_id, &profile_id)?;
    ensure!(
        proposition == independently_serialized,
        "proposition bytes do not match the independently serialized v4 reference contract"
    );
    ensure!(
        sha256_hex(proposition) == REFERENCE_PROPOSITION_SHA256,
        "reference proposition SHA-256 changed"
    );

    let contract_id = contract_id(proposition);
    ensure!(
        hex::encode(contract_id) == REFERENCE_CONTRACT_ID_HEX,
        "reference contract ID changed"
    );
    let statement = ergo_statement_v1(
        &chain_domain_id,
        &profile_id,
        &program_id,
        proposition,
        application_payload,
    )
    .context("cannot construct ErgoStatementV1")?;
    let claim = ok_receipt_claim_digests(&program_id, &statement)
        .context("cannot derive the RISC Zero receipt claim")?;
    let manifest = build_manifest(
        &chain_domain_id,
        &profile_id,
        &program_id,
        proposition,
        application_payload,
        &contract_id,
        &statement,
        &claim,
    )?;
    validate_canonical_json_source(&manifest)?;

    Ok(StatementBundle {
        chain_domain_id,
        profile_id,
        program_id,
        proposition: proposition.to_vec(),
        application_payload: application_payload.to_vec(),
        contract_id,
        statement,
        claim,
        manifest,
    })
}

/// Generate a self-contained statement bundle into a new directory.
///
/// The complete B3 package is verified and the profile ID is independently
/// derived before any output path is created. Every output uses create-new
/// semantics; an interrupted partial directory is never resumed in place.
///
/// # Errors
///
/// Returns an error unless all inputs are regular non-link files with exact
/// bounds, B3 verifies, the output parent is a regular non-link directory, and
/// the output directory does not already exist.
pub fn write_statement_bundle(
    profile_dir: &Path,
    chain_domain_id_file: &Path,
    program_id_file: &Path,
    proposition_file: &Path,
    application_payload_file: &Path,
    output_dir: &Path,
) -> Result<StatementBundle> {
    let profile_id = derive_verified_profile_id(profile_dir)?;
    let chain_domain_id = read_exact_array(chain_domain_id_file)?;
    let program_id = read_exact_array(program_id_file)?;
    let proposition = read_regular_bounded(proposition_file, 1, MAX_PROPOSITION_BYTES)?;
    let application_payload =
        read_regular_bounded(application_payload_file, 0, MAX_APPLICATION_PAYLOAD_BYTES)?;
    let bundle = build_statement_bundle(
        chain_domain_id,
        profile_id,
        program_id,
        &proposition,
        &application_payload,
    )?;
    install_statement_bundle(profile_dir, output_dir, &bundle)?;
    Ok(bundle)
}

/// Derive and write the exact reference statement from one guest ELF.
///
/// The chain domain, 32-byte conformance payload, profile ID, proposition, and
/// contract ID are fixed or derived internally. The program ID is computed
/// directly from the bounded ELF; callers cannot supply an independent image
/// ID or proposition.
///
/// # Errors
///
/// Returns an error unless B3 verifies, the ELF is a regular bounded non-link
/// file with the frozen image ID, every derived binding is exact, and a new
/// output directory can be populated with create-new writes and replayed.
pub fn write_reference_statement_bundle(
    profile_dir: &Path,
    guest_elf_file: &Path,
    output_dir: &Path,
) -> Result<StatementBundle> {
    let profile_id = derive_verified_profile_id(profile_dir)?;
    let guest_elf = read_regular_bounded(guest_elf_file, 1, MAX_GUEST_ELF_BYTES)?;
    let program_digest =
        compute_image_id(&guest_elf).context("cannot compute reference guest ELF image ID")?;
    let program_id: [u8; DIGEST_BYTES] = program_digest
        .as_bytes()
        .try_into()
        .context("computed reference guest image ID is not exactly 32 bytes")?;
    let chain_domain_id = decode_digest(REFERENCE_CHAIN_DOMAIN_ID_HEX)?;
    let proposition = reference_contract_proposition_bytes(&program_id, &profile_id)?;
    let application_payload = (0_u8..32).collect::<Vec<_>>();
    let bundle = build_statement_bundle(
        chain_domain_id,
        profile_id,
        program_id,
        &proposition,
        &application_payload,
    )?;
    install_statement_bundle(profile_dir, output_dir, &bundle)?;
    Ok(bundle)
}

fn install_statement_bundle(
    profile_dir: &Path,
    output_dir: &Path,
    bundle: &StatementBundle,
) -> Result<()> {
    ensure!(
        !output_dir.exists(),
        "refusing to overwrite {}",
        output_dir.display()
    );
    let parent = output_dir
        .parent()
        .context("statement output directory has no parent")?;
    require_regular_directory(parent)?;
    fs::create_dir(output_dir)
        .with_context(|| format!("cannot create {}", output_dir.display()))?;
    for (name, bytes) in bundle_files(bundle) {
        write_new(&output_dir.join(name), bytes)?;
    }
    verify_statement_bundle_directory(profile_dir, output_dir)?;
    Ok(())
}

/// Strictly verify a self-contained statement bundle from disk.
///
/// # Errors
///
/// Returns an error for any missing, linked, extra, oversized, non-canonical,
/// substituted, or internally inconsistent file, or if the profile no longer
/// derives from the exact verified B3 package.
pub fn verify_statement_bundle_directory(profile_dir: &Path, bundle_dir: &Path) -> Result<()> {
    require_regular_directory(bundle_dir)?;
    verify_closed_file_set(bundle_dir)?;
    let profile_id = derive_verified_profile_id(profile_dir)?;
    let supplied_profile_id = read_exact_array(&bundle_dir.join(PROFILE_ID_FILE))?;
    ensure!(
        supplied_profile_id == profile_id,
        "bundle profile ID differs from the verified B3 package"
    );
    let expected = build_statement_bundle(
        read_exact_array(&bundle_dir.join(CHAIN_DOMAIN_ID_FILE))?,
        profile_id,
        read_exact_array(&bundle_dir.join(PROGRAM_ID_FILE))?,
        &read_regular_bounded(&bundle_dir.join(PROPOSITION_FILE), 1, MAX_PROPOSITION_BYTES)?,
        &read_regular_bounded(
            &bundle_dir.join(APPLICATION_PAYLOAD_FILE),
            0,
            MAX_APPLICATION_PAYLOAD_BYTES,
        )?,
    )?;

    for (name, expected_bytes) in bundle_files(&expected) {
        let supplied = read_regular_bounded(
            &bundle_dir.join(name),
            expected_bytes.len(),
            expected_bytes.len(),
        )?;
        if name == STATEMENT_MANIFEST_FILE {
            validate_canonical_json_source(&supplied)?;
        }
        ensure!(supplied == expected_bytes, "{name} mismatch");
    }
    Ok(())
}

/// Stable identities returned after strict statement-bundle verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementBundleSummary {
    /// Exact statement length in bytes.
    pub statement_bytes: usize,
    /// SHA-256 of the exact statement bytes.
    pub statement_sha256: String,
    /// BLAKE2b-256 contract ID as lowercase hex.
    pub contract_id_hex: String,
    /// SHA-256 journal digest as lowercase hex.
    pub journal_digest_hex: String,
    /// Expected receipt-claim digest as lowercase hex.
    pub claim_digest_hex: String,
}

/// Verify a disk bundle and return its stable identities.
///
/// # Errors
///
/// Returns any strict directory-verification error.
pub fn verified_statement_summary(
    profile_dir: &Path,
    bundle_dir: &Path,
) -> Result<StatementBundleSummary> {
    verify_statement_bundle_directory(profile_dir, bundle_dir)?;
    let statement = read_regular_bounded(
        &bundle_dir.join(STATEMENT_FILE),
        ERGO_STATEMENT_DOMAIN.len() + 1,
        ERGO_STATEMENT_DOMAIN.len() + 1 + 4 * DIGEST_BYTES + 4 + MAX_APPLICATION_PAYLOAD_BYTES,
    )?;
    Ok(StatementBundleSummary {
        statement_bytes: statement.len(),
        statement_sha256: sha256_hex(&statement),
        contract_id_hex: hex::encode(read_exact_array::<DIGEST_BYTES>(
            &bundle_dir.join(CONTRACT_ID_FILE),
        )?),
        journal_digest_hex: hex::encode(read_exact_array::<DIGEST_BYTES>(
            &bundle_dir.join(JOURNAL_DIGEST_FILE),
        )?),
        claim_digest_hex: hex::encode(read_exact_array::<DIGEST_BYTES>(
            &bundle_dir.join(CLAIM_DIGEST_FILE),
        )?),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatementManifest {
    artifacts: Vec<ArtifactIdentity>,
    claim: ClaimIdentity,
    format: &'static str,
    format_version: u8,
    statement: StatementIdentity,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactIdentity {
    length: usize,
    path: &'static str,
    role: &'static str,
    sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClaimIdentity {
    expected_claim: String,
    journal_digest: String,
    output: String,
    post: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatementIdentity {
    application_payload_length: usize,
    chain_domain_id: String,
    contract_id: String,
    domain_hex: String,
    profile_id: String,
    program_id: String,
    proposition_bytes_length: usize,
    statement_length: usize,
    statement_sha256: String,
    version: u8,
}

#[allow(clippy::too_many_arguments)]
fn build_manifest(
    chain_domain_id: &[u8; DIGEST_BYTES],
    profile_id: &[u8; DIGEST_BYTES],
    program_id: &[u8; DIGEST_BYTES],
    proposition: &[u8],
    application_payload: &[u8],
    contract_id: &[u8; DIGEST_BYTES],
    statement: &[u8],
    claim: &ReceiptClaimDigests,
) -> Result<Vec<u8>> {
    let artifacts = [
        (
            APPLICATION_PAYLOAD_FILE,
            "application-payload",
            application_payload,
        ),
        (
            CHAIN_DOMAIN_ID_FILE,
            "chain-domain-id",
            chain_domain_id.as_slice(),
        ),
        (
            CLAIM_DIGEST_FILE,
            "expected-claim-digest",
            claim.expected_claim.as_slice(),
        ),
        (CONTRACT_ID_FILE, "contract-id", contract_id.as_slice()),
        (
            JOURNAL_DIGEST_FILE,
            "journal-digest",
            claim.journal_digest.as_slice(),
        ),
        (
            OUTPUT_DIGEST_FILE,
            "receipt-output-digest",
            claim.output.as_slice(),
        ),
        (
            POST_DIGEST_FILE,
            "receipt-post-digest",
            claim.post.as_slice(),
        ),
        (PROFILE_ID_FILE, "stark-profile-id", profile_id.as_slice()),
        (PROGRAM_ID_FILE, "guest-program-id", program_id.as_slice()),
        (PROPOSITION_FILE, "self-proposition-bytes", proposition),
        (STATEMENT_FILE, "ergo-statement-v1", statement),
    ]
    .into_iter()
    .map(|(path, role, bytes)| ArtifactIdentity {
        length: bytes.len(),
        path,
        role,
        sha256: sha256_hex(bytes),
    })
    .collect();
    let view = StatementManifest {
        artifacts,
        claim: ClaimIdentity {
            expected_claim: hex::encode(claim.expected_claim),
            journal_digest: hex::encode(claim.journal_digest),
            output: hex::encode(claim.output),
            post: hex::encode(claim.post),
        },
        format: STATEMENT_FORMAT,
        format_version: STATEMENT_FORMAT_VERSION,
        statement: StatementIdentity {
            application_payload_length: application_payload.len(),
            chain_domain_id: hex::encode(chain_domain_id),
            contract_id: hex::encode(contract_id),
            domain_hex: hex::encode(ERGO_STATEMENT_DOMAIN),
            profile_id: hex::encode(profile_id),
            program_id: hex::encode(program_id),
            proposition_bytes_length: proposition.len(),
            statement_length: statement.len(),
            statement_sha256: sha256_hex(statement),
            version: 1,
        },
    };
    let value = serde_json::to_value(view).context("cannot serialize statement manifest")?;
    let bytes = canonical_json_bytes(&value)?;
    ensure!(
        bytes.len() <= MAX_MANIFEST_BYTES,
        "statement manifest exceeds {MAX_MANIFEST_BYTES} bytes"
    );
    Ok(bytes)
}

fn derive_verified_profile_id(profile_dir: &Path) -> Result<[u8; DIGEST_BYTES]> {
    verify_profile_freeze_directory(profile_dir, profile_dir)
        .context("B3 profile package verification failed")?;
    let (algorithm, binary_data) = read_profile_artifacts(profile_dir)?;
    let bundle = build_profile_freeze_bundle(&algorithm, &binary_data)?;
    Ok(*bundle.profile_id())
}

fn bundle_files(bundle: &StatementBundle) -> [(&'static str, &[u8]); 12] {
    [
        (APPLICATION_PAYLOAD_FILE, &bundle.application_payload),
        (CHAIN_DOMAIN_ID_FILE, &bundle.chain_domain_id),
        (CLAIM_DIGEST_FILE, &bundle.claim.expected_claim),
        (CONTRACT_ID_FILE, &bundle.contract_id),
        (JOURNAL_DIGEST_FILE, &bundle.claim.journal_digest),
        (OUTPUT_DIGEST_FILE, &bundle.claim.output),
        (POST_DIGEST_FILE, &bundle.claim.post),
        (PROFILE_ID_FILE, &bundle.profile_id),
        (PROGRAM_ID_FILE, &bundle.program_id),
        (PROPOSITION_FILE, &bundle.proposition),
        (STATEMENT_FILE, &bundle.statement),
        (STATEMENT_MANIFEST_FILE, &bundle.manifest),
    ]
}

fn read_regular_bounded(path: &Path, minimum: usize, maximum: usize) -> Result<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("cannot inspect {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file() && !is_reparse_point(&metadata),
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

fn require_regular_directory(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("cannot inspect {}", path.display()))?;
    ensure!(
        metadata.file_type().is_dir() && !is_reparse_point(&metadata),
        "directory is not a regular non-link directory: {}",
        path.display()
    );
    Ok(())
}

fn verify_closed_file_set(bundle_dir: &Path) -> Result<()> {
    let expected: BTreeSet<&str> = CLOSED_FILE_SET.into_iter().collect();
    let mut actual = BTreeSet::new();
    for entry in
        fs::read_dir(bundle_dir).with_context(|| format!("cannot list {}", bundle_dir.display()))?
    {
        let entry =
            entry.with_context(|| format!("cannot read entry in {}", bundle_dir.display()))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("bundle contains a non-UTF-8 filename"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .with_context(|| format!("cannot inspect {}", entry.path().display()))?;
        ensure!(
            metadata.file_type().is_file() && !is_reparse_point(&metadata),
            "bundle entry is not a regular non-link file: {name}"
        );
        ensure!(actual.insert(name), "duplicate bundle entry");
    }
    let actual_refs: BTreeSet<&str> = actual.iter().map(String::as_str).collect();
    ensure!(
        actual_refs == expected,
        "statement bundle closed file set mismatch"
    );
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &Metadata) -> bool {
    false
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

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn decode_digest(value: &str) -> Result<[u8; DIGEST_BYTES]> {
    hex::decode(value)?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("digest has {} bytes", bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const B1: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/algorithm.txt");
    const B2: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/constants.bin");
    const PROPOSITION_HEX: &str = concat!(
        "1c53020e209490a07414919c7eca0176d4ff9614523beecc8746ae7ffd4916f29b2edb9fe5",
        "0e2023c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383",
        "d1b9e4e3001ae4e3010e73007301"
    );

    #[test]
    fn current_reference_inputs_build_twice_byte_for_byte() {
        let profile = build_profile_freeze_bundle(B1, B2).unwrap();
        let chain = decode_32("b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b");
        let program = decode_32("9490a07414919c7eca0176d4ff9614523beecc8746ae7ffd4916f29b2edb9fe5");
        let proposition = hex::decode(PROPOSITION_HEX).unwrap();
        let payload: Vec<u8> = (0..32).collect();

        let first = build_statement_bundle(
            chain,
            *profile.profile_id(),
            program,
            &proposition,
            &payload,
        )
        .unwrap();
        let second = build_statement_bundle(
            chain,
            *profile.profile_id(),
            program,
            &proposition,
            &payload,
        )
        .unwrap();

        assert_eq!(first, second);
        assert_eq!(
            reference_contract_proposition_bytes(&program, profile.profile_id()).unwrap(),
            proposition
        );
        assert_eq!(first.statement().len(), 191);
        assert_eq!(
            hex::encode(first.contract_id()),
            "f3582418f41ba6920c83758e56ac4475bf6084a039f91a762388e774258a6c61"
        );
        assert_eq!(&first.statement()[27..59], &chain);
        assert_eq!(&first.statement()[59..91], profile.profile_id());
        assert_eq!(&first.statement()[91..123], &program);
        assert_eq!(&first.statement()[123..155], first.contract_id());
        assert_eq!(&first.statement()[155..159], &32_u32.to_le_bytes());
        assert_eq!(&first.statement()[159..], payload);
        assert_eq!(
            sha256_hex(first.statement()),
            "fc8064e54129958bcbdfa292b90251c1536d7cd8ce5e641a326e7cbd78b452ef"
        );
        assert_eq!(
            hex::encode(first.claim().expected_claim),
            "2ea54a883cfb8b2252937074a3b9d453264cf3e87ae6760afc3680c1da6fc92d"
        );
        assert_eq!(
            sha256_hex(first.manifest()),
            "83a2c75473d4d048cdf66d922a4f9ab6909d46025ce94c3a3793e1348c388123"
        );
        assert!(!first.manifest().ends_with(b"\n"));
        validate_canonical_json_source(first.manifest()).unwrap();
    }

    #[test]
    fn proposition_and_payload_bounds_are_closed() {
        let ids = [0_u8; DIGEST_BYTES];
        assert!(build_statement_bundle(ids, ids, ids, b"", b"").is_err());
        assert!(
            build_statement_bundle(ids, ids, ids, &vec![0_u8; MAX_PROPOSITION_BYTES + 1], b"",)
                .is_err()
        );
        assert!(
            build_statement_bundle(
                ids,
                ids,
                ids,
                b"x",
                &vec![0_u8; MAX_APPLICATION_PAYLOAD_BYTES + 1],
            )
            .is_err()
        );
    }

    #[test]
    fn every_frozen_reference_binding_is_rejected_in_isolation() {
        let profile = build_profile_freeze_bundle(B1, B2).unwrap();
        let chain = decode_32(REFERENCE_CHAIN_DOMAIN_ID_HEX);
        let program = decode_32(REFERENCE_PROGRAM_ID_HEX);
        let proposition = hex::decode(PROPOSITION_HEX).unwrap();
        let payload: Vec<u8> = (0..32).collect();

        let mut changed_chain = chain;
        changed_chain[0] ^= 1;
        assert!(
            build_statement_bundle(
                changed_chain,
                *profile.profile_id(),
                program,
                &proposition,
                &payload,
            )
            .is_err()
        );

        let mut changed_profile = *profile.profile_id();
        changed_profile[0] ^= 1;
        assert!(
            build_statement_bundle(chain, changed_profile, program, &proposition, &payload)
                .is_err()
        );

        let mut changed_program = program;
        changed_program[0] ^= 1;
        assert!(
            build_statement_bundle(
                chain,
                *profile.profile_id(),
                changed_program,
                &proposition,
                &payload,
            )
            .is_err()
        );

        let mut changed_proposition = proposition.clone();
        changed_proposition[0] ^= 1;
        assert!(
            build_statement_bundle(
                chain,
                *profile.profile_id(),
                program,
                &changed_proposition,
                &payload,
            )
            .is_err()
        );

        let mut changed_payload = payload;
        changed_payload[0] ^= 1;
        assert!(
            build_statement_bundle(
                chain,
                *profile.profile_id(),
                program,
                &proposition,
                &changed_payload,
            )
            .is_err()
        );
    }

    fn decode_32(value: &str) -> [u8; DIGEST_BYTES] {
        hex::decode(value).unwrap().try_into().unwrap()
    }
}
