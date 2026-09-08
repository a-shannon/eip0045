//! Independent re-reading and verification of one candidate export.
//!
//! This module validates non-final candidate artifacts produced by the pinned
//! generator. The upstream bincode receipt remains a reproduction oracle; it
//! is neither a consensus encoding nor suitable for parsing untrusted network
//! input.
//!
//! The bounded snapshots detect stable defects and accidental concurrent
//! changes. Operators must still give the checker exclusive access to the
//! export: it is not a security boundary against a malicious same-host process
//! racing path resolution or restoring bytes between snapshots.

use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::Read as _,
    path::Path,
};

use anyhow::{Context, Result, bail, ensure};
use eip_0045_reproduction::{
    candidate_metadata::{
        CANDIDATE_METADATA_V1_MAX_BYTES, CandidateMetadataV1 as CandidateMetadata,
    },
    canonical::{validate_canonical_json_source, validate_unsigned_decimal},
    claim::ok_receipt_claim_digests,
    constants::{MAX_STATEMENT_BYTES, PROOF_BYTES, PROOF_WORDS, RISC0_COMMIT, RISC0_REPOSITORY},
    manifest::{ManifestEntry, ProofOutputManifest, validate_manifest_shape},
};
#[cfg(feature = "proof-generation")]
use risc0_zkp::verify::VerificationError;
use risc0_zkvm::{
    Digest, InnerReceipt, MaybePruned, ReceiptClaim, VerifierContext, compute_image_id,
    sha::Digestible,
};
use sha2::{Digest as _, Sha256};

#[cfg(feature = "proof-generation")]
use crate::{
    ALTERNATE_ROOT_SEGMENT_PO2, EXPECTED_ALTERNATE_CONTROL_ROOT_HEX,
    EXPECTED_ALTERNATE_VERIFIER_PARAMETERS_HEX, alternate_control_root_profile,
    validate_alternate_root_succinct_shape,
};
use crate::{
    CANDIDATE_RECEIPT_ORACLE_MAX_BYTES, EXECUTOR_SEGMENT_LIMIT_PO2,
    EXPECTED_INNER_CONTROL_ROOT_HEX, EXPECTED_OUTER_PO2, EXPECTED_VERIFIER_PARAMETERS_HEX,
    WORKLOAD_SEED, expected_normal_lift_control_id,
    receipt_oracle_wire::decode_outer_receipt_oracle, validate_candidate_succinct_shape,
    validate_ergo_statement_v1,
};

const PROOF_OUTPUT_DIRECTORY: &str = "proof-output";
const OUTPUT_MANIFEST_FILE: &str = "candidate-proof-output-manifest.json";
const RAW_SEAL_FILE: &str = "candidate-raw-seal.bin";
const RECEIPT_ORACLE_FILE: &str = "candidate-receipt-oracle.bincode";
const JOURNAL_FILE: &str = "candidate-journal.bin";
const IMAGE_ID_FILE: &str = "candidate-image-id.bin";
const CLAIM_DIGEST_FILE: &str = "candidate-claim-digest.bin";
const CONTROL_ID_FILE: &str = "candidate-control-id.bin";
const METADATA_FILE: &str = "candidate-metadata.json";

const METADATA_MAX_BYTES: usize = CANDIDATE_METADATA_V1_MAX_BYTES;
const MANIFEST_MAX_BYTES: usize = 8 * 1024;
const DIGEST_ARTIFACT_BYTES: usize = 32;
const PROOF_OUTPUT_MAX_BYTES: usize = PROOF_BYTES
    + CANDIDATE_RECEIPT_ORACLE_MAX_BYTES
    + MAX_STATEMENT_BYTES
    + METADATA_MAX_BYTES
    + 3 * DIGEST_ARTIFACT_BYTES;

const MANIFEST_PATHS: [&str; 7] = [
    CLAIM_DIGEST_FILE,
    CONTROL_ID_FILE,
    IMAGE_ID_FILE,
    JOURNAL_FILE,
    METADATA_FILE,
    RAW_SEAL_FILE,
    RECEIPT_ORACLE_FILE,
];

const METADATA_FILE_ROLES: [(&str, &str); 6] = [
    (RAW_SEAL_FILE, "raw-succinct-seal"),
    (RECEIPT_ORACLE_FILE, "upstream-bincode-receipt-oracle"),
    (JOURNAL_FILE, "journal"),
    (IMAGE_ID_FILE, "guest-image-id"),
    (CLAIM_DIGEST_FILE, "receipt-claim-digest"),
    (CONTROL_ID_FILE, "normal-lift-control-id"),
];

/// Recomputed observations for one successfully verified candidate export.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCandidateExport {
    /// Requested and verified final segment exponent.
    pub segment_po2: u32,
    /// Exact canonical guest image ID bytes.
    pub image_id: Digest,
    /// Digest of the independently reconstructed successful receipt claim.
    pub claim_digest: Digest,
    /// Exact normal-lift control ID for `segment_po2`.
    pub control_id: Digest,
    /// Digest of the exact expected statement journal.
    pub journal_digest: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CandidateExportMode {
    StockProfile,
    #[cfg(feature = "proof-generation")]
    FixedAlternate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExpectedMethodIdentity {
    image_id: Digest,
    elf_length: usize,
    elf_sha256: [u8; 32],
}

impl ExpectedMethodIdentity {
    fn from_guest_elf(expected_guest_elf: &[u8], expected_image_id: Digest) -> Result<Self> {
        let computed_image_id = compute_image_id(expected_guest_elf)
            .context("cannot compute the caller-supplied expected guest ELF image ID")?;
        ensure!(
            computed_image_id == expected_image_id,
            "caller-supplied expected guest ELF differs from the expected guest image ID"
        );
        Ok(Self {
            image_id: expected_image_id,
            elf_length: expected_guest_elf.len(),
            elf_sha256: Sha256::digest(expected_guest_elf).into(),
        })
    }
}

/// Re-read and verify one complete non-final candidate export.
///
/// The caller supplies the expected statement, segment exponent, exact guest
/// ELF bytes, and expected guest image ID. Values in candidate metadata are
/// checked against recomputed observations and never select trusted verifier
/// parameters. The expected ELF and image ID must agree; there is no embedded
/// or metadata-selected fallback.
///
/// # Errors
///
/// Returns an error at the first failed scalar, method, layout, canonical JSON,
/// bounded-file, receipt-codec, proof-shape, cryptographic, metadata, or final
/// snapshot gate.
pub fn verify_candidate_export(
    export_root: &Path,
    expected_statement_file: &Path,
    expected_segment_po2: u32,
    expected_guest_elf: &[u8],
    expected_image_id: Digest,
) -> Result<VerifiedCandidateExport> {
    verify_candidate_export_for_mode(
        export_root,
        expected_statement_file,
        expected_segment_po2,
        expected_guest_elf,
        expected_image_id,
        CandidateExportMode::StockProfile,
    )
}

/// Re-read and verify one complete fixed alternate-root po2-15 export.
///
/// This path is deliberately separate from [`verify_candidate_export`]. It
/// never auto-detects a root from untrusted receipt or metadata bytes and has
/// no caller-selected segment or verifier parameters.
///
/// # Errors
///
/// Returns an error at the first failed layout, bound, statement, receipt,
/// fixed-profile, cryptographic, metadata, or final-snapshot gate.
#[cfg(feature = "proof-generation")]
pub fn verify_alternate_root_candidate_export(
    export_root: &Path,
    expected_statement_file: &Path,
    expected_guest_elf: &[u8],
    expected_image_id: Digest,
) -> Result<VerifiedCandidateExport> {
    verify_candidate_export_for_mode(
        export_root,
        expected_statement_file,
        ALTERNATE_ROOT_SEGMENT_PO2,
        expected_guest_elf,
        expected_image_id,
        CandidateExportMode::FixedAlternate,
    )
}

fn verify_candidate_export_for_mode(
    export_root: &Path,
    expected_statement_file: &Path,
    expected_segment_po2: u32,
    expected_guest_elf: &[u8],
    expected_image_id: Digest,
    mode: CandidateExportMode,
) -> Result<VerifiedCandidateExport> {
    // Validate the caller-owned scalar before touching either filesystem input.
    let control_id = expected_normal_lift_control_id(expected_segment_po2)?;
    let expected_method =
        ExpectedMethodIdentity::from_guest_elf(expected_guest_elf, expected_image_id)?;
    verify_candidate_export_for_mode_with_authenticated_method(
        export_root,
        expected_statement_file,
        expected_segment_po2,
        control_id,
        expected_method,
        mode,
    )
}

// This core remains private: public callers reach it only after the exact guest
// ELF has been reduced to an authenticated image ID, length, and SHA-256 above.
// Unit tests may instead pin that same closed identity for a checked-in receipt
// KAT without publishing the path-bearing ELF. It keeps every filesystem,
// fail-first, cryptographic, metadata, and final-snapshot gate in one visible
// order.
#[allow(clippy::too_many_lines)]
fn verify_candidate_export_for_mode_with_authenticated_method(
    export_root: &Path,
    expected_statement_file: &Path,
    expected_segment_po2: u32,
    control_id: Digest,
    expected_method: ExpectedMethodIdentity,
    mode: CandidateExportMode,
) -> Result<VerifiedCandidateExport> {
    let expected_image_id = expected_method.image_id;
    let expected_statement = read_regular_file(expected_statement_file, MAX_STATEMENT_BYTES)?;
    validate_ergo_statement_v1(&expected_statement, &expected_image_id)
        .context("expected statement is not canonical ErgoStatementV1 for the expected guest")?;

    require_exact_export_layout(export_root)?;
    let proof_output = export_root.join(PROOF_OUTPUT_DIRECTORY);
    let manifest_path = export_root.join(OUTPUT_MANIFEST_FILE);
    let manifest_source = read_regular_file(&manifest_path, MANIFEST_MAX_BYTES)?;
    let manifest_value = validate_canonical_json_source(&manifest_source)
        .context("candidate proof-output manifest is not exact RFC 8785 JCS")?;
    let manifest: ProofOutputManifest = serde_json::from_value(manifest_value)
        .context("candidate proof-output manifest has the wrong closed shape")?;
    validate_candidate_tree_snapshot(&proof_output, &manifest, expected_statement.len())
        .context("candidate proof-output manifest does not match the bounded physical tree")?;

    let raw_seal =
        read_manifested_file_bounded(&proof_output, &manifest, RAW_SEAL_FILE, PROOF_BYTES)?;
    ensure!(
        raw_seal.len() == PROOF_BYTES,
        "candidate raw seal has {} bytes, expected {PROOF_BYTES}",
        raw_seal.len()
    );
    let receipt_oracle = read_manifested_file_bounded(
        &proof_output,
        &manifest,
        RECEIPT_ORACLE_FILE,
        CANDIDATE_RECEIPT_ORACLE_MAX_BYTES,
    )?;
    let journal =
        read_manifested_file_bounded(&proof_output, &manifest, JOURNAL_FILE, MAX_STATEMENT_BYTES)?;
    let image_id_bytes = read_fixed_artifact::<32>(&proof_output, &manifest, IMAGE_ID_FILE)?;
    let claim_digest_bytes =
        read_fixed_artifact::<32>(&proof_output, &manifest, CLAIM_DIGEST_FILE)?;
    let control_id_bytes = read_fixed_artifact::<32>(&proof_output, &manifest, CONTROL_ID_FILE)?;
    let metadata_source =
        read_manifested_file_bounded(&proof_output, &manifest, METADATA_FILE, METADATA_MAX_BYTES)?;
    let metadata = CandidateMetadata::from_canonical_jcs(&metadata_source)?;

    ensure!(
        journal == expected_statement,
        "candidate journal differs from the expected statement"
    );

    let image_id = expected_image_id;
    ensure!(
        image_id.as_bytes() == image_id_bytes,
        "candidate image-ID artifact differs from the expected guest image ID"
    );

    let receipt = decode_outer_receipt_oracle(&receipt_oracle)?;
    ensure!(
        receipt.journal.bytes == expected_statement,
        "receipt-oracle journal differs from the expected statement"
    );
    ensure!(
        receipt.metadata.verifier_parameters == receipt.inner.verifier_parameters(),
        "receipt-oracle metadata verifier parameters differ from the inner receipt"
    );
    let InnerReceipt::Succinct(succinct) = &receipt.inner else {
        bail!("receipt oracle does not contain a succinct receipt");
    };

    let journal_digest = receipt.journal.digest();
    let independent_claim = ok_receipt_claim_digests(image_id.as_bytes(), &expected_statement)
        .context("independent byte-level receipt-claim derivation failed")?;
    ensure!(
        journal_digest.as_bytes() == independent_claim.journal_digest,
        "receipt-oracle journal digest differs from the independent SHA-256 derivation"
    );
    let expected_claim = ReceiptClaim::ok(image_id, MaybePruned::Pruned(journal_digest));
    let expected_claim_digest = expected_claim.digest();
    ensure!(
        expected_claim_digest.as_bytes() == independent_claim.expected_claim,
        "upstream OK claim differs from the independent byte-level claim derivation"
    );
    let receipt_claim = receipt
        .claim()
        .map_err(|error| anyhow::anyhow!("cannot resolve receipt-oracle claim: {error}"))?;
    ensure!(
        receipt_claim.digest() == expected_claim_digest,
        "receipt-oracle claim is not the independently reconstructed successful claim"
    );
    ensure!(
        succinct.claim.digest() == expected_claim_digest,
        "succinct receipt claim differs from the independently reconstructed successful claim"
    );
    ensure!(
        expected_claim_digest.as_bytes() == claim_digest_bytes,
        "candidate claim-digest artifact differs from the reconstructed claim"
    );

    ensure!(
        succinct.control_id == control_id,
        "succinct receipt control ID differs from the expected normal lift"
    );
    ensure!(
        control_id.as_bytes() == control_id_bytes,
        "candidate control-ID artifact differs from the expected normal lift"
    );
    let extracted_raw_seal = match mode {
        CandidateExportMode::StockProfile => validate_candidate_succinct_shape(
            succinct,
            expected_segment_po2,
            &expected_claim_digest,
        )?,
        #[cfg(feature = "proof-generation")]
        CandidateExportMode::FixedAlternate => {
            let profile = alternate_control_root_profile()?;
            validate_alternate_root_succinct_shape(succinct, &expected_claim_digest, &profile)?
        }
    };
    ensure!(
        extracted_raw_seal == raw_seal,
        "candidate raw-seal artifact differs from SuccinctReceipt::get_seal_bytes()"
    );

    let verifier_context = VerifierContext::default().with_dev_mode(false);
    ensure!(
        !verifier_context.dev_mode(),
        "candidate verifier context enabled development mode"
    );
    match mode {
        CandidateExportMode::StockProfile => receipt
            .verify_with_context(&verifier_context, image_id)
            .map_err(|error| {
                anyhow::anyhow!(
                    "upstream verification of the candidate receipt oracle failed: {error}"
                )
            })?,
        #[cfg(feature = "proof-generation")]
        CandidateExportMode::FixedAlternate => {
            let profile = alternate_control_root_profile()?;
            let alternate_context = VerifierContext::default()
                .with_dev_mode(false)
                .with_succinct_verifier_parameters(profile.verifier_parameters().clone());
            ensure!(
                !alternate_context.dev_mode(),
                "fixed alternate-root verifier context enabled development mode"
            );
            receipt
                .verify_with_context(&alternate_context, image_id)
                .map_err(|error| {
                    anyhow::anyhow!(
                        "upstream fixed alternate-root receipt verification failed: {error}"
                    )
                })?;
            match receipt.verify_with_context(&verifier_context, image_id) {
                Ok(()) => {
                    bail!("stock verifier context accepted the fixed alternate-root receipt")
                }
                Err(VerificationError::VerifierParametersMismatch { expected, received }) => {
                    ensure!(
                        hex::encode(expected.as_bytes()) == EXPECTED_VERIFIER_PARAMETERS_HEX
                            && received == profile.verifier_parameters_digest(),
                        "stock verifier rejected the alternate receipt with unexpected verifier parameters"
                    );
                }
                Err(other) => bail!(
                    "stock verifier rejected the alternate receipt at the wrong boundary: {other:?}"
                ),
            }
        }
    }

    validate_metadata(
        &metadata,
        &manifest,
        &expected_statement,
        expected_segment_po2,
        &raw_seal,
        &receipt_oracle,
        &expected_method,
        expected_claim_digest,
        control_id,
        journal_digest,
        mode,
    )?;

    validate_final_candidate_snapshot(
        export_root,
        &proof_output,
        &manifest_path,
        &manifest_source,
        &manifest,
        expected_statement.len(),
    )?;

    Ok(VerifiedCandidateExport {
        segment_po2: expected_segment_po2,
        image_id,
        claim_digest: expected_claim_digest,
        control_id,
        journal_digest,
    })
}

fn validate_expected_method_identity(
    metadata: &CandidateMetadata,
    expected_method: &ExpectedMethodIdentity,
) -> Result<()> {
    ensure!(
        metadata.method.image_id == hex::encode(expected_method.image_id.as_bytes())
            && parse_decimal_usize(&metadata.method.elf_length, "method ELF length")?
                == expected_method.elf_length
            && metadata.method.elf_sha256 == hex::encode(expected_method.elf_sha256),
        "candidate metadata method identity differs from the expected guest"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
// This deliberately mirrors the closed metadata schema in field order so a
// reviewer can see every non-authoritative observation checked in one place.
#[allow(clippy::too_many_lines)]
fn validate_metadata(
    metadata: &CandidateMetadata,
    manifest: &[ManifestEntry],
    statement: &[u8],
    segment_po2: u32,
    raw_seal: &[u8],
    receipt_oracle: &[u8],
    expected_method: &ExpectedMethodIdentity,
    claim_digest: Digest,
    control_id: Digest,
    journal_digest: Digest,
    mode: CandidateExportMode,
) -> Result<()> {
    let (
        expected_status,
        expected_receipt_kind,
        expected_inner_control_root,
        expected_verifier_parameters,
        expected_verification_authority,
        expected_profile_owned_shape_verify,
    ) = match mode {
        CandidateExportMode::StockProfile => (
            "non-final-reproduction-candidate",
            "succinct-single-lift",
            EXPECTED_INNER_CONTROL_ROOT_HEX,
            EXPECTED_VERIFIER_PARAMETERS_HEX,
            "pinned-stock-verifier-context",
            true,
        ),
        #[cfg(feature = "proof-generation")]
        CandidateExportMode::FixedAlternate => (
            "non-final-alternate-root-negative-witness",
            "succinct-single-lift-fixed-alternate-root",
            EXPECTED_ALTERNATE_CONTROL_ROOT_HEX,
            EXPECTED_ALTERNATE_VERIFIER_PARAMETERS_HEX,
            "fixed-alternate-control-root-verifier-context",
            false,
        ),
    };
    ensure!(
        metadata.candidate_status == expected_status,
        "candidate metadata status is not exact"
    );
    ensure!(
        metadata.format_version == 1,
        "candidate metadata version is not 1"
    );
    ensure!(
        metadata.upstream.repository == RISC0_REPOSITORY
            && metadata.upstream.commit == RISC0_COMMIT
            && metadata.upstream.risc0_zkvm_version == risc0_zkvm::VERSION
            && metadata.upstream.receipt_oracle_codec
                == "bincode-1.3.3-upstream-host-serialization",
        "candidate metadata upstream identity is not exact"
    );
    validate_expected_method_identity(metadata, expected_method)?;
    ensure!(
        metadata.proof_bound.receipt_bound
            && parse_decimal_usize(
                &metadata.proof_bound.statement_length,
                "proof-bound statement length"
            )? == statement.len()
            && metadata.proof_bound.statement_sha256 == sha256_hex(statement)
            && metadata.proof_bound.journal_digest == hex::encode(journal_digest.as_bytes())
            && metadata.proof_bound.claim_digest == hex::encode(claim_digest.as_bytes()),
        "candidate proof-bound metadata differs from recomputed values"
    );
    ensure!(
        !metadata.private_calibration.receipt_bound
            && metadata.private_calibration.candidate_scope == "local-reproduction-provenance-only"
            && metadata.private_calibration.selection_rule
                == "canonical-monotone-ranking-v1-not-global-minimum"
            && metadata.private_calibration.selected_observation_is_exact
            && metadata.private_calibration.workload_seed_hex == format!("{WORKLOAD_SEED:016x}"),
        "candidate private-calibration metadata is not exact"
    );
    parse_decimal_u32(
        &metadata.private_calibration.workload_iterations,
        "candidate workload iteration count",
    )?;

    let observation = &metadata.local_execution_observation;
    ensure!(
        !observation.receipt_bound
            && observation.candidate_scope == "local-reproduction-provenance-only"
            && observation.segment_count == "1"
            && observation.executor_segment_limit_po2 == EXECUTOR_SEGMENT_LIMIT_PO2
            && observation.segment_po2 == segment_po2,
        "candidate local-execution metadata is not exact"
    );
    let user_cycles = parse_decimal_u64(&observation.user_cycles, "user cycles")?;
    let total_cycles = parse_decimal_u64(&observation.total_cycles, "total cycles")?;
    let paging_cycles = parse_decimal_u64(&observation.paging_cycles, "paging cycles")?;
    let reserved_cycles = parse_decimal_u64(&observation.reserved_cycles, "reserved cycles")?;
    ensure!(
        user_cycles
            .checked_add(paging_cycles)
            .and_then(|value| value.checked_add(reserved_cycles))
            == Some(total_cycles),
        "candidate local cycle observations are internally inconsistent"
    );
    ensure!(
        total_cycles
            == 1_u64
                .checked_shl(segment_po2)
                .context("segment po2 is too large")?,
        "candidate total-cycle observation differs from the segment exponent"
    );

    ensure!(
        metadata.proof.receipt_kind == expected_receipt_kind
            && metadata.proof.hash_function == "poseidon2"
            && metadata.proof.control_id == hex::encode(control_id.as_bytes())
            && metadata.proof.inner_control_root == expected_inner_control_root
            && metadata.proof.verifier_parameters == expected_verifier_parameters
            && metadata.proof.outer_po2 == EXPECTED_OUTER_PO2
            && parse_decimal_usize(&metadata.proof.raw_seal_words, "raw seal words")?
                == PROOF_WORDS
            && parse_decimal_usize(&metadata.proof.raw_seal_bytes, "raw seal bytes")?
                == PROOF_BYTES
            && metadata.proof.claim_digest == hex::encode(claim_digest.as_bytes())
            && metadata.proof.journal_digest == hex::encode(journal_digest.as_bytes()),
        "candidate proof metadata differs from recomputed values"
    );
    ensure!(
        !metadata.verification.receipt_bound
            && metadata.verification.verification_authority == expected_verification_authority
            && metadata.verification.explicit_local_prover
            && !metadata.verification.dev_mode
            && !metadata.verification.prove_guest_errors
            && !metadata.verification.work_receipt_present
            && metadata.verification.upstream_receipt_verify
            && metadata.verification.profile_owned_shape_verify
                == expected_profile_owned_shape_verify
            && !metadata.verification.receipt_oracle_is_consensus_encoding,
        "candidate verification metadata is not exact"
    );

    ensure!(
        metadata.files.len() == METADATA_FILE_ROLES.len(),
        "candidate metadata file list has {} entries, expected {}",
        metadata.files.len(),
        METADATA_FILE_ROLES.len()
    );
    for (index, ((path, role), file)) in METADATA_FILE_ROLES.iter().zip(&metadata.files).enumerate()
    {
        ensure!(
            file.path == *path && file.role == *role,
            "candidate metadata file entry {index} has the wrong path or role"
        );
        let manifest_entry = find_manifest_entry(manifest, path)?;
        ensure!(
            file.length == manifest_entry.length && file.sha256 == manifest_entry.sha256,
            "candidate metadata file entry {index} differs from the physical manifest"
        );
    }
    ensure!(
        find_manifest_entry(manifest, RAW_SEAL_FILE)?.sha256 == sha256_hex(raw_seal)
            && find_manifest_entry(manifest, RECEIPT_ORACLE_FILE)?.sha256
                == sha256_hex(receipt_oracle),
        "candidate manifest proof digests differ from the bytes just verified"
    );
    Ok(())
}

fn require_exact_export_layout(export_root: &Path) -> Result<()> {
    require_ordinary_directory(export_root, "candidate export root")?;
    let names = bounded_directory_names(export_root, "candidate export root", 2)?;
    ensure!(
        names == [OUTPUT_MANIFEST_FILE, PROOF_OUTPUT_DIRECTORY],
        "candidate export top-level entries are not exact"
    );
    require_ordinary_directory(&export_root.join(PROOF_OUTPUT_DIRECTORY), "proof-output")?;
    require_regular_file(
        &export_root.join(OUTPUT_MANIFEST_FILE),
        "proof-output manifest",
    )?;
    Ok(())
}

fn bounded_directory_names(path: &Path, label: &str, expected_count: usize) -> Result<Vec<String>> {
    let entries = fs::read_dir(path)
        .with_context(|| format!("cannot enumerate {label} {}", path.display()))?;
    let mut names = Vec::with_capacity(expected_count);
    for entry in entries {
        ensure!(
            names.len() < expected_count,
            "{label} contains more than {expected_count} entries"
        );
        let entry = entry.with_context(|| format!("cannot read {label} entry"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("{label} contains a non-UTF-8 path"))?;
        names.push(name);
    }
    names.sort();
    Ok(names)
}

fn require_exact_proof_output_layout(proof_output: &Path) -> Result<()> {
    require_ordinary_directory(proof_output, "proof-output")?;
    let entries = fs::read_dir(proof_output).with_context(|| {
        format!(
            "cannot enumerate candidate proof-output {}",
            proof_output.display()
        )
    })?;
    let mut names = Vec::with_capacity(MANIFEST_PATHS.len());
    for entry in entries {
        ensure!(
            names.len() < MANIFEST_PATHS.len(),
            "candidate proof-output contains more than {} entries",
            MANIFEST_PATHS.len()
        );
        let entry = entry.context("cannot read candidate proof-output entry")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("candidate proof-output contains a non-UTF-8 path"))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("cannot inspect candidate artifact {}", path.display()))?;
        ensure!(
            metadata.file_type().is_file() && !is_reparse_point(&metadata),
            "candidate proof-output entry is not a regular non-link file: {}",
            path.display()
        );
        names.push(name);
    }
    names.sort();
    ensure!(
        names == MANIFEST_PATHS,
        "candidate proof-output entries are not the exact flat set"
    );
    Ok(())
}

fn require_exact_manifest_paths(manifest: &[ManifestEntry]) -> Result<()> {
    let paths = manifest
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<Vec<_>>();
    ensure!(
        paths == MANIFEST_PATHS,
        "candidate proof-output manifest paths are not the exact closed set"
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArtifactLengthContract {
    Exact(usize),
    AtMost(usize),
}

impl ArtifactLengthContract {
    fn maximum(self) -> usize {
        match self {
            Self::Exact(length) | Self::AtMost(length) => length,
        }
    }

    fn validate(self, source: &str, name: &str, length: usize) -> Result<()> {
        match self {
            Self::Exact(expected) => ensure!(
                length == expected,
                "candidate {source} length for {name} is {length}, expected exactly {expected}"
            ),
            Self::AtMost(maximum) => ensure!(
                length <= maximum,
                "candidate {source} length for {name} is {length}, maximum is {maximum}"
            ),
        }
        Ok(())
    }
}

fn artifact_length_contract(
    name: &str,
    expected_statement_length: usize,
) -> Result<ArtifactLengthContract> {
    let contract = match name {
        CLAIM_DIGEST_FILE | CONTROL_ID_FILE | IMAGE_ID_FILE => {
            ArtifactLengthContract::Exact(DIGEST_ARTIFACT_BYTES)
        }
        JOURNAL_FILE => ArtifactLengthContract::Exact(expected_statement_length),
        METADATA_FILE => ArtifactLengthContract::AtMost(METADATA_MAX_BYTES),
        RAW_SEAL_FILE => ArtifactLengthContract::Exact(PROOF_BYTES),
        RECEIPT_ORACLE_FILE => ArtifactLengthContract::AtMost(CANDIDATE_RECEIPT_ORACLE_MAX_BYTES),
        _ => bail!("unknown candidate artifact path {name}"),
    };
    Ok(contract)
}

fn validate_candidate_manifest_contract(
    manifest: &[ManifestEntry],
    expected_statement_length: usize,
) -> Result<()> {
    validate_manifest_shape(manifest).context("candidate manifest fields are not canonical")?;
    require_exact_manifest_paths(manifest)?;
    ensure!(
        expected_statement_length <= MAX_STATEMENT_BYTES,
        "expected statement length exceeds the profile maximum"
    );

    let mut declared_total = 0_usize;
    for entry in manifest {
        let length = parse_decimal_usize(&entry.length, "manifest file length")?;
        artifact_length_contract(&entry.path, expected_statement_length)?.validate(
            "manifest-declared",
            &entry.path,
            length,
        )?;
        declared_total = declared_total
            .checked_add(length)
            .context("candidate manifest total length overflows usize")?;
    }
    ensure!(
        declared_total <= PROOF_OUTPUT_MAX_BYTES,
        "candidate manifest declares {declared_total} total bytes, maximum is {PROOF_OUTPUT_MAX_BYTES}"
    );
    Ok(())
}

fn preflight_candidate_tree(
    proof_output: &Path,
    manifest: &[ManifestEntry],
    expected_statement_length: usize,
) -> Result<()> {
    validate_candidate_manifest_contract(manifest, expected_statement_length)?;
    require_exact_proof_output_layout(proof_output)?;

    let mut physical_total = 0_usize;
    for entry in manifest {
        let declared_length = parse_decimal_usize(&entry.length, "manifest file length")?;
        let contract = artifact_length_contract(&entry.path, expected_statement_length)?;
        let path = proof_output.join(&entry.path);
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("cannot inspect candidate artifact {}", path.display()))?;
        ensure!(
            metadata.file_type().is_file() && !is_reparse_point(&metadata),
            "candidate artifact is not a regular non-link file: {}",
            path.display()
        );
        let physical_length = usize::try_from(metadata.len()).with_context(|| {
            format!(
                "candidate artifact length does not fit usize: {}",
                path.display()
            )
        })?;
        contract.validate("physical", &entry.path, physical_length)?;
        ensure!(
            physical_length == declared_length,
            "candidate artifact {} has physical length {physical_length}, manifest declares {declared_length}",
            entry.path
        );
        physical_total = physical_total
            .checked_add(physical_length)
            .context("candidate physical tree length overflows usize")?;
    }
    ensure!(
        physical_total <= PROOF_OUTPUT_MAX_BYTES,
        "candidate physical tree has {physical_total} bytes, maximum is {PROOF_OUTPUT_MAX_BYTES}"
    );
    Ok(())
}

fn validate_candidate_tree_snapshot(
    proof_output: &Path,
    manifest: &[ManifestEntry],
    expected_statement_length: usize,
) -> Result<()> {
    // Complete every layout and length check before hashing the first byte.
    preflight_candidate_tree(proof_output, manifest, expected_statement_length)?;
    for entry in manifest {
        let maximum = artifact_length_contract(&entry.path, expected_statement_length)?.maximum();
        read_manifested_file_bounded(proof_output, manifest, &entry.path, maximum)?;
    }
    Ok(())
}

fn require_unchanged_manifest(
    manifest_path: &Path,
    expected_source: &[u8],
    phase: &str,
) -> Result<()> {
    let observed_source = read_regular_file(manifest_path, MANIFEST_MAX_BYTES)?;
    ensure!(
        observed_source == expected_source,
        "candidate proof-output manifest changed {phase}"
    );
    Ok(())
}

fn validate_final_candidate_snapshot(
    export_root: &Path,
    proof_output: &Path,
    manifest_path: &Path,
    manifest_source: &[u8],
    manifest: &[ManifestEntry],
    expected_statement_length: usize,
) -> Result<()> {
    require_exact_export_layout(export_root)?;
    require_unchanged_manifest(
        manifest_path,
        manifest_source,
        "before the final proof-output snapshot",
    )?;
    validate_candidate_tree_snapshot(proof_output, manifest, expected_statement_length)
        .context("candidate proof-output tree changed during verification")?;
    require_exact_export_layout(export_root)?;
    require_unchanged_manifest(
        manifest_path,
        manifest_source,
        "during the final proof-output snapshot",
    )?;
    Ok(())
}

fn read_manifested_file_bounded(
    proof_output: &Path,
    manifest: &[ManifestEntry],
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>> {
    let entry = find_manifest_entry(manifest, name)?;
    let bytes = read_regular_file(&proof_output.join(name), maximum)?;
    let length = parse_decimal_usize(&entry.length, "manifest file length")?;
    ensure!(
        bytes.len() == length && sha256_hex(&bytes) == entry.sha256,
        "candidate artifact {name} differs from its manifest entry"
    );
    Ok(bytes)
}

fn read_fixed_artifact<const N: usize>(
    proof_output: &Path,
    manifest: &[ManifestEntry],
    name: &str,
) -> Result<[u8; N]> {
    let bytes = read_manifested_file_bounded(proof_output, manifest, name, N)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            "candidate artifact {name} has {} bytes, expected {N}",
            bytes.len()
        )
    })
}

fn find_manifest_entry<'a>(manifest: &'a [ManifestEntry], name: &str) -> Result<&'a ManifestEntry> {
    manifest
        .iter()
        .find(|entry| entry.path == name)
        .with_context(|| format!("candidate manifest is missing {name}"))
}

fn read_regular_file(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    read_regular_file_with_interposition(path, maximum, || Ok(()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    filesystem: u64,
    file: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OpenFileObservation {
    identity: FileIdentity,
    length: u64,
}

fn read_regular_file_with_interposition(
    path: &Path,
    maximum: usize,
    interpose_path: impl FnOnce() -> Result<()>,
) -> Result<Vec<u8>> {
    let mut file = open_candidate_file_nofollow(path)?;
    let initial = observe_open_regular_file(&file, path)?;
    interpose_path()?;
    require_path_identity(path, initial.identity, "before read")?;

    let maximum_u64 = u64::try_from(maximum).context("candidate artifact cap does not fit u64")?;
    ensure!(
        initial.length <= maximum_u64,
        "candidate artifact {} exceeds {maximum} bytes",
        path.display()
    );
    let bytes = read_to_end_bounded(&mut file, path, maximum)?;
    let final_handle = observe_open_regular_file(&file, path)?;
    ensure!(
        u64::try_from(bytes.len())
            .context("observed candidate artifact length does not fit u64")?
            == initial.length
            && final_handle == initial,
        "candidate artifact {} changed length while being read",
        path.display()
    );
    require_path_identity(path, initial.identity, "after read")?;
    Ok(bytes)
}

fn open_candidate_file_nofollow(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    configure_nofollow_open(&mut options);
    options.open(path).with_context(|| {
        format!(
            "cannot open candidate artifact without following links: {}",
            path.display()
        )
    })
}

#[cfg(unix)]
fn configure_nofollow_open(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt as _;

    options.custom_flags(libc::O_NOFOLLOW);
}

#[cfg(windows)]
fn configure_nofollow_open(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

fn observe_open_regular_file(file: &File, path: &Path) -> Result<OpenFileObservation> {
    let metadata = file
        .metadata()
        .with_context(|| format!("cannot inspect open candidate artifact {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file() && !is_reparse_point(&metadata),
        "candidate artifact is not an open regular non-link file: {}",
        path.display()
    );
    #[cfg(unix)]
    let (identity, hard_links) = platform_file_identity_and_links(&metadata);
    #[cfg(windows)]
    let (identity, hard_links) = platform_file_identity_and_links(file, path)?;
    ensure!(
        hard_links == 1,
        "candidate artifact must have exactly one hard link: {} has {hard_links}",
        path.display()
    );
    Ok(OpenFileObservation {
        identity,
        length: metadata.len(),
    })
}

fn require_path_identity(path: &Path, expected: FileIdentity, phase: &str) -> Result<()> {
    let path_file = open_candidate_file_nofollow(path)?;
    let observed = observe_open_regular_file(&path_file, path)?;
    ensure!(
        observed.identity == expected,
        "candidate artifact open handle identity differs from path {phase}: {}",
        path.display()
    );
    Ok(())
}

#[cfg(unix)]
fn platform_file_identity_and_links(metadata: &Metadata) -> (FileIdentity, u64) {
    use std::os::unix::fs::MetadataExt as _;

    (
        FileIdentity {
            filesystem: metadata.dev(),
            file: metadata.ino(),
        },
        metadata.nlink(),
    )
}

#[cfg(windows)]
fn platform_file_identity_and_links(file: &File, path: &Path) -> Result<(FileIdentity, u64)> {
    let information = winapi_util::file::information(file).with_context(|| {
        format!(
            "cannot inspect candidate artifact handle identity {}",
            path.display()
        )
    })?;
    Ok((
        FileIdentity {
            filesystem: information.volume_serial_number(),
            file: information.file_index(),
        },
        information.number_of_links(),
    ))
}

fn read_to_end_bounded(
    reader: &mut impl std::io::Read,
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>> {
    let limit = u64::try_from(maximum)
        .context("candidate artifact cap does not fit u64")?
        .checked_add(1)
        .context("candidate artifact read limit overflows u64")?;
    let mut bytes = Vec::new();
    reader
        .take(limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read candidate artifact {}", path.display()))?;
    ensure!(
        bytes.len() <= maximum,
        "candidate artifact {} grew above {maximum} bytes while being read",
        path.display()
    );
    Ok(bytes)
}

fn require_ordinary_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {label} {}", path.display()))?;
    ensure!(
        metadata.file_type().is_dir() && !is_reparse_point(&metadata),
        "{label} is not an ordinary directory: {}",
        path.display()
    );
    Ok(())
}

fn require_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {label} {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file() && !is_reparse_point(&metadata),
        "{label} is not a regular non-link file: {}",
        path.display()
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

fn parse_decimal_usize(value: &str, label: &str) -> Result<usize> {
    validate_unsigned_decimal(value).with_context(|| format!("{label} is not canonical"))?;
    value
        .parse::<usize>()
        .with_context(|| format!("{label} does not fit usize"))
}

fn parse_decimal_u64(value: &str, label: &str) -> Result<u64> {
    validate_unsigned_decimal(value).with_context(|| format!("{label} is not canonical"))?;
    value
        .parse::<u64>()
        .with_context(|| format!("{label} does not fit u64"))
}

fn parse_decimal_u32(value: &str, label: &str) -> Result<u32> {
    validate_unsigned_decimal(value).with_context(|| format!("{label} is not canonical"))?;
    value
        .parse::<u32>()
        .with_context(|| format!("{label} does not fit u32"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use std::{
        io::Cursor,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use bincode::Options as _;

    use super::*;
    use crate::receipt_oracle_bincode_options;
    #[cfg(all(feature = "proof-generation", feature = "embedded-method"))]
    use eip_0045_methods::{EIP_0045_GUEST_ELF, EIP_0045_GUEST_ID};
    #[cfg(feature = "proof-generation")]
    use eip_0045_reproduction::candidate_metadata::{
        CandidateFileMetadataV1, CandidateLocalExecutionObservationV1, CandidateMethodMetadataV1,
        CandidatePrivateCalibrationMetadataV1, CandidateProofBoundMetadataV1,
        CandidateProofMetadataV1, CandidateUpstreamMetadataV1, CandidateVerificationMetadataV1,
    };

    static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);
    const BUNDLED_ALTERNATE_GUEST_ELF_BYTES: usize = 129_308;
    const BUNDLED_ALTERNATE_GUEST_ELF_SHA256: &str =
        "9ec1918661f691808006d91e2ab672bfa8cd9aac6a704b23c3ed3410c372ca07";
    const BUNDLED_ALTERNATE_GUEST_IMAGE_ID: &str =
        "cc4598c901b00eaac10b058a41448db19e84607a5ab67deca585ebb3805f5b27";

    struct TestDirectory {
        path: PathBuf,
    }

    fn bundled_alternate_root_export() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/alternate-root-lift-po2-15-v1/candidate-proof-export")
    }

    fn bundled_alternate_method_identity() -> ExpectedMethodIdentity {
        let mut image_id = [0_u8; 32];
        hex::decode_to_slice(BUNDLED_ALTERNATE_GUEST_IMAGE_ID, &mut image_id).unwrap();
        let mut elf_sha256 = [0_u8; 32];
        hex::decode_to_slice(BUNDLED_ALTERNATE_GUEST_ELF_SHA256, &mut elf_sha256).unwrap();
        ExpectedMethodIdentity {
            image_id: Digest::from(image_id),
            elf_length: BUNDLED_ALTERNATE_GUEST_ELF_BYTES,
            elf_sha256,
        }
    }

    #[cfg(feature = "proof-generation")]
    struct MetadataContractFixture {
        metadata: CandidateMetadata,
        manifest: Vec<ManifestEntry>,
        statement: Vec<u8>,
        raw_seal: Vec<u8>,
        receipt_oracle: Vec<u8>,
        guest_elf: Vec<u8>,
        image_id: Digest,
        claim_digest: Digest,
        control_id: Digest,
        journal_digest: Digest,
    }

    #[cfg(feature = "proof-generation")]
    // Keeping the complete literal together makes this security fixture easier
    // to compare against the metadata contract it is intended to exercise.
    #[allow(
        clippy::too_many_lines,
        reason = "the complete alternate-root metadata fixture is more auditable in one literal"
    )]
    fn alternate_metadata_contract_fixture() -> MetadataContractFixture {
        let statement = b"statement".to_vec();
        let raw_seal = b"seal".to_vec();
        let receipt_oracle = b"oracle".to_vec();
        let guest_elf = b"guest".to_vec();
        let image_id = Digest::ZERO;
        let claim_digest = Digest::ZERO;
        let journal_digest = Digest::ZERO;
        let control_id = expected_normal_lift_control_id(ALTERNATE_ROOT_SEGMENT_PO2).unwrap();
        let observed_files: [(&str, &[u8], &str); 6] = [
            (RAW_SEAL_FILE, &raw_seal, "raw-succinct-seal"),
            (
                RECEIPT_ORACLE_FILE,
                &receipt_oracle,
                "upstream-bincode-receipt-oracle",
            ),
            (JOURNAL_FILE, &statement, "journal"),
            (IMAGE_ID_FILE, image_id.as_bytes(), "guest-image-id"),
            (
                CLAIM_DIGEST_FILE,
                claim_digest.as_bytes(),
                "receipt-claim-digest",
            ),
            (
                CONTROL_ID_FILE,
                control_id.as_bytes(),
                "normal-lift-control-id",
            ),
        ];
        let manifest = observed_files
            .iter()
            .map(|(path, bytes, _)| ManifestEntry {
                path: (*path).to_owned(),
                length: bytes.len().to_string(),
                sha256: sha256_hex(bytes),
            })
            .collect::<Vec<_>>();
        let files = observed_files
            .iter()
            .map(|(path, bytes, role)| CandidateFileMetadataV1 {
                path: (*path).to_owned(),
                length: bytes.len().to_string(),
                sha256: sha256_hex(bytes),
                role: (*role).to_owned(),
            })
            .collect();
        let metadata = CandidateMetadata {
            candidate_status: "non-final-alternate-root-negative-witness".to_owned(),
            format_version: 1,
            upstream: CandidateUpstreamMetadataV1 {
                repository: RISC0_REPOSITORY.to_owned(),
                commit: RISC0_COMMIT.to_owned(),
                risc0_zkvm_version: risc0_zkvm::VERSION.to_owned(),
                receipt_oracle_codec: "bincode-1.3.3-upstream-host-serialization".to_owned(),
            },
            method: CandidateMethodMetadataV1 {
                image_id: hex::encode(image_id.as_bytes()),
                elf_length: guest_elf.len().to_string(),
                elf_sha256: sha256_hex(&guest_elf),
            },
            proof_bound: CandidateProofBoundMetadataV1 {
                receipt_bound: true,
                statement_length: statement.len().to_string(),
                statement_sha256: sha256_hex(&statement),
                journal_digest: hex::encode(journal_digest.as_bytes()),
                claim_digest: hex::encode(claim_digest.as_bytes()),
            },
            private_calibration: CandidatePrivateCalibrationMetadataV1 {
                receipt_bound: false,
                candidate_scope: "local-reproduction-provenance-only".to_owned(),
                selection_rule: "canonical-monotone-ranking-v1-not-global-minimum".to_owned(),
                selected_observation_is_exact: true,
                workload_iterations: "0".to_owned(),
                workload_seed_hex: format!("{WORKLOAD_SEED:016x}"),
            },
            local_execution_observation: CandidateLocalExecutionObservationV1 {
                receipt_bound: false,
                candidate_scope: "local-reproduction-provenance-only".to_owned(),
                segment_count: "1".to_owned(),
                executor_segment_limit_po2: EXECUTOR_SEGMENT_LIMIT_PO2,
                segment_po2: ALTERNATE_ROOT_SEGMENT_PO2,
                user_cycles: (1_u64 << ALTERNATE_ROOT_SEGMENT_PO2).to_string(),
                total_cycles: (1_u64 << ALTERNATE_ROOT_SEGMENT_PO2).to_string(),
                paging_cycles: "0".to_owned(),
                reserved_cycles: "0".to_owned(),
            },
            proof: CandidateProofMetadataV1 {
                receipt_kind: "succinct-single-lift-fixed-alternate-root".to_owned(),
                hash_function: "poseidon2".to_owned(),
                control_id: hex::encode(control_id.as_bytes()),
                inner_control_root: EXPECTED_ALTERNATE_CONTROL_ROOT_HEX.to_owned(),
                verifier_parameters: EXPECTED_ALTERNATE_VERIFIER_PARAMETERS_HEX.to_owned(),
                outer_po2: EXPECTED_OUTER_PO2,
                raw_seal_words: PROOF_WORDS.to_string(),
                raw_seal_bytes: PROOF_BYTES.to_string(),
                claim_digest: hex::encode(claim_digest.as_bytes()),
                journal_digest: hex::encode(journal_digest.as_bytes()),
            },
            verification: CandidateVerificationMetadataV1 {
                receipt_bound: false,
                verification_authority: "fixed-alternate-control-root-verifier-context".to_owned(),
                explicit_local_prover: true,
                dev_mode: false,
                prove_guest_errors: false,
                work_receipt_present: false,
                upstream_receipt_verify: true,
                profile_owned_shape_verify: false,
                receipt_oracle_is_consensus_encoding: false,
            },
            files,
        };
        MetadataContractFixture {
            metadata,
            manifest,
            statement,
            raw_seal,
            receipt_oracle,
            guest_elf,
            image_id,
            claim_digest,
            control_id,
            journal_digest,
        }
    }

    #[cfg(feature = "proof-generation")]
    fn validate_metadata_fixture(
        fixture: &MetadataContractFixture,
        mode: CandidateExportMode,
    ) -> Result<()> {
        let expected_method = ExpectedMethodIdentity {
            image_id: fixture.image_id,
            elf_length: fixture.guest_elf.len(),
            elf_sha256: Sha256::digest(&fixture.guest_elf).into(),
        };
        validate_metadata(
            &fixture.metadata,
            &fixture.manifest,
            &fixture.statement,
            ALTERNATE_ROOT_SEGMENT_PO2,
            &fixture.raw_seal,
            &fixture.receipt_oracle,
            &expected_method,
            fixture.claim_digest,
            fixture.control_id,
            fixture.journal_digest,
            mode,
        )
    }

    #[cfg(feature = "proof-generation")]
    #[test]
    fn fixed_alternate_metadata_contract_accepts_only_its_exact_mode() {
        let alternate = alternate_metadata_contract_fixture();
        validate_metadata_fixture(&alternate, CandidateExportMode::FixedAlternate).unwrap();
        assert!(validate_metadata_fixture(&alternate, CandidateExportMode::StockProfile).is_err());

        let mut stock = alternate_metadata_contract_fixture();
        stock.metadata.candidate_status = "non-final-reproduction-candidate".to_owned();
        stock.metadata.proof.receipt_kind = "succinct-single-lift".to_owned();
        stock.metadata.proof.inner_control_root = EXPECTED_INNER_CONTROL_ROOT_HEX.to_owned();
        stock.metadata.proof.verifier_parameters = EXPECTED_VERIFIER_PARAMETERS_HEX.to_owned();
        stock.metadata.verification.verification_authority =
            "pinned-stock-verifier-context".to_owned();
        stock.metadata.verification.profile_owned_shape_verify = true;
        validate_metadata_fixture(&stock, CandidateExportMode::StockProfile).unwrap();
        assert!(
            validate_metadata_fixture(&stock, CandidateExportMode::FixedAlternate).is_err(),
            "stock metadata crossed the fixed alternate-root mode boundary"
        );
    }

    #[cfg(feature = "proof-generation")]
    #[test]
    fn fixed_alternate_metadata_rejects_authority_root_control_parameters_and_files() {
        let mut fixture = alternate_metadata_contract_fixture();
        fixture.metadata.verification.verification_authority =
            "pinned-stock-verifier-context".to_owned();
        assert!(validate_metadata_fixture(&fixture, CandidateExportMode::FixedAlternate).is_err());

        let mut fixture = alternate_metadata_contract_fixture();
        fixture.metadata.proof.inner_control_root = EXPECTED_INNER_CONTROL_ROOT_HEX.to_owned();
        assert!(validate_metadata_fixture(&fixture, CandidateExportMode::FixedAlternate).is_err());

        let mut fixture = alternate_metadata_contract_fixture();
        fixture.metadata.proof.control_id = "00".repeat(32);
        assert!(validate_metadata_fixture(&fixture, CandidateExportMode::FixedAlternate).is_err());

        let mut fixture = alternate_metadata_contract_fixture();
        fixture.metadata.proof.verifier_parameters = EXPECTED_VERIFIER_PARAMETERS_HEX.to_owned();
        assert!(validate_metadata_fixture(&fixture, CandidateExportMode::FixedAlternate).is_err());

        let mut fixture = alternate_metadata_contract_fixture();
        fixture.metadata.files.swap(0, 1);
        assert!(validate_metadata_fixture(&fixture, CandidateExportMode::FixedAlternate).is_err());
    }

    #[cfg(feature = "proof-generation")]
    #[test]
    fn bundled_fixed_alternate_export_verifies_only_through_its_explicit_mode() {
        let export_root = bundled_alternate_root_export();
        let statement = export_root.join(PROOF_OUTPUT_DIRECTORY).join(JOURNAL_FILE);
        let method = bundled_alternate_method_identity();
        let control_id = expected_normal_lift_control_id(ALTERNATE_ROOT_SEGMENT_PO2).unwrap();

        let verified = verify_candidate_export_for_mode_with_authenticated_method(
            &export_root,
            &statement,
            ALTERNATE_ROOT_SEGMENT_PO2,
            control_id,
            method,
            CandidateExportMode::FixedAlternate,
        )
        .unwrap();
        assert_eq!(verified.segment_po2, ALTERNATE_ROOT_SEGMENT_PO2);

        let error = verify_candidate_export_for_mode_with_authenticated_method(
            &export_root,
            &statement,
            ALTERNATE_ROOT_SEGMENT_PO2,
            control_id,
            method,
            CandidateExportMode::StockProfile,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("verifier-parameters"),
            "alternate export crossed the stock mode or failed at an unexpected boundary: {error}"
        );
    }

    #[test]
    fn bundled_alternate_root_kat_has_the_closed_export_envelope() {
        const FIXTURE_BYTES: usize = 450_496;
        let export_root = bundled_alternate_root_export();
        require_exact_export_layout(&export_root).unwrap();
        let proof_output = export_root.join(PROOF_OUTPUT_DIRECTORY);
        require_exact_proof_output_layout(&proof_output).unwrap();

        let mut observed_bytes =
            read_regular_file(&export_root.join(OUTPUT_MANIFEST_FILE), MANIFEST_MAX_BYTES)
                .unwrap()
                .len();
        for name in MANIFEST_PATHS {
            observed_bytes += read_regular_file(
                &proof_output.join(name),
                artifact_length_contract(name, 159).unwrap().maximum(),
            )
            .unwrap()
            .len();
        }
        assert_eq!(observed_bytes, FIXTURE_BYTES);

        let method = bundled_alternate_method_identity();
        let metadata_source =
            read_regular_file(&proof_output.join(METADATA_FILE), METADATA_MAX_BYTES).unwrap();
        let metadata = CandidateMetadata::from_canonical_jcs(&metadata_source).unwrap();
        validate_expected_method_identity(&metadata, &method).unwrap();

        let mut wrong_image = method;
        wrong_image.image_id = Digest::from([1_u8; 32]);
        assert!(validate_expected_method_identity(&metadata, &wrong_image).is_err());

        let mut wrong_length = method;
        wrong_length.elf_length += 1;
        assert!(validate_expected_method_identity(&metadata, &wrong_length).is_err());

        let mut wrong_sha256 = method;
        wrong_sha256.elf_sha256[0] ^= 1;
        assert!(validate_expected_method_identity(&metadata, &wrong_sha256).is_err());
    }

    #[cfg(all(feature = "proof-generation", feature = "embedded-method"))]
    #[test]
    #[ignore = "requires EIP0045_REAL_STOCK_EXPORT and EIP0045_REAL_STATEMENT"]
    fn real_stock_export_is_rejected_by_the_fixed_alternate_mode() {
        let export_root = PathBuf::from(
            std::env::var_os("EIP0045_REAL_STOCK_EXPORT")
                .expect("EIP0045_REAL_STOCK_EXPORT must name candidate-proof-export"),
        );
        let statement = PathBuf::from(
            std::env::var_os("EIP0045_REAL_STATEMENT")
                .expect("EIP0045_REAL_STATEMENT must name the exact statement"),
        );
        let image_id = Digest::from(EIP_0045_GUEST_ID);
        let verified = verify_candidate_export(
            &export_root,
            &statement,
            ALTERNATE_ROOT_SEGMENT_PO2,
            EIP_0045_GUEST_ELF,
            image_id,
        )
        .unwrap();
        assert_eq!(verified.segment_po2, ALTERNATE_ROOT_SEGMENT_PO2);

        let error = verify_alternate_root_candidate_export(
            &export_root,
            &statement,
            EIP_0045_GUEST_ELF,
            image_id,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("verifier-parameters"),
            "stock export crossed the fixed alternate-root mode or failed at an unexpected boundary: {error}"
        );
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let counter = TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock after epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "eip0045-export-{label}-{}-{nanos}-{counter}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create unique export-verifier test directory");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn manifest_fixture(statement_length: usize) -> Vec<ManifestEntry> {
        MANIFEST_PATHS
            .iter()
            .map(|path| {
                let length = match *path {
                    CLAIM_DIGEST_FILE | CONTROL_ID_FILE | IMAGE_ID_FILE => DIGEST_ARTIFACT_BYTES,
                    JOURNAL_FILE => statement_length,
                    METADATA_FILE | RECEIPT_ORACLE_FILE => 1,
                    RAW_SEAL_FILE => PROOF_BYTES,
                    _ => unreachable!("fixture uses the closed manifest path set"),
                };
                ManifestEntry {
                    path: (*path).to_owned(),
                    length: length.to_string(),
                    sha256: "00".repeat(32),
                }
            })
            .collect()
    }

    fn create_regular_file_with_length(path: &Path, length: usize) {
        let file = File::create(path).expect("create fixture file");
        file.set_len(u64::try_from(length).expect("fixture length fits u64"))
            .expect("set fixture file length");
    }

    fn materialize_manifest_files(proof_output: &Path, manifest: &[ManifestEntry]) {
        fs::create_dir_all(proof_output).expect("create proof-output fixture");
        for entry in manifest {
            let length = entry
                .length
                .parse::<usize>()
                .expect("fixture manifest length fits usize");
            create_regular_file_with_length(&proof_output.join(&entry.path), length);
        }
    }

    fn create_empty_flat_proof_output(proof_output: &Path) {
        fs::create_dir_all(proof_output).expect("create flat proof-output fixture");
        for path in MANIFEST_PATHS {
            create_regular_file_with_length(&proof_output.join(path), 0);
        }
    }

    #[test]
    fn expected_segment_po2_is_validated_before_any_filesystem_access() {
        let temp = TestDirectory::new("early-po2");
        let missing = temp.path().join("missing");
        let error = verify_candidate_export(&missing, &missing, 14, &[], Digest::ZERO)
            .unwrap_err()
            .to_string();
        assert!(error.contains("outside the frozen range 15..=22"));
    }

    #[test]
    fn public_verifier_authenticates_the_guest_elf_before_filesystem_access() {
        let temp = TestDirectory::new("early-method");
        let missing = temp.path().join("missing");
        let error = verify_candidate_export(&missing, &missing, 15, &[], Digest::ZERO)
            .unwrap_err()
            .to_string();
        assert!(error.contains("cannot compute the caller-supplied expected guest ELF image ID"));
        assert!(!error.contains("cannot open candidate artifact"));
    }

    #[test]
    fn canonical_decimal_parsing_rejects_noncanonical_and_overflow_values() {
        assert_eq!(parse_decimal_u64("0", "fixture").unwrap(), 0);
        assert_eq!(parse_decimal_u64("42", "fixture").unwrap(), 42);
        for invalid in ["", "00", "01", "+1", "-1", " 1", "1 "] {
            assert!(parse_decimal_u64(invalid, "fixture").is_err());
        }
        assert!(parse_decimal_u64("18446744073709551616", "fixture").is_err());
    }

    #[test]
    fn manifest_path_set_is_closed_and_ordered() {
        let valid = MANIFEST_PATHS
            .iter()
            .map(|path| ManifestEntry {
                path: (*path).to_owned(),
                length: "0".to_owned(),
                sha256: "00".repeat(32),
            })
            .collect::<Vec<_>>();
        require_exact_manifest_paths(&valid).unwrap();

        let mut missing = valid.clone();
        missing.pop();
        assert!(require_exact_manifest_paths(&missing).is_err());

        let mut reordered = valid;
        reordered.swap(0, 1);
        assert!(require_exact_manifest_paths(&reordered).is_err());
    }

    #[test]
    fn top_level_and_proof_output_enumerations_reject_extra_entries() {
        let top = TestDirectory::new("extra-top-level");
        fs::create_dir(top.path().join(PROOF_OUTPUT_DIRECTORY)).unwrap();
        fs::write(top.path().join(OUTPUT_MANIFEST_FILE), []).unwrap();
        fs::write(top.path().join("unexpected.bin"), []).unwrap();
        let top_error = require_exact_export_layout(top.path())
            .unwrap_err()
            .to_string();
        assert!(top_error.contains("more than 2 entries"));

        let proof = TestDirectory::new("extra-proof-output");
        create_empty_flat_proof_output(proof.path());
        fs::write(proof.path().join("unexpected.bin"), []).unwrap();
        let proof_error = require_exact_proof_output_layout(proof.path())
            .unwrap_err()
            .to_string();
        assert!(proof_error.contains("more than 7 entries"));
    }

    #[test]
    fn proof_output_layout_rejects_empty_and_nested_directories() {
        for nested in [false, true] {
            let label = if nested {
                "nested-directory"
            } else {
                "empty-directory"
            };
            let temp = TestDirectory::new(label);
            fs::create_dir(temp.path().join(CLAIM_DIGEST_FILE)).unwrap();
            if nested {
                fs::write(temp.path().join(CLAIM_DIGEST_FILE).join("nested.bin"), []).unwrap();
            }
            for path in MANIFEST_PATHS {
                if path != CLAIM_DIGEST_FILE {
                    create_regular_file_with_length(&temp.path().join(path), 0);
                }
            }

            let error = require_exact_proof_output_layout(temp.path())
                .unwrap_err()
                .to_string();
            assert!(error.contains("not a regular non-link file"));
        }
    }

    #[test]
    fn manifest_declared_lengths_obey_every_artifact_cap() {
        const STATEMENT_LENGTH: usize = 159;
        let valid = manifest_fixture(STATEMENT_LENGTH);
        validate_candidate_manifest_contract(&valid, STATEMENT_LENGTH).unwrap();

        let invalid_lengths = [
            (CLAIM_DIGEST_FILE, DIGEST_ARTIFACT_BYTES - 1),
            (CONTROL_ID_FILE, DIGEST_ARTIFACT_BYTES + 1),
            (IMAGE_ID_FILE, DIGEST_ARTIFACT_BYTES - 1),
            (JOURNAL_FILE, STATEMENT_LENGTH + 1),
            (METADATA_FILE, METADATA_MAX_BYTES + 1),
            (RAW_SEAL_FILE, PROOF_BYTES + 1),
            (RECEIPT_ORACLE_FILE, CANDIDATE_RECEIPT_ORACLE_MAX_BYTES + 1),
        ];
        for (path, invalid_length) in invalid_lengths {
            let mut invalid = valid.clone();
            find_manifest_entry_mut(&mut invalid, path).length = invalid_length.to_string();
            let error = validate_candidate_manifest_contract(&invalid, STATEMENT_LENGTH)
                .unwrap_err()
                .to_string();
            assert!(error.contains(path), "wrong error for {path}: {error}");
        }

        let mut maximum = valid;
        find_manifest_entry_mut(&mut maximum, JOURNAL_FILE).length =
            MAX_STATEMENT_BYTES.to_string();
        find_manifest_entry_mut(&mut maximum, METADATA_FILE).length =
            METADATA_MAX_BYTES.to_string();
        find_manifest_entry_mut(&mut maximum, RECEIPT_ORACLE_FILE).length =
            CANDIDATE_RECEIPT_ORACLE_MAX_BYTES.to_string();
        validate_candidate_manifest_contract(&maximum, MAX_STATEMENT_BYTES).unwrap();
        let total = maximum
            .iter()
            .map(|entry| entry.length.parse::<usize>().unwrap())
            .sum::<usize>();
        assert_eq!(total, PROOF_OUTPUT_MAX_BYTES);
    }

    #[test]
    fn physical_oversize_is_rejected_by_preflight_before_snapshot_hashing() {
        const STATEMENT_LENGTH: usize = 159;
        let temp = TestDirectory::new("physical-oversize");
        let manifest = manifest_fixture(STATEMENT_LENGTH);
        materialize_manifest_files(temp.path(), &manifest);
        create_regular_file_with_length(&temp.path().join(RAW_SEAL_FILE), PROOF_BYTES + 1);

        let error = validate_candidate_tree_snapshot(temp.path(), &manifest, STATEMENT_LENGTH)
            .unwrap_err()
            .to_string();
        assert!(error.contains("physical length"));
        assert!(error.contains("expected exactly"));
        assert!(!error.contains("differs from its manifest entry"));
    }

    #[test]
    fn bounded_reader_and_regular_file_reject_maximum_plus_one() {
        let mut cursor = Cursor::new([0_u8; 4]);
        let stream_error = read_to_end_bounded(&mut cursor, Path::new("fixture.bin"), 3)
            .unwrap_err()
            .to_string();
        assert!(stream_error.contains("grew above 3 bytes"));

        let temp = TestDirectory::new("maximum-plus-one");
        let path = temp.path().join("fixture.bin");
        create_regular_file_with_length(&path, 4);
        let metadata_error = read_regular_file(&path, 3).unwrap_err().to_string();
        assert!(metadata_error.contains("exceeds 3 bytes"));
    }

    #[test]
    fn bounded_reader_rejects_a_regular_file_with_multiple_hardlinks() {
        let temp = TestDirectory::new("hardlink");
        let original = temp.path().join("original.bin");
        let alias = temp.path().join("alias.bin");
        fs::write(&original, b"fixture").unwrap();
        fs::hard_link(&original, &alias).unwrap();

        let error = read_regular_file(&original, 7).unwrap_err().to_string();
        assert!(
            error.contains("exactly one hard link"),
            "hardlinked artifact failed at the wrong boundary: {error}"
        );
    }

    #[test]
    fn bounded_reader_rejects_path_substitution_between_check_and_open() {
        let temp = TestDirectory::new("check-open-substitution");
        let path = temp.path().join("fixture.bin");
        let replacement = temp.path().join("replacement.bin");
        let parked = temp.path().join("parked.bin");
        fs::write(&path, b"trusted").unwrap();
        fs::write(&replacement, b"swapped").unwrap();

        let error = read_regular_file_with_interposition(&path, 7, || {
            fs::rename(&path, &parked)?;
            fs::rename(&replacement, &path)?;
            Ok(())
        })
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("open handle identity differs from path before read"),
            "substitution failed at the wrong boundary: {error}"
        );
    }

    #[test]
    fn unchanged_manifest_helper_rejects_final_manifest_drift() {
        let temp = TestDirectory::new("manifest-drift");
        let path = temp.path().join(OUTPUT_MANIFEST_FILE);
        fs::write(&path, b"[]").unwrap();
        require_unchanged_manifest(&path, b"[]", "in the fixture").unwrap();

        fs::write(&path, b"[ ]").unwrap();
        let error = require_unchanged_manifest(&path, b"[]", "in the fixture")
            .unwrap_err()
            .to_string();
        assert!(error.contains("changed in the fixture"));
    }

    #[test]
    fn explicit_bincode_options_match_the_pinned_legacy_encoder_and_reject_trailing_bytes() {
        let fixture = (0x0102_0304_u32, vec![5_u8, 6, 7]);
        let legacy = bincode::serialize(&fixture).unwrap();
        assert_eq!(
            receipt_oracle_bincode_options()
                .serialize(&fixture)
                .unwrap(),
            legacy
        );
        assert_eq!(
            receipt_oracle_bincode_options()
                .deserialize::<(u32, Vec<u8>)>(&legacy)
                .unwrap(),
            fixture
        );

        let mut trailing = legacy;
        trailing.push(0);
        assert!(
            receipt_oracle_bincode_options()
                .deserialize::<(u32, Vec<u8>)>(&trailing)
                .is_err()
        );
    }

    fn find_manifest_entry_mut<'a>(
        manifest: &'a mut [ManifestEntry],
        name: &str,
    ) -> &'a mut ManifestEntry {
        manifest
            .iter_mut()
            .find(|entry| entry.path == name)
            .expect("fixture contains the closed path set")
    }
}
