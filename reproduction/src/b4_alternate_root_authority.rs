//! Fixed, descriptor-independent replay authority for the B4 alternate-root witness.
//!
//! The public request has no proof-profile selectors. The public generated
//! bundle owns one exact, compiled seven-file inventory, but is never authority
//! by itself. Only the crate-private consuming replay can mint the opaque
//! authority after both upstream receipt verification and direct raw-STARK
//! verification succeed.

#![cfg_attr(
    all(
        feature = "negative-materialization-set",
        not(any(test, target_os = "linux"))
    ),
    allow(
        dead_code,
        reason = "the descriptor-rooted authority consumer is Linux-only; Windows still builds the shared untrusted bundle DTO"
    )
)]

#[cfg(feature = "negative-materialization-set")]
use core::fmt;
#[cfg(feature = "negative-materialization-set")]
use std::collections::BTreeMap;

#[cfg(feature = "negative-materialization-set")]
use risc0_zkvm::{
    ALLOWED_CONTROL_IDS, Digest as Risc0Digest, InnerReceipt, MaybePruned, Receipt, ReceiptClaim,
    SuccinctReceiptVerifierParameters, VerifierContext, compute_image_id, sha::Digestible as _,
};
#[cfg(feature = "negative-materialization-set")]
use sha2::{Digest as _, Sha256};

#[cfg(feature = "negative-materialization-set")]
use crate::{
    b4_terminal::B4_TERMINAL_FIXTURE_RISC0_VERSION,
    b4_validator::verify_fixed_alternate_root_stark,
    candidate_metadata::{CANDIDATE_METADATA_V1_MAX_BYTES, CandidateMetadataV1},
    canonical::validate_canonical_json_source,
    claim::ok_receipt_claim_digests,
    constants::{
        B4_ALTERNATE_CONTROL_ROOT, B4_ALTERNATE_OMITTED_CONTROL_ID_HEX,
        B4_ALTERNATE_VERIFIER_PARAMETERS_HEX, MAX_STATEMENT_BYTES, PROOF_BYTES, PROOF_WORDS,
        RISC0_COMMIT, RISC0_NORMAL_LIFT_CONTROL_IDS_HEX, RISC0_OUTER_PO2, RISC0_REPOSITORY,
    },
    ergo_statement::parse_ergo_statement_v1,
    manifest::{ManifestEntry, ProofOutputManifest, validate_manifest_shape},
    receipt_oracle_codec::RECEIPT_ORACLE_MAX_BYTES,
    receipt_oracle_replay::{CompiledStockSuccinctReplayV1, decode_exact},
};

#[cfg(feature = "negative-materialization-set")]
const MANIFEST_MAX_BYTES: usize = 16 * 1024;
#[cfg(feature = "negative-materialization-set")]
const CONTROL_INCLUSION_PROOF_DEPTH: usize = 8;
#[cfg(feature = "negative-materialization-set")]
const FIXED_LIFT_15_CONTROL_INDEX: u32 = 5;
#[cfg(feature = "negative-materialization-set")]
const EXPECTED_STOCK_VERIFIER_PARAMETERS_HEX: &str =
    "ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013";

#[cfg(feature = "negative-materialization-set")]
const EXPECTED_FILES: [&str; 7] = [
    "candidate-claim-digest.bin",
    "candidate-control-id.bin",
    "candidate-image-id.bin",
    "candidate-journal.bin",
    "candidate-metadata.json",
    "candidate-raw-seal.bin",
    "candidate-receipt-oracle.bincode",
];

#[cfg(feature = "negative-materialization-set")]
const METADATA_FILE_ROLES: [(&str, &str); 6] = [
    ("candidate-raw-seal.bin", "raw-succinct-seal"),
    (
        "candidate-receipt-oracle.bincode",
        "upstream-bincode-receipt-oracle",
    ),
    ("candidate-journal.bin", "journal"),
    ("candidate-image-id.bin", "guest-image-id"),
    ("candidate-claim-digest.bin", "receipt-claim-digest"),
    ("candidate-control-id.bin", "normal-lift-control-id"),
];

/// Opaque fixed proof request created only from already authenticated inputs.
///
/// The generator can read only the exact statement. The independently
/// computed image identity and ELF measurement remain private verifier inputs.
#[cfg(feature = "negative-materialization-set")]
pub struct B4FixedAlternateRootProofRequestV1 {
    statement: Vec<u8>,
    image_id: [u8; 32],
    guest_elf_length: usize,
    guest_elf_sha256: [u8; 32],
}

#[cfg(feature = "negative-materialization-set")]
impl B4FixedAlternateRootProofRequestV1 {
    pub(crate) fn from_authenticated(
        statement: &[u8],
        guest_elf: &[u8],
    ) -> Result<Self, B4AlternateRootAuthorityError> {
        let computed = compute_image_id(guest_elf).map_err(|error| {
            reject(
                B4AlternateRootAuthorityErrorKind::RequestIdentity,
                format!("cannot derive the authenticated guest image ID: {error}"),
            )
        })?;
        let image_id = digest_bytes(&computed);
        let decoded = parse_ergo_statement_v1(statement).map_err(|error| {
            reject(
                B4AlternateRootAuthorityErrorKind::RequestStatement,
                format!("authenticated statement is not canonical ErgoStatementV1: {error}"),
            )
        })?;
        if decoded.program_id() != image_id {
            return Err(reject(
                B4AlternateRootAuthorityErrorKind::RequestIdentity,
                "authenticated statement program ID differs from the derived guest image ID",
            ));
        }
        Ok(Self {
            statement: statement.to_vec(),
            image_id,
            guest_elf_length: guest_elf.len(),
            guest_elf_sha256: Sha256::digest(guest_elf).into(),
        })
    }

    /// Exact authenticated statement the fixed generator must commit.
    #[must_use]
    pub fn statement(&self) -> &[u8] {
        &self.statement
    }

    #[cfg(test)]
    fn from_retained_test_identity(
        statement: &[u8],
        image_id: [u8; 32],
        guest_elf_length: usize,
        guest_elf_sha256: [u8; 32],
    ) -> Self {
        let decoded = parse_ergo_statement_v1(statement).unwrap();
        assert_eq!(decoded.program_id(), image_id);
        Self {
            statement: statement.to_vec(),
            image_id,
            guest_elf_length,
            guest_elf_sha256,
        }
    }
}

/// Owned generator output for exactly one fixed alternate-root proof.
///
/// Construction performs no authentication. The artifact names and roles are
/// compiled into this type; callers cannot supply paths, roots, exponents,
/// controls, proving modes, workloads, or verifier implementations.
pub struct B4GeneratedAlternateRootProofBundleV1 {
    manifest_jcs: Vec<u8>,
    claim_digest: [u8; 32],
    control_id: [u8; 32],
    image_id: [u8; 32],
    journal: Vec<u8>,
    metadata_jcs: Vec<u8>,
    raw_seal: Vec<u8>,
    receipt_oracle: Vec<u8>,
}

impl B4GeneratedAlternateRootProofBundleV1 {
    /// Own one generated fixed-shape bundle without promoting it to authority.
    #[allow(
        clippy::too_many_arguments,
        reason = "seven compiled artifact roles plus their manifest intentionally prevent a caller-selected path map"
    )]
    #[must_use]
    pub fn new(
        manifest_jcs: Vec<u8>,
        claim_digest: [u8; 32],
        control_id: [u8; 32],
        image_id: [u8; 32],
        journal: Vec<u8>,
        metadata_jcs: Vec<u8>,
        raw_seal: Vec<u8>,
        receipt_oracle: Vec<u8>,
    ) -> Self {
        Self {
            manifest_jcs,
            claim_digest,
            control_id,
            image_id,
            journal,
            metadata_jcs,
            raw_seal,
            receipt_oracle,
        }
    }

    /// Exact canonical proof-output manifest bytes.
    #[must_use]
    pub fn manifest_jcs(&self) -> &[u8] {
        &self.manifest_jcs
    }

    /// Generated successful-claim digest artifact.
    #[must_use]
    pub const fn claim_digest(&self) -> [u8; 32] {
        self.claim_digest
    }

    /// Generated fixed Lift15 control-ID artifact.
    #[must_use]
    pub const fn control_id(&self) -> [u8; 32] {
        self.control_id
    }

    /// Generated guest image-ID artifact.
    #[must_use]
    pub const fn image_id(&self) -> [u8; 32] {
        self.image_id
    }

    /// Generated journal artifact.
    #[must_use]
    pub fn journal(&self) -> &[u8] {
        &self.journal
    }

    /// Exact canonical candidate-metadata bytes.
    #[must_use]
    pub fn metadata_jcs(&self) -> &[u8] {
        &self.metadata_jcs
    }

    /// Generated raw succinct seal artifact.
    #[must_use]
    pub fn raw_seal(&self) -> &[u8] {
        &self.raw_seal
    }

    /// Generated exact outer-Receipt bincode oracle.
    #[must_use]
    pub fn receipt_oracle(&self) -> &[u8] {
        &self.receipt_oracle
    }

    #[cfg(feature = "negative-materialization-set")]
    fn artifacts(&self) -> [(&'static str, &[u8]); 7] {
        [
            ("candidate-claim-digest.bin", &self.claim_digest),
            ("candidate-control-id.bin", &self.control_id),
            ("candidate-image-id.bin", &self.image_id),
            ("candidate-journal.bin", &self.journal),
            ("candidate-metadata.json", &self.metadata_jcs),
            ("candidate-raw-seal.bin", &self.raw_seal),
            ("candidate-receipt-oracle.bincode", &self.receipt_oracle),
        ]
    }
}

#[cfg(feature = "negative-materialization-set")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum B4AlternateRootAuthorityErrorKind {
    RequestStatement,
    RequestIdentity,
    BundleManifest,
    BundleShape,
    BundleMetadata,
    JournalBinding,
    ImageIdentity,
    ClaimBinding,
    ControlBinding,
    ReceiptDecode,
    ReceiptShape,
    RawSealBinding,
    AlternateReceiptVerification,
    StockIsolation,
    DirectStarkReplay,
    TerminalBinding,
}

#[cfg(feature = "negative-materialization-set")]
#[derive(Debug)]
pub(crate) struct B4AlternateRootAuthorityError {
    kind: B4AlternateRootAuthorityErrorKind,
    detail: String,
}

#[cfg(feature = "negative-materialization-set")]
#[cfg(test)]
impl B4AlternateRootAuthorityError {
    pub(crate) const fn kind(&self) -> B4AlternateRootAuthorityErrorKind {
        self.kind
    }

    pub(crate) fn detail(&self) -> &str {
        &self.detail
    }
}

#[cfg(feature = "negative-materialization-set")]
impl fmt::Display for B4AlternateRootAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.detail)
    }
}

#[cfg(feature = "negative-materialization-set")]
impl std::error::Error for B4AlternateRootAuthorityError {}

/// Opaque, non-serializable authority retained only after every replay gate.
#[cfg(feature = "negative-materialization-set")]
pub(crate) struct B4FixedAlternateRootProofAuthorityV1 {
    bundle: B4GeneratedAlternateRootProofBundleV1,
}

#[cfg(feature = "negative-materialization-set")]
impl fmt::Debug for B4FixedAlternateRootProofAuthorityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("B4FixedAlternateRootProofAuthorityV1")
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "negative-materialization-set")]
impl B4FixedAlternateRootProofAuthorityV1 {
    pub(crate) fn statement(&self) -> &[u8] {
        &self.bundle.journal
    }

    pub(crate) fn raw_seal(&self) -> &[u8] {
        &self.bundle.raw_seal
    }

    #[cfg(test)]
    pub(crate) fn receipt_oracle(&self) -> &[u8] {
        &self.bundle.receipt_oracle
    }

    #[cfg(test)]
    pub(crate) fn journal(&self) -> &[u8] {
        &self.bundle.journal
    }

    #[cfg(test)]
    pub(crate) const fn image_id(&self) -> [u8; 32] {
        self.bundle.image_id
    }

    #[cfg(test)]
    pub(crate) const fn claim_digest(&self) -> [u8; 32] {
        self.bundle.claim_digest
    }

    #[cfg(test)]
    pub(crate) const fn control_id(&self) -> [u8; 32] {
        self.bundle.control_id
    }
}

#[cfg(feature = "negative-materialization-set")]
#[derive(Debug)]
struct B4AlternateRootCryptographicReplayV1 {
    image_id: [u8; 32],
    claim_digest: [u8; 32],
    control_id: [u8; 32],
}

#[cfg(feature = "negative-materialization-set")]
pub(crate) fn authenticate_fixed_alternate_root_bundle(
    request: &B4FixedAlternateRootProofRequestV1,
    bundle: B4GeneratedAlternateRootProofBundleV1,
) -> Result<B4FixedAlternateRootProofAuthorityV1, B4AlternateRootAuthorityError> {
    let manifest = validate_bundle_manifest(&bundle)?;
    validate_bundle_metadata(request, &bundle, &manifest)?;
    let replay = replay_cryptographic_bundle(request, &bundle)?;
    if replay.image_id != bundle.image_id
        || replay.claim_digest != bundle.claim_digest
        || replay.control_id != bundle.control_id
    {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::DirectStarkReplay,
            "cryptographic replay observation differs from the retained bundle",
        ));
    }
    Ok(B4FixedAlternateRootProofAuthorityV1 { bundle })
}

#[cfg(feature = "negative-materialization-set")]
fn validate_bundle_manifest(
    bundle: &B4GeneratedAlternateRootProofBundleV1,
) -> Result<ProofOutputManifest, B4AlternateRootAuthorityError> {
    if !(2..=MANIFEST_MAX_BYTES).contains(&bundle.manifest_jcs.len()) {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::BundleManifest,
            "proof-output manifest is outside its closed byte bound",
        ));
    }
    let value = validate_canonical_json_source(&bundle.manifest_jcs).map_err(|error| {
        reject(
            B4AlternateRootAuthorityErrorKind::BundleManifest,
            format!("proof-output manifest is not exact canonical JCS: {error}"),
        )
    })?;
    let manifest: ProofOutputManifest = serde_json::from_value(value).map_err(|error| {
        reject(
            B4AlternateRootAuthorityErrorKind::BundleManifest,
            format!("proof-output manifest has the wrong closed shape: {error}"),
        )
    })?;
    validate_manifest_shape(&manifest).map_err(|error| {
        reject(
            B4AlternateRootAuthorityErrorKind::BundleManifest,
            format!("proof-output manifest shape is invalid: {error}"),
        )
    })?;
    if manifest.len() != EXPECTED_FILES.len()
        || !manifest
            .iter()
            .zip(EXPECTED_FILES)
            .all(|(entry, expected)| entry.path == expected)
    {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::BundleManifest,
            "proof-output manifest is not the exact seven-file inventory",
        ));
    }

    for (entry, (name, bytes)) in manifest.iter().zip(bundle.artifacts()) {
        if entry.path != name
            || entry.length != bytes.len().to_string()
            || entry.sha256 != sha256_hex(bytes)
        {
            return Err(reject(
                B4AlternateRootAuthorityErrorKind::BundleManifest,
                format!("artifact {name} differs from its exact manifest entry"),
            ));
        }
    }
    if bundle.journal.len() > MAX_STATEMENT_BYTES
        || bundle.metadata_jcs.len() > CANDIDATE_METADATA_V1_MAX_BYTES
        || bundle.raw_seal.len() != PROOF_BYTES
        || bundle.receipt_oracle.is_empty()
        || bundle.receipt_oracle.len() > RECEIPT_ORACLE_MAX_BYTES
    {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::BundleShape,
            "one fixed bundle artifact is outside its closed byte bound",
        ));
    }
    Ok(manifest)
}

#[allow(
    clippy::too_many_lines,
    reason = "the closed metadata contract stays linear so every non-authoritative field is visibly checked before cryptographic replay"
)]
#[cfg(feature = "negative-materialization-set")]
fn validate_bundle_metadata(
    request: &B4FixedAlternateRootProofRequestV1,
    bundle: &B4GeneratedAlternateRootProofBundleV1,
    manifest: &[ManifestEntry],
) -> Result<(), B4AlternateRootAuthorityError> {
    let metadata =
        CandidateMetadataV1::from_canonical_jcs(&bundle.metadata_jcs).map_err(|error| {
            reject(
                B4AlternateRootAuthorityErrorKind::BundleMetadata,
                format!("candidate metadata is not the closed canonical V1 document: {error}"),
            )
        })?;
    let journal_sha256 = sha256_hex(&bundle.journal);
    if metadata.candidate_status != "non-final-alternate-root-negative-witness"
        || metadata.format_version != 1
        || metadata.upstream.repository != RISC0_REPOSITORY
        || metadata.upstream.commit != RISC0_COMMIT
        || metadata.upstream.risc0_zkvm_version != B4_TERMINAL_FIXTURE_RISC0_VERSION
        || metadata.upstream.receipt_oracle_codec != "bincode-1.3.3-upstream-host-serialization"
        || metadata.method.image_id != hex::encode(bundle.image_id)
        || metadata.method.image_id != hex::encode(request.image_id)
        || metadata.method.elf_length != request.guest_elf_length.to_string()
        || metadata.method.elf_sha256 != hex::encode(request.guest_elf_sha256)
        || !metadata.proof_bound.receipt_bound
        || metadata.proof_bound.statement_length != bundle.journal.len().to_string()
        || metadata.proof_bound.statement_sha256 != journal_sha256
        || metadata.proof_bound.journal_digest != journal_sha256
        || metadata.proof_bound.claim_digest != hex::encode(bundle.claim_digest)
    {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::BundleMetadata,
            "candidate identity or receipt-bound metadata differs from measured inputs",
        ));
    }
    let _workload_iterations = parse_canonical_u64(
        &metadata.private_calibration.workload_iterations,
    )
    .ok_or_else(|| {
        reject(
            B4AlternateRootAuthorityErrorKind::BundleMetadata,
            "private calibration workload is not canonical u64",
        )
    })?;
    if metadata.private_calibration.receipt_bound
        || metadata.private_calibration.candidate_scope != "local-reproduction-provenance-only"
        || metadata.private_calibration.selection_rule
            != "canonical-monotone-ranking-v1-not-global-minimum"
        || !metadata.private_calibration.selected_observation_is_exact
        || metadata.private_calibration.workload_seed_hex != "4549503030343501"
    {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::BundleMetadata,
            "private calibration metadata differs from the fixed non-authoritative contract",
        ));
    }
    let observation = &metadata.local_execution_observation;
    let user_cycles = parse_canonical_u64(&observation.user_cycles).ok_or_else(|| {
        reject(
            B4AlternateRootAuthorityErrorKind::BundleMetadata,
            "user-cycle observation is not canonical u64",
        )
    })?;
    let total_cycles = parse_canonical_u64(&observation.total_cycles).ok_or_else(|| {
        reject(
            B4AlternateRootAuthorityErrorKind::BundleMetadata,
            "total-cycle observation is not canonical u64",
        )
    })?;
    let paging_cycles = parse_canonical_u64(&observation.paging_cycles).ok_or_else(|| {
        reject(
            B4AlternateRootAuthorityErrorKind::BundleMetadata,
            "paging-cycle observation is not canonical u64",
        )
    })?;
    let reserved_cycles = parse_canonical_u64(&observation.reserved_cycles).ok_or_else(|| {
        reject(
            B4AlternateRootAuthorityErrorKind::BundleMetadata,
            "reserved-cycle observation is not canonical u64",
        )
    })?;
    if observation.receipt_bound
        || observation.candidate_scope != "local-reproduction-provenance-only"
        || observation.segment_count != "1"
        || observation.executor_segment_limit_po2 != 23
        || observation.segment_po2 != 15
        || user_cycles
            .checked_add(paging_cycles)
            .and_then(|value| value.checked_add(reserved_cycles))
            != Some(total_cycles)
        || total_cycles != (1_u64 << observation.segment_po2)
    {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::BundleMetadata,
            "local execution observation differs from the fixed single-segment contract",
        ));
    }
    if metadata.proof.receipt_kind != "succinct-single-lift-fixed-alternate-root"
        || metadata.proof.hash_function != "poseidon2"
        || metadata.proof.control_id != hex::encode(bundle.control_id)
        || metadata.proof.inner_control_root != hex::encode(B4_ALTERNATE_CONTROL_ROOT)
        || metadata.proof.verifier_parameters != B4_ALTERNATE_VERIFIER_PARAMETERS_HEX
        || metadata.proof.outer_po2 != u32::from(RISC0_OUTER_PO2)
        || metadata.proof.raw_seal_words != PROOF_WORDS.to_string()
        || metadata.proof.raw_seal_bytes != PROOF_BYTES.to_string()
        || metadata.proof.claim_digest != hex::encode(bundle.claim_digest)
        || metadata.proof.journal_digest != journal_sha256
        || metadata.verification.receipt_bound
        || metadata.verification.verification_authority
            != "fixed-alternate-control-root-verifier-context"
        || !metadata.verification.explicit_local_prover
        || metadata.verification.dev_mode
        || metadata.verification.prove_guest_errors
        || metadata.verification.work_receipt_present
        || !metadata.verification.upstream_receipt_verify
        || metadata.verification.profile_owned_shape_verify
        || metadata.verification.receipt_oracle_is_consensus_encoding
    {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::BundleMetadata,
            "candidate proof or verification metadata differs from the fixed alternate witness",
        ));
    }
    if metadata.files.len() != METADATA_FILE_ROLES.len() {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::BundleMetadata,
            "candidate metadata has the wrong exact measured-file inventory",
        ));
    }
    for ((path, role), file) in METADATA_FILE_ROLES.iter().zip(&metadata.files) {
        let Some(entry) = manifest.iter().find(|entry| entry.path == *path) else {
            return Err(reject(
                B4AlternateRootAuthorityErrorKind::BundleMetadata,
                format!("manifest lacks metadata-bound file {path}"),
            ));
        };
        if file.path != *path
            || file.role != *role
            || file.length != entry.length
            || file.sha256 != entry.sha256
        {
            return Err(reject(
                B4AlternateRootAuthorityErrorKind::BundleMetadata,
                format!("metadata-bound file {path} differs from the measured manifest"),
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "negative-materialization-set")]
fn parse_canonical_u64(value: &str) -> Option<u64> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value != "0" && value.starts_with('0'))
    {
        return None;
    }
    value.parse().ok()
}

#[allow(
    clippy::too_many_lines,
    reason = "security-sensitive replay order is deliberately linear and independently falsifiable"
)]
#[cfg(feature = "negative-materialization-set")]
fn replay_cryptographic_bundle(
    request: &B4FixedAlternateRootProofRequestV1,
    bundle: &B4GeneratedAlternateRootProofBundleV1,
) -> Result<B4AlternateRootCryptographicReplayV1, B4AlternateRootAuthorityError> {
    if bundle.journal != request.statement {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::JournalBinding,
            "candidate journal differs from the authenticated request statement",
        ));
    }
    if bundle.image_id != request.image_id {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::ImageIdentity,
            "candidate image-ID artifact differs from the ELF-derived identity",
        ));
    }

    let independent =
        ok_receipt_claim_digests(&request.image_id, &request.statement).map_err(|error| {
            reject(
                B4AlternateRootAuthorityErrorKind::ClaimBinding,
                format!("independent successful-claim derivation failed: {error}"),
            )
        })?;
    if bundle.claim_digest != independent.expected_claim {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::ClaimBinding,
            "candidate claim artifact differs from the independently derived OK claim",
        ));
    }

    let expected_control_id = decode_digest_hex(RISC0_NORMAL_LIFT_CONTROL_IDS_HEX[0])?;
    if bundle.control_id != digest_bytes(&expected_control_id) {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::ControlBinding,
            "candidate control-ID artifact is not the fixed normal Lift15 control",
        ));
    }

    let receipt: Receipt = decode_exact(&bundle.receipt_oracle).map_err(|error| {
        reject(
            B4AlternateRootAuthorityErrorKind::ReceiptDecode,
            format!("outer Receipt oracle is not exact bincode: {error}"),
        )
    })?;
    if receipt.journal.bytes != request.statement {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::JournalBinding,
            "outer Receipt journal differs from the authenticated statement",
        ));
    }
    if receipt.metadata.verifier_parameters != receipt.inner.verifier_parameters() {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::ReceiptShape,
            "outer Receipt metadata parameters differ from its inner receipt",
        ));
    }
    let InnerReceipt::Succinct(succinct) = &receipt.inner else {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::ReceiptShape,
            "outer Receipt does not contain exactly one succinct receipt",
        ));
    };

    let image_id = Risc0Digest::from(request.image_id);
    let journal_digest = receipt.journal.digest();
    if digest_bytes(&journal_digest) != independent.journal_digest {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::JournalBinding,
            "Receipt journal digest differs from independent SHA-256",
        ));
    }
    let expected_claim = ReceiptClaim::ok(image_id, MaybePruned::Pruned(journal_digest));
    let expected_claim_digest = expected_claim.digest();
    if digest_bytes(&expected_claim_digest) != independent.expected_claim
        || receipt
            .claim()
            .map_err(|error| {
                reject(
                    B4AlternateRootAuthorityErrorKind::ClaimBinding,
                    format!("cannot resolve outer Receipt claim: {error}"),
                )
            })?
            .digest()
            != expected_claim_digest
        || succinct.claim.digest() != expected_claim_digest
    {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::ClaimBinding,
            "outer or inner receipt claim differs from the independently derived OK claim",
        ));
    }

    let stock = CompiledStockSuccinctReplayV1::from_compiled_profile().map_err(|error| {
        reject(
            B4AlternateRootAuthorityErrorKind::StockIsolation,
            format!("compiled stock verifier authority drifted: {error}"),
        )
    })?;
    let alternate = fixed_alternate_verifier()?;
    if succinct.hashfn != "poseidon2"
        || succinct.verifier_parameters != alternate.parameters_digest
        || succinct.control_id != expected_control_id
        || succinct.control_inclusion_proof.index != FIXED_LIFT_15_CONTROL_INDEX
        || succinct.control_inclusion_proof.digests.len() != CONTROL_INCLUSION_PROOF_DEPTH
        || succinct.seal.len() != PROOF_WORDS
        || succinct.seal.get(32).copied() != Some(u32::from(RISC0_OUTER_PO2))
    {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::ReceiptShape,
            "succinct receipt differs from the fixed alternate Lift15 shape",
        ));
    }
    if succinct.get_seal_bytes() != bundle.raw_seal {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::RawSealBinding,
            "raw-seal artifact differs from the exact succinct receipt seal",
        ));
    }

    receipt
        .verify_with_context(&alternate.context, image_id)
        .map_err(|error| {
            reject(
                B4AlternateRootAuthorityErrorKind::AlternateReceiptVerification,
                format!("fixed alternate verifier context rejected the receipt: {error}"),
            )
        })?;

    match receipt.verify_with_context(stock.context(), image_id) {
        Err(risc0_zkp::verify::VerificationError::VerifierParametersMismatch {
            expected,
            received,
        }) if expected == stock.parameters_digest()
            && digest_hex(&expected) == EXPECTED_STOCK_VERIFIER_PARAMETERS_HEX
            && received == alternate.parameters_digest => {}
        Ok(()) => {
            return Err(reject(
                B4AlternateRootAuthorityErrorKind::StockIsolation,
                "stock verifier context accepted the fixed alternate-root receipt",
            ));
        }
        Err(error) => {
            return Err(reject(
                B4AlternateRootAuthorityErrorKind::StockIsolation,
                format!("stock verifier rejected at the wrong boundary: {error:?}"),
            ));
        }
    }

    let stark = verify_fixed_alternate_root_stark(&bundle.raw_seal, independent.expected_claim)
        .map_err(|error| {
            reject(
                B4AlternateRootAuthorityErrorKind::DirectStarkReplay,
                format!("direct raw-STARK replay failed: {error}"),
            )
        })?;
    if !stark.terminal_is_lift
        || stark.terminal_parameter != 15
        || stark.terminal_control_id != bundle.control_id
        || stark.inner_control_root != B4_ALTERNATE_CONTROL_ROOT
        || stark.claim_digest != independent.expected_claim
    {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::TerminalBinding,
            "direct raw-STARK replay did not bind fixed Lift15/root/claim",
        ));
    }

    Ok(B4AlternateRootCryptographicReplayV1 {
        image_id: request.image_id,
        claim_digest: independent.expected_claim,
        control_id: bundle.control_id,
    })
}

#[cfg(feature = "negative-materialization-set")]
struct FixedAlternateVerifierV1 {
    context: VerifierContext,
    parameters_digest: Risc0Digest,
}

#[cfg(feature = "negative-materialization-set")]
fn fixed_alternate_verifier() -> Result<FixedAlternateVerifierV1, B4AlternateRootAuthorityError> {
    if ALLOWED_CONTROL_IDS.len() != 27 {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::AlternateReceiptVerification,
            "compiled stock control-ID count is not exactly 27",
        ));
    }
    let omitted = decode_digest_hex(B4_ALTERNATE_OMITTED_CONTROL_ID_HEX)?;
    let expected_control = decode_digest_hex(RISC0_NORMAL_LIFT_CONTROL_IDS_HEX[0])?;
    if ALLOWED_CONTROL_IDS.last() != Some(&omitted)
        || ALLOWED_CONTROL_IDS[FIXED_LIFT_15_CONTROL_INDEX as usize] != expected_control
    {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::AlternateReceiptVerification,
            "compiled stock controls differ from the fixed omission or Lift15 index",
        ));
    }

    let mut suites = VerifierContext::default_hash_suites();
    let poseidon2 = suites.remove("poseidon2").ok_or_else(|| {
        reject(
            B4AlternateRootAuthorityErrorKind::AlternateReceiptVerification,
            "compiled verifier has no Poseidon2 hash suite",
        )
    })?;
    let control_root = Risc0Digest::from(B4_ALTERNATE_CONTROL_ROOT);
    let parameters = SuccinctReceiptVerifierParameters {
        control_root,
        inner_control_root: None,
        ..Default::default()
    };
    let parameters_digest = parameters.digest();
    if digest_hex(&parameters_digest) != B4_ALTERNATE_VERIFIER_PARAMETERS_HEX {
        return Err(reject(
            B4AlternateRootAuthorityErrorKind::AlternateReceiptVerification,
            "computed alternate verifier-parameter digest differs from the frozen digest",
        ));
    }
    let context = VerifierContext::empty()
        .with_suites(BTreeMap::from([("poseidon2".to_owned(), poseidon2)]))
        .with_succinct_verifier_parameters(parameters)
        .with_dev_mode(false);
    Ok(FixedAlternateVerifierV1 {
        context,
        parameters_digest,
    })
}

#[cfg(feature = "negative-materialization-set")]
fn decode_digest_hex(value: &str) -> Result<Risc0Digest, B4AlternateRootAuthorityError> {
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|error| {
        reject(
            B4AlternateRootAuthorityErrorKind::ControlBinding,
            format!("compiled digest is not exact 32-byte lowercase hex: {error}"),
        )
    })?;
    Ok(Risc0Digest::from(bytes))
}

#[cfg(feature = "negative-materialization-set")]
fn digest_bytes(digest: &Risc0Digest) -> [u8; 32] {
    digest
        .as_bytes()
        .try_into()
        .expect("RISC Zero Digest is exactly 32 bytes")
}

#[cfg(feature = "negative-materialization-set")]
fn digest_hex(digest: &Risc0Digest) -> String {
    hex::encode(digest.as_bytes())
}

#[cfg(feature = "negative-materialization-set")]
fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(feature = "negative-materialization-set")]
fn reject(
    kind: B4AlternateRootAuthorityErrorKind,
    detail: impl Into<String>,
) -> B4AlternateRootAuthorityError {
    B4AlternateRootAuthorityError {
        kind,
        detail: detail.into(),
    }
}

#[cfg(all(test, feature = "negative-materialization-set"))]
pub(crate) fn authenticate_retained_alternate_root_kat()
-> Result<B4FixedAlternateRootProofAuthorityV1, B4AlternateRootAuthorityError> {
    let manifest = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../generator/testdata/alternate-root-lift-po2-15-v1/",
        "candidate-proof-export/candidate-proof-output-manifest.json"
    ));
    let claim = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../generator/testdata/alternate-root-lift-po2-15-v1/",
        "candidate-proof-export/proof-output/candidate-claim-digest.bin"
    ));
    let control = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../generator/testdata/alternate-root-lift-po2-15-v1/",
        "candidate-proof-export/proof-output/candidate-control-id.bin"
    ));
    let image = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../generator/testdata/alternate-root-lift-po2-15-v1/",
        "candidate-proof-export/proof-output/candidate-image-id.bin"
    ));
    let journal = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../generator/testdata/alternate-root-lift-po2-15-v1/",
        "candidate-proof-export/proof-output/candidate-journal.bin"
    ));
    let metadata = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../generator/testdata/alternate-root-lift-po2-15-v1/",
        "candidate-proof-export/proof-output/candidate-metadata.json"
    ));
    let raw_seal = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../generator/testdata/alternate-root-lift-po2-15-v1/",
        "candidate-proof-export/proof-output/candidate-raw-seal.bin"
    ));
    let receipt_oracle = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../generator/testdata/alternate-root-lift-po2-15-v1/",
        "candidate-proof-export/proof-output/candidate-receipt-oracle.bincode"
    ));
    let parsed_metadata = CandidateMetadataV1::from_canonical_jcs(metadata).map_err(|error| {
        reject(
            B4AlternateRootAuthorityErrorKind::BundleMetadata,
            format!("retained KAT metadata is invalid: {error}"),
        )
    })?;
    let guest_elf_sha256: [u8; 32] = hex::decode(&parsed_metadata.method.elf_sha256)
        .map_err(|error| {
            reject(
                B4AlternateRootAuthorityErrorKind::RequestIdentity,
                format!("retained KAT ELF digest is invalid: {error}"),
            )
        })?
        .try_into()
        .map_err(|_| {
            reject(
                B4AlternateRootAuthorityErrorKind::RequestIdentity,
                "retained KAT ELF digest is not exactly 32 bytes",
            )
        })?;
    let request = B4FixedAlternateRootProofRequestV1::from_retained_test_identity(
        journal,
        *image,
        parsed_metadata.method.elf_length.parse().map_err(|error| {
            reject(
                B4AlternateRootAuthorityErrorKind::RequestIdentity,
                format!("retained KAT ELF length is invalid: {error}"),
            )
        })?,
        guest_elf_sha256,
    );
    let bundle = B4GeneratedAlternateRootProofBundleV1::new(
        manifest.to_vec(),
        *claim,
        *control,
        *image,
        journal.to_vec(),
        metadata.to_vec(),
        raw_seal.to_vec(),
        receipt_oracle.to_vec(),
    );
    authenticate_fixed_alternate_root_bundle(&request, bundle)
}

/// Local diagnostic loader, not descriptor custody or campaign authority.
/// The existing authenticator owns all decoding and cryptographic decisions.
#[cfg(all(test, feature = "negative-materialization-set"))]
pub(crate) mod genuine_alternate_root {
    use super::*;
    use anyhow::{Context as _, Result, ensure};
    use std::{fs, io::Read as _, path::{Component, Path}};

    fn physical(path: &Path, directory: bool) -> Result<()> {
        ensure!(path.is_absolute() && !path.components().any(|c| matches!(c, Component::ParentDir)),
            "alternate input path is not absolute and normalized");
        for ancestor in path.ancestors() {
            let metadata = fs::symlink_metadata(ancestor)?;
            ensure!(!metadata.file_type().is_symlink(), "alternate input redirect");
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt as _;
                ensure!(metadata.file_attributes() & 0x400 == 0, "alternate input redirect");
            }
            ensure!(if ancestor == path && !directory { metadata.is_file() } else { metadata.is_dir() },
                "alternate input physical kind");
        }
        Ok(())
    }

    fn bounded(reader: &mut impl std::io::Read, min: usize, max: usize, size: u64) -> Result<Vec<u8>> {
        ensure!(size >= min as u64 && size <= max as u64, "alternate input bounds");
        let mut bytes = Vec::with_capacity(size as usize);
        reader.take(max as u64 + 1).read_to_end(&mut bytes)?;
        ensure!(bytes.len() as u64 == size, "alternate input length drift");
        Ok(bytes)
    }

    fn read(path: &Path, min: usize, max: usize) -> Result<Vec<u8>> {
        physical(path, false)?;
        let mut file = fs::File::open(path)?;
        let size = file.metadata()?.len();
        let bytes = bounded(&mut file, min, max, size);
        physical(path, false)?;
        bytes
    }

    fn inventory(root: &Path, expected: &[&str]) -> Result<()> {
        physical(root, true)?;
        let mut names = fs::read_dir(root)?.enumerate().map(|(index, entry)| {
            ensure!(index < expected.len(), "alternate export inventory differs");
            let entry = entry?;
            entry.file_name().into_string().map_err(|_| anyhow::anyhow!("alternate inventory name"))
        }).collect::<Result<Vec<_>>>()?;
        names.sort();
        let mut expected = expected.to_vec();
        expected.sort();
        ensure!(names == expected, "alternate export inventory differs");
        Ok(())
    }

    fn bundle(root: &Path) -> Result<B4GeneratedAlternateRootProofBundleV1> {
        inventory(root, &["candidate-proof-output-manifest.json", "proof-output"])?;
        let output = root.join("proof-output");
        inventory(&output, &EXPECTED_FILES)?;
        Ok(B4GeneratedAlternateRootProofBundleV1::new(
            read(&root.join("candidate-proof-output-manifest.json"), 2, MANIFEST_MAX_BYTES)?,
            read(&output.join(EXPECTED_FILES[0]), 32, 32)?.try_into().unwrap(),
            read(&output.join(EXPECTED_FILES[1]), 32, 32)?.try_into().unwrap(),
            read(&output.join(EXPECTED_FILES[2]), 32, 32)?.try_into().unwrap(),
            read(&output.join(EXPECTED_FILES[3]), 160, 160)?,
            read(&output.join(EXPECTED_FILES[4]), 1, CANDIDATE_METADATA_V1_MAX_BYTES)?,
            read(&output.join(EXPECTED_FILES[5]), PROOF_BYTES, PROOF_BYTES)?,
            read(&output.join(EXPECTED_FILES[6]), 1, RECEIPT_ORACLE_MAX_BYTES)?,
        ))
    }

    fn request(statement: &[u8], guest: &Path) -> Result<B4FixedAlternateRootProofRequestV1> {
        let bytes = read(guest, 129704, 129704)?;
        ensure!(sha256_hex(&bytes) == "88c72323c0831de4f7e4a234df65cf84e2723621fbed855c57f329a091f90542",
            "alternate guest fixture pin differs");
        B4FixedAlternateRootProofRequestV1::from_authenticated(statement, &bytes).map_err(Into::into)
    }

    pub(crate) fn load_authenticated(root: &Path, statement: &[u8], guest: &Path)
        -> Result<B4FixedAlternateRootProofAuthorityV1> {
        let request = request(statement, guest)?;
        authenticate_fixed_alternate_root_bundle(&request, bundle(root)?).map_err(Into::into)
    }

    /// Single-fault checks reuse the production layers; no replacement proof is generated.
    pub(crate) fn assert_single_faults(root: &Path, statement: &[u8], guest: &Path) -> Result<()> {
        let request = request(statement, guest)?;
        let mut wrong = statement.to_vec();
        wrong[159] ^= 1;
        let wrong_request = self::request(&wrong, guest)?;
        assert_eq!(authenticate_fixed_alternate_root_bundle(&wrong_request, bundle(root)?)
            .unwrap_err().kind(), B4AlternateRootAuthorityErrorKind::JournalBinding);
        wrong = statement.to_vec();
        wrong[91] ^= 1;
        assert_eq!(self::request(&wrong, guest).err().unwrap().downcast_ref::<B4AlternateRootAuthorityError>()
            .context("request error kind absent")?.kind(), B4AlternateRootAuthorityErrorKind::RequestIdentity);
        let guest_bytes = read(guest, 129704, 129704)?;
        assert_eq!(B4FixedAlternateRootProofRequestV1::from_authenticated(statement, &guest_bytes[..16])
            .err().unwrap().kind(), B4AlternateRootAuthorityErrorKind::RequestIdentity);
        for role in 0..4 {
            let mut changed = bundle(root)?;
            match role {
                0 => changed.manifest_jcs[0] ^= 1,
                1 => changed.metadata_jcs[0] ^= 1,
                2 => changed.raw_seal[0] ^= 1,
                _ => changed.receipt_oracle[0] ^= 1,
            }
            assert_eq!(authenticate_fixed_alternate_root_bundle(&request, changed).unwrap_err().kind(),
                B4AlternateRootAuthorityErrorKind::BundleManifest);
        }
        let mut changed = bundle(root)?;
        changed.metadata_jcs = b"{}".to_vec();
        let mut manifest: ProofOutputManifest = serde_json::from_slice(&changed.manifest_jcs)?;
        let entry = manifest.iter_mut().find(|e| e.path == "candidate-metadata.json").unwrap();
        entry.length = changed.metadata_jcs.len().to_string();
        entry.sha256 = sha256_hex(&changed.metadata_jcs);
        changed.manifest_jcs = crate::canonical::canonical_json_bytes(&serde_json::to_value(manifest)?)?;
        assert_eq!(authenticate_fixed_alternate_root_bundle(&request, changed).unwrap_err().kind(),
            B4AlternateRootAuthorityErrorKind::BundleMetadata);
        let mut changed = bundle(root)?;
        changed.receipt_oracle.clear();
        assert_eq!(replay_cryptographic_bundle(&request, &changed).err().unwrap().kind(),
            B4AlternateRootAuthorityErrorKind::ReceiptDecode);
        let mut changed = bundle(root)?;
        changed.raw_seal[0] ^= 1;
        assert_eq!(replay_cryptographic_bundle(&request, &changed).err().unwrap().kind(),
            B4AlternateRootAuthorityErrorKind::RawSealBinding);
        Ok(())
    }

    #[test]
    fn alternate_reader_bounds_and_growth_are_closed() {
        let mut input = std::io::Cursor::new(b"abc");
        assert_eq!(bounded(&mut input, 3, 3, 3).unwrap(), b"abc");
        assert_eq!(bounded(&mut input, 3, 3, 4).unwrap_err().to_string(), "alternate input bounds");
        let mut growing = std::io::Cursor::new([0; 10]);
        assert_eq!(bounded(&mut growing, 3, 3, 3).unwrap_err().to_string(), "alternate input length drift");
        assert_eq!(growing.position(), 4);
        assert_eq!(physical(Path::new("relative/../input"), false).unwrap_err().to_string(),
            "alternate input path is not absolute and normalized");
    }

    #[test]
    fn alternate_loader_inventory_is_exact() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("proof-output")).unwrap();
        fs::write(root.path().join("candidate-proof-output-manifest.json"), b"[]").unwrap();
        inventory(root.path(), &["proof-output", "candidate-proof-output-manifest.json"]).unwrap();
        fs::write(root.path().join("extra"), b"").unwrap();
        assert_eq!(bundle(root.path()).err().unwrap().to_string(), "alternate export inventory differs");
    }

    #[cfg(unix)]
    #[test]
    fn alternate_reader_rejects_leaf_and_parent_redirects() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("physical");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("file"), b"abc").unwrap();
        assert_eq!(read(&dir.join("file"), 3, 3).unwrap(), b"abc");
        std::os::unix::fs::symlink(dir.join("file"), root.path().join("leaf")).unwrap();
        std::os::unix::fs::symlink(&dir, root.path().join("parent")).unwrap();
        for path in [root.path().join("leaf"), root.path().join("parent/file")] {
            assert_eq!(read(&path, 3, 3).unwrap_err().to_string(), "alternate input redirect");
        }
    }
}

#[cfg(all(test, feature = "negative-materialization-set"))]
mod tests {
    use bincode::Options as _;

    use crate::{
        candidate_metadata::CandidateMetadataV1,
        receipt_oracle_codec::receipt_oracle_bincode_options,
    };

    use super::*;

    const FIXTURE_ROOT: &str =
        "../generator/testdata/alternate-root-lift-po2-15-v1/candidate-proof-export";

    fn fixture_bytes(name: &str) -> &'static [u8] {
        match name {
            "manifest" => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../generator/testdata/alternate-root-lift-po2-15-v1/",
                "candidate-proof-export/candidate-proof-output-manifest.json"
            )),
            "claim" => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../generator/testdata/alternate-root-lift-po2-15-v1/",
                "candidate-proof-export/proof-output/candidate-claim-digest.bin"
            )),
            "control" => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../generator/testdata/alternate-root-lift-po2-15-v1/",
                "candidate-proof-export/proof-output/candidate-control-id.bin"
            )),
            "image" => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../generator/testdata/alternate-root-lift-po2-15-v1/",
                "candidate-proof-export/proof-output/candidate-image-id.bin"
            )),
            "journal" => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../generator/testdata/alternate-root-lift-po2-15-v1/",
                "candidate-proof-export/proof-output/candidate-journal.bin"
            )),
            "metadata" => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../generator/testdata/alternate-root-lift-po2-15-v1/",
                "candidate-proof-export/proof-output/candidate-metadata.json"
            )),
            "raw" => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../generator/testdata/alternate-root-lift-po2-15-v1/",
                "candidate-proof-export/proof-output/candidate-raw-seal.bin"
            )),
            "receipt" => include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../generator/testdata/alternate-root-lift-po2-15-v1/",
                "candidate-proof-export/proof-output/candidate-receipt-oracle.bincode"
            )),
            _ => panic!("unknown fixture"),
        }
    }

    fn fixture_request() -> B4FixedAlternateRootProofRequestV1 {
        let metadata = CandidateMetadataV1::from_canonical_jcs(fixture_bytes("metadata")).unwrap();
        B4FixedAlternateRootProofRequestV1::from_retained_test_identity(
            fixture_bytes("journal"),
            fixture_bytes("image").try_into().unwrap(),
            metadata.method.elf_length.parse().unwrap(),
            hex::decode(metadata.method.elf_sha256)
                .unwrap()
                .try_into()
                .unwrap(),
        )
    }

    fn fixture_bundle() -> B4GeneratedAlternateRootProofBundleV1 {
        B4GeneratedAlternateRootProofBundleV1::new(
            fixture_bytes("manifest").to_vec(),
            fixture_bytes("claim").try_into().unwrap(),
            fixture_bytes("control").try_into().unwrap(),
            fixture_bytes("image").try_into().unwrap(),
            fixture_bytes("journal").to_vec(),
            fixture_bytes("metadata").to_vec(),
            fixture_bytes("raw").to_vec(),
            fixture_bytes("receipt").to_vec(),
        )
    }

    fn fixture_bundle_with_metadata(
        metadata_jcs: Vec<u8>,
    ) -> B4GeneratedAlternateRootProofBundleV1 {
        let mut bundle = fixture_bundle();
        let mut manifest: ProofOutputManifest =
            serde_json::from_slice(&bundle.manifest_jcs).unwrap();
        let entry = manifest
            .iter_mut()
            .find(|entry| entry.path == "candidate-metadata.json")
            .unwrap();
        entry.length = metadata_jcs.len().to_string();
        entry.sha256 = sha256_hex(&metadata_jcs);
        bundle.manifest_jcs =
            crate::canonical::canonical_json_bytes(&serde_json::to_value(&manifest).unwrap())
                .unwrap();
        bundle.metadata_jcs = metadata_jcs;
        bundle
    }

    #[test]
    fn request_derives_the_program_identity_from_the_authenticated_guest_elf() {
        let (guest_elf, program_id) = crate::test_support::valid_program_fixture();
        let statement = crate::ergo_statement::ErgoStatementV1::new(
            [0x11; 32],
            [0x22; 32],
            program_id,
            [0x33; 32],
            b"alternate-root request",
        )
        .unwrap()
        .encode()
        .unwrap();
        let request =
            B4FixedAlternateRootProofRequestV1::from_authenticated(&statement, &guest_elf).unwrap();
        assert_eq!(request.statement(), statement);

        let wrong_program = crate::ergo_statement::ErgoStatementV1::new(
            [0x11; 32],
            [0x22; 32],
            [0x44; 32],
            [0x33; 32],
            b"alternate-root request",
        )
        .unwrap()
        .encode()
        .unwrap();
        assert_eq!(
            B4FixedAlternateRootProofRequestV1::from_authenticated(&wrong_program, &guest_elf)
                .err()
                .unwrap()
                .kind(),
            B4AlternateRootAuthorityErrorKind::RequestIdentity
        );
        assert_eq!(
            B4FixedAlternateRootProofRequestV1::from_authenticated(b"not-a-statement", &guest_elf)
                .err()
                .unwrap()
                .kind(),
            B4AlternateRootAuthorityErrorKind::RequestStatement
        );
    }

    #[test]
    fn retained_bundle_mints_authority_only_after_both_cryptographic_replays() {
        let authority = authenticate_retained_alternate_root_kat().unwrap();

        assert_eq!(authority.journal(), fixture_bytes("journal"));
        assert_eq!(authority.raw_seal(), fixture_bytes("raw"));
        assert_eq!(authority.receipt_oracle(), fixture_bytes("receipt"));
        assert_eq!(authority.image_id(), fixture_bytes("image"));
        assert_eq!(authority.claim_digest(), fixture_bytes("claim"));
        assert_eq!(authority.control_id(), fixture_bytes("control"));
    }

    #[test]
    fn manifest_identity_rejects_a_single_artifact_drift_before_replay() {
        let request = fixture_request();
        let mut bundle = fixture_bundle();
        bundle.raw_seal[PROOF_BYTES - 1] ^= 1;

        let error = authenticate_fixed_alternate_root_bundle(&request, bundle).unwrap_err();
        assert_eq!(
            error.kind(),
            B4AlternateRootAuthorityErrorKind::BundleManifest
        );
        assert!(error.detail().contains("candidate-raw-seal.bin"));
    }

    #[test]
    fn refreshed_custody_and_metadata_alone_cannot_mint_authority() {
        let request = fixture_request();
        let mut metadata =
            CandidateMetadataV1::from_canonical_jcs(fixture_bytes("metadata")).unwrap();
        metadata.verification.upstream_receipt_verify = false;
        let metadata_jcs = metadata.to_canonical_jcs().unwrap();
        let bundle = fixture_bundle_with_metadata(metadata_jcs);

        validate_bundle_manifest(&bundle).unwrap();
        let error = authenticate_fixed_alternate_root_bundle(&request, bundle).unwrap_err();
        assert_eq!(
            error.kind(),
            B4AlternateRootAuthorityErrorKind::BundleMetadata
        );
        assert!(error.detail().contains("proof or verification metadata"));
    }

    #[test]
    fn journal_image_claim_control_and_raw_seal_drifts_are_causally_distinct() {
        let request = fixture_request();

        let mut journal = fixture_bundle();
        journal.journal[0] ^= 1;
        assert_eq!(
            replay_cryptographic_bundle(&request, &journal)
                .unwrap_err()
                .kind(),
            B4AlternateRootAuthorityErrorKind::JournalBinding
        );

        let mut image = fixture_bundle();
        image.image_id[0] ^= 1;
        assert_eq!(
            replay_cryptographic_bundle(&request, &image)
                .unwrap_err()
                .kind(),
            B4AlternateRootAuthorityErrorKind::ImageIdentity
        );

        let mut claim = fixture_bundle();
        claim.claim_digest[0] ^= 1;
        assert_eq!(
            replay_cryptographic_bundle(&request, &claim)
                .unwrap_err()
                .kind(),
            B4AlternateRootAuthorityErrorKind::ClaimBinding
        );

        let mut control = fixture_bundle();
        control.control_id[0] ^= 1;
        assert_eq!(
            replay_cryptographic_bundle(&request, &control)
                .unwrap_err()
                .kind(),
            B4AlternateRootAuthorityErrorKind::ControlBinding
        );

        let mut raw = fixture_bundle();
        raw.raw_seal[0] ^= 1;
        assert_eq!(
            replay_cryptographic_bundle(&request, &raw)
                .unwrap_err()
                .kind(),
            B4AlternateRootAuthorityErrorKind::RawSealBinding
        );
    }

    #[test]
    fn outer_receipt_requires_exact_decode_and_exact_statement_binding() {
        let request = fixture_request();
        let mut trailing = fixture_bundle();
        trailing.receipt_oracle.push(0);
        assert_eq!(
            replay_cryptographic_bundle(&request, &trailing)
                .unwrap_err()
                .kind(),
            B4AlternateRootAuthorityErrorKind::ReceiptDecode
        );

        let mut wrong_journal = fixture_bundle();
        let mut receipt: Receipt = receipt_oracle_bincode_options()
            .deserialize(&wrong_journal.receipt_oracle)
            .unwrap();
        receipt.journal.bytes[0] ^= 1;
        wrong_journal.receipt_oracle = receipt_oracle_bincode_options()
            .serialize(&receipt)
            .unwrap();
        assert_eq!(
            replay_cryptographic_bundle(&request, &wrong_journal)
                .unwrap_err()
                .kind(),
            B4AlternateRootAuthorityErrorKind::JournalBinding
        );
    }

    #[test]
    fn fixed_verifier_has_no_runtime_selector_and_is_distinct_from_stock() {
        let alternate = fixed_alternate_verifier().unwrap();
        let stock = CompiledStockSuccinctReplayV1::from_compiled_profile().unwrap();

        assert!(!alternate.context.dev_mode());
        assert_eq!(alternate.context.suites.len(), 1);
        assert!(alternate.context.suites.contains_key("poseidon2"));
        assert_ne!(alternate.parameters_digest, stock.parameters_digest());
        assert_eq!(
            digest_hex(&alternate.parameters_digest),
            B4_ALTERNATE_VERIFIER_PARAMETERS_HEX
        );
        assert!(FIXTURE_ROOT.contains("alternate-root"));
    }
}
