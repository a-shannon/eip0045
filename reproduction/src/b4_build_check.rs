//! Strict post-publication validation for the hermetic B4 build evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use risc0_binfmt::compute_image_id;
use sha2::{Digest, Sha256};

use crate::canonical::{parse_json_strict, validate_canonical_json_source};
use crate::cargo_closure::{
    CargoClosureEvidence, CargoClosureRole, ProfileRootIdentity, validate_cargo_closure,
};
use crate::constants::{DIGEST_BYTES, MAX_STATEMENT_BYTES};
use crate::profile::{contract_id, ergo_statement_v1};
use crate::source_lock::{CandidateSourceLock, MaterializedFileEntry};

const COMPLETE_FILE: &str = "B4-COMPLETE";
const MANIFEST_FILE: &str = "evidence-manifest.txt";
const RUN_IDENTITY_FILE: &str = "run-evidence-identity.txt";
const COMPLETION_SCHEMA: &str = "eip0045-b4-build-completion-v2";
const INPUT_ISOLATION: &str =
    "path-disjoint-standalone-clean-checkouts-private-object-stores-and-seeds";
const EXECUTION_ISOLATION: &str = "fresh-home-target-and-work-per-run-same-pinned-runtime";
const RUNTIME_MANIFEST: &str =
    "sha256:1aa2ca80b59886af9ab34cf9775a567a80aacb03c0c29176c9120e1f34fcd855";
const MAX_MARKER_BYTES: u64 = 2 * 1024;
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 240;
const MAX_TREE_NODES: usize = 105;
const MAX_SEMANTIC_TEXT_BYTES: u64 = 8 * 1024;
const MAX_IDENTITY_BYTES: u64 = 16 * 1024;
const MAX_PROVENANCE_JSON_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SOURCE_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;
const MAX_PROPOSITION_BYTES: u64 = 64 * 1024;
const MAX_GUEST_ELF_BYTES: u64 = 4 * 1024 * 1024;
const PROFILE_ROOT: &str = "/workspace";
const PROFILE_ROOT_IDENTITY: &str = "eip-0045-profile";
const EVIDENCE_ROOT_DOMAIN: &[u8] = b"EIP0045-B4-EVIDENCE-ROOT-V1\0";
const CHAIN_DOMAIN_ID_HEX: &str =
    "b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b";
const PROFILE_ID_HEX: &str = "23c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383";
const PROFILE_MANIFEST_SHA256: &str =
    "d971285a9902b12741775302346c0960545264fcdea00bd8d3f8badca907a05b";
const PROOF_GENERATION_TESTS: &str = "schema=eip0045-proof-generation-tests-v2\nstatus=passed\nprofile=release\ndefaultFeatures=disabled\nfeatures=proof-generation\nembeddedMethodFeatures=embedded-method\nembeddedMethodExactTest=recursive::tests::pinned_guest_explicit_root_twice_proves_duplicate_heads_and_lift\nnetwork=offline\n";
const REFERENCE_TREE_PREFIX: [u8; 5] = [0x1c, 0x53, 0x02, 0x0e, 0x20];
const REFERENCE_SECOND_CONSTANT_PREFIX: [u8; 2] = [0x0e, 0x20];
const REFERENCE_TREE_EXPRESSION: [u8; 14] = [
    0xd1, 0xb9, 0xe4, 0xe3, 0x00, 0x1a, 0xe4, 0xe3, 0x01, 0x0e, 0x73, 0x00, 0x73, 0x01,
];

const ROOT_EVIDENCE_FILES: [&str; 3] = [
    "base-images-inspect.txt",
    RUN_IDENTITY_FILE,
    "runtime-image-inspect.txt",
];

const EXPECTED_DIRECTORIES: [&str; 4] = ["run-1", "run-1/statement", "run-2", "run-2/statement"];

const ROOT_OPAQUE_HASH_BOUND_FILES: [&str; 2] =
    ["base-images-inspect.txt", "runtime-image-inspect.txt"];

const RUN_OPAQUE_HASH_BOUND_FILES: [&str; 5] = [
    "build-environment.txt",
    "candidate-generator",
    "guest-toolchain-observed.txt",
    "host-toolchain-observed.txt",
    "resource-policy-observed.txt",
];

const RUN_EVIDENCE_FILES: [&str; 48] = [
    "alternate-program-guest.elf",
    "alternate-program-image-id-declaration.txt",
    "alternate-program-image-id.bin",
    "alternate-program-image-id.hex",
    "build-environment.txt",
    "build-policy.txt",
    "candidate-generator",
    "candidate-source-lock-first.json",
    "candidate-source-lock-second.json",
    "candidate-source-lock.json",
    "cargo-closure-generator-host.json",
    "cargo-closure-guest.json",
    "cargo-closure-methods-build.json",
    "cargo-metadata-generator-host.json",
    "cargo-metadata-guest.json",
    "cargo-metadata-methods-build.json",
    "guest-toolchain-observed.txt",
    "guest.elf",
    "host-toolchain-observed.txt",
    "identity.txt",
    "image-id-declaration.txt",
    "image-id.bin",
    "image-id.hex",
    "proof-generation-tests.txt",
    "reproduction-invariants.txt",
    "resource-policy-observed.txt",
    "source-checkout-admin-manifest-after.txt",
    "source-checkout-admin-manifest-before.txt",
    "source-checkout-admin-manifest.txt",
    "source-git-observed.txt",
    "source-materialized-manifest-after.txt",
    "source-materialized-manifest-before.txt",
    "source-materialized-manifest.txt",
    "statement/application-payload.bin",
    "statement/candidate-contract-id.bin",
    "statement/candidate-program-id.bin",
    "statement/candidate-proposition.bin",
    "statement/candidate-statement-transcript.txt",
    "statement/candidate-statement.bin",
    "statement/chain-domain-id.bin",
    "statement/inputs.txt",
    "statement/profile-id.bin",
    "workspace-git-after.txt",
    "workspace-git-before.txt",
    "workspace-git.txt",
    "workspace-source-manifest-after.txt",
    "workspace-source-manifest-before.txt",
    "workspace-source-manifest.txt",
];

#[derive(Clone, Debug, PartialEq, Eq)]
struct EvidenceEntry {
    path: String,
    sha256: String,
    size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompletionMarker {
    manifest_hash: String,
    guest_elf_sha256: String,
    image_id_digest: String,
    alternate_program_guest_elf_sha256: String,
    alternate_program_image_id_digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PhysicalFileIdentity {
    device: u64,
    inode: u64,
    links: u64,
}

#[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DescriptorObjectState {
    device: u64,
    inode: u64,
    mount_id: u64,
    byte_length: u64,
    links: u64,
    mode: u32,
    owner: u64,
    group: u64,
    modified_seconds: i64,
    modified_nanoseconds: u64,
    changed_seconds: i64,
    changed_nanoseconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TreeSnapshot {
    directories: Vec<String>,
    files: Vec<EvidenceEntry>,
    physical_files: BTreeMap<String, PhysicalFileIdentity>,
    #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
    descriptor_directories: BTreeMap<String, DescriptorObjectState>,
    #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
    descriptor_files: BTreeMap<String, DescriptorObjectState>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileBinding {
    size: u64,
    sha256: String,
    physical: Option<PhysicalFileIdentity>,
    #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
    descriptor_state: Option<DescriptorObjectState>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CapturedFile {
    bytes: Vec<u8>,
    binding: FileBinding,
}

#[derive(Clone, Copy)]
enum ValidationRoot<'a> {
    #[allow(dead_code)]
    Path(&'a Path),
    #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
    Descriptor(&'a descriptor_build_check_linux::DescriptorBuildCustody),
}

impl ValidationRoot<'_> {
    fn validate(self) -> Result<()> {
        match self {
            Self::Path(root) => require_ordinary_directory(root, "published B4 root"),
            #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
            Self::Descriptor(root) => root.reauthenticate_directories(),
        }
    }

    fn capture_file(self, relative: &str, max: u64, label: &str) -> Result<CapturedFile> {
        match self {
            Self::Path(root) => capture_file(&root.join(relative), max, label),
            #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
            Self::Descriptor(root) => {
                descriptor_build_check_linux::capture_file(root, relative, None, max, label)
            }
        }
    }

    fn reread_file(
        self,
        relative: &str,
        binding: &FileBinding,
        max: u64,
        label: &str,
    ) -> Result<Vec<u8>> {
        match self {
            Self::Path(root) => reread_captured_file(&root.join(relative), binding, max, label),
            #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
            Self::Descriptor(root) => Ok(descriptor_build_check_linux::capture_file(
                root,
                relative,
                Some(binding),
                max,
                label,
            )?
            .bytes),
        }
    }

    fn capture_tree(self) -> Result<TreeSnapshot> {
        match self {
            Self::Path(root) => capture_tree(root),
            #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
            Self::Descriptor(root) => descriptor_build_check_linux::capture_tree(root),
        }
    }
}

struct CapturedArchive<'a> {
    root: ValidationRoot<'a>,
    files: &'a [EvidenceEntry],
    entries: BTreeMap<&'a str, &'a EvidenceEntry>,
    physical_files: &'a BTreeMap<String, PhysicalFileIdentity>,
    #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
    descriptor_files: &'a BTreeMap<String, DescriptorObjectState>,
}

impl<'a> CapturedArchive<'a> {
    #[cfg(test)]
    fn new(root: &'a Path, snapshot: &'a TreeSnapshot) -> Self {
        Self::from_root(ValidationRoot::Path(root), snapshot)
    }

    fn from_root(root: ValidationRoot<'a>, snapshot: &'a TreeSnapshot) -> Self {
        Self {
            root,
            files: &snapshot.files,
            entries: entry_map(&snapshot.files),
            physical_files: &snapshot.physical_files,
            #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
            descriptor_files: &snapshot.descriptor_files,
        }
    }

    fn entry(&self, path: &str) -> Result<&'a EvidenceEntry> {
        require_entry(&self.entries, path)
    }

    fn read(&self, path: &str, max: u64, label: &str) -> Result<Vec<u8>> {
        let entry = self.entry(path)?;
        let physical = self.physical_files.get(path);
        match self.root {
            ValidationRoot::Path(root) => {
                read_captured_entry(&root.join(path), entry, physical, max, label)
            }
            #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
            ValidationRoot::Descriptor(root) => descriptor_build_check_linux::read_captured_entry(
                root,
                path,
                entry,
                self.descriptor_files.get(path),
                max,
                label,
            ),
        }
    }

    fn read_digest(&self, path: &str, label: &str) -> Result<[u8; DIGEST_BYTES]> {
        let bytes = self.read(path, u64::try_from(DIGEST_BYTES)?, label)?;
        bytes.try_into().map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!("{label} has {} bytes, expected {DIGEST_BYTES}", bytes.len())
        })
    }
}

/// Caller-supplied expectations which are deliberately outside the archive.
///
/// The source commit and tree must be supplied together. An expected evidence
/// root additionally requires that source pair, so an archive cannot promote
/// its own mutable declarations into an external anchor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct B4BuildExpectations<'a> {
    /// Expected commit of the clean profile workspace used by both runs.
    pub expected_source_commit: Option<&'a str>,
    /// Expected root tree of the clean profile workspace used by both runs.
    pub expected_source_tree: Option<&'a str>,
    /// Optional externally retained evidence-root commitment.
    pub expected_evidence_root: Option<&'a str>,
}

/// Whether the archive's workspace identity was compared with external input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum B4SourceBindingStatus {
    /// No expected workspace commit/tree was supplied by the caller.
    Unbound,
    /// Both archived runs match the externally supplied commit and tree.
    Matched,
}

/// Execution-history claims which a final archive cannot authenticate alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum B4RunnerClaimStatus {
    /// Freshness, path isolation, command execution, and atomic history remain
    /// runner observations even when their archived records are coherent.
    Unattested,
}

/// Strength of the physical-file checks available to this validation run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum B4FilesystemBindingStatus {
    /// Every opened file was tied to one Unix device/inode with link count one.
    UnixFileIdentityBound,
    /// Windows inspection checked bytes but cannot use unstable standard-library
    /// file-ID/link-count APIs; authoritative mode is therefore rejected.
    UnavailableForInspection,
}

/// What the checker established for an artifact whose payload it does not parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum B4ArtifactEvidenceStatus {
    /// Exact path, size, and SHA-256 are bound; payload claims are not interpreted.
    OpaqueHashBound,
}

/// Per-artifact disclosure for evidence which remains opaque to this checker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B4ArtifactEvidence {
    /// Canonical archive-relative path.
    pub path: String,
    /// Exact captured byte length.
    pub size: u64,
    /// Exact captured lowercase SHA-256.
    pub sha256: String,
    /// Semantic coverage classification.
    pub status: B4ArtifactEvidenceStatus,
}

/// Scoped result of strict B4 archive validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B4BuildValidation {
    /// Domain-separated commitment over the completion marker and manifest.
    pub computed_evidence_root: String,
    /// `Some(true)` only when a caller-provided digest matched. A mismatch is
    /// an error; `None` means explicit unanchored inspection.
    pub provided_digest_matched: Option<bool>,
    /// External workspace-source comparison state.
    pub source_binding: B4SourceBindingStatus,
    /// Physical-file binding strength used during this run.
    pub filesystem_binding: B4FilesystemBindingStatus,
    /// Honest classification of non-archive-verifiable runner claims.
    pub runner_claims: B4RunnerClaimStatus,
    /// Exact hash-bound artifacts whose payload semantics were not validated.
    pub opaque_artifacts: Vec<B4ArtifactEvidence>,
    authoritative_projection: Option<AuthoritativeB4BuildProjection>,
}

impl B4BuildValidation {
    /// Return the immutable downstream projection only when validation used all
    /// caller-owned external anchors and Unix physical-file identity binding.
    ///
    /// Unanchored inspection deliberately returns `None`. The projection has no
    /// public constructor, so safe callers cannot promote self-declared values
    /// into authoritative B4 input-set anchors.
    #[must_use]
    pub const fn authoritative_projection(&self) -> Option<&AuthoritativeB4BuildProjection> {
        self.authoritative_projection.as_ref()
    }
}

/// Immutable identities established by authoritative B4 build validation.
///
/// Every value is derived from the validated archive or from the three
/// caller-owned external anchors which the archive matched. Fields are private
/// and there is intentionally no public constructor.
///
/// This positive-build projection intentionally remains consumer-only. E3
/// negative ancestry binds its private consumer/alternate embedded pair
/// directly and does not broaden this projection's downstream authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthoritativeB4BuildProjection {
    evidence_root_sha256: String,
    source_commit: String,
    source_tree: String,
    source_lock_sha256: String,
    generator_cargo_closure_sha256: String,
    proof_generation_tests_sha256: String,
    generator_artifact_sha256: String,
    generator_artifact_byte_length: u64,
    guest_elf_sha256: String,
    guest_elf_byte_length: u64,
    image_id_hex: String,
    statement_sha256: String,
    statement_byte_length: u64,
    contract_id_hex: String,
    chain_domain_id_hex: String,
    application_payload_sha256: String,
    application_payload_byte_length: u64,
}

impl AuthoritativeB4BuildProjection {
    /// Domain-separated evidence-root commitment matched against external input.
    #[must_use]
    pub fn evidence_root_sha256(&self) -> &str {
        &self.evidence_root_sha256
    }

    /// Externally anchored source commit matched by both archived runs.
    #[must_use]
    pub fn source_commit(&self) -> &str {
        &self.source_commit
    }

    /// Externally anchored source tree matched by both archived runs.
    #[must_use]
    pub fn source_tree(&self) -> &str {
        &self.source_tree
    }

    /// SHA-256 of the validated candidate source-lock document.
    #[must_use]
    pub fn source_lock_sha256(&self) -> &str {
        &self.source_lock_sha256
    }

    /// SHA-256 of the validated proof-generator Cargo closure.
    #[must_use]
    pub fn generator_cargo_closure_sha256(&self) -> &str {
        &self.generator_cargo_closure_sha256
    }

    /// SHA-256 of the exact successful proof-generation test marker.
    #[must_use]
    pub fn proof_generation_tests_sha256(&self) -> &str {
        &self.proof_generation_tests_sha256
    }

    /// SHA-256 of the byte-identical proof-generator artifact.
    #[must_use]
    pub fn generator_artifact_sha256(&self) -> &str {
        &self.generator_artifact_sha256
    }

    /// Byte length of the byte-identical proof-generator artifact.
    #[must_use]
    pub const fn generator_artifact_byte_length(&self) -> u64 {
        self.generator_artifact_byte_length
    }

    /// SHA-256 of the byte-identical approved guest ELF.
    #[must_use]
    pub fn guest_elf_sha256(&self) -> &str {
        &self.guest_elf_sha256
    }

    /// Byte length of the byte-identical approved guest ELF.
    #[must_use]
    pub const fn guest_elf_byte_length(&self) -> u64 {
        self.guest_elf_byte_length
    }

    /// Canonical image-ID hex recomputed from the approved guest ELF.
    #[must_use]
    pub fn image_id_hex(&self) -> &str {
        &self.image_id_hex
    }

    /// SHA-256 of the exact approved `ErgoStatementV1` bytes.
    #[must_use]
    pub fn statement_sha256(&self) -> &str {
        &self.statement_sha256
    }

    /// Byte length of the exact approved `ErgoStatementV1` bytes.
    #[must_use]
    pub const fn statement_byte_length(&self) -> u64 {
        self.statement_byte_length
    }

    /// Contract ID derived from the approved reference proposition.
    #[must_use]
    pub fn contract_id_hex(&self) -> &str {
        &self.contract_id_hex
    }

    /// Exact chain-domain ID embedded in the approved statement.
    #[must_use]
    pub fn chain_domain_id_hex(&self) -> &str {
        &self.chain_domain_id_hex
    }

    /// SHA-256 commitment of the approved application payload.
    #[must_use]
    pub fn application_payload_sha256(&self) -> &str {
        &self.application_payload_sha256
    }

    /// Byte length of the approved application payload.
    #[must_use]
    pub const fn application_payload_byte_length(&self) -> u64 {
        self.application_payload_byte_length
    }
}

#[cfg(test)]
#[allow(missing_docs)]
pub(crate) struct TestAuthoritativeB4BuildProjection {
    pub evidence_root_sha256: String,
    pub source_commit: String,
    pub source_tree: String,
    pub source_lock_sha256: String,
    pub generator_cargo_closure_sha256: String,
    pub proof_generation_tests_sha256: String,
    pub generator_artifact_sha256: String,
    pub generator_artifact_byte_length: u64,
    pub guest_elf_sha256: String,
    pub guest_elf_byte_length: u64,
    pub image_id_hex: String,
    pub statement_sha256: String,
    pub statement_byte_length: u64,
    pub contract_id_hex: String,
    pub chain_domain_id_hex: String,
    pub application_payload_sha256: String,
    pub application_payload_byte_length: u64,
}

#[cfg(test)]
impl AuthoritativeB4BuildProjection {
    #[allow(missing_docs)]
    pub(crate) fn for_test(values: TestAuthoritativeB4BuildProjection) -> Self {
        Self {
            evidence_root_sha256: values.evidence_root_sha256,
            source_commit: values.source_commit,
            source_tree: values.source_tree,
            source_lock_sha256: values.source_lock_sha256,
            generator_cargo_closure_sha256: values.generator_cargo_closure_sha256,
            proof_generation_tests_sha256: values.proof_generation_tests_sha256,
            generator_artifact_sha256: values.generator_artifact_sha256,
            generator_artifact_byte_length: values.generator_artifact_byte_length,
            guest_elf_sha256: values.guest_elf_sha256,
            guest_elf_byte_length: values.guest_elf_byte_length,
            image_id_hex: values.image_id_hex,
            statement_sha256: values.statement_sha256,
            statement_byte_length: values.statement_byte_length,
            contract_id_hex: values.contract_id_hex,
            chain_domain_id_hex: values.chain_domain_id_hex,
            application_payload_sha256: values.application_payload_sha256,
            application_payload_byte_length: values.application_payload_byte_length,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ValidatedDownstreamIdentity {
    image_id: [u8; DIGEST_BYTES],
    contract_id: [u8; DIGEST_BYTES],
    chain_domain_id: [u8; DIGEST_BYTES],
    application_payload_sha256: [u8; DIGEST_BYTES],
    application_payload_byte_length: u64,
    statement_sha256: String,
    statement_byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WorkspaceSourceIdentity {
    commit: String,
    tree: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExternalAnchors<'a> {
    commit: &'a str,
    tree: &'a str,
    evidence_root: &'a str,
}

/// Validate one closed B4 build-evidence archive without external bindings.
///
/// The marker, manifest, root files, two run directories, and every run
/// artifact have an exact closed shape. Traversal never follows links or
/// reparse points and repeated snapshots detect concurrent mutation. The
/// returned result remains explicitly unanchored and runner claims remain
/// unattested.
///
/// # Errors
///
/// Returns the first root, marker, manifest, path, file, digest,
/// run-agreement, or stability mismatch.
pub fn validate_published_b4_build(root: impl AsRef<Path>) -> Result<B4BuildValidation> {
    validate_published_b4_build_with_expectations(root, &B4BuildExpectations::default())
}

/// Validate one closed B4 archive against optional caller-owned expectations.
///
/// An expected evidence root is accepted only together with an expected source
/// commit and tree. All three values are supplied by the caller and are never
/// discovered inside the archive.
///
/// # Errors
///
/// Returns the first archive-semantic, external-source, anchor, or stability
/// mismatch.
pub fn validate_published_b4_build_with_expectations(
    root: impl AsRef<Path>,
    expectations: &B4BuildExpectations<'_>,
) -> Result<B4BuildValidation> {
    let external_anchors = validate_external_expectations(expectations)?;
    #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
    {
        let root = descriptor_build_check_linux::open_path_root(root.as_ref())?;
        let custody = descriptor_build_check_linux::DescriptorBuildCustody::open(
            std::os::fd::AsFd::as_fd(&root),
        )?;
        validate_published_b4_build_from_root(
            ValidationRoot::Descriptor(&custody),
            external_anchors,
        )
    }

    #[cfg(not(all(target_os = "linux", feature = "b4-descriptor-build-check")))]
    validate_published_b4_build_from_root(ValidationRoot::Path(root.as_ref()), external_anchors)
}

/// Validate one closed B4 archive beneath a caller-retained Linux directory.
///
/// Every directory and file lookup remains relative to the retained descriptor.
/// The checker requires Linux `openat2` confinement and `statx` mount identities;
/// unsupported kernels fail closed. An authoritative projection is returned only
/// when all three caller-owned expectations match.
///
/// # Errors
///
/// Returns the first root-descriptor, confinement, inventory, file-stability,
/// archive-semantic, external-source, or anchor mismatch.
#[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
pub fn validate_published_b4_build_from_directory_descriptor(
    root: std::os::fd::BorrowedFd<'_>,
    expectations: &B4BuildExpectations<'_>,
) -> Result<B4BuildValidation> {
    let external_anchors = validate_external_expectations(expectations)?;
    let custody = descriptor_build_check_linux::DescriptorBuildCustody::open(root)?;
    validate_published_b4_build_from_root(ValidationRoot::Descriptor(&custody), external_anchors)
}

fn validate_published_b4_build_from_root(
    root: ValidationRoot<'_>,
    external_anchors: Option<ExternalAnchors<'_>>,
) -> Result<B4BuildValidation> {
    if external_anchors.is_some() {
        require_authoritative_filesystem()?;
    }
    root.validate()?;
    let marker_capture = root.capture_file(COMPLETE_FILE, MAX_MARKER_BYTES, "B4 marker")?;
    let manifest_capture =
        root.capture_file(MANIFEST_FILE, MAX_MANIFEST_BYTES, "B4 evidence manifest")?;
    let marker = parse_completion_marker(&marker_capture.bytes)?;
    let expected_manifest = parse_evidence_manifest(&manifest_capture.bytes, &expected_paths())?;
    ensure!(
        manifest_capture.binding.sha256 == marker.manifest_hash,
        "B4 marker evidence-manifest digest mismatch"
    );

    let first = root.capture_tree()?;
    let second = root.capture_tree()?;
    ensure!(
        first == second,
        "published B4 tree changed between snapshots"
    );
    ensure!(
        second.directories == EXPECTED_DIRECTORIES.map(str::to_owned),
        "published B4 tree has a missing or extra run directory"
    );
    ensure_manifest_matches(&expected_manifest, &second.files)?;
    ensure_run_agreement(&second.files)?;
    let by_path = entry_map(&second.files);
    let guest = require_entry(&by_path, "run-1/guest.elf")?;
    ensure!(guest.size > 0, "B4 guest ELF is empty");
    ensure!(
        guest.sha256 == marker.guest_elf_sha256,
        "B4 marker guest ELF digest mismatch"
    );
    let image_id = require_entry(&by_path, "run-1/image-id.bin")?;
    ensure!(image_id.size == 32, "B4 image ID is not exactly 32 bytes");
    ensure!(
        image_id.sha256 == marker.image_id_digest,
        "B4 marker image ID digest mismatch"
    );
    let alternate_guest = require_entry(&by_path, "run-1/alternate-program-guest.elf")?;
    ensure!(
        alternate_guest.size > 0,
        "B4 alternate-program guest ELF is empty"
    );
    ensure!(
        alternate_guest.sha256 == marker.alternate_program_guest_elf_sha256,
        "B4 marker alternate-program guest ELF digest mismatch"
    );
    let alternate_image_id = require_entry(&by_path, "run-1/alternate-program-image-id.bin")?;
    ensure!(
        alternate_image_id.size == 32,
        "B4 alternate-program image ID is not exactly 32 bytes"
    );
    ensure!(
        alternate_image_id.sha256 == marker.alternate_program_image_id_digest,
        "B4 marker alternate-program image ID digest mismatch"
    );
    let archive = CapturedArchive::from_root(root, &second);
    validate_run_identity(&archive)?;
    let downstream_identity = validate_downstream_evidence(&archive)?;
    let archive_source = validate_provenance_semantics(&archive)?;

    let source_binding = if let Some(anchors) = external_anchors {
        ensure!(
            archive_source.commit == anchors.commit && archive_source.tree == anchors.tree,
            "B4 workspace source identity differs from caller expectation"
        );
        B4SourceBindingStatus::Matched
    } else {
        B4SourceBindingStatus::Unbound
    };

    let computed_evidence_root = evidence_root_hex(&marker_capture.bytes, &manifest_capture.bytes);
    let provided_digest_matched = if let Some(anchors) = external_anchors {
        ensure!(
            computed_evidence_root == anchors.evidence_root,
            "B4 evidence root differs from caller-owned external commitment"
        );
        Some(true)
    } else {
        None
    };

    validate_final_archive_stability(root, &marker_capture, &manifest_capture, &second)?;
    let filesystem_binding = filesystem_binding_status();
    let authoritative_projection = optional_authoritative_projection(
        external_anchors,
        source_binding,
        provided_digest_matched,
        filesystem_binding,
        &by_path,
        &computed_evidence_root,
        &downstream_identity,
    )?;
    Ok(B4BuildValidation {
        computed_evidence_root,
        provided_digest_matched,
        source_binding,
        filesystem_binding,
        runner_claims: B4RunnerClaimStatus::Unattested,
        opaque_artifacts: opaque_artifact_evidence(&second.files)?,
        authoritative_projection,
    })
}

fn validate_final_archive_stability(
    root: ValidationRoot<'_>,
    marker_capture: &CapturedFile,
    manifest_capture: &CapturedFile,
    snapshot: &TreeSnapshot,
) -> Result<()> {
    ensure!(
        root.reread_file(
            COMPLETE_FILE,
            &marker_capture.binding,
            MAX_MARKER_BYTES,
            "B4 marker"
        )? == marker_capture.bytes
            && root.reread_file(
                MANIFEST_FILE,
                &manifest_capture.binding,
                MAX_MANIFEST_BYTES,
                "B4 evidence manifest",
            )? == manifest_capture.bytes,
        "B4 marker or evidence manifest changed during validation"
    );
    ensure!(
        root.capture_tree()? == *snapshot,
        "published B4 tree changed during final validation"
    );
    Ok(())
}

fn optional_authoritative_projection(
    anchors: Option<ExternalAnchors<'_>>,
    source_binding: B4SourceBindingStatus,
    provided_digest_matched: Option<bool>,
    filesystem_binding: B4FilesystemBindingStatus,
    entries: &BTreeMap<&str, &EvidenceEntry>,
    computed_evidence_root: &str,
    downstream: &ValidatedDownstreamIdentity,
) -> Result<Option<AuthoritativeB4BuildProjection>> {
    anchors
        .map(|anchors| {
            ensure!(
                source_binding == B4SourceBindingStatus::Matched
                    && provided_digest_matched == Some(true)
                    && filesystem_binding == B4FilesystemBindingStatus::UnixFileIdentityBound,
                "authoritative B4 projection requires matched anchors and Unix file identity"
            );
            authoritative_projection(anchors, entries, computed_evidence_root, downstream)
        })
        .transpose()
}

fn authoritative_projection(
    anchors: ExternalAnchors<'_>,
    entries: &BTreeMap<&str, &EvidenceEntry>,
    computed_evidence_root: &str,
    downstream: &ValidatedDownstreamIdentity,
) -> Result<AuthoritativeB4BuildProjection> {
    let source_lock = require_entry(entries, "run-1/candidate-source-lock.json")?;
    let generator_closure = require_entry(entries, "run-1/cargo-closure-generator-host.json")?;
    let proof_tests = require_entry(entries, "run-1/proof-generation-tests.txt")?;
    let generator = require_entry(entries, "run-1/candidate-generator")?;
    let guest_elf = require_entry(entries, "run-1/guest.elf")?;
    let statement = require_entry(entries, "run-1/statement/candidate-statement.bin")?;
    ensure!(
        statement.sha256 == downstream.statement_sha256
            && statement.size == downstream.statement_byte_length,
        "validated statement identity differs from the evidence manifest"
    );
    Ok(AuthoritativeB4BuildProjection {
        evidence_root_sha256: computed_evidence_root.to_owned(),
        source_commit: anchors.commit.to_owned(),
        source_tree: anchors.tree.to_owned(),
        source_lock_sha256: source_lock.sha256.clone(),
        generator_cargo_closure_sha256: generator_closure.sha256.clone(),
        proof_generation_tests_sha256: proof_tests.sha256.clone(),
        generator_artifact_sha256: generator.sha256.clone(),
        generator_artifact_byte_length: generator.size,
        guest_elf_sha256: guest_elf.sha256.clone(),
        guest_elf_byte_length: guest_elf.size,
        image_id_hex: hex::encode(downstream.image_id),
        statement_sha256: downstream.statement_sha256.clone(),
        statement_byte_length: downstream.statement_byte_length,
        contract_id_hex: hex::encode(downstream.contract_id),
        chain_domain_id_hex: hex::encode(downstream.chain_domain_id),
        application_payload_sha256: hex::encode(downstream.application_payload_sha256),
        application_payload_byte_length: downstream.application_payload_byte_length,
    })
}

fn validate_external_expectations<'a>(
    expectations: &B4BuildExpectations<'a>,
) -> Result<Option<ExternalAnchors<'a>>> {
    let anchors = match (
        expectations.expected_source_commit,
        expectations.expected_source_tree,
        expectations.expected_evidence_root,
    ) {
        (None, None, None) => None,
        (Some(commit), Some(tree), Some(evidence_root)) => {
            validate_git_object_id(commit, "expected workspace source commit")?;
            validate_git_object_id(tree, "expected workspace source tree")?;
            validate_digest(evidence_root, "expected B4 evidence root")?;
            Some(ExternalAnchors {
                commit,
                tree,
                evidence_root,
            })
        }
        _ => bail!(
            "authoritative B4 validation requires external source commit, source tree, and evidence root together"
        ),
    };
    Ok(anchors)
}

fn require_authoritative_filesystem() -> Result<()> {
    #[cfg(unix)]
    {
        Ok(())
    }
    #[cfg(not(unix))]
    {
        bail!(
            "authoritative B4 validation requires Unix device/inode/link-count binding; this platform supports unanchored inspection only"
        )
    }
}

fn filesystem_binding_status() -> B4FilesystemBindingStatus {
    #[cfg(unix)]
    {
        B4FilesystemBindingStatus::UnixFileIdentityBound
    }
    #[cfg(not(unix))]
    {
        B4FilesystemBindingStatus::UnavailableForInspection
    }
}

fn opaque_artifact_evidence(actual: &[EvidenceEntry]) -> Result<Vec<B4ArtifactEvidence>> {
    let by_path = entry_map(actual);
    let mut paths = ROOT_OPAQUE_HASH_BOUND_FILES
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    for run in ["run-1", "run-2"] {
        paths.extend(
            RUN_OPAQUE_HASH_BOUND_FILES
                .into_iter()
                .map(|file| format!("{run}/{file}")),
        );
    }
    paths.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    paths
        .into_iter()
        .map(|path| {
            let entry = require_entry(&by_path, &path)?;
            Ok(B4ArtifactEvidence {
                path,
                size: entry.size,
                sha256: entry.sha256.clone(),
                status: B4ArtifactEvidenceStatus::OpaqueHashBound,
            })
        })
        .collect()
}

fn evidence_root_hex(marker: &[u8], manifest: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(EVIDENCE_ROOT_DOMAIN);
    hasher.update(Sha256::digest(marker));
    hasher.update(Sha256::digest(manifest));
    hex::encode(hasher.finalize())
}

fn expected_paths() -> BTreeSet<String> {
    let mut paths = ROOT_EVIDENCE_FILES
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    for run in ["run-1", "run-2"] {
        for file in RUN_EVIDENCE_FILES {
            paths.insert(format!("{run}/{file}"));
        }
    }
    paths
}

fn parse_completion_marker(bytes: &[u8]) -> Result<CompletionMarker> {
    let lines = exact_ascii_lf_lines(bytes, "B4 completion marker")?;
    ensure!(
        lines.len() == 11,
        "B4 completion marker must have exactly 11 fields"
    );
    require_line(lines[0], "schema", COMPLETION_SCHEMA)?;
    require_line(lines[1], "status", "complete")?;
    require_line(lines[2], "runCount", "2")?;
    require_line(lines[3], "inputIsolation", INPUT_ISOLATION)?;
    require_line(lines[4], "executionIsolation", EXECUTION_ISOLATION)?;
    require_line(lines[5], "runtimeManifest", RUNTIME_MANIFEST)?;
    Ok(CompletionMarker {
        manifest_hash: digest_line(lines[6], "evidenceManifestSha256")?,
        guest_elf_sha256: digest_line(lines[7], "guestElfSha256")?,
        image_id_digest: digest_line(lines[8], "imageIdSha256")?,
        alternate_program_guest_elf_sha256: digest_line(
            lines[9],
            "alternateProgramGuestElfSha256",
        )?,
        alternate_program_image_id_digest: digest_line(lines[10], "alternateProgramImageIdSha256")?,
    })
}

fn parse_evidence_manifest(
    bytes: &[u8],
    exact_paths: &BTreeSet<String>,
) -> Result<Vec<EvidenceEntry>> {
    let lines = exact_ascii_lf_lines(bytes, "B4 evidence manifest")?;
    ensure!(
        lines.len() == exact_paths.len(),
        "B4 evidence manifest entry count mismatch"
    );
    let mut entries = Vec::with_capacity(lines.len());
    let mut previous: Option<&str> = None;
    let mut folded = BTreeSet::new();
    for (index, line) in lines.into_iter().enumerate() {
        let rest = line
            .strip_prefix("file path=")
            .with_context(|| format!("manifest line {index} has the wrong prefix"))?;
        let (path, rest) = rest
            .split_once(" sha256=")
            .with_context(|| format!("manifest line {index} lacks sha256"))?;
        let (sha256, size) = rest
            .split_once(" size=")
            .with_context(|| format!("manifest line {index} lacks size"))?;
        ensure!(
            !size.contains(' '),
            "manifest line {index} has trailing fields"
        );
        validate_relative_path(path)?;
        ensure!(
            !path.eq_ignore_ascii_case(COMPLETE_FILE) && !path.eq_ignore_ascii_case(MANIFEST_FILE),
            "manifest includes a reserved publication file"
        );
        validate_digest(sha256, "manifest SHA-256")?;
        let size = canonical_u64(size, "manifest size")?;
        if let Some(previous) = previous {
            ensure!(
                previous.as_bytes() < path.as_bytes(),
                "manifest paths are not strictly sorted"
            );
        }
        ensure!(
            folded.insert(path.to_ascii_lowercase()),
            "manifest has a case-fold collision"
        );
        previous = Some(path);
        entries.push(EvidenceEntry {
            path: path.to_owned(),
            sha256: sha256.to_owned(),
            size,
        });
    }
    ensure!(
        entries
            .iter()
            .map(|entry| entry.path.clone())
            .collect::<BTreeSet<_>>()
            == *exact_paths,
        "manifest does not contain the exact closed artifact paths"
    );
    Ok(entries)
}

fn capture_tree(root: &Path) -> Result<TreeSnapshot> {
    let mut snapshot = TreeSnapshot {
        directories: Vec::new(),
        files: Vec::new(),
        physical_files: BTreeMap::new(),
        #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
        descriptor_directories: BTreeMap::new(),
        #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
        descriptor_files: BTreeMap::new(),
    };
    let mut total = 0_u64;
    let mut nodes = 0_usize;
    let allowed_files = expected_paths()
        .into_iter()
        .chain([COMPLETE_FILE.to_owned(), MANIFEST_FILE.to_owned()])
        .collect::<BTreeSet<_>>();
    let allowed_directories = EXPECTED_DIRECTORIES
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    collect_directory(
        root,
        root,
        &mut snapshot,
        &mut total,
        &mut nodes,
        &allowed_files,
        &allowed_directories,
    )?;
    snapshot
        .directories
        .sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    snapshot
        .files
        .sort_unstable_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    ensure!(
        snapshot.files.len() == expected_paths().len(),
        "published B4 tree has a missing or extra evidence file"
    );
    Ok(snapshot)
}

fn collect_directory(
    root: &Path,
    directory: &Path,
    snapshot: &mut TreeSnapshot,
    total: &mut u64,
    nodes: &mut usize,
    allowed_files: &BTreeSet<String>,
    allowed_directories: &BTreeSet<String>,
) -> Result<()> {
    let metadata = fs::symlink_metadata(directory)
        .with_context(|| format!("cannot inspect B4 directory {}", directory.display()))?;
    reject_link_or_reparse(directory, &metadata)?;
    ensure!(
        metadata.file_type().is_dir(),
        "B4 traversal target is not a directory"
    );
    for child in fs::read_dir(directory)
        .with_context(|| format!("cannot enumerate B4 directory {}", directory.display()))?
    {
        let child = child.with_context(|| format!("cannot enumerate {}", directory.display()))?;
        *nodes = nodes
            .checked_add(1)
            .context("B4 tree node count overflow")?;
        ensure!(
            *nodes <= MAX_TREE_NODES,
            "published B4 tree exceeds its global node bound"
        );
        let path = child.path();
        let relative = repository_relative(root, &path)?;
        ensure!(
            allowed_files.contains(&relative) || allowed_directories.contains(&relative),
            "published B4 tree contains an unexpected path: {relative}"
        );
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("cannot inspect B4 entry {}", path.display()))?;
        reject_link_or_reparse(&path, &metadata)?;
        if path.parent() == Some(root)
            && (relative.eq_ignore_ascii_case(COMPLETE_FILE)
                || relative.eq_ignore_ascii_case(MANIFEST_FILE))
        {
            ensure!(
                relative == COMPLETE_FILE || relative == MANIFEST_FILE,
                "reserved publication path has a noncanonical case alias"
            );
            ensure!(
                metadata.file_type().is_file(),
                "reserved publication path is not a file"
            );
            #[cfg(unix)]
            observe_physical_identity(&path, &metadata)?;
            continue;
        }
        validate_relative_path(&relative)?;
        if metadata.file_type().is_dir() {
            ensure!(
                allowed_directories.contains(&relative),
                "published B4 file path is a directory: {relative}"
            );
            snapshot.directories.push(relative);
            collect_directory(
                root,
                &path,
                snapshot,
                total,
                nodes,
                allowed_files,
                allowed_directories,
            )?;
        } else if metadata.file_type().is_file() {
            ensure!(
                allowed_files.contains(&relative),
                "published B4 directory path is a file: {relative}"
            );
            let (size, sha256, physical) = hash_regular_file_bound(&path)?;
            *total = total
                .checked_add(size)
                .context("B4 evidence total overflow")?;
            ensure!(
                *total <= MAX_TOTAL_BYTES,
                "B4 evidence exceeds its total byte bound"
            );
            snapshot.files.push(EvidenceEntry {
                path: relative.clone(),
                sha256,
                size,
            });
            if let Some(physical) = physical {
                ensure!(
                    snapshot.physical_files.insert(relative, physical).is_none(),
                    "published B4 tree repeats a physical-file path"
                );
            }
        } else {
            bail!(
                "B4 entry is neither directory nor regular file: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn ensure_manifest_matches(expected: &[EvidenceEntry], actual: &[EvidenceEntry]) -> Result<()> {
    ensure!(
        expected.len() == actual.len(),
        "manifest and tree entry counts differ"
    );
    for (index, (expected, actual)) in expected.iter().zip(actual).enumerate() {
        ensure!(
            expected == actual,
            "B4 tree mismatch at manifest index {index}: expected {expected:?}, actual {actual:?}"
        );
    }
    Ok(())
}

fn entry_map(files: &[EvidenceEntry]) -> BTreeMap<&str, &EvidenceEntry> {
    files
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect()
}

fn ensure_run_agreement(files: &[EvidenceEntry]) -> Result<()> {
    let by_path = entry_map(files);
    for file in RUN_EVIDENCE_FILES {
        let left = require_entry(&by_path, &format!("run-1/{file}"))?;
        let right = require_entry(&by_path, &format!("run-2/{file}"))?;
        ensure!(
            left.sha256 == right.sha256 && left.size == right.size,
            "B4 run evidence disagrees for {file}"
        );
    }
    Ok(())
}

fn validate_run_identity(archive: &CapturedArchive<'_>) -> Result<()> {
    let bytes = archive.read(RUN_IDENTITY_FILE, MAX_MANIFEST_BYTES, "B4 run identity")?;
    let run_paths = RUN_EVIDENCE_FILES
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let identity = parse_evidence_manifest(&bytes, &run_paths)
        .context("B4 run identity is not an exact manifest")?;
    let run_one = archive
        .files
        .iter()
        .filter_map(|entry| {
            entry.path.strip_prefix("run-1/").map(|path| EvidenceEntry {
                path: path.to_owned(),
                sha256: entry.sha256.clone(),
                size: entry.size,
            })
        })
        .collect::<Vec<_>>();
    ensure!(
        identity == run_one,
        "B4 run identity does not describe exact run-1 evidence"
    );
    let identity_entry = archive.entry(RUN_IDENTITY_FILE)?;
    ensure!(
        identity_entry.sha256 == sha256_hex(&bytes)
            && identity_entry.size == u64::try_from(bytes.len())?,
        "B4 run identity changed while parsed"
    );
    Ok(())
}

fn validate_provenance_semantics(archive: &CapturedArchive<'_>) -> Result<WorkspaceSourceIdentity> {
    validate_within_run_snapshots(archive, "run-1")?;

    let source_lock_bytes = archive.read(
        "run-1/candidate-source-lock.json",
        MAX_PROVENANCE_JSON_BYTES,
        "B4 candidate source lock",
    )?;
    let source_lock_value = validate_canonical_json_source(&source_lock_bytes)
        .context("B4 candidate source lock is not exact RFC 8785 JCS")?;
    let source_lock: CandidateSourceLock = serde_json::from_value(source_lock_value)
        .context("B4 candidate source lock does not match its closed shape")?;
    source_lock
        .validate()
        .context("B4 candidate source lock violates frozen candidate pins")?;

    let source_manifest_bytes = archive.read(
        "run-1/source-materialized-manifest.txt",
        MAX_SOURCE_MANIFEST_BYTES,
        "B4 materialized source manifest",
    )?;
    let source_manifest = parse_file_identity_manifest(
        &source_manifest_bytes,
        false,
        "B4 materialized source manifest",
    )?;
    ensure!(
        source_manifest == source_lock.materialized_files.entries,
        "B4 materialized source manifest differs from candidate source lock"
    );

    let workspace_manifest_bytes = archive.read(
        "run-1/workspace-source-manifest.txt",
        MAX_SOURCE_MANIFEST_BYTES,
        "B4 workspace source manifest",
    )?;
    let workspace_manifest = parse_file_identity_manifest(
        &workspace_manifest_bytes,
        false,
        "B4 workspace source manifest",
    )?;
    require_manifest_entry(&workspace_manifest, "Dockerfile.reproduction")?;
    require_manifest_entry(
        &workspace_manifest,
        "reproduction/cargo-offline-config.toml",
    )?;

    let checkout_admin_bytes = archive.read(
        "run-1/source-checkout-admin-manifest.txt",
        MAX_SOURCE_MANIFEST_BYTES,
        "B4 source checkout-administration manifest",
    )?;
    parse_file_identity_manifest(
        &checkout_admin_bytes,
        true,
        "B4 source checkout-administration manifest",
    )?;

    let workspace_git = parse_workspace_git(&archive.read(
        "run-1/workspace-git.txt",
        MAX_SEMANTIC_TEXT_BYTES,
        "B4 workspace Git evidence",
    )?)?;

    validate_cargo_evidence(archive, "run-1")?;
    validate_image_representations(archive, "run-1")?;
    validate_build_policy(archive, "run-1", &source_lock)?;
    validate_source_git_observation(archive, "run-1", &source_lock)?;
    ensure!(
        archive.read(
            "run-1/reproduction-invariants.txt",
            MAX_SEMANTIC_TEXT_BYTES,
            "B4 reproduction invariant marker",
        )? == b"EIP-0045 pinned invariants: ok\n",
        "B4 reproduction invariant marker is not exact"
    );
    validate_identity_record(archive, "run-1", &source_lock, &workspace_manifest)?;

    Ok(workspace_git)
}

fn validate_within_run_snapshots(archive: &CapturedArchive<'_>, run: &str) -> Result<()> {
    require_identical_snapshot_group(
        archive,
        run,
        &[
            "candidate-source-lock-first.json",
            "candidate-source-lock-second.json",
            "candidate-source-lock.json",
        ],
        MAX_PROVENANCE_JSON_BYTES,
        "candidate source-lock snapshots",
    )?;
    require_identical_snapshot_group(
        archive,
        run,
        &[
            "source-materialized-manifest-before.txt",
            "source-materialized-manifest-after.txt",
            "source-materialized-manifest.txt",
        ],
        MAX_SOURCE_MANIFEST_BYTES,
        "materialized source snapshots",
    )?;
    require_identical_snapshot_group(
        archive,
        run,
        &[
            "source-checkout-admin-manifest-before.txt",
            "source-checkout-admin-manifest-after.txt",
            "source-checkout-admin-manifest.txt",
        ],
        MAX_SOURCE_MANIFEST_BYTES,
        "source checkout-administration snapshots",
    )?;
    require_identical_snapshot_group(
        archive,
        run,
        &[
            "workspace-source-manifest-before.txt",
            "workspace-source-manifest-after.txt",
            "workspace-source-manifest.txt",
        ],
        MAX_SOURCE_MANIFEST_BYTES,
        "workspace source snapshots",
    )?;
    require_identical_snapshot_group(
        archive,
        run,
        &[
            "workspace-git-before.txt",
            "workspace-git-after.txt",
            "workspace-git.txt",
        ],
        MAX_SEMANTIC_TEXT_BYTES,
        "workspace Git snapshots",
    )?;
    Ok(())
}

fn require_identical_snapshot_group(
    archive: &CapturedArchive<'_>,
    run: &str,
    files: &[&str],
    max: u64,
    label: &str,
) -> Result<()> {
    let first_path = files.first().context("snapshot group is empty")?;
    let first = archive.read(&format!("{run}/{first_path}"), max, label)?;
    for file in &files[1..] {
        ensure!(
            archive.read(&format!("{run}/{file}"), max, label)? == first,
            "B4 {label} disagree within one run"
        );
    }
    Ok(())
}

fn parse_file_identity_manifest(
    bytes: &[u8],
    allow_git_admin: bool,
    label: &str,
) -> Result<Vec<MaterializedFileEntry>> {
    let lines = exact_ascii_lf_lines(bytes, label)?;
    let mut entries = Vec::with_capacity(lines.len());
    let mut previous: Option<&str> = None;
    let mut folded = BTreeSet::new();
    for (index, line) in lines.into_iter().enumerate() {
        let rest = line
            .strip_prefix("file path=")
            .with_context(|| format!("{label} line {index} has the wrong prefix"))?;
        let (path, rest) = rest
            .split_once(" executable=")
            .with_context(|| format!("{label} line {index} lacks executable"))?;
        let (executable, rest) = rest
            .split_once(" sha256=")
            .with_context(|| format!("{label} line {index} lacks sha256"))?;
        let (sha256, size) = rest
            .split_once(" size=")
            .with_context(|| format!("{label} line {index} lacks size"))?;
        ensure!(
            !size.contains(' '),
            "{label} line {index} has trailing fields"
        );
        validate_manifest_path(path, allow_git_admin)?;
        let executable = match executable {
            "true" => true,
            "false" => false,
            _ => bail!("{label} line {index} has a noncanonical executable flag"),
        };
        validate_digest(sha256, label)?;
        let size = canonical_u64(size, label)?;
        if let Some(previous) = previous {
            ensure!(
                previous.as_bytes() < path.as_bytes(),
                "{label} paths are not strictly sorted"
            );
        }
        ensure!(
            folded.insert(path.to_ascii_lowercase()),
            "{label} has a case-fold path collision"
        );
        previous = Some(path);
        entries.push(MaterializedFileEntry {
            path: path.to_owned(),
            byte_length: size,
            sha256: sha256.to_owned(),
            executable,
        });
    }
    Ok(entries)
}

fn validate_manifest_path(path: &str, allow_git_admin: bool) -> Result<()> {
    ensure!(
        !path.is_empty()
            && path.len() <= 1024
            && !path.starts_with('/')
            && !path.ends_with('/')
            && !path.contains('\\')
            && !path.contains(':')
            && path.bytes().all(|byte| (0x20..=0x7e).contains(&byte)),
        "B4 file-identity manifest path is not canonical portable ASCII"
    );
    for component in path.split('/') {
        ensure!(
            !component.is_empty()
                && component != "."
                && component != ".."
                && (allow_git_admin || component != ".git")
                && !component.ends_with(['.', ' ']),
            "B4 file-identity manifest path contains an unsafe component"
        );
    }
    Ok(())
}

fn require_manifest_entry<'a>(
    entries: &'a [MaterializedFileEntry],
    path: &str,
) -> Result<&'a MaterializedFileEntry> {
    entries
        .binary_search_by(|entry| entry.path.as_bytes().cmp(path.as_bytes()))
        .ok()
        .map(|index| &entries[index])
        .with_context(|| format!("B4 workspace source manifest lacks {path}"))
}

fn parse_workspace_git(bytes: &[u8]) -> Result<WorkspaceSourceIdentity> {
    let lines = exact_ascii_lf_lines(bytes, "B4 workspace Git evidence")?;
    ensure!(
        lines.len() == 5,
        "B4 workspace Git evidence must have exactly five lines"
    );
    let commit = lines[0]
        .strip_prefix("head=")
        .context("B4 workspace Git evidence lacks head")?;
    let tree = lines[1]
        .strip_prefix("tree=")
        .context("B4 workspace Git evidence lacks tree")?;
    validate_git_object_id(commit, "B4 workspace commit")?;
    validate_git_object_id(tree, "B4 workspace tree")?;
    ensure!(
        lines[2] == "storage=standalone-private-object-store"
            && lines[3] == "statusBegin"
            && lines[4] == "statusEnd",
        "B4 workspace Git status framing is not exact"
    );
    Ok(WorkspaceSourceIdentity {
        commit: commit.to_owned(),
        tree: tree.to_owned(),
    })
}

fn validate_git_object_id(value: &str, label: &str) -> Result<()> {
    ensure!(
        value.len() == 40
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} is not lowercase 40-character Git hex"
    );
    Ok(())
}

fn validate_cargo_evidence(archive: &CapturedArchive<'_>, run: &str) -> Result<()> {
    let profile_root = ProfileRootIdentity::new(PROFILE_ROOT, PROFILE_ROOT_IDENTITY)
        .context("cannot construct fixed B4 Cargo profile-root identity")?;
    for (metadata_file, closure_file, expected_role) in [
        (
            "cargo-metadata-generator-host.json",
            "cargo-closure-generator-host.json",
            CargoClosureRole::GeneratorHost,
        ),
        (
            "cargo-metadata-methods-build.json",
            "cargo-closure-methods-build.json",
            CargoClosureRole::MethodsBuild,
        ),
        (
            "cargo-metadata-guest.json",
            "cargo-closure-guest.json",
            CargoClosureRole::Guest,
        ),
    ] {
        let metadata_bytes = archive.read(
            &format!("{run}/{metadata_file}"),
            MAX_PROVENANCE_JSON_BYTES,
            "B4 Cargo metadata",
        )?;
        let metadata = parse_json_strict(&metadata_bytes)
            .with_context(|| format!("{metadata_file} is not one strict JSON document"))?;
        let closure_bytes = archive.read(
            &format!("{run}/{closure_file}"),
            MAX_PROVENANCE_JSON_BYTES,
            "B4 Cargo closure",
        )?;
        let closure_value = validate_canonical_json_source(&closure_bytes)
            .with_context(|| format!("{closure_file} is not exact RFC 8785 JCS"))?;
        let closure: CargoClosureEvidence = serde_json::from_value(closure_value)
            .with_context(|| format!("{closure_file} does not match its closed shape"))?;
        ensure!(
            closure.role == expected_role,
            "B4 Cargo closure role differs from its file role"
        );
        validate_cargo_closure(&metadata, &closure, &profile_root)
            .with_context(|| format!("{closure_file} disagrees with {metadata_file}"))?;
    }
    Ok(())
}

fn validate_image_representations(archive: &CapturedArchive<'_>, run: &str) -> Result<()> {
    validate_image_representation(archive, run, "image-id", "EIP_0045_GUEST", "B4 image ID")?;
    validate_image_representation(
        archive,
        run,
        "alternate-program-image-id",
        "EIP_0045_ALTERNATE_PROGRAM_GUEST",
        "B4 alternate-program image ID",
    )
}

fn validate_image_representation(
    archive: &CapturedArchive<'_>,
    run: &str,
    file_stem: &str,
    generated_symbol: &str,
    label: &str,
) -> Result<()> {
    let image_id = archive.read_digest(&format!("{run}/{file_stem}.bin"), label)?;
    let expected_hex = format!("{}\n", hex::encode(image_id));
    ensure!(
        archive.read(
            &format!("{run}/{file_stem}.hex"),
            65,
            &format!("{label} hexadecimal representation"),
        )? == expected_hex.as_bytes(),
        "{label} hexadecimal representation is not canonical"
    );

    let words = image_id
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("four-byte chunk")))
        .map(|word| word.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let expected_declaration = format!("pubconst{generated_symbol}_ID:[u32;8]=[{words}];");
    ensure!(
        archive.read(
            &format!("{run}/{file_stem}-declaration.txt"),
            1024,
            &format!("{label} declaration"),
        )? == expected_declaration.as_bytes(),
        "{label} declaration is not the eight little-endian image-ID words"
    );
    Ok(())
}

fn validate_build_policy(
    archive: &CapturedArchive<'_>,
    run: &str,
    source_lock: &CandidateSourceLock,
) -> Result<()> {
    let expected = expected_build_policy(source_lock);
    ensure!(
        archive.read(
            &format!("{run}/build-policy.txt"),
            MAX_SEMANTIC_TEXT_BYTES,
            "B4 build policy",
        )? == expected.as_bytes(),
        "B4 build policy differs from the frozen candidate source lock"
    );
    Ok(())
}

fn expected_build_policy(source_lock: &CandidateSourceLock) -> String {
    let build = &source_lock.build;
    format!(
        "hostTarget={}\nguestTarget={}\ngeneratorProfile={}\nguestProfile={}\ncargoProfileConfigurationBinding=clean-workspace-git-tree-and-workspace-source-manifest\ncargoBuildJobs={}\ncargoBuildJobsEnforcement=config-build.jobs\ncargoIncremental=disabled\ncargoIncrementalEnforcement=config-build.incremental\ncontainerCpuSet={}\ncontainerMemoryBytes={}\ncontainerSwapBytes=0\nproofPolicyLifecycle={}\nplannedLocalProverBackend={}\nplannedLocalProverName={}\ncandidateExecutorSegmentLimitPo2=23\ncandidateMinSegmentPo2=15\ncandidateMaxSegmentPo2=22\nplannedReceiptKind={}\nplannedHashSuite={}\nplannedDevMode=disabled\nplannedVerifierDevMode=disabled\nplannedProveGuestErrors=disabled\n",
        source_lock.toolchains.host_target,
        source_lock.toolchains.guest_target,
        build.generator_profile,
        build.guest_profile,
        build.cargo_build_jobs,
        build.container_cpu_set,
        build.container_memory_bytes,
        build.proof_policy_lifecycle,
        build.planned_local_prover_backend,
        build.planned_local_prover_name,
        build.planned_receipt_kind,
        build.planned_hash_suite,
    )
}

fn validate_source_git_observation(
    archive: &CapturedArchive<'_>,
    run: &str,
    source_lock: &CandidateSourceLock,
) -> Result<()> {
    let expected = expected_source_git_observation(source_lock)?;
    ensure!(
        archive.read(
            &format!("{run}/source-git-observed.txt"),
            MAX_SEMANTIC_TEXT_BYTES,
            "B4 source Git observation",
        )? == expected.as_bytes(),
        "B4 source Git observation differs from the frozen candidate source lock"
    );
    Ok(())
}

fn expected_source_git_observation(source_lock: &CandidateSourceLock) -> Result<String> {
    let [circom, recursion] = source_lock.lfs_objects.as_slice() else {
        bail!("B4 candidate source lock has the wrong LFS cardinality");
    };
    Ok(format!(
        "commit={}\ntree={}\ncomputedCheckoutTreeExact=true\nexcludedCargoMarker=.cargo-ok\ncircomPointerGitBlobSha1={}\ncircomPointerByteLength={}\ncircomPointerSha256={}\nrecursionPointerGitBlobSha1={}\nrecursionPointerByteLength={}\nrecursionPointerSha256={}\n",
        source_lock.source.commit,
        source_lock.source.tree,
        circom.pointer_git_blob_sha1,
        circom.pointer_byte_length,
        circom.pointer_sha256,
        recursion.pointer_git_blob_sha1,
        recursion.pointer_byte_length,
        recursion.pointer_sha256,
    ))
}

fn validate_identity_record(
    archive: &CapturedArchive<'_>,
    run: &str,
    source_lock: &CandidateSourceLock,
    workspace_manifest: &[MaterializedFileEntry],
) -> Result<()> {
    let expected = expected_identity_record(archive, run, source_lock, workspace_manifest)?;
    ensure!(
        archive.read(
            &format!("{run}/identity.txt"),
            MAX_IDENTITY_BYTES,
            "B4 build identity record",
        )? == expected.as_bytes(),
        "B4 build identity record is not the exact recomputation of archived artifacts"
    );
    Ok(())
}

fn expected_identity_record(
    archive: &CapturedArchive<'_>,
    run: &str,
    source_lock: &CandidateSourceLock,
    workspace_manifest: &[MaterializedFileEntry],
) -> Result<String> {
    let run_entry =
        |file: &str| -> Result<&EvidenceEntry> { archive.entry(&format!("{run}/{file}")) };
    let guest = run_entry("guest.elf")?;
    let image_id = archive.read_digest(&format!("{run}/image-id.bin"), "B4 image ID")?;
    let image_id_entry = run_entry("image-id.bin")?;
    let alternate_program_guest = run_entry("alternate-program-guest.elf")?;
    let alternate_program_image_id = archive.read_digest(
        &format!("{run}/alternate-program-image-id.bin"),
        "B4 alternate-program image ID",
    )?;
    let alternate_program_image_id_entry = run_entry("alternate-program-image-id.bin")?;
    let generator = run_entry("candidate-generator")?;
    let cargo_config =
        require_manifest_entry(workspace_manifest, "reproduction/cargo-offline-config.toml")?;
    let dockerfile = require_manifest_entry(workspace_manifest, "Dockerfile.reproduction")?;
    Ok(format!(
        "guestElfSha256={}\nguestElfByteLength={}\nimageIdCanonicalHex={}\nimageIdCanonicalSha256={}\nimageIdDeclarationSha256={}\nalternateProgramGuestElfSha256={}\nalternateProgramGuestElfByteLength={}\nalternateProgramImageIdCanonicalHex={}\nalternateProgramImageIdCanonicalSha256={}\nalternateProgramImageIdDeclarationSha256={}\nhostRust={}\nhostTarget={}\nguestBuildCargoObserved={}\nguestRustObserved={}\nbundledGuestCargoObserved={}\nguestTarget={}\ngeneratorProfile={}\ngeneratorBinarySha256={}\ngeneratorBinaryByteLength={}\nbuildPolicySha256={}\nproofGenerationTestsSha256={}\nresourcePolicyObservationSha256={}\nhostToolchainObservationSha256={}\nguestToolchainObservationSha256={}\nsourceCommit={}\ndeclaredSourceTree={}\nsourceGitObservationSha256={}\nrecursionSourceRelativePath=risc0/circuit/recursion/src/recursion_zkr.zip\nsourceManifestSha256={}\nsourceCheckoutAdminManifestSha256={}\ncandidateSourceLockSha256={}\ncargoMetadataGeneratorHostSha256={}\ncargoMetadataMethodsBuildSha256={}\ncargoMetadataGuestSha256={}\ncargoClosureGeneratorHostSha256={}\ncargoClosureMethodsBuildSha256={}\ncargoClosureGuestSha256={}\nbuildEnvironmentSha256={}\ncargoConfigSha256={}\ndockerfileSha256={}\ncandidateStatementInputsSha256={}\ncandidateStatementSha256={}\n",
        guest.sha256,
        guest.size,
        hex::encode(image_id),
        image_id_entry.sha256,
        run_entry("image-id-declaration.txt")?.sha256,
        alternate_program_guest.sha256,
        alternate_program_guest.size,
        hex::encode(alternate_program_image_id),
        alternate_program_image_id_entry.sha256,
        run_entry("alternate-program-image-id-declaration.txt")?.sha256,
        source_lock.toolchains.host_rust,
        source_lock.toolchains.host_target,
        source_lock.toolchains.host_rust,
        source_lock.toolchains.guest_rust,
        source_lock.toolchains.guest_rust,
        source_lock.toolchains.guest_target,
        source_lock.build.generator_profile,
        generator.sha256,
        generator.size,
        run_entry("build-policy.txt")?.sha256,
        run_entry("proof-generation-tests.txt")?.sha256,
        run_entry("resource-policy-observed.txt")?.sha256,
        run_entry("host-toolchain-observed.txt")?.sha256,
        run_entry("guest-toolchain-observed.txt")?.sha256,
        source_lock.source.commit,
        source_lock.source.tree,
        run_entry("source-git-observed.txt")?.sha256,
        run_entry("source-materialized-manifest.txt")?.sha256,
        run_entry("source-checkout-admin-manifest.txt")?.sha256,
        run_entry("candidate-source-lock.json")?.sha256,
        run_entry("cargo-metadata-generator-host.json")?.sha256,
        run_entry("cargo-metadata-methods-build.json")?.sha256,
        run_entry("cargo-metadata-guest.json")?.sha256,
        run_entry("cargo-closure-generator-host.json")?.sha256,
        run_entry("cargo-closure-methods-build.json")?.sha256,
        run_entry("cargo-closure-guest.json")?.sha256,
        run_entry("build-environment.txt")?.sha256,
        cargo_config.sha256,
        dockerfile.sha256,
        run_entry("statement/inputs.txt")?.sha256,
        run_entry("statement/candidate-statement.bin")?.sha256,
    ))
}

fn validate_downstream_evidence(
    archive: &CapturedArchive<'_>,
) -> Result<ValidatedDownstreamIdentity> {
    let proof_tests = archive.read(
        "run-1/proof-generation-tests.txt",
        MAX_SEMANTIC_TEXT_BYTES,
        "B4 proof-generation test marker",
    )?;
    ensure!(
        proof_tests == PROOF_GENERATION_TESTS.as_bytes(),
        "B4 proof-generation test marker is not exact"
    );

    let expected_chain = decode_digest(CHAIN_DOMAIN_ID_HEX, "fixed chain-domain ID")?;
    let chain = archive.read_digest(
        "run-1/statement/chain-domain-id.bin",
        "B4 statement chain-domain ID",
    )?;
    ensure!(
        chain == expected_chain,
        "B4 statement chain-domain ID mismatch"
    );

    let expected_payload = (0_u8..32).collect::<Vec<_>>();
    let payload = archive.read(
        "run-1/statement/application-payload.bin",
        32,
        "B4 statement application payload",
    )?;
    ensure!(
        payload == expected_payload,
        "B4 statement application payload mismatch"
    );

    let expected_profile = decode_digest(PROFILE_ID_HEX, "fixed B3 profile ID")?;
    let profile =
        archive.read_digest("run-1/statement/profile-id.bin", "B4 statement profile ID")?;
    ensure!(
        profile == expected_profile,
        "B4 statement profile ID mismatch"
    );

    let (program_id, proposition, candidate_contract) =
        validate_program_contract_identity(archive, &profile)?;

    let candidate_statement = archive.read(
        "run-1/statement/candidate-statement.bin",
        u64::try_from(MAX_STATEMENT_BYTES)?,
        "B4 candidate statement",
    )?;
    let expected_statement =
        ergo_statement_v1(&chain, &profile, &program_id, &proposition, &payload)
            .context("cannot reconstruct B4 candidate statement")?;
    ensure!(
        candidate_statement == expected_statement,
        "B4 candidate statement is not the exact ErgoStatementV1 construction"
    );

    let transcript = archive.read(
        "run-1/statement/candidate-statement-transcript.txt",
        MAX_SEMANTIC_TEXT_BYTES,
        "B4 candidate statement transcript",
    )?;
    let expected_transcript =
        expected_candidate_transcript(&program_id, &candidate_contract, candidate_statement.len());
    ensure!(
        transcript == expected_transcript,
        "B4 candidate statement transcript mismatch"
    );

    let generator = archive.entry("run-1/candidate-generator")?;
    let guest = archive.entry("run-1/guest.elf")?;
    let inputs = archive.read(
        "run-1/statement/inputs.txt",
        MAX_SEMANTIC_TEXT_BYTES,
        "B4 candidate statement inputs",
    )?;
    let expected_inputs =
        expected_statement_inputs(&generator.sha256, &guest.sha256, &program_id, &transcript)?;
    ensure!(
        inputs == expected_inputs,
        "B4 candidate statement inputs mismatch"
    );
    Ok(ValidatedDownstreamIdentity {
        image_id: program_id,
        contract_id: candidate_contract,
        chain_domain_id: chain,
        application_payload_sha256: Sha256::digest(&payload).into(),
        application_payload_byte_length: u64::try_from(payload.len())?,
        statement_sha256: sha256_hex(&candidate_statement),
        statement_byte_length: u64::try_from(candidate_statement.len())?,
    })
}

fn validate_program_contract_identity(
    archive: &CapturedArchive<'_>,
    profile: &[u8; DIGEST_BYTES],
) -> Result<([u8; DIGEST_BYTES], Vec<u8>, [u8; DIGEST_BYTES])> {
    let guest_elf = archive.read(
        "run-1/guest.elf",
        MAX_GUEST_ELF_BYTES,
        "B4 guest ProgramBinary",
    )?;
    let recomputed_image_id: [u8; DIGEST_BYTES] = compute_image_id(&guest_elf)
        .context("cannot recompute the B4 guest ProgramBinary image ID")?
        .into();
    let image_id = archive.read_digest("run-1/image-id.bin", "B4 image ID")?;
    ensure!(
        image_id == recomputed_image_id,
        "B4 image ID does not equal risc0-binfmt computation over guest.elf"
    );
    let alternate_program_guest_elf = archive.read(
        "run-1/alternate-program-guest.elf",
        MAX_GUEST_ELF_BYTES,
        "B4 alternate-program guest ProgramBinary",
    )?;
    let recomputed_alternate_program_image_id: [u8; DIGEST_BYTES] =
        compute_image_id(&alternate_program_guest_elf)
            .context("cannot recompute the B4 alternate-program guest ProgramBinary image ID")?
            .into();
    let alternate_program_image_id = archive.read_digest(
        "run-1/alternate-program-image-id.bin",
        "B4 alternate-program image ID",
    )?;
    ensure!(
        alternate_program_image_id == recomputed_alternate_program_image_id,
        "B4 alternate-program image ID does not equal risc0-binfmt computation over alternate-program-guest.elf"
    );
    ensure!(
        alternate_program_image_id != image_id,
        "B4 alternate-program image ID equals the consumer image ID"
    );
    let program_id = archive.read_digest(
        "run-1/statement/candidate-program-id.bin",
        "B4 candidate program ID",
    )?;
    ensure!(
        program_id == image_id,
        "B4 candidate program ID differs from image ID"
    );

    let proposition = archive.read(
        "run-1/statement/candidate-proposition.bin",
        MAX_PROPOSITION_BYTES,
        "B4 candidate proposition",
    )?;
    ensure!(
        proposition == reference_contract_proposition(&program_id, profile),
        "B4 candidate proposition is not the exact 85-byte v4 reference contract"
    );
    let candidate_contract = archive.read_digest(
        "run-1/statement/candidate-contract-id.bin",
        "B4 candidate contract ID",
    )?;
    ensure!(
        candidate_contract == contract_id(&proposition),
        "B4 candidate contract ID is not derived from the proposition"
    );
    Ok((program_id, proposition, candidate_contract))
}

fn reference_contract_proposition(
    program_id: &[u8; DIGEST_BYTES],
    profile_id: &[u8; DIGEST_BYTES],
) -> [u8; 85] {
    let mut proposition = [0_u8; 85];
    proposition[..5].copy_from_slice(&REFERENCE_TREE_PREFIX);
    proposition[5..37].copy_from_slice(program_id);
    proposition[37..39].copy_from_slice(&REFERENCE_SECOND_CONSTANT_PREFIX);
    proposition[39..71].copy_from_slice(profile_id);
    proposition[71..].copy_from_slice(&REFERENCE_TREE_EXPRESSION);
    proposition
}

fn decode_digest(value: &str, label: &str) -> Result<[u8; DIGEST_BYTES]> {
    validate_digest(value, label)?;
    let bytes = hex::decode(value).with_context(|| format!("cannot decode {label}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} is not {DIGEST_BYTES} bytes"))
}

fn expected_candidate_transcript(
    program_id: &[u8; DIGEST_BYTES],
    contract: &[u8; DIGEST_BYTES],
    statement_bytes: usize,
) -> Vec<u8> {
    format!(
        "programId={}\ncontractId={}\nstatementBytes={statement_bytes}\ncandidateOnly=true\n",
        hex::encode(program_id),
        hex::encode(contract)
    )
    .into_bytes()
}

fn expected_statement_inputs(
    generator_sha256: &str,
    guest_elf_sha256: &str,
    image_id: &[u8; DIGEST_BYTES],
    transcript: &[u8],
) -> Result<Vec<u8>> {
    validate_digest(generator_sha256, "candidate generator SHA-256")?;
    validate_digest(guest_elf_sha256, "guest ELF SHA-256")?;
    let chain = decode_digest(CHAIN_DOMAIN_ID_HEX, "fixed chain-domain ID")?;
    let payload = (0_u8..32).collect::<Vec<_>>();
    let profile = decode_digest(PROFILE_ID_HEX, "fixed B3 profile ID")?;
    Ok(format!(
        "schema=eip0045-b4-statement-inputs-v1\nchainDomainIdHex={CHAIN_DOMAIN_ID_HEX}\nchainDomainIdSha256={}\napplicationPayloadHex={}\napplicationPayloadSha256={}\nprofileIdHex={PROFILE_ID_HEX}\nprofileIdSha256={}\nprofileManifestSha256={PROFILE_MANIFEST_SHA256}\ngeneratorBinarySha256={generator_sha256}\nguestElfSha256={guest_elf_sha256}\nimageIdHex={}\ncandidateStatementTranscriptSha256={}\nproofGenerated=false\n",
        sha256_hex(&chain),
        hex::encode(&payload),
        sha256_hex(&payload),
        sha256_hex(&profile),
        hex::encode(image_id),
        sha256_hex(transcript),
    )
    .into_bytes())
}

fn require_entry<'a>(
    entries: &BTreeMap<&str, &'a EvidenceEntry>,
    path: &str,
) -> Result<&'a EvidenceEntry> {
    entries
        .get(path)
        .copied()
        .with_context(|| format!("B4 evidence lacks {path}"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BoundReadStage {
    PathInspected,
    HandleOpened,
    BytesRead,
}

fn capture_file(path: &Path, max: u64, label: &str) -> Result<CapturedFile> {
    read_file_with_binding_and_hook(path, None, max, label, |_, _| Ok(()))
}

fn reread_captured_file(
    path: &Path,
    binding: &FileBinding,
    max: u64,
    label: &str,
) -> Result<Vec<u8>> {
    Ok(read_file_with_binding_and_hook(path, Some(binding), max, label, |_, _| Ok(()))?.bytes)
}

fn read_captured_entry(
    path: &Path,
    entry: &EvidenceEntry,
    physical: Option<&PhysicalFileIdentity>,
    max: u64,
    label: &str,
) -> Result<Vec<u8>> {
    Ok(read_captured_entry_with_hook(path, entry, physical, max, label, |_, _| Ok(()))?.bytes)
}

fn read_captured_entry_with_hook<F>(
    path: &Path,
    entry: &EvidenceEntry,
    physical: Option<&PhysicalFileIdentity>,
    max: u64,
    label: &str,
    hook: F,
) -> Result<CapturedFile>
where
    F: FnMut(BoundReadStage, &Path) -> Result<()>,
{
    let binding = FileBinding {
        size: entry.size,
        sha256: entry.sha256.clone(),
        physical: physical.copied(),
        #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
        descriptor_state: None,
    };
    read_file_with_binding_and_hook(path, Some(&binding), max, label, hook)
}

fn read_file_with_binding_and_hook<F>(
    path: &Path,
    expected: Option<&FileBinding>,
    max: u64,
    label: &str,
    mut hook: F,
) -> Result<CapturedFile>
where
    F: FnMut(BoundReadStage, &Path) -> Result<()>,
{
    let before = fs::symlink_metadata(path)
        .with_context(|| format!("{label} is missing: {}", path.display()))?;
    validate_regular_metadata(path, &before, max, label)?;
    let before_physical = observe_physical_identity(path, &before)?;
    validate_expected_binding(
        expected,
        before.len(),
        before_physical,
        label,
        "before opening",
    )?;
    hook(BoundReadStage::PathInspected, path)?;

    let mut file = File::open(path).with_context(|| format!("cannot open {label}"))?;
    let opened = file
        .metadata()
        .with_context(|| format!("cannot inspect open {label}"))?;
    validate_regular_metadata(path, &opened, max, label)?;
    let opened_physical = observe_physical_identity(path, &opened)?;
    ensure_same_physical_identity(before_physical, opened_physical, label, "while opening")?;
    ensure!(
        opened.len() == before.len(),
        "{label} changed length while opening"
    );
    validate_expected_binding(
        expected,
        opened.len(),
        opened_physical,
        label,
        "after opening",
    )?;
    hook(BoundReadStage::HandleOpened, path)?;

    let mut bytes = Vec::with_capacity(usize::try_from(opened.len())?);
    (&mut file)
        .take(max + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {label}"))?;
    ensure!(
        u64::try_from(bytes.len())? == opened.len(),
        "{label} changed while reading"
    );
    hook(BoundReadStage::BytesRead, path)?;

    let handle_after = file
        .metadata()
        .with_context(|| format!("cannot re-inspect open {label}"))?;
    validate_regular_metadata(path, &handle_after, max, label)?;
    let handle_after_physical = observe_physical_identity(path, &handle_after)?;
    ensure_same_physical_identity(
        opened_physical,
        handle_after_physical,
        label,
        "on the open handle after reading",
    )?;
    ensure!(
        handle_after.len() == opened.len(),
        "{label} changed length on the open handle"
    );

    let path_after =
        fs::symlink_metadata(path).with_context(|| format!("cannot re-inspect {label}"))?;
    validate_regular_metadata(path, &path_after, max, label)?;
    let path_after_physical = observe_physical_identity(path, &path_after)?;
    ensure_same_physical_identity(
        opened_physical,
        path_after_physical,
        label,
        "at the path after reading",
    )?;
    ensure!(
        path_after.len() == opened.len(),
        "{label} changed length after reading"
    );

    let sha256 = sha256_hex(&bytes);
    if let Some(expected) = expected {
        ensure!(
            sha256 == expected.sha256,
            "{label} SHA-256 differs from the captured evidence entry"
        );
    }
    Ok(CapturedFile {
        binding: FileBinding {
            size: opened.len(),
            sha256,
            physical: opened_physical,
            #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
            descriptor_state: None,
        },
        bytes,
    })
}

fn validate_regular_metadata(
    path: &Path,
    metadata: &Metadata,
    max: u64,
    label: &str,
) -> Result<()> {
    reject_link_or_reparse(path, metadata)?;
    ensure!(
        metadata.file_type().is_file(),
        "{label} is not a regular file"
    );
    ensure!(metadata.len() <= max, "{label} exceeds its byte bound");
    Ok(())
}

fn validate_expected_binding(
    expected: Option<&FileBinding>,
    size: u64,
    physical: Option<PhysicalFileIdentity>,
    label: &str,
    stage: &str,
) -> Result<()> {
    if let Some(expected) = expected {
        ensure!(size == expected.size, "{label} size differs {stage}");
        ensure_same_physical_identity(expected.physical, physical, label, stage)?;
    }
    Ok(())
}

fn ensure_same_physical_identity(
    expected: Option<PhysicalFileIdentity>,
    actual: Option<PhysicalFileIdentity>,
    label: &str,
    stage: &str,
) -> Result<()> {
    #[cfg(unix)]
    ensure!(
        expected.is_some() && expected == actual,
        "{label} physical file identity changed {stage}"
    );
    #[cfg(not(unix))]
    ensure!(
        expected.is_none() && actual.is_none(),
        "{label} unexpectedly acquired a physical identity {stage}"
    );
    Ok(())
}

fn observe_physical_identity(
    path: &Path,
    metadata: &Metadata,
) -> Result<Option<PhysicalFileIdentity>> {
    ensure!(
        metadata.file_type().is_file(),
        "physical identity target is not a regular file: {}",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let identity = PhysicalFileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            links: metadata.nlink(),
        };
        ensure!(
            identity.links == 1,
            "hard-linked B4 file is forbidden: {}",
            path.display()
        );
        Ok(Some(identity))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Ok(None)
    }
}

fn hash_regular_file_bound(path: &Path) -> Result<(u64, String, Option<PhysicalFileIdentity>)> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect B4 file {}", path.display()))?;
    reject_link_or_reparse(path, &metadata)?;
    ensure!(
        metadata.file_type().is_file(),
        "B4 evidence path is not a regular file"
    );
    ensure!(
        metadata.len() <= MAX_FILE_BYTES,
        "B4 evidence file exceeds byte bound"
    );
    let before_physical = observe_physical_identity(path, &metadata)?;
    let mut file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let opened = file.metadata().context("cannot inspect open B4 file")?;
    let opened_physical = observe_physical_identity(path, &opened)?;
    ensure!(
        opened.file_type().is_file() && opened.len() == metadata.len(),
        "B4 file changed before hashing"
    );
    ensure_same_physical_identity(
        before_physical,
        opened_physical,
        "B4 file",
        "while opening for hashing",
    )?;
    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file.read(&mut buffer).context("cannot hash B4 file")?;
        if count == 0 {
            break;
        }
        observed = observed
            .checked_add(u64::try_from(count)?)
            .context("B4 file length overflow")?;
        ensure!(observed <= opened.len(), "B4 file grew while hashing");
        hasher.update(&buffer[..count]);
    }
    ensure!(
        observed == opened.len(),
        "B4 file changed length while hashing"
    );
    let handle_after = file.metadata().context("cannot re-inspect open B4 file")?;
    let handle_after_physical = observe_physical_identity(path, &handle_after)?;
    ensure_same_physical_identity(
        opened_physical,
        handle_after_physical,
        "B4 file",
        "on the open handle after hashing",
    )?;
    ensure!(
        handle_after.len() == opened.len(),
        "B4 file changed length on the open handle after hashing"
    );
    let after = fs::symlink_metadata(path).context("cannot re-inspect B4 file")?;
    reject_link_or_reparse(path, &after)?;
    ensure!(
        after.file_type().is_file() && after.len() == opened.len(),
        "B4 file changed after hashing"
    );
    let after_physical = observe_physical_identity(path, &after)?;
    ensure_same_physical_identity(
        opened_physical,
        after_physical,
        "B4 file",
        "at the path after hashing",
    )?;
    Ok((observed, hex::encode(hasher.finalize()), opened_physical))
}

#[cfg(test)]
fn hash_regular_file(path: &Path) -> Result<(u64, String)> {
    let (size, sha256, _) = hash_regular_file_bound(path)?;
    Ok((size, sha256))
}

fn exact_ascii_lf_lines<'a>(bytes: &'a [u8], label: &str) -> Result<Vec<&'a str>> {
    ensure!(!bytes.is_empty(), "{label} is empty");
    ensure!(bytes.is_ascii(), "{label} is not ASCII");
    ensure!(!bytes.contains(&b'\r'), "{label} contains CR");
    ensure!(bytes.ends_with(b"\n"), "{label} lacks final LF");
    let text = std::str::from_utf8(bytes).expect("ASCII is UTF-8");
    let body = text.strip_suffix('\n').expect("final LF checked");
    ensure!(!body.is_empty(), "{label} has no fields");
    let lines = body.split('\n').collect::<Vec<_>>();
    ensure!(
        lines.iter().all(|line| !line.is_empty()),
        "{label} contains an empty line"
    );
    Ok(lines)
}

fn require_line(line: &str, key: &str, value: &str) -> Result<()> {
    ensure!(line == format!("{key}={value}"), "B4 marker {key} mismatch");
    Ok(())
}

fn digest_line(line: &str, key: &str) -> Result<String> {
    let value = line
        .strip_prefix(&format!("{key}="))
        .with_context(|| format!("B4 marker {key} is missing or reordered"))?;
    validate_digest(value, key)?;
    Ok(value.to_owned())
}

fn canonical_u64(value: &str, label: &str) -> Result<u64> {
    ensure!(
        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        "{label} is not unsigned decimal"
    );
    ensure!(
        value == "0" || !value.starts_with('0'),
        "{label} has a leading zero"
    );
    value
        .parse::<u64>()
        .with_context(|| format!("{label} exceeds u64"))
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} is not lowercase SHA-256 hex"
    );
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty() && path.len() <= MAX_PATH_BYTES,
        "B4 path is empty or too long"
    );
    ensure!(
        path.bytes().all(|byte| (0x21..=0x7e).contains(&byte)),
        "B4 path is not printable space-free ASCII"
    );
    ensure!(
        !path.starts_with('/')
            && !path.ends_with('/')
            && !path.contains('\\')
            && !path.contains(':'),
        "B4 path is not canonical relative POSIX"
    );
    for component in path.split('/') {
        let bytes = component.as_bytes();
        ensure!(
            !bytes.is_empty()
                && matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9')
                && bytes
                    .iter()
                    .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
                && component != "."
                && component != ".."
                && !component.ends_with('.')
                && !is_windows_device_component(component),
            "B4 path contains an unsafe component"
        );
    }
    Ok(())
}

fn repository_relative(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .with_context(|| format!("B4 path escaped root: {}", path.display()))?;
    let mut components = Vec::new();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            bail!("B4 path is not normal: {}", relative.display());
        };
        components.push(
            component
                .to_str()
                .with_context(|| format!("B4 path is not UTF-8: {}", relative.display()))?,
        );
    }
    Ok(components.join("/"))
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

fn require_ordinary_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("{label} is missing: {}", path.display()))?;
    reject_link_or_reparse(path, &metadata)?;
    ensure!(metadata.file_type().is_dir(), "{label} is not a directory");
    Ok(())
}

fn reject_link_or_reparse(path: &Path, metadata: &Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || is_windows_reparse_point(metadata) {
        bail!("link or reparse point is forbidden: {}", path.display());
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

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
mod descriptor_build_check_linux {
    use std::{
        collections::{BTreeMap, BTreeSet},
        ffi::CStr,
        fs::File,
        os::{
            fd::{AsFd as _, BorrowedFd, OwnedFd},
            unix::fs::FileExt as _,
        },
        path::Path,
    };

    use anyhow::{Context as _, Result, ensure};
    use sha2::{Digest as _, Sha256};

    use super::{
        COMPLETE_FILE, CapturedFile, DescriptorObjectState, EXPECTED_DIRECTORIES, EvidenceEntry,
        FileBinding, MANIFEST_FILE, MAX_FILE_BYTES, MAX_PATH_BYTES, MAX_TOTAL_BYTES,
        MAX_TREE_NODES, PhysicalFileIdentity, TreeSnapshot, expected_paths,
    };

    const PATH_DIRECTORY_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::PATH
        .union(rustix::fs::OFlags::DIRECTORY)
        .union(rustix::fs::OFlags::NOFOLLOW)
        .union(rustix::fs::OFlags::CLOEXEC);
    const READ_DIRECTORY_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY
        .union(rustix::fs::OFlags::DIRECTORY)
        .union(rustix::fs::OFlags::NOFOLLOW)
        .union(rustix::fs::OFlags::NONBLOCK)
        .union(rustix::fs::OFlags::CLOEXEC);
    const PATH_FILE_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::PATH
        .union(rustix::fs::OFlags::NOFOLLOW)
        .union(rustix::fs::OFlags::CLOEXEC);
    const READ_FILE_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY
        .union(rustix::fs::OFlags::NOFOLLOW)
        .union(rustix::fs::OFlags::NONBLOCK)
        .union(rustix::fs::OFlags::CLOEXEC);
    const RESOLVE_FLAGS: rustix::fs::ResolveFlags = rustix::fs::ResolveFlags::BENEATH
        .union(rustix::fs::ResolveFlags::NO_SYMLINKS)
        .union(rustix::fs::ResolveFlags::NO_MAGICLINKS)
        .union(rustix::fs::ResolveFlags::NO_XDEV);

    struct PinnedDirectory {
        path_descriptor: OwnedFd,
        state: DescriptorObjectState,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum DescriptorFileReadStage {
        DirectoriesAuthenticated,
        PathPinned,
        DataOpened,
        BytesRead,
        FileRepinned,
    }

    pub(super) struct DescriptorBuildCustody {
        root: PinnedDirectory,
        directories: BTreeMap<String, PinnedDirectory>,
        inventories: BTreeMap<String, BTreeSet<Vec<u8>>>,
    }

    fn checked_u64<T>(value: T, error: &'static str) -> Result<u64>
    where
        u64: TryFrom<T>,
    {
        u64::try_from(value).map_err(|_| anyhow::Error::msg(error))
    }

    fn mount_id(descriptor: BorrowedFd<'_>, label: &str) -> Result<u64> {
        let statx = rustix::fs::statx(
            descriptor,
            "",
            rustix::fs::AtFlags::EMPTY_PATH,
            rustix::fs::StatxFlags::BASIC_STATS | rustix::fs::StatxFlags::MNT_ID,
        )
        .with_context(|| format!("cannot obtain mount identity for {label}"))?;
        ensure!(
            rustix::fs::StatxFlags::from_bits_retain(statx.stx_mask)
                .contains(rustix::fs::StatxFlags::MNT_ID),
            "Linux statx did not return a mount identity for {label}"
        );
        Ok(statx.stx_mnt_id)
    }

    fn object_state(
        descriptor: BorrowedFd<'_>,
        expect_directory: bool,
        label: &str,
    ) -> Result<DescriptorObjectState> {
        let stat = rustix::fs::fstat(descriptor)
            .with_context(|| format!("cannot inspect retained B4 object {label}"))?;
        let file_type = rustix::fs::FileType::from_raw_mode(stat.st_mode);
        if expect_directory {
            ensure!(file_type.is_dir(), "{label} is not an ordinary directory");
        } else {
            ensure!(
                file_type.is_file(),
                "{label} is not an ordinary regular file"
            );
        }
        let links = checked_u64(stat.st_nlink, "B4 link count does not fit u64")?;
        if !expect_directory {
            ensure!(links == 1, "hard-linked B4 file is forbidden: {label}");
        }
        Ok(DescriptorObjectState {
            device: checked_u64(stat.st_dev, "B4 device identity does not fit u64")?,
            inode: checked_u64(stat.st_ino, "B4 inode identity does not fit u64")?,
            mount_id: mount_id(descriptor, label)?,
            byte_length: checked_u64(stat.st_size, "B4 byte length does not fit u64")?,
            links,
            mode: stat.st_mode,
            owner: checked_u64(stat.st_uid, "B4 owner identity does not fit u64")?,
            group: checked_u64(stat.st_gid, "B4 group identity does not fit u64")?,
            modified_seconds: stat.st_mtime,
            modified_nanoseconds: stat.st_mtime_nsec,
            changed_seconds: stat.st_ctime,
            changed_nanoseconds: stat.st_ctime_nsec,
        })
    }

    fn directory_state(
        descriptor: impl std::os::fd::AsFd,
        label: &str,
    ) -> Result<DescriptorObjectState> {
        object_state(descriptor.as_fd(), true, label)
    }

    fn file_state(
        descriptor: impl std::os::fd::AsFd,
        label: &str,
    ) -> Result<DescriptorObjectState> {
        object_state(descriptor.as_fd(), false, label)
    }

    fn open_directory_descriptor(
        parent: BorrowedFd<'_>,
        name: &str,
        label: &str,
        flags: rustix::fs::OFlags,
    ) -> Result<OwnedFd> {
        rustix::fs::openat2(
            parent,
            name,
            flags,
            rustix::fs::Mode::empty(),
            RESOLVE_FLAGS,
        )
        .with_context(|| format!("cannot open descriptor-rooted B4 directory {label}"))
    }

    fn directory_label(relative: &str) -> &str {
        if relative.is_empty() {
            "published B4 root"
        } else {
            relative
        }
    }

    fn enumerate_directory(descriptor: &OwnedFd, label: &str) -> Result<BTreeSet<Vec<u8>>> {
        let initial = directory_state(descriptor, label)?;
        let mut directory = rustix::fs::Dir::read_from(descriptor.as_fd())
            .with_context(|| format!("cannot enumerate retained B4 directory {label}"))?;
        let mut entries = BTreeSet::new();
        for entry in &mut directory {
            let entry = entry
                .with_context(|| format!("cannot read retained B4 directory entry in {label}"))?;
            let name: &CStr = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            ensure!(
                entries.len() < MAX_TREE_NODES,
                "published B4 directory exceeds its node bound: {label}"
            );
            ensure!(
                entries.insert(name.to_bytes().to_vec()),
                "published B4 directory contains a duplicate entry: {label}"
            );
        }
        ensure!(
            directory_state(descriptor, label)? == initial,
            "retained B4 directory changed while enumerating {label}"
        );
        Ok(entries)
    }

    fn expected_inventories() -> Result<BTreeMap<String, BTreeSet<Vec<u8>>>> {
        let mut inventories = BTreeMap::<String, BTreeSet<Vec<u8>>>::new();
        inventories.insert(String::new(), BTreeSet::new());
        for path in expected_paths()
            .into_iter()
            .chain([COMPLETE_FILE.to_owned(), MANIFEST_FILE.to_owned()])
        {
            ensure!(
                path.len() <= MAX_PATH_BYTES,
                "compiled B4 path exceeds its byte bound"
            );
            let components = path.split('/').collect::<Vec<_>>();
            ensure!(
                !components.is_empty()
                    && components.iter().all(|component| !component.is_empty()
                        && *component != "."
                        && *component != ".."),
                "compiled B4 path is not component-normal"
            );
            let mut parent = String::new();
            for component in &components[..components.len() - 1] {
                inventories
                    .entry(parent.clone())
                    .or_default()
                    .insert(component.as_bytes().to_vec());
                if !parent.is_empty() {
                    parent.push('/');
                }
                parent.push_str(component);
                inventories.entry(parent.clone()).or_default();
            }
            ensure!(
                inventories
                    .entry(parent)
                    .or_default()
                    .insert(components[components.len() - 1].as_bytes().to_vec()),
                "compiled B4 file entry is duplicated"
            );
        }
        let expected_directories = std::iter::once("")
            .chain(EXPECTED_DIRECTORIES)
            .collect::<BTreeSet<_>>();
        ensure!(
            inventories
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == expected_directories,
            "compiled B4 directory inventory drifted"
        );
        Ok(inventories)
    }

    fn open_pinned_directory(
        parent: BorrowedFd<'_>,
        name: &str,
        relative: &str,
        root_mount: Option<u64>,
    ) -> Result<PinnedDirectory> {
        let label = directory_label(relative);
        let path_descriptor = open_directory_descriptor(parent, name, label, PATH_DIRECTORY_FLAGS)?;
        let state = directory_state(&path_descriptor, label)?;
        if let Some(root_mount) = root_mount {
            ensure!(
                state.mount_id == root_mount,
                "descriptor-rooted B4 directory crossed a mount: {label}"
            );
        }
        let read_descriptor = open_directory_descriptor(parent, name, label, READ_DIRECTORY_FLAGS)?;
        ensure!(
            directory_state(&read_descriptor, label)? == state,
            "descriptor-rooted B4 directory changed while opening {label}"
        );
        let _ = enumerate_directory(&read_descriptor, label)?;
        ensure!(
            directory_state(&path_descriptor, label)? == state,
            "descriptor-rooted B4 directory changed while pinning {label}"
        );
        Ok(PinnedDirectory {
            path_descriptor,
            state,
        })
    }

    pub(super) fn open_path_root(path: &Path) -> Result<OwnedFd> {
        rustix::fs::open(path, READ_DIRECTORY_FLAGS, rustix::fs::Mode::empty())
            .with_context(|| format!("cannot open published B4 root {}", path.display()))
    }

    impl DescriptorBuildCustody {
        pub(super) fn open(root: BorrowedFd<'_>) -> Result<Self> {
            let inventories = expected_inventories()?;
            let root = open_pinned_directory(root, ".", "", None)?;
            let root_mount = root.state.mount_id;
            let mut directories = BTreeMap::<String, PinnedDirectory>::new();
            for relative in inventories.keys().filter(|relative| !relative.is_empty()) {
                let (parent, name) = split_parent_and_name(relative)?;
                let parent_descriptor = if parent.is_empty() {
                    root.path_descriptor.as_fd()
                } else {
                    directories
                        .get(parent)
                        .with_context(|| format!("B4 directory parent is absent: {parent}"))?
                        .path_descriptor
                        .as_fd()
                };
                let directory =
                    open_pinned_directory(parent_descriptor, name, relative, Some(root_mount))?;
                ensure!(
                    directories.insert(relative.clone(), directory).is_none(),
                    "descriptor-rooted B4 directory is duplicated"
                );
            }
            let custody = Self {
                root,
                directories,
                inventories,
            };
            custody.reauthenticate_directories()?;
            Ok(custody)
        }

        fn directory(&self, relative: &str) -> Result<&PinnedDirectory> {
            if relative.is_empty() {
                Ok(&self.root)
            } else {
                self.directories
                    .get(relative)
                    .with_context(|| format!("retained B4 directory is absent: {relative}"))
            }
        }

        pub(super) fn reauthenticate_directories(&self) -> Result<()> {
            for (relative, expected_inventory) in &self.inventories {
                let retained = self.directory(relative)?;
                let label = directory_label(relative);
                ensure!(
                    directory_state(&retained.path_descriptor, label)? == retained.state,
                    "retained B4 directory metadata changed: {label}"
                );
                let (parent, name) = if relative.is_empty() {
                    (self.root.path_descriptor.as_fd(), ".")
                } else {
                    let (parent, name) = split_parent_and_name(relative)?;
                    (self.directory(parent)?.path_descriptor.as_fd(), name)
                };
                let reopened =
                    open_directory_descriptor(parent, name, label, PATH_DIRECTORY_FLAGS)?;
                ensure!(
                    directory_state(&reopened, label)? == retained.state,
                    "named B4 directory no longer identifies the retained directory: {label}"
                );
                let read_descriptor =
                    open_directory_descriptor(parent, name, label, READ_DIRECTORY_FLAGS)?;
                ensure!(
                    directory_state(&read_descriptor, label)? == retained.state,
                    "B4 directory changed while reopening its inventory: {label}"
                );
                ensure!(
                    enumerate_directory(&read_descriptor, label)? == *expected_inventory,
                    "published B4 directory has a missing or extra entry: {label}"
                );
            }
            Ok(())
        }

        fn file_parent_and_name<'custody, 'relative>(
            &'custody self,
            relative: &'relative str,
        ) -> Result<(BorrowedFd<'custody>, &'relative str)> {
            let (parent, name) = split_parent_and_name(relative)?;
            Ok((self.directory(parent)?.path_descriptor.as_fd(), name))
        }

        fn directory_states(&self) -> BTreeMap<String, DescriptorObjectState> {
            std::iter::once((String::new(), self.root.state))
                .chain(
                    self.directories
                        .iter()
                        .map(|(path, directory)| (path.clone(), directory.state)),
                )
                .collect()
        }
    }

    fn split_parent_and_name(relative: &str) -> Result<(&str, &str)> {
        let (parent, name) = relative.rsplit_once('/').unwrap_or(("", relative));
        ensure!(
            !name.is_empty() && name != "." && name != ".." && !name.contains('/'),
            "descriptor-rooted B4 name is not one canonical component"
        );
        Ok((parent, name))
    }

    fn open_file_pair(
        custody: &DescriptorBuildCustody,
        relative: &str,
        maximum: u64,
        label: &str,
    ) -> Result<(OwnedFd, File, DescriptorObjectState)> {
        open_file_pair_with_hook(custody, relative, maximum, label, |_, _| Ok(()))
    }

    fn open_file_pair_with_hook<Hook>(
        custody: &DescriptorBuildCustody,
        relative: &str,
        maximum: u64,
        label: &str,
        mut hook: Hook,
    ) -> Result<(OwnedFd, File, DescriptorObjectState)>
    where
        Hook: FnMut(DescriptorFileReadStage, Option<&[u8]>) -> Result<()>,
    {
        let (parent, name) = custody.file_parent_and_name(relative)?;
        let path_descriptor = rustix::fs::openat2(
            parent,
            name,
            PATH_FILE_FLAGS,
            rustix::fs::Mode::empty(),
            RESOLVE_FLAGS,
        )
        .with_context(|| format!("cannot pin descriptor-rooted {label}: {relative}"))?;
        let state = file_state(&path_descriptor, label)?;
        ensure!(
            state.mount_id == custody.root.state.mount_id,
            "descriptor-rooted {label} crossed a mount"
        );
        ensure!(
            state.byte_length <= maximum,
            "{label} exceeds its byte bound"
        );
        hook(DescriptorFileReadStage::PathPinned, None)?;
        let data_descriptor = rustix::fs::openat2(
            parent,
            name,
            READ_FILE_FLAGS,
            rustix::fs::Mode::empty(),
            RESOLVE_FLAGS,
        )
        .with_context(|| format!("cannot open descriptor-rooted {label}: {relative}"))?;
        let data_descriptor = File::from(data_descriptor);
        ensure!(
            file_state(&data_descriptor, label)? == state,
            "descriptor-rooted {label} changed while opening"
        );
        hook(DescriptorFileReadStage::DataOpened, None)?;
        Ok((path_descriptor, data_descriptor, state))
    }

    fn validate_open_file_after_read(
        custody: &DescriptorBuildCustody,
        relative: &str,
        path_descriptor: &OwnedFd,
        data_descriptor: &File,
        state: DescriptorObjectState,
        label: &str,
    ) -> Result<()> {
        ensure!(
            file_state(path_descriptor, label)? == state
                && file_state(data_descriptor, label)? == state,
            "descriptor-rooted {label} metadata changed while reading"
        );
        let (parent, name) = custody.file_parent_and_name(relative)?;
        let reopened = rustix::fs::openat2(
            parent,
            name,
            PATH_FILE_FLAGS,
            rustix::fs::Mode::empty(),
            RESOLVE_FLAGS,
        )
        .with_context(|| format!("cannot repin descriptor-rooted {label}: {relative}"))?;
        ensure!(
            file_state(&reopened, label)? == state,
            "named {label} no longer identifies the retained file"
        );
        Ok(())
    }

    fn read_exact_bytes(file: &File, state: DescriptorObjectState, label: &str) -> Result<Vec<u8>> {
        let length = usize::try_from(state.byte_length)
            .with_context(|| format!("{label} byte length does not fit memory"))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .with_context(|| format!("cannot allocate bounded buffer for {label}"))?;
        bytes.resize(length, 0);
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let count = file
                .read_at(&mut bytes[offset..], u64::try_from(offset)?)
                .with_context(|| format!("cannot read retained {label}"))?;
            ensure!(count != 0, "retained {label} ended before its bound length");
            offset = offset
                .checked_add(count)
                .context("B4 read offset overflow")?;
        }
        let mut trailing = [0_u8; 1];
        ensure!(
            file.read_at(&mut trailing, state.byte_length)
                .with_context(|| format!("cannot verify EOF for retained {label}"))?
                == 0,
            "retained {label} has trailing bytes"
        );
        Ok(bytes)
    }

    pub(super) fn capture_file(
        custody: &DescriptorBuildCustody,
        relative: &str,
        expected: Option<&FileBinding>,
        maximum: u64,
        label: &str,
    ) -> Result<CapturedFile> {
        capture_file_with_hook(custody, relative, expected, maximum, label, |_, _| Ok(()))
    }

    fn capture_file_with_hook<Hook>(
        custody: &DescriptorBuildCustody,
        relative: &str,
        expected: Option<&FileBinding>,
        maximum: u64,
        label: &str,
        mut hook: Hook,
    ) -> Result<CapturedFile>
    where
        Hook: FnMut(DescriptorFileReadStage, Option<&[u8]>) -> Result<()>,
    {
        custody.reauthenticate_directories()?;
        hook(DescriptorFileReadStage::DirectoriesAuthenticated, None)?;
        let (path_descriptor, data_descriptor, state) =
            open_file_pair_with_hook(custody, relative, maximum, label, &mut hook)?;
        if let Some(expected) = expected {
            ensure!(
                expected.size == state.byte_length,
                "{label} size differs before reading"
            );
            ensure!(
                expected.descriptor_state == Some(state),
                "{label} descriptor identity differs from the captured binding"
            );
        }
        let bytes = read_exact_bytes(&data_descriptor, state, label)?;
        hook(DescriptorFileReadStage::BytesRead, Some(&bytes))?;
        validate_open_file_after_read(
            custody,
            relative,
            &path_descriptor,
            &data_descriptor,
            state,
            label,
        )?;
        hook(DescriptorFileReadStage::FileRepinned, Some(&bytes))?;
        custody.reauthenticate_directories()?;
        let sha256 = hex::encode(Sha256::digest(&bytes));
        if let Some(expected) = expected {
            ensure!(
                expected.sha256 == sha256,
                "{label} SHA-256 differs from the captured evidence entry"
            );
        }
        Ok(CapturedFile {
            bytes,
            binding: FileBinding {
                size: state.byte_length,
                sha256,
                physical: Some(PhysicalFileIdentity {
                    device: state.device,
                    inode: state.inode,
                    links: state.links,
                }),
                descriptor_state: Some(state),
            },
        })
    }

    #[cfg(test)]
    pub(super) fn capture_file_with_test_hook<Hook>(
        custody: &DescriptorBuildCustody,
        relative: &str,
        expected: Option<&FileBinding>,
        maximum: u64,
        label: &str,
        hook: Hook,
    ) -> Result<CapturedFile>
    where
        Hook: FnMut(DescriptorFileReadStage, Option<&[u8]>) -> Result<()>,
    {
        capture_file_with_hook(custody, relative, expected, maximum, label, hook)
    }

    fn hash_file(
        custody: &DescriptorBuildCustody,
        relative: &str,
    ) -> Result<(u64, String, PhysicalFileIdentity, DescriptorObjectState)> {
        let label = "B4 evidence file";
        let (path_descriptor, data_descriptor, state) =
            open_file_pair(custody, relative, MAX_FILE_BYTES, label)?;
        let mut hasher = Sha256::new();
        let mut offset = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
        while offset < state.byte_length {
            let remaining = usize::try_from((state.byte_length - offset).min(buffer.len() as u64))?;
            let count = data_descriptor
                .read_at(&mut buffer[..remaining], offset)
                .with_context(|| format!("cannot hash descriptor-rooted B4 file {relative}"))?;
            ensure!(
                count != 0,
                "descriptor-rooted B4 file ended while hashing: {relative}"
            );
            offset = offset
                .checked_add(u64::try_from(count)?)
                .context("B4 file length overflow")?;
            hasher.update(&buffer[..count]);
        }
        let mut trailing = [0_u8; 1];
        ensure!(
            data_descriptor.read_at(&mut trailing, state.byte_length)? == 0,
            "descriptor-rooted B4 file grew while hashing: {relative}"
        );
        validate_open_file_after_read(
            custody,
            relative,
            &path_descriptor,
            &data_descriptor,
            state,
            label,
        )?;
        Ok((
            state.byte_length,
            hex::encode(hasher.finalize()),
            PhysicalFileIdentity {
                device: state.device,
                inode: state.inode,
                links: state.links,
            },
            state,
        ))
    }

    pub(super) fn capture_tree(custody: &DescriptorBuildCustody) -> Result<TreeSnapshot> {
        custody.reauthenticate_directories()?;
        let node_count = expected_paths()
            .len()
            .checked_add(EXPECTED_DIRECTORIES.len())
            .and_then(|count| count.checked_add(2))
            .context("compiled B4 node count overflow")?;
        ensure!(
            node_count <= MAX_TREE_NODES,
            "published B4 tree exceeds its global node bound"
        );
        let mut snapshot = TreeSnapshot {
            directories: EXPECTED_DIRECTORIES.map(str::to_owned).to_vec(),
            files: Vec::new(),
            physical_files: BTreeMap::new(),
            descriptor_directories: custody.directory_states(),
            descriptor_files: BTreeMap::new(),
        };
        let mut total = 0_u64;
        let mut identities = BTreeSet::new();
        for relative in expected_paths() {
            let (size, sha256, physical, state) = hash_file(custody, &relative)?;
            total = total
                .checked_add(size)
                .context("B4 evidence total overflow")?;
            ensure!(
                total <= MAX_TOTAL_BYTES,
                "B4 evidence exceeds its total byte bound"
            );
            ensure!(
                identities.insert((state.device, state.inode, state.mount_id)),
                "published B4 tree aliases one physical file at multiple paths"
            );
            snapshot.files.push(EvidenceEntry {
                path: relative.clone(),
                sha256,
                size,
            });
            ensure!(
                snapshot
                    .physical_files
                    .insert(relative.clone(), physical)
                    .is_none(),
                "published B4 tree repeats a physical-file path"
            );
            ensure!(
                snapshot.descriptor_files.insert(relative, state).is_none(),
                "published B4 tree repeats a descriptor-file path"
            );
        }
        snapshot
            .files
            .sort_unstable_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        custody.reauthenticate_directories()?;
        Ok(snapshot)
    }

    pub(super) fn read_captured_entry(
        custody: &DescriptorBuildCustody,
        relative: &str,
        entry: &EvidenceEntry,
        state: Option<&DescriptorObjectState>,
        maximum: u64,
        label: &str,
    ) -> Result<Vec<u8>> {
        let state =
            state.with_context(|| format!("B4 evidence lacks descriptor state for {relative}"))?;
        let captured = capture_file(
            custody,
            relative,
            Some(&FileBinding {
                size: entry.size,
                sha256: entry.sha256.clone(),
                physical: Some(PhysicalFileIdentity {
                    device: state.device,
                    inode: state.inode,
                    links: state.links,
                }),
                descriptor_state: Some(*state),
            }),
            maximum,
            label,
        )?;
        Ok(captured.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::canonical_json_bytes;
    use crate::cargo_closure::{
        CargoConfigurationEvidence, RISC0_CARGO_SOURCE_REPOSITORY, RISC0_CARGO_SOURCE_REVISION,
        derive_cargo_closure_evidence,
    };
    use crate::test_support::{program_binary, tempdir, valid_program_fixture};
    use serde_json::{Value, json};
    use std::fmt::Write as _;
    use std::path::PathBuf;

    const TEST_SOURCE_COMMIT: &str = "1111111111111111111111111111111111111111";
    const TEST_SOURCE_TREE: &str = "2222222222222222222222222222222222222222";
    const TEST_EVIDENCE_ROOT: &str =
        "d19a4ad9100509217c9ae79213a389481fc9cb9831edfb29ec49e1481a0a49db";

    #[test]
    fn b4_build_runner_lock_sha_literals_match_checked_in_lockfiles() {
        let runner = include_str!("../b4-build/container-build.sh");
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("reproduction crate must be inside the workspace");
        let roles = [
            ("reproduction", workspace.join("Cargo.lock")),
            ("methods", workspace.join("methods/Cargo.lock")),
            ("guest", workspace.join("methods/guest/Cargo.lock")),
            ("generator", workspace.join("generator/Cargo.lock")),
        ];

        for (role, lock_path) in roles {
            let prefix = format!("readonly expected_{role}_lock_sha=");
            let assignments = runner
                .lines()
                .filter_map(|line| line.strip_prefix(&prefix))
                .collect::<Vec<_>>();
            assert_eq!(
                assignments.len(),
                1,
                "runner must contain exactly one {prefix}<sha256> assignment"
            );

            let measured =
                sha256_hex(&fs::read(&lock_path).unwrap_or_else(|error| {
                    panic!("cannot read {}: {error}", lock_path.display())
                }));
            assert_eq!(
                assignments[0],
                measured,
                "{role} lock authority differs from {}",
                lock_path.display()
            );
        }
    }

    #[test]
    fn b4_build_runner_source_tree_matches_candidate_source_lock() {
        const EXPECTED_RISC0_TREE: &str = "a4e8abc0fffa0eab25f66266150f998f581f1cac";
        let runner = include_str!("../b4-build/container-build.sh");
        let source_lock = include_str!("source_lock.rs");
        let runner_prefix = "readonly declared_source_tree=";
        let source_lock_prefix = "const SOURCE_TREE: &str = \"";

        let runner_assignments = runner
            .lines()
            .filter_map(|line| line.strip_prefix(runner_prefix))
            .collect::<Vec<_>>();
        let source_lock_assignments = source_lock
            .lines()
            .filter_map(|line| {
                line.strip_prefix(source_lock_prefix)
                    .and_then(|value| value.strip_suffix("\";"))
            })
            .collect::<Vec<_>>();

        assert_eq!(runner_assignments, [EXPECTED_RISC0_TREE]);
        assert_eq!(source_lock_assignments, [EXPECTED_RISC0_TREE]);
    }

    #[test]
    fn proof_generation_marker_requires_exact_twice_proof_and_lift() {
        assert!(
            PROOF_GENERATION_TESTS
                .starts_with("schema=eip0045-proof-generation-tests-v2\nstatus=passed\n")
        );
        assert!(PROOF_GENERATION_TESTS.contains("features=proof-generation\n"));
        assert!(PROOF_GENERATION_TESTS.contains("embeddedMethodFeatures=embedded-method\n"));
        assert!(PROOF_GENERATION_TESTS.contains(
            "embeddedMethodExactTest=recursive::tests::pinned_guest_explicit_root_twice_proves_duplicate_heads_and_lift\n"
        ));
        assert!(PROOF_GENERATION_TESTS.ends_with("network=offline\n"));

        let runner = include_str!("../b4-build/container-build.sh");
        let exact_test =
            "recursive::tests::pinned_guest_explicit_root_twice_proves_duplicate_heads_and_lift";
        assert!(runner.contains(&format!("readonly embedded_exact_test={exact_test}")));
        assert!(runner.contains("-- --ignored --exact --list --format terse"));
        assert!(runner.contains("[ \"$embedded_test_listing\" = \"$embedded_exact_test: test\" ]"));
        let listing_gate = runner
            .find("embedded_test_listing=$(")
            .expect("runner must enumerate the exact proof test");
        let selection_gate = runner
            .find("[ \"$embedded_test_listing\" = \"$embedded_exact_test: test\" ]")
            .expect("runner must require exactly one enumerated proof test");
        let proof_run = runner[selection_gate..]
            .find("cargo test --manifest-path /workspace/generator/Cargo.toml --release --lib")
            .map(|offset| selection_gate + offset)
            .expect("runner must execute the enumerated proof test");
        let marker_write = runner
            .find("} > /output/proof-generation-tests.txt")
            .expect("runner must write the proof marker");
        assert!(
            listing_gate < selection_gate && selection_gate < proof_run && proof_run < marker_write
        );
    }

    fn emit_manifest(entries: &[EvidenceEntry]) -> Vec<u8> {
        let mut output = String::new();
        for entry in entries {
            writeln!(
                &mut output,
                "file path={} sha256={} size={}",
                entry.path, entry.sha256, entry.size
            )
            .unwrap();
        }
        output.into_bytes()
    }

    fn emit_marker(
        manifest: &[u8],
        guest: &str,
        image_id: &str,
        alternate_guest: &str,
        alternate_image_id: &str,
    ) -> Vec<u8> {
        format!(
            "schema={COMPLETION_SCHEMA}\nstatus=complete\nrunCount=2\ninputIsolation={INPUT_ISOLATION}\nexecutionIsolation={EXECUTION_ISOLATION}\nruntimeManifest={RUNTIME_MANIFEST}\nevidenceManifestSha256={}\nguestElfSha256={guest}\nimageIdSha256={image_id}\nalternateProgramGuestElfSha256={alternate_guest}\nalternateProgramImageIdSha256={alternate_image_id}\n",
            sha256_hex(manifest)
        ).into_bytes()
    }

    fn source_entries() -> Vec<MaterializedFileEntry> {
        vec![
            MaterializedFileEntry {
                path: "Cargo.lock".to_owned(),
                byte_length: 243_680,
                sha256: "5a108fef13e051f497679ef07ba887230ba355d281c109691dbcd24d92328382"
                    .to_owned(),
                executable: false,
            },
            MaterializedFileEntry {
                path: "groth16_proof/groth16/stark_verify.circom".to_owned(),
                byte_length: 58_353_446,
                sha256: "a3789471909ba1a13cca783dc5269b25b6d41295abe60234a8075f750017518c"
                    .to_owned(),
                executable: false,
            },
            MaterializedFileEntry {
                path: "risc0/circuit/recursion/src/recursion_zkr.zip".to_owned(),
                byte_length: 59_768_781,
                sha256: "744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849"
                    .to_owned(),
                executable: false,
            },
        ]
    }

    fn workspace_entries() -> Vec<MaterializedFileEntry> {
        vec![
            MaterializedFileEntry {
                path: "Dockerfile.reproduction".to_owned(),
                byte_length: 12,
                sha256: "10".repeat(32),
                executable: false,
            },
            MaterializedFileEntry {
                path: "reproduction/cargo-offline-config.toml".to_owned(),
                byte_length: 24,
                sha256: "20".repeat(32),
                executable: false,
            },
        ]
    }

    fn emit_file_identity_manifest(entries: &[MaterializedFileEntry]) -> Vec<u8> {
        let mut output = String::new();
        for entry in entries {
            writeln!(
                &mut output,
                "file path={} executable={} sha256={} size={}",
                entry.path, entry.executable, entry.sha256, entry.byte_length
            )
            .unwrap();
        }
        output.into_bytes()
    }

    fn candidate_source_lock() -> (CandidateSourceLock, Vec<u8>) {
        let lock = CandidateSourceLock::from_materialized_entries(source_entries()).unwrap();
        let value = serde_json::to_value(&lock).unwrap();
        (lock, canonical_json_bytes(&value).unwrap())
    }

    fn risc0_source() -> String {
        format!(
            "git+{RISC0_CARGO_SOURCE_REPOSITORY}?rev={RISC0_CARGO_SOURCE_REVISION}#{RISC0_CARGO_SOURCE_REVISION}"
        )
    }

    fn cargo_metadata(role: CargoClosureRole) -> Value {
        let local = |name: &str, relative: &str| {
            json!({
                "name": name,
                "id": format!("path+file:///workspace/{relative}#{name}@0.1.0"),
                "source": null,
                "manifest_path": format!("/workspace/{relative}/Cargo.toml")
            })
        };
        let risc0 = |name: &str| {
            json!({
                "name": name,
                "id": format!("git+https://github.com/a-shannon/risc0?rev=x#{name}@3.0.5"),
                "source": risc0_source(),
                "manifest_path": format!("/fixture/cargo/git/checkouts/risc0/{name}/Cargo.toml")
            })
        };
        let node = |package: &Value, features: Vec<&str>| {
            json!({
                "id": package["id"].as_str().unwrap(),
                "features": features
            })
        };
        match role {
            CargoClosureRole::GeneratorHost => {
                let generator = local("eip-0045-generator", "generator");
                let zkvm = risc0("risc0-zkvm");
                let methods = local("eip-0045-methods", "methods");
                json!({
                    "packages": [generator.clone(), zkvm.clone(), methods.clone()],
                    "resolve": {"nodes": [
                        node(&generator, vec![]),
                        node(&zkvm, vec!["client", "disable-dev-mode", "prove"]),
                        node(&methods, vec!["embed-methods"])
                    ]}
                })
            }
            CargoClosureRole::MethodsBuild => {
                let methods = local("eip-0045-methods", "methods");
                let build = risc0("risc0-build");
                json!({
                    "packages": [methods.clone(), build.clone()],
                    "resolve": {"nodes": [
                        node(&methods, vec!["embed-methods"]),
                        node(&build, vec![])
                    ]}
                })
            }
            CargoClosureRole::Guest => {
                let guest = local("eip-0045-guest", "methods/guest");
                let zkvm = risc0("risc0-zkvm");
                let methods = local("eip-0045-methods", "methods");
                json!({
                    "packages": [guest.clone(), zkvm.clone(), methods.clone()],
                    "resolve": {"nodes": [
                        node(&guest, vec![]),
                        node(&zkvm, vec!["std"]),
                        node(&methods, vec![])
                    ]}
                })
            }
        }
    }

    fn cargo_pair(role: CargoClosureRole) -> (Vec<u8>, Vec<u8>) {
        let metadata = cargo_metadata(role);
        let root = ProfileRootIdentity::new(PROFILE_ROOT, PROFILE_ROOT_IDENTITY).unwrap();
        let closure = derive_cargo_closure_evidence(
            &metadata,
            role,
            &root,
            CargoConfigurationEvidence::default(),
        )
        .unwrap();
        let closure = canonical_json_bytes(&serde_json::to_value(closure).unwrap()).unwrap();
        (serde_json::to_vec(&metadata).unwrap(), closure)
    }

    fn image_declaration(symbol: &str, image_id: &[u8; DIGEST_BYTES]) -> Vec<u8> {
        let words = image_id
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()).to_string())
            .collect::<Vec<_>>()
            .join(",");
        format!("pubconst{symbol}_ID:[u32;8]=[{words}];").into_bytes()
    }

    fn workspace_git(commit: &str, tree: &str) -> Vec<u8> {
        format!(
            "head={commit}\ntree={tree}\nstorage=standalone-private-object-store\nstatusBegin\nstatusEnd\n"
        )
        .into_bytes()
    }

    fn create_payload(root: &Path) {
        fs::create_dir(root).unwrap();
        for run in ["run-1", "run-2"] {
            fs::create_dir(root.join(run)).unwrap();
            fs::create_dir(root.join(run).join("statement")).unwrap();
        }
        fs::write(root.join("base-images-inspect.txt"), b"base\n").unwrap();
        fs::write(root.join("runtime-image-inspect.txt"), b"runtime\n").unwrap();
        let chain = decode_digest(CHAIN_DOMAIN_ID_HEX, "test chain-domain ID").unwrap();
        let payload = (0_u8..32).collect::<Vec<_>>();
        let profile = decode_digest(PROFILE_ID_HEX, "test profile ID").unwrap();
        let (guest, program_id) = valid_program_fixture();
        let alternate_program_guest = program_binary(0x0000_0093, 0x0010_0113);
        let alternate_program_id: [u8; DIGEST_BYTES] =
            compute_image_id(&alternate_program_guest).unwrap().into();
        assert_ne!(program_id, alternate_program_id);
        let proposition = reference_contract_proposition(&program_id, &profile).to_vec();
        let contract = contract_id(&proposition);
        let statement =
            ergo_statement_v1(&chain, &profile, &program_id, &proposition, &payload).unwrap();
        let transcript = expected_candidate_transcript(&program_id, &contract, statement.len());
        let (source_lock, source_lock_bytes) = candidate_source_lock();
        let source_manifest = emit_file_identity_manifest(&source_entries());
        let workspace_manifest = emit_file_identity_manifest(&workspace_entries());
        let checkout_admin = emit_file_identity_manifest(&[MaterializedFileEntry {
            path: ".cargo-ok".to_owned(),
            byte_length: 0,
            sha256: sha256_hex(&[]),
            executable: false,
        }]);
        let build_policy = expected_build_policy(&source_lock).into_bytes();
        let source_git = expected_source_git_observation(&source_lock)
            .unwrap()
            .into_bytes();
        let generator_pair = cargo_pair(CargoClosureRole::GeneratorHost);
        let methods_pair = cargo_pair(CargoClosureRole::MethodsBuild);
        let guest_pair = cargo_pair(CargoClosureRole::Guest);
        let image_hex = format!("{}\n", hex::encode(program_id)).into_bytes();
        let consumer_image_declaration = image_declaration("EIP_0045_GUEST", &program_id);
        let alternate_program_image_hex =
            format!("{}\n", hex::encode(alternate_program_id)).into_bytes();
        let alternate_program_image_declaration =
            image_declaration("EIP_0045_ALTERNATE_PROGRAM_GUEST", &alternate_program_id);
        let workspace_git = workspace_git(TEST_SOURCE_COMMIT, TEST_SOURCE_TREE);
        for file in RUN_EVIDENCE_FILES {
            let bytes = match file {
                "build-policy.txt" => build_policy.clone(),
                "candidate-source-lock-first.json"
                | "candidate-source-lock-second.json"
                | "candidate-source-lock.json" => source_lock_bytes.clone(),
                "cargo-metadata-generator-host.json" => generator_pair.0.clone(),
                "cargo-closure-generator-host.json" => generator_pair.1.clone(),
                "cargo-metadata-methods-build.json" => methods_pair.0.clone(),
                "cargo-closure-methods-build.json" => methods_pair.1.clone(),
                "cargo-metadata-guest.json" => guest_pair.0.clone(),
                "cargo-closure-guest.json" => guest_pair.1.clone(),
                "image-id.bin" | "statement/candidate-program-id.bin" => program_id.to_vec(),
                "image-id.hex" => image_hex.clone(),
                "image-id-declaration.txt" => consumer_image_declaration.clone(),
                "guest.elf" => guest.clone(),
                "alternate-program-image-id.bin" => alternate_program_id.to_vec(),
                "alternate-program-image-id.hex" => alternate_program_image_hex.clone(),
                "alternate-program-image-id-declaration.txt" => {
                    alternate_program_image_declaration.clone()
                }
                "alternate-program-guest.elf" => alternate_program_guest.clone(),
                "proof-generation-tests.txt" => PROOF_GENERATION_TESTS.as_bytes().to_vec(),
                "reproduction-invariants.txt" => b"EIP-0045 pinned invariants: ok\n".to_vec(),
                "source-checkout-admin-manifest-before.txt"
                | "source-checkout-admin-manifest-after.txt"
                | "source-checkout-admin-manifest.txt" => checkout_admin.clone(),
                "source-git-observed.txt" => source_git.clone(),
                "source-materialized-manifest-before.txt"
                | "source-materialized-manifest-after.txt"
                | "source-materialized-manifest.txt" => source_manifest.clone(),
                "statement/application-payload.bin" => payload.clone(),
                "statement/candidate-contract-id.bin" => contract.to_vec(),
                "statement/candidate-proposition.bin" => proposition.clone(),
                "statement/candidate-statement-transcript.txt" => transcript.clone(),
                "statement/candidate-statement.bin" => statement.clone(),
                "statement/chain-domain-id.bin" => chain.to_vec(),
                "statement/inputs.txt" => Vec::new(),
                "statement/profile-id.bin" => profile.to_vec(),
                "workspace-git-before.txt" | "workspace-git-after.txt" | "workspace-git.txt" => {
                    workspace_git.clone()
                }
                "workspace-source-manifest-before.txt"
                | "workspace-source-manifest-after.txt"
                | "workspace-source-manifest.txt" => workspace_manifest.clone(),
                _ => format!("{file}\n").into_bytes(),
            };
            for run in ["run-1", "run-2"] {
                fs::write(root.join(run).join(file), &bytes).unwrap();
            }
        }
        let (_, generator_sha256) =
            hash_regular_file(&root.join("run-1/candidate-generator")).unwrap();
        let (_, guest_elf_sha256) = hash_regular_file(&root.join("run-1/guest.elf")).unwrap();
        let inputs = expected_statement_inputs(
            &generator_sha256,
            &guest_elf_sha256,
            &program_id,
            &transcript,
        )
        .unwrap();
        for run in ["run-1", "run-2"] {
            fs::write(root.join(run).join("statement/inputs.txt"), &inputs).unwrap();
        }
        refresh_identity_record(root);
        refresh_run_identity(root);
    }

    fn rebind_candidate_identity(root: &Path, program_id: [u8; DIGEST_BYTES], proposition: &[u8]) {
        let chain = decode_digest(CHAIN_DOMAIN_ID_HEX, "test chain-domain ID").unwrap();
        let profile = decode_digest(PROFILE_ID_HEX, "test profile ID").unwrap();
        let payload = (0_u8..32).collect::<Vec<_>>();
        let contract = contract_id(proposition);
        let statement =
            ergo_statement_v1(&chain, &profile, &program_id, proposition, &payload).unwrap();
        let transcript = expected_candidate_transcript(&program_id, &contract, statement.len());
        for run in ["run-1", "run-2"] {
            let run_root = root.join(run);
            fs::write(run_root.join("image-id.bin"), program_id).unwrap();
            fs::write(
                run_root.join("statement/candidate-program-id.bin"),
                program_id,
            )
            .unwrap();
            fs::write(
                run_root.join("statement/candidate-proposition.bin"),
                proposition,
            )
            .unwrap();
            fs::write(
                run_root.join("statement/candidate-contract-id.bin"),
                contract,
            )
            .unwrap();
            fs::write(
                run_root.join("statement/candidate-statement.bin"),
                &statement,
            )
            .unwrap();
            fs::write(
                run_root.join("statement/candidate-statement-transcript.txt"),
                &transcript,
            )
            .unwrap();
        }
        let (_, generator_sha256) =
            hash_regular_file(&root.join("run-1/candidate-generator")).unwrap();
        let (_, guest_elf_sha256) = hash_regular_file(&root.join("run-1/guest.elf")).unwrap();
        let inputs = expected_statement_inputs(
            &generator_sha256,
            &guest_elf_sha256,
            &program_id,
            &transcript,
        )
        .unwrap();
        for run in ["run-1", "run-2"] {
            fs::write(root.join(run).join("statement/inputs.txt"), &inputs).unwrap();
        }
        refresh_run_identity(root);
    }

    fn current_run_snapshot(root: &Path) -> TreeSnapshot {
        let mut files = Vec::new();
        let mut physical_files = BTreeMap::new();
        for run in ["run-1", "run-2"] {
            for file in RUN_EVIDENCE_FILES {
                let path = format!("{run}/{file}");
                let (size, sha256, physical) = hash_regular_file_bound(&root.join(&path)).unwrap();
                files.push(EvidenceEntry {
                    path: path.clone(),
                    sha256,
                    size,
                });
                if let Some(physical) = physical {
                    physical_files.insert(path, physical);
                }
            }
        }
        TreeSnapshot {
            directories: EXPECTED_DIRECTORIES.map(str::to_owned).to_vec(),
            files,
            physical_files,
            #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
            descriptor_directories: BTreeMap::new(),
            #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
            descriptor_files: BTreeMap::new(),
        }
    }

    fn refresh_identity_record(root: &Path) {
        let run_root = root.join("run-1");
        let lock_value = validate_canonical_json_source(
            &fs::read(run_root.join("candidate-source-lock.json")).unwrap(),
        )
        .unwrap();
        let lock: CandidateSourceLock = serde_json::from_value(lock_value).unwrap();
        let workspace_manifest = parse_file_identity_manifest(
            &fs::read(run_root.join("workspace-source-manifest.txt")).unwrap(),
            false,
            "test workspace manifest",
        )
        .unwrap();
        let snapshot = current_run_snapshot(root);
        let archive = CapturedArchive::new(root, &snapshot);
        let identity =
            expected_identity_record(&archive, "run-1", &lock, &workspace_manifest).unwrap();
        for run in ["run-1", "run-2"] {
            fs::write(root.join(run).join("identity.txt"), &identity).unwrap();
        }
    }

    fn refresh_run_identity(root: &Path) {
        let run_one = RUN_EVIDENCE_FILES
            .into_iter()
            .map(|file| {
                let (size, sha256) = hash_regular_file(&root.join("run-1").join(file)).unwrap();
                EvidenceEntry {
                    path: file.to_owned(),
                    sha256,
                    size,
                }
            })
            .collect::<Vec<_>>();
        fs::write(root.join(RUN_IDENTITY_FILE), emit_manifest(&run_one)).unwrap();
    }

    fn rebind(root: &Path) {
        for reserved in [COMPLETE_FILE, MANIFEST_FILE] {
            if root.join(reserved).exists() {
                fs::remove_file(root.join(reserved)).unwrap();
            }
        }
        let snapshot = capture_tree(root).unwrap();
        let manifest = emit_manifest(&snapshot.files);
        fs::write(root.join(MANIFEST_FILE), &manifest).unwrap();
        let map = entry_map(&snapshot.files);
        fs::write(
            root.join(COMPLETE_FILE),
            emit_marker(
                &manifest,
                &require_entry(&map, "run-1/guest.elf").unwrap().sha256,
                &require_entry(&map, "run-1/image-id.bin").unwrap().sha256,
                &require_entry(&map, "run-1/alternate-program-guest.elf")
                    .unwrap()
                    .sha256,
                &require_entry(&map, "run-1/alternate-program-image-id.bin")
                    .unwrap()
                    .sha256,
            ),
        )
        .unwrap();
    }

    fn valid_root() -> (crate::test_support::TempDir, PathBuf) {
        let temp = tempdir().unwrap();
        let root = temp.path().join("published");
        create_payload(&root);
        rebind(&root);
        (temp, root)
    }

    fn write_both_runs(root: &Path, file: &str, bytes: &[u8]) {
        for run in ["run-1", "run-2"] {
            fs::write(root.join(run).join(file), bytes).unwrap();
        }
    }

    fn write_snapshot_group(root: &Path, files: &[&str], bytes: &[u8]) {
        for file in files {
            write_both_runs(root, file, bytes);
        }
    }

    fn fully_rebind(root: &Path) {
        refresh_identity_record(root);
        refresh_run_identity(root);
        rebind(root);
    }

    fn outer_rebind(root: &Path) {
        refresh_run_identity(root);
        rebind(root);
    }

    fn replace_marker_line(root: &Path, index: usize, replacement: &str) {
        let source = fs::read_to_string(root.join(COMPLETE_FILE)).unwrap();
        let mut lines = source
            .strip_suffix('\n')
            .unwrap()
            .split('\n')
            .collect::<Vec<_>>();
        lines[index] = replacement;
        fs::write(root.join(COMPLETE_FILE), format!("{}\n", lines.join("\n"))).unwrap();
    }

    #[test]
    fn accepts_exact_published_tree() {
        let (_temp, root) = valid_root();
        let result = validate_published_b4_build(root).unwrap();
        assert_eq!(result.source_binding, B4SourceBindingStatus::Unbound);
        assert_eq!(result.provided_digest_matched, None);
        assert_eq!(result.runner_claims, B4RunnerClaimStatus::Unattested);
        assert_eq!(result.computed_evidence_root, TEST_EVIDENCE_ROOT);
        assert_eq!(result.opaque_artifacts.len(), 12);
        assert!(result.authoritative_projection().is_none());
    }

    #[test]
    fn authoritative_projection_remains_consumer_only() {
        let source = include_str!("b4_build_check.rs");
        let fields = source
            .split("pub struct AuthoritativeB4BuildProjection {")
            .nth(1)
            .unwrap()
            .split("\n}\n\nimpl AuthoritativeB4BuildProjection")
            .next()
            .unwrap();
        assert!(fields.contains("guest_elf_sha256"));
        assert!(fields.contains("image_id_hex"));
        assert!(!fields.contains("alternate"));
    }

    #[cfg(unix)]
    #[test]
    fn accepts_caller_owned_source_and_evidence_root_anchor() {
        let (_temp, root) = valid_root();
        let expectations = B4BuildExpectations {
            expected_source_commit: Some(TEST_SOURCE_COMMIT),
            expected_source_tree: Some(TEST_SOURCE_TREE),
            expected_evidence_root: Some(TEST_EVIDENCE_ROOT),
        };
        let anchored = validate_published_b4_build_with_expectations(&root, &expectations).unwrap();
        assert_eq!(anchored.source_binding, B4SourceBindingStatus::Matched);
        assert_eq!(anchored.provided_digest_matched, Some(true));
        assert_eq!(
            anchored.filesystem_binding,
            B4FilesystemBindingStatus::UnixFileIdentityBound
        );
        assert_eq!(anchored.runner_claims, B4RunnerClaimStatus::Unattested);
        let projection = anchored
            .authoritative_projection()
            .expect("anchored Unix validation must expose the authoritative projection");
        assert_eq!(projection.evidence_root_sha256(), TEST_EVIDENCE_ROOT);
        assert_eq!(projection.source_commit(), TEST_SOURCE_COMMIT);
        assert_eq!(projection.source_tree(), TEST_SOURCE_TREE);
    }

    #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
    #[test]
    fn descriptor_rooted_validation_matches_anchored_path_validation() {
        use std::os::fd::AsFd as _;

        let (_temp, root) = valid_root();
        let expectations = B4BuildExpectations {
            expected_source_commit: Some(TEST_SOURCE_COMMIT),
            expected_source_tree: Some(TEST_SOURCE_TREE),
            expected_evidence_root: Some(TEST_EVIDENCE_ROOT),
        };
        let path_validation = validate_published_b4_build_from_root(
            ValidationRoot::Path(&root),
            validate_external_expectations(&expectations).unwrap(),
        )
        .unwrap();
        let root_directory = File::open(&root).unwrap();
        let descriptor_validation = validate_published_b4_build_from_directory_descriptor(
            root_directory.as_fd(),
            &expectations,
        )
        .unwrap();

        assert_eq!(descriptor_validation, path_validation);
    }

    #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
    #[test]
    fn descriptor_rooted_authority_ignores_replaced_root_pathname() {
        use std::os::fd::AsFd as _;

        let (temp, root) = valid_root();
        let root_directory = File::open(&root).unwrap();
        let retained_name = temp.path().join("retained-published");
        fs::rename(&root, &retained_name).unwrap();
        fs::create_dir(&root).unwrap();

        let validation = validate_published_b4_build_from_directory_descriptor(
            root_directory.as_fd(),
            &B4BuildExpectations {
                expected_source_commit: Some(TEST_SOURCE_COMMIT),
                expected_source_tree: Some(TEST_SOURCE_TREE),
                expected_evidence_root: Some(TEST_EVIDENCE_ROOT),
            },
        )
        .unwrap();

        assert!(validation.authoritative_projection().is_some());
    }

    #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
    fn descriptor_expectations() -> B4BuildExpectations<'static> {
        B4BuildExpectations {
            expected_source_commit: Some(TEST_SOURCE_COMMIT),
            expected_source_tree: Some(TEST_SOURCE_TREE),
            expected_evidence_root: Some(TEST_EVIDENCE_ROOT),
        }
    }

    #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
    fn descriptor_file_binding(snapshot: &TreeSnapshot, relative: &str) -> FileBinding {
        let entry = snapshot
            .files
            .iter()
            .find(|entry| entry.path == relative)
            .unwrap();
        FileBinding {
            size: entry.size,
            sha256: entry.sha256.clone(),
            physical: snapshot.physical_files.get(relative).copied(),
            descriptor_state: snapshot.descriptor_files.get(relative).copied(),
        }
    }

    #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
    #[test]
    fn descriptor_rooted_unanchored_inspection_remains_non_authoritative() {
        use std::os::fd::AsFd as _;

        let (_temp, root) = valid_root();
        let path_validation =
            validate_published_b4_build_from_root(ValidationRoot::Path(&root), None).unwrap();
        let root_directory = File::open(root).unwrap();
        let validation = validate_published_b4_build_from_directory_descriptor(
            root_directory.as_fd(),
            &B4BuildExpectations::default(),
        )
        .unwrap();

        assert_eq!(validation.source_binding, B4SourceBindingStatus::Unbound);
        assert_eq!(validation.provided_digest_matched, None);
        assert!(validation.authoritative_projection().is_none());
        assert_eq!(validation, path_validation);
    }

    #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
    #[test]
    fn descriptor_rooted_validation_rejects_a_non_directory_descriptor() {
        use std::os::fd::AsFd as _;

        let temp = tempdir().unwrap();
        let file_path = temp.path().join("ordinary-file");
        fs::write(&file_path, b"not a directory").unwrap();
        let file = File::open(file_path).unwrap();
        let error = validate_published_b4_build_from_directory_descriptor(
            file.as_fd(),
            &B4BuildExpectations::default(),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("directory") || error.contains("open"));
    }

    #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
    #[test]
    fn descriptor_rooted_validation_rejects_extra_and_missing_entries() {
        use std::os::fd::AsFd as _;

        let (_temp, extra_root) = valid_root();
        fs::write(extra_root.join("unexpected"), b"extra").unwrap();
        let extra_directory = File::open(&extra_root).unwrap();
        let extra_error = validate_published_b4_build_from_directory_descriptor(
            extra_directory.as_fd(),
            &descriptor_expectations(),
        )
        .unwrap_err()
        .to_string();
        assert!(extra_error.contains("missing or extra entry"));

        let (_temp, missing_root) = valid_root();
        fs::remove_file(missing_root.join("run-1/build-environment.txt")).unwrap();
        let missing_directory = File::open(&missing_root).unwrap();
        let missing_error = validate_published_b4_build_from_directory_descriptor(
            missing_directory.as_fd(),
            &descriptor_expectations(),
        )
        .unwrap_err()
        .to_string();
        assert!(missing_error.contains("missing or extra entry"));

        let (_temp, nested_extra_root) = valid_root();
        fs::write(nested_extra_root.join("run-1/unexpected"), b"extra").unwrap();
        let nested_extra_directory = File::open(&nested_extra_root).unwrap();
        let nested_extra_error = validate_published_b4_build_from_directory_descriptor(
            nested_extra_directory.as_fd(),
            &descriptor_expectations(),
        )
        .unwrap_err()
        .to_string();
        assert!(nested_extra_error.contains("missing or extra entry"));
    }

    #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
    #[test]
    fn descriptor_rooted_validation_rejects_non_utf8_inventory_entries() {
        use std::{
            ffi::OsString,
            os::{fd::AsFd as _, unix::ffi::OsStringExt as _},
        };

        let (_temp, root) = valid_root();
        fs::write(root.join(OsString::from_vec(vec![0xff, 0xfe])), b"extra").unwrap();
        let root_directory = File::open(root).unwrap();

        assert!(
            validate_published_b4_build_from_directory_descriptor(
                root_directory.as_fd(),
                &descriptor_expectations(),
            )
            .is_err()
        );
    }

    #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
    #[test]
    fn descriptor_rooted_validation_rejects_links_and_special_files() {
        use std::os::{
            fd::AsFd as _,
            unix::{fs::symlink, net::UnixListener},
        };

        let (_temp, symlink_root) = valid_root();
        let symlink_path = symlink_root.join("run-2/identity.txt");
        fs::remove_file(&symlink_path).unwrap();
        symlink("../run-1/identity.txt", &symlink_path).unwrap();
        let symlink_directory = File::open(&symlink_root).unwrap();
        let symlink_error = validate_published_b4_build_from_directory_descriptor(
            symlink_directory.as_fd(),
            &descriptor_expectations(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            symlink_error.contains("not an ordinary regular file"),
            "unexpected symlink error: {symlink_error}"
        );

        let (_temp, hardlink_root) = valid_root();
        let hardlink_path = hardlink_root.join("run-2/identity.txt");
        fs::remove_file(&hardlink_path).unwrap();
        fs::hard_link(hardlink_root.join("run-1/identity.txt"), &hardlink_path).unwrap();
        let hardlink_directory = File::open(&hardlink_root).unwrap();
        let hardlink_error = validate_published_b4_build_from_directory_descriptor(
            hardlink_directory.as_fd(),
            &descriptor_expectations(),
        )
        .unwrap_err()
        .to_string();
        assert!(hardlink_error.contains("hard-linked B4 file"));

        let (_temp, socket_root) = valid_root();
        let socket_path = socket_root.join("run-2/identity.txt");
        fs::remove_file(&socket_path).unwrap();
        let _socket = UnixListener::bind(&socket_path).unwrap();
        let socket_directory = File::open(&socket_root).unwrap();
        let socket_error = validate_published_b4_build_from_directory_descriptor(
            socket_directory.as_fd(),
            &descriptor_expectations(),
        )
        .unwrap_err()
        .to_string();
        assert!(socket_error.contains("not an ordinary regular file"));

        let (directory_symlink_temp, directory_symlink_root) = valid_root();
        let held_run = directory_symlink_temp.path().join("held-run-2");
        fs::rename(directory_symlink_root.join("run-2"), &held_run).unwrap();
        symlink(&held_run, directory_symlink_root.join("run-2")).unwrap();
        let directory_symlink = File::open(&directory_symlink_root).unwrap();
        let directory_symlink_error = validate_published_b4_build_from_directory_descriptor(
            directory_symlink.as_fd(),
            &descriptor_expectations(),
        )
        .unwrap_err()
        .to_string();
        assert!(directory_symlink_error.contains("cannot open descriptor-rooted B4 directory"));
    }

    #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
    #[test]
    fn descriptor_rooted_file_windows_reject_deterministic_races() {
        use std::os::fd::AsFd as _;

        use descriptor_build_check_linux::DescriptorFileReadStage;

        for attacked_stage in [
            DescriptorFileReadStage::PathPinned,
            DescriptorFileReadStage::DataOpened,
            DescriptorFileReadStage::BytesRead,
        ] {
            let (temp, root) = valid_root();
            let root_directory = File::open(&root).unwrap();
            let custody =
                descriptor_build_check_linux::DescriptorBuildCustody::open(root_directory.as_fd())
                    .unwrap();
            let snapshot = descriptor_build_check_linux::capture_tree(&custody).unwrap();
            let relative = "run-1/build-environment.txt";
            let binding = descriptor_file_binding(&snapshot, relative);
            let path = root.join(relative);
            let original = fs::read(&path).unwrap();
            let held = temp.path().join(format!("held-{attacked_stage:?}"));
            let mut attacked = false;

            let error = descriptor_build_check_linux::capture_file_with_test_hook(
                &custody,
                relative,
                Some(&binding),
                MAX_SEMANTIC_TEXT_BYTES,
                "race fixture",
                |stage, _bytes| {
                    if stage == attacked_stage && !attacked {
                        if stage == DescriptorFileReadStage::DataOpened {
                            let mut mutated = original.clone();
                            mutated[0] ^= 1;
                            fs::write(&path, mutated)?;
                        } else {
                            fs::rename(&path, &held)?;
                            fs::write(&path, &original)?;
                        }
                        attacked = true;
                    }
                    Ok(())
                },
            )
            .unwrap_err()
            .to_string();

            assert!(
                error.contains("changed")
                    || error.contains("identity")
                    || error.contains("SHA-256"),
                "unexpected error for {attacked_stage:?}: {error}"
            );
        }
    }

    #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
    #[test]
    fn descriptor_rooted_parent_pin_rejects_transient_subtree_substitution() {
        use std::os::fd::AsFd as _;

        use descriptor_build_check_linux::DescriptorFileReadStage;

        let (temp, root) = valid_root();
        let root_directory = File::open(&root).unwrap();
        let custody =
            descriptor_build_check_linux::DescriptorBuildCustody::open(root_directory.as_fd())
                .unwrap();
        let relative = "run-1/build-environment.txt";
        let original = fs::read(root.join(relative)).unwrap();
        let attacker = b"attacker-controlled";
        let retained_run = temp.path().join("retained-run-1");
        let replacement_run = root.join("run-1");
        let mut substituted = false;
        let mut observed = None;

        let error = descriptor_build_check_linux::capture_file_with_test_hook(
            &custody,
            relative,
            None,
            MAX_SEMANTIC_TEXT_BYTES,
            "subtree race fixture",
            |stage, bytes| {
                if stage == DescriptorFileReadStage::DirectoriesAuthenticated && !substituted {
                    fs::rename(&replacement_run, &retained_run)?;
                    fs::create_dir(&replacement_run)?;
                    fs::write(replacement_run.join("build-environment.txt"), attacker)?;
                    substituted = true;
                } else if stage == DescriptorFileReadStage::FileRepinned {
                    observed = Some(
                        bytes
                            .ok_or_else(|| anyhow::anyhow!("repinned hook lacks captured bytes"))?
                            .to_vec(),
                    );
                    fs::remove_file(replacement_run.join("build-environment.txt"))?;
                    fs::remove_dir(&replacement_run)?;
                    fs::rename(&retained_run, &replacement_run)?;
                }
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("directory") || error.contains("changed"));
        assert_eq!(observed.as_deref(), Some(original.as_slice()));
        assert_ne!(observed.as_deref(), Some(attacker.as_slice()));
    }

    #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
    #[test]
    fn descriptor_rooted_semantic_reread_rejects_byte_identical_inode_substitution() {
        use std::os::fd::AsFd as _;

        let (temp, root) = valid_root();
        let root_directory = File::open(&root).unwrap();
        let custody =
            descriptor_build_check_linux::DescriptorBuildCustody::open(root_directory.as_fd())
                .unwrap();
        let snapshot = descriptor_build_check_linux::capture_tree(&custody).unwrap();
        let archive = CapturedArchive::from_root(ValidationRoot::Descriptor(&custody), &snapshot);
        let relative = "run-1/build-environment.txt";
        let original = fs::read(root.join(relative)).unwrap();
        fs::rename(
            root.join(relative),
            temp.path().join("held-build-environment"),
        )
        .unwrap();
        fs::write(root.join(relative), original).unwrap();

        let error = archive
            .read(relative, MAX_SEMANTIC_TEXT_BYTES, "substitution fixture")
            .unwrap_err()
            .to_string();
        assert!(error.contains("changed") || error.contains("identity"));
    }

    #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
    #[test]
    fn descriptor_rooted_repeated_and_concurrent_calls_do_not_share_offsets() {
        use std::{
            os::fd::AsFd as _,
            sync::{Arc, Barrier},
            thread,
        };

        let (_temp, root) = valid_root();
        let root_directory = Arc::new(File::open(root).unwrap());
        let mut advanced = rustix::fs::Dir::read_from(root_directory.as_fd()).unwrap();
        assert!(advanced.next().is_some());
        drop(advanced);

        let first = validate_published_b4_build_from_directory_descriptor(
            root_directory.as_fd(),
            &descriptor_expectations(),
        )
        .unwrap();
        let second = validate_published_b4_build_from_directory_descriptor(
            root_directory.as_fd(),
            &descriptor_expectations(),
        )
        .unwrap();
        assert_eq!(first, second);

        let barrier = Arc::new(Barrier::new(2));
        let workers = (0..2)
            .map(|_| {
                let root_directory = Arc::clone(&root_directory);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    validate_published_b4_build_from_directory_descriptor(
                        root_directory.as_fd(),
                        &descriptor_expectations(),
                    )
                    .unwrap()
                })
            })
            .collect::<Vec<_>>();
        let concurrent = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(concurrent, vec![first.clone(), first]);
    }

    #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
    #[test]
    fn descriptor_rooted_backend_has_no_ambient_path_or_shared_offset_escape() {
        let source = include_str!("b4_build_check.rs");
        let backend = source
            .split("mod descriptor_build_check_linux {")
            .nth(1)
            .unwrap()
            .split("\n}\n\n#[cfg(test)]")
            .next()
            .unwrap();

        for required in [
            "rustix::fs::openat2(",
            "ResolveFlags::BENEATH",
            "ResolveFlags::NO_SYMLINKS",
            "ResolveFlags::NO_MAGICLINKS",
            "ResolveFlags::NO_XDEV",
            "rustix::fs::statx(",
            "rustix::fs::Dir::read_from(",
            ".read_at(",
        ] {
            assert!(backend.contains(required), "missing {required}");
        }
        for forbidden in [
            "/proc/self/fd",
            "canonicalize(",
            "root.join(",
            "fs::read_dir(",
            "File::open(",
            ".read(",
            ".seek(",
            "from_raw_fd",
            "unsafe {",
            "std::process",
        ] {
            assert!(!backend.contains(forbidden), "forbidden {forbidden}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn authoritative_validation_is_fail_closed_without_windows_file_ids() {
        let (_temp, root) = valid_root();
        let error = validate_published_b4_build_with_expectations(
            root,
            &B4BuildExpectations {
                expected_source_commit: Some(TEST_SOURCE_COMMIT),
                expected_source_tree: Some(TEST_SOURCE_TREE),
                expected_evidence_root: Some(TEST_EVIDENCE_ROOT),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("requires Unix device/inode/link-count binding"));
    }

    #[test]
    fn external_root_requires_external_source_pair() {
        let (_temp, root) = valid_root();
        let error = validate_published_b4_build_with_expectations(
            root,
            &B4BuildExpectations {
                expected_source_commit: None,
                expected_source_tree: None,
                expected_evidence_root: Some(TEST_EVIDENCE_ROOT),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("requires external source commit"));
    }

    #[test]
    fn rejects_coordinated_source_lock_pin_rewrite() {
        let (_temp, root) = valid_root();
        let source = fs::read(root.join("run-1/candidate-source-lock.json")).unwrap();
        let value = validate_canonical_json_source(&source).unwrap();
        let mut lock: CandidateSourceLock = serde_json::from_value(value).unwrap();
        lock.source.commit = "3333333333333333333333333333333333333333".to_owned();
        let bytes = canonical_json_bytes(&serde_json::to_value(&lock).unwrap()).unwrap();
        write_snapshot_group(
            &root,
            &[
                "candidate-source-lock-first.json",
                "candidate-source-lock-second.json",
                "candidate-source-lock.json",
            ],
            &bytes,
        );
        write_both_runs(
            &root,
            "source-git-observed.txt",
            expected_source_git_observation(&lock).unwrap().as_bytes(),
        );
        fully_rebind(&root);
        let error = validate_published_b4_build(root).unwrap_err().to_string();
        assert!(error.contains("source lock"));
    }

    #[test]
    fn rejects_coordinated_source_manifest_lock_divergence() {
        let (_temp, root) = valid_root();
        let mut entries = source_entries();
        entries[0].executable = true;
        let bytes = emit_file_identity_manifest(&entries);
        write_snapshot_group(
            &root,
            &[
                "source-materialized-manifest-before.txt",
                "source-materialized-manifest-after.txt",
                "source-materialized-manifest.txt",
            ],
            &bytes,
        );
        fully_rebind(&root);
        let error = validate_published_b4_build(root).unwrap_err().to_string();
        assert!(error.contains("differs from candidate source lock"));
    }

    #[test]
    fn rejects_same_cross_run_but_divergent_within_run_snapshots() {
        for file in [
            "candidate-source-lock-first.json",
            "source-materialized-manifest-before.txt",
            "source-checkout-admin-manifest-before.txt",
            "workspace-source-manifest-before.txt",
            "workspace-git-before.txt",
        ] {
            let (_temp, root) = valid_root();
            write_both_runs(&root, file, b"coordinated but divergent\n");
            outer_rebind(&root);
            assert!(
                validate_published_b4_build(&root).is_err(),
                "accepted within-run snapshot divergence for {file}"
            );
        }
    }

    #[test]
    fn rejects_coordinated_cargo_metadata_and_closure_rewrite() {
        let (_temp, root) = valid_root();
        let mut metadata = cargo_metadata(CargoClosureRole::GeneratorHost);
        metadata["resolve"]["nodes"][1]["features"] =
            json!(["client", "cuda", "disable-dev-mode", "prove"]);
        let profile_root = ProfileRootIdentity::new(PROFILE_ROOT, PROFILE_ROOT_IDENTITY).unwrap();
        let closure = derive_cargo_closure_evidence(
            &metadata,
            CargoClosureRole::GeneratorHost,
            &profile_root,
            CargoConfigurationEvidence::default(),
        )
        .unwrap();
        write_both_runs(
            &root,
            "cargo-metadata-generator-host.json",
            &serde_json::to_vec(&metadata).unwrap(),
        );
        write_both_runs(
            &root,
            "cargo-closure-generator-host.json",
            &canonical_json_bytes(&serde_json::to_value(closure).unwrap()).unwrap(),
        );
        fully_rebind(&root);
        let error = validate_published_b4_build(root).unwrap_err().to_string();
        assert!(error.contains("cargo-closure-generator-host.json"));
    }

    #[test]
    fn rejects_coordinated_identity_and_image_representation_rewrites() {
        let (_temp, root) = valid_root();
        write_both_runs(
            &root,
            "image-id.hex",
            format!("{}\n", "00".repeat(32)).as_bytes(),
        );
        fully_rebind(&root);
        assert!(validate_published_b4_build(root).is_err());

        let (_temp, root) = valid_root();
        write_both_runs(
            &root,
            "image-id-declaration.txt",
            b"pubconstEIP_0045_GUEST_ID:[u32;8]=[0,0,0,0,0,0,0,0];",
        );
        fully_rebind(&root);
        assert!(validate_published_b4_build(root).is_err());

        let (_temp, root) = valid_root();
        write_both_runs(
            &root,
            "alternate-program-image-id.hex",
            format!("{}\n", "00".repeat(32)).as_bytes(),
        );
        fully_rebind(&root);
        assert!(validate_published_b4_build(root).is_err());

        let (_temp, root) = valid_root();
        write_both_runs(
            &root,
            "alternate-program-image-id-declaration.txt",
            b"pubconstEIP_0045_ALTERNATE_PROGRAM_GUEST_ID:[u32;8]=[0,0,0,0,0,0,0,0];",
        );
        fully_rebind(&root);
        assert!(validate_published_b4_build(root).is_err());

        let (_temp, root) = valid_root();
        let changed = fs::read_to_string(root.join("run-1/identity.txt"))
            .unwrap()
            .replace("hostRust=1.89.0\n", "hostRust=9.99.0\n");
        write_both_runs(&root, "identity.txt", changed.as_bytes());
        outer_rebind(&root);
        let error = validate_published_b4_build(root).unwrap_err().to_string();
        assert!(error.contains("identity record"));
    }

    #[cfg(unix)]
    #[test]
    fn caller_source_binding_rejects_fully_rebound_workspace_identity() {
        let (_temp, root) = valid_root();
        let changed = workspace_git(
            "4444444444444444444444444444444444444444",
            "5555555555555555555555555555555555555555",
        );
        write_snapshot_group(
            &root,
            &[
                "workspace-git-before.txt",
                "workspace-git-after.txt",
                "workspace-git.txt",
            ],
            &changed,
        );
        fully_rebind(&root);
        assert!(validate_published_b4_build(&root).is_ok());
        let error = validate_published_b4_build_with_expectations(
            root,
            &B4BuildExpectations {
                expected_source_commit: Some(TEST_SOURCE_COMMIT),
                expected_source_tree: Some(TEST_SOURCE_TREE),
                expected_evidence_root: Some(TEST_EVIDENCE_ROOT),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("caller expectation"));
    }

    #[cfg(unix)]
    #[test]
    fn external_root_rejects_fully_rebound_runner_observation() {
        let (_temp, root) = valid_root();
        let initial = validate_published_b4_build(&root).unwrap();
        assert_eq!(initial.computed_evidence_root, TEST_EVIDENCE_ROOT);
        write_both_runs(
            &root,
            "resource-policy-observed.txt",
            b"coherent runner observation with no archive attestation\n",
        );
        fully_rebind(&root);
        let rebound = validate_published_b4_build(&root).unwrap();
        assert_ne!(
            initial.computed_evidence_root,
            rebound.computed_evidence_root
        );
        assert_eq!(rebound.runner_claims, B4RunnerClaimStatus::Unattested);
        let error = validate_published_b4_build_with_expectations(
            root,
            &B4BuildExpectations {
                expected_source_commit: Some(TEST_SOURCE_COMMIT),
                expected_source_tree: Some(TEST_SOURCE_TREE),
                expected_evidence_root: Some(TEST_EVIDENCE_ROOT),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("external commitment"));
    }

    #[test]
    fn rejects_marker_encoding_order_count_and_value_mutations() {
        for kind in ["crlf", "order", "extra", "run-count", "isolation"] {
            let (_temp, root) = valid_root();
            let source = fs::read(root.join(COMPLETE_FILE)).unwrap();
            let mutated = match kind {
                "crlf" => String::from_utf8(source)
                    .unwrap()
                    .replace('\n', "\r\n")
                    .into_bytes(),
                "order" => {
                    let mut lines = exact_ascii_lf_lines(&source, "test").unwrap();
                    lines.swap(0, 1);
                    format!("{}\n", lines.join("\n")).into_bytes()
                }
                "extra" => [source, b"extra=x\n".to_vec()].concat(),
                "run-count" => {
                    replace_marker_line(&root, 2, "runCount=3");
                    fs::read(root.join(COMPLETE_FILE)).unwrap()
                }
                "isolation" => {
                    replace_marker_line(&root, 3, "inputIsolation=machines");
                    fs::read(root.join(COMPLETE_FILE)).unwrap()
                }
                _ => unreachable!(),
            };
            fs::write(root.join(COMPLETE_FILE), mutated).unwrap();
            assert!(
                validate_published_b4_build(root).is_err(),
                "accepted {kind}"
            );
        }
    }

    fn assert_marker_mutation_rejected_causally(
        line: usize,
        replacement: &str,
        expected_error: &str,
    ) {
        let (_temp, root) = valid_root();
        replace_marker_line(&root, line, replacement);

        let error = validate_published_b4_build(root).unwrap_err().to_string();
        assert_eq!(error, expected_error);
    }

    #[test]
    fn rejects_isolated_completion_marker_v1_schema_regression_causally() {
        assert_marker_mutation_rejected_causally(
            0,
            "schema=eip0045-b4-build-completion-v1",
            "B4 marker schema mismatch",
        );
    }

    #[test]
    fn rejects_isolated_completion_marker_unknown_schema_causally() {
        assert_marker_mutation_rejected_causally(
            0,
            "schema=eip0045-b4-build-completion-v3",
            "B4 marker schema mismatch",
        );
    }

    #[test]
    fn rejects_isolated_completion_marker_status_mutation_causally() {
        assert_marker_mutation_rejected_causally(
            1,
            "status=incomplete",
            "B4 marker status mismatch",
        );
    }

    #[test]
    fn rejects_isolated_completion_marker_execution_isolation_mutation_causally() {
        assert_marker_mutation_rejected_causally(
            4,
            "executionIsolation=reused-home-target-or-work",
            "B4 marker executionIsolation mismatch",
        );
    }

    #[test]
    fn rejects_isolated_completion_marker_runtime_manifest_mutation_causally() {
        assert_marker_mutation_rejected_causally(
            5,
            "runtimeManifest=mutable-host-runtime",
            "B4 marker runtimeManifest mismatch",
        );
    }

    #[test]
    fn rejects_manifest_grammar_order_path_and_size_mutations() {
        for kind in ["prefix", "order", "path", "size"] {
            let (_temp, root) = valid_root();
            let source = fs::read_to_string(root.join(MANIFEST_FILE)).unwrap();
            let mut lines = source
                .strip_suffix('\n')
                .unwrap()
                .split('\n')
                .map(str::to_owned)
                .collect::<Vec<_>>();
            match kind {
                "prefix" => lines[0] = lines[0].replacen("file path=", "path=", 1),
                "order" => lines.swap(0, 1),
                "path" => lines[0] = lines[0].replacen("base-images-inspect.txt", "../escape", 1),
                "size" => {
                    let at = lines[0].rfind(" size=").unwrap();
                    lines[0].replace_range(at + 6.., "01");
                }
                _ => unreachable!(),
            }
            fs::write(root.join(MANIFEST_FILE), format!("{}\n", lines.join("\n"))).unwrap();
            assert!(
                validate_published_b4_build(root).is_err(),
                "accepted {kind}"
            );
        }
    }

    #[test]
    fn rejects_marker_manifest_guest_and_image_digest_mutations() {
        for (line, key) in [
            (6, "evidenceManifestSha256"),
            (7, "guestElfSha256"),
            (8, "imageIdSha256"),
            (9, "alternateProgramGuestElfSha256"),
            (10, "alternateProgramImageIdSha256"),
        ] {
            let (_temp, root) = valid_root();
            replace_marker_line(&root, line, &format!("{key}={}", "00".repeat(32)));
            assert!(validate_published_b4_build(root).is_err(), "accepted {key}");
        }
    }

    #[test]
    fn rejects_missing_extra_changed_and_directory_tree_mutations() {
        for kind in ["missing", "extra", "changed", "directory"] {
            let (_temp, root) = valid_root();
            match kind {
                "missing" => fs::remove_file(root.join("run-1/identity.txt")).unwrap(),
                "extra" => fs::write(root.join("unexpected.txt"), b"x").unwrap(),
                "changed" => fs::write(root.join("run-1/identity.txt"), b"changed").unwrap(),
                "directory" => fs::create_dir(root.join("empty")).unwrap(),
                _ => unreachable!(),
            }
            assert!(
                validate_published_b4_build(root).is_err(),
                "accepted {kind}"
            );
        }
    }

    #[test]
    fn rejects_rebound_but_disagreeing_runs_and_run_identity() {
        let (_temp, root) = valid_root();
        fs::write(root.join("run-2/identity.txt"), b"different\n").unwrap();
        rebind(&root);
        assert!(
            validate_published_b4_build(&root)
                .unwrap_err()
                .to_string()
                .contains("run evidence disagrees")
        );

        let (_temp, root) = valid_root();
        fs::write(root.join(RUN_IDENTITY_FILE),
            b"file path=x sha256=0000000000000000000000000000000000000000000000000000000000000000 size=0\n").unwrap();
        rebind(&root);
        assert!(validate_published_b4_build(root).is_err());
    }

    #[test]
    fn rejects_rebound_downstream_semantic_mutations() {
        let mutations = [
            ("proof-generation-tests.txt", b"status=passed\n".to_vec()),
            ("statement/chain-domain-id.bin", vec![0; DIGEST_BYTES]),
            ("statement/application-payload.bin", vec![0; 32]),
            ("statement/profile-id.bin", vec![0; DIGEST_BYTES]),
            ("statement/candidate-program-id.bin", vec![8; DIGEST_BYTES]),
            (
                "statement/candidate-proposition.bin",
                b"changed proposition".to_vec(),
            ),
            ("statement/candidate-contract-id.bin", vec![0; DIGEST_BYTES]),
            ("statement/candidate-statement.bin", b"changed".to_vec()),
            (
                "statement/candidate-statement-transcript.txt",
                b"candidateOnly=true\n".to_vec(),
            ),
            ("statement/inputs.txt", b"proofGenerated=false\n".to_vec()),
        ];
        for (file, bytes) in mutations {
            let (_temp, root) = valid_root();
            for run in ["run-1", "run-2"] {
                fs::write(root.join(run).join(file), &bytes).unwrap();
            }
            refresh_run_identity(&root);
            rebind(&root);
            assert!(
                validate_published_b4_build(&root).is_err(),
                "accepted rebound semantic mutation of {file}"
            );
        }
    }

    #[test]
    fn rejects_rebound_false_elf_image_identity() {
        let (_temp, root) = valid_root();
        let false_guest = program_binary(0x0010_0093, 0x0000_0013);
        let false_image_id: [u8; DIGEST_BYTES] = Sha256::digest(&false_guest).into();
        let actual_image_id: [u8; DIGEST_BYTES] = compute_image_id(&false_guest).unwrap().into();
        assert_ne!(false_image_id, actual_image_id);
        for run in ["run-1", "run-2"] {
            fs::write(root.join(run).join("guest.elf"), &false_guest).unwrap();
        }
        let profile = decode_digest(PROFILE_ID_HEX, "test profile ID").unwrap();
        let proposition = reference_contract_proposition(&false_image_id, &profile);
        rebind_candidate_identity(&root, false_image_id, &proposition);
        rebind(&root);

        let error = validate_published_b4_build(root).unwrap_err().to_string();
        assert!(error.contains("does not equal risc0-binfmt computation"));
    }

    #[test]
    fn rejects_rebound_false_alternate_program_elf_image_identity() {
        let (_temp, root) = valid_root();
        let false_guest = program_binary(0x0020_0093, 0x0000_0013);
        let false_image_id: [u8; DIGEST_BYTES] = Sha256::digest(&false_guest).into();
        let actual_image_id: [u8; DIGEST_BYTES] = compute_image_id(&false_guest).unwrap().into();
        assert_ne!(false_image_id, actual_image_id);
        for run in ["run-1", "run-2"] {
            let run_root = root.join(run);
            fs::write(run_root.join("alternate-program-guest.elf"), &false_guest).unwrap();
            fs::write(
                run_root.join("alternate-program-image-id.bin"),
                false_image_id,
            )
            .unwrap();
            fs::write(
                run_root.join("alternate-program-image-id.hex"),
                format!("{}\n", hex::encode(false_image_id)),
            )
            .unwrap();
            fs::write(
                run_root.join("alternate-program-image-id-declaration.txt"),
                image_declaration("EIP_0045_ALTERNATE_PROGRAM_GUEST", &false_image_id),
            )
            .unwrap();
        }
        fully_rebind(&root);

        let error = validate_published_b4_build(root).unwrap_err().to_string();
        assert!(
            error.contains("alternate-program image ID does not equal risc0-binfmt computation")
        );
    }

    #[test]
    fn rejects_rebound_equal_consumer_and_alternate_program_identities() {
        let (_temp, root) = valid_root();
        let guest = fs::read(root.join("run-1/guest.elf")).unwrap();
        let image_id: [u8; DIGEST_BYTES] = fs::read(root.join("run-1/image-id.bin"))
            .unwrap()
            .try_into()
            .unwrap();
        for run in ["run-1", "run-2"] {
            let run_root = root.join(run);
            fs::write(run_root.join("alternate-program-guest.elf"), &guest).unwrap();
            fs::write(run_root.join("alternate-program-image-id.bin"), image_id).unwrap();
            fs::write(
                run_root.join("alternate-program-image-id.hex"),
                format!("{}\n", hex::encode(image_id)),
            )
            .unwrap();
            fs::write(
                run_root.join("alternate-program-image-id-declaration.txt"),
                image_declaration("EIP_0045_ALTERNATE_PROGRAM_GUEST", &image_id),
            )
            .unwrap();
        }
        fully_rebind(&root);

        let error = validate_published_b4_build(root).unwrap_err().to_string();
        assert!(error.contains("alternate-program image ID equals the consumer image ID"));
    }

    #[test]
    fn rejects_each_isolated_dual_guest_run_disagreement() {
        for file in [
            "guest.elf",
            "image-id.bin",
            "alternate-program-guest.elf",
            "alternate-program-image-id.bin",
        ] {
            let (_temp, root) = valid_root();
            let path = root.join("run-2").join(file);
            let mut bytes = fs::read(&path).unwrap();
            bytes[0] ^= 1;
            fs::write(path, bytes).unwrap();
            rebind(&root);

            let error = validate_published_b4_build(root).unwrap_err().to_string();
            assert!(
                error.contains("run evidence disagrees"),
                "run disagreement for {file} failed at an incidental boundary: {error}"
            );
        }
    }

    #[test]
    fn rejects_rebound_noncanonical_self_consistent_proposition_chain() {
        let (_temp, root) = valid_root();
        let program_id: [u8; DIGEST_BYTES] = fs::read(root.join("run-1/image-id.bin"))
            .unwrap()
            .try_into()
            .unwrap();
        let noncanonical_proposition = b"self-consistent but noncanonical proposition";
        rebind_candidate_identity(&root, program_id, noncanonical_proposition);
        rebind(&root);

        let error = validate_published_b4_build(root).unwrap_err().to_string();
        assert!(error.contains("not the exact 85-byte v4 reference contract"));
    }

    #[test]
    fn rejects_reserved_case_alias() {
        let (_temp, root) = valid_root();
        fs::write(root.join("b4-complete"), b"alias").unwrap();
        assert!(validate_published_b4_build(root).is_err());
    }

    #[test]
    fn captured_entry_rejects_a_same_size_swap_before_open() {
        let (temp, root) = valid_root();
        let snapshot = capture_tree(&root).unwrap();
        let relative = "run-1/build-environment.txt";
        let entry = snapshot
            .files
            .iter()
            .find(|entry| entry.path == relative)
            .unwrap();
        let path = root.join(relative);
        let original = fs::read(&path).unwrap();
        let mut replacement = original.clone();
        replacement[0] ^= 1;
        let held = temp.path().join("held-before-open");
        let replacement_path = temp.path().join("replacement-before-open");
        fs::write(&replacement_path, replacement).unwrap();
        let mut swapped = false;
        let error = read_captured_entry_with_hook(
            &path,
            entry,
            snapshot.physical_files.get(relative),
            MAX_SEMANTIC_TEXT_BYTES,
            "swap fixture",
            |stage, path| {
                if stage == BoundReadStage::PathInspected && !swapped {
                    fs::rename(path, &held)?;
                    fs::rename(&replacement_path, path)?;
                    swapped = true;
                }
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("physical file identity") || error.contains("SHA-256"));
    }

    #[cfg(unix)]
    #[test]
    fn captured_entry_rejects_identical_inode_substitution() {
        let (temp, root) = valid_root();
        let snapshot = capture_tree(&root).unwrap();
        let relative = "run-1/build-environment.txt";
        let entry = snapshot
            .files
            .iter()
            .find(|entry| entry.path == relative)
            .unwrap();
        let path = root.join(relative);
        let original = fs::read(&path).unwrap();
        let held = temp.path().join("held-identical");
        let replacement_path = temp.path().join("replacement-identical");
        fs::write(&replacement_path, original).unwrap();
        let mut swapped = false;
        let error = read_captured_entry_with_hook(
            &path,
            entry,
            snapshot.physical_files.get(relative),
            MAX_SEMANTIC_TEXT_BYTES,
            "identical swap fixture",
            |stage, path| {
                if stage == BoundReadStage::PathInspected && !swapped {
                    fs::rename(path, &held)?;
                    fs::rename(&replacement_path, path)?;
                    swapped = true;
                }
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("physical file identity"));
    }

    #[cfg(unix)]
    #[test]
    fn captured_entry_rejects_path_swap_after_handle_open() {
        let (temp, root) = valid_root();
        let snapshot = capture_tree(&root).unwrap();
        let relative = "run-1/build-environment.txt";
        let entry = snapshot
            .files
            .iter()
            .find(|entry| entry.path == relative)
            .unwrap();
        let path = root.join(relative);
        let original = fs::read(&path).unwrap();
        let held = temp.path().join("held-after-open");
        let replacement_path = temp.path().join("replacement-after-open");
        fs::write(&replacement_path, original).unwrap();
        let mut swapped = false;
        let error = read_captured_entry_with_hook(
            &path,
            entry,
            snapshot.physical_files.get(relative),
            MAX_SEMANTIC_TEXT_BYTES,
            "open-handle swap fixture",
            |stage, path| {
                if stage == BoundReadStage::HandleOpened && !swapped {
                    fs::rename(path, &held)?;
                    fs::rename(&replacement_path, path)?;
                    swapped = true;
                }
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("physical file identity"));
    }

    #[test]
    fn directory_fan_out_hits_the_global_node_bound_before_collection() {
        let temp = tempdir().unwrap();
        let mut allowed_files = BTreeSet::new();
        for index in 0..=MAX_TREE_NODES {
            let name = format!("node-{index:03}");
            fs::write(temp.path().join(&name), b"x").unwrap();
            allowed_files.insert(name);
        }
        let mut snapshot = TreeSnapshot {
            directories: Vec::new(),
            files: Vec::new(),
            physical_files: BTreeMap::new(),
            #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
            descriptor_directories: BTreeMap::new(),
            #[cfg(all(target_os = "linux", feature = "b4-descriptor-build-check"))]
            descriptor_files: BTreeMap::new(),
        };
        let mut total = 0;
        let mut nodes = 0;
        let allowed_directories = BTreeSet::new();
        let error = collect_directory(
            temp.path(),
            temp.path(),
            &mut snapshot,
            &mut total,
            &mut nodes,
            &allowed_files,
            &allowed_directories,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("global node bound"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symbolic_and_hard_links() {
        use std::os::unix::fs::symlink;

        let (_temp, root) = valid_root();
        fs::remove_file(root.join("run-2/identity.txt")).unwrap();
        symlink("../run-1/identity.txt", root.join("run-2/identity.txt")).unwrap();
        assert!(validate_published_b4_build(&root).is_err());

        let (_temp, root) = valid_root();
        fs::remove_file(root.join("run-2/identity.txt")).unwrap();
        fs::hard_link(
            root.join("run-1/identity.txt"),
            root.join("run-2/identity.txt"),
        )
        .unwrap();
        assert!(validate_published_b4_build(root).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_hard_link_fixture_cannot_enter_authoritative_mode() {
        let (_temp, root) = valid_root();
        fs::remove_file(root.join("run-2/identity.txt")).unwrap();
        fs::hard_link(
            root.join("run-1/identity.txt"),
            root.join("run-2/identity.txt"),
        )
        .unwrap();
        let inspection = validate_published_b4_build(&root).unwrap();
        assert_eq!(
            inspection.filesystem_binding,
            B4FilesystemBindingStatus::UnavailableForInspection
        );
        let error = validate_published_b4_build_with_expectations(
            root,
            &B4BuildExpectations {
                expected_source_commit: Some(TEST_SOURCE_COMMIT),
                expected_source_tree: Some(TEST_SOURCE_TREE),
                expected_evidence_root: Some(TEST_EVIDENCE_ROOT),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("requires Unix device/inode/link-count binding"));
    }
}
