//! Closed candidate grammar for the EIP-0045 B4 conformance corpus.

use std::collections::BTreeSet;
use std::fs::{self, File, Metadata};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::b4_plan::{
    B4_NEGATIVE_PLAN_VARIANT_COUNT, B4MaterializationDomain, Eip0045B4NegativePlanV1,
    negative_group_requires_fixture_selection,
};
use crate::b4_subject::B4SequenceSubjectElement;
use crate::canonical::{canonical_json_bytes, validate_canonical_json_source};

/// Exact format label for the candidate B4 registry.
pub const B4_CANDIDATE_FORMAT: &str = "Eip0045B4CorpusV1Candidate";
/// Exact format version for the candidate B4 registry.
pub const B4_CANDIDATE_FORMAT_VERSION: u8 = 1;
/// Largest integer which RFC 8785 can represent without IEEE-754 rounding.
///
/// Every integer serialized in a canonical B4 JSON document is bounded by
/// this value even when its Rust storage type is `u64`.
pub const B4_MAX_JCS_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
/// Canonical repository-relative location of the candidate B4 registry.
pub const B4_CANDIDATE_REGISTRY_PATH: &str = "reproduction/schema/b4-corpus-v1.candidate.json";

const B4_CANDIDATE_ARTIFACT_ROOT: &str = "reproduction/schema/b4-corpus-v1.candidate/";
const MAX_REPOSITORY_PATH_BYTES: usize = 240;
const PROFILE_ID: &str = "23c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383";
const PROFILE_MANIFEST_PATH: &str = "profiles/risc0-v3-succinct/manifest.bin";
const PROFILE_MANIFEST_BYTES: u64 = 458;
const PROFILE_MANIFEST_SHA256: &str =
    "deffb2cb231f98a348cbd166d5f1c43315661ccd8bd212099f16f238d0fe8946";
const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CANONICAL_JSON_BYTES: u64 = 8 * 1024 * 1024;
const B4_ANCESTRY_INVENTORY_EDIT_EXECUTION_ID: &str =
    "resolve-assumption-inventory-sweep--pruned-assumption";
const B4_ALTERNATE_ROOT_ASSUMPTION_EXECUTION_ID: &str =
    "resolve-explicit-field-sweep--assumption-receipt-root";

/// Candidate registry lifecycle. Only `expanded` can describe a populated B4 corpus.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4RegistryStage {
    /// Closed grammar and case inventory, before generated identities exist.
    Skeleton,
    /// Every identity and positive artifact is bound and all negative recipes are enumerated.
    Expanded,
}

/// Byte-level encoding asserted for an archived artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4ArtifactEncoding {
    /// Opaque bytes.
    RawBytes,
    /// Exact UTF-8 RFC 8785 JSON Canonicalization Scheme bytes.
    Rfc8785Jcs,
}

/// Whether one identity slot is still pending or bound to exact bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4BindingState {
    /// Identity cannot be known until the new guest and tools are built.
    Pending,
    /// Identity is bound to one exact regular file.
    Bound,
}

/// One exact artifact identity or one deliberately empty pending slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4ArtifactBinding {
    /// Exact byte length, or zero while pending.
    pub byte_length: u64,
    /// Required byte encoding.
    pub encoding: B4ArtifactEncoding,
    /// Canonical repository-relative path, or empty while pending.
    pub path: String,
    /// Lowercase SHA-256, or empty while pending.
    pub sha256: String,
    /// Binding lifecycle.
    pub state: B4BindingState,
}

/// Immutable B3 profile package identity used by every B4 case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4ProfileBinding {
    /// Exact 458-byte binary manifest identity.
    pub manifest: B4ArtifactBinding,
    /// Exact closed B3 profile ID.
    pub profile_id: String,
}

/// Reference statement bundle identity, pending until the new guest ID exists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4StatementBinding {
    /// Blake2b-256 contract ID, or empty while pending.
    pub contract_id: String,
    /// Exact canonical statement-bundle manifest.
    pub manifest: B4ArtifactBinding,
    /// SHA-256 of the exact `ErgoStatementV1`, or empty while pending.
    pub statement_sha256: String,
    /// Binding lifecycle.
    pub state: B4BindingState,
}

/// Reference guest identity, pending until the two pinned builds agree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4GuestBinding {
    /// Exact guest ELF identity.
    pub elf: B4ArtifactBinding,
    /// Exact 32-byte RISC Zero image ID, or empty while pending.
    pub image_id: String,
    /// Binding lifecycle.
    pub state: B4BindingState,
}

/// Complete global identity binding for the B4 corpus.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4IdentityBindings {
    /// Exact shipping proof-generator executable.
    pub generator: B4ArtifactBinding,
    /// Exact shared guest ELF and image ID.
    pub guest: B4GuestBinding,
    /// Exact independent JVM verifier artifact.
    pub jvm_verifier: B4ArtifactBinding,
    /// Exact canonical negative-plan JCS artifact.
    pub negative_plan: B4ArtifactBinding,
    /// Exact deterministic reference statement bundle.
    pub reference_statement_bundle: B4StatementBinding,
    /// Exact upstream Rust replay verifier artifact.
    pub rust_verifier: B4ArtifactBinding,
    /// Exact materialized-source lock.
    pub source_lock: B4ArtifactBinding,
    /// Exact canonical detached-subject catalog JCS artifact.
    pub subject_catalog: B4ArtifactBinding,
    /// Exact canonical terminal-fixture catalog JCS artifact.
    pub terminal_fixture_catalog: B4ArtifactBinding,
}

/// Closed positive receipt family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4PositiveFamily {
    /// One segment lifted to a selected outer exponent.
    Lift,
    /// Two lifted segments joined at the terminal.
    TerminalJoin,
    /// Explicit-root assumption resolved at the terminal.
    TerminalResolve,
    /// Zero-root assumption resolved before a final join.
    ResolveThenJoin,
}

/// Closed private guest mode used only to create recursion ancestry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4GuestMode {
    /// No assumption.
    Plain,
    /// Exact assumption claim with a zero self-composition root.
    VerifyAssumptionZeroRoot,
    /// Exact assumption claim with the pinned explicit control root.
    VerifyAssumptionExplicitRoot,
}

/// Closed outer terminal kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4TerminalKind {
    /// Lift control with exponent in 15 through 22.
    Lift,
    /// Join control, with reserved parameter zero.
    Join,
    /// Resolve control, with reserved parameter zero.
    Resolve,
}

/// Exact terminal descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4Terminal {
    /// Terminal kind.
    pub kind: B4TerminalKind,
    /// Lift exponent, or reserved zero for join/resolve.
    pub parameter: u8,
}

/// Assumption-root branch exercised by a positive case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4RootBranch {
    /// No assumption edge.
    None,
    /// Pinned explicit allowed-control root.
    Explicit,
    /// Zero-root self-composition.
    Zero,
}

/// Expected acceptance result for one positive case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4PositiveVerdict {
    /// Verification succeeds.
    Accept,
}

/// Expected final receipt status for one positive case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4FinalStatus {
    /// Successful RISC Zero receipt claim.
    Ok,
}

/// Closed expected-result record for a positive case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4PositiveExpectedResult {
    /// Final receipt assumption count; always zero.
    pub final_assumption_count: u8,
    /// Final receipt status; always OK.
    pub final_status: B4FinalStatus,
    /// Independent JVM verdict.
    pub independent_jvm: B4PositiveVerdict,
    /// Upstream Rust verdict.
    pub upstream_rust: B4PositiveVerdict,
}

/// Closed positive-case artifact role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4PositiveArtifactRole {
    /// Canonical recursion ancestry view, present only for recursive cases.
    Ancestry,
    /// Canonical recursive calibration record, present only for recursive cases.
    Calibration,
    /// Exact expected receipt-claim digest.
    ClaimDigest,
    /// Exact terminal control ID.
    ControlId,
    /// Exact shared guest image ID/program ID.
    ImageId,
    /// Exact receipt journal.
    Journal,
    /// Canonical case metadata.
    Metadata,
    /// Exact raw succinct seal.
    RawSeal,
    /// Upstream receipt/replay oracle material.
    ReceiptOracle,
}

/// One exact positive-case artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4PositiveArtifact {
    /// Exact byte length.
    pub byte_length: u64,
    /// Required byte encoding.
    pub encoding: B4ArtifactEncoding,
    /// Canonical repository-relative candidate path.
    pub path: String,
    /// Closed artifact role.
    pub role: B4PositiveArtifactRole,
    /// Lowercase SHA-256 of the exact bytes.
    pub sha256: String,
}

/// One declared B4 positive case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4PositiveCase {
    /// Exact positive-case artifacts; empty only in the skeleton stage.
    pub artifacts: Vec<B4PositiveArtifact>,
    /// Stable case ID.
    pub case_id: String,
    /// Exact expected dual-verifier result.
    pub expected_result: B4PositiveExpectedResult,
    /// Closed receipt family.
    pub family: B4PositiveFamily,
    /// Closed private guest mode.
    pub guest_mode: B4GuestMode,
    /// Mandatory ordinal from zero through ten.
    pub index: u8,
    /// Assumption-root branch.
    pub root_branch: B4RootBranch,
    /// Exact number of source execution segments.
    pub source_segments: u8,
    /// Exact outer terminal.
    pub terminal: B4Terminal,
}

/// Closed negative acceptance-boundary class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4NegativeClass {
    /// Serialized statement and identity binding.
    StatementBinding,
    /// Proof chunking and transport grammar.
    ProofTransport,
    /// Canonical outer word encoding.
    CanonicalOuterWords,
    /// Frozen parser read phases and offsets.
    ParserPhases,
    /// Terminal allowlist and typed controls.
    TerminalPolicy,
    /// Final and recursive claim semantics.
    ClaimSemantics,
    /// Explicit- and zero-root resolve semantics.
    ResolveSemantics,
    /// Early, middle, late, and final cryptographic rejection boundaries.
    CryptographicRejectionDepth,
    /// Profile package and registry closure.
    ProfilePackageAndRegistry,
}

/// One of the six non-manifest profile artifacts addressable by a byte edit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4ProfileArtifact {
    /// Normative algorithm text.
    Algorithm,
    /// Canonical algorithm artifact preimage.
    AlgorithmArtifactPreimage,
    /// Normative binary constants.
    Constants,
    /// Canonical binary-data artifact preimage.
    BinaryDataArtifactPreimage,
    /// Exact 32-byte profile identifier.
    ProfileId,
    /// Canonical profile-ID preimage.
    ProfileIdPreimage,
}

/// Closed coarse target for one byte-level mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    tag = "targetKind",
    deny_unknown_fields
)]
pub enum B4ByteTarget {
    /// Script-supplied application payload before host statement construction.
    ApplicationPayload,
    /// Canonical recursive ancestry JSON.
    Ancestry,
    /// Exact candidate-registry source bytes before strict parsing.
    CandidateRegistrySource,
    /// Canonical recursive calibration artifact.
    PositiveCalibration,
    /// Canonical positive-case metadata artifact.
    PositiveMetadata,
    /// One of the six non-manifest profile artifacts.
    ProfileArtifact {
        /// Exact profile artifact selected by this mutation.
        artifact: B4ProfileArtifact,
    },
    /// Binary profile manifest.
    ProfileManifest,
    /// Script-supplied 32-byte profile identifier before dispatch.
    ProfileId,
    /// Script-supplied 32-byte program identifier before claim construction.
    ProgramId,
    /// Upstream receipt/replay oracle.
    ReceiptOracle,
    /// Raw succinct seal.
    RawSeal,
    /// Exact Ergo statement bytes.
    Statement,
    /// One exact detached-subject catalogue entry.
    SubjectCatalogEntry,
    /// One exact terminal-fixture catalogue entry.
    TerminalFixtureCatalogEntry,
    /// One exact terminal metadata record.
    TerminalMetadataRecord,
    /// One exact control ID supplied to the shared terminal-policy selector.
    TerminalPolicyProbe,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", tag = "targetKind")]
enum B4ByteTargetWire {
    ApplicationPayload(ClosedUnitWire),
    Ancestry(ClosedUnitWire),
    CandidateRegistrySource(ClosedUnitWire),
    PositiveCalibration(ClosedUnitWire),
    PositiveMetadata(ClosedUnitWire),
    ProfileArtifact(ProfileArtifactTargetWire),
    ProfileManifest(ClosedUnitWire),
    ProfileId(ClosedUnitWire),
    ProgramId(ClosedUnitWire),
    ReceiptOracle(ClosedUnitWire),
    RawSeal(ClosedUnitWire),
    Statement(ClosedUnitWire),
    SubjectCatalogEntry(ClosedUnitWire),
    TerminalFixtureCatalogEntry(ClosedUnitWire),
    TerminalMetadataRecord(ClosedUnitWire),
    TerminalPolicyProbe(ClosedUnitWire),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClosedUnitWire {}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProfileArtifactTargetWire {
    artifact: B4ProfileArtifact,
}

impl<'de> Deserialize<'de> for B4ByteTarget {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        B4ByteTargetWire::deserialize(deserializer).map(|wire| match wire {
            B4ByteTargetWire::ApplicationPayload(_) => Self::ApplicationPayload,
            B4ByteTargetWire::Ancestry(_) => Self::Ancestry,
            B4ByteTargetWire::CandidateRegistrySource(_) => Self::CandidateRegistrySource,
            B4ByteTargetWire::PositiveCalibration(_) => Self::PositiveCalibration,
            B4ByteTargetWire::PositiveMetadata(_) => Self::PositiveMetadata,
            B4ByteTargetWire::ProfileArtifact(ProfileArtifactTargetWire { artifact }) => {
                Self::ProfileArtifact { artifact }
            }
            B4ByteTargetWire::ProfileManifest(_) => Self::ProfileManifest,
            B4ByteTargetWire::ProfileId(_) => Self::ProfileId,
            B4ByteTargetWire::ProgramId(_) => Self::ProgramId,
            B4ByteTargetWire::ReceiptOracle(_) => Self::ReceiptOracle,
            B4ByteTargetWire::RawSeal(_) => Self::RawSeal,
            B4ByteTargetWire::Statement(_) => Self::Statement,
            B4ByteTargetWire::SubjectCatalogEntry(_) => Self::SubjectCatalogEntry,
            B4ByteTargetWire::TerminalFixtureCatalogEntry(_) => Self::TerminalFixtureCatalogEntry,
            B4ByteTargetWire::TerminalMetadataRecord(_) => Self::TerminalMetadataRecord,
            B4ByteTargetWire::TerminalPolicyProbe(_) => Self::TerminalPolicyProbe,
        })
    }
}

/// Closed byte mutation operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    tag = "operation",
    deny_unknown_fields
)]
pub enum B4ByteOperation {
    /// Delete exact bytes beginning at `offset`.
    Delete {
        /// Exact bytes present before deletion.
        before_hex: String,
        /// Zero-based byte offset.
        offset: u64,
    },
    /// Insert exact nonempty bytes at `offset`.
    Insert {
        /// Exact inserted bytes.
        inserted_hex: String,
        /// Zero-based byte offset.
        offset: u64,
    },
    /// Replace exact bytes without changing byte length.
    Replace {
        /// Exact bytes present before replacement.
        before_hex: String,
        /// Exact distinct replacement bytes.
        replacement_hex: String,
        /// Zero-based byte offset.
        offset: u64,
    },
    /// Truncate a known original byte string to a strictly shorter length.
    Truncate {
        /// Nonempty prefix of the bytes removed at the new boundary.
        before_hex: String,
        /// Resulting byte length.
        new_length: u64,
        /// Byte length before truncation.
        original_length: u64,
    },
}

/// Closed coarse target for one ordered-sequence mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    tag = "targetKind",
    deny_unknown_fields
)]
pub enum B4SequenceTarget {
    /// Abstract required-entry inventory consumed by the closed-tree validator.
    AbstractTreeProbe,
    /// Detached ordered positive-case registry projection.
    RegistryPositiveCases,
    /// Detached ordered negative-case registry projection.
    RegistryNegativeCases,
    /// Detached closed negative-class registry projection.
    RegistryNegativeClasses,
    /// Detached negative-row binding projection over the four canonical row fields.
    RegistryNegativeBindings,
    /// Detached closed profile-package file projection.
    ProfilePackageFiles,
    /// Chunk sequence supplied to the proof transport layer.
    ProofChunks,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", tag = "targetKind")]
enum B4SequenceTargetWire {
    AbstractTreeProbe(ClosedUnitWire),
    RegistryPositiveCases(ClosedUnitWire),
    RegistryNegativeCases(ClosedUnitWire),
    RegistryNegativeClasses(ClosedUnitWire),
    RegistryNegativeBindings(ClosedUnitWire),
    ProfilePackageFiles(ClosedUnitWire),
    ProofChunks(ClosedUnitWire),
}

impl<'de> Deserialize<'de> for B4SequenceTarget {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        B4SequenceTargetWire::deserialize(deserializer).map(|wire| match wire {
            B4SequenceTargetWire::AbstractTreeProbe(_) => Self::AbstractTreeProbe,
            B4SequenceTargetWire::RegistryPositiveCases(_) => Self::RegistryPositiveCases,
            B4SequenceTargetWire::RegistryNegativeCases(_) => Self::RegistryNegativeCases,
            B4SequenceTargetWire::RegistryNegativeClasses(_) => Self::RegistryNegativeClasses,
            B4SequenceTargetWire::RegistryNegativeBindings(_) => Self::RegistryNegativeBindings,
            B4SequenceTargetWire::ProfilePackageFiles(_) => Self::ProfilePackageFiles,
            B4SequenceTargetWire::ProofChunks(_) => Self::ProofChunks,
        })
    }
}

/// Closed semantic target for one recursive ancestry inventory mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "targetKind", deny_unknown_fields)]
pub enum B4AncestryInventoryTarget {
    /// The sole revealed head of an assumption receipt's source inventory.
    AssumptionSourceInventoryHead,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", tag = "targetKind")]
enum B4AncestryInventoryTargetWire {
    AssumptionSourceInventoryHead(ClosedUnitWire),
}

impl<'de> Deserialize<'de> for B4AncestryInventoryTarget {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        B4AncestryInventoryTargetWire::deserialize(deserializer).map(|wire| match wire {
            B4AncestryInventoryTargetWire::AssumptionSourceInventoryHead(_) => {
                Self::AssumptionSourceInventoryHead
            }
        })
    }
}

/// Closed semantic operation over one recursive ancestry source inventory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    tag = "operation",
    deny_unknown_fields
)]
pub enum B4AncestryInventoryOperation {
    /// Replace one exact revealed head with its exact upstream pruned digest.
    PruneRevealedHead {
        /// Claim digest carried by the revealed head before pruning.
        before_claim_digest: String,
        /// Control root carried by the revealed head before pruning.
        before_control_root: String,
        /// Exact upstream digest stored by the resulting pruned head.
        exact_digest: String,
    },
}

/// Direction in which bytes cross one proof-chunk boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4BoundaryShiftDirection {
    /// Move bytes from the left chunk into the right chunk.
    LeftToRight,
    /// Move bytes from the right chunk into the left chunk.
    RightToLeft,
}

/// Closed ordered-sequence mutation operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    tag = "operation",
    deny_unknown_fields
)]
pub enum B4SequenceOperation {
    /// Replace a nonempty proof-chunk sequence with an empty sequence.
    Empty {},
    /// Insert one exact canonical element identity.
    Insert {
        /// Complete inserted element material.
        inserted_element: B4SequenceSubjectElement,
        /// Zero-based insertion index.
        index: u64,
    },
    /// Move one exact existing element to a distinct final index.
    ///
    /// Reconstruction removes `from_index` first, then inserts the removed
    /// element at `to_index` in the shortened sequence. Thus `to_index` is the
    /// element's final index, not its index in the pre-removal sequence.
    Move {
        /// Stable identifier of the element before movement.
        before_element_id: String,
        /// SHA-256 of the canonical element bytes before movement.
        before_element_sha256: String,
        /// Existing zero-based index.
        from_index: u64,
        /// Distinct destination index.
        to_index: u64,
    },
    /// Omit one exact existing element.
    Omit {
        /// Stable identifier of the element before omission.
        before_element_id: String,
        /// SHA-256 of the canonical element bytes before omission.
        before_element_sha256: String,
        /// Existing zero-based index.
        index: u64,
    },
    /// Replace one exact existing element with complete distinct material.
    Replace {
        /// Stable identifier of the element before replacement.
        before_element_id: String,
        /// SHA-256 of the canonical element bytes before replacement.
        before_element_sha256: String,
        /// Existing zero-based index.
        index: u64,
        /// Complete replacement element material.
        replacement_element: B4SequenceSubjectElement,
    },
    /// Shift bytes across one adjacent proof-chunk boundary.
    ///
    /// Left-to-right moves the exact suffix of the left chunk to the prefix of
    /// the right chunk. Right-to-left moves the exact prefix of the right chunk
    /// to the suffix of the left chunk. Reconstruction must require the source
    /// chunk to remain nonempty and must preserve both chunk count and the
    /// concatenation of all chunk bytes.
    ShiftBoundary {
        /// Strictly positive number of bytes moved across the boundary.
        byte_count: u64,
        /// Direction of the boundary shift.
        direction: B4BoundaryShiftDirection,
        /// Index of the chunk immediately left of the boundary.
        left_chunk_index: u64,
    },
}

/// Closed semantic recipe for substituting one authenticated recursive-ancestry witness.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4NegativeAncestryWitnessRecipeV1 {
    /// Copy the authenticated case-9 assumption Lift into case-8 step zero.
    ReuseCase9AssumptionAtTerminalJoinStep0,
    /// Copy the authenticated case-9 assumption Lift into case-9 step zero.
    ReuseCase9AssumptionAtTerminalResolveStep0,
    /// Copy the authenticated case-9 final Resolve into case-10 step two.
    ReuseCase9FinalResolveAtResolveThenJoinStep2,
    /// XOR chain-domain byte zero with `0x01`, then prove its case-9 assumption Lift.
    AlternateStatementAssumptionLiftForTerminalResolve,
    /// Prove the alternate-ELF Lift used by case 9.
    AlternateGuestLiftForTerminalResolve,
    /// XOR chain-domain byte zero with `0x01`, then prove the case-9 final Resolve.
    AlternateStatementFinalResolveForTerminalResolve,
    /// XOR chain-domain byte zero with `0x01`, then prove its case-10 assumption Lift.
    AlternateStatementAssumptionLiftForResolveThenJoin,
    /// Prove the alternate-ELF Lift used by case 10.
    AlternateGuestLiftForResolveThenJoin,
    /// XOR chain-domain byte zero with `0x01`, then prove the case-10 final Join.
    AlternateStatementFinalJoinForResolveThenJoin,
    /// Copy the authenticated case-9 assumption Lift and expose no inventory.
    ReuseCase9AssumptionWithEmptyInventory,
    /// Prove a Lift which records the same assumption exactly twice.
    DuplicateAssumptionLiftWithDuplicatedInventory,
}

const B4_NEGATIVE_ANCESTRY_WITNESS_SUBSTITUTIONS: [(&str, B4NegativeAncestryWitnessRecipeV1); 11] = [
    (
        "claim-edge-family-sweep--terminal-join",
        B4NegativeAncestryWitnessRecipeV1::ReuseCase9AssumptionAtTerminalJoinStep0,
    ),
    (
        "claim-edge-family-sweep--terminal-resolve-explicit-root",
        B4NegativeAncestryWitnessRecipeV1::ReuseCase9AssumptionAtTerminalResolveStep0,
    ),
    (
        "claim-edge-family-sweep--resolve-zero-root-then-join",
        B4NegativeAncestryWitnessRecipeV1::ReuseCase9FinalResolveAtResolveThenJoinStep2,
    ),
    (
        "resolve-explicit-field-sweep--assumption-claim",
        B4NegativeAncestryWitnessRecipeV1::AlternateStatementAssumptionLiftForTerminalResolve,
    ),
    (
        "resolve-explicit-field-sweep--program-id",
        B4NegativeAncestryWitnessRecipeV1::AlternateGuestLiftForTerminalResolve,
    ),
    (
        "resolve-explicit-field-sweep--final-claim",
        B4NegativeAncestryWitnessRecipeV1::AlternateStatementFinalResolveForTerminalResolve,
    ),
    (
        "resolve-zero-root-field-sweep--assumption-claim",
        B4NegativeAncestryWitnessRecipeV1::AlternateStatementAssumptionLiftForResolveThenJoin,
    ),
    (
        "resolve-zero-root-field-sweep--program-id",
        B4NegativeAncestryWitnessRecipeV1::AlternateGuestLiftForResolveThenJoin,
    ),
    (
        "resolve-zero-root-field-sweep--final-claim",
        B4NegativeAncestryWitnessRecipeV1::AlternateStatementFinalJoinForResolveThenJoin,
    ),
    (
        "resolve-assumption-inventory-sweep--missing-assumption",
        B4NegativeAncestryWitnessRecipeV1::ReuseCase9AssumptionWithEmptyInventory,
    ),
    (
        "resolve-assumption-inventory-sweep--extra-assumption",
        B4NegativeAncestryWitnessRecipeV1::DuplicateAssumptionLiftWithDuplicatedInventory,
    ),
];

/// Return the one closed ancestry-witness recipe reserved for `execution_id`.
#[must_use]
pub fn negative_ancestry_witness_recipe(
    execution_id: &str,
) -> Option<B4NegativeAncestryWitnessRecipeV1> {
    B4_NEGATIVE_ANCESTRY_WITNESS_SUBSTITUTIONS
        .iter()
        .find_map(|(candidate, recipe)| (*candidate == execution_id).then_some(*recipe))
}

/// One explicit mutation with no wildcard expansion left to perform.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    tag = "family",
    deny_unknown_fields
)]
pub enum B4NegativeMutation {
    /// Replace only the case-9 assumption producer with the fixed,
    /// independently authenticated alternate-root lift.
    AlternateRootAssumptionSubstitution {},
    /// Apply one closed semantic edit to a recursive ancestry source inventory.
    AncestryInventoryEdit {
        /// Closed ancestry-inventory operation.
        edit: B4AncestryInventoryOperation,
        /// Closed ancestry-inventory target.
        target: B4AncestryInventoryTarget,
    },
    /// Select one authenticated recursive-ancestry witness by its closed semantic recipe.
    AncestryWitnessSubstitution {
        /// Exact execution-bound producer and placement recipe.
        recipe: B4NegativeAncestryWitnessRecipeV1,
    },
    /// Edit one exact byte string.
    ByteEdit {
        /// Closed byte operation.
        edit: B4ByteOperation,
        /// Closed coarse byte target.
        target: B4ByteTarget,
    },
    /// Edit one exact ordered sequence.
    SequenceEdit {
        /// Closed ordered-sequence operation.
        edit: B4SequenceOperation,
        /// Closed coarse sequence target.
        target: B4SequenceTarget,
    },
}

#[derive(Deserialize)]
#[serde(tag = "family")]
enum B4NegativeMutationWire {
    #[serde(rename = "alternate-root-assumption-substitution")]
    AlternateRootAssumptionSubstitution(ClosedUnitWire),
    #[serde(rename = "ancestry-inventory-edit")]
    AncestryInventory(AncestryInventoryEditMutationWire),
    #[serde(rename = "ancestry-witness-substitution")]
    AncestryWitnessSubstitution(AncestryWitnessSubstitutionMutationWire),
    #[serde(rename = "byte-edit")]
    Byte(ByteEditMutationWire),
    #[serde(rename = "sequence-edit")]
    Sequence(SequenceEditMutationWire),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AncestryInventoryEditMutationWire {
    edit: B4AncestryInventoryOperation,
    target: B4AncestryInventoryTarget,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AncestryWitnessSubstitutionMutationWire {
    recipe: B4NegativeAncestryWitnessRecipeV1,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ByteEditMutationWire {
    edit: B4ByteOperation,
    target: B4ByteTarget,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SequenceEditMutationWire {
    edit: B4SequenceOperation,
    target: B4SequenceTarget,
}

impl From<B4NegativeMutationWire> for B4NegativeMutation {
    fn from(value: B4NegativeMutationWire) -> Self {
        match value {
            B4NegativeMutationWire::AlternateRootAssumptionSubstitution(_) => {
                Self::AlternateRootAssumptionSubstitution {}
            }
            B4NegativeMutationWire::AncestryInventory(AncestryInventoryEditMutationWire {
                edit,
                target,
            }) => Self::AncestryInventoryEdit { edit, target },
            B4NegativeMutationWire::AncestryWitnessSubstitution(
                AncestryWitnessSubstitutionMutationWire { recipe },
            ) => Self::AncestryWitnessSubstitution { recipe },
            B4NegativeMutationWire::Byte(ByteEditMutationWire { edit, target }) => {
                Self::ByteEdit { edit, target }
            }
            B4NegativeMutationWire::Sequence(SequenceEditMutationWire { edit, target }) => {
                Self::SequenceEdit { edit, target }
            }
        }
    }
}

impl<'de> Deserialize<'de> for B4NegativeMutation {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        B4NegativeMutationWire::deserialize(deserializer).map(Into::into)
    }
}

impl B4NegativeMutation {
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::AncestryInventoryEdit { edit, .. } => validate_ancestry_inventory_operation(edit),
            Self::AlternateRootAssumptionSubstitution {}
            | Self::AncestryWitnessSubstitution { .. } => Ok(()),
            Self::ByteEdit { edit, .. } => validate_byte_operation(edit),
            Self::SequenceEdit { edit, target } => validate_sequence_operation(*target, edit),
        }
    }
}

/// Closed recipe selected by the canonical plan for one negative execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    tag = "materializationKind",
    deny_unknown_fields
)]
pub enum B4NegativeMaterialization {
    /// Reconstruct an isolated mutation against the plan-selected base.
    Mutation {
        /// Exact closed mutation record.
        mutation: B4NegativeMutation,
    },
    /// Select one independently verified receipt fixture without fabricating a mutation.
    FixtureSelection {
        /// Exact fixture ID fixed by the canonical plan execution.
        fixture_id: String,
    },
}

/// One fully expanded isolated negative row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4NegativeCase {
    /// Exact negative execution identity from the canonical plan.
    pub execution_id: String,
    /// Exact independently authoritative base selector fixed by the plan.
    pub base_selector_id: String,
    /// Closed materializer/validator family fixed by the plan.
    pub materialization_domain: B4MaterializationDomain,
    /// Exact materialization recipe; results and artifact identities live outside this row.
    pub materialization: B4NegativeMaterialization,
}

/// Closed candidate B4 corpus registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4CandidateCorpus {
    /// Guest, statement, source, generator, and verifier identities.
    pub bindings: B4IdentityBindings,
    /// Exact format label.
    pub format: String,
    /// Exact format version.
    pub format_version: u8,
    /// Fully expanded negative rows; empty only in the skeleton stage.
    pub negative_cases: Vec<B4NegativeCase>,
    /// Closed ordered inventory of admitted negative classes.
    pub negative_classes: Vec<B4NegativeClass>,
    /// Exactly eleven ordered positive cases.
    pub positive_cases: Vec<B4PositiveCase>,
    /// Closed B3 profile binding.
    pub profile: B4ProfileBinding,
    /// Candidate registry lifecycle.
    pub stage: B4RegistryStage,
}

#[derive(Clone, Copy)]
struct ExpectedPositive {
    id: &'static str,
    family: B4PositiveFamily,
    mode: B4GuestMode,
    source_segments: u8,
    terminal: B4Terminal,
    root: B4RootBranch,
}

const EXPECTED_POSITIVES: [ExpectedPositive; 11] = [
    lift_case("lift-po2-15", 15),
    lift_case("lift-po2-16", 16),
    lift_case("lift-po2-17", 17),
    lift_case("lift-po2-18", 18),
    lift_case("lift-po2-19", 19),
    lift_case("lift-po2-20", 20),
    lift_case("lift-po2-21", 21),
    lift_case("lift-po2-22", 22),
    ExpectedPositive {
        id: "terminal-join",
        family: B4PositiveFamily::TerminalJoin,
        mode: B4GuestMode::Plain,
        source_segments: 2,
        terminal: B4Terminal {
            kind: B4TerminalKind::Join,
            parameter: 0,
        },
        root: B4RootBranch::None,
    },
    ExpectedPositive {
        id: "terminal-resolve-explicit-root",
        family: B4PositiveFamily::TerminalResolve,
        mode: B4GuestMode::VerifyAssumptionExplicitRoot,
        source_segments: 1,
        terminal: B4Terminal {
            kind: B4TerminalKind::Resolve,
            parameter: 0,
        },
        root: B4RootBranch::Explicit,
    },
    ExpectedPositive {
        id: "resolve-zero-root-then-join",
        family: B4PositiveFamily::ResolveThenJoin,
        mode: B4GuestMode::VerifyAssumptionZeroRoot,
        source_segments: 2,
        terminal: B4Terminal {
            kind: B4TerminalKind::Join,
            parameter: 0,
        },
        root: B4RootBranch::Zero,
    },
];

const fn lift_case(id: &'static str, po2: u8) -> ExpectedPositive {
    ExpectedPositive {
        id,
        family: B4PositiveFamily::Lift,
        mode: B4GuestMode::Plain,
        source_segments: 1,
        terminal: B4Terminal {
            kind: B4TerminalKind::Lift,
            parameter: po2,
        },
        root: B4RootBranch::None,
    }
}

const EXPECTED_NEGATIVE_CLASSES: [B4NegativeClass; 9] = [
    B4NegativeClass::StatementBinding,
    B4NegativeClass::ProofTransport,
    B4NegativeClass::CanonicalOuterWords,
    B4NegativeClass::ParserPhases,
    B4NegativeClass::TerminalPolicy,
    B4NegativeClass::ClaimSemantics,
    B4NegativeClass::ResolveSemantics,
    B4NegativeClass::CryptographicRejectionDepth,
    B4NegativeClass::ProfilePackageAndRegistry,
];

const POSITIVE_LIFT_ARTIFACTS: [B4PositiveArtifactRole; 7] = [
    B4PositiveArtifactRole::ClaimDigest,
    B4PositiveArtifactRole::ControlId,
    B4PositiveArtifactRole::ImageId,
    B4PositiveArtifactRole::Journal,
    B4PositiveArtifactRole::Metadata,
    B4PositiveArtifactRole::RawSeal,
    B4PositiveArtifactRole::ReceiptOracle,
];

const POSITIVE_RECURSIVE_ARTIFACTS: [B4PositiveArtifactRole; 8] = [
    B4PositiveArtifactRole::Ancestry,
    B4PositiveArtifactRole::Calibration,
    B4PositiveArtifactRole::ClaimDigest,
    B4PositiveArtifactRole::ControlId,
    B4PositiveArtifactRole::ImageId,
    B4PositiveArtifactRole::Journal,
    B4PositiveArtifactRole::RawSeal,
    B4PositiveArtifactRole::ReceiptOracle,
];

impl B4CandidateCorpus {
    /// Parse an exact RFC 8785 JCS candidate registry without authorizing activation.
    ///
    /// This accepts either lifecycle only after its complete structural validation;
    /// [`Self::validate`] remains the fail-closed activation-facing gate.
    ///
    /// # Errors
    ///
    /// Returns an error when the source is oversized, is not exact canonical JCS,
    /// has an invalid registry shape, fails structural validation, or does not
    /// round-trip byte-exactly.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            u64::try_from(source.len()).context("candidate registry length exceeds u64")?
                <= MAX_CANONICAL_JSON_BYTES,
            "B4 candidate registry exceeds its canonical-byte bound"
        );
        let value = validate_canonical_json_source(source)
            .context("B4 candidate registry is not exact RFC 8785 JCS")?;
        let corpus: Self =
            serde_json::from_value(value).context("invalid B4 candidate registry shape")?;
        corpus.validate_structural()?;
        ensure!(
            corpus.to_canonical_jcs()? == source,
            "B4 candidate registry does not round-trip byte-exactly"
        );
        Ok(corpus)
    }

    /// Serialize the structurally valid candidate registry as exact RFC 8785 JCS.
    ///
    /// # Errors
    ///
    /// Returns an error when structural validation or canonical serialization
    /// fails, or when the resulting source exceeds the canonical-byte bound.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.validate_structural()?;
        let value = serde_json::to_value(self).context("cannot serialize B4 candidate registry")?;
        let bytes = canonical_json_bytes(&value)?;
        ensure!(
            u64::try_from(bytes.len()).context("candidate registry length exceeds u64")?
                <= MAX_CANONICAL_JSON_BYTES,
            "B4 candidate registry exceeds its canonical-byte bound"
        );
        Ok(bytes)
    }

    /// Validate the closed in-memory registry grammar and all semantic mappings.
    ///
    /// # Errors
    ///
    /// Returns an error for any format, identity, ordering, family, root,
    /// artifact, materialization, or finite-negative-registry mismatch.
    pub fn validate(&self) -> Result<()> {
        self.validate_structural()?;
        ensure!(
            self.stage == B4RegistryStage::Skeleton,
            "expanded B4 validation remains disabled until the dual-verifier semantic corpus gate is implemented"
        );
        Ok(())
    }

    /// Bind this registry to the exact canonical negative-plan source bytes.
    ///
    /// This updates only the quarantined artifact identity. It does not mark
    /// B4 final, validate verifier observations, or bypass the future semantic
    /// corpus gate.
    ///
    /// # Errors
    ///
    /// Returns an error unless `source` is the byte-exact canonical V1 plan and
    /// `path` is a valid candidate-quarantine artifact path.
    pub fn bind_canonical_negative_plan_source(
        &mut self,
        path: impl Into<String>,
        source: &[u8],
    ) -> Result<()> {
        canonical_negative_plan_source(source)?;
        let binding =
            binding_for_exact_source(path.into(), B4ArtifactEncoding::Rfc8785Jcs, source)?;
        validate_candidate_binding(&binding)?;
        self.bindings.negative_plan = binding;
        Ok(())
    }

    /// Validate an expanded registry against the exact canonical plan source
    /// and the registry's bound plan artifact identity.
    ///
    /// Success proves structural plan/registry bijection only. It deliberately
    /// does not make the expanded corpus final or satisfy the future semantic
    /// Rust/JVM result gate.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-expanded registry, noncanonical or non-V1
    /// source, artifact length/digest mismatch, or any missing, surplus,
    /// duplicated, reordered, or rebound negative execution.
    pub fn validate_expanded_against_canonical_plan_source(&self, source: &[u8]) -> Result<()> {
        ensure!(
            self.stage == B4RegistryStage::Expanded,
            "plan-source validation requires an expanded B4 registry"
        );
        let plan = canonical_negative_plan_source(source)?;
        self.validate_structural()?;
        validate_binding_matches_source(&self.bindings.negative_plan, source)?;
        self.validate_negative_inventory_against_plan(&plan)
    }

    /// Validate the complete candidate grammar without authorizing activation.
    fn validate_structural(&self) -> Result<()> {
        ensure!(self.format == B4_CANDIDATE_FORMAT, "wrong B4 format label");
        ensure!(
            self.format_version == B4_CANDIDATE_FORMAT_VERSION,
            "wrong B4 format version"
        );
        self.validate_profile()?;
        self.validate_positive_inventory()?;
        self.validate_negative_inventory()?;
        self.validate_bindings()?;
        Ok(())
    }

    /// Validate every bound artifact against a physical repository tree.
    ///
    /// # Errors
    ///
    /// Returns an error when the in-memory registry is invalid or a bound path
    /// is missing, linked, outside the repository, duplicated, non-canonical,
    /// unbounded, or differs in length, digest, or declared encoding.
    /// Success for an expanded tree remains structural and physical evidence;
    /// it does not satisfy the future semantic corpus gate or make B4 final.
    pub fn validate_physical(&self, repository_root: impl AsRef<Path>) -> Result<()> {
        self.validate_structural()?;
        let repository_root = repository_root.as_ref();
        require_ordinary_directory(repository_root, "B4 repository root")?;
        let canonical_root =
            fs::canonicalize(repository_root).context("cannot canonicalize B4 repository root")?;
        let mut paths = BTreeSet::new();

        Self::check_binding_file(&canonical_root, &self.profile.manifest, &mut paths)?;
        Self::check_binding_file(
            &canonical_root,
            &self.bindings.reference_statement_bundle.manifest,
            &mut paths,
        )?;
        Self::check_binding_file(&canonical_root, &self.bindings.guest.elf, &mut paths)?;
        Self::check_binding_file(&canonical_root, &self.bindings.source_lock, &mut paths)?;
        Self::check_binding_file(&canonical_root, &self.bindings.generator, &mut paths)?;
        Self::check_binding_file(&canonical_root, &self.bindings.rust_verifier, &mut paths)?;
        Self::check_binding_file(&canonical_root, &self.bindings.jvm_verifier, &mut paths)?;
        Self::check_binding_file(&canonical_root, &self.bindings.negative_plan, &mut paths)?;
        Self::check_binding_file(&canonical_root, &self.bindings.subject_catalog, &mut paths)?;
        Self::check_binding_file(
            &canonical_root,
            &self.bindings.terminal_fixture_catalog,
            &mut paths,
        )?;

        for case in &self.positive_cases {
            for artifact in &case.artifacts {
                check_physical_artifact(
                    &canonical_root,
                    &artifact.path,
                    artifact.byte_length,
                    &artifact.sha256,
                    artifact.encoding,
                    &mut paths,
                )?;
            }
        }
        if self.stage == B4RegistryStage::Expanded {
            let plan_path = join_physical_path(&canonical_root, &self.bindings.negative_plan.path)?;
            let plan_source = fs::read(&plan_path).with_context(|| {
                format!("cannot read bound negative plan {}", plan_path.display())
            })?;
            self.validate_expanded_against_canonical_plan_source(&plan_source)?;
        }
        Ok(())
    }

    fn validate_profile(&self) -> Result<()> {
        ensure!(self.profile.profile_id == PROFILE_ID, "B3 profile ID drift");
        validate_bound_artifact(&self.profile.manifest, false)?;
        ensure!(
            self.profile.manifest.path == PROFILE_MANIFEST_PATH
                && self.profile.manifest.byte_length == PROFILE_MANIFEST_BYTES
                && self.profile.manifest.sha256 == PROFILE_MANIFEST_SHA256
                && self.profile.manifest.encoding == B4ArtifactEncoding::RawBytes,
            "B3 binary manifest identity drift"
        );
        Ok(())
    }

    fn validate_bindings(&self) -> Result<()> {
        validate_statement_binding(&self.bindings.reference_statement_bundle)?;
        validate_guest_binding(&self.bindings.guest)?;
        for (label, binding, expected_encoding) in [
            (
                "source lock",
                &self.bindings.source_lock,
                B4ArtifactEncoding::Rfc8785Jcs,
            ),
            (
                "generator",
                &self.bindings.generator,
                B4ArtifactEncoding::RawBytes,
            ),
            (
                "Rust verifier",
                &self.bindings.rust_verifier,
                B4ArtifactEncoding::RawBytes,
            ),
            (
                "JVM verifier",
                &self.bindings.jvm_verifier,
                B4ArtifactEncoding::RawBytes,
            ),
            (
                "negative plan",
                &self.bindings.negative_plan,
                B4ArtifactEncoding::Rfc8785Jcs,
            ),
            (
                "subject catalog",
                &self.bindings.subject_catalog,
                B4ArtifactEncoding::Rfc8785Jcs,
            ),
            (
                "terminal fixture catalog",
                &self.bindings.terminal_fixture_catalog,
                B4ArtifactEncoding::Rfc8785Jcs,
            ),
        ] {
            validate_candidate_binding(binding).with_context(|| format!("invalid {label}"))?;
            ensure!(
                binding.encoding == expected_encoding,
                "{label} encoding drift"
            );
        }

        match self.stage {
            B4RegistryStage::Skeleton => {
                ensure!(
                    self.bindings.reference_statement_bundle.state == B4BindingState::Pending
                        && self.bindings.guest.state == B4BindingState::Pending
                        && self.bindings.source_lock.state == B4BindingState::Pending
                        && self.bindings.generator.state == B4BindingState::Pending
                        && self.bindings.rust_verifier.state == B4BindingState::Pending
                        && self.bindings.jvm_verifier.state == B4BindingState::Pending
                        && self.bindings.negative_plan.state == B4BindingState::Pending
                        && self.bindings.subject_catalog.state == B4BindingState::Pending
                        && self.bindings.terminal_fixture_catalog.state == B4BindingState::Pending,
                    "B4 skeleton must leave every post-B3 identity pending"
                );
            }
            B4RegistryStage::Expanded => {
                ensure!(
                    self.bindings.reference_statement_bundle.state == B4BindingState::Bound
                        && self.bindings.guest.state == B4BindingState::Bound
                        && self.bindings.source_lock.state == B4BindingState::Bound
                        && self.bindings.generator.state == B4BindingState::Bound
                        && self.bindings.rust_verifier.state == B4BindingState::Bound
                        && self.bindings.jvm_verifier.state == B4BindingState::Bound
                        && self.bindings.negative_plan.state == B4BindingState::Bound
                        && self.bindings.subject_catalog.state == B4BindingState::Bound
                        && self.bindings.terminal_fixture_catalog.state == B4BindingState::Bound,
                    "expanded B4 registry has an unbound global identity"
                );
            }
        }
        Ok(())
    }

    fn validate_positive_inventory(&self) -> Result<()> {
        ensure!(
            self.positive_cases.len() == EXPECTED_POSITIVES.len(),
            "B4 registry must contain exactly eleven positives"
        );
        for (index, (case, expected)) in self
            .positive_cases
            .iter()
            .zip(EXPECTED_POSITIVES)
            .enumerate()
        {
            let expected_index = u8::try_from(index).context("positive index does not fit u8")?;
            ensure!(
                case.index == expected_index,
                "positive case index drift at {index}"
            );
            ensure!(
                case.case_id == expected.id,
                "positive case ID/order drift at {index}"
            );
            ensure!(
                case.family == expected.family,
                "positive family drift for {}",
                case.case_id
            );
            ensure!(
                case.guest_mode == expected.mode,
                "guest mode drift for {}",
                case.case_id
            );
            ensure!(
                case.source_segments == expected.source_segments,
                "source-segment count drift for {}",
                case.case_id
            );
            ensure!(
                case.terminal == expected.terminal,
                "terminal drift for {}",
                case.case_id
            );
            ensure!(
                case.root_branch == expected.root,
                "root-branch drift for {}",
                case.case_id
            );
            ensure!(
                case.expected_result
                    == (B4PositiveExpectedResult {
                        final_assumption_count: 0,
                        final_status: B4FinalStatus::Ok,
                        independent_jvm: B4PositiveVerdict::Accept,
                        upstream_rust: B4PositiveVerdict::Accept,
                    }),
                "expected positive result drift for {}",
                case.case_id
            );

            match self.stage {
                B4RegistryStage::Skeleton => ensure!(
                    case.artifacts.is_empty(),
                    "B4 skeleton positive {} must not contain generated artifacts",
                    case.case_id
                ),
                B4RegistryStage::Expanded => validate_positive_artifacts(case)?,
            }
        }
        Ok(())
    }

    fn validate_negative_inventory(&self) -> Result<()> {
        ensure!(
            self.negative_classes == EXPECTED_NEGATIVE_CLASSES,
            "negative class inventory/order drift"
        );
        if self.stage == B4RegistryStage::Skeleton {
            ensure!(
                self.negative_cases.is_empty(),
                "B4 skeleton must not contain partially expanded negative rows"
            );
            return Ok(());
        }
        let plan = Eip0045B4NegativePlanV1::canonical()
            .context("cannot construct canonical B4 negative plan")?;
        self.validate_negative_inventory_against_plan(&plan)
    }

    fn validate_negative_inventory_against_plan(
        &self,
        plan: &Eip0045B4NegativePlanV1,
    ) -> Result<()> {
        plan.validate().context("invalid B4 negative plan")?;
        ensure!(
            self.negative_cases.len() == usize::from(B4_NEGATIVE_PLAN_VARIANT_COUNT),
            "expanded B4 registry must contain exactly {B4_NEGATIVE_PLAN_VARIANT_COUNT} negative rows"
        );

        let mut registry_rows = self.negative_cases.iter();
        let mut seen = BTreeSet::new();
        for (index, (group, execution)) in plan
            .groups
            .iter()
            .flat_map(|group| {
                group
                    .executions
                    .iter()
                    .map(move |execution| (group, execution))
            })
            .enumerate()
        {
            let case = registry_rows
                .next()
                .context("expanded B4 registry is missing a planned execution")?;
            validate_execution_id(&case.execution_id, "negative execution ID")?;
            reject_unexpanded(&case.execution_id, "negative execution ID")?;
            ensure!(
                seen.insert(case.execution_id.as_str()),
                "duplicate negative execution ID at index {index}"
            );
            ensure!(
                case.execution_id == execution.execution_id,
                "negative execution ID/order drift at index {index}"
            );
            ensure!(
                case.base_selector_id == execution.base_selector_id,
                "negative base-selector binding drift for {}",
                case.execution_id
            );
            ensure!(
                case.materialization_domain == execution.materialization_domain,
                "negative materialization-domain drift for {}",
                case.execution_id
            );
            validate_semantic_id(&case.base_selector_id, "negative base selector ID")?;
            reject_unexpanded(&case.base_selector_id, "negative base selector ID")?;
            let requires_fixture = negative_group_requires_fixture_selection(&group.case_id);
            match (&case.materialization, requires_fixture) {
                (B4NegativeMaterialization::FixtureSelection { fixture_id }, true) => {
                    validate_semantic_id(fixture_id, "negative fixture ID")?;
                    reject_unexpanded(fixture_id, "negative fixture ID")?;
                    ensure!(
                        fixture_id == &execution.base_selector_id,
                        "negative fixture selection differs from the canonical plan for {}",
                        case.execution_id
                    );
                }
                (B4NegativeMaterialization::Mutation { mutation }, false) => {
                    validate_negative_mutation_family(&case.execution_id, mutation)?;
                    mutation.validate()?;
                }
                (B4NegativeMaterialization::FixtureSelection { .. }, false) => bail!(
                    "negative execution {} uses fixture selection outside the four closed receipt groups",
                    case.execution_id
                ),
                (B4NegativeMaterialization::Mutation { .. }, true) => bail!(
                    "negative execution {} must select its independently verified receipt fixture",
                    case.execution_id
                ),
            }
        }
        ensure!(
            registry_rows.next().is_none(),
            "expanded B4 registry contains an execution outside the canonical plan"
        );
        Ok(())
    }

    fn check_binding_file(
        root: &Path,
        binding: &B4ArtifactBinding,
        paths: &mut BTreeSet<String>,
    ) -> Result<()> {
        if binding.state == B4BindingState::Bound {
            check_physical_artifact(
                root,
                &binding.path,
                binding.byte_length,
                &binding.sha256,
                binding.encoding,
                paths,
            )?;
        }
        Ok(())
    }
}

fn validate_negative_mutation_family(
    execution_id: &str,
    mutation: &B4NegativeMutation,
) -> Result<()> {
    match (
        execution_id == B4_ALTERNATE_ROOT_ASSUMPTION_EXECUTION_ID,
        mutation,
    ) {
        (true, B4NegativeMutation::AlternateRootAssumptionSubstitution {}) => return Ok(()),
        (true, _) => bail!(
            "negative execution {execution_id} must use the fixed alternate-root assumption substitution"
        ),
        (false, B4NegativeMutation::AlternateRootAssumptionSubstitution {}) => bail!(
            "alternate-root assumption substitution is reserved for negative execution \
             {B4_ALTERNATE_ROOT_ASSUMPTION_EXECUTION_ID}"
        ),
        (false, _) => {}
    }
    if let Some(expected_recipe) = negative_ancestry_witness_recipe(execution_id) {
        return match mutation {
            B4NegativeMutation::AncestryWitnessSubstitution { recipe }
                if *recipe == expected_recipe =>
            {
                Ok(())
            }
            B4NegativeMutation::AncestryWitnessSubstitution { .. } => bail!(
                "negative execution {execution_id} uses the wrong ancestry-witness-substitution recipe"
            ),
            _ => bail!(
                "negative execution {execution_id} must use its ancestry-witness-substitution recipe"
            ),
        };
    }
    if matches!(
        mutation,
        B4NegativeMutation::AncestryWitnessSubstitution { .. }
    ) {
        bail!(
            "ancestry-witness-substitution is reserved for its eleven closed negative executions"
        );
    }
    match (
        execution_id == B4_ANCESTRY_INVENTORY_EDIT_EXECUTION_ID,
        mutation,
    ) {
        (true, B4NegativeMutation::AncestryInventoryEdit { .. }) => Ok(()),
        (true, _) => {
            bail!("negative execution {execution_id} must use the ancestry-inventory-edit family")
        }
        (false, B4NegativeMutation::AncestryInventoryEdit { .. }) => bail!(
            "ancestry-inventory-edit is reserved for negative execution \
             {B4_ANCESTRY_INVENTORY_EDIT_EXECUTION_ID}"
        ),
        (false, _) => Ok(()),
    }
}

fn validate_statement_binding(binding: &B4StatementBinding) -> Result<()> {
    ensure!(
        binding.manifest.state == binding.state,
        "statement binding state differs from its manifest"
    );
    ensure!(
        binding.manifest.encoding == B4ArtifactEncoding::Rfc8785Jcs,
        "statement bundle manifest must be RFC 8785 JCS"
    );
    match binding.state {
        B4BindingState::Pending => {
            validate_pending_artifact(&binding.manifest)?;
            ensure!(
                binding.contract_id.is_empty() && binding.statement_sha256.is_empty(),
                "pending statement binding contains an identity"
            );
        }
        B4BindingState::Bound => {
            validate_candidate_binding(&binding.manifest)?;
            validate_digest(&binding.contract_id, "statement contract ID")?;
            validate_digest(&binding.statement_sha256, "statement SHA-256")?;
        }
    }
    Ok(())
}

fn validate_guest_binding(binding: &B4GuestBinding) -> Result<()> {
    ensure!(
        binding.elf.state == binding.state,
        "guest binding state differs from its ELF"
    );
    ensure!(
        binding.elf.encoding == B4ArtifactEncoding::RawBytes,
        "guest ELF must be raw bytes"
    );
    match binding.state {
        B4BindingState::Pending => {
            validate_pending_artifact(&binding.elf)?;
            ensure!(
                binding.image_id.is_empty(),
                "pending guest contains an image ID"
            );
        }
        B4BindingState::Bound => {
            validate_candidate_binding(&binding.elf)?;
            validate_digest(&binding.image_id, "guest image ID")?;
        }
    }
    Ok(())
}

fn validate_candidate_binding(binding: &B4ArtifactBinding) -> Result<()> {
    match binding.state {
        B4BindingState::Pending => validate_pending_artifact(binding),
        B4BindingState::Bound => {
            validate_bound_artifact(binding, true)?;
            ensure!(
                binding.path.starts_with(B4_CANDIDATE_ARTIFACT_ROOT),
                "bound B4 candidate identity is outside its quarantine tree"
            );
            Ok(())
        }
    }
}

fn validate_pending_artifact(binding: &B4ArtifactBinding) -> Result<()> {
    ensure!(
        binding.state == B4BindingState::Pending
            && binding.path.is_empty()
            && binding.byte_length == 0
            && binding.sha256.is_empty(),
        "pending artifact slot is not exactly empty"
    );
    Ok(())
}

fn validate_bound_artifact(binding: &B4ArtifactBinding, reject_final_path: bool) -> Result<()> {
    ensure!(
        binding.state == B4BindingState::Bound,
        "artifact is not bound"
    );
    validate_artifact_fields(
        &binding.path,
        binding.byte_length,
        &binding.sha256,
        reject_final_path,
    )
}

fn validate_positive_artifacts(case: &B4PositiveCase) -> Result<()> {
    let expected_roles = if case.family == B4PositiveFamily::Lift {
        POSITIVE_LIFT_ARTIFACTS.as_slice()
    } else {
        POSITIVE_RECURSIVE_ARTIFACTS.as_slice()
    };
    let actual_roles = case
        .artifacts
        .iter()
        .map(|item| item.role)
        .collect::<Vec<_>>();
    ensure!(
        actual_roles == expected_roles,
        "positive {} artifact roles/order are not closed",
        case.case_id
    );
    for artifact in &case.artifacts {
        let expected_encoding = match artifact.role {
            B4PositiveArtifactRole::Ancestry
            | B4PositiveArtifactRole::Calibration
            | B4PositiveArtifactRole::Metadata => B4ArtifactEncoding::Rfc8785Jcs,
            B4PositiveArtifactRole::ClaimDigest
            | B4PositiveArtifactRole::ControlId
            | B4PositiveArtifactRole::ImageId
            | B4PositiveArtifactRole::Journal
            | B4PositiveArtifactRole::RawSeal
            | B4PositiveArtifactRole::ReceiptOracle => B4ArtifactEncoding::RawBytes,
        };
        ensure!(
            artifact.encoding == expected_encoding,
            "positive {} artifact encoding drift for {:?}",
            case.case_id,
            artifact.role
        );
    }
    let prefix = format!("{}/", positive_case_artifact_directory(&case.case_id));
    validate_case_artifacts(&case.artifacts, &prefix, |artifact| {
        (&artifact.path, artifact.byte_length, &artifact.sha256)
    })
}

/// Return the one canonical candidate-directory path for a positive-case artifact.
#[cfg(feature = "positive-gate")]
pub(crate) fn canonical_positive_case_artifact_path(case_id: &str, basename: &str) -> String {
    format!("{}/{}", positive_case_artifact_directory(case_id), basename)
}

/// Bind one positive artifact to its exact case-local candidate path and basename.
#[cfg(feature = "positive-gate")]
pub(crate) fn validate_canonical_positive_case_artifact_path(
    case_id: &str,
    path: &str,
    basename: &str,
) -> Result<()> {
    validate_repository_path(path)?;
    ensure!(
        path == canonical_positive_case_artifact_path(case_id, basename),
        "positive artifact path differs from its canonical case directory or basename"
    );
    Ok(())
}

fn positive_case_artifact_directory(case_id: &str) -> String {
    format!("{B4_CANDIDATE_ARTIFACT_ROOT}positive/{case_id}")
}

fn validate_case_artifacts<'a, T, F>(artifacts: &'a [T], prefix: &str, fields: F) -> Result<()>
where
    F: Fn(&'a T) -> (&'a String, u64, &'a String),
{
    let mut paths = BTreeSet::new();
    for artifact in artifacts {
        let (path, byte_length, sha256) = fields(artifact);
        validate_artifact_fields(path, byte_length, sha256, true)?;
        ensure!(
            path.starts_with(prefix),
            "case artifact escapes its case directory"
        );
        ensure!(
            paths.insert(path.as_str()),
            "case artifact paths contain a duplicate"
        );
    }
    Ok(())
}

fn validate_artifact_fields(
    path: &str,
    byte_length: u64,
    sha256: &str,
    reject_final_path: bool,
) -> Result<()> {
    validate_repository_path(path)?;
    ensure!(
        path != B4_CANDIDATE_REGISTRY_PATH,
        "B4 registry cannot include itself"
    );
    if reject_final_path {
        reject_final_location(path)?;
    }
    ensure!(
        (1..=MAX_ARTIFACT_BYTES).contains(&byte_length),
        "artifact length is zero or exceeds the closed bound"
    );
    validate_digest(sha256, "artifact SHA-256")
}

fn validate_repository_path(path: &str) -> Result<()> {
    ensure!(
        (1..=MAX_REPOSITORY_PATH_BYTES).contains(&path.len()),
        "artifact path is empty or exceeds the portable bound"
    );
    ensure!(
        path.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-' | b'/')
        }),
        "artifact path is outside the portable lowercase ASCII subset"
    );
    ensure!(
        !path.starts_with('/') && !path.ends_with('/') && !path.contains("//"),
        "artifact path is not canonical repository-relative POSIX"
    );
    for component in path.split('/') {
        let bytes = component.as_bytes();
        ensure!(
            !bytes.is_empty()
                && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
                && component != "."
                && component != ".."
                && !component.ends_with('.')
                && !is_windows_device_component(component),
            "artifact path contains an unsafe or non-portable component"
        );
    }
    Ok(())
}

fn is_windows_device_component(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    matches!(stem, "con" | "prn" | "aux" | "nul")
        || stem
            .strip_prefix("com")
            .is_some_and(is_windows_device_digit)
        || stem
            .strip_prefix("lpt")
            .is_some_and(is_windows_device_digit)
}

fn is_windows_device_digit(suffix: &str) -> bool {
    suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9')
}

fn reject_final_location(path: &str) -> Result<()> {
    let lower = path.to_ascii_lowercase();
    ensure!(
        !lower.starts_with("vectors/")
            && !lower.starts_with("reproduction/frozen/")
            && lower != "reproduction/lock.json"
            && lower != "reproduction/schema-v1.json"
            && !lower.contains("/lock.json"),
        "candidate registry references a final vector or lock location"
    );
    Ok(())
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

fn validate_even_lower_hex(value: &str, label: &str) -> Result<()> {
    ensure!(
        value.len() <= 256
            && value.len().is_multiple_of(2)
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} is not bounded even-length lowercase hexadecimal"
    );
    Ok(())
}

fn validate_nonempty_hex(value: &str, label: &str) -> Result<u64> {
    validate_even_lower_hex(value, label)?;
    ensure!(!value.is_empty(), "{label} is empty");
    u64::try_from(value.len() / 2).context("hex byte length does not fit u64")
}

pub(crate) fn validate_byte_operation(operation: &B4ByteOperation) -> Result<()> {
    match operation {
        B4ByteOperation::Delete { before_hex, offset } => {
            let byte_length = validate_nonempty_hex(before_hex, "deleted bytes")?;
            validate_jcs_safe_integer(*offset, "byte deletion offset")?;
            let end = offset
                .checked_add(byte_length)
                .context("byte deletion range overflows u64")?;
            validate_jcs_safe_integer(end, "byte deletion range end")?;
        }
        B4ByteOperation::Insert {
            inserted_hex,
            offset,
        } => {
            let byte_length = validate_nonempty_hex(inserted_hex, "inserted bytes")?;
            validate_jcs_safe_integer(*offset, "byte insertion offset")?;
            let end = offset
                .checked_add(byte_length)
                .context("byte insertion range overflows u64")?;
            validate_jcs_safe_integer(end, "byte insertion range end")?;
        }
        B4ByteOperation::Replace {
            before_hex,
            replacement_hex,
            offset,
        } => {
            let before_length = validate_nonempty_hex(before_hex, "replaced bytes")?;
            let replacement_length = validate_nonempty_hex(replacement_hex, "replacement bytes")?;
            ensure!(
                before_length == replacement_length,
                "byte replacement changes length; use insert or delete"
            );
            ensure!(before_hex != replacement_hex, "byte replacement is a no-op");
            validate_jcs_safe_integer(*offset, "byte replacement offset")?;
            let end = offset
                .checked_add(before_length)
                .context("byte replacement range overflows u64")?;
            validate_jcs_safe_integer(end, "byte replacement range end")?;
        }
        B4ByteOperation::Truncate {
            before_hex,
            new_length,
            original_length,
        } => {
            let witness_length = validate_nonempty_hex(before_hex, "truncated bytes witness")?;
            validate_jcs_safe_integer(*new_length, "truncated new length")?;
            validate_jcs_safe_integer(*original_length, "truncated original length")?;
            ensure!(
                new_length < original_length,
                "truncation does not shorten the target"
            );
            let removed_length = original_length - new_length;
            ensure!(
                witness_length <= removed_length,
                "truncation witness exceeds the removed suffix"
            );
        }
    }
    Ok(())
}

fn validate_ancestry_inventory_operation(operation: &B4AncestryInventoryOperation) -> Result<()> {
    let B4AncestryInventoryOperation::PruneRevealedHead {
        before_claim_digest,
        before_control_root,
        exact_digest,
    } = operation;
    validate_digest(
        before_claim_digest,
        "revealed ancestry assumption claim digest",
    )?;
    validate_digest(
        before_control_root,
        "revealed ancestry assumption control root",
    )?;
    validate_digest(exact_digest, "pruned ancestry assumption exact digest")
}

pub(crate) fn validate_sequence_operation(
    target: B4SequenceTarget,
    operation: &B4SequenceOperation,
) -> Result<()> {
    match operation {
        B4SequenceOperation::Empty {} => ensure!(
            target == B4SequenceTarget::ProofChunks,
            "empty sequence mutation is admitted only for proof chunks"
        ),
        B4SequenceOperation::Insert {
            inserted_element,
            index,
        } => {
            validate_jcs_safe_integer(*index, "sequence insertion index")?;
            inserted_element.validate_for(target)?;
        }
        B4SequenceOperation::Move {
            before_element_id,
            before_element_sha256,
            from_index,
            to_index,
        } => {
            validate_semantic_id(before_element_id, "moved sequence element ID")?;
            validate_digest(before_element_sha256, "moved sequence element SHA-256")?;
            validate_jcs_safe_integer(*from_index, "sequence move source index")?;
            validate_jcs_safe_integer(*to_index, "sequence move destination index")?;
            ensure!(from_index != to_index, "sequence move is a no-op");
        }
        B4SequenceOperation::Omit {
            before_element_id,
            before_element_sha256,
            index,
        } => {
            validate_semantic_id(before_element_id, "omitted sequence element ID")?;
            validate_digest(before_element_sha256, "omitted sequence element SHA-256")?;
            validate_jcs_safe_integer(*index, "sequence omission index")?;
        }
        B4SequenceOperation::Replace {
            before_element_id,
            before_element_sha256,
            index,
            replacement_element,
        } => {
            validate_semantic_id(before_element_id, "replaced sequence element ID")?;
            validate_digest(before_element_sha256, "replaced sequence element SHA-256")?;
            validate_jcs_safe_integer(*index, "sequence replacement index")?;
            replacement_element.validate_for(target)?;
            ensure!(
                before_element_id != &replacement_element.element_id
                    || before_element_sha256 != &replacement_element.sha256,
                "sequence replacement is a no-op"
            );
        }
        B4SequenceOperation::ShiftBoundary {
            byte_count,
            left_chunk_index,
            ..
        } => {
            ensure!(
                target == B4SequenceTarget::ProofChunks,
                "boundary shift is admitted only for proof chunks"
            );
            validate_jcs_safe_integer(*byte_count, "proof-chunk boundary byte count")?;
            validate_jcs_safe_integer(*left_chunk_index, "proof-chunk boundary index")?;
            ensure!(*byte_count > 0, "boundary shift moves zero bytes");
            // The source-chunk length is bound by the selected positive case,
            // so only the semantic reconstruction gate can enforce
            // `byte_count < source_chunk.len()` and keep the source nonempty.
            let right_chunk_index = left_chunk_index
                .checked_add(1)
                .context("proof-chunk boundary index has no right neighbor")?;
            validate_jcs_safe_integer(right_chunk_index, "proof-chunk right-neighbor index")?;
        }
    }
    Ok(())
}

fn validate_jcs_safe_integer(value: u64, label: &str) -> Result<()> {
    ensure!(
        value <= B4_MAX_JCS_SAFE_INTEGER,
        "{label} exceeds the RFC 8785 exact-integer bound"
    );
    Ok(())
}

fn validate_semantic_id(value: &str, label: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !value.starts_with('-')
            && !value.ends_with('-')
            && !value.contains("--"),
        "{label} is not a bounded lower-kebab identifier"
    );
    Ok(())
}

fn validate_execution_id(value: &str, label: &str) -> Result<()> {
    let (group_id, variant_id) = value.split_once("--").with_context(|| {
        format!("{label} does not contain the canonical group/variant separator")
    })?;
    ensure!(
        !variant_id.contains("--"),
        "{label} contains more than one group/variant separator"
    );
    validate_semantic_id(group_id, label)?;
    validate_semantic_id(variant_id, label)
}

fn reject_unexpanded(value: &str, label: &str) -> Result<()> {
    let lower = value.to_ascii_lowercase();
    let forbidden = [
        "template", "wildcard", "every", "each", "all-", "todo", "tbd",
    ];
    ensure!(
        !forbidden.iter().any(|needle| lower.contains(needle))
            && !value.contains(['*', '{', '}', '[', ']', '?']),
        "{label} contains an unexpanded template"
    );
    Ok(())
}

fn canonical_negative_plan_source(source: &[u8]) -> Result<Eip0045B4NegativePlanV1> {
    let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(source)
        .context("invalid canonical B4 negative-plan source")?;
    ensure!(
        plan == Eip0045B4NegativePlanV1::canonical()?,
        "negative-plan source is not the exact canonical V1 inventory"
    );
    Ok(plan)
}

fn binding_for_exact_source(
    path: String,
    encoding: B4ArtifactEncoding,
    source: &[u8],
) -> Result<B4ArtifactBinding> {
    Ok(B4ArtifactBinding {
        byte_length: u64::try_from(source.len()).context("artifact source length exceeds u64")?,
        encoding,
        path,
        sha256: hex::encode(Sha256::digest(source)),
        state: B4BindingState::Bound,
    })
}

fn validate_binding_matches_source(binding: &B4ArtifactBinding, source: &[u8]) -> Result<()> {
    validate_candidate_binding(binding)?;
    ensure!(
        binding.encoding == B4ArtifactEncoding::Rfc8785Jcs,
        "negative-plan artifact binding is not RFC 8785 JCS"
    );
    ensure!(
        binding.byte_length
            == u64::try_from(source.len()).context("negative-plan source length exceeds u64")?
            && binding.sha256 == hex::encode(Sha256::digest(source)),
        "negative-plan artifact binding differs from the supplied canonical source"
    );
    Ok(())
}

fn require_ordinary_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {label}: {}", path.display()))?;
    reject_link_or_reparse(path, &metadata)?;
    ensure!(metadata.file_type().is_dir(), "{label} is not a directory");
    Ok(())
}

fn check_physical_artifact(
    root: &Path,
    relative: &str,
    expected_length: u64,
    expected_sha256: &str,
    encoding: B4ArtifactEncoding,
    paths: &mut BTreeSet<String>,
) -> Result<()> {
    ensure!(
        paths.insert(relative.to_owned()),
        "duplicate artifact path: {relative}"
    );
    let path = join_physical_path(root, relative)?;
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("cannot inspect B4 artifact {relative}"))?;
    reject_link_or_reparse(&path, &metadata)?;
    ensure!(
        metadata.file_type().is_file(),
        "B4 artifact is not a regular file: {relative}"
    );
    ensure!(
        metadata.len() == expected_length,
        "B4 artifact length mismatch: {relative}"
    );

    let mut file =
        File::open(&path).with_context(|| format!("cannot open B4 artifact {relative}"))?;
    let opened = file
        .metadata()
        .with_context(|| format!("cannot inspect opened B4 artifact {relative}"))?;
    reject_link_or_reparse(&path, &opened)?;
    ensure!(
        opened.file_type().is_file(),
        "opened B4 artifact is not regular: {relative}"
    );
    ensure!(
        opened.len() == expected_length,
        "opened B4 artifact length mismatch: {relative}"
    );

    let mut digest = Sha256::new();
    let mut canonical_bytes = if encoding == B4ArtifactEncoding::Rfc8785Jcs {
        ensure!(
            expected_length <= MAX_CANONICAL_JSON_BYTES,
            "canonical B4 artifact exceeds its closed size bound: {relative}"
        );
        Some(Vec::with_capacity(usize::try_from(expected_length)?))
    } else {
        None
    };
    let mut observed = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("cannot read B4 artifact {relative}"))?;
        if count == 0 {
            break;
        }
        observed = observed
            .checked_add(u64::try_from(count)?)
            .context("B4 artifact observed length overflow")?;
        digest.update(&buffer[..count]);
        if let Some(bytes) = &mut canonical_bytes {
            bytes.write_all(&buffer[..count])?;
        }
    }
    ensure!(
        observed == expected_length,
        "B4 artifact changed while hashing: {relative}"
    );
    ensure!(
        hex::encode(digest.finalize()) == expected_sha256,
        "B4 artifact digest mismatch: {relative}"
    );
    if let Some(bytes) = canonical_bytes {
        validate_canonical_json_source(&bytes)
            .with_context(|| format!("B4 artifact is not exact RFC 8785 JCS: {relative}"))?;
    }
    Ok(())
}

fn join_physical_path(root: &Path, relative: &str) -> Result<PathBuf> {
    validate_repository_path(relative)?;
    let mut current = root.to_path_buf();
    let components = relative.split('/').collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("cannot inspect B4 path component {}", current.display()))?;
        reject_link_or_reparse(&current, &metadata)?;
        if index + 1 != components.len() {
            ensure!(
                metadata.file_type().is_dir(),
                "B4 artifact parent is not a directory: {}",
                current.display()
            );
        }
    }
    let canonical = fs::canonicalize(&current)
        .with_context(|| format!("cannot canonicalize B4 artifact {}", current.display()))?;
    ensure!(
        canonical.starts_with(root),
        "B4 artifact escapes repository root"
    );
    Ok(canonical)
}

fn reject_link_or_reparse(path: &Path, metadata: &Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || is_windows_path_alias(metadata) {
        bail!(
            "symlink or path-redirection reparse point is forbidden: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn is_windows_path_alias(metadata: &Metadata) -> bool {
    use std::os::windows::fs::FileTypeExt;

    let file_type = metadata.file_type();
    file_type.is_symlink_dir() || file_type.is_symlink_file()
}

#[cfg(not(windows))]
fn is_windows_path_alias(_metadata: &Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn skeleton() -> B4CandidateCorpus {
        let bytes = include_bytes!("../schema/b4-corpus-v1.candidate.json");
        B4CandidateCorpus::from_canonical_jcs(bytes).unwrap()
    }

    fn digest(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn canonical_plan_source() -> Vec<u8> {
        Eip0045B4NegativePlanV1::canonical()
            .unwrap()
            .to_canonical_jcs()
            .unwrap()
    }

    fn sequence_element(id: &str, bytes: &[u8]) -> B4SequenceSubjectElement {
        B4SequenceSubjectElement::from_bytes(id, bytes).unwrap()
    }

    fn bound(path: String, encoding: B4ArtifactEncoding) -> B4ArtifactBinding {
        B4ArtifactBinding {
            byte_length: 1,
            encoding,
            path,
            sha256: digest(0),
            state: B4BindingState::Bound,
        }
    }

    fn pending(encoding: B4ArtifactEncoding) -> B4ArtifactBinding {
        B4ArtifactBinding {
            byte_length: 0,
            encoding,
            path: String::new(),
            sha256: String::new(),
            state: B4BindingState::Pending,
        }
    }

    fn positive_artifacts(case: &B4PositiveCase) -> Vec<B4PositiveArtifact> {
        let roles = if case.family == B4PositiveFamily::Lift {
            POSITIVE_LIFT_ARTIFACTS.as_slice()
        } else {
            POSITIVE_RECURSIVE_ARTIFACTS.as_slice()
        };
        roles
            .iter()
            .copied()
            .enumerate()
            .map(|(index, role)| B4PositiveArtifact {
                byte_length: 1,
                encoding: match role {
                    B4PositiveArtifactRole::Ancestry
                    | B4PositiveArtifactRole::Calibration
                    | B4PositiveArtifactRole::Metadata => B4ArtifactEncoding::Rfc8785Jcs,
                    B4PositiveArtifactRole::ClaimDigest
                    | B4PositiveArtifactRole::ControlId
                    | B4PositiveArtifactRole::ImageId
                    | B4PositiveArtifactRole::Journal
                    | B4PositiveArtifactRole::RawSeal
                    | B4PositiveArtifactRole::ReceiptOracle => B4ArtifactEncoding::RawBytes,
                },
                path: format!(
                    "{B4_CANDIDATE_ARTIFACT_ROOT}positive/{}/{index:02}-artifact",
                    case.case_id
                ),
                role,
                sha256: digest(1),
            })
            .collect()
    }

    fn valid_mutation(index: usize) -> B4NegativeMutation {
        match index % 2 {
            0 => B4NegativeMutation::ByteEdit {
                edit: B4ByteOperation::Replace {
                    before_hex: "00".to_owned(),
                    offset: 0,
                    replacement_hex: "01".to_owned(),
                },
                target: B4ByteTarget::Statement,
            },
            1 => B4NegativeMutation::SequenceEdit {
                edit: B4SequenceOperation::Omit {
                    before_element_id: "proof-chunk-00".to_owned(),
                    before_element_sha256: digest(2),
                    index: 0,
                },
                target: B4SequenceTarget::ProofChunks,
            },
            _ => unreachable!("modulo two has only byte and sequence mutation branches"),
        }
    }

    fn valid_ancestry_inventory_mutation() -> B4NegativeMutation {
        B4NegativeMutation::AncestryInventoryEdit {
            edit: B4AncestryInventoryOperation::PruneRevealedHead {
                before_claim_digest: digest(0x11),
                before_control_root: digest(0x22),
                exact_digest: digest(0x33),
            },
            target: B4AncestryInventoryTarget::AssumptionSourceInventoryHead,
        }
    }

    const ANCESTRY_SUBSTITUTION_WIRE_BINDINGS: [(&str, &str); 11] = [
        (
            "claim-edge-family-sweep--terminal-join",
            "reuse-case9-assumption-at-terminal-join-step0",
        ),
        (
            "claim-edge-family-sweep--terminal-resolve-explicit-root",
            "reuse-case9-assumption-at-terminal-resolve-step0",
        ),
        (
            "claim-edge-family-sweep--resolve-zero-root-then-join",
            "reuse-case9-final-resolve-at-resolve-then-join-step2",
        ),
        (
            "resolve-explicit-field-sweep--assumption-claim",
            "alternate-statement-assumption-lift-for-terminal-resolve",
        ),
        (
            "resolve-explicit-field-sweep--program-id",
            "alternate-guest-lift-for-terminal-resolve",
        ),
        (
            "resolve-explicit-field-sweep--final-claim",
            "alternate-statement-final-resolve-for-terminal-resolve",
        ),
        (
            "resolve-zero-root-field-sweep--assumption-claim",
            "alternate-statement-assumption-lift-for-resolve-then-join",
        ),
        (
            "resolve-zero-root-field-sweep--program-id",
            "alternate-guest-lift-for-resolve-then-join",
        ),
        (
            "resolve-zero-root-field-sweep--final-claim",
            "alternate-statement-final-join-for-resolve-then-join",
        ),
        (
            "resolve-assumption-inventory-sweep--missing-assumption",
            "reuse-case9-assumption-with-empty-inventory",
        ),
        (
            "resolve-assumption-inventory-sweep--extra-assumption",
            "duplicate-assumption-lift-with-duplicated-inventory",
        ),
    ];

    fn negative_case(
        index: usize,
        group_id: &str,
        execution: &crate::b4_plan::B4NegativePlanExecutionV1,
    ) -> B4NegativeCase {
        B4NegativeCase {
            execution_id: execution.execution_id.clone(),
            base_selector_id: execution.base_selector_id.clone(),
            materialization_domain: execution.materialization_domain,
            materialization: if let Some(recipe) =
                negative_ancestry_witness_recipe(&execution.execution_id)
            {
                B4NegativeMaterialization::Mutation {
                    mutation: B4NegativeMutation::AncestryWitnessSubstitution { recipe },
                }
            } else if execution.execution_id == B4_ALTERNATE_ROOT_ASSUMPTION_EXECUTION_ID {
                B4NegativeMaterialization::Mutation {
                    mutation: B4NegativeMutation::AlternateRootAssumptionSubstitution {},
                }
            } else if execution.execution_id == B4_ANCESTRY_INVENTORY_EDIT_EXECUTION_ID {
                B4NegativeMaterialization::Mutation {
                    mutation: valid_ancestry_inventory_mutation(),
                }
            } else if negative_group_requires_fixture_selection(group_id) {
                B4NegativeMaterialization::FixtureSelection {
                    fixture_id: execution.base_selector_id.clone(),
                }
            } else {
                B4NegativeMaterialization::Mutation {
                    mutation: valid_mutation(index),
                }
            },
        }
    }

    fn expanded() -> B4CandidateCorpus {
        let mut corpus = skeleton();
        corpus.stage = B4RegistryStage::Expanded;
        corpus.bindings.reference_statement_bundle = B4StatementBinding {
            contract_id: digest(8),
            manifest: bound(
                format!("{B4_CANDIDATE_ARTIFACT_ROOT}bindings/statement-manifest.json"),
                B4ArtifactEncoding::Rfc8785Jcs,
            ),
            statement_sha256: digest(9),
            state: B4BindingState::Bound,
        };
        corpus.bindings.guest = B4GuestBinding {
            elf: bound(
                format!("{B4_CANDIDATE_ARTIFACT_ROOT}bindings/guest.elf"),
                B4ArtifactEncoding::RawBytes,
            ),
            image_id: digest(10),
            state: B4BindingState::Bound,
        };
        corpus.bindings.source_lock = bound(
            format!("{B4_CANDIDATE_ARTIFACT_ROOT}bindings/source-lock.json"),
            B4ArtifactEncoding::Rfc8785Jcs,
        );
        corpus.bindings.generator = bound(
            format!("{B4_CANDIDATE_ARTIFACT_ROOT}bindings/generator.bin"),
            B4ArtifactEncoding::RawBytes,
        );
        corpus.bindings.rust_verifier = bound(
            format!("{B4_CANDIDATE_ARTIFACT_ROOT}bindings/rust-verifier.bin"),
            B4ArtifactEncoding::RawBytes,
        );
        corpus.bindings.jvm_verifier = bound(
            format!("{B4_CANDIDATE_ARTIFACT_ROOT}bindings/jvm-verifier.bin"),
            B4ArtifactEncoding::RawBytes,
        );
        corpus
            .bind_canonical_negative_plan_source(
                format!("{B4_CANDIDATE_ARTIFACT_ROOT}bindings/negative-plan.json"),
                &canonical_plan_source(),
            )
            .unwrap();
        corpus.bindings.subject_catalog = bound(
            format!("{B4_CANDIDATE_ARTIFACT_ROOT}bindings/subject-catalog.json"),
            B4ArtifactEncoding::Rfc8785Jcs,
        );
        corpus.bindings.terminal_fixture_catalog = bound(
            format!("{B4_CANDIDATE_ARTIFACT_ROOT}bindings/terminal-fixture-catalog.json"),
            B4ArtifactEncoding::Rfc8785Jcs,
        );
        for case in &mut corpus.positive_cases {
            case.artifacts = positive_artifacts(case);
        }
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        corpus.negative_cases = plan
            .groups
            .iter()
            .flat_map(|group| {
                group
                    .executions
                    .iter()
                    .map(move |execution| (group, execution))
            })
            .enumerate()
            .map(|(index, (group, execution))| negative_case(index, &group.case_id, execution))
            .collect();
        corpus.validate_structural().unwrap();
        corpus
            .validate_expanded_against_canonical_plan_source(&canonical_plan_source())
            .unwrap();
        corpus
    }

    #[test]
    fn exact_candidate_skeleton_is_canonical_and_valid() {
        skeleton().validate().unwrap();
    }

    #[test]
    fn expanded_lifecycle_is_fail_closed_until_the_semantic_gate_exists() {
        let expanded = expanded();
        expanded.validate_structural().unwrap();
        expanded
            .validate_expanded_against_canonical_plan_source(&canonical_plan_source())
            .unwrap();
        assert!(expanded.validate().is_err());
        assert!(expanded.validate_physical(".").is_err());
    }

    #[test]
    fn expanded_negative_rows_are_minimal_plan_bound_and_cycle_free() {
        let expanded = expanded();
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        assert_eq!(
            expanded.negative_cases.len(),
            usize::from(B4_NEGATIVE_PLAN_VARIANT_COUNT)
        );
        let planned = plan
            .groups
            .iter()
            .flat_map(|group| {
                group
                    .executions
                    .iter()
                    .map(move |execution| (group, execution))
            })
            .collect::<Vec<_>>();
        let mut fixture_count = 0_usize;
        for (index, (case, (group, execution))) in
            expanded.negative_cases.iter().zip(planned).enumerate()
        {
            assert_eq!(case.execution_id, execution.execution_id, "row {index}");
            assert_eq!(
                case.base_selector_id, execution.base_selector_id,
                "row {index}"
            );
            assert_eq!(
                case.materialization_domain, execution.materialization_domain,
                "row {index}"
            );
            let value = serde_json::to_value(case).unwrap();
            let object = value.as_object().unwrap();
            assert_eq!(object.len(), 4, "row {index}");
            for key in [
                "executionId",
                "baseSelectorId",
                "materializationDomain",
                "materialization",
            ] {
                assert!(object.contains_key(key), "row {index} lacks {key}");
            }
            for forbidden in [
                "artifacts",
                "class",
                "intendedInvariant",
                "mutation",
                "observedJvmRejection",
                "observedRustRejection",
            ] {
                assert!(
                    !object.contains_key(forbidden),
                    "row {index} retains {forbidden}"
                );
            }
            match (
                &case.materialization,
                negative_group_requires_fixture_selection(&group.case_id),
            ) {
                (B4NegativeMaterialization::FixtureSelection { fixture_id }, true) => {
                    fixture_count += 1;
                    assert_eq!(fixture_id, &execution.base_selector_id);
                }
                (B4NegativeMaterialization::Mutation { .. }, false) => {}
                _ => panic!("row {index} has the wrong materialization family"),
            }
        }
        assert_eq!(fixture_count, 11);

        let inner_root = expanded
            .negative_cases
            .iter()
            .find(|case| case.execution_id == "terminal-inner-root-mismatch--inner-control-root")
            .unwrap();
        assert_eq!(inner_root.base_selector_id, "alternate-root-lift-po2-15-v1");
        assert_eq!(
            inner_root.materialization,
            B4NegativeMaterialization::FixtureSelection {
                fixture_id: "alternate-root-lift-po2-15-v1".to_owned(),
            }
        );

        for forbidden in [
            "artifacts",
            "class",
            "intendedInvariant",
            "observedJvmRejection",
            "observedRustRejection",
        ] {
            let mut value = serde_json::to_value(&expanded.negative_cases[0]).unwrap();
            value[forbidden] = serde_json::Value::Null;
            assert!(serde_json::from_value::<B4NegativeCase>(value).is_err());
        }

        let mut noncanonical = canonical_plan_source();
        noncanonical.push(b'\n');
        assert!(
            expanded
                .validate_expanded_against_canonical_plan_source(&noncanonical)
                .is_err()
        );
    }

    #[test]
    fn expanded_identity_branches_reject_each_unbound_slot() {
        for index in 0..9 {
            let mut corpus = expanded();
            match index {
                0 => {
                    corpus.bindings.reference_statement_bundle = B4StatementBinding {
                        contract_id: String::new(),
                        manifest: pending(B4ArtifactEncoding::Rfc8785Jcs),
                        statement_sha256: String::new(),
                        state: B4BindingState::Pending,
                    };
                }
                1 => {
                    corpus.bindings.guest = B4GuestBinding {
                        elf: pending(B4ArtifactEncoding::RawBytes),
                        image_id: String::new(),
                        state: B4BindingState::Pending,
                    };
                }
                2 => {
                    corpus.bindings.source_lock = pending(B4ArtifactEncoding::Rfc8785Jcs);
                }
                3 => corpus.bindings.generator = pending(B4ArtifactEncoding::RawBytes),
                4 => corpus.bindings.rust_verifier = pending(B4ArtifactEncoding::RawBytes),
                5 => corpus.bindings.jvm_verifier = pending(B4ArtifactEncoding::RawBytes),
                6 => corpus.bindings.negative_plan = pending(B4ArtifactEncoding::Rfc8785Jcs),
                7 => corpus.bindings.subject_catalog = pending(B4ArtifactEncoding::Rfc8785Jcs),
                8 => {
                    corpus.bindings.terminal_fixture_catalog =
                        pending(B4ArtifactEncoding::Rfc8785Jcs);
                }
                _ => unreachable!(),
            }
            assert!(
                corpus.validate_structural().is_err(),
                "accepted slot {index}"
            );
        }
    }

    #[test]
    fn expanded_positive_artifact_branches_reject_isolated_drifts() {
        let mut missing = expanded();
        missing.positive_cases[0].artifacts.pop();
        assert!(missing.validate_structural().is_err());

        let mut missing_ancestry = expanded();
        missing_ancestry.positive_cases[8].artifacts.remove(0);
        assert!(missing_ancestry.validate_structural().is_err());

        let mut wrong_encoding = expanded();
        wrong_encoding.positive_cases[0].artifacts[4].encoding = B4ArtifactEncoding::RawBytes;
        assert!(wrong_encoding.validate_structural().is_err());

        let mut escaped_case = expanded();
        escaped_case.positive_cases[0].artifacts[0].path =
            format!("{B4_CANDIDATE_ARTIFACT_ROOT}positive/other/00-artifact");
        assert!(escaped_case.validate_structural().is_err());
    }

    #[test]
    fn expanded_recursive_positive_paths_follow_role_order_and_remain_unique() {
        let mut corpus = expanded();
        let recursive = &mut corpus.positive_cases[8];
        let case_directory = format!("{B4_CANDIDATE_ARTIFACT_ROOT}positive/{}", recursive.case_id);
        let canonical_basenames = [
            "candidate-ancestry.json",
            "candidate-recursive-calibration.json",
            "candidate-claim-digest.bin",
            "candidate-control-id.bin",
            "candidate-image-id.bin",
            "candidate-journal.bin",
            "candidate-raw-seal.bin",
            "candidate-recursive-oracle.borsh",
        ];
        for (artifact, basename) in recursive.artifacts.iter_mut().zip(canonical_basenames) {
            artifact.path = format!("{case_directory}/{basename}");
        }

        corpus.validate_structural().unwrap();

        let mut role_swap = corpus.clone();
        let calibration = role_swap.positive_cases[8].artifacts[1].role;
        role_swap.positive_cases[8].artifacts[1].role =
            role_swap.positive_cases[8].artifacts[2].role;
        role_swap.positive_cases[8].artifacts[2].role = calibration;
        assert!(role_swap.validate_structural().is_err());

        let mut duplicate = corpus;
        duplicate.positive_cases[8].artifacts[2].path =
            duplicate.positive_cases[8].artifacts[1].path.clone();
        assert!(duplicate.validate_structural().is_err());
    }

    #[test]
    fn expanded_negative_coverage_and_materialization_reject_isolated_drifts() {
        let mut missing = expanded();
        missing.negative_cases.pop();
        assert!(missing.validate_structural().is_err());

        let mut surplus = expanded();
        surplus
            .negative_cases
            .push(surplus.negative_cases.last().unwrap().clone());
        assert!(surplus.validate_structural().is_err());

        let mut wrong_selector = expanded();
        wrong_selector.negative_cases[0].base_selector_id = "unknown-selector".to_owned();
        assert!(wrong_selector.validate_structural().is_err());

        let mut wrong_domain = expanded();
        wrong_domain.negative_cases[0].materialization_domain =
            B4MaterializationDomain::ArtifactValidator;
        assert!(wrong_domain.validate_structural().is_err());

        let mut unsorted = expanded();
        unsorted.negative_cases.swap(0, 1);
        assert!(unsorted.validate_structural().is_err());

        let fixture_index = expanded()
            .negative_cases
            .iter()
            .position(|case| {
                matches!(
                    case.materialization,
                    B4NegativeMaterialization::FixtureSelection { .. }
                )
            })
            .unwrap();
        let mut wrong_fixture = expanded();
        wrong_fixture.negative_cases[fixture_index].materialization =
            B4NegativeMaterialization::FixtureSelection {
                fixture_id: "wrong-fixture".to_owned(),
            };
        assert!(wrong_fixture.validate_structural().is_err());

        let mut fixture_as_mutation = expanded();
        fixture_as_mutation.negative_cases[fixture_index].materialization =
            B4NegativeMaterialization::Mutation {
                mutation: valid_mutation(0),
            };
        assert!(fixture_as_mutation.validate_structural().is_err());

        let mut mutation_as_fixture = expanded();
        mutation_as_fixture.negative_cases[0].materialization =
            B4NegativeMaterialization::FixtureSelection {
                fixture_id: mutation_as_fixture.negative_cases[0]
                    .base_selector_id
                    .clone(),
            };
        assert!(mutation_as_fixture.validate_structural().is_err());

        let source = canonical_plan_source();
        let mut wrong_binding = expanded();
        wrong_binding.bindings.negative_plan.sha256 = digest(31);
        assert!(
            wrong_binding
                .validate_expanded_against_canonical_plan_source(&source)
                .is_err()
        );
    }

    #[test]
    fn ancestry_inventory_edit_family_is_bijectively_bound_to_row_155() {
        const ROW_155_EXECUTION_ID: &str = "resolve-assumption-inventory-sweep--pruned-assumption";

        let row_155_index = expanded()
            .negative_cases
            .iter()
            .position(|case| case.execution_id == ROW_155_EXECUTION_ID)
            .expect("canonical plan must contain the row-155 execution");
        assert_eq!(row_155_index, 155);

        let mut exact = expanded();
        exact.negative_cases[row_155_index].materialization = B4NegativeMaterialization::Mutation {
            mutation: valid_ancestry_inventory_mutation(),
        };
        exact.validate_structural().unwrap();

        let mut misplaced = exact.clone();
        misplaced.negative_cases[0].materialization = B4NegativeMaterialization::Mutation {
            mutation: valid_ancestry_inventory_mutation(),
        };
        assert!(misplaced.validate_structural().is_err());

        let mut downgraded = exact;
        downgraded.negative_cases[row_155_index].materialization =
            B4NegativeMaterialization::Mutation {
                mutation: valid_mutation(row_155_index),
            };
        assert!(downgraded.validate_structural().is_err());
    }

    #[test]
    fn alternate_root_assumption_substitution_is_bijectively_bound_to_row_146() {
        const ROW_146_EXECUTION_ID: &str = "resolve-explicit-field-sweep--assumption-receipt-root";

        let row_146_index = expanded()
            .negative_cases
            .iter()
            .position(|case| case.execution_id == ROW_146_EXECUTION_ID)
            .expect("canonical plan must contain the row-146 execution");
        assert_eq!(row_146_index, 146);

        let mut exact = expanded();
        exact.negative_cases[row_146_index].materialization = B4NegativeMaterialization::Mutation {
            mutation: B4NegativeMutation::AlternateRootAssumptionSubstitution {},
        };
        exact.validate_structural().unwrap();
        assert!(matches!(
            exact.negative_cases[row_146_index].materialization,
            B4NegativeMaterialization::Mutation {
                mutation: B4NegativeMutation::AlternateRootAssumptionSubstitution {},
            }
        ));

        let mut misplaced = exact.clone();
        misplaced.negative_cases[0].materialization = B4NegativeMaterialization::Mutation {
            mutation: B4NegativeMutation::AlternateRootAssumptionSubstitution {},
        };
        assert!(misplaced.validate_structural().is_err());

        let mut downgraded = exact.clone();
        downgraded.negative_cases[row_146_index].materialization =
            B4NegativeMaterialization::Mutation {
                mutation: valid_mutation(row_146_index),
            };
        assert!(downgraded.validate_structural().is_err());

        let mut relabelled = exact;
        relabelled.negative_cases[row_146_index].materialization =
            B4NegativeMaterialization::FixtureSelection {
                fixture_id: relabelled.negative_cases[row_146_index]
                    .base_selector_id
                    .clone(),
            };
        assert!(relabelled.validate_structural().is_err());
    }

    #[test]
    fn ancestry_witness_substitution_wire_and_registry_binding_are_exact() {
        let mutations = ANCESTRY_SUBSTITUTION_WIRE_BINDINGS
            .iter()
            .map(|(_, recipe)| {
                let value = serde_json::json!({
                    "family": "ancestry-witness-substitution",
                    "recipe": recipe
                });
                let mutation = serde_json::from_value::<B4NegativeMutation>(value.clone())
                    .expect("the exact ancestry-witness-substitution wire must parse");
                assert_eq!(serde_json::to_value(&mutation).unwrap(), value);
                mutation
            })
            .collect::<Vec<_>>();

        let exact = expanded();
        exact.validate_structural().unwrap();
        for ((execution_id, _), expected_mutation) in
            ANCESTRY_SUBSTITUTION_WIRE_BINDINGS.iter().zip(&mutations)
        {
            let row_index = exact
                .negative_cases
                .iter()
                .position(|case| case.execution_id == *execution_id)
                .expect("the central ancestry substitution execution must exist");
            for (candidate_index, candidate_mutation) in mutations.iter().enumerate() {
                let mut candidate = exact.clone();
                candidate.negative_cases[row_index].materialization =
                    B4NegativeMaterialization::Mutation {
                        mutation: candidate_mutation.clone(),
                    };
                assert_eq!(
                    candidate.validate_structural().is_ok(),
                    candidate_mutation == expected_mutation,
                    "execution {execution_id} accepted recipe index {candidate_index}"
                );
            }
        }

        for (row_index, row) in exact.negative_cases.iter().enumerate() {
            if ANCESTRY_SUBSTITUTION_WIRE_BINDINGS
                .iter()
                .any(|(execution_id, _)| row.execution_id == *execution_id)
            {
                continue;
            }
            for mutation in &mutations {
                let mut candidate = exact.clone();
                candidate.negative_cases[row_index].materialization =
                    B4NegativeMaterialization::Mutation {
                        mutation: mutation.clone(),
                    };
                assert!(
                    candidate.validate_structural().is_err(),
                    "{} accepted a reserved ancestry substitution recipe",
                    row.execution_id
                );
            }
        }

        for excluded_row in [144_usize, 146, 149, 155] {
            assert!(
                ANCESTRY_SUBSTITUTION_WIRE_BINDINGS
                    .iter()
                    .all(
                        |(execution_id, _)| exact.negative_cases[excluded_row].execution_id
                            != *execution_id
                    ),
                "row {excluded_row} entered the ancestry substitution table"
            );
        }

        for invalid in [
            serde_json::json!({
                "family": "ancestry-witness-substitution",
                "recipe": ANCESTRY_SUBSTITUTION_WIRE_BINDINGS[0].1,
                "witnessId": "case9-assumption-lift"
            }),
            serde_json::json!({
                "family": "ancestry-witness-substitution",
                "recipe": "unknown-recipe"
            }),
        ] {
            assert!(serde_json::from_value::<B4NegativeMutation>(invalid).is_err());
        }
    }

    #[test]
    fn terminal_metadata_record_byte_target_wire_is_exact_and_closed() {
        let value = serde_json::json!({
            "edit": {
                "insertedHex": "00",
                "offset": 0,
                "operation": "insert"
            },
            "family": "byte-edit",
            "target": {
                "targetKind": "terminal-metadata-record"
            }
        });
        let parsed = serde_json::from_value::<B4NegativeMutation>(value.clone())
            .expect("terminal-metadata-record byte target must parse");
        assert_eq!(serde_json::to_value(parsed).unwrap(), value);

        let mut unknown_kind = value.clone();
        unknown_kind["target"]["targetKind"] =
            serde_json::Value::String("unknown-terminal-target".to_owned());
        assert!(serde_json::from_value::<B4NegativeMutation>(unknown_kind).is_err());

        let mut unknown_field = value;
        unknown_field["target"]["unexpected"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<B4NegativeMutation>(unknown_field).is_err());
    }

    #[test]
    fn ancestry_inventory_edit_wire_is_exact_closed_and_hex_bounded() {
        let value = serde_json::json!({
            "edit": {
                "beforeClaimDigest": "11".repeat(32),
                "beforeControlRoot": "22".repeat(32),
                "exactDigest": "33".repeat(32),
                "operation": "prune-revealed-head"
            },
            "family": "ancestry-inventory-edit",
            "target": {
                "targetKind": "assumption-source-inventory-head"
            }
        });
        let parsed = serde_json::from_value::<B4NegativeMutation>(value.clone())
            .expect("closed ancestry-inventory edit must parse");
        parsed.validate().unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), value);

        for pointer in [
            "/edit/beforeClaimDigest",
            "/edit/beforeControlRoot",
            "/edit/exactDigest",
        ] {
            for invalid in ["aa".repeat(31), "AA".repeat(32)] {
                let mut candidate = value.clone();
                *candidate.pointer_mut(pointer).unwrap() = serde_json::Value::String(invalid);
                let parsed = serde_json::from_value::<B4NegativeMutation>(candidate).unwrap();
                assert!(parsed.validate().is_err());
            }
        }

        for candidate in [
            {
                let mut candidate = value.clone();
                candidate["unexpected"] = serde_json::Value::Bool(true);
                candidate
            },
            {
                let mut candidate = value.clone();
                candidate["edit"]["unexpected"] = serde_json::Value::Bool(true);
                candidate
            },
            {
                let mut candidate = value.clone();
                candidate["target"]["unexpected"] = serde_json::Value::Bool(true);
                candidate
            },
        ] {
            assert!(serde_json::from_value::<B4NegativeMutation>(candidate).is_err());
        }
    }

    #[test]
    fn closed_mutation_grammar_accepts_every_byte_operation_and_target() {
        let byte_targets = [
            B4ByteTarget::ApplicationPayload,
            B4ByteTarget::Ancestry,
            B4ByteTarget::CandidateRegistrySource,
            B4ByteTarget::PositiveCalibration,
            B4ByteTarget::PositiveMetadata,
            B4ByteTarget::ProfileArtifact {
                artifact: B4ProfileArtifact::Algorithm,
            },
            B4ByteTarget::ProfileArtifact {
                artifact: B4ProfileArtifact::AlgorithmArtifactPreimage,
            },
            B4ByteTarget::ProfileArtifact {
                artifact: B4ProfileArtifact::Constants,
            },
            B4ByteTarget::ProfileArtifact {
                artifact: B4ProfileArtifact::BinaryDataArtifactPreimage,
            },
            B4ByteTarget::ProfileArtifact {
                artifact: B4ProfileArtifact::ProfileId,
            },
            B4ByteTarget::ProfileArtifact {
                artifact: B4ProfileArtifact::ProfileIdPreimage,
            },
            B4ByteTarget::ProfileManifest,
            B4ByteTarget::ProfileId,
            B4ByteTarget::ProgramId,
            B4ByteTarget::ReceiptOracle,
            B4ByteTarget::RawSeal,
            B4ByteTarget::Statement,
            B4ByteTarget::SubjectCatalogEntry,
            B4ByteTarget::TerminalFixtureCatalogEntry,
            B4ByteTarget::TerminalMetadataRecord,
            B4ByteTarget::TerminalPolicyProbe,
        ];
        for target in byte_targets {
            let mutation = B4NegativeMutation::ByteEdit {
                edit: B4ByteOperation::Insert {
                    inserted_hex: "00".to_owned(),
                    offset: 0,
                },
                target,
            };
            mutation.validate().unwrap();
            let value = serde_json::to_value(&mutation).unwrap();
            serde_json::from_value::<B4NegativeMutation>(value).unwrap();
        }

        for edit in [
            B4ByteOperation::Delete {
                before_hex: "00".to_owned(),
                offset: 0,
            },
            B4ByteOperation::Insert {
                inserted_hex: "00".to_owned(),
                offset: 0,
            },
            B4ByteOperation::Replace {
                before_hex: "00".to_owned(),
                replacement_hex: "01".to_owned(),
                offset: 0,
            },
            B4ByteOperation::Truncate {
                before_hex: "00".to_owned(),
                new_length: 1,
                original_length: 2,
            },
        ] {
            B4NegativeMutation::ByteEdit {
                edit,
                target: B4ByteTarget::Statement,
            }
            .validate()
            .unwrap();
        }
    }

    #[test]
    fn closed_mutation_grammar_accepts_every_sequence_operation_target_and_terminal_family() {
        let sequence_targets = [
            B4SequenceTarget::AbstractTreeProbe,
            B4SequenceTarget::RegistryPositiveCases,
            B4SequenceTarget::RegistryNegativeCases,
            B4SequenceTarget::RegistryNegativeClasses,
            B4SequenceTarget::RegistryNegativeBindings,
            B4SequenceTarget::ProfilePackageFiles,
            B4SequenceTarget::ProofChunks,
        ];
        for target in sequence_targets {
            let mutation = B4NegativeMutation::SequenceEdit {
                edit: B4SequenceOperation::Omit {
                    before_element_id: "element-00".to_owned(),
                    before_element_sha256: digest(11),
                    index: 0,
                },
                target,
            };
            mutation.validate().unwrap();
            let value = serde_json::to_value(&mutation).unwrap();
            serde_json::from_value::<B4NegativeMutation>(value).unwrap();
        }

        for (target, edit) in [
            (B4SequenceTarget::ProofChunks, B4SequenceOperation::Empty {}),
            (
                B4SequenceTarget::ProfilePackageFiles,
                B4SequenceOperation::Insert {
                    inserted_element: sequence_element("file-c", br#"{"path":"c"}"#),
                    index: 0,
                },
            ),
            (
                B4SequenceTarget::RegistryPositiveCases,
                B4SequenceOperation::Move {
                    before_element_id: "case-00".to_owned(),
                    before_element_sha256: digest(13),
                    from_index: 0,
                    to_index: 1,
                },
            ),
            (
                B4SequenceTarget::RegistryNegativeClasses,
                B4SequenceOperation::Omit {
                    before_element_id: "class-00".to_owned(),
                    before_element_sha256: digest(14),
                    index: 0,
                },
            ),
            (
                B4SequenceTarget::ProofChunks,
                B4SequenceOperation::Replace {
                    before_element_id: "proof-chunk-00".to_owned(),
                    before_element_sha256: digest(15),
                    index: 0,
                    replacement_element: sequence_element("proof-chunk-00", b"replacement"),
                },
            ),
            (
                B4SequenceTarget::ProofChunks,
                B4SequenceOperation::ShiftBoundary {
                    byte_count: 1,
                    direction: B4BoundaryShiftDirection::LeftToRight,
                    left_chunk_index: 0,
                },
            ),
            (
                B4SequenceTarget::ProofChunks,
                B4SequenceOperation::ShiftBoundary {
                    byte_count: 1,
                    direction: B4BoundaryShiftDirection::RightToLeft,
                    left_chunk_index: 0,
                },
            ),
        ] {
            B4NegativeMutation::SequenceEdit { edit, target }
                .validate()
                .unwrap();
        }
    }

    #[test]
    fn mutation_integers_round_trip_at_the_rfc8785_exact_boundary() {
        let boundary = B4NegativeMutation::SequenceEdit {
            edit: B4SequenceOperation::Omit {
                before_element_id: "proof-chunk-00".to_owned(),
                before_element_sha256: digest(18),
                index: B4_MAX_JCS_SAFE_INTEGER,
            },
            target: B4SequenceTarget::ProofChunks,
        };
        boundary.validate().unwrap();
        let value = serde_json::to_value(&boundary).unwrap();
        let source = canonical_json_bytes(&value).unwrap();
        let reparsed_value = validate_canonical_json_source(&source).unwrap();
        let reparsed: B4NegativeMutation = serde_json::from_value(reparsed_value).unwrap();
        assert_eq!(reparsed, boundary);

        let above_boundary = B4NegativeMutation::SequenceEdit {
            edit: B4SequenceOperation::Omit {
                before_element_id: "proof-chunk-00".to_owned(),
                before_element_sha256: digest(18),
                index: B4_MAX_JCS_SAFE_INTEGER + 1,
            },
            target: B4SequenceTarget::ProofChunks,
        };
        assert!(above_boundary.validate().is_err());
    }

    #[test]
    fn byte_mutation_grammar_rejects_no_ops_and_impossible_records() {
        let invalid_byte_edits = [
            B4ByteOperation::Delete {
                before_hex: String::new(),
                offset: 0,
            },
            B4ByteOperation::Delete {
                before_hex: "00".to_owned(),
                offset: u64::MAX,
            },
            B4ByteOperation::Insert {
                inserted_hex: String::new(),
                offset: 0,
            },
            B4ByteOperation::Insert {
                inserted_hex: "00".to_owned(),
                offset: u64::MAX,
            },
            B4ByteOperation::Replace {
                before_hex: "00".to_owned(),
                replacement_hex: "00".to_owned(),
                offset: 0,
            },
            B4ByteOperation::Replace {
                before_hex: "00".to_owned(),
                replacement_hex: "0001".to_owned(),
                offset: 0,
            },
            B4ByteOperation::Replace {
                before_hex: "00".to_owned(),
                replacement_hex: "01".to_owned(),
                offset: u64::MAX,
            },
            B4ByteOperation::Truncate {
                before_hex: "00".to_owned(),
                new_length: 1,
                original_length: 1,
            },
            B4ByteOperation::Truncate {
                before_hex: "00".to_owned(),
                new_length: 2,
                original_length: 1,
            },
            B4ByteOperation::Truncate {
                before_hex: "0001".to_owned(),
                new_length: 1,
                original_length: 2,
            },
        ];
        for edit in invalid_byte_edits {
            assert!(
                B4NegativeMutation::ByteEdit {
                    edit,
                    target: B4ByteTarget::RawSeal,
                }
                .validate()
                .is_err()
            );
        }
    }

    #[test]
    fn sequence_and_terminal_mutation_grammar_rejects_no_ops_and_impossible_records() {
        let invalid_sequence_edits = [
            (
                B4SequenceTarget::RegistryPositiveCases,
                B4SequenceOperation::Empty {},
            ),
            (
                B4SequenceTarget::ProofChunks,
                B4SequenceOperation::Move {
                    before_element_id: "proof-chunk-00".to_owned(),
                    before_element_sha256: digest(19),
                    from_index: 1,
                    to_index: 1,
                },
            ),
            (
                B4SequenceTarget::RegistryNegativeClasses,
                B4SequenceOperation::ShiftBoundary {
                    byte_count: 1,
                    direction: B4BoundaryShiftDirection::LeftToRight,
                    left_chunk_index: 0,
                },
            ),
            (
                B4SequenceTarget::ProofChunks,
                B4SequenceOperation::ShiftBoundary {
                    byte_count: 0,
                    direction: B4BoundaryShiftDirection::LeftToRight,
                    left_chunk_index: 0,
                },
            ),
            (
                B4SequenceTarget::ProofChunks,
                B4SequenceOperation::ShiftBoundary {
                    byte_count: 1,
                    direction: B4BoundaryShiftDirection::LeftToRight,
                    left_chunk_index: u64::MAX,
                },
            ),
        ];
        for (target, edit) in invalid_sequence_edits {
            assert!(
                B4NegativeMutation::SequenceEdit { edit, target }
                    .validate()
                    .is_err()
            );
        }

        let same_element = sequence_element("proof-chunk-00", b"same-element");
        assert!(
            B4NegativeMutation::SequenceEdit {
                edit: B4SequenceOperation::Replace {
                    before_element_id: same_element.element_id.clone(),
                    before_element_sha256: same_element.sha256.clone(),
                    index: 0,
                    replacement_element: same_element,
                },
                target: B4SequenceTarget::ProofChunks,
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn fixture_selection_is_a_bounded_plan_exact_semantic_id() {
        for invalid in [
            String::new(),
            "invariant\ncontrol".to_owned(),
            "invariant-é".to_owned(),
            "a".repeat(129),
        ] {
            let mut corpus = expanded();
            let index = corpus
                .negative_cases
                .iter()
                .position(|case| {
                    matches!(
                        case.materialization,
                        B4NegativeMaterialization::FixtureSelection { .. }
                    )
                })
                .unwrap();
            corpus.negative_cases[index].materialization =
                B4NegativeMaterialization::FixtureSelection {
                    fixture_id: invalid,
                };
            assert!(corpus.validate_structural().is_err());
        }

        expanded().validate_structural().unwrap();
    }

    #[test]
    fn materialization_serde_is_closed_and_uses_stable_tags() {
        let mutation = B4NegativeMaterialization::Mutation {
            mutation: valid_mutation(0),
        };
        let mutation_value = serde_json::to_value(&mutation).unwrap();
        assert_eq!(mutation_value["materializationKind"], "mutation");
        serde_json::from_value::<B4NegativeMaterialization>(mutation_value).unwrap();

        let fixture = B4NegativeMaterialization::FixtureSelection {
            fixture_id: "lift-po2-14".to_owned(),
        };
        let mut fixture_value = serde_json::to_value(&fixture).unwrap();
        assert_eq!(fixture_value["materializationKind"], "fixture-selection");
        assert_eq!(fixture_value["fixtureId"], "lift-po2-14");
        serde_json::from_value::<B4NegativeMaterialization>(fixture_value.clone()).unwrap();
        fixture_value["unexpected"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<B4NegativeMaterialization>(fixture_value).is_err());

        assert!(
            serde_json::from_str::<B4NegativeMaterialization>(
                r#"{"materializationKind":"fixture-selection","fixtureId":"lift-po2-14","fixtureId":"lift-po2-14"}"#,
            )
            .is_err()
        );
    }

    #[test]
    fn surrogate_and_generic_v1_targets_reject_deserialization() {
        let byte_edit = serde_json::json!({
            "edit": {"insertedHex": "00", "offset": 0, "operation": "insert"},
            "family": "byte-edit",
            "target": {"targetKind": "corpus-registry"}
        });
        assert!(serde_json::from_value::<B4NegativeMutation>(byte_edit).is_err());

        for target in [
            serde_json::json!({"targetKind": "artifact-references"}),
            serde_json::json!({"targetKind": "negative-cases"}),
            serde_json::json!({"targetKind": "positive-cases"}),
            serde_json::json!({"targetKind": "negative-classes"}),
            serde_json::json!({"targetKind": "profile-artifact-references"}),
            serde_json::json!({"targetKind": "terminal-controls"}),
            serde_json::json!({
                "caseId": "lift-po2-15",
                "targetKind": "positive-case-artifacts"
            }),
            serde_json::json!({
                "caseId": "negative-00",
                "caseKind": "negative",
                "targetKind": "case-artifacts"
            }),
        ] {
            let sequence_edit = serde_json::json!({
                "edit": {
                    "beforeElementId": "element-00",
                    "beforeElementSha256": digest(25),
                    "index": 0,
                    "operation": "omit"
                },
                "family": "sequence-edit",
                "target": target
            });
            assert!(serde_json::from_value::<B4NegativeMutation>(sequence_edit).is_err());
        }
    }

    #[test]
    fn mutation_serde_is_closed_and_uses_stable_tags() {
        let mutations = [
            (
                valid_mutation(0),
                "byte-edit",
                Some(("beforeHex", "replacementHex")),
            ),
            (valid_mutation(1), "sequence-edit", None),
        ];
        for (mutation, expected_family, camel_case_edit_fields) in mutations {
            let value = serde_json::to_value(&mutation).unwrap();
            assert_eq!(value["family"], expected_family);
            if let Some((before, replacement)) = camel_case_edit_fields {
                assert!(value["edit"].get(before).is_some());
                assert!(value["edit"].get(replacement).is_some());
            }
            serde_json::from_value::<B4NegativeMutation>(value).unwrap();
        }

        let reject = |label: &str, value| {
            assert!(
                serde_json::from_value::<B4NegativeMutation>(value).is_err(),
                "mutation serde accepted {label}"
            );
        };
        reject("unknown family", serde_json::json!({"family": "unknown"}));

        let mut value = serde_json::to_value(valid_mutation(0)).unwrap();
        value["unexpected"] = serde_json::Value::Bool(true);
        reject("unknown outer field", value);

        let mut value = serde_json::to_value(valid_mutation(0)).unwrap();
        value["edit"]["unexpected"] = serde_json::Value::Bool(true);
        reject("unknown edit field", value);

        reject(
            "unknown empty-operation field",
            serde_json::json!({
                "edit": {"operation": "empty", "unexpected": true},
                "family": "sequence-edit",
                "target": {"targetKind": "proof-chunks"}
            }),
        );

        let mut value = serde_json::to_value(valid_mutation(0)).unwrap();
        value["target"]["unexpected"] = serde_json::Value::Bool(true);
        reject("unknown target field", value);

        let mut value = serde_json::to_value(valid_mutation(0)).unwrap();
        value["edit"]["operation"] = serde_json::Value::String("unknown".to_owned());
        reject("unknown operation", value);

        let mut value = serde_json::to_value(valid_mutation(1)).unwrap();
        value["target"]["targetKind"] = serde_json::Value::String("unknown".to_owned());
        reject("unknown target kind", value);

        reject(
            "surrogate inserted element",
            serde_json::json!({
                "edit": {
                    "index": 0,
                    "insertedElementSha256": digest(26),
                    "operation": "insert"
                },
                "family": "sequence-edit",
                "target": {"targetKind": "proof-chunks"}
            }),
        );

        let insertion = B4NegativeMutation::SequenceEdit {
            edit: B4SequenceOperation::Insert {
                inserted_element: sequence_element("proof-chunk-00", b"chunk"),
                index: 0,
            },
            target: B4SequenceTarget::ProofChunks,
        };
        let mut value = serde_json::to_value(insertion).unwrap();
        value["edit"]["insertedElement"]["unexpected"] = serde_json::Value::Bool(true);
        reject("unknown inserted-element field", value);
    }

    #[test]
    fn mutation_serde_rejects_duplicate_fields_before_value_flattening() {
        let duplicate_sources = [
            r#"{"family":"byte-edit","family":"byte-edit","edit":{"insertedHex":"00","offset":0,"operation":"insert"},"target":{"targetKind":"statement"}}"#,
            r#"{"family":"byte-edit","edit":{"insertedHex":"00","offset":0,"operation":"insert","operation":"insert"},"target":{"targetKind":"statement"}}"#,
            r#"{"family":"byte-edit","edit":{"insertedHex":"00","offset":0,"operation":"insert"},"target":{"targetKind":"statement","targetKind":"statement"}}"#,
            r#"{"family":"sequence-edit","edit":{"index":0,"insertedElement":{"bytesHex":"00","elementId":"chunk-new","elementId":"chunk-new","sha256":"0000000000000000000000000000000000000000000000000000000000000000"},"operation":"insert"},"target":{"targetKind":"proof-chunks"}}"#,
        ];
        for source in duplicate_sources {
            assert!(serde_json::from_str::<B4NegativeMutation>(source).is_err());
        }

        assert!(
            serde_json::from_str::<B4NegativeMutation>(
                r#"{"family":"byte-edit","edit":{"insertedHex":"00","operation":"insert"},"target":{"targetKind":"statement"}}"#,
            )
            .is_err()
        );
    }

    #[test]
    fn empty_sequence_operation_wire_format_is_exact() {
        let value = serde_json::to_value(B4SequenceOperation::Empty {}).unwrap();
        assert_eq!(value, serde_json::json!({"operation": "empty"}));
        assert_eq!(
            serde_json::from_value::<B4SequenceOperation>(value).unwrap(),
            B4SequenceOperation::Empty {}
        );
    }

    #[test]
    fn missing_duplicate_reordered_and_relabelled_positives_reject() {
        let mut missing = skeleton();
        missing.positive_cases.pop();
        assert!(missing.validate().is_err());

        let mut duplicate = skeleton();
        duplicate.positive_cases[1] = duplicate.positive_cases[0].clone();
        assert!(duplicate.validate().is_err());

        let mut reordered = skeleton();
        reordered.positive_cases.swap(0, 1);
        assert!(reordered.validate().is_err());

        let mut relabelled = skeleton();
        relabelled.positive_cases[8].case_id = "terminal-join-renamed".to_owned();
        assert!(relabelled.validate().is_err());
    }

    #[test]
    fn family_mode_terminal_po2_and_root_drift_reject() {
        let mut family = skeleton();
        family.positive_cases[8].family = B4PositiveFamily::Lift;
        assert!(family.validate().is_err());

        let mut mode = skeleton();
        mode.positive_cases[9].guest_mode = B4GuestMode::VerifyAssumptionZeroRoot;
        assert!(mode.validate().is_err());

        let mut terminal = skeleton();
        terminal.positive_cases[9].terminal.kind = B4TerminalKind::Join;
        assert!(terminal.validate().is_err());

        let mut po2 = skeleton();
        po2.positive_cases[0].terminal.parameter = 16;
        assert!(po2.validate().is_err());

        let mut root = skeleton();
        root.positive_cases[10].root_branch = B4RootBranch::Explicit;
        assert!(root.validate().is_err());
    }

    #[test]
    fn pending_binding_encodings_are_exact() {
        let mut statement = skeleton();
        statement
            .bindings
            .reference_statement_bundle
            .manifest
            .encoding = B4ArtifactEncoding::RawBytes;
        assert!(statement.validate().is_err());

        let mut guest = skeleton();
        guest.bindings.guest.elf.encoding = B4ArtifactEncoding::Rfc8785Jcs;
        assert!(guest.validate().is_err());

        let mut source_lock = skeleton();
        source_lock.bindings.source_lock.encoding = B4ArtifactEncoding::RawBytes;
        assert!(source_lock.validate().is_err());

        let mut generator = skeleton();
        generator.bindings.generator.encoding = B4ArtifactEncoding::Rfc8785Jcs;
        assert!(generator.validate().is_err());

        let mut rust_verifier = skeleton();
        rust_verifier.bindings.rust_verifier.encoding = B4ArtifactEncoding::Rfc8785Jcs;
        assert!(rust_verifier.validate().is_err());

        let mut jvm_verifier = skeleton();
        jvm_verifier.bindings.jvm_verifier.encoding = B4ArtifactEncoding::Rfc8785Jcs;
        assert!(jvm_verifier.validate().is_err());

        let mut negative_plan = skeleton();
        negative_plan.bindings.negative_plan.encoding = B4ArtifactEncoding::RawBytes;
        assert!(negative_plan.validate().is_err());

        let mut subject_catalog = skeleton();
        subject_catalog.bindings.subject_catalog.encoding = B4ArtifactEncoding::RawBytes;
        assert!(subject_catalog.validate().is_err());

        let mut terminal_fixture_catalog = skeleton();
        terminal_fixture_catalog
            .bindings
            .terminal_fixture_catalog
            .encoding = B4ArtifactEncoding::RawBytes;
        assert!(terminal_fixture_catalog.validate().is_err());
    }

    #[test]
    fn unknown_negative_class_and_unknown_fields_reject_deserialization() {
        let mut value = serde_json::to_value(skeleton()).unwrap();
        value["negativeClasses"][0] = serde_json::Value::String("unknown-class".to_owned());
        assert!(serde_json::from_value::<B4CandidateCorpus>(value).is_err());

        let mut value = serde_json::to_value(skeleton()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("template".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<B4CandidateCorpus>(value).is_err());
    }

    #[test]
    fn unexpanded_template_tokens_reject() {
        for token in ["every-phase", "parser-*", "offset-{n}", "todo-case"] {
            assert!(
                reject_unexpanded(token, "test").is_err(),
                "accepted {token}"
            );
        }
        reject_unexpanded("parser-read-17", "test").unwrap();
    }

    #[test]
    fn final_vector_lock_and_self_paths_reject() {
        for path in [
            "vectors/b4/raw-seal.bin",
            "reproduction/frozen/b4/raw-seal.bin",
            "reproduction/lock.json",
            "reproduction/schema/b4-corpus-v1.candidate/lock.json.bak",
            "reproduction/schema/b4-corpus-v1.candidate/lock.json/child",
        ] {
            let error = validate_artifact_fields(path, 1, &"00".repeat(32), true).unwrap_err();
            assert!(
                format!("{error:#}").contains("candidate registry references a final"),
                "path rejected at the wrong boundary: {path}: {error:#}"
            );
        }
        assert!(
            validate_artifact_fields(B4_CANDIDATE_REGISTRY_PATH, 1, &"00".repeat(32), true)
                .is_err()
        );
    }

    #[test]
    fn repository_paths_use_one_portable_case_and_device_namespace() {
        for path in [
            "reproduction/schema/b4-corpus-v1.candidate/bindings/guest.elf",
            "a/b-c_d.0",
        ] {
            validate_repository_path(path).unwrap();
        }
        for path in [
            "Reproduction/schema/input.bin",
            "reproduction//input.bin",
            "reproduction/con",
            "reproduction/aux.json",
            "reproduction/com1.bin",
            "reproduction/lpt9",
            "reproduction/input.",
            "a/../b",
        ] {
            assert!(
                validate_repository_path(path).is_err(),
                "accepted non-portable path: {path}"
            );
        }
        assert!(validate_repository_path(&"a".repeat(MAX_REPOSITORY_PATH_BYTES)).is_ok());
        assert!(validate_repository_path(&"a".repeat(MAX_REPOSITORY_PATH_BYTES + 1)).is_err());
    }

    #[test]
    fn repository_root_passes_candidate_physical_validation() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let repository_root = manifest_dir
            .parent()
            .expect("reproduction crate must have a repository parent");
        skeleton().validate_physical(repository_root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_junction_is_rejected_as_a_path_alias() {
        use std::os::windows::process::CommandExt;
        use std::process::Command;
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

        struct JunctionTree {
            junction: PathBuf,
            root: PathBuf,
            target: PathBuf,
        }

        impl Drop for JunctionTree {
            fn drop(&mut self) {
                let _ = fs::remove_dir(&self.junction);
                let _ = fs::remove_dir(&self.target);
                let _ = fs::remove_dir(&self.root);
            }
        }

        let unique = format!(
            "eip0045-b4-junction-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        );
        let root = std::env::temp_dir().join(unique);
        let target = root.join("target");
        let junction = root.join("junction");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&target).unwrap();
        let _cleanup = JunctionTree {
            junction: junction.clone(),
            root,
            target: target.clone(),
        };

        let command_line = format!(
            "mklink /J \"{}\" \"{}\"",
            junction.display(),
            target.display()
        );
        let mut command = Command::new("cmd");
        command.args(["/d", "/c"]);
        command.raw_arg(command_line);
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "cannot create test junction: stdout={}, stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let error = require_ordinary_directory(&junction, "test junction").unwrap_err();
        assert!(error.to_string().contains("path-redirection reparse point"));
    }

    #[test]
    fn canonical_round_trip_preserves_the_exact_skeleton() {
        let source = include_bytes!("../schema/b4-corpus-v1.candidate.json");
        let parsed = B4CandidateCorpus::from_canonical_jcs(source).unwrap();
        assert_eq!(parsed.to_canonical_jcs().unwrap(), source);

        let mut noncanonical = source.to_vec();
        noncanonical.push(b'\n');
        assert!(B4CandidateCorpus::from_canonical_jcs(&noncanonical).is_err());
    }
}
