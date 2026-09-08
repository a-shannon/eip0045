//! Live-derived, pre-artifact sequence subjects for the EIP-0045 B4 corpus.
//!
//! This module deliberately does not write a corpus tree. It projects the exact
//! inputs needed by the sequence-mutation layer and returns their canonical
//! bytes together with a non-self-referential catalogue. The caller remains
//! responsible for create-only publication and whole-tree closure.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::b4::{
    B4_CANDIDATE_FORMAT, B4_CANDIDATE_FORMAT_VERSION, B4ArtifactEncoding, B4CandidateCorpus,
    B4PositiveArtifactRole, B4PositiveCase, B4RegistryStage, B4SequenceTarget,
};
use crate::b4_plan::{
    B4_NEGATIVE_PLAN_GROUP_COUNT, B4_NEGATIVE_PLAN_VARIANT_COUNT, B4MaterializationDomain,
    B4NegativeExecutionSurface, B4NegativePlanClass, B4NegativePlanFixture, B4NegativeQaResultCode,
    Eip0045B4NegativePlanV1,
};
use crate::b4_subject::{B4SequenceSubjectElement, Eip0045B4SequenceSubjectV1};
use crate::canonical::{canonical_json_bytes, validate_canonical_json_source};

/// Exact format label for the live-derived subject catalogue.
pub const B4_SUBJECT_CATALOG_FORMAT: &str = "Eip0045B4SubjectCatalogV1";
/// Exact format version for the live-derived subject catalogue.
pub const B4_SUBJECT_CATALOG_FORMAT_VERSION: u8 = 1;
/// Exact number of detached sequence subjects in the closed B4 catalogue.
pub const B4_SUBJECT_COUNT: usize = 15;
/// Exact proof chunk lengths imposed by the B3 transport profile.
pub const B4_PROOF_CHUNK_LENGTHS: [usize; 4] = [65_535, 65_535, 65_535, 26_063];

const SUBJECT_ARTIFACT_ROOT: &str = "reproduction/schema/b4-corpus-v1.candidate/subjects/";
const MAX_CATALOG_BYTES: usize = 128 * 1024;
const MAX_SUBJECT_BYTES: usize = 8 * 1024 * 1024;
const MAX_SOURCE_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 128;
const EXPECTED_POSITIVE_COUNT: usize = 11;
const EXPECTED_CLASS_COUNT: usize = 9;

const POSITIVE_CASE_IDS: [&str; EXPECTED_POSITIVE_COUNT] = [
    "lift-po2-15",
    "lift-po2-16",
    "lift-po2-17",
    "lift-po2-18",
    "lift-po2-19",
    "lift-po2-20",
    "lift-po2-21",
    "lift-po2-22",
    "terminal-join",
    "terminal-resolve-explicit-root",
    "resolve-zero-root-then-join",
];

const PROFILE_FILES: [(&str, &str); 7] = [
    ("manifest", "profiles/risc0-v3-succinct/manifest.bin"),
    ("algorithm", "profiles/risc0-v3-succinct/algorithm.txt"),
    (
        "algorithm-artifact-preimage",
        "profiles/risc0-v3-succinct/algorithm-artifact-preimage.bin",
    ),
    ("constants", "profiles/risc0-v3-succinct/constants.bin"),
    (
        "binary-data-artifact-preimage",
        "profiles/risc0-v3-succinct/binary-data-artifact-preimage.bin",
    ),
    ("profile-id", "profiles/risc0-v3-succinct/profile-id.bin"),
    (
        "profile-id-preimage",
        "profiles/risc0-v3-succinct/profile-id-preimage.bin",
    ),
];

const NEGATIVE_CLASSES: [B4NegativePlanClass; EXPECTED_CLASS_COUNT] = [
    B4NegativePlanClass::StatementBinding,
    B4NegativePlanClass::ProofTransport,
    B4NegativePlanClass::CanonicalOuterWords,
    B4NegativePlanClass::ParserPhases,
    B4NegativePlanClass::TerminalPolicy,
    B4NegativePlanClass::ClaimSemantics,
    B4NegativePlanClass::ResolveSemantics,
    B4NegativePlanClass::CryptographicRejectionDepth,
    B4NegativePlanClass::ProfilePackageAndRegistry,
];

/// Exact identity of one detached subject artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4SubjectArtifactIdentityV1 {
    /// Exact canonical subject byte length.
    pub byte_length: u64,
    /// Canonical repository-relative path reserved for the subject.
    pub path: String,
    /// Lowercase SHA-256 of the exact canonical subject bytes.
    pub sha256: String,
}

/// Minimal non-cyclic provenance for one detached subject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    tag = "provenanceKind",
    deny_unknown_fields
)]
pub enum B4SubjectProvenanceV1 {
    /// Projection of the eleven positive rows before generated artifacts.
    PositiveProjection {
        /// Exact number of projected positive rows.
        positive_case_count: u8,
    },
    /// Expansion of the exact closed negative plan.
    NegativePlan {
        /// SHA-256 of the exact canonical closed negative plan.
        plan_sha256: String,
    },
    /// Ordered class inventory derived from the exact closed negative plan.
    NegativeClasses {
        /// SHA-256 of the exact canonical closed negative plan.
        plan_sha256: String,
    },
    /// Projection of the seven normative B3 package files.
    ProfilePackage {
        /// Exact profile identifier authenticated by `profile-id.bin`.
        profile_id: String,
    },
    /// Chunk projection of one positive raw succinct seal.
    ProofChunks {
        /// Exact positive case owning the raw seal.
        case_id: String,
        /// SHA-256 of the complete raw seal before chunking.
        raw_seal_sha256: String,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case", tag = "provenanceKind")]
enum B4SubjectProvenanceWire {
    PositiveProjection(PositiveProjectionWire),
    NegativePlan(NegativePlanWire),
    NegativeClasses(NegativePlanWire),
    ProfilePackage(ProfilePackageWire),
    ProofChunks(ProofChunksWire),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PositiveProjectionWire {
    positive_case_count: u8,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NegativePlanWire {
    plan_sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProfilePackageWire {
    profile_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProofChunksWire {
    case_id: String,
    raw_seal_sha256: String,
}

impl<'de> Deserialize<'de> for B4SubjectProvenanceV1 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        B4SubjectProvenanceWire::deserialize(deserializer).map(|wire| match wire {
            B4SubjectProvenanceWire::PositiveProjection(PositiveProjectionWire {
                positive_case_count,
            }) => Self::PositiveProjection {
                positive_case_count,
            },
            B4SubjectProvenanceWire::NegativePlan(NegativePlanWire { plan_sha256 }) => {
                Self::NegativePlan { plan_sha256 }
            }
            B4SubjectProvenanceWire::NegativeClasses(NegativePlanWire { plan_sha256 }) => {
                Self::NegativeClasses { plan_sha256 }
            }
            B4SubjectProvenanceWire::ProfilePackage(ProfilePackageWire { profile_id }) => {
                Self::ProfilePackage { profile_id }
            }
            B4SubjectProvenanceWire::ProofChunks(ProofChunksWire {
                case_id,
                raw_seal_sha256,
            }) => Self::ProofChunks {
                case_id,
                raw_seal_sha256,
            },
        })
    }
}

/// One exact catalogue row for a detached sequence subject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4SubjectCatalogEntryV1 {
    /// Identity of the canonical subject artifact.
    pub artifact: B4SubjectArtifactIdentityV1,
    /// Minimal live-derived provenance, excluding timestamps and signatures.
    pub provenance: B4SubjectProvenanceV1,
    /// Stable lower-kebab subject identifier.
    pub subject_id: String,
    /// Closed sequence target encoded inside the detached subject.
    pub target: B4SequenceTarget,
}

/// Exact non-self-referential catalogue of the fifteen B4 sequence subjects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Eip0045B4SubjectCatalogV1 {
    /// Exact V1 format label.
    pub format: String,
    /// Exact format version.
    pub format_version: u8,
    /// Closed ordered inventory of fifteen subject identities.
    pub subjects: Vec<B4SubjectCatalogEntryV1>,
}

impl Eip0045B4SubjectCatalogV1 {
    /// Parse an exact canonical JCS catalogue and enforce its closed shape.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, non-canonical, duplicate-key,
    /// unknown-field, incorrectly ordered, or otherwise invalid input.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            source.len() <= MAX_CATALOG_BYTES,
            "B4 subject catalogue exceeds its canonical-byte bound"
        );
        let value = validate_canonical_json_source(source)
            .context("B4 subject catalogue is not exact RFC 8785 JCS")?;
        let catalogue: Self =
            serde_json::from_value(value).context("invalid B4 subject catalogue shape")?;
        catalogue.validate()?;
        ensure!(
            catalogue.to_canonical_jcs()? == source,
            "B4 subject catalogue does not round-trip byte-exactly"
        );
        Ok(catalogue)
    }

    /// Serialize this catalogue to exact RFC 8785 JCS bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when validation or canonical serialization fails.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value = serde_json::to_value(self).context("cannot serialize B4 subject catalogue")?;
        let bytes = canonical_json_bytes(&value)?;
        ensure!(
            bytes.len() <= MAX_CATALOG_BYTES,
            "B4 subject catalogue exceeds its canonical-byte bound"
        );
        Ok(bytes)
    }

    /// Validate the exact fifteen-row V1 catalogue grammar and ordering.
    ///
    /// This validates catalogue-internal closure. Use
    /// [`verify_b4_subject_bundle`] to compare every row and subject byte with
    /// live sources.
    ///
    /// # Errors
    ///
    /// Returns an error for any format, order, target, path, digest,
    /// provenance, or uniqueness drift.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == B4_SUBJECT_CATALOG_FORMAT,
            "wrong B4 subject-catalogue format label"
        );
        ensure!(
            self.format_version == B4_SUBJECT_CATALOG_FORMAT_VERSION,
            "wrong B4 subject-catalogue format version"
        );
        ensure!(
            self.subjects.len() == B4_SUBJECT_COUNT,
            "B4 subject catalogue must contain exactly {B4_SUBJECT_COUNT} rows"
        );

        let expected = expected_subject_specs();
        let mut ids = BTreeSet::new();
        let mut paths = BTreeSet::new();
        let mut plan_digest: Option<&str> = None;
        for (index, (entry, spec)) in self.subjects.iter().zip(expected).enumerate() {
            validate_lower_kebab(&entry.subject_id, "B4 subject ID")?;
            ensure!(
                ids.insert(entry.subject_id.as_str()),
                "duplicate B4 subject ID at index {index}"
            );
            ensure!(
                entry.subject_id == spec.subject_id,
                "B4 subject ID/order drift at index {index}"
            );
            ensure!(
                entry.target == spec.target,
                "B4 subject target drift at index {index}"
            );
            let expected_path = subject_artifact_path(spec.subject_id);
            ensure!(
                entry.artifact.path == expected_path,
                "B4 subject artifact path drift at index {index}"
            );
            validate_relative_posix_path(&entry.artifact.path)?;
            ensure!(
                paths.insert(entry.artifact.path.as_str()),
                "duplicate B4 subject artifact path at index {index}"
            );
            ensure!(
                (1..=u64::try_from(MAX_SUBJECT_BYTES)?).contains(&entry.artifact.byte_length),
                "B4 subject artifact length is outside the closed bound at index {index}"
            );
            validate_digest(&entry.artifact.sha256, "B4 subject artifact SHA-256")?;

            match (&entry.provenance, spec.kind) {
                (
                    B4SubjectProvenanceV1::PositiveProjection {
                        positive_case_count,
                    },
                    ExpectedProvenanceKind::PositiveProjection,
                ) => ensure!(
                    usize::from(*positive_case_count) == EXPECTED_POSITIVE_COUNT,
                    "wrong positive projection count"
                ),
                (
                    B4SubjectProvenanceV1::NegativePlan { plan_sha256 },
                    ExpectedProvenanceKind::NegativePlan,
                )
                | (
                    B4SubjectProvenanceV1::NegativeClasses { plan_sha256 },
                    ExpectedProvenanceKind::NegativeClasses,
                ) => {
                    validate_digest(plan_sha256, "B4 negative-plan SHA-256")?;
                    if let Some(previous) = plan_digest {
                        ensure!(
                            previous == plan_sha256,
                            "negative plan and class projections bind different plans"
                        );
                    } else {
                        plan_digest = Some(plan_sha256);
                    }
                }
                (
                    B4SubjectProvenanceV1::ProfilePackage { profile_id },
                    ExpectedProvenanceKind::ProfilePackage,
                ) => validate_digest(profile_id, "B4 profile ID")?,
                (
                    B4SubjectProvenanceV1::ProofChunks {
                        case_id,
                        raw_seal_sha256,
                    },
                    ExpectedProvenanceKind::ProofChunks(expected_case_id),
                ) => {
                    ensure!(
                        case_id == expected_case_id,
                        "proof-chunk provenance case drift at index {index}"
                    );
                    validate_digest(raw_seal_sha256, "B4 raw-seal SHA-256")?;
                }
                _ => bail!("B4 subject provenance kind drift at index {index}"),
            }
        }
        Ok(())
    }
}

/// In-memory, create-free result of live subject derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B4DerivedSubjectBundle {
    /// Closed catalogue whose artifact rows authenticate `subject_files`.
    pub catalog: Eip0045B4SubjectCatalogV1,
    /// Exact canonical subject bytes keyed by their reserved artifact paths.
    pub subject_files: BTreeMap<String, Vec<u8>>,
}

impl B4DerivedSubjectBundle {
    /// Serialize the derived catalogue to exact RFC 8785 JCS bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when catalogue validation or serialization fails.
    pub fn catalog_jcs(&self) -> Result<Vec<u8>> {
        self.catalog.to_canonical_jcs()
    }
}

/// Derive all fifteen detached subjects and their catalogue from live sources.
///
/// The current `B4CandidateCorpus::validate()` deliberately rejects the
/// `expanded` lifecycle until the dual-verifier gate exists. This function does
/// not weaken or bypass that gate: it performs a narrower structural check of
/// only the expanded fields it consumes, then returns unauthorizing,
/// pre-artifact projections. In particular, negative rows and their artifacts
/// are never read into the negative-plan subject.
///
/// # Errors
///
/// Returns an error for plan drift, wrong corpus stage/inventory, unsafe or
/// missing source files, raw-seal binding mismatch, package mismatch, or any
/// canonical-subject violation.
pub fn derive_b4_subject_bundle(
    corpus: &B4CandidateCorpus,
    plan: &Eip0045B4NegativePlanV1,
    repository_root: impl AsRef<Path>,
) -> Result<B4DerivedSubjectBundle> {
    plan.validate().context("invalid exact B4 negative plan")?;
    validate_consumed_expanded_structure(corpus, plan)?;

    let repository_root = repository_root.as_ref();
    require_ordinary_directory(repository_root, "B4 subject repository root")?;
    let repository_root = fs::canonicalize(repository_root)
        .context("cannot canonicalize B4 subject repository root")?;

    let plan_bytes = plan.to_canonical_jcs()?;
    let plan_sha256 = sha256_hex(&plan_bytes);
    let mut derived = Vec::with_capacity(B4_SUBJECT_COUNT);

    derived.push(DerivedSubject::new(
        "registry-positive-cases",
        positive_projection(corpus)?,
        B4SubjectProvenanceV1::PositiveProjection {
            positive_case_count: u8::try_from(EXPECTED_POSITIVE_COUNT)?,
        },
    )?);
    derived.push(DerivedSubject::new(
        "registry-negative-cases",
        negative_plan_projection(plan)?,
        B4SubjectProvenanceV1::NegativePlan {
            plan_sha256: plan_sha256.clone(),
        },
    )?);
    derived.push(DerivedSubject::new(
        "registry-negative-classes",
        negative_class_projection(plan)?,
        B4SubjectProvenanceV1::NegativeClasses {
            plan_sha256: plan_sha256.clone(),
        },
    )?);
    derived.push(DerivedSubject::new(
        "profile-package-files",
        profile_package_projection(corpus, &repository_root)?,
        B4SubjectProvenanceV1::ProfilePackage {
            profile_id: corpus.profile.profile_id.clone(),
        },
    )?);

    for (case, expected_id) in corpus.positive_cases.iter().zip(POSITIVE_CASE_IDS) {
        ensure!(case.case_id == expected_id, "positive case order drift");
        let (subject, raw_seal_sha256) = proof_chunk_projection(case, &repository_root)?;
        derived.push(DerivedSubject::new(
            &format!("proof-chunks-{expected_id}"),
            subject,
            B4SubjectProvenanceV1::ProofChunks {
                case_id: expected_id.to_owned(),
                raw_seal_sha256,
            },
        )?);
    }

    ensure!(
        derived.len() == B4_SUBJECT_COUNT,
        "internal B4 subject derivation count drift"
    );
    let mut catalog_entries = Vec::with_capacity(B4_SUBJECT_COUNT);
    let mut subject_files = BTreeMap::new();
    for item in derived {
        let path = subject_artifact_path(&item.subject_id);
        let bytes = item.subject.to_canonical_jcs()?;
        ensure!(
            bytes.len() <= MAX_SUBJECT_BYTES,
            "derived B4 subject exceeds its closed byte bound"
        );
        let identity = B4SubjectArtifactIdentityV1 {
            byte_length: u64::try_from(bytes.len())?,
            path: path.clone(),
            sha256: sha256_hex(&bytes),
        };
        ensure!(
            subject_files.insert(path, bytes).is_none(),
            "duplicate derived B4 subject path"
        );
        catalog_entries.push(B4SubjectCatalogEntryV1 {
            artifact: identity,
            provenance: item.provenance,
            subject_id: item.subject_id,
            target: item.subject.target,
        });
    }

    let catalog = Eip0045B4SubjectCatalogV1 {
        format: B4_SUBJECT_CATALOG_FORMAT.to_owned(),
        format_version: B4_SUBJECT_CATALOG_FORMAT_VERSION,
        subjects: catalog_entries,
    };
    catalog.validate()?;
    Ok(B4DerivedSubjectBundle {
        catalog,
        subject_files,
    })
}

/// Rebuild and compare a complete in-memory subject bundle byte-for-byte.
///
/// The supplied map is exhaustive: a missing subject, an extra subject, a path
/// substitution, or any byte drift is rejected. No filesystem output is
/// created.
///
/// # Errors
///
/// Returns an error when the catalogue is not exact canonical JCS, live
/// derivation fails, the catalogue differs, or the subject map differs in keys
/// or bytes.
pub fn verify_b4_subject_bundle(
    corpus: &B4CandidateCorpus,
    plan: &Eip0045B4NegativePlanV1,
    repository_root: impl AsRef<Path>,
    catalog_source: &[u8],
    subject_files: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let supplied_catalog = Eip0045B4SubjectCatalogV1::from_canonical_jcs(catalog_source)?;
    let expected = derive_b4_subject_bundle(corpus, plan, repository_root)?;
    ensure!(
        expected.catalog.to_canonical_jcs()? == catalog_source,
        "B4 subject catalogue differs from its live-derived bytes"
    );
    ensure!(
        supplied_catalog == expected.catalog,
        "B4 subject catalogue differs from its live-derived model"
    );
    ensure!(
        subject_files.len() == expected.subject_files.len(),
        "B4 subject map has a missing or extra path"
    );
    for (path, expected_bytes) in &expected.subject_files {
        let supplied = subject_files
            .get(path)
            .with_context(|| format!("missing B4 subject artifact: {path}"))?;
        ensure!(
            supplied == expected_bytes,
            "B4 subject bytes differ from live derivation: {path}"
        );
    }
    ensure!(
        subject_files.keys().eq(expected.subject_files.keys()),
        "B4 subject map contains a substituted or extra path"
    );
    Ok(())
}

struct DerivedSubject {
    provenance: B4SubjectProvenanceV1,
    subject: Eip0045B4SequenceSubjectV1,
    subject_id: String,
}

impl DerivedSubject {
    fn new(
        subject_id: &str,
        subject: Eip0045B4SequenceSubjectV1,
        provenance: B4SubjectProvenanceV1,
    ) -> Result<Self> {
        validate_lower_kebab(subject_id, "B4 subject ID")?;
        Ok(Self {
            provenance,
            subject,
            subject_id: subject_id.to_owned(),
        })
    }
}

#[derive(Clone, Copy)]
enum ExpectedProvenanceKind {
    PositiveProjection,
    NegativePlan,
    NegativeClasses,
    ProfilePackage,
    ProofChunks(&'static str),
}

#[derive(Clone, Copy)]
struct ExpectedSubjectSpec {
    kind: ExpectedProvenanceKind,
    subject_id: &'static str,
    target: B4SequenceTarget,
}

fn expected_subject_specs() -> Vec<ExpectedSubjectSpec> {
    let mut specs = vec![
        ExpectedSubjectSpec {
            kind: ExpectedProvenanceKind::PositiveProjection,
            subject_id: "registry-positive-cases",
            target: B4SequenceTarget::RegistryPositiveCases,
        },
        ExpectedSubjectSpec {
            kind: ExpectedProvenanceKind::NegativePlan,
            subject_id: "registry-negative-cases",
            target: B4SequenceTarget::RegistryNegativeCases,
        },
        ExpectedSubjectSpec {
            kind: ExpectedProvenanceKind::NegativeClasses,
            subject_id: "registry-negative-classes",
            target: B4SequenceTarget::RegistryNegativeClasses,
        },
        ExpectedSubjectSpec {
            kind: ExpectedProvenanceKind::ProfilePackage,
            subject_id: "profile-package-files",
            target: B4SequenceTarget::ProfilePackageFiles,
        },
    ];
    specs.extend(
        [
            "proof-chunks-lift-po2-15",
            "proof-chunks-lift-po2-16",
            "proof-chunks-lift-po2-17",
            "proof-chunks-lift-po2-18",
            "proof-chunks-lift-po2-19",
            "proof-chunks-lift-po2-20",
            "proof-chunks-lift-po2-21",
            "proof-chunks-lift-po2-22",
            "proof-chunks-terminal-join",
            "proof-chunks-terminal-resolve-explicit-root",
            "proof-chunks-resolve-zero-root-then-join",
        ]
        .into_iter()
        .zip(POSITIVE_CASE_IDS)
        .map(|(subject_id, case_id)| ExpectedSubjectSpec {
            kind: ExpectedProvenanceKind::ProofChunks(case_id),
            subject_id,
            target: B4SequenceTarget::ProofChunks,
        }),
    );
    specs
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PositiveProjection<'a> {
    case_id: &'a str,
    expected_result: &'a crate::b4::B4PositiveExpectedResult,
    family: crate::b4::B4PositiveFamily,
    guest_mode: crate::b4::B4GuestMode,
    index: u8,
    root_branch: crate::b4::B4RootBranch,
    source_segments: u8,
    terminal: crate::b4::B4Terminal,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NegativeExecutionProjection<'a> {
    base_selector_id: &'a str,
    class: B4NegativePlanClass,
    execution_id: &'a str,
    execution_surface: B4NegativeExecutionSurface,
    fixture: B4NegativePlanFixture,
    group_id: &'a str,
    materialization_domain: B4MaterializationDomain,
    #[serde(skip_serializing_if = "Option::is_none")]
    parser_truncation_words: Option<u32>,
    qa_result_code: B4NegativeQaResultCode,
    variant_id: &'a str,
}

#[derive(Serialize)]
struct NegativeClassProjection {
    class: B4NegativePlanClass,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileFileProjection<'a> {
    byte_length: u64,
    path: &'a str,
    sha256: String,
}

fn positive_projection(corpus: &B4CandidateCorpus) -> Result<Eip0045B4SequenceSubjectV1> {
    let mut elements = Vec::with_capacity(EXPECTED_POSITIVE_COUNT);
    for case in &corpus.positive_cases {
        let projection = PositiveProjection {
            case_id: &case.case_id,
            expected_result: &case.expected_result,
            family: case.family,
            guest_mode: case.guest_mode,
            index: case.index,
            root_branch: case.root_branch,
            source_segments: case.source_segments,
            terminal: case.terminal,
        };
        elements.push(structured_element(&case.case_id, &projection)?);
    }
    Eip0045B4SequenceSubjectV1::new(B4SequenceTarget::RegistryPositiveCases, elements)
}

fn negative_plan_projection(plan: &Eip0045B4NegativePlanV1) -> Result<Eip0045B4SequenceSubjectV1> {
    let mut elements = Vec::with_capacity(usize::from(B4_NEGATIVE_PLAN_VARIANT_COUNT));
    for group in &plan.groups {
        for execution in &group.executions {
            let projection = NegativeExecutionProjection {
                base_selector_id: &execution.base_selector_id,
                class: group.class,
                execution_id: &execution.execution_id,
                execution_surface: execution.execution_surface,
                fixture: execution.fixture,
                group_id: &group.case_id,
                materialization_domain: execution.materialization_domain,
                parser_truncation_words: execution.parser_truncation_words,
                qa_result_code: execution.qa_result_code,
                variant_id: &execution.variant_id,
            };
            let ordinal = elements.len();
            elements.push(structured_element(
                &format!("execution-{ordinal:03}"),
                &projection,
            )?);
        }
    }
    ensure!(
        elements.len() == usize::from(B4_NEGATIVE_PLAN_VARIANT_COUNT),
        "negative-plan projection does not contain exactly {B4_NEGATIVE_PLAN_VARIANT_COUNT} executions"
    );
    Eip0045B4SequenceSubjectV1::new(B4SequenceTarget::RegistryNegativeCases, elements)
}

fn negative_class_projection(plan: &Eip0045B4NegativePlanV1) -> Result<Eip0045B4SequenceSubjectV1> {
    let covered = plan
        .groups
        .iter()
        .map(|group| group.class)
        .collect::<BTreeSet<_>>();
    ensure!(
        covered == NEGATIVE_CLASSES.into_iter().collect(),
        "negative plan does not cover the exact closed class inventory"
    );
    let classes = NEGATIVE_CLASSES
        .into_iter()
        .map(|class| {
            let id = enum_string(class)?;
            structured_element(&id, &NegativeClassProjection { class })
        })
        .collect::<Result<Vec<_>>>()?;
    Eip0045B4SequenceSubjectV1::new(B4SequenceTarget::RegistryNegativeClasses, classes)
}

fn profile_package_projection(
    corpus: &B4CandidateCorpus,
    repository_root: &Path,
) -> Result<Eip0045B4SequenceSubjectV1> {
    let mut elements = Vec::with_capacity(PROFILE_FILES.len());
    let mut profile_id_bytes: Option<Vec<u8>> = None;
    for (element_id, relative_path) in PROFILE_FILES {
        let bytes =
            read_bounded_regular_file(repository_root, relative_path, MAX_SOURCE_FILE_BYTES)?;
        if element_id == "manifest" {
            ensure!(
                corpus.profile.manifest.path == relative_path,
                "B3 manifest path differs from the normative package list"
            );
            ensure!(
                corpus.profile.manifest.encoding == B4ArtifactEncoding::RawBytes,
                "B3 manifest binding is not raw bytes"
            );
            ensure!(
                corpus.profile.manifest.byte_length == u64::try_from(bytes.len())?
                    && corpus.profile.manifest.sha256 == sha256_hex(&bytes),
                "B3 manifest binding differs from live bytes"
            );
        }
        if element_id == "profile-id" {
            profile_id_bytes = Some(bytes.clone());
        }
        let projection = ProfileFileProjection {
            byte_length: u64::try_from(bytes.len())?,
            path: relative_path,
            sha256: sha256_hex(&bytes),
        };
        elements.push(structured_element(element_id, &projection)?);
    }

    let profile_id_bytes = profile_id_bytes.context("normative profile-id file was not read")?;
    ensure!(
        profile_id_bytes.len() == 32 && hex::encode(profile_id_bytes) == corpus.profile.profile_id,
        "live profile-id.bin does not authenticate the corpus profile ID"
    );
    Eip0045B4SequenceSubjectV1::new(B4SequenceTarget::ProfilePackageFiles, elements)
}

fn proof_chunk_projection(
    case: &B4PositiveCase,
    repository_root: &Path,
) -> Result<(Eip0045B4SequenceSubjectV1, String)> {
    let raw_seals = case
        .artifacts
        .iter()
        .filter(|artifact| artifact.role == B4PositiveArtifactRole::RawSeal)
        .collect::<Vec<_>>();
    ensure!(
        raw_seals.len() == 1,
        "positive {} must bind exactly one raw-seal artifact",
        case.case_id
    );
    let raw_seal = raw_seals[0];
    ensure!(
        raw_seal.encoding == B4ArtifactEncoding::RawBytes,
        "positive {} raw seal is not declared as raw bytes",
        case.case_id
    );
    let exact_length = B4_PROOF_CHUNK_LENGTHS.iter().sum::<usize>();
    ensure!(
        raw_seal.byte_length == u64::try_from(exact_length)?,
        "positive {} raw-seal length is not the exact B3 proof length",
        case.case_id
    );
    validate_digest(&raw_seal.sha256, "positive raw-seal SHA-256")?;
    let bytes = read_bounded_regular_file(
        repository_root,
        &raw_seal.path,
        u64::try_from(exact_length)?,
    )?;
    ensure!(
        bytes.len() == exact_length,
        "positive {} raw-seal file has the wrong length",
        case.case_id
    );
    let observed_sha256 = sha256_hex(&bytes);
    ensure!(
        observed_sha256 == raw_seal.sha256,
        "positive {} raw-seal file differs from its registry binding",
        case.case_id
    );

    let mut elements = Vec::with_capacity(B4_PROOF_CHUNK_LENGTHS.len());
    let mut offset = 0_usize;
    for (index, byte_length) in B4_PROOF_CHUNK_LENGTHS.into_iter().enumerate() {
        let end = offset
            .checked_add(byte_length)
            .context("B4 proof chunk boundary overflows usize")?;
        elements.push(B4SequenceSubjectElement::from_bytes(
            format!("chunk-{index:02}"),
            &bytes[offset..end],
        )?);
        offset = end;
    }
    ensure!(
        offset == bytes.len(),
        "B4 proof chunking did not consume EOF"
    );
    let subject = Eip0045B4SequenceSubjectV1::new(B4SequenceTarget::ProofChunks, elements)?;
    let concatenated = subject
        .elements
        .iter()
        .map(B4SequenceSubjectElement::decoded_bytes)
        .collect::<Result<Vec<_>>>()?
        .concat();
    ensure!(
        concatenated == bytes,
        "B4 proof-chunk subject does not reconstruct the raw seal"
    );
    Ok((subject, observed_sha256))
}

fn validate_consumed_expanded_structure(
    corpus: &B4CandidateCorpus,
    plan: &Eip0045B4NegativePlanV1,
) -> Result<()> {
    ensure!(
        corpus.format == B4_CANDIDATE_FORMAT
            && corpus.format_version == B4_CANDIDATE_FORMAT_VERSION,
        "wrong B4 candidate format for subject derivation"
    );
    ensure!(
        corpus.stage == B4RegistryStage::Expanded,
        "B4 subject derivation requires an expanded candidate with raw seals"
    );
    ensure!(
        corpus.positive_cases.len() == EXPECTED_POSITIVE_COUNT,
        "B4 subject derivation requires exactly eleven positives"
    );
    let mut positive_ids = BTreeSet::new();
    for (index, (case, expected_id)) in corpus
        .positive_cases
        .iter()
        .zip(POSITIVE_CASE_IDS)
        .enumerate()
    {
        ensure!(
            usize::from(case.index) == index && case.case_id == expected_id,
            "positive case identity/order drift at index {index}"
        );
        ensure!(
            positive_ids.insert(case.case_id.as_str()),
            "duplicate positive case ID at index {index}"
        );
    }
    validate_digest(&corpus.profile.profile_id, "B4 corpus profile ID")?;

    ensure!(
        plan.groups.len() == B4_NEGATIVE_PLAN_GROUP_COUNT
            && plan.total_variant_count == B4_NEGATIVE_PLAN_VARIANT_COUNT,
        "B4 negative plan count drift"
    );
    let covered_plan_classes = plan
        .groups
        .iter()
        .map(|group| group.class)
        .collect::<BTreeSet<_>>();
    ensure!(
        covered_plan_classes == NEGATIVE_CLASSES.into_iter().collect(),
        "exact plan does not cover the closed negative-class inventory"
    );
    let plan_classes = NEGATIVE_CLASSES
        .into_iter()
        .map(enum_string)
        .collect::<Result<Vec<_>>>()?;
    let corpus_classes = corpus
        .negative_classes
        .iter()
        .copied()
        .map(enum_string)
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        corpus_classes == plan_classes && plan_classes.len() == EXPECTED_CLASS_COUNT,
        "corpus negative-class inventory differs from the exact plan"
    );
    Ok(())
}

fn structured_element<T: Serialize>(
    element_id: &str,
    value: &T,
) -> Result<B4SequenceSubjectElement> {
    let value = serde_json::to_value(value).context("cannot serialize B4 subject element")?;
    let bytes = canonical_json_bytes(&value)?;
    B4SequenceSubjectElement::from_bytes(element_id, &bytes)
}

fn enum_string<T: Serialize>(value: T) -> Result<String> {
    serde_json::to_value(value)
        .context("cannot serialize closed B4 enum")?
        .as_str()
        .map(str::to_owned)
        .context("closed B4 enum did not serialize as a string")
}

fn subject_artifact_path(subject_id: &str) -> String {
    format!("{SUBJECT_ARTIFACT_ROOT}{subject_id}.subject.json")
}

fn read_bounded_regular_file(root: &Path, relative: &str, max_bytes: u64) -> Result<Vec<u8>> {
    ensure!(
        max_bytes <= MAX_SOURCE_FILE_BYTES,
        "internal B4 source-file bound is outside the closed limits"
    );
    let path = join_checked_path(root, relative)?;
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("cannot inspect B4 subject source: {relative}"))?;
    reject_link_or_reparse(&path, &metadata)?;
    ensure!(
        metadata.file_type().is_file(),
        "B4 subject source is not a regular file: {relative}"
    );
    ensure!(
        metadata.len() <= max_bytes,
        "B4 subject source exceeds its closed byte bound: {relative}"
    );

    let file =
        File::open(&path).with_context(|| format!("cannot open B4 subject source: {relative}"))?;
    let opened = file
        .metadata()
        .with_context(|| format!("cannot inspect opened B4 subject source: {relative}"))?;
    reject_link_or_reparse(&path, &opened)?;
    ensure!(
        opened.file_type().is_file() && opened.len() == metadata.len(),
        "B4 subject source changed while opening: {relative}"
    );

    let capacity = usize::try_from(opened.len()).context("B4 source length does not fit usize")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read B4 subject source: {relative}"))?;
    ensure!(
        bytes.len() == capacity,
        "B4 subject source changed or was not consumed exactly: {relative}"
    );
    Ok(bytes)
}

fn join_checked_path(root: &Path, relative: &str) -> Result<PathBuf> {
    validate_relative_posix_path(relative)?;
    let mut current = root.to_path_buf();
    for segment in relative.split('/') {
        current.push(segment);
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("cannot inspect B4 source path component: {relative}"))?;
        reject_link_or_reparse(&current, &metadata)?;
    }
    let canonical = fs::canonicalize(&current)
        .with_context(|| format!("cannot canonicalize B4 source path: {relative}"))?;
    ensure!(
        canonical.starts_with(root),
        "B4 source path escapes its canonical repository root: {relative}"
    );
    Ok(current)
}

fn validate_relative_posix_path(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 512
            && value.is_ascii()
            && !value.starts_with('/')
            && !value.ends_with('/')
            && !value.contains(['\\', ':']),
        "B4 path is not bounded canonical repository-relative POSIX text"
    );
    for segment in value.split('/') {
        ensure!(
            !segment.is_empty() && segment != "." && segment != "..",
            "B4 path contains an unsafe segment"
        );
    }
    Ok(())
}

fn validate_lower_kebab(value: &str, label: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= MAX_IDENTIFIER_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !value.starts_with('-')
            && !value.ends_with('-')
            && !value.contains("--"),
        "{label} is not bounded canonical lower-kebab ASCII"
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

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn require_ordinary_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {label}: {}", path.display()))?;
    reject_link_or_reparse(path, &metadata)?;
    ensure!(metadata.file_type().is_dir(), "{label} is not a directory");
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
    use crate::b4::{
        B4_CANDIDATE_FORMAT, B4_CANDIDATE_FORMAT_VERSION, B4NegativeClass, B4PositiveArtifact,
    };
    use crate::test_support::{TempDir, tempdir};

    fn write_relative(root: &Path, relative: &str, bytes: &[u8]) {
        let path = relative
            .split('/')
            .fold(root.to_path_buf(), |mut path, part| {
                path.push(part);
                path
            });
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn fixture_repository() -> (TempDir, B4CandidateCorpus, Eip0045B4NegativePlanV1) {
        let temp = tempdir().unwrap();
        for (relative, bytes) in [
            (
                "profiles/risc0-v3-succinct/manifest.bin",
                include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin").as_slice(),
            ),
            (
                "profiles/risc0-v3-succinct/algorithm.txt",
                include_bytes!("../../profiles/risc0-v3-succinct/algorithm.txt").as_slice(),
            ),
            (
                "profiles/risc0-v3-succinct/algorithm-artifact-preimage.bin",
                include_bytes!("../../profiles/risc0-v3-succinct/algorithm-artifact-preimage.bin")
                    .as_slice(),
            ),
            (
                "profiles/risc0-v3-succinct/constants.bin",
                include_bytes!("../../profiles/risc0-v3-succinct/constants.bin").as_slice(),
            ),
            (
                "profiles/risc0-v3-succinct/binary-data-artifact-preimage.bin",
                include_bytes!(
                    "../../profiles/risc0-v3-succinct/binary-data-artifact-preimage.bin"
                )
                .as_slice(),
            ),
            (
                "profiles/risc0-v3-succinct/profile-id.bin",
                include_bytes!("../../profiles/risc0-v3-succinct/profile-id.bin").as_slice(),
            ),
            (
                "profiles/risc0-v3-succinct/profile-id-preimage.bin",
                include_bytes!("../../profiles/risc0-v3-succinct/profile-id-preimage.bin")
                    .as_slice(),
            ),
        ] {
            write_relative(temp.path(), relative, bytes);
        }

        let mut corpus: B4CandidateCorpus =
            serde_json::from_slice(include_bytes!("../schema/b4-corpus-v1.candidate.json"))
                .unwrap();
        corpus.format = B4_CANDIDATE_FORMAT.to_owned();
        corpus.format_version = B4_CANDIDATE_FORMAT_VERSION;
        corpus.stage = B4RegistryStage::Expanded;
        let seal = (0..B4_PROOF_CHUNK_LENGTHS.iter().sum::<usize>())
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect::<Vec<_>>();
        let seal_sha256 = sha256_hex(&seal);
        for case in &mut corpus.positive_cases {
            let path = format!("raw-seals/{}.seal", case.case_id);
            write_relative(temp.path(), &path, &seal);
            case.artifacts = vec![B4PositiveArtifact {
                byte_length: u64::try_from(seal.len()).unwrap(),
                encoding: B4ArtifactEncoding::RawBytes,
                path,
                role: B4PositiveArtifactRole::RawSeal,
                sha256: seal_sha256.clone(),
            }];
        }
        (temp, corpus, Eip0045B4NegativePlanV1::canonical().unwrap())
    }

    #[test]
    fn derives_exact_fifteen_subjects_and_proof_chunk_boundaries() {
        let (temp, corpus, plan) = fixture_repository();
        let bundle = derive_b4_subject_bundle(&corpus, &plan, temp.path()).unwrap();
        assert_eq!(bundle.catalog.subjects.len(), B4_SUBJECT_COUNT);
        assert_eq!(bundle.subject_files.len(), B4_SUBJECT_COUNT);
        let proof_path = subject_artifact_path("proof-chunks-lift-po2-15");
        let proof = Eip0045B4SequenceSubjectV1::from_canonical_jcs(
            bundle.subject_files.get(&proof_path).unwrap(),
        )
        .unwrap();
        assert_eq!(
            proof
                .elements
                .iter()
                .map(|element| element.decoded_bytes().unwrap().len())
                .collect::<Vec<_>>(),
            B4_PROOF_CHUNK_LENGTHS
        );
        assert_eq!(
            proof
                .elements
                .iter()
                .map(|element| element.element_id.as_str())
                .collect::<Vec<_>>(),
            ["chunk-00", "chunk-01", "chunk-02", "chunk-03"]
        );
        verify_b4_subject_bundle(
            &corpus,
            &plan,
            temp.path(),
            &bundle.catalog_jcs().unwrap(),
            &bundle.subject_files,
        )
        .unwrap();
    }

    #[test]
    fn pre_artifact_projections_have_no_registry_self_reference() {
        let (temp, mut corpus, plan) = fixture_repository();
        corpus.negative_cases.clear();
        let bundle = derive_b4_subject_bundle(&corpus, &plan, temp.path()).unwrap();
        for id in ["registry-positive-cases", "registry-negative-cases"] {
            let bytes = bundle
                .subject_files
                .get(&subject_artifact_path(id))
                .unwrap();
            let subject = Eip0045B4SequenceSubjectV1::from_canonical_jcs(bytes).unwrap();
            for element in subject.elements {
                let value =
                    validate_canonical_json_source(&element.decoded_bytes().unwrap()).unwrap();
                let object = value.as_object().unwrap();
                assert!(!object.contains_key("artifacts"));
                assert!(!object.contains_key("bindings"));
                assert!(!object.contains_key("stage"));
                assert!(!object.contains_key("mutation"));
            }
        }
        let negative = Eip0045B4SequenceSubjectV1::from_canonical_jcs(
            bundle
                .subject_files
                .get(&subject_artifact_path("registry-negative-cases"))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            negative.elements.len(),
            usize::from(B4_NEGATIVE_PLAN_VARIANT_COUNT)
        );
        let first =
            validate_canonical_json_source(&negative.elements[0].decoded_bytes().unwrap()).unwrap();
        assert_eq!(
            first
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "baseSelectorId",
                "class",
                "executionId",
                "executionSurface",
                "fixture",
                "groupId",
                "materializationDomain",
                "qaResultCode",
                "variantId"
            ]
        );
    }

    #[test]
    fn missing_extra_and_changed_subjects_fail_byte_exact_replay() {
        let (temp, corpus, plan) = fixture_repository();
        let bundle = derive_b4_subject_bundle(&corpus, &plan, temp.path()).unwrap();
        let catalog = bundle.catalog_jcs().unwrap();

        let mut missing = bundle.subject_files.clone();
        missing.pop_first();
        assert!(verify_b4_subject_bundle(&corpus, &plan, temp.path(), &catalog, &missing).is_err());

        let mut extra = bundle.subject_files.clone();
        extra.insert("unexpected.subject.json".to_owned(), b"{}".to_vec());
        assert!(verify_b4_subject_bundle(&corpus, &plan, temp.path(), &catalog, &extra).is_err());

        let mut changed = bundle.subject_files.clone();
        changed.values_mut().next().unwrap().push(b'\n');
        assert!(verify_b4_subject_bundle(&corpus, &plan, temp.path(), &catalog, &changed).is_err());
    }

    #[test]
    fn missing_source_and_plan_drift_fail_closed() {
        let (temp, corpus, plan) = fixture_repository();
        fs::remove_file(
            temp.path()
                .join("profiles")
                .join("risc0-v3-succinct")
                .join("constants.bin"),
        )
        .unwrap();
        assert!(derive_b4_subject_bundle(&corpus, &plan, temp.path()).is_err());

        let (temp, corpus, mut plan) = fixture_repository();
        plan.groups[0].executions[0].execution_id = "drift--single".to_owned();
        assert!(derive_b4_subject_bundle(&corpus, &plan, temp.path()).is_err());
    }

    #[test]
    fn execution_surface_is_bound_into_the_negative_projection() {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let baseline = negative_plan_projection(&plan)
            .unwrap()
            .to_canonical_jcs()
            .unwrap();
        let mut changed = plan;
        let original = changed.groups[0].executions[0].execution_surface;
        changed.groups[0].executions[0].execution_surface =
            if original == B4NegativeExecutionSurface::OpcodePreflight {
                B4NegativeExecutionSurface::RawStatementClaimBinding
            } else {
                B4NegativeExecutionSurface::OpcodePreflight
            };
        let changed = negative_plan_projection(&changed)
            .unwrap()
            .to_canonical_jcs()
            .unwrap();
        assert_ne!(baseline, changed);
    }

    #[test]
    fn parser_cut_word_offset_is_bound_into_the_negative_projection() {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let baseline = negative_plan_projection(&plan)
            .unwrap()
            .to_canonical_jcs()
            .unwrap();
        let mut changed = plan;
        let execution = changed
            .groups
            .iter_mut()
            .flat_map(|group| &mut group.executions)
            .find(|execution| execution.parser_truncation_words.is_some())
            .expect("the closed parser sweep must contain exact word offsets");
        execution.parser_truncation_words = Some(
            execution
                .parser_truncation_words
                .unwrap()
                .checked_add(1)
                .unwrap(),
        );
        let changed = negative_plan_projection(&changed)
            .unwrap()
            .to_canonical_jcs()
            .unwrap();
        assert_ne!(baseline, changed);
    }

    #[cfg(unix)]
    #[test]
    fn linked_source_file_is_rejected() {
        use std::os::unix::fs::symlink;

        let (temp, corpus, plan) = fixture_repository();
        let constants = temp
            .path()
            .join("profiles")
            .join("risc0-v3-succinct")
            .join("constants.bin");
        let target = temp.path().join("constants-target.bin");
        fs::rename(&constants, &target).unwrap();
        symlink(&target, &constants).unwrap();
        assert!(derive_b4_subject_bundle(&corpus, &plan, temp.path()).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn junction_in_source_path_is_rejected() {
        use std::os::windows::process::CommandExt;
        use std::process::Command;

        let (temp, corpus, plan) = fixture_repository();
        let profile = temp.path().join("profiles").join("risc0-v3-succinct");
        let target = temp.path().join("profile-target");
        fs::rename(&profile, &target).unwrap();
        let command_line = format!(
            "mklink /J \"{}\" \"{}\"",
            profile.display(),
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
        assert!(derive_b4_subject_bundle(&corpus, &plan, temp.path()).is_err());
        fs::remove_dir(&profile).unwrap();
        fs::rename(target, profile).unwrap();
    }

    #[test]
    fn catalogue_parser_rejects_unknown_fields() {
        let (temp, corpus, plan) = fixture_repository();
        let bundle = derive_b4_subject_bundle(&corpus, &plan, temp.path()).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&bundle.catalog_jcs().unwrap()).unwrap();
        value["subjects"][0]["provenance"]["unexpected"] = serde_json::json!(true);
        let bytes = canonical_json_bytes(&value).unwrap();
        assert!(Eip0045B4SubjectCatalogV1::from_canonical_jcs(&bytes).is_err());
    }

    #[test]
    fn full_validator_does_not_accept_the_narrow_structural_projector_fixture() {
        let (_temp, corpus, _plan) = fixture_repository();
        assert!(corpus.validate().is_err());
    }

    #[test]
    fn closed_projection_does_not_depend_on_negative_registry_artifacts() {
        let (temp, corpus, plan) = fixture_repository();
        let first = derive_b4_subject_bundle(&corpus, &plan, temp.path()).unwrap();
        let mut second_corpus = corpus.clone();
        second_corpus.negative_cases.clear();
        let second = derive_b4_subject_bundle(&second_corpus, &plan, temp.path()).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn negative_classes_match_the_corpus_inventory() {
        let (temp, mut corpus, plan) = fixture_repository();
        corpus.negative_classes.swap(0, 1);
        assert!(derive_b4_subject_bundle(&corpus, &plan, temp.path()).is_err());
        assert_eq!(
            enum_string(B4NegativeClass::StatementBinding).unwrap(),
            "statement-binding"
        );
    }
}
