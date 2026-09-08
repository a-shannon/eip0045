//! Trusted-finalizer cross-document bindings for the B4 positive gate.
//!
//! The module applies its closed embedded Draft 2020-12 schemas, closes the
//! cross-document relationships which those schemas cannot express, then binds
//! caller-supplied physical measurements to the documents. It does not attest
//! that the caller performed generator replay, OCI execution, archive or JAR
//! inspection, or no-follow measurement; the trusted finalizer executor must
//! establish those facts before calling this semantic layer.

mod runtime_observation;

pub use runtime_observation::{
    B4ParsedProcessIdentityRecordV1, B4ParsedRuncStateStatusV1, B4ParsedRuncStateV1,
    B4PositiveProcessIdentityContractV1, B4PositiveRuncStateContractV1,
    B4StructuralCreatedProcessMatchV1,
};

use crate::{
    b4_build_check::AuthoritativeB4BuildProjection,
    b4_campaign_contract::{
        B4CampaignValidatorBindingV1, B4CampaignValidatorImplementationV1,
        B4ContractArtifactEncodingV1, B4ContractArtifactIdentityV1,
        B4NamedContractArtifactIdentityV1, B4PositiveGateAuthorityV1,
        B4PositiveGenerationExternalClosureV2, B4PositiveGenerationPhysicalBindingsV2,
        B4PositivePrecommitAuthorityV2, B4ReviewedSourceBindingV1, Eip0045B4VerifierContractV1,
        b4_paths_conflict, validate_safe_relative_path,
    },
    b4_positive_input_set::{
        B4PositiveInputSetPublicationBindingV2, derive_b4_positive_input_set_completion_jcs_v2,
    },
    b4_recursive_auxiliary_paths::compiled_positive_auxiliary_artifact_paths,
    canonical::{canonical_json_bytes, parse_json_strict, validate_canonical_json_source},
    claim::ok_receipt_claim_digests,
    constants::{
        DIGEST_BYTES, PROOF_BYTES, TERMINAL_CONTROL_KIND_JOIN, TERMINAL_CONTROL_KIND_LIFT,
        TERMINAL_CONTROL_KIND_RESOLVE,
    },
    ergo_statement::parse_ergo_statement_v1,
    manifest::{ManifestEntry, ProofOutputManifest, validate_manifest_shape},
    profile_manifest::{ProfileArtifacts, StarkProfileManifestV1, validate_profile_package_v1},
};
use anyhow::{Context, Result, ensure};
use risc0_binfmt::compute_image_id;
use runtime_observation::{RUNTIME_PROCESS_IDENTITY_CONTRACT_ID, RUNTIME_STATE_CONTRACT_ID};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};

const MAX_PROVENANCE_JCS_BYTES: usize = 1_048_576;
const MAX_RUN_JCS_BYTES: usize = 65_536;
const MAX_SOURCE_BYTES: u64 = 536_870_912;
const MAX_DEPENDENCY_BYTES: u64 = 8_589_934_592;
const MAX_TOOLCHAIN_BYTES: u64 = 8_589_934_592;
const MAX_OCI_UNCOMPRESSED_LAYER_BYTES: u64 = 34_359_738_368;
const USTAR_BLOCK_BYTES: u64 = 512;
const B4_POSITIVE_PROFILE_ID_HEX: &str =
    "23c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383";
const OCI_LAYOUT_PAYLOAD: &[u8] = b"{\"imageLayoutVersion\":\"1.0.0\"}";
const LINEAGE_DIGEST_DOMAIN: &[u8] = b"EIP0045-B4-LINEAGE-V1\0";
const DEPENDENCY_DIGEST_DOMAIN: &[u8] = b"EIP0045-B4-DEPENDENCY-CLOSURE-V1\0";
const TOOLCHAIN_DIGEST_DOMAIN: &[u8] = b"EIP0045-B4-TOOLCHAIN-CLOSURE-V1\0";
const STARTUP_DEPENDENCY_POLICY_ID: &str = "eip0045-b4-elf64-amd64-startup-dependency-closure-v1";
const RUNTIME_CONFIGURATION_POLICY_ID: &str = "eip0045-b4-oci-runtime-config-projection-v1";
const RETAINED_HOST_ROOTFS_METADATA_POLICY_ID: &str =
    "eip0045-b4-retained-host-rootfs-metadata-obligations-v1";
const RETAINED_HOST_ROOTFS_METADATA_POLICY_V2_ID: &str =
    "eip0045-b4-retained-host-rootfs-metadata-obligations-v2";
const TMPFS_METADATA_PROVIDER_PROFILE_ID: &str = "eip0045-b4-tmpfs-metadata-provider-v1";
const SUPERVISED_FILESYSTEM_SESSION_PROTOCOL_ID: &str =
    "eip0045-b4-supervised-filesystem-session-v1";
const BUILDROOT_APPLIANCE_PROFILE_ID: &str = "eip0045-b4-buildroot-appliance-v1";
const RETAINED_HOST_ROOTFS_METADATA_OBLIGATION_IDS: [&str; 11] = [
    "xattr-name-set",
    "posix-access-acl",
    "posix-default-acl",
    "linux-file-capability",
    "immutable",
    "append-only",
    "encrypted",
    "verity",
    "casefold",
    "nonzero-project-id",
    "project-inherit",
];
const RETAINED_HOST_ROOTFS_METADATA_OUTCOME_IDS: [&str; 6] = [
    "absent",
    "present",
    "unsupported",
    "inaccessible",
    "oversize",
    "unstable",
];
const RUNTIME_NAMESPACES_SELECTOR_ID: &str =
    "eip0045-b4-runtime-observation-namespaces-reserved-v1";
const RUNTIME_ID_MAPPINGS_SELECTOR_ID: &str =
    "eip0045-b4-runtime-observation-id-mappings-reserved-v1";
const RUNTIME_MOUNTINFO_SELECTOR_ID: &str = "eip0045-b4-runtime-observation-mountinfo-reserved-v1";
const RUNTIME_SECURITY_STATUS_SELECTOR_ID: &str =
    "eip0045-b4-runtime-observation-security-status-reserved-v1";
const RUNTIME_CGROUP_V2_SELECTOR_ID: &str = "eip0045-b4-runtime-observation-cgroup-v2-reserved-v1";
const RUNTIME_ROOT_IDENTITY_SELECTOR_ID: &str =
    "eip0045-b4-runtime-observation-root-identity-reserved-v1";
const RUNTIME_AUXV_SELECTOR_ID: &str = "eip0045-b4-runtime-observation-auxv-reserved-v1";
const RUNTIME_PROCESS_MAPPINGS_SELECTOR_ID: &str =
    "eip0045-b4-runtime-observation-process-mappings-reserved-v1";
const RUNTIME_SMOKE_IDENTITY_SELECTOR_ID: &str =
    "eip0045-b4-runtime-observation-smoke-identity-reserved-v1";
const INPUT_SET_SCHEMA: &str =
    include_str!("../finalizer-schema/b4-positive-input-set-v1.schema.json");
const INPUT_SET_V2_SCHEMA: &str =
    include_str!("../finalizer-schema/b4-positive-input-set-v2.schema.json");
const GENERATION_SET_SCHEMA: &str =
    include_str!("../finalizer-schema/b4-positive-generation-set-v1.schema.json");
const GENERATION_SET_V2_SCHEMA: &str =
    include_str!("../finalizer-schema/b4-positive-generation-set-v2.schema.json");
const VALIDATOR_DESCRIPTOR_SCHEMA: &str =
    include_str!("../finalizer-schema/b4-validator-build-descriptor-v1.schema.json");
const VALIDATOR_DESCRIPTOR_V2_SCHEMA: &str =
    include_str!("../finalizer-schema/b4-validator-build-descriptor-v2.schema.json");
const JVM_COPY_ONLY_INCLUSION_MANIFEST_SCHEMA: &str =
    include_str!("../finalizer-schema/b4-jvm-copy-only-inclusion-manifest-v1.schema.json");
const RUNNER_PROFILE_SCHEMA: &str =
    include_str!("../finalizer-schema/b4-positive-oci-runner-profile-v1.schema.json");
const RUNNER_PROFILE_V2_SCHEMA: &str =
    include_str!("../finalizer-schema/b4-positive-oci-runner-profile-v2.schema.json");
const SECCOMP_SCHEMA: &str = include_str!("../finalizer-schema/b4-positive-seccomp-v1.schema.json");
const VERIFIER_INPUT_SCHEMA: &str =
    include_str!("../finalizer-schema/b4-positive-verifier-input-v1.schema.json");
const OBSERVATION_SCHEMA: &str =
    include_str!("../finalizer-schema/b4-positive-observation-v1.schema.json");
const ACCEPTANCE_SCHEMA: &str =
    include_str!("../finalizer-schema/b4-positive-acceptance-v1.schema.json");
const ACCEPTANCE_V2_SCHEMA: &str =
    include_str!("../finalizer-schema/b4-positive-acceptance-v2.schema.json");
type CompiledSchema = std::result::Result<jsonschema::Validator, String>;
static INPUT_SET_VALIDATOR: OnceLock<CompiledSchema> = OnceLock::new();
static INPUT_SET_V2_VALIDATOR: OnceLock<CompiledSchema> = OnceLock::new();
static GENERATION_SET_VALIDATOR: OnceLock<CompiledSchema> = OnceLock::new();
static GENERATION_SET_V2_VALIDATOR: OnceLock<CompiledSchema> = OnceLock::new();
static VALIDATOR_DESCRIPTOR_VALIDATOR: OnceLock<CompiledSchema> = OnceLock::new();
static VALIDATOR_DESCRIPTOR_V2_VALIDATOR: OnceLock<CompiledSchema> = OnceLock::new();
static JVM_COPY_ONLY_INCLUSION_MANIFEST_VALIDATOR: OnceLock<CompiledSchema> = OnceLock::new();
static RUNNER_PROFILE_VALIDATOR: OnceLock<CompiledSchema> = OnceLock::new();
static RUNNER_PROFILE_V2_VALIDATOR: OnceLock<CompiledSchema> = OnceLock::new();
static SECCOMP_VALIDATOR: OnceLock<CompiledSchema> = OnceLock::new();
static VERIFIER_INPUT_VALIDATOR: OnceLock<CompiledSchema> = OnceLock::new();
static OBSERVATION_VALIDATOR: OnceLock<CompiledSchema> = OnceLock::new();
static ACCEPTANCE_VALIDATOR: OnceLock<CompiledSchema> = OnceLock::new();
static ACCEPTANCE_V2_VALIDATOR: OnceLock<CompiledSchema> = OnceLock::new();
const POSITIVE_CASE_COUNT: usize = 11;
const POSITIVE_ACCEPTANCE_COUNT: usize = POSITIVE_CASE_COUNT * 2;
const LIFT_ARTIFACT_LAYOUT: [(&str, &str); 7] = [
    ("claim-digest", "candidate-claim-digest.bin"),
    ("control-id", "candidate-control-id.bin"),
    ("image-id", "candidate-image-id.bin"),
    ("journal", "candidate-journal.bin"),
    ("metadata", "candidate-metadata.json"),
    ("raw-seal", "candidate-raw-seal.bin"),
    ("receipt-oracle", "candidate-receipt-oracle.bincode"),
];
const RECURSIVE_ARTIFACT_LAYOUT: [(&str, &str); 8] = [
    ("ancestry", "candidate-ancestry.json"),
    ("calibration", "candidate-recursive-calibration.json"),
    ("claim-digest", "candidate-claim-digest.bin"),
    ("control-id", "candidate-control-id.bin"),
    ("image-id", "candidate-image-id.bin"),
    ("journal", "candidate-journal.bin"),
    ("raw-seal", "candidate-raw-seal.bin"),
    ("receipt-oracle", "candidate-recursive-oracle.borsh"),
];
/// Exact case-indexed physical auxiliary raw-seal inventory.
pub(crate) fn positive_auxiliary_artifact_paths(
    case_index: usize,
) -> Result<&'static [&'static str]> {
    compiled_positive_auxiliary_artifact_paths(case_index)
}
const JVM_OPTIONS: [&str; 9] = [
    "-Xms64m",
    "-Xmx3072m",
    "-XX:+UseSerialGC",
    "-XX:+DisableAttachMechanism",
    "-Djava.io.tmpdir=/tmp",
    "-Dfile.encoding=UTF-8",
    "-Duser.language=en",
    "-Duser.country=US",
    "-Duser.timezone=UTC",
];
const JVM_COPY_ONLY_PACKAGER_ARGUMENTS: [&str; 7] = [
    "replay-copy-only-v1",
    "--manifest",
    "/phase-input/inclusion-manifest.json",
    "--archive-root",
    "/phase-input/archives",
    "--output",
    "/out/validator.jar",
];

#[derive(Clone, Copy, Debug)]
enum EmbeddedSchema {
    InputSet,
    InputSetV2,
    GenerationSet,
    GenerationSetV2,
    ValidatorDescriptor,
    ValidatorDescriptorV2,
    JvmCopyOnlyInclusionManifest,
    RunnerProfile,
    RunnerProfileV2,
    Seccomp,
    VerifierInput,
    Observation,
    Acceptance,
    AcceptanceV2,
}

impl EmbeddedSchema {
    fn source_and_cache(self) -> (&'static str, &'static OnceLock<CompiledSchema>) {
        match self {
            Self::InputSet => (INPUT_SET_SCHEMA, &INPUT_SET_VALIDATOR),
            Self::InputSetV2 => (INPUT_SET_V2_SCHEMA, &INPUT_SET_V2_VALIDATOR),
            Self::GenerationSet => (GENERATION_SET_SCHEMA, &GENERATION_SET_VALIDATOR),
            Self::GenerationSetV2 => (GENERATION_SET_V2_SCHEMA, &GENERATION_SET_V2_VALIDATOR),
            Self::ValidatorDescriptor => {
                (VALIDATOR_DESCRIPTOR_SCHEMA, &VALIDATOR_DESCRIPTOR_VALIDATOR)
            }
            Self::ValidatorDescriptorV2 => (
                VALIDATOR_DESCRIPTOR_V2_SCHEMA,
                &VALIDATOR_DESCRIPTOR_V2_VALIDATOR,
            ),
            Self::JvmCopyOnlyInclusionManifest => (
                JVM_COPY_ONLY_INCLUSION_MANIFEST_SCHEMA,
                &JVM_COPY_ONLY_INCLUSION_MANIFEST_VALIDATOR,
            ),
            Self::RunnerProfile => (RUNNER_PROFILE_SCHEMA, &RUNNER_PROFILE_VALIDATOR),
            Self::RunnerProfileV2 => (RUNNER_PROFILE_V2_SCHEMA, &RUNNER_PROFILE_V2_VALIDATOR),
            Self::Seccomp => (SECCOMP_SCHEMA, &SECCOMP_VALIDATOR),
            Self::VerifierInput => (VERIFIER_INPUT_SCHEMA, &VERIFIER_INPUT_VALIDATOR),
            Self::Observation => (OBSERVATION_SCHEMA, &OBSERVATION_VALIDATOR),
            Self::Acceptance => (ACCEPTANCE_SCHEMA, &ACCEPTANCE_VALIDATOR),
            Self::AcceptanceV2 => (ACCEPTANCE_V2_SCHEMA, &ACCEPTANCE_V2_VALIDATOR),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum V2PositiveDocumentKind {
    InputSet,
    GenerationSet,
    ValidatorDescriptor,
    RunnerProfile,
    Acceptance,
}

impl V2PositiveDocumentKind {
    const fn format(self) -> &'static str {
        match self {
            Self::InputSet => "Eip0045B4PositiveInputSetV2",
            Self::GenerationSet => "Eip0045B4PositiveGenerationSetV2",
            Self::ValidatorDescriptor => "Eip0045B4ValidatorBuildDescriptorV2",
            Self::RunnerProfile => "Eip0045B4PositiveOciRunnerProfileV2",
            Self::Acceptance => "Eip0045B4PositiveAcceptanceV2",
        }
    }

    const fn schema(self) -> EmbeddedSchema {
        match self {
            Self::InputSet => EmbeddedSchema::InputSetV2,
            Self::GenerationSet => EmbeddedSchema::GenerationSetV2,
            Self::ValidatorDescriptor => EmbeddedSchema::ValidatorDescriptorV2,
            Self::RunnerProfile => EmbeddedSchema::RunnerProfileV2,
            Self::Acceptance => EmbeddedSchema::AcceptanceV2,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct PositiveCaseSpec {
    case_id: &'static str,
    family: &'static str,
    terminal_kind: &'static str,
    terminal_parameter: u8,
}

const POSITIVE_CASE_SPECS: [PositiveCaseSpec; POSITIVE_CASE_COUNT] = [
    PositiveCaseSpec {
        case_id: "lift-po2-15",
        family: "lift",
        terminal_kind: "lift",
        terminal_parameter: 15,
    },
    PositiveCaseSpec {
        case_id: "lift-po2-16",
        family: "lift",
        terminal_kind: "lift",
        terminal_parameter: 16,
    },
    PositiveCaseSpec {
        case_id: "lift-po2-17",
        family: "lift",
        terminal_kind: "lift",
        terminal_parameter: 17,
    },
    PositiveCaseSpec {
        case_id: "lift-po2-18",
        family: "lift",
        terminal_kind: "lift",
        terminal_parameter: 18,
    },
    PositiveCaseSpec {
        case_id: "lift-po2-19",
        family: "lift",
        terminal_kind: "lift",
        terminal_parameter: 19,
    },
    PositiveCaseSpec {
        case_id: "lift-po2-20",
        family: "lift",
        terminal_kind: "lift",
        terminal_parameter: 20,
    },
    PositiveCaseSpec {
        case_id: "lift-po2-21",
        family: "lift",
        terminal_kind: "lift",
        terminal_parameter: 21,
    },
    PositiveCaseSpec {
        case_id: "lift-po2-22",
        family: "lift",
        terminal_kind: "lift",
        terminal_parameter: 22,
    },
    PositiveCaseSpec {
        case_id: "terminal-join",
        family: "terminal-join",
        terminal_kind: "join",
        terminal_parameter: 0,
    },
    PositiveCaseSpec {
        case_id: "terminal-resolve-explicit-root",
        family: "terminal-resolve",
        terminal_kind: "resolve",
        terminal_parameter: 0,
    },
    PositiveCaseSpec {
        case_id: "resolve-zero-root-then-join",
        family: "resolve-then-join",
        terminal_kind: "join",
        terminal_parameter: 0,
    },
];

fn canonical_positive_case_plan(index: usize, spec: PositiveCaseSpec) -> Value {
    let (guest_mode, source_segments, root_branch) = match index {
        0..=7 => ("plain", 1, "none"),
        8 => ("plain", 2, "none"),
        9 => ("verify-assumption-explicit-root", 1, "explicit"),
        10 => ("verify-assumption-zero-root", 2, "zero"),
        _ => unreachable!("the compiled positive-case inventory has eleven entries"),
    };
    let roles: Vec<Value> = if index < 8 {
        LIFT_ARTIFACT_LAYOUT
            .iter()
            .map(|(role, _)| json!(role))
            .collect()
    } else {
        RECURSIVE_ARTIFACT_LAYOUT
            .iter()
            .map(|(role, _)| json!(role))
            .collect()
    };
    json!({
        "index": index,
        "caseId": spec.case_id,
        "family": spec.family,
        "guestMode": guest_mode,
        "sourceSegments": source_segments,
        "rootBranch": root_branch,
        "terminal": {
            "kind": spec.terminal_kind,
            "parameter": spec.terminal_parameter
        },
        "artifactRoles": roles
    })
}

/// One path-qualified canonical JCS document held below the provenance root.
#[derive(Clone, Copy, Debug)]
pub struct NamedCanonicalJcs<'a> {
    /// Lowercase finalizer-created relative path.
    pub relative_path: &'a str,
    /// Exact canonical document bytes.
    pub bytes: &'a [u8],
}

/// The pre-proof documents needed to establish positive-gate authority.
#[derive(Clone, Copy, Debug)]
pub struct PositiveProvenanceDocuments<'a> {
    /// Opaque projection emitted only by authoritative B4 build validation.
    pub authoritative_build: &'a AuthoritativeB4BuildProjection,
    /// Exact path-qualified canonical pre-proof input-set bytes.
    pub input_set: NamedCanonicalJcs<'a>,
    /// Exact path-qualified canonical dual-surface verifier-contract bytes
    /// committed by the input set.
    pub verifier_contract: NamedCanonicalJcs<'a>,
    /// Four runner profiles in their canonical role order.
    pub runner_profiles: [NamedCanonicalJcs<'a>; 4],
    /// Four exact seccomp documents in runner-role order.
    pub seccomp_profiles: [NamedCanonicalJcs<'a>; 4],
    /// Rust then JVM-lineage build descriptors. Independent source review is
    /// external to this semantic token.
    pub validator_descriptors: [NamedCanonicalJcs<'a>; 2],
    /// Exact JVM COPY-ONLY inclusion-manifest bytes consumed by the packer.
    pub jvm_copy_only_inclusion_manifest: NamedCanonicalJcs<'a>,
}

/// Exact mixed-wire document set admitted by the V2 positive precommit gate.
///
/// The positive input set, all four runner profiles, and both validator build
/// descriptors are V2 documents. The verifier contract, seccomp documents,
/// and JVM COPY-ONLY inclusion manifest deliberately retain their reviewed V1
/// wire identities. This view carries bytes only; it is not an H0 publication,
/// provider, session, filesystem, or campaign authority.
#[derive(Clone, Copy, Debug)]
pub struct B4PositivePrecommitDocumentsV2<'a> {
    /// Exact path-qualified canonical V2 positive input-set bytes.
    pub input_set: NamedCanonicalJcs<'a>,
    /// Exact path-qualified canonical V1 verifier-contract bytes.
    pub verifier_contract: NamedCanonicalJcs<'a>,
    /// Four V2 runner profiles in canonical role order.
    pub runner_profiles: [NamedCanonicalJcs<'a>; 4],
    /// Four V1 seccomp documents in the same role order.
    pub seccomp_documents: [NamedCanonicalJcs<'a>; 4],
    /// Rust then JVM V2 validator build descriptors.
    pub validator_descriptors: [NamedCanonicalJcs<'a>; 2],
    /// Exact V1 JVM COPY-ONLY inclusion manifest.
    pub jvm_copy_only_inclusion_manifest: NamedCanonicalJcs<'a>,
}

/// Private pathless projection consumed by the canonical input-set assembler.
///
/// There is deliberately no production constructor. A future descriptor-rooted
/// importer must create this value inside its affine import session. The
/// current test module can name the private fields only to prove byte equality
/// with the long-standing semantic fixture.
struct PositiveInputSetConstructionProjectionV1<'a> {
    authoritative_build: &'a AuthoritativeB4BuildProjection,
    profile_manifest: B4ContractArtifactIdentityV1,
    profile_algorithm: B4ContractArtifactIdentityV1,
    profile_constants: B4ContractArtifactIdentityV1,
    guest_elf_path: &'a str,
    reference_statement_bundle_manifest: B4ContractArtifactIdentityV1,
    source_lock: B4ContractArtifactIdentityV1,
    proof_generator_path: &'a str,
    verifier_contract: NamedCanonicalJcs<'a>,
    runner_profiles: [NamedCanonicalJcs<'a>; 4],
    validator_descriptors: [NamedCanonicalJcs<'a>; 2],
    recursive_calibrations: [B4ContractArtifactIdentityV1; 3],
}

fn constructor_identity_value(
    identity: &B4ContractArtifactIdentityV1,
    encoding: B4ContractArtifactEncodingV1,
    label: &str,
) -> Result<Value> {
    identity
        .validate()
        .with_context(|| format!("invalid canonical input-set {label} identity"))?;
    ensure!(
        identity.encoding == encoding,
        "canonical input-set {label} uses the wrong encoding"
    );
    serde_json::to_value(identity)
        .with_context(|| format!("cannot serialize canonical input-set {label} identity"))
}

fn authoritative_raw_identity(
    path: &str,
    byte_length: u64,
    sha256: &str,
    label: &str,
) -> Result<B4ContractArtifactIdentityV1> {
    let identity = B4ContractArtifactIdentityV1 {
        path: path.to_owned(),
        byte_length,
        sha256: sha256.to_owned(),
        encoding: B4ContractArtifactEncodingV1::RawBytes,
    };
    identity
        .validate()
        .with_context(|| format!("invalid authoritative {label} identity"))?;
    Ok(identity)
}

/// Assemble the sole canonical pathless positive input-set document.
///
/// This kernel returns bytes only. It creates no positive gate, publication
/// binding, filesystem authority, H0 source, or mutation guard. Its projection
/// has no production constructor until descriptor-rooted physical import lands.
#[allow(
    clippy::too_many_lines,
    dead_code,
    reason = "the canonical kernel lands before the descriptor-rooted H0 importer can construct its private projection"
)]
fn construct_canonical_positive_input_set_jcs_v1(
    projection: PositiveInputSetConstructionProjectionV1<'_>,
) -> Result<Vec<u8>> {
    let profile_manifest = constructor_identity_value(
        &projection.profile_manifest,
        B4ContractArtifactEncodingV1::RawBytes,
        "profile manifest",
    )?;
    let profile_algorithm = constructor_identity_value(
        &projection.profile_algorithm,
        B4ContractArtifactEncodingV1::RawBytes,
        "profile algorithm",
    )?;
    let profile_constants = constructor_identity_value(
        &projection.profile_constants,
        B4ContractArtifactEncodingV1::RawBytes,
        "profile constants",
    )?;
    let reference_statement_bundle_manifest = constructor_identity_value(
        &projection.reference_statement_bundle_manifest,
        B4ContractArtifactEncodingV1::Rfc8785Jcs,
        "reference statement-bundle manifest",
    )?;
    let source_lock = constructor_identity_value(
        &projection.source_lock,
        B4ContractArtifactEncodingV1::Rfc8785Jcs,
        "source lock",
    )?;
    ensure!(
        projection.source_lock.sha256 == projection.authoritative_build.source_lock_sha256(),
        "canonical input-set source lock differs from authoritative B4 validation"
    );

    let guest_elf_identity = authoritative_raw_identity(
        projection.guest_elf_path,
        projection.authoritative_build.guest_elf_byte_length(),
        projection.authoritative_build.guest_elf_sha256(),
        "guest ELF",
    )?;
    let guest_elf = constructor_identity_value(
        &guest_elf_identity,
        B4ContractArtifactEncodingV1::RawBytes,
        "guest ELF",
    )?;
    let proof_generator_identity = authoritative_raw_identity(
        projection.proof_generator_path,
        projection
            .authoritative_build
            .generator_artifact_byte_length(),
        projection.authoritative_build.generator_artifact_sha256(),
        "proof generator",
    )?;
    let proof_generator = constructor_identity_value(
        &proof_generator_identity,
        B4ContractArtifactEncodingV1::RawBytes,
        "proof generator",
    )?;
    let proof_generator_commitment = binary_commitment(&proof_generator)?;

    let verifier_contract = BoundDocument::parse(
        projection.verifier_contract,
        "canonical input-set verifier contract",
    )?;
    let runner_profiles: [BoundDocument; 4] = projection
        .runner_profiles
        .into_iter()
        .enumerate()
        .map(|(index, document)| {
            BoundDocument::parse(
                document,
                &format!("canonical input-set runner profile {index}"),
            )
        })
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("canonical input-set runner cardinality drift"))?;
    let validator_descriptors: [BoundDocument; 2] = projection
        .validator_descriptors
        .into_iter()
        .enumerate()
        .map(|(index, document)| {
            BoundDocument::parse(
                document,
                &format!("canonical input-set validator descriptor {index}"),
            )
        })
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("canonical input-set validator cardinality drift"))?;

    let runner_inventory: Vec<Value> = PositiveRunnerRole::all()
        .into_iter()
        .enumerate()
        .map(|(index, role)| {
            json!({
                "runnerProfileIndex": index,
                "purpose": role.purpose(),
                "artifact": runner_profiles[index]
                    .identity_with_path("Eip0045B4PositiveOciRunnerProfileV1")
            })
        })
        .collect();
    let validator_inventory: Vec<Value> = [
        PositiveImplementation::RustReference,
        PositiveImplementation::IndependentJvm,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, implementation)| {
        json!({
            "implementationIndex": index,
            "implementation": implementation.implementation(),
            "language": implementation.language(),
            "buildDescriptor": validator_descriptors[index]
                .identity_with_path("Eip0045B4ValidatorBuildDescriptorV1")
        })
    })
    .collect();
    let recursive_calibrations: Vec<Value> = projection
        .recursive_calibrations
        .iter()
        .enumerate()
        .map(|(index, identity)| {
            let identity = constructor_identity_value(
                identity,
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                "recursive calibration",
            )?;
            Ok(json!({
                "caseId": POSITIVE_CASE_SPECS[index + 8].case_id,
                "artifact": identity
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let positive_cases: Vec<Value> = POSITIVE_CASE_SPECS
        .iter()
        .copied()
        .enumerate()
        .map(|(index, spec)| canonical_positive_case_plan(index, spec))
        .collect();

    let input_set = json!({
        "format": "Eip0045B4PositiveInputSetV1",
        "formatVersion": 1,
        "profile": {
            "profileId": B4_POSITIVE_PROFILE_ID_HEX,
            "manifest": profile_manifest,
            "algorithm": profile_algorithm,
            "constants": profile_constants
        },
        "guest": {
            "elf": guest_elf,
            "imageId": projection.authoritative_build.image_id_hex()
        },
        "referenceStatement": {
            "bundleManifest": reference_statement_bundle_manifest,
            "contractId": projection.authoritative_build.contract_id_hex(),
            "statementByteLength": projection.authoritative_build.statement_byte_length(),
            "statementSha256": projection.authoritative_build.statement_sha256(),
            "chainDomainId": projection.authoritative_build.chain_domain_id_hex(),
            "applicationPayloadByteLength": projection
                .authoritative_build
                .application_payload_byte_length(),
            "applicationPayloadSha256": projection
                .authoritative_build
                .application_payload_sha256()
        },
        "sourceLock": source_lock,
        "proofGenerator": {
            "artifact": proof_generator,
            "qualifyingBuild": {
                "policy": "eip0045-b4-qualifying-build-binding-v1",
                "validationMode": "authoritative-external-anchors",
                "filesystemBinding": "unix-file-identity-bound",
                "evidenceRootSha256": projection.authoritative_build.evidence_root_sha256(),
                "sourceCommit": projection.authoritative_build.source_commit(),
                "sourceTree": projection.authoritative_build.source_tree(),
                "sourceLockSha256": projection.authoritative_build.source_lock_sha256(),
                "generatorCargoClosureSha256": projection
                    .authoritative_build
                    .generator_cargo_closure_sha256(),
                "proofGenerationTestsSha256": projection
                    .authoritative_build
                    .proof_generation_tests_sha256(),
                "generatorArtifact": proof_generator_commitment
            },
            "executionPolicy": {
                "policy": "eip0045-b4-proof-generation-executor-v1",
                "caseOrder": "input-set-order",
                "generatorProcessReuse": false,
                "replayProcessReuse": false,
                "network": "disabled",
                "environmentInheritance": "none",
                "inputSetMount": "read-only-preexisting",
                "caseOutput": "fresh-empty-create-only",
                "replayExportMount": "read-only-physical-export",
                "failurePublication": "none"
            }
        },
        "verifierCliContract": verifier_contract
            .identity_with_path("Eip0045B4VerifierContractV1"),
        "validators": validator_inventory,
        "runnerProfiles": runner_inventory,
        "recursiveCalibrations": recursive_calibrations,
        "positiveCases": positive_cases
    });

    validate_json_schema(
        &input_set,
        EmbeddedSchema::InputSet,
        "constructed positive input set",
    )?;
    require_format(&input_set, "Eip0045B4PositiveInputSetV1", 1)?;
    validate_authoritative_build_projection(&input_set, projection.authoritative_build)?;
    let source = canonical_json_bytes(&input_set)?;
    ensure!(
        source.len() <= MAX_PROVENANCE_JCS_BYTES,
        "constructed positive input set exceeds the 1 MiB canonical-document bound"
    );
    ensure!(
        validate_canonical_json_source(&source)? == input_set,
        "constructed positive input set does not reparse byte-exactly"
    );
    Ok(source)
}

/// Exact bytes of one named file in a generator export's `proof-output`
/// directory. The caller must obtain these bytes through the trusted
/// finalizer's no-follow, bounded regular-file reader.
#[derive(Clone, Copy, Debug)]
pub struct GeneratedArtifactContents<'a> {
    /// Exact basename under the case-local `proof-output` directory.
    pub source_file: &'a str,
    /// Exact physical file bytes.
    pub bytes: &'a [u8],
}

/// Exact bytes of one nested ancestry seal in a recursive generator export.
///
/// These physical files are bound by the full proof-output manifest but are
/// deliberately not semantic roles in the generation set or expanded registry.
#[derive(Clone, Copy, Debug)]
pub struct GeneratedAuxiliaryArtifactContents<'a> {
    /// Exact repository-relative POSIX path under the recursive proof-output root.
    pub relative_path: &'a str,
    /// Exact physical file bytes.
    pub bytes: &'a [u8],
}

/// Exact physical documents for one generator export.
///
/// The trusted finalizer must replay-verify the export before constructing this
/// view. This raw view carries bytes, not an execution or replay attestation.
#[derive(Clone, Copy, Debug)]
pub struct PositiveGenerationCaseDocuments<'a> {
    /// Exact canonical proof-output manifest bytes.
    pub proof_output_manifest_jcs: &'a [u8],
    /// Exact artifact bytes in the generation-set role order.
    pub artifacts: &'a [GeneratedArtifactContents<'a>],
    /// Exact nested auxiliary artifacts in the closed family path order.
    ///
    /// Lift cases supply an empty slice. Recursive auxiliary seals remain
    /// physical manifest members and never become repeated `raw-seal` roles.
    pub auxiliary_artifacts: &'a [GeneratedAuxiliaryArtifactContents<'a>],
}

/// Post-proof documents consumed by the generation binding phase.
#[derive(Clone, Copy, Debug)]
pub struct PositiveGenerationDocuments<'a> {
    /// Exact finalizer-created canonical generation-set document.
    pub generation_set: NamedCanonicalJcs<'a>,
    /// Exact physically launched proof-generator artifact bytes.
    pub proof_generator_artifact: &'a [u8],
    /// Eleven export snapshots in canonical case order.
    pub cases: [PositiveGenerationCaseDocuments<'a>; 11],
}

/// Construct the exact canonical V2 positive generation set from the retained
/// pre-proof input and all eleven physical generator exports.
///
/// This function performs no proving, filesystem access, process launch, or
/// publication. It validates every supplied export against the closed case
/// grammar before emitting bytes, but the returned document carries no
/// authority until it is joined to the independent physical source closure by
/// [`validate_and_bind_v2_positive_generation_preacceptance`].
///
/// # Errors
///
/// Returns an error for any malformed V2 input set, proof-generator mismatch,
/// case-order or role drift, noncanonical artifact, incomplete manifest,
/// auxiliary-path mismatch, reused manifest or seal digest, or output-schema
/// violation.
pub fn construct_canonical_positive_generation_set_jcs_v2(
    positive_input_set: &B4PositiveInputSetPublicationBindingV2,
    proof_generator_artifact: &[u8],
    cases: [PositiveGenerationCaseDocuments<'_>; POSITIVE_CASE_COUNT],
) -> Result<Vec<u8>> {
    derive_b4_positive_input_set_completion_jcs_v2(positive_input_set)
        .context("retained V2 positive input-set publication binding is stale")?;
    let input_set = BoundDocument::parse(
        NamedCanonicalJcs {
            relative_path: positive_input_set.input_set_path(),
            bytes: positive_input_set.input_set_jcs(),
        },
        "V2 positive input set",
    )?;
    validate_json_schema(
        &input_set.value,
        EmbeddedSchema::InputSetV2,
        "V2 positive input set",
    )?;
    require_format(
        &input_set.value,
        V2PositiveDocumentKind::InputSet.format(),
        2,
    )?;
    let planned_cases = array_field(&input_set.value, "positiveCases")?;
    ensure!(
        planned_cases.len() == POSITIVE_CASE_COUNT,
        "V2 positive input set must bind exactly eleven planned cases"
    );
    ensure!(
        array_field(&input_set.value, "recursiveCalibrations")?.len() == 3,
        "V2 positive input set must bind exactly three recursive calibrations"
    );
    let proof_generator_identity = field(field(&input_set.value, "proofGenerator")?, "artifact")?;
    validate_measurement(
        proof_generator_identity,
        &measure_bytes(proof_generator_artifact),
        "V2 proof generator artifact",
    )?;

    let mut manifest_digests = BTreeSet::new();
    let mut raw_seal_digests = BTreeSet::new();
    let generated_cases = planned_cases
        .iter()
        .zip(cases)
        .enumerate()
        .map(|(index, (planned, physical))| {
            let generated = construct_v2_generation_case(index, physical)?;
            let bound =
                validate_generation_case(index, planned, &generated, physical, &input_set.value)?;
            ensure!(
                manifest_digests.insert(bound.proof_output_manifest.sha256),
                "V2 positive generation set reuses a proof-output manifest digest"
            );
            ensure!(
                raw_seal_digests.insert(bound.raw_seal.sha256),
                "V2 positive generation set reuses a raw-seal digest"
            );
            Ok(generated)
        })
        .collect::<Result<Vec<_>>>()?;

    let generation_set = json!({
        "format": V2PositiveDocumentKind::GenerationSet.format(),
        "formatVersion": 2,
        "inputSetCommitment": input_set.commitment(V2PositiveDocumentKind::InputSet.format()),
        "proofGeneratorArtifact": binary_commitment(proof_generator_identity)?,
        "cases": generated_cases,
    });
    validate_json_schema(
        &generation_set,
        EmbeddedSchema::GenerationSetV2,
        "constructed V2 positive generation set",
    )?;
    require_format(
        &generation_set,
        V2PositiveDocumentKind::GenerationSet.format(),
        2,
    )?;
    let source = canonical_json_bytes(&generation_set)
        .context("cannot canonicalize the constructed V2 positive generation set")?;
    ensure!(
        source.len() <= MAX_PROVENANCE_JCS_BYTES,
        "constructed V2 positive generation set exceeds the 1 MiB canonical-document bound"
    );
    ensure!(
        validate_canonical_json_source(&source)? == generation_set,
        "constructed V2 positive generation set does not reparse byte-exactly"
    );
    Ok(source)
}

fn construct_v2_generation_case(
    index: usize,
    physical: PositiveGenerationCaseDocuments<'_>,
) -> Result<Value> {
    let spec = POSITIVE_CASE_SPECS
        .get(index)
        .context("positive generation case index is outside the closed plan")?;
    let layout: &[(&str, &str)] = if index < 8 {
        &LIFT_ARTIFACT_LAYOUT
    } else {
        &RECURSIVE_ARTIFACT_LAYOUT
    };
    ensure!(
        physical.artifacts.len() == layout.len(),
        "positive generation artifact cardinality differs from the closed case layout"
    );
    let generated_artifacts = layout
        .iter()
        .zip(physical.artifacts)
        .map(|((role, source_file), artifact)| {
            let measurement = measure_bytes(artifact.bytes);
            let encoding = if matches!(*role, "metadata" | "ancestry" | "calibration") {
                "rfc8785-jcs"
            } else {
                "raw-bytes"
            };
            let mut identity = json!({
                "role": role,
                "sourceFile": source_file,
                "byteLength": measurement.byte_length,
                "sha256": hex::encode(measurement.sha256),
                "encoding": encoding,
            });
            if matches!(*role, "claim-digest" | "control-id" | "image-id") {
                identity["contentHex"] = json!(hex::encode(artifact.bytes));
            }
            if *role == "receipt-oracle" {
                identity["codec"] = json!(if index < 8 {
                    "bincode-1.3.3-little-endian-fixed-int-reject-trailing"
                } else {
                    "eip0045-recursive-oracle-borsh-v1"
                });
            }
            identity
        })
        .collect::<Vec<_>>();
    let manifest = measure_bytes(physical.proof_output_manifest_jcs);
    let generation = if index < 8 {
        json!({"kind": "lift", "segmentPo2": spec.terminal_parameter})
    } else {
        json!({"kind": "recursive", "family": spec.family})
    };
    Ok(json!({
        "caseIndex": index,
        "caseId": spec.case_id,
        "generation": generation,
        "proofOutputManifest": {
            "fileName": if index < 8 {
                "candidate-proof-output-manifest.json"
            } else {
                "candidate-recursive-output-manifest.json"
            },
            "byteLength": manifest.byte_length,
            "sha256": hex::encode(manifest.sha256),
            "encoding": "rfc8785-jcs",
        },
        "artifacts": generated_artifacts,
    }))
}

/// One of the two verifier lineages whose committed metadata must not alias.
/// Independent authorship and source review remain external evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PositiveImplementation {
    /// Native Rust reference verifier.
    RustReference,
    /// Scala/JVM lineage identified by the stable `independent-jvm` wire name;
    /// the variant does not attest independent review.
    IndependentJvm,
}

impl PositiveImplementation {
    fn index(self) -> usize {
        match self {
            Self::RustReference => 0,
            Self::IndependentJvm => 1,
        }
    }

    fn implementation(self) -> &'static str {
        match self {
            Self::RustReference => "rust-reference",
            Self::IndependentJvm => "independent-jvm",
        }
    }

    fn language(self) -> &'static str {
        match self {
            Self::RustReference => "rust",
            Self::IndependentJvm => "scala",
        }
    }

    fn build_role(self) -> PositiveRunnerRole {
        match self {
            Self::RustReference => PositiveRunnerRole::RustValidatorBuild,
            Self::IndependentJvm => PositiveRunnerRole::JvmValidatorBuild,
        }
    }

    fn execution_role(self) -> PositiveRunnerRole {
        match self {
            Self::RustReference => PositiveRunnerRole::RustVerifier,
            Self::IndependentJvm => PositiveRunnerRole::JvmVerifier,
        }
    }
}

/// Canonical finalizer-owned OCI runner role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PositiveRunnerRole {
    /// Rust validator reproducible build.
    RustValidatorBuild,
    /// JVM validator reproducible build.
    JvmValidatorBuild,
    /// Rust verification.
    RustVerifier,
    /// JVM verification.
    JvmVerifier,
}

impl PositiveRunnerRole {
    fn all() -> [Self; 4] {
        [
            Self::RustValidatorBuild,
            Self::JvmValidatorBuild,
            Self::RustVerifier,
            Self::JvmVerifier,
        ]
    }

    fn index(self) -> usize {
        match self {
            Self::RustValidatorBuild => 0,
            Self::JvmValidatorBuild => 1,
            Self::RustVerifier => 2,
            Self::JvmVerifier => 3,
        }
    }

    fn purpose(self) -> &'static str {
        match self {
            Self::RustValidatorBuild => "rust-validator-build",
            Self::JvmValidatorBuild => "jvm-validator-build",
            Self::RustVerifier => "rust-validator",
            Self::JvmVerifier => "jvm-validator",
        }
    }
}

/// Trusted physical measurement of one bounded regular file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileMeasurement {
    /// Exact byte length observed through the trusted finalizer.
    pub byte_length: u64,
    /// SHA-256 of the exact observed bytes.
    pub sha256: [u8; 32],
}

/// Trusted physical measurements of all six verifier-visible cryptographic files.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifierRootMeasurements {
    /// `profile-manifest.bin`.
    pub profile_manifest: FileMeasurement,
    /// `profile-algorithm.txt`.
    pub profile_algorithm: FileMeasurement,
    /// `profile-constants.bin`.
    pub profile_constants: FileMeasurement,
    /// `guest.elf`.
    pub guest_elf: FileMeasurement,
    /// `statement.bin`.
    pub statement: FileMeasurement,
    /// `raw-seal.bin`.
    pub raw_seal: FileMeasurement,
}

/// Exact bytes of all six verifier-visible cryptographic files.
#[derive(Clone, Copy, Debug)]
pub struct VerifierRootContents<'a> {
    /// `profile-manifest.bin`.
    pub profile_manifest: &'a [u8],
    /// `profile-algorithm.txt`.
    pub profile_algorithm: &'a [u8],
    /// `profile-constants.bin`.
    pub profile_constants: &'a [u8],
    /// `guest.elf`.
    pub guest_elf: &'a [u8],
    /// `statement.bin`, which is also the exact receipt journal.
    pub statement: &'a [u8],
    /// `raw-seal.bin`.
    pub raw_seal: &'a [u8],
}

impl VerifierRootContents<'_> {
    fn measurements(self) -> VerifierRootMeasurements {
        VerifierRootMeasurements {
            profile_manifest: measure_bytes(self.profile_manifest),
            profile_algorithm: measure_bytes(self.profile_algorithm),
            profile_constants: measure_bytes(self.profile_constants),
            guest_elf: measure_bytes(self.guest_elf),
            statement: measure_bytes(self.statement),
            raw_seal: measure_bytes(self.raw_seal),
        }
    }
}

/// Canonical documents and caller-supplied measurements for one verifier run.
///
/// The trusted finalizer must perform the execution and no-follow measurement;
/// this value alone does not attest either event.
#[derive(Clone, Copy, Debug)]
pub struct PositiveRunDocuments<'a> {
    /// Case index selected by the finalizer-held case plan.
    pub trusted_case_index: u8,
    /// Implementation selected by the finalizer.
    pub trusted_implementation: PositiveImplementation,
    /// Exact verifier-input JCS bytes supplied to the process.
    pub verifier_input_jcs: &'a [u8],
    /// Exact successful stdout observation bytes.
    pub observation_jcs: &'a [u8],
    /// Exact finalizer-created acceptance bytes.
    pub acceptance_jcs: &'a [u8],
    /// Exact contents of the six verifier-visible files.
    pub verifier_files: VerifierRootContents<'a>,
    /// Physical measurement of the launched native executable or JAR.
    pub launched_artifact: FileMeasurement,
    /// Physical Java launcher measurement, required only for the JVM run.
    pub java_binary: Option<FileMeasurement>,
    /// Physical Java `release` file measurement, required only for the JVM run.
    pub java_release: Option<FileMeasurement>,
}

#[derive(Clone, Debug)]
struct BoundDocument {
    relative_path: String,
    bytes: Vec<u8>,
    value: Value,
    sha256: String,
}

impl BoundDocument {
    fn parse(named: NamedCanonicalJcs<'_>, label: &str) -> Result<Self> {
        ensure!(
            named.bytes.len() <= MAX_PROVENANCE_JCS_BYTES,
            "{label} exceeds the 1 MiB canonical-document bound"
        );
        ensure!(
            !named.relative_path.is_empty(),
            "{label} relative path is empty"
        );
        validate_archive_relative_path(named.relative_path)
            .with_context(|| format!("{label} relative path is not canonical"))?;
        let value = validate_canonical_json_source(named.bytes)
            .with_context(|| format!("{label} is not exact canonical JCS"))?;
        Ok(Self {
            relative_path: named.relative_path.to_owned(),
            bytes: named.bytes.to_vec(),
            value,
            sha256: sha256_hex(named.bytes),
        })
    }

    fn identity_with_path(&self, format: &str) -> Value {
        json!({
            "format": format,
            "path": self.relative_path,
            "byteLength": self.bytes.len(),
            "sha256": self.sha256,
            "encoding": "rfc8785-jcs"
        })
    }

    fn commitment(&self, format: &str) -> Value {
        json!({
            "format": format,
            "byteLength": self.bytes.len(),
            "sha256": self.sha256,
            "encoding": "rfc8785-jcs"
        })
    }

    fn contract_identity(&self) -> B4ContractArtifactIdentityV1 {
        B4ContractArtifactIdentityV1 {
            path: self.relative_path.clone(),
            byte_length: u64::try_from(self.bytes.len())
                .expect("bounded positive-gate document length fits u64"),
            sha256: self.sha256.clone(),
            encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
        }
    }
}

/// Opaque content identity for one profile-bound OCI JSON blob.
///
/// The fields are private and this type has no parser or public constructor.
/// Values originate only in the closed projection retained by
/// [`PositiveGateBindings`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct B4PositiveOciDescriptorV1 {
    digest: [u8; DIGEST_BYTES],
    byte_length: u64,
}

impl B4PositiveOciDescriptorV1 {
    /// SHA-256 payload of the exact `sha256:<hex>` OCI descriptor digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; DIGEST_BYTES] {
        self.digest
    }

    /// Exact descriptor-declared blob byte length.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }
}

/// One ordered layer identity from an authenticated positive runner profile.
///
/// The compressed digest and byte length bind the physical OCI blob. The
/// uncompressed byte length and `DiffID` remain separate inputs for the later
/// gzip and changeset gates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct B4PositiveOciLayerV1 {
    compressed_digest: [u8; DIGEST_BYTES],
    compressed_byte_length: u64,
    uncompressed_byte_length: u64,
    diff_id: [u8; DIGEST_BYTES],
}

impl B4PositiveOciLayerV1 {
    /// SHA-256 of the exact compressed layer blob.
    #[must_use]
    pub const fn compressed_digest(&self) -> [u8; DIGEST_BYTES] {
        self.compressed_digest
    }

    /// Exact compressed layer blob byte length.
    #[must_use]
    pub const fn compressed_byte_length(&self) -> u64 {
        self.compressed_byte_length
    }

    /// Exact profile-declared uncompressed layer byte length.
    #[must_use]
    pub const fn uncompressed_byte_length(&self) -> u64 {
        self.uncompressed_byte_length
    }

    /// SHA-256 `DiffID` of the exact uncompressed layer stream.
    #[must_use]
    pub const fn diff_id(&self) -> [u8; DIGEST_BYTES] {
        self.diff_id
    }
}

/// Closed post-changeset rootfs counts retained for the later layer gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct B4PositiveOciRootfsCountsV1 {
    entry_count: u64,
    regular_file_count: u64,
    directory_count: u64,
    symbolic_link_count: u64,
    regular_file_bytes: u64,
}

impl B4PositiveOciRootfsCountsV1 {
    /// Total post-changeset rootfs entries.
    #[must_use]
    pub const fn entry_count(&self) -> u64 {
        self.entry_count
    }

    /// Total post-changeset regular files.
    #[must_use]
    pub const fn regular_file_count(&self) -> u64 {
        self.regular_file_count
    }

    /// Total post-changeset directories.
    #[must_use]
    pub const fn directory_count(&self) -> u64 {
        self.directory_count
    }

    /// Total post-changeset symbolic links.
    #[must_use]
    pub const fn symbolic_link_count(&self) -> u64 {
        self.symbolic_link_count
    }

    /// Aggregate bytes of all post-changeset regular files.
    #[must_use]
    pub const fn regular_file_bytes(&self) -> u64 {
        self.regular_file_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum B4PositiveRetainedHostRootfsMetadataPolicyKindV1 {
    ClosedObligations,
}

/// Opaque retained-host rootfs metadata-policy expectation for one runner role.
///
/// This value has no public constructor and is deliberately non-serializable.
/// It binds only the closed policy vocabulary selected by the runner profile;
/// it does not prove a filesystem observation, metadata absence, runtime
/// support, mount state, H0 completion, or B4 readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct B4PositiveRetainedHostRootfsMetadataPolicyV1 {
    role: PositiveRunnerRole,
    kind: B4PositiveRetainedHostRootfsMetadataPolicyKindV1,
}

impl B4PositiveRetainedHostRootfsMetadataPolicyV1 {
    /// Canonical runner role to which this policy expectation is bound.
    #[must_use]
    pub const fn role(&self) -> PositiveRunnerRole {
        self.role
    }

    /// Closed retained-host rootfs metadata-policy identifier.
    #[must_use]
    pub const fn policy_id(&self) -> &'static str {
        match self.kind {
            B4PositiveRetainedHostRootfsMetadataPolicyKindV1::ClosedObligations => {
                RETAINED_HOST_ROOTFS_METADATA_POLICY_ID
            }
        }
    }

    /// Closed atomic obligation vocabulary for a later physical producer.
    ///
    /// These identifiers describe prohibited metadata classes only. They do
    /// not attest that any class was observed or absent.
    #[must_use]
    pub const fn obligation_ids(&self) -> [&'static str; 11] {
        RETAINED_HOST_ROOTFS_METADATA_OBLIGATION_IDS
    }

    /// Closed outcome vocabulary reserved for a later physical producer.
    ///
    /// These strings do not classify an observation. Only a separately
    /// versioned, custody-bearing producer may eventually emit an outcome.
    #[must_use]
    pub const fn outcome_ids(&self) -> [&'static str; 6] {
        RETAINED_HOST_ROOTFS_METADATA_OUTCOME_IDS
    }

    /// Sole future outcome which can satisfy this policy.
    ///
    /// Returning this identifier does not attest that the outcome occurred.
    #[must_use]
    pub const fn accepted_outcome_id(&self) -> &'static str {
        "absent"
    }
}

/// Opaque profile-bound identity of one JVM runtime ELF executable.
///
/// The fields are private and this type has no parser or public constructor.
/// Values originate only in the closed runner-profile projection retained by
/// [`PositiveGateBindings`]. Fixed runtime-ELF invariants remain guaranteed by
/// that gate; the retained fields are the variable projection which a later
/// physical rootfs consumer must rederive from the exact measured bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct B4PositiveRuntimeElfIdentityV1 {
    image_path: String,
    byte_length: u64,
    sha256: [u8; DIGEST_BYTES],
    elf_type: String,
    os_abi: String,
    program_header_count: u64,
    section_header_count: u64,
    load_segment_count: u64,
    executable_load_segment_count: u64,
    interpreter_path: String,
    dynamic_entry_count: u64,
    needed_library_count: u64,
    gnu_stack_segment_count: u64,
}

impl B4PositiveRuntimeElfIdentityV1 {
    /// Absolute image-root path of the executable.
    #[must_use]
    pub fn image_path(&self) -> &str {
        &self.image_path
    }

    /// Exact profile-bound executable byte length.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// SHA-256 of the exact profile-bound executable bytes.
    #[must_use]
    pub const fn sha256(&self) -> [u8; DIGEST_BYTES] {
        self.sha256
    }

    /// Profile-bound ELF file type.
    #[must_use]
    pub fn elf_type(&self) -> &str {
        &self.elf_type
    }

    /// Profile-bound ELF OS ABI.
    #[must_use]
    pub fn os_abi(&self) -> &str {
        &self.os_abi
    }

    /// Exact program-header count.
    #[must_use]
    pub const fn program_header_count(&self) -> u64 {
        self.program_header_count
    }

    /// Exact section-header count.
    #[must_use]
    pub const fn section_header_count(&self) -> u64 {
        self.section_header_count
    }

    /// Exact `PT_LOAD` segment count.
    #[must_use]
    pub const fn load_segment_count(&self) -> u64 {
        self.load_segment_count
    }

    /// Exact executable `PT_LOAD` segment count.
    #[must_use]
    pub const fn executable_load_segment_count(&self) -> u64 {
        self.executable_load_segment_count
    }

    /// Canonical absolute `PT_INTERP` path.
    #[must_use]
    pub fn interpreter_path(&self) -> &str {
        &self.interpreter_path
    }

    /// Exact dynamic-table entry count.
    #[must_use]
    pub const fn dynamic_entry_count(&self) -> u64 {
        self.dynamic_entry_count
    }

    /// Exact `DT_NEEDED` entry count.
    #[must_use]
    pub const fn needed_library_count(&self) -> u64 {
        self.needed_library_count
    }

    /// Exact `PT_GNU_STACK` segment count.
    #[must_use]
    pub const fn gnu_stack_segment_count(&self) -> u64 {
        self.gnu_stack_segment_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum B4PositiveStartupDependencyPolicyKindV1 {
    InitialElfClosure,
}

/// Opaque static startup-dependency policy retained for one JVM runner image.
///
/// The private policy kind prevents callers from constructing or widening a
/// policy. Values originate only in the closed runner-profile projection.
/// Copied values are inert expectations, not rootfs, session, publication, or
/// runtime authority; a physical consumer must retain the complete gate-rooted
/// JVM closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct B4PositiveStartupDependencyPolicyV1 {
    kind: B4PositiveStartupDependencyPolicyKindV1,
}

impl B4PositiveStartupDependencyPolicyV1 {
    /// Closed runner-profile policy identifier.
    #[must_use]
    pub const fn policy_id(&self) -> &'static str {
        match self.kind {
            B4PositiveStartupDependencyPolicyKindV1::InitialElfClosure => {
                STARTUP_DEPENDENCY_POLICY_ID
            }
        }
    }
}

/// Opaque JVM executable closure for one canonical positive OCI runner role.
///
/// JVM build images bind both the launcher and compiler. JVM verifier images
/// bind only the launcher. The type has no public constructor. Cloned values
/// remain inert expectations, not session or rootfs authority; the physical
/// consumer must obtain its expectation from the retained gate completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct B4PositiveJvmExecutableClosureV1 {
    startup_dependency_policy: B4PositiveStartupDependencyPolicyV1,
    launcher: B4PositiveRuntimeElfIdentityV1,
    compiler: Option<B4PositiveRuntimeElfIdentityV1>,
}

impl B4PositiveJvmExecutableClosureV1 {
    /// Closed static startup-dependency policy common to every executable in
    /// this profile-level JVM closure.
    #[must_use]
    pub const fn startup_dependency_policy(&self) -> &B4PositiveStartupDependencyPolicyV1 {
        &self.startup_dependency_policy
    }

    /// Profile-bound Java launcher identity.
    #[must_use]
    pub const fn launcher(&self) -> &B4PositiveRuntimeElfIdentityV1 {
        &self.launcher
    }

    /// Profile-bound Java compiler identity, present only for the JVM build
    /// image.
    #[must_use]
    pub const fn compiler(&self) -> Option<&B4PositiveRuntimeElfIdentityV1> {
        self.compiler.as_ref()
    }
}

/// Opaque profile-bound identity of the Java `release` file retained for one
/// JVM runner image.
///
/// The type has no public constructor. Cloned values are inert expectations;
/// they do not carry rootfs, session, or publication authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct B4PositiveJvmReleaseIdentityV1 {
    image_path: String,
    byte_length: u64,
    sha256: [u8; DIGEST_BYTES],
    feature_version: u64,
    vendor: String,
    version: String,
}

impl B4PositiveJvmReleaseIdentityV1 {
    /// Absolute image path of the bound `OpenJDK` release file.
    #[must_use]
    pub fn image_path(&self) -> &str {
        &self.image_path
    }

    /// Exact release-file byte length.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// SHA-256 of the exact release-file bytes.
    #[must_use]
    pub const fn sha256(&self) -> [u8; DIGEST_BYTES] {
        self.sha256
    }

    /// Profile-bound Java feature version.
    #[must_use]
    pub const fn feature_version(&self) -> u64 {
        self.feature_version
    }

    /// Profile-bound value required for `IMPLEMENTOR`.
    #[must_use]
    pub fn vendor(&self) -> &str {
        &self.vendor
    }

    /// Profile-bound value required for `JAVA_VERSION`.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum B4PositiveRuntimeConfigurationPolicyKindV1 {
    ClosedProjection,
}

/// Opaque closed configuration policy for a future OCI runtime consumer.
///
/// This value is an inert profile expectation. It does not represent a
/// generated or validated `config.json`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct B4PositiveRuntimeConfigurationPolicyV1 {
    kind: B4PositiveRuntimeConfigurationPolicyKindV1,
}

impl B4PositiveRuntimeConfigurationPolicyV1 {
    /// Closed semantic configuration-projection policy identifier.
    #[must_use]
    pub const fn policy_id(&self) -> &'static str {
        match self.kind {
            B4PositiveRuntimeConfigurationPolicyKindV1::ClosedProjection => {
                RUNTIME_CONFIGURATION_POLICY_ID
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum B4PositiveRuntimeObservationReservedKindV1 {
    RemainingSelectors,
}

/// Opaque parser contracts and reserved selectors for runtime inputs.
///
/// The state and process-identity members select bounded, purely syntactic
/// parsers. The remaining members carry no parser or observation semantics and
/// retain their reserved identifiers. None of these values proves that `runc`
/// executed, that `/proc` was read, or that two parsed inputs were captured
/// contemporaneously. The type has no public constructor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct B4PositiveRuntimeObservationSelectorsV1 {
    state_contract: B4PositiveRuncStateContractV1,
    process_identity_contract: B4PositiveProcessIdentityContractV1,
    reserved_kind: B4PositiveRuntimeObservationReservedKindV1,
}

impl B4PositiveRuntimeObservationSelectorsV1 {
    /// Bound pure `runc state` parser contract.
    #[must_use]
    pub const fn state_contract(&self) -> &B4PositiveRuncStateContractV1 {
        &self.state_contract
    }

    /// Bound pure process-identity-record parser contract.
    #[must_use]
    pub const fn process_identity_contract(&self) -> &B4PositiveProcessIdentityContractV1 {
        &self.process_identity_contract
    }

    /// Bound `runc state` parser contract identifier.
    #[must_use]
    pub const fn state_selector_id(&self) -> &'static str {
        self.state_contract.contract_id()
    }

    /// Bound process-identity-record parser contract identifier.
    #[must_use]
    pub const fn process_identity_selector_id(&self) -> &'static str {
        self.process_identity_contract.contract_id()
    }

    /// Reserved namespace-identity selector identifier.
    #[must_use]
    pub const fn namespaces_selector_id(&self) -> &'static str {
        match self.reserved_kind {
            B4PositiveRuntimeObservationReservedKindV1::RemainingSelectors => {
                RUNTIME_NAMESPACES_SELECTOR_ID
            }
        }
    }

    /// Reserved UID/GID-mapping selector identifier.
    #[must_use]
    pub const fn id_mappings_selector_id(&self) -> &'static str {
        RUNTIME_ID_MAPPINGS_SELECTOR_ID
    }

    /// Reserved mount-topology selector identifier.
    #[must_use]
    pub const fn mountinfo_selector_id(&self) -> &'static str {
        RUNTIME_MOUNTINFO_SELECTOR_ID
    }

    /// Reserved process-security-status selector identifier.
    #[must_use]
    pub const fn security_status_selector_id(&self) -> &'static str {
        RUNTIME_SECURITY_STATUS_SELECTOR_ID
    }

    /// Reserved cgroup-v2 selector identifier.
    #[must_use]
    pub const fn cgroup_v2_selector_id(&self) -> &'static str {
        RUNTIME_CGROUP_V2_SELECTOR_ID
    }

    /// Reserved process-root-identity selector identifier.
    #[must_use]
    pub const fn root_identity_selector_id(&self) -> &'static str {
        RUNTIME_ROOT_IDENTITY_SELECTOR_ID
    }

    /// Reserved auxiliary-vector selector identifier.
    #[must_use]
    pub const fn auxv_selector_id(&self) -> &'static str {
        RUNTIME_AUXV_SELECTOR_ID
    }

    /// Reserved process-mapping selector identifier.
    #[must_use]
    pub const fn process_mappings_selector_id(&self) -> &'static str {
        RUNTIME_PROCESS_MAPPINGS_SELECTOR_ID
    }

    /// Reserved post-`exec` smoke-identity selector identifier.
    #[must_use]
    pub const fn smoke_identity_selector_id(&self) -> &'static str {
        RUNTIME_SMOKE_IDENTITY_SELECTOR_ID
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum B4PositiveOciRuntimeSpecKindV1 {
    V1_3_0,
}

/// Opaque profile-bound identity of the static `runc` ELF.
///
/// This identity is a future custody expectation only. It does not attest that
/// the file was remeasured, source-reviewed, or executed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct B4PositiveStaticRuntimeElfIdentityV1 {
    relative_path: String,
    byte_length: u64,
    sha256: [u8; DIGEST_BYTES],
    elf_type: String,
    os_abi: String,
    program_header_count: u64,
    section_header_count: u64,
    load_segment_count: u64,
    executable_load_segment_count: u64,
    gnu_stack_segment_count: u64,
}

impl B4PositiveStaticRuntimeElfIdentityV1 {
    /// Canonical campaign/provenance-relative path of the bound runtime binary.
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    /// Exact profile-bound runtime byte length.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// SHA-256 of the exact profile-bound runtime bytes.
    #[must_use]
    pub const fn sha256(&self) -> [u8; DIGEST_BYTES] {
        self.sha256
    }

    /// Profile-bound ELF file type.
    #[must_use]
    pub fn elf_type(&self) -> &str {
        &self.elf_type
    }

    /// Profile-bound ELF OS ABI.
    #[must_use]
    pub fn os_abi(&self) -> &str {
        &self.os_abi
    }

    /// Exact program-header count.
    #[must_use]
    pub const fn program_header_count(&self) -> u64 {
        self.program_header_count
    }

    /// Exact section-header count.
    #[must_use]
    pub const fn section_header_count(&self) -> u64 {
        self.section_header_count
    }

    /// Exact `PT_LOAD` segment count.
    #[must_use]
    pub const fn load_segment_count(&self) -> u64 {
        self.load_segment_count
    }

    /// Exact executable `PT_LOAD` segment count.
    #[must_use]
    pub const fn executable_load_segment_count(&self) -> u64 {
        self.executable_load_segment_count
    }

    /// Exact `PT_GNU_STACK` segment count.
    #[must_use]
    pub const fn gnu_stack_segment_count(&self) -> u64 {
        self.gnu_stack_segment_count
    }
}

/// Opaque runtime contract retained with one canonical OCI role.
///
/// It binds only profile expectations. It confers no command, process,
/// namespace, rootfs, observation, completion, or publication authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct B4PositiveOciRuntimeContractV1 {
    role: PositiveRunnerRole,
    version: String,
    runtime_spec: B4PositiveOciRuntimeSpecKindV1,
    binary: B4PositiveStaticRuntimeElfIdentityV1,
    configuration_policy: B4PositiveRuntimeConfigurationPolicyV1,
    observation_selectors: B4PositiveRuntimeObservationSelectorsV1,
}

impl B4PositiveOciRuntimeContractV1 {
    /// Canonical role to which this runtime contract remains attached.
    #[must_use]
    pub const fn role(&self) -> PositiveRunnerRole {
        self.role
    }

    /// Profile-bound `runc` implementation version.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Pinned OCI Runtime Specification version.
    #[must_use]
    pub const fn runtime_spec_version(&self) -> &'static str {
        match self.runtime_spec {
            B4PositiveOciRuntimeSpecKindV1::V1_3_0 => "1.3.0",
        }
    }

    /// Pinned OCI Runtime Specification Git commit.
    #[must_use]
    pub const fn runtime_spec_commit(&self) -> &'static str {
        match self.runtime_spec {
            B4PositiveOciRuntimeSpecKindV1::V1_3_0 => "92249139eea7161e13745abd4cb6d0ea02a3227a",
        }
    }

    /// Bound static runtime binary expectation.
    #[must_use]
    pub const fn binary(&self) -> &B4PositiveStaticRuntimeElfIdentityV1 {
        &self.binary
    }

    /// Closed semantic configuration-projection policy.
    #[must_use]
    pub const fn configuration_policy(&self) -> &B4PositiveRuntimeConfigurationPolicyV1 {
        &self.configuration_policy
    }

    /// Runtime parser contracts and remaining reserved selector set.
    #[must_use]
    pub const fn observation_selectors(&self) -> &B4PositiveRuntimeObservationSelectorsV1 {
        &self.observation_selectors
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum B4PositiveRootfsPathKindV1 {
    Directory,
    EmptyRegular,
}

/// Opaque physical path prerequisite for one positive OCI rootfs.
///
/// This is a pre-launch rootfs expectation, not a mount instruction. In
/// particular `/dev` is retained as an inventory anchor while only its five
/// fixed children are future pseudodevice mount targets. The type has no
/// public constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct B4PositiveRootfsPathRequirementV1 {
    image_path: String,
    kind: B4PositiveRootfsPathKindV1,
}

impl B4PositiveRootfsPathRequirementV1 {
    /// Absolute path required in the authenticated rootfs.
    #[must_use]
    pub fn image_path(&self) -> &str {
        &self.image_path
    }

    /// Whether the path must be a sealed directory.
    #[must_use]
    pub const fn requires_directory(&self) -> bool {
        matches!(self.kind, B4PositiveRootfsPathKindV1::Directory)
    }

    /// Whether the path must be an empty regular-file placeholder.
    #[must_use]
    pub const fn requires_empty_regular(&self) -> bool {
        matches!(self.kind, B4PositiveRootfsPathKindV1::EmptyRegular)
    }
}

/// Opaque OCI image-layout projection for one canonical positive runner role.
///
/// The type is deliberately non-serializable and has no public constructor.
/// It carries only fixed identities and counts extracted after the complete
/// runner-profile schema and cross-document gate succeeds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct B4PositiveOciImageLayoutV1 {
    role: PositiveRunnerRole,
    runtime_contract: B4PositiveOciRuntimeContractV1,
    retained_host_rootfs_metadata_policy: B4PositiveRetainedHostRootfsMetadataPolicyV1,
    archive_path: String,
    archive_byte_length: u64,
    archive_sha256: [u8; DIGEST_BYTES],
    manifest: B4PositiveOciDescriptorV1,
    config: B4PositiveOciDescriptorV1,
    layers: Vec<B4PositiveOciLayerV1>,
    post_changeset_rootfs: B4PositiveOciRootfsCountsV1,
    jvm_executables: Option<B4PositiveJvmExecutableClosureV1>,
    jvm_release: Option<B4PositiveJvmReleaseIdentityV1>,
    rootfs_path_requirements: Vec<B4PositiveRootfsPathRequirementV1>,
}

impl B4PositiveOciImageLayoutV1 {
    /// Canonical finalizer-owned role for this image.
    #[must_use]
    pub const fn role(&self) -> PositiveRunnerRole {
        self.role
    }

    /// Closed runtime expectation retained with this exact image role.
    ///
    /// This token is non-authorizing and does not attest any generated bundle,
    /// runtime invocation, process, or kernel observation.
    #[must_use]
    pub const fn runtime_contract(&self) -> &B4PositiveOciRuntimeContractV1 {
        &self.runtime_contract
    }

    /// Closed retained-host rootfs metadata-policy expectation for this role.
    ///
    /// This token is non-authorizing and does not attest any physical metadata
    /// observation, filesystem support, mount, runtime, H0, or B4 outcome.
    #[must_use]
    pub const fn retained_host_rootfs_metadata_policy(
        &self,
    ) -> &B4PositiveRetainedHostRootfsMetadataPolicyV1 {
        &self.retained_host_rootfs_metadata_policy
    }

    /// Canonical archive-relative path of the image-layout ustar.
    #[must_use]
    pub fn archive_path(&self) -> &str {
        &self.archive_path
    }

    /// Exact authenticated archive byte length.
    #[must_use]
    pub const fn archive_byte_length(&self) -> u64 {
        self.archive_byte_length
    }

    /// SHA-256 of the exact authenticated archive bytes.
    #[must_use]
    pub const fn archive_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.archive_sha256
    }

    /// Closed manifest descriptor identity.
    #[must_use]
    pub const fn manifest(&self) -> &B4PositiveOciDescriptorV1 {
        &self.manifest
    }

    /// Closed config descriptor identity.
    #[must_use]
    pub const fn config(&self) -> &B4PositiveOciDescriptorV1 {
        &self.config
    }

    /// Ordered layer identities exactly as committed by the runner profile.
    #[must_use]
    pub fn layers(&self) -> &[B4PositiveOciLayerV1] {
        &self.layers
    }

    /// Closed post-changeset rootfs counts for the later layer gate.
    #[must_use]
    pub const fn post_changeset_rootfs(&self) -> &B4PositiveOciRootfsCountsV1 {
        &self.post_changeset_rootfs
    }

    /// Closed JVM executable identities for this image, if it is a JVM role.
    ///
    /// The JVM build role retains the launcher and compiler; the JVM verifier
    /// role retains only the launcher. Native Rust roles return `None`.
    #[must_use]
    pub const fn jvm_executables(&self) -> Option<&B4PositiveJvmExecutableClosureV1> {
        self.jvm_executables.as_ref()
    }

    /// Closed Java release-file identity for this image, if it is a JVM role.
    #[must_use]
    pub const fn jvm_release(&self) -> Option<&B4PositiveJvmReleaseIdentityV1> {
        self.jvm_release.as_ref()
    }

    /// Sorted union of physical rootfs paths required before any role phase.
    ///
    /// These values describe the retained rootfs only. They do not merge the
    /// application and packaging launch configurations and are not authority
    /// to create mounts or devices.
    #[must_use]
    pub fn rootfs_path_requirements(&self) -> &[B4PositiveRootfsPathRequirementV1] {
        &self.rootfs_path_requirements
    }
}

/// Validated, immutable positive-gate provenance bindings.
#[derive(Debug)]
pub struct PositiveGateBindings {
    input_set: BoundDocument,
    verifier_contract: BoundDocument,
    runner_profiles: [BoundDocument; 4],
    seccomp_profiles: [BoundDocument; 4],
    validator_descriptors: [BoundDocument; 2],
    jvm_copy_only_inclusion_manifest: BoundDocument,
    provenance_paths: BTreeSet<String>,
    provenance_sha256: BTreeMap<String, String>,
    campaign_precommit_authority: B4PositiveGateAuthorityV1,
    oci_image_layouts: [B4PositiveOciImageLayoutV1; 4],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct B4PositiveProvenanceClosureV1 {
    paths: BTreeSet<String>,
    sha256_by_path: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BoundGenerationCase {
    proof_output_manifest: FileMeasurement,
    raw_seal: FileMeasurement,
}

/// Opaque, immutable identity of one generation-bound positive export.
///
/// The fields are private and the type has no parser or public constructor.
/// Values can only be projected from a successfully bound generation set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct B4PositiveGenerationCaseAuthorityV1 {
    case_index: u8,
    proof_output_manifest: FileMeasurement,
    raw_seal: FileMeasurement,
}

impl B4PositiveGenerationCaseAuthorityV1 {
    /// Exact zero-based position in the closed eleven-case plan.
    #[must_use]
    pub const fn case_index(&self) -> u8 {
        self.case_index
    }

    /// Exact physical proof-output-manifest measurement.
    #[must_use]
    pub const fn proof_output_manifest(&self) -> FileMeasurement {
        self.proof_output_manifest
    }

    /// Exact physical raw-seal measurement.
    #[must_use]
    pub const fn raw_seal(&self) -> FileMeasurement {
        self.raw_seal
    }
}

/// Opaque post-proof authority emitted only by the positive generation gate.
///
/// This is a non-serializable projection, not a candidate document. It binds
/// the exact canonical input and generation sets, all eleven independently
/// measured proof-output manifests and raw seals, and the complete pre-proof
/// provenance path closure. There is no parser or caller-supplied constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct B4PositiveGenerationAuthorityV1 {
    input_set: B4ContractArtifactIdentityV1,
    generation_set: B4ContractArtifactIdentityV1,
    cases: [B4PositiveGenerationCaseAuthorityV1; POSITIVE_CASE_COUNT],
    provenance_paths: BTreeSet<String>,
    provenance_sha256: BTreeMap<String, String>,
}

impl B4PositiveGenerationAuthorityV1 {
    /// Exact canonical positive input-set identity.
    #[must_use]
    pub fn input_set(&self) -> &B4ContractArtifactIdentityV1 {
        &self.input_set
    }

    /// Exact canonical positive generation-set identity.
    #[must_use]
    pub fn generation_set(&self) -> &B4ContractArtifactIdentityV1 {
        &self.generation_set
    }

    /// Exact ordered eleven-case physical export projection.
    #[must_use]
    pub fn cases(&self) -> &[B4PositiveGenerationCaseAuthorityV1; POSITIVE_CASE_COUNT] {
        &self.cases
    }

    /// Complete ancestry-safe pre-proof and generation-set path closure.
    #[must_use]
    pub fn provenance_paths(&self) -> &BTreeSet<String> {
        &self.provenance_paths
    }

    #[must_use]
    pub(crate) fn provenance_sha256(&self) -> &BTreeMap<String, String> {
        &self.provenance_sha256
    }
}

/// Validated post-proof bindings for the complete eleven-case generator
/// export set. Verifier execution is unavailable until this phase succeeds.
#[derive(Debug)]
pub struct PositiveGenerationBindings {
    provenance: PositiveGateBindings,
    generation_set: BoundDocument,
    cases: [BoundGenerationCase; 11],
    generation_authority: B4PositiveGenerationAuthorityV1,
}

/// One semantically validated implementation-specific positive-run record.
///
/// This token proves the semantic bindings checked by this module. It is not an
/// independent execution attestation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPositiveRun {
    case_index: u8,
    implementation: PositiveImplementation,
    input_set_sha256: [u8; DIGEST_BYTES],
    generation_set_sha256: [u8; DIGEST_BYTES],
    proof_output_manifest_sha256: [u8; DIGEST_BYTES],
    raw_seal_sha256: [u8; DIGEST_BYTES],
    acceptance_sha256: [u8; DIGEST_BYTES],
    verifier_input_jcs: Vec<u8>,
    observation_jcs: Vec<u8>,
}

/// One exact Rust/JVM agreement pair, suitable for the eleven-case aggregate
/// completeness gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedDifferentialPair {
    case_index: u8,
    input_set_sha256: [u8; DIGEST_BYTES],
    generation_set_sha256: [u8; DIGEST_BYTES],
    proof_output_manifest_sha256: [u8; DIGEST_BYTES],
    raw_seal_sha256: [u8; DIGEST_BYTES],
    rust_acceptance_sha256: [u8; DIGEST_BYTES],
    jvm_acceptance_sha256: [u8; DIGEST_BYTES],
}

/// Semantic completion token proving that the supplied Rust and JVM records
/// agree on all eleven generation-bound positive cases exactly once and in
/// order.
///
/// It does not attest OCI execution or generator replay and cannot substitute
/// for the future finalizer-executor completion type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticallyValidatedPositiveSuite {
    input_set_sha256: [u8; DIGEST_BYTES],
    generation_set_sha256: [u8; DIGEST_BYTES],
    acceptance_sha256s: [[u8; DIGEST_BYTES]; POSITIVE_ACCEPTANCE_COUNT],
}

impl SemanticallyValidatedPositiveSuite {
    /// SHA-256 of the exact canonical pre-proof input set.
    #[must_use]
    pub const fn input_set_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.input_set_sha256
    }

    /// SHA-256 of the exact canonical post-proof generation set.
    #[must_use]
    pub const fn generation_set_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.generation_set_sha256
    }

    /// SHA-256 values of the exact acceptance bytes in
    /// `(case-0 Rust, case-0 JVM, ..., case-10 Rust, case-10 JVM)` order.
    #[must_use]
    pub const fn acceptance_sha256s(&self) -> &[[u8; DIGEST_BYTES]; POSITIVE_ACCEPTANCE_COUNT] {
        &self.acceptance_sha256s
    }
}

impl PositiveGateBindings {
    /// Validate the pre-proof JCS documents against their exact embedded Draft
    /// 2020-12 schemas, then enforce every cross-document relationship which
    /// JSON Schema cannot express.
    ///
    /// # Errors
    ///
    /// Returns an error for noncanonical bytes, stale commitments, role drift,
    /// ambiguous inventories, descriptor-selected policy, authoritative-build
    /// drift, or lost validator metadata separation.
    #[allow(clippy::too_many_lines)]
    pub fn validate_and_bind_jcs(documents: PositiveProvenanceDocuments<'_>) -> Result<Self> {
        let input_set = BoundDocument::parse(documents.input_set, "positive input set")?;
        validate_json_schema(
            &input_set.value,
            EmbeddedSchema::InputSet,
            "positive input set",
        )?;
        require_format(&input_set.value, "Eip0045B4PositiveInputSetV1", 1)?;
        validate_authoritative_build_projection(&input_set.value, documents.authoritative_build)?;

        let verifier_contract =
            BoundDocument::parse(documents.verifier_contract, "B4 verifier contract")?;
        let parsed_verifier_contract =
            Eip0045B4VerifierContractV1::from_canonical_jcs(&verifier_contract.bytes)?;
        ensure!(
            field(&input_set.value, "verifierCliContract")?
                == &verifier_contract.identity_with_path("Eip0045B4VerifierContractV1"),
            "input-set verifier-contract identity is stale"
        );

        let seccomp_profiles: [BoundDocument; 4] = documents
            .seccomp_profiles
            .into_iter()
            .enumerate()
            .map(|(index, named)| {
                let role = PositiveRunnerRole::all()[index];
                let document =
                    BoundDocument::parse(named, &format!("{} seccomp profile", role.purpose()))?;
                validate_json_schema(
                    &document.value,
                    EmbeddedSchema::Seccomp,
                    &format!("{} seccomp profile", role.purpose()),
                )?;
                validate_seccomp_document(&document.value, role.purpose())?;
                Ok(document)
            })
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("seccomp-profile cardinality drift"))?;

        let runner_profiles: [BoundDocument; 4] = documents
            .runner_profiles
            .into_iter()
            .enumerate()
            .map(|(index, named)| {
                let role = PositiveRunnerRole::all()[index];
                let document = BoundDocument::parse(named, role.purpose())?;
                validate_json_schema(
                    &document.value,
                    EmbeddedSchema::RunnerProfile,
                    role.purpose(),
                )?;
                require_format(&document.value, "Eip0045B4PositiveOciRunnerProfileV1", 1)?;
                require_role(&document.value, role, "runner profile")?;
                validate_runner_profile(&document.value, role.purpose())?;
                validate_seccomp_binding(
                    &document.value,
                    &seccomp_profiles[index],
                    role.purpose(),
                )?;
                if role == PositiveRunnerRole::JvmVerifier {
                    validate_jvm_options(&document.value)?;
                }
                Ok(document)
            })
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("runner-profile cardinality drift"))?;
        let oci_image_layouts: [B4PositiveOciImageLayoutV1; 4] = runner_profiles
            .iter()
            .enumerate()
            .map(|(index, profile)| {
                project_positive_oci_image_layout(profile, PositiveRunnerRole::all()[index])
            })
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("OCI image-layout projection cardinality drift"))?;

        let input_profiles = array_field(&input_set.value, "runnerProfiles")?;
        ensure!(
            input_profiles.len() == 4,
            "input set must bind exactly four runner profiles"
        );
        for (index, role) in PositiveRunnerRole::all().into_iter().enumerate() {
            require_role(&input_profiles[index], role, "input-set runner profile")?;
            let expected =
                runner_profiles[index].identity_with_path("Eip0045B4PositiveOciRunnerProfileV1");
            ensure!(
                field(&input_profiles[index], "artifact")? == &expected,
                "input-set {} runner-profile identity is stale",
                role.purpose()
            );
        }

        let validator_descriptors: [BoundDocument; 2] = documents
            .validator_descriptors
            .into_iter()
            .enumerate()
            .map(|(index, named)| {
                let implementation = if index == 0 {
                    PositiveImplementation::RustReference
                } else {
                    PositiveImplementation::IndependentJvm
                };
                let descriptor = BoundDocument::parse(named, implementation.implementation())?;
                validate_json_schema(
                    &descriptor.value,
                    EmbeddedSchema::ValidatorDescriptor,
                    implementation.implementation(),
                )?;
                require_format(&descriptor.value, "Eip0045B4ValidatorBuildDescriptorV1", 1)?;
                require_string_eq(
                    &descriptor.value,
                    "implementation",
                    implementation.implementation(),
                )?;
                require_string_eq(
                    &descriptor.value,
                    "implementationLanguage",
                    implementation.language(),
                )?;
                validate_descriptor(&descriptor.value, implementation, &runner_profiles)?;
                Ok(descriptor)
            })
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("validator-descriptor cardinality drift"))?;

        let jvm_copy_only_inclusion_manifest = BoundDocument::parse(
            documents.jvm_copy_only_inclusion_manifest,
            "JVM COPY-ONLY inclusion manifest",
        )?;
        validate_json_schema(
            &jvm_copy_only_inclusion_manifest.value,
            EmbeddedSchema::JvmCopyOnlyInclusionManifest,
            "JVM COPY-ONLY inclusion manifest",
        )?;
        require_format(
            &jvm_copy_only_inclusion_manifest.value,
            "Eip0045B4JvmCopyOnlyInclusionManifestV1",
            1,
        )?;
        validate_jvm_copy_only_inclusion_manifest(
            &jvm_copy_only_inclusion_manifest,
            &validator_descriptors[1].value,
        )?;

        let validators = array_field(&input_set.value, "validators")?;
        ensure!(
            validators.len() == 2,
            "input set must bind exactly two validators"
        );
        for (index, implementation) in [
            PositiveImplementation::RustReference,
            PositiveImplementation::IndependentJvm,
        ]
        .into_iter()
        .enumerate()
        {
            require_u64_eq(&validators[index], "implementationIndex", index as u64)?;
            require_string_eq(
                &validators[index],
                "implementation",
                implementation.implementation(),
            )?;
            require_string_eq(&validators[index], "language", implementation.language())?;
            let expected = validator_descriptors[index]
                .identity_with_path("Eip0045B4ValidatorBuildDescriptorV1");
            ensure!(
                field(&validators[index], "buildDescriptor")? == &expected,
                "input-set validator descriptor identity is stale for {}",
                implementation.implementation()
            );
        }

        validate_non_alias_lineage_separation(&validator_descriptors)?;
        let provenance_closure = validate_provenance_closure(
            &input_set,
            &runner_profiles,
            &seccomp_profiles,
            &validator_descriptors,
        )?;
        let provenance_paths = provenance_closure.paths;
        ensure!(
            provenance_paths.contains(&jvm_copy_only_inclusion_manifest.relative_path),
            "JVM COPY-ONLY inclusion-manifest path is absent from provenance"
        );
        ensure!(
            provenance_paths.contains(&verifier_contract.relative_path),
            "verifier-contract path is absent from provenance"
        );

        let campaign_precommit_authority = build_campaign_precommit_authority(
            &input_set,
            &verifier_contract,
            &parsed_verifier_contract,
            &validator_descriptors,
            &runner_profiles,
            &seccomp_profiles,
            &jvm_copy_only_inclusion_manifest,
            &provenance_paths,
        )?;

        Ok(Self {
            input_set,
            verifier_contract,
            runner_profiles,
            seccomp_profiles,
            validator_descriptors,
            jvm_copy_only_inclusion_manifest,
            provenance_paths,
            provenance_sha256: provenance_closure.sha256_by_path,
            campaign_precommit_authority,
            oci_image_layouts,
        })
    }

    /// Opaque pre-proof projection consumed by the campaign-precommit closure.
    ///
    /// The returned token can only originate from this successful positive
    /// cross-document gate. Historical review independence remains finalizer
    /// custody evidence.
    #[must_use]
    pub fn campaign_precommit_authority(&self) -> B4PositiveGateAuthorityV1 {
        self.campaign_precommit_authority.clone()
    }

    /// Exact four-role OCI image-layout projection in canonical runner order.
    ///
    /// The array order is Rust build, JVM build, Rust verifier, JVM verifier.
    /// Its values are retained during successful gate binding and cannot be
    /// supplied or parsed independently by a caller.
    #[must_use]
    pub const fn oci_image_layouts(&self) -> &[B4PositiveOciImageLayoutV1; 4] {
        &self.oci_image_layouts
    }

    /// Crate-private pathful identity used to derive the H0 completion witness.
    ///
    /// This projection is deliberately unavailable to callers: the public
    /// completion API accepts this opaque gate rather than a detached identity.
    #[must_use]
    pub(crate) fn input_set_contract_identity(&self) -> B4ContractArtifactIdentityV1 {
        self.input_set.contract_identity()
    }

    /// Exact canonical positive input-set bytes retained by this gate.
    #[must_use]
    pub(crate) fn input_set_jcs(&self) -> &[u8] {
        &self.input_set.bytes
    }

    pub(crate) fn require_nonprovenance_completion_path(&self, candidate: &str) -> Result<()> {
        validate_safe_relative_path(candidate)
            .context("invalid positive input-set completion path")?;
        ensure!(
            !self
                .provenance_paths
                .iter()
                .any(|path| b4_paths_conflict(path, candidate)),
            "positive input-set completion path aliases or ancestor/descendant-conflicts with positive provenance"
        );
        Ok(())
    }

    /// Exact canonical verifier-contract bytes retained by this gate.
    #[must_use]
    pub fn verifier_contract_jcs(&self) -> &[u8] {
        &self.verifier_contract.bytes
    }

    /// Exact canonical seccomp-profile bytes retained for one closed runner
    /// role.
    #[must_use]
    pub fn seccomp_profile_jcs(&self, role: PositiveRunnerRole) -> &[u8] {
        &self.seccomp_profiles[role.index()].bytes
    }

    /// Exact canonical JVM COPY-ONLY inclusion-manifest bytes retained by this
    /// gate.
    #[must_use]
    pub fn jvm_copy_only_inclusion_manifest_jcs(&self) -> &[u8] {
        &self.jvm_copy_only_inclusion_manifest.bytes
    }

    /// Bind the finalizer-created post-proof projection before any verifier
    /// acceptance can be validated.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale pre-proof root, proof-generator drift,
    /// case-plan drift, malformed embedded digests, calibration drift, reused
    /// proof manifests or reused raw seals.
    pub fn bind_generation_set(
        self,
        documents: PositiveGenerationDocuments<'_>,
    ) -> Result<PositiveGenerationBindings> {
        let generation_set =
            BoundDocument::parse(documents.generation_set, "positive generation set")?;
        validate_json_schema(
            &generation_set.value,
            EmbeddedSchema::GenerationSet,
            "positive generation set",
        )?;
        require_format(&generation_set.value, "Eip0045B4PositiveGenerationSetV1", 1)?;
        ensure!(
            !self.provenance_paths.iter().any(|path| {
                b4_paths_conflict(path.as_str(), generation_set.relative_path.as_str())
            }),
            "generation-set path aliases or ancestor/descendant-conflicts with a pre-proof provenance document"
        );
        ensure!(
            field(&generation_set.value, "inputSetCommitment")?
                == &self.input_set.commitment("Eip0045B4PositiveInputSetV1"),
            "generation-set input-set commitment is stale"
        );
        ensure!(
            field(&generation_set.value, "proofGeneratorArtifact")?
                == &binary_commitment(field(
                    field(&self.input_set.value, "proofGenerator")?,
                    "artifact",
                )?)?,
            "generation-set proof-generator artifact binding is stale"
        );
        validate_measurement(
            field(field(&self.input_set.value, "proofGenerator")?, "artifact")?,
            &measure_bytes(documents.proof_generator_artifact),
            "proof generator artifact",
        )?;

        let planned_cases = array_field(&self.input_set.value, "positiveCases")?;
        let generated_cases = array_field(&generation_set.value, "cases")?;
        ensure!(
            planned_cases.len() == 11 && generated_cases.len() == 11,
            "positive generation set must bind exactly eleven planned cases"
        );
        let calibrations = array_field(&self.input_set.value, "recursiveCalibrations")?;
        ensure!(
            calibrations.len() == 3,
            "pre-proof input set must bind exactly three recursive calibrations"
        );

        let mut manifest_digests = BTreeSet::new();
        let mut raw_seal_digests = BTreeSet::new();
        let cases: [BoundGenerationCase; 11] = planned_cases
            .iter()
            .zip(generated_cases)
            .zip(documents.cases)
            .enumerate()
            .map(|(index, ((planned, generated), physical))| {
                let bound = validate_generation_case(
                    index,
                    planned,
                    generated,
                    physical,
                    &self.input_set.value,
                )?;
                ensure!(
                    manifest_digests.insert(bound.proof_output_manifest.sha256),
                    "positive generation set reuses a proof-output manifest digest"
                );
                ensure!(
                    raw_seal_digests.insert(bound.raw_seal.sha256),
                    "positive generation set reuses a raw-seal digest"
                );
                Ok(bound)
            })
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("positive generation-set cardinality drift"))?;

        let generation_authority =
            build_positive_generation_authority(&self, &generation_set, &cases)?;
        Ok(PositiveGenerationBindings {
            provenance: self,
            generation_set,
            cases,
            generation_authority,
        })
    }

    fn validate_implementation_binding(
        &self,
        binding: &Value,
        implementation: PositiveImplementation,
        launched_artifact: &FileMeasurement,
        java_binary: Option<&FileMeasurement>,
        java_release: Option<&FileMeasurement>,
    ) -> Result<()> {
        let index = implementation.index();
        let descriptor = &self.validator_descriptors[index];
        let descriptor_value = &descriptor.value;
        require_u64_eq(binding, "implementationIndex", index as u64)?;
        require_string_eq(binding, "implementation", implementation.implementation())?;
        require_string_eq(binding, "language", implementation.language())?;
        ensure!(
            field(binding, "lineageSha256")?
                == field(
                    field(descriptor_value, "implementationLineage")?,
                    "lineageSha256"
                )?,
            "acceptance lineage binding is stale"
        );
        ensure!(
            field(binding, "reviewedSource")?
                == &reviewed_source_projection(field(descriptor_value, "reviewedSource")?)?,
            "acceptance reviewed-source binding is stale"
        );
        ensure!(
            field(binding, "buildDescriptor")?
                == &descriptor.commitment("Eip0045B4ValidatorBuildDescriptorV1"),
            "acceptance descriptor commitment is stale"
        );

        let descriptor_artifact = field(descriptor_value, "artifact")?;
        validate_measurement(descriptor_artifact, launched_artifact, "launched artifact")?;
        ensure!(
            field(binding, "launchedArtifact")? == &binary_commitment(descriptor_artifact)?,
            "acceptance launched-artifact binding is stale"
        );

        let role = implementation.execution_role();
        let profile = &self.runner_profiles[role.index()];
        let runner_binding = field(binding, "executionRunnerProfile")?;
        require_role(runner_binding, role, "acceptance execution runner")?;
        ensure!(
            field(runner_binding, "artifact")?
                == &profile.commitment("Eip0045B4PositiveOciRunnerProfileV1"),
            "acceptance execution-runner commitment is stale"
        );

        match implementation {
            PositiveImplementation::RustReference => {
                ensure!(
                    java_binary.is_none() && java_release.is_none(),
                    "Rust acceptance cannot carry Java measurements"
                );
                ensure!(
                    object(binding, "Rust acceptance binding")?
                        .get("javaRuntime")
                        .is_none(),
                    "Rust acceptance cannot carry a Java runtime"
                );
            }
            PositiveImplementation::IndependentJvm => {
                let measured_java = java_binary.context("JVM run lacks Java measurement")?;
                let measured_release =
                    java_release.context("JVM run lacks Java release measurement")?;
                let profile_java = field(&profile.value, "javaRuntime")?;
                validate_measurement(field(profile_java, "binary")?, measured_java, "Java binary")?;
                validate_measurement(
                    field(profile_java, "release")?,
                    measured_release,
                    "Java release",
                )?;
                ensure!(
                    field(binding, "javaRuntime")? == &java_runtime_projection(profile_java)?,
                    "acceptance Java runtime binding is stale"
                );
            }
        }
        Ok(())
    }
}

/// Validate the complete pre-proof V2 semantic closure and mint its affine
/// campaign-precommit authority.
///
/// This gate deliberately retains the reviewed V1 wire identities for the
/// verifier contract, seccomp documents, JVM inclusion manifest, and campaign
/// precommit. It does not accept any V1 positive input, runner profile, or
/// validator descriptor, and it does not construct an H0 source or a
/// post-proof generation authority.
///
/// # Errors
///
/// Returns an error for a noncanonical or wrong-version document, stale direct
/// identity, role/order drift, seccomp or JVM packaging mismatch, authoritative
/// build drift, provenance alias, or incomplete path/digest closure.
#[allow(clippy::too_many_lines)]
pub fn validate_and_bind_positive_precommit_v2(
    authoritative_build: &AuthoritativeB4BuildProjection,
    documents: B4PositivePrecommitDocumentsV2<'_>,
) -> Result<B4PositivePrecommitAuthorityV2> {
    let V2InputIdentityBindings {
        input_set,
        runner_profiles,
        validator_descriptors,
    } = bind_v2_input_identity_closure(
        authoritative_build,
        documents.input_set,
        documents.runner_profiles,
        documents.validator_descriptors,
    )?;

    let verifier_contract = BoundDocument::parse(
        documents.verifier_contract,
        "V2 precommit verifier contract",
    )?;
    let parsed_verifier_contract =
        Eip0045B4VerifierContractV1::from_canonical_jcs(&verifier_contract.bytes)?;
    ensure!(
        field(&input_set.value, "verifierCliContract")?
            == &verifier_contract.identity_with_path("Eip0045B4VerifierContractV1"),
        "V2 input-set verifier-contract identity is stale"
    );

    let seccomp_documents: [BoundDocument; 4] = documents
        .seccomp_documents
        .into_iter()
        .enumerate()
        .map(|(index, named)| {
            let role = PositiveRunnerRole::all()[index];
            let label = format!("V2 precommit {} seccomp profile", role.purpose());
            let document = BoundDocument::parse(named, &label)?;
            validate_json_schema(&document.value, EmbeddedSchema::Seccomp, &label)?;
            validate_seccomp_document(&document.value, role.purpose())?;
            validate_seccomp_binding(&runner_profiles[index].value, &document, role.purpose())?;
            Ok(document)
        })
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("V2 precommit seccomp cardinality drift"))?;
    validate_jvm_options(&runner_profiles[PositiveRunnerRole::JvmVerifier.index()].value)?;

    let jvm_copy_only_inclusion_manifest = BoundDocument::parse(
        documents.jvm_copy_only_inclusion_manifest,
        "V2 precommit JVM COPY-ONLY inclusion manifest",
    )?;
    validate_json_schema(
        &jvm_copy_only_inclusion_manifest.value,
        EmbeddedSchema::JvmCopyOnlyInclusionManifest,
        "V2 precommit JVM COPY-ONLY inclusion manifest",
    )?;
    require_format(
        &jvm_copy_only_inclusion_manifest.value,
        "Eip0045B4JvmCopyOnlyInclusionManifestV1",
        1,
    )?;
    validate_jvm_copy_only_inclusion_manifest(
        &jvm_copy_only_inclusion_manifest,
        &validator_descriptors[PositiveImplementation::IndependentJvm.index()].value,
    )?;

    let provenance_closure = validate_provenance_closure(
        &input_set,
        &runner_profiles,
        &seccomp_documents,
        &validator_descriptors,
    )?;
    ensure!(
        provenance_closure
            .paths
            .contains(&jvm_copy_only_inclusion_manifest.relative_path),
        "V2 precommit JVM COPY-ONLY inclusion-manifest path is absent from provenance"
    );
    ensure!(
        provenance_closure
            .paths
            .contains(&verifier_contract.relative_path),
        "V2 precommit verifier-contract path is absent from provenance"
    );

    build_positive_precommit_authority_v2(
        &input_set,
        &verifier_contract,
        &parsed_verifier_contract,
        &validator_descriptors,
        &runner_profiles,
        &seccomp_documents,
        &jvm_copy_only_inclusion_manifest,
        &provenance_closure.paths,
    )
}

impl PositiveGenerationBindings {
    /// Opaque post-proof projection consumed by later materialization phases.
    ///
    /// The returned value is a snapshot created inside
    /// [`PositiveGateBindings::bind_generation_set`] only after all eleven
    /// physical exports and their canonical generation document were
    /// cross-bound successfully.
    #[must_use]
    pub fn positive_generation_authority(&self) -> B4PositiveGenerationAuthorityV1 {
        self.generation_authority.clone()
    }

    /// Validate one physical verifier run and its finalizer-created acceptance.
    ///
    /// # Errors
    ///
    /// Returns an error for authority-surface drift, physical identity drift,
    /// stale acceptance projections, or disagreement with the independent
    /// semantic derivation.
    #[allow(clippy::too_many_lines)]
    pub fn validate_run(
        &self,
        documents: PositiveRunDocuments<'_>,
    ) -> Result<ValidatedPositiveRun> {
        for (label, bytes) in [
            ("verifier input", documents.verifier_input_jcs),
            ("observation", documents.observation_jcs),
            ("acceptance", documents.acceptance_jcs),
        ] {
            ensure!(
                bytes.len() <= MAX_RUN_JCS_BYTES,
                "{label} exceeds the 64 KiB bound"
            );
        }

        let verifier_input = validate_canonical_json_source(documents.verifier_input_jcs)
            .context("verifier input is not exact canonical JCS")?;
        let observation = validate_canonical_json_source(documents.observation_jcs)
            .context("observation is not exact canonical JCS")?;
        let acceptance = validate_canonical_json_source(documents.acceptance_jcs)
            .context("acceptance is not exact canonical JCS")?;

        validate_json_schema(
            &verifier_input,
            EmbeddedSchema::VerifierInput,
            "verifier input",
        )?;
        validate_json_schema(&observation, EmbeddedSchema::Observation, "observation")?;
        validate_json_schema(&acceptance, EmbeddedSchema::Acceptance, "acceptance")?;

        require_format(&verifier_input, "Eip0045B4PositiveVerifierInputV1", 1)?;
        require_exact_keys(
            &verifier_input,
            &[
                "format",
                "formatVersion",
                "profileManifest",
                "profileAlgorithm",
                "profileConstants",
                "guestElf",
                "statement",
                "rawSeal",
            ],
            "verifier input",
        )?;
        require_format(&observation, "Eip0045B4PositiveObservationV1", 1)?;
        require_format(&acceptance, "Eip0045B4PositiveAcceptanceV1", 1)?;
        require_u64_eq(
            &acceptance,
            "caseIndex",
            u64::from(documents.trusted_case_index),
        )?;
        let case = array_field(&self.provenance.input_set.value, "positiveCases")?
            .get(usize::from(documents.trusted_case_index))
            .context("trusted positive case index is outside the input-set plan")?;
        let generated_case = array_field(&self.generation_set.value, "cases")?
            .get(usize::from(documents.trusted_case_index))
            .context("trusted positive case index is outside the generation set")?;
        let expected_observation = derive_expected_observation(
            &verifier_input,
            &documents.verifier_files,
            &self.provenance.input_set.value,
            case,
        )?;
        ensure!(
            documents.observation_jcs == expected_observation,
            "verifier observation differs from the independently derived input semantics"
        );
        ensure!(
            field(&acceptance, "caseId")? == field(case, "caseId")?,
            "acceptance case ID differs from the finalizer-held case plan"
        );
        validate_terminal_against_case(&observation, case)?;
        validate_generated_case_against_run(
            generated_case,
            &self.cases[usize::from(documents.trusted_case_index)],
            &verifier_input,
            &observation,
        )?;

        ensure!(
            field(&acceptance, "inputSetCommitment")?
                == &self
                    .provenance
                    .input_set
                    .commitment("Eip0045B4PositiveInputSetV1"),
            "acceptance input-set commitment is stale"
        );
        ensure!(
            field(&acceptance, "generationSetCommitment")?
                == &self
                    .generation_set
                    .commitment("Eip0045B4PositiveGenerationSetV1"),
            "acceptance generation-set commitment is stale"
        );
        ensure!(
            field(&acceptance, "verifierInputCommitment")?
                == &jcs_commitment(
                    "Eip0045B4PositiveVerifierInputV1",
                    documents.verifier_input_jcs
                ),
            "acceptance verifier-input commitment is stale"
        );
        ensure!(
            field(&acceptance, "observationCommitment")?
                == &jcs_commitment("Eip0045B4PositiveObservationV1", documents.observation_jcs),
            "acceptance observation commitment is stale"
        );
        ensure!(
            field(&acceptance, "observation")? == &observation,
            "acceptance embeds a different observation"
        );

        self.provenance.validate_implementation_binding(
            field(&acceptance, "implementationBinding")?,
            documents.trusted_implementation,
            &documents.launched_artifact,
            documents.java_binary.as_ref(),
            documents.java_release.as_ref(),
        )?;

        Ok(ValidatedPositiveRun {
            case_index: documents.trusted_case_index,
            implementation: documents.trusted_implementation,
            input_set_sha256: Sha256::digest(&self.provenance.input_set.bytes).into(),
            generation_set_sha256: Sha256::digest(&self.generation_set.bytes).into(),
            proof_output_manifest_sha256: self.cases[usize::from(documents.trusted_case_index)]
                .proof_output_manifest
                .sha256,
            raw_seal_sha256: Sha256::digest(documents.verifier_files.raw_seal).into(),
            acceptance_sha256: Sha256::digest(documents.acceptance_jcs).into(),
            verifier_input_jcs: documents.verifier_input_jcs.to_vec(),
            observation_jcs: documents.observation_jcs.to_vec(),
        })
    }

    /// Validate one Rust run and one JVM-lineage run for the same bound case and
    /// produce an opaque agreement token. This does not attest source review.
    ///
    /// # Errors
    ///
    /// Returns an error for implementation, case, provenance, manifest, raw
    /// seal, verifier-input, or observation disagreement.
    pub fn validate_differential_pair(
        &self,
        rust: &ValidatedPositiveRun,
        jvm: &ValidatedPositiveRun,
    ) -> Result<ValidatedDifferentialPair> {
        ensure!(
            rust.implementation == PositiveImplementation::RustReference,
            "differential pair first member is not the Rust reference run"
        );
        ensure!(
            jvm.implementation == PositiveImplementation::IndependentJvm,
            "differential pair second member is not the JVM-lineage run"
        );
        ensure!(rust.case_index == jvm.case_index, "differential case drift");
        let case_index = usize::from(rust.case_index);
        let bound = self
            .cases
            .get(case_index)
            .context("differential case index is outside the closed positive plan")?;
        let expected_input_set: [u8; DIGEST_BYTES] =
            Sha256::digest(&self.provenance.input_set.bytes).into();
        let expected_generation_set: [u8; DIGEST_BYTES] =
            Sha256::digest(&self.generation_set.bytes).into();
        for run in [rust, jvm] {
            ensure!(
                run.input_set_sha256 == expected_input_set,
                "differential input-set root differs from the bound gate"
            );
            ensure!(
                run.generation_set_sha256 == expected_generation_set,
                "differential generation-set root differs from the bound gate"
            );
            ensure!(
                run.proof_output_manifest_sha256 == bound.proof_output_manifest.sha256,
                "differential proof-output manifest differs from the bound case"
            );
            ensure!(
                run.raw_seal_sha256 == bound.raw_seal.sha256,
                "differential raw seal differs from the bound case"
            );
        }
        ensure!(
            rust.verifier_input_jcs == jvm.verifier_input_jcs,
            "validators received different verifier-input bytes"
        );
        ensure!(
            rust.observation_jcs == jvm.observation_jcs,
            "validators emitted different observation bytes"
        );
        ensure!(
            rust.acceptance_sha256 != jvm.acceptance_sha256,
            "Rust and JVM runs reuse the same acceptance bytes"
        );
        Ok(ValidatedDifferentialPair {
            case_index: rust.case_index,
            input_set_sha256: expected_input_set,
            generation_set_sha256: expected_generation_set,
            proof_output_manifest_sha256: bound.proof_output_manifest.sha256,
            raw_seal_sha256: bound.raw_seal.sha256,
            rust_acceptance_sha256: rust.acceptance_sha256,
            jvm_acceptance_sha256: jvm.acceptance_sha256,
        })
    }

    /// Validate the exact ordered eleven-pair positive suite.
    ///
    /// # Errors
    ///
    /// Returns an error for an absent, duplicated, reordered, foreign-root, or
    /// foreign-case pair.
    pub fn validate_positive_suite(
        &self,
        pairs: [ValidatedDifferentialPair; POSITIVE_CASE_COUNT],
    ) -> Result<SemanticallyValidatedPositiveSuite> {
        let expected_input_set: [u8; DIGEST_BYTES] =
            Sha256::digest(&self.provenance.input_set.bytes).into();
        let expected_generation_set: [u8; DIGEST_BYTES] =
            Sha256::digest(&self.generation_set.bytes).into();
        let mut manifests = BTreeSet::new();
        let mut raw_seals = BTreeSet::new();
        let mut acceptances = BTreeSet::new();
        let mut acceptance_sha256s = [[0_u8; DIGEST_BYTES]; POSITIVE_ACCEPTANCE_COUNT];
        for (index, pair) in pairs.iter().enumerate() {
            let bound = &self.cases[index];
            ensure!(
                usize::from(pair.case_index) == index,
                "positive differential suite is absent, duplicated, or out of order"
            );
            ensure!(
                pair.input_set_sha256 == expected_input_set
                    && pair.generation_set_sha256 == expected_generation_set,
                "positive differential suite mixes provenance roots"
            );
            ensure!(
                pair.proof_output_manifest_sha256 == bound.proof_output_manifest.sha256,
                "positive differential suite carries a foreign proof-output manifest"
            );
            ensure!(
                pair.raw_seal_sha256 == bound.raw_seal.sha256,
                "positive differential suite carries a foreign raw seal"
            );
            ensure!(
                manifests.insert(pair.proof_output_manifest_sha256),
                "positive differential suite reuses a proof-output manifest"
            );
            ensure!(
                raw_seals.insert(pair.raw_seal_sha256),
                "positive differential suite reuses a raw seal"
            );
            for (implementation_index, acceptance_sha256) in
                [pair.rust_acceptance_sha256, pair.jvm_acceptance_sha256]
                    .into_iter()
                    .enumerate()
            {
                ensure!(
                    acceptances.insert(acceptance_sha256),
                    "positive differential suite reuses acceptance bytes"
                );
                acceptance_sha256s[index * 2 + implementation_index] = acceptance_sha256;
            }
        }
        Ok(SemanticallyValidatedPositiveSuite {
            input_set_sha256: expected_input_set,
            generation_set_sha256: expected_generation_set,
            acceptance_sha256s,
        })
    }
}

fn validate_authoritative_build_projection(
    input_set: &Value,
    authoritative: &AuthoritativeB4BuildProjection,
) -> Result<()> {
    let generator = field(input_set, "proofGenerator")?;
    validate_qualifying_build_projection(input_set, generator, authoritative)?;
    validate_approved_guest_projection(input_set, authoritative)?;
    validate_approved_statement_projection(input_set, authoritative)?;
    require_string_eq(
        field(generator, "executionPolicy")?,
        "policy",
        "eip0045-b4-proof-generation-executor-v1",
    )
}

fn validate_qualifying_build_projection(
    input_set: &Value,
    generator: &Value,
    authoritative: &AuthoritativeB4BuildProjection,
) -> Result<()> {
    let artifact = field(generator, "artifact")?;
    let qualifying_build = field(generator, "qualifyingBuild")?;
    ensure!(
        field(qualifying_build, "generatorArtifact")? == &binary_commitment(artifact)?,
        "qualifying build generator artifact differs from the input-set generator"
    );
    ensure!(
        string_field(qualifying_build, "sourceLockSha256")?
            == string_field(field(input_set, "sourceLock")?, "sha256")?,
        "qualifying build source-lock digest differs from the input-set source lock"
    );
    for (field_name, expected, label) in [
        (
            "evidenceRootSha256",
            authoritative.evidence_root_sha256(),
            "evidence root",
        ),
        (
            "sourceCommit",
            authoritative.source_commit(),
            "source commit",
        ),
        ("sourceTree", authoritative.source_tree(), "source tree"),
        (
            "sourceLockSha256",
            authoritative.source_lock_sha256(),
            "source lock",
        ),
        (
            "generatorCargoClosureSha256",
            authoritative.generator_cargo_closure_sha256(),
            "proof-generator Cargo closure",
        ),
        (
            "proofGenerationTestsSha256",
            authoritative.proof_generation_tests_sha256(),
            "proof-generation tests",
        ),
    ] {
        ensure!(
            string_field(qualifying_build, field_name)? == expected,
            "qualifying build {label} differs from authoritative B4 validation"
        );
    }
    ensure!(
        string_field(field(qualifying_build, "generatorArtifact")?, "sha256")?
            == authoritative.generator_artifact_sha256()
            && u64_field(field(qualifying_build, "generatorArtifact")?, "byteLength")?
                == authoritative.generator_artifact_byte_length(),
        "qualifying build generator artifact differs from authoritative B4 validation"
    );
    ensure!(
        string_field(artifact, "sha256")? == authoritative.generator_artifact_sha256()
            && u64_field(artifact, "byteLength")? == authoritative.generator_artifact_byte_length(),
        "input-set proof-generator artifact differs from authoritative B4 validation"
    );
    require_string_eq(
        qualifying_build,
        "policy",
        "eip0045-b4-qualifying-build-binding-v1",
    )
}

fn validate_approved_guest_projection(
    input_set: &Value,
    authoritative: &AuthoritativeB4BuildProjection,
) -> Result<()> {
    let guest = field(input_set, "guest")?;
    let guest_elf = field(guest, "elf")?;
    ensure!(
        string_field(guest_elf, "sha256")? == authoritative.guest_elf_sha256()
            && u64_field(guest_elf, "byteLength")? == authoritative.guest_elf_byte_length(),
        "input-set guest ELF differs from authoritative B4 validation"
    );
    ensure!(
        string_field(guest, "imageId")? == authoritative.image_id_hex(),
        "input-set image ID differs from authoritative B4 validation"
    );
    Ok(())
}

fn validate_approved_statement_projection(
    input_set: &Value,
    authoritative: &AuthoritativeB4BuildProjection,
) -> Result<()> {
    let statement = field(input_set, "referenceStatement")?;
    for (field_name, expected, label) in [
        (
            "statementSha256",
            authoritative.statement_sha256(),
            "statement digest",
        ),
        ("contractId", authoritative.contract_id_hex(), "contract ID"),
        (
            "chainDomainId",
            authoritative.chain_domain_id_hex(),
            "chain-domain ID",
        ),
        (
            "applicationPayloadSha256",
            authoritative.application_payload_sha256(),
            "application-payload digest",
        ),
    ] {
        ensure!(
            string_field(statement, field_name)? == expected,
            "input-set reference {label} differs from authoritative B4 validation"
        );
    }
    ensure!(
        u64_field(statement, "statementByteLength")? == authoritative.statement_byte_length(),
        "input-set reference statement length differs from authoritative B4 validation"
    );
    ensure!(
        u64_field(statement, "applicationPayloadByteLength")?
            == authoritative.application_payload_byte_length(),
        "input-set application-payload length differs from authoritative B4 validation"
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_generation_case(
    index: usize,
    planned: &Value,
    generated: &Value,
    physical: PositiveGenerationCaseDocuments<'_>,
    input_set: &Value,
) -> Result<BoundGenerationCase> {
    let bound = validate_generation_case_physical_bindings(index, planned, generated, physical)?;
    validate_generation_case_semantics(index, generated, input_set)?;
    Ok(bound)
}

#[allow(clippy::too_many_lines)]
fn validate_generation_case_physical_bindings(
    index: usize,
    planned: &Value,
    generated: &Value,
    physical: PositiveGenerationCaseDocuments<'_>,
) -> Result<BoundGenerationCase> {
    let spec = POSITIVE_CASE_SPECS
        .get(index)
        .context("positive generation case index is outside the closed plan")?;
    require_u64_eq(planned, "index", index as u64)?;
    require_string_eq(planned, "caseId", spec.case_id)?;
    require_string_eq(planned, "family", spec.family)?;
    let planned_terminal = field(planned, "terminal")?;
    require_string_eq(planned_terminal, "kind", spec.terminal_kind)?;
    require_u64_eq(
        planned_terminal,
        "parameter",
        u64::from(spec.terminal_parameter),
    )?;
    validate_closed_case_plan(index, planned)?;

    require_u64_eq(generated, "caseIndex", index as u64)?;
    require_string_eq(generated, "caseId", spec.case_id)?;
    let generation = field(generated, "generation")?;
    if index < 8 {
        require_string_eq(generation, "kind", "lift")?;
        require_u64_eq(generation, "segmentPo2", u64::from(spec.terminal_parameter))?;
    } else {
        require_string_eq(generation, "kind", "recursive")?;
        require_string_eq(generation, "family", spec.family)?;
    }

    let layout: &[(&str, &str)] = if index < 8 {
        &LIFT_ARTIFACT_LAYOUT
    } else {
        &RECURSIVE_ARTIFACT_LAYOUT
    };
    let planned_roles = array_field(planned, "artifactRoles")?;
    let generated_artifacts = array_field(generated, "artifacts")?;
    ensure!(
        planned_roles.len() == layout.len()
            && generated_artifacts.len() == layout.len()
            && physical.artifacts.len() == layout.len(),
        "positive generation artifact cardinality differs from the closed case layout"
    );

    let auxiliary_paths = positive_auxiliary_artifact_paths(index)?;
    ensure!(
        physical.auxiliary_artifacts.len() == auxiliary_paths.len(),
        "positive generation auxiliary artifact cardinality differs from the closed physical export"
    );
    let mut reconstructed_manifest =
        Vec::with_capacity(layout.len() + physical.auxiliary_artifacts.len());
    for (position, ((expected_role, expected_file), physical_artifact)) in
        layout.iter().zip(physical.artifacts).enumerate()
    {
        ensure!(
            planned_roles[position].as_str() == Some(expected_role),
            "pre-proof artifact-role order differs from the closed case layout"
        );
        let generated_artifact = &generated_artifacts[position];
        require_string_eq(generated_artifact, "role", expected_role)?;
        require_string_eq(generated_artifact, "sourceFile", expected_file)?;
        ensure!(
            physical_artifact.source_file == *expected_file,
            "physical generator artifact name differs from the closed case layout"
        );
        let measurement = measure_bytes(physical_artifact.bytes);
        validate_measurement(
            generated_artifact,
            &measurement,
            &format!("generated {expected_role} artifact"),
        )?;
        let expected_encoding = if matches!(*expected_role, "metadata" | "ancestry" | "calibration")
        {
            "rfc8785-jcs"
        } else {
            "raw-bytes"
        };
        require_string_eq(generated_artifact, "encoding", expected_encoding)?;
        if expected_encoding == "rfc8785-jcs" {
            validate_canonical_json_source(physical_artifact.bytes).with_context(|| {
                format!("generated {expected_role} artifact is not exact canonical JCS")
            })?;
        }
        if matches!(*expected_role, "claim-digest" | "control-id" | "image-id") {
            ensure!(
                physical_artifact.bytes.len() == DIGEST_BYTES,
                "generated {expected_role} artifact is not exactly one digest"
            );
            ensure!(
                string_field(generated_artifact, "contentHex")?
                    == hex::encode(physical_artifact.bytes),
                "generated {expected_role} content differs from its physical bytes"
            );
        }
        reconstructed_manifest.push(ManifestEntry {
            path: (*expected_file).to_owned(),
            length: physical_artifact.bytes.len().to_string(),
            sha256: hex::encode(measurement.sha256),
        });
    }
    for (expected_path, physical_artifact) in auxiliary_paths
        .iter()
        .copied()
        .zip(physical.auxiliary_artifacts)
    {
        ensure!(
            physical_artifact.relative_path == expected_path,
            "physical recursive auxiliary artifact path or order differs from the closed family export"
        );
        ensure!(
            physical_artifact.bytes.len() == PROOF_BYTES,
            "physical recursive auxiliary raw seal has the wrong exact byte length"
        );
        let measurement = measure_bytes(physical_artifact.bytes);
        reconstructed_manifest.push(ManifestEntry {
            path: expected_path.to_owned(),
            length: physical_artifact.bytes.len().to_string(),
            sha256: hex::encode(measurement.sha256),
        });
    }
    reconstructed_manifest.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    validate_manifest_shape(&reconstructed_manifest)
        .context("reconstructed proof-output manifest is invalid")?;

    let physical_manifest_value =
        validate_canonical_json_source(physical.proof_output_manifest_jcs)
            .context("physical proof-output manifest is not exact canonical JCS")?;
    let physical_manifest: ProofOutputManifest = serde_json::from_value(physical_manifest_value)
        .context("physical proof-output manifest has the wrong closed shape")?;
    validate_manifest_shape(&physical_manifest)
        .context("physical proof-output manifest fields are invalid")?;
    ensure!(
        physical_manifest == reconstructed_manifest,
        "physical proof-output manifest differs from the exact artifact snapshot"
    );

    let manifest_identity = field(generated, "proofOutputManifest")?;
    let expected_manifest_name = if index < 8 {
        "candidate-proof-output-manifest.json"
    } else {
        "candidate-recursive-output-manifest.json"
    };
    require_string_eq(manifest_identity, "fileName", expected_manifest_name)?;
    require_string_eq(manifest_identity, "encoding", "rfc8785-jcs")?;
    let manifest_measurement = measure_bytes(physical.proof_output_manifest_jcs);
    validate_measurement(
        manifest_identity,
        &manifest_measurement,
        "physical proof-output manifest",
    )?;

    let raw_seal_artifact = generated_artifact_by_role(generated_artifacts, "raw-seal")?;
    let raw_seal = FileMeasurement {
        byte_length: u64_field(raw_seal_artifact, "byteLength")?,
        sha256: decode_digest(
            string_field(raw_seal_artifact, "sha256")?,
            "generated raw-seal SHA-256",
        )?,
    };
    ensure!(
        raw_seal.byte_length == PROOF_BYTES as u64,
        "generated raw seal has the wrong exact byte length"
    );

    Ok(BoundGenerationCase {
        proof_output_manifest: manifest_measurement,
        raw_seal,
    })
}

fn validate_generation_case_semantics(
    index: usize,
    generated: &Value,
    input_set: &Value,
) -> Result<()> {
    let spec = POSITIVE_CASE_SPECS
        .get(index)
        .context("positive generation case index is outside the closed plan")?;
    let generated_artifacts = array_field(generated, "artifacts")?;
    let image_artifact = generated_artifact_by_role(generated_artifacts, "image-id")?;
    ensure!(
        string_field(image_artifact, "contentHex")?
            == string_field(field(input_set, "guest")?, "imageId")?,
        "generated image-ID artifact differs from the pre-proof guest"
    );
    let journal_artifact = generated_artifact_by_role(generated_artifacts, "journal")?;
    ensure!(
        field(journal_artifact, "sha256")?
            == field(field(input_set, "referenceStatement")?, "statementSha256")?,
        "generated journal digest differs from the pre-proof statement"
    );
    ensure!(
        field(journal_artifact, "byteLength")?
            == field(
                field(input_set, "referenceStatement")?,
                "statementByteLength",
            )?,
        "generated journal length differs from the pre-proof statement"
    );

    if index >= 8 {
        let calibration = generated_artifact_by_role(generated_artifacts, "calibration")?;
        let mut matching_calibrations = array_field(input_set, "recursiveCalibrations")?
            .iter()
            .filter(|candidate| string_field(candidate, "caseId").ok() == Some(spec.case_id));
        let expected_calibration = matching_calibrations
            .next()
            .context("recursive case has no pre-proof calibration")?;
        ensure!(
            matching_calibrations.next().is_none(),
            "recursive case has ambiguous pre-proof calibrations"
        );
        ensure!(
            binary_commitment(calibration)?
                == binary_commitment(field(expected_calibration, "artifact")?)?,
            "generated recursive calibration differs from the pre-proof calibration"
        );
    }
    Ok(())
}

fn build_positive_generation_authority(
    provenance: &PositiveGateBindings,
    generation_set: &BoundDocument,
    cases: &[BoundGenerationCase; POSITIVE_CASE_COUNT],
) -> Result<B4PositiveGenerationAuthorityV1> {
    let mut final_closure = B4PositiveProvenanceClosureV1 {
        paths: provenance.provenance_paths.clone(),
        sha256_by_path: provenance.provenance_sha256.clone(),
    };
    insert_provenance_binding(
        &mut final_closure,
        &generation_set.relative_path,
        &generation_set.sha256,
        "positive generation set",
    )?;
    let provenance_paths = final_closure.paths;
    let provenance_sha256 = final_closure.sha256_by_path;
    ensure!(
        provenance_paths.iter().eq(provenance_sha256.keys()),
        "positive provenance path/digest closure is incomplete"
    );
    let cases = std::array::from_fn(|index| B4PositiveGenerationCaseAuthorityV1 {
        case_index: u8::try_from(index).expect("eleven-case index fits u8"),
        proof_output_manifest: cases[index].proof_output_manifest,
        raw_seal: cases[index].raw_seal,
    });
    Ok(B4PositiveGenerationAuthorityV1 {
        input_set: provenance.input_set.contract_identity(),
        generation_set: generation_set.contract_identity(),
        cases,
        provenance_paths,
        provenance_sha256,
    })
}

fn validate_closed_case_plan(index: usize, planned: &Value) -> Result<()> {
    let (guest_mode, source_segments, root_branch) = match index {
        0..=7 => ("plain", 1, "none"),
        8 => ("plain", 2, "none"),
        9 => ("verify-assumption-explicit-root", 1, "explicit"),
        10 => ("verify-assumption-zero-root", 2, "zero"),
        _ => anyhow::bail!("positive case index is outside the closed plan"),
    };
    require_string_eq(planned, "guestMode", guest_mode)?;
    require_u64_eq(planned, "sourceSegments", source_segments)?;
    require_string_eq(planned, "rootBranch", root_branch)
}

fn generated_artifact_by_role<'a>(artifacts: &'a [Value], role: &str) -> Result<&'a Value> {
    let mut matches = artifacts
        .iter()
        .filter(|artifact| string_field(artifact, "role").ok() == Some(role));
    let artifact = matches
        .next()
        .with_context(|| format!("generated case lacks {role} artifact"))?;
    ensure!(
        matches.next().is_none(),
        "generated case has duplicate {role} artifacts"
    );
    Ok(artifact)
}

fn validate_generated_case_against_run(
    generated: &Value,
    bound: &BoundGenerationCase,
    verifier_input: &Value,
    observation: &Value,
) -> Result<()> {
    validate_generated_case_semantics(generated, observation)?;
    validate_generated_case_physical_bindings(generated, bound, verifier_input)
}

fn validate_generated_case_semantics(generated: &Value, observation: &Value) -> Result<()> {
    let artifacts = array_field(generated, "artifacts")?;
    let claim = generated_artifact_by_role(artifacts, "claim-digest")?;
    ensure!(
        field(claim, "contentHex")? == field(observation, "claimDigest")?,
        "generated claim digest differs from the independently derived observation"
    );
    let control = generated_artifact_by_role(artifacts, "control-id")?;
    ensure!(
        field(control, "contentHex")? == field(field(observation, "terminal")?, "controlId")?,
        "generated control ID differs from the independently derived observation"
    );
    let image = generated_artifact_by_role(artifacts, "image-id")?;
    ensure!(
        field(image, "contentHex")? == field(observation, "programId")?,
        "generated image ID differs from the independently derived observation"
    );
    Ok(())
}

fn validate_generated_case_physical_bindings(
    generated: &Value,
    bound: &BoundGenerationCase,
    verifier_input: &Value,
) -> Result<()> {
    let artifacts = array_field(generated, "artifacts")?;
    let journal = generated_artifact_by_role(artifacts, "journal")?;
    require_same_file_identity(
        journal,
        field(verifier_input, "statement")?,
        "generated journal",
    )?;
    let raw_seal = generated_artifact_by_role(artifacts, "raw-seal")?;
    require_same_file_identity(
        raw_seal,
        field(verifier_input, "rawSeal")?,
        "generated raw seal",
    )?;
    validate_measurement(
        field(verifier_input, "rawSeal")?,
        &bound.raw_seal,
        "generation-bound raw seal",
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn build_campaign_precommit_authority(
    input_set: &BoundDocument,
    verifier_contract: &BoundDocument,
    parsed_verifier_contract: &Eip0045B4VerifierContractV1,
    descriptors: &[BoundDocument; 2],
    runner_profiles: &[BoundDocument; 4],
    seccomp_profiles: &[BoundDocument; 4],
    jvm_copy_only_inclusion_manifest: &BoundDocument,
    provenance_paths: &BTreeSet<String>,
) -> Result<B4PositiveGateAuthorityV1> {
    let validators = [
        campaign_validator_binding(
            PositiveImplementation::RustReference,
            &descriptors[PositiveImplementation::RustReference.index()],
        )?,
        campaign_validator_binding(
            PositiveImplementation::IndependentJvm,
            &descriptors[PositiveImplementation::IndependentJvm.index()],
        )?,
    ];
    let runner_profiles = std::array::from_fn(|index| B4NamedContractArtifactIdentityV1 {
        role: PositiveRunnerRole::all()[index].purpose().to_owned(),
        artifact: runner_profiles[index].contract_identity(),
    });
    let seccomp_documents = std::array::from_fn(|index| B4NamedContractArtifactIdentityV1 {
        role: PositiveRunnerRole::all()[index].purpose().to_owned(),
        artifact: seccomp_profiles[index].contract_identity(),
    });
    B4PositiveGateAuthorityV1::from_validated_positive_gate(
        input_set.contract_identity(),
        verifier_contract.contract_identity(),
        parsed_verifier_contract.expectation_set.clone(),
        validators,
        runner_profiles,
        seccomp_documents,
        jvm_copy_only_inclusion_manifest.contract_identity(),
        provenance_paths,
    )
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn build_positive_precommit_authority_v2(
    input_set: &BoundDocument,
    verifier_contract: &BoundDocument,
    parsed_verifier_contract: &Eip0045B4VerifierContractV1,
    descriptors: &[BoundDocument; 2],
    runner_profiles: &[BoundDocument; 4],
    seccomp_documents: &[BoundDocument; 4],
    jvm_copy_only_inclusion_manifest: &BoundDocument,
    provenance_paths: &BTreeSet<String>,
) -> Result<B4PositivePrecommitAuthorityV2> {
    let validators = [
        campaign_validator_binding(
            PositiveImplementation::RustReference,
            &descriptors[PositiveImplementation::RustReference.index()],
        )?,
        campaign_validator_binding(
            PositiveImplementation::IndependentJvm,
            &descriptors[PositiveImplementation::IndependentJvm.index()],
        )?,
    ];
    let runner_profiles = std::array::from_fn(|index| B4NamedContractArtifactIdentityV1 {
        role: PositiveRunnerRole::all()[index].purpose().to_owned(),
        artifact: runner_profiles[index].contract_identity(),
    });
    let seccomp_documents = std::array::from_fn(|index| B4NamedContractArtifactIdentityV1 {
        role: PositiveRunnerRole::all()[index].purpose().to_owned(),
        artifact: seccomp_documents[index].contract_identity(),
    });
    B4PositivePrecommitAuthorityV2::from_validated_positive_precommit(
        input_set.contract_identity(),
        verifier_contract.contract_identity(),
        parsed_verifier_contract.expectation_set.clone(),
        validators,
        runner_profiles,
        seccomp_documents,
        jvm_copy_only_inclusion_manifest.contract_identity(),
        provenance_paths,
    )
}

fn campaign_validator_binding(
    implementation: PositiveImplementation,
    descriptor: &BoundDocument,
) -> Result<B4CampaignValidatorBindingV1> {
    let value = &descriptor.value;
    let reviewed_source = field(value, "reviewedSource")?;
    let lineage = field(value, "implementationLineage")?;
    let implementation = match implementation {
        PositiveImplementation::RustReference => B4CampaignValidatorImplementationV1::RustReference,
        PositiveImplementation::IndependentJvm => {
            B4CampaignValidatorImplementationV1::IndependentJvm
        }
    };
    Ok(B4CampaignValidatorBindingV1 {
        implementation,
        build_descriptor: descriptor.contract_identity(),
        artifact: project_campaign_artifact_identity(
            field(value, "artifact")?,
            B4ContractArtifactEncodingV1::RawBytes,
            "validator artifact",
        )?,
        reviewed_source: B4ReviewedSourceBindingV1 {
            repository: string_field(reviewed_source, "repository")?.to_owned(),
            commit: string_field(reviewed_source, "commit")?.to_owned(),
            tree: string_field(reviewed_source, "tree")?.to_owned(),
            archive: project_campaign_artifact_identity(
                field(reviewed_source, "archive")?,
                B4ContractArtifactEncodingV1::GitBundle,
                "validator reviewed-source archive",
            )?,
        },
        lineage_sha256: string_field(lineage, "lineageSha256")?.to_owned(),
    })
}

fn project_campaign_artifact_identity(
    value: &Value,
    encoding: B4ContractArtifactEncodingV1,
    label: &str,
) -> Result<B4ContractArtifactIdentityV1> {
    let expected_encoding = match encoding {
        B4ContractArtifactEncodingV1::RawBytes => "raw-bytes",
        B4ContractArtifactEncodingV1::Rfc8785Jcs => "rfc8785-jcs",
        B4ContractArtifactEncodingV1::GitBundle => "git-bundle",
    };
    ensure!(
        string_field(value, "encoding")? == expected_encoding,
        "{label} uses the wrong encoding"
    );
    Ok(B4ContractArtifactIdentityV1 {
        path: string_field(value, "path")?.to_owned(),
        byte_length: u64_field(value, "byteLength")?,
        sha256: string_field(value, "sha256")?.to_owned(),
        encoding,
    })
}

#[allow(clippy::too_many_lines)]
fn validate_provenance_closure(
    input_set: &BoundDocument,
    profiles: &[BoundDocument; 4],
    seccomp_profiles: &[BoundDocument; 4],
    descriptors: &[BoundDocument; 2],
) -> Result<B4PositiveProvenanceClosureV1> {
    let mut closure = B4PositiveProvenanceClosureV1 {
        paths: BTreeSet::new(),
        sha256_by_path: BTreeMap::new(),
    };
    insert_provenance_binding(
        &mut closure,
        &input_set.relative_path,
        &input_set.sha256,
        "positive input set",
    )?;

    let profile = field(&input_set.value, "profile")?;
    for (key, label) in [
        ("manifest", "profile manifest"),
        ("algorithm", "profile algorithm"),
        ("constants", "profile constants"),
    ] {
        insert_identity_binding(&mut closure, field(profile, key)?, label)?;
    }
    insert_identity_binding(
        &mut closure,
        field(field(&input_set.value, "guest")?, "elf")?,
        "guest ELF",
    )?;
    insert_identity_binding(
        &mut closure,
        field(
            field(&input_set.value, "referenceStatement")?,
            "bundleManifest",
        )?,
        "reference-statement bundle manifest",
    )?;
    insert_identity_binding(
        &mut closure,
        field(&input_set.value, "sourceLock")?,
        "source lock",
    )?;
    let proof_generator = field(&input_set.value, "proofGenerator")?;
    insert_identity_binding(
        &mut closure,
        field(proof_generator, "artifact")?,
        "proof-generator artifact",
    )?;
    insert_identity_binding(
        &mut closure,
        field(&input_set.value, "verifierCliContract")?,
        "verifier CLI contract",
    )?;
    for validator in array_field(&input_set.value, "validators")? {
        insert_identity_binding(
            &mut closure,
            field(validator, "buildDescriptor")?,
            "validator build descriptor",
        )?;
    }
    for runner in array_field(&input_set.value, "runnerProfiles")? {
        insert_identity_binding(
            &mut closure,
            field(runner, "artifact")?,
            "runner-profile document",
        )?;
    }
    for calibration in array_field(&input_set.value, "recursiveCalibrations")? {
        insert_identity_binding(
            &mut closure,
            field(calibration, "artifact")?,
            "recursive calibration",
        )?;
    }

    for (index, document) in profiles.iter().enumerate() {
        ensure!(
            closure.paths.contains(&document.relative_path),
            "runner-profile document path is absent from the input-set inventory"
        );
        insert_identity_binding(
            &mut closure,
            field(field(&document.value, "image")?, "archive")?,
            "runner OCI image archive",
        )?;
        insert_identity_binding(
            &mut closure,
            field(field(&document.value, "runtime")?, "binary")?,
            "runner OCI runtime binary",
        )?;
        insert_identity_binding(
            &mut closure,
            field(field(&document.value, "seccomp")?, "profile")?,
            "runner seccomp document",
        )?;
        ensure!(
            string_field(
                field(field(&document.value, "seccomp")?, "profile")?,
                "path"
            )? == seccomp_profiles[index].relative_path,
            "bound seccomp document path differs from the runner inventory"
        );
        ensure!(
            closure
                .paths
                .contains(&seccomp_profiles[index].relative_path),
            "bound seccomp document path is absent from the provenance inventory"
        );
    }

    for (index, document) in descriptors.iter().enumerate() {
        ensure!(
            closure.paths.contains(&document.relative_path),
            "validator descriptor path is absent from the input-set inventory"
        );
        insert_identity_binding(
            &mut closure,
            field(field(&document.value, "reviewedSource")?, "archive")?,
            "validator reviewed-source archive",
        )?;
        let dependencies = field(&document.value, "dependencyClosure")?;
        insert_identity_binding(
            &mut closure,
            field(dependencies, "lockfile")?,
            "validator dependency lockfile",
        )?;
        for dependency in array_field(dependencies, "entries")? {
            insert_identity_binding(
                &mut closure,
                field(dependency, "artifact")?,
                "validator dependency artifact",
            )?;
        }
        insert_identity_binding(
            &mut closure,
            field(&document.value, "artifact")?,
            "validator artifact",
        )?;
        if index == PositiveImplementation::IndependentJvm.index() {
            let packaging = field(field(&document.value, "artifact")?, "packaging")?;
            insert_identity_binding(
                &mut closure,
                field(packaging, "applicationInput")?,
                "JVM packaging application input",
            )?;
            insert_identity_binding(
                &mut closure,
                field(packaging, "inclusionManifest")?,
                "JVM COPY-ONLY inclusion manifest",
            )?;
        }
    }
    ensure!(
        closure.paths.iter().eq(closure.sha256_by_path.keys()),
        "positive provenance path/digest closure is incomplete"
    );
    Ok(closure)
}

fn insert_identity_binding(
    closure: &mut B4PositiveProvenanceClosureV1,
    identity: &Value,
    label: &str,
) -> Result<()> {
    insert_provenance_binding(
        closure,
        string_field(identity, "path")?,
        string_field(identity, "sha256")?,
        label,
    )
}

fn insert_provenance_binding(
    closure: &mut B4PositiveProvenanceClosureV1,
    path: &str,
    sha256: &str,
    label: &str,
) -> Result<()> {
    validate_archive_relative_path(path)
        .with_context(|| format!("{label} path is not canonical"))?;
    let digest = decode_digest(sha256, &format!("{label} SHA-256"))?;
    ensure!(
        hex::encode(digest) == sha256,
        "{label} SHA-256 is not canonical lowercase hex"
    );
    if let Some(existing) = closure
        .paths
        .iter()
        .find(|existing| b4_paths_conflict(existing, path))
    {
        ensure!(
            false,
            "pre-proof provenance path aliases or ancestor/descendant-conflicts with another artifact: {path} versus {existing}"
        );
    }
    ensure!(
        closure.paths.insert(path.to_owned()),
        "pre-proof provenance path aliases another artifact: {path}"
    );
    ensure!(
        closure
            .sha256_by_path
            .insert(path.to_owned(), sha256.to_owned())
            .is_none(),
        "pre-proof provenance digest duplicates another artifact: {path}"
    );
    Ok(())
}

fn validate_archive_relative_path(path: &str) -> Result<()> {
    ensure!(
        (1..=240).contains(&path.len()) && path.is_ascii(),
        "relative path length or encoding is invalid"
    );
    for segment in path.split('/') {
        let bytes = segment.as_bytes();
        ensure!(!bytes.is_empty(), "relative path contains an empty segment");
        ensure!(
            matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9'),
            "relative path segment has a noncanonical first byte"
        );
        ensure!(
            bytes
                .iter()
                .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-')),
            "relative path contains a forbidden byte"
        );
        ensure!(
            segment != "." && segment != ".." && !segment.ends_with('.'),
            "relative path contains a dot or trailing-dot segment"
        );
        let stem = segment.split('.').next().unwrap_or(segment);
        let reserved = matches!(stem, "con" | "prn" | "aux" | "nul")
            || (stem.len() == 4
                && (stem.starts_with("com") || stem.starts_with("lpt"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9'));
        ensure!(!reserved, "relative path contains a Windows device segment");
    }
    Ok(())
}

fn validate_elf_projection(elf: &Value, label: &str) -> Result<()> {
    let program_headers = u64_field(elf, "programHeaderCount")?;
    let load_segments = u64_field(elf, "loadSegmentCount")?;
    let executable_load_segments = u64_field(elf, "executableLoadSegmentCount")?;
    ensure!(
        executable_load_segments <= load_segments,
        "{label} executable-load segment count exceeds the load-segment count"
    );
    ensure!(
        load_segments <= program_headers,
        "{label} load-segment count exceeds the program-header count"
    );

    let interpreter_segments = u64_field(elf, "interpreterSegmentCount")?;
    let dynamic_segments = u64_field(elf, "dynamicSegmentCount")?;
    let gnu_stack_segments = u64_field(elf, "gnuStackSegmentCount")?;
    let classified_program_headers = load_segments
        .checked_add(interpreter_segments)
        .and_then(|count| count.checked_add(dynamic_segments))
        .and_then(|count| count.checked_add(gnu_stack_segments))
        .context("ELF classified program-header count overflow")?;
    ensure!(
        classified_program_headers <= program_headers,
        "{label} classified segment counts exceed the program-header count"
    );
    match (elf.get("dynamicEntryCount"), elf.get("neededLibraryCount")) {
        (None, None) => {}
        (Some(_), Some(_)) => {
            let dynamic_entries = u64_field(elf, "dynamicEntryCount")?;
            let needed_libraries = u64_field(elf, "neededLibraryCount")?;
            if needed_libraries != 0 {
                let minimum_dynamic_entries = needed_libraries
                    .checked_add(3)
                    .context("ELF runtime dynamic-entry relation overflow")?;
                ensure!(
                    dynamic_entries >= minimum_dynamic_entries,
                    "{label} dynamic-entry count cannot contain its DT_NEEDED entries, DT_STRTAB, DT_STRSZ, and DT_NULL"
                );
            }
        }
        _ => anyhow::bail!(
            "{label} runtime ELF projection does not carry both dynamic-entry and DT_NEEDED counts"
        ),
    }
    Ok(())
}

fn validate_descriptor(
    descriptor: &Value,
    implementation: PositiveImplementation,
    profiles: &[BoundDocument; 4],
) -> Result<()> {
    validate_descriptor_with_runner_profile_format(
        descriptor,
        implementation,
        profiles,
        "Eip0045B4PositiveOciRunnerProfileV1",
    )
}

fn validate_descriptor_with_runner_profile_format(
    descriptor: &Value,
    implementation: PositiveImplementation,
    profiles: &[BoundDocument; 4],
    runner_profile_format: &str,
) -> Result<()> {
    let deterministic_build = field(descriptor, "deterministicBuild")?;
    let build_role = implementation.build_role();
    validate_profile_reference_with_format(
        field(deterministic_build, "runnerProfile")?,
        build_role,
        &profiles[build_role.index()],
        "descriptor build runner",
        runner_profile_format,
    )?;
    let execution_role = implementation.execution_role();
    validate_profile_reference_with_format(
        field(field(descriptor, "executionEnvironment")?, "runnerProfile")?,
        execution_role,
        &profiles[execution_role.index()],
        "descriptor execution runner",
        runner_profile_format,
    )?;
    validate_build_environment(field(deterministic_build, "environment")?)?;
    validate_build_recipe(
        deterministic_build,
        field(descriptor, "toolchainClosure")?,
        &profiles[build_role.index()].value,
        implementation,
    )?;
    validate_inventory_order_and_bounds(descriptor)?;
    match implementation {
        PositiveImplementation::RustReference => {
            require_string_eq(descriptor, "artifactKind", "native-executable")?;
            ensure!(
                field(deterministic_build, "outputPath")?
                    == field(field(descriptor, "artifact")?, "path")?,
                "deterministic build output path differs from descriptor artifact path"
            );
            validate_elf_projection(
                field(field(descriptor, "artifact")?, "elf")?,
                "native validator artifact ELF",
            )?;
        }
        PositiveImplementation::IndependentJvm => {
            require_string_eq(descriptor, "artifactKind", "executable-jar")?;
            validate_jvm_artifact(descriptor, field(descriptor, "artifact")?)?;
            validate_build_jdk_toolchain(
                descriptor,
                &profiles[PositiveRunnerRole::JvmValidatorBuild.index()],
            )?;
            validate_java_feature_version(
                field(
                    &profiles[PositiveRunnerRole::JvmVerifier.index()].value,
                    "javaRuntime",
                )?,
                "JVM verification runtime",
            )?;
        }
    }
    Ok(())
}

fn validate_jvm_artifact(descriptor: &Value, artifact: &Value) -> Result<()> {
    validate_jvm_packaging(descriptor, field(artifact, "packaging")?)?;
    let archive = field(artifact, "archive")?;
    let entry_count = u64_field(archive, "entryCount")?;
    ensure!(
        u64_field(archive, "localFileRecordCount")? == entry_count,
        "JAR local-record and central-directory entry counts differ"
    );
    ensure!(
        u64_field(archive, "regularFileEntryCount")?
            .checked_add(u64_field(archive, "directoryEntryCount")?)
            == Some(entry_count),
        "JAR regular-file and directory counts do not cover every entry"
    );
    ensure!(
        u64_field(archive, "largestEntryUncompressedByteLength")?
            <= u64_field(archive, "uncompressedByteLength")?,
        "JAR largest entry exceeds the aggregate uncompressed length"
    );
    ensure!(
        u64_field(archive, "dataDescriptorCount")? <= entry_count,
        "JAR data-descriptor count exceeds the entry count"
    );

    let manifest = field(artifact, "manifest")?;
    ensure!(
        u64_field(manifest, "mainAttributeCount")?
            == 2 + u64_field(manifest, "createdByAttributeCount")?,
        "JAR manifest main-attribute count does not match its closed attribute set"
    );
    ensure!(
        u64_field(manifest, "manifestByteLength")?
            <= u64_field(archive, "largestEntryUncompressedByteLength")?,
        "JAR manifest length exceeds the largest uncompressed entry"
    );
    let main_class = string_field(manifest, "mainClass")?;
    let expected_main_entry = format!("{}.class", main_class.replace('.', "/"));
    ensure!(
        string_field(manifest, "mainClassEntry")? == expected_main_entry,
        "JAR Main-Class does not identify its exact class entry"
    );

    let class_files = field(artifact, "classFiles")?;
    ensure!(
        u64_field(class_files, "minimumObservedMajorVersion")?
            <= u64_field(class_files, "maximumObservedMajorVersion")?,
        "JAR class-version interval is inverted"
    );
    let non_class_files = field(artifact, "nonClassFiles")?;
    ensure!(
        u64_field(non_class_files, "regularEntryCount")?
            == u64_field(non_class_files, "scannedEntryCount")?,
        "JAR non-class scan does not cover every non-class regular entry"
    );
    ensure!(
        u64_field(class_files, "classEntryCount")?
            .checked_add(u64_field(non_class_files, "regularEntryCount")?)
            == Some(u64_field(archive, "regularFileEntryCount")?),
        "JAR class and non-class scans do not cover every regular entry"
    );
    Ok(())
}

fn validate_jvm_packaging(descriptor: &Value, packaging: &Value) -> Result<()> {
    let dependency_count = array_field(field(descriptor, "dependencyClosure")?, "entries")?.len();
    ensure!(
        u64_field(packaging, "dependencyArtifactCount")?
            == u64::try_from(dependency_count).context("dependency count does not fit u64")?,
        "JVM packaging dependency-artifact count differs from the bound dependency closure"
    );

    let packager = field(packaging, "packer")?;
    let mut packagers = array_field(field(descriptor, "toolchainClosure")?, "entries")?
        .iter()
        .filter(|entry| entry.get("role").and_then(Value::as_str) == Some("packager"));
    let bound_packager = packagers
        .next()
        .context("JVM packaging lacks a packager toolchain entry")?;
    ensure!(
        packagers.next().is_none(),
        "JVM packaging has more than one packager toolchain entry"
    );
    ensure!(
        packager == bound_packager,
        "JVM packaging packager reference differs from the bound toolchain entry"
    );

    let source_files = array_field(field(descriptor, "implementationLineage")?, "sourceFiles")?;
    let configuration = field(packaging, "configuration")?;
    ensure!(
        source_files
            .iter()
            .filter(|source| *source == configuration)
            .count()
            == 1,
        "JVM packaging configuration does not identify exactly one bound source entry"
    );

    require_string_eq(packaging, "policy", "eip0045-b4-jvm-copy-only-packaging-v1")?;
    require_string_eq(packaging, "mode", "copy-only-inclusion-manifest")?;
    require_string_eq(packaging, "applicationSelection", "all-regular-entries")?;
    require_string_eq(packaging, "dependencySelection", "reviewed-exact-copy-list")?;
    require_string_eq(
        packaging,
        "replayPolicy",
        "exact-input-output-entry-replay-required",
    )?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_jvm_copy_only_inclusion_manifest(
    manifest: &BoundDocument,
    descriptor: &Value,
) -> Result<()> {
    let artifact = field(descriptor, "artifact")?;
    let packaging = field(artifact, "packaging")?;
    require_string_eq(
        &manifest.value,
        "policy",
        "eip0045-b4-jvm-copy-only-packaging-v1",
    )?;
    require_string_eq(
        &manifest.value,
        "applicationSelection",
        "all-regular-entries",
    )?;
    require_string_eq(
        &manifest.value,
        "dependencySelection",
        "reviewed-exact-copy-list",
    )?;
    require_string_eq(
        &manifest.value,
        "inputArchivePolicy",
        "eip0045-b4-jar-source-read-v1",
    )?;
    require_string_eq(
        &manifest.value,
        "archivePolicy",
        "eip0045-b4-canonical-jar-zip-v1",
    )?;
    ensure!(
        field(packaging, "inclusionManifest")?
            == &manifest.identity_with_path("Eip0045B4JvmCopyOnlyInclusionManifestV1"),
        "JVM COPY-ONLY inclusion-manifest commitment is stale"
    );

    let inputs = array_field(&manifest.value, "inputs")?;
    let dependencies = array_field(field(descriptor, "dependencyClosure")?, "entries")?;
    ensure!(
        inputs.len() == dependencies.len() + 1,
        "JVM COPY-ONLY input count differs from the application plus dependency closure"
    );
    let application = &inputs[0];
    require_string_eq(application, "id", "application")?;
    require_string_eq(application, "role", "application-intermediate")?;
    require_archive_identity_fields(
        application,
        field(packaging, "applicationInput")?,
        true,
        "JVM COPY-ONLY application input",
    )?;
    ensure!(
        field(application, "regularEntryCount")?
            == field(field(packaging, "applicationInput")?, "regularEntryCount")?,
        "JVM COPY-ONLY application input regular-entry count is stale"
    );
    for (index, dependency) in dependencies.iter().enumerate() {
        ensure!(
            matches!(string_field(dependency, "ecosystem")?, "maven" | "local"),
            "JVM COPY-ONLY dependency input has a non-JAR ecosystem"
        );
        let input = &inputs[index + 1];
        ensure!(
            string_field(input, "id")? == format!("dependency-{index:03}"),
            "JVM COPY-ONLY dependency input ID is not canonical"
        );
        require_string_eq(input, "role", "dependency-artifact")?;
        require_archive_identity_fields(
            input,
            field(dependency, "artifact")?,
            false,
            "JVM COPY-ONLY dependency input",
        )?;
    }

    ensure!(
        array_field(&manifest.value, "generatedEntries")?.is_empty(),
        "JVM COPY-ONLY generated entries must be empty"
    );
    let entries = array_field(&manifest.value, "entries")?;
    ensure!(
        string_field(&entries[0], "name")? == "META-INF/MANIFEST.MF",
        "JVM COPY-ONLY manifest entry is not first"
    );
    let input_ids = inputs
        .iter()
        .map(|input| string_field(input, "id"))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        input_ids.len() == inputs.len(),
        "JVM COPY-ONLY input IDs are duplicated"
    );
    let mut output_names = BTreeSet::new();
    let mut folded_output_names = BTreeSet::new();
    let mut source_entries = BTreeSet::new();
    let mut previous_non_manifest_name: Option<&str> = None;
    let mut total_bytes = 0_u64;
    let mut largest_entry = 0_u64;
    let mut class_entries = 0_u64;
    let mut application_entries = 0_u64;
    let mut selected_input_entries = BTreeMap::new();
    let mut manifest_entry_length = None;
    let main_class_entry = string_field(field(artifact, "manifest")?, "mainClassEntry")?;
    for (index, entry) in entries.iter().enumerate() {
        let name = string_field(entry, "name")?;
        ensure!(
            output_names.insert(name),
            "JVM COPY-ONLY output entry name is duplicated"
        );
        ensure!(
            folded_output_names.insert(name.to_ascii_lowercase()),
            "JVM COPY-ONLY output entry has an ASCII case-fold collision"
        );
        if index > 0 {
            ensure!(
                previous_non_manifest_name
                    .is_none_or(|previous| previous.as_bytes() < name.as_bytes()),
                "JVM COPY-ONLY output entry names are not in canonical order"
            );
            previous_non_manifest_name = Some(name);
        }
        ensure!(
            string_field(entry, "sourceEntryName")? == name,
            "JVM COPY-ONLY entry relocation is forbidden"
        );
        let source_input = string_field(entry, "sourceInputId")?;
        ensure!(
            input_ids.contains(source_input),
            "JVM COPY-ONLY entry names an unknown source input"
        );
        if name == "META-INF/MANIFEST.MF" || name == main_class_entry {
            ensure!(
                source_input == "application",
                "JVM COPY-ONLY manifest and Main-Class entries must come from the application input"
            );
        }
        if source_input == "application" {
            application_entries = application_entries
                .checked_add(1)
                .context("JVM COPY-ONLY application-entry count overflow")?;
        }
        let selected_count = selected_input_entries.entry(source_input).or_insert(0_u64);
        *selected_count = selected_count
            .checked_add(1)
            .context("JVM COPY-ONLY per-input selected-entry count overflow")?;
        ensure!(
            source_entries.insert(format!("{source_input}\0{name}")),
            "JVM COPY-ONLY source entry is selected more than once"
        );
        let byte_length = u64_field(entry, "byteLength")?;
        total_bytes = total_bytes
            .checked_add(byte_length)
            .context("JVM COPY-ONLY aggregate entry length overflow")?;
        largest_entry = largest_entry.max(byte_length);
        // Archive classification is the exact, case-sensitive byte suffix from
        // the JVM artifact policy; filesystem-style case folding is forbidden.
        if name.as_bytes().ends_with(b".class") {
            class_entries = class_entries
                .checked_add(1)
                .context("JVM COPY-ONLY class-entry count overflow")?;
        }
        if name == "META-INF/MANIFEST.MF" {
            manifest_entry_length = Some(byte_length);
        }
    }
    ensure!(
        application_entries == u64_field(application, "regularEntryCount")?,
        "JVM COPY-ONLY manifest does not select every application entry exactly once"
    );
    for dependency_input in &inputs[1..] {
        let input_id = string_field(dependency_input, "id")?;
        let selected_count = selected_input_entries.get(input_id).copied().unwrap_or(0);
        ensure!(
            selected_count <= u64_field(dependency_input, "regularEntryCount")?,
            "JVM COPY-ONLY manifest selects more entries from {input_id} than the dependency archive declares"
        );
    }

    let archive = field(artifact, "archive")?;
    ensure!(
        u64_field(archive, "directoryEntryCount")? == 0,
        "JVM COPY-ONLY output cannot contain directory entries"
    );
    ensure!(
        u64::try_from(entries.len()).context("JVM COPY-ONLY entry count does not fit u64")?
            == u64_field(archive, "regularFileEntryCount")?,
        "JVM COPY-ONLY manifest entry count differs from the output JAR"
    );
    ensure!(
        u64::try_from(entries.len()).context("JVM COPY-ONLY entry count does not fit u64")?
            == u64_field(archive, "entryCount")?,
        "JVM COPY-ONLY manifest entry count differs from the total output entry count"
    );
    ensure!(
        total_bytes == u64_field(archive, "uncompressedByteLength")?,
        "JVM COPY-ONLY entry lengths differ from the output JAR aggregate"
    );
    ensure!(
        largest_entry == u64_field(archive, "largestEntryUncompressedByteLength")?,
        "JVM COPY-ONLY largest entry differs from the output JAR"
    );
    let non_class_entries = u64::try_from(entries.len())
        .context("JVM COPY-ONLY entry count does not fit u64")?
        - class_entries;
    ensure!(
        class_entries == u64_field(field(artifact, "classFiles")?, "classEntryCount")?
            && non_class_entries
                == u64_field(field(artifact, "nonClassFiles")?, "regularEntryCount")?,
        "JVM COPY-ONLY class/non-class entry counts differ from the output JAR scan"
    );
    ensure!(
        manifest_entry_length
            == Some(u64_field(
                field(artifact, "manifest")?,
                "manifestByteLength"
            )?),
        "JVM COPY-ONLY manifest length differs from the output JAR scan"
    );
    ensure!(
        output_names.contains(string_field(
            field(artifact, "manifest")?,
            "mainClassEntry",
        )?),
        "JVM COPY-ONLY output omits the declared Main-Class entry"
    );
    require_archive_identity_fields(
        field(&manifest.value, "output")?,
        artifact,
        true,
        "JVM COPY-ONLY output",
    )?;
    Ok(())
}

fn require_archive_identity_fields(
    actual: &Value,
    expected: &Value,
    require_file_format: bool,
    label: &str,
) -> Result<()> {
    for key in ["path", "byteLength", "sha256", "encoding"] {
        ensure!(
            field(actual, key)? == field(expected, key)?,
            "{label} {key} differs from its bound identity"
        );
    }
    if require_file_format {
        ensure!(
            field(actual, "fileFormat")? == field(expected, "fileFormat")?,
            "{label} fileFormat differs from its bound identity"
        );
    }
    Ok(())
}

fn validate_build_jdk_toolchain(descriptor: &Value, profile: &BoundDocument) -> Result<()> {
    let build_jdk = field(&profile.value, "buildJdk")?;
    validate_java_feature_version(build_jdk, "JVM build JDK")?;
    let entries = array_field(field(descriptor, "toolchainClosure")?, "entries")?;
    validate_jdk_toolchain_binary(
        entries,
        "runtime",
        "java",
        field(build_jdk, "launcher")?,
        string_field(build_jdk, "version")?,
    )?;
    validate_jdk_toolchain_binary(
        entries,
        "compiler",
        "javac",
        field(build_jdk, "compiler")?,
        string_field(build_jdk, "version")?,
    )?;
    Ok(())
}

fn validate_jdk_toolchain_binary(
    entries: &[Value],
    role: &str,
    name: &str,
    binary: &Value,
    version: &str,
) -> Result<()> {
    let mut matches = entries.iter().filter(|entry| {
        entry.get("role").and_then(Value::as_str) == Some(role)
            && entry.get("name").and_then(Value::as_str) == Some(name)
    });
    let entry = matches
        .next()
        .with_context(|| format!("JVM build JDK lacks its unique {name} toolchain entry"))?;
    ensure!(
        matches.next().is_none(),
        "JVM build JDK has duplicate {name} toolchain entries"
    );
    ensure!(
        string_field(entry, "version")? == version
            && string_field(entry, "imagePath")? == string_field(binary, "imagePath")?
            && u64_field(entry, "byteLength")? == u64_field(binary, "byteLength")?
            && string_field(entry, "sha256")? == string_field(binary, "sha256")?,
        "JVM build JDK {name} toolchain entry differs from the bound runner binary"
    );
    Ok(())
}

fn validate_java_feature_version(runtime: &Value, label: &str) -> Result<()> {
    require_u64_eq(runtime, "featureVersion", 21)?;
    let version = string_field(runtime, "version")?;
    let version_number = version
        .split(['-', '+'])
        .next()
        .context("Java runtime version lacks its version number")?;
    let mut components = version_number.split('.');
    ensure!(
        components.next() == Some("21"),
        "{label} does not identify Java SE feature 21"
    );
    let remaining = components.collect::<Vec<_>>();
    ensure!(
        remaining.len() <= 3
            && remaining.iter().all(|component| {
                !component.is_empty()
                    && component.bytes().all(|byte| byte.is_ascii_digit())
                    && (component == &"0" || !component.starts_with('0'))
            })
            && remaining.last().is_none_or(|component| *component != "0"),
        "{label} version number is not canonical"
    );
    Ok(())
}

fn validate_profile_reference_with_format(
    reference: &Value,
    role: PositiveRunnerRole,
    profile: &BoundDocument,
    label: &str,
    runner_profile_format: &str,
) -> Result<()> {
    require_role(reference, role, label)?;
    ensure!(
        field(reference, "commitment")? == &profile.identity_with_path(runner_profile_format),
        "{label} commitment is stale"
    );
    Ok(())
}

fn validate_build_environment(environment: &Value) -> Result<()> {
    let variables = array_field(environment, "variables")?;
    ensure!(
        variables.is_empty(),
        "descriptor-supplied build environment must be empty; only the bound runner environment is permitted"
    );
    Ok(())
}

fn validate_build_recipe(
    build: &Value,
    toolchain: &Value,
    profile: &Value,
    implementation: PositiveImplementation,
) -> Result<()> {
    match implementation {
        PositiveImplementation::RustReference => {
            validate_single_phase_build_recipe(build, toolchain, profile, "build-driver")
        }
        PositiveImplementation::IndependentJvm => {
            validate_jvm_two_phase_build_recipe(build, toolchain, profile)
        }
    }
}

fn validate_single_phase_build_recipe(
    build: &Value,
    toolchain: &Value,
    profile: &Value,
    executable_role: &str,
) -> Result<()> {
    let steps = array_field(build, "steps")?;
    ensure!(
        steps.len() == 1,
        "build recipe must contain exactly one direct step"
    );
    let step = &steps[0];
    require_string_eq(step, "shell", "none")?;
    ensure!(
        field(step, "workingDirectory")? == field(field(profile, "policy")?, "workingDirectory")?,
        "build-step working directory differs from the bound runner policy"
    );
    let executable = string_field(step, "executable")?;
    let drivers = array_field(toolchain, "entries")?
        .iter()
        .filter(|entry| string_field(entry, "role").ok() == Some(executable_role))
        .collect::<Vec<_>>();
    ensure!(
        drivers.len() == 1,
        "toolchain closure must contain exactly one {executable_role} entry"
    );
    ensure!(
        string_field(drivers[0], "imagePath")? == executable,
        "build step executable differs from the hashed {executable_role} entry"
    );
    Ok(())
}

fn validate_jvm_two_phase_build_recipe(
    build: &Value,
    toolchain: &Value,
    profile: &Value,
) -> Result<()> {
    require_string_eq(
        build,
        "executionOrder",
        "complete-and-compare-each-phase-before-next",
    )?;
    require_u64_eq(build, "repetitionsPerPhase", 2)?;
    require_string_eq(
        build,
        "instancePolicy",
        "fresh-oci-instance-and-output-root-per-phase-repetition",
    )?;
    require_string_eq(
        build,
        "comparison",
        "byte-for-byte-and-bound-identity-per-phase",
    )?;

    let phases = array_field(build, "phases")?;
    ensure!(
        phases.len() == 2,
        "JVM deterministic build must contain exactly two phases"
    );
    let application = &phases[0];
    require_string_eq(application, "phase", "application-intermediate")?;
    let application_step = field(application, "step")?;
    validate_direct_step(application_step, "/src")?;
    validate_step_executable_role(application_step, toolchain, "build-driver")?;
    require_string_eq(
        field(application, "output")?,
        "role",
        "application-intermediate",
    )?;
    require_string_eq(
        field(application, "output")?,
        "containerPath",
        "/out/application.jar",
    )?;

    let packaging = &phases[1];
    require_string_eq(packaging, "phase", "copy-only-packaging")?;
    let input_layout = field(packaging, "inputLayout")?;
    require_string_eq(
        input_layout,
        "policy",
        "eip0045-b4-jvm-copy-only-phase-input-v1",
    )?;
    require_string_eq(
        input_layout,
        "manifestPath",
        "/phase-input/inclusion-manifest.json",
    )?;
    require_string_eq(input_layout, "archiveRoot", "/phase-input/archives")?;
    let packaging_step = field(packaging, "step")?;
    validate_direct_step(packaging_step, "/phase-input")?;
    validate_step_executable_role(packaging_step, toolchain, "packager")?;
    let arguments = array_field(packaging_step, "arguments")?;
    ensure!(
        arguments.len() == JVM_COPY_ONLY_PACKAGER_ARGUMENTS.len(),
        "JVM COPY-ONLY packager argument count drift"
    );
    for (actual, expected) in arguments.iter().zip(JVM_COPY_ONLY_PACKAGER_ARGUMENTS) {
        ensure!(
            actual.as_str() == Some(expected),
            "JVM COPY-ONLY packager argument vector drift"
        );
    }
    require_string_eq(field(packaging, "output")?, "role", "validator-artifact")?;
    require_string_eq(
        field(packaging, "output")?,
        "containerPath",
        "/out/validator.jar",
    )?;

    let runner_policy = field(profile, "policy")?;
    ensure!(
        field(application_step, "workingDirectory")? == field(runner_policy, "workingDirectory")?,
        "JVM application phase working directory differs from the bound runner policy"
    );
    let packaging_policy = field(runner_policy, "packagingPhase")?;
    require_string_eq(packaging_policy, "phase", "copy-only-packaging")?;
    ensure!(
        field(packaging_step, "workingDirectory")? == field(packaging_policy, "workingDirectory")?,
        "JVM packaging phase working directory differs from the bound runner policy"
    );
    let packaging_mounts = array_field(packaging_policy, "mounts")?;
    ensure!(
        packaging_mounts.len() == 2
            && string_field(&packaging_mounts[0], "target")? == "/phase-input"
            && string_field(&packaging_mounts[1], "target")? == "/out",
        "JVM packaging runner mount projection drift"
    );
    Ok(())
}

fn validate_direct_step(step: &Value, working_directory: &str) -> Result<()> {
    require_string_eq(step, "shell", "none")?;
    require_string_eq(step, "workingDirectory", working_directory)?;
    string_field(step, "executable")?;
    Ok(())
}

fn validate_step_executable_role(step: &Value, toolchain: &Value, role: &str) -> Result<()> {
    let executable = string_field(step, "executable")?;
    let entries = array_field(toolchain, "entries")?
        .iter()
        .filter(|entry| string_field(entry, "role").ok() == Some(role))
        .collect::<Vec<_>>();
    ensure!(
        entries.len() == 1,
        "toolchain closure must contain exactly one {role} entry"
    );
    ensure!(
        string_field(entries[0], "imagePath")? == executable,
        "build step executable differs from the hashed {role} entry"
    );
    Ok(())
}

fn validate_inventory_order_and_bounds(descriptor: &Value) -> Result<()> {
    let lineage = field(descriptor, "implementationLineage")?;
    let source_files = array_field(lineage, "sourceFiles")?;
    let source_total = validate_sorted_paths(source_files, "path", "source inventory")?;
    ensure!(
        source_total <= MAX_SOURCE_BYTES,
        "source inventory exceeds aggregate byte bound"
    );
    validate_inventory_digest(
        lineage,
        "lineageSha256",
        LINEAGE_DIGEST_DOMAIN,
        &lineage_digest_preimage(lineage)?,
        "implementation lineage",
    )?;

    let dependencies = field(descriptor, "dependencyClosure")?;
    let entries = array_field(dependencies, "entries")?;
    let mut previous_key: Option<String> = None;
    let mut paths = BTreeSet::new();
    let mut dependency_total = artifact_length(field(dependencies, "lockfile")?)?;
    ensure!(
        paths.insert(string_field(field(dependencies, "lockfile")?, "path")?),
        "duplicate dependency artifact path"
    );
    for entry in entries {
        let key = format!(
            "{}\0{}\0{}\0{}",
            string_field(entry, "ecosystem")?,
            string_field(entry, "name")?,
            string_field(entry, "version")?,
            string_field(entry, "origin")?
        );
        if let Some(previous) = &previous_key {
            ensure!(
                previous < &key,
                "dependency keys are not strictly increasing"
            );
        }
        previous_key = Some(key);
        let artifact = field(entry, "artifact")?;
        ensure!(
            paths.insert(string_field(artifact, "path")?),
            "duplicate dependency artifact path"
        );
        dependency_total = dependency_total
            .checked_add(artifact_length(artifact)?)
            .context("dependency aggregate byte count overflow")?;
    }
    ensure!(
        dependency_total <= MAX_DEPENDENCY_BYTES,
        "dependency closure exceeds aggregate byte bound"
    );
    validate_inventory_digest(
        dependencies,
        "closureSha256",
        DEPENDENCY_DIGEST_DOMAIN,
        &dependency_digest_preimage(dependencies)?,
        "dependency closure",
    )?;

    let toolchain_closure = field(descriptor, "toolchainClosure")?;
    let toolchains = array_field(toolchain_closure, "entries")?;
    let mut previous_name: Option<&str> = None;
    let mut image_paths = BTreeSet::new();
    let mut toolchain_total = 0_u64;
    for entry in toolchains {
        let name = string_field(entry, "name")?;
        if let Some(previous) = previous_name {
            ensure!(
                previous < name,
                "toolchain names are not strictly increasing"
            );
        }
        previous_name = Some(name);
        ensure!(
            image_paths.insert(string_field(entry, "imagePath")?),
            "duplicate toolchain image path"
        );
        toolchain_total = toolchain_total
            .checked_add(u64_field(entry, "byteLength")?)
            .context("toolchain aggregate byte count overflow")?;
    }
    ensure!(
        toolchain_total <= MAX_TOOLCHAIN_BYTES,
        "toolchain inventory exceeds aggregate byte bound"
    );
    validate_inventory_digest(
        toolchain_closure,
        "closureSha256",
        TOOLCHAIN_DIGEST_DOMAIN,
        &toolchain_digest_preimage(toolchain_closure)?,
        "toolchain closure",
    )?;
    Ok(())
}

fn lineage_digest_preimage(lineage: &Value) -> Result<Value> {
    Ok(json!({
        "method": field(lineage, "method")?,
        "sharedVerifierImplementation": field(lineage, "sharedVerifierImplementation")?,
        "sourceFiles": field(lineage, "sourceFiles")?
    }))
}

fn dependency_digest_preimage(closure: &Value) -> Result<Value> {
    Ok(json!({
        "method": field(closure, "method")?,
        "lockfile": field(closure, "lockfile")?,
        "entries": field(closure, "entries")?
    }))
}

fn toolchain_digest_preimage(closure: &Value) -> Result<Value> {
    Ok(json!({
        "method": field(closure, "method")?,
        "entries": field(closure, "entries")?
    }))
}

fn validate_inventory_digest(
    container: &Value,
    field_name: &str,
    domain: &[u8],
    preimage: &Value,
    label: &str,
) -> Result<()> {
    let expected = domain_separated_jcs_sha256(domain, preimage)?;
    ensure!(
        string_field(container, field_name)? == expected,
        "{label} digest differs from its domain-separated canonical preimage"
    );
    Ok(())
}

fn domain_separated_jcs_sha256(domain: &[u8], value: &Value) -> Result<String> {
    let canonical = canonical_json_bytes(value)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}

fn validate_sorted_paths(entries: &[Value], key: &str, label: &str) -> Result<u64> {
    let mut previous: Option<&str> = None;
    let mut total = 0_u64;
    for entry in entries {
        let path = string_field(entry, key)?;
        if let Some(prior) = previous {
            ensure!(prior < path, "{label} paths are not strictly increasing");
        }
        previous = Some(path);
        total = total
            .checked_add(u64_field(entry, "byteLength")?)
            .with_context(|| format!("{label} aggregate byte count overflow"))?;
    }
    Ok(total)
}

fn validate_seccomp_document(document: &Value, label: &str) -> Result<()> {
    require_format(document, "Eip0045B4PositiveSeccompV1", 1)?;
    require_exact_keys(
        document,
        &["format", "formatVersion", "linuxSeccomp"],
        &format!("{label} seccomp document"),
    )?;
    let seccomp = field(document, "linuxSeccomp")?;
    require_exact_keys(
        seccomp,
        &[
            "defaultAction",
            "defaultErrnoRet",
            "architectures",
            "flags",
            "syscalls",
        ],
        &format!("{label} linuxSeccomp"),
    )?;
    require_string_eq(seccomp, "defaultAction", "SCMP_ACT_ERRNO")?;
    require_u64_eq(seccomp, "defaultErrnoRet", 1)?;
    ensure!(
        array_field(seccomp, "architectures")? == [json!("SCMP_ARCH_X86_64")],
        "{label} seccomp architecture vector drift"
    );
    ensure!(
        array_field(seccomp, "flags")?.is_empty(),
        "{label} seccomp flags are not empty"
    );
    let rules = array_field(seccomp, "syscalls")?;
    ensure!(
        rules.len() == 1,
        "{label} seccomp document must contain exactly one syscall rule"
    );
    let rule = &rules[0];
    require_exact_keys(
        rule,
        &["names", "action", "args"],
        &format!("{label} seccomp allow rule"),
    )?;
    require_string_eq(rule, "action", "SCMP_ACT_ALLOW")?;
    ensure!(
        array_field(rule, "args")?.is_empty(),
        "{label} seccomp allow rule carries argument filters"
    );
    let syscalls = array_field(rule, "names")?;
    ensure!(
        (1..=256).contains(&syscalls.len()),
        "{label} seccomp syscall cardinality is outside the closed bound"
    );
    let mut previous: Option<&str> = None;
    for syscall in syscalls {
        let name = syscall
            .as_str()
            .with_context(|| format!("{label} seccomp syscall is not a string"))?;
        ensure!(
            !name.is_empty()
                && name.len() <= 64
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'),
            "{label} seccomp syscall name is not canonical"
        );
        if let Some(prior) = previous {
            ensure!(
                prior < name,
                "{label} seccomp syscalls are not strictly increasing"
            );
        }
        previous = Some(name);
    }
    Ok(())
}

fn validate_seccomp_binding(runner: &Value, document: &BoundDocument, label: &str) -> Result<()> {
    let binding = field(runner, "seccomp")?;
    require_exact_keys(
        binding,
        &["policy", "format", "profile", "allowedSyscalls"],
        &format!("{label} seccomp runner projection"),
    )?;
    require_string_eq(binding, "policy", "eip0045-b4-positive-seccomp-v1")?;
    require_string_eq(binding, "format", "Eip0045B4PositiveSeccompV1")?;
    ensure!(
        field(binding, "profile")? == &document.identity_with_path("Eip0045B4PositiveSeccompV1"),
        "{label} seccomp document identity is stale"
    );
    let rules = array_field(field(&document.value, "linuxSeccomp")?, "syscalls")?;
    ensure!(
        field(binding, "allowedSyscalls")? == field(&rules[0], "names")?,
        "{label} seccomp syscall projection differs from the bound document"
    );
    Ok(())
}

fn validate_jvm_options(profile: &Value) -> Result<()> {
    let options = array_field(field(profile, "javaRuntime")?, "options")?;
    ensure!(
        options.len() == JVM_OPTIONS.len(),
        "JVM runner option count drift"
    );
    for (actual, expected) in options.iter().zip(JVM_OPTIONS) {
        ensure!(
            actual.as_str() == Some(expected),
            "JVM runner option vector drift"
        );
    }
    Ok(())
}

fn v2_canonical_role(role: PositiveRunnerRole) -> &'static str {
    match role {
        PositiveRunnerRole::RustValidatorBuild => "RustValidatorBuild",
        PositiveRunnerRole::JvmValidatorBuild => "JvmValidatorBuild",
        PositiveRunnerRole::RustVerifier => "RustVerifier",
        PositiveRunnerRole::JvmVerifier => "JvmVerifier",
    }
}

#[allow(dead_code)]
fn validate_v2_runner_profile(profile: &Value, role: PositiveRunnerRole) -> Result<()> {
    validate_json_schema(
        profile,
        EmbeddedSchema::RunnerProfileV2,
        "V2 runner profile",
    )?;
    require_format(profile, "Eip0045B4PositiveOciRunnerProfileV2", 2)?;
    require_role(profile, role, "V2 runner profile")?;
    validate_runner_profile_with_metadata_policy(
        profile,
        role.purpose(),
        RETAINED_HOST_ROOTFS_METADATA_POLICY_V2_ID,
    )?;

    let image = field(profile, "image")?;
    require_string_eq(
        image,
        "retainedHostRootfsMetadataPolicy",
        RETAINED_HOST_ROOTFS_METADATA_POLICY_V2_ID,
    )?;

    let provider = field(profile, "retainedHostRootfsMetadataProvider")?;
    require_exact_keys(
        provider,
        &[
            "metadataPolicy",
            "providerProfile",
            "sessionProtocol",
            "applianceProfile",
            "expectedModeTableSha256",
            "canonicalRole",
        ],
        "V2 retained-host rootfs metadata provider binding",
    )?;
    require_string_eq(
        provider,
        "metadataPolicy",
        RETAINED_HOST_ROOTFS_METADATA_POLICY_V2_ID,
    )?;
    ensure!(
        field(provider, "metadataPolicy")? == field(image, "retainedHostRootfsMetadataPolicy")?,
        "V2 metadata-policy binding differs from the image policy"
    );
    require_string_eq(
        provider,
        "providerProfile",
        TMPFS_METADATA_PROVIDER_PROFILE_ID,
    )?;
    require_string_eq(
        provider,
        "sessionProtocol",
        SUPERVISED_FILESYSTEM_SESSION_PROTOCOL_ID,
    )?;
    require_string_eq(provider, "applianceProfile", BUILDROOT_APPLIANCE_PROFILE_ID)?;
    require_string_eq(provider, "canonicalRole", v2_canonical_role(role))?;
    let table_digest = string_field(provider, "expectedModeTableSha256")?;
    ensure!(
        table_digest.len() == 64
            && table_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "V2 expected-mode-table SHA-256 is not lower-case hexadecimal"
    );
    Ok(())
}

#[derive(Debug)]
struct V2InputIdentityBindings {
    input_set: BoundDocument,
    runner_profiles: [BoundDocument; 4],
    validator_descriptors: [BoundDocument; 2],
}

#[derive(Debug)]
struct V2GenerationBindings {
    provenance: V2InputIdentityBindings,
    generation_set: BoundDocument,
    cases: [BoundGenerationCase; POSITIVE_CASE_COUNT],
}

const H0_ARTIFACT_IDENTITY_DOMAIN_V1: &[u8] = b"eip0045-b4-artifact-identity-commitment-v1\0";
const H0_OCI_IMAGE_LAYOUT_DOMAIN_V1: &[u8] = b"eip0045-b4-oci-image-layout-commitment-v1\0";
const H0_ROOTFS_PLAN_DOMAIN_V1: &[u8] = b"eip0045-b4-rootfs-plan-commitment-v1\0";
const H0_ROLE_BLOCK_BYTES_V1: usize = 1 + 3 * DIGEST_BYTES;

#[allow(
    dead_code,
    reason = "the opaque projection retains exact path-qualified preimages for the later G0 join"
)]
struct B4H0ArtifactIdentityPreimageV1 {
    encoded: Vec<u8>,
    commitment: [u8; DIGEST_BYTES],
}

#[allow(
    dead_code,
    reason = "descriptor identities remain retained but are intentionally absent from the G0 request wire"
)]
struct B4H0PathQualifiedJcsPreimageV1 {
    format: &'static str,
    path: String,
    byte_length: u64,
    sha256: [u8; DIGEST_BYTES],
    encoding: u8,
}

/// One opaque canonical-role block in the non-authorizing H0 request projection.
///
/// Its private fields retain the complete runner and archive identity preimages
/// plus the exact OCI and rootfs-plan preimages. Only the three commitments
/// required by G0 are exposed inside this crate.
pub struct B4H0RoleRequestProjectionV1 {
    role: PositiveRunnerRole,
    runner_identity: B4H0ArtifactIdentityPreimageV1,
    #[allow(
        dead_code,
        reason = "the archive identity preimage remains custody evidence for ingress remeasurement"
    )]
    archive_identity: B4H0ArtifactIdentityPreimageV1,
    #[allow(
        dead_code,
        reason = "the exact OCI preimage is retained so the commitment is never a detached digest"
    )]
    oci_layout_preimage: Vec<u8>,
    oci_layout_commitment: [u8; DIGEST_BYTES],
    #[allow(
        dead_code,
        reason = "the exact rootfs-plan preimage is retained so the commitment is never a detached digest"
    )]
    rootfs_plan_preimage: Vec<u8>,
    rootfs_plan_commitment: [u8; DIGEST_BYTES],
}

#[allow(
    dead_code,
    reason = "these fixed projections are consumed by the later crate-private G0 request join"
)]
impl B4H0RoleRequestProjectionV1 {
    pub(crate) const fn role(&self) -> PositiveRunnerRole {
        self.role
    }

    pub(crate) const fn runner_ai(&self) -> [u8; DIGEST_BYTES] {
        self.runner_identity.commitment
    }

    pub(crate) const fn oci_layout_commitment(&self) -> [u8; DIGEST_BYTES] {
        self.oci_layout_commitment
    }

    pub(crate) const fn rootfs_plan_commitment(&self) -> [u8; DIGEST_BYTES] {
        self.rootfs_plan_commitment
    }

    fn encode(&self) -> [u8; H0_ROLE_BLOCK_BYTES_V1] {
        let mut block = [0_u8; H0_ROLE_BLOCK_BYTES_V1];
        block[0] = u8::try_from(self.role.index())
            .expect("the four canonical positive runner roles fit one byte");
        block[1..33].copy_from_slice(&self.runner_identity.commitment);
        block[33..65].copy_from_slice(&self.oci_layout_commitment);
        block[65..97].copy_from_slice(&self.rootfs_plan_commitment);
        block
    }
}

/// Opaque authority-rooted projection of the exact A+ inputs required by G0.
///
/// This value is derived only while consuming the same complete semantic and
/// physical V2 closure used by the affine generation authority. It is neither
/// H0 authority nor evidence of archive custody, filesystem observation,
/// runtime execution, publication, or a live session. It has no public
/// constructor, decoder, serializer, or conversion from detached commitments.
pub struct B4H0RequestProjectionV1 {
    positive_input_set_identity: B4H0ArtifactIdentityPreimageV1,
    positive_generation_set_identity: B4H0ArtifactIdentityPreimageV1,
    role_blocks: [B4H0RoleRequestProjectionV1; 4],
    #[allow(
        dead_code,
        reason = "A+ retains both descriptor preimages although the G0 request does not repeat them"
    )]
    validator_descriptor_preimages: [B4H0PathQualifiedJcsPreimageV1; 2],
}

#[allow(
    dead_code,
    reason = "these fixed projections are consumed by the later crate-private G0 request join"
)]
impl B4H0RequestProjectionV1 {
    /// Return the non-authorizing artifact-identity commitment for the input set.
    #[must_use]
    pub const fn positive_input_set_ai(&self) -> [u8; DIGEST_BYTES] {
        self.positive_input_set_identity.commitment
    }

    /// Return the non-authorizing artifact-identity commitment for the generation set.
    #[must_use]
    pub const fn positive_generation_set_ai(&self) -> [u8; DIGEST_BYTES] {
        self.positive_generation_set_identity.commitment
    }

    pub(crate) const fn role_blocks(&self) -> &[B4H0RoleRequestProjectionV1; 4] {
        &self.role_blocks
    }

    /// Encode the four canonical role blocks required by the G0 request preimage.
    #[must_use]
    pub fn encoded_role_blocks(&self) -> [[u8; H0_ROLE_BLOCK_BYTES_V1]; 4] {
        std::array::from_fn(|index| self.role_blocks[index].encode())
    }
}

fn h0_sha256(bytes: &[u8]) -> [u8; DIGEST_BYTES] {
    Sha256::digest(bytes).into()
}

fn h0_artifact_identity(
    kind: u8,
    encoding: u8,
    path: &str,
    byte_length: u64,
    sha256: [u8; DIGEST_BYTES],
) -> Result<B4H0ArtifactIdentityPreimageV1> {
    ensure!(
        matches!((kind, encoding), (0..=5, 1) | (8, 3)),
        "H0 artifact kind and encoding are not a closed compatible pair"
    );
    validate_safe_relative_path(path).context("H0 artifact identity path is not canonical")?;
    let path_length = u16::try_from(path.len()).context("H0 artifact path length exceeds u16")?;
    let exact_length = 87_usize
        .checked_add(path.len())
        .context("H0 artifact identity preimage length overflow")?;
    let mut encoded = Vec::with_capacity(exact_length);
    encoded.extend_from_slice(H0_ARTIFACT_IDENTITY_DOMAIN_V1);
    encoded.push(kind);
    encoded.push(encoding);
    encoded.extend_from_slice(&path_length.to_le_bytes());
    encoded.extend_from_slice(path.as_bytes());
    encoded.extend_from_slice(&byte_length.to_le_bytes());
    encoded.extend_from_slice(&sha256);
    ensure!(
        encoded.len() == exact_length,
        "H0 artifact identity preimage length drift"
    );
    let commitment = h0_sha256(&encoded);
    Ok(B4H0ArtifactIdentityPreimageV1 {
        encoded,
        commitment,
    })
}

fn h0_document_identity(
    document: &BoundDocument,
    format: &'static str,
) -> Result<B4H0PathQualifiedJcsPreimageV1> {
    validate_safe_relative_path(&document.relative_path)
        .context("H0 retained document identity path is not canonical")?;
    Ok(B4H0PathQualifiedJcsPreimageV1 {
        format,
        path: document.relative_path.clone(),
        byte_length: u64::try_from(document.bytes.len())
            .context("H0 retained document length exceeds u64")?,
        sha256: decode_digest(&document.sha256, "H0 retained document SHA-256")?,
        encoding: 1,
    })
}

fn h0_document_artifact_identity(
    document: &BoundDocument,
    kind: u8,
) -> Result<B4H0ArtifactIdentityPreimageV1> {
    h0_artifact_identity(
        kind,
        1,
        &document.relative_path,
        u64::try_from(document.bytes.len()).context("H0 canonical document length exceeds u64")?,
        h0_sha256(&document.bytes),
    )
}

fn validate_h0_rootfs_requirement_path(path: &str) -> Result<()> {
    ensure!(
        (1..=240).contains(&path.len()) && path.is_ascii(),
        "H0 rootfs requirement path length or encoding is invalid"
    );
    ensure!(
        path.starts_with('/') && !path.ends_with('/') && !path.contains("//"),
        "H0 rootfs requirement path has a non-canonical separator"
    );
    ensure!(
        !path.as_bytes().contains(&0),
        "H0 rootfs requirement path contains NUL"
    );
    for segment in path[1..].split('/') {
        ensure!(
            !segment.is_empty() && segment != "." && segment != "..",
            "H0 rootfs requirement path contains an empty, dot, or parent segment"
        );
    }
    Ok(())
}

fn derive_h0_role_request_projection(
    profile: &BoundDocument,
    role: PositiveRunnerRole,
) -> Result<B4H0RoleRequestProjectionV1> {
    let role_byte = u8::try_from(role.index()).context("H0 runner role exceeds one byte")?;
    let runner_kind = 2_u8
        .checked_add(role_byte)
        .context("H0 runner artifact kind overflow")?;
    let runner_identity = h0_document_artifact_identity(profile, runner_kind)?;
    let image = field(&profile.value, "image")?;
    let archive = field(image, "archive")?;
    let archive_identity = h0_artifact_identity(
        8,
        3,
        string_field(archive, "path")?,
        u64_field(archive, "byteLength")?,
        decode_digest(string_field(archive, "sha256")?, "H0 OCI archive SHA-256")?,
    )?;

    let manifest = field(image, "manifest")?;
    let config = field(image, "config")?;
    let layers = array_field(image, "layers")?;
    ensure!(
        (1..=128).contains(&layers.len()),
        "H0 OCI layer cardinality is outside the closed bound"
    );
    let oci_length = 157_usize
        .checked_add(
            80_usize
                .checked_mul(layers.len())
                .context("H0 OCI layer preimage length overflow")?,
        )
        .context("H0 OCI preimage length overflow")?;
    let mut oci_layout_preimage = Vec::with_capacity(oci_length);
    oci_layout_preimage.extend_from_slice(H0_OCI_IMAGE_LAYOUT_DOMAIN_V1);
    oci_layout_preimage.push(role_byte);
    oci_layout_preimage.extend_from_slice(&archive_identity.commitment);
    oci_layout_preimage.extend_from_slice(&decode_oci_sha256_digest(
        string_field(manifest, "digest")?,
        "H0 OCI manifest digest",
    )?);
    oci_layout_preimage.extend_from_slice(&u64_field(manifest, "size")?.to_le_bytes());
    oci_layout_preimage.extend_from_slice(&decode_oci_sha256_digest(
        string_field(config, "digest")?,
        "H0 OCI config digest",
    )?);
    oci_layout_preimage.extend_from_slice(&u64_field(config, "size")?.to_le_bytes());
    oci_layout_preimage.extend_from_slice(
        &u16::try_from(layers.len())
            .context("H0 OCI layer count exceeds u16")?
            .to_le_bytes(),
    );
    for (index, layer) in layers.iter().enumerate() {
        oci_layout_preimage.extend_from_slice(&decode_oci_sha256_digest(
            string_field(layer, "digest")?,
            &format!("H0 OCI layer {index} compressed digest"),
        )?);
        oci_layout_preimage.extend_from_slice(&u64_field(layer, "size")?.to_le_bytes());
        oci_layout_preimage
            .extend_from_slice(&u64_field(layer, "uncompressedBytes")?.to_le_bytes());
        oci_layout_preimage.extend_from_slice(&decode_oci_sha256_digest(
            string_field(layer, "diffId")?,
            &format!("H0 OCI layer {index} DiffID"),
        )?);
    }
    ensure!(
        oci_layout_preimage.len() == oci_length,
        "H0 OCI image-layout preimage length drift"
    );
    let oci_layout_commitment = h0_sha256(&oci_layout_preimage);

    let requirements = project_positive_rootfs_path_requirements(profile, role)?;
    ensure!(
        (1..=16).contains(&requirements.len()),
        "H0 rootfs requirement cardinality is outside the closed bound"
    );
    let mut prior_path: Option<&str> = None;
    let mut rootfs_length = 112_usize;
    for requirement in &requirements {
        validate_h0_rootfs_requirement_path(&requirement.image_path)?;
        if let Some(prior) = prior_path {
            ensure!(
                prior.as_bytes() < requirement.image_path.as_bytes(),
                "H0 rootfs requirements are not unique and byte-sorted"
            );
        }
        prior_path = Some(&requirement.image_path);
        rootfs_length = rootfs_length
            .checked_add(
                3_usize
                    .checked_add(requirement.image_path.len())
                    .context("H0 rootfs requirement preimage length overflow")?,
            )
            .context("H0 rootfs-plan preimage length overflow")?;
    }
    let provider = field(&profile.value, "retainedHostRootfsMetadataProvider")?;
    let rootfs = field(image, "postChangesetRootfs")?;
    let mut rootfs_plan_preimage = Vec::with_capacity(rootfs_length);
    rootfs_plan_preimage.extend_from_slice(H0_ROOTFS_PLAN_DOMAIN_V1);
    rootfs_plan_preimage.push(role_byte);
    rootfs_plan_preimage.extend_from_slice(&decode_digest(
        string_field(provider, "expectedModeTableSha256")?,
        "H0 expected-mode-table SHA-256",
    )?);
    for field_name in [
        "entryCount",
        "regularFileCount",
        "directoryCount",
        "symbolicLinkCount",
        "regularFileBytes",
    ] {
        rootfs_plan_preimage.extend_from_slice(&u64_field(rootfs, field_name)?.to_le_bytes());
    }
    rootfs_plan_preimage.extend_from_slice(
        &u16::try_from(requirements.len())
            .context("H0 rootfs requirement count exceeds u16")?
            .to_le_bytes(),
    );
    for requirement in &requirements {
        rootfs_plan_preimage.push(match requirement.kind {
            B4PositiveRootfsPathKindV1::Directory => 0,
            B4PositiveRootfsPathKindV1::EmptyRegular => 1,
        });
        rootfs_plan_preimage.extend_from_slice(
            &u16::try_from(requirement.image_path.len())
                .context("H0 rootfs requirement path length exceeds u16")?
                .to_le_bytes(),
        );
        rootfs_plan_preimage.extend_from_slice(requirement.image_path.as_bytes());
    }
    ensure!(
        rootfs_plan_preimage.len() == rootfs_length,
        "H0 rootfs-plan preimage length drift"
    );
    let rootfs_plan_commitment = h0_sha256(&rootfs_plan_preimage);

    Ok(B4H0RoleRequestProjectionV1 {
        role,
        runner_identity,
        archive_identity,
        oci_layout_preimage,
        oci_layout_commitment,
        rootfs_plan_preimage,
        rootfs_plan_commitment,
    })
}

fn derive_h0_request_projection(
    semantic: &V2GenerationBindings,
) -> Result<B4H0RequestProjectionV1> {
    let role_blocks = PositiveRunnerRole::all()
        .into_iter()
        .enumerate()
        .map(|(index, role)| {
            derive_h0_role_request_projection(&semantic.provenance.runner_profiles[index], role)
        })
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_: Vec<_>| anyhow::anyhow!("H0 role-block cardinality drift"))?;
    let validator_descriptor_preimages = semantic
        .provenance
        .validator_descriptors
        .iter()
        .map(|document| {
            h0_document_identity(
                document,
                V2PositiveDocumentKind::ValidatorDescriptor.format(),
            )
        })
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_: Vec<_>| anyhow::anyhow!("H0 descriptor-preimage cardinality drift"))?;
    Ok(B4H0RequestProjectionV1 {
        positive_input_set_identity: h0_document_artifact_identity(
            &semantic.provenance.input_set,
            0,
        )?,
        positive_generation_set_identity: h0_document_artifact_identity(
            &semantic.generation_set,
            1,
        )?,
        role_blocks,
        validator_descriptor_preimages,
    })
}

/// Opaque affine predecessor for one V2 positive-generation authority.
///
/// This value exists only after the complete Task 2 semantic closure and the
/// complete A+ physical source closure agree on the exact input and generation
/// documents. It is pre-acceptance and grants no campaign, session, provider,
/// H0, or filesystem authority.
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_positive_gate::
///     B4ValidatedPositiveGenerationPreacceptanceV2;
/// fn require_clone<T: Clone>() {}
/// require_clone::<B4ValidatedPositiveGenerationPreacceptanceV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_positive_gate::
///     B4ValidatedPositiveGenerationPreacceptanceV2;
/// fn require_copy<T: Copy>() {}
/// require_copy::<B4ValidatedPositiveGenerationPreacceptanceV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_positive_gate::
///     B4ValidatedPositiveGenerationPreacceptanceV2;
/// fn require_default<T: Default>() {}
/// require_default::<B4ValidatedPositiveGenerationPreacceptanceV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_positive_gate::
///     B4ValidatedPositiveGenerationPreacceptanceV2;
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<B4ValidatedPositiveGenerationPreacceptanceV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_positive_gate::
///     B4ValidatedPositiveGenerationPreacceptanceV2;
/// fn require_deserialize<T: serde::de::DeserializeOwned>() {}
/// require_deserialize::<B4ValidatedPositiveGenerationPreacceptanceV2>();
/// ```
pub struct B4ValidatedPositiveGenerationPreacceptanceV2 {
    #[allow(
        dead_code,
        reason = "the affine token retains the complete semantic proof while downstream consumers expose only its joined physical views"
    )]
    semantic: V2GenerationBindings,
    physical: B4PositiveGenerationPhysicalBindingsV2,
}

impl B4ValidatedPositiveGenerationPreacceptanceV2 {
    pub(crate) const fn physical(&self) -> &B4PositiveGenerationPhysicalBindingsV2 {
        &self.physical
    }

    pub(crate) fn derive_h0_request_projection(&self) -> Result<B4H0RequestProjectionV1> {
        ensure!(
            self.semantic.provenance.input_set.contract_identity() == *self.physical.input_set(),
            "H0 projection semantic and physical branches bind different positive input sets"
        );
        ensure!(
            self.semantic.generation_set.contract_identity() == *self.physical.generation_set(),
            "H0 projection semantic and physical branches bind different positive generation sets"
        );
        derive_h0_request_projection(&self.semantic)
    }
}

#[allow(clippy::too_many_lines)]
fn bind_v2_input_identity_closure(
    authoritative_build: &AuthoritativeB4BuildProjection,
    input_set: NamedCanonicalJcs<'_>,
    runner_profiles: [NamedCanonicalJcs<'_>; 4],
    validator_descriptors: [NamedCanonicalJcs<'_>; 2],
) -> Result<V2InputIdentityBindings> {
    let input_set = BoundDocument::parse(input_set, "V2 positive input set")?;
    validate_json_schema(
        &input_set.value,
        V2PositiveDocumentKind::InputSet.schema(),
        "V2 positive input set",
    )?;
    require_format(
        &input_set.value,
        V2PositiveDocumentKind::InputSet.format(),
        2,
    )?;

    let runner_profiles: [BoundDocument; 4] = runner_profiles
        .into_iter()
        .enumerate()
        .map(|(index, named)| {
            let role = PositiveRunnerRole::all()[index];
            let label = format!("V2 {} runner profile", role.purpose());
            let document = BoundDocument::parse(named, &label)?;
            validate_json_schema(
                &document.value,
                V2PositiveDocumentKind::RunnerProfile.schema(),
                &label,
            )?;
            require_format(
                &document.value,
                V2PositiveDocumentKind::RunnerProfile.format(),
                2,
            )?;
            require_role(&document.value, role, "V2 runner profile")?;
            Ok(document)
        })
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("V2 runner-profile cardinality drift"))?;

    let validator_descriptors: [BoundDocument; 2] = validator_descriptors
        .into_iter()
        .enumerate()
        .map(|(index, named)| {
            let implementation = if index == 0 {
                PositiveImplementation::RustReference
            } else {
                PositiveImplementation::IndependentJvm
            };
            let label = format!(
                "V2 {} validator descriptor",
                implementation.implementation()
            );
            let document = BoundDocument::parse(named, &label)?;
            validate_json_schema(
                &document.value,
                V2PositiveDocumentKind::ValidatorDescriptor.schema(),
                &label,
            )?;
            require_format(
                &document.value,
                V2PositiveDocumentKind::ValidatorDescriptor.format(),
                2,
            )?;
            require_string_eq(
                &document.value,
                "implementation",
                implementation.implementation(),
            )?;
            require_string_eq(
                &document.value,
                "implementationLanguage",
                implementation.language(),
            )?;
            Ok(document)
        })
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("V2 validator-descriptor cardinality drift"))?;

    let mut document_paths = BTreeSet::new();
    ensure!(
        document_paths.insert(input_set.relative_path.as_str()),
        "V2 input-set path aliases another identity document"
    );
    for runner in &runner_profiles {
        ensure!(
            document_paths.insert(runner.relative_path.as_str()),
            "V2 runner-profile path aliases another identity document"
        );
    }
    for descriptor in &validator_descriptors {
        ensure!(
            document_paths.insert(descriptor.relative_path.as_str()),
            "V2 validator-descriptor path aliases another identity document"
        );
    }

    let input_profiles = array_field(&input_set.value, "runnerProfiles")?;
    ensure!(
        input_profiles.len() == 4,
        "V2 input set must bind exactly four runner profiles"
    );
    for (index, role) in PositiveRunnerRole::all().into_iter().enumerate() {
        require_role(&input_profiles[index], role, "V2 input-set runner profile")?;
        let expected = runner_profiles[index]
            .identity_with_path(V2PositiveDocumentKind::RunnerProfile.format());
        ensure!(
            field(&input_profiles[index], "artifact")? == &expected,
            "V2 input-set {} runner-profile identity is stale",
            role.purpose()
        );
    }

    for (index, implementation) in [
        PositiveImplementation::RustReference,
        PositiveImplementation::IndependentJvm,
    ]
    .into_iter()
    .enumerate()
    {
        let descriptor = &validator_descriptors[index].value;
        let build_role = implementation.build_role();
        validate_profile_reference_with_format(
            field(field(descriptor, "deterministicBuild")?, "runnerProfile")?,
            build_role,
            &runner_profiles[build_role.index()],
            "V2 descriptor build runner",
            V2PositiveDocumentKind::RunnerProfile.format(),
        )?;
        let execution_role = implementation.execution_role();
        validate_profile_reference_with_format(
            field(field(descriptor, "executionEnvironment")?, "runnerProfile")?,
            execution_role,
            &runner_profiles[execution_role.index()],
            "V2 descriptor execution runner",
            V2PositiveDocumentKind::RunnerProfile.format(),
        )?;
    }

    let validators = array_field(&input_set.value, "validators")?;
    ensure!(
        validators.len() == 2,
        "V2 input set must bind exactly two validator descriptors"
    );
    for (index, implementation) in [
        PositiveImplementation::RustReference,
        PositiveImplementation::IndependentJvm,
    ]
    .into_iter()
    .enumerate()
    {
        require_u64_eq(&validators[index], "implementationIndex", index as u64)?;
        require_string_eq(
            &validators[index],
            "implementation",
            implementation.implementation(),
        )?;
        require_string_eq(&validators[index], "language", implementation.language())?;
        let expected = validator_descriptors[index]
            .identity_with_path(V2PositiveDocumentKind::ValidatorDescriptor.format());
        ensure!(
            field(&validators[index], "buildDescriptor")? == &expected,
            "V2 input-set validator descriptor identity is stale for {}",
            implementation.implementation()
        );
    }

    validate_authoritative_build_projection(&input_set.value, authoritative_build)?;
    for (index, role) in PositiveRunnerRole::all().into_iter().enumerate() {
        validate_v2_runner_profile(&runner_profiles[index].value, role)?;
    }
    for (index, implementation) in [
        PositiveImplementation::RustReference,
        PositiveImplementation::IndependentJvm,
    ]
    .into_iter()
    .enumerate()
    {
        validate_descriptor_with_runner_profile_format(
            &validator_descriptors[index].value,
            implementation,
            &runner_profiles,
            V2PositiveDocumentKind::RunnerProfile.format(),
        )?;
    }
    validate_non_alias_lineage_separation(&validator_descriptors)?;
    Ok(V2InputIdentityBindings {
        input_set,
        runner_profiles,
        validator_descriptors,
    })
}

#[allow(dead_code)]
fn validate_v2_input_identity_closure(
    authoritative_build: &AuthoritativeB4BuildProjection,
    input_set: NamedCanonicalJcs<'_>,
    runner_profiles: [NamedCanonicalJcs<'_>; 4],
    validator_descriptors: [NamedCanonicalJcs<'_>; 2],
) -> Result<()> {
    bind_v2_input_identity_closure(
        authoritative_build,
        input_set,
        runner_profiles,
        validator_descriptors,
    )
    .map(drop)
}

#[allow(clippy::too_many_lines)]
fn validate_v2_generation_set(
    provenance: V2InputIdentityBindings,
    documents: &PositiveGenerationDocuments<'_>,
) -> Result<V2GenerationBindings> {
    let generation_set =
        BoundDocument::parse(documents.generation_set, "V2 positive generation set")?;
    validate_json_schema(
        &generation_set.value,
        V2PositiveDocumentKind::GenerationSet.schema(),
        "V2 positive generation set",
    )?;
    require_format(
        &generation_set.value,
        V2PositiveDocumentKind::GenerationSet.format(),
        2,
    )?;

    for prior in std::iter::once(&provenance.input_set)
        .chain(provenance.runner_profiles.iter())
        .chain(provenance.validator_descriptors.iter())
    {
        ensure!(
            !b4_paths_conflict(
                prior.relative_path.as_str(),
                generation_set.relative_path.as_str(),
            ),
            "V2 generation-set path aliases or ancestor/descendant-conflicts with a Task 1B identity document"
        );
    }

    let planned_cases = array_field(&provenance.input_set.value, "positiveCases")?;
    let generated_cases = array_field(&generation_set.value, "cases")?;
    ensure!(
        planned_cases.len() == POSITIVE_CASE_COUNT && generated_cases.len() == POSITIVE_CASE_COUNT,
        "V2 positive generation set must bind exactly eleven planned cases"
    );
    let calibrations = array_field(&provenance.input_set.value, "recursiveCalibrations")?;
    ensure!(
        calibrations.len() == 3,
        "V2 pre-proof input set must bind exactly three recursive calibrations"
    );

    ensure!(
        field(&generation_set.value, "inputSetCommitment")?
            == &provenance
                .input_set
                .commitment(V2PositiveDocumentKind::InputSet.format()),
        "V2 generation-set input-set commitment is stale"
    );
    ensure!(
        field(&generation_set.value, "proofGeneratorArtifact")?
            == &binary_commitment(field(
                field(&provenance.input_set.value, "proofGenerator")?,
                "artifact",
            )?)?,
        "V2 generation-set proof-generator artifact binding is stale"
    );
    validate_measurement(
        field(
            field(&provenance.input_set.value, "proofGenerator")?,
            "artifact",
        )?,
        &measure_bytes(documents.proof_generator_artifact),
        "V2 proof generator artifact",
    )?;

    let mut manifest_digests = BTreeSet::new();
    let mut raw_seal_digests = BTreeSet::new();
    let cases: [BoundGenerationCase; POSITIVE_CASE_COUNT] = planned_cases
        .iter()
        .zip(generated_cases)
        .zip(documents.cases.iter().copied())
        .enumerate()
        .map(|(index, ((planned, generated), physical))| {
            let bound =
                validate_generation_case_physical_bindings(index, planned, generated, physical)?;
            ensure!(
                manifest_digests.insert(bound.proof_output_manifest.sha256),
                "V2 positive generation set reuses a proof-output manifest digest"
            );
            ensure!(
                raw_seal_digests.insert(bound.raw_seal.sha256),
                "V2 positive generation set reuses a raw-seal digest"
            );
            Ok(bound)
        })
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("V2 positive generation-set cardinality drift"))?;
    for (index, generated) in generated_cases.iter().enumerate() {
        validate_generation_case_semantics(index, generated, &provenance.input_set.value)?;
    }

    Ok(V2GenerationBindings {
        provenance,
        generation_set,
        cases,
    })
}

/// Validate and bind the complete pre-acceptance V2 positive generation.
///
/// The semantic branch enforces the exact two validators, four runner roles,
/// three recursive calibrations, and eleven ordered cases. The independent
/// physical branch reopens every nested input source and every artifact of all
/// eleven exports. Success returns the sole opaque predecessor accepted by the
/// affine authority mint.
///
/// # Errors
///
/// Returns an error for any V2 schema, format, role, order, cardinality,
/// semantic, physical, path, digest, length, encoding, or cross-branch identity
/// mismatch.
#[allow(clippy::too_many_arguments)]
pub fn validate_and_bind_v2_positive_generation_preacceptance(
    authoritative_build: &AuthoritativeB4BuildProjection,
    input_set: NamedCanonicalJcs<'_>,
    runner_profiles: [NamedCanonicalJcs<'_>; 4],
    validator_descriptors: [NamedCanonicalJcs<'_>; 2],
    generation: PositiveGenerationDocuments<'_>,
    physical_source: B4PositiveGenerationExternalClosureV2<'_>,
) -> Result<B4ValidatedPositiveGenerationPreacceptanceV2> {
    let semantic = validate_v2_generation_set(
        bind_v2_input_identity_closure(
            authoritative_build,
            input_set,
            runner_profiles,
            validator_descriptors,
        )?,
        &generation,
    )?;
    let physical = B4PositiveGenerationPhysicalBindingsV2::from_external_closure(physical_source)?;
    ensure!(
        semantic.provenance.input_set.contract_identity() == *physical.input_set(),
        "V2 semantic and physical branches bind different positive input sets"
    );
    ensure!(
        semantic.generation_set.contract_identity() == *physical.generation_set(),
        "V2 semantic and physical branches bind different positive generation sets"
    );
    Ok(B4ValidatedPositiveGenerationPreacceptanceV2 { semantic, physical })
}

fn validate_v2_implementation_document_bindings(
    provenance: &V2InputIdentityBindings,
    binding: &Value,
    implementation: PositiveImplementation,
) -> Result<()> {
    let index = implementation.index();
    let descriptor = &provenance.validator_descriptors[index];
    let descriptor_value = &descriptor.value;
    require_u64_eq(binding, "implementationIndex", index as u64)?;
    require_string_eq(binding, "implementation", implementation.implementation())?;
    require_string_eq(binding, "language", implementation.language())?;

    ensure!(
        field(binding, "buildDescriptor")?
            == &descriptor.commitment(V2PositiveDocumentKind::ValidatorDescriptor.format()),
        "V2 acceptance descriptor commitment is stale"
    );
    let descriptor_artifact = field(descriptor_value, "artifact")?;
    ensure!(
        field(binding, "launchedArtifact")? == &binary_commitment(descriptor_artifact)?,
        "V2 acceptance launched-artifact binding is stale"
    );
    let role = implementation.execution_role();
    let profile = &provenance.runner_profiles[role.index()];
    let runner_binding = field(binding, "executionRunnerProfile")?;
    require_role(runner_binding, role, "V2 acceptance execution runner")?;
    ensure!(
        field(runner_binding, "artifact")?
            == &profile.commitment(V2PositiveDocumentKind::RunnerProfile.format()),
        "V2 acceptance execution-runner commitment is stale"
    );

    Ok(())
}

fn validate_v2_implementation_physical_bindings(
    provenance: &V2InputIdentityBindings,
    implementation: PositiveImplementation,
    launched_artifact: &FileMeasurement,
    java_binary: Option<&FileMeasurement>,
    java_release: Option<&FileMeasurement>,
) -> Result<()> {
    let descriptor_value = &provenance.validator_descriptors[implementation.index()].value;
    validate_measurement(
        field(descriptor_value, "artifact")?,
        launched_artifact,
        "V2 launched artifact",
    )?;

    match implementation {
        PositiveImplementation::RustReference => {
            ensure!(
                java_binary.is_none() && java_release.is_none(),
                "V2 Rust acceptance cannot carry Java measurements"
            );
        }
        PositiveImplementation::IndependentJvm => {
            let measured_java = java_binary.context("V2 JVM run lacks Java measurement")?;
            let measured_release =
                java_release.context("V2 JVM run lacks Java release measurement")?;
            let profile = &provenance.runner_profiles[implementation.execution_role().index()];
            let profile_java = field(&profile.value, "javaRuntime")?;
            validate_measurement(
                field(profile_java, "binary")?,
                measured_java,
                "V2 Java binary",
            )?;
            validate_measurement(
                field(profile_java, "release")?,
                measured_release,
                "V2 Java release",
            )?;
        }
    }
    Ok(())
}

fn validate_v2_implementation_semantics(
    provenance: &V2InputIdentityBindings,
    binding: &Value,
    implementation: PositiveImplementation,
) -> Result<()> {
    let descriptor_value = &provenance.validator_descriptors[implementation.index()].value;
    let profile = &provenance.runner_profiles[implementation.execution_role().index()];

    ensure!(
        field(binding, "lineageSha256")?
            == field(
                field(descriptor_value, "implementationLineage")?,
                "lineageSha256",
            )?,
        "V2 acceptance lineage binding is stale"
    );
    ensure!(
        field(binding, "reviewedSource")?
            == &reviewed_source_projection(field(descriptor_value, "reviewedSource")?)?,
        "V2 acceptance reviewed-source binding is stale"
    );

    match implementation {
        PositiveImplementation::RustReference => {
            ensure!(
                object(binding, "V2 Rust acceptance binding")?
                    .get("javaRuntime")
                    .is_none(),
                "V2 Rust acceptance cannot carry a Java runtime"
            );
        }
        PositiveImplementation::IndependentJvm => {
            let profile_java = field(&profile.value, "javaRuntime")?;
            ensure!(
                field(binding, "javaRuntime")? == &java_runtime_projection(profile_java)?,
                "V2 acceptance Java runtime binding is stale"
            );
        }
    }
    Ok(())
}

impl V2GenerationBindings {
    #[allow(clippy::too_many_lines)]
    fn validate_acceptance(&self, documents: &PositiveRunDocuments<'_>) -> Result<()> {
        for (label, bytes) in [
            ("V2 verifier input", documents.verifier_input_jcs),
            ("V2 observation", documents.observation_jcs),
            ("V2 acceptance", documents.acceptance_jcs),
        ] {
            ensure!(
                bytes.len() <= MAX_RUN_JCS_BYTES,
                "{label} exceeds the 64 KiB bound"
            );
        }

        let verifier_input = validate_canonical_json_source(documents.verifier_input_jcs)
            .context("V2 verifier input is not exact canonical JCS")?;
        let observation = validate_canonical_json_source(documents.observation_jcs)
            .context("V2 observation is not exact canonical JCS")?;
        let acceptance = validate_canonical_json_source(documents.acceptance_jcs)
            .context("V2 acceptance is not exact canonical JCS")?;

        validate_json_schema(
            &verifier_input,
            EmbeddedSchema::VerifierInput,
            "V2 verifier input",
        )?;
        validate_json_schema(&observation, EmbeddedSchema::Observation, "V2 observation")?;
        validate_json_schema(
            &acceptance,
            V2PositiveDocumentKind::Acceptance.schema(),
            "V2 acceptance",
        )?;
        require_format(&verifier_input, "Eip0045B4PositiveVerifierInputV1", 1)?;
        require_exact_keys(
            &verifier_input,
            &[
                "format",
                "formatVersion",
                "profileManifest",
                "profileAlgorithm",
                "profileConstants",
                "guestElf",
                "statement",
                "rawSeal",
            ],
            "V2 verifier input",
        )?;
        require_format(&observation, "Eip0045B4PositiveObservationV1", 1)?;
        require_format(&acceptance, V2PositiveDocumentKind::Acceptance.format(), 2)?;

        let case_index = usize::from(documents.trusted_case_index);
        require_u64_eq(
            &acceptance,
            "caseIndex",
            u64::from(documents.trusted_case_index),
        )?;
        let case = array_field(&self.provenance.input_set.value, "positiveCases")?
            .get(case_index)
            .context("trusted V2 positive case index is outside the input-set plan")?;
        let generated_case = array_field(&self.generation_set.value, "cases")?
            .get(case_index)
            .context("trusted V2 positive case index is outside the generation set")?;
        ensure!(
            field(&acceptance, "caseId")? == field(case, "caseId")?,
            "V2 acceptance case ID differs from the finalizer-held case plan"
        );
        let implementation_binding = field(&acceptance, "implementationBinding")?;
        require_u64_eq(
            implementation_binding,
            "implementationIndex",
            documents.trusted_implementation.index() as u64,
        )?;
        require_string_eq(
            implementation_binding,
            "implementation",
            documents.trusted_implementation.implementation(),
        )?;
        require_string_eq(
            implementation_binding,
            "language",
            documents.trusted_implementation.language(),
        )?;
        require_role(
            field(implementation_binding, "executionRunnerProfile")?,
            documents.trusted_implementation.execution_role(),
            "V2 acceptance execution runner",
        )?;

        ensure!(
            field(&acceptance, "inputSetCommitment")?
                == &self
                    .provenance
                    .input_set
                    .commitment(V2PositiveDocumentKind::InputSet.format()),
            "V2 acceptance input-set commitment is stale"
        );
        ensure!(
            field(&acceptance, "generationSetCommitment")?
                == &self
                    .generation_set
                    .commitment(V2PositiveDocumentKind::GenerationSet.format()),
            "V2 acceptance generation-set commitment is stale"
        );
        ensure!(
            field(&acceptance, "verifierInputCommitment")?
                == &jcs_commitment(
                    "Eip0045B4PositiveVerifierInputV1",
                    documents.verifier_input_jcs,
                ),
            "V2 acceptance verifier-input commitment is stale"
        );
        ensure!(
            field(&acceptance, "observationCommitment")?
                == &jcs_commitment("Eip0045B4PositiveObservationV1", documents.observation_jcs,),
            "V2 acceptance observation commitment is stale"
        );
        validate_v2_implementation_document_bindings(
            &self.provenance,
            implementation_binding,
            documents.trusted_implementation,
        )?;

        validate_v2_implementation_physical_bindings(
            &self.provenance,
            documents.trusted_implementation,
            &documents.launched_artifact,
            documents.java_binary.as_ref(),
            documents.java_release.as_ref(),
        )?;
        let verifier_measurements = documents.verifier_files.measurements();
        validate_verifier_physical_measurements(&verifier_input, &verifier_measurements)?;
        validate_measurement(
            field(&verifier_input, "rawSeal")?,
            &self.cases[case_index].raw_seal,
            "V2 generation-bound raw seal",
        )?;
        validate_generated_case_physical_bindings(
            generated_case,
            &self.cases[case_index],
            &verifier_input,
        )?;
        validate_verifier_input_bindings(&verifier_input, &self.provenance.input_set.value)?;

        validate_v2_implementation_semantics(
            &self.provenance,
            implementation_binding,
            documents.trusted_implementation,
        )?;
        ensure!(
            field(&acceptance, "observation")? == &observation,
            "V2 acceptance embeds a different observation"
        );

        let expected_observation = derive_expected_observation_from_bound_inputs(
            &documents.verifier_files,
            &self.provenance.input_set.value,
            case,
        )?;
        ensure!(
            documents.observation_jcs == expected_observation,
            "V2 verifier observation differs from the independently derived input semantics"
        );
        validate_terminal_against_case(&observation, case)?;
        validate_generated_case_semantics(generated_case, &observation)?;
        Ok(())
    }
}

#[allow(dead_code, clippy::too_many_arguments)]
fn validate_v2_generation_and_acceptance_identity_closure(
    authoritative_build: &AuthoritativeB4BuildProjection,
    input_set: NamedCanonicalJcs<'_>,
    runner_profiles: [NamedCanonicalJcs<'_>; 4],
    validator_descriptors: [NamedCanonicalJcs<'_>; 2],
    generation: &PositiveGenerationDocuments<'_>,
    acceptance: &PositiveRunDocuments<'_>,
) -> Result<()> {
    let provenance = bind_v2_input_identity_closure(
        authoritative_build,
        input_set,
        runner_profiles,
        validator_descriptors,
    )?;
    validate_v2_generation_set(provenance, generation)?.validate_acceptance(acceptance)
}

fn validate_runner_profile(profile: &Value, label: &str) -> Result<()> {
    validate_runner_profile_with_metadata_policy(
        profile,
        label,
        RETAINED_HOST_ROOTFS_METADATA_POLICY_ID,
    )
}

fn validate_runner_profile_with_metadata_policy(
    profile: &Value,
    label: &str,
    metadata_policy_id: &str,
) -> Result<()> {
    let image = field(profile, "image")?;
    require_string_eq(image, "policy", "eip0045-b4-oci-image-v1")?;
    require_string_eq(
        image,
        "retainedHostRootfsMetadataPolicy",
        metadata_policy_id,
    )?;
    let image_spec = field(image, "imageSpec")?;
    require_string_eq(image_spec, "version", "1.1.1")?;
    require_string_eq(
        image_spec,
        "commit",
        "147f9c13cedb47a0c4d9a11a222961073d585877",
    )?;
    require_string_eq(image, "layoutVersion", "1.0.0")?;
    require_string_eq(
        field(image, "archive")?,
        "encoding",
        "eip0045-b4-oci-image-layout-ustar-v1",
    )?;
    ensure!(
        field(image, "platform")? == field(profile, "platform")?,
        "{label} image platform differs from the runner platform"
    );

    let manifest = field(image, "manifest")?;
    let config = field(image, "config")?;
    let mut blob_digests = BTreeSet::new();
    ensure!(
        blob_digests.insert(string_field(manifest, "digest")?),
        "{label} OCI manifest digest is duplicated"
    );
    ensure!(
        blob_digests.insert(string_field(config, "digest")?),
        "{label} OCI config digest aliases the manifest"
    );
    let layer_uncompressed_bytes = validate_oci_layers(image, label, &mut blob_digests)?;
    let expected_archive_bytes = expected_oci_archive_byte_length(image)?;
    ensure!(
        u64_field(field(image, "archive")?, "byteLength")? == expected_archive_bytes,
        "{label} OCI archive byte length differs from the exact closed-ustar footprint"
    );

    let rootfs = field(image, "postChangesetRootfs")?;
    let regular_files = u64_field(rootfs, "regularFileCount")?;
    let directories = u64_field(rootfs, "directoryCount")?;
    let symbolic_links = u64_field(rootfs, "symbolicLinkCount")?;
    let typed_entries = regular_files
        .checked_add(directories)
        .and_then(|count| count.checked_add(symbolic_links))
        .context("OCI rootfs type-count overflow")?;
    ensure!(
        typed_entries == u64_field(rootfs, "entryCount")?,
        "{label} OCI rootfs type counts do not cover every entry"
    );
    ensure!(
        u64_field(rootfs, "regularFileBytes")? <= layer_uncompressed_bytes,
        "{label} OCI rootfs regular-file bytes exceed all uncompressed layer bytes"
    );

    let runtime = field(profile, "runtime")?;
    require_string_eq(runtime, "name", "runc")?;
    let runtime_spec = field(runtime, "runtimeSpec")?;
    require_string_eq(runtime_spec, "version", "1.3.0")?;
    require_string_eq(
        runtime_spec,
        "commit",
        "92249139eea7161e13745abd4cb6d0ea02a3227a",
    )?;
    validate_elf_projection(
        field(field(runtime, "binary")?, "elf")?,
        &format!("{label} OCI runtime binary ELF"),
    )?;
    if let Some(java_runtime) = object(profile, label)?.get("javaRuntime") {
        validate_elf_projection(
            field(field(java_runtime, "binary")?, "elf")?,
            &format!("{label} Java launcher ELF"),
        )?;
        validate_java_feature_version(java_runtime, &format!("{label} Java runtime"))?;
    }
    if let Some(build_jdk) = object(profile, label)?.get("buildJdk") {
        validate_elf_projection(
            field(field(build_jdk, "launcher")?, "elf")?,
            &format!("{label} Java launcher ELF"),
        )?;
        validate_elf_projection(
            field(field(build_jdk, "compiler")?, "elf")?,
            &format!("{label} Java compiler ELF"),
        )?;
        validate_java_feature_version(build_jdk, &format!("{label} build JDK"))?;
    }
    Ok(())
}

fn project_positive_jvm_executable_closure(
    profile: &BoundDocument,
    role: PositiveRunnerRole,
) -> Result<Option<B4PositiveJvmExecutableClosureV1>> {
    Ok(match role {
        PositiveRunnerRole::JvmValidatorBuild => {
            let build_jdk = field(&profile.value, "buildJdk")?;
            Some(B4PositiveJvmExecutableClosureV1 {
                startup_dependency_policy: project_positive_startup_dependency_policy(
                    build_jdk,
                    "JVM build JDK",
                )?,
                launcher: project_positive_runtime_elf_identity(
                    field(build_jdk, "launcher")?,
                    "JVM build launcher",
                )?,
                compiler: Some(project_positive_runtime_elf_identity(
                    field(build_jdk, "compiler")?,
                    "JVM build compiler",
                )?),
            })
        }
        PositiveRunnerRole::JvmVerifier => {
            let java_runtime = field(&profile.value, "javaRuntime")?;
            Some(B4PositiveJvmExecutableClosureV1 {
                startup_dependency_policy: project_positive_startup_dependency_policy(
                    java_runtime,
                    "JVM verifier runtime",
                )?,
                launcher: project_positive_runtime_elf_identity(
                    field(java_runtime, "binary")?,
                    "JVM verifier launcher",
                )?,
                compiler: None,
            })
        }
        PositiveRunnerRole::RustValidatorBuild | PositiveRunnerRole::RustVerifier => None,
    })
}

fn validate_runtime_observation_selectors(observation: &Value) -> Result<()> {
    require_exact_keys(
        observation,
        &[
            "state",
            "processIdentity",
            "namespaces",
            "idMappings",
            "mountinfo",
            "securityStatus",
            "cgroupV2",
            "rootIdentity",
            "auxv",
            "processMappings",
            "smokeIdentity",
        ],
        "runtime observation selector set",
    )?;
    for (key, expected) in [
        ("state", RUNTIME_STATE_CONTRACT_ID),
        ("processIdentity", RUNTIME_PROCESS_IDENTITY_CONTRACT_ID),
        ("namespaces", RUNTIME_NAMESPACES_SELECTOR_ID),
        ("idMappings", RUNTIME_ID_MAPPINGS_SELECTOR_ID),
        ("mountinfo", RUNTIME_MOUNTINFO_SELECTOR_ID),
        ("securityStatus", RUNTIME_SECURITY_STATUS_SELECTOR_ID),
        ("cgroupV2", RUNTIME_CGROUP_V2_SELECTOR_ID),
        ("rootIdentity", RUNTIME_ROOT_IDENTITY_SELECTOR_ID),
        ("auxv", RUNTIME_AUXV_SELECTOR_ID),
        ("processMappings", RUNTIME_PROCESS_MAPPINGS_SELECTOR_ID),
        ("smokeIdentity", RUNTIME_SMOKE_IDENTITY_SELECTOR_ID),
    ] {
        require_string_eq(observation, key, expected)?;
    }
    Ok(())
}

fn project_positive_oci_runtime_contract(
    profile: &BoundDocument,
    role: PositiveRunnerRole,
) -> Result<B4PositiveOciRuntimeContractV1> {
    require_role(&profile.value, role, "OCI runtime-contract projection")?;
    let runtime = field(&profile.value, "runtime")?;
    require_string_eq(runtime, "name", "runc")?;
    require_string_eq(runtime, "version", "1.3.0")?;
    let runtime_spec = field(runtime, "runtimeSpec")?;
    require_string_eq(runtime_spec, "version", "1.3.0")?;
    require_string_eq(
        runtime_spec,
        "commit",
        "92249139eea7161e13745abd4cb6d0ea02a3227a",
    )?;
    require_string_eq(
        runtime,
        "configurationPolicy",
        RUNTIME_CONFIGURATION_POLICY_ID,
    )?;
    validate_runtime_observation_selectors(field(runtime, "observationSelectors")?)?;

    let binary = field(runtime, "binary")?;
    require_string_eq(binary, "encoding", "raw-bytes")?;
    require_string_eq(binary, "fileFormat", "elf64")?;
    require_string_eq(binary, "architecture", "amd64")?;
    require_string_eq(binary, "linkage", "static-no-interpreter")?;
    require_string_eq(
        binary,
        "inspectionPolicy",
        "eip0045-b4-elf64-amd64-static-v1",
    )?;
    let elf = field(binary, "elf")?;
    require_string_eq(elf, "policy", "eip0045-b4-elf64-amd64-structural-v1")?;
    validate_elf_projection(elf, &format!("{} OCI runtime binary ELF", role.purpose()))?;
    for (key, expected) in [
        ("interpreterSegmentCount", 0),
        ("dynamicSegmentCount", 0),
        ("gnuStackSegmentCount", 1),
        ("writableExecutableLoadSegmentCount", 0),
        ("executableStackSegmentCount", 0),
        ("overlappingLoadFileRangeCount", 0),
        ("extendedNumberingCount", 0),
        ("structuralParseFailureCount", 0),
    ] {
        require_u64_eq(elf, key, expected)?;
    }
    ensure!(
        field(elf, "entryPointInExecutableLoad")? == &Value::Bool(true),
        "entryPointInExecutableLoad differs from true"
    );

    Ok(B4PositiveOciRuntimeContractV1 {
        role,
        version: string_field(runtime, "version")?.to_owned(),
        runtime_spec: B4PositiveOciRuntimeSpecKindV1::V1_3_0,
        binary: B4PositiveStaticRuntimeElfIdentityV1 {
            relative_path: string_field(binary, "path")?.to_owned(),
            byte_length: u64_field(binary, "byteLength")?,
            sha256: decode_digest(
                string_field(binary, "sha256")?,
                &format!("{} OCI runtime binary SHA-256", role.purpose()),
            )?,
            elf_type: string_field(elf, "elfType")?.to_owned(),
            os_abi: string_field(elf, "osAbi")?.to_owned(),
            program_header_count: u64_field(elf, "programHeaderCount")?,
            section_header_count: u64_field(elf, "sectionHeaderCount")?,
            load_segment_count: u64_field(elf, "loadSegmentCount")?,
            executable_load_segment_count: u64_field(elf, "executableLoadSegmentCount")?,
            gnu_stack_segment_count: u64_field(elf, "gnuStackSegmentCount")?,
        },
        configuration_policy: B4PositiveRuntimeConfigurationPolicyV1 {
            kind: B4PositiveRuntimeConfigurationPolicyKindV1::ClosedProjection,
        },
        observation_selectors: B4PositiveRuntimeObservationSelectorsV1 {
            state_contract: B4PositiveRuncStateContractV1::new(role),
            process_identity_contract: B4PositiveProcessIdentityContractV1::new(role),
            reserved_kind: B4PositiveRuntimeObservationReservedKindV1::RemainingSelectors,
        },
    })
}

fn project_positive_retained_host_rootfs_metadata_policy(
    profile: &BoundDocument,
    role: PositiveRunnerRole,
) -> Result<B4PositiveRetainedHostRootfsMetadataPolicyV1> {
    require_role(
        &profile.value,
        role,
        "retained-host rootfs metadata-policy projection",
    )?;
    require_string_eq(
        field(&profile.value, "image")?,
        "retainedHostRootfsMetadataPolicy",
        RETAINED_HOST_ROOTFS_METADATA_POLICY_ID,
    )?;
    Ok(B4PositiveRetainedHostRootfsMetadataPolicyV1 {
        role,
        kind: B4PositiveRetainedHostRootfsMetadataPolicyKindV1::ClosedObligations,
    })
}

fn project_positive_oci_image_layout(
    profile: &BoundDocument,
    role: PositiveRunnerRole,
) -> Result<B4PositiveOciImageLayoutV1> {
    require_role(&profile.value, role, "OCI image-layout projection")?;
    let runtime_contract = project_positive_oci_runtime_contract(profile, role)?;
    let retained_host_rootfs_metadata_policy =
        project_positive_retained_host_rootfs_metadata_policy(profile, role)?;
    let image = field(&profile.value, "image")?;
    let archive = field(image, "archive")?;
    let manifest = field(image, "manifest")?;
    let config = field(image, "config")?;
    let layers = array_field(image, "layers")?
        .iter()
        .enumerate()
        .map(|(index, layer)| {
            Ok(B4PositiveOciLayerV1 {
                compressed_digest: decode_oci_sha256_digest(
                    string_field(layer, "digest")?,
                    &format!("{} OCI layer {index} digest", role.purpose()),
                )?,
                compressed_byte_length: u64_field(layer, "size")?,
                uncompressed_byte_length: u64_field(layer, "uncompressedBytes")?,
                diff_id: decode_oci_sha256_digest(
                    string_field(layer, "diffId")?,
                    &format!("{} OCI layer {index} DiffID", role.purpose()),
                )?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let rootfs = field(image, "postChangesetRootfs")?;
    let jvm_executables = project_positive_jvm_executable_closure(profile, role)?;
    let jvm_release = match role {
        PositiveRunnerRole::JvmValidatorBuild => Some(project_positive_jvm_release_identity(
            field(&profile.value, "buildJdk")?,
            "JVM build JDK release",
        )?),
        PositiveRunnerRole::JvmVerifier => Some(project_positive_jvm_release_identity(
            field(&profile.value, "javaRuntime")?,
            "JVM verifier release",
        )?),
        PositiveRunnerRole::RustValidatorBuild | PositiveRunnerRole::RustVerifier => None,
    };
    let rootfs_path_requirements = project_positive_rootfs_path_requirements(profile, role)?;

    Ok(B4PositiveOciImageLayoutV1 {
        role,
        runtime_contract,
        retained_host_rootfs_metadata_policy,
        archive_path: string_field(archive, "path")?.to_owned(),
        archive_byte_length: u64_field(archive, "byteLength")?,
        archive_sha256: decode_digest(
            string_field(archive, "sha256")?,
            &format!("{} OCI archive SHA-256", role.purpose()),
        )?,
        manifest: B4PositiveOciDescriptorV1 {
            digest: decode_oci_sha256_digest(
                string_field(manifest, "digest")?,
                &format!("{} OCI manifest digest", role.purpose()),
            )?,
            byte_length: u64_field(manifest, "size")?,
        },
        config: B4PositiveOciDescriptorV1 {
            digest: decode_oci_sha256_digest(
                string_field(config, "digest")?,
                &format!("{} OCI config digest", role.purpose()),
            )?,
            byte_length: u64_field(config, "size")?,
        },
        layers,
        post_changeset_rootfs: B4PositiveOciRootfsCountsV1 {
            entry_count: u64_field(rootfs, "entryCount")?,
            regular_file_count: u64_field(rootfs, "regularFileCount")?,
            directory_count: u64_field(rootfs, "directoryCount")?,
            symbolic_link_count: u64_field(rootfs, "symbolicLinkCount")?,
            regular_file_bytes: u64_field(rootfs, "regularFileBytes")?,
        },
        jvm_executables,
        jvm_release,
        rootfs_path_requirements,
    })
}

fn project_positive_startup_dependency_policy(
    runtime: &Value,
    label: &str,
) -> Result<B4PositiveStartupDependencyPolicyV1> {
    match string_field(runtime, "startupDependencyPolicy")? {
        STARTUP_DEPENDENCY_POLICY_ID => Ok(B4PositiveStartupDependencyPolicyV1 {
            kind: B4PositiveStartupDependencyPolicyKindV1::InitialElfClosure,
        }),
        other => anyhow::bail!("{label} has unsupported startup-dependency policy: {other}"),
    }
}

fn project_positive_jvm_release_identity(
    runtime: &Value,
    label: &str,
) -> Result<B4PositiveJvmReleaseIdentityV1> {
    let release = field(runtime, "release")?;
    Ok(B4PositiveJvmReleaseIdentityV1 {
        image_path: string_field(release, "imagePath")?.to_owned(),
        byte_length: u64_field(release, "byteLength")?,
        sha256: decode_digest(
            string_field(release, "sha256")?,
            &format!("{label} SHA-256"),
        )?,
        feature_version: u64_field(runtime, "featureVersion")?,
        vendor: string_field(runtime, "vendor")?.to_owned(),
        version: string_field(runtime, "version")?.to_owned(),
    })
}

fn project_positive_rootfs_path_requirements(
    profile: &BoundDocument,
    role: PositiveRunnerRole,
) -> Result<Vec<B4PositiveRootfsPathRequirementV1>> {
    fn insert(
        requirements: &mut BTreeMap<String, B4PositiveRootfsPathKindV1>,
        image_path: &str,
        kind: B4PositiveRootfsPathKindV1,
    ) -> Result<()> {
        if let Some(previous) = requirements.insert(image_path.to_owned(), kind) {
            ensure!(
                previous == kind,
                "positive OCI rootfs path has conflicting physical requirements: {image_path}"
            );
        }
        Ok(())
    }

    fn insert_mount(
        requirements: &mut BTreeMap<String, B4PositiveRootfsPathKindV1>,
        mount: &Value,
    ) -> Result<()> {
        let kind = match string_field(mount, "type")? {
            "bind-directory" => B4PositiveRootfsPathKindV1::Directory,
            "bind-file" => B4PositiveRootfsPathKindV1::EmptyRegular,
            other => anyhow::bail!("unsupported positive OCI bind type: {other}"),
        };
        insert(requirements, string_field(mount, "target")?, kind)
    }

    let policy = field(&profile.value, "policy")?;
    let mut requirements = BTreeMap::new();
    for mount in array_field(policy, "mounts")? {
        insert_mount(&mut requirements, mount)?;
    }
    if role == PositiveRunnerRole::JvmValidatorBuild {
        let packaging = field(policy, "packagingPhase")?;
        for mount in array_field(packaging, "mounts")? {
            insert_mount(&mut requirements, mount)?;
        }
    }
    let tmpfs = array_field(policy, "tmpfs")?;
    ensure!(
        tmpfs.len() == 1,
        "positive OCI runner tmpfs cardinality drift"
    );
    insert(
        &mut requirements,
        string_field(&tmpfs[0], "target")?,
        B4PositiveRootfsPathKindV1::Directory,
    )?;
    for directory in ["/dev", "/proc"] {
        insert(
            &mut requirements,
            directory,
            B4PositiveRootfsPathKindV1::Directory,
        )?;
    }
    for pseudodevice in ["full", "null", "random", "urandom", "zero"] {
        insert(
            &mut requirements,
            &format!("/dev/{pseudodevice}"),
            B4PositiveRootfsPathKindV1::EmptyRegular,
        )?;
    }

    Ok(requirements
        .into_iter()
        .map(|(image_path, kind)| B4PositiveRootfsPathRequirementV1 { image_path, kind })
        .collect())
}

fn project_positive_runtime_elf_identity(
    executable: &Value,
    label: &str,
) -> Result<B4PositiveRuntimeElfIdentityV1> {
    let elf = field(executable, "elf")?;
    Ok(B4PositiveRuntimeElfIdentityV1 {
        image_path: string_field(executable, "imagePath")?.to_owned(),
        byte_length: u64_field(executable, "byteLength")?,
        sha256: decode_digest(
            string_field(executable, "sha256")?,
            &format!("{label} SHA-256"),
        )?,
        elf_type: string_field(elf, "elfType")?.to_owned(),
        os_abi: string_field(elf, "osAbi")?.to_owned(),
        program_header_count: u64_field(elf, "programHeaderCount")?,
        section_header_count: u64_field(elf, "sectionHeaderCount")?,
        load_segment_count: u64_field(elf, "loadSegmentCount")?,
        executable_load_segment_count: u64_field(elf, "executableLoadSegmentCount")?,
        interpreter_path: string_field(elf, "interpreterPath")?.to_owned(),
        dynamic_entry_count: u64_field(elf, "dynamicEntryCount")?,
        needed_library_count: u64_field(elf, "neededLibraryCount")?,
        gnu_stack_segment_count: u64_field(elf, "gnuStackSegmentCount")?,
    })
}

fn decode_oci_sha256_digest(value: &str, label: &str) -> Result<[u8; DIGEST_BYTES]> {
    let digest = value
        .strip_prefix("sha256:")
        .with_context(|| format!("{label} does not use the sha256 algorithm"))?;
    decode_digest(digest, label)
}

fn validate_oci_layers<'a>(
    image: &'a Value,
    label: &str,
    blob_digests: &mut BTreeSet<&'a str>,
) -> Result<u64> {
    let layers = array_field(image, "layers")?;
    ensure!(
        (1..=128).contains(&layers.len()),
        "{label} OCI layer cardinality is outside the closed bound"
    );
    let mut diff_ids = BTreeSet::new();
    let mut uncompressed_bytes = 0_u64;
    for layer in layers {
        ensure!(
            blob_digests.insert(string_field(layer, "digest")?),
            "{label} OCI compressed blob digest is reused"
        );
        ensure!(
            diff_ids.insert(string_field(layer, "diffId")?),
            "{label} OCI rootfs DiffID is reused"
        );
        uncompressed_bytes = uncompressed_bytes
            .checked_add(u64_field(layer, "uncompressedBytes")?)
            .context("OCI cumulative uncompressed-layer byte count overflow")?;
    }
    ensure!(
        uncompressed_bytes <= MAX_OCI_UNCOMPRESSED_LAYER_BYTES,
        "{label} OCI cumulative uncompressed-layer bytes exceed the closed aggregate bound"
    );
    Ok(uncompressed_bytes)
}

fn expected_oci_archive_byte_length(image: &Value) -> Result<u64> {
    let manifest = field(image, "manifest")?;
    let config = field(image, "config")?;
    let index_bytes = canonical_oci_index_bytes(image)?;
    let index_byte_length =
        u64::try_from(index_bytes.len()).context("canonical OCI index length exceeds u64")?;
    let layout_byte_length =
        u64::try_from(OCI_LAYOUT_PAYLOAD.len()).context("OCI layout length exceeds u64")?;

    let mut archive_bytes = USTAR_BLOCK_BYTES
        .checked_mul(2)
        .context("OCI outer-ustar terminator length overflow")?;
    for payload_bytes in [
        layout_byte_length,
        index_byte_length,
        u64_field(manifest, "size")?,
        u64_field(config, "size")?,
    ] {
        archive_bytes = archive_bytes
            .checked_add(ustar_member_extent(payload_bytes)?)
            .context("OCI outer-ustar aggregate length overflow")?;
    }
    for layer in array_field(image, "layers")? {
        archive_bytes = archive_bytes
            .checked_add(ustar_member_extent(u64_field(layer, "size")?)?)
            .context("OCI outer-ustar aggregate layer length overflow")?;
    }
    Ok(archive_bytes)
}

fn canonical_oci_index_bytes(image: &Value) -> Result<Vec<u8>> {
    let manifest = field(image, "manifest")?;
    canonical_json_bytes(&json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": field(manifest, "mediaType")?,
            "digest": field(manifest, "digest")?,
            "size": field(manifest, "size")?,
            "platform": field(image, "platform")?
        }]
    }))
    .context("cannot derive canonical OCI index bytes")
}

fn ustar_member_extent(payload_bytes: u64) -> Result<u64> {
    let padded_payload_bytes = payload_bytes
        .checked_add(USTAR_BLOCK_BYTES - 1)
        .context("ustar payload rounding overflow")?
        .checked_div(USTAR_BLOCK_BYTES)
        .context("ustar block size cannot be zero")?
        .checked_mul(USTAR_BLOCK_BYTES)
        .context("ustar padded payload length overflow")?;
    USTAR_BLOCK_BYTES
        .checked_add(padded_payload_bytes)
        .context("ustar member extent overflow")
}

fn validate_non_alias_lineage_separation(descriptors: &[BoundDocument; 2]) -> Result<()> {
    ensure!(
        descriptors[0].sha256 != descriptors[1].sha256,
        "validator descriptor digests are equal"
    );
    let rust = &descriptors[0].value;
    let jvm = &descriptors[1].value;
    ensure_distinct(
        field(field(rust, "artifact")?, "sha256")?,
        field(field(jvm, "artifact")?, "sha256")?,
        "validator artifact digest",
    )?;
    ensure_distinct(
        &reviewed_source_projection(field(rust, "reviewedSource")?)?,
        &reviewed_source_projection(field(jvm, "reviewedSource")?)?,
        "reviewed source tuple",
    )?;
    ensure_distinct(
        field(field(field(rust, "reviewedSource")?, "archive")?, "sha256")?,
        field(field(field(jvm, "reviewedSource")?, "archive")?, "sha256")?,
        "source archive digest",
    )?;
    ensure_distinct(
        field(field(rust, "implementationLineage")?, "lineageSha256")?,
        field(field(jvm, "implementationLineage")?, "lineageSha256")?,
        "implementation lineage digest",
    )?;
    ensure_distinct(
        field(rust, "implementationLanguage")?,
        field(jvm, "implementationLanguage")?,
        "implementation language",
    )?;
    ensure_distinct(
        field(field(rust, "entrypoint")?, "kind")?,
        field(field(jvm, "entrypoint")?, "kind")?,
        "entrypoint kind",
    )?;
    Ok(())
}

fn derive_expected_observation(
    verifier_input: &Value,
    contents: &VerifierRootContents<'_>,
    input_set: &Value,
    case: &Value,
) -> Result<Vec<u8>> {
    let measurements = contents.measurements();
    validate_verifier_measurements(verifier_input, &measurements, input_set)?;
    derive_expected_observation_from_bound_inputs(contents, input_set, case)
}

fn derive_expected_observation_from_bound_inputs(
    contents: &VerifierRootContents<'_>,
    input_set: &Value,
    case: &Value,
) -> Result<Vec<u8>> {
    let expected_profile_id = decode_digest(
        string_field(field(input_set, "profile")?, "profileId")?,
        "input-set profile ID",
    )?;
    let package = validate_profile_package_v1(
        contents.profile_manifest,
        ProfileArtifacts {
            algorithm: contents.profile_algorithm,
            binary_data: contents.profile_constants,
        },
        &expected_profile_id,
    )
    .context("verifier profile package is invalid")?;
    package
        .manifest()
        .validate_initial_profile_target()
        .context("verifier profile differs from the selected initial target")?;

    let program_id: [u8; DIGEST_BYTES] = compute_image_id(contents.guest_elf)
        .context("cannot derive the RISC Zero image ID from guest.elf")?
        .into();
    ensure!(
        string_field(field(input_set, "guest")?, "imageId")? == hex::encode(program_id),
        "input-set image ID differs from the guest ELF derivation"
    );

    let statement = parse_ergo_statement_v1(contents.statement)?;
    ensure!(
        statement.profile_id() == expected_profile_id,
        "statement profile ID differs from the validated profile package"
    );
    ensure!(
        statement.program_id() == program_id,
        "statement program ID differs from the guest ELF derivation"
    );
    let reference_statement = field(input_set, "referenceStatement")?;
    let expected_chain_domain = decode_digest(
        string_field(reference_statement, "chainDomainId")?,
        "input-set chain-domain ID",
    )?;
    ensure!(
        statement.chain_domain_id() == expected_chain_domain,
        "statement chain-domain ID differs from the pre-proof input set"
    );
    let expected_payload_sha256 = decode_digest(
        string_field(reference_statement, "applicationPayloadSha256")?,
        "input-set application-payload SHA-256",
    )?;
    ensure!(
        statement.application_payload_sha256() == expected_payload_sha256
            && u64::try_from(statement.application_payload().len())
                .context("statement application payload length does not fit u64")?
                == u64_field(reference_statement, "applicationPayloadByteLength")?,
        "statement application payload differs from the pre-proof input set"
    );
    let expected_contract_id = decode_digest(
        string_field(reference_statement, "contractId")?,
        "input-set contract ID",
    )?;
    ensure!(
        statement.contract_id() == expected_contract_id,
        "statement contract ID differs from the pre-proof input set"
    );

    let statement_sha256: [u8; DIGEST_BYTES] = Sha256::digest(contents.statement).into();
    let claim_digest = ok_receipt_claim_digests(&program_id, contents.statement)
        .context("cannot derive the exact OK receipt claim")?
        .expected_claim;
    let terminal = derive_terminal(package.manifest(), field(case, "terminal")?)?;
    canonical_json_bytes(&json!({
        "format": "Eip0045B4PositiveObservationV1",
        "formatVersion": 1,
        "verdict": "accept",
        "profileId": hex::encode(expected_profile_id),
        "programId": hex::encode(program_id),
        "statementSha256": hex::encode(statement_sha256),
        "claimDigest": hex::encode(claim_digest),
        "finalStatus": "ok",
        "finalAssumptionCount": 0,
        "terminal": terminal
    }))
    .context("cannot canonicalize the independently derived observation")
}

fn derive_terminal(manifest: &StarkProfileManifestV1, expected: &Value) -> Result<Value> {
    let kind = string_field(expected, "kind")?;
    let numeric_kind = match kind {
        "lift" => TERMINAL_CONTROL_KIND_LIFT,
        "join" => TERMINAL_CONTROL_KIND_JOIN,
        "resolve" => TERMINAL_CONTROL_KIND_RESOLVE,
        _ => anyhow::bail!("case plan has an unsupported terminal kind"),
    };
    let parameter = u8::try_from(u64_field(expected, "parameter")?)
        .context("case terminal parameter does not fit u8")?;
    let mut matches = manifest.terminal_controls().iter().filter(|control| {
        control.control_kind() == numeric_kind && control.parameter() == parameter
    });
    let control = matches
        .next()
        .context("case terminal is absent from the validated profile manifest")?;
    ensure!(
        matches.next().is_none(),
        "case terminal is ambiguous in the validated profile manifest"
    );
    Ok(json!({
        "kind": kind,
        "parameter": parameter,
        "controlId": hex::encode(control.control_id())
    }))
}

fn decode_digest(value: &str, label: &str) -> Result<[u8; DIGEST_BYTES]> {
    let bytes = hex::decode(value).with_context(|| format!("{label} is not lowercase hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} is not exactly 32 bytes"))
}

fn measure_bytes(bytes: &[u8]) -> FileMeasurement {
    FileMeasurement {
        byte_length: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
    }
}

fn validate_verifier_physical_measurements(
    verifier_input: &Value,
    measurements: &VerifierRootMeasurements,
) -> Result<()> {
    for (field_name, measurement, label) in [
        (
            "profileManifest",
            &measurements.profile_manifest,
            "profile manifest",
        ),
        (
            "profileAlgorithm",
            &measurements.profile_algorithm,
            "profile algorithm",
        ),
        (
            "profileConstants",
            &measurements.profile_constants,
            "profile constants",
        ),
        ("guestElf", &measurements.guest_elf, "guest ELF"),
        ("statement", &measurements.statement, "statement"),
        ("rawSeal", &measurements.raw_seal, "raw seal"),
    ] {
        validate_measurement(field(verifier_input, field_name)?, measurement, label)?;
    }
    Ok(())
}

fn validate_verifier_measurements(
    verifier_input: &Value,
    measurements: &VerifierRootMeasurements,
    input_set: &Value,
) -> Result<()> {
    validate_verifier_physical_measurements(verifier_input, measurements)?;
    validate_verifier_input_bindings(verifier_input, input_set)
}

fn validate_verifier_input_bindings(verifier_input: &Value, input_set: &Value) -> Result<()> {
    let profile = field(input_set, "profile")?;
    for (input_field, set_field) in [
        ("profileManifest", "manifest"),
        ("profileAlgorithm", "algorithm"),
        ("profileConstants", "constants"),
    ] {
        require_same_file_identity(
            field(verifier_input, input_field)?,
            field(profile, set_field)?,
            input_field,
        )?;
    }
    require_same_file_identity(
        field(verifier_input, "guestElf")?,
        field(field(input_set, "guest")?, "elf")?,
        "guest ELF",
    )?;
    ensure!(
        field(field(verifier_input, "statement")?, "sha256")?
            == field(field(input_set, "referenceStatement")?, "statementSha256")?,
        "verifier statement digest differs from the pre-proof input set"
    );
    ensure!(
        field(field(verifier_input, "statement")?, "byteLength")?
            == field(
                field(input_set, "referenceStatement")?,
                "statementByteLength",
            )?,
        "verifier statement length differs from the pre-proof input set"
    );
    Ok(())
}

fn validate_terminal_against_case(observation: &Value, case: &Value) -> Result<()> {
    let observed = field(observation, "terminal")?;
    let expected = field(case, "terminal")?;
    for key in ["kind", "parameter"] {
        ensure!(
            field(observed, key)? == field(expected, key)?,
            "observation terminal {key} differs from the finalizer-held case plan"
        );
    }
    Ok(())
}

fn require_same_file_identity(left: &Value, right: &Value, label: &str) -> Result<()> {
    for key in ["byteLength", "sha256", "encoding"] {
        ensure!(
            field(left, key)? == field(right, key)?,
            "{label} {key} differs from the pre-proof input set"
        );
    }
    Ok(())
}

fn validate_measurement(identity: &Value, measured: &FileMeasurement, label: &str) -> Result<()> {
    ensure!(
        u64_field(identity, "byteLength")? == measured.byte_length,
        "{label} byte length differs from the physical measurement"
    );
    ensure!(
        string_field(identity, "sha256")? == hex::encode(measured.sha256),
        "{label} digest differs from the physical measurement"
    );
    Ok(())
}

fn reviewed_source_projection(source: &Value) -> Result<Value> {
    Ok(json!({
        "repository": string_field(source, "repository")?,
        "commit": string_field(source, "commit")?,
        "tree": string_field(source, "tree")?
    }))
}

fn binary_commitment(identity: &Value) -> Result<Value> {
    Ok(json!({
        "byteLength": u64_field(identity, "byteLength")?,
        "sha256": string_field(identity, "sha256")?,
        "encoding": string_field(identity, "encoding")?
    }))
}

fn java_runtime_projection(runtime: &Value) -> Result<Value> {
    Ok(json!({
        "binary": binary_commitment(field(runtime, "binary")?)?,
        "release": binary_commitment(field(runtime, "release")?)?,
        "featureVersion": u64_field(runtime, "featureVersion")?,
        "vendor": string_field(runtime, "vendor")?,
        "version": string_field(runtime, "version")?,
        "options": field(runtime, "options")?.clone()
    }))
}

fn jcs_commitment(format: &str, bytes: &[u8]) -> Value {
    json!({
        "format": format,
        "byteLength": bytes.len(),
        "sha256": sha256_hex(bytes),
        "encoding": "rfc8785-jcs"
    })
}

fn require_format(value: &Value, format: &str, version: u64) -> Result<()> {
    require_string_eq(value, "format", format)?;
    require_u64_eq(value, "formatVersion", version)
}

fn require_role(value: &Value, role: PositiveRunnerRole, label: &str) -> Result<()> {
    ensure!(
        u64_field(value, "runnerProfileIndex")? == role.index() as u64,
        "{label} index drift for {}",
        role.purpose()
    );
    ensure!(
        string_field(value, "purpose")? == role.purpose(),
        "{label} purpose drift for {}",
        role.purpose()
    );
    Ok(())
}

fn require_exact_keys(value: &Value, expected: &[&str], label: &str) -> Result<()> {
    let actual = object(value, label)?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    ensure!(actual == expected, "{label} authority surface drift");
    Ok(())
}

fn validate_json_schema(instance: &Value, schema: EmbeddedSchema, label: &str) -> Result<()> {
    let (schema_source, cache) = schema.source_and_cache();
    let validator = cache.get_or_init(|| {
        let schema = parse_json_strict(schema_source.as_bytes())
            .map_err(|error| format!("strict JSON is invalid: {error:#}"))?;
        jsonschema::draft202012::options()
            .build(&schema)
            .map_err(|error| format!("Draft 2020-12 schema is invalid: {error}"))
    });
    let validator = validator
        .as_ref()
        .map_err(|error| anyhow::anyhow!("embedded {label} JSON Schema failure: {error}"))?;
    validator
        .validate(instance)
        .map_err(|error| anyhow::anyhow!("{label} fails Draft 2020-12 schema: {error}"))?;
    Ok(())
}

fn require_string_eq(value: &Value, key: &str, expected: &str) -> Result<()> {
    ensure!(
        string_field(value, key)? == expected,
        "{key} differs from {expected}"
    );
    Ok(())
}

fn require_u64_eq(value: &Value, key: &str, expected: u64) -> Result<()> {
    ensure!(
        u64_field(value, key)? == expected,
        "{key} differs from {expected}"
    );
    Ok(())
}

fn ensure_distinct(left: &Value, right: &Value, label: &str) -> Result<()> {
    ensure!(left != right, "{label} is shared between validators");
    Ok(())
}

fn artifact_length(identity: &Value) -> Result<u64> {
    u64_field(identity, "byteLength")
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    object(value, "JSON object")?
        .get(key)
        .with_context(|| format!("missing required field {key}"))
}

fn object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .with_context(|| format!("{label} is not a JSON object"))
}

fn array_field<'a>(value: &'a Value, key: &str) -> Result<&'a [Value]> {
    field(value, key)?
        .as_array()
        .map(Vec::as_slice)
        .with_context(|| format!("{key} is not an array"))
}

fn string_field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    field(value, key)?
        .as_str()
        .with_context(|| format!("{key} is not a string"))
}

fn u64_field(value: &Value, key: &str) -> Result<u64> {
    field(value, key)?
        .as_u64()
        .with_context(|| format!("{key} is not an unsigned integer"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::{
        b4_build_check::TestAuthoritativeB4BuildProjection,
        b4_campaign_contract::B4_VERIFIER_SCHEMA_ROLES,
        canonical::canonical_json_bytes,
        profile::{contract_id, ergo_statement_v1},
        test_support::valid_program_fixture,
    };

    const RUNNER_PATHS: [&str; 4] = [
        "runner/rust-build.json",
        "runner/jvm-build.json",
        "runner/rust-verify.json",
        "runner/jvm-verify.json",
    ];
    const SECCOMP_PATHS: [&str; 4] = [
        "runner/seccomp-rust-build.json",
        "runner/seccomp-jvm-build.json",
        "runner/seccomp-rust-verify.json",
        "runner/seccomp-jvm-verify.json",
    ];
    const DESCRIPTOR_PATHS: [&str; 2] = [
        "validator/rust-descriptor.json",
        "validator/jvm-descriptor.json",
    ];
    const JVM_COPY_ONLY_INCLUSION_MANIFEST_PATH: &str = "packaging/jvm-copy-only-inclusion.json";
    const VERIFIER_CONTRACT_PATH: &str = "preproof/verifier-contract.json";
    const INPUT_SET_PATH: &str = "positive/input-set.json";
    const GENERATION_SET_PATH: &str = "positive/generation-set.json";
    const HISTORICAL_REFERENCE_CHAIN_DOMAIN_ID: [u8; DIGEST_BYTES] = [0x71; DIGEST_BYTES];
    const HISTORICAL_REFERENCE_APPLICATION_PAYLOAD: &[u8] = b"";
    const FIXTURE_PROFILE_MANIFEST_BYTES: &[u8] =
        include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin");
    const FIXTURE_PROFILE_ALGORITHM_BYTES: &[u8] =
        include_bytes!("../../profiles/risc0-v3-succinct/algorithm.txt");

    #[derive(Clone)]
    struct Fixture {
        seccomp_values: [Value; 4],
        runner_values: [Value; 4],
        descriptor_values: [Value; 2],
        verifier_contract_value: Value,
        jvm_copy_only_inclusion_manifest_value: Value,
        input_value: Value,
        reference_statement_bundle_manifest: Vec<u8>,
        source_lock: Vec<u8>,
        verifier_files: OwnedVerifierFiles,
        proof_generator_artifact: Vec<u8>,
        recursive_calibrations: [Vec<u8>; 3],
        authoritative_build: AuthoritativeB4BuildProjection,
    }

    #[derive(Clone)]
    struct OwnedGenerationArtifact {
        source_file: &'static str,
        bytes: Vec<u8>,
    }

    #[derive(Clone)]
    struct OwnedGenerationCase {
        proof_output_manifest_jcs: Vec<u8>,
        artifacts: Vec<OwnedGenerationArtifact>,
        auxiliary_artifacts: Vec<OwnedGenerationArtifact>,
    }

    #[derive(Clone)]
    struct OwnedVerifierFiles {
        profile_manifest: Vec<u8>,
        profile_algorithm: Vec<u8>,
        profile_constants: Vec<u8>,
        guest_elf: Vec<u8>,
        statement: Vec<u8>,
        raw_seal: Vec<u8>,
    }

    impl OwnedVerifierFiles {
        fn contents(&self) -> VerifierRootContents<'_> {
            VerifierRootContents {
                profile_manifest: &self.profile_manifest,
                profile_algorithm: &self.profile_algorithm,
                profile_constants: &self.profile_constants,
                guest_elf: &self.guest_elf,
                statement: &self.statement,
                raw_seal: &self.raw_seal,
            }
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the test manifest keeps every independently bound statement identity explicit"
    )]
    fn reference_statement_bundle_manifest_jcs(
        statement: &[u8],
        chain_domain_id: [u8; DIGEST_BYTES],
        profile_id: [u8; DIGEST_BYTES],
        program_id: [u8; DIGEST_BYTES],
        contract_id: [u8; DIGEST_BYTES],
        application_payload: &[u8],
        proposition: &[u8],
    ) -> Vec<u8> {
        let claim = ok_receipt_claim_digests(&program_id, statement).unwrap();
        let artifact = |path: &str, role: &str, bytes: &[u8]| {
            json!({
                "length": bytes.len(),
                "path": path,
                "role": role,
                "sha256": sha256_hex(bytes)
            })
        };
        canonical_json_bytes(&json!({
            "artifacts": [
                artifact("application-payload.bin", "application-payload", application_payload),
                artifact("chain-domain-id.bin", "chain-domain-id", &chain_domain_id),
                artifact("claim-digest.bin", "expected-claim-digest", &claim.expected_claim),
                artifact("contract-id.bin", "contract-id", &contract_id),
                artifact("journal-digest.bin", "journal-digest", &claim.journal_digest),
                artifact("output-digest.bin", "receipt-output-digest", &claim.output),
                artifact("post-digest.bin", "receipt-post-digest", &claim.post),
                artifact("profile-id.bin", "stark-profile-id", &profile_id),
                artifact("program-id.bin", "guest-program-id", &program_id),
                artifact("proposition.bin", "self-proposition-bytes", proposition),
                artifact("statement.bin", "ergo-statement-v1", statement)
            ],
            "claim": {
                "expectedClaim": hex::encode(claim.expected_claim),
                "journalDigest": hex::encode(claim.journal_digest),
                "output": hex::encode(claim.output),
                "post": hex::encode(claim.post)
            },
            "format": "ErgoStatementBundleV1",
            "formatVersion": 1,
            "statement": {
                "applicationPayloadLength": application_payload.len(),
                "chainDomainId": hex::encode(chain_domain_id),
                "contractId": hex::encode(contract_id),
                "domainHex": hex::encode(crate::constants::ERGO_STATEMENT_DOMAIN),
                "profileId": hex::encode(profile_id),
                "programId": hex::encode(program_id),
                "propositionBytesLength": proposition.len(),
                "statementLength": statement.len(),
                "statementSha256": sha256_hex(statement),
                "version": 1
            }
        }))
        .unwrap()
    }

    fn static_elf_inspection() -> Value {
        json!({
            "policy": "eip0045-b4-elf64-amd64-structural-v1",
            "elfType": "et-exec",
            "osAbi": "sysv",
            "programHeaderCount": 6,
            "sectionHeaderCount": 12,
            "loadSegmentCount": 3,
            "executableLoadSegmentCount": 1,
            "entryPointInExecutableLoad": true,
            "interpreterSegmentCount": 0,
            "dynamicSegmentCount": 0,
            "gnuStackSegmentCount": 1,
            "writableExecutableLoadSegmentCount": 0,
            "executableStackSegmentCount": 0,
            "overlappingLoadFileRangeCount": 0,
            "extendedNumberingCount": 0,
            "structuralParseFailureCount": 0
        })
    }

    fn runtime_elf_inspection() -> Value {
        json!({
            "policy": "eip0045-b4-elf64-amd64-structural-v1",
            "elfType": "et-dyn",
            "osAbi": "sysv",
            "programHeaderCount": 11,
            "sectionHeaderCount": 30,
            "loadSegmentCount": 4,
            "executableLoadSegmentCount": 1,
            "entryPointInExecutableLoad": true,
            "interpreterSegmentCount": 1,
            "interpreterPath": "/lib64/ld-linux-x86-64.so.2",
            "dynamicSegmentCount": 1,
            "dynamicEntryCount": 20,
            "neededLibraryCount": 3,
            "gnuStackSegmentCount": 1,
            "writableExecutableLoadSegmentCount": 0,
            "executableStackSegmentCount": 0,
            "overlappingLoadFileRangeCount": 0,
            "extendedNumberingCount": 0,
            "structuralParseFailureCount": 0
        })
    }

    fn jvm_archive_inspection() -> Value {
        json!({
            "policy": "eip0045-b4-canonical-jar-zip-v1",
            "entryCount": 3,
            "localFileRecordCount": 3,
            "regularFileEntryCount": 3,
            "directoryEntryCount": 0,
            "uncompressedByteLength": 200,
            "largestEntryUncompressedByteLength": 100,
            "allowedCompressionMethods": ["stored", "deflate"],
            "dataDescriptorPolicy": "signed-immediate-classic-match-central-directory",
            "dataDescriptorCount": 0,
            "unsignedDataDescriptorCount": 0,
            "zip64DataDescriptorCount": 0,
            "zip64RecordCount": 0,
            "encryptedEntryCount": 0,
            "multiDiskFieldCount": 0,
            "unsupportedFlagEntryCount": 0,
            "unsupportedExtraFieldEntryCount": 0,
            "archiveCommentByteLength": 0,
            "entryCommentCount": 0,
            "prefixByteLength": 0,
            "suffixByteLength": 0,
            "unreferencedByteLength": 0,
            "overlappingEntryCount": 0,
            "centralDirectoryOrderMismatchCount": 0,
            "versionFieldMismatchCount": 0,
            "nonCanonicalTimestampCount": 0,
            "utf8FlagMissingCount": 0,
            "nonZeroAttributeCount": 0,
            "manifestFirstEntryCount": 1,
            "canonicalEntryOrderMismatchCount": 0,
            "duplicateEntryNameCount": 0,
            "asciiCaseFoldCollisionCount": 0,
            "nonCanonicalEntryNameCount": 0,
            "linkOrSpecialEntryCount": 0,
            "localCentralHeaderMismatchCount": 0,
            "crcMismatchCount": 0,
            "sizeMismatchCount": 0,
            "decompressionFailureCount": 0
        })
    }

    fn jvm_manifest_inspection() -> Value {
        json!({
            "policy": "java-se-21-jar-manifest-executable-v1",
            "manifestEntryCount": 1,
            "manifestByteLength": 80,
            "mainAttributeCount": 2,
            "createdByAttributeCount": 0,
            "individualSectionCount": 0,
            "unsupportedMainAttributeCount": 0,
            "manifestVersionAttributeCount": 1,
            "manifestVersion": "1.0",
            "mainClassAttributeCount": 1,
            "mainClass": "org.example.Main",
            "mainClassEntry": "org/example/Main.class",
            "mainClassEntryCount": 1,
            "classPathAttributeCount": 0,
            "multiReleaseAttributeCount": 0,
            "launcherAgentClassAttributeCount": 0,
            "addExportsAttributeCount": 0,
            "addOpensAttributeCount": 0,
            "javaFxApplicationClassAttributeCount": 0,
            "signatureVersionAttributeCount": 0,
            "signatureRelatedEntryCount": 0,
            "versionedEntryCount": 0,
            "classpathMode": "jar-only",
            "launchMode": "java-jar"
        })
    }

    #[allow(clippy::too_many_lines)]
    fn runner_policy(role: PositiveRunnerRole) -> Value {
        let (provenance, mounts, tmpfs_bytes, working_directory) = match role {
            PositiveRunnerRole::RustValidatorBuild | PositiveRunnerRole::JvmValidatorBuild => (
                "exact-source-dependency-output-mounts-only",
                json!([
                    {
                        "sourceRole": "verified-source-tree",
                        "type": "bind-directory",
                        "target": "/src",
                        "readOnly": true,
                        "nodev": true,
                        "nosuid": true,
                        "noexec": true,
                        "propagation": "private"
                    },
                    {
                        "sourceRole": "dependency-closure",
                        "type": "bind-directory",
                        "target": "/deps",
                        "readOnly": true,
                        "nodev": true,
                        "nosuid": true,
                        "noexec": true,
                        "propagation": "private"
                    },
                    {
                        "sourceRole": "fresh-output-root",
                        "type": "bind-directory",
                        "target": "/out",
                        "readOnly": false,
                        "freshEmpty": true,
                        "nodev": true,
                        "nosuid": true,
                        "noexec": false,
                        "propagation": "private"
                    }
                ]),
                268_435_456,
                "/src",
            ),
            PositiveRunnerRole::RustVerifier => (
                "none",
                json!([
                    {
                        "sourceRole": "verifier-input-root",
                        "type": "bind-directory",
                        "target": "/input",
                        "readOnly": true,
                        "nodev": true,
                        "nosuid": true,
                        "noexec": true,
                        "propagation": "private"
                    },
                    {
                        "sourceRole": "validator-artifact",
                        "type": "bind-file",
                        "target": "/validator/validator",
                        "readOnly": true,
                        "nodev": true,
                        "nosuid": true,
                        "noexec": false,
                        "propagation": "private"
                    }
                ]),
                67_108_864,
                "/input",
            ),
            PositiveRunnerRole::JvmVerifier => (
                "none",
                json!([
                    {
                        "sourceRole": "verifier-input-root",
                        "type": "bind-directory",
                        "target": "/input",
                        "readOnly": true,
                        "nodev": true,
                        "nosuid": true,
                        "noexec": true,
                        "propagation": "private"
                    },
                    {
                        "sourceRole": "validator-artifact",
                        "type": "bind-file",
                        "target": "/validator/validator.jar",
                        "readOnly": true,
                        "nodev": true,
                        "nosuid": true,
                        "noexec": true,
                        "propagation": "private"
                    }
                ]),
                67_108_864,
                "/input",
            ),
        };
        let mut policy = json!({
            "lifecycle": "derive-create-inspect-start-wait-inspect-delete-confirm-absence",
            "reuse": false,
            "pullPolicy": "never",
            "network": "private-empty-loopback-down-no-address-no-route",
            "rootFilesystem": "read-only",
            "user": {"uid": 65532, "gid": 65532, "additionalGids": []},
            "namespaces": {
                "mount": "private",
                "pid": "private",
                "ipc": "private",
                "uts": "private",
                "user": "private",
                "cgroup": "private",
                "userMapping": "container-65532-to-finalizer-euid-egid-single-id",
                "network": "private-empty-loopback-down-no-address-no-route"
            },
            "capabilities": {
                "bounding": [],
                "effective": [],
                "inheritable": [],
                "permitted": [],
                "ambient": []
            },
            "noNewPrivileges": true,
            "fileDescriptors": {
                "stdin": "closed",
                "stdout": "bounded-capture",
                "stderr": "bounded-capture",
                "additionalInherited": 0
            },
            "hostAccess": {
                "devices": "fixed-host-pseudodevices-null-zero-full-random-urandom-only",
                "sockets": "none",
                "home": "none",
                "cache": "none",
                "provenance": provenance,
                "sysfs": "none",
                "proc": "private-pid-namespace-only"
            },
            "mounts": mounts,
            "tmpfs": [{
                "target": "/tmp",
                "sizeBytes": tmpfs_bytes,
                "fresh": true,
                "destroyAfterRun": true,
                "nodev": true,
                "nosuid": true,
                "noexec": true
            }],
            "workingDirectory": working_directory,
            "imageEntrypoint": "ignored-by-finalizer",
            "imageCmd": "ignored-by-finalizer",
            "imageEnvironment": "ignored-by-finalizer",
            "caseMetadata": "none",
            "crossRunMutableState": "none",
            "clockPolicy": "host-clocks-visible-not-authoritative",
            "inspection": {
                "beforeLaunch": "semantic-projection-and-created-state-required",
                "afterExit": "semantic-projection-and-stopped-state-required",
                "afterDestroy": "runtime-state-and-owned-path-absence-required"
            }
        });
        if role == PositiveRunnerRole::JvmValidatorBuild {
            policy["packagingPhase"] = json!({
                "phase": "copy-only-packaging",
                "hostAccessProvenance": "exact-phase-input-output-mounts-only",
                "mounts": [
                    {
                        "sourceRole": "jvm-copy-only-phase-input",
                        "type": "bind-directory",
                        "target": "/phase-input",
                        "readOnly": true,
                        "freshMaterialization": true,
                        "destroyAfterRun": true,
                        "contentsPolicy": "eip0045-b4-jvm-copy-only-phase-input-v1",
                        "nodev": true,
                        "nosuid": true,
                        "noexec": true,
                        "propagation": "private"
                    },
                    {
                        "sourceRole": "fresh-output-root",
                        "type": "bind-directory",
                        "target": "/out",
                        "readOnly": false,
                        "freshEmpty": true,
                        "nodev": true,
                        "nosuid": true,
                        "noexec": false,
                        "propagation": "private"
                    }
                ],
                "workingDirectory": "/phase-input"
            });
        }
        policy
    }

    fn runner_limits(role: PositiveRunnerRole) -> Value {
        match role {
            PositiveRunnerRole::RustValidatorBuild | PositiveRunnerRole::JvmValidatorBuild => {
                json!({
                    "wallTimeoutMilliseconds": 3_600_000,
                    "cgroup": {
                        "memoryBytes": 12_884_901_888_u64,
                        "memorySwapBytes": 0,
                        "cpuPeriodMicroseconds": 100_000,
                        "cpuQuotaMicroseconds": 800_000,
                        "pids": 512
                    },
                    "maximumOpenFileDescriptors": 1024,
                    "coreDumps": "disabled",
                    "stdoutBytes": 1_048_576,
                    "stderrBytes": 1_048_576,
                    "outputBytes": 34_359_738_368_u64,
                    "outputEntries": 1_000_000
                })
            }
            PositiveRunnerRole::RustVerifier | PositiveRunnerRole::JvmVerifier => {
                json!({
                    "wallTimeoutMilliseconds": 300_000,
                    "cgroup": {
                        "memoryBytes": 4_294_967_296_u64,
                        "memorySwapBytes": 0,
                        "cpuPeriodMicroseconds": 100_000,
                        "cpuQuotaMicroseconds": 400_000,
                        "pids": 256
                    },
                    "maximumOpenFileDescriptors": 256,
                    "coreDumps": "disabled",
                    "stdoutBytes": 65_536,
                    "stderrBytes": 65_536
                })
            }
        }
    }

    struct MaterializedFixture {
        seccomp_bytes: [Vec<u8>; 4],
        runner_values: [Value; 4],
        runner_bytes: [Vec<u8>; 4],
        descriptor_values: [Value; 2],
        descriptor_bytes: [Vec<u8>; 2],
        verifier_contract_bytes: Vec<u8>,
        jvm_copy_only_inclusion_manifest_value: Value,
        jvm_copy_only_inclusion_manifest_bytes: Vec<u8>,
        input_value: Value,
        input_bytes: Vec<u8>,
        reference_statement_bundle_manifest: Vec<u8>,
        source_lock: Vec<u8>,
        verifier_files: OwnedVerifierFiles,
        proof_generator_artifact: Vec<u8>,
        recursive_calibrations: [Vec<u8>; 3],
        generation_value: Value,
        generation_bytes: Vec<u8>,
        generation_cases: [OwnedGenerationCase; POSITIVE_CASE_COUNT],
        authoritative_build: AuthoritativeB4BuildProjection,
    }

    /// Exact owned bytes retained by the real positive gates for the bounded
    /// negative-ancestry constructor test.
    #[cfg(feature = "recursive-ancestry")]
    #[derive(Clone, Debug)]
    pub(crate) struct OwnedPositiveAuthorityTestArtifactV1 {
        pub(crate) path: String,
        pub(crate) bytes: Vec<u8>,
    }

    /// One complete owned V1 positive-case export emitted by the real
    /// positive-generation fixture and retained for sibling constructor tests.
    #[cfg(feature = "recursive-ancestry")]
    #[derive(Clone, Debug)]
    pub(crate) struct OwnedPositiveAuthorityTestCaseV1 {
        pub(crate) proof_output_manifest: OwnedPositiveAuthorityTestArtifactV1,
        pub(crate) primary_artifacts: Vec<OwnedPositiveAuthorityTestArtifactV1>,
        pub(crate) auxiliary_artifacts: Vec<OwnedPositiveAuthorityTestArtifactV1>,
    }

    /// Opaque positive authorities plus the exact source closure needed by the
    /// campaign and negative-ancestry production constructors.
    #[cfg(feature = "recursive-ancestry")]
    #[derive(Clone, Debug)]
    pub(crate) struct PositiveAuthorityTestSupportV1 {
        pub(crate) positive_gate_authority: B4PositiveGateAuthorityV1,
        pub(crate) positive_generation_authority: B4PositiveGenerationAuthorityV1,
        pub(crate) input_set: OwnedPositiveAuthorityTestArtifactV1,
        pub(crate) generation_set: OwnedPositiveAuthorityTestArtifactV1,
        pub(crate) proof_generator_artifact: OwnedPositiveAuthorityTestArtifactV1,
        pub(crate) verifier_contract: OwnedPositiveAuthorityTestArtifactV1,
        pub(crate) validator_descriptors: [OwnedPositiveAuthorityTestArtifactV1; 2],
        pub(crate) validator_artifacts: [OwnedPositiveAuthorityTestArtifactV1; 2],
        pub(crate) validator_source_archives: [OwnedPositiveAuthorityTestArtifactV1; 2],
        pub(crate) runner_profiles: [OwnedPositiveAuthorityTestArtifactV1; 4],
        pub(crate) seccomp_documents: [OwnedPositiveAuthorityTestArtifactV1; 4],
        pub(crate) jvm_copy_only_inclusion_manifest: OwnedPositiveAuthorityTestArtifactV1,
        pub(crate) profile_manifest: OwnedPositiveAuthorityTestArtifactV1,
        pub(crate) profile_algorithm: OwnedPositiveAuthorityTestArtifactV1,
        pub(crate) profile_constants: OwnedPositiveAuthorityTestArtifactV1,
        pub(crate) consumer_guest_elf: OwnedPositiveAuthorityTestArtifactV1,
        pub(crate) materialization_sources: Vec<OwnedPositiveAuthorityTestArtifactV1>,
        pub(crate) cases: [OwnedPositiveAuthorityTestCaseV1; POSITIVE_CASE_COUNT],
        pub(crate) case0_proof_output_manifest_jcs: Vec<u8>,
        pub(crate) case0_primary_artifacts: Vec<OwnedPositiveAuthorityTestArtifactV1>,
        pub(crate) case0_auxiliary_artifacts: Vec<OwnedPositiveAuthorityTestArtifactV1>,
        pub(crate) case8_proof_output_manifest_jcs: Vec<u8>,
        pub(crate) case8_primary_artifacts: Vec<OwnedPositiveAuthorityTestArtifactV1>,
        pub(crate) case8_auxiliary_artifacts: Vec<OwnedPositiveAuthorityTestArtifactV1>,
        pub(crate) case9_proof_output_manifest_jcs: Vec<u8>,
        pub(crate) case9_primary_artifacts: Vec<OwnedPositiveAuthorityTestArtifactV1>,
        pub(crate) case9_auxiliary_artifacts: Vec<OwnedPositiveAuthorityTestArtifactV1>,
    }

    impl Fixture {
        #[allow(clippy::too_many_lines)]
        fn valid() -> Self {
            Self::valid_with_reference_statement(
                HISTORICAL_REFERENCE_CHAIN_DOMAIN_ID,
                HISTORICAL_REFERENCE_APPLICATION_PAYLOAD,
            )
        }

        #[allow(clippy::too_many_lines)]
        fn valid_with_reference_statement(
            chain_domain_id: [u8; DIGEST_BYTES],
            application_payload: &[u8],
        ) -> Self {
            let profile_manifest = FIXTURE_PROFILE_MANIFEST_BYTES.to_vec();
            let profile_algorithm = FIXTURE_PROFILE_ALGORITHM_BYTES.to_vec();
            let profile_constants =
                include_bytes!("../../profiles/risc0-v3-succinct/constants.bin").to_vec();
            let profile_id = crate::profile::profile_id(&profile_manifest).unwrap();
            let (guest_elf, image_id) = valid_program_fixture();
            let proposition = b"semantic-gate-test-proposition";
            let statement = ergo_statement_v1(
                &chain_domain_id,
                &profile_id,
                &image_id,
                proposition,
                application_payload,
            )
            .unwrap();
            let reference_statement_bundle_manifest = reference_statement_bundle_manifest_jcs(
                &statement,
                chain_domain_id,
                profile_id,
                image_id,
                contract_id(proposition),
                application_payload,
                proposition,
            );
            let source_lock = canonical_json_bytes(&json!({
                "format": "Eip0045B4SourceLockV1",
                "formatVersion": 1,
                "sourceCommit": "ab".repeat(20),
                "sourceTree": "cd".repeat(20)
            }))
            .unwrap();
            let verifier_files = OwnedVerifierFiles {
                profile_manifest,
                profile_algorithm,
                profile_constants,
                guest_elf,
                statement,
                raw_seal: vec![0x06; 222_668],
            };
            let seccomp_values = std::array::from_fn(|_| {
                json!({
                    "format": "Eip0045B4PositiveSeccompV1",
                    "formatVersion": 1,
                    "linuxSeccomp": {
                        "defaultAction": "SCMP_ACT_ERRNO",
                        "defaultErrnoRet": 1,
                        "architectures": ["SCMP_ARCH_X86_64"],
                        "flags": [],
                        "syscalls": [{
                            "names": ["brk", "read", "write"],
                            "action": "SCMP_ACT_ALLOW",
                            "args": []
                        }]
                    }
                })
            });
            let roles = PositiveRunnerRole::all();
            let runner_values = std::array::from_fn(|index| {
                let role = roles[index];
                let index_byte = u8::try_from(index).unwrap();
                let mut profile = json!({
                    "format": "Eip0045B4PositiveOciRunnerProfileV1",
                    "formatVersion": 1,
                    "runnerProfileIndex": index,
                    "purpose": role.purpose(),
                    "platform": {
                        "os": "linux",
                        "architecture": "amd64"
                    },
                    "image": {
                        "policy": "eip0045-b4-oci-image-v1",
                        "retainedHostRootfsMetadataPolicy": "eip0045-b4-retained-host-rootfs-metadata-obligations-v1",
                        "imageSpec": {
                            "version": "1.1.1",
                            "commit": "147f9c13cedb47a0c4d9a11a222961073d585877"
                        },
                        "layoutVersion": "1.0.0",
                        "archive": {
                            "path": format!("runner/image-{index}.tar"),
                            "byteLength": 1024,
                            "sha256": digest(0x70_u8.wrapping_add(index_byte)),
                            "encoding": "eip0045-b4-oci-image-layout-ustar-v1"
                        },
                        "manifest": {
                            "mediaType": "application/vnd.oci.image.manifest.v1+json",
                            "digest": format!("sha256:{}", digest(0x71_u8.wrapping_add(index_byte))),
                            "size": 512
                        },
                        "config": {
                            "mediaType": "application/vnd.oci.image.config.v1+json",
                            "digest": format!("sha256:{}", digest(0x72_u8.wrapping_add(index_byte))),
                            "size": 256
                        },
                        "platform": {
                            "os": "linux",
                            "architecture": "amd64"
                        },
                        "layers": [{
                            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                            "digest": format!("sha256:{}", digest(0x73_u8.wrapping_add(index_byte))),
                            "size": 768,
                            "uncompressedBytes": 2048,
                            "diffId": format!("sha256:{}", digest(0x74_u8.wrapping_add(index_byte)))
                        }],
                        "postChangesetRootfs": {
                            "entryCount": 3,
                            "regularFileCount": 1,
                            "directoryCount": 1,
                            "symbolicLinkCount": 1,
                            "regularFileBytes": 64
                        }
                    },
                    "runtime": {
                        "name": "runc",
                        "version": "1.3.0",
                        "runtimeSpec": {
                            "version": "1.3.0",
                            "commit": "92249139eea7161e13745abd4cb6d0ea02a3227a"
                        },
                        "configurationPolicy": "eip0045-b4-oci-runtime-config-projection-v1",
                        "observationSelectors": {
                            "state": "eip0045-b4-runtime-observation-runc-state-json-v1",
                            "processIdentity": "eip0045-b4-runtime-observation-linux-boot-id-pid-starttime-jcs-v1",
                            "namespaces": "eip0045-b4-runtime-observation-namespaces-reserved-v1",
                            "idMappings": "eip0045-b4-runtime-observation-id-mappings-reserved-v1",
                            "mountinfo": "eip0045-b4-runtime-observation-mountinfo-reserved-v1",
                            "securityStatus": "eip0045-b4-runtime-observation-security-status-reserved-v1",
                            "cgroupV2": "eip0045-b4-runtime-observation-cgroup-v2-reserved-v1",
                            "rootIdentity": "eip0045-b4-runtime-observation-root-identity-reserved-v1",
                            "auxv": "eip0045-b4-runtime-observation-auxv-reserved-v1",
                            "processMappings": "eip0045-b4-runtime-observation-process-mappings-reserved-v1",
                            "smokeIdentity": "eip0045-b4-runtime-observation-smoke-identity-reserved-v1"
                        },
                        "binary": {
                            "path": format!("runner/runc-{index}"),
                            "byteLength": 64,
                            "sha256": digest(0x80_u8.wrapping_add(index_byte)),
                            "encoding": "raw-bytes",
                            "fileFormat": "elf64",
                            "architecture": "amd64",
                            "linkage": "static-no-interpreter",
                            "inspectionPolicy": "eip0045-b4-elf64-amd64-static-v1",
                            "elf": static_elf_inspection()
                        }
                    },
                    "seccomp": {
                        "policy": "eip0045-b4-positive-seccomp-v1",
                        "format": "Eip0045B4PositiveSeccompV1",
                        "profile": document_identity(
                            "Eip0045B4PositiveSeccompV1",
                            &format!("runner/seccomp-{index}.json"),
                            b"{}"
                        ),
                        "allowedSyscalls": ["brk", "read", "write"]
                    },
                    "environment": {
                        "inheritance": "none",
                        "variables": {
                            "LANG": "C.UTF-8",
                            "LC_ALL": "C.UTF-8",
                            "TZ": "UTC"
                        }
                    },
                    "policy": runner_policy(role),
                    "limits": runner_limits(role)
                });
                if role == PositiveRunnerRole::JvmValidatorBuild {
                    profile["buildJdk"] = json!({
                        "startupDependencyPolicy": STARTUP_DEPENDENCY_POLICY_ID,
                        "launcher": {
                            "imagePath": "/runtime/bin/java",
                            "byteLength": 64,
                            "sha256": digest(0x61),
                            "encoding": "raw-bytes",
                            "fileFormat": "elf64",
                            "architecture": "amd64",
                            "inspectionPolicy": "eip0045-b4-elf64-amd64-runtime-v1",
                            "elf": runtime_elf_inspection()
                        },
                        "compiler": {
                            "imagePath": "/runtime/bin/javac",
                            "byteLength": 64,
                            "sha256": digest(0x63),
                            "encoding": "raw-bytes",
                            "fileFormat": "elf64",
                            "architecture": "amd64",
                            "inspectionPolicy": "eip0045-b4-elf64-amd64-runtime-v1",
                            "elf": runtime_elf_inspection()
                        },
                        "release": {
                            "imagePath": "/runtime/release",
                            "byteLength": 128,
                            "sha256": digest(0x62),
                            "encoding": "openjdk-release-file-utf8-v1"
                        },
                        "featureVersion": 21,
                        "vendor": "Fixture JVM",
                        "version": "21.0.1"
                    });
                } else if role == PositiveRunnerRole::JvmVerifier {
                    profile["javaRuntime"] = json!({
                        "startupDependencyPolicy": STARTUP_DEPENDENCY_POLICY_ID,
                        "binary": {
                            "imagePath": "/runtime/bin/java",
                            "byteLength": 64,
                            "sha256": digest(0x61),
                            "encoding": "raw-bytes",
                            "fileFormat": "elf64",
                            "architecture": "amd64",
                            "inspectionPolicy": "eip0045-b4-elf64-amd64-runtime-v1",
                            "elf": runtime_elf_inspection()
                        },
                        "release": {
                            "imagePath": "/runtime/release",
                            "byteLength": 128,
                            "sha256": digest(0x62),
                            "encoding": "openjdk-release-file-utf8-v1"
                        },
                        "featureVersion": 21,
                        "vendor": "Fixture JVM",
                        "version": "21.0.1",
                        "options": JVM_OPTIONS
                    });
                }
                profile["image"]["archive"]["byteLength"] =
                    json!(expected_oci_archive_byte_length(&profile["image"]).unwrap());
                profile
            });
            let mut descriptor_values = [
                descriptor(
                    PositiveImplementation::RustReference,
                    "src/rust/Verifier.rs",
                    0x11,
                    0x31,
                    0x41,
                    "artifacts/rust-validator",
                    100,
                    0x51,
                    "direct-native",
                ),
                descriptor(
                    PositiveImplementation::IndependentJvm,
                    "src/jvm/SuccinctVerifier.scala",
                    0x12,
                    0x32,
                    0x42,
                    "artifacts/jvm-validator.jar",
                    200,
                    0x52,
                    "direct-java-jar",
                ),
            ];
            let jvm_copy_only_inclusion_manifest_value =
                jvm_copy_only_inclusion_manifest(&descriptor_values[1]);
            let jvm_copy_only_inclusion_manifest_bytes =
                canonical_json_bytes(&jvm_copy_only_inclusion_manifest_value).unwrap();
            descriptor_values[1]["artifact"]["packaging"]["inclusionManifest"] = document_identity(
                "Eip0045B4JvmCopyOnlyInclusionManifestV1",
                JVM_COPY_ONLY_INCLUSION_MANIFEST_PATH,
                &jvm_copy_only_inclusion_manifest_bytes,
            );
            let proof_generator_artifact = vec![0xa1; 128];
            let proof_generator_identity = file_identity_from_bytes(
                "generator/eip0045-candidate-generator",
                &proof_generator_artifact,
            );
            let proof_generator_commitment = binary_commitment(&proof_generator_identity).unwrap();
            let source_lock_identity =
                jcs_file_identity_from_bytes("locks/source-lock.json", &source_lock);
            let recursive_calibrations = [
                canonical_json_bytes(&json!({
                    "caseId": "terminal-join",
                    "fixture": 8
                }))
                .unwrap(),
                canonical_json_bytes(&json!({
                    "caseId": "terminal-resolve-explicit-root",
                    "fixture": 9
                }))
                .unwrap(),
                canonical_json_bytes(&json!({
                    "caseId": "resolve-zero-root-then-join",
                    "fixture": 10
                }))
                .unwrap(),
            ];
            let positive_cases = Value::Array(
                POSITIVE_CASE_SPECS
                    .iter()
                    .enumerate()
                    .map(|(index, spec)| canonical_positive_case_plan(index, *spec))
                    .collect(),
            );
            let verifier_contract_value = fixture_verifier_contract();
            let verifier_contract_bytes = canonical_json_bytes(&verifier_contract_value).unwrap();
            let input_value = json!({
                "format": "Eip0045B4PositiveInputSetV1",
                "formatVersion": 1,
                "profile": {
                    "profileId": hex::encode(profile_id),
                    "manifest": file_identity_from_bytes("profiles/risc0-v3-succinct/manifest.bin", &verifier_files.profile_manifest),
                    "algorithm": file_identity_from_bytes("profiles/risc0-v3-succinct/algorithm.txt", &verifier_files.profile_algorithm),
                    "constants": file_identity_from_bytes("profiles/risc0-v3-succinct/constants.bin", &verifier_files.profile_constants)
                },
                "guest": {
                    "elf": file_identity_from_bytes("methods/guest.elf", &verifier_files.guest_elf),
                    "imageId": hex::encode(image_id)
                },
                "referenceStatement": {
                    "bundleManifest": jcs_file_identity_from_bytes(
                        "statement/bundle-manifest.json",
                        &reference_statement_bundle_manifest
                    ),
                    "contractId": hex::encode(contract_id(proposition)),
                    "statementByteLength": verifier_files.statement.len(),
                    "statementSha256": sha256_hex(&verifier_files.statement),
                    "chainDomainId": hex::encode(chain_domain_id),
                    "applicationPayloadByteLength": application_payload.len(),
                    "applicationPayloadSha256": sha256_hex(application_payload)
                },
                "sourceLock": source_lock_identity,
                "proofGenerator": {
                    "artifact": proof_generator_identity,
                    "qualifyingBuild": {
                        "policy": "eip0045-b4-qualifying-build-binding-v1",
                        "validationMode": "authoritative-external-anchors",
                        "filesystemBinding": "unix-file-identity-bound",
                        "evidenceRootSha256": digest(0xa4),
                        "sourceCommit": "ab".repeat(20),
                        "sourceTree": "cd".repeat(20),
                        "sourceLockSha256": sha256_hex(&source_lock),
                        "generatorCargoClosureSha256": digest(0xa6),
                        "proofGenerationTestsSha256": digest(0xa7),
                        "generatorArtifact": proof_generator_commitment
                    },
                    "executionPolicy": {
                        "policy": "eip0045-b4-proof-generation-executor-v1",
                        "caseOrder": "input-set-order",
                        "generatorProcessReuse": false,
                        "replayProcessReuse": false,
                        "network": "disabled",
                        "environmentInheritance": "none",
                        "inputSetMount": "read-only-preexisting",
                        "caseOutput": "fresh-empty-create-only",
                        "replayExportMount": "read-only-physical-export",
                        "failurePublication": "none"
                    }
                },
                "verifierCliContract": document_identity(
                    "Eip0045B4VerifierContractV1",
                    VERIFIER_CONTRACT_PATH,
                    &verifier_contract_bytes
                ),
                "runnerProfiles": [{}, {}, {}, {}],
                "validators": [{}, {}],
                "recursiveCalibrations": [
                    {
                        "caseId": "terminal-join",
                        "artifact": jcs_file_identity_from_bytes(
                            "calibration/terminal-join.json",
                            &recursive_calibrations[0]
                        )
                    },
                    {
                        "caseId": "terminal-resolve-explicit-root",
                        "artifact": jcs_file_identity_from_bytes(
                            "calibration/terminal-resolve-explicit-root.json",
                            &recursive_calibrations[1]
                        )
                    },
                    {
                        "caseId": "resolve-zero-root-then-join",
                        "artifact": jcs_file_identity_from_bytes(
                            "calibration/resolve-zero-root-then-join.json",
                            &recursive_calibrations[2]
                        )
                    }
                ],
                "positiveCases": positive_cases
            });
            let authoritative_build =
                AuthoritativeB4BuildProjection::for_test(TestAuthoritativeB4BuildProjection {
                    evidence_root_sha256: digest(0xa4),
                    source_commit: "ab".repeat(20),
                    source_tree: "cd".repeat(20),
                    source_lock_sha256: sha256_hex(&source_lock),
                    generator_cargo_closure_sha256: digest(0xa6),
                    proof_generation_tests_sha256: digest(0xa7),
                    generator_artifact_sha256: sha256_hex(&proof_generator_artifact),
                    generator_artifact_byte_length: u64::try_from(proof_generator_artifact.len())
                        .unwrap(),
                    guest_elf_sha256: sha256_hex(&verifier_files.guest_elf),
                    guest_elf_byte_length: u64::try_from(verifier_files.guest_elf.len()).unwrap(),
                    image_id_hex: hex::encode(image_id),
                    statement_sha256: sha256_hex(&verifier_files.statement),
                    statement_byte_length: u64::try_from(verifier_files.statement.len()).unwrap(),
                    contract_id_hex: hex::encode(contract_id(proposition)),
                    chain_domain_id_hex: hex::encode(chain_domain_id),
                    application_payload_sha256: sha256_hex(application_payload),
                    application_payload_byte_length: u64::try_from(application_payload.len())
                        .unwrap(),
                });
            Self {
                seccomp_values,
                runner_values,
                descriptor_values,
                verifier_contract_value,
                jvm_copy_only_inclusion_manifest_value,
                input_value,
                reference_statement_bundle_manifest,
                source_lock,
                verifier_files,
                proof_generator_artifact,
                recursive_calibrations,
                authoritative_build,
            }
        }

        fn materialize(&self) -> MaterializedFixture {
            let verifier_contract_value = self.verifier_contract_value.clone();
            let verifier_contract_bytes = canonical_json_bytes(&verifier_contract_value).unwrap();
            let jvm_copy_only_inclusion_manifest_value =
                self.jvm_copy_only_inclusion_manifest_value.clone();
            let jvm_copy_only_inclusion_manifest_bytes =
                canonical_json_bytes(&jvm_copy_only_inclusion_manifest_value).unwrap();
            let seccomp_values = self.seccomp_values.clone();
            let seccomp_bytes = seccomp_values
                .clone()
                .map(|value| canonical_json_bytes(&value).unwrap());
            let mut runner_values = self.runner_values.clone();
            for index in 0..runner_values.len() {
                runner_values[index]["seccomp"]["profile"] = document_identity(
                    "Eip0045B4PositiveSeccompV1",
                    SECCOMP_PATHS[index],
                    &seccomp_bytes[index],
                );
            }
            let runner_bytes = runner_values
                .clone()
                .map(|value| canonical_json_bytes(&value).unwrap());
            let runner_identities: [Value; 4] = std::array::from_fn(|index| {
                document_identity(
                    "Eip0045B4PositiveOciRunnerProfileV1",
                    RUNNER_PATHS[index],
                    &runner_bytes[index],
                )
            });

            let mut descriptor_values = self.descriptor_values.clone();
            for (index, implementation) in [
                PositiveImplementation::RustReference,
                PositiveImplementation::IndependentJvm,
            ]
            .into_iter()
            .enumerate()
            {
                let build = implementation.build_role();
                descriptor_values[index]["deterministicBuild"]["runnerProfile"] =
                    profile_reference(build, &runner_identities[build.index()]);
                let execution = implementation.execution_role();
                descriptor_values[index]["executionEnvironment"]["runnerProfile"] =
                    profile_reference(execution, &runner_identities[execution.index()]);
            }
            let descriptor_bytes = descriptor_values
                .clone()
                .map(|value| canonical_json_bytes(&value).unwrap());

            let mut input_value = self.input_value.clone();
            for (index, runner_identity) in runner_identities.iter().enumerate() {
                let role = PositiveRunnerRole::all()[index];
                input_value["runnerProfiles"][index] = json!({
                    "runnerProfileIndex": index,
                    "purpose": role.purpose(),
                    "artifact": runner_identity
                });
            }
            for (index, implementation) in [
                PositiveImplementation::RustReference,
                PositiveImplementation::IndependentJvm,
            ]
            .into_iter()
            .enumerate()
            {
                input_value["validators"][index] = json!({
                    "implementationIndex": index,
                    "implementation": implementation.implementation(),
                    "language": implementation.language(),
                    "buildDescriptor": document_identity(
                        "Eip0045B4ValidatorBuildDescriptorV1",
                        DESCRIPTOR_PATHS[index],
                        &descriptor_bytes[index]
                    )
                });
            }
            let input_bytes = canonical_json_bytes(&input_value).unwrap();
            let (generation_value, generation_bytes, generation_cases) = build_generation_fixture(
                &input_value,
                &input_bytes,
                &self.verifier_files,
                &self.proof_generator_artifact,
                &self.recursive_calibrations,
            );
            MaterializedFixture {
                seccomp_bytes,
                runner_values,
                runner_bytes,
                descriptor_values,
                descriptor_bytes,
                verifier_contract_bytes,
                jvm_copy_only_inclusion_manifest_value,
                jvm_copy_only_inclusion_manifest_bytes,
                input_value,
                input_bytes,
                reference_statement_bundle_manifest: self
                    .reference_statement_bundle_manifest
                    .clone(),
                source_lock: self.source_lock.clone(),
                verifier_files: self.verifier_files.clone(),
                proof_generator_artifact: self.proof_generator_artifact.clone(),
                recursive_calibrations: self.recursive_calibrations.clone(),
                generation_value,
                generation_bytes,
                generation_cases,
                authoritative_build: self.authoritative_build.clone(),
            }
        }
    }

    impl MaterializedFixture {
        fn bind(&self) -> Result<PositiveGateBindings> {
            self.bind_with_input_path(INPUT_SET_PATH)
        }

        fn bind_with_input_path(&self, input_set_path: &str) -> Result<PositiveGateBindings> {
            self.bind_with_input_and_verifier_paths(input_set_path, VERIFIER_CONTRACT_PATH)
        }

        fn bind_with_input_and_verifier_paths(
            &self,
            input_set_path: &str,
            verifier_contract_path: &str,
        ) -> Result<PositiveGateBindings> {
            PositiveGateBindings::validate_and_bind_jcs(PositiveProvenanceDocuments {
                authoritative_build: &self.authoritative_build,
                input_set: NamedCanonicalJcs {
                    relative_path: input_set_path,
                    bytes: &self.input_bytes,
                },
                verifier_contract: NamedCanonicalJcs {
                    relative_path: verifier_contract_path,
                    bytes: &self.verifier_contract_bytes,
                },
                runner_profiles: std::array::from_fn(|index| NamedCanonicalJcs {
                    relative_path: RUNNER_PATHS[index],
                    bytes: &self.runner_bytes[index],
                }),
                seccomp_profiles: std::array::from_fn(|index| NamedCanonicalJcs {
                    relative_path: SECCOMP_PATHS[index],
                    bytes: &self.seccomp_bytes[index],
                }),
                validator_descriptors: std::array::from_fn(|index| NamedCanonicalJcs {
                    relative_path: DESCRIPTOR_PATHS[index],
                    bytes: &self.descriptor_bytes[index],
                }),
                jvm_copy_only_inclusion_manifest: NamedCanonicalJcs {
                    relative_path: JVM_COPY_ONLY_INCLUSION_MANIFEST_PATH,
                    bytes: &self.jvm_copy_only_inclusion_manifest_bytes,
                },
            })
        }

        fn bind_generation(&self) -> Result<PositiveGenerationBindings> {
            self.bind_generation_at(GENERATION_SET_PATH)
        }

        fn bind_generation_at(
            &self,
            generation_set_path: &str,
        ) -> Result<PositiveGenerationBindings> {
            let provenance = self.bind()?;
            let artifact_views: [Vec<GeneratedArtifactContents<'_>>; POSITIVE_CASE_COUNT] =
                std::array::from_fn(|index| {
                    self.generation_cases[index]
                        .artifacts
                        .iter()
                        .map(|artifact| GeneratedArtifactContents {
                            source_file: artifact.source_file,
                            bytes: &artifact.bytes,
                        })
                        .collect()
                });
            let auxiliary_artifact_views: [Vec<GeneratedAuxiliaryArtifactContents<'_>>;
                POSITIVE_CASE_COUNT] = std::array::from_fn(|index| {
                self.generation_cases[index]
                    .auxiliary_artifacts
                    .iter()
                    .map(|artifact| GeneratedAuxiliaryArtifactContents {
                        relative_path: artifact.source_file,
                        bytes: &artifact.bytes,
                    })
                    .collect()
            });
            let cases = std::array::from_fn(|index| PositiveGenerationCaseDocuments {
                proof_output_manifest_jcs: &self.generation_cases[index].proof_output_manifest_jcs,
                artifacts: &artifact_views[index],
                auxiliary_artifacts: &auxiliary_artifact_views[index],
            });
            provenance.bind_generation_set(PositiveGenerationDocuments {
                generation_set: NamedCanonicalJcs {
                    relative_path: generation_set_path,
                    bytes: &self.generation_bytes,
                },
                proof_generator_artifact: &self.proof_generator_artifact,
                cases,
            })
        }

        fn validate_generation_case_only(&self, index: usize) -> Result<()> {
            let artifacts = self.generation_cases[index]
                .artifacts
                .iter()
                .map(|artifact| GeneratedArtifactContents {
                    source_file: artifact.source_file,
                    bytes: &artifact.bytes,
                })
                .collect::<Vec<_>>();
            let auxiliary_artifacts = self.generation_cases[index]
                .auxiliary_artifacts
                .iter()
                .map(|artifact| GeneratedAuxiliaryArtifactContents {
                    relative_path: artifact.source_file,
                    bytes: &artifact.bytes,
                })
                .collect::<Vec<_>>();
            validate_generation_case(
                index,
                &self.input_value["positiveCases"][index],
                &self.generation_value["cases"][index],
                PositiveGenerationCaseDocuments {
                    proof_output_manifest_jcs: &self.generation_cases[index]
                        .proof_output_manifest_jcs,
                    artifacts: &artifacts,
                    auxiliary_artifacts: &auxiliary_artifacts,
                },
                &self.input_value,
            )
            .map(|_| ())
        }
    }

    /// Build both opaque positive authorities through the production gates
    /// while replacing the otherwise preimage-free synthetic descriptor
    /// identities with exact caller-held bytes.
    ///
    /// This is deliberately test-only. It does not expose `Fixture`,
    /// `MaterializedFixture`, or either authority's private fields.
    #[allow(
        clippy::too_many_lines,
        reason = "the helper keeps one linear production-gate setup so no intermediate unchecked authority escapes"
    )]
    #[cfg(feature = "recursive-ancestry")]
    pub(crate) fn build_positive_authority_test_support(
        verifier_contract_jcs: &[u8],
        validator_artifacts: [&[u8]; 2],
        validator_source_archives: [&[u8]; 2],
        case9_assumption_raw_seal: &[u8],
    ) -> Result<PositiveAuthorityTestSupportV1> {
        build_positive_authority_test_support_with_reference_statement(
            verifier_contract_jcs,
            validator_artifacts,
            validator_source_archives,
            case9_assumption_raw_seal,
            HISTORICAL_REFERENCE_CHAIN_DOMAIN_ID,
            HISTORICAL_REFERENCE_APPLICATION_PAYLOAD,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the test-only sibling preserves the complete production-gate setup while varying only the authenticated reference-statement inputs"
    )]
    #[cfg(feature = "recursive-ancestry")]
    pub(crate) fn build_positive_authority_test_support_with_reference_statement(
        verifier_contract_jcs: &[u8],
        validator_artifacts: [&[u8]; 2],
        validator_source_archives: [&[u8]; 2],
        case9_assumption_raw_seal: &[u8],
        chain_domain_id: [u8; DIGEST_BYTES],
        application_payload: &[u8],
    ) -> Result<PositiveAuthorityTestSupportV1> {
        ensure!(
            case9_assumption_raw_seal.len() == PROOF_BYTES,
            "test case-9 assumption raw seal has the wrong exact length"
        );
        let verifier_contract_value = validate_canonical_json_source(verifier_contract_jcs)?;

        let mut fixture =
            Fixture::valid_with_reference_statement(chain_domain_id, application_payload);
        fixture.verifier_contract_value = verifier_contract_value;
        fixture.input_value["verifierCliContract"] = document_identity(
            "Eip0045B4VerifierContractV1",
            VERIFIER_CONTRACT_PATH,
            verifier_contract_jcs,
        );
        for index in 0..2 {
            fixture.descriptor_values[index]["artifact"]["byteLength"] =
                json!(validator_artifacts[index].len());
            fixture.descriptor_values[index]["artifact"]["sha256"] =
                json!(sha256_hex(validator_artifacts[index]));
            fixture.descriptor_values[index]["reviewedSource"]["archive"]["byteLength"] =
                json!(validator_source_archives[index].len());
            fixture.descriptor_values[index]["reviewedSource"]["archive"]["sha256"] =
                json!(sha256_hex(validator_source_archives[index]));
        }
        fixture.jvm_copy_only_inclusion_manifest_value =
            jvm_copy_only_inclusion_manifest(&fixture.descriptor_values[1]);
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut fixture);

        let mut materialized = fixture.materialize();
        let case9 = &mut materialized.generation_cases[9];
        let conditional_raw_seal = case9
            .auxiliary_artifacts
            .get(1)
            .context("positive case 9 lacks its conditional auxiliary seal")?
            .bytes
            .clone();
        let final_raw_seal = case9
            .artifacts
            .get(6)
            .context("positive case 9 lacks its final raw seal")?
            .bytes
            .clone();
        let mut ancestry = crate::recursive_ancestry::tests::synthetic_terminal_resolve(
            &materialized.verifier_files.statement,
        );
        ancestry
            .assumption_receipt
            .as_mut()
            .context("synthetic terminal-resolve ancestry lacks its assumption")?
            .raw_seal
            .sha256 = sha256_hex(case9_assumption_raw_seal);
        ancestry
            .steps
            .get_mut(0)
            .context("synthetic terminal-resolve ancestry lacks step zero")?
            .raw_seal
            .sha256 = sha256_hex(&conditional_raw_seal);
        ancestry
            .steps
            .get_mut(1)
            .context("synthetic terminal-resolve ancestry lacks its final step")?
            .raw_seal
            .sha256 = sha256_hex(&final_raw_seal);
        case9
            .artifacts
            .get_mut(0)
            .context("positive case 9 lacks its ancestry artifact")?
            .bytes = crate::recursive_ancestry::recursive_ancestry_to_jcs(&ancestry)?;
        case9
            .auxiliary_artifacts
            .get_mut(0)
            .context("positive case 9 lacks its assumption auxiliary seal")?
            .bytes = case9_assumption_raw_seal.to_vec();
        refresh_generation_case(&mut materialized, 9);

        let generation_bindings = materialized.bind_generation()?;
        let positive_gate_authority = generation_bindings
            .provenance
            .campaign_precommit_authority();
        let positive_generation_authority = generation_bindings.positive_generation_authority();

        let owned = |path: &str, bytes: &[u8]| OwnedPositiveAuthorityTestArtifactV1 {
            path: path.to_owned(),
            bytes: bytes.to_vec(),
        };
        let descriptor_values = &materialized.descriptor_values;
        let validator_artifacts = std::array::from_fn(|index| {
            owned(
                descriptor_values[index]["artifact"]["path"]
                    .as_str()
                    .expect("validated descriptor artifact path"),
                validator_artifacts[index],
            )
        });
        let validator_source_archives = std::array::from_fn(|index| {
            owned(
                descriptor_values[index]["reviewedSource"]["archive"]["path"]
                    .as_str()
                    .expect("validated descriptor source-archive path"),
                validator_source_archives[index],
            )
        });
        let proof_generator_path = materialized.input_value["proofGenerator"]["artifact"]["path"]
            .as_str()
            .context("validated proof-generator artifact path is absent")?;
        let cases: [OwnedPositiveAuthorityTestCaseV1; POSITIVE_CASE_COUNT] = materialized
            .generation_cases
            .iter()
            .enumerate()
            .map(|(index, case)| {
                let generated = &materialized.generation_value["cases"][index];
                let case_id = generated["caseId"]
                    .as_str()
                    .with_context(|| format!("validated positive case {index} ID is absent"))?;
                let manifest_name = generated["proofOutputManifest"]["fileName"]
                    .as_str()
                    .with_context(|| {
                        format!("validated positive case {index} manifest filename is absent")
                    })?;
                Ok(OwnedPositiveAuthorityTestCaseV1 {
                    proof_output_manifest: owned(
                        &crate::b4::canonical_positive_case_artifact_path(case_id, manifest_name),
                        &case.proof_output_manifest_jcs,
                    ),
                    primary_artifacts: case
                        .artifacts
                        .iter()
                        .map(|artifact| {
                            owned(
                                &crate::b4::canonical_positive_case_artifact_path(
                                    case_id,
                                    artifact.source_file,
                                ),
                                &artifact.bytes,
                            )
                        })
                        .collect(),
                    auxiliary_artifacts: case
                        .auxiliary_artifacts
                        .iter()
                        .map(|artifact| owned(artifact.source_file, &artifact.bytes))
                        .collect(),
                })
            })
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_: Vec<_>| anyhow::anyhow!("positive V1 test case cardinality drift"))?;
        let reference_statement_manifest_path =
            materialized.input_value["referenceStatement"]["bundleManifest"]["path"]
                .as_str()
                .context("validated reference-statement manifest path is absent")?;
        let source_lock_path = materialized.input_value["sourceLock"]["path"]
            .as_str()
            .context("validated source-lock path is absent")?;
        let mut materialization_sources = vec![
            owned(
                "profiles/risc0-v3-succinct/manifest.bin",
                &materialized.verifier_files.profile_manifest,
            ),
            owned(
                "profiles/risc0-v3-succinct/algorithm.txt",
                &materialized.verifier_files.profile_algorithm,
            ),
            owned(
                "profiles/risc0-v3-succinct/constants.bin",
                &materialized.verifier_files.profile_constants,
            ),
            owned("methods/guest.elf", &materialized.verifier_files.guest_elf),
            owned(
                reference_statement_manifest_path,
                &materialized.reference_statement_bundle_manifest,
            ),
            owned(source_lock_path, &materialized.source_lock),
            owned(proof_generator_path, &materialized.proof_generator_artifact),
            owned(VERIFIER_CONTRACT_PATH, verifier_contract_jcs),
        ];
        materialization_sources.extend(
            materialized
                .runner_bytes
                .iter()
                .enumerate()
                .map(|(index, bytes)| owned(RUNNER_PATHS[index], bytes)),
        );
        materialization_sources.extend(
            materialized
                .descriptor_bytes
                .iter()
                .enumerate()
                .map(|(index, bytes)| owned(DESCRIPTOR_PATHS[index], bytes)),
        );
        materialization_sources.extend(materialized.recursive_calibrations.iter().enumerate().map(
            |(index, bytes)| {
                let path =
                    materialized.input_value["recursiveCalibrations"][index]["artifact"]["path"]
                        .as_str()
                        .expect("validated recursive-calibration path");
                owned(path, bytes)
            },
        ));
        materialization_sources.extend(validator_artifacts.iter().cloned());
        materialization_sources
            .sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        ensure!(
            materialization_sources
                .windows(2)
                .all(|pair| pair[0].path.as_bytes() < pair[1].path.as_bytes()),
            "positive V1 materialization-source inventory contains a duplicate path"
        );
        let case0_proof_output_manifest_jcs = cases[0].proof_output_manifest.bytes.clone();
        let case0_primary_artifacts = cases[0].primary_artifacts.clone();
        let case0_auxiliary_artifacts = cases[0].auxiliary_artifacts.clone();
        let case8_proof_output_manifest_jcs = cases[8].proof_output_manifest.bytes.clone();
        let case8_primary_artifacts = cases[8].primary_artifacts.clone();
        let case8_auxiliary_artifacts = cases[8].auxiliary_artifacts.clone();
        let case9_proof_output_manifest_jcs = cases[9].proof_output_manifest.bytes.clone();
        let case9_primary_artifacts = cases[9].primary_artifacts.clone();
        let case9_auxiliary_artifacts = cases[9].auxiliary_artifacts.clone();

        Ok(PositiveAuthorityTestSupportV1 {
            positive_gate_authority,
            positive_generation_authority,
            input_set: owned(INPUT_SET_PATH, &materialized.input_bytes),
            generation_set: owned(GENERATION_SET_PATH, &materialized.generation_bytes),
            proof_generator_artifact: owned(
                proof_generator_path,
                &materialized.proof_generator_artifact,
            ),
            verifier_contract: owned(VERIFIER_CONTRACT_PATH, verifier_contract_jcs),
            validator_descriptors: std::array::from_fn(|index| {
                owned(
                    DESCRIPTOR_PATHS[index],
                    &materialized.descriptor_bytes[index],
                )
            }),
            validator_artifacts,
            validator_source_archives,
            runner_profiles: std::array::from_fn(|index| {
                owned(RUNNER_PATHS[index], &materialized.runner_bytes[index])
            }),
            seccomp_documents: std::array::from_fn(|index| {
                owned(SECCOMP_PATHS[index], &materialized.seccomp_bytes[index])
            }),
            jvm_copy_only_inclusion_manifest: owned(
                JVM_COPY_ONLY_INCLUSION_MANIFEST_PATH,
                &materialized.jvm_copy_only_inclusion_manifest_bytes,
            ),
            profile_manifest: owned(
                "profiles/risc0-v3-succinct/manifest.bin",
                &materialized.verifier_files.profile_manifest,
            ),
            profile_algorithm: owned(
                "profiles/risc0-v3-succinct/algorithm.txt",
                &materialized.verifier_files.profile_algorithm,
            ),
            profile_constants: owned(
                "profiles/risc0-v3-succinct/constants.bin",
                &materialized.verifier_files.profile_constants,
            ),
            consumer_guest_elf: owned("methods/guest.elf", &materialized.verifier_files.guest_elf),
            materialization_sources,
            cases,
            case0_proof_output_manifest_jcs,
            case0_primary_artifacts,
            case0_auxiliary_artifacts,
            case8_proof_output_manifest_jcs,
            case8_primary_artifacts,
            case8_auxiliary_artifacts,
            case9_proof_output_manifest_jcs,
            case9_primary_artifacts,
            case9_auxiliary_artifacts,
        })
    }

    #[cfg(feature = "recursive-ancestry")]
    #[test]
    fn historical_positive_authority_wrapper_is_exact_and_parameterized_sibling_is_bound() {
        let verifier_contract = canonical_json_bytes(&fixture_verifier_contract()).unwrap();
        let validator_artifacts = [vec![0x91; 100], vec![0x92; 200]];
        let validator_source_archives = [vec![0x93; 1_000], vec![0x94; 1_000]];
        let case9_assumption_raw_seal = vec![0xa5; PROOF_BYTES];
        let historical = build_positive_authority_test_support(
            &verifier_contract,
            [&validator_artifacts[0], &validator_artifacts[1]],
            [&validator_source_archives[0], &validator_source_archives[1]],
            &case9_assumption_raw_seal,
        )
        .unwrap();
        let explicit_historical = build_positive_authority_test_support_with_reference_statement(
            &verifier_contract,
            [&validator_artifacts[0], &validator_artifacts[1]],
            [&validator_source_archives[0], &validator_source_archives[1]],
            &case9_assumption_raw_seal,
            HISTORICAL_REFERENCE_CHAIN_DOMAIN_ID,
            HISTORICAL_REFERENCE_APPLICATION_PAYLOAD,
        )
        .unwrap();
        assert_eq!(
            historical.positive_generation_authority,
            explicit_historical.positive_generation_authority
        );
        assert_eq!(
            historical.input_set.path,
            explicit_historical.input_set.path
        );
        assert_eq!(
            historical.input_set.bytes,
            explicit_historical.input_set.bytes
        );
        assert_eq!(
            historical.generation_set.path,
            explicit_historical.generation_set.path
        );
        assert_eq!(
            historical.generation_set.bytes,
            explicit_historical.generation_set.bytes
        );
        assert_eq!(
            historical.case9_proof_output_manifest_jcs,
            explicit_historical.case9_proof_output_manifest_jcs
        );
        for (left, right) in historical
            .case9_primary_artifacts
            .iter()
            .zip(&explicit_historical.case9_primary_artifacts)
        {
            assert_eq!(left.path, right.path);
            assert_eq!(left.bytes, right.bytes);
        }

        let compatible_chain_domain_id = std::array::from_fn(|index| u8::try_from(index).unwrap());
        let compatible_payload = b"E5 descriptor-rooted shared core";
        let compatible = build_positive_authority_test_support_with_reference_statement(
            &verifier_contract,
            [&validator_artifacts[0], &validator_artifacts[1]],
            [&validator_source_archives[0], &validator_source_archives[1]],
            &case9_assumption_raw_seal,
            compatible_chain_domain_id,
            compatible_payload,
        )
        .unwrap();
        let statement = crate::parse_ergo_statement_v1(
            &compatible
                .case9_primary_artifacts
                .iter()
                .find(|artifact| artifact.path.ends_with("/candidate-journal.bin"))
                .unwrap()
                .bytes,
        )
        .unwrap();
        assert_eq!(statement.chain_domain_id(), compatible_chain_domain_id);
        assert_eq!(statement.application_payload(), compatible_payload);
        assert_ne!(
            compatible.positive_generation_authority,
            historical.positive_generation_authority
        );
    }

    #[allow(clippy::too_many_lines)]
    fn build_generation_fixture(
        input_value: &Value,
        input_bytes: &[u8],
        verifier_files: &OwnedVerifierFiles,
        proof_generator_artifact: &[u8],
        recursive_calibrations: &[Vec<u8>; 3],
    ) -> (Value, Vec<u8>, [OwnedGenerationCase; POSITIVE_CASE_COUNT]) {
        let profile_id = decode_digest(
            string_field(field(input_value, "profile").unwrap(), "profileId").unwrap(),
            "fixture profile ID",
        )
        .unwrap();
        let package = validate_profile_package_v1(
            &verifier_files.profile_manifest,
            ProfileArtifacts {
                algorithm: &verifier_files.profile_algorithm,
                binary_data: &verifier_files.profile_constants,
            },
            &profile_id,
        )
        .unwrap();
        let program_id: [u8; DIGEST_BYTES] =
            compute_image_id(&verifier_files.guest_elf).unwrap().into();
        let claim = ok_receipt_claim_digests(&program_id, &verifier_files.statement)
            .unwrap()
            .expected_claim;
        let mut generated_rows = Vec::with_capacity(POSITIVE_CASE_COUNT);
        let mut owned_cases = Vec::with_capacity(POSITIVE_CASE_COUNT);

        for (index, spec) in POSITIVE_CASE_SPECS.iter().copied().enumerate() {
            let index_byte = u8::try_from(index).unwrap();
            let terminal = derive_terminal(
                package.manifest(),
                &input_value["positiveCases"][index]["terminal"],
            )
            .unwrap();
            let control = decode_digest(
                string_field(&terminal, "controlId").unwrap(),
                "fixture control ID",
            )
            .unwrap();
            let raw_seal = if index == 0 {
                verifier_files.raw_seal.clone()
            } else {
                vec![0x10_u8.wrapping_add(index_byte); PROOF_BYTES]
            };
            let layout: &[(&str, &str)] = if index < 8 {
                &LIFT_ARTIFACT_LAYOUT
            } else {
                &RECURSIVE_ARTIFACT_LAYOUT
            };
            let mut artifacts = Vec::with_capacity(layout.len());
            for (role, source_file) in layout {
                let bytes = match *role {
                    "claim-digest" => claim.to_vec(),
                    "control-id" => control.to_vec(),
                    "image-id" => program_id.to_vec(),
                    "journal" => verifier_files.statement.clone(),
                    "metadata" => canonical_json_bytes(&json!({
                        "caseId": spec.case_id,
                        "fixture": index
                    }))
                    .unwrap(),
                    "raw-seal" => raw_seal.clone(),
                    "receipt-oracle" => vec![0xc0, index_byte, 0x01],
                    "ancestry" => canonical_json_bytes(&json!({
                        "caseId": spec.case_id,
                        "family": spec.family,
                        "fixture": index
                    }))
                    .unwrap(),
                    "calibration" => recursive_calibrations[index - 8].clone(),
                    _ => unreachable!(),
                };
                artifacts.push(OwnedGenerationArtifact { source_file, bytes });
            }
            let auxiliary_artifacts = positive_auxiliary_artifact_paths(index)
                .unwrap()
                .iter()
                .copied()
                .enumerate()
                .map(|(position, path)| OwnedGenerationArtifact {
                    source_file: path,
                    bytes: vec![
                        0x80_u8.wrapping_add(u8::try_from(index * 8 + position).unwrap(),);
                        PROOF_BYTES
                    ],
                })
                .collect::<Vec<_>>();

            let mut manifest_entries: ProofOutputManifest = artifacts
                .iter()
                .chain(&auxiliary_artifacts)
                .map(|artifact| ManifestEntry {
                    path: artifact.source_file.to_owned(),
                    length: artifact.bytes.len().to_string(),
                    sha256: sha256_hex(&artifact.bytes),
                })
                .collect();
            manifest_entries.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
            let manifest_value = serde_json::to_value(&manifest_entries).unwrap();
            let manifest_bytes = canonical_json_bytes(&manifest_value).unwrap();
            let generated_artifacts: Vec<Value> = layout
                .iter()
                .zip(&artifacts)
                .map(|((role, source_file), artifact)| {
                    let encoding = if matches!(*role, "metadata" | "ancestry" | "calibration") {
                        "rfc8785-jcs"
                    } else {
                        "raw-bytes"
                    };
                    let mut identity = json!({
                        "role": role,
                        "sourceFile": source_file,
                        "byteLength": artifact.bytes.len(),
                        "sha256": sha256_hex(&artifact.bytes),
                        "encoding": encoding
                    });
                    if matches!(*role, "claim-digest" | "control-id" | "image-id") {
                        identity["contentHex"] = json!(hex::encode(&artifact.bytes));
                    }
                    if *role == "receipt-oracle" {
                        identity["codec"] = json!(if index < 8 {
                            "bincode-1.3.3-little-endian-fixed-int-reject-trailing"
                        } else {
                            "eip0045-recursive-oracle-borsh-v1"
                        });
                    }
                    identity
                })
                .collect();
            let generation = if index < 8 {
                json!({"kind": "lift", "segmentPo2": spec.terminal_parameter})
            } else {
                json!({"kind": "recursive", "family": spec.family})
            };
            generated_rows.push(json!({
                "caseIndex": index,
                "caseId": spec.case_id,
                "generation": generation,
                "proofOutputManifest": {
                    "fileName": if index < 8 {
                        "candidate-proof-output-manifest.json"
                    } else {
                        "candidate-recursive-output-manifest.json"
                    },
                    "byteLength": manifest_bytes.len(),
                    "sha256": sha256_hex(&manifest_bytes),
                    "encoding": "rfc8785-jcs"
                },
                "artifacts": generated_artifacts
            }));
            owned_cases.push(OwnedGenerationCase {
                proof_output_manifest_jcs: manifest_bytes,
                artifacts,
                auxiliary_artifacts,
            });
        }

        let generation_value = json!({
            "format": "Eip0045B4PositiveGenerationSetV1",
            "formatVersion": 1,
            "inputSetCommitment": jcs_commitment(
                "Eip0045B4PositiveInputSetV1",
                input_bytes
            ),
            "proofGeneratorArtifact": {
                "byteLength": proof_generator_artifact.len(),
                "sha256": sha256_hex(proof_generator_artifact),
                "encoding": "raw-bytes"
            },
            "cases": generated_rows
        });
        let generation_bytes = canonical_json_bytes(&generation_value).unwrap();
        (
            generation_value,
            generation_bytes,
            owned_cases.try_into().unwrap_or_else(|_| unreachable!()),
        )
    }

    fn refresh_generation_case_parts(
        generation_value: &mut Value,
        generation_cases: &mut [OwnedGenerationCase; POSITIVE_CASE_COUNT],
        index: usize,
    ) {
        let artifacts = &generation_cases[index].artifacts;
        for (generated, physical) in generation_value["cases"][index]["artifacts"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .zip(artifacts)
        {
            generated["byteLength"] = json!(physical.bytes.len());
            generated["sha256"] = json!(sha256_hex(&physical.bytes));
            if generated.get("contentHex").is_some() {
                generated["contentHex"] = json!(hex::encode(&physical.bytes));
            }
        }
        let mut entries: ProofOutputManifest = artifacts
            .iter()
            .chain(&generation_cases[index].auxiliary_artifacts)
            .map(|artifact| ManifestEntry {
                path: artifact.source_file.to_owned(),
                length: artifact.bytes.len().to_string(),
                sha256: sha256_hex(&artifact.bytes),
            })
            .collect();
        entries.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        let manifest_bytes = canonical_json_bytes(&serde_json::to_value(entries).unwrap()).unwrap();
        generation_cases[index].proof_output_manifest_jcs = manifest_bytes.clone();
        let manifest = &mut generation_value["cases"][index]["proofOutputManifest"];
        manifest["byteLength"] = json!(manifest_bytes.len());
        manifest["sha256"] = json!(sha256_hex(&manifest_bytes));
    }

    fn refresh_generation_case(materialized: &mut MaterializedFixture, index: usize) {
        refresh_generation_case_parts(
            &mut materialized.generation_value,
            &mut materialized.generation_cases,
            index,
        );
        materialized.generation_bytes =
            canonical_json_bytes(&materialized.generation_value).unwrap();
    }

    fn populate_recursive_auxiliary_artifacts(materialized: &mut MaterializedFixture) {
        for index in 8..POSITIVE_CASE_COUNT {
            materialized.generation_cases[index].auxiliary_artifacts =
                positive_auxiliary_artifact_paths(index)
                    .unwrap()
                    .iter()
                    .enumerate()
                    .map(|(position, path)| OwnedGenerationArtifact {
                        source_file: path,
                        bytes: vec![
                            0x80_u8
                                .wrapping_add(u8::try_from(index * 8 + position).unwrap(),);
                            PROOF_BYTES
                        ],
                    })
                    .collect();
            let mut entries: ProofOutputManifest = materialized.generation_cases[index]
                .artifacts
                .iter()
                .chain(&materialized.generation_cases[index].auxiliary_artifacts)
                .map(|artifact| ManifestEntry {
                    path: artifact.source_file.to_owned(),
                    length: artifact.bytes.len().to_string(),
                    sha256: sha256_hex(&artifact.bytes),
                })
                .collect();
            entries.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
            let manifest_bytes =
                canonical_json_bytes(&serde_json::to_value(entries).unwrap()).unwrap();
            materialized.generation_cases[index].proof_output_manifest_jcs = manifest_bytes.clone();
            let manifest =
                &mut materialized.generation_value["cases"][index]["proofOutputManifest"];
            manifest["byteLength"] = json!(manifest_bytes.len());
            manifest["sha256"] = json!(sha256_hex(&manifest_bytes));
        }
        materialized.generation_bytes =
            canonical_json_bytes(&materialized.generation_value).unwrap();
    }

    fn replace_recursive_manifest(
        materialized: &mut MaterializedFixture,
        index: usize,
        manifest: ProofOutputManifest,
    ) {
        let manifest_bytes =
            canonical_json_bytes(&serde_json::to_value(manifest).unwrap()).unwrap();
        materialized.generation_cases[index].proof_output_manifest_jcs = manifest_bytes.clone();
        let manifest_identity =
            &mut materialized.generation_value["cases"][index]["proofOutputManifest"];
        manifest_identity["byteLength"] = json!(manifest_bytes.len());
        manifest_identity["sha256"] = json!(sha256_hex(&manifest_bytes));
        materialized.generation_bytes =
            canonical_json_bytes(&materialized.generation_value).unwrap();
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)]
    fn descriptor(
        implementation: PositiveImplementation,
        source_path: &str,
        source_byte: u8,
        source_archive_byte: u8,
        lineage_byte: u8,
        artifact_path: &str,
        artifact_length: u64,
        artifact_byte: u8,
        entrypoint_kind: &str,
    ) -> Value {
        let (artifact_kind, artifact, execution_kind) = match implementation {
            PositiveImplementation::RustReference => (
                "native-executable",
                json!({
                    "path": artifact_path,
                    "byteLength": artifact_length,
                    "sha256": digest(artifact_byte),
                    "encoding": "raw-bytes",
                    "fileFormat": "elf64",
                    "architecture": "amd64",
                    "linkage": "static-no-interpreter",
                    "inspectionPolicy": "eip0045-b4-elf64-amd64-static-v1",
                    "elf": static_elf_inspection()
                }),
                "isolated-oci-native",
            ),
            PositiveImplementation::IndependentJvm => (
                "executable-jar",
                json!({
                    "path": artifact_path,
                    "byteLength": artifact_length,
                    "sha256": digest(artifact_byte),
                    "encoding": "raw-bytes",
                    "fileFormat": "zip-jar",
                    "inspectionPolicy": "eip0045-b4-jvm-artifact-v1",
                    "packaging": {
                        "policy": "eip0045-b4-jvm-copy-only-packaging-v1",
                        "mode": "copy-only-inclusion-manifest",
                        "applicationSelection": "all-regular-entries",
                        "dependencySelection": "reviewed-exact-copy-list",
                        "replayPolicy": "exact-input-output-entry-replay-required",
                        "dependencyArtifactCount": 1,
                        "packer": {
                            "role": "packager",
                            "name": "jar-packer",
                            "version": "1",
                            "imagePath": "/tool/independent-jvm-packager",
                            "byteLength": 41,
                            "sha256": digest(source_byte.wrapping_add(7))
                        },
                        "configuration": {
                            "path": source_path,
                            "role": "implementation-source",
                            "byteLength": 10,
                            "sha256": digest(source_byte)
                        },
                        "applicationInput": {
                            "path": "intermediate/jvm-application.jar",
                            "byteLength": 150,
                            "sha256": digest(0xd8),
                            "encoding": "raw-bytes",
                            "fileFormat": "zip-jar",
                            "regularEntryCount": 2
                        },
                        "inclusionManifest": {
                            "format": "Eip0045B4JvmCopyOnlyInclusionManifestV1",
                            "path": "packaging/jvm-copy-only-inclusion.json",
                            "byteLength": 2,
                            "sha256": digest(0xd9),
                            "encoding": "rfc8785-jcs"
                        }
                    },
                    "archive": jvm_archive_inspection(),
                    "manifest": jvm_manifest_inspection(),
                    "classFiles": {
                        "policy": "jvms-se21-complete-class-file-v1",
                        "runtimeFeatureVersion": 21,
                        "maximumSupportedMajorVersion": 65,
                        "classEntryCount": 1,
                        "minimumObservedMajorVersion": 65,
                        "maximumObservedMajorVersion": 65,
                        "nonZeroMinorVersionCount": 0,
                        "structuralParseFailureCount": 0,
                        "trailingByteCount": 0,
                        "accNativeMethodCount": 0,
                        "nativeLoadMethodReferenceCount": 0,
                        "foreignApiTypeReferenceCount": 0,
                        "jnaTypeReferenceCount": 0,
                        "jnrTypeReferenceCount": 0,
                        "processLaunchMethodReferenceCount": 0,
                        "forbiddenMethodHandleTargetCount": 0
                    },
                    "nonClassFiles": {
                        "policy": "eip0045-b4-jvm-nonclass-scan-v1",
                        "regularEntryCount": 2,
                        "scannedEntryCount": 2,
                        "forbiddenNameMatchCount": 0,
                        "nativeExecutableMagicMatchCount": 0,
                        "nestedArchiveMagicMatchCount": 0,
                        "scriptMagicMatchCount": 0,
                        "misnamedClassMagicMatchCount": 0
                    },
                    "analysisBoundary": {
                        "staticResultScope": "complete-archive-structure-direct-symbolic-reference-and-byte-signature-scan",
                        "reflection": "not-established-source-review-required",
                        "generatedBytecode": "not-established-source-review-required",
                        "encodedOrAssembledSymbols": "not-established-source-review-required",
                        "resourceDrivenDelegation": "not-established-source-review-required",
                        "runtimeNativeCode": "outside-jar-scan-bound-by-runner-profile"
                    }
                }),
                "isolated-oci-jvm",
            ),
        };
        let toolchain_entries = match implementation {
            PositiveImplementation::RustReference => json!([{
                "role": "build-driver",
                "name": "tool",
                "version": "1",
                "imagePath": "/tool/rust-reference",
                "byteLength": 40,
                "sha256": digest(source_byte.wrapping_add(4))
            }]),
            PositiveImplementation::IndependentJvm => json!([
                {
                    "role": "packager",
                    "name": "jar-packer",
                    "version": "1",
                    "imagePath": "/tool/independent-jvm-packager",
                    "byteLength": 41,
                    "sha256": digest(source_byte.wrapping_add(7))
                },
                {
                    "role": "runtime",
                    "name": "java",
                    "version": "21.0.1",
                    "imagePath": "/runtime/bin/java",
                    "byteLength": 64,
                    "sha256": digest(0x61)
                },
                {
                    "role": "compiler",
                    "name": "javac",
                    "version": "21.0.1",
                    "imagePath": "/runtime/bin/javac",
                    "byteLength": 64,
                    "sha256": digest(0x63)
                },
                {
                    "role": "build-driver",
                    "name": "tool",
                    "version": "1",
                    "imagePath": "/tool/independent-jvm",
                    "byteLength": 40,
                    "sha256": digest(source_byte.wrapping_add(4))
                }
            ]),
        };
        let deterministic_build = match implementation {
            PositiveImplementation::RustReference => json!({
                "runnerProfile": {},
                "environment": {"inheritance": "none", "variables": []},
                "steps": [{
                    "executable": "/tool/rust-reference",
                    "arguments": [],
                    "workingDirectory": "/src",
                    "shell": "none"
                }],
                "outputPath": artifact_path,
                "repetitions": 2,
                "comparison": "byte-for-byte",
                "networkAccess": "disabled",
                "cachePolicy": "none"
            }),
            PositiveImplementation::IndependentJvm => json!({
                "runnerProfile": {},
                "environment": {"inheritance": "none", "variables": []},
                "phases": [
                    {
                        "phase": "application-intermediate",
                        "step": {
                            "executable": "/tool/independent-jvm",
                            "arguments": [],
                            "workingDirectory": "/src",
                            "shell": "none"
                        },
                        "output": {
                            "role": "application-intermediate",
                            "containerPath": "/out/application.jar"
                        }
                    },
                    {
                        "phase": "copy-only-packaging",
                        "inputLayout": {
                            "policy": "eip0045-b4-jvm-copy-only-phase-input-v1",
                            "manifestPath": "/phase-input/inclusion-manifest.json",
                            "archiveRoot": "/phase-input/archives"
                        },
                        "step": {
                            "executable": "/tool/independent-jvm-packager",
                            "arguments": JVM_COPY_ONLY_PACKAGER_ARGUMENTS,
                            "workingDirectory": "/phase-input",
                            "shell": "none"
                        },
                        "output": {
                            "role": "validator-artifact",
                            "containerPath": "/out/validator.jar"
                        }
                    }
                ],
                "executionOrder": "complete-and-compare-each-phase-before-next",
                "repetitionsPerPhase": 2,
                "instancePolicy": "fresh-oci-instance-and-output-root-per-phase-repetition",
                "comparison": "byte-for-byte-and-bound-identity-per-phase",
                "networkAccess": "disabled",
                "cachePolicy": "none"
            }),
        };
        let mut descriptor = json!({
            "format": "Eip0045B4ValidatorBuildDescriptorV1",
            "formatVersion": 1,
            "implementation": implementation.implementation(),
            "implementationLanguage": implementation.language(),
            "implementationLineage": {
                "method": "canonical-source-inventory-v1",
                "sharedVerifierImplementation": "none",
                "sourceFiles": [{
                    "path": source_path,
                    "role": "implementation-source",
                    "byteLength": 10,
                    "sha256": digest(source_byte)
                }],
                "lineageSha256": digest(lineage_byte)
            },
            "reviewedSource": {
                "repository": format!("https://github.com/example/{}.git", implementation.implementation()),
                "commit": format!("{source_byte:02x}").repeat(20),
                "tree": format!("{:02x}", source_byte.wrapping_add(1)).repeat(20),
                "archive": {
                    "path": format!("source/{}.bundle", implementation.implementation()),
                    "byteLength": 1000,
                    "sha256": digest(source_archive_byte),
                    "encoding": "git-bundle"
                }
            },
            "dependencyClosure": {
                "method": "content-addressed-offline-v1",
                "lockfile": {
                    "path": format!("deps/{}/lock", implementation.implementation()),
                    "byteLength": 20,
                    "sha256": digest(source_byte.wrapping_add(2)),
                    "encoding": "raw-bytes"
                },
                "entries": [{
                    "ecosystem": "local",
                    "name": "fixture",
                    "version": "1",
                    "origin": "fixture",
                    "artifact": {
                        "path": format!("deps/{}/fixture", implementation.implementation()),
                        "byteLength": 30,
                        "sha256": digest(source_byte.wrapping_add(3)),
                        "encoding": "raw-bytes"
                    }
                }],
                "closureSha256": digest(source_byte.wrapping_add(5))
            },
            "toolchainClosure": {
                "method": "container-toolchain-inventory-v1",
                "entries": toolchain_entries,
                "closureSha256": digest(source_byte.wrapping_add(6))
            },
            "deterministicBuild": deterministic_build,
            "artifactKind": artifact_kind,
            "artifact": artifact,
            "entrypoint": {
                "kind": entrypoint_kind,
                "interface": "eip0045-b4-verifier-cli-v2",
                "subcommand": "verify-positive",
                "wrapper": "none"
            },
            "executionEnvironment": {
                "kind": execution_kind,
                "runnerProfile": {}
            }
        });
        bind_inventory_digests(&mut descriptor);
        descriptor
    }

    fn jvm_copy_only_inclusion_manifest(descriptor: &Value) -> Value {
        let artifact = &descriptor["artifact"];
        let packaging = &artifact["packaging"];
        let dependency = &descriptor["dependencyClosure"]["entries"][0]["artifact"];
        json!({
            "format": "Eip0045B4JvmCopyOnlyInclusionManifestV1",
            "formatVersion": 1,
            "policy": "eip0045-b4-jvm-copy-only-packaging-v1",
            "applicationSelection": "all-regular-entries",
            "dependencySelection": "reviewed-exact-copy-list",
            "inputArchivePolicy": "eip0045-b4-jar-source-read-v1",
            "archivePolicy": "eip0045-b4-canonical-jar-zip-v1",
            "inputs": [
                {
                    "id": "application",
                    "role": "application-intermediate",
                    "path": packaging["applicationInput"]["path"],
                    "byteLength": packaging["applicationInput"]["byteLength"],
                    "sha256": packaging["applicationInput"]["sha256"],
                    "encoding": packaging["applicationInput"]["encoding"],
                    "fileFormat": packaging["applicationInput"]["fileFormat"],
                    "regularEntryCount": packaging["applicationInput"]["regularEntryCount"]
                },
                {
                    "id": "dependency-000",
                    "role": "dependency-artifact",
                    "path": dependency["path"],
                    "byteLength": dependency["byteLength"],
                    "sha256": dependency["sha256"],
                    "encoding": dependency["encoding"],
                    "fileFormat": "zip-jar",
                    "regularEntryCount": 1
                }
            ],
            "entries": [
                {
                    "kind": "regular-file",
                    "name": "META-INF/MANIFEST.MF",
                    "sourceInputId": "application",
                    "sourceEntryName": "META-INF/MANIFEST.MF",
                    "byteLength": 80,
                    "sha256": digest(0xe1)
                },
                {
                    "kind": "regular-file",
                    "name": "org/example/Main.class",
                    "sourceInputId": "application",
                    "sourceEntryName": "org/example/Main.class",
                    "byteLength": 100,
                    "sha256": digest(0xe2)
                },
                {
                    "kind": "regular-file",
                    "name": "reference.conf",
                    "sourceInputId": "dependency-000",
                    "sourceEntryName": "reference.conf",
                    "byteLength": 20,
                    "sha256": digest(0xe3)
                }
            ],
            "generatedEntries": [],
            "output": {
                "path": artifact["path"],
                "byteLength": artifact["byteLength"],
                "sha256": artifact["sha256"],
                "encoding": artifact["encoding"],
                "fileFormat": artifact["fileFormat"]
            }
        })
    }

    fn refresh_jvm_copy_only_inclusion_manifest_binding(fixture: &mut Fixture) {
        let bytes = canonical_json_bytes(&fixture.jvm_copy_only_inclusion_manifest_value).unwrap();
        fixture.descriptor_values[1]["artifact"]["packaging"]["inclusionManifest"] =
            document_identity(
                "Eip0045B4JvmCopyOnlyInclusionManifestV1",
                JVM_COPY_ONLY_INCLUSION_MANIFEST_PATH,
                &bytes,
            );
    }

    fn bind_inventory_digests(descriptor: &mut Value) {
        let lineage = &descriptor["implementationLineage"];
        descriptor["implementationLineage"]["lineageSha256"] = json!(
            domain_separated_jcs_sha256(
                LINEAGE_DIGEST_DOMAIN,
                &lineage_digest_preimage(lineage).unwrap()
            )
            .unwrap()
        );
        let dependencies = &descriptor["dependencyClosure"];
        descriptor["dependencyClosure"]["closureSha256"] = json!(
            domain_separated_jcs_sha256(
                DEPENDENCY_DIGEST_DOMAIN,
                &dependency_digest_preimage(dependencies).unwrap(),
            )
            .unwrap()
        );
        let toolchains = &descriptor["toolchainClosure"];
        descriptor["toolchainClosure"]["closureSha256"] = json!(
            domain_separated_jcs_sha256(
                TOOLCHAIN_DIGEST_DOMAIN,
                &toolchain_digest_preimage(toolchains).unwrap(),
            )
            .unwrap()
        );
    }

    fn profile_reference(role: PositiveRunnerRole, commitment: &Value) -> Value {
        json!({
            "runnerProfileIndex": role.index(),
            "purpose": role.purpose(),
            "commitment": commitment
        })
    }

    fn document_identity(format: &str, path: &str, bytes: &[u8]) -> Value {
        json!({
            "format": format,
            "path": path,
            "byteLength": bytes.len(),
            "sha256": sha256_hex(bytes),
            "encoding": "rfc8785-jcs"
        })
    }

    fn file_identity(path: &str, byte_length: u64, byte: u8) -> Value {
        json!({
            "path": path,
            "byteLength": byte_length,
            "sha256": digest(byte),
            "encoding": "raw-bytes"
        })
    }

    fn jcs_file_identity(path: &str, byte_length: u64, byte: u8) -> Value {
        let mut identity = file_identity(path, byte_length, byte);
        identity["encoding"] = json!("rfc8785-jcs");
        identity
    }

    fn file_identity_from_bytes(path: &str, bytes: &[u8]) -> Value {
        json!({
            "path": path,
            "byteLength": bytes.len(),
            "sha256": sha256_hex(bytes),
            "encoding": "raw-bytes"
        })
    }

    fn jcs_file_identity_from_bytes(path: &str, bytes: &[u8]) -> Value {
        let mut identity = file_identity_from_bytes(path, bytes);
        identity["encoding"] = json!("rfc8785-jcs");
        identity
    }

    fn fixture_verifier_contract() -> Value {
        let schema_identities = B4_VERIFIER_SCHEMA_ROLES
            .iter()
            .enumerate()
            .map(|(index, role)| {
                json!({
                    "role": role,
                    "artifact": file_identity(
                        &format!("schemas/{role}.schema.json"),
                        64,
                        0x70_u8.wrapping_add(u8::try_from(index).unwrap())
                    )
                })
            })
            .collect::<Vec<_>>();
        json!({
            "format": "Eip0045B4VerifierContractV1",
            "formatVersion": 1,
            "interface": "eip0045-b4-verifier-cli-v2",
            "positiveSubcommand": "verify-positive",
            "negativeSubcommand": "verify-negative",
            "cliSpec": file_identity("specs/b4-verifier-cli-v2.md", 128, 0x60),
            "negativePlan": jcs_file_identity("preproof/negative-plan.json", 1024, 0x61),
            "expectationSet": jcs_file_identity(
                "preproof/negative-expectation-set.json",
                2048,
                0x62
            ),
            "schemaIdentities": schema_identities
        })
    }

    fn digest(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn v2_runner_profile(role: PositiveRunnerRole) -> Value {
        let mut profile = Fixture::valid().runner_values[role.index()].clone();
        promote_runner_profile_v2(&mut profile, role);
        profile
    }

    fn promote_runner_profile_v2(profile: &mut Value, role: PositiveRunnerRole) {
        profile["format"] = json!("Eip0045B4PositiveOciRunnerProfileV2");
        profile["formatVersion"] = json!(2);
        profile["image"]["retainedHostRootfsMetadataPolicy"] =
            json!("eip0045-b4-retained-host-rootfs-metadata-obligations-v2");
        profile["retainedHostRootfsMetadataProvider"] = json!({
            "metadataPolicy": "eip0045-b4-retained-host-rootfs-metadata-obligations-v2",
            "providerProfile": "eip0045-b4-tmpfs-metadata-provider-v1",
            "sessionProtocol": "eip0045-b4-supervised-filesystem-session-v1",
            "applianceProfile": "eip0045-b4-buildroot-appliance-v1",
            "expectedModeTableSha256": digest(0xa5),
            "canonicalRole": v2_canonical_role(role)
        });
    }

    #[derive(Clone)]
    struct V2InputIdentityFixture {
        authoritative_build: AuthoritativeB4BuildProjection,
        input_value: Value,
        input_bytes: Vec<u8>,
        runner_values: [Value; 4],
        runner_bytes: [Vec<u8>; 4],
        descriptor_values: [Value; 2],
        descriptor_bytes: [Vec<u8>; 2],
    }

    impl V2InputIdentityFixture {
        fn valid() -> Self {
            let base = Fixture::valid().materialize();
            Self::from_materialized(&base)
        }

        fn from_materialized(base: &MaterializedFixture) -> Self {
            let mut runner_values = base.runner_values.clone();
            for (index, role) in PositiveRunnerRole::all().into_iter().enumerate() {
                promote_runner_profile_v2(&mut runner_values[index], role);
            }
            let mut descriptor_values = base.descriptor_values.clone();
            for descriptor in &mut descriptor_values {
                descriptor["format"] = json!("Eip0045B4ValidatorBuildDescriptorV2");
                descriptor["formatVersion"] = json!(2);
            }
            let mut fixture = Self {
                authoritative_build: base.authoritative_build.clone(),
                input_value: base.input_value.clone(),
                input_bytes: Vec::new(),
                runner_values,
                runner_bytes: std::array::from_fn(|_| Vec::new()),
                descriptor_values,
                descriptor_bytes: std::array::from_fn(|_| Vec::new()),
            };
            fixture.input_value["format"] = json!("Eip0045B4PositiveInputSetV2");
            fixture.input_value["formatVersion"] = json!(2);
            fixture.refresh_all_commitments();
            fixture
        }

        fn refresh_all_commitments(&mut self) {
            self.runner_bytes = self
                .runner_values
                .clone()
                .map(|value| canonical_json_bytes(&value).unwrap());
            let runner_identities: [Value; 4] = std::array::from_fn(|index| {
                document_identity(
                    "Eip0045B4PositiveOciRunnerProfileV2",
                    RUNNER_PATHS[index],
                    &self.runner_bytes[index],
                )
            });
            for (index, implementation) in [
                PositiveImplementation::RustReference,
                PositiveImplementation::IndependentJvm,
            ]
            .into_iter()
            .enumerate()
            {
                let build = implementation.build_role();
                self.descriptor_values[index]["deterministicBuild"]["runnerProfile"] =
                    profile_reference(build, &runner_identities[build.index()]);
                let execution = implementation.execution_role();
                self.descriptor_values[index]["executionEnvironment"]["runnerProfile"] =
                    profile_reference(execution, &runner_identities[execution.index()]);
            }
            for (index, runner_identity) in runner_identities.iter().enumerate() {
                let role = PositiveRunnerRole::all()[index];
                self.input_value["runnerProfiles"][index] = json!({
                    "runnerProfileIndex": index,
                    "purpose": role.purpose(),
                    "artifact": runner_identity
                });
            }
            self.refresh_descriptor_sources_and_input_bindings();
        }

        fn refresh_descriptor_sources_and_input_bindings(&mut self) {
            self.descriptor_bytes = self
                .descriptor_values
                .clone()
                .map(|value| canonical_json_bytes(&value).unwrap());
            for (index, implementation) in [
                PositiveImplementation::RustReference,
                PositiveImplementation::IndependentJvm,
            ]
            .into_iter()
            .enumerate()
            {
                self.input_value["validators"][index] = json!({
                    "implementationIndex": index,
                    "implementation": implementation.implementation(),
                    "language": implementation.language(),
                    "buildDescriptor": document_identity(
                        "Eip0045B4ValidatorBuildDescriptorV2",
                        DESCRIPTOR_PATHS[index],
                        &self.descriptor_bytes[index]
                    )
                });
            }
            self.refresh_input_source();
        }

        fn refresh_input_source(&mut self) {
            self.input_bytes = canonical_json_bytes(&self.input_value).unwrap();
        }

        fn validate(&self) -> Result<()> {
            validate_v2_input_identity_closure(
                &self.authoritative_build,
                NamedCanonicalJcs {
                    relative_path: INPUT_SET_PATH,
                    bytes: &self.input_bytes,
                },
                std::array::from_fn(|index| NamedCanonicalJcs {
                    relative_path: RUNNER_PATHS[index],
                    bytes: &self.runner_bytes[index],
                }),
                std::array::from_fn(|index| NamedCanonicalJcs {
                    relative_path: DESCRIPTOR_PATHS[index],
                    bytes: &self.descriptor_bytes[index],
                }),
            )
        }

        fn bind_positive_precommit(
            &self,
            retained_v1_documents: &MaterializedFixture,
        ) -> Result<B4PositivePrecommitAuthorityV2> {
            validate_and_bind_positive_precommit_v2(
                &self.authoritative_build,
                B4PositivePrecommitDocumentsV2 {
                    input_set: NamedCanonicalJcs {
                        relative_path: INPUT_SET_PATH,
                        bytes: &self.input_bytes,
                    },
                    verifier_contract: NamedCanonicalJcs {
                        relative_path: VERIFIER_CONTRACT_PATH,
                        bytes: &retained_v1_documents.verifier_contract_bytes,
                    },
                    runner_profiles: std::array::from_fn(|index| NamedCanonicalJcs {
                        relative_path: RUNNER_PATHS[index],
                        bytes: &self.runner_bytes[index],
                    }),
                    seccomp_documents: std::array::from_fn(|index| NamedCanonicalJcs {
                        relative_path: SECCOMP_PATHS[index],
                        bytes: &retained_v1_documents.seccomp_bytes[index],
                    }),
                    validator_descriptors: std::array::from_fn(|index| NamedCanonicalJcs {
                        relative_path: DESCRIPTOR_PATHS[index],
                        bytes: &self.descriptor_bytes[index],
                    }),
                    jvm_copy_only_inclusion_manifest: NamedCanonicalJcs {
                        relative_path: JVM_COPY_ONLY_INCLUSION_MANIFEST_PATH,
                        bytes: &retained_v1_documents.jvm_copy_only_inclusion_manifest_bytes,
                    },
                },
            )
        }
    }

    /// Owned V2 identity document exported only to sibling constructor tests.
    #[derive(Clone, Debug)]
    pub(crate) struct OwnedV2SemanticIdentityDocument {
        pub(crate) path: String,
        pub(crate) bytes: Vec<u8>,
    }

    /// Exact runner-profile and validator-descriptor documents accepted by the
    /// Task-2 V2 semantic gate.
    #[derive(Clone, Debug)]
    pub(crate) struct V2SemanticIdentityDocumentsTestSupport {
        pub(crate) input_template: Value,
        pub(crate) runner_profiles: [OwnedV2SemanticIdentityDocument; 4],
        pub(crate) validator_descriptors: [OwnedV2SemanticIdentityDocument; 2],
    }

    /// Owned exact inputs accompanying one affine authority minted by the real
    /// V2 positive-precommit gate for a sibling campaign-constructor test.
    pub(crate) struct PositivePrecommitV2TestSupport {
        pub(crate) input_set: OwnedV2SemanticIdentityDocument,
        pub(crate) verifier_contract: OwnedV2SemanticIdentityDocument,
        pub(crate) runner_profiles: [OwnedV2SemanticIdentityDocument; 4],
        pub(crate) seccomp_documents: [OwnedV2SemanticIdentityDocument; 4],
        pub(crate) validator_descriptors: [OwnedV2SemanticIdentityDocument; 2],
        pub(crate) validator_artifacts: [OwnedV2SemanticIdentityDocument; 2],
        pub(crate) validator_source_archives: [OwnedV2SemanticIdentityDocument; 2],
        pub(crate) jvm_copy_only_inclusion_manifest: OwnedV2SemanticIdentityDocument,
    }

    /// Produce the six mutually bound V2 identity documents through the same
    /// fixture path used by the isolated Task-2 semantic regressions.
    pub(crate) fn v2_semantic_identity_documents_test_support()
    -> V2SemanticIdentityDocumentsTestSupport {
        let fixture = V2InputIdentityFixture::valid();
        V2SemanticIdentityDocumentsTestSupport {
            input_template: fixture.input_value.clone(),
            runner_profiles: std::array::from_fn(|index| OwnedV2SemanticIdentityDocument {
                path: RUNNER_PATHS[index].to_owned(),
                bytes: fixture.runner_bytes[index].clone(),
            }),
            validator_descriptors: std::array::from_fn(|index| OwnedV2SemanticIdentityDocument {
                path: DESCRIPTOR_PATHS[index].to_owned(),
                bytes: fixture.descriptor_bytes[index].clone(),
            }),
        }
    }

    /// Mint one V2 positive-precommit authority through the production gate
    /// while retaining the exact independently remeasured campaign inputs.
    pub(crate) fn build_positive_precommit_v2_test_support(
        verifier_contract_jcs: &[u8],
        validator_artifacts: [&[u8]; 2],
        validator_source_archives: [&[u8]; 2],
    ) -> Result<(
        B4PositivePrecommitAuthorityV2,
        PositivePrecommitV2TestSupport,
    )> {
        let verifier_contract_value = validate_canonical_json_source(verifier_contract_jcs)?;
        let mut fixture = Fixture::valid();
        fixture.verifier_contract_value = verifier_contract_value;
        fixture.input_value["verifierCliContract"] = document_identity(
            "Eip0045B4VerifierContractV1",
            VERIFIER_CONTRACT_PATH,
            verifier_contract_jcs,
        );
        for index in 0..2 {
            fixture.descriptor_values[index]["artifact"]["byteLength"] =
                json!(validator_artifacts[index].len());
            fixture.descriptor_values[index]["artifact"]["sha256"] =
                json!(sha256_hex(validator_artifacts[index]));
            fixture.descriptor_values[index]["reviewedSource"]["archive"]["byteLength"] =
                json!(validator_source_archives[index].len());
            fixture.descriptor_values[index]["reviewedSource"]["archive"]["sha256"] =
                json!(sha256_hex(validator_source_archives[index]));
        }
        fixture.jvm_copy_only_inclusion_manifest_value =
            jvm_copy_only_inclusion_manifest(&fixture.descriptor_values[1]);
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut fixture);

        let retained_v1 = fixture.materialize();
        let v2 = V2InputIdentityFixture::from_materialized(&retained_v1);
        let authority = v2.bind_positive_precommit(&retained_v1)?;
        let owned = |path: &str, bytes: &[u8]| OwnedV2SemanticIdentityDocument {
            path: path.to_owned(),
            bytes: bytes.to_vec(),
        };
        let descriptor_artifact_path = |index: usize| {
            v2.descriptor_values[index]["artifact"]["path"]
                .as_str()
                .expect("validated V2 descriptor artifact path")
        };
        let descriptor_source_path = |index: usize| {
            v2.descriptor_values[index]["reviewedSource"]["archive"]["path"]
                .as_str()
                .expect("validated V2 descriptor source path")
        };
        let support = PositivePrecommitV2TestSupport {
            input_set: owned(INPUT_SET_PATH, &v2.input_bytes),
            verifier_contract: owned(VERIFIER_CONTRACT_PATH, &retained_v1.verifier_contract_bytes),
            runner_profiles: std::array::from_fn(|index| {
                owned(RUNNER_PATHS[index], &v2.runner_bytes[index])
            }),
            seccomp_documents: std::array::from_fn(|index| {
                owned(SECCOMP_PATHS[index], &retained_v1.seccomp_bytes[index])
            }),
            validator_descriptors: std::array::from_fn(|index| {
                owned(DESCRIPTOR_PATHS[index], &v2.descriptor_bytes[index])
            }),
            validator_artifacts: std::array::from_fn(|index| {
                owned(descriptor_artifact_path(index), validator_artifacts[index])
            }),
            validator_source_archives: std::array::from_fn(|index| {
                owned(
                    descriptor_source_path(index),
                    validator_source_archives[index],
                )
            }),
            jvm_copy_only_inclusion_manifest: owned(
                JVM_COPY_ONLY_INCLUSION_MANIFEST_PATH,
                &retained_v1.jvm_copy_only_inclusion_manifest_bytes,
            ),
        };
        Ok((authority, support))
    }

    fn drift_document_identity_field(identity: &mut Value, field_name: &str) {
        match field_name {
            "format" => identity[field_name] = json!("Eip0045DriftedFormatV2"),
            "path" => identity[field_name] = json!("drift/identity.json"),
            "byteLength" => {
                identity[field_name] = json!(identity[field_name].as_u64().unwrap() + 1)
            }
            "sha256" => identity[field_name] = json!(digest(0xfe)),
            "encoding" => identity[field_name] = json!("raw-bytes"),
            _ => panic!("unsupported identity field {field_name}"),
        }
    }

    fn set_json_pointer(value: &mut Value, path: &[&str], replacement: Value) {
        let (last, parents) = path.split_last().unwrap();
        let mut current = value;
        for component in parents {
            current = match current {
                Value::Object(object) => object.get_mut(*component).unwrap(),
                Value::Array(array) => &mut array[component.parse::<usize>().unwrap()],
                _ => panic!("JSON path enters a scalar at {component}"),
            };
        }
        match current {
            Value::Object(object) => {
                object.insert((*last).to_owned(), replacement);
            }
            Value::Array(array) => array[last.parse::<usize>().unwrap()] = replacement,
            _ => panic!("JSON path terminates at a scalar"),
        }
    }

    fn assert_v2_identity_rejects(fixture: &V2InputIdentityFixture, context: &str) {
        let error = fixture.validate().unwrap_err();
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains(context),
            "expected rejecting context {context:?}, got {rendered}"
        );
    }

    #[derive(Clone)]
    struct V2AcceptanceFixture {
        case_index: u8,
        implementation: PositiveImplementation,
        verifier_files: OwnedVerifierFiles,
        verifier_input_value: Value,
        verifier_input_bytes: Vec<u8>,
        observation_value: Value,
        observation_bytes: Vec<u8>,
        acceptance_value: Value,
        acceptance_bytes: Vec<u8>,
        launched_artifact: FileMeasurement,
        java_binary: Option<FileMeasurement>,
        java_release: Option<FileMeasurement>,
    }

    impl V2AcceptanceFixture {
        fn refresh_acceptance_source(&mut self) {
            self.acceptance_bytes = canonical_json_bytes(&self.acceptance_value).unwrap();
        }
    }

    fn measurement_from_identity(identity: &Value) -> FileMeasurement {
        FileMeasurement {
            byte_length: u64_field(identity, "byteLength").unwrap(),
            sha256: decode_digest(
                string_field(identity, "sha256").unwrap(),
                "test identity SHA-256",
            )
            .unwrap(),
        }
    }

    fn v2_acceptance_fixture(
        input: &V2InputIdentityFixture,
        generation_bytes: &[u8],
        generation_cases: &[OwnedGenerationCase; POSITIVE_CASE_COUNT],
        base_verifier_files: &OwnedVerifierFiles,
        case_index: usize,
        implementation: PositiveImplementation,
    ) -> V2AcceptanceFixture {
        let mut verifier_files = base_verifier_files.clone();
        verifier_files.raw_seal = generation_cases[case_index]
            .artifacts
            .iter()
            .find(|artifact| artifact.source_file == "candidate-raw-seal.bin")
            .unwrap()
            .bytes
            .clone();
        let verifier_input_value = verifier_input_for_files(&verifier_files);
        let verifier_input_bytes = canonical_json_bytes(&verifier_input_value).unwrap();
        let observation_bytes = derive_expected_observation(
            &verifier_input_value,
            &verifier_files.contents(),
            &input.input_value,
            &input.input_value["positiveCases"][case_index],
        )
        .unwrap();
        let observation_value = validate_canonical_json_source(&observation_bytes).unwrap();
        let implementation_index = implementation.index();
        let descriptor = &input.descriptor_values[implementation_index];
        let execution_role = implementation.execution_role();
        let mut implementation_binding = json!({
            "implementationIndex": implementation_index,
            "implementation": implementation.implementation(),
            "language": implementation.language(),
            "lineageSha256": descriptor["implementationLineage"]["lineageSha256"],
            "reviewedSource": reviewed_source_projection(&descriptor["reviewedSource"])
                .unwrap(),
            "buildDescriptor": jcs_commitment(
                "Eip0045B4ValidatorBuildDescriptorV2",
                &input.descriptor_bytes[implementation_index],
            ),
            "launchedArtifact": binary_commitment(&descriptor["artifact"]).unwrap(),
            "executionRunnerProfile": {
                "runnerProfileIndex": execution_role.index(),
                "purpose": execution_role.purpose(),
                "artifact": jcs_commitment(
                    "Eip0045B4PositiveOciRunnerProfileV2",
                    &input.runner_bytes[execution_role.index()],
                ),
            },
        });
        if implementation == PositiveImplementation::IndependentJvm {
            implementation_binding["javaRuntime"] = java_runtime_projection(
                &input.runner_values[execution_role.index()]["javaRuntime"],
            )
            .unwrap();
        }
        let acceptance_value = json!({
            "format": "Eip0045B4PositiveAcceptanceV2",
            "formatVersion": 2,
            "caseId": input.input_value["positiveCases"][case_index]["caseId"],
            "caseIndex": case_index,
            "inputSetCommitment": jcs_commitment(
                "Eip0045B4PositiveInputSetV2",
                &input.input_bytes,
            ),
            "generationSetCommitment": jcs_commitment(
                "Eip0045B4PositiveGenerationSetV2",
                generation_bytes,
            ),
            "verifierInputCommitment": jcs_commitment(
                "Eip0045B4PositiveVerifierInputV1",
                &verifier_input_bytes,
            ),
            "observationCommitment": jcs_commitment(
                "Eip0045B4PositiveObservationV1",
                &observation_bytes,
            ),
            "implementationBinding": implementation_binding,
            "observation": observation_value,
        });
        let acceptance_bytes = canonical_json_bytes(&acceptance_value).unwrap();
        let launched_artifact = measurement_from_identity(&descriptor["artifact"]);
        let (java_binary, java_release) = match implementation {
            PositiveImplementation::RustReference => (None, None),
            PositiveImplementation::IndependentJvm => {
                let java = &input.runner_values[execution_role.index()]["javaRuntime"];
                (
                    Some(measurement_from_identity(&java["binary"])),
                    Some(measurement_from_identity(&java["release"])),
                )
            }
        };
        V2AcceptanceFixture {
            case_index: u8::try_from(case_index).unwrap(),
            implementation,
            verifier_files,
            verifier_input_value,
            verifier_input_bytes,
            observation_value,
            observation_bytes,
            acceptance_value,
            acceptance_bytes,
            launched_artifact,
            java_binary,
            java_release,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_v2_fixture(
        input: &V2InputIdentityFixture,
        generation_path: &str,
        generation_bytes: &[u8],
        generation_cases: &[OwnedGenerationCase; POSITIVE_CASE_COUNT],
        proof_generator_artifact: &[u8],
        run: &V2AcceptanceFixture,
    ) -> Result<()> {
        let artifact_views: [Vec<GeneratedArtifactContents<'_>>; POSITIVE_CASE_COUNT] =
            std::array::from_fn(|index| {
                generation_cases[index]
                    .artifacts
                    .iter()
                    .map(|artifact| GeneratedArtifactContents {
                        source_file: artifact.source_file,
                        bytes: &artifact.bytes,
                    })
                    .collect()
            });
        let auxiliary_views: [Vec<GeneratedAuxiliaryArtifactContents<'_>>; POSITIVE_CASE_COUNT] =
            std::array::from_fn(|index| {
                generation_cases[index]
                    .auxiliary_artifacts
                    .iter()
                    .map(|artifact| GeneratedAuxiliaryArtifactContents {
                        relative_path: artifact.source_file,
                        bytes: &artifact.bytes,
                    })
                    .collect()
            });
        let cases = std::array::from_fn(|index| PositiveGenerationCaseDocuments {
            proof_output_manifest_jcs: &generation_cases[index].proof_output_manifest_jcs,
            artifacts: &artifact_views[index],
            auxiliary_artifacts: &auxiliary_views[index],
        });
        validate_v2_generation_and_acceptance_identity_closure(
            &input.authoritative_build,
            NamedCanonicalJcs {
                relative_path: INPUT_SET_PATH,
                bytes: &input.input_bytes,
            },
            std::array::from_fn(|index| NamedCanonicalJcs {
                relative_path: RUNNER_PATHS[index],
                bytes: &input.runner_bytes[index],
            }),
            std::array::from_fn(|index| NamedCanonicalJcs {
                relative_path: DESCRIPTOR_PATHS[index],
                bytes: &input.descriptor_bytes[index],
            }),
            &PositiveGenerationDocuments {
                generation_set: NamedCanonicalJcs {
                    relative_path: generation_path,
                    bytes: generation_bytes,
                },
                proof_generator_artifact,
                cases,
            },
            &PositiveRunDocuments {
                trusted_case_index: run.case_index,
                trusted_implementation: run.implementation,
                verifier_input_jcs: &run.verifier_input_bytes,
                observation_jcs: &run.observation_bytes,
                acceptance_jcs: &run.acceptance_bytes,
                verifier_files: run.verifier_files.contents(),
                launched_artifact: run.launched_artifact,
                java_binary: run.java_binary,
                java_release: run.java_release,
            },
        )
    }

    fn measurement(byte_length: u64, byte: u8) -> FileMeasurement {
        FileMeasurement {
            byte_length,
            sha256: [byte; 32],
        }
    }

    fn rust_run_documents<'a>(
        materialized: &'a MaterializedFixture,
        bindings: &PositiveGenerationBindings,
        verifier_input_bytes: &'a [u8],
        observation_bytes: &'a [u8],
        acceptance_bytes: &'a [u8],
    ) -> PositiveRunDocuments<'a> {
        let _ = bindings;
        PositiveRunDocuments {
            trusted_case_index: 0,
            trusted_implementation: PositiveImplementation::RustReference,
            verifier_input_jcs: verifier_input_bytes,
            observation_jcs: observation_bytes,
            acceptance_jcs: acceptance_bytes,
            verifier_files: materialized.verifier_files.contents(),
            launched_artifact: measurement(
                materialized.descriptor_values[0]["artifact"]["byteLength"]
                    .as_u64()
                    .unwrap(),
                0x51,
            ),
            java_binary: None,
            java_release: None,
        }
    }

    fn verifier_input_for_files(files: &OwnedVerifierFiles) -> Value {
        json!({
            "format": "Eip0045B4PositiveVerifierInputV1",
            "formatVersion": 1,
            "profileManifest": file_identity_from_bytes("profile-manifest.bin", &files.profile_manifest),
            "profileAlgorithm": file_identity_from_bytes("profile-algorithm.txt", &files.profile_algorithm),
            "profileConstants": file_identity_from_bytes("profile-constants.bin", &files.profile_constants),
            "guestElf": file_identity_from_bytes("guest.elf", &files.guest_elf),
            "statement": file_identity_from_bytes("statement.bin", &files.statement),
            "rawSeal": file_identity_from_bytes("raw-seal.bin", &files.raw_seal)
        })
    }

    fn verifier_input(materialized: &MaterializedFixture) -> Value {
        verifier_input_for_files(&materialized.verifier_files)
    }

    fn observation(materialized: &MaterializedFixture) -> (Value, Vec<u8>) {
        let verifier_input = verifier_input(materialized);
        let bytes = derive_expected_observation(
            &verifier_input,
            &materialized.verifier_files.contents(),
            &materialized.input_value,
            &materialized.input_value["positiveCases"][0],
        )
        .unwrap();
        let value = validate_canonical_json_source(&bytes).unwrap();
        (value, bytes)
    }

    fn rust_acceptance(
        materialized: &MaterializedFixture,
        bindings: &PositiveGenerationBindings,
        verifier_input_bytes: &[u8],
        observation_value: &Value,
        observation_bytes: &[u8],
    ) -> Value {
        let descriptor = &materialized.descriptor_values[0];
        json!({
            "format": "Eip0045B4PositiveAcceptanceV1",
            "formatVersion": 1,
            "caseId": "lift-po2-15",
            "caseIndex": 0,
            "inputSetCommitment": bindings.provenance.input_set.commitment("Eip0045B4PositiveInputSetV1"),
            "generationSetCommitment": bindings.generation_set.commitment("Eip0045B4PositiveGenerationSetV1"),
            "verifierInputCommitment": jcs_commitment("Eip0045B4PositiveVerifierInputV1", verifier_input_bytes),
            "observationCommitment": jcs_commitment("Eip0045B4PositiveObservationV1", observation_bytes),
            "implementationBinding": {
                "implementationIndex": 0,
                "implementation": "rust-reference",
                "language": "rust",
                "lineageSha256": descriptor["implementationLineage"]["lineageSha256"],
                "reviewedSource": reviewed_source_projection(&descriptor["reviewedSource"]).unwrap(),
                "buildDescriptor": bindings.provenance.validator_descriptors[0]
                    .commitment("Eip0045B4ValidatorBuildDescriptorV1"),
                "launchedArtifact": binary_commitment(&descriptor["artifact"]).unwrap(),
                "executionRunnerProfile": {
                    "runnerProfileIndex": 2,
                    "purpose": "rust-validator",
                    "artifact": bindings.provenance.runner_profiles[2]
                        .commitment("Eip0045B4PositiveOciRunnerProfileV1")
                }
            },
            "observation": observation_value
        })
    }

    fn jvm_acceptance(
        materialized: &MaterializedFixture,
        bindings: &PositiveGenerationBindings,
        verifier_input_bytes: &[u8],
        observation_value: &Value,
        observation_bytes: &[u8],
    ) -> Value {
        let descriptor = &materialized.descriptor_values[1];
        let java_runtime = &materialized.runner_values[3]["javaRuntime"];
        json!({
            "format": "Eip0045B4PositiveAcceptanceV1",
            "formatVersion": 1,
            "caseId": "lift-po2-15",
            "caseIndex": 0,
            "inputSetCommitment": bindings.provenance.input_set.commitment("Eip0045B4PositiveInputSetV1"),
            "generationSetCommitment": bindings.generation_set.commitment("Eip0045B4PositiveGenerationSetV1"),
            "verifierInputCommitment": jcs_commitment("Eip0045B4PositiveVerifierInputV1", verifier_input_bytes),
            "observationCommitment": jcs_commitment("Eip0045B4PositiveObservationV1", observation_bytes),
            "implementationBinding": {
                "implementationIndex": 1,
                "implementation": "independent-jvm",
                "language": "scala",
                "lineageSha256": descriptor["implementationLineage"]["lineageSha256"],
                "reviewedSource": reviewed_source_projection(&descriptor["reviewedSource"]).unwrap(),
                "buildDescriptor": bindings.provenance.validator_descriptors[1]
                    .commitment("Eip0045B4ValidatorBuildDescriptorV1"),
                "launchedArtifact": binary_commitment(&descriptor["artifact"]).unwrap(),
                "javaRuntime": java_runtime_projection(java_runtime).unwrap(),
                "executionRunnerProfile": {
                    "runnerProfileIndex": 3,
                    "purpose": "jvm-validator",
                    "artifact": bindings.provenance.runner_profiles[3]
                        .commitment("Eip0045B4PositiveOciRunnerProfileV1")
                }
            },
            "observation": observation_value
        })
    }

    fn jvm_run_documents<'a>(
        materialized: &'a MaterializedFixture,
        verifier_input_bytes: &'a [u8],
        observation_bytes: &'a [u8],
        acceptance_bytes: &'a [u8],
    ) -> PositiveRunDocuments<'a> {
        PositiveRunDocuments {
            trusted_case_index: 0,
            trusted_implementation: PositiveImplementation::IndependentJvm,
            verifier_input_jcs: verifier_input_bytes,
            observation_jcs: observation_bytes,
            acceptance_jcs: acceptance_bytes,
            verifier_files: materialized.verifier_files.contents(),
            launched_artifact: measurement(
                materialized.descriptor_values[1]["artifact"]["byteLength"]
                    .as_u64()
                    .unwrap(),
                0x52,
            ),
            java_binary: Some(measurement(64, 0x61)),
            java_release: Some(measurement(128, 0x62)),
        }
    }

    #[test]
    fn v2_runner_profile_closes_provider_bindings_and_four_roles() {
        for role in PositiveRunnerRole::all() {
            validate_v2_runner_profile(&v2_runner_profile(role), role).unwrap();
        }

        let mut wrong_case = v2_runner_profile(PositiveRunnerRole::RustValidatorBuild);
        wrong_case["format"] = json!("eip0045B4PositiveOciRunnerProfileV2");
        assert!(
            validate_v2_runner_profile(&wrong_case, PositiveRunnerRole::RustValidatorBuild)
                .is_err()
        );

        let mut wrong_version = v2_runner_profile(PositiveRunnerRole::RustValidatorBuild);
        wrong_version["formatVersion"] = json!(1);
        assert!(
            validate_v2_runner_profile(&wrong_version, PositiveRunnerRole::RustValidatorBuild)
                .is_err()
        );

        let v1 = Fixture::valid().runner_values[0].clone();
        assert!(validate_v2_runner_profile(&v1, PositiveRunnerRole::RustValidatorBuild).is_err());

        let mut unknown_root = v2_runner_profile(PositiveRunnerRole::RustValidatorBuild);
        unknown_root["unexpected"] = json!(true);
        assert!(
            validate_v2_runner_profile(&unknown_root, PositiveRunnerRole::RustValidatorBuild)
                .is_err()
        );

        let mut unknown_binding = v2_runner_profile(PositiveRunnerRole::RustValidatorBuild);
        unknown_binding["retainedHostRootfsMetadataProvider"]["unexpected"] = json!(true);
        assert!(
            validate_v2_runner_profile(&unknown_binding, PositiveRunnerRole::RustValidatorBuild)
                .is_err()
        );

        let valid_rust = v2_runner_profile(PositiveRunnerRole::RustValidatorBuild);
        assert!(
            validate_v2_runner_profile(&valid_rust, PositiveRunnerRole::JvmValidatorBuild).is_err()
        );

        let mut wrong_index = v2_runner_profile(PositiveRunnerRole::RustValidatorBuild);
        wrong_index["runnerProfileIndex"] = json!(1);
        assert!(
            validate_v2_runner_profile(&wrong_index, PositiveRunnerRole::RustValidatorBuild)
                .is_err()
        );

        let mut wrong_purpose = v2_runner_profile(PositiveRunnerRole::RustValidatorBuild);
        wrong_purpose["purpose"] = json!("jvm-validator-build");
        assert!(
            validate_v2_runner_profile(&wrong_purpose, PositiveRunnerRole::RustValidatorBuild)
                .is_err()
        );

        let mut wrong_canonical_role = v2_runner_profile(PositiveRunnerRole::RustValidatorBuild);
        wrong_canonical_role["retainedHostRootfsMetadataProvider"]["canonicalRole"] =
            json!("JvmValidatorBuild");
        assert!(
            validate_v2_runner_profile(
                &wrong_canonical_role,
                PositiveRunnerRole::RustValidatorBuild,
            )
            .is_err()
        );

        let mut caller_selected_mode = v2_runner_profile(PositiveRunnerRole::RustValidatorBuild);
        caller_selected_mode["retainedHostRootfsMetadataProvider"]["metadataMode"] =
            json!("ObservedAbsentComplete");
        assert!(
            validate_v2_runner_profile(
                &caller_selected_mode,
                PositiveRunnerRole::RustValidatorBuild,
            )
            .is_err()
        );

        let mut v1_image_policy = v2_runner_profile(PositiveRunnerRole::RustValidatorBuild);
        v1_image_policy["image"]["retainedHostRootfsMetadataPolicy"] =
            json!("eip0045-b4-retained-host-rootfs-metadata-obligations-v1");
        assert!(
            validate_v2_runner_profile(&v1_image_policy, PositiveRunnerRole::RustValidatorBuild)
                .is_err()
        );

        let binding_drifts = [
            (
                "metadataPolicy",
                "eip0045-b4-retained-host-rootfs-metadata-obligations-v1",
            ),
            ("providerProfile", "eip0045-b4-tmpfs-metadata-provider-v0"),
            (
                "sessionProtocol",
                "eip0045-b4-supervised-filesystem-session-v0",
            ),
            ("applianceProfile", "eip0045-b4-buildroot-appliance-v0"),
        ];
        for (field_name, drifted_value) in binding_drifts {
            let mut drift = v2_runner_profile(PositiveRunnerRole::RustValidatorBuild);
            drift["retainedHostRootfsMetadataProvider"][field_name] = json!(drifted_value);
            assert!(
                validate_v2_runner_profile(&drift, PositiveRunnerRole::RustValidatorBuild).is_err(),
                "provider binding {field_name} accepted a one-field drift"
            );
        }

        let mut bad_digest = v2_runner_profile(PositiveRunnerRole::RustValidatorBuild);
        bad_digest["retainedHostRootfsMetadataProvider"]["expectedModeTableSha256"] =
            json!("A5".repeat(32));
        assert!(
            validate_v2_runner_profile(&bad_digest, PositiveRunnerRole::RustValidatorBuild)
                .is_err()
        );

        let mut missing_digest = v2_runner_profile(PositiveRunnerRole::RustValidatorBuild);
        missing_digest["retainedHostRootfsMetadataProvider"]
            .as_object_mut()
            .unwrap()
            .remove("expectedModeTableSha256");
        assert!(
            validate_v2_runner_profile(&missing_digest, PositiveRunnerRole::RustValidatorBuild)
                .is_err()
        );

        for invalid_digest in ["a".repeat(63), "g".repeat(64)] {
            let mut invalid = v2_runner_profile(PositiveRunnerRole::RustValidatorBuild);
            invalid["retainedHostRootfsMetadataProvider"]["expectedModeTableSha256"] =
                json!(invalid_digest);
            assert!(
                validate_v2_runner_profile(&invalid, PositiveRunnerRole::RustValidatorBuild)
                    .is_err()
            );
        }

        validate_json_schema(
            &Fixture::valid().runner_values[0],
            EmbeddedSchema::RunnerProfile,
            "V1 runner profile after V2 cache initialization",
        )
        .unwrap();
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v2_input_set_commits_only_v2_runner_and_descriptor_formats() {
        let valid = V2InputIdentityFixture::valid();
        valid.validate().unwrap();

        for (field, value) in [
            ("format", json!("eip0045B4PositiveInputSetV2")),
            ("formatVersion", json!(1)),
        ] {
            let mut fixture = valid.clone();
            fixture.input_value[field] = value;
            fixture.refresh_input_source();
            assert_v2_identity_rejects(&fixture, "V2 positive input set");
        }

        let v1_materialized = Fixture::valid().materialize();
        let mut v1_input = valid.clone();
        v1_input.input_bytes = v1_materialized.input_bytes.clone();
        assert_v2_identity_rejects(&v1_input, "V2 positive input set");

        for (field, value) in [
            ("format", json!("eip0045B4ValidatorBuildDescriptorV2")),
            ("formatVersion", json!(1)),
        ] {
            for descriptor_index in 0..2 {
                let mut fixture = valid.clone();
                fixture.descriptor_values[descriptor_index][field] = value.clone();
                fixture.refresh_descriptor_sources_and_input_bindings();
                assert_v2_identity_rejects(&fixture, "validator descriptor");
            }
        }

        for target in ["input", "descriptor", "nested-identity"] {
            let mut fixture = valid.clone();
            match target {
                "input" => fixture.input_value["unexpected"] = json!(true),
                "descriptor" => fixture.descriptor_values[0]["unexpected"] = json!(true),
                "nested-identity" => {
                    fixture.input_value["runnerProfiles"][0]["artifact"]["unexpected"] = json!(true)
                }
                _ => unreachable!(),
            }
            if target == "descriptor" {
                fixture.refresh_descriptor_sources_and_input_bindings();
                assert_v2_identity_rejects(&fixture, "validator descriptor");
            } else {
                fixture.refresh_input_source();
                assert_v2_identity_rejects(&fixture, "V2 positive input set");
            }
        }

        for mutation in ["missing", "extra", "duplicate", "reordered"] {
            let mut fixture = valid.clone();
            let runners = fixture.input_value["runnerProfiles"]
                .as_array_mut()
                .unwrap();
            match mutation {
                "missing" => {
                    runners.remove(3);
                }
                "extra" => runners.push(runners[3].clone()),
                "duplicate" => runners[1] = runners[0].clone(),
                "reordered" => runners.swap(0, 1),
                _ => unreachable!(),
            }
            fixture.refresh_input_source();
            assert_v2_identity_rejects(&fixture, "V2 positive input set");
        }

        for mutation in ["missing", "extra", "duplicate", "reordered"] {
            let mut fixture = valid.clone();
            let validators = fixture.input_value["validators"].as_array_mut().unwrap();
            match mutation {
                "missing" => {
                    validators.remove(1);
                }
                "extra" => validators.push(validators[1].clone()),
                "duplicate" => validators[1] = validators[0].clone(),
                "reordered" => validators.swap(0, 1),
                _ => unreachable!(),
            }
            fixture.refresh_input_source();
            assert_v2_identity_rejects(&fixture, "V2 positive input set");
        }

        for field in ["runnerProfileIndex", "purpose"] {
            let mut fixture = valid.clone();
            fixture.input_value["runnerProfiles"][0][field] = if field == "runnerProfileIndex" {
                json!(1)
            } else {
                json!("jvm-validator-build")
            };
            fixture.refresh_input_source();
            assert_v2_identity_rejects(&fixture, "V2 positive input set");
        }

        for field in ["implementationIndex", "implementation", "language"] {
            let mut fixture = valid.clone();
            fixture.input_value["validators"][0][field] = match field {
                "implementationIndex" => json!(1),
                "implementation" => json!("independent-jvm"),
                "language" => json!("scala"),
                _ => unreachable!(),
            };
            fixture.refresh_input_source();
            assert_v2_identity_rejects(&fixture, "V2 positive input set");
        }

        let mut wrong_role_source = valid.clone();
        wrong_role_source.runner_values[1] = wrong_role_source.runner_values[0].clone();
        wrong_role_source.refresh_all_commitments();
        assert_v2_identity_rejects(&wrong_role_source, "runner profile");

        let mut v1_runner = valid.clone();
        v1_runner.runner_values[0] = v1_materialized.runner_values[0].clone();
        v1_runner.refresh_all_commitments();
        assert_v2_identity_rejects(&v1_runner, "runner profile");

        let mut v1_descriptor = valid.clone();
        v1_descriptor.descriptor_values[0] = v1_materialized.descriptor_values[0].clone();
        v1_descriptor.refresh_descriptor_sources_and_input_bindings();
        assert_v2_identity_rejects(&v1_descriptor, "validator descriptor");

        let mut v1_profile_commitment = valid.clone();
        v1_profile_commitment.descriptor_values[0]["deterministicBuild"]["runnerProfile"]["commitment"]
            ["format"] = json!("Eip0045B4PositiveOciRunnerProfileV1");
        v1_profile_commitment.refresh_descriptor_sources_and_input_bindings();
        assert_v2_identity_rejects(&v1_profile_commitment, "validator descriptor");

        for runner_index in 0..4 {
            for field_name in ["format", "path", "byteLength", "sha256", "encoding"] {
                let mut fixture = valid.clone();
                drift_document_identity_field(
                    &mut fixture.input_value["runnerProfiles"][runner_index]["artifact"],
                    field_name,
                );
                fixture.refresh_input_source();
                let context = match field_name {
                    "format" | "encoding" => "V2 positive input set",
                    "path" | "byteLength" | "sha256" => "V2 input-set",
                    _ => unreachable!(),
                };
                assert_v2_identity_rejects(&fixture, context);
            }
        }

        for (descriptor_index, edge) in [
            (0, "deterministicBuild"),
            (0, "executionEnvironment"),
            (1, "deterministicBuild"),
            (1, "executionEnvironment"),
        ] {
            for field_name in ["format", "path", "byteLength", "sha256", "encoding"] {
                let mut fixture = valid.clone();
                drift_document_identity_field(
                    &mut fixture.descriptor_values[descriptor_index][edge]["runnerProfile"]["commitment"],
                    field_name,
                );
                fixture.refresh_descriptor_sources_and_input_bindings();
                let context = match field_name {
                    "format" | "encoding" => "validator descriptor",
                    "path" | "byteLength" | "sha256" => "V2 descriptor",
                    _ => unreachable!(),
                };
                assert_v2_identity_rejects(&fixture, context);
            }
        }

        for descriptor_index in 0..2 {
            for field_name in ["format", "path", "byteLength", "sha256", "encoding"] {
                let mut fixture = valid.clone();
                drift_document_identity_field(
                    &mut fixture.input_value["validators"][descriptor_index]["buildDescriptor"],
                    field_name,
                );
                fixture.refresh_input_source();
                let context = match field_name {
                    "format" | "encoding" => "V2 positive input set",
                    "path" | "byteLength" | "sha256" => "V2 input-set",
                    _ => unreachable!(),
                };
                assert_v2_identity_rejects(&fixture, context);
            }
        }

        let mut stale_runner_source = valid.clone();
        stale_runner_source.runner_values[0]["retainedHostRootfsMetadataProvider"]["expectedModeTableSha256"] =
            json!(digest(0xa6));
        stale_runner_source.runner_bytes[0] =
            canonical_json_bytes(&stale_runner_source.runner_values[0]).unwrap();
        assert_v2_identity_rejects(
            &stale_runner_source,
            "V2 input-set rust-validator-build runner-profile identity is stale",
        );

        let mut malformed_runner = valid.clone();
        malformed_runner.runner_values[0]["unexpected"] = json!(true);
        malformed_runner.refresh_all_commitments();
        assert_v2_identity_rejects(&malformed_runner, "runner profile");

        let mut aliased_descriptors = valid.clone();
        let descriptor_alias =
            aliased_descriptors.input_value["validators"][0]["buildDescriptor"].clone();
        aliased_descriptors.input_value["validators"][1]["buildDescriptor"] = descriptor_alias;
        aliased_descriptors.refresh_input_source();
        assert_v2_identity_rejects(
            &aliased_descriptors,
            "V2 input-set validator descriptor identity is stale",
        );

        for source in ["input", "runner", "descriptor"] {
            let mut fixture = valid.clone();
            match source {
                "input" => fixture.input_bytes.push(b' '),
                "runner" => fixture.runner_bytes[0].push(b' '),
                "descriptor" => fixture.descriptor_bytes[0].push(b' '),
                _ => unreachable!(),
            }
            assert_v2_identity_rejects(&fixture, "canonical");
        }

        assert!(!std::ptr::eq(&INPUT_SET_VALIDATOR, &INPUT_SET_V2_VALIDATOR));
        assert!(!std::ptr::eq(
            &VALIDATOR_DESCRIPTOR_VALIDATOR,
            &VALIDATOR_DESCRIPTOR_V2_VALIDATOR
        ));
        v1_materialized.bind().unwrap();
        valid.validate().unwrap();
        v1_materialized.bind().unwrap();
    }

    #[test]
    fn v2_positive_precommit_gate_closes_the_exact_mixed_wire_family() {
        let v2 = V2InputIdentityFixture::valid();
        let retained_v1_documents = Fixture::valid().materialize();

        retained_v1_documents.bind().unwrap();
        v2.bind_positive_precommit(&retained_v1_documents).unwrap();
        retained_v1_documents.bind().unwrap();

        let mut v1_input = v2.clone();
        v1_input.input_bytes = retained_v1_documents.input_bytes.clone();
        assert!(
            v1_input
                .bind_positive_precommit(&retained_v1_documents)
                .is_err(),
            "the V2 precommit gate accepted a complete V1 positive input set"
        );

        let mut v1_runner = v2.clone();
        v1_runner.runner_values[0] = retained_v1_documents.runner_values[0].clone();
        v1_runner.refresh_all_commitments();
        assert!(
            v1_runner
                .bind_positive_precommit(&retained_v1_documents)
                .is_err(),
            "the V2 precommit gate accepted a V1 runner profile"
        );

        let mut v1_descriptor = v2.clone();
        v1_descriptor.descriptor_values[0] = retained_v1_documents.descriptor_values[0].clone();
        v1_descriptor.refresh_descriptor_sources_and_input_bindings();
        assert!(
            v1_descriptor
                .bind_positive_precommit(&retained_v1_documents)
                .is_err(),
            "the V2 precommit gate accepted a V1 validator descriptor"
        );
    }

    #[test]
    fn v2_positive_precommit_gate_rejects_each_retained_v1_child_substitution() {
        let v2 = V2InputIdentityFixture::valid();

        let mut stale_verifier = Fixture::valid().materialize();
        stale_verifier.verifier_contract_bytes.push(b' ');
        assert!(v2.bind_positive_precommit(&stale_verifier).is_err());

        let mut substituted_seccomp_fixture = Fixture::valid();
        substituted_seccomp_fixture.seccomp_values[0]["linuxSeccomp"]["syscalls"][0]["names"] =
            json!(["brk", "close", "read", "write"]);
        let substituted_seccomp = substituted_seccomp_fixture.materialize();
        assert!(v2.bind_positive_precommit(&substituted_seccomp).is_err());

        let mut stale_manifest = Fixture::valid().materialize();
        stale_manifest
            .jvm_copy_only_inclusion_manifest_bytes
            .push(b' ');
        assert!(v2.bind_positive_precommit(&stale_manifest).is_err());
    }

    fn construct_v2_generation_fixture(
        input: &V2InputIdentityFixture,
        proof_generator_artifact: &[u8],
        generation_cases: &[OwnedGenerationCase; POSITIVE_CASE_COUNT],
    ) -> Result<Vec<u8>> {
        let paths =
            crate::b4_positive_input_set::project_b4_positive_input_set_publication_paths_v2(
                "positive",
            )?;
        let input_binding =
            crate::b4_positive_input_set::bind_b4_positive_input_set_publication_v2(
                &paths,
                &input.input_bytes,
            )?;
        let artifact_views: [Vec<GeneratedArtifactContents<'_>>; POSITIVE_CASE_COUNT] =
            std::array::from_fn(|case_index| {
                generation_cases[case_index]
                    .artifacts
                    .iter()
                    .map(|artifact| GeneratedArtifactContents {
                        source_file: artifact.source_file,
                        bytes: &artifact.bytes,
                    })
                    .collect()
            });
        let auxiliary_views: [Vec<GeneratedAuxiliaryArtifactContents<'_>>; POSITIVE_CASE_COUNT] =
            std::array::from_fn(|case_index| {
                generation_cases[case_index]
                    .auxiliary_artifacts
                    .iter()
                    .map(|artifact| GeneratedAuxiliaryArtifactContents {
                        relative_path: artifact.source_file,
                        bytes: &artifact.bytes,
                    })
                    .collect()
            });
        let cases = std::array::from_fn(|case_index| PositiveGenerationCaseDocuments {
            proof_output_manifest_jcs: &generation_cases[case_index].proof_output_manifest_jcs,
            artifacts: &artifact_views[case_index],
            auxiliary_artifacts: &auxiliary_views[case_index],
        });
        construct_canonical_positive_generation_set_jcs_v2(
            &input_binding,
            proof_generator_artifact,
            cases,
        )
    }

    #[test]
    fn v2_generation_set_builder_reproduces_the_closed_fixture_byte_exactly() {
        let base = Fixture::valid();
        let input = V2InputIdentityFixture::valid();
        let (mut generation_value, _, generation_cases) = build_generation_fixture(
            &input.input_value,
            &input.input_bytes,
            &base.verifier_files,
            &base.proof_generator_artifact,
            &base.recursive_calibrations,
        );
        generation_value["format"] = json!("Eip0045B4PositiveGenerationSetV2");
        generation_value["formatVersion"] = json!(2);
        generation_value["inputSetCommitment"] =
            jcs_commitment("Eip0045B4PositiveInputSetV2", &input.input_bytes);
        let expected = canonical_json_bytes(&generation_value).unwrap();
        let actual = construct_v2_generation_fixture(
            &input,
            &base.proof_generator_artifact,
            &generation_cases,
        )
        .unwrap();

        assert_eq!(actual, expected);
    }

    #[test]
    fn v2_generation_set_builder_rejects_isolated_physical_export_mutants() {
        let base = Fixture::valid();
        let input = V2InputIdentityFixture::valid();
        let (generation_value, _, exact_cases) = build_generation_fixture(
            &input.input_value,
            &input.input_bytes,
            &base.verifier_files,
            &base.proof_generator_artifact,
            &base.recursive_calibrations,
        );

        let mut wrong_primary_name = exact_cases.clone();
        wrong_primary_name[0].artifacts[0].source_file = "candidate-control-id.bin";
        let error = construct_v2_generation_fixture(
            &input,
            &base.proof_generator_artifact,
            &wrong_primary_name,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("physical generator artifact name differs"),
            "wrong primary name reached the wrong rejection: {error:#}"
        );

        let mut noncanonical_manifest = exact_cases.clone();
        noncanonical_manifest[0]
            .proof_output_manifest_jcs
            .push(b' ');
        let error = construct_v2_generation_fixture(
            &input,
            &base.proof_generator_artifact,
            &noncanonical_manifest,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}")
                .contains("physical proof-output manifest is not exact canonical JCS"),
            "noncanonical manifest reached the wrong rejection: {error:#}"
        );

        let mut reordered_auxiliary = exact_cases.clone();
        reordered_auxiliary[10].auxiliary_artifacts.swap(0, 1);
        let error = construct_v2_generation_fixture(
            &input,
            &base.proof_generator_artifact,
            &reordered_auxiliary,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("recursive auxiliary artifact path or order differs"),
            "reordered auxiliary export reached the wrong rejection: {error:#}"
        );

        let mut duplicate_raw_seal_value = generation_value;
        let mut duplicate_raw_seal = exact_cases;
        let first_raw_seal = duplicate_raw_seal[0]
            .artifacts
            .iter()
            .find(|artifact| artifact.source_file == "candidate-raw-seal.bin")
            .unwrap()
            .bytes
            .clone();
        duplicate_raw_seal[1]
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.source_file == "candidate-raw-seal.bin")
            .unwrap()
            .bytes = first_raw_seal;
        refresh_generation_case_parts(&mut duplicate_raw_seal_value, &mut duplicate_raw_seal, 1);
        let error = construct_v2_generation_fixture(
            &input,
            &base.proof_generator_artifact,
            &duplicate_raw_seal,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("reuses a raw-seal digest"),
            "duplicate raw seal reached the wrong rejection: {error:#}"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn v2_generation_and_acceptance_recompute_every_nested_identity() {
        let base = Fixture::valid();
        let input = V2InputIdentityFixture::valid();
        let (mut generation_value, generation_v1_bytes, generation_cases) =
            build_generation_fixture(
                &input.input_value,
                &input.input_bytes,
                &base.verifier_files,
                &base.proof_generator_artifact,
                &base.recursive_calibrations,
            );
        generation_value["format"] = json!("Eip0045B4PositiveGenerationSetV2");
        generation_value["formatVersion"] = json!(2);
        generation_value["inputSetCommitment"] =
            jcs_commitment("Eip0045B4PositiveInputSetV2", &input.input_bytes);
        let generation_bytes = canonical_json_bytes(&generation_value).unwrap();

        for case_index in 0..POSITIVE_CASE_COUNT {
            for implementation in [
                PositiveImplementation::RustReference,
                PositiveImplementation::IndependentJvm,
            ] {
                let run = v2_acceptance_fixture(
                    &input,
                    &generation_bytes,
                    &generation_cases,
                    &base.verifier_files,
                    case_index,
                    implementation,
                );
                validate_v2_fixture(
                    &input,
                    GENERATION_SET_PATH,
                    &generation_bytes,
                    &generation_cases,
                    &base.proof_generator_artifact,
                    &run,
                )
                .unwrap();
            }
        }

        let valid_rust = v2_acceptance_fixture(
            &input,
            &generation_bytes,
            &generation_cases,
            &base.verifier_files,
            0,
            PositiveImplementation::RustReference,
        );
        let assert_generation_rejects =
            |path: &str, bytes: &[u8], proof_generator: &[u8], expected: &str| {
                let error = validate_v2_fixture(
                    &input,
                    path,
                    bytes,
                    &generation_cases,
                    proof_generator,
                    &valid_rust,
                )
                .unwrap_err();
                let rendered = format!("{error:#}");
                assert!(
                    rendered.contains(expected),
                    "expected generation rejection {expected:?}, got {rendered}"
                );
            };

        assert_generation_rejects(
            GENERATION_SET_PATH,
            &generation_v1_bytes,
            &base.proof_generator_artifact,
            "V2 positive generation set",
        );
        for (field_name, replacement) in [
            ("format", json!("eip0045B4PositiveGenerationSetV2")),
            ("formatVersion", json!(1)),
        ] {
            let mut drift = generation_value.clone();
            drift[field_name] = replacement;
            let bytes = canonical_json_bytes(&drift).unwrap();
            assert_generation_rejects(
                GENERATION_SET_PATH,
                &bytes,
                &base.proof_generator_artifact,
                "V2 positive generation set",
            );
        }
        let mut unknown_generation = generation_value.clone();
        unknown_generation["unexpected"] = json!(true);
        let unknown_generation = canonical_json_bytes(&unknown_generation).unwrap();
        assert_generation_rejects(
            GENERATION_SET_PATH,
            &unknown_generation,
            &base.proof_generator_artifact,
            "V2 positive generation set",
        );
        for alias in [INPUT_SET_PATH, "positive", "runner/rust-build.json/child"] {
            assert_generation_rejects(
                alias,
                &generation_bytes,
                &base.proof_generator_artifact,
                "path aliases or ancestor/descendant-conflicts",
            );
        }

        for field_name in ["format", "byteLength", "sha256", "encoding"] {
            let mut drift = generation_value.clone();
            drift_document_identity_field(&mut drift["inputSetCommitment"], field_name);
            let bytes = canonical_json_bytes(&drift).unwrap();
            let expected = if matches!(field_name, "format" | "encoding") {
                "V2 positive generation set"
            } else {
                "V2 generation-set input-set commitment"
            };
            assert_generation_rejects(
                GENERATION_SET_PATH,
                &bytes,
                &base.proof_generator_artifact,
                expected,
            );
        }
        let mut v1_input_commitment = generation_value.clone();
        v1_input_commitment["inputSetCommitment"]["format"] = json!("Eip0045B4PositiveInputSetV1");
        let v1_input_commitment = canonical_json_bytes(&v1_input_commitment).unwrap();
        assert_generation_rejects(
            GENERATION_SET_PATH,
            &v1_input_commitment,
            &base.proof_generator_artifact,
            "V2 positive generation set",
        );
        for field_name in ["byteLength", "sha256", "encoding"] {
            let mut drift = generation_value.clone();
            drift["proofGeneratorArtifact"][field_name] = match field_name {
                "byteLength" => json!(
                    drift["proofGeneratorArtifact"][field_name]
                        .as_u64()
                        .unwrap()
                        + 1
                ),
                "sha256" => json!(digest(0xfe)),
                "encoding" => json!("rfc8785-jcs"),
                _ => unreachable!(),
            };
            let bytes = canonical_json_bytes(&drift).unwrap();
            let expected = if field_name == "encoding" {
                "V2 positive generation set"
            } else {
                "V2 generation-set proof-generator artifact binding"
            };
            assert_generation_rejects(
                GENERATION_SET_PATH,
                &bytes,
                &base.proof_generator_artifact,
                expected,
            );
        }
        let mut changed_proof_generator = base.proof_generator_artifact.clone();
        changed_proof_generator[0] ^= 1;
        assert_generation_rejects(
            GENERATION_SET_PATH,
            &generation_bytes,
            &changed_proof_generator,
            "V2 proof generator artifact digest",
        );

        let mut changed_input_source = input.clone();
        changed_input_source.runner_values[0]["retainedHostRootfsMetadataProvider"]["expectedModeTableSha256"] =
            json!(digest(0xa7));
        changed_input_source.refresh_all_commitments();
        let error = validate_v2_fixture(
            &changed_input_source,
            GENERATION_SET_PATH,
            &generation_bytes,
            &generation_cases,
            &base.proof_generator_artifact,
            &valid_rust,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("V2 generation-set input-set commitment"),
            "changed V2 input source did not reach the generation commitment: {error:#}"
        );

        let mut changed_generation_value = generation_value.clone();
        let mut changed_generation_cases = generation_cases.clone();
        changed_generation_cases[10]
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.source_file == "candidate-raw-seal.bin")
            .unwrap()
            .bytes[0] ^= 1;
        refresh_generation_case_parts(
            &mut changed_generation_value,
            &mut changed_generation_cases,
            10,
        );
        let changed_generation_bytes = canonical_json_bytes(&changed_generation_value).unwrap();
        let error = validate_v2_fixture(
            &input,
            GENERATION_SET_PATH,
            &changed_generation_bytes,
            &changed_generation_cases,
            &base.proof_generator_artifact,
            &valid_rust,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("V2 acceptance generation-set commitment"),
            "changed V2 generation source did not reach the acceptance commitment: {error:#}"
        );

        let assert_generation_case_set_rejects =
            |value: &Value, cases: &[OwnedGenerationCase; POSITIVE_CASE_COUNT], expected: &str| {
                let bytes = canonical_json_bytes(value).unwrap();
                let error = validate_v2_fixture(
                    &input,
                    GENERATION_SET_PATH,
                    &bytes,
                    cases,
                    &base.proof_generator_artifact,
                    &valid_rust,
                )
                .unwrap_err();
                let rendered = format!("{error:#}");
                assert!(
                    rendered.contains(expected),
                    "expected V2 generation-set rejection {expected:?}, got {rendered}"
                );
            };
        let mut duplicate_raw_seal_value = generation_value.clone();
        let mut duplicate_raw_seal_cases = generation_cases.clone();
        let raw_seal = duplicate_raw_seal_cases[0]
            .artifacts
            .iter()
            .find(|artifact| artifact.source_file == "candidate-raw-seal.bin")
            .unwrap()
            .bytes
            .clone();
        duplicate_raw_seal_cases[1]
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.source_file == "candidate-raw-seal.bin")
            .unwrap()
            .bytes = raw_seal;
        refresh_generation_case_parts(
            &mut duplicate_raw_seal_value,
            &mut duplicate_raw_seal_cases,
            1,
        );
        assert_generation_case_set_rejects(
            &duplicate_raw_seal_value,
            &duplicate_raw_seal_cases,
            "reuses a raw-seal digest",
        );

        let mut duplicate_manifest_value = generation_value.clone();
        let mut duplicate_manifest_cases = generation_cases.clone();
        duplicate_manifest_cases[1] = duplicate_manifest_cases[0].clone();
        refresh_generation_case_parts(
            &mut duplicate_manifest_value,
            &mut duplicate_manifest_cases,
            1,
        );
        assert_generation_case_set_rejects(
            &duplicate_manifest_value,
            &duplicate_manifest_cases,
            "reuses a proof-output manifest digest",
        );

        let mut global_order_value = generation_value.clone();
        let mut global_order_cases = generation_cases.clone();
        global_order_cases[0]
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.source_file == "candidate-image-id.bin")
            .unwrap()
            .bytes[0] ^= 1;
        refresh_generation_case_parts(&mut global_order_value, &mut global_order_cases, 0);
        global_order_cases[1]
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.source_file == "candidate-raw-seal.bin")
            .unwrap()
            .bytes[0] ^= 1;
        assert_generation_case_set_rejects(
            &global_order_value,
            &global_order_cases,
            "generated raw-seal artifact digest",
        );

        for mutation in ["missing", "extra", "duplicate", "reordered"] {
            let mut drift = generation_value.clone();
            let cases = drift["cases"].as_array_mut().unwrap();
            match mutation {
                "missing" => {
                    cases.remove(10);
                }
                "extra" => cases.push(cases[10].clone()),
                "duplicate" => cases[1] = cases[0].clone(),
                "reordered" => cases.swap(0, 1),
                _ => unreachable!(),
            }
            let bytes = canonical_json_bytes(&drift).unwrap();
            assert_generation_rejects(
                GENERATION_SET_PATH,
                &bytes,
                &base.proof_generator_artifact,
                "V2 positive generation set",
            );
        }
        let generation_case_drifts = [
            (&["cases", "0", "caseIndex"][..], json!(1)),
            (&["cases", "0", "caseId"][..], json!("lift-po2-16")),
            (
                &["cases", "0", "generation", "kind"][..],
                json!("recursive"),
            ),
            (&["cases", "0", "generation", "segmentPo2"][..], json!(16)),
            (
                &["cases", "0", "artifacts", "0", "role"][..],
                json!("control-id"),
            ),
            (
                &["cases", "0", "artifacts", "0", "sourceFile"][..],
                json!("candidate-control-id.bin"),
            ),
            (
                &["cases", "8", "generation", "family"][..],
                json!("terminal-resolve"),
            ),
        ];
        for (path, replacement) in generation_case_drifts {
            let mut drift = generation_value.clone();
            set_json_pointer(&mut drift, path, replacement);
            let bytes = canonical_json_bytes(&drift).unwrap();
            assert_generation_rejects(
                GENERATION_SET_PATH,
                &bytes,
                &base.proof_generator_artifact,
                "V2 positive generation set",
            );
        }
        let mut noncanonical_generation = generation_bytes.clone();
        noncanonical_generation.push(b' ');
        assert_generation_rejects(
            GENERATION_SET_PATH,
            &noncanonical_generation,
            &base.proof_generator_artifact,
            "canonical",
        );

        for implementation in [
            PositiveImplementation::RustReference,
            PositiveImplementation::IndependentJvm,
        ] {
            let valid = v2_acceptance_fixture(
                &input,
                &generation_bytes,
                &generation_cases,
                &base.verifier_files,
                0,
                implementation,
            );
            let assert_acceptance_rejects = |run: &V2AcceptanceFixture, expected: &str| {
                let error = validate_v2_fixture(
                    &input,
                    GENERATION_SET_PATH,
                    &generation_bytes,
                    &generation_cases,
                    &base.proof_generator_artifact,
                    run,
                )
                .unwrap_err();
                let rendered = format!("{error:#}");
                assert!(
                    rendered.contains(expected),
                    "expected acceptance rejection {expected:?}, got {rendered}"
                );
            };

            let mut v1 = valid.clone();
            v1.acceptance_value["format"] = json!("Eip0045B4PositiveAcceptanceV1");
            v1.acceptance_value["formatVersion"] = json!(1);
            v1.acceptance_value["inputSetCommitment"]["format"] =
                json!("Eip0045B4PositiveInputSetV1");
            v1.acceptance_value["generationSetCommitment"]["format"] =
                json!("Eip0045B4PositiveGenerationSetV1");
            v1.acceptance_value["implementationBinding"]["buildDescriptor"]["format"] =
                json!("Eip0045B4ValidatorBuildDescriptorV1");
            v1.acceptance_value["implementationBinding"]["executionRunnerProfile"]["artifact"]["format"] =
                json!("Eip0045B4PositiveOciRunnerProfileV1");
            v1.refresh_acceptance_source();
            assert_acceptance_rejects(&v1, "V2 acceptance");

            for (field_name, replacement) in [
                ("format", json!("eip0045B4PositiveAcceptanceV2")),
                ("formatVersion", json!(1)),
            ] {
                let mut drift = valid.clone();
                drift.acceptance_value[field_name] = replacement;
                drift.refresh_acceptance_source();
                assert_acceptance_rejects(&drift, "V2 acceptance");
            }
            let mut unknown = valid.clone();
            unknown.acceptance_value["unexpected"] = json!(true);
            unknown.refresh_acceptance_source();
            assert_acceptance_rejects(&unknown, "V2 acceptance");

            let mut case_index = valid.clone();
            case_index.acceptance_value["caseIndex"] = json!(1);
            case_index.refresh_acceptance_source();
            assert_acceptance_rejects(&case_index, "V2 acceptance");
            let mut case_id = valid.clone();
            case_id.acceptance_value["caseId"] =
                input.input_value["positiveCases"][1]["caseId"].clone();
            case_id.refresh_acceptance_source();
            assert_acceptance_rejects(&case_id, "V2 acceptance");
            let mut trusted_case = valid.clone();
            trusted_case.case_index = 1;
            assert_acceptance_rejects(&trusted_case, "caseIndex differs from 1");
            let mut other_case_source = v2_acceptance_fixture(
                &input,
                &generation_bytes,
                &generation_cases,
                &base.verifier_files,
                1,
                implementation,
            );
            other_case_source.case_index = 0;
            assert_acceptance_rejects(&other_case_source, "caseIndex differs from 0");

            for (target, semantic_context) in [
                ("inputSetCommitment", "V2 acceptance input-set commitment"),
                (
                    "generationSetCommitment",
                    "V2 acceptance generation-set commitment",
                ),
                (
                    "verifierInputCommitment",
                    "V2 acceptance verifier-input commitment",
                ),
                (
                    "observationCommitment",
                    "V2 acceptance observation commitment",
                ),
            ] {
                for field_name in ["format", "byteLength", "sha256", "encoding"] {
                    let mut drift = valid.clone();
                    drift_document_identity_field(&mut drift.acceptance_value[target], field_name);
                    drift.refresh_acceptance_source();
                    let expected = if matches!(field_name, "format" | "encoding") {
                        "V2 acceptance"
                    } else {
                        semantic_context
                    };
                    assert_acceptance_rejects(&drift, expected);
                }
            }
            for (target, v1_format) in [
                ("inputSetCommitment", "Eip0045B4PositiveInputSetV1"),
                (
                    "generationSetCommitment",
                    "Eip0045B4PositiveGenerationSetV1",
                ),
            ] {
                let mut mixed = valid.clone();
                mixed.acceptance_value[target]["format"] = json!(v1_format);
                mixed.refresh_acceptance_source();
                assert_acceptance_rejects(&mixed, "V2 acceptance");
            }
            for (target, semantic_context) in [
                ("descriptor", "V2 acceptance descriptor commitment"),
                ("runner", "V2 acceptance execution-runner commitment"),
            ] {
                for field_name in ["format", "byteLength", "sha256", "encoding"] {
                    let mut drift = valid.clone();
                    let identity = if target == "descriptor" {
                        &mut drift.acceptance_value["implementationBinding"]["buildDescriptor"]
                    } else {
                        &mut drift.acceptance_value["implementationBinding"]["executionRunnerProfile"]
                            ["artifact"]
                    };
                    drift_document_identity_field(identity, field_name);
                    drift.refresh_acceptance_source();
                    let expected = if matches!(field_name, "format" | "encoding") {
                        "V2 acceptance"
                    } else {
                        semantic_context
                    };
                    assert_acceptance_rejects(&drift, expected);
                }
            }
            for (target, v1_format) in [
                ("descriptor", "Eip0045B4ValidatorBuildDescriptorV1"),
                ("runner", "Eip0045B4PositiveOciRunnerProfileV1"),
            ] {
                let mut mixed = valid.clone();
                let identity = if target == "descriptor" {
                    &mut mixed.acceptance_value["implementationBinding"]["buildDescriptor"]
                } else {
                    &mut mixed.acceptance_value["implementationBinding"]["executionRunnerProfile"]["artifact"]
                };
                identity["format"] = json!(v1_format);
                mixed.refresh_acceptance_source();
                assert_acceptance_rejects(&mixed, "V2 acceptance");
            }

            for field_name in ["implementationIndex", "implementation", "language"] {
                let mut drift = valid.clone();
                drift.acceptance_value["implementationBinding"][field_name] = match field_name {
                    "implementationIndex" => json!(1 - implementation.index()),
                    "implementation" => {
                        json!(if implementation == PositiveImplementation::RustReference {
                            "independent-jvm"
                        } else {
                            "rust-reference"
                        })
                    }
                    "language" => {
                        json!(if implementation == PositiveImplementation::RustReference {
                            "scala"
                        } else {
                            "rust"
                        })
                    }
                    _ => unreachable!(),
                };
                drift.refresh_acceptance_source();
                assert_acceptance_rejects(&drift, "V2 acceptance");
            }
            for field_name in ["runnerProfileIndex", "purpose"] {
                let mut drift = valid.clone();
                drift.acceptance_value["implementationBinding"]["executionRunnerProfile"]
                    [field_name] = if field_name == "runnerProfileIndex" {
                    json!(if implementation == PositiveImplementation::RustReference {
                        3
                    } else {
                        2
                    })
                } else {
                    json!(if implementation == PositiveImplementation::RustReference {
                        "jvm-validator"
                    } else {
                        "rust-validator"
                    })
                };
                drift.refresh_acceptance_source();
                assert_acceptance_rejects(&drift, "V2 acceptance");
            }

            let other_implementation = if implementation == PositiveImplementation::RustReference {
                PositiveImplementation::IndependentJvm
            } else {
                PositiveImplementation::RustReference
            };
            let mut other_branch_source = v2_acceptance_fixture(
                &input,
                &generation_bytes,
                &generation_cases,
                &base.verifier_files,
                0,
                other_implementation,
            );
            other_branch_source.implementation = implementation;
            assert_acceptance_rejects(&other_branch_source, "implementationIndex differs from");
            let mut other_descriptor = valid.clone();
            other_descriptor.acceptance_value["implementationBinding"]["buildDescriptor"] =
                jcs_commitment(
                    "Eip0045B4ValidatorBuildDescriptorV2",
                    &input.descriptor_bytes[other_implementation.index()],
                );
            other_descriptor.refresh_acceptance_source();
            assert_acceptance_rejects(&other_descriptor, "V2 acceptance descriptor commitment");
            let mut other_runner = valid.clone();
            other_runner.acceptance_value["implementationBinding"]["executionRunnerProfile"]["artifact"] =
                jcs_commitment(
                    "Eip0045B4PositiveOciRunnerProfileV2",
                    &input.runner_bytes[other_implementation.execution_role().index()],
                );
            other_runner.refresh_acceptance_source();
            assert_acceptance_rejects(&other_runner, "V2 acceptance execution-runner commitment");

            let mut stale_verifier_input = valid.clone();
            stale_verifier_input.verifier_input_value["rawSeal"]["sha256"] = json!(digest(0xfd));
            stale_verifier_input.verifier_input_bytes =
                canonical_json_bytes(&stale_verifier_input.verifier_input_value).unwrap();
            assert_acceptance_rejects(
                &stale_verifier_input,
                "V2 acceptance verifier-input commitment",
            );
            let mut stale_observation = valid.clone();
            stale_observation.observation_value["claimDigest"] = json!(digest(0xfc));
            stale_observation.observation_bytes =
                canonical_json_bytes(&stale_observation.observation_value).unwrap();
            assert_acceptance_rejects(&stale_observation, "V2 acceptance observation commitment");
            let mut different_embedded_observation = valid.clone();
            different_embedded_observation.acceptance_value["observation"]["claimDigest"] =
                json!(digest(0xfb));
            different_embedded_observation.refresh_acceptance_source();
            assert_acceptance_rejects(
                &different_embedded_observation,
                "embeds a different observation",
            );

            let mut lineage = valid.clone();
            lineage.acceptance_value["implementationBinding"]["lineageSha256"] =
                json!(digest(0xfa));
            lineage.refresh_acceptance_source();
            assert_acceptance_rejects(&lineage, "lineage binding");
            let mut reviewed_source = valid.clone();
            reviewed_source.acceptance_value["implementationBinding"]["reviewedSource"]["tree"] =
                json!("f".repeat(40));
            reviewed_source.refresh_acceptance_source();
            assert_acceptance_rejects(&reviewed_source, "reviewed-source binding");
            let mut global_order = valid.clone();
            global_order.acceptance_value["implementationBinding"]["lineageSha256"] =
                json!(digest(0xf7));
            global_order.verifier_files.guest_elf[0] ^= 1;
            global_order.verifier_input_value["guestElf"] =
                file_identity_from_bytes("guest.elf", &global_order.verifier_files.guest_elf);
            global_order.verifier_input_bytes =
                canonical_json_bytes(&global_order.verifier_input_value).unwrap();
            global_order.acceptance_value["verifierInputCommitment"] = jcs_commitment(
                "Eip0045B4PositiveVerifierInputV1",
                &global_order.verifier_input_bytes,
            );
            global_order.refresh_acceptance_source();
            assert_acceptance_rejects(
                &global_order,
                "guest ELF sha256 differs from the pre-proof input set",
            );
            let mut launched_binding = valid.clone();
            launched_binding.acceptance_value["implementationBinding"]["launchedArtifact"]["sha256"] =
                json!(digest(0xf9));
            launched_binding.refresh_acceptance_source();
            assert_acceptance_rejects(&launched_binding, "launched-artifact binding");
            let mut launched_physical = valid.clone();
            launched_physical.launched_artifact.sha256[0] ^= 1;
            assert_acceptance_rejects(&launched_physical, "V2 launched artifact digest");
            let mut statement_physical = valid.clone();
            statement_physical.verifier_files.statement[0] ^= 1;
            assert_acceptance_rejects(&statement_physical, "statement digest");
            let mut raw_seal_physical = valid.clone();
            raw_seal_physical.verifier_files.raw_seal[0] ^= 1;
            assert_acceptance_rejects(&raw_seal_physical, "raw seal digest");

            if implementation == PositiveImplementation::IndependentJvm {
                let mut java_binding = valid.clone();
                java_binding.acceptance_value["implementationBinding"]["javaRuntime"]["binary"]["sha256"] =
                    json!(digest(0xf8));
                java_binding.refresh_acceptance_source();
                assert_acceptance_rejects(&java_binding, "Java runtime binding");
                let mut java_physical = valid.clone();
                java_physical.java_binary.as_mut().unwrap().sha256[0] ^= 1;
                assert_acceptance_rejects(&java_physical, "V2 Java binary digest");
                let mut release_physical = valid.clone();
                release_physical.java_release.as_mut().unwrap().sha256[0] ^= 1;
                assert_acceptance_rejects(&release_physical, "V2 Java release digest");
            }

            let mut noncanonical_acceptance = valid.clone();
            noncanonical_acceptance.acceptance_bytes.push(b' ');
            assert_acceptance_rejects(&noncanonical_acceptance, "canonical");
            let mut noncanonical_input = valid.clone();
            noncanonical_input.verifier_input_bytes.push(b' ');
            assert_acceptance_rejects(&noncanonical_input, "canonical");
            let mut noncanonical_observation = valid.clone();
            noncanonical_observation.observation_bytes.push(b' ');
            assert_acceptance_rejects(&noncanonical_observation, "canonical");

            let mut malformed_input = valid.clone();
            malformed_input.verifier_input_value["unexpected"] = json!(true);
            malformed_input.verifier_input_bytes =
                canonical_json_bytes(&malformed_input.verifier_input_value).unwrap();
            malformed_input.acceptance_value["verifierInputCommitment"] = jcs_commitment(
                "Eip0045B4PositiveVerifierInputV1",
                &malformed_input.verifier_input_bytes,
            );
            malformed_input.refresh_acceptance_source();
            assert_acceptance_rejects(&malformed_input, "V2 verifier input");
            let mut malformed_observation = valid.clone();
            malformed_observation
                .observation_value
                .as_object_mut()
                .unwrap()
                .remove("claimDigest");
            malformed_observation.observation_bytes =
                canonical_json_bytes(&malformed_observation.observation_value).unwrap();
            malformed_observation.acceptance_value["observationCommitment"] = jcs_commitment(
                "Eip0045B4PositiveObservationV1",
                &malformed_observation.observation_bytes,
            );
            malformed_observation.refresh_acceptance_source();
            assert_acceptance_rejects(&malformed_observation, "V2 observation");
        }

        assert!(!std::ptr::eq(
            &raw const GENERATION_SET_VALIDATOR,
            &raw const GENERATION_SET_V2_VALIDATOR,
        ));
        assert!(!std::ptr::eq(
            &raw const ACCEPTANCE_VALIDATOR,
            &raw const ACCEPTANCE_V2_VALIDATOR,
        ));
        let v1 = base.materialize();
        let validate_v1_acceptance = || {
            let bindings = v1.bind_generation().unwrap();
            let verifier_input_value = verifier_input(&v1);
            let verifier_input_bytes = canonical_json_bytes(&verifier_input_value).unwrap();
            let (observation_value, observation_bytes) = observation(&v1);
            let acceptance_bytes = canonical_json_bytes(&rust_acceptance(
                &v1,
                &bindings,
                &verifier_input_bytes,
                &observation_value,
                &observation_bytes,
            ))
            .unwrap();
            bindings
                .validate_run(rust_run_documents(
                    &v1,
                    &bindings,
                    &verifier_input_bytes,
                    &observation_bytes,
                    &acceptance_bytes,
                ))
                .unwrap();
        };
        validate_v1_acceptance();
        validate_v2_fixture(
            &input,
            GENERATION_SET_PATH,
            &generation_bytes,
            &generation_cases,
            &base.proof_generator_artifact,
            &valid_rust,
        )
        .unwrap();
        validate_v1_acceptance();
    }

    #[test]
    fn v1_schema_bytes_remain_frozen() {
        assert_eq!(RUNNER_PROFILE_SCHEMA.len(), 32_905);
        assert_eq!(
            sha256_hex(RUNNER_PROFILE_SCHEMA.as_bytes()),
            "6a71fc144228eb04294b760973b1a8c8567654365a54cc24c8b92f8bbe1e77a2"
        );
        assert_eq!(INPUT_SET_SCHEMA.len(), 27_278);
        assert_eq!(
            sha256_hex(INPUT_SET_SCHEMA.as_bytes()),
            "eff6f23285ecd3b7969164fc04a26207f2f67768ad0d943bcdae96394b32ed1e"
        );
        assert_eq!(VALIDATOR_DESCRIPTOR_SCHEMA.len(), 33_953);
        assert_eq!(
            sha256_hex(VALIDATOR_DESCRIPTOR_SCHEMA.as_bytes()),
            "64c7e1f6a80ae16346497d58d102fb5ede52fba93973610f849c41980a6ef2a7"
        );
        assert_eq!(GENERATION_SET_SCHEMA.len(), 13_605);
        assert_eq!(
            sha256_hex(GENERATION_SET_SCHEMA.as_bytes()),
            "4391c589ce64908b47244c987bacf466b66294b95617e3b29ee3f8bd9489472e"
        );
        assert_eq!(ACCEPTANCE_SCHEMA.len(), 14_209);
        assert_eq!(
            sha256_hex(ACCEPTANCE_SCHEMA.as_bytes()),
            "eae3fbaa0c1e1f9bf11af2cd3a124652bff5bd5f518b080be5255fa3eca94aca"
        );
    }

    #[test]
    fn v2_generation_and_acceptance_schemas_are_exact_v1_deltas() {
        let expected_generation = GENERATION_SET_SCHEMA
            .replacen(
                "b4-positive-generation-set-v1",
                "b4-positive-generation-set-v2",
                1,
            )
            .replacen(
                "Eip0045B4PositiveGenerationSetV1",
                "Eip0045B4PositiveGenerationSetV2",
                2,
            )
            .replacen(
                "\"formatVersion\": {\"const\": 1}",
                "\"formatVersion\": {\"const\": 2}",
                1,
            )
            .replacen(
                "Eip0045B4PositiveInputSetV1",
                "Eip0045B4PositiveInputSetV2",
                1,
            );
        assert_eq!(GENERATION_SET_V2_SCHEMA, expected_generation);
        assert_eq!(GENERATION_SET_V2_SCHEMA.len(), 13_605);
        assert_eq!(
            sha256_hex(GENERATION_SET_V2_SCHEMA.as_bytes()),
            "bbeb6cbec59024b07a572ac3aed2a7124dabbdb5386b0580a184e6ed85f76e78"
        );

        let expected_acceptance = ACCEPTANCE_SCHEMA
            .replacen("b4-positive-acceptance-v1", "b4-positive-acceptance-v2", 1)
            .replacen(
                "Eip0045B4PositiveAcceptanceV1",
                "Eip0045B4PositiveAcceptanceV2",
                2,
            )
            .replacen("\"const\": 1", "\"const\": 2", 1)
            .replacen(
                "Eip0045B4PositiveInputSetV1",
                "Eip0045B4PositiveInputSetV2",
                1,
            )
            .replacen(
                "Eip0045B4PositiveGenerationSetV1",
                "Eip0045B4PositiveGenerationSetV2",
                1,
            )
            .replacen(
                "Eip0045B4ValidatorBuildDescriptorV1",
                "Eip0045B4ValidatorBuildDescriptorV2",
                1,
            )
            .replacen(
                "Eip0045B4PositiveOciRunnerProfileV1",
                "Eip0045B4PositiveOciRunnerProfileV2",
                1,
            );
        assert_eq!(ACCEPTANCE_V2_SCHEMA, expected_acceptance);
        assert_eq!(ACCEPTANCE_V2_SCHEMA.len(), 14_209);
        assert_eq!(
            sha256_hex(ACCEPTANCE_V2_SCHEMA.as_bytes()),
            "ad50f862bd24f54b1c76c2a0d697d7b863d15e04ddfa57871b4899f2997e638b"
        );
    }

    #[test]
    fn embedded_schema_draft_ids_and_references_are_closed() {
        let schemas = [
            (
                INPUT_SET_SCHEMA,
                "urn:ergo:eip-0045:b4-positive-input-set-v1",
            ),
            (
                INPUT_SET_V2_SCHEMA,
                "urn:ergo:eip-0045:b4-positive-input-set-v2",
            ),
            (
                GENERATION_SET_SCHEMA,
                "urn:ergo:eip-0045:b4-positive-generation-set-v1",
            ),
            (
                GENERATION_SET_V2_SCHEMA,
                "urn:ergo:eip-0045:b4-positive-generation-set-v2",
            ),
            (
                VALIDATOR_DESCRIPTOR_SCHEMA,
                "urn:ergo:eip-0045:b4-validator-build-descriptor-v1",
            ),
            (
                VALIDATOR_DESCRIPTOR_V2_SCHEMA,
                "urn:ergo:eip-0045:b4-validator-build-descriptor-v2",
            ),
            (
                JVM_COPY_ONLY_INCLUSION_MANIFEST_SCHEMA,
                "urn:ergo:eip-0045:b4-jvm-copy-only-inclusion-manifest-v1",
            ),
            (
                RUNNER_PROFILE_SCHEMA,
                "urn:ergo:eip-0045:b4-positive-oci-runner-profile-v1",
            ),
            (
                RUNNER_PROFILE_V2_SCHEMA,
                "urn:ergo:eip-0045:b4-positive-oci-runner-profile-v2",
            ),
            (SECCOMP_SCHEMA, "urn:ergo:eip-0045:b4-positive-seccomp-v1"),
            (
                VERIFIER_INPUT_SCHEMA,
                "urn:ergo:eip-0045:b4-positive-verifier-input-v1",
            ),
            (
                OBSERVATION_SCHEMA,
                "urn:ergo:eip-0045:b4-positive-observation-v1",
            ),
            (
                ACCEPTANCE_SCHEMA,
                "urn:ergo:eip-0045:b4-positive-acceptance-v1",
            ),
            (
                ACCEPTANCE_V2_SCHEMA,
                "urn:ergo:eip-0045:b4-positive-acceptance-v2",
            ),
        ];
        let mut ids = BTreeSet::new();
        for (source, expected_id) in schemas {
            let schema = parse_json_strict(source.as_bytes()).unwrap();
            assert_eq!(
                schema["$schema"],
                "https://json-schema.org/draft/2020-12/schema"
            );
            assert_eq!(schema["$id"], expected_id);
            assert!(ids.insert(expected_id));
            assert_schema_references_are_internal(&schema);
        }
        assert_eq!(ids.len(), 14);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn schema_authority_and_role_contracts_remain_aligned() {
        let verifier = parse_json_strict(VERIFIER_INPUT_SCHEMA.as_bytes()).unwrap();
        let acceptance = parse_json_strict(ACCEPTANCE_SCHEMA.as_bytes()).unwrap();
        let input_set = parse_json_strict(INPUT_SET_SCHEMA.as_bytes()).unwrap();
        let generation_set = parse_json_strict(GENERATION_SET_SCHEMA.as_bytes()).unwrap();
        let descriptor = parse_json_strict(VALIDATOR_DESCRIPTOR_SCHEMA.as_bytes()).unwrap();
        let runner = parse_json_strict(RUNNER_PROFILE_SCHEMA.as_bytes()).unwrap();
        let seccomp = parse_json_strict(SECCOMP_SCHEMA.as_bytes()).unwrap();

        let verifier_required = verifier["required"].as_array().unwrap();
        assert_eq!(verifier_required.len(), 8);
        assert!(
            !verifier_required
                .iter()
                .any(|value| value == "inputSetCommitment")
        );
        assert!(verifier["properties"].get("inputSetCommitment").is_none());
        assert!(
            acceptance["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "inputSetCommitment")
        );
        assert!(
            acceptance["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "generationSetCommitment")
        );
        assert_eq!(
            generation_set["properties"]["cases"]["minItems"],
            POSITIVE_CASE_COUNT
        );
        assert_eq!(
            generation_set["properties"]["cases"]["maxItems"],
            POSITIVE_CASE_COUNT
        );
        for forbidden in ["image", "runtime", "seccomp", "limits", "javaRuntime"] {
            assert!(!schema_declares_property(&descriptor, forbidden));
        }
        assert!(descriptor["properties"].get("policy").is_none());
        let runner_options = runner["$defs"]["JavaRuntime"]["properties"]["options"]["prefixItems"]
            .as_array()
            .unwrap();
        let acceptance_options =
            acceptance["$defs"]["JavaRuntime"]["properties"]["options"]["prefixItems"]
                .as_array()
                .unwrap();
        assert_eq!(runner_options, acceptance_options);
        assert_eq!(runner_options.len(), 9);
        assert_eq!(
            runner["$defs"]["SeccompIdentity"]["properties"]["profile"]["$ref"],
            "#/$defs/SeccompDocumentIdentity"
        );
        assert_eq!(
            runner["$defs"]["SeccompDocumentIdentity"]["properties"]["format"]["const"],
            "Eip0045B4PositiveSeccompV1"
        );
        assert_eq!(
            seccomp["properties"]["linuxSeccomp"]["$ref"],
            "#/$defs/LinuxSeccomp"
        );
        assert_eq!(
            descriptor["$defs"]["JvmClassFileInspection"]["properties"]["runtimeFeatureVersion"]["const"],
            21
        );
        for definition in ["NativeEntrypoint", "JvmEntrypoint"] {
            assert_eq!(
                descriptor["$defs"][definition]["properties"]["interface"]["const"],
                "eip0045-b4-verifier-cli-v2"
            );
            assert_eq!(
                descriptor["$defs"][definition]["properties"]["subcommand"]["const"],
                "verify-positive"
            );
        }
        assert_eq!(
            runner["allOf"][0]["oneOf"][2]["properties"]["purpose"]["const"],
            "rust-validator"
        );
        assert_eq!(
            runner["allOf"][0]["oneOf"][3]["properties"]["purpose"]["const"],
            "jvm-validator"
        );
        for obsolete in [
            "selfContained",
            "nativeLibraryEntries",
            "nativeInterfaceReferences",
            "processLaunchReferences",
            "maximumEntryCompressionRatio",
        ] {
            assert!(!schema_declares_property(&descriptor, obsolete));
        }

        let mappings = [
            (
                PositiveRunnerRole::RustValidatorBuild,
                "RustValidatorBuildRunnerProfile",
                "RustBuildRunnerProfile",
                None,
            ),
            (
                PositiveRunnerRole::JvmValidatorBuild,
                "JvmValidatorBuildRunnerProfile",
                "JvmBuildRunnerProfile",
                None,
            ),
            (
                PositiveRunnerRole::RustVerifier,
                "RustPositiveVerifierRunnerProfile",
                "RustExecutionRunnerProfile",
                Some("RustPositiveVerifierRunnerProfileBinding"),
            ),
            (
                PositiveRunnerRole::JvmVerifier,
                "JvmPositiveVerifierRunnerProfile",
                "JvmExecutionRunnerProfile",
                Some("JvmPositiveVerifierRunnerProfileBinding"),
            ),
        ];
        for (role, input_definition, descriptor_definition, acceptance_definition) in mappings {
            let runner_properties = &runner["allOf"][0]["oneOf"][role.index()]["properties"];
            assert_eq!(
                runner_properties["runnerProfileIndex"]["const"],
                role.index()
            );
            assert_eq!(runner_properties["purpose"]["const"], role.purpose());
            for properties in [
                &input_set["$defs"][input_definition]["properties"],
                &descriptor["$defs"][descriptor_definition]["properties"],
            ] {
                assert_eq!(properties["runnerProfileIndex"]["const"], role.index());
                assert_eq!(properties["purpose"]["const"], role.purpose());
            }
            if let Some(definition) = acceptance_definition {
                let properties = &acceptance["$defs"][definition]["properties"];
                assert_eq!(properties["runnerProfileIndex"]["const"], role.index());
                assert_eq!(properties["purpose"]["const"], role.purpose());
            }
        }
    }

    #[test]
    fn policy_schemas_bind_closed_elf_jar_and_java_measurements() {
        let descriptor = parse_json_strict(VALIDATOR_DESCRIPTOR_SCHEMA.as_bytes()).unwrap();
        let inclusion =
            parse_json_strict(JVM_COPY_ONLY_INCLUSION_MANIFEST_SCHEMA.as_bytes()).unwrap();
        let runner = parse_json_strict(RUNNER_PROFILE_SCHEMA.as_bytes()).unwrap();
        let acceptance = parse_json_strict(ACCEPTANCE_SCHEMA.as_bytes()).unwrap();

        assert_eq!(
            descriptor["$defs"]["NativeArtifactIdentity"]["properties"]["inspectionPolicy"]["const"],
            "eip0045-b4-elf64-amd64-static-v1"
        );
        assert_eq!(
            descriptor["$defs"]["NativeArtifactIdentity"]["properties"]["elf"]["$ref"],
            "#/$defs/StaticElfInspection"
        );
        assert_eq!(
            descriptor["$defs"]["StaticElfInspection"],
            runner["$defs"]["StaticElfInspection"]
        );
        assert_eq!(
            descriptor["$defs"]["JvmJarArchiveInspection"]["properties"]["entryCount"]["maximum"],
            65_534
        );
        assert_eq!(
            descriptor["$defs"]["JvmJarManifestInspection"]["properties"]["manifestByteLength"]["maximum"],
            65_536
        );
        assert_eq!(
            descriptor["$defs"]["JvmCopyOnlyPackaging"]["properties"]["mode"]["const"],
            "copy-only-inclusion-manifest"
        );
        assert_eq!(inclusion["properties"]["inputs"]["minItems"], 1);
        assert_eq!(inclusion["properties"]["entries"]["maxItems"], 4096);
        let archive_length =
            &runner["$defs"]["OciImageArchiveIdentity"]["properties"]["byteLength"];
        assert_eq!(archive_length["minimum"], 6_144);
        assert_eq!(archive_length["multipleOf"], USTAR_BLOCK_BYTES);
        assert_eq!(
            inclusion["properties"]["inputArchivePolicy"]["const"],
            "eip0045-b4-jar-source-read-v1"
        );
        assert_eq!(
            descriptor["$defs"]["BuildStep"]["properties"]["workingDirectory"]["const"],
            "/src"
        );
        let packager_arguments =
            &descriptor["$defs"]["JvmCopyOnlyPackagingStep"]["properties"]["arguments"];
        assert_eq!(packager_arguments["minItems"], 7);
        assert_eq!(packager_arguments["maxItems"], 7);
        assert_eq!(
            packager_arguments["prefixItems"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item["const"].as_str().unwrap())
                .collect::<Vec<_>>(),
            JVM_COPY_ONLY_PACKAGER_ARGUMENTS
        );
        assert_eq!(
            runner["$defs"]["JvmPackagingPhaseInputMount"]["properties"]["target"]["const"],
            "/phase-input"
        );
        assert!(
            runner["allOf"][0]["oneOf"][1]["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "buildJdk")
        );
        assert_eq!(
            runner["$defs"]["BuildJdk"]["properties"]["featureVersion"]["const"],
            21
        );
        for field_name in ["release", "featureVersion"] {
            assert!(
                acceptance["$defs"]["JavaRuntime"]["required"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|value| value == field_name)
            );
        }
        assert_eq!(
            acceptance["$defs"]["JavaRuntime"]["properties"]["featureVersion"]["const"],
            21
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn all_nine_embedded_schemas_accept_and_reject_closed_shape_drifts() {
        let materialized = Fixture::valid().materialize();
        let bindings = materialized.bind_generation().unwrap();
        let verifier_input_value = verifier_input(&materialized);
        let verifier_input_bytes = canonical_json_bytes(&verifier_input_value).unwrap();
        let (observation_value, observation_bytes) = observation(&materialized);
        let acceptance_value = rust_acceptance(
            &materialized,
            &bindings,
            &verifier_input_bytes,
            &observation_value,
            &observation_bytes,
        );

        validate_json_schema(
            &materialized.input_value,
            EmbeddedSchema::InputSet,
            "test input set",
        )
        .unwrap();
        validate_json_schema(
            &materialized.generation_value,
            EmbeddedSchema::GenerationSet,
            "test generation set",
        )
        .unwrap();
        for descriptor in &materialized.descriptor_values {
            validate_json_schema(
                descriptor,
                EmbeddedSchema::ValidatorDescriptor,
                "test descriptor",
            )
            .unwrap();
        }
        validate_json_schema(
            &materialized.jvm_copy_only_inclusion_manifest_value,
            EmbeddedSchema::JvmCopyOnlyInclusionManifest,
            "test JVM COPY-ONLY inclusion manifest",
        )
        .unwrap();
        for runner in &materialized.runner_values {
            validate_json_schema(runner, EmbeddedSchema::RunnerProfile, "test runner profile")
                .unwrap();
        }
        for seccomp in &Fixture::valid().seccomp_values {
            validate_json_schema(seccomp, EmbeddedSchema::Seccomp, "test seccomp").unwrap();
        }
        validate_json_schema(
            &verifier_input_value,
            EmbeddedSchema::VerifierInput,
            "test verifier input",
        )
        .unwrap();
        validate_json_schema(
            &observation_value,
            EmbeddedSchema::Observation,
            "test observation",
        )
        .unwrap();
        validate_json_schema(
            &acceptance_value,
            EmbeddedSchema::Acceptance,
            "test acceptance",
        )
        .unwrap();

        let mut input_missing_required = materialized.input_value.clone();
        input_missing_required
            .as_object_mut()
            .unwrap()
            .remove("proofGenerator");
        assert!(
            validate_json_schema(
                &input_missing_required,
                EmbeddedSchema::InputSet,
                "test input set",
            )
            .is_err()
        );

        let mut input_hidden_path_component = materialized.input_value.clone();
        input_hidden_path_component["verifierCliContract"]["path"] =
            json!("preproof/.verifier-contract.json");
        assert!(
            validate_json_schema(
                &input_hidden_path_component,
                EmbeddedSchema::InputSet,
                "test input set",
            )
            .is_err()
        );

        let mut generation_wrong_const = materialized.generation_value.clone();
        generation_wrong_const["cases"][0]["caseId"] = json!("lift-po2-16");
        assert!(
            validate_json_schema(
                &generation_wrong_const,
                EmbeddedSchema::GenerationSet,
                "test generation set",
            )
            .is_err()
        );

        let mut descriptor_wrong_branch = materialized.descriptor_values[1].clone();
        descriptor_wrong_branch["entrypoint"]["kind"] = json!("direct-native");
        assert!(
            validate_json_schema(
                &descriptor_wrong_branch,
                EmbeddedSchema::ValidatorDescriptor,
                "test descriptor",
            )
            .is_err()
        );

        let mut inclusion_unknown_field =
            materialized.jvm_copy_only_inclusion_manifest_value.clone();
        inclusion_unknown_field["unexpected"] = json!(true);
        assert!(
            validate_json_schema(
                &inclusion_unknown_field,
                EmbeddedSchema::JvmCopyOnlyInclusionManifest,
                "test JVM COPY-ONLY inclusion manifest",
            )
            .is_err()
        );

        let mut runner_additional_property = materialized.runner_values[0].clone();
        runner_additional_property["unexpected"] = json!(true);
        assert!(
            validate_json_schema(
                &runner_additional_property,
                EmbeddedSchema::RunnerProfile,
                "test runner profile",
            )
            .is_err()
        );

        let mut seccomp_missing_required = Fixture::valid().seccomp_values[0].clone();
        seccomp_missing_required
            .as_object_mut()
            .unwrap()
            .remove("linuxSeccomp");
        assert!(
            validate_json_schema(
                &seccomp_missing_required,
                EmbeddedSchema::Seccomp,
                "test seccomp",
            )
            .is_err()
        );

        let mut verifier_input_additional_property = verifier_input_value.clone();
        verifier_input_additional_property["caseId"] = json!("lift-po2-15");
        assert!(
            validate_json_schema(
                &verifier_input_additional_property,
                EmbeddedSchema::VerifierInput,
                "test verifier input",
            )
            .is_err()
        );

        let mut observation_missing_required = observation_value.clone();
        observation_missing_required
            .as_object_mut()
            .unwrap()
            .remove("claimDigest");
        assert!(
            validate_json_schema(
                &observation_missing_required,
                EmbeddedSchema::Observation,
                "test observation",
            )
            .is_err()
        );

        let mut acceptance_wrong_branch = acceptance_value;
        acceptance_wrong_branch["implementationBinding"]["language"] = json!("scala");
        assert!(
            validate_json_schema(
                &acceptance_wrong_branch,
                EmbeddedSchema::Acceptance,
                "test acceptance",
            )
            .is_err()
        );
    }

    fn schema_declares_property(schema: &Value, property: &str) -> bool {
        match schema {
            Value::Object(object) => {
                if object
                    .get("properties")
                    .and_then(Value::as_object)
                    .is_some_and(|properties| properties.contains_key(property))
                {
                    return true;
                }
                object
                    .values()
                    .any(|value| schema_declares_property(value, property))
            }
            Value::Array(values) => values
                .iter()
                .any(|value| schema_declares_property(value, property)),
            _ => false,
        }
    }

    fn assert_schema_references_are_internal(schema: &Value) {
        match schema {
            Value::Object(object) => {
                assert!(!object.contains_key("$dynamicRef"));
                if let Some(reference) = object.get("$ref") {
                    assert!(
                        reference
                            .as_str()
                            .is_some_and(|value| value.starts_with('#'))
                    );
                }
                for value in object.values() {
                    assert_schema_references_are_internal(value);
                }
            }
            Value::Array(values) => {
                for value in values {
                    assert_schema_references_are_internal(value);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn canonical_provenance_bindings_accept_and_isolated_drifts_reject() {
        Fixture::valid().materialize().bind().unwrap();

        let mut output_drift = Fixture::valid();
        output_drift.descriptor_values[0]["deterministicBuild"]["outputPath"] =
            json!("artifacts/other");
        assert!(
            format!("{:#}", output_drift.materialize().bind().unwrap_err()).contains("output path")
        );

        let mut environment_drift = Fixture::valid();
        environment_drift.descriptor_values[0]["deterministicBuild"]["environment"]["variables"] = json!([
            {"name": "FOO", "value": "1"},
            {"name": "FOO", "value": "2"}
        ]);
        assert!(
            format!("{:#}", environment_drift.materialize().bind().unwrap_err())
                .contains("fails Draft 2020-12 schema")
        );

        let mut generator_artifact_drift = Fixture::valid();
        generator_artifact_drift.input_value["proofGenerator"]["qualifyingBuild"]["generatorArtifact"]
            ["sha256"] = json!(digest(0xf1));
        assert!(
            format!(
                "{:#}",
                generator_artifact_drift.materialize().bind().unwrap_err()
            )
            .contains("qualifying build generator artifact")
        );

        let mut generator_source_lock_drift = Fixture::valid();
        generator_source_lock_drift.input_value["proofGenerator"]["qualifyingBuild"]["sourceLockSha256"] =
            json!(digest(0xf2));
        assert!(
            format!(
                "{:#}",
                generator_source_lock_drift
                    .materialize()
                    .bind()
                    .unwrap_err()
            )
            .contains("qualifying build source-lock digest")
        );

        let mut non_alias_drift = Fixture::valid();
        non_alias_drift.descriptor_values[1]["artifact"]["sha256"] =
            non_alias_drift.descriptor_values[0]["artifact"]["sha256"].clone();
        non_alias_drift.jvm_copy_only_inclusion_manifest_value["output"]["sha256"] =
            non_alias_drift.descriptor_values[0]["artifact"]["sha256"].clone();
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut non_alias_drift);
        assert!(
            format!("{:#}", non_alias_drift.materialize().bind().unwrap_err())
                .contains("artifact digest")
        );

        let mut seccomp_drift = Fixture::valid();
        seccomp_drift.runner_values[0]["seccomp"]["allowedSyscalls"] = json!(["write", "read"]);
        assert!(
            format!("{:#}", seccomp_drift.materialize().bind().unwrap_err())
                .contains("seccomp syscall projection")
        );

        let mut seccomp_document_drift = Fixture::valid();
        seccomp_document_drift.seccomp_values[0]["linuxSeccomp"]["syscalls"][0]["names"] =
            json!(["write", "read"]);
        assert!(
            format!(
                "{:#}",
                seccomp_document_drift.materialize().bind().unwrap_err()
            )
            .contains("strictly increasing")
        );

        let stale_fixture = Fixture::valid();
        let mut stale = stale_fixture.materialize();
        let mut changed = stale.runner_values[0].clone();
        changed["extraInspectionMarker"] = json!(true);
        stale.runner_bytes[0] = canonical_json_bytes(&changed).unwrap();
        assert!(
            format!("{:#}", stale.bind().unwrap_err())
                .contains("rust-validator-build fails Draft 2020-12 schema")
        );
    }

    #[test]
    fn proof_generator_fixed_policy_fields_reject_isolated_drifts() {
        let mutations: [(&[&str], Value); 13] = [
            (
                &["proofGenerator", "qualifyingBuild", "policy"],
                json!("other"),
            ),
            (
                &["proofGenerator", "qualifyingBuild", "validationMode"],
                json!("unanchored-inspection"),
            ),
            (
                &["proofGenerator", "qualifyingBuild", "filesystemBinding"],
                json!("unavailable"),
            ),
            (
                &["proofGenerator", "executionPolicy", "policy"],
                json!("other"),
            ),
            (
                &["proofGenerator", "executionPolicy", "caseOrder"],
                json!("caller-order"),
            ),
            (
                &["proofGenerator", "executionPolicy", "generatorProcessReuse"],
                json!(true),
            ),
            (
                &["proofGenerator", "executionPolicy", "replayProcessReuse"],
                json!(true),
            ),
            (
                &["proofGenerator", "executionPolicy", "network"],
                json!("enabled"),
            ),
            (
                &[
                    "proofGenerator",
                    "executionPolicy",
                    "environmentInheritance",
                ],
                json!("ambient"),
            ),
            (
                &["proofGenerator", "executionPolicy", "inputSetMount"],
                json!("read-write"),
            ),
            (
                &["proofGenerator", "executionPolicy", "caseOutput"],
                json!("reused"),
            ),
            (
                &["proofGenerator", "executionPolicy", "replayExportMount"],
                json!("read-write"),
            ),
            (
                &["proofGenerator", "executionPolicy", "failurePublication"],
                json!("partial"),
            ),
        ];
        for (path, replacement) in mutations {
            let mut fixture = Fixture::valid();
            set_path(&mut fixture.input_value, path, replacement);
            let error = fixture.materialize().bind().unwrap_err();
            assert!(
                format!("{error:#}").contains("positive input set fails Draft 2020-12 schema"),
                "generator policy field {path:?} rejected at an unexpected boundary: {error:#}"
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn authoritative_build_projection_rejects_each_isolated_anchor_drift() {
        let mutations: [(&str, &[&str], Value); 14] = [
            (
                "evidence root",
                &["proofGenerator", "qualifyingBuild", "evidenceRootSha256"],
                json!(digest(0xb1)),
            ),
            (
                "source commit",
                &["proofGenerator", "qualifyingBuild", "sourceCommit"],
                json!("ef".repeat(20)),
            ),
            (
                "source tree",
                &["proofGenerator", "qualifyingBuild", "sourceTree"],
                json!("fe".repeat(20)),
            ),
            (
                "generator Cargo closure",
                &[
                    "proofGenerator",
                    "qualifyingBuild",
                    "generatorCargoClosureSha256",
                ],
                json!(digest(0xb2)),
            ),
            (
                "proof-generation tests",
                &[
                    "proofGenerator",
                    "qualifyingBuild",
                    "proofGenerationTestsSha256",
                ],
                json!(digest(0xb3)),
            ),
            (
                "guest ELF digest",
                &["guest", "elf", "sha256"],
                json!(digest(0xb4)),
            ),
            (
                "guest ELF length",
                &["guest", "elf", "byteLength"],
                json!(1),
            ),
            ("image ID", &["guest", "imageId"], json!(digest(0xb5))),
            (
                "statement digest",
                &["referenceStatement", "statementSha256"],
                json!(digest(0xb6)),
            ),
            (
                "statement length",
                &["referenceStatement", "statementByteLength"],
                json!(160),
            ),
            (
                "contract ID",
                &["referenceStatement", "contractId"],
                json!(digest(0xb7)),
            ),
            (
                "chain-domain ID",
                &["referenceStatement", "chainDomainId"],
                json!(digest(0xb8)),
            ),
            (
                "application-payload digest",
                &["referenceStatement", "applicationPayloadSha256"],
                json!(digest(0xb9)),
            ),
            (
                "application-payload length",
                &["referenceStatement", "applicationPayloadByteLength"],
                json!(1),
            ),
        ];
        for (label, path, replacement) in mutations {
            let mut fixture = Fixture::valid();
            set_path(&mut fixture.input_value, path, replacement);
            let error = fixture.materialize().bind().unwrap_err();
            assert!(
                format!("{error:#}").contains("authoritative B4 validation"),
                "{label} rejected at an unexpected boundary: {error:#}"
            );
        }

        let mut source_lock = Fixture::valid();
        source_lock.input_value["sourceLock"]["sha256"] = json!(digest(0xba));
        source_lock.input_value["proofGenerator"]["qualifyingBuild"]["sourceLockSha256"] =
            json!(digest(0xba));
        let error = source_lock.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("authoritative B4 validation"));

        for (label, field_name, replacement) in [
            ("digest", "sha256", json!(digest(0xbb))),
            ("length", "byteLength", json!(129)),
        ] {
            let mut generator = Fixture::valid();
            generator.input_value["proofGenerator"]["artifact"][field_name] = replacement.clone();
            generator.input_value["proofGenerator"]["qualifyingBuild"]["generatorArtifact"]
                [field_name] = replacement;
            let error = generator.materialize().bind().unwrap_err();
            assert!(
                format!("{error:#}").contains("authoritative B4 validation"),
                "generator artifact {label} rejected at an unexpected boundary: {error:#}"
            );
        }
    }

    #[test]
    fn descriptor_supplied_build_environment_is_closed_for_both_roles() {
        for descriptor_index in 0..2 {
            for name in [
                "RUSTC",
                "CARGO_BUILD_RUSTC",
                "CC",
                "LD_AUDIT",
                "NODE_OPTIONS",
                "SBT_OPTS",
                "MAVEN_OPTS",
                "SOURCE_DATE_EPOCH",
            ] {
                let mut fixture = Fixture::valid();
                fixture.descriptor_values[descriptor_index]["deterministicBuild"]["environment"]
                    ["variables"] = json!([{"name": name, "value": "1"}]);
                let error = fixture.materialize().bind().unwrap_err();
                assert!(
                    format!("{error:#}").contains("fails Draft 2020-12 schema"),
                    "descriptor {descriptor_index} variable {name} rejected at an unexpected boundary: {error:#}"
                );
            }
        }
    }

    #[test]
    fn runner_oci_seccomp_and_jvm_jar_relations_reject() {
        let mut image_spec_drift = Fixture::valid();
        image_spec_drift.runner_values[0]["image"]["imageSpec"]["commit"] = json!("00".repeat(20));
        assert!(
            format!("{:#}", image_spec_drift.materialize().bind().unwrap_err())
                .contains("147f9c13")
        );

        let mut blob_alias = Fixture::valid();
        blob_alias.runner_values[0]["image"]["config"]["digest"] =
            blob_alias.runner_values[0]["image"]["manifest"]["digest"].clone();
        assert!(
            format!("{:#}", blob_alias.materialize().bind().unwrap_err())
                .contains("aliases the manifest")
        );

        let mut rootfs_count_drift = Fixture::valid();
        rootfs_count_drift.runner_values[0]["image"]["postChangesetRootfs"]["entryCount"] =
            json!(4);
        assert!(
            format!("{:#}", rootfs_count_drift.materialize().bind().unwrap_err())
                .contains("rootfs type counts")
        );

        let mut aggregate_layer_inflate_drift = Fixture::valid();
        aggregate_layer_inflate_drift.runner_values[0]["image"]["layers"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": format!("sha256:{}", digest(0xf4)),
                "size": 768,
                "uncompressedBytes": MAX_OCI_UNCOMPRESSED_LAYER_BYTES,
                "diffId": format!("sha256:{}", digest(0xf5))
            }));
        assert!(
            format!(
                "{:#}",
                aggregate_layer_inflate_drift
                    .materialize()
                    .bind()
                    .unwrap_err()
            )
            .contains("aggregate bound")
        );

        let mut compressed_blob_exceeds_archive = Fixture::valid();
        compressed_blob_exceeds_archive.runner_values[0]["image"]["layers"][0]["size"] =
            json!(1_280);
        let error = compressed_blob_exceeds_archive
            .materialize()
            .bind()
            .unwrap_err();
        assert!(format!("{error:#}").contains("closed-ustar footprint"));

        let mut aggregate_compressed_blobs_exceed_archive = Fixture::valid();
        aggregate_compressed_blobs_exceed_archive.runner_values[0]["image"]["layers"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": format!("sha256:{}", digest(0xf6)),
                "size": 768,
                "uncompressedBytes": 1024,
                "diffId": format!("sha256:{}", digest(0xf7))
            }));
        let error = aggregate_compressed_blobs_exceed_archive
            .materialize()
            .bind()
            .unwrap_err();
        assert!(format!("{error:#}").contains("closed-ustar footprint"));

        let mut java_feature_drift = Fixture::valid();
        java_feature_drift.runner_values[3]["javaRuntime"]["version"] = json!("22.0.1");
        assert!(
            format!("{:#}", java_feature_drift.materialize().bind().unwrap_err())
                .contains("fails Draft 2020-12 schema")
        );

        let mut main_class_drift = Fixture::valid();
        main_class_drift.descriptor_values[1]["artifact"]["manifest"]["mainClassEntry"] =
            json!("org/example/Other.class");
        assert!(
            format!("{:#}", main_class_drift.materialize().bind().unwrap_err())
                .contains("Main-Class")
        );

        let mut jar_coverage_drift = Fixture::valid();
        jar_coverage_drift.descriptor_values[1]["artifact"]["nonClassFiles"]["scannedEntryCount"] =
            json!(1);
        assert!(
            format!("{:#}", jar_coverage_drift.materialize().bind().unwrap_err())
                .contains("non-class scan")
        );

        let materialized = Fixture::valid().materialize();
        let mut stale_seccomp = materialized;
        stale_seccomp.seccomp_bytes[0].push(b' ');
        assert!(format!("{:#}", stale_seccomp.bind().unwrap_err()).contains("exact canonical JCS"));
    }

    #[test]
    fn jvm_copy_only_packaging_inventory_bindings_reject_isolated_drifts() {
        let mut dependency_count = Fixture::valid();
        dependency_count.descriptor_values[1]["artifact"]["packaging"]["dependencyArtifactCount"] =
            json!(0);
        let error = dependency_count.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("dependency-artifact count"));

        let mut packager = Fixture::valid();
        packager.descriptor_values[1]["artifact"]["packaging"]["packer"]["sha256"] =
            json!(digest(0xd2));
        let error = packager.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("packager reference"));

        let mut configuration = Fixture::valid();
        configuration.descriptor_values[1]["artifact"]["packaging"]["configuration"]["sha256"] =
            json!(digest(0xd3));
        let error = configuration.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("configuration"));

        let mut full_closure_mode = Fixture::valid();
        full_closure_mode.descriptor_values[1]["artifact"]["packaging"]["mode"] =
            json!("full-dependency-closure");
        let error = full_closure_mode.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("fails Draft 2020-12 schema"));

        let mut extra_manifest = Fixture::valid();
        extra_manifest.descriptor_values[1]["artifact"]["packaging"]["inclusionManifest"]["entryCount"] =
            json!(3);
        let error = extra_manifest.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("fails Draft 2020-12 schema"));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn jvm_two_phase_build_contract_rejects_invocation_and_runner_drifts() {
        Fixture::valid().materialize().bind().unwrap();

        let mut missing_phase = Fixture::valid();
        missing_phase.descriptor_values[1]["deterministicBuild"]["phases"]
            .as_array_mut()
            .unwrap()
            .pop();
        let error = missing_phase.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("fails Draft 2020-12 schema"));

        let mut swapped_phases = Fixture::valid();
        swapped_phases.descriptor_values[1]["deterministicBuild"]["phases"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        let error = swapped_phases.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("fails Draft 2020-12 schema"));

        let mut application_executable = Fixture::valid();
        application_executable.descriptor_values[1]["deterministicBuild"]["phases"][0]["step"]["executable"] =
            json!("/tool/independent-jvm-packager");
        let error = application_executable.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("build-driver"));

        let mut packaging_executable = Fixture::valid();
        packaging_executable.descriptor_values[1]["deterministicBuild"]["phases"][1]["step"]["executable"] =
            json!("/tool/independent-jvm");
        let error = packaging_executable.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("packager"));

        for index in 0..JVM_COPY_ONLY_PACKAGER_ARGUMENTS.len() {
            let mut argument_drift = Fixture::valid();
            argument_drift.descriptor_values[1]["deterministicBuild"]["phases"][1]["step"]["arguments"]
                [index] = json!("drift");
            let error = argument_drift.materialize().bind().unwrap_err();
            assert!(
                format!("{error:#}").contains("fails Draft 2020-12 schema"),
                "packager argument {index} drift reached an unexpected boundary: {error:#}"
            );
        }

        for mutation in ["remove", "append", "swap"] {
            let mut arguments = Fixture::valid();
            let vector = arguments.descriptor_values[1]["deterministicBuild"]["phases"][1]["step"]
                ["arguments"]
                .as_array_mut()
                .unwrap();
            match mutation {
                "remove" => {
                    vector.pop();
                }
                "append" => vector.push(json!("--extra")),
                "swap" => vector.swap(1, 3),
                _ => unreachable!(),
            }
            let error = arguments.materialize().bind().unwrap_err();
            assert!(
                format!("{error:#}").contains("fails Draft 2020-12 schema"),
                "packager argument {mutation} reached an unexpected boundary: {error:#}"
            );
        }

        for field_name in ["executionOrder", "instancePolicy", "comparison"] {
            let mut scheduling = Fixture::valid();
            scheduling.descriptor_values[1]["deterministicBuild"][field_name] = json!("drift");
            let error = scheduling.materialize().bind().unwrap_err();
            assert!(
                format!("{error:#}").contains("fails Draft 2020-12 schema"),
                "JVM scheduling field {field_name} reached an unexpected boundary: {error:#}"
            );
        }

        let mut repetitions = Fixture::valid();
        repetitions.descriptor_values[1]["deterministicBuild"]["repetitionsPerPhase"] = json!(3);
        let error = repetitions.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("fails Draft 2020-12 schema"));

        for field_name in ["policy", "manifestPath", "archiveRoot"] {
            let mut input_layout = Fixture::valid();
            input_layout.descriptor_values[1]["deterministicBuild"]["phases"][1]["inputLayout"]
                [field_name] = json!("drift");
            let error = input_layout.materialize().bind().unwrap_err();
            assert!(
                format!("{error:#}").contains("fails Draft 2020-12 schema"),
                "packaging input-layout field {field_name} reached an unexpected boundary: {error:#}"
            );
        }

        for phase_index in 0..2 {
            let mut output = Fixture::valid();
            output.descriptor_values[1]["deterministicBuild"]["phases"][phase_index]["output"]["containerPath"] =
                json!("/out/drift.jar");
            let error = output.materialize().bind().unwrap_err();
            assert!(
                format!("{error:#}").contains("fails Draft 2020-12 schema"),
                "phase {phase_index} output path reached an unexpected boundary: {error:#}"
            );
        }

        let mut packaging_cwd = Fixture::valid();
        packaging_cwd.descriptor_values[1]["deterministicBuild"]["phases"][1]["step"]["workingDirectory"] =
            json!("/src");
        let error = packaging_cwd.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("fails Draft 2020-12 schema"));

        let mut missing_runner_phase = Fixture::valid();
        missing_runner_phase.runner_values[1]["policy"]
            .as_object_mut()
            .unwrap()
            .remove("packagingPhase");
        let error = missing_runner_phase.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("fails Draft 2020-12 schema"));

        let mut exposed_source = Fixture::valid();
        exposed_source.runner_values[1]["policy"]["packagingPhase"]["mounts"][0]["target"] =
            json!("/src");
        let error = exposed_source.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("fails Draft 2020-12 schema"));

        let mut mutable_phase_input = Fixture::valid();
        mutable_phase_input.runner_values[1]["policy"]["packagingPhase"]["mounts"][0]["readOnly"] =
            json!(false);
        let error = mutable_phase_input.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("fails Draft 2020-12 schema"));

        for field_name in ["freshMaterialization", "destroyAfterRun"] {
            let mut freshness = Fixture::valid();
            freshness.runner_values[1]["policy"]["packagingPhase"]["mounts"][0][field_name] =
                json!(false);
            let error = freshness.materialize().bind().unwrap_err();
            assert!(
                format!("{error:#}").contains("fails Draft 2020-12 schema"),
                "phase-input field {field_name} reached an unexpected boundary: {error:#}"
            );
        }

        let mut rust_runner_phase = Fixture::valid();
        rust_runner_phase.runner_values[0]["policy"]["packagingPhase"] =
            rust_runner_phase.runner_values[1]["policy"]["packagingPhase"].clone();
        let error = rust_runner_phase.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("fails Draft 2020-12 schema"));

        for runner_index in [2, 3] {
            let mut verification_runner_phase = Fixture::valid();
            verification_runner_phase.runner_values[runner_index]["policy"]["packagingPhase"] =
                verification_runner_phase.runner_values[1]["policy"]["packagingPhase"].clone();
            let error = verification_runner_phase.materialize().bind().unwrap_err();
            assert!(
                format!("{error:#}").contains("fails Draft 2020-12 schema"),
                "verification runner {runner_index} accepted a JVM packaging phase: {error:#}"
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn jvm_copy_only_manifest_relations_reject_isolated_drifts() {
        let mut stale_commitment = Fixture::valid();
        stale_commitment.descriptor_values[1]["artifact"]["packaging"]["inclusionManifest"]["sha256"] =
            json!(digest(0xf0));
        let error = stale_commitment.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("commitment is stale"));

        let mut input_count = Fixture::valid();
        input_count.jvm_copy_only_inclusion_manifest_value["inputs"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id": "dependency-001",
                "role": "dependency-artifact",
                "path": "deps/independent-jvm/extra",
                "byteLength": 30,
                "sha256": digest(0xf1),
                "encoding": "raw-bytes",
                "fileFormat": "zip-jar",
                "regularEntryCount": 1
            }));
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut input_count);
        let error = input_count.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("input count"));

        let mut input_order = Fixture::valid();
        input_order.jvm_copy_only_inclusion_manifest_value["inputs"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut input_order);
        let error = input_order.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("id differs from application"));

        let mut input_id = Fixture::valid();
        input_id.jvm_copy_only_inclusion_manifest_value["inputs"][1]["id"] =
            json!("dependency-001");
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut input_id);
        let error = input_id.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("input ID is not canonical"));

        let mut input_role = Fixture::valid();
        input_role.jvm_copy_only_inclusion_manifest_value["inputs"][1]["role"] =
            json!("application-intermediate");
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut input_role);
        let error = input_role.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("role differs from dependency-artifact"));

        let mut input_identity = Fixture::valid();
        input_identity.jvm_copy_only_inclusion_manifest_value["inputs"][1]["sha256"] =
            json!(digest(0xf2));
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut input_identity);
        let error = input_identity.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("dependency input sha256"));

        let mut non_jar_ecosystem = Fixture::valid();
        non_jar_ecosystem.descriptor_values[1]["dependencyClosure"]["entries"][0]["ecosystem"] =
            json!("cargo");
        bind_inventory_digests(&mut non_jar_ecosystem.descriptor_values[1]);
        let error = non_jar_ecosystem.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("non-JAR ecosystem"));

        let mut application_omission = Fixture::valid();
        application_omission.jvm_copy_only_inclusion_manifest_value["entries"]
            .as_array_mut()
            .unwrap()
            .remove(1);
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut application_omission);
        let error = application_omission.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("every application entry"));

        let mut stale_application_count = Fixture::valid();
        stale_application_count.jvm_copy_only_inclusion_manifest_value["inputs"][0]["regularEntryCount"] =
            json!(3);
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut stale_application_count);
        let error = stale_application_count.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("regular-entry count is stale"));

        let mut application_count = Fixture::valid();
        application_count.jvm_copy_only_inclusion_manifest_value["inputs"][0]["regularEntryCount"] =
            json!(3);
        application_count.descriptor_values[1]["artifact"]["packaging"]["applicationInput"]["regularEntryCount"] =
            json!(3);
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut application_count);
        let error = application_count.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("every application entry"));

        let mut dependency_selection_overflow = Fixture::valid();
        dependency_selection_overflow.jvm_copy_only_inclusion_manifest_value["entries"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "kind": "regular-file",
                "name": "z-reference.conf",
                "sourceInputId": "dependency-000",
                "sourceEntryName": "z-reference.conf",
                "byteLength": 20,
                "sha256": digest(0xf3)
            }));
        let archive =
            &mut dependency_selection_overflow.descriptor_values[1]["artifact"]["archive"];
        archive["entryCount"] = json!(4);
        archive["localFileRecordCount"] = json!(4);
        archive["regularFileEntryCount"] = json!(4);
        archive["uncompressedByteLength"] = json!(220);
        dependency_selection_overflow.descriptor_values[1]["artifact"]["nonClassFiles"]["regularEntryCount"] =
            json!(3);
        dependency_selection_overflow.descriptor_values[1]["artifact"]["nonClassFiles"]["scannedEntryCount"] =
            json!(3);
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut dependency_selection_overflow);
        let error = dependency_selection_overflow
            .materialize()
            .bind()
            .unwrap_err();
        assert!(format!("{error:#}").contains("dependency archive declares"));

        let mut generated = Fixture::valid();
        generated.jvm_copy_only_inclusion_manifest_value["generatedEntries"] = json!([{}]);
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut generated);
        let error = generated.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("fails Draft 2020-12 schema"));

        let mut first_manifest = Fixture::valid();
        first_manifest.jvm_copy_only_inclusion_manifest_value["entries"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut first_manifest);
        let error = first_manifest.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("manifest entry is not first"));

        let mut order = Fixture::valid();
        order.jvm_copy_only_inclusion_manifest_value["entries"]
            .as_array_mut()
            .unwrap()
            .swap(1, 2);
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut order);
        let error = order.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("canonical order"));

        let mut duplicate = Fixture::valid();
        duplicate.jvm_copy_only_inclusion_manifest_value["entries"][2]["name"] =
            json!("org/example/Main.class");
        duplicate.jvm_copy_only_inclusion_manifest_value["entries"][2]["sourceEntryName"] =
            json!("org/example/Main.class");
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut duplicate);
        let error = duplicate.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("name is duplicated"));

        let mut casefold = Fixture::valid();
        casefold.jvm_copy_only_inclusion_manifest_value["entries"][2]["name"] =
            json!("org/example/main.class");
        casefold.jvm_copy_only_inclusion_manifest_value["entries"][2]["sourceEntryName"] =
            json!("org/example/main.class");
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut casefold);
        let error = casefold.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("case-fold collision"));

        let mut relocation = Fixture::valid();
        relocation.jvm_copy_only_inclusion_manifest_value["entries"][2]["sourceEntryName"] =
            json!("other.conf");
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut relocation);
        let error = relocation.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("relocation is forbidden"));

        let mut unknown_source = Fixture::valid();
        unknown_source.jvm_copy_only_inclusion_manifest_value["entries"][2]["sourceInputId"] =
            json!("dependency-001");
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut unknown_source);
        let error = unknown_source.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("unknown source input"));

        for (label, entry_index) in [("manifest", 0), ("Main-Class", 1)] {
            let mut dependency_source = Fixture::valid();
            dependency_source.jvm_copy_only_inclusion_manifest_value["entries"][entry_index]["sourceInputId"] =
                json!("dependency-000");
            refresh_jvm_copy_only_inclusion_manifest_binding(&mut dependency_source);
            let error = dependency_source.materialize().bind().unwrap_err();
            assert!(
                format!("{error:#}").contains("must come from the application input"),
                "{label} source rejected at an unexpected boundary: {error:#}"
            );
        }

        let mut directory = Fixture::valid();
        directory.descriptor_values[1]["artifact"]["archive"]["directoryEntryCount"] = json!(1);
        directory.descriptor_values[1]["artifact"]["archive"]["entryCount"] = json!(4);
        directory.descriptor_values[1]["artifact"]["archive"]["localFileRecordCount"] = json!(4);
        let error = directory.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("cannot contain directory entries"));

        let mut entry_count = Fixture::valid();
        entry_count.descriptor_values[1]["artifact"]["archive"]["entryCount"] = json!(4);
        entry_count.descriptor_values[1]["artifact"]["archive"]["localFileRecordCount"] = json!(4);
        entry_count.descriptor_values[1]["artifact"]["archive"]["regularFileEntryCount"] = json!(4);
        entry_count.descriptor_values[1]["artifact"]["nonClassFiles"]["regularEntryCount"] =
            json!(3);
        entry_count.descriptor_values[1]["artifact"]["nonClassFiles"]["scannedEntryCount"] =
            json!(3);
        let error = entry_count.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("manifest entry count"));

        let mut aggregate = Fixture::valid();
        aggregate.descriptor_values[1]["artifact"]["archive"]["uncompressedByteLength"] =
            json!(201);
        let error = aggregate.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("aggregate"));

        let mut maximum = Fixture::valid();
        maximum.descriptor_values[1]["artifact"]["archive"]["largestEntryUncompressedByteLength"] =
            json!(99);
        let error = maximum.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("largest entry"));

        let mut class_partition = Fixture::valid();
        class_partition.jvm_copy_only_inclusion_manifest_value["entries"][2]["name"] =
            json!("reference.class");
        class_partition.jvm_copy_only_inclusion_manifest_value["entries"][2]["sourceEntryName"] =
            json!("reference.class");
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut class_partition);
        let error = class_partition.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("class/non-class"));

        let mut manifest_length = Fixture::valid();
        manifest_length.descriptor_values[1]["artifact"]["manifest"]["manifestByteLength"] =
            json!(81);
        let error = manifest_length.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("manifest length"));

        let mut main_class_omission = Fixture::valid();
        main_class_omission.jvm_copy_only_inclusion_manifest_value["entries"][1]["name"] =
            json!("org/example/Other.class");
        main_class_omission.jvm_copy_only_inclusion_manifest_value["entries"][1]["sourceEntryName"] =
            json!("org/example/Other.class");
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut main_class_omission);
        let error = main_class_omission.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("omits the declared Main-Class"));

        let mut output = Fixture::valid();
        output.jvm_copy_only_inclusion_manifest_value["output"]["sha256"] = json!(digest(0xf3));
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut output);
        let error = output.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("output sha256"));
    }

    #[test]
    fn jvm_copy_only_zero_dependency_closure_is_supported() {
        let mut fixture = Fixture::valid();
        fixture.descriptor_values[1]["dependencyClosure"]["entries"] = json!([]);
        fixture.descriptor_values[1]["artifact"]["packaging"]["dependencyArtifactCount"] = json!(0);
        fixture.jvm_copy_only_inclusion_manifest_value["inputs"]
            .as_array_mut()
            .unwrap()
            .remove(1);
        fixture.jvm_copy_only_inclusion_manifest_value["entries"]
            .as_array_mut()
            .unwrap()
            .remove(2);
        let archive = &mut fixture.descriptor_values[1]["artifact"]["archive"];
        archive["entryCount"] = json!(2);
        archive["localFileRecordCount"] = json!(2);
        archive["regularFileEntryCount"] = json!(2);
        archive["uncompressedByteLength"] = json!(180);
        fixture.descriptor_values[1]["artifact"]["nonClassFiles"]["regularEntryCount"] = json!(1);
        fixture.descriptor_values[1]["artifact"]["nonClassFiles"]["scannedEntryCount"] = json!(1);
        bind_inventory_digests(&mut fixture.descriptor_values[1]);
        refresh_jvm_copy_only_inclusion_manifest_binding(&mut fixture);

        fixture.materialize().bind().unwrap();
    }

    #[test]
    fn jvm_build_jdk_and_build_working_directory_reject_isolated_drifts() {
        let mut missing_jdk = Fixture::valid();
        missing_jdk.runner_values[1]
            .as_object_mut()
            .unwrap()
            .remove("buildJdk");
        let error = missing_jdk.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("fails Draft 2020-12 schema"));

        let mut noncanonical_version = Fixture::valid();
        noncanonical_version.runner_values[1]["buildJdk"]["version"] = json!("21.0");
        noncanonical_version.descriptor_values[1]["toolchainClosure"]["entries"][1]["version"] =
            json!("21.0");
        noncanonical_version.descriptor_values[1]["toolchainClosure"]["entries"][2]["version"] =
            json!("21.0");
        bind_inventory_digests(&mut noncanonical_version.descriptor_values[1]);
        let error = noncanonical_version.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("version number is not canonical"));

        for (label, binary, entry_index, expected) in [
            ("launcher", "launcher", 1, "java toolchain entry"),
            ("compiler", "compiler", 2, "javac toolchain entry"),
        ] {
            let mut identity_drift = Fixture::valid();
            identity_drift.runner_values[1]["buildJdk"][binary]["sha256"] = json!(digest(0xd6));
            let error = identity_drift.materialize().bind().unwrap_err();
            assert!(
                format!("{error:#}").contains(expected),
                "{label} identity rejected at an unexpected boundary: {error:#}"
            );

            let mut toolchain_drift = Fixture::valid();
            toolchain_drift.descriptor_values[1]["toolchainClosure"]["entries"][entry_index]["sha256"] =
                json!(digest(0xd7));
            bind_inventory_digests(&mut toolchain_drift.descriptor_values[1]);
            let error = toolchain_drift.materialize().bind().unwrap_err();
            assert!(
                format!("{error:#}").contains(expected),
                "{label} toolchain entry rejected at an unexpected boundary: {error:#}"
            );
        }

        let mut output_cwd = Fixture::valid();
        output_cwd.descriptor_values[1]["deterministicBuild"]["phases"][0]["step"]["workingDirectory"] =
            json!("/out");
        let error = output_cwd.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("fails Draft 2020-12 schema"));
    }

    #[test]
    fn positive_gate_projects_closed_oci_image_layouts_in_canonical_role_order() {
        let mut fixture = Fixture::valid();
        for (index, profile) in fixture.runner_values.iter_mut().enumerate() {
            let index_byte = u8::try_from(index).unwrap();
            profile["image"]["layers"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": format!(
                        "sha256:{}",
                        digest(0x90_u8.wrapping_add(index_byte))
                    ),
                    "size": 1_024,
                    "uncompressedBytes": 4_096,
                    "diffId": format!(
                        "sha256:{}",
                        digest(0xa0_u8.wrapping_add(index_byte))
                    )
                }));
            profile["image"]["archive"]["byteLength"] =
                json!(expected_oci_archive_byte_length(&profile["image"]).unwrap());
        }
        let materialized = fixture.materialize();
        let bindings = materialized.bind().unwrap();
        let images = bindings.oci_image_layouts();

        assert_eq!(images.len(), 4);
        for (index, role) in PositiveRunnerRole::all().into_iter().enumerate() {
            let index_byte = u8::try_from(index).unwrap();
            let image = &images[index];
            assert_eq!(image.role(), role);
            assert_eq!(image.archive_path(), format!("runner/image-{index}.tar"));
            assert_eq!(
                image.archive_byte_length(),
                expected_oci_archive_byte_length(&materialized.runner_values[index]["image"])
                    .unwrap()
            );
            assert_eq!(
                image.archive_sha256(),
                [0x70_u8.wrapping_add(index_byte); DIGEST_BYTES]
            );
            assert_eq!(
                image.manifest().digest(),
                [0x71_u8.wrapping_add(index_byte); DIGEST_BYTES]
            );
            assert_eq!(image.manifest().byte_length(), 512);
            assert_eq!(
                image.config().digest(),
                [0x72_u8.wrapping_add(index_byte); DIGEST_BYTES]
            );
            assert_eq!(image.config().byte_length(), 256);
            assert_eq!(image.layers().len(), 2);
            assert_eq!(
                image.layers()[0].compressed_digest(),
                [0x73_u8.wrapping_add(index_byte); DIGEST_BYTES]
            );
            assert_eq!(image.layers()[0].compressed_byte_length(), 768);
            assert_eq!(image.layers()[0].uncompressed_byte_length(), 2_048);
            assert_eq!(
                image.layers()[0].diff_id(),
                [0x74_u8.wrapping_add(index_byte); DIGEST_BYTES]
            );
            assert_eq!(
                image.layers()[1].compressed_digest(),
                [0x90_u8.wrapping_add(index_byte); DIGEST_BYTES]
            );
            assert_eq!(image.layers()[1].compressed_byte_length(), 1_024);
            assert_eq!(image.layers()[1].uncompressed_byte_length(), 4_096);
            assert_eq!(
                image.layers()[1].diff_id(),
                [0xa0_u8.wrapping_add(index_byte); DIGEST_BYTES]
            );
            assert_eq!(image.post_changeset_rootfs().entry_count(), 3);
            assert_eq!(image.post_changeset_rootfs().regular_file_count(), 1);
            assert_eq!(image.post_changeset_rootfs().directory_count(), 1);
            assert_eq!(image.post_changeset_rootfs().symbolic_link_count(), 1);
            assert_eq!(image.post_changeset_rootfs().regular_file_bytes(), 64);
        }
    }

    #[test]
    fn positive_gate_projects_retained_host_rootfs_metadata_policy_for_each_role() {
        let materialized = Fixture::valid().materialize();
        let bindings = materialized.bind().unwrap();

        for (index, role) in PositiveRunnerRole::all().into_iter().enumerate() {
            let policy = bindings.oci_image_layouts()[index].retained_host_rootfs_metadata_policy();
            assert_eq!(policy.role(), role);
            assert_eq!(policy.policy_id(), RETAINED_HOST_ROOTFS_METADATA_POLICY_ID);
            assert_eq!(
                policy.obligation_ids(),
                [
                    "xattr-name-set",
                    "posix-access-acl",
                    "posix-default-acl",
                    "linux-file-capability",
                    "immutable",
                    "append-only",
                    "encrypted",
                    "verity",
                    "casefold",
                    "nonzero-project-id",
                    "project-inherit"
                ]
            );
            assert_eq!(
                policy.outcome_ids(),
                [
                    "absent",
                    "present",
                    "unsupported",
                    "inaccessible",
                    "oversize",
                    "unstable"
                ]
            );
            assert_eq!(policy.accepted_outcome_id(), "absent");
        }
    }

    #[test]
    fn positive_gate_rejects_retained_host_rootfs_metadata_policy_shape_and_id_drift() {
        let mut missing = Fixture::valid();
        missing.runner_values[0]["image"]
            .as_object_mut()
            .unwrap()
            .remove("retainedHostRootfsMetadataPolicy");
        let error = missing.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("fails Draft 2020-12 schema"));

        for invalid in [
            "eip0045-b4-retained-host-rootfs-metadata-obligations-v0",
            "EIP0045-b4-retained-host-rootfs-metadata-obligations-v1",
            "eip0045-b4-retained-host-rootfs-metadata-unknown-v1",
        ] {
            let mut fixture = Fixture::valid();
            fixture.runner_values[0]["image"]["retainedHostRootfsMetadataPolicy"] = json!(invalid);
            let error = fixture.materialize().bind().unwrap_err();
            assert!(
                format!("{error:#}").contains("fails Draft 2020-12 schema"),
                "metadata-policy ID {invalid} reached an unexpected boundary: {error:#}"
            );
        }

        let mut wrong_type = Fixture::valid();
        wrong_type.runner_values[0]["image"]["retainedHostRootfsMetadataPolicy"] = json!({});
        let error = wrong_type.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("fails Draft 2020-12 schema"));

        let mut second_selector = Fixture::valid();
        second_selector.runner_values[0]["image"]["metadataPolicy"] =
            json!("eip0045-b4-retained-host-rootfs-metadata-obligations-v1");
        let error = second_selector.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("fails Draft 2020-12 schema"));
    }

    #[test]
    fn retained_host_rootfs_metadata_policy_projector_rejects_role_and_id_bypasses() {
        let fixture = Fixture::valid();
        let profile = profile_projection_test_document(fixture.runner_values[0].clone());
        let error = project_positive_retained_host_rootfs_metadata_policy(
            &profile,
            PositiveRunnerRole::JvmValidatorBuild,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("index drift"));

        let mut unknown = fixture.runner_values[0].clone();
        unknown["image"]["retainedHostRootfsMetadataPolicy"] =
            json!("eip0045-b4-retained-host-rootfs-metadata-unknown-v1");
        let unknown = profile_projection_test_document(unknown);
        let error = project_positive_retained_host_rootfs_metadata_policy(
            &unknown,
            PositiveRunnerRole::RustValidatorBuild,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("retainedHostRootfsMetadataPolicy"));

        let error =
            project_positive_oci_image_layout(&unknown, PositiveRunnerRole::RustValidatorBuild)
                .unwrap_err();
        assert!(format!("{error:#}").contains("retainedHostRootfsMetadataPolicy"));
    }

    #[test]
    fn positive_gate_projects_runtime_observation_contracts_and_reserved_selectors() {
        let materialized = Fixture::valid().materialize();
        let bindings = materialized.bind().unwrap();

        for (index, role) in PositiveRunnerRole::all().into_iter().enumerate() {
            let runtime = bindings.oci_image_layouts()[index].runtime_contract();
            assert_eq!(runtime.role(), role);
            assert_eq!(runtime.version(), "1.3.0");
            assert_eq!(runtime.runtime_spec_version(), "1.3.0");
            assert_eq!(
                runtime.runtime_spec_commit(),
                "92249139eea7161e13745abd4cb6d0ea02a3227a"
            );
            assert_eq!(
                runtime.configuration_policy().policy_id(),
                "eip0045-b4-oci-runtime-config-projection-v1"
            );

            let binary = runtime.binary();
            assert_eq!(binary.relative_path(), format!("runner/runc-{index}"));
            assert_eq!(binary.byte_length(), 64);
            assert_eq!(
                binary.sha256(),
                [0x80_u8.wrapping_add(u8::try_from(index).unwrap()); DIGEST_BYTES]
            );
            assert_eq!(binary.elf_type(), "et-exec");
            assert_eq!(binary.os_abi(), "sysv");
            assert_eq!(binary.program_header_count(), 6);
            assert_eq!(binary.section_header_count(), 12);
            assert_eq!(binary.load_segment_count(), 3);
            assert_eq!(binary.executable_load_segment_count(), 1);
            assert_eq!(binary.gnu_stack_segment_count(), 1);

            let observation = runtime.observation_selectors();
            let state_contract = observation.state_contract();
            assert_eq!(state_contract.role(), role);
            assert_eq!(state_contract.maximum_source_bytes(), 16_384);
            let process_identity_contract = observation.process_identity_contract();
            assert_eq!(process_identity_contract.role(), role);
            assert_eq!(process_identity_contract.maximum_source_bytes(), 128);
            assert_eq!(
                observation.state_selector_id(),
                "eip0045-b4-runtime-observation-runc-state-json-v1"
            );
            assert_eq!(
                observation.process_identity_selector_id(),
                "eip0045-b4-runtime-observation-linux-boot-id-pid-starttime-jcs-v1"
            );
            assert_eq!(
                observation.namespaces_selector_id(),
                "eip0045-b4-runtime-observation-namespaces-reserved-v1"
            );
            assert_eq!(
                observation.id_mappings_selector_id(),
                "eip0045-b4-runtime-observation-id-mappings-reserved-v1"
            );
            assert_eq!(
                observation.mountinfo_selector_id(),
                "eip0045-b4-runtime-observation-mountinfo-reserved-v1"
            );
            assert_eq!(
                observation.security_status_selector_id(),
                "eip0045-b4-runtime-observation-security-status-reserved-v1"
            );
            assert_eq!(
                observation.cgroup_v2_selector_id(),
                "eip0045-b4-runtime-observation-cgroup-v2-reserved-v1"
            );
            assert_eq!(
                observation.root_identity_selector_id(),
                "eip0045-b4-runtime-observation-root-identity-reserved-v1"
            );
            assert_eq!(
                observation.auxv_selector_id(),
                "eip0045-b4-runtime-observation-auxv-reserved-v1"
            );
            assert_eq!(
                observation.process_mappings_selector_id(),
                "eip0045-b4-runtime-observation-process-mappings-reserved-v1"
            );
            assert_eq!(
                observation.smoke_identity_selector_id(),
                "eip0045-b4-runtime-observation-smoke-identity-reserved-v1"
            );
        }
    }

    #[test]
    fn positive_gate_rejects_runtime_observation_selector_shape_and_id_drift() {
        let mut missing = Fixture::valid();
        missing.runner_values[0]["runtime"]
            .as_object_mut()
            .unwrap()
            .remove("observationSelectors");
        let error = missing.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("fails Draft 2020-12 schema"));

        let mut extra = Fixture::valid();
        extra.runner_values[0]["runtime"]["observationSelectors"]["extension"] = json!("forbidden");
        let error = extra.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("fails Draft 2020-12 schema"));

        for key in [
            "state",
            "processIdentity",
            "namespaces",
            "idMappings",
            "mountinfo",
            "securityStatus",
            "cgroupV2",
            "rootIdentity",
            "auxv",
            "processMappings",
            "smokeIdentity",
        ] {
            let mut missing_member = Fixture::valid();
            missing_member.runner_values[0]["runtime"]["observationSelectors"]
                .as_object_mut()
                .unwrap()
                .remove(key);
            let error = missing_member.materialize().bind().unwrap_err();
            assert!(
                format!("{error:#}").contains("fails Draft 2020-12 schema"),
                "missing runtime observation selector {key} reached an unexpected boundary: {error:#}"
            );

            let mut fixture = Fixture::valid();
            fixture.runner_values[0]["runtime"]["observationSelectors"][key] =
                json!("eip0045-b4-unknown-runtime-observation-v1");
            let error = fixture.materialize().bind().unwrap_err();
            assert!(
                format!("{error:#}").contains("fails Draft 2020-12 schema"),
                "runtime observation field {key} reached an unexpected boundary: {error:#}"
            );
        }

        for (key, former_reserved_id) in [
            ("state", "eip0045-b4-runtime-observation-state-reserved-v1"),
            (
                "processIdentity",
                "eip0045-b4-runtime-observation-process-identity-reserved-v1",
            ),
        ] {
            let mut legacy = Fixture::valid();
            legacy.runner_values[0]["runtime"]["observationSelectors"][key] =
                json!(former_reserved_id);
            let error = legacy.materialize().bind().unwrap_err();
            assert!(
                format!("{error:#}").contains("fails Draft 2020-12 schema"),
                "former reserved runtime observation ID for {key} was reinterpreted in place: {error:#}"
            );
        }
    }

    fn profile_projection_test_document(value: Value) -> BoundDocument {
        BoundDocument {
            relative_path: String::new(),
            bytes: Vec::new(),
            value,
            sha256: String::new(),
        }
    }

    fn assert_runtime_contract_projection_rejects_path(
        valid: &Value,
        path: &[&str],
        replacement: Value,
        expected: &str,
    ) {
        let mut profile = valid.clone();
        let mut target = &mut profile;
        for key in path {
            target = &mut target[*key];
        }
        *target = replacement;
        let error = project_positive_oci_image_layout(
            &profile_projection_test_document(profile),
            PositiveRunnerRole::RustValidatorBuild,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains(expected),
            "runtime invariant {path:?} reached an unexpected boundary: {error:#}"
        );
    }

    #[test]
    fn runtime_contract_projection_rejects_detached_role_and_selector_drift() {
        let fixture = Fixture::valid();
        let error = project_positive_oci_runtime_contract(
            &profile_projection_test_document(fixture.runner_values[0].clone()),
            PositiveRunnerRole::JvmValidatorBuild,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("index drift"));

        let error = project_positive_oci_image_layout(
            &profile_projection_test_document(fixture.runner_values[0].clone()),
            PositiveRunnerRole::JvmValidatorBuild,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("index drift"));

        let mut configuration = fixture.runner_values[0].clone();
        configuration["runtime"]["configurationPolicy"] =
            json!("eip0045-b4-unknown-runtime-configuration-v1");
        let error = project_positive_oci_image_layout(
            &profile_projection_test_document(configuration),
            PositiveRunnerRole::RustValidatorBuild,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("configurationPolicy"));

        let mut binary_drift = fixture.runner_values[0].clone();
        binary_drift["runtime"]["binary"]["path"] = json!("runner/runc-remeasured");
        binary_drift["runtime"]["binary"]["byteLength"] = json!(65);
        binary_drift["runtime"]["binary"]["sha256"] = json!(digest(0xb1));
        let projected = project_positive_oci_image_layout(
            &profile_projection_test_document(binary_drift),
            PositiveRunnerRole::RustValidatorBuild,
        )
        .unwrap();
        assert_eq!(projected.runtime_contract().version(), "1.3.0");
        assert_eq!(
            projected.runtime_contract().binary().relative_path(),
            "runner/runc-remeasured"
        );
        assert_eq!(projected.runtime_contract().binary().byte_length(), 65);
        assert_eq!(
            projected.runtime_contract().binary().sha256(),
            [0xb1; DIGEST_BYTES]
        );

        let mut extra = fixture.runner_values[0].clone();
        extra["runtime"]["observationSelectors"]["extension"] = json!("forbidden");
        let error = project_positive_oci_image_layout(
            &profile_projection_test_document(extra),
            PositiveRunnerRole::RustValidatorBuild,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}")
                .contains("runtime observation selector set authority surface drift")
        );

        for key in [
            "state",
            "processIdentity",
            "namespaces",
            "idMappings",
            "mountinfo",
            "securityStatus",
            "cgroupV2",
            "rootIdentity",
            "auxv",
            "processMappings",
            "smokeIdentity",
        ] {
            let mut profile = fixture.runner_values[0].clone();
            profile["runtime"]["observationSelectors"][key] =
                json!("eip0045-b4-unknown-runtime-observation-v1");
            let error = project_positive_oci_image_layout(
                &profile_projection_test_document(profile),
                PositiveRunnerRole::RustValidatorBuild,
            )
            .unwrap_err();
            assert!(
                format!("{error:#}").contains(key),
                "runtime observation field {key} reached an unexpected projection boundary: {error:#}"
            );
        }
    }

    #[test]
    fn runtime_contract_projector_defends_fixed_runtime_and_elf_invariants() {
        let valid = Fixture::valid().runner_values[0].clone();
        let cases: Vec<(&[&str], Value, &str)> = vec![
            (&["runtime", "name"], json!("not-runc"), "name"),
            (&["runtime", "version"], json!("1.3.0-fixture"), "version"),
            (
                &["runtime", "runtimeSpec", "version"],
                json!("1.2.0"),
                "version",
            ),
            (
                &["runtime", "runtimeSpec", "commit"],
                json!(digest(0xb2)),
                "commit",
            ),
            (
                &["runtime", "binary", "encoding"],
                json!("rfc8785-jcs"),
                "encoding",
            ),
            (
                &["runtime", "binary", "fileFormat"],
                json!("pe32"),
                "fileFormat",
            ),
            (
                &["runtime", "binary", "architecture"],
                json!("arm64"),
                "architecture",
            ),
            (
                &["runtime", "binary", "linkage"],
                json!("dynamic"),
                "linkage",
            ),
            (
                &["runtime", "binary", "inspectionPolicy"],
                json!("unknown"),
                "inspectionPolicy",
            ),
            (
                &["runtime", "binary", "elf", "policy"],
                json!("unknown"),
                "policy",
            ),
            (
                &["runtime", "binary", "elf", "entryPointInExecutableLoad"],
                json!(false),
                "entryPointInExecutableLoad",
            ),
        ];
        for (path, replacement, expected) in cases {
            assert_runtime_contract_projection_rejects_path(&valid, path, replacement, expected);
        }

        for key in [
            "interpreterSegmentCount",
            "dynamicSegmentCount",
            "writableExecutableLoadSegmentCount",
            "executableStackSegmentCount",
            "overlappingLoadFileRangeCount",
            "extendedNumberingCount",
            "structuralParseFailureCount",
        ] {
            assert_runtime_contract_projection_rejects_path(
                &valid,
                &["runtime", "binary", "elf", key],
                json!(1),
                key,
            );
        }

        assert_runtime_contract_projection_rejects_path(
            &valid,
            &["runtime", "binary", "elf", "gnuStackSegmentCount"],
            json!(2),
            "gnuStackSegmentCount",
        );
    }

    #[test]
    fn positive_gate_projects_gate_rooted_physical_rootfs_requirements() {
        fn observed(image: &B4PositiveOciImageLayoutV1) -> Vec<(&str, bool, bool)> {
            image
                .rootfs_path_requirements()
                .iter()
                .map(|requirement| {
                    (
                        requirement.image_path(),
                        requirement.requires_directory(),
                        requirement.requires_empty_regular(),
                    )
                })
                .collect()
        }

        let materialized = Fixture::valid().materialize();
        let bindings = materialized.bind().unwrap();
        let images = bindings.oci_image_layouts();
        let common_dev = [
            ("/dev", true, false),
            ("/dev/full", false, true),
            ("/dev/null", false, true),
            ("/dev/random", false, true),
            ("/dev/urandom", false, true),
            ("/dev/zero", false, true),
        ];
        assert_eq!(
            observed(&images[0]),
            [
                [("/deps", true, false)].as_slice(),
                common_dev.as_slice(),
                &[
                    ("/out", true, false),
                    ("/proc", true, false),
                    ("/src", true, false),
                    ("/tmp", true, false),
                ],
            ]
            .concat()
        );
        assert_eq!(
            observed(&images[1]),
            [
                [("/deps", true, false)].as_slice(),
                common_dev.as_slice(),
                &[
                    ("/out", true, false),
                    ("/phase-input", true, false),
                    ("/proc", true, false),
                    ("/src", true, false),
                    ("/tmp", true, false),
                ],
            ]
            .concat()
        );
        assert_eq!(
            observed(&images[2]),
            [
                common_dev.as_slice(),
                &[
                    ("/input", true, false),
                    ("/proc", true, false),
                    ("/tmp", true, false),
                    ("/validator/validator", false, true),
                ],
            ]
            .concat()
        );
        assert_eq!(
            observed(&images[3]),
            [
                common_dev.as_slice(),
                &[
                    ("/input", true, false),
                    ("/proc", true, false),
                    ("/tmp", true, false),
                    ("/validator/validator.jar", false, true),
                ],
            ]
            .concat()
        );

        assert!(images[0].jvm_release().is_none());
        assert!(images[2].jvm_release().is_none());
        let build_release = images[1].jvm_release().unwrap();
        assert_eq!(build_release.image_path(), "/runtime/release");
        assert_eq!(build_release.byte_length(), 128);
        assert_eq!(build_release.sha256(), [0x62; DIGEST_BYTES]);
        assert_eq!(build_release.feature_version(), 21);
        assert_eq!(build_release.vendor(), "Fixture JVM");
        assert_eq!(build_release.version(), "21.0.1");
        assert_eq!(images[3].jvm_release().unwrap(), build_release);
    }

    #[test]
    fn positive_gate_projects_closed_jvm_executable_identities() {
        let materialized = Fixture::valid().materialize();
        let bindings = materialized.bind().unwrap();
        let images = bindings.oci_image_layouts();

        assert!(images[0].jvm_executables().is_none());
        assert!(images[2].jvm_executables().is_none());

        let build = images[1].jvm_executables().unwrap();
        let build_launcher = build.launcher();
        assert_eq!(build_launcher.image_path(), "/runtime/bin/java");
        assert_eq!(build_launcher.byte_length(), 64);
        assert_eq!(build_launcher.sha256(), [0x61; DIGEST_BYTES]);
        assert_eq!(build_launcher.elf_type(), "et-dyn");
        assert_eq!(build_launcher.os_abi(), "sysv");
        assert_eq!(build_launcher.program_header_count(), 11);
        assert_eq!(build_launcher.section_header_count(), 30);
        assert_eq!(build_launcher.load_segment_count(), 4);
        assert_eq!(build_launcher.executable_load_segment_count(), 1);
        assert_eq!(
            build_launcher.interpreter_path(),
            "/lib64/ld-linux-x86-64.so.2"
        );
        assert_eq!(build_launcher.dynamic_entry_count(), 20);
        assert_eq!(build_launcher.needed_library_count(), 3);
        assert_eq!(build_launcher.gnu_stack_segment_count(), 1);

        let build_compiler = build.compiler().unwrap();
        assert_eq!(build_compiler.image_path(), "/runtime/bin/javac");
        assert_eq!(build_compiler.byte_length(), 64);
        assert_eq!(build_compiler.sha256(), [0x63; DIGEST_BYTES]);
        assert_eq!(build_compiler.elf_type(), "et-dyn");
        assert_eq!(build_compiler.os_abi(), "sysv");
        assert_eq!(build_compiler.program_header_count(), 11);
        assert_eq!(build_compiler.section_header_count(), 30);
        assert_eq!(build_compiler.load_segment_count(), 4);
        assert_eq!(build_compiler.executable_load_segment_count(), 1);
        assert_eq!(
            build_compiler.interpreter_path(),
            "/lib64/ld-linux-x86-64.so.2"
        );
        assert_eq!(build_compiler.dynamic_entry_count(), 20);
        assert_eq!(build_compiler.needed_library_count(), 3);
        assert_eq!(build_compiler.gnu_stack_segment_count(), 1);

        let verifier = images[3].jvm_executables().unwrap();
        assert_eq!(verifier.launcher(), build_launcher);
        assert!(verifier.compiler().is_none());
    }

    #[test]
    fn positive_gate_projects_closed_startup_dependency_policy() {
        let materialized = Fixture::valid().materialize();
        let bindings = materialized.bind().unwrap();
        let images = bindings.oci_image_layouts();

        assert!(images[0].jvm_executables().is_none());
        assert!(images[2].jvm_executables().is_none());

        let build = images[1].jvm_executables().unwrap();
        assert_eq!(
            build.startup_dependency_policy().policy_id(),
            STARTUP_DEPENDENCY_POLICY_ID
        );

        let verifier = images[3].jvm_executables().unwrap();
        assert_eq!(
            verifier.startup_dependency_policy().policy_id(),
            STARTUP_DEPENDENCY_POLICY_ID
        );
    }

    #[test]
    fn positive_gate_rejects_missing_startup_dependency_policy() {
        for (profile_index, runtime_field) in [(1, "buildJdk"), (3, "javaRuntime")] {
            let mut fixture = Fixture::valid();
            fixture.runner_values[profile_index][runtime_field]
                .as_object_mut()
                .unwrap()
                .remove("startupDependencyPolicy");

            let error = fixture.materialize().bind().unwrap_err();
            assert!(
                format!("{error:#}").contains("fails Draft 2020-12 schema"),
                "{runtime_field} missing-policy mutant reached an unexpected boundary: {error:#}"
            );
        }
    }

    #[test]
    fn positive_gate_rejects_unknown_startup_dependency_policy() {
        for (profile_index, runtime_field) in [(1, "buildJdk"), (3, "javaRuntime")] {
            let mut fixture = Fixture::valid();
            fixture.runner_values[profile_index][runtime_field]["startupDependencyPolicy"] =
                json!("eip0045-b4-elf64-amd64-startup-dependency-closure-unknown");

            let error = fixture.materialize().bind().unwrap_err();
            assert!(
                format!("{error:#}").contains("fails Draft 2020-12 schema"),
                "{runtime_field} unknown-policy mutant reached an unexpected boundary: {error:#}"
            );
        }
    }

    #[test]
    fn positive_projection_rejects_unknown_startup_dependency_policy_defense_in_depth() {
        fn document(value: Value) -> BoundDocument {
            BoundDocument {
                relative_path: String::new(),
                bytes: Vec::new(),
                value,
                sha256: String::new(),
            }
        }

        let fixture = Fixture::valid();
        for (profile_index, runtime_field, role) in [
            (1, "buildJdk", PositiveRunnerRole::JvmValidatorBuild),
            (3, "javaRuntime", PositiveRunnerRole::JvmVerifier),
        ] {
            let mut profile = fixture.runner_values[profile_index].clone();
            profile[runtime_field]["startupDependencyPolicy"] =
                json!("eip0045-b4-elf64-amd64-startup-dependency-closure-unknown");

            let error = project_positive_oci_image_layout(&document(profile), role).unwrap_err();
            assert!(
                format!("{error:#}").contains("unsupported startup-dependency policy"),
                "{runtime_field} unknown-policy mutant reached an unexpected projection boundary: {error:#}"
            );
        }
    }

    #[test]
    fn jvm_executable_projection_keeps_distinct_nested_elf_fields() {
        fn document(value: Value) -> BoundDocument {
            BoundDocument {
                relative_path: String::new(),
                bytes: Vec::new(),
                value,
                sha256: String::new(),
            }
        }

        let fixture = Fixture::valid();
        let mut build = fixture.runner_values[1].clone();
        build["buildJdk"]["launcher"]["elf"]["executableLoadSegmentCount"] = json!(2);
        build["buildJdk"]["launcher"]["elf"]["gnuStackSegmentCount"] = json!(1);
        build["buildJdk"]["compiler"]["elf"]["programHeaderCount"] = json!(13);
        build["buildJdk"]["compiler"]["elf"]["dynamicEntryCount"] = json!(19);
        let projected_build = project_positive_oci_image_layout(
            &document(build),
            PositiveRunnerRole::JvmValidatorBuild,
        )
        .unwrap();
        let projected_build = projected_build.jvm_executables().unwrap();
        assert_eq!(
            projected_build.launcher().executable_load_segment_count(),
            2
        );
        assert_eq!(projected_build.launcher().gnu_stack_segment_count(), 1);
        assert_eq!(
            projected_build.compiler().unwrap().program_header_count(),
            13
        );
        assert_eq!(
            projected_build.compiler().unwrap().dynamic_entry_count(),
            19
        );

        let mut verifier = fixture.runner_values[3].clone();
        verifier["javaRuntime"]["binary"]["sha256"] = json!(digest(0x91));
        verifier["javaRuntime"]["binary"]["elf"]["sectionHeaderCount"] = json!(29);
        verifier["javaRuntime"]["binary"]["elf"]["neededLibraryCount"] = json!(2);
        let projected_verifier =
            project_positive_oci_image_layout(&document(verifier), PositiveRunnerRole::JvmVerifier)
                .unwrap();
        let projected_verifier = projected_verifier.jvm_executables().unwrap();
        assert_eq!(projected_verifier.launcher().sha256(), [0x91; DIGEST_BYTES]);
        assert_eq!(projected_verifier.launcher().section_header_count(), 29);
        assert_eq!(projected_verifier.launcher().needed_library_count(), 2);
        assert!(projected_verifier.compiler().is_none());
    }

    #[test]
    fn elf_manifest_and_ustar_relations_reject_isolated_drifts() {
        let baseline = Fixture::valid();
        assert_eq!(
            canonical_oci_index_bytes(&baseline.runner_values[0]["image"])
                .unwrap()
                .len(),
            289
        );
        assert_eq!(
            expected_oci_archive_byte_length(&baseline.runner_values[0]["image"]).unwrap(),
            6_656
        );
        for (payload_bytes, expected_extent) in [
            (0, 512),
            (1, 1_024),
            (511, 1_024),
            (512, 1_024),
            (513, 1_536),
            (8_589_934_591, 8_589_935_104),
        ] {
            assert_eq!(ustar_member_extent(payload_bytes).unwrap(), expected_extent);
        }

        let mut runner_exec_load = Fixture::valid();
        runner_exec_load.runner_values[0]["runtime"]["binary"]["elf"]["executableLoadSegmentCount"] =
            json!(4);
        let error = runner_exec_load.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("executable-load"));

        let mut runner_program_headers = Fixture::valid();
        runner_program_headers.runner_values[0]["runtime"]["binary"]["elf"]["loadSegmentCount"] =
            json!(7);
        let error = runner_program_headers.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("program-header"));

        let mut native_exec_load = Fixture::valid();
        native_exec_load.descriptor_values[0]["artifact"]["elf"]["executableLoadSegmentCount"] =
            json!(4);
        let error = native_exec_load.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("executable-load"));

        let mut java_program_headers = Fixture::valid();
        java_program_headers.runner_values[3]["javaRuntime"]["binary"]["elf"]["loadSegmentCount"] =
            json!(12);
        let error = java_program_headers.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("program-header"));

        let mut exact_runtime_linkage_minimum = Fixture::valid();
        exact_runtime_linkage_minimum.runner_values[3]["javaRuntime"]["binary"]["elf"]["dynamicEntryCount"] =
            json!(6);
        exact_runtime_linkage_minimum.runner_values[3]["javaRuntime"]["binary"]["elf"]["neededLibraryCount"] =
            json!(3);
        exact_runtime_linkage_minimum.materialize().bind().unwrap();

        let mut empty_runtime_linkage = Fixture::valid();
        empty_runtime_linkage.runner_values[3]["javaRuntime"]["binary"]["elf"]["dynamicEntryCount"] =
            json!(1);
        empty_runtime_linkage.runner_values[3]["javaRuntime"]["binary"]["elf"]["neededLibraryCount"] =
            json!(0);
        empty_runtime_linkage.materialize().bind().unwrap();

        let mut impossible_runtime_linkage = Fixture::valid();
        impossible_runtime_linkage.runner_values[3]["javaRuntime"]["binary"]["elf"]["dynamicEntryCount"] =
            json!(5);
        impossible_runtime_linkage.runner_values[3]["javaRuntime"]["binary"]["elf"]["neededLibraryCount"] =
            json!(3);
        let error = impossible_runtime_linkage.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("dynamic-entry count"));

        let mut manifest_attributes = Fixture::valid();
        manifest_attributes.descriptor_values[1]["artifact"]["manifest"]["createdByAttributeCount"] =
            json!(1);
        let error = manifest_attributes.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("main-attribute"));

        let mut manifest_length = Fixture::valid();
        manifest_length.descriptor_values[1]["artifact"]["manifest"]["manifestByteLength"] =
            json!(101);
        let error = manifest_length.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("manifest length"));

        let mut exact_layer_maximum = Fixture::valid();
        exact_layer_maximum.runner_values[0]["image"]["layers"][0]["size"] =
            json!(8_589_934_591_u64);
        let expected_archive_bytes =
            expected_oci_archive_byte_length(&exact_layer_maximum.runner_values[0]["image"])
                .unwrap();
        assert_eq!(expected_archive_bytes, 8_589_940_224);
        exact_layer_maximum.runner_values[0]["image"]["archive"]["byteLength"] =
            json!(expected_archive_bytes);
        exact_layer_maximum.materialize().bind().unwrap();

        let mut layer_overflow = Fixture::valid();
        layer_overflow.runner_values[0]["image"]["layers"][0]["size"] = json!(8_589_934_592_u64);
        let error = layer_overflow.materialize().bind().unwrap_err();
        assert!(format!("{error:#}").contains("fails Draft 2020-12 schema"));

        for field_name in [
            "centralDirectoryOrderMismatchCount",
            "versionFieldMismatchCount",
            "nonCanonicalTimestampCount",
            "utf8FlagMissingCount",
            "nonZeroAttributeCount",
            "canonicalEntryOrderMismatchCount",
        ] {
            let mut archive_drift = Fixture::valid();
            archive_drift.descriptor_values[1]["artifact"]["archive"][field_name] = json!(1);
            let error = archive_drift.materialize().bind().unwrap_err();
            assert!(
                format!("{error:#}").contains("fails Draft 2020-12 schema"),
                "archive field {field_name} rejected at an unexpected boundary: {error:#}"
            );
        }

        for field_name in [
            "addExportsAttributeCount",
            "addOpensAttributeCount",
            "javaFxApplicationClassAttributeCount",
        ] {
            let mut manifest_drift = Fixture::valid();
            manifest_drift.descriptor_values[1]["artifact"]["manifest"][field_name] = json!(1);
            let error = manifest_drift.materialize().bind().unwrap_err();
            assert!(
                format!("{error:#}").contains("fails Draft 2020-12 schema"),
                "manifest field {field_name} rejected at an unexpected boundary: {error:#}"
            );
        }
    }

    #[test]
    fn provenance_non_alias_environment_and_role_matrix_rejects() {
        let mut cases: Vec<(&str, Fixture, &str)> = Vec::new();

        let mut source_tuple = Fixture::valid();
        for key in ["repository", "commit", "tree"] {
            source_tuple.descriptor_values[1]["reviewedSource"][key] =
                source_tuple.descriptor_values[0]["reviewedSource"][key].clone();
        }
        cases.push(("source tuple", source_tuple, "reviewed source tuple"));

        let mut source_archive = Fixture::valid();
        source_archive.descriptor_values[1]["reviewedSource"]["archive"]["sha256"] =
            source_archive.descriptor_values[0]["reviewedSource"]["archive"]["sha256"].clone();
        cases.push(("source archive", source_archive, "source archive digest"));

        let mut lineage = Fixture::valid();
        lineage.descriptor_values[1]["implementationLineage"]["lineageSha256"] =
            lineage.descriptor_values[0]["implementationLineage"]["lineageSha256"].clone();
        cases.push(("lineage", lineage, "lineage digest"));

        let mut entrypoint = Fixture::valid();
        entrypoint.descriptor_values[1]["entrypoint"]["kind"] =
            entrypoint.descriptor_values[0]["entrypoint"]["kind"].clone();
        cases.push(("entrypoint", entrypoint, "fails Draft 2020-12 schema"));

        let mut fixed_environment = Fixture::valid();
        fixed_environment.descriptor_values[0]["deterministicBuild"]["environment"]["variables"] =
            json!([{"name": "LANG", "value": "other"}]);
        cases.push((
            "fixed environment",
            fixed_environment,
            "fails Draft 2020-12 schema",
        ));

        let mut unsorted_environment = Fixture::valid();
        unsorted_environment.descriptor_values[0]["deterministicBuild"]["environment"]["variables"] = json!([
            {"name": "ZED", "value": "1"},
            {"name": "ALPHA", "value": "2"}
        ]);
        cases.push((
            "unsorted environment",
            unsorted_environment,
            "fails Draft 2020-12 schema",
        ));

        let mut role = Fixture::valid();
        role.runner_values[0]["runnerProfileIndex"] = json!(1);
        cases.push(("runner role", role, "fails Draft 2020-12 schema"));

        for (label, fixture, expected) in cases {
            let error = fixture.materialize().bind().unwrap_err();
            assert!(
                format!("{error:#}").contains(expected),
                "{label} rejected at an unexpected boundary: {error:#}"
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn generation_phase_binds_physical_exports_and_global_paths() {
        let bindings = Fixture::valid().materialize().bind().unwrap();
        let nested_paths = [
            (
                "guest",
                string_field(
                    field(field(&bindings.input_set.value, "guest").unwrap(), "elf").unwrap(),
                    "path",
                )
                .unwrap()
                .to_owned(),
            ),
            (
                "profile",
                string_field(
                    field(&bindings.input_set.value, "profile")
                        .and_then(|profile| field(profile, "manifest"))
                        .unwrap(),
                    "path",
                )
                .unwrap()
                .to_owned(),
            ),
            (
                "dependency",
                string_field(
                    field(
                        &bindings.validator_descriptors[0].value,
                        "dependencyClosure",
                    )
                    .and_then(|closure| array_field(closure, "entries"))
                    .map(|entries| field(&entries[0], "artifact").unwrap())
                    .unwrap(),
                    "path",
                )
                .unwrap()
                .to_owned(),
            ),
            (
                "toolchain runtime",
                string_field(
                    field(&bindings.runner_profiles[0].value, "runtime")
                        .and_then(|runtime| field(runtime, "binary"))
                        .unwrap(),
                    "path",
                )
                .unwrap()
                .to_owned(),
            ),
            (
                "OCI archive",
                string_field(
                    field(&bindings.runner_profiles[0].value, "image")
                        .and_then(|image| field(image, "archive"))
                        .unwrap(),
                    "path",
                )
                .unwrap()
                .to_owned(),
            ),
        ];
        let authority = bindings.campaign_precommit_authority();
        for (label, path) in nested_paths {
            assert!(
                bindings.provenance_paths.contains(&path),
                "positive provenance omitted nested {label} path {path}"
            );
            assert!(
                authority.provenance_paths().contains(&path),
                "opaque positive authority omitted nested {label} path {path}"
            );
        }
        Fixture::valid().materialize().bind_generation().unwrap();

        let dangerous_input_path = Fixture::valid().materialize();
        let error = dangerous_input_path
            .bind_with_input_path("../input.json")
            .unwrap_err();
        assert!(format!("{error:#}").contains("path is not canonical"));

        let generation_alias = Fixture::valid().materialize();
        let error = generation_alias
            .bind_generation_at("locks/source-lock.json")
            .unwrap_err();
        assert!(format!("{error:#}").contains("aliases or ancestor/descendant"));

        let generation_descendant = Fixture::valid().materialize();
        let error = generation_descendant
            .bind_generation_at("locks/source-lock.json/child")
            .unwrap_err();
        assert!(format!("{error:#}").contains("ancestor/descendant"));

        let mut generator_drift = Fixture::valid().materialize();
        generator_drift.proof_generator_artifact[0] ^= 1;
        let error = generator_drift.bind_generation().unwrap_err();
        assert!(format!("{error:#}").contains("proof generator artifact digest"));

        let mut case_drift = Fixture::valid().materialize();
        case_drift.generation_value["cases"][0]["caseId"] = json!("lift-po2-16");
        case_drift.generation_bytes = canonical_json_bytes(&case_drift.generation_value).unwrap();
        let error = case_drift.bind_generation().unwrap_err();
        assert!(
            format!("{error:#}").contains("positive generation set fails Draft 2020-12 schema")
        );

        let mut physical_drift = Fixture::valid().materialize();
        physical_drift.generation_cases[0]
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.source_file == "candidate-raw-seal.bin")
            .unwrap()
            .bytes[0] ^= 1;
        let error = physical_drift.bind_generation().unwrap_err();
        assert!(format!("{error:#}").contains("generated raw-seal artifact digest"));

        let mut duplicate_raw_seal = Fixture::valid().materialize();
        let raw_seal = duplicate_raw_seal.generation_cases[0]
            .artifacts
            .iter()
            .find(|artifact| artifact.source_file == "candidate-raw-seal.bin")
            .unwrap()
            .bytes
            .clone();
        duplicate_raw_seal.generation_cases[1]
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.source_file == "candidate-raw-seal.bin")
            .unwrap()
            .bytes = raw_seal;
        refresh_generation_case(&mut duplicate_raw_seal, 1);
        let error = duplicate_raw_seal.bind_generation().unwrap_err();
        assert!(format!("{error:#}").contains("reuses a raw-seal digest"));

        let mut duplicate_manifest = Fixture::valid().materialize();
        duplicate_manifest.generation_cases[1] = duplicate_manifest.generation_cases[0].clone();
        refresh_generation_case(&mut duplicate_manifest, 1);
        let error = duplicate_manifest.bind_generation().unwrap_err();
        assert!(format!("{error:#}").contains("reuses a proof-output manifest digest"));

        let mut calibration_swap = Fixture::valid().materialize();
        let calibration = calibration_swap.generation_cases[8]
            .artifacts
            .iter()
            .find(|artifact| artifact.source_file == "candidate-recursive-calibration.json")
            .unwrap()
            .bytes
            .clone();
        calibration_swap.generation_cases[9]
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.source_file == "candidate-recursive-calibration.json")
            .unwrap()
            .bytes = calibration;
        refresh_generation_case(&mut calibration_swap, 9);
        let error = calibration_swap.bind_generation().unwrap_err();
        assert!(format!("{error:#}").contains("pre-proof calibration"));
    }

    #[test]
    fn recursive_generation_binds_full_physical_exports_without_promoting_auxiliary_seals() {
        let mut materialized = Fixture::valid().materialize();
        populate_recursive_auxiliary_artifacts(&mut materialized);

        for (index, expected_manifest_count) in [(8, 10), (9, 10), (10, 12)] {
            assert_eq!(
                materialized.generation_value["cases"][index]["artifacts"]
                    .as_array()
                    .unwrap()
                    .len(),
                RECURSIVE_ARTIFACT_LAYOUT.len(),
                "recursive primary role inventory changed at case {index}"
            );
            assert_eq!(
                materialized.generation_cases[index].artifacts.len(),
                RECURSIVE_ARTIFACT_LAYOUT.len(),
                "recursive physical primary inventory changed at case {index}"
            );
            assert_eq!(
                materialized.generation_cases[index]
                    .auxiliary_artifacts
                    .len(),
                expected_manifest_count - RECURSIVE_ARTIFACT_LAYOUT.len(),
                "recursive auxiliary inventory drifted at case {index}"
            );
            let manifest: ProofOutputManifest = serde_json::from_slice(
                &materialized.generation_cases[index].proof_output_manifest_jcs,
            )
            .unwrap();
            assert_eq!(manifest.len(), expected_manifest_count);
        }

        materialized.bind_generation().unwrap();
    }

    fn assert_recursive_auxiliary_rejection(
        index: usize,
        mutate: impl FnOnce(&mut MaterializedFixture),
        expected_error: &str,
    ) {
        let mut materialized = Fixture::valid().materialize();
        populate_recursive_auxiliary_artifacts(&mut materialized);
        mutate(&mut materialized);
        let error = materialized
            .validate_generation_case_only(index)
            .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains(expected_error),
            "expected {expected_error:?}, got {rendered:?}"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn recursive_auxiliary_custody_rejects_every_inventory_identity_and_content_drift() {
        assert_recursive_auxiliary_rejection(
            8,
            |materialized| {
                materialized.generation_cases[8].auxiliary_artifacts.pop();
            },
            "auxiliary artifact cardinality",
        );
        assert_recursive_auxiliary_rejection(
            8,
            |materialized| {
                materialized.generation_cases[8].auxiliary_artifacts.push(
                    OwnedGenerationArtifact {
                        source_file: "unmanifested-recursive-auxiliary-raw-seal.bin",
                        bytes: vec![0x44; PROOF_BYTES],
                    },
                );
            },
            "auxiliary artifact cardinality",
        );
        assert_recursive_auxiliary_rejection(
            8,
            |materialized| {
                materialized.generation_cases[8]
                    .auxiliary_artifacts
                    .swap(0, 1);
            },
            "path or order",
        );
        assert_recursive_auxiliary_rejection(
            8,
            |materialized| {
                let duplicate_path =
                    materialized.generation_cases[8].auxiliary_artifacts[0].source_file;
                materialized.generation_cases[8].auxiliary_artifacts[1].source_file =
                    duplicate_path;
            },
            "path or order",
        );
        assert_recursive_auxiliary_rejection(
            8,
            |materialized| {
                materialized.generation_cases[8].auxiliary_artifacts[0].source_file =
                    positive_auxiliary_artifact_paths(9).unwrap()[0];
            },
            "path or order",
        );
        assert_recursive_auxiliary_rejection(
            8,
            |materialized| {
                materialized.generation_cases[8].auxiliary_artifacts[0].source_file =
                    "wrong/recursive-auxiliary-raw-seal.bin";
            },
            "path or order",
        );
        assert_recursive_auxiliary_rejection(
            8,
            |materialized| {
                materialized.generation_cases[8].auxiliary_artifacts[0]
                    .bytes
                    .pop();
            },
            "wrong exact byte length",
        );
        assert_recursive_auxiliary_rejection(
            8,
            |materialized| {
                materialized.generation_cases[8].auxiliary_artifacts[0].bytes[0] ^= 0xff;
            },
            "differs from the exact artifact snapshot",
        );
        assert_recursive_auxiliary_rejection(
            8,
            |materialized| {
                let promoted = materialized.generation_cases[8].auxiliary_artifacts[0].clone();
                materialized.generation_cases[8].artifacts.push(promoted);
            },
            "artifact cardinality differs from the closed case layout",
        );
        assert_recursive_auxiliary_rejection(
            8,
            |materialized| {
                materialized.generation_value["cases"][8]["artifacts"][7]["role"] =
                    json!("raw-seal");
            },
            "role differs from receipt-oracle",
        );

        assert_recursive_auxiliary_rejection(
            8,
            |materialized| {
                let mut manifest: ProofOutputManifest = serde_json::from_slice(
                    &materialized.generation_cases[8].proof_output_manifest_jcs,
                )
                .unwrap();
                manifest.pop();
                replace_recursive_manifest(materialized, 8, manifest);
            },
            "differs from the exact artifact snapshot",
        );
        assert_recursive_auxiliary_rejection(
            8,
            |materialized| {
                let mut manifest: ProofOutputManifest = serde_json::from_slice(
                    &materialized.generation_cases[8].proof_output_manifest_jcs,
                )
                .unwrap();
                manifest.push(ManifestEntry {
                    path: "unexpected-manifest-member.bin".to_owned(),
                    length: PROOF_BYTES.to_string(),
                    sha256: "00".repeat(32),
                });
                manifest.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
                replace_recursive_manifest(materialized, 8, manifest);
            },
            "differs from the exact artifact snapshot",
        );
        assert_recursive_auxiliary_rejection(
            8,
            |materialized| {
                let mut manifest: ProofOutputManifest = serde_json::from_slice(
                    &materialized.generation_cases[8].proof_output_manifest_jcs,
                )
                .unwrap();
                manifest.swap(0, 1);
                replace_recursive_manifest(materialized, 8, manifest);
            },
            "manifest fields are invalid",
        );
        assert_recursive_auxiliary_rejection(
            8,
            |materialized| {
                let mut manifest: ProofOutputManifest = serde_json::from_slice(
                    &materialized.generation_cases[8].proof_output_manifest_jcs,
                )
                .unwrap();
                let duplicate_path = manifest[0].path.clone();
                manifest[1].path = duplicate_path;
                manifest.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
                replace_recursive_manifest(materialized, 8, manifest);
            },
            "manifest fields are invalid",
        );
        assert_recursive_auxiliary_rejection(
            8,
            |materialized| {
                let mut manifest: ProofOutputManifest = serde_json::from_slice(
                    &materialized.generation_cases[8].proof_output_manifest_jcs,
                )
                .unwrap();
                let auxiliary = manifest
                    .iter_mut()
                    .find(|entry| entry.path == positive_auxiliary_artifact_paths(8).unwrap()[0])
                    .unwrap();
                auxiliary.path = positive_auxiliary_artifact_paths(9).unwrap()[0].to_owned();
                manifest.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
                replace_recursive_manifest(materialized, 8, manifest);
            },
            "differs from the exact artifact snapshot",
        );
        assert_recursive_auxiliary_rejection(
            8,
            |materialized| {
                let mut manifest: ProofOutputManifest = serde_json::from_slice(
                    &materialized.generation_cases[8].proof_output_manifest_jcs,
                )
                .unwrap();
                let auxiliary = manifest
                    .iter_mut()
                    .find(|entry| entry.path == positive_auxiliary_artifact_paths(8).unwrap()[0])
                    .unwrap();
                auxiliary.length = (PROOF_BYTES - 1).to_string();
                replace_recursive_manifest(materialized, 8, manifest);
            },
            "differs from the exact artifact snapshot",
        );
        assert_recursive_auxiliary_rejection(
            8,
            |materialized| {
                let mut manifest: ProofOutputManifest = serde_json::from_slice(
                    &materialized.generation_cases[8].proof_output_manifest_jcs,
                )
                .unwrap();
                let auxiliary = manifest
                    .iter_mut()
                    .find(|entry| entry.path == positive_auxiliary_artifact_paths(8).unwrap()[0])
                    .unwrap();
                auxiliary.sha256 = "00".repeat(32);
                replace_recursive_manifest(materialized, 8, manifest);
            },
            "differs from the exact artifact snapshot",
        );
    }

    #[test]
    fn positive_generation_authority_retains_digest_for_every_provenance_path() {
        let materialized = Fixture::valid().materialize();
        let authority = materialized
            .bind_generation()
            .unwrap()
            .positive_generation_authority();
        assert_eq!(
            authority.provenance_paths().len(),
            authority.provenance_sha256().len()
        );
        for path in authority.provenance_paths() {
            assert!(
                authority.provenance_sha256().contains_key(path),
                "missing digest for {path}"
            );
        }
        for path in [
            "deps/independent-jvm/fixture",
            "deps/independent-jvm/lock",
            "deps/rust-reference/fixture",
            "deps/rust-reference/lock",
            "intermediate/jvm-application.jar",
            "runner/image-0.tar",
            "runner/image-1.tar",
            "runner/image-2.tar",
            "runner/image-3.tar",
            "runner/runc-0",
            "runner/runc-1",
            "runner/runc-2",
            "runner/runc-3",
        ] {
            assert!(authority.provenance_sha256().contains_key(path), "{path}");
        }
    }

    #[test]
    fn positive_generation_authority_is_exact_opaque_and_rewrite_sensitive() {
        let original = Fixture::valid().materialize();
        let original_bindings = original.bind_generation().unwrap();
        let authority = original_bindings.positive_generation_authority();

        assert_eq!(
            authority.input_set(),
            &original_bindings.provenance.input_set.contract_identity()
        );
        assert_eq!(
            authority.generation_set(),
            &original_bindings.generation_set.contract_identity()
        );
        assert_eq!(authority.cases().len(), POSITIVE_CASE_COUNT);
        assert!(
            authority
                .provenance_paths()
                .contains(&original_bindings.provenance.input_set.relative_path)
        );
        assert!(
            authority
                .provenance_paths()
                .contains(&original_bindings.generation_set.relative_path)
        );
        for (index, case) in authority.cases().iter().enumerate() {
            assert_eq!(usize::from(case.case_index()), index);
            assert_eq!(
                case.proof_output_manifest(),
                measure_bytes(&original.generation_cases[index].proof_output_manifest_jcs)
            );
            let raw_seal = original.generation_cases[index]
                .artifacts
                .iter()
                .find(|artifact| artifact.source_file == "candidate-raw-seal.bin")
                .unwrap();
            assert_eq!(case.raw_seal(), measure_bytes(&raw_seal.bytes));
        }

        let mut rewritten = Fixture::valid().materialize();
        rewritten.generation_cases[0]
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.source_file == "candidate-raw-seal.bin")
            .unwrap()
            .bytes[0] ^= 1;
        refresh_generation_case(&mut rewritten, 0);
        let rewritten_authority = rewritten
            .bind_generation()
            .unwrap()
            .positive_generation_authority();
        assert_eq!(authority.input_set(), rewritten_authority.input_set());
        assert_ne!(
            authority.generation_set(),
            rewritten_authority.generation_set()
        );
        assert_ne!(
            authority.cases()[0].proof_output_manifest(),
            rewritten_authority.cases()[0].proof_output_manifest()
        );
        assert_ne!(
            authority.cases()[0].raw_seal(),
            rewritten_authority.cases()[0].raw_seal()
        );
    }

    #[test]
    fn run_binding_rejects_authority_commitment_and_semantic_drift() {
        let materialized = Fixture::valid().materialize();
        let bindings = materialized.bind_generation().unwrap();
        let verifier_input_value = verifier_input(&materialized);
        let verifier_input_bytes = canonical_json_bytes(&verifier_input_value).unwrap();
        let (observation_value, observation_bytes) = observation(&materialized);
        let acceptance_value = rust_acceptance(
            &materialized,
            &bindings,
            &verifier_input_bytes,
            &observation_value,
            &observation_bytes,
        );
        let acceptance_bytes = canonical_json_bytes(&acceptance_value).unwrap();
        bindings
            .validate_run(rust_run_documents(
                &materialized,
                &bindings,
                &verifier_input_bytes,
                &observation_bytes,
                &acceptance_bytes,
            ))
            .unwrap();

        let mut authority_drift = verifier_input_value.clone();
        authority_drift["caseId"] = json!("lift-po2-15");
        let authority_bytes = canonical_json_bytes(&authority_drift).unwrap();
        let error = bindings
            .validate_run(rust_run_documents(
                &materialized,
                &bindings,
                &authority_bytes,
                &observation_bytes,
                &acceptance_bytes,
            ))
            .unwrap_err();
        assert!(format!("{error:#}").contains("verifier input fails Draft 2020-12 schema"));

        let mut commitment_drift = acceptance_value.clone();
        commitment_drift["inputSetCommitment"]["sha256"] = json!(digest(0xff));
        let commitment_bytes = canonical_json_bytes(&commitment_drift).unwrap();
        let error = bindings
            .validate_run(rust_run_documents(
                &materialized,
                &bindings,
                &verifier_input_bytes,
                &observation_bytes,
                &commitment_bytes,
            ))
            .unwrap_err();
        assert!(format!("{error:#}").contains("input-set commitment"));

        let mut generation_commitment_drift = acceptance_value.clone();
        generation_commitment_drift["generationSetCommitment"]["sha256"] = json!(digest(0xfd));
        let generation_commitment_bytes =
            canonical_json_bytes(&generation_commitment_drift).unwrap();
        let error = bindings
            .validate_run(rust_run_documents(
                &materialized,
                &bindings,
                &verifier_input_bytes,
                &observation_bytes,
                &generation_commitment_bytes,
            ))
            .unwrap_err();
        assert!(format!("{error:#}").contains("generation-set commitment"));

        let mut forged_observation = observation_value.clone();
        forged_observation["claimDigest"] = json!(digest(0xfe));
        let forged_observation_bytes = canonical_json_bytes(&forged_observation).unwrap();
        let forged_acceptance = rust_acceptance(
            &materialized,
            &bindings,
            &verifier_input_bytes,
            &forged_observation,
            &forged_observation_bytes,
        );
        let forged_acceptance_bytes = canonical_json_bytes(&forged_acceptance).unwrap();
        let documents = rust_run_documents(
            &materialized,
            &bindings,
            &verifier_input_bytes,
            &forged_observation_bytes,
            &forged_acceptance_bytes,
        );
        let error = bindings.validate_run(documents).unwrap_err();
        assert!(format!("{error:#}").contains("independently derived input semantics"));
    }

    #[test]
    fn acceptance_projection_and_physical_measurement_matrix_rejects() {
        let materialized = Fixture::valid().materialize();
        let bindings = materialized.bind_generation().unwrap();
        let verifier_input_bytes = canonical_json_bytes(&verifier_input(&materialized)).unwrap();
        let (observation_value, observation_bytes) = observation(&materialized);
        let acceptance_value = rust_acceptance(
            &materialized,
            &bindings,
            &verifier_input_bytes,
            &observation_value,
            &observation_bytes,
        );

        let mutations = [
            (
                "descriptor",
                &["implementationBinding", "buildDescriptor", "sha256"][..],
                "descriptor commitment",
            ),
            (
                "artifact",
                &["implementationBinding", "launchedArtifact", "sha256"][..],
                "launched-artifact binding",
            ),
            (
                "runner",
                &[
                    "implementationBinding",
                    "executionRunnerProfile",
                    "artifact",
                    "sha256",
                ][..],
                "execution-runner commitment",
            ),
            (
                "lineage",
                &["implementationBinding", "lineageSha256"][..],
                "lineage binding",
            ),
            (
                "source",
                &["implementationBinding", "reviewedSource", "tree"][..],
                "reviewed-source binding",
            ),
        ];
        for (label, path, expected) in mutations {
            let mut changed = acceptance_value.clone();
            let replacement = if label == "source" {
                json!("f".repeat(40))
            } else {
                json!(digest(0xee))
            };
            set_path(&mut changed, path, replacement);
            let changed_bytes = canonical_json_bytes(&changed).unwrap();
            let error = bindings
                .validate_run(rust_run_documents(
                    &materialized,
                    &bindings,
                    &verifier_input_bytes,
                    &observation_bytes,
                    &changed_bytes,
                ))
                .unwrap_err();
            assert!(
                format!("{error:#}").contains(expected),
                "{label} rejected at an unexpected boundary: {error:#}"
            );
        }

        let acceptance_bytes = canonical_json_bytes(&acceptance_value).unwrap();
        let mut physical = rust_run_documents(
            &materialized,
            &bindings,
            &verifier_input_bytes,
            &observation_bytes,
            &acceptance_bytes,
        );
        physical.launched_artifact.sha256 = [0xee; 32];
        let error = bindings.validate_run(physical).unwrap_err();
        assert!(format!("{error:#}").contains("physical measurement"));

        let mut input_physical = rust_run_documents(
            &materialized,
            &bindings,
            &verifier_input_bytes,
            &observation_bytes,
            &acceptance_bytes,
        );
        let mut changed_statement = materialized.verifier_files.statement.clone();
        changed_statement[0] ^= 1;
        input_physical.verifier_files.statement = &changed_statement;
        let error = bindings.validate_run(input_physical).unwrap_err();
        assert!(format!("{error:#}").contains("statement digest"));
    }

    #[test]
    fn rust_and_jvm_acceptances_bind_same_bytes_and_exact_java_runtime() {
        let materialized = Fixture::valid().materialize();
        let bindings = materialized.bind_generation().unwrap();
        let verifier_input_bytes = canonical_json_bytes(&verifier_input(&materialized)).unwrap();
        let (observation_value, observation_bytes) = observation(&materialized);
        let rust_acceptance_bytes = canonical_json_bytes(&rust_acceptance(
            &materialized,
            &bindings,
            &verifier_input_bytes,
            &observation_value,
            &observation_bytes,
        ))
        .unwrap();
        let jvm_acceptance_value = jvm_acceptance(
            &materialized,
            &bindings,
            &verifier_input_bytes,
            &observation_value,
            &observation_bytes,
        );
        let jvm_acceptance_bytes = canonical_json_bytes(&jvm_acceptance_value).unwrap();

        let rust = bindings
            .validate_run(rust_run_documents(
                &materialized,
                &bindings,
                &verifier_input_bytes,
                &observation_bytes,
                &rust_acceptance_bytes,
            ))
            .unwrap();
        let jvm = bindings
            .validate_run(jvm_run_documents(
                &materialized,
                &verifier_input_bytes,
                &observation_bytes,
                &jvm_acceptance_bytes,
            ))
            .unwrap();
        let expected_rust_acceptance: [u8; DIGEST_BYTES] =
            Sha256::digest(&rust_acceptance_bytes).into();
        let expected_jvm_acceptance: [u8; DIGEST_BYTES] =
            Sha256::digest(&jvm_acceptance_bytes).into();
        assert_eq!(rust.acceptance_sha256, expected_rust_acceptance);
        assert_eq!(jvm.acceptance_sha256, expected_jvm_acceptance);
        bindings.validate_differential_pair(&rust, &jvm).unwrap();

        let mut stale_java = jvm_acceptance_value.clone();
        stale_java["implementationBinding"]["javaRuntime"]["binary"]["sha256"] =
            json!(digest(0xee));
        let stale_java_bytes = canonical_json_bytes(&stale_java).unwrap();
        let error = bindings
            .validate_run(jvm_run_documents(
                &materialized,
                &verifier_input_bytes,
                &observation_bytes,
                &stale_java_bytes,
            ))
            .unwrap_err();
        assert!(format!("{error:#}").contains("Java runtime binding"));

        let mut stale_release = jvm_acceptance_value.clone();
        stale_release["implementationBinding"]["javaRuntime"]["release"]["sha256"] =
            json!(digest(0xed));
        let stale_release_bytes = canonical_json_bytes(&stale_release).unwrap();
        let error = bindings
            .validate_run(jvm_run_documents(
                &materialized,
                &verifier_input_bytes,
                &observation_bytes,
                &stale_release_bytes,
            ))
            .unwrap_err();
        assert!(format!("{error:#}").contains("Java runtime binding"));

        let mut stale_feature = jvm_acceptance_value;
        stale_feature["implementationBinding"]["javaRuntime"]["featureVersion"] = json!(22);
        let stale_feature_bytes = canonical_json_bytes(&stale_feature).unwrap();
        let error = bindings
            .validate_run(jvm_run_documents(
                &materialized,
                &verifier_input_bytes,
                &observation_bytes,
                &stale_feature_bytes,
            ))
            .unwrap_err();
        assert!(format!("{error:#}").contains("fails Draft 2020-12 schema"));

        let mut physical_java = jvm_run_documents(
            &materialized,
            &verifier_input_bytes,
            &observation_bytes,
            &jvm_acceptance_bytes,
        );
        physical_java.java_binary.as_mut().unwrap().sha256 = [0xee; 32];
        let error = bindings.validate_run(physical_java).unwrap_err();
        assert!(format!("{error:#}").contains("Java binary digest"));

        let mut physical_release = jvm_run_documents(
            &materialized,
            &verifier_input_bytes,
            &observation_bytes,
            &jvm_acceptance_bytes,
        );
        physical_release.java_release.as_mut().unwrap().sha256 = [0xec; 32];
        let error = bindings.validate_run(physical_release).unwrap_err();
        assert!(format!("{error:#}").contains("Java release digest"));
    }

    fn set_path(value: &mut Value, path: &[&str], replacement: Value) {
        let (last, parents) = path.split_last().unwrap();
        let mut current = value;
        for key in parents {
            current = current.get_mut(*key).unwrap();
        }
        current[*last] = replacement;
    }

    #[test]
    fn differential_pair_requires_exact_case_input_and_observation_bytes() {
        let materialized = Fixture::valid().materialize();
        let bindings = materialized.bind_generation().unwrap();
        let base = ValidatedPositiveRun {
            case_index: 0,
            implementation: PositiveImplementation::RustReference,
            input_set_sha256: Sha256::digest(&bindings.provenance.input_set.bytes).into(),
            generation_set_sha256: Sha256::digest(&bindings.generation_set.bytes).into(),
            proof_output_manifest_sha256: bindings.cases[0].proof_output_manifest.sha256,
            raw_seal_sha256: bindings.cases[0].raw_seal.sha256,
            acceptance_sha256: [0x41; DIGEST_BYTES],
            verifier_input_jcs: b"input".to_vec(),
            observation_jcs: b"observation".to_vec(),
        };
        let mut jvm = base.clone();
        jvm.implementation = PositiveImplementation::IndependentJvm;
        jvm.acceptance_sha256 = [0x42; DIGEST_BYTES];
        bindings.validate_differential_pair(&base, &jvm).unwrap();

        let mut reused_acceptance = jvm.clone();
        reused_acceptance.acceptance_sha256 = base.acceptance_sha256;
        assert!(
            bindings
                .validate_differential_pair(&base, &reused_acceptance)
                .is_err()
        );

        jvm.case_index = 1;
        assert!(bindings.validate_differential_pair(&base, &jvm).is_err());
        jvm.case_index = 0;
        jvm.verifier_input_jcs.push(0);
        assert!(bindings.validate_differential_pair(&base, &jvm).is_err());
        jvm.verifier_input_jcs = base.verifier_input_jcs.clone();
        jvm.observation_jcs.push(0);
        assert!(bindings.validate_differential_pair(&base, &jvm).is_err());
        jvm.observation_jcs = base.observation_jcs.clone();
        jvm.generation_set_sha256[0] ^= 1;
        assert!(bindings.validate_differential_pair(&base, &jvm).is_err());
        jvm.generation_set_sha256 = base.generation_set_sha256;
        jvm.proof_output_manifest_sha256[0] ^= 1;
        assert!(bindings.validate_differential_pair(&base, &jvm).is_err());
        jvm.proof_output_manifest_sha256 = base.proof_output_manifest_sha256;
        jvm.raw_seal_sha256[0] ^= 1;
        assert!(bindings.validate_differential_pair(&base, &jvm).is_err());
    }

    #[test]
    fn positive_suite_requires_all_eleven_pairs_once_and_in_order() {
        let materialized = Fixture::valid().materialize();
        let bindings = materialized.bind_generation().unwrap();
        let input_set_sha256: [u8; DIGEST_BYTES] =
            Sha256::digest(&bindings.provenance.input_set.bytes).into();
        let generation_set_sha256: [u8; DIGEST_BYTES] =
            Sha256::digest(&bindings.generation_set.bytes).into();
        let pairs = std::array::from_fn(|index| {
            let index_byte = u8::try_from(index).unwrap();
            let rust = ValidatedPositiveRun {
                case_index: index_byte,
                implementation: PositiveImplementation::RustReference,
                input_set_sha256,
                generation_set_sha256,
                proof_output_manifest_sha256: bindings.cases[index].proof_output_manifest.sha256,
                raw_seal_sha256: bindings.cases[index].raw_seal.sha256,
                acceptance_sha256: [index_byte; DIGEST_BYTES],
                verifier_input_jcs: format!("input-{index}").into_bytes(),
                observation_jcs: format!("observation-{index}").into_bytes(),
            };
            let mut jvm = rust.clone();
            jvm.implementation = PositiveImplementation::IndependentJvm;
            jvm.acceptance_sha256 = [0x80_u8 + index_byte; DIGEST_BYTES];
            bindings.validate_differential_pair(&rust, &jvm).unwrap()
        });

        let suite = bindings.validate_positive_suite(pairs).unwrap();
        assert_eq!(suite.input_set_sha256(), input_set_sha256);
        assert_eq!(suite.generation_set_sha256(), generation_set_sha256);
        assert_eq!(suite.acceptance_sha256s().len(), POSITIVE_ACCEPTANCE_COUNT);
        for index in 0..POSITIVE_CASE_COUNT {
            let index_byte = u8::try_from(index).unwrap();
            assert_eq!(
                suite.acceptance_sha256s()[index * 2],
                [index_byte; DIGEST_BYTES]
            );
            assert_eq!(
                suite.acceptance_sha256s()[index * 2 + 1],
                [0x80_u8 + index_byte; DIGEST_BYTES]
            );
        }

        let duplicate = [pairs[0]; POSITIVE_CASE_COUNT];
        assert!(bindings.validate_positive_suite(duplicate).is_err());

        let mut reordered = pairs;
        reordered.swap(8, 10);
        assert!(bindings.validate_positive_suite(reordered).is_err());

        let mut foreign_root = pairs;
        foreign_root[5].generation_set_sha256[0] ^= 1;
        assert!(bindings.validate_positive_suite(foreign_root).is_err());

        let mut reused_acceptance = pairs;
        reused_acceptance[5].rust_acceptance_sha256 = reused_acceptance[4].jvm_acceptance_sha256;
        assert!(bindings.validate_positive_suite(reused_acceptance).is_err());
    }

    #[test]
    fn positive_input_set_completion_is_derived_from_the_bound_gate_identity() {
        let materialized = Fixture::valid().materialize();
        let paths =
            crate::b4_positive_input_set::project_b4_positive_input_set_publication_paths_v1(
                "phases/prepare-001",
            )
            .unwrap();
        let bindings = materialized
            .bind_with_input_path(paths.input_set_path())
            .unwrap();
        let publication =
            crate::b4_positive_input_set::bind_b4_positive_input_set_publication(&paths, &bindings)
                .unwrap();

        assert_eq!(publication.input_set_jcs(), materialized.input_bytes);

        let completion =
            crate::b4_positive_input_set::derive_b4_positive_input_set_completion_jcs(&publication)
                .unwrap();
        crate::b4_positive_input_set::validate_b4_positive_input_set_completion_jcs(
            &completion,
            &publication,
        )
        .unwrap();

        let value = validate_canonical_json_source(&completion).unwrap();
        assert_eq!(value["format"], "Eip0045B4PositiveInputSetCompletionV1");
        assert_eq!(value["formatVersion"], 1);
        assert_eq!(value["inputSet"]["path"], paths.input_set_path());
        assert_eq!(
            value["inputSet"]["byteLength"],
            materialized.input_bytes.len()
        );
        assert_eq!(
            value["inputSet"]["sha256"],
            sha256_hex(&materialized.input_bytes)
        );
        assert_eq!(value["inputSet"]["encoding"], "rfc8785-jcs");
        assert_eq!(
            publication.completion_path(),
            "phases/prepare-001/positive-input-set-completion.json"
        );

        for (field, replacement) in [
            ("path", json!("phases/prepare-009/positive-input-set.json")),
            ("byteLength", json!(materialized.input_bytes.len() + 1)),
            ("sha256", json!("11".repeat(DIGEST_BYTES))),
            ("encoding", json!("raw-bytes")),
        ] {
            let mut mutated = value.clone();
            mutated["inputSet"][field] = replacement;
            let mutated = canonical_json_bytes(&mutated).unwrap();
            assert!(
                crate::b4_positive_input_set::validate_b4_positive_input_set_completion_jcs(
                    &mutated,
                    &publication,
                )
                .is_err(),
                "{field} mutation unexpectedly passed"
            );
        }
    }

    fn positive_input_set_construction_projection(
        materialized: &MaterializedFixture,
    ) -> PositiveInputSetConstructionProjectionV1<'_> {
        PositiveInputSetConstructionProjectionV1 {
            authoritative_build: &materialized.authoritative_build,
            profile_manifest: serde_json::from_value(
                materialized.input_value["profile"]["manifest"].clone(),
            )
            .unwrap(),
            profile_algorithm: serde_json::from_value(
                materialized.input_value["profile"]["algorithm"].clone(),
            )
            .unwrap(),
            profile_constants: serde_json::from_value(
                materialized.input_value["profile"]["constants"].clone(),
            )
            .unwrap(),
            guest_elf_path: string_field(&materialized.input_value["guest"]["elf"], "path")
                .unwrap(),
            reference_statement_bundle_manifest: serde_json::from_value(
                materialized.input_value["referenceStatement"]["bundleManifest"].clone(),
            )
            .unwrap(),
            source_lock: serde_json::from_value(materialized.input_value["sourceLock"].clone())
                .unwrap(),
            proof_generator_path: string_field(
                &materialized.input_value["proofGenerator"]["artifact"],
                "path",
            )
            .unwrap(),
            verifier_contract: NamedCanonicalJcs {
                relative_path: VERIFIER_CONTRACT_PATH,
                bytes: &materialized.verifier_contract_bytes,
            },
            runner_profiles: std::array::from_fn(|index| NamedCanonicalJcs {
                relative_path: RUNNER_PATHS[index],
                bytes: &materialized.runner_bytes[index],
            }),
            validator_descriptors: std::array::from_fn(|index| NamedCanonicalJcs {
                relative_path: DESCRIPTOR_PATHS[index],
                bytes: &materialized.descriptor_bytes[index],
            }),
            recursive_calibrations: std::array::from_fn(|index| {
                serde_json::from_value(
                    materialized.input_value["recursiveCalibrations"][index]["artifact"].clone(),
                )
                .unwrap()
            }),
        }
    }

    #[test]
    fn canonical_positive_input_set_constructor_is_byte_exact_before_gate_binding() {
        let fixture = Fixture::valid();
        let materialized = fixture.materialize();
        let projection = positive_input_set_construction_projection(&materialized);

        let constructed = construct_canonical_positive_input_set_jcs_v1(projection).unwrap();
        assert_eq!(constructed, materialized.input_bytes);

        PositiveGateBindings::validate_and_bind_jcs(PositiveProvenanceDocuments {
            authoritative_build: &materialized.authoritative_build,
            input_set: NamedCanonicalJcs {
                relative_path: INPUT_SET_PATH,
                bytes: &constructed,
            },
            verifier_contract: NamedCanonicalJcs {
                relative_path: VERIFIER_CONTRACT_PATH,
                bytes: &materialized.verifier_contract_bytes,
            },
            runner_profiles: std::array::from_fn(|index| NamedCanonicalJcs {
                relative_path: RUNNER_PATHS[index],
                bytes: &materialized.runner_bytes[index],
            }),
            seccomp_profiles: std::array::from_fn(|index| NamedCanonicalJcs {
                relative_path: SECCOMP_PATHS[index],
                bytes: &materialized.seccomp_bytes[index],
            }),
            validator_descriptors: std::array::from_fn(|index| NamedCanonicalJcs {
                relative_path: DESCRIPTOR_PATHS[index],
                bytes: &materialized.descriptor_bytes[index],
            }),
            jvm_copy_only_inclusion_manifest: NamedCanonicalJcs {
                relative_path: JVM_COPY_ONLY_INCLUSION_MANIFEST_PATH,
                bytes: &materialized.jvm_copy_only_inclusion_manifest_bytes,
            },
        })
        .unwrap();
    }

    #[test]
    fn canonical_positive_input_set_constructor_rejects_detached_or_noncanonical_inputs() {
        let materialized = Fixture::valid().materialize();

        let mut detached_source_lock = positive_input_set_construction_projection(&materialized);
        detached_source_lock.source_lock.sha256 = "01".repeat(DIGEST_BYTES);
        let error =
            construct_canonical_positive_input_set_jcs_v1(detached_source_lock).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("source lock differs from authoritative B4 validation")
        );

        let mut wrong_profile_encoding = positive_input_set_construction_projection(&materialized);
        wrong_profile_encoding.profile_manifest.encoding = B4ContractArtifactEncodingV1::Rfc8785Jcs;
        let error =
            construct_canonical_positive_input_set_jcs_v1(wrong_profile_encoding).unwrap_err();
        assert!(error.to_string().contains("uses the wrong encoding"));

        let mut noncanonical_contract = positive_input_set_construction_projection(&materialized);
        noncanonical_contract.verifier_contract = NamedCanonicalJcs {
            relative_path: VERIFIER_CONTRACT_PATH,
            bytes: b"{}\n",
        };
        let error =
            construct_canonical_positive_input_set_jcs_v1(noncanonical_contract).unwrap_err();
        assert!(format!("{error:#}").contains("canonical"));
    }

    #[test]
    fn positive_input_set_completion_rejects_another_gate_or_nonlayout_input_path() {
        let materialized = Fixture::valid().materialize();
        let first_paths =
            crate::b4_positive_input_set::project_b4_positive_input_set_publication_paths_v1(
                "phases/prepare-001",
            )
            .unwrap();
        let second_paths =
            crate::b4_positive_input_set::project_b4_positive_input_set_publication_paths_v1(
                "phases/prepare-002",
            )
            .unwrap();
        let first = materialized
            .bind_with_input_path(first_paths.input_set_path())
            .unwrap();
        let second = materialized
            .bind_with_input_path(second_paths.input_set_path())
            .unwrap();
        let first_publication =
            crate::b4_positive_input_set::bind_b4_positive_input_set_publication(
                &first_paths,
                &first,
            )
            .unwrap();
        let second_publication =
            crate::b4_positive_input_set::bind_b4_positive_input_set_publication(
                &second_paths,
                &second,
            )
            .unwrap();
        let completion = crate::b4_positive_input_set::derive_b4_positive_input_set_completion_jcs(
            &first_publication,
        )
        .unwrap();

        assert!(
            crate::b4_positive_input_set::validate_b4_positive_input_set_completion_jcs(
                &completion,
                &second_publication,
            )
            .is_err()
        );

        for invalid_path in [
            "positive-input-set.json",
            "phases/prepare-001/input-set.json",
        ] {
            let gate = materialized.bind_with_input_path(invalid_path).unwrap();
            assert!(
                crate::b4_positive_input_set::bind_b4_positive_input_set_publication(
                    &first_paths,
                    &gate,
                )
                .is_err(),
                "{invalid_path} unexpectedly admitted the closed H0 layout"
            );
        }
    }

    #[test]
    fn h0_publication_binding_rejects_projection_a_with_gate_b() {
        let materialized = Fixture::valid().materialize();
        let paths_a =
            crate::b4_positive_input_set::project_b4_positive_input_set_publication_paths_v1(
                "phases/prepare-a",
            )
            .unwrap();
        let paths_b =
            crate::b4_positive_input_set::project_b4_positive_input_set_publication_paths_v1(
                "phases/prepare-b",
            )
            .unwrap();
        let gate_b = materialized
            .bind_with_input_path(paths_b.input_set_path())
            .unwrap();

        let bound_b =
            crate::b4_positive_input_set::bind_b4_positive_input_set_publication(&paths_b, &gate_b)
                .unwrap();
        let marker_b =
            crate::b4_positive_input_set::derive_b4_positive_input_set_completion_jcs(&bound_b)
                .unwrap();
        crate::b4_positive_input_set::validate_b4_positive_input_set_completion_jcs(
            &marker_b, &bound_b,
        )
        .unwrap();

        let error =
            crate::b4_positive_input_set::bind_b4_positive_input_set_publication(&paths_a, &gate_b)
                .unwrap_err();
        assert!(
            format!("{error:#}")
                .contains("positive input-set path differs from the projected H0 publication")
        );
    }

    #[test]
    fn h0_publication_binding_rejects_all_provenance_collision_orientations() {
        let paths =
            crate::b4_positive_input_set::project_b4_positive_input_set_publication_paths_v1(
                "phases/prepare-001",
            )
            .unwrap();

        for verifier_contract_path in [
            paths.completion_path().to_owned(),
            format!("{}/child.json", paths.completion_path()),
        ] {
            let mut materialized = Fixture::valid().materialize();
            materialized.input_value["verifierCliContract"]["path"] = json!(verifier_contract_path);
            materialized.input_bytes = canonical_json_bytes(&materialized.input_value).unwrap();
            let gate = materialized
                .bind_with_input_and_verifier_paths(paths.input_set_path(), &verifier_contract_path)
                .unwrap();

            let error =
                crate::b4_positive_input_set::bind_b4_positive_input_set_publication(&paths, &gate)
                    .unwrap_err();
            assert!(
                format!("{error:#}").contains(
                    "positive input-set completion path aliases or ancestor/descendant-conflicts with positive provenance"
                )
            );
        }

        let mut materialized = Fixture::valid().materialize();
        materialized.input_value["verifierCliContract"]["path"] = json!(paths.phase_root());
        materialized.input_bytes = canonical_json_bytes(&materialized.input_value).unwrap();
        let error = materialized
            .bind_with_input_and_verifier_paths(paths.input_set_path(), paths.phase_root())
            .unwrap_err();
        assert!(
            format!("{error:#}")
                .contains("pre-proof provenance path aliases or ancestor/descendant-conflicts")
        );
    }
}
