//! Pre-proof contracts for the EIP-0045 B4 validator and campaign executor.
//!
//! These documents bind identities; they do not prove that the identified
//! files were reviewed, built, or executed.  Callers must supply independently
//! measured expectations to [`Eip0045B4VerifierContractV1::verify_against`] and
//! [`Eip0045B4CampaignPrecommitV1::verify_against`].  Those expectations are
//! deliberately non-serializable so a candidate document cannot replace the
//! external authority used to verify it.

use std::collections::BTreeSet;

#[cfg(feature = "positive-gate")]
use std::collections::BTreeMap;

use anyhow::{ensure, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::{
    b4_expectation::verify_b4_negative_expectation_set,
    b4_negative_io::require_b4_negative_handler_contract_frozen,
    b4_plan::Eip0045B4NegativePlanV1,
    b4_positive_input_set::B4ValidatedPositiveInputSetCompletionV2,
    canonical::{canonical_json_bytes, parse_json_strict, validate_canonical_json_source},
};

#[cfg(feature = "positive-gate")]
use crate::{
    b4::canonical_positive_case_artifact_path,
    b4_fixture_sources::B4FixtureSourceResolverV2,
    b4_positive_gate::{
        B4H0RequestProjectionV1, B4ValidatedPositiveGenerationPreacceptanceV2, FileMeasurement,
    },
    b4_positive_source_auth::{
        bind_external_path, B4AuthenticatedPositiveCaseSourceV2, B4PositiveCaseSourceV2,
        B4PositiveSourceBytesV2,
    },
};

mod terminal_evidence_campaign_receipt;
pub use terminal_evidence_campaign_receipt::{
    b4_publish_terminal_evidence_canonical_argv_sha256, validate_b4_campaign_command_invocation,
    validate_b4_publish_terminal_evidence_invocation, B4TerminalEvidenceCampaignReceiptInputsV1,
    Eip0045B4TerminalEvidenceCampaignReceiptV1, B4_PUBLISH_TERMINAL_EVIDENCE_CANONICAL_ARGV_FORMAT,
    B4_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_FORMAT,
    B4_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_FORMAT_VERSION,
    MAX_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES,
};

/// Exact verifier-contract format discriminator.
pub const B4_VERIFIER_CONTRACT_FORMAT: &str = "Eip0045B4VerifierContractV1";
/// Exact campaign-executor-contract format discriminator.
pub const B4_CAMPAIGN_EXECUTOR_CONTRACT_FORMAT: &str = "Eip0045B4CampaignExecutorContractV1";
/// Exact campaign-precommit format discriminator.
pub const B4_CAMPAIGN_PRECOMMIT_FORMAT: &str = "Eip0045B4CampaignPrecommitV1";
/// Exact shared format version.
pub const B4_CAMPAIGN_CONTRACT_FORMAT_VERSION: u8 = 1;
/// Exact dual-surface verifier interface.
pub const B4_VERIFIER_INTERFACE: &str = "eip0045-b4-verifier-cli-v2";
/// Exact positive verifier subcommand.
pub const B4_POSITIVE_SUBCOMMAND: &str = "verify-positive";
/// Exact negative verifier subcommand.
pub const B4_NEGATIVE_SUBCOMMAND: &str = "verify-negative";

/// Ordered command inventory of the measured campaign executor.
pub const B4_CAMPAIGN_EXECUTOR_COMMANDS: [&str; 11] = [
    "prepare-input-set",
    "prepare-campaign-precommit",
    "generate-case",
    "finalize-generation-set",
    "publish-terminal-evidence",
    "generate-negative-ancestry-witness-catalog",
    "prepare-negative-materialization-set",
    "run-positive-suite",
    "run-negative-suite",
    "finalize-corpus",
    "replay-corpus",
];

/// Ordered runner/seccomp roles frozen before the campaign precommit.
pub const B4_CAMPAIGN_RUNNER_ROLES: [&str; 4] = [
    "rust-validator-build",
    "jvm-validator-build",
    "rust-validator",
    "jvm-validator",
];

/// Ordered post-precommit output roles. Each role corresponds to one of the
/// nine executor commands which are allowed to publish after precommit.
pub const B4_CAMPAIGN_FUTURE_OUTPUT_ROLES: [&str; 9] = [
    "positive-case",
    "positive-generation-set",
    "terminal-evidence-campaign",
    "negative-ancestry-witness-catalog",
    "negative-materialization-set",
    "positive-suite",
    "negative-suite",
    "final-corpus",
    "corpus-replay",
];

/// Exact ordered schema roles admitted by the V1 verifier contract.
///
/// The compiled authority pins the exact checked-in bytes for each position.
/// Callers cannot add, remove, rename, reorder, or replace a schema.
pub const B4_VERIFIER_SCHEMA_ROLES: [&str; 20] = [
    "verifier-contract",
    "campaign-executor-contract",
    "campaign-executor-build-descriptor",
    "campaign-precommit",
    "terminal-evidence-campaign-receipt",
    "negative-plan",
    "expanded-corpus-registry",
    "sequence-subject",
    "subject-catalog",
    "terminal-fixture-catalog",
    "negative-binding-index",
    "abstract-tree",
    "negative-ancestry-witness-catalog",
    "negative-materialization-set",
    "materialization-identity",
    "negative-verifier-input",
    "negative-observation",
    "negative-expectation-set",
    "validation-result",
    "semantic-report",
];

const B4_VERIFIER_SCHEMA_IDS: [&str; 20] = [
    "urn:ergo:eip-0045:b4-verifier-contract-v1",
    "urn:ergo:eip-0045:b4-campaign-executor-contract-v1",
    "urn:ergo:eip-0045:b4-campaign-executor-build-descriptor-v1",
    "urn:ergo:eip-0045:b4-campaign-precommit-v1",
    "urn:ergo:eip-0045:b4-terminal-evidence-campaign-receipt-v1",
    "urn:ergo:eip-0045:b4-negative-plan-v1",
    "urn:ergo:eip-0045:b4-expanded-corpus-registry-v1",
    "urn:ergo:eip-0045:b4-sequence-subject-v1",
    "urn:ergo:eip-0045:b4-subject-catalog-v1",
    "urn:ergo:eip-0045:b4-terminal-fixture-catalog-v1",
    "urn:ergo:eip-0045:b4-negative-binding-index-v1",
    "urn:ergo:eip-0045:b4-abstract-tree-v1",
    "urn:ergo:eip-0045:b4-negative-ancestry-witness-catalog-v1",
    "urn:ergo:eip-0045:b4-negative-materialization-set-v1",
    "urn:ergo:eip-0045:b4-materialization-identity-v1",
    "urn:ergo:eip-0045:b4-negative-verifier-input-v1",
    "urn:ergo:eip-0045:b4-negative-observation-v1",
    "urn:ergo:eip-0045:b4-negative-expectation-set-v1",
    "urn:ergo:eip-0045:b4-validation-result-v1",
    "urn:ergo:eip-0045:b4-semantic-report-v1",
];

const B4_VERIFIER_SCHEMA_SOURCES: [&[u8]; B4_VERIFIER_SCHEMA_ROLES.len()] = [
    include_bytes!("../finalizer-schema/b4-verifier-contract-v1.schema.json"),
    include_bytes!("../finalizer-schema/b4-campaign-executor-contract-v1.schema.json"),
    include_bytes!("../finalizer-schema/b4-campaign-executor-build-descriptor-v1.schema.json"),
    include_bytes!("../finalizer-schema/b4-campaign-precommit-v1.schema.json"),
    include_bytes!("../finalizer-schema/b4-terminal-evidence-campaign-receipt-v1.schema.json"),
    include_bytes!("../finalizer-schema/b4-negative-plan-v1.schema.json"),
    include_bytes!("../finalizer-schema/b4-expanded-corpus-registry-v1.schema.json"),
    include_bytes!("../finalizer-schema/b4-sequence-subject-v1.schema.json"),
    include_bytes!("../finalizer-schema/b4-subject-catalog-v1.schema.json"),
    include_bytes!("../finalizer-schema/b4-terminal-fixture-catalog-v1.schema.json"),
    include_bytes!("../finalizer-schema/b4-negative-binding-index-v1.schema.json"),
    include_bytes!("../finalizer-schema/b4-abstract-tree-v1.schema.json"),
    include_bytes!("../finalizer-schema/b4-negative-ancestry-witness-catalog-v1.schema.json"),
    include_bytes!("../finalizer-schema/b4-negative-materialization-set-v1.schema.json"),
    include_bytes!("../finalizer-schema/b4-materialization-identity-v1.schema.json"),
    include_bytes!("../finalizer-schema/b4-negative-verifier-input-v1.schema.json"),
    include_bytes!("../finalizer-schema/b4-negative-observation-v1.schema.json"),
    include_bytes!("../finalizer-schema/b4-negative-expectation-set-v1.schema.json"),
    include_bytes!("../finalizer-schema/b4-validation-result-v1.schema.json"),
    include_bytes!("../finalizer-schema/b4-semantic-report-v1.schema.json"),
];

const MAX_VERIFIER_CONTRACT_BYTES: usize = 1024 * 1024;
const MAX_EXECUTOR_CONTRACT_BYTES: usize = 64 * 1024;
/// Maximum canonical byte length of one B4 campaign precommit.
pub const MAX_CAMPAIGN_PRECOMMIT_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_INPUT_SET_BYTES: u64 = 1024 * 1024;
const MAX_CLI_SPEC_BYTES: u64 = 1024 * 1024;
const MAX_NEGATIVE_PLAN_BYTES: u64 = 128 * 1024;
const MAX_EXPECTATION_SET_BYTES: u64 = 256 * 1024;
const MAX_SCHEMA_DOCUMENT_BYTES: u64 = 1024 * 1024;
const MAX_DESCRIPTOR_BYTES: u64 = 1024 * 1024;
const MAX_DESCRIPTOR_CANONICAL_BYTES: usize = 1024 * 1024;
const MAX_RUNNER_PROFILE_BYTES: u64 = 1024 * 1024;
const MAX_SECCOMP_DOCUMENT_BYTES: u64 = 1024 * 1024;
const MAX_JVM_INCLUSION_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_VALIDATOR_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_EXECUTOR_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_SOURCE_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ANY_ARTIFACT_BYTES: u64 = MAX_VALIDATOR_ARTIFACT_BYTES;
const MAX_RELATIVE_PATH_BYTES: usize = 240;
const MAX_ROLE_BYTES: usize = 96;

/// Encoding authenticated by one safe artifact identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4ContractArtifactEncodingV1 {
    /// Uninterpreted exact bytes, including executables, JARs, archives, and
    /// normative text.
    RawBytes,
    /// Exact RFC 8785 JCS bytes.
    Rfc8785Jcs,
    /// Exact Git bundle bytes selected as a reviewed source archive.
    GitBundle,
}

/// Pathful physical identity used by all three campaign contracts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4ContractArtifactIdentityV1 {
    /// Safe repository/archive-relative path.
    pub path: String,
    /// Exact non-zero byte length.
    pub byte_length: u64,
    /// Lowercase SHA-256 of the exact bytes.
    pub sha256: String,
    /// Exact byte encoding.
    pub encoding: B4ContractArtifactEncodingV1,
}

impl B4ContractArtifactIdentityV1 {
    /// Construct and validate an identity from exact bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe path, empty or oversized bytes, or any
    /// other V1 identity defect.
    pub fn from_bytes(
        path: impl Into<String>,
        encoding: B4ContractArtifactEncodingV1,
        bytes: &[u8],
    ) -> Result<Self> {
        let path = path.into();
        validate_safe_relative_path(&path)?;
        let byte_length =
            u64::try_from(bytes.len()).context("campaign artifact length does not fit u64")?;
        ensure!(
            (1..=MAX_ANY_ARTIFACT_BYTES).contains(&byte_length),
            "campaign artifact length is outside the V1 bound"
        );
        let identity = Self {
            path,
            byte_length,
            sha256: sha256_hex(bytes),
            encoding,
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Validate the safe path, bound, digest, and encoding shape.
    ///
    /// # Errors
    ///
    /// Returns an error for a path escape or alias, an empty or oversized
    /// artifact, or a malformed/placeholder digest.
    pub fn validate(&self) -> Result<()> {
        validate_safe_relative_path(&self.path)?;
        ensure!(
            (1..=MAX_ANY_ARTIFACT_BYTES).contains(&self.byte_length),
            "campaign artifact length is outside the V1 bound"
        );
        validate_digest(&self.sha256, "campaign artifact SHA-256")
    }

    fn validate_for(
        &self,
        encoding: B4ContractArtifactEncodingV1,
        maximum_bytes: u64,
        label: &str,
    ) -> Result<()> {
        self.validate()
            .with_context(|| format!("invalid {label} identity"))?;
        ensure!(
            self.encoding == encoding,
            "{label} uses the wrong artifact encoding"
        );
        ensure!(
            self.byte_length <= maximum_bytes,
            "{label} exceeds its role-specific byte bound"
        );
        Ok(())
    }
}

/// Role-labelled artifact identity used for ordered schema, runner, and
/// seccomp inventories.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4NamedContractArtifactIdentityV1 {
    /// Closed semantic role interpreted by the enclosing contract.
    pub role: String,
    /// Exact physical artifact identity.
    pub artifact: B4ContractArtifactIdentityV1,
}

impl B4NamedContractArtifactIdentityV1 {
    /// Validate the semantic role and physical artifact identity.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-canonical role or invalid artifact identity.
    pub fn validate(&self) -> Result<()> {
        validate_role(&self.role)?;
        self.artifact.validate()
    }
}

/// Exact externally held bytes used to construct an opaque authority token.
///
/// This is an input view, not authority by itself. Historical independence,
/// review custody, and the selection of these bytes remain finalizer duties.
#[derive(Clone, Copy, Debug)]
pub struct B4ExternalArtifactV1<'a> {
    /// Safe archive-relative path selected outside the candidate document.
    pub path: &'a str,
    /// Exact bytes read and measured by the finalizer.
    pub bytes: &'a [u8],
    /// Exact semantic encoding required for this role.
    pub encoding: B4ContractArtifactEncodingV1,
}

impl B4ExternalArtifactV1<'_> {
    fn identity(
        self,
        expected_encoding: B4ContractArtifactEncodingV1,
        maximum_bytes: u64,
        label: &str,
    ) -> Result<B4ContractArtifactIdentityV1> {
        ensure!(
            self.encoding == expected_encoding,
            "{label} external bytes use the wrong encoding"
        );
        let byte_length = u64::try_from(self.bytes.len())
            .with_context(|| format!("{label} external byte length does not fit u64"))?;
        ensure!(
            (1..=maximum_bytes).contains(&byte_length),
            "{label} external byte length is outside the role-specific bound"
        );
        let identity =
            B4ContractArtifactIdentityV1::from_bytes(self.path, self.encoding, self.bytes)?;
        identity.validate_for(expected_encoding, maximum_bytes, label)?;
        Ok(identity)
    }
}

/// Exact externally held bytes consumed by the V2 post-proof authority gate.
///
/// This borrowed view carries no authority and has no format selector. The
/// enclosing field fixes whether the bytes are canonical JCS or raw bytes.
#[cfg(feature = "positive-gate")]
#[derive(Clone, Copy, Debug)]
pub struct B4PositiveGenerationExternalBytesV2<'a> {
    /// Safe repository-relative physical path.
    pub path: &'a str,
    /// Exact externally retained source bytes.
    pub bytes: &'a [u8],
}

/// Complete physical export closure for one fixed V2 positive case.
#[cfg(feature = "positive-gate")]
#[derive(Clone, Copy, Debug)]
pub struct B4PositiveGenerationCaseExternalV2<'a> {
    /// Exact path-qualified proof-output manifest bytes.
    pub proof_output_manifest: B4PositiveGenerationExternalBytesV2<'a>,
    /// Exact primary artifacts in the compiled role order.
    pub primary_artifacts: &'a [B4PositiveGenerationExternalBytesV2<'a>],
    /// Exact recursive auxiliary artifacts in the compiled path order.
    pub auxiliary_artifacts: &'a [B4PositiveGenerationExternalBytesV2<'a>],
}

/// Complete post-proof V2 source closure consumed by the affine authority gate.
///
/// The eleven case slots are positional and cannot be caller-shortened. The
/// constructor reparses both canonical documents, remeasures every nested input
/// source, and authenticates all eleven physical exports before minting an
/// authority.
#[cfg(feature = "positive-gate")]
#[derive(Clone, Copy, Debug)]
pub struct B4PositiveGenerationExternalClosureV2<'a> {
    /// Exact path-qualified canonical V2 positive input set.
    pub positive_input_set: B4PositiveGenerationExternalBytesV2<'a>,
    /// Exact path-qualified canonical V2 positive generation set.
    pub positive_generation_set: B4PositiveGenerationExternalBytesV2<'a>,
    /// Exact proof-generator artifact selected by both V2 documents.
    pub proof_generator: B4PositiveGenerationExternalBytesV2<'a>,
    /// Complete nested source inventory selected by the V2 input set.
    pub nested_input_sources: &'a [B4PositiveGenerationExternalBytesV2<'a>],
    /// All eleven physical exports in compiled case order.
    pub cases: [B4PositiveGenerationCaseExternalV2<'a>; 11],
}

#[cfg(feature = "positive-gate")]
struct B4PositiveGenerationCaseAuthorityV2 {
    case_index: usize,
    case_id: String,
    proof_output_manifest: FileMeasurement,
    raw_seal: FileMeasurement,
    primary_measurements: Vec<FileMeasurement>,
    auxiliary_measurements: Vec<FileMeasurement>,
}

/// Crate-private materialization measurements retained by one authenticated V2 case.
#[cfg(feature = "positive-gate")]
pub(crate) struct B4PositiveGenerationCaseMaterializationMeasurementsV2 {
    proof_output_manifest: FileMeasurement,
    raw_seal: FileMeasurement,
}

#[cfg(feature = "positive-gate")]
impl B4PositiveGenerationCaseMaterializationMeasurementsV2 {
    pub(crate) const fn proof_output_manifest(&self) -> FileMeasurement {
        self.proof_output_manifest
    }

    pub(crate) const fn raw_seal(&self) -> FileMeasurement {
        self.raw_seal
    }
}

/// Crate-private physical half of the V2 positive-generation closure.
///
/// This value is not semantic authority on its own. It is joined to the full
/// Task 2 semantic bindings before the public affine authority can be minted.
#[cfg(feature = "positive-gate")]
pub(crate) struct B4PositiveGenerationPhysicalBindingsV2 {
    input_set: B4ContractArtifactIdentityV1,
    generation_set: B4ContractArtifactIdentityV1,
    resolver: B4FixtureSourceResolverV2,
    cases: [B4PositiveGenerationCaseAuthorityV2; 11],
    provenance_paths: BTreeSet<String>,
    provenance_sha256: BTreeMap<String, [u8; 32]>,
}

/// Opaque affine authority for one fully closed V2 positive generation.
///
/// It is minted only by consuming one opaque
/// [`B4ValidatedPositiveGenerationPreacceptanceV2`] after strict V2 semantic
/// validation, post-proof reparsing, complete nested-source authentication, a
/// global path antichain, and all eleven physical case closures. It has no field
/// constructor, parser, decoder, deserializer, clone, copy, default, V1
/// conversion, or detached-document reconstruction path.
///
/// This is deliberately a pre-acceptance generation authority. It authenticates
/// neither the later implementation acceptances nor a positive gate, campaign
/// approval, live session, or H0 authority.
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::
///     B4PositiveGenerationAuthorityV2;
/// fn require_clone<T: Clone>() {}
/// require_clone::<B4PositiveGenerationAuthorityV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::
///     B4PositiveGenerationAuthorityV2;
/// fn require_copy<T: Copy>() {}
/// require_copy::<B4PositiveGenerationAuthorityV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::
///     B4PositiveGenerationAuthorityV2;
/// fn require_default<T: Default>() {}
/// require_default::<B4PositiveGenerationAuthorityV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::
///     B4PositiveGenerationAuthorityV2;
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<B4PositiveGenerationAuthorityV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::
///     B4PositiveGenerationAuthorityV2;
/// fn require_deserialize<T: serde::de::DeserializeOwned>() {}
/// require_deserialize::<B4PositiveGenerationAuthorityV2>();
/// ```
#[cfg(feature = "positive-gate")]
pub struct B4PositiveGenerationAuthorityV2 {
    validated: B4ValidatedPositiveGenerationPreacceptanceV2,
}

/// Opaque affine pairing of the complete V2 generation authority and its G0 projection.
///
/// Both halves originate from one consumed semantic-and-physical predecessor.
/// Borrowing the projection grants no H0, runtime, filesystem, publication, or
/// live-session authority, and the generation authority is never exposed apart
/// from this pair.
///
/// ```
/// use eip_0045_reproduction::{
///     b4_campaign_contract::B4PositiveGenerationSessionBindingV2,
///     b4_positive_gate::B4ValidatedPositiveGenerationPreacceptanceV2,
/// };
///
/// fn bind_for_generator(
///     validated: B4ValidatedPositiveGenerationPreacceptanceV2,
/// ) -> anyhow::Result<B4PositiveGenerationSessionBindingV2> {
///     let binding = B4PositiveGenerationSessionBindingV2::from_validated(validated)?;
///     let projection = binding.request_projection();
///     let _: [u8; 32] = projection.positive_input_set_ai();
///     let _: [u8; 32] = projection.positive_generation_set_ai();
///     let _: [[u8; 97]; 4] = projection.encoded_role_blocks();
///     Ok(binding)
/// }
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::
///     B4PositiveGenerationSessionBindingV2;
/// fn require_clone<T: Clone>() {}
/// require_clone::<B4PositiveGenerationSessionBindingV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::
///     B4PositiveGenerationSessionBindingV2;
/// fn require_copy<T: Copy>() {}
/// require_copy::<B4PositiveGenerationSessionBindingV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::
///     B4PositiveGenerationSessionBindingV2;
/// fn require_default<T: Default>() {}
/// require_default::<B4PositiveGenerationSessionBindingV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::
///     B4PositiveGenerationSessionBindingV2;
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<B4PositiveGenerationSessionBindingV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::
///     B4PositiveGenerationSessionBindingV2;
/// fn require_deserialize<T: serde::de::DeserializeOwned>() {}
/// require_deserialize::<B4PositiveGenerationSessionBindingV2>();
/// ```
#[cfg(feature = "positive-gate")]
pub struct B4PositiveGenerationSessionBindingV2 {
    #[allow(
        dead_code,
        reason = "the complete affine authority remains owned until the future live session consumes the pair"
    )]
    authority: B4PositiveGenerationAuthorityV2,
    request_projection: B4H0RequestProjectionV1,
}

#[cfg(feature = "positive-gate")]
#[allow(
    dead_code,
    reason = "the pair is the fixed input to the later crate-private G0 session join"
)]
impl B4PositiveGenerationSessionBindingV2 {
    /// Consume one fully validated predecessor into the indivisible G0 binding.
    ///
    /// This transition accepts no caller-selected bytes, paths, digests, or
    /// formats. The request projection and generation authority are derived
    /// from the same consumed semantic-and-physical predecessor.
    ///
    /// # Errors
    ///
    /// Returns an error if the retained semantic and physical identities no
    /// longer form the exact checked H0 request projection.
    pub fn from_validated(validated: B4ValidatedPositiveGenerationPreacceptanceV2) -> Result<Self> {
        let request_projection = validated.derive_h0_request_projection()?;
        let authority = B4PositiveGenerationAuthorityV2::from_validated(validated);
        Ok(Self {
            authority,
            request_projection,
        })
    }

    /// Borrow the exact non-authorizing request projection while retaining the authority.
    #[must_use]
    pub const fn request_projection(&self) -> &B4H0RequestProjectionV1 {
        &self.request_projection
    }
}

#[cfg(feature = "positive-gate")]
impl B4PositiveGenerationPhysicalBindingsV2 {
    #[allow(
        clippy::too_many_lines,
        reason = "the ordered document, path, and eleven-case authority closure remains linear for auditability"
    )]
    pub(crate) fn from_external_closure(
        source: B4PositiveGenerationExternalClosureV2<'_>,
    ) -> Result<Self> {
        let input_set = B4ContractArtifactIdentityV1::from_bytes(
            source.positive_input_set.path,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            source.positive_input_set.bytes,
        )
        .context("V2 authority cannot measure the positive input set")?;
        let generation_set = B4ContractArtifactIdentityV1::from_bytes(
            source.positive_generation_set.path,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            source.positive_generation_set.bytes,
        )
        .context("V2 authority cannot measure the positive generation set")?;

        let proof_generator = positive_generation_source_v2(source.proof_generator);
        let nested_input_sources = source
            .nested_input_sources
            .iter()
            .copied()
            .map(positive_generation_source_v2)
            .collect::<Vec<_>>();
        let resolver = B4FixtureSourceResolverV2::from_postproof_documents(
            source.positive_input_set.bytes,
            source.positive_generation_set.bytes,
            proof_generator,
            &nested_input_sources,
        )
        .context("V2 authority post-proof document closure failed")?;
        require_v2_measurement_identity(
            resolver.postproof().input_set_measurement,
            &input_set,
            "positive input set",
        )?;
        require_v2_measurement_identity(
            resolver.postproof().generation_set_measurement,
            &generation_set,
            "positive generation set",
        )?;

        let mut provenance_paths = BTreeSet::new();
        bind_external_path(
            &mut provenance_paths,
            source.positive_input_set.path,
            false,
            "V2 positive input set",
        )?;
        bind_external_path(
            &mut provenance_paths,
            source.positive_generation_set.path,
            false,
            "V2 positive generation set",
        )?;
        for nested in source.nested_input_sources {
            bind_external_path(
                &mut provenance_paths,
                nested.path,
                false,
                "V2 nested positive-input source",
            )?;
        }
        bind_external_path(
            &mut provenance_paths,
            source.proof_generator.path,
            true,
            "V2 proof-generator replay",
        )?;

        let mut closed_cases = Vec::with_capacity(11);
        for (case_index, external) in source.cases.iter().copied().enumerate() {
            let case_id = crate::b4_materialization_set::compiled_positive_case_id(case_index)?;
            let manifest_name = if case_index < 8 {
                "candidate-proof-output-manifest.json"
            } else {
                "candidate-recursive-output-manifest.json"
            };
            ensure!(
                external.proof_output_manifest.path
                    == canonical_positive_case_artifact_path(&case_id, manifest_name),
                "V2 proof-output manifest path differs at case {case_index}"
            );
            bind_external_path(
                &mut provenance_paths,
                external.proof_output_manifest.path,
                false,
                "V2 proof-output manifest",
            )?;
            for artifact in external
                .primary_artifacts
                .iter()
                .chain(external.auxiliary_artifacts)
            {
                bind_external_path(
                    &mut provenance_paths,
                    artifact.path,
                    false,
                    "V2 positive-case artifact",
                )?;
            }

            let primary_artifacts = external
                .primary_artifacts
                .iter()
                .copied()
                .map(positive_generation_source_v2)
                .collect::<Vec<_>>();
            let auxiliary_artifacts = external
                .auxiliary_artifacts
                .iter()
                .copied()
                .map(positive_generation_source_v2)
                .collect::<Vec<_>>();
            let authenticated = resolver
                .positive_case(
                    case_index,
                    B4PositiveCaseSourceV2 {
                        proof_output_manifest_jcs: external.proof_output_manifest.bytes,
                        primary_artifacts: &primary_artifacts,
                        auxiliary_artifacts: &auxiliary_artifacts,
                    },
                )
                .with_context(|| format!("V2 authority physical case {case_index} failed"))?;
            closed_cases.push(B4PositiveGenerationCaseAuthorityV2 {
                case_index: authenticated.case_index(),
                case_id: authenticated.case_id().to_owned(),
                proof_output_manifest: authenticated.proof_output_manifest(),
                raw_seal: measure_v2_authenticated_bytes(authenticated.raw_seal())?,
                primary_measurements: authenticated.primary_measurements().to_vec(),
                auxiliary_measurements: authenticated.auxiliary_measurements().to_vec(),
            });
        }
        let cases = closed_cases
            .try_into()
            .map_err(|_: Vec<_>| anyhow::anyhow!("V2 authority case cardinality is not eleven"))?;
        let provenance_sha256 = retain_v2_provenance_sha256(&source)?;
        ensure!(
            provenance_sha256.keys().eq(provenance_paths.iter()),
            "V2 retained provenance digest keys differ from the authenticated path closure"
        );

        Ok(Self {
            input_set,
            generation_set,
            resolver,
            cases,
            provenance_paths,
            provenance_sha256,
        })
    }

    pub(crate) const fn input_set(&self) -> &B4ContractArtifactIdentityV1 {
        &self.input_set
    }

    pub(crate) const fn generation_set(&self) -> &B4ContractArtifactIdentityV1 {
        &self.generation_set
    }

    pub(crate) fn provenance_paths(&self) -> &BTreeSet<String> {
        &self.provenance_paths
    }

    pub(crate) fn provenance_sha256(&self) -> &BTreeMap<String, [u8; 32]> {
        &self.provenance_sha256
    }

    pub(crate) fn case_materialization_measurements(
        &self,
        case_index: usize,
    ) -> Result<B4PositiveGenerationCaseMaterializationMeasurementsV2> {
        let retained = self
            .cases
            .get(case_index)
            .context("V2 materialization case index is outside the fixed closure")?;
        ensure!(
            retained.case_index == case_index,
            "V2 retained materialization case index drifted"
        );
        Ok(B4PositiveGenerationCaseMaterializationMeasurementsV2 {
            proof_output_manifest: retained.proof_output_manifest,
            raw_seal: retained.raw_seal,
        })
    }

    pub(crate) fn authenticate_case<'bytes>(
        &self,
        case_index: usize,
        source: B4PositiveCaseSourceV2<'bytes, '_>,
    ) -> Result<B4AuthenticatedPositiveCaseSourceV2<'bytes>> {
        let authenticated = self.resolver.positive_case(case_index, source)?;
        let retained = self
            .cases
            .get(case_index)
            .context("V2 authority case index is outside the fixed closure")?;
        let authenticated_raw_seal = measure_v2_authenticated_bytes(authenticated.raw_seal())?;
        ensure!(
            retained.case_index == case_index
                && authenticated.case_index() == case_index
                && retained.case_id == authenticated.case_id()
                && retained.proof_output_manifest == authenticated.proof_output_manifest()
                && retained.raw_seal == authenticated_raw_seal
                && retained.primary_measurements == authenticated.primary_measurements()
                && retained.auxiliary_measurements == authenticated.auxiliary_measurements(),
            "V2 selected case differs from the retained generation authority"
        );
        Ok(authenticated)
    }

    pub(crate) fn case_custody_matches(
        &self,
        case_index: usize,
        case_id: &str,
        proof_output_manifest: FileMeasurement,
        primary_measurements: &[FileMeasurement],
        auxiliary_measurements: &[FileMeasurement],
    ) -> bool {
        self.cases.get(case_index).is_some_and(|retained| {
            retained.case_index == case_index
                && retained.case_id == case_id
                && retained.proof_output_manifest == proof_output_manifest
                && retained.primary_measurements == primary_measurements
                && retained.auxiliary_measurements == auxiliary_measurements
        })
    }
}

#[cfg(feature = "positive-gate")]
impl B4PositiveGenerationAuthorityV2 {
    /// Consume one fully validated semantic-and-physical predecessor.
    ///
    /// This transition is infallible because no raw bytes, paths, digests, or
    /// caller-selected formats enter the mint boundary.
    ///
    /// ```compile_fail
    /// use eip_0045_reproduction::{
    ///     b4_campaign_contract::B4PositiveGenerationAuthorityV2,
    ///     b4_positive_gate::B4ValidatedPositiveGenerationPreacceptanceV2,
    /// };
    ///
    /// fn consume_twice(validated: B4ValidatedPositiveGenerationPreacceptanceV2) {
    ///     let _first = B4PositiveGenerationAuthorityV2::from_validated(validated);
    ///     let _second = B4PositiveGenerationAuthorityV2::from_validated(validated);
    /// }
    /// ```
    ///
    /// ```compile_fail
    /// use eip_0045_reproduction::b4_campaign_contract::
    ///     B4PositiveGenerationAuthorityV2;
    ///
    /// let _ = B4PositiveGenerationAuthorityV2::from_validated(Default::default());
    /// ```
    #[must_use]
    pub fn from_validated(validated: B4ValidatedPositiveGenerationPreacceptanceV2) -> Self {
        Self { validated }
    }

    /// Borrow the exact measured V2 positive-input-set identity.
    ///
    /// This path-qualified byte identity is information only. Borrowing it
    /// grants no construction, positive-gate, campaign, live-session, or H0
    /// authority and does not expose the retained document bytes.
    #[must_use]
    pub fn positive_input_set_identity(&self) -> &B4ContractArtifactIdentityV1 {
        self.validated.physical().input_set()
    }

    /// Borrow the exact measured V2 positive-generation-set identity.
    ///
    /// This path-qualified byte identity is information only. Borrowing it
    /// grants no construction, positive-gate, campaign, live-session, or H0
    /// authority and does not expose the retained document bytes.
    #[must_use]
    pub fn positive_generation_set_identity(&self) -> &B4ContractArtifactIdentityV1 {
        self.validated.physical().generation_set()
    }

    pub(crate) fn input_set(&self) -> &B4ContractArtifactIdentityV1 {
        self.positive_input_set_identity()
    }

    pub(crate) fn generation_set(&self) -> &B4ContractArtifactIdentityV1 {
        self.positive_generation_set_identity()
    }

    pub(crate) fn provenance_paths(&self) -> &BTreeSet<String> {
        self.validated.physical().provenance_paths()
    }

    pub(crate) fn provenance_sha256(&self) -> &BTreeMap<String, [u8; 32]> {
        self.validated.physical().provenance_sha256()
    }

    pub(crate) fn case_materialization_measurements(
        &self,
        case_index: usize,
    ) -> Result<B4PositiveGenerationCaseMaterializationMeasurementsV2> {
        self.validated
            .physical()
            .case_materialization_measurements(case_index)
    }

    pub(crate) fn authenticate_case<'bytes>(
        &self,
        case_index: usize,
        source: B4PositiveCaseSourceV2<'bytes, '_>,
    ) -> Result<B4AuthenticatedPositiveCaseSourceV2<'bytes>> {
        self.validated
            .physical()
            .authenticate_case(case_index, source)
    }

    pub(crate) fn case_custody_matches(
        &self,
        case_index: usize,
        case_id: &str,
        proof_output_manifest: FileMeasurement,
        primary_measurements: &[FileMeasurement],
        auxiliary_measurements: &[FileMeasurement],
    ) -> bool {
        self.validated.physical().case_custody_matches(
            case_index,
            case_id,
            proof_output_manifest,
            primary_measurements,
            auxiliary_measurements,
        )
    }
}

#[cfg(feature = "positive-gate")]
fn measure_v2_authenticated_bytes(bytes: &[u8]) -> Result<FileMeasurement> {
    Ok(FileMeasurement {
        byte_length: u64::try_from(bytes.len())?,
        sha256: Sha256::digest(bytes).into(),
    })
}

#[cfg(feature = "positive-gate")]
fn retain_v2_provenance_sha256(
    source: &B4PositiveGenerationExternalClosureV2<'_>,
) -> Result<BTreeMap<String, [u8; 32]>> {
    fn retain(
        closure: &mut BTreeMap<String, [u8; 32]>,
        source: B4PositiveGenerationExternalBytesV2<'_>,
    ) -> Result<()> {
        let sha256 = Sha256::digest(source.bytes).into();
        if let Some(retained) = closure.insert(source.path.to_owned(), sha256) {
            ensure!(
                retained == sha256,
                "V2 authenticated provenance replay changed content digest"
            );
        }
        Ok(())
    }

    let mut closure = BTreeMap::new();
    retain(&mut closure, source.positive_input_set)?;
    retain(&mut closure, source.positive_generation_set)?;
    for nested in source.nested_input_sources {
        retain(&mut closure, *nested)?;
    }
    retain(&mut closure, source.proof_generator)?;
    for case in source.cases {
        retain(&mut closure, case.proof_output_manifest)?;
        for artifact in case
            .primary_artifacts
            .iter()
            .chain(case.auxiliary_artifacts)
        {
            retain(&mut closure, *artifact)?;
        }
    }
    Ok(closure)
}

#[cfg(feature = "positive-gate")]
fn positive_generation_source_v2(
    external: B4PositiveGenerationExternalBytesV2<'_>,
) -> B4PositiveSourceBytesV2<'_> {
    B4PositiveSourceBytesV2 {
        path: external.path,
        bytes: external.bytes,
    }
}

#[cfg(feature = "positive-gate")]
fn require_v2_measurement_identity(
    measured: FileMeasurement,
    identity: &B4ContractArtifactIdentityV1,
    label: &str,
) -> Result<()> {
    ensure!(
        identity.encoding == B4ContractArtifactEncodingV1::Rfc8785Jcs
            && identity.byte_length == measured.byte_length
            && identity.sha256 == hex::encode(measured.sha256),
        "V2 authority {label} identity differs from reparsed exact bytes"
    );
    Ok(())
}

/// One exact externally selected schema document.
#[derive(Clone, Copy, Debug)]
pub struct B4ExternalSchemaDocumentV1<'a> {
    /// Closed role; membership and ordering are checked against
    /// [`B4_VERIFIER_SCHEMA_ROLES`].
    pub role: &'a str,
    /// Exact readable checked-in JSON bytes. Insignificant whitespace is part
    /// of the authenticated identity; schema documents are not required JCS.
    pub document: B4ExternalArtifactV1<'a>,
}

/// Exact reviewed Git source identity carried by validator and executor
/// bindings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4ReviewedSourceBindingV1 {
    /// Canonical HTTPS GitHub repository URL.
    pub repository: String,
    /// Exact 40-hex reviewed commit.
    pub commit: String,
    /// Exact 40-hex reviewed tree.
    pub tree: String,
    /// Exact reviewed Git bundle.
    pub archive: B4ContractArtifactIdentityV1,
}

impl B4ReviewedSourceBindingV1 {
    fn validate(&self, label: &str) -> Result<()> {
        validate_repository(&self.repository, label)?;
        validate_git_object_id(&self.commit, &format!("{label} commit"))?;
        validate_git_object_id(&self.tree, &format!("{label} tree"))?;
        self.archive.validate_for(
            B4ContractArtifactEncodingV1::GitBundle,
            MAX_SOURCE_ARCHIVE_BYTES,
            &format!("{label} archive"),
        )
    }
}

/// Exact externally selected reviewed source and archive bytes.
#[derive(Clone, Copy, Debug)]
pub struct B4ExternalReviewedSourceV1<'a> {
    /// Canonical repository URL selected by review.
    pub repository: &'a str,
    /// Exact reviewed commit.
    pub commit: &'a str,
    /// Exact reviewed tree.
    pub tree: &'a str,
    /// Exact Git bundle bytes read by the finalizer.
    pub archive: B4ExternalArtifactV1<'a>,
}

impl B4ExternalReviewedSourceV1<'_> {
    fn binding(self, label: &str) -> Result<B4ReviewedSourceBindingV1> {
        let binding = B4ReviewedSourceBindingV1 {
            repository: self.repository.to_owned(),
            commit: self.commit.to_owned(),
            tree: self.tree.to_owned(),
            archive: self.archive.identity(
                B4ContractArtifactEncodingV1::GitBundle,
                MAX_SOURCE_ARCHIVE_BYTES,
                &format!("{label} archive"),
            )?,
        };
        binding.validate(label)?;
        Ok(binding)
    }
}

/// Canonical verifier-contract manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Eip0045B4VerifierContractV1 {
    /// Exact V1 format discriminator.
    pub format: String,
    /// Exact V1 format version.
    pub format_version: u8,
    /// Exact dual-surface CLI interface.
    pub interface: String,
    /// Exact positive subcommand.
    pub positive_subcommand: String,
    /// Exact negative subcommand.
    pub negative_subcommand: String,
    /// Exact normative CLI specification.
    pub cli_spec: B4ContractArtifactIdentityV1,
    /// Exact canonical negative-plan artifact.
    pub negative_plan: B4ContractArtifactIdentityV1,
    /// Exact canonical implementation-specific expectation set.
    pub expectation_set: B4ContractArtifactIdentityV1,
    /// Complete externally prescribed ordered schema inventory.
    pub schema_identities: Vec<B4NamedContractArtifactIdentityV1>,
}

impl Eip0045B4VerifierContractV1 {
    /// Parse exact RFC 8785 JCS and enforce every closed V1 invariant.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, duplicate-key,
    /// noncanonical, unknown-field, wrong-interface, unsafe-path, or
    /// inconsistent inventory input.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        parse_contract(source, MAX_VERIFIER_CONTRACT_BYTES, "B4 verifier contract")
    }

    /// Serialize this contract as exact RFC 8785 JCS.
    ///
    /// # Errors
    ///
    /// Returns an error when the contract is invalid or oversized.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        serialize_contract(self, MAX_VERIFIER_CONTRACT_BYTES, "B4 verifier contract")
    }

    /// Validate internal V1 invariants.
    ///
    /// This is deliberately a document-local check. Identity values and the
    /// transitive path closure remain externally authenticated; consumers
    /// must use [`Self::verify_against`] before relying on the contract.
    ///
    /// # Errors
    ///
    /// Returns an error for a wrong label, interface, subcommand, encoding,
    /// identity, bound, duplicate role, or aliased schema path.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == B4_VERIFIER_CONTRACT_FORMAT,
            "wrong B4 verifier-contract format"
        );
        ensure!(
            self.format_version == B4_CAMPAIGN_CONTRACT_FORMAT_VERSION,
            "wrong B4 verifier-contract version"
        );
        ensure!(
            self.interface == B4_VERIFIER_INTERFACE,
            "wrong B4 verifier interface"
        );
        ensure!(
            self.positive_subcommand == B4_POSITIVE_SUBCOMMAND,
            "wrong B4 positive verifier subcommand"
        );
        ensure!(
            self.negative_subcommand == B4_NEGATIVE_SUBCOMMAND,
            "wrong B4 negative verifier subcommand"
        );
        require_identity(
            &self.cli_spec,
            B4ContractArtifactEncodingV1::RawBytes,
            MAX_CLI_SPEC_BYTES,
            "CLI specification",
        )?;
        require_identity(
            &self.negative_plan,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_NEGATIVE_PLAN_BYTES,
            "negative plan",
        )?;
        require_identity(
            &self.expectation_set,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_EXPECTATION_SET_BYTES,
            "expectation set",
        )?;
        validate_fixed_named_inventory(
            &self.schema_identities,
            &B4_VERIFIER_SCHEMA_ROLES,
            B4ContractArtifactEncodingV1::RawBytes,
            MAX_SCHEMA_DOCUMENT_BYTES,
            "verifier-contract schema",
        )?;
        require_global_path_injectivity(
            std::iter::once(&self.cli_spec)
                .chain(std::iter::once(&self.negative_plan))
                .chain(std::iter::once(&self.expectation_set))
                .chain(
                    self.schema_identities
                        .iter()
                        .map(|identity| &identity.artifact),
                ),
            "verifier contract",
        )
    }

    /// Rebind every variable identity to independently selected expectations.
    ///
    /// # Errors
    ///
    /// Returns an error when this document is internally invalid, the external
    /// expectations are invalid, or any identity/list position differs.
    pub fn verify_against(&self, expected: &B4VerifierContractAuthorityV1) -> Result<()> {
        self.validate()?;
        ensure!(
            self == &expected.expected,
            "verifier contract differs from the externally constructed authority"
        );
        Ok(())
    }
}

impl CanonicalContract for Eip0045B4VerifierContractV1 {
    fn validate_contract(&self) -> Result<()> {
        self.validate()
    }
}

/// Opaque verifier authority rebuilt from exact externally supplied bytes.
///
/// The token prevents a candidate document from filling its own comparison
/// fields. It cannot prove who selected or reviewed the supplied bytes;
/// historical independence and custody remain finalizer evidence.
#[derive(Clone, Debug)]
pub struct B4VerifierContractAuthorityV1 {
    expected: Eip0045B4VerifierContractV1,
    cli_spec_source: Vec<u8>,
    negative_plan_source: Vec<u8>,
    expectation_set_source: Vec<u8>,
    schema_sources: [Vec<u8>; B4_VERIFIER_SCHEMA_ROLES.len()],
    artifact_paths: BTreeSet<String>,
}

impl B4VerifierContractAuthorityV1 {
    /// Build an opaque authority from the exact externally selected CLI,
    /// canonical plan, reviewed expectation set, and twenty pinned schema
    /// documents.
    ///
    /// # Errors
    ///
    /// Returns an error for a noncanonical or non-closed plan/expectation,
    /// missing, extra, reordered, wrongly identified, duplicate-key,
    /// externally referenced, malformed, path-conflicting, or oversized
    /// schema input, any unsafe physical identity, or (when the positive-gate
    /// feature is enabled) a Draft 2020-12 compilation failure.
    pub fn from_external_documents(
        cli_spec: B4ExternalArtifactV1<'_>,
        negative_plan: B4ExternalArtifactV1<'_>,
        expectation_set: B4ExternalArtifactV1<'_>,
        schema_documents: [B4ExternalSchemaDocumentV1<'_>; B4_VERIFIER_SCHEMA_ROLES.len()],
    ) -> Result<Self> {
        require_b4_negative_handler_contract_frozen()?;
        let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(negative_plan.bytes)?;
        ensure!(
            plan == Eip0045B4NegativePlanV1::canonical()?,
            "external negative plan differs from the compiled closed plan"
        );
        verify_b4_negative_expectation_set(expectation_set.bytes, negative_plan.bytes)?;

        let mut schema_identities = Vec::with_capacity(B4_VERIFIER_SCHEMA_ROLES.len());
        let mut schema_sources = Vec::with_capacity(B4_VERIFIER_SCHEMA_ROLES.len());
        for (index, schema) in schema_documents.into_iter().enumerate() {
            validate_pinned_schema_source(index, schema)?;
            schema_identities.push(B4NamedContractArtifactIdentityV1 {
                role: schema.role.to_owned(),
                artifact: schema.document.identity(
                    B4ContractArtifactEncodingV1::RawBytes,
                    MAX_SCHEMA_DOCUMENT_BYTES,
                    &format!("{} schema", schema.role),
                )?,
            });
            schema_sources.push(schema.document.bytes.to_vec());
        }
        let schema_sources = schema_sources
            .try_into()
            .map_err(|_| anyhow::anyhow!("validated verifier schema cardinality drift"))?;

        let expected = Eip0045B4VerifierContractV1 {
            format: B4_VERIFIER_CONTRACT_FORMAT.to_owned(),
            format_version: B4_CAMPAIGN_CONTRACT_FORMAT_VERSION,
            interface: B4_VERIFIER_INTERFACE.to_owned(),
            positive_subcommand: B4_POSITIVE_SUBCOMMAND.to_owned(),
            negative_subcommand: B4_NEGATIVE_SUBCOMMAND.to_owned(),
            cli_spec: cli_spec.identity(
                B4ContractArtifactEncodingV1::RawBytes,
                MAX_CLI_SPEC_BYTES,
                "CLI specification",
            )?,
            negative_plan: negative_plan.identity(
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                MAX_NEGATIVE_PLAN_BYTES,
                "negative plan",
            )?,
            expectation_set: expectation_set.identity(
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                MAX_EXPECTATION_SET_BYTES,
                "expectation set",
            )?,
            schema_identities,
        };
        expected.validate()?;
        let artifact_paths = verifier_contract_artifact_paths(&expected)?;
        Ok(Self {
            expected,
            cli_spec_source: cli_spec.bytes.to_vec(),
            negative_plan_source: negative_plan.bytes.to_vec(),
            expectation_set_source: expectation_set.bytes.to_vec(),
            schema_sources,
            artifact_paths,
        })
    }

    /// Exact canonical verifier-contract bytes prescribed by this authority.
    ///
    /// # Errors
    ///
    /// Returns an error if the retained contract no longer satisfies its
    /// closed grammar or canonical byte bound.
    pub fn to_canonical_contract_jcs(&self) -> Result<Vec<u8>> {
        self.expected.to_canonical_jcs()
    }

    /// Exact immutable verifier contract selected by this authority.
    #[must_use]
    pub fn contract(&self) -> &Eip0045B4VerifierContractV1 {
        &self.expected
    }

    /// Exact canonical negative-plan bytes retained by this authority.
    #[must_use]
    pub fn negative_plan_jcs(&self) -> &[u8] {
        &self.negative_plan_source
    }

    /// Exact canonical expectation-set bytes retained by this authority.
    #[must_use]
    pub fn expectation_set_jcs(&self) -> &[u8] {
        &self.expectation_set_source
    }

    fn verify_external_replay(
        &self,
        cli_spec: B4ExternalArtifactV1<'_>,
        negative_plan: B4ExternalArtifactV1<'_>,
        expectation_set: B4ExternalArtifactV1<'_>,
        schema_documents: &[B4ExternalSchemaDocumentV1<'_>; B4_VERIFIER_SCHEMA_ROLES.len()],
    ) -> Result<()> {
        ensure!(
            cli_spec.bytes == self.cli_spec_source
                && negative_plan.bytes == self.negative_plan_source
                && expectation_set.bytes == self.expectation_set_source,
            "verifier authority replay bytes differ from the retained external authority"
        );
        ensure!(
            cli_spec.identity(
                B4ContractArtifactEncodingV1::RawBytes,
                MAX_CLI_SPEC_BYTES,
                "replayed CLI specification",
            )? == self.expected.cli_spec
                && negative_plan.identity(
                    B4ContractArtifactEncodingV1::Rfc8785Jcs,
                    MAX_NEGATIVE_PLAN_BYTES,
                    "replayed negative plan",
                )? == self.expected.negative_plan
                && expectation_set.identity(
                    B4ContractArtifactEncodingV1::Rfc8785Jcs,
                    MAX_EXPECTATION_SET_BYTES,
                    "replayed expectation set",
                )? == self.expected.expectation_set,
            "verifier authority replay identities differ from the retained contract"
        );
        ensure!(
            Eip0045B4NegativePlanV1::from_canonical_jcs(negative_plan.bytes)?
                == Eip0045B4NegativePlanV1::canonical()?,
            "replayed negative plan differs from the compiled closed plan"
        );
        verify_b4_negative_expectation_set(expectation_set.bytes, negative_plan.bytes)?;
        for (index, schema) in schema_documents.iter().copied().enumerate() {
            ensure!(
                schema.role == B4_VERIFIER_SCHEMA_ROLES[index]
                    && schema.document.bytes == self.schema_sources[index],
                "replayed verifier schema differs from retained role or bytes at index {index}"
            );
            validate_schema_source(
                schema.document.bytes,
                B4_VERIFIER_SCHEMA_IDS[index],
                schema.role,
            )?;
            ensure!(
                schema.document.identity(
                    B4ContractArtifactEncodingV1::RawBytes,
                    MAX_SCHEMA_DOCUMENT_BYTES,
                    &format!("replayed {} schema", schema.role),
                )? == self.expected.schema_identities[index].artifact,
                "replayed verifier schema identity differs at index {index}"
            );
        }
        ensure!(
            self.artifact_paths == verifier_contract_artifact_paths(&self.expected)?,
            "retained verifier-authority path closure differs from its exact contract"
        );
        Ok(())
    }

    /// Complete ancestry-safe path closure retained by this authority.
    pub(crate) fn artifact_paths(&self) -> &BTreeSet<String> {
        &self.artifact_paths
    }
}

/// Create-only phase policy shared by every campaign-executor command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4CreateOnlyPhasePolicyV1 {
    /// A command consumes only an immutable prior phase root.
    pub input_root: String,
    /// A command writes only a distinct root which was absent at launch.
    pub output_root: String,
    /// Durable publication never replaces an existing destination.
    pub publication: String,
    /// A partial or completed phase is never overwritten.
    pub overwrite: String,
    /// A partial phase is never repaired or merged into a later phase.
    pub partial_repair: String,
}

impl B4CreateOnlyPhasePolicyV1 {
    /// Construct the one admitted V1 phase policy.
    #[must_use]
    pub fn closed_v1() -> Self {
        Self {
            input_root: "immutable-prior-phase-root".to_owned(),
            output_root: "distinct-absent-output-root".to_owned(),
            publication: "create-only".to_owned(),
            overwrite: "forbidden".to_owned(),
            partial_repair: "forbidden".to_owned(),
        }
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self == &Self::closed_v1(),
            "campaign executor phase policy differs from closed V1 policy"
        );
        Ok(())
    }
}

/// Canonical command contract of the measured campaign executor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Eip0045B4CampaignExecutorContractV1 {
    /// Exact V1 format discriminator.
    pub format: String,
    /// Exact V1 format version.
    pub format_version: u8,
    /// Complete exact command set in lifecycle order.
    pub commands: Vec<String>,
    /// Exact create-only phase-root policy.
    pub phase_policy: B4CreateOnlyPhasePolicyV1,
}

impl Eip0045B4CampaignExecutorContractV1 {
    /// Construct the single admitted V1 executor contract.
    #[must_use]
    pub fn closed_v1() -> Self {
        Self {
            format: B4_CAMPAIGN_EXECUTOR_CONTRACT_FORMAT.to_owned(),
            format_version: B4_CAMPAIGN_CONTRACT_FORMAT_VERSION,
            commands: B4_CAMPAIGN_EXECUTOR_COMMANDS
                .iter()
                .map(ToString::to_string)
                .collect(),
            phase_policy: B4CreateOnlyPhasePolicyV1::closed_v1(),
        }
    }

    /// Parse exact RFC 8785 JCS and enforce the closed command/policy grammar.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, duplicate-key,
    /// noncanonical, unknown-field, missing, reordered, aliased, or additional
    /// commands/policy fields.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        parse_contract(
            source,
            MAX_EXECUTOR_CONTRACT_BYTES,
            "B4 campaign executor contract",
        )
    }

    /// Serialize this contract as exact RFC 8785 JCS.
    ///
    /// # Errors
    ///
    /// Returns an error when the contract is not the closed V1 value.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        serialize_contract(
            self,
            MAX_EXECUTOR_CONTRACT_BYTES,
            "B4 campaign executor contract",
        )
    }

    /// Validate the exact format, command order, and create-only policy.
    ///
    /// # Errors
    ///
    /// Returns an error for any value other than the single admitted V1
    /// contract.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == B4_CAMPAIGN_EXECUTOR_CONTRACT_FORMAT,
            "wrong B4 campaign-executor-contract format"
        );
        ensure!(
            self.format_version == B4_CAMPAIGN_CONTRACT_FORMAT_VERSION,
            "wrong B4 campaign-executor-contract version"
        );
        ensure!(
            strings_equal_exact(&self.commands, &B4_CAMPAIGN_EXECUTOR_COMMANDS),
            "campaign executor commands differ from the exact ordered V1 inventory"
        );
        self.phase_policy.validate()
    }
}

impl CanonicalContract for Eip0045B4CampaignExecutorContractV1 {
    fn validate_contract(&self) -> Result<()> {
        self.validate()
    }
}

/// Minimal closed build descriptor for the measured campaign executor.
///
/// Physical reproducibility, toolchain closure, and review receipts remain
/// separate finalizer evidence. This document closes the indispensable direct
/// links from the reviewed source and command contract to the exact launched
/// artifact; a format-only placeholder is never sufficient.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Eip0045B4CampaignExecutorBuildDescriptorV1 {
    /// Exact V1 format discriminator.
    pub format: String,
    /// Exact V1 format version.
    pub format_version: u8,
    /// Exact built executor artifact.
    pub artifact: B4ContractArtifactIdentityV1,
    /// Exact reviewed source identity and Git bundle.
    pub reviewed_source: B4ReviewedSourceBindingV1,
    /// Exact closed command-contract identity.
    pub executor_contract: B4ContractArtifactIdentityV1,
    /// Exact ordered command inventory implemented by the artifact.
    pub commands: Vec<String>,
}

impl Eip0045B4CampaignExecutorBuildDescriptorV1 {
    /// Parse exact canonical JCS and enforce every direct build binding.
    ///
    /// # Errors
    ///
    /// Returns an error for noncanonical, oversized, unknown-field, wrong
    /// format, unsafe-path, aliased, unbound, or command-drift input.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        parse_contract(
            source,
            MAX_DESCRIPTOR_CANONICAL_BYTES,
            "B4 campaign executor build descriptor",
        )
    }

    /// Serialize the closed descriptor as exact canonical JCS.
    ///
    /// # Errors
    ///
    /// Returns an error if any direct build binding, command, path, encoding,
    /// digest, or canonical byte bound is invalid.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        serialize_contract(
            self,
            MAX_DESCRIPTOR_CANONICAL_BYTES,
            "B4 campaign executor build descriptor",
        )
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.format == "Eip0045B4CampaignExecutorBuildDescriptorV1",
            "wrong B4 campaign executor build-descriptor format"
        );
        ensure!(
            self.format_version == B4_CAMPAIGN_CONTRACT_FORMAT_VERSION,
            "wrong B4 campaign executor build-descriptor version"
        );
        self.artifact.validate_for(
            B4ContractArtifactEncodingV1::RawBytes,
            MAX_EXECUTOR_ARTIFACT_BYTES,
            "campaign executor build artifact",
        )?;
        self.reviewed_source
            .validate("campaign executor build reviewed source")?;
        self.executor_contract.validate_for(
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_EXECUTOR_CONTRACT_BYTES as u64,
            "campaign executor build command contract",
        )?;
        ensure!(
            strings_equal_exact(&self.commands, &B4_CAMPAIGN_EXECUTOR_COMMANDS),
            "campaign executor build commands differ from the closed V1 inventory"
        );
        require_global_path_injectivity(
            [
                &self.artifact,
                &self.reviewed_source.archive,
                &self.executor_contract,
            ],
            "campaign executor build descriptor",
        )
    }
}

impl CanonicalContract for Eip0045B4CampaignExecutorBuildDescriptorV1 {
    fn validate_contract(&self) -> Result<()> {
        self.validate()
    }
}

/// Complete measured campaign-executor binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4CampaignExecutorBindingV1 {
    /// Exact executable artifact.
    pub artifact: B4ContractArtifactIdentityV1,
    /// Exact independently reviewed source archive/inventory.
    pub reviewed_source: B4ReviewedSourceBindingV1,
    /// Exact canonical build descriptor.
    pub build_descriptor: B4ContractArtifactIdentityV1,
}

impl B4CampaignExecutorBindingV1 {
    fn validate(&self) -> Result<()> {
        require_identity(
            &self.artifact,
            B4ContractArtifactEncodingV1::RawBytes,
            MAX_EXECUTOR_ARTIFACT_BYTES,
            "campaign executor artifact",
        )?;
        self.reviewed_source
            .validate("campaign executor reviewed source")?;
        require_identity(
            &self.build_descriptor,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_DESCRIPTOR_BYTES,
            "campaign executor build descriptor",
        )?;
        require_distinct_paths(
            [
                &self.artifact,
                &self.reviewed_source.archive,
                &self.build_descriptor,
            ],
            "campaign executor binding",
        )
    }
}

/// Closed validator implementation role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4CampaignValidatorImplementationV1 {
    /// Reference Rust implementation using the pinned upstream verifier.
    RustReference,
    /// Independently implemented pure-JVM verifier.
    IndependentJvm,
}

/// One validator's descriptor and executable identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4CampaignValidatorBindingV1 {
    /// Closed implementation role.
    pub implementation: B4CampaignValidatorImplementationV1,
    /// Exact canonical build descriptor.
    pub build_descriptor: B4ContractArtifactIdentityV1,
    /// Exact executable/JAR artifact.
    pub artifact: B4ContractArtifactIdentityV1,
    /// Exact independently reviewed source identity and Git bundle.
    pub reviewed_source: B4ReviewedSourceBindingV1,
    /// Exact domain-separated implementation-lineage digest from the
    /// descriptor.
    pub lineage_sha256: String,
}

impl B4CampaignValidatorBindingV1 {
    fn validate(&self) -> Result<()> {
        require_identity(
            &self.build_descriptor,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_DESCRIPTOR_BYTES,
            "validator build descriptor",
        )?;
        require_identity(
            &self.artifact,
            B4ContractArtifactEncodingV1::RawBytes,
            MAX_VALIDATOR_ARTIFACT_BYTES,
            "validator artifact",
        )?;
        self.reviewed_source.validate("validator reviewed source")?;
        validate_digest(&self.lineage_sha256, "validator lineage SHA-256")?;
        require_distinct_paths(
            [
                &self.build_descriptor,
                &self.artifact,
                &self.reviewed_source.archive,
            ],
            "validator descriptor, artifact, and source",
        )
    }
}

/// Canonical pre-proof campaign precommit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Eip0045B4CampaignPrecommitV1 {
    /// Exact V1 format discriminator.
    pub format: String,
    /// Exact V1 format version.
    pub format_version: u8,
    /// Exact create-only positive input-set identity.
    pub input_set: B4ContractArtifactIdentityV1,
    /// Complete exact campaign-executor binding.
    pub campaign_executor: B4CampaignExecutorBindingV1,
    /// Exact command-contract identity of that executor.
    pub executor_contract: B4ContractArtifactIdentityV1,
    /// Exact dual-surface verifier-contract identity.
    pub verifier_contract: B4ContractArtifactIdentityV1,
    /// Exact 508-slot expectation-set identity.
    pub expectation_set: B4ContractArtifactIdentityV1,
    /// Exactly Rust then JVM validator descriptor/artifact bindings.
    pub validators: Vec<B4CampaignValidatorBindingV1>,
    /// Exactly four runner-profile identities in the closed role order.
    pub runner_profiles: Vec<B4NamedContractArtifactIdentityV1>,
    /// Exactly four seccomp-document identities in the same role order.
    pub seccomp_documents: Vec<B4NamedContractArtifactIdentityV1>,
    /// Exact JVM COPY-ONLY inclusion-manifest identity.
    pub jvm_copy_only_inclusion_manifest: B4ContractArtifactIdentityV1,
    /// Exact outputs which post-precommit commands may publish.
    pub future_output_roles: Vec<String>,
}

impl Eip0045B4CampaignPrecommitV1 {
    /// Parse exact RFC 8785 JCS and enforce the closed precommit grammar.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, duplicate-key,
    /// noncanonical, unknown-field, unsafe, reordered, aliased, or
    /// inconsistent input.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        parse_contract(
            source,
            MAX_CAMPAIGN_PRECOMMIT_BYTES,
            "B4 campaign precommit",
        )
    }

    /// Serialize this precommit as exact RFC 8785 JCS.
    ///
    /// # Errors
    ///
    /// Returns an error when the precommit is invalid or oversized.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        serialize_contract(self, MAX_CAMPAIGN_PRECOMMIT_BYTES, "B4 campaign precommit")
    }

    /// Validate all internal, ordered, encoding, and non-aliasing invariants.
    ///
    /// This is deliberately a document-local check. Physical identities and
    /// paths nested behind the verifier and positive-gate authorities are not
    /// visible here; consumers must use [`Self::verify_against`] with an
    /// authority built by [`B4CampaignPrecommitAuthorityV1::from_external_closure`].
    ///
    /// # Errors
    ///
    /// Returns an error for any V1 shape, order, role, encoding, identity,
    /// path, bound, or non-aliasing defect.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == B4_CAMPAIGN_PRECOMMIT_FORMAT,
            "wrong B4 campaign-precommit format"
        );
        ensure!(
            self.format_version == B4_CAMPAIGN_CONTRACT_FORMAT_VERSION,
            "wrong B4 campaign-precommit version"
        );
        require_identity(
            &self.input_set,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_INPUT_SET_BYTES,
            "input set",
        )?;
        self.campaign_executor.validate()?;
        require_identity(
            &self.executor_contract,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_EXECUTOR_CONTRACT_BYTES as u64,
            "campaign executor contract",
        )?;
        require_identity(
            &self.verifier_contract,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_VERIFIER_CONTRACT_BYTES as u64,
            "verifier contract",
        )?;
        require_identity(
            &self.expectation_set,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_EXPECTATION_SET_BYTES,
            "expectation set",
        )?;
        require_identity(
            &self.jvm_copy_only_inclusion_manifest,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_JVM_INCLUSION_MANIFEST_BYTES,
            "JVM COPY-ONLY inclusion manifest",
        )?;
        validate_validator_bindings(&self.validators)?;
        validate_fixed_named_inventory(
            &self.runner_profiles,
            &B4_CAMPAIGN_RUNNER_ROLES,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_RUNNER_PROFILE_BYTES,
            "runner profile",
        )?;
        validate_fixed_named_inventory(
            &self.seccomp_documents,
            &B4_CAMPAIGN_RUNNER_ROLES,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_SECCOMP_DOCUMENT_BYTES,
            "seccomp document",
        )?;
        ensure!(
            strings_equal_exact(&self.future_output_roles, &B4_CAMPAIGN_FUTURE_OUTPUT_ROLES),
            "future output roles differ from the exact ordered V1 inventory"
        );
        require_global_path_injectivity(
            std::iter::once(&self.input_set)
                .chain(std::iter::once(&self.campaign_executor.artifact))
                .chain(std::iter::once(
                    &self.campaign_executor.reviewed_source.archive,
                ))
                .chain(std::iter::once(&self.campaign_executor.build_descriptor))
                .chain(std::iter::once(&self.executor_contract))
                .chain(std::iter::once(&self.verifier_contract))
                .chain(std::iter::once(&self.expectation_set))
                .chain(self.validators.iter().flat_map(|binding| {
                    [
                        &binding.build_descriptor,
                        &binding.artifact,
                        &binding.reviewed_source.archive,
                    ]
                }))
                .chain(
                    self.runner_profiles
                        .iter()
                        .map(|identity| &identity.artifact),
                )
                .chain(
                    self.seccomp_documents
                        .iter()
                        .map(|identity| &identity.artifact),
                )
                .chain(std::iter::once(&self.jvm_copy_only_inclusion_manifest)),
            "campaign precommit",
        )?;
        Ok(())
    }

    /// Rebind every variable identity to independently selected expectations.
    ///
    /// # Errors
    ///
    /// Returns an error when this precommit is internally invalid, the
    /// external expectations are invalid, or any identity/list position
    /// differs.
    pub fn verify_against(&self, expected: &B4CampaignPrecommitAuthorityV1) -> Result<()> {
        self.validate()?;
        ensure!(
            self == &expected.expected,
            "campaign precommit differs from the externally closed authority"
        );
        Ok(())
    }
}

impl CanonicalContract for Eip0045B4CampaignPrecommitV1 {
    fn validate_contract(&self) -> Result<()> {
        self.validate()
    }
}

/// Opaque campaign-precommit authority.
///
/// Instances are created only by the exact-byte closure constructor. The type
/// authenticates byte relationships, not the historical independence of the
/// people or systems which selected those bytes; that remains finalizer
/// custody evidence.
#[derive(Clone, Debug)]
pub struct B4CampaignPrecommitAuthorityV1 {
    expected: Eip0045B4CampaignPrecommitV1,
    verifier_authority: B4VerifierContractAuthorityV1,
    artifact_paths: BTreeSet<String>,
}

/// Opaque affine V2 authority prescribing the unchanged canonical V1
/// campaign-precommit wire.
///
/// V2 names the validated positive-input provenance used to derive this
/// authority, not a second serialized document format. Candidate bytes are
/// therefore parsed only as [`Eip0045B4CampaignPrecommitV1`] and compared
/// byte-exactly with the internally derived V1 document. This type has no
/// parser, deserializer, clone, copy, default, V1 conversion, or caller-filled
/// constructor.
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::B4CampaignPrecommitAuthorityV2;
/// fn require_clone<T: Clone>() {}
/// require_clone::<B4CampaignPrecommitAuthorityV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::B4CampaignPrecommitAuthorityV2;
/// fn require_copy<T: Copy>() {}
/// require_copy::<B4CampaignPrecommitAuthorityV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::B4CampaignPrecommitAuthorityV2;
/// fn require_default<T: Default>() {}
/// require_default::<B4CampaignPrecommitAuthorityV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::B4CampaignPrecommitAuthorityV2;
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<B4CampaignPrecommitAuthorityV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::B4CampaignPrecommitAuthorityV2;
/// fn require_deserialize<T: for<'de> serde::Deserialize<'de>>() {}
/// require_deserialize::<B4CampaignPrecommitAuthorityV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::B4CampaignPrecommitAuthorityV2;
/// let _ = B4CampaignPrecommitAuthorityV2 {};
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::{
///     B4CampaignPrecommitAuthorityV1, B4CampaignPrecommitAuthorityV2,
/// };
/// fn downgrade(value: B4CampaignPrecommitAuthorityV2) -> B4CampaignPrecommitAuthorityV1 {
///     value.into()
/// }
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::{
///     B4CampaignPrecommitAuthorityV1, B4CampaignPrecommitAuthorityV2,
/// };
/// fn upgrade(value: B4CampaignPrecommitAuthorityV1) -> B4CampaignPrecommitAuthorityV2 {
///     value.into()
/// }
/// ```
pub struct B4CampaignPrecommitAuthorityV2 {
    expected: Eip0045B4CampaignPrecommitV1,
    verifier_authority: B4VerifierContractAuthorityV1,
    artifact_paths: BTreeSet<String>,
}

/// Opaque projection emitted only after the positive gate has parsed and
/// cross-bound the exact input set, verifier contract, descriptors, profiles,
/// seccomp documents, and JVM packaging manifest.
///
/// The constructor is crate-private so an external caller cannot manufacture
/// this token from a candidate precommit.
#[derive(Clone, Debug)]
pub struct B4PositiveGateAuthorityV1 {
    input_set: B4ContractArtifactIdentityV1,
    verifier_contract: B4ContractArtifactIdentityV1,
    expectation_set: B4ContractArtifactIdentityV1,
    validators: [B4CampaignValidatorBindingV1; 2],
    runner_profiles: [B4NamedContractArtifactIdentityV1; 4],
    seccomp_documents: [B4NamedContractArtifactIdentityV1; 4],
    jvm_copy_only_inclusion_manifest: B4ContractArtifactIdentityV1,
    provenance_paths: BTreeSet<String>,
}

/// Opaque affine projection emitted only after the exact V2 positive
/// precommit documents have been semantically validated and cross-bound.
///
/// The type deliberately exposes no parser, deserializer, clone, copy,
/// default, V1 conversion, or field constructor. Its sole crate-private mint
/// accepts already validated projections from the positive-gate module, and
/// the public V2 campaign constructor consumes the value.
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::B4PositivePrecommitAuthorityV2;
/// fn require_clone<T: Clone>() {}
/// require_clone::<B4PositivePrecommitAuthorityV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::B4PositivePrecommitAuthorityV2;
/// fn require_copy<T: Copy>() {}
/// require_copy::<B4PositivePrecommitAuthorityV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::B4PositivePrecommitAuthorityV2;
/// fn require_default<T: Default>() {}
/// require_default::<B4PositivePrecommitAuthorityV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::B4PositivePrecommitAuthorityV2;
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<B4PositivePrecommitAuthorityV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::B4PositivePrecommitAuthorityV2;
/// fn require_deserialize<T: for<'de> serde::Deserialize<'de>>() {}
/// require_deserialize::<B4PositivePrecommitAuthorityV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::B4PositivePrecommitAuthorityV2;
/// let _ = B4PositivePrecommitAuthorityV2 {};
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::{
///     B4PositiveGateAuthorityV1, B4PositivePrecommitAuthorityV2,
/// };
/// fn downgrade(value: B4PositivePrecommitAuthorityV2) -> B4PositiveGateAuthorityV1 {
///     value.into()
/// }
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::{
///     B4PositiveGateAuthorityV1, B4PositivePrecommitAuthorityV2,
/// };
/// fn upgrade(value: B4PositiveGateAuthorityV1) -> B4PositivePrecommitAuthorityV2 {
///     value.into()
/// }
/// ```
pub struct B4PositivePrecommitAuthorityV2 {
    input_set: B4ContractArtifactIdentityV1,
    verifier_contract: B4ContractArtifactIdentityV1,
    expectation_set: B4ContractArtifactIdentityV1,
    validators: [B4CampaignValidatorBindingV1; 2],
    runner_profiles: [B4NamedContractArtifactIdentityV1; 4],
    seccomp_documents: [B4NamedContractArtifactIdentityV1; 4],
    jvm_copy_only_inclusion_manifest: B4ContractArtifactIdentityV1,
    provenance_paths: BTreeSet<String>,
}

impl B4PositiveGateAuthorityV1 {
    #[cfg(any(feature = "positive-gate", test))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_validated_positive_gate(
        input_set: B4ContractArtifactIdentityV1,
        verifier_contract: B4ContractArtifactIdentityV1,
        expectation_set: B4ContractArtifactIdentityV1,
        validators: [B4CampaignValidatorBindingV1; 2],
        runner_profiles: [B4NamedContractArtifactIdentityV1; 4],
        seccomp_documents: [B4NamedContractArtifactIdentityV1; 4],
        jvm_copy_only_inclusion_manifest: B4ContractArtifactIdentityV1,
        provenance_paths: &BTreeSet<String>,
    ) -> Result<Self> {
        input_set.validate_for(
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_INPUT_SET_BYTES,
            "positive-gate input set",
        )?;
        verifier_contract.validate_for(
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_VERIFIER_CONTRACT_BYTES as u64,
            "positive-gate verifier contract",
        )?;
        expectation_set.validate_for(
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_EXPECTATION_SET_BYTES,
            "positive-gate expectation set",
        )?;
        validate_validator_bindings(&validators)?;
        validate_fixed_named_inventory(
            &runner_profiles,
            &B4_CAMPAIGN_RUNNER_ROLES,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_RUNNER_PROFILE_BYTES,
            "positive-gate runner profile",
        )?;
        validate_fixed_named_inventory(
            &seccomp_documents,
            &B4_CAMPAIGN_RUNNER_ROLES,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_SECCOMP_DOCUMENT_BYTES,
            "positive-gate seccomp document",
        )?;
        jvm_copy_only_inclusion_manifest.validate_for(
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_JVM_INCLUSION_MANIFEST_BYTES,
            "positive-gate JVM inclusion manifest",
        )?;
        let provenance_paths = require_path_antichain(
            provenance_paths.iter().map(String::as_str),
            "positive-gate provenance",
        )?;
        for required_path in std::iter::once(input_set.path.as_str())
            .chain(std::iter::once(verifier_contract.path.as_str()))
            .chain(validators.iter().flat_map(|binding| {
                [
                    binding.build_descriptor.path.as_str(),
                    binding.artifact.path.as_str(),
                    binding.reviewed_source.archive.path.as_str(),
                ]
            }))
            .chain(
                runner_profiles
                    .iter()
                    .map(|identity| identity.artifact.path.as_str()),
            )
            .chain(
                seccomp_documents
                    .iter()
                    .map(|identity| identity.artifact.path.as_str()),
            )
            .chain(std::iter::once(
                jvm_copy_only_inclusion_manifest.path.as_str(),
            ))
        {
            ensure!(
                provenance_paths.contains(required_path),
                "positive-gate provenance omits a directly bound campaign path: {required_path}"
            );
        }
        Ok(Self {
            input_set,
            verifier_contract,
            expectation_set,
            validators,
            runner_profiles,
            seccomp_documents,
            jvm_copy_only_inclusion_manifest,
            provenance_paths,
        })
    }

    /// Complete pre-proof physical path closure validated by the positive gate.
    pub(crate) fn provenance_paths(&self) -> &BTreeSet<String> {
        &self.provenance_paths
    }
}

impl B4PositivePrecommitAuthorityV2 {
    #[cfg(any(feature = "positive-gate", test))]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_validated_positive_precommit(
        input_set: B4ContractArtifactIdentityV1,
        verifier_contract: B4ContractArtifactIdentityV1,
        expectation_set: B4ContractArtifactIdentityV1,
        validators: [B4CampaignValidatorBindingV1; 2],
        runner_profiles: [B4NamedContractArtifactIdentityV1; 4],
        seccomp_documents: [B4NamedContractArtifactIdentityV1; 4],
        jvm_copy_only_inclusion_manifest: B4ContractArtifactIdentityV1,
        provenance_paths: &BTreeSet<String>,
    ) -> Result<Self> {
        input_set.validate_for(
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_INPUT_SET_BYTES,
            "V2 positive-precommit input set",
        )?;
        verifier_contract.validate_for(
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_VERIFIER_CONTRACT_BYTES as u64,
            "V2 positive-precommit verifier contract",
        )?;
        expectation_set.validate_for(
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_EXPECTATION_SET_BYTES,
            "V2 positive-precommit expectation set",
        )?;
        validate_validator_bindings(&validators)?;
        validate_fixed_named_inventory(
            &runner_profiles,
            &B4_CAMPAIGN_RUNNER_ROLES,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_RUNNER_PROFILE_BYTES,
            "V2 positive-precommit runner profile",
        )?;
        validate_fixed_named_inventory(
            &seccomp_documents,
            &B4_CAMPAIGN_RUNNER_ROLES,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_SECCOMP_DOCUMENT_BYTES,
            "V2 positive-precommit seccomp document",
        )?;
        jvm_copy_only_inclusion_manifest.validate_for(
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_JVM_INCLUSION_MANIFEST_BYTES,
            "V2 positive-precommit JVM inclusion manifest",
        )?;
        let provenance_paths = require_path_antichain(
            provenance_paths.iter().map(String::as_str),
            "V2 positive-precommit provenance",
        )?;
        for required_path in std::iter::once(input_set.path.as_str())
            .chain(std::iter::once(verifier_contract.path.as_str()))
            .chain(validators.iter().flat_map(|binding| {
                [
                    binding.build_descriptor.path.as_str(),
                    binding.artifact.path.as_str(),
                    binding.reviewed_source.archive.path.as_str(),
                ]
            }))
            .chain(
                runner_profiles
                    .iter()
                    .map(|identity| identity.artifact.path.as_str()),
            )
            .chain(
                seccomp_documents
                    .iter()
                    .map(|identity| identity.artifact.path.as_str()),
            )
            .chain(std::iter::once(
                jvm_copy_only_inclusion_manifest.path.as_str(),
            ))
        {
            ensure!(
                provenance_paths.contains(required_path),
                "V2 positive-precommit provenance omits a directly bound campaign path: {required_path}"
            );
        }
        Ok(Self {
            input_set,
            verifier_contract,
            expectation_set,
            validators,
            runner_profiles,
            seccomp_documents,
            jvm_copy_only_inclusion_manifest,
            provenance_paths,
        })
    }
}

/// Exact external bytes remeasured while closing a campaign precommit.
#[derive(Clone, Copy, Debug)]
pub struct B4CampaignPrecommitExternalInputsV1<'a> {
    /// Exact positive input set consumed by the positive gate.
    pub input_set: B4ExternalArtifactV1<'a>,
    /// Exact measured campaign-executor binary.
    pub campaign_executor_artifact: B4ExternalArtifactV1<'a>,
    /// Exact externally reviewed executor source identity and Git bundle.
    pub campaign_executor_reviewed_source: B4ExternalReviewedSourceV1<'a>,
    /// Exact canonical executor build descriptor.
    pub campaign_executor_build_descriptor: B4ExternalArtifactV1<'a>,
    /// Exact closed eleven-command executor contract.
    pub executor_contract: B4ExternalArtifactV1<'a>,
    /// Exact verifier contract already consumed by the positive gate.
    pub verifier_contract: B4ExternalArtifactV1<'a>,
    /// Exact normative verifier CLI bytes retained by verifier authority.
    pub verifier_cli_spec: B4ExternalArtifactV1<'a>,
    /// Exact canonical negative plan retained by verifier authority.
    pub negative_plan: B4ExternalArtifactV1<'a>,
    /// Exact 508-slot expectation set selected by verifier authority.
    pub expectation_set: B4ExternalArtifactV1<'a>,
    /// Exact ordered verifier schema documents retained by verifier authority.
    pub verifier_schema_documents: [B4ExternalSchemaDocumentV1<'a>; B4_VERIFIER_SCHEMA_ROLES.len()],
    /// Exact Rust then JVM descriptor bytes consumed by the positive gate.
    pub validator_build_descriptors: [B4ExternalArtifactV1<'a>; 2],
    /// Exact Rust then JVM artifact bytes.
    pub validator_artifacts: [B4ExternalArtifactV1<'a>; 2],
    /// Exact Rust then JVM reviewed Git bundle bytes.
    pub validator_source_archives: [B4ExternalArtifactV1<'a>; 2],
    /// Exact four runner-profile documents consumed by the positive gate.
    pub runner_profiles: [B4ExternalArtifactV1<'a>; 4],
    /// Exact four seccomp documents consumed by the positive gate.
    pub seccomp_documents: [B4ExternalArtifactV1<'a>; 4],
    /// Exact JVM COPY-ONLY inclusion manifest consumed by the positive gate.
    pub jvm_copy_only_inclusion_manifest: B4ExternalArtifactV1<'a>,
}

/// Exact external bytes remeasured while closing one V2-derived campaign
/// precommit authority.
///
/// The final serialized precommit remains the V1 wire. The V2 suffix denotes
/// that the positive input, runner, and validator identities are supplied by a
/// distinct consumed [`B4PositivePrecommitAuthorityV2`].
///
/// A detached path cannot replace the opaque validated H0 completion token:
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::B4CampaignPrecommitExternalInputsV2;
/// fn substitute_detached_path(inputs: &mut B4CampaignPrecommitExternalInputsV2<'_>) {
///     inputs.positive_input_set_completion = "detached/completion.json";
/// }
/// ```
#[derive(Debug)]
pub struct B4CampaignPrecommitExternalInputsV2<'a> {
    /// Exact canonical V2 positive input set consumed by the positive gate.
    pub input_set: B4ExternalArtifactV1<'a>,
    /// Opaque proof of the exact H0 completion bytes and their closed path.
    pub positive_input_set_completion: B4ValidatedPositiveInputSetCompletionV2,
    /// Exact measured campaign-executor binary.
    pub campaign_executor_artifact: B4ExternalArtifactV1<'a>,
    /// Exact externally reviewed executor source identity and Git bundle.
    pub campaign_executor_reviewed_source: B4ExternalReviewedSourceV1<'a>,
    /// Exact canonical executor build descriptor.
    pub campaign_executor_build_descriptor: B4ExternalArtifactV1<'a>,
    /// Exact closed eleven-command executor contract.
    pub executor_contract: B4ExternalArtifactV1<'a>,
    /// Exact V1 verifier contract committed by the V2 positive input set.
    pub verifier_contract: B4ExternalArtifactV1<'a>,
    /// Exact normative verifier CLI bytes retained by verifier authority.
    pub verifier_cli_spec: B4ExternalArtifactV1<'a>,
    /// Exact canonical negative plan retained by verifier authority.
    pub negative_plan: B4ExternalArtifactV1<'a>,
    /// Exact 508-slot expectation set selected by verifier authority.
    pub expectation_set: B4ExternalArtifactV1<'a>,
    /// Exact ordered V1 verifier schema documents retained by verifier authority.
    pub verifier_schema_documents: [B4ExternalSchemaDocumentV1<'a>; B4_VERIFIER_SCHEMA_ROLES.len()],
    /// Exact Rust then JVM V2 descriptor bytes consumed by the positive gate.
    pub validator_build_descriptors: [B4ExternalArtifactV1<'a>; 2],
    /// Exact Rust then JVM artifact bytes.
    pub validator_artifacts: [B4ExternalArtifactV1<'a>; 2],
    /// Exact Rust then JVM reviewed Git bundle bytes.
    pub validator_source_archives: [B4ExternalArtifactV1<'a>; 2],
    /// Exact four V2 runner-profile documents consumed by the positive gate.
    pub runner_profiles: [B4ExternalArtifactV1<'a>; 4],
    /// Exact four seccomp documents consumed by the positive gate.
    pub seccomp_documents: [B4ExternalArtifactV1<'a>; 4],
    /// Exact JVM COPY-ONLY inclusion manifest consumed by the positive gate.
    pub jvm_copy_only_inclusion_manifest: B4ExternalArtifactV1<'a>,
}

impl B4CampaignPrecommitAuthorityV1 {
    /// Rebuild the complete precommit from an opaque positive-gate projection
    /// and exact independently held physical bytes.
    ///
    /// The byte constructor proves all current cross-document links and
    /// remeasures the executor, both validator artifacts/descriptors/source
    /// archives, verifier contract, and expectation set. Historical source
    /// independence and review provenance remain finalizer custody evidence.
    ///
    /// # Errors
    ///
    /// Returns an error for any stale digest, wrong format, source or artifact
    /// mismatch, missing JVM binding, cross-role alias, command drift, or
    /// canonical-byte defect.
    #[allow(clippy::too_many_lines)]
    pub fn from_external_closure(
        positive_gate: &B4PositiveGateAuthorityV1,
        verifier_authority: &B4VerifierContractAuthorityV1,
        external: B4CampaignPrecommitExternalInputsV1<'_>,
    ) -> Result<Self> {
        ensure!(
            external.input_set.identity(
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                MAX_INPUT_SET_BYTES,
                "positive input set",
            )? == positive_gate.input_set,
            "positive input-set bytes differ from the positive-gate input set"
        );
        verifier_authority.verify_external_replay(
            external.verifier_cli_spec,
            external.negative_plan,
            external.expectation_set,
            &external.verifier_schema_documents,
        )?;
        for index in 0..B4_CAMPAIGN_RUNNER_ROLES.len() {
            ensure!(
                external.runner_profiles[index].identity(
                    B4ContractArtifactEncodingV1::Rfc8785Jcs,
                    MAX_RUNNER_PROFILE_BYTES,
                    "runner profile",
                )? == positive_gate.runner_profiles[index].artifact,
                "runner-profile bytes differ from the positive-gate document at index {index}"
            );
            ensure!(
                external.seccomp_documents[index].identity(
                    B4ContractArtifactEncodingV1::Rfc8785Jcs,
                    MAX_SECCOMP_DOCUMENT_BYTES,
                    "seccomp document",
                )? == positive_gate.seccomp_documents[index].artifact,
                "seccomp bytes differ from the positive-gate document at index {index}"
            );
        }
        ensure!(
            external.jvm_copy_only_inclusion_manifest.identity(
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                MAX_JVM_INCLUSION_MANIFEST_BYTES,
                "JVM COPY-ONLY inclusion manifest",
            )? == positive_gate.jvm_copy_only_inclusion_manifest,
            "JVM COPY-ONLY inclusion-manifest bytes differ from the positive gate"
        );

        let executor_contract = Eip0045B4CampaignExecutorContractV1::from_canonical_jcs(
            external.executor_contract.bytes,
        )?;
        ensure!(
            executor_contract == Eip0045B4CampaignExecutorContractV1::closed_v1(),
            "external executor contract differs from the closed V1 command contract"
        );
        let executor_contract_identity = external.executor_contract.identity(
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_EXECUTOR_CONTRACT_BYTES as u64,
            "campaign executor contract",
        )?;
        let executor_artifact_identity = external.campaign_executor_artifact.identity(
            B4ContractArtifactEncodingV1::RawBytes,
            MAX_EXECUTOR_ARTIFACT_BYTES,
            "campaign executor artifact",
        )?;
        let executor_reviewed_source = external
            .campaign_executor_reviewed_source
            .binding("campaign executor reviewed source")?;
        let executor_build_descriptor =
            Eip0045B4CampaignExecutorBuildDescriptorV1::from_canonical_jcs(
                external.campaign_executor_build_descriptor.bytes,
            )?;
        ensure!(
            executor_build_descriptor.artifact == executor_artifact_identity
                && executor_build_descriptor.reviewed_source == executor_reviewed_source
                && executor_build_descriptor.executor_contract == executor_contract_identity,
            "campaign executor build descriptor does not bind the measured artifact, reviewed source, and command contract"
        );

        let verifier_contract =
            Eip0045B4VerifierContractV1::from_canonical_jcs(external.verifier_contract.bytes)?;
        verifier_contract.verify_against(verifier_authority)?;
        let verifier_contract_identity = external.verifier_contract.identity(
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_VERIFIER_CONTRACT_BYTES as u64,
            "verifier contract",
        )?;
        ensure!(
            verifier_contract_identity == positive_gate.verifier_contract,
            "positive input set and campaign closure bind different verifier contracts"
        );

        verify_b4_negative_expectation_set(
            external.expectation_set.bytes,
            &verifier_authority.negative_plan_source,
        )?;
        let expectation_set_identity = external.expectation_set.identity(
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_EXPECTATION_SET_BYTES,
            "expectation set",
        )?;
        ensure!(
            expectation_set_identity == positive_gate.expectation_set
                && expectation_set_identity == verifier_contract.expectation_set,
            "positive gate, verifier contract, and campaign closure bind different expectation sets"
        );

        let validator_bindings = positive_gate.validators.clone();
        for (index, validator_binding) in validator_bindings.iter().enumerate() {
            let descriptor_identity = external.validator_build_descriptors[index].identity(
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                MAX_DESCRIPTOR_BYTES,
                "validator build descriptor",
            )?;
            ensure!(
                descriptor_identity == validator_binding.build_descriptor,
                "validator descriptor bytes differ from the positive-gate descriptor"
            );
            let artifact_identity = external.validator_artifacts[index].identity(
                B4ContractArtifactEncodingV1::RawBytes,
                MAX_VALIDATOR_ARTIFACT_BYTES,
                "validator artifact",
            )?;
            ensure!(
                artifact_identity == validator_binding.artifact,
                "validator artifact bytes differ from the descriptor-bound artifact"
            );
            let source_identity = external.validator_source_archives[index].identity(
                B4ContractArtifactEncodingV1::GitBundle,
                MAX_SOURCE_ARCHIVE_BYTES,
                "validator source archive",
            )?;
            ensure!(
                source_identity == validator_binding.reviewed_source.archive,
                "validator source archive differs from the descriptor-bound reviewed source"
            );
        }

        let campaign_executor = B4CampaignExecutorBindingV1 {
            artifact: executor_artifact_identity,
            reviewed_source: executor_reviewed_source,
            build_descriptor: external.campaign_executor_build_descriptor.identity(
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                MAX_DESCRIPTOR_BYTES,
                "campaign executor build descriptor",
            )?,
        };
        let artifact_paths = require_path_antichain(
            positive_gate
                .provenance_paths()
                .iter()
                .map(String::as_str)
                .chain(
                    verifier_authority
                        .artifact_paths()
                        .iter()
                        .map(String::as_str),
                )
                .chain([
                    campaign_executor.artifact.path.as_str(),
                    campaign_executor.reviewed_source.archive.path.as_str(),
                    campaign_executor.build_descriptor.path.as_str(),
                    executor_contract_identity.path.as_str(),
                ]),
            "global campaign closure",
        )?;

        let expected = Eip0045B4CampaignPrecommitV1 {
            format: B4_CAMPAIGN_PRECOMMIT_FORMAT.to_owned(),
            format_version: B4_CAMPAIGN_CONTRACT_FORMAT_VERSION,
            input_set: positive_gate.input_set.clone(),
            campaign_executor,
            executor_contract: executor_contract_identity,
            verifier_contract: verifier_contract_identity,
            expectation_set: expectation_set_identity,
            validators: validator_bindings.to_vec(),
            runner_profiles: positive_gate.runner_profiles.to_vec(),
            seccomp_documents: positive_gate.seccomp_documents.to_vec(),
            jvm_copy_only_inclusion_manifest: positive_gate
                .jvm_copy_only_inclusion_manifest
                .clone(),
            future_output_roles: B4_CAMPAIGN_FUTURE_OUTPUT_ROLES
                .iter()
                .map(ToString::to_string)
                .collect(),
        };
        expected.validate()?;
        Ok(Self {
            expected,
            verifier_authority: verifier_authority.clone(),
            artifact_paths,
        })
    }

    /// Exact canonical precommit bytes prescribed by this authority.
    ///
    /// # Errors
    ///
    /// Returns an error if the retained precommit no longer satisfies its
    /// closed grammar or canonical byte bound.
    pub fn to_canonical_precommit_jcs(&self) -> Result<Vec<u8>> {
        self.expected.to_canonical_jcs()
    }

    /// Exact immutable precommit prescribed by this authority.
    #[must_use]
    pub fn precommit(&self) -> &Eip0045B4CampaignPrecommitV1 {
        &self.expected
    }

    /// Retained non-forgeable verifier closure for later finalizer stages.
    #[must_use]
    pub fn verifier_authority(&self) -> &B4VerifierContractAuthorityV1 {
        &self.verifier_authority
    }

    /// Complete ancestry-safe physical path closure retained for later
    /// finalizer stages.
    #[must_use]
    pub fn artifact_paths(&self) -> &BTreeSet<String> {
        &self.artifact_paths
    }
}

impl B4CampaignPrecommitAuthorityV2 {
    /// Derive the unchanged V1 wire precommit from one consumed V2 positive
    /// precommit authority and exact independently held physical bytes.
    ///
    /// The constructor remeasures every direct input, replays the complete V1
    /// verifier authority, and closes the same global path antichain as the V1
    /// campaign constructor. It accepts no candidate precommit bytes and no
    /// post-generation authority.
    ///
    /// # Errors
    ///
    /// Returns an error for any stale digest, wrong format, source or artifact
    /// mismatch, missing JVM binding, cross-role alias, command drift, or
    /// canonical-byte defect.
    #[allow(clippy::too_many_lines)]
    pub fn from_external_closure(
        positive_precommit: B4PositivePrecommitAuthorityV2,
        verifier_authority: &B4VerifierContractAuthorityV1,
        external: B4CampaignPrecommitExternalInputsV2<'_>,
    ) -> Result<Self> {
        let external_input_set = external.input_set.identity(
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_INPUT_SET_BYTES,
            "V2 positive input set",
        )?;
        ensure!(
            external_input_set == positive_precommit.input_set,
            "V2 positive input-set bytes differ from the positive-precommit authority"
        );
        ensure!(
            external.positive_input_set_completion.input_set_identity()
                == &positive_precommit.input_set,
            "validated V2 positive input-set completion belongs to a different input set"
        );
        verifier_authority.verify_external_replay(
            external.verifier_cli_spec,
            external.negative_plan,
            external.expectation_set,
            &external.verifier_schema_documents,
        )?;
        for index in 0..B4_CAMPAIGN_RUNNER_ROLES.len() {
            ensure!(
                external.runner_profiles[index].identity(
                    B4ContractArtifactEncodingV1::Rfc8785Jcs,
                    MAX_RUNNER_PROFILE_BYTES,
                    "V2 runner profile",
                )? == positive_precommit.runner_profiles[index].artifact,
                "V2 runner-profile bytes differ from the positive-precommit document at index {index}"
            );
            ensure!(
                external.seccomp_documents[index].identity(
                    B4ContractArtifactEncodingV1::Rfc8785Jcs,
                    MAX_SECCOMP_DOCUMENT_BYTES,
                    "seccomp document",
                )? == positive_precommit.seccomp_documents[index].artifact,
                "seccomp bytes differ from the V2 positive-precommit document at index {index}"
            );
        }
        ensure!(
            external.jvm_copy_only_inclusion_manifest.identity(
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                MAX_JVM_INCLUSION_MANIFEST_BYTES,
                "JVM COPY-ONLY inclusion manifest",
            )? == positive_precommit.jvm_copy_only_inclusion_manifest,
            "JVM COPY-ONLY inclusion-manifest bytes differ from the V2 positive-precommit authority"
        );

        let executor_contract = Eip0045B4CampaignExecutorContractV1::from_canonical_jcs(
            external.executor_contract.bytes,
        )?;
        ensure!(
            executor_contract == Eip0045B4CampaignExecutorContractV1::closed_v1(),
            "external executor contract differs from the closed V1 command contract"
        );
        let executor_contract_identity = external.executor_contract.identity(
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_EXECUTOR_CONTRACT_BYTES as u64,
            "campaign executor contract",
        )?;
        let executor_artifact_identity = external.campaign_executor_artifact.identity(
            B4ContractArtifactEncodingV1::RawBytes,
            MAX_EXECUTOR_ARTIFACT_BYTES,
            "campaign executor artifact",
        )?;
        let executor_reviewed_source = external
            .campaign_executor_reviewed_source
            .binding("campaign executor reviewed source")?;
        let executor_build_descriptor =
            Eip0045B4CampaignExecutorBuildDescriptorV1::from_canonical_jcs(
                external.campaign_executor_build_descriptor.bytes,
            )?;
        ensure!(
            executor_build_descriptor.artifact == executor_artifact_identity
                && executor_build_descriptor.reviewed_source == executor_reviewed_source
                && executor_build_descriptor.executor_contract == executor_contract_identity,
            "campaign executor build descriptor does not bind the measured artifact, reviewed source, and command contract"
        );

        let verifier_contract =
            Eip0045B4VerifierContractV1::from_canonical_jcs(external.verifier_contract.bytes)?;
        verifier_contract.verify_against(verifier_authority)?;
        let verifier_contract_identity = external.verifier_contract.identity(
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_VERIFIER_CONTRACT_BYTES as u64,
            "verifier contract",
        )?;
        ensure!(
            verifier_contract_identity == positive_precommit.verifier_contract,
            "V2 positive input set and campaign closure bind different verifier contracts"
        );

        verify_b4_negative_expectation_set(
            external.expectation_set.bytes,
            &verifier_authority.negative_plan_source,
        )?;
        let expectation_set_identity = external.expectation_set.identity(
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            MAX_EXPECTATION_SET_BYTES,
            "expectation set",
        )?;
        ensure!(
            expectation_set_identity == positive_precommit.expectation_set
                && expectation_set_identity == verifier_contract.expectation_set,
            "V2 positive precommit, verifier contract, and campaign closure bind different expectation sets"
        );

        let validator_bindings = positive_precommit.validators;
        for (index, validator_binding) in validator_bindings.iter().enumerate() {
            let descriptor_identity = external.validator_build_descriptors[index].identity(
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                MAX_DESCRIPTOR_BYTES,
                "V2 validator build descriptor",
            )?;
            ensure!(
                descriptor_identity == validator_binding.build_descriptor,
                "V2 validator descriptor bytes differ from the positive-precommit descriptor"
            );
            let artifact_identity = external.validator_artifacts[index].identity(
                B4ContractArtifactEncodingV1::RawBytes,
                MAX_VALIDATOR_ARTIFACT_BYTES,
                "validator artifact",
            )?;
            ensure!(
                artifact_identity == validator_binding.artifact,
                "validator artifact bytes differ from the V2 descriptor-bound artifact"
            );
            let source_identity = external.validator_source_archives[index].identity(
                B4ContractArtifactEncodingV1::GitBundle,
                MAX_SOURCE_ARCHIVE_BYTES,
                "validator source archive",
            )?;
            ensure!(
                source_identity == validator_binding.reviewed_source.archive,
                "validator source archive differs from the V2 descriptor-bound reviewed source"
            );
        }

        let campaign_executor = B4CampaignExecutorBindingV1 {
            artifact: executor_artifact_identity,
            reviewed_source: executor_reviewed_source,
            build_descriptor: external.campaign_executor_build_descriptor.identity(
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                MAX_DESCRIPTOR_BYTES,
                "campaign executor build descriptor",
            )?,
        };
        let artifact_paths = require_path_antichain(
            positive_precommit
                .provenance_paths
                .iter()
                .map(String::as_str)
                .chain(
                    verifier_authority
                        .artifact_paths()
                        .iter()
                        .map(String::as_str),
                )
                .chain(std::iter::once(
                    external.positive_input_set_completion.completion_path(),
                ))
                .chain([
                    campaign_executor.artifact.path.as_str(),
                    campaign_executor.reviewed_source.archive.path.as_str(),
                    campaign_executor.build_descriptor.path.as_str(),
                    executor_contract_identity.path.as_str(),
                ]),
            "global V2-derived campaign closure",
        )?;

        let expected = Eip0045B4CampaignPrecommitV1 {
            format: B4_CAMPAIGN_PRECOMMIT_FORMAT.to_owned(),
            format_version: B4_CAMPAIGN_CONTRACT_FORMAT_VERSION,
            input_set: positive_precommit.input_set,
            campaign_executor,
            executor_contract: executor_contract_identity,
            verifier_contract: verifier_contract_identity,
            expectation_set: expectation_set_identity,
            validators: validator_bindings.to_vec(),
            runner_profiles: positive_precommit.runner_profiles.to_vec(),
            seccomp_documents: positive_precommit.seccomp_documents.to_vec(),
            jvm_copy_only_inclusion_manifest: positive_precommit.jvm_copy_only_inclusion_manifest,
            future_output_roles: B4_CAMPAIGN_FUTURE_OUTPUT_ROLES
                .iter()
                .map(ToString::to_string)
                .collect(),
        };
        expected.validate()?;
        Ok(Self {
            expected,
            verifier_authority: verifier_authority.clone(),
            artifact_paths,
        })
    }

    /// Exact canonical V1 wire prescribed by this V2-derived authority.
    ///
    /// # Errors
    ///
    /// Returns an error if the retained V1 document no longer satisfies its
    /// closed grammar or canonical byte bound.
    pub fn to_canonical_precommit_jcs(&self) -> Result<Vec<u8>> {
        self.expected.to_canonical_jcs()
    }

    /// Require candidate bytes to be the exact canonical V1 wire prescribed
    /// by this V2-derived authority.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, V2-discriminated, or
    /// byte-different input.
    pub fn verify_candidate_jcs(&self, source: &[u8]) -> Result<()> {
        let candidate = Eip0045B4CampaignPrecommitV1::from_canonical_jcs(source)?;
        ensure!(
            candidate == self.expected && source == self.expected.to_canonical_jcs()?,
            "candidate campaign precommit differs from the V2-derived authority"
        );
        Ok(())
    }

    /// Exact immutable V1 wire document prescribed by this V2-derived authority.
    #[must_use]
    pub fn precommit(&self) -> &Eip0045B4CampaignPrecommitV1 {
        &self.expected
    }

    /// Retained non-forgeable V1 verifier closure.
    #[must_use]
    pub fn verifier_authority(&self) -> &B4VerifierContractAuthorityV1 {
        &self.verifier_authority
    }

    /// Complete ancestry-safe physical path closure retained for later stages.
    #[must_use]
    pub fn artifact_paths(&self) -> &BTreeSet<String> {
        &self.artifact_paths
    }
}

trait CanonicalContract: Serialize + DeserializeOwned {
    fn validate_contract(&self) -> Result<()>;
}

fn parse_contract<T>(source: &[u8], maximum_bytes: usize, label: &'static str) -> Result<T>
where
    T: CanonicalContract,
{
    ensure!(
        source.len() <= maximum_bytes,
        "{label} exceeds its canonical-byte bound"
    );
    let value = validate_canonical_json_source(source)
        .with_context(|| format!("{label} is not exact RFC 8785 JCS"))?;
    let contract: T =
        serde_json::from_value(value).with_context(|| format!("invalid {label} shape"))?;
    contract.validate_contract()?;
    ensure!(
        serialize_contract(&contract, maximum_bytes, label)? == source,
        "{label} does not round-trip byte-exactly"
    );
    Ok(contract)
}

fn serialize_contract<T>(contract: &T, maximum_bytes: usize, label: &'static str) -> Result<Vec<u8>>
where
    T: CanonicalContract,
{
    contract.validate_contract()?;
    let value =
        serde_json::to_value(contract).with_context(|| format!("cannot serialize {label}"))?;
    let bytes = canonical_json_bytes(&value)?;
    ensure!(
        bytes.len() <= maximum_bytes,
        "{label} exceeds its canonical-byte bound"
    );
    Ok(bytes)
}

fn require_identity(
    identity: &B4ContractArtifactIdentityV1,
    expected: B4ContractArtifactEncodingV1,
    maximum_bytes: u64,
    label: &str,
) -> Result<()> {
    identity.validate_for(expected, maximum_bytes, label)
}

fn validate_named_inventory(
    identities: &[B4NamedContractArtifactIdentityV1],
    minimum: usize,
    maximum: usize,
    expected_encoding: Option<B4ContractArtifactEncodingV1>,
    maximum_bytes: u64,
    label: &str,
) -> Result<()> {
    ensure!(
        (minimum..=maximum).contains(&identities.len()),
        "{label} inventory length is outside the V1 bound"
    );
    let mut roles = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for (index, identity) in identities.iter().enumerate() {
        identity
            .validate()
            .with_context(|| format!("invalid {label} identity at index {index}"))?;
        if let Some(encoding) = expected_encoding {
            ensure!(
                identity.artifact.encoding == encoding,
                "{label} identity at index {index} uses the wrong encoding"
            );
        }
        ensure!(
            identity.artifact.byte_length <= maximum_bytes,
            "{label} identity at index {index} exceeds its role-specific byte bound"
        );
        ensure!(
            roles.insert(identity.role.as_str()),
            "duplicate {label} role at index {index}"
        );
        insert_non_conflicting_path(
            &mut paths,
            identity.artifact.path.as_str(),
            &format!("{label} path at index {index}"),
        )?;
    }
    Ok(())
}

fn validate_fixed_named_inventory(
    identities: &[B4NamedContractArtifactIdentityV1],
    roles: &[&str],
    expected_encoding: B4ContractArtifactEncodingV1,
    maximum_bytes: u64,
    label: &str,
) -> Result<()> {
    validate_named_inventory(
        identities,
        roles.len(),
        roles.len(),
        Some(expected_encoding),
        maximum_bytes,
        label,
    )?;
    ensure!(
        identities
            .iter()
            .map(|identity| identity.role.as_str())
            .eq(roles.iter().copied()),
        "{label} roles differ from the exact ordered V1 inventory"
    );
    Ok(())
}

fn verifier_contract_artifact_paths(
    contract: &Eip0045B4VerifierContractV1,
) -> Result<BTreeSet<String>> {
    require_path_antichain(
        std::iter::once(contract.cli_spec.path.as_str())
            .chain(std::iter::once(contract.negative_plan.path.as_str()))
            .chain(std::iter::once(contract.expectation_set.path.as_str()))
            .chain(
                contract
                    .schema_identities
                    .iter()
                    .map(|identity| identity.artifact.path.as_str()),
            ),
        "verifier-authority artifact closure",
    )
}

fn validate_validator_bindings(bindings: &[B4CampaignValidatorBindingV1]) -> Result<()> {
    ensure!(
        bindings.len() == 2,
        "campaign precommit must bind exactly two validators"
    );
    ensure!(
        bindings[0].implementation == B4CampaignValidatorImplementationV1::RustReference
            && bindings[1].implementation == B4CampaignValidatorImplementationV1::IndependentJvm,
        "validator bindings must be ordered Rust reference then independent JVM"
    );
    for (index, binding) in bindings.iter().enumerate() {
        binding
            .validate()
            .with_context(|| format!("invalid validator binding at index {index}"))?;
    }
    ensure!(
        !b4_paths_conflict(&bindings[0].artifact.path, &bindings[1].artifact.path)
            && bindings[0].artifact.sha256 != bindings[1].artifact.sha256,
        "Rust and JVM validator artifacts alias or path-conflict"
    );
    ensure!(
        !b4_paths_conflict(
            &bindings[0].build_descriptor.path,
            &bindings[1].build_descriptor.path
        ) && bindings[0].build_descriptor.sha256 != bindings[1].build_descriptor.sha256,
        "Rust and JVM validator descriptors alias or path-conflict"
    );
    ensure!(
        bindings[0].reviewed_source.repository != bindings[1].reviewed_source.repository
            || bindings[0].reviewed_source.commit != bindings[1].reviewed_source.commit
            || bindings[0].reviewed_source.tree != bindings[1].reviewed_source.tree,
        "Rust and JVM reviewed source tuples alias"
    );
    ensure!(
        !b4_paths_conflict(
            &bindings[0].reviewed_source.archive.path,
            &bindings[1].reviewed_source.archive.path
        ) && bindings[0].reviewed_source.archive.sha256
            != bindings[1].reviewed_source.archive.sha256,
        "Rust and JVM reviewed source archives alias or path-conflict"
    );
    ensure!(
        bindings[0].lineage_sha256 != bindings[1].lineage_sha256,
        "Rust and JVM implementation lineages alias"
    );
    Ok(())
}

fn require_distinct_paths<'a>(
    identities: impl IntoIterator<Item = &'a B4ContractArtifactIdentityV1>,
    label: &str,
) -> Result<()> {
    require_path_antichain(
        identities
            .into_iter()
            .map(|identity| identity.path.as_str()),
        label,
    )?;
    Ok(())
}

fn require_global_path_injectivity<'a>(
    identities: impl IntoIterator<Item = &'a B4ContractArtifactIdentityV1>,
    label: &str,
) -> Result<()> {
    require_path_antichain(
        identities
            .into_iter()
            .map(|identity| identity.path.as_str()),
        label,
    )?;
    Ok(())
}

fn require_path_antichain<'a>(
    candidates: impl IntoIterator<Item = &'a str>,
    label: &str,
) -> Result<BTreeSet<String>> {
    let mut paths = BTreeSet::new();
    for path in candidates {
        validate_safe_relative_path(path)
            .with_context(|| format!("{label} contains an invalid artifact path"))?;
        insert_non_conflicting_path(&mut paths, path, label)?;
    }
    Ok(paths)
}

fn insert_non_conflicting_path(
    paths: &mut BTreeSet<String>,
    candidate: &str,
    label: &str,
) -> Result<()> {
    if let Some(existing) = paths
        .iter()
        .find(|existing| b4_paths_conflict(existing, candidate))
    {
        ensure!(
            false,
            "{label} path conflict: {candidate} equals, contains, or is contained by {existing}"
        );
    }
    paths.insert(candidate.to_owned());
    Ok(())
}

/// Return true when two canonical relative paths name the same component path
/// or when either is a component ancestor of the other.
pub(crate) fn b4_paths_conflict(left: &str, right: &str) -> bool {
    fn is_same_or_ancestor(ancestor: &str, descendant: &str) -> bool {
        ancestor == descendant
            || descendant
                .strip_prefix(ancestor)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }

    is_same_or_ancestor(left, right) || is_same_or_ancestor(right, left)
}

fn strings_equal_exact(actual: &[String], expected: &[&str]) -> bool {
    actual
        .iter()
        .map(String::as_str)
        .eq(expected.iter().copied())
}

fn validate_role(role: &str) -> Result<()> {
    ensure!(
        (1..=MAX_ROLE_BYTES).contains(&role.len()),
        "contract role length is outside the V1 bound"
    );
    let mut components = role.split('-');
    let first = components.next().context("contract role is empty")?;
    validate_role_component(first, true)?;
    for component in components {
        validate_role_component(component, false)?;
    }
    Ok(())
}

fn validate_role_component(component: &str, first: bool) -> Result<()> {
    ensure!(
        !component.is_empty(),
        "contract role contains an empty component"
    );
    let bytes = component.as_bytes();
    if first {
        ensure!(
            bytes[0].is_ascii_lowercase(),
            "contract role must start with a lowercase letter"
        );
    }
    ensure!(
        bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()),
        "contract role must use canonical lowercase kebab-case"
    );
    Ok(())
}

pub(crate) fn validate_safe_relative_path(path: &str) -> Result<()> {
    ensure!(
        (1..=MAX_RELATIVE_PATH_BYTES).contains(&path.len()),
        "artifact path length is outside the V1 bound"
    );
    ensure!(
        path.is_ascii(),
        "artifact path must use the portable ASCII subset"
    );
    ensure!(
        path.as_bytes()[0].is_ascii_lowercase() || path.as_bytes()[0].is_ascii_digit(),
        "artifact path must start with a lowercase letter or digit"
    );
    ensure!(
        path.as_bytes().iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-' | b'/')
        }),
        "artifact path contains a non-portable character"
    );
    ensure!(
        !path.ends_with('/') && !path.contains("//"),
        "artifact path has a non-canonical separator"
    );
    for component in path.split('/') {
        ensure!(
            !component.is_empty() && component != "." && component != "..",
            "artifact path contains an empty, dot, or parent component"
        );
        ensure!(
            component.as_bytes()[0].is_ascii_lowercase()
                || component.as_bytes()[0].is_ascii_digit(),
            "artifact path component must start with a lowercase letter or digit"
        );
        ensure!(
            !component.ends_with('.'),
            "artifact path component has a trailing dot"
        );
        let device_stem = component.split('.').next().unwrap_or(component);
        ensure!(
            !is_windows_device_name(device_stem),
            "artifact path contains a reserved Windows device component"
        );
    }
    Ok(())
}

fn validate_repository(repository: &str, label: &str) -> Result<()> {
    ensure!(
        (20..=200).contains(&repository.len()) && repository.is_ascii(),
        "{label} repository length or encoding is invalid"
    );
    let body = repository
        .strip_prefix("https://github.com/")
        .and_then(|value| value.strip_suffix(".git"))
        .context("reviewed repository must be a canonical GitHub HTTPS URL")?;
    let mut parts = body.split('/');
    let owner = parts
        .next()
        .context("reviewed repository owner is absent")?;
    let name = parts.next().context("reviewed repository name is absent")?;
    ensure!(
        parts.next().is_none() && !owner.is_empty() && !name.is_empty(),
        "{label} repository must contain exactly one owner and repository"
    );
    ensure!(
        owner.as_bytes()[0].is_ascii_lowercase() || owner.as_bytes()[0].is_ascii_digit(),
        "{label} repository owner has a noncanonical first byte"
    );
    ensure!(
        name.as_bytes()[0].is_ascii_lowercase() || name.as_bytes()[0].is_ascii_digit(),
        "{label} repository name has a noncanonical first byte"
    );
    ensure!(
        owner.bytes().all(|byte| byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'.' | b'-'))
            && name.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            }),
        "{label} repository contains a noncanonical byte"
    );
    Ok(())
}

fn validate_git_object_id(value: &str, label: &str) -> Result<()> {
    ensure!(
        value.len() == 40
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "{label} must be exactly 20 lowercase hexadecimal bytes"
    );
    ensure!(
        value.bytes().any(|byte| byte != b'0'),
        "{label} cannot be the all-zero placeholder"
    );
    Ok(())
}

fn validate_schema_source(source: &[u8], expected_id: &str, role: &str) -> Result<Value> {
    let source_len =
        u64::try_from(source.len()).context("schema byte length does not fit unsigned 64-bit")?;
    ensure!(
        (1..=MAX_SCHEMA_DOCUMENT_BYTES).contains(&source_len),
        "{role} schema byte length is outside the V1 bound"
    );
    let value =
        parse_json_strict(source).with_context(|| format!("{role} schema is not strict JSON"))?;
    validate_schema_document(&value, expected_id, role)?;
    Ok(value)
}

fn validate_pinned_schema_source(
    index: usize,
    schema: B4ExternalSchemaDocumentV1<'_>,
) -> Result<()> {
    ensure!(
        index < B4_VERIFIER_SCHEMA_ROLES.len(),
        "external schema index is outside the closed inventory"
    );
    ensure!(
        schema.role == B4_VERIFIER_SCHEMA_ROLES[index],
        "external schema role differs from the closed inventory at index {index}"
    );
    ensure!(
        schema.document.bytes == B4_VERIFIER_SCHEMA_SOURCES[index],
        "external {} schema bytes differ from the compiled checked-in authority",
        schema.role
    );
    validate_schema_source(
        schema.document.bytes,
        B4_VERIFIER_SCHEMA_IDS[index],
        schema.role,
    )?;
    Ok(())
}

fn validate_schema_document(value: &Value, expected_id: &str, role: &str) -> Result<()> {
    let object = value
        .as_object()
        .with_context(|| format!("{role} schema root must be an object"))?;
    ensure!(
        object.get("$schema").and_then(Value::as_str)
            == Some("https://json-schema.org/draft/2020-12/schema"),
        "{role} schema does not declare Draft 2020-12"
    );
    ensure!(
        object.get("$id").and_then(Value::as_str) == Some(expected_id),
        "{role} schema has the wrong canonical ID"
    );
    ensure!(
        object.get("type").and_then(Value::as_str) == Some("object"),
        "{role} schema root type must be object"
    );
    ensure!(
        object.get("additionalProperties").and_then(Value::as_bool) == Some(false),
        "{role} schema root must close additional properties"
    );
    validate_internal_schema_references(value, true, role)?;
    #[cfg(feature = "positive-gate")]
    jsonschema::draft202012::options()
        .build(value)
        .map_err(|error| {
            anyhow::anyhow!("{role} schema does not compile as Draft 2020-12: {error}")
        })?;
    Ok(())
}

fn validate_internal_schema_references(value: &Value, root: bool, role: &str) -> Result<()> {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("object") {
                ensure!(
                    object.get("additionalProperties").and_then(Value::as_bool) == Some(false),
                    "{role} schema contains an open object subschema"
                );
            }
            for (key, nested) in object {
                if matches!(key.as_str(), "$ref" | "$dynamicRef") {
                    let reference = nested
                        .as_str()
                        .with_context(|| format!("{role} schema {key} must be a string"))?;
                    ensure!(
                        reference.starts_with('#'),
                        "{role} schema contains a non-internal {key}: {reference}"
                    );
                }
                ensure!(
                    root || key != "$id",
                    "{role} schema contains a nested resource ID"
                );
                validate_internal_schema_references(nested, false, role)?;
            }
        }
        Value::Array(values) => {
            for nested in values {
                validate_internal_schema_references(nested, false, role)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn is_windows_device_name(component: &str) -> bool {
    matches!(component, "con" | "prn" | "aux" | "nul")
        || component
            .strip_prefix("com")
            .is_some_and(is_windows_device_digit)
        || component
            .strip_prefix("lpt")
            .is_some_and(is_windows_device_digit)
}

fn is_windows_device_digit(suffix: &str) -> bool {
    suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9')
}

fn validate_digest(digest: &str, label: &str) -> Result<()> {
    ensure!(
        digest.len() == 64
            && digest
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')),
        "{label} must be exactly 32 lowercase hexadecimal bytes"
    );
    ensure!(
        digest.as_bytes().iter().any(|byte| *byte != b'0'),
        "{label} cannot be the all-zero placeholder"
    );
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(all(test, feature = "positive-gate"))]
pub(crate) mod test_support {
    use super::*;
    use crate::b4_positive_gate::test_support::{
        build_positive_precommit_v2_test_support as build_raw_positive_precommit_v2_test_support,
        PositivePrecommitV2TestSupport,
    };
    #[cfg(feature = "recursive-ancestry")]
    use crate::b4_positive_gate::{
        test_support::{
            build_positive_authority_test_support,
            build_positive_authority_test_support_with_reference_statement,
            v2_semantic_identity_documents_test_support, OwnedPositiveAuthorityTestArtifactV1,
            OwnedPositiveAuthorityTestCaseV1,
        },
        validate_and_bind_v2_positive_generation_preacceptance, B4PositiveGenerationAuthorityV1,
        B4ValidatedPositiveGenerationPreacceptanceV2, GeneratedArtifactContents,
        GeneratedAuxiliaryArtifactContents, NamedCanonicalJcs, PositiveGenerationCaseDocuments,
        PositiveGenerationDocuments, PositiveRunnerRole,
    };
    use crate::b4_positive_input_set::{
        bind_b4_positive_input_set_publication_v2, derive_b4_positive_input_set_completion_jcs_v2,
        project_b4_positive_input_set_publication_paths_v2,
        validate_b4_positive_input_set_completion_jcs_v2, B4ValidatedPositiveInputSetCompletionV2,
    };
    #[cfg(feature = "recursive-ancestry")]
    use crate::{
        b4::{B4ArtifactEncoding, B4PositiveArtifactRole},
        b4_fixture_sources::synthetic_valid_recursive_ancestry_top_level,
        b4_materialization_set::{
            compiled_positive_generation_recipe, parse_positive_input_sources,
            parse_positive_input_sources_v2, positive_artifact_layout,
        },
    };
    use crate::{
        b4_build_check::{AuthoritativeB4BuildProjection, TestAuthoritativeB4BuildProjection},
        b4_expectation::{
            B4NegativeExpectationPairV1, B4NegativeExpectationSlotV1,
            B4NegativeExpectedRejectionV1, Eip0045B4NegativeExpectationSetV1,
        },
        b4_result::B4ValidatorImplementation,
    };
    use serde_json::Value;

    fn build_positive_precommit_v2_test_support(
        verifier_contract_jcs: &[u8],
        validator_artifacts: [&[u8]; 2],
        validator_source_archives: [&[u8]; 2],
    ) -> Result<(
        B4PositivePrecommitAuthorityV2,
        PositivePrecommitV2TestSupport,
    )> {
        const H0_INPUT_SET_PATH: &str = "h0/prepare-001/positive-input-set.json";
        let (authority, mut support) = build_raw_positive_precommit_v2_test_support(
            verifier_contract_jcs,
            validator_artifacts,
            validator_source_archives,
        )?;
        let B4PositivePrecommitAuthorityV2 {
            input_set: prior_input_set,
            verifier_contract,
            expectation_set,
            validators,
            runner_profiles,
            seccomp_documents,
            jvm_copy_only_inclusion_manifest,
            mut provenance_paths,
        } = authority;
        assert!(provenance_paths.remove(&prior_input_set.path));
        assert!(provenance_paths.insert(H0_INPUT_SET_PATH.to_owned()));
        support.input_set.path = H0_INPUT_SET_PATH.to_owned();
        let input_set = B4ContractArtifactIdentityV1::from_bytes(
            H0_INPUT_SET_PATH,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            &support.input_set.bytes,
        )?;
        let authority = B4PositivePrecommitAuthorityV2::from_validated_positive_precommit(
            input_set,
            verifier_contract,
            expectation_set,
            validators,
            runner_profiles,
            seccomp_documents,
            jvm_copy_only_inclusion_manifest,
            &provenance_paths,
        )?;
        Ok((authority, support))
    }

    #[cfg(feature = "positive-gate")]
    const VERIFIER_CONTRACT_SCHEMA: &str =
        include_str!("../finalizer-schema/b4-verifier-contract-v1.schema.json");
    #[cfg(feature = "positive-gate")]
    const EXECUTOR_CONTRACT_SCHEMA: &str =
        include_str!("../finalizer-schema/b4-campaign-executor-contract-v1.schema.json");
    #[cfg(feature = "positive-gate")]
    const EXECUTOR_BUILD_DESCRIPTOR_SCHEMA: &str =
        include_str!("../finalizer-schema/b4-campaign-executor-build-descriptor-v1.schema.json");
    #[cfg(feature = "positive-gate")]
    const CAMPAIGN_PRECOMMIT_SCHEMA: &str =
        include_str!("../finalizer-schema/b4-campaign-precommit-v1.schema.json");
    #[cfg(feature = "recursive-ancestry")]
    const HISTORICAL_REFERENCE_CHAIN_DOMAIN_ID: [u8; 32] = [0x71; 32];
    #[cfg(feature = "recursive-ancestry")]
    const HISTORICAL_REFERENCE_APPLICATION_PAYLOAD: &[u8] = b"";

    fn artifact(
        path: &str,
        encoding: B4ContractArtifactEncodingV1,
        seed: &str,
    ) -> B4ContractArtifactIdentityV1 {
        B4ContractArtifactIdentityV1::from_bytes(path, encoding, seed.as_bytes()).unwrap()
    }

    fn named(role: &str, path: &str, seed: &str) -> B4NamedContractArtifactIdentityV1 {
        B4NamedContractArtifactIdentityV1 {
            role: role.to_owned(),
            artifact: artifact(path, B4ContractArtifactEncodingV1::Rfc8785Jcs, seed),
        }
    }

    fn named_schema(role: &str, path: &str, seed: &str) -> B4NamedContractArtifactIdentityV1 {
        B4NamedContractArtifactIdentityV1 {
            role: role.to_owned(),
            artifact: artifact(path, B4ContractArtifactEncodingV1::RawBytes, seed),
        }
    }

    fn verifier_contract() -> Eip0045B4VerifierContractV1 {
        Eip0045B4VerifierContractV1 {
            format: B4_VERIFIER_CONTRACT_FORMAT.to_owned(),
            format_version: B4_CAMPAIGN_CONTRACT_FORMAT_VERSION,
            interface: B4_VERIFIER_INTERFACE.to_owned(),
            positive_subcommand: B4_POSITIVE_SUBCOMMAND.to_owned(),
            negative_subcommand: B4_NEGATIVE_SUBCOMMAND.to_owned(),
            cli_spec: artifact(
                "docs/specs/b4-verifier-cli-v2.md",
                B4ContractArtifactEncodingV1::RawBytes,
                "cli-v2",
            ),
            negative_plan: artifact(
                "reproduction/negative-plan.json",
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                "negative-plan",
            ),
            expectation_set: artifact(
                "reproduction/expectation-set.json",
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                "expectations",
            ),
            schema_identities: B4_VERIFIER_SCHEMA_ROLES
                .iter()
                .map(|role| {
                    named_schema(
                        role,
                        &format!("reproduction/finalizer-schema/{role}.schema.json"),
                        &format!("{role}-schema"),
                    )
                })
                .collect(),
        }
    }

    fn reviewed_source(prefix: &str) -> B4ReviewedSourceBindingV1 {
        let commit_digest = sha256_hex(format!("{prefix}-commit").as_bytes());
        let tree_digest = sha256_hex(format!("{prefix}-tree").as_bytes());
        B4ReviewedSourceBindingV1 {
            repository: format!("https://github.com/example/{prefix}-validator.git"),
            commit: commit_digest[..40].to_owned(),
            tree: tree_digest[..40].to_owned(),
            archive: artifact(
                &format!("reproduction/preproof/{prefix}-source.bundle"),
                B4ContractArtifactEncodingV1::GitBundle,
                &format!("{prefix}-source"),
            ),
        }
    }

    fn validator(
        implementation: B4CampaignValidatorImplementationV1,
        prefix: &str,
    ) -> B4CampaignValidatorBindingV1 {
        B4CampaignValidatorBindingV1 {
            implementation,
            build_descriptor: artifact(
                &format!("reproduction/preproof/{prefix}-descriptor.json"),
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &format!("{prefix}-descriptor"),
            ),
            artifact: artifact(
                &format!("reproduction/preproof/{prefix}-validator.bin"),
                B4ContractArtifactEncodingV1::RawBytes,
                &format!("{prefix}-artifact"),
            ),
            reviewed_source: reviewed_source(prefix),
            lineage_sha256: sha256_hex(format!("{prefix}-lineage").as_bytes()),
        }
    }

    fn fixed_named(prefix: &str) -> Vec<B4NamedContractArtifactIdentityV1> {
        B4_CAMPAIGN_RUNNER_ROLES
            .iter()
            .enumerate()
            .map(|(index, role)| {
                named(
                    role,
                    &format!("reproduction/preproof/{prefix}-{index}.json"),
                    &format!("{prefix}-{index}"),
                )
            })
            .collect()
    }

    fn precommit(verifier: &Eip0045B4VerifierContractV1) -> Eip0045B4CampaignPrecommitV1 {
        let verifier_source = verifier.to_canonical_jcs().unwrap();
        Eip0045B4CampaignPrecommitV1 {
            format: B4_CAMPAIGN_PRECOMMIT_FORMAT.to_owned(),
            format_version: B4_CAMPAIGN_CONTRACT_FORMAT_VERSION,
            input_set: artifact(
                "reproduction/preproof/input-set.json",
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                "input-set",
            ),
            campaign_executor: B4CampaignExecutorBindingV1 {
                artifact: artifact(
                    "reproduction/preproof/campaign-executor",
                    B4ContractArtifactEncodingV1::RawBytes,
                    "campaign-executor",
                ),
                reviewed_source: reviewed_source("campaign-executor"),
                build_descriptor: artifact(
                    "reproduction/preproof/campaign-executor-build.json",
                    B4ContractArtifactEncodingV1::Rfc8785Jcs,
                    "campaign-executor-build",
                ),
            },
            executor_contract: artifact(
                "reproduction/preproof/executor-contract.json",
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                "executor-contract",
            ),
            verifier_contract: B4ContractArtifactIdentityV1::from_bytes(
                "reproduction/preproof/verifier-contract.json",
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &verifier_source,
            )
            .unwrap(),
            expectation_set: verifier.expectation_set.clone(),
            validators: vec![
                validator(B4CampaignValidatorImplementationV1::RustReference, "rust"),
                validator(B4CampaignValidatorImplementationV1::IndependentJvm, "jvm"),
            ],
            runner_profiles: fixed_named("runner"),
            seccomp_documents: fixed_named("seccomp"),
            jvm_copy_only_inclusion_manifest: artifact(
                "reproduction/preproof/jvm-inclusion.json",
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                "jvm-inclusion",
            ),
            future_output_roles: B4_CAMPAIGN_FUTURE_OUTPUT_ROLES
                .iter()
                .map(ToString::to_string)
                .collect(),
        }
    }

    fn verifier_authority(contract: &Eip0045B4VerifierContractV1) -> B4VerifierContractAuthorityV1 {
        B4VerifierContractAuthorityV1 {
            expected: contract.clone(),
            cli_spec_source: Vec::new(),
            negative_plan_source: Vec::new(),
            expectation_set_source: Vec::new(),
            schema_sources: std::array::from_fn(|_| Vec::new()),
            artifact_paths: verifier_contract_artifact_paths(contract).unwrap(),
        }
    }

    fn precommit_authority(value: &Eip0045B4CampaignPrecommitV1) -> B4CampaignPrecommitAuthorityV1 {
        B4CampaignPrecommitAuthorityV1 {
            expected: value.clone(),
            verifier_authority: verifier_authority(&verifier_contract()),
            artifact_paths: require_path_antichain(
                value
                    .validators
                    .iter()
                    .flat_map(|binding| {
                        [
                            binding.build_descriptor.path.as_str(),
                            binding.artifact.path.as_str(),
                            binding.reviewed_source.archive.path.as_str(),
                        ]
                    })
                    .chain([
                        value.input_set.path.as_str(),
                        value.campaign_executor.artifact.path.as_str(),
                        value
                            .campaign_executor
                            .reviewed_source
                            .archive
                            .path
                            .as_str(),
                        value.campaign_executor.build_descriptor.path.as_str(),
                        value.executor_contract.path.as_str(),
                        value.verifier_contract.path.as_str(),
                        value.expectation_set.path.as_str(),
                        value.jvm_copy_only_inclusion_manifest.path.as_str(),
                    ])
                    .chain(
                        value
                            .runner_profiles
                            .iter()
                            .map(|identity| identity.artifact.path.as_str()),
                    )
                    .chain(
                        value
                            .seccomp_documents
                            .iter()
                            .map(|identity| identity.artifact.path.as_str()),
                    ),
                "test precommit authority",
            )
            .unwrap(),
        }
    }

    fn canonical_plan_and_expectation() -> (Vec<u8>, Vec<u8>) {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let plan_source = plan.to_canonical_jcs().unwrap();
        let slots = |execution: &crate::b4_plan::B4NegativePlanExecutionV1| {
            let boundary =
                crate::b4_negative_handler_contract::exact_negative_rejection_boundary(execution)
                    .unwrap();
            let class = boundary.class().to_owned();
            let stage = boundary.stage().to_owned();
            vec![
                B4NegativeExpectationSlotV1 {
                    implementation: B4ValidatorImplementation::RustReference,
                    rejection: B4NegativeExpectedRejectionV1 {
                        class: class.clone(),
                        stage: stage.clone(),
                    },
                },
                B4NegativeExpectationSlotV1 {
                    implementation: B4ValidatorImplementation::IndependentJvm,
                    rejection: B4NegativeExpectedRejectionV1 { class, stage },
                },
            ]
        };
        let pairs = plan
            .groups
            .iter()
            .flat_map(|group| &group.executions)
            .map(|execution| B4NegativeExpectationPairV1 {
                execution_id: execution.execution_id.clone(),
                slots: slots(execution),
            })
            .collect::<Vec<_>>();
        let expectation =
            Eip0045B4NegativeExpectationSetV1::from_external_pairs(&plan_source, &pairs).unwrap();
        (plan_source, expectation.to_canonical_jcs().unwrap())
    }

    fn minimal_schema_source(index: usize) -> Vec<u8> {
        canonical_json_bytes(&serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": B4_VERIFIER_SCHEMA_IDS[index],
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        }))
        .unwrap()
    }

    fn checked_in_verifier_schema_sources() -> [&'static [u8]; B4_VERIFIER_SCHEMA_ROLES.len()] {
        B4_VERIFIER_SCHEMA_SOURCES
    }

    struct ClosureFixture {
        positive_gate: B4PositiveGateAuthorityV1,
        verifier_authority: B4VerifierContractAuthorityV1,
        input_set: Vec<u8>,
        verifier_cli_spec: Vec<u8>,
        negative_plan: Vec<u8>,
        verifier_schema_documents: [Vec<u8>; B4_VERIFIER_SCHEMA_ROLES.len()],
        executor_artifact: Vec<u8>,
        executor_reviewed_source: B4ReviewedSourceBindingV1,
        executor_source_archive: Vec<u8>,
        executor_build_descriptor: Vec<u8>,
        executor_contract: Vec<u8>,
        verifier_contract: Vec<u8>,
        expectation_set: Vec<u8>,
        validator_descriptors: [Vec<u8>; 2],
        validator_artifacts: [Vec<u8>; 2],
        validator_source_archives: [Vec<u8>; 2],
        runner_profiles: [Vec<u8>; 4],
        seccomp_documents: [Vec<u8>; 4],
        jvm_copy_only_inclusion_manifest: Vec<u8>,
    }

    /// Test-only source closure produced by the real positive-generation and
    /// campaign-precommit authority constructors.
    ///
    /// The verifier-contract authority supplied to the campaign constructor is
    /// fixture-private: its production constructor remains deliberately
    /// fail-closed while nine negative-handler rows are still pending.
    #[derive(Clone, Debug)]
    #[cfg(feature = "recursive-ancestry")]
    #[allow(
        dead_code,
        reason = "the remaining exact source fields are consumed by the sibling public-constructor rejection test"
    )]
    pub(crate) struct NegativeAncestryConstructorTestSupportV1 {
        pub(crate) campaign_precommit_authority: B4CampaignPrecommitAuthorityV1,
        pub(crate) positive_generation_authority: B4PositiveGenerationAuthorityV1,
        pub(crate) campaign_precommit_jcs: Vec<u8>,
        pub(crate) positive_input_set: OwnedPositiveAuthorityTestArtifactV1,
        pub(crate) positive_generation_set: OwnedPositiveAuthorityTestArtifactV1,
        pub(crate) profile_manifest: OwnedPositiveAuthorityTestArtifactV1,
        pub(crate) profile_algorithm: OwnedPositiveAuthorityTestArtifactV1,
        pub(crate) profile_constants: OwnedPositiveAuthorityTestArtifactV1,
        pub(crate) consumer_guest_elf: OwnedPositiveAuthorityTestArtifactV1,
        pub(crate) materialization_sources: Vec<OwnedPositiveAuthorityTestArtifactV1>,
        pub(crate) positive_cases: [OwnedPositiveAuthorityTestCaseV1; 11],
        pub(crate) case9_proof_output_manifest_jcs: Vec<u8>,
        pub(crate) case9_primary_artifacts: Vec<OwnedPositiveAuthorityTestArtifactV1>,
        pub(crate) case9_auxiliary_artifacts: Vec<OwnedPositiveAuthorityTestArtifactV1>,
    }

    /// Immutable test-only closure for the fixed terminal-lineage constructor.
    ///
    /// Both opaque authorities are produced by their production constructors
    /// after the campaign executor fixture is aligned with the exact positive
    /// proof-generator bytes.
    #[derive(Clone, Debug)]
    #[cfg(feature = "recursive-ancestry")]
    #[allow(
        dead_code,
        reason = "checkpoint 2B consumes this immutable constructor support"
    )]
    pub(crate) struct TerminalLineageConstructorTestSupportV1 {
        pub(crate) campaign_precommit_authority: B4CampaignPrecommitAuthorityV1,
        pub(crate) positive_generation_authority: B4PositiveGenerationAuthorityV1,
        pub(crate) positive_input_set: OwnedPositiveAuthorityTestArtifactV1,
        pub(crate) positive_generation_set: OwnedPositiveAuthorityTestArtifactV1,
        pub(crate) consumer_guest_elf: OwnedPositiveAuthorityTestArtifactV1,
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

    /// One owned source used only to drive the production V2 closure in tests.
    #[cfg(feature = "recursive-ancestry")]
    #[derive(Clone, Debug)]
    pub(crate) struct OwnedPositiveAuthorityTestArtifactV2 {
        pub(crate) path: String,
        pub(crate) bytes: Vec<u8>,
    }

    #[cfg(feature = "recursive-ancestry")]
    impl OwnedPositiveAuthorityTestArtifactV2 {
        fn external(&self) -> B4PositiveGenerationExternalBytesV2<'_> {
            B4PositiveGenerationExternalBytesV2 {
                path: &self.path,
                bytes: &self.bytes,
            }
        }
    }

    /// One complete owned V2 positive-case export.
    #[cfg(feature = "recursive-ancestry")]
    #[derive(Clone, Debug)]
    pub(crate) struct OwnedPositiveAuthorityTestCaseV2 {
        pub(crate) proof_output_manifest: OwnedPositiveAuthorityTestArtifactV2,
        pub(crate) primary_artifacts: Vec<OwnedPositiveAuthorityTestArtifactV2>,
        pub(crate) auxiliary_artifacts: Vec<OwnedPositiveAuthorityTestArtifactV2>,
    }

    /// Exact owned source closure used to exercise the production affine V2 gate.
    #[cfg(feature = "recursive-ancestry")]
    #[derive(Clone, Debug)]
    pub(crate) struct PositiveGenerationConstructorSourcesV2 {
        pub(crate) authoritative_build: AuthoritativeB4BuildProjection,
        pub(crate) positive_input_set: OwnedPositiveAuthorityTestArtifactV2,
        pub(crate) positive_generation_set: OwnedPositiveAuthorityTestArtifactV2,
        pub(crate) proof_generator: OwnedPositiveAuthorityTestArtifactV2,
        pub(crate) runner_profiles: [OwnedPositiveAuthorityTestArtifactV2; 4],
        pub(crate) validator_descriptors: [OwnedPositiveAuthorityTestArtifactV2; 2],
        pub(crate) nested_input_sources: Vec<OwnedPositiveAuthorityTestArtifactV2>,
        pub(crate) cases: [OwnedPositiveAuthorityTestCaseV2; 11],
    }

    #[cfg(feature = "recursive-ancestry")]
    impl PositiveGenerationConstructorSourcesV2 {
        pub(crate) fn with_external_closure<T>(
            &self,
            use_closure: impl FnOnce(B4PositiveGenerationExternalClosureV2<'_>) -> T,
        ) -> T {
            let nested_input_sources = self
                .nested_input_sources
                .iter()
                .map(OwnedPositiveAuthorityTestArtifactV2::external)
                .collect::<Vec<_>>();
            let primary_artifacts: [Vec<_>; 11] = std::array::from_fn(|index| {
                self.cases[index]
                    .primary_artifacts
                    .iter()
                    .map(OwnedPositiveAuthorityTestArtifactV2::external)
                    .collect()
            });
            let auxiliary_artifacts: [Vec<_>; 11] = std::array::from_fn(|index| {
                self.cases[index]
                    .auxiliary_artifacts
                    .iter()
                    .map(OwnedPositiveAuthorityTestArtifactV2::external)
                    .collect()
            });
            let cases = std::array::from_fn(|index| B4PositiveGenerationCaseExternalV2 {
                proof_output_manifest: self.cases[index].proof_output_manifest.external(),
                primary_artifacts: &primary_artifacts[index],
                auxiliary_artifacts: &auxiliary_artifacts[index],
            });
            use_closure(B4PositiveGenerationExternalClosureV2 {
                positive_input_set: self.positive_input_set.external(),
                positive_generation_set: self.positive_generation_set.external(),
                proof_generator: self.proof_generator.external(),
                nested_input_sources: &nested_input_sources,
                cases,
            })
        }

        pub(crate) fn validate_preacceptance(
            &self,
        ) -> Result<B4ValidatedPositiveGenerationPreacceptanceV2> {
            let artifact_views: [Vec<GeneratedArtifactContents<'_>>; 11] =
                std::array::from_fn(|case_index| {
                    positive_artifact_layout(case_index)
                        .expect("fixed V2 positive case layout")
                        .iter()
                        .zip(&self.cases[case_index].primary_artifacts)
                        .map(|((_, source_file), artifact)| GeneratedArtifactContents {
                            source_file,
                            bytes: &artifact.bytes,
                        })
                        .collect()
                });
            let auxiliary_views: [Vec<GeneratedAuxiliaryArtifactContents<'_>>; 11] =
                std::array::from_fn(|case_index| {
                    self.cases[case_index]
                        .auxiliary_artifacts
                        .iter()
                        .map(|artifact| GeneratedAuxiliaryArtifactContents {
                            relative_path: &artifact.path,
                            bytes: &artifact.bytes,
                        })
                        .collect()
                });
            let cases = std::array::from_fn(|case_index| PositiveGenerationCaseDocuments {
                proof_output_manifest_jcs: &self.cases[case_index].proof_output_manifest.bytes,
                artifacts: &artifact_views[case_index],
                auxiliary_artifacts: &auxiliary_views[case_index],
            });
            self.with_external_closure(|physical| {
                validate_and_bind_v2_positive_generation_preacceptance(
                    &self.authoritative_build,
                    NamedCanonicalJcs {
                        relative_path: &self.positive_input_set.path,
                        bytes: &self.positive_input_set.bytes,
                    },
                    std::array::from_fn(|index| NamedCanonicalJcs {
                        relative_path: &self.runner_profiles[index].path,
                        bytes: &self.runner_profiles[index].bytes,
                    }),
                    std::array::from_fn(|index| NamedCanonicalJcs {
                        relative_path: &self.validator_descriptors[index].path,
                        bytes: &self.validator_descriptors[index].bytes,
                    }),
                    PositiveGenerationDocuments {
                        generation_set: NamedCanonicalJcs {
                            relative_path: &self.positive_generation_set.path,
                            bytes: &self.positive_generation_set.bytes,
                        },
                        proof_generator_artifact: &self.proof_generator.bytes,
                        cases,
                    },
                    physical,
                )
            })
        }
    }

    /// Production-created V1 campaign plus the distinct affine V2 generation gate.
    #[cfg(feature = "recursive-ancestry")]
    pub(crate) struct TerminalLineageConstructorTestSupportV2 {
        pub(crate) campaign_precommit_authority: B4CampaignPrecommitAuthorityV1,
        pub(crate) positive_generation_authority: B4PositiveGenerationAuthorityV2,
        pub(crate) sources: PositiveGenerationConstructorSourcesV2,
    }

    /// Separately valid campaign authorities used by the terminal-lineage
    /// boundary matrix. Both members are built through the production
    /// campaign constructor; no positive source bundle is retained.
    #[cfg(feature = "recursive-ancestry")]
    #[allow(
        dead_code,
        reason = "checkpoint 2C consumes these independently valid campaign authorities"
    )]
    pub(crate) struct TerminalLineageAlternateCampaignsV1 {
        pub(crate) different_input: B4CampaignPrecommitAuthorityV1,
        pub(crate) different_executor: B4CampaignPrecommitAuthorityV1,
    }

    impl ClosureFixture {
        #[allow(clippy::too_many_lines)]
        fn valid() -> Self {
            let (negative_plan_source, expectation_set) = canonical_plan_and_expectation();
            let mut verifier_contract = verifier_contract();
            verifier_contract.negative_plan = B4ContractArtifactIdentityV1::from_bytes(
                "reproduction/negative-plan.json",
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &negative_plan_source,
            )
            .unwrap();
            verifier_contract.expectation_set = B4ContractArtifactIdentityV1::from_bytes(
                "reproduction/expectation-set.json",
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &expectation_set,
            )
            .unwrap();
            let verifier_cli_spec = b"cli-v2".to_vec();
            let verifier_schema_documents =
                checked_in_verifier_schema_sources().map(<[u8]>::to_vec);
            verifier_contract.schema_identities = B4_VERIFIER_SCHEMA_ROLES
                .iter()
                .enumerate()
                .map(|(index, role)| B4NamedContractArtifactIdentityV1 {
                    role: (*role).to_owned(),
                    artifact: B4ContractArtifactIdentityV1::from_bytes(
                        format!("reproduction/finalizer-schema/{role}.schema.json"),
                        B4ContractArtifactEncodingV1::RawBytes,
                        &verifier_schema_documents[index],
                    )
                    .unwrap(),
                })
                .collect();
            let verifier_contract_source = verifier_contract.to_canonical_jcs().unwrap();
            let verifier_authority = B4VerifierContractAuthorityV1 {
                expected: verifier_contract.clone(),
                cli_spec_source: verifier_cli_spec.clone(),
                negative_plan_source: negative_plan_source.clone(),
                expectation_set_source: expectation_set.clone(),
                schema_sources: verifier_schema_documents.clone(),
                artifact_paths: verifier_contract_artifact_paths(&verifier_contract).unwrap(),
            };

            let validator_descriptors = [
                canonical_json_bytes(&serde_json::json!({
                    "format": "fixture-rust-validator-descriptor"
                }))
                .unwrap(),
                canonical_json_bytes(&serde_json::json!({
                    "format": "fixture-jvm-validator-descriptor"
                }))
                .unwrap(),
            ];
            let validator_artifacts = [
                b"measured-rust-validator".to_vec(),
                b"measured-jvm-validator".to_vec(),
            ];
            let validator_source_archives = [b"rust-source".to_vec(), b"jvm-source".to_vec()];
            let validators = [
                B4CampaignValidatorBindingV1 {
                    implementation: B4CampaignValidatorImplementationV1::RustReference,
                    build_descriptor: B4ContractArtifactIdentityV1::from_bytes(
                        "reproduction/preproof/rust-descriptor.json",
                        B4ContractArtifactEncodingV1::Rfc8785Jcs,
                        &validator_descriptors[0],
                    )
                    .unwrap(),
                    artifact: B4ContractArtifactIdentityV1::from_bytes(
                        "reproduction/preproof/rust-validator.bin",
                        B4ContractArtifactEncodingV1::RawBytes,
                        &validator_artifacts[0],
                    )
                    .unwrap(),
                    reviewed_source: reviewed_source("rust"),
                    lineage_sha256: sha256_hex(b"rust-lineage"),
                },
                B4CampaignValidatorBindingV1 {
                    implementation: B4CampaignValidatorImplementationV1::IndependentJvm,
                    build_descriptor: B4ContractArtifactIdentityV1::from_bytes(
                        "reproduction/preproof/jvm-descriptor.json",
                        B4ContractArtifactEncodingV1::Rfc8785Jcs,
                        &validator_descriptors[1],
                    )
                    .unwrap(),
                    artifact: B4ContractArtifactIdentityV1::from_bytes(
                        "reproduction/preproof/jvm-validator.bin",
                        B4ContractArtifactEncodingV1::RawBytes,
                        &validator_artifacts[1],
                    )
                    .unwrap(),
                    reviewed_source: reviewed_source("jvm"),
                    lineage_sha256: sha256_hex(b"jvm-lineage"),
                },
            ];
            assert_eq!(
                validators[0].reviewed_source.archive,
                B4ContractArtifactIdentityV1::from_bytes(
                    "reproduction/preproof/rust-source.bundle",
                    B4ContractArtifactEncodingV1::GitBundle,
                    &validator_source_archives[0],
                )
                .unwrap()
            );
            assert_eq!(
                validators[1].reviewed_source.archive,
                B4ContractArtifactIdentityV1::from_bytes(
                    "reproduction/preproof/jvm-source.bundle",
                    B4ContractArtifactEncodingV1::GitBundle,
                    &validator_source_archives[1],
                )
                .unwrap()
            );

            let input_set_source = canonical_json_bytes(&serde_json::json!({
                "format": "Eip0045B4PositiveInputSetV2",
                "formatVersion": 2,
            }))
            .unwrap();
            let inclusion_manifest_source = b"{}".to_vec();
            let runner_profiles: [Vec<u8>; 4] =
                std::array::from_fn(|index| format!("runner-{index}").into_bytes());
            let seccomp_documents: [Vec<u8>; 4] =
                std::array::from_fn(|index| format!("seccomp-{index}").into_bytes());
            let input_set_identity = B4ContractArtifactIdentityV1::from_bytes(
                "h0/prepare-001/positive-input-set.json",
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &input_set_source,
            )
            .unwrap();
            let verifier_contract_identity = B4ContractArtifactIdentityV1::from_bytes(
                "reproduction/preproof/verifier-contract.json",
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &verifier_contract_source,
            )
            .unwrap();
            let runner_bindings: [B4NamedContractArtifactIdentityV1; 4] =
                fixed_named("runner").try_into().unwrap();
            let seccomp_bindings: [B4NamedContractArtifactIdentityV1; 4] =
                fixed_named("seccomp").try_into().unwrap();
            let inclusion_identity = B4ContractArtifactIdentityV1::from_bytes(
                "reproduction/preproof/jvm-inclusion.json",
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &inclusion_manifest_source,
            )
            .unwrap();
            let positive_provenance_paths = require_path_antichain(
                std::iter::once(input_set_identity.path.as_str())
                    .chain(std::iter::once(verifier_contract_identity.path.as_str()))
                    .chain(validators.iter().flat_map(|binding| {
                        [
                            binding.build_descriptor.path.as_str(),
                            binding.artifact.path.as_str(),
                            binding.reviewed_source.archive.path.as_str(),
                        ]
                    }))
                    .chain(
                        runner_bindings
                            .iter()
                            .map(|identity| identity.artifact.path.as_str()),
                    )
                    .chain(
                        seccomp_bindings
                            .iter()
                            .map(|identity| identity.artifact.path.as_str()),
                    )
                    .chain(std::iter::once(inclusion_identity.path.as_str()))
                    .chain([
                        "methods/guest.elf",
                        "profiles/risc0-v3-succinct/manifest.bin",
                        "deps/rust-reference/fixture",
                        "runner/toolchain-runtime.bin",
                        "runner/image-extra.tar",
                    ]),
                "test positive provenance",
            )
            .unwrap();
            let positive_gate = B4PositiveGateAuthorityV1::from_validated_positive_gate(
                input_set_identity,
                verifier_contract_identity,
                verifier_contract.expectation_set.clone(),
                validators,
                runner_bindings,
                seccomp_bindings,
                inclusion_identity,
                &positive_provenance_paths,
            )
            .unwrap();

            let executor_artifact = b"measured-campaign-executor".to_vec();
            let executor_source_archive = b"campaign-executor-source".to_vec();
            let executor_reviewed_source = reviewed_source("campaign-executor");
            assert_eq!(
                executor_reviewed_source.archive,
                B4ContractArtifactIdentityV1::from_bytes(
                    "reproduction/preproof/campaign-executor-source.bundle",
                    B4ContractArtifactEncodingV1::GitBundle,
                    &executor_source_archive,
                )
                .unwrap()
            );
            let executor_contract = Eip0045B4CampaignExecutorContractV1::closed_v1()
                .to_canonical_jcs()
                .unwrap();
            let executor_build_descriptor = Eip0045B4CampaignExecutorBuildDescriptorV1 {
                format: "Eip0045B4CampaignExecutorBuildDescriptorV1".to_owned(),
                format_version: 1,
                artifact: B4ContractArtifactIdentityV1::from_bytes(
                    "reproduction/preproof/campaign-executor",
                    B4ContractArtifactEncodingV1::RawBytes,
                    &executor_artifact,
                )
                .unwrap(),
                reviewed_source: executor_reviewed_source.clone(),
                executor_contract: B4ContractArtifactIdentityV1::from_bytes(
                    "reproduction/preproof/executor-contract.json",
                    B4ContractArtifactEncodingV1::Rfc8785Jcs,
                    &executor_contract,
                )
                .unwrap(),
                commands: B4_CAMPAIGN_EXECUTOR_COMMANDS
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            }
            .to_canonical_jcs()
            .unwrap();

            Self {
                positive_gate,
                verifier_authority,
                input_set: input_set_source,
                verifier_cli_spec,
                negative_plan: negative_plan_source,
                verifier_schema_documents,
                executor_artifact,
                executor_reviewed_source,
                executor_source_archive,
                executor_build_descriptor,
                executor_contract,
                verifier_contract: verifier_contract_source,
                expectation_set,
                validator_descriptors,
                validator_artifacts,
                validator_source_archives,
                runner_profiles,
                seccomp_documents,
                jvm_copy_only_inclusion_manifest: inclusion_manifest_source,
            }
        }

        #[cfg(feature = "recursive-ancestry")]
        fn replace_executor_artifact(&mut self, bytes: &[u8]) {
            self.replace_executor_artifact_at_path(
                bytes,
                "reproduction/preproof/campaign-executor",
            );
        }

        #[cfg(feature = "recursive-ancestry")]
        fn replace_executor_artifact_at_path(&mut self, bytes: &[u8], path: &str) {
            self.executor_artifact = bytes.to_vec();
            let mut descriptor = Eip0045B4CampaignExecutorBuildDescriptorV1::from_canonical_jcs(
                &self.executor_build_descriptor,
            )
            .expect("valid test executor descriptor");
            descriptor.artifact = B4ContractArtifactIdentityV1::from_bytes(
                path,
                B4ContractArtifactEncodingV1::RawBytes,
                &self.executor_artifact,
            )
            .expect("bounded test proof-generator bytes");
            self.executor_build_descriptor = descriptor
                .to_canonical_jcs()
                .expect("canonical repaired test executor descriptor");
        }

        #[cfg(feature = "recursive-ancestry")]
        fn replace_positive_input_set_v2(&mut self, bytes: &[u8]) {
            self.input_set = bytes.to_vec();
            self.positive_gate.input_set = B4ContractArtifactIdentityV1::from_bytes(
                "h0/prepare-001/positive-input-set.json",
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &self.input_set,
            )
            .expect("bounded canonical V2 positive input set");
        }

        #[allow(clippy::too_many_lines)]
        fn external(&self) -> B4CampaignPrecommitExternalInputsV1<'_> {
            B4CampaignPrecommitExternalInputsV1 {
                input_set: B4ExternalArtifactV1 {
                    path: "h0/prepare-001/positive-input-set.json",
                    bytes: &self.input_set,
                    encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
                },
                campaign_executor_artifact: B4ExternalArtifactV1 {
                    path: "reproduction/preproof/campaign-executor",
                    bytes: &self.executor_artifact,
                    encoding: B4ContractArtifactEncodingV1::RawBytes,
                },
                campaign_executor_reviewed_source: B4ExternalReviewedSourceV1 {
                    repository: &self.executor_reviewed_source.repository,
                    commit: &self.executor_reviewed_source.commit,
                    tree: &self.executor_reviewed_source.tree,
                    archive: B4ExternalArtifactV1 {
                        path: "reproduction/preproof/campaign-executor-source.bundle",
                        bytes: &self.executor_source_archive,
                        encoding: B4ContractArtifactEncodingV1::GitBundle,
                    },
                },
                campaign_executor_build_descriptor: B4ExternalArtifactV1 {
                    path: "reproduction/preproof/campaign-executor-build.json",
                    bytes: &self.executor_build_descriptor,
                    encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
                },
                executor_contract: B4ExternalArtifactV1 {
                    path: "reproduction/preproof/executor-contract.json",
                    bytes: &self.executor_contract,
                    encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
                },
                verifier_contract: B4ExternalArtifactV1 {
                    path: "reproduction/preproof/verifier-contract.json",
                    bytes: &self.verifier_contract,
                    encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
                },
                verifier_cli_spec: B4ExternalArtifactV1 {
                    path: "docs/specs/b4-verifier-cli-v2.md",
                    bytes: &self.verifier_cli_spec,
                    encoding: B4ContractArtifactEncodingV1::RawBytes,
                },
                negative_plan: B4ExternalArtifactV1 {
                    path: "reproduction/negative-plan.json",
                    bytes: &self.negative_plan,
                    encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
                },
                expectation_set: B4ExternalArtifactV1 {
                    path: "reproduction/expectation-set.json",
                    bytes: &self.expectation_set,
                    encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
                },
                verifier_schema_documents: std::array::from_fn(|index| {
                    B4ExternalSchemaDocumentV1 {
                        role: B4_VERIFIER_SCHEMA_ROLES[index],
                        document: B4ExternalArtifactV1 {
                            path: &self.verifier_authority.expected.schema_identities[index]
                                .artifact
                                .path,
                            bytes: &self.verifier_schema_documents[index],
                            encoding: B4ContractArtifactEncodingV1::RawBytes,
                        },
                    }
                }),
                validator_build_descriptors: [
                    B4ExternalArtifactV1 {
                        path: "reproduction/preproof/rust-descriptor.json",
                        bytes: &self.validator_descriptors[0],
                        encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
                    },
                    B4ExternalArtifactV1 {
                        path: "reproduction/preproof/jvm-descriptor.json",
                        bytes: &self.validator_descriptors[1],
                        encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
                    },
                ],
                validator_artifacts: [
                    B4ExternalArtifactV1 {
                        path: "reproduction/preproof/rust-validator.bin",
                        bytes: &self.validator_artifacts[0],
                        encoding: B4ContractArtifactEncodingV1::RawBytes,
                    },
                    B4ExternalArtifactV1 {
                        path: "reproduction/preproof/jvm-validator.bin",
                        bytes: &self.validator_artifacts[1],
                        encoding: B4ContractArtifactEncodingV1::RawBytes,
                    },
                ],
                validator_source_archives: [
                    B4ExternalArtifactV1 {
                        path: "reproduction/preproof/rust-source.bundle",
                        bytes: &self.validator_source_archives[0],
                        encoding: B4ContractArtifactEncodingV1::GitBundle,
                    },
                    B4ExternalArtifactV1 {
                        path: "reproduction/preproof/jvm-source.bundle",
                        bytes: &self.validator_source_archives[1],
                        encoding: B4ContractArtifactEncodingV1::GitBundle,
                    },
                ],
                runner_profiles: std::array::from_fn(|index| B4ExternalArtifactV1 {
                    path: &self.positive_gate.runner_profiles[index].artifact.path,
                    bytes: &self.runner_profiles[index],
                    encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
                }),
                seccomp_documents: std::array::from_fn(|index| B4ExternalArtifactV1 {
                    path: &self.positive_gate.seccomp_documents[index].artifact.path,
                    bytes: &self.seccomp_documents[index],
                    encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
                }),
                jvm_copy_only_inclusion_manifest: B4ExternalArtifactV1 {
                    path: "reproduction/preproof/jvm-inclusion.json",
                    bytes: &self.jvm_copy_only_inclusion_manifest,
                    encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
                },
            }
        }

        fn positive_precommit_v2(&self) -> B4PositivePrecommitAuthorityV2 {
            B4PositivePrecommitAuthorityV2::from_validated_positive_precommit(
                self.positive_gate.input_set.clone(),
                self.positive_gate.verifier_contract.clone(),
                self.positive_gate.expectation_set.clone(),
                self.positive_gate.validators.clone(),
                self.positive_gate.runner_profiles.clone(),
                self.positive_gate.seccomp_documents.clone(),
                self.positive_gate.jvm_copy_only_inclusion_manifest.clone(),
                &self.positive_gate.provenance_paths,
            )
            .expect("valid V2 positive-precommit projection")
        }

        fn validated_input_set_completion_v2(
            input_set: B4ExternalArtifactV1<'_>,
        ) -> B4ValidatedPositiveInputSetCompletionV2 {
            let phase_root = input_set
                .path
                .rsplit_once('/')
                .expect("test input-set path has a phase root")
                .0;
            let paths = project_b4_positive_input_set_publication_paths_v2(phase_root)
                .expect("valid test H0 publication paths");
            assert_eq!(paths.input_set_path(), input_set.path);
            let binding = bind_b4_positive_input_set_publication_v2(&paths, input_set.bytes)
                .expect("valid test H0 input-set binding");
            let completion = derive_b4_positive_input_set_completion_jcs_v2(&binding)
                .expect("valid test H0 completion bytes");
            validate_b4_positive_input_set_completion_jcs_v2(&completion, &binding)
                .expect("validated test H0 completion")
        }

        fn external_v2(&self) -> B4CampaignPrecommitExternalInputsV2<'_> {
            let B4CampaignPrecommitExternalInputsV1 {
                input_set,
                campaign_executor_artifact,
                campaign_executor_reviewed_source,
                campaign_executor_build_descriptor,
                executor_contract,
                verifier_contract,
                verifier_cli_spec,
                negative_plan,
                expectation_set,
                verifier_schema_documents,
                validator_build_descriptors,
                validator_artifacts,
                validator_source_archives,
                runner_profiles,
                seccomp_documents,
                jvm_copy_only_inclusion_manifest,
            } = self.external();
            let positive_input_set_completion = Self::validated_input_set_completion_v2(input_set);
            B4CampaignPrecommitExternalInputsV2 {
                input_set,
                positive_input_set_completion,
                campaign_executor_artifact,
                campaign_executor_reviewed_source,
                campaign_executor_build_descriptor,
                executor_contract,
                verifier_contract,
                verifier_cli_spec,
                negative_plan,
                expectation_set,
                verifier_schema_documents,
                validator_build_descriptors,
                validator_artifacts,
                validator_source_archives,
                runner_profiles,
                seccomp_documents,
                jvm_copy_only_inclusion_manifest,
            }
        }

        fn external_v2_from_positive<'a>(
            &'a self,
            positive: &'a PositivePrecommitV2TestSupport,
        ) -> B4CampaignPrecommitExternalInputsV2<'a> {
            let B4CampaignPrecommitExternalInputsV1 {
                campaign_executor_artifact,
                campaign_executor_reviewed_source,
                campaign_executor_build_descriptor,
                executor_contract,
                verifier_cli_spec,
                negative_plan,
                expectation_set,
                verifier_schema_documents,
                ..
            } = self.external();
            let input_set = B4ExternalArtifactV1 {
                path: &positive.input_set.path,
                bytes: &positive.input_set.bytes,
                encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
            };
            let positive_input_set_completion = Self::validated_input_set_completion_v2(input_set);
            B4CampaignPrecommitExternalInputsV2 {
                input_set,
                positive_input_set_completion,
                campaign_executor_artifact,
                campaign_executor_reviewed_source,
                campaign_executor_build_descriptor,
                executor_contract,
                verifier_contract: B4ExternalArtifactV1 {
                    path: &positive.verifier_contract.path,
                    bytes: &positive.verifier_contract.bytes,
                    encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
                },
                verifier_cli_spec,
                negative_plan,
                expectation_set,
                verifier_schema_documents,
                validator_build_descriptors: std::array::from_fn(|index| B4ExternalArtifactV1 {
                    path: &positive.validator_descriptors[index].path,
                    bytes: &positive.validator_descriptors[index].bytes,
                    encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
                }),
                validator_artifacts: std::array::from_fn(|index| B4ExternalArtifactV1 {
                    path: &positive.validator_artifacts[index].path,
                    bytes: &positive.validator_artifacts[index].bytes,
                    encoding: B4ContractArtifactEncodingV1::RawBytes,
                }),
                validator_source_archives: std::array::from_fn(|index| B4ExternalArtifactV1 {
                    path: &positive.validator_source_archives[index].path,
                    bytes: &positive.validator_source_archives[index].bytes,
                    encoding: B4ContractArtifactEncodingV1::GitBundle,
                }),
                runner_profiles: std::array::from_fn(|index| B4ExternalArtifactV1 {
                    path: &positive.runner_profiles[index].path,
                    bytes: &positive.runner_profiles[index].bytes,
                    encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
                }),
                seccomp_documents: std::array::from_fn(|index| B4ExternalArtifactV1 {
                    path: &positive.seccomp_documents[index].path,
                    bytes: &positive.seccomp_documents[index].bytes,
                    encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
                }),
                jvm_copy_only_inclusion_manifest: B4ExternalArtifactV1 {
                    path: &positive.jvm_copy_only_inclusion_manifest.path,
                    bytes: &positive.jvm_copy_only_inclusion_manifest.bytes,
                    encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
                },
            }
        }
    }

    #[cfg(feature = "recursive-ancestry")]
    fn campaign_external_from_positive<'a>(
        campaign: &'a ClosureFixture,
        positive: &'a crate::b4_positive_gate::test_support::PositiveAuthorityTestSupportV1,
    ) -> B4CampaignPrecommitExternalInputsV1<'a> {
        campaign_external_from_positive_with_executor_path(
            campaign,
            positive,
            "reproduction/preproof/campaign-executor",
        )
    }

    #[cfg(feature = "recursive-ancestry")]
    fn campaign_external_from_positive_with_executor_path<'a>(
        campaign: &'a ClosureFixture,
        positive: &'a crate::b4_positive_gate::test_support::PositiveAuthorityTestSupportV1,
        executor_path: &'a str,
    ) -> B4CampaignPrecommitExternalInputsV1<'a> {
        B4CampaignPrecommitExternalInputsV1 {
            input_set: B4ExternalArtifactV1 {
                path: &positive.input_set.path,
                bytes: &positive.input_set.bytes,
                encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
            },
            campaign_executor_artifact: B4ExternalArtifactV1 {
                path: executor_path,
                bytes: &campaign.executor_artifact,
                encoding: B4ContractArtifactEncodingV1::RawBytes,
            },
            campaign_executor_reviewed_source: B4ExternalReviewedSourceV1 {
                repository: &campaign.executor_reviewed_source.repository,
                commit: &campaign.executor_reviewed_source.commit,
                tree: &campaign.executor_reviewed_source.tree,
                archive: B4ExternalArtifactV1 {
                    path: "reproduction/preproof/campaign-executor-source.bundle",
                    bytes: &campaign.executor_source_archive,
                    encoding: B4ContractArtifactEncodingV1::GitBundle,
                },
            },
            campaign_executor_build_descriptor: B4ExternalArtifactV1 {
                path: "reproduction/preproof/campaign-executor-build.json",
                bytes: &campaign.executor_build_descriptor,
                encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
            },
            executor_contract: B4ExternalArtifactV1 {
                path: "reproduction/preproof/executor-contract.json",
                bytes: &campaign.executor_contract,
                encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
            },
            verifier_contract: B4ExternalArtifactV1 {
                path: &positive.verifier_contract.path,
                bytes: &positive.verifier_contract.bytes,
                encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
            },
            verifier_cli_spec: B4ExternalArtifactV1 {
                path: "docs/specs/b4-verifier-cli-v2.md",
                bytes: &campaign.verifier_cli_spec,
                encoding: B4ContractArtifactEncodingV1::RawBytes,
            },
            negative_plan: B4ExternalArtifactV1 {
                path: "reproduction/negative-plan.json",
                bytes: &campaign.negative_plan,
                encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
            },
            expectation_set: B4ExternalArtifactV1 {
                path: "reproduction/expectation-set.json",
                bytes: &campaign.expectation_set,
                encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
            },
            verifier_schema_documents: std::array::from_fn(|index| B4ExternalSchemaDocumentV1 {
                role: B4_VERIFIER_SCHEMA_ROLES[index],
                document: B4ExternalArtifactV1 {
                    path: &campaign.verifier_authority.expected.schema_identities[index]
                        .artifact
                        .path,
                    bytes: &campaign.verifier_schema_documents[index],
                    encoding: B4ContractArtifactEncodingV1::RawBytes,
                },
            }),
            validator_build_descriptors: std::array::from_fn(|index| B4ExternalArtifactV1 {
                path: &positive.validator_descriptors[index].path,
                bytes: &positive.validator_descriptors[index].bytes,
                encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
            }),
            validator_artifacts: std::array::from_fn(|index| B4ExternalArtifactV1 {
                path: &positive.validator_artifacts[index].path,
                bytes: &positive.validator_artifacts[index].bytes,
                encoding: B4ContractArtifactEncodingV1::RawBytes,
            }),
            validator_source_archives: std::array::from_fn(|index| B4ExternalArtifactV1 {
                path: &positive.validator_source_archives[index].path,
                bytes: &positive.validator_source_archives[index].bytes,
                encoding: B4ContractArtifactEncodingV1::GitBundle,
            }),
            runner_profiles: std::array::from_fn(|index| B4ExternalArtifactV1 {
                path: &positive.runner_profiles[index].path,
                bytes: &positive.runner_profiles[index].bytes,
                encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
            }),
            seccomp_documents: std::array::from_fn(|index| B4ExternalArtifactV1 {
                path: &positive.seccomp_documents[index].path,
                bytes: &positive.seccomp_documents[index].bytes,
                encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
            }),
            jvm_copy_only_inclusion_manifest: B4ExternalArtifactV1 {
                path: &positive.jvm_copy_only_inclusion_manifest.path,
                bytes: &positive.jvm_copy_only_inclusion_manifest.bytes,
                encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
            },
        }
    }

    /// Produce the exact opaque-authority/source bundle used to exercise the
    /// public negative-ancestry constructor without adding an unchecked
    /// production constructor. The campaign and positive-generation gates are
    /// real; verifier-contract genesis remains the explicit upstream
    /// handler-freeze dependency documented on the returned test bundle.
    #[allow(
        clippy::too_many_lines,
        reason = "the helper spells out the complete production external closure without a second test-only constructor"
    )]
    #[cfg(feature = "recursive-ancestry")]
    pub(crate) fn build_negative_ancestry_constructor_test_support(
        case9_assumption_raw_seal: &[u8],
    ) -> Result<NegativeAncestryConstructorTestSupportV1> {
        build_negative_ancestry_constructor_test_support_with_reference_statement(
            case9_assumption_raw_seal,
            HISTORICAL_REFERENCE_CHAIN_DOMAIN_ID,
            HISTORICAL_REFERENCE_APPLICATION_PAYLOAD,
        )
    }

    /// Test-only sibling of the historical negative-ancestry constructor
    /// support with explicit authenticated reference-statement inputs.
    #[allow(
        clippy::too_many_lines,
        reason = "the helper spells out the complete production external closure without a second test-only constructor"
    )]
    #[cfg(feature = "recursive-ancestry")]
    pub(crate) fn build_negative_ancestry_constructor_test_support_with_reference_statement(
        case9_assumption_raw_seal: &[u8],
        chain_domain_id: [u8; 32],
        application_payload: &[u8],
    ) -> Result<NegativeAncestryConstructorTestSupportV1> {
        let mut campaign = ClosureFixture::valid();
        let validator_artifacts = [vec![0x91; 100], vec![0x92; 200]];
        let validator_source_archives = [vec![0x93; 1_000], vec![0x94; 1_000]];
        let positive = build_positive_authority_test_support_with_reference_statement(
            &campaign.verifier_contract,
            [&validator_artifacts[0], &validator_artifacts[1]],
            [&validator_source_archives[0], &validator_source_archives[1]],
            case9_assumption_raw_seal,
            chain_domain_id,
            application_payload,
        )?;
        campaign.replace_executor_artifact(&positive.proof_generator_artifact.bytes);
        let campaign_precommit_authority = B4CampaignPrecommitAuthorityV1::from_external_closure(
            &positive.positive_gate_authority,
            &campaign.verifier_authority,
            campaign_external_from_positive(&campaign, &positive),
        )?;
        let campaign_precommit_jcs = campaign_precommit_authority.to_canonical_precommit_jcs()?;

        Ok(NegativeAncestryConstructorTestSupportV1 {
            campaign_precommit_authority,
            positive_generation_authority: positive.positive_generation_authority,
            campaign_precommit_jcs,
            positive_input_set: positive.input_set,
            positive_generation_set: positive.generation_set,
            profile_manifest: positive.profile_manifest,
            profile_algorithm: positive.profile_algorithm,
            profile_constants: positive.profile_constants,
            consumer_guest_elf: positive.consumer_guest_elf,
            materialization_sources: positive.materialization_sources,
            positive_cases: positive.cases,
            case9_proof_output_manifest_jcs: positive.case9_proof_output_manifest_jcs,
            case9_primary_artifacts: positive.case9_primary_artifacts,
            case9_auxiliary_artifacts: positive.case9_auxiliary_artifacts,
        })
    }

    /// Build the immutable exact-byte support consumed by checkpoint 2B.
    #[cfg(feature = "recursive-ancestry")]
    #[allow(
        dead_code,
        reason = "checkpoint 2B consumes this production-constructor support"
    )]
    pub(crate) fn build_terminal_lineage_constructor_test_support(
        case9_assumption_raw_seal: &[u8],
    ) -> Result<TerminalLineageConstructorTestSupportV1> {
        build_terminal_lineage_constructor_test_support_with_executor_path(
            case9_assumption_raw_seal,
            false,
        )
    }

    #[cfg(feature = "recursive-ancestry")]
    fn v2_role_name(role: B4PositiveArtifactRole) -> &'static str {
        match role {
            B4PositiveArtifactRole::Ancestry => "ancestry",
            B4PositiveArtifactRole::Calibration => "calibration",
            B4PositiveArtifactRole::ClaimDigest => "claim-digest",
            B4PositiveArtifactRole::ControlId => "control-id",
            B4PositiveArtifactRole::ImageId => "image-id",
            B4PositiveArtifactRole::Journal => "journal",
            B4PositiveArtifactRole::Metadata => "metadata",
            B4PositiveArtifactRole::RawSeal => "raw-seal",
            B4PositiveArtifactRole::ReceiptOracle => "receipt-oracle",
        }
    }

    #[cfg(feature = "recursive-ancestry")]
    fn v2_input_identity(path: &str, bytes: &[u8], encoding: &str) -> Value {
        serde_json::json!({
            "path": path,
            "byteLength": bytes.len(),
            "sha256": sha256_hex(bytes),
            "encoding": encoding,
        })
    }

    #[cfg(feature = "recursive-ancestry")]
    fn v2_document_identity(format: &str, path: &str, bytes: &[u8]) -> Value {
        serde_json::json!({
            "format": format,
            "path": path,
            "byteLength": bytes.len(),
            "sha256": sha256_hex(bytes),
            "encoding": "rfc8785-jcs",
        })
    }

    #[cfg(feature = "recursive-ancestry")]
    fn authoritative_build_from_v2_input(input: &Value) -> Result<AuthoritativeB4BuildProjection> {
        let qualifying = &input["proofGenerator"]["qualifyingBuild"];
        let generator = &input["proofGenerator"]["artifact"];
        let guest = &input["guest"];
        let statement = &input["referenceStatement"];
        let text = |value: &Value, label: &str| {
            value
                .as_str()
                .map(str::to_owned)
                .with_context(|| format!("missing V2 authority fixture {label}"))
        };
        let number = |value: &Value, label: &str| {
            value
                .as_u64()
                .with_context(|| format!("missing V2 authority fixture {label}"))
        };
        Ok(AuthoritativeB4BuildProjection::for_test(
            TestAuthoritativeB4BuildProjection {
                evidence_root_sha256: text(&qualifying["evidenceRootSha256"], "evidence root")?,
                source_commit: text(&qualifying["sourceCommit"], "source commit")?,
                source_tree: text(&qualifying["sourceTree"], "source tree")?,
                source_lock_sha256: text(&qualifying["sourceLockSha256"], "source lock")?,
                generator_cargo_closure_sha256: text(
                    &qualifying["generatorCargoClosureSha256"],
                    "generator Cargo closure",
                )?,
                proof_generation_tests_sha256: text(
                    &qualifying["proofGenerationTestsSha256"],
                    "proof-generation tests",
                )?,
                generator_artifact_sha256: text(&generator["sha256"], "generator digest")?,
                generator_artifact_byte_length: number(
                    &generator["byteLength"],
                    "generator length",
                )?,
                guest_elf_sha256: text(&guest["elf"]["sha256"], "guest digest")?,
                guest_elf_byte_length: number(&guest["elf"]["byteLength"], "guest length")?,
                image_id_hex: text(&guest["imageId"], "image ID")?,
                statement_sha256: text(&statement["statementSha256"], "statement digest")?,
                statement_byte_length: number(
                    &statement["statementByteLength"],
                    "statement length",
                )?,
                contract_id_hex: text(&statement["contractId"], "contract ID")?,
                chain_domain_id_hex: text(&statement["chainDomainId"], "chain-domain ID")?,
                application_payload_sha256: text(
                    &statement["applicationPayloadSha256"],
                    "application-payload digest",
                )?,
                application_payload_byte_length: number(
                    &statement["applicationPayloadByteLength"],
                    "application-payload length",
                )?,
            },
        ))
    }

    #[cfg(feature = "recursive-ancestry")]
    #[allow(
        clippy::too_many_lines,
        reason = "the fixture spells out the exact eleven-row V2 source closure consumed by the production constructor"
    )]
    fn build_positive_generation_constructor_sources_v2(
    ) -> Result<PositiveGenerationConstructorSourcesV2> {
        build_positive_generation_constructor_sources_v2_with_executor(None)
    }

    #[cfg(feature = "recursive-ancestry")]
    #[allow(
        clippy::too_many_lines,
        reason = "the fixture spells out the exact eleven-row V2 source closure consumed by the production constructor"
    )]
    fn build_positive_generation_constructor_sources_v2_with_executor(
        executor_override: Option<&[u8]>,
    ) -> Result<PositiveGenerationConstructorSourcesV2> {
        let mut top_level = synthetic_valid_recursive_ancestry_top_level();
        let verifier_cli_path = "contracts/eip0045-verifier-cli-contract.json";
        let verifier_cli_jcs = b"{}".to_vec();
        top_level
            .source_artifacts
            .insert(verifier_cli_path.to_owned(), verifier_cli_jcs.clone());

        let physical_input = validate_canonical_json_source(&top_level.positive_input_set)?;
        let semantic_documents = v2_semantic_identity_documents_test_support();
        let mut input = semantic_documents.input_template;
        for field_name in ["profile", "guest", "referenceStatement", "sourceLock"] {
            input[field_name] = physical_input[field_name].clone();
        }
        input["proofGenerator"]["artifact"] = physical_input["proofGenerator"]["artifact"].clone();
        if let Some(current_executable) = executor_override {
            ensure!(
                !current_executable.is_empty(),
                "V2 terminal-import test executor cannot be empty"
            );
            let executor_path = input["proofGenerator"]["artifact"]["path"]
                .as_str()
                .context("missing V2 proof-generator artifact path")?
                .to_owned();
            ensure!(
                top_level
                    .source_artifacts
                    .insert(executor_path, current_executable.to_vec())
                    .is_some(),
                "V2 proof-generator source was absent before executor replacement"
            );
            input["proofGenerator"]["artifact"]["byteLength"] =
                serde_json::json!(current_executable.len());
            input["proofGenerator"]["artifact"]["sha256"] =
                serde_json::json!(sha256_hex(current_executable));
        }
        input["proofGenerator"]["qualifyingBuild"]["sourceLockSha256"] =
            input["sourceLock"]["sha256"].clone();
        input["proofGenerator"]["qualifyingBuild"]["generatorArtifact"] = serde_json::json!({
            "byteLength": input["proofGenerator"]["artifact"]["byteLength"].clone(),
            "sha256": input["proofGenerator"]["artifact"]["sha256"].clone(),
            "encoding": input["proofGenerator"]["artifact"]["encoding"].clone(),
        });
        input["verifierCliContract"] = v2_document_identity(
            "Eip0045B4VerifierContractV1",
            verifier_cli_path,
            &verifier_cli_jcs,
        );

        let runner_purposes = [
            "rust-validator-build",
            "jvm-validator-build",
            "rust-validator",
            "jvm-validator",
        ];
        let runner_profiles = semantic_documents.runner_profiles.map(|document| {
            OwnedPositiveAuthorityTestArtifactV2 {
                path: document.path,
                bytes: document.bytes,
            }
        });
        let mut runner_bindings = Vec::with_capacity(runner_profiles.len());
        for (index, runner) in runner_profiles.iter().enumerate() {
            top_level
                .source_artifacts
                .insert(runner.path.clone(), runner.bytes.clone());
            runner_bindings.push(serde_json::json!({
                "runnerProfileIndex": index,
                "purpose": runner_purposes[index],
                "artifact": v2_document_identity(
                    "Eip0045B4PositiveOciRunnerProfileV2",
                    &runner.path,
                    &runner.bytes,
                ),
            }));
        }
        input["runnerProfiles"] = Value::Array(runner_bindings);

        let validator_implementations = [("rust-reference", "rust"), ("independent-jvm", "scala")];
        let validator_descriptors = semantic_documents.validator_descriptors.map(|document| {
            OwnedPositiveAuthorityTestArtifactV2 {
                path: document.path,
                bytes: document.bytes,
            }
        });
        let mut validator_bindings = Vec::with_capacity(validator_descriptors.len());
        for (index, descriptor) in validator_descriptors.iter().enumerate() {
            top_level
                .source_artifacts
                .insert(descriptor.path.clone(), descriptor.bytes.clone());
            validator_bindings.push(serde_json::json!({
                "implementationIndex": index,
                "implementation": validator_implementations[index].0,
                "language": validator_implementations[index].1,
                "buildDescriptor": v2_document_identity(
                    "Eip0045B4ValidatorBuildDescriptorV2",
                    &descriptor.path,
                    &descriptor.bytes,
                ),
            }));
        }
        input["validators"] = Value::Array(validator_bindings);

        let calibration_paths = [
            "calibration/terminal-join.json",
            "calibration/terminal-resolve-explicit-root.json",
            "calibration/resolve-zero-root-then-join.json",
        ];
        let recursive_calibrations = calibration_paths
            .into_iter()
            .enumerate()
            .map(|(offset, path)| {
                let case_index = offset + 8;
                let case = &top_level.expanded_registry.positive_cases[case_index];
                let bytes = b"{}".to_vec();
                top_level
                    .source_artifacts
                    .insert(path.to_owned(), bytes.clone());
                Ok(serde_json::json!({
                    "caseId": case.case_id,
                    "artifact": v2_input_identity(
                        path,
                        &bytes,
                        "rfc8785-jcs",
                    ),
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        input["recursiveCalibrations"] = Value::Array(recursive_calibrations);
        let authoritative_build = authoritative_build_from_v2_input(&input)?;
        let input_jcs = canonical_json_bytes(&input)?;
        let parsed_input = parse_positive_input_sources_v2(&input_jcs)?;
        let nested_input_sources = parsed_input
            .artifacts
            .keys()
            .map(|path| {
                Ok(OwnedPositiveAuthorityTestArtifactV2 {
                    path: path.clone(),
                    bytes: top_level
                        .source_artifacts
                        .get(path)
                        .with_context(|| format!("missing V2 nested test source {path}"))?
                        .clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let proof_generator = OwnedPositiveAuthorityTestArtifactV2 {
            path: parsed_input.generator.path.clone(),
            bytes: top_level
                .source_artifacts
                .get(&parsed_input.generator.path)
                .context("missing V2 proof-generator test source")?
                .clone(),
        };

        let generation_cases = top_level
            .expanded_registry
            .positive_cases
            .iter()
            .enumerate()
            .map(|(case_index, case)| {
                let artifacts = positive_artifact_layout(case_index)?
                    .iter()
                    .zip(&case.artifacts)
                    .map(|((role, basename), identity)| {
                        ensure!(*role == identity.role, "V2 test role layout drift");
                        let bytes = if *role == B4PositiveArtifactRole::RawSeal {
                            &top_level.positive_exports[case_index].raw_seal
                        } else {
                            top_level
                                .source_artifacts
                                .get(&identity.path)
                                .context("missing V2 primary test source")?
                        };
                        let encoding = match identity.encoding {
                            B4ArtifactEncoding::RawBytes => "raw-bytes",
                            B4ArtifactEncoding::Rfc8785Jcs => "rfc8785-jcs",
                        };
                        let mut artifact = serde_json::json!({
                            "role": v2_role_name(*role),
                            "sourceFile": basename,
                            "byteLength": bytes.len(),
                            "sha256": sha256_hex(bytes),
                            "encoding": encoding,
                        });
                        if matches!(
                            role,
                            B4PositiveArtifactRole::ClaimDigest
                                | B4PositiveArtifactRole::ControlId
                                | B4PositiveArtifactRole::ImageId
                        ) {
                            artifact["contentHex"] = serde_json::json!(hex::encode(bytes));
                        }
                        if *role == B4PositiveArtifactRole::ReceiptOracle {
                            artifact["codec"] = serde_json::json!(if case_index < 8 {
                                "bincode-1.3.3-little-endian-fixed-int-reject-trailing"
                            } else {
                                "eip0045-recursive-oracle-borsh-v1"
                            });
                        }
                        Ok(artifact)
                    })
                    .collect::<Result<Vec<_>>>()?;
                let manifest = &top_level.positive_exports[case_index].proof_output_manifest_jcs;
                Ok(serde_json::json!({
                    "caseIndex": case_index,
                    "caseId": case.case_id,
                    "generation": compiled_positive_generation_recipe(case_index)?,
                    "proofOutputManifest": {
                        "fileName": if case_index < 8 {
                            "candidate-proof-output-manifest.json"
                        } else {
                            "candidate-recursive-output-manifest.json"
                        },
                        "byteLength": manifest.len(),
                        "sha256": sha256_hex(manifest),
                        "encoding": "rfc8785-jcs",
                    },
                    "artifacts": artifacts,
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        let generation_jcs = canonical_json_bytes(&serde_json::json!({
            "format": "Eip0045B4PositiveGenerationSetV2",
            "formatVersion": 2,
            "inputSetCommitment": {
                "format": "Eip0045B4PositiveInputSetV2",
                "byteLength": input_jcs.len(),
                "sha256": sha256_hex(&input_jcs),
                "encoding": "rfc8785-jcs",
            },
            "proofGeneratorArtifact": {
                "byteLength": proof_generator.bytes.len(),
                "sha256": sha256_hex(&proof_generator.bytes),
                "encoding": "raw-bytes",
            },
            "cases": generation_cases,
        }))?;

        let cases = top_level
            .expanded_registry
            .positive_cases
            .iter()
            .enumerate()
            .map(|(case_index, case)| {
                let primary_artifacts = case
                    .artifacts
                    .iter()
                    .map(|identity| {
                        let bytes = if identity.role == B4PositiveArtifactRole::RawSeal {
                            top_level.positive_exports[case_index].raw_seal.clone()
                        } else {
                            top_level
                                .source_artifacts
                                .get(&identity.path)
                                .context("missing V2 owned primary test source")?
                                .clone()
                        };
                        Ok(OwnedPositiveAuthorityTestArtifactV2 {
                            path: identity.path.clone(),
                            bytes,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let auxiliary_artifacts = top_level.positive_exports[case_index]
                    .auxiliary_artifacts
                    .iter()
                    .map(|identity| {
                        Ok(OwnedPositiveAuthorityTestArtifactV2 {
                            path: identity.path.clone(),
                            bytes: top_level
                                .source_artifacts
                                .get(&identity.path)
                                .context("missing V2 owned auxiliary test source")?
                                .clone(),
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let manifest_name = if case_index < 8 {
                    "candidate-proof-output-manifest.json"
                } else {
                    "candidate-recursive-output-manifest.json"
                };
                Ok(OwnedPositiveAuthorityTestCaseV2 {
                    proof_output_manifest: OwnedPositiveAuthorityTestArtifactV2 {
                        path: canonical_positive_case_artifact_path(&case.case_id, manifest_name),
                        bytes: top_level.positive_exports[case_index]
                            .proof_output_manifest_jcs
                            .clone(),
                    },
                    primary_artifacts,
                    auxiliary_artifacts,
                })
            })
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_: Vec<_>| anyhow::anyhow!("V2 test source case count is not eleven"))?;

        Ok(PositiveGenerationConstructorSourcesV2 {
            authoritative_build,
            positive_input_set: OwnedPositiveAuthorityTestArtifactV2 {
                path: "reproduction/preproof/input-set.json".to_owned(),
                bytes: input_jcs,
            },
            positive_generation_set: OwnedPositiveAuthorityTestArtifactV2 {
                path: "reproduction/postproof/positive-generation-set-v2.json".to_owned(),
                bytes: generation_jcs,
            },
            proof_generator,
            runner_profiles,
            validator_descriptors,
            nested_input_sources,
            cases,
        })
    }

    /// Build one campaign-V1 / positive-V2 pair exclusively through production gates.
    #[cfg(feature = "recursive-ancestry")]
    pub(crate) fn build_terminal_lineage_constructor_test_support_v2(
    ) -> Result<TerminalLineageConstructorTestSupportV2> {
        build_terminal_lineage_constructor_test_support_v2_with_executor(None)
    }

    /// Build the V2 terminal-lineage test support around the exact running
    /// Linux test image so the production executable gate can be crossed.
    #[cfg(all(feature = "recursive-ancestry", target_os = "linux"))]
    pub(crate) fn build_terminal_lineage_constructor_test_support_v2_for_executor(
        current_executable: &[u8],
    ) -> Result<TerminalLineageConstructorTestSupportV2> {
        ensure!(
            !current_executable.is_empty(),
            "V2 terminal-import test executor cannot be empty"
        );
        build_terminal_lineage_constructor_test_support_v2_with_executor(Some(current_executable))
    }

    #[cfg(feature = "recursive-ancestry")]
    fn build_terminal_lineage_constructor_test_support_v2_with_executor(
        executor_override: Option<&[u8]>,
    ) -> Result<TerminalLineageConstructorTestSupportV2> {
        let sources =
            build_positive_generation_constructor_sources_v2_with_executor(executor_override)?;
        let positive_generation_authority =
            B4PositiveGenerationAuthorityV2::from_validated(sources.validate_preacceptance()?);
        let mut campaign = ClosureFixture::valid();
        campaign.replace_positive_input_set_v2(&sources.positive_input_set.bytes);
        campaign.replace_executor_artifact(&sources.proof_generator.bytes);
        for fixture_only_path in [
            "deps/rust-reference/fixture",
            "runner/toolchain-runtime.bin",
            "runner/image-extra.tar",
        ] {
            ensure!(
                campaign
                    .positive_gate
                    .provenance_paths
                    .remove(fixture_only_path),
                "V2 terminal-lineage campaign fixture lacks its test-only provenance path: {fixture_only_path}"
            );
        }
        let campaign_precommit_authority = B4CampaignPrecommitAuthorityV1::from_external_closure(
            &campaign.positive_gate,
            &campaign.verifier_authority,
            campaign.external(),
        )?;
        Ok(TerminalLineageConstructorTestSupportV2 {
            campaign_precommit_authority,
            positive_generation_authority,
            sources,
        })
    }

    #[cfg(feature = "recursive-ancestry")]
    fn h0_test_sha256(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    #[cfg(feature = "recursive-ancestry")]
    fn h0_test_decode_digest(value: &str) -> [u8; 32] {
        hex::decode(value.strip_prefix("sha256:").unwrap_or(value))
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[cfg(feature = "recursive-ancestry")]
    fn h0_test_artifact_identity(
        kind: u8,
        encoding: u8,
        path: &str,
        byte_length: u64,
        sha256: [u8; 32],
    ) -> [u8; 32] {
        let path_length = u16::try_from(path.len()).unwrap();
        let mut preimage = Vec::with_capacity(87 + path.len());
        preimage.extend_from_slice(b"eip0045-b4-artifact-identity-commitment-v1\0");
        preimage.push(kind);
        preimage.push(encoding);
        preimage.extend_from_slice(&path_length.to_le_bytes());
        preimage.extend_from_slice(path.as_bytes());
        preimage.extend_from_slice(&byte_length.to_le_bytes());
        preimage.extend_from_slice(&sha256);
        assert_eq!(preimage.len(), 87 + path.len());
        h0_test_sha256(&preimage)
    }

    #[cfg(feature = "recursive-ancestry")]
    fn h0_test_role_commitments(
        runner: &OwnedPositiveAuthorityTestArtifactV2,
        role_index: usize,
    ) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let profile: Value = serde_json::from_slice(&runner.bytes).unwrap();
        let image = &profile["image"];
        let archive = &image["archive"];
        let archive_path = archive["path"].as_str().unwrap();
        let archive_ai = h0_test_artifact_identity(
            8,
            3,
            archive_path,
            archive["byteLength"].as_u64().unwrap(),
            h0_test_decode_digest(archive["sha256"].as_str().unwrap()),
        );
        let runner_ai = h0_test_artifact_identity(
            u8::try_from(2 + role_index).unwrap(),
            1,
            &runner.path,
            u64::try_from(runner.bytes.len()).unwrap(),
            h0_test_sha256(&runner.bytes),
        );

        let layers = image["layers"].as_array().unwrap();
        let mut oci = Vec::with_capacity(157 + 80 * layers.len());
        oci.extend_from_slice(b"eip0045-b4-oci-image-layout-commitment-v1\0");
        oci.push(u8::try_from(role_index).unwrap());
        oci.extend_from_slice(&archive_ai);
        for descriptor in [&image["manifest"], &image["config"]] {
            oci.extend_from_slice(&h0_test_decode_digest(
                descriptor["digest"].as_str().unwrap(),
            ));
            oci.extend_from_slice(&descriptor["size"].as_u64().unwrap().to_le_bytes());
        }
        oci.extend_from_slice(&u16::try_from(layers.len()).unwrap().to_le_bytes());
        for layer in layers {
            oci.extend_from_slice(&h0_test_decode_digest(layer["digest"].as_str().unwrap()));
            oci.extend_from_slice(&layer["size"].as_u64().unwrap().to_le_bytes());
            oci.extend_from_slice(&layer["uncompressedBytes"].as_u64().unwrap().to_le_bytes());
            oci.extend_from_slice(&h0_test_decode_digest(layer["diffId"].as_str().unwrap()));
        }
        assert_eq!(oci.len(), 157 + 80 * layers.len());

        let mut requirements = std::collections::BTreeMap::new();
        let mut add_mount = |mount: &Value| {
            requirements.insert(
                mount["target"].as_str().unwrap().to_owned(),
                match mount["type"].as_str().unwrap() {
                    "bind-directory" => 0_u8,
                    "bind-file" => 1_u8,
                    other => panic!("unexpected test mount type: {other}"),
                },
            );
        };
        for mount in profile["policy"]["mounts"].as_array().unwrap() {
            add_mount(mount);
        }
        if let Some(packaging) = profile["policy"].get("packagingPhase") {
            for mount in packaging["mounts"].as_array().unwrap() {
                add_mount(mount);
            }
        }
        for tmpfs in profile["policy"]["tmpfs"].as_array().unwrap() {
            requirements.insert(tmpfs["target"].as_str().unwrap().to_owned(), 0);
        }
        for directory in ["/dev", "/proc"] {
            requirements.insert(directory.to_owned(), 0);
        }
        for pseudodevice in ["full", "null", "random", "urandom", "zero"] {
            requirements.insert(format!("/dev/{pseudodevice}"), 1);
        }

        let rootfs = &image["postChangesetRootfs"];
        let mut rootfs_plan = Vec::new();
        rootfs_plan.extend_from_slice(b"eip0045-b4-rootfs-plan-commitment-v1\0");
        rootfs_plan.push(u8::try_from(role_index).unwrap());
        rootfs_plan.extend_from_slice(&h0_test_decode_digest(
            profile["retainedHostRootfsMetadataProvider"]["expectedModeTableSha256"]
                .as_str()
                .unwrap(),
        ));
        for field_name in [
            "entryCount",
            "regularFileCount",
            "directoryCount",
            "symbolicLinkCount",
            "regularFileBytes",
        ] {
            rootfs_plan.extend_from_slice(&rootfs[field_name].as_u64().unwrap().to_le_bytes());
        }
        rootfs_plan.extend_from_slice(&u16::try_from(requirements.len()).unwrap().to_le_bytes());
        let mut expected_length = 112;
        for (path, kind) in requirements {
            rootfs_plan.push(kind);
            rootfs_plan.extend_from_slice(&u16::try_from(path.len()).unwrap().to_le_bytes());
            rootfs_plan.extend_from_slice(path.as_bytes());
            expected_length += 3 + path.len();
        }
        assert_eq!(rootfs_plan.len(), expected_length);

        (
            runner_ai,
            h0_test_sha256(&oci),
            h0_test_sha256(&rootfs_plan),
        )
    }

    #[cfg(feature = "recursive-ancestry")]
    fn h0_test_session_binding(
        sources: &PositiveGenerationConstructorSourcesV2,
    ) -> Result<B4PositiveGenerationSessionBindingV2> {
        B4PositiveGenerationSessionBindingV2::from_validated(sources.validate_preacceptance()?)
    }

    #[test]
    #[cfg(feature = "recursive-ancestry")]
    fn h0_request_projection_v1_is_exact_role_ordered_and_path_qualified() {
        let sources = build_positive_generation_constructor_sources_v2().unwrap();
        let binding = h0_test_session_binding(&sources).unwrap();
        let projection = binding.request_projection();
        let expected_roles = [
            PositiveRunnerRole::RustValidatorBuild,
            PositiveRunnerRole::JvmValidatorBuild,
            PositiveRunnerRole::RustVerifier,
            PositiveRunnerRole::JvmVerifier,
        ];
        assert_eq!(
            projection.positive_input_set_ai(),
            h0_test_artifact_identity(
                0,
                1,
                &sources.positive_input_set.path,
                u64::try_from(sources.positive_input_set.bytes.len()).unwrap(),
                h0_test_sha256(&sources.positive_input_set.bytes),
            )
        );
        assert_eq!(
            projection.positive_generation_set_ai(),
            h0_test_artifact_identity(
                1,
                1,
                &sources.positive_generation_set.path,
                u64::try_from(sources.positive_generation_set.bytes.len()).unwrap(),
                h0_test_sha256(&sources.positive_generation_set.bytes),
            )
        );
        for (index, block) in projection.role_blocks().iter().enumerate() {
            let expected = h0_test_role_commitments(&sources.runner_profiles[index], index);
            assert_eq!(block.role(), expected_roles[index]);
            assert_eq!(block.runner_ai(), expected.0);
            assert_eq!(block.oci_layout_commitment(), expected.1);
            assert_eq!(block.rootfs_plan_commitment(), expected.2);
        }

        let baseline_input_ai = projection.positive_input_set_ai();
        let baseline_generation_ai = projection.positive_generation_set_ai();
        let baseline_role_blocks = projection.encoded_role_blocks();
        let mut relocated = sources.clone();
        relocated.positive_input_set.path =
            "reproduction/preproof/relocated-input-set.json".to_owned();
        let relocated_binding = h0_test_session_binding(&relocated).unwrap();
        let relocated_projection = relocated_binding.request_projection();
        assert_ne!(
            relocated_projection.positive_input_set_ai(),
            baseline_input_ai
        );
        assert_eq!(
            relocated_projection.positive_generation_set_ai(),
            baseline_generation_ai
        );
        assert_eq!(
            relocated_projection.encoded_role_blocks(),
            baseline_role_blocks
        );
    }

    #[test]
    #[cfg(feature = "recursive-ancestry")]
    fn positive_generation_session_binding_v2_requires_the_complete_affine_gate() {
        let sources = build_positive_generation_constructor_sources_v2().unwrap();
        let binding = h0_test_session_binding(&sources).unwrap();
        assert_eq!(binding.request_projection().role_blocks().len(), 4);

        let mut colliding = sources.clone();
        colliding.positive_generation_set.path = colliding.positive_input_set.path.clone();
        let error = match h0_test_session_binding(&colliding) {
            Ok(_) => panic!("a path-colliding V2 closure minted a session binding"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("path aliases or ancestor/descendant-conflicts"),
            "unexpected first discriminator: {error:#}"
        );
    }

    #[test]
    #[cfg(feature = "recursive-ancestry")]
    fn positive_generation_authority_v2_exposes_only_exact_borrowed_document_identities() {
        let sources = build_positive_generation_constructor_sources_v2().unwrap();
        let authority = B4PositiveGenerationAuthorityV2::from_validated(
            sources.validate_preacceptance().unwrap(),
        );

        assert_eq!(
            authority.positive_input_set_identity(),
            &B4ContractArtifactIdentityV1::from_bytes(
                &sources.positive_input_set.path,
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &sources.positive_input_set.bytes,
            )
            .unwrap()
        );
        assert_eq!(
            authority.positive_generation_set_identity(),
            &B4ContractArtifactIdentityV1::from_bytes(
                &sources.positive_generation_set.path,
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &sources.positive_generation_set.bytes,
            )
            .unwrap()
        );
    }

    #[test]
    #[cfg(feature = "recursive-ancestry")]
    fn positive_generation_v2_provenance_sha256_keys_and_digests_are_exact() {
        let sources = build_positive_generation_constructor_sources_v2().unwrap();
        let authority = B4PositiveGenerationAuthorityV2::from_validated(
            sources.validate_preacceptance().unwrap(),
        );
        let mut expected = std::collections::BTreeMap::<String, [u8; 32]>::new();
        let mut retain = |artifact: &OwnedPositiveAuthorityTestArtifactV2| {
            let digest = h0_test_sha256(&artifact.bytes);
            if let Some(previous) = expected.insert(artifact.path.clone(), digest) {
                assert_eq!(
                    previous, digest,
                    "a replayed provenance path changed digest: {}",
                    artifact.path
                );
            }
        };

        retain(&sources.positive_input_set);
        retain(&sources.positive_generation_set);
        for nested_input_source in &sources.nested_input_sources {
            retain(nested_input_source);
        }
        retain(&sources.proof_generator);
        for case in &sources.cases {
            retain(&case.proof_output_manifest);
            for artifact in &case.primary_artifacts {
                retain(artifact);
            }
            for artifact in &case.auxiliary_artifacts {
                retain(artifact);
            }
        }

        assert!(authority.provenance_paths().iter().eq(expected.keys()));
        assert_eq!(authority.provenance_sha256(), &expected);
    }

    #[test]
    #[cfg(feature = "recursive-ancestry")]
    fn positive_generation_v2_case_materialization_measurements_are_role_derived_and_bounded() {
        let sources = build_positive_generation_constructor_sources_v2().unwrap();
        let authority = B4PositiveGenerationAuthorityV2::from_validated(
            sources.validate_preacceptance().unwrap(),
        );

        for (case_index, case) in sources.cases.iter().enumerate() {
            let raw_seal_position = positive_artifact_layout(case_index)
                .unwrap()
                .iter()
                .position(|(role, _)| *role == B4PositiveArtifactRole::RawSeal)
                .unwrap();
            let measurements = authority
                .case_materialization_measurements(case_index)
                .unwrap();
            assert_eq!(
                measurements.proof_output_manifest(),
                FileMeasurement {
                    byte_length: u64::try_from(case.proof_output_manifest.bytes.len()).unwrap(),
                    sha256: h0_test_sha256(&case.proof_output_manifest.bytes),
                }
            );
            assert_eq!(
                measurements.raw_seal(),
                FileMeasurement {
                    byte_length: u64::try_from(
                        case.primary_artifacts[raw_seal_position].bytes.len()
                    )
                    .unwrap(),
                    sha256: h0_test_sha256(&case.primary_artifacts[raw_seal_position].bytes),
                }
            );
        }

        for out_of_range in [sources.cases.len(), usize::MAX] {
            let error = match authority.case_materialization_measurements(out_of_range) {
                Ok(_) => panic!("out-of-range case {out_of_range} returned measurements"),
                Err(error) => error,
            };
            assert!(
                format!("{error:#}").contains("outside the fixed closure"),
                "unexpected out-of-range rejection: {error:#}"
            );
        }
    }

    #[test]
    #[cfg(feature = "recursive-ancestry")]
    fn positive_generation_v2_physical_projections_remain_crate_private() {
        let source = include_str!("b4_campaign_contract.rs");
        let production = source
            .split("#[cfg(all(test, feature = \"positive-gate\"))]")
            .next()
            .unwrap();

        assert!(production.contains("pub(crate) fn provenance_sha256("));
        assert!(!production.contains("pub fn provenance_sha256("));
        assert!(production.contains("pub(crate) fn case_materialization_measurements("));
        assert!(!production.contains("pub fn case_materialization_measurements("));
        assert!(production
            .contains("pub(crate) struct B4PositiveGenerationCaseMaterializationMeasurementsV2"));
        assert!(!production
            .contains("pub struct B4PositiveGenerationCaseMaterializationMeasurementsV2"));
    }

    /// Build a campaign authority whose measured executor is the exact
    /// caller-held Linux test-runner image.
    ///
    /// This helper exists only so descriptor-rooted terminal-import tests can
    /// pass the production running-executable gate before exercising an
    /// independently malformed campaign root. It does not mint terminal
    /// lineage or import authority and is unavailable outside this crate's
    /// test build.
    #[cfg(all(feature = "recursive-ancestry", target_os = "linux"))]
    pub(crate) fn build_terminal_import_executor_campaign_test_authority(
        case9_assumption_raw_seal: &[u8],
        current_executable: &[u8],
    ) -> Result<B4CampaignPrecommitAuthorityV1> {
        let mut campaign = ClosureFixture::valid();
        let validator_artifacts = [vec![0x91; 100], vec![0x92; 200]];
        let validator_source_archives = [vec![0x93; 1_000], vec![0x94; 1_000]];
        let positive = build_positive_authority_test_support(
            &campaign.verifier_contract,
            [&validator_artifacts[0], &validator_artifacts[1]],
            [&validator_source_archives[0], &validator_source_archives[1]],
            case9_assumption_raw_seal,
        )?;
        campaign.replace_executor_artifact(current_executable);
        B4CampaignPrecommitAuthorityV1::from_external_closure(
            &positive.positive_gate_authority,
            &campaign.verifier_authority,
            campaign_external_from_positive(&campaign, &positive),
        )
    }

    /// Build a separately valid campaign whose executor physically preclaims
    /// the positive authority's post-proof generation-set path.
    #[cfg(feature = "recursive-ancestry")]
    #[allow(
        dead_code,
        reason = "the terminal-lineage collision regression consumes this production-constructor support"
    )]
    pub(crate) fn build_terminal_lineage_generation_path_collision_test_support(
        case9_assumption_raw_seal: &[u8],
    ) -> Result<TerminalLineageConstructorTestSupportV1> {
        build_terminal_lineage_constructor_test_support_with_executor_path(
            case9_assumption_raw_seal,
            true,
        )
    }

    /// Build the two non-nominal opaque campaign authorities required by the
    /// terminal-lineage public rejection matrix.
    #[cfg(feature = "recursive-ancestry")]
    #[allow(
        dead_code,
        reason = "checkpoint 2C consumes these production-constructor authorities"
    )]
    pub(crate) fn build_terminal_lineage_alternate_campaigns(
        case9_assumption_raw_seal: &[u8],
    ) -> Result<TerminalLineageAlternateCampaignsV1> {
        let mut different_input_campaign = ClosureFixture::valid();
        let different_validator_artifacts = [vec![0xb1; 100], vec![0xb2; 200]];
        let different_validator_source_archives = [vec![0xb3; 1_000], vec![0xb4; 1_000]];
        let different_input_positive = build_positive_authority_test_support(
            &different_input_campaign.verifier_contract,
            [
                &different_validator_artifacts[0],
                &different_validator_artifacts[1],
            ],
            [
                &different_validator_source_archives[0],
                &different_validator_source_archives[1],
            ],
            case9_assumption_raw_seal,
        )?;
        different_input_campaign
            .replace_executor_artifact(&different_input_positive.proof_generator_artifact.bytes);
        let different_input = B4CampaignPrecommitAuthorityV1::from_external_closure(
            &different_input_positive.positive_gate_authority,
            &different_input_campaign.verifier_authority,
            campaign_external_from_positive(&different_input_campaign, &different_input_positive),
        )?;

        let mut different_executor_campaign = ClosureFixture::valid();
        let nominal_validator_artifacts = [vec![0x91; 100], vec![0x92; 200]];
        let nominal_validator_source_archives = [vec![0x93; 1_000], vec![0x94; 1_000]];
        let nominal_positive = build_positive_authority_test_support(
            &different_executor_campaign.verifier_contract,
            [
                &nominal_validator_artifacts[0],
                &nominal_validator_artifacts[1],
            ],
            [
                &nominal_validator_source_archives[0],
                &nominal_validator_source_archives[1],
            ],
            case9_assumption_raw_seal,
        )?;
        different_executor_campaign
            .replace_executor_artifact(b"distinct-nonempty-campaign-executor");
        let different_executor = B4CampaignPrecommitAuthorityV1::from_external_closure(
            &nominal_positive.positive_gate_authority,
            &different_executor_campaign.verifier_authority,
            campaign_external_from_positive(&different_executor_campaign, &nominal_positive),
        )?;

        Ok(TerminalLineageAlternateCampaignsV1 {
            different_input,
            different_executor,
        })
    }

    #[cfg(feature = "recursive-ancestry")]
    fn build_terminal_lineage_constructor_test_support_with_executor_path(
        case9_assumption_raw_seal: &[u8],
        collide_with_generation_set: bool,
    ) -> Result<TerminalLineageConstructorTestSupportV1> {
        let mut campaign = ClosureFixture::valid();
        let validator_artifacts = [vec![0x91; 100], vec![0x92; 200]];
        let validator_source_archives = [vec![0x93; 1_000], vec![0x94; 1_000]];
        let positive = build_positive_authority_test_support(
            &campaign.verifier_contract,
            [&validator_artifacts[0], &validator_artifacts[1]],
            [&validator_source_archives[0], &validator_source_archives[1]],
            case9_assumption_raw_seal,
        )?;
        let executor_path = if collide_with_generation_set {
            positive.generation_set.path.as_str()
        } else {
            "reproduction/preproof/campaign-executor"
        };
        campaign.replace_executor_artifact_at_path(
            &positive.proof_generator_artifact.bytes,
            executor_path,
        );
        let campaign_precommit_authority = B4CampaignPrecommitAuthorityV1::from_external_closure(
            &positive.positive_gate_authority,
            &campaign.verifier_authority,
            campaign_external_from_positive_with_executor_path(&campaign, &positive, executor_path),
        )?;

        Ok(TerminalLineageConstructorTestSupportV1 {
            campaign_precommit_authority,
            positive_generation_authority: positive.positive_generation_authority,
            positive_input_set: positive.input_set,
            positive_generation_set: positive.generation_set,
            consumer_guest_elf: positive.consumer_guest_elf,
            case0_proof_output_manifest_jcs: positive.case0_proof_output_manifest_jcs,
            case0_primary_artifacts: positive.case0_primary_artifacts,
            case0_auxiliary_artifacts: positive.case0_auxiliary_artifacts,
            case8_proof_output_manifest_jcs: positive.case8_proof_output_manifest_jcs,
            case8_primary_artifacts: positive.case8_primary_artifacts,
            case8_auxiliary_artifacts: positive.case8_auxiliary_artifacts,
            case9_proof_output_manifest_jcs: positive.case9_proof_output_manifest_jcs,
            case9_primary_artifacts: positive.case9_primary_artifacts,
            case9_auxiliary_artifacts: positive.case9_auxiliary_artifacts,
        })
    }

    #[test]
    #[cfg(feature = "recursive-ancestry")]
    fn terminal_lineage_test_support_binds_one_generator_executor_content_identity() {
        let mut campaign_fixture = ClosureFixture::valid();
        let validator_artifacts = [vec![0x91; 100], vec![0x92; 200]];
        let validator_source_archives = [vec![0x93; 1_000], vec![0x94; 1_000]];
        let case9_assumption_raw_seal = vec![0xa5; crate::constants::PROOF_BYTES];
        let positive = build_positive_authority_test_support(
            &campaign_fixture.verifier_contract,
            [&validator_artifacts[0], &validator_artifacts[1]],
            [&validator_source_archives[0], &validator_source_archives[1]],
            &case9_assumption_raw_seal,
        )
        .unwrap();

        campaign_fixture.replace_executor_artifact(&positive.proof_generator_artifact.bytes);
        assert_eq!(
            (
                positive.proof_generator_artifact.bytes.len(),
                sha256_hex(&positive.proof_generator_artifact.bytes),
            ),
            (
                campaign_fixture.executor_artifact.len(),
                sha256_hex(&campaign_fixture.executor_artifact),
            ),
        );
        B4CampaignPrecommitAuthorityV1::from_external_closure(
            &positive.positive_gate_authority,
            &campaign_fixture.verifier_authority,
            campaign_external_from_positive(&campaign_fixture, &positive),
        )
        .unwrap();
    }

    #[test]
    #[cfg(all(feature = "recursive-ancestry", feature = "receipt-oracle"))]
    fn negative_ancestry_test_support_uses_real_shared_input_set_authorities() {
        let lineage = crate::b4_negative_ancestry_authority::test_support::
            fixed_negative_ancestry_lineage_test_support()
            .unwrap();
        let support = &lineage.prior;
        assert_eq!(
            support.campaign_precommit_authority.precommit().input_set,
            *support.positive_generation_authority.input_set()
        );
        for (index, (owned, authority)) in support
            .positive_cases
            .iter()
            .zip(support.positive_generation_authority.cases())
            .enumerate()
        {
            assert_eq!(usize::from(authority.case_index()), index);
            assert_eq!(
                authority.proof_output_manifest().byte_length,
                u64::try_from(owned.proof_output_manifest.bytes.len()).unwrap()
            );
            assert_eq!(
                hex::encode(authority.proof_output_manifest().sha256),
                sha256_hex(&owned.proof_output_manifest.bytes)
            );
            let raw_seal = owned
                .primary_artifacts
                .iter()
                .find(|artifact| artifact.path.ends_with("/candidate-raw-seal.bin"))
                .expect("owned V1 positive case lacks its canonical raw seal");
            assert_eq!(
                authority.raw_seal().byte_length,
                u64::try_from(raw_seal.bytes.len()).unwrap()
            );
            assert_eq!(
                hex::encode(authority.raw_seal().sha256),
                sha256_hex(&raw_seal.bytes)
            );
            assert_eq!(owned.auxiliary_artifacts.is_empty(), index < 8);
        }
        assert_eq!(
            support.case9_auxiliary_artifacts[0].bytes,
            support.positive_cases[9].auxiliary_artifacts[0].bytes
        );
        assert_eq!(
            B4ContractArtifactIdentityV1::from_bytes(
                &support.positive_input_set.path,
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &support.positive_input_set.bytes,
            )
            .unwrap(),
            *support.positive_generation_authority.input_set()
        );
        parse_positive_input_sources(&support.positive_input_set.bytes).unwrap();
        let input = validate_canonical_json_source(&support.positive_input_set.bytes).unwrap();
        let mut input_identities = vec![
            &input["profile"]["manifest"],
            &input["profile"]["algorithm"],
            &input["profile"]["constants"],
            &input["guest"]["elf"],
            &input["referenceStatement"]["bundleManifest"],
            &input["sourceLock"],
            &input["proofGenerator"]["artifact"],
            &input["verifierCliContract"],
        ];
        input_identities.extend(
            input["validators"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| &entry["buildDescriptor"]),
        );
        input_identities.extend(
            input["runnerProfiles"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| &entry["artifact"]),
        );
        input_identities.extend(
            input["recursiveCalibrations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| &entry["artifact"]),
        );
        assert_eq!(input_identities.len(), 17);
        assert_eq!(support.materialization_sources.len(), 19);
        for identity in input_identities {
            let path = identity["path"].as_str().unwrap();
            let source = support
                .materialization_sources
                .iter()
                .find(|source| source.path == path)
                .unwrap_or_else(|| panic!("V1 materialization support lacks {path}"));
            assert_eq!(
                identity["byteLength"].as_u64().unwrap(),
                u64::try_from(source.bytes.len()).unwrap()
            );
            assert_eq!(
                identity["sha256"].as_str().unwrap(),
                sha256_hex(&source.bytes)
            );
        }
        for identity in support
            .campaign_precommit_authority
            .precommit()
            .validators
            .iter()
            .map(|validator| &validator.artifact)
        {
            let source = support
                .materialization_sources
                .iter()
                .find(|source| source.path == identity.path)
                .expect("V1 materialization support lacks a validator artifact");
            assert_eq!(
                B4ContractArtifactIdentityV1::from_bytes(
                    &source.path,
                    B4ContractArtifactEncodingV1::RawBytes,
                    &source.bytes,
                )
                .unwrap(),
                *identity
            );
        }
        let statement_manifest_path = input["referenceStatement"]["bundleManifest"]["path"]
            .as_str()
            .unwrap();
        let statement_manifest = support
            .materialization_sources
            .iter()
            .find(|source| source.path == statement_manifest_path)
            .unwrap();
        crate::b4_statement_bundle_manifest::StatementBundleManifestV1::from_canonical_jcs(
            &statement_manifest.bytes,
        )
        .unwrap();
    }

    #[test]
    #[cfg(feature = "recursive-ancestry")]
    fn checked_in_materialization_schema_revision_rebuilds_authority_fixture_chain() {
        let assumption_raw_seal = vec![0xa5; crate::constants::PROOF_BYTES];
        let support =
            build_negative_ancestry_constructor_test_support(&assumption_raw_seal).unwrap();
        let expected_schema_identity = &support
            .campaign_precommit_authority
            .verifier_authority()
            .contract()
            .schema_identities[13]
            .artifact;

        assert_eq!(
            B4ContractArtifactIdentityV1::from_bytes(
                &expected_schema_identity.path,
                B4ContractArtifactEncodingV1::RawBytes,
                B4_VERIFIER_SCHEMA_SOURCES[13],
            )
            .unwrap(),
            *expected_schema_identity
        );
        assert_eq!(
            support.campaign_precommit_authority.precommit().input_set,
            *support.positive_generation_authority.input_set()
        );
        assert_eq!(
            B4ContractArtifactIdentityV1::from_bytes(
                &support.positive_input_set.path,
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &support.positive_input_set.bytes,
            )
            .unwrap(),
            *support.positive_generation_authority.input_set()
        );
        assert_eq!(
            B4ContractArtifactIdentityV1::from_bytes(
                &support.positive_generation_set.path,
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &support.positive_generation_set.bytes,
            )
            .unwrap(),
            *support.positive_generation_authority.generation_set()
        );
        assert_eq!(
            support
                .campaign_precommit_authority
                .to_canonical_precommit_jcs()
                .unwrap(),
            support.campaign_precommit_jcs
        );
    }

    fn schema_accepts(source: &str, value: &Value) -> bool {
        let schema: Value = serde_json::from_str(source).unwrap();
        jsonschema::draft202012::options()
            .build(&schema)
            .unwrap()
            .validate(value)
            .is_ok()
    }

    #[test]
    fn all_contracts_round_trip_as_exact_canonical_jcs() {
        let verifier = verifier_contract();
        let verifier_source = verifier.to_canonical_jcs().unwrap();
        assert_eq!(
            Eip0045B4VerifierContractV1::from_canonical_jcs(&verifier_source).unwrap(),
            verifier
        );

        let executor = Eip0045B4CampaignExecutorContractV1::closed_v1();
        let executor_source = executor.to_canonical_jcs().unwrap();
        assert_eq!(
            Eip0045B4CampaignExecutorContractV1::from_canonical_jcs(&executor_source).unwrap(),
            executor
        );

        let precommit = precommit(&verifier);
        let precommit_source = precommit.to_canonical_jcs().unwrap();
        assert_eq!(
            Eip0045B4CampaignPrecommitV1::from_canonical_jcs(&precommit_source).unwrap(),
            precommit
        );
    }

    #[test]
    fn terminal_publication_and_catalog_precede_negative_materialization() {
        assert_eq!(
            B4_CAMPAIGN_EXECUTOR_COMMANDS.as_slice(),
            &[
                "prepare-input-set",
                "prepare-campaign-precommit",
                "generate-case",
                "finalize-generation-set",
                "publish-terminal-evidence",
                "generate-negative-ancestry-witness-catalog",
                "prepare-negative-materialization-set",
                "run-positive-suite",
                "run-negative-suite",
                "finalize-corpus",
                "replay-corpus",
            ]
        );
        assert_eq!(
            B4_CAMPAIGN_FUTURE_OUTPUT_ROLES.as_slice(),
            &[
                "positive-case",
                "positive-generation-set",
                "terminal-evidence-campaign",
                "negative-ancestry-witness-catalog",
                "negative-materialization-set",
                "positive-suite",
                "negative-suite",
                "final-corpus",
                "corpus-replay",
            ]
        );
        assert_eq!(B4_VERIFIER_SCHEMA_ROLES.len(), 20);
        assert_eq!(
            B4_VERIFIER_SCHEMA_ROLES[4],
            "terminal-evidence-campaign-receipt"
        );
        assert_eq!(
            B4_VERIFIER_SCHEMA_ROLES[12],
            "negative-ancestry-witness-catalog"
        );
        assert_eq!(B4_VERIFIER_SCHEMA_ROLES[13], "negative-materialization-set");
    }

    #[test]
    fn parsers_reject_unknown_duplicate_and_noncanonical_sources() {
        let verifier_source = verifier_contract().to_canonical_jcs().unwrap();
        let mut unknown: Value = serde_json::from_slice(&verifier_source).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("host".to_owned(), Value::String("forbidden".to_owned()));
        let unknown = canonical_json_bytes(&unknown).unwrap();
        assert!(Eip0045B4VerifierContractV1::from_canonical_jcs(&unknown).is_err());

        let canonical = String::from_utf8(verifier_source.clone()).unwrap();
        let duplicate = format!(
            "{{\"format\":\"{B4_VERIFIER_CONTRACT_FORMAT}\",{}",
            &canonical[1..]
        );
        assert!(Eip0045B4VerifierContractV1::from_canonical_jcs(duplicate.as_bytes()).is_err());

        let pretty =
            serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&verifier_source).unwrap())
                .unwrap();
        assert!(Eip0045B4VerifierContractV1::from_canonical_jcs(&pretty).is_err());

        let executor_source = Eip0045B4CampaignExecutorContractV1::closed_v1()
            .to_canonical_jcs()
            .unwrap();
        let mut executor_value: Value = serde_json::from_slice(&executor_source).unwrap();
        executor_value
            .as_object_mut()
            .unwrap()
            .insert("timestamp".to_owned(), Value::from(1));
        assert!(Eip0045B4CampaignExecutorContractV1::from_canonical_jcs(
            &canonical_json_bytes(&executor_value).unwrap()
        )
        .is_err());

        let verifier = verifier_contract();
        let precommit_source = precommit(&verifier).to_canonical_jcs().unwrap();
        let mut precommit_value: Value = serde_json::from_slice(&precommit_source).unwrap();
        precommit_value["campaignExecutor"]
            .as_object_mut()
            .unwrap()
            .insert("machine".to_owned(), Value::String("forbidden".to_owned()));
        assert!(Eip0045B4CampaignPrecommitV1::from_canonical_jcs(
            &canonical_json_bytes(&precommit_value).unwrap()
        )
        .is_err());
    }

    #[test]
    fn missing_reordered_and_aliased_roles_reject() {
        let expected_contract = verifier_contract();
        let expected = verifier_authority(&expected_contract);

        let mut missing = expected_contract.clone();
        missing.schema_identities.pop();
        assert!(missing.validate().is_err());
        assert!(missing.verify_against(&expected).is_err());

        let mut reordered = expected_contract.clone();
        reordered.schema_identities.swap(0, 1);
        assert!(reordered.validate().is_err());
        assert!(reordered.verify_against(&expected).is_err());

        let mut aliased = expected_contract.clone();
        aliased.schema_identities[1].role = "negative-input".to_owned();
        assert!(aliased.validate().is_err());

        let mut campaign = precommit(&expected_contract);
        campaign.validators.swap(0, 1);
        assert!(campaign.validate().is_err());

        let mut campaign = precommit(&expected_contract);
        campaign.runner_profiles.swap(0, 1);
        assert!(campaign.validate().is_err());

        let mut campaign = precommit(&expected_contract);
        campaign.seccomp_documents[1].role = "jvm-build".to_owned();
        assert!(campaign.validate().is_err());

        let mut campaign = precommit(&expected_contract);
        campaign.future_output_roles.swap(0, 1);
        assert!(campaign.validate().is_err());

        let mut campaign = precommit(&expected_contract);
        campaign.future_output_roles[0] = "receipt".to_owned();
        assert!(campaign.validate().is_err());
    }

    #[test]
    fn wrong_interface_subcommands_commands_and_phase_policy_reject() {
        let mut verifier = verifier_contract();
        verifier.interface = "eip0045-b4-verifier-cli-v1".to_owned();
        assert!(verifier.validate().is_err());

        let mut verifier = verifier_contract();
        verifier.negative_subcommand = "verify-proof".to_owned();
        assert!(verifier.validate().is_err());

        let mut executor = Eip0045B4CampaignExecutorContractV1::closed_v1();
        executor.commands.swap(0, 1);
        assert!(executor.validate().is_err());

        let mut executor = Eip0045B4CampaignExecutorContractV1::closed_v1();
        executor.commands.pop();
        assert!(executor.validate().is_err());

        let mut executor = Eip0045B4CampaignExecutorContractV1::closed_v1();
        executor.commands[2] = "generate-all".to_owned();
        assert!(executor.validate().is_err());

        let mut executor = Eip0045B4CampaignExecutorContractV1::closed_v1();
        executor.phase_policy.publication = "replace".to_owned();
        assert!(executor.validate().is_err());
    }

    #[test]
    fn coordinated_identity_rewrites_cannot_replace_external_expectations() {
        let original_contract = verifier_contract();
        let original_contract_expectations = verifier_authority(&original_contract);
        let original_precommit = precommit(&original_contract);
        let original_precommit_expectations = precommit_authority(&original_precommit);

        let mut rewritten_contract = original_contract.clone();
        rewritten_contract.negative_plan = artifact(
            "reproduction/negative-plan.json",
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            "attacker-negative-plan",
        );
        rewritten_contract.expectation_set = artifact(
            "reproduction/expectation-set.json",
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            "attacker-expectations",
        );
        for (index, schema) in rewritten_contract.schema_identities.iter_mut().enumerate() {
            schema.artifact = artifact(
                &schema.artifact.path,
                B4ContractArtifactEncodingV1::RawBytes,
                &format!("attacker-schema-{index}"),
            );
        }
        assert!(rewritten_contract.validate().is_ok());
        assert!(rewritten_contract
            .verify_against(&original_contract_expectations)
            .is_err());

        let mut rewritten_precommit = original_precommit.clone();
        rewritten_precommit.verifier_contract = B4ContractArtifactIdentityV1::from_bytes(
            "reproduction/preproof/verifier-contract.json",
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            &rewritten_contract.to_canonical_jcs().unwrap(),
        )
        .unwrap();
        rewritten_precommit.expectation_set = rewritten_contract.expectation_set.clone();
        rewritten_precommit.validators[0].artifact = artifact(
            "reproduction/preproof/rust-validator.bin",
            B4ContractArtifactEncodingV1::RawBytes,
            "attacker-rust-validator",
        );
        rewritten_precommit.validators[0].build_descriptor = artifact(
            "reproduction/preproof/rust-descriptor.json",
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            "attacker-rust-descriptor",
        );
        assert!(rewritten_precommit.validate().is_ok());
        assert!(rewritten_precommit
            .verify_against(&original_precommit_expectations)
            .is_err());
    }

    #[test]
    fn safe_identity_rejects_path_and_digest_placeholders() {
        let mut identity = artifact(
            "reproduction/preproof/input.json",
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            "input",
        );
        for path in [
            "",
            "/absolute",
            "../escape",
            "a/../escape",
            "a//b",
            "a\\b",
            "a/con.json",
            "a/trailing.",
            "a/.hidden",
            "a/_private",
            "a/-dash",
            "Uppercase/path",
        ] {
            identity.path = path.to_owned();
            assert!(identity.validate().is_err(), "{path}");
        }
        identity.path = "reproduction/preproof/input.json".to_owned();
        identity.sha256 = "00".repeat(32);
        assert!(identity.validate().is_err());
    }

    #[test]
    fn external_identity_preflights_role_bounds_before_digest_construction() {
        let oversized = vec![0_u8; usize::try_from(MAX_CLI_SPEC_BYTES + 1).unwrap()];
        let error = B4ExternalArtifactV1 {
            path: "authority/cli.md",
            bytes: &oversized,
            encoding: B4ContractArtifactEncodingV1::RawBytes,
        }
        .identity(
            B4ContractArtifactEncodingV1::RawBytes,
            MAX_CLI_SPEC_BYTES,
            "CLI specification",
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("outside the role-specific bound"));

        let error = B4ExternalArtifactV1 {
            path: "authority/empty.bin",
            bytes: &[],
            encoding: B4ContractArtifactEncodingV1::RawBytes,
        }
        .identity(
            B4ContractArtifactEncodingV1::RawBytes,
            MAX_CLI_SPEC_BYTES,
            "empty fixture",
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("outside the role-specific bound"));
    }

    #[test]
    fn oversized_schema_is_rejected_before_it_can_enter_retained_sources() {
        let oversized = vec![b' '; usize::try_from(MAX_SCHEMA_DOCUMENT_BYTES + 1).unwrap()];
        let error = validate_pinned_schema_source(
            0,
            B4ExternalSchemaDocumentV1 {
                role: B4_VERIFIER_SCHEMA_ROLES[0],
                document: B4ExternalArtifactV1 {
                    path: "schemas/verifier-contract.schema.json",
                    bytes: &oversized,
                    encoding: B4ContractArtifactEncodingV1::RawBytes,
                },
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("compiled checked-in authority"));
    }

    #[test]
    fn verifier_authority_fails_closed_until_all_handler_cardinalities_are_frozen() {
        let empty = B4ExternalArtifactV1 {
            path: "authority/placeholder.json",
            bytes: b"{}",
            encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
        };
        let schemas = std::array::from_fn(|index| B4ExternalSchemaDocumentV1 {
            role: B4_VERIFIER_SCHEMA_ROLES[index],
            document: B4ExternalArtifactV1 {
                path: "authority/placeholder-schema.json",
                bytes: b"{}",
                encoding: B4ContractArtifactEncodingV1::RawBytes,
            },
        });
        let error = B4VerifierContractAuthorityV1::from_external_documents(
            B4ExternalArtifactV1 {
                path: "authority/cli.md",
                bytes: b"cli",
                encoding: B4ContractArtifactEncodingV1::RawBytes,
            },
            empty,
            empty,
            schemas,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("campaign precommit is forbidden"));
    }

    #[test]
    fn exact_checked_in_schema_bytes_are_strict_closed_raw_json_and_compile_when_enabled() {
        for (index, source) in checked_in_verifier_schema_sources().into_iter().enumerate() {
            validate_schema_source(
                source,
                B4_VERIFIER_SCHEMA_IDS[index],
                B4_VERIFIER_SCHEMA_ROLES[index],
            )
            .unwrap_or_else(|error| {
                panic!(
                    "checked-in schema {} rejected: {error:#}",
                    B4_VERIFIER_SCHEMA_ROLES[index]
                )
            });
            let identity = B4ContractArtifactIdentityV1::from_bytes(
                format!(
                    "reproduction/finalizer-schema/{}.schema.json",
                    B4_VERIFIER_SCHEMA_ROLES[index]
                ),
                B4ContractArtifactEncodingV1::RawBytes,
                source,
            )
            .unwrap();
            assert_eq!(identity.encoding, B4ContractArtifactEncodingV1::RawBytes);
        }
    }

    #[test]
    fn schema_raw_byte_identity_preserves_whitespace_and_strict_parse_boundaries() {
        let source = checked_in_verifier_schema_sources()[0];
        let mut whitespace_drift = source.to_vec();
        whitespace_drift.push(b' ');
        validate_schema_source(
            &whitespace_drift,
            B4_VERIFIER_SCHEMA_IDS[0],
            B4_VERIFIER_SCHEMA_ROLES[0],
        )
        .unwrap();
        let original = B4ContractArtifactIdentityV1::from_bytes(
            "schemas/verifier-contract.schema.json",
            B4ContractArtifactEncodingV1::RawBytes,
            source,
        )
        .unwrap();
        let drifted = B4ContractArtifactIdentityV1::from_bytes(
            "schemas/verifier-contract.schema.json",
            B4ContractArtifactEncodingV1::RawBytes,
            &whitespace_drift,
        )
        .unwrap();
        assert_ne!(original, drifted);

        let source_text = std::str::from_utf8(source).unwrap();
        let duplicate_id = format!(
            "{{\"$id\":\"{}\",{}",
            B4_VERIFIER_SCHEMA_IDS[0],
            &source_text[1..]
        );
        let duplicate_error = validate_schema_source(
            duplicate_id.as_bytes(),
            B4_VERIFIER_SCHEMA_IDS[0],
            B4_VERIFIER_SCHEMA_ROLES[0],
        )
        .unwrap_err();
        assert!(format!("{duplicate_error:#}").contains("duplicate object key"));

        let mut trailing_value = source.to_vec();
        trailing_value.extend_from_slice(b"{}");
        let trailing_error = validate_schema_source(
            &trailing_value,
            B4_VERIFIER_SCHEMA_IDS[0],
            B4_VERIFIER_SCHEMA_ROLES[0],
        )
        .unwrap_err();
        assert!(format!("{trailing_error:#}").contains("unexpected data"));

        let mut external_ref: Value = serde_json::from_slice(&minimal_schema_source(0)).unwrap();
        external_ref["properties"]["escape"] =
            serde_json::json!({"$ref": "https://example.com/escape.schema.json"});
        let external_ref = serde_json::to_vec_pretty(&external_ref).unwrap();
        let reference_error = validate_schema_source(
            &external_ref,
            B4_VERIFIER_SCHEMA_IDS[0],
            B4_VERIFIER_SCHEMA_ROLES[0],
        )
        .unwrap_err();
        assert!(format!("{reference_error:#}").contains("non-internal"));
    }

    #[test]
    fn pinned_schema_authority_rejects_same_id_semantics_free_substitution() {
        let source = minimal_schema_source(0);
        validate_schema_source(
            &source,
            B4_VERIFIER_SCHEMA_IDS[0],
            B4_VERIFIER_SCHEMA_ROLES[0],
        )
        .unwrap();
        let error = validate_pinned_schema_source(
            0,
            B4ExternalSchemaDocumentV1 {
                role: B4_VERIFIER_SCHEMA_ROLES[0],
                document: B4ExternalArtifactV1 {
                    path: "schemas/verifier-contract.schema.json",
                    bytes: &source,
                    encoding: B4ContractArtifactEncodingV1::RawBytes,
                },
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("compiled checked-in authority"));
    }

    #[test]
    fn schema_authority_rejects_open_nested_object_subschemas() {
        let source = canonical_json_bytes(&serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": B4_VERIFIER_SCHEMA_IDS[0],
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "nested": {
                    "type": "object",
                    "properties": {}
                }
            }
        }))
        .unwrap();
        let error = validate_schema_source(
            &source,
            B4_VERIFIER_SCHEMA_IDS[0],
            B4_VERIFIER_SCHEMA_ROLES[0],
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("open object subschema"));
    }

    #[test]
    fn global_path_injectivity_and_role_bounds_reject() {
        let mut verifier = verifier_contract();
        verifier.schema_identities[0].artifact.path = verifier.cli_spec.path.clone();
        assert!(verifier.validate().is_err());

        let mut verifier = verifier_contract();
        verifier.cli_spec.path = "foo".to_owned();
        verifier.negative_plan.path = "foo/bar".to_owned();
        let error = verifier.validate().unwrap_err();
        assert!(format!("{error:#}").contains("path conflict"));

        let mut verifier = verifier_contract();
        verifier.negative_plan.encoding = B4ContractArtifactEncodingV1::RawBytes;
        assert!(verifier.validate().is_err());

        let mut verifier = verifier_contract();
        verifier.expectation_set.byte_length = MAX_EXPECTATION_SET_BYTES + 1;
        assert!(verifier.validate().is_err());

        let base = verifier_contract();
        let mut campaign = precommit(&base);
        campaign.input_set.path = campaign.campaign_executor.artifact.path.clone();
        assert!(campaign.validate().is_err());

        let mut campaign = precommit(&base);
        campaign.validators[0].artifact.encoding = B4ContractArtifactEncodingV1::Rfc8785Jcs;
        assert!(campaign.validate().is_err());

        let mut campaign = precommit(&base);
        campaign.seccomp_documents[0].artifact.byte_length = MAX_SECCOMP_DOCUMENT_BYTES + 1;
        assert!(campaign.validate().is_err());
    }

    #[test]
    fn external_precommit_closure_remeasures_every_direct_binding() {
        let fixture = ClosureFixture::valid();
        let authority = B4CampaignPrecommitAuthorityV1::from_external_closure(
            &fixture.positive_gate,
            &fixture.verifier_authority,
            fixture.external(),
        )
        .unwrap();
        let source = authority.to_canonical_precommit_jcs().unwrap();
        let parsed = Eip0045B4CampaignPrecommitV1::from_canonical_jcs(&source).unwrap();
        parsed.verify_against(&authority).unwrap();

        let mut artifact_drift = fixture.validator_artifacts[0].clone();
        artifact_drift[0] ^= 1;
        let mut external = fixture.external();
        external.validator_artifacts[0].bytes = &artifact_drift;
        assert!(B4CampaignPrecommitAuthorityV1::from_external_closure(
            &fixture.positive_gate,
            &fixture.verifier_authority,
            external,
        )
        .is_err());

        let mut descriptor = Eip0045B4CampaignExecutorBuildDescriptorV1::from_canonical_jcs(
            &fixture.executor_build_descriptor,
        )
        .unwrap();
        descriptor.artifact = artifact(
            "reproduction/preproof/campaign-executor",
            B4ContractArtifactEncodingV1::RawBytes,
            "different-executor",
        );
        let descriptor_drift = descriptor.to_canonical_jcs().unwrap();
        let mut external = fixture.external();
        external.campaign_executor_build_descriptor.bytes = &descriptor_drift;
        assert!(B4CampaignPrecommitAuthorityV1::from_external_closure(
            &fixture.positive_gate,
            &fixture.verifier_authority,
            external,
        )
        .is_err());

        let mut verifier =
            Eip0045B4VerifierContractV1::from_canonical_jcs(&fixture.verifier_contract).unwrap();
        verifier.cli_spec.sha256 = sha256_hex(b"different-cli-specification");
        let verifier_drift = verifier.to_canonical_jcs().unwrap();
        let mut external = fixture.external();
        external.verifier_contract.bytes = &verifier_drift;
        assert!(B4CampaignPrecommitAuthorityV1::from_external_closure(
            &fixture.positive_gate,
            &fixture.verifier_authority,
            external,
        )
        .is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn external_precommit_single_fault_toctou_matrix_hits_each_intended_boundary() {
        #[derive(Clone, Copy)]
        enum Drift {
            ExpectationSet,
            ValidatorDescriptor(usize),
            ValidatorArtifact(usize),
            ValidatorSourceArchive(usize),
            ExecutorArtifact,
            ExecutorSourceArchive,
            ExecutorContract,
            ExecutorDescriptor,
            Schema(usize),
        }

        fn corrupt(bytes: &mut [u8]) {
            bytes[0] ^= 1;
        }

        let mut cases = vec![
            (
                "expectation set",
                Drift::ExpectationSet,
                "verifier authority replay bytes",
            ),
            (
                "Rust validator descriptor",
                Drift::ValidatorDescriptor(0),
                "validator descriptor bytes differ",
            ),
            (
                "JVM validator descriptor",
                Drift::ValidatorDescriptor(1),
                "validator descriptor bytes differ",
            ),
            (
                "Rust validator artifact",
                Drift::ValidatorArtifact(0),
                "validator artifact bytes differ",
            ),
            (
                "JVM validator artifact",
                Drift::ValidatorArtifact(1),
                "validator artifact bytes differ",
            ),
            (
                "Rust validator source archive",
                Drift::ValidatorSourceArchive(0),
                "validator source archive differs",
            ),
            (
                "JVM validator source archive",
                Drift::ValidatorSourceArchive(1),
                "validator source archive differs",
            ),
            (
                "executor artifact",
                Drift::ExecutorArtifact,
                "campaign executor build descriptor does not bind",
            ),
            (
                "executor source archive",
                Drift::ExecutorSourceArchive,
                "campaign executor build descriptor does not bind",
            ),
            (
                "executor contract",
                Drift::ExecutorContract,
                "B4 campaign executor contract is not exact RFC 8785 JCS",
            ),
            (
                "executor descriptor",
                Drift::ExecutorDescriptor,
                "B4 campaign executor build descriptor is not exact RFC 8785 JCS",
            ),
        ];
        cases.extend(
            B4_VERIFIER_SCHEMA_ROLES
                .iter()
                .enumerate()
                .map(|(index, role)| {
                    (
                        *role,
                        Drift::Schema(index),
                        "replayed verifier schema differs",
                    )
                }),
        );

        for (label, drift, expected_boundary) in cases {
            let mut fixture = ClosureFixture::valid();
            match drift {
                Drift::ExpectationSet => corrupt(&mut fixture.expectation_set),
                Drift::ValidatorDescriptor(index) => {
                    corrupt(&mut fixture.validator_descriptors[index]);
                }
                Drift::ValidatorArtifact(index) => {
                    corrupt(&mut fixture.validator_artifacts[index]);
                }
                Drift::ValidatorSourceArchive(index) => {
                    corrupt(&mut fixture.validator_source_archives[index]);
                }
                Drift::ExecutorArtifact => corrupt(&mut fixture.executor_artifact),
                Drift::ExecutorSourceArchive => corrupt(&mut fixture.executor_source_archive),
                Drift::ExecutorContract => corrupt(&mut fixture.executor_contract),
                Drift::ExecutorDescriptor => corrupt(&mut fixture.executor_build_descriptor),
                Drift::Schema(index) => {
                    corrupt(&mut fixture.verifier_schema_documents[index]);
                }
            }
            let error = B4CampaignPrecommitAuthorityV1::from_external_closure(
                &fixture.positive_gate,
                &fixture.verifier_authority,
                fixture.external(),
            )
            .unwrap_err();
            assert!(
                format!("{error:#}").contains(expected_boundary),
                "{label} TOCTOU drift reached an unexpected boundary: {error:#}"
            );
        }
    }

    #[test]
    fn external_precommit_closure_rejects_cross_role_path_aliases() {
        fn assert_executor_path_conflict(path: &str, expected_boundary: &str) {
            let mut fixture = ClosureFixture::valid();
            let mut descriptor = Eip0045B4CampaignExecutorBuildDescriptorV1::from_canonical_jcs(
                &fixture.executor_build_descriptor,
            )
            .unwrap();
            descriptor.artifact.path = path.to_owned();
            fixture.executor_build_descriptor = descriptor.to_canonical_jcs().unwrap();
            let mut external = fixture.external();
            external.campaign_executor_artifact.path = path;
            let error = B4CampaignPrecommitAuthorityV1::from_external_closure(
                &fixture.positive_gate,
                &fixture.verifier_authority,
                external,
            )
            .unwrap_err();
            assert!(
                format!("{error:#}").contains(expected_boundary),
                "path {path} rejected at an unexpected boundary: {error:#}"
            );
        }

        let fixture = ClosureFixture::valid();
        assert_executor_path_conflict(
            &fixture.positive_gate.input_set.path,
            "global campaign closure path conflict",
        );

        for (label, path) in [
            ("guest", "methods/guest.elf"),
            ("profile", "profiles/risc0-v3-succinct/manifest.bin"),
            ("dependency", "deps/rust-reference/fixture"),
            ("toolchain", "runner/toolchain-runtime.bin"),
            ("OCI", "runner/image-extra.tar"),
        ] {
            assert!(
                fixture.positive_gate.provenance_paths.contains(path),
                "test fixture omitted the nested {label} path"
            );
            assert_executor_path_conflict(path, "global campaign closure path conflict");
        }

        for (label, path) in [
            (
                "CLI",
                fixture.verifier_authority.expected.cli_spec.path.as_str(),
            ),
            (
                "plan",
                fixture
                    .verifier_authority
                    .expected
                    .negative_plan
                    .path
                    .as_str(),
            ),
            (
                "schema",
                fixture.verifier_authority.expected.schema_identities[0]
                    .artifact
                    .path
                    .as_str(),
            ),
        ] {
            assert!(
                fixture.verifier_authority.artifact_paths.contains(path),
                "test fixture omitted the nested verifier {label} path"
            );
            assert_executor_path_conflict(path, "global campaign closure path conflict");
        }

        assert_executor_path_conflict(
            "methods/guest.elf/child",
            "global campaign closure path conflict",
        );
    }

    #[test]
    fn external_precommit_closure_rejects_positive_and_verifier_toctou() {
        let fixture = ClosureFixture::valid();

        let input_drift = b"{\"drift\":true}".to_vec();
        let mut external = fixture.external();
        external.input_set.bytes = &input_drift;
        assert!(B4CampaignPrecommitAuthorityV1::from_external_closure(
            &fixture.positive_gate,
            &fixture.verifier_authority,
            external,
        )
        .is_err());

        let runner_drift = b"runner-drift".to_vec();
        let mut external = fixture.external();
        external.runner_profiles[0].bytes = &runner_drift;
        assert!(B4CampaignPrecommitAuthorityV1::from_external_closure(
            &fixture.positive_gate,
            &fixture.verifier_authority,
            external,
        )
        .is_err());

        let seccomp_drift = b"seccomp-drift".to_vec();
        let mut external = fixture.external();
        external.seccomp_documents[0].bytes = &seccomp_drift;
        assert!(B4CampaignPrecommitAuthorityV1::from_external_closure(
            &fixture.positive_gate,
            &fixture.verifier_authority,
            external,
        )
        .is_err());

        let inclusion_drift = b"{\"drift\":true}".to_vec();
        let mut external = fixture.external();
        external.jvm_copy_only_inclusion_manifest.bytes = &inclusion_drift;
        assert!(B4CampaignPrecommitAuthorityV1::from_external_closure(
            &fixture.positive_gate,
            &fixture.verifier_authority,
            external,
        )
        .is_err());

        let cli_drift = b"changed-cli".to_vec();
        let mut external = fixture.external();
        external.verifier_cli_spec.bytes = &cli_drift;
        assert!(B4CampaignPrecommitAuthorityV1::from_external_closure(
            &fixture.positive_gate,
            &fixture.verifier_authority,
            external,
        )
        .is_err());

        let plan_drift = b"{}".to_vec();
        let mut external = fixture.external();
        external.negative_plan.bytes = &plan_drift;
        assert!(B4CampaignPrecommitAuthorityV1::from_external_closure(
            &fixture.positive_gate,
            &fixture.verifier_authority,
            external,
        )
        .is_err());

        let schema_drift = minimal_schema_source(1);
        let mut external = fixture.external();
        external.verifier_schema_documents[0].document.bytes = &schema_drift;
        assert!(B4CampaignPrecommitAuthorityV1::from_external_closure(
            &fixture.positive_gate,
            &fixture.verifier_authority,
            external,
        )
        .is_err());
    }

    #[test]
    fn v2_authority_prescribes_the_unchanged_exact_v1_wire() {
        const COMPLETION_PATH: &str = "h0/prepare-001/positive-input-set-completion.json";
        let fixture = ClosureFixture::valid();
        let v1 = B4CampaignPrecommitAuthorityV1::from_external_closure(
            &fixture.positive_gate,
            &fixture.verifier_authority,
            fixture.external(),
        )
        .unwrap();
        let v2 = B4CampaignPrecommitAuthorityV2::from_external_closure(
            fixture.positive_precommit_v2(),
            &fixture.verifier_authority,
            fixture.external_v2(),
        )
        .unwrap();

        let v1_wire = v1.to_canonical_precommit_jcs().unwrap();
        let v2_wire = v2.to_canonical_precommit_jcs().unwrap();
        assert_eq!(v2_wire, v1_wire);
        assert_eq!(v2.precommit(), v1.precommit());
        assert_eq!(v2.precommit().format, B4_CAMPAIGN_PRECOMMIT_FORMAT);
        assert_eq!(
            v2.precommit().format_version,
            B4_CAMPAIGN_CONTRACT_FORMAT_VERSION
        );
        assert_eq!(
            v2.verifier_authority().contract(),
            v1.verifier_authority().contract()
        );
        let mut expected_v2_paths = v1.artifact_paths().clone();
        assert!(expected_v2_paths.insert(COMPLETION_PATH.to_owned()));
        assert_eq!(v2.artifact_paths(), &expected_v2_paths);
        assert!(!String::from_utf8_lossy(&v2_wire).contains(COMPLETION_PATH));
        v2.verify_candidate_jcs(&v2_wire).unwrap();
        Eip0045B4CampaignPrecommitV1::from_canonical_jcs(&v2_wire).unwrap();
    }

    #[test]
    fn v2_production_gate_authority_closes_the_exact_v1_campaign_wire() {
        let fixture = ClosureFixture::valid();
        let validator_artifacts = [vec![0x91; 100], vec![0x92; 200]];
        let validator_source_archives = [vec![0x93; 64], vec![0x94; 64]];
        let (positive_precommit, positive_documents) = build_positive_precommit_v2_test_support(
            &fixture.verifier_contract,
            [&validator_artifacts[0], &validator_artifacts[1]],
            [&validator_source_archives[0], &validator_source_archives[1]],
        )
        .unwrap();
        let authority = B4CampaignPrecommitAuthorityV2::from_external_closure(
            positive_precommit,
            &fixture.verifier_authority,
            fixture.external_v2_from_positive(&positive_documents),
        )
        .unwrap();

        let wire = authority.to_canonical_precommit_jcs().unwrap();
        let parsed = Eip0045B4CampaignPrecommitV1::from_canonical_jcs(&wire).unwrap();
        assert_eq!(&parsed, authority.precommit());
        assert_eq!(parsed.format, B4_CAMPAIGN_PRECOMMIT_FORMAT);
        assert_eq!(parsed.format_version, B4_CAMPAIGN_CONTRACT_FORMAT_VERSION);
        authority.verify_candidate_jcs(&wire).unwrap();
    }

    #[test]
    fn v2_production_gate_rejects_coordinated_valid_verifier_contract_substitution_at_join() {
        let fixture = ClosureFixture::valid();
        let validator_artifacts = [vec![0x91; 100], vec![0x92; 200]];
        let validator_source_archives = [vec![0x93; 64], vec![0x94; 64]];
        let mut substituted_verifier_contract =
            Eip0045B4VerifierContractV1::from_canonical_jcs(&fixture.verifier_contract).unwrap();
        substituted_verifier_contract.cli_spec.sha256 = "a6".repeat(32);
        let substituted_verifier_contract_jcs =
            substituted_verifier_contract.to_canonical_jcs().unwrap();
        assert_ne!(
            substituted_verifier_contract_jcs, fixture.verifier_contract,
            "the coordinated substitution fixture did not change the V1 verifier contract"
        );
        Eip0045B4VerifierContractV1::from_canonical_jcs(&substituted_verifier_contract_jcs)
            .unwrap();

        let (positive_precommit, positive_documents) = build_positive_precommit_v2_test_support(
            &substituted_verifier_contract_jcs,
            [&validator_artifacts[0], &validator_artifacts[1]],
            [&validator_source_archives[0], &validator_source_archives[1]],
        )
        .unwrap();
        let error = match B4CampaignPrecommitAuthorityV2::from_external_closure(
            positive_precommit,
            &fixture.verifier_authority,
            fixture.external_v2_from_positive(&positive_documents),
        ) {
            Ok(_) => panic!(
                "the V2 campaign join accepted a coordinated valid verifier-contract substitution"
            ),
            Err(error) => error,
        };
        let message = format!("{error:#}");
        assert!(
            message.contains("verifier contract differs from the externally constructed authority"),
            "coordinated verifier substitution stopped at an unexpected boundary: {message}"
        );
    }

    #[test]
    fn v2_authority_and_v1_parser_reject_a_v2_discriminated_wire() {
        let fixture = ClosureFixture::valid();
        let authority = B4CampaignPrecommitAuthorityV2::from_external_closure(
            fixture.positive_precommit_v2(),
            &fixture.verifier_authority,
            fixture.external_v2(),
        )
        .unwrap();
        let canonical = authority.to_canonical_precommit_jcs().unwrap();

        for (field, replacement) in [
            (
                "format",
                Value::String("Eip0045B4CampaignPrecommitV2".to_owned()),
            ),
            ("formatVersion", Value::from(2)),
        ] {
            let mut candidate: Value = serde_json::from_slice(&canonical).unwrap();
            candidate[field] = replacement;
            let candidate = canonical_json_bytes(&candidate).unwrap();
            assert!(
                Eip0045B4CampaignPrecommitV1::from_canonical_jcs(&candidate).is_err(),
                "V1 parser accepted a V2-discriminated {field}"
            );
            assert!(
                authority.verify_candidate_jcs(&candidate).is_err(),
                "V2 authority accepted non-V1 wire bytes at {field}"
            );
        }
    }

    #[test]
    fn v2_external_closure_remeasures_direct_inputs_and_replay_sources() {
        #[derive(Clone, Copy, Debug)]
        enum Drift {
            InputSet,
            Runner(usize),
            Seccomp(usize),
            JvmManifest,
            ExecutorArtifact,
            ExecutorSource,
            ExecutorBuildDescriptor,
            ExecutorContract,
            VerifierContract,
            VerifierCli,
            NegativePlan,
            ExpectationSet,
            VerifierSchema(usize),
            ValidatorDescriptor(usize),
            ValidatorArtifact(usize),
            ValidatorSource(usize),
        }

        fn corrupt_raw(bytes: &mut [u8]) {
            bytes[0] ^= 1;
        }

        fn add_canonical_drift(bytes: &mut Vec<u8>) {
            let mut value: Value = serde_json::from_slice(bytes).unwrap();
            value["adversarialDrift"] = Value::Bool(true);
            *bytes = canonical_json_bytes(&value).unwrap();
        }

        let mut drifts = vec![
            (Drift::InputSet, "V2 positive input-set bytes differ"),
            (
                Drift::JvmManifest,
                "JVM COPY-ONLY inclusion-manifest bytes differ",
            ),
            (
                Drift::ExecutorArtifact,
                "campaign executor build descriptor does not bind",
            ),
            (
                Drift::ExecutorSource,
                "campaign executor build descriptor does not bind",
            ),
            (
                Drift::ExecutorBuildDescriptor,
                "campaign executor build descriptor does not bind",
            ),
            (
                Drift::ExecutorContract,
                "campaign executor commands differ from the exact ordered V1 inventory",
            ),
            (
                Drift::VerifierContract,
                "verifier contract differs from the externally constructed authority",
            ),
            (
                Drift::VerifierCli,
                "verifier authority replay bytes differ from the retained external authority",
            ),
            (
                Drift::NegativePlan,
                "verifier authority replay bytes differ from the retained external authority",
            ),
            (
                Drift::ExpectationSet,
                "verifier authority replay bytes differ from the retained external authority",
            ),
        ];
        for index in 0..4 {
            drifts.push((
                Drift::Runner(index),
                "V2 runner-profile bytes differ from the positive-precommit document",
            ));
            drifts.push((
                Drift::Seccomp(index),
                "seccomp bytes differ from the V2 positive-precommit document",
            ));
        }
        for index in 0..B4_VERIFIER_SCHEMA_ROLES.len() {
            drifts.push((
                Drift::VerifierSchema(index),
                "replayed verifier schema differs from retained role or bytes",
            ));
        }
        for index in 0..2 {
            drifts.push((
                Drift::ValidatorDescriptor(index),
                "V2 validator descriptor bytes differ from the positive-precommit descriptor",
            ));
            drifts.push((
                Drift::ValidatorArtifact(index),
                "validator artifact bytes differ from the V2 descriptor-bound artifact",
            ));
            drifts.push((
                Drift::ValidatorSource(index),
                "validator source archive differs from the V2 descriptor-bound reviewed source",
            ));
        }

        for (drift, expected_boundary) in drifts {
            let mut fixture = ClosureFixture::valid();
            let validator_artifacts = [vec![0x91; 100], vec![0x92; 200]];
            let validator_source_archives = [vec![0x93; 64], vec![0x94; 64]];
            let (positive_precommit, mut positive_documents) =
                build_positive_precommit_v2_test_support(
                    &fixture.verifier_contract,
                    [&validator_artifacts[0], &validator_artifacts[1]],
                    [&validator_source_archives[0], &validator_source_archives[1]],
                )
                .unwrap();
            match drift {
                Drift::InputSet => add_canonical_drift(&mut positive_documents.input_set.bytes),
                Drift::Runner(index) => {
                    add_canonical_drift(&mut positive_documents.runner_profiles[index].bytes);
                }
                Drift::Seccomp(index) => {
                    add_canonical_drift(&mut positive_documents.seccomp_documents[index].bytes);
                }
                Drift::JvmManifest => {
                    add_canonical_drift(
                        &mut positive_documents.jvm_copy_only_inclusion_manifest.bytes,
                    );
                }
                Drift::ExecutorArtifact => corrupt_raw(&mut fixture.executor_artifact),
                Drift::ExecutorSource => corrupt_raw(&mut fixture.executor_source_archive),
                Drift::ExecutorBuildDescriptor => {
                    let mut descriptor: Value =
                        serde_json::from_slice(&fixture.executor_build_descriptor).unwrap();
                    descriptor["artifact"]["sha256"] = Value::String("a5".repeat(32));
                    fixture.executor_build_descriptor = canonical_json_bytes(&descriptor).unwrap();
                }
                Drift::ExecutorContract => {
                    let mut contract: Value =
                        serde_json::from_slice(&fixture.executor_contract).unwrap();
                    contract["commands"][0] = Value::String("mutant-command".to_owned());
                    fixture.executor_contract = canonical_json_bytes(&contract).unwrap();
                }
                Drift::VerifierContract => {
                    let mut contract: Value =
                        serde_json::from_slice(&positive_documents.verifier_contract.bytes)
                            .unwrap();
                    contract["cliSpec"]["sha256"] = Value::String("a6".repeat(32));
                    positive_documents.verifier_contract.bytes =
                        canonical_json_bytes(&contract).unwrap();
                }
                Drift::VerifierCli => corrupt_raw(&mut fixture.verifier_cli_spec),
                Drift::NegativePlan => add_canonical_drift(&mut fixture.negative_plan),
                Drift::ExpectationSet => add_canonical_drift(&mut fixture.expectation_set),
                Drift::VerifierSchema(index) => {
                    corrupt_raw(&mut fixture.verifier_schema_documents[index]);
                }
                Drift::ValidatorDescriptor(index) => {
                    add_canonical_drift(&mut positive_documents.validator_descriptors[index].bytes);
                }
                Drift::ValidatorArtifact(index) => {
                    corrupt_raw(&mut positive_documents.validator_artifacts[index].bytes);
                }
                Drift::ValidatorSource(index) => {
                    corrupt_raw(&mut positive_documents.validator_source_archives[index].bytes);
                }
            }
            let error = match B4CampaignPrecommitAuthorityV2::from_external_closure(
                positive_precommit,
                &fixture.verifier_authority,
                fixture.external_v2_from_positive(&positive_documents),
            ) {
                Ok(_) => panic!("V2 campaign constructor accepted drift {drift:?}"),
                Err(error) => error,
            };
            let message = format!("{error:#}");
            assert!(
                message.contains(expected_boundary),
                "drift {drift:?} stopped at an unexpected boundary: {message}"
            );
        }
    }

    #[test]
    fn v2_positive_precommit_mint_requires_roles_and_complete_path_antichain() {
        let fixture = ClosureFixture::valid();
        let positive = &fixture.positive_gate;

        let mut missing = positive.provenance_paths.clone();
        assert!(missing.remove(&positive.input_set.path));
        let error = match B4PositivePrecommitAuthorityV2::from_validated_positive_precommit(
            positive.input_set.clone(),
            positive.verifier_contract.clone(),
            positive.expectation_set.clone(),
            positive.validators.clone(),
            positive.runner_profiles.clone(),
            positive.seccomp_documents.clone(),
            positive.jvm_copy_only_inclusion_manifest.clone(),
            &missing,
        ) {
            Ok(_) => panic!("V2 positive-precommit mint accepted incomplete provenance"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("omits a directly bound campaign path"));

        let mut reordered_runners = positive.runner_profiles.clone();
        reordered_runners.swap(0, 1);
        assert!(
            B4PositivePrecommitAuthorityV2::from_validated_positive_precommit(
                positive.input_set.clone(),
                positive.verifier_contract.clone(),
                positive.expectation_set.clone(),
                positive.validators.clone(),
                reordered_runners,
                positive.seccomp_documents.clone(),
                positive.jvm_copy_only_inclusion_manifest.clone(),
                &positive.provenance_paths,
            )
            .is_err()
        );
    }

    #[test]
    fn v2_campaign_closure_rejects_positive_provenance_path_alias() {
        let mut fixture = ClosureFixture::valid();
        let positive_precommit = fixture.positive_precommit_v2();
        let alias = fixture.positive_gate.input_set.path.clone();
        let mut descriptor = Eip0045B4CampaignExecutorBuildDescriptorV1::from_canonical_jcs(
            &fixture.executor_build_descriptor,
        )
        .unwrap();
        descriptor.artifact.path.clone_from(&alias);
        fixture.executor_build_descriptor = descriptor.to_canonical_jcs().unwrap();
        let mut external = fixture.external_v2();
        external.campaign_executor_artifact.path = &alias;

        let error = match B4CampaignPrecommitAuthorityV2::from_external_closure(
            positive_precommit,
            &fixture.verifier_authority,
            external,
        ) {
            Ok(_) => panic!("V2 campaign closure accepted a cross-authority path alias"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("global V2-derived campaign closure path conflict"));
    }

    #[test]
    fn v2_campaign_closure_rejects_completion_exact_ancestor_and_descendant_conflicts() {
        for (conflict_class, conflict) in [
            ("exact", "h0/prepare-001/positive-input-set-completion.json"),
            ("ancestor", "h0/prepare-001"),
            (
                "descendant",
                "h0/prepare-001/positive-input-set-completion.json/child",
            ),
        ] {
            let mut fixture = ClosureFixture::valid();
            let positive_precommit = fixture.positive_precommit_v2();
            let mut descriptor = Eip0045B4CampaignExecutorBuildDescriptorV1::from_canonical_jcs(
                &fixture.executor_build_descriptor,
            )
            .unwrap();
            descriptor.artifact.path = conflict.to_owned();
            fixture.executor_build_descriptor = descriptor.to_canonical_jcs().unwrap();
            let mut external = fixture.external_v2();
            external.campaign_executor_artifact.path = conflict;

            let error = match B4CampaignPrecommitAuthorityV2::from_external_closure(
                positive_precommit,
                &fixture.verifier_authority,
                external,
            ) {
                Ok(_) => {
                    panic!("V2 campaign closure accepted completion {conflict_class} conflict")
                }
                Err(error) => error,
            };
            assert!(
                format!("{error:#}").contains("global V2-derived campaign closure path conflict"),
                "unexpected completion {conflict_class} conflict error: {error:#}"
            );
        }
    }

    #[test]
    fn v2_campaign_closure_rejects_completion_token_for_a_different_input_path() {
        let fixture = ClosureFixture::valid();
        let positive_precommit = fixture.positive_precommit_v2();
        let mismatched_completion =
            ClosureFixture::validated_input_set_completion_v2(B4ExternalArtifactV1 {
                path: "h0/prepare-002/positive-input-set.json",
                bytes: &fixture.input_set,
                encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
            });
        let mut external = fixture.external_v2();
        external.positive_input_set_completion = mismatched_completion;

        let error = match B4CampaignPrecommitAuthorityV2::from_external_closure(
            positive_precommit,
            &fixture.verifier_authority,
            external,
        ) {
            Ok(_) => panic!("V2 campaign closure accepted a completion token for another input"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains(
            "validated V2 positive input-set completion belongs to a different input set"
        ));
    }

    #[test]
    fn v2_campaign_closure_rejects_completion_token_for_different_bytes_at_the_same_path() {
        let mut fixture = ClosureFixture::valid();
        let accepted_input_set = canonical_json_bytes(&serde_json::json!({
            "format": "Eip0045B4PositiveInputSetV2",
            "formatVersion": 2,
            "nonce": "aa",
        }))
        .unwrap();
        let different_input_set = canonical_json_bytes(&serde_json::json!({
            "format": "Eip0045B4PositiveInputSetV2",
            "formatVersion": 2,
            "nonce": "bb",
        }))
        .unwrap();
        assert_eq!(accepted_input_set.len(), different_input_set.len());
        assert_ne!(accepted_input_set, different_input_set);

        let accepted_identity = B4ContractArtifactIdentityV1::from_bytes(
            "h0/prepare-001/positive-input-set.json",
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            &accepted_input_set,
        )
        .unwrap();
        let different_identity = B4ContractArtifactIdentityV1::from_bytes(
            "h0/prepare-001/positive-input-set.json",
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            &different_input_set,
        )
        .unwrap();
        assert_eq!(accepted_identity.path, different_identity.path);
        assert_eq!(
            accepted_identity.byte_length,
            different_identity.byte_length
        );
        assert_ne!(accepted_identity.sha256, different_identity.sha256);

        fixture.input_set = accepted_input_set;
        fixture.positive_gate.input_set = accepted_identity;
        let positive_precommit = fixture.positive_precommit_v2();
        let mismatched_completion =
            ClosureFixture::validated_input_set_completion_v2(B4ExternalArtifactV1 {
                path: "h0/prepare-001/positive-input-set.json",
                bytes: &different_input_set,
                encoding: B4ContractArtifactEncodingV1::Rfc8785Jcs,
            });
        let mut external = fixture.external_v2();
        external.positive_input_set_completion = mismatched_completion;

        let error = match B4CampaignPrecommitAuthorityV2::from_external_closure(
            positive_precommit,
            &fixture.verifier_authority,
            external,
        ) {
            Ok(_) => panic!(
                "V2 campaign closure accepted a completion token for different same-path bytes"
            ),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains(
            "validated V2 positive input-set completion belongs to a different input set"
        ));
    }

    #[test]
    fn v2_precommit_authorities_have_no_v1_conversion_or_constructible_surface() {
        let source = include_str!("b4_campaign_contract.rs");
        let production = source
            .split("#[cfg(all(test, feature = \"positive-gate\"))]")
            .next()
            .unwrap();

        for type_name in [
            "B4PositivePrecommitAuthorityV2",
            "B4CampaignPrecommitAuthorityV2",
        ] {
            let marker = format!("pub struct {type_name} {{");
            let (prefix, suffix) = production.split_once(&marker).unwrap();
            let body = suffix.split_once("\n}").unwrap().0;
            let prefix_tail = &prefix[prefix.len().saturating_sub(160)..];
            assert!(!prefix_tail.contains("#[derive"));
            assert!(!body.contains("pub "));
            assert!(!production.contains(&format!("impl Clone for {type_name}")));
            assert!(!production.contains(&format!("impl Copy for {type_name}")));
            assert!(!production.contains(&format!("impl Default for {type_name}")));
            assert!(!production.contains(&format!("impl serde::Serialize for {type_name}")));
            assert!(!production.contains(&format!("impl serde::Deserialize")));
            assert!(!production.contains(&format!("type {type_name} =")));
        }
        assert!(!production.contains(
            "impl From<B4CampaignPrecommitAuthorityV2> for B4CampaignPrecommitAuthorityV1"
        ));
        assert!(!production.contains(
            "impl From<B4CampaignPrecommitAuthorityV1> for B4CampaignPrecommitAuthorityV2"
        ));
        assert!(!production.contains("pub struct Eip0045B4CampaignPrecommitV2"));

        let constructor = production
            .split("impl B4CampaignPrecommitAuthorityV2 {")
            .nth(1)
            .unwrap();
        assert!(constructor.contains("positive_precommit: B4PositivePrecommitAuthorityV2"));
        assert!(!constructor.contains("positive_precommit: &B4PositivePrecommitAuthorityV2"));
    }

    #[test]
    fn v2_completion_retention_oracle_rejects_antichain_and_wire_mutants() {
        fn oracle(production: &str) -> bool {
            let Some(external) = production
                .split("pub struct B4CampaignPrecommitExternalInputsV2<'a> {")
                .nth(1)
                .and_then(|suffix| suffix.split("\n}").next())
            else {
                return false;
            };
            let Some(wire) = production
                .split("pub struct Eip0045B4CampaignPrecommitV1 {")
                .nth(1)
                .and_then(|suffix| suffix.split("\n}").next())
            else {
                return false;
            };
            let Some(constructor) = production
                .split("impl B4CampaignPrecommitAuthorityV2 {")
                .nth(1)
                .and_then(|suffix| suffix.split("\ntrait CanonicalContract").next())
            else {
                return false;
            };
            let Some(antichain) = constructor
                .split("let artifact_paths = require_path_antichain(")
                .nth(1)
                .and_then(|suffix| {
                    suffix
                        .split("\"global V2-derived campaign closure\"")
                        .next()
                })
            else {
                return false;
            };

            external
                .matches(
                    "pub positive_input_set_completion: B4ValidatedPositiveInputSetCompletionV2",
                )
                .count()
                == 1
                && !external.contains("positive_input_set_completion_path")
                && constructor
                    .matches(
                        "external.positive_input_set_completion.input_set_identity()\n                == &positive_precommit.input_set",
                    )
                    .count()
                    == 1
                && antichain
                    .matches("external.positive_input_set_completion.completion_path()")
                    .count()
                    == 1
                && antichain.contains(".chain(std::iter::once(")
                && constructor.matches("artifact_paths,\n        })").count() == 1
                && !wire.contains("positive_input_set_completion")
        }

        let source = include_str!("b4_campaign_contract.rs").replace("\r\n", "\n");
        let production = source
            .split("#[cfg(all(test, feature = \"positive-gate\"))]")
            .next()
            .unwrap();
        assert!(oracle(production));

        let missing_antichain_edge = production.replacen(
            "external.positive_input_set_completion.completion_path()",
            "positive_precommit.input_set.path.as_str()",
            1,
        );
        assert!(!oracle(&missing_antichain_edge));

        let missing_identity_edge =
            production.replacen(".input_set_identity()", ".completion_path()", 1);
        assert!(!oracle(&missing_identity_edge));

        let path_only_identity_edge = production.replacen(
            "external.positive_input_set_completion.input_set_identity()\n                == &positive_precommit.input_set",
            "external\n                .positive_input_set_completion\n                .input_set_identity()\n                .path\n                == positive_precommit.input_set.path",
            1,
        );
        assert!(!oracle(&path_only_identity_edge));

        let detached_path_surface = production.replacen(
            "pub positive_input_set_completion: B4ValidatedPositiveInputSetCompletionV2",
            "pub positive_input_set_completion_path: &'a str",
            1,
        );
        assert!(!oracle(&detached_path_surface));

        let (prefix, v2_constructor) = production
            .split_once("impl B4CampaignPrecommitAuthorityV2 {")
            .unwrap();
        let omitted_returned_path = format!(
            "{prefix}impl B4CampaignPrecommitAuthorityV2 {{{}",
            v2_constructor.replacen(
                "artifact_paths,\n        })",
                "artifact_paths: BTreeSet::new(),\n        })",
                1,
            )
        );
        assert!(!oracle(&omitted_returned_path));

        let serialized_completion = production.replacen(
            "pub struct Eip0045B4CampaignPrecommitV1 {\n",
            "pub struct Eip0045B4CampaignPrecommitV1 {\n    pub positive_input_set_completion_path: String,\n",
            1,
        );
        assert!(!oracle(&serialized_completion));
    }

    #[cfg(feature = "positive-gate")]
    #[test]
    fn draft_2020_12_contract_schemas_accept_rust_values_and_reject_drifts() {
        let verifier = verifier_contract();
        let executor = Eip0045B4CampaignExecutorContractV1::closed_v1();
        let campaign = precommit(&verifier);
        let closure = ClosureFixture::valid();
        let verifier_value = serde_json::to_value(&verifier).unwrap();
        let executor_value = serde_json::to_value(&executor).unwrap();
        let executor_build_descriptor_value: Value =
            serde_json::from_slice(&closure.executor_build_descriptor).unwrap();
        let campaign_value = serde_json::to_value(&campaign).unwrap();

        assert!(schema_accepts(VERIFIER_CONTRACT_SCHEMA, &verifier_value));
        assert!(schema_accepts(EXECUTOR_CONTRACT_SCHEMA, &executor_value));
        assert!(schema_accepts(
            EXECUTOR_BUILD_DESCRIPTOR_SCHEMA,
            &executor_build_descriptor_value
        ));
        assert!(schema_accepts(CAMPAIGN_PRECOMMIT_SCHEMA, &campaign_value));

        let mut missing_schema = verifier_value.clone();
        missing_schema["schemaIdentities"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(!schema_accepts(VERIFIER_CONTRACT_SCHEMA, &missing_schema));

        let mut reordered_schema = verifier_value.clone();
        reordered_schema["schemaIdentities"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        assert!(!schema_accepts(VERIFIER_CONTRACT_SCHEMA, &reordered_schema));

        let mut hidden_component = verifier_value;
        hidden_component["cliSpec"]["path"] = Value::String("specs/.hidden.md".to_owned());
        assert!(!schema_accepts(VERIFIER_CONTRACT_SCHEMA, &hidden_component));

        let mut command_drift = executor_value;
        command_drift["commands"].as_array_mut().unwrap().swap(0, 1);
        assert!(!schema_accepts(EXECUTOR_CONTRACT_SCHEMA, &command_drift));

        let mut build_descriptor_drift = executor_build_descriptor_value;
        build_descriptor_drift["artifact"]["encoding"] = Value::String("git-bundle".to_owned());
        assert!(!schema_accepts(
            EXECUTOR_BUILD_DESCRIPTOR_SCHEMA,
            &build_descriptor_drift
        ));

        let mut validator_order = campaign_value.clone();
        validator_order["validators"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        assert!(!schema_accepts(CAMPAIGN_PRECOMMIT_SCHEMA, &validator_order));

        let mut oversized = campaign_value;
        oversized["seccompDocuments"][0]["artifact"]["byteLength"] =
            Value::from(MAX_SECCOMP_DOCUMENT_BYTES + 1);
        assert!(!schema_accepts(CAMPAIGN_PRECOMMIT_SCHEMA, &oversized));
    }

    #[cfg(feature = "positive-gate")]
    #[test]
    fn legacy_v1_10_8_19_shapes_reject_without_fallback() {
        let verifier = verifier_contract();
        let executor = Eip0045B4CampaignExecutorContractV1::closed_v1();
        let campaign = precommit(&verifier);
        let closure = ClosureFixture::valid();

        let mut legacy_executor = serde_json::to_value(&executor).unwrap();
        assert_eq!(
            legacy_executor["commands"]
                .as_array_mut()
                .unwrap()
                .remove(4),
            Value::String("publish-terminal-evidence".to_owned())
        );
        assert!(!schema_accepts(EXECUTOR_CONTRACT_SCHEMA, &legacy_executor));
        assert!(Eip0045B4CampaignExecutorContractV1::from_canonical_jcs(
            &canonical_json_bytes(&legacy_executor).unwrap()
        )
        .is_err());

        let mut legacy_build_descriptor: Value =
            serde_json::from_slice(&closure.executor_build_descriptor).unwrap();
        assert_eq!(
            legacy_build_descriptor["commands"]
                .as_array_mut()
                .unwrap()
                .remove(4),
            Value::String("publish-terminal-evidence".to_owned())
        );
        assert!(!schema_accepts(
            EXECUTOR_BUILD_DESCRIPTOR_SCHEMA,
            &legacy_build_descriptor
        ));
        assert!(
            Eip0045B4CampaignExecutorBuildDescriptorV1::from_canonical_jcs(
                &canonical_json_bytes(&legacy_build_descriptor).unwrap()
            )
            .is_err()
        );

        let mut legacy_campaign = serde_json::to_value(&campaign).unwrap();
        assert_eq!(
            legacy_campaign["futureOutputRoles"]
                .as_array_mut()
                .unwrap()
                .remove(2),
            Value::String("terminal-evidence-campaign".to_owned())
        );
        assert!(!schema_accepts(CAMPAIGN_PRECOMMIT_SCHEMA, &legacy_campaign));
        assert!(Eip0045B4CampaignPrecommitV1::from_canonical_jcs(
            &canonical_json_bytes(&legacy_campaign).unwrap()
        )
        .is_err());

        let mut legacy_verifier = serde_json::to_value(&verifier).unwrap();
        assert_eq!(
            legacy_verifier["schemaIdentities"]
                .as_array_mut()
                .unwrap()
                .remove(4)["role"],
            Value::String("terminal-evidence-campaign-receipt".to_owned())
        );
        assert!(!schema_accepts(VERIFIER_CONTRACT_SCHEMA, &legacy_verifier));
        assert!(Eip0045B4VerifierContractV1::from_canonical_jcs(
            &canonical_json_bytes(&legacy_verifier).unwrap()
        )
        .is_err());
    }

    #[cfg(feature = "positive-gate")]
    #[test]
    fn mixed_v1_inventory_closures_reject_without_fallback() {
        let mut old_executor = ClosureFixture::valid();
        let mut old_executor_value: Value =
            serde_json::from_slice(&old_executor.executor_contract).unwrap();
        old_executor_value["commands"]
            .as_array_mut()
            .unwrap()
            .remove(4);
        old_executor.executor_contract = canonical_json_bytes(&old_executor_value).unwrap();
        assert!(B4CampaignPrecommitAuthorityV1::from_external_closure(
            &old_executor.positive_gate,
            &old_executor.verifier_authority,
            old_executor.external(),
        )
        .is_err());

        let mut old_descriptor = ClosureFixture::valid();
        let mut old_descriptor_value: Value =
            serde_json::from_slice(&old_descriptor.executor_build_descriptor).unwrap();
        old_descriptor_value["commands"]
            .as_array_mut()
            .unwrap()
            .remove(4);
        old_descriptor.executor_build_descriptor =
            canonical_json_bytes(&old_descriptor_value).unwrap();
        assert!(B4CampaignPrecommitAuthorityV1::from_external_closure(
            &old_descriptor.positive_gate,
            &old_descriptor.verifier_authority,
            old_descriptor.external(),
        )
        .is_err());

        let verifier = verifier_contract();
        let mut old_campaign = serde_json::to_value(precommit(&verifier)).unwrap();
        old_campaign["futureOutputRoles"]
            .as_array_mut()
            .unwrap()
            .remove(2);
        assert!(!schema_accepts(CAMPAIGN_PRECOMMIT_SCHEMA, &old_campaign));
        assert!(Eip0045B4CampaignPrecommitV1::from_canonical_jcs(
            &canonical_json_bytes(&old_campaign).unwrap()
        )
        .is_err());

        let mut old_verifier = ClosureFixture::valid();
        let mut old_verifier_value: Value =
            serde_json::from_slice(&old_verifier.verifier_contract).unwrap();
        old_verifier_value["schemaIdentities"]
            .as_array_mut()
            .unwrap()
            .remove(4);
        old_verifier.verifier_contract = canonical_json_bytes(&old_verifier_value).unwrap();
        assert!(B4CampaignPrecommitAuthorityV1::from_external_closure(
            &old_verifier.positive_gate,
            &old_verifier.verifier_authority,
            old_verifier.external(),
        )
        .is_err());
    }
}
