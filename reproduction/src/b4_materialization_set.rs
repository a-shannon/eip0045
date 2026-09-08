//! Structural and opaque-authority contracts for the canonical B4 negative
//! materialization set.
//!
//! The document commits to the exact pre-run bytes used to prepare all 254
//! negative executions. Its ten document commitments are pathless; the
//! authenticated ancestry-catalogue commitment retains one fixed
//! archive-relative path. It contains no absolute root, runtime result, or
//! validator identity. Parsing it never confers authority. The opaque
//! authority below is emitted only after prior opaque authorities, exact
//! external byte views, global path closure, and all 254 closed row producers
//! agree byte-for-byte.

#[cfg(feature = "positive-gate")]
use anyhow::bail;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::{
    b4_campaign_contract::{B4ContractArtifactEncodingV1, B4ContractArtifactIdentityV1},
    b4_negative_ancestry_layout::{
        B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_MAX_BYTES, B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_PATH,
    },
    b4_negative_handler_contract::planned_negative_handler_contract,
    b4_plan::{
        B4_ARTIFACT_VALIDATOR_EXECUTION_COUNT, B4_NEGATIVE_PLAN_VARIANT_COUNT,
        B4_TREE_VALIDATOR_EXECUTION_COUNT, B4_VERIFIER_INPUT_EXECUTION_COUNT,
        B4MaterializationDomain, B4NegativeExecutionSurface, Eip0045B4NegativePlanV1,
    },
    canonical::{canonical_json_bytes, validate_canonical_json_source},
};

#[cfg(feature = "positive-gate")]
use std::collections::{BTreeMap, BTreeSet};
#[cfg(feature = "negative-materialization-set")]
use std::path::Path;

#[cfg(feature = "positive-gate")]
use sha2::{Digest, Sha256};

#[cfg(feature = "positive-gate")]
use serde_json::Value;

#[cfg(feature = "positive-gate")]
use crate::{
    b4::{
        B4ArtifactBinding, B4ArtifactEncoding, B4BindingState, B4CandidateCorpus, B4NegativeCase,
        B4PositiveArtifactRole, B4PositiveCase,
    },
    b4_campaign_contract::{
        B4CampaignPrecommitAuthorityV1, B4PositiveGenerationAuthorityV2, b4_paths_conflict,
        validate_safe_relative_path,
    },
    b4_catalog::{B4SubjectProvenanceV1, Eip0045B4SubjectCatalogV1},
    b4_mutation::{
        B4MaterializationReplayAdapterV1, Eip0045B4MaterializationIdentityV1,
        canonical_materialization_recipe_jcs, create_materialization_identity_with_adapter,
        verify_materialization_identity_with_adapter,
    },
    b4_negative_io::{
        B4_NEGATIVE_VERIFIER_INPUT_FORMAT, B4_NEGATIVE_VERIFIER_INPUT_FORMAT_VERSION,
        B4NegativeFileEncoding, B4NegativeNamedIdentityV1, Eip0045B4NegativeVerifierInputV1,
    },
    b4_plan::B4NegativePlanExecutionV1,
    b4_positive_gate::{
        B4PositiveGenerationAuthorityV1, B4PositiveGenerationCaseAuthorityV1, FileMeasurement,
        positive_auxiliary_artifact_paths,
    },
    b4_positive_source_auth::{
        B4PositiveCaseSourceV2, B4PositiveGenerationDocumentV2, B4PositiveSourceBytesV2,
    },
    b4_registry_probe::{
        B4RegistryProbeReplayAdapterV1, Eip0045B4NegativeBindingIndexV1,
        materialize_registry_probe, synthetic_registry_skeleton_source,
    },
    b4_subject_envelope::{
        B4SubjectEnvelopeContract, B4SubjectEnvelopeKind, B4SubjectPartBounds,
        encode_subject_envelope,
    },
    b4_terminal::{B4_TERMINAL_FIXTURE_RISC0_VERSION, Eip0045B4TerminalFixtureCatalogV1},
    b4_tree_probe::{
        B4AbstractTreePolicyOutcome, Eip0045B4AbstractTreeV1, materialize_tree_probe,
        validate_abstract_tree_policy, verify_tree_probe_materialization,
    },
    candidate_metadata::{CANDIDATE_METADATA_V1_MAX_BYTES, CandidateMetadataV1},
    claim::ok_receipt_claim_digests,
    constants::{
        B4_ALTERNATE_CONTROL_ROOT_HEX, B4_ALTERNATE_VERIFIER_PARAMETERS_HEX,
        MAX_APPLICATION_PAYLOAD_BYTES, MAX_STATEMENT_BYTES, PROOF_BYTES, PROOF_WORDS, RISC0_COMMIT,
        RISC0_NORMAL_LIFT_CONTROL_IDS_HEX, RISC0_OUTER_PO2, RISC0_REPOSITORY,
        STATEMENT_PREFIX_BYTES,
    },
    manifest::{ManifestEntry, ProofOutputManifest, validate_manifest_shape},
    receipt_oracle_codec::RECEIPT_ORACLE_MAX_BYTES,
};

#[cfg(all(feature = "negative-materialization-set", target_os = "linux"))]
use crate::b4_negative_ancestry_publication::{
    authenticate_published_b4_negative_ancestry_read_set_from_directory_descriptor,
    authenticate_published_b4_negative_ancestry_read_set_from_directory_descriptor_v2,
};
#[cfg(all(
    feature = "negative-materialization-set",
    any(target_os = "linux", test)
))]
use crate::b4_terminal_evidence_packet::{
    B4TerminalEvidenceImportAuthorityV1, B4TerminalEvidenceImportAuthorityV2,
};
#[cfg(all(
    feature = "negative-materialization-set",
    any(target_os = "linux", test)
))]
use crate::{
    b4_alternate_root_authority::B4FixedAlternateRootProofAuthorityV1,
    b4_c2_crypto::{
        B4DirectSealCheckpointMutationAuthorityV1, B4DirectSealCheckpointMutationAuthorityV2,
    },
};
#[cfg(all(feature = "negative-materialization-set", target_os = "linux"))]
use crate::{
    b4_alternate_root_authority::{
        B4FixedAlternateRootProofRequestV1, B4GeneratedAlternateRootProofBundleV1,
        authenticate_fixed_alternate_root_bundle,
    },
    b4_fixture_sources::{B4FixtureSourceResolverV1, B4MaterializationFixtureSourceResolverV2},
};
#[cfg(feature = "negative-materialization-set")]
use crate::{
    b4_negative_ancestry_authority::{
        B4NegativeAncestryWitnessCatalogAuthorityV1, B4NegativeAncestryWitnessCatalogAuthorityV2,
    },
    b4_negative_ancestry_publication::{
        B4NegativeAncestryPublicationReadSetV1, B4NegativeAncestryPublicationReadSetV2,
        authenticate_published_b4_negative_ancestry_read_set,
        validate_published_b4_negative_ancestry_witness_catalog,
    },
    b4_negative_ancestry_witness::Eip0045B4NegativeAncestryWitnessCatalogV1,
};

/// Exact format discriminator for the canonical negative materialization set.
pub const B4_NEGATIVE_MATERIALIZATION_SET_FORMAT: &str = "Eip0045B4NegativeMaterializationSetV1";
/// Exact format version for the canonical negative materialization set.
pub const B4_NEGATIVE_MATERIALIZATION_SET_FORMAT_VERSION: u8 = 1;
/// Exact number of negative executions in the canonical set.
pub const B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT: usize =
    B4_NEGATIVE_PLAN_VARIANT_COUNT as usize;
/// Maximum number of ordered raw context identities in one execution.
pub const B4_NEGATIVE_MATERIALIZATION_SET_MAX_CONTEXTS: usize = 64;

const MAX_MATERIALIZATION_SET_BYTES: usize = 8 * 1024 * 1024;
const MAX_RAW_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CAMPAIGN_PRECOMMIT_BYTES: u64 = 1024 * 1024;
const MAX_POSITIVE_GENERATION_SET_BYTES: u64 = 1024 * 1024;
const MAX_TERMINAL_EVIDENCE_DOCUMENT_BYTES: u64 = 64 * 1024;
const MAX_NEGATIVE_PLAN_BYTES: u64 = 128 * 1024;
const MAX_EXPANDED_REGISTRY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SUBJECT_CATALOG_BYTES: u64 = 128 * 1024;
const MAX_TERMINAL_FIXTURE_CATALOG_BYTES: u64 = 256 * 1024;
const MAX_NEGATIVE_BINDING_INDEX_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ABSTRACT_TREE_BYTES: u64 = 16 * 1024;
const MAX_MATERIALIZATION_IDENTITY_BYTES: u64 = 64 * 1024;
const MAX_NEGATIVE_INPUT_BYTES: u64 = 64 * 1024;
#[cfg(feature = "positive-gate")]
const C1_TREE_FIRST_INDEX: usize = 210;
#[cfg(feature = "positive-gate")]
const C1_REGISTRY_FIRST_INDEX: usize = 231;
#[cfg(feature = "positive-gate")]
const C1_NEGATIVE_CASE_DUPLICATE_INDEX: usize = 243;
#[cfg(feature = "positive-gate")]
const C1_BIJECTION_FIRST_INDEX: usize = 249;
#[cfg(feature = "positive-gate")]
const C1_END_INDEX_EXCLUSIVE: usize = 254;
#[cfg(feature = "positive-gate")]
const C1_CANDIDATE_REGISTRY_PARTS: [B4SubjectPartBounds; 1] =
    [B4SubjectPartBounds::new(1, 8 * 1024 * 1024)];
#[cfg(feature = "positive-gate")]
const C1_NEGATIVE_BINDING_INDEX_PARTS: [B4SubjectPartBounds; 2] = [
    B4SubjectPartBounds::new(1, 128 * 1024),
    B4SubjectPartBounds::new(1, 8 * 1024 * 1024),
];
#[cfg(feature = "positive-gate")]
const MAX_ALTERNATE_ROOT_MANIFEST_BYTES: usize = 8 * 1024;
/// One retained external byte view selected and held by the finalizer.
///
/// A view is evidence input, never authority by itself. Its path is the exact
/// archive-relative physical identity and its bytes are remeasured by the
/// materialization closure.
#[cfg(feature = "positive-gate")]
#[derive(Clone, Copy, Debug)]
pub struct B4NegativeMaterializationExternalBytesV1<'a> {
    /// Exact safe archive-relative path.
    pub path: &'a str,
    /// Exact retained bytes observed at the authority boundary.
    pub bytes: &'a [u8],
}

/// Exact post-proof files remeasured for one ordered positive case.
#[cfg(feature = "positive-gate")]
#[derive(Clone, Copy, Debug)]
pub struct B4NegativeMaterializationPositiveExportV1<'a> {
    /// Exact zero-based positive-case position.
    pub case_index: u8,
    /// Exact canonical proof-output manifest.
    pub proof_output_manifest: B4NegativeMaterializationExternalBytesV1<'a>,
    /// Exact raw succinct seal.
    pub raw_seal: B4NegativeMaterializationExternalBytesV1<'a>,
}

/// One generator-produced alternate-root export shared by the only two rows
/// whose closed recipes require it.
///
/// The canonical manifest commits to the complete proof-output directory.
/// This view supplies every listed file exactly once; later closed producers
/// independently verify the same retained receipt for executions 108 and 146.
#[cfg(feature = "positive-gate")]
#[derive(Clone, Copy, Debug)]
pub struct B4NegativeAlternateRootExportV1<'a> {
    /// Exact canonical proof-output manifest outside the manifested directory.
    pub proof_output_manifest: B4NegativeMaterializationExternalBytesV1<'a>,
    /// Exact files listed by the manifest, in manifest path order.
    pub artifacts: &'a [B4NegativeMaterializationExternalBytesV1<'a>],
}

/// Exact external files proposed for one canonical negative execution.
///
/// These bytes do not authorize themselves. A closed producer must
/// independently reconstruct all six byte families before they can be retained
/// by [`B4NegativeMaterializationSetAuthorityV1`].
#[cfg(feature = "positive-gate")]
#[derive(Clone, Copy, Debug)]
pub struct B4NegativeMaterializationExternalExecutionV1<'a> {
    /// Exact zero-based canonical-plan position.
    pub execution_index: u16,
    /// Exact canonical-plan execution ID.
    pub execution_id: &'a str,
    /// Exact independently selected unmutated base.
    pub base: B4NegativeMaterializationExternalBytesV1<'a>,
    /// Exact canonical materialization-identity document.
    pub materialization_identity: B4NegativeMaterializationExternalBytesV1<'a>,
    /// Exact canonical neutral verifier-input document.
    pub negative_input: B4NegativeMaterializationExternalBytesV1<'a>,
    /// Exact raw subject mounted in the neutral verifier root.
    pub subject: B4NegativeMaterializationExternalBytesV1<'a>,
    /// Exact ordered raw context prefix mounted in the neutral verifier root.
    pub contexts: &'a [B4NegativeMaterializationExternalBytesV1<'a>],
}

/// Complete retained input view for the negative materialization phase.
///
/// The eight public top-level commitments are accompanied by the positive input
/// set and the eleven physical positive exports because the opaque authority
/// must remeasure prior-gate bytes rather than trust their copied digests.
#[cfg(feature = "positive-gate")]
#[derive(Clone, Copy, Debug)]
pub struct B4NegativeMaterializationSetExternalInputsV1<'a> {
    /// Exact canonical positive input set retained by the prior gate.
    pub positive_input_set: B4NegativeMaterializationExternalBytesV1<'a>,
    /// Exact canonical campaign precommit.
    pub campaign_precommit: B4NegativeMaterializationExternalBytesV1<'a>,
    /// Exact canonical positive generation set.
    pub positive_generation_set: B4NegativeMaterializationExternalBytesV1<'a>,
    /// Exact canonical negative plan.
    pub negative_plan: B4NegativeMaterializationExternalBytesV1<'a>,
    /// Exact canonical expanded candidate registry.
    pub expanded_registry: B4NegativeMaterializationExternalBytesV1<'a>,
    /// Exact canonical detached-subject catalogue.
    pub subject_catalog: B4NegativeMaterializationExternalBytesV1<'a>,
    /// Exact canonical terminal-fixture catalogue.
    pub terminal_fixture_catalog: B4NegativeMaterializationExternalBytesV1<'a>,
    /// Exact canonical negative-binding index.
    pub negative_binding_index: B4NegativeMaterializationExternalBytesV1<'a>,
    /// Exact canonical abstract corpus tree.
    pub abstract_tree: B4NegativeMaterializationExternalBytesV1<'a>,
    /// Exactly eleven positive proof-output manifests and raw seals.
    pub positive_exports: &'a [B4NegativeMaterializationPositiveExportV1<'a>],
    /// The sole fixed alternate-root export, shared by rows 108 and 146.
    pub alternate_root_export: B4NegativeAlternateRootExportV1<'a>,
    /// Exhaustive exact source-object inventory selected by the closed
    /// registry, subject, terminal, and positive-export documents. The
    /// alternate-root export is supplied separately because its manifest is
    /// the authority for that one generated directory.
    ///
    /// This is one global source map, not a caller-populated per-row replay
    /// map. Closed producers select from it only through compiled plan rules.
    pub source_artifacts: &'a [B4NegativeMaterializationExternalBytesV1<'a>],
    /// Exactly 254 canonical-plan materialization views.
    pub executions: &'a [B4NegativeMaterializationExternalExecutionV1<'a>],
}

/// Pathless SHA-256 identity of exact bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4NegativeMaterializationByteIdentityV1 {
    /// Exact byte length.
    pub byte_length: u64,
    /// Lowercase SHA-256 of the exact bytes.
    pub sha256: String,
}

impl B4NegativeMaterializationByteIdentityV1 {
    fn validate(&self, maximum: u64, label: &str) -> Result<()> {
        self.validate_with_minimum(1, maximum, label)
    }

    fn validate_with_minimum(&self, minimum: u64, maximum: u64, label: &str) -> Result<()> {
        ensure!(
            (minimum..=maximum).contains(&self.byte_length),
            "{label} byte length is outside the V1 bound"
        );
        validate_digest(&self.sha256, &format!("{label} SHA-256"))
    }
}

/// Exact closed materialization-domain totals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4NegativeMaterializationDomainTotalsV1 {
    /// Verifier-input executions.
    pub verifier_input: u16,
    /// Artifact-validator executions.
    pub artifact_validator: u16,
    /// Closed-tree-validator executions.
    pub tree_validator: u16,
}

impl B4NegativeMaterializationDomainTotalsV1 {
    const EXPECTED: Self = Self {
        verifier_input: B4_VERIFIER_INPUT_EXECUTION_COUNT,
        artifact_validator: B4_ARTIFACT_VALIDATOR_EXECUTION_COUNT,
        tree_validator: B4_TREE_VALIDATOR_EXECUTION_COUNT,
    };

    fn increment(&mut self, domain: B4MaterializationDomain) -> Result<()> {
        let counter = match domain {
            B4MaterializationDomain::VerifierInput => &mut self.verifier_input,
            B4MaterializationDomain::ArtifactValidator => &mut self.artifact_validator,
            B4MaterializationDomain::TreeValidator => &mut self.tree_validator,
        };
        *counter = counter
            .checked_add(1)
            .context("materialization-domain total overflows u16")?;
        Ok(())
    }
}

/// Pathless commitments for one exact canonical negative-plan execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4NegativeMaterializationSetExecutionV1 {
    /// Zero-based index in exact flattened canonical-plan order.
    pub execution_index: u16,
    /// Exact canonical-plan execution ID.
    pub execution_id: String,
    /// Exact canonical-plan materialization domain.
    pub materialization_domain: B4MaterializationDomain,
    /// Exact canonical-plan validation surface.
    pub validation_surface: B4NegativeExecutionSurface,
    /// Exact unmutated raw base bytes.
    pub base: B4NegativeMaterializationByteIdentityV1,
    /// Exact canonical materialization-identity document bytes.
    pub materialization_identity: B4NegativeMaterializationByteIdentityV1,
    /// Exact canonical neutral negative-input document bytes.
    pub negative_input: B4NegativeMaterializationByteIdentityV1,
    /// Exact raw subject bytes supplied to both validators.
    pub subject: B4NegativeMaterializationByteIdentityV1,
    /// Ordered raw context bytes supplied to both validators.
    pub contexts: Vec<B4NegativeMaterializationByteIdentityV1>,
}

impl B4NegativeMaterializationSetExecutionV1 {
    fn validate_identities(&self, index: usize) -> Result<()> {
        self.base.validate(MAX_RAW_BYTES, "materialization base")?;
        self.materialization_identity.validate(
            MAX_MATERIALIZATION_IDENTITY_BYTES,
            "materialization identity",
        )?;
        self.negative_input
            .validate(MAX_NEGATIVE_INPUT_BYTES, "negative input")?;
        self.subject.validate_with_minimum(
            subject_minimum_byte_length(self.materialization_domain, self.validation_surface),
            MAX_RAW_BYTES,
            "negative subject",
        )?;
        ensure!(
            self.contexts.len() <= B4_NEGATIVE_MATERIALIZATION_SET_MAX_CONTEXTS,
            "materialization execution at index {index} has too many contexts"
        );
        let handler = planned_negative_handler_contract(
            self.materialization_domain,
            self.validation_surface,
        )?
        .context("materialization execution has no planned handler contract")?;
        ensure!(
            self.contexts.len() == handler.custody().contexts().len(),
            "materialization execution at index {index} has the wrong exact context cardinality"
        );
        for (context_index, context) in self.contexts.iter().enumerate() {
            context.validate(MAX_RAW_BYTES, &format!("negative context {context_index}"))?;
        }
        Ok(())
    }
}

const fn subject_minimum_byte_length(
    domain: B4MaterializationDomain,
    surface: B4NegativeExecutionSurface,
) -> u64 {
    if matches!(domain, B4MaterializationDomain::VerifierInput)
        && matches!(surface, B4NegativeExecutionSurface::Risc0ParserInternal)
    {
        0
    } else {
        1
    }
}

/// Canonical structural commitments prepared before the first negative run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Eip0045B4NegativeMaterializationSetV1 {
    /// Exact V1 format discriminator.
    pub format: String,
    /// Exact V1 format version.
    pub format_version: u8,
    /// Exact canonical campaign-precommit bytes.
    pub campaign_precommit: B4NegativeMaterializationByteIdentityV1,
    /// Exact canonical positive-generation-set bytes.
    pub positive_generation_set: B4NegativeMaterializationByteIdentityV1,
    /// Exact pathless identity of the reopened terminal-evidence packet manifest.
    pub terminal_evidence_packet_manifest: B4NegativeMaterializationByteIdentityV1,
    /// Exact pathless identity of the canonical terminal-evidence campaign receipt.
    pub terminal_evidence_campaign_receipt: B4NegativeMaterializationByteIdentityV1,
    /// Exact canonical negative-plan bytes.
    pub negative_plan: B4NegativeMaterializationByteIdentityV1,
    /// Exact canonical expanded-registry bytes.
    pub expanded_registry: B4NegativeMaterializationByteIdentityV1,
    /// Exact canonical subject-catalog bytes.
    pub subject_catalog: B4NegativeMaterializationByteIdentityV1,
    /// Exact canonical terminal-fixture-catalog bytes.
    pub terminal_fixture_catalog: B4NegativeMaterializationByteIdentityV1,
    /// Exact canonical negative-binding-index bytes.
    pub negative_binding_index: B4NegativeMaterializationByteIdentityV1,
    /// Exact canonical abstract-tree bytes.
    pub abstract_tree: B4NegativeMaterializationByteIdentityV1,
    /// Exact archive-relative identity of the authenticated ancestry catalogue.
    pub negative_ancestry_witness_catalog: B4ContractArtifactIdentityV1,
    /// Exact independently counted materialization-domain totals.
    pub domain_totals: B4NegativeMaterializationDomainTotalsV1,
    /// Exact negative execution count.
    pub execution_count: u16,
    /// Exactly 254 rows in flattened canonical-plan order.
    pub executions: Vec<B4NegativeMaterializationSetExecutionV1>,
}

impl Eip0045B4NegativeMaterializationSetV1 {
    /// Parse exact RFC 8785 JCS and enforce every local structural invariant.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, duplicate-key,
    /// noncanonical, unknown-field, incorrectly counted, reordered, or
    /// otherwise structurally invalid input.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            source.len() <= MAX_MATERIALIZATION_SET_BYTES,
            "B4 negative materialization set exceeds its canonical-byte bound"
        );
        let value = validate_canonical_json_source(source)
            .context("B4 negative materialization set is not exact RFC 8785 JCS")?;
        let materialization_set: Self = serde_json::from_value(value)
            .context("invalid B4 negative materialization-set shape")?;
        materialization_set.validate()?;
        ensure!(
            materialization_set.to_canonical_jcs()? == source,
            "B4 negative materialization set does not round-trip byte-exactly"
        );
        Ok(materialization_set)
    }

    /// Serialize the validated structural contract as exact RFC 8785 JCS.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid in-memory contract or an oversized
    /// canonical representation.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value = serde_json::to_value(self)
            .context("cannot serialize B4 negative materialization set")?;
        let bytes = canonical_json_bytes(&value)?;
        ensure!(
            bytes.len() <= MAX_MATERIALIZATION_SET_BYTES,
            "B4 negative materialization set exceeds its canonical-byte bound"
        );
        Ok(bytes)
    }

    /// Validate the exact format, bounds, counts, and canonical-plan sequence.
    ///
    /// This structural validation does not authenticate committed external
    /// bytes or confer campaign authority.
    ///
    /// # Errors
    ///
    /// Returns an error for any local V1 invariant defect.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == B4_NEGATIVE_MATERIALIZATION_SET_FORMAT,
            "wrong B4 negative materialization-set format label"
        );
        ensure!(
            self.format_version == B4_NEGATIVE_MATERIALIZATION_SET_FORMAT_VERSION,
            "wrong B4 negative materialization-set format version"
        );
        self.validate_document_identities()?;
        ensure!(
            self.domain_totals == B4NegativeMaterializationDomainTotalsV1::EXPECTED,
            "wrong B4 negative materialization-domain totals"
        );
        ensure!(
            usize::from(self.execution_count) == B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT,
            "wrong B4 negative materialization execution count"
        );
        ensure!(
            self.executions.len() == B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT,
            "B4 negative materialization set must contain exactly {B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT} executions"
        );

        let plan = Eip0045B4NegativePlanV1::canonical()?;
        let flattened_plan = plan.groups.iter().flat_map(|group| group.executions.iter());
        let mut observed_totals = B4NegativeMaterializationDomainTotalsV1 {
            verifier_input: 0,
            artifact_validator: 0,
            tree_validator: 0,
        };
        for (index, (actual, planned)) in self.executions.iter().zip(flattened_plan).enumerate() {
            actual
                .validate_identities(index)
                .with_context(|| format!("invalid materialization execution at index {index}"))?;
            ensure!(
                usize::from(actual.execution_index) == index,
                "materialization execution index drift at index {index}"
            );
            ensure!(
                actual.execution_id == planned.execution_id,
                "materialization execution ID drift at index {index}"
            );
            ensure!(
                actual.materialization_domain == planned.materialization_domain,
                "materialization domain drift at index {index}"
            );
            ensure!(
                actual.validation_surface == planned.execution_surface,
                "validation surface drift at index {index}"
            );
            observed_totals.increment(actual.materialization_domain)?;
        }
        ensure!(
            observed_totals == B4NegativeMaterializationDomainTotalsV1::EXPECTED
                && observed_totals == self.domain_totals,
            "materialization execution rows do not reproduce the exact domain totals"
        );
        Ok(())
    }

    fn validate_document_identities(&self) -> Result<()> {
        self.campaign_precommit
            .validate(MAX_CAMPAIGN_PRECOMMIT_BYTES, "campaign precommit")?;
        self.positive_generation_set
            .validate(MAX_POSITIVE_GENERATION_SET_BYTES, "positive generation set")?;
        self.terminal_evidence_packet_manifest.validate(
            MAX_TERMINAL_EVIDENCE_DOCUMENT_BYTES,
            "terminal-evidence packet manifest",
        )?;
        self.terminal_evidence_campaign_receipt.validate(
            MAX_TERMINAL_EVIDENCE_DOCUMENT_BYTES,
            "terminal-evidence campaign receipt",
        )?;
        self.negative_plan
            .validate(MAX_NEGATIVE_PLAN_BYTES, "negative plan")?;
        self.expanded_registry
            .validate(MAX_EXPANDED_REGISTRY_BYTES, "expanded registry")?;
        self.subject_catalog
            .validate(MAX_SUBJECT_CATALOG_BYTES, "subject catalog")?;
        self.terminal_fixture_catalog.validate(
            MAX_TERMINAL_FIXTURE_CATALOG_BYTES,
            "terminal fixture catalog",
        )?;
        self.negative_binding_index
            .validate(MAX_NEGATIVE_BINDING_INDEX_BYTES, "negative binding index")?;
        self.abstract_tree
            .validate(MAX_ABSTRACT_TREE_BYTES, "abstract tree")?;
        self.negative_ancestry_witness_catalog
            .validate()
            .context("negative-ancestry witness catalogue has an invalid identity")?;
        ensure!(
            self.negative_ancestry_witness_catalog.path
                == B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_PATH,
            "negative-ancestry witness catalogue has the wrong archive path"
        );
        ensure!(
            self.negative_ancestry_witness_catalog.encoding
                == B4ContractArtifactEncodingV1::Rfc8785Jcs,
            "negative-ancestry witness catalogue must use rfc8785-jcs encoding"
        );
        ensure!(
            (1..=B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_MAX_BYTES)
                .contains(&self.negative_ancestry_witness_catalog.byte_length),
            "negative-ancestry witness catalogue byte length is outside 1..=131072"
        );
        Ok(())
    }
}

/// Opaque materialization authority emitted only by the closed finalizer
/// reconstruction path.
///
/// The fields are private, the type has no parser or deserializer, and parsing
/// [`Eip0045B4NegativeMaterializationSetV1`] cannot create a value of this
/// type. The retained bytes are the exact bytes later mounted into both
/// validator roots.
#[cfg(feature = "positive-gate")]
#[derive(Clone, Debug)]
pub struct B4NegativeMaterializationSetAuthorityV1 {
    expected: Eip0045B4NegativeMaterializationSetV1,
    canonical_jcs: Vec<u8>,
    executions: Vec<B4RetainedNegativeMaterializationExecutionV1>,
    provenance_paths: BTreeSet<String>,
}

/// Opaque affine authority for the complete V2-rooted physical materialization closure.
///
/// The serialized materialization set remains the canonical V1 wire. This
/// distinct authority can be minted only from the V2 positive, ancestry, and
/// terminal-import branches and has no V1 conversion, parser, clone, copy,
/// default, or serde constructor.
#[cfg(feature = "positive-gate")]
pub struct B4NegativeMaterializationSetAuthorityV2 {
    expected: Eip0045B4NegativeMaterializationSetV1,
    canonical_jcs: Vec<u8>,
    executions: Vec<B4RetainedNegativeMaterializationExecutionV1>,
    provenance_paths: BTreeSet<String>,
}

#[cfg(feature = "negative-materialization-set")]
struct B4AuthenticatedNegativeAncestryHandoffV1 {
    read_set: B4NegativeAncestryPublicationReadSetV1,
    catalog_identity: B4ContractArtifactIdentityV1,
}

#[cfg(feature = "negative-materialization-set")]
impl B4AuthenticatedNegativeAncestryHandoffV1 {
    fn from_publication(
        root: &Path,
        authority: &B4NegativeAncestryWitnessCatalogAuthorityV1,
    ) -> Result<Self> {
        let read_set = authenticate_published_b4_negative_ancestry_read_set(root, authority)?;
        Self::from_read_set(read_set)
    }

    #[cfg(target_os = "linux")]
    fn from_directory_descriptor(
        root: std::os::fd::BorrowedFd<'_>,
        authority: &B4NegativeAncestryWitnessCatalogAuthorityV1,
    ) -> Result<Self> {
        let read_set =
            authenticate_published_b4_negative_ancestry_read_set_from_directory_descriptor(
                root, authority,
            )?;
        Self::from_read_set(read_set)
    }

    fn from_read_set(read_set: B4NegativeAncestryPublicationReadSetV1) -> Result<Self> {
        let catalog_identity = B4ContractArtifactIdentityV1::from_bytes(
            B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_PATH,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            read_set.catalog_jcs(),
        )?;
        ensure!(
            catalog_identity.byte_length <= B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_MAX_BYTES,
            "authenticated negative-ancestry catalogue exceeds 131072 bytes"
        );
        Ok(Self {
            read_set,
            catalog_identity,
        })
    }
}

#[cfg(feature = "negative-materialization-set")]
struct B4AuthenticatedNegativeAncestryHandoffV2 {
    read_set: B4NegativeAncestryPublicationReadSetV2,
    catalog_identity: B4ContractArtifactIdentityV1,
}

#[cfg(feature = "negative-materialization-set")]
impl B4AuthenticatedNegativeAncestryHandoffV2 {
    #[cfg(target_os = "linux")]
    fn from_directory_descriptor(
        root: std::os::fd::BorrowedFd<'_>,
        authority: &B4NegativeAncestryWitnessCatalogAuthorityV2,
    ) -> Result<Self> {
        let read_set =
            authenticate_published_b4_negative_ancestry_read_set_from_directory_descriptor_v2(
                root, authority,
            )?;
        let catalog_identity = B4ContractArtifactIdentityV1::from_bytes(
            B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_PATH,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            read_set.catalog_jcs(),
        )?;
        ensure!(
            catalog_identity.byte_length <= B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_MAX_BYTES,
            "authenticated V2 negative-ancestry catalogue exceeds 131072 bytes"
        );
        Ok(Self {
            read_set,
            catalog_identity,
        })
    }
}

#[cfg(feature = "negative-materialization-set")]
#[derive(Clone, Debug)]
#[allow(
    dead_code,
    reason = "production validates the returned ownership partition while tests inspect each class"
)]
struct B4NegativeAncestryProvenancePartitionV1 {
    publication_payloads: BTreeSet<String>,
    prior_authorities: BTreeSet<String>,
    profile_case9: BTreeSet<String>,
}

#[cfg(feature = "positive-gate")]
#[derive(Clone, Debug)]
pub(crate) struct B4RetainedNegativeMaterializationExecutionV1 {
    execution_index: u16,
    execution_id: String,
    base: Vec<u8>,
    materialization_identity_jcs: Vec<u8>,
    negative_input_jcs: Vec<u8>,
    subject: Vec<u8>,
    contexts: Vec<Vec<u8>>,
}

#[cfg(feature = "positive-gate")]
impl B4NegativeMaterializationSetAuthorityV1 {
    /// Close the exact prior-authority, ancestry-publication, and external-byte
    /// handoff into the sole opaque negative-materialization authority.
    ///
    /// # Errors
    ///
    /// Returns an error for lineage drift, publication drift, path-role
    /// aliasing, top-level external-input drift, incomplete producers, or final
    /// publication revalidation failure.
    #[cfg(feature = "negative-materialization-set")]
    pub fn from_external_closure(
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV1,
        ancestry: &B4NegativeAncestryWitnessCatalogAuthorityV1,
        ancestry_publication_root: &Path,
        external: &B4NegativeMaterializationSetExternalInputsV1<'_>,
    ) -> Result<Self> {
        let prior =
            B4MaterializationPriorAuthoritySnapshotV1::from_authorities(campaign, positive)?;
        ancestry.verify_prior_authority_lineage(campaign, positive)?;
        let handoff = B4AuthenticatedNegativeAncestryHandoffV1::from_publication(
            ancestry_publication_root,
            ancestry,
        )?;
        let mut paths = B4PhysicalPathClosureV1::from_prior(&prior)?;
        for (path, bytes) in handoff.read_set.ordered_files() {
            paths.bind_publication_source(path, bytes, "negative-ancestry publication")?;
        }
        let top_level = authenticate_top_level(
            &prior,
            external,
            &mut paths,
            B4AlternateRootSourceModeV1::CallerCustody,
        )?;
        ensure_top_level_snapshot_unchanged(
            &top_level,
            external,
            B4AlternateRootSourceModeV1::CallerCustody,
        )?;
        close_authenticated_negative_ancestry_handoff(
            &prior,
            ancestry,
            ancestry_publication_root,
            &handoff,
            &top_level,
            external.executions,
            &mut paths,
            &ProductionRowProducer,
        )
    }

    /// Close the descriptor-rooted terminal-evidence and negative-ancestry
    /// handoffs into the production materialization reconstruction path.
    ///
    /// This distinct constructor requires the opaque terminal import
    /// authority. It cannot be reached through the historical five-input
    /// closure and it never accepts caller-selected packet or receipt
    /// identities.
    ///
    /// # Errors
    ///
    /// Returns an error for any terminal, lineage, descriptor, external-byte,
    /// producer-coverage, or final revalidation defect.
    #[doc(hidden)]
    #[cfg(all(feature = "negative-materialization-set", target_os = "linux"))]
    pub fn from_descriptor_rooted_terminal_closure(
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV1,
        ancestry: &B4NegativeAncestryWitnessCatalogAuthorityV1,
        ancestry_root: std::os::fd::BorrowedFd<'_>,
        terminal: &B4TerminalEvidenceImportAuthorityV1,
        external: &B4NegativeMaterializationSetExternalInputsV1<'_>,
    ) -> Result<Self> {
        terminal
            .verify_authority_bindings(campaign, positive)
            .context("terminal-evidence import differs from materialization authorities")?;
        let prior =
            B4MaterializationPriorAuthoritySnapshotV1::from_authorities(campaign, positive)?;
        ancestry.verify_prior_authority_lineage(campaign, positive)?;
        let handoff = B4AuthenticatedNegativeAncestryHandoffV1::from_directory_descriptor(
            ancestry_root,
            ancestry,
        )?;
        let mut paths = B4PhysicalPathClosureV1::from_prior(&prior)?;
        for (path, bytes) in handoff.read_set.ordered_files() {
            paths.bind_publication_source(path, bytes, "negative-ancestry publication")?;
        }
        let top_level = authenticate_top_level(
            &prior,
            external,
            &mut paths,
            B4AlternateRootSourceModeV1::CallerCustody,
        )?;
        ensure_top_level_snapshot_unchanged(
            &top_level,
            external,
            B4AlternateRootSourceModeV1::CallerCustody,
        )?;
        let authority = close_authenticated_negative_ancestry_handoff_core(
            &prior,
            ancestry,
            &handoff,
            &top_level,
            external.executions,
            &mut paths,
            &DescriptorRootedStrongInferenceRowProducer {
                terminal,
                read_set: &handoff.read_set,
            },
        )?;
        terminal
            .verify_authority_bindings(campaign, positive)
            .context("terminal-evidence import changed during materialization closure")?;
        authenticate_published_b4_negative_ancestry_read_set_from_directory_descriptor(
            ancestry_root,
            ancestry,
        )
        .context("negative-ancestry publication changed during materialization closure")?;
        Ok(authority)
    }

    /// Close the descriptor-rooted E6 path after one fixed alternate-root
    /// proof is generated and independently replayed.
    ///
    /// The callback receives one opaque, parameter-free request derived only
    /// from the authenticated positive input. The caller cannot select a root,
    /// terminal, proof exponent, mode, workload, or filesystem path. The
    /// callback is invoked exactly once after top-level authentication. The
    /// production handler supplies it from the measured executor's
    /// proof-capability branch.
    ///
    /// # Errors
    ///
    /// Returns an error for any prior-authority, descriptor, top-level,
    /// provider, receipt, STARK, fixed-root, producer-coverage, or final
    /// revalidation defect.
    #[doc(hidden)]
    #[cfg(all(feature = "negative-materialization-set", target_os = "linux"))]
    pub fn from_descriptor_rooted_alternate_root_closure<P>(
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV1,
        ancestry: &B4NegativeAncestryWitnessCatalogAuthorityV1,
        ancestry_root: std::os::fd::BorrowedFd<'_>,
        terminal: &B4TerminalEvidenceImportAuthorityV1,
        external: &B4NegativeMaterializationSetExternalInputsV1<'_>,
        provider: P,
    ) -> Result<Self>
    where
        P: FnOnce(
            &B4FixedAlternateRootProofRequestV1,
        ) -> Result<B4GeneratedAlternateRootProofBundleV1>,
    {
        terminal
            .verify_authority_bindings(campaign, positive)
            .context("terminal-evidence import differs from materialization authorities")?;
        let prior =
            B4MaterializationPriorAuthoritySnapshotV1::from_authorities(campaign, positive)?;
        ancestry.verify_prior_authority_lineage(campaign, positive)?;
        let handoff = B4AuthenticatedNegativeAncestryHandoffV1::from_directory_descriptor(
            ancestry_root,
            ancestry,
        )?;
        let mut paths = B4PhysicalPathClosureV1::from_prior(&prior)?;
        for (path, bytes) in handoff.read_set.ordered_files() {
            paths.bind_publication_source(path, bytes, "negative-ancestry publication")?;
        }
        let top_level = authenticate_top_level(
            &prior,
            external,
            &mut paths,
            B4AlternateRootSourceModeV1::ProviderDeferred,
        )?;
        ensure_top_level_snapshot_unchanged(
            &top_level,
            external,
            B4AlternateRootSourceModeV1::ProviderDeferred,
        )?;

        let resolver = B4FixtureSourceResolverV1::from_authenticated(&top_level)
            .context("alternate-root request cannot authenticate fixture sources")?;
        let input = resolver
            .positive_input()
            .context("alternate-root request cannot authenticate the positive input")?;
        let statement = resolver
            .case_zero_reference_statement()
            .context("alternate-root request cannot authenticate the global statement")?;
        let request = B4FixedAlternateRootProofRequestV1::from_authenticated(
            statement.statement_bytes(),
            input.guest_elf(),
        )?;
        let bundle = provider(&request).context("fixed alternate-root provider failed")?;
        let alternate = authenticate_fixed_alternate_root_bundle(&request, bundle)
            .context("fixed alternate-root proof bundle failed cryptographic replay")?;

        let authority = close_authenticated_negative_ancestry_handoff_core(
            &prior,
            ancestry,
            &handoff,
            &top_level,
            external.executions,
            &mut paths,
            &DescriptorRootedAlternateRootRowProducer {
                terminal,
                read_set: &handoff.read_set,
                alternate: &alternate,
            },
        )?;
        terminal
            .verify_authority_bindings(campaign, positive)
            .context("terminal-evidence import changed during materialization closure")?;
        authenticate_published_b4_negative_ancestry_read_set_from_directory_descriptor(
            ancestry_root,
            ancestry,
        )
        .context("negative-ancestry publication changed during materialization closure")?;
        ensure_top_level_snapshot_unchanged(
            &top_level,
            external,
            B4AlternateRootSourceModeV1::ProviderDeferred,
        )?;
        Ok(authority)
    }

    /// Close the descriptor-rooted E7 path after the fixed alternate-root
    /// proof and the four exact direct-seal checkpoint mutations are derived.
    ///
    /// The alternate-root callback retains the E6 contract: it receives one
    /// opaque, parameter-free request and is invoked exactly once. Only after
    /// that generated proof is independently replayed does this constructor
    /// authenticate the case-0 receipt oracle and derive rows 156 through 159.
    ///
    /// # Errors
    ///
    /// Returns an error for any prior-authority, descriptor, top-level,
    /// provider, receipt, STARK, fixed-root, typed-checkpoint,
    /// producer-coverage, or final revalidation defect.
    #[doc(hidden)]
    #[cfg(all(feature = "negative-materialization-set", target_os = "linux"))]
    pub fn from_descriptor_rooted_cryptographic_closure<P>(
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV1,
        ancestry: &B4NegativeAncestryWitnessCatalogAuthorityV1,
        ancestry_root: std::os::fd::BorrowedFd<'_>,
        terminal: &B4TerminalEvidenceImportAuthorityV1,
        external: &B4NegativeMaterializationSetExternalInputsV1<'_>,
        provider: P,
    ) -> Result<Self>
    where
        P: FnOnce(
            &B4FixedAlternateRootProofRequestV1,
        ) -> Result<B4GeneratedAlternateRootProofBundleV1>,
    {
        terminal
            .verify_authority_bindings(campaign, positive)
            .context("terminal-evidence import differs from materialization authorities")?;
        let prior =
            B4MaterializationPriorAuthoritySnapshotV1::from_authorities(campaign, positive)?;
        ancestry.verify_prior_authority_lineage(campaign, positive)?;
        let handoff = B4AuthenticatedNegativeAncestryHandoffV1::from_directory_descriptor(
            ancestry_root,
            ancestry,
        )?;
        let mut paths = B4PhysicalPathClosureV1::from_prior(&prior)?;
        for (path, bytes) in handoff.read_set.ordered_files() {
            paths.bind_publication_source(path, bytes, "negative-ancestry publication")?;
        }
        let top_level = authenticate_top_level(
            &prior,
            external,
            &mut paths,
            B4AlternateRootSourceModeV1::ProviderDeferred,
        )?;
        ensure_top_level_snapshot_unchanged(
            &top_level,
            external,
            B4AlternateRootSourceModeV1::ProviderDeferred,
        )?;

        let resolver = B4FixtureSourceResolverV1::from_authenticated(&top_level)
            .context("alternate-root request cannot authenticate fixture sources")?;
        let input = resolver
            .positive_input()
            .context("alternate-root request cannot authenticate the positive input")?;
        let statement = resolver
            .case_zero_reference_statement()
            .context("alternate-root request cannot authenticate the global statement")?;
        let request = B4FixedAlternateRootProofRequestV1::from_authenticated(
            statement.statement_bytes(),
            input.guest_elf(),
        )?;
        let bundle = provider(&request).context("fixed alternate-root provider failed")?;
        let alternate = authenticate_fixed_alternate_root_bundle(&request, bundle)
            .context("fixed alternate-root proof bundle failed cryptographic replay")?;
        let crypto = B4DirectSealCheckpointMutationAuthorityV1::from_authenticated(&top_level)
            .context("direct-seal checkpoint mutation authority failed")?;

        let authority = close_authenticated_negative_ancestry_handoff_core(
            &prior,
            ancestry,
            &handoff,
            &top_level,
            external.executions,
            &mut paths,
            &DescriptorRootedCryptographicRowProducer {
                terminal,
                read_set: &handoff.read_set,
                alternate: &alternate,
                crypto: &crypto,
            },
        )?;
        terminal
            .verify_authority_bindings(campaign, positive)
            .context("terminal-evidence import changed during materialization closure")?;
        authenticate_published_b4_negative_ancestry_read_set_from_directory_descriptor(
            ancestry_root,
            ancestry,
        )
        .context("negative-ancestry publication changed during materialization closure")?;
        ensure_top_level_snapshot_unchanged(
            &top_level,
            external,
            B4AlternateRootSourceModeV1::ProviderDeferred,
        )?;
        Ok(authority)
    }

    /// Compare a separately supplied candidate document with the exact
    /// internally reconstructed canonical set.
    ///
    /// Parsing and equality establish only that the candidate serializes the
    /// already-held authority. They cannot create the authority.
    ///
    /// # Errors
    ///
    /// Returns an error for any structural, canonical, or byte-level
    /// difference.
    pub fn verify_candidate_jcs(&self, candidate_jcs: &[u8]) -> Result<()> {
        let parsed = Eip0045B4NegativeMaterializationSetV1::from_canonical_jcs(candidate_jcs)?;
        ensure!(
            parsed == self.expected && candidate_jcs == self.canonical_jcs,
            "candidate negative materialization set differs from the independently reconstructed authority"
        );
        Ok(())
    }

    /// Exact canonical materialization-set bytes prescribed by this authority.
    #[must_use]
    pub fn canonical_materialization_set_jcs(&self) -> &[u8] {
        &self.canonical_jcs
    }

    /// Exact public projection prescribed by this authority.
    #[must_use]
    pub fn materialization_set(&self) -> &Eip0045B4NegativeMaterializationSetV1 {
        &self.expected
    }

    /// Complete ancestry-safe physical path closure retained for later
    /// finalizer phases.
    pub(crate) fn provenance_paths(&self) -> &BTreeSet<String> {
        &self.provenance_paths
    }

    /// Resolve one exact retained neutral execution root.
    pub(crate) fn retained_execution(
        &self,
        execution_index: usize,
    ) -> Result<&B4RetainedNegativeMaterializationExecutionV1> {
        let execution = self
            .executions
            .get(execution_index)
            .context("negative materialization execution index is outside the authority")?;
        ensure!(
            usize::from(execution.execution_index) == execution_index,
            "retained negative materialization execution index drift"
        );
        Ok(execution)
    }

    fn validate_retained_closure(&self) -> Result<()> {
        ensure!(
            self.executions.len() == B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT
                && self.executions.len() == self.expected.executions.len(),
            "opaque negative materialization authority retained the wrong execution cardinality"
        );
        for path in self.provenance_paths() {
            validate_safe_relative_path(path)?;
        }
        for (index, public) in self.expected.executions.iter().enumerate() {
            let retained = self.retained_execution(index)?;
            ensure!(
                retained.execution_id == public.execution_id
                    && pathless_identity_allow_empty(&retained.base)? == public.base
                    && pathless_identity(&retained.materialization_identity_jcs)?
                        == public.materialization_identity
                    && pathless_identity(&retained.negative_input_jcs)? == public.negative_input
                    && pathless_identity_allow_empty(&retained.subject)? == public.subject
                    && retained
                        .contexts
                        .iter()
                        .map(|bytes| pathless_identity(bytes))
                        .collect::<Result<Vec<_>>>()?
                        == public.contexts,
                "opaque negative materialization authority retained bytes that differ from its public projection at index {index}"
            );
            Eip0045B4MaterializationIdentityV1::from_canonical_jcs(
                &retained.materialization_identity_jcs,
            )?;
            Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(&retained.negative_input_jcs)?;
        }
        Ok(())
    }
}

#[cfg(feature = "positive-gate")]
impl B4NegativeMaterializationSetAuthorityV2 {
    /// Close the descriptor-rooted cryptographic materialization path from the
    /// exact V2 positive, ancestry-publication, and terminal-import authorities.
    ///
    /// The alternate-root callback is invoked exactly once after V2 top-level
    /// authentication and receives only the fixed authority-derived request.
    ///
    /// # Errors
    ///
    /// Returns the first lineage, descriptor, source, proof, producer-coverage,
    /// or final byte-revalidation defect.
    #[doc(hidden)]
    #[cfg(all(feature = "negative-materialization-set", target_os = "linux"))]
    pub fn from_descriptor_rooted_cryptographic_closure_v2<P>(
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV2,
        ancestry: &B4NegativeAncestryWitnessCatalogAuthorityV2,
        ancestry_root: std::os::fd::BorrowedFd<'_>,
        terminal: &B4TerminalEvidenceImportAuthorityV2,
        external: &B4NegativeMaterializationSetExternalInputsV1<'_>,
        provider: P,
    ) -> Result<Self>
    where
        P: FnOnce(
            &B4FixedAlternateRootProofRequestV1,
        ) -> Result<B4GeneratedAlternateRootProofBundleV1>,
    {
        terminal
            .verify_authority_bindings(campaign, positive)
            .context("V2 terminal import differs from materialization authorities")?;
        let prior =
            B4MaterializationPriorAuthoritySnapshotV2::from_authorities(campaign, positive)?;
        ancestry.verify_prior_authority_lineage(campaign, positive)?;
        let handoff = B4AuthenticatedNegativeAncestryHandoffV2::from_directory_descriptor(
            ancestry_root,
            ancestry,
        )?;
        let mut paths = B4PhysicalPathClosureV2::from_prior(&prior)?;
        for (path, bytes) in handoff.read_set.ordered_files() {
            paths.storage_mut().bind_publication_source(
                path,
                bytes,
                "V2 negative-ancestry publication",
            )?;
        }
        let top_level = authenticate_top_level_v2(&prior, positive, external, &mut paths)?;
        ensure_top_level_snapshot_unchanged_v2(&top_level, external)?;

        let resolver = B4MaterializationFixtureSourceResolverV2::from_authenticated(&top_level)
            .context("V2 alternate-root request cannot authenticate fixture sources")?;
        let input = resolver
            .positive_input()
            .context("V2 alternate-root request cannot authenticate the positive input")?;
        let statement = resolver
            .case_zero_reference_statement()
            .context("V2 alternate-root request cannot authenticate the global statement")?;
        let request = B4FixedAlternateRootProofRequestV1::from_authenticated(
            statement.statement_bytes(),
            input.guest_elf(),
        )?;
        let bundle = provider(&request).context("V2 fixed alternate-root provider failed")?;
        let alternate = authenticate_fixed_alternate_root_bundle(&request, bundle)
            .context("V2 fixed alternate-root proof bundle failed cryptographic replay")?;
        let crypto = B4DirectSealCheckpointMutationAuthorityV2::from_authenticated(&top_level)
            .context("V2 direct-seal checkpoint mutation authority failed")?;

        let authority = close_authenticated_negative_ancestry_handoff_core_v2(
            &prior,
            ancestry,
            &handoff,
            &top_level,
            external.executions,
            &mut paths,
            &DescriptorRootedCryptographicRowProducerV2 {
                terminal,
                read_set: &handoff.read_set,
                alternate: &alternate,
                crypto: &crypto,
            },
        )?;
        terminal
            .verify_authority_bindings(campaign, positive)
            .context("V2 terminal import changed during materialization closure")?;
        authenticate_published_b4_negative_ancestry_read_set_from_directory_descriptor_v2(
            ancestry_root,
            ancestry,
        )
        .context("V2 negative-ancestry publication changed during materialization closure")?;
        ensure_top_level_snapshot_unchanged_v2(&top_level, external)?;
        Ok(authority)
    }

    /// Compare candidate V1 wire bytes with this V2-rooted authority.
    pub fn verify_candidate_jcs(&self, candidate_jcs: &[u8]) -> Result<()> {
        let parsed = Eip0045B4NegativeMaterializationSetV1::from_canonical_jcs(candidate_jcs)?;
        ensure!(
            parsed == self.expected && candidate_jcs == self.canonical_jcs,
            "candidate negative materialization set differs from the V2-rooted authority"
        );
        Ok(())
    }

    /// Exact canonical V1 wire bytes prescribed by this V2 authority.
    #[must_use]
    pub fn canonical_materialization_set_jcs(&self) -> &[u8] {
        &self.canonical_jcs
    }

    /// Exact public V1 wire projection prescribed by this V2 authority.
    #[must_use]
    pub const fn materialization_set(&self) -> &Eip0045B4NegativeMaterializationSetV1 {
        &self.expected
    }

    pub(crate) fn provenance_paths(&self) -> &BTreeSet<String> {
        &self.provenance_paths
    }

    pub(crate) fn retained_execution(
        &self,
        execution_index: usize,
    ) -> Result<&B4RetainedNegativeMaterializationExecutionV1> {
        let execution = self
            .executions
            .get(execution_index)
            .context("V2 negative materialization execution index is outside the authority")?;
        ensure!(
            usize::from(execution.execution_index) == execution_index,
            "retained V2 negative materialization execution index drift"
        );
        Ok(execution)
    }

    fn validate_retained_closure(&self) -> Result<()> {
        ensure!(
            self.executions.len() == B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT
                && self.executions.len() == self.expected.executions.len(),
            "V2 materialization authority retained the wrong execution cardinality"
        );
        for path in self.provenance_paths() {
            validate_safe_relative_path(path)?;
        }
        for (index, public) in self.expected.executions.iter().enumerate() {
            let retained = self.retained_execution(index)?;
            ensure!(
                retained.execution_id == public.execution_id
                    && pathless_identity_allow_empty(&retained.base)? == public.base
                    && pathless_identity(&retained.materialization_identity_jcs)?
                        == public.materialization_identity
                    && pathless_identity(&retained.negative_input_jcs)? == public.negative_input
                    && pathless_identity_allow_empty(&retained.subject)? == public.subject
                    && retained
                        .contexts
                        .iter()
                        .map(|bytes| pathless_identity(bytes))
                        .collect::<Result<Vec<_>>>()?
                        == public.contexts,
                "V2 retained execution bytes differ from public wire at index {index}"
            );
            Eip0045B4MaterializationIdentityV1::from_canonical_jcs(
                &retained.materialization_identity_jcs,
            )?;
            Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(&retained.negative_input_jcs)?;
        }
        Ok(())
    }
}

#[cfg(feature = "positive-gate")]
#[derive(Clone, Debug)]
struct B4MaterializationPriorAuthoritySnapshotV1 {
    campaign_precommit_jcs: Vec<u8>,
    positive_input_set: B4ContractArtifactIdentityV1,
    positive_generation_set: B4ContractArtifactIdentityV1,
    negative_plan: B4ContractArtifactIdentityV1,
    negative_plan_jcs: Vec<u8>,
    generator: B4ContractArtifactIdentityV1,
    rust_verifier: B4ContractArtifactIdentityV1,
    jvm_verifier: B4ContractArtifactIdentityV1,
    positive_cases: Vec<B4PositiveExportMeasurementsV1>,
    provenance_paths: BTreeSet<String>,
    provenance_sha256: BTreeMap<String, String>,
}

#[cfg(feature = "positive-gate")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct B4PositiveExportMeasurementsV1 {
    case_index: u8,
    proof_output_manifest: FileMeasurement,
    raw_seal: FileMeasurement,
}

#[cfg(feature = "positive-gate")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct B4PositiveExportMeasurementsV2 {
    case_index: u8,
    proof_output_manifest: FileMeasurement,
    raw_seal: FileMeasurement,
}

#[cfg(feature = "positive-gate")]
struct B4MaterializationPriorAuthoritySnapshotV2 {
    campaign_precommit_jcs: Vec<u8>,
    positive_input_set: B4ContractArtifactIdentityV1,
    positive_generation_set: B4ContractArtifactIdentityV1,
    negative_plan: B4ContractArtifactIdentityV1,
    negative_plan_jcs: Vec<u8>,
    generator: B4ContractArtifactIdentityV1,
    rust_verifier: B4ContractArtifactIdentityV1,
    jvm_verifier: B4ContractArtifactIdentityV1,
    positive_cases: [B4PositiveExportMeasurementsV2; 11],
    provenance_paths: BTreeSet<String>,
    provenance_sha256: BTreeMap<String, String>,
}

#[cfg(feature = "positive-gate")]
impl B4MaterializationPriorAuthoritySnapshotV1 {
    #[allow(clippy::too_many_lines)]
    fn from_authorities(
        campaign_precommit: &B4CampaignPrecommitAuthorityV1,
        positive_generation: &B4PositiveGenerationAuthorityV1,
    ) -> Result<Self> {
        ensure!(
            campaign_precommit.precommit().input_set == *positive_generation.input_set(),
            "campaign precommit and positive generation authority bind different input sets"
        );
        let verifier_authority = campaign_precommit.verifier_authority();
        let negative_plan = verifier_authority.contract().negative_plan.clone();
        let negative_plan_jcs = verifier_authority.negative_plan_jcs().to_vec();
        ensure!(
            B4ContractArtifactIdentityV1::from_bytes(
                negative_plan.path.clone(),
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &negative_plan_jcs,
            )? == negative_plan,
            "campaign precommit retained negative-plan bytes differ from its identity"
        );
        ensure!(
            Eip0045B4NegativePlanV1::from_canonical_jcs(&negative_plan_jcs)?
                == Eip0045B4NegativePlanV1::canonical()?,
            "campaign precommit retained a noncanonical closed negative plan"
        );

        let mut provenance_paths = campaign_precommit.artifact_paths().clone();
        merge_prior_authority_paths(
            &mut provenance_paths,
            positive_generation.provenance_paths(),
        )?;
        let mut provenance_sha256 = positive_generation.provenance_sha256().clone();
        let precommit = campaign_precommit.precommit();
        for identity in [
            &precommit.input_set,
            &precommit.campaign_executor.artifact,
            &precommit.campaign_executor.reviewed_source.archive,
            &precommit.campaign_executor.build_descriptor,
            &precommit.executor_contract,
            &precommit.verifier_contract,
            &precommit.expectation_set,
            &precommit.jvm_copy_only_inclusion_manifest,
            positive_generation.input_set(),
            positive_generation.generation_set(),
            &verifier_authority.contract().cli_spec,
            &verifier_authority.contract().negative_plan,
            &verifier_authority.contract().expectation_set,
        ]
        .into_iter()
        .chain(precommit.validators.iter().flat_map(|validator| {
            [
                &validator.build_descriptor,
                &validator.artifact,
                &validator.reviewed_source.archive,
            ]
        }))
        .chain(
            precommit
                .runner_profiles
                .iter()
                .map(|identity| &identity.artifact),
        )
        .chain(
            precommit
                .seccomp_documents
                .iter()
                .map(|identity| &identity.artifact),
        )
        .chain(
            verifier_authority
                .contract()
                .schema_identities
                .iter()
                .map(|identity| &identity.artifact),
        ) {
            insert_prior_identity(&mut provenance_sha256, identity)?;
        }
        let positive_cases = positive_generation
            .cases()
            .iter()
            .map(
                |case: &B4PositiveGenerationCaseAuthorityV1| B4PositiveExportMeasurementsV1 {
                    case_index: case.case_index(),
                    proof_output_manifest: case.proof_output_manifest(),
                    raw_seal: case.raw_seal(),
                },
            )
            .collect();
        let rust_verifier = precommit
            .validators
            .first()
            .context("campaign precommit lacks the Rust validator")?
            .artifact
            .clone();
        let jvm_verifier = precommit
            .validators
            .get(1)
            .context("campaign precommit lacks the JVM validator")?
            .artifact
            .clone();
        ensure!(
            provenance_paths.iter().eq(provenance_sha256.keys()),
            "prior authority path/digest closure is incomplete"
        );

        Ok(Self {
            campaign_precommit_jcs: campaign_precommit.to_canonical_precommit_jcs()?,
            positive_input_set: positive_generation.input_set().clone(),
            positive_generation_set: positive_generation.generation_set().clone(),
            negative_plan,
            negative_plan_jcs,
            generator: precommit.campaign_executor.artifact.clone(),
            rust_verifier,
            jvm_verifier,
            positive_cases,
            provenance_paths,
            provenance_sha256,
        })
    }
}

#[cfg(feature = "positive-gate")]
impl B4MaterializationPriorAuthoritySnapshotV2 {
    #[allow(clippy::too_many_lines)]
    fn from_authorities(
        campaign_precommit: &B4CampaignPrecommitAuthorityV1,
        positive_generation: &B4PositiveGenerationAuthorityV2,
    ) -> Result<Self> {
        ensure!(
            campaign_precommit.precommit().input_set
                == *positive_generation.positive_input_set_identity(),
            "campaign precommit and V2 positive generation authority bind different input sets"
        );
        let verifier_authority = campaign_precommit.verifier_authority();
        let negative_plan = verifier_authority.contract().negative_plan.clone();
        let negative_plan_jcs = verifier_authority.negative_plan_jcs().to_vec();
        ensure!(
            B4ContractArtifactIdentityV1::from_bytes(
                negative_plan.path.clone(),
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &negative_plan_jcs,
            )? == negative_plan,
            "campaign precommit retained negative-plan bytes differ from its V2 snapshot identity"
        );
        ensure!(
            Eip0045B4NegativePlanV1::from_canonical_jcs(&negative_plan_jcs)?
                == Eip0045B4NegativePlanV1::canonical()?,
            "campaign precommit retained a noncanonical closed negative plan before V2 materialization"
        );

        let mut provenance_paths = campaign_precommit.artifact_paths().clone();
        merge_prior_authority_paths(
            &mut provenance_paths,
            positive_generation.provenance_paths(),
        )?;
        let mut provenance_sha256 = positive_generation
            .provenance_sha256()
            .iter()
            .map(|(path, digest)| (path.clone(), hex::encode(digest)))
            .collect::<BTreeMap<_, _>>();
        let precommit = campaign_precommit.precommit();
        for identity in [
            &precommit.input_set,
            &precommit.campaign_executor.artifact,
            &precommit.campaign_executor.reviewed_source.archive,
            &precommit.campaign_executor.build_descriptor,
            &precommit.executor_contract,
            &precommit.verifier_contract,
            &precommit.expectation_set,
            &precommit.jvm_copy_only_inclusion_manifest,
            positive_generation.positive_input_set_identity(),
            positive_generation.positive_generation_set_identity(),
            &verifier_authority.contract().cli_spec,
            &verifier_authority.contract().negative_plan,
            &verifier_authority.contract().expectation_set,
        ]
        .into_iter()
        .chain(precommit.validators.iter().flat_map(|validator| {
            [
                &validator.build_descriptor,
                &validator.artifact,
                &validator.reviewed_source.archive,
            ]
        }))
        .chain(
            precommit
                .runner_profiles
                .iter()
                .map(|identity| &identity.artifact),
        )
        .chain(
            precommit
                .seccomp_documents
                .iter()
                .map(|identity| &identity.artifact),
        )
        .chain(
            verifier_authority
                .contract()
                .schema_identities
                .iter()
                .map(|identity| &identity.artifact),
        ) {
            insert_prior_identity(&mut provenance_sha256, identity)?;
        }
        let positive_cases = (0..11)
            .map(|case_index| {
                let measurements = positive_generation
                    .case_materialization_measurements(case_index)
                    .with_context(|| {
                        format!("V2 positive generation lacks materialization case {case_index}")
                    })?;
                Ok(B4PositiveExportMeasurementsV2 {
                    case_index: u8::try_from(case_index)?,
                    proof_output_manifest: measurements.proof_output_manifest(),
                    raw_seal: measurements.raw_seal(),
                })
            })
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|cases: Vec<_>| {
                anyhow::anyhow!(
                    "V2 positive materialization snapshot has {} cases",
                    cases.len()
                )
            })?;
        let rust_verifier = precommit
            .validators
            .first()
            .context("campaign precommit lacks the Rust validator")?
            .artifact
            .clone();
        let jvm_verifier = precommit
            .validators
            .get(1)
            .context("campaign precommit lacks the JVM validator")?
            .artifact
            .clone();
        ensure!(
            provenance_paths.iter().eq(provenance_sha256.keys()),
            "V2 prior authority path/digest closure is incomplete"
        );

        Ok(Self {
            campaign_precommit_jcs: campaign_precommit.to_canonical_precommit_jcs()?,
            positive_input_set: positive_generation.positive_input_set_identity().clone(),
            positive_generation_set: positive_generation
                .positive_generation_set_identity()
                .clone(),
            negative_plan,
            negative_plan_jcs,
            generator: precommit.campaign_executor.artifact.clone(),
            rust_verifier,
            jvm_verifier,
            positive_cases,
            provenance_paths,
            provenance_sha256,
        })
    }
}

#[cfg(feature = "positive-gate")]
fn insert_prior_identity(
    identities: &mut BTreeMap<String, String>,
    identity: &B4ContractArtifactIdentityV1,
) -> Result<()> {
    if let Some(previous) = identities.insert(identity.path.clone(), identity.sha256.clone()) {
        ensure!(
            previous == identity.sha256,
            "prior authorities bind different bytes to the same physical path"
        );
    }
    Ok(())
}

#[cfg(feature = "positive-gate")]
#[derive(Clone, Debug)]
pub(crate) struct B4AuthenticatedPositiveInputSourcesV1 {
    pub(crate) profile_id: String,
    pub(crate) profile_manifest: B4ContractArtifactIdentityV1,
    pub(crate) profile_algorithm: B4ContractArtifactIdentityV1,
    pub(crate) profile_constants: B4ContractArtifactIdentityV1,
    pub(crate) guest_elf: B4ContractArtifactIdentityV1,
    pub(crate) guest_image_id: String,
    reference_statement_manifest: B4ContractArtifactIdentityV1,
    reference_contract_id: String,
    reference_statement_byte_length: u64,
    reference_statement_sha256: String,
    reference_chain_domain_id: String,
    reference_application_payload_byte_length: u64,
    reference_application_payload_sha256: String,
    source_lock: B4ContractArtifactIdentityV1,
    generator: B4ContractArtifactIdentityV1,
    artifacts: BTreeMap<String, B4ContractArtifactIdentityV1>,
}

#[cfg(feature = "positive-gate")]
impl B4AuthenticatedPositiveInputSourcesV1 {
    pub(crate) const fn guest_elf_identity(&self) -> &B4ContractArtifactIdentityV1 {
        &self.guest_elf
    }

    pub(crate) fn guest_image_id_hex(&self) -> &str {
        &self.guest_image_id
    }

    pub(crate) const fn generator_identity(&self) -> &B4ContractArtifactIdentityV1 {
        &self.generator
    }

    /// Reference statement-bundle manifest identity retained from the
    /// positive-input authority.
    pub(crate) const fn reference_statement_manifest(&self) -> &B4ContractArtifactIdentityV1 {
        &self.reference_statement_manifest
    }

    /// Reference contract ID already parsed and digest-shaped by the
    /// positive-input authority.
    pub(crate) fn reference_contract_id(&self) -> &str {
        &self.reference_contract_id
    }

    /// Exact reference-statement byte length declared by the positive input.
    pub(crate) const fn reference_statement_byte_length(&self) -> u64 {
        self.reference_statement_byte_length
    }

    /// Reference statement SHA-256 already parsed and digest-shaped by the
    /// positive-input authority.
    pub(crate) fn reference_statement_sha256(&self) -> &str {
        &self.reference_statement_sha256
    }

    /// Chain-domain ID declared for the reference statement.
    pub(crate) fn reference_chain_domain_id(&self) -> &str {
        &self.reference_chain_domain_id
    }

    /// Exact reference application-payload byte length.
    pub(crate) const fn reference_application_payload_byte_length(&self) -> u64 {
        self.reference_application_payload_byte_length
    }

    /// SHA-256 of the exact reference application payload.
    pub(crate) fn reference_application_payload_sha256(&self) -> &str {
        &self.reference_application_payload_sha256
    }
}

#[cfg(feature = "positive-gate")]
#[derive(Clone, Debug)]
pub(crate) struct B4AuthenticatedPositiveInputSourcesV2 {
    pub(crate) profile_id: String,
    pub(crate) profile_manifest: B4ContractArtifactIdentityV1,
    pub(crate) profile_algorithm: B4ContractArtifactIdentityV1,
    pub(crate) profile_constants: B4ContractArtifactIdentityV1,
    pub(crate) guest_elf: B4ContractArtifactIdentityV1,
    pub(crate) guest_image_id: String,
    reference_statement_manifest: B4ContractArtifactIdentityV1,
    reference_contract_id: String,
    reference_statement_byte_length: u64,
    reference_statement_sha256: String,
    reference_chain_domain_id: String,
    reference_application_payload_byte_length: u64,
    reference_application_payload_sha256: String,
    pub(crate) source_lock: B4ContractArtifactIdentityV1,
    pub(crate) generator: B4ContractArtifactIdentityV1,
    pub(crate) artifacts: BTreeMap<String, B4ContractArtifactIdentityV1>,
}

#[cfg(feature = "positive-gate")]
impl B4AuthenticatedPositiveInputSourcesV2 {
    pub(crate) const fn reference_statement_manifest(&self) -> &B4ContractArtifactIdentityV1 {
        &self.reference_statement_manifest
    }

    pub(crate) fn reference_contract_id(&self) -> &str {
        &self.reference_contract_id
    }

    pub(crate) const fn reference_statement_byte_length(&self) -> u64 {
        self.reference_statement_byte_length
    }

    pub(crate) fn reference_statement_sha256(&self) -> &str {
        &self.reference_statement_sha256
    }

    pub(crate) fn reference_chain_domain_id(&self) -> &str {
        &self.reference_chain_domain_id
    }

    pub(crate) const fn reference_application_payload_byte_length(&self) -> u64 {
        self.reference_application_payload_byte_length
    }

    pub(crate) fn reference_application_payload_sha256(&self) -> &str {
        &self.reference_application_payload_sha256
    }
}

#[cfg(feature = "positive-gate")]
fn merge_prior_authority_paths(
    paths: &mut BTreeSet<String>,
    additional: &BTreeSet<String>,
) -> Result<()> {
    for path in additional {
        validate_safe_relative_path(path)?;
        if paths.contains(path) {
            continue;
        }
        ensure!(
            !paths
                .iter()
                .any(|existing| b4_paths_conflict(existing, path)),
            "prior authority paths form an ancestor/descendant conflict"
        );
        paths.insert(path.clone());
    }
    Ok(())
}

#[cfg(feature = "positive-gate")]
#[derive(Clone, Debug)]
pub(crate) struct B4ClosedReconstructedExecutionV1 {
    pub(crate) derived_registry_row: B4NegativeCase,
    pub(crate) base: Vec<u8>,
    pub(crate) materialization_identity_jcs: Vec<u8>,
    pub(crate) negative_input_jcs: Vec<u8>,
    pub(crate) subject: Vec<u8>,
    pub(crate) contexts: Vec<Vec<u8>>,
}

#[cfg(feature = "positive-gate")]
trait B4ClosedMaterializationRowProducerV1 {
    fn reconstruct(
        &self,
        execution_index: usize,
        planned: &B4NegativePlanExecutionV1,
        top_level: &B4AuthenticatedMaterializationTopLevelV1,
    ) -> Result<Option<B4ClosedReconstructedExecutionV1>>;

    fn terminal_evidence_document_identities(
        &self,
    ) -> Option<B4TerminalEvidenceDocumentIdentitiesV1> {
        None
    }
}

#[cfg(feature = "positive-gate")]
trait B4ClosedMaterializationRowProducerV2 {
    fn reconstruct(
        &self,
        execution_index: usize,
        planned: &B4NegativePlanExecutionV1,
        top_level: &B4AuthenticatedMaterializationTopLevelV2,
    ) -> Result<Option<B4ClosedReconstructedExecutionV1>>;

    fn terminal_evidence_document_identities(
        &self,
    ) -> Option<B4TerminalEvidenceDocumentIdentitiesV1> {
        None
    }
}

#[cfg(feature = "positive-gate")]
struct B4TerminalEvidenceDocumentIdentitiesV1 {
    packet_manifest: B4NegativeMaterializationByteIdentityV1,
    campaign_receipt: B4NegativeMaterializationByteIdentityV1,
}

#[cfg(feature = "positive-gate")]
struct C1ProductionRowProducer;

#[cfg(feature = "positive-gate")]
impl B4ClosedMaterializationRowProducerV1 for C1ProductionRowProducer {
    fn reconstruct(
        &self,
        execution_index: usize,
        planned: &B4NegativePlanExecutionV1,
        top_level: &B4AuthenticatedMaterializationTopLevelV1,
    ) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
        match execution_index {
            C1_TREE_FIRST_INDEX..C1_REGISTRY_FIRST_INDEX => {
                reconstruct_c1_tree_execution(execution_index, planned, top_level).map(Some)
            }
            C1_REGISTRY_FIRST_INDEX..C1_END_INDEX_EXCLUSIVE => {
                reconstruct_c1_registry_execution(execution_index, planned, top_level).map(Some)
            }
            _ => Ok(None),
        }
    }
}

/// Composite production dispatcher for every deterministic row closed by C1
/// and C2. Receipt-, instrumentation-, alternate-root-, and new-proof-gated
/// rows deliberately continue to return `None`.
#[cfg(feature = "positive-gate")]
struct ProductionRowProducer;

#[cfg(feature = "positive-gate")]
impl B4ClosedMaterializationRowProducerV1 for ProductionRowProducer {
    fn reconstruct(
        &self,
        execution_index: usize,
        planned: &B4NegativePlanExecutionV1,
        top_level: &B4AuthenticatedMaterializationTopLevelV1,
    ) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
        if let Some(reconstructed) =
            crate::b4_c2_raw::reconstruct_raw_execution(execution_index, planned, top_level)?
        {
            return Ok(Some(reconstructed));
        }
        if let Some(reconstructed) =
            crate::b4_c2_parser::reconstruct_parser_execution(execution_index, planned, top_level)?
        {
            return Ok(Some(reconstructed));
        }
        if let Some(reconstructed) =
            crate::b4_c2_opcode_sequence::reconstruct_opcode_sequence_execution(
                execution_index,
                planned,
                top_level,
            )?
        {
            return Ok(Some(reconstructed));
        }
        if let Some(reconstructed) = crate::b4_c2_terminal::reconstruct_terminal_execution(
            execution_index,
            planned,
            top_level,
        )? {
            return Ok(Some(reconstructed));
        }
        if let Some(reconstructed) = crate::b4_c2_profile::reconstruct_profile_execution(
            execution_index,
            planned,
            top_level,
        )? {
            return Ok(Some(reconstructed));
        }
        C1ProductionRowProducer.reconstruct(execution_index, planned, top_level)
    }
}

/// Narrow bridge for deterministic producers whose implementations consume
/// only bytes already retained by the authenticated top-level wrapper. These
/// four producer families neither construct a fixture resolver nor select an
/// authority generation. All resolver-bearing and authority-bearing V2 rows
/// remain outside this bridge and must use their dedicated V2 entrypoints.
#[cfg(feature = "positive-gate")]
struct V2AuthenticatedVersionNeutralDeterministicRowAdapter;

#[cfg(feature = "positive-gate")]
impl B4ClosedMaterializationRowProducerV2 for V2AuthenticatedVersionNeutralDeterministicRowAdapter {
    fn reconstruct(
        &self,
        execution_index: usize,
        planned: &B4NegativePlanExecutionV1,
        top_level: &B4AuthenticatedMaterializationTopLevelV2,
    ) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
        let authenticated_bytes = top_level.storage();
        if let Some(reconstructed) =
            crate::b4_c2_opcode_sequence::reconstruct_opcode_sequence_execution(
                execution_index,
                planned,
                authenticated_bytes,
            )?
        {
            return Ok(Some(reconstructed));
        }
        if let Some(reconstructed) = crate::b4_c2_terminal::reconstruct_terminal_execution(
            execution_index,
            planned,
            authenticated_bytes,
        )? {
            return Ok(Some(reconstructed));
        }
        if let Some(reconstructed) = crate::b4_c2_profile::reconstruct_profile_execution(
            execution_index,
            planned,
            authenticated_bytes,
        )? {
            return Ok(Some(reconstructed));
        }
        C1ProductionRowProducer.reconstruct(execution_index, planned, authenticated_bytes)
    }
}

/// V2 dispatcher for deterministic rows. Resolver-bearing raw and parser rows
/// stay on their V2 entrypoints; only the explicitly audited byte-only seam
/// above may borrow the wrapper's retained storage.
#[cfg(feature = "positive-gate")]
struct ProductionRowProducerV2;

#[cfg(feature = "positive-gate")]
impl B4ClosedMaterializationRowProducerV2 for ProductionRowProducerV2 {
    fn reconstruct(
        &self,
        execution_index: usize,
        planned: &B4NegativePlanExecutionV1,
        top_level: &B4AuthenticatedMaterializationTopLevelV2,
    ) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
        if let Some(reconstructed) =
            crate::b4_c2_raw::reconstruct_raw_execution_v2(execution_index, planned, top_level)?
        {
            return Ok(Some(reconstructed));
        }
        if let Some(reconstructed) = crate::b4_c2_parser::reconstruct_parser_execution_v2(
            execution_index,
            planned,
            top_level,
        )? {
            return Ok(Some(reconstructed));
        }
        V2AuthenticatedVersionNeutralDeterministicRowAdapter.reconstruct(
            execution_index,
            planned,
            top_level,
        )
    }
}

#[cfg(all(
    feature = "negative-materialization-set",
    any(target_os = "linux", test)
))]
struct TerminalAwareProductionRowProducer<'authority> {
    terminal: &'authority B4TerminalEvidenceImportAuthorityV1,
}

#[cfg(all(
    feature = "negative-materialization-set",
    any(target_os = "linux", test)
))]
impl B4ClosedMaterializationRowProducerV1 for TerminalAwareProductionRowProducer<'_> {
    fn reconstruct(
        &self,
        execution_index: usize,
        planned: &B4NegativePlanExecutionV1,
        top_level: &B4AuthenticatedMaterializationTopLevelV1,
    ) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
        if let Some(reconstructed) =
            ProductionRowProducer.reconstruct(execution_index, planned, top_level)?
        {
            return Ok(Some(reconstructed));
        }
        if let Some(reconstructed) =
            crate::b4_c2_terminal_catalog::reconstruct_terminal_catalog_execution(
                execution_index,
                planned,
                &top_level.negative_plan,
                self.terminal,
            )?
        {
            return Ok(Some(reconstructed));
        }
        if let Some(reconstructed) =
            crate::b4_c2_terminal_metadata::reconstruct_terminal_metadata_execution_from_import(
                execution_index,
                planned,
                &top_level.negative_plan,
                self.terminal,
            )?
        {
            return Ok(Some(reconstructed));
        }
        crate::b4_c2_terminal_fixture::reconstruct_terminal_fixture_execution(
            execution_index,
            planned,
            &top_level.negative_plan,
            self.terminal,
        )
    }

    fn terminal_evidence_document_identities(
        &self,
    ) -> Option<B4TerminalEvidenceDocumentIdentitiesV1> {
        let projection = self.terminal.terminal_materialization_projection();
        let packet_manifest = projection.terminal_evidence_packet_manifest_identity();
        let campaign_receipt = projection.terminal_evidence_campaign_receipt_identity();
        Some(B4TerminalEvidenceDocumentIdentitiesV1 {
            packet_manifest: B4NegativeMaterializationByteIdentityV1 {
                byte_length: packet_manifest.byte_length(),
                sha256: packet_manifest.sha256().to_owned(),
            },
            campaign_receipt: B4NegativeMaterializationByteIdentityV1 {
                byte_length: campaign_receipt.byte_length(),
                sha256: campaign_receipt.sha256().to_owned(),
            },
        })
    }
}

/// Concrete V2 consumer for the fifteen fixed terminal materialization rows.
///
/// This producer is intentionally a sibling of the preserved V1 producer. It
/// accepts only the affine V2 terminal import, carries no selector or detached
/// bytes, and performs no V2-to-V1 authority conversion. The row modules borrow
/// their exact source projection directly from the V2 import.
#[cfg(all(
    feature = "negative-materialization-set",
    any(target_os = "linux", test)
))]
struct TerminalAwareProductionRowProducerV2<'authority> {
    terminal: &'authority B4TerminalEvidenceImportAuthorityV2,
}

#[cfg(all(
    feature = "negative-materialization-set",
    any(target_os = "linux", test)
))]
impl B4ClosedMaterializationRowProducerV2 for TerminalAwareProductionRowProducerV2<'_> {
    fn reconstruct(
        &self,
        execution_index: usize,
        planned: &B4NegativePlanExecutionV1,
        top_level: &B4AuthenticatedMaterializationTopLevelV2,
    ) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
        if let Some(reconstructed) =
            ProductionRowProducerV2.reconstruct(execution_index, planned, top_level)?
        {
            return Ok(Some(reconstructed));
        }
        let resolver = crate::b4_fixture_sources::B4MaterializationFixtureSourceResolverV2::
            from_authenticated(top_level)
            .context("V2 terminal producer cannot authenticate fixture sources")?;
        let negative_plan_jcs = resolver.negative_plan_jcs();
        if let Some(reconstructed) =
            crate::b4_c2_terminal_catalog::reconstruct_terminal_catalog_execution_v2(
                execution_index,
                planned,
                negative_plan_jcs,
                self.terminal,
            )?
        {
            return Ok(Some(reconstructed));
        }
        if let Some(reconstructed) =
            crate::b4_c2_terminal_metadata::reconstruct_terminal_metadata_execution_from_import_v2(
                execution_index,
                planned,
                negative_plan_jcs,
                self.terminal,
            )?
        {
            return Ok(Some(reconstructed));
        }
        crate::b4_c2_terminal_fixture::reconstruct_terminal_fixture_execution_v2(
            execution_index,
            planned,
            negative_plan_jcs,
            self.terminal,
        )
    }

    fn terminal_evidence_document_identities(
        &self,
    ) -> Option<B4TerminalEvidenceDocumentIdentitiesV1> {
        let projection = self.terminal.terminal_materialization_projection_v2();
        let packet_manifest = projection.terminal_evidence_packet_manifest_identity();
        let campaign_receipt = projection.terminal_evidence_campaign_receipt_identity();
        Some(B4TerminalEvidenceDocumentIdentitiesV1 {
            packet_manifest: B4NegativeMaterializationByteIdentityV1 {
                byte_length: packet_manifest.byte_length(),
                sha256: packet_manifest.sha256().to_owned(),
            },
            campaign_receipt: B4NegativeMaterializationByteIdentityV1 {
                byte_length: campaign_receipt.byte_length(),
                sha256: campaign_receipt.sha256().to_owned(),
            },
        })
    }
}

#[cfg(all(
    feature = "negative-materialization-set",
    any(target_os = "linux", test)
))]
struct DescriptorRootedStrongInferenceRowProducer<'authority> {
    terminal: &'authority B4TerminalEvidenceImportAuthorityV1,
    read_set: &'authority B4NegativeAncestryPublicationReadSetV1,
}

#[cfg(all(
    feature = "negative-materialization-set",
    any(target_os = "linux", test)
))]
impl B4ClosedMaterializationRowProducerV1 for DescriptorRootedStrongInferenceRowProducer<'_> {
    fn reconstruct(
        &self,
        execution_index: usize,
        planned: &B4NegativePlanExecutionV1,
        top_level: &B4AuthenticatedMaterializationTopLevelV1,
    ) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
        if let Some(reconstructed) = (TerminalAwareProductionRowProducer {
            terminal: self.terminal,
        })
        .reconstruct(execution_index, planned, top_level)?
        {
            return Ok(Some(reconstructed));
        }
        if let Some(reconstructed) =
            crate::b4_c2_receipt_claim::reconstruct_receipt_claim_execution(
                execution_index,
                planned,
                top_level,
            )?
        {
            return Ok(Some(reconstructed));
        }
        if let Some(reconstructed) =
            crate::b4_c2_negative_ancestry_witness::reconstruct_negative_ancestry_witness_execution(
                execution_index,
                planned,
                top_level,
                self.read_set,
            )?
        {
            return Ok(Some(reconstructed));
        }
        crate::b4_c2_ancestry::reconstruct_ancestry_execution(execution_index, planned, top_level)
    }

    fn terminal_evidence_document_identities(
        &self,
    ) -> Option<B4TerminalEvidenceDocumentIdentitiesV1> {
        (TerminalAwareProductionRowProducer {
            terminal: self.terminal,
        })
        .terminal_evidence_document_identities()
    }
}

#[cfg(all(
    feature = "negative-materialization-set",
    any(target_os = "linux", test)
))]
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "the composite producer is exercised by the Linux descriptor-rooted E6 constructor; Windows tests cover its disjoint row producer directly"
    )
)]
struct DescriptorRootedAlternateRootRowProducer<'authority> {
    terminal: &'authority B4TerminalEvidenceImportAuthorityV1,
    read_set: &'authority B4NegativeAncestryPublicationReadSetV1,
    alternate: &'authority B4FixedAlternateRootProofAuthorityV1,
}

#[cfg(all(
    feature = "negative-materialization-set",
    any(target_os = "linux", test)
))]
impl B4ClosedMaterializationRowProducerV1 for DescriptorRootedAlternateRootRowProducer<'_> {
    fn reconstruct(
        &self,
        execution_index: usize,
        planned: &B4NegativePlanExecutionV1,
        top_level: &B4AuthenticatedMaterializationTopLevelV1,
    ) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
        if let Some(reconstructed) = (DescriptorRootedStrongInferenceRowProducer {
            terminal: self.terminal,
            read_set: self.read_set,
        })
        .reconstruct(execution_index, planned, top_level)?
        {
            return Ok(Some(reconstructed));
        }
        crate::b4_c2_alternate_root::reconstruct_alternate_root_execution(
            execution_index,
            planned,
            top_level,
            self.alternate,
        )
    }

    fn terminal_evidence_document_identities(
        &self,
    ) -> Option<B4TerminalEvidenceDocumentIdentitiesV1> {
        (DescriptorRootedStrongInferenceRowProducer {
            terminal: self.terminal,
            read_set: self.read_set,
        })
        .terminal_evidence_document_identities()
    }
}

#[cfg(all(
    feature = "negative-materialization-set",
    any(target_os = "linux", test)
))]
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "the composite producer is exercised by the Linux descriptor-rooted E7 constructor; cross-platform tests cover its disjoint row inventory"
    )
)]
struct DescriptorRootedCryptographicRowProducer<'authority> {
    terminal: &'authority B4TerminalEvidenceImportAuthorityV1,
    read_set: &'authority B4NegativeAncestryPublicationReadSetV1,
    alternate: &'authority B4FixedAlternateRootProofAuthorityV1,
    crypto: &'authority B4DirectSealCheckpointMutationAuthorityV1,
}

#[cfg(all(
    feature = "negative-materialization-set",
    any(target_os = "linux", test)
))]
impl B4ClosedMaterializationRowProducerV1 for DescriptorRootedCryptographicRowProducer<'_> {
    fn reconstruct(
        &self,
        execution_index: usize,
        planned: &B4NegativePlanExecutionV1,
        top_level: &B4AuthenticatedMaterializationTopLevelV1,
    ) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
        if let Some(reconstructed) = (DescriptorRootedAlternateRootRowProducer {
            terminal: self.terminal,
            read_set: self.read_set,
            alternate: self.alternate,
        })
        .reconstruct(execution_index, planned, top_level)?
        {
            return Ok(Some(reconstructed));
        }
        crate::b4_c2_crypto::reconstruct_crypto_execution(
            execution_index,
            planned,
            top_level,
            self.crypto,
        )
    }

    fn terminal_evidence_document_identities(
        &self,
    ) -> Option<B4TerminalEvidenceDocumentIdentitiesV1> {
        (DescriptorRootedAlternateRootRowProducer {
            terminal: self.terminal,
            read_set: self.read_set,
            alternate: self.alternate,
        })
        .terminal_evidence_document_identities()
    }
}

#[cfg(all(
    feature = "negative-materialization-set",
    any(target_os = "linux", test)
))]
struct DescriptorRootedStrongInferenceRowProducerV2<'authority> {
    terminal: &'authority B4TerminalEvidenceImportAuthorityV2,
    read_set: &'authority B4NegativeAncestryPublicationReadSetV2,
}

#[cfg(all(
    feature = "negative-materialization-set",
    any(target_os = "linux", test)
))]
impl B4ClosedMaterializationRowProducerV2 for DescriptorRootedStrongInferenceRowProducerV2<'_> {
    fn reconstruct(
        &self,
        execution_index: usize,
        planned: &B4NegativePlanExecutionV1,
        top_level: &B4AuthenticatedMaterializationTopLevelV2,
    ) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
        if let Some(reconstructed) = (TerminalAwareProductionRowProducerV2 {
            terminal: self.terminal,
        })
        .reconstruct(execution_index, planned, top_level)?
        {
            return Ok(Some(reconstructed));
        }
        if let Some(reconstructed) =
            crate::b4_c2_receipt_claim::reconstruct_receipt_claim_execution_v2(
                execution_index,
                planned,
                top_level,
            )?
        {
            return Ok(Some(reconstructed));
        }
        if let Some(reconstructed) = crate::b4_c2_negative_ancestry_witness::
            reconstruct_negative_ancestry_witness_execution_v2(
                execution_index,
                planned,
                top_level,
                self.read_set,
            )?
        {
            return Ok(Some(reconstructed));
        }
        crate::b4_c2_ancestry::reconstruct_ancestry_execution_v2(
            execution_index,
            planned,
            top_level,
        )
    }

    fn terminal_evidence_document_identities(
        &self,
    ) -> Option<B4TerminalEvidenceDocumentIdentitiesV1> {
        (TerminalAwareProductionRowProducerV2 {
            terminal: self.terminal,
        })
        .terminal_evidence_document_identities()
    }
}

#[cfg(all(
    feature = "negative-materialization-set",
    any(target_os = "linux", test)
))]
struct DescriptorRootedAlternateRootRowProducerV2<'authority> {
    terminal: &'authority B4TerminalEvidenceImportAuthorityV2,
    read_set: &'authority B4NegativeAncestryPublicationReadSetV2,
    alternate: &'authority B4FixedAlternateRootProofAuthorityV1,
}

#[cfg(all(
    feature = "negative-materialization-set",
    any(target_os = "linux", test)
))]
impl B4ClosedMaterializationRowProducerV2 for DescriptorRootedAlternateRootRowProducerV2<'_> {
    fn reconstruct(
        &self,
        execution_index: usize,
        planned: &B4NegativePlanExecutionV1,
        top_level: &B4AuthenticatedMaterializationTopLevelV2,
    ) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
        if let Some(reconstructed) = (DescriptorRootedStrongInferenceRowProducerV2 {
            terminal: self.terminal,
            read_set: self.read_set,
        })
        .reconstruct(execution_index, planned, top_level)?
        {
            return Ok(Some(reconstructed));
        }
        crate::b4_c2_alternate_root::reconstruct_alternate_root_execution_v2(
            execution_index,
            planned,
            top_level,
            self.alternate,
        )
    }

    fn terminal_evidence_document_identities(
        &self,
    ) -> Option<B4TerminalEvidenceDocumentIdentitiesV1> {
        (DescriptorRootedStrongInferenceRowProducerV2 {
            terminal: self.terminal,
            read_set: self.read_set,
        })
        .terminal_evidence_document_identities()
    }
}

#[cfg(all(
    feature = "negative-materialization-set",
    any(target_os = "linux", test)
))]
struct DescriptorRootedCryptographicRowProducerV2<'authority> {
    terminal: &'authority B4TerminalEvidenceImportAuthorityV2,
    read_set: &'authority B4NegativeAncestryPublicationReadSetV2,
    alternate: &'authority B4FixedAlternateRootProofAuthorityV1,
    crypto: &'authority B4DirectSealCheckpointMutationAuthorityV2,
}

#[cfg(all(
    feature = "negative-materialization-set",
    any(target_os = "linux", test)
))]
impl B4ClosedMaterializationRowProducerV2 for DescriptorRootedCryptographicRowProducerV2<'_> {
    fn reconstruct(
        &self,
        execution_index: usize,
        planned: &B4NegativePlanExecutionV1,
        top_level: &B4AuthenticatedMaterializationTopLevelV2,
    ) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
        if let Some(reconstructed) = (DescriptorRootedAlternateRootRowProducerV2 {
            terminal: self.terminal,
            read_set: self.read_set,
            alternate: self.alternate,
        })
        .reconstruct(execution_index, planned, top_level)?
        {
            return Ok(Some(reconstructed));
        }
        crate::b4_c2_crypto::reconstruct_crypto_execution_v2(
            execution_index,
            planned,
            top_level,
            self.crypto,
        )
    }

    fn terminal_evidence_document_identities(
        &self,
    ) -> Option<B4TerminalEvidenceDocumentIdentitiesV1> {
        (DescriptorRootedAlternateRootRowProducerV2 {
            terminal: self.terminal,
            read_set: self.read_set,
            alternate: self.alternate,
        })
        .terminal_evidence_document_identities()
    }
}

#[cfg(all(feature = "positive-gate", test))]
struct UnavailableProductionRowProducer;

#[cfg(all(feature = "positive-gate", test))]
impl B4ClosedMaterializationRowProducerV1 for UnavailableProductionRowProducer {
    fn reconstruct(
        &self,
        _execution_index: usize,
        _planned: &B4NegativePlanExecutionV1,
        _top_level: &B4AuthenticatedMaterializationTopLevelV1,
    ) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
        // Deliberately no caller-controlled fallback. Domain producers are
        // connected here only after their physical source and replay closures
        // have independent tests.
        Ok(None)
    }
}

#[cfg(feature = "positive-gate")]
#[derive(Clone, Copy, Debug)]
struct C1RegistrySubjectReplayAdapterV1<'a> {
    raw_probe: B4RegistryProbeReplayAdapterV1<'a>,
    negative_plan_jcs: &'a [u8],
    verifier_subject: &'a [u8],
    execution_surface: B4NegativeExecutionSurface,
}

#[cfg(feature = "positive-gate")]
impl B4MaterializationReplayAdapterV1 for C1RegistrySubjectReplayAdapterV1<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::ArtifactValidator
    }

    fn base_bytes(&self) -> &[u8] {
        self.raw_probe.base
    }

    fn output_bytes(&self) -> &[u8] {
        self.verifier_subject
    }

    fn replay_recipe(
        &self,
        base_selector_id: &str,
        materialization: &crate::b4::B4NegativeMaterialization,
    ) -> Result<()> {
        self.raw_probe
            .replay_recipe(base_selector_id, materialization)?;
        ensure!(
            encode_c1_registry_subject(
                self.execution_surface,
                self.negative_plan_jcs,
                self.raw_probe.output,
            )? == self.verifier_subject,
            "C1 verifier subject differs from the independently replayed and framed registry probe"
        );
        Ok(())
    }
}

#[cfg(feature = "positive-gate")]
fn encode_c1_registry_subject(
    execution_surface: B4NegativeExecutionSurface,
    negative_plan_jcs: &[u8],
    raw_materialized_output: &[u8],
) -> Result<Vec<u8>> {
    match execution_surface {
        B4NegativeExecutionSurface::CandidateRegistry => Ok(encode_subject_envelope(
            &[raw_materialized_output],
            B4SubjectEnvelopeContract::new(
                B4SubjectEnvelopeKind::CandidateRegistryBundle,
                &C1_CANDIDATE_REGISTRY_PARTS,
            ),
        )?),
        B4NegativeExecutionSurface::NegativeBindingIndex => Ok(encode_subject_envelope(
            &[negative_plan_jcs, raw_materialized_output],
            B4SubjectEnvelopeContract::new(
                B4SubjectEnvelopeKind::NegativeBindingIndexBundle,
                &C1_NEGATIVE_BINDING_INDEX_PARTS,
            ),
        )?),
        _ => bail!("C1 registry row selects a non-registry execution surface"),
    }
}

#[cfg(feature = "positive-gate")]
fn reconstruct_c1_tree_execution(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
) -> Result<B4ClosedReconstructedExecutionV1> {
    ensure!(
        planned.materialization_domain == B4MaterializationDomain::TreeValidator
            && planned.execution_surface == B4NegativeExecutionSurface::CorpusClosure,
        "C1 tree row differs from the closed domain/surface partition"
    );
    let materialized = materialize_tree_probe(&top_level.negative_plan, &planned.execution_id)?;
    ensure!(
        materialized.base_jcs == top_level.abstract_tree_jcs,
        "C1 tree probe base differs from the authenticated abstract-tree bytes"
    );
    let raw_identity = verify_tree_probe_materialization(&materialized, &top_level.negative_plan)?;
    close_c1_execution(
        execution_index,
        planned,
        &top_level.negative_plan,
        materialized.registry_row,
        materialized.base_jcs,
        &materialized.output_jcs,
        &raw_identity,
        &raw_identity,
        materialized.output_jcs.clone(),
    )
}

#[cfg(feature = "positive-gate")]
fn reconstruct_c1_registry_execution(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
) -> Result<B4ClosedReconstructedExecutionV1> {
    ensure!(
        planned.materialization_domain == B4MaterializationDomain::ArtifactValidator,
        "C1 registry row differs from the closed materialization domain"
    );
    let materialized = materialize_registry_probe(&top_level.negative_plan, &planned.execution_id)?;
    let raw_adapter = materialized.replay_adapter();
    let raw_identity = create_materialization_identity_with_adapter(
        &top_level.negative_plan,
        &materialized.registry_row,
        &raw_adapter,
    )?;
    verify_materialization_identity_with_adapter(
        &raw_identity,
        &top_level.negative_plan,
        &materialized.registry_row,
        &raw_adapter,
    )?;

    match planned.execution_surface {
        B4NegativeExecutionSurface::CandidateRegistry => {
            ensure!(
                (C1_REGISTRY_FIRST_INDEX..C1_NEGATIVE_CASE_DUPLICATE_INDEX)
                    .contains(&execution_index)
                    || ((C1_NEGATIVE_CASE_DUPLICATE_INDEX + 1)..C1_BIJECTION_FIRST_INDEX)
                        .contains(&execution_index),
                "C1 candidate-registry row differs from the exact plan-order partition"
            );
            ensure!(
                materialized.base == synthetic_registry_skeleton_source()?,
                "C1 candidate-registry probe base differs from the compiled skeleton"
            );
        }
        B4NegativeExecutionSurface::NegativeBindingIndex => {
            ensure!(
                execution_index == C1_NEGATIVE_CASE_DUPLICATE_INDEX
                    || (C1_BIJECTION_FIRST_INDEX..C1_END_INDEX_EXCLUSIVE)
                        .contains(&execution_index),
                "C1 negative-binding-index row differs from the exact plan-order partition"
            );
            ensure!(
                materialized.base == top_level.negative_binding_index_jcs,
                "C1 negative-binding probe base differs from the authenticated index bytes"
            );
        }
        _ => bail!("C1 registry row selects a non-registry execution surface"),
    }
    let subject = encode_c1_registry_subject(
        planned.execution_surface,
        &top_level.negative_plan,
        &materialized.output,
    )?;
    let subject_adapter = C1RegistrySubjectReplayAdapterV1 {
        raw_probe: raw_adapter,
        negative_plan_jcs: &top_level.negative_plan,
        verifier_subject: &subject,
        execution_surface: planned.execution_surface,
    };
    let final_identity = create_materialization_identity_with_adapter(
        &top_level.negative_plan,
        &materialized.registry_row,
        &subject_adapter,
    )?;
    verify_materialization_identity_with_adapter(
        &final_identity,
        &top_level.negative_plan,
        &materialized.registry_row,
        &subject_adapter,
    )?;

    close_c1_execution(
        execution_index,
        planned,
        &top_level.negative_plan,
        materialized.registry_row,
        materialized.base,
        &materialized.output,
        &raw_identity,
        &final_identity,
        subject,
    )
}

#[cfg(feature = "positive-gate")]
#[allow(clippy::too_many_arguments)]
fn close_c1_execution(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    registry_row: B4NegativeCase,
    base: Vec<u8>,
    raw_materialized_output: &[u8],
    raw_identity: &Eip0045B4MaterializationIdentityV1,
    final_identity: &Eip0045B4MaterializationIdentityV1,
    verifier_subject: Vec<u8>,
) -> Result<B4ClosedReconstructedExecutionV1> {
    ensure!(
        registry_row.execution_id == planned.execution_id
            && registry_row.base_selector_id == planned.base_selector_id
            && registry_row.materialization_domain == planned.materialization_domain,
        "C1 producer-derived registry row differs from the canonical plan"
    );
    let recipe_jcs = canonical_materialization_recipe_jcs(&registry_row.materialization)?;
    ensure!(
        raw_identity.execution_id == planned.execution_id
            && raw_identity.base_selector_id == planned.base_selector_id
            && raw_identity.materialization_domain == planned.materialization_domain
            && raw_identity.base_byte_length == u64::try_from(base.len())?
            && raw_identity.base_sha256 == sha256_hex(&base)
            && raw_identity.materialization_recipe_byte_length == u64::try_from(recipe_jcs.len())?
            && raw_identity.materialization_recipe_sha256 == sha256_hex(&recipe_jcs)
            && raw_identity.negative_plan_byte_length == u64::try_from(negative_plan_jcs.len())?
            && raw_identity.negative_plan_sha256 == sha256_hex(negative_plan_jcs)
            && raw_identity.output_byte_length == u64::try_from(raw_materialized_output.len())?
            && raw_identity.output_sha256 == sha256_hex(raw_materialized_output),
        "C1 raw probe identity differs from its plan, row, base, recipe, or mutated payload"
    );

    ensure!(
        final_identity.execution_id == raw_identity.execution_id
            && final_identity.base_selector_id == raw_identity.base_selector_id
            && final_identity.materialization_domain == raw_identity.materialization_domain
            && final_identity.base_byte_length == raw_identity.base_byte_length
            && final_identity.base_sha256 == raw_identity.base_sha256
            && final_identity.materialization_recipe_byte_length
                == raw_identity.materialization_recipe_byte_length
            && final_identity.materialization_recipe_sha256
                == raw_identity.materialization_recipe_sha256
            && final_identity.negative_plan_byte_length == raw_identity.negative_plan_byte_length
            && final_identity.negative_plan_sha256 == raw_identity.negative_plan_sha256
            && final_identity.output_byte_length == u64::try_from(verifier_subject.len())?
            && final_identity.output_sha256 == sha256_hex(&verifier_subject),
        "C1 final identity differs from the verified raw probe binding or exact verifier subject"
    );
    let materialization_identity_jcs = final_identity.to_canonical_jcs()?;
    let negative_input = Eip0045B4NegativeVerifierInputV1 {
        format: B4_NEGATIVE_VERIFIER_INPUT_FORMAT.to_owned(),
        format_version: B4_NEGATIVE_VERIFIER_INPUT_FORMAT_VERSION,
        materialization_domain: planned.materialization_domain,
        validation_surface: planned.execution_surface,
        subject: B4NegativeNamedIdentityV1 {
            role: "subject".to_owned(),
            path: "subject.bin".to_owned(),
            byte_length: u64::try_from(verifier_subject.len())?,
            sha256: sha256_hex(&verifier_subject),
            encoding: B4NegativeFileEncoding::RawBytes,
        },
        context: Vec::new(),
    };
    let negative_input_jcs = negative_input.to_canonical_jcs()?;
    validate_execution_bytes(
        execution_index,
        planned,
        negative_plan_jcs,
        Some(&registry_row),
        &base,
        &materialization_identity_jcs,
        &negative_input_jcs,
        &verifier_subject,
        &[],
    )?;

    Ok(B4ClosedReconstructedExecutionV1 {
        derived_registry_row: registry_row,
        base,
        materialization_identity_jcs,
        negative_input_jcs,
        subject: verifier_subject,
        contexts: Vec::new(),
    })
}

/// Close one production-derived row after both its raw mutation replay and its
/// exact consumer framing have been independently reconstructed.
///
/// C2 modules own domain-specific source selection and replay adapters. This
/// shared boundary owns the common plan/recipe identities, neutral input
/// document, context naming, and final byte-level validation.
#[cfg(feature = "positive-gate")]
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "this shared closeout boundary keeps all independently reconstructed row authorities explicit and audits them in one protocol-ordered checklist"
)]
pub(crate) fn close_production_execution(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    registry_row: B4NegativeCase,
    raw_adapter: &impl B4MaterializationReplayAdapterV1,
    final_adapter: &impl B4MaterializationReplayAdapterV1,
    verifier_subject: Vec<u8>,
    contexts: Vec<Vec<u8>>,
) -> Result<B4ClosedReconstructedExecutionV1> {
    ensure!(
        registry_row.execution_id == planned.execution_id
            && registry_row.base_selector_id == planned.base_selector_id
            && registry_row.materialization_domain == planned.materialization_domain,
        "production-derived registry row differs from the canonical plan"
    );
    ensure!(
        raw_adapter.materialization_domain() == planned.materialization_domain
            && final_adapter.materialization_domain() == planned.materialization_domain,
        "production replay adapter differs from the canonical materialization domain"
    );
    ensure!(
        raw_adapter.base_bytes() == final_adapter.base_bytes(),
        "raw and final production replay adapters select different base bytes"
    );
    ensure!(
        final_adapter.output_bytes() == verifier_subject,
        "final production replay adapter differs from the exact verifier subject"
    );

    let raw_identity = create_materialization_identity_with_adapter(
        negative_plan_jcs,
        &registry_row,
        raw_adapter,
    )?;
    verify_materialization_identity_with_adapter(
        &raw_identity,
        negative_plan_jcs,
        &registry_row,
        raw_adapter,
    )?;
    let final_identity = create_materialization_identity_with_adapter(
        negative_plan_jcs,
        &registry_row,
        final_adapter,
    )?;
    verify_materialization_identity_with_adapter(
        &final_identity,
        negative_plan_jcs,
        &registry_row,
        final_adapter,
    )?;

    ensure!(
        final_identity.execution_id == raw_identity.execution_id
            && final_identity.base_selector_id == raw_identity.base_selector_id
            && final_identity.materialization_domain == raw_identity.materialization_domain
            && final_identity.base_byte_length == raw_identity.base_byte_length
            && final_identity.base_sha256 == raw_identity.base_sha256
            && final_identity.materialization_recipe_byte_length
                == raw_identity.materialization_recipe_byte_length
            && final_identity.materialization_recipe_sha256
                == raw_identity.materialization_recipe_sha256
            && final_identity.negative_plan_byte_length == raw_identity.negative_plan_byte_length
            && final_identity.negative_plan_sha256 == raw_identity.negative_plan_sha256,
        "raw and final production identities differ outside the consumer output binding"
    );

    let materialization_identity_jcs = final_identity.to_canonical_jcs()?;
    let context = contexts
        .iter()
        .enumerate()
        .map(|(index, bytes)| {
            Ok(B4NegativeNamedIdentityV1 {
                role: format!("context-{index:02}"),
                path: format!("context/{index:02}.bin"),
                byte_length: u64::try_from(bytes.len())?,
                sha256: sha256_hex(bytes),
                encoding: B4NegativeFileEncoding::RawBytes,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let negative_input = Eip0045B4NegativeVerifierInputV1 {
        format: B4_NEGATIVE_VERIFIER_INPUT_FORMAT.to_owned(),
        format_version: B4_NEGATIVE_VERIFIER_INPUT_FORMAT_VERSION,
        materialization_domain: planned.materialization_domain,
        validation_surface: planned.execution_surface,
        subject: B4NegativeNamedIdentityV1 {
            role: "subject".to_owned(),
            path: "subject.bin".to_owned(),
            byte_length: u64::try_from(verifier_subject.len())?,
            sha256: sha256_hex(&verifier_subject),
            encoding: B4NegativeFileEncoding::RawBytes,
        },
        context,
    };
    let negative_input_jcs = negative_input.to_canonical_jcs()?;
    let context_refs = contexts.iter().map(Vec::as_slice).collect::<Vec<_>>();
    validate_execution_bytes(
        execution_index,
        planned,
        negative_plan_jcs,
        Some(&registry_row),
        raw_adapter.base_bytes(),
        &materialization_identity_jcs,
        &negative_input_jcs,
        &verifier_subject,
        &context_refs,
    )?;

    Ok(B4ClosedReconstructedExecutionV1 {
        derived_registry_row: registry_row,
        base: raw_adapter.base_bytes().to_vec(),
        materialization_identity_jcs,
        negative_input_jcs,
        subject: verifier_subject,
        contexts,
    })
}

#[cfg(feature = "positive-gate")]
#[derive(Clone, Debug)]
pub(crate) struct B4AuthenticatedMaterializationTopLevelV1 {
    pub(crate) positive_input_set: Vec<u8>,
    pub(crate) campaign_precommit: Vec<u8>,
    pub(crate) positive_generation_set: Vec<u8>,
    pub(crate) negative_plan: Vec<u8>,
    pub(crate) expanded_registry: B4CandidateCorpus,
    pub(crate) subject_catalog_jcs: Vec<u8>,
    pub(crate) terminal_fixture_catalog_jcs: Vec<u8>,
    pub(crate) negative_binding_index_jcs: Vec<u8>,
    pub(crate) abstract_tree_jcs: Vec<u8>,
    pub(crate) positive_exports: Vec<B4AuthenticatedPositiveExportV1>,
    pub(crate) source_artifacts: BTreeMap<String, Vec<u8>>,
    #[cfg(feature = "negative-materialization-set")]
    negative_ancestry_provenance_evidence: B4AuthenticatedNegativeAncestryProvenanceEvidenceV1,
    document_identities: B4AuthenticatedTopLevelIdentitiesV1,
}

#[cfg(feature = "positive-gate")]
pub(crate) struct B4AuthenticatedMaterializationTopLevelV2 {
    authenticated_storage: B4AuthenticatedMaterializationTopLevelV1,
}

#[cfg(feature = "positive-gate")]
impl B4AuthenticatedMaterializationTopLevelV2 {
    pub(crate) fn storage(&self) -> &B4AuthenticatedMaterializationTopLevelV1 {
        &self.authenticated_storage
    }
}

#[cfg(feature = "negative-materialization-set")]
#[derive(Clone, Debug)]
struct B4AuthenticatedNegativeAncestryProvenanceEvidenceV1 {
    profile_manifest: B4ContractArtifactIdentityV1,
    profile_package_paths: BTreeSet<String>,
    case9_paths: BTreeSet<String>,
}

#[cfg(feature = "positive-gate")]
#[derive(Clone, Debug)]
pub(crate) struct B4AuthenticatedPositiveExportV1 {
    pub(crate) case_index: u8,
    pub(crate) proof_output_manifest_jcs: Vec<u8>,
    pub(crate) raw_seal: Vec<u8>,
    pub(crate) auxiliary_artifacts: Vec<B4AuthenticatedPositiveAuxiliaryArtifactV1>,
}

#[cfg(feature = "positive-gate")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct B4AuthenticatedPositiveAuxiliaryArtifactV1 {
    pub(crate) path: String,
    pub(crate) byte_length: u64,
    pub(crate) sha256: String,
}

#[cfg(feature = "positive-gate")]
#[derive(Clone, Debug)]
struct B4AuthenticatedTopLevelIdentitiesV1 {
    campaign_precommit: B4NegativeMaterializationByteIdentityV1,
    positive_generation_set: B4NegativeMaterializationByteIdentityV1,
    negative_plan: B4NegativeMaterializationByteIdentityV1,
    expanded_registry: B4NegativeMaterializationByteIdentityV1,
    subject_catalog: B4NegativeMaterializationByteIdentityV1,
    terminal_fixture_catalog: B4NegativeMaterializationByteIdentityV1,
    negative_binding_index: B4NegativeMaterializationByteIdentityV1,
    abstract_tree: B4NegativeMaterializationByteIdentityV1,
}

#[cfg(feature = "negative-materialization-set")]
fn verify_negative_ancestry_catalog_cross_bindings(
    catalog: &Eip0045B4NegativeAncestryWitnessCatalogV1,
    negative_plan: &B4ContractArtifactIdentityV1,
    profile_manifest: &B4ContractArtifactIdentityV1,
) -> Result<()> {
    ensure!(
        catalog.negative_plan == *negative_plan,
        "negative-ancestry catalogue binds a different negative plan"
    );
    ensure!(
        catalog.profile_manifest == *profile_manifest,
        "negative-ancestry catalogue binds a different profile manifest"
    );
    Ok(())
}

#[cfg(feature = "negative-materialization-set")]
#[allow(
    clippy::too_many_arguments,
    reason = "the fixed shared core makes all three authorities, the publication root/read set, authenticated top level, executions, path ledger, and producer explicit"
)]
fn close_authenticated_negative_ancestry_handoff(
    prior: &B4MaterializationPriorAuthoritySnapshotV1,
    ancestry: &B4NegativeAncestryWitnessCatalogAuthorityV1,
    ancestry_publication_root: &Path,
    handoff: &B4AuthenticatedNegativeAncestryHandoffV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
    external_executions: &[B4NegativeMaterializationExternalExecutionV1<'_>],
    paths: &mut B4PhysicalPathClosureV1,
    producer: &impl B4ClosedMaterializationRowProducerV1,
) -> Result<B4NegativeMaterializationSetAuthorityV1> {
    let authority = close_authenticated_negative_ancestry_handoff_core(
        prior,
        ancestry,
        handoff,
        top_level,
        external_executions,
        paths,
        producer,
    )?;
    validate_published_b4_negative_ancestry_witness_catalog(ancestry_publication_root, ancestry)?;
    Ok(authority)
}

#[cfg(feature = "negative-materialization-set")]
#[allow(
    clippy::too_many_arguments,
    reason = "the shared authenticated handoff core keeps each authority, retained read set, top-level closure, external execution inventory, path ledger, and producer explicit"
)]
fn close_authenticated_negative_ancestry_handoff_core(
    prior: &B4MaterializationPriorAuthoritySnapshotV1,
    ancestry: &B4NegativeAncestryWitnessCatalogAuthorityV1,
    handoff: &B4AuthenticatedNegativeAncestryHandoffV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
    external_executions: &[B4NegativeMaterializationExternalExecutionV1<'_>],
    paths: &mut B4PhysicalPathClosureV1,
    producer: &impl B4ClosedMaterializationRowProducerV1,
) -> Result<B4NegativeMaterializationSetAuthorityV1> {
    let reparsed = parse_positive_input_sources(&top_level.positive_input_set)?;
    let evidence = &top_level.negative_ancestry_provenance_evidence;
    ensure!(
        reparsed.profile_manifest == evidence.profile_manifest,
        "retained profile-manifest evidence differs from reparsed authenticated positive input"
    );
    let reparsed_profile_paths = [
        &reparsed.profile_manifest,
        &reparsed.profile_algorithm,
        &reparsed.profile_constants,
        &reparsed.guest_elf,
    ]
    .into_iter()
    .map(|identity| identity.path.clone())
    .collect::<BTreeSet<_>>();
    ensure!(
        reparsed_profile_paths == evidence.profile_package_paths,
        "retained profile-package paths differ from reparsed authenticated positive input"
    );
    verify_negative_ancestry_catalog_cross_bindings(
        handoff.read_set.catalog(),
        &prior.negative_plan,
        &evidence.profile_manifest,
    )?;
    close_negative_ancestry_provenance_partition(prior, ancestry, handoff, top_level, paths)?;
    assemble_materialization_authority(
        top_level,
        &handoff.catalog_identity,
        external_executions,
        paths,
        producer,
    )
}

#[cfg(feature = "negative-materialization-set")]
#[allow(
    clippy::too_many_arguments,
    reason = "the V2 core keeps every affine authority, authenticated byte view, path ledger, and producer explicit"
)]
fn close_authenticated_negative_ancestry_handoff_core_v2(
    prior: &B4MaterializationPriorAuthoritySnapshotV2,
    ancestry: &B4NegativeAncestryWitnessCatalogAuthorityV2,
    handoff: &B4AuthenticatedNegativeAncestryHandoffV2,
    top_level: &B4AuthenticatedMaterializationTopLevelV2,
    external_executions: &[B4NegativeMaterializationExternalExecutionV1<'_>],
    paths: &mut B4PhysicalPathClosureV2,
    producer: &impl B4ClosedMaterializationRowProducerV2,
) -> Result<B4NegativeMaterializationSetAuthorityV2> {
    let storage = top_level.storage();
    let reparsed = parse_positive_input_sources_v2(&storage.positive_input_set)?;
    let evidence = &storage.negative_ancestry_provenance_evidence;
    ensure!(
        reparsed.profile_manifest == evidence.profile_manifest,
        "V2 retained profile-manifest evidence differs from reparsed positive input"
    );
    let reparsed_profile_paths = [
        &reparsed.profile_manifest,
        &reparsed.profile_algorithm,
        &reparsed.profile_constants,
        &reparsed.guest_elf,
    ]
    .into_iter()
    .map(|identity| identity.path.clone())
    .collect::<BTreeSet<_>>();
    ensure!(
        reparsed_profile_paths == evidence.profile_package_paths,
        "V2 retained profile-package paths differ from reparsed positive input"
    );
    verify_negative_ancestry_catalog_cross_bindings(
        handoff.read_set.catalog(),
        &prior.negative_plan,
        &evidence.profile_manifest,
    )?;
    close_negative_ancestry_provenance_partition_v2(prior, ancestry, handoff, top_level, paths)?;
    assemble_materialization_authority_v2(
        top_level,
        &handoff.catalog_identity,
        external_executions,
        paths,
        producer,
    )
}

#[cfg(feature = "negative-materialization-set")]
#[allow(clippy::too_many_lines)]
fn close_negative_ancestry_provenance_partition_v2(
    prior: &B4MaterializationPriorAuthoritySnapshotV2,
    ancestry: &B4NegativeAncestryWitnessCatalogAuthorityV2,
    handoff: &B4AuthenticatedNegativeAncestryHandoffV2,
    top_level: &B4AuthenticatedMaterializationTopLevelV2,
    paths: &B4PhysicalPathClosureV2,
) -> Result<B4NegativeAncestryProvenancePartitionV1> {
    let storage = top_level.storage();
    let path_storage = paths.storage();
    let publication_payloads = handoff
        .read_set
        .ordered_files()
        .skip(1)
        .map(|(path, _)| path.to_owned())
        .collect::<BTreeSet<_>>();
    ensure!(
        publication_payloads.len() == 23,
        "V2 negative-ancestry publication payload ownership does not contain exactly 23 paths"
    );
    let prior_authorities = prior
        .provenance_paths
        .difference(&publication_payloads)
        .cloned()
        .collect::<BTreeSet<_>>();
    let evidence = &storage.negative_ancestry_provenance_evidence;
    ensure!(
        storage.expanded_registry.positive_cases[9].index == 9
            && storage.positive_exports[9].case_index == 9,
        "V2 case index 9 drifted in registry or positive-export evidence"
    );
    let case9 = &storage.expanded_registry.positive_cases[9];
    let retained_case9 = &storage.positive_exports[9];
    let mut derived_case9_paths = case9
        .artifacts
        .iter()
        .map(|artifact| artifact.path.clone())
        .collect::<BTreeSet<_>>();
    derived_case9_paths.extend(
        retained_case9
            .auxiliary_artifacts
            .iter()
            .map(|artifact| artifact.path.clone()),
    );
    ensure!(
        derived_case9_paths == evidence.case9_paths,
        "V2 retained case-9 ancestry paths differ from authenticated evidence"
    );
    let mut profile_case9 = evidence.profile_package_paths.clone();
    profile_case9.extend(evidence.case9_paths.iter().cloned());
    profile_case9 = profile_case9
        .difference(&publication_payloads)
        .cloned()
        .collect::<BTreeSet<_>>()
        .difference(&prior_authorities)
        .cloned()
        .collect();
    ensure!(
        publication_payloads.is_disjoint(&prior_authorities)
            && publication_payloads.is_disjoint(&profile_case9)
            && prior_authorities.is_disjoint(&profile_case9),
        "V2 negative-ancestry provenance ownership classes overlap"
    );
    let mut owned_union = publication_payloads.clone();
    owned_union.extend(prior_authorities.iter().cloned());
    owned_union.extend(profile_case9.iter().cloned());
    ensure!(
        owned_union == *ancestry.provenance_paths(),
        "V2 negative-ancestry provenance ownership does not exactly close"
    );
    ensure!(
        !owned_union.contains(B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_PATH),
        "V2 catalogue path appears in retained ancestry provenance"
    );

    let publication_digests = handoff
        .read_set
        .ordered_files()
        .skip(1)
        .map(|(path, bytes)| (path.to_owned(), sha256_hex(bytes)))
        .collect::<BTreeMap<_, _>>();
    let mut evidence_digests = BTreeMap::new();
    for path in &evidence.profile_package_paths {
        let digest = if path == &evidence.profile_manifest.path {
            evidence.profile_manifest.sha256.clone()
        } else {
            storage
                .source_artifacts
                .get(path)
                .map(|bytes| sha256_hex(bytes))
                .with_context(|| format!("V2 retained profile source bytes are absent: {path}"))?
        };
        insert_closed_provenance_digest(&mut evidence_digests, path, &digest)?;
    }
    for artifact in &case9.artifacts {
        insert_closed_provenance_digest(&mut evidence_digests, &artifact.path, &artifact.sha256)?;
    }
    for artifact in &retained_case9.auxiliary_artifacts {
        insert_closed_provenance_digest(&mut evidence_digests, &artifact.path, &artifact.sha256)?;
    }
    for path in &owned_union {
        ensure!(
            path_storage.role_by_path.get(path) == Some(&B4PhysicalPathRoleV1::Source),
            "V2 negative-ancestry provenance path lacks retained source role: {path}"
        );
        let retained_digest = path_storage
            .sha256_by_path
            .get(path)
            .with_context(|| format!("V2 ancestry provenance path lacks a digest: {path}"))?;
        if let Some(expected) = publication_digests
            .get(path)
            .or_else(|| evidence_digests.get(path))
        {
            ensure!(
                retained_digest == expected,
                "V2 ancestry provenance digest disagrees with authenticated evidence: {path}"
            );
        }
    }
    ensure!(
        publication_payloads
            .iter()
            .all(|path| path_storage.publication_paths.contains(path)),
        "V2 negative-ancestry publication payload lacks publication ownership"
    );
    Ok(B4NegativeAncestryProvenancePartitionV1 {
        publication_payloads,
        prior_authorities,
        profile_case9,
    })
}

#[cfg(feature = "negative-materialization-set")]
fn close_negative_ancestry_provenance_partition(
    prior: &B4MaterializationPriorAuthoritySnapshotV1,
    ancestry: &B4NegativeAncestryWitnessCatalogAuthorityV1,
    handoff: &B4AuthenticatedNegativeAncestryHandoffV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
    paths: &B4PhysicalPathClosureV1,
) -> Result<B4NegativeAncestryProvenancePartitionV1> {
    close_negative_ancestry_provenance_partition_against(
        ancestry.provenance_paths(),
        prior,
        handoff,
        top_level,
        paths,
    )
}

#[cfg(feature = "negative-materialization-set")]
#[allow(
    clippy::too_many_lines,
    reason = "the exact ownership partition keeps precedence, role, digest, and publication checks adjacent for review"
)]
fn close_negative_ancestry_provenance_partition_against(
    expected_provenance: &BTreeSet<String>,
    prior: &B4MaterializationPriorAuthoritySnapshotV1,
    handoff: &B4AuthenticatedNegativeAncestryHandoffV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
    paths: &B4PhysicalPathClosureV1,
) -> Result<B4NegativeAncestryProvenancePartitionV1> {
    let publication_payloads = handoff
        .read_set
        .ordered_files()
        .skip(1)
        .map(|(path, _)| path.to_owned())
        .collect::<BTreeSet<_>>();
    ensure!(
        publication_payloads.len() == 23,
        "negative-ancestry publication payload ownership does not contain exactly 23 paths"
    );
    let prior_authorities = prior
        .provenance_paths
        .difference(&publication_payloads)
        .cloned()
        .collect::<BTreeSet<_>>();
    let evidence = &top_level.negative_ancestry_provenance_evidence;
    ensure!(
        top_level
            .expanded_registry
            .positive_cases
            .get(9)
            .is_some_and(|case| case.index == 9)
            && top_level
                .positive_exports
                .get(9)
                .is_some_and(|case| case.case_index == 9),
        "case index 9 drifted in retained registry or positive-export evidence"
    );
    let case9 = &top_level.expanded_registry.positive_cases[9];
    let retained_case9 = &top_level.positive_exports[9];
    let mut derived_case9_paths = case9
        .artifacts
        .iter()
        .map(|artifact| artifact.path.clone())
        .collect::<BTreeSet<_>>();
    derived_case9_paths.extend(
        retained_case9
            .auxiliary_artifacts
            .iter()
            .map(|artifact| artifact.path.clone()),
    );
    ensure!(
        derived_case9_paths == evidence.case9_paths,
        "retained case-9 ancestry paths differ from authenticated registry/export evidence"
    );
    let mut profile_case9 = evidence.profile_package_paths.clone();
    profile_case9.extend(evidence.case9_paths.iter().cloned());
    profile_case9 = profile_case9
        .difference(&publication_payloads)
        .cloned()
        .collect::<BTreeSet<_>>()
        .difference(&prior_authorities)
        .cloned()
        .collect();
    ensure!(
        publication_payloads.is_disjoint(&prior_authorities)
            && publication_payloads.is_disjoint(&profile_case9)
            && prior_authorities.is_disjoint(&profile_case9),
        "negative-ancestry provenance ownership classes overlap"
    );
    let mut owned_union = publication_payloads.clone();
    owned_union.extend(prior_authorities.iter().cloned());
    owned_union.extend(profile_case9.iter().cloned());
    ensure!(
        owned_union == *expected_provenance,
        "negative-ancestry provenance ownership does not exactly close"
    );
    ensure!(
        !owned_union.contains(B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_PATH),
        "catalogue path must not appear in retained ancestry provenance"
    );

    let publication_digests = handoff
        .read_set
        .ordered_files()
        .skip(1)
        .map(|(path, bytes)| (path.to_owned(), sha256_hex(bytes)))
        .collect::<BTreeMap<_, _>>();
    let mut evidence_digests = BTreeMap::new();
    for path in &evidence.profile_package_paths {
        let digest = if path == &evidence.profile_manifest.path {
            evidence.profile_manifest.sha256.clone()
        } else {
            top_level
                .source_artifacts
                .get(path)
                .map(|bytes| sha256_hex(bytes))
                .with_context(|| {
                    format!("retained profile-package source bytes are absent: {path}")
                })?
        };
        insert_closed_provenance_digest(&mut evidence_digests, path, &digest)?;
    }
    for artifact in &case9.artifacts {
        insert_closed_provenance_digest(&mut evidence_digests, &artifact.path, &artifact.sha256)?;
    }
    for artifact in &retained_case9.auxiliary_artifacts {
        insert_closed_provenance_digest(&mut evidence_digests, &artifact.path, &artifact.sha256)?;
    }
    for path in &owned_union {
        ensure!(
            paths.role_by_path.get(path) == Some(&B4PhysicalPathRoleV1::Source),
            "negative-ancestry provenance path is not retained with source role: {path}"
        );
        let retained_digest = paths
            .sha256_by_path
            .get(path)
            .with_context(|| format!("negative-ancestry provenance path lacks a digest: {path}"))?;
        if let Some(expected) = publication_digests
            .get(path)
            .or_else(|| evidence_digests.get(path))
        {
            ensure!(
                retained_digest == expected,
                "negative-ancestry provenance path digest disagrees with authenticated evidence: {path}"
            );
        }
    }
    ensure!(
        publication_payloads
            .iter()
            .all(|path| paths.publication_paths.contains(path)),
        "negative-ancestry publication payload lacks publication ownership"
    );
    Ok(B4NegativeAncestryProvenancePartitionV1 {
        publication_payloads,
        prior_authorities,
        profile_case9,
    })
}

#[cfg(feature = "negative-materialization-set")]
fn insert_closed_provenance_digest(
    digests: &mut BTreeMap<String, String>,
    path: &str,
    digest: &str,
) -> Result<()> {
    if let Some(previous) = digests.insert(path.to_owned(), digest.to_owned()) {
        ensure!(
            previous == digest,
            "authenticated ancestry evidence binds one path to different digests"
        );
    }
    Ok(())
}

#[cfg(feature = "positive-gate")]
#[allow(clippy::too_many_lines)]
fn assemble_materialization_authority(
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
    negative_ancestry_witness_catalog: &B4ContractArtifactIdentityV1,
    external_executions: &[B4NegativeMaterializationExternalExecutionV1<'_>],
    paths: &mut B4PhysicalPathClosureV1,
    producer: &impl B4ClosedMaterializationRowProducerV1,
) -> Result<B4NegativeMaterializationSetAuthorityV1> {
    let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(&top_level.negative_plan)?;
    let flattened_plan = plan
        .groups
        .iter()
        .flat_map(|group| group.executions.iter())
        .collect::<Vec<_>>();
    ensure!(
        flattened_plan.len() == B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT,
        "closed negative plan does not flatten to exactly 254 executions"
    );
    ensure!(
        external_executions.len() == B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT,
        "external materialization inventory must contain exactly 254 executions"
    );
    ensure!(
        top_level.expanded_registry.negative_cases.len()
            == B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT,
        "authenticated expanded registry does not contain exactly 254 negative rows"
    );

    let mut rows = Vec::with_capacity(B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT);
    let mut retained = Vec::with_capacity(B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT);
    let mut unavailable = Vec::new();
    for (index, ((planned, registry_row), supplied)) in flattened_plan
        .iter()
        .zip(&top_level.expanded_registry.negative_cases)
        .zip(external_executions)
        .enumerate()
    {
        ensure!(
            usize::from(supplied.execution_index) == index,
            "external materialization execution index drift at index {index}"
        );
        ensure!(
            supplied.execution_id == planned.execution_id,
            "external materialization execution ID/order drift at index {index}"
        );
        validate_external_execution(index, planned, &top_level.negative_plan, supplied, paths)?;

        let Some(reconstructed) = producer.reconstruct(index, planned, top_level)? else {
            unavailable.push(planned.execution_id.as_str());
            continue;
        };
        ensure!(
            reconstructed.derived_registry_row == *registry_row,
            "closed producer-derived registry row differs from the authenticated expanded registry at index {index}"
        );
        ensure_reconstruction_matches_external(index, &reconstructed, supplied)?;
        let (row, retained_row) = retain_authenticated_execution(
            index,
            planned,
            &top_level.negative_plan,
            reconstructed,
        )?;
        rows.push(row);
        retained.push(retained_row);
    }

    ensure!(
        unavailable.is_empty(),
        "closed negative materialization producers reconstructed only {}/{} executions; authority remains unavailable (first unavailable: {})",
        B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT - unavailable.len(),
        B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT,
        unavailable.first().copied().unwrap_or("none")
    );
    ensure!(
        rows.len() == B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT
            && retained.len() == B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT,
        "closed producer coverage did not yield exactly 254 retained executions"
    );
    let terminal_evidence = producer
        .terminal_evidence_document_identities()
        .context("closed producer lacks authenticated terminal-evidence document identities")?;

    let expected = Eip0045B4NegativeMaterializationSetV1 {
        format: B4_NEGATIVE_MATERIALIZATION_SET_FORMAT.to_owned(),
        format_version: B4_NEGATIVE_MATERIALIZATION_SET_FORMAT_VERSION,
        campaign_precommit: top_level.document_identities.campaign_precommit.clone(),
        positive_generation_set: top_level
            .document_identities
            .positive_generation_set
            .clone(),
        terminal_evidence_packet_manifest: terminal_evidence.packet_manifest,
        terminal_evidence_campaign_receipt: terminal_evidence.campaign_receipt,
        negative_plan: top_level.document_identities.negative_plan.clone(),
        expanded_registry: top_level.document_identities.expanded_registry.clone(),
        subject_catalog: top_level.document_identities.subject_catalog.clone(),
        terminal_fixture_catalog: top_level
            .document_identities
            .terminal_fixture_catalog
            .clone(),
        negative_binding_index: top_level.document_identities.negative_binding_index.clone(),
        abstract_tree: top_level.document_identities.abstract_tree.clone(),
        negative_ancestry_witness_catalog: negative_ancestry_witness_catalog.clone(),
        domain_totals: B4NegativeMaterializationDomainTotalsV1::EXPECTED,
        execution_count: B4_NEGATIVE_PLAN_VARIANT_COUNT,
        executions: rows,
    };
    expected.validate()?;
    let canonical_jcs = expected.to_canonical_jcs()?;
    ensure!(
        Eip0045B4NegativeMaterializationSetV1::from_canonical_jcs(&canonical_jcs)? == expected,
        "internally reconstructed materialization set does not round-trip byte-exactly"
    );
    let authority = B4NegativeMaterializationSetAuthorityV1 {
        expected,
        canonical_jcs,
        executions: retained,
        provenance_paths: paths.paths.clone(),
    };
    authority.validate_retained_closure()?;
    Ok(authority)
}

#[cfg(feature = "positive-gate")]
#[allow(clippy::too_many_lines)]
fn assemble_materialization_authority_v2(
    top_level: &B4AuthenticatedMaterializationTopLevelV2,
    negative_ancestry_witness_catalog: &B4ContractArtifactIdentityV1,
    external_executions: &[B4NegativeMaterializationExternalExecutionV1<'_>],
    paths: &mut B4PhysicalPathClosureV2,
    producer: &impl B4ClosedMaterializationRowProducerV2,
) -> Result<B4NegativeMaterializationSetAuthorityV2> {
    let storage = top_level.storage();
    let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(&storage.negative_plan)?;
    let flattened_plan = plan
        .groups
        .iter()
        .flat_map(|group| group.executions.iter())
        .collect::<Vec<_>>();
    ensure!(
        flattened_plan.len() == B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT
            && external_executions.len() == B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT
            && storage.expanded_registry.negative_cases.len()
                == B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT,
        "V2 materialization closure does not contain exactly 254 planned, supplied, and registry executions"
    );

    let mut rows = Vec::with_capacity(B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT);
    let mut retained = Vec::with_capacity(B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT);
    let mut unavailable = Vec::new();
    for (index, ((planned, registry_row), supplied)) in flattened_plan
        .iter()
        .zip(&storage.expanded_registry.negative_cases)
        .zip(external_executions)
        .enumerate()
    {
        ensure!(
            usize::from(supplied.execution_index) == index
                && supplied.execution_id == planned.execution_id,
            "V2 external materialization execution order drift at index {index}"
        );
        validate_external_execution(
            index,
            planned,
            &storage.negative_plan,
            supplied,
            paths.storage_mut(),
        )?;
        let Some(reconstructed) = producer.reconstruct(index, planned, top_level)? else {
            unavailable.push(planned.execution_id.as_str());
            continue;
        };
        ensure!(
            reconstructed.derived_registry_row == *registry_row,
            "V2 producer-derived registry row differs at index {index}"
        );
        ensure_reconstruction_matches_external(index, &reconstructed, supplied)?;
        let (row, retained_row) =
            retain_authenticated_execution(index, planned, &storage.negative_plan, reconstructed)?;
        rows.push(row);
        retained.push(retained_row);
    }
    ensure!(
        unavailable.is_empty(),
        "V2 materialization producers reconstructed only {}/{} executions (first unavailable: {})",
        B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT - unavailable.len(),
        B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT,
        unavailable.first().copied().unwrap_or("none")
    );
    ensure!(
        rows.len() == B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT
            && retained.len() == B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT,
        "V2 producer coverage did not yield exactly 254 retained executions"
    );
    let terminal_evidence = producer
        .terminal_evidence_document_identities()
        .context("V2 closed producer lacks terminal-evidence document identities")?;
    let expected = Eip0045B4NegativeMaterializationSetV1 {
        format: B4_NEGATIVE_MATERIALIZATION_SET_FORMAT.to_owned(),
        format_version: B4_NEGATIVE_MATERIALIZATION_SET_FORMAT_VERSION,
        campaign_precommit: storage.document_identities.campaign_precommit.clone(),
        positive_generation_set: storage.document_identities.positive_generation_set.clone(),
        terminal_evidence_packet_manifest: terminal_evidence.packet_manifest,
        terminal_evidence_campaign_receipt: terminal_evidence.campaign_receipt,
        negative_plan: storage.document_identities.negative_plan.clone(),
        expanded_registry: storage.document_identities.expanded_registry.clone(),
        subject_catalog: storage.document_identities.subject_catalog.clone(),
        terminal_fixture_catalog: storage.document_identities.terminal_fixture_catalog.clone(),
        negative_binding_index: storage.document_identities.negative_binding_index.clone(),
        abstract_tree: storage.document_identities.abstract_tree.clone(),
        negative_ancestry_witness_catalog: negative_ancestry_witness_catalog.clone(),
        domain_totals: B4NegativeMaterializationDomainTotalsV1::EXPECTED,
        execution_count: B4_NEGATIVE_PLAN_VARIANT_COUNT,
        executions: rows,
    };
    expected.validate()?;
    let canonical_jcs = expected.to_canonical_jcs()?;
    ensure!(
        Eip0045B4NegativeMaterializationSetV1::from_canonical_jcs(&canonical_jcs)? == expected,
        "V2 internally reconstructed materialization set does not round-trip byte-exactly"
    );
    let authority = B4NegativeMaterializationSetAuthorityV2 {
        expected,
        canonical_jcs,
        executions: retained,
        provenance_paths: paths.storage().paths.clone(),
    };
    authority.validate_retained_closure()?;
    Ok(authority)
}

#[cfg(feature = "positive-gate")]
#[cfg_attr(
    not(target_os = "linux"),
    allow(
        dead_code,
        reason = "provider-deferred alternate-root custody is opened only by the Linux descriptor-rooted E6 constructor"
    )
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum B4AlternateRootSourceModeV1 {
    CallerCustody,
    ProviderDeferred,
}

#[cfg(feature = "positive-gate")]
#[allow(clippy::too_many_lines)]
fn authenticate_top_level(
    prior: &B4MaterializationPriorAuthoritySnapshotV1,
    external: &B4NegativeMaterializationSetExternalInputsV1<'_>,
    paths: &mut B4PhysicalPathClosureV1,
    alternate_root_mode: B4AlternateRootSourceModeV1,
) -> Result<B4AuthenticatedMaterializationTopLevelV1> {
    authenticate_prior_artifact(
        external.positive_input_set,
        &prior.positive_input_set,
        "positive input set",
        paths,
    )?;
    let positive_input_sources =
        authenticate_positive_input_sources(external.positive_input_set.bytes, paths)?;

    ensure!(
        external.campaign_precommit.bytes == prior.campaign_precommit_jcs,
        "campaign-precommit bytes differ from the opaque prior authority"
    );
    validate_canonical_json_source(external.campaign_precommit.bytes)
        .context("campaign precommit is not exact canonical JCS")?;
    paths.bind_new_source(external.campaign_precommit, false, "campaign precommit")?;

    authenticate_prior_artifact(
        external.positive_generation_set,
        &prior.positive_generation_set,
        "positive generation set",
        paths,
    )?;
    validate_canonical_json_source(external.positive_generation_set.bytes)
        .context("positive generation set is not exact canonical JCS")?;
    authenticate_prior_artifact(
        external.negative_plan,
        &prior.negative_plan,
        "negative plan",
        paths,
    )?;
    ensure!(
        external.negative_plan.bytes == prior.negative_plan_jcs,
        "negative-plan bytes differ from the campaign-precommit authority"
    );
    let negative_plan = Eip0045B4NegativePlanV1::from_canonical_jcs(external.negative_plan.bytes)?;
    ensure!(
        negative_plan == Eip0045B4NegativePlanV1::canonical()?,
        "external negative plan differs from the compiled closed plan"
    );

    paths.bind_new_source(external.expanded_registry, false, "expanded registry")?;
    let expanded_registry =
        B4CandidateCorpus::from_canonical_jcs(external.expanded_registry.bytes)?;
    expanded_registry
        .validate_expanded_against_canonical_plan_source(external.negative_plan.bytes)?;

    paths.bind_new_source(external.subject_catalog, false, "subject catalog")?;
    let subject_catalog =
        Eip0045B4SubjectCatalogV1::from_canonical_jcs(external.subject_catalog.bytes)?;
    paths.bind_new_source(
        external.terminal_fixture_catalog,
        false,
        "terminal fixture catalog",
    )?;
    let terminal_fixture_catalog = Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(
        external.terminal_fixture_catalog.bytes,
    )?;
    paths.bind_new_source(
        external.negative_binding_index,
        false,
        "negative binding index",
    )?;
    let negative_binding_index =
        Eip0045B4NegativeBindingIndexV1::from_canonical_jcs(external.negative_binding_index.bytes)?;
    negative_binding_index.validate_against_plan(&negative_plan)?;
    ensure!(
        negative_binding_index == Eip0045B4NegativeBindingIndexV1::from_plan(&negative_plan)?,
        "negative-binding index differs from independent plan reconstruction"
    );
    paths.bind_new_source(external.abstract_tree, false, "abstract tree")?;
    let abstract_tree = Eip0045B4AbstractTreeV1::from_canonical_jcs(external.abstract_tree.bytes)?;
    ensure!(
        abstract_tree == Eip0045B4AbstractTreeV1::canonical_baseline()?
            && validate_abstract_tree_policy(&abstract_tree)?
                == B4AbstractTreePolicyOutcome::Accepted,
        "abstract tree differs from the exact accepted baseline"
    );

    authenticate_registry_quarantine_document_copy(
        &expanded_registry.bindings.negative_plan,
        external.negative_plan,
        B4ArtifactEncoding::Rfc8785Jcs,
        "expanded-registry negative plan",
    )?;
    authenticate_registry_document_binding(
        &expanded_registry.bindings.subject_catalog,
        external.subject_catalog,
        B4ArtifactEncoding::Rfc8785Jcs,
        "expanded-registry subject catalog",
    )?;
    authenticate_registry_document_binding(
        &expanded_registry.bindings.terminal_fixture_catalog,
        external.terminal_fixture_catalog,
        B4ArtifactEncoding::Rfc8785Jcs,
        "expanded-registry terminal fixture catalog",
    )?;
    let mut positive_exports = authenticate_positive_exports(prior, external.positive_exports)?;
    authenticate_positive_generation_closure(
        external.positive_generation_set.bytes,
        &expanded_registry,
        prior,
        &mut positive_exports,
        external.positive_exports,
    )?;
    for export in external.positive_exports {
        paths.bind_authority_selected_source(
            export.proof_output_manifest,
            "positive proof-output manifest",
        )?;
        paths.bind_authority_selected_source(export.raw_seal, "positive raw seal")?;
    }
    authenticate_registry_prior_bindings(&expanded_registry, &positive_input_sources, prior)?;
    authenticate_subject_catalog(
        &subject_catalog,
        &expanded_registry,
        external.negative_plan.bytes,
        prior,
    )?;
    ensure!(
        terminal_fixture_catalog.program_id == expanded_registry.bindings.guest.image_id,
        "terminal fixture catalog and expanded registry bind different guest program IDs"
    );
    let mut source_artifacts = authenticate_source_artifacts(
        &expanded_registry,
        &subject_catalog,
        &terminal_fixture_catalog,
        &positive_input_sources,
        &positive_exports,
        external.source_artifacts,
        paths,
    )?;
    if alternate_root_mode == B4AlternateRootSourceModeV1::CallerCustody {
        for (path, bytes) in authenticate_alternate_root_export(
            external.alternate_root_export,
            &positive_input_sources,
            paths,
        )? {
            ensure!(
                source_artifacts.insert(path, bytes).is_none(),
                "alternate-root export aliases the deterministic source inventory"
            );
        }
    }

    #[cfg(feature = "negative-materialization-set")]
    let negative_ancestry_provenance_evidence = {
        ensure!(
            prior
                .positive_cases
                .get(9)
                .is_some_and(|case| case.case_index == 9)
                && expanded_registry
                    .positive_cases
                    .get(9)
                    .is_some_and(|case| case.index == 9)
                && external
                    .positive_exports
                    .get(9)
                    .is_some_and(|case| case.case_index == 9)
                && positive_exports
                    .get(9)
                    .is_some_and(|case| case.case_index == 9),
            "case index 9 drifted across generation, registry, supplied, or retained views"
        );
        let profile_package_paths = [
            &positive_input_sources.profile_manifest,
            &positive_input_sources.profile_algorithm,
            &positive_input_sources.profile_constants,
            &positive_input_sources.guest_elf,
        ]
        .into_iter()
        .map(|identity| identity.path.clone())
        .collect();
        let case9 = &expanded_registry.positive_cases[9];
        let retained_case9 = &positive_exports[9];
        let mut case9_paths = case9
            .artifacts
            .iter()
            .map(|artifact| artifact.path.clone())
            .collect::<BTreeSet<_>>();
        case9_paths.extend(
            retained_case9
                .auxiliary_artifacts
                .iter()
                .map(|artifact| artifact.path.clone()),
        );
        B4AuthenticatedNegativeAncestryProvenanceEvidenceV1 {
            profile_manifest: positive_input_sources.profile_manifest.clone(),
            profile_package_paths,
            case9_paths,
        }
    };

    let document_identities = B4AuthenticatedTopLevelIdentitiesV1 {
        campaign_precommit: pathless_identity(external.campaign_precommit.bytes)?,
        positive_generation_set: pathless_identity(external.positive_generation_set.bytes)?,
        negative_plan: pathless_identity(external.negative_plan.bytes)?,
        expanded_registry: pathless_identity(external.expanded_registry.bytes)?,
        subject_catalog: pathless_identity(external.subject_catalog.bytes)?,
        terminal_fixture_catalog: pathless_identity(external.terminal_fixture_catalog.bytes)?,
        negative_binding_index: pathless_identity(external.negative_binding_index.bytes)?,
        abstract_tree: pathless_identity(external.abstract_tree.bytes)?,
    };
    Ok(B4AuthenticatedMaterializationTopLevelV1 {
        positive_input_set: external.positive_input_set.bytes.to_vec(),
        campaign_precommit: external.campaign_precommit.bytes.to_vec(),
        positive_generation_set: external.positive_generation_set.bytes.to_vec(),
        negative_plan: external.negative_plan.bytes.to_vec(),
        expanded_registry,
        subject_catalog_jcs: external.subject_catalog.bytes.to_vec(),
        terminal_fixture_catalog_jcs: external.terminal_fixture_catalog.bytes.to_vec(),
        negative_binding_index_jcs: external.negative_binding_index.bytes.to_vec(),
        abstract_tree_jcs: external.abstract_tree.bytes.to_vec(),
        positive_exports,
        source_artifacts,
        #[cfg(feature = "negative-materialization-set")]
        negative_ancestry_provenance_evidence,
        document_identities,
    })
}

#[cfg(feature = "positive-gate")]
#[allow(clippy::too_many_lines)]
fn authenticate_top_level_v2(
    prior: &B4MaterializationPriorAuthoritySnapshotV2,
    positive: &B4PositiveGenerationAuthorityV2,
    external: &B4NegativeMaterializationSetExternalInputsV1<'_>,
    paths: &mut B4PhysicalPathClosureV2,
) -> Result<B4AuthenticatedMaterializationTopLevelV2> {
    authenticate_prior_artifact(
        external.positive_input_set,
        &prior.positive_input_set,
        "V2 positive input set",
        paths.storage_mut(),
    )?;
    let positive_input_sources =
        authenticate_positive_input_sources_v2(external.positive_input_set.bytes, paths)?;

    ensure!(
        external.campaign_precommit.bytes == prior.campaign_precommit_jcs,
        "campaign-precommit bytes differ from the opaque V2 prior snapshot"
    );
    validate_canonical_json_source(external.campaign_precommit.bytes)
        .context("V2 materialization campaign precommit is not exact canonical JCS")?;
    paths.storage_mut().bind_new_source(
        external.campaign_precommit,
        false,
        "V2 campaign precommit",
    )?;

    authenticate_prior_artifact(
        external.positive_generation_set,
        &prior.positive_generation_set,
        "V2 positive generation set",
        paths.storage_mut(),
    )?;
    let generator_source = external
        .source_artifacts
        .iter()
        .find(|source| source.path == positive_input_sources.generator.path)
        .context("V2 materialization source inventory lacks the authenticated proof generator")?;
    let postproof = reparse_v2_postproof_documents(
        external.positive_input_set.bytes,
        external.positive_generation_set.bytes,
        B4PositiveSourceBytesV2 {
            path: generator_source.path,
            bytes: generator_source.bytes,
        },
    )?;
    ensure!(
        postproof.input_set_measurement == measure_bytes(external.positive_input_set.bytes)
            && postproof.generation_set_measurement
                == measure_bytes(external.positive_generation_set.bytes)
            && postproof.proof_generator_measurement == measure_bytes(generator_source.bytes),
        "V2 postproof document measurements differ from exact materialization sources"
    );

    authenticate_prior_artifact(
        external.negative_plan,
        &prior.negative_plan,
        "V2 negative plan",
        paths.storage_mut(),
    )?;
    ensure!(
        external.negative_plan.bytes == prior.negative_plan_jcs,
        "negative-plan bytes differ from the V2 prior snapshot"
    );
    let negative_plan = Eip0045B4NegativePlanV1::from_canonical_jcs(external.negative_plan.bytes)?;
    ensure!(
        negative_plan == Eip0045B4NegativePlanV1::canonical()?,
        "V2 materialization external negative plan differs from compiled plan"
    );

    paths.storage_mut().bind_new_source(
        external.expanded_registry,
        false,
        "V2 expanded registry",
    )?;
    let expanded_registry =
        B4CandidateCorpus::from_canonical_jcs(external.expanded_registry.bytes)?;
    expanded_registry
        .validate_expanded_against_canonical_plan_source(external.negative_plan.bytes)?;

    paths
        .storage_mut()
        .bind_new_source(external.subject_catalog, false, "V2 subject catalog")?;
    let subject_catalog =
        Eip0045B4SubjectCatalogV1::from_canonical_jcs(external.subject_catalog.bytes)?;
    paths.storage_mut().bind_new_source(
        external.terminal_fixture_catalog,
        false,
        "V2 terminal fixture catalog",
    )?;
    let terminal_fixture_catalog = Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(
        external.terminal_fixture_catalog.bytes,
    )?;
    paths.storage_mut().bind_new_source(
        external.negative_binding_index,
        false,
        "V2 negative binding index",
    )?;
    let negative_binding_index =
        Eip0045B4NegativeBindingIndexV1::from_canonical_jcs(external.negative_binding_index.bytes)?;
    negative_binding_index.validate_against_plan(&negative_plan)?;
    ensure!(
        negative_binding_index == Eip0045B4NegativeBindingIndexV1::from_plan(&negative_plan)?,
        "V2 negative-binding index differs from independent plan reconstruction"
    );
    paths
        .storage_mut()
        .bind_new_source(external.abstract_tree, false, "V2 abstract tree")?;
    let abstract_tree = Eip0045B4AbstractTreeV1::from_canonical_jcs(external.abstract_tree.bytes)?;
    ensure!(
        abstract_tree == Eip0045B4AbstractTreeV1::canonical_baseline()?
            && validate_abstract_tree_policy(&abstract_tree)?
                == B4AbstractTreePolicyOutcome::Accepted,
        "V2 abstract tree differs from the exact accepted baseline"
    );

    authenticate_registry_quarantine_document_copy(
        &expanded_registry.bindings.negative_plan,
        external.negative_plan,
        B4ArtifactEncoding::Rfc8785Jcs,
        "V2 expanded-registry negative plan",
    )?;
    authenticate_registry_document_binding(
        &expanded_registry.bindings.subject_catalog,
        external.subject_catalog,
        B4ArtifactEncoding::Rfc8785Jcs,
        "V2 expanded-registry subject catalog",
    )?;
    authenticate_registry_document_binding(
        &expanded_registry.bindings.terminal_fixture_catalog,
        external.terminal_fixture_catalog,
        B4ArtifactEncoding::Rfc8785Jcs,
        "V2 expanded-registry terminal fixture catalog",
    )?;
    let positive_exports = authenticate_positive_exports_v2(
        positive,
        &expanded_registry,
        external.positive_exports,
        external.source_artifacts,
    )?;
    for export in external.positive_exports {
        paths.storage_mut().bind_authority_selected_source(
            export.proof_output_manifest,
            "V2 positive proof-output manifest",
        )?;
        paths
            .storage_mut()
            .bind_authority_selected_source(export.raw_seal, "V2 positive raw seal")?;
    }
    authenticate_registry_prior_bindings_v2(&expanded_registry, &positive_input_sources, prior)?;
    authenticate_subject_catalog_v2(
        &subject_catalog,
        &expanded_registry,
        external.negative_plan.bytes,
        prior,
    )?;
    ensure!(
        terminal_fixture_catalog.program_id == expanded_registry.bindings.guest.image_id,
        "V2 terminal fixture catalog and expanded registry bind different guest program IDs"
    );
    let source_artifacts = authenticate_source_artifacts_v2(
        &expanded_registry,
        &subject_catalog,
        &terminal_fixture_catalog,
        &positive_input_sources,
        &positive_exports,
        external.source_artifacts,
        paths,
    )?;

    #[cfg(feature = "negative-materialization-set")]
    let negative_ancestry_provenance_evidence = {
        ensure!(
            prior.positive_cases[9].case_index == 9
                && expanded_registry.positive_cases[9].index == 9
                && external.positive_exports[9].case_index == 9
                && positive_exports[9].case_index == 9,
            "case index 9 drifted across V2 generation, registry, supplied, or retained views"
        );
        let profile_package_paths = [
            &positive_input_sources.profile_manifest,
            &positive_input_sources.profile_algorithm,
            &positive_input_sources.profile_constants,
            &positive_input_sources.guest_elf,
        ]
        .into_iter()
        .map(|identity| identity.path.clone())
        .collect();
        let case9 = &expanded_registry.positive_cases[9];
        let retained_case9 = &positive_exports[9];
        let mut case9_paths = case9
            .artifacts
            .iter()
            .map(|artifact| artifact.path.clone())
            .collect::<BTreeSet<_>>();
        case9_paths.extend(
            retained_case9
                .auxiliary_artifacts
                .iter()
                .map(|artifact| artifact.path.clone()),
        );
        B4AuthenticatedNegativeAncestryProvenanceEvidenceV1 {
            profile_manifest: positive_input_sources.profile_manifest.clone(),
            profile_package_paths,
            case9_paths,
        }
    };
    let document_identities = B4AuthenticatedTopLevelIdentitiesV1 {
        campaign_precommit: pathless_identity(external.campaign_precommit.bytes)?,
        positive_generation_set: pathless_identity(external.positive_generation_set.bytes)?,
        negative_plan: pathless_identity(external.negative_plan.bytes)?,
        expanded_registry: pathless_identity(external.expanded_registry.bytes)?,
        subject_catalog: pathless_identity(external.subject_catalog.bytes)?,
        terminal_fixture_catalog: pathless_identity(external.terminal_fixture_catalog.bytes)?,
        negative_binding_index: pathless_identity(external.negative_binding_index.bytes)?,
        abstract_tree: pathless_identity(external.abstract_tree.bytes)?,
    };
    Ok(B4AuthenticatedMaterializationTopLevelV2 {
        authenticated_storage: B4AuthenticatedMaterializationTopLevelV1 {
            positive_input_set: external.positive_input_set.bytes.to_vec(),
            campaign_precommit: external.campaign_precommit.bytes.to_vec(),
            positive_generation_set: external.positive_generation_set.bytes.to_vec(),
            negative_plan: external.negative_plan.bytes.to_vec(),
            expanded_registry,
            subject_catalog_jcs: external.subject_catalog.bytes.to_vec(),
            terminal_fixture_catalog_jcs: external.terminal_fixture_catalog.bytes.to_vec(),
            negative_binding_index_jcs: external.negative_binding_index.bytes.to_vec(),
            abstract_tree_jcs: external.abstract_tree.bytes.to_vec(),
            positive_exports,
            source_artifacts,
            #[cfg(feature = "negative-materialization-set")]
            negative_ancestry_provenance_evidence,
            document_identities,
        },
    })
}

#[cfg(feature = "positive-gate")]
fn authenticate_prior_artifact(
    external: B4NegativeMaterializationExternalBytesV1<'_>,
    expected: &B4ContractArtifactIdentityV1,
    label: &str,
    paths: &mut B4PhysicalPathClosureV1,
) -> Result<()> {
    ensure!(
        expected.encoding == B4ContractArtifactEncodingV1::Rfc8785Jcs,
        "{label} prior authority uses the wrong encoding"
    );
    let measured = B4ContractArtifactIdentityV1::from_bytes(
        external.path,
        B4ContractArtifactEncodingV1::Rfc8785Jcs,
        external.bytes,
    )?;
    ensure!(
        &measured == expected,
        "{label} path or bytes differ from the opaque prior authority"
    );
    paths.bind_prior_replay(external, label)
}

#[cfg(feature = "positive-gate")]
#[allow(clippy::too_many_lines)]
fn authenticate_positive_input_sources(
    source: &[u8],
    paths: &mut B4PhysicalPathClosureV1,
) -> Result<B4AuthenticatedPositiveInputSourcesV1> {
    let authenticated = parse_positive_input_sources(source)?;
    for identity in authenticated.artifacts.values() {
        paths.bind_prior_identity(identity, "positive input-set nested artifact")?;
    }
    Ok(authenticated)
}

#[cfg(feature = "positive-gate")]
fn authenticate_positive_input_sources_v2(
    source: &[u8],
    paths: &mut B4PhysicalPathClosureV2,
) -> Result<B4AuthenticatedPositiveInputSourcesV2> {
    let authenticated = parse_positive_input_sources_v2(source)?;
    for identity in authenticated.artifacts.values() {
        paths
            .storage_mut()
            .bind_prior_identity(identity, "V2 positive input-set nested artifact")?;
    }
    Ok(authenticated)
}

#[cfg(feature = "positive-gate")]
#[allow(clippy::too_many_lines)]
pub(crate) fn parse_positive_input_sources(
    source: &[u8],
) -> Result<B4AuthenticatedPositiveInputSourcesV1> {
    let value = validate_canonical_json_source(source)
        .context("positive input set is not exact canonical JCS")?;
    ensure!(
        json_string_field(&value, "format", "positive input set")? == "Eip0045B4PositiveInputSetV1"
            && json_u64_field(&value, "formatVersion", "positive input set")? == 1,
        "positive input set has the wrong format identity"
    );

    let profile = json_field(&value, "profile", "positive input set")?;
    let profile_manifest =
        contract_identity_from_value(json_field(profile, "manifest", "input-set profile")?)?;
    let profile_algorithm =
        contract_identity_from_value(json_field(profile, "algorithm", "input-set profile")?)?;
    let profile_constants =
        contract_identity_from_value(json_field(profile, "constants", "input-set profile")?)?;
    require_contract_encoding(
        &profile_manifest,
        B4ContractArtifactEncodingV1::RawBytes,
        "input-set profile manifest",
    )?;
    require_contract_encoding(
        &profile_algorithm,
        B4ContractArtifactEncodingV1::RawBytes,
        "input-set profile algorithm",
    )?;
    require_contract_encoding(
        &profile_constants,
        B4ContractArtifactEncodingV1::RawBytes,
        "input-set profile constants",
    )?;
    let profile_id = json_string_field(profile, "profileId", "input-set profile")?.to_owned();
    validate_digest(&profile_id, "input-set profile ID")?;

    let guest = json_field(&value, "guest", "positive input set")?;
    let guest_elf = contract_identity_from_value(json_field(guest, "elf", "input-set guest")?)?;
    require_contract_encoding(
        &guest_elf,
        B4ContractArtifactEncodingV1::RawBytes,
        "input-set guest ELF",
    )?;
    let guest_image_id = json_string_field(guest, "imageId", "input-set guest")?.to_owned();
    validate_digest(&guest_image_id, "input-set guest image ID")?;

    let reference = json_field(&value, "referenceStatement", "positive input set")?;
    let reference_statement_manifest = contract_identity_from_value(json_field(
        reference,
        "bundleManifest",
        "input-set reference statement",
    )?)?;
    require_contract_encoding(
        &reference_statement_manifest,
        B4ContractArtifactEncodingV1::Rfc8785Jcs,
        "input-set reference-statement manifest",
    )?;
    let reference_contract_id =
        json_string_field(reference, "contractId", "input-set reference statement")?.to_owned();
    validate_digest(&reference_contract_id, "input-set reference contract ID")?;
    let reference_statement_byte_length = json_u64_field(
        reference,
        "statementByteLength",
        "input-set reference statement",
    )?;
    let reference_statement_sha256 = json_string_field(
        reference,
        "statementSha256",
        "input-set reference statement",
    )?
    .to_owned();
    validate_digest(
        &reference_statement_sha256,
        "input-set reference statement SHA-256",
    )?;
    let reference_chain_domain_id =
        json_string_field(reference, "chainDomainId", "input-set reference statement")?.to_owned();
    validate_digest(
        &reference_chain_domain_id,
        "input-set reference chain-domain ID",
    )?;
    let reference_application_payload_byte_length = json_u64_field(
        reference,
        "applicationPayloadByteLength",
        "input-set reference statement",
    )?;
    let reference_application_payload_sha256 = json_string_field(
        reference,
        "applicationPayloadSha256",
        "input-set reference statement",
    )?
    .to_owned();
    validate_digest(
        &reference_application_payload_sha256,
        "input-set reference application-payload SHA-256",
    )?;
    ensure!(
        (STATEMENT_PREFIX_BYTES as u64..=MAX_STATEMENT_BYTES as u64)
            .contains(&reference_statement_byte_length),
        "input-set reference statement byte length is outside the exact statement bounds"
    );
    ensure!(
        reference_application_payload_byte_length <= MAX_APPLICATION_PAYLOAD_BYTES as u64,
        "input-set reference application payload exceeds the exact payload bound"
    );
    ensure!(
        reference_statement_byte_length
            == STATEMENT_PREFIX_BYTES as u64 + reference_application_payload_byte_length,
        "input-set reference statement length does not equal its fixed prefix plus payload"
    );

    let source_lock =
        contract_identity_from_value(json_field(&value, "sourceLock", "positive input set")?)?;
    require_contract_encoding(
        &source_lock,
        B4ContractArtifactEncodingV1::Rfc8785Jcs,
        "input-set source lock",
    )?;
    let proof_generator = json_field(&value, "proofGenerator", "positive input set")?;
    let generator = contract_identity_from_value(json_field(
        proof_generator,
        "artifact",
        "input-set proof generator",
    )?)?;
    require_contract_encoding(
        &generator,
        B4ContractArtifactEncodingV1::RawBytes,
        "input-set proof-generator artifact",
    )?;

    let mut artifacts = BTreeMap::new();
    collect_contract_artifact_identities(&value, &mut artifacts)?;
    for expected in [
        &profile_manifest,
        &profile_algorithm,
        &profile_constants,
        &guest_elf,
        &reference_statement_manifest,
        &source_lock,
        &generator,
    ] {
        ensure!(
            artifacts
                .get(&expected.path)
                .is_some_and(|actual| actual == expected),
            "positive input-set nested identity inventory is incomplete"
        );
    }
    Ok(B4AuthenticatedPositiveInputSourcesV1 {
        profile_id,
        profile_manifest,
        profile_algorithm,
        profile_constants,
        guest_elf,
        guest_image_id,
        reference_statement_manifest,
        reference_contract_id,
        reference_statement_byte_length,
        reference_statement_sha256,
        reference_chain_domain_id,
        reference_application_payload_byte_length,
        reference_application_payload_sha256,
        source_lock,
        generator,
        artifacts,
    })
}

#[cfg(feature = "positive-gate")]
#[allow(clippy::too_many_lines)]
pub(crate) fn parse_positive_input_sources_v2(
    source: &[u8],
) -> Result<B4AuthenticatedPositiveInputSourcesV2> {
    ensure!(
        (2..=1024 * 1024).contains(&source.len()),
        "V2 positive input set is outside its closed byte bound"
    );
    let value = validate_canonical_json_source(source)
        .context("V2 positive input set is not exact canonical JCS")?;
    require_exact_json_keys(
        &value,
        &[
            "format",
            "formatVersion",
            "profile",
            "guest",
            "referenceStatement",
            "sourceLock",
            "proofGenerator",
            "verifierCliContract",
            "validators",
            "runnerProfiles",
            "recursiveCalibrations",
            "positiveCases",
        ],
        "V2 positive input set",
    )?;
    ensure!(
        json_string_field(&value, "format", "V2 positive input set")?
            == "Eip0045B4PositiveInputSetV2"
            && json_u64_field(&value, "formatVersion", "V2 positive input set")? == 2,
        "V2 positive input set has the wrong format identity"
    );

    let profile = json_field(&value, "profile", "V2 positive input set")?;
    let profile_manifest =
        contract_identity_from_value(json_field(profile, "manifest", "V2 input-set profile")?)?;
    let profile_algorithm =
        contract_identity_from_value(json_field(profile, "algorithm", "V2 input-set profile")?)?;
    let profile_constants =
        contract_identity_from_value(json_field(profile, "constants", "V2 input-set profile")?)?;
    require_contract_encoding(
        &profile_manifest,
        B4ContractArtifactEncodingV1::RawBytes,
        "V2 input-set profile manifest",
    )?;
    require_contract_encoding(
        &profile_algorithm,
        B4ContractArtifactEncodingV1::RawBytes,
        "V2 input-set profile algorithm",
    )?;
    require_contract_encoding(
        &profile_constants,
        B4ContractArtifactEncodingV1::RawBytes,
        "V2 input-set profile constants",
    )?;
    let profile_id = json_string_field(profile, "profileId", "V2 input-set profile")?.to_owned();
    validate_digest(&profile_id, "V2 input-set profile ID")?;

    let guest = json_field(&value, "guest", "V2 positive input set")?;
    let guest_elf = contract_identity_from_value(json_field(guest, "elf", "V2 input-set guest")?)?;
    require_contract_encoding(
        &guest_elf,
        B4ContractArtifactEncodingV1::RawBytes,
        "V2 input-set guest ELF",
    )?;
    let guest_image_id = json_string_field(guest, "imageId", "V2 input-set guest")?.to_owned();
    validate_digest(&guest_image_id, "V2 input-set guest image ID")?;

    let reference = json_field(&value, "referenceStatement", "V2 positive input set")?;
    let reference_statement_manifest = contract_identity_from_value(json_field(
        reference,
        "bundleManifest",
        "V2 input-set reference statement",
    )?)?;
    require_contract_encoding(
        &reference_statement_manifest,
        B4ContractArtifactEncodingV1::Rfc8785Jcs,
        "V2 input-set reference-statement manifest",
    )?;
    let reference_contract_id =
        json_string_field(reference, "contractId", "V2 input-set reference statement")?.to_owned();
    validate_digest(&reference_contract_id, "V2 input-set reference contract ID")?;
    let reference_statement_byte_length = json_u64_field(
        reference,
        "statementByteLength",
        "V2 input-set reference statement",
    )?;
    let reference_statement_sha256 = json_string_field(
        reference,
        "statementSha256",
        "V2 input-set reference statement",
    )?
    .to_owned();
    validate_digest(
        &reference_statement_sha256,
        "V2 input-set reference statement SHA-256",
    )?;
    let reference_chain_domain_id = json_string_field(
        reference,
        "chainDomainId",
        "V2 input-set reference statement",
    )?
    .to_owned();
    validate_digest(
        &reference_chain_domain_id,
        "V2 input-set reference chain-domain ID",
    )?;
    let reference_application_payload_byte_length = json_u64_field(
        reference,
        "applicationPayloadByteLength",
        "V2 input-set reference statement",
    )?;
    let reference_application_payload_sha256 = json_string_field(
        reference,
        "applicationPayloadSha256",
        "V2 input-set reference statement",
    )?
    .to_owned();
    validate_digest(
        &reference_application_payload_sha256,
        "V2 input-set reference application-payload SHA-256",
    )?;
    ensure!(
        (STATEMENT_PREFIX_BYTES as u64..=MAX_STATEMENT_BYTES as u64)
            .contains(&reference_statement_byte_length),
        "V2 input-set reference statement byte length is outside the exact statement bounds"
    );
    ensure!(
        reference_application_payload_byte_length <= MAX_APPLICATION_PAYLOAD_BYTES as u64,
        "V2 input-set reference application payload exceeds the exact payload bound"
    );
    ensure!(
        reference_statement_byte_length
            == STATEMENT_PREFIX_BYTES as u64 + reference_application_payload_byte_length,
        "V2 input-set reference statement length does not equal its fixed prefix plus payload"
    );

    let source_lock =
        contract_identity_from_value(json_field(&value, "sourceLock", "V2 positive input set")?)?;
    require_contract_encoding(
        &source_lock,
        B4ContractArtifactEncodingV1::Rfc8785Jcs,
        "V2 input-set source lock",
    )?;
    let proof_generator = json_field(&value, "proofGenerator", "V2 positive input set")?;
    let generator = contract_identity_from_value(json_field(
        proof_generator,
        "artifact",
        "V2 input-set proof generator",
    )?)?;
    require_contract_encoding(
        &generator,
        B4ContractArtifactEncodingV1::RawBytes,
        "V2 input-set proof-generator artifact",
    )?;

    let mut artifacts = BTreeMap::new();
    collect_contract_artifact_identities(&value, &mut artifacts)?;
    for expected in [
        &profile_manifest,
        &profile_algorithm,
        &profile_constants,
        &guest_elf,
        &reference_statement_manifest,
        &source_lock,
        &generator,
    ] {
        ensure!(
            artifacts
                .get(&expected.path)
                .is_some_and(|actual| actual == expected),
            "V2 positive input-set nested identity inventory is incomplete"
        );
    }
    let artifact_paths = artifacts.keys().collect::<Vec<_>>();
    for (index, path) in artifact_paths.iter().enumerate() {
        ensure!(
            !artifact_paths[index + 1..]
                .iter()
                .any(|other| b4_paths_conflict(path, other)),
            "V2 positive input-set nested paths form an ancestor/descendant conflict"
        );
    }

    Ok(B4AuthenticatedPositiveInputSourcesV2 {
        profile_id,
        profile_manifest,
        profile_algorithm,
        profile_constants,
        guest_elf,
        guest_image_id,
        reference_statement_manifest,
        reference_contract_id,
        reference_statement_byte_length,
        reference_statement_sha256,
        reference_chain_domain_id,
        reference_application_payload_byte_length,
        reference_application_payload_sha256,
        source_lock,
        generator,
        artifacts,
    })
}

#[cfg(feature = "positive-gate")]
pub(crate) struct B4AuthenticatedPostproofDocumentsV2 {
    pub(crate) input: B4AuthenticatedPositiveInputSourcesV2,
    pub(crate) generation: B4PositiveGenerationDocumentV2,
    pub(crate) input_set_measurement: FileMeasurement,
    pub(crate) generation_set_measurement: FileMeasurement,
    pub(crate) proof_generator_measurement: FileMeasurement,
}

#[cfg(feature = "positive-gate")]
pub(crate) fn reparse_v2_postproof_documents(
    input_set_jcs: &[u8],
    generation_set_jcs: &[u8],
    proof_generator: B4PositiveSourceBytesV2<'_>,
) -> Result<B4AuthenticatedPostproofDocumentsV2> {
    let input = parse_positive_input_sources_v2(input_set_jcs)?;
    let generation = B4PositiveGenerationDocumentV2::from_canonical_jcs(generation_set_jcs)?;
    let input_set_measurement = generation.authenticate_input_set(input_set_jcs)?;

    let measured_generator = B4ContractArtifactIdentityV1::from_bytes(
        proof_generator.path,
        B4ContractArtifactEncodingV1::RawBytes,
        proof_generator.bytes,
    )?;
    ensure!(
        measured_generator == input.generator,
        "V2 proof-generator path or bytes differ from the positive input set"
    );
    let proof_generator_measurement = FileMeasurement {
        byte_length: measured_generator.byte_length,
        sha256: hex::decode(&measured_generator.sha256)?
            .try_into()
            .map_err(|bytes: Vec<u8>| {
                anyhow::anyhow!(
                    "V2 proof-generator SHA-256 has {} bytes instead of 32",
                    bytes.len()
                )
            })?,
    };
    ensure!(
        proof_generator_measurement == generation.proof_generator_measurement()?,
        "V2 positive generation set binds different proof-generator bytes"
    );
    let generation_set_measurement = FileMeasurement {
        byte_length: u64::try_from(generation_set_jcs.len())?,
        sha256: Sha256::digest(generation_set_jcs).into(),
    };
    Ok(B4AuthenticatedPostproofDocumentsV2 {
        input,
        generation,
        input_set_measurement,
        generation_set_measurement,
        proof_generator_measurement,
    })
}

#[cfg(feature = "positive-gate")]
fn json_field<'a>(value: &'a Value, key: &str, label: &str) -> Result<&'a Value> {
    value
        .as_object()
        .with_context(|| format!("{label} must be a JSON object"))?
        .get(key)
        .with_context(|| format!("{label} lacks `{key}`"))
}

#[cfg(feature = "positive-gate")]
fn json_string_field<'a>(value: &'a Value, key: &str, label: &str) -> Result<&'a str> {
    json_field(value, key, label)?
        .as_str()
        .with_context(|| format!("{label} `{key}` must be a string"))
}

#[cfg(feature = "positive-gate")]
fn json_u64_field(value: &Value, key: &str, label: &str) -> Result<u64> {
    json_field(value, key, label)?
        .as_u64()
        .with_context(|| format!("{label} `{key}` must be an unsigned integer"))
}

#[cfg(feature = "positive-gate")]
fn json_array_field<'a>(value: &'a Value, key: &str, label: &str) -> Result<&'a [Value]> {
    json_field(value, key, label)?
        .as_array()
        .map(Vec::as_slice)
        .with_context(|| format!("{label} `{key}` must be an array"))
}

#[cfg(feature = "positive-gate")]
fn require_exact_json_keys(value: &Value, expected: &[&str], label: &str) -> Result<()> {
    let object = value
        .as_object()
        .with_context(|| format!("{label} must be a JSON object"))?;
    ensure!(
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key)),
        "{label} has missing or unknown fields"
    );
    Ok(())
}

#[cfg(feature = "positive-gate")]
fn contract_identity_from_value(value: &Value) -> Result<B4ContractArtifactIdentityV1> {
    let encoding = match json_string_field(value, "encoding", "artifact identity")? {
        "raw-bytes" => B4ContractArtifactEncodingV1::RawBytes,
        "rfc8785-jcs" => B4ContractArtifactEncodingV1::Rfc8785Jcs,
        "git-bundle" => B4ContractArtifactEncodingV1::GitBundle,
        _ => anyhow::bail!("artifact identity uses an unknown encoding"),
    };
    let identity = B4ContractArtifactIdentityV1 {
        path: json_string_field(value, "path", "artifact identity")?.to_owned(),
        byte_length: json_u64_field(value, "byteLength", "artifact identity")?,
        sha256: json_string_field(value, "sha256", "artifact identity")?.to_owned(),
        encoding,
    };
    identity.validate()?;
    Ok(identity)
}

#[cfg(feature = "positive-gate")]
fn require_contract_encoding(
    identity: &B4ContractArtifactIdentityV1,
    expected: B4ContractArtifactEncodingV1,
    label: &str,
) -> Result<()> {
    ensure!(
        identity.encoding == expected,
        "{label} uses the wrong physical encoding"
    );
    Ok(())
}

#[cfg(feature = "positive-gate")]
fn collect_contract_artifact_identities(
    value: &Value,
    identities: &mut BTreeMap<String, B4ContractArtifactIdentityV1>,
) -> Result<()> {
    match value {
        Value::Object(object)
            if ["path", "byteLength", "sha256", "encoding"]
                .iter()
                .all(|key| object.contains_key(*key)) =>
        {
            let identity = contract_identity_from_value(value)?;
            if let Some(previous) = identities.insert(identity.path.clone(), identity.clone()) {
                ensure!(
                    previous == identity,
                    "positive input set binds one nested path to two byte identities"
                );
            }
        }
        Value::Object(object) => {
            for nested in object.values() {
                collect_contract_artifact_identities(nested, identities)?;
            }
        }
        Value::Array(values) => {
            for nested in values {
                collect_contract_artifact_identities(nested, identities)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

#[cfg(feature = "positive-gate")]
fn authenticate_registry_document_binding(
    binding: &B4ArtifactBinding,
    external: B4NegativeMaterializationExternalBytesV1<'_>,
    encoding: B4ArtifactEncoding,
    label: &str,
) -> Result<()> {
    ensure!(
        binding.state == B4BindingState::Bound
            && binding.encoding == encoding
            && binding.path == external.path
            && binding.byte_length == u64::try_from(external.bytes.len())?
            && binding.sha256 == sha256_hex(external.bytes),
        "{label} identity differs from independently measured bytes"
    );
    Ok(())
}

#[cfg(feature = "positive-gate")]
fn authenticate_registry_quarantine_document_copy(
    binding: &B4ArtifactBinding,
    upstream: B4NegativeMaterializationExternalBytesV1<'_>,
    encoding: B4ArtifactEncoding,
    label: &str,
) -> Result<()> {
    ensure!(
        binding.state == B4BindingState::Bound
            && binding.encoding == encoding
            && binding.path != upstream.path
            && binding
                .path
                .starts_with("reproduction/schema/b4-corpus-v1.candidate/")
            && binding.byte_length == u64::try_from(upstream.bytes.len())?
            && binding.sha256 == sha256_hex(upstream.bytes),
        "{label} quarantine copy differs from independently measured upstream bytes"
    );
    Ok(())
}

#[cfg(feature = "positive-gate")]
fn authenticate_positive_exports(
    prior: &B4MaterializationPriorAuthoritySnapshotV1,
    supplied: &[B4NegativeMaterializationPositiveExportV1<'_>],
) -> Result<Vec<B4AuthenticatedPositiveExportV1>> {
    ensure!(
        supplied.len() == prior.positive_cases.len() && supplied.len() == 11,
        "positive export replay must contain exactly eleven cases"
    );
    let mut authenticated = Vec::with_capacity(supplied.len());
    for (index, (external, expected)) in supplied.iter().zip(&prior.positive_cases).enumerate() {
        ensure!(
            usize::from(external.case_index) == index && usize::from(expected.case_index) == index,
            "positive export order/index drift at index {index}"
        );
        ensure!(
            measure_bytes(external.proof_output_manifest.bytes) == expected.proof_output_manifest,
            "positive proof-output manifest bytes differ from prior authority at index {index}"
        );
        let manifest_maximum = if index < 8 { 8 * 1024 } else { 16 * 1024 };
        ensure!(
            (2..=manifest_maximum).contains(&external.proof_output_manifest.bytes.len()),
            "positive proof-output manifest is outside its closed byte bound at index {index}"
        );
        validate_canonical_json_source(external.proof_output_manifest.bytes).with_context(
            || format!("positive proof-output manifest is not canonical JCS at index {index}"),
        )?;
        ensure!(
            measure_bytes(external.raw_seal.bytes) == expected.raw_seal,
            "positive raw-seal bytes differ from prior authority at index {index}"
        );
        authenticated.push(B4AuthenticatedPositiveExportV1 {
            case_index: external.case_index,
            proof_output_manifest_jcs: external.proof_output_manifest.bytes.to_vec(),
            raw_seal: external.raw_seal.bytes.to_vec(),
            auxiliary_artifacts: Vec::new(),
        });
    }
    Ok(authenticated)
}

#[cfg(feature = "positive-gate")]
fn authenticate_positive_exports_v2(
    positive: &B4PositiveGenerationAuthorityV2,
    registry: &B4CandidateCorpus,
    supplied: &[B4NegativeMaterializationPositiveExportV1<'_>],
    source_artifacts: &[B4NegativeMaterializationExternalBytesV1<'_>],
) -> Result<Vec<B4AuthenticatedPositiveExportV1>> {
    ensure!(
        supplied.len() == 11 && registry.positive_cases.len() == 11,
        "V2 positive export replay must contain exactly eleven cases"
    );
    let source_by_path = source_artifacts
        .iter()
        .map(|source| (source.path, source.bytes))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        source_by_path.len() == source_artifacts.len(),
        "V2 source-artifact inventory contains a duplicate path"
    );

    let mut retained = Vec::with_capacity(11);
    for (case_index, (external, registry_case)) in
        supplied.iter().zip(&registry.positive_cases).enumerate()
    {
        ensure!(
            usize::from(external.case_index) == case_index
                && usize::from(registry_case.index) == case_index,
            "V2 positive export order/index drift at index {case_index}"
        );
        let case_id = compiled_positive_case_id(case_index)?;
        let manifest_name = if case_index < 8 {
            "candidate-proof-output-manifest.json"
        } else {
            "candidate-recursive-output-manifest.json"
        };
        ensure!(
            registry_case.case_id == case_id
                && external.proof_output_manifest.path
                    == crate::b4::canonical_positive_case_artifact_path(&case_id, manifest_name),
            "V2 positive manifest path or registry case ID drift at index {case_index}"
        );
        let measurements = positive.case_materialization_measurements(case_index)?;
        ensure!(
            measure_bytes(external.proof_output_manifest.bytes)
                == measurements.proof_output_manifest()
                && measure_bytes(external.raw_seal.bytes) == measurements.raw_seal(),
            "V2 positive materialization bytes differ from retained case measurements at index {case_index}"
        );

        let primary_artifacts = registry_case
            .artifacts
            .iter()
            .map(|artifact| {
                let bytes = if artifact.role == B4PositiveArtifactRole::RawSeal {
                    ensure!(
                        external.raw_seal.path == artifact.path,
                        "V2 positive raw-seal path differs from the registry at index {case_index}"
                    );
                    external.raw_seal.bytes
                } else {
                    source_by_path
                        .get(artifact.path.as_str())
                        .copied()
                        .with_context(|| {
                            format!(
                                "V2 positive primary source is absent at index {case_index}: {}",
                                artifact.path
                            )
                        })?
                };
                Ok(B4PositiveSourceBytesV2 {
                    path: &artifact.path,
                    bytes,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let auxiliary_artifacts = positive_auxiliary_artifact_paths(case_index)?
            .into_iter()
            .map(|path| {
                let bytes = source_by_path.get(path).copied().with_context(|| {
                    format!("V2 positive auxiliary source is absent at index {case_index}: {path}")
                })?;
                Ok(B4PositiveSourceBytesV2 {
                    path: source_artifacts
                        .iter()
                        .find(|source| source.path == *path)
                        .map(|source| source.path)
                        .context("V2 auxiliary source path lookup drifted")?,
                    bytes,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let authenticated = positive.authenticate_case(
            case_index,
            B4PositiveCaseSourceV2 {
                proof_output_manifest_jcs: external.proof_output_manifest.bytes,
                primary_artifacts: &primary_artifacts,
                auxiliary_artifacts: &auxiliary_artifacts,
            },
        )?;
        ensure!(
            authenticated.proof_output_manifest() == measurements.proof_output_manifest()
                && measure_bytes(authenticated.raw_seal()) == measurements.raw_seal(),
            "V2 selected-case authentication differs from retained materialization measurements"
        );
        retained.push(B4AuthenticatedPositiveExportV1 {
            case_index: external.case_index,
            proof_output_manifest_jcs: external.proof_output_manifest.bytes.to_vec(),
            raw_seal: authenticated.raw_seal().to_vec(),
            auxiliary_artifacts: authenticated
                .auxiliary_artifacts()
                .iter()
                .map(|artifact| {
                    Ok(B4AuthenticatedPositiveAuxiliaryArtifactV1 {
                        path: artifact.path.to_owned(),
                        byte_length: u64::try_from(artifact.bytes.len())?,
                        sha256: sha256_hex(artifact.bytes),
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        });
    }
    Ok(retained)
}

#[cfg(feature = "positive-gate")]
#[allow(clippy::too_many_lines)]
fn authenticate_positive_generation_closure(
    source: &[u8],
    registry: &B4CandidateCorpus,
    prior: &B4MaterializationPriorAuthoritySnapshotV1,
    authenticated: &mut [B4AuthenticatedPositiveExportV1],
    supplied: &[B4NegativeMaterializationPositiveExportV1<'_>],
) -> Result<()> {
    let generation_set = validate_canonical_json_source(source)
        .context("positive generation set is not exact canonical JCS")?;
    require_exact_json_keys(
        &generation_set,
        &[
            "format",
            "formatVersion",
            "inputSetCommitment",
            "proofGeneratorArtifact",
            "cases",
        ],
        "positive generation set",
    )?;
    ensure!(
        json_string_field(&generation_set, "format", "positive generation set")?
            == "Eip0045B4PositiveGenerationSetV1"
            && json_u64_field(&generation_set, "formatVersion", "positive generation set")? == 1,
        "positive generation set has the wrong format identity"
    );

    let input_set = json_field(
        &generation_set,
        "inputSetCommitment",
        "positive generation set",
    )?;
    require_exact_json_keys(
        input_set,
        &["format", "byteLength", "sha256", "encoding"],
        "positive generation input-set commitment",
    )?;
    ensure!(
        json_string_field(
            input_set,
            "format",
            "positive generation input-set commitment"
        )? == "Eip0045B4PositiveInputSetV1"
            && json_u64_field(
                input_set,
                "byteLength",
                "positive generation input-set commitment"
            )? == prior.positive_input_set.byte_length
            && json_string_field(
                input_set,
                "sha256",
                "positive generation input-set commitment"
            )? == prior.positive_input_set.sha256
            && json_string_field(
                input_set,
                "encoding",
                "positive generation input-set commitment"
            )? == "rfc8785-jcs"
            && prior.positive_input_set.encoding == B4ContractArtifactEncodingV1::Rfc8785Jcs,
        "positive generation set differs from the prior input-set authority"
    );

    let generator = json_field(
        &generation_set,
        "proofGeneratorArtifact",
        "positive generation set",
    )?;
    require_exact_json_keys(
        generator,
        &["byteLength", "sha256", "encoding"],
        "positive generation proof-generator commitment",
    )?;
    ensure!(
        json_u64_field(
            generator,
            "byteLength",
            "positive generation proof-generator commitment"
        )? == prior.generator.byte_length
            && json_string_field(
                generator,
                "sha256",
                "positive generation proof-generator commitment"
            )? == prior.generator.sha256
            && json_string_field(
                generator,
                "encoding",
                "positive generation proof-generator commitment"
            )? == "raw-bytes"
            && prior.generator.encoding == B4ContractArtifactEncodingV1::RawBytes,
        "positive generation set differs from the prior proof-generator authority"
    );

    let generated_cases = json_array_field(&generation_set, "cases", "positive generation set")?;
    ensure!(
        generated_cases.len() == 11
            && registry.positive_cases.len() == 11
            && prior.positive_cases.len() == 11
            && authenticated.len() == 11
            && supplied.len() == 11,
        "positive generation closure must contain exactly eleven cases"
    );

    for index in 0..11 {
        let generated_case = &generated_cases[index];
        let registry_case = &registry.positive_cases[index];
        let expected = &prior.positive_cases[index];
        let retained = &mut authenticated[index];
        let external = &supplied[index];
        ensure!(
            usize::from(registry_case.index) == index
                && usize::from(retained.case_index) == index
                && usize::from(external.case_index) == index,
            "positive generation case order/index drift at index {index}"
        );
        ensure!(
            retained.proof_output_manifest_jcs == external.proof_output_manifest.bytes
                && retained.raw_seal == external.raw_seal.bytes
                && measure_bytes(&retained.proof_output_manifest_jcs)
                    == expected.proof_output_manifest
                && measure_bytes(&retained.raw_seal) == expected.raw_seal,
            "positive export replay differs from the prior authority at index {index}"
        );

        let manifest_identity = json_field(
            generated_case,
            "proofOutputManifest",
            "positive generation case",
        )?;
        let expected_manifest_name = if index < 8 {
            "candidate-proof-output-manifest.json"
        } else {
            "candidate-recursive-output-manifest.json"
        };
        ensure!(
            json_string_field(
                manifest_identity,
                "fileName",
                "positive proof-output manifest identity"
            )? == expected_manifest_name
                && external
                    .proof_output_manifest
                    .path
                    .rsplit('/')
                    .next()
                    .is_some_and(|name| name == expected_manifest_name),
            "positive proof-output manifest physical filename drift at index {index}"
        );

        retained.auxiliary_artifacts = authenticate_positive_generation_case(
            index,
            generated_case,
            registry_case,
            &retained.proof_output_manifest_jcs,
            external.raw_seal.path,
            &retained.raw_seal,
        )
        .with_context(|| format!("positive generation closure failed for case index {index}"))?;
    }
    Ok(())
}

#[cfg(feature = "positive-gate")]
pub(crate) const LIFT_POSITIVE_ARTIFACT_LAYOUT: [(B4PositiveArtifactRole, &str); 7] = [
    (
        B4PositiveArtifactRole::ClaimDigest,
        "candidate-claim-digest.bin",
    ),
    (
        B4PositiveArtifactRole::ControlId,
        "candidate-control-id.bin",
    ),
    (B4PositiveArtifactRole::ImageId, "candidate-image-id.bin"),
    (B4PositiveArtifactRole::Journal, "candidate-journal.bin"),
    (B4PositiveArtifactRole::Metadata, "candidate-metadata.json"),
    (B4PositiveArtifactRole::RawSeal, "candidate-raw-seal.bin"),
    (
        B4PositiveArtifactRole::ReceiptOracle,
        "candidate-receipt-oracle.bincode",
    ),
];

#[cfg(feature = "positive-gate")]
pub(crate) const RECURSIVE_POSITIVE_ARTIFACT_LAYOUT: [(B4PositiveArtifactRole, &str); 8] = [
    (B4PositiveArtifactRole::Ancestry, "candidate-ancestry.json"),
    (
        B4PositiveArtifactRole::Calibration,
        "candidate-recursive-calibration.json",
    ),
    (
        B4PositiveArtifactRole::ClaimDigest,
        "candidate-claim-digest.bin",
    ),
    (
        B4PositiveArtifactRole::ControlId,
        "candidate-control-id.bin",
    ),
    (B4PositiveArtifactRole::ImageId, "candidate-image-id.bin"),
    (B4PositiveArtifactRole::Journal, "candidate-journal.bin"),
    (B4PositiveArtifactRole::RawSeal, "candidate-raw-seal.bin"),
    (
        B4PositiveArtifactRole::ReceiptOracle,
        "candidate-recursive-oracle.borsh",
    ),
];

#[cfg(feature = "positive-gate")]
pub(crate) fn positive_artifact_layout(
    case_index: usize,
) -> Result<&'static [(B4PositiveArtifactRole, &'static str)]> {
    match case_index {
        0..=7 => Ok(&LIFT_POSITIVE_ARTIFACT_LAYOUT),
        8..=10 => Ok(&RECURSIVE_POSITIVE_ARTIFACT_LAYOUT),
        _ => anyhow::bail!("positive generation case index is outside the closed eleven-case plan"),
    }
}

#[cfg(feature = "positive-gate")]
pub(crate) fn positive_artifact_role_name(role: B4PositiveArtifactRole) -> &'static str {
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

#[cfg(feature = "positive-gate")]
pub(crate) fn positive_artifact_encoding(
    role: B4PositiveArtifactRole,
) -> (&'static str, B4ArtifactEncoding) {
    if matches!(
        role,
        B4PositiveArtifactRole::Ancestry
            | B4PositiveArtifactRole::Calibration
            | B4PositiveArtifactRole::Metadata
    ) {
        ("rfc8785-jcs", B4ArtifactEncoding::Rfc8785Jcs)
    } else {
        ("raw-bytes", B4ArtifactEncoding::RawBytes)
    }
}

#[cfg(feature = "positive-gate")]
pub(crate) fn validate_positive_artifact_length(
    case_index: usize,
    role: B4PositiveArtifactRole,
    byte_length: u64,
) -> Result<()> {
    let accepted = match role {
        B4PositiveArtifactRole::Ancestry => (2..=65_536).contains(&byte_length),
        B4PositiveArtifactRole::Calibration => (2..=4_096).contains(&byte_length),
        B4PositiveArtifactRole::ClaimDigest
        | B4PositiveArtifactRole::ControlId
        | B4PositiveArtifactRole::ImageId => byte_length == 32,
        B4PositiveArtifactRole::Journal => (159..=16_543).contains(&byte_length),
        B4PositiveArtifactRole::Metadata => (2..=16_384).contains(&byte_length),
        B4PositiveArtifactRole::RawSeal => byte_length == PROOF_BYTES as u64,
        B4PositiveArtifactRole::ReceiptOracle if case_index < 8 => {
            (1..=RECEIPT_ORACLE_MAX_BYTES as u64).contains(&byte_length)
        }
        B4PositiveArtifactRole::ReceiptOracle => (1..=33_554_432).contains(&byte_length),
    };
    ensure!(
        accepted,
        "positive generated {} artifact has an invalid byte length",
        positive_artifact_role_name(role)
    );
    Ok(())
}

/// Return the exact compiled positive-case ID for one closed ordinal.
#[cfg(feature = "positive-gate")]
pub(crate) fn compiled_positive_case_id(case_index: usize) -> Result<String> {
    let registry = B4CandidateCorpus::from_canonical_jcs(include_bytes!(
        "../schema/b4-corpus-v1.candidate.json"
    ))?;
    registry
        .positive_cases
        .get(case_index)
        .map(|case| case.case_id.clone())
        .context("positive case index is outside the closed eleven-case plan")
}

#[cfg(feature = "positive-gate")]
pub(crate) fn compiled_positive_generation_recipe(case_index: usize) -> Result<Value> {
    Ok(match case_index {
        0..=7 => serde_json::json!({
            "kind": "lift",
            "segmentPo2": 15 + case_index,
        }),
        8 => serde_json::json!({"kind": "recursive", "family": "terminal-join"}),
        9 => serde_json::json!({"kind": "recursive", "family": "terminal-resolve"}),
        10 => serde_json::json!({"kind": "recursive", "family": "resolve-then-join"}),
        _ => anyhow::bail!("positive generation case index is outside the closed plan"),
    })
}

#[cfg(feature = "positive-gate")]
#[allow(clippy::too_many_lines)]
fn authenticate_positive_generation_case(
    index: usize,
    generated_case: &Value,
    registry_case: &B4PositiveCase,
    manifest_jcs: &[u8],
    raw_seal_path: &str,
    raw_seal: &[u8],
) -> Result<Vec<B4AuthenticatedPositiveAuxiliaryArtifactV1>> {
    require_exact_json_keys(
        generated_case,
        &[
            "caseIndex",
            "caseId",
            "generation",
            "proofOutputManifest",
            "artifacts",
        ],
        "positive generation case",
    )?;
    ensure!(
        json_u64_field(generated_case, "caseIndex", "positive generation case")?
            == u64::try_from(index)?
            && usize::from(registry_case.index) == index
            && json_string_field(generated_case, "caseId", "positive generation case")?
                == registry_case.case_id,
        "positive generated case differs from the registry case order or ID"
    );
    ensure!(
        json_field(generated_case, "generation", "positive generation case")?
            == &compiled_positive_generation_recipe(index)?,
        "positive generated case differs from the exact closed generation recipe"
    );

    let layout = positive_artifact_layout(index)?;
    let generated_artifacts =
        json_array_field(generated_case, "artifacts", "positive generation case")?;
    ensure!(
        generated_artifacts.len() == layout.len() && registry_case.artifacts.len() == layout.len(),
        "positive generation artifact cardinality differs from the exact closed layout"
    );

    let manifest_identity = json_field(
        generated_case,
        "proofOutputManifest",
        "positive generation case",
    )?;
    require_exact_json_keys(
        manifest_identity,
        &["fileName", "byteLength", "sha256", "encoding"],
        "positive proof-output manifest identity",
    )?;
    let (manifest_name, manifest_maximum) = if index < 8 {
        ("candidate-proof-output-manifest.json", 8 * 1024)
    } else {
        ("candidate-recursive-output-manifest.json", 16 * 1024)
    };
    ensure!(
        (2..=manifest_maximum).contains(&manifest_jcs.len()),
        "positive proof-output manifest is outside its closed byte bound"
    );
    ensure!(
        json_string_field(
            manifest_identity,
            "fileName",
            "positive proof-output manifest identity"
        )? == manifest_name
            && json_u64_field(
                manifest_identity,
                "byteLength",
                "positive proof-output manifest identity"
            )? == u64::try_from(manifest_jcs.len())?
            && json_string_field(
                manifest_identity,
                "sha256",
                "positive proof-output manifest identity"
            )? == sha256_hex(manifest_jcs)
            && json_string_field(
                manifest_identity,
                "encoding",
                "positive proof-output manifest identity"
            )? == "rfc8785-jcs",
        "positive proof-output manifest identity differs from the authenticated bytes"
    );
    let manifest_value = validate_canonical_json_source(manifest_jcs)
        .context("positive proof-output manifest is not exact canonical JCS")?;
    let manifest: ProofOutputManifest = serde_json::from_value(manifest_value)
        .context("positive proof-output manifest has the wrong shape")?;
    validate_manifest_shape(&manifest)?;
    let auxiliary_paths = positive_auxiliary_artifact_paths(index)?;
    ensure!(
        manifest.len() == layout.len() + auxiliary_paths.len(),
        "positive proof-output manifest has the wrong exact file count"
    );

    for (position, (expected_role, expected_file)) in layout.iter().copied().enumerate() {
        let generated = &generated_artifacts[position];
        let role_name = positive_artifact_role_name(expected_role);
        let expected_keys: &[&str] = if matches!(
            expected_role,
            B4PositiveArtifactRole::ClaimDigest
                | B4PositiveArtifactRole::ControlId
                | B4PositiveArtifactRole::ImageId
        ) {
            &[
                "role",
                "sourceFile",
                "byteLength",
                "sha256",
                "encoding",
                "contentHex",
            ]
        } else if expected_role == B4PositiveArtifactRole::ReceiptOracle {
            &[
                "role",
                "sourceFile",
                "byteLength",
                "sha256",
                "encoding",
                "codec",
            ]
        } else {
            &["role", "sourceFile", "byteLength", "sha256", "encoding"]
        };
        require_exact_json_keys(
            generated,
            expected_keys,
            &format!("positive generated {role_name} artifact"),
        )?;
        ensure!(
            json_string_field(generated, "role", "positive generated artifact")? == role_name
                && json_string_field(generated, "sourceFile", "positive generated artifact")?
                    == expected_file,
            "positive generated artifact order, role, or source filename drift"
        );
        let generated_length =
            json_u64_field(generated, "byteLength", "positive generated artifact")?;
        let generated_sha256 =
            json_string_field(generated, "sha256", "positive generated artifact")?;
        validate_digest(generated_sha256, "positive generated artifact SHA-256")?;
        validate_positive_artifact_length(index, expected_role, generated_length)?;
        let (encoding_name, registry_encoding) = positive_artifact_encoding(expected_role);
        ensure!(
            json_string_field(generated, "encoding", "positive generated artifact")?
                == encoding_name,
            "positive generated artifact has the wrong encoding"
        );

        let registry_artifact = &registry_case.artifacts[position];
        validate_safe_relative_path(&registry_artifact.path)?;
        ensure!(
            registry_artifact.role == expected_role
                && registry_artifact.encoding == registry_encoding
                && registry_artifact.byte_length == generated_length
                && registry_artifact.sha256 == generated_sha256,
            "expanded-registry positive artifact differs from the generation authority"
        );

        let mut manifest_entries = manifest.iter().filter(|entry| entry.path == expected_file);
        let manifest_entry = manifest_entries
            .next()
            .context("positive proof-output manifest lacks a generated artifact")?;
        ensure!(
            manifest_entries.next().is_none()
                && manifest_entry.length == generated_length.to_string()
                && manifest_entry.sha256 == generated_sha256,
            "positive proof-output manifest entry differs from the generation authority"
        );

        if matches!(
            expected_role,
            B4PositiveArtifactRole::ClaimDigest
                | B4PositiveArtifactRole::ControlId
                | B4PositiveArtifactRole::ImageId
        ) {
            let content = hex::decode(json_string_field(
                generated,
                "contentHex",
                "positive generated digest artifact",
            )?)
            .context("positive generated digest content is not hexadecimal")?;
            ensure!(
                content.len() == 32 && sha256_hex(&content) == generated_sha256,
                "positive generated digest content differs from its artifact identity"
            );
        }
        if expected_role == B4PositiveArtifactRole::ReceiptOracle {
            let expected_codec = if index < 8 {
                "bincode-1.3.3-little-endian-fixed-int-reject-trailing"
            } else {
                "eip0045-recursive-oracle-borsh-v1"
            };
            ensure!(
                json_string_field(generated, "codec", "positive generated receipt oracle")?
                    == expected_codec,
                "positive generated receipt oracle has the wrong codec"
            );
        }
        if expected_role == B4PositiveArtifactRole::RawSeal {
            ensure!(
                registry_artifact.path == raw_seal_path
                    && u64::try_from(raw_seal.len())? == generated_length
                    && sha256_hex(raw_seal) == generated_sha256,
                "positive raw seal differs across generation, registry, manifest, or physical replay"
            );
        }
    }
    ensure!(
        manifest.iter().all(|entry| {
            layout
                .iter()
                .any(|(_, expected_file)| entry.path == *expected_file)
                || auxiliary_paths.contains(&entry.path.as_str())
        }),
        "positive proof-output manifest contains an artifact outside the closed layout"
    );
    let mut auxiliary_artifacts = Vec::with_capacity(auxiliary_paths.len());
    for expected_path in auxiliary_paths {
        let mut entries = manifest.iter().filter(|entry| entry.path == *expected_path);
        let entry = entries
            .next()
            .context("positive proof-output manifest lacks a recursive auxiliary artifact")?;
        ensure!(
            entries.next().is_none(),
            "positive proof-output manifest duplicates a recursive auxiliary artifact"
        );
        let byte_length = parse_canonical_decimal_u64(
            &entry.length,
            "positive recursive auxiliary artifact length",
        )?;
        ensure!(
            byte_length == PROOF_BYTES as u64,
            "positive recursive auxiliary raw seal has the wrong exact byte length"
        );
        validate_digest(
            &entry.sha256,
            "positive recursive auxiliary artifact SHA-256",
        )?;
        auxiliary_artifacts.push(B4AuthenticatedPositiveAuxiliaryArtifactV1 {
            path: entry.path.clone(),
            byte_length,
            sha256: entry.sha256.clone(),
        });
    }
    Ok(auxiliary_artifacts)
}

#[cfg(feature = "positive-gate")]
fn authenticate_registry_prior_bindings(
    registry: &B4CandidateCorpus,
    input: &B4AuthenticatedPositiveInputSourcesV1,
    prior: &B4MaterializationPriorAuthoritySnapshotV1,
) -> Result<()> {
    authenticate_generator_executor_content_identity(
        &input.generator,
        &prior.generator,
        "positive input set and campaign-precommit authority",
    )?;
    authenticate_registry_prior_quarantine_copy(
        &registry.bindings.generator,
        &input.generator,
        "expanded-registry generator",
    )?;
    authenticate_registry_prior_quarantine_copy(
        &registry.bindings.guest.elf,
        &input.guest_elf,
        "expanded-registry guest ELF",
    )?;
    authenticate_registry_prior_quarantine_copy(
        &registry.bindings.reference_statement_bundle.manifest,
        &input.reference_statement_manifest,
        "expanded-registry reference-statement manifest",
    )?;
    authenticate_registry_prior_quarantine_copy(
        &registry.bindings.source_lock,
        &input.source_lock,
        "expanded-registry source lock",
    )?;
    authenticate_registry_prior_quarantine_copy(
        &registry.bindings.rust_verifier,
        &prior.rust_verifier,
        "expanded-registry Rust verifier",
    )?;
    authenticate_registry_prior_quarantine_copy(
        &registry.bindings.jvm_verifier,
        &prior.jvm_verifier,
        "expanded-registry JVM verifier",
    )?;
    authenticate_registry_prior_binding(
        &registry.profile.manifest,
        &input.profile_manifest,
        "expanded-registry profile manifest",
    )?;
    ensure!(
        registry.profile.profile_id == input.profile_id,
        "expanded registry and positive input set bind different profile IDs"
    );
    ensure!(
        registry.bindings.guest.state == B4BindingState::Bound
            && registry.bindings.guest.image_id == input.guest_image_id,
        "expanded registry and positive input set bind different guest image IDs"
    );
    ensure!(
        registry.bindings.reference_statement_bundle.state == B4BindingState::Bound
            && registry.bindings.reference_statement_bundle.contract_id
                == input.reference_contract_id
            && registry
                .bindings
                .reference_statement_bundle
                .statement_sha256
                == input.reference_statement_sha256,
        "expanded registry and positive input set bind different reference statements"
    );
    Ok(())
}

#[cfg(feature = "positive-gate")]
fn authenticate_registry_prior_bindings_v2(
    registry: &B4CandidateCorpus,
    input: &B4AuthenticatedPositiveInputSourcesV2,
    prior: &B4MaterializationPriorAuthoritySnapshotV2,
) -> Result<()> {
    authenticate_generator_executor_content_identity(
        &input.generator,
        &prior.generator,
        "V2 positive input set and campaign-precommit authority",
    )?;
    for (binding, expected, label) in [
        (
            &registry.bindings.generator,
            &input.generator,
            "V2 expanded-registry generator",
        ),
        (
            &registry.bindings.guest.elf,
            &input.guest_elf,
            "V2 expanded-registry guest ELF",
        ),
        (
            &registry.bindings.reference_statement_bundle.manifest,
            &input.reference_statement_manifest,
            "V2 expanded-registry reference-statement manifest",
        ),
        (
            &registry.bindings.source_lock,
            &input.source_lock,
            "V2 expanded-registry source lock",
        ),
        (
            &registry.bindings.rust_verifier,
            &prior.rust_verifier,
            "V2 expanded-registry Rust verifier",
        ),
        (
            &registry.bindings.jvm_verifier,
            &prior.jvm_verifier,
            "V2 expanded-registry JVM verifier",
        ),
    ] {
        authenticate_registry_prior_quarantine_copy(binding, expected, label)?;
    }
    authenticate_registry_prior_binding(
        &registry.profile.manifest,
        &input.profile_manifest,
        "V2 expanded-registry profile manifest",
    )?;
    ensure!(
        registry.profile.profile_id == input.profile_id
            && registry.bindings.guest.state == B4BindingState::Bound
            && registry.bindings.guest.image_id == input.guest_image_id
            && registry.bindings.reference_statement_bundle.state == B4BindingState::Bound
            && registry.bindings.reference_statement_bundle.contract_id
                == input.reference_contract_id
            && registry
                .bindings
                .reference_statement_bundle
                .statement_sha256
                == input.reference_statement_sha256,
        "V2 expanded registry differs from positive input semantic bindings"
    );
    Ok(())
}

#[cfg(feature = "positive-gate")]
fn authenticate_registry_prior_binding(
    binding: &B4ArtifactBinding,
    expected: &B4ContractArtifactIdentityV1,
    label: &str,
) -> Result<()> {
    let expected_encoding = match expected.encoding {
        B4ContractArtifactEncodingV1::RawBytes => B4ArtifactEncoding::RawBytes,
        B4ContractArtifactEncodingV1::Rfc8785Jcs => B4ArtifactEncoding::Rfc8785Jcs,
        B4ContractArtifactEncodingV1::GitBundle => {
            anyhow::bail!("{label} cannot bind a Git bundle")
        }
    };
    ensure!(
        binding.state == B4BindingState::Bound
            && binding.path == expected.path
            && binding.byte_length == expected.byte_length
            && binding.sha256 == expected.sha256
            && binding.encoding == expected_encoding,
        "{label} differs from the authenticated prior authority"
    );
    Ok(())
}

#[cfg(feature = "positive-gate")]
fn authenticate_generator_executor_content_identity(
    generator: &B4ContractArtifactIdentityV1,
    executor: &B4ContractArtifactIdentityV1,
    label: &str,
) -> Result<()> {
    ensure!(
        generator.encoding == B4ContractArtifactEncodingV1::RawBytes
            && executor.encoding == B4ContractArtifactEncodingV1::RawBytes
            && generator.path != executor.path
            && generator.byte_length == executor.byte_length
            && generator.sha256 == executor.sha256,
        "{label} bind different generator/executor content identities"
    );
    Ok(())
}

#[cfg(feature = "positive-gate")]
fn authenticate_registry_prior_quarantine_copy(
    binding: &B4ArtifactBinding,
    expected: &B4ContractArtifactIdentityV1,
    label: &str,
) -> Result<()> {
    let expected_encoding = match expected.encoding {
        B4ContractArtifactEncodingV1::RawBytes => B4ArtifactEncoding::RawBytes,
        B4ContractArtifactEncodingV1::Rfc8785Jcs => B4ArtifactEncoding::Rfc8785Jcs,
        B4ContractArtifactEncodingV1::GitBundle => {
            anyhow::bail!("{label} cannot bind a Git bundle")
        }
    };
    ensure!(
        binding.state == B4BindingState::Bound,
        "{label} quarantine copy is unbound"
    );
    ensure!(
        binding
            .path
            .starts_with("reproduction/schema/b4-corpus-v1.candidate/"),
        "{label} quarantine copy is outside its quarantine tree"
    );
    ensure!(
        binding.path != expected.path,
        "{label} quarantine copy aliases the authenticated prior authority"
    );
    ensure!(
        binding.byte_length == expected.byte_length
            && binding.sha256 == expected.sha256
            && binding.encoding == expected_encoding,
        "{label} quarantine copy differs from the authenticated prior authority"
    );
    Ok(())
}

#[cfg(feature = "positive-gate")]
fn authenticate_subject_catalog(
    catalog: &Eip0045B4SubjectCatalogV1,
    registry: &B4CandidateCorpus,
    negative_plan_jcs: &[u8],
    prior: &B4MaterializationPriorAuthoritySnapshotV1,
) -> Result<()> {
    let plan_sha256 = sha256_hex(negative_plan_jcs);
    let mut positive_case_index = 0_usize;
    for entry in &catalog.subjects {
        match &entry.provenance {
            B4SubjectProvenanceV1::PositiveProjection {
                positive_case_count,
            } => ensure!(
                usize::from(*positive_case_count) == prior.positive_cases.len(),
                "subject catalog positive projection count drift"
            ),
            B4SubjectProvenanceV1::NegativePlan {
                plan_sha256: actual,
            }
            | B4SubjectProvenanceV1::NegativeClasses {
                plan_sha256: actual,
            } => ensure!(
                actual == &plan_sha256,
                "subject catalog negative projection binds a different plan"
            ),
            B4SubjectProvenanceV1::ProfilePackage { profile_id } => ensure!(
                profile_id == &registry.profile.profile_id,
                "subject catalog and expanded registry bind different profile IDs"
            ),
            B4SubjectProvenanceV1::ProofChunks {
                case_id,
                raw_seal_sha256,
            } => {
                let case = registry
                    .positive_cases
                    .get(positive_case_index)
                    .context("subject catalog has too many proof-chunk rows")?;
                let expected = prior
                    .positive_cases
                    .get(positive_case_index)
                    .context("positive authority has too few cases")?;
                ensure!(
                    case_id == &case.case_id
                        && raw_seal_sha256 == &hex::encode(expected.raw_seal.sha256),
                    "subject catalog proof-chunk provenance drift at positive index {positive_case_index}"
                );
                positive_case_index += 1;
            }
        }
    }
    ensure!(
        positive_case_index == prior.positive_cases.len(),
        "subject catalog does not bind all eleven positive raw seals"
    );
    Ok(())
}

#[cfg(feature = "positive-gate")]
fn authenticate_subject_catalog_v2(
    catalog: &Eip0045B4SubjectCatalogV1,
    registry: &B4CandidateCorpus,
    negative_plan_jcs: &[u8],
    prior: &B4MaterializationPriorAuthoritySnapshotV2,
) -> Result<()> {
    let plan_sha256 = sha256_hex(negative_plan_jcs);
    let mut positive_case_index = 0_usize;
    for entry in &catalog.subjects {
        match &entry.provenance {
            B4SubjectProvenanceV1::PositiveProjection {
                positive_case_count,
            } => ensure!(
                usize::from(*positive_case_count) == prior.positive_cases.len(),
                "V2 subject catalog positive projection count drift"
            ),
            B4SubjectProvenanceV1::NegativePlan {
                plan_sha256: actual,
            }
            | B4SubjectProvenanceV1::NegativeClasses {
                plan_sha256: actual,
            } => ensure!(
                actual == &plan_sha256,
                "V2 subject catalog negative projection binds a different plan"
            ),
            B4SubjectProvenanceV1::ProfilePackage { profile_id } => ensure!(
                profile_id == &registry.profile.profile_id,
                "V2 subject catalog and expanded registry bind different profile IDs"
            ),
            B4SubjectProvenanceV1::ProofChunks {
                case_id,
                raw_seal_sha256,
            } => {
                let case = registry
                    .positive_cases
                    .get(positive_case_index)
                    .context("V2 subject catalog has too many proof-chunk rows")?;
                let expected = prior
                    .positive_cases
                    .get(positive_case_index)
                    .context("V2 positive authority has too few cases")?;
                ensure!(
                    case_id == &case.case_id
                        && raw_seal_sha256 == &hex::encode(expected.raw_seal.sha256),
                    "V2 subject catalog proof-chunk provenance drift at positive index {positive_case_index}"
                );
                positive_case_index += 1;
            }
        }
    }
    ensure!(
        positive_case_index == prior.positive_cases.len(),
        "V2 subject catalog does not bind all eleven positive raw seals"
    );
    Ok(())
}

#[cfg(feature = "positive-gate")]
#[allow(clippy::too_many_lines)]
fn authenticate_source_artifacts(
    registry: &B4CandidateCorpus,
    subject_catalog: &Eip0045B4SubjectCatalogV1,
    terminal_catalog: &Eip0045B4TerminalFixtureCatalogV1,
    positive_input: &B4AuthenticatedPositiveInputSourcesV1,
    positive_exports: &[B4AuthenticatedPositiveExportV1],
    supplied: &[B4NegativeMaterializationExternalBytesV1<'_>],
    paths: &mut B4PhysicalPathClosureV1,
) -> Result<BTreeMap<String, Vec<u8>>> {
    authenticate_source_artifacts_with_terminal_fixtures(
        registry,
        subject_catalog,
        &terminal_catalog.fixtures,
        positive_input,
        positive_exports,
        supplied,
        paths,
    )
}

#[cfg(feature = "positive-gate")]
#[allow(clippy::too_many_lines)]
fn authenticate_source_artifacts_with_terminal_fixtures(
    registry: &B4CandidateCorpus,
    subject_catalog: &Eip0045B4SubjectCatalogV1,
    terminal_fixtures: &[crate::b4_terminal::B4TerminalFixtureV1],
    positive_input: &B4AuthenticatedPositiveInputSourcesV1,
    positive_exports: &[B4AuthenticatedPositiveExportV1],
    supplied: &[B4NegativeMaterializationExternalBytesV1<'_>],
    paths: &mut B4PhysicalPathClosureV1,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut expected = BTreeMap::new();
    for identity in [
        &positive_input.profile_manifest,
        &positive_input.profile_algorithm,
        &positive_input.profile_constants,
        &positive_input.guest_elf,
        &positive_input.reference_statement_manifest,
        &positive_input.source_lock,
        &positive_input.generator,
    ] {
        insert_expected_source(
            &mut expected,
            &identity.path,
            identity.byte_length,
            &identity.sha256,
            "required positive-input source",
        )?;
    }
    for identity in positive_input.artifacts.values() {
        insert_expected_source(
            &mut expected,
            &identity.path,
            identity.byte_length,
            &identity.sha256,
            "positive-input nested source",
        )?;
    }
    for binding in [
        &registry.bindings.generator,
        &registry.bindings.guest.elf,
        &registry.bindings.jvm_verifier,
        &registry.bindings.negative_plan,
        &registry.bindings.reference_statement_bundle.manifest,
        &registry.bindings.rust_verifier,
        &registry.bindings.source_lock,
        &registry.profile.manifest,
    ] {
        ensure!(
            binding.state == B4BindingState::Bound,
            "expanded registry contains an unbound nested source path"
        );
        insert_expected_source(
            &mut expected,
            &binding.path,
            binding.byte_length,
            &binding.sha256,
            "expanded-registry binding",
        )?;
    }
    for artifact in registry
        .positive_cases
        .iter()
        .flat_map(|case| case.artifacts.iter())
        .filter(|artifact| artifact.role != B4PositiveArtifactRole::RawSeal)
    {
        insert_expected_source(
            &mut expected,
            &artifact.path,
            artifact.byte_length,
            &artifact.sha256,
            "expanded-registry positive artifact",
        )?;
    }
    ensure!(
        positive_exports.len() == registry.positive_cases.len(),
        "authenticated positive-export inventory differs from the registry cardinality"
    );
    for (case_index, export) in positive_exports.iter().enumerate() {
        ensure!(
            usize::from(export.case_index) == case_index,
            "authenticated positive-export order/index drift while deriving auxiliary sources"
        );
        let expected_paths = positive_auxiliary_artifact_paths(case_index)?;
        ensure!(
            export.auxiliary_artifacts.len() == expected_paths.len(),
            "authenticated positive-export auxiliary cardinality drift"
        );
        for (identity, expected_path) in
            export.auxiliary_artifacts.iter().zip(expected_paths.iter())
        {
            ensure!(
                identity.path == *expected_path,
                "authenticated positive-export auxiliary path/order drift"
            );
            insert_expected_source(
                &mut expected,
                &identity.path,
                identity.byte_length,
                &identity.sha256,
                "authenticated recursive auxiliary artifact",
            )?;
        }
    }
    for entry in &subject_catalog.subjects {
        insert_expected_source(
            &mut expected,
            &entry.artifact.path,
            entry.artifact.byte_length,
            &entry.artifact.sha256,
            "subject-catalog artifact",
        )?;
    }
    for fixture in terminal_fixtures {
        insert_expected_source(
            &mut expected,
            &fixture.raw_seal.path,
            fixture.raw_seal.byte_length,
            &fixture.raw_seal.sha256,
            "terminal raw-seal artifact",
        )?;
        insert_expected_source(
            &mut expected,
            &fixture.receipt_oracle.path,
            fixture.receipt_oracle.byte_length,
            &fixture.receipt_oracle.sha256,
            "terminal receipt-oracle artifact",
        )?;
    }
    let supplied_paths = supplied
        .iter()
        .map(|source| source.path)
        .collect::<BTreeSet<_>>();
    let expected_paths = expected.keys().map(String::as_str).collect::<BTreeSet<_>>();
    ensure!(
        supplied_paths == expected_paths,
        "external source-artifact inventory differs from the deterministic path set; missing={:?}; extra={:?}",
        expected_paths
            .difference(&supplied_paths)
            .collect::<Vec<_>>(),
        supplied_paths
            .difference(&expected_paths)
            .collect::<Vec<_>>()
    );
    let mut retained = BTreeMap::new();
    let mut previous_path: Option<&str> = None;
    for external in supplied.iter().copied() {
        if let Some(previous) = previous_path {
            ensure!(
                previous.as_bytes() < external.path.as_bytes(),
                "external source-artifact inventory is not in strict unsigned UTF-8 path order"
            );
        }
        previous_path = Some(external.path);
        let (expected_length, expected_sha256) =
            expected.get(external.path).with_context(|| {
                format!(
                    "external source-artifact path is outside the deterministic inventory: {}",
                    external.path
                )
            })?;
        ensure!(
            u64::try_from(external.bytes.len())? == *expected_length
                && sha256_hex(external.bytes) == *expected_sha256,
            "external source artifact differs from its deterministic identity: {}",
            external.path
        );
        ensure!(
            retained
                .insert(external.path.to_owned(), external.bytes.to_vec())
                .is_none(),
            "external source-artifact inventory contains a duplicate path"
        );
        paths.bind_authority_selected_source(external, "authenticated source artifact")?;
    }
    ensure!(
        retained.keys().eq(expected.keys()),
        "external source-artifact inventory is not the exact deterministic path set"
    );
    Ok(retained)
}

#[cfg(feature = "positive-gate")]
#[allow(clippy::too_many_lines)]
fn authenticate_source_artifacts_v2(
    registry: &B4CandidateCorpus,
    subject_catalog: &Eip0045B4SubjectCatalogV1,
    terminal_catalog: &Eip0045B4TerminalFixtureCatalogV1,
    positive_input: &B4AuthenticatedPositiveInputSourcesV2,
    positive_exports: &[B4AuthenticatedPositiveExportV1],
    supplied: &[B4NegativeMaterializationExternalBytesV1<'_>],
    paths: &mut B4PhysicalPathClosureV2,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut expected = BTreeMap::new();
    for identity in [
        &positive_input.profile_manifest,
        &positive_input.profile_algorithm,
        &positive_input.profile_constants,
        &positive_input.guest_elf,
        &positive_input.reference_statement_manifest,
        &positive_input.source_lock,
        &positive_input.generator,
    ] {
        insert_expected_source(
            &mut expected,
            &identity.path,
            identity.byte_length,
            &identity.sha256,
            "required V2 positive-input source",
        )?;
    }
    for identity in positive_input.artifacts.values() {
        insert_expected_source(
            &mut expected,
            &identity.path,
            identity.byte_length,
            &identity.sha256,
            "V2 positive-input nested source",
        )?;
    }
    for binding in [
        &registry.bindings.generator,
        &registry.bindings.guest.elf,
        &registry.bindings.jvm_verifier,
        &registry.bindings.negative_plan,
        &registry.bindings.reference_statement_bundle.manifest,
        &registry.bindings.rust_verifier,
        &registry.bindings.source_lock,
        &registry.profile.manifest,
    ] {
        ensure!(
            binding.state == B4BindingState::Bound,
            "V2 expanded registry contains an unbound nested source path"
        );
        insert_expected_source(
            &mut expected,
            &binding.path,
            binding.byte_length,
            &binding.sha256,
            "V2 expanded-registry binding",
        )?;
    }
    for artifact in registry
        .positive_cases
        .iter()
        .flat_map(|case| case.artifacts.iter())
        .filter(|artifact| artifact.role != B4PositiveArtifactRole::RawSeal)
    {
        insert_expected_source(
            &mut expected,
            &artifact.path,
            artifact.byte_length,
            &artifact.sha256,
            "V2 expanded-registry positive artifact",
        )?;
    }
    ensure!(
        positive_exports.len() == registry.positive_cases.len(),
        "authenticated V2 positive-export inventory differs from registry cardinality"
    );
    for (case_index, export) in positive_exports.iter().enumerate() {
        ensure!(
            usize::from(export.case_index) == case_index,
            "authenticated V2 positive-export order/index drift"
        );
        let expected_paths = positive_auxiliary_artifact_paths(case_index)?;
        ensure!(
            export.auxiliary_artifacts.len() == expected_paths.len(),
            "authenticated V2 positive-export auxiliary cardinality drift"
        );
        for (identity, expected_path) in
            export.auxiliary_artifacts.iter().zip(expected_paths.iter())
        {
            ensure!(
                identity.path == *expected_path,
                "authenticated V2 positive-export auxiliary path/order drift"
            );
            insert_expected_source(
                &mut expected,
                &identity.path,
                identity.byte_length,
                &identity.sha256,
                "authenticated V2 recursive auxiliary artifact",
            )?;
        }
    }
    for entry in &subject_catalog.subjects {
        insert_expected_source(
            &mut expected,
            &entry.artifact.path,
            entry.artifact.byte_length,
            &entry.artifact.sha256,
            "V2 subject-catalog artifact",
        )?;
    }
    for fixture in &terminal_catalog.fixtures {
        for (identity, label) in [
            (&fixture.raw_seal, "V2 terminal raw-seal artifact"),
            (
                &fixture.receipt_oracle,
                "V2 terminal receipt-oracle artifact",
            ),
        ] {
            insert_expected_source(
                &mut expected,
                &identity.path,
                identity.byte_length,
                &identity.sha256,
                label,
            )?;
        }
    }

    let supplied_paths = supplied
        .iter()
        .map(|source| source.path)
        .collect::<BTreeSet<_>>();
    let expected_paths = expected.keys().map(String::as_str).collect::<BTreeSet<_>>();
    ensure!(
        supplied_paths == expected_paths,
        "V2 external source-artifact inventory differs from the deterministic path set"
    );
    let mut retained = BTreeMap::new();
    let mut previous_path: Option<&str> = None;
    for external in supplied.iter().copied() {
        if let Some(previous) = previous_path {
            ensure!(
                previous.as_bytes() < external.path.as_bytes(),
                "V2 external source-artifact inventory is not in strict unsigned UTF-8 path order"
            );
        }
        previous_path = Some(external.path);
        let (expected_length, expected_sha256) =
            expected.get(external.path).with_context(|| {
                format!(
                    "V2 external source path is outside inventory: {}",
                    external.path
                )
            })?;
        ensure!(
            u64::try_from(external.bytes.len())? == *expected_length
                && sha256_hex(external.bytes) == *expected_sha256,
            "V2 external source artifact differs from deterministic identity: {}",
            external.path
        );
        ensure!(
            retained
                .insert(external.path.to_owned(), external.bytes.to_vec())
                .is_none(),
            "V2 external source-artifact inventory contains a duplicate path"
        );
        paths
            .storage_mut()
            .bind_authority_selected_source(external, "authenticated V2 source artifact")?;
    }
    ensure!(
        retained.keys().eq(expected.keys()),
        "V2 external source-artifact inventory is not the exact deterministic path set"
    );
    Ok(retained)
}

#[cfg(feature = "positive-gate")]
#[derive(Clone, Copy)]
struct B4AlternateRootMeasuredArtifactsV1<'a> {
    manifest: &'a [ManifestEntry],
    claim_digest: &'a [u8],
    control_id: &'a [u8],
    image_id: &'a [u8],
    journal: &'a [u8],
    raw_seal: &'a [u8],
    receipt_oracle: &'a [u8],
}

#[cfg(feature = "positive-gate")]
const ALTERNATE_METADATA_FILE_ROLES: [(&str, &str); 6] = [
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

#[cfg(feature = "positive-gate")]
#[allow(clippy::too_many_lines)]
fn authenticate_alternate_root_export(
    supplied: B4NegativeAlternateRootExportV1<'_>,
    positive_input_sources: &B4AuthenticatedPositiveInputSourcesV1,
    paths: &mut B4PhysicalPathClosureV1,
) -> Result<BTreeMap<String, Vec<u8>>> {
    // This function closes physical custody and generator metadata only. It
    // deliberately returns ordinary retained bytes, never an authority token.
    // Closed row producers 108 and 146 must each replay the receipt oracle and
    // raw seal against claim, journal, alternate root, and terminal semantics
    // before either row can contribute to the 254/254 authority transition.
    const MANIFEST_NAME: &str = "candidate-proof-output-manifest.json";
    const EXPECTED_FILES: [&str; 7] = [
        "candidate-claim-digest.bin",
        "candidate-control-id.bin",
        "candidate-image-id.bin",
        "candidate-journal.bin",
        "candidate-metadata.json",
        "candidate-raw-seal.bin",
        "candidate-receipt-oracle.bincode",
    ];

    ensure!(
        (2..=MAX_ALTERNATE_ROOT_MANIFEST_BYTES)
            .contains(&supplied.proof_output_manifest.bytes.len()),
        "alternate-root proof-output manifest is outside its closed byte bound"
    );
    let manifest_value = validate_canonical_json_source(supplied.proof_output_manifest.bytes)
        .context("alternate-root proof-output manifest is not exact canonical JCS")?;
    let manifest: ProofOutputManifest = serde_json::from_value(manifest_value)
        .context("alternate-root proof-output manifest has the wrong shape")?;
    validate_manifest_shape(&manifest)?;
    ensure!(
        manifest.len() == EXPECTED_FILES.len()
            && manifest
                .iter()
                .zip(EXPECTED_FILES)
                .all(|(entry, expected)| entry.path == expected),
        "alternate-root proof-output manifest has the wrong exact file inventory"
    );
    ensure!(
        supplied.artifacts.len() == manifest.len(),
        "alternate-root export does not supply every manifested file exactly once"
    );
    let (export_root, manifest_name) = supplied
        .proof_output_manifest
        .path
        .rsplit_once('/')
        .context("alternate-root manifest path has no export root")?;
    ensure!(
        manifest_name == MANIFEST_NAME,
        "alternate-root manifest has the wrong physical filename"
    );
    validate_safe_relative_path(export_root)?;

    paths.bind_new_source(
        supplied.proof_output_manifest,
        false,
        "alternate-root proof-output manifest",
    )?;
    let mut retained = BTreeMap::new();
    ensure!(
        retained
            .insert(
                supplied.proof_output_manifest.path.to_owned(),
                supplied.proof_output_manifest.bytes.to_vec(),
            )
            .is_none(),
        "alternate-root manifest path is duplicated"
    );

    let mut metadata = None;
    let mut raw_seal = None;
    let mut claim_digest = None;
    let mut control_id = None;
    let mut image_id = None;
    let mut journal = None;
    let mut receipt_oracle = None;
    for (entry, external) in manifest.iter().zip(supplied.artifacts.iter().copied()) {
        let expected_path = format!("{export_root}/proof-output/{}", entry.path);
        let expected_length = entry
            .length
            .parse::<u64>()
            .context("alternate-root manifest length is not canonical u64")?;
        ensure!(
            external.path == expected_path
                && u64::try_from(external.bytes.len())? == expected_length
                && sha256_hex(external.bytes) == entry.sha256,
            "alternate-root artifact differs from its manifest entry: {}",
            entry.path
        );
        match entry.path.as_str() {
            "candidate-claim-digest.bin"
            | "candidate-control-id.bin"
            | "candidate-image-id.bin" => ensure!(
                external.bytes.len() == 32,
                "alternate-root digest artifact has the wrong exact byte length"
            ),
            "candidate-journal.bin" => ensure!(
                (159..=16_543).contains(&external.bytes.len()),
                "alternate-root journal is outside its closed byte bound"
            ),
            "candidate-metadata.json" => ensure!(
                (2..=CANDIDATE_METADATA_V1_MAX_BYTES).contains(&external.bytes.len()),
                "alternate-root metadata is outside its closed byte bound"
            ),
            "candidate-raw-seal.bin" => ensure!(
                external.bytes.len() == PROOF_BYTES,
                "alternate-root raw seal has the wrong exact byte length"
            ),
            "candidate-receipt-oracle.bincode" => ensure!(
                (1..=RECEIPT_ORACLE_MAX_BYTES).contains(&external.bytes.len()),
                "alternate-root receipt oracle is outside its closed byte bound"
            ),
            _ => {}
        }
        ensure!(
            retained
                .insert(external.path.to_owned(), external.bytes.to_vec())
                .is_none(),
            "alternate-root export contains a duplicate physical path"
        );
        match entry.path.as_str() {
            "candidate-claim-digest.bin" => claim_digest = Some(external.bytes),
            "candidate-control-id.bin" => control_id = Some(external.bytes),
            "candidate-image-id.bin" => image_id = Some(external.bytes),
            "candidate-journal.bin" => journal = Some(external.bytes),
            "candidate-metadata.json" => metadata = Some(external.bytes),
            "candidate-raw-seal.bin" => raw_seal = Some(external.bytes),
            "candidate-receipt-oracle.bincode" => {
                ensure!(
                    !external.bytes.is_empty(),
                    "alternate-root receipt oracle is empty"
                );
                receipt_oracle = Some(external.bytes);
            }
            _ => unreachable!("exact alternate-root file inventory was checked above"),
        }
    }
    let claim_digest = claim_digest.context("alternate-root claim digest is absent")?;
    let control_id = control_id.context("alternate-root control ID is absent")?;
    let image_id = image_id.context("alternate-root image ID is absent")?;
    let journal = journal.context("alternate-root journal is absent")?;
    let raw_seal = raw_seal.context("alternate-root raw seal is absent")?;
    let receipt_oracle = receipt_oracle.context("alternate-root receipt oracle is absent")?;
    ensure!(
        claim_digest.len() == 32
            && control_id.len() == 32
            && image_id.len() == 32
            && (159..=16_543).contains(&journal.len())
            && raw_seal.len() == PROOF_BYTES,
        "alternate-root export has an invalid fixed artifact length"
    );
    authenticate_alternate_root_metadata(
        metadata.context("alternate-root metadata is absent")?,
        &B4AlternateRootMeasuredArtifactsV1 {
            manifest: &manifest,
            claim_digest,
            control_id,
            image_id,
            journal,
            raw_seal,
            receipt_oracle,
        },
        positive_input_sources,
    )?;
    for external in supplied.artifacts.iter().copied() {
        paths.bind_authority_selected_source(external, "alternate-root proof-output artifact")?;
    }
    Ok(retained)
}

#[cfg(feature = "positive-gate")]
#[allow(
    clippy::too_many_lines,
    reason = "the authenticated alternate-root metadata contract is intentionally kept as one linear, protocol-ordered checklist"
)]
fn authenticate_alternate_root_metadata(
    source: &[u8],
    measured: &B4AlternateRootMeasuredArtifactsV1<'_>,
    positive_input_sources: &B4AuthenticatedPositiveInputSourcesV1,
) -> Result<()> {
    let metadata = CandidateMetadataV1::from_canonical_jcs(source)?;
    ensure!(
        metadata.candidate_status == "non-final-alternate-root-negative-witness"
            && metadata.format_version == 1,
        "alternate-root metadata has the wrong format identity"
    );
    ensure!(
        metadata.upstream.repository == RISC0_REPOSITORY
            && metadata.upstream.commit == RISC0_COMMIT
            && metadata.upstream.risc0_zkvm_version == B4_TERMINAL_FIXTURE_RISC0_VERSION
            && metadata.upstream.receipt_oracle_codec
                == "bincode-1.3.3-upstream-host-serialization",
        "alternate-root metadata has the wrong upstream identity"
    );
    ensure!(
        metadata.method.image_id == hex::encode(measured.image_id)
            && positive_input_sources.guest_image_id == metadata.method.image_id
            && parse_canonical_decimal_u64(
                &metadata.method.elf_length,
                "alternate-root guest ELF length"
            )? == positive_input_sources.guest_elf.byte_length
            && metadata.method.elf_sha256 == positive_input_sources.guest_elf.sha256,
        "alternate-root method metadata differs from the authenticated positive input"
    );
    let journal_digest = sha256_hex(measured.journal);
    ensure!(
        metadata.proof_bound.receipt_bound
            && parse_canonical_decimal_usize(
                &metadata.proof_bound.statement_length,
                "alternate-root statement length"
            )? == measured.journal.len()
            && metadata.proof_bound.statement_sha256 == journal_digest
            && metadata.proof_bound.journal_digest == journal_digest
            && metadata.proof_bound.claim_digest == hex::encode(measured.claim_digest),
        "alternate-root proof-bound metadata differs from measured statement and claim bytes"
    );
    ensure!(
        ok_receipt_claim_digests(measured.image_id, measured.journal)?
            .expected_claim
            .as_slice()
            == measured.claim_digest,
        "alternate-root claim digest differs from the measured image and statement"
    );
    ensure!(
        !metadata.private_calibration.receipt_bound
            && metadata.private_calibration.candidate_scope == "local-reproduction-provenance-only"
            && metadata.private_calibration.selection_rule
                == "canonical-monotone-ranking-v1-not-global-minimum"
            && metadata.private_calibration.selected_observation_is_exact
            && metadata.private_calibration.workload_seed_hex == "4549503030343501",
        "alternate-root private calibration metadata is not exact"
    );
    let _workload_iterations = parse_canonical_decimal_u64(
        &metadata.private_calibration.workload_iterations,
        "alternate-root workload iterations",
    )?;
    let observation = &metadata.local_execution_observation;
    let user_cycles =
        parse_canonical_decimal_u64(&observation.user_cycles, "alternate-root user cycles")?;
    let total_cycles =
        parse_canonical_decimal_u64(&observation.total_cycles, "alternate-root total cycles")?;
    let paging_cycles =
        parse_canonical_decimal_u64(&observation.paging_cycles, "alternate-root paging cycles")?;
    let reserved_cycles = parse_canonical_decimal_u64(
        &observation.reserved_cycles,
        "alternate-root reserved cycles",
    )?;
    ensure!(
        !observation.receipt_bound
            && observation.candidate_scope == "local-reproduction-provenance-only"
            && observation.segment_count == "1"
            && observation.executor_segment_limit_po2 == 23
            && observation.segment_po2 == 15
            && user_cycles
                .checked_add(paging_cycles)
                .and_then(|value| value.checked_add(reserved_cycles))
                == Some(total_cycles)
            && total_cycles == (1_u64 << observation.segment_po2),
        "alternate-root local execution observation is not exact or internally consistent"
    );
    ensure!(
        metadata.proof.receipt_kind == "succinct-single-lift-fixed-alternate-root"
            && metadata.proof.hash_function == "poseidon2"
            && metadata.proof.control_id == hex::encode(measured.control_id)
            && metadata.proof.inner_control_root == B4_ALTERNATE_CONTROL_ROOT_HEX
            && metadata.proof.verifier_parameters == B4_ALTERNATE_VERIFIER_PARAMETERS_HEX
            && metadata.proof.outer_po2 == u32::from(RISC0_OUTER_PO2)
            && parse_canonical_decimal_usize(
                &metadata.proof.raw_seal_words,
                "alternate-root raw-seal words"
            )? == PROOF_WORDS
            && parse_canonical_decimal_usize(
                &metadata.proof.raw_seal_bytes,
                "alternate-root raw-seal bytes"
            )? == PROOF_BYTES
            && metadata.proof.claim_digest == hex::encode(measured.claim_digest)
            && metadata.proof.journal_digest == journal_digest,
        "alternate-root proof metadata differs from the fixed profile or measured files"
    );
    ensure!(
        measured.control_id == hex::decode(RISC0_NORMAL_LIFT_CONTROL_IDS_HEX[0])?
            && measured.raw_seal.len() == PROOF_BYTES
            && !measured.receipt_oracle.is_empty(),
        "alternate-root measured proof files differ from the fixed lift-15 witness shape"
    );
    ensure!(
        !metadata.verification.receipt_bound
            && metadata.verification.verification_authority
                == "fixed-alternate-control-root-verifier-context"
            && metadata.verification.explicit_local_prover
            && !metadata.verification.dev_mode
            && !metadata.verification.prove_guest_errors
            && !metadata.verification.work_receipt_present
            && metadata.verification.upstream_receipt_verify
            && !metadata.verification.profile_owned_shape_verify
            && !metadata.verification.receipt_oracle_is_consensus_encoding,
        "alternate-root metadata lacks the fixed upstream verification disposition"
    );
    ensure!(
        metadata.files.len() == ALTERNATE_METADATA_FILE_ROLES.len(),
        "alternate-root metadata has the wrong exact file inventory"
    );
    for (index, ((path, role), file)) in ALTERNATE_METADATA_FILE_ROLES
        .iter()
        .zip(&metadata.files)
        .enumerate()
    {
        ensure!(
            file.path == *path && file.role == *role,
            "alternate-root metadata file entry {index} has the wrong path or role"
        );
        let manifest_entry = measured
            .manifest
            .iter()
            .find(|entry| entry.path == *path)
            .with_context(|| {
                format!("alternate-root proof-output manifest lacks metadata file {path}")
            })?;
        ensure!(
            file.length == manifest_entry.length && file.sha256 == manifest_entry.sha256,
            "alternate-root metadata file entry {index} differs from the measured manifest"
        );
    }
    Ok(())
}

#[cfg(feature = "positive-gate")]
fn parse_canonical_decimal_u64(source: &str, label: &str) -> Result<u64> {
    ensure!(
        !source.is_empty()
            && source.bytes().all(|byte| byte.is_ascii_digit())
            && (source == "0" || !source.starts_with('0')),
        "{label} is not canonical unsigned decimal"
    );
    source
        .parse::<u64>()
        .with_context(|| format!("{label} does not fit u64"))
}

#[cfg(feature = "positive-gate")]
fn parse_canonical_decimal_usize(source: &str, label: &str) -> Result<usize> {
    usize::try_from(parse_canonical_decimal_u64(source, label)?)
        .with_context(|| format!("{label} does not fit usize"))
}

#[cfg(feature = "positive-gate")]
fn insert_expected_source(
    expected: &mut BTreeMap<String, (u64, String)>,
    path: &str,
    byte_length: u64,
    sha256: &str,
    label: &str,
) -> Result<()> {
    validate_safe_relative_path(path)?;
    validate_digest(sha256, &format!("{label} SHA-256"))?;
    ensure!(
        byte_length <= MAX_RAW_BYTES,
        "{label} exceeds the source-artifact byte bound"
    );
    if let Some(previous) = expected.insert(path.to_owned(), (byte_length, sha256.to_owned())) {
        ensure!(
            previous == (byte_length, sha256.to_owned()),
            "deterministic source inventory binds one path to two byte identities"
        );
    }
    Ok(())
}

#[cfg(feature = "positive-gate")]
fn validate_external_execution(
    index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    supplied: &B4NegativeMaterializationExternalExecutionV1<'_>,
    paths: &mut B4PhysicalPathClosureV1,
) -> Result<()> {
    paths.bind_new_source(supplied.base, true, "materialization base")?;
    paths.bind_unique_output(
        supplied.materialization_identity,
        "materialization identity",
    )?;
    paths.bind_unique_output(supplied.negative_input, "negative verifier input")?;
    paths.bind_unique_output(supplied.subject, "negative subject")?;
    for (context_index, context) in supplied.contexts.iter().copied().enumerate() {
        paths
            .bind_unique_output(context, &format!("negative context {context_index}"))
            .with_context(|| {
                format!("invalid external path closure for execution index {index}")
            })?;
    }
    let context_bytes = supplied
        .contexts
        .iter()
        .map(|context| context.bytes)
        .collect::<Vec<_>>();
    validate_execution_bytes(
        index,
        planned,
        negative_plan_jcs,
        None,
        supplied.base.bytes,
        supplied.materialization_identity.bytes,
        supplied.negative_input.bytes,
        supplied.subject.bytes,
        &context_bytes,
    )?;
    Ok(())
}

#[cfg(feature = "positive-gate")]
fn ensure_reconstruction_matches_external(
    index: usize,
    reconstructed: &B4ClosedReconstructedExecutionV1,
    supplied: &B4NegativeMaterializationExternalExecutionV1<'_>,
) -> Result<()> {
    ensure!(
        reconstructed.base == supplied.base.bytes
            && reconstructed.materialization_identity_jcs
                == supplied.materialization_identity.bytes
            && reconstructed.negative_input_jcs == supplied.negative_input.bytes
            && reconstructed.subject == supplied.subject.bytes
            && reconstructed.contexts.len() == supplied.contexts.len()
            && reconstructed
                .contexts
                .iter()
                .zip(supplied.contexts)
                .all(|(actual, expected)| actual == expected.bytes),
        "external execution bytes differ from the closed producer reconstruction at index {index}"
    );
    Ok(())
}

#[cfg(feature = "positive-gate")]
fn retain_authenticated_execution(
    index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    reconstructed: B4ClosedReconstructedExecutionV1,
) -> Result<(
    B4NegativeMaterializationSetExecutionV1,
    B4RetainedNegativeMaterializationExecutionV1,
)> {
    let context_bytes = reconstructed
        .contexts
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let row = derive_execution_row(
        index,
        planned,
        negative_plan_jcs,
        &reconstructed.derived_registry_row,
        &reconstructed.base,
        &reconstructed.materialization_identity_jcs,
        &reconstructed.negative_input_jcs,
        &reconstructed.subject,
        &context_bytes,
    )?;
    let retained = B4RetainedNegativeMaterializationExecutionV1 {
        execution_index: u16::try_from(index)
            .context("negative materialization index does not fit u16")?,
        execution_id: planned.execution_id.clone(),
        base: reconstructed.base,
        materialization_identity_jcs: reconstructed.materialization_identity_jcs,
        negative_input_jcs: reconstructed.negative_input_jcs,
        subject: reconstructed.subject,
        contexts: reconstructed.contexts,
    };
    Ok((row, retained))
}

#[cfg(feature = "positive-gate")]
#[allow(clippy::too_many_arguments)]
fn derive_execution_row(
    index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    registry_row: &B4NegativeCase,
    base: &[u8],
    materialization_identity_jcs: &[u8],
    negative_input_jcs: &[u8],
    subject: &[u8],
    contexts: &[&[u8]],
) -> Result<B4NegativeMaterializationSetExecutionV1> {
    ensure!(
        registry_row.execution_id == planned.execution_id
            && registry_row.base_selector_id == planned.base_selector_id
            && registry_row.materialization_domain == planned.materialization_domain,
        "producer-derived expanded-registry row differs from the canonical plan at index {index}"
    );
    validate_execution_bytes(
        index,
        planned,
        negative_plan_jcs,
        Some(registry_row),
        base,
        materialization_identity_jcs,
        negative_input_jcs,
        subject,
        contexts,
    )?;
    let row = B4NegativeMaterializationSetExecutionV1 {
        execution_index: u16::try_from(index)
            .context("negative materialization index does not fit u16")?,
        execution_id: planned.execution_id.clone(),
        materialization_domain: planned.materialization_domain,
        validation_surface: planned.execution_surface,
        base: pathless_identity_allow_empty(base)?,
        materialization_identity: pathless_identity(materialization_identity_jcs)?,
        negative_input: pathless_identity(negative_input_jcs)?,
        subject: pathless_identity_allow_empty(subject)?,
        contexts: contexts
            .iter()
            .map(|bytes| pathless_identity(bytes))
            .collect::<Result<Vec<_>>>()?,
    };
    row.validate_identities(index)?;
    Ok(row)
}

#[cfg(feature = "positive-gate")]
#[allow(clippy::too_many_arguments)]
fn validate_execution_bytes(
    index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    derived_registry_row: Option<&B4NegativeCase>,
    base: &[u8],
    materialization_identity_jcs: &[u8],
    negative_input_jcs: &[u8],
    subject: &[u8],
    contexts: &[&[u8]],
) -> Result<()> {
    let materialization_identity =
        Eip0045B4MaterializationIdentityV1::from_canonical_jcs(materialization_identity_jcs)?;
    ensure!(
        materialization_identity.execution_id == planned.execution_id
            && materialization_identity.base_selector_id == planned.base_selector_id
            && materialization_identity.materialization_domain == planned.materialization_domain
            && materialization_identity.base_byte_length == u64::try_from(base.len())?
            && materialization_identity.base_sha256 == sha256_hex(base)
            && materialization_identity.negative_plan_byte_length
                == u64::try_from(negative_plan_jcs.len())?
            && materialization_identity.negative_plan_sha256 == sha256_hex(negative_plan_jcs)
            && materialization_identity.output_byte_length == u64::try_from(subject.len())?
            && materialization_identity.output_sha256 == sha256_hex(subject),
        "materialization identity differs from independently measured plan, base, or output at index {index}"
    );
    if let Some(registry_row) = derived_registry_row {
        let recipe_jcs = canonical_materialization_recipe_jcs(&registry_row.materialization)?;
        ensure!(
            materialization_identity.materialization_recipe_byte_length
                == u64::try_from(recipe_jcs.len())?
                && materialization_identity.materialization_recipe_sha256
                    == sha256_hex(&recipe_jcs),
            "materialization identity differs from the closed producer-derived recipe at index {index}"
        );
    }

    let negative_input = Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(negative_input_jcs)?;
    // The preceding campaign-precommit authority already owns the global
    // "all handler adapters frozen" gate. Requiring it again here would make
    // this byte-closure primitive depend on mutable implementation readiness
    // instead of the retained prior authority. We still rederive and enforce
    // the exact per-row custody cardinality from the sole handler table.
    negative_input.validate()?;
    let handler = planned_negative_handler_contract(
        planned.materialization_domain,
        planned.execution_surface,
    )?
    .context("canonical negative plan row has no handler contract")?;
    ensure!(
        negative_input.materialization_domain == planned.materialization_domain
            && negative_input.validation_surface == planned.execution_surface
            && negative_input.subject.byte_length == u64::try_from(subject.len())?
            && negative_input.subject.sha256 == sha256_hex(subject)
            && negative_input.subject.encoding == B4NegativeFileEncoding::RawBytes
            && negative_input.context.len() == contexts.len()
            && negative_input.context.len() == handler.custody().contexts().len(),
        "negative verifier input differs from plan or subject bytes at index {index}"
    );
    for (context_index, (identity, bytes)) in
        negative_input.context.iter().zip(contexts).enumerate()
    {
        ensure!(
            identity.byte_length == u64::try_from(bytes.len())?
                && identity.sha256 == sha256_hex(bytes)
                && identity.encoding == B4NegativeFileEncoding::RawBytes,
            "negative verifier input context differs from exact bytes at execution {index}, context {context_index}"
        );
    }

    Ok(())
}

#[cfg(feature = "positive-gate")]
fn ensure_top_level_snapshot_unchanged(
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
    external: &B4NegativeMaterializationSetExternalInputsV1<'_>,
    alternate_root_mode: B4AlternateRootSourceModeV1,
) -> Result<()> {
    ensure!(
        top_level.positive_input_set == external.positive_input_set.bytes
            && top_level.campaign_precommit == external.campaign_precommit.bytes
            && top_level.positive_generation_set == external.positive_generation_set.bytes
            && top_level.negative_plan == external.negative_plan.bytes
            && top_level.expanded_registry.to_canonical_jcs()? == external.expanded_registry.bytes
            && top_level.subject_catalog_jcs == external.subject_catalog.bytes
            && top_level.terminal_fixture_catalog_jcs == external.terminal_fixture_catalog.bytes
            && top_level.negative_binding_index_jcs == external.negative_binding_index.bytes
            && top_level.abstract_tree_jcs == external.abstract_tree.bytes,
        "top-level materialization source changed between authentication and authority closure"
    );
    ensure!(
        top_level.positive_exports.len() == external.positive_exports.len()
            && top_level
                .positive_exports
                .iter()
                .zip(external.positive_exports)
                .all(|(retained, supplied)| {
                    retained.case_index == supplied.case_index
                        && retained.proof_output_manifest_jcs
                            == supplied.proof_output_manifest.bytes
                        && retained.raw_seal == supplied.raw_seal.bytes
                }),
        "positive export changed between authentication and authority closure"
    );
    ensure!(
        external.source_artifacts.iter().all(|supplied| {
            top_level
                .source_artifacts
                .get(supplied.path)
                .is_some_and(|retained| retained == supplied.bytes)
        }),
        "source artifact changed between authentication and authority closure"
    );
    match alternate_root_mode {
        B4AlternateRootSourceModeV1::CallerCustody => {
            let alternate = external.alternate_root_export;
            ensure!(
                top_level.source_artifacts.len()
                    == external.source_artifacts.len() + alternate.artifacts.len() + 1
                    && top_level
                        .source_artifacts
                        .get(alternate.proof_output_manifest.path)
                        .is_some_and(|retained| retained == alternate.proof_output_manifest.bytes)
                    && alternate.artifacts.iter().all(|supplied| {
                        top_level
                            .source_artifacts
                            .get(supplied.path)
                            .is_some_and(|retained| retained == supplied.bytes)
                    }),
                "caller-custody alternate-root source changed during authority closure"
            );
        }
        B4AlternateRootSourceModeV1::ProviderDeferred => ensure!(
            top_level.source_artifacts.len() == external.source_artifacts.len(),
            "provider-deferred top-level authentication retained caller alternate-root bytes"
        ),
    }
    Ok(())
}

#[cfg(feature = "positive-gate")]
fn ensure_top_level_snapshot_unchanged_v2(
    top_level: &B4AuthenticatedMaterializationTopLevelV2,
    external: &B4NegativeMaterializationSetExternalInputsV1<'_>,
) -> Result<()> {
    ensure_top_level_snapshot_unchanged(
        top_level.storage(),
        external,
        B4AlternateRootSourceModeV1::ProviderDeferred,
    )
    .context("V2 top-level materialization snapshot changed")
}

#[cfg(feature = "positive-gate")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum B4PhysicalPathRoleV1 {
    Source,
    Output,
}

#[cfg(feature = "positive-gate")]
#[derive(Clone)]
struct B4PhysicalPathClosureV1 {
    paths: BTreeSet<String>,
    sha256_by_path: BTreeMap<String, String>,
    role_by_path: BTreeMap<String, B4PhysicalPathRoleV1>,
    #[cfg(feature = "negative-materialization-set")]
    publication_paths: BTreeSet<String>,
}

#[cfg(feature = "positive-gate")]
struct B4PhysicalPathClosureV2 {
    authenticated_storage: B4PhysicalPathClosureV1,
}

#[cfg(feature = "positive-gate")]
impl B4PhysicalPathClosureV2 {
    fn from_prior(prior: &B4MaterializationPriorAuthoritySnapshotV2) -> Result<Self> {
        ensure!(
            prior
                .provenance_paths
                .iter()
                .eq(prior.provenance_sha256.keys()),
            "V2 prior authority path/digest closure is incomplete at physical-path construction"
        );
        for path in &prior.provenance_paths {
            validate_safe_relative_path(path)?;
        }
        for left in &prior.provenance_paths {
            for right in prior.provenance_paths.range(left.clone()..) {
                if left == right {
                    continue;
                }
                ensure!(
                    !b4_paths_conflict(left, right),
                    "V2 prior authority closure contains an ancestor/descendant path conflict"
                );
            }
        }
        Ok(Self {
            authenticated_storage: B4PhysicalPathClosureV1 {
                paths: prior.provenance_paths.clone(),
                sha256_by_path: prior.provenance_sha256.clone(),
                role_by_path: prior
                    .provenance_paths
                    .iter()
                    .map(|path| (path.clone(), B4PhysicalPathRoleV1::Source))
                    .collect(),
                #[cfg(feature = "negative-materialization-set")]
                publication_paths: BTreeSet::new(),
            },
        })
    }

    fn storage(&self) -> &B4PhysicalPathClosureV1 {
        &self.authenticated_storage
    }

    fn storage_mut(&mut self) -> &mut B4PhysicalPathClosureV1 {
        &mut self.authenticated_storage
    }
}

#[cfg(feature = "positive-gate")]
impl B4PhysicalPathClosureV1 {
    fn from_prior(prior: &B4MaterializationPriorAuthoritySnapshotV1) -> Result<Self> {
        ensure!(
            prior
                .provenance_paths
                .iter()
                .eq(prior.provenance_sha256.keys()),
            "prior authority path/digest closure is incomplete at physical-path construction"
        );
        for path in &prior.provenance_paths {
            validate_safe_relative_path(path)?;
        }
        for left in &prior.provenance_paths {
            for right in prior.provenance_paths.range(left.clone()..) {
                if left == right {
                    continue;
                }
                ensure!(
                    !b4_paths_conflict(left, right),
                    "prior authority closure contains an ancestor/descendant path conflict"
                );
            }
        }
        Ok(Self {
            paths: prior.provenance_paths.clone(),
            sha256_by_path: prior.provenance_sha256.clone(),
            role_by_path: prior
                .provenance_paths
                .iter()
                .map(|path| (path.clone(), B4PhysicalPathRoleV1::Source))
                .collect(),
            #[cfg(feature = "negative-materialization-set")]
            publication_paths: BTreeSet::new(),
        })
    }

    #[cfg(feature = "negative-materialization-set")]
    fn bind_publication_source(&mut self, path: &str, bytes: &[u8], label: &str) -> Result<()> {
        self.bind_path(
            path,
            &sha256_hex(bytes),
            true,
            B4PhysicalPathRoleV1::Source,
            label,
        )?;
        self.publication_paths.insert(path.to_owned());
        Ok(())
    }

    #[cfg(feature = "negative-materialization-set")]
    fn bind_authority_selected_source(
        &mut self,
        external: B4NegativeMaterializationExternalBytesV1<'_>,
        label: &str,
    ) -> Result<()> {
        self.bind_path(
            external.path,
            &sha256_hex(external.bytes),
            true,
            B4PhysicalPathRoleV1::Source,
            label,
        )
    }

    #[cfg(not(feature = "negative-materialization-set"))]
    fn bind_authority_selected_source(
        &mut self,
        external: B4NegativeMaterializationExternalBytesV1<'_>,
        label: &str,
    ) -> Result<()> {
        self.bind_new_source(external, true, label)
    }

    fn bind_prior_replay(
        &mut self,
        external: B4NegativeMaterializationExternalBytesV1<'_>,
        label: &str,
    ) -> Result<()> {
        validate_safe_relative_path(external.path)?;
        ensure!(
            self.paths.contains(external.path),
            "{label} path is absent from the prior authority closure"
        );
        ensure!(
            self.role_by_path.get(external.path) == Some(&B4PhysicalPathRoleV1::Source),
            "{label} prior path is not classified as a source"
        );
        let digest = sha256_hex(external.bytes);
        ensure!(
            self.sha256_by_path
                .get(external.path)
                .is_some_and(|expected| expected == &digest),
            "{label} bytes differ from the prior path identity"
        );
        Ok(())
    }

    fn bind_prior_identity(
        &mut self,
        identity: &B4ContractArtifactIdentityV1,
        label: &str,
    ) -> Result<()> {
        identity
            .validate()
            .with_context(|| format!("{label} has an invalid identity"))?;
        ensure!(
            self.paths.contains(&identity.path),
            "{label} path is absent from the prior authority closure: {}",
            identity.path
        );
        ensure!(
            self.role_by_path.get(&identity.path) == Some(&B4PhysicalPathRoleV1::Source),
            "{label} prior path is not classified as a source"
        );
        if let Some(previous) = self.sha256_by_path.get(&identity.path) {
            ensure!(
                previous == &identity.sha256,
                "{label} disagrees with an existing prior-authority digest"
            );
        } else {
            self.sha256_by_path
                .insert(identity.path.clone(), identity.sha256.clone());
        }
        Ok(())
    }

    fn bind_new_source(
        &mut self,
        external: B4NegativeMaterializationExternalBytesV1<'_>,
        allow_exact_reuse: bool,
        label: &str,
    ) -> Result<()> {
        #[cfg(feature = "negative-materialization-set")]
        ensure!(
            !self.publication_paths.contains(external.path),
            "{label} cannot reuse an authenticated publication-owned path"
        );
        self.bind_path(
            external.path,
            &sha256_hex(external.bytes),
            allow_exact_reuse,
            B4PhysicalPathRoleV1::Source,
            label,
        )
    }

    fn bind_unique_output(
        &mut self,
        external: B4NegativeMaterializationExternalBytesV1<'_>,
        label: &str,
    ) -> Result<()> {
        #[cfg(feature = "negative-materialization-set")]
        ensure!(
            !self.publication_paths.contains(external.path),
            "{label} cannot reuse an authenticated publication-owned path"
        );
        self.bind_path(
            external.path,
            &sha256_hex(external.bytes),
            false,
            B4PhysicalPathRoleV1::Output,
            label,
        )
    }

    fn bind_path(
        &mut self,
        path: &str,
        sha256: &str,
        allow_exact_reuse: bool,
        role: B4PhysicalPathRoleV1,
        label: &str,
    ) -> Result<()> {
        validate_safe_relative_path(path)
            .with_context(|| format!("{label} has an unsafe physical path"))?;
        if self.paths.contains(path) {
            ensure!(
                allow_exact_reuse
                    && role == B4PhysicalPathRoleV1::Source
                    && self.role_by_path.get(path) == Some(&B4PhysicalPathRoleV1::Source)
                    && self
                        .sha256_by_path
                        .get(path)
                        .is_some_and(|existing| existing == sha256),
                "{label} aliases an existing physical role or rewrites its bytes: {path}"
            );
            return Ok(());
        }
        ensure!(
            !self
                .paths
                .iter()
                .any(|existing| b4_paths_conflict(existing, path)),
            "{label} path has an ancestor/descendant conflict with the retained authority closure"
        );
        self.paths.insert(path.to_owned());
        self.sha256_by_path
            .insert(path.to_owned(), sha256.to_owned());
        self.role_by_path.insert(path.to_owned(), role);
        Ok(())
    }
}

#[cfg(feature = "positive-gate")]
fn pathless_identity(bytes: &[u8]) -> Result<B4NegativeMaterializationByteIdentityV1> {
    ensure!(
        !bytes.is_empty(),
        "authenticated byte object is unexpectedly empty"
    );
    pathless_identity_allow_empty(bytes)
}

#[cfg(feature = "positive-gate")]
fn pathless_identity_allow_empty(bytes: &[u8]) -> Result<B4NegativeMaterializationByteIdentityV1> {
    Ok(B4NegativeMaterializationByteIdentityV1 {
        byte_length: u64::try_from(bytes.len()).context("byte-object length does not fit u64")?,
        sha256: sha256_hex(bytes),
    })
}

#[cfg(feature = "positive-gate")]
fn measure_bytes(bytes: &[u8]) -> FileMeasurement {
    FileMeasurement {
        byte_length: u64::try_from(bytes.len())
            .expect("usize always fits u64 on supported targets"),
        sha256: Sha256::digest(bytes).into(),
    }
}

#[cfg(feature = "positive-gate")]
fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
            && !value.as_bytes().iter().any(u8::is_ascii_uppercase),
        "{label} is not lowercase 32-byte hex"
    );
    Ok(())
}

#[cfg(all(test, feature = "positive-gate"))]
pub(crate) mod authority_tdd_tests {
    #[cfg(feature = "negative-materialization-set")]
    use std::path::{Path, PathBuf};

    use super::*;
    #[cfg(feature = "negative-materialization-set")]
    use crate::recursive_ancestry::RecursiveAncestryFamily;
    use crate::{
        b4::{B4NegativeMaterialization, B4PositiveArtifact, B4RegistryStage},
        b4_negative_io::{
            B4_NEGATIVE_VERIFIER_INPUT_FORMAT, B4_NEGATIVE_VERIFIER_INPUT_FORMAT_VERSION,
            B4NegativeNamedIdentityV1,
        },
        b4_registry_probe::{materialize_registry_probe, synthetic_negative_binding_index_source},
        b4_terminal::B4_TERMINAL_FIXTURE_RISC0_VERSION,
        b4_tree_probe::{Eip0045B4AbstractTreeV1, materialize_tree_probe},
        candidate_metadata::{
            CandidateFileMetadataV1, CandidateLocalExecutionObservationV1, CandidateMetadataV1,
            CandidateMethodMetadataV1, CandidatePrivateCalibrationMetadataV1,
            CandidateProofBoundMetadataV1, CandidateProofMetadataV1, CandidateUpstreamMetadataV1,
            CandidateVerificationMetadataV1,
        },
        claim::ok_receipt_claim_digests,
        constants::{RISC0_COMMIT, RISC0_NORMAL_LIFT_CONTROL_IDS_HEX, RISC0_REPOSITORY},
    };

    #[test]
    #[allow(clippy::no_effect_underscore_binding)]
    fn candidate_bytes_are_only_a_comparison_input_after_authority_exists() {
        let _verifier: fn(&B4NegativeMaterializationSetAuthorityV1, &[u8]) -> Result<()> =
            B4NegativeMaterializationSetAuthorityV1::verify_candidate_jcs;
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn production_constructor_requires_three_authorities_root_and_external_inputs() {
        let constructor: for<'a> fn(
            &'a B4CampaignPrecommitAuthorityV1,
            &'a B4PositiveGenerationAuthorityV1,
            &'a crate::b4_negative_ancestry_authority::B4NegativeAncestryWitnessCatalogAuthorityV1,
            &'a std::path::Path,
            &'a B4NegativeMaterializationSetExternalInputsV1<'a>,
        ) -> Result<B4NegativeMaterializationSetAuthorityV1> =
            B4NegativeMaterializationSetAuthorityV1::from_external_closure;
        std::hint::black_box(constructor);
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn production_source_has_a_distinct_non_test_v2_terminal_consumer() {
        let source = include_str!("b4_materialization_set.rs");
        let production = source
            .split("#[cfg(all(test, feature = \"positive-gate\"))]")
            .next()
            .unwrap();
        let v2 = production
            .split("struct TerminalAwareProductionRowProducerV2")
            .nth(1)
            .unwrap()
            .split("struct DescriptorRootedStrongInferenceRowProducer")
            .next()
            .unwrap();

        assert!(v2.contains("B4TerminalEvidenceImportAuthorityV2"));
        assert!(v2.contains("reconstruct_terminal_catalog_execution_v2("));
        assert!(v2.contains("reconstruct_terminal_metadata_execution_from_import_v2("));
        assert!(v2.contains("reconstruct_terminal_fixture_execution_v2("));
        assert!(v2.contains("terminal_materialization_projection_v2()"));
        assert!(!v2.contains("B4TerminalEvidenceImportAuthorityV1"));
        assert!(!v2.contains("from_descriptor_rooted_cryptographic_closure_v2"));
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn production_v2_dispatch_preserves_wrapper_authority_at_every_resolver_bearing_row() {
        let source = include_str!("b4_materialization_set.rs");
        let production = source
            .split("#[cfg(all(test, feature = \"positive-gate\"))]")
            .next()
            .unwrap();
        let section = |start: &str, end: &str| {
            production
                .split(start)
                .nth(1)
                .unwrap()
                .split(end)
                .next()
                .unwrap()
        };

        let trait_v2 = section(
            "trait B4ClosedMaterializationRowProducerV2",
            "struct B4TerminalEvidenceDocumentIdentitiesV1",
        );
        assert!(trait_v2.contains("&B4AuthenticatedMaterializationTopLevelV2"));
        assert!(!trait_v2.contains("&B4AuthenticatedMaterializationTopLevelV1"));

        let deterministic_v2 = section(
            "impl B4ClosedMaterializationRowProducerV2 for ProductionRowProducerV2",
            "struct TerminalAwareProductionRowProducer<'authority>",
        );
        assert!(deterministic_v2.contains("reconstruct_raw_execution_v2("));
        assert!(deterministic_v2.contains("reconstruct_parser_execution_v2("));
        assert!(!deterministic_v2.contains("reconstruct_raw_execution("));
        assert!(!deterministic_v2.contains("reconstruct_parser_execution("));

        let strong_v2 = section(
            "impl B4ClosedMaterializationRowProducerV2 for DescriptorRootedStrongInferenceRowProducerV2",
            "struct DescriptorRootedAlternateRootRowProducerV2",
        );
        assert!(strong_v2.contains("reconstruct_receipt_claim_execution_v2("));
        assert!(strong_v2.contains("reconstruct_negative_ancestry_witness_execution_v2("));
        assert!(strong_v2.contains("reconstruct_ancestry_execution_v2("));
        assert!(!strong_v2.contains("reconstruct_receipt_claim_execution("));
        assert!(!strong_v2.contains("reconstruct_negative_ancestry_witness_execution("));
        assert!(!strong_v2.contains("reconstruct_ancestry_execution("));

        let alternate_v2 = section(
            "impl B4ClosedMaterializationRowProducerV2 for DescriptorRootedAlternateRootRowProducerV2",
            "struct DescriptorRootedCryptographicRowProducerV2",
        );
        assert!(alternate_v2.contains("reconstruct_alternate_root_execution_v2("));
        assert!(!alternate_v2.contains("reconstruct_alternate_root_execution("));

        let crypto_v2 = section(
            "impl B4ClosedMaterializationRowProducerV2 for DescriptorRootedCryptographicRowProducerV2",
            "struct UnavailableProductionRowProducer",
        );
        assert!(crypto_v2.contains("reconstruct_crypto_execution_v2("));
        assert!(!crypto_v2.contains("reconstruct_crypto_execution("));
    }

    #[test]
    fn production_v2_storage_adapter_is_narrow_and_explicit() {
        let source = include_str!("b4_materialization_set.rs");
        let production = source
            .split("#[cfg(all(test, feature = \"positive-gate\"))]")
            .next()
            .unwrap();
        let adapter = production
            .split("impl B4ClosedMaterializationRowProducerV2 for V2AuthenticatedVersionNeutralDeterministicRowAdapter")
            .nth(1)
            .unwrap()
            .split("struct ProductionRowProducerV2")
            .next()
            .unwrap();

        assert_eq!(adapter.matches("top_level.storage()").count(), 1);
        assert!(adapter.contains("reconstruct_opcode_sequence_execution("));
        assert!(adapter.contains("reconstruct_terminal_execution("));
        assert!(adapter.contains("reconstruct_profile_execution("));
        assert!(adapter.contains("C1ProductionRowProducer.reconstruct("));
        for forbidden in [
            "reconstruct_raw_execution",
            "reconstruct_parser_execution",
            "reconstruct_receipt_claim_execution",
            "reconstruct_negative_ancestry_witness_execution",
            "reconstruct_ancestry_execution",
            "reconstruct_alternate_root_execution",
            "reconstruct_crypto_execution",
            "B4FixtureSourceResolverV1",
            "B4MaterializationFixtureSourceResolverV2",
        ] {
            assert!(
                !adapter.contains(forbidden),
                "forbidden broad V2 adapter seam: {forbidden}"
            );
        }
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn production_v2_core_and_constructor_retain_wrapper_and_crypto_authority() {
        let source = include_str!("b4_materialization_set.rs");
        let production = source
            .split("#[cfg(all(test, feature = \"positive-gate\"))]")
            .next()
            .unwrap();
        let core = production
            .split("fn close_authenticated_negative_ancestry_handoff_core_v2(")
            .nth(1)
            .unwrap()
            .split("fn close_negative_ancestry_provenance_partition_v2(")
            .next()
            .unwrap();
        assert!(core.contains("producer: &impl B4ClosedMaterializationRowProducerV2"));
        assert!(core.contains("assemble_materialization_authority_v2(\n        top_level,"));

        let assembler = production
            .split("fn assemble_materialization_authority_v2(")
            .nth(1)
            .unwrap()
            .split("enum B4AlternateRootSourceModeV1")
            .next()
            .unwrap();
        assert!(assembler.contains("top_level: &B4AuthenticatedMaterializationTopLevelV2"));
        assert!(assembler.contains("producer: &impl B4ClosedMaterializationRowProducerV2"));
        assert!(assembler.contains("producer.reconstruct(index, planned, top_level)"));
        assert!(!assembler.contains("producer.reconstruct(index, planned, storage)"));

        let constructor = production
            .split("from_descriptor_rooted_cryptographic_closure_v2")
            .nth(1)
            .unwrap()
            .split("pub fn verify_candidate_jcs")
            .next()
            .unwrap();
        assert!(
            constructor.contains(
                "B4DirectSealCheckpointMutationAuthorityV2::from_authenticated(&top_level)"
            )
        );
        assert!(
            !constructor.contains("B4DirectSealCheckpointMutationAuthorityV1::from_authenticated")
        );
        assert!(!constructor.contains("from_authenticated(top_level.storage())"));
    }

    #[test]
    fn v2_materialization_fixture_resolver_authenticates_distinct_v2_views() {
        let storage = crate::b4_fixture_sources::synthetic_v2_materialization_fixture_storage();
        let parsed_input = parse_positive_input_sources_v2(&storage.positive_input_set).unwrap();
        let guest_candidate_path = storage.expanded_registry.bindings.guest.elf.path.clone();
        let statement_candidate_path = storage
            .expanded_registry
            .bindings
            .reference_statement_bundle
            .manifest
            .path
            .clone();
        let top_level = B4AuthenticatedMaterializationTopLevelV2 {
            authenticated_storage: storage,
        };
        let resolver = crate::b4_fixture_sources::B4MaterializationFixtureSourceResolverV2::
            from_authenticated(&top_level)
            .unwrap();
        let input = resolver.positive_input().unwrap();
        assert!(
            input
                .positive_input_set()
                .windows(b"Eip0045B4PositiveInputSetV2".len())
                .any(|window| window == b"Eip0045B4PositiveInputSetV2")
        );
        assert!(std::ptr::eq(
            input.guest_elf(),
            top_level.storage().source_artifacts[&guest_candidate_path].as_slice()
        ));
        assert!(!std::ptr::eq(
            input.guest_elf(),
            top_level.storage().source_artifacts[&parsed_input.guest_elf.path].as_slice()
        ));
        assert!(std::ptr::eq(
            input.reference_statement_manifest(),
            top_level.storage().source_artifacts[&statement_candidate_path].as_slice()
        ));
        assert!(!std::ptr::eq(
            input.reference_statement_manifest(),
            top_level.storage().source_artifacts[&parsed_input.reference_statement_manifest.path]
                .as_slice()
        ));
        let case = resolver.positive_case(0, "lift-po2-15").unwrap();
        assert_eq!(case.case_index(), 0);
        assert_eq!(case.case_id(), "lift-po2-15");
        assert!(!case.proof_output_manifest_jcs().is_empty());
        let case_zero = resolver.case_zero_reference_statement().unwrap();
        let global = resolver.global_reference_statement().unwrap();
        assert_eq!(case_zero.statement_bytes(), global.statement_bytes());
        assert_eq!(case_zero.profile_id(), global.statement().profile_id());
        assert_eq!(case_zero.program_id(), global.statement().program_id());
    }

    #[test]
    fn v2_materialization_fixture_resolver_rejects_missing_and_drifted_quarantine_copies() {
        for role in ["guest", "reference-statement"] {
            for mutation in ["missing", "byte-drift"] {
                let mut storage =
                    crate::b4_fixture_sources::synthetic_v2_materialization_fixture_storage();
                let candidate_path = match role {
                    "guest" => storage.expanded_registry.bindings.guest.elf.path.clone(),
                    "reference-statement" => storage
                        .expanded_registry
                        .bindings
                        .reference_statement_bundle
                        .manifest
                        .path
                        .clone(),
                    _ => unreachable!(),
                };
                match mutation {
                    "missing" => {
                        storage.source_artifacts.remove(&candidate_path).unwrap();
                    }
                    "byte-drift" => {
                        storage.source_artifacts.get_mut(&candidate_path).unwrap()[0] ^= 1;
                    }
                    _ => unreachable!(),
                }
                let top_level = B4AuthenticatedMaterializationTopLevelV2 {
                    authenticated_storage: storage,
                };
                let resolver = crate::b4_fixture_sources::
                    B4MaterializationFixtureSourceResolverV2::from_authenticated(&top_level)
                    .unwrap();
                let message = format!(
                    "{:#}",
                    resolver
                        .positive_input()
                        .err()
                        .expect("V2 quarantine-copy mutant unexpectedly resolved")
                );
                let expected = if mutation == "missing" {
                    "lacks candidate"
                } else {
                    "authenticated candidate"
                };
                assert!(
                    message.contains(expected),
                    "{role} {mutation} failed outside candidate-copy authentication: {message}"
                );
            }
        }
    }

    #[test]
    fn v2_materialization_fixture_resolver_rejects_version_path_and_digest_drift() {
        let reject = |mutation: fn(&mut serde_json::Value)| {
            let mut storage =
                crate::b4_fixture_sources::synthetic_v2_materialization_fixture_storage();
            let mut input = validate_canonical_json_source(&storage.positive_input_set).unwrap();
            mutation(&mut input);
            storage.positive_input_set = canonical_json_bytes(&input).unwrap();
            let top_level = B4AuthenticatedMaterializationTopLevelV2 {
                authenticated_storage: storage,
            };
            crate::b4_fixture_sources::B4MaterializationFixtureSourceResolverV2::from_authenticated(
                &top_level,
            )
            .and_then(|resolver| resolver.positive_input().map(|_| ()))
            .is_err()
        };

        assert!(reject(|input| input["formatVersion"] = serde_json::json!(1)));
        assert!(reject(|input| {
            input["profile"]["manifest"]["path"] =
                serde_json::json!("profiles/substituted/manifest.bin");
        }));
        assert!(reject(|input| {
            input["profile"]["manifest"]["sha256"] = serde_json::json!("00".repeat(32));
        }));
    }

    #[test]
    fn v2_materialization_fixture_resolver_has_no_v1_parser_or_resolver_fallback() {
        let source = include_str!("b4_fixture_sources.rs");
        let implementation = source
            .split("impl<'a> B4MaterializationFixtureSourceResolverV2<'a>")
            .nth(1)
            .unwrap()
            .split("impl<'a> B4FixtureSourceResolverV1<'a>")
            .next()
            .unwrap();
        assert!(implementation.contains("parse_positive_input_sources_v2("));
        assert!(!implementation.contains("parse_positive_input_sources("));
        assert!(!implementation.contains("B4FixtureSourceResolverV1"));
        assert!(!implementation.contains("From<"));
        assert!(!implementation.contains("Into<"));

        let materialization = include_str!("b4_materialization_set.rs");
        let constructor = materialization
            .split("from_descriptor_rooted_cryptographic_closure_v2")
            .nth(1)
            .unwrap()
            .split("fn close_authenticated_negative_ancestry_handoff_core")
            .next()
            .unwrap();
        assert!(constructor.contains("B4MaterializationFixtureSourceResolverV2"));
        assert!(!constructor.contains("B4FixtureSourceResolverV1::from_authenticated"));
    }

    #[cfg(feature = "negative-materialization-set")]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum RealV2QuarantineRole {
        Generator,
        GuestElf,
        ReferenceStatementManifest,
        SourceLock,
        RustVerifier,
        JvmVerifier,
        NegativePlan,
    }

    #[cfg(feature = "negative-materialization-set")]
    impl RealV2QuarantineRole {
        const ALL: [Self; 7] = [
            Self::Generator,
            Self::GuestElf,
            Self::ReferenceStatementManifest,
            Self::SourceLock,
            Self::RustVerifier,
            Self::JvmVerifier,
            Self::NegativePlan,
        ];

        const PRIOR_BACKED_SIX: [Self; 6] = [
            Self::Generator,
            Self::GuestElf,
            Self::ReferenceStatementManifest,
            Self::SourceLock,
            Self::RustVerifier,
            Self::JvmVerifier,
        ];
    }

    #[cfg(feature = "negative-materialization-set")]
    fn real_v2_registry_quarantine_binding(
        registry: &B4CandidateCorpus,
        role: RealV2QuarantineRole,
    ) -> &B4ArtifactBinding {
        match role {
            RealV2QuarantineRole::Generator => &registry.bindings.generator,
            RealV2QuarantineRole::GuestElf => &registry.bindings.guest.elf,
            RealV2QuarantineRole::ReferenceStatementManifest => {
                &registry.bindings.reference_statement_bundle.manifest
            }
            RealV2QuarantineRole::SourceLock => &registry.bindings.source_lock,
            RealV2QuarantineRole::RustVerifier => &registry.bindings.rust_verifier,
            RealV2QuarantineRole::JvmVerifier => &registry.bindings.jvm_verifier,
            RealV2QuarantineRole::NegativePlan => &registry.bindings.negative_plan,
        }
    }

    #[cfg(feature = "negative-materialization-set")]
    fn real_v2_registry_quarantine_binding_mut(
        registry: &mut B4CandidateCorpus,
        role: RealV2QuarantineRole,
    ) -> &mut B4ArtifactBinding {
        match role {
            RealV2QuarantineRole::Generator => &mut registry.bindings.generator,
            RealV2QuarantineRole::GuestElf => &mut registry.bindings.guest.elf,
            RealV2QuarantineRole::ReferenceStatementManifest => {
                &mut registry.bindings.reference_statement_bundle.manifest
            }
            RealV2QuarantineRole::SourceLock => &mut registry.bindings.source_lock,
            RealV2QuarantineRole::RustVerifier => &mut registry.bindings.rust_verifier,
            RealV2QuarantineRole::JvmVerifier => &mut registry.bindings.jvm_verifier,
            RealV2QuarantineRole::NegativePlan => &mut registry.bindings.negative_plan,
        }
    }

    #[cfg(feature = "negative-materialization-set")]
    fn real_v2_quarantine_upstream_identity<'a>(
        role: RealV2QuarantineRole,
        input: &'a B4AuthenticatedPositiveInputSourcesV2,
        prior: &'a B4MaterializationPriorAuthoritySnapshotV2,
    ) -> &'a B4ContractArtifactIdentityV1 {
        match role {
            RealV2QuarantineRole::Generator => &input.generator,
            RealV2QuarantineRole::GuestElf => &input.guest_elf,
            RealV2QuarantineRole::ReferenceStatementManifest => &input.reference_statement_manifest,
            RealV2QuarantineRole::SourceLock => &input.source_lock,
            RealV2QuarantineRole::RustVerifier => &prior.rust_verifier,
            RealV2QuarantineRole::JvmVerifier => &prior.jvm_verifier,
            RealV2QuarantineRole::NegativePlan => &prior.negative_plan,
        }
    }

    #[cfg(feature = "negative-materialization-set")]
    enum RealV2SourceMutation<'a> {
        Relocate(&'a str),
        Remove(&'a str),
        Truncate(&'a str),
        FlipByte(&'a str),
        ChangeRecursiveFamily(&'a str),
        Case8CalibrationBasename,
        RegistryQuarantineAlias(RealV2QuarantineRole),
        RegistryQuarantineIdentityDrift(RealV2QuarantineRole),
        RegistryQuarantineEncoding(RealV2QuarantineRole),
        RegistryCandidatePathAlias,
        RelocateRegistryProfileManifest,
        RelocateExternalNegativePlan,
        TruncateExternalNegativePlan,
        FlipExternalNegativePlanByte,
        RelocateExternalSubjectCatalog,
        RelocateExternalTerminalFixtureCatalog,
    }

    /// Exact test owner for the external views consumed by the private V2 mint.
    /// The nominal and mutant paths all replay through the production prior
    /// snapshot, physical path closure, and `authenticate_top_level_v2` gate.
    #[cfg(feature = "negative-materialization-set")]
    struct RealV2MaterializationMintFixture {
        lineage: crate::b4_negative_ancestry_authority::test_support::
            B4NegativeAncestryLineageTestSupportV2,
        campaign_precommit_jcs: Vec<u8>,
        storage: B4AuthenticatedMaterializationTopLevelV1,
        expanded_registry_jcs: Vec<u8>,
        sources: BTreeMap<String, Vec<u8>>,
    }

    #[cfg(feature = "negative-materialization-set")]
    fn real_v2_fixture_negative_mutation(
        index: usize,
        execution_id: &str,
    ) -> crate::b4::B4NegativeMutation {
        use crate::b4::{
            B4AncestryInventoryOperation, B4AncestryInventoryTarget, B4ByteOperation, B4ByteTarget,
            B4NegativeMutation, B4SequenceOperation, B4SequenceTarget,
        };

        if execution_id == "resolve-explicit-field-sweep--assumption-receipt-root" {
            B4NegativeMutation::AlternateRootAssumptionSubstitution {}
        } else if let Some(recipe) = crate::b4::negative_ancestry_witness_recipe(execution_id) {
            B4NegativeMutation::AncestryWitnessSubstitution { recipe }
        } else if execution_id == "resolve-assumption-inventory-sweep--pruned-assumption" {
            B4NegativeMutation::AncestryInventoryEdit {
                edit: B4AncestryInventoryOperation::PruneRevealedHead {
                    before_claim_digest: "11".repeat(32),
                    before_control_root: "22".repeat(32),
                    exact_digest: "33".repeat(32),
                },
                target: B4AncestryInventoryTarget::AssumptionSourceInventoryHead,
            }
        } else if index.is_multiple_of(2) {
            B4NegativeMutation::ByteEdit {
                edit: B4ByteOperation::Replace {
                    before_hex: "00".to_owned(),
                    offset: 0,
                    replacement_hex: "01".to_owned(),
                },
                target: B4ByteTarget::Statement,
            }
        } else {
            B4NegativeMutation::SequenceEdit {
                edit: B4SequenceOperation::Omit {
                    before_element_id: "proof-chunk-00".to_owned(),
                    before_element_sha256: "02".repeat(32),
                    index: 0,
                },
                target: B4SequenceTarget::ProofChunks,
            }
        }
    }

    #[cfg(feature = "negative-materialization-set")]
    #[allow(
        clippy::too_many_lines,
        reason = "the regression fixture keeps the complete V1 production authentication boundary visible"
    )]
    fn real_v1_authenticated_top_level() -> Result<(
        B4AuthenticatedMaterializationTopLevelV1,
        String,
        String,
        String,
        String,
    )> {
        let lineage = crate::b4_negative_ancestry_authority::test_support::
            fixed_negative_ancestry_lineage_test_support()
            .context("cannot build the real V1 negative-ancestry lineage")?;
        let generation = &lineage.prior;
        let prior = B4MaterializationPriorAuthoritySnapshotV1::from_authorities(
            &generation.campaign_precommit_authority,
            &generation.positive_generation_authority,
        )?;
        let input = parse_positive_input_sources(&generation.positive_input_set.bytes)?;
        let mut storage = crate::b4_fixture_sources::synthetic_valid_recursive_ancestry_top_level();
        let original_sources = storage.source_artifacts.clone();
        let terminal_catalog = Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(
            &storage.terminal_fixture_catalog_jcs,
        )?;
        let mut sources = BTreeMap::new();
        for fixture in &terminal_catalog.fixtures {
            for (path, label) in [
                (&fixture.raw_seal.path, "terminal raw seal"),
                (&fixture.receipt_oracle.path, "terminal receipt oracle"),
            ] {
                let bytes = original_sources
                    .get(path)
                    .with_context(|| format!("real V1 fixture omits {label} source {path}"))?;
                ensure!(
                    sources.insert(path.clone(), bytes.clone()).is_none(),
                    "real V1 terminal fixture aliases source path {path}"
                );
            }
        }

        set_registry_quarantine_copy_binding(
            &mut storage.expanded_registry.bindings.generator,
            &input.generator,
            "reproduction/schema/b4-corpus-v1.candidate/bindings/generator.bin",
        );
        set_registry_quarantine_copy_binding(
            &mut storage.expanded_registry.bindings.guest.elf,
            &input.guest_elf,
            "reproduction/schema/b4-corpus-v1.candidate/bindings/guest.elf",
        );
        set_registry_quarantine_copy_binding(
            &mut storage
                .expanded_registry
                .bindings
                .reference_statement_bundle
                .manifest,
            &input.reference_statement_manifest,
            "reproduction/schema/b4-corpus-v1.candidate/bindings/statement-manifest.json",
        );
        set_registry_quarantine_copy_binding(
            &mut storage.expanded_registry.bindings.source_lock,
            &input.source_lock,
            "reproduction/schema/b4-corpus-v1.candidate/bindings/source-lock.json",
        );
        set_registry_quarantine_copy_binding(
            &mut storage.expanded_registry.bindings.rust_verifier,
            &prior.rust_verifier,
            "reproduction/schema/b4-corpus-v1.candidate/bindings/rust-verifier.bin",
        );
        set_registry_quarantine_copy_binding(
            &mut storage.expanded_registry.bindings.jvm_verifier,
            &prior.jvm_verifier,
            "reproduction/schema/b4-corpus-v1.candidate/bindings/jvm-verifier.bin",
        );
        set_registry_quarantine_copy_binding(
            &mut storage.expanded_registry.bindings.negative_plan,
            &prior.negative_plan,
            "reproduction/schema/b4-corpus-v1.candidate/bindings/negative-plan.json",
        );
        set_registry_binding(
            &mut storage.expanded_registry.profile.manifest,
            &input.profile_manifest,
        );
        storage.expanded_registry.profile.profile_id = input.profile_id.clone();
        storage.expanded_registry.bindings.guest.state = B4BindingState::Bound;
        storage.expanded_registry.bindings.guest.image_id = input.guest_image_id.clone();
        storage
            .expanded_registry
            .bindings
            .reference_statement_bundle
            .state = B4BindingState::Bound;
        storage
            .expanded_registry
            .bindings
            .reference_statement_bundle
            .contract_id = input.reference_contract_id.clone();
        storage
            .expanded_registry
            .bindings
            .reference_statement_bundle
            .statement_sha256 = input.reference_statement_sha256.clone();
        let terminal_identity = B4ContractArtifactIdentityV1::from_bytes(
            "reproduction/schema/b4-corpus-v1.candidate/bindings/terminal-fixture-catalog.json",
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            &storage.terminal_fixture_catalog_jcs,
        )?;
        set_registry_binding(
            &mut storage.expanded_registry.bindings.terminal_fixture_catalog,
            &terminal_identity,
        );

        let plan = Eip0045B4NegativePlanV1::canonical()?;
        storage.negative_binding_index_jcs = synthetic_negative_binding_index_source(&plan)?;
        storage.abstract_tree_jcs =
            Eip0045B4AbstractTreeV1::canonical_baseline()?.to_canonical_jcs()?;
        storage.expanded_registry.negative_cases = plan
            .groups
            .iter()
            .flat_map(|group| {
                group
                    .executions
                    .iter()
                    .map(move |execution| (group, execution))
            })
            .enumerate()
            .map(|(index, (group, execution))| crate::b4::B4NegativeCase {
                execution_id: execution.execution_id.clone(),
                base_selector_id: execution.base_selector_id.clone(),
                materialization_domain: execution.materialization_domain,
                materialization: if crate::b4_plan::negative_group_requires_fixture_selection(
                    &group.case_id,
                ) {
                    B4NegativeMaterialization::FixtureSelection {
                        fixture_id: execution.base_selector_id.clone(),
                    }
                } else {
                    B4NegativeMaterialization::Mutation {
                        mutation: real_v2_fixture_negative_mutation(index, &execution.execution_id),
                    }
                },
            })
            .collect();
        for (case_index, (registry_case, generated_case)) in storage
            .expanded_registry
            .positive_cases
            .iter_mut()
            .zip(&generation.positive_cases)
            .enumerate()
        {
            ensure!(
                generated_case.primary_artifacts.len()
                    == positive_artifact_layout(case_index)?.len(),
                "real V1 positive case {case_index} has the wrong primary cardinality"
            );
            registry_case.artifacts = generated_case
                .primary_artifacts
                .iter()
                .zip(positive_artifact_layout(case_index)?)
                .map(|(artifact, (role, _))| B4PositiveArtifact {
                    byte_length: u64::try_from(artifact.bytes.len()).unwrap(),
                    encoding: positive_artifact_encoding(*role).1,
                    path: artifact.path.clone(),
                    role: *role,
                    sha256: sha256_hex(&artifact.bytes),
                })
                .collect();
        }

        let materialization_bytes = |identity: &B4ContractArtifactIdentityV1| -> Result<&[u8]> {
            generation
                .materialization_sources
                .iter()
                .find(|source| source.path == identity.path)
                .map(|source| source.bytes.as_slice())
                .with_context(|| {
                    format!(
                        "real V1 source fixture omits upstream bytes for {}",
                        identity.path
                    )
                })
        };
        let subject_repository = crate::test_support::tempdir()
            .context("cannot create the real V1 subject-derivation repository")?;
        let write_subject_source = |relative: &str, bytes: &[u8]| -> Result<()> {
            let path = relative.split('/').fold(
                subject_repository.path().to_path_buf(),
                |mut path, segment| {
                    path.push(segment);
                    path
                },
            );
            std::fs::create_dir_all(
                path.parent()
                    .context("real V1 subject source has no parent directory")?,
            )?;
            std::fs::write(path, bytes)?;
            Ok(())
        };
        for source in &generation.materialization_sources {
            write_subject_source(&source.path, &source.bytes)?;
        }
        for (path, bytes) in [
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
            write_subject_source(path, bytes)?;
        }
        for (case_index, case) in generation.positive_cases.iter().enumerate() {
            let raw = case
                .primary_artifacts
                .iter()
                .zip(positive_artifact_layout(case_index)?)
                .find(|(_, (role, _))| *role == B4PositiveArtifactRole::RawSeal)
                .map(|(artifact, _)| artifact)
                .context("real V1 subject derivation omits a positive raw seal")?;
            write_subject_source(&raw.path, &raw.bytes)?;
        }
        let subject_bundle = crate::b4_catalog::derive_b4_subject_bundle(
            &storage.expanded_registry,
            &plan,
            subject_repository.path(),
        )?;
        storage.subject_catalog_jcs = subject_bundle.catalog_jcs()?;
        for (path, bytes) in subject_bundle.subject_files {
            ensure!(
                sources.insert(path.clone(), bytes).is_none(),
                "real V1 subject source aliases an existing path: {path}"
            );
        }
        let subject_identity = B4ContractArtifactIdentityV1::from_bytes(
            "reproduction/schema/b4-corpus-v1.candidate/bindings/subject-catalog.json",
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            &storage.subject_catalog_jcs,
        )?;
        set_registry_binding(
            &mut storage.expanded_registry.bindings.subject_catalog,
            &subject_identity,
        );

        let quarantine_copies = [
            (
                storage.expanded_registry.bindings.generator.path.clone(),
                materialization_bytes(&input.generator)?.to_vec(),
            ),
            (
                storage.expanded_registry.bindings.guest.elf.path.clone(),
                materialization_bytes(&input.guest_elf)?.to_vec(),
            ),
            (
                storage
                    .expanded_registry
                    .bindings
                    .reference_statement_bundle
                    .manifest
                    .path
                    .clone(),
                materialization_bytes(&input.reference_statement_manifest)?.to_vec(),
            ),
            (
                storage.expanded_registry.bindings.source_lock.path.clone(),
                materialization_bytes(&input.source_lock)?.to_vec(),
            ),
            (
                storage
                    .expanded_registry
                    .bindings
                    .rust_verifier
                    .path
                    .clone(),
                materialization_bytes(&prior.rust_verifier)?.to_vec(),
            ),
            (
                storage.expanded_registry.bindings.jvm_verifier.path.clone(),
                materialization_bytes(&prior.jvm_verifier)?.to_vec(),
            ),
            (
                storage
                    .expanded_registry
                    .bindings
                    .negative_plan
                    .path
                    .clone(),
                prior.negative_plan_jcs.clone(),
            ),
        ];
        for (path, bytes) in quarantine_copies {
            ensure!(
                sources.insert(path.clone(), bytes).is_none(),
                "real V1 quarantine copy aliases source path {path}"
            );
        }
        let mut retain = |path: &str, bytes: &[u8]| -> Result<()> {
            if let Some(previous) = sources.get(path) {
                ensure!(
                    previous == bytes,
                    "real V1 fixture has conflicting exact bytes for {path}"
                );
            }
            sources.insert(path.to_owned(), bytes.to_vec());
            Ok(())
        };
        for identity in [
            &input.profile_manifest,
            &input.profile_algorithm,
            &input.profile_constants,
            &input.guest_elf,
            &input.reference_statement_manifest,
            &input.source_lock,
            &input.generator,
        ]
        .into_iter()
        .chain(input.artifacts.values())
        {
            retain(&identity.path, materialization_bytes(identity)?)?;
        }
        for (case_index, case) in generation.positive_cases.iter().enumerate() {
            for (artifact, (role, _)) in case
                .primary_artifacts
                .iter()
                .zip(positive_artifact_layout(case_index)?)
            {
                if *role != B4PositiveArtifactRole::RawSeal {
                    retain(&artifact.path, &artifact.bytes)?;
                }
            }
            for artifact in &case.auxiliary_artifacts {
                retain(&artifact.path, &artifact.bytes)?;
            }
        }

        let expanded_registry_jcs = storage.expanded_registry.to_canonical_jcs()?;
        let source_views = sources
            .iter()
            .map(|(path, bytes)| B4NegativeMaterializationExternalBytesV1 { path, bytes })
            .collect::<Vec<_>>();
        let positive_exports = generation
            .positive_cases
            .iter()
            .enumerate()
            .map(|(case_index, case)| {
                let raw = case
                    .primary_artifacts
                    .iter()
                    .zip(positive_artifact_layout(case_index)?)
                    .find(|(_, (role, _))| *role == B4PositiveArtifactRole::RawSeal)
                    .map(|(artifact, _)| artifact)
                    .context("real V1 fixture omits a positive raw seal")?;
                Ok(B4NegativeMaterializationPositiveExportV1 {
                    case_index: u8::try_from(case_index)?,
                    proof_output_manifest: B4NegativeMaterializationExternalBytesV1 {
                        path: &case.proof_output_manifest.path,
                        bytes: &case.proof_output_manifest.bytes,
                    },
                    raw_seal: B4NegativeMaterializationExternalBytesV1 {
                        path: &raw.path,
                        bytes: &raw.bytes,
                    },
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let no_alternate_artifacts = [];
        let external = B4NegativeMaterializationSetExternalInputsV1 {
            positive_input_set: B4NegativeMaterializationExternalBytesV1 {
                path: &prior.positive_input_set.path,
                bytes: &generation.positive_input_set.bytes,
            },
            campaign_precommit: B4NegativeMaterializationExternalBytesV1 {
                path: "reproduction/campaign-precommit.json",
                bytes: &generation.campaign_precommit_jcs,
            },
            positive_generation_set: B4NegativeMaterializationExternalBytesV1 {
                path: &prior.positive_generation_set.path,
                bytes: &generation.positive_generation_set.bytes,
            },
            negative_plan: B4NegativeMaterializationExternalBytesV1 {
                path: &prior.negative_plan.path,
                bytes: &prior.negative_plan_jcs,
            },
            expanded_registry: B4NegativeMaterializationExternalBytesV1 {
                path: "reproduction/schema/b4-corpus-v1.candidate/expanded-registry.json",
                bytes: &expanded_registry_jcs,
            },
            subject_catalog: B4NegativeMaterializationExternalBytesV1 {
                path: "reproduction/schema/b4-corpus-v1.candidate/bindings/subject-catalog.json",
                bytes: &storage.subject_catalog_jcs,
            },
            terminal_fixture_catalog: B4NegativeMaterializationExternalBytesV1 {
                path: "reproduction/schema/b4-corpus-v1.candidate/bindings/terminal-fixture-catalog.json",
                bytes: &storage.terminal_fixture_catalog_jcs,
            },
            negative_binding_index: B4NegativeMaterializationExternalBytesV1 {
                path: "reproduction/negative-binding-index.json",
                bytes: &storage.negative_binding_index_jcs,
            },
            abstract_tree: B4NegativeMaterializationExternalBytesV1 {
                path: "reproduction/abstract-tree.json",
                bytes: &storage.abstract_tree_jcs,
            },
            positive_exports: &positive_exports,
            alternate_root_export: B4NegativeAlternateRootExportV1 {
                proof_output_manifest: B4NegativeMaterializationExternalBytesV1 {
                    path: "test-only/unused-alternate-root-manifest.json",
                    bytes: b"{}",
                },
                artifacts: &no_alternate_artifacts,
            },
            source_artifacts: &source_views,
            executions: &[],
        };
        let guest_candidate_path = storage.expanded_registry.bindings.guest.elf.path.clone();
        let statement_candidate_path = storage
            .expanded_registry
            .bindings
            .reference_statement_bundle
            .manifest
            .path
            .clone();
        let guest_upstream_path = input.guest_elf.path.clone();
        let statement_upstream_path = input.reference_statement_manifest.path.clone();
        let mut paths = B4PhysicalPathClosureV1::from_prior(&prior)?;
        let authenticated = authenticate_top_level(
            &prior,
            &external,
            &mut paths,
            B4AlternateRootSourceModeV1::ProviderDeferred,
        )?;
        Ok((
            authenticated,
            guest_candidate_path,
            statement_candidate_path,
            guest_upstream_path,
            statement_upstream_path,
        ))
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn v1_top_level_authentication_feeds_quarantine_copies_to_the_resolver() {
        let (
            top_level,
            guest_candidate_path,
            statement_candidate_path,
            guest_upstream_path,
            statement_upstream_path,
        ) = real_v1_authenticated_top_level().unwrap();
        let resolver =
            crate::b4_fixture_sources::B4FixtureSourceResolverV1::from_authenticated(&top_level)
                .unwrap();
        let input = resolver.positive_input().unwrap();
        assert!(std::ptr::eq(
            input.guest_elf(),
            top_level.source_artifacts[&guest_candidate_path].as_slice()
        ));
        assert!(!std::ptr::eq(
            input.guest_elf(),
            top_level.source_artifacts[&guest_upstream_path].as_slice()
        ));
        assert!(std::ptr::eq(
            input.reference_statement_manifest(),
            top_level.source_artifacts[&statement_candidate_path].as_slice()
        ));
        assert!(!std::ptr::eq(
            input.reference_statement_manifest(),
            top_level.source_artifacts[&statement_upstream_path].as_slice()
        ));
    }

    #[cfg(feature = "negative-materialization-set")]
    impl RealV2MaterializationMintFixture {
        fn exact() -> Result<Self> {
            let lineage = crate::b4_negative_ancestry_authority::test_support::
                fixed_negative_ancestry_lineage_test_support_v2()
                .context("cannot build the real V2 negative-ancestry lineage")?;
            let campaign_precommit_jcs = lineage
                .prior
                .campaign_precommit_authority
                .to_canonical_precommit_jcs()?;
            let mut storage =
                crate::b4_fixture_sources::synthetic_valid_recursive_ancestry_top_level();
            let mut sources = storage.source_artifacts.clone();
            let generation = &lineage.prior.sources;
            let prior = B4MaterializationPriorAuthoritySnapshotV2::from_authorities(
                &lineage.prior.campaign_precommit_authority,
                &lineage.prior.positive_generation_authority,
            )?;
            let input = parse_positive_input_sources_v2(&generation.positive_input_set.bytes)?;
            set_registry_quarantine_copy_binding(
                &mut storage.expanded_registry.bindings.generator,
                &input.generator,
                "reproduction/schema/b4-corpus-v1.candidate/bindings/generator.bin",
            );
            set_registry_quarantine_copy_binding(
                &mut storage.expanded_registry.bindings.guest.elf,
                &input.guest_elf,
                "reproduction/schema/b4-corpus-v1.candidate/bindings/guest.elf",
            );
            set_registry_quarantine_copy_binding(
                &mut storage
                    .expanded_registry
                    .bindings
                    .reference_statement_bundle
                    .manifest,
                &input.reference_statement_manifest,
                "reproduction/schema/b4-corpus-v1.candidate/bindings/statement-manifest.json",
            );
            set_registry_quarantine_copy_binding(
                &mut storage.expanded_registry.bindings.source_lock,
                &input.source_lock,
                "reproduction/schema/b4-corpus-v1.candidate/bindings/source-lock.json",
            );
            set_registry_quarantine_copy_binding(
                &mut storage.expanded_registry.bindings.rust_verifier,
                &prior.rust_verifier,
                "reproduction/schema/b4-corpus-v1.candidate/bindings/rust-verifier.bin",
            );
            set_registry_quarantine_copy_binding(
                &mut storage.expanded_registry.bindings.jvm_verifier,
                &prior.jvm_verifier,
                "reproduction/schema/b4-corpus-v1.candidate/bindings/jvm-verifier.bin",
            );
            set_registry_quarantine_copy_binding(
                &mut storage.expanded_registry.bindings.negative_plan,
                &prior.negative_plan,
                "reproduction/schema/b4-corpus-v1.candidate/bindings/negative-plan.json",
            );
            set_registry_binding(
                &mut storage.expanded_registry.profile.manifest,
                &input.profile_manifest,
            );
            storage.expanded_registry.bindings.guest.state = B4BindingState::Bound;
            storage.expanded_registry.bindings.guest.image_id = input.guest_image_id.clone();
            storage
                .expanded_registry
                .bindings
                .reference_statement_bundle
                .state = B4BindingState::Bound;
            storage
                .expanded_registry
                .bindings
                .reference_statement_bundle
                .contract_id = input.reference_contract_id.clone();
            storage
                .expanded_registry
                .bindings
                .reference_statement_bundle
                .statement_sha256 = input.reference_statement_sha256.clone();
            storage.expanded_registry.profile.profile_id = input.profile_id.clone();
            let terminal_identity = B4ContractArtifactIdentityV1::from_bytes(
                "reproduction/schema/b4-corpus-v1.candidate/bindings/terminal-fixture-catalog.json",
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &storage.terminal_fixture_catalog_jcs,
            )?;
            set_registry_binding(
                &mut storage.expanded_registry.bindings.terminal_fixture_catalog,
                &terminal_identity,
            );
            let plan = Eip0045B4NegativePlanV1::canonical()?;
            storage.negative_binding_index_jcs = synthetic_negative_binding_index_source(&plan)?;
            storage.abstract_tree_jcs =
                Eip0045B4AbstractTreeV1::canonical_baseline()?.to_canonical_jcs()?;
            storage.expanded_registry.negative_cases = plan
                .groups
                .iter()
                .flat_map(|group| {
                    group
                        .executions
                        .iter()
                        .map(move |execution| (group, execution))
                })
                .enumerate()
                .map(|(index, (group, execution))| crate::b4::B4NegativeCase {
                    execution_id: execution.execution_id.clone(),
                    base_selector_id: execution.base_selector_id.clone(),
                    materialization_domain: execution.materialization_domain,
                    materialization: if crate::b4_plan::negative_group_requires_fixture_selection(
                        &group.case_id,
                    ) {
                        B4NegativeMaterialization::FixtureSelection {
                            fixture_id: execution.base_selector_id.clone(),
                        }
                    } else {
                        B4NegativeMaterialization::Mutation {
                            mutation: real_v2_fixture_negative_mutation(
                                index,
                                &execution.execution_id,
                            ),
                        }
                    },
                })
                .collect();

            for (case_index, (registry_case, generated_case)) in storage
                .expanded_registry
                .positive_cases
                .iter_mut()
                .zip(&generation.cases)
                .enumerate()
            {
                registry_case.artifacts = generated_case
                    .primary_artifacts
                    .iter()
                    .zip(positive_artifact_layout(case_index)?)
                    .map(|(artifact, (role, _))| B4PositiveArtifact {
                        byte_length: u64::try_from(artifact.bytes.len()).unwrap(),
                        encoding: positive_artifact_encoding(*role).1,
                        path: artifact.path.clone(),
                        role: *role,
                        sha256: sha256_hex(&artifact.bytes),
                    })
                    .collect();
            }

            let subject_repository = crate::test_support::tempdir()
                .context("cannot create the real V2 subject-derivation repository")?;
            let write_subject_source = |relative: &str, bytes: &[u8]| -> Result<()> {
                let path = relative.split('/').fold(
                    subject_repository.path().to_path_buf(),
                    |mut path, segment| {
                        path.push(segment);
                        path
                    },
                );
                std::fs::create_dir_all(
                    path.parent()
                        .context("real V2 subject source has no parent directory")?,
                )?;
                std::fs::write(path, bytes)?;
                Ok(())
            };
            for source in &generation.nested_input_sources {
                write_subject_source(&source.path, &source.bytes)?;
            }
            for (path, bytes) in [
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
                    include_bytes!(
                        "../../profiles/risc0-v3-succinct/algorithm-artifact-preimage.bin"
                    )
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
                write_subject_source(path, bytes)?;
            }
            for (case_index, case) in generation.cases.iter().enumerate() {
                let raw = case
                    .primary_artifacts
                    .iter()
                    .zip(positive_artifact_layout(case_index)?)
                    .find(|(_, (role, _))| *role == B4PositiveArtifactRole::RawSeal)
                    .map(|(artifact, _)| artifact)
                    .context("real V2 subject derivation omits a positive raw seal")?;
                write_subject_source(&raw.path, &raw.bytes)?;
            }
            let subject_bundle = crate::b4_catalog::derive_b4_subject_bundle(
                &storage.expanded_registry,
                &plan,
                subject_repository.path(),
            )?;
            storage.subject_catalog_jcs = subject_bundle.catalog_jcs()?;
            for (path, bytes) in subject_bundle.subject_files {
                ensure!(
                    sources.insert(path.clone(), bytes).is_none(),
                    "real V2 subject source aliases an existing path: {path}"
                );
            }
            let subject_identity = B4ContractArtifactIdentityV1::from_bytes(
                "reproduction/schema/b4-corpus-v1.candidate/bindings/subject-catalog.json",
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &storage.subject_catalog_jcs,
            )?;
            set_registry_binding(
                &mut storage.expanded_registry.bindings.subject_catalog,
                &subject_identity,
            );
            for (label, path) in [
                (
                    "generator",
                    storage.expanded_registry.bindings.generator.path.as_str(),
                ),
                (
                    "guest",
                    storage.expanded_registry.bindings.guest.elf.path.as_str(),
                ),
                (
                    "statement",
                    storage
                        .expanded_registry
                        .bindings
                        .reference_statement_bundle
                        .manifest
                        .path
                        .as_str(),
                ),
                (
                    "source-lock",
                    storage.expanded_registry.bindings.source_lock.path.as_str(),
                ),
                (
                    "rust-verifier",
                    storage
                        .expanded_registry
                        .bindings
                        .rust_verifier
                        .path
                        .as_str(),
                ),
                (
                    "jvm-verifier",
                    storage
                        .expanded_registry
                        .bindings
                        .jvm_verifier
                        .path
                        .as_str(),
                ),
                (
                    "negative-plan",
                    storage
                        .expanded_registry
                        .bindings
                        .negative_plan
                        .path
                        .as_str(),
                ),
            ] {
                ensure!(
                    path.starts_with("reproduction/schema/b4-corpus-v1.candidate/"),
                    "real V2 raw registry {label} binding is outside quarantine: {path}"
                );
            }
            ensure!(
                storage.expanded_registry.profile.manifest.path == input.profile_manifest.path,
                "real V2 profile binding must retain the exact B3 source path"
            );

            let nested_bytes = |identity: &B4ContractArtifactIdentityV1| -> Result<&[u8]> {
                generation
                    .nested_input_sources
                    .iter()
                    .find(|source| source.path == identity.path)
                    .map(|source| source.bytes.as_slice())
                    .with_context(|| {
                        format!(
                            "real V2 source fixture omits upstream bytes for {}",
                            identity.path
                        )
                    })
            };
            ensure!(
                B4ContractArtifactIdentityV1::from_bytes(
                    &generation.proof_generator.path,
                    B4ContractArtifactEncodingV1::RawBytes,
                    &generation.proof_generator.bytes,
                )? == input.generator,
                "real V2 proof-generator bytes differ from the positive input authority"
            );
            let rust_verifier = b"measured-rust-validator".as_slice();
            let jvm_verifier = b"measured-jvm-validator".as_slice();
            for (identity, bytes, label) in [
                (&prior.rust_verifier, rust_verifier, "Rust verifier"),
                (&prior.jvm_verifier, jvm_verifier, "JVM verifier"),
            ] {
                ensure!(
                    B4ContractArtifactIdentityV1::from_bytes(
                        &identity.path,
                        B4ContractArtifactEncodingV1::RawBytes,
                        bytes,
                    )? == *identity,
                    "real V2 {label} fixture bytes differ from the prior authority"
                );
            }
            let quarantine_copies = [
                (
                    storage.expanded_registry.bindings.generator.path.clone(),
                    generation.proof_generator.bytes.clone(),
                ),
                (
                    storage.expanded_registry.bindings.guest.elf.path.clone(),
                    nested_bytes(&input.guest_elf)?.to_vec(),
                ),
                (
                    storage
                        .expanded_registry
                        .bindings
                        .reference_statement_bundle
                        .manifest
                        .path
                        .clone(),
                    nested_bytes(&input.reference_statement_manifest)?.to_vec(),
                ),
                (
                    storage.expanded_registry.bindings.source_lock.path.clone(),
                    nested_bytes(&input.source_lock)?.to_vec(),
                ),
                (
                    storage
                        .expanded_registry
                        .bindings
                        .rust_verifier
                        .path
                        .clone(),
                    rust_verifier.to_vec(),
                ),
                (
                    storage.expanded_registry.bindings.jvm_verifier.path.clone(),
                    jvm_verifier.to_vec(),
                ),
                (
                    storage
                        .expanded_registry
                        .bindings
                        .negative_plan
                        .path
                        .clone(),
                    prior.negative_plan_jcs.clone(),
                ),
            ];
            for (path, bytes) in quarantine_copies {
                if let Some(previous) = sources.insert(path.clone(), bytes.clone()) {
                    ensure!(
                        previous == bytes,
                        "real V2 fixture preloaded conflicting quarantine bytes for {path}"
                    );
                }
            }

            let mut retain = |path: &str, bytes: &[u8]| -> Result<()> {
                if let Some(previous) = sources.get(path) {
                    ensure!(
                        previous == bytes,
                        "real V2 mint fixture has conflicting exact bytes for {path}"
                    );
                }
                sources.insert(path.to_owned(), bytes.to_vec());
                Ok(())
            };
            for artifact in generation
                .nested_input_sources
                .iter()
                .chain(std::iter::once(&generation.proof_generator))
                .chain(generation.runner_profiles.iter())
                .chain(generation.validator_descriptors.iter())
            {
                retain(&artifact.path, &artifact.bytes)?;
            }
            for (case_index, case) in generation.cases.iter().enumerate() {
                for (artifact, (role, _)) in case
                    .primary_artifacts
                    .iter()
                    .zip(positive_artifact_layout(case_index)?)
                {
                    if *role != B4PositiveArtifactRole::RawSeal {
                        retain(&artifact.path, &artifact.bytes)?;
                    }
                }
                for artifact in &case.auxiliary_artifacts {
                    retain(&artifact.path, &artifact.bytes)?;
                }
            }
            let expanded_registry_jcs = storage.expanded_registry.to_canonical_jcs()?;
            Ok(Self {
                lineage,
                campaign_precommit_jcs,
                storage,
                expanded_registry_jcs,
                sources,
            })
        }

        fn case_artifact_path(
            &self,
            case_index: usize,
            role: B4PositiveArtifactRole,
        ) -> Result<&str> {
            self.lineage.prior.sources.cases[case_index]
                .primary_artifacts
                .iter()
                .zip(positive_artifact_layout(case_index)?)
                .find(|(_, (candidate, _))| *candidate == role)
                .map(|(artifact, _)| artifact.path.as_str())
                .with_context(|| format!("real V2 mint case {case_index} omits role {role:?}"))
        }

        fn auxiliary_path(&self, case_index: usize, index: usize) -> Result<&str> {
            self.lineage.prior.sources.cases[case_index]
                .auxiliary_artifacts
                .get(index)
                .map(|artifact| artifact.path.as_str())
                .with_context(|| {
                    format!("real V2 mint case {case_index} omits auxiliary artifact {index}")
                })
        }

        fn quarantine_paths(&self, role: RealV2QuarantineRole) -> Result<(String, String)> {
            let prior = B4MaterializationPriorAuthoritySnapshotV2::from_authorities(
                &self.lineage.prior.campaign_precommit_authority,
                &self.lineage.prior.positive_generation_authority,
            )?;
            let input = parse_positive_input_sources_v2(
                &self.lineage.prior.sources.positive_input_set.bytes,
            )?;
            Ok((
                real_v2_registry_quarantine_binding(&self.storage.expanded_registry, role)
                    .path
                    .clone(),
                real_v2_quarantine_upstream_identity(role, &input, &prior)
                    .path
                    .clone(),
            ))
        }

        fn mint(
            &self,
            mutation: Option<RealV2SourceMutation<'_>>,
        ) -> Result<B4AuthenticatedMaterializationTopLevelV2> {
            let prior = B4MaterializationPriorAuthoritySnapshotV2::from_authorities(
                &self.lineage.prior.campaign_precommit_authority,
                &self.lineage.prior.positive_generation_authority,
            )?;
            let mut paths = B4PhysicalPathClosureV2::from_prior(&prior)?;
            let mut sources = self.sources.clone();
            let mut expanded_registry_jcs = self.expanded_registry_jcs.clone();
            let mut negative_plan_path = prior.negative_plan.path.clone();
            let mut negative_plan_jcs = prior.negative_plan_jcs.clone();
            let mut subject_catalog_path =
                "reproduction/schema/b4-corpus-v1.candidate/bindings/subject-catalog.json"
                    .to_owned();
            let mut terminal_fixture_catalog_path =
                "reproduction/schema/b4-corpus-v1.candidate/bindings/terminal-fixture-catalog.json"
                    .to_owned();
            if let Some(mutation) = mutation {
                match mutation {
                    RealV2SourceMutation::Relocate(target) => {
                        let bytes = sources.remove(target).with_context(|| {
                            format!("real V2 relocation target is absent: {target}")
                        })?;
                        sources.insert(format!("relocated/{target}"), bytes);
                    }
                    RealV2SourceMutation::Remove(target) => {
                        sources.remove(target).with_context(|| {
                            format!("real V2 removal target is absent: {target}")
                        })?;
                    }
                    RealV2SourceMutation::Truncate(target) => {
                        sources
                            .get_mut(target)
                            .with_context(|| format!("real V2 length target is absent: {target}"))?
                            .pop()
                            .context("cannot truncate an empty V2 source")?;
                    }
                    RealV2SourceMutation::FlipByte(target) => {
                        let first = sources
                            .get_mut(target)
                            .with_context(|| format!("real V2 digest target is absent: {target}"))?
                            .first_mut()
                            .context("cannot mutate an empty V2 source")?;
                        *first ^= 1;
                    }
                    RealV2SourceMutation::ChangeRecursiveFamily(target) => {
                        let bytes = sources.get_mut(target).with_context(|| {
                            format!("real V2 family target is absent: {target}")
                        })?;
                        let mut ancestry = validate_canonical_json_source(bytes)?;
                        ancestry["family"] = serde_json::json!("terminal-resolve");
                        *bytes = canonical_json_bytes(&ancestry)?;
                    }
                    RealV2SourceMutation::Case8CalibrationBasename => {
                        let mut registry =
                            B4CandidateCorpus::from_canonical_jcs(&expanded_registry_jcs)?;
                        let case_id = registry.positive_cases[8].case_id.clone();
                        let artifact = registry.positive_cases[8]
                            .artifacts
                            .iter_mut()
                            .find(|artifact| artifact.role == B4PositiveArtifactRole::Calibration)
                            .context("real V2 case 8 omits calibration")?;
                        let old_path = artifact.path.clone();
                        artifact.path = crate::b4::canonical_positive_case_artifact_path(
                            &case_id,
                            "candidate-calibration.json",
                        );
                        let bytes = sources
                            .remove(&old_path)
                            .context("real V2 calibration source is absent")?;
                        sources.insert(artifact.path.clone(), bytes);
                        expanded_registry_jcs = registry.to_canonical_jcs()?;
                    }
                    RealV2SourceMutation::RegistryQuarantineAlias(role) => {
                        let input = parse_positive_input_sources_v2(
                            &self.lineage.prior.sources.positive_input_set.bytes,
                        )?;
                        let mut registry =
                            B4CandidateCorpus::from_canonical_jcs(&expanded_registry_jcs)?;
                        let candidate_path = real_v2_registry_quarantine_binding(&registry, role)
                            .path
                            .clone();
                        let upstream_path =
                            real_v2_quarantine_upstream_identity(role, &input, &prior)
                                .path
                                .clone();
                        real_v2_registry_quarantine_binding_mut(&mut registry, role).path =
                            upstream_path;
                        ensure!(
                            sources.contains_key(&candidate_path),
                            "real V2 aliased quarantine source is absent before mutation: {candidate_path}"
                        );
                        expanded_registry_jcs = registry.to_canonical_jcs()?;
                    }
                    RealV2SourceMutation::RegistryQuarantineIdentityDrift(role) => {
                        let mut registry =
                            B4CandidateCorpus::from_canonical_jcs(&expanded_registry_jcs)?;
                        let binding = real_v2_registry_quarantine_binding_mut(&mut registry, role);
                        let alternate = match binding.encoding {
                            B4ArtifactEncoding::Rfc8785Jcs => {
                                canonical_json_bytes(&serde_json::json!({
                                    "format": "Eip0045B4QuarantineIdentityMutantV1",
                                    "role": format!("{role:?}")
                                }))?
                            }
                            B4ArtifactEncoding::RawBytes => {
                                format!("coordinated-quarantine-identity-drift-{role:?}")
                                    .into_bytes()
                            }
                        };
                        ensure!(
                            sources
                                .insert(binding.path.clone(), alternate.clone())
                                .is_some(),
                            "real V2 identity-drift quarantine source is absent"
                        );
                        binding.byte_length = u64::try_from(alternate.len())?;
                        binding.sha256 = sha256_hex(&alternate);
                        expanded_registry_jcs = registry.to_canonical_jcs()?;
                    }
                    RealV2SourceMutation::RegistryQuarantineEncoding(role) => {
                        let mut registry =
                            B4CandidateCorpus::from_canonical_jcs(&expanded_registry_jcs)?;
                        let binding = real_v2_registry_quarantine_binding_mut(&mut registry, role);
                        binding.encoding = match binding.encoding {
                            B4ArtifactEncoding::RawBytes => B4ArtifactEncoding::Rfc8785Jcs,
                            B4ArtifactEncoding::Rfc8785Jcs => B4ArtifactEncoding::RawBytes,
                        };
                        expanded_registry_jcs = registry.to_canonical_jcs()?;
                    }
                    RealV2SourceMutation::RegistryCandidatePathAlias => {
                        let mut registry =
                            B4CandidateCorpus::from_canonical_jcs(&expanded_registry_jcs)?;
                        registry.bindings.generator.path = registry.bindings.guest.elf.path.clone();
                        expanded_registry_jcs = registry.to_canonical_jcs()?;
                    }
                    RealV2SourceMutation::RelocateRegistryProfileManifest => {
                        let mut registry =
                            B4CandidateCorpus::from_canonical_jcs(&expanded_registry_jcs)?;
                        registry.profile.manifest.path =
                            "profiles/risc0-v3-succinct/relocated-manifest.bin".to_owned();
                        expanded_registry_jcs = registry.to_canonical_jcs()?;
                    }
                    RealV2SourceMutation::RelocateExternalNegativePlan => {
                        negative_plan_path = format!("relocated/{negative_plan_path}");
                    }
                    RealV2SourceMutation::TruncateExternalNegativePlan => {
                        negative_plan_jcs
                            .pop()
                            .context("cannot truncate the empty V2 external negative plan")?;
                    }
                    RealV2SourceMutation::FlipExternalNegativePlanByte => {
                        let first = negative_plan_jcs
                            .first_mut()
                            .context("cannot mutate the empty V2 external negative plan")?;
                        *first ^= 1;
                    }
                    RealV2SourceMutation::RelocateExternalSubjectCatalog => {
                        subject_catalog_path = "reproduction/schema/b4-corpus-v1.candidate/relocated/subject-catalog.json".to_owned();
                    }
                    RealV2SourceMutation::RelocateExternalTerminalFixtureCatalog => {
                        terminal_fixture_catalog_path = "reproduction/schema/b4-corpus-v1.candidate/relocated/terminal-fixture-catalog.json".to_owned();
                    }
                }
            }
            let source_views = sources
                .iter()
                .map(|(path, bytes)| B4NegativeMaterializationExternalBytesV1 { path, bytes })
                .collect::<Vec<_>>();
            let generation = &self.lineage.prior.sources;
            let positive_exports = generation
                .cases
                .iter()
                .enumerate()
                .map(|(case_index, case)| {
                    let raw = case
                        .primary_artifacts
                        .iter()
                        .zip(positive_artifact_layout(case_index)?)
                        .find(|(_, (role, _))| *role == B4PositiveArtifactRole::RawSeal)
                        .map(|(artifact, _)| artifact)
                        .context("real V2 mint omits a positive raw seal")?;
                    Ok(B4NegativeMaterializationPositiveExportV1 {
                        case_index: u8::try_from(case_index)?,
                        proof_output_manifest: B4NegativeMaterializationExternalBytesV1 {
                            path: &case.proof_output_manifest.path,
                            bytes: &case.proof_output_manifest.bytes,
                        },
                        raw_seal: B4NegativeMaterializationExternalBytesV1 {
                            path: &raw.path,
                            bytes: &raw.bytes,
                        },
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let no_alternate_artifacts = [];
            let external = B4NegativeMaterializationSetExternalInputsV1 {
                positive_input_set: B4NegativeMaterializationExternalBytesV1 {
                    path: &prior.positive_input_set.path,
                    bytes: &generation.positive_input_set.bytes,
                },
                campaign_precommit: B4NegativeMaterializationExternalBytesV1 {
                    path: "reproduction/campaign-precommit.json",
                    bytes: &self.campaign_precommit_jcs,
                },
                positive_generation_set: B4NegativeMaterializationExternalBytesV1 {
                    path: &prior.positive_generation_set.path,
                    bytes: &generation.positive_generation_set.bytes,
                },
                negative_plan: B4NegativeMaterializationExternalBytesV1 {
                    path: &negative_plan_path,
                    bytes: &negative_plan_jcs,
                },
                expanded_registry: B4NegativeMaterializationExternalBytesV1 {
                    path: "reproduction/schema/b4-corpus-v1.candidate/expanded-registry.json",
                    bytes: &expanded_registry_jcs,
                },
                subject_catalog: B4NegativeMaterializationExternalBytesV1 {
                    path: &subject_catalog_path,
                    bytes: &self.storage.subject_catalog_jcs,
                },
                terminal_fixture_catalog: B4NegativeMaterializationExternalBytesV1 {
                    path: &terminal_fixture_catalog_path,
                    bytes: &self.storage.terminal_fixture_catalog_jcs,
                },
                negative_binding_index: B4NegativeMaterializationExternalBytesV1 {
                    path: "reproduction/negative-binding-index.json",
                    bytes: &self.storage.negative_binding_index_jcs,
                },
                abstract_tree: B4NegativeMaterializationExternalBytesV1 {
                    path: "reproduction/abstract-tree.json",
                    bytes: &self.storage.abstract_tree_jcs,
                },
                positive_exports: &positive_exports,
                alternate_root_export: B4NegativeAlternateRootExportV1 {
                    proof_output_manifest: B4NegativeMaterializationExternalBytesV1 {
                        path: "test-only/unused-alternate-root-manifest.json",
                        bytes: b"{}",
                    },
                    artifacts: &no_alternate_artifacts,
                },
                source_artifacts: &source_views,
                executions: &[],
            };
            authenticate_top_level_v2(
                &prior,
                &self.lineage.prior.positive_generation_authority,
                &external,
                &mut paths,
            )
        }
    }

    #[cfg(feature = "negative-materialization-set")]
    fn real_v2_mint_rejection_message(
        fixture: &RealV2MaterializationMintFixture,
        mutation: RealV2SourceMutation<'_>,
    ) -> String {
        let error = fixture
            .mint(Some(mutation))
            .err()
            .expect("single-fault V2 source mutant unexpectedly authenticated");
        format!("{error:#}")
    }

    #[cfg(feature = "negative-materialization-set")]
    fn assert_real_v2_mint_rejects(
        fixture: &RealV2MaterializationMintFixture,
        mutation: RealV2SourceMutation<'_>,
    ) {
        let _ = real_v2_mint_rejection_message(fixture, mutation);
    }

    #[cfg(feature = "negative-materialization-set")]
    fn assert_real_v2_mint_rejects_with_any(
        fixture: &RealV2MaterializationMintFixture,
        mutation: RealV2SourceMutation<'_>,
        expected: &[&str],
    ) {
        let message = real_v2_mint_rejection_message(fixture, mutation);
        assert!(
            expected.iter().any(|needle| message.contains(needle)),
            "V2 mutant failed outside its expected boundary {:?}: {message}",
            expected
        );
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn real_v2_mint_resolves_nonzero_recursive_families_and_case9_restricted_seal() {
        let fixture = RealV2MaterializationMintFixture::exact().unwrap();
        let top_level = fixture.mint(None).unwrap();
        let resolver = crate::b4_fixture_sources::B4MaterializationFixtureSourceResolverV2::
            from_authenticated(&top_level)
            .unwrap();
        let nonzero_id = compiled_positive_case_id(1).unwrap();
        assert_eq!(
            resolver.positive_case(1, &nonzero_id).unwrap().case_index(),
            1
        );
        for family in [
            RecursiveAncestryFamily::TerminalJoin,
            RecursiveAncestryFamily::TerminalResolve,
            RecursiveAncestryFamily::ResolveThenJoin,
        ] {
            let recursive = resolver.recursive_ancestry_source(family).unwrap();
            assert_eq!(recursive.family(), family);
            assert!(!recursive.ancestry_jcs().is_empty());
            assert!(!recursive.final_raw_seal().is_empty());
            assert!(recursive.auxiliary_seals().len() > 0);
        }
        let restricted = resolver.case9_conditional_receipt_source().unwrap();
        assert_eq!(
            restricted.conditional_raw_seal_path(),
            fixture.auxiliary_path(9, 1).unwrap()
        );
        assert!(!restricted.conditional_raw_seal().is_empty());
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn real_v2_mint_rejects_nonzero_recursive_path_length_and_digest_mutants() {
        let fixture = RealV2MaterializationMintFixture::exact().unwrap();
        let path = fixture
            .case_artifact_path(8, B4PositiveArtifactRole::Ancestry)
            .unwrap();
        // These preserve every other source and respectively isolate physical
        // location, observed length, and same-length content digest.
        assert_real_v2_mint_rejects(&fixture, RealV2SourceMutation::Relocate(path));
        assert_real_v2_mint_rejects(&fixture, RealV2SourceMutation::Truncate(path));
        assert_real_v2_mint_rejects(&fixture, RealV2SourceMutation::FlipByte(path));
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn real_v2_mint_rejects_recursive_family_program_claim_control_and_aux_path_mutants() {
        let fixture = RealV2MaterializationMintFixture::exact().unwrap();
        let ancestry = fixture
            .case_artifact_path(8, B4PositiveArtifactRole::Ancestry)
            .unwrap();
        assert_real_v2_mint_rejects(
            &fixture,
            RealV2SourceMutation::ChangeRecursiveFamily(ancestry),
        );
        // Program, claim, and control are equally path-qualified 32-byte
        // primary identities; parameterizing the identical single-byte fault
        // proves the same authority predicate without conflating sources.
        for role in [
            B4PositiveArtifactRole::ImageId,
            B4PositiveArtifactRole::ClaimDigest,
            B4PositiveArtifactRole::ControlId,
        ] {
            let path = fixture.case_artifact_path(8, role).unwrap();
            assert_real_v2_mint_rejects(&fixture, RealV2SourceMutation::FlipByte(path));
        }
        let auxiliary = fixture.auxiliary_path(8, 0).unwrap();
        assert_real_v2_mint_rejects(&fixture, RealV2SourceMutation::Relocate(auxiliary));
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn real_v2_mint_rejects_case9_restricted_seal_and_nonzero_global_journal_mutants() {
        let fixture = RealV2MaterializationMintFixture::exact().unwrap();
        let restricted = fixture.auxiliary_path(9, 1).unwrap();
        assert_real_v2_mint_rejects(&fixture, RealV2SourceMutation::FlipByte(restricted));
        let journal = fixture
            .case_artifact_path(1, B4PositiveArtifactRole::Journal)
            .unwrap();
        assert_real_v2_mint_rejects(&fixture, RealV2SourceMutation::FlipByte(journal));
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn real_v2_mint_rejects_case8_calibration_canonical_basename_mutant() {
        let fixture = RealV2MaterializationMintFixture::exact().unwrap();
        // The source move and registry identity remain mutually coherent and
        // preserve the case prefix, bytes, length, and digest. Only the exact
        // production basename changes.
        assert_real_v2_mint_rejects(&fixture, RealV2SourceMutation::Case8CalibrationBasename);
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn real_v2_mint_rejects_each_quarantine_copy_alias_absence_and_identity_drift() {
        let fixture = RealV2MaterializationMintFixture::exact().unwrap();
        let prior = B4MaterializationPriorAuthoritySnapshotV2::from_authorities(
            &fixture.lineage.prior.campaign_precommit_authority,
            &fixture.lineage.prior.positive_generation_authority,
        )
        .unwrap();

        for role in RealV2QuarantineRole::ALL {
            let (candidate_path, upstream_path) = fixture.quarantine_paths(role).unwrap();
            assert_ne!(candidate_path, upstream_path, "{role:?} aliases upstream");
            let candidate_bytes = fixture.sources.get(&candidate_path).unwrap();
            match role {
                RealV2QuarantineRole::RustVerifier => {
                    assert_eq!(
                        candidate_bytes.as_slice(),
                        b"measured-rust-validator",
                        "{role:?}"
                    );
                }
                RealV2QuarantineRole::JvmVerifier => {
                    assert_eq!(
                        candidate_bytes.as_slice(),
                        b"measured-jvm-validator",
                        "{role:?}"
                    );
                }
                RealV2QuarantineRole::NegativePlan => {
                    assert_eq!(candidate_bytes, &prior.negative_plan_jcs, "{role:?}");
                }
                _ => assert_eq!(
                    candidate_bytes,
                    fixture.sources.get(&upstream_path).unwrap(),
                    "{role:?}"
                ),
            }

            assert_real_v2_mint_rejects_with_any(
                &fixture,
                RealV2SourceMutation::RegistryQuarantineAlias(role),
                &["outside its quarantine tree"],
            );
            assert_real_v2_mint_rejects_with_any(
                &fixture,
                RealV2SourceMutation::Remove(&candidate_path),
                &["source-artifact inventory"],
            );
            assert_real_v2_mint_rejects_with_any(
                &fixture,
                RealV2SourceMutation::Relocate(&candidate_path),
                &["source-artifact inventory"],
            );
            assert_real_v2_mint_rejects_with_any(
                &fixture,
                RealV2SourceMutation::Truncate(&candidate_path),
                &["source artifact differs"],
            );
            assert_real_v2_mint_rejects_with_any(
                &fixture,
                RealV2SourceMutation::FlipByte(&candidate_path),
                &["source artifact differs"],
            );
            assert_real_v2_mint_rejects_with_any(
                &fixture,
                RealV2SourceMutation::RegistryQuarantineEncoding(role),
                &["encoding drift", "raw bytes", "RFC 8785 JCS"],
            );
        }
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn real_v2_mint_rejects_coordinated_identity_drift_for_each_prior_backed_quarantine_role() {
        let fixture = RealV2MaterializationMintFixture::exact().unwrap();
        for role in RealV2QuarantineRole::PRIOR_BACKED_SIX {
            assert_real_v2_mint_rejects_with_any(
                &fixture,
                RealV2SourceMutation::RegistryQuarantineIdentityDrift(role),
                &["quarantine copy differs from the authenticated prior authority"],
            );
        }
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn real_v2_mint_rejects_candidate_to_candidate_path_alias() {
        let fixture = RealV2MaterializationMintFixture::exact().unwrap();
        assert_real_v2_mint_rejects_with_any(
            &fixture,
            RealV2SourceMutation::RegistryCandidatePathAlias,
            &["one path to two byte identities"],
        );
    }

    #[cfg(feature = "negative-materialization-set")]
    #[derive(Clone, Copy, Debug)]
    enum PriorClosureKeyMutation {
        AddPath,
        RemovePath,
        AddDigestKey,
        RemoveDigestKey,
    }

    #[cfg(feature = "negative-materialization-set")]
    fn mutate_v1_prior_closure_keys(
        prior: &mut B4MaterializationPriorAuthoritySnapshotV1,
        mutation: PriorClosureKeyMutation,
    ) {
        match mutation {
            PriorClosureKeyMutation::AddPath => {
                prior
                    .provenance_paths
                    .insert("test-only/v1-extra-prior-path.bin".to_owned());
            }
            PriorClosureKeyMutation::RemovePath => {
                let path = prior.provenance_paths.iter().next().unwrap().clone();
                assert!(prior.provenance_paths.remove(&path));
            }
            PriorClosureKeyMutation::AddDigestKey => {
                assert!(
                    prior
                        .provenance_sha256
                        .insert(
                            "test-only/v1-extra-prior-digest.bin".to_owned(),
                            "00".repeat(32),
                        )
                        .is_none()
                );
            }
            PriorClosureKeyMutation::RemoveDigestKey => {
                let path = prior.provenance_sha256.keys().next().unwrap().clone();
                assert!(prior.provenance_sha256.remove(&path).is_some());
            }
        }
    }

    #[cfg(feature = "negative-materialization-set")]
    fn mutate_v2_prior_closure_keys(
        prior: &mut B4MaterializationPriorAuthoritySnapshotV2,
        mutation: PriorClosureKeyMutation,
    ) {
        match mutation {
            PriorClosureKeyMutation::AddPath => {
                prior
                    .provenance_paths
                    .insert("test-only/v2-extra-prior-path.bin".to_owned());
            }
            PriorClosureKeyMutation::RemovePath => {
                let path = prior.provenance_paths.iter().next().unwrap().clone();
                assert!(prior.provenance_paths.remove(&path));
            }
            PriorClosureKeyMutation::AddDigestKey => {
                assert!(
                    prior
                        .provenance_sha256
                        .insert(
                            "test-only/v2-extra-prior-digest.bin".to_owned(),
                            "00".repeat(32),
                        )
                        .is_none()
                );
            }
            PriorClosureKeyMutation::RemoveDigestKey => {
                let path = prior.provenance_sha256.keys().next().unwrap().clone();
                assert!(prior.provenance_sha256.remove(&path).is_some());
            }
        }
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn v1_and_v2_physical_closures_reject_each_path_digest_key_set_mutant() {
        let v1 = crate::b4_negative_ancestry_authority::test_support::
            fixed_negative_ancestry_lineage_test_support()
            .unwrap();
        let v2 = crate::b4_negative_ancestry_authority::test_support::
            fixed_negative_ancestry_lineage_test_support_v2()
            .unwrap();
        for mutation in [
            PriorClosureKeyMutation::AddPath,
            PriorClosureKeyMutation::RemovePath,
            PriorClosureKeyMutation::AddDigestKey,
            PriorClosureKeyMutation::RemoveDigestKey,
        ] {
            let mut prior_v1 = B4MaterializationPriorAuthoritySnapshotV1::from_authorities(
                &v1.prior.campaign_precommit_authority,
                &v1.prior.positive_generation_authority,
            )
            .unwrap();
            mutate_v1_prior_closure_keys(&mut prior_v1, mutation);
            let v1_error = B4PhysicalPathClosureV1::from_prior(&prior_v1)
                .err()
                .expect("V1 prior closure key-set mutant unexpectedly authenticated");
            assert!(
                format!("{v1_error:#}").contains(
                    "prior authority path/digest closure is incomplete at physical-path construction"
                ),
                "unexpected V1 {mutation:?} rejection: {v1_error:#}"
            );

            let mut prior_v2 = B4MaterializationPriorAuthoritySnapshotV2::from_authorities(
                &v2.prior.campaign_precommit_authority,
                &v2.prior.positive_generation_authority,
            )
            .unwrap();
            mutate_v2_prior_closure_keys(&mut prior_v2, mutation);
            let v2_error = B4PhysicalPathClosureV2::from_prior(&prior_v2)
                .err()
                .expect("V2 prior closure key-set mutant unexpectedly authenticated");
            assert!(
                format!("{v2_error:#}").contains(
                    "V2 prior authority path/digest closure is incomplete at physical-path construction"
                ),
                "unexpected V2 {mutation:?} rejection: {v2_error:#}"
            );
        }
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn real_v2_mint_rejects_each_upstream_quarantine_occurrence_drift() {
        let fixture = RealV2MaterializationMintFixture::exact().unwrap();

        for role in [
            RealV2QuarantineRole::Generator,
            RealV2QuarantineRole::GuestElf,
            RealV2QuarantineRole::ReferenceStatementManifest,
            RealV2QuarantineRole::SourceLock,
        ] {
            let (_, upstream_path) = fixture.quarantine_paths(role).unwrap();
            assert!(
                fixture.sources.contains_key(&upstream_path),
                "{role:?} upstream source is not physically supplied"
            );
            assert_real_v2_mint_rejects_with_any(
                &fixture,
                RealV2SourceMutation::Remove(&upstream_path),
                &[
                    "proof generator",
                    "proof-generator",
                    "source-artifact inventory",
                ],
            );
            assert_real_v2_mint_rejects_with_any(
                &fixture,
                RealV2SourceMutation::Relocate(&upstream_path),
                &[
                    "proof generator",
                    "proof-generator",
                    "source-artifact inventory",
                ],
            );
            assert_real_v2_mint_rejects_with_any(
                &fixture,
                RealV2SourceMutation::Truncate(&upstream_path),
                &[
                    "proof generator",
                    "proof-generator",
                    "source artifact differs",
                ],
            );
            assert_real_v2_mint_rejects_with_any(
                &fixture,
                RealV2SourceMutation::FlipByte(&upstream_path),
                &[
                    "proof generator",
                    "proof-generator",
                    "source artifact differs",
                ],
            );
        }
        assert_real_v2_mint_rejects_with_any(
            &fixture,
            RealV2SourceMutation::RelocateExternalNegativePlan,
            &["V2 negative plan"],
        );
        assert_real_v2_mint_rejects_with_any(
            &fixture,
            RealV2SourceMutation::TruncateExternalNegativePlan,
            &["V2 negative plan"],
        );
        assert_real_v2_mint_rejects_with_any(
            &fixture,
            RealV2SourceMutation::FlipExternalNegativePlanByte,
            &["V2 negative plan"],
        );
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn real_v2_mint_rejects_same_bytes_at_wrong_profile_and_catalog_paths() {
        let fixture = RealV2MaterializationMintFixture::exact().unwrap();
        assert_real_v2_mint_rejects_with_any(
            &fixture,
            RealV2SourceMutation::RelocateRegistryProfileManifest,
            &["B3 binary manifest identity drift"],
        );
        assert_real_v2_mint_rejects_with_any(
            &fixture,
            RealV2SourceMutation::RelocateExternalSubjectCatalog,
            &["V2 expanded-registry subject catalog"],
        );
        assert_real_v2_mint_rejects_with_any(
            &fixture,
            RealV2SourceMutation::RelocateExternalTerminalFixtureCatalog,
            &["V2 expanded-registry terminal fixture catalog"],
        );
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn catalog_cross_bindings_require_independent_negative_plan_and_profile_manifest() {
        let support = crate::b4_negative_ancestry_authority::test_support::
            fixed_negative_ancestry_lineage_test_support()
            .unwrap();
        let negative_plan = support
            .prior
            .campaign_precommit_authority
            .verifier_authority()
            .contract()
            .negative_plan
            .clone();
        let profile_manifest = B4ContractArtifactIdentityV1::from_bytes(
            &support.prior.profile_manifest.path,
            B4ContractArtifactEncodingV1::RawBytes,
            &support.prior.profile_manifest.bytes,
        )
        .unwrap();
        verify_negative_ancestry_catalog_cross_bindings(
            support.ancestry.catalog(),
            &negative_plan,
            &profile_manifest,
        )
        .unwrap();

        let mut wrong_plan = negative_plan.clone();
        wrong_plan.sha256 = sha256_hex(b"wrong negative plan");
        assert!(
            verify_negative_ancestry_catalog_cross_bindings(
                support.ancestry.catalog(),
                &wrong_plan,
                &profile_manifest,
            )
            .is_err()
        );

        let mut wrong_profile = profile_manifest.clone();
        wrong_profile.sha256 = sha256_hex(b"wrong profile manifest");
        assert!(
            verify_negative_ancestry_catalog_cross_bindings(
                support.ancestry.catalog(),
                &negative_plan,
                &wrong_profile,
            )
            .is_err()
        );

        let mut coordinated_copy = support.ancestry.catalog().clone();
        coordinated_copy.negative_plan = wrong_plan;
        coordinated_copy.profile_manifest = wrong_profile;
        assert!(
            verify_negative_ancestry_catalog_cross_bindings(
                &coordinated_copy,
                &negative_plan,
                &profile_manifest,
            )
            .is_err()
        );
    }

    fn input_identity(path: &str, bytes: &[u8], encoding: &str) -> Value {
        serde_json::json!({
            "path": path,
            "byteLength": bytes.len(),
            "sha256": sha256_hex(bytes),
            "encoding": encoding,
        })
    }

    fn contract_identity(
        path: &str,
        bytes: &[u8],
        encoding: B4ContractArtifactEncodingV1,
    ) -> B4ContractArtifactIdentityV1 {
        B4ContractArtifactIdentityV1::from_bytes(path, encoding, bytes).unwrap()
    }

    fn set_registry_binding(
        binding: &mut B4ArtifactBinding,
        identity: &B4ContractArtifactIdentityV1,
    ) {
        binding.state = B4BindingState::Bound;
        binding.path.clone_from(&identity.path);
        binding.byte_length = identity.byte_length;
        binding.sha256.clone_from(&identity.sha256);
        binding.encoding = match identity.encoding {
            B4ContractArtifactEncodingV1::RawBytes => B4ArtifactEncoding::RawBytes,
            B4ContractArtifactEncodingV1::Rfc8785Jcs => B4ArtifactEncoding::Rfc8785Jcs,
            B4ContractArtifactEncodingV1::GitBundle => panic!("registry cannot bind Git bundles"),
        };
    }

    fn set_registry_quarantine_copy_binding(
        binding: &mut B4ArtifactBinding,
        identity: &B4ContractArtifactIdentityV1,
        candidate_path: &str,
    ) {
        assert!(candidate_path.starts_with("reproduction/schema/b4-corpus-v1.candidate/"));
        assert_ne!(candidate_path, identity.path);
        set_registry_binding(binding, identity);
        binding.path = candidate_path.to_owned();
    }

    fn alternate_positive_inputs(
        image_id: &[u8],
        journal: &[u8],
        guest_elf: &[u8],
    ) -> B4AuthenticatedPositiveInputSourcesV1 {
        let guest = contract_identity(
            "inputs/guest.elf",
            guest_elf,
            B4ContractArtifactEncodingV1::RawBytes,
        );
        let statement_manifest = contract_identity(
            "inputs/reference-statement-manifest.json",
            b"statement-manifest",
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
        );
        let dummy = contract_identity(
            "inputs/dummy.bin",
            b"dummy",
            B4ContractArtifactEncodingV1::RawBytes,
        );
        B4AuthenticatedPositiveInputSourcesV1 {
            profile_id: "0".repeat(64),
            profile_manifest: dummy.clone(),
            profile_algorithm: dummy.clone(),
            profile_constants: dummy.clone(),
            guest_elf: guest,
            guest_image_id: hex::encode(image_id),
            reference_statement_manifest: statement_manifest,
            reference_contract_id: "1".repeat(64),
            reference_statement_byte_length: u64::try_from(journal.len()).unwrap(),
            reference_statement_sha256: sha256_hex(journal),
            reference_chain_domain_id: "2".repeat(64),
            reference_application_payload_byte_length: 0,
            reference_application_payload_sha256: sha256_hex(b""),
            source_lock: dummy.clone(),
            generator: dummy,
            artifacts: BTreeMap::new(),
        }
    }

    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the test fixture mirrors the complete alternate-root metadata record field-for-field"
    )]
    fn alternate_metadata_fixture(
        image_id: &[u8],
        journal: &[u8],
        claim_digest: &[u8],
        control_id: &[u8],
        guest_elf: &[u8],
        raw_seal: &[u8],
        receipt_oracle: &[u8],
    ) -> CandidateMetadataV1 {
        let journal_digest = sha256_hex(journal);
        CandidateMetadataV1 {
            candidate_status: "non-final-alternate-root-negative-witness".to_owned(),
            format_version: 1,
            upstream: CandidateUpstreamMetadataV1 {
                repository: RISC0_REPOSITORY.to_owned(),
                commit: RISC0_COMMIT.to_owned(),
                risc0_zkvm_version: B4_TERMINAL_FIXTURE_RISC0_VERSION.to_owned(),
                receipt_oracle_codec: "bincode-1.3.3-upstream-host-serialization".to_owned(),
            },
            method: CandidateMethodMetadataV1 {
                image_id: hex::encode(image_id),
                elf_length: guest_elf.len().to_string(),
                elf_sha256: sha256_hex(guest_elf),
            },
            proof_bound: CandidateProofBoundMetadataV1 {
                receipt_bound: true,
                statement_length: journal.len().to_string(),
                statement_sha256: sha256_hex(journal),
                journal_digest: journal_digest.clone(),
                claim_digest: hex::encode(claim_digest),
            },
            private_calibration: CandidatePrivateCalibrationMetadataV1 {
                receipt_bound: false,
                candidate_scope: "local-reproduction-provenance-only".to_owned(),
                selection_rule: "canonical-monotone-ranking-v1-not-global-minimum".to_owned(),
                selected_observation_is_exact: true,
                workload_iterations: "0".to_owned(),
                workload_seed_hex: "4549503030343501".to_owned(),
            },
            local_execution_observation: CandidateLocalExecutionObservationV1 {
                receipt_bound: false,
                candidate_scope: "local-reproduction-provenance-only".to_owned(),
                segment_count: "1".to_owned(),
                executor_segment_limit_po2: 23,
                segment_po2: 15,
                user_cycles: "3399".to_owned(),
                total_cycles: "32768".to_owned(),
                paging_cycles: "15864".to_owned(),
                reserved_cycles: "13505".to_owned(),
            },
            proof: CandidateProofMetadataV1 {
                receipt_kind: "succinct-single-lift-fixed-alternate-root".to_owned(),
                hash_function: "poseidon2".to_owned(),
                control_id: hex::encode(control_id),
                inner_control_root: B4_ALTERNATE_CONTROL_ROOT_HEX.to_owned(),
                verifier_parameters: B4_ALTERNATE_VERIFIER_PARAMETERS_HEX.to_owned(),
                outer_po2: u32::from(RISC0_OUTER_PO2),
                raw_seal_words: PROOF_WORDS.to_string(),
                raw_seal_bytes: PROOF_BYTES.to_string(),
                claim_digest: hex::encode(claim_digest),
                journal_digest,
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
            files: vec![
                CandidateFileMetadataV1 {
                    path: "candidate-raw-seal.bin".to_owned(),
                    length: raw_seal.len().to_string(),
                    sha256: sha256_hex(raw_seal),
                    role: "raw-succinct-seal".to_owned(),
                },
                CandidateFileMetadataV1 {
                    path: "candidate-receipt-oracle.bincode".to_owned(),
                    length: receipt_oracle.len().to_string(),
                    sha256: sha256_hex(receipt_oracle),
                    role: "upstream-bincode-receipt-oracle".to_owned(),
                },
                CandidateFileMetadataV1 {
                    path: "candidate-journal.bin".to_owned(),
                    length: journal.len().to_string(),
                    sha256: sha256_hex(journal),
                    role: "journal".to_owned(),
                },
                CandidateFileMetadataV1 {
                    path: "candidate-image-id.bin".to_owned(),
                    length: image_id.len().to_string(),
                    sha256: sha256_hex(image_id),
                    role: "guest-image-id".to_owned(),
                },
                CandidateFileMetadataV1 {
                    path: "candidate-claim-digest.bin".to_owned(),
                    length: claim_digest.len().to_string(),
                    sha256: sha256_hex(claim_digest),
                    role: "receipt-claim-digest".to_owned(),
                },
                CandidateFileMetadataV1 {
                    path: "candidate-control-id.bin".to_owned(),
                    length: control_id.len().to_string(),
                    sha256: sha256_hex(control_id),
                    role: "normal-lift-control-id".to_owned(),
                },
            ],
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the parser test isolates every required nested field and scalar in one canonical input document"
    )]
    fn authenticated_input_set_seeds_every_nested_path_and_profile_source_digest() {
        let manifest = input_identity("profiles/manifest.bin", b"manifest", "raw-bytes");
        let algorithm = input_identity("profiles/algorithm.txt", b"algorithm", "raw-bytes");
        let constants = input_identity("profiles/constants.bin", b"constants", "raw-bytes");
        let guest = input_identity("guest/guest.elf", b"guest", "raw-bytes");
        let statement = input_identity("statement/bundle.json", b"statement", "rfc8785-jcs");
        let source_lock = input_identity("source/lock.json", b"source-lock", "rfc8785-jcs");
        let generator = input_identity("bin/generator", b"generator", "raw-bytes");
        let cli = input_identity("contracts/verifier.json", b"cli", "rfc8785-jcs");
        let statement_byte_length = crate::constants::STATEMENT_PREFIX_BYTES + 7;
        let chain_domain_id = sha256_hex(b"chain-domain-id");
        let application_payload_sha256 = sha256_hex(b"payload");
        let value = serde_json::json!({
            "format": "Eip0045B4PositiveInputSetV1",
            "formatVersion": 1,
            "profile": {
                "profileId": sha256_hex(b"profile-id"),
                "manifest": manifest,
                "algorithm": algorithm,
                "constants": constants,
            },
            "guest": {
                "elf": guest,
                "imageId": sha256_hex(b"image-id"),
            },
            "referenceStatement": {
                "bundleManifest": statement,
                "contractId": sha256_hex(b"contract-id"),
                "statementByteLength": statement_byte_length,
                "statementSha256": sha256_hex(b"statement-bytes"),
                "chainDomainId": chain_domain_id,
                "applicationPayloadByteLength": 7,
                "applicationPayloadSha256": application_payload_sha256,
            },
            "sourceLock": source_lock,
            "proofGenerator": {"artifact": generator},
            "verifierCliContract": cli,
        });
        let bytes = canonical_json_bytes(&value).unwrap();
        let mut identities = BTreeMap::new();
        collect_contract_artifact_identities(&value, &mut identities).unwrap();
        let mut paths = B4PhysicalPathClosureV1 {
            paths: identities.keys().cloned().collect(),
            sha256_by_path: BTreeMap::new(),
            role_by_path: identities
                .keys()
                .map(|path| (path.clone(), B4PhysicalPathRoleV1::Source))
                .collect(),
            #[cfg(feature = "negative-materialization-set")]
            publication_paths: BTreeSet::new(),
        };

        let authenticated = authenticate_positive_input_sources(&bytes, &mut paths).unwrap();

        assert_eq!(authenticated.artifacts, identities);
        assert_eq!(
            authenticated.profile_algorithm.path,
            "profiles/algorithm.txt"
        );
        assert_eq!(
            authenticated.profile_constants.path,
            "profiles/constants.bin"
        );
        assert_eq!(
            authenticated.reference_statement_manifest().path,
            "statement/bundle.json"
        );
        assert_eq!(
            authenticated.reference_statement_byte_length(),
            statement_byte_length as u64
        );
        assert_eq!(authenticated.reference_chain_domain_id(), chain_domain_id);
        assert_eq!(authenticated.reference_application_payload_byte_length(), 7);
        assert_eq!(
            authenticated.reference_application_payload_sha256(),
            application_payload_sha256
        );
        assert_eq!(paths.sha256_by_path.len(), identities.len());
        assert!(
            identities.iter().all(|(path, identity)| {
                paths.sha256_by_path.get(path) == Some(&identity.sha256)
            })
        );

        for required in [
            "statementByteLength",
            "chainDomainId",
            "applicationPayloadByteLength",
            "applicationPayloadSha256",
        ] {
            let mut missing = value.clone();
            missing["referenceStatement"]
                .as_object_mut()
                .unwrap()
                .remove(required);
            let missing_jcs = canonical_json_bytes(&missing).unwrap();
            assert!(
                parse_positive_input_sources(&missing_jcs).is_err(),
                "accepted missing reference-statement field {required}"
            );
        }

        let mut inconsistent_length = value;
        inconsistent_length["referenceStatement"]["statementByteLength"] =
            serde_json::json!(statement_byte_length + 1);
        let inconsistent_jcs = canonical_json_bytes(&inconsistent_length).unwrap();
        assert!(
            parse_positive_input_sources(&inconsistent_jcs).is_err(),
            "accepted a reference statement length inconsistent with its payload"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn coordinated_registry_and_input_rewrite_cannot_replace_prior_binary_authority() {
        let manifest = contract_identity(
            "profiles/manifest.bin",
            b"manifest",
            B4ContractArtifactEncodingV1::RawBytes,
        );
        let algorithm = contract_identity(
            "profiles/algorithm.txt",
            b"algorithm",
            B4ContractArtifactEncodingV1::RawBytes,
        );
        let constants = contract_identity(
            "profiles/constants.bin",
            b"constants",
            B4ContractArtifactEncodingV1::RawBytes,
        );
        let guest = contract_identity(
            "guest/guest.elf",
            b"guest",
            B4ContractArtifactEncodingV1::RawBytes,
        );
        let statement = contract_identity(
            "statement/bundle.json",
            b"statement",
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
        );
        let source_lock = contract_identity(
            "source/lock.json",
            b"source-lock",
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
        );
        let generator = contract_identity(
            "bin/generator",
            b"generator",
            B4ContractArtifactEncodingV1::RawBytes,
        );
        let rust = contract_identity(
            "bin/rust-verifier",
            b"rust",
            B4ContractArtifactEncodingV1::RawBytes,
        );
        let jvm = contract_identity(
            "bin/jvm-verifier",
            b"jvm",
            B4ContractArtifactEncodingV1::RawBytes,
        );
        let profile_id = sha256_hex(b"profile-id");
        let guest_image_id = sha256_hex(b"image-id");
        let reference_contract_id = sha256_hex(b"contract-id");
        let reference_statement_sha256 = sha256_hex(b"statement-bytes");
        let input = B4AuthenticatedPositiveInputSourcesV1 {
            profile_id: profile_id.clone(),
            profile_manifest: manifest.clone(),
            profile_algorithm: algorithm,
            profile_constants: constants,
            guest_elf: guest.clone(),
            guest_image_id: guest_image_id.clone(),
            reference_statement_manifest: statement.clone(),
            reference_contract_id: reference_contract_id.clone(),
            reference_statement_byte_length: crate::constants::STATEMENT_PREFIX_BYTES as u64,
            reference_statement_sha256: reference_statement_sha256.clone(),
            reference_chain_domain_id: sha256_hex(b"chain-domain-id"),
            reference_application_payload_byte_length: 0,
            reference_application_payload_sha256: sha256_hex(b""),
            source_lock: source_lock.clone(),
            generator: generator.clone(),
            artifacts: BTreeMap::new(),
        };
        let mut registry = B4CandidateCorpus::from_canonical_jcs(include_bytes!(
            "../schema/b4-corpus-v1.candidate.json"
        ))
        .unwrap();
        set_registry_binding(&mut registry.profile.manifest, &manifest);
        registry.profile.profile_id = profile_id;
        set_registry_quarantine_copy_binding(
            &mut registry.bindings.generator,
            &generator,
            "reproduction/schema/b4-corpus-v1.candidate/bindings/generator.bin",
        );
        set_registry_quarantine_copy_binding(
            &mut registry.bindings.guest.elf,
            &guest,
            "reproduction/schema/b4-corpus-v1.candidate/bindings/guest.elf",
        );
        registry.bindings.guest.state = B4BindingState::Bound;
        registry.bindings.guest.image_id = guest_image_id;
        set_registry_quarantine_copy_binding(
            &mut registry.bindings.reference_statement_bundle.manifest,
            &statement,
            "reproduction/schema/b4-corpus-v1.candidate/bindings/statement-manifest.json",
        );
        registry.bindings.reference_statement_bundle.state = B4BindingState::Bound;
        registry.bindings.reference_statement_bundle.contract_id = reference_contract_id;
        registry
            .bindings
            .reference_statement_bundle
            .statement_sha256 = reference_statement_sha256;
        set_registry_quarantine_copy_binding(
            &mut registry.bindings.source_lock,
            &source_lock,
            "reproduction/schema/b4-corpus-v1.candidate/bindings/source-lock.json",
        );
        set_registry_quarantine_copy_binding(
            &mut registry.bindings.rust_verifier,
            &rust,
            "reproduction/schema/b4-corpus-v1.candidate/bindings/rust-verifier.bin",
        );
        set_registry_quarantine_copy_binding(
            &mut registry.bindings.jvm_verifier,
            &jvm,
            "reproduction/schema/b4-corpus-v1.candidate/bindings/jvm-verifier.bin",
        );
        let prior = B4MaterializationPriorAuthoritySnapshotV1 {
            campaign_precommit_jcs: Vec::new(),
            positive_input_set: generator.clone(),
            positive_generation_set: generator.clone(),
            negative_plan: generator.clone(),
            negative_plan_jcs: Vec::new(),
            generator: contract_identity(
                "campaign/executor",
                b"generator",
                B4ContractArtifactEncodingV1::RawBytes,
            ),
            rust_verifier: rust,
            jvm_verifier: jvm,
            positive_cases: Vec::new(),
            provenance_paths: BTreeSet::new(),
            provenance_sha256: BTreeMap::new(),
        };
        authenticate_registry_prior_bindings(&registry, &input, &prior).unwrap();

        for role in [
            "generator",
            "guest",
            "reference-statement",
            "source-lock",
            "rust-verifier",
            "jvm-verifier",
        ] {
            let mut aliased_registry = registry.clone();
            match role {
                "generator" => aliased_registry
                    .bindings
                    .generator
                    .path
                    .clone_from(&input.generator.path),
                "guest" => aliased_registry
                    .bindings
                    .guest
                    .elf
                    .path
                    .clone_from(&input.guest_elf.path),
                "reference-statement" => aliased_registry
                    .bindings
                    .reference_statement_bundle
                    .manifest
                    .path
                    .clone_from(&input.reference_statement_manifest.path),
                "source-lock" => aliased_registry
                    .bindings
                    .source_lock
                    .path
                    .clone_from(&input.source_lock.path),
                "rust-verifier" => aliased_registry
                    .bindings
                    .rust_verifier
                    .path
                    .clone_from(&prior.rust_verifier.path),
                "jvm-verifier" => aliased_registry
                    .bindings
                    .jvm_verifier
                    .path
                    .clone_from(&prior.jvm_verifier.path),
                _ => unreachable!(),
            }
            let error = authenticate_registry_prior_bindings(&aliased_registry, &input, &prior)
                .expect_err("shared upstream/quarantine path alias unexpectedly authenticated");
            assert!(
                format!("{error:#}").contains("quarantine copy"),
                "{role} alias failed outside quarantine-copy authentication: {error:#}"
            );
        }

        let alternate_generator = contract_identity(
            "bin/generator",
            b"coordinated-rewrite",
            B4ContractArtifactEncodingV1::RawBytes,
        );
        let mut rewritten_input = input;
        rewritten_input.generator = alternate_generator.clone();
        set_registry_quarantine_copy_binding(
            &mut registry.bindings.generator,
            &alternate_generator,
            "reproduction/schema/b4-corpus-v1.candidate/bindings/generator.bin",
        );
        let error =
            authenticate_registry_prior_bindings(&registry, &rewritten_input, &prior).unwrap_err();
        assert!(format!("{error:#}").contains("campaign-precommit authority"));
    }

    #[test]
    fn generator_executor_content_identity_rejects_each_isolated_identity_drift() {
        let generator = contract_identity(
            "bin/generator",
            b"shared executable bytes",
            B4ContractArtifactEncodingV1::RawBytes,
        );
        let executor = contract_identity(
            "campaign/executor",
            b"shared executable bytes",
            B4ContractArtifactEncodingV1::RawBytes,
        );
        authenticate_generator_executor_content_identity(&generator, &executor, "test identity")
            .unwrap();

        for mutant in ["same-path", "length", "encoding", "digest"] {
            let mut changed_executor = executor.clone();
            match mutant {
                "same-path" => changed_executor.path.clone_from(&generator.path),
                "length" => changed_executor.byte_length += 1,
                "encoding" => changed_executor.encoding = B4ContractArtifactEncodingV1::Rfc8785Jcs,
                "digest" => changed_executor.sha256 = sha256_hex(b"different executable bytes"),
                _ => unreachable!(),
            }
            let error = authenticate_generator_executor_content_identity(
                &generator,
                &changed_executor,
                "test identity",
            )
            .expect_err("isolated generator/executor identity mutant unexpectedly authenticated");
            assert!(
                format!("{error:#}").contains("different generator/executor content identities"),
                "{mutant} failed outside generator/executor identity authentication: {error:#}"
            );
        }
    }

    #[test]
    fn negative_plan_quarantine_copy_rejects_each_isolated_identity_drift() {
        let upstream_bytes = br#"{"schema":"negative-plan"}"#;
        let upstream_identity = contract_identity(
            "plans/negative-plan.json",
            upstream_bytes,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
        );
        let upstream = B4NegativeMaterializationExternalBytesV1 {
            path: &upstream_identity.path,
            bytes: upstream_bytes,
        };
        let mut registry = B4CandidateCorpus::from_canonical_jcs(include_bytes!(
            "../schema/b4-corpus-v1.candidate.json"
        ))
        .unwrap();
        set_registry_quarantine_copy_binding(
            &mut registry.bindings.negative_plan,
            &upstream_identity,
            "reproduction/schema/b4-corpus-v1.candidate/negative-plan.json",
        );
        authenticate_registry_quarantine_document_copy(
            &registry.bindings.negative_plan,
            upstream,
            B4ArtifactEncoding::Rfc8785Jcs,
            "negative plan",
        )
        .unwrap();

        for mutant in ["same-path", "length", "encoding", "digest"] {
            let mut changed_binding = registry.bindings.negative_plan.clone();
            match mutant {
                "same-path" => changed_binding.path.clone_from(&upstream_identity.path),
                "length" => changed_binding.byte_length += 1,
                "encoding" => changed_binding.encoding = B4ArtifactEncoding::RawBytes,
                "digest" => changed_binding.sha256 = sha256_hex(b"different negative plan"),
                _ => unreachable!(),
            }
            let error = authenticate_registry_quarantine_document_copy(
                &changed_binding,
                upstream,
                B4ArtifactEncoding::Rfc8785Jcs,
                "negative plan",
            )
            .expect_err("isolated negative-plan quarantine mutant unexpectedly authenticated");
            assert!(
                format!("{error:#}").contains("quarantine copy"),
                "{mutant} failed outside negative-plan quarantine-copy authentication: {error:#}"
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn one_manifest_bound_alternate_source_is_retained_but_is_not_proof_authority() {
        let image_id = vec![0x33; 32];
        let journal = vec![0x44; 159];
        let claim_digest = ok_receipt_claim_digests(&image_id, &journal)
            .unwrap()
            .expected_claim
            .to_vec();
        let control_id = hex::decode(RISC0_NORMAL_LIFT_CONTROL_IDS_HEX[0]).unwrap();
        let guest_elf = b"authenticated-guest-elf".to_vec();
        let raw_seal = vec![0x55; PROOF_BYTES];
        let receipt_oracle = b"receipt-oracle".to_vec();
        let metadata_model = alternate_metadata_fixture(
            &image_id,
            &journal,
            &claim_digest,
            &control_id,
            &guest_elf,
            &raw_seal,
            &receipt_oracle,
        );
        let metadata = metadata_model.to_canonical_jcs().unwrap();
        let metadata_value = validate_canonical_json_source(&metadata).unwrap();
        let positive_inputs = alternate_positive_inputs(&image_id, &journal, &guest_elf);
        let names = [
            "candidate-claim-digest.bin",
            "candidate-control-id.bin",
            "candidate-image-id.bin",
            "candidate-journal.bin",
            "candidate-metadata.json",
            "candidate-raw-seal.bin",
            "candidate-receipt-oracle.bincode",
        ];
        let bytes = [
            claim_digest.as_slice(),
            control_id.as_slice(),
            image_id.as_slice(),
            journal.as_slice(),
            metadata.as_slice(),
            raw_seal.as_slice(),
            receipt_oracle.as_slice(),
        ];
        let manifest = names
            .iter()
            .zip(bytes)
            .map(|(path, bytes)| crate::manifest::ManifestEntry {
                path: (*path).to_owned(),
                length: bytes.len().to_string(),
                sha256: sha256_hex(bytes),
            })
            .collect::<Vec<_>>();
        let manifest_bytes =
            canonical_json_bytes(&serde_json::to_value(&manifest).unwrap()).unwrap();
        let root = "negative-sources/alternate-root";
        let manifest_path = format!("{root}/candidate-proof-output-manifest.json");
        let artifact_paths = names
            .iter()
            .map(|name| format!("{root}/proof-output/{name}"))
            .collect::<Vec<_>>();
        let artifacts = artifact_paths
            .iter()
            .zip(bytes)
            .map(|(path, bytes)| B4NegativeMaterializationExternalBytesV1 { path, bytes })
            .collect::<Vec<_>>();
        let export = B4NegativeAlternateRootExportV1 {
            proof_output_manifest: B4NegativeMaterializationExternalBytesV1 {
                path: &manifest_path,
                bytes: &manifest_bytes,
            },
            artifacts: &artifacts,
        };

        let retained =
            authenticate_alternate_root_export(export, &positive_inputs, &mut empty_paths())
                .unwrap();

        assert_eq!(retained.len(), names.len() + 1);
        assert_eq!(
            retained
                .get(&format!("{root}/proof-output/candidate-raw-seal.bin"))
                .unwrap(),
            &raw_seal
        );

        let oversized_oracle = vec![0x66; RECEIPT_ORACLE_MAX_BYTES + 1];
        let oversized_bytes = [
            claim_digest.as_slice(),
            control_id.as_slice(),
            image_id.as_slice(),
            journal.as_slice(),
            metadata.as_slice(),
            raw_seal.as_slice(),
            oversized_oracle.as_slice(),
        ];
        let oversized_manifest = names
            .iter()
            .zip(oversized_bytes)
            .map(|(path, bytes)| crate::manifest::ManifestEntry {
                path: (*path).to_owned(),
                length: bytes.len().to_string(),
                sha256: sha256_hex(bytes),
            })
            .collect::<Vec<_>>();
        let oversized_manifest_bytes =
            canonical_json_bytes(&serde_json::to_value(&oversized_manifest).unwrap()).unwrap();
        let oversized_artifacts = artifact_paths
            .iter()
            .zip(oversized_bytes)
            .map(|(path, bytes)| B4NegativeMaterializationExternalBytesV1 { path, bytes })
            .collect::<Vec<_>>();
        let oversized_export = B4NegativeAlternateRootExportV1 {
            proof_output_manifest: B4NegativeMaterializationExternalBytesV1 {
                path: &manifest_path,
                bytes: &oversized_manifest_bytes,
            },
            artifacts: &oversized_artifacts,
        };
        assert!(
            authenticate_alternate_root_export(
                oversized_export,
                &positive_inputs,
                &mut empty_paths(),
            )
            .is_err(),
            "a manifest-consistent receipt oracle above the fixed maximum must be rejected"
        );

        let mut unknown_nested = metadata_value.clone();
        unknown_nested["proof"]["unexpected"] = Value::Bool(false);
        let unknown_nested = canonical_json_bytes(&unknown_nested).unwrap();
        let measured = B4AlternateRootMeasuredArtifactsV1 {
            manifest: &manifest,
            claim_digest: &claim_digest,
            control_id: &control_id,
            image_id: &image_id,
            journal: &journal,
            raw_seal: &raw_seal,
            receipt_oracle: &receipt_oracle,
        };
        assert!(
            authenticate_alternate_root_metadata(&unknown_nested, &measured, &positive_inputs)
                .is_err(),
            "closed candidate metadata must reject an unknown nested field"
        );

        let mut wrong_root = metadata_value;
        wrong_root["proof"]["innerControlRoot"] = Value::String("0".repeat(64));
        let wrong_root = canonical_json_bytes(&wrong_root).unwrap();
        assert!(
            authenticate_alternate_root_metadata(&wrong_root, &measured, &positive_inputs).is_err()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn coordinated_positive_registry_and_source_rewrite_cannot_replace_generation_authority() {
        let mut registry = B4CandidateCorpus::from_canonical_jcs(include_bytes!(
            "../schema/b4-corpus-v1.candidate.json"
        ))
        .unwrap();
        let names = [
            "candidate-claim-digest.bin",
            "candidate-control-id.bin",
            "candidate-image-id.bin",
            "candidate-journal.bin",
            "candidate-metadata.json",
            "candidate-raw-seal.bin",
            "candidate-receipt-oracle.bincode",
        ];
        let roles = [
            B4PositiveArtifactRole::ClaimDigest,
            B4PositiveArtifactRole::ControlId,
            B4PositiveArtifactRole::ImageId,
            B4PositiveArtifactRole::Journal,
            B4PositiveArtifactRole::Metadata,
            B4PositiveArtifactRole::RawSeal,
            B4PositiveArtifactRole::ReceiptOracle,
        ];
        let bytes = [
            vec![0x11; 32],
            vec![0x22; 32],
            vec![0x33; 32],
            vec![0x44; 159],
            b"{}".to_vec(),
            vec![0x55; PROOF_BYTES],
            b"receipt-oracle".to_vec(),
        ];
        registry.positive_cases[0].artifacts = names
            .iter()
            .zip(roles)
            .zip(&bytes)
            .map(
                |((source_file, role), bytes)| crate::b4::B4PositiveArtifact {
                    byte_length: u64::try_from(bytes.len()).unwrap(),
                    encoding: if role == B4PositiveArtifactRole::Metadata {
                        B4ArtifactEncoding::Rfc8785Jcs
                    } else {
                        B4ArtifactEncoding::RawBytes
                    },
                    path: format!("positive/lift-po2-15/{source_file}"),
                    role,
                    sha256: sha256_hex(bytes),
                },
            )
            .collect();
        let manifest = names
            .iter()
            .zip(&bytes)
            .map(|(path, bytes)| crate::manifest::ManifestEntry {
                path: (*path).to_owned(),
                length: bytes.len().to_string(),
                sha256: sha256_hex(bytes),
            })
            .collect::<Vec<_>>();
        let manifest_jcs = canonical_json_bytes(&serde_json::to_value(&manifest).unwrap()).unwrap();
        let generated_artifacts = names
            .iter()
            .zip(roles)
            .zip(&bytes)
            .map(|((source_file, role), bytes)| {
                let mut artifact = serde_json::json!({
                    "role": serde_json::to_value(role).unwrap(),
                    "sourceFile": source_file,
                    "byteLength": bytes.len(),
                    "sha256": sha256_hex(bytes),
                    "encoding": if role == B4PositiveArtifactRole::Metadata {
                        "rfc8785-jcs"
                    } else {
                        "raw-bytes"
                    },
                });
                if matches!(
                    role,
                    B4PositiveArtifactRole::ClaimDigest
                        | B4PositiveArtifactRole::ControlId
                        | B4PositiveArtifactRole::ImageId
                ) {
                    artifact["contentHex"] = Value::String(hex::encode(bytes));
                }
                if role == B4PositiveArtifactRole::ReceiptOracle {
                    artifact["codec"] = Value::String(
                        "bincode-1.3.3-little-endian-fixed-int-reject-trailing".to_owned(),
                    );
                }
                artifact
            })
            .collect::<Vec<_>>();
        let generated_case = serde_json::json!({
            "caseIndex": 0,
            "caseId": "lift-po2-15",
            "generation": {"kind": "lift", "segmentPo2": 15},
            "proofOutputManifest": {
                "fileName": "candidate-proof-output-manifest.json",
                "byteLength": manifest_jcs.len(),
                "sha256": sha256_hex(&manifest_jcs),
                "encoding": "rfc8785-jcs",
            },
            "artifacts": generated_artifacts,
        });
        let raw_seal = &bytes[5];
        let raw_seal_path = registry.positive_cases[0].artifacts[5].path.clone();
        let _ = authenticate_positive_generation_case(
            0,
            &generated_case,
            &registry.positive_cases[0],
            &manifest_jcs,
            &raw_seal_path,
            raw_seal,
        )
        .unwrap();

        let rewritten_source = vec![0xaa; 159];
        let rewritten = registry.positive_cases[0]
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.role == B4PositiveArtifactRole::Journal)
            .unwrap();
        rewritten.byte_length = u64::try_from(rewritten_source.len()).unwrap();
        rewritten.sha256 = sha256_hex(&rewritten_source);
        assert_eq!(rewritten.sha256, sha256_hex(&rewritten_source));

        assert!(
            authenticate_positive_generation_case(
                0,
                &generated_case,
                &registry.positive_cases[0],
                &manifest_jcs,
                &raw_seal_path,
                raw_seal,
            )
            .is_err()
        );
    }

    fn production_shaped_recursive_generation_case(
        top_level: &B4AuthenticatedMaterializationTopLevelV1,
        index: usize,
    ) -> (Value, Vec<u8>) {
        let case = &top_level.expanded_registry.positive_cases[index];
        let mut generated_artifacts = Vec::with_capacity(case.artifacts.len());
        let mut manifest = Vec::with_capacity(
            case.artifacts.len()
                + crate::b4_positive_gate::positive_auxiliary_artifact_paths(index)
                    .unwrap()
                    .len(),
        );
        for (&(role, source_file), artifact) in positive_artifact_layout(index)
            .unwrap()
            .iter()
            .zip(&case.artifacts)
        {
            let bytes = if role == B4PositiveArtifactRole::RawSeal {
                &top_level.positive_exports[index].raw_seal
            } else {
                &top_level.source_artifacts[&artifact.path]
            };
            let mut identity = serde_json::json!({
                "role": positive_artifact_role_name(role),
                "sourceFile": source_file,
                "byteLength": artifact.byte_length,
                "sha256": artifact.sha256,
                "encoding": positive_artifact_encoding(role).0,
            });
            if matches!(
                role,
                B4PositiveArtifactRole::ClaimDigest
                    | B4PositiveArtifactRole::ControlId
                    | B4PositiveArtifactRole::ImageId
            ) {
                identity["contentHex"] = Value::String(hex::encode(bytes));
            }
            if role == B4PositiveArtifactRole::ReceiptOracle {
                identity["codec"] = Value::String("eip0045-recursive-oracle-borsh-v1".to_owned());
            }
            generated_artifacts.push(identity);
            manifest.push(ManifestEntry {
                path: source_file.to_owned(),
                length: artifact.byte_length.to_string(),
                sha256: artifact.sha256.clone(),
            });
        }
        for (position, path) in crate::b4_positive_gate::positive_auxiliary_artifact_paths(index)
            .unwrap()
            .iter()
            .copied()
            .enumerate()
        {
            let bytes = vec![
                0x90_u8
                    .wrapping_add(u8::try_from(index).unwrap())
                    .wrapping_add(u8::try_from(position).unwrap());
                PROOF_BYTES
            ];
            manifest.push(ManifestEntry {
                path: path.to_owned(),
                length: bytes.len().to_string(),
                sha256: sha256_hex(&bytes),
            });
        }
        manifest.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        let manifest_jcs = canonical_json_bytes(&serde_json::to_value(manifest).unwrap()).unwrap();
        let family = match index {
            8 => "terminal-join",
            9 => "terminal-resolve",
            10 => "resolve-then-join",
            _ => unreachable!(),
        };
        (
            serde_json::json!({
                "caseIndex": index,
                "caseId": case.case_id,
                "generation": {"kind": "recursive", "family": family},
                "proofOutputManifest": {
                    "fileName": "candidate-recursive-output-manifest.json",
                    "byteLength": manifest_jcs.len(),
                    "sha256": sha256_hex(&manifest_jcs),
                    "encoding": "rfc8785-jcs",
                },
                "artifacts": generated_artifacts,
            }),
            manifest_jcs,
        )
    }

    #[test]
    fn positive_generation_authenticates_full_recursive_manifests_with_eight_primary_roles() {
        let top_level = CoreFixture::with_exact_implemented_producer_top_level().top_level;
        for (index, expected_manifest_count) in [(8, 10), (9, 10), (10, 12)] {
            let (generated_case, manifest_jcs) =
                production_shaped_recursive_generation_case(&top_level, index);
            let case = &top_level.expanded_registry.positive_cases[index];
            assert_eq!(
                case.artifacts.len(),
                RECURSIVE_POSITIVE_ARTIFACT_LAYOUT.len()
            );
            let manifest: ProofOutputManifest = serde_json::from_slice(&manifest_jcs).unwrap();
            assert_eq!(manifest.len(), expected_manifest_count);
            let raw_seal = &top_level.positive_exports[index].raw_seal;
            let raw_seal_path = &case
                .artifacts
                .iter()
                .find(|artifact| artifact.role == B4PositiveArtifactRole::RawSeal)
                .unwrap()
                .path;

            let _ = authenticate_positive_generation_case(
                index,
                &generated_case,
                case,
                &manifest_jcs,
                raw_seal_path,
                raw_seal,
            )
            .unwrap();
        }
    }

    fn assert_recursive_manifest_authentication_rejection(
        top_level: &B4AuthenticatedMaterializationTopLevelV1,
        mutate: impl FnOnce(&mut Value, &mut ProofOutputManifest),
        expected_error: &str,
    ) {
        let index = 8;
        let (mut generated_case, manifest_jcs) =
            production_shaped_recursive_generation_case(top_level, index);
        let mut manifest: ProofOutputManifest = serde_json::from_slice(&manifest_jcs).unwrap();
        mutate(&mut generated_case, &mut manifest);
        let manifest_jcs = canonical_json_bytes(&serde_json::to_value(manifest).unwrap()).unwrap();
        generated_case["proofOutputManifest"]["byteLength"] = serde_json::json!(manifest_jcs.len());
        generated_case["proofOutputManifest"]["sha256"] =
            serde_json::json!(sha256_hex(&manifest_jcs));
        let case = &top_level.expanded_registry.positive_cases[index];
        let raw_seal = &top_level.positive_exports[index].raw_seal;
        let raw_seal_path = &case
            .artifacts
            .iter()
            .find(|artifact| artifact.role == B4PositiveArtifactRole::RawSeal)
            .unwrap()
            .path;
        let error = authenticate_positive_generation_case(
            index,
            &generated_case,
            case,
            &manifest_jcs,
            raw_seal_path,
            raw_seal,
        )
        .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains(expected_error),
            "expected {expected_error:?}, got {rendered:?}"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn recursive_manifest_authentication_rejects_inventory_path_and_role_drift() {
        let top_level = CoreFixture::with_exact_implemented_producer_top_level().top_level;
        let auxiliary_path = positive_auxiliary_artifact_paths(8).unwrap()[0];

        assert_recursive_manifest_authentication_rejection(
            &top_level,
            |_, manifest| {
                manifest.retain(|entry| entry.path != auxiliary_path);
            },
            "wrong exact file count",
        );
        assert_recursive_manifest_authentication_rejection(
            &top_level,
            |_, manifest| {
                manifest.push(ManifestEntry {
                    path: "unexpected-recursive-export-member.bin".to_owned(),
                    length: PROOF_BYTES.to_string(),
                    sha256: "00".repeat(32),
                });
                manifest.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
            },
            "wrong exact file count",
        );
        assert_recursive_manifest_authentication_rejection(
            &top_level,
            |_, manifest| manifest.swap(0, 1),
            "manifest paths are not in strict unsigned-ASCII order",
        );
        assert_recursive_manifest_authentication_rejection(
            &top_level,
            |_, manifest| {
                let duplicate_path = manifest[0].path.clone();
                manifest[1].path = duplicate_path;
                manifest.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
            },
            "manifest paths are not in strict unsigned-ASCII order",
        );
        assert_recursive_manifest_authentication_rejection(
            &top_level,
            |_, manifest| {
                manifest
                    .iter_mut()
                    .find(|entry| entry.path == auxiliary_path)
                    .unwrap()
                    .path = positive_auxiliary_artifact_paths(9).unwrap()[0].to_owned();
                manifest.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
            },
            "outside the closed layout",
        );
        assert_recursive_manifest_authentication_rejection(
            &top_level,
            |_, manifest| {
                manifest
                    .iter_mut()
                    .find(|entry| entry.path == auxiliary_path)
                    .unwrap()
                    .path = "wrong/recursive-auxiliary-raw-seal.bin".to_owned();
                manifest.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
            },
            "outside the closed layout",
        );
        assert_recursive_manifest_authentication_rejection(
            &top_level,
            |_, manifest| {
                manifest
                    .iter_mut()
                    .find(|entry| entry.path == auxiliary_path)
                    .unwrap()
                    .length = (PROOF_BYTES - 1).to_string();
            },
            "wrong exact byte length",
        );
        assert_recursive_manifest_authentication_rejection(
            &top_level,
            |generated, _| {
                let promoted = serde_json::json!({
                    "role": "raw-seal",
                    "sourceFile": auxiliary_path,
                    "byteLength": PROOF_BYTES,
                    "sha256": "00".repeat(32),
                    "encoding": "raw-bytes",
                });
                generated["artifacts"]
                    .as_array_mut()
                    .unwrap()
                    .push(promoted);
            },
            "artifact cardinality differs from the exact closed layout",
        );
        assert_recursive_manifest_authentication_rejection(
            &top_level,
            |generated, _| {
                generated["artifacts"][7]["role"] = serde_json::json!("raw-seal");
            },
            "order, role, or source filename drift",
        );
    }

    #[derive(Clone)]
    struct OwnedAuxiliarySource {
        path: String,
        bytes: Vec<u8>,
    }

    #[derive(Clone)]
    struct RecursiveAuxiliarySourceFixture {
        registry: B4CandidateCorpus,
        subject_catalog: Eip0045B4SubjectCatalogV1,
        terminal_catalog: Eip0045B4TerminalFixtureCatalogV1,
        positive_input: B4AuthenticatedPositiveInputSourcesV1,
        positive_exports: Vec<B4AuthenticatedPositiveExportV1>,
        supplied: Vec<OwnedAuxiliarySource>,
    }

    impl RecursiveAuxiliarySourceFixture {
        fn exact() -> Self {
            let positive_input = alternate_positive_inputs(&[0x11; 32], b"journal", b"guest");
            let mut registry = CoreFixture::exact().top_level.expanded_registry;
            let dummy = &positive_input.profile_manifest;
            set_registry_binding(&mut registry.bindings.generator, dummy);
            set_registry_binding(&mut registry.bindings.guest.elf, dummy);
            set_registry_binding(&mut registry.bindings.jvm_verifier, dummy);
            set_registry_binding(
                &mut registry.bindings.reference_statement_bundle.manifest,
                dummy,
            );
            set_registry_binding(&mut registry.bindings.rust_verifier, dummy);
            set_registry_binding(&mut registry.bindings.source_lock, dummy);
            set_registry_binding(&mut registry.bindings.negative_plan, dummy);
            set_registry_binding(&mut registry.profile.manifest, dummy);
            for case in &mut registry.positive_cases {
                case.artifacts.clear();
            }

            let subject_catalog = serde_json::from_value(serde_json::json!({
                "format": "test-empty-subject-catalog",
                "formatVersion": 1,
                "subjects": [],
            }))
            .unwrap();
            let terminal_catalog = serde_json::from_value(serde_json::json!({
                "format": "test-empty-terminal-catalog",
                "formatVersion": 1,
                "stage": "test",
                "upstream": {
                    "repository": "test",
                    "commit": "test",
                    "risc0ZkvmVersion": "test",
                    "receiptOracleCodec": "test",
                },
                "programId": "00",
                "innerControlRoot": "00",
                "stockControls": [],
                "fixtures": [],
            }))
            .unwrap();

            let mut source_map = BTreeMap::from([
                ("inputs/dummy.bin".to_owned(), b"dummy".to_vec()),
                ("inputs/guest.elf".to_owned(), b"guest".to_vec()),
                (
                    "inputs/reference-statement-manifest.json".to_owned(),
                    b"statement-manifest".to_vec(),
                ),
            ]);
            let mut positive_exports = Vec::with_capacity(registry.positive_cases.len());
            for case_index in 0..registry.positive_cases.len() {
                let mut auxiliary_artifacts = Vec::new();
                for (position, path) in positive_auxiliary_artifact_paths(case_index)
                    .unwrap()
                    .iter()
                    .copied()
                    .enumerate()
                {
                    let bytes =
                        vec![
                            0xb0_u8.wrapping_add(u8::try_from(case_index * 8 + position).unwrap(),);
                            PROOF_BYTES
                        ];
                    let identity = B4AuthenticatedPositiveAuxiliaryArtifactV1 {
                        path: path.to_owned(),
                        byte_length: u64::try_from(bytes.len()).unwrap(),
                        sha256: sha256_hex(&bytes),
                    };
                    assert!(source_map.insert(identity.path.clone(), bytes).is_none());
                    auxiliary_artifacts.push(identity);
                }
                positive_exports.push(B4AuthenticatedPositiveExportV1 {
                    case_index: u8::try_from(case_index).unwrap(),
                    proof_output_manifest_jcs: b"[]".to_vec(),
                    raw_seal: Vec::new(),
                    auxiliary_artifacts,
                });
            }
            let supplied = source_map
                .into_iter()
                .map(|(path, bytes)| OwnedAuxiliarySource { path, bytes })
                .collect();
            Self {
                registry,
                subject_catalog,
                terminal_catalog,
                positive_input,
                positive_exports,
                supplied,
            }
        }

        fn authenticate(&self) -> Result<BTreeMap<String, Vec<u8>>> {
            let supplied = self
                .supplied
                .iter()
                .map(|source| B4NegativeMaterializationExternalBytesV1 {
                    path: &source.path,
                    bytes: &source.bytes,
                })
                .collect::<Vec<_>>();
            authenticate_source_artifacts(
                &self.registry,
                &self.subject_catalog,
                &self.terminal_catalog,
                &self.positive_input,
                &self.positive_exports,
                &supplied,
                &mut empty_paths(),
            )
        }

        fn source_position(&self, path: &str) -> usize {
            self.supplied
                .iter()
                .position(|source| source.path == path)
                .unwrap()
        }
    }

    fn assert_recursive_auxiliary_source_rejection(
        mutate: impl FnOnce(&mut RecursiveAuxiliarySourceFixture),
        expected_error: &str,
    ) {
        let mut fixture = RecursiveAuxiliarySourceFixture::exact();
        mutate(&mut fixture);
        let error = fixture.authenticate().unwrap_err();
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains(expected_error),
            "expected {expected_error:?}, got {rendered:?}"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn recursive_auxiliary_source_authentication_is_exhaustive_ordered_and_byte_exact() {
        let exact = RecursiveAuxiliarySourceFixture::exact();
        let retained = exact.authenticate().unwrap();
        for index in 8..=10 {
            for path in positive_auxiliary_artifact_paths(index).unwrap() {
                assert!(retained.contains_key(*path));
            }
        }

        let case_8_first = positive_auxiliary_artifact_paths(8).unwrap()[0];
        let case_8_second = positive_auxiliary_artifact_paths(8).unwrap()[1];
        let case_9_first = positive_auxiliary_artifact_paths(9).unwrap()[0];
        let duplicate_lost_path = exact.supplied[1].path.clone();

        assert_recursive_auxiliary_source_rejection(
            |fixture| {
                let position = fixture.source_position(case_8_first);
                fixture.supplied.remove(position);
            },
            &format!("missing=[{case_8_first:?}]; extra=[]"),
        );
        assert_recursive_auxiliary_source_rejection(
            |fixture| {
                fixture.supplied.push(OwnedAuxiliarySource {
                    path: "unmanifested-recursive-auxiliary.bin".to_owned(),
                    bytes: vec![0x55; PROOF_BYTES],
                });
                fixture
                    .supplied
                    .sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
            },
            "missing=[]; extra=[\"unmanifested-recursive-auxiliary.bin\"]",
        );
        assert_recursive_auxiliary_source_rejection(
            |fixture| fixture.supplied.swap(0, 1),
            "not in strict unsigned UTF-8 path order",
        );
        assert_recursive_auxiliary_source_rejection(
            |fixture| {
                fixture.supplied[1] = fixture.supplied[0].clone();
            },
            &format!("missing=[{duplicate_lost_path:?}]; extra=[]"),
        );
        assert_recursive_auxiliary_source_rejection(
            |fixture| {
                fixture.positive_exports[8].auxiliary_artifacts.swap(0, 1);
            },
            "auxiliary path/order drift",
        );
        assert_recursive_auxiliary_source_rejection(
            |fixture| {
                let duplicate = fixture.positive_exports[8].auxiliary_artifacts[0].clone();
                fixture.positive_exports[8].auxiliary_artifacts[1] = duplicate;
            },
            "auxiliary path/order drift",
        );
        assert_recursive_auxiliary_source_rejection(
            |fixture| {
                fixture.positive_exports[8].auxiliary_artifacts[0].path = case_9_first.to_owned();
            },
            "auxiliary path/order drift",
        );
        assert_recursive_auxiliary_source_rejection(
            |fixture| {
                fixture.positive_exports[8].auxiliary_artifacts[0].path =
                    "wrong/recursive-auxiliary.bin".to_owned();
            },
            "auxiliary path/order drift",
        );
        assert_recursive_auxiliary_source_rejection(
            |fixture| {
                fixture.positive_exports[8].auxiliary_artifacts[0].byte_length -= 1;
            },
            "differs from its deterministic identity",
        );
        assert_recursive_auxiliary_source_rejection(
            |fixture| {
                fixture.positive_exports[8].auxiliary_artifacts[0].sha256 = "00".repeat(32);
            },
            "differs from its deterministic identity",
        );
        assert_recursive_auxiliary_source_rejection(
            |fixture| {
                let position = fixture.source_position(case_8_first);
                fixture.supplied[position].bytes[0] ^= 0xff;
            },
            "differs from its deterministic identity",
        );
        assert_recursive_auxiliary_source_rejection(
            |fixture| {
                let left = fixture.source_position(case_8_second);
                let right = fixture.source_position(case_9_first);
                let left_bytes = fixture.supplied[left].bytes.clone();
                let right_bytes = fixture.supplied[right].bytes.clone();
                fixture.supplied[right].bytes = left_bytes;
                fixture.supplied[left].bytes = right_bytes;
            },
            "differs from its deterministic identity",
        );
    }

    #[test]
    fn output_path_cannot_be_reclassified_as_an_exact_reusable_source() {
        let bytes = b"same-bytes";
        let path = "materializations/000/root/subject.bin";
        let external = B4NegativeMaterializationExternalBytesV1 { path, bytes };
        let mut paths = empty_paths();
        paths
            .bind_unique_output(external, "negative materialization output")
            .unwrap();

        assert!(
            paths
                .bind_new_source(external, true, "later materialization source")
                .is_err()
        );
    }

    #[derive(Clone)]
    struct OwnedExecution {
        execution_index: u16,
        execution_id: String,
        base_path: String,
        base: Vec<u8>,
        materialization_identity_path: String,
        materialization_identity_jcs: Vec<u8>,
        negative_input_path: String,
        negative_input_jcs: Vec<u8>,
        subject_path: String,
        subject: Vec<u8>,
        context_paths: Vec<String>,
        contexts: Vec<Vec<u8>>,
    }

    #[derive(Clone)]
    struct CoreFixture {
        top_level: B4AuthenticatedMaterializationTopLevelV1,
        catalog_identity: B4ContractArtifactIdentityV1,
        external: Vec<OwnedExecution>,
        reconstructed: Vec<B4ClosedReconstructedExecutionV1>,
    }

    fn fixture_montgomery_encode(value: u32, modulus: u32) -> u32 {
        let radix = (1_u64 << 32) % u64::from(modulus);
        u32::try_from((u64::from(value) * radix) % u64::from(modulus)).unwrap()
    }

    fn synthetic_raw_producer_seal() -> Vec<u8> {
        // Structural materializer fixture only. It authenticates every source
        // edge needed by the producer but is deliberately not a
        // cryptographically valid positive receipt and cannot close real
        // first-rejection or Rust/JVM agreement evidence.
        const BYTE_ORDER_REJECTION_SOURCE: u32 = 0x0100_0078;
        const CHUNK_BOUNDARY_LEFT_WORD: usize = 16_383;
        const CHUNK_BOUNDARY_RIGHT_WORD: usize = 16_384;
        let b2 = crate::constants_artifact::verify_canonical(include_bytes!(
            "../../profiles/risc0-v3-succinct/constants.bin"
        ))
        .unwrap();
        let modulus = b2.baby_bear.modulus;
        assert_eq!(BYTE_ORDER_REJECTION_SOURCE.swap_bytes(), modulus);

        let mut words = vec![0_u32; PROOF_WORDS];
        words[0] = BYTE_ORDER_REJECTION_SOURCE;
        for (offset, word) in words[16..32].iter_mut().enumerate() {
            *word = fixture_montgomery_encode(u32::try_from(offset + 1).unwrap(), modulus);
        }
        words[32] = u32::from(RISC0_OUTER_PO2);
        for index in [33, 1_057, 4_461, 4_717, 4_729] {
            words[index] = BYTE_ORDER_REJECTION_SOURCE;
        }

        // The first two canonical chunks meet one byte before a word boundary.
        // Moving chunk 0 to final index 1 therefore makes the moved
        // concatenation begin with `[01, 00, 00, 78]`, exactly one
        // non-reduced BabyBear word, while both original aligned words remain
        // reduced.
        words[CHUNK_BOUNDARY_LEFT_WORD] = 0x0100_0000;
        words[CHUNK_BOUNDARY_RIGHT_WORD] = 0x0078_0000;

        assert!(words.iter().all(|word| *word < modulus));
        assert!((1..16).step_by(2).all(|index| words[index] == 0));
        assert_eq!(words[32], u32::from(RISC0_OUTER_PO2));
        assert_eq!(words.len(), PROOF_WORDS);
        let bytes = words
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(bytes.len(), PROOF_BYTES);
        bytes
    }

    #[derive(Clone)]
    struct TestClosedProducer {
        rows: Vec<B4ClosedReconstructedExecutionV1>,
    }

    impl B4ClosedMaterializationRowProducerV1 for TestClosedProducer {
        fn reconstruct(
            &self,
            execution_index: usize,
            planned: &B4NegativePlanExecutionV1,
            top_level: &B4AuthenticatedMaterializationTopLevelV1,
        ) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
            // The test producer proves the production trait needs authenticated
            // sources but has no access to caller-supplied external executions.
            let _authenticated_source_count = top_level.source_artifacts.len();
            let row = self
                .rows
                .get(execution_index)
                .context("test producer row is missing")?;
            ensure!(
                row.derived_registry_row.execution_id == planned.execution_id,
                "test producer plan drift"
            );
            Ok(Some(row.clone()))
        }

        fn terminal_evidence_document_identities(
            &self,
        ) -> Option<B4TerminalEvidenceDocumentIdentitiesV1> {
            Some(B4TerminalEvidenceDocumentIdentitiesV1 {
                packet_manifest: B4NegativeMaterializationByteIdentityV1 {
                    byte_length: 4_096,
                    sha256: "11".repeat(32),
                },
                campaign_receipt: B4NegativeMaterializationByteIdentityV1 {
                    byte_length: 2_048,
                    sha256: "22".repeat(32),
                },
            })
        }
    }

    #[cfg(feature = "negative-materialization-set")]
    struct MutatePublicationAtFinalRowProducer<'a> {
        inner: TestClosedProducer,
        root: &'a Path,
        relative_path: &'a str,
    }

    #[cfg(feature = "negative-materialization-set")]
    impl B4ClosedMaterializationRowProducerV1 for MutatePublicationAtFinalRowProducer<'_> {
        fn reconstruct(
            &self,
            execution_index: usize,
            planned: &B4NegativePlanExecutionV1,
            top_level: &B4AuthenticatedMaterializationTopLevelV1,
        ) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
            let reconstructed = self
                .inner
                .reconstruct(execution_index, planned, top_level)?;
            if execution_index == 253 {
                let path = self.relative_path.split('/').fold(
                    self.root.to_path_buf(),
                    |mut path, segment| {
                        path.push(segment);
                        path
                    },
                );
                let mut bytes = std::fs::read(&path)?;
                bytes[0] ^= 1;
                std::fs::write(path, bytes)?;
            }
            Ok(reconstructed)
        }

        fn terminal_evidence_document_identities(
            &self,
        ) -> Option<B4TerminalEvidenceDocumentIdentitiesV1> {
            self.inner.terminal_evidence_document_identities()
        }
    }

    #[derive(Clone)]
    struct C1ThenTestProducer {
        fallback: TestClosedProducer,
    }

    impl B4ClosedMaterializationRowProducerV1 for C1ThenTestProducer {
        fn reconstruct(
            &self,
            execution_index: usize,
            planned: &B4NegativePlanExecutionV1,
            top_level: &B4AuthenticatedMaterializationTopLevelV1,
        ) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
            if let Some(reconstructed) =
                C1ProductionRowProducer.reconstruct(execution_index, planned, top_level)?
            {
                return Ok(Some(reconstructed));
            }
            self.fallback
                .reconstruct(execution_index, planned, top_level)
        }

        fn terminal_evidence_document_identities(
            &self,
        ) -> Option<B4TerminalEvidenceDocumentIdentitiesV1> {
            self.fallback.terminal_evidence_document_identities()
        }
    }

    #[derive(Clone)]
    struct C2ProfileThenTestProducer {
        fallback: TestClosedProducer,
    }

    impl B4ClosedMaterializationRowProducerV1 for C2ProfileThenTestProducer {
        fn reconstruct(
            &self,
            execution_index: usize,
            planned: &B4NegativePlanExecutionV1,
            top_level: &B4AuthenticatedMaterializationTopLevelV1,
        ) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
            if let Some(reconstructed) = crate::b4_c2_profile::reconstruct_profile_execution(
                execution_index,
                planned,
                top_level,
            )? {
                return Ok(Some(reconstructed));
            }
            self.fallback
                .reconstruct(execution_index, planned, top_level)
        }

        fn terminal_evidence_document_identities(
            &self,
        ) -> Option<B4TerminalEvidenceDocumentIdentitiesV1> {
            self.fallback.terminal_evidence_document_identities()
        }
    }

    #[derive(Clone)]
    struct ProductionThenTestProducer {
        fallback: TestClosedProducer,
    }

    impl B4ClosedMaterializationRowProducerV1 for ProductionThenTestProducer {
        fn reconstruct(
            &self,
            execution_index: usize,
            planned: &B4NegativePlanExecutionV1,
            top_level: &B4AuthenticatedMaterializationTopLevelV1,
        ) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
            if (72..=107).contains(&execution_index) {
                return ProductionRowProducer
                    .reconstruct(execution_index, planned, top_level)
                    .and_then(|row| {
                        row.context("parser production dispatcher returned no reconstructed row")
                            .map(Some)
                    });
            }
            self.fallback
                .reconstruct(execution_index, planned, top_level)
        }

        fn terminal_evidence_document_identities(
            &self,
        ) -> Option<B4TerminalEvidenceDocumentIdentitiesV1> {
            self.fallback.terminal_evidence_document_identities()
        }
    }

    #[derive(Clone)]
    struct RawThenTestProducer {
        fallback: TestClosedProducer,
    }

    impl B4ClosedMaterializationRowProducerV1 for RawThenTestProducer {
        fn reconstruct(
            &self,
            execution_index: usize,
            planned: &B4NegativePlanExecutionV1,
            top_level: &B4AuthenticatedMaterializationTopLevelV1,
        ) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
            if (0..=6).contains(&execution_index)
                || execution_index == 29
                || (33..=71).contains(&execution_index)
                || execution_index == 109
            {
                return ProductionRowProducer
                    .reconstruct(execution_index, planned, top_level)
                    .and_then(|row| {
                        row.context("raw production dispatcher returned no reconstructed row")
                            .map(Some)
                    });
            }
            self.fallback
                .reconstruct(execution_index, planned, top_level)
        }

        fn terminal_evidence_document_identities(
            &self,
        ) -> Option<B4TerminalEvidenceDocumentIdentitiesV1> {
            self.fallback.terminal_evidence_document_identities()
        }
    }

    impl CoreFixture {
        #[allow(clippy::too_many_lines)]
        fn exact() -> Self {
            let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
            let negative_plan = plan.to_canonical_jcs().unwrap();
            let planned = plan
                .groups
                .iter()
                .flat_map(|group| group.executions.iter())
                .collect::<Vec<_>>();
            let registry_rows = planned
                .iter()
                .map(|execution| B4NegativeCase {
                    execution_id: execution.execution_id.clone(),
                    base_selector_id: execution.base_selector_id.clone(),
                    materialization_domain: execution.materialization_domain,
                    materialization: B4NegativeMaterialization::FixtureSelection {
                        fixture_id: execution.base_selector_id.clone(),
                    },
                })
                .collect::<Vec<_>>();

            let mut registry = B4CandidateCorpus::from_canonical_jcs(include_bytes!(
                "../schema/b4-corpus-v1.candidate.json"
            ))
            .unwrap();
            registry.stage = B4RegistryStage::Expanded;
            registry.negative_cases.clone_from(&registry_rows);

            let mut external = Vec::with_capacity(planned.len());
            let mut reconstructed = Vec::with_capacity(planned.len());
            for (index, (execution, registry_row)) in planned.iter().zip(registry_rows).enumerate()
            {
                let base = vec![
                    u8::try_from(index % 251).unwrap(),
                    u8::try_from((index + 1) % 251).unwrap(),
                    0xa5,
                ];
                let handler = planned_negative_handler_contract(
                    execution.materialization_domain,
                    execution.execution_surface,
                )
                .unwrap()
                .unwrap();
                let subject_len =
                    usize::try_from(handler.custody().subject().minimum().max(3)).unwrap();
                let mut subject = vec![u8::try_from((index + 2) % 251).unwrap(); subject_len];
                subject[1] = u8::try_from((index + 3) % 251).unwrap();
                subject[2] = 0x5a;
                let context_count = handler.custody().contexts().len();
                let contexts = (0..context_count)
                    .map(|context_index| {
                        vec![
                            u8::try_from(index % 251).unwrap(),
                            u8::try_from(context_index % 251).unwrap(),
                            0x3c,
                        ]
                    })
                    .collect::<Vec<_>>();
                let (materialization_identity_jcs, negative_input_jcs) = execution_documents(
                    execution,
                    &registry_row,
                    &negative_plan,
                    &base,
                    &subject,
                    &contexts,
                );
                let root = format!("materializations/{index:03}");
                external.push(OwnedExecution {
                    execution_index: u16::try_from(index).unwrap(),
                    execution_id: execution.execution_id.clone(),
                    base_path: format!("{root}/base.bin"),
                    base: base.clone(),
                    materialization_identity_path: format!("{root}/materialization-identity.json"),
                    materialization_identity_jcs: materialization_identity_jcs.clone(),
                    negative_input_path: format!("{root}/negative-input.json"),
                    negative_input_jcs: negative_input_jcs.clone(),
                    subject_path: format!("{root}/root/subject.bin"),
                    subject: subject.clone(),
                    context_paths: (0..context_count)
                        .map(|context_index| format!("{root}/root/context/{context_index:02}.bin"))
                        .collect(),
                    contexts: contexts.clone(),
                });
                reconstructed.push(B4ClosedReconstructedExecutionV1 {
                    derived_registry_row: registry_row,
                    base,
                    materialization_identity_jcs,
                    negative_input_jcs,
                    subject,
                    contexts,
                });
            }

            let document_identities = B4AuthenticatedTopLevelIdentitiesV1 {
                campaign_precommit: identity_for(b"campaign-precommit"),
                positive_generation_set: identity_for(b"positive-generation-set"),
                negative_plan: identity_for(&negative_plan),
                expanded_registry: identity_for(b"expanded-registry"),
                subject_catalog: identity_for(b"subject-catalog"),
                terminal_fixture_catalog: identity_for(b"terminal-fixture-catalog"),
                negative_binding_index: identity_for(b"negative-binding-index"),
                abstract_tree: identity_for(b"abstract-tree"),
            };
            Self {
                top_level: B4AuthenticatedMaterializationTopLevelV1 {
                    positive_input_set: b"positive-input-set".to_vec(),
                    campaign_precommit: b"campaign-precommit".to_vec(),
                    positive_generation_set: b"positive-generation-set".to_vec(),
                    negative_plan,
                    expanded_registry: registry,
                    subject_catalog_jcs: b"subject-catalog".to_vec(),
                    terminal_fixture_catalog_jcs: b"terminal-fixture-catalog".to_vec(),
                    negative_binding_index_jcs: b"negative-binding-index".to_vec(),
                    abstract_tree_jcs: b"abstract-tree".to_vec(),
                    positive_exports: Vec::new(),
                    source_artifacts: BTreeMap::new(),
                    #[cfg(feature = "negative-materialization-set")]
                    negative_ancestry_provenance_evidence:
                        B4AuthenticatedNegativeAncestryProvenanceEvidenceV1 {
                            profile_manifest: B4ContractArtifactIdentityV1::from_bytes(
                                "profiles/fixture-manifest.bin",
                                B4ContractArtifactEncodingV1::RawBytes,
                                b"fixture-profile-manifest",
                            )
                            .unwrap(),
                            profile_package_paths: BTreeSet::new(),
                            case9_paths: BTreeSet::new(),
                        },
                    document_identities,
                },
                catalog_identity: B4ContractArtifactIdentityV1::from_bytes(
                    B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_PATH,
                    B4ContractArtifactEncodingV1::Rfc8785Jcs,
                    b"{\"fixture\":\"negative-ancestry\"}",
                )
                .unwrap(),
                external,
                reconstructed,
            }
        }

        fn producer(&self) -> TestClosedProducer {
            TestClosedProducer {
                rows: self.reconstructed.clone(),
            }
        }

        fn c1_then_test_producer(&self) -> C1ThenTestProducer {
            C1ThenTestProducer {
                fallback: self.producer(),
            }
        }

        fn c2_profile_then_test_producer(&self) -> C2ProfileThenTestProducer {
            C2ProfileThenTestProducer {
                fallback: self.producer(),
            }
        }

        fn production_then_test_producer(&self) -> ProductionThenTestProducer {
            ProductionThenTestProducer {
                fallback: self.producer(),
            }
        }

        fn raw_then_test_producer(&self) -> RawThenTestProducer {
            RawThenTestProducer {
                fallback: self.producer(),
            }
        }

        fn with_exact_c2_profile_top_level() -> Self {
            let mut fixture = Self::exact();
            for (path, bytes) in [
                (
                    "profiles/risc0-v3-succinct/manifest.bin",
                    include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin").as_slice(),
                ),
                (
                    "profiles/risc0-v3-succinct/algorithm.txt",
                    include_bytes!("../../profiles/risc0-v3-succinct/algorithm.txt").as_slice(),
                ),
                (
                    "profiles/risc0-v3-succinct/constants.bin",
                    include_bytes!("../../profiles/risc0-v3-succinct/constants.bin").as_slice(),
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
                fixture
                    .top_level
                    .source_artifacts
                    .insert(path.to_owned(), bytes.to_vec());
            }
            fixture
        }

        fn with_exact_c2_profile_materializations() -> Self {
            let mut fixture = Self::with_exact_c2_profile_top_level();
            let plan =
                Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.top_level.negative_plan)
                    .unwrap();
            let planned = plan
                .groups
                .iter()
                .flat_map(|group| group.executions.iter())
                .collect::<Vec<_>>();
            for (index, execution) in planned.iter().enumerate().take(210).skip(160) {
                let reconstructed = crate::b4_c2_profile::reconstruct_profile_execution(
                    index,
                    execution,
                    &fixture.top_level,
                )
                .unwrap()
                .unwrap();
                fixture.top_level.expanded_registry.negative_cases[index] =
                    reconstructed.derived_registry_row.clone();
                fixture.external[index] = owned_c1_execution(index, execution, &reconstructed);
                fixture.reconstructed[index] = reconstructed;
            }
            fixture
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the fixture assembles the complete authenticated case-0 source graph used by the production C2 entry"
        )]
        fn with_exact_c2_opcode_top_level() -> Self {
            let mut fixture = Self::exact();
            let temporary_repository = crate::test_support::tempdir().unwrap();
            let write_relative = |relative: &str, bytes: &[u8]| {
                let path = relative.split('/').fold(
                    temporary_repository.path().to_path_buf(),
                    |mut path, segment| {
                        path.push(segment);
                        path
                    },
                );
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, bytes).unwrap();
            };
            let profile_files: [(&str, &[u8]); 7] = [
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
                    include_bytes!(
                        "../../profiles/risc0-v3-succinct/algorithm-artifact-preimage.bin"
                    )
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
            ];
            for (relative, bytes) in profile_files {
                write_relative(relative, bytes);
                fixture
                    .top_level
                    .source_artifacts
                    .insert(relative.to_owned(), bytes.to_vec());
            }

            let raw_seal = synthetic_raw_producer_seal();
            let raw_seal_sha256 = sha256_hex(&raw_seal);
            let mut registry = fixture.top_level.expanded_registry.clone();
            for case in &mut registry.positive_cases {
                let path = format!("raw-seals/{}.seal", case.case_id);
                write_relative(&path, &raw_seal);
                case.artifacts = vec![B4PositiveArtifact {
                    byte_length: u64::try_from(raw_seal.len()).unwrap(),
                    encoding: B4ArtifactEncoding::RawBytes,
                    path,
                    role: B4PositiveArtifactRole::RawSeal,
                    sha256: raw_seal_sha256.clone(),
                }];
            }

            let profile_id: [u8; 32] = hex::decode(&registry.profile.profile_id)
                .unwrap()
                .try_into()
                .unwrap();
            let chain_domain_id = std::array::from_fn(|index| u8::try_from(index + 1).unwrap());
            let program_id = std::array::from_fn(|index| 0x40_u8 + u8::try_from(index).unwrap());
            let contract_id = std::array::from_fn(|index| 0x80_u8 + u8::try_from(index).unwrap());
            let statement = crate::ErgoStatementV1::new(
                chain_domain_id,
                profile_id,
                program_id,
                contract_id,
                b"authenticated-opcode-source",
            )
            .unwrap()
            .encode()
            .unwrap();
            let statement_path = "positive/lift-po2-15/candidate-journal.bin";
            let image_id_path = "positive/lift-po2-15/candidate-image-id.bin";
            fixture
                .top_level
                .source_artifacts
                .insert(statement_path.to_owned(), statement.clone());
            fixture
                .top_level
                .source_artifacts
                .insert(image_id_path.to_owned(), program_id.to_vec());
            registry.positive_cases[0].artifacts.extend_from_slice(&[
                B4PositiveArtifact {
                    byte_length: u64::try_from(statement.len()).unwrap(),
                    encoding: B4ArtifactEncoding::RawBytes,
                    path: statement_path.to_owned(),
                    role: B4PositiveArtifactRole::Journal,
                    sha256: sha256_hex(&statement),
                },
                B4PositiveArtifact {
                    byte_length: u64::try_from(program_id.len()).unwrap(),
                    encoding: B4ArtifactEncoding::RawBytes,
                    path: image_id_path.to_owned(),
                    role: B4PositiveArtifactRole::ImageId,
                    sha256: sha256_hex(&program_id),
                },
            ]);
            registry.bindings.guest.image_id = hex::encode(program_id);
            registry.bindings.guest.state = B4BindingState::Bound;
            registry.bindings.reference_statement_bundle.contract_id = hex::encode(contract_id);
            registry
                .bindings
                .reference_statement_bundle
                .statement_sha256 = sha256_hex(&statement);
            registry.bindings.reference_statement_bundle.state = B4BindingState::Bound;

            let plan =
                Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.top_level.negative_plan)
                    .unwrap();
            let subject_bundle = crate::b4_catalog::derive_b4_subject_bundle(
                &registry,
                &plan,
                temporary_repository.path(),
            )
            .unwrap();
            let subject_catalog_jcs = subject_bundle.catalog_jcs().unwrap();
            for (path, bytes) in subject_bundle.subject_files {
                fixture.top_level.source_artifacts.insert(path, bytes);
            }
            let subject_catalog_identity = contract_identity(
                "reproduction/schema/b4-corpus-v1.candidate/subject-catalog.json",
                &subject_catalog_jcs,
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
            );
            set_registry_binding(
                &mut registry.bindings.subject_catalog,
                &subject_catalog_identity,
            );
            fixture.top_level.subject_catalog_jcs = subject_catalog_jcs;
            fixture.top_level.document_identities.subject_catalog =
                identity_for(&fixture.top_level.subject_catalog_jcs);
            fixture.top_level.source_artifacts.insert(
                subject_catalog_identity.path,
                fixture.top_level.subject_catalog_jcs.clone(),
            );
            fixture.top_level.positive_exports = registry
                .positive_cases
                .iter()
                .map(|case| B4AuthenticatedPositiveExportV1 {
                    case_index: case.index,
                    proof_output_manifest_jcs: b"[]".to_vec(),
                    raw_seal: raw_seal.clone(),
                    auxiliary_artifacts: Vec::new(),
                })
                .collect();
            fixture.top_level.expanded_registry = registry;
            fixture.seed_exact_fixture_resolver_sources();
            for (case, export) in fixture
                .top_level
                .expanded_registry
                .positive_cases
                .iter()
                .zip(&fixture.top_level.positive_exports)
            {
                let raw = case
                    .artifacts
                    .iter()
                    .find(|artifact| artifact.role == B4PositiveArtifactRole::RawSeal)
                    .unwrap();
                write_relative(&raw.path, &export.raw_seal);
            }
            let regenerated = crate::b4_catalog::derive_b4_subject_bundle(
                &fixture.top_level.expanded_registry,
                &plan,
                temporary_repository.path(),
            )
            .unwrap();
            assert_eq!(
                regenerated.catalog_jcs().unwrap(),
                fixture.top_level.subject_catalog_jcs
            );
            for (path, bytes) in regenerated.subject_files {
                assert_eq!(
                    fixture.top_level.source_artifacts.get(&path),
                    Some(&bytes),
                    "production-shaped resolver fixture changed subject source {path}"
                );
            }
            fixture
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the shared test fixture explicitly assembles every resolver-authenticated positive role, export manifest, and positive-input binding"
        )]
        fn seed_exact_fixture_resolver_sources(&mut self) {
            let raw_seal = self.top_level.positive_exports[0].raw_seal.clone();
            let statement = self
                .top_level
                .source_artifacts
                .get("positive/lift-po2-15/candidate-journal.bin")
                .unwrap()
                .clone();
            let program_id = self
                .top_level
                .source_artifacts
                .get("positive/lift-po2-15/candidate-image-id.bin")
                .unwrap()
                .clone();
            assert_eq!(program_id.len(), 32);

            let mut exports = Vec::with_capacity(11);
            for (case_index, case) in self
                .top_level
                .expanded_registry
                .positive_cases
                .iter_mut()
                .enumerate()
            {
                assert_eq!(usize::from(case.index), case_index);
                let mut artifacts = Vec::new();
                let mut manifest_entries = Vec::new();
                for &(role, file_name) in positive_artifact_layout(case_index).unwrap() {
                    let bytes = match role {
                        B4PositiveArtifactRole::Ancestry
                        | B4PositiveArtifactRole::Calibration
                        | B4PositiveArtifactRole::Metadata => b"{}".to_vec(),
                        B4PositiveArtifactRole::ImageId if case_index == 0 => program_id.clone(),
                        B4PositiveArtifactRole::ClaimDigest
                        | B4PositiveArtifactRole::ControlId
                        | B4PositiveArtifactRole::ImageId => {
                            vec![u8::try_from(case_index).unwrap(); 32]
                        }
                        B4PositiveArtifactRole::Journal if case_index == 0 => statement.clone(),
                        B4PositiveArtifactRole::Journal => {
                            vec![u8::try_from(case_index).unwrap(); 159]
                        }
                        B4PositiveArtifactRole::RawSeal => raw_seal.clone(),
                        B4PositiveArtifactRole::ReceiptOracle => {
                            vec![u8::try_from(case_index).unwrap()]
                        }
                    };
                    let path = format!(
                        "reproduction/schema/b4-corpus-v1.candidate/positive/{}/{}",
                        case.case_id, file_name
                    );
                    if role != B4PositiveArtifactRole::RawSeal {
                        self.top_level
                            .source_artifacts
                            .insert(path.clone(), bytes.clone());
                    }
                    let artifact = B4PositiveArtifact {
                        byte_length: u64::try_from(bytes.len()).unwrap(),
                        encoding: positive_artifact_encoding(role).1,
                        path,
                        role,
                        sha256: sha256_hex(&bytes),
                    };
                    manifest_entries.push(ManifestEntry {
                        path: file_name.to_owned(),
                        length: artifact.byte_length.to_string(),
                        sha256: artifact.sha256.clone(),
                    });
                    artifacts.push(artifact);
                }
                let mut auxiliary_artifacts = Vec::new();
                for (position, path) in positive_auxiliary_artifact_paths(case_index)
                    .unwrap()
                    .iter()
                    .copied()
                    .enumerate()
                {
                    let bytes =
                        vec![
                            0xc0_u8.wrapping_add(u8::try_from(case_index * 8 + position).unwrap(),);
                            PROOF_BYTES
                        ];
                    let identity = B4AuthenticatedPositiveAuxiliaryArtifactV1 {
                        path: path.to_owned(),
                        byte_length: u64::try_from(bytes.len()).unwrap(),
                        sha256: sha256_hex(&bytes),
                    };
                    self.top_level
                        .source_artifacts
                        .insert(identity.path.clone(), bytes);
                    manifest_entries.push(ManifestEntry {
                        path: identity.path.clone(),
                        length: identity.byte_length.to_string(),
                        sha256: identity.sha256.clone(),
                    });
                    auxiliary_artifacts.push(identity);
                }
                manifest_entries.sort_by(|left, right| left.path.cmp(&right.path));
                case.artifacts = artifacts;
                exports.push(B4AuthenticatedPositiveExportV1 {
                    case_index: case.index,
                    proof_output_manifest_jcs: canonical_json_bytes(
                        &serde_json::to_value(manifest_entries).unwrap(),
                    )
                    .unwrap(),
                    raw_seal: raw_seal.clone(),
                    auxiliary_artifacts,
                });
            }
            self.top_level.positive_exports = exports;

            let manifest_path = "profiles/risc0-v3-succinct/manifest.bin";
            let algorithm_path = "profiles/risc0-v3-succinct/algorithm.txt";
            let constants_path = "profiles/risc0-v3-succinct/constants.bin";
            let guest_path = "methods/parser-fixture-guest.elf";
            let guest_candidate_path =
                "reproduction/schema/b4-corpus-v1.candidate/bindings/guest.elf";
            let statement_manifest_path = "statement/parser-fixture-bundle-manifest.json";
            let statement_manifest_candidate_path =
                "reproduction/schema/b4-corpus-v1.candidate/bindings/statement-manifest.json";
            let source_lock_path = "locks/parser-fixture-source-lock.json";
            let generator_path = "generator/parser-fixture-generator";
            let manifest = self.top_level.source_artifacts[manifest_path].clone();
            let algorithm = self.top_level.source_artifacts[algorithm_path].clone();
            let constants = self.top_level.source_artifacts[constants_path].clone();
            let guest_elf = b"authenticated-parser-fixture-guest-elf".to_vec();
            let statement_manifest = b"{}".to_vec();
            let source_lock = b"{}".to_vec();
            let generator = b"authenticated-parser-fixture-generator".to_vec();
            let profile_id = hex::encode(crate::profile::profile_id(&manifest).unwrap());
            assert_eq!(
                self.top_level.expanded_registry.profile.profile_id,
                profile_id
            );
            let image_id = hex::encode(&program_id);
            assert_eq!(
                self.top_level.expanded_registry.bindings.guest.image_id,
                image_id
            );
            for (path, bytes) in [
                (guest_path, guest_elf.clone()),
                (guest_candidate_path, guest_elf.clone()),
                (statement_manifest_path, statement_manifest.clone()),
                (
                    statement_manifest_candidate_path,
                    statement_manifest.clone(),
                ),
                (source_lock_path, source_lock.clone()),
                (generator_path, generator.clone()),
            ] {
                self.top_level
                    .source_artifacts
                    .insert(path.to_owned(), bytes);
            }
            self.top_level.expanded_registry.profile.manifest = B4ArtifactBinding {
                byte_length: u64::try_from(manifest.len()).unwrap(),
                encoding: B4ArtifactEncoding::RawBytes,
                path: manifest_path.to_owned(),
                sha256: sha256_hex(&manifest),
                state: B4BindingState::Bound,
            };
            self.top_level.expanded_registry.bindings.guest.elf = B4ArtifactBinding {
                byte_length: u64::try_from(guest_elf.len()).unwrap(),
                encoding: B4ArtifactEncoding::RawBytes,
                path: guest_candidate_path.to_owned(),
                sha256: sha256_hex(&guest_elf),
                state: B4BindingState::Bound,
            };
            self.top_level.expanded_registry.bindings.guest.state = B4BindingState::Bound;
            let parsed_statement = crate::parse_ergo_statement_v1(&statement).unwrap();
            let reference_contract_id = hex::encode(parsed_statement.contract_id());
            let reference_statement_sha256 = sha256_hex(&statement);
            let reference_binding = &mut self
                .top_level
                .expanded_registry
                .bindings
                .reference_statement_bundle;
            reference_binding.state = B4BindingState::Bound;
            reference_binding.manifest = B4ArtifactBinding {
                byte_length: u64::try_from(statement_manifest.len()).unwrap(),
                encoding: B4ArtifactEncoding::Rfc8785Jcs,
                path: statement_manifest_candidate_path.to_owned(),
                sha256: sha256_hex(&statement_manifest),
                state: B4BindingState::Bound,
            };
            reference_binding
                .contract_id
                .clone_from(&reference_contract_id);
            reference_binding
                .statement_sha256
                .clone_from(&reference_statement_sha256);
            let positive_input = serde_json::json!({
                "format": "Eip0045B4PositiveInputSetV1",
                "formatVersion": 1,
                "profile": {
                    "profileId": profile_id,
                    "manifest": input_identity(manifest_path, &manifest, "raw-bytes"),
                    "algorithm": input_identity(algorithm_path, &algorithm, "raw-bytes"),
                    "constants": input_identity(constants_path, &constants, "raw-bytes"),
                },
                "guest": {
                    "elf": input_identity(guest_path, &guest_elf, "raw-bytes"),
                    "imageId": image_id,
                },
                "referenceStatement": {
                    "bundleManifest": input_identity(
                        statement_manifest_path,
                        &statement_manifest,
                        "rfc8785-jcs"
                    ),
                    "contractId": reference_contract_id,
                    "statementByteLength": statement.len(),
                    "statementSha256": reference_statement_sha256,
                    "chainDomainId": hex::encode(parsed_statement.chain_domain_id()),
                    "applicationPayloadByteLength": parsed_statement.application_payload().len(),
                    "applicationPayloadSha256": sha256_hex(
                        parsed_statement.application_payload()
                    ),
                },
                "sourceLock": input_identity(source_lock_path, &source_lock, "rfc8785-jcs"),
                "proofGenerator": {
                    "artifact": input_identity(generator_path, &generator, "raw-bytes")
                },
            });
            self.top_level.positive_input_set = canonical_json_bytes(&positive_input).unwrap();
        }

        fn with_exact_c1_top_level() -> Self {
            let mut fixture = Self::exact();
            fixture.seed_exact_c1_top_level();
            fixture
        }

        fn with_exact_implemented_producer_top_level() -> Self {
            let mut fixture = Self::with_exact_c2_opcode_top_level();
            fixture.seed_exact_c1_top_level();
            fixture
        }

        fn seed_exact_production_materializations(&mut self) {
            let plan =
                Eip0045B4NegativePlanV1::from_canonical_jcs(&self.top_level.negative_plan).unwrap();
            let planned = plan
                .groups
                .iter()
                .flat_map(|group| group.executions.iter())
                .collect::<Vec<_>>();
            assert_eq!(planned.len(), 254);
            let mut replaced = 0;
            for (index, execution) in planned.iter().enumerate() {
                if let Some(reconstructed) = ProductionRowProducer
                    .reconstruct(index, execution, &self.top_level)
                    .unwrap()
                {
                    self.top_level.expanded_registry.negative_cases[index] =
                        reconstructed.derived_registry_row.clone();
                    self.external[index] =
                        owned_c1_execution(index, planned[index], &reconstructed);
                    self.reconstructed[index] = reconstructed;
                    replaced += 1;
                }
            }
            assert_eq!(replaced, 218);
        }

        fn seed_exact_c1_top_level(&mut self) {
            let plan =
                Eip0045B4NegativePlanV1::from_canonical_jcs(&self.top_level.negative_plan).unwrap();
            self.top_level.abstract_tree_jcs = Eip0045B4AbstractTreeV1::canonical_baseline()
                .unwrap()
                .to_canonical_jcs()
                .unwrap();
            self.top_level.negative_binding_index_jcs =
                synthetic_negative_binding_index_source(&plan).unwrap();
            self.top_level.document_identities.abstract_tree =
                identity_for(&self.top_level.abstract_tree_jcs);
            self.top_level.document_identities.negative_binding_index =
                identity_for(&self.top_level.negative_binding_index_jcs);

            let planned = plan
                .groups
                .iter()
                .flat_map(|group| group.executions.iter())
                .collect::<Vec<_>>();
            for (index, execution) in planned.iter().enumerate().skip(210) {
                self.top_level.expanded_registry.negative_cases[index] = if index < 231 {
                    materialize_tree_probe(&self.top_level.negative_plan, &execution.execution_id)
                        .unwrap()
                        .registry_row
                } else {
                    materialize_registry_probe(
                        &self.top_level.negative_plan,
                        &execution.execution_id,
                    )
                    .unwrap()
                    .registry_row
                };
            }
        }

        fn with_exact_c1_materializations() -> Self {
            let mut fixture = Self::with_exact_c1_top_level();
            let plan =
                Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.top_level.negative_plan)
                    .unwrap();
            let planned = plan
                .groups
                .iter()
                .flat_map(|group| group.executions.iter())
                .collect::<Vec<_>>();
            let c1 = planned
                .iter()
                .enumerate()
                .filter_map(|(index, execution)| {
                    C1ProductionRowProducer
                        .reconstruct(index, execution, &fixture.top_level)
                        .unwrap()
                        .map(|reconstructed| (index, reconstructed))
                })
                .collect::<Vec<_>>();
            assert_eq!(c1.len(), 44);
            for (index, reconstructed) in c1 {
                fixture.external[index] = owned_c1_execution(index, planned[index], &reconstructed);
                fixture.reconstructed[index] = reconstructed;
            }
            fixture
        }

        fn with_exact_parser_materializations() -> Self {
            let mut fixture = Self::with_exact_implemented_producer_top_level();
            let plan =
                Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.top_level.negative_plan)
                    .unwrap();
            let planned = plan
                .groups
                .iter()
                .flat_map(|group| group.executions.iter())
                .collect::<Vec<_>>();
            for (index, execution) in planned.iter().enumerate().take(108).skip(72) {
                let reconstructed = crate::b4_c2_parser::reconstruct_parser_execution(
                    index,
                    execution,
                    &fixture.top_level,
                )
                .unwrap()
                .unwrap();
                fixture.top_level.expanded_registry.negative_cases[index] =
                    reconstructed.derived_registry_row.clone();
                fixture.external[index] = owned_c1_execution(index, execution, &reconstructed);
                fixture.reconstructed[index] = reconstructed;
            }
            for (index, execution) in planned.iter().enumerate().skip(C1_TREE_FIRST_INDEX) {
                let reconstructed = C1ProductionRowProducer
                    .reconstruct(index, execution, &fixture.top_level)
                    .unwrap()
                    .unwrap();
                fixture.external[index] = owned_c1_execution(index, execution, &reconstructed);
                fixture.reconstructed[index] = reconstructed;
            }
            fixture
        }

        fn with_exact_raw_materializations() -> Self {
            let mut fixture = Self::with_exact_implemented_producer_top_level();
            let plan =
                Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.top_level.negative_plan)
                    .unwrap();
            let planned = plan
                .groups
                .iter()
                .flat_map(|group| group.executions.iter())
                .collect::<Vec<_>>();
            for index in (0..=6).chain([29]).chain(33..=71).chain([109]) {
                let execution = planned[index];
                let reconstructed = crate::b4_c2_raw::reconstruct_raw_execution(
                    index,
                    execution,
                    &fixture.top_level,
                )
                .unwrap()
                .unwrap();
                fixture.top_level.expanded_registry.negative_cases[index] =
                    reconstructed.derived_registry_row.clone();
                fixture.external[index] = owned_c1_execution(index, execution, &reconstructed);
                fixture.reconstructed[index] = reconstructed;
            }
            for (index, execution) in planned.iter().enumerate().skip(C1_TREE_FIRST_INDEX) {
                let reconstructed = C1ProductionRowProducer
                    .reconstruct(index, execution, &fixture.top_level)
                    .unwrap()
                    .unwrap();
                fixture.external[index] = owned_c1_execution(index, execution, &reconstructed);
                fixture.reconstructed[index] = reconstructed;
            }
            fixture
        }
    }

    #[cfg(feature = "negative-materialization-set")]
    struct B4SharedPostAuthenticationCoreTemplateV1 {
        lineage: std::sync::Arc<
            crate::b4_negative_ancestry_authority::test_support::
                B4NegativeAncestryLineageTestSupportV1,
        >,
        core: CoreFixture,
        path_ledger: B4PhysicalPathClosureV1,
    }

    #[cfg(feature = "negative-materialization-set")]
    #[allow(
        dead_code,
        reason = "the guard is retained solely to keep the exact publication root alive"
    )]
    struct B4SharedPostAuthenticationCoreFixtureV1 {
        lineage: std::sync::Arc<
            crate::b4_negative_ancestry_authority::test_support::
                B4NegativeAncestryLineageTestSupportV1,
        >,
        publication_guard: tempfile::TempDir,
        publication_root: PathBuf,
        core: CoreFixture,
        path_ledger: B4PhysicalPathClosureV1,
    }

    #[cfg(feature = "negative-materialization-set")]
    pub(crate) struct B4NegativeAncestryProducerTestInputsV1 {
        pub(crate) top_level: B4AuthenticatedMaterializationTopLevelV1,
        pub(crate) read_set: B4NegativeAncestryPublicationReadSetV1,
    }

    #[cfg(feature = "negative-materialization-set")]
    pub(crate) fn exact_negative_ancestry_producer_test_inputs()
    -> Result<B4NegativeAncestryProducerTestInputsV1> {
        let fixture = B4SharedPostAuthenticationCoreFixtureV1::exact()?;
        let (_, handoff, _) = fixture.authenticated_handoff()?;
        Ok(B4NegativeAncestryProducerTestInputsV1 {
            top_level: fixture.core.top_level,
            read_set: handoff.read_set,
        })
    }

    #[cfg(feature = "negative-materialization-set")]
    impl B4SharedPostAuthenticationCoreFixtureV1 {
        fn exact() -> Result<Self> {
            static FIXTURE: std::sync::OnceLock<
                std::result::Result<B4SharedPostAuthenticationCoreTemplateV1, String>,
            > = std::sync::OnceLock::new();
            match FIXTURE.get_or_init(|| {
                Self::build_uncached()
                    .map(
                        |B4SharedPostAuthenticationCoreFixtureV1 {
                             lineage,
                             publication_guard: _,
                             publication_root: _,
                             core,
                             path_ledger,
                         }| B4SharedPostAuthenticationCoreTemplateV1 {
                            lineage,
                            core,
                            path_ledger,
                        },
                    )
                    .map_err(|error| format!("{error:#}"))
            }) {
                Ok(template) => {
                    let publication_guard = tempfile::tempdir()?;
                    let publication_root = publication_guard.path().join("published");
                    crate::b4_negative_ancestry_publication::test_support::
                        write_exact_test_publication(&publication_root, &template.lineage.ancestry)?;
                    Ok(Self {
                        lineage: std::sync::Arc::clone(&template.lineage),
                        publication_guard,
                        publication_root,
                        core: template.core.clone(),
                        path_ledger: template.path_ledger.clone(),
                    })
                }
                Err(message) => anyhow::bail!(
                    "cannot build the cached shared post-authentication core fixture: {message}"
                ),
            }
        }

        #[allow(
            clippy::too_many_lines,
            reason = "the test-only seam builder performs the complete fixed-lineage, publication, source, and producer coherence construction in one auditable operation"
        )]
        fn build_uncached() -> Result<Self> {
            let reference_chain_domain_id =
                std::array::from_fn(|index| u8::try_from(index).expect("digest index fits u8"));
            let reference_application_payload = b"E5 descriptor-rooted shared core";
            let lineage = std::sync::Arc::new(
                crate::b4_negative_ancestry_authority::test_support::
                    fixed_negative_ancestry_lineage_test_support_with_reference_statement(
                        reference_chain_domain_id,
                        reference_application_payload,
                    )?,
            );
            let lineage_statement = lineage
                .prior
                .case9_primary_artifacts
                .iter()
                .find(|artifact| artifact.path.ends_with("/candidate-journal.bin"))
                .context("parameterized lineage case 9 omits its Journal")?;
            let lineage_statement = crate::parse_ergo_statement_v1(&lineage_statement.bytes)?;
            ensure!(
                lineage_statement.chain_domain_id() == reference_chain_domain_id
                    && lineage_statement.application_payload() == reference_application_payload,
                "parameterized lineage did not retain the requested reference statement"
            );
            ensure!(
                lineage
                    .prior
                    .positive_generation_authority
                    .cases()
                    .get(9)
                    .is_some_and(|case| case.case_index() == 9),
                "fixed lineage generation view does not retain case index 9"
            );
            let publication_guard = tempfile::tempdir()?;
            let publication_root = publication_guard.path().join("published");
            crate::b4_negative_ancestry_publication::test_support::write_exact_test_publication(
                &publication_root,
                &lineage.ancestry,
            )?;

            let mut core = CoreFixture::with_exact_implemented_producer_top_level();

            let profile_artifacts = [
                &lineage.prior.profile_manifest,
                &lineage.prior.profile_algorithm,
                &lineage.prior.profile_constants,
                &lineage.prior.consumer_guest_elf,
            ];
            let profile_identities = profile_artifacts
                .iter()
                .map(|artifact| {
                    B4ContractArtifactIdentityV1::from_bytes(
                        &artifact.path,
                        B4ContractArtifactEncodingV1::RawBytes,
                        &artifact.bytes,
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            let mut positive_input: Value =
                serde_json::from_slice(&core.top_level.positive_input_set)?;
            let previous_input_guest_path = positive_input["guest"]["elf"]["path"]
                .as_str()
                .context("shared-core positive input omits its guest-ELF path")?
                .to_owned();
            positive_input["profile"]["manifest"] = input_identity(
                &profile_identities[0].path,
                &lineage.prior.profile_manifest.bytes,
                "raw-bytes",
            );
            positive_input["profile"]["algorithm"] = input_identity(
                &profile_identities[1].path,
                &lineage.prior.profile_algorithm.bytes,
                "raw-bytes",
            );
            positive_input["profile"]["constants"] = input_identity(
                &profile_identities[2].path,
                &lineage.prior.profile_constants.bytes,
                "raw-bytes",
            );
            positive_input["guest"]["elf"] = input_identity(
                &profile_identities[3].path,
                &lineage.prior.consumer_guest_elf.bytes,
                "raw-bytes",
            );
            core.top_level.positive_input_set = canonical_json_bytes(&positive_input)?;
            let guest_candidate_path = core
                .top_level
                .expanded_registry
                .bindings
                .guest
                .elf
                .path
                .clone();
            set_registry_binding(
                &mut core.top_level.expanded_registry.profile.manifest,
                &profile_identities[0],
            );
            set_registry_quarantine_copy_binding(
                &mut core.top_level.expanded_registry.bindings.guest.elf,
                &profile_identities[3],
                &guest_candidate_path,
            );
            if previous_input_guest_path != profile_identities[3].path {
                ensure!(
                    core.top_level
                        .source_artifacts
                        .remove(&previous_input_guest_path)
                        .is_some(),
                    "shared-core fixture omits its stale pre-reseed upstream guest source"
                );
            }
            for artifact in profile_artifacts {
                core.top_level
                    .source_artifacts
                    .insert(artifact.path.clone(), artifact.bytes.clone());
            }
            ensure!(
                core.top_level
                    .source_artifacts
                    .insert(
                        guest_candidate_path,
                        lineage.prior.consumer_guest_elf.bytes.clone(),
                    )
                    .is_some(),
                "shared-core fixture omits its guest quarantine-copy source"
            );

            let case9 = core
                .top_level
                .expanded_registry
                .positive_cases
                .get_mut(9)
                .context("fixed core registry omits case index 9")?;
            ensure!(
                case9.index == 9
                    && case9.artifacts.len() == lineage.prior.case9_primary_artifacts.len(),
                "fixed core registry case-9 view has the wrong index or primary cardinality"
            );
            for ((artifact, owned), (role, file_name)) in case9
                .artifacts
                .iter_mut()
                .zip(&lineage.prior.case9_primary_artifacts)
                .zip(positive_artifact_layout(9)?.iter().copied())
            {
                ensure!(
                    owned.path.ends_with(file_name),
                    "fixed lineage case-9 primary path/order drift"
                );
                *artifact = B4PositiveArtifact {
                    byte_length: u64::try_from(owned.bytes.len())?,
                    encoding: positive_artifact_encoding(role).1,
                    path: owned.path.clone(),
                    role,
                    sha256: sha256_hex(&owned.bytes),
                };
                if role != B4PositiveArtifactRole::RawSeal {
                    core.top_level
                        .source_artifacts
                        .insert(owned.path.clone(), owned.bytes.clone());
                }
            }

            let export = core
                .top_level
                .positive_exports
                .get_mut(9)
                .context("fixed core positive exports omit case index 9")?;
            ensure!(
                export.case_index == 9,
                "fixed core retained positive-export view is not case index 9"
            );
            export
                .proof_output_manifest_jcs
                .clone_from(&lineage.prior.case9_proof_output_manifest_jcs);
            export.raw_seal = lineage
                .prior
                .case9_primary_artifacts
                .iter()
                .zip(positive_artifact_layout(9)?)
                .find(|(_, (role, _))| *role == B4PositiveArtifactRole::RawSeal)
                .map(|(artifact, _)| artifact.bytes.clone())
                .context("fixed lineage case 9 omits its raw seal")?;
            export.auxiliary_artifacts = lineage
                .prior
                .case9_auxiliary_artifacts
                .iter()
                .map(|artifact| {
                    core.top_level
                        .source_artifacts
                        .insert(artifact.path.clone(), artifact.bytes.clone());
                    B4AuthenticatedPositiveAuxiliaryArtifactV1 {
                        path: artifact.path.clone(),
                        byte_length: u64::try_from(artifact.bytes.len()).unwrap(),
                        sha256: sha256_hex(&artifact.bytes),
                    }
                })
                .collect();

            let (terminal_catalogue, terminal_sources) =
                crate::b4_terminal::synthetic_terminal_fixture_catalog_source()?;
            core.top_level.terminal_fixture_catalog_jcs = terminal_catalogue;
            for (path, bytes) in terminal_sources {
                ensure!(
                    core.top_level
                        .source_artifacts
                        .insert(path, bytes)
                        .is_none(),
                    "shared-core terminal fixture source aliases an existing deterministic path"
                );
            }
            crate::b4_fixture_sources::reseed_descriptor_rooted_recursive_sources_from_case9(
                &mut core.top_level,
                b"semantic-gate-test-proposition",
            )?;
            core.top_level.document_identities.terminal_fixture_catalog =
                identity_for(&core.top_level.terminal_fixture_catalog_jcs);

            let fixed_input_sources =
                parse_positive_input_sources(&core.top_level.positive_input_set)?;
            set_registry_binding(
                &mut core.top_level.expanded_registry.bindings.generator,
                &fixed_input_sources.generator,
            );
            set_registry_binding(
                &mut core.top_level.expanded_registry.bindings.source_lock,
                &fixed_input_sources.source_lock,
            );
            for (binding, path, bytes) in [
                (
                    &mut core.top_level.expanded_registry.bindings.rust_verifier,
                    "validator/parser-fixture-rust-verifier",
                    b"authenticated-parser-fixture-rust-verifier".as_slice(),
                ),
                (
                    &mut core.top_level.expanded_registry.bindings.jvm_verifier,
                    "validator/parser-fixture-jvm-verifier",
                    b"authenticated-parser-fixture-jvm-verifier".as_slice(),
                ),
            ] {
                let identity = B4ContractArtifactIdentityV1::from_bytes(
                    path,
                    B4ContractArtifactEncodingV1::RawBytes,
                    bytes,
                )?;
                set_registry_binding(binding, &identity);
                ensure!(
                    core.top_level
                        .source_artifacts
                        .insert(path.to_owned(), bytes.to_vec())
                        .is_none(),
                    "shared-core verifier source aliases an existing deterministic fixture path"
                );
            }

            let profile_package_paths = profile_identities
                .iter()
                .map(|identity| identity.path.clone())
                .collect();
            let case9_paths = lineage
                .prior
                .case9_primary_artifacts
                .iter()
                .chain(&lineage.prior.case9_auxiliary_artifacts)
                .map(|artifact| artifact.path.clone())
                .collect();
            core.top_level.negative_ancestry_provenance_evidence =
                B4AuthenticatedNegativeAncestryProvenanceEvidenceV1 {
                    profile_manifest: profile_identities[0].clone(),
                    profile_package_paths,
                    case9_paths,
                };

            let parsed = parse_positive_input_sources(&core.top_level.positive_input_set)?;
            ensure!(
                parsed.profile_manifest == lineage.ancestry.catalog().profile_manifest,
                "fixed core positive-input profile manifest differs from ancestry catalogue"
            );
            let negative_plan = B4ContractArtifactIdentityV1::from_bytes(
                &lineage.ancestry.catalog().negative_plan.path,
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &core.top_level.negative_plan,
            )?;
            ensure!(
                negative_plan == lineage.ancestry.catalog().negative_plan,
                "fixed core negative plan differs from ancestry catalogue"
            );
            let negative_plan_candidate_path =
                "reproduction/schema/b4-corpus-v1.candidate/bindings/negative-plan.json";
            set_registry_quarantine_copy_binding(
                &mut core.top_level.expanded_registry.bindings.negative_plan,
                &negative_plan,
                negative_plan_candidate_path,
            );
            ensure!(
                core.top_level
                    .source_artifacts
                    .insert(
                        negative_plan_candidate_path.to_owned(),
                        core.top_level.negative_plan.clone(),
                    )
                    .is_none(),
                "shared-core negative-plan quarantine copy aliases an existing fixture path"
            );

            let prior = B4MaterializationPriorAuthoritySnapshotV1::from_authorities(
                &lineage.prior.campaign_precommit_authority,
                &lineage.prior.positive_generation_authority,
            )?;
            lineage.ancestry.verify_prior_authority_lineage(
                &lineage.prior.campaign_precommit_authority,
                &lineage.prior.positive_generation_authority,
            )?;
            let handoff = B4AuthenticatedNegativeAncestryHandoffV1::from_publication(
                &publication_root,
                &lineage.ancestry,
            )?;
            let mut path_ledger = B4PhysicalPathClosureV1::from_prior(&prior)?;
            for (path, bytes) in handoff.read_set.ordered_files() {
                path_ledger.bind_publication_source(
                    path,
                    bytes,
                    "negative-ancestry publication",
                )?;
            }
            for artifact in [
                &lineage.prior.profile_manifest,
                &lineage.prior.profile_algorithm,
                &lineage.prior.profile_constants,
                &lineage.prior.consumer_guest_elf,
            ] {
                ensure!(
                    core.top_level
                        .source_artifacts
                        .get(&artifact.path)
                        .is_some_and(|bytes| bytes == &artifact.bytes),
                    "shared-core profile source differs from the exact fixed-lineage bytes"
                );
            }
            for (artifact, (role, _)) in lineage
                .prior
                .case9_primary_artifacts
                .iter()
                .zip(positive_artifact_layout(9)?)
            {
                let retained = if *role == B4PositiveArtifactRole::RawSeal {
                    Some(&core.top_level.positive_exports[9].raw_seal)
                } else {
                    core.top_level.source_artifacts.get(&artifact.path)
                };
                ensure!(
                    retained.is_some_and(|bytes| bytes == &artifact.bytes),
                    "shared-core case-9 primary source differs from the exact fixed-lineage bytes"
                );
            }
            for artifact in &lineage.prior.case9_auxiliary_artifacts {
                ensure!(
                    core.top_level
                        .source_artifacts
                        .get(&artifact.path)
                        .is_some_and(|bytes| bytes == &artifact.bytes),
                    "shared-core case-9 auxiliary source differs from the exact fixed-lineage bytes"
                );
            }
            for stale_path in [
                "positive/lift-po2-15/candidate-image-id.bin",
                "positive/lift-po2-15/candidate-journal.bin",
                "reproduction/schema/b4-corpus-v1.candidate/subject-catalog.json",
            ] {
                ensure!(
                    core.top_level.source_artifacts.remove(stale_path).is_some(),
                    "shared-core fixture no longer contains the expected stale pre-reseed source"
                );
            }
            {
                let positive_input_sources =
                    parse_positive_input_sources(&core.top_level.positive_input_set)?;
                let subject_catalog = Eip0045B4SubjectCatalogV1::from_canonical_jcs(
                    &core.top_level.subject_catalog_jcs,
                )?;
                let exact_profile_support = [
                    (
                        "profiles/risc0-v3-succinct/algorithm-artifact-preimage.bin",
                        include_bytes!(
                            "../../profiles/risc0-v3-succinct/algorithm-artifact-preimage.bin"
                        )
                        .as_slice(),
                    ),
                    (
                        "profiles/risc0-v3-succinct/binary-data-artifact-preimage.bin",
                        include_bytes!(
                            "../../profiles/risc0-v3-succinct/binary-data-artifact-preimage.bin"
                        )
                        .as_slice(),
                    ),
                    (
                        "profiles/risc0-v3-succinct/profile-id-preimage.bin",
                        include_bytes!("../../profiles/risc0-v3-succinct/profile-id-preimage.bin")
                            .as_slice(),
                    ),
                    (
                        "profiles/risc0-v3-succinct/profile-id.bin",
                        include_bytes!("../../profiles/risc0-v3-succinct/profile-id.bin")
                            .as_slice(),
                    ),
                ];
                for (path, bytes) in exact_profile_support {
                    ensure!(
                        core.top_level
                            .source_artifacts
                            .get(path)
                            .is_some_and(|retained| retained == bytes),
                        "shared-core profile support source differs from its exact fixture bytes"
                    );
                }
                let source_views = core
                    .top_level
                    .source_artifacts
                    .iter()
                    .filter(|(path, _)| {
                        !exact_profile_support
                            .iter()
                            .any(|(exact_path, _)| path == exact_path)
                    })
                    .map(|(path, bytes)| B4NegativeMaterializationExternalBytesV1 { path, bytes })
                    .collect::<Vec<_>>();
                let terminal_catalogue = Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(
                    &core.top_level.terminal_fixture_catalog_jcs,
                )?;
                let mut retained_sources = authenticate_source_artifacts_with_terminal_fixtures(
                    &core.top_level.expanded_registry,
                    &subject_catalog,
                    &terminal_catalogue.fixtures,
                    &positive_input_sources,
                    &core.top_level.positive_exports,
                    &source_views,
                    &mut path_ledger,
                )?;
                for (path, bytes) in exact_profile_support {
                    path_ledger.bind_authority_selected_source(
                        B4NegativeMaterializationExternalBytesV1 { path, bytes },
                        "exact shared-core profile support source",
                    )?;
                    ensure!(
                        retained_sources
                            .insert(path.to_owned(), bytes.to_vec())
                            .is_none(),
                        "shared-core profile support source aliases the deterministic inventory"
                    );
                }
                ensure!(
                    retained_sources == core.top_level.source_artifacts,
                    "shared-core deterministic source inventory changed during authentication"
                );
            }
            let case9_raw_seal = lineage
                .prior
                .case9_primary_artifacts
                .iter()
                .zip(positive_artifact_layout(9)?)
                .find(|(_, (role, _))| *role == B4PositiveArtifactRole::RawSeal)
                .map(|(artifact, _)| artifact)
                .context("fixed lineage case 9 omits its raw seal")?;
            path_ledger.bind_authority_selected_source(
                B4NegativeMaterializationExternalBytesV1 {
                    path: &case9_raw_seal.path,
                    bytes: &case9_raw_seal.bytes,
                },
                "exact fixed-lineage case-9 raw seal",
            )?;

            core.seed_exact_production_materializations();
            Ok(Self {
                lineage,
                publication_guard,
                publication_root,
                core,
                path_ledger,
            })
        }

        fn authenticated_handoff(
            &self,
        ) -> Result<(
            B4MaterializationPriorAuthoritySnapshotV1,
            B4AuthenticatedNegativeAncestryHandoffV1,
            B4PhysicalPathClosureV1,
        )> {
            self.authenticated_handoff_at(&self.publication_root)
        }

        fn authenticated_handoff_at(
            &self,
            publication_root: &Path,
        ) -> Result<(
            B4MaterializationPriorAuthoritySnapshotV1,
            B4AuthenticatedNegativeAncestryHandoffV1,
            B4PhysicalPathClosureV1,
        )> {
            let prior = B4MaterializationPriorAuthoritySnapshotV1::from_authorities(
                &self.lineage.prior.campaign_precommit_authority,
                &self.lineage.prior.positive_generation_authority,
            )?;
            self.lineage.ancestry.verify_prior_authority_lineage(
                &self.lineage.prior.campaign_precommit_authority,
                &self.lineage.prior.positive_generation_authority,
            )?;
            let handoff = B4AuthenticatedNegativeAncestryHandoffV1::from_publication(
                publication_root,
                &self.lineage.ancestry,
            )?;
            let publication_paths = handoff
                .read_set
                .ordered_files()
                .map(|(path, _)| path.to_owned())
                .collect::<BTreeSet<_>>();
            ensure!(
                self.path_ledger.publication_paths == publication_paths,
                "stored shared-core publication path set differs from the fresh authenticated read set"
            );
            let mut paths = self.path_ledger.clone();
            for (path, digest) in &prior.provenance_sha256 {
                ensure!(
                    paths.sha256_by_path.get(path) == Some(digest)
                        && paths.role_by_path.get(path) == Some(&B4PhysicalPathRoleV1::Source),
                    "stored shared-core ledger differs from the rederived opaque prior closure"
                );
            }
            for (path, bytes) in handoff.read_set.ordered_files() {
                paths.bind_publication_source(path, bytes, "negative-ancestry publication")?;
            }
            Ok((prior, handoff, paths))
        }
    }

    pub(crate) fn fixture_source_top_level() -> B4AuthenticatedMaterializationTopLevelV1 {
        CoreFixture::exact().top_level
    }

    pub(crate) fn production_shaped_fixture_top_level() -> B4AuthenticatedMaterializationTopLevelV1
    {
        CoreFixture::with_exact_implemented_producer_top_level().top_level
    }

    fn identity_for(bytes: &[u8]) -> B4NegativeMaterializationByteIdentityV1 {
        pathless_identity(bytes).unwrap()
    }

    fn execution_documents(
        execution: &B4NegativePlanExecutionV1,
        registry_row: &B4NegativeCase,
        negative_plan: &[u8],
        base: &[u8],
        subject: &[u8],
        contexts: &[Vec<u8>],
    ) -> (Vec<u8>, Vec<u8>) {
        let recipe = canonical_materialization_recipe_jcs(&registry_row.materialization).unwrap();
        let identity = Eip0045B4MaterializationIdentityV1 {
            format: crate::b4_mutation::B4_MATERIALIZATION_IDENTITY_FORMAT.to_owned(),
            format_version: crate::b4_mutation::B4_MATERIALIZATION_IDENTITY_FORMAT_VERSION,
            base_selector_id: execution.base_selector_id.clone(),
            base_byte_length: u64::try_from(base.len()).unwrap(),
            base_sha256: sha256_hex(base),
            execution_id: execution.execution_id.clone(),
            materialization_domain: execution.materialization_domain,
            materialization_recipe_byte_length: u64::try_from(recipe.len()).unwrap(),
            materialization_recipe_sha256: sha256_hex(&recipe),
            negative_plan_byte_length: u64::try_from(negative_plan.len()).unwrap(),
            negative_plan_sha256: sha256_hex(negative_plan),
            output_byte_length: u64::try_from(subject.len()).unwrap(),
            output_sha256: sha256_hex(subject),
        };
        let input = Eip0045B4NegativeVerifierInputV1 {
            format: B4_NEGATIVE_VERIFIER_INPUT_FORMAT.to_owned(),
            format_version: B4_NEGATIVE_VERIFIER_INPUT_FORMAT_VERSION,
            materialization_domain: execution.materialization_domain,
            validation_surface: execution.execution_surface,
            subject: B4NegativeNamedIdentityV1 {
                role: "subject".to_owned(),
                path: "subject.bin".to_owned(),
                byte_length: u64::try_from(subject.len()).unwrap(),
                sha256: sha256_hex(subject),
                encoding: B4NegativeFileEncoding::RawBytes,
            },
            context: contexts
                .iter()
                .enumerate()
                .map(|(context_index, bytes)| B4NegativeNamedIdentityV1 {
                    role: format!("context-{context_index:02}"),
                    path: format!("context/{context_index:02}.bin"),
                    byte_length: u64::try_from(bytes.len()).unwrap(),
                    sha256: sha256_hex(bytes),
                    encoding: B4NegativeFileEncoding::RawBytes,
                })
                .collect(),
        };
        (
            identity.to_canonical_jcs().unwrap(),
            input.to_canonical_jcs().unwrap(),
        )
    }

    fn owned_c1_execution(
        index: usize,
        execution: &B4NegativePlanExecutionV1,
        reconstructed: &B4ClosedReconstructedExecutionV1,
    ) -> OwnedExecution {
        let root = format!("materializations/{index:03}");
        OwnedExecution {
            execution_index: u16::try_from(index).unwrap(),
            execution_id: execution.execution_id.clone(),
            base_path: format!("{root}/base.bin"),
            base: reconstructed.base.clone(),
            materialization_identity_path: format!("{root}/materialization-identity.json"),
            materialization_identity_jcs: reconstructed.materialization_identity_jcs.clone(),
            negative_input_path: format!("{root}/negative-input.json"),
            negative_input_jcs: reconstructed.negative_input_jcs.clone(),
            subject_path: format!("{root}/root/subject.bin"),
            subject: reconstructed.subject.clone(),
            context_paths: reconstructed
                .contexts
                .iter()
                .enumerate()
                .map(|(context_index, _)| format!("{root}/root/context/{context_index:02}.bin"))
                .collect(),
            contexts: reconstructed.contexts.clone(),
        }
    }

    fn raw_subject_envelope(kind: u8, parts: &[&[u8]]) -> Vec<u8> {
        let mut encoded = b"EIP45B4S\x01".to_vec();
        encoded.push(kind);
        encoded.extend_from_slice(&u16::try_from(parts.len()).unwrap().to_le_bytes());
        for part in parts {
            encoded.extend_from_slice(&u32::try_from(part.len()).unwrap().to_le_bytes());
            encoded.extend_from_slice(part);
        }
        encoded
    }

    fn assert_coordinated_c1_subject_rewrite_is_rejected(
        index: usize,
        execution: &B4NegativePlanExecutionV1,
        negative_plan: &[u8],
        canonical: &B4ClosedReconstructedExecutionV1,
        rewritten_subject: Vec<u8>,
    ) {
        let mut rewritten = owned_c1_execution(index, execution, canonical);
        rewritten.subject = rewritten_subject;
        let (identity, input) = execution_documents(
            execution,
            &canonical.derived_registry_row,
            negative_plan,
            &rewritten.base,
            &rewritten.subject,
            &rewritten.contexts,
        );
        rewritten.materialization_identity_jcs = identity;
        rewritten.negative_input_jcs = input;
        let rows = [rewritten];
        let contexts = context_views(&rows);
        let supplied = execution_views(&rows, &contexts);
        let error =
            ensure_reconstruction_matches_external(index, canonical, &supplied[0]).unwrap_err();
        assert!(
            format!("{error:#}").contains("closed producer reconstruction"),
            "{error:#}"
        );
    }

    fn context_views(
        rows: &[OwnedExecution],
    ) -> Vec<Vec<B4NegativeMaterializationExternalBytesV1<'_>>> {
        rows.iter()
            .map(|row| {
                row.context_paths
                    .iter()
                    .zip(&row.contexts)
                    .map(|(path, bytes)| B4NegativeMaterializationExternalBytesV1 { path, bytes })
                    .collect()
            })
            .collect()
    }

    fn execution_views<'a>(
        rows: &'a [OwnedExecution],
        contexts: &'a [Vec<B4NegativeMaterializationExternalBytesV1<'a>>],
    ) -> Vec<B4NegativeMaterializationExternalExecutionV1<'a>> {
        rows.iter()
            .zip(contexts)
            .map(
                |(row, context)| B4NegativeMaterializationExternalExecutionV1 {
                    execution_index: row.execution_index,
                    execution_id: &row.execution_id,
                    base: B4NegativeMaterializationExternalBytesV1 {
                        path: &row.base_path,
                        bytes: &row.base,
                    },
                    materialization_identity: B4NegativeMaterializationExternalBytesV1 {
                        path: &row.materialization_identity_path,
                        bytes: &row.materialization_identity_jcs,
                    },
                    negative_input: B4NegativeMaterializationExternalBytesV1 {
                        path: &row.negative_input_path,
                        bytes: &row.negative_input_jcs,
                    },
                    subject: B4NegativeMaterializationExternalBytesV1 {
                        path: &row.subject_path,
                        bytes: &row.subject,
                    },
                    contexts: context,
                },
            )
            .collect()
    }

    #[cfg(feature = "negative-materialization-set")]
    fn exact_terminal_projection_sources()
    -> Result<crate::b4_terminal_evidence_packet::B4TerminalEvidenceImportProjectionFixtureV1> {
        let (catalogue, artifacts) =
            crate::b4_terminal::synthetic_terminal_fixture_catalog_source()?;
        let parsed = Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(&catalogue)?;
        ensure!(
            parsed.fixtures.len() == crate::b4_terminal::B4_TERMINAL_FIXTURE_COUNT,
            "terminal projection catalogue does not contain the fixed fixture inventory"
        );
        let raw_seals =
            std::array::from_fn(|index| artifacts[&parsed.fixtures[index].raw_seal.path].clone());
        let receipt_oracles = std::array::from_fn(|index| {
            artifacts[&parsed.fixtures[index].receipt_oracle.path].clone()
        });

        let profile_manifest =
            include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin").to_vec();
        let profile_algorithm =
            include_bytes!("../../profiles/risc0-v3-succinct/algorithm.txt").to_vec();
        let profile_constants =
            include_bytes!("../../profiles/risc0-v3-succinct/constants.bin").to_vec();
        let manifest = crate::profile_manifest::StarkProfileManifestV1::decode(&profile_manifest)?;
        manifest.validate_initial_profile_target()?;
        let (guest_elf, program_id) = crate::test_support::valid_program_fixture();
        let reference_statement = crate::ErgoStatementV1::new(
            [0x11; 32],
            manifest.profile_id()?,
            program_id,
            [0x22; 32],
            b"E4 terminal materialization projection",
        )?
        .encode()?;
        let direct_raw_seal = synthetic_raw_producer_seal();
        let verifier_input = crate::b4_validator::synthesize_positive_verifier_input_v1(
            &profile_manifest,
            &profile_algorithm,
            &profile_constants,
            &guest_elf,
            &reference_statement,
            &direct_raw_seal,
        )?;

        let join_controls = manifest
            .terminal_controls()
            .iter()
            .filter(|control| {
                control.control_kind() == crate::constants::TERMINAL_CONTROL_KIND_JOIN
                    && control.parameter() == 0
            })
            .collect::<Vec<_>>();
        ensure!(
            join_controls.len() == 1,
            "initial profile does not contain exactly one Join/0 control"
        );
        let mut terminal_metadata_record = [0_u8; crate::constants::MANIFEST_CONTROL_ENTRY_BYTES];
        terminal_metadata_record[0] = crate::constants::TERMINAL_CONTROL_KIND_JOIN;
        terminal_metadata_record[1] = 0;
        terminal_metadata_record[2..].copy_from_slice(&join_controls[0].control_id());

        Ok(
            crate::b4_terminal_evidence_packet::B4TerminalEvidenceImportProjectionFixtureV1 {
                terminal_fixture_catalog_jcs: catalogue,
                raw_seals,
                receipt_oracles,
                profile_manifest: profile_manifest.clone(),
                reference_statement: reference_statement.clone(),
                terminal_metadata_record,
                terminal_metadata_contexts: [
                    verifier_input,
                    profile_manifest,
                    profile_algorithm,
                    profile_constants,
                    guest_elf,
                    reference_statement,
                    direct_raw_seal,
                ],
                terminal_evidence_packet_manifest: b"E4 projection-only packet manifest".to_vec(),
                terminal_evidence_campaign_receipt: b"E4 projection-only campaign receipt".to_vec(),
            },
        )
    }

    #[cfg(feature = "negative-materialization-set")]
    fn exact_terminal_projection_authority(
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV1,
    ) -> Result<B4TerminalEvidenceImportAuthorityV1> {
        B4TerminalEvidenceImportAuthorityV1::from_materialization_projection_fixture_for_tests(
            campaign,
            positive,
            exact_terminal_projection_sources()?,
        )
    }

    #[cfg(feature = "negative-materialization-set")]
    fn seed_exact_terminal_import_materializations(
        core: &mut CoreFixture,
        terminal: &B4TerminalEvidenceImportAuthorityV1,
    ) -> Result<Vec<usize>> {
        let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(&core.top_level.negative_plan)?;
        let planned = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .collect::<Vec<_>>();
        let producer = TerminalAwareProductionRowProducer { terminal };
        let indices = (11..=13)
            .chain(110..=112)
            .chain(131..=139)
            .collect::<Vec<_>>();
        for &index in &indices {
            ensure!(
                ProductionRowProducer
                    .reconstruct(index, planned[index], &core.top_level)?
                    .is_none(),
                "terminal projection test row was already owned by the historical producer"
            );
            let reconstructed = producer
                .reconstruct(index, planned[index], &core.top_level)?
                .with_context(|| {
                    format!("terminal projection did not reconstruct exact row {index}")
                })?;
            core.top_level.expanded_registry.negative_cases[index] =
                reconstructed.derived_registry_row.clone();
            core.external[index] = owned_c1_execution(index, planned[index], &reconstructed);
            core.reconstructed[index] = reconstructed;
        }
        Ok(indices)
    }

    #[cfg(feature = "negative-materialization-set")]
    fn seed_exact_descriptor_rooted_strong_inference_materializations(
        core: &mut CoreFixture,
        terminal: &B4TerminalEvidenceImportAuthorityV1,
        read_set: &B4NegativeAncestryPublicationReadSetV1,
    ) -> Result<Vec<usize>> {
        let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(&core.top_level.negative_plan)?;
        let planned = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .collect::<Vec<_>>();
        let terminal_producer = TerminalAwareProductionRowProducer { terminal };
        let producer = DescriptorRootedStrongInferenceRowProducer { terminal, read_set };
        let indices = (140..=145).chain(147..=155).collect::<Vec<_>>();
        for &index in &indices {
            ensure!(
                terminal_producer
                    .reconstruct(index, planned[index], &core.top_level)?
                    .is_none(),
                "strong-inference test row was already owned by the terminal-aware producer"
            );
            let reconstructed = producer
                .reconstruct(index, planned[index], &core.top_level)
                .with_context(|| {
                    format!(
                        "strong-inference dispatcher failed at row {index} ({})",
                        planned[index].execution_id
                    )
                })?
                .with_context(|| {
                    format!("strong-inference dispatcher did not reconstruct exact row {index}")
                })?;
            core.top_level.expanded_registry.negative_cases[index] =
                reconstructed.derived_registry_row.clone();
            core.external[index] = owned_c1_execution(index, planned[index], &reconstructed);
            core.reconstructed[index] = reconstructed;
        }
        Ok(indices)
    }

    #[cfg(feature = "negative-materialization-set")]
    fn synthetic_crypto_authority(
        top_level: &B4AuthenticatedMaterializationTopLevelV1,
    ) -> Result<B4DirectSealCheckpointMutationAuthorityV1> {
        let raw_seal = top_level
            .positive_exports
            .iter()
            .find(|export| export.case_index == 0)
            .context("synthetic crypto test fixture lacks case zero")?
            .raw_seal
            .clone();
        crate::b4_c2_crypto::synthetic_crypto_authority_for_tests(
            raw_seal,
            b"authenticated-profile-manifest-context".to_vec(),
            b"authenticated-receipt-oracle-context".to_vec(),
        )
    }

    fn empty_paths() -> B4PhysicalPathClosureV1 {
        B4PhysicalPathClosureV1 {
            paths: BTreeSet::new(),
            sha256_by_path: BTreeMap::new(),
            role_by_path: BTreeMap::new(),
            #[cfg(feature = "negative-materialization-set")]
            publication_paths: BTreeSet::new(),
        }
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn fixed_prior_snapshot_has_a_digest_for_every_provenance_path() {
        let lineage = crate::b4_negative_ancestry_authority::test_support::
            fixed_negative_ancestry_lineage_test_support()
            .unwrap();
        let prior = B4MaterializationPriorAuthoritySnapshotV1::from_authorities(
            &lineage.prior.campaign_precommit_authority,
            &lineage.prior.positive_generation_authority,
        )
        .unwrap();
        assert!(
            prior
                .provenance_paths
                .iter()
                .eq(prior.provenance_sha256.keys())
        );
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn shared_post_authentication_core_remains_unavailable_at_exact_218() {
        // This is a shared-core unit seam with real prior/publication
        // attachments; it does not replay the public authenticate_top_level
        // constructor.
        let fixture = B4SharedPostAuthenticationCoreFixtureV1::exact().unwrap();
        let second_fixture = B4SharedPostAuthenticationCoreFixtureV1::exact().unwrap();
        assert_ne!(fixture.publication_root, second_fixture.publication_root);
        assert_eq!(
            fixture.core.top_level.source_artifacts,
            second_fixture.core.top_level.source_artifacts
        );
        assert_eq!(
            fixture.path_ledger.sha256_by_path,
            second_fixture.path_ledger.sha256_by_path
        );
        assert_eq!(
            fixture.path_ledger.role_by_path,
            second_fixture.path_ledger.role_by_path
        );
        assert_eq!(
            fixture.path_ledger.publication_paths,
            second_fixture.path_ledger.publication_paths
        );
        let (prior, handoff, mut paths) = fixture.authenticated_handoff().unwrap();
        let contexts = context_views(&fixture.core.external);
        let executions = execution_views(&fixture.core.external, &contexts);

        let error = close_authenticated_negative_ancestry_handoff(
            &prior,
            &fixture.lineage.ancestry,
            &fixture.publication_root,
            &handoff,
            &fixture.core.top_level,
            &executions,
            &mut paths,
            &ProductionRowProducer,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains(
                "closed negative materialization producers reconstructed only 218/254 executions"
            ),
            "{error:#}"
        );
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn terminal_projection_dispatcher_covers_exactly_233_rows_in_plan_order() {
        // This projection-only unit seam exercises producer coverage and
        // ordering. It does not authenticate a physical packet, executable
        // custody, or any STARK proof.
        let fixture = B4SharedPostAuthenticationCoreFixtureV1::exact().unwrap();
        let terminal = exact_terminal_projection_authority(
            &fixture.lineage.prior.campaign_precommit_authority,
            &fixture.lineage.prior.positive_generation_authority,
        )
        .unwrap();
        let plan =
            Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.core.top_level.negative_plan)
                .unwrap();
        let planned = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .collect::<Vec<_>>();
        let producer = TerminalAwareProductionRowProducer {
            terminal: &terminal,
        };
        let mut covered = Vec::new();
        for (index, execution) in planned.iter().enumerate() {
            if producer
                .reconstruct(index, execution, &fixture.core.top_level)
                .unwrap()
                .is_some()
            {
                covered.push(index);
            }
        }
        let expected = (0..=107)
            .chain(109..=139)
            .chain(160..=253)
            .collect::<Vec<_>>();
        assert_eq!(covered, expected);
        assert_eq!(covered.len(), 233);
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn descriptor_rooted_strong_inference_dispatcher_covers_exactly_248_rows() {
        // This descriptor-rooted unit seam consumes the retained authenticated
        // ancestry read set. It does not authenticate a physical terminal
        // packet, executable custody, or any STARK proof.
        let fixture = B4SharedPostAuthenticationCoreFixtureV1::exact().unwrap();
        let terminal = exact_terminal_projection_authority(
            &fixture.lineage.prior.campaign_precommit_authority,
            &fixture.lineage.prior.positive_generation_authority,
        )
        .unwrap();
        let (_, handoff, _) = fixture.authenticated_handoff().unwrap();
        let plan =
            Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.core.top_level.negative_plan)
                .unwrap();
        let planned = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .collect::<Vec<_>>();
        let producer = DescriptorRootedStrongInferenceRowProducer {
            terminal: &terminal,
            read_set: &handoff.read_set,
        };
        let mut covered = Vec::new();
        for (index, execution) in planned.iter().enumerate() {
            if producer
                .reconstruct(index, execution, &fixture.core.top_level)
                .unwrap()
                .is_some()
            {
                covered.push(index);
            }
        }
        let expected = (0..=107)
            .chain(109..=145)
            .chain(147..=155)
            .chain(160..=253)
            .collect::<Vec<_>>();
        assert_eq!(covered, expected);
        assert_eq!(covered.len(), 248);
        assert_eq!(
            (0..B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT)
                .filter(|index| !covered.contains(index))
                .collect::<Vec<_>>(),
            vec![108, 146, 156, 157, 158, 159]
        );
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn descriptor_rooted_producer_inventory_accounts_for_exactly_250_rows() {
        // The retained alternate-root KAT and the established 248-row fixture
        // intentionally authenticate different statements. Prove the concrete
        // 248 set, prove that cross-statement authority is rejected, and then
        // combine it only with the alternate producer's closed two-row table.
        let strong_fixture = B4SharedPostAuthenticationCoreFixtureV1::exact().unwrap();
        let terminal = exact_terminal_projection_authority(
            &strong_fixture.lineage.prior.campaign_precommit_authority,
            &strong_fixture.lineage.prior.positive_generation_authority,
        )
        .unwrap();
        let (_, strong_handoff, _) = strong_fixture.authenticated_handoff().unwrap();
        let strong_plan = Eip0045B4NegativePlanV1::from_canonical_jcs(
            &strong_fixture.core.top_level.negative_plan,
        )
        .unwrap();
        let strong_planned = strong_plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .collect::<Vec<_>>();
        let strong_producer = DescriptorRootedStrongInferenceRowProducer {
            terminal: &terminal,
            read_set: &strong_handoff.read_set,
        };
        let mut covered = Vec::new();
        for (index, execution) in strong_planned.iter().enumerate() {
            if strong_producer
                .reconstruct(index, execution, &strong_fixture.core.top_level)
                .unwrap()
                .is_some()
            {
                covered.push(index);
            }
        }
        assert_eq!(covered.len(), 248);

        let alternate =
            crate::b4_alternate_root_authority::authenticate_retained_alternate_root_kat().unwrap();
        let error = crate::b4_c2_alternate_root::reconstruct_alternate_root_execution(
            108,
            strong_planned[108],
            &strong_fixture.core.top_level,
            &alternate,
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "alternate-root authority statement differs from the authenticated materialization statement"
        );

        let alternate_rows =
            crate::b4_c2_alternate_root::alternate_root_execution_indices().to_vec();
        assert_eq!(alternate_rows, [108, 146]);
        assert!(alternate_rows.iter().all(|row| !covered.contains(row)));
        covered.extend(alternate_rows);
        covered.sort_unstable();
        let expected = (0..=155).chain(160..=253).collect::<Vec<_>>();
        assert_eq!(covered, expected);
        assert_eq!(covered.len(), 250);
        assert_eq!(
            (0..B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT)
                .filter(|index| !covered.contains(index))
                .collect::<Vec<_>>(),
            vec![156, 157, 158, 159]
        );
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn direct_seal_checkpoint_dispatcher_covers_exactly_rows_156_through_159() {
        let fixture = B4SharedPostAuthenticationCoreFixtureV1::exact().unwrap();
        let authority = synthetic_crypto_authority(&fixture.core.top_level).unwrap();
        let plan =
            Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.core.top_level.negative_plan)
                .unwrap();
        let planned = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .collect::<Vec<_>>();
        let mut covered = Vec::new();
        for (index, execution) in planned.iter().enumerate() {
            if crate::b4_c2_crypto::reconstruct_crypto_execution(
                index,
                execution,
                &fixture.core.top_level,
                &authority,
            )
            .unwrap()
            .is_some()
            {
                covered.push(index);
            }
        }
        assert_eq!(covered, [156, 157, 158, 159]);
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn descriptor_rooted_e7_inventory_accounts_for_exactly_254_rows() {
        let fixture = B4SharedPostAuthenticationCoreFixtureV1::exact().unwrap();
        let terminal = exact_terminal_projection_authority(
            &fixture.lineage.prior.campaign_precommit_authority,
            &fixture.lineage.prior.positive_generation_authority,
        )
        .unwrap();
        let (_, handoff, _) = fixture.authenticated_handoff().unwrap();
        let plan =
            Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.core.top_level.negative_plan)
                .unwrap();
        let planned = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .collect::<Vec<_>>();
        let strong = DescriptorRootedStrongInferenceRowProducer {
            terminal: &terminal,
            read_set: &handoff.read_set,
        };
        let mut covered = Vec::new();
        for (index, execution) in planned.iter().enumerate() {
            if strong
                .reconstruct(index, execution, &fixture.core.top_level)
                .unwrap()
                .is_some()
            {
                covered.push(index);
            }
        }
        assert_eq!(covered.len(), 248);

        let alternate_rows =
            crate::b4_c2_alternate_root::alternate_root_execution_indices().to_vec();
        assert!(alternate_rows.iter().all(|row| !covered.contains(row)));
        covered.extend(alternate_rows);

        let crypto = synthetic_crypto_authority(&fixture.core.top_level).unwrap();
        let mut crypto_rows = Vec::new();
        for index in 156..=159 {
            let reconstructed = crate::b4_c2_crypto::reconstruct_crypto_execution(
                index,
                planned[index],
                &fixture.core.top_level,
                &crypto,
            )
            .unwrap();
            assert!(reconstructed.is_some());
            crypto_rows.push(index);
        }
        assert!(crypto_rows.iter().all(|row| !covered.contains(row)));
        covered.extend(crypto_rows);
        covered.sort_unstable();
        assert_eq!(
            covered,
            (0..B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT).collect::<Vec<_>>()
        );
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn descriptor_rooted_row141_rejects_a_coordinated_external_subject_rewrite() {
        let fixture = B4SharedPostAuthenticationCoreFixtureV1::exact().unwrap();
        let terminal = exact_terminal_projection_authority(
            &fixture.lineage.prior.campaign_precommit_authority,
            &fixture.lineage.prior.positive_generation_authority,
        )
        .unwrap();
        let (_, handoff, _) = fixture.authenticated_handoff().unwrap();
        let plan =
            Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.core.top_level.negative_plan)
                .unwrap();
        let planned = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .collect::<Vec<_>>();
        let producer = DescriptorRootedStrongInferenceRowProducer {
            terminal: &terminal,
            read_set: &handoff.read_set,
        };
        let canonical = producer
            .reconstruct(141, planned[141], &fixture.core.top_level)
            .unwrap()
            .unwrap();
        let mut rewritten = owned_c1_execution(141, planned[141], &canonical);
        rewritten.subject[0] ^= 0x01;
        (
            rewritten.materialization_identity_jcs,
            rewritten.negative_input_jcs,
        ) = execution_documents(
            planned[141],
            &canonical.derived_registry_row,
            &fixture.core.top_level.negative_plan,
            &rewritten.base,
            &rewritten.subject,
            &rewritten.contexts,
        );
        let rewritten_contexts = rewritten
            .contexts
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        validate_execution_bytes(
            141,
            planned[141],
            &fixture.core.top_level.negative_plan,
            Some(&canonical.derived_registry_row),
            &rewritten.base,
            &rewritten.materialization_identity_jcs,
            &rewritten.negative_input_jcs,
            &rewritten.subject,
            &rewritten_contexts,
        )
        .unwrap();

        let external = [rewritten];
        let contexts = context_views(&external);
        let supplied = execution_views(&external, &contexts);
        let error =
            ensure_reconstruction_matches_external(141, &canonical, &supplied[0]).unwrap_err();
        assert!(
            format!("{error:#}").contains("closed producer reconstruction"),
            "{error:#}"
        );
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn retained_row141_read_set_is_stable_but_fresh_publication_auth_rejects_mutation() {
        let fixture = B4SharedPostAuthenticationCoreFixtureV1::exact().unwrap();
        let terminal = exact_terminal_projection_authority(
            &fixture.lineage.prior.campaign_precommit_authority,
            &fixture.lineage.prior.positive_generation_authority,
        )
        .unwrap();
        let (_, handoff, _) = fixture.authenticated_handoff().unwrap();
        let plan =
            Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.core.top_level.negative_plan)
                .unwrap();
        let planned = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .collect::<Vec<_>>();
        let producer = DescriptorRootedStrongInferenceRowProducer {
            terminal: &terminal,
            read_set: &handoff.read_set,
        };
        let before = producer
            .reconstruct(141, planned[141], &fixture.core.top_level)
            .unwrap()
            .unwrap();

        let compiled_layout =
            crate::b4_negative_ancestry_witness::compiled_negative_ancestry_witness_layout()
                .unwrap();
        let witness_slot = compiled_layout
            .iter()
            .position(|slot| slot.expanded_row == 141)
            .unwrap();
        let relative_path = compiled_layout[witness_slot].raw_seal_path.clone();
        assert_eq!(
            handoff
                .read_set
                .ordered_files()
                .nth(2 + witness_slot * 2)
                .unwrap()
                .0,
            relative_path
        );
        let published_path =
            relative_path
                .split('/')
                .fold(fixture.publication_root.clone(), |mut path, segment| {
                    path.push(segment);
                    path
                });
        std::fs::write(&published_path, b"post-handoff-row141-mutation").unwrap();

        let after = producer
            .reconstruct(141, planned[141], &fixture.core.top_level)
            .unwrap()
            .unwrap();
        assert_eq!(after.derived_registry_row, before.derived_registry_row);
        assert_eq!(after.base, before.base);
        assert_eq!(
            after.materialization_identity_jcs,
            before.materialization_identity_jcs
        );
        assert_eq!(after.negative_input_jcs, before.negative_input_jcs);
        assert_eq!(after.subject, before.subject);
        assert_eq!(after.contexts, before.contexts);

        let Err(error) = B4AuthenticatedNegativeAncestryHandoffV1::from_publication(
            &fixture.publication_root,
            &fixture.lineage.ancestry,
        ) else {
            panic!("fresh publication authentication accepted mutated row-141 bytes");
        };
        assert!(
            format!("{error:#}").contains("invalid published file"),
            "{error:#}"
        );
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn shared_core_with_terminal_projection_remains_unavailable_at_exact_233() {
        // This projection-only unit seam reaches the real shared closeout
        // counter. It cannot authenticate an imported packet or mint the final
        // authority because rows 108 and 140..=159 remain unavailable.
        let mut fixture = B4SharedPostAuthenticationCoreFixtureV1::exact().unwrap();
        let terminal = exact_terminal_projection_authority(
            &fixture.lineage.prior.campaign_precommit_authority,
            &fixture.lineage.prior.positive_generation_authority,
        )
        .unwrap();
        terminal
            .verify_authority_bindings(
                &fixture.lineage.prior.campaign_precommit_authority,
                &fixture.lineage.prior.positive_generation_authority,
            )
            .unwrap();
        assert_eq!(
            seed_exact_terminal_import_materializations(&mut fixture.core, &terminal).unwrap(),
            (11..=13)
                .chain(110..=112)
                .chain(131..=139)
                .collect::<Vec<_>>()
        );

        let (prior, handoff, mut paths) = fixture.authenticated_handoff().unwrap();
        let contexts = context_views(&fixture.core.external);
        let executions = execution_views(&fixture.core.external, &contexts);
        let error = close_authenticated_negative_ancestry_handoff_core(
            &prior,
            &fixture.lineage.ancestry,
            &handoff,
            &fixture.core.top_level,
            &executions,
            &mut paths,
            &TerminalAwareProductionRowProducer {
                terminal: &terminal,
            },
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains(
                "closed negative materialization producers reconstructed only 233/254 executions"
            ),
            "{error:#}"
        );
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn shared_core_with_descriptor_rooted_strong_inference_remains_unavailable_at_exact_248() {
        // This descriptor-rooted unit seam reaches the real shared closeout
        // counter. It cannot mint the final authority because rows 108, 146,
        // and 156..=159 remain unavailable.
        let mut fixture = B4SharedPostAuthenticationCoreFixtureV1::exact().unwrap();
        let terminal = exact_terminal_projection_authority(
            &fixture.lineage.prior.campaign_precommit_authority,
            &fixture.lineage.prior.positive_generation_authority,
        )
        .unwrap();
        terminal
            .verify_authority_bindings(
                &fixture.lineage.prior.campaign_precommit_authority,
                &fixture.lineage.prior.positive_generation_authority,
            )
            .unwrap();
        let (prior, handoff, mut paths) = fixture.authenticated_handoff().unwrap();
        assert_eq!(
            seed_exact_terminal_import_materializations(&mut fixture.core, &terminal).unwrap(),
            (11..=13)
                .chain(110..=112)
                .chain(131..=139)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            seed_exact_descriptor_rooted_strong_inference_materializations(
                &mut fixture.core,
                &terminal,
                &handoff.read_set,
            )
            .unwrap(),
            (140..=145).chain(147..=155).collect::<Vec<_>>()
        );
        let first_unavailable_execution_id =
            Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.core.top_level.negative_plan)
                .unwrap()
                .groups
                .iter()
                .flat_map(|group| group.executions.iter())
                .nth(108)
                .unwrap()
                .execution_id
                .clone();

        let contexts = context_views(&fixture.core.external);
        let executions = execution_views(&fixture.core.external, &contexts);
        let error = close_authenticated_negative_ancestry_handoff_core(
            &prior,
            &fixture.lineage.ancestry,
            &handoff,
            &fixture.core.top_level,
            &executions,
            &mut paths,
            &DescriptorRootedStrongInferenceRowProducer {
                terminal: &terminal,
                read_set: &handoff.read_set,
            },
        )
        .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains(
                "closed negative materialization producers reconstructed only 248/254 executions"
            ),
            "{rendered}"
        );
        assert!(
            rendered.contains(&format!(
                "first unavailable: {first_unavailable_execution_id}"
            )),
            "{rendered}"
        );
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn terminal_projection_fixture_rejects_record_and_context_drift() {
        let support = crate::b4_negative_ancestry_authority::test_support::
            fixed_negative_ancestry_lineage_test_support()
            .unwrap();
        let campaign = &support.prior.campaign_precommit_authority;
        let positive = &support.prior.positive_generation_authority;
        let mut wrong_record = exact_terminal_projection_sources().unwrap();
        wrong_record.terminal_metadata_record[2] ^= 1;
        let Err(error) =
            B4TerminalEvidenceImportAuthorityV1::from_materialization_projection_fixture_for_tests(
                campaign,
                positive,
                wrong_record,
            )
        else {
            panic!("wrong terminal record unexpectedly authenticated");
        };
        assert!(
            format!("{error:#}").contains("exact manifest-owned Join/0 record"),
            "{error:#}"
        );

        let mut wrong_manifest_context = exact_terminal_projection_sources().unwrap();
        wrong_manifest_context.terminal_metadata_contexts[1][0] ^= 1;
        let Err(error) =
            B4TerminalEvidenceImportAuthorityV1::from_materialization_projection_fixture_for_tests(
                campaign,
                positive,
                wrong_manifest_context,
            )
        else {
            panic!("separated manifest context unexpectedly authenticated");
        };
        assert!(
            format!("{error:#}").contains("separates shared case-8 packet sources"),
            "{error:#}"
        );

        let mut wrong_verifier_input = exact_terminal_projection_sources().unwrap();
        wrong_verifier_input.terminal_metadata_contexts[0][0] ^= 1;
        let Err(error) =
            B4TerminalEvidenceImportAuthorityV1::from_materialization_projection_fixture_for_tests(
                campaign,
                positive,
                wrong_verifier_input,
            )
        else {
            panic!("wrong verifier input unexpectedly authenticated");
        };
        assert!(
            format!("{error:#}").contains("case-8 verifier input is not exact"),
            "{error:#}"
        );

        let mut wrong_statement_context = exact_terminal_projection_sources().unwrap();
        wrong_statement_context.terminal_metadata_contexts[5][0] ^= 1;
        let Err(error) =
            B4TerminalEvidenceImportAuthorityV1::from_materialization_projection_fixture_for_tests(
                campaign,
                positive,
                wrong_statement_context,
            )
        else {
            panic!("separated statement context unexpectedly authenticated");
        };
        assert!(
            format!("{error:#}").contains("separates shared case-8 packet sources"),
            "{error:#}"
        );
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn ancestry_provenance_partition_applies_publication_prior_profile_case9_precedence() {
        let fixture = B4SharedPostAuthenticationCoreFixtureV1::exact().unwrap();
        let (prior, handoff, paths) = fixture.authenticated_handoff().unwrap();
        let partition = close_negative_ancestry_provenance_partition(
            &prior,
            &fixture.lineage.ancestry,
            &handoff,
            &fixture.core.top_level,
            &paths,
        )
        .unwrap();

        assert_eq!(partition.publication_payloads.len(), 23);
        assert!(
            !partition
                .publication_payloads
                .contains(B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_PATH)
        );
        let expected_prior = prior
            .provenance_paths
            .difference(&partition.publication_payloads)
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(partition.prior_authorities, expected_prior);
        let mut expected_profile_case9 = fixture
            .core
            .top_level
            .negative_ancestry_provenance_evidence
            .profile_package_paths
            .clone();
        expected_profile_case9.extend(
            fixture
                .core
                .top_level
                .negative_ancestry_provenance_evidence
                .case9_paths
                .iter()
                .cloned(),
        );
        expected_profile_case9 = expected_profile_case9
            .difference(&partition.publication_payloads)
            .cloned()
            .collect::<BTreeSet<_>>()
            .difference(&partition.prior_authorities)
            .cloned()
            .collect();
        assert_eq!(partition.profile_case9, expected_profile_case9);
        assert!(
            partition
                .publication_payloads
                .is_disjoint(&partition.prior_authorities)
                && partition
                    .publication_payloads
                    .is_disjoint(&partition.profile_case9)
                && partition
                    .prior_authorities
                    .is_disjoint(&partition.profile_case9)
        );
        let mut union = partition.publication_payloads.clone();
        union.extend(partition.prior_authorities.iter().cloned());
        union.extend(partition.profile_case9.iter().cloned());
        assert_eq!(union, *fixture.lineage.ancestry.provenance_paths());
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn ancestry_provenance_partition_rejects_unclassified_path_and_disagreeing_overlap() {
        let fixture = B4SharedPostAuthenticationCoreFixtureV1::exact().unwrap();
        let (prior, handoff, mut paths) = fixture.authenticated_handoff().unwrap();
        let mut unclassified = fixture.lineage.ancestry.provenance_paths().clone();
        unclassified.insert("unclassified/safe-source.bin".to_owned());
        let error = close_negative_ancestry_provenance_partition_against(
            &unclassified,
            &prior,
            &handoff,
            &fixture.core.top_level,
            &paths,
        );
        assert!(
            format!("{:#}", error.unwrap_err())
                .contains("negative-ancestry provenance ownership does not exactly close")
        );

        let publication_path = handoff
            .read_set
            .ordered_files()
            .nth(1)
            .unwrap()
            .0
            .to_owned();
        paths.sha256_by_path.insert(
            publication_path,
            sha256_hex(b"disagreeing publication bytes"),
        );
        let error = close_negative_ancestry_provenance_partition_against(
            fixture.lineage.ancestry.provenance_paths(),
            &prior,
            &handoff,
            &fixture.core.top_level,
            &paths,
        );
        assert!(
            format!("{:#}", error.unwrap_err())
                .contains("digest disagrees with authenticated evidence")
        );
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn publication_payload_cannot_be_reused_as_external_base_or_output() {
        let fixture = B4SharedPostAuthenticationCoreFixtureV1::exact().unwrap();
        let (publication_path, publication_bytes) = fixture
            .authenticated_handoff()
            .unwrap()
            .1
            .read_set
            .ordered_files()
            .nth(1)
            .map(|(path, bytes)| (path.to_owned(), bytes.to_vec()))
            .unwrap();

        let (prior, handoff, mut paths) = fixture.authenticated_handoff().unwrap();
        let mut external = fixture.core.external.clone();
        external[0].base_path.clone_from(&publication_path);
        external[0].base.clone_from(&publication_bytes);
        let contexts = context_views(&external);
        let executions = execution_views(&external, &contexts);
        let error = close_authenticated_negative_ancestry_handoff(
            &prior,
            &fixture.lineage.ancestry,
            &fixture.publication_root,
            &handoff,
            &fixture.core.top_level,
            &executions,
            &mut paths,
            &fixture.core.producer(),
        );
        assert!(
            format!("{:#}", error.unwrap_err()).contains(
                "materialization base cannot reuse an authenticated publication-owned path"
            )
        );

        let (prior, handoff, mut paths) = fixture.authenticated_handoff().unwrap();
        let mut external = fixture.core.external.clone();
        external[0]
            .materialization_identity_path
            .clone_from(&publication_path);
        external[0]
            .materialization_identity_jcs
            .clone_from(&publication_bytes);
        let contexts = context_views(&external);
        let executions = execution_views(&external, &contexts);
        let error = close_authenticated_negative_ancestry_handoff(
            &prior,
            &fixture.lineage.ancestry,
            &fixture.publication_root,
            &handoff,
            &fixture.core.top_level,
            &executions,
            &mut paths,
            &fixture.core.producer(),
        );
        assert!(format!("{:#}", error.unwrap_err()).contains(
            "materialization identity cannot reuse an authenticated publication-owned path"
        ));
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn two_exact_publication_roots_produce_byte_identical_complete_materialization_sets() {
        let fixture = B4SharedPostAuthenticationCoreFixtureV1::exact().unwrap();
        let second_guard = crate::test_support::tempdir().unwrap();
        let second_root = second_guard.path().join("published");
        crate::b4_negative_ancestry_publication::test_support::write_exact_test_publication(
            &second_root,
            &fixture.lineage.ancestry,
        )
        .unwrap();
        let contexts = context_views(&fixture.core.external);
        let executions = execution_views(&fixture.core.external, &contexts);

        let (first_prior, first_handoff, mut first_paths) =
            fixture.authenticated_handoff().unwrap();
        let first = close_authenticated_negative_ancestry_handoff(
            &first_prior,
            &fixture.lineage.ancestry,
            &fixture.publication_root,
            &first_handoff,
            &fixture.core.top_level,
            &executions,
            &mut first_paths,
            &fixture.core.producer(),
        )
        .unwrap();
        let (second_prior, second_handoff, mut second_paths) =
            fixture.authenticated_handoff_at(&second_root).unwrap();
        let second = close_authenticated_negative_ancestry_handoff(
            &second_prior,
            &fixture.lineage.ancestry,
            &second_root,
            &second_handoff,
            &fixture.core.top_level,
            &executions,
            &mut second_paths,
            &fixture.core.producer(),
        )
        .unwrap();
        assert_eq!(
            first.canonical_materialization_set_jcs(),
            second.canonical_materialization_set_jcs()
        );
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn mutation_after_initial_read_set_before_final_revalidation_returns_no_authority() {
        let fixture = B4SharedPostAuthenticationCoreFixtureV1::exact().unwrap();
        let mutation_guard = crate::test_support::tempdir().unwrap();
        let mutation_root = mutation_guard.path().join("published");
        crate::b4_negative_ancestry_publication::test_support::write_exact_test_publication(
            &mutation_root,
            &fixture.lineage.ancestry,
        )
        .unwrap();
        let (prior, handoff, mut paths) = fixture.authenticated_handoff_at(&mutation_root).unwrap();
        let relative_path = handoff.read_set.ordered_files().nth(1).unwrap().0;
        let contexts = context_views(&fixture.core.external);
        let executions = execution_views(&fixture.core.external, &contexts);
        let producer = MutatePublicationAtFinalRowProducer {
            inner: fixture.core.producer(),
            root: &mutation_root,
            relative_path,
        };

        let error = close_authenticated_negative_ancestry_handoff(
            &prior,
            &fixture.lineage.ancestry,
            &mutation_root,
            &handoff,
            &fixture.core.top_level,
            &executions,
            &mut paths,
            &producer,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("invalid published file"),
            "{error:#}"
        );
    }

    #[test]
    fn independently_reconstructed_254_rows_create_one_opaque_byte_exact_authority() {
        let fixture = CoreFixture::exact();
        let contexts = context_views(&fixture.external);
        let executions = execution_views(&fixture.external, &contexts);
        let mut paths = empty_paths();
        let authority = assemble_materialization_authority(
            &fixture.top_level,
            &fixture.catalog_identity,
            &executions,
            &mut paths,
            &fixture.producer(),
        )
        .unwrap();
        assert_eq!(
            authority.materialization_set().executions.len(),
            B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT
        );
        assert_eq!(
            authority.executions.len(),
            B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT
        );
        let first = authority.retained_execution(0).unwrap();
        assert_eq!(first.execution_id, fixture.external[0].execution_id);
        assert_eq!(first.subject, fixture.external[0].subject);
        assert_eq!(first.contexts, fixture.external[0].contexts);
        authority
            .verify_candidate_jcs(authority.canonical_materialization_set_jcs())
            .unwrap();

        let mut rewritten = authority.materialization_set().clone();
        rewritten.expanded_registry.sha256 = "f".repeat(64);
        let rewritten_jcs = rewritten.to_canonical_jcs().unwrap();
        assert!(authority.verify_candidate_jcs(&rewritten_jcs).is_err());
    }

    #[test]
    fn production_row_producer_closes_exactly_the_44_c1_rows() {
        let fixture = CoreFixture::with_exact_c1_top_level();
        let plan =
            Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.top_level.negative_plan).unwrap();
        let planned = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .collect::<Vec<_>>();
        let producer = C1ProductionRowProducer;
        let closed = planned
            .iter()
            .enumerate()
            .filter_map(|(index, execution)| {
                producer
                    .reconstruct(index, execution, &fixture.top_level)
                    .unwrap()
            })
            .count();

        assert_eq!(closed, 44);
    }

    #[test]
    fn c2_profile_public_entry_closes_exactly_fifty_rows_with_final_documents() {
        let fixture = CoreFixture::with_exact_c2_profile_top_level();
        let plan =
            Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.top_level.negative_plan).unwrap();
        let planned = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .collect::<Vec<_>>();
        let mut closed = Vec::new();
        for (index, execution) in planned.iter().enumerate() {
            let reconstructed = crate::b4_c2_profile::reconstruct_profile_execution(
                index,
                execution,
                &fixture.top_level,
            )
            .unwrap();
            if let Some(reconstructed) = reconstructed {
                Eip0045B4MaterializationIdentityV1::from_canonical_jcs(
                    &reconstructed.materialization_identity_jcs,
                )
                .unwrap();
                Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(
                    &reconstructed.negative_input_jcs,
                )
                .unwrap();
                assert_eq!(
                    reconstructed.derived_registry_row.execution_id,
                    execution.execution_id
                );
                closed.push(index);
            }
        }
        assert_eq!(closed, (160..210).collect::<Vec<_>>());
    }

    #[test]
    fn c2_profile_rows_integrate_and_registry_recipe_drift_fails_closed() {
        let fixture = CoreFixture::with_exact_c2_profile_materializations();
        let contexts = context_views(&fixture.external);
        let executions = execution_views(&fixture.external, &contexts);
        let authority = assemble_materialization_authority(
            &fixture.top_level,
            &fixture.catalog_identity,
            &executions,
            &mut empty_paths(),
            &fixture.c2_profile_then_test_producer(),
        )
        .unwrap();
        assert_eq!(authority.executions.len(), 254);

        let mut drifted = fixture;
        drifted.top_level.expanded_registry.negative_cases[160].materialization =
            B4NegativeMaterialization::FixtureSelection {
                fixture_id: drifted.top_level.expanded_registry.negative_cases[160]
                    .base_selector_id
                    .clone(),
            };
        let contexts = context_views(&drifted.external);
        let executions = execution_views(&drifted.external, &contexts);
        let error = assemble_materialization_authority(
            &drifted.top_level,
            &drifted.catalog_identity,
            &executions,
            &mut empty_paths(),
            &drifted.c2_profile_then_test_producer(),
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("producer-derived registry row"),
            "{error:#}"
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the integration test keeps all twenty-two index, framing, base, context, and drift assertions in one auditable production-path checklist"
    )]
    fn c2_opcode_sequence_production_entry_authenticates_and_closes_exactly_twenty_two_rows() {
        let fixture = CoreFixture::with_exact_c2_opcode_top_level();
        let plan =
            Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.top_level.negative_plan).unwrap();
        let planned = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .collect::<Vec<_>>();
        let exact_indices = [
            7, 8, 9, 10, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 30, 31, 32,
        ];
        let opcode_bounds = [
            crate::b4_subject_envelope::B4SubjectPartBounds::new(
                2 + 3 * 4,
                2 + 5 * 4 + crate::constants::PROOF_BYTES + 4,
            ),
            crate::b4_subject_envelope::B4SubjectPartBounds::new(
                0,
                crate::constants::MAX_APPLICATION_PAYLOAD_BYTES + 1,
            ),
            crate::b4_subject_envelope::B4SubjectPartBounds::new(31, 33),
            crate::b4_subject_envelope::B4SubjectPartBounds::new(31, 33),
        ];
        let catalog_bounds = [crate::b4_subject_envelope::B4SubjectPartBounds::new(
            1,
            128 * 1024,
        )];
        let manifest = include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin").as_slice();
        let raw_seal = &fixture.top_level.positive_exports[0].raw_seal;
        let mut closed = Vec::new();
        let mut opcode_base_sha256 = None;

        for &index in &exact_indices {
            let reconstructed = ProductionRowProducer
                .reconstruct(index, planned[index], &fixture.top_level)
                .unwrap()
                .unwrap();
            assert_eq!(
                reconstructed.derived_registry_row.execution_id,
                planned[index].execution_id
            );
            assert_eq!(
                reconstructed.derived_registry_row.base_selector_id,
                planned[index].base_selector_id
            );
            assert_eq!(
                reconstructed.derived_registry_row.materialization_domain,
                planned[index].materialization_domain
            );
            assert!(matches!(
                reconstructed.derived_registry_row.materialization,
                B4NegativeMaterialization::Mutation { .. }
            ));
            let identity = Eip0045B4MaterializationIdentityV1::from_canonical_jcs(
                &reconstructed.materialization_identity_jcs,
            )
            .unwrap();
            let input = Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(
                &reconstructed.negative_input_jcs,
            )
            .unwrap();
            assert_eq!(identity.output_sha256, sha256_hex(&reconstructed.subject));
            assert_eq!(input.context.len(), reconstructed.contexts.len());

            if (14..=18).contains(&index) {
                assert!(reconstructed.contexts.is_empty());
                assert_eq!(reconstructed.base, fixture.top_level.subject_catalog_jcs);
                let decoded = crate::b4_subject_envelope::decode_subject_envelope(
                    &reconstructed.subject,
                    crate::b4_subject_envelope::B4SubjectEnvelopeContract::new(
                        crate::b4_subject_envelope::B4SubjectEnvelopeKind::SequenceCatalogBundle,
                        &catalog_bounds,
                    ),
                )
                .unwrap();
                let original =
                    crate::canonical::validate_canonical_json_source(&reconstructed.base).unwrap();
                let mutated =
                    crate::canonical::validate_canonical_json_source(decoded.parts()[0]).unwrap();
                let original_rows = original["subjects"].as_array().unwrap();
                let mutated_rows = mutated["subjects"].as_array().unwrap();
                let changed = original_rows
                    .iter()
                    .zip(mutated_rows)
                    .enumerate()
                    .filter_map(|(position, (before, after))| (before != after).then_some(position))
                    .collect::<Vec<_>>();
                assert_eq!(changed, vec![index - 14]);
            } else {
                assert_eq!(reconstructed.contexts, vec![manifest.to_vec()]);
                let decoded = crate::b4_subject_envelope::decode_subject_envelope(
                    &reconstructed.subject,
                    crate::b4_subject_envelope::B4SubjectEnvelopeContract::new(
                        crate::b4_subject_envelope::B4SubjectEnvelopeKind::OpcodeInputs,
                        &opcode_bounds,
                    ),
                )
                .unwrap();
                assert_eq!(decoded.parts().len(), 4);
                assert_eq!(
                    decoded.parts()[1].len(),
                    if index == 19 {
                        crate::constants::MAX_APPLICATION_PAYLOAD_BYTES + 1
                    } else {
                        crate::constants::MAX_APPLICATION_PAYLOAD_BYTES
                    }
                );
                assert_eq!(
                    decoded.parts()[2].len(),
                    match index {
                        9 => 31,
                        10 => 33,
                        _ => 32,
                    }
                );
                assert_eq!(
                    decoded.parts()[3].len(),
                    match index {
                        7 => 31,
                        8 => 33,
                        _ => 32,
                    }
                );
                if matches!(index, 20..=28 | 30..=32) {
                    assert_eq!(&reconstructed.base, raw_seal);
                } else {
                    let digest = sha256_hex(&reconstructed.base);
                    if let Some(expected) = &opcode_base_sha256 {
                        assert_eq!(&digest, expected);
                    } else {
                        opcode_base_sha256 = Some(digest);
                    }
                }
            }
            closed.push(index);
        }
        assert_eq!(closed, exact_indices);

        let mut drifted = fixture;
        drifted.top_level.positive_exports[0].raw_seal[0] ^= 1;
        let error = ProductionRowProducer
            .reconstruct(20, planned[20], &drifted.top_level)
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("raw seal differs"),
            "{error:#}"
        );
    }

    #[test]
    fn production_row_producer_closes_exactly_the_218_implemented_deterministic_rows() {
        let fixture = CoreFixture::with_exact_implemented_producer_top_level();
        let plan =
            Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.top_level.negative_plan).unwrap();
        let planned = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .collect::<Vec<_>>();
        let actual = planned
            .iter()
            .enumerate()
            .filter_map(|(index, execution)| {
                ProductionRowProducer
                    .reconstruct(index, execution, &fixture.top_level)
                    .unwrap()
                    .map(|closed| {
                        Eip0045B4MaterializationIdentityV1::from_canonical_jcs(
                            &closed.materialization_identity_jcs,
                        )
                        .unwrap();
                        Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(
                            &closed.negative_input_jcs,
                        )
                        .unwrap();
                        index
                    })
            })
            .collect::<Vec<_>>();
        let expected = [
            (0..=10).collect::<Vec<_>>(),
            (14..=107).collect(),
            vec![109],
            (113..=130).collect(),
            (160..=209).collect(),
            (210..=253).collect(),
        ]
        .concat();

        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 218);
    }

    #[test]
    fn raw_rows_integrate_through_physical_external_comparison_and_retained_authority() {
        let fixture = CoreFixture::with_exact_raw_materializations();
        let contexts = context_views(&fixture.external);
        let executions = execution_views(&fixture.external, &contexts);
        let authority = assemble_materialization_authority(
            &fixture.top_level,
            &fixture.catalog_identity,
            &executions,
            &mut empty_paths(),
            &fixture.raw_then_test_producer(),
        )
        .unwrap();

        for index in (0..=6).chain([29]).chain(33..=71).chain([109]) {
            let retained = authority.retained_execution(index).unwrap();
            assert_eq!(retained.execution_id, fixture.external[index].execution_id);
            assert_eq!(retained.base, fixture.external[index].base);
            assert_eq!(retained.subject, fixture.external[index].subject);
            assert_eq!(retained.contexts, fixture.external[index].contexts);
        }
    }

    #[test]
    fn raw_physical_external_and_registry_drift_classes_fail_closed() {
        fn close_raw_row(fixture: &CoreFixture, index: usize) -> Result<()> {
            let plan =
                Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.top_level.negative_plan)?;
            let planned = plan
                .groups
                .iter()
                .flat_map(|group| group.executions.iter())
                .nth(index)
                .context("test raw index is outside the canonical plan")?;
            let contexts = context_views(&fixture.external);
            let executions = execution_views(&fixture.external, &contexts);
            let supplied = &executions[index];
            validate_external_execution(
                index,
                planned,
                &fixture.top_level.negative_plan,
                supplied,
                &mut empty_paths(),
            )?;
            let reconstructed = ProductionRowProducer
                .reconstruct(index, planned, &fixture.top_level)?
                .context("production dispatcher did not reconstruct the raw row")?;
            ensure!(
                reconstructed.derived_registry_row
                    == fixture.top_level.expanded_registry.negative_cases[index],
                "closed producer-derived registry row differs from the authenticated expanded registry at index {index}"
            );
            ensure_reconstruction_matches_external(index, &reconstructed, supplied)?;
            retain_authenticated_execution(
                index,
                planned,
                &fixture.top_level.negative_plan,
                reconstructed,
            )?;
            Ok(())
        }

        fn closure_error(fixture: &CoreFixture) -> String {
            format!("{:#}", close_raw_row(fixture, 0).unwrap_err())
        }

        let fixture = CoreFixture::with_exact_raw_materializations();

        let mut subject_drift = fixture.clone();
        subject_drift.external[0].subject[27] ^= 1;
        let error = closure_error(&subject_drift);
        assert!(error.contains("output"), "{error}");

        let mut context_drift = fixture.clone();
        context_drift.external[0].contexts[0][0] ^= 1;
        let error = closure_error(&context_drift);
        assert!(error.contains("context"), "{error}");

        let mut identity_drift = fixture.clone();
        let identity_last = identity_drift.external[0]
            .materialization_identity_jcs
            .len()
            - 1;
        identity_drift.external[0].materialization_identity_jcs[identity_last] ^= 1;
        let error = closure_error(&identity_drift);
        assert!(
            error.contains("materialization identity is not exact RFC 8785 JCS"),
            "{error}"
        );

        let mut input_drift = fixture.clone();
        let input_last = input_drift.external[0].negative_input_jcs.len() - 1;
        input_drift.external[0].negative_input_jcs[input_last] ^= 1;
        let error = closure_error(&input_drift);
        assert!(
            error.contains("negative verifier input is not exact RFC 8785 JCS"),
            "{error}"
        );

        let mut recipe_drift = fixture;
        recipe_drift.top_level.expanded_registry.negative_cases[0].materialization =
            B4NegativeMaterialization::FixtureSelection {
                fixture_id: recipe_drift.top_level.expanded_registry.negative_cases[0]
                    .base_selector_id
                    .clone(),
            };
        let recipe_jcs = canonical_materialization_recipe_jcs(
            &recipe_drift.top_level.expanded_registry.negative_cases[0].materialization,
        )
        .unwrap();
        let mut identity = Eip0045B4MaterializationIdentityV1::from_canonical_jcs(
            &recipe_drift.external[0].materialization_identity_jcs,
        )
        .unwrap();
        identity.materialization_recipe_byte_length = u64::try_from(recipe_jcs.len()).unwrap();
        identity.materialization_recipe_sha256 = sha256_hex(&recipe_jcs);
        recipe_drift.external[0].materialization_identity_jcs =
            identity.to_canonical_jcs().unwrap();
        let error = closure_error(&recipe_drift);
        assert!(error.contains("producer-derived registry row"), "{error}");
    }

    #[test]
    fn parser_rows_integrate_through_physical_external_comparison_and_retained_authority() {
        let fixture = CoreFixture::with_exact_parser_materializations();
        let contexts = context_views(&fixture.external);
        let executions = execution_views(&fixture.external, &contexts);
        let authority = assemble_materialization_authority(
            &fixture.top_level,
            &fixture.catalog_identity,
            &executions,
            &mut empty_paths(),
            &fixture.production_then_test_producer(),
        )
        .unwrap();

        for index in 72..=107 {
            let retained = authority.retained_execution(index).unwrap();
            assert_eq!(retained.execution_id, fixture.external[index].execution_id);
            assert_eq!(retained.subject, fixture.external[index].subject);
            assert_eq!(retained.contexts, fixture.external[index].contexts);
        }
    }

    #[test]
    fn parser_physical_external_and_registry_drift_classes_fail_closed() {
        fn close_parser_row(fixture: &CoreFixture, index: usize) -> Result<()> {
            let plan =
                Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.top_level.negative_plan)?;
            let planned = plan
                .groups
                .iter()
                .flat_map(|group| group.executions.iter())
                .nth(index)
                .context("test parser index is outside the canonical plan")?;
            let contexts = context_views(&fixture.external);
            let executions = execution_views(&fixture.external, &contexts);
            let supplied = &executions[index];
            validate_external_execution(
                index,
                planned,
                &fixture.top_level.negative_plan,
                supplied,
                &mut empty_paths(),
            )?;
            let reconstructed = ProductionRowProducer
                .reconstruct(index, planned, &fixture.top_level)?
                .context("production dispatcher did not reconstruct the parser row")?;
            ensure!(
                reconstructed.derived_registry_row
                    == fixture.top_level.expanded_registry.negative_cases[index],
                "closed producer-derived registry row differs from the authenticated expanded registry at index {index}"
            );
            ensure_reconstruction_matches_external(index, &reconstructed, supplied)?;
            retain_authenticated_execution(
                index,
                planned,
                &fixture.top_level.negative_plan,
                reconstructed,
            )?;
            Ok(())
        }

        fn closure_error(fixture: &CoreFixture) -> String {
            format!("{:#}", close_parser_row(fixture, 72).unwrap_err())
        }

        let fixture = CoreFixture::with_exact_parser_materializations();

        let mut subject_drift = fixture.clone();
        subject_drift.external[72].subject.push(0xa5);
        let error = closure_error(&subject_drift);
        assert!(error.contains("output"), "{error}");

        let mut context_drift = fixture.clone();
        context_drift.external[72].contexts[0][0] ^= 1;
        let error = closure_error(&context_drift);
        assert!(error.contains("context"), "{error}");

        let mut identity_drift = fixture.clone();
        let identity_last = identity_drift.external[72]
            .materialization_identity_jcs
            .len()
            - 1;
        identity_drift.external[72].materialization_identity_jcs[identity_last] ^= 1;
        let error = closure_error(&identity_drift);
        assert!(
            error.contains("materialization identity is not exact RFC 8785 JCS"),
            "{error}"
        );

        let mut input_drift = fixture.clone();
        let input_last = input_drift.external[72].negative_input_jcs.len() - 1;
        input_drift.external[72].negative_input_jcs[input_last] ^= 1;
        let error = closure_error(&input_drift);
        assert!(
            error.contains("negative verifier input is not exact RFC 8785 JCS"),
            "{error}"
        );

        let mut recipe_drift = fixture;
        recipe_drift.top_level.expanded_registry.negative_cases[72].materialization =
            B4NegativeMaterialization::FixtureSelection {
                fixture_id: recipe_drift.top_level.expanded_registry.negative_cases[72]
                    .base_selector_id
                    .clone(),
            };
        let recipe_jcs = canonical_materialization_recipe_jcs(
            &recipe_drift.top_level.expanded_registry.negative_cases[72].materialization,
        )
        .unwrap();
        let mut identity = Eip0045B4MaterializationIdentityV1::from_canonical_jcs(
            &recipe_drift.external[72].materialization_identity_jcs,
        )
        .unwrap();
        identity.materialization_recipe_byte_length = u64::try_from(recipe_jcs.len()).unwrap();
        identity.materialization_recipe_sha256 = sha256_hex(&recipe_jcs);
        recipe_drift.external[72].materialization_identity_jcs =
            identity.to_canonical_jcs().unwrap();
        let error = closure_error(&recipe_drift);
        assert!(error.contains("producer-derived registry row"), "{error}");
    }

    #[test]
    fn c1_coverage_remains_fail_closed_until_the_other_210_rows_exist() {
        let fixture = CoreFixture::with_exact_c1_materializations();
        let contexts = context_views(&fixture.external);
        let executions = execution_views(&fixture.external, &contexts);
        let error = assemble_materialization_authority(
            &fixture.top_level,
            &fixture.catalog_identity,
            &executions,
            &mut empty_paths(),
            &C1ProductionRowProducer,
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("44/254"), "{error:#}");
    }

    #[test]
    fn c1_rows_integrate_byte_exactly_with_independent_fallback_producers() {
        let fixture = CoreFixture::with_exact_c1_materializations();
        let contexts = context_views(&fixture.external);
        let executions = execution_views(&fixture.external, &contexts);
        let authority = assemble_materialization_authority(
            &fixture.top_level,
            &fixture.catalog_identity,
            &executions,
            &mut empty_paths(),
            &fixture.c1_then_test_producer(),
        )
        .unwrap();

        assert_eq!(authority.executions.len(), 254);
        for index in C1_TREE_FIRST_INDEX..C1_END_INDEX_EXCLUSIVE {
            assert_eq!(
                authority.retained_execution(index).unwrap().subject,
                fixture.external[index].subject,
                "C1 subject drift at index {index}"
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn c1_rows_freeze_exact_tree_and_registry_subject_grammars() {
        let fixture = CoreFixture::with_exact_c1_top_level();
        let plan =
            Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.top_level.negative_plan).unwrap();
        let planned = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .collect::<Vec<_>>();
        let producer = C1ProductionRowProducer;
        let mut tree_count = 0;
        let mut candidate_registry_count = 0;
        let mut negative_binding_index_count = 0;
        let mut candidate_registry_indices = Vec::new();
        let mut negative_binding_index_indices = Vec::new();

        for (index, execution) in planned.iter().enumerate() {
            let reconstructed = producer
                .reconstruct(index, execution, &fixture.top_level)
                .unwrap();
            if index < C1_TREE_FIRST_INDEX {
                assert!(reconstructed.is_none());
                continue;
            }
            let reconstructed = reconstructed.unwrap();
            let identity = Eip0045B4MaterializationIdentityV1::from_canonical_jcs(
                &reconstructed.materialization_identity_jcs,
            )
            .unwrap();
            assert_eq!(
                identity.output_byte_length,
                u64::try_from(reconstructed.subject.len()).unwrap()
            );
            assert_eq!(identity.output_sha256, sha256_hex(&reconstructed.subject));
            assert_eq!(
                identity.base_sha256,
                sha256_hex(&reconstructed.base),
                "{}",
                execution.execution_id
            );

            match execution.execution_surface {
                B4NegativeExecutionSurface::CorpusClosure => {
                    tree_count += 1;
                    assert!((C1_TREE_FIRST_INDEX..C1_REGISTRY_FIRST_INDEX).contains(&index));
                    let materialized = materialize_tree_probe(
                        &fixture.top_level.negative_plan,
                        &execution.execution_id,
                    )
                    .unwrap();
                    assert_eq!(reconstructed.subject, materialized.output_jcs);
                    Eip0045B4AbstractTreeV1::from_canonical_jcs(&reconstructed.subject).unwrap();
                }
                B4NegativeExecutionSurface::CandidateRegistry => {
                    candidate_registry_count += 1;
                    candidate_registry_indices.push(index);
                    let materialized = materialize_registry_probe(
                        &fixture.top_level.negative_plan,
                        &execution.execution_id,
                    )
                    .unwrap();
                    let decoded = crate::b4_subject_envelope::decode_subject_envelope(
                        &reconstructed.subject,
                        B4SubjectEnvelopeContract::new(
                            B4SubjectEnvelopeKind::CandidateRegistryBundle,
                            &C1_CANDIDATE_REGISTRY_PARTS,
                        ),
                    )
                    .unwrap();
                    assert_eq!(decoded.parts(), &[materialized.output.as_slice()]);
                }
                B4NegativeExecutionSurface::NegativeBindingIndex => {
                    negative_binding_index_count += 1;
                    negative_binding_index_indices.push(index);
                    let materialized = materialize_registry_probe(
                        &fixture.top_level.negative_plan,
                        &execution.execution_id,
                    )
                    .unwrap();
                    let decoded = crate::b4_subject_envelope::decode_subject_envelope(
                        &reconstructed.subject,
                        B4SubjectEnvelopeContract::new(
                            B4SubjectEnvelopeKind::NegativeBindingIndexBundle,
                            &C1_NEGATIVE_BINDING_INDEX_PARTS,
                        ),
                    )
                    .unwrap();
                    assert_eq!(
                        decoded.parts(),
                        &[
                            fixture.top_level.negative_plan.as_slice(),
                            materialized.output.as_slice()
                        ]
                    );
                }
                _ => panic!(
                    "C1 producer covered an unexpected surface at index {index}: {:?}",
                    execution.execution_surface
                ),
            }
            assert!(reconstructed.contexts.is_empty());
        }

        assert_eq!(tree_count, 21);
        assert_eq!(candidate_registry_count, 17);
        assert_eq!(negative_binding_index_count, 6);
        assert_eq!(
            candidate_registry_indices,
            (231..243).chain(244..249).collect::<Vec<_>>()
        );
        assert_eq!(
            negative_binding_index_indices,
            vec![243, 249, 250, 251, 252, 253]
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn c1_closed_reconstruction_rejects_wrong_kind_order_payload_and_identity() {
        let fixture = CoreFixture::with_exact_c1_top_level();
        let plan =
            Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.top_level.negative_plan).unwrap();
        let planned = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .collect::<Vec<_>>();
        let producer = C1ProductionRowProducer;

        let candidate_index = C1_REGISTRY_FIRST_INDEX;
        let candidate_execution = planned[candidate_index];
        let candidate = producer
            .reconstruct(candidate_index, candidate_execution, &fixture.top_level)
            .unwrap()
            .unwrap();

        let mut wrong_kind = candidate.subject.clone();
        wrong_kind[9] = B4SubjectEnvelopeKind::NegativeBindingIndexBundle as u8;
        assert_coordinated_c1_subject_rewrite_is_rejected(
            candidate_index,
            candidate_execution,
            &fixture.top_level.negative_plan,
            &candidate,
            wrong_kind,
        );

        let mut wrong_payload = candidate.subject.clone();
        *wrong_payload.last_mut().unwrap() ^= 1;
        assert_coordinated_c1_subject_rewrite_is_rejected(
            candidate_index,
            candidate_execution,
            &fixture.top_level.negative_plan,
            &candidate,
            wrong_payload,
        );

        let binding_index = C1_NEGATIVE_CASE_DUPLICATE_INDEX;
        let binding_execution = planned[binding_index];
        let binding = producer
            .reconstruct(binding_index, binding_execution, &fixture.top_level)
            .unwrap()
            .unwrap();
        let decoded = crate::b4_subject_envelope::decode_subject_envelope(
            &binding.subject,
            B4SubjectEnvelopeContract::new(
                B4SubjectEnvelopeKind::NegativeBindingIndexBundle,
                &C1_NEGATIVE_BINDING_INDEX_PARTS,
            ),
        )
        .unwrap();
        let wrong_order = raw_subject_envelope(
            B4SubjectEnvelopeKind::NegativeBindingIndexBundle as u8,
            &[decoded.parts()[1], decoded.parts()[0]],
        );
        assert_coordinated_c1_subject_rewrite_is_rejected(
            binding_index,
            binding_execution,
            &fixture.top_level.negative_plan,
            &binding,
            wrong_order,
        );

        let mut wrong_identity =
            owned_c1_execution(candidate_index, candidate_execution, &candidate);
        let mut parsed_identity = Eip0045B4MaterializationIdentityV1::from_canonical_jcs(
            &wrong_identity.materialization_identity_jcs,
        )
        .unwrap();
        parsed_identity.output_sha256 = if parsed_identity.output_sha256 == "f".repeat(64) {
            "e".repeat(64)
        } else {
            "f".repeat(64)
        };
        wrong_identity.materialization_identity_jcs = parsed_identity.to_canonical_jcs().unwrap();
        let rows = [wrong_identity];
        let contexts = context_views(&rows);
        let supplied = execution_views(&rows, &contexts);
        assert!(
            ensure_reconstruction_matches_external(candidate_index, &candidate, &supplied[0])
                .is_err()
        );

        let mut wrong_tree_base = fixture.top_level.clone();
        wrong_tree_base.abstract_tree_jcs.push(b' ');
        assert!(
            producer
                .reconstruct(
                    C1_TREE_FIRST_INDEX,
                    planned[C1_TREE_FIRST_INDEX],
                    &wrong_tree_base,
                )
                .is_err()
        );

        let mut wrong_index_base = fixture.top_level.clone();
        *wrong_index_base
            .negative_binding_index_jcs
            .last_mut()
            .unwrap() ^= 1;
        assert!(
            producer
                .reconstruct(binding_index, binding_execution, &wrong_index_base)
                .is_err()
        );

        let mut wrong_recipe_authority = fixture.top_level.clone();
        wrong_recipe_authority.expanded_registry.negative_cases[candidate_index].materialization =
            B4NegativeMaterialization::FixtureSelection {
                fixture_id: candidate_execution.base_selector_id.clone(),
            };
        let independently_derived = producer
            .reconstruct(
                candidate_index,
                candidate_execution,
                &wrong_recipe_authority,
            )
            .unwrap()
            .unwrap();
        assert_ne!(
            independently_derived.derived_registry_row,
            wrong_recipe_authority.expanded_registry.negative_cases[candidate_index]
        );
    }

    #[test]
    fn all_external_rows_still_fail_closed_without_closed_producer_coverage() {
        let fixture = CoreFixture::exact();
        let contexts = context_views(&fixture.external);
        let executions = execution_views(&fixture.external, &contexts);
        let error = assemble_materialization_authority(
            &fixture.top_level,
            &fixture.catalog_identity,
            &executions,
            &mut empty_paths(),
            &UnavailableProductionRowProducer,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("0/254"));
    }

    #[test]
    fn coordinated_external_row_rewrite_cannot_rewrite_the_closed_producer() {
        let fixture = CoreFixture::exact();
        let mut rewritten = fixture.external.clone();
        rewritten[0].subject[0] ^= 1;
        let plan =
            Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.top_level.negative_plan).unwrap();
        let execution = &plan.groups[0].executions[0];
        let registry_row = &fixture.top_level.expanded_registry.negative_cases[0];
        let (identity, input) = execution_documents(
            execution,
            registry_row,
            &fixture.top_level.negative_plan,
            &rewritten[0].base,
            &rewritten[0].subject,
            &rewritten[0].contexts,
        );
        rewritten[0].materialization_identity_jcs = identity;
        rewritten[0].negative_input_jcs = input;

        let contexts = context_views(&rewritten);
        let executions = execution_views(&rewritten, &contexts);
        let error = assemble_materialization_authority(
            &fixture.top_level,
            &fixture.catalog_identity,
            &executions,
            &mut empty_paths(),
            &fixture.producer(),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("closed producer reconstruction"));
    }

    #[test]
    fn order_cardinality_and_physical_path_alias_drift_fail_independently() {
        let fixture = CoreFixture::exact();

        let mut reordered = fixture.external.clone();
        reordered.swap(0, 1);
        let contexts = context_views(&reordered);
        let executions = execution_views(&reordered, &contexts);
        assert!(
            assemble_materialization_authority(
                &fixture.top_level,
                &fixture.catalog_identity,
                &executions,
                &mut empty_paths(),
                &fixture.producer(),
            )
            .is_err()
        );

        let mut cardinality = fixture.external.clone();
        cardinality[0].contexts.pop();
        cardinality[0].context_paths.pop();
        let contexts = context_views(&cardinality);
        let executions = execution_views(&cardinality, &contexts);
        assert!(
            assemble_materialization_authority(
                &fixture.top_level,
                &fixture.catalog_identity,
                &executions,
                &mut empty_paths(),
                &fixture.producer(),
            )
            .is_err()
        );

        let mut alias = fixture.external.clone();
        alias[1].subject_path = alias[0].subject_path.clone();
        let contexts = context_views(&alias);
        let executions = execution_views(&alias, &contexts);
        let error = assemble_materialization_authority(
            &fixture.top_level,
            &fixture.catalog_identity,
            &executions,
            &mut empty_paths(),
            &fixture.producer(),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("aliases an existing physical role"));
    }

    #[test]
    fn producer_derived_recipe_not_synthetic_binding_index_is_authority() {
        let fixture = CoreFixture::exact();
        let mut rewritten_top = fixture.top_level.clone();
        rewritten_top.expanded_registry.negative_cases[0].materialization =
            B4NegativeMaterialization::FixtureSelection {
                fixture_id: "coordinated-rewrite".to_owned(),
            };
        let contexts = context_views(&fixture.external);
        let executions = execution_views(&fixture.external, &contexts);
        let error = assemble_materialization_authority(
            &rewritten_top,
            &fixture.catalog_identity,
            &executions,
            &mut empty_paths(),
            &fixture.producer(),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("producer-derived registry row"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn identity(byte_length: u64, seed: usize) -> B4NegativeMaterializationByteIdentityV1 {
        B4NegativeMaterializationByteIdentityV1 {
            byte_length,
            sha256: format!("{seed:064x}"),
        }
    }

    pub(super) fn canonical_fixture() -> Eip0045B4NegativeMaterializationSetV1 {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let executions = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .enumerate()
            .map(|(index, planned)| {
                let context_count = planned_negative_handler_contract(
                    planned.materialization_domain,
                    planned.execution_surface,
                )
                .unwrap()
                .unwrap()
                .custody()
                .contexts()
                .len();
                B4NegativeMaterializationSetExecutionV1 {
                    execution_index: u16::try_from(index).unwrap(),
                    execution_id: planned.execution_id.clone(),
                    materialization_domain: planned.materialization_domain,
                    validation_surface: planned.execution_surface,
                    base: identity(1, 1_000 + index),
                    materialization_identity: identity(256, 2_000 + index),
                    negative_input: identity(512, 3_000 + index),
                    subject: identity(1, 4_000 + index),
                    contexts: (0..context_count)
                        .map(|context| identity(1, 10_000 + index * 100 + context))
                        .collect(),
                }
            })
            .collect();
        Eip0045B4NegativeMaterializationSetV1 {
            format: B4_NEGATIVE_MATERIALIZATION_SET_FORMAT.to_owned(),
            format_version: B4_NEGATIVE_MATERIALIZATION_SET_FORMAT_VERSION,
            campaign_precommit: identity(1_024, 1),
            positive_generation_set: identity(2_048, 2),
            terminal_evidence_packet_manifest: identity(4_096, 9),
            terminal_evidence_campaign_receipt: identity(2_048, 10),
            negative_plan: identity(4_096, 3),
            expanded_registry: identity(8_192, 4),
            subject_catalog: identity(4_096, 5),
            terminal_fixture_catalog: identity(8_192, 6),
            negative_binding_index: identity(16_384, 7),
            abstract_tree: identity(2_048, 8),
            negative_ancestry_witness_catalog: B4ContractArtifactIdentityV1::from_bytes(
                B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_PATH,
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                b"{\"fixture\":\"negative-ancestry\"}",
            )
            .unwrap(),
            domain_totals: B4NegativeMaterializationDomainTotalsV1::EXPECTED,
            execution_count: B4_NEGATIVE_PLAN_VARIANT_COUNT,
            executions,
        }
    }

    fn canonical_value() -> Value {
        serde_json::to_value(canonical_fixture()).unwrap()
    }

    fn assert_parser_rejects(value: &Value) {
        let source = canonical_json_bytes(value).unwrap();
        assert!(Eip0045B4NegativeMaterializationSetV1::from_canonical_jcs(&source).is_err());
    }

    #[test]
    fn canonical_254_row_fixture_round_trips_byte_exactly() {
        let fixture = canonical_fixture();
        fixture.validate().unwrap();
        assert_eq!(
            fixture.executions.len(),
            B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT
        );
        assert_eq!(
            fixture.domain_totals,
            B4NegativeMaterializationDomainTotalsV1 {
                verifier_input: 131,
                artifact_validator: 102,
                tree_validator: 21,
            }
        );
        assert_eq!(fixture.executions[0].contexts.len(), 2);
        let terminal_metadata = fixture
            .executions
            .iter()
            .find(|execution| {
                execution.validation_surface == B4NegativeExecutionSurface::TerminalMetadata
            })
            .unwrap();
        assert_eq!(terminal_metadata.contexts.len(), 7);

        let source = fixture.to_canonical_jcs().unwrap();
        assert_eq!(
            Eip0045B4NegativeMaterializationSetV1::from_canonical_jcs(&source).unwrap(),
            fixture
        );
    }

    #[test]
    fn negative_ancestry_catalog_identity_is_required_and_round_trips() {
        let fixture = canonical_fixture();
        let bytes = fixture.to_canonical_jcs().unwrap();
        assert_eq!(
            Eip0045B4NegativeMaterializationSetV1::from_canonical_jcs(&bytes).unwrap(),
            fixture
        );

        let mut legacy = serde_json::to_value(&fixture).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("negativeAncestryWitnessCatalog");
        assert_parser_rejects(&legacy);
    }

    #[test]
    fn rejects_every_negative_ancestry_catalog_identity_mutation_class() {
        let valid = canonical_value();
        let mut mutations = Vec::new();

        let mut wrong_path = valid.clone();
        wrong_path["negativeAncestryWitnessCatalog"]["path"] =
            json!("reproduction/wrong-catalog.json");
        mutations.push(("wrong path", wrong_path));

        let mut wrong_encoding = valid.clone();
        wrong_encoding["negativeAncestryWitnessCatalog"]["encoding"] = json!("raw-bytes");
        mutations.push(("wrong encoding", wrong_encoding));

        let mut empty = valid.clone();
        empty["negativeAncestryWitnessCatalog"]["byteLength"] = json!(0);
        mutations.push(("empty", empty));

        let mut oversized = valid.clone();
        oversized["negativeAncestryWitnessCatalog"]["byteLength"] =
            json!(B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_MAX_BYTES + 1);
        mutations.push(("oversized", oversized));

        let mut uppercase_digest = valid.clone();
        uppercase_digest["negativeAncestryWitnessCatalog"]["sha256"] = json!("A".repeat(64));
        mutations.push(("uppercase digest", uppercase_digest));

        let mut zero_digest = valid.clone();
        zero_digest["negativeAncestryWitnessCatalog"]["sha256"] = json!("0".repeat(64));
        mutations.push(("all-zero digest", zero_digest));

        let mut unknown_nested = valid;
        unknown_nested["negativeAncestryWitnessCatalog"]["unknown"] = json!(true);
        mutations.push(("unknown nested field", unknown_nested));

        for (class, mutation) in mutations {
            let source = canonical_json_bytes(&mutation).unwrap();
            assert!(
                Eip0045B4NegativeMaterializationSetV1::from_canonical_jcs(&source).is_err(),
                "parser accepted {class} mutation"
            );
        }
    }

    #[test]
    fn rejects_format_version_totals_and_declared_count_drift() {
        let mut value = canonical_value();
        value["format"] = json!("Other");
        assert_parser_rejects(&value);

        let mut value = canonical_value();
        value["formatVersion"] = json!(2);
        assert_parser_rejects(&value);

        for total in ["verifierInput", "artifactValidator", "treeValidator"] {
            let mut value = canonical_value();
            value["domainTotals"][total] =
                json!(value["domainTotals"][total].as_u64().unwrap() + 1);
            assert_parser_rejects(&value);
        }

        let mut value = canonical_value();
        value["executionCount"] = json!(253);
        assert_parser_rejects(&value);
    }

    #[test]
    fn rejects_every_top_level_document_identity_mutation_class() {
        let fields = [
            ("campaignPrecommit", MAX_CAMPAIGN_PRECOMMIT_BYTES),
            ("positiveGenerationSet", MAX_POSITIVE_GENERATION_SET_BYTES),
            (
                "terminalEvidencePacketManifest",
                MAX_TERMINAL_EVIDENCE_DOCUMENT_BYTES,
            ),
            (
                "terminalEvidenceCampaignReceipt",
                MAX_TERMINAL_EVIDENCE_DOCUMENT_BYTES,
            ),
            ("negativePlan", MAX_NEGATIVE_PLAN_BYTES),
            ("expandedRegistry", MAX_EXPANDED_REGISTRY_BYTES),
            ("subjectCatalog", MAX_SUBJECT_CATALOG_BYTES),
            ("terminalFixtureCatalog", MAX_TERMINAL_FIXTURE_CATALOG_BYTES),
            ("negativeBindingIndex", MAX_NEGATIVE_BINDING_INDEX_BYTES),
            ("abstractTree", MAX_ABSTRACT_TREE_BYTES),
        ];
        for (field, maximum) in fields {
            let mut empty = canonical_value();
            empty[field]["byteLength"] = json!(0);
            assert_parser_rejects(&empty);

            let mut oversized = canonical_value();
            oversized[field]["byteLength"] = json!(maximum + 1);
            assert_parser_rejects(&oversized);

            let mut malformed_digest = canonical_value();
            malformed_digest[field]["sha256"] = json!("A".repeat(64));
            assert_parser_rejects(&malformed_digest);
        }
    }

    #[test]
    fn rejects_each_missing_terminal_evidence_identity() {
        for field in [
            "terminalEvidencePacketManifest",
            "terminalEvidenceCampaignReceipt",
        ] {
            let mut missing = canonical_value();
            missing.as_object_mut().unwrap().remove(field);
            assert_parser_rejects(&missing);
        }
    }

    #[test]
    fn rejects_row_identity_bounds_and_malformed_digests() {
        let fields = [
            ("base", MAX_RAW_BYTES),
            (
                "materializationIdentity",
                MAX_MATERIALIZATION_IDENTITY_BYTES,
            ),
            ("negativeInput", MAX_NEGATIVE_INPUT_BYTES),
            ("subject", MAX_RAW_BYTES),
        ];
        for (field, maximum) in fields {
            let mut empty = canonical_value();
            empty["executions"][0][field]["byteLength"] = json!(0);
            assert_parser_rejects(&empty);

            let mut oversized = canonical_value();
            oversized["executions"][0][field]["byteLength"] = json!(maximum + 1);
            assert_parser_rejects(&oversized);

            let mut malformed_digest = canonical_value();
            malformed_digest["executions"][0][field]["sha256"] = json!("f".repeat(63));
            assert_parser_rejects(&malformed_digest);
        }

        let mut empty_context = canonical_value();
        empty_context["executions"][1]["contexts"][0]["byteLength"] = json!(0);
        assert_parser_rejects(&empty_context);

        let mut oversized_context = canonical_value();
        oversized_context["executions"][1]["contexts"][0]["byteLength"] = json!(MAX_RAW_BYTES + 1);
        assert_parser_rejects(&oversized_context);
    }

    #[test]
    fn only_internal_parser_rows_admit_an_empty_materialized_subject() {
        let mut fixture = canonical_fixture();
        let parser_index = fixture
            .executions
            .iter()
            .position(|execution| {
                execution.materialization_domain == B4MaterializationDomain::VerifierInput
                    && execution.validation_surface
                        == B4NegativeExecutionSurface::Risc0ParserInternal
            })
            .unwrap();
        fixture.executions[parser_index].subject.byte_length = 0;
        fixture.validate().unwrap();
        let source = fixture.to_canonical_jcs().unwrap();
        assert_eq!(
            Eip0045B4NegativeMaterializationSetV1::from_canonical_jcs(&source).unwrap(),
            fixture
        );

        let mut wrong_surface = fixture;
        wrong_surface.executions[parser_index].validation_surface =
            B4NegativeExecutionSurface::RawSealShape;
        assert!(wrong_surface.validate().is_err());
    }

    #[test]
    fn accepts_every_inclusive_identity_and_context_bound() {
        let mut fixture = canonical_fixture();
        fixture.campaign_precommit.byte_length = MAX_CAMPAIGN_PRECOMMIT_BYTES;
        fixture.positive_generation_set.byte_length = MAX_POSITIVE_GENERATION_SET_BYTES;
        fixture.terminal_evidence_packet_manifest.byte_length =
            MAX_TERMINAL_EVIDENCE_DOCUMENT_BYTES;
        fixture.terminal_evidence_campaign_receipt.byte_length =
            MAX_TERMINAL_EVIDENCE_DOCUMENT_BYTES;
        fixture.negative_plan.byte_length = MAX_NEGATIVE_PLAN_BYTES;
        fixture.expanded_registry.byte_length = MAX_EXPANDED_REGISTRY_BYTES;
        fixture.subject_catalog.byte_length = MAX_SUBJECT_CATALOG_BYTES;
        fixture.terminal_fixture_catalog.byte_length = MAX_TERMINAL_FIXTURE_CATALOG_BYTES;
        fixture.negative_binding_index.byte_length = MAX_NEGATIVE_BINDING_INDEX_BYTES;
        fixture.abstract_tree.byte_length = MAX_ABSTRACT_TREE_BYTES;

        let execution = &mut fixture.executions[1];
        execution.base.byte_length = MAX_RAW_BYTES;
        execution.materialization_identity.byte_length = MAX_MATERIALIZATION_IDENTITY_BYTES;
        execution.negative_input.byte_length = MAX_NEGATIVE_INPUT_BYTES;
        execution.subject.byte_length = MAX_RAW_BYTES;
        for context in &mut execution.contexts {
            context.byte_length = MAX_RAW_BYTES;
        }
        fixture.validate().unwrap();
    }

    #[test]
    fn rejects_plan_index_id_domain_and_surface_drift() {
        let mut index = canonical_value();
        index["executions"][0]["executionIndex"] = json!(1);
        assert_parser_rejects(&index);

        let mut execution_id = canonical_value();
        execution_id["executions"][0]["executionId"] =
            execution_id["executions"][1]["executionId"].clone();
        assert_parser_rejects(&execution_id);

        let mut domain = canonical_value();
        domain["executions"][0]["materializationDomain"] = json!("artifact-validator");
        assert_parser_rejects(&domain);

        let mut surface = canonical_value();
        surface["executions"][0]["validationSurface"] = json!("opcode-preflight");
        assert_parser_rejects(&surface);
    }

    #[test]
    fn rejects_reordered_missing_extra_and_duplicate_rows() {
        let mut reordered = canonical_fixture();
        reordered.executions.swap(0, 1);
        assert!(reordered.validate().is_err());

        let mut missing = canonical_fixture();
        missing.executions.pop();
        assert!(missing.validate().is_err());

        let mut extra = canonical_fixture();
        extra.executions.push(extra.executions[0].clone());
        assert!(extra.validate().is_err());

        let mut duplicate = canonical_fixture();
        duplicate.executions[1] = duplicate.executions[0].clone();
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn rejects_context_cardinality_drift_and_preserves_context_position() {
        let mut missing = canonical_fixture();
        missing.executions[0].contexts.pop();
        assert!(missing.validate().is_err());

        let mut extra = canonical_fixture();
        extra.executions[0].contexts.push(identity(1, 42));
        assert!(extra.validate().is_err());

        let source = canonical_fixture().to_canonical_jcs().unwrap();
        let parsed = Eip0045B4NegativeMaterializationSetV1::from_canonical_jcs(&source).unwrap();
        for (index, context) in parsed.executions[1].contexts.iter().enumerate() {
            assert_eq!(context.sha256, format!("{:064x}", 10_100 + index));
        }
    }

    #[test]
    fn permits_content_deduplication_without_digest_uniqueness() {
        let mut fixture = canonical_fixture();
        let shared = identity(1, 999);
        fixture.campaign_precommit = shared.clone();
        fixture.positive_generation_set = shared.clone();
        fixture.terminal_evidence_packet_manifest = shared.clone();
        fixture.terminal_evidence_campaign_receipt = shared.clone();
        fixture.negative_plan = shared.clone();
        fixture.expanded_registry = shared.clone();
        fixture.subject_catalog = shared.clone();
        fixture.terminal_fixture_catalog = shared.clone();
        fixture.negative_binding_index = shared.clone();
        fixture.abstract_tree = shared.clone();
        fixture.executions[2].base = shared.clone();
        fixture.executions[2].materialization_identity = shared.clone();
        fixture.executions[2].negative_input = shared.clone();
        fixture.executions[2].subject = shared.clone();
        fixture.executions[2].contexts = vec![shared.clone(), shared];
        fixture.validate().unwrap();
    }

    #[test]
    fn rejects_duplicate_trailing_noncanonical_and_unknown_json() {
        let source = canonical_fixture().to_canonical_jcs().unwrap();
        let text = String::from_utf8(source.clone()).unwrap();
        let duplicate = text.replacen(
            "\"format\":\"Eip0045B4NegativeMaterializationSetV1\",",
            "\"format\":\"Eip0045B4NegativeMaterializationSetV1\",\"format\":\"Eip0045B4NegativeMaterializationSetV1\",",
            1,
        );
        assert!(
            Eip0045B4NegativeMaterializationSetV1::from_canonical_jcs(duplicate.as_bytes())
                .is_err()
        );

        let mut trailing = source.clone();
        trailing.push(b'\n');
        assert!(Eip0045B4NegativeMaterializationSetV1::from_canonical_jcs(&trailing).is_err());

        let pretty = serde_json::to_vec_pretty(&canonical_fixture()).unwrap();
        assert!(Eip0045B4NegativeMaterializationSetV1::from_canonical_jcs(&pretty).is_err());

        let mut unknown_top = canonical_value();
        unknown_top["unknown"] = json!(true);
        assert_parser_rejects(&unknown_top);

        let mut unknown_row = canonical_value();
        unknown_row["executions"][0]["unknown"] = json!(true);
        assert_parser_rejects(&unknown_row);

        let mut unknown_identity = canonical_value();
        unknown_identity["executions"][0]["base"]["path"] = json!("forbidden.bin");
        assert_parser_rejects(&unknown_identity);
    }
}

#[cfg(all(test, feature = "positive-gate"))]
mod schema_tests {
    use std::collections::BTreeSet;

    use super::*;
    use jsonschema::Validator;
    use serde_json::{Value, json};

    const SCHEMA_SOURCE: &str =
        include_str!("../finalizer-schema/b4-negative-materialization-set-v1.schema.json");

    #[allow(clippy::too_many_lines)]
    fn expected_schema() -> Value {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let prefix_items = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .enumerate()
            .map(|(index, execution)| {
                let context_count = planned_negative_handler_contract(
                    execution.materialization_domain,
                    execution.execution_surface,
                )
                .unwrap()
                .unwrap()
                .custody()
                .contexts()
                .len();
                json!({
                    "$ref": "#/$defs/Execution",
                    "properties": {
                        "executionIndex": {"const": index},
                        "executionId": {"const": execution.execution_id},
                        "materializationDomain": {
                            "const": serde_json::to_value(execution.materialization_domain).unwrap()
                        },
                        "validationSurface": {
                            "const": serde_json::to_value(execution.execution_surface).unwrap()
                        },
                        "contexts": {
                            "minItems": context_count,
                            "maxItems": context_count
                        }
                    }
                })
            })
            .collect::<Vec<_>>();

        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "urn:ergo:eip-0045:b4-negative-materialization-set-v1",
            "title": "Eip0045B4NegativeMaterializationSetV1",
            "$comment": "Pathless identities intentionally have no uniqueness constraint: distinct roles may legitimately deduplicate to the same exact bytes. Each execution prefix fixes the exact handler-owned context cardinality. Schema validity is structural only and does not confer campaign authority.",
            "description": "Canonical pre-run commitments to the campaign precommit, positive generation set, terminal-evidence packet manifest and receipt, seven negative-corpus documents, and all 254 canonical-plan materializations.",
            "type": "object",
            "additionalProperties": false,
            "required": [
                "format",
                "formatVersion",
                "campaignPrecommit",
                "positiveGenerationSet",
                "terminalEvidencePacketManifest",
                "terminalEvidenceCampaignReceipt",
                "negativePlan",
                "expandedRegistry",
                "subjectCatalog",
                "terminalFixtureCatalog",
                "negativeBindingIndex",
                "abstractTree",
                "negativeAncestryWitnessCatalog",
                "domainTotals",
                "executionCount",
                "executions"
            ],
            "properties": {
                "format": {"const": "Eip0045B4NegativeMaterializationSetV1"},
                "formatVersion": {"const": 1},
                "campaignPrecommit": {
                    "$ref": "#/$defs/ByteIdentity",
                    "properties": {"byteLength": {"maximum": 1_048_576}}
                },
                "positiveGenerationSet": {
                    "$ref": "#/$defs/ByteIdentity",
                    "properties": {"byteLength": {"maximum": 1_048_576}}
                },
                "terminalEvidencePacketManifest": {
                    "$ref": "#/$defs/ByteIdentity",
                    "properties": {"byteLength": {"maximum": 65_536}}
                },
                "terminalEvidenceCampaignReceipt": {
                    "$ref": "#/$defs/ByteIdentity",
                    "properties": {"byteLength": {"maximum": 65_536}}
                },
                "negativePlan": {
                    "$ref": "#/$defs/ByteIdentity",
                    "properties": {"byteLength": {"maximum": 131_072}}
                },
                "expandedRegistry": {
                    "$ref": "#/$defs/ByteIdentity",
                    "properties": {"byteLength": {"maximum": 8_388_608}}
                },
                "subjectCatalog": {
                    "$ref": "#/$defs/ByteIdentity",
                    "properties": {"byteLength": {"maximum": 131_072}}
                },
                "terminalFixtureCatalog": {
                    "$ref": "#/$defs/ByteIdentity",
                    "properties": {"byteLength": {"maximum": 262_144}}
                },
                "negativeBindingIndex": {
                    "$ref": "#/$defs/ByteIdentity",
                    "properties": {"byteLength": {"maximum": 8_388_608}}
                },
                "abstractTree": {
                    "$ref": "#/$defs/ByteIdentity",
                    "properties": {"byteLength": {"maximum": 16384}}
                },
                "negativeAncestryWitnessCatalog": {
                    "$ref": "#/$defs/NegativeAncestryWitnessCatalogIdentity"
                },
                "domainTotals": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["verifierInput", "artifactValidator", "treeValidator"],
                    "properties": {
                        "verifierInput": {"const": 131},
                        "artifactValidator": {"const": 102},
                        "treeValidator": {"const": 21}
                    }
                },
                "executionCount": {"const": 254},
                "executions": {
                    "type": "array",
                    "minItems": 254,
                    "maxItems": 254,
                    "prefixItems": prefix_items,
                    "items": false
                }
            },
            "$defs": {
                "Hex32": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{64}$"
                },
                "ByteIdentity": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["byteLength", "sha256"],
                    "properties": {
                        "byteLength": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 536_870_912
                        },
                        "sha256": {"$ref": "#/$defs/Hex32"}
                    }
                },
                "NegativeAncestryWitnessCatalogIdentity": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["path", "byteLength", "sha256", "encoding"],
                    "properties": {
                        "path": {
                            "const": "reproduction/negative-ancestry-witness-catalog.json"
                        },
                        "byteLength": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 131_072
                        },
                        "sha256": {
                            "$ref": "#/$defs/Hex32",
                            "not": {
                                "const": "0000000000000000000000000000000000000000000000000000000000000000"
                            }
                        },
                        "encoding": {
                            "const": "rfc8785-jcs"
                        }
                    }
                },
                "SubjectIdentity": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["byteLength", "sha256"],
                    "properties": {
                        "byteLength": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 536_870_912
                        },
                        "sha256": {"$ref": "#/$defs/Hex32"}
                    }
                },
                "Execution": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [
                        "executionIndex",
                        "executionId",
                        "materializationDomain",
                        "validationSurface",
                        "base",
                        "materializationIdentity",
                        "negativeInput",
                        "subject",
                        "contexts"
                    ],
                    "properties": {
                        "executionIndex": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 253
                        },
                        "executionId": {
                            "type": "string",
                            "minLength": 4,
                            "maxLength": 258,
                            "pattern": "^(?=.{1,128}--.{1,128}$)[a-z](?:[a-z0-9]|-[a-z0-9])*--[a-z](?:[a-z0-9]|-[a-z0-9])*$"
                        },
                        "materializationDomain": {
                            "enum": [
                                "verifier-input",
                                "artifact-validator",
                                "tree-validator"
                            ]
                        },
                        "validationSurface": {
                            "enum": [
                                "opcode-preflight",
                                "raw-statement-claim-binding",
                                "raw-seal-shape",
                                "risc0-parser-internal",
                                "risc0-cryptographic-verifier",
                                "terminal-policy",
                                "receipt-claim-policy",
                                "ancestry-replay",
                                "profile-manifest-codec",
                                "initial-profile-target",
                                "profile-artifact-envelope",
                                "activated-profile-package",
                                "terminal-fixture-catalog",
                                "sequence-subject-catalog",
                                "terminal-metadata",
                                "profile-id-preimage",
                                "candidate-registry",
                                "negative-binding-index",
                                "corpus-closure"
                            ]
                        },
                        "base": {"$ref": "#/$defs/ByteIdentity"},
                        "materializationIdentity": {
                            "$ref": "#/$defs/ByteIdentity",
                            "properties": {"byteLength": {"maximum": 65536}}
                        },
                        "negativeInput": {
                            "$ref": "#/$defs/ByteIdentity",
                            "properties": {"byteLength": {"maximum": 65536}}
                        },
                        "subject": {"$ref": "#/$defs/SubjectIdentity"},
                        "contexts": {
                            "type": "array",
                            "minItems": 0,
                            "maxItems": 64,
                            "items": {"$ref": "#/$defs/ByteIdentity"}
                        }
                    },
                    "allOf": [{
                        "if": {
                            "properties": {
                                "materializationDomain": {"const": "verifier-input"},
                                "validationSurface": {"const": "risc0-parser-internal"}
                            },
                            "required": ["materializationDomain", "validationSurface"]
                        },
                        "else": {
                            "properties": {
                                "subject": {
                                    "properties": {
                                        "byteLength": {"minimum": 1}
                                    }
                                }
                            }
                        }
                    }]
                }
            }
        })
    }

    fn compile_schema() -> Validator {
        let schema = crate::canonical::parse_json_strict(SCHEMA_SOURCE.as_bytes()).unwrap();
        jsonschema::draft202012::options().build(&schema).unwrap()
    }

    fn assert_internal_refs_and_closed_objects(value: &Value) {
        match value {
            Value::Object(object) => {
                if object.get("type") == Some(&Value::String("object".to_owned())) {
                    assert_eq!(
                        object.get("additionalProperties"),
                        Some(&Value::Bool(false)),
                        "object schema is not closed"
                    );
                }
                for (key, nested) in object {
                    if key == "$ref" {
                        assert!(
                            nested.as_str().unwrap().starts_with("#/"),
                            "schema contains a non-internal reference"
                        );
                    }
                    assert_internal_refs_and_closed_objects(nested);
                }
            }
            Value::Array(items) => {
                for item in items {
                    assert_internal_refs_and_closed_objects(item);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }

    fn fixture_value() -> Value {
        serde_json::to_value(super::tests::canonical_fixture()).unwrap()
    }

    fn assert_schema_and_rust_reject(value: &Value) {
        assert!(compile_schema().validate(value).is_err());
        let source = canonical_json_bytes(value).unwrap();
        assert!(Eip0045B4NegativeMaterializationSetV1::from_canonical_jcs(&source).is_err());
    }

    #[test]
    fn actual_schema_parses_compiles_closes_objects_and_uses_internal_refs() {
        let schema = crate::canonical::parse_json_strict(SCHEMA_SOURCE.as_bytes()).unwrap();
        assert_eq!(schema, expected_schema());
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(
            schema["$id"],
            "urn:ergo:eip-0045:b4-negative-materialization-set-v1"
        );
        assert_internal_refs_and_closed_objects(&schema);
        compile_schema();
    }

    #[test]
    fn schema_prefix_sequence_is_the_exact_flattened_canonical_plan() {
        let schema = crate::canonical::parse_json_strict(SCHEMA_SOURCE.as_bytes()).unwrap();
        let prefix = schema["properties"]["executions"]["prefixItems"]
            .as_array()
            .unwrap();
        assert_eq!(
            prefix.len(),
            B4_NEGATIVE_MATERIALIZATION_SET_EXECUTION_COUNT
        );
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        for (index, (item, execution)) in prefix
            .iter()
            .zip(plan.groups.iter().flat_map(|group| group.executions.iter()))
            .enumerate()
        {
            assert_eq!(item["properties"]["executionIndex"]["const"], index);
            assert_eq!(
                item["properties"]["executionId"]["const"],
                execution.execution_id
            );
            assert_eq!(
                item["properties"]["materializationDomain"]["const"],
                serde_json::to_value(execution.materialization_domain).unwrap()
            );
            assert_eq!(
                item["properties"]["validationSurface"]["const"],
                serde_json::to_value(execution.execution_surface).unwrap()
            );
            let context_count = planned_negative_handler_contract(
                execution.materialization_domain,
                execution.execution_surface,
            )
            .unwrap()
            .unwrap()
            .custody()
            .contexts()
            .len();
            assert_eq!(
                item["properties"]["contexts"]["minItems"],
                json!(context_count)
            );
            assert_eq!(
                item["properties"]["contexts"]["maxItems"],
                json!(context_count)
            );
        }
    }

    #[test]
    fn schema_and_rust_bind_every_handler_context_cardinality() {
        let validator = compile_schema();
        let fixture = fixture_value();
        let mut observed = BTreeSet::new();
        for (index, execution) in fixture["executions"].as_array().unwrap().iter().enumerate() {
            let pair = (
                execution["materializationDomain"].as_str().unwrap(),
                execution["validationSurface"].as_str().unwrap(),
            );
            if !observed.insert(pair) {
                continue;
            }
            let mut drift = fixture.clone();
            let contexts = drift["executions"][index]["contexts"]
                .as_array_mut()
                .unwrap();
            if contexts.is_empty() {
                contexts.push(json!({"byteLength": 1, "sha256": "0".repeat(64)}));
            } else {
                contexts.pop();
            }
            assert!(validator.validate(&drift).is_err());
            let source = canonical_json_bytes(&drift).unwrap();
            assert!(Eip0045B4NegativeMaterializationSetV1::from_canonical_jcs(&source).is_err());
        }
        assert_eq!(
            observed.len(),
            crate::b4_negative_handler_contract::B4_NEGATIVE_HANDLER_CONTRACT_COUNT
        );
    }

    #[test]
    fn canonical_rust_fixture_satisfies_actual_schema_and_parser() {
        let fixture = super::tests::canonical_fixture();
        let value = serde_json::to_value(&fixture).unwrap();
        compile_schema().validate(&value).unwrap();
        let source = fixture.to_canonical_jcs().unwrap();
        Eip0045B4NegativeMaterializationSetV1::from_canonical_jcs(&source).unwrap();
    }

    #[test]
    fn schema_and_rust_reject_legacy_v1_without_ancestry_catalog_identity() {
        let compiled_schema = compile_schema();
        let mut value = fixture_value();
        value
            .as_object_mut()
            .unwrap()
            .remove("negativeAncestryWitnessCatalog");
        assert!(!compiled_schema.is_valid(&value));
        assert_schema_and_rust_reject(&value);
    }

    #[test]
    fn schema_and_rust_reject_every_ancestry_catalog_identity_mutation_class() {
        let compiled_schema = compile_schema();
        let valid = fixture_value();
        let mut mutations = Vec::new();

        let mut wrong_path = valid.clone();
        wrong_path["negativeAncestryWitnessCatalog"]["path"] =
            json!("reproduction/wrong-catalog.json");
        mutations.push(("wrong path", wrong_path));

        let mut wrong_encoding = valid.clone();
        wrong_encoding["negativeAncestryWitnessCatalog"]["encoding"] = json!("raw-bytes");
        mutations.push(("wrong encoding", wrong_encoding));

        let mut empty = valid.clone();
        empty["negativeAncestryWitnessCatalog"]["byteLength"] = json!(0);
        mutations.push(("empty", empty));

        let mut oversized = valid.clone();
        oversized["negativeAncestryWitnessCatalog"]["byteLength"] =
            json!(B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_MAX_BYTES + 1);
        mutations.push(("oversized", oversized));

        let mut uppercase_digest = valid.clone();
        uppercase_digest["negativeAncestryWitnessCatalog"]["sha256"] = json!("A".repeat(64));
        mutations.push(("uppercase digest", uppercase_digest));

        let mut zero_digest = valid.clone();
        zero_digest["negativeAncestryWitnessCatalog"]["sha256"] = json!("0".repeat(64));
        mutations.push(("all-zero digest", zero_digest));

        let mut unknown_nested = valid;
        unknown_nested["negativeAncestryWitnessCatalog"]["unknown"] = json!(true);
        mutations.push(("unknown nested field", unknown_nested));

        for (class, value) in mutations {
            assert!(
                !compiled_schema.is_valid(&value),
                "schema accepted {class} mutation"
            );
            assert_schema_and_rust_reject(&value);
        }
    }

    #[test]
    fn schema_and_rust_allow_zero_subject_only_for_internal_parser_rows() {
        let mut value = fixture_value();
        let parser_index = value["executions"]
            .as_array()
            .unwrap()
            .iter()
            .position(|execution| {
                execution["materializationDomain"] == "verifier-input"
                    && execution["validationSurface"] == "risc0-parser-internal"
            })
            .unwrap();
        value["executions"][parser_index]["subject"]["byteLength"] = json!(0);
        compile_schema().validate(&value).unwrap();
        let source = canonical_json_bytes(&value).unwrap();
        Eip0045B4NegativeMaterializationSetV1::from_canonical_jcs(&source).unwrap();

        value["executions"][parser_index]["validationSurface"] = json!("raw-seal-shape");
        assert_schema_and_rust_reject(&value);
    }

    #[test]
    fn schema_and_rust_reject_all_schema_visible_structural_classes() {
        let mut wrong_format = fixture_value();
        wrong_format["format"] = json!("Other");
        assert_schema_and_rust_reject(&wrong_format);

        let mut bad_digest = fixture_value();
        bad_digest["negativePlan"]["sha256"] = json!("A".repeat(64));
        assert_schema_and_rust_reject(&bad_digest);

        let mut bad_document_bound = fixture_value();
        bad_document_bound["abstractTree"]["byteLength"] = json!(MAX_ABSTRACT_TREE_BYTES + 1);
        assert_schema_and_rust_reject(&bad_document_bound);

        let mut wrong_total = fixture_value();
        wrong_total["domainTotals"]["verifierInput"] = json!(130);
        assert_schema_and_rust_reject(&wrong_total);

        let mut wrong_index = fixture_value();
        wrong_index["executions"][0]["executionIndex"] = json!(1);
        assert_schema_and_rust_reject(&wrong_index);

        let mut wrong_id = fixture_value();
        wrong_id["executions"][0]["executionId"] = wrong_id["executions"][1]["executionId"].clone();
        assert_schema_and_rust_reject(&wrong_id);

        let mut wrong_domain = fixture_value();
        wrong_domain["executions"][0]["materializationDomain"] = json!("artifact-validator");
        assert_schema_and_rust_reject(&wrong_domain);

        let mut wrong_surface = fixture_value();
        wrong_surface["executions"][0]["validationSurface"] = json!("opcode-preflight");
        assert_schema_and_rust_reject(&wrong_surface);

        let mut bad_row_bound = fixture_value();
        bad_row_bound["executions"][0]["negativeInput"]["byteLength"] =
            json!(MAX_NEGATIVE_INPUT_BYTES + 1);
        assert_schema_and_rust_reject(&bad_row_bound);

        let mut too_many_contexts = fixture_value();
        too_many_contexts["executions"][0]["contexts"] =
            Value::Array(vec![json!({"byteLength": 1, "sha256": "0".repeat(64)}); 65]);
        assert_schema_and_rust_reject(&too_many_contexts);

        let mut missing = fixture_value();
        missing["executions"].as_array_mut().unwrap().pop();
        assert_schema_and_rust_reject(&missing);

        let mut extra = fixture_value();
        let first = extra["executions"][0].clone();
        extra["executions"].as_array_mut().unwrap().push(first);
        assert_schema_and_rust_reject(&extra);

        let mut reordered = fixture_value();
        reordered["executions"].as_array_mut().unwrap().swap(0, 1);
        assert_schema_and_rust_reject(&reordered);

        let mut unknown = fixture_value();
        unknown["executions"][0]["base"]["path"] = json!("forbidden.bin");
        assert_schema_and_rust_reject(&unknown);

        for field in [
            "negativeBindingIndex",
            "terminalEvidencePacketManifest",
            "terminalEvidenceCampaignReceipt",
        ] {
            let mut missing_top_level = fixture_value();
            missing_top_level.as_object_mut().unwrap().remove(field);
            assert_schema_and_rust_reject(&missing_top_level);
        }

        let mut missing_row_field = fixture_value();
        missing_row_field["executions"][0]
            .as_object_mut()
            .unwrap()
            .remove("subject");
        assert_schema_and_rust_reject(&missing_row_field);
    }

    #[test]
    fn schema_and_rust_both_permit_legitimate_content_deduplication() {
        let mut value = fixture_value();
        let shared = json!({"byteLength": 1, "sha256": "f".repeat(64)});
        for field in [
            "campaignPrecommit",
            "positiveGenerationSet",
            "negativePlan",
            "expandedRegistry",
            "subjectCatalog",
            "terminalFixtureCatalog",
            "negativeBindingIndex",
            "abstractTree",
        ] {
            value[field] = shared.clone();
        }
        for field in [
            "base",
            "materializationIdentity",
            "negativeInput",
            "subject",
        ] {
            value["executions"][2][field] = shared.clone();
        }
        value["executions"][2]["contexts"] = json!([shared.clone(), shared]);

        compile_schema().validate(&value).unwrap();
        let source = canonical_json_bytes(&value).unwrap();
        Eip0045B4NegativeMaterializationSetV1::from_canonical_jcs(&source).unwrap();
    }
}
