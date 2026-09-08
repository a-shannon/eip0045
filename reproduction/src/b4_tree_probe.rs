//! Abstract, role-only closed-tree probes for the EIP-0045 B4 plan.
//!
//! This module owns no second materialization identity. Each probe produces
//! exact base/output bytes and the exact registry recipe consumed by the
//! generic [`crate::b4_mutation::Eip0045B4MaterializationIdentityV1`] layer.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use sha2::{Digest, Sha256};

use crate::{
    b4::{
        B4NegativeCase, B4NegativeMaterialization, B4NegativeMutation, B4SequenceOperation,
        B4SequenceTarget,
    },
    b4_mutation::{
        B4MaterializationReplayAdapterV1, Eip0045B4MaterializationIdentityV1,
        create_materialization_identity_with_adapter, verify_materialization_identity_with_adapter,
    },
    b4_plan::{
        B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanExecutionV1,
        B4NegativeQaResultCode, Eip0045B4NegativePlanV1,
    },
    b4_subject::B4SequenceSubjectElement,
    canonical::{canonical_json_bytes, validate_canonical_json_source},
};

/// Exact format label for the abstract role-only tree model.
pub const B4_ABSTRACT_TREE_FORMAT: &str = "Eip0045B4AbstractTreeV1";
/// Exact format version for the abstract role-only tree model.
pub const B4_ABSTRACT_TREE_FORMAT_VERSION: u8 = 1;
/// Exact number of structural roles in the accepted abstract baseline.
pub const B4_REQUIRED_STRUCTURAL_STRATUM_COUNT: usize = 20;
/// Exact number of tree-domain executions in the closed B4 plan.
pub const B4_TREE_PROBE_EXECUTION_COUNT: usize = 21;

const MAX_ABSTRACT_TREE_BYTES: usize = 16 * 1024;
const ABSTRACT_CORPUS_SELECTOR: &str = "abstract-corpus-strata-v1";
const OMIT_EXECUTION_PREFIX: &str = "corpus-representative-stratum-omit-sweep--";
const EXTRA_EXECUTION_ID: &str = "corpus-extra-file--unregistered-file";

/// Literal closed inventory of all tree-validator executions.
pub const B4_TREE_PROBE_EXECUTION_IDS: [&str; B4_TREE_PROBE_EXECUTION_COUNT] = [
    "corpus-representative-stratum-omit-sweep--profile-manifest",
    "corpus-representative-stratum-omit-sweep--statement-bundle-manifest",
    "corpus-representative-stratum-omit-sweep--guest-elf",
    "corpus-representative-stratum-omit-sweep--source-lock",
    "corpus-representative-stratum-omit-sweep--proof-generator",
    "corpus-representative-stratum-omit-sweep--rust-verifier",
    "corpus-representative-stratum-omit-sweep--jvm-verifier",
    "corpus-representative-stratum-omit-sweep--positive-raw-seal",
    "corpus-representative-stratum-omit-sweep--recursive-ancestry",
    "corpus-representative-stratum-omit-sweep--negative-plan",
    "corpus-representative-stratum-omit-sweep--subject-catalog",
    "corpus-representative-stratum-omit-sweep--terminal-fixture-catalog",
    "corpus-representative-stratum-omit-sweep--positive-registry",
    "corpus-representative-stratum-omit-sweep--expanded-negative-registry",
    "corpus-representative-stratum-omit-sweep--mutation-identities",
    "corpus-representative-stratum-omit-sweep--rust-negative-results",
    "corpus-representative-stratum-omit-sweep--jvm-negative-results",
    "corpus-representative-stratum-omit-sweep--semantic-report",
    "corpus-representative-stratum-omit-sweep--tree-manifest",
    "corpus-representative-stratum-omit-sweep--lock",
    EXTRA_EXECUTION_ID,
];

/// Closed abstract roles. These names do not identify paths or artifact bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4AbstractCorpusRole {
    /// Profile-manifest structural stratum.
    ProfileManifest,
    /// Statement-bundle-manifest structural stratum.
    StatementBundleManifest,
    /// Guest-ELF structural stratum.
    GuestElf,
    /// Source-lock structural stratum.
    SourceLock,
    /// Proof-generator structural stratum.
    ProofGenerator,
    /// Rust-verifier structural stratum.
    RustVerifier,
    /// JVM-verifier structural stratum.
    JvmVerifier,
    /// Positive raw-seal structural stratum.
    PositiveRawSeal,
    /// Recursive-ancestry structural stratum.
    RecursiveAncestry,
    /// Negative-plan structural stratum.
    NegativePlan,
    /// Detached subject-catalog structural stratum.
    SubjectCatalog,
    /// Terminal-fixture-catalog structural stratum.
    TerminalFixtureCatalog,
    /// Positive-registry structural stratum.
    PositiveRegistry,
    /// Expanded-negative-registry structural stratum.
    ExpandedNegativeRegistry,
    /// Mutation-identities structural stratum.
    MutationIdentities,
    /// Rust negative-results structural stratum.
    RustNegativeResults,
    /// JVM negative-results structural stratum.
    JvmNegativeResults,
    /// Semantic-report structural stratum.
    SemanticReport,
    /// Tree-manifest structural stratum.
    TreeManifest,
    /// Terminal-lock structural stratum.
    Lock,
    /// One fixed synthetic role used only by the extra-role negative probe.
    UnregisteredExtra,
}

impl B4AbstractCorpusRole {
    const fn ordinal(self) -> u8 {
        match self {
            Self::ProfileManifest => 0,
            Self::StatementBundleManifest => 1,
            Self::GuestElf => 2,
            Self::SourceLock => 3,
            Self::ProofGenerator => 4,
            Self::RustVerifier => 5,
            Self::JvmVerifier => 6,
            Self::PositiveRawSeal => 7,
            Self::RecursiveAncestry => 8,
            Self::NegativePlan => 9,
            Self::SubjectCatalog => 10,
            Self::TerminalFixtureCatalog => 11,
            Self::PositiveRegistry => 12,
            Self::ExpandedNegativeRegistry => 13,
            Self::MutationIdentities => 14,
            Self::RustNegativeResults => 15,
            Self::JvmNegativeResults => 16,
            Self::SemanticReport => 17,
            Self::TreeManifest => 18,
            Self::Lock => 19,
            Self::UnregisteredExtra => 20,
        }
    }

    const fn semantic_id(self) -> &'static str {
        match self {
            Self::ProfileManifest => "profile-manifest",
            Self::StatementBundleManifest => "statement-bundle-manifest",
            Self::GuestElf => "guest-elf",
            Self::SourceLock => "source-lock",
            Self::ProofGenerator => "proof-generator",
            Self::RustVerifier => "rust-verifier",
            Self::JvmVerifier => "jvm-verifier",
            Self::PositiveRawSeal => "positive-raw-seal",
            Self::RecursiveAncestry => "recursive-ancestry",
            Self::NegativePlan => "negative-plan",
            Self::SubjectCatalog => "subject-catalog",
            Self::TerminalFixtureCatalog => "terminal-fixture-catalog",
            Self::PositiveRegistry => "positive-registry",
            Self::ExpandedNegativeRegistry => "expanded-negative-registry",
            Self::MutationIdentities => "mutation-identities",
            Self::RustNegativeResults => "rust-negative-results",
            Self::JvmNegativeResults => "jvm-negative-results",
            Self::SemanticReport => "semantic-report",
            Self::TreeManifest => "tree-manifest",
            Self::Lock => "lock",
            Self::UnregisteredExtra => "unregistered-extra",
        }
    }
}

/// Exact accepted structural-role baseline, in canonical semantic order.
pub const B4_REQUIRED_STRUCTURAL_STRATA: [B4AbstractCorpusRole;
    B4_REQUIRED_STRUCTURAL_STRATUM_COUNT] = [
    B4AbstractCorpusRole::ProfileManifest,
    B4AbstractCorpusRole::StatementBundleManifest,
    B4AbstractCorpusRole::GuestElf,
    B4AbstractCorpusRole::SourceLock,
    B4AbstractCorpusRole::ProofGenerator,
    B4AbstractCorpusRole::RustVerifier,
    B4AbstractCorpusRole::JvmVerifier,
    B4AbstractCorpusRole::PositiveRawSeal,
    B4AbstractCorpusRole::RecursiveAncestry,
    B4AbstractCorpusRole::NegativePlan,
    B4AbstractCorpusRole::SubjectCatalog,
    B4AbstractCorpusRole::TerminalFixtureCatalog,
    B4AbstractCorpusRole::PositiveRegistry,
    B4AbstractCorpusRole::ExpandedNegativeRegistry,
    B4AbstractCorpusRole::MutationIdentities,
    B4AbstractCorpusRole::RustNegativeResults,
    B4AbstractCorpusRole::JvmNegativeResults,
    B4AbstractCorpusRole::SemanticReport,
    B4AbstractCorpusRole::TreeManifest,
    B4AbstractCorpusRole::Lock,
];

/// Strict V1 abstract tree model. It deliberately contains roles only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Eip0045B4AbstractTreeV1 {
    /// Exact abstract-tree format label.
    pub format: String,
    /// Exact abstract-tree format version.
    pub format_version: u8,
    /// Canonically ordered closed structural roles.
    pub roles: Vec<B4AbstractCorpusRole>,
}

impl Eip0045B4AbstractTreeV1 {
    /// Construct the one accepted twenty-role baseline.
    ///
    /// # Errors
    ///
    /// Returns an error if the compiled role inventory is inconsistent.
    pub fn canonical_baseline() -> Result<Self> {
        let model = Self {
            format: B4_ABSTRACT_TREE_FORMAT.to_owned(),
            format_version: B4_ABSTRACT_TREE_FORMAT_VERSION,
            roles: B4_REQUIRED_STRUCTURAL_STRATA.to_vec(),
        };
        model.validate_shape()?;
        ensure!(
            validate_abstract_tree_policy(&model)? == B4AbstractTreePolicyOutcome::Accepted,
            "canonical abstract tree baseline does not satisfy its policy"
        );
        Ok(model)
    }

    /// Parse exact RFC 8785 JCS into the closed abstract grammar.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, noncanonical, duplicate-field,
    /// unknown-field, duplicate-role, or noncanonically ordered material.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            source.len() <= MAX_ABSTRACT_TREE_BYTES,
            "abstract B4 tree exceeds the canonical-byte bound"
        );
        let value = validate_canonical_json_source(source)
            .context("abstract B4 tree is not exact RFC 8785 JCS")?;
        let model: Self =
            serde_json::from_value(value).context("invalid abstract B4 tree shape")?;
        model.validate_shape()?;
        ensure!(
            model.to_canonical_jcs()? == source,
            "abstract B4 tree does not round-trip byte-exactly"
        );
        Ok(model)
    }

    /// Serialize the closed abstract grammar as exact RFC 8785 JCS.
    ///
    /// # Errors
    ///
    /// Returns an error when the model is invalid or exceeds its byte bound.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.validate_shape()?;
        let value = serde_json::to_value(self).context("cannot serialize abstract B4 tree")?;
        let bytes = canonical_json_bytes(&value)?;
        ensure!(
            bytes.len() <= MAX_ABSTRACT_TREE_BYTES,
            "abstract B4 tree exceeds the canonical-byte bound"
        );
        Ok(bytes)
    }

    fn validate_shape(&self) -> Result<()> {
        ensure!(
            self.format == B4_ABSTRACT_TREE_FORMAT,
            "wrong abstract B4 tree format label"
        );
        ensure!(
            self.format_version == B4_ABSTRACT_TREE_FORMAT_VERSION,
            "wrong abstract B4 tree format version"
        );
        ensure!(
            !self.roles.is_empty() && self.roles.len() <= B4_REQUIRED_STRUCTURAL_STRATUM_COUNT + 1,
            "abstract B4 role count is outside the closed bound"
        );
        let mut unique = BTreeSet::new();
        for role in &self.roles {
            ensure!(unique.insert(*role), "duplicate abstract B4 role");
        }
        ensure!(
            self.roles
                .windows(2)
                .all(|pair| pair[0].ordinal() < pair[1].ordinal()),
            "abstract B4 roles are not in canonical semantic order"
        );
        Ok(())
    }
}

/// Closed policy result for one structurally valid abstract tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum B4AbstractTreePolicyOutcome {
    /// The model contains exactly the twenty required roles.
    Accepted,
    /// The model violates one closed tree-policy condition.
    Rejected(B4AbstractTreePolicyRejection),
}

/// Exact normalized rejection emitted by the abstract tree policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct B4AbstractTreePolicyRejection {
    /// Exact surface which owns abstract tree closure.
    pub execution_surface: B4NegativeExecutionSurface,
    /// Exact normalized result derived by the tree policy.
    pub qa_result_code: B4NegativeQaResultCode,
}

/// Validate the closed role-set policy without reading a physical tree.
///
/// # Errors
///
/// Returns an error when the supplied model is outside the strict V1 grammar.
pub fn validate_abstract_tree_policy(
    model: &Eip0045B4AbstractTreeV1,
) -> Result<B4AbstractTreePolicyOutcome> {
    model.validate_shape()?;
    if model
        .roles
        .contains(&B4AbstractCorpusRole::UnregisteredExtra)
    {
        return Ok(B4AbstractTreePolicyOutcome::Rejected(
            B4AbstractTreePolicyRejection {
                execution_surface: B4NegativeExecutionSurface::CorpusClosure,
                qa_result_code: B4NegativeQaResultCode::B4CorpusExtraFile,
            },
        ));
    }
    if model.roles.as_slice() != B4_REQUIRED_STRUCTURAL_STRATA {
        return Ok(B4AbstractTreePolicyOutcome::Rejected(
            B4AbstractTreePolicyRejection {
                execution_surface: B4NegativeExecutionSurface::CorpusClosure,
                qa_result_code: B4NegativeQaResultCode::B4CorpusRepresentativeStratumMissing,
            },
        ));
    }
    Ok(B4AbstractTreePolicyOutcome::Accepted)
}

/// Canonical replay view for one abstract-tree base/output pair.
///
/// The view owns no authority and serializes nothing. It authenticates the
/// plan-selected baseline, independently re-applies the registry recipe, and
/// derives the first typed rejection by running the tree policy on the exact
/// reconstructed output.
#[derive(Clone, Copy, Debug)]
pub struct B4TreeProbeReplayAdapterV1<'a> {
    base_jcs: &'a [u8],
    output_jcs: &'a [u8],
}

impl<'a> B4TreeProbeReplayAdapterV1<'a> {
    /// Construct a replay view over exact role-only JCS bytes.
    #[must_use]
    pub const fn new(base_jcs: &'a [u8], output_jcs: &'a [u8]) -> Self {
        Self {
            base_jcs,
            output_jcs,
        }
    }

    /// Re-apply one exact tree recipe and derive its typed policy rejection.
    ///
    /// # Errors
    ///
    /// Returns an error for selector drift, a noncanonical or non-baseline
    /// base, a wrong domain recipe, a wrong target or element witness, output
    /// drift, or a materialization accepted by the tree policy.
    pub fn replay_and_observe_rejection(
        &self,
        base_selector_id: &str,
        materialization: &B4NegativeMaterialization,
    ) -> Result<B4AbstractTreePolicyRejection> {
        ensure!(
            base_selector_id == ABSTRACT_CORPUS_SELECTOR,
            "tree-probe adapter received the wrong base selector"
        );
        let baseline = Eip0045B4AbstractTreeV1::from_canonical_jcs(self.base_jcs)?;
        ensure!(
            baseline == Eip0045B4AbstractTreeV1::canonical_baseline()?,
            "tree-probe base is not the exact canonical role baseline"
        );
        ensure!(
            validate_abstract_tree_policy(&baseline)? == B4AbstractTreePolicyOutcome::Accepted,
            "tree-probe base is not accepted by the tree policy"
        );

        let reconstructed = apply_tree_recipe(&baseline, materialization)?;
        let reconstructed_jcs = reconstructed.to_canonical_jcs()?;
        ensure!(
            reconstructed_jcs == self.output_jcs,
            "tree-probe output differs from independent recipe replay"
        );
        let supplied_output = Eip0045B4AbstractTreeV1::from_canonical_jcs(self.output_jcs)?;
        ensure!(
            supplied_output == reconstructed,
            "tree-probe output model differs from independent recipe replay"
        );
        match validate_abstract_tree_policy(&supplied_output)? {
            B4AbstractTreePolicyOutcome::Rejected(rejection) => Ok(rejection),
            B4AbstractTreePolicyOutcome::Accepted => {
                bail!("tree-probe recipe produced an accepted output")
            }
        }
    }
}

impl B4MaterializationReplayAdapterV1 for B4TreeProbeReplayAdapterV1<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::TreeValidator
    }

    fn base_bytes(&self) -> &[u8] {
        self.base_jcs
    }

    fn output_bytes(&self) -> &[u8] {
        self.output_jcs
    }

    fn replay_recipe(
        &self,
        base_selector_id: &str,
        materialization: &B4NegativeMaterialization,
    ) -> Result<()> {
        self.replay_and_observe_rejection(base_selector_id, materialization)?;
        Ok(())
    }
}

/// In-memory deterministic materialization of one tree-domain plan execution.
///
/// This is a replay view, not a canonical published record. The generic B4
/// evidence layer owns the sole serializable materialization identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B4MaterializedTreeProbeV1 {
    /// Exact canonical bytes of the accepted abstract baseline.
    pub base_jcs: Vec<u8>,
    /// Exact canonical bytes of the single-fault mutated model.
    pub output_jcs: Vec<u8>,
    /// Exact registry row whose recipe reconstructs `output_jcs` from `base_jcs`.
    pub registry_row: B4NegativeCase,
    /// Exact rejection independently derived by the tree policy.
    pub observed_rejection: B4AbstractTreePolicyRejection,
}

impl B4MaterializedTreeProbeV1 {
    /// Borrow this materialization through the canonical replay adapter.
    #[must_use]
    pub fn adapter(&self) -> B4TreeProbeReplayAdapterV1<'_> {
        B4TreeProbeReplayAdapterV1::new(&self.base_jcs, &self.output_jcs)
    }
}

/// Materialize one of the exact 21 abstract tree-domain plan executions.
///
/// # Errors
///
/// Returns an error unless the plan is exact canonical V1 authority, the
/// execution is one of its literal tree-domain rows, its recipe has exact
/// role witnesses, and the independently run policy produces the planned
/// surface and QA code.
pub fn materialize_tree_probe(
    negative_plan_source: &[u8],
    execution_id: &str,
) -> Result<B4MaterializedTreeProbeV1> {
    let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(negative_plan_source)?;
    validate_literal_tree_inventory(&plan)?;
    ensure!(
        B4_TREE_PROBE_EXECUTION_IDS.contains(&execution_id),
        "execution ID is outside the literal tree-probe inventory"
    );
    let execution = find_execution(&plan, execution_id)?;
    validate_tree_execution_contract(execution)?;

    let baseline = Eip0045B4AbstractTreeV1::canonical_baseline()?;
    let materialization = recipe_for_execution(execution, &baseline)?;
    let output = independently_materialize_execution(execution, &baseline)?;
    let base_jcs = baseline.to_canonical_jcs()?;
    let output_jcs = output.to_canonical_jcs()?;
    let registry_row = B4NegativeCase {
        execution_id: execution.execution_id.clone(),
        base_selector_id: execution.base_selector_id.clone(),
        materialization_domain: execution.materialization_domain,
        materialization,
    };
    let adapter = B4TreeProbeReplayAdapterV1::new(&base_jcs, &output_jcs);
    let observed_rejection = adapter.replay_and_observe_rejection(
        &registry_row.base_selector_id,
        &registry_row.materialization,
    )?;
    ensure!(
        observed_rejection.execution_surface == execution.execution_surface,
        "tree policy rejected at a different surface than the canonical plan"
    );
    ensure!(
        observed_rejection.qa_result_code == execution.qa_result_code,
        "tree policy emitted a different QA code than the canonical plan"
    );

    Ok(B4MaterializedTreeProbeV1 {
        base_jcs,
        output_jcs,
        registry_row,
        observed_rejection,
    })
}

/// Verify a materialized tree probe and return its sole generic identity.
///
/// # Errors
///
/// Returns an error for any plan, execution, selector, domain, recipe, role
/// witness, base, output, policy-rejection, or deterministic-row drift.
pub fn verify_tree_probe_materialization(
    materialized: &B4MaterializedTreeProbeV1,
    negative_plan_source: &[u8],
) -> Result<Eip0045B4MaterializationIdentityV1> {
    let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(negative_plan_source)?;
    validate_literal_tree_inventory(&plan)?;
    let execution = find_execution(&plan, &materialized.registry_row.execution_id)?;
    validate_tree_execution_contract(execution)?;
    ensure!(
        materialized.registry_row.base_selector_id == execution.base_selector_id,
        "tree-probe registry row selects a different plan base"
    );
    ensure!(
        materialized.registry_row.materialization_domain == execution.materialization_domain,
        "tree-probe registry row names a different plan domain"
    );

    let adapter = materialized.adapter();
    let observed = adapter.replay_and_observe_rejection(
        &materialized.registry_row.base_selector_id,
        &materialized.registry_row.materialization,
    )?;
    ensure!(
        observed == materialized.observed_rejection,
        "tree-probe claimed rejection differs from the policy observation"
    );
    ensure!(
        observed.execution_surface == execution.execution_surface
            && observed.qa_result_code == execution.qa_result_code,
        "tree-probe policy observation differs from the canonical plan"
    );

    let identity = create_materialization_identity_with_adapter(
        negative_plan_source,
        &materialized.registry_row,
        &adapter,
    )?;
    verify_materialization_identity_with_adapter(
        &identity,
        negative_plan_source,
        &materialized.registry_row,
        &adapter,
    )?;

    let rebuilt = materialize_tree_probe(negative_plan_source, &execution.execution_id)?;
    ensure!(
        materialized == &rebuilt,
        "tree-probe materialization differs from exact deterministic reconstruction"
    );
    Ok(identity)
}

fn validate_literal_tree_inventory(plan: &Eip0045B4NegativePlanV1) -> Result<()> {
    let tree_ids = plan
        .groups
        .iter()
        .flat_map(|group| group.executions.iter())
        .filter(|execution| {
            execution.materialization_domain == B4MaterializationDomain::TreeValidator
        })
        .map(|execution| execution.execution_id.as_str())
        .collect::<Vec<_>>();
    ensure!(
        tree_ids == B4_TREE_PROBE_EXECUTION_IDS,
        "canonical plan tree inventory differs from the literal 21-execution contract"
    );
    Ok(())
}

fn validate_tree_execution_contract(execution: &B4NegativePlanExecutionV1) -> Result<()> {
    ensure!(
        execution.materialization_domain == B4MaterializationDomain::TreeValidator,
        "B4 execution is not owned by the tree validator"
    );
    ensure!(
        execution.execution_surface == B4NegativeExecutionSurface::CorpusClosure,
        "B4 tree execution does not use corpus closure"
    );
    ensure!(
        execution.base_selector_id == ABSTRACT_CORPUS_SELECTOR,
        "B4 tree execution does not select the abstract corpus strata"
    );
    ensure!(
        B4_TREE_PROBE_EXECUTION_IDS.contains(&execution.execution_id.as_str()),
        "B4 tree execution is outside the literal inventory"
    );
    Ok(())
}

fn find_execution<'a>(
    plan: &'a Eip0045B4NegativePlanV1,
    execution_id: &str,
) -> Result<&'a B4NegativePlanExecutionV1> {
    let mut matches = plan
        .groups
        .iter()
        .flat_map(|group| group.executions.iter())
        .filter(|execution| execution.execution_id == execution_id);
    let execution = matches
        .next()
        .context("B4 tree-probe execution ID is absent from the exact plan")?;
    ensure!(
        matches.next().is_none(),
        "B4 negative plan contains duplicate tree-probe execution IDs"
    );
    Ok(execution)
}

fn recipe_for_execution(
    execution: &B4NegativePlanExecutionV1,
    baseline: &Eip0045B4AbstractTreeV1,
) -> Result<B4NegativeMaterialization> {
    if let Some(variant_id) = execution.execution_id.strip_prefix(OMIT_EXECUTION_PREFIX) {
        ensure!(
            variant_id == execution.variant_id,
            "tree omission execution ID and variant ID differ"
        );
        let role = role_for_plan_variant(variant_id)
            .context("tree omission variant does not name one required stratum")?;
        let index = baseline
            .roles
            .iter()
            .position(|candidate| *candidate == role)
            .context("required abstract stratum is absent from the baseline")?;
        let witness = role_witness(role)?;
        return Ok(B4NegativeMaterialization::Mutation {
            mutation: B4NegativeMutation::SequenceEdit {
                edit: B4SequenceOperation::Omit {
                    before_element_id: witness.element_id,
                    before_element_sha256: witness.sha256,
                    index: u64::try_from(index).context("tree role index exceeds u64")?,
                },
                target: B4SequenceTarget::AbstractTreeProbe,
            },
        });
    }
    ensure!(
        execution.execution_id == EXTRA_EXECUTION_ID && execution.variant_id == "unregistered-file",
        "tree execution has no closed materialization recipe"
    );
    Ok(B4NegativeMaterialization::Mutation {
        mutation: B4NegativeMutation::SequenceEdit {
            edit: B4SequenceOperation::Insert {
                inserted_element: role_witness(B4AbstractCorpusRole::UnregisteredExtra)?,
                index: u64::try_from(baseline.roles.len())
                    .context("tree role count exceeds u64")?,
            },
            target: B4SequenceTarget::AbstractTreeProbe,
        },
    })
}

fn independently_materialize_execution(
    execution: &B4NegativePlanExecutionV1,
    baseline: &Eip0045B4AbstractTreeV1,
) -> Result<Eip0045B4AbstractTreeV1> {
    let mut output = baseline.clone();
    if let Some(variant_id) = execution.execution_id.strip_prefix(OMIT_EXECUTION_PREFIX) {
        let role = role_for_plan_variant(variant_id)
            .context("tree omission variant does not name one required stratum")?;
        let index = output
            .roles
            .iter()
            .position(|candidate| *candidate == role)
            .context("required abstract stratum is absent from the baseline")?;
        output.roles.remove(index);
    } else {
        ensure!(
            execution.execution_id == EXTRA_EXECUTION_ID,
            "tree execution has no closed output materialization"
        );
        output.roles.push(B4AbstractCorpusRole::UnregisteredExtra);
    }
    output.validate_shape()?;
    Ok(output)
}

fn apply_tree_recipe(
    baseline: &Eip0045B4AbstractTreeV1,
    materialization: &B4NegativeMaterialization,
) -> Result<Eip0045B4AbstractTreeV1> {
    let B4NegativeMaterialization::Mutation {
        mutation: B4NegativeMutation::SequenceEdit { edit, target },
    } = materialization
    else {
        bail!("tree-probe adapter requires one sequence-edit mutation")
    };
    ensure!(
        *target == B4SequenceTarget::AbstractTreeProbe,
        "tree-probe recipe uses the wrong sequence target"
    );

    let mut reconstructed = baseline.clone();
    let expected_role_count = match edit {
        B4SequenceOperation::Omit {
            before_element_id,
            before_element_sha256,
            index,
        } => {
            let index = usize::try_from(*index).context("tree omission index exceeds usize")?;
            let role = reconstructed
                .roles
                .get(index)
                .copied()
                .context("tree omission index is outside the baseline")?;
            ensure!(
                role != B4AbstractCorpusRole::UnregisteredExtra,
                "tree omission recipe cannot target the synthetic extra role"
            );
            let witness = role_witness(role)?;
            ensure!(
                before_element_id == &witness.element_id,
                "tree omission element ID does not witness the indexed role"
            );
            ensure!(
                before_element_sha256 == &witness.sha256,
                "tree omission element SHA-256 does not witness the indexed role"
            );
            reconstructed.roles.remove(index);
            B4_REQUIRED_STRUCTURAL_STRATUM_COUNT - 1
        }
        B4SequenceOperation::Insert {
            inserted_element,
            index,
        } => {
            let index = usize::try_from(*index).context("tree insertion index exceeds usize")?;
            ensure!(
                index == reconstructed.roles.len(),
                "tree extra-role insertion is not at the canonical terminal index"
            );
            let inserted_role = role_from_inserted_witness(inserted_element)?;
            ensure!(
                inserted_role == B4AbstractCorpusRole::UnregisteredExtra,
                "tree insertion does not name the one closed synthetic extra role"
            );
            reconstructed.roles.insert(index, inserted_role);
            B4_REQUIRED_STRUCTURAL_STRATUM_COUNT + 1
        }
        _ => bail!("tree-probe recipe uses an inadmissible sequence operation"),
    };
    ensure!(
        reconstructed.roles.len() == expected_role_count,
        "tree-probe output has the wrong exact role count"
    );
    ensure!(
        reconstructed
            .roles
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len()
            == expected_role_count,
        "tree-probe output contains a duplicate role"
    );
    reconstructed.validate_shape()?;
    Ok(reconstructed)
}

fn role_witness(role: B4AbstractCorpusRole) -> Result<B4SequenceSubjectElement> {
    let value = serde_json::to_value(role).context("cannot serialize abstract tree role")?;
    let bytes = canonical_json_bytes(&value)?;
    let witness = B4SequenceSubjectElement::from_bytes(role.semantic_id(), &bytes)?;
    witness.validate_for(B4SequenceTarget::AbstractTreeProbe)?;
    Ok(witness)
}

fn role_from_inserted_witness(witness: &B4SequenceSubjectElement) -> Result<B4AbstractCorpusRole> {
    witness.validate_for(B4SequenceTarget::AbstractTreeProbe)?;
    let bytes = witness.decoded_bytes()?;
    let value = validate_canonical_json_source(&bytes)
        .context("inserted tree-role witness is not exact RFC 8785 JCS")?;
    let role: B4AbstractCorpusRole =
        serde_json::from_value(value).context("inserted tree-role witness is not a closed role")?;
    ensure!(
        witness == &role_witness(role)?,
        "inserted tree-role element identity does not match its canonical role bytes"
    );
    Ok(role)
}

fn role_for_plan_variant(variant_id: &str) -> Option<B4AbstractCorpusRole> {
    B4_REQUIRED_STRUCTURAL_STRATA
        .iter()
        .copied()
        .find(|role| role.semantic_id() == variant_id)
}

#[cfg(test)]
fn sha256_hex(source: &[u8]) -> String {
    hex::encode(Sha256::digest(source))
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::{
        b4_mutation::{
            Eip0045B4MaterializationIdentityV1, create_materialization_identity_with_adapter,
            verify_materialization_identity_with_adapter,
        },
        canonical::canonical_json_bytes,
    };

    fn plan_source() -> Vec<u8> {
        Eip0045B4NegativePlanV1::canonical()
            .unwrap()
            .to_canonical_jcs()
            .unwrap()
    }

    fn tree_execution_ids(plan: &Eip0045B4NegativePlanV1) -> Vec<&str> {
        plan.groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .filter(|execution| {
                execution.materialization_domain == B4MaterializationDomain::TreeValidator
            })
            .map(|execution| execution.execution_id.as_str())
            .collect()
    }

    #[test]
    fn baseline_is_the_exact_twenty_role_model_and_accepts() {
        let baseline = Eip0045B4AbstractTreeV1::canonical_baseline().unwrap();
        assert_eq!(baseline.roles, B4_REQUIRED_STRUCTURAL_STRATA);
        assert_eq!(baseline.roles.len(), B4_REQUIRED_STRUCTURAL_STRATUM_COUNT);
        assert_eq!(
            validate_abstract_tree_policy(&baseline).unwrap(),
            B4AbstractTreePolicyOutcome::Accepted
        );

        let source = baseline.to_canonical_jcs().unwrap();
        assert_eq!(
            Eip0045B4AbstractTreeV1::from_canonical_jcs(&source).unwrap(),
            baseline
        );
    }

    #[test]
    fn all_twenty_one_literal_executions_use_the_generic_identity_and_unique_outputs() {
        let plan_source = plan_source();
        let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(&plan_source).unwrap();
        assert_eq!(
            tree_execution_ids(&plan),
            B4_TREE_PROBE_EXECUTION_IDS.to_vec()
        );

        let mut output_digests = BTreeSet::new();
        for execution_id in B4_TREE_PROBE_EXECUTION_IDS {
            let execution = find_execution(&plan, execution_id).unwrap();
            let materialized = materialize_tree_probe(&plan_source, execution_id).unwrap();
            assert_eq!(materialized.registry_row.execution_id, execution_id);
            assert_eq!(
                materialized.registry_row.base_selector_id,
                ABSTRACT_CORPUS_SELECTOR
            );
            assert_eq!(
                materialized.registry_row.materialization_domain,
                B4MaterializationDomain::TreeValidator
            );
            assert_eq!(
                materialized.observed_rejection,
                B4AbstractTreePolicyRejection {
                    execution_surface: execution.execution_surface,
                    qa_result_code: execution.qa_result_code,
                }
            );

            let adapter = materialized.adapter();
            let identity = create_materialization_identity_with_adapter(
                &plan_source,
                &materialized.registry_row,
                &adapter,
            )
            .unwrap();
            let identity_source = identity.to_canonical_jcs().unwrap();
            assert_eq!(
                Eip0045B4MaterializationIdentityV1::from_canonical_jcs(&identity_source).unwrap(),
                identity
            );
            verify_materialization_identity_with_adapter(
                &identity,
                &plan_source,
                &materialized.registry_row,
                &adapter,
            )
            .unwrap();
            assert_eq!(
                verify_tree_probe_materialization(&materialized, &plan_source).unwrap(),
                identity
            );
            assert!(output_digests.insert(identity.output_sha256));

            match &materialized.registry_row.materialization {
                B4NegativeMaterialization::Mutation {
                    mutation:
                        B4NegativeMutation::SequenceEdit {
                            edit: B4SequenceOperation::Omit { .. },
                            target: B4SequenceTarget::AbstractTreeProbe,
                        },
                } => assert!(execution_id.starts_with(OMIT_EXECUTION_PREFIX)),
                B4NegativeMaterialization::Mutation {
                    mutation:
                        B4NegativeMutation::SequenceEdit {
                            edit: B4SequenceOperation::Insert { .. },
                            target: B4SequenceTarget::AbstractTreeProbe,
                        },
                } => assert_eq!(execution_id, EXTRA_EXECUTION_ID),
                _ => panic!("tree probe has a non-tree materialization recipe"),
            }
        }
        assert_eq!(output_digests.len(), B4_TREE_PROBE_EXECUTION_COUNT);

        let non_tree = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .find(|execution| {
                execution.materialization_domain != B4MaterializationDomain::TreeValidator
            })
            .unwrap();
        assert!(materialize_tree_probe(&plan_source, &non_tree.execution_id).is_err());
    }

    #[test]
    fn abstract_models_are_strict_bounded_role_only_jcs() {
        let baseline = Eip0045B4AbstractTreeV1::canonical_baseline().unwrap();
        let pretty = serde_json::to_vec_pretty(&baseline).unwrap();
        assert!(Eip0045B4AbstractTreeV1::from_canonical_jcs(&pretty).is_err());
        assert!(
            Eip0045B4AbstractTreeV1::from_canonical_jcs(&vec![b' '; MAX_ABSTRACT_TREE_BYTES + 1])
                .is_err()
        );
        let duplicate = br#"{"format":"Eip0045B4AbstractTreeV1","format":"Eip0045B4AbstractTreeV1","formatVersion":1,"roles":[]}"#;
        assert!(Eip0045B4AbstractTreeV1::from_canonical_jcs(duplicate).is_err());

        let mut value = serde_json::to_value(&baseline).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), Value::Bool(true));
        assert!(
            Eip0045B4AbstractTreeV1::from_canonical_jcs(&canonical_json_bytes(&value).unwrap())
                .is_err()
        );

        let keys = serde_json::to_value(&baseline)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            keys,
            ["format", "formatVersion", "roles"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
        let source = baseline.to_canonical_jcs().unwrap();
        let text = std::str::from_utf8(&source).unwrap();
        for forbidden in [
            "physicalPath",
            "manifestBytes",
            "lockBytes",
            "createdAt",
            "timestamp",
            "host",
        ] {
            assert!(!text.contains(forbidden));
        }
    }

    #[test]
    fn corrupted_recipe_selector_domain_and_output_fail_closed() {
        let plan_source = plan_source();
        let mut wrong_witness = materialize_tree_probe(
            &plan_source,
            "corpus-representative-stratum-omit-sweep--profile-manifest",
        )
        .unwrap();
        let B4NegativeMaterialization::Mutation {
            mutation:
                B4NegativeMutation::SequenceEdit {
                    edit:
                        B4SequenceOperation::Omit {
                            before_element_sha256,
                            ..
                        },
                    ..
                },
        } = &mut wrong_witness.registry_row.materialization
        else {
            panic!("expected omission recipe")
        };
        *before_element_sha256 = "00".repeat(32);
        assert!(verify_tree_probe_materialization(&wrong_witness, &plan_source).is_err());

        let mut wrong_selector = materialize_tree_probe(
            &plan_source,
            "corpus-representative-stratum-omit-sweep--profile-manifest",
        )
        .unwrap();
        wrong_selector.registry_row.base_selector_id = "synthetic-registry-skeleton-v1".to_owned();
        assert!(verify_tree_probe_materialization(&wrong_selector, &plan_source).is_err());

        let mut wrong_domain = materialize_tree_probe(
            &plan_source,
            "corpus-representative-stratum-omit-sweep--profile-manifest",
        )
        .unwrap();
        wrong_domain.registry_row.materialization_domain = B4MaterializationDomain::VerifierInput;
        assert!(verify_tree_probe_materialization(&wrong_domain, &plan_source).is_err());

        let other_output = materialize_tree_probe(
            &plan_source,
            "corpus-representative-stratum-omit-sweep--statement-bundle-manifest",
        )
        .unwrap()
        .output_jcs;
        let mut wrong_output = materialize_tree_probe(
            &plan_source,
            "corpus-representative-stratum-omit-sweep--profile-manifest",
        )
        .unwrap();
        wrong_output.output_jcs = other_output;
        assert!(verify_tree_probe_materialization(&wrong_output, &plan_source).is_err());
    }

    #[test]
    fn corrupted_target_element_witness_and_qa_rejection_fail_closed() {
        let plan_source = plan_source();
        let mut wrong_target = materialize_tree_probe(
            &plan_source,
            "corpus-representative-stratum-omit-sweep--profile-manifest",
        )
        .unwrap();
        let B4NegativeMaterialization::Mutation {
            mutation: B4NegativeMutation::SequenceEdit { target, .. },
        } = &mut wrong_target.registry_row.materialization
        else {
            panic!("expected sequence-edit recipe")
        };
        *target = B4SequenceTarget::RegistryNegativeCases;
        assert!(verify_tree_probe_materialization(&wrong_target, &plan_source).is_err());

        let mut wrong_omitted_id = materialize_tree_probe(
            &plan_source,
            "corpus-representative-stratum-omit-sweep--profile-manifest",
        )
        .unwrap();
        let B4NegativeMaterialization::Mutation {
            mutation:
                B4NegativeMutation::SequenceEdit {
                    edit:
                        B4SequenceOperation::Omit {
                            before_element_id, ..
                        },
                    ..
                },
        } = &mut wrong_omitted_id.registry_row.materialization
        else {
            panic!("expected omission recipe")
        };
        *before_element_id = "statement-bundle-manifest".to_owned();
        assert!(verify_tree_probe_materialization(&wrong_omitted_id, &plan_source).is_err());

        let mut wrong_inserted_id =
            materialize_tree_probe(&plan_source, EXTRA_EXECUTION_ID).unwrap();
        let B4NegativeMaterialization::Mutation {
            mutation:
                B4NegativeMutation::SequenceEdit {
                    edit:
                        B4SequenceOperation::Insert {
                            inserted_element, ..
                        },
                    ..
                },
        } = &mut wrong_inserted_id.registry_row.materialization
        else {
            panic!("expected insertion recipe")
        };
        inserted_element.element_id = "different-extra".to_owned();
        assert!(verify_tree_probe_materialization(&wrong_inserted_id, &plan_source).is_err());

        let mut wrong_qa = materialize_tree_probe(
            &plan_source,
            "corpus-representative-stratum-omit-sweep--profile-manifest",
        )
        .unwrap();
        wrong_qa.observed_rejection.qa_result_code = B4NegativeQaResultCode::B4CorpusExtraFile;
        assert!(verify_tree_probe_materialization(&wrong_qa, &plan_source).is_err());
    }

    #[test]
    fn no_second_tree_materialization_record_is_serialized() {
        let plan_source = plan_source();
        let materialized = materialize_tree_probe(&plan_source, EXTRA_EXECUTION_ID).unwrap();
        let identity = verify_tree_probe_materialization(&materialized, &plan_source).unwrap();
        let identity_value = serde_json::to_value(identity).unwrap();
        assert_eq!(
            identity_value["format"],
            Value::String("Eip0045B4MaterializationIdentityV1".to_owned())
        );
        let recipe_value =
            serde_json::to_value(&materialized.registry_row.materialization).unwrap();
        let recipe_text = canonical_json_bytes(&recipe_value).unwrap();
        let recipe_text = std::str::from_utf8(&recipe_text).unwrap();
        assert!(recipe_text.contains("abstract-tree-probe"));
        assert!(!recipe_text.contains("TreeProbeMaterialization"));
        assert_eq!(
            sha256_hex(&materialized.base_jcs),
            sha256_hex(
                &Eip0045B4AbstractTreeV1::canonical_baseline()
                    .unwrap()
                    .to_canonical_jcs()
                    .unwrap()
            )
        );
    }
}
