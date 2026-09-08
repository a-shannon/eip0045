//! Non-cyclic materializers for the registry-owned EIP-0045 B4 probes.
//!
//! Candidate-registry grammar probes start from the checked-in skeleton.
//! Negative-row and plan-bijection probes start from a strict JCS index derived
//! directly from the canonical plan. Neither baseline reads the future expanded
//! registry, semantic report, materialization identities, or verifier results.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::b4::{
    B4ByteOperation, B4ByteTarget, B4CandidateCorpus, B4NegativeCase, B4NegativeClass,
    B4NegativeMaterialization, B4NegativeMutation, B4SequenceOperation, B4SequenceTarget,
};
use crate::b4_mutation::{B4MaterializationReplayAdapterV1, reconstruct_mutation};
use crate::b4_plan::{
    B4_NEGATIVE_PLAN_VARIANT_COUNT, B4MaterializationDomain, B4NegativeExecutionSurface,
    B4NegativePlanExecutionV1, B4NegativeQaResultCode, Eip0045B4NegativePlanV1,
    negative_group_requires_fixture_selection,
};
use crate::b4_subject::{B4SequenceSubjectElement, Eip0045B4SequenceSubjectV1};
use crate::canonical::{canonical_json_bytes, validate_canonical_json_source};

/// Exact selector of the independently reconstructed candidate-registry baseline.
pub const B4_SYNTHETIC_REGISTRY_SKELETON_ID: &str = "synthetic-registry-skeleton-v1";
/// Exact selector of the independently reconstructed negative-binding baseline.
pub const B4_SYNTHETIC_NEGATIVE_BINDING_INDEX_ID: &str = "synthetic-negative-binding-index-v1";
/// Exact format discriminator for the negative-binding index.
pub const B4_NEGATIVE_BINDING_INDEX_FORMAT: &str = "Eip0045B4NegativeBindingIndexV1";
/// Exact format version for the negative-binding index.
pub const B4_NEGATIVE_BINDING_INDEX_FORMAT_VERSION: u8 = 1;

const MAX_INDEX_BYTES: usize = 8 * 1024 * 1024;
const MAX_INDEX_ROWS: usize = B4_NEGATIVE_PLAN_VARIANT_COUNT as usize + 1;
const MAX_PROBE_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_IDENTIFIER_COMPONENT_BYTES: usize = 128;
const SYNTHETIC_REGISTRY_SOURCE: &[u8] = include_bytes!("../schema/b4-corpus-v1.candidate.json");

const REGISTRY_GROUPS: [&str; 9] = [
    "registry-positive-case-omit-sweep",
    "registry-positive-case-id-duplicate",
    "registry-negative-case-id-duplicate",
    "registry-positive-cases-reordered",
    "registry-positive-case-relabel",
    "registry-negative-class-unknown",
    "registry-unknown-field",
    "registry-noncanonical-jcs",
    "negative-plan-registry-bijection-sweep",
];

/// One exact synthetic projection of the four real expanded-negative-row fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4NegativeBindingRowV1 {
    /// Exact execution identity from the canonical plan.
    pub execution_id: String,
    /// Exact independently authoritative base selector from the plan.
    pub base_selector_id: String,
    /// Exact materializer/validator domain from the plan.
    pub materialization_domain: B4MaterializationDomain,
    /// Typed materialization occupying the fourth real registry-row field.
    pub materialization: B4NegativeMaterialization,
}

/// Strict, non-cyclic synthetic index covering all 254 negative executions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Eip0045B4NegativeBindingIndexV1 {
    /// Exact format discriminator.
    pub format: String,
    /// Exact format version.
    pub format_version: u8,
    /// Exact plan-order negative-row projections.
    pub rows: Vec<B4NegativeBindingRowV1>,
}

impl Eip0045B4NegativeBindingIndexV1 {
    /// Construct the independent baseline directly from the validated plan.
    ///
    /// # Errors
    ///
    /// Returns an error when the plan is invalid or a derived row violates the
    /// closed materialization/index grammar.
    pub fn from_plan(plan: &Eip0045B4NegativePlanV1) -> Result<Self> {
        plan.validate().context("invalid B4 negative plan")?;
        let mut rows = Vec::with_capacity(usize::from(B4_NEGATIVE_PLAN_VARIANT_COUNT));
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
            rows.push(B4NegativeBindingRowV1 {
                execution_id: execution.execution_id.clone(),
                base_selector_id: execution.base_selector_id.clone(),
                materialization_domain: execution.materialization_domain,
                materialization: synthetic_materialization(index, &group.case_id, execution)?,
            });
        }
        let index = Self {
            format: B4_NEGATIVE_BINDING_INDEX_FORMAT.to_owned(),
            format_version: B4_NEGATIVE_BINDING_INDEX_FORMAT_VERSION,
            rows,
        };
        index.validate_against_plan(plan)?;
        Ok(index)
    }

    /// Parse exact RFC 8785 JCS and enforce the bounded index grammar.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized, noncanonical, duplicate-field,
    /// unknown-field, lexically invalid, or structurally invalid index.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            source.len() <= MAX_INDEX_BYTES,
            "negative-binding index exceeds its byte bound"
        );
        let value = validate_canonical_json_source(source)
            .context("negative-binding index is not exact RFC 8785 JCS")?;
        let index: Self =
            serde_json::from_value(value).context("invalid negative-binding index shape")?;
        index.validate_internal()?;
        ensure!(
            index.to_canonical_jcs()? == source,
            "negative-binding index does not round-trip byte-exactly"
        );
        Ok(index)
    }

    /// Serialize a valid index as exact RFC 8785 JCS.
    ///
    /// # Errors
    ///
    /// Returns an error when the index violates its closed grammar or its
    /// canonical encoding exceeds the byte bound.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.validate_internal()?;
        canonical_index_bytes(self)
    }

    /// Rebind every row and all four real row fields to the canonical plan.
    ///
    /// # Errors
    ///
    /// Returns an error when the plan or index is invalid, the row inventory is
    /// not bijective, or any plan-derived field or materialization drifts.
    pub fn validate_against_plan(&self, plan: &Eip0045B4NegativePlanV1) -> Result<()> {
        plan.validate().context("invalid B4 negative plan")?;
        self.validate_internal()?;
        ensure!(
            self.rows.len() == usize::from(B4_NEGATIVE_PLAN_VARIANT_COUNT),
            "negative-binding index does not contain exactly 254 rows"
        );
        let mut supplied = self.rows.iter();
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
            let row = supplied
                .next()
                .context("negative-binding index is missing a planned row")?;
            ensure!(
                row.execution_id == execution.execution_id,
                "execution binding drift at row {index}"
            );
            ensure!(
                row.base_selector_id == execution.base_selector_id,
                "base-selector binding drift at row {index}"
            );
            ensure!(
                row.materialization_domain == execution.materialization_domain,
                "materialization-domain drift at row {index}"
            );
            ensure!(
                row.materialization == synthetic_materialization(index, &group.case_id, execution)?,
                "materialization binding drift at row {index}"
            );
        }
        ensure!(
            supplied.next().is_none(),
            "negative-binding index has an unexpected row"
        );
        Ok(())
    }

    fn validate_internal(&self) -> Result<()> {
        ensure!(
            self.format == B4_NEGATIVE_BINDING_INDEX_FORMAT,
            "wrong negative-binding index format"
        );
        ensure!(
            self.format_version == B4_NEGATIVE_BINDING_INDEX_FORMAT_VERSION,
            "wrong negative-binding index version"
        );
        ensure!(
            self.rows.len() <= MAX_INDEX_ROWS,
            "negative-binding index has too many rows"
        );
        let mut execution_ids = BTreeSet::new();
        for (index, row) in self.rows.iter().enumerate() {
            validate_execution_id(&row.execution_id, "negative-binding execution ID")?;
            validate_lower_kebab(&row.base_selector_id, "negative-binding base selector")?;
            ensure!(
                execution_ids.insert(row.execution_id.as_str()),
                "duplicate execution ID at row {index}"
            );
            validate_materialization(&row.materialization)?;
        }
        Ok(())
    }
}

/// Validated plan-owned outcome of one registry probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B4RegistryProbeOutcomeV1 {
    /// Exact execution selected from the canonical plan.
    pub execution_id: String,
    /// Exact independently authoritative base selector.
    pub base_selector_id: String,
    /// Exact plan-owned materialization domain.
    pub materialization_domain: B4MaterializationDomain,
    /// Exact plan-owned validation surface.
    pub execution_surface: B4NegativeExecutionSurface,
    /// Independently classified rejection code, checked against the plan.
    pub qa_result_code: B4NegativeQaResultCode,
}

/// In-memory registry-probe materialization consumed by the single B4 identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B4RegistryProbeMaterializationV1 {
    /// Exact independently reconstructed baseline bytes.
    pub base: Vec<u8>,
    /// Exact mutated bytes supplied to the real artifact validator.
    pub output: Vec<u8>,
    /// Exact plan-bound registry row with the replayable mutation recipe.
    pub registry_row: B4NegativeCase,
    /// Exact validated plan-owned outcome.
    pub outcome: B4RegistryProbeOutcomeV1,
}

impl B4RegistryProbeMaterializationV1 {
    /// Borrow this exact base/output pair through the canonical registry adapter.
    #[must_use]
    pub fn replay_adapter(&self) -> B4RegistryProbeReplayAdapterV1<'_> {
        B4RegistryProbeReplayAdapterV1 {
            base: &self.base,
            output: &self.output,
        }
    }
}

/// Canonical replay adapter for candidate-registry and negative-index probes.
///
/// Byte recipes replay directly over the complete source. Sequence recipes are
/// replayed over a deterministic detached projection and inverse-projected into
/// the otherwise unchanged source before comparison with the exact output.
#[derive(Clone, Copy, Debug)]
pub struct B4RegistryProbeReplayAdapterV1<'a> {
    /// Exact independently reconstructed registry baseline.
    pub base: &'a [u8],
    /// Exact registry bytes submitted to the real parser/validator.
    pub output: &'a [u8],
}

impl B4MaterializationReplayAdapterV1 for B4RegistryProbeReplayAdapterV1<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::ArtifactValidator
    }

    fn base_bytes(&self) -> &[u8] {
        self.base
    }

    fn output_bytes(&self) -> &[u8] {
        self.output
    }

    fn replay_recipe(
        &self,
        base_selector_id: &str,
        materialization: &B4NegativeMaterialization,
    ) -> Result<()> {
        let B4NegativeMaterialization::Mutation { mutation } = materialization else {
            bail!("registry-probe adapter received a fixture-selection recipe");
        };
        match mutation {
            B4NegativeMutation::AlternateRootAssumptionSubstitution {} => {
                bail!("registry-probe adapter received an alternate-root assumption recipe")
            }
            B4NegativeMutation::AncestryInventoryEdit { .. } => {
                bail!("registry-probe adapter received an ancestry-inventory recipe")
            }
            B4NegativeMutation::AncestryWitnessSubstitution { .. } => {
                bail!("registry-probe adapter received an ancestry-witness substitution recipe")
            }
            B4NegativeMutation::ByteEdit { target, .. } => {
                ensure!(
                    *target == B4ByteTarget::CandidateRegistrySource,
                    "registry-probe byte recipe uses the wrong coarse target"
                );
                ensure!(
                    reconstruct_mutation(self.base, mutation)? == self.output,
                    "registry-probe byte recipe does not reconstruct the exact output"
                );
            }
            B4NegativeMutation::SequenceEdit { edit, target } => {
                replay_registry_sequence_edit(
                    base_selector_id,
                    self.base,
                    self.output,
                    *target,
                    edit,
                )?;
            }
        }
        Ok(())
    }
}

/// Return and validate the exact synthetic candidate-registry baseline bytes.
///
/// # Errors
///
/// Returns an error when the checked-in skeleton is not exact canonical JCS or
/// no longer passes the real candidate-registry parser.
pub fn synthetic_registry_skeleton_source() -> Result<&'static [u8]> {
    B4CandidateCorpus::from_canonical_jcs(SYNTHETIC_REGISTRY_SOURCE)
        .context("invalid synthetic candidate-registry skeleton")?;
    Ok(SYNTHETIC_REGISTRY_SOURCE)
}

/// Construct exact canonical bytes for the synthetic negative-binding baseline.
///
/// # Errors
///
/// Returns an error when the plan is invalid or the derived index cannot be
/// validated and canonically encoded.
pub fn synthetic_negative_binding_index_source(plan: &Eip0045B4NegativePlanV1) -> Result<Vec<u8>> {
    Eip0045B4NegativeBindingIndexV1::from_plan(plan)?.to_canonical_jcs()
}

/// Enumerate the exact registry-probe executions in canonical plan order.
///
/// # Errors
///
/// Returns an error when the plan is invalid or its registry group inventory,
/// order, or execution count differs from the closed V1 list.
pub fn registry_probe_execution_ids(plan: &Eip0045B4NegativePlanV1) -> Result<Vec<String>> {
    plan.validate().context("invalid B4 negative plan")?;
    let groups = plan
        .groups
        .iter()
        .filter(|group| REGISTRY_GROUPS.contains(&group.case_id.as_str()))
        .collect::<Vec<_>>();
    ensure!(
        groups
            .iter()
            .map(|group| group.case_id.as_str())
            .eq(REGISTRY_GROUPS),
        "registry-probe group inventory/order differs from the closed list"
    );
    let executions = groups
        .into_iter()
        .flat_map(|group| group.executions.iter())
        .map(|execution| execution.execution_id.clone())
        .collect::<Vec<_>>();
    ensure!(
        executions.len() == 23,
        "registry-probe inventory does not contain exactly 23 executions"
    );
    Ok(executions)
}

/// Materialize one plan-selected probe and prove its exact typed rejection.
///
/// # Errors
///
/// Returns an error for a noncanonical plan, an unknown or wrongly bound
/// execution, a failed reconstruction, an unclassified rejection, or an
/// observed QA code which differs from the plan.
pub fn materialize_registry_probe(
    negative_plan_source: &[u8],
    execution_id: &str,
) -> Result<B4RegistryProbeMaterializationV1> {
    let plan = canonical_plan_source(negative_plan_source)?;
    let (group_id, execution) = find_registry_execution(&plan, execution_id)?;
    ensure!(
        execution.materialization_domain == B4MaterializationDomain::ArtifactValidator,
        "registry execution is not owned by the artifact-validator domain"
    );
    ensure!(
        execution.execution_surface == expected_execution_surface(group_id)?,
        "registry execution is not owned by its explicit validation surface"
    );
    ensure!(
        execution.qa_result_code == expected_qa_result(group_id)?,
        "registry execution carries the wrong normalized QA result"
    );

    let base = match execution.base_selector_id.as_str() {
        B4_SYNTHETIC_REGISTRY_SKELETON_ID => synthetic_registry_skeleton_source()?.to_vec(),
        B4_SYNTHETIC_NEGATIVE_BINDING_INDEX_ID => synthetic_negative_binding_index_source(&plan)?,
        other => bail!("registry execution selects an unknown independent baseline: {other}"),
    };
    let output = match execution.base_selector_id.as_str() {
        B4_SYNTHETIC_REGISTRY_SKELETON_ID => {
            mutate_candidate_registry(group_id, &execution.variant_id, &base)?
        }
        B4_SYNTHETIC_NEGATIVE_BINDING_INDEX_ID => {
            mutate_negative_binding_index(group_id, &execution.variant_id, &base, &plan)?
        }
        _ => unreachable!("base selector checked above"),
    };
    ensure!(
        !output.is_empty(),
        "registry probe produced an empty output"
    );
    ensure!(
        output.len() <= MAX_PROBE_OUTPUT_BYTES,
        "registry probe output exceeds its byte bound"
    );
    ensure!(output != base, "registry probe reconstructed a no-op");

    let materialization = derive_registry_probe_materialization(
        group_id,
        &execution.variant_id,
        execution.base_selector_id.as_str(),
        &base,
        &output,
    )?;
    let registry_row = B4NegativeCase {
        execution_id: execution.execution_id.clone(),
        base_selector_id: execution.base_selector_id.clone(),
        materialization_domain: execution.materialization_domain,
        materialization,
    };
    B4RegistryProbeReplayAdapterV1 {
        base: &base,
        output: &output,
    }
    .replay_recipe(
        execution.base_selector_id.as_str(),
        &registry_row.materialization,
    )?;

    let observed_qa_result =
        classify_observed_rejection(execution.base_selector_id.as_str(), &base, &output, &plan)?;
    ensure!(
        observed_qa_result == execution.qa_result_code,
        "independently classified registry rejection differs from the plan QA result"
    );
    let outcome = B4RegistryProbeOutcomeV1 {
        execution_id: execution.execution_id.clone(),
        base_selector_id: execution.base_selector_id.clone(),
        materialization_domain: execution.materialization_domain,
        execution_surface: execution.execution_surface,
        qa_result_code: observed_qa_result,
    };
    Ok(B4RegistryProbeMaterializationV1 {
        base,
        output,
        registry_row,
        outcome,
    })
}

fn synthetic_materialization(
    index: usize,
    group_id: &str,
    execution: &B4NegativePlanExecutionV1,
) -> Result<B4NegativeMaterialization> {
    if execution.execution_id == "resolve-explicit-field-sweep--assumption-receipt-root" {
        ensure!(
            index == 146 && !negative_group_requires_fixture_selection(group_id),
            "fixed alternate-root assumption substitution moved outside row 146"
        );
        return Ok(B4NegativeMaterialization::Mutation {
            mutation: B4NegativeMutation::AlternateRootAssumptionSubstitution {},
        });
    }
    if negative_group_requires_fixture_selection(group_id) {
        return Ok(B4NegativeMaterialization::FixtureSelection {
            fixture_id: execution.base_selector_id.clone(),
        });
    }
    Ok(B4NegativeMaterialization::Mutation {
        mutation: B4NegativeMutation::ByteEdit {
            edit: B4ByteOperation::Insert {
                inserted_hex: format!("{:02x}", (index % 255) + 1),
                offset: u64::try_from(index).context("synthetic mutation index exceeds u64")?,
            },
            target: B4ByteTarget::CandidateRegistrySource,
        },
    })
}

fn validate_materialization(materialization: &B4NegativeMaterialization) -> Result<()> {
    match materialization {
        B4NegativeMaterialization::Mutation { mutation } => mutation.validate(),
        B4NegativeMaterialization::FixtureSelection { fixture_id } => {
            validate_lower_kebab(fixture_id, "negative-binding fixture ID")
        }
    }
}

#[derive(Clone, Copy)]
enum SequenceChangeKind {
    Insert,
    Move,
    Omit,
    Replace,
}

fn derive_registry_probe_materialization(
    group_id: &str,
    variant_id: &str,
    base_selector_id: &str,
    base: &[u8],
    output: &[u8],
) -> Result<B4NegativeMaterialization> {
    use SequenceChangeKind as S;
    let sequence = match (group_id, variant_id) {
        ("registry-positive-case-omit-sweep", _) => {
            Some((B4SequenceTarget::RegistryPositiveCases, S::Omit))
        }
        ("registry-positive-cases-reordered", "first-two-positive-cases") => {
            Some((B4SequenceTarget::RegistryPositiveCases, S::Move))
        }
        ("registry-positive-case-relabel", "terminal-resolve-explicit-root") => {
            Some((B4SequenceTarget::RegistryPositiveCases, S::Replace))
        }
        ("registry-negative-class-unknown", "unknown-negative-class") => {
            Some((B4SequenceTarget::RegistryNegativeClasses, S::Replace))
        }
        ("negative-plan-registry-bijection-sweep", "missing-execution") => {
            Some((B4SequenceTarget::RegistryNegativeBindings, S::Omit))
        }
        ("negative-plan-registry-bijection-sweep", "unexpected-execution") => {
            Some((B4SequenceTarget::RegistryNegativeBindings, S::Insert))
        }
        (
            "negative-plan-registry-bijection-sweep",
            "wrong-base-selector-binding"
            | "wrong-materialization-domain"
            | "wrong-materialization-binding",
        ) => Some((B4SequenceTarget::RegistryNegativeBindings, S::Replace)),
        ("registry-positive-case-id-duplicate", "positive-case-id")
        | ("registry-negative-case-id-duplicate", "negative-case-id")
        | ("registry-unknown-field", "unknown-registry-field")
        | ("registry-noncanonical-jcs", "noncanonical-registry-source") => None,
        _ => bail!("registry probe has no closed replay-recipe derivation"),
    };
    let mutation = match sequence {
        Some((target, kind)) => {
            derive_sequence_mutation(base_selector_id, base, output, target, kind)?
        }
        None => B4NegativeMutation::ByteEdit {
            edit: derive_exact_byte_operation(base, output)?,
            target: B4ByteTarget::CandidateRegistrySource,
        },
    };
    mutation.validate()?;
    Ok(B4NegativeMaterialization::Mutation { mutation })
}

fn derive_sequence_mutation(
    base_selector_id: &str,
    base: &[u8],
    output: &[u8],
    target: B4SequenceTarget,
    kind: SequenceChangeKind,
) -> Result<B4NegativeMutation> {
    let base_subject = project_registry_sequence(base_selector_id, base, target)?;
    let output_subject = project_registry_sequence(base_selector_id, output, target)?;
    let edit = match kind {
        SequenceChangeKind::Insert => {
            derive_sequence_insert(&base_subject.elements, &output_subject.elements)?
        }
        SequenceChangeKind::Move => {
            derive_sequence_move(&base_subject.elements, &output_subject.elements)?
        }
        SequenceChangeKind::Omit => {
            derive_sequence_omit(&base_subject.elements, &output_subject.elements)?
        }
        SequenceChangeKind::Replace => {
            derive_sequence_replace(&base_subject.elements, &output_subject.elements)?
        }
    };
    Ok(B4NegativeMutation::SequenceEdit { edit, target })
}

fn derive_sequence_insert(
    base: &[B4SequenceSubjectElement],
    output: &[B4SequenceSubjectElement],
) -> Result<B4SequenceOperation> {
    ensure!(
        output.len() == base.len() + 1,
        "sequence insertion does not add exactly one element"
    );
    for index in 0..output.len() {
        let mut candidate = output.to_vec();
        let inserted_element = candidate.remove(index);
        if candidate == base {
            return Ok(B4SequenceOperation::Insert {
                inserted_element,
                index: u64::try_from(index).context("sequence insertion index exceeds u64")?,
            });
        }
    }
    bail!("sequence insertion cannot reconstruct the observed projection")
}

fn derive_sequence_omit(
    base: &[B4SequenceSubjectElement],
    output: &[B4SequenceSubjectElement],
) -> Result<B4SequenceOperation> {
    ensure!(
        base.len() == output.len() + 1,
        "sequence omission does not remove exactly one element"
    );
    for index in 0..base.len() {
        let mut candidate = base.to_vec();
        let omitted = candidate.remove(index);
        if candidate == output {
            return Ok(B4SequenceOperation::Omit {
                before_element_id: omitted.element_id,
                before_element_sha256: omitted.sha256,
                index: u64::try_from(index).context("sequence omission index exceeds u64")?,
            });
        }
    }
    bail!("sequence omission cannot reconstruct the observed projection")
}

fn derive_sequence_move(
    base: &[B4SequenceSubjectElement],
    output: &[B4SequenceSubjectElement],
) -> Result<B4SequenceOperation> {
    ensure!(
        base.len() == output.len(),
        "sequence move changes the element count"
    );
    for from_index in 0..base.len() {
        for to_index in 0..base.len() {
            if from_index == to_index {
                continue;
            }
            let mut candidate = base.to_vec();
            let moved = candidate.remove(from_index);
            candidate.insert(to_index, moved.clone());
            if candidate == output {
                return Ok(B4SequenceOperation::Move {
                    before_element_id: moved.element_id,
                    before_element_sha256: moved.sha256,
                    from_index: u64::try_from(from_index)
                        .context("sequence move source index exceeds u64")?,
                    to_index: u64::try_from(to_index)
                        .context("sequence move target index exceeds u64")?,
                });
            }
        }
    }
    bail!("sequence move cannot reconstruct the observed projection")
}

fn derive_sequence_replace(
    base: &[B4SequenceSubjectElement],
    output: &[B4SequenceSubjectElement],
) -> Result<B4SequenceOperation> {
    ensure!(
        base.len() == output.len(),
        "sequence replacement changes the element count"
    );
    let changed = base
        .iter()
        .zip(output)
        .enumerate()
        .filter_map(|(index, (before, after))| (before != after).then_some((index, before, after)))
        .collect::<Vec<_>>();
    ensure!(
        changed.len() == 1,
        "sequence replacement does not isolate exactly one element"
    );
    let (index, before, replacement) = changed[0];
    Ok(B4SequenceOperation::Replace {
        before_element_id: before.element_id.clone(),
        before_element_sha256: before.sha256.clone(),
        index: u64::try_from(index).context("sequence replacement index exceeds u64")?,
        replacement_element: replacement.clone(),
    })
}

fn derive_exact_byte_operation(base: &[u8], output: &[u8]) -> Result<B4ByteOperation> {
    let common_prefix = base
        .iter()
        .zip(output)
        .take_while(|(left, right)| left == right)
        .count();
    let suffix_bound = base.len().min(output.len()) - common_prefix;
    let common_suffix = base[common_prefix..]
        .iter()
        .rev()
        .zip(output[common_prefix..].iter().rev())
        .take(suffix_bound)
        .take_while(|(left, right)| left == right)
        .count();
    let before = &base[common_prefix..base.len() - common_suffix];
    let replacement = &output[common_prefix..output.len() - common_suffix];
    let offset = u64::try_from(common_prefix).context("byte-edit offset exceeds u64")?;
    match (before.is_empty(), replacement.is_empty()) {
        (true, false) => Ok(B4ByteOperation::Insert {
            inserted_hex: hex::encode(replacement),
            offset,
        }),
        (false, true) => Ok(B4ByteOperation::Delete {
            before_hex: hex::encode(before),
            offset,
        }),
        (false, false) if before.len() == replacement.len() => Ok(B4ByteOperation::Replace {
            before_hex: hex::encode(before),
            replacement_hex: hex::encode(replacement),
            offset,
        }),
        _ => bail!("registry source change is not one exact closed byte operation"),
    }
}

fn canonical_index_bytes(index: &Eip0045B4NegativeBindingIndexV1) -> Result<Vec<u8>> {
    let value = serde_json::to_value(index).context("cannot serialize negative-binding index")?;
    let bytes = canonical_json_bytes(&value)?;
    ensure!(
        bytes.len() <= MAX_INDEX_BYTES,
        "negative-binding index exceeds its byte bound"
    );
    Ok(bytes)
}

fn canonical_plan_source(source: &[u8]) -> Result<Eip0045B4NegativePlanV1> {
    let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(source)
        .context("invalid canonical B4 negative-plan source")?;
    ensure!(
        plan == Eip0045B4NegativePlanV1::canonical()?,
        "negative-plan source is not the exact canonical V1 inventory"
    );
    Ok(plan)
}

fn find_registry_execution<'a>(
    plan: &'a Eip0045B4NegativePlanV1,
    execution_id: &str,
) -> Result<(&'a str, &'a B4NegativePlanExecutionV1)> {
    validate_execution_id(execution_id, "registry-probe execution ID")?;
    let mut matches = plan.groups.iter().flat_map(|group| {
        group
            .executions
            .iter()
            .filter(move |execution| execution.execution_id == execution_id)
            .map(move |execution| (group.case_id.as_str(), execution))
    });
    let found = matches
        .next()
        .context("registry-probe execution is absent from the canonical plan")?;
    ensure!(
        matches.next().is_none(),
        "registry-probe execution is duplicated in the canonical plan"
    );
    ensure!(
        REGISTRY_GROUPS.contains(&found.0),
        "plan execution is not a registry-owned artifact probe"
    );
    Ok(found)
}

fn expected_qa_result(group_id: &str) -> Result<B4NegativeQaResultCode> {
    use B4NegativeQaResultCode as Q;
    Ok(match group_id {
        "registry-positive-case-omit-sweep" => Q::B4RegistryMandatoryPositiveMissing,
        "registry-positive-case-id-duplicate" | "registry-negative-case-id-duplicate" => {
            Q::B4RegistryCaseIdDuplicate
        }
        "registry-positive-cases-reordered" => Q::B4RegistryPositiveOrderInvalid,
        "registry-positive-case-relabel" => Q::B4RegistryPositiveLabelInvalid,
        "registry-negative-class-unknown" => Q::B4RegistryNegativeClassUnknown,
        "registry-unknown-field" => Q::B4RegistryUnknownField,
        "registry-noncanonical-jcs" => Q::B4RegistryNoncanonicalJcs,
        "negative-plan-registry-bijection-sweep" => Q::B4NegativePlanRegistryBijectionMismatch,
        _ => bail!("group is not a registry-owned artifact probe"),
    })
}

fn expected_execution_surface(group_id: &str) -> Result<B4NegativeExecutionSurface> {
    use B4NegativeExecutionSurface as S;

    Ok(match group_id {
        "registry-positive-case-omit-sweep"
        | "registry-positive-case-id-duplicate"
        | "registry-positive-cases-reordered"
        | "registry-positive-case-relabel"
        | "registry-negative-class-unknown"
        | "registry-unknown-field"
        | "registry-noncanonical-jcs" => S::CandidateRegistry,
        "registry-negative-case-id-duplicate" | "negative-plan-registry-bijection-sweep" => {
            S::NegativeBindingIndex
        }
        _ => bail!("group is not a registry-owned artifact probe"),
    })
}

fn mutate_candidate_registry(group_id: &str, variant_id: &str, base: &[u8]) -> Result<Vec<u8>> {
    B4CandidateCorpus::from_canonical_jcs(base)
        .context("candidate-registry probe base does not pass the real parser")?;
    let mut value = validate_canonical_json_source(base)
        .context("candidate-registry probe base is not exact canonical JCS")?;
    match group_id {
        "registry-positive-case-omit-sweep" => {
            ensure!(!variant_id.is_empty(), "positive omission variant is empty");
            let positives = array_field_mut(&mut value, "positiveCases")?;
            let matches = positives
                .iter()
                .enumerate()
                .filter_map(|(index, item)| {
                    (string_field(item, "caseId").ok() == Some(variant_id)).then_some(index)
                })
                .collect::<Vec<_>>();
            ensure!(
                matches.len() == 1,
                "positive omission selector is not unique in the baseline"
            );
            positives.remove(matches[0]);
        }
        "registry-positive-case-id-duplicate" => {
            ensure!(
                variant_id == "positive-case-id",
                "wrong candidate-registry duplicate variant"
            );
            let positives = array_field_mut(&mut value, "positiveCases")?;
            ensure!(
                positives.len() >= 2,
                "candidate baseline has fewer than two positives"
            );
            let duplicate = string_field(&positives[0], "caseId")?.to_owned();
            set_string_field(&mut positives[1], "caseId", duplicate)?;
        }
        "registry-positive-cases-reordered" => {
            ensure!(
                variant_id == "first-two-positive-cases",
                "wrong positive reorder variant"
            );
            let positives = array_field_mut(&mut value, "positiveCases")?;
            ensure!(
                positives.len() >= 2,
                "candidate baseline has fewer than two positives"
            );
            positives.swap(0, 1);
        }
        "registry-positive-case-relabel" => {
            ensure!(
                variant_id == "terminal-resolve-explicit-root",
                "wrong positive relabel variant"
            );
            let positives = array_field_mut(&mut value, "positiveCases")?;
            let target = positives
                .iter_mut()
                .find(|item| string_field(item, "caseId").ok() == Some(variant_id))
                .context("positive relabel target is absent")?;
            set_string_field(
                target,
                "caseId",
                "terminal-resolve-explicit-root-relabeled".to_owned(),
            )?;
        }
        "registry-negative-class-unknown" => {
            ensure!(
                variant_id == "unknown-negative-class",
                "wrong negative-class variant"
            );
            let first = array_field_mut(&mut value, "negativeClasses")?
                .first_mut()
                .context("candidate baseline has no negative classes")?;
            *first = Value::String("unknown-negative-class".to_owned());
        }
        "registry-unknown-field" => {
            ensure!(
                variant_id == "unknown-registry-field",
                "wrong unknown-field variant"
            );
            value
                .as_object_mut()
                .context("candidate registry is not an object")?
                .insert("unknownRegistryField".to_owned(), Value::Bool(true));
        }
        "registry-noncanonical-jcs" => {
            ensure!(
                variant_id == "noncanonical-registry-source",
                "wrong noncanonical-JCS variant"
            );
            let mut output = base.to_vec();
            output.push(b'\n');
            return Ok(output);
        }
        _ => bail!("group does not use the synthetic candidate-registry baseline"),
    }
    let output = canonical_json_bytes(&value)?;
    ensure!(
        output.len() <= MAX_PROBE_OUTPUT_BYTES,
        "candidate-registry probe output exceeds its byte bound"
    );
    Ok(output)
}

fn mutate_negative_binding_index(
    group_id: &str,
    variant_id: &str,
    base: &[u8],
    plan: &Eip0045B4NegativePlanV1,
) -> Result<Vec<u8>> {
    let mut index = Eip0045B4NegativeBindingIndexV1::from_canonical_jcs(base)
        .context("negative-binding probe base does not pass its real parser")?;
    index.validate_against_plan(plan)?;
    match (group_id, variant_id) {
        ("registry-negative-case-id-duplicate", "negative-case-id") => {
            let (source_index, target_index) = equal_length_execution_pair(&index.rows)?;
            let duplicate_execution_id = index.rows[source_index].execution_id.clone();
            index.rows[target_index].execution_id = duplicate_execution_id;
        }
        ("negative-plan-registry-bijection-sweep", "missing-execution") => {
            ensure!(
                index.rows.len() > 8,
                "negative-binding baseline is unexpectedly short"
            );
            index.rows.remove(8);
        }
        ("negative-plan-registry-bijection-sweep", "unexpected-execution") => {
            let mut extra = index
                .rows
                .last()
                .context("negative-binding baseline is empty")?
                .clone();
            "unexpected-group--unexpected-variant".clone_into(&mut extra.execution_id);
            "unexpected-base-selector-v1".clone_into(&mut extra.base_selector_id);
            index.rows.push(extra);
        }
        ("negative-plan-registry-bijection-sweep", "wrong-base-selector-binding") => {
            let row = index
                .rows
                .get_mut(2)
                .context("negative-binding baseline lacks row two")?;
            "wrong-base-selector-v1".clone_into(&mut row.base_selector_id);
        }
        ("negative-plan-registry-bijection-sweep", "wrong-materialization-domain") => {
            let row = index
                .rows
                .get_mut(3)
                .context("negative-binding baseline lacks row three")?;
            row.materialization_domain = different_domain(row.materialization_domain);
        }
        ("negative-plan-registry-bijection-sweep", "wrong-materialization-binding") => {
            let row = index
                .rows
                .get_mut(4)
                .context("negative-binding baseline lacks row four")?;
            row.materialization = B4NegativeMaterialization::Mutation {
                mutation: B4NegativeMutation::ByteEdit {
                    edit: B4ByteOperation::Insert {
                        inserted_hex: "ff".to_owned(),
                        offset: 65_535,
                    },
                    target: B4ByteTarget::CandidateRegistrySource,
                },
            };
        }
        _ => bail!("unsupported negative-binding index probe variant"),
    }
    let output = canonical_index_bytes(&index)?;
    ensure!(
        output.len() <= MAX_PROBE_OUTPUT_BYTES,
        "negative-binding probe output exceeds its byte bound"
    );
    Ok(output)
}

fn different_domain(domain: B4MaterializationDomain) -> B4MaterializationDomain {
    match domain {
        B4MaterializationDomain::VerifierInput => B4MaterializationDomain::ArtifactValidator,
        B4MaterializationDomain::ArtifactValidator => B4MaterializationDomain::TreeValidator,
        B4MaterializationDomain::TreeValidator => B4MaterializationDomain::VerifierInput,
    }
}

fn equal_length_execution_pair(rows: &[B4NegativeBindingRowV1]) -> Result<(usize, usize)> {
    for (source_index, source) in rows.iter().enumerate() {
        if let Some((target_index, _)) = rows
            .iter()
            .enumerate()
            .skip(source_index + 1)
            .find(|(_, target)| target.execution_id.len() == source.execution_id.len())
        {
            return Ok((source_index, target_index));
        }
    }
    bail!("negative-binding baseline has no equal-length execution-ID pair")
}

fn replay_registry_sequence_edit(
    base_selector_id: &str,
    base: &[u8],
    output: &[u8],
    target: B4SequenceTarget,
    edit: &B4SequenceOperation,
) -> Result<()> {
    let mut reconstructed_value = validate_canonical_json_source(base)
        .context("registry sequence-replay base is not exact canonical JCS")?;
    let base_subject = project_registry_sequence(base_selector_id, base, target)?;
    let mutation = B4NegativeMutation::SequenceEdit {
        edit: edit.clone(),
        target,
    };
    let subject_output = reconstruct_mutation(&base_subject.to_canonical_jcs()?, &mutation)?;
    let reconstructed_subject = Eip0045B4SequenceSubjectV1::from_canonical_jcs(&subject_output)?;
    let reconstructed_elements = reconstructed_subject
        .elements
        .iter()
        .map(|element| {
            validate_canonical_json_source(&element.decoded_bytes()?)
                .context("reconstructed registry sequence element is not exact canonical JCS")
        })
        .collect::<Result<Vec<_>>>()?;
    let field = projection_field(base_selector_id, target)?;
    *array_field_mut(&mut reconstructed_value, field)? = reconstructed_elements;
    ensure!(
        canonical_json_bytes(&reconstructed_value)? == output,
        "registry sequence recipe does not inverse-project to the exact output"
    );
    Ok(())
}

fn project_registry_sequence(
    base_selector_id: &str,
    source: &[u8],
    target: B4SequenceTarget,
) -> Result<Eip0045B4SequenceSubjectV1> {
    let value = validate_canonical_json_source(source)
        .context("registry sequence projection source is not exact canonical JCS")?;
    let field = projection_field(base_selector_id, target)?;
    let elements = array_field(&value, field)?
        .iter()
        .map(|item| projection_element(target, item))
        .collect::<Result<Vec<_>>>()?;
    Eip0045B4SequenceSubjectV1::new(target, elements)
}

fn projection_field(base_selector_id: &str, target: B4SequenceTarget) -> Result<&'static str> {
    match (base_selector_id, target) {
        (B4_SYNTHETIC_REGISTRY_SKELETON_ID, B4SequenceTarget::RegistryPositiveCases) => {
            Ok("positiveCases")
        }
        (B4_SYNTHETIC_REGISTRY_SKELETON_ID, B4SequenceTarget::RegistryNegativeClasses) => {
            Ok("negativeClasses")
        }
        (B4_SYNTHETIC_NEGATIVE_BINDING_INDEX_ID, B4SequenceTarget::RegistryNegativeBindings) => {
            Ok("rows")
        }
        _ => bail!("registry sequence target contradicts its independent base selector"),
    }
}

fn projection_element(target: B4SequenceTarget, value: &Value) -> Result<B4SequenceSubjectElement> {
    let element_id = match target {
        B4SequenceTarget::RegistryPositiveCases => string_field(value, "caseId")?.to_owned(),
        B4SequenceTarget::RegistryNegativeClasses => value
            .as_str()
            .context("negative-class projection element is not a string")?
            .to_owned(),
        B4SequenceTarget::RegistryNegativeBindings => {
            binding_element_id(string_field(value, "executionId")?)
        }
        _ => bail!("unsupported registry sequence projection target"),
    };
    B4SequenceSubjectElement::from_bytes(element_id, &canonical_json_bytes(value)?)
}

fn binding_element_id(execution_id: &str) -> String {
    format!(
        "binding-{}",
        hex::encode(Sha256::digest(execution_id.as_bytes()))
    )
}

fn classify_observed_rejection(
    base_selector_id: &str,
    base: &[u8],
    output: &[u8],
    plan: &Eip0045B4NegativePlanV1,
) -> Result<B4NegativeQaResultCode> {
    match base_selector_id {
        B4_SYNTHETIC_REGISTRY_SKELETON_ID => classify_candidate_registry_rejection(base, output),
        B4_SYNTHETIC_NEGATIVE_BINDING_INDEX_ID => {
            classify_negative_binding_index_rejection(output, plan)
        }
        other => bail!("cannot classify rejection for unknown registry baseline: {other}"),
    }
}

fn classify_candidate_registry_rejection(
    base: &[u8],
    output: &[u8],
) -> Result<B4NegativeQaResultCode> {
    ensure!(
        B4CandidateCorpus::from_canonical_jcs(output).is_err(),
        "candidate-registry probe was accepted by the real parser"
    );
    let Ok(output_value) = validate_canonical_json_source(output) else {
        return Ok(B4NegativeQaResultCode::B4RegistryNoncanonicalJcs);
    };
    let base_value = validate_canonical_json_source(base)
        .context("candidate-registry classification base is not exact canonical JCS")?;
    let base_object = base_value
        .as_object()
        .context("candidate-registry classification base is not an object")?;
    let output_object = output_value
        .as_object()
        .context("candidate-registry probe output is not an object")?;
    if output_object
        .keys()
        .any(|field| !base_object.contains_key(field))
    {
        return Ok(B4NegativeQaResultCode::B4RegistryUnknownField);
    }
    if array_field(&output_value, "negativeClasses")?
        .iter()
        .any(|class| serde_json::from_value::<B4NegativeClass>(class.clone()).is_err())
    {
        return Ok(B4NegativeQaResultCode::B4RegistryNegativeClassUnknown);
    }
    classify_positive_registry_rejection(&base_value, &output_value)
}

fn classify_positive_registry_rejection(
    base: &Value,
    output: &Value,
) -> Result<B4NegativeQaResultCode> {
    let base_ids = positive_case_ids(base)?;
    let output_ids = positive_case_ids(output)?;
    let output_set = output_ids.iter().copied().collect::<BTreeSet<_>>();
    if output_set.len() != output_ids.len() {
        return Ok(B4NegativeQaResultCode::B4RegistryCaseIdDuplicate);
    }
    let base_set = base_ids.iter().copied().collect::<BTreeSet<_>>();
    if output_ids.len() + 1 == base_ids.len() && output_set.is_subset(&base_set) {
        return Ok(B4NegativeQaResultCode::B4RegistryMandatoryPositiveMissing);
    }
    if output_ids.len() == base_ids.len() && output_set == base_set && output_ids != base_ids {
        return Ok(B4NegativeQaResultCode::B4RegistryPositiveOrderInvalid);
    }
    if output_ids.len() == base_ids.len()
        && output_set.difference(&base_set).count() == 1
        && base_set.difference(&output_set).count() == 1
    {
        return Ok(B4NegativeQaResultCode::B4RegistryPositiveLabelInvalid);
    }
    bail!("candidate-registry rejection does not match a closed registry-probe class")
}

fn classify_negative_binding_index_rejection(
    output: &[u8],
    plan: &Eip0045B4NegativePlanV1,
) -> Result<B4NegativeQaResultCode> {
    let value = validate_canonical_json_source(output)
        .context("negative-binding probe output is not exact canonical JCS")?;
    let rows = array_field(&value, "rows")?;
    let mut execution_ids = BTreeSet::new();
    let duplicate = rows.iter().try_fold(false, |duplicate, row| {
        let execution_id = string_field(row, "executionId")?;
        Ok::<_, anyhow::Error>(duplicate || !execution_ids.insert(execution_id))
    })?;
    if duplicate {
        ensure!(
            Eip0045B4NegativeBindingIndexV1::from_canonical_jcs(output).is_err(),
            "duplicate negative execution ID was accepted by the real index parser"
        );
        return Ok(B4NegativeQaResultCode::B4RegistryCaseIdDuplicate);
    }
    let index = Eip0045B4NegativeBindingIndexV1::from_canonical_jcs(output)
        .context("nonduplicate negative-binding probe failed its structural parser")?;
    ensure!(
        index.validate_against_plan(plan).is_err(),
        "negative-binding bijection probe was accepted by the real plan validator"
    );
    Ok(B4NegativeQaResultCode::B4NegativePlanRegistryBijectionMismatch)
}

fn array_field<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>> {
    value
        .as_object()
        .context("registry probe value is not an object")?
        .get(field)
        .with_context(|| format!("registry probe value lacks {field}"))?
        .as_array()
        .with_context(|| format!("registry probe field {field} is not an array"))
}

fn array_field_mut<'a>(value: &'a mut Value, field: &str) -> Result<&'a mut Vec<Value>> {
    value
        .as_object_mut()
        .context("registry probe value is not an object")?
        .get_mut(field)
        .with_context(|| format!("registry probe value lacks {field}"))?
        .as_array_mut()
        .with_context(|| format!("registry probe field {field} is not an array"))
}

fn positive_case_ids(value: &Value) -> Result<Vec<&str>> {
    array_field(value, "positiveCases")?
        .iter()
        .map(|positive| string_field(positive, "caseId"))
        .collect()
}

fn string_field<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .as_object()
        .context("registry probe row is not an object")?
        .get(field)
        .with_context(|| format!("registry probe row lacks {field}"))?
        .as_str()
        .with_context(|| format!("registry probe row field {field} is not a string"))
}

fn set_string_field(value: &mut Value, field: &str, replacement: String) -> Result<()> {
    let slot = value
        .as_object_mut()
        .context("candidate registry row is not an object")?
        .get_mut(field)
        .with_context(|| format!("candidate registry row lacks {field}"))?;
    ensure!(
        slot.is_string(),
        "candidate registry row field {field} is not a string"
    );
    *slot = Value::String(replacement);
    Ok(())
}

fn validate_lower_kebab(value: &str, label: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= MAX_IDENTIFIER_COMPONENT_BYTES,
        "{label} is empty or too long"
    );
    ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && value.as_bytes()[0].is_ascii_lowercase()
            && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
            && !value.contains("--"),
        "{label} is not a bounded lower-kebab identifier"
    );
    Ok(())
}

fn validate_execution_id(value: &str, label: &str) -> Result<()> {
    let (group_id, variant_id) = value
        .split_once("--")
        .with_context(|| format!("{label} lacks the group/variant separator"))?;
    ensure!(
        !variant_id.contains("--"),
        "{label} contains more than one group/variant separator"
    );
    validate_lower_kebab(group_id, label)?;
    validate_lower_kebab(variant_id, label)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::b4_mutation::{
        create_materialization_identity_with_adapter, verify_materialization_identity_with_adapter,
    };

    const EXPECTED_EXECUTIONS: [&str; 23] = [
        "registry-positive-case-omit-sweep--lift-po2-15",
        "registry-positive-case-omit-sweep--lift-po2-16",
        "registry-positive-case-omit-sweep--lift-po2-17",
        "registry-positive-case-omit-sweep--lift-po2-18",
        "registry-positive-case-omit-sweep--lift-po2-19",
        "registry-positive-case-omit-sweep--lift-po2-20",
        "registry-positive-case-omit-sweep--lift-po2-21",
        "registry-positive-case-omit-sweep--lift-po2-22",
        "registry-positive-case-omit-sweep--terminal-join",
        "registry-positive-case-omit-sweep--terminal-resolve-explicit-root",
        "registry-positive-case-omit-sweep--resolve-zero-root-then-join",
        "registry-positive-case-id-duplicate--positive-case-id",
        "registry-negative-case-id-duplicate--negative-case-id",
        "registry-positive-cases-reordered--first-two-positive-cases",
        "registry-positive-case-relabel--terminal-resolve-explicit-root",
        "registry-negative-class-unknown--unknown-negative-class",
        "registry-unknown-field--unknown-registry-field",
        "registry-noncanonical-jcs--noncanonical-registry-source",
        "negative-plan-registry-bijection-sweep--missing-execution",
        "negative-plan-registry-bijection-sweep--unexpected-execution",
        "negative-plan-registry-bijection-sweep--wrong-base-selector-binding",
        "negative-plan-registry-bijection-sweep--wrong-materialization-domain",
        "negative-plan-registry-bijection-sweep--wrong-materialization-binding",
    ];

    fn plan() -> Eip0045B4NegativePlanV1 {
        Eip0045B4NegativePlanV1::canonical().unwrap()
    }

    fn plan_source() -> Vec<u8> {
        plan().to_canonical_jcs().unwrap()
    }

    #[test]
    fn both_independent_baselines_are_strict_accepted_and_non_cyclic() {
        let plan = plan();
        let skeleton = synthetic_registry_skeleton_source().unwrap();
        B4CandidateCorpus::from_canonical_jcs(skeleton).unwrap();
        let source = synthetic_negative_binding_index_source(&plan).unwrap();
        let index = Eip0045B4NegativeBindingIndexV1::from_canonical_jcs(&source).unwrap();
        index.validate_against_plan(&plan).unwrap();
        assert_eq!(
            index.rows.len(),
            usize::from(B4_NEGATIVE_PLAN_VARIANT_COUNT)
        );
        let value = validate_canonical_json_source(&source).unwrap();
        let root = value.as_object().unwrap();
        assert_eq!(root.len(), 3);
        for key in ["format", "formatVersion", "rows"] {
            assert!(root.contains_key(key));
        }
        let first = value["rows"][0].as_object().unwrap();
        assert_eq!(first.len(), 4);
        for key in [
            "executionId",
            "baseSelectorId",
            "materializationDomain",
            "materialization",
        ] {
            assert!(first.contains_key(key));
        }
        for forbidden in ["class", "artifacts", "resultSlots"] {
            assert!(!first.contains_key(forbidden));
        }
    }

    #[test]
    fn registry_probe_inventory_is_exact_and_plan_ordered() {
        let actual = registry_probe_execution_ids(&plan()).unwrap();
        assert_eq!(
            actual,
            EXPECTED_EXECUTIONS
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn every_probe_has_unique_output_typed_qa_and_rebindable_generic_identity() {
        let plan_source = plan_source();
        let plan = plan();
        let mut outputs = BTreeSet::new();
        let mut byte_recipes = 0;
        let mut sequence_recipes = 0;
        for execution_id in EXPECTED_EXECUTIONS {
            let materialized = materialize_registry_probe(&plan_source, execution_id).unwrap();
            assert!(outputs.insert(materialized.output.clone()));
            let (group_id, execution) = find_registry_execution(&plan, execution_id).unwrap();
            assert_eq!(
                materialized.outcome.execution_surface,
                expected_execution_surface(group_id).unwrap()
            );
            assert_eq!(
                materialized.outcome.materialization_domain,
                B4MaterializationDomain::ArtifactValidator
            );
            assert_eq!(
                materialized.outcome.qa_result_code,
                expected_qa_result(group_id).unwrap()
            );
            assert_eq!(
                materialized.outcome.qa_result_code,
                execution.qa_result_code
            );
            assert_eq!(materialized.registry_row.execution_id, execution_id);
            assert_eq!(
                materialized.registry_row.base_selector_id,
                execution.base_selector_id
            );
            match &materialized.registry_row.materialization {
                B4NegativeMaterialization::Mutation {
                    mutation: B4NegativeMutation::AlternateRootAssumptionSubstitution {},
                } => panic!("registry probe fabricated an alternate-root assumption substitution"),
                B4NegativeMaterialization::Mutation {
                    mutation: B4NegativeMutation::AncestryInventoryEdit { .. },
                } => panic!("registry probe fabricated an ancestry-inventory mutation"),
                B4NegativeMaterialization::Mutation {
                    mutation: B4NegativeMutation::AncestryWitnessSubstitution { .. },
                } => panic!("registry probe fabricated an ancestry-witness substitution"),
                B4NegativeMaterialization::Mutation {
                    mutation: B4NegativeMutation::ByteEdit { .. },
                } => byte_recipes += 1,
                B4NegativeMaterialization::Mutation {
                    mutation: B4NegativeMutation::SequenceEdit { .. },
                } => sequence_recipes += 1,
                B4NegativeMaterialization::FixtureSelection { .. } => {
                    panic!("registry probe fabricated a fixture selection")
                }
            }
            let adapter = materialized.replay_adapter();
            let identity = create_materialization_identity_with_adapter(
                &plan_source,
                &materialized.registry_row,
                &adapter,
            )
            .unwrap();
            verify_materialization_identity_with_adapter(
                &identity,
                &plan_source,
                &materialized.registry_row,
                &adapter,
            )
            .unwrap();
            assert_eq!(
                materialized,
                materialize_registry_probe(&plan_source, execution_id).unwrap()
            );
        }
        assert_eq!(outputs.len(), EXPECTED_EXECUTIONS.len());
        assert_eq!(byte_recipes, 4);
        assert_eq!(sequence_recipes, 19);
    }

    #[test]
    fn index_parser_rejects_unknown_duplicate_noncanonical_and_bad_shape() {
        let plan = plan();
        let source = synthetic_negative_binding_index_source(&plan).unwrap();
        let mut unknown = validate_canonical_json_source(&source).unwrap();
        unknown["unexpected"] = Value::Bool(true);
        let unknown = canonical_json_bytes(&unknown).unwrap();
        assert!(Eip0045B4NegativeBindingIndexV1::from_canonical_jcs(&unknown).is_err());
        let mut unknown_row = validate_canonical_json_source(&source).unwrap();
        unknown_row["rows"][0]["unexpected"] = Value::Bool(true);
        let unknown_row = canonical_json_bytes(&unknown_row).unwrap();
        assert!(Eip0045B4NegativeBindingIndexV1::from_canonical_jcs(&unknown_row).is_err());
        let duplicate = format!(
            "{{\"format\":\"{B4_NEGATIVE_BINDING_INDEX_FORMAT}\",\"format\":\"{B4_NEGATIVE_BINDING_INDEX_FORMAT}\",\"formatVersion\":1,\"rows\":[]}}"
        );
        assert!(Eip0045B4NegativeBindingIndexV1::from_canonical_jcs(duplicate.as_bytes()).is_err());
        let mut noncanonical = source.clone();
        noncanonical.push(b'\n');
        assert!(Eip0045B4NegativeBindingIndexV1::from_canonical_jcs(&noncanonical).is_err());
        assert!(
            Eip0045B4NegativeBindingIndexV1::from_canonical_jcs(&vec![b' '; MAX_INDEX_BYTES + 1])
                .is_err()
        );
    }

    #[test]
    fn probe_selection_rejects_unknown_execution_and_plan_authority_drift() {
        let plan_source = plan_source();
        assert!(
            materialize_registry_probe(&plan_source, "unknown-group--unknown-variant").is_err()
        );
        let mut wrong_plan = plan_source.clone();
        wrong_plan.push(b'\n');
        assert!(materialize_registry_probe(&wrong_plan, EXPECTED_EXECUTIONS[0]).is_err());
    }

    #[test]
    fn all_negative_index_variants_mutate_real_index_fields() {
        let plan_source = plan_source();
        let plan = plan();
        let base = synthetic_negative_binding_index_source(&plan).unwrap();
        for execution_id in [
            "registry-negative-case-id-duplicate--negative-case-id",
            "negative-plan-registry-bijection-sweep--missing-execution",
            "negative-plan-registry-bijection-sweep--unexpected-execution",
            "negative-plan-registry-bijection-sweep--wrong-base-selector-binding",
            "negative-plan-registry-bijection-sweep--wrong-materialization-domain",
            "negative-plan-registry-bijection-sweep--wrong-materialization-binding",
        ] {
            let materialized = materialize_registry_probe(&plan_source, execution_id).unwrap();
            assert_ne!(materialized.output, base);
            let rejected =
                match Eip0045B4NegativeBindingIndexV1::from_canonical_jcs(&materialized.output) {
                    Ok(index) => index.validate_against_plan(&plan).is_err(),
                    Err(_) => true,
                };
            assert!(rejected, "negative index accepted {execution_id}");
        }
    }
}
