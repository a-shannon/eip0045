//! Structural report contract for the EIP-0045 B4 negative campaign.
//!
//! The serializable value is a compact commitment, not campaign authority and
//! not a validator receipt. A production authority/finalizer constructor is
//! intentionally unavailable until it can consume the opaque
//! campaign-precommit, positive-generation, negative-materialization-set, and
//! physical-run authorities. The former caller-supplied replay path remains
//! test-only so raw adapters cannot authorize a report.

use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::{
    b4_plan::{
        B4_ARTIFACT_VALIDATOR_EXECUTION_COUNT, B4_NEGATIVE_PLAN_VARIANT_COUNT,
        B4_TREE_VALIDATOR_EXECUTION_COUNT, B4_VERIFIER_INPUT_EXECUTION_COUNT,
    },
    b4_result::{B4ValidatorArtifactIdentityV1, B4ValidatorImplementation},
    canonical::{canonical_json_bytes, validate_canonical_json_source},
};

#[cfg(test)]
use sha2::{Digest as _, Sha256};

#[cfg(test)]
use crate::{
    b4::{B4BindingState, B4CandidateCorpus},
    b4_expectation::{
        B4_NEGATIVE_EXPECTATION_EXECUTION_COUNT, B4_NEGATIVE_EXPECTATION_SLOT_COUNT,
        verify_b4_negative_expectation_set,
    },
    b4_mutation::{
        B4_MATERIALIZATION_IDENTITY_FORMAT, B4_MATERIALIZATION_IDENTITY_FORMAT_VERSION,
        B4MaterializationReplayAdapterV1, Eip0045B4MaterializationIdentityV1,
        canonical_materialization_recipe_jcs,
    },
    b4_negative_io::{
        B4NegativeObservationVerdict, Eip0045B4NegativeObservationV1,
        Eip0045B4NegativeVerifierInputV1,
    },
    b4_plan::{
        B4MaterializationDomain, Eip0045B4NegativePlanV1, negative_group_requires_fixture_selection,
    },
    b4_result::{B4ValidationVerdict, Eip0045B4ValidationResultV1},
};

/// Exact format discriminator for the global negative semantic report.
pub const B4_SEMANTIC_REPORT_FORMAT: &str = "Eip0045B4SemanticReportV1";
/// Exact format version for the global negative semantic report.
pub const B4_SEMANTIC_REPORT_FORMAT_VERSION: u8 = 1;
/// Exact number of negative executions in the closed campaign.
pub const B4_SEMANTIC_REPORT_EXECUTION_COUNT: usize = B4_NEGATIVE_PLAN_VARIANT_COUNT as usize;
/// Exact number of implementation-specific results in the closed campaign.
pub const B4_SEMANTIC_REPORT_RESULT_COUNT: usize = B4_SEMANTIC_REPORT_EXECUTION_COUNT * 2;

const MAX_REPORT_BYTES: usize = 1024 * 1024;
const MAX_EXTERNAL_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_VALIDATOR_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;
#[cfg(test)]
const MAX_DESCRIPTOR_BYTES: usize = 16 * 1024 * 1024;
const MAX_EXECUTION_COMPONENT_BYTES: usize = 192;

/// Exact SHA-256 identity of externally supplied canonical bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4SemanticByteIdentityV1 {
    /// Exact source byte length.
    pub byte_length: u64,
    /// Lowercase SHA-256 of the exact source bytes.
    pub sha256: String,
}

impl B4SemanticByteIdentityV1 {
    #[cfg(test)]
    fn from_source(source: &[u8], maximum: usize, label: &str) -> Result<Self> {
        ensure!(!source.is_empty(), "{label} is empty");
        ensure!(source.len() <= maximum, "{label} exceeds its byte bound");
        let identity = Self {
            byte_length: u64::try_from(source.len())
                .with_context(|| format!("{label} length does not fit u64"))?,
            sha256: sha256_hex(source),
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            (1..=MAX_EXTERNAL_DOCUMENT_BYTES).contains(&self.byte_length),
            "semantic byte identity length is outside the V1 bound"
        );
        validate_digest(&self.sha256, "semantic byte identity SHA-256")
    }
}

/// Exact implementation artifact and finalizer-authoritative descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4SemanticValidatorCommitmentV1 {
    /// Exact ordered implementation role.
    pub implementation: B4ValidatorImplementation,
    /// Exact executable or JAR identity used by every result for this role.
    pub artifact: B4ValidatorArtifactIdentityV1,
    /// Identity of the exact canonical build descriptor validated by the finalizer.
    pub build_descriptor: B4SemanticByteIdentityV1,
}

impl B4SemanticValidatorCommitmentV1 {
    fn validate(&self) -> Result<()> {
        validate_artifact_identity(&self.artifact)?;
        self.build_descriptor.validate()
    }
}

/// Exact closed materialization-domain totals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4SemanticDomainTotalsV1 {
    /// Verifier-input executions.
    pub verifier_input: u16,
    /// Artifact-validator executions.
    pub artifact_validator: u16,
    /// Closed-tree validator executions.
    pub tree_validator: u16,
}

impl B4SemanticDomainTotalsV1 {
    const EXPECTED: Self = Self {
        verifier_input: B4_VERIFIER_INPUT_EXECUTION_COUNT,
        artifact_validator: B4_ARTIFACT_VALIDATOR_EXECUTION_COUNT,
        tree_validator: B4_TREE_VALIDATOR_EXECUTION_COUNT,
    };
}

/// Exact commitments for one implementation-specific validation slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4SemanticResultSlotV1 {
    /// Exact ordered implementation role.
    pub implementation: B4ValidatorImplementation,
    /// Exact canonical pathless observation bytes.
    pub observation: B4SemanticByteIdentityV1,
    /// Exact canonical attributed result bytes.
    pub result: B4SemanticByteIdentityV1,
}

impl B4SemanticResultSlotV1 {
    fn validate(&self) -> Result<()> {
        self.observation.validate()?;
        self.result.validate()
    }
}

/// Exact commitments for one plan/registry/materialization execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4SemanticExecutionV1 {
    /// Zero-based exact flattened-plan index.
    pub execution_index: u16,
    /// Exact closed-plan execution ID.
    pub execution_id: String,
    /// Exact independently replayed materialization-identity source.
    pub materialization_identity: B4SemanticByteIdentityV1,
    /// Exact neutral verifier input shared by both validators.
    pub negative_input: B4SemanticByteIdentityV1,
    /// Exactly two ordered result slots: Rust, then independent JVM.
    pub slots: Vec<B4SemanticResultSlotV1>,
}

impl B4SemanticExecutionV1 {
    fn validate(&self) -> Result<()> {
        validate_execution_id(&self.execution_id)?;
        self.materialization_identity.validate()?;
        self.negative_input.validate()?;
        validate_slot_pair(&self.slots)
    }
}

/// Canonical global report for all 254 negative executions and 508 results.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Eip0045B4SemanticReportV1 {
    /// Exact V1 format discriminator.
    pub format: String,
    /// Exact V1 format version.
    pub format_version: u8,
    /// Exact canonical negative-plan identity.
    pub negative_plan: B4SemanticByteIdentityV1,
    /// Exact expanded candidate-registry identity.
    pub expanded_registry: B4SemanticByteIdentityV1,
    /// Exact pre-proof 508-slot expectation-set identity.
    pub expectation_set: B4SemanticByteIdentityV1,
    /// Exactly two ordered validator artifact/descriptor commitments.
    pub validators: Vec<B4SemanticValidatorCommitmentV1>,
    /// Exact independently counted materialization-domain totals.
    pub domain_totals: B4SemanticDomainTotalsV1,
    /// Exact negative execution count.
    pub execution_count: u16,
    /// Exact implementation-specific result count.
    pub result_count: u16,
    /// Exactly 254 entries in flattened canonical-plan order.
    pub executions: Vec<B4SemanticExecutionV1>,
}

impl Eip0045B4SemanticReportV1 {
    /// Parse exact RFC 8785 JCS and enforce the report-local closed grammar.
    ///
    /// This does not authenticate the report's external commitments. No
    /// production authority constructor exists at this phase.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, duplicate-key,
    /// noncanonical, unknown-field, incorrectly counted, aliased, reordered,
    /// or otherwise invalid input.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            source.len() <= MAX_REPORT_BYTES,
            "B4 semantic report exceeds its canonical-byte bound"
        );
        let value = validate_canonical_json_source(source)
            .context("B4 semantic report is not exact RFC 8785 JCS")?;
        let report: Self =
            serde_json::from_value(value).context("invalid B4 semantic-report shape")?;
        report.validate()?;
        ensure!(
            report.to_canonical_jcs()? == source,
            "B4 semantic report does not round-trip byte-exactly"
        );
        Ok(report)
    }

    /// Serialize a valid report to exact RFC 8785 JCS bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the report violates its local V1 grammar or the
    /// canonical representation exceeds the V1 bound.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value = serde_json::to_value(self).context("cannot serialize B4 semantic report")?;
        let bytes = canonical_json_bytes(&value)?;
        ensure!(
            bytes.len() <= MAX_REPORT_BYTES,
            "B4 semantic report exceeds its canonical-byte bound"
        );
        Ok(bytes)
    }

    /// Validate the report-local exact counts, ordering, identities, and labels.
    ///
    /// Cross-document equality is intentionally left to the future
    /// opaque-authority report constructor.
    ///
    /// # Errors
    ///
    /// Returns an error for any local format, count, ordering, duplicate,
    /// implementation, digest, or byte-bound defect.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == B4_SEMANTIC_REPORT_FORMAT,
            "wrong B4 semantic-report format label"
        );
        ensure!(
            self.format_version == B4_SEMANTIC_REPORT_FORMAT_VERSION,
            "wrong B4 semantic-report format version"
        );
        self.negative_plan.validate()?;
        self.expanded_registry.validate()?;
        self.expectation_set.validate()?;
        validate_validator_pair(&self.validators)?;
        ensure!(
            self.domain_totals == B4SemanticDomainTotalsV1::EXPECTED,
            "wrong B4 semantic-report domain totals"
        );
        ensure!(
            usize::from(self.execution_count) == B4_SEMANTIC_REPORT_EXECUTION_COUNT,
            "wrong B4 semantic-report execution count"
        );
        ensure!(
            usize::from(self.result_count) == B4_SEMANTIC_REPORT_RESULT_COUNT,
            "wrong B4 semantic-report result count"
        );
        ensure!(
            self.executions.len() == B4_SEMANTIC_REPORT_EXECUTION_COUNT,
            "B4 semantic report must contain exactly {B4_SEMANTIC_REPORT_EXECUTION_COUNT} executions"
        );

        let mut execution_ids = BTreeSet::new();
        let mut result_count = 0_usize;
        for (index, execution) in self.executions.iter().enumerate() {
            execution
                .validate()
                .with_context(|| format!("invalid semantic-report execution at index {index}"))?;
            ensure!(
                usize::from(execution.execution_index) == index,
                "semantic-report execution index or order drift at index {index}"
            );
            ensure!(
                execution_ids.insert(execution.execution_id.as_str()),
                "duplicate semantic-report execution ID at index {index}"
            );
            result_count = result_count
                .checked_add(execution.slots.len())
                .context("semantic-report result count overflows usize")?;
        }
        ensure!(
            result_count == B4_SEMANTIC_REPORT_RESULT_COUNT,
            "semantic-report result-slot total differs from 508"
        );
        Ok(())
    }
}

/// One exact validator artifact and descriptor selected by the finalizer.
///
/// Descriptor schema and physical artifact validation remain prior finalizer
/// obligations. This gate independently checks canonical descriptor identity,
/// implementation label, and its embedded artifact length/digest binding.
#[cfg(test)]
pub struct B4SemanticValidatorAuthorityV1<'a> {
    /// Exact ordered implementation role.
    pub implementation: B4ValidatorImplementation,
    /// Exact externally measured executable or JAR identity.
    pub artifact: &'a B4ValidatorArtifactIdentityV1,
    /// Exact canonical validator-build descriptor bytes.
    pub build_descriptor_source: &'a [u8],
}

/// Exact evidence for one flattened negative-plan execution.
#[cfg(test)]
pub struct B4SemanticExecutionEvidenceV1<'a> {
    /// Exact canonical materialization-identity bytes.
    pub materialization_identity_source: &'a [u8],
    /// Exact neutral negative-input bytes supplied unchanged to both validators.
    pub negative_input_source: &'a [u8],
    /// Exactly two ordered canonical observations: Rust, then JVM.
    pub observation_sources: [&'a [u8]; 2],
    /// Exactly two ordered canonical attributed results: Rust, then JVM.
    pub result_sources: [&'a [u8]; 2],
    /// Canonical domain-specific replay authority over exact base/output bytes.
    pub adapter: &'a dyn B4MaterializationReplayAdapterV1,
}

/// Complete external authority required to rebuild a semantic report.
#[cfg(test)]
pub struct B4SemanticReportInputsV1<'a> {
    /// Exact canonical closed negative-plan bytes.
    pub negative_plan_source: &'a [u8],
    /// Exact canonical expanded candidate-registry bytes.
    pub expanded_registry_source: &'a [u8],
    /// Exact canonical 508-slot pre-proof expectation-set bytes.
    pub expectation_set_source: &'a [u8],
    /// Exactly two ordered validator authorities: Rust, then JVM.
    pub validators: [B4SemanticValidatorAuthorityV1<'a>; 2],
    /// Exactly 254 entries in flattened canonical-plan order.
    pub executions: &'a [B4SemanticExecutionEvidenceV1<'a>],
}

/// Independently rebuild one complete B4 negative semantic report.
///
/// # Errors
///
/// Returns an error for any plan, registry, materialization, input,
/// observation, expectation, result, artifact, descriptor, count, order, or
/// identity mismatch. Empty or malformed observation/result bytes are errors;
/// runtime failures have no representation accepted by this function.
#[cfg(test)]
pub(crate) fn create_b4_semantic_report(
    inputs: &B4SemanticReportInputsV1<'_>,
) -> Result<Eip0045B4SemanticReportV1> {
    rebuild_b4_semantic_report(inputs)
}

/// Verify a canonical report by independently rebuilding it from exact
/// external authority.
///
/// # Errors
///
/// Returns an error for a malformed report or for any byte, identity, ordering,
/// attribution, expectation, or cross-document difference.
#[cfg(test)]
pub(crate) fn verify_b4_semantic_report(
    report_source: &[u8],
    inputs: &B4SemanticReportInputsV1<'_>,
) -> Result<Eip0045B4SemanticReportV1> {
    let supplied = Eip0045B4SemanticReportV1::from_canonical_jcs(report_source)?;
    let rebuilt = rebuild_b4_semantic_report(inputs)?;
    ensure!(
        supplied == rebuilt,
        "B4 semantic report differs from exact independently rebuilt campaign bindings"
    );
    Ok(supplied)
}

#[cfg(test)]
fn rebuild_b4_semantic_report(
    inputs: &B4SemanticReportInputsV1<'_>,
) -> Result<Eip0045B4SemanticReportV1> {
    let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(inputs.negative_plan_source)
        .context("invalid semantic-report negative plan")?;
    let planned = plan
        .groups
        .iter()
        .flat_map(|group| group.executions.iter())
        .collect::<Vec<_>>();
    ensure!(
        planned.len() == B4_SEMANTIC_REPORT_EXECUTION_COUNT,
        "canonical plan flattening does not contain exactly 254 executions"
    );

    let registry = B4CandidateCorpus::from_canonical_jcs(inputs.expanded_registry_source)
        .context("invalid semantic-report expanded registry")?;
    registry
        .validate_expanded_against_canonical_plan_source(inputs.negative_plan_source)
        .context("expanded registry does not bind the exact canonical plan")?;
    ensure!(
        registry.negative_cases.len() == B4_SEMANTIC_REPORT_EXECUTION_COUNT,
        "expanded registry does not contain exactly 254 negative rows"
    );

    let expectation = verify_b4_negative_expectation_set(
        inputs.expectation_set_source,
        inputs.negative_plan_source,
    )
    .context("invalid semantic-report expectation authority")?;
    ensure!(
        expectation.executions.len() == B4_NEGATIVE_EXPECTATION_EXECUTION_COUNT,
        "expectation authority does not contain exactly 254 executions"
    );
    ensure!(
        expectation
            .executions
            .iter()
            .map(|execution| execution.slots.len())
            .sum::<usize>()
            == B4_NEGATIVE_EXPECTATION_SLOT_COUNT,
        "expectation authority does not contain exactly 508 slots"
    );
    ensure!(
        inputs.executions.len() == B4_SEMANTIC_REPORT_EXECUTION_COUNT,
        "semantic-report replay requires exactly 254 execution evidence entries"
    );

    let validator_commitments = validate_validator_authorities(&inputs.validators)?;
    ensure_registry_artifact(
        &registry.bindings.rust_verifier,
        &validator_commitments[0].artifact,
        "rust-reference",
    )?;
    ensure_registry_artifact(
        &registry.bindings.jvm_verifier,
        &validator_commitments[1].artifact,
        "independent-jvm",
    )?;

    let mut totals = B4SemanticDomainTotalsV1 {
        verifier_input: 0,
        artifact_validator: 0,
        tree_validator: 0,
    };
    let mut executions = Vec::with_capacity(B4_SEMANTIC_REPORT_EXECUTION_COUNT);
    for (index, (((planned_execution, registry_row), expected_execution), evidence)) in planned
        .into_iter()
        .zip(&registry.negative_cases)
        .zip(&expectation.executions)
        .zip(inputs.executions)
        .enumerate()
    {
        increment_domain_total(&mut totals, planned_execution.materialization_domain)?;
        executions.push(rebuild_semantic_execution(B4ExecutionRebuildContext {
            index,
            negative_plan_source: inputs.negative_plan_source,
            planned_execution,
            registry_row,
            expected_execution,
            evidence,
            validator_commitments: &validator_commitments,
        })?);
    }
    ensure!(
        totals == B4SemanticDomainTotalsV1::EXPECTED,
        "independently counted materialization-domain totals differ from 131/102/21"
    );

    finalize_semantic_report(inputs, validator_commitments, totals, executions)
}

#[cfg(test)]
#[derive(Clone, Copy)]
struct B4ExecutionRebuildContext<'a> {
    index: usize,
    negative_plan_source: &'a [u8],
    planned_execution: &'a crate::b4_plan::B4NegativePlanExecutionV1,
    registry_row: &'a crate::b4::B4NegativeCase,
    expected_execution: &'a crate::b4_expectation::B4NegativeExpectationExecutionV1,
    evidence: &'a B4SemanticExecutionEvidenceV1<'a>,
    validator_commitments: &'a [B4SemanticValidatorCommitmentV1],
}

#[cfg(test)]
fn rebuild_semantic_execution(
    context: B4ExecutionRebuildContext<'_>,
) -> Result<B4SemanticExecutionV1> {
    ensure!(
        context.registry_row.execution_id == context.planned_execution.execution_id,
        "registry execution ID differs from plan at index {}",
        context.index
    );
    ensure!(
        context.expected_execution.execution_id == context.planned_execution.execution_id
            && usize::from(context.expected_execution.execution_index) == context.index,
        "expectation execution differs from plan at index {}",
        context.index
    );

    let materialization_identity = Eip0045B4MaterializationIdentityV1::from_canonical_jcs(
        context.evidence.materialization_identity_source,
    )
    .with_context(|| {
        format!(
            "invalid materialization identity at index {}",
            context.index
        )
    })?;
    ensure!(
        materialization_identity.execution_id == context.planned_execution.execution_id,
        "materialization identity is cross-bound at index {}",
        context.index
    );
    verify_materialization_binding(
        &materialization_identity,
        context.negative_plan_source,
        context.planned_execution,
        context.registry_row,
        context.evidence.adapter,
    )
    .with_context(|| format!("materialization replay failed at index {}", context.index))?;

    let negative_input = Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(
        context.evidence.negative_input_source,
    )
    .with_context(|| format!("invalid negative verifier input at index {}", context.index))?;
    verify_negative_input_materialization(
        &negative_input,
        &materialization_identity,
        context.planned_execution,
        context.evidence.adapter,
        context.index,
    )?;

    let implementations = [
        B4ValidatorImplementation::RustReference,
        B4ValidatorImplementation::IndependentJvm,
    ];
    let mut slots = Vec::with_capacity(2);
    for (slot_index, implementation) in implementations.into_iter().enumerate() {
        slots.push(rebuild_semantic_slot(B4SlotRebuildContext {
            execution_index: context.index,
            slot_index,
            implementation,
            negative_plan_source: context.negative_plan_source,
            planned_execution: context.planned_execution,
            expected_slot: &context.expected_execution.slots[slot_index],
            negative_input: &negative_input,
            evidence: context.evidence,
            validator_artifact: &context.validator_commitments[slot_index].artifact,
        })?);
    }

    Ok(B4SemanticExecutionV1 {
        execution_index: u16::try_from(context.index)
            .context("semantic-report execution index does not fit u16")?,
        execution_id: context.planned_execution.execution_id.clone(),
        materialization_identity: B4SemanticByteIdentityV1::from_source(
            context.evidence.materialization_identity_source,
            64 * 1024,
            "materialization identity",
        )?,
        negative_input: B4SemanticByteIdentityV1::from_source(
            context.evidence.negative_input_source,
            64 * 1024,
            "negative verifier input",
        )?,
        slots,
    })
}

#[cfg(test)]
fn verify_negative_input_materialization(
    negative_input: &Eip0045B4NegativeVerifierInputV1,
    materialization_identity: &Eip0045B4MaterializationIdentityV1,
    planned_execution: &crate::b4_plan::B4NegativePlanExecutionV1,
    adapter: &dyn B4MaterializationReplayAdapterV1,
    index: usize,
) -> Result<()> {
    ensure!(
        negative_input.materialization_domain == planned_execution.materialization_domain,
        "negative input has the wrong materialization domain at index {index}"
    );
    ensure!(
        negative_input.validation_surface == planned_execution.execution_surface,
        "negative input has the wrong validation surface at index {index}"
    );
    ensure!(
        negative_input.subject.byte_length == materialization_identity.output_byte_length
            && negative_input.subject.sha256 == materialization_identity.output_sha256,
        "negative input subject is not the independently replayed materialization at index {index}"
    );
    let adapter_output_length = u64::try_from(adapter.output_bytes().len())
        .context("materialization adapter output length does not fit u64")?;
    ensure!(
        negative_input.subject.byte_length == adapter_output_length
            && negative_input.subject.sha256 == sha256_hex(adapter.output_bytes()),
        "negative input subject differs from exact replay-adapter output at index {index}"
    );
    Ok(())
}

#[cfg(test)]
#[derive(Clone, Copy)]
struct B4SlotRebuildContext<'a> {
    execution_index: usize,
    slot_index: usize,
    implementation: B4ValidatorImplementation,
    negative_plan_source: &'a [u8],
    planned_execution: &'a crate::b4_plan::B4NegativePlanExecutionV1,
    expected_slot: &'a crate::b4_expectation::B4NegativeExpectationSlotV1,
    negative_input: &'a Eip0045B4NegativeVerifierInputV1,
    evidence: &'a B4SemanticExecutionEvidenceV1<'a>,
    validator_artifact: &'a B4ValidatorArtifactIdentityV1,
}

#[cfg(test)]
fn rebuild_semantic_slot(context: B4SlotRebuildContext<'_>) -> Result<B4SemanticResultSlotV1> {
    ensure!(
        context.expected_slot.implementation == context.implementation,
        "expectation implementation order drift at execution {}, slot {}",
        context.execution_index,
        context.slot_index
    );
    let observation_source = context.evidence.observation_sources[context.slot_index];
    let observation = Eip0045B4NegativeObservationV1::from_canonical_jcs(observation_source)
        .with_context(|| {
            format!(
                "invalid observation at execution {}, slot {}",
                context.execution_index, context.slot_index
            )
        })?;
    verify_observation(
        &observation,
        context.evidence.negative_input_source,
        context.negative_input,
        context.planned_execution.materialization_domain,
        context.planned_execution.execution_surface,
        &context.expected_slot.rejection.class,
        &context.expected_slot.rejection.stage,
        context.execution_index,
        context.slot_index,
    )?;

    let result_source = context.evidence.result_sources[context.slot_index];
    verify_result_binding(
        result_source,
        context.negative_plan_source,
        context.evidence.materialization_identity_source,
        context.planned_execution,
        context.implementation,
        context.validator_artifact,
        &observation,
    )
    .with_context(|| {
        format!(
            "invalid result at execution {}, slot {}",
            context.execution_index, context.slot_index
        )
    })?;

    Ok(B4SemanticResultSlotV1 {
        implementation: context.implementation,
        observation: B4SemanticByteIdentityV1::from_source(
            observation_source,
            4 * 1024,
            "negative observation",
        )?,
        result: B4SemanticByteIdentityV1::from_source(
            result_source,
            64 * 1024,
            "validation result",
        )?,
    })
}

#[cfg(test)]
fn finalize_semantic_report(
    inputs: &B4SemanticReportInputsV1<'_>,
    validator_commitments: Vec<B4SemanticValidatorCommitmentV1>,
    totals: B4SemanticDomainTotalsV1,
    executions: Vec<B4SemanticExecutionV1>,
) -> Result<Eip0045B4SemanticReportV1> {
    let report = Eip0045B4SemanticReportV1 {
        format: B4_SEMANTIC_REPORT_FORMAT.to_owned(),
        format_version: B4_SEMANTIC_REPORT_FORMAT_VERSION,
        negative_plan: B4SemanticByteIdentityV1::from_source(
            inputs.negative_plan_source,
            128 * 1024,
            "negative plan",
        )?,
        expanded_registry: B4SemanticByteIdentityV1::from_source(
            inputs.expanded_registry_source,
            8 * 1024 * 1024,
            "expanded registry",
        )?,
        expectation_set: B4SemanticByteIdentityV1::from_source(
            inputs.expectation_set_source,
            256 * 1024,
            "expectation set",
        )?,
        validators: validator_commitments,
        domain_totals: totals,
        execution_count: B4_NEGATIVE_PLAN_VARIANT_COUNT,
        result_count: u16::try_from(B4_SEMANTIC_REPORT_RESULT_COUNT)
            .context("semantic-report result count does not fit u16")?,
        executions,
    };
    report.validate()?;
    Ok(report)
}

#[cfg(test)]
fn validate_validator_authorities(
    authorities: &[B4SemanticValidatorAuthorityV1<'_>; 2],
) -> Result<Vec<B4SemanticValidatorCommitmentV1>> {
    let implementations = [
        B4ValidatorImplementation::RustReference,
        B4ValidatorImplementation::IndependentJvm,
    ];
    let mut commitments = Vec::with_capacity(2);
    for (index, implementation) in implementations.into_iter().enumerate() {
        let authority = &authorities[index];
        ensure!(
            authority.implementation == implementation,
            "validator authority implementation order drift at index {index}"
        );
        validate_artifact_identity(authority.artifact)?;
        validate_descriptor_authority(
            authority.build_descriptor_source,
            implementation,
            authority.artifact,
        )
        .with_context(|| format!("invalid validator descriptor authority at index {index}"))?;
        commitments.push(B4SemanticValidatorCommitmentV1 {
            implementation,
            artifact: authority.artifact.clone(),
            build_descriptor: B4SemanticByteIdentityV1::from_source(
                authority.build_descriptor_source,
                MAX_DESCRIPTOR_BYTES,
                "validator build descriptor",
            )?,
        });
    }
    validate_validator_pair(&commitments)?;
    Ok(commitments)
}

#[cfg(test)]
fn expected_materialization_identity(
    negative_plan_source: &[u8],
    planned_execution: &crate::b4_plan::B4NegativePlanExecutionV1,
    registry_row: &crate::b4::B4NegativeCase,
    adapter: &dyn B4MaterializationReplayAdapterV1,
) -> Result<Eip0045B4MaterializationIdentityV1> {
    ensure!(
        registry_row.execution_id == planned_execution.execution_id
            && registry_row.base_selector_id == planned_execution.base_selector_id
            && registry_row.materialization_domain == planned_execution.materialization_domain,
        "registry row differs from the selected plan execution"
    );
    ensure!(
        adapter.materialization_domain() == planned_execution.materialization_domain,
        "materialization adapter has the wrong domain"
    );
    adapter.replay_recipe(
        &planned_execution.base_selector_id,
        &registry_row.materialization,
    )?;
    let recipe = canonical_materialization_recipe_jcs(&registry_row.materialization)?;
    Ok(Eip0045B4MaterializationIdentityV1 {
        format: B4_MATERIALIZATION_IDENTITY_FORMAT.to_owned(),
        format_version: B4_MATERIALIZATION_IDENTITY_FORMAT_VERSION,
        base_selector_id: planned_execution.base_selector_id.clone(),
        base_byte_length: u64::try_from(adapter.base_bytes().len())
            .context("materialization base length does not fit u64")?,
        base_sha256: sha256_hex(adapter.base_bytes()),
        execution_id: planned_execution.execution_id.clone(),
        materialization_domain: planned_execution.materialization_domain,
        materialization_recipe_byte_length: u64::try_from(recipe.len())
            .context("materialization recipe length does not fit u64")?,
        materialization_recipe_sha256: sha256_hex(&recipe),
        negative_plan_byte_length: u64::try_from(negative_plan_source.len())
            .context("negative plan length does not fit u64")?,
        negative_plan_sha256: sha256_hex(negative_plan_source),
        output_byte_length: u64::try_from(adapter.output_bytes().len())
            .context("materialization output length does not fit u64")?,
        output_sha256: sha256_hex(adapter.output_bytes()),
    })
}

#[cfg(test)]
fn verify_materialization_binding(
    supplied: &Eip0045B4MaterializationIdentityV1,
    negative_plan_source: &[u8],
    planned_execution: &crate::b4_plan::B4NegativePlanExecutionV1,
    registry_row: &crate::b4::B4NegativeCase,
    adapter: &dyn B4MaterializationReplayAdapterV1,
) -> Result<()> {
    let expected = expected_materialization_identity(
        negative_plan_source,
        planned_execution,
        registry_row,
        adapter,
    )?;
    ensure!(
        supplied == &expected,
        "materialization identity differs from independently rebuilt bindings"
    );
    Ok(())
}

#[cfg(test)]
fn verify_result_binding(
    result_source: &[u8],
    negative_plan_source: &[u8],
    materialization_identity_source: &[u8],
    planned_execution: &crate::b4_plan::B4NegativePlanExecutionV1,
    implementation: B4ValidatorImplementation,
    validator_artifact: &B4ValidatorArtifactIdentityV1,
    observation: &Eip0045B4NegativeObservationV1,
) -> Result<()> {
    let result = Eip0045B4ValidationResultV1::from_canonical_jcs(result_source)?;
    ensure!(
        result.execution_id == planned_execution.execution_id,
        "result names a different plan execution"
    );
    ensure!(
        result.implementation == implementation,
        "result names a different implementation"
    );
    ensure!(
        result.materialization_identity_byte_length
            == u64::try_from(materialization_identity_source.len())
                .context("materialization identity length does not fit u64")?
            && result.materialization_identity_sha256
                == sha256_hex(materialization_identity_source),
        "result materialization-identity commitment is stale"
    );
    ensure!(
        result.materialization_domain == planned_execution.materialization_domain,
        "result materialization domain differs from the plan"
    );
    ensure!(
        result.negative_plan_byte_length
            == u64::try_from(negative_plan_source.len())
                .context("negative plan length does not fit u64")?
            && result.negative_plan_sha256 == sha256_hex(negative_plan_source),
        "result negative-plan commitment is stale"
    );
    ensure!(
        result.qa_result_code == planned_execution.qa_result_code,
        "result QA code differs from the plan"
    );
    ensure!(
        result.validation_surface == planned_execution.execution_surface,
        "result validation surface differs from the plan"
    );
    ensure!(
        result.validator_artifact == *validator_artifact,
        "result validator artifact differs from finalizer authority"
    );
    ensure!(
        result.rejection.verdict == B4ValidationVerdict::Reject
            && result.rejection.class == observation.rejection.class
            && result.rejection.stage == observation.rejection.stage,
        "result rejection differs from the exact observation"
    );
    Ok(())
}

#[cfg(test)]
fn validate_descriptor_authority(
    source: &[u8],
    implementation: B4ValidatorImplementation,
    artifact: &B4ValidatorArtifactIdentityV1,
) -> Result<()> {
    ensure!(
        !source.is_empty() && source.len() <= MAX_DESCRIPTOR_BYTES,
        "validator build descriptor is empty or oversized"
    );
    let value = validate_canonical_json_source(source)
        .context("validator build descriptor is not exact RFC 8785 JCS")?;
    ensure!(
        canonical_json_bytes(&value)? == source,
        "validator build descriptor does not round-trip byte-exactly"
    );
    let object = value
        .as_object()
        .context("validator build descriptor is not an object")?;
    ensure!(
        object.get("format").and_then(serde_json::Value::as_str)
            == Some("Eip0045B4ValidatorBuildDescriptorV1"),
        "wrong validator build-descriptor format label"
    );
    ensure!(
        object
            .get("formatVersion")
            .and_then(serde_json::Value::as_u64)
            == Some(1),
        "wrong validator build-descriptor format version"
    );
    ensure!(
        object
            .get("implementation")
            .and_then(serde_json::Value::as_str)
            == Some(implementation_label(implementation)),
        "validator build descriptor names a different implementation"
    );
    let descriptor_artifact = object
        .get("artifact")
        .and_then(serde_json::Value::as_object)
        .context("validator build descriptor has no artifact object")?;
    ensure!(
        descriptor_artifact
            .get("byteLength")
            .and_then(serde_json::Value::as_u64)
            == Some(artifact.byte_length),
        "validator build descriptor binds a different artifact length"
    );
    ensure!(
        descriptor_artifact
            .get("sha256")
            .and_then(serde_json::Value::as_str)
            == Some(artifact.sha256.as_str()),
        "validator build descriptor binds a different artifact digest"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn verify_observation(
    observation: &Eip0045B4NegativeObservationV1,
    negative_input_source: &[u8],
    negative_input: &Eip0045B4NegativeVerifierInputV1,
    materialization_domain: B4MaterializationDomain,
    validation_surface: crate::b4_plan::B4NegativeExecutionSurface,
    expected_class: &str,
    expected_stage: &str,
    execution_index: usize,
    slot_index: usize,
) -> Result<()> {
    ensure!(
        observation.verdict == B4NegativeObservationVerdict::Reject,
        "observation is not a rejection at execution {execution_index}, slot {slot_index}"
    );
    ensure!(
        observation.materialization_domain == materialization_domain
            && observation.materialization_domain == negative_input.materialization_domain,
        "observation materialization domain is cross-bound at execution {execution_index}, slot {slot_index}"
    );
    ensure!(
        observation.validation_surface == validation_surface
            && observation.validation_surface == negative_input.validation_surface,
        "observation validation surface is cross-bound at execution {execution_index}, slot {slot_index}"
    );
    ensure!(
        observation.negative_input_sha256 == sha256_hex(negative_input_source),
        "observation negative-input commitment is stale at execution {execution_index}, slot {slot_index}"
    );
    ensure!(
        observation.subject_byte_length == negative_input.subject.byte_length
            && observation.subject_sha256 == negative_input.subject.sha256,
        "observation subject commitment is stale at execution {execution_index}, slot {slot_index}"
    );
    ensure!(
        observation.rejection.class == expected_class
            && observation.rejection.stage == expected_stage,
        "observation differs from the frozen expectation at execution {execution_index}, slot {slot_index}"
    );
    Ok(())
}

#[cfg(test)]
fn ensure_registry_artifact(
    binding: &crate::b4::B4ArtifactBinding,
    artifact: &B4ValidatorArtifactIdentityV1,
    label: &str,
) -> Result<()> {
    ensure!(
        binding.state == B4BindingState::Bound,
        "expanded registry {label} artifact is not bound"
    );
    ensure!(
        binding.byte_length == artifact.byte_length && binding.sha256 == artifact.sha256,
        "expanded registry {label} artifact identity differs from finalizer authority"
    );
    Ok(())
}

#[cfg(test)]
fn increment_domain_total(
    totals: &mut B4SemanticDomainTotalsV1,
    domain: B4MaterializationDomain,
) -> Result<()> {
    let target = match domain {
        B4MaterializationDomain::VerifierInput => &mut totals.verifier_input,
        B4MaterializationDomain::ArtifactValidator => &mut totals.artifact_validator,
        B4MaterializationDomain::TreeValidator => &mut totals.tree_validator,
    };
    *target = target
        .checked_add(1)
        .context("semantic-report domain total overflows u16")?;
    Ok(())
}

fn validate_validator_pair(validators: &[B4SemanticValidatorCommitmentV1]) -> Result<()> {
    ensure!(
        validators.len() == 2,
        "semantic report must contain exactly two validator commitments"
    );
    ensure!(
        validators[0].implementation == B4ValidatorImplementation::RustReference,
        "semantic-report validator zero must be rust-reference"
    );
    ensure!(
        validators[1].implementation == B4ValidatorImplementation::IndependentJvm,
        "semantic-report validator one must be independent-jvm"
    );
    validators[0].validate()?;
    validators[1].validate()?;
    ensure!(
        validators[0].artifact != validators[1].artifact,
        "semantic-report validator artifacts alias"
    );
    ensure!(
        validators[0].build_descriptor != validators[1].build_descriptor,
        "semantic-report validator descriptors alias"
    );
    Ok(())
}

fn validate_slot_pair(slots: &[B4SemanticResultSlotV1]) -> Result<()> {
    ensure!(
        slots.len() == 2,
        "semantic-report execution must contain exactly two result slots"
    );
    ensure!(
        slots[0].implementation == B4ValidatorImplementation::RustReference,
        "semantic-report slot zero must be rust-reference"
    );
    ensure!(
        slots[1].implementation == B4ValidatorImplementation::IndependentJvm,
        "semantic-report slot one must be independent-jvm"
    );
    slots[0].validate()?;
    slots[1].validate()
}

fn validate_artifact_identity(identity: &B4ValidatorArtifactIdentityV1) -> Result<()> {
    ensure!(
        (1..=MAX_VALIDATOR_ARTIFACT_BYTES).contains(&identity.byte_length),
        "validator artifact length is outside the V1 bound"
    );
    validate_digest(&identity.sha256, "validator artifact SHA-256")
}

#[cfg(test)]
fn implementation_label(implementation: B4ValidatorImplementation) -> &'static str {
    match implementation {
        B4ValidatorImplementation::RustReference => "rust-reference",
        B4ValidatorImplementation::IndependentJvm => "independent-jvm",
    }
}

fn validate_execution_id(value: &str) -> Result<()> {
    let (group, variant) = value
        .split_once("--")
        .context("semantic-report execution ID has no group/variant separator")?;
    ensure!(
        !variant.contains("--"),
        "semantic-report execution ID has more than one group/variant separator"
    );
    validate_lower_kebab(group, "semantic-report execution group ID")?;
    validate_lower_kebab(variant, "semantic-report execution variant ID")
}

fn validate_lower_kebab(value: &str, label: &str) -> Result<()> {
    let bytes = value.as_bytes();
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_EXECUTION_COMPONENT_BYTES,
        "{label} is empty or too long"
    );
    ensure!(
        bytes[0].is_ascii_lowercase() && bytes[bytes.len() - 1].is_ascii_alphanumeric(),
        "{label} must start with a lowercase letter and end with an alphanumeric"
    );
    ensure!(
        bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-'),
        "{label} is not bounded lower-kebab ASCII"
    );
    ensure!(!value.contains("--"), "{label} contains an empty component");
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

#[cfg(test)]
fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use anyhow::{Result, ensure};
    use serde_json::{Value, json};

    use super::*;
    use crate::{
        b4::{
            B4AncestryInventoryOperation, B4AncestryInventoryTarget, B4ArtifactBinding,
            B4ArtifactEncoding, B4BindingState, B4ByteOperation, B4ByteTarget, B4GuestBinding,
            B4NegativeCase, B4NegativeMaterialization, B4NegativeMutation, B4PositiveArtifact,
            B4PositiveArtifactRole, B4PositiveFamily, B4RegistryStage, B4StatementBinding,
            negative_ancestry_witness_recipe,
        },
        b4_expectation::{
            B4NegativeExpectationPairV1, B4NegativeExpectationSlotV1,
            B4NegativeExpectedRejectionV1, create_b4_negative_expectation_set,
        },
        b4_mutation::B4MaterializationReplayAdapterV1,
        b4_negative_io::{
            B4NegativeFileEncoding, B4NegativeNamedIdentityV1, B4NegativeObservationRejectionV1,
        },
        b4_plan::B4NegativePlanExecutionV1,
        b4_result::B4ObservedRejectionV1,
    };

    const CANDIDATE_ROOT: &str = "reproduction/schema/b4-corpus-v1.candidate/";

    #[derive(Clone, Debug)]
    struct ExactAdapter {
        domain: B4MaterializationDomain,
        base_selector_id: String,
        base: Vec<u8>,
        output: Vec<u8>,
        materialization: B4NegativeMaterialization,
    }

    impl B4MaterializationReplayAdapterV1 for ExactAdapter {
        fn materialization_domain(&self) -> B4MaterializationDomain {
            self.domain
        }

        fn base_bytes(&self) -> &[u8] {
            &self.base
        }

        fn output_bytes(&self) -> &[u8] {
            &self.output
        }

        fn replay_recipe(
            &self,
            base_selector_id: &str,
            materialization: &B4NegativeMaterialization,
        ) -> Result<()> {
            ensure!(
                base_selector_id == self.base_selector_id,
                "synthetic adapter selector drift"
            );
            ensure!(
                materialization == &self.materialization,
                "synthetic adapter recipe drift"
            );
            Ok(())
        }
    }

    #[derive(Clone, Debug)]
    struct OwnedExecutionEvidence {
        adapter: ExactAdapter,
        materialization_identity: Vec<u8>,
        negative_input: Vec<u8>,
        observations: [Vec<u8>; 2],
        results: [Vec<u8>; 2],
    }

    #[derive(Clone, Debug)]
    struct CampaignFixture {
        plan: Vec<u8>,
        registry: Vec<u8>,
        expectation: Vec<u8>,
        artifacts: [B4ValidatorArtifactIdentityV1; 2],
        descriptors: [Vec<u8>; 2],
        executions: Vec<OwnedExecutionEvidence>,
    }

    impl CampaignFixture {
        fn with_inputs<T>(&self, operation: impl FnOnce(&B4SemanticReportInputsV1<'_>) -> T) -> T {
            let execution_evidence = self
                .executions
                .iter()
                .map(|evidence| B4SemanticExecutionEvidenceV1 {
                    materialization_identity_source: &evidence.materialization_identity,
                    negative_input_source: &evidence.negative_input,
                    observation_sources: [&evidence.observations[0], &evidence.observations[1]],
                    result_sources: [&evidence.results[0], &evidence.results[1]],
                    adapter: &evidence.adapter,
                })
                .collect::<Vec<_>>();
            let inputs = B4SemanticReportInputsV1 {
                negative_plan_source: &self.plan,
                expanded_registry_source: &self.registry,
                expectation_set_source: &self.expectation,
                validators: [
                    B4SemanticValidatorAuthorityV1 {
                        implementation: B4ValidatorImplementation::RustReference,
                        artifact: &self.artifacts[0],
                        build_descriptor_source: &self.descriptors[0],
                    },
                    B4SemanticValidatorAuthorityV1 {
                        implementation: B4ValidatorImplementation::IndependentJvm,
                        artifact: &self.artifacts[1],
                        build_descriptor_source: &self.descriptors[1],
                    },
                ],
                executions: &execution_evidence,
            };
            operation(&inputs)
        }

        fn report(&self) -> Eip0045B4SemanticReportV1 {
            self.with_inputs(create_b4_semantic_report).unwrap()
        }

        fn verify(&self, report: &[u8]) -> Result<Eip0045B4SemanticReportV1> {
            self.with_inputs(|inputs| verify_b4_semantic_report(report, inputs))
        }
    }

    fn digest(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn fixture_rejection(execution: &B4NegativePlanExecutionV1) -> B4NegativeExpectedRejectionV1 {
        let boundary =
            crate::b4_negative_handler_contract::exact_negative_rejection_boundary(execution)
                .unwrap();
        B4NegativeExpectedRejectionV1 {
            class: boundary.class().to_owned(),
            stage: boundary.stage().to_owned(),
        }
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

    fn positive_artifacts(case_id: &str, family: B4PositiveFamily) -> Vec<B4PositiveArtifact> {
        let lift = [
            B4PositiveArtifactRole::ClaimDigest,
            B4PositiveArtifactRole::ControlId,
            B4PositiveArtifactRole::ImageId,
            B4PositiveArtifactRole::Journal,
            B4PositiveArtifactRole::Metadata,
            B4PositiveArtifactRole::RawSeal,
            B4PositiveArtifactRole::ReceiptOracle,
        ];
        let recursive = [
            B4PositiveArtifactRole::Ancestry,
            B4PositiveArtifactRole::Calibration,
            B4PositiveArtifactRole::ClaimDigest,
            B4PositiveArtifactRole::ControlId,
            B4PositiveArtifactRole::ImageId,
            B4PositiveArtifactRole::Journal,
            B4PositiveArtifactRole::RawSeal,
            B4PositiveArtifactRole::ReceiptOracle,
        ];
        let roles: &[B4PositiveArtifactRole] = if family == B4PositiveFamily::Lift {
            &lift
        } else {
            &recursive
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
                path: format!("{CANDIDATE_ROOT}positive/{case_id}/{index:02}-artifact"),
                role,
                sha256: digest(1),
            })
            .collect()
    }

    fn materialization(
        group_id: &str,
        execution: &B4NegativePlanExecutionV1,
    ) -> B4NegativeMaterialization {
        if let Some(recipe) = negative_ancestry_witness_recipe(&execution.execution_id) {
            B4NegativeMaterialization::Mutation {
                mutation: B4NegativeMutation::AncestryWitnessSubstitution { recipe },
            }
        } else if execution.execution_id == "resolve-assumption-inventory-sweep--pruned-assumption"
        {
            B4NegativeMaterialization::Mutation {
                mutation: B4NegativeMutation::AncestryInventoryEdit {
                    target: B4AncestryInventoryTarget::AssumptionSourceInventoryHead,
                    edit: B4AncestryInventoryOperation::PruneRevealedHead {
                        before_claim_digest: digest(0x31),
                        before_control_root: digest(0x32),
                        exact_digest: digest(0x33),
                    },
                },
            }
        } else if execution.execution_id == "resolve-explicit-field-sweep--assumption-receipt-root"
        {
            B4NegativeMaterialization::Mutation {
                mutation: B4NegativeMutation::AlternateRootAssumptionSubstitution {},
            }
        } else if negative_group_requires_fixture_selection(group_id) {
            B4NegativeMaterialization::FixtureSelection {
                fixture_id: execution.base_selector_id.clone(),
            }
        } else {
            B4NegativeMaterialization::Mutation {
                mutation: B4NegativeMutation::ByteEdit {
                    edit: B4ByteOperation::Replace {
                        before_hex: "00".to_owned(),
                        offset: 0,
                        replacement_hex: "01".to_owned(),
                    },
                    target: B4ByteTarget::Statement,
                },
            }
        }
    }

    #[test]
    fn complete_campaign_fixture_uses_all_eleven_closed_ancestry_witness_recipes() {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let ancestry_rows = plan
            .groups
            .iter()
            .flat_map(|group| {
                group
                    .executions
                    .iter()
                    .map(move |execution| (&group.case_id, execution))
            })
            .filter_map(|(group_id, execution)| {
                negative_ancestry_witness_recipe(&execution.execution_id)
                    .map(|recipe| (group_id, execution, recipe))
            })
            .collect::<Vec<_>>();

        assert_eq!(ancestry_rows.len(), 11);
        for (group_id, execution, recipe) in ancestry_rows {
            assert_eq!(
                materialization(group_id, execution),
                B4NegativeMaterialization::Mutation {
                    mutation: B4NegativeMutation::AncestryWitnessSubstitution { recipe },
                }
            );
        }
    }

    #[test]
    fn complete_campaign_fixture_uses_the_closed_row_155_semantic_recipe() {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let execution = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .find(|execution| {
                execution.execution_id == "resolve-assumption-inventory-sweep--pruned-assumption"
            })
            .unwrap();
        let recipe = materialization("resolve-assumption-inventory-sweep", execution);

        assert!(matches!(
            recipe,
            B4NegativeMaterialization::Mutation {
                mutation: B4NegativeMutation::AncestryInventoryEdit {
                    target: B4AncestryInventoryTarget::AssumptionSourceInventoryHead,
                    edit: B4AncestryInventoryOperation::PruneRevealedHead { .. },
                },
            }
        ));
    }

    #[test]
    fn complete_campaign_fixture_uses_the_closed_row_146_alternate_root_recipe() {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let execution = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .find(|execution| {
                execution.execution_id == "resolve-explicit-field-sweep--assumption-receipt-root"
            })
            .unwrap();

        assert_eq!(
            materialization("resolve-explicit-field-sweep", execution),
            B4NegativeMaterialization::Mutation {
                mutation: B4NegativeMutation::AlternateRootAssumptionSubstitution {},
            }
        );
    }

    fn descriptor(
        implementation: B4ValidatorImplementation,
        artifact: &B4ValidatorArtifactIdentityV1,
    ) -> Vec<u8> {
        canonical_json_bytes(&json!({
            "artifact": {
                "byteLength": artifact.byte_length,
                "sha256": artifact.sha256,
            },
            "format": "Eip0045B4ValidatorBuildDescriptorV1",
            "formatVersion": 1,
            "implementation": implementation_label(implementation),
        }))
        .unwrap()
    }

    fn expanded_registry(
        plan: &Eip0045B4NegativePlanV1,
        plan_source: &[u8],
        artifacts: &[B4ValidatorArtifactIdentityV1; 2],
    ) -> (B4CandidateCorpus, Vec<(String, B4NegativeCase)>) {
        let mut corpus = B4CandidateCorpus::from_canonical_jcs(include_bytes!(
            "../schema/b4-corpus-v1.candidate.json"
        ))
        .unwrap();
        corpus.stage = B4RegistryStage::Expanded;
        corpus.bindings.reference_statement_bundle = B4StatementBinding {
            contract_id: digest(8),
            manifest: bound(
                format!("{CANDIDATE_ROOT}bindings/statement-manifest.json"),
                B4ArtifactEncoding::Rfc8785Jcs,
            ),
            statement_sha256: digest(9),
            state: B4BindingState::Bound,
        };
        corpus.bindings.guest = B4GuestBinding {
            elf: bound(
                format!("{CANDIDATE_ROOT}bindings/guest.elf"),
                B4ArtifactEncoding::RawBytes,
            ),
            image_id: digest(10),
            state: B4BindingState::Bound,
        };
        corpus.bindings.source_lock = bound(
            format!("{CANDIDATE_ROOT}bindings/source-lock.json"),
            B4ArtifactEncoding::Rfc8785Jcs,
        );
        corpus.bindings.generator = bound(
            format!("{CANDIDATE_ROOT}bindings/generator.bin"),
            B4ArtifactEncoding::RawBytes,
        );
        corpus.bindings.rust_verifier = B4ArtifactBinding {
            byte_length: artifacts[0].byte_length,
            encoding: B4ArtifactEncoding::RawBytes,
            path: format!("{CANDIDATE_ROOT}bindings/rust-verifier.bin"),
            sha256: artifacts[0].sha256.clone(),
            state: B4BindingState::Bound,
        };
        corpus.bindings.jvm_verifier = B4ArtifactBinding {
            byte_length: artifacts[1].byte_length,
            encoding: B4ArtifactEncoding::RawBytes,
            path: format!("{CANDIDATE_ROOT}bindings/jvm-verifier.bin"),
            sha256: artifacts[1].sha256.clone(),
            state: B4BindingState::Bound,
        };
        corpus
            .bind_canonical_negative_plan_source(
                format!("{CANDIDATE_ROOT}bindings/negative-plan.json"),
                plan_source,
            )
            .unwrap();
        corpus.bindings.subject_catalog = bound(
            format!("{CANDIDATE_ROOT}bindings/subject-catalog.json"),
            B4ArtifactEncoding::Rfc8785Jcs,
        );
        corpus.bindings.terminal_fixture_catalog = bound(
            format!("{CANDIDATE_ROOT}bindings/terminal-fixture-catalog.json"),
            B4ArtifactEncoding::Rfc8785Jcs,
        );
        for case in &mut corpus.positive_cases {
            case.artifacts = positive_artifacts(&case.case_id, case.family);
        }

        let rows = plan
            .groups
            .iter()
            .flat_map(|group| {
                group
                    .executions
                    .iter()
                    .map(move |execution| (group.case_id.clone(), execution))
            })
            .map(|(group_id, execution)| {
                (
                    group_id.clone(),
                    B4NegativeCase {
                        execution_id: execution.execution_id.clone(),
                        base_selector_id: execution.base_selector_id.clone(),
                        materialization_domain: execution.materialization_domain,
                        materialization: materialization(&group_id, execution),
                    },
                )
            })
            .collect::<Vec<_>>();
        corpus.negative_cases = rows.iter().map(|(_, row)| row.clone()).collect();
        corpus
            .validate_expanded_against_canonical_plan_source(plan_source)
            .unwrap();
        (corpus, rows)
    }

    #[allow(clippy::too_many_lines)]
    fn campaign_fixture() -> CampaignFixture {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let plan_source = plan.to_canonical_jcs().unwrap();
        let artifacts = [
            B4ValidatorArtifactIdentityV1::from_bytes(b"rust-reference-artifact").unwrap(),
            B4ValidatorArtifactIdentityV1::from_bytes(b"independent-jvm-artifact").unwrap(),
        ];
        let descriptors = [
            descriptor(B4ValidatorImplementation::RustReference, &artifacts[0]),
            descriptor(B4ValidatorImplementation::IndependentJvm, &artifacts[1]),
        ];
        let (registry, rows) = expanded_registry(&plan, &plan_source, &artifacts);
        let registry_source = registry.to_canonical_jcs().unwrap();
        let planned = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .collect::<Vec<_>>();

        let pairs = planned
            .iter()
            .map(|execution| {
                let rejection = fixture_rejection(execution);
                B4NegativeExpectationPairV1 {
                    execution_id: execution.execution_id.clone(),
                    slots: vec![
                        B4NegativeExpectationSlotV1 {
                            implementation: B4ValidatorImplementation::RustReference,
                            rejection: rejection.clone(),
                        },
                        B4NegativeExpectationSlotV1 {
                            implementation: B4ValidatorImplementation::IndependentJvm,
                            rejection,
                        },
                    ],
                }
            })
            .collect::<Vec<_>>();
        let expectation_source = create_b4_negative_expectation_set(&plan_source, &pairs)
            .unwrap()
            .to_canonical_jcs()
            .unwrap();

        let executions = planned
            .iter()
            .zip(rows.iter())
            .enumerate()
            .map(|(index, (execution, (_, registry_row)))| {
                let required_subject_length = usize::try_from(
                    crate::b4_negative_handler_contract::planned_negative_handler_contract(
                        execution.materialization_domain,
                        execution.execution_surface,
                    )
                    .unwrap()
                    .unwrap()
                    .custody()
                    .subject()
                    .minimum(),
                )
                .unwrap();
                let mut base = vec![
                    0,
                    u8::try_from(index / 256).unwrap(),
                    u8::try_from(index % 256).unwrap(),
                ];
                base.resize(base.len().max(required_subject_length), 0);
                let output = match &registry_row.materialization {
                    B4NegativeMaterialization::Mutation { .. } => {
                        let mut mutated = base.clone();
                        mutated[0] = 1;
                        mutated
                    }
                    B4NegativeMaterialization::FixtureSelection { .. } => base.clone(),
                };
                let adapter = ExactAdapter {
                    domain: execution.materialization_domain,
                    base_selector_id: execution.base_selector_id.clone(),
                    base,
                    output: output.clone(),
                    materialization: registry_row.materialization.clone(),
                };
                let identity = expected_materialization_identity(
                    &plan_source,
                    execution,
                    registry_row,
                    &adapter,
                )
                .unwrap()
                .to_canonical_jcs()
                .unwrap();
                let negative_input = Eip0045B4NegativeVerifierInputV1 {
                    format: crate::b4_negative_io::B4_NEGATIVE_VERIFIER_INPUT_FORMAT.to_owned(),
                    format_version:
                        crate::b4_negative_io::B4_NEGATIVE_VERIFIER_INPUT_FORMAT_VERSION,
                    materialization_domain: execution.materialization_domain,
                    validation_surface: execution.execution_surface,
                    subject: B4NegativeNamedIdentityV1 {
                        role: "subject".to_owned(),
                        path: "subject.bin".to_owned(),
                        byte_length: u64::try_from(output.len()).unwrap(),
                        sha256: sha256_hex(&output),
                        encoding: B4NegativeFileEncoding::RawBytes,
                    },
                    context: vec![],
                }
                .to_canonical_jcs()
                .unwrap();
                let rejection = fixture_rejection(execution);
                let observation = Eip0045B4NegativeObservationV1 {
                    format: crate::b4_negative_io::B4_NEGATIVE_OBSERVATION_FORMAT.to_owned(),
                    format_version: crate::b4_negative_io::B4_NEGATIVE_OBSERVATION_FORMAT_VERSION,
                    materialization_domain: execution.materialization_domain,
                    validation_surface: execution.execution_surface,
                    negative_input_sha256: sha256_hex(&negative_input),
                    subject_byte_length: u64::try_from(output.len()).unwrap(),
                    subject_sha256: sha256_hex(&output),
                    verdict: B4NegativeObservationVerdict::Reject,
                    rejection: B4NegativeObservationRejectionV1 {
                        class: rejection.class.clone(),
                        stage: rejection.stage.clone(),
                    },
                }
                .to_canonical_jcs()
                .unwrap();
                let observed = B4ObservedRejectionV1 {
                    class: rejection.class.clone(),
                    stage: rejection.stage.clone(),
                    verdict: B4ValidationVerdict::Reject,
                };
                let result = |implementation, validator_artifact, rejection| {
                    Eip0045B4ValidationResultV1 {
                        format: crate::b4_result::B4_VALIDATION_RESULT_FORMAT.to_owned(),
                        format_version: crate::b4_result::B4_VALIDATION_RESULT_FORMAT_VERSION,
                        execution_id: execution.execution_id.clone(),
                        implementation,
                        materialization_identity_byte_length: u64::try_from(identity.len())
                            .unwrap(),
                        materialization_identity_sha256: sha256_hex(&identity),
                        materialization_domain: execution.materialization_domain,
                        negative_plan_byte_length: u64::try_from(plan_source.len()).unwrap(),
                        negative_plan_sha256: sha256_hex(&plan_source),
                        qa_result_code: execution.qa_result_code,
                        rejection,
                        validator_artifact,
                        validation_surface: execution.execution_surface,
                    }
                    .to_canonical_jcs()
                    .unwrap()
                };
                let results = [
                    result(
                        B4ValidatorImplementation::RustReference,
                        artifacts[0].clone(),
                        observed.clone(),
                    ),
                    result(
                        B4ValidatorImplementation::IndependentJvm,
                        artifacts[1].clone(),
                        observed,
                    ),
                ];
                OwnedExecutionEvidence {
                    adapter,
                    materialization_identity: identity,
                    negative_input,
                    observations: [observation.clone(), observation],
                    results,
                }
            })
            .collect();

        CampaignFixture {
            plan: plan_source,
            registry: registry_source,
            expectation: expectation_source,
            artifacts,
            descriptors,
            executions,
        }
    }

    #[test]
    fn semantic_report_rebuilds_the_complete_254_by_2_campaign() {
        let fixture = campaign_fixture();
        let report = fixture.report();
        assert_eq!(report.executions.len(), 254);
        assert_eq!(report.result_count, 508);
        assert_eq!(
            report.domain_totals,
            B4SemanticDomainTotalsV1 {
                verifier_input: 131,
                artifact_validator: 102,
                tree_validator: 21,
            }
        );
        assert_eq!(
            report.executions[0].slots[0].observation, report.executions[0].slots[1].observation,
            "identical observation bytes are valid when exact bindings agree"
        );
        let source = report.to_canonical_jcs().unwrap();
        assert_eq!(
            Eip0045B4SemanticReportV1::from_canonical_jcs(&source).unwrap(),
            report
        );
        assert_eq!(fixture.verify(&source).unwrap(), report);
    }

    #[test]
    fn global_gate_rejects_missing_duplicate_swapped_relabelled_and_cross_bound_evidence() {
        let fixture = campaign_fixture();
        fixture.with_inputs(|inputs| {
            let shortened = &inputs.executions[..253];
            let altered = B4SemanticReportInputsV1 {
                negative_plan_source: inputs.negative_plan_source,
                expanded_registry_source: inputs.expanded_registry_source,
                expectation_set_source: inputs.expectation_set_source,
                validators: [
                    B4SemanticValidatorAuthorityV1 {
                        implementation: inputs.validators[0].implementation,
                        artifact: inputs.validators[0].artifact,
                        build_descriptor_source: inputs.validators[0].build_descriptor_source,
                    },
                    B4SemanticValidatorAuthorityV1 {
                        implementation: inputs.validators[1].implementation,
                        artifact: inputs.validators[1].artifact,
                        build_descriptor_source: inputs.validators[1].build_descriptor_source,
                    },
                ],
                executions: shortened,
            };
            assert!(create_b4_semantic_report(&altered).is_err());
        });

        let mut duplicate = fixture.clone();
        duplicate.executions[1] = duplicate.executions[0].clone();
        assert!(duplicate.with_inputs(create_b4_semantic_report).is_err());

        let mut swapped = fixture.clone();
        swapped.executions.swap(0, 1);
        assert!(swapped.with_inputs(create_b4_semantic_report).is_err());

        let mut cross_bound_input = fixture.clone();
        cross_bound_input.executions[1].negative_input =
            cross_bound_input.executions[0].negative_input.clone();
        assert!(
            cross_bound_input
                .with_inputs(create_b4_semantic_report)
                .is_err()
        );

        let mut reused_observation = fixture.clone();
        reused_observation.executions[1].observations[0] =
            reused_observation.executions[0].observations[0].clone();
        assert!(
            reused_observation
                .with_inputs(create_b4_semantic_report)
                .is_err()
        );

        let mut swapped_result = fixture.clone();
        swapped_result.executions[0].results.swap(0, 1);
        assert!(
            swapped_result
                .with_inputs(create_b4_semantic_report)
                .is_err()
        );

        let mut relabelled_identity = fixture.clone();
        let mut identity: Value =
            serde_json::from_slice(&relabelled_identity.executions[0].materialization_identity)
                .unwrap();
        identity["executionId"] = json!(
            Eip0045B4NegativePlanV1::canonical().unwrap().groups[0].executions[1].execution_id
        );
        relabelled_identity.executions[0].materialization_identity =
            canonical_json_bytes(&identity).unwrap();
        assert!(
            relabelled_identity
                .with_inputs(create_b4_semantic_report)
                .is_err()
        );
    }

    #[test]
    fn global_gate_rejects_expectation_artifact_descriptor_and_registry_drift() {
        let fixture = campaign_fixture();

        let mut expectation_drift = fixture.clone();
        let mut expectation: Value =
            serde_json::from_slice(&expectation_drift.expectation).unwrap();
        expectation["executions"][0]["slots"][0]["rejection"]["stage"] =
            json!("different-stable-checkpoint");
        expectation_drift.expectation = canonical_json_bytes(&expectation).unwrap();
        assert!(
            expectation_drift
                .with_inputs(create_b4_semantic_report)
                .is_err()
        );

        let mut descriptor_drift = fixture.clone();
        let mut descriptor_value: Value =
            serde_json::from_slice(&descriptor_drift.descriptors[0]).unwrap();
        descriptor_value["artifact"]["sha256"] = json!(digest(99));
        descriptor_drift.descriptors[0] = canonical_json_bytes(&descriptor_value).unwrap();
        assert!(
            descriptor_drift
                .with_inputs(create_b4_semantic_report)
                .is_err()
        );

        let mut artifact_swap = fixture.clone();
        artifact_swap.artifacts.swap(0, 1);
        assert!(
            artifact_swap
                .with_inputs(create_b4_semantic_report)
                .is_err()
        );

        let mut registry_drift = fixture.clone();
        let mut registry: Value = serde_json::from_slice(&registry_drift.registry).unwrap();
        registry["negativeCases"].as_array_mut().unwrap().swap(0, 1);
        registry_drift.registry = canonical_json_bytes(&registry).unwrap();
        assert!(
            registry_drift
                .with_inputs(create_b4_semantic_report)
                .is_err()
        );
    }

    #[test]
    fn report_parser_rejects_duplicate_unknown_noncanonical_bounds_order_and_trailing_bytes() {
        let fixture = campaign_fixture();
        let canonical = fixture.report().to_canonical_jcs().unwrap();
        let pretty =
            serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&canonical).unwrap())
                .unwrap();
        assert!(Eip0045B4SemanticReportV1::from_canonical_jcs(&pretty).is_err());

        let mut unknown: Value = serde_json::from_slice(&canonical).unwrap();
        unknown["runtimeStatus"] = json!("success");
        assert!(
            Eip0045B4SemanticReportV1::from_canonical_jcs(&canonical_json_bytes(&unknown).unwrap())
                .is_err()
        );

        let duplicate = String::from_utf8(canonical.clone()).unwrap().replacen(
            "\"format\":\"Eip0045B4SemanticReportV1\"",
            "\"format\":\"Eip0045B4SemanticReportV1\",\"format\":\"Eip0045B4SemanticReportV1\"",
            1,
        );
        assert!(Eip0045B4SemanticReportV1::from_canonical_jcs(duplicate.as_bytes()).is_err());

        let mut trailing = canonical.clone();
        trailing.push(b'\n');
        assert!(Eip0045B4SemanticReportV1::from_canonical_jcs(&trailing).is_err());
        assert!(
            Eip0045B4SemanticReportV1::from_canonical_jcs(&canonical[..canonical.len() - 1])
                .is_err()
        );

        for replacement in ["254.5", "\"254\"", "9007199254740992"] {
            let altered = String::from_utf8(canonical.clone()).unwrap().replacen(
                "\"executionCount\":254",
                &format!("\"executionCount\":{replacement}"),
                1,
            );
            assert!(
                Eip0045B4SemanticReportV1::from_canonical_jcs(altered.as_bytes()).is_err(),
                "invalid scalar unexpectedly accepted: {replacement}"
            );
        }

        let mut wrong_index: Eip0045B4SemanticReportV1 =
            Eip0045B4SemanticReportV1::from_canonical_jcs(&canonical).unwrap();
        wrong_index.executions[0].execution_index = 1;
        assert!(wrong_index.validate().is_err());
        let mut swapped_slots = wrong_index;
        swapped_slots.executions[0].execution_index = 0;
        swapped_slots.executions[0].slots.swap(0, 1);
        assert!(swapped_slots.validate().is_err());

        let mut zero_identity = Eip0045B4SemanticReportV1::from_canonical_jcs(&canonical).unwrap();
        zero_identity.executions[0].negative_input.byte_length = 0;
        assert!(zero_identity.validate().is_err());
        let mut oversized = zero_identity;
        oversized.executions[0].negative_input.byte_length = MAX_EXTERNAL_DOCUMENT_BYTES + 1;
        assert!(oversized.validate().is_err());
    }

    #[test]
    fn report_commitments_cannot_authorize_their_own_coordinated_rewrite() {
        let fixture = campaign_fixture();
        let mut report = fixture.report();
        report.executions[0].slots[0].observation.sha256 = digest(77);
        let source = report.to_canonical_jcs().unwrap();
        assert!(fixture.verify(&source).is_err());

        let mut report = fixture.report();
        report.validators[0].build_descriptor.sha256 = digest(78);
        let source = report.to_canonical_jcs().unwrap();
        assert!(fixture.verify(&source).is_err());
    }

    #[test]
    fn runtime_failure_or_counts_without_exact_records_cannot_become_evidence() {
        let mut fixture = campaign_fixture();
        fixture.executions[0].observations[0].clear();
        assert!(fixture.with_inputs(create_b4_semantic_report).is_err());

        let mut fixture = campaign_fixture();
        fixture.executions[0].results[0].clear();
        assert!(fixture.with_inputs(create_b4_semantic_report).is_err());

        let mut report = campaign_fixture().report();
        report.executions.pop();
        report.execution_count = 254;
        report.result_count = 508;
        assert!(report.validate().is_err());
    }

    #[cfg(feature = "positive-gate")]
    #[test]
    fn semantic_report_schema_matches_the_closed_shape() {
        let fixture = campaign_fixture();
        let report = serde_json::to_value(fixture.report()).unwrap();
        let schema = crate::canonical::parse_json_strict(include_bytes!(
            "../finalizer-schema/b4-semantic-report-v1.schema.json"
        ))
        .unwrap();
        let validator = jsonschema::draft202012::options().build(&schema).unwrap();
        validator.validate(&report).unwrap();

        let mut unknown = report.clone();
        unknown["runtimeStatus"] = json!("success");
        assert!(validator.validate(&unknown).is_err());
        let mut swapped = report;
        swapped["executions"][0]["slots"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        assert!(validator.validate(&swapped).is_err());
    }
}
