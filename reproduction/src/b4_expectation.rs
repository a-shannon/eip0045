//! Canonical pre-proof rejection expectations for the EIP-0045 B4 campaign.
//!
//! This document is finalizer authority, not validator input. It binds one
//! externally reviewed `(class, stage)` pair to each implementation slot of
//! every execution in the closed negative plan. It deliberately contains no QA
//! result code, validator artifact, materialized input, path, observation, or
//! result record.

use std::collections::BTreeSet;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    b4_negative_handler_contract::exact_negative_rejection_boundary,
    b4_plan::{B4_NEGATIVE_PLAN_VARIANT_COUNT, B4NegativePlanExecutionV1, Eip0045B4NegativePlanV1},
    b4_result::B4ValidatorImplementation,
    canonical::{canonical_json_bytes, validate_canonical_json_source},
};

/// Exact format discriminator for the B4 negative expectation set.
pub const B4_NEGATIVE_EXPECTATION_SET_FORMAT: &str = "Eip0045B4NegativeExpectationSetV1";
/// Exact format version for the B4 negative expectation set.
pub const B4_NEGATIVE_EXPECTATION_SET_FORMAT_VERSION: u8 = 1;
/// Exact number of plan executions represented by the expectation set.
pub const B4_NEGATIVE_EXPECTATION_EXECUTION_COUNT: usize = B4_NEGATIVE_PLAN_VARIANT_COUNT as usize;
/// Exact number of implementation-specific expectation slots.
pub const B4_NEGATIVE_EXPECTATION_SLOT_COUNT: usize = B4_NEGATIVE_EXPECTATION_EXECUTION_COUNT * 2;

const MAX_EXPECTATION_SET_BYTES: usize = 256 * 1024;
const MAX_NEGATIVE_PLAN_BYTES: u64 = 128 * 1024;
const MAX_SEMANTIC_ID_BYTES: usize = 192;

/// SHA-256 identity of the exact canonical negative-plan bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4NegativeExpectationPlanIdentityV1 {
    /// Exact canonical negative-plan byte length.
    pub byte_length: u64,
    /// Lowercase SHA-256 of the exact canonical negative-plan bytes.
    pub sha256: String,
}

impl B4NegativeExpectationPlanIdentityV1 {
    fn from_source(source: &[u8]) -> Result<Self> {
        let identity = Self {
            byte_length: u64::try_from(source.len())
                .context("negative-plan byte length does not fit u64")?,
            sha256: sha256_hex(source),
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            (1..=MAX_NEGATIVE_PLAN_BYTES).contains(&self.byte_length),
            "negative-plan byte length is outside the expectation-set bound"
        );
        validate_digest(&self.sha256, "negative-plan SHA-256")
    }
}

/// One reviewed first stable rejection boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4NegativeExpectedRejectionV1 {
    /// Stable implementation-specific rejection class.
    pub class: String,
    /// Stable first rejection stage or checkpoint.
    pub stage: String,
}

impl B4NegativeExpectedRejectionV1 {
    fn validate(&self) -> Result<()> {
        validate_semantic_id(&self.class, "expected rejection class")?;
        reject_placeholder(&self.class, "expected rejection class")?;
        validate_semantic_id(&self.stage, "expected rejection stage")?;
        reject_placeholder(&self.stage, "expected rejection stage")
    }
}

/// One implementation-labelled expectation slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4NegativeExpectationSlotV1 {
    /// Exact implementation occupying this ordered slot.
    pub implementation: B4ValidatorImplementation,
    /// Reviewed first stable rejection for this implementation and execution.
    pub rejection: B4NegativeExpectedRejectionV1,
}

impl B4NegativeExpectationSlotV1 {
    fn validate(&self) -> Result<()> {
        self.rejection.validate()
    }
}

/// One externally supplied pair before the finalizer adds its plan index.
///
/// The two slots remain explicitly implementation-labelled so that a caller
/// cannot silently swap their positional meaning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B4NegativeExpectationPairV1 {
    /// Exact execution ID claimed by the external pair.
    pub execution_id: String,
    /// Exactly two ordered slots: Rust reference, then independent JVM.
    pub slots: Vec<B4NegativeExpectationSlotV1>,
}

impl B4NegativeExpectationPairV1 {
    fn validate(&self) -> Result<()> {
        validate_execution_id(&self.execution_id)?;
        validate_slot_pair(&self.slots)
    }
}

/// One plan-indexed pair in the canonical expectation set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4NegativeExpectationExecutionV1 {
    /// Zero-based index in the exact flattened negative-plan order.
    pub execution_index: u16,
    /// Exact closed-plan execution ID at that index.
    pub execution_id: String,
    /// Exactly two ordered slots: Rust reference, then independent JVM.
    pub slots: Vec<B4NegativeExpectationSlotV1>,
}

impl B4NegativeExpectationExecutionV1 {
    fn validate(&self) -> Result<()> {
        validate_execution_id(&self.execution_id)?;
        validate_slot_pair(&self.slots)
    }

    fn as_external_pair(&self) -> B4NegativeExpectationPairV1 {
        B4NegativeExpectationPairV1 {
            execution_id: self.execution_id.clone(),
            slots: self.slots.clone(),
        }
    }
}

/// Canonical implementation-specific expectation authority for all B4
/// negative executions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Eip0045B4NegativeExpectationSetV1 {
    /// Exact V1 format discriminator.
    pub format: String,
    /// Exact V1 format version.
    pub format_version: u8,
    /// Identity of the exact canonical closed negative plan.
    pub negative_plan: B4NegativeExpectationPlanIdentityV1,
    /// Exactly 254 entries in flattened negative-plan order.
    pub executions: Vec<B4NegativeExpectationExecutionV1>,
}

impl Eip0045B4NegativeExpectationSetV1 {
    /// Construct the expectation set from externally reviewed, labelled pairs.
    ///
    /// The constructor parses the supplied plan as exact RFC 8785 JCS, rebuilds
    /// its canonical 254-entry flattening, and requires the external pairs to
    /// match every position and execution ID exactly.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed or noncanonical plan, the wrong number
    /// of pairs or slots, missing/extra/duplicate/swapped entries, an unknown
    /// implementation label, a placeholder rejection boundary, or any
    /// deviation from the compiled closed plan.
    pub fn from_external_pairs(
        negative_plan_source: &[u8],
        pairs: &[B4NegativeExpectationPairV1],
    ) -> Result<Self> {
        let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(negative_plan_source)?;
        let flattened = flatten_plan(&plan);
        ensure!(
            flattened.len() == B4_NEGATIVE_EXPECTATION_EXECUTION_COUNT,
            "closed negative-plan flattening has the wrong execution count"
        );
        ensure!(
            pairs.len() == B4_NEGATIVE_EXPECTATION_EXECUTION_COUNT,
            "expectation input must contain exactly {B4_NEGATIVE_EXPECTATION_EXECUTION_COUNT} pairs"
        );

        let mut pair_ids = BTreeSet::new();
        let mut executions = Vec::with_capacity(B4_NEGATIVE_EXPECTATION_EXECUTION_COUNT);
        for (index, (planned, pair)) in flattened.iter().zip(pairs).enumerate() {
            pair.validate()
                .with_context(|| format!("invalid external expectation pair at index {index}"))?;
            ensure!(
                pair_ids.insert(pair.execution_id.as_str()),
                "duplicate external expectation execution ID at index {index}"
            );
            ensure!(
                pair.execution_id == planned.execution_id,
                "external expectation pair differs from negative-plan execution at index {index}"
            );
            validate_exact_rejection_slots(planned, &pair.slots, index)?;
            executions.push(B4NegativeExpectationExecutionV1 {
                execution_index: u16::try_from(index)
                    .context("expectation execution index does not fit u16")?,
                execution_id: planned.execution_id.clone(),
                slots: pair.slots.clone(),
            });
        }

        let expectation_set = Self {
            format: B4_NEGATIVE_EXPECTATION_SET_FORMAT.to_owned(),
            format_version: B4_NEGATIVE_EXPECTATION_SET_FORMAT_VERSION,
            negative_plan: B4NegativeExpectationPlanIdentityV1::from_source(negative_plan_source)?,
            executions,
        };
        expectation_set.validate()?;
        Ok(expectation_set)
    }

    /// Parse exact RFC 8785 JCS and validate the closed local grammar plus the
    /// compiled execution-level rejection projection.
    ///
    /// Call [`verify_b4_negative_expectation_set`] to additionally bind the
    /// parsed document to independently supplied negative-plan bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, duplicate-key,
    /// noncanonical, unknown-field, incorrectly ordered, placeholder, or
    /// otherwise invalid input.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            source.len() <= MAX_EXPECTATION_SET_BYTES,
            "B4 negative expectation set exceeds its canonical-byte bound"
        );
        let value = validate_canonical_json_source(source)
            .context("B4 negative expectation set is not exact RFC 8785 JCS")?;
        let expectation_set: Self =
            serde_json::from_value(value).context("invalid B4 negative expectation-set shape")?;
        expectation_set.validate()?;
        ensure!(
            expectation_set.to_canonical_jcs()? == source,
            "B4 negative expectation set does not round-trip byte-exactly"
        );
        Ok(expectation_set)
    }

    /// Serialize this expectation set to exact RFC 8785 JCS bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid document or an oversized serialization.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value =
            serde_json::to_value(self).context("cannot serialize B4 negative expectation set")?;
        let bytes = canonical_json_bytes(&value)?;
        ensure!(
            bytes.len() <= MAX_EXPECTATION_SET_BYTES,
            "B4 negative expectation set exceeds its canonical-byte bound"
        );
        Ok(bytes)
    }

    /// Validate the exact local V1 grammar, compiled plan order, counts,
    /// namespaces, and sole rejection boundary for both implementation slots.
    ///
    /// The declared plan digest remains a cross-document property checked by
    /// [`verify_b4_negative_expectation_set`].
    ///
    /// # Errors
    ///
    /// Returns an error for a format, plan identity, count, index, duplicate,
    /// implementation order, identifier, or placeholder defect.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == B4_NEGATIVE_EXPECTATION_SET_FORMAT,
            "wrong B4 negative expectation-set format label"
        );
        ensure!(
            self.format_version == B4_NEGATIVE_EXPECTATION_SET_FORMAT_VERSION,
            "wrong B4 negative expectation-set format version"
        );
        self.negative_plan.validate()?;
        ensure!(
            self.executions.len() == B4_NEGATIVE_EXPECTATION_EXECUTION_COUNT,
            "B4 negative expectation set must contain exactly {B4_NEGATIVE_EXPECTATION_EXECUTION_COUNT} executions"
        );

        let plan = Eip0045B4NegativePlanV1::canonical()?;
        let flattened_plan = flatten_plan(&plan);
        ensure!(
            flattened_plan.len() == B4_NEGATIVE_EXPECTATION_EXECUTION_COUNT,
            "compiled negative-plan flattening has the wrong execution count"
        );

        let mut execution_ids = BTreeSet::new();
        let mut slot_count = 0_usize;
        for (index, (execution, planned)) in self.executions.iter().zip(flattened_plan).enumerate()
        {
            execution
                .validate()
                .with_context(|| format!("invalid expectation execution at index {index}"))?;
            ensure!(
                usize::from(execution.execution_index) == index,
                "expectation execution index or order drift at index {index}"
            );
            ensure!(
                execution_ids.insert(execution.execution_id.as_str()),
                "duplicate expectation execution ID at index {index}"
            );
            ensure!(
                execution.execution_id == planned.execution_id,
                "expectation execution ID differs from the compiled plan at index {index}"
            );
            validate_exact_rejection_slots(planned, &execution.slots, index)?;
            slot_count = slot_count
                .checked_add(execution.slots.len())
                .context("expectation slot count overflows usize")?;
        }
        ensure!(
            slot_count == B4_NEGATIVE_EXPECTATION_SLOT_COUNT,
            "B4 negative expectation set must contain exactly {B4_NEGATIVE_EXPECTATION_SLOT_COUNT} slots"
        );
        Ok(())
    }
}

/// Convenience constructor for one closed expectation set.
///
/// # Errors
///
/// Returns the same errors as
/// [`Eip0045B4NegativeExpectationSetV1::from_external_pairs`].
pub fn create_b4_negative_expectation_set(
    negative_plan_source: &[u8],
    pairs: &[B4NegativeExpectationPairV1],
) -> Result<Eip0045B4NegativeExpectationSetV1> {
    Eip0045B4NegativeExpectationSetV1::from_external_pairs(negative_plan_source, pairs)
}

/// Rebind a canonical expectation set to independently supplied plan bytes.
///
/// Verification reconstructs the document through the same external-pair
/// constructor. Consequently, changing the plan identity, plan order, an
/// execution index or ID, or an implementation slot cannot be accepted merely
/// by coordinating self-consistent rewrites inside the expectation document.
///
/// # Errors
///
/// Returns an error for any canonical-JSON, plan, identity, order, execution,
/// implementation, rejection, or reconstruction drift.
pub fn verify_b4_negative_expectation_set(
    expectation_set_source: &[u8],
    negative_plan_source: &[u8],
) -> Result<Eip0045B4NegativeExpectationSetV1> {
    let supplied = Eip0045B4NegativeExpectationSetV1::from_canonical_jcs(expectation_set_source)?;
    let external_pairs = supplied
        .executions
        .iter()
        .map(B4NegativeExpectationExecutionV1::as_external_pair)
        .collect::<Vec<_>>();
    let rebuilt = Eip0045B4NegativeExpectationSetV1::from_external_pairs(
        negative_plan_source,
        &external_pairs,
    )?;
    ensure!(
        supplied == rebuilt,
        "B4 negative expectation set differs from exact independently rebuilt plan bindings"
    );
    Ok(supplied)
}

fn flatten_plan(plan: &Eip0045B4NegativePlanV1) -> Vec<&B4NegativePlanExecutionV1> {
    plan.groups
        .iter()
        .flat_map(|group| group.executions.iter())
        .collect()
}

fn validate_exact_rejection_slots(
    planned: &B4NegativePlanExecutionV1,
    slots: &[B4NegativeExpectationSlotV1],
    index: usize,
) -> Result<()> {
    let expected = exact_negative_rejection_boundary(planned)
        .with_context(|| format!("cannot project exact rejection at index {index}"))?;
    for slot in slots {
        ensure!(
            slot.rejection.class == expected.class() && slot.rejection.stage == expected.stage(),
            "expectation rejection differs from the exact execution boundary at index {index}"
        );
    }
    Ok(())
}

fn validate_slot_pair(slots: &[B4NegativeExpectationSlotV1]) -> Result<()> {
    ensure!(
        slots.len() == 2,
        "expectation pair must contain exactly two implementation slots"
    );
    ensure!(
        slots[0].implementation == B4ValidatorImplementation::RustReference,
        "expectation slot zero must be rust-reference"
    );
    ensure!(
        slots[1].implementation == B4ValidatorImplementation::IndependentJvm,
        "expectation slot one must be independent-jvm"
    );
    slots[0]
        .validate()
        .context("invalid rust-reference expectation slot")?;
    slots[1]
        .validate()
        .context("invalid independent-jvm expectation slot")
}

fn validate_execution_id(value: &str) -> Result<()> {
    let (group, variant) = value
        .split_once("--")
        .context("expectation execution ID has no group/variant separator")?;
    ensure!(
        !variant.contains("--"),
        "expectation execution ID has more than one group/variant separator"
    );
    validate_semantic_id(group, "expectation execution group ID")?;
    validate_semantic_id(variant, "expectation execution variant ID")
}

fn validate_semantic_id(value: &str, label: &str) -> Result<()> {
    let bytes = value.as_bytes();
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_SEMANTIC_ID_BYTES,
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

fn reject_placeholder(value: &str, label: &str) -> Result<()> {
    const FORBIDDEN: [&str; 12] = [
        "error",
        "failure",
        "fixme",
        "generic",
        "pending",
        "placeholder",
        "reject",
        "tbd",
        "todo",
        "unclassified",
        "unknown",
        "unspecified",
    ];
    ensure!(
        !value
            .split('-')
            .any(|component| FORBIDDEN.contains(&component)),
        "{label} contains a placeholder component"
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn fixture() -> (
        Vec<u8>,
        Vec<B4NegativeExpectationPairV1>,
        Eip0045B4NegativeExpectationSetV1,
    ) {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let plan_source = plan.to_canonical_jcs().unwrap();
        let pairs = flatten_plan(&plan)
            .into_iter()
            .map(|execution| {
                let boundary =
                    crate::b4_negative_handler_contract::exact_negative_rejection_boundary(
                        execution,
                    )
                    .unwrap();
                let class = boundary.class().to_owned();
                let stage = boundary.stage().to_owned();
                B4NegativeExpectationPairV1 {
                    execution_id: execution.execution_id.clone(),
                    slots: vec![
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
                    ],
                }
            })
            .collect::<Vec<_>>();
        let expectation_set = create_b4_negative_expectation_set(&plan_source, &pairs).unwrap();
        (plan_source, pairs, expectation_set)
    }

    #[test]
    fn canonical_set_round_trips_rebinds_and_contains_exactly_508_slots() {
        let (plan_source, _, expectation_set) = fixture();
        assert_eq!(
            expectation_set.executions.len(),
            B4_NEGATIVE_EXPECTATION_EXECUTION_COUNT
        );
        assert_eq!(
            expectation_set
                .executions
                .iter()
                .map(|execution| execution.slots.len())
                .sum::<usize>(),
            B4_NEGATIVE_EXPECTATION_SLOT_COUNT
        );
        for (index, execution) in expectation_set.executions.iter().enumerate() {
            assert_eq!(usize::from(execution.execution_index), index);
            assert_eq!(
                execution.slots[0].implementation,
                B4ValidatorImplementation::RustReference
            );
            assert_eq!(
                execution.slots[1].implementation,
                B4ValidatorImplementation::IndependentJvm
            );
        }

        let source = expectation_set.to_canonical_jcs().unwrap();
        assert_eq!(
            Eip0045B4NegativeExpectationSetV1::from_canonical_jcs(&source).unwrap(),
            expectation_set
        );
        assert_eq!(
            verify_b4_negative_expectation_set(&source, &plan_source).unwrap(),
            expectation_set
        );
    }

    #[test]
    fn constructor_rejects_missing_extra_swapped_duplicate_and_relabelled_pairs() {
        let (plan_source, pairs, _) = fixture();

        let mut missing = pairs.clone();
        missing.pop();
        assert!(create_b4_negative_expectation_set(&plan_source, &missing).is_err());

        let mut extra = pairs.clone();
        extra.push(pairs[0].clone());
        assert!(create_b4_negative_expectation_set(&plan_source, &extra).is_err());

        let mut swapped_pairs = pairs.clone();
        swapped_pairs.swap(0, 1);
        assert!(create_b4_negative_expectation_set(&plan_source, &swapped_pairs).is_err());

        let mut duplicate_id = pairs.clone();
        duplicate_id[1].execution_id = duplicate_id[0].execution_id.clone();
        assert!(create_b4_negative_expectation_set(&plan_source, &duplicate_id).is_err());

        let mut swapped_slots = pairs.clone();
        swapped_slots[0].slots.swap(0, 1);
        assert!(create_b4_negative_expectation_set(&plan_source, &swapped_slots).is_err());

        let mut duplicate_slot = pairs.clone();
        duplicate_slot[0].slots[1] = duplicate_slot[0].slots[0].clone();
        assert!(create_b4_negative_expectation_set(&plan_source, &duplicate_slot).is_err());

        let mut relabelled = pairs.clone();
        relabelled[0].execution_id = "different-group--different-variant".to_owned();
        assert!(create_b4_negative_expectation_set(&plan_source, &relabelled).is_err());
    }

    #[test]
    fn parser_rejects_noncanonical_duplicate_unknown_and_placeholder_material() {
        let (_, _, expectation_set) = fixture();
        let source = expectation_set.to_canonical_jcs().unwrap();

        let pretty = serde_json::to_vec_pretty(&expectation_set).unwrap();
        assert!(Eip0045B4NegativeExpectationSetV1::from_canonical_jcs(&pretty).is_err());

        let duplicate = String::from_utf8(source.clone()).unwrap().replacen(
            '{',
            &format!("{{\"format\":\"{B4_NEGATIVE_EXPECTATION_SET_FORMAT}\","),
            1,
        );
        assert!(
            Eip0045B4NegativeExpectationSetV1::from_canonical_jcs(duplicate.as_bytes()).is_err()
        );

        let mut value = serde_json::to_value(&expectation_set).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknownField".to_owned(), Value::Bool(true));
        assert!(
            Eip0045B4NegativeExpectationSetV1::from_canonical_jcs(
                &canonical_json_bytes(&value).unwrap()
            )
            .is_err()
        );

        value.as_object_mut().unwrap().remove("unknownField");
        value["executions"][0]["slots"][0]["rejection"]["class"] =
            Value::String("unknown-error".to_owned());
        assert!(
            Eip0045B4NegativeExpectationSetV1::from_canonical_jcs(
                &canonical_json_bytes(&value).unwrap()
            )
            .is_err()
        );

        for placeholder in ["fixme", "pending"] {
            value["executions"][0]["slots"][0]["rejection"]["class"] =
                Value::String(placeholder.to_owned());
            assert!(
                Eip0045B4NegativeExpectationSetV1::from_canonical_jcs(
                    &canonical_json_bytes(&value).unwrap()
                )
                .is_err(),
                "expectation parser accepted placeholder rejection class: {placeholder}"
            );
        }

        value["executions"][0]["slots"][0]["rejection"]["class"] =
            Value::String("valid-boundary".to_owned());
        value["executions"][0]["slots"][0]["rejection"]["stage"] =
            Value::String("Noncanonical-Stage".to_owned());
        assert!(
            Eip0045B4NegativeExpectationSetV1::from_canonical_jcs(
                &canonical_json_bytes(&value).unwrap()
            )
            .is_err()
        );

        value["executions"][0]["slots"][0]["rejection"]["stage"] =
            Value::String("valid-stage".to_owned());
        value["executions"][0]["slots"][0]["unexpected"] = Value::Bool(true);
        assert!(
            Eip0045B4NegativeExpectationSetV1::from_canonical_jcs(
                &canonical_json_bytes(&value).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn verification_rejects_identity_index_id_and_coordinated_plan_rewrites() {
        let (plan_source, _, expectation_set) = fixture();

        let mut identity_drift = serde_json::to_value(&expectation_set).unwrap();
        identity_drift["negativePlan"]["sha256"] = Value::String("f".repeat(64));
        let identity_drift = canonical_json_bytes(&identity_drift).unwrap();
        Eip0045B4NegativeExpectationSetV1::from_canonical_jcs(&identity_drift).unwrap();
        assert!(verify_b4_negative_expectation_set(&identity_drift, &plan_source).is_err());

        let mut id_drift = serde_json::to_value(&expectation_set).unwrap();
        id_drift["executions"][0]["executionId"] =
            Value::String("coordinated-rewrite--slot-zero".to_owned());
        let id_drift = canonical_json_bytes(&id_drift).unwrap();
        assert!(Eip0045B4NegativeExpectationSetV1::from_canonical_jcs(&id_drift).is_err());

        let mut index_drift = serde_json::to_value(&expectation_set).unwrap();
        index_drift["executions"][0]["executionIndex"] = json!(1);
        let index_drift = canonical_json_bytes(&index_drift).unwrap();
        assert!(Eip0045B4NegativeExpectationSetV1::from_canonical_jcs(&index_drift).is_err());

        let mut rewritten_plan = validate_canonical_json_source(&plan_source).unwrap();
        rewritten_plan["groups"][0]["caseId"] = json!("coordinated-rewrite");
        rewritten_plan["groups"][0]["executions"][0]["executionId"] =
            json!("coordinated-rewrite--profile-id");
        let rewritten_plan_source = canonical_json_bytes(&rewritten_plan).unwrap();

        let mut coordinated = serde_json::to_value(&expectation_set).unwrap();
        coordinated["negativePlan"]["byteLength"] = json!(rewritten_plan_source.len());
        coordinated["negativePlan"]["sha256"] = Value::String(sha256_hex(&rewritten_plan_source));
        coordinated["executions"][0]["executionId"] = json!("coordinated-rewrite--profile-id");
        let coordinated = canonical_json_bytes(&coordinated).unwrap();
        assert!(Eip0045B4NegativeExpectationSetV1::from_canonical_jcs(&coordinated).is_err());
    }

    #[test]
    fn external_expectation_rejects_a_known_boundary_from_another_handler() {
        let (plan_source, mut pairs, _) = fixture();
        pairs[0].slots[0].rejection = B4NegativeExpectedRejectionV1 {
            class: "profile-manifest-invalid".to_owned(),
            stage: "profile-manifest-byte-length".to_owned(),
        };
        assert!(create_b4_negative_expectation_set(&plan_source, &pairs).is_err());
    }

    #[test]
    fn rejects_all_106_legacy_handler_wide_boundary_choices() {
        let (plan_source, pairs, expectation_set) = fixture();
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let planned = flatten_plan(&plan);
        let mut mismatch_count = 0;
        let mut first_mismatch = None;

        for (index, execution) in planned.iter().copied().enumerate() {
            let exact =
                crate::b4_negative_handler_contract::exact_negative_rejection_boundary(execution)
                    .unwrap();
            let handler = crate::b4_negative_handler_contract::planned_negative_handler_contract(
                execution.materialization_domain,
                execution.execution_surface,
            )
            .unwrap()
            .unwrap();
            let legacy = if execution.execution_surface
                == crate::b4_plan::B4NegativeExecutionSurface::Risc0ParserInternal
            {
                exact
            } else {
                handler.rejection_boundaries()[0]
            };
            if legacy == exact {
                continue;
            }
            mismatch_count += 1;
            first_mismatch.get_or_insert((index, legacy));

            let mut drift = pairs.clone();
            drift[index].slots[0].rejection = B4NegativeExpectedRejectionV1 {
                class: legacy.class().to_owned(),
                stage: legacy.stage().to_owned(),
            };
            assert!(
                create_b4_negative_expectation_set(&plan_source, &drift).is_err(),
                "legacy handler-wide choice survived for {}",
                execution.execution_id
            );
        }
        assert_eq!(mismatch_count, 106);

        let (index, legacy) = first_mismatch.unwrap();
        for slot_index in 0..2 {
            let mut value = serde_json::to_value(&expectation_set).unwrap();
            value["executions"][index]["slots"][slot_index]["rejection"]["class"] =
                json!(legacy.class());
            value["executions"][index]["slots"][slot_index]["rejection"]["stage"] =
                json!(legacy.stage());
            assert!(
                Eip0045B4NegativeExpectationSetV1::from_canonical_jcs(
                    &canonical_json_bytes(&value).unwrap()
                )
                .is_err(),
                "canonical parser admitted slot {slot_index} handler-wide drift"
            );
        }
    }

    #[test]
    fn serialized_authority_surface_contains_only_plan_ids_slots_and_rejections() {
        let (_, _, expectation_set) = fixture();
        let value = serde_json::to_value(expectation_set).unwrap();
        assert_eq!(
            value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            ["executions", "format", "formatVersion", "negativePlan"]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
        assert_eq!(
            value["negativePlan"]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            ["byteLength", "sha256"].into_iter().collect()
        );
        assert_eq!(
            value["executions"][0]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            ["executionId", "executionIndex", "slots"]
                .into_iter()
                .collect()
        );
        assert_eq!(
            value["executions"][0]["slots"][0]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            ["implementation", "rejection"].into_iter().collect()
        );
        assert_eq!(
            value["executions"][0]["slots"][0]["rejection"]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            ["class", "stage"].into_iter().collect()
        );

        let source = String::from_utf8(canonical_json_bytes(&value).unwrap()).unwrap();
        for forbidden in [
            "qaResultCode",
            "validatorArtifact",
            "materializedInput",
            "\"path\"",
            "observation",
            "validationResult",
        ] {
            assert!(!source.contains(forbidden), "{forbidden}");
        }
    }

    #[cfg(feature = "positive-gate")]
    #[test]
    fn draft_2020_12_schema_accepts_the_canonical_shape_and_rejects_drift() {
        let (_, _, expectation_set) = fixture();
        let instance = serde_json::to_value(&expectation_set).unwrap();
        let schema = crate::canonical::parse_json_strict(
            include_str!("../finalizer-schema/b4-negative-expectation-set-v1.schema.json")
                .as_bytes(),
        )
        .unwrap();
        let validator = jsonschema::draft202012::options().build(&schema).unwrap();
        validator.validate(&instance).unwrap();

        let mut missing = instance.clone();
        missing["executions"].as_array_mut().unwrap().pop();
        assert!(validator.validate(&missing).is_err());

        let mut extra_slot = instance.clone();
        let slot = extra_slot["executions"][0]["slots"][0].clone();
        extra_slot["executions"][0]["slots"]
            .as_array_mut()
            .unwrap()
            .push(slot);
        assert!(validator.validate(&extra_slot).is_err());

        let mut swapped = instance.clone();
        swapped["executions"][0]["slots"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
        assert!(validator.validate(&swapped).is_err());

        let mut extra_separator = instance.clone();
        extra_separator["executions"][0]["executionId"] = json!("group--variant--extra");
        assert!(validator.validate(&extra_separator).is_err());

        let mut oversized_component = instance.clone();
        oversized_component["executions"][0]["executionId"] = json!(format!(
            "{}--variant",
            "a".repeat(MAX_SEMANTIC_ID_BYTES + 1)
        ));
        assert!(validator.validate(&oversized_component).is_err());

        let mut forbidden = instance;
        forbidden["executions"][0]["qaResultCode"] = json!("raw-seal-claim-mismatch");
        assert!(validator.validate(&forbidden).is_err());
    }
}
