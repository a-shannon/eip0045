//! Canonical, implementation-specific validation results for EIP-0045 B4.
//!
//! A result binds one exact materialization-identity source to the exact
//! canonical negative-plan row, validator domain, validation surface, QA code,
//! implementation artifact, and first stable rejection observed by that
//! implementation. It contains no materialized input, path, error message,
//! clock reading, or host identity. Verification requires an independently
//! supplied observation and rebuilds every other field from external authority.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::b4::B4NegativeCase;
use crate::b4_mutation::{
    B4MaterializationReplayAdapterV1, Eip0045B4MaterializationIdentityV1,
    verify_materialization_identity_with_adapter,
};
use crate::b4_negative_handler_contract::validate_negative_rejection_boundary;
use crate::b4_plan::{
    B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanExecutionV1,
    B4NegativeQaResultCode, Eip0045B4NegativePlanV1,
};
use crate::canonical::{canonical_json_bytes, validate_canonical_json_source};

/// Exact format discriminator for one implementation's negative result.
pub const B4_VALIDATION_RESULT_FORMAT: &str = "Eip0045B4ValidationResultV1";
/// Exact format version for one implementation's negative result.
pub const B4_VALIDATION_RESULT_FORMAT_VERSION: u8 = 1;

const MAX_RESULT_BYTES: usize = 64 * 1024;
const MAX_VALIDATOR_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_MATERIALIZATION_IDENTITY_BYTES: usize = 64 * 1024;
const MAX_NEGATIVE_PLAN_BYTES: usize = 128 * 1024;
const MAX_SEMANTIC_ID_BYTES: usize = 192;

/// Closed implementation identity for a differential B4 result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4ValidatorImplementation {
    /// The reference Rust validator for the selected materialization domain.
    RustReference,
    /// The independent pure-JVM validation path.
    IndependentJvm,
}

/// Closed verdict for a negative B4 execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4ValidationVerdict {
    /// The named validator rejected at the recorded stable boundary.
    Reject,
}

/// Exact identity of the executable or JAR which emitted a result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4ValidatorArtifactIdentityV1 {
    /// Exact artifact byte length.
    pub byte_length: u64,
    /// Lowercase SHA-256 of the exact artifact bytes.
    pub sha256: String,
}

impl B4ValidatorArtifactIdentityV1 {
    /// Construct an identity from exact validator artifact bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the artifact is empty or exceeds the V1 bound.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let identity = Self {
            byte_length: u64::try_from(bytes.len())
                .context("validator artifact length does not fit u64")?,
            sha256: sha256_hex(bytes),
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            (1..=MAX_VALIDATOR_ARTIFACT_BYTES).contains(&self.byte_length),
            "validator artifact length is outside the V1 bound"
        );
        validate_digest(&self.sha256, "validator artifact SHA-256")
    }
}

/// First stable rejection boundary observed by one implementation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4ObservedRejectionV1 {
    /// Stable normalized implementation-specific rejection class identifier.
    pub class: String,
    /// Stable normalized first rejection stage/checkpoint identifier.
    pub stage: String,
    /// Negative verdict; V1 admits only rejection.
    pub verdict: B4ValidationVerdict,
}

impl B4ObservedRejectionV1 {
    fn validate(&self) -> Result<()> {
        validate_semantic_id(&self.class, "observed rejection class")?;
        reject_placeholder(&self.class, "observed rejection class")?;
        validate_semantic_id(&self.stage, "observed rejection stage")?;
        reject_placeholder(&self.stage, "observed rejection stage")
    }
}

/// Exact external material required to authenticate one identity before a
/// result is created or verified.
pub struct B4ValidationReplayContextV1<'a> {
    /// Exact canonical materialization-identity source bytes.
    pub materialization_identity_source: &'a [u8],
    /// Exact independently selected and validated registry row.
    pub registry_row: &'a B4NegativeCase,
    /// Exact domain-labelled base and output bytes used for replay.
    pub adapter: &'a dyn B4MaterializationReplayAdapterV1,
}

/// Independent expectations used when replaying one validation result.
///
/// `rejection` must come from the replaying validator runner or another
/// independent observation channel. It must never be copied from the result
/// being checked.
#[derive(Clone, Copy, Debug)]
pub struct B4ValidationResultExpectationV1<'a> {
    /// Exact plan execution expected in this result slot.
    pub execution_id: &'a str,
    /// Exact validator implementation expected in this result slot.
    pub implementation: B4ValidatorImplementation,
    /// Exact independently selected validator artifact identity.
    pub validator_artifact: &'a B4ValidatorArtifactIdentityV1,
    /// Exact independently observed first stable rejection.
    pub rejection: &'a B4ObservedRejectionV1,
}

/// Canonical result for one plan execution and one validator implementation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Eip0045B4ValidationResultV1 {
    /// Exact V1 format discriminator.
    pub format: String,
    /// Exact V1 format version.
    pub format_version: u8,
    /// Exact closed-plan execution ID.
    pub execution_id: String,
    /// Implementation which emitted the result.
    pub implementation: B4ValidatorImplementation,
    /// Exact canonical materialization-identity byte length.
    pub materialization_identity_byte_length: u64,
    /// SHA-256 of the exact canonical materialization-identity bytes.
    pub materialization_identity_sha256: String,
    /// Closed materialization and validator domain fixed by the plan.
    pub materialization_domain: B4MaterializationDomain,
    /// Exact canonical negative-plan byte length.
    pub negative_plan_byte_length: u64,
    /// SHA-256 of the exact canonical negative-plan bytes.
    pub negative_plan_sha256: String,
    /// Planned normalized semantic result, not an implementation error string.
    pub qa_result_code: B4NegativeQaResultCode,
    /// First stable rejection boundary actually observed by this implementation.
    pub rejection: B4ObservedRejectionV1,
    /// Exact artifact identity of the implementation which emitted the result.
    pub validator_artifact: B4ValidatorArtifactIdentityV1,
    /// Exact validation entry point fixed by the plan.
    pub validation_surface: B4NegativeExecutionSurface,
}

impl Eip0045B4ValidationResultV1 {
    /// Parse exact RFC 8785 JCS and enforce the closed result grammar.
    ///
    /// This checks internal structure only. Use [`verify_b4_validation_result`]
    /// to rebind the result to the exact plan, registry recipe, replay bytes,
    /// validator artifact, and independent observation.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, noncanonical, duplicate-key,
    /// unknown-field, malformed, or internally inconsistent input.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            source.len() <= MAX_RESULT_BYTES,
            "B4 validation result exceeds its canonical-byte bound"
        );
        let value = validate_canonical_json_source(source)
            .context("B4 validation result is not exact RFC 8785 JCS")?;
        let result: Self =
            serde_json::from_value(value).context("invalid B4 validation-result shape")?;
        result.validate()?;
        ensure!(
            result.to_canonical_jcs()? == source,
            "B4 validation result does not round-trip byte-exactly"
        );
        Ok(result)
    }

    /// Serialize this result to exact RFC 8785 JCS bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid result or an oversized serialization.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value = serde_json::to_value(self).context("cannot serialize B4 validation result")?;
        let bytes = canonical_json_bytes(&value)?;
        ensure!(
            bytes.len() <= MAX_RESULT_BYTES,
            "B4 validation result exceeds its canonical-byte bound"
        );
        Ok(bytes)
    }

    /// Validate the result's internal V1 lexical and arithmetic invariants.
    ///
    /// # Errors
    ///
    /// Returns an error for a format, identifier, digest, bound, observation,
    /// or validator-artifact defect.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == B4_VALIDATION_RESULT_FORMAT,
            "wrong B4 validation-result format label"
        );
        ensure!(
            self.format_version == B4_VALIDATION_RESULT_FORMAT_VERSION,
            "wrong B4 validation-result format version"
        );
        validate_execution_id(&self.execution_id)?;
        ensure!(
            (1..=MAX_MATERIALIZATION_IDENTITY_BYTES as u64)
                .contains(&self.materialization_identity_byte_length),
            "materialization-identity length is outside the result bound"
        );
        ensure!(
            (1..=MAX_NEGATIVE_PLAN_BYTES as u64).contains(&self.negative_plan_byte_length),
            "negative-plan length is outside the result bound"
        );
        validate_digest(
            &self.materialization_identity_sha256,
            "materialization-identity SHA-256",
        )?;
        validate_digest(&self.negative_plan_sha256, "negative-plan SHA-256")?;
        self.rejection.validate()?;
        validate_negative_rejection_boundary(
            self.materialization_domain,
            self.validation_surface,
            &self.rejection.class,
            &self.rejection.stage,
        )?;
        self.validator_artifact.validate()
    }
}

/// Construct one result only after replaying its exact plan, registry row, and
/// materialization identity.
///
/// This function does not run a validator. The caller supplies the observed
/// rejection; independent replay through [`verify_b4_validation_result`] is
/// required before that observation is evidence.
///
/// # Errors
///
/// Returns an error for malformed input, plan/registry/identity/domain drift,
/// reconstruction failure, or invalid observation/artifact identity.
pub fn create_b4_validation_result(
    negative_plan_source: &[u8],
    replay: &B4ValidationReplayContextV1<'_>,
    implementation: B4ValidatorImplementation,
    validator_artifact: B4ValidatorArtifactIdentityV1,
    rejection: B4ObservedRejectionV1,
) -> Result<Eip0045B4ValidationResultV1> {
    let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(negative_plan_source)?;
    let identity = Eip0045B4MaterializationIdentityV1::from_canonical_jcs(
        replay.materialization_identity_source,
    )?;
    let execution = find_execution(&plan, &replay.registry_row.execution_id)?;
    ensure!(
        identity.execution_id == execution.execution_id,
        "materialization identity names a different plan execution"
    );
    verify_materialization_identity_with_adapter(
        &identity,
        negative_plan_source,
        replay.registry_row,
        replay.adapter,
    )
    .context("materialization identity does not replay against exact campaign material")?;
    validator_artifact.validate()?;
    rejection.validate()?;

    let result = Eip0045B4ValidationResultV1 {
        format: B4_VALIDATION_RESULT_FORMAT.to_owned(),
        format_version: B4_VALIDATION_RESULT_FORMAT_VERSION,
        execution_id: execution.execution_id.clone(),
        implementation,
        materialization_identity_byte_length: u64::try_from(
            replay.materialization_identity_source.len(),
        )
        .context("materialization identity length does not fit u64")?,
        materialization_identity_sha256: sha256_hex(replay.materialization_identity_source),
        materialization_domain: execution.materialization_domain,
        negative_plan_byte_length: u64::try_from(negative_plan_source.len())
            .context("negative plan length does not fit u64")?,
        negative_plan_sha256: sha256_hex(negative_plan_source),
        qa_result_code: execution.qa_result_code,
        rejection,
        validator_artifact,
        validation_surface: execution.execution_surface,
    };
    result.validate()?;
    Ok(result)
}

/// Rebind a canonical result to exact replay material and independent
/// expectations.
///
/// # Errors
///
/// Returns an error for any parse, plan, registry, identity, domain, surface,
/// QA-code, implementation, observation, or validator-artifact drift.
pub fn verify_b4_validation_result(
    result_source: &[u8],
    negative_plan_source: &[u8],
    replay: &B4ValidationReplayContextV1<'_>,
    expectation: &B4ValidationResultExpectationV1<'_>,
) -> Result<Eip0045B4ValidationResultV1> {
    let supplied = Eip0045B4ValidationResultV1::from_canonical_jcs(result_source)?;
    validate_execution_id(expectation.execution_id)?;
    expectation.validator_artifact.validate()?;
    expectation.rejection.validate()?;
    ensure!(
        supplied.execution_id == expectation.execution_id,
        "B4 result names a different plan execution"
    );
    ensure!(
        supplied.implementation == expectation.implementation,
        "B4 result names a different validator implementation"
    );
    ensure!(
        &supplied.validator_artifact == expectation.validator_artifact,
        "B4 result binds a different validator artifact"
    );
    ensure!(
        &supplied.rejection == expectation.rejection,
        "B4 result differs from the independently observed rejection"
    );
    let rebuilt = create_b4_validation_result(
        negative_plan_source,
        replay,
        expectation.implementation,
        expectation.validator_artifact.clone(),
        expectation.rejection.clone(),
    )?;
    ensure!(
        supplied == rebuilt,
        "B4 validation result differs from exact independently rebuilt bindings"
    );
    Ok(supplied)
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
        .with_context(|| format!("negative plan has no execution {execution_id}"))?;
    ensure!(
        matches.next().is_none(),
        "negative plan contains duplicate execution IDs"
    );
    Ok(execution)
}

fn validate_execution_id(value: &str) -> Result<()> {
    let (group, variant) = value
        .split_once("--")
        .context("result execution ID has no group/variant separator")?;
    ensure!(
        !variant.contains("--"),
        "result execution ID has more than one group/variant separator"
    );
    validate_semantic_id(group, "result execution group ID")?;
    validate_semantic_id(variant, "result execution variant ID")
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
    use crate::b4::{B4ByteOperation, B4ByteTarget, B4NegativeMaterialization, B4NegativeMutation};
    use crate::b4_mutation::{
        B4ByteEditReplayAdapterV1, create_materialization_identity_with_adapter,
        reconstruct_mutation,
    };

    const EXECUTION_ID: &str = "statement-field-byte-sweep--profile-id";

    #[derive(Debug)]
    struct Fixture {
        base: Vec<u8>,
        identity: Vec<u8>,
        output: Vec<u8>,
        plan: Vec<u8>,
        rejection: B4ObservedRejectionV1,
        registry_row: B4NegativeCase,
        validator: B4ValidatorArtifactIdentityV1,
    }

    impl Fixture {
        fn replay(&self) -> B4ValidationReplayContextV1<'_> {
            B4ValidationReplayContextV1 {
                materialization_identity_source: &self.identity,
                registry_row: &self.registry_row,
                adapter: self,
            }
        }

        fn expectation(
            &self,
            implementation: B4ValidatorImplementation,
        ) -> B4ValidationResultExpectationV1<'_> {
            B4ValidationResultExpectationV1 {
                execution_id: EXECUTION_ID,
                implementation,
                validator_artifact: &self.validator,
                rejection: &self.rejection,
            }
        }

        fn result(&self, implementation: B4ValidatorImplementation) -> Eip0045B4ValidationResultV1 {
            create_b4_validation_result(
                &self.plan,
                &self.replay(),
                implementation,
                self.validator.clone(),
                self.rejection.clone(),
            )
            .unwrap()
        }
    }

    impl B4MaterializationReplayAdapterV1 for Fixture {
        fn materialization_domain(&self) -> B4MaterializationDomain {
            B4MaterializationDomain::VerifierInput
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
            let adapter = B4ByteEditReplayAdapterV1 {
                materialization_domain: B4MaterializationDomain::VerifierInput,
                base: &self.base,
                output: &self.output,
            };
            adapter.replay_recipe(base_selector_id, materialization)
        }
    }

    fn fixture() -> Fixture {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let execution = find_execution(&plan, EXECUTION_ID).unwrap().clone();
        let plan_source = plan.to_canonical_jcs().unwrap();
        let base = b"abcdef".to_vec();
        let mutation = B4NegativeMutation::ByteEdit {
            edit: B4ByteOperation::Replace {
                before_hex: "63".to_owned(),
                offset: 2,
                replacement_hex: "ff".to_owned(),
            },
            target: B4ByteTarget::Statement,
        };
        let output = reconstruct_mutation(&base, &mutation).unwrap();
        let registry_row = B4NegativeCase {
            execution_id: execution.execution_id,
            base_selector_id: execution.base_selector_id,
            materialization_domain: execution.materialization_domain,
            materialization: B4NegativeMaterialization::Mutation { mutation },
        };
        let adapter = B4ByteEditReplayAdapterV1 {
            materialization_domain: B4MaterializationDomain::VerifierInput,
            base: &base,
            output: &output,
        };
        let identity =
            create_materialization_identity_with_adapter(&plan_source, &registry_row, &adapter)
                .unwrap()
                .to_canonical_jcs()
                .unwrap();
        let validator = B4ValidatorArtifactIdentityV1::from_bytes(b"pinned-validator").unwrap();
        let rejection = B4ObservedRejectionV1 {
            class: "receipt-claim-mismatch".to_owned(),
            stage: "expected-claim-binding".to_owned(),
            verdict: B4ValidationVerdict::Reject,
        };
        Fixture {
            base,
            identity,
            output,
            plan: plan_source,
            rejection,
            registry_row,
            validator,
        }
    }

    #[test]
    fn canonical_result_round_trips_and_rebinds_every_identity() {
        let fixture = fixture();
        let result = fixture.result(B4ValidatorImplementation::RustReference);
        let source = result.to_canonical_jcs().unwrap();
        let verified = verify_b4_validation_result(
            &source,
            &fixture.plan,
            &fixture.replay(),
            &fixture.expectation(B4ValidatorImplementation::RustReference),
        )
        .unwrap();
        assert_eq!(verified, result);
        assert_eq!(
            verified.qa_result_code,
            B4NegativeQaResultCode::RawSealClaimMismatch
        );
        assert_eq!(
            verified.validation_surface,
            B4NegativeExecutionSurface::RawStatementClaimBinding
        );
        assert_eq!(
            verified.materialization_domain,
            B4MaterializationDomain::VerifierInput
        );
        assert_eq!(
            serde_json::to_value(B4ValidatorImplementation::RustReference).unwrap(),
            serde_json::Value::String("rust-reference".to_owned())
        );
    }

    #[test]
    fn result_parser_rejects_noncanonical_duplicate_unknown_and_placeholder_material() {
        let fixture = fixture();
        let result = fixture.result(B4ValidatorImplementation::RustReference);
        let pretty = serde_json::to_vec_pretty(&result).unwrap();
        assert!(Eip0045B4ValidationResultV1::from_canonical_jcs(&pretty).is_err());

        let source = result.to_canonical_jcs().unwrap();
        let duplicate = String::from_utf8(source.clone()).unwrap().replacen(
            '{',
            &format!("{{\"format\":\"{B4_VALIDATION_RESULT_FORMAT}\","),
            1,
        );
        assert!(Eip0045B4ValidationResultV1::from_canonical_jcs(duplicate.as_bytes()).is_err());

        let mut value = serde_json::to_value(result).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), serde_json::Value::Bool(true));
        let unknown = canonical_json_bytes(&value).unwrap();
        assert!(Eip0045B4ValidationResultV1::from_canonical_jcs(&unknown).is_err());

        value.as_object_mut().unwrap().remove("unknown");
        value["rejection"]["class"] = serde_json::Value::String("unknown-error".to_owned());
        let placeholder = canonical_json_bytes(&value).unwrap();
        assert!(Eip0045B4ValidationResultV1::from_canonical_jcs(&placeholder).is_err());

        for placeholder in ["fixme", "pending"] {
            value["rejection"]["class"] = serde_json::Value::String(placeholder.to_owned());
            let placeholder = canonical_json_bytes(&value).unwrap();
            assert!(
                Eip0045B4ValidationResultV1::from_canonical_jcs(&placeholder).is_err(),
                "result parser accepted placeholder rejection class"
            );
        }

        value["rejection"]["class"] =
            serde_json::Value::String("receipt-claim-mismatch".to_owned());
        value["rejection"]["stage"] =
            serde_json::Value::String("expected-claim-binding".to_owned());
        value["materializationIdentityByteLength"] = serde_json::Value::from(u64::MAX);
        let oversized = canonical_json_bytes(&value).unwrap();
        assert!(Eip0045B4ValidationResultV1::from_canonical_jcs(&oversized).is_err());
    }

    #[test]
    fn result_rejects_a_known_boundary_from_another_handler() {
        let fixture = fixture();
        let mut result = fixture.result(B4ValidatorImplementation::RustReference);
        result.rejection.class = "profile-manifest-invalid".to_owned();
        result.rejection.stage = "profile-manifest-byte-length".to_owned();
        assert!(result.validate().is_err());

        result.rejection.class = "receipt-claim-mismatch".to_owned();
        result.rejection.stage = "profile-manifest-byte-length".to_owned();
        assert!(result.validate().is_err());
    }

    #[test]
    fn verification_rejects_plan_implementation_validator_and_slot_drift() {
        let fixture = fixture();
        let result = fixture.result(B4ValidatorImplementation::RustReference);
        let source = result.to_canonical_jcs().unwrap();

        assert!(
            verify_b4_validation_result(
                &source,
                &fixture.plan,
                &fixture.replay(),
                &fixture.expectation(B4ValidatorImplementation::IndependentJvm),
            )
            .is_err()
        );
        let other_validator =
            B4ValidatorArtifactIdentityV1::from_bytes(b"other-validator").unwrap();
        let other_validator_expectation = B4ValidationResultExpectationV1 {
            execution_id: EXECUTION_ID,
            implementation: B4ValidatorImplementation::RustReference,
            validator_artifact: &other_validator,
            rejection: &fixture.rejection,
        };
        assert!(
            verify_b4_validation_result(
                &source,
                &fixture.plan,
                &fixture.replay(),
                &other_validator_expectation,
            )
            .is_err()
        );

        let mut changed_identity = fixture.identity.clone();
        let last = changed_identity.len() - 1;
        changed_identity[last] ^= 1;
        let changed_replay = B4ValidationReplayContextV1 {
            materialization_identity_source: &changed_identity,
            ..fixture.replay()
        };
        assert!(
            verify_b4_validation_result(
                &source,
                &fixture.plan,
                &changed_replay,
                &fixture.expectation(B4ValidatorImplementation::RustReference),
            )
            .is_err()
        );

        let mut changed_plan = fixture.plan.clone();
        let last = changed_plan.len() - 1;
        changed_plan[last] ^= 1;
        assert!(
            verify_b4_validation_result(
                &source,
                &changed_plan,
                &fixture.replay(),
                &fixture.expectation(B4ValidatorImplementation::RustReference),
            )
            .is_err()
        );

        let wrong_slot = B4ValidationResultExpectationV1 {
            execution_id: "statement-field-byte-sweep--program-id",
            ..fixture.expectation(B4ValidatorImplementation::RustReference)
        };
        assert!(
            verify_b4_validation_result(&source, &fixture.plan, &fixture.replay(), &wrong_slot)
                .is_err()
        );
    }

    #[test]
    fn result_content_cannot_replace_the_handler_owned_rejection() {
        let fixture = fixture();
        let result = fixture.result(B4ValidatorImplementation::RustReference);
        let mut value = serde_json::to_value(&result).unwrap();
        value["rejection"]["class"] =
            serde_json::Value::String("alternate-digest-mismatch".to_owned());
        let forged = canonical_json_bytes(&value).unwrap();
        assert!(Eip0045B4ValidationResultV1::from_canonical_jcs(&forged).is_err());
    }

    #[test]
    fn coordinated_result_field_drift_is_rebuilt_from_plan_and_identity() {
        let fixture = fixture();
        let result = fixture.result(B4ValidatorImplementation::RustReference);
        let mut value = serde_json::to_value(result).unwrap();
        value["materializationDomain"] = serde_json::Value::String("artifact-validator".to_owned());
        value["validationSurface"] = serde_json::Value::String("profile-manifest-codec".to_owned());
        value["qaResultCode"] =
            serde_json::Value::String("b4-profile-manifest-length-invalid".to_owned());
        let drifted = canonical_json_bytes(&value).unwrap();
        assert!(
            verify_b4_validation_result(
                &drifted,
                &fixture.plan,
                &fixture.replay(),
                &fixture.expectation(B4ValidatorImplementation::RustReference),
            )
            .is_err()
        );
    }
}
