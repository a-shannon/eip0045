//! Opaque completion token for one physically executed B4 negative run.
//!
//! The token is deliberately non-serializable and has no public constructor.
//! Canonical observations and attributed results are data; neither is evidence
//! that the required validator process actually ran. A production token may
//! therefore be sealed only by the physical executor in this module after all
//! root, artifact, runtime, output, lifecycle, and remeasurement checks pass.

use anyhow::{Context, Result, ensure};
use sha2::{Digest as _, Sha256};

use crate::{
    b4_negative_io::Eip0045B4NegativeObservationV1,
    b4_result::{
        B4ValidatorArtifactIdentityV1, B4ValidatorImplementation, Eip0045B4ValidationResultV1,
    },
};

const DIGEST_BYTES: usize = 32;
const MAX_EXECUTION_ID_BYTES: usize = 386;
const MAX_OBSERVATION_BYTES: usize = 4 * 1024;
const MAX_RESULT_BYTES: usize = 64 * 1024;

/// Exact pathless identity of one runtime-policy or runtime artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
struct B4NegativeRunByteIdentityV1 {
    byte_length: u64,
    sha256: [u8; DIGEST_BYTES],
}

impl B4NegativeRunByteIdentityV1 {
    fn from_bytes(bytes: &[u8], maximum: usize, label: &str) -> Result<Self> {
        ensure!(!bytes.is_empty(), "{label} is empty");
        ensure!(bytes.len() <= maximum, "{label} exceeds its byte bound");
        Ok(Self {
            byte_length: u64::try_from(bytes.len())
                .with_context(|| format!("{label} length does not fit u64"))?,
            sha256: Sha256::digest(bytes).into(),
        })
    }
}

/// Exact Java runtime identities required only by the JVM implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
struct B4NegativeJvmRuntimeIdentityV1 {
    binary: B4NegativeRunByteIdentityV1,
    release: B4NegativeRunByteIdentityV1,
}

/// Private, already-verified inputs to the token sealer.
///
/// The future physical executor will construct this value only after its
/// complete launch and teardown state machine succeeds. Keeping this type
/// private prevents canonical result bytes from becoming a public authority
/// shortcut.
struct B4VerifiedPhysicalNegativeRunV1<'a> {
    campaign_precommit_sha256: [u8; DIGEST_BYTES],
    positive_generation_set_sha256: [u8; DIGEST_BYTES],
    materialization_set_sha256: [u8; DIGEST_BYTES],
    expectation_set_sha256: [u8; DIGEST_BYTES],
    execution_index: u16,
    execution_id: &'a str,
    implementation: B4ValidatorImplementation,
    verifier_root_manifest_sha256: [u8; DIGEST_BYTES],
    validator_artifact: B4ValidatorArtifactIdentityV1,
    validator_descriptor: &'a [u8],
    runner_profile: &'a [u8],
    seccomp_document: &'a [u8],
    java_binary: Option<&'a [u8]>,
    java_release: Option<&'a [u8]>,
    observation_jcs: &'a [u8],
    result_jcs: &'a [u8],
}

/// One successful, physically executed negative validation.
///
/// Possession proves only that the reviewed in-crate executor reached its
/// success transition. The token is not a remote attestation and has no
/// serialized representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct B4NegativeRunTokenV1 {
    campaign_precommit_sha256: [u8; DIGEST_BYTES],
    positive_generation_set_sha256: [u8; DIGEST_BYTES],
    materialization_set_sha256: [u8; DIGEST_BYTES],
    expectation_set_sha256: [u8; DIGEST_BYTES],
    execution_index: u16,
    execution_id: String,
    implementation: B4ValidatorImplementation,
    verifier_root_manifest_sha256: [u8; DIGEST_BYTES],
    validator_artifact: B4ValidatorArtifactIdentityV1,
    validator_descriptor: B4NegativeRunByteIdentityV1,
    runner_profile: B4NegativeRunByteIdentityV1,
    seccomp_document: B4NegativeRunByteIdentityV1,
    java_runtime: Option<B4NegativeJvmRuntimeIdentityV1>,
    observation_jcs: Vec<u8>,
    result_jcs: Vec<u8>,
}

impl B4NegativeRunTokenV1 {
    fn seal_verified(evidence: B4VerifiedPhysicalNegativeRunV1<'_>) -> Result<Self> {
        validate_execution_id(evidence.execution_id)?;
        ensure!(
            evidence.observation_jcs.len() <= MAX_OBSERVATION_BYTES,
            "physical negative observation exceeds its byte bound"
        );
        ensure!(
            evidence.result_jcs.len() <= MAX_RESULT_BYTES,
            "physical negative result exceeds its byte bound"
        );
        let observation =
            Eip0045B4NegativeObservationV1::from_canonical_jcs(evidence.observation_jcs)
                .context("physical negative run produced an invalid canonical observation")?;
        let result = Eip0045B4ValidationResultV1::from_canonical_jcs(evidence.result_jcs)
            .context("physical negative run produced an invalid canonical attributed result")?;
        ensure!(
            result.execution_id == evidence.execution_id,
            "physical negative result names a different execution"
        );
        ensure!(
            result.implementation == evidence.implementation,
            "physical negative result names a different implementation"
        );
        ensure!(
            result.validator_artifact == evidence.validator_artifact,
            "physical negative result binds a different validator artifact"
        );
        ensure!(
            result.materialization_domain == observation.materialization_domain
                && result.validation_surface == observation.validation_surface,
            "physical negative observation and result disagree on their dispatch surface"
        );
        ensure!(
            result.rejection.class == observation.rejection.class
                && result.rejection.stage == observation.rejection.stage,
            "physical negative observation and result disagree on their rejection boundary"
        );

        let java_runtime = match evidence.implementation {
            B4ValidatorImplementation::RustReference => {
                ensure!(
                    evidence.java_binary.is_none() && evidence.java_release.is_none(),
                    "Rust physical run cannot bind a Java runtime"
                );
                None
            }
            B4ValidatorImplementation::IndependentJvm => {
                let binary = evidence
                    .java_binary
                    .context("JVM physical run lacks its Java binary")?;
                let release = evidence
                    .java_release
                    .context("JVM physical run lacks its Java release metadata")?;
                Some(B4NegativeJvmRuntimeIdentityV1 {
                    binary: B4NegativeRunByteIdentityV1::from_bytes(
                        binary,
                        1024 * 1024 * 1024,
                        "Java binary",
                    )?,
                    release: B4NegativeRunByteIdentityV1::from_bytes(
                        release,
                        1024 * 1024,
                        "Java release metadata",
                    )?,
                })
            }
        };

        Ok(Self {
            campaign_precommit_sha256: evidence.campaign_precommit_sha256,
            positive_generation_set_sha256: evidence.positive_generation_set_sha256,
            materialization_set_sha256: evidence.materialization_set_sha256,
            expectation_set_sha256: evidence.expectation_set_sha256,
            execution_index: evidence.execution_index,
            execution_id: evidence.execution_id.to_owned(),
            implementation: evidence.implementation,
            verifier_root_manifest_sha256: evidence.verifier_root_manifest_sha256,
            validator_artifact: evidence.validator_artifact,
            validator_descriptor: B4NegativeRunByteIdentityV1::from_bytes(
                evidence.validator_descriptor,
                16 * 1024 * 1024,
                "validator build descriptor",
            )?,
            runner_profile: B4NegativeRunByteIdentityV1::from_bytes(
                evidence.runner_profile,
                1024 * 1024,
                "validator runner profile",
            )?,
            seccomp_document: B4NegativeRunByteIdentityV1::from_bytes(
                evidence.seccomp_document,
                1024 * 1024,
                "validator seccomp document",
            )?,
            java_runtime,
            observation_jcs: evidence.observation_jcs.to_vec(),
            result_jcs: evidence.result_jcs.to_vec(),
        })
    }

    pub(crate) const fn campaign_precommit_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.campaign_precommit_sha256
    }

    pub(crate) const fn positive_generation_set_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.positive_generation_set_sha256
    }

    pub(crate) const fn materialization_set_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.materialization_set_sha256
    }

    pub(crate) const fn expectation_set_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.expectation_set_sha256
    }

    pub(crate) const fn execution_index(&self) -> u16 {
        self.execution_index
    }

    pub(crate) fn execution_id(&self) -> &str {
        &self.execution_id
    }

    pub(crate) const fn implementation(&self) -> B4ValidatorImplementation {
        self.implementation
    }

    pub(crate) const fn verifier_root_manifest_sha256(&self) -> [u8; DIGEST_BYTES] {
        self.verifier_root_manifest_sha256
    }

    pub(crate) fn validator_artifact(&self) -> &B4ValidatorArtifactIdentityV1 {
        &self.validator_artifact
    }

    pub(crate) const fn validator_descriptor_identity(&self) -> (u64, [u8; DIGEST_BYTES]) {
        (
            self.validator_descriptor.byte_length,
            self.validator_descriptor.sha256,
        )
    }

    pub(crate) const fn runner_profile_identity(&self) -> (u64, [u8; DIGEST_BYTES]) {
        (self.runner_profile.byte_length, self.runner_profile.sha256)
    }

    pub(crate) const fn seccomp_document_identity(&self) -> (u64, [u8; DIGEST_BYTES]) {
        (
            self.seccomp_document.byte_length,
            self.seccomp_document.sha256,
        )
    }

    pub(crate) const fn java_runtime_identities(
        &self,
    ) -> Option<((u64, [u8; DIGEST_BYTES]), (u64, [u8; DIGEST_BYTES]))> {
        match &self.java_runtime {
            Some(runtime) => Some((
                (runtime.binary.byte_length, runtime.binary.sha256),
                (runtime.release.byte_length, runtime.release.sha256),
            )),
            None => None,
        }
    }

    pub(crate) fn observation_jcs(&self) -> &[u8] {
        &self.observation_jcs
    }

    pub(crate) fn result_jcs(&self) -> &[u8] {
        &self.result_jcs
    }
}

fn validate_execution_id(value: &str) -> Result<()> {
    ensure!(
        (4..=MAX_EXECUTION_ID_BYTES).contains(&value.len()),
        "negative-run execution ID length is outside the V1 bound"
    );
    let (group, variant) = value
        .split_once("--")
        .context("negative-run execution ID lacks its group/variant separator")?;
    ensure!(
        !variant.contains("--"),
        "negative-run execution ID has more than one group/variant separator"
    );
    validate_lower_kebab(group, "negative-run execution group")?;
    validate_lower_kebab(variant, "negative-run execution variant")
}

fn validate_lower_kebab(value: &str, label: &str) -> Result<()> {
    let bytes = value.as_bytes();
    ensure!(!bytes.is_empty(), "{label} is empty");
    ensure!(
        bytes[0].is_ascii_lowercase() && bytes[bytes.len() - 1].is_ascii_alphanumeric(),
        "{label} must start with a lowercase letter and end with an alphanumeric"
    );
    ensure!(
        bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-'),
        "{label} is not bounded lowercase kebab-case"
    );
    ensure!(!value.contains("--"), "{label} contains an empty component");
    Ok(())
}

#[cfg(test)]
impl B4NegativeRunTokenV1 {
    pub(crate) fn seal_test_fixture(evidence: B4NegativeRunTestFixtureV1<'_>) -> Result<Self> {
        Self::seal_verified(B4VerifiedPhysicalNegativeRunV1 {
            campaign_precommit_sha256: evidence.campaign_precommit_sha256,
            positive_generation_set_sha256: evidence.positive_generation_set_sha256,
            materialization_set_sha256: evidence.materialization_set_sha256,
            expectation_set_sha256: evidence.expectation_set_sha256,
            execution_index: evidence.execution_index,
            execution_id: evidence.execution_id,
            implementation: evidence.implementation,
            verifier_root_manifest_sha256: evidence.verifier_root_manifest_sha256,
            validator_artifact: evidence.validator_artifact,
            validator_descriptor: evidence.validator_descriptor,
            runner_profile: evidence.runner_profile,
            seccomp_document: evidence.seccomp_document,
            java_binary: evidence.java_binary,
            java_release: evidence.java_release,
            observation_jcs: evidence.observation_jcs,
            result_jcs: evidence.result_jcs,
        })
    }
}

/// Test-only input to the private physical-run sealer.
#[cfg(test)]
pub(crate) struct B4NegativeRunTestFixtureV1<'a> {
    pub campaign_precommit_sha256: [u8; DIGEST_BYTES],
    pub positive_generation_set_sha256: [u8; DIGEST_BYTES],
    pub materialization_set_sha256: [u8; DIGEST_BYTES],
    pub expectation_set_sha256: [u8; DIGEST_BYTES],
    pub execution_index: u16,
    pub execution_id: &'a str,
    pub implementation: B4ValidatorImplementation,
    pub verifier_root_manifest_sha256: [u8; DIGEST_BYTES],
    pub validator_artifact: B4ValidatorArtifactIdentityV1,
    pub validator_descriptor: &'a [u8],
    pub runner_profile: &'a [u8],
    pub seccomp_document: &'a [u8],
    pub java_binary: Option<&'a [u8]>,
    pub java_release: Option<&'a [u8]>,
    pub observation_jcs: &'a [u8],
    pub result_jcs: &'a [u8],
}
