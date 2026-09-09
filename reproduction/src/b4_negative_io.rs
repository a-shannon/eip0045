//! Authority-minimal verifier input and observation formats for B4 negatives.
//!
//! These formats deliberately separate cryptographic or artifact validation
//! from campaign attribution. A validator receives only a neutral dispatch
//! surface and exact physical file identities. On rejection it emits only
//! physical bindings and the first stable rejection boundary. Execution IDs,
//! QA codes, expected outcomes, implementation identities, external paths,
//! and diagnostics belong to the finalizer and are not part of either format.

use std::{cmp::Ordering, collections::BTreeSet};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::{
    b4_negative_handler_contract::{
        planned_negative_handler_contract, require_negative_handler_contracts_frozen,
        validate_negative_rejection_boundary,
    },
    b4_plan::{B4MaterializationDomain, B4NegativeExecutionSurface},
    canonical::{canonical_json_bytes, validate_canonical_json_source},
};

/// Exact format discriminator for a neutral B4 negative verifier input.
pub const B4_NEGATIVE_VERIFIER_INPUT_FORMAT: &str = "Eip0045B4NegativeVerifierInputV1";
/// Exact format version for a neutral B4 negative verifier input.
pub const B4_NEGATIVE_VERIFIER_INPUT_FORMAT_VERSION: u8 = 1;
/// Exact format discriminator for a pathless B4 negative observation.
pub const B4_NEGATIVE_OBSERVATION_FORMAT: &str = "Eip0045B4NegativeObservationV1";
/// Exact format version for a pathless B4 negative observation.
pub const B4_NEGATIVE_OBSERVATION_FORMAT_VERSION: u8 = 1;

const MAX_NEGATIVE_INPUT_BYTES: usize = 65_536;
const MAX_NEGATIVE_OBSERVATION_BYTES: usize = 4_096;
const MAX_CONTEXT_IDENTITIES: usize = 64;
const MAX_FILE_BYTES: u64 = 536_870_912;
const MAX_PATH_BYTES: usize = 240;
const MAX_ROLE_BYTES: usize = 128;
const MAX_REJECTION_ID_BYTES: usize = 192;

/// Closed physical encoding of a file visible to a negative verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4NegativeFileEncoding {
    /// Opaque bytes interpreted only by the selected validation surface.
    RawBytes,
    /// Exact RFC 8785 JSON Canonicalization Scheme bytes.
    Rfc8785Jcs,
}

/// Exact identity and neutral role of one file visible to a negative verifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4NegativeNamedIdentityV1 {
    /// Closed positional role used for neutral dispatch.
    pub role: String,
    /// Safe relative POSIX path below the isolated verifier root.
    pub path: String,
    /// Exact physical byte length.
    pub byte_length: u64,
    /// Lowercase SHA-256 of the exact physical bytes.
    pub sha256: String,
    /// Closed physical encoding.
    pub encoding: B4NegativeFileEncoding,
}

impl B4NegativeNamedIdentityV1 {
    /// Validate the lexical, path, digest, and byte-bound invariants.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid role, unsafe path, empty or oversized
    /// file, malformed SHA-256, or invalid encoding label.
    pub fn validate(&self) -> Result<()> {
        self.validate_with_minimum(1)
    }

    fn validate_with_minimum(&self, minimum: u64) -> Result<()> {
        validate_lower_kebab(&self.role, MAX_ROLE_BYTES, "negative file role")?;
        validate_safe_relative_path(&self.path)?;
        ensure!(
            (minimum..=MAX_FILE_BYTES).contains(&self.byte_length),
            "negative file byte length is outside the V1 bound"
        );
        validate_digest(&self.sha256, "negative file SHA-256")?;
        Ok(())
    }
}

/// Canonical implementation-neutral input for one B4 negative validation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Eip0045B4NegativeVerifierInputV1 {
    /// Exact V1 format discriminator.
    pub format: String,
    /// Exact V1 format version.
    pub format_version: u8,
    /// Closed owner of the materialized subject.
    pub materialization_domain: B4MaterializationDomain,
    /// Closed validation entry point.
    pub validation_surface: B4NegativeExecutionSurface,
    /// Exact identity of the independently materialized subject.
    pub subject: B4NegativeNamedIdentityV1,
    /// Required context identities in strict unsigned UTF-8 role/path order.
    pub context: Vec<B4NegativeNamedIdentityV1>,
}

impl Eip0045B4NegativeVerifierInputV1 {
    /// Parse exact RFC 8785 JCS and enforce the closed neutral input contract.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, duplicate-key,
    /// noncanonical, unknown-field, incorrectly ordered, aliased, unsafe, or
    /// otherwise invalid input.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            source.len() <= MAX_NEGATIVE_INPUT_BYTES,
            "B4 negative verifier input exceeds its canonical-byte bound"
        );
        let value = validate_canonical_json_source(source)
            .context("B4 negative verifier input is not exact RFC 8785 JCS")?;
        let input: Self =
            serde_json::from_value(value).context("invalid B4 negative verifier-input shape")?;
        input.validate()?;
        ensure!(
            input.to_canonical_jcs()? == source,
            "B4 negative verifier input does not round-trip byte-exactly"
        );
        Ok(input)
    }

    /// Serialize a valid neutral input to exact RFC 8785 JCS bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the input violates any V1 invariant or its
    /// canonical representation exceeds the V1 byte bound.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value =
            serde_json::to_value(self).context("cannot serialize B4 negative verifier input")?;
        let bytes = canonical_json_bytes(&value)?;
        ensure!(
            bytes.len() <= MAX_NEGATIVE_INPUT_BYTES,
            "B4 negative verifier input exceeds its canonical-byte bound"
        );
        Ok(bytes)
    }

    /// Validate the closed V1 shape and cross-identity invariants.
    ///
    /// The subject is fixed to `subject` / `subject.bin`. Context identities
    /// form the exact prefix `context-00` / `context/00.bin` through
    /// `context-63` / `context/63.bin`; every file uses the non-semantic
    /// `raw-bytes` encoding. Paths form a component-prefix antichain.
    ///
    /// # Errors
    ///
    /// Returns an error for format drift, invalid identities, excessive
    /// context cardinality, duplicate roles or paths, or noncanonical context
    /// order.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == B4_NEGATIVE_VERIFIER_INPUT_FORMAT,
            "wrong B4 negative verifier-input format label"
        );
        ensure!(
            self.format_version == B4_NEGATIVE_VERIFIER_INPUT_FORMAT_VERSION,
            "wrong B4 negative verifier-input format version"
        );
        ensure!(
            self.context.len() <= MAX_CONTEXT_IDENTITIES,
            "B4 negative verifier input has too many context identities"
        );
        let handler = planned_negative_handler_contract(
            self.materialization_domain,
            self.validation_surface,
        )?
        .context(
            "B4 negative verifier input uses a domain/surface pair outside the canonical plan",
        )?;

        self.subject
            .validate_with_minimum(handler.custody().subject().minimum())?;
        let mut roles = BTreeSet::new();
        let mut paths = BTreeSet::new();
        roles.insert(self.subject.role.as_str());
        paths.insert(self.subject.path.as_str());

        let mut previous: Option<&B4NegativeNamedIdentityV1> = None;
        for identity in &self.context {
            identity.validate()?;
            ensure!(
                roles.insert(identity.role.as_str()),
                "B4 negative verifier input contains a duplicate file role"
            );
            ensure!(
                paths.insert(identity.path.as_str()),
                "B4 negative verifier input contains a duplicate file path"
            );
            if let Some(prior) = previous {
                ensure!(
                    compare_named_identities(prior, identity) == Ordering::Less,
                    "B4 negative context identities are not in strict unsigned UTF-8 role/path order"
                );
            }
            previous = Some(identity);
        }
        let identities = std::iter::once(&self.subject)
            .chain(&self.context)
            .collect::<Vec<_>>();
        for (left_index, left) in identities.iter().enumerate() {
            for right in identities.iter().skip(left_index + 1) {
                ensure!(
                    !paths_have_ancestor_relationship(&left.path, &right.path),
                    "B4 negative verifier input contains an ancestor/descendant file-path alias"
                );
            }
        }
        ensure!(
            self.subject.role == "subject"
                && self.subject.path == "subject.bin"
                && self.subject.encoding == B4NegativeFileEncoding::RawBytes,
            "B4 negative subject identity differs from the fixed V1 positional contract"
        );
        for (index, identity) in self.context.iter().enumerate() {
            ensure!(
                identity.role == format!("context-{index:02}")
                    && identity.path == format!("context/{index:02}.bin")
                    && identity.encoding == B4NegativeFileEncoding::RawBytes,
                "B4 negative context identity differs from the fixed V1 positional prefix at index {index}"
            );
        }
        Ok(())
    }

    /// Require the post-handler exact context cardinality for campaign use.
    ///
    /// Structural parsing intentionally admits a bounded positional prefix so
    /// the implementation-neutral format can be reviewed before the handlers.
    /// The sole handler table already owns every target cardinality, but this
    /// stronger gate remains fail-closed until all twenty production adapters
    /// and their focused fixtures are frozen.
    ///
    /// # Errors
    ///
    /// Returns an error while the selected pair has no reviewed exact
    /// cardinality, or when the supplied prefix length differs from it.
    pub fn validate_for_campaign_precommit(&self) -> Result<()> {
        self.validate()?;
        require_b4_negative_handler_contract_frozen()?;
        let expected = planned_negative_handler_contract(
            self.materialization_domain,
            self.validation_surface,
        )?
        .map(|contract| contract.custody().contexts().len())
            .context(
                "B4 negative handler context cardinality is not frozen; campaign precommit is forbidden",
            )?;
        ensure!(
            self.context.len() == expected,
            "B4 negative context cardinality differs from the reviewed handler contract"
        );
        Ok(())
    }
}

/// Closed verdict emitted after a materialized negative subject is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4NegativeObservationVerdict {
    /// The selected validation surface rejected the supplied subject.
    Reject,
}

/// First stable rejection boundary emitted by a negative verifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4NegativeObservationRejectionV1 {
    /// Stable normalized rejection class, without placeholder components.
    pub class: String,
    /// Stable normalized first rejection stage, without placeholder components.
    pub stage: String,
}

impl B4NegativeObservationRejectionV1 {
    /// Validate the closed lexical vocabulary for a rejection boundary.
    ///
    /// # Errors
    ///
    /// Returns an error unless both fields are bounded lower-kebab ASCII and
    /// contain no placeholder component.
    pub fn validate(&self) -> Result<()> {
        validate_lower_kebab(
            &self.class,
            MAX_REJECTION_ID_BYTES,
            "negative rejection class",
        )?;
        reject_placeholder(&self.class, "negative rejection class")?;
        validate_lower_kebab(
            &self.stage,
            MAX_REJECTION_ID_BYTES,
            "negative rejection stage",
        )?;
        reject_placeholder(&self.stage, "negative rejection stage")
    }
}

/// Canonical pathless observation for one rejected B4 negative input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Eip0045B4NegativeObservationV1 {
    /// Exact V1 format discriminator.
    pub format: String,
    /// Exact V1 format version.
    pub format_version: u8,
    /// Materialization domain copied from the validated neutral input.
    pub materialization_domain: B4MaterializationDomain,
    /// Validation surface copied from the validated neutral input.
    pub validation_surface: B4NegativeExecutionSurface,
    /// Lowercase SHA-256 of the canonical negative verifier-input bytes.
    pub negative_input_sha256: String,
    /// Exact physical byte length of the independently read subject.
    pub subject_byte_length: u64,
    /// Lowercase SHA-256 of the independently read subject bytes.
    pub subject_sha256: String,
    /// Closed negative verdict.
    pub verdict: B4NegativeObservationVerdict,
    /// First stable rejection boundary.
    pub rejection: B4NegativeObservationRejectionV1,
}

impl Eip0045B4NegativeObservationV1 {
    /// Parse exact RFC 8785 JCS and enforce the pathless observation contract.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, duplicate-key,
    /// noncanonical, unknown-field, incorrectly bounded, placeholder, or
    /// otherwise invalid observation bytes.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            source.len() <= MAX_NEGATIVE_OBSERVATION_BYTES,
            "B4 negative observation exceeds its canonical-byte bound"
        );
        let value = validate_canonical_json_source(source)
            .context("B4 negative observation is not exact RFC 8785 JCS")?;
        let observation: Self =
            serde_json::from_value(value).context("invalid B4 negative-observation shape")?;
        observation.validate()?;
        ensure!(
            observation.to_canonical_jcs()? == source,
            "B4 negative observation does not round-trip byte-exactly"
        );
        Ok(observation)
    }

    /// Serialize a valid pathless observation to exact RFC 8785 JCS bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the observation violates a V1 invariant or its
    /// canonical representation exceeds the V1 byte bound.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value =
            serde_json::to_value(self).context("cannot serialize B4 negative observation")?;
        let bytes = canonical_json_bytes(&value)?;
        ensure!(
            bytes.len() <= MAX_NEGATIVE_OBSERVATION_BYTES,
            "B4 negative observation exceeds its canonical-byte bound"
        );
        Ok(bytes)
    }

    /// Validate the closed V1 lexical and arithmetic invariants.
    ///
    /// # Errors
    ///
    /// Returns an error for format drift, invalid byte bounds, malformed
    /// digests, or an invalid rejection boundary.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == B4_NEGATIVE_OBSERVATION_FORMAT,
            "wrong B4 negative-observation format label"
        );
        ensure!(
            self.format_version == B4_NEGATIVE_OBSERVATION_FORMAT_VERSION,
            "wrong B4 negative-observation format version"
        );
        let handler = planned_negative_handler_contract(
            self.materialization_domain,
            self.validation_surface,
        )?
        .context("B4 negative observation uses a domain/surface pair outside the canonical plan")?;
        validate_digest(
            &self.negative_input_sha256,
            "negative-input observation SHA-256",
        )?;
        ensure!(
            (handler.custody().subject().minimum()..=handler.custody().subject().maximum())
                .contains(&self.subject_byte_length),
            "negative subject byte length is outside the selected handler bound"
        );
        validate_digest(&self.subject_sha256, "negative subject SHA-256")?;
        self.rejection.validate()?;
        validate_negative_rejection_boundary(
            self.materialization_domain,
            self.validation_surface,
            &self.rejection.class,
            &self.rejection.stage,
        )
    }
}

fn compare_named_identities(
    left: &B4NegativeNamedIdentityV1,
    right: &B4NegativeNamedIdentityV1,
) -> Ordering {
    left.role
        .as_bytes()
        .cmp(right.role.as_bytes())
        .then_with(|| left.path.as_bytes().cmp(right.path.as_bytes()))
}

/// Require the complete reviewed 20-row negative-handler context contract.
///
/// Pre-proof authorities must invoke this global gate before they can create
/// or accept a campaign precommit. Per-input validation alone is insufficient
/// because a campaign could otherwise omit every negative input while the
/// handler table remains incomplete.
///
/// # Errors
///
/// Returns an error unless the sole canonical handler-contract table is
/// complete, internally consistent, plan-exact, and fully production-frozen.
pub fn require_b4_negative_handler_contract_frozen() -> Result<()> {
    require_negative_handler_contracts_frozen()
}

fn paths_have_ancestor_relationship(left: &str, right: &str) -> bool {
    fn is_ancestor(ancestor: &str, descendant: &str) -> bool {
        descendant
            .strip_prefix(ancestor)
            .is_some_and(|suffix| suffix.starts_with('/'))
    }

    is_ancestor(left, right) || is_ancestor(right, left)
}

fn validate_lower_kebab(value: &str, max_bytes: usize, label: &str) -> Result<()> {
    let bytes = value.as_bytes();
    ensure!(
        !bytes.is_empty() && bytes.len() <= max_bytes,
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
        "{label} is not lowercase SHA-256 hex"
    );
    Ok(())
}

fn validate_safe_relative_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty() && path.len() <= MAX_PATH_BYTES,
        "B4 negative file path is empty or too long"
    );
    ensure!(
        !path.starts_with('/')
            && !path.ends_with('/')
            && !path.contains('\\')
            && !path.contains(':'),
        "B4 negative file path is not canonical relative POSIX"
    );
    ensure!(
        path != "negative-input.json" && !path.starts_with("negative-input.json/"),
        "B4 negative file path aliases the verifier-input control file"
    );
    for component in path.split('/') {
        let bytes = component.as_bytes();
        ensure!(
            !bytes.is_empty()
                && matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9')
                && bytes
                    .iter()
                    .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
                && component != "."
                && component != ".."
                && !component.ends_with('.')
                && !is_windows_device_component(component),
            "B4 negative file path contains an unsafe component"
        );
    }
    Ok(())
}

fn is_windows_device_component(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
    {
        return true;
    }
    let bytes = stem.as_bytes();
    bytes.len() == 4
        && (stem[..3].eq_ignore_ascii_case("COM") || stem[..3].eq_ignore_ascii_case("LPT"))
        && (b'1'..=b'9').contains(&bytes[3])
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    const ALL_DOMAINS: [B4MaterializationDomain; 3] = [
        B4MaterializationDomain::VerifierInput,
        B4MaterializationDomain::ArtifactValidator,
        B4MaterializationDomain::TreeValidator,
    ];
    const ALL_SURFACES: [B4NegativeExecutionSurface; 19] = [
        B4NegativeExecutionSurface::OpcodePreflight,
        B4NegativeExecutionSurface::RawStatementClaimBinding,
        B4NegativeExecutionSurface::RawSealShape,
        B4NegativeExecutionSurface::Risc0ParserInternal,
        B4NegativeExecutionSurface::Risc0CryptographicVerifier,
        B4NegativeExecutionSurface::TerminalPolicy,
        B4NegativeExecutionSurface::ReceiptClaimPolicy,
        B4NegativeExecutionSurface::AncestryReplay,
        B4NegativeExecutionSurface::ProfileManifestCodec,
        B4NegativeExecutionSurface::InitialProfileTarget,
        B4NegativeExecutionSurface::ProfileArtifactEnvelope,
        B4NegativeExecutionSurface::ActivatedProfilePackage,
        B4NegativeExecutionSurface::TerminalFixtureCatalog,
        B4NegativeExecutionSurface::SequenceSubjectCatalog,
        B4NegativeExecutionSurface::TerminalMetadata,
        B4NegativeExecutionSurface::ProfileIdPreimage,
        B4NegativeExecutionSurface::CandidateRegistry,
        B4NegativeExecutionSurface::NegativeBindingIndex,
        B4NegativeExecutionSurface::CorpusClosure,
    ];

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn identity(role: &str, path: &str, byte: char) -> B4NegativeNamedIdentityV1 {
        B4NegativeNamedIdentityV1 {
            role: role.to_owned(),
            path: path.to_owned(),
            byte_length: 17,
            sha256: digest(byte),
            encoding: B4NegativeFileEncoding::RawBytes,
        }
    }

    fn context_identity(index: usize, byte: char) -> B4NegativeNamedIdentityV1 {
        identity(
            &format!("context-{index:02}"),
            &format!("context/{index:02}.bin"),
            byte,
        )
    }

    fn input() -> Eip0045B4NegativeVerifierInputV1 {
        Eip0045B4NegativeVerifierInputV1 {
            format: B4_NEGATIVE_VERIFIER_INPUT_FORMAT.to_owned(),
            format_version: B4_NEGATIVE_VERIFIER_INPUT_FORMAT_VERSION,
            materialization_domain: B4MaterializationDomain::VerifierInput,
            validation_surface: B4NegativeExecutionSurface::RawSealShape,
            subject: identity("subject", "subject.bin", '1'),
            context: vec![context_identity(0, '2'), context_identity(1, '3')],
        }
    }

    fn observation() -> Eip0045B4NegativeObservationV1 {
        Eip0045B4NegativeObservationV1 {
            format: B4_NEGATIVE_OBSERVATION_FORMAT.to_owned(),
            format_version: B4_NEGATIVE_OBSERVATION_FORMAT_VERSION,
            materialization_domain: B4MaterializationDomain::VerifierInput,
            validation_surface: B4NegativeExecutionSurface::RawSealShape,
            negative_input_sha256: digest('a'),
            subject_byte_length: 222_668,
            subject_sha256: digest('b'),
            verdict: B4NegativeObservationVerdict::Reject,
            rejection: B4NegativeObservationRejectionV1 {
                class: "raw-seal-shape-invalid".to_owned(),
                stage: "babybear-word-reduction".to_owned(),
            },
        }
    }

    fn canonical_dispatch_pairs() -> BTreeSet<(B4MaterializationDomain, B4NegativeExecutionSurface)>
    {
        crate::b4_plan::Eip0045B4NegativePlanV1::canonical()
            .unwrap()
            .groups
            .into_iter()
            .flat_map(|group| group.executions)
            .map(|execution| {
                (
                    execution.materialization_domain,
                    execution.execution_surface,
                )
            })
            .collect()
    }

    #[test]
    fn negative_input_round_trips_as_exact_jcs_and_has_only_neutral_fields() {
        let expected = input();
        let bytes = expected.to_canonical_jcs().unwrap();
        assert_eq!(
            Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(&bytes).unwrap(),
            expected
        );

        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            [
                "context",
                "format",
                "formatVersion",
                "materializationDomain",
                "subject",
                "validationSurface",
            ]
            .into_iter()
            .collect::<BTreeSet<_>>()
        );
        for forbidden in [
            "executionId",
            "qaResultCode",
            "expectedVerdict",
            "expectedRejection",
            "implementation",
            "descriptor",
        ] {
            assert!(value.get(forbidden).is_none());
        }
    }

    #[test]
    fn negative_input_rejects_non_jcs_duplicates_unknown_fields_and_trailing_data() {
        let canonical = input().to_canonical_jcs().unwrap();
        let pretty =
            serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&canonical).unwrap())
                .unwrap();
        assert!(Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(&pretty).is_err());

        let duplicate = br#"{"context":[],"format":"Eip0045B4NegativeVerifierInputV1","format":"Eip0045B4NegativeVerifierInputV1","formatVersion":1,"materializationDomain":"verifier-input","subject":{"byteLength":1,"encoding":"raw-bytes","path":"subject.bin","role":"subject","sha256":"1111111111111111111111111111111111111111111111111111111111111111"},"validationSurface":"raw-seal-shape"}"#;
        assert!(Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(duplicate).is_err());

        let mut unknown: Value = serde_json::from_slice(&canonical).unwrap();
        unknown["executionId"] = json!("opaque");
        let unknown = canonical_json_bytes(&unknown).unwrap();
        assert!(Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(&unknown).is_err());

        let mut trailing = canonical;
        trailing.push(b'\n');
        assert!(Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(&trailing).is_err());
    }

    #[test]
    fn negative_input_rejects_context_order_and_role_or_path_aliases() {
        let mut reordered = input();
        reordered.context.swap(0, 1);
        assert!(reordered.validate().is_err());

        let mut duplicate_role = input();
        duplicate_role.context[0].role = "subject".to_owned();
        assert!(duplicate_role.validate().is_err());

        let mut duplicate_path = input();
        duplicate_path.context[0].path = "subject.bin".to_owned();
        assert!(duplicate_path.validate().is_err());

        let mut duplicate_context_role = input();
        duplicate_context_role.context[1].role = duplicate_context_role.context[0].role.clone();
        assert!(duplicate_context_role.validate().is_err());

        let mut duplicate_context_path = input();
        duplicate_context_path.context[1].path = duplicate_context_path.context[0].path.clone();
        assert!(duplicate_context_path.validate().is_err());

        let mut subject_prefix_alias = input();
        subject_prefix_alias.subject.path = "context".to_owned();
        assert!(
            subject_prefix_alias
                .validate()
                .unwrap_err()
                .to_string()
                .contains("ancestor")
        );

        let mut context_prefix_alias = input();
        context_prefix_alias.context[0].path = "shared".to_owned();
        context_prefix_alias.context[1].path = "shared/nested.bin".to_owned();
        assert!(
            context_prefix_alias
                .validate()
                .unwrap_err()
                .to_string()
                .contains("ancestor")
        );
    }

    #[test]
    fn negative_input_closes_subject_and_positional_context_channels() {
        input().validate().unwrap();

        let mut subject_role = input();
        subject_role.subject.role = "raw-seal-shape".to_owned();
        assert!(subject_role.validate().is_err());
        let mut subject_path = input();
        subject_path.subject.path = "execution-id.bin".to_owned();
        assert!(subject_path.validate().is_err());
        let mut subject_encoding = input();
        subject_encoding.subject.encoding = B4NegativeFileEncoding::Rfc8785Jcs;
        assert!(subject_encoding.validate().is_err());

        for forbidden_role in [
            "execution-id",
            "qa-result-code",
            "expected-boundary",
            "profile-algorithm",
        ] {
            let mut candidate = input();
            candidate.context[0].role = forbidden_role.to_owned();
            assert!(
                candidate.validate().is_err(),
                "arbitrary context role unexpectedly accepted: {forbidden_role}"
            );
        }

        let mut gap = input();
        gap.context[1] = context_identity(2, '3');
        assert!(gap.validate().is_err());
        let mut wrong_path = input();
        wrong_path.context[0].path = "context/01.bin".to_owned();
        assert!(wrong_path.validate().is_err());
        let mut semantic_extension = input();
        semantic_extension.context[0].path = "context/00-execution-id.bin".to_owned();
        assert!(semantic_extension.validate().is_err());
        let mut context_encoding = input();
        context_encoding.context[0].encoding = B4NegativeFileEncoding::Rfc8785Jcs;
        assert!(context_encoding.validate().is_err());
    }

    #[test]
    fn frozen_handlers_preserve_exact_campaign_input_cardinality() {
        input().validate().unwrap();
        require_b4_negative_handler_contract_frozen().unwrap();
        assert!(
            input()
                .validate_for_campaign_precommit()
                .unwrap_err()
                .to_string()
                .contains("B4 negative context cardinality differs from the reviewed handler contract")
        );
        let mut exact = input();
        exact.context.pop();
        exact.validate_for_campaign_precommit().unwrap();
    }

    #[test]
    fn dispatch_whitelist_matches_exact_canonical_plan_pairs() {
        let planned = canonical_dispatch_pairs();
        assert_eq!(
            planned.len(),
            crate::b4_negative_handler_contract::B4_NEGATIVE_HANDLER_CONTRACT_COUNT
        );

        for domain in ALL_DOMAINS {
            for surface in ALL_SURFACES {
                let mut candidate = input();
                candidate.materialization_domain = domain;
                candidate.validation_surface = surface;
                if let Some(contract) = planned_negative_handler_contract(domain, surface).unwrap()
                {
                    candidate.subject.byte_length = contract.custody().subject().minimum();
                }
                let accepted = candidate.validate().is_ok();
                assert_eq!(
                    accepted,
                    planned.contains(&(domain, surface)),
                    "dispatch contract drift for {domain:?}/{surface:?}"
                );

                let mut observed = observation();
                observed.materialization_domain = domain;
                observed.validation_surface = surface;
                if let Some(contract) = planned_negative_handler_contract(domain, surface).unwrap()
                {
                    observed.subject_byte_length = contract.custody().subject().minimum();
                    let boundary = contract.rejection_boundaries()[0];
                    observed.rejection.class = boundary.class().to_owned();
                    observed.rejection.stage = boundary.stage().to_owned();
                }
                assert_eq!(
                    observed.validate().is_ok(),
                    planned.contains(&(domain, surface)),
                    "observation dispatch contract drift for {domain:?}/{surface:?}"
                );
            }
        }
    }

    #[test]
    fn named_identity_enforces_bounds_digests_labels_and_safe_paths() {
        let valid = identity("profile-manifest", "context/profile-manifest.bin", 'a');
        valid.validate().unwrap();

        for path in [
            "",
            "/absolute",
            "trailing/",
            "a//b",
            "a/../b",
            "a\\b",
            "c:relative",
            "Uppercase",
            "name.",
            "con",
            "aux.txt",
            "dir/com1.bin",
            "space here",
            ".hidden",
            "negative-input.json",
            "negative-input.json/context.bin",
        ] {
            let mut candidate = valid.clone();
            candidate.path = path.to_owned();
            assert!(
                candidate.validate().is_err(),
                "unsafe path unexpectedly accepted: {path}"
            );
        }

        for role in ["", "Upper", "-prefix", "suffix-", "two--parts", "\u{00e9}"] {
            let mut candidate = valid.clone();
            candidate.role = role.to_owned();
            assert!(
                candidate.validate().is_err(),
                "invalid role unexpectedly accepted: {role}"
            );
        }

        let encoded = serde_json::to_value(&valid).unwrap();
        for encoding in ["", "RawBytes", "raw_bytes", "utf8", "raw--bytes"] {
            let mut candidate = encoded.clone();
            candidate["encoding"] = json!(encoding);
            assert!(
                serde_json::from_value::<B4NegativeNamedIdentityV1>(candidate).is_err(),
                "invalid encoding unexpectedly accepted: {encoding}"
            );
        }

        let mut zero = valid.clone();
        zero.byte_length = 0;
        assert!(zero.validate().is_err());
        let mut oversized = valid.clone();
        oversized.byte_length = MAX_FILE_BYTES + 1;
        assert!(oversized.validate().is_err());
        let mut upper_digest = valid.clone();
        upper_digest.sha256 = "A".repeat(64);
        assert!(upper_digest.validate().is_err());
        let mut short_digest = valid;
        short_digest.sha256 = "a".repeat(63);
        assert!(short_digest.validate().is_err());
    }

    #[test]
    fn only_the_internal_parser_pair_admits_a_zero_byte_subject() {
        let mut parser_input = input();
        parser_input.validation_surface = B4NegativeExecutionSurface::Risc0ParserInternal;
        parser_input.subject.byte_length = 0;
        parser_input.validate().unwrap();
        let parser_source = parser_input.to_canonical_jcs().unwrap();
        assert_eq!(
            Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(&parser_source).unwrap(),
            parser_input
        );

        let mut wrong_surface = parser_input.clone();
        wrong_surface.validation_surface = B4NegativeExecutionSurface::RawSealShape;
        assert!(wrong_surface.validate().is_err());
        let mut wrong_domain = parser_input.clone();
        wrong_domain.materialization_domain = B4MaterializationDomain::ArtifactValidator;
        wrong_domain.validation_surface = B4NegativeExecutionSurface::CandidateRegistry;
        assert!(wrong_domain.validate().is_err());
        let mut empty_context = parser_input.clone();
        empty_context.context[0].byte_length = 0;
        assert!(empty_context.validate().is_err());

        let mut parser_observation = observation();
        parser_observation.validation_surface = B4NegativeExecutionSurface::Risc0ParserInternal;
        parser_observation.subject_byte_length = 0;
        parser_observation.rejection.class = "risc0-parser-invalid".to_owned();
        parser_observation.rejection.stage = "risc0-read-iop-output-before-read".to_owned();
        parser_observation.validate().unwrap();
        let observation_source = parser_observation.to_canonical_jcs().unwrap();
        assert_eq!(
            Eip0045B4NegativeObservationV1::from_canonical_jcs(&observation_source).unwrap(),
            parser_observation
        );

        let mut wrong_observation = parser_observation;
        wrong_observation.validation_surface = B4NegativeExecutionSurface::RawSealShape;
        assert!(wrong_observation.validate().is_err());
    }

    #[test]
    fn negative_input_enforces_format_version_and_context_bound() {
        let mut wrong_format = input();
        wrong_format.format = "Eip0045B4NegativeVerifierInputV2".to_owned();
        assert!(wrong_format.validate().is_err());

        let mut wrong_version = input();
        wrong_version.format_version = 2;
        assert!(wrong_version.validate().is_err());

        let mut maximum = input();
        maximum.context = (0..MAX_CONTEXT_IDENTITIES)
            .map(|index| context_identity(index, 'c'))
            .collect();
        maximum.validate().unwrap();

        let mut too_many = maximum;
        too_many
            .context
            .push(context_identity(MAX_CONTEXT_IDENTITIES, 'd'));
        assert!(too_many.validate().is_err());
    }

    #[test]
    fn negative_observation_round_trips_and_has_no_attribution_or_diagnostic_fields() {
        let expected = observation();
        let bytes = expected.to_canonical_jcs().unwrap();
        assert_eq!(
            Eip0045B4NegativeObservationV1::from_canonical_jcs(&bytes).unwrap(),
            expected
        );
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            [
                "format",
                "formatVersion",
                "materializationDomain",
                "negativeInputSha256",
                "rejection",
                "subjectByteLength",
                "subjectSha256",
                "validationSurface",
                "verdict",
            ]
            .into_iter()
            .collect::<BTreeSet<_>>()
        );
        for forbidden in [
            "path",
            "executionId",
            "qaResultCode",
            "implementation",
            "diagnostic",
            "message",
            "clock",
        ] {
            assert!(value.get(forbidden).is_none());
        }
    }

    #[test]
    fn negative_observation_rejects_noncanonical_unknown_and_nonreject_shapes() {
        let canonical = observation().to_canonical_jcs().unwrap();
        let pretty =
            serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&canonical).unwrap())
                .unwrap();
        assert!(Eip0045B4NegativeObservationV1::from_canonical_jcs(&pretty).is_err());

        let duplicate = br#"{"format":"Eip0045B4NegativeObservationV1","formatVersion":1,"materializationDomain":"verifier-input","negativeInputSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","rejection":{"class":"raw-seal-shape-invalid","class":"raw-seal-shape-invalid","stage":"canonical-word-decoding"},"subjectByteLength":222668,"subjectSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","validationSurface":"raw-seal-shape","verdict":"reject"}"#;
        assert!(Eip0045B4NegativeObservationV1::from_canonical_jcs(duplicate).is_err());

        let mut unknown: Value = serde_json::from_slice(&canonical).unwrap();
        unknown["diagnostic"] = json!("not allowed");
        let unknown = canonical_json_bytes(&unknown).unwrap();
        assert!(Eip0045B4NegativeObservationV1::from_canonical_jcs(&unknown).is_err());

        let mut nested_unknown: Value = serde_json::from_slice(&canonical).unwrap();
        nested_unknown["rejection"]["path"] = json!("subject.bin");
        let nested_unknown = canonical_json_bytes(&nested_unknown).unwrap();
        assert!(Eip0045B4NegativeObservationV1::from_canonical_jcs(&nested_unknown).is_err());

        let mut accept: Value = serde_json::from_slice(&canonical).unwrap();
        accept["verdict"] = json!("accept");
        let accept = canonical_json_bytes(&accept).unwrap();
        assert!(Eip0045B4NegativeObservationV1::from_canonical_jcs(&accept).is_err());

        let mut removed_field: Value = serde_json::from_slice(&canonical).unwrap();
        removed_field["negativeInputByteLength"] = json!(511);
        let removed_field = canonical_json_bytes(&removed_field).unwrap();
        assert!(Eip0045B4NegativeObservationV1::from_canonical_jcs(&removed_field).is_err());
    }

    #[test]
    fn negative_observation_enforces_bounds_digests_and_nonplaceholder_rejection_ids() {
        let mut wrong_format = observation();
        wrong_format.format = "Eip0045B4NegativeObservationV2".to_owned();
        assert!(wrong_format.validate().is_err());
        let mut wrong_version = observation();
        wrong_version.format_version = 2;
        assert!(wrong_version.validate().is_err());

        for length in [0, MAX_FILE_BYTES + 1] {
            let mut candidate = observation();
            candidate.subject_byte_length = length;
            assert!(candidate.validate().is_err());
        }
        let handler = planned_negative_handler_contract(
            B4MaterializationDomain::VerifierInput,
            B4NegativeExecutionSurface::RawSealShape,
        )
        .unwrap()
        .unwrap();
        let mut above_handler_maximum = observation();
        above_handler_maximum.subject_byte_length = handler
            .custody()
            .subject()
            .maximum()
            .checked_add(1)
            .unwrap();
        assert!(above_handler_maximum.validate().is_err());

        let mut bad_input_digest = observation();
        bad_input_digest.negative_input_sha256 = "A".repeat(64);
        assert!(bad_input_digest.validate().is_err());
        let mut bad_subject_digest = observation();
        bad_subject_digest.subject_sha256 = "a".repeat(65);
        assert!(bad_subject_digest.validate().is_err());

        for field in ["class", "stage"] {
            for invalid in [
                "",
                "Upper",
                "-prefix",
                "suffix-",
                "two--parts",
                "unknown",
                "parser-error",
                "generic-parser",
                "proof-failure-stage",
                "fixme",
                "pending",
                "tbd",
            ] {
                let mut candidate = observation();
                match field {
                    "class" => candidate.rejection.class = invalid.to_owned(),
                    "stage" => candidate.rejection.stage = invalid.to_owned(),
                    _ => unreachable!(),
                }
                assert!(
                    candidate.validate().is_err(),
                    "invalid {field} unexpectedly accepted: {invalid}"
                );
            }
        }

        let mut cross_handler = observation();
        cross_handler.rejection.class = "profile-manifest-invalid".to_owned();
        cross_handler.rejection.stage = "profile-manifest-byte-length".to_owned();
        assert!(cross_handler.validate().is_err());

        let mut crossed_pair = observation();
        crossed_pair.rejection.stage = "inner-control-root-binding".to_owned();
        assert!(crossed_pair.validate().is_err());
    }

    #[cfg(feature = "positive-gate")]
    fn schema_validator(source: &str) -> jsonschema::Validator {
        let schema = crate::canonical::parse_json_strict(source.as_bytes()).unwrap();
        jsonschema::draft202012::options().build(&schema).unwrap()
    }

    #[cfg(feature = "positive-gate")]
    fn assert_input_schema_local_rules(input_schema: &jsonschema::Validator) {
        let mut input_value = serde_json::to_value(input()).unwrap();
        input_schema.validate(&input_value).unwrap();
        input_value["implementation"] = json!("rust-reference");
        assert!(input_schema.validate(&input_value).is_err());
        input_value = serde_json::to_value(input()).unwrap();
        input_value["subject"]["path"] = json!("context/con.txt");
        assert!(input_schema.validate(&input_value).is_err());
        input_value = serde_json::to_value(input()).unwrap();
        input_value["subject"]["encoding"] = json!("utf8");
        assert!(input_schema.validate(&input_value).is_err());
        input_value = serde_json::to_value(input()).unwrap();
        input_value["subject"]["role"] = json!("execution-id");
        assert!(input_schema.validate(&input_value).is_err());
        input_value = serde_json::to_value(input()).unwrap();
        input_value["context"][0]["role"] = json!("expected-boundary");
        assert!(input_schema.validate(&input_value).is_err());
        input_value = serde_json::to_value(input()).unwrap();
        input_value["context"][1]["role"] = json!("context-02");
        input_value["context"][1]["path"] = json!("context/02.bin");
        assert!(input_schema.validate(&input_value).is_err());
        input_value = serde_json::to_value(input()).unwrap();
        input_value["context"][0]["path"] = json!("negative-input.json/context.bin");
        assert!(input_schema.validate(&input_value).is_err());
        input_value = serde_json::to_value(input()).unwrap();
        input_value["validationSurface"] = json!("risc0-parser-internal");
        input_value["subject"]["byteLength"] = json!(0);
        input_schema.validate(&input_value).unwrap();
        input_value["validationSurface"] = json!("raw-seal-shape");
        assert!(input_schema.validate(&input_value).is_err());
        input_value["validationSurface"] = json!("risc0-parser-internal");
        input_value["context"][0]["byteLength"] = json!(0);
        assert!(input_schema.validate(&input_value).is_err());
    }

    #[cfg(feature = "positive-gate")]
    fn assert_observation_schema_local_rules(observation_schema: &jsonschema::Validator) {
        let mut observation_value = serde_json::to_value(observation()).unwrap();
        observation_schema.validate(&observation_value).unwrap();
        observation_value["diagnostic"] = json!("not allowed");
        assert!(observation_schema.validate(&observation_value).is_err());
        observation_value = serde_json::to_value(observation()).unwrap();
        observation_value["rejection"]["class"] = json!("unknown");
        assert!(observation_schema.validate(&observation_value).is_err());
        for placeholder in ["fixme", "pending"] {
            observation_value = serde_json::to_value(observation()).unwrap();
            observation_value["rejection"]["stage"] = json!(placeholder);
            assert!(
                observation_schema.validate(&observation_value).is_err(),
                "schema accepted placeholder rejection stage: {placeholder}"
            );
        }
        observation_value = serde_json::to_value(observation()).unwrap();
        observation_value["materializationDomain"] = json!("tree-validator");
        observation_value["validationSurface"] = json!("raw-seal-shape");
        assert!(observation_schema.validate(&observation_value).is_err());
        observation_value = serde_json::to_value(observation()).unwrap();
        observation_value["negativeInputByteLength"] = json!(511);
        assert!(observation_schema.validate(&observation_value).is_err());
        observation_value = serde_json::to_value(observation()).unwrap();
        observation_value["validationSurface"] = json!("risc0-parser-internal");
        observation_value["subjectByteLength"] = json!(0);
        observation_value["rejection"]["class"] = json!("risc0-parser-invalid");
        observation_value["rejection"]["stage"] = json!("risc0-read-iop-output-before-read");
        observation_schema.validate(&observation_value).unwrap();
        observation_value["validationSurface"] = json!("raw-seal-shape");
        assert!(observation_schema.validate(&observation_value).is_err());
    }

    #[cfg(feature = "positive-gate")]
    fn assert_schema_dispatch_and_rejection_parity(
        input_schema: &jsonschema::Validator,
        observation_schema: &jsonschema::Validator,
    ) {
        let planned = canonical_dispatch_pairs();
        for domain in ALL_DOMAINS {
            for surface in ALL_SURFACES {
                let mut input_value = serde_json::to_value(input()).unwrap();
                input_value["materializationDomain"] = serde_json::to_value(domain).unwrap();
                input_value["validationSurface"] = serde_json::to_value(surface).unwrap();
                assert_eq!(
                    input_schema.is_valid(&input_value),
                    planned.contains(&(domain, surface)),
                    "input schema dispatch drift for {domain:?}/{surface:?}"
                );

                let mut observation_value = serde_json::to_value(observation()).unwrap();
                observation_value["materializationDomain"] = serde_json::to_value(domain).unwrap();
                observation_value["validationSurface"] = serde_json::to_value(surface).unwrap();
                if let Some(contract) = planned_negative_handler_contract(domain, surface).unwrap()
                {
                    let boundary = contract.rejection_boundaries()[0];
                    observation_value["rejection"]["class"] = json!(boundary.class());
                    observation_value["rejection"]["stage"] = json!(boundary.stage());
                }
                assert_eq!(
                    observation_schema.is_valid(&observation_value),
                    planned.contains(&(domain, surface)),
                    "observation schema dispatch drift for {domain:?}/{surface:?}"
                );
            }
        }

        let mut validated_boundary_count = 0;
        for (domain, surface) in planned {
            let contract = planned_negative_handler_contract(domain, surface)
                .unwrap()
                .expect("canonical dispatch pair must have one handler contract");
            for boundary in contract.rejection_boundaries() {
                let mut candidate = observation();
                candidate.materialization_domain = domain;
                candidate.validation_surface = surface;
                candidate.subject_byte_length = contract.custody().subject().minimum();
                candidate.rejection.class = boundary.class().to_owned();
                candidate.rejection.stage = boundary.stage().to_owned();
                candidate.validate().unwrap_or_else(|error| {
                    panic!(
                        "Rust rejects planned boundary {domain:?}/{surface:?}/{}/{}: {error:#}",
                        boundary.class(),
                        boundary.stage()
                    )
                });
                let value = serde_json::to_value(candidate).unwrap();
                observation_schema.validate(&value).unwrap_or_else(|error| {
                    panic!(
                        "schema rejects planned boundary {domain:?}/{surface:?}/{}/{}: {error}",
                        boundary.class(),
                        boundary.stage()
                    )
                });
                validated_boundary_count += 1;
            }
        }
        assert_eq!(
            validated_boundary_count, 82,
            "Rust/schema boundary parity count drift"
        );
    }

    #[cfg(feature = "positive-gate")]
    #[test]
    fn schemas_accept_valid_instances_and_reject_forbidden_fields() {
        let input_schema = schema_validator(include_str!(
            "../finalizer-schema/b4-negative-verifier-input-v1.schema.json"
        ));
        let observation_schema = schema_validator(include_str!(
            "../finalizer-schema/b4-negative-observation-v1.schema.json"
        ));
        assert_input_schema_local_rules(&input_schema);
        assert_observation_schema_local_rules(&observation_schema);
        assert_schema_dispatch_and_rejection_parity(&input_schema, &observation_schema);
    }
}
