//! Closed publication layout and completion witness for the B4 positive input set.
//!
//! The physical phase root is selected per campaign and authenticated by the
//! campaign executor. This module freezes only the two direct phase-local file
//! names and the canonical completion document. The completion document is a
//! closure witness, not an authority for reconstructing the positive gate.

use anyhow::{ensure, Context as _, Result};
#[cfg(any(feature = "positive-gate", test))]
use serde::{Deserialize, Serialize};

use crate::b4_campaign_contract::{
    b4_paths_conflict, validate_safe_relative_path, B4ContractArtifactIdentityV1,
};
#[cfg(feature = "positive-gate")]
use crate::b4_positive_gate::PositiveGateBindings;
#[cfg(any(feature = "positive-gate", test))]
use crate::{
    b4_campaign_contract::{B4ContractArtifactEncodingV1, MAX_INPUT_SET_BYTES},
    canonical::{canonical_json_bytes, validate_canonical_json_source},
};

const POSITIVE_INPUT_SET_FILE: &str = "positive-input-set.json";
const POSITIVE_INPUT_SET_COMPLETION_FILE: &str = "positive-input-set-completion.json";
const POSITIVE_INPUT_SET_PUBLICATION_ORDER: [&str; 2] =
    [POSITIVE_INPUT_SET_FILE, POSITIVE_INPUT_SET_COMPLETION_FILE];
#[cfg(any(feature = "positive-gate", test))]
const COMPLETION_FORMAT: &str = "Eip0045B4PositiveInputSetCompletionV1";
#[cfg(any(feature = "positive-gate", test))]
const FORMAT_VERSION: u8 = 1;
#[cfg(any(feature = "positive-gate", test))]
const COMPLETION_FORMAT_V2: &str = "Eip0045B4PositiveInputSetCompletionV2";
#[cfg(any(feature = "positive-gate", test))]
const INPUT_SET_FORMAT_V2: &str = "Eip0045B4PositiveInputSetV2";
#[cfg(any(feature = "positive-gate", test))]
const FORMAT_VERSION_V2: u8 = 2;
#[cfg(any(feature = "positive-gate", test))]
const MAX_COMPLETION_BYTES: usize = 4096;

/// Compiled role ceiling for the canonical positive input-set artifact.
#[cfg(feature = "positive-gate")]
pub const B4_POSITIVE_INPUT_SET_MAX_BYTES: usize = MAX_INPUT_SET_BYTES as usize;

/// Compiled role ceiling for the last-written H0 completion witness.
#[cfg(feature = "positive-gate")]
pub const B4_POSITIVE_INPUT_SET_COMPLETION_MAX_BYTES: usize = MAX_COMPLETION_BYTES;

/// Closed, non-serializable V1 layout for one H0 input-set publication root.
///
/// The root itself is deliberately absent from this value. It is a
/// campaign-selected path authenticated separately by executor custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct B4PositiveInputSetLayoutV1 {
    _private: (),
}

impl B4PositiveInputSetLayoutV1 {
    /// Return the only admitted V1 layout.
    #[must_use]
    pub const fn closed_v1() -> Self {
        Self { _private: () }
    }

    /// Direct phase-local filename of the canonical positive input set.
    #[must_use]
    pub const fn input_set_file(self) -> &'static str {
        POSITIVE_INPUT_SET_FILE
    }

    /// Direct phase-local filename of the last-written completion witness.
    #[must_use]
    pub const fn completion_file(self) -> &'static str {
        POSITIVE_INPUT_SET_COMPLETION_FILE
    }

    /// Exact write order required before the outer create-only commit.
    #[must_use]
    pub const fn publication_order(self) -> [&'static str; 2] {
        POSITIVE_INPUT_SET_PUBLICATION_ORDER
    }
}

/// Opaque, non-serializable projection of the two campaign-relative H0 paths.
///
/// This value authenticates no filesystem object. It freezes only the lexical
/// relationship between one campaign-relative phase root and the two direct
/// filenames admitted by [`B4PositiveInputSetLayoutV1`]. Physical authority
/// remains in the executor's retained campaign and mutation custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct B4PositiveInputSetPublicationPathsV1 {
    phase_root: String,
    input_set_path: String,
    completion_path: String,
}

impl B4PositiveInputSetPublicationPathsV1 {
    /// Campaign-relative H0 phase root from which both file paths were derived.
    #[must_use]
    pub fn phase_root(&self) -> &str {
        &self.phase_root
    }

    /// Exact campaign-relative path of the canonical positive input set.
    #[must_use]
    pub fn input_set_path(&self) -> &str {
        &self.input_set_path
    }

    /// Exact campaign-relative path of the last-written completion witness.
    #[must_use]
    pub fn completion_path(&self) -> &str {
        &self.completion_path
    }
}

/// Project the closed H0 paths from one campaign-relative phase root.
///
/// The caller supplies no artifact locator: both sibling paths are derived
/// from the closed layout. This pure projection grants no filesystem authority.
///
/// # Errors
///
/// Returns an error if the phase root or either derived path is noncanonical,
/// outside the path bound, or conflicts component-wise.
pub fn project_b4_positive_input_set_publication_paths_v1(
    campaign_relative_phase_root: &str,
) -> Result<B4PositiveInputSetPublicationPathsV1> {
    validate_safe_relative_path(campaign_relative_phase_root)
        .context("invalid campaign-relative H0 phase root")?;
    let layout = B4PositiveInputSetLayoutV1::closed_v1();
    let input_set_path = format!("{campaign_relative_phase_root}/{}", layout.input_set_file());
    let completion_path = format!(
        "{campaign_relative_phase_root}/{}",
        layout.completion_file()
    );
    validate_safe_relative_path(&input_set_path)
        .context("invalid projected positive input-set path")?;
    validate_safe_relative_path(&completion_path)
        .context("invalid projected positive input-set completion path")?;
    ensure!(
        !b4_paths_conflict(&input_set_path, &completion_path),
        "projected positive input-set paths conflict"
    );
    Ok(B4PositiveInputSetPublicationPathsV1 {
        phase_root: campaign_relative_phase_root.to_owned(),
        input_set_path,
        completion_path,
    })
}

#[cfg(any(feature = "positive-gate", test))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Eip0045B4PositiveInputSetCompletionV1 {
    format: String,
    format_version: u8,
    input_set: B4ContractArtifactIdentityV1,
}

#[cfg(any(feature = "positive-gate", test))]
impl Eip0045B4PositiveInputSetCompletionV1 {
    fn for_input_set(input_set: B4ContractArtifactIdentityV1) -> Result<Self> {
        let completion = Self {
            format: COMPLETION_FORMAT.to_owned(),
            format_version: FORMAT_VERSION,
            input_set,
        };
        completion.validate()?;
        Ok(completion)
    }

    fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            (1..=MAX_COMPLETION_BYTES).contains(&source.len()),
            "positive input-set completion is outside its byte bound"
        );
        let value = validate_canonical_json_source(source)
            .context("positive input-set completion is not exact canonical JCS")?;
        let completion: Self = serde_json::from_value(value.clone())
            .context("cannot decode positive input-set completion")?;
        ensure!(
            canonical_json_bytes(&serde_json::to_value(&completion)?)? == source,
            "positive input-set completion does not reserialize byte-exactly"
        );
        completion.validate()?;
        Ok(completion)
    }

    fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let source = canonical_json_bytes(&serde_json::to_value(self)?)?;
        ensure!(
            (1..=MAX_COMPLETION_BYTES).contains(&source.len()),
            "positive input-set completion is outside its byte bound"
        );
        Ok(source)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.format == COMPLETION_FORMAT && self.format_version == FORMAT_VERSION,
            "positive input-set completion format drift"
        );
        self.input_set
            .validate()
            .context("invalid completed positive input-set identity")?;
        ensure!(
            self.input_set.encoding == B4ContractArtifactEncodingV1::Rfc8785Jcs,
            "completed positive input set must use RFC 8785 JCS"
        );
        ensure!(
            self.input_set.byte_length <= MAX_INPUT_SET_BYTES,
            "completed positive input set exceeds its role-specific byte bound"
        );
        Ok(())
    }
}

/// Semantic-only binding between one projected H0 path pair and one positive gate.
///
/// This value is opaque, non-serializable, and cannot be created from detached
/// identities or marker bytes. It still grants no filesystem or mutation
/// authority; a future handler must create and consume it inside the exact
/// retained executor capability which owns the projected layout.
#[cfg(feature = "positive-gate")]
#[derive(Debug)]
pub struct B4PositiveInputSetPublicationBindingV1 {
    paths: B4PositiveInputSetPublicationPathsV1,
    input_set: B4ContractArtifactIdentityV1,
    input_set_jcs: Vec<u8>,
    completion_jcs: Vec<u8>,
}

#[cfg(feature = "positive-gate")]
fn gate_bound_input_and_completion_path(
    paths: &B4PositiveInputSetPublicationPathsV1,
    positive_gate: &PositiveGateBindings,
) -> Result<B4ContractArtifactIdentityV1> {
    let input_set = positive_gate.input_set_contract_identity();
    ensure!(
        input_set.path == paths.input_set_path(),
        "positive input-set path differs from the projected H0 publication"
    );
    let (phase_path, filename) = input_set
        .path
        .rsplit_once('/')
        .context("positive input-set path has no campaign-relative phase root")?;
    ensure!(
        phase_path == paths.phase_root() && filename == POSITIVE_INPUT_SET_FILE,
        "positive input-set path differs from the closed H0 layout"
    );
    let gate_derived_completion = format!("{phase_path}/{POSITIVE_INPUT_SET_COMPLETION_FILE}");
    ensure!(
        gate_derived_completion == paths.completion_path(),
        "positive input-set completion path differs from the projected H0 publication"
    );
    positive_gate.require_nonprovenance_completion_path(paths.completion_path())?;
    Ok(input_set)
}

/// Bind one positive gate to the exact paths retained by an H0 layout projection.
///
/// This is the only public route to canonical completion bytes. The input-set
/// identity retained by the gate and the gate-derived completion sibling must
/// both equal the supplied opaque projection.
///
/// # Errors
///
/// Returns an error for a gate/layout mismatch, provenance conflict, or marker
/// encoding failure.
#[cfg(feature = "positive-gate")]
pub fn bind_b4_positive_input_set_publication(
    paths: &B4PositiveInputSetPublicationPathsV1,
    positive_gate: &PositiveGateBindings,
) -> Result<B4PositiveInputSetPublicationBindingV1> {
    let input_set = gate_bound_input_and_completion_path(paths, positive_gate)?;
    let input_set_jcs = positive_gate.input_set_jcs().to_vec();
    ensure!(
        B4ContractArtifactIdentityV1::from_bytes(
            input_set.path.clone(),
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            &input_set_jcs,
        )? == input_set,
        "retained positive input-set bytes differ from the gate identity"
    );
    let completion_jcs = Eip0045B4PositiveInputSetCompletionV1::for_input_set(input_set.clone())?
        .to_canonical_jcs()?;
    Ok(B4PositiveInputSetPublicationBindingV1 {
        paths: paths.clone(),
        input_set,
        input_set_jcs,
        completion_jcs,
    })
}

#[cfg(feature = "positive-gate")]
impl B4PositiveInputSetPublicationBindingV1 {
    /// Exact canonical input-set bytes retained by the bound positive gate.
    ///
    /// A publication handler can therefore write the authenticated source
    /// directly instead of accepting detached bytes from its caller.
    #[must_use]
    pub fn input_set_jcs(&self) -> &[u8] {
        &self.input_set_jcs
    }

    /// Exact campaign-relative input-set path cross-bound to the positive gate.
    #[must_use]
    pub fn input_set_path(&self) -> &str {
        self.paths.input_set_path()
    }

    /// Exact campaign-relative completion path cross-bound to the positive gate.
    #[must_use]
    pub fn completion_path(&self) -> &str {
        self.paths.completion_path()
    }
}

/// Derive the exact canonical completion witness from one path-bound positive gate.
///
/// The caller cannot supply a detached path, digest, identity, or marker body.
///
/// # Errors
///
/// Returns an error only if the retained semantic binding no longer forms the
/// canonical marker; the binding itself is already gate/path validated.
#[cfg(feature = "positive-gate")]
pub fn derive_b4_positive_input_set_completion_jcs(
    binding: &B4PositiveInputSetPublicationBindingV1,
) -> Result<Vec<u8>> {
    let expected = Eip0045B4PositiveInputSetCompletionV1::for_input_set(binding.input_set.clone())?
        .to_canonical_jcs()?;
    ensure!(
        binding.completion_jcs == expected,
        "retained positive input-set completion binding drift"
    );
    Ok(expected)
}

/// Validate exact completion bytes against one path-bound positive gate.
///
/// This comparison never reconstructs gate or filesystem authority from the
/// marker. A consumer must independently rebuild the positive gate and the
/// descriptor-rooted path binding before calling it.
///
/// # Errors
///
/// Returns an error for noncanonical bytes, format or identity drift, or a
/// marker belonging to any other input-set gate.
#[cfg(feature = "positive-gate")]
pub fn validate_b4_positive_input_set_completion_jcs(
    source: &[u8],
    binding: &B4PositiveInputSetPublicationBindingV1,
) -> Result<()> {
    let parsed = Eip0045B4PositiveInputSetCompletionV1::from_canonical_jcs(source)?;
    let expected = Eip0045B4PositiveInputSetCompletionV1::for_input_set(binding.input_set.clone())?;
    ensure!(
        parsed == expected,
        "positive input-set completion differs from the independently rebuilt gate"
    );
    ensure!(
        source == expected.to_canonical_jcs()?,
        "positive input-set completion bytes differ from the rebuilt witness"
    );
    ensure!(
        source == binding.completion_jcs,
        "positive input-set completion differs from the retained path binding"
    );
    Ok(())
}

/// Closed, non-serializable V2 layout for one H0 input-set publication root.
///
/// V2 deliberately retains the two V1 physical leaf names. The distinct type
/// prevents a V1 projection or mutation capability from being admitted where
/// the V2 publication envelope is required.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct B4PositiveInputSetLayoutV2 {
    _private: (),
}

impl B4PositiveInputSetLayoutV2 {
    /// Return the only admitted V2 layout.
    #[must_use]
    pub const fn closed_v2() -> Self {
        Self { _private: () }
    }

    /// Direct phase-local filename of the canonical V2 positive input set.
    #[must_use]
    pub const fn input_set_file(self) -> &'static str {
        POSITIVE_INPUT_SET_FILE
    }

    /// Direct phase-local filename of the last-written V2 completion witness.
    #[must_use]
    pub const fn completion_file(self) -> &'static str {
        POSITIVE_INPUT_SET_COMPLETION_FILE
    }

    /// Exact V2 write order required before the outer create-only commit.
    #[must_use]
    pub const fn publication_order(self) -> [&'static str; 2] {
        POSITIVE_INPUT_SET_PUBLICATION_ORDER
    }
}

/// Opaque, non-serializable projection of the two campaign-relative V2 paths.
///
/// This pure value grants no filesystem or mutation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct B4PositiveInputSetPublicationPathsV2 {
    phase_root: String,
    input_set_path: String,
    completion_path: String,
}

impl B4PositiveInputSetPublicationPathsV2 {
    /// Campaign-relative H0 phase root from which both V2 paths were derived.
    #[must_use]
    pub fn phase_root(&self) -> &str {
        &self.phase_root
    }

    /// Exact campaign-relative path of the canonical V2 positive input set.
    #[must_use]
    pub fn input_set_path(&self) -> &str {
        &self.input_set_path
    }

    /// Exact campaign-relative path of the last-written V2 completion witness.
    #[must_use]
    pub fn completion_path(&self) -> &str {
        &self.completion_path
    }
}

/// Project the closed V2 H0 paths from one campaign-relative phase root.
///
/// The caller supplies no artifact locator and receives no filesystem
/// authority: both direct sibling paths are derived from the closed layout.
///
/// # Errors
///
/// Returns an error if the phase root or either derived path is noncanonical,
/// outside the path bound, or conflicts component-wise.
pub fn project_b4_positive_input_set_publication_paths_v2(
    campaign_relative_phase_root: &str,
) -> Result<B4PositiveInputSetPublicationPathsV2> {
    validate_safe_relative_path(campaign_relative_phase_root)
        .context("invalid campaign-relative V2 H0 phase root")?;
    let layout = B4PositiveInputSetLayoutV2::closed_v2();
    let input_set_path = format!("{campaign_relative_phase_root}/{}", layout.input_set_file());
    let completion_path = format!(
        "{campaign_relative_phase_root}/{}",
        layout.completion_file()
    );
    validate_safe_relative_path(&input_set_path)
        .context("invalid projected V2 positive input-set path")?;
    validate_safe_relative_path(&completion_path)
        .context("invalid projected V2 positive input-set completion path")?;
    ensure!(
        !b4_paths_conflict(&input_set_path, &completion_path),
        "projected V2 positive input-set paths conflict"
    );
    Ok(B4PositiveInputSetPublicationPathsV2 {
        phase_root: campaign_relative_phase_root.to_owned(),
        input_set_path,
        completion_path,
    })
}

#[cfg(any(feature = "positive-gate", test))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Eip0045B4PositiveInputSetCompletionV2 {
    format: String,
    format_version: u8,
    input_set: B4ContractArtifactIdentityV1,
}

#[cfg(any(feature = "positive-gate", test))]
impl Eip0045B4PositiveInputSetCompletionV2 {
    fn for_input_set(input_set: B4ContractArtifactIdentityV1) -> Result<Self> {
        let completion = Self {
            format: COMPLETION_FORMAT_V2.to_owned(),
            format_version: FORMAT_VERSION_V2,
            input_set,
        };
        completion.validate()?;
        Ok(completion)
    }

    fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            (1..=MAX_COMPLETION_BYTES).contains(&source.len()),
            "V2 positive input-set completion is outside its byte bound"
        );
        let value = validate_canonical_json_source(source)
            .context("V2 positive input-set completion is not exact canonical JCS")?;
        let completion: Self = serde_json::from_value(value.clone())
            .context("cannot decode V2 positive input-set completion")?;
        ensure!(
            canonical_json_bytes(&serde_json::to_value(&completion)?)? == source,
            "V2 positive input-set completion does not reserialize byte-exactly"
        );
        completion.validate()?;
        Ok(completion)
    }

    fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let source = canonical_json_bytes(&serde_json::to_value(self)?)?;
        ensure!(
            (1..=MAX_COMPLETION_BYTES).contains(&source.len()),
            "V2 positive input-set completion is outside its byte bound"
        );
        Ok(source)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.format == COMPLETION_FORMAT_V2 && self.format_version == FORMAT_VERSION_V2,
            "V2 positive input-set completion format drift"
        );
        self.input_set
            .validate()
            .context("invalid completed V2 positive input-set identity")?;
        ensure!(
            self.input_set.encoding == B4ContractArtifactEncodingV1::Rfc8785Jcs,
            "completed V2 positive input set must use RFC 8785 JCS"
        );
        ensure!(
            self.input_set.byte_length <= MAX_INPUT_SET_BYTES,
            "completed V2 positive input set exceeds its role-specific byte bound"
        );
        let (phase_root, filename) = self
            .input_set
            .path
            .rsplit_once('/')
            .context("completed V2 positive input-set path has no phase root")?;
        validate_safe_relative_path(phase_root)
            .context("invalid completed V2 positive input-set phase root")?;
        ensure!(
            filename == POSITIVE_INPUT_SET_FILE,
            "completed V2 positive input-set path has the wrong leaf name"
        );
        Ok(())
    }
}

/// Pure binding of canonical V2 input bytes to one closed path projection.
///
/// This value is opaque and non-serializable. It authenticates no filesystem
/// object, grants no mutation authority, and cannot construct the affine V2
/// publication source.
#[cfg(feature = "positive-gate")]
#[derive(Debug)]
pub struct B4PositiveInputSetPublicationBindingV2 {
    paths: B4PositiveInputSetPublicationPathsV2,
    input_set: B4ContractArtifactIdentityV1,
    input_set_jcs: Vec<u8>,
    completion_jcs: Vec<u8>,
}

#[cfg(feature = "positive-gate")]
fn validate_v2_publication_paths(paths: &B4PositiveInputSetPublicationPathsV2) -> Result<()> {
    validate_safe_relative_path(paths.phase_root()).context("invalid retained V2 H0 phase root")?;
    let layout = B4PositiveInputSetLayoutV2::closed_v2();
    let expected_input_set = format!("{}/{}", paths.phase_root(), layout.input_set_file());
    let expected_completion = format!("{}/{}", paths.phase_root(), layout.completion_file());
    ensure!(
        paths.input_set_path() == expected_input_set,
        "V2 positive input-set path differs from the closed layout"
    );
    ensure!(
        paths.completion_path() == expected_completion,
        "V2 positive input-set completion path differs from the closed layout"
    );
    validate_safe_relative_path(paths.input_set_path())
        .context("invalid retained V2 positive input-set path")?;
    validate_safe_relative_path(paths.completion_path())
        .context("invalid retained V2 positive input-set completion path")?;
    ensure!(
        !b4_paths_conflict(paths.input_set_path(), paths.completion_path()),
        "retained V2 positive input-set paths conflict"
    );
    Ok(())
}

#[cfg(feature = "positive-gate")]
fn derive_v2_input_set_identity(
    paths: &B4PositiveInputSetPublicationPathsV2,
    source: &[u8],
) -> Result<B4ContractArtifactIdentityV1> {
    validate_v2_publication_paths(paths)?;
    ensure!(
        !source.is_empty(),
        "canonical V2 positive input set is empty"
    );
    let byte_length =
        u64::try_from(source.len()).context("V2 positive input-set length does not fit u64")?;
    ensure!(
        byte_length <= MAX_INPUT_SET_BYTES,
        "canonical V2 positive input set exceeds its role-specific byte bound"
    );
    let value = validate_canonical_json_source(source)
        .context("V2 positive input set is not exact canonical JCS")?;
    let root = value
        .as_object()
        .context("V2 positive input set root must be an object")?;
    ensure!(
        root.get("format").and_then(serde_json::Value::as_str) == Some(INPUT_SET_FORMAT_V2),
        "V2 positive input-set format drift"
    );
    ensure!(
        root.get("formatVersion")
            .and_then(serde_json::Value::as_u64)
            == Some(u64::from(FORMAT_VERSION_V2)),
        "V2 positive input-set format version drift"
    );
    let identity = B4ContractArtifactIdentityV1::from_bytes(
        paths.input_set_path().to_owned(),
        B4ContractArtifactEncodingV1::Rfc8785Jcs,
        source,
    )?;
    ensure!(
        identity.path == paths.input_set_path()
            && identity.byte_length == byte_length
            && identity.encoding == B4ContractArtifactEncodingV1::Rfc8785Jcs,
        "derived V2 positive input-set identity differs from its exact source"
    );
    Ok(identity)
}

/// Bind exact canonical V2 input-set bytes to one closed path projection.
///
/// The binder is pure and inert. It validates the source bound, canonical JCS,
/// exact V2 discriminator, closed path recomposition, and independently
/// derives the pathful identity and completion witness.
///
/// # Errors
///
/// Returns an error for source, discriminator, path, identity, or completion
/// drift. Success grants no filesystem or publication authority.
#[cfg(feature = "positive-gate")]
pub fn bind_b4_positive_input_set_publication_v2(
    paths: &B4PositiveInputSetPublicationPathsV2,
    input_set_jcs: &[u8],
) -> Result<B4PositiveInputSetPublicationBindingV2> {
    let input_set = derive_v2_input_set_identity(paths, input_set_jcs)?;
    let completion_jcs = Eip0045B4PositiveInputSetCompletionV2::for_input_set(input_set.clone())?
        .to_canonical_jcs()?;
    Ok(B4PositiveInputSetPublicationBindingV2 {
        paths: paths.clone(),
        input_set,
        input_set_jcs: input_set_jcs.to_vec(),
        completion_jcs,
    })
}

#[cfg(feature = "positive-gate")]
impl B4PositiveInputSetPublicationBindingV2 {
    /// Exact canonical V2 input-set bytes retained by this inert binding.
    #[must_use]
    pub fn input_set_jcs(&self) -> &[u8] {
        &self.input_set_jcs
    }

    /// Exact campaign-relative V2 input-set path retained by this binding.
    #[must_use]
    pub fn input_set_path(&self) -> &str {
        self.paths.input_set_path()
    }

    /// Exact campaign-relative V2 completion path retained by this binding.
    #[must_use]
    pub fn completion_path(&self) -> &str {
        self.paths.completion_path()
    }
}

/// Independently rederive the exact V2 completion witness retained by a binding.
///
/// # Errors
///
/// Returns an error if the retained source, identity, paths, or completion
/// bytes differ from their independent derivation.
#[cfg(feature = "positive-gate")]
pub fn derive_b4_positive_input_set_completion_jcs_v2(
    binding: &B4PositiveInputSetPublicationBindingV2,
) -> Result<Vec<u8>> {
    let input_set = derive_v2_input_set_identity(&binding.paths, &binding.input_set_jcs)?;
    ensure!(
        input_set == binding.input_set,
        "retained V2 positive input-set identity drift"
    );
    let expected =
        Eip0045B4PositiveInputSetCompletionV2::for_input_set(input_set)?.to_canonical_jcs()?;
    ensure!(
        binding.completion_jcs == expected,
        "retained V2 positive input-set completion binding drift"
    );
    Ok(expected)
}

/// Opaque proof that exact V2 completion bytes matched one path-bound input set.
///
/// This value is non-serializable and cannot be constructed from a detached
/// path or identity. Consuming it preserves the causal edge from validated H0
/// completion bytes to the exact completion path retained by later stages.
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_campaign_contract::B4ContractArtifactIdentityV1;
/// use eip_0045_reproduction::b4_positive_input_set::B4ValidatedPositiveInputSetCompletionV2;
/// fn forge(input_set: B4ContractArtifactIdentityV1) -> B4ValidatedPositiveInputSetCompletionV2 {
///     B4ValidatedPositiveInputSetCompletionV2 {
///         input_set,
///         completion_path: "detached/completion.json".to_owned(),
///     }
/// }
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_positive_input_set::B4ValidatedPositiveInputSetCompletionV2;
/// fn require_clone<T: Clone>() {}
/// require_clone::<B4ValidatedPositiveInputSetCompletionV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_positive_input_set::B4ValidatedPositiveInputSetCompletionV2;
/// fn require_copy<T: Copy>() {}
/// require_copy::<B4ValidatedPositiveInputSetCompletionV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_positive_input_set::B4ValidatedPositiveInputSetCompletionV2;
/// fn require_default<T: Default>() {}
/// require_default::<B4ValidatedPositiveInputSetCompletionV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_positive_input_set::B4ValidatedPositiveInputSetCompletionV2;
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<B4ValidatedPositiveInputSetCompletionV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_positive_input_set::B4ValidatedPositiveInputSetCompletionV2;
/// fn require_deserialize<T: for<'de> serde::Deserialize<'de>>() {}
/// require_deserialize::<B4ValidatedPositiveInputSetCompletionV2>();
/// ```
#[derive(Debug)]
pub struct B4ValidatedPositiveInputSetCompletionV2 {
    input_set: B4ContractArtifactIdentityV1,
    completion_path: String,
}

impl B4ValidatedPositiveInputSetCompletionV2 {
    /// Exact campaign-relative completion path whose bytes were validated.
    #[must_use]
    pub fn completion_path(&self) -> &str {
        &self.completion_path
    }

    pub(crate) fn input_set_identity(&self) -> &B4ContractArtifactIdentityV1 {
        &self.input_set
    }
}

/// Validate exact V2 completion bytes against one inert publication binding.
///
/// This comparison does not reconstruct positive-gate, filesystem, mutation,
/// provider, or session authority from the serialized witness.
///
/// # Errors
///
/// Returns an error for noncanonical bytes, V1 substitution, format drift, or
/// any pathful input-set identity mismatch.
#[cfg(feature = "positive-gate")]
pub fn validate_b4_positive_input_set_completion_jcs_v2(
    source: &[u8],
    binding: &B4PositiveInputSetPublicationBindingV2,
) -> Result<B4ValidatedPositiveInputSetCompletionV2> {
    let parsed = Eip0045B4PositiveInputSetCompletionV2::from_canonical_jcs(source)?;
    let input_set = derive_v2_input_set_identity(&binding.paths, &binding.input_set_jcs)?;
    ensure!(
        input_set == binding.input_set,
        "retained V2 positive input-set identity drift"
    );
    let expected = Eip0045B4PositiveInputSetCompletionV2::for_input_set(input_set.clone())?;
    ensure!(
        parsed == expected,
        "V2 positive input-set completion differs from the independently rebuilt binding"
    );
    ensure!(
        source == expected.to_canonical_jcs()?,
        "V2 positive input-set completion bytes differ from the rebuilt witness"
    );
    ensure!(
        source == binding.completion_jcs,
        "V2 positive input-set completion differs from the retained path binding"
    );
    Ok(B4ValidatedPositiveInputSetCompletionV2 {
        input_set,
        completion_path: binding.completion_path().to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::canonical_json_bytes;
    use serde_json::json;
    use sha2::Digest as _;

    fn input_identity(bytes: &[u8]) -> B4ContractArtifactIdentityV1 {
        B4ContractArtifactIdentityV1::from_bytes(
            "phases/prepare-001/positive-input-set.json",
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            bytes,
        )
        .unwrap()
    }

    #[cfg(feature = "positive-gate")]
    fn positive_input_set_v2_source() -> Vec<u8> {
        canonical_json_bytes(&json!({
            "format": "Eip0045B4PositiveInputSetV2",
            "formatVersion": 2,
        }))
        .unwrap()
    }

    #[cfg(feature = "positive-gate")]
    fn positive_input_set_v2_binding(source: &[u8]) -> B4PositiveInputSetPublicationBindingV2 {
        let paths =
            project_b4_positive_input_set_publication_paths_v2("phases/prepare-001").unwrap();
        bind_b4_positive_input_set_publication_v2(&paths, source).unwrap()
    }

    #[cfg(feature = "positive-gate")]
    fn assert_v2_rejected_at<T>(result: anyhow::Result<T>, expected_boundary: &str, label: &str) {
        let Err(error) = result else {
            panic!("{label} unexpectedly passed")
        };
        assert!(
            format!("{error:#}").contains(expected_boundary),
            "{label} reached the wrong V2 boundary: {error:#}"
        );
    }

    #[cfg(feature = "positive-gate")]
    #[test]
    fn positive_input_set_v2_closed_layout_fixes_v1_leaf_names_and_order() {
        let layout = B4PositiveInputSetLayoutV2::closed_v2();
        assert_eq!(
            layout.publication_order(),
            [
                "positive-input-set.json",
                "positive-input-set-completion.json"
            ]
        );
        assert_eq!(layout.input_set_file(), layout.publication_order()[0]);
        assert_eq!(layout.completion_file(), layout.publication_order()[1]);

        let paths =
            project_b4_positive_input_set_publication_paths_v2("phases/prepare-001").unwrap();
        assert_eq!(paths.phase_root(), "phases/prepare-001");
        assert_eq!(
            paths.input_set_path(),
            "phases/prepare-001/positive-input-set.json"
        );
        assert_eq!(
            paths.completion_path(),
            "phases/prepare-001/positive-input-set-completion.json"
        );
    }

    #[cfg(feature = "positive-gate")]
    #[test]
    fn positive_input_set_v2_completion_is_exact_clone_v1_shape_with_derived_identity() {
        let input = positive_input_set_v2_source();
        let binding = positive_input_set_v2_binding(&input);
        let source = derive_b4_positive_input_set_completion_jcs_v2(&binding).unwrap();

        assert_eq!(
            source,
            format!(
                "{{\"format\":\"Eip0045B4PositiveInputSetCompletionV2\",\"formatVersion\":2,\"inputSet\":{{\"byteLength\":{},\"encoding\":\"rfc8785-jcs\",\"path\":\"phases/prepare-001/positive-input-set.json\",\"sha256\":\"{}\"}}}}",
                input.len(),
                hex::encode(sha2::Sha256::digest(&input))
            )
            .into_bytes()
        );
        let parsed = Eip0045B4PositiveInputSetCompletionV2::from_canonical_jcs(&source).unwrap();
        assert_eq!(parsed.to_canonical_jcs().unwrap(), source);
        validate_b4_positive_input_set_completion_jcs_v2(&source, &binding).unwrap();
    }

    #[cfg(feature = "positive-gate")]
    #[test]
    fn positive_input_set_v2_rejects_root_shape_and_header_drift() {
        let input = positive_input_set_v2_source();
        let binding = positive_input_set_v2_binding(&input);
        let source = derive_b4_positive_input_set_completion_jcs_v2(&binding).unwrap();
        let original = validate_canonical_json_source(&source).unwrap();

        for (field, replacement, expected_boundary) in [
            (
                "format",
                json!("eip0045B4PositiveInputSetCompletionV2"),
                "V2 positive input-set completion format drift",
            ),
            (
                "formatVersion",
                json!(1),
                "V2 positive input-set completion format drift",
            ),
        ] {
            let mut drifted = original.clone();
            drifted[field] = replacement;
            assert_v2_rejected_at(
                validate_b4_positive_input_set_completion_jcs_v2(
                    &canonical_json_bytes(&drifted).unwrap(),
                    &binding,
                ),
                expected_boundary,
                &format!("root field {field} drift"),
            );
        }

        let mut unknown = original.clone();
        unknown["status"] = json!("complete");
        assert_v2_rejected_at(
            validate_b4_positive_input_set_completion_jcs_v2(
                &canonical_json_bytes(&unknown).unwrap(),
                &binding,
            ),
            "unknown field `status`",
            "unknown completion root field",
        );

        let mut missing = original;
        missing.as_object_mut().unwrap().remove("inputSet");
        assert_v2_rejected_at(
            validate_b4_positive_input_set_completion_jcs_v2(
                &canonical_json_bytes(&missing).unwrap(),
                &binding,
            ),
            "missing field `inputSet`",
            "missing completion inputSet field",
        );
    }

    #[cfg(feature = "positive-gate")]
    #[test]
    fn positive_input_set_v2_completion_parser_rejects_bounds_and_noncanonical_json() {
        let input = positive_input_set_v2_source();
        let binding = positive_input_set_v2_binding(&input);
        let source = derive_b4_positive_input_set_completion_jcs_v2(&binding).unwrap();

        assert_v2_rejected_at(
            Eip0045B4PositiveInputSetCompletionV2::from_canonical_jcs(&[]),
            "V2 positive input-set completion is outside its byte bound",
            "empty completion",
        );
        assert_v2_rejected_at(
            Eip0045B4PositiveInputSetCompletionV2::from_canonical_jcs(&vec![
                b'x';
                MAX_COMPLETION_BYTES
                    + 1
            ]),
            "V2 positive input-set completion is outside its byte bound",
            "oversized completion",
        );

        let text = String::from_utf8(source.clone()).unwrap();
        let root_needle = format!("\"format\":\"{COMPLETION_FORMAT_V2}\"");
        let duplicate_root =
            text.replacen(&root_needle, &format!("{root_needle},{root_needle}"), 1);
        assert_ne!(duplicate_root, text, "duplicate-root fixture must mutate");
        assert_v2_rejected_at(
            Eip0045B4PositiveInputSetCompletionV2::from_canonical_jcs(duplicate_root.as_bytes()),
            "duplicate object key: \"format\"",
            "duplicate completion root field",
        );

        let original = validate_canonical_json_source(&source).unwrap();
        let sha256 = original["inputSet"]["sha256"].as_str().unwrap();
        let nested_needle = format!("\"sha256\":\"{sha256}\"");
        let duplicate_nested = text.replacen(
            &nested_needle,
            &format!("{nested_needle},{nested_needle}"),
            1,
        );
        assert_ne!(
            duplicate_nested, text,
            "duplicate-nested fixture must mutate"
        );
        assert_v2_rejected_at(
            Eip0045B4PositiveInputSetCompletionV2::from_canonical_jcs(duplicate_nested.as_bytes()),
            "duplicate object key: \"sha256\"",
            "duplicate nested input-set identity field",
        );

        let mut leading_whitespace = vec![b' '];
        leading_whitespace.extend_from_slice(&source);
        let mut trailing_whitespace = source.clone();
        trailing_whitespace.push(b' ');
        for (label, noncanonical) in [
            ("leading completion whitespace", leading_whitespace),
            ("trailing completion whitespace", trailing_whitespace),
        ] {
            assert_v2_rejected_at(
                Eip0045B4PositiveInputSetCompletionV2::from_canonical_jcs(&noncanonical),
                "JSON source is not the exact RFC 8785 canonical encoding",
                label,
            );
        }

        let mut trailing_json = source;
        trailing_json.extend_from_slice(b"{}");
        assert_v2_rejected_at(
            Eip0045B4PositiveInputSetCompletionV2::from_canonical_jcs(&trailing_json),
            "unexpected data after the JSON value",
            "trailing completion JSON value",
        );
    }

    #[cfg(feature = "positive-gate")]
    #[test]
    fn positive_input_set_v2_completion_parser_rejects_each_missing_or_mistyped_root_field() {
        let input = positive_input_set_v2_source();
        let binding = positive_input_set_v2_binding(&input);
        let source = derive_b4_positive_input_set_completion_jcs_v2(&binding).unwrap();
        let original = validate_canonical_json_source(&source).unwrap();

        for field in ["format", "formatVersion", "inputSet"] {
            let mut missing = original.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert_v2_rejected_at(
                Eip0045B4PositiveInputSetCompletionV2::from_canonical_jcs(
                    &canonical_json_bytes(&missing).unwrap(),
                ),
                &format!("missing field `{field}`"),
                &format!("missing completion root field {field}"),
            );
        }

        for (field, replacement) in [
            ("format", json!(false)),
            ("formatVersion", json!("2")),
            ("inputSet", json!(false)),
        ] {
            let mut mistyped = original.clone();
            mistyped[field] = replacement;
            assert_v2_rejected_at(
                Eip0045B4PositiveInputSetCompletionV2::from_canonical_jcs(
                    &canonical_json_bytes(&mistyped).unwrap(),
                ),
                "invalid type",
                &format!("mistyped completion root field {field}"),
            );
        }
    }

    #[cfg(feature = "positive-gate")]
    #[test]
    fn positive_input_set_v2_rejects_each_derived_input_identity_drift() {
        let input = positive_input_set_v2_source();
        let binding = positive_input_set_v2_binding(&input);
        let source = derive_b4_positive_input_set_completion_jcs_v2(&binding).unwrap();
        let original = validate_canonical_json_source(&source).unwrap();

        for (field, replacement, expected_boundary) in [
            (
                "path",
                json!("phases/prepare-002/positive-input-set.json"),
                "V2 positive input-set completion differs from the independently rebuilt binding",
            ),
            (
                "byteLength",
                json!(input.len() + 1),
                "V2 positive input-set completion differs from the independently rebuilt binding",
            ),
            (
                "sha256",
                json!("01".repeat(32)),
                "V2 positive input-set completion differs from the independently rebuilt binding",
            ),
            (
                "encoding",
                json!("raw-bytes"),
                "completed V2 positive input set must use RFC 8785 JCS",
            ),
        ] {
            let mut drifted = original.clone();
            drifted["inputSet"][field] = replacement;
            assert_v2_rejected_at(
                validate_b4_positive_input_set_completion_jcs_v2(
                    &canonical_json_bytes(&drifted).unwrap(),
                    &binding,
                ),
                expected_boundary,
                &format!("input-set identity field {field} drift"),
            );
        }
    }

    #[cfg(feature = "positive-gate")]
    #[test]
    fn positive_input_set_v2_binder_rejects_bounds_canonicality_and_isolated_headers() {
        let paths =
            project_b4_positive_input_set_publication_paths_v2("phases/prepare-001").unwrap();

        assert_v2_rejected_at(
            bind_b4_positive_input_set_publication_v2(&paths, &[]),
            "canonical V2 positive input set is empty",
            "empty V2 input set",
        );
        let oversized = vec![b'x'; usize::try_from(MAX_INPUT_SET_BYTES).unwrap() + 1];
        assert_v2_rejected_at(
            bind_b4_positive_input_set_publication_v2(&paths, &oversized),
            "canonical V2 positive input set exceeds its role-specific byte bound",
            "oversized V2 input set",
        );

        let canonical = positive_input_set_v2_source();
        let mut newline = canonical.clone();
        newline.push(b'\n');
        let mut bom = vec![0xef, 0xbb, 0xbf];
        bom.extend_from_slice(&canonical);
        let mut trailing_json = canonical;
        trailing_json.extend_from_slice(b"{}");
        for (label, noncanonical) in [
            ("newline-terminated V2 input set", newline),
            ("BOM-prefixed V2 input set", bom),
            ("trailing V2 input-set JSON value", trailing_json),
        ] {
            assert_v2_rejected_at(
                bind_b4_positive_input_set_publication_v2(&paths, &noncanonical),
                "V2 positive input set is not exact canonical JCS",
                label,
            );
        }

        let original = validate_canonical_json_source(&positive_input_set_v2_source()).unwrap();
        let mut format_drift = original.clone();
        format_drift["format"] = json!("Eip0045B4PositiveInputSetV1");
        assert_v2_rejected_at(
            bind_b4_positive_input_set_publication_v2(
                &paths,
                &canonical_json_bytes(&format_drift).unwrap(),
            ),
            "V2 positive input-set format drift",
            "isolated V2 input-set format drift",
        );

        let mut version_drift = original;
        version_drift["formatVersion"] = json!(1);
        assert_v2_rejected_at(
            bind_b4_positive_input_set_publication_v2(
                &paths,
                &canonical_json_bytes(&version_drift).unwrap(),
            ),
            "V2 positive input-set format version drift",
            "isolated V2 input-set format-version drift",
        );
    }

    #[cfg(feature = "positive-gate")]
    #[test]
    fn positive_input_set_v2_binding_rejects_equal_length_source_mutation_as_stale_identity() {
        let original = canonical_json_bytes(&json!({
            "format": INPUT_SET_FORMAT_V2,
            "formatVersion": FORMAT_VERSION_V2,
            "nonce": "aa",
        }))
        .unwrap();
        let mutated = canonical_json_bytes(&json!({
            "format": INPUT_SET_FORMAT_V2,
            "formatVersion": FORMAT_VERSION_V2,
            "nonce": "bb",
        }))
        .unwrap();
        assert_eq!(original.len(), mutated.len());
        assert_ne!(original, mutated);

        let mut binding = positive_input_set_v2_binding(&original);
        binding.input_set_jcs = mutated;
        assert_v2_rejected_at(
            derive_b4_positive_input_set_completion_jcs_v2(&binding),
            "retained V2 positive input-set identity drift",
            "equal-length retained V2 source mutation",
        );
    }

    #[cfg(feature = "positive-gate")]
    #[test]
    fn positive_input_set_v2_projection_rejects_invalid_overlong_and_tampered_paths() {
        for invalid_root in [
            "",
            "/absolute",
            "../phase",
            "phases//prepare-001",
            "phases/./prepare-001",
            "phases\\prepare-001",
            "phases/con",
        ] {
            assert_v2_rejected_at(
                project_b4_positive_input_set_publication_paths_v2(invalid_root),
                "invalid campaign-relative V2 H0 phase root",
                &format!("invalid V2 phase root {invalid_root:?}"),
            );
        }

        let overlong_after_projection = "a".repeat(220);
        validate_safe_relative_path(&overlong_after_projection).unwrap();
        assert_v2_rejected_at(
            project_b4_positive_input_set_publication_paths_v2(&overlong_after_projection),
            "invalid projected V2 positive input-set path",
            "V2 phase root leaving no room for the closed input filename",
        );

        let source = positive_input_set_v2_source();
        let projected =
            project_b4_positive_input_set_publication_paths_v2("phases/prepare-001").unwrap();

        let mut alternate_leaf = projected.clone();
        alternate_leaf.input_set_path = "phases/prepare-001/alternate.json".to_owned();
        assert_v2_rejected_at(
            bind_b4_positive_input_set_publication_v2(&alternate_leaf, &source),
            "V2 positive input-set path differs from the closed layout",
            "alternate private V2 input-set leaf",
        );

        let mut nested_leaf = projected.clone();
        nested_leaf.completion_path =
            "phases/prepare-001/nested/positive-input-set-completion.json".to_owned();
        assert_v2_rejected_at(
            bind_b4_positive_input_set_publication_v2(&nested_leaf, &source),
            "V2 positive input-set completion path differs from the closed layout",
            "nested private V2 completion leaf",
        );

        let mut conflicting = projected;
        conflicting.completion_path = conflicting.input_set_path.clone();
        assert!(b4_paths_conflict(
            conflicting.input_set_path(),
            conflicting.completion_path()
        ));
        assert_v2_rejected_at(
            bind_b4_positive_input_set_publication_v2(&conflicting, &source),
            "V2 positive input-set completion path differs from the closed layout",
            "conflicting private V2 paths",
        );
    }

    #[cfg(feature = "positive-gate")]
    #[test]
    fn positive_input_set_v2_rejects_noncanonical_and_v1_completion_substitution() {
        let input = positive_input_set_v2_source();
        let binding = positive_input_set_v2_binding(&input);
        let source = derive_b4_positive_input_set_completion_jcs_v2(&binding).unwrap();

        let mut newline = source.clone();
        newline.push(b'\n');
        let mut bom = vec![0xef, 0xbb, 0xbf];
        bom.extend_from_slice(&source);
        for noncanonical in [newline, bom] {
            assert_v2_rejected_at(
                validate_b4_positive_input_set_completion_jcs_v2(&noncanonical, &binding),
                "V2 positive input-set completion is not exact canonical JCS",
                "noncanonical V2 completion substitution",
            );
        }

        let v1_completion =
            Eip0045B4PositiveInputSetCompletionV1::for_input_set(input_identity(&input))
                .unwrap()
                .to_canonical_jcs()
                .unwrap();
        assert_v2_rejected_at(
            validate_b4_positive_input_set_completion_jcs_v2(&v1_completion, &binding),
            "V2 positive input-set completion format drift",
            "V1 completion substitution",
        );
    }

    #[cfg(feature = "positive-gate")]
    #[test]
    fn positive_input_set_v2_rejects_v1_input_with_freshly_recomputed_identity() {
        let v1_input = canonical_json_bytes(&json!({
            "format": "Eip0045B4PositiveInputSetV1",
            "formatVersion": 1,
        }))
        .unwrap();
        input_identity(&v1_input).validate().unwrap();

        let paths =
            project_b4_positive_input_set_publication_paths_v2("phases/prepare-001").unwrap();
        assert_v2_rejected_at(
            bind_b4_positive_input_set_publication_v2(&paths, &v1_input),
            "V2 positive input-set format drift",
            "V1 input with recomputed identity",
        );
    }

    #[cfg(feature = "positive-gate")]
    #[test]
    fn positive_input_set_v2_completion_remains_rejected_by_v1_codec() {
        let input = positive_input_set_v2_source();
        let binding = positive_input_set_v2_binding(&input);
        let source = derive_b4_positive_input_set_completion_jcs_v2(&binding).unwrap();

        let error = Eip0045B4PositiveInputSetCompletionV1::from_canonical_jcs(&source)
            .expect_err("V2 completion unexpectedly passed the V1 codec");
        assert!(
            format!("{error:#}").contains("positive input-set completion format drift"),
            "V2 completion reached the wrong V1 boundary: {error:#}"
        );
    }

    #[test]
    fn closed_layout_fixes_two_safe_nonconflicting_direct_files() {
        let layout = B4PositiveInputSetLayoutV1::closed_v1();
        assert_eq!(
            layout.publication_order(),
            [
                "positive-input-set.json",
                "positive-input-set-completion.json"
            ]
        );
        assert_eq!(layout.input_set_file(), layout.publication_order()[0]);
        assert_eq!(layout.completion_file(), layout.publication_order()[1]);
        for path in layout.publication_order() {
            validate_safe_relative_path(path).unwrap();
            assert!(!path.contains('/'));
        }
        assert!(!b4_paths_conflict(
            layout.input_set_file(),
            layout.completion_file()
        ));
    }

    #[test]
    fn publication_path_projection_rejects_noncanonical_or_overlong_phase_roots() {
        for invalid_root in [
            "",
            "/absolute",
            "../phase",
            "phases//prepare-001",
            "phases/./prepare-001",
            "phases\\prepare-001",
            "phases/con",
            "phases/con.txt",
            "phases/com1",
            "phases/lpt9",
        ] {
            assert!(
                project_b4_positive_input_set_publication_paths_v1(invalid_root).is_err(),
                "{invalid_root:?} unexpectedly projected"
            );
        }

        let root_with_no_room_for_closed_filenames = "a".repeat(220);
        assert!(
            validate_safe_relative_path(&root_with_no_room_for_closed_filenames).is_ok(),
            "test precondition: the root itself must fit"
        );
        assert!(project_b4_positive_input_set_publication_paths_v1(
            &root_with_no_room_for_closed_filenames
        )
        .is_err());
    }

    #[test]
    fn completion_codec_is_exact_canonical_jcs_with_a_pathful_input_identity() {
        let input = canonical_json_bytes(&json!({"format": "test"})).unwrap();
        let completion =
            Eip0045B4PositiveInputSetCompletionV1::for_input_set(input_identity(&input)).unwrap();
        let source = completion.to_canonical_jcs().unwrap();

        assert_eq!(
            Eip0045B4PositiveInputSetCompletionV1::from_canonical_jcs(&source).unwrap(),
            completion
        );
        assert_eq!(
            source,
            format!(
                "{{\"format\":\"{COMPLETION_FORMAT}\",\"formatVersion\":1,\"inputSet\":{{\"byteLength\":{},\"encoding\":\"rfc8785-jcs\",\"path\":\"phases/prepare-001/positive-input-set.json\",\"sha256\":\"{}\"}}}}",
                input.len(),
                hex::encode(sha2::Sha256::digest(&input))
            )
            .into_bytes()
        );
    }

    #[test]
    fn completion_codec_rejects_format_encoding_shape_and_canonicality_drift() {
        let input = canonical_json_bytes(&json!({"format": "test"})).unwrap();
        let source = Eip0045B4PositiveInputSetCompletionV1::for_input_set(input_identity(&input))
            .unwrap()
            .to_canonical_jcs()
            .unwrap();
        let original = validate_canonical_json_source(&source).unwrap();

        let mutations = [
            ("format", json!("Eip0045B4PositiveInputSetCompletionV2")),
            ("formatVersion", json!(2)),
        ];
        for (field, replacement) in mutations {
            let mut value = original.clone();
            value[field] = replacement;
            let mutated = canonical_json_bytes(&value).unwrap();
            assert!(Eip0045B4PositiveInputSetCompletionV1::from_canonical_jcs(&mutated).is_err());
        }

        for (field, replacement) in [
            ("encoding", json!("raw-bytes")),
            ("path", json!("../positive-input-set.json")),
            ("byteLength", json!(0)),
            ("sha256", json!("00")),
        ] {
            let mut value = original.clone();
            value["inputSet"][field] = replacement;
            let mutated = canonical_json_bytes(&value).unwrap();
            assert!(
                Eip0045B4PositiveInputSetCompletionV1::from_canonical_jcs(&mutated).is_err(),
                "{field} mutation unexpectedly passed"
            );
        }

        for invalid_path in [
            "/phases/prepare-001/positive-input-set.json",
            "phases//prepare-001/positive-input-set.json",
            "phases/./positive-input-set.json",
            "phases\\prepare-001\\positive-input-set.json",
            "phases/con/positive-input-set.json",
            "phases/con.txt/positive-input-set.json",
            "phases/com1/positive-input-set.json",
            "phases/lpt9/positive-input-set.json",
        ] {
            let mut value = original.clone();
            value["inputSet"]["path"] = json!(invalid_path);
            assert!(
                Eip0045B4PositiveInputSetCompletionV1::from_canonical_jcs(
                    &canonical_json_bytes(&value).unwrap()
                )
                .is_err(),
                "{invalid_path:?} unexpectedly passed"
            );
        }

        let mut oversized_input = original.clone();
        oversized_input["inputSet"]["byteLength"] = json!(MAX_INPUT_SET_BYTES + 1);
        assert!(Eip0045B4PositiveInputSetCompletionV1::from_canonical_jcs(
            &canonical_json_bytes(&oversized_input).unwrap()
        )
        .is_err());

        let mut maximum_input = original.clone();
        maximum_input["inputSet"]["byteLength"] = json!(MAX_INPUT_SET_BYTES);
        assert!(Eip0045B4PositiveInputSetCompletionV1::from_canonical_jcs(
            &canonical_json_bytes(&maximum_input).unwrap()
        )
        .is_ok());

        let mut inner_unknown = original.clone();
        inner_unknown["inputSet"]["unexpected"] = json!(true);
        assert!(Eip0045B4PositiveInputSetCompletionV1::from_canonical_jcs(
            &canonical_json_bytes(&inner_unknown).unwrap()
        )
        .is_err());

        let mut inner_missing = original.clone();
        inner_missing["inputSet"]
            .as_object_mut()
            .unwrap()
            .remove("sha256");
        assert!(Eip0045B4PositiveInputSetCompletionV1::from_canonical_jcs(
            &canonical_json_bytes(&inner_missing).unwrap()
        )
        .is_err());

        let mut inner_type_drift = original.clone();
        inner_type_drift["inputSet"]["byteLength"] = json!("1");
        assert!(Eip0045B4PositiveInputSetCompletionV1::from_canonical_jcs(
            &canonical_json_bytes(&inner_type_drift).unwrap()
        )
        .is_err());

        let mut extra = original;
        extra["status"] = json!("complete");
        assert!(Eip0045B4PositiveInputSetCompletionV1::from_canonical_jcs(
            &canonical_json_bytes(&extra).unwrap()
        )
        .is_err());

        let mut noncanonical = source;
        noncanonical.push(b'\n');
        assert!(Eip0045B4PositiveInputSetCompletionV1::from_canonical_jcs(&noncanonical).is_err());
        assert!(Eip0045B4PositiveInputSetCompletionV1::from_canonical_jcs(&[]).is_err());
        assert!(
            Eip0045B4PositiveInputSetCompletionV1::from_canonical_jcs(&vec![
                b' ';
                MAX_COMPLETION_BYTES
                    + 1
            ])
            .is_err()
        );
    }

    #[test]
    fn validated_v2_completion_token_surface_remains_affine_private_and_feature_independent() {
        fn oracle(source: &str) -> bool {
            let marker = "pub struct B4ValidatedPositiveInputSetCompletionV2 {";
            let Some((prefix, suffix)) = source.split_once(marker) else {
                return false;
            };
            let Some(body) = suffix.split_once("\n}").map(|(body, _)| body) else {
                return false;
            };
            let declaration_prefix = &prefix[prefix.len().saturating_sub(192)..];
            declaration_prefix.ends_with("#[derive(Debug)]\n")
                && !declaration_prefix.contains("#[cfg")
                && body
                    == "\n    input_set: B4ContractArtifactIdentityV1,\n    completion_path: String,"
                && !source.contains("impl Clone for B4ValidatedPositiveInputSetCompletionV2")
                && !source.contains("impl Copy for B4ValidatedPositiveInputSetCompletionV2")
                && !source.contains("impl Default for B4ValidatedPositiveInputSetCompletionV2")
                && !source.contains("impl Serialize for B4ValidatedPositiveInputSetCompletionV2")
                && !source
                    .contains("impl serde::Serialize for B4ValidatedPositiveInputSetCompletionV2")
                && !source.contains(
                    "impl<'de> Deserialize<'de> for B4ValidatedPositiveInputSetCompletionV2",
                )
                && !source.contains(
                    "impl<'de> serde::Deserialize<'de> for B4ValidatedPositiveInputSetCompletionV2",
                )
        }

        let source = include_str!("b4_positive_input_set.rs").replace("\r\n", "\n");
        let production = source
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .expect("missing production/test boundary");
        assert!(oracle(production));

        let declaration = "pub struct B4ValidatedPositiveInputSetCompletionV2 {\n    input_set: B4ContractArtifactIdentityV1,\n    completion_path: String,\n}";
        let public_fields = "pub struct B4ValidatedPositiveInputSetCompletionV2 {\n    pub input_set: B4ContractArtifactIdentityV1,\n    pub completion_path: String,\n}";
        for mutant in [
            production.replacen(
                "#[derive(Debug)]\npub struct B4ValidatedPositiveInputSetCompletionV2",
                "#[derive(Clone, Debug)]\npub struct B4ValidatedPositiveInputSetCompletionV2",
                1,
            ),
            production.replacen(
                "#[derive(Debug)]\npub struct B4ValidatedPositiveInputSetCompletionV2",
                "#[derive(Clone, Copy, Debug)]\npub struct B4ValidatedPositiveInputSetCompletionV2",
                1,
            ),
            production.replacen(
                "#[derive(Debug)]\npub struct B4ValidatedPositiveInputSetCompletionV2",
                "#[derive(Debug, Serialize)]\npub struct B4ValidatedPositiveInputSetCompletionV2",
                1,
            ),
            production.replacen(
                "#[derive(Debug)]\npub struct B4ValidatedPositiveInputSetCompletionV2",
                "#[derive(Debug, Deserialize)]\npub struct B4ValidatedPositiveInputSetCompletionV2",
                1,
            ),
            production.replacen(declaration, public_fields, 1),
            production.replacen(
                "#[derive(Debug)]\npub struct B4ValidatedPositiveInputSetCompletionV2",
                "#[cfg(feature = \"positive-gate\")]\n#[derive(Debug)]\npub struct B4ValidatedPositiveInputSetCompletionV2",
                1,
            ),
            format!(
                "{production}\nimpl Clone for B4ValidatedPositiveInputSetCompletionV2 {{ fn clone(&self) -> Self {{ todo!() }} }}"
            ),
        ] {
            assert!(!oracle(&mutant), "token surface oracle accepted a mutant");
        }
    }
}
