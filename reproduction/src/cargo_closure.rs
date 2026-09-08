//! Pure structural validation for candidate Cargo-closure evidence.
//!
//! Cargo metadata alone cannot prove which configuration files or environment
//! variables influenced a run. The caller must therefore supply the normalized
//! feature/configuration evidence defined here. This candidate validator checks
//! internal agreement; it does not attest how that evidence was captured.

use core::{fmt, str::FromStr};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const EVIDENCE_SCHEMA: &str = "eip0045-candidate-cargo-closure-v2";
// The semantic profile remains rooted at the reviewed upstream parent. Cargo
// alone resolves this separately reviewed observational fork so verifier
// checkpoints are available without changing proof-system semantics.
pub(crate) const RISC0_CARGO_SOURCE_REPOSITORY: &str = "https://github.com/a-shannon/risc0";
pub(crate) const RISC0_CARGO_SOURCE_REVISION: &str = "227229dc793c215c533cbc0e07911601974a4629";
const RISC0_SEMANTIC_SOURCE_REPOSITORY: &str = "https://github.com/risc0/risc0";
const REQUIRED_HOST_CRATE: &str = "risc0-zkvm";
const REQUIRED_HOST_FEATURES: [&str; 2] = ["disable-dev-mode", "prove"];
const REQUIRED_METHODS_CRATE: &str = "eip-0045-methods";
const REQUIRED_METHODS_FEATURE: &str = "embed-methods";
const FORBIDDEN_FEATURES: [&str; 5] = ["bonsai", "cuda", "docker", "metal", "witgen_debug"];

/// Cargo dependency-closure role governed by one explicit feature policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CargoClosureRole {
    /// Host proof generator: one `risc0-zkvm` with `prove` and
    /// `disable-dev-mode`, without Cargo's `default` feature, and exactly one
    /// `eip-0045-methods` package with `embed-methods`.
    GeneratorHost,
    /// Method build-script closure: no `risc0-zkvm` package is expected, and
    /// the sole `eip-0045-methods` package has `embed-methods`.
    MethodsBuild,
    /// Guest closure: one `risc0-zkvm` without `default` or `prove`, and the
    /// sole `eip-0045-methods` package does not activate `embed-methods`.
    Guest,
}

impl fmt::Display for CargoClosureRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::GeneratorHost => "generator-host",
            Self::MethodsBuild => "methods-build",
            Self::Guest => "guest",
        })
    }
}

impl FromStr for CargoClosureRole {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "generator-host" => Ok(Self::GeneratorHost),
            "methods-build" => Ok(Self::MethodsBuild),
            "guest" => Ok(Self::Guest),
            _ => Err("expected generator-host, methods-build, or guest"),
        }
    }
}

/// A private comparison root paired with a portable, non-path identity.
///
/// The private root is intentionally omitted from `Debug` output and has no
/// public accessor, so validation errors and normalized evidence need expose
/// only `public_identity`.
#[derive(Clone, PartialEq, Eq)]
pub struct ProfileRootIdentity {
    private_root: String,
    windows_semantics: bool,
    public_identity: String,
}

impl ProfileRootIdentity {
    /// Construct a root identity from a canonical absolute path and a portable
    /// evidence label such as `eip-0045-profile`.
    ///
    /// # Errors
    ///
    /// Returns an error if the private root is not an absolute normalized path
    /// or if the public identity could itself be interpreted as a path.
    pub fn new(private_root: &str, public_identity: &str) -> Result<Self, CargoClosureError> {
        let (private_root, windows_semantics) =
            normalize_absolute_root(private_root).ok_or(CargoClosureError::InvalidProfileRoot)?;
        if !is_public_identity(public_identity) {
            return Err(CargoClosureError::InvalidProfileRootIdentity);
        }
        Ok(Self {
            private_root,
            windows_semantics,
            public_identity: public_identity.to_owned(),
        })
    }

    /// Return the portable identity that may appear in shareable evidence.
    #[must_use]
    pub fn public_identity(&self) -> &str {
        &self.public_identity
    }

    fn relative_manifest(&self, manifest_path: &str) -> Option<String> {
        let (path, windows_semantics) = normalize_absolute_root(manifest_path)?;
        if windows_semantics != self.windows_semantics || !path.ends_with("/Cargo.toml") {
            return None;
        }
        let suffix = if self.windows_semantics {
            let root = self.private_root.to_ascii_lowercase();
            let candidate = path.to_ascii_lowercase();
            candidate.strip_prefix(&root)?;
            path.get(self.private_root.len()..)?
        } else {
            path.strip_prefix(&self.private_root)?
        };
        Some(suffix.strip_prefix('/')?.to_owned())
    }
}

impl fmt::Debug for ProfileRootIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfileRootIdentity")
            .field("public_identity", &self.public_identity)
            .finish_non_exhaustive()
    }
}

/// Normalized feature-tree and Cargo-configuration observations accompanying
/// one `cargo metadata` document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CargoClosureEvidence {
    /// Candidate evidence schema identifier.
    pub schema: String,
    /// Lifecycle marker; must remain `candidate`.
    pub lifecycle: String,
    /// Portable root identity, never an absolute path.
    pub profile_root_identity: String,
    /// Explicit closure role selecting the applicable feature policy.
    pub role: CargoClosureRole,
    /// Complete feature set for every node in the metadata resolve graph.
    pub feature_tree: Vec<FeatureTreePackage>,
    /// Observed Cargo configuration and wrapper influences.
    pub configuration: CargoConfigurationEvidence,
}

/// Activated features for one exact Cargo package ID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FeatureTreePackage {
    /// Exact package ID emitted by Cargo metadata.
    pub package_id: String,
    /// Strictly sorted, duplicate-free activated feature names.
    pub features: Vec<String>,
}

/// Configuration influences that must all be absent for this candidate path.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CargoConfigurationEvidence {
    /// `[patch]` entries observed across the configuration closure.
    pub patches: Vec<String>,
    /// `[replace]` entries observed across the configuration closure.
    pub replacements: Vec<String>,
    /// Registry or source replacement entries.
    pub source_replacements: Vec<String>,
    /// Cargo path overrides outside ordinary workspace packages.
    pub path_overrides: Vec<String>,
    /// `RUSTC_WRAPPER`, `build.rustc-wrapper`, or equivalent wrapper identity.
    pub rustc_wrapper: Option<String>,
    /// `RUSTC_WORKSPACE_WRAPPER` or `build.rustc-workspace-wrapper` identity.
    pub rustc_workspace_wrapper: Option<String>,
}

/// Failure returned by candidate Cargo-closure validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CargoClosureError {
    /// The private comparison root is not a normalized absolute path.
    InvalidProfileRoot,
    /// The public root identity is empty, unsafe, or path-like.
    InvalidProfileRootIdentity,
    /// Cargo metadata cannot be parsed into the required structural subset.
    MalformedMetadata,
    /// Candidate schema, lifecycle, or root identity differs.
    InvalidEvidenceMarker(&'static str),
    /// Cargo configuration contains a forbidden influence.
    ForbiddenConfiguration(&'static str),
    /// Metadata package IDs are duplicated.
    DuplicatePackageId,
    /// A resolve node is duplicated or references an unknown package.
    InvalidResolveGraph,
    /// A local package is outside the supplied private profile root.
    LocalPackageOutsideProfile,
    /// A RISC Zero crate is not sourced from the exact pinned Git revision.
    UnpinnedRisc0Package,
    /// A non-registry, non-profile, non-pinned source entered the closure.
    UnsupportedPackageSource,
    /// Feature-tree evidence is missing, duplicated, unsorted, or disagrees.
    FeatureTreeMismatch,
    /// A forbidden feature is active.
    ForbiddenFeature,
    /// The selected role has the wrong number of resolved `risc0-zkvm` packages.
    InvalidRisc0ZkvmPackageCount,
    /// The selected role is missing an explicit required `risc0-zkvm` feature.
    MissingRequiredRisc0ZkvmFeature(&'static str),
    /// The selected role activates a disallowed `risc0-zkvm` feature.
    DisallowedRisc0ZkvmFeature(&'static str),
    /// The selected closure does not contain exactly one resolved methods package.
    InvalidMethodsPackageCount,
    /// The selected role is missing a required methods-package feature.
    MissingRequiredMethodsFeature(&'static str),
    /// The selected role activates a disallowed methods-package feature.
    DisallowedMethodsFeature(&'static str),
}

impl fmt::Display for CargoClosureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProfileRoot => formatter.write_str("invalid private profile root"),
            Self::InvalidProfileRootIdentity => {
                formatter.write_str("invalid portable profile-root identity")
            }
            Self::MalformedMetadata => formatter.write_str("malformed cargo metadata"),
            Self::InvalidEvidenceMarker(name) => {
                write!(formatter, "invalid cargo-closure evidence marker: {name}")
            }
            Self::ForbiddenConfiguration(name) => {
                write!(formatter, "forbidden Cargo configuration influence: {name}")
            }
            Self::DuplicatePackageId => formatter.write_str("duplicate cargo package ID"),
            Self::InvalidResolveGraph => formatter.write_str("invalid cargo resolve graph"),
            Self::LocalPackageOutsideProfile => {
                formatter.write_str("local Cargo package is outside the supplied profile root")
            }
            Self::UnpinnedRisc0Package => {
                formatter.write_str("RISC Zero package is not pinned to the exact source revision")
            }
            Self::UnsupportedPackageSource => {
                formatter.write_str("unsupported package source in Cargo closure")
            }
            Self::FeatureTreeMismatch => {
                formatter.write_str("feature-tree evidence disagrees with Cargo metadata")
            }
            Self::ForbiddenFeature => formatter.write_str("forbidden Cargo feature is active"),
            Self::InvalidRisc0ZkvmPackageCount => {
                formatter.write_str("unexpected risc0-zkvm package count for closure role")
            }
            Self::MissingRequiredRisc0ZkvmFeature(feature) => {
                write!(
                    formatter,
                    "required risc0-zkvm feature is absent for closure role: {feature}"
                )
            }
            Self::DisallowedRisc0ZkvmFeature(feature) => {
                write!(
                    formatter,
                    "risc0-zkvm feature is disallowed for closure role: {feature}"
                )
            }
            Self::InvalidMethodsPackageCount => {
                formatter.write_str("unexpected eip-0045-methods package count for closure role")
            }
            Self::MissingRequiredMethodsFeature(feature) => {
                write!(
                    formatter,
                    "required eip-0045-methods feature is absent for closure role: {feature}"
                )
            }
            Self::DisallowedMethodsFeature(feature) => {
                write!(
                    formatter,
                    "eip-0045-methods feature is disallowed for closure role: {feature}"
                )
            }
        }
    }
}

impl std::error::Error for CargoClosureError {}

/// Validate one supplied Cargo metadata document and its normalized candidate
/// feature/configuration evidence.
///
/// # Errors
///
/// Returns the first structural, source, root-confinement, feature, or
/// configuration mismatch. The function performs no filesystem access.
pub fn validate_cargo_closure(
    metadata_json: &Value,
    evidence: &CargoClosureEvidence,
    profile_root: &ProfileRootIdentity,
) -> Result<(), CargoClosureError> {
    validate_evidence_markers(evidence, profile_root)?;
    validate_configuration(&evidence.configuration)?;

    let metadata: MetadataDocument = serde_json::from_value(metadata_json.clone())
        .map_err(|_| CargoClosureError::MalformedMetadata)?;
    let resolve = metadata
        .resolve
        .ok_or(CargoClosureError::InvalidResolveGraph)?;

    let mut packages = BTreeMap::new();
    for package in &metadata.packages {
        if packages.insert(package.id.as_str(), package).is_some() {
            return Err(CargoClosureError::DuplicatePackageId);
        }
        validate_package_source(package, profile_root)?;
    }

    let mut resolved_features = BTreeMap::new();
    for node in &resolve.nodes {
        let package = packages
            .get(node.id.as_str())
            .ok_or(CargoClosureError::InvalidResolveGraph)?;
        let evidence_id = evidence_package_id(package, profile_root)?;
        if resolved_features
            .insert(evidence_id, node.features.as_slice())
            .is_some()
        {
            return Err(CargoClosureError::InvalidResolveGraph);
        }
        if has_duplicates(&node.features) {
            return Err(CargoClosureError::InvalidResolveGraph);
        }
        if node
            .features
            .iter()
            .any(|feature| is_forbidden_feature(feature))
        {
            return Err(CargoClosureError::ForbiddenFeature);
        }
    }

    validate_feature_evidence(&resolved_features, &evidence.feature_tree)?;

    validate_role_policy(&resolve.nodes, &packages, evidence.role)
}

/// Derive the canonical candidate evidence record from an actual Cargo
/// metadata document and an explicit configuration observation.
///
/// Feature-tree entries and each feature list are emitted in strict bytewise
/// order. Duplicate or dangling resolve nodes are rejected instead of being
/// normalized away.
///
/// # Errors
///
/// Returns an error when metadata is malformed, has no resolve graph, contains
/// duplicate/dangling nodes, or contains duplicate features.
pub fn derive_cargo_closure_evidence(
    metadata_json: &Value,
    role: CargoClosureRole,
    profile_root: &ProfileRootIdentity,
    configuration: CargoConfigurationEvidence,
) -> Result<CargoClosureEvidence, CargoClosureError> {
    let metadata: MetadataDocument = serde_json::from_value(metadata_json.clone())
        .map_err(|_| CargoClosureError::MalformedMetadata)?;
    let resolve = metadata
        .resolve
        .ok_or(CargoClosureError::InvalidResolveGraph)?;
    let mut packages = BTreeMap::new();
    for package in &metadata.packages {
        if packages.insert(package.id.as_str(), package).is_some() {
            return Err(CargoClosureError::DuplicatePackageId);
        }
    }

    let mut nodes = BTreeMap::new();
    for node in resolve.nodes {
        let package = packages
            .get(node.id.as_str())
            .ok_or(CargoClosureError::InvalidResolveGraph)?;
        let evidence_id = evidence_package_id(package, profile_root)?;
        if has_duplicates(&node.features) || nodes.insert(evidence_id, node.features).is_some() {
            return Err(CargoClosureError::InvalidResolveGraph);
        }
    }

    let feature_tree = nodes
        .into_iter()
        .map(|(package_id, mut features)| {
            features.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
            FeatureTreePackage {
                package_id,
                features,
            }
        })
        .collect();

    Ok(CargoClosureEvidence {
        schema: EVIDENCE_SCHEMA.to_owned(),
        lifecycle: "candidate".to_owned(),
        profile_root_identity: profile_root.public_identity().to_owned(),
        role,
        feature_tree,
        configuration,
    })
}

fn validate_evidence_markers(
    evidence: &CargoClosureEvidence,
    profile_root: &ProfileRootIdentity,
) -> Result<(), CargoClosureError> {
    if evidence.schema != EVIDENCE_SCHEMA {
        return Err(CargoClosureError::InvalidEvidenceMarker("schema"));
    }
    if evidence.lifecycle != "candidate" {
        return Err(CargoClosureError::InvalidEvidenceMarker("lifecycle"));
    }
    if evidence.profile_root_identity != profile_root.public_identity() {
        return Err(CargoClosureError::InvalidEvidenceMarker(
            "profile root identity",
        ));
    }
    Ok(())
}

fn validate_configuration(
    configuration: &CargoConfigurationEvidence,
) -> Result<(), CargoClosureError> {
    if !configuration.patches.is_empty() {
        return Err(CargoClosureError::ForbiddenConfiguration("patch"));
    }
    if !configuration.replacements.is_empty() {
        return Err(CargoClosureError::ForbiddenConfiguration("replace"));
    }
    if !configuration.source_replacements.is_empty() {
        return Err(CargoClosureError::ForbiddenConfiguration(
            "source replacement",
        ));
    }
    if !configuration.path_overrides.is_empty() {
        return Err(CargoClosureError::ForbiddenConfiguration("path override"));
    }
    if configuration.rustc_wrapper.is_some() {
        return Err(CargoClosureError::ForbiddenConfiguration("rustc wrapper"));
    }
    if configuration.rustc_workspace_wrapper.is_some() {
        return Err(CargoClosureError::ForbiddenConfiguration(
            "rustc workspace wrapper",
        ));
    }
    Ok(())
}

fn validate_role_policy(
    nodes: &[MetadataNode],
    packages: &BTreeMap<&str, &MetadataPackage>,
    role: CargoClosureRole,
) -> Result<(), CargoClosureError> {
    let zkvm_nodes: Vec<&MetadataNode> = nodes
        .iter()
        .filter(|node| {
            packages
                .get(node.id.as_str())
                .is_some_and(|package| package.name == REQUIRED_HOST_CRATE)
        })
        .collect();

    match role {
        CargoClosureRole::GeneratorHost => {
            if zkvm_nodes.len() != 1 {
                return Err(CargoClosureError::InvalidRisc0ZkvmPackageCount);
            }
            let zkvm = zkvm_nodes[0];
            if zkvm.features.iter().any(|feature| feature == "default") {
                return Err(CargoClosureError::DisallowedRisc0ZkvmFeature("default"));
            }
            for feature in REQUIRED_HOST_FEATURES {
                if !zkvm.features.iter().any(|active| active == feature) {
                    return Err(CargoClosureError::MissingRequiredRisc0ZkvmFeature(feature));
                }
            }
        }
        CargoClosureRole::Guest => {
            if zkvm_nodes.len() != 1 {
                return Err(CargoClosureError::InvalidRisc0ZkvmPackageCount);
            }
            let zkvm = zkvm_nodes[0];
            if zkvm.features.iter().any(|feature| feature == "default") {
                return Err(CargoClosureError::DisallowedRisc0ZkvmFeature("default"));
            }
            if zkvm.features.iter().any(|feature| feature == "prove") {
                return Err(CargoClosureError::DisallowedRisc0ZkvmFeature("prove"));
            }
        }
        CargoClosureRole::MethodsBuild => {
            if !zkvm_nodes.is_empty() {
                return Err(CargoClosureError::InvalidRisc0ZkvmPackageCount);
            }
        }
    }

    let methods_nodes: Vec<&MetadataNode> = nodes
        .iter()
        .filter(|node| {
            packages
                .get(node.id.as_str())
                .is_some_and(|package| package.name == REQUIRED_METHODS_CRATE)
        })
        .collect();
    if methods_nodes.len() != 1 {
        return Err(CargoClosureError::InvalidMethodsPackageCount);
    }
    let embeds_methods = methods_nodes[0]
        .features
        .iter()
        .any(|feature| feature == REQUIRED_METHODS_FEATURE);
    match role {
        CargoClosureRole::GeneratorHost | CargoClosureRole::MethodsBuild if !embeds_methods => {
            return Err(CargoClosureError::MissingRequiredMethodsFeature(
                REQUIRED_METHODS_FEATURE,
            ));
        }
        CargoClosureRole::Guest if embeds_methods => {
            return Err(CargoClosureError::DisallowedMethodsFeature(
                REQUIRED_METHODS_FEATURE,
            ));
        }
        CargoClosureRole::GeneratorHost
        | CargoClosureRole::MethodsBuild
        | CargoClosureRole::Guest => {}
    }
    Ok(())
}

fn validate_package_source(
    package: &MetadataPackage,
    profile_root: &ProfileRootIdentity,
) -> Result<(), CargoClosureError> {
    let risc0_named = package.name == "risc0" || package.name.starts_with("risc0-");
    match &package.source {
        None => {
            if risc0_named
                || profile_root
                    .relative_manifest(&package.manifest_path)
                    .is_none()
            {
                return Err(if risc0_named {
                    CargoClosureError::UnpinnedRisc0Package
                } else {
                    CargoClosureError::LocalPackageOutsideProfile
                });
            }
        }
        // The pinned RISC Zero workspace contains packages whose names do not
        // use the `risc0-` prefix. Source identity, not crate naming, is the
        // authority boundary for packages from that exact repository commit.
        Some(source) if is_exact_risc0_source(source) => {}
        Some(source) if source.starts_with("registry+") || source.starts_with("sparse+") => {
            if risc0_named {
                return Err(CargoClosureError::UnpinnedRisc0Package);
            }
        }
        Some(source) if source.starts_with("git+") => {
            return Err(
                if risc0_named
                    || source.contains(RISC0_SEMANTIC_SOURCE_REPOSITORY)
                    || source.contains(RISC0_CARGO_SOURCE_REPOSITORY)
                {
                    CargoClosureError::UnpinnedRisc0Package
                } else {
                    CargoClosureError::UnsupportedPackageSource
                },
            );
        }
        Some(_) => return Err(CargoClosureError::UnsupportedPackageSource),
    }
    Ok(())
}

fn evidence_package_id(
    package: &MetadataPackage,
    profile_root: &ProfileRootIdentity,
) -> Result<String, CargoClosureError> {
    if package.source.is_some() {
        return Ok(package.id.clone());
    }
    let relative = profile_root
        .relative_manifest(&package.manifest_path)
        .ok_or(CargoClosureError::LocalPackageOutsideProfile)?;
    Ok(format!(
        "path+{}/{relative}",
        profile_root.public_identity()
    ))
}

fn validate_feature_evidence(
    resolved: &BTreeMap<String, &[String]>,
    evidence: &[FeatureTreePackage],
) -> Result<(), CargoClosureError> {
    if resolved.len() != evidence.len() {
        return Err(CargoClosureError::FeatureTreeMismatch);
    }
    let mut previous: Option<&str> = None;
    for package in evidence {
        if previous.is_some_and(|id| id.as_bytes() >= package.package_id.as_bytes())
            || !is_strictly_sorted(&package.features)
            || package
                .features
                .iter()
                .any(|feature| is_forbidden_feature(feature))
        {
            return Err(CargoClosureError::FeatureTreeMismatch);
        }
        let actual = resolved
            .get(package.package_id.as_str())
            .ok_or(CargoClosureError::FeatureTreeMismatch)?;
        let actual_set: BTreeSet<&str> = actual.iter().map(String::as_str).collect();
        let evidence_set: BTreeSet<&str> = package.features.iter().map(String::as_str).collect();
        if actual_set != evidence_set {
            return Err(CargoClosureError::FeatureTreeMismatch);
        }
        previous = Some(&package.package_id);
    }
    Ok(())
}

fn is_exact_risc0_source(source: &str) -> bool {
    source
        == format!(
            "git+{RISC0_CARGO_SOURCE_REPOSITORY}?rev={RISC0_CARGO_SOURCE_REVISION}#{RISC0_CARGO_SOURCE_REVISION}"
        )
}

fn is_forbidden_feature(feature: &str) -> bool {
    let normalized = feature.to_ascii_lowercase().replace('-', "_");
    let leaf = normalized
        .rsplit(['/', ':'])
        .next()
        .unwrap_or(normalized.as_str());
    FORBIDDEN_FEATURES.contains(&leaf)
}

fn has_duplicates(values: &[String]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().any(|value| !seen.insert(value))
}

fn is_strictly_sorted(values: &[String]) -> bool {
    values
        .windows(2)
        .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
}

fn is_public_identity(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'0'..=b'9' => true,
            b'.' | b'_' | b'-' => index > 0,
            _ => false,
        })
        && !value.ends_with(['.', '_', '-'])
        && value != "."
        && value != ".."
}

fn normalize_absolute_root(path: &str) -> Option<(String, bool)> {
    if path.is_empty() || path.bytes().any(|byte| byte.is_ascii_control()) {
        return None;
    }
    let normalized = path.replace('\\', "/");
    let windows = normalized.as_bytes().get(1) == Some(&b':');
    let body = if windows {
        let bytes = normalized.as_bytes();
        if !bytes.first().is_some_and(u8::is_ascii_alphabetic) || bytes.get(2) != Some(&b'/') {
            return None;
        }
        &normalized[3..]
    } else {
        normalized.strip_prefix('/')?
    };
    if normalized.ends_with('/') || body.is_empty() {
        return None;
    }
    if !body
        .split('/')
        .all(|component| !component.is_empty() && component != "." && component != "..")
    {
        return None;
    }
    Some((normalized, windows))
}

#[derive(Deserialize)]
struct MetadataDocument {
    packages: Vec<MetadataPackage>,
    resolve: Option<MetadataResolve>,
}

#[derive(Deserialize)]
struct MetadataPackage {
    name: String,
    id: String,
    source: Option<String>,
    manifest_path: String,
}

#[derive(Deserialize)]
struct MetadataResolve {
    nodes: Vec<MetadataNode>,
}

#[derive(Deserialize)]
struct MetadataNode {
    id: String,
    features: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn root() -> ProfileRootIdentity {
        ProfileRootIdentity::new("C:/fixture/private/eip-0045-profile", "eip-0045-profile").unwrap()
    }

    fn risc0_source() -> String {
        format!(
            "git+{RISC0_CARGO_SOURCE_REPOSITORY}?rev={RISC0_CARGO_SOURCE_REVISION}#{RISC0_CARGO_SOURCE_REVISION}"
        )
    }

    fn valid_metadata() -> Value {
        json!({
            "packages": [
                {
                    "name": "eip-0045-generator",
                    "id": "path+file:///profile#eip-0045-generator@0.1.0",
                    "source": null,
                    "manifest_path": "C:/fixture/private/eip-0045-profile/generator/Cargo.toml"
                },
                {
                    "name": "risc0-zkvm",
                    "id": "git+https://github.com/a-shannon/risc0?rev=x#risc0-zkvm@3.0.5",
                    "source": risc0_source(),
                    "manifest_path": "C:/fixture/cargo/git/checkouts/risc0/risc0/zkvm/Cargo.toml"
                },
                {
                    "name": "serde",
                    "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
                    "source": "registry+https://github.com/rust-lang/crates.io-index",
                    "manifest_path": "C:/fixture/cargo/registry/src/serde/Cargo.toml"
                },
                {
                    "name": "eip-0045-methods",
                    "id": "path+file:///profile#eip-0045-methods@0.1.0",
                    "source": null,
                    "manifest_path": "C:/fixture/private/eip-0045-profile/methods/Cargo.toml"
                }
            ],
            "resolve": {
                "nodes": [
                    {
                        "id": "path+file:///profile#eip-0045-generator@0.1.0",
                        "features": []
                    },
                    {
                        "id": "git+https://github.com/a-shannon/risc0?rev=x#risc0-zkvm@3.0.5",
                        "features": ["client", "disable-dev-mode", "prove"]
                    },
                    {
                        "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228",
                        "features": ["derive", "std"]
                    },
                    {
                        "id": "path+file:///profile#eip-0045-methods@0.1.0",
                        "features": ["embed-methods"]
                    }
                ]
            }
        })
    }

    fn valid_evidence() -> CargoClosureEvidence {
        CargoClosureEvidence {
            schema: EVIDENCE_SCHEMA.to_owned(),
            lifecycle: "candidate".to_owned(),
            profile_root_identity: "eip-0045-profile".to_owned(),
            role: CargoClosureRole::GeneratorHost,
            feature_tree: vec![
                FeatureTreePackage {
                    package_id: "git+https://github.com/a-shannon/risc0?rev=x#risc0-zkvm@3.0.5"
                        .to_owned(),
                    features: vec![
                        "client".to_owned(),
                        "disable-dev-mode".to_owned(),
                        "prove".to_owned(),
                    ],
                },
                FeatureTreePackage {
                    package_id: "path+eip-0045-profile/generator/Cargo.toml".to_owned(),
                    features: vec![],
                },
                FeatureTreePackage {
                    package_id: "path+eip-0045-profile/methods/Cargo.toml".to_owned(),
                    features: vec!["embed-methods".to_owned()],
                },
                FeatureTreePackage {
                    package_id:
                        "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.228"
                            .to_owned(),
                    features: vec!["derive".to_owned(), "std".to_owned()],
                },
            ],
            configuration: CargoConfigurationEvidence::default(),
        }
    }

    fn methods_metadata() -> Value {
        let mut metadata = valid_metadata();
        metadata["packages"].as_array_mut().unwrap().pop();
        metadata["resolve"]["nodes"].as_array_mut().unwrap().pop();
        let id = "git+https://github.com/a-shannon/risc0?rev=x#risc0-build@3.0.5";
        metadata["packages"][0]["name"] = json!("eip-0045-methods");
        metadata["packages"][0]["manifest_path"] =
            json!("C:/fixture/private/eip-0045-profile/methods/Cargo.toml");
        metadata["packages"][1]["name"] = json!("risc0-build");
        metadata["packages"][1]["id"] = json!(id);
        metadata["resolve"]["nodes"][0]["id"] =
            json!("path+file:///profile#eip-0045-methods@0.1.0");
        metadata["packages"][0]["id"] = json!("path+file:///profile#eip-0045-methods@0.1.0");
        metadata["resolve"]["nodes"][0]["features"] = json!(["embed-methods"]);
        metadata["resolve"]["nodes"][1]["id"] = json!(id);
        metadata["resolve"]["nodes"][1]["features"] = json!([]);
        metadata
    }

    fn guest_metadata() -> Value {
        let mut metadata = valid_metadata();
        metadata["packages"][0]["name"] = json!("eip-0045-guest");
        metadata["packages"][0]["manifest_path"] =
            json!("C:/fixture/private/eip-0045-profile/methods/guest/Cargo.toml");
        metadata["packages"][0]["id"] = json!("path+file:///profile#eip-0045-guest@0.1.0");
        metadata["resolve"]["nodes"][0]["id"] = json!("path+file:///profile#eip-0045-guest@0.1.0");
        metadata["resolve"]["nodes"][1]["features"] = json!(["std"]);
        metadata["resolve"]["nodes"][3]["features"] = json!([]);
        metadata
    }

    fn derived_evidence(metadata: &Value, role: CargoClosureRole) -> CargoClosureEvidence {
        derive_cargo_closure_evidence(
            metadata,
            role,
            &root(),
            CargoConfigurationEvidence::default(),
        )
        .unwrap()
    }

    #[test]
    fn accepts_exact_candidate_closure() {
        validate_cargo_closure(&valid_metadata(), &valid_evidence(), &root()).unwrap();
    }

    #[test]
    fn derives_canonical_feature_tree_and_validates_generator_role() {
        let mut metadata = valid_metadata();
        metadata["resolve"]["nodes"][1]["features"] =
            json!(["prove", "disable-dev-mode", "client"]);
        metadata["resolve"]["nodes"]
            .as_array_mut()
            .unwrap()
            .reverse();

        let evidence = derived_evidence(&metadata, CargoClosureRole::GeneratorHost);
        assert!(
            evidence
                .feature_tree
                .windows(2)
                .all(|pair| pair[0].package_id.as_bytes() < pair[1].package_id.as_bytes())
        );
        assert!(
            evidence
                .feature_tree
                .iter()
                .all(|package| is_strictly_sorted(&package.features))
        );
        validate_cargo_closure(&metadata, &evidence, &root()).unwrap();
    }

    #[test]
    fn accepts_methods_build_without_risc0_zkvm() {
        let metadata = methods_metadata();
        let evidence = derived_evidence(&metadata, CargoClosureRole::MethodsBuild);
        validate_cargo_closure(&metadata, &evidence, &root()).unwrap();
    }

    #[test]
    fn accepts_guest_without_default_or_prove() {
        let metadata = guest_metadata();
        let evidence = derived_evidence(&metadata, CargoClosureRole::Guest);
        validate_cargo_closure(&metadata, &evidence, &root()).unwrap();
    }

    #[test]
    fn rejects_every_role_without_exactly_one_resolved_methods_package() {
        for (mut metadata, role) in [
            (valid_metadata(), CargoClosureRole::GeneratorHost),
            (methods_metadata(), CargoClosureRole::MethodsBuild),
            (guest_metadata(), CargoClosureRole::Guest),
        ] {
            metadata["resolve"]["nodes"]
                .as_array_mut()
                .unwrap()
                .retain(|node| {
                    node["id"].as_str() != Some("path+file:///profile#eip-0045-methods@0.1.0")
                });
            let evidence = derived_evidence(&metadata, role);
            assert_eq!(
                validate_cargo_closure(&metadata, &evidence, &root()),
                Err(CargoClosureError::InvalidMethodsPackageCount)
            );
        }

        let mut metadata = valid_metadata();
        metadata["packages"].as_array_mut().unwrap().push(json!({
            "name": "eip-0045-methods",
            "id": "path+file:///profile#eip-0045-methods@0.1.1",
            "source": null,
            "manifest_path": "C:/fixture/private/eip-0045-profile/methods-copy/Cargo.toml"
        }));
        metadata["resolve"]["nodes"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id": "path+file:///profile#eip-0045-methods@0.1.1",
                "features": ["embed-methods"]
            }));
        let evidence = derived_evidence(&metadata, CargoClosureRole::GeneratorHost);
        assert_eq!(
            validate_cargo_closure(&metadata, &evidence, &root()),
            Err(CargoClosureError::InvalidMethodsPackageCount)
        );
    }

    #[test]
    fn enforces_embed_methods_feature_by_role() {
        for (mut metadata, role, methods_node_index) in [
            (valid_metadata(), CargoClosureRole::GeneratorHost, 3),
            (methods_metadata(), CargoClosureRole::MethodsBuild, 0),
        ] {
            metadata["resolve"]["nodes"][methods_node_index]["features"] = json!([]);
            let evidence = derived_evidence(&metadata, role);
            assert_eq!(
                validate_cargo_closure(&metadata, &evidence, &root()),
                Err(CargoClosureError::MissingRequiredMethodsFeature(
                    "embed-methods"
                ))
            );
        }

        let mut metadata = guest_metadata();
        metadata["resolve"]["nodes"][3]["features"] = json!(["embed-methods"]);
        let evidence = derived_evidence(&metadata, CargoClosureRole::Guest);
        assert_eq!(
            validate_cargo_closure(&metadata, &evidence, &root()),
            Err(CargoClosureError::DisallowedMethodsFeature("embed-methods"))
        );
    }

    #[test]
    fn rejects_role_substitution() {
        let generator = valid_metadata();
        let evidence = derived_evidence(&generator, CargoClosureRole::Guest);
        assert_eq!(
            validate_cargo_closure(&generator, &evidence, &root()),
            Err(CargoClosureError::DisallowedRisc0ZkvmFeature("prove"))
        );

        let evidence = derived_evidence(&generator, CargoClosureRole::MethodsBuild);
        assert_eq!(
            validate_cargo_closure(&generator, &evidence, &root()),
            Err(CargoClosureError::InvalidRisc0ZkvmPackageCount)
        );

        let guest = guest_metadata();
        let evidence = derived_evidence(&guest, CargoClosureRole::GeneratorHost);
        assert_eq!(
            validate_cargo_closure(&guest, &evidence, &root()),
            Err(CargoClosureError::MissingRequiredRisc0ZkvmFeature(
                "disable-dev-mode"
            ))
        );
    }

    #[test]
    fn role_has_exact_self_describing_spelling() {
        for (spelling, role) in [
            ("generator-host", CargoClosureRole::GeneratorHost),
            ("methods-build", CargoClosureRole::MethodsBuild),
            ("guest", CargoClosureRole::Guest),
        ] {
            assert_eq!(spelling.parse::<CargoClosureRole>(), Ok(role));
            assert_eq!(role.to_string(), spelling);
            assert_eq!(serde_json::to_value(role).unwrap(), json!(spelling));
        }
        assert!("host".parse::<CargoClosureRole>().is_err());
        assert!(serde_json::from_value::<CargoClosureRole>(json!("host")).is_err());
    }

    #[test]
    fn derivation_rejects_duplicate_nodes_and_features() {
        let mut metadata = valid_metadata();
        let duplicate = metadata["resolve"]["nodes"][0].clone();
        metadata["resolve"]["nodes"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        assert_eq!(
            derive_cargo_closure_evidence(
                &metadata,
                CargoClosureRole::GeneratorHost,
                &root(),
                CargoConfigurationEvidence::default()
            ),
            Err(CargoClosureError::InvalidResolveGraph)
        );

        let mut metadata = valid_metadata();
        metadata["resolve"]["nodes"][1]["features"] = json!(["prove", "prove"]);
        assert_eq!(
            derive_cargo_closure_evidence(
                &metadata,
                CargoClosureRole::GeneratorHost,
                &root(),
                CargoConfigurationEvidence::default()
            ),
            Err(CargoClosureError::InvalidResolveGraph)
        );
    }

    #[test]
    fn profile_root_debug_output_never_contains_private_path() {
        let root = root();
        let rendered = format!("{root:?}");
        assert!(rendered.contains("eip-0045-profile"));
        assert!(!rendered.contains("C:/fixture/private"));
    }

    #[test]
    fn derived_evidence_replaces_private_local_package_ids() {
        let mut metadata = valid_metadata();
        let private_id =
            "path+file:///fixture/private/eip-0045-profile/generator#eip-0045-generator@0.1.0";
        metadata["packages"][0]["id"] = json!(private_id);
        metadata["resolve"]["nodes"][0]["id"] = json!(private_id);

        let evidence = derived_evidence(&metadata, CargoClosureRole::GeneratorHost);
        let serialized = serde_json::to_string(&evidence).unwrap();
        assert!(!serialized.contains("/fixture/private"));
        assert!(!serialized.contains("file:///"));
        assert!(serialized.contains("path+eip-0045-profile/generator/Cargo.toml"));
        validate_cargo_closure(&metadata, &evidence, &root()).unwrap();
    }

    #[test]
    fn rejects_local_package_escape_and_prefix_collision() {
        for path in [
            "C:/fixture/private/other/Cargo.toml",
            "C:/fixture/private/eip-0045-profile-evil/Cargo.toml",
            "C:/fixture/private/eip-0045-profile/../escape/Cargo.toml",
        ] {
            let mut metadata = valid_metadata();
            metadata["packages"][0]["manifest_path"] = Value::String(path.to_owned());
            assert_eq!(
                validate_cargo_closure(&metadata, &valid_evidence(), &root()),
                Err(CargoClosureError::LocalPackageOutsideProfile)
            );
        }
    }

    #[test]
    fn rejects_registry_local_and_wrong_revision_risc0_packages() {
        let mut metadata = valid_metadata();
        metadata["packages"][1]["source"] =
            Value::String("registry+https://github.com/rust-lang/crates.io-index".to_owned());
        assert_eq!(
            validate_cargo_closure(&metadata, &valid_evidence(), &root()),
            Err(CargoClosureError::UnpinnedRisc0Package)
        );

        let mut metadata = valid_metadata();
        metadata["packages"][1]["source"] = Value::Null;
        assert_eq!(
            validate_cargo_closure(&metadata, &valid_evidence(), &root()),
            Err(CargoClosureError::UnpinnedRisc0Package)
        );

        let mut metadata = valid_metadata();
        metadata["packages"][1]["source"] = Value::String(format!(
            "git+{RISC0_CARGO_SOURCE_REPOSITORY}?rev={}#{}",
            "0".repeat(40),
            "0".repeat(40)
        ));
        assert_eq!(
            validate_cargo_closure(&metadata, &valid_evidence(), &root()),
            Err(CargoClosureError::UnpinnedRisc0Package)
        );
    }

    #[test]
    fn accepts_non_prefixed_package_from_exact_pinned_risc0_source() {
        let mut metadata = valid_metadata();
        metadata["packages"][2]["name"] = json!("rv32im");
        metadata["packages"][2]["source"] = json!(risc0_source());
        let evidence = derived_evidence(&metadata, CargoClosureRole::GeneratorHost);
        validate_cargo_closure(&metadata, &evidence, &root()).unwrap();
    }

    #[test]
    fn rejects_other_git_sources() {
        let mut metadata = valid_metadata();
        metadata["packages"][2]["source"] =
            Value::String("git+https://example.invalid/fork#0123456789abcdef".to_owned());
        assert_eq!(
            validate_cargo_closure(&metadata, &valid_evidence(), &root()),
            Err(CargoClosureError::UnsupportedPackageSource)
        );
    }

    #[test]
    fn rejects_all_configuration_influence_classes() {
        let mut cases = Vec::new();
        let mut evidence = valid_evidence();
        evidence.configuration.patches.push("x".to_owned());
        cases.push(evidence);
        let mut evidence = valid_evidence();
        evidence.configuration.replacements.push("x".to_owned());
        cases.push(evidence);
        let mut evidence = valid_evidence();
        evidence
            .configuration
            .source_replacements
            .push("x".to_owned());
        cases.push(evidence);
        let mut evidence = valid_evidence();
        evidence.configuration.path_overrides.push("x".to_owned());
        cases.push(evidence);
        let mut evidence = valid_evidence();
        evidence.configuration.rustc_wrapper = Some("sccache".to_owned());
        cases.push(evidence);
        let mut evidence = valid_evidence();
        evidence.configuration.rustc_workspace_wrapper = Some("wrapper".to_owned());
        cases.push(evidence);

        for evidence in cases {
            assert!(matches!(
                validate_cargo_closure(&valid_metadata(), &evidence, &root()),
                Err(CargoClosureError::ForbiddenConfiguration(_))
            ));
        }
    }

    #[test]
    fn rejects_default_missing_required_and_every_forbidden_feature() {
        let mut metadata = valid_metadata();
        metadata["resolve"]["nodes"][1]["features"] =
            json!(["client", "default", "disable-dev-mode", "prove"]);
        let mut evidence = valid_evidence();
        evidence.feature_tree[0].features = vec![
            "client".to_owned(),
            "default".to_owned(),
            "disable-dev-mode".to_owned(),
            "prove".to_owned(),
        ];
        assert_eq!(
            validate_cargo_closure(&metadata, &evidence, &root()),
            Err(CargoClosureError::DisallowedRisc0ZkvmFeature("default"))
        );

        let mut metadata = valid_metadata();
        metadata["resolve"]["nodes"][1]["features"] = json!(["client", "disable-dev-mode"]);
        let mut evidence = valid_evidence();
        evidence.feature_tree[0].features =
            vec!["client".to_owned(), "disable-dev-mode".to_owned()];
        assert_eq!(
            validate_cargo_closure(&metadata, &evidence, &root()),
            Err(CargoClosureError::MissingRequiredRisc0ZkvmFeature("prove"))
        );

        for forbidden in FORBIDDEN_FEATURES {
            let mut metadata = valid_metadata();
            metadata["resolve"]["nodes"][2]["features"] = json!(["derive", forbidden, "std"]);
            let mut evidence = valid_evidence();
            evidence.feature_tree[2].features =
                vec!["derive".to_owned(), forbidden.to_owned(), "std".to_owned()];
            assert!(matches!(
                validate_cargo_closure(&metadata, &evidence, &root()),
                Err(CargoClosureError::ForbiddenFeature | CargoClosureError::FeatureTreeMismatch)
            ));
        }
    }

    #[test]
    fn rejects_lying_incomplete_unsorted_or_duplicate_feature_evidence() {
        let mut evidence = valid_evidence();
        evidence.feature_tree[0].features.pop();
        assert_eq!(
            validate_cargo_closure(&valid_metadata(), &evidence, &root()),
            Err(CargoClosureError::FeatureTreeMismatch)
        );

        let mut evidence = valid_evidence();
        evidence.feature_tree.swap(0, 1);
        assert_eq!(
            validate_cargo_closure(&valid_metadata(), &evidence, &root()),
            Err(CargoClosureError::FeatureTreeMismatch)
        );

        let mut evidence = valid_evidence();
        evidence.feature_tree[0].features.push("prove".to_owned());
        assert_eq!(
            validate_cargo_closure(&valid_metadata(), &evidence, &root()),
            Err(CargoClosureError::FeatureTreeMismatch)
        );
    }

    #[test]
    fn rejects_path_like_public_identity_and_private_path_in_evidence() {
        assert_eq!(
            ProfileRootIdentity::new("C:/fixture/private/root", "C:/fixture/private/root"),
            Err(CargoClosureError::InvalidProfileRootIdentity)
        );
        let mut evidence = valid_evidence();
        evidence.profile_root_identity = "c-private-root".to_owned();
        assert_eq!(
            validate_cargo_closure(&valid_metadata(), &evidence, &root()),
            Err(CargoClosureError::InvalidEvidenceMarker(
                "profile root identity"
            ))
        );
    }

    #[test]
    fn strict_evidence_deserialization_rejects_unknown_fields() {
        let mut value = serde_json::to_value(valid_evidence()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("trustMe".to_owned(), Value::Bool(true));
        assert!(serde_json::from_value::<CargoClosureEvidence>(value).is_err());
    }
}
