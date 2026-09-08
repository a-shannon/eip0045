//! Pure validation for the candidate RISC Zero source-materialization lock.
//!
//! This module checks a supplied record. It does not read Git, OCI, LFS, or the
//! filesystem, and validation is not evidence that the recorded bytes were
//! independently obtained.

use core::fmt;
use serde::{Deserialize, Serialize};

use crate::constants::{
    GUEST_BUILDER_OCI_DIGEST, GUEST_BUILDER_OCI_PLATFORM, GUEST_BUILDER_OCI_REPOSITORY,
    GUEST_RUST_VERSION, HOST_RUST_OCI_DIGEST, HOST_RUST_OCI_PLATFORM, HOST_RUST_OCI_REPOSITORY,
    HOST_RUST_VERSION, RISC0_COMMIT, RISC0_REPOSITORY,
};

const SOURCE_TREE: &str = "a4e8abc0fffa0eab25f66266150f998f581f1cac";
// Exact Git-blob bytes (LF), independent of checkout line-ending conversion.
const CARGO_LOCK_LENGTH: u64 = 243_680;
const CARGO_LOCK_SHA256: &str = "5a108fef13e051f497679ef07ba887230ba355d281c109691dbcd24d92328382";
const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.docker.distribution.manifest.v2+json";
const OCI_CONFIG_MEDIA_TYPE: &str = "application/vnd.docker.container.image.v1+json";
const OCI_CONFIG_DIGEST: &str =
    "sha256:6ea2426d517508b8e0f61732150b1ca83f6e626737a6b2b5eed71e3e27b03536";
const OCI_CONFIG_SIZE: u64 = 3_703;
const HOST_OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const HOST_OCI_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
const HOST_OCI_CONFIG_DIGEST: &str =
    "sha256:4894a80c681567a132f49725f3fc179d12a004160f4dfa83acbc3046257dfcd7";
const HOST_OCI_CONFIG_SIZE: u64 = 2_945;
const HOST_TARGET: &str = "x86_64-unknown-linux-gnu";
const GUEST_TARGET: &str = "riscv32im-risc0-zkvm-elf";
const GENERATOR_BUILD_PROFILE: &str = "release";
const GUEST_BUILD_PROFILE: &str = "release";
const PROOF_POLICY_LIFECYCLE: &str = "unexercised-pending-b7";
const LOCAL_PROVER_BACKEND: &str = "risc0-local-in-process";
const LOCAL_PROVER_NAME: &str = "eip-0045-pinned-local";
const RECEIPT_KIND: &str = "succinct";
const RECEIPT_HASH_SUITE: &str = "poseidon2";
const CARGO_BUILD_JOBS: u16 = 2;
const CONTAINER_CPU_SET: &str = "0-3";
const CONTAINER_MEMORY_BYTES: u64 = 12 * 1024 * 1024 * 1024;

const LFS_FILES: [(&str, &str, u64, &str, &str, u64); 2] = [
    (
        "groth16_proof/groth16/stark_verify.circom",
        "a3789471909ba1a13cca783dc5269b25b6d41295abe60234a8075f750017518c",
        58_353_446,
        "81557c4f15ce43f5c7c840c287e76abd3a676cd5",
        "80fa1d37ad35395391e8115ea8e26e6f5d2b77a1b2ac321da5068903631a2463",
        133,
    ),
    (
        "risc0/circuit/recursion/src/recursion_zkr.zip",
        "744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849",
        59_768_781,
        "78e673e7dcbe0c04d3246db18645ae4b67c03c99",
        "34b81b81bd2664696b3a4ed1fbf385bd40443ca43b125b5eda3f9dc5fc32aceb",
        133,
    ),
];

/// Candidate record tying the source tree, LFS payloads, image, and toolchains
/// to a normalized materialized-file manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CandidateSourceLock {
    /// Schema identifier; currently exactly `eip0045-candidate-source-lock-v3`.
    pub schema: String,
    /// Lifecycle marker; must remain `candidate` until separate promotion gates.
    pub lifecycle: String,
    /// Exact upstream Git materialization.
    pub source: GitSourcePin,
    /// The two LFS objects required by the pinned tree.
    pub lfs_objects: Vec<LfsObjectPin>,
    /// Exact OCI guest-builder image materialization.
    pub guest_builder: OciImagePin,
    /// Exact OCI host Rust image materialization.
    pub host_rust: OciImagePin,
    /// Exact host and guest compiler selections.
    pub toolchains: ToolchainPins,
    /// Exact B4 build controls and the explicitly unexercised B7 proof policy.
    pub build: BuildPins,
    /// Normalized manifest of materialized regular files.
    pub materialized_files: MaterializedFileManifest,
}

/// Exact Git repository, commit, tree, and upstream lockfile identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GitSourcePin {
    /// Canonical upstream repository URL.
    pub repository: String,
    /// Full upstream commit object ID.
    pub commit: String,
    /// Full root-tree object ID reached by `commit`.
    pub tree: String,
    /// Byte identity of the upstream root `Cargo.lock`.
    pub cargo_lock: FileIdentity,
}

/// Length and SHA-256 identity for one regular file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FileIdentity {
    /// Exact byte length.
    pub byte_length: u64,
    /// Lowercase, unprefixed SHA-256 digest.
    pub sha256: String,
}

/// Git LFS pointer identity together with its materialized payload identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LfsObjectPin {
    /// Normalized repository-relative path.
    pub path: String,
    /// Lowercase, unprefixed SHA-256 OID from the Git LFS pointer.
    pub pointer_oid_sha256: String,
    /// Exact `size` from the Git LFS pointer.
    pub pointer_size: u64,
    /// SHA-1 object ID of the exact pointer blob committed in the Git tree.
    pub pointer_git_blob_sha1: String,
    /// Exact byte length of the committed Git LFS pointer.
    pub pointer_byte_length: u64,
    /// SHA-256 of the exact committed Git LFS pointer bytes.
    pub pointer_sha256: String,
    /// SHA-256 of the materialized payload.
    pub materialized_sha256: String,
    /// Exact materialized payload length.
    pub materialized_byte_length: u64,
}

/// Immutable OCI manifest, platform, and config identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OciImagePin {
    /// OCI repository without a mutable tag.
    pub repository: String,
    /// `sha256:`-prefixed manifest digest.
    pub manifest_digest: String,
    /// Exact manifest media type.
    pub manifest_media_type: String,
    /// Exact operating-system and architecture pair.
    pub platform: OciPlatform,
    /// Immutable image-config descriptor.
    pub config: OciDescriptor,
}

/// OCI operating system and architecture.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OciPlatform {
    /// OCI operating system.
    pub os: String,
    /// OCI CPU architecture.
    pub architecture: String,
}

/// OCI descriptor for the image configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OciDescriptor {
    /// Exact config media type.
    pub media_type: String,
    /// `sha256:`-prefixed config digest.
    pub digest: String,
    /// Exact config JSON byte length.
    pub byte_length: u64,
}

/// Host and guest compiler pins.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ToolchainPins {
    /// Host Rust release.
    pub host_rust: String,
    /// Rust compiler release embedded in the guest builder; the pinned host
    /// Cargo orchestrates the guest compilation through `risc0-build`.
    pub guest_rust: String,
    /// Host compilation target used for the generator and build scripts.
    pub host_target: String,
    /// RISC Zero guest compilation target.
    pub guest_target: String,
}

/// Frozen B4 compiler controls and separately declared B7 proof selections.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BuildPins {
    /// Cargo profile used for the candidate generator binary. The profile
    /// configuration is bound by the clean workspace Git tree and the
    /// workspace-source manifest emitted by the runner.
    pub generator_profile: String,
    /// Cargo profile used by `risc0-build` for the guest ELF. The profile
    /// configuration is bound by the clean workspace Git tree and the
    /// workspace-source manifest emitted by the runner.
    pub guest_profile: String,
    /// Exact maximum parallel Cargo job count, enforced in the Cargo config so
    /// it survives `risc0-build` removing inherited `CARGO*` variables.
    pub cargo_build_jobs: u16,
    /// Whether incremental compilation is admitted, enforced in the Cargo
    /// config across both host and nested guest builds.
    pub cargo_incremental: PolicySwitch,
    /// Exact container CPU affinity used by the B4 guest build.
    pub container_cpu_set: String,
    /// Exact container memory ceiling in bytes, with no additional swap.
    pub container_memory_bytes: u64,
    /// Lifecycle marker proving that the following proof controls were not
    /// exercised by B4 and remain pending the B7 proof-generation gate.
    pub proof_policy_lifecycle: String,
    /// Planned B7 in-process prover backend; not observed during B4.
    pub planned_local_prover_backend: String,
    /// Planned B7 local-prover name; not observed during B4.
    pub planned_local_prover_name: String,
    /// Planned B7 receipt kind; not observed during B4.
    pub planned_receipt_kind: String,
    /// Planned B7 receipt hash suite; not observed during B4.
    pub planned_hash_suite: String,
    /// Planned B7 RISC Zero development-mode setting; not observed during B4.
    pub planned_dev_mode: PolicySwitch,
    /// Planned B7 verifier-context development-mode setting; not observed
    /// during B4.
    pub planned_verifier_dev_mode: PolicySwitch,
    /// Planned B7 guest-error proving setting; not observed during B4.
    pub planned_prove_guest_errors: PolicySwitch,
}

/// Closed enabled/disabled state used by candidate build-policy fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicySwitch {
    /// The behavior is forbidden.
    Disabled,
    /// The behavior is enabled; current candidate validation rejects it.
    Enabled,
}

/// Normalized regular-file inventory for one materialized Git tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MaterializedFileManifest {
    /// Schema identifier; currently exactly `eip0045-materialized-files-v1`.
    pub schema: String,
    /// Root Git tree described by the inventory.
    pub source_tree: String,
    /// Strictly path-sorted, duplicate-free regular-file entries.
    pub entries: Vec<MaterializedFileEntry>,
}

/// One normalized materialized regular-file entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MaterializedFileEntry {
    /// Normalized repository-relative path using `/` separators.
    pub path: String,
    /// Exact file byte length.
    pub byte_length: u64,
    /// Lowercase, unprefixed SHA-256 digest.
    pub sha256: String,
    /// Whether the Git executable bit is set.
    pub executable: bool,
}

/// Failure returned by pure candidate source-lock validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceLockError {
    /// A top-level schema or lifecycle marker is not the candidate value.
    InvalidMarker(&'static str),
    /// A frozen source, image, toolchain, or digest pin differs.
    PinMismatch(&'static str),
    /// The LFS set is missing, reordered, duplicated, or inconsistent.
    InvalidLfsObject(usize),
    /// A materialized path is not canonical and repository-relative.
    InvalidPath(usize),
    /// Materialized entries are not in strict bytewise path order.
    NonCanonicalOrder(usize),
    /// A file digest is not lowercase SHA-256.
    InvalidDigest(usize),
    /// A pinned required file is absent or has the wrong identity.
    RequiredFileMismatch(&'static str),
    /// The inventory is empty.
    EmptyMaterializedManifest,
}

impl fmt::Display for SourceLockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMarker(name) => write!(formatter, "invalid candidate marker: {name}"),
            Self::PinMismatch(name) => write!(formatter, "candidate source pin mismatch: {name}"),
            Self::InvalidLfsObject(index) => {
                write!(formatter, "invalid LFS object at index {index}")
            }
            Self::InvalidPath(index) => {
                write!(formatter, "invalid materialized path at index {index}")
            }
            Self::NonCanonicalOrder(index) => write!(
                formatter,
                "materialized paths are not strictly ordered at index {index}"
            ),
            Self::InvalidDigest(index) => {
                write!(formatter, "invalid materialized digest at index {index}")
            }
            Self::RequiredFileMismatch(name) => {
                write!(formatter, "required materialized file mismatch: {name}")
            }
            Self::EmptyMaterializedManifest => {
                formatter.write_str("materialized manifest is empty")
            }
        }
    }
}

impl std::error::Error for SourceLockError {}

impl CandidateSourceLock {
    /// Construct and validate the candidate lock around one captured
    /// materialized-file inventory.
    ///
    /// All source, LFS, OCI, and toolchain pins come from this package's
    /// compiled candidate profile. The caller remains responsible for proving
    /// that `entries` were captured from the checkout and images used by the
    /// run; this constructor does not perform external reads.
    ///
    /// # Errors
    ///
    /// Returns the first malformed inventory or frozen-pin mismatch.
    pub fn from_materialized_entries(
        entries: Vec<MaterializedFileEntry>,
    ) -> Result<Self, SourceLockError> {
        let candidate = Self {
            schema: "eip0045-candidate-source-lock-v3".to_owned(),
            lifecycle: "candidate".to_owned(),
            source: GitSourcePin {
                repository: RISC0_REPOSITORY.to_owned(),
                commit: RISC0_COMMIT.to_owned(),
                tree: SOURCE_TREE.to_owned(),
                cargo_lock: FileIdentity {
                    byte_length: CARGO_LOCK_LENGTH,
                    sha256: CARGO_LOCK_SHA256.to_owned(),
                },
            },
            lfs_objects: LFS_FILES
                .iter()
                .map(
                    |(path, digest, length, pointer_blob, pointer_digest, pointer_length)| {
                        LfsObjectPin {
                            path: (*path).to_owned(),
                            pointer_oid_sha256: (*digest).to_owned(),
                            pointer_size: *length,
                            pointer_git_blob_sha1: (*pointer_blob).to_owned(),
                            pointer_byte_length: *pointer_length,
                            pointer_sha256: (*pointer_digest).to_owned(),
                            materialized_sha256: (*digest).to_owned(),
                            materialized_byte_length: *length,
                        }
                    },
                )
                .collect(),
            guest_builder: OciImagePin {
                repository: GUEST_BUILDER_OCI_REPOSITORY.to_owned(),
                manifest_digest: GUEST_BUILDER_OCI_DIGEST.to_owned(),
                manifest_media_type: OCI_MANIFEST_MEDIA_TYPE.to_owned(),
                platform: split_platform(GUEST_BUILDER_OCI_PLATFORM),
                config: OciDescriptor {
                    media_type: OCI_CONFIG_MEDIA_TYPE.to_owned(),
                    digest: OCI_CONFIG_DIGEST.to_owned(),
                    byte_length: OCI_CONFIG_SIZE,
                },
            },
            host_rust: OciImagePin {
                repository: HOST_RUST_OCI_REPOSITORY.to_owned(),
                manifest_digest: HOST_RUST_OCI_DIGEST.to_owned(),
                manifest_media_type: HOST_OCI_MANIFEST_MEDIA_TYPE.to_owned(),
                platform: split_platform(HOST_RUST_OCI_PLATFORM),
                config: OciDescriptor {
                    media_type: HOST_OCI_CONFIG_MEDIA_TYPE.to_owned(),
                    digest: HOST_OCI_CONFIG_DIGEST.to_owned(),
                    byte_length: HOST_OCI_CONFIG_SIZE,
                },
            },
            toolchains: ToolchainPins {
                host_rust: HOST_RUST_VERSION.to_owned(),
                guest_rust: GUEST_RUST_VERSION.to_owned(),
                host_target: HOST_TARGET.to_owned(),
                guest_target: GUEST_TARGET.to_owned(),
            },
            build: BuildPins {
                generator_profile: GENERATOR_BUILD_PROFILE.to_owned(),
                guest_profile: GUEST_BUILD_PROFILE.to_owned(),
                cargo_build_jobs: CARGO_BUILD_JOBS,
                cargo_incremental: PolicySwitch::Disabled,
                container_cpu_set: CONTAINER_CPU_SET.to_owned(),
                container_memory_bytes: CONTAINER_MEMORY_BYTES,
                proof_policy_lifecycle: PROOF_POLICY_LIFECYCLE.to_owned(),
                planned_local_prover_backend: LOCAL_PROVER_BACKEND.to_owned(),
                planned_local_prover_name: LOCAL_PROVER_NAME.to_owned(),
                planned_receipt_kind: RECEIPT_KIND.to_owned(),
                planned_hash_suite: RECEIPT_HASH_SUITE.to_owned(),
                planned_dev_mode: PolicySwitch::Disabled,
                planned_verifier_dev_mode: PolicySwitch::Disabled,
                planned_prove_guest_errors: PolicySwitch::Disabled,
            },
            materialized_files: MaterializedFileManifest {
                schema: "eip0045-materialized-files-v1".to_owned(),
                source_tree: SOURCE_TREE.to_owned(),
                entries,
            },
        };
        candidate.validate()?;
        Ok(candidate)
    }

    /// Validate all frozen pins and normalized materialized-file rules.
    ///
    /// # Errors
    ///
    /// Returns the first marker, pin, LFS, path, ordering, or required-file
    /// mismatch. This function performs no external reads.
    pub fn validate(&self) -> Result<(), SourceLockError> {
        if self.schema != "eip0045-candidate-source-lock-v3" {
            return Err(SourceLockError::InvalidMarker("schema"));
        }
        if self.lifecycle != "candidate" {
            return Err(SourceLockError::InvalidMarker("lifecycle"));
        }
        validate_source(&self.source)?;
        validate_lfs(&self.lfs_objects)?;
        validate_guest_oci(&self.guest_builder)?;
        validate_host_oci(&self.host_rust)?;
        validate_toolchains(&self.toolchains)?;
        validate_build(&self.build)?;
        self.materialized_files.validate()?;
        if self.materialized_files.source_tree != self.source.tree {
            return Err(SourceLockError::PinMismatch("materialized source tree"));
        }
        require_materialized_file(
            &self.materialized_files.entries,
            "Cargo.lock",
            CARGO_LOCK_LENGTH,
            CARGO_LOCK_SHA256,
            "Cargo.lock",
        )?;
        for (path, digest, length, _, _, _) in LFS_FILES {
            require_materialized_file(
                &self.materialized_files.entries,
                path,
                length,
                digest,
                "Git LFS payload",
            )?;
        }
        Ok(())
    }
}

fn split_platform(value: &str) -> OciPlatform {
    let (os, architecture) = value
        .split_once('/')
        .expect("frozen OCI platform has an os/architecture separator");
    OciPlatform {
        os: os.to_owned(),
        architecture: architecture.to_owned(),
    }
}

impl MaterializedFileManifest {
    /// Validate schema, tree identity, path normalization, ordering, and hashes.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty inventory or the first malformed entry.
    pub fn validate(&self) -> Result<(), SourceLockError> {
        if self.schema != "eip0045-materialized-files-v1" {
            return Err(SourceLockError::InvalidMarker("file-manifest schema"));
        }
        if self.source_tree != SOURCE_TREE {
            return Err(SourceLockError::PinMismatch("file-manifest source tree"));
        }
        if self.entries.is_empty() {
            return Err(SourceLockError::EmptyMaterializedManifest);
        }
        let mut previous: Option<&str> = None;
        for (index, entry) in self.entries.iter().enumerate() {
            if !is_normalized_repo_path(&entry.path) {
                return Err(SourceLockError::InvalidPath(index));
            }
            if previous.is_some_and(|path| path.as_bytes() >= entry.path.as_bytes()) {
                return Err(SourceLockError::NonCanonicalOrder(index));
            }
            if !is_lower_hex(&entry.sha256, 64) {
                return Err(SourceLockError::InvalidDigest(index));
            }
            previous = Some(&entry.path);
        }
        Ok(())
    }
}

fn validate_source(source: &GitSourcePin) -> Result<(), SourceLockError> {
    if source.repository != RISC0_REPOSITORY {
        return Err(SourceLockError::PinMismatch("repository"));
    }
    if source.commit != RISC0_COMMIT || !is_lower_hex(&source.commit, 40) {
        return Err(SourceLockError::PinMismatch("commit"));
    }
    if source.tree != SOURCE_TREE || !is_lower_hex(&source.tree, 40) {
        return Err(SourceLockError::PinMismatch("tree"));
    }
    if source.cargo_lock.byte_length != CARGO_LOCK_LENGTH
        || source.cargo_lock.sha256 != CARGO_LOCK_SHA256
    {
        return Err(SourceLockError::PinMismatch("upstream Cargo.lock"));
    }
    Ok(())
}

fn validate_lfs(objects: &[LfsObjectPin]) -> Result<(), SourceLockError> {
    if objects.len() != LFS_FILES.len() {
        return Err(SourceLockError::PinMismatch("Git LFS object count"));
    }
    for (index, (object, (path, digest, length, pointer_blob, pointer_digest, pointer_length))) in
        objects.iter().zip(LFS_FILES).enumerate()
    {
        if object.path != path
            || object.pointer_oid_sha256 != digest
            || object.pointer_size != length
            || object.pointer_git_blob_sha1 != pointer_blob
            || object.pointer_byte_length != pointer_length
            || object.pointer_sha256 != pointer_digest
            || object.materialized_sha256 != digest
            || object.materialized_byte_length != length
        {
            return Err(SourceLockError::InvalidLfsObject(index));
        }
    }
    Ok(())
}

fn validate_guest_oci(image: &OciImagePin) -> Result<(), SourceLockError> {
    let expected_platform = GUEST_BUILDER_OCI_PLATFORM
        .split_once('/')
        .expect("frozen OCI platform has an os/architecture separator");
    if image.repository != GUEST_BUILDER_OCI_REPOSITORY
        || image.manifest_digest != GUEST_BUILDER_OCI_DIGEST
        || image.manifest_media_type != OCI_MANIFEST_MEDIA_TYPE
        || image.platform.os != expected_platform.0
        || image.platform.architecture != expected_platform.1
        || image.config.media_type != OCI_CONFIG_MEDIA_TYPE
        || image.config.digest != OCI_CONFIG_DIGEST
        || image.config.byte_length != OCI_CONFIG_SIZE
    {
        return Err(SourceLockError::PinMismatch("OCI image"));
    }
    Ok(())
}

fn validate_host_oci(image: &OciImagePin) -> Result<(), SourceLockError> {
    let expected_platform = HOST_RUST_OCI_PLATFORM
        .split_once('/')
        .expect("frozen host OCI platform has an os/architecture separator");
    if image.repository != HOST_RUST_OCI_REPOSITORY
        || image.manifest_digest != HOST_RUST_OCI_DIGEST
        || image.manifest_media_type != HOST_OCI_MANIFEST_MEDIA_TYPE
        || image.platform.os != expected_platform.0
        || image.platform.architecture != expected_platform.1
        || image.config.media_type != HOST_OCI_CONFIG_MEDIA_TYPE
        || image.config.digest != HOST_OCI_CONFIG_DIGEST
        || image.config.byte_length != HOST_OCI_CONFIG_SIZE
    {
        return Err(SourceLockError::PinMismatch("host Rust OCI image"));
    }
    Ok(())
}

fn validate_toolchains(toolchains: &ToolchainPins) -> Result<(), SourceLockError> {
    if toolchains.host_rust != HOST_RUST_VERSION
        || toolchains.guest_rust != GUEST_RUST_VERSION
        || toolchains.host_target != HOST_TARGET
        || toolchains.guest_target != GUEST_TARGET
    {
        return Err(SourceLockError::PinMismatch("toolchains"));
    }
    Ok(())
}

fn validate_build(build: &BuildPins) -> Result<(), SourceLockError> {
    if build.generator_profile != GENERATOR_BUILD_PROFILE
        || build.guest_profile != GUEST_BUILD_PROFILE
        || build.cargo_build_jobs != CARGO_BUILD_JOBS
        || build.cargo_incremental != PolicySwitch::Disabled
        || build.container_cpu_set != CONTAINER_CPU_SET
        || build.container_memory_bytes != CONTAINER_MEMORY_BYTES
        || build.proof_policy_lifecycle != PROOF_POLICY_LIFECYCLE
        || build.planned_local_prover_backend != LOCAL_PROVER_BACKEND
        || build.planned_local_prover_name != LOCAL_PROVER_NAME
        || build.planned_receipt_kind != RECEIPT_KIND
        || build.planned_hash_suite != RECEIPT_HASH_SUITE
        || build.planned_dev_mode != PolicySwitch::Disabled
        || build.planned_verifier_dev_mode != PolicySwitch::Disabled
        || build.planned_prove_guest_errors != PolicySwitch::Disabled
    {
        return Err(SourceLockError::PinMismatch(
            "B4 build controls or pending B7 proof policy",
        ));
    }
    Ok(())
}

fn require_materialized_file(
    entries: &[MaterializedFileEntry],
    path: &str,
    byte_length: u64,
    sha256: &str,
    label: &'static str,
) -> Result<(), SourceLockError> {
    let entry = entries
        .binary_search_by(|entry| entry.path.as_str().cmp(path))
        .ok()
        .and_then(|index| entries.get(index))
        .ok_or(SourceLockError::RequiredFileMismatch(label))?;
    if entry.byte_length != byte_length || entry.sha256 != sha256 || entry.executable {
        return Err(SourceLockError::RequiredFileMismatch(label));
    }
    Ok(())
}

fn is_normalized_repo_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.ends_with('/')
        && !path.contains('\\')
        && !path.contains(':')
        && path.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        && path.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component != ".git"
                && !component.ends_with(['.', ' '])
        })
}

fn is_lower_hex(value: &str, exact_len: usize) -> bool {
    value.len() == exact_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, length: u64, digest: &str) -> MaterializedFileEntry {
        MaterializedFileEntry {
            path: path.to_owned(),
            byte_length: length,
            sha256: digest.to_owned(),
            executable: false,
        }
    }

    fn valid_lock() -> CandidateSourceLock {
        CandidateSourceLock {
            schema: "eip0045-candidate-source-lock-v3".to_owned(),
            lifecycle: "candidate".to_owned(),
            source: GitSourcePin {
                repository: RISC0_REPOSITORY.to_owned(),
                commit: RISC0_COMMIT.to_owned(),
                tree: SOURCE_TREE.to_owned(),
                cargo_lock: FileIdentity {
                    byte_length: CARGO_LOCK_LENGTH,
                    sha256: CARGO_LOCK_SHA256.to_owned(),
                },
            },
            lfs_objects: LFS_FILES
                .iter()
                .map(
                    |(path, digest, length, pointer_blob, pointer_digest, pointer_length)| {
                        LfsObjectPin {
                            path: (*path).to_owned(),
                            pointer_oid_sha256: (*digest).to_owned(),
                            pointer_size: *length,
                            pointer_git_blob_sha1: (*pointer_blob).to_owned(),
                            pointer_byte_length: *pointer_length,
                            pointer_sha256: (*pointer_digest).to_owned(),
                            materialized_sha256: (*digest).to_owned(),
                            materialized_byte_length: *length,
                        }
                    },
                )
                .collect(),
            guest_builder: OciImagePin {
                repository: GUEST_BUILDER_OCI_REPOSITORY.to_owned(),
                manifest_digest: GUEST_BUILDER_OCI_DIGEST.to_owned(),
                manifest_media_type: OCI_MANIFEST_MEDIA_TYPE.to_owned(),
                platform: OciPlatform {
                    os: "linux".to_owned(),
                    architecture: "amd64".to_owned(),
                },
                config: OciDescriptor {
                    media_type: OCI_CONFIG_MEDIA_TYPE.to_owned(),
                    digest: OCI_CONFIG_DIGEST.to_owned(),
                    byte_length: OCI_CONFIG_SIZE,
                },
            },
            host_rust: OciImagePin {
                repository: HOST_RUST_OCI_REPOSITORY.to_owned(),
                manifest_digest: HOST_RUST_OCI_DIGEST.to_owned(),
                manifest_media_type: HOST_OCI_MANIFEST_MEDIA_TYPE.to_owned(),
                platform: OciPlatform {
                    os: "linux".to_owned(),
                    architecture: "amd64".to_owned(),
                },
                config: OciDescriptor {
                    media_type: HOST_OCI_CONFIG_MEDIA_TYPE.to_owned(),
                    digest: HOST_OCI_CONFIG_DIGEST.to_owned(),
                    byte_length: HOST_OCI_CONFIG_SIZE,
                },
            },
            toolchains: ToolchainPins {
                host_rust: HOST_RUST_VERSION.to_owned(),
                guest_rust: GUEST_RUST_VERSION.to_owned(),
                host_target: HOST_TARGET.to_owned(),
                guest_target: GUEST_TARGET.to_owned(),
            },
            build: BuildPins {
                generator_profile: GENERATOR_BUILD_PROFILE.to_owned(),
                guest_profile: GUEST_BUILD_PROFILE.to_owned(),
                cargo_build_jobs: CARGO_BUILD_JOBS,
                cargo_incremental: PolicySwitch::Disabled,
                container_cpu_set: CONTAINER_CPU_SET.to_owned(),
                container_memory_bytes: CONTAINER_MEMORY_BYTES,
                proof_policy_lifecycle: PROOF_POLICY_LIFECYCLE.to_owned(),
                planned_local_prover_backend: LOCAL_PROVER_BACKEND.to_owned(),
                planned_local_prover_name: LOCAL_PROVER_NAME.to_owned(),
                planned_receipt_kind: RECEIPT_KIND.to_owned(),
                planned_hash_suite: RECEIPT_HASH_SUITE.to_owned(),
                planned_dev_mode: PolicySwitch::Disabled,
                planned_verifier_dev_mode: PolicySwitch::Disabled,
                planned_prove_guest_errors: PolicySwitch::Disabled,
            },
            materialized_files: MaterializedFileManifest {
                schema: "eip0045-materialized-files-v1".to_owned(),
                source_tree: SOURCE_TREE.to_owned(),
                entries: vec![
                    entry("Cargo.lock", CARGO_LOCK_LENGTH, CARGO_LOCK_SHA256),
                    entry(LFS_FILES[0].0, LFS_FILES[0].2, LFS_FILES[0].1),
                    entry(LFS_FILES[1].0, LFS_FILES[1].2, LFS_FILES[1].1),
                ],
            },
        }
    }

    #[test]
    fn accepts_exact_candidate_lock() {
        valid_lock().validate().unwrap();
    }

    #[test]
    fn constructor_freezes_every_non_inventory_field() {
        let expected = valid_lock();
        let actual = CandidateSourceLock::from_materialized_entries(
            expected.materialized_files.entries.clone(),
        )
        .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn rejects_a_final_lifecycle_claim() {
        let mut lock = valid_lock();
        lock.lifecycle = "final".to_owned();
        assert_eq!(
            lock.validate(),
            Err(SourceLockError::InvalidMarker("lifecycle"))
        );
    }

    #[test]
    fn rejects_commit_tree_and_lockfile_drift() {
        let mut lock = valid_lock();
        lock.source.tree.replace_range(..1, "0");
        assert_eq!(lock.validate(), Err(SourceLockError::PinMismatch("tree")));

        let mut lock = valid_lock();
        lock.source.cargo_lock.byte_length += 1;
        assert_eq!(
            lock.validate(),
            Err(SourceLockError::PinMismatch("upstream Cargo.lock"))
        );
    }

    #[test]
    fn rejects_target_profile_and_pending_b7_proof_policy_drift() {
        let mut lock = valid_lock();
        lock.toolchains.host_target = "aarch64-unknown-linux-gnu".to_owned();
        assert_eq!(
            lock.validate(),
            Err(SourceLockError::PinMismatch("toolchains"))
        );

        let mut lock = valid_lock();
        lock.build.generator_profile = "debug".to_owned();
        assert_eq!(
            lock.validate(),
            Err(SourceLockError::PinMismatch(
                "B4 build controls or pending B7 proof policy"
            ))
        );

        let mut lock = valid_lock();
        lock.build.proof_policy_lifecycle = "observed-in-b4".to_owned();
        assert_eq!(
            lock.validate(),
            Err(SourceLockError::PinMismatch(
                "B4 build controls or pending B7 proof policy"
            ))
        );

        let mut lock = valid_lock();
        lock.build.planned_dev_mode = PolicySwitch::Enabled;
        assert_eq!(
            lock.validate(),
            Err(SourceLockError::PinMismatch(
                "B4 build controls or pending B7 proof policy"
            ))
        );
    }

    #[test]
    fn rejects_pointer_payload_substitution_and_lfs_reordering() {
        let mut lock = valid_lock();
        lock.lfs_objects[0].pointer_sha256 = "00".repeat(32);
        assert_eq!(lock.validate(), Err(SourceLockError::InvalidLfsObject(0)));

        let mut lock = valid_lock();
        lock.lfs_objects[0].materialized_sha256 = "00".repeat(32);
        assert_eq!(lock.validate(), Err(SourceLockError::InvalidLfsObject(0)));

        let mut lock = valid_lock();
        lock.lfs_objects.swap(0, 1);
        assert_eq!(lock.validate(), Err(SourceLockError::InvalidLfsObject(0)));
    }

    #[test]
    fn rejects_mutable_or_wrong_platform_image_identity() {
        let mut lock = valid_lock();
        lock.guest_builder.manifest_digest = "latest".to_owned();
        assert_eq!(
            lock.validate(),
            Err(SourceLockError::PinMismatch("OCI image"))
        );

        let mut lock = valid_lock();
        lock.guest_builder.platform.architecture = "arm64".to_owned();
        assert_eq!(
            lock.validate(),
            Err(SourceLockError::PinMismatch("OCI image"))
        );
    }

    #[test]
    fn rejects_every_host_rust_oci_identity_drift() {
        let mut lock = valid_lock();
        lock.host_rust.manifest_digest = "sha256:00".to_owned();
        assert_eq!(
            lock.validate(),
            Err(SourceLockError::PinMismatch("host Rust OCI image"))
        );

        let mut lock = valid_lock();
        lock.host_rust.manifest_media_type = OCI_MANIFEST_MEDIA_TYPE.to_owned();
        assert_eq!(
            lock.validate(),
            Err(SourceLockError::PinMismatch("host Rust OCI image"))
        );

        let mut lock = valid_lock();
        lock.host_rust.platform.architecture = "arm64".to_owned();
        assert_eq!(
            lock.validate(),
            Err(SourceLockError::PinMismatch("host Rust OCI image"))
        );

        let mut lock = valid_lock();
        lock.host_rust.config.digest = OCI_CONFIG_DIGEST.to_owned();
        assert_eq!(
            lock.validate(),
            Err(SourceLockError::PinMismatch("host Rust OCI image"))
        );

        let mut lock = valid_lock();
        lock.host_rust.config.media_type = OCI_CONFIG_MEDIA_TYPE.to_owned();
        assert_eq!(
            lock.validate(),
            Err(SourceLockError::PinMismatch("host Rust OCI image"))
        );

        let mut lock = valid_lock();
        lock.host_rust.config.byte_length += 1;
        assert_eq!(
            lock.validate(),
            Err(SourceLockError::PinMismatch("host Rust OCI image"))
        );
    }

    #[test]
    fn rejects_noncanonical_duplicate_and_traversal_paths() {
        let mut lock = valid_lock();
        lock.materialized_files.entries[1].path = "z".to_owned();
        assert_eq!(lock.validate(), Err(SourceLockError::NonCanonicalOrder(2)));

        let mut lock = valid_lock();
        lock.materialized_files.entries[1].path = "Cargo.lock".to_owned();
        assert_eq!(lock.validate(), Err(SourceLockError::NonCanonicalOrder(1)));

        let mut lock = valid_lock();
        lock.materialized_files.entries[1].path = "../escape".to_owned();
        assert_eq!(lock.validate(), Err(SourceLockError::InvalidPath(1)));

        for path in [".git/config", "unicode/\u{e9}.txt", "ambiguous/name. "] {
            let mut lock = valid_lock();
            lock.materialized_files.entries[1].path = path.to_owned();
            assert_eq!(lock.validate(), Err(SourceLockError::InvalidPath(1)));
        }
    }

    #[test]
    fn rejects_missing_or_mismatched_materialized_required_files() {
        let mut lock = valid_lock();
        lock.materialized_files.entries[0].sha256 = "00".repeat(32);
        assert_eq!(
            lock.validate(),
            Err(SourceLockError::RequiredFileMismatch("Cargo.lock"))
        );

        let mut lock = valid_lock();
        lock.materialized_files.entries.remove(2);
        assert_eq!(
            lock.validate(),
            Err(SourceLockError::RequiredFileMismatch("Git LFS payload"))
        );
    }

    #[test]
    fn strict_deserialization_rejects_unknown_fields() {
        let mut value = serde_json::to_value(valid_lock()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unreviewed".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<CandidateSourceLock>(value).is_err());
    }

    #[test]
    fn serialized_proof_policy_is_explicitly_planned_and_pending_b7() {
        let value = serde_json::to_value(valid_lock()).unwrap();
        let build = value
            .get("build")
            .and_then(serde_json::Value::as_object)
            .unwrap();
        assert_eq!(
            build
                .get("proofPolicyLifecycle")
                .and_then(serde_json::Value::as_str),
            Some("unexercised-pending-b7")
        );
        for planned in [
            "plannedLocalProverBackend",
            "plannedLocalProverName",
            "plannedReceiptKind",
            "plannedHashSuite",
            "plannedDevMode",
            "plannedVerifierDevMode",
            "plannedProveGuestErrors",
        ] {
            assert!(
                build.contains_key(planned),
                "missing planned B7 field: {planned}"
            );
        }
        for misleading_b4_observation in [
            "localProverBackend",
            "localProverName",
            "receiptKind",
            "hashSuite",
            "devMode",
            "verifierDevMode",
            "proveGuestErrors",
        ] {
            assert!(
                !build.contains_key(misleading_b4_observation),
                "B7 policy was serialized as a B4 observation: {misleading_b4_observation}"
            );
        }
    }

    struct B4RunnerScripts {
        powershell: &'static str,
        bash: &'static str,
        container: &'static str,
        diagnostics: &'static str,
        observability_test: &'static str,
        powershell_native: &'static str,
        powershell_observability: &'static str,
    }

    fn b4_runner_scripts() -> B4RunnerScripts {
        B4RunnerScripts {
            powershell: include_str!("../b4-build.ps1"),
            bash: include_str!("../b4-build.sh"),
            container: include_str!("../b4-build/container-build.sh"),
            diagnostics: include_str!("../b4-build/diagnostics.sh"),
            observability_test: include_str!("../b4-build/test-observability.sh"),
            powershell_native: include_str!("../b4-build/native-command.ps1"),
            powershell_observability: include_str!("../b4-build/test-observability.ps1"),
        }
    }

    fn assert_b4_shared_runner_configuration(scripts: &B4RunnerScripts) {
        for shared in [
            "sha256:1aa2ca80b59886af9ab34cf9775a567a80aacb03c0c29176c9120e1f34fcd855",
            "sha256:e89c6b7bdb6d5dbf7456f550fd17e8983edba597881a9a8e806b1bc589ac3074",
            "risczero/risc0-guest-builder@sha256:3e12f71bacd27527a61dea96fa0e53e468c99aa261d3a1019b593f6dbd943eb3",
            "rust@sha256:294917190b5a3fed18d3303213943f40ec9b644b3cd6e5cdc8cd029334a770b3",
            "2026-02-03T00:19:36Z",
            "eip0045-b4-build-completion-v2",
            "path-disjoint-standalone-clean-checkouts-private-object-stores-and-seeds",
            "fresh-home-target-and-work-per-run-same-pinned-runtime",
        ] {
            assert!(
                scripts.powershell.contains(shared),
                "PowerShell runner lost {shared}"
            );
            assert!(scripts.bash.contains(shared), "Bash runner lost {shared}");
        }
        for shared_policy in [
            "cargoProfileConfigurationBinding=clean-workspace-git-tree-and-workspace-source-manifest",
            "proofPolicyLifecycle=unexercised-pending-b7",
            "plannedLocalProverBackend=risc0-local-in-process",
            "plannedReceiptKind=succinct",
            "plannedHashSuite=poseidon2",
            "plannedDevMode=disabled",
        ] {
            assert!(
                scripts.container.contains(shared_policy),
                "container policy lost {shared_policy}"
            );
        }
        assert!(scripts.powershell.contains("'--cpuset-cpus', '0-3'"));
        assert!(scripts.bash.contains("--cpuset-cpus 0-3"));
        assert!(
            scripts
                .powershell
                .contains("'--memory', '12g', '--memory-swap', '12g'")
        );
        assert!(scripts.bash.contains("--memory 12g --memory-swap 12g"));
        assert!(
            scripts
                .container
                .contains("[ \"$observed_cpu_set\" = 0-3 ]")
        );
        assert!(
            scripts
                .container
                .contains("[ \"$observed_memory_max\" = 12884901888 ]")
        );
    }

    fn assert_b4_runner_observability_configuration(scripts: &B4RunnerScripts) {
        for runner in [scripts.powershell, scripts.bash] {
            assert!(runner.contains("host-diagnostics"));
            assert!(runner.contains("container-inspect.json"));
            assert!(runner.contains("container-logs.txt"));
            assert!(runner.contains("retained for diagnosis"));
            assert!(runner.contains("docker"));
            assert!(runner.contains("run-status.txt"));
        }
        assert!(scripts.bash.contains("docker rm"));
        assert!(scripts.powershell.contains("@('rm', $Name)"));
        assert!(!scripts.powershell.contains("'--rm'"));
        assert!(!scripts.bash.contains("docker run --rm"));
        assert!(
            scripts
                .powershell
                .contains("PSNativeCommandUseErrorActionPreference = $false")
        );
        for contract in [
            "Invoke-B4NativeCapture",
            "Invoke-B4NativePassthrough",
            "--allow-unanchored-inspection",
            "Assert-B4NoDescendantHardLink",
            "Assert-B4StandaloneGitCheckout",
            "storage=standalone-private-object-store",
        ] {
            assert!(scripts.powershell.contains(contract));
        }
        for contract in [
            "--allow-unanchored-inspection",
            "b4_diag_reject_hard_links",
            "b4_git_assert_standalone_checkout",
            "storage=standalone-private-object-store",
        ] {
            assert!(scripts.bash.contains(contract));
        }
        for contract in [
            "$ErrorActionPreference = 'Continue'",
            "finally",
            "Assert-B4PlainSingleLinkFile $final",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        ] {
            assert!(scripts.powershell_native.contains(contract));
        }
        assert!(
            scripts
                .diagnostics
                .contains("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        );
        for contract in [
            "b4_normalize_cargo_checkout_pack_hard_links",
            "cp --reflink=never",
            "--preserve=mode",
            "Cargo checkout hardlinks are not exactly one matching pack/index pair",
        ] {
            assert!(
                scripts.diagnostics.contains(contract),
                "Cargo checkout hardlink normalizer lost {contract}"
            );
        }
        assert!(
            scripts
                .observability_test
                .contains("run_cargo_checkout_unexpected_location_cases")
        );
        assert!(
            scripts
                .observability_test
                .contains("run_cargo_checkout_topology_cases")
        );
        assert!(
            scripts
                .observability_test
                .contains("run_cargo_checkout_copy_and_replace_faults")
        );
        assert!(
            scripts
                .powershell_observability
                .contains("Get-B4WindowsHardLinkCount")
        );
        assert!(scripts.powershell_observability.contains("worktree"));
        assert!(
            scripts
                .observability_test
                .contains("kind=forbidden-hard-link")
        );
        assert!(scripts.observability_test.contains("worktree"));
    }

    fn assert_b4_container_guard_contract(scripts: &B4RunnerScripts) {
        for guard_contract in [
            "Initialize-B4ContainerGuard",
            "Start-B4ContainerGuard",
            "Set-B4ContainerInspected",
            "Complete-B4ContainerRemoval",
            "Test-B4ContainerBindSourcesMustRemain",
            "Write-B4ContainerUncertainty",
            "eip0045-b4-host-container-presence-v1",
        ] {
            assert!(
                scripts.powershell_native.contains(guard_contract),
                "PowerShell container guard lost {guard_contract}"
            );
        }
        for guard_contract in [
            "b4_host_container_guard_init",
            "b4_host_container_guard_before_run",
            "b4_host_container_guard_mark_inspected",
            "b4_host_container_guard_mark_removed",
            "b4_host_container_guard_should_preserve",
            "b4_host_container_guard_record_uncertainty",
            "eip0045-b4-host-container-presence-v1",
        ] {
            assert!(
                scripts.diagnostics.contains(guard_contract),
                "Bash container guard lost {guard_contract}"
            );
        }
        assert!(
            scripts
                .bash
                .find("b4_host_container_guard_before_run")
                .expect("Bash guard arm is absent")
                < scripts
                    .bash
                    .find("docker run --name")
                    .expect("Bash qualifying docker run is absent")
        );
        assert!(
            scripts
                .bash
                .rfind("docker rm")
                .expect("Bash docker removal is absent")
                < scripts
                    .bash
                    .rfind("b4_host_container_guard_mark_removed")
                    .expect("Bash guard completion is absent")
        );
        assert!(
            scripts
                .powershell
                .find("Start-B4ContainerGuard")
                .expect("PowerShell guard arm is absent")
                < scripts
                    .powershell
                    .find("Invoke-B4NativePassthrough")
                    .expect("PowerShell qualifying docker run is absent")
        );
        assert!(
            scripts
                .powershell
                .rfind("@('rm', $Name)")
                .expect("PowerShell docker removal is absent")
                < scripts
                    .powershell
                    .rfind("Complete-B4ContainerRemoval")
                    .expect("PowerShell guard completion is absent")
        );
        assert!(
            scripts
                .bash
                .contains("runner-exited-before-removal-confirmed")
        );
        assert!(
            scripts
                .powershell
                .contains("runner-exited-before-removal-confirmed")
        );
        assert!(!scripts.diagnostics.contains("export B4_HOST_CONTAINER"));
        assert!(
            scripts
                .powershell_observability
                .contains("ExitStatus', '37'")
        );
        assert!(
            scripts
                .powershell_observability
                .contains("ErrorActionPreference")
        );
        assert!(scripts.bash.contains("set +e\n    docker run --name"));
        assert!(scripts.bash.contains("host_preflight_diagnostics"));
        assert!(scripts.bash.contains("retained_qualifying_container"));
        assert!(scripts.powershell.contains("retainedQualifyingContainer"));
    }

    fn assert_b4_container_and_diagnostic_contract(scripts: &B4RunnerScripts) {
        for phase in [
            "bootstrap",
            "proof-generation-tests",
            "post-test-tree-preflight",
            "identity-extraction",
            "complete",
        ] {
            assert!(
                scripts.container.contains(phase),
                "container lost phase {phase}"
            );
        }
        assert!(scripts.container.contains("/work/diagnostics"));
        assert!(!scripts.container.contains("/output/diagnostics"));
        assert!(scripts.container.contains("shopt -s inherit_errexit"));
        let checkout_special = scripts
            .container
            .find("reject_special_nodes checkout-initial")
            .expect("initial checkout special-node scan is absent");
        let checkout_tree = scripts
            .container
            .find("actual_tree=$(")
            .expect("checkout tree reconstruction is absent");
        let checkout_normalization = scripts
            .container
            .find("b4_normalize_cargo_checkout_pack_hard_links")
            .expect("Cargo checkout hardlink normalization is absent");
        let checkout_hard_links = scripts
            .container
            .find("reject_hard_links checkout-initial-hard-links")
            .expect("post-normalization checkout hardlink scan is absent");
        let checkout_admin = scripts
            .container
            .find("normalize_checkout_admin \"$candidate\"")
            .expect("checkout administration normalization is absent");
        assert!(checkout_special < checkout_tree);
        assert!(checkout_tree < checkout_normalization);
        assert!(checkout_normalization < checkout_hard_links);
        assert!(checkout_hard_links < checkout_admin);
        for contract in [
            "eip0045-b4-diagnostic-failure-v1",
            "return \"$status\"",
            "b4_diag_reject_crlf_paths",
            "b4_diag_reject_hard_links",
            "forbidden-hard-link",
            "forbidden-path",
            "forbidden-node",
            "enumeration-failure",
            "exit 91",
            "scan-$scan_label.stderr",
        ] {
            assert!(scripts.diagnostics.contains(contract));
        }
        assert!(!scripts.diagnostics.contains("export B4_DIAG"));
        for scan_label in [
            "checkout-initial-paths",
            "checkout-materialized-paths",
            "input-workspace-paths",
            "input-seed-cargo-paths",
            "input-seed-lfs-paths",
            "cargo-registry-paths",
            "cargo-checkouts-paths",
            "post-test-workspace-paths",
            "post-test-checkout-paths",
        ] {
            assert!(
                scripts
                    .container
                    .contains(&format!("reject_crlf_paths {scan_label} ")),
                "container lost CR/LF scan label {scan_label}"
            );
        }
        assert_eq!(
            scripts
                .container
                .lines()
                .filter(|line| line.trim_start().starts_with("reject_crlf_paths "))
                .count(),
            9
        );
        for contract in [
            "bash -c 'exit 37'",
            "printf survived",
            "env | grep -q '^B4_DIAG_'",
            "env | grep -q '^B4_HOST_CONTAINER_'",
            "container-presence-uncertain.txt",
            "kind=forbidden-node",
            "expected 91",
            "kind=forbidden-path",
            "kind=enumeration-failure",
            "diff -ru",
        ] {
            assert!(scripts.observability_test.contains(contract));
        }
        assert!(
            scripts
                .powershell_observability
                .contains("container-presence-uncertain.txt")
        );
    }

    #[test]
    fn b4_runner_constants_and_completion_contract_remain_in_parity() {
        let scripts = b4_runner_scripts();
        assert_b4_shared_runner_configuration(&scripts);
        assert_b4_runner_observability_configuration(&scripts);
        assert_b4_container_guard_contract(&scripts);
        assert_b4_container_and_diagnostic_contract(&scripts);
    }
}
