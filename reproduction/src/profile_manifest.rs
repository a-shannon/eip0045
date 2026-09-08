//! Strict codec for the initial profile's binary Manifest V1 envelope.
//!
//! Decoding is deliberately split into three layers:
//!
//! 1. [`crate::profile_manifest::StarkProfileManifestV1::decode`] enforces the reusable V1 grammar;
//! 2. [`crate::profile_manifest::StarkProfileManifestV1::validate_initial_profile_target`] checks the
//!    pre-B3 construction target selected by the EIP; and
//! 3. [`crate::profile_manifest::StarkProfileManifestV1::validate_artifact_package`] binds the two
//!    external artifacts committed by one concrete manifest.
//!
//! After activation, the transition-owned `profileId` authenticates the exact
//! raw manifest. Runtime code consumes those authenticated fields rather than
//! treating a duplicated prose table as a second source of truth.

use core::fmt;

use blake2::{Blake2b, Digest as _, digest::consts::U32};

use crate::{
    constants::{
        ALGORITHM_ARTIFACT_KIND, BINARY_DATA_ARTIFACT_KIND, DIGEST_BYTES, MANIFEST_BYTES,
        MANIFEST_CONTROL_COUNT, MANIFEST_FORMAT_VERSION, MAX_APPLICATION_PAYLOAD_BYTES,
        PROFILE_ARTIFACT_DOMAIN, PROOF_BYTES, RISC0_INNER_CONTROL_ROOT_HEX,
        RISC0_JOIN_CONTROL_ID_HEX, RISC0_NORMAL_LIFT_CONTROL_IDS_HEX, RISC0_OUTER_PO2,
        RISC0_RESOLVE_CONTROL_ID_HEX, SUPPORTED_SEGMENT_PO2, TERMINAL_CONTROL_KIND_JOIN,
        TERMINAL_CONTROL_KIND_LIFT, TERMINAL_CONTROL_KIND_RESOLVE,
    },
    profile::{profile_id as hash_profile_id, profile_id_preimage as build_profile_id_preimage},
};

type Blake2b256 = Blake2b<U32>;

const TERMINAL_CONTROL_COUNT: usize = MANIFEST_CONTROL_COUNT;

/// One fixed-position typed terminal-control entry in Manifest V1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalControl {
    kind: u8,
    parameter: u8,
    control_id: [u8; DIGEST_BYTES],
}

impl TerminalControl {
    /// Construct one typed terminal-control entry.
    #[must_use]
    pub const fn new(control_kind: u8, parameter: u8, control_id: [u8; DIGEST_BYTES]) -> Self {
        Self {
            kind: control_kind,
            parameter,
            control_id,
        }
    }

    /// Terminal-program kind discriminator.
    #[must_use]
    pub const fn control_kind(self) -> u8 {
        self.kind
    }

    /// Kind-specific terminal parameter.
    #[must_use]
    pub const fn parameter(self) -> u8 {
        self.parameter
    }

    /// Raw 32-byte control ID in manifest order.
    #[must_use]
    pub const fn control_id(self) -> [u8; DIGEST_BYTES] {
        self.control_id
    }
}

/// One length- and digest-bound profile artifact reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfileArtifactReference {
    kind: u16,
    length: u32,
    digest: [u8; DIGEST_BYTES],
}

impl ProfileArtifactReference {
    /// Construct a reference from already computed fields.
    #[must_use]
    pub const fn new(
        artifact_kind: u16,
        artifact_length: u32,
        artifact_digest: [u8; DIGEST_BYTES],
    ) -> Self {
        Self {
            kind: artifact_kind,
            length: artifact_length,
            digest: artifact_digest,
        }
    }

    /// Construct the exact reference for `artifact_bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileManifestError::ArtifactTooLarge`] when the artifact
    /// length cannot be represented by the required `u32le` field.
    pub fn from_artifact(
        artifact_kind: u16,
        artifact_bytes: &[u8],
    ) -> Result<Self, ProfileManifestError> {
        let artifact_length = u32::try_from(artifact_bytes.len()).map_err(|_| {
            ProfileManifestError::ArtifactTooLarge {
                kind: artifact_kind,
                actual: artifact_bytes.len(),
            }
        })?;
        let artifact_digest = profile_artifact_digest(artifact_kind, artifact_bytes)?;
        Ok(Self::new(artifact_kind, artifact_length, artifact_digest))
    }

    /// Artifact-kind discriminator.
    #[must_use]
    pub const fn artifact_kind(self) -> u16 {
        self.kind
    }

    /// Declared artifact byte length.
    #[must_use]
    pub const fn artifact_length(self) -> u32 {
        self.length
    }

    /// Domain-separated artifact digest.
    #[must_use]
    pub const fn artifact_digest(self) -> [u8; DIGEST_BYTES] {
        self.digest
    }
}

/// Fully decoded Manifest V1 fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StarkProfileManifestV1 {
    raw_bytes: [u8; MANIFEST_BYTES],
    exact_proof_bytes: u32,
    max_application_payload_bytes: u32,
    outer_po2: u8,
    inner_control_root: [u8; DIGEST_BYTES],
    terminal_controls: [TerminalControl; TERMINAL_CONTROL_COUNT],
    algorithm_artifact: ProfileArtifactReference,
    binary_data_artifact: ProfileArtifactReference,
}

/// Typed artifact bytes associated with one concrete Manifest V1.
#[derive(Clone, Copy, Debug)]
pub struct ProfileArtifacts<'a> {
    /// Exact normative algorithm artifact bytes.
    pub algorithm: &'a [u8],
    /// Exact normative binary-data artifact bytes.
    pub binary_data: &'a [u8],
}

/// Package whose manifest identity and both artifact envelopes were validated.
#[derive(Clone, Debug)]
pub struct ValidatedProfilePackageV1<'a> {
    manifest: StarkProfileManifestV1,
    artifacts: ProfileArtifacts<'a>,
}

impl<'a> ValidatedProfilePackageV1<'a> {
    /// Strictly decoded and identity-authenticated manifest.
    #[must_use]
    pub const fn manifest(&self) -> &StarkProfileManifestV1 {
        &self.manifest
    }

    /// Exact artifact bytes bound by the manifest.
    #[must_use]
    pub const fn artifacts(&self) -> ProfileArtifacts<'a> {
        self.artifacts
    }
}

impl StarkProfileManifestV1 {
    /// Construct and validate one Manifest V1 value.
    ///
    /// This enforces the reusable binary grammar, not the initial profile's
    /// pre-B3 root, control IDs, or scalar construction target.
    ///
    /// # Errors
    ///
    /// Returns the first structural or semantic grammar violation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        exact_proof_bytes: u32,
        max_application_payload_bytes: u32,
        outer_po2: u8,
        inner_control_root: [u8; DIGEST_BYTES],
        terminal_controls: [TerminalControl; TERMINAL_CONTROL_COUNT],
        algorithm_artifact: ProfileArtifactReference,
        binary_data_artifact: ProfileArtifactReference,
    ) -> Result<Self, ProfileManifestError> {
        let mut manifest = Self {
            raw_bytes: [0u8; MANIFEST_BYTES],
            exact_proof_bytes,
            max_application_payload_bytes,
            outer_po2,
            inner_control_root,
            terminal_controls,
            algorithm_artifact,
            binary_data_artifact,
        };
        manifest.validate_v1_grammar()?;
        manifest.raw_bytes = manifest.encode_fields()?;
        Ok(manifest)
    }

    /// Decode exactly 458 bytes and enforce the complete V1 grammar.
    ///
    /// # Errors
    ///
    /// Returns an error before field access when the byte length is not exact,
    /// or the first malformed scalar, control table, or artifact reference.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProfileManifestError> {
        if bytes.len() != MANIFEST_BYTES {
            return Err(ProfileManifestError::InvalidLength {
                actual: bytes.len(),
                expected: MANIFEST_BYTES,
            });
        }

        let mut cursor = ManifestCursor::new(bytes);
        let version = cursor.take_u8()?;
        if version != MANIFEST_FORMAT_VERSION {
            return Err(ProfileManifestError::UnsupportedVersion(version));
        }
        let exact_proof_bytes = cursor.take_u32_le()?;
        let max_application_payload_bytes = cursor.take_u32_le()?;
        let outer_po2 = cursor.take_u8()?;
        let inner_control_root = cursor.take_array::<DIGEST_BYTES>()?;

        let mut terminal_controls = Vec::with_capacity(TERMINAL_CONTROL_COUNT);
        for _ in 0..TERMINAL_CONTROL_COUNT {
            terminal_controls.push(TerminalControl::new(
                cursor.take_u8()?,
                cursor.take_u8()?,
                cursor.take_array::<DIGEST_BYTES>()?,
            ));
        }
        let terminal_controls: [TerminalControl; TERMINAL_CONTROL_COUNT] = terminal_controls
            .try_into()
            .map_err(|_| ProfileManifestError::InternalLayout)?;

        let algorithm_artifact = cursor.take_artifact_reference()?;
        let binary_data_artifact = cursor.take_artifact_reference()?;
        if cursor.position() != MANIFEST_BYTES {
            return Err(ProfileManifestError::InternalLayout);
        }

        let manifest = Self::new(
            exact_proof_bytes,
            max_application_payload_bytes,
            outer_po2,
            inner_control_root,
            terminal_controls,
            algorithm_artifact,
            binary_data_artifact,
        )?;
        let raw_bytes: [u8; MANIFEST_BYTES] = bytes
            .try_into()
            .map_err(|_| ProfileManifestError::InternalLayout)?;
        if manifest.raw_bytes != raw_bytes {
            return Err(ProfileManifestError::InternalLayout);
        }
        Ok(manifest)
    }

    /// Encode the unique 458-byte representation of this validated value.
    ///
    /// # Errors
    ///
    /// Returns an error if fields were somehow constructed outside
    /// [`Self::new`] and do not satisfy the V1 grammar.
    pub fn encode(&self) -> Result<[u8; MANIFEST_BYTES], ProfileManifestError> {
        self.validate_v1_grammar()?;
        if self.encode_fields()? != self.raw_bytes {
            return Err(ProfileManifestError::InternalLayout);
        }
        Ok(self.raw_bytes)
    }

    fn encode_fields(&self) -> Result<[u8; MANIFEST_BYTES], ProfileManifestError> {
        let mut bytes = Vec::with_capacity(MANIFEST_BYTES);
        bytes.push(MANIFEST_FORMAT_VERSION);
        bytes.extend_from_slice(&self.exact_proof_bytes.to_le_bytes());
        bytes.extend_from_slice(&self.max_application_payload_bytes.to_le_bytes());
        bytes.push(self.outer_po2);
        bytes.extend_from_slice(&self.inner_control_root);
        for control in self.terminal_controls {
            bytes.push(control.kind);
            bytes.push(control.parameter);
            bytes.extend_from_slice(&control.control_id);
        }
        append_artifact_reference(&mut bytes, self.algorithm_artifact);
        append_artifact_reference(&mut bytes, self.binary_data_artifact);
        bytes
            .try_into()
            .map_err(|_| ProfileManifestError::InternalLayout)
    }

    /// Validate the exact scalar, root, and normal-lift table selected for the
    /// initial profile before artifact fixation.
    ///
    /// Artifact lengths and digests are intentionally excluded: B1 and B2 must
    /// supply and validate those through [`Self::validate_artifact_package`].
    ///
    /// # Errors
    ///
    /// Returns the first field that differs from the selected initial target,
    /// or an error if an embedded construction pin is malformed.
    pub fn validate_initial_profile_target(&self) -> Result<(), ProfileManifestError> {
        let expected_proof_bytes =
            u32::try_from(PROOF_BYTES).map_err(|_| ProfileManifestError::InternalLayout)?;
        let expected_payload_bytes = u32::try_from(MAX_APPLICATION_PAYLOAD_BYTES)
            .map_err(|_| ProfileManifestError::InternalLayout)?;
        if self.exact_proof_bytes != expected_proof_bytes {
            return Err(ProfileManifestError::InitialTargetMismatch(
                InitialProfileTargetField::ExactProofBytes,
            ));
        }
        if self.max_application_payload_bytes != expected_payload_bytes {
            return Err(ProfileManifestError::InitialTargetMismatch(
                InitialProfileTargetField::MaxApplicationPayloadBytes,
            ));
        }
        if self.outer_po2 != RISC0_OUTER_PO2 {
            return Err(ProfileManifestError::InitialTargetMismatch(
                InitialProfileTargetField::OuterPo2,
            ));
        }
        if self.inner_control_root != decode_frozen_digest(RISC0_INNER_CONTROL_ROOT_HEX)? {
            return Err(ProfileManifestError::InitialTargetMismatch(
                InitialProfileTargetField::InnerControlRoot,
            ));
        }
        for (index, expected_parameter) in SUPPORTED_SEGMENT_PO2.iter().copied().enumerate() {
            let control = self.terminal_controls[index];
            if control.kind != TERMINAL_CONTROL_KIND_LIFT || control.parameter != expected_parameter
            {
                return Err(ProfileManifestError::InitialControlMismatch(index));
            }
            if control.control_id != decode_frozen_digest(RISC0_NORMAL_LIFT_CONTROL_IDS_HEX[index])?
            {
                return Err(ProfileManifestError::InitialControlMismatch(index));
            }
        }
        let join_index = SUPPORTED_SEGMENT_PO2.len();
        let join = self.terminal_controls[join_index];
        if join.kind != TERMINAL_CONTROL_KIND_JOIN
            || join.parameter != 0
            || join.control_id != decode_frozen_digest(RISC0_JOIN_CONTROL_ID_HEX)?
        {
            return Err(ProfileManifestError::InitialControlMismatch(join_index));
        }
        let resolve_index = join_index + 1;
        let resolve = self.terminal_controls[resolve_index];
        if resolve.kind != TERMINAL_CONTROL_KIND_RESOLVE
            || resolve.parameter != 0
            || resolve.control_id != decode_frozen_digest(RISC0_RESOLVE_CONTROL_ID_HEX)?
        {
            return Err(ProfileManifestError::InitialControlMismatch(resolve_index));
        }
        Ok(())
    }

    /// Recompute and validate both artifact references against exact bytes.
    ///
    /// # Errors
    ///
    /// Returns the first length or domain-separated digest mismatch.
    pub fn validate_artifact_package(
        &self,
        algorithm_bytes: &[u8],
        binary_data_bytes: &[u8],
    ) -> Result<(), ProfileManifestError> {
        validate_artifact_reference(self.algorithm_artifact, algorithm_bytes)?;
        validate_artifact_reference(self.binary_data_artifact, binary_data_bytes)
    }

    /// Compute the profile ID over this value's unique validated encoding.
    ///
    /// # Errors
    ///
    /// Returns any V1 grammar or frozen-length inconsistency.
    pub fn profile_id(&self) -> Result<[u8; DIGEST_BYTES], ProfileManifestError> {
        self.encode()?;
        hash_profile_id(&self.raw_bytes).map_err(|_| ProfileManifestError::InternalLayout)
    }

    /// Exact domain-separated profile-ID preimage for these raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an internal-layout error only if the independently frozen
    /// manifest and preimage lengths disagree.
    pub fn profile_id_preimage(
        &self,
    ) -> Result<[u8; crate::constants::PROFILE_ID_PREIMAGE_BYTES], ProfileManifestError> {
        self.encode()?;
        build_profile_id_preimage(&self.raw_bytes).map_err(|_| ProfileManifestError::InternalLayout)
    }

    /// Exact raw manifest bytes authenticated by [`Self::profile_id`].
    #[must_use]
    pub const fn raw_bytes(&self) -> &[u8; MANIFEST_BYTES] {
        &self.raw_bytes
    }

    /// Manifest-owned raw proof byte length.
    #[must_use]
    pub const fn exact_proof_bytes(&self) -> u32 {
        self.exact_proof_bytes
    }

    /// Manifest-owned maximum application payload length.
    #[must_use]
    pub const fn max_application_payload_bytes(&self) -> u32 {
        self.max_application_payload_bytes
    }

    /// Manifest-owned outer recursion exponent.
    #[must_use]
    pub const fn outer_po2(&self) -> u8 {
        self.outer_po2
    }

    /// Manifest-owned inner control root.
    #[must_use]
    pub const fn inner_control_root(&self) -> [u8; DIGEST_BYTES] {
        self.inner_control_root
    }

    /// Fixed-position typed terminal-control entries.
    #[must_use]
    pub const fn terminal_controls(&self) -> &[TerminalControl; TERMINAL_CONTROL_COUNT] {
        &self.terminal_controls
    }

    /// Normative algorithm artifact reference.
    #[must_use]
    pub const fn algorithm_artifact(&self) -> ProfileArtifactReference {
        self.algorithm_artifact
    }

    /// Normative binary-data artifact reference.
    #[must_use]
    pub const fn binary_data_artifact(&self) -> ProfileArtifactReference {
        self.binary_data_artifact
    }

    fn validate_v1_grammar(&self) -> Result<(), ProfileManifestError> {
        if self.exact_proof_bytes == 0 {
            return Err(ProfileManifestError::ZeroProofLength);
        }

        for (index, control) in self.terminal_controls.iter().enumerate() {
            match control.kind {
                TERMINAL_CONTROL_KIND_LIFT => {}
                TERMINAL_CONTROL_KIND_JOIN | TERMINAL_CONTROL_KIND_RESOLVE => {
                    if control.parameter != 0 {
                        return Err(ProfileManifestError::InvalidControlParameter {
                            index,
                            kind: control.kind,
                            actual: control.parameter,
                        });
                    }
                }
                actual => {
                    return Err(ProfileManifestError::UnsupportedControlKind { index, actual });
                }
            }
            if index != 0
                && (control.kind, control.parameter)
                    <= (
                        self.terminal_controls[index - 1].kind,
                        self.terminal_controls[index - 1].parameter,
                    )
            {
                return Err(ProfileManifestError::ControlOrder(index));
            }
            if self.terminal_controls[..index]
                .iter()
                .any(|earlier| earlier.control_id == control.control_id)
            {
                return Err(ProfileManifestError::DuplicateControlId(index));
            }
        }

        validate_artifact_reference_shape(self.algorithm_artifact, ALGORITHM_ARTIFACT_KIND, 0)?;
        validate_artifact_reference_shape(self.binary_data_artifact, BINARY_DATA_ARTIFACT_KIND, 1)
    }
}

/// Compute the domain-separated digest of one profile artifact.
///
/// # Errors
///
/// Returns [`ProfileManifestError::ArtifactTooLarge`] when the byte length
/// does not fit the required `u32le` envelope.
pub fn profile_artifact_digest(
    artifact_kind: u16,
    artifact_bytes: &[u8],
) -> Result<[u8; DIGEST_BYTES], ProfileManifestError> {
    let artifact_length = u32::try_from(artifact_bytes.len()).map_err(|_| {
        ProfileManifestError::ArtifactTooLarge {
            kind: artifact_kind,
            actual: artifact_bytes.len(),
        }
    })?;
    let mut hasher = Blake2b256::new();
    hasher.update(PROFILE_ARTIFACT_DOMAIN);
    hasher.update([0x00]);
    hasher.update(artifact_kind.to_le_bytes());
    hasher.update(artifact_length.to_le_bytes());
    hasher.update(artifact_bytes);
    Ok(hasher.finalize().into())
}

/// Validate one activated-style profile package by manifest identity and
/// artifact envelopes.
///
/// This deliberately does not call
/// [`StarkProfileManifestV1::validate_initial_profile_target`]. Once a
/// transition authorizes `expected_profile_id`, the authenticated raw manifest
/// is the runtime authority for its V1 fields.
///
/// # Errors
///
/// Returns the first grammar, profile-ID, artifact-length, or artifact-digest
/// mismatch.
pub fn validate_profile_package_v1<'a>(
    manifest_bytes: &[u8],
    artifacts: ProfileArtifacts<'a>,
    expected_profile_id: &[u8; DIGEST_BYTES],
) -> Result<ValidatedProfilePackageV1<'a>, ProfileManifestError> {
    let manifest = StarkProfileManifestV1::decode(manifest_bytes)?;
    let actual_profile_id = manifest.profile_id()?;
    if &actual_profile_id != expected_profile_id {
        return Err(ProfileManifestError::ProfileIdMismatch);
    }
    manifest.validate_artifact_package(artifacts.algorithm, artifacts.binary_data)?;
    Ok(ValidatedProfilePackageV1 {
        manifest,
        artifacts,
    })
}

/// Scalar or root field selected by the frozen initial-profile target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitialProfileTargetField {
    /// Exact raw succinct-seal byte length.
    ExactProofBytes,
    /// Maximum application-payload byte length.
    MaxApplicationPayloadBytes,
    /// Outermost recursion exponent.
    OuterPo2,
    /// Inner recursion control root.
    InnerControlRoot,
}

impl fmt::Display for InitialProfileTargetField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ExactProofBytes => "exactProofBytes",
            Self::MaxApplicationPayloadBytes => "maxApplicationPayloadBytes",
            Self::OuterPo2 => "outerPo2",
            Self::InnerControlRoot => "innerControlRoot",
        })
    }
}

/// Failure returned by Manifest V1 decoding or package validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileManifestError {
    /// Raw manifest length differs from the exact V1 size.
    InvalidLength {
        /// Supplied byte length.
        actual: usize,
        /// Required byte length.
        expected: usize,
    },
    /// Manifest-format version is unknown.
    UnsupportedVersion(u8),
    /// Proof byte length is zero.
    ZeroProofLength,
    /// A terminal-control kind is not defined by Manifest V1.
    UnsupportedControlKind {
        /// Terminal-control table index.
        index: usize,
        /// Decoded kind discriminator.
        actual: u8,
    },
    /// A terminal-control parameter is not canonical for its kind.
    InvalidControlParameter {
        /// Terminal-control table index.
        index: usize,
        /// Decoded kind discriminator.
        kind: u8,
        /// Decoded kind-specific parameter.
        actual: u8,
    },
    /// Terminal `(kind, parameter)` keys are not in strict lexicographic order.
    ControlOrder(usize),
    /// A control ID duplicates an earlier entry.
    DuplicateControlId(usize),
    /// Artifact kind differs from the fixed reference position.
    ArtifactKind {
        /// Reference index, zero for algorithm and one for binary data.
        index: usize,
        /// Decoded kind.
        actual: u16,
        /// Required kind.
        expected: u16,
    },
    /// Artifact reference declares an empty byte string.
    EmptyArtifact(usize),
    /// Artifact byte length cannot fit the manifest envelope.
    ArtifactTooLarge {
        /// Artifact kind.
        kind: u16,
        /// Supplied byte length.
        actual: usize,
    },
    /// Concrete artifact length differs from the manifest reference.
    ArtifactLengthMismatch {
        /// Artifact kind.
        kind: u16,
        /// Declared length.
        expected: u32,
        /// Supplied length.
        actual: usize,
    },
    /// Concrete artifact digest differs from the manifest reference.
    ArtifactDigestMismatch(u16),
    /// One scalar or root differs from the initial construction target.
    InitialTargetMismatch(InitialProfileTargetField),
    /// One control pair differs from the initial construction target.
    InitialControlMismatch(usize),
    /// Raw manifest bytes do not match the transition-authorized profile ID.
    ProfileIdMismatch,
    /// A source-embedded hexadecimal construction pin is malformed.
    InvalidFrozenDigest,
    /// A compile-time layout relationship failed unexpectedly.
    InternalLayout,
}

impl fmt::Display for ProfileManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { actual, expected } => {
                write!(
                    formatter,
                    "profile manifest has {actual} bytes, expected {expected}"
                )
            }
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported profile manifest version {version:#04x}"
                )
            }
            Self::ZeroProofLength => formatter.write_str("profile proof length is zero"),
            Self::UnsupportedControlKind { index, actual } => write!(
                formatter,
                "unsupported terminal-control kind {actual} at index {index}"
            ),
            Self::InvalidControlParameter {
                index,
                kind,
                actual,
            } => write!(
                formatter,
                "terminal-control kind {kind} has parameter {actual} at index {index}"
            ),
            Self::ControlOrder(index) => {
                write!(
                    formatter,
                    "profile terminal controls are not ordered at index {index}"
                )
            }
            Self::DuplicateControlId(index) => {
                write!(formatter, "duplicate profile control ID at index {index}")
            }
            Self::ArtifactKind {
                index,
                actual,
                expected,
            } => write!(
                formatter,
                "artifact reference {index} has kind {actual}, expected {expected}"
            ),
            Self::EmptyArtifact(index) => {
                write!(formatter, "artifact reference {index} has zero length")
            }
            Self::ArtifactTooLarge { kind, actual } => {
                write!(
                    formatter,
                    "artifact kind {kind} has {actual} bytes, above u32"
                )
            }
            Self::ArtifactLengthMismatch {
                kind,
                expected,
                actual,
            } => write!(
                formatter,
                "artifact kind {kind} has {actual} bytes, expected {expected}"
            ),
            Self::ArtifactDigestMismatch(kind) => {
                write!(formatter, "artifact kind {kind} digest mismatch")
            }
            Self::InitialTargetMismatch(field) => {
                write!(formatter, "initial profile target mismatch: {field}")
            }
            Self::InitialControlMismatch(index) => {
                write!(
                    formatter,
                    "initial profile control mismatch at index {index}"
                )
            }
            Self::ProfileIdMismatch => formatter.write_str("profile ID mismatch"),
            Self::InvalidFrozenDigest => formatter.write_str("invalid frozen profile digest"),
            Self::InternalLayout => formatter.write_str("internal Manifest V1 layout mismatch"),
        }
    }
}

impl std::error::Error for ProfileManifestError {}

fn validate_artifact_reference_shape(
    reference: ProfileArtifactReference,
    expected_kind: u16,
    index: usize,
) -> Result<(), ProfileManifestError> {
    if reference.kind != expected_kind {
        return Err(ProfileManifestError::ArtifactKind {
            index,
            actual: reference.kind,
            expected: expected_kind,
        });
    }
    if reference.length == 0 {
        return Err(ProfileManifestError::EmptyArtifact(index));
    }
    Ok(())
}

fn validate_artifact_reference(
    reference: ProfileArtifactReference,
    artifact_bytes: &[u8],
) -> Result<(), ProfileManifestError> {
    if usize::try_from(reference.length).map_err(|_| ProfileManifestError::InternalLayout)?
        != artifact_bytes.len()
    {
        return Err(ProfileManifestError::ArtifactLengthMismatch {
            kind: reference.kind,
            expected: reference.length,
            actual: artifact_bytes.len(),
        });
    }
    if reference.digest != profile_artifact_digest(reference.kind, artifact_bytes)? {
        return Err(ProfileManifestError::ArtifactDigestMismatch(reference.kind));
    }
    Ok(())
}

fn append_artifact_reference(bytes: &mut Vec<u8>, reference: ProfileArtifactReference) {
    bytes.extend_from_slice(&reference.kind.to_le_bytes());
    bytes.extend_from_slice(&reference.length.to_le_bytes());
    bytes.extend_from_slice(&reference.digest);
}

fn decode_frozen_digest(value: &str) -> Result<[u8; DIGEST_BYTES], ProfileManifestError> {
    let mut bytes = [0u8; DIGEST_BYTES];
    hex::decode_to_slice(value, &mut bytes)
        .map_err(|_| ProfileManifestError::InvalidFrozenDigest)?;
    Ok(bytes)
}

struct ManifestCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> ManifestCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn take_u8(&mut self) -> Result<u8, ProfileManifestError> {
        Ok(self.take_array::<1>()?[0])
    }

    fn take_u16_le(&mut self) -> Result<u16, ProfileManifestError> {
        Ok(u16::from_le_bytes(self.take_array::<2>()?))
    }

    fn take_u32_le(&mut self) -> Result<u32, ProfileManifestError> {
        Ok(u32::from_le_bytes(self.take_array::<4>()?))
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], ProfileManifestError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(ProfileManifestError::InternalLayout)?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(ProfileManifestError::InternalLayout)?;
        self.position = end;
        slice
            .try_into()
            .map_err(|_| ProfileManifestError::InternalLayout)
    }

    fn take_artifact_reference(
        &mut self,
    ) -> Result<ProfileArtifactReference, ProfileManifestError> {
        Ok(ProfileArtifactReference::new(
            self.take_u16_le()?,
            self.take_u32_le()?,
            self.take_array::<DIGEST_BYTES>()?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALGORITHM_BYTES: &[u8] = b"candidate algorithm artifact";
    const BINARY_BYTES: &[u8] = b"candidate binary-data artifact";
    const PO14_CONTROL_ID_HEX: &str =
        "411fa636f2d364648f035174d3778d6340d9ae1dd648fc35657c173f01e27e5f";

    #[test]
    fn terminal_control_api_exposes_the_typed_wire_fields() {
        let control = TerminalControl::new(2, 0, [0x5a; DIGEST_BYTES]);
        assert_eq!(control.control_kind(), 2);
        assert_eq!(control.parameter(), 0);
        assert_eq!(control.control_id(), [0x5a; DIGEST_BYTES]);
    }

    fn initial_terminal_controls() -> [TerminalControl; TERMINAL_CONTROL_COUNT] {
        let mut controls = SUPPORTED_SEGMENT_PO2
            .iter()
            .copied()
            .zip(RISC0_NORMAL_LIFT_CONTROL_IDS_HEX.iter().copied())
            .map(|(segment_po2, control_id)| {
                TerminalControl::new(
                    TERMINAL_CONTROL_KIND_LIFT,
                    segment_po2,
                    decode_frozen_digest(control_id).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        controls.push(TerminalControl::new(
            TERMINAL_CONTROL_KIND_JOIN,
            0,
            decode_frozen_digest(RISC0_JOIN_CONTROL_ID_HEX).unwrap(),
        ));
        controls.push(TerminalControl::new(
            TERMINAL_CONTROL_KIND_RESOLVE,
            0,
            decode_frozen_digest(RISC0_RESOLVE_CONTROL_ID_HEX).unwrap(),
        ));
        controls.try_into().unwrap()
    }

    fn initial_manifest() -> StarkProfileManifestV1 {
        StarkProfileManifestV1::new(
            u32::try_from(PROOF_BYTES).unwrap(),
            u32::try_from(MAX_APPLICATION_PAYLOAD_BYTES).unwrap(),
            RISC0_OUTER_PO2,
            decode_frozen_digest(RISC0_INNER_CONTROL_ROOT_HEX).unwrap(),
            initial_terminal_controls(),
            ProfileArtifactReference::from_artifact(ALGORITHM_ARTIFACT_KIND, ALGORITHM_BYTES)
                .unwrap(),
            ProfileArtifactReference::from_artifact(BINARY_DATA_ARTIFACT_KIND, BINARY_BYTES)
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn initial_manifest_round_trips_with_exact_offsets() {
        let manifest = initial_manifest();
        manifest.validate_initial_profile_target().unwrap();
        manifest
            .validate_artifact_package(ALGORITHM_BYTES, BINARY_BYTES)
            .unwrap();

        let bytes = manifest.encode().unwrap();
        assert_eq!(bytes.len(), MANIFEST_BYTES);
        assert_eq!(bytes[0], MANIFEST_FORMAT_VERSION);
        assert_eq!(u32::from_le_bytes(bytes[1..5].try_into().unwrap()), 222_668);
        assert_eq!(u32::from_le_bytes(bytes[5..9].try_into().unwrap()), 16_384);
        assert_eq!(bytes[9], 18);
        assert_eq!(&bytes[10..42], &manifest.inner_control_root);
        assert_eq!(&bytes[42..44], &[TERMINAL_CONTROL_KIND_LIFT, 15]);
        assert_eq!(
            &bytes[42 + 7 * 34..42 + 7 * 34 + 2],
            &[TERMINAL_CONTROL_KIND_LIFT, 22]
        );
        assert_eq!(
            &bytes[42 + 8 * 34..42 + 8 * 34 + 2],
            &[TERMINAL_CONTROL_KIND_JOIN, 0]
        );
        assert_eq!(
            &bytes[42 + 8 * 34 + 2..42 + 9 * 34],
            &decode_frozen_digest(RISC0_JOIN_CONTROL_ID_HEX).unwrap()
        );
        assert_eq!(
            &bytes[42 + 9 * 34..42 + 9 * 34 + 2],
            &[TERMINAL_CONTROL_KIND_RESOLVE, 0]
        );
        assert_eq!(
            &bytes[42 + 9 * 34 + 2..382],
            &decode_frozen_digest(RISC0_RESOLVE_CONTROL_ID_HEX).unwrap()
        );
        assert_eq!(&bytes[382..384], &1u16.to_le_bytes());
        assert_eq!(
            &bytes[384..388],
            &u32::try_from(ALGORITHM_BYTES.len()).unwrap().to_le_bytes()
        );
        assert_eq!(&bytes[420..422], &2u16.to_le_bytes());
        assert_eq!(
            &bytes[422..426],
            &u32::try_from(BINARY_BYTES.len()).unwrap().to_le_bytes()
        );
        assert_eq!(StarkProfileManifestV1::decode(&bytes).unwrap(), manifest);
        assert_eq!(
            manifest.profile_id().unwrap(),
            hash_profile_id(&bytes).unwrap()
        );
        let preimage = manifest.profile_id_preimage().unwrap();
        assert_eq!(preimage.len(), 485);
        assert_eq!(&preimage[23..27], &[0xca, 0x01, 0x00, 0x00]);
        assert_eq!(&preimage[27..], &bytes);
    }

    #[test]
    fn generic_v1_grammar_does_not_duplicate_the_initial_target_authority() {
        let mut bytes = initial_manifest().encode().unwrap();
        bytes[1..5].copy_from_slice(&222_669u32.to_le_bytes());
        bytes[9] = 19;
        bytes[10] ^= 1;
        for index in 0..SUPPORTED_SEGMENT_PO2.len() {
            bytes[43 + index * 34] = 16 + u8::try_from(index).unwrap();
        }
        bytes[44] ^= 1;

        let decoded = StarkProfileManifestV1::decode(&bytes).unwrap();
        assert!(matches!(
            decoded.validate_initial_profile_target(),
            Err(ProfileManifestError::InitialTargetMismatch(_)
                | ProfileManifestError::InitialControlMismatch(_))
        ));
    }

    #[test]
    fn exact_length_and_version_are_gated_before_other_fields() {
        let bytes = initial_manifest().encode().unwrap();
        for actual in [0, 457, 459, 491] {
            let mut value = vec![0u8; actual];
            let copied = actual.min(MANIFEST_BYTES);
            value[..copied].copy_from_slice(&bytes[..copied]);
            assert!(matches!(
                StarkProfileManifestV1::decode(&value),
                Err(ProfileManifestError::InvalidLength { .. })
            ));
        }

        let mut wrong_version = bytes;
        wrong_version[0] = 2;
        assert_eq!(
            StarkProfileManifestV1::decode(&wrong_version),
            Err(ProfileManifestError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn zero_proof_is_rejected_but_payload_limit_is_profile_owned() {
        let mut bytes = initial_manifest().encode().unwrap();
        bytes[1..5].fill(0);
        assert_eq!(
            StarkProfileManifestV1::decode(&bytes),
            Err(ProfileManifestError::ZeroProofLength)
        );

        let mut bytes = initial_manifest().encode().unwrap();
        bytes[5..9].copy_from_slice(&16_385u32.to_le_bytes());
        let decoded = StarkProfileManifestV1::decode(&bytes).unwrap();
        assert_eq!(decoded.max_application_payload_bytes(), 16_385);
        assert_eq!(
            decoded.validate_initial_profile_target(),
            Err(ProfileManifestError::InitialTargetMismatch(
                InitialProfileTargetField::MaxApplicationPayloadBytes
            ))
        );
    }

    #[test]
    fn terminal_control_kinds_parameters_order_and_ids_are_canonical() {
        let bytes = initial_manifest().encode().unwrap();

        let mut unknown = bytes;
        unknown[42] = 0;
        assert_eq!(
            StarkProfileManifestV1::decode(&unknown),
            Err(ProfileManifestError::UnsupportedControlKind {
                index: 0,
                actual: 0,
            })
        );

        let mut unknown = bytes;
        unknown[42 + 9 * 34] = 4;
        assert_eq!(
            StarkProfileManifestV1::decode(&unknown),
            Err(ProfileManifestError::UnsupportedControlKind {
                index: 9,
                actual: 4,
            })
        );

        for (index, kind) in [
            (8usize, TERMINAL_CONTROL_KIND_JOIN),
            (9usize, TERMINAL_CONTROL_KIND_RESOLVE),
        ] {
            let mut parameterized = bytes;
            parameterized[43 + index * 34] = 1;
            assert_eq!(
                StarkProfileManifestV1::decode(&parameterized),
                Err(ProfileManifestError::InvalidControlParameter {
                    index,
                    kind,
                    actual: 1,
                })
            );
        }

        let mut repeated_lift_parameter = bytes;
        repeated_lift_parameter[43 + 34] = 15;
        assert_eq!(
            StarkProfileManifestV1::decode(&repeated_lift_parameter),
            Err(ProfileManifestError::ControlOrder(1))
        );

        let mut repeated_join_key = bytes;
        repeated_join_key[42 + 9 * 34] = TERMINAL_CONTROL_KIND_JOIN;
        assert_eq!(
            StarkProfileManifestV1::decode(&repeated_join_key),
            Err(ProfileManifestError::ControlOrder(9))
        );

        let mut duplicate_id = bytes;
        let first_id: [u8; DIGEST_BYTES] = bytes[44..76].try_into().unwrap();
        duplicate_id[78..110].copy_from_slice(&first_id);
        assert_eq!(
            StarkProfileManifestV1::decode(&duplicate_id),
            Err(ProfileManifestError::DuplicateControlId(1))
        );
    }

    #[test]
    fn negative_terminal_kind_and_parameter_recipes_reject_in_the_manifest_codec() {
        let bytes = initial_manifest().encode().unwrap();

        for index in 0..TERMINAL_CONTROL_COUNT {
            let mut changed = bytes;
            changed[42 + index * 34] = u8::MAX;
            assert_eq!(
                StarkProfileManifestV1::decode(&changed),
                Err(ProfileManifestError::UnsupportedControlKind {
                    index,
                    actual: u8::MAX,
                })
            );
        }

        for index in 0..TERMINAL_CONTROL_COUNT {
            let mut changed = bytes;
            let parameter_offset = 43 + index * 34;
            let expected = if index < SUPPORTED_SEGMENT_PO2.len() {
                // Make the lift key equal to its neighbour. For index zero the
                // following key becomes the first duplicate; every later lift
                // duplicates its predecessor.
                changed[parameter_offset] = if index == 0 {
                    SUPPORTED_SEGMENT_PO2[1]
                } else {
                    SUPPORTED_SEGMENT_PO2[index - 1]
                };
                ProfileManifestError::ControlOrder(index.max(1))
            } else {
                // Join and resolve admit only the zero parameter in V1.
                changed[parameter_offset] = 1;
                ProfileManifestError::InvalidControlParameter {
                    index,
                    kind: changed[42 + index * 34],
                    actual: 1,
                }
            };
            assert_eq!(StarkProfileManifestV1::decode(&changed), Err(expected));
        }
    }

    #[test]
    fn negative_terminal_control_id_recipes_reach_the_initial_profile_target() {
        let bytes = initial_manifest().encode().unwrap();

        for index in 0..TERMINAL_CONTROL_COUNT {
            let mut changed = bytes;
            let control_id_offset = 44 + index * 34;
            changed[control_id_offset] ^= 1;

            let decoded = StarkProfileManifestV1::decode(&changed).unwrap();
            assert_eq!(
                decoded.validate_initial_profile_target(),
                Err(ProfileManifestError::InitialControlMismatch(index))
            );
        }
    }

    #[test]
    fn artifact_positions_kinds_and_nonempty_lengths_are_exact() {
        for (offset, expected_error) in [
            (
                382,
                ProfileManifestError::ArtifactKind {
                    index: 0,
                    actual: 2,
                    expected: 1,
                },
            ),
            (
                420,
                ProfileManifestError::ArtifactKind {
                    index: 1,
                    actual: 3,
                    expected: 2,
                },
            ),
        ] {
            let mut bytes = initial_manifest().encode().unwrap();
            let wrong_kind = if offset == 382 { 2u16 } else { 3u16 };
            bytes[offset..offset + 2].copy_from_slice(&wrong_kind.to_le_bytes());
            assert_eq!(StarkProfileManifestV1::decode(&bytes), Err(expected_error));
        }

        for (length_offset, index) in [(384, 0), (422, 1)] {
            let mut bytes = initial_manifest().encode().unwrap();
            bytes[length_offset..length_offset + 4].fill(0);
            assert_eq!(
                StarkProfileManifestV1::decode(&bytes),
                Err(ProfileManifestError::EmptyArtifact(index))
            );
        }
    }

    #[test]
    fn negative_artifact_reference_recipes_reach_the_artifact_envelope() {
        let bytes = initial_manifest().encode().unwrap();

        for (length_offset, kind, actual_length) in [
            (384, ALGORITHM_ARTIFACT_KIND, ALGORITHM_BYTES.len()),
            (422, BINARY_DATA_ARTIFACT_KIND, BINARY_BYTES.len()),
        ] {
            let mut changed = bytes;
            let declared = u32::from_le_bytes(
                changed[length_offset..length_offset + 4]
                    .try_into()
                    .unwrap(),
            );
            let changed_declared = declared.checked_add(1).unwrap();
            changed[length_offset..length_offset + 4]
                .copy_from_slice(&changed_declared.to_le_bytes());

            let decoded = StarkProfileManifestV1::decode(&changed).unwrap();
            assert_eq!(
                decoded.validate_artifact_package(ALGORITHM_BYTES, BINARY_BYTES),
                Err(ProfileManifestError::ArtifactLengthMismatch {
                    kind,
                    expected: changed_declared,
                    actual: actual_length,
                })
            );
        }

        for (digest_offset, kind) in [
            (388, ALGORITHM_ARTIFACT_KIND),
            (426, BINARY_DATA_ARTIFACT_KIND),
        ] {
            let mut changed = bytes;
            changed[digest_offset] ^= 1;

            let decoded = StarkProfileManifestV1::decode(&changed).unwrap();
            assert_eq!(
                decoded.validate_artifact_package(ALGORITHM_BYTES, BINARY_BYTES),
                Err(ProfileManifestError::ArtifactDigestMismatch(kind))
            );
        }
    }

    #[test]
    fn artifact_package_rejects_length_and_digest_substitution() {
        let manifest = initial_manifest();
        assert!(matches!(
            manifest.validate_artifact_package(b"short", BINARY_BYTES),
            Err(ProfileManifestError::ArtifactLengthMismatch { kind: 1, .. })
        ));

        let mut same_length = ALGORITHM_BYTES.to_vec();
        same_length[0] ^= 1;
        assert_eq!(
            manifest.validate_artifact_package(&same_length, BINARY_BYTES),
            Err(ProfileManifestError::ArtifactDigestMismatch(1))
        );

        assert!(matches!(
            manifest.validate_artifact_package(ALGORITHM_BYTES, b"short"),
            Err(ProfileManifestError::ArtifactLengthMismatch { kind: 2, .. })
        ));

        let mut same_length = BINARY_BYTES.to_vec();
        same_length[0] ^= 1;
        assert_eq!(
            manifest.validate_artifact_package(ALGORITHM_BYTES, &same_length),
            Err(ProfileManifestError::ArtifactDigestMismatch(2))
        );
    }

    #[test]
    fn artifact_envelope_matches_an_independent_blake2b_256_vector() {
        let digest = profile_artifact_digest(ALGORITHM_ARTIFACT_KIND, b"abc").unwrap();
        assert_eq!(
            hex::encode(digest),
            "a16874031c15d7bf7f5a3fbe5a14e1a34bb4d57b02d33344ab5e9d9caa7d024c"
        );
        assert_ne!(
            digest,
            profile_artifact_digest(BINARY_DATA_ARTIFACT_KIND, b"abc").unwrap()
        );
        assert_ne!(
            digest,
            profile_artifact_digest(ALGORITHM_ARTIFACT_KIND, b"abcd").unwrap()
        );
    }

    #[test]
    fn valid_upstream_po14_control_is_rejected_by_the_initial_allowlist() {
        let mut bytes = initial_manifest().encode().unwrap();
        bytes[44..76].copy_from_slice(&decode_frozen_digest(PO14_CONTROL_ID_HEX).unwrap());

        let decoded = StarkProfileManifestV1::decode(&bytes).unwrap();
        assert_eq!(
            decoded.validate_initial_profile_target(),
            Err(ProfileManifestError::InitialControlMismatch(0))
        );
    }

    #[test]
    fn activated_package_uses_profile_identity_not_the_initial_target_table() {
        let initial = initial_manifest();
        let initial_bytes = initial.encode().unwrap();
        let artifacts = ProfileArtifacts {
            algorithm: ALGORITHM_BYTES,
            binary_data: BINARY_BYTES,
        };
        let initial_id = initial.profile_id().unwrap();
        let package = validate_profile_package_v1(&initial_bytes, artifacts, &initial_id).unwrap();
        assert_eq!(package.manifest().raw_bytes(), &initial_bytes);
        assert_eq!(package.artifacts().algorithm, ALGORITHM_BYTES);

        let mut alternate_bytes = initial_bytes;
        alternate_bytes[1..5].copy_from_slice(&222_669u32.to_le_bytes());
        alternate_bytes[10] ^= 1;
        let alternate = StarkProfileManifestV1::decode(&alternate_bytes).unwrap();
        assert!(alternate.validate_initial_profile_target().is_err());
        let alternate_id = alternate.profile_id().unwrap();
        validate_profile_package_v1(&alternate_bytes, artifacts, &alternate_id).unwrap();
        assert!(matches!(
            validate_profile_package_v1(&alternate_bytes, artifacts, &initial_id),
            Err(ProfileManifestError::ProfileIdMismatch)
        ));
    }

    #[test]
    fn every_initial_target_component_is_checked_separately() {
        let initial = initial_manifest();
        let bytes = initial.encode().unwrap();
        for (offset, expected_error) in [
            (
                1usize,
                ProfileManifestError::InitialTargetMismatch(
                    InitialProfileTargetField::ExactProofBytes,
                ),
            ),
            (
                9,
                ProfileManifestError::InitialTargetMismatch(InitialProfileTargetField::OuterPo2),
            ),
            (43, ProfileManifestError::InitialControlMismatch(0)),
        ] {
            let mut changed = bytes;
            changed[offset] ^= 1;
            let decoded = StarkProfileManifestV1::decode(&changed).unwrap();
            assert_eq!(
                decoded.validate_initial_profile_target(),
                Err(expected_error)
            );
        }

        let mut last_lift_parameter = bytes;
        last_lift_parameter[43 + (SUPPORTED_SEGMENT_PO2.len() - 1) * 34] = 23;
        assert_eq!(
            StarkProfileManifestV1::decode(&last_lift_parameter)
                .unwrap()
                .validate_initial_profile_target(),
            Err(ProfileManifestError::InitialControlMismatch(
                SUPPORTED_SEGMENT_PO2.len() - 1
            ))
        );

        for root_offset in (10..42).step_by(4) {
            let mut changed = bytes;
            changed[root_offset] ^= 1;
            assert_eq!(
                StarkProfileManifestV1::decode(&changed)
                    .unwrap()
                    .validate_initial_profile_target(),
                Err(ProfileManifestError::InitialTargetMismatch(
                    InitialProfileTargetField::InnerControlRoot
                ))
            );
        }

        for index in 0..TERMINAL_CONTROL_COUNT {
            let mut changed = bytes;
            changed[44 + index * 34] ^= 1;
            assert_eq!(
                StarkProfileManifestV1::decode(&changed)
                    .unwrap()
                    .validate_initial_profile_target(),
                Err(ProfileManifestError::InitialControlMismatch(index))
            );
        }

        // The wire grammar requires strict typed-key ordering and canonical
        // join/resolve parameters. Isolate every target-table kind/parameter
        // predicate on the already-decoded value as well as wire rejection.
        for index in 0..TERMINAL_CONTROL_COUNT {
            let mut changed = initial.clone();
            changed.terminal_controls[index].parameter ^= 0x40;
            assert_eq!(
                changed.validate_initial_profile_target(),
                Err(ProfileManifestError::InitialControlMismatch(index))
            );
        }
        for index in 0..TERMINAL_CONTROL_COUNT {
            let mut changed = initial.clone();
            changed.terminal_controls[index].kind = match changed.terminal_controls[index].kind {
                TERMINAL_CONTROL_KIND_LIFT => TERMINAL_CONTROL_KIND_JOIN,
                _ => TERMINAL_CONTROL_KIND_LIFT,
            };
            assert_eq!(
                changed.validate_initial_profile_target(),
                Err(ProfileManifestError::InitialControlMismatch(index))
            );
        }

        let mut smaller_payload_limit = bytes;
        smaller_payload_limit[5..9].copy_from_slice(&16_383u32.to_le_bytes());
        let decoded = StarkProfileManifestV1::decode(&smaller_payload_limit).unwrap();
        assert_eq!(
            decoded.validate_initial_profile_target(),
            Err(ProfileManifestError::InitialTargetMismatch(
                InitialProfileTargetField::MaxApplicationPayloadBytes
            ))
        );
    }
}
