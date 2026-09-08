// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Typed negative adapters for profile-package validation surfaces.
//!
//! The selected handler is supplied by the sole negative-handler table. This
//! module authenticates the complete frozen package before calling exactly one
//! mutation-facing production consumer. Only structured errors emitted by that
//! consumer can become a rejection; framing, authority, or unexpected errors
//! remain private adapter failures.

use crate::{
    b4_negative_handler_contract::B4NegativeHandlerSelector,
    b4_subject_envelope::{
        B4SubjectEnvelopeContract, B4SubjectEnvelopeError, B4SubjectEnvelopeKind,
        B4SubjectPartBounds, decode_subject_envelope,
    },
    constants::{DIGEST_BYTES, MANIFEST_BYTES, PROFILE_ID_PREIMAGE_BYTES},
    constants_artifact,
    profile::{ProfileIdPreimageValidationError, validate_profile_id_preimage},
    profile_algorithm::{self, authenticate_profile_algorithm},
    profile_manifest::{
        InitialProfileTargetField, ProfileArtifacts, ProfileManifestError, StarkProfileManifestV1,
        validate_profile_package_v1,
    },
};

use super::profile::INITIAL_PROFILE_ID_HEX;

const FROZEN_ALGORITHM: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/algorithm.txt");
const FROZEN_CONSTANTS: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/constants.bin");
const FROZEN_MANIFEST: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");

const PROFILE_PACKAGE_PARTS: [B4SubjectPartBounds; 3] = [
    B4SubjectPartBounds::new(MANIFEST_BYTES, MANIFEST_BYTES),
    B4SubjectPartBounds::new(
        profile_algorithm::ALGORITHM_BYTES,
        profile_algorithm::ALGORITHM_BYTES,
    ),
    B4SubjectPartBounds::new(
        constants_artifact::ARTIFACT_BYTES,
        constants_artifact::ARTIFACT_BYTES,
    ),
];
const PROFILE_ID_PREIMAGE_PARTS: [B4SubjectPartBounds; 2] = [
    B4SubjectPartBounds::new(MANIFEST_BYTES, MANIFEST_BYTES),
    B4SubjectPartBounds::new(PROFILE_ID_PREIMAGE_BYTES, PROFILE_ID_PREIMAGE_BYTES),
];

/// Closed profile-package rejection facts emitted by production consumers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum B4ArtifactProfileRejection {
    ManifestLength,
    ManifestVersion,
    ManifestProofLength,
    ManifestTerminalKind { index: usize },
    ManifestTerminalParameter { index: usize },
    ManifestTerminalOrder { index: usize },
    ManifestTerminalControlIdDuplicate { index: usize },
    ManifestArtifactKind { index: usize },
    ManifestArtifactEmpty { index: usize },
    InitialExactProofBytes,
    InitialMaximumPayload,
    InitialOuterPo2,
    InitialInnerControlRoot,
    InitialTerminalControl { index: usize },
    ArtifactLength { kind: u16 },
    ArtifactDigest { kind: u16 },
    ActivatedProfileId,
    ProfileIdPreimage,
}

/// Private failures which cannot become campaign rejection observations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum B4ArtifactProfileAdapterError {
    UnsupportedSelector,
    ContextCount { actual: usize, expected: usize },
    SubjectLength { actual: usize, expected: usize },
    SubjectEnvelope(B4SubjectEnvelopeError),
    FrozenManifest(ProfileManifestError),
    FrozenInitialTarget(ProfileManifestError),
    FrozenAlgorithm,
    FrozenConstants,
    FrozenProfileId,
    FrozenPackage(ProfileManifestError),
    CandidateManifest(ProfileManifestError),
    CandidateInitialTarget(ProfileManifestError),
    CandidateProfileId,
    UnexpectedManifestCodecAcceptance,
    UnexpectedInitialTargetAcceptance,
    UnexpectedArtifactEnvelopeAcceptance,
    UnexpectedActivatedPackageAcceptance,
    UnexpectedProfileIdPreimageAcceptance,
    ProfileIdPreimageConstruction,
}

/// Validate one profile-focused negative subject selected by the sole handler table.
///
/// `selector` is not inferred from bytes or campaign labels. Context bytes are
/// positional and must have the cardinality owned by that selected table row.
pub(super) fn validate_profile_negative(
    selector: B4NegativeHandlerSelector,
    subject: &[u8],
    contexts: &[&[u8]],
) -> Result<B4ArtifactProfileRejection, B4ArtifactProfileAdapterError> {
    match selector {
        B4NegativeHandlerSelector::ArtifactProfileManifestCodec => {
            require_context_count(contexts, 0)?;
            validate_manifest_codec(subject)
        }
        B4NegativeHandlerSelector::ArtifactInitialProfileTarget => {
            require_context_count(contexts, 0)?;
            validate_initial_profile_target(subject)
        }
        B4NegativeHandlerSelector::ArtifactProfileArtifactEnvelope => {
            require_context_count(contexts, 0)?;
            validate_profile_artifact_envelope(subject)
        }
        B4NegativeHandlerSelector::ArtifactActivatedProfilePackage => {
            require_context_count(contexts, 3)?;
            validate_activated_profile_package(subject, contexts)
        }
        B4NegativeHandlerSelector::ArtifactProfileIdPreimage => {
            require_context_count(contexts, 0)?;
            validate_profile_id_preimage_bundle(subject)
        }
        _ => Err(B4ArtifactProfileAdapterError::UnsupportedSelector),
    }
}

fn validate_manifest_codec(
    subject: &[u8],
) -> Result<B4ArtifactProfileRejection, B4ArtifactProfileAdapterError> {
    authenticate_frozen_base()?;
    match StarkProfileManifestV1::decode(subject) {
        Ok(_) => Err(B4ArtifactProfileAdapterError::UnexpectedManifestCodecAcceptance),
        Err(error) => map_manifest_codec_error(error),
    }
}

fn validate_initial_profile_target(
    subject: &[u8],
) -> Result<B4ArtifactProfileRejection, B4ArtifactProfileAdapterError> {
    require_subject_length(subject, MANIFEST_BYTES)?;
    authenticate_frozen_base()?;
    let candidate = StarkProfileManifestV1::decode(subject)
        .map_err(B4ArtifactProfileAdapterError::CandidateManifest)?;
    match candidate.validate_initial_profile_target() {
        Ok(()) => Err(B4ArtifactProfileAdapterError::UnexpectedInitialTargetAcceptance),
        Err(ProfileManifestError::InitialTargetMismatch(field)) => Ok(match field {
            InitialProfileTargetField::ExactProofBytes => {
                B4ArtifactProfileRejection::InitialExactProofBytes
            }
            InitialProfileTargetField::MaxApplicationPayloadBytes => {
                B4ArtifactProfileRejection::InitialMaximumPayload
            }
            InitialProfileTargetField::OuterPo2 => B4ArtifactProfileRejection::InitialOuterPo2,
            InitialProfileTargetField::InnerControlRoot => {
                B4ArtifactProfileRejection::InitialInnerControlRoot
            }
        }),
        Err(ProfileManifestError::InitialControlMismatch(index)) => {
            Ok(B4ArtifactProfileRejection::InitialTerminalControl { index })
        }
        Err(error) => Err(B4ArtifactProfileAdapterError::CandidateInitialTarget(error)),
    }
}

fn validate_profile_artifact_envelope(
    subject: &[u8],
) -> Result<B4ArtifactProfileRejection, B4ArtifactProfileAdapterError> {
    let envelope = decode_subject_envelope(
        subject,
        B4SubjectEnvelopeContract::new(
            B4SubjectEnvelopeKind::ProfilePackage,
            &PROFILE_PACKAGE_PARTS,
        ),
    )
    .map_err(B4ArtifactProfileAdapterError::SubjectEnvelope)?;
    authenticate_frozen_base()?;
    let parts = envelope.parts();
    let manifest = StarkProfileManifestV1::decode(parts[0])
        .map_err(B4ArtifactProfileAdapterError::CandidateManifest)?;
    manifest
        .validate_initial_profile_target()
        .map_err(B4ArtifactProfileAdapterError::CandidateInitialTarget)?;
    match manifest.validate_artifact_package(parts[1], parts[2]) {
        Ok(()) => Err(B4ArtifactProfileAdapterError::UnexpectedArtifactEnvelopeAcceptance),
        Err(ProfileManifestError::ArtifactLengthMismatch { kind, .. }) => {
            Ok(B4ArtifactProfileRejection::ArtifactLength { kind })
        }
        Err(ProfileManifestError::ArtifactDigestMismatch(kind)) => {
            Ok(B4ArtifactProfileRejection::ArtifactDigest { kind })
        }
        Err(error) => Err(B4ArtifactProfileAdapterError::CandidateManifest(error)),
    }
}

fn validate_activated_profile_package(
    subject: &[u8],
    contexts: &[&[u8]],
) -> Result<B4ArtifactProfileRejection, B4ArtifactProfileAdapterError> {
    require_subject_length(subject, DIGEST_BYTES)?;
    let frozen_profile_id = authenticate_frozen_base()?;
    authenticate_supplied_base(contexts, &frozen_profile_id)?;
    let claimed_profile_id: [u8; DIGEST_BYTES] =
        subject
            .try_into()
            .map_err(|_| B4ArtifactProfileAdapterError::SubjectLength {
                actual: subject.len(),
                expected: DIGEST_BYTES,
            })?;
    match validate_profile_package_v1(
        contexts[0],
        ProfileArtifacts {
            algorithm: contexts[1],
            binary_data: contexts[2],
        },
        &claimed_profile_id,
    ) {
        Ok(_) => Err(B4ArtifactProfileAdapterError::UnexpectedActivatedPackageAcceptance),
        Err(ProfileManifestError::ProfileIdMismatch) => {
            Ok(B4ArtifactProfileRejection::ActivatedProfileId)
        }
        Err(error) => Err(B4ArtifactProfileAdapterError::CandidateManifest(error)),
    }
}

fn validate_profile_id_preimage_bundle(
    subject: &[u8],
) -> Result<B4ArtifactProfileRejection, B4ArtifactProfileAdapterError> {
    let envelope = decode_subject_envelope(
        subject,
        B4SubjectEnvelopeContract::new(
            B4SubjectEnvelopeKind::ProfileIdPreimageBundle,
            &PROFILE_ID_PREIMAGE_PARTS,
        ),
    )
    .map_err(B4ArtifactProfileAdapterError::SubjectEnvelope)?;
    let frozen_profile_id = authenticate_frozen_base()?;
    let parts = envelope.parts();
    let manifest = StarkProfileManifestV1::decode(parts[0])
        .map_err(B4ArtifactProfileAdapterError::CandidateManifest)?;
    manifest
        .validate_initial_profile_target()
        .map_err(B4ArtifactProfileAdapterError::CandidateInitialTarget)?;
    if manifest
        .profile_id()
        .map_err(B4ArtifactProfileAdapterError::CandidateManifest)?
        != frozen_profile_id
    {
        return Err(B4ArtifactProfileAdapterError::CandidateProfileId);
    }
    let claimed_preimage: &[u8; PROFILE_ID_PREIMAGE_BYTES] =
        parts[1]
            .try_into()
            .map_err(|_| B4ArtifactProfileAdapterError::SubjectLength {
                actual: parts[1].len(),
                expected: PROFILE_ID_PREIMAGE_BYTES,
            })?;
    match validate_profile_id_preimage(parts[0], claimed_preimage) {
        Ok(()) => Err(B4ArtifactProfileAdapterError::UnexpectedProfileIdPreimageAcceptance),
        Err(ProfileIdPreimageValidationError::Mismatch) => {
            Ok(B4ArtifactProfileRejection::ProfileIdPreimage)
        }
        Err(ProfileIdPreimageValidationError::Construction(_)) => {
            Err(B4ArtifactProfileAdapterError::ProfileIdPreimageConstruction)
        }
    }
}

fn map_manifest_codec_error(
    error: ProfileManifestError,
) -> Result<B4ArtifactProfileRejection, B4ArtifactProfileAdapterError> {
    Ok(match error {
        ProfileManifestError::InvalidLength { .. } => B4ArtifactProfileRejection::ManifestLength,
        ProfileManifestError::UnsupportedVersion(_) => B4ArtifactProfileRejection::ManifestVersion,
        ProfileManifestError::ZeroProofLength => B4ArtifactProfileRejection::ManifestProofLength,
        ProfileManifestError::UnsupportedControlKind { index, .. } => {
            B4ArtifactProfileRejection::ManifestTerminalKind { index }
        }
        ProfileManifestError::InvalidControlParameter { index, .. } => {
            B4ArtifactProfileRejection::ManifestTerminalParameter { index }
        }
        ProfileManifestError::ControlOrder(index) => {
            B4ArtifactProfileRejection::ManifestTerminalOrder { index }
        }
        ProfileManifestError::DuplicateControlId(index) => {
            B4ArtifactProfileRejection::ManifestTerminalControlIdDuplicate { index }
        }
        ProfileManifestError::ArtifactKind { index, .. } => {
            B4ArtifactProfileRejection::ManifestArtifactKind { index }
        }
        ProfileManifestError::EmptyArtifact(index) => {
            B4ArtifactProfileRejection::ManifestArtifactEmpty { index }
        }
        error => return Err(B4ArtifactProfileAdapterError::CandidateManifest(error)),
    })
}

fn authenticate_frozen_base() -> Result<[u8; DIGEST_BYTES], B4ArtifactProfileAdapterError> {
    let manifest = StarkProfileManifestV1::decode(FROZEN_MANIFEST)
        .map_err(B4ArtifactProfileAdapterError::FrozenManifest)?;
    if manifest
        .encode()
        .map_err(B4ArtifactProfileAdapterError::FrozenManifest)?
        .as_slice()
        != FROZEN_MANIFEST
    {
        return Err(B4ArtifactProfileAdapterError::FrozenProfileId);
    }
    manifest
        .validate_initial_profile_target()
        .map_err(B4ArtifactProfileAdapterError::FrozenInitialTarget)?;
    authenticate_profile_algorithm(FROZEN_ALGORITHM, &manifest)
        .map_err(|_| B4ArtifactProfileAdapterError::FrozenAlgorithm)?;
    constants_artifact::verify_canonical(FROZEN_CONSTANTS)
        .map_err(|_| B4ArtifactProfileAdapterError::FrozenConstants)?;
    let profile_id = manifest
        .profile_id()
        .map_err(B4ArtifactProfileAdapterError::FrozenManifest)?;
    if hex::encode(profile_id) != INITIAL_PROFILE_ID_HEX {
        return Err(B4ArtifactProfileAdapterError::FrozenProfileId);
    }
    validate_profile_package_v1(
        FROZEN_MANIFEST,
        ProfileArtifacts {
            algorithm: FROZEN_ALGORITHM,
            binary_data: FROZEN_CONSTANTS,
        },
        &profile_id,
    )
    .map_err(B4ArtifactProfileAdapterError::FrozenPackage)?;
    Ok(profile_id)
}

fn authenticate_supplied_base(
    contexts: &[&[u8]],
    frozen_profile_id: &[u8; DIGEST_BYTES],
) -> Result<(), B4ArtifactProfileAdapterError> {
    let package = validate_profile_package_v1(
        contexts[0],
        ProfileArtifacts {
            algorithm: contexts[1],
            binary_data: contexts[2],
        },
        frozen_profile_id,
    )
    .map_err(B4ArtifactProfileAdapterError::FrozenPackage)?;
    package
        .manifest()
        .validate_initial_profile_target()
        .map_err(B4ArtifactProfileAdapterError::FrozenInitialTarget)?;
    authenticate_profile_algorithm(contexts[1], package.manifest())
        .map_err(|_| B4ArtifactProfileAdapterError::FrozenAlgorithm)?;
    constants_artifact::verify_canonical(contexts[2])
        .map_err(|_| B4ArtifactProfileAdapterError::FrozenConstants)?;
    Ok(())
}

fn require_context_count(
    contexts: &[&[u8]],
    expected: usize,
) -> Result<(), B4ArtifactProfileAdapterError> {
    if contexts.len() == expected {
        Ok(())
    } else {
        Err(B4ArtifactProfileAdapterError::ContextCount {
            actual: contexts.len(),
            expected,
        })
    }
}

fn require_subject_length(
    subject: &[u8],
    expected: usize,
) -> Result<(), B4ArtifactProfileAdapterError> {
    if subject.len() == expected {
        Ok(())
    } else {
        Err(B4ArtifactProfileAdapterError::SubjectLength {
            actual: subject.len(),
            expected,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTROL_TABLE_OFFSET: usize = 42;
    const CONTROL_BYTES: usize = 34;
    const CONTROL_ID_OFFSET: usize = 2;
    const ALGORITHM_REFERENCE_OFFSET: usize = 382;
    const BINARY_REFERENCE_OFFSET: usize = 420;
    const REFERENCE_BYTES: usize = 38;

    fn frozen_manifest() -> [u8; MANIFEST_BYTES] {
        FROZEN_MANIFEST.try_into().unwrap()
    }

    fn envelope(kind: B4SubjectEnvelopeKind, parts: &[&[u8]]) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(b"EIP45B4S");
        encoded.push(1);
        encoded.push(kind as u8);
        encoded.extend_from_slice(&u16::try_from(parts.len()).unwrap().to_le_bytes());
        for part in parts {
            encoded.extend_from_slice(&u32::try_from(part.len()).unwrap().to_le_bytes());
            encoded.extend_from_slice(part);
        }
        encoded
    }

    fn no_context(
        selector: B4NegativeHandlerSelector,
        subject: &[u8],
    ) -> Result<B4ArtifactProfileRejection, B4ArtifactProfileAdapterError> {
        validate_profile_negative(selector, subject, &[])
    }

    fn profile_package(manifest: &[u8], algorithm: &[u8], constants: &[u8]) -> Vec<u8> {
        envelope(
            B4SubjectEnvelopeKind::ProfilePackage,
            &[manifest, algorithm, constants],
        )
    }

    fn swap_fixed<const N: usize>(bytes: &mut [u8], first: usize, second: usize) {
        let first_bytes: [u8; N] = bytes[first..first + N].try_into().unwrap();
        let second_bytes: [u8; N] = bytes[second..second + N].try_into().unwrap();
        bytes[first..first + N].copy_from_slice(&second_bytes);
        bytes[second..second + N].copy_from_slice(&first_bytes);
    }

    #[test]
    fn manifest_codec_rejects_every_fixed_manifest_and_table_variant() {
        let selector = B4NegativeHandlerSelector::ArtifactProfileManifestCodec;
        let canonical = frozen_manifest();
        let mut observed = 0;

        assert_eq!(
            no_context(selector, &canonical[..MANIFEST_BYTES - 1]),
            Ok(B4ArtifactProfileRejection::ManifestLength)
        );
        observed += 1;

        let mut trailing = canonical.to_vec();
        trailing.push(0);
        assert_eq!(
            no_context(selector, &trailing),
            Ok(B4ArtifactProfileRejection::ManifestLength)
        );
        observed += 1;

        let mut version = canonical;
        version[0] ^= 1;
        assert_eq!(
            no_context(selector, &version),
            Ok(B4ArtifactProfileRejection::ManifestVersion)
        );
        observed += 1;

        let mut duplicate_id = canonical;
        let first_id: [u8; DIGEST_BYTES] = duplicate_id[CONTROL_TABLE_OFFSET + CONTROL_ID_OFFSET
            ..CONTROL_TABLE_OFFSET + CONTROL_ID_OFFSET + DIGEST_BYTES]
            .try_into()
            .unwrap();
        let second_id = CONTROL_TABLE_OFFSET + CONTROL_BYTES + CONTROL_ID_OFFSET;
        duplicate_id[second_id..second_id + DIGEST_BYTES].copy_from_slice(&first_id);
        assert_eq!(
            no_context(selector, &duplicate_id),
            Ok(B4ArtifactProfileRejection::ManifestTerminalControlIdDuplicate { index: 1 })
        );
        observed += 1;

        let mut reordered_controls = canonical;
        swap_fixed::<CONTROL_BYTES>(
            &mut reordered_controls,
            CONTROL_TABLE_OFFSET,
            CONTROL_TABLE_OFFSET + CONTROL_BYTES,
        );
        assert_eq!(
            no_context(selector, &reordered_controls),
            Ok(B4ArtifactProfileRejection::ManifestTerminalOrder { index: 1 })
        );
        observed += 1;

        let mut reordered_references = canonical;
        swap_fixed::<REFERENCE_BYTES>(
            &mut reordered_references,
            ALGORITHM_REFERENCE_OFFSET,
            BINARY_REFERENCE_OFFSET,
        );
        assert_eq!(
            no_context(selector, &reordered_references),
            Ok(B4ArtifactProfileRejection::ManifestArtifactKind { index: 0 })
        );
        observed += 1;

        for index in 0..10 {
            let mut changed = canonical;
            changed[CONTROL_TABLE_OFFSET + index * CONTROL_BYTES] = u8::MAX;
            assert_eq!(
                no_context(selector, &changed),
                Ok(B4ArtifactProfileRejection::ManifestTerminalKind { index })
            );
            observed += 1;
        }

        for index in 0..10 {
            let mut changed = canonical;
            let parameter = CONTROL_TABLE_OFFSET + index * CONTROL_BYTES + 1;
            let expected = if index < 8 {
                changed[parameter] = if index == 0 {
                    canonical[CONTROL_TABLE_OFFSET + CONTROL_BYTES + 1]
                } else {
                    canonical[CONTROL_TABLE_OFFSET + (index - 1) * CONTROL_BYTES + 1]
                };
                B4ArtifactProfileRejection::ManifestTerminalOrder {
                    index: index.max(1),
                }
            } else {
                changed[parameter] = 1;
                B4ArtifactProfileRejection::ManifestTerminalParameter { index }
            };
            assert_eq!(no_context(selector, &changed), Ok(expected));
            observed += 1;
        }

        for (index, offset, kind) in [
            (0, ALGORITHM_REFERENCE_OFFSET, 2_u16),
            (1, BINARY_REFERENCE_OFFSET, 1_u16),
        ] {
            let mut changed = canonical;
            changed[offset..offset + 2].copy_from_slice(&kind.to_le_bytes());
            assert_eq!(
                no_context(selector, &changed),
                Ok(B4ArtifactProfileRejection::ManifestArtifactKind { index })
            );
            observed += 1;
        }

        assert_eq!(observed, 28);
    }

    #[test]
    fn initial_target_rejects_all_four_scalars_and_ten_control_ids() {
        let selector = B4NegativeHandlerSelector::ArtifactInitialProfileTarget;
        let canonical = frozen_manifest();
        let mutations = [
            (1, B4ArtifactProfileRejection::InitialExactProofBytes),
            (5, B4ArtifactProfileRejection::InitialMaximumPayload),
            (9, B4ArtifactProfileRejection::InitialOuterPo2),
            (10, B4ArtifactProfileRejection::InitialInnerControlRoot),
        ];
        let mut observed = 0;

        for (offset, expected) in mutations {
            let mut changed = canonical;
            changed[offset] ^= 1;
            assert_eq!(no_context(selector, &changed), Ok(expected));
            observed += 1;
        }

        for index in 0..10 {
            let mut changed = canonical;
            changed[CONTROL_TABLE_OFFSET + index * CONTROL_BYTES + CONTROL_ID_OFFSET] ^= 1;
            assert_eq!(
                no_context(selector, &changed),
                Ok(B4ArtifactProfileRejection::InitialTerminalControl { index })
            );
            observed += 1;
        }

        assert_eq!(observed, 14);
    }

    #[test]
    fn artifact_envelope_rejects_all_reference_and_artifact_byte_variants() {
        let selector = B4NegativeHandlerSelector::ArtifactProfileArtifactEnvelope;
        let canonical = frozen_manifest();
        let mut observed = 0;

        for (offset, kind) in [
            (ALGORITHM_REFERENCE_OFFSET + 2, 1_u16),
            (BINARY_REFERENCE_OFFSET + 2, 2_u16),
        ] {
            let mut changed = canonical;
            let current = u32::from_le_bytes(changed[offset..offset + 4].try_into().unwrap());
            changed[offset..offset + 4].copy_from_slice(&(current + 1).to_le_bytes());
            let subject = profile_package(&changed, FROZEN_ALGORITHM, FROZEN_CONSTANTS);
            assert_eq!(
                no_context(selector, &subject),
                Ok(B4ArtifactProfileRejection::ArtifactLength { kind })
            );
            observed += 1;
        }

        for (offset, kind) in [
            (ALGORITHM_REFERENCE_OFFSET + 6, 1_u16),
            (BINARY_REFERENCE_OFFSET + 6, 2_u16),
        ] {
            let mut changed = canonical;
            changed[offset] ^= 1;
            let subject = profile_package(&changed, FROZEN_ALGORITHM, FROZEN_CONSTANTS);
            assert_eq!(
                no_context(selector, &subject),
                Ok(B4ArtifactProfileRejection::ArtifactDigest { kind })
            );
            observed += 1;
        }

        let mut changed_algorithm = FROZEN_ALGORITHM.to_vec();
        changed_algorithm[0] ^= 1;
        let subject = profile_package(&canonical, &changed_algorithm, FROZEN_CONSTANTS);
        assert_eq!(
            no_context(selector, &subject),
            Ok(B4ArtifactProfileRejection::ArtifactDigest { kind: 1 })
        );
        observed += 1;

        let mut changed_constants = FROZEN_CONSTANTS.to_vec();
        changed_constants[0] ^= 1;
        let subject = profile_package(&canonical, FROZEN_ALGORITHM, &changed_constants);
        assert_eq!(
            no_context(selector, &subject),
            Ok(B4ArtifactProfileRejection::ArtifactDigest { kind: 2 })
        );
        observed += 1;

        assert_eq!(observed, 6);
    }

    #[test]
    fn activated_package_rejects_the_claimed_profile_id_variant() {
        let selector = B4NegativeHandlerSelector::ArtifactActivatedProfilePackage;
        let mut claimed = StarkProfileManifestV1::decode(FROZEN_MANIFEST)
            .unwrap()
            .profile_id()
            .unwrap();
        claimed[0] ^= 1;
        assert_eq!(
            validate_profile_negative(
                selector,
                &claimed,
                &[FROZEN_MANIFEST, FROZEN_ALGORITHM, FROZEN_CONSTANTS],
            ),
            Ok(B4ArtifactProfileRejection::ActivatedProfileId)
        );
    }

    #[test]
    fn profile_id_preimage_policy_rejects_the_single_preimage_variant() {
        let selector = B4NegativeHandlerSelector::ArtifactProfileIdPreimage;
        let mut claimed = crate::profile::profile_id_preimage(FROZEN_MANIFEST).unwrap();
        claimed[PROFILE_ID_PREIMAGE_BYTES - 1] ^= 1;
        let subject = envelope(
            B4SubjectEnvelopeKind::ProfileIdPreimageBundle,
            &[FROZEN_MANIFEST, &claimed],
        );
        assert_eq!(
            no_context(selector, &subject),
            Ok(B4ArtifactProfileRejection::ProfileIdPreimage)
        );
    }

    #[test]
    fn valid_subjects_and_private_framing_failures_cannot_emit_rejections() {
        assert_eq!(
            no_context(
                B4NegativeHandlerSelector::ArtifactProfileManifestCodec,
                FROZEN_MANIFEST,
            ),
            Err(B4ArtifactProfileAdapterError::UnexpectedManifestCodecAcceptance)
        );
        assert_eq!(
            no_context(
                B4NegativeHandlerSelector::ArtifactInitialProfileTarget,
                FROZEN_MANIFEST,
            ),
            Err(B4ArtifactProfileAdapterError::UnexpectedInitialTargetAcceptance)
        );

        let valid_package = profile_package(FROZEN_MANIFEST, FROZEN_ALGORITHM, FROZEN_CONSTANTS);
        assert_eq!(
            no_context(
                B4NegativeHandlerSelector::ArtifactProfileArtifactEnvelope,
                &valid_package,
            ),
            Err(B4ArtifactProfileAdapterError::UnexpectedArtifactEnvelopeAcceptance)
        );

        let valid_id = StarkProfileManifestV1::decode(FROZEN_MANIFEST)
            .unwrap()
            .profile_id()
            .unwrap();
        assert_eq!(
            validate_profile_negative(
                B4NegativeHandlerSelector::ArtifactActivatedProfilePackage,
                &valid_id,
                &[FROZEN_MANIFEST, FROZEN_ALGORITHM, FROZEN_CONSTANTS],
            ),
            Err(B4ArtifactProfileAdapterError::UnexpectedActivatedPackageAcceptance)
        );

        let valid_preimage = crate::profile::profile_id_preimage(FROZEN_MANIFEST).unwrap();
        let valid_bundle = envelope(
            B4SubjectEnvelopeKind::ProfileIdPreimageBundle,
            &[FROZEN_MANIFEST, &valid_preimage],
        );
        assert_eq!(
            no_context(
                B4NegativeHandlerSelector::ArtifactProfileIdPreimage,
                &valid_bundle,
            ),
            Err(B4ArtifactProfileAdapterError::UnexpectedProfileIdPreimageAcceptance)
        );

        let wrong_kind = envelope(
            B4SubjectEnvelopeKind::ProfileIdPreimageBundle,
            &[FROZEN_MANIFEST, FROZEN_ALGORITHM, FROZEN_CONSTANTS],
        );
        assert!(matches!(
            no_context(
                B4NegativeHandlerSelector::ArtifactProfileArtifactEnvelope,
                &wrong_kind,
            ),
            Err(B4ArtifactProfileAdapterError::SubjectEnvelope(_))
        ));
        assert_eq!(
            validate_profile_negative(
                B4NegativeHandlerSelector::ArtifactActivatedProfilePackage,
                &valid_id,
                &[FROZEN_MANIFEST, FROZEN_ALGORITHM],
            ),
            Err(B4ArtifactProfileAdapterError::ContextCount {
                actual: 2,
                expected: 3,
            })
        );
        assert_eq!(
            no_context(B4NegativeHandlerSelector::ArtifactTerminalPolicy, b"x"),
            Err(B4ArtifactProfileAdapterError::UnsupportedSelector)
        );
    }

    #[test]
    fn profile_bundle_part_and_activated_context_failures_remain_private() {
        let valid_id = StarkProfileManifestV1::decode(FROZEN_MANIFEST)
            .unwrap()
            .profile_id()
            .unwrap();

        for malformed in [
            envelope(
                B4SubjectEnvelopeKind::ProfilePackage,
                &[FROZEN_MANIFEST, FROZEN_ALGORITHM],
            ),
            envelope(
                B4SubjectEnvelopeKind::ProfilePackage,
                &[
                    FROZEN_MANIFEST,
                    FROZEN_ALGORITHM,
                    FROZEN_CONSTANTS,
                    b"extra",
                ],
            ),
            envelope(
                B4SubjectEnvelopeKind::ProfilePackage,
                &[FROZEN_ALGORITHM, FROZEN_MANIFEST, FROZEN_CONSTANTS],
            ),
        ] {
            assert!(matches!(
                no_context(
                    B4NegativeHandlerSelector::ArtifactProfileArtifactEnvelope,
                    &malformed,
                ),
                Err(B4ArtifactProfileAdapterError::SubjectEnvelope(_))
            ));
        }

        let valid_preimage = crate::profile::profile_id_preimage(FROZEN_MANIFEST).unwrap();
        for malformed in [
            envelope(
                B4SubjectEnvelopeKind::ProfileIdPreimageBundle,
                &[FROZEN_MANIFEST],
            ),
            envelope(
                B4SubjectEnvelopeKind::ProfileIdPreimageBundle,
                &[FROZEN_MANIFEST, &valid_preimage, b"extra"],
            ),
            envelope(
                B4SubjectEnvelopeKind::ProfileIdPreimageBundle,
                &[&valid_preimage, FROZEN_MANIFEST],
            ),
        ] {
            assert!(matches!(
                no_context(
                    B4NegativeHandlerSelector::ArtifactProfileIdPreimage,
                    &malformed,
                ),
                Err(B4ArtifactProfileAdapterError::SubjectEnvelope(_))
            ));
        }

        assert!(matches!(
            validate_profile_negative(
                B4NegativeHandlerSelector::ArtifactActivatedProfilePackage,
                &valid_id,
                &[FROZEN_MANIFEST, FROZEN_CONSTANTS, FROZEN_ALGORITHM],
            ),
            Err(B4ArtifactProfileAdapterError::FrozenPackage(_)
                | B4ArtifactProfileAdapterError::FrozenAlgorithm
                | B4ArtifactProfileAdapterError::FrozenConstants)
        ));
        assert_eq!(
            validate_profile_negative(
                B4NegativeHandlerSelector::ArtifactActivatedProfilePackage,
                &valid_id,
                &[
                    FROZEN_MANIFEST,
                    FROZEN_ALGORITHM,
                    FROZEN_CONSTANTS,
                    b"extra",
                ],
            ),
            Err(B4ArtifactProfileAdapterError::ContextCount {
                actual: 4,
                expected: 3,
            })
        );

        let mut malformed_manifest = frozen_manifest();
        malformed_manifest[0] ^= 1;
        let mut changed_id = valid_id;
        changed_id[0] ^= 1;
        assert!(matches!(
            validate_profile_negative(
                B4NegativeHandlerSelector::ArtifactActivatedProfilePackage,
                &changed_id,
                &[&malformed_manifest, FROZEN_ALGORITHM, FROZEN_CONSTANTS],
            ),
            Err(B4ArtifactProfileAdapterError::FrozenPackage(_))
        ));
    }
}
