// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Producer-backed terminal-metadata derivation.
//!
//! The expected 34-byte record is derived only from a successfully verified
//! positive root and the manifest bytes retained by that same authenticated
//! root measurement. Candidate bytes are consulted only after derivation.

use crate::{
    b4_terminal_metadata_record::{
        B4TerminalMetadataRecordError, project_verified_join_terminal_record,
    },
    constants::{MANIFEST_BYTES, MANIFEST_CONTROL_ENTRY_BYTES},
    profile_manifest::StarkProfileManifestV1,
};

use super::input::B4PositiveVerifierRootSources;
use super::positive::{
    B4PositiveTerminalObservationV1, verify_positive_sources_with_manifest_evidence,
};

pub(super) const TERMINAL_METADATA_RECORD_BYTES: usize = MANIFEST_CONTROL_ENTRY_BYTES;

/// Private producer failures which cannot become negative observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum B4TerminalMetadataProducerErrorKind {
    PositiveRoot,
    ProfileManifest,
    PositiveManifestEvidenceMismatch,
    TerminalObservationEncoding,
    TerminalObservationProfileBinding,
    CandidateRecordLength,
    CandidateRecordMutationShape,
    UnexpectedAcceptance,
}

/// Exact terminal tuple derived before any candidate comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct B4DerivedTerminalMetadata([u8; TERMINAL_METADATA_RECORD_BYTES]);

impl B4DerivedTerminalMetadata {
    #[allow(
        dead_code,
        reason = "the closed materializer will use the producer-derived record; runtime comparison currently consumes it internally"
    )]
    pub(super) const fn bytes(self) -> [u8; TERMINAL_METADATA_RECORD_BYTES] {
        self.0
    }
}

/// Derive the exact terminal record from immutable positive-root byte views.
pub(super) fn derive_terminal_metadata_from_positive_sources(
    sources: B4PositiveVerifierRootSources<'_>,
    manifest_source: &[u8],
) -> Result<B4DerivedTerminalMetadata, B4TerminalMetadataProducerErrorKind> {
    let manifest = decode_manifest_evidence(manifest_source)?;
    let (observation, measured_manifest) = verify_positive_sources_with_manifest_evidence(sources)
        .map_err(|_| B4TerminalMetadataProducerErrorKind::PositiveRoot)?;
    derive_terminal_metadata_from_verified(
        &observation,
        &measured_manifest,
        manifest_source,
        &manifest,
    )
}

fn derive_terminal_metadata_from_verified(
    observation: &super::positive::Eip0045B4PositiveObservationV1,
    measured_manifest: &[u8; MANIFEST_BYTES],
    manifest_source: &[u8],
    manifest: &StarkProfileManifestV1,
) -> Result<B4DerivedTerminalMetadata, B4TerminalMetadataProducerErrorKind> {
    if measured_manifest.as_slice() != manifest_source {
        return Err(B4TerminalMetadataProducerErrorKind::PositiveManifestEvidenceMismatch);
    }
    encode_observed_terminal(observation.terminal(), manifest)
}

/// Compare a candidate after complete positive replay from positional bytes.
pub(super) fn reject_terminal_metadata_candidate_from_positive_sources(
    sources: B4PositiveVerifierRootSources<'_>,
    manifest_source: &[u8],
    candidate_record: &[u8],
) -> Result<B4DerivedTerminalMetadata, B4TerminalMetadataProducerErrorKind> {
    let derived = derive_terminal_metadata_from_positive_sources(sources, manifest_source)?;
    let candidate: &[u8; TERMINAL_METADATA_RECORD_BYTES] = candidate_record
        .try_into()
        .map_err(|_| B4TerminalMetadataProducerErrorKind::CandidateRecordLength)?;
    require_one_terminal_metadata_field_mutation(&derived.0, candidate)?;
    Ok(derived)
}

fn require_one_terminal_metadata_field_mutation(
    derived: &[u8; TERMINAL_METADATA_RECORD_BYTES],
    candidate: &[u8; TERMINAL_METADATA_RECORD_BYTES],
) -> Result<(), B4TerminalMetadataProducerErrorKind> {
    let changed_fields = u8::from(candidate[0] != derived[0])
        + u8::from(candidate[1] != derived[1])
        + u8::from(candidate[2..] != derived[2..]);
    match changed_fields {
        0 => Err(B4TerminalMetadataProducerErrorKind::UnexpectedAcceptance),
        1 => Ok(()),
        _ => Err(B4TerminalMetadataProducerErrorKind::CandidateRecordMutationShape),
    }
}

fn decode_manifest_evidence(
    manifest_source: &[u8],
) -> Result<StarkProfileManifestV1, B4TerminalMetadataProducerErrorKind> {
    let exact_source: &[u8; MANIFEST_BYTES] = manifest_source
        .try_into()
        .map_err(|_| B4TerminalMetadataProducerErrorKind::ProfileManifest)?;
    let manifest = StarkProfileManifestV1::decode(exact_source)
        .map_err(|_| B4TerminalMetadataProducerErrorKind::ProfileManifest)?;
    if manifest
        .encode()
        .map_err(|_| B4TerminalMetadataProducerErrorKind::ProfileManifest)?
        .as_slice()
        != manifest_source
        || manifest.validate_initial_profile_target().is_err()
    {
        return Err(B4TerminalMetadataProducerErrorKind::ProfileManifest);
    }
    Ok(manifest)
}

fn encode_observed_terminal(
    terminal: &B4PositiveTerminalObservationV1,
    manifest: &StarkProfileManifestV1,
) -> Result<B4DerivedTerminalMetadata, B4TerminalMetadataProducerErrorKind> {
    project_verified_join_terminal_record(terminal, manifest)
        .map(B4DerivedTerminalMetadata)
        .map_err(|error| match error {
            B4TerminalMetadataRecordError::Encoding => {
                B4TerminalMetadataProducerErrorKind::TerminalObservationEncoding
            }
            B4TerminalMetadataRecordError::ProfileBinding => {
                B4TerminalMetadataProducerErrorKind::TerminalObservationProfileBinding
            }
        })
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        path::{Path, PathBuf},
    };

    use crate::constants::{
        TERMINAL_CONTROL_KIND_JOIN, TERMINAL_CONTROL_KIND_LIFT, TERMINAL_CONTROL_KIND_RESOLVE,
    };

    use super::super::input::{
        GUEST_ELF_FILE, POSITIVE_INPUT_FILE, PROFILE_ALGORITHM_FILE, PROFILE_CONSTANTS_FILE,
        PROFILE_MANIFEST_FILE, RAW_SEAL_FILE, STATEMENT_FILE,
    };
    use super::super::positive::B4PositiveTerminalKind;
    use super::*;

    const MANIFEST: &[u8; MANIFEST_BYTES] =
        include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");

    fn manifest() -> StarkProfileManifestV1 {
        let manifest = StarkProfileManifestV1::decode(MANIFEST).unwrap();
        manifest.validate_initial_profile_target().unwrap();
        manifest
    }

    struct OwnedPositiveSources {
        verifier_input: Vec<u8>,
        profile_manifest: Vec<u8>,
        profile_algorithm: Vec<u8>,
        profile_constants: Vec<u8>,
        guest_elf: Vec<u8>,
        statement: Vec<u8>,
        raw_seal: Vec<u8>,
    }

    impl OwnedPositiveSources {
        fn from_root(root: &Path) -> Self {
            Self {
                verifier_input: fs::read(root.join(POSITIVE_INPUT_FILE)).unwrap(),
                profile_manifest: fs::read(root.join(PROFILE_MANIFEST_FILE)).unwrap(),
                profile_algorithm: fs::read(root.join(PROFILE_ALGORITHM_FILE)).unwrap(),
                profile_constants: fs::read(root.join(PROFILE_CONSTANTS_FILE)).unwrap(),
                guest_elf: fs::read(root.join(GUEST_ELF_FILE)).unwrap(),
                statement: fs::read(root.join(STATEMENT_FILE)).unwrap(),
                raw_seal: fs::read(root.join(RAW_SEAL_FILE)).unwrap(),
            }
        }

        fn invalid() -> Self {
            Self {
                verifier_input: b"x".to_vec(),
                profile_manifest: b"x".to_vec(),
                profile_algorithm: b"x".to_vec(),
                profile_constants: b"x".to_vec(),
                guest_elf: b"x".to_vec(),
                statement: b"x".to_vec(),
                raw_seal: b"x".to_vec(),
            }
        }

        fn views(&self) -> B4PositiveVerifierRootSources<'_> {
            B4PositiveVerifierRootSources {
                verifier_input: &self.verifier_input,
                profile_manifest: &self.profile_manifest,
                profile_algorithm: &self.profile_algorithm,
                profile_constants: &self.profile_constants,
                guest_elf: &self.guest_elf,
                statement: &self.statement,
                raw_seal: &self.raw_seal,
            }
        }
    }

    #[test]
    fn terminal_join_zero_is_bound_to_one_exact_manifest_row() {
        let manifest = manifest();
        let join = manifest
            .terminal_controls()
            .iter()
            .find(|control| {
                control.control_kind() == TERMINAL_CONTROL_KIND_JOIN && control.parameter() == 0
            })
            .unwrap();
        let observed = B4PositiveTerminalObservationV1 {
            kind: B4PositiveTerminalKind::Join,
            parameter: 0,
            control_id: hex::encode(join.control_id()),
        };
        let record = encode_observed_terminal(&observed, &manifest)
            .unwrap()
            .bytes();
        assert_eq!(record[0], TERMINAL_CONTROL_KIND_JOIN);
        assert_eq!(record[1], 0);
        assert_eq!(&record[2..], &join.control_id());
    }

    #[test]
    fn lift_and_resolve_manifest_rows_cannot_substitute_for_terminal_join() {
        let manifest = manifest();
        for (control_kind, observed_kind) in [
            (TERMINAL_CONTROL_KIND_LIFT, B4PositiveTerminalKind::Lift),
            (
                TERMINAL_CONTROL_KIND_RESOLVE,
                B4PositiveTerminalKind::Resolve,
            ),
        ] {
            let control = manifest
                .terminal_controls()
                .iter()
                .find(|control| control.control_kind() == control_kind)
                .unwrap();
            let observed = B4PositiveTerminalObservationV1 {
                kind: observed_kind,
                parameter: control.parameter(),
                control_id: hex::encode(control.control_id()),
            };
            assert_eq!(
                encode_observed_terminal(&observed, &manifest),
                Err(B4TerminalMetadataProducerErrorKind::TerminalObservationProfileBinding)
            );
        }
    }

    #[test]
    fn malformed_or_unbound_observation_remains_private() {
        let manifest = manifest();
        let join = manifest
            .terminal_controls()
            .iter()
            .find(|control| control.control_kind() == TERMINAL_CONTROL_KIND_JOIN)
            .unwrap();
        let mut unbound_id = join.control_id();
        unbound_id[0] ^= 1;
        let unbound = B4PositiveTerminalObservationV1 {
            kind: B4PositiveTerminalKind::Join,
            parameter: 0,
            control_id: hex::encode(unbound_id),
        };
        assert_eq!(
            encode_observed_terminal(&unbound, &manifest),
            Err(B4TerminalMetadataProducerErrorKind::TerminalObservationProfileBinding)
        );
        let malformed = B4PositiveTerminalObservationV1 {
            kind: B4PositiveTerminalKind::Join,
            parameter: 0,
            control_id: "AA".repeat(32),
        };
        assert_eq!(
            encode_observed_terminal(&malformed, &manifest),
            Err(B4TerminalMetadataProducerErrorKind::TerminalObservationEncoding)
        );
    }

    #[test]
    fn candidate_comparison_admits_exactly_one_semantic_field_mutation() {
        let derived = [0_u8; TERMINAL_METADATA_RECORD_BYTES];
        for index in [0, 1, 2, 33] {
            let mut candidate = derived;
            candidate[index] = 1;
            require_one_terminal_metadata_field_mutation(&derived, &candidate).unwrap();
        }

        assert_eq!(
            require_one_terminal_metadata_field_mutation(&derived, &derived),
            Err(B4TerminalMetadataProducerErrorKind::UnexpectedAcceptance)
        );
        let mut coordinated = derived;
        coordinated[0] = 1;
        coordinated[2] = 1;
        assert_eq!(
            require_one_terminal_metadata_field_mutation(&derived, &coordinated),
            Err(B4TerminalMetadataProducerErrorKind::CandidateRecordMutationShape)
        );
    }

    #[test]
    fn invalid_positive_sources_and_manifest_drift_fail_closed() {
        let invalid = OwnedPositiveSources::invalid();
        assert_eq!(
            derive_terminal_metadata_from_positive_sources(invalid.views(), MANIFEST),
            Err(B4TerminalMetadataProducerErrorKind::PositiveRoot)
        );
        assert_eq!(
            reject_terminal_metadata_candidate_from_positive_sources(
                invalid.views(),
                MANIFEST,
                &[]
            ),
            Err(B4TerminalMetadataProducerErrorKind::PositiveRoot)
        );
        let mut drift = MANIFEST.to_vec();
        drift[0] ^= 1;
        assert_eq!(
            derive_terminal_metadata_from_positive_sources(invalid.views(), &drift),
            Err(B4TerminalMetadataProducerErrorKind::ProfileManifest)
        );
    }

    #[test]
    #[ignore = "requires EIP0045_B4_TERMINAL_JOIN_POSITIVE_ROOT"]
    fn terminal_join_positive_root_derives_before_candidate_comparison() {
        let root = PathBuf::from(env::var_os("EIP0045_B4_TERMINAL_JOIN_POSITIVE_ROOT").unwrap());
        let sources = OwnedPositiveSources::from_root(&root);
        let derived =
            derive_terminal_metadata_from_positive_sources(sources.views(), MANIFEST).unwrap();
        assert_eq!(
            reject_terminal_metadata_candidate_from_positive_sources(
                sources.views(),
                MANIFEST,
                &derived.bytes()
            ),
            Err(B4TerminalMetadataProducerErrorKind::UnexpectedAcceptance)
        );
        for offset in [0, 1, 2] {
            let mut changed = derived.bytes();
            changed[offset] ^= 1;
            assert_eq!(
                reject_terminal_metadata_candidate_from_positive_sources(
                    sources.views(),
                    MANIFEST,
                    &changed
                )
                .unwrap(),
                derived
            );
        }
    }

    #[test]
    #[ignore = "requires EIP0045_B4_LIFT_PO2_15_POSITIVE_ROOT"]
    fn lift_po2_15_positive_root_cannot_supply_terminal_join_metadata() {
        let root = PathBuf::from(env::var_os("EIP0045_B4_LIFT_PO2_15_POSITIVE_ROOT").unwrap());
        let sources = OwnedPositiveSources::from_root(&root);
        assert_eq!(
            derive_terminal_metadata_from_positive_sources(sources.views(), MANIFEST),
            Err(B4TerminalMetadataProducerErrorKind::TerminalObservationProfileBinding)
        );
    }
}
