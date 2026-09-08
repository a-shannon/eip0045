// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Fixed owned positive root for the recursive `terminal-join` case.
//!
//! The unverified state exposes no materialization authority. Exact contexts
//! and terminal metadata become available only after the pinned in-memory
//! positive replay succeeds.

#![allow(dead_code)] // Task 4 consumes this seam only after the real case-8 root lands.

use anyhow::{Context as _, Result, ensure};
use risc0_binfmt::compute_image_id;
use sha2::{Digest as _, Sha256};

#[cfg(feature = "materializer-replay")]
use crate::{
    b4::{
        B4PositiveArtifactRole,
        B4PositiveArtifactRole::{ClaimDigest, ControlId, ImageId, Journal},
    },
    b4_fixture_sources::B4FixtureSourceResolverV1,
};
use crate::{
    b4_terminal_metadata_record::project_verified_join_terminal_record,
    b4_validator::{
        B4PositiveTerminalKind, B4PositiveVerifierRootSources, Eip0045B4PositiveObservationV1,
        synthesize_positive_verifier_input_v1, verify_positive_sources_with_manifest_evidence,
    },
    claim::ok_receipt_claim_digests,
    constants::{MANIFEST_BYTES, MANIFEST_CONTROL_ENTRY_BYTES, TERMINAL_CONTROL_KIND_JOIN},
    ergo_statement::parse_ergo_statement_v1,
    profile_manifest::{ProfileArtifacts, StarkProfileManifestV1, validate_profile_package_v1},
};

const CASE8_INDEX: usize = 8;
const CASE8_ID: &str = "terminal-join";

/// Exact packet-owned bytes needed to derive and replay fixed case 8.
pub(crate) struct B4Case8TerminalJoinPacketSourcesV1<'a> {
    pub(crate) profile_manifest: &'a [u8],
    pub(crate) profile_algorithm: &'a [u8],
    pub(crate) profile_constants: &'a [u8],
    pub(crate) guest_elf: &'a [u8],
    pub(crate) statement: &'a [u8],
    pub(crate) raw_seal: &'a [u8],
}

/// Owned but not yet verified positive root for the one fixed case-8 source.
///
/// No selector is accepted, and this state exposes no producer contexts or
/// terminal record outside this module.
pub(crate) struct B4OwnedCase8TerminalJoinRootV1 {
    verifier_input: Vec<u8>,
    profile_manifest: Vec<u8>,
    profile_algorithm: Vec<u8>,
    profile_constants: Vec<u8>,
    guest_elf: Vec<u8>,
    statement: Vec<u8>,
    raw_seal: Vec<u8>,
    expected_profile_id: [u8; 32],
    expected_program_id: [u8; 32],
    expected_statement_sha256: [u8; 32],
    expected_claim_digest: [u8; 32],
    expected_terminal_kind: u8,
    expected_terminal_parameter: u8,
    expected_control_id: [u8; 32],
}

impl B4OwnedCase8TerminalJoinRootV1 {
    /// Derive and own the fixed case-8 replay root from packet bytes alone.
    pub(crate) fn from_packet_sources(
        sources: B4Case8TerminalJoinPacketSourcesV1<'_>,
    ) -> Result<Self> {
        let manifest = StarkProfileManifestV1::decode(sources.profile_manifest)
            .context("cannot decode the packet-owned initial profile manifest")?;
        ensure!(
            manifest.encode()?.as_slice() == sources.profile_manifest,
            "packet-owned Manifest V1 decode/re-encode changed bytes"
        );
        manifest
            .validate_initial_profile_target()
            .context("packet-owned manifest differs from the frozen initial-profile target")?;
        let expected_profile_id = manifest.profile_id()?;
        let package = validate_profile_package_v1(
            sources.profile_manifest,
            ProfileArtifacts {
                algorithm: sources.profile_algorithm,
                binary_data: sources.profile_constants,
            },
            &expected_profile_id,
        )
        .context("packet-owned initial profile package is not internally bound")?;
        ensure!(
            package.manifest().encode()?.as_slice() == sources.profile_manifest
                && package.artifacts().algorithm == sources.profile_algorithm
                && package.artifacts().binary_data == sources.profile_constants,
            "validated packet-owned profile package did not retain its exact bytes"
        );

        let expected_program_id: [u8; 32] = compute_image_id(sources.guest_elf)
            .context("packet-owned guest is not a valid encoded RISC Zero program")?
            .into();
        let statement = parse_ergo_statement_v1(sources.statement)
            .context("cannot decode packet-owned ErgoStatementV1")?;
        ensure!(
            statement.encode()?.as_slice() == sources.statement,
            "packet-owned ErgoStatementV1 decode/re-encode changed bytes"
        );
        ensure!(
            statement.profile_id() == expected_profile_id,
            "packet-owned statement profile ID differs from the derived profile"
        );
        ensure!(
            statement.program_id() == expected_program_id,
            "packet-owned statement program ID differs from the derived guest image ID"
        );
        let expected_statement_sha256: [u8; 32] = Sha256::digest(sources.statement).into();
        let claim = ok_receipt_claim_digests(&expected_program_id, sources.statement)
            .context("cannot derive the packet-owned empty-assumptions OK receipt claim")?;
        ensure!(
            claim.journal_digest == expected_statement_sha256,
            "packet-owned receipt journal digest differs from the statement SHA-256"
        );
        let expected_claim_digest = claim.expected_claim;

        let join_controls = manifest
            .terminal_controls()
            .iter()
            .filter(|control| {
                control.control_kind() == TERMINAL_CONTROL_KIND_JOIN && control.parameter() == 0
            })
            .collect::<Vec<_>>();
        ensure!(
            join_controls.len() == 1,
            "packet-owned manifest does not contain exactly one Join/0 control"
        );
        let expected_control_id = join_controls[0].control_id();

        let verifier_input = synthesize_positive_verifier_input_v1(
            sources.profile_manifest,
            sources.profile_algorithm,
            sources.profile_constants,
            sources.guest_elf,
            sources.statement,
            sources.raw_seal,
        )
        .context("cannot synthesize the packet-owned case-8 verifier descriptor")?;

        Ok(Self {
            verifier_input,
            profile_manifest: sources.profile_manifest.to_vec(),
            profile_algorithm: sources.profile_algorithm.to_vec(),
            profile_constants: sources.profile_constants.to_vec(),
            guest_elf: sources.guest_elf.to_vec(),
            statement: sources.statement.to_vec(),
            raw_seal: sources.raw_seal.to_vec(),
            expected_profile_id,
            expected_program_id,
            expected_statement_sha256,
            expected_claim_digest,
            expected_terminal_kind: TERMINAL_CONTROL_KIND_JOIN,
            expected_terminal_parameter: 0,
            expected_control_id,
        })
    }

    /// Resolve and own exactly positive case 8 / `terminal-join`.
    #[cfg(feature = "materializer-replay")]
    pub(crate) fn from_resolver(resolver: &B4FixtureSourceResolverV1<'_>) -> Result<Self> {
        let input = resolver
            .positive_input()
            .context("cannot authenticate the fixed case-8 positive input package")?;
        let reference = resolver
            .global_reference_statement()
            .context("cannot resolve the global positive reference statement")?;
        let case = resolver
            .positive_case(CASE8_INDEX, CASE8_ID)
            .context("cannot authenticate fixed positive case 8 / terminal-join")?;
        ensure!(
            case.case_index() == CASE8_INDEX && case.case_id() == CASE8_ID,
            "authenticated positive source did not retain fixed case-8 identity"
        );

        let statement = case
            .artifact(Journal)
            .context("case-8 root lacks its authenticated Journal")?;
        ensure!(
            statement == reference.statement_bytes(),
            "case-8 Journal differs from the global positive reference statement"
        );
        let expected_profile_id = reference.statement().profile_id();
        let expected_program_id = reference.statement().program_id();
        let expected_statement_sha256: [u8; 32] = Sha256::digest(statement).into();
        let expected_claim_digest = reference.claim_digests().expected_claim;

        let case_program_id = exact_case_digest(&case, ImageId)?;
        ensure!(
            case_program_id == expected_program_id,
            "case-8 ImageId differs from the global reference statement"
        );
        let case_claim_digest = exact_case_digest(&case, ClaimDigest)?;
        ensure!(
            case_claim_digest == expected_claim_digest,
            "case-8 ClaimDigest differs from the reconstructed successful claim"
        );
        let expected_control_id = exact_case_digest(&case, ControlId)?;

        let manifest = input.initial_profile_manifest()?;
        ensure!(
            manifest.profile_id()? == expected_profile_id,
            "case-8 profile manifest differs from the global reference statement"
        );
        let matching_join_rows = manifest
            .terminal_controls()
            .iter()
            .filter(|control| {
                control.control_kind() == TERMINAL_CONTROL_KIND_JOIN
                    && control.parameter() == 0
                    && control.control_id() == expected_control_id
            })
            .count();
        ensure!(
            matching_join_rows == 1,
            "case-8 ControlId is not the sole Join/0 row in the initial profile manifest"
        );

        let root = Self::from_packet_sources(B4Case8TerminalJoinPacketSourcesV1 {
            profile_manifest: input.profile_manifest(),
            profile_algorithm: input.profile_algorithm(),
            profile_constants: input.profile_constants(),
            guest_elf: input.guest_elf(),
            statement,
            raw_seal: case.raw_seal(),
        })
        .context("cannot derive the fixed case-8 root from authenticated sources")?;
        ensure!(
            root.expected_profile_id == expected_profile_id
                && root.expected_program_id == expected_program_id
                && root.expected_statement_sha256 == expected_statement_sha256
                && root.expected_claim_digest == expected_claim_digest
                && root.expected_terminal_kind == TERMINAL_CONTROL_KIND_JOIN
                && root.expected_terminal_parameter == 0
                && root.expected_control_id == expected_control_id,
            "derived case-8 root differs from resolver-authenticated identities"
        );
        Ok(root)
    }

    /// Consume the unverified root and promote it only after one complete
    /// in-memory execution of the pinned positive verifier.
    pub(crate) fn replay(self) -> Result<B4VerifiedCase8TerminalJoinReplayV1> {
        let (observation, measured_manifest) =
            verify_positive_sources_with_manifest_evidence(self.sources())
                .context("fixed case-8 positive root failed direct in-memory replay")?;
        self.authenticate_replay(&observation, &measured_manifest)?;

        let manifest = StarkProfileManifestV1::decode(&measured_manifest)
            .context("replayed case-8 manifest evidence does not decode")?;
        ensure!(
            manifest.encode()?.as_slice() == measured_manifest,
            "replayed case-8 manifest evidence does not re-encode exactly"
        );
        let terminal_metadata_record = project_verified_join_terminal_record(
            observation.terminal(),
            &manifest,
        )
        .map_err(|error| {
            anyhow::anyhow!("verified case-8 terminal cannot project exact metadata: {error:?}")
        })?;
        ensure!(
            terminal_metadata_record[0] == self.expected_terminal_kind
                && terminal_metadata_record[1] == self.expected_terminal_parameter
                && terminal_metadata_record[2..] == self.expected_control_id,
            "verified case-8 terminal record differs from authenticated source identities"
        );

        Ok(B4VerifiedCase8TerminalJoinReplayV1 {
            root: self,
            observation,
            terminal_metadata_record,
        })
    }

    fn sources(&self) -> B4PositiveVerifierRootSources<'_> {
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

    fn contexts(&self) -> [&[u8]; 7] {
        [
            &self.verifier_input,
            &self.profile_manifest,
            &self.profile_algorithm,
            &self.profile_constants,
            &self.guest_elf,
            &self.statement,
            &self.raw_seal,
        ]
    }

    fn authenticate_replay(
        &self,
        observation: &Eip0045B4PositiveObservationV1,
        measured_manifest: &[u8; MANIFEST_BYTES],
    ) -> Result<()> {
        ensure!(
            measured_manifest.as_slice() == self.profile_manifest,
            "case-8 replay returned different manifest evidence"
        );
        ensure!(
            observation.profile_id() == hex::encode(self.expected_profile_id),
            "case-8 replay profile ID differs from authenticated source authority"
        );
        ensure!(
            observation.program_id() == hex::encode(self.expected_program_id),
            "case-8 replay program ID differs from authenticated source authority"
        );
        ensure!(
            observation.statement_sha256() == hex::encode(self.expected_statement_sha256),
            "case-8 replay statement SHA-256 differs from authenticated source authority"
        );
        ensure!(
            observation.claim_digest() == hex::encode(self.expected_claim_digest),
            "case-8 replay claim digest differs from authenticated source authority"
        );
        ensure!(
            observation.terminal().kind == B4PositiveTerminalKind::Join
                && observation.terminal().parameter == self.expected_terminal_parameter
                && observation.terminal().control_id == hex::encode(self.expected_control_id),
            "case-8 replay terminal tuple differs from authenticated source authority"
        );
        Ok(())
    }
}

#[cfg(feature = "materializer-replay")]
fn exact_case_digest(
    case: &crate::b4_fixture_sources::B4PositiveFixtureSourceViewV1<'_>,
    role: B4PositiveArtifactRole,
) -> Result<[u8; 32]> {
    case.artifact(role)?
        .try_into()
        .with_context(|| format!("case-8 {role:?} is not exactly 32 bytes"))
}

/// Case-8 replay authority after successful direct STARK verification and all
/// source/manifest/observation cross-bindings.
pub(crate) struct B4VerifiedCase8TerminalJoinReplayV1 {
    root: B4OwnedCase8TerminalJoinRootV1,
    observation: Eip0045B4PositiveObservationV1,
    terminal_metadata_record: [u8; MANIFEST_CONTROL_ENTRY_BYTES],
}

impl B4VerifiedCase8TerminalJoinReplayV1 {
    /// Exact seven contexts in the negative descriptor's required order.
    pub(crate) fn contexts(&self) -> [&[u8]; 7] {
        self.root.contexts()
    }

    /// Exact producer-derived `[Join, 0, controlId]` record.
    pub(crate) const fn terminal_metadata_record(&self) -> &[u8; MANIFEST_CONTROL_ENTRY_BYTES] {
        &self.terminal_metadata_record
    }

    /// Final accepted observation retained from the single direct replay.
    pub(crate) const fn observation(&self) -> &Eip0045B4PositiveObservationV1 {
        &self.observation
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "b4-terminal-evidence-packet")]
    use std::sync::OnceLock;

    #[cfg(feature = "b4-terminal-evidence-packet")]
    use risc0_binfmt::compute_image_id;
    use sha2::{Digest as _, Sha256};

    use crate::constants::TERMINAL_CONTROL_KIND_JOIN;
    #[cfg(feature = "materializer-replay")]
    use crate::{
        b4_fixture_sources::{
            B4FixtureSourceResolverV1, synthetic_case8_control_drift_top_level,
            synthetic_global_reference_statement_top_level,
        },
        canonical::validate_canonical_json_source,
        constants::{MANIFEST_CONTROL_ENTRY_BYTES, PROOF_BYTES},
    };
    #[cfg(feature = "b4-terminal-evidence-packet")]
    use crate::{
        b4_validator::B4StarkError,
        claim::ok_receipt_claim_digests,
        ergo_statement::{ErgoStatementV1, parse_ergo_statement_v1},
        profile_manifest::StarkProfileManifestV1,
    };

    #[cfg(feature = "b4-terminal-evidence-packet")]
    use super::B4Case8TerminalJoinPacketSourcesV1;
    use super::B4OwnedCase8TerminalJoinRootV1;

    #[cfg(feature = "b4-terminal-evidence-packet")]
    fn fixed_manifest() -> &'static [u8] {
        include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin")
    }

    #[cfg(feature = "b4-terminal-evidence-packet")]
    fn fixed_algorithm() -> &'static [u8] {
        include_bytes!("../../profiles/risc0-v3-succinct/algorithm.txt")
    }

    #[cfg(feature = "b4-terminal-evidence-packet")]
    fn fixed_constants() -> &'static [u8] {
        include_bytes!("../../profiles/risc0-v3-succinct/constants.bin")
    }

    #[cfg(feature = "b4-terminal-evidence-packet")]
    fn fixed_guest() -> &'static [u8] {
        static GUEST: OnceLock<Vec<u8>> = OnceLock::new();
        GUEST.get_or_init(|| crate::test_support::valid_program_fixture().0)
    }

    #[cfg(feature = "b4-terminal-evidence-packet")]
    fn fixed_statement() -> &'static [u8] {
        static STATEMENT: OnceLock<Vec<u8>> = OnceLock::new();
        STATEMENT.get_or_init(|| {
            let profile_id = StarkProfileManifestV1::decode(fixed_manifest())
                .unwrap()
                .profile_id()
                .unwrap();
            let program_id = compute_image_id(fixed_guest()).unwrap().into();
            ErgoStatementV1::new(
                [0x11; 32],
                profile_id,
                program_id,
                [0x22; 32],
                b"fixed packet case-8 replay",
            )
            .unwrap()
            .encode()
            .unwrap()
        })
    }

    #[cfg(feature = "b4-terminal-evidence-packet")]
    #[test]
    fn packet_sources_are_fixed_and_native() {
        let malformed_seal = vec![0_u8; crate::constants::PROOF_BYTES];
        let sources = B4Case8TerminalJoinPacketSourcesV1 {
            profile_manifest: fixed_manifest(),
            profile_algorithm: fixed_algorithm(),
            profile_constants: fixed_constants(),
            guest_elf: fixed_guest(),
            statement: fixed_statement(),
            raw_seal: &malformed_seal,
        };

        let root = B4OwnedCase8TerminalJoinRootV1::from_packet_sources(sources).unwrap();
        let manifest = StarkProfileManifestV1::decode(fixed_manifest()).unwrap();
        let statement = parse_ergo_statement_v1(fixed_statement()).unwrap();
        let program_id: [u8; 32] = compute_image_id(fixed_guest()).unwrap().into();
        let statement_sha256: [u8; 32] = Sha256::digest(fixed_statement()).into();
        let claim_digest = ok_receipt_claim_digests(&program_id, fixed_statement())
            .unwrap()
            .expected_claim;
        let join_controls = manifest
            .terminal_controls()
            .iter()
            .filter(|control| {
                control.control_kind() == TERMINAL_CONTROL_KIND_JOIN && control.parameter() == 0
            })
            .collect::<Vec<_>>();

        assert_eq!(root.expected_program_id, program_id);
        assert_eq!(root.expected_profile_id, manifest.profile_id().unwrap());
        assert_eq!(statement.profile_id(), root.expected_profile_id);
        assert_eq!(root.expected_statement_sha256, statement_sha256);
        assert_eq!(root.expected_claim_digest, claim_digest);
        assert_eq!(join_controls.len(), 1);
        assert_eq!(root.expected_terminal_kind, TERMINAL_CONTROL_KIND_JOIN);
        assert_eq!(root.expected_terminal_parameter, 0);
        assert_eq!(root.expected_control_id, join_controls[0].control_id());

        let error = root.replay().err().unwrap();
        assert!(matches!(
            error.downcast_ref::<B4StarkError>(),
            Some(B4StarkError::OuterPo2Mismatch {
                actual: 0,
                expected: 18
            })
        ));
    }

    #[cfg(feature = "materializer-replay")]
    #[test]
    fn fixed_case8_builder_synthesizes_the_exact_seven_context_root() {
        let top_level = synthetic_global_reference_statement_top_level();
        let resolver = B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();

        let root = B4OwnedCase8TerminalJoinRootV1::from_resolver(&resolver).unwrap();
        let contexts = root.contexts();

        assert_eq!(contexts.len(), 7);
        assert_eq!(contexts[0], root.verifier_input);
        assert_eq!(contexts[1], root.profile_manifest);
        assert_eq!(contexts[2], root.profile_algorithm);
        assert_eq!(contexts[3], root.profile_constants);
        assert_eq!(contexts[4], root.guest_elf);
        assert_eq!(contexts[5], root.statement);
        assert_eq!(contexts[6], root.raw_seal);
        assert_eq!(root.raw_seal.len(), PROOF_BYTES);
        assert!(root.raw_seal.iter().all(|byte| *byte == 8));

        let descriptor = validate_canonical_json_source(&root.verifier_input).unwrap();
        assert_eq!(descriptor["format"], "Eip0045B4PositiveVerifierInputV1");
        assert_eq!(descriptor["formatVersion"], 1);
        for (field, path, bytes) in [
            (
                "profileManifest",
                "profile-manifest.bin",
                root.profile_manifest.as_slice(),
            ),
            (
                "profileAlgorithm",
                "profile-algorithm.txt",
                root.profile_algorithm.as_slice(),
            ),
            (
                "profileConstants",
                "profile-constants.bin",
                root.profile_constants.as_slice(),
            ),
            ("guestElf", "guest.elf", root.guest_elf.as_slice()),
            ("statement", "statement.bin", root.statement.as_slice()),
            ("rawSeal", "raw-seal.bin", root.raw_seal.as_slice()),
        ] {
            assert_eq!(descriptor[field]["path"], path);
            assert_eq!(descriptor[field]["byteLength"], bytes.len());
            assert_eq!(
                descriptor[field]["sha256"],
                hex::encode(Sha256::digest(bytes))
            );
            assert_eq!(descriptor[field]["encoding"], "raw-bytes");
        }

        assert_eq!(root.expected_terminal_kind, TERMINAL_CONTROL_KIND_JOIN);
        assert_eq!(root.expected_terminal_parameter, 0);
        assert_eq!(
            root.expected_control_id.len(),
            MANIFEST_CONTROL_ENTRY_BYTES - 2
        );
    }

    #[cfg(feature = "materializer-replay")]
    #[test]
    fn synthetic_case8_seal_cannot_produce_verified_authority_or_a_record() {
        let top_level = synthetic_global_reference_statement_top_level();
        let resolver = B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();
        let root = B4OwnedCase8TerminalJoinRootV1::from_resolver(&resolver).unwrap();

        assert!(root.replay().is_err());
    }

    #[cfg(feature = "materializer-replay")]
    #[test]
    fn case8_control_artifact_must_bind_the_single_manifest_join_row() {
        let top_level = synthetic_case8_control_drift_top_level();
        let resolver = B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();

        let error = B4OwnedCase8TerminalJoinRootV1::from_resolver(&resolver)
            .err()
            .unwrap()
            .to_string();

        assert!(error.contains("sole Join/0 row"));
    }
}
