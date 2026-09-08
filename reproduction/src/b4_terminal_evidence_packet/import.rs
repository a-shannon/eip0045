// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Later-process authentication of one fixed terminal-evidence campaign.

use anyhow::{Context as _, Result, ensure};
use sha2::{Digest as _, Sha256};

use crate::{
    b4_campaign_contract::{
        B4CampaignPrecommitAuthorityV1, B4ContractArtifactEncodingV1, B4ContractArtifactIdentityV1,
        B4PositiveGenerationAuthorityV2, Eip0045B4TerminalEvidenceCampaignReceiptV1,
    },
    b4_case8_terminal_join_root::{
        B4Case8TerminalJoinPacketSourcesV1, B4OwnedCase8TerminalJoinRootV1,
        B4VerifiedCase8TerminalJoinReplayV1,
    },
    b4_positive_gate::B4PositiveGenerationAuthorityV1,
    b4_terminal::B4_TERMINAL_FIXTURE_COUNT,
    b4_terminal_source_lineage::{
        B4TerminalSourceLineageAuthorityV1, B4TerminalSourceLineageAuthorityV2,
    },
};

use super::{B4TerminalEvidenceSemanticStateV1, B4VerifiedTerminalEvidencePacketV1};

/// Pathless identity retained only inside the authenticated terminal import.
pub(crate) struct B4TerminalEvidenceImportByteIdentityV1 {
    byte_length: u64,
    sha256: String,
}

impl B4TerminalEvidenceImportByteIdentityV1 {
    fn from_bytes(source: &[u8]) -> Result<Self> {
        ensure!(
            !source.is_empty(),
            "terminal import identity cannot bind empty bytes"
        );
        Ok(Self {
            byte_length: u64::try_from(source.len())
                .context("terminal import byte length does not fit u64")?,
            sha256: hex::encode(Sha256::digest(source)),
        })
    }

    fn from_packet(packet: &B4VerifiedTerminalEvidencePacketV1) -> Result<Self> {
        let byte_length = packet.manifest_byte_length();
        ensure!(
            byte_length > 0,
            "terminal packet manifest identity cannot bind empty bytes"
        );
        Ok(Self {
            byte_length,
            sha256: hex::encode(packet.packet_id()),
        })
    }

    /// Exact pathless byte length.
    pub(crate) const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// Lowercase SHA-256 of the exact bytes.
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// Fixed, selector-free projection consumed by the fifteen terminal rows.
pub(crate) struct B4TerminalMaterializationProjectionV1<'authority> {
    terminal_fixture_catalog_jcs: &'authority [u8],
    raw_seals: [&'authority [u8]; B4_TERMINAL_FIXTURE_COUNT],
    receipt_oracles: [&'authority [u8]; B4_TERMINAL_FIXTURE_COUNT],
    profile_manifest: &'authority [u8],
    reference_statement: &'authority [u8],
    terminal_metadata_record: &'authority [u8; crate::constants::MANIFEST_CONTROL_ENTRY_BYTES],
    terminal_metadata_contexts: [&'authority [u8]; 7],
    packet_manifest_identity: &'authority B4TerminalEvidenceImportByteIdentityV1,
    campaign_receipt_identity: &'authority B4TerminalEvidenceImportByteIdentityV1,
}

impl<'authority> B4TerminalMaterializationProjectionV1<'authority> {
    /// Exact canonical terminal-fixture catalogue.
    pub(crate) const fn terminal_fixture_catalog_jcs(&self) -> &'authority [u8] {
        self.terminal_fixture_catalog_jcs
    }

    /// Exact nine fixed raw seals in compiled fixture order.
    pub(crate) const fn raw_seals(&self) -> [&'authority [u8]; B4_TERMINAL_FIXTURE_COUNT] {
        self.raw_seals
    }

    /// Exact nine fixed receipt oracles in compiled fixture order.
    pub(crate) const fn receipt_oracles(&self) -> [&'authority [u8]; B4_TERMINAL_FIXTURE_COUNT] {
        self.receipt_oracles
    }

    /// Exact authenticated initial profile manifest.
    pub(crate) const fn profile_manifest(&self) -> &'authority [u8] {
        self.profile_manifest
    }

    /// Exact common reference statement.
    pub(crate) const fn reference_statement(&self) -> &'authority [u8] {
        self.reference_statement
    }

    /// Exact Join/0 record derived by the direct case-8 replay.
    pub(crate) const fn terminal_metadata_record(
        &self,
    ) -> &'authority [u8; crate::constants::MANIFEST_CONTROL_ENTRY_BYTES] {
        self.terminal_metadata_record
    }

    /// Exact seven direct case-8 contexts in negative-input order.
    pub(crate) const fn terminal_metadata_contexts(&self) -> [&'authority [u8]; 7] {
        self.terminal_metadata_contexts
    }

    /// Exact pathless packet-manifest identity.
    pub(crate) const fn terminal_evidence_packet_manifest_identity(
        &self,
    ) -> &'authority B4TerminalEvidenceImportByteIdentityV1 {
        self.packet_manifest_identity
    }

    /// Exact pathless terminal campaign-receipt identity.
    pub(crate) const fn terminal_evidence_campaign_receipt_identity(
        &self,
    ) -> &'authority B4TerminalEvidenceImportByteIdentityV1 {
        self.campaign_receipt_identity
    }
}

/// Fixed, selector-free projection borrowed from the V2 terminal import.
///
/// The physical packet and receipt remain the same authenticated V1 wire
/// documents, but this affine projection can be minted only from the distinct
/// V2 import authority. It has no V1 conversion, serializer, clone, selector,
/// or detached constructor.
pub(crate) struct B4TerminalMaterializationProjectionV2<'authority> {
    terminal_fixture_catalog_jcs: &'authority [u8],
    raw_seals: [&'authority [u8]; B4_TERMINAL_FIXTURE_COUNT],
    receipt_oracles: [&'authority [u8]; B4_TERMINAL_FIXTURE_COUNT],
    profile_manifest: &'authority [u8],
    reference_statement: &'authority [u8],
    terminal_metadata_record: &'authority [u8; crate::constants::MANIFEST_CONTROL_ENTRY_BYTES],
    terminal_metadata_contexts: [&'authority [u8]; 7],
    packet_manifest_identity: &'authority B4TerminalEvidenceImportByteIdentityV1,
    campaign_receipt_identity: &'authority B4TerminalEvidenceImportByteIdentityV1,
}

impl<'authority> B4TerminalMaterializationProjectionV2<'authority> {
    pub(crate) const fn terminal_fixture_catalog_jcs(&self) -> &'authority [u8] {
        self.terminal_fixture_catalog_jcs
    }

    pub(crate) const fn raw_seals(&self) -> [&'authority [u8]; B4_TERMINAL_FIXTURE_COUNT] {
        self.raw_seals
    }

    pub(crate) const fn receipt_oracles(&self) -> [&'authority [u8]; B4_TERMINAL_FIXTURE_COUNT] {
        self.receipt_oracles
    }

    pub(crate) const fn profile_manifest(&self) -> &'authority [u8] {
        self.profile_manifest
    }

    pub(crate) const fn reference_statement(&self) -> &'authority [u8] {
        self.reference_statement
    }

    pub(crate) const fn terminal_metadata_record(
        &self,
    ) -> &'authority [u8; crate::constants::MANIFEST_CONTROL_ENTRY_BYTES] {
        self.terminal_metadata_record
    }

    pub(crate) const fn terminal_metadata_contexts(&self) -> [&'authority [u8]; 7] {
        self.terminal_metadata_contexts
    }

    pub(crate) const fn terminal_evidence_packet_manifest_identity(
        &self,
    ) -> &'authority B4TerminalEvidenceImportByteIdentityV1 {
        self.packet_manifest_identity
    }

    pub(crate) const fn terminal_evidence_campaign_receipt_identity(
        &self,
    ) -> &'authority B4TerminalEvidenceImportByteIdentityV1 {
        self.campaign_receipt_identity
    }
}

/// Owned test-only inputs for exercising the fixed materialization projection.
///
/// This seam cannot authenticate filesystem custody or mint production
/// authority: it is compiled only into this crate's unit-test build. Its
/// case-8 record and contexts are checked against the same initial manifest and
/// shared statement consumed by the production projection.
#[cfg(test)]
pub(crate) struct B4TerminalEvidenceImportProjectionFixtureV1 {
    pub(crate) terminal_fixture_catalog_jcs: Vec<u8>,
    pub(crate) raw_seals: [Vec<u8>; B4_TERMINAL_FIXTURE_COUNT],
    pub(crate) receipt_oracles: [Vec<u8>; B4_TERMINAL_FIXTURE_COUNT],
    pub(crate) profile_manifest: Vec<u8>,
    pub(crate) reference_statement: Vec<u8>,
    pub(crate) terminal_metadata_record: [u8; crate::constants::MANIFEST_CONTROL_ENTRY_BYTES],
    pub(crate) terminal_metadata_contexts: [Vec<u8>; 7],
    pub(crate) terminal_evidence_packet_manifest: Vec<u8>,
    pub(crate) terminal_evidence_campaign_receipt: Vec<u8>,
}

#[allow(
    clippy::large_enum_variant,
    reason = "keeping the authenticated packet, lineage, and replay inline makes the opaque authority's ownership boundary explicit"
)]
enum B4TerminalEvidenceImportBackingV1 {
    Authenticated {
        #[cfg(target_os = "linux")]
        current_executable: crate::b4_executor_custody::B4CurrentExecutableObservationV1,
        campaign_precommit_identity: B4ContractArtifactIdentityV1,
        packet: B4VerifiedTerminalEvidencePacketV1,
        campaign_receipt_jcs: Vec<u8>,
        lineage: B4TerminalSourceLineageAuthorityV1,
        case8_replay: B4VerifiedCase8TerminalJoinReplayV1,
    },
    #[cfg(test)]
    ProjectionFixture {
        campaign_precommit_jcs: Vec<u8>,
        positive_input_set: B4ContractArtifactIdentityV1,
        positive_generation_set: B4ContractArtifactIdentityV1,
        terminal_fixture_catalog_jcs: Vec<u8>,
        raw_seals: [Vec<u8>; B4_TERMINAL_FIXTURE_COUNT],
        receipt_oracles: [Vec<u8>; B4_TERMINAL_FIXTURE_COUNT],
        profile_manifest: Vec<u8>,
        reference_statement: Vec<u8>,
        terminal_metadata_record: [u8; crate::constants::MANIFEST_CONTROL_ENTRY_BYTES],
        terminal_metadata_contexts: [Vec<u8>; 7],
    },
}

/// Opaque fresh-process authority for one exact terminal-evidence campaign.
///
/// The authority has no field constructor, parser, deserializer, clone, debug
/// projection, or caller-selected payload accessor.
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4TerminalEvidenceImportAuthorityV1;
///
/// let _ = B4TerminalEvidenceImportAuthorityV1 {};
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4TerminalEvidenceImportAuthorityV1;
///
/// fn require_clone<T: Clone>() {}
/// require_clone::<B4TerminalEvidenceImportAuthorityV1>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4TerminalEvidenceImportAuthorityV1;
///
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<B4TerminalEvidenceImportAuthorityV1>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4TerminalEvidenceImportAuthorityV1;
///
/// fn select(authority: &B4TerminalEvidenceImportAuthorityV1) {
///     let _ = authority.fixture(0);
/// }
/// ```
pub struct B4TerminalEvidenceImportAuthorityV1 {
    backing: B4TerminalEvidenceImportBackingV1,
    packet_manifest_identity: B4TerminalEvidenceImportByteIdentityV1,
    campaign_receipt_identity: B4TerminalEvidenceImportByteIdentityV1,
}

/// Opaque terminal-evidence import authority bound to the V2 positive branch.
///
/// The physical packet and campaign receipt keep their existing V1 wire
/// formats. Only the positive-generation and terminal-lineage authorities are
/// V2, and the resulting affine type cannot enter a V1 consumer.
/// This import remains pre-acceptance and grants no positive-gate, campaign,
/// live-session, or H0 authority.
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4TerminalEvidenceImportAuthorityV2;
/// fn require_clone<T: Clone>() {}
/// require_clone::<B4TerminalEvidenceImportAuthorityV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4TerminalEvidenceImportAuthorityV2;
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<B4TerminalEvidenceImportAuthorityV2>();
/// ```
pub struct B4TerminalEvidenceImportAuthorityV2 {
    #[cfg(target_os = "linux")]
    current_executable: crate::b4_executor_custody::B4CurrentExecutableObservationV1,
    campaign_precommit_identity: B4ContractArtifactIdentityV1,
    packet: B4VerifiedTerminalEvidencePacketV1,
    campaign_receipt_jcs: Vec<u8>,
    lineage: B4TerminalSourceLineageAuthorityV2,
    case8_replay: B4VerifiedCase8TerminalJoinReplayV1,
    packet_manifest_identity: B4TerminalEvidenceImportByteIdentityV1,
    campaign_receipt_identity: B4TerminalEvidenceImportByteIdentityV1,
}

impl B4TerminalEvidenceImportAuthorityV2 {
    pub(crate) fn verify_authority_bindings(
        &self,
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV2,
    ) -> Result<()> {
        #[cfg(target_os = "linux")]
        self.current_executable
            .require_artifact_identity(&campaign.precommit().campaign_executor.artifact)
            .context("V2 terminal import running-executor binding changed")?;
        self.lineage
            .verify_authority_bindings(campaign, positive)
            .context("V2 terminal import complete source lineage changed")?;
        verify_import_relationship_v2(
            &self.campaign_precommit_identity,
            campaign,
            positive,
            &self.lineage,
            &self.packet,
            &self.campaign_receipt_jcs,
        )
    }

    /// Borrow the one fixed V2 terminal materialization projection.
    pub(crate) fn terminal_materialization_projection_v2(
        &self,
    ) -> B4TerminalMaterializationProjectionV2<'_> {
        let semantic = &self.packet.semantic;
        B4TerminalMaterializationProjectionV2 {
            terminal_fixture_catalog_jcs: semantic.catalogue.as_slice(),
            raw_seals: std::array::from_fn(|index| semantic.fixtures[index].raw_seal.as_slice()),
            receipt_oracles: std::array::from_fn(|index| {
                semantic.fixtures[index].receipt_oracle.as_slice()
            }),
            profile_manifest: semantic.profile.manifest.as_slice(),
            reference_statement: semantic.sources.statement.as_slice(),
            terminal_metadata_record: self.case8_replay.terminal_metadata_record(),
            terminal_metadata_contexts: self.case8_replay.contexts(),
            packet_manifest_identity: &self.packet_manifest_identity,
            campaign_receipt_identity: &self.campaign_receipt_identity,
        }
    }
}

impl B4TerminalEvidenceImportAuthorityV1 {
    /// Recheck the retained executable and complete prior-authority bindings.
    pub(crate) fn verify_authority_bindings(
        &self,
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV1,
    ) -> Result<()> {
        match &self.backing {
            B4TerminalEvidenceImportBackingV1::Authenticated {
                #[cfg(target_os = "linux")]
                current_executable,
                campaign_precommit_identity,
                packet,
                campaign_receipt_jcs,
                lineage,
                case8_replay: _,
            } => {
                #[cfg(target_os = "linux")]
                current_executable
                    .require_artifact_identity(&campaign.precommit().campaign_executor.artifact)
                    .context("terminal import running-executor binding changed")?;
                lineage
                    .verify_authority_bindings(campaign, positive)
                    .context("terminal import complete source lineage changed")?;
                verify_import_relationship(
                    campaign_precommit_identity,
                    campaign,
                    positive,
                    lineage,
                    packet,
                    campaign_receipt_jcs,
                )
            }
            #[cfg(test)]
            B4TerminalEvidenceImportBackingV1::ProjectionFixture {
                campaign_precommit_jcs,
                positive_input_set,
                positive_generation_set,
                ..
            } => {
                ensure!(
                    campaign.to_canonical_precommit_jcs()? == *campaign_precommit_jcs,
                    "test terminal import differs from campaign authority"
                );
                ensure!(
                    positive.input_set() == positive_input_set
                        && positive.generation_set() == positive_generation_set,
                    "test terminal import differs from positive authority"
                );
                Ok(())
            }
        }
    }

    /// Borrow the one fixed terminal materialization projection.
    pub(crate) fn terminal_materialization_projection(
        &self,
    ) -> B4TerminalMaterializationProjectionV1<'_> {
        let (
            terminal_fixture_catalog_jcs,
            raw_seals,
            receipt_oracles,
            profile_manifest,
            reference_statement,
            terminal_metadata_record,
            terminal_metadata_contexts,
        ) = match &self.backing {
            B4TerminalEvidenceImportBackingV1::Authenticated {
                packet,
                case8_replay,
                ..
            } => {
                let semantic = &packet.semantic;
                (
                    semantic.catalogue.as_slice(),
                    std::array::from_fn(|index| semantic.fixtures[index].raw_seal.as_slice()),
                    std::array::from_fn(|index| semantic.fixtures[index].receipt_oracle.as_slice()),
                    semantic.profile.manifest.as_slice(),
                    semantic.sources.statement.as_slice(),
                    case8_replay.terminal_metadata_record(),
                    case8_replay.contexts(),
                )
            }
            #[cfg(test)]
            B4TerminalEvidenceImportBackingV1::ProjectionFixture {
                terminal_fixture_catalog_jcs,
                raw_seals,
                receipt_oracles,
                profile_manifest,
                reference_statement,
                terminal_metadata_record,
                terminal_metadata_contexts,
                ..
            } => (
                terminal_fixture_catalog_jcs.as_slice(),
                std::array::from_fn(|index| raw_seals[index].as_slice()),
                std::array::from_fn(|index| receipt_oracles[index].as_slice()),
                profile_manifest.as_slice(),
                reference_statement.as_slice(),
                terminal_metadata_record,
                std::array::from_fn(|index| terminal_metadata_contexts[index].as_slice()),
            ),
        };
        B4TerminalMaterializationProjectionV1 {
            terminal_fixture_catalog_jcs,
            raw_seals,
            receipt_oracles,
            profile_manifest,
            reference_statement,
            terminal_metadata_record,
            terminal_metadata_contexts,
            packet_manifest_identity: &self.packet_manifest_identity,
            campaign_receipt_identity: &self.campaign_receipt_identity,
        }
    }

    /// Build the fixed projection for crate-internal producer unit tests.
    ///
    /// This deliberately omits physical import and executable custody. It is
    /// unavailable to normal and downstream builds, accepts no row selector,
    /// and preserves campaign/positive rebinding plus the exact manifest-owned
    /// Join/0 projection consumed by rows `110..=112`.
    #[cfg(test)]
    pub(crate) fn from_materialization_projection_fixture_for_tests(
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV1,
        fixture: B4TerminalEvidenceImportProjectionFixtureV1,
    ) -> Result<Self> {
        ensure!(
            !fixture.terminal_fixture_catalog_jcs.is_empty()
                && fixture.raw_seals.iter().all(|source| !source.is_empty())
                && fixture
                    .receipt_oracles
                    .iter()
                    .all(|source| !source.is_empty())
                && !fixture.profile_manifest.is_empty()
                && !fixture.reference_statement.is_empty()
                && fixture
                    .terminal_metadata_contexts
                    .iter()
                    .all(|source| !source.is_empty()),
            "test terminal-import projection contains an empty semantic source"
        );
        let manifest =
            crate::profile_manifest::StarkProfileManifestV1::decode(&fixture.profile_manifest)
                .context("test terminal-import projection manifest does not decode")?;
        ensure!(
            manifest.encode()?.as_slice() == fixture.profile_manifest,
            "test terminal-import projection manifest does not re-encode byte-exactly"
        );
        manifest
            .validate_initial_profile_target()
            .context("test terminal-import projection manifest is not the initial target")?;
        ensure!(
            fixture.terminal_metadata_contexts[1] == fixture.profile_manifest
                && fixture.terminal_metadata_contexts[5] == fixture.reference_statement,
            "test terminal-import projection separates shared case-8 packet sources"
        );
        let verifier_input = crate::b4_validator::synthesize_positive_verifier_input_v1(
            &fixture.terminal_metadata_contexts[1],
            &fixture.terminal_metadata_contexts[2],
            &fixture.terminal_metadata_contexts[3],
            &fixture.terminal_metadata_contexts[4],
            &fixture.terminal_metadata_contexts[5],
            &fixture.terminal_metadata_contexts[6],
        )
        .context("cannot synthesize test terminal-import case-8 verifier input")?;
        ensure!(
            fixture.terminal_metadata_contexts[0] == verifier_input,
            "test terminal-import projection case-8 verifier input is not exact"
        );
        let join_controls = manifest
            .terminal_controls()
            .iter()
            .filter(|control| {
                control.control_kind() == crate::constants::TERMINAL_CONTROL_KIND_JOIN
                    && control.parameter() == 0
            })
            .collect::<Vec<_>>();
        ensure!(
            join_controls.len() == 1
                && fixture.terminal_metadata_record[0]
                    == crate::constants::TERMINAL_CONTROL_KIND_JOIN
                && fixture.terminal_metadata_record[1] == 0
                && fixture.terminal_metadata_record[2..] == join_controls[0].control_id(),
            "test terminal-import projection lacks the exact manifest-owned Join/0 record"
        );
        let packet_manifest_identity = B4TerminalEvidenceImportByteIdentityV1::from_bytes(
            &fixture.terminal_evidence_packet_manifest,
        )?;
        let campaign_receipt_identity = B4TerminalEvidenceImportByteIdentityV1::from_bytes(
            &fixture.terminal_evidence_campaign_receipt,
        )?;
        let campaign_precommit_jcs = campaign.to_canonical_precommit_jcs()?;
        Ok(Self {
            backing: B4TerminalEvidenceImportBackingV1::ProjectionFixture {
                campaign_precommit_jcs,
                positive_input_set: positive.input_set().clone(),
                positive_generation_set: positive.generation_set().clone(),
                terminal_fixture_catalog_jcs: fixture.terminal_fixture_catalog_jcs,
                raw_seals: fixture.raw_seals,
                receipt_oracles: fixture.receipt_oracles,
                profile_manifest: fixture.profile_manifest,
                reference_statement: fixture.reference_statement,
                terminal_metadata_record: fixture.terminal_metadata_record,
                terminal_metadata_contexts: fixture.terminal_metadata_contexts,
            },
            packet_manifest_identity,
            campaign_receipt_identity,
        })
    }
}

fn reconstruct_case8_replay(
    semantic: &B4TerminalEvidenceSemanticStateV1,
) -> Result<B4VerifiedCase8TerminalJoinReplayV1> {
    B4OwnedCase8TerminalJoinRootV1::from_packet_sources(B4Case8TerminalJoinPacketSourcesV1 {
        profile_manifest: &semantic.profile.manifest,
        profile_algorithm: &semantic.profile.algorithm,
        profile_constants: &semantic.profile.constants,
        guest_elf: &semantic.sources.guest_elf,
        statement: &semantic.sources.statement,
        raw_seal: &semantic.case8_direct.raw_seal,
    })?
    .replay()
    .context("terminal import cannot reconstruct the direct case-8 replay")
}

fn terminal_producer_sources_are_byte_exact(
    packet_sources: [&[u8]; 5],
    lineage_sources: [&[u8]; 5],
) -> bool {
    packet_sources
        .iter()
        .zip(lineage_sources)
        .all(|(packet, lineage)| *packet == lineage)
}

fn verify_campaign_receipt_relationship(
    campaign_precommit_identity: &B4ContractArtifactIdentityV1,
    campaign: &B4CampaignPrecommitAuthorityV1,
    positive: &B4PositiveGenerationAuthorityV1,
    packet_manifest_byte_length: u64,
    packet_id: [u8; 32],
    receipt: &Eip0045B4TerminalEvidenceCampaignReceiptV1,
) -> Result<()> {
    ensure!(
        receipt.campaign_precommit() == campaign_precommit_identity,
        "terminal campaign receipt binds a different campaign precommit"
    );
    ensure!(
        receipt.positive_input_set() == positive.input_set(),
        "terminal campaign receipt binds a different positive input set"
    );
    ensure!(
        receipt.positive_generation_set() == positive.generation_set(),
        "terminal campaign receipt binds a different positive generation set"
    );
    ensure!(
        receipt.executor_artifact() == &campaign.precommit().campaign_executor.artifact,
        "terminal campaign receipt binds a different executor artifact"
    );
    ensure!(
        receipt.executor_build_descriptor()
            == &campaign.precommit().campaign_executor.build_descriptor,
        "terminal campaign receipt binds a different executor build descriptor"
    );
    ensure!(
        receipt.executor_contract() == &campaign.precommit().executor_contract,
        "terminal campaign receipt binds a different executor contract"
    );
    ensure!(
        receipt.terminal_packet_manifest_byte_length() == packet_manifest_byte_length
            && receipt.terminal_packet_id() == hex::encode(packet_id),
        "terminal campaign receipt binds a different terminal packet"
    );
    Ok(())
}

fn verify_campaign_receipt_relationship_v2(
    campaign_precommit_identity: &B4ContractArtifactIdentityV1,
    campaign: &B4CampaignPrecommitAuthorityV1,
    positive: &B4PositiveGenerationAuthorityV2,
    packet_manifest_byte_length: u64,
    packet_id: [u8; 32],
    receipt: &Eip0045B4TerminalEvidenceCampaignReceiptV1,
) -> Result<()> {
    ensure!(
        receipt.campaign_precommit() == campaign_precommit_identity,
        "V2 terminal campaign receipt binds a different campaign precommit"
    );
    ensure!(
        receipt.positive_input_set() == positive.input_set(),
        "V2 terminal campaign receipt binds a different positive input set"
    );
    ensure!(
        receipt.positive_generation_set() == positive.generation_set(),
        "V2 terminal campaign receipt binds a different positive generation set"
    );
    ensure!(
        receipt.executor_artifact() == &campaign.precommit().campaign_executor.artifact,
        "V2 terminal campaign receipt binds a different executor artifact"
    );
    ensure!(
        receipt.executor_build_descriptor()
            == &campaign.precommit().campaign_executor.build_descriptor,
        "V2 terminal campaign receipt binds a different executor build descriptor"
    );
    ensure!(
        receipt.executor_contract() == &campaign.precommit().executor_contract,
        "V2 terminal campaign receipt binds a different executor contract"
    );
    ensure!(
        receipt.terminal_packet_manifest_byte_length() == packet_manifest_byte_length
            && receipt.terminal_packet_id() == hex::encode(packet_id),
        "V2 terminal campaign receipt binds a different terminal packet"
    );
    Ok(())
}

fn verify_campaign_precommit_identity(
    campaign_precommit_identity: &B4ContractArtifactIdentityV1,
    campaign: &B4CampaignPrecommitAuthorityV1,
) -> Result<()> {
    let canonical_precommit = campaign
        .to_canonical_precommit_jcs()
        .context("cannot reserialize terminal import campaign precommit")?;
    let expected_precommit_identity = B4ContractArtifactIdentityV1::from_bytes(
        campaign_precommit_identity.path.clone(),
        B4ContractArtifactEncodingV1::Rfc8785Jcs,
        &canonical_precommit,
    )
    .context("cannot derive terminal import campaign-precommit identity")?;
    ensure!(
        campaign_precommit_identity == &expected_precommit_identity,
        "terminal import campaign-precommit identity differs from its authority"
    );
    Ok(())
}

fn verify_import_relationship(
    campaign_precommit_identity: &B4ContractArtifactIdentityV1,
    campaign: &B4CampaignPrecommitAuthorityV1,
    positive: &B4PositiveGenerationAuthorityV1,
    lineage: &B4TerminalSourceLineageAuthorityV1,
    packet: &B4VerifiedTerminalEvidencePacketV1,
    campaign_receipt_jcs: &[u8],
) -> Result<()> {
    verify_campaign_precommit_identity(campaign_precommit_identity, campaign)?;

    lineage
        .verify_authority_bindings(campaign, positive)
        .context("terminal import source lineage differs from campaign/positive authority")?;
    let packet_sources = packet.source_replay_view();
    let lineage_sources = lineage.producer_source();
    ensure!(
        terminal_producer_sources_are_byte_exact(
            [
                packet_sources.guest_elf(),
                packet_sources.statement(),
                packet_sources.case0_lift15_receipt_oracle(),
                packet_sources.case8_terminal_join_recursive_oracle(),
                packet_sources.case9_terminal_resolve_recursive_oracle(),
            ],
            [
                lineage_sources.guest_elf(),
                lineage_sources.statement(),
                lineage_sources.case0_lift15_receipt_oracle(),
                lineage_sources.case8_terminal_join_recursive_oracle(),
                lineage_sources.case9_terminal_resolve_recursive_oracle(),
            ],
        ),
        "terminal packet producer sources differ from complete reconstructed lineage"
    );

    let receipt =
        Eip0045B4TerminalEvidenceCampaignReceiptV1::from_canonical_jcs(campaign_receipt_jcs)
            .context("terminal campaign receipt is not exact canonical JCS")?;
    ensure!(
        receipt.to_canonical_jcs()? == campaign_receipt_jcs,
        "terminal campaign receipt does not round-trip byte-exactly"
    );
    verify_campaign_receipt_relationship(
        campaign_precommit_identity,
        campaign,
        positive,
        packet.manifest_byte_length(),
        packet.packet_id(),
        &receipt,
    )
}

fn verify_import_relationship_v2(
    campaign_precommit_identity: &B4ContractArtifactIdentityV1,
    campaign: &B4CampaignPrecommitAuthorityV1,
    positive: &B4PositiveGenerationAuthorityV2,
    lineage: &B4TerminalSourceLineageAuthorityV2,
    packet: &B4VerifiedTerminalEvidencePacketV1,
    campaign_receipt_jcs: &[u8],
) -> Result<()> {
    verify_campaign_precommit_identity(campaign_precommit_identity, campaign)?;
    lineage
        .verify_authority_bindings(campaign, positive)
        .context("V2 terminal import source lineage differs from campaign/positive authority")?;
    let packet_sources = packet.source_replay_view();
    let lineage_sources = lineage.producer_source();
    ensure!(
        terminal_producer_sources_are_byte_exact(
            [
                packet_sources.guest_elf(),
                packet_sources.statement(),
                packet_sources.case0_lift15_receipt_oracle(),
                packet_sources.case8_terminal_join_recursive_oracle(),
                packet_sources.case9_terminal_resolve_recursive_oracle(),
            ],
            [
                lineage_sources.guest_elf(),
                lineage_sources.statement(),
                lineage_sources.case0_lift15_receipt_oracle(),
                lineage_sources.case8_terminal_join_recursive_oracle(),
                lineage_sources.case9_terminal_resolve_recursive_oracle(),
            ],
        ),
        "terminal packet producer sources differ from complete V2 reconstructed lineage"
    );

    let receipt =
        Eip0045B4TerminalEvidenceCampaignReceiptV1::from_canonical_jcs(campaign_receipt_jcs)
            .context("V2 terminal campaign receipt is not exact canonical JCS")?;
    ensure!(
        receipt.to_canonical_jcs()? == campaign_receipt_jcs,
        "V2 terminal campaign receipt does not round-trip byte-exactly"
    );
    verify_campaign_receipt_relationship_v2(
        campaign_precommit_identity,
        campaign,
        positive,
        packet.manifest_byte_length(),
        packet.packet_id(),
        &receipt,
    )
}

fn terminal_semantic_states_are_byte_exact(
    left: &B4TerminalEvidenceSemanticStateV1,
    right: &B4TerminalEvidenceSemanticStateV1,
) -> bool {
    left.profile_id == right.profile_id
        && left.program_id == right.program_id
        && left.statement_sha256 == right.statement_sha256
        && left.profile.manifest == right.profile.manifest
        && left.profile.algorithm == right.profile.algorithm
        && left.profile.constants == right.profile.constants
        && left.sources.guest_elf == right.sources.guest_elf
        && left.sources.statement == right.sources.statement
        && left.sources.case0_lift15_receipt_oracle == right.sources.case0_lift15_receipt_oracle
        && left.sources.case8_terminal_join_recursive_oracle
            == right.sources.case8_terminal_join_recursive_oracle
        && left.sources.case9_terminal_resolve_recursive_oracle
            == right.sources.case9_terminal_resolve_recursive_oracle
        && left
            .fixtures
            .iter()
            .zip(&right.fixtures)
            .all(|(left, right)| {
                left.raw_seal == right.raw_seal && left.receipt_oracle == right.receipt_oracle
            })
        && left.catalogue == right.catalogue
        && left.case8_direct.raw_seal == right.case8_direct.raw_seal
        && left.case8_direct.receipt_oracle == right.case8_direct.receipt_oracle
}

fn terminal_packet_physical_closures_are_exact(
    first: &crate::b4_terminal_evidence_io::B4PhysicalPacketClosureIdentityV1,
    final_reopen: &crate::b4_terminal_evidence_io::B4PhysicalPacketClosureIdentityV1,
) -> bool {
    first.names_same_objects_as(final_reopen)
}

fn require_same_verified_terminal_packet(
    first: &B4VerifiedTerminalEvidencePacketV1,
    final_reopen: &B4VerifiedTerminalEvidencePacketV1,
) -> Result<()> {
    ensure!(
        terminal_packet_physical_closures_are_exact(
            first.physical_closure_identity(),
            final_reopen.physical_closure_identity(),
        ),
        "terminal packet physical closure changed between complete descriptor-rooted reopens"
    );
    ensure!(
        terminal_packet_reopens_are_byte_exact(
            first.manifest_byte_length(),
            first.packet_id(),
            &first.semantic,
            final_reopen.manifest_byte_length(),
            final_reopen.packet_id(),
            &final_reopen.semantic,
        ),
        "terminal packet changed between complete descriptor-rooted reopens"
    );
    Ok(())
}

fn terminal_packet_reopens_are_byte_exact(
    first_manifest_byte_length: u64,
    first_packet_id: [u8; 32],
    first_semantic: &B4TerminalEvidenceSemanticStateV1,
    final_manifest_byte_length: u64,
    final_packet_id: [u8; 32],
    final_semantic: &B4TerminalEvidenceSemanticStateV1,
) -> bool {
    first_manifest_byte_length == final_manifest_byte_length
        && first_packet_id == final_packet_id
        && terminal_semantic_states_are_byte_exact(first_semantic, final_semantic)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        collections::BTreeSet,
        fs::File,
        io::{Read as _, Seek as _, SeekFrom},
        os::fd::{AsFd as _, BorrowedFd},
        path::Path,
    };

    use anyhow::{Context as _, Result, ensure};
    use sha2::{Digest as _, Sha256};

    use crate::{
        b4_campaign_contract::{
            B4CampaignPrecommitAuthorityV1, B4ContractArtifactIdentityV1,
            B4PositiveGenerationAuthorityV2, MAX_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES,
        },
        b4_executor_custody::B4CurrentExecutableObservationV1,
        b4_positive_gate::B4PositiveGenerationAuthorityV1,
        b4_terminal_source_lineage::{
            B4TerminalSourceLineageAuthorityV1, B4TerminalSourceLineageAuthorityV2,
        },
    };

    use super::{
        B4TerminalEvidenceImportAuthorityV1, B4TerminalEvidenceImportAuthorityV2,
        B4TerminalEvidenceImportBackingV1, B4TerminalEvidenceImportByteIdentityV1,
        reconstruct_case8_replay, verify_import_relationship, verify_import_relationship_v2,
    };

    const TERMINAL_PACKET_DIRECTORY: &str = "terminal-evidence-packet";
    const TERMINAL_CAMPAIGN_RECEIPT_FILE: &str = "terminal-evidence-campaign-receipt.json";
    const MAX_TERMINAL_CAMPAIGN_ROOT_ENTRIES: usize = 4;
    const PERMISSION_AND_SPECIAL_BITS: u32 = 0o7777;
    const PRIVATE_DIRECTORY_MODE: rustix::fs::Mode = rustix::fs::Mode::RWXU;
    const PRIVATE_FILE_MODE: rustix::fs::Mode =
        rustix::fs::Mode::RUSR.union(rustix::fs::Mode::WUSR);
    const DIRECTORY_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY
        .union(rustix::fs::OFlags::DIRECTORY)
        .union(rustix::fs::OFlags::NOFOLLOW)
        .union(rustix::fs::OFlags::CLOEXEC);
    const FILE_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY
        .union(rustix::fs::OFlags::NOFOLLOW)
        .union(rustix::fs::OFlags::NONBLOCK)
        .union(rustix::fs::OFlags::CLOEXEC);
    const RESOLVE_FLAGS: rustix::fs::ResolveFlags = rustix::fs::ResolveFlags::BENEATH
        .union(rustix::fs::ResolveFlags::NO_SYMLINKS)
        .union(rustix::fs::ResolveFlags::NO_MAGICLINKS)
        .union(rustix::fs::ResolveFlags::NO_XDEV);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct LinuxIdentity {
        device: u64,
        inode: u64,
        mount_id: u64,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct LinuxDirectoryState {
        identity: LinuxIdentity,
        hard_link_count: u64,
        mode: u32,
        owner: u64,
        group: u64,
        modified_seconds: i64,
        modified_nanoseconds: u64,
        changed_seconds: i64,
        changed_nanoseconds: u64,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct LinuxFileState {
        identity: LinuxIdentity,
        byte_length: u64,
        hard_link_count: u64,
        mode: u32,
        owner: u64,
        group: u64,
        modified_seconds: i64,
        modified_nanoseconds: u64,
        changed_seconds: i64,
        changed_nanoseconds: u64,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct StableFileSnapshot {
        state: LinuxFileState,
        sha256: [u8; 32],
    }

    fn checked_u64<T>(value: T, error: &'static str) -> Result<u64>
    where
        u64: TryFrom<T>,
    {
        u64::try_from(value).map_err(|_| anyhow::Error::msg(error))
    }

    fn descriptor_mount_id(descriptor: BorrowedFd<'_>) -> Result<u64> {
        let statx = rustix::fs::statx(
            descriptor,
            "",
            rustix::fs::AtFlags::EMPTY_PATH,
            rustix::fs::StatxFlags::BASIC_STATS | rustix::fs::StatxFlags::MNT_ID,
        )
        .context("cannot obtain terminal-import mount identity")?;
        ensure!(
            rustix::fs::StatxFlags::from_bits_retain(statx.stx_mask)
                .contains(rustix::fs::StatxFlags::MNT_ID),
            "Linux statx did not return terminal-import mount identity"
        );
        Ok(statx.stx_mnt_id)
    }

    fn directory_state(
        descriptor: impl std::os::fd::AsFd,
        label: &str,
    ) -> Result<LinuxDirectoryState> {
        let descriptor = descriptor.as_fd();
        let stat = rustix::fs::fstat(descriptor)
            .with_context(|| format!("cannot inspect retained {label}"))?;
        ensure!(
            rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir(),
            "{label} is not an ordinary directory"
        );
        Ok(LinuxDirectoryState {
            identity: LinuxIdentity {
                device: checked_u64(stat.st_dev, "directory device does not fit u64")?,
                inode: checked_u64(stat.st_ino, "directory inode does not fit u64")?,
                mount_id: descriptor_mount_id(descriptor)?,
            },
            hard_link_count: checked_u64(
                stat.st_nlink,
                "directory hard-link count does not fit u64",
            )?,
            mode: stat.st_mode,
            owner: checked_u64(stat.st_uid, "directory owner does not fit u64")?,
            group: checked_u64(stat.st_gid, "directory group does not fit u64")?,
            modified_seconds: stat.st_mtime,
            modified_nanoseconds: stat.st_mtime_nsec,
            changed_seconds: stat.st_ctime,
            changed_nanoseconds: stat.st_ctime_nsec,
        })
    }

    fn file_state(descriptor: impl std::os::fd::AsFd, label: &str) -> Result<LinuxFileState> {
        let descriptor = descriptor.as_fd();
        let stat = rustix::fs::fstat(descriptor)
            .with_context(|| format!("cannot inspect retained {label}"))?;
        ensure!(
            rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file(),
            "{label} is not an ordinary regular file"
        );
        let hard_link_count = checked_u64(stat.st_nlink, "file hard-link count does not fit u64")?;
        ensure!(
            hard_link_count == 1,
            "{label} must have exactly one hard link"
        );
        Ok(LinuxFileState {
            identity: LinuxIdentity {
                device: checked_u64(stat.st_dev, "file device does not fit u64")?,
                inode: checked_u64(stat.st_ino, "file inode does not fit u64")?,
                mount_id: descriptor_mount_id(descriptor)?,
            },
            byte_length: checked_u64(stat.st_size, "file byte length does not fit u64")?,
            hard_link_count,
            mode: stat.st_mode,
            owner: checked_u64(stat.st_uid, "file owner does not fit u64")?,
            group: checked_u64(stat.st_gid, "file group does not fit u64")?,
            modified_seconds: stat.st_mtime,
            modified_nanoseconds: stat.st_mtime_nsec,
            changed_seconds: stat.st_ctime,
            changed_nanoseconds: stat.st_ctime_nsec,
        })
    }

    fn enumerate_root(root: BorrowedFd<'_>) -> Result<BTreeSet<String>> {
        let mut directory = rustix::fs::Dir::read_from(root)
            .context("cannot enumerate retained terminal campaign root")?;
        let mut entries = BTreeSet::new();
        for entry in &mut directory {
            let entry = entry.context("cannot read retained terminal campaign entry")?;
            let name = entry
                .file_name()
                .to_str()
                .context("terminal campaign root contains a non-UTF-8 entry")?;
            if matches!(name, "." | "..") {
                continue;
            }
            ensure!(
                entries.len() < MAX_TERMINAL_CAMPAIGN_ROOT_ENTRIES,
                "terminal campaign root exceeds its compiled inventory bound"
            );
            ensure!(
                entries.insert(name.to_owned()),
                "terminal campaign root contains a duplicate entry"
            );
        }
        Ok(entries)
    }

    fn require_exact_root_inventory(root: BorrowedFd<'_>) -> Result<()> {
        ensure!(
            enumerate_root(root)?
                == BTreeSet::from([
                    TERMINAL_PACKET_DIRECTORY.to_owned(),
                    TERMINAL_CAMPAIGN_RECEIPT_FILE.to_owned(),
                ]),
            "terminal campaign root inventory differs from packet plus receipt"
        );
        Ok(())
    }

    fn read_receipt(file: &mut File) -> Result<(StableFileSnapshot, Vec<u8>)> {
        file.seek(SeekFrom::Start(0))
            .context("cannot seek terminal campaign receipt")?;
        let before = file_state(&*file, "terminal campaign receipt")?;
        let maximum = u64::try_from(MAX_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES)?;
        ensure!(
            (1..=maximum).contains(&before.byte_length),
            "terminal campaign receipt byte length is outside its bound"
        );
        let capacity = usize::try_from(before.byte_length)
            .context("terminal campaign receipt length does not fit memory")?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .context("cannot reserve terminal campaign receipt bytes")?;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let count = file
                .read(&mut buffer)
                .context("cannot read terminal campaign receipt")?;
            if count == 0 {
                break;
            }
            let next_length = bytes
                .len()
                .checked_add(count)
                .context("terminal campaign receipt length overflowed")?;
            ensure!(
                next_length <= MAX_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES,
                "terminal campaign receipt exceeds its bound while reading"
            );
            bytes.extend_from_slice(&buffer[..count]);
            hasher.update(&buffer[..count]);
        }
        let after = file_state(&*file, "terminal campaign receipt")?;
        ensure!(
            before == after && u64::try_from(bytes.len())? == before.byte_length,
            "terminal campaign receipt changed while being read"
        );
        Ok((
            StableFileSnapshot {
                state: after,
                sha256: hasher.finalize().into(),
            },
            bytes,
        ))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the descriptor-rooted authentication sequence stays linear so its exact check order remains auditable"
    )]
    pub(super) fn authenticate(
        terminal_campaign_root: BorrowedFd<'_>,
        configured_executor_artifact: &Path,
        campaign_precommit_identity: &B4ContractArtifactIdentityV1,
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV1,
        lineage: B4TerminalSourceLineageAuthorityV1,
    ) -> Result<B4TerminalEvidenceImportAuthorityV1> {
        let current_executable =
            B4CurrentExecutableObservationV1::capture(configured_executor_artifact)?;
        current_executable
            .require_artifact_identity(&campaign.precommit().campaign_executor.artifact)
            .context("terminal import running-executor binding failed")?;
        let initial_root = directory_state(terminal_campaign_root, "terminal campaign root")?;
        ensure!(
            initial_root.mode & PERMISSION_AND_SPECIAL_BITS == PRIVATE_DIRECTORY_MODE.bits()
                && initial_root.hard_link_count == 3,
            "terminal campaign root lacks its exact private one-subdirectory policy"
        );
        require_exact_root_inventory(terminal_campaign_root)?;

        let packet_descriptor = rustix::fs::openat2(
            terminal_campaign_root,
            TERMINAL_PACKET_DIRECTORY,
            DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
            RESOLVE_FLAGS,
        )
        .context("cannot open fixed terminal packet directory")?;
        let initial_packet = directory_state(&packet_descriptor, "terminal packet directory")?;
        ensure!(
            initial_packet.mode & PERMISSION_AND_SPECIAL_BITS == PRIVATE_DIRECTORY_MODE.bits()
                && initial_packet.identity.mount_id == initial_root.identity.mount_id
                && initial_packet.owner == initial_root.owner
                && initial_packet.group == initial_root.group,
            "terminal packet directory differs from retained campaign-root policy"
        );

        let receipt_descriptor = rustix::fs::openat2(
            terminal_campaign_root,
            TERMINAL_CAMPAIGN_RECEIPT_FILE,
            FILE_FLAGS,
            rustix::fs::Mode::empty(),
            RESOLVE_FLAGS,
        )
        .context("cannot open fixed terminal campaign receipt")?;
        let mut receipt_file = File::from(receipt_descriptor);
        let (initial_receipt, receipt_jcs) = read_receipt(&mut receipt_file)?;
        ensure!(
            initial_receipt.state.mode & PERMISSION_AND_SPECIAL_BITS == PRIVATE_FILE_MODE.bits()
                && initial_receipt.state.identity.mount_id == initial_root.identity.mount_id
                && initial_receipt.state.owner == initial_root.owner
                && initial_receipt.state.group == initial_root.group,
            "terminal campaign receipt differs from retained campaign-root policy"
        );

        let packet =
            crate::b4_terminal_evidence_packet::reopen_b4_terminal_evidence_packet_from_directory_descriptor(
                packet_descriptor.as_fd(),
            )
            .context("cannot semantically reopen fixed terminal packet")?;
        ensure!(
            directory_state(&packet_descriptor, "terminal packet directory")? == initial_packet,
            "terminal packet directory changed during semantic reopen"
        );
        let mut receipt_recheck = receipt_file
            .try_clone()
            .context("cannot duplicate retained terminal campaign receipt")?;
        let (final_receipt, final_receipt_jcs) = read_receipt(&mut receipt_recheck)?;
        ensure!(
            final_receipt == initial_receipt && final_receipt_jcs == receipt_jcs,
            "terminal campaign receipt changed during packet reopen"
        );
        ensure!(
            directory_state(terminal_campaign_root, "terminal campaign root")? == initial_root,
            "terminal campaign root changed during import"
        );
        require_exact_root_inventory(terminal_campaign_root)?;

        verify_import_relationship(
            campaign_precommit_identity,
            campaign,
            positive,
            &lineage,
            &packet,
            &receipt_jcs,
        )?;
        let case8_replay = reconstruct_case8_replay(&packet.semantic)?;
        let packet_manifest_identity =
            B4TerminalEvidenceImportByteIdentityV1::from_packet(&packet)?;
        let campaign_receipt_identity =
            B4TerminalEvidenceImportByteIdentityV1::from_bytes(&receipt_jcs)?;

        current_executable
            .require_artifact_identity(&campaign.precommit().campaign_executor.artifact)
            .context("terminal import running-executor binding changed before authority mint")?;
        lineage.verify_authority_bindings(campaign, positive)?;
        let final_packet =
            crate::b4_terminal_evidence_packet::reopen_b4_terminal_evidence_packet_from_directory_descriptor(
                packet_descriptor.as_fd(),
            )
            .context("cannot complete final semantic reopen of fixed terminal packet")?;
        super::require_same_verified_terminal_packet(&packet, &final_packet)?;
        ensure!(
            directory_state(&packet_descriptor, "terminal packet directory")? == initial_packet
                && directory_state(terminal_campaign_root, "terminal campaign root")?
                    == initial_root,
            "terminal campaign physical custody changed before authority mint"
        );
        require_exact_root_inventory(terminal_campaign_root)?;
        let mut last_receipt_recheck = receipt_file
            .try_clone()
            .context("cannot duplicate terminal campaign receipt for final recheck")?;
        let (last_receipt, last_receipt_jcs) = read_receipt(&mut last_receipt_recheck)?;
        ensure!(
            last_receipt == initial_receipt && last_receipt_jcs == receipt_jcs,
            "terminal campaign receipt changed before authority mint"
        );
        ensure!(
            directory_state(&packet_descriptor, "terminal packet directory")? == initial_packet
                && directory_state(terminal_campaign_root, "terminal campaign root")?
                    == initial_root,
            "terminal campaign physical custody changed after final receipt recheck"
        );
        require_exact_root_inventory(terminal_campaign_root)?;
        // The first packet owns the original directory/file handle guard. Drop
        // it only after every final physical, semantic, and receipt decision.
        drop(packet);
        let packet = final_packet;

        Ok(B4TerminalEvidenceImportAuthorityV1 {
            backing: B4TerminalEvidenceImportBackingV1::Authenticated {
                current_executable,
                campaign_precommit_identity: campaign_precommit_identity.clone(),
                packet,
                campaign_receipt_jcs: receipt_jcs,
                lineage,
                case8_replay,
            },
            packet_manifest_identity,
            campaign_receipt_identity,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the V2 authority branch repeats the descriptor-rooted sequence so no generic or dual authority can select its semantics"
    )]
    pub(super) fn authenticate_v2(
        terminal_campaign_root: BorrowedFd<'_>,
        configured_executor_artifact: &Path,
        campaign_precommit_identity: &B4ContractArtifactIdentityV1,
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV2,
        lineage: B4TerminalSourceLineageAuthorityV2,
    ) -> Result<B4TerminalEvidenceImportAuthorityV2> {
        let current_executable =
            B4CurrentExecutableObservationV1::capture(configured_executor_artifact)?;
        current_executable
            .require_artifact_identity(&campaign.precommit().campaign_executor.artifact)
            .context("V2 terminal import running-executor binding failed")?;
        let initial_root = directory_state(terminal_campaign_root, "V2 terminal campaign root")?;
        ensure!(
            initial_root.mode & PERMISSION_AND_SPECIAL_BITS == PRIVATE_DIRECTORY_MODE.bits()
                && initial_root.hard_link_count == 3,
            "V2 terminal campaign root lacks its exact private one-subdirectory policy"
        );
        require_exact_root_inventory(terminal_campaign_root)?;

        let packet_descriptor = rustix::fs::openat2(
            terminal_campaign_root,
            TERMINAL_PACKET_DIRECTORY,
            DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
            RESOLVE_FLAGS,
        )
        .context("cannot open fixed V2 terminal packet directory")?;
        let initial_packet = directory_state(&packet_descriptor, "V2 terminal packet directory")?;
        ensure!(
            initial_packet.mode & PERMISSION_AND_SPECIAL_BITS == PRIVATE_DIRECTORY_MODE.bits()
                && initial_packet.identity.mount_id == initial_root.identity.mount_id
                && initial_packet.owner == initial_root.owner
                && initial_packet.group == initial_root.group,
            "V2 terminal packet directory differs from retained campaign-root policy"
        );

        let receipt_descriptor = rustix::fs::openat2(
            terminal_campaign_root,
            TERMINAL_CAMPAIGN_RECEIPT_FILE,
            FILE_FLAGS,
            rustix::fs::Mode::empty(),
            RESOLVE_FLAGS,
        )
        .context("cannot open fixed V2 terminal campaign receipt")?;
        let mut receipt_file = File::from(receipt_descriptor);
        let (initial_receipt, receipt_jcs) = read_receipt(&mut receipt_file)?;
        ensure!(
            initial_receipt.state.mode & PERMISSION_AND_SPECIAL_BITS == PRIVATE_FILE_MODE.bits()
                && initial_receipt.state.identity.mount_id == initial_root.identity.mount_id
                && initial_receipt.state.owner == initial_root.owner
                && initial_receipt.state.group == initial_root.group,
            "V2 terminal campaign receipt differs from retained campaign-root policy"
        );

        let packet =
            crate::b4_terminal_evidence_packet::reopen_b4_terminal_evidence_packet_from_directory_descriptor(
                packet_descriptor.as_fd(),
            )
            .context("cannot semantically reopen fixed V2 terminal packet")?;
        ensure!(
            directory_state(&packet_descriptor, "V2 terminal packet directory")? == initial_packet,
            "V2 terminal packet directory changed during semantic reopen"
        );
        let mut receipt_recheck = receipt_file
            .try_clone()
            .context("cannot duplicate retained V2 terminal campaign receipt")?;
        let (final_receipt, final_receipt_jcs) = read_receipt(&mut receipt_recheck)?;
        ensure!(
            final_receipt == initial_receipt && final_receipt_jcs == receipt_jcs,
            "V2 terminal campaign receipt changed during packet reopen"
        );
        ensure!(
            directory_state(terminal_campaign_root, "V2 terminal campaign root")? == initial_root,
            "V2 terminal campaign root changed during import"
        );
        require_exact_root_inventory(terminal_campaign_root)?;

        verify_import_relationship_v2(
            campaign_precommit_identity,
            campaign,
            positive,
            &lineage,
            &packet,
            &receipt_jcs,
        )?;
        let case8_replay = reconstruct_case8_replay(&packet.semantic)?;
        let packet_manifest_identity =
            B4TerminalEvidenceImportByteIdentityV1::from_packet(&packet)?;
        let campaign_receipt_identity =
            B4TerminalEvidenceImportByteIdentityV1::from_bytes(&receipt_jcs)?;

        current_executable
            .require_artifact_identity(&campaign.precommit().campaign_executor.artifact)
            .context("V2 terminal import running-executor binding changed before authority mint")?;
        lineage.verify_authority_bindings(campaign, positive)?;
        let final_packet =
            crate::b4_terminal_evidence_packet::reopen_b4_terminal_evidence_packet_from_directory_descriptor(
                packet_descriptor.as_fd(),
            )
            .context("cannot complete final semantic reopen of fixed V2 terminal packet")?;
        super::require_same_verified_terminal_packet(&packet, &final_packet)?;
        ensure!(
            directory_state(&packet_descriptor, "V2 terminal packet directory")? == initial_packet
                && directory_state(terminal_campaign_root, "V2 terminal campaign root")?
                    == initial_root,
            "V2 terminal campaign physical custody changed before authority mint"
        );
        require_exact_root_inventory(terminal_campaign_root)?;
        let mut last_receipt_recheck = receipt_file
            .try_clone()
            .context("cannot duplicate V2 terminal campaign receipt for final recheck")?;
        let (last_receipt, last_receipt_jcs) = read_receipt(&mut last_receipt_recheck)?;
        ensure!(
            last_receipt == initial_receipt && last_receipt_jcs == receipt_jcs,
            "V2 terminal campaign receipt changed before authority mint"
        );
        ensure!(
            directory_state(&packet_descriptor, "V2 terminal packet directory")? == initial_packet
                && directory_state(terminal_campaign_root, "V2 terminal campaign root")?
                    == initial_root,
            "V2 terminal campaign physical custody changed after final receipt recheck"
        );
        require_exact_root_inventory(terminal_campaign_root)?;
        drop(packet);

        Ok(B4TerminalEvidenceImportAuthorityV2 {
            current_executable,
            campaign_precommit_identity: campaign_precommit_identity.clone(),
            packet: final_packet,
            campaign_receipt_jcs: receipt_jcs,
            lineage,
            case8_replay,
            packet_manifest_identity,
            campaign_receipt_identity,
        })
    }
}

/// Authenticate one fixed terminal-evidence campaign from retained Linux
/// directory custody.
///
/// Packet and receipt names are compiled into this implementation. The caller
/// supplies no packet path, receipt path, digest, length, expected identity, or
/// executable observation.
///
/// # Errors
///
/// Returns an error for unsupported filesystem semantics, unsafe or unstable
/// objects, inventory drift, current-executable mismatch, prior-authority
/// mismatch, packet semantic failure, receipt failure, or any cross-binding
/// difference.
#[cfg(target_os = "linux")]
pub fn authenticate_b4_terminal_evidence_import_from_directory_descriptor(
    terminal_campaign_root: std::os::fd::BorrowedFd<'_>,
    configured_executor_artifact: &std::path::Path,
    campaign_precommit_identity: &B4ContractArtifactIdentityV1,
    campaign: &B4CampaignPrecommitAuthorityV1,
    positive: &B4PositiveGenerationAuthorityV1,
    lineage: B4TerminalSourceLineageAuthorityV1,
) -> Result<B4TerminalEvidenceImportAuthorityV1> {
    linux::authenticate(
        terminal_campaign_root,
        configured_executor_artifact,
        campaign_precommit_identity,
        campaign,
        positive,
        lineage,
    )
}

/// Authenticate the existing terminal-evidence packet and receipt wire formats
/// against the explicit V2 positive-generation and source-lineage branch.
///
/// The returned authority is a distinct opaque V2 type. No V1 import authority
/// or serialized packet can be converted into it.
///
/// # Errors
///
/// Returns an error for unsupported filesystem semantics, physical custody
/// drift, executor drift, a V2 authority mismatch, packet semantic failure,
/// receipt failure, or any source-lineage substitution.
#[cfg(target_os = "linux")]
pub fn authenticate_b4_terminal_evidence_import_from_directory_descriptor_v2(
    terminal_campaign_root: std::os::fd::BorrowedFd<'_>,
    configured_executor_artifact: &std::path::Path,
    campaign_precommit_identity: &B4ContractArtifactIdentityV1,
    campaign: &B4CampaignPrecommitAuthorityV1,
    positive: &B4PositiveGenerationAuthorityV2,
    lineage: B4TerminalSourceLineageAuthorityV2,
) -> Result<B4TerminalEvidenceImportAuthorityV2> {
    linux::authenticate_v2(
        terminal_campaign_root,
        configured_executor_artifact,
        campaign_precommit_identity,
        campaign,
        positive,
        lineage,
    )
}

#[cfg(test)]
mod tests {
    use std::{any::TypeId, ffi::OsString, fs};

    use sha2::{Digest as _, Sha256};

    use crate::b4_campaign_contract::{
        B4TerminalEvidenceCampaignReceiptInputsV1,
        test_support::{
            build_terminal_lineage_constructor_test_support,
            build_terminal_lineage_constructor_test_support_v2,
        },
    };

    use super::{
        B4TerminalEvidenceImportAuthorityV1, B4TerminalEvidenceImportAuthorityV2,
        B4TerminalEvidenceImportByteIdentityV1, B4TerminalEvidenceSemanticStateV1,
        B4TerminalMaterializationProjectionV1, B4TerminalMaterializationProjectionV2,
        terminal_packet_physical_closures_are_exact, terminal_packet_reopens_are_byte_exact,
        terminal_producer_sources_are_byte_exact, verify_campaign_precommit_identity,
        verify_campaign_receipt_relationship, verify_campaign_receipt_relationship_v2,
    };

    fn synthetic_semantic(seed: u8) -> super::super::B4TerminalEvidenceSemanticStateV1 {
        super::super::B4TerminalEvidenceSemanticStateV1 {
            profile_id: [seed; 32],
            program_id: [seed.wrapping_add(1); 32],
            statement_sha256: [seed.wrapping_add(2); 32],
            profile: super::super::B4OwnedTerminalEvidenceProfilePayloadsV1 {
                manifest: vec![seed.wrapping_add(3)],
                algorithm: vec![seed.wrapping_add(4)],
                constants: vec![seed.wrapping_add(5)],
            },
            sources: super::super::B4OwnedTerminalEvidenceProducerSourcesV1 {
                guest_elf: vec![seed.wrapping_add(6)],
                statement: vec![seed.wrapping_add(7)],
                case0_lift15_receipt_oracle: vec![seed.wrapping_add(8)],
                case8_terminal_join_recursive_oracle: vec![seed.wrapping_add(9)],
                case9_terminal_resolve_recursive_oracle: vec![seed.wrapping_add(10)],
            },
            fixtures: std::array::from_fn(|index| {
                super::super::B4OwnedTerminalEvidencePairPayloadV1 {
                    raw_seal: vec![seed.wrapping_add(u8::try_from(index).unwrap())],
                    receipt_oracle: vec![seed.wrapping_add(u8::try_from(index + 9).unwrap())],
                }
            }),
            catalogue: vec![seed.wrapping_add(27)],
            case8_direct: super::super::B4OwnedTerminalEvidencePairPayloadV1 {
                raw_seal: vec![seed.wrapping_add(28)],
                receipt_oracle: vec![seed.wrapping_add(29)],
            },
        }
    }

    fn changed_identity(
        identity: &crate::b4_campaign_contract::B4ContractArtifactIdentityV1,
        seed: u8,
    ) -> crate::b4_campaign_contract::B4ContractArtifactIdentityV1 {
        crate::b4_campaign_contract::B4ContractArtifactIdentityV1::from_bytes(
            identity.path.clone(),
            identity.encoding,
            &[seed],
        )
        .unwrap()
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the test builder isolates each of the six receipt identities plus the two packet bindings"
    )]
    fn receipt_with(
        campaign_precommit: &crate::b4_campaign_contract::B4ContractArtifactIdentityV1,
        positive_input_set: &crate::b4_campaign_contract::B4ContractArtifactIdentityV1,
        positive_generation_set: &crate::b4_campaign_contract::B4ContractArtifactIdentityV1,
        executor_artifact: &crate::b4_campaign_contract::B4ContractArtifactIdentityV1,
        executor_build_descriptor: &crate::b4_campaign_contract::B4ContractArtifactIdentityV1,
        executor_contract: &crate::b4_campaign_contract::B4ContractArtifactIdentityV1,
        packet_manifest_byte_length: usize,
        packet_id: &str,
    ) -> crate::b4_campaign_contract::Eip0045B4TerminalEvidenceCampaignReceiptV1 {
        let process_argv = [
            OsString::from("ignored-bin"),
            OsString::from("publish-terminal-evidence"),
            OsString::from("--outer-root"),
            OsString::from("campaign/terminal"),
        ];
        crate::b4_campaign_contract::Eip0045B4TerminalEvidenceCampaignReceiptV1::new(
            B4TerminalEvidenceCampaignReceiptInputsV1 {
                campaign_precommit,
                positive_input_set,
                positive_generation_set,
                executor_artifact,
                executor_build_descriptor,
                executor_contract,
                process_argv: &process_argv,
                parsed_preflight_only: false,
                risc0_dev_mode: None,
                terminal_packet_manifest_byte_length: packet_manifest_byte_length,
                terminal_packet_id: packet_id,
            },
        )
        .unwrap()
    }

    fn assert_semantic_reopen_drift(mutate: fn(&mut B4TerminalEvidenceSemanticStateV1)) {
        let first = synthetic_semantic(1);
        let mut changed = synthetic_semantic(1);
        mutate(&mut changed);
        assert!(!terminal_packet_reopens_are_byte_exact(
            31, [0x31; 32], &first, 31, [0x31; 32], &changed,
        ));
    }

    #[test]
    fn import_byte_identity_is_pathless_and_exact() {
        let source = b"exact terminal campaign receipt";
        let identity = B4TerminalEvidenceImportByteIdentityV1::from_bytes(source).unwrap();

        assert_eq!(identity.byte_length(), source.len() as u64);
        assert_eq!(identity.sha256(), hex::encode(Sha256::digest(source)));
    }

    #[test]
    fn import_authority_exposes_only_one_fixed_materialization_projection() {
        fn assert_projection_api<'authority>(
            projection: &B4TerminalMaterializationProjectionV1<'authority>,
        ) {
            let _: &'authority [u8] = projection.terminal_fixture_catalog_jcs();
            let _: [&'authority [u8]; 9] = projection.raw_seals();
            let _: [&'authority [u8]; 9] = projection.receipt_oracles();
            let _: &'authority [u8] = projection.profile_manifest();
            let _: &'authority [u8] = projection.reference_statement();
            let _: &'authority [u8; crate::constants::MANIFEST_CONTROL_ENTRY_BYTES] =
                projection.terminal_metadata_record();
            let _: [&'authority [u8]; 7] = projection.terminal_metadata_contexts();
            let _: &'authority B4TerminalEvidenceImportByteIdentityV1 =
                projection.terminal_evidence_packet_manifest_identity();
            let _: &'authority B4TerminalEvidenceImportByteIdentityV1 =
                projection.terminal_evidence_campaign_receipt_identity();
        }

        let _: for<'authority> fn(
            &'authority B4TerminalEvidenceImportAuthorityV1,
        ) -> B4TerminalMaterializationProjectionV1<'authority> =
            B4TerminalEvidenceImportAuthorityV1::terminal_materialization_projection;
        let _: for<'authority> fn(&B4TerminalMaterializationProjectionV1<'authority>) =
            assert_projection_api;
    }

    #[test]
    fn v2_import_authority_exposes_the_exact_distinct_materialization_projection() {
        fn assert_projection_api<'authority>(
            projection: &B4TerminalMaterializationProjectionV2<'authority>,
        ) {
            let _: &'authority [u8] = projection.terminal_fixture_catalog_jcs();
            let _: [&'authority [u8]; 9] = projection.raw_seals();
            let _: [&'authority [u8]; 9] = projection.receipt_oracles();
            let _: &'authority [u8] = projection.profile_manifest();
            let _: &'authority [u8] = projection.reference_statement();
            let _: &'authority [u8; crate::constants::MANIFEST_CONTROL_ENTRY_BYTES] =
                projection.terminal_metadata_record();
            let _: [&'authority [u8]; 7] = projection.terminal_metadata_contexts();
            let _: &'authority B4TerminalEvidenceImportByteIdentityV1 =
                projection.terminal_evidence_packet_manifest_identity();
            let _: &'authority B4TerminalEvidenceImportByteIdentityV1 =
                projection.terminal_evidence_campaign_receipt_identity();
        }

        let _: for<'authority> fn(
            &'authority B4TerminalEvidenceImportAuthorityV2,
        ) -> B4TerminalMaterializationProjectionV2<'authority> =
            B4TerminalEvidenceImportAuthorityV2::terminal_materialization_projection_v2;
        let _: for<'authority> fn(&B4TerminalMaterializationProjectionV2<'authority>) =
            assert_projection_api;
    }

    #[test]
    fn terminal_producer_source_binding_isolates_all_five_inputs() {
        let packet: [&[u8]; 5] = [b"guest", b"statement", b"case-0", b"case-8", b"case-9"];
        assert!(terminal_producer_sources_are_byte_exact(packet, packet));

        for index in 0..packet.len() {
            let mut drift = packet;
            drift[index] = b"drift";
            assert!(
                !terminal_producer_sources_are_byte_exact(drift, packet),
                "source binding {index} was not isolated"
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the isolated eight-binding matrix stays visibly adjacent to its exact expected predicates"
    )]
    fn campaign_precommit_and_receipt_relationship_isolate_every_binding() {
        let support = build_terminal_lineage_constructor_test_support(
            crate::receipt_oracle_replay::test_support::alternate_raw_seal_bytes(),
        )
        .unwrap();
        let campaign = &support.campaign_precommit_authority;
        let positive = &support.positive_generation_authority;
        let campaign_precommit =
            crate::b4_campaign_contract::B4ContractArtifactIdentityV1::from_bytes(
                "reproduction/terminal-evidence-campaign/campaign-precommit.json",
                crate::b4_campaign_contract::B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &campaign.to_canonical_precommit_jcs().unwrap(),
            )
            .unwrap();
        verify_campaign_precommit_identity(&campaign_precommit, campaign).unwrap();
        let wrong_precommit = changed_identity(&campaign_precommit, 0xa1);
        let error = verify_campaign_precommit_identity(&wrong_precommit, campaign).unwrap_err();
        assert!(
            format!("{error:#}")
                .contains("terminal import campaign-precommit identity differs from its authority")
        );

        let packet_manifest_byte_length = 31_u64;
        let packet_id = [0x42; 32];
        let packet_id_hex = hex::encode(packet_id);
        let executor = &campaign.precommit().campaign_executor;
        let valid = receipt_with(
            &campaign_precommit,
            positive.input_set(),
            positive.generation_set(),
            &executor.artifact,
            &executor.build_descriptor,
            &campaign.precommit().executor_contract,
            usize::try_from(packet_manifest_byte_length).unwrap(),
            &packet_id_hex,
        );
        verify_campaign_receipt_relationship(
            &campaign_precommit,
            campaign,
            positive,
            packet_manifest_byte_length,
            packet_id,
            &valid,
        )
        .unwrap();

        let alternate_precommit = changed_identity(&campaign_precommit, 0xa2);
        let alternate_input = changed_identity(positive.input_set(), 0xa3);
        let alternate_generation = changed_identity(positive.generation_set(), 0xa4);
        let alternate_artifact = changed_identity(&executor.artifact, 0xa5);
        let alternate_build = changed_identity(&executor.build_descriptor, 0xa6);
        let alternate_contract = changed_identity(&campaign.precommit().executor_contract, 0xa7);
        let alternate_packet_id = hex::encode([0x43; 32]);
        let cases = [
            (
                receipt_with(
                    &alternate_precommit,
                    positive.input_set(),
                    positive.generation_set(),
                    &executor.artifact,
                    &executor.build_descriptor,
                    &campaign.precommit().executor_contract,
                    usize::try_from(packet_manifest_byte_length).unwrap(),
                    &packet_id_hex,
                ),
                "different campaign precommit",
            ),
            (
                receipt_with(
                    &campaign_precommit,
                    &alternate_input,
                    positive.generation_set(),
                    &executor.artifact,
                    &executor.build_descriptor,
                    &campaign.precommit().executor_contract,
                    usize::try_from(packet_manifest_byte_length).unwrap(),
                    &packet_id_hex,
                ),
                "different positive input set",
            ),
            (
                receipt_with(
                    &campaign_precommit,
                    positive.input_set(),
                    &alternate_generation,
                    &executor.artifact,
                    &executor.build_descriptor,
                    &campaign.precommit().executor_contract,
                    usize::try_from(packet_manifest_byte_length).unwrap(),
                    &packet_id_hex,
                ),
                "different positive generation set",
            ),
            (
                receipt_with(
                    &campaign_precommit,
                    positive.input_set(),
                    positive.generation_set(),
                    &alternate_artifact,
                    &executor.build_descriptor,
                    &campaign.precommit().executor_contract,
                    usize::try_from(packet_manifest_byte_length).unwrap(),
                    &packet_id_hex,
                ),
                "different executor artifact",
            ),
            (
                receipt_with(
                    &campaign_precommit,
                    positive.input_set(),
                    positive.generation_set(),
                    &executor.artifact,
                    &alternate_build,
                    &campaign.precommit().executor_contract,
                    usize::try_from(packet_manifest_byte_length).unwrap(),
                    &packet_id_hex,
                ),
                "different executor build descriptor",
            ),
            (
                receipt_with(
                    &campaign_precommit,
                    positive.input_set(),
                    positive.generation_set(),
                    &executor.artifact,
                    &executor.build_descriptor,
                    &alternate_contract,
                    usize::try_from(packet_manifest_byte_length).unwrap(),
                    &packet_id_hex,
                ),
                "different executor contract",
            ),
            (
                receipt_with(
                    &campaign_precommit,
                    positive.input_set(),
                    positive.generation_set(),
                    &executor.artifact,
                    &executor.build_descriptor,
                    &campaign.precommit().executor_contract,
                    usize::try_from(packet_manifest_byte_length + 1).unwrap(),
                    &packet_id_hex,
                ),
                "different terminal packet",
            ),
            (
                receipt_with(
                    &campaign_precommit,
                    positive.input_set(),
                    positive.generation_set(),
                    &executor.artifact,
                    &executor.build_descriptor,
                    &campaign.precommit().executor_contract,
                    usize::try_from(packet_manifest_byte_length).unwrap(),
                    &alternate_packet_id,
                ),
                "different terminal packet",
            ),
        ];
        for (index, (receipt, expected)) in cases.iter().enumerate() {
            let error = verify_campaign_receipt_relationship(
                &campaign_precommit,
                campaign,
                positive,
                packet_manifest_byte_length,
                packet_id,
                receipt,
            )
            .unwrap_err();
            assert!(
                format!("{error:#}").contains(expected),
                "receipt binding {index} rejected at the wrong predicate: {error:#}"
            );
        }
    }

    #[test]
    fn v2_generation_authority_uses_distinct_import_and_shared_v1_receipt() {
        assert_ne!(
            TypeId::of::<B4TerminalEvidenceImportAuthorityV1>(),
            TypeId::of::<B4TerminalEvidenceImportAuthorityV2>()
        );
        let support = build_terminal_lineage_constructor_test_support_v2().unwrap();
        let campaign = &support.campaign_precommit_authority;
        let positive = &support.positive_generation_authority;
        let campaign_precommit =
            crate::b4_campaign_contract::B4ContractArtifactIdentityV1::from_bytes(
                "reproduction/terminal-evidence-campaign/campaign-precommit.json",
                crate::b4_campaign_contract::B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &campaign.to_canonical_precommit_jcs().unwrap(),
            )
            .unwrap();
        let packet_manifest_byte_length = 37_u64;
        let packet_id = [0x52; 32];
        let executor = &campaign.precommit().campaign_executor;
        let valid = receipt_with(
            &campaign_precommit,
            positive.input_set(),
            positive.generation_set(),
            &executor.artifact,
            &executor.build_descriptor,
            &campaign.precommit().executor_contract,
            usize::try_from(packet_manifest_byte_length).unwrap(),
            &hex::encode(packet_id),
        );
        verify_campaign_receipt_relationship_v2(
            &campaign_precommit,
            campaign,
            positive,
            packet_manifest_byte_length,
            packet_id,
            &valid,
        )
        .unwrap();

        let wrong_input = changed_identity(positive.input_set(), 0x53);
        let wrong_generation = changed_identity(positive.generation_set(), 0x54);
        for receipt in [
            receipt_with(
                &campaign_precommit,
                &wrong_input,
                positive.generation_set(),
                &executor.artifact,
                &executor.build_descriptor,
                &campaign.precommit().executor_contract,
                usize::try_from(packet_manifest_byte_length).unwrap(),
                &hex::encode(packet_id),
            ),
            receipt_with(
                &campaign_precommit,
                positive.input_set(),
                &wrong_generation,
                &executor.artifact,
                &executor.build_descriptor,
                &campaign.precommit().executor_contract,
                usize::try_from(packet_manifest_byte_length).unwrap(),
                &hex::encode(packet_id),
            ),
        ] {
            assert!(
                verify_campaign_receipt_relationship_v2(
                    &campaign_precommit,
                    campaign,
                    positive,
                    packet_manifest_byte_length,
                    packet_id,
                    &receipt,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn final_packet_comparison_isolates_all_derived_fields_and_29_payloads() {
        let first = synthetic_semantic(1);
        let exact = synthetic_semantic(1);
        assert!(terminal_packet_reopens_are_byte_exact(
            31, [0x31; 32], &first, 31, [0x31; 32], &exact,
        ));
        assert!(!terminal_packet_reopens_are_byte_exact(
            31, [0x31; 32], &first, 32, [0x31; 32], &exact,
        ));
        assert!(!terminal_packet_reopens_are_byte_exact(
            31, [0x31; 32], &first, 31, [0x32; 32], &exact,
        ));

        let derived_mutations: [fn(&mut B4TerminalEvidenceSemanticStateV1); 3] = [
            |state| state.profile_id[0] ^= 1,
            |state| state.program_id[0] ^= 1,
            |state| state.statement_sha256[0] ^= 1,
        ];
        for mutate in derived_mutations {
            assert_semantic_reopen_drift(mutate);
        }

        let payload_mutations: [fn(&mut B4TerminalEvidenceSemanticStateV1); 11] = [
            |state| state.profile.manifest[0] ^= 1,
            |state| state.profile.algorithm[0] ^= 1,
            |state| state.profile.constants[0] ^= 1,
            |state| state.sources.guest_elf[0] ^= 1,
            |state| state.sources.statement[0] ^= 1,
            |state| state.sources.case0_lift15_receipt_oracle[0] ^= 1,
            |state| state.sources.case8_terminal_join_recursive_oracle[0] ^= 1,
            |state| state.sources.case9_terminal_resolve_recursive_oracle[0] ^= 1,
            |state| state.catalogue[0] ^= 1,
            |state| state.case8_direct.raw_seal[0] ^= 1,
            |state| state.case8_direct.receipt_oracle[0] ^= 1,
        ];
        for mutate in payload_mutations {
            assert_semantic_reopen_drift(mutate);
        }

        for fixture_index in 0..crate::b4_terminal::B4_TERMINAL_FIXTURE_COUNT {
            let mut raw_seal_drift = synthetic_semantic(1);
            raw_seal_drift.fixtures[fixture_index].raw_seal[0] ^= 1;
            assert!(!terminal_packet_reopens_are_byte_exact(
                31,
                [0x31; 32],
                &first,
                31,
                [0x31; 32],
                &raw_seal_drift,
            ));

            let mut oracle_drift = synthetic_semantic(1);
            oracle_drift.fixtures[fixture_index].receipt_oracle[0] ^= 1;
            assert!(!terminal_packet_reopens_are_byte_exact(
                31,
                [0x31; 32],
                &first,
                31,
                [0x31; 32],
                &oracle_drift,
            ));
        }
        assert_eq!(
            payload_mutations.len() + 2 * crate::b4_terminal::B4_TERMINAL_FIXTURE_COUNT,
            29
        );
    }

    #[test]
    fn final_packet_comparison_rejects_byte_identical_file_replacement() {
        let first =
            crate::b4_terminal_evidence_io::B4PhysicalPacketClosureIdentityV1::synthetic_for_test();
        let exact =
            crate::b4_terminal_evidence_io::B4PhysicalPacketClosureIdentityV1::synthetic_for_test();
        let changed =
            crate::b4_terminal_evidence_io::B4PhysicalPacketClosureIdentityV1::synthetic_for_test()
                .with_changed_file_identity_for_test();

        assert!(terminal_packet_physical_closures_are_exact(&first, &exact));
        assert!(!terminal_packet_physical_closures_are_exact(
            &first, &changed
        ));
    }

    #[test]
    fn final_packet_comparison_rejects_byte_identical_directory_replacement() {
        let first =
            crate::b4_terminal_evidence_io::B4PhysicalPacketClosureIdentityV1::synthetic_for_test();
        let changed =
            crate::b4_terminal_evidence_io::B4PhysicalPacketClosureIdentityV1::synthetic_for_test()
                .with_changed_directory_identity_for_test();

        assert!(!terminal_packet_physical_closures_are_exact(
            &first, &changed
        ));
    }

    #[test]
    fn final_packet_comparison_retains_first_os_handles_until_decision() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("packet");
        let nested = root.join("nested");
        let live = nested.join("payload.bin");
        let displaced = temporary.path().join("payload.displaced.bin");
        fs::create_dir_all(&nested).unwrap();
        fs::write(&live, b"same bytes").unwrap();

        let first =
            crate::b4_terminal_evidence_io::B4PhysicalPacketClosureIdentityV1::from_test_tree(
                &root,
                &["nested/payload.bin"],
            )
            .unwrap();
        fs::rename(&live, &displaced).unwrap();
        fs::write(&live, b"same bytes").unwrap();
        let final_reopen =
            crate::b4_terminal_evidence_io::B4PhysicalPacketClosureIdentityV1::from_test_tree(
                &root,
                &["nested/payload.bin"],
            )
            .unwrap();

        assert_eq!(first.retained_handle_counts_for_test(), (2, 1));
        assert!(first.retained_handles_are_live_for_test().unwrap());
        assert!(!terminal_packet_physical_closures_are_exact(
            &first,
            &final_reopen
        ));
        assert_eq!(first.retained_handle_counts_for_test(), (2, 1));
        assert!(first.retained_handles_are_live_for_test().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn final_packet_comparison_retains_displaced_directory_handle_until_decision() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("packet");
        let nested = root.join("nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("payload.bin"), b"same bytes").unwrap();

        let first =
            crate::b4_terminal_evidence_io::B4PhysicalPacketClosureIdentityV1::from_test_tree(
                &root,
                &["nested/payload.bin"],
            )
            .unwrap();
        fs::rename(&nested, temporary.path().join("nested.displaced")).unwrap();
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("payload.bin"), b"same bytes").unwrap();
        let final_reopen =
            crate::b4_terminal_evidence_io::B4PhysicalPacketClosureIdentityV1::from_test_tree(
                &root,
                &["nested/payload.bin"],
            )
            .unwrap();

        assert_eq!(first.retained_handle_counts_for_test(), (2, 1));
        assert!(first.retained_handles_are_live_for_test().unwrap());
        assert!(!terminal_packet_physical_closures_are_exact(
            &first,
            &final_reopen
        ));
        assert!(first.retained_handles_are_live_for_test().unwrap());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod physical_import_tests {
    use std::{
        fs::{self, File},
        os::{fd::AsFd as _, unix::fs::PermissionsExt as _},
        path::{Path, PathBuf},
        sync::OnceLock,
    };

    use anyhow::{Context as _, Result, ensure};

    use crate::{
        b4::canonical_positive_case_artifact_path,
        b4_campaign_contract::{
            B4CampaignPrecommitAuthorityV1, B4ContractArtifactEncodingV1,
            B4ContractArtifactIdentityV1,
            test_support::{
                PositiveGenerationConstructorSourcesV2, TerminalLineageConstructorTestSupportV1,
                TerminalLineageConstructorTestSupportV2,
                build_terminal_import_executor_campaign_test_authority,
                build_terminal_lineage_constructor_test_support,
                build_terminal_lineage_constructor_test_support_v2,
                build_terminal_lineage_constructor_test_support_v2_for_executor,
            },
        },
        b4_materialization_set::compiled_positive_case_id,
        b4_terminal_source_lineage::{
            B4TerminalSourceCaseExternalV1, B4TerminalSourceCaseExternalV2,
            B4TerminalSourceExternalBytesV1, B4TerminalSourceExternalBytesV2,
            B4TerminalSourceExternalClosureV1, B4TerminalSourceExternalClosureV2,
            B4TerminalSourceLineageAuthorityV1, B4TerminalSourceLineageAuthorityV2,
        },
    };

    use super::{
        authenticate_b4_terminal_evidence_import_from_directory_descriptor,
        authenticate_b4_terminal_evidence_import_from_directory_descriptor_v2,
    };

    const TERMINAL_PACKET_DIRECTORY: &str = "terminal-evidence-packet";
    const TERMINAL_CAMPAIGN_RECEIPT_FILE: &str = "terminal-evidence-campaign-receipt.json";

    fn terminal_support() -> &'static TerminalLineageConstructorTestSupportV1 {
        static SUPPORT: OnceLock<TerminalLineageConstructorTestSupportV1> = OnceLock::new();
        SUPPORT.get_or_init(|| {
            build_terminal_lineage_constructor_test_support(
                crate::receipt_oracle_replay::test_support::alternate_raw_seal_bytes(),
            )
            .expect("fixed terminal-import authority support")
        })
    }

    fn external_bytes(
        source: &crate::b4_positive_gate::test_support::OwnedPositiveAuthorityTestArtifactV1,
    ) -> B4TerminalSourceExternalBytesV1<'_> {
        B4TerminalSourceExternalBytesV1 {
            path: &source.path,
            bytes: &source.bytes,
        }
    }

    fn construct_terminal_lineage(
        support: &TerminalLineageConstructorTestSupportV1,
    ) -> Result<B4TerminalSourceLineageAuthorityV1> {
        let case0_manifest_path = canonical_positive_case_artifact_path(
            &compiled_positive_case_id(0).context("missing fixed positive case 0")?,
            "candidate-proof-output-manifest.json",
        );
        let case8_manifest_path = canonical_positive_case_artifact_path(
            &compiled_positive_case_id(8).context("missing fixed positive case 8")?,
            "candidate-recursive-output-manifest.json",
        );
        let case9_manifest_path = canonical_positive_case_artifact_path(
            &compiled_positive_case_id(9).context("missing fixed positive case 9")?,
            "candidate-recursive-output-manifest.json",
        );
        let case0_primary = support
            .case0_primary_artifacts
            .iter()
            .map(external_bytes)
            .collect::<Vec<_>>();
        let case0_auxiliary = support
            .case0_auxiliary_artifacts
            .iter()
            .map(external_bytes)
            .collect::<Vec<_>>();
        let case8_primary = support
            .case8_primary_artifacts
            .iter()
            .map(external_bytes)
            .collect::<Vec<_>>();
        let case8_auxiliary = support
            .case8_auxiliary_artifacts
            .iter()
            .map(external_bytes)
            .collect::<Vec<_>>();
        let case9_primary = support
            .case9_primary_artifacts
            .iter()
            .map(external_bytes)
            .collect::<Vec<_>>();
        let case9_auxiliary = support
            .case9_auxiliary_artifacts
            .iter()
            .map(external_bytes)
            .collect::<Vec<_>>();

        B4TerminalSourceLineageAuthorityV1::from_external_closure(
            &support.campaign_precommit_authority,
            &support.positive_generation_authority,
            B4TerminalSourceExternalClosureV1 {
                positive_input_set: external_bytes(&support.positive_input_set),
                positive_generation_set: external_bytes(&support.positive_generation_set),
                guest_elf: external_bytes(&support.consumer_guest_elf),
                case0_lift15: B4TerminalSourceCaseExternalV1 {
                    proof_output_manifest: B4TerminalSourceExternalBytesV1 {
                        path: &case0_manifest_path,
                        bytes: &support.case0_proof_output_manifest_jcs,
                    },
                    primary_artifacts: &case0_primary,
                    auxiliary_artifacts: &case0_auxiliary,
                },
                case8_terminal_join: B4TerminalSourceCaseExternalV1 {
                    proof_output_manifest: B4TerminalSourceExternalBytesV1 {
                        path: &case8_manifest_path,
                        bytes: &support.case8_proof_output_manifest_jcs,
                    },
                    primary_artifacts: &case8_primary,
                    auxiliary_artifacts: &case8_auxiliary,
                },
                case9_terminal_resolve: B4TerminalSourceCaseExternalV1 {
                    proof_output_manifest: B4TerminalSourceExternalBytesV1 {
                        path: &case9_manifest_path,
                        bytes: &support.case9_proof_output_manifest_jcs,
                    },
                    primary_artifacts: &case9_primary,
                    auxiliary_artifacts: &case9_auxiliary,
                },
            },
        )
    }

    fn construct_terminal_lineage_v2(
        support: &TerminalLineageConstructorTestSupportV2,
    ) -> Result<B4TerminalSourceLineageAuthorityV2> {
        let sources: &PositiveGenerationConstructorSourcesV2 = &support.sources;
        let terminal_cases = [0_usize, 8, 9];
        let primary: [Vec<_>; 3] = std::array::from_fn(|position| {
            sources.cases[terminal_cases[position]]
                .primary_artifacts
                .iter()
                .map(|artifact| B4TerminalSourceExternalBytesV2 {
                    path: &artifact.path,
                    bytes: &artifact.bytes,
                })
                .collect()
        });
        let auxiliary: [Vec<_>; 3] = std::array::from_fn(|position| {
            sources.cases[terminal_cases[position]]
                .auxiliary_artifacts
                .iter()
                .map(|artifact| B4TerminalSourceExternalBytesV2 {
                    path: &artifact.path,
                    bytes: &artifact.bytes,
                })
                .collect()
        });
        let case = |position: usize| B4TerminalSourceCaseExternalV2 {
            proof_output_manifest: B4TerminalSourceExternalBytesV2 {
                path: &sources.cases[terminal_cases[position]]
                    .proof_output_manifest
                    .path,
                bytes: &sources.cases[terminal_cases[position]]
                    .proof_output_manifest
                    .bytes,
            },
            primary_artifacts: &primary[position],
            auxiliary_artifacts: &auxiliary[position],
        };
        let guest = sources
            .nested_input_sources
            .iter()
            .find(|source| source.path == "methods/guest.elf")
            .context("missing fixed V2 guest source")?;
        B4TerminalSourceLineageAuthorityV2::from_external_closure(
            &support.campaign_precommit_authority,
            &support.positive_generation_authority,
            B4TerminalSourceExternalClosureV2 {
                positive_input_set: B4TerminalSourceExternalBytesV2 {
                    path: &sources.positive_input_set.path,
                    bytes: &sources.positive_input_set.bytes,
                },
                positive_generation_set: B4TerminalSourceExternalBytesV2 {
                    path: &sources.positive_generation_set.path,
                    bytes: &sources.positive_generation_set.bytes,
                },
                guest_elf: B4TerminalSourceExternalBytesV2 {
                    path: &guest.path,
                    bytes: &guest.bytes,
                },
                case0_lift15: case(0),
                case8_terminal_join: case(1),
                case9_terminal_resolve: case(2),
            },
        )
    }

    fn current_executable_path_and_bytes() -> Result<(PathBuf, Vec<u8>)> {
        let path = fs::read_link("/proc/self/exe")
            .context("cannot resolve the Linux test runner executable")?;
        let bytes = fs::read(&path).context("cannot read the Linux test runner executable")?;
        Ok((path, bytes))
    }

    fn current_executable_campaign(
        executable_bytes: &[u8],
    ) -> Result<B4CampaignPrecommitAuthorityV1> {
        build_terminal_import_executor_campaign_test_authority(
            crate::receipt_oracle_replay::test_support::alternate_raw_seal_bytes(),
            executable_bytes,
        )
    }

    fn campaign_precommit_identity(
        campaign: &B4CampaignPrecommitAuthorityV1,
    ) -> Result<B4ContractArtifactIdentityV1> {
        B4ContractArtifactIdentityV1::from_bytes(
            "reproduction/terminal-evidence-campaign/campaign-precommit.json",
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            &campaign.to_canonical_precommit_jcs()?,
        )
    }

    struct PhysicalImportRootFixture {
        _guard: tempfile::TempDir,
        root: PathBuf,
        packet: PathBuf,
        receipt: PathBuf,
    }

    impl PhysicalImportRootFixture {
        fn exact_presemantic() -> Result<Self> {
            let guard = tempfile::tempdir()?;
            let root = guard.path().join("terminal-campaign");
            let packet = root.join(TERMINAL_PACKET_DIRECTORY);
            let receipt = root.join(TERMINAL_CAMPAIGN_RECEIPT_FILE);
            fs::create_dir(&root)?;
            fs::create_dir(&packet)?;
            fs::write(&receipt, b"{}")?;
            set_mode(&root, 0o700)?;
            set_mode(&packet, 0o700)?;
            set_mode(&receipt, 0o600)?;
            Ok(Self {
                _guard: guard,
                root,
                packet,
                receipt,
            })
        }

        fn root_descriptor(&self) -> Result<File> {
            File::open(&self.root).context("cannot retain physical import test root")
        }
    }

    fn set_mode(path: &Path, mode: u32) -> Result<()> {
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(mode);
        fs::set_permissions(path, permissions)?;
        Ok(())
    }

    fn authenticate_fixture(
        root: &File,
        executable_path: &Path,
        campaign: &B4CampaignPrecommitAuthorityV1,
    ) -> Result<super::B4TerminalEvidenceImportAuthorityV1> {
        let support = terminal_support();
        ensure!(
            campaign.precommit().input_set == *support.positive_generation_authority.input_set(),
            "physical import test campaign and positive authority bind different inputs"
        );
        let identity = campaign_precommit_identity(campaign)?;
        authenticate_b4_terminal_evidence_import_from_directory_descriptor(
            root.as_fd(),
            executable_path,
            &identity,
            campaign,
            &support.positive_generation_authority,
            construct_terminal_lineage(support)?,
        )
    }

    fn require_rejection_contains(
        result: Result<super::B4TerminalEvidenceImportAuthorityV1>,
        expected: &str,
    ) {
        let Err(error) = result else {
            panic!("malformed physical terminal import unexpectedly minted authority");
        };
        let message = format!("{error:#}");
        assert!(
            message.contains(expected),
            "unexpected physical import rejection: {message}"
        );
    }

    #[test]
    fn physical_import_rejects_executor_identity_before_root_inspection() {
        let fixture = PhysicalImportRootFixture::exact_presemantic().unwrap();
        let non_directory_root = File::open(&fixture.receipt).unwrap();
        let (executable_path, _) = current_executable_path_and_bytes().unwrap();
        let support = terminal_support();
        let identity = campaign_precommit_identity(&support.campaign_precommit_authority).unwrap();
        let result = authenticate_b4_terminal_evidence_import_from_directory_descriptor(
            non_directory_root.as_fd(),
            &executable_path,
            &identity,
            &support.campaign_precommit_authority,
            &support.positive_generation_authority,
            construct_terminal_lineage(support).unwrap(),
        );
        let Err(error) = result else {
            panic!("wrong executor identity unexpectedly minted terminal import authority");
        };
        let message = format!("{error:#}");
        assert!(message.contains("terminal import running-executor binding failed"));
        assert!(
            !message.contains("terminal campaign root is not an ordinary directory"),
            "root was inspected before executor identity rejection: {message}"
        );
    }

    #[test]
    fn v2_terminal_import_descriptor() {
        let fixture = PhysicalImportRootFixture::exact_presemantic().unwrap();
        let non_directory_root = File::open(&fixture.receipt).unwrap();
        let (executable_path, _) = current_executable_path_and_bytes().unwrap();
        let support = build_terminal_lineage_constructor_test_support_v2().unwrap();
        let identity = campaign_precommit_identity(&support.campaign_precommit_authority).unwrap();
        let result = authenticate_b4_terminal_evidence_import_from_directory_descriptor_v2(
            non_directory_root.as_fd(),
            &executable_path,
            &identity,
            &support.campaign_precommit_authority,
            &support.positive_generation_authority,
            construct_terminal_lineage_v2(&support).unwrap(),
        );
        let Err(error) = result else {
            panic!("wrong V2 running executable unexpectedly minted terminal import authority");
        };
        let message = format!("{error:#}");
        assert!(message.contains("V2 terminal import running-executor binding failed"));
        assert!(
            !message.contains("V2 terminal campaign root is not an ordinary directory"),
            "V2 campaign root was inspected before running-executable rejection: {message}"
        );
    }

    #[test]
    fn v2_terminal_import_current_executor_reaches_root_descriptor_gate() {
        let fixture = PhysicalImportRootFixture::exact_presemantic().unwrap();
        let non_directory_root = File::open(&fixture.receipt).unwrap();
        let (executable_path, executable_bytes) = current_executable_path_and_bytes().unwrap();
        let support =
            build_terminal_lineage_constructor_test_support_v2_for_executor(&executable_bytes)
                .unwrap();
        let identity = campaign_precommit_identity(&support.campaign_precommit_authority).unwrap();
        let result = authenticate_b4_terminal_evidence_import_from_directory_descriptor_v2(
            non_directory_root.as_fd(),
            &executable_path,
            &identity,
            &support.campaign_precommit_authority,
            &support.positive_generation_authority,
            construct_terminal_lineage_v2(&support).unwrap(),
        );
        let Err(error) = result else {
            panic!("non-directory V2 campaign root unexpectedly minted terminal import authority");
        };
        let message = format!("{error:#}");
        assert!(message.contains("V2 terminal campaign root is not an ordinary directory"));
        assert!(
            !message.contains("V2 terminal import running-executor binding failed"),
            "current executable did not cross the V2 executor gate: {message}"
        );
    }

    #[test]
    fn physical_import_rejects_non_private_root_mode_before_packet_open() {
        let fixture = PhysicalImportRootFixture::exact_presemantic().unwrap();
        set_mode(&fixture.root, 0o750).unwrap();
        let root = fixture.root_descriptor().unwrap();
        let (executable_path, executable_bytes) = current_executable_path_and_bytes().unwrap();
        let campaign = current_executable_campaign(&executable_bytes).unwrap();

        require_rejection_contains(
            authenticate_fixture(&root, &executable_path, &campaign),
            "terminal campaign root lacks its exact private one-subdirectory policy",
        );
    }

    #[test]
    fn physical_import_rejects_root_inventory_drift_before_packet_open() {
        let fixture = PhysicalImportRootFixture::exact_presemantic().unwrap();
        let extra = fixture.root.join("unexpected-entry");
        fs::write(&extra, b"unexpected").unwrap();
        set_mode(&extra, 0o600).unwrap();
        let root = fixture.root_descriptor().unwrap();
        let (executable_path, executable_bytes) = current_executable_path_and_bytes().unwrap();
        let campaign = current_executable_campaign(&executable_bytes).unwrap();

        require_rejection_contains(
            authenticate_fixture(&root, &executable_path, &campaign),
            "terminal campaign root inventory differs from packet plus receipt",
        );
    }

    #[test]
    fn physical_import_rejects_packet_mode_relationship_before_receipt_open() {
        let fixture = PhysicalImportRootFixture::exact_presemantic().unwrap();
        set_mode(&fixture.packet, 0o750).unwrap();
        let root = fixture.root_descriptor().unwrap();
        let (executable_path, executable_bytes) = current_executable_path_and_bytes().unwrap();
        let campaign = current_executable_campaign(&executable_bytes).unwrap();

        require_rejection_contains(
            authenticate_fixture(&root, &executable_path, &campaign),
            "terminal packet directory differs from retained campaign-root policy",
        );
    }

    #[test]
    fn physical_import_rejects_receipt_mode_relationship_before_semantic_reopen() {
        let fixture = PhysicalImportRootFixture::exact_presemantic().unwrap();
        set_mode(&fixture.receipt, 0o640).unwrap();
        let root = fixture.root_descriptor().unwrap();
        let (executable_path, executable_bytes) = current_executable_path_and_bytes().unwrap();
        let campaign = current_executable_campaign(&executable_bytes).unwrap();

        require_rejection_contains(
            authenticate_fixture(&root, &executable_path, &campaign),
            "terminal campaign receipt differs from retained campaign-root policy",
        );
    }
}
