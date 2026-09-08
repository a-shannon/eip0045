//! Proof-free semantic replay for exported B4 terminal-evidence sources.

#[cfg(unix)]
use std::os::fd::BorrowedFd;
use std::path::Path;

use anyhow::{Context as _, Result, ensure};
#[cfg(unix)]
use eip_0045_reproduction::b4_terminal_evidence_packet::{
    preflight_b4_terminal_evidence_publication_from_directory_descriptor,
    publish_b4_terminal_evidence_packet_from_directory_descriptor,
};
use eip_0045_reproduction::{
    b4_campaign_contract::{
        B4CampaignPrecommitAuthorityV1, B4ContractArtifactIdentityV1,
        B4PositiveGenerationAuthorityV2,
    },
    b4_terminal::{
        B4_TERMINAL_FIXTURE_COUNT, B4_TERMINAL_FIXTURE_LAYOUT, terminal_fixture_raw_seal_path,
        terminal_fixture_receipt_oracle_path,
    },
    b4_terminal_evidence_packet::{
        B4TerminalEvidenceDirectPairPayloadV1, B4TerminalEvidenceFixturePairPayloadV1,
        B4TerminalEvidencePacketIdentityV1, B4TerminalEvidencePacketPayloadsV1,
        B4TerminalEvidenceProducerSourcesV1, B4TerminalEvidenceProfilePayloadsV1,
        B4VerifiedTerminalEvidencePacketV1, preflight_b4_terminal_evidence_publication,
        publish_b4_terminal_evidence_packet,
    },
    b4_terminal_source_lineage::{
        B4TerminalSourceLineageAuthorityV1, B4TerminalSourceLineageAuthorityV2,
    },
};
use risc0_zkvm::LocalProver;

use crate::{
    terminal_evidence_profile::{
        B4AuthenticatedCompiledTerminalEvidenceProfileV1,
        authenticate_compiled_terminal_evidence_profile,
    },
    terminal_fixtures::{
        B4AuthenticatedTerminalFixtureSourcesV1, B4Case8FinalJoinDirectEvidenceV1,
        B4GeneratedTerminalFixtureSetV1, authenticate_b4_terminal_fixture_sources,
        compose_authenticated_b4_terminal_fixture_set, derive_case8_final_join_direct_evidence,
    },
    terminal_lineage::{
        authenticate_lineaged_b4_terminal_sources, authenticate_lineaged_b4_terminal_sources_v2,
    },
};

/// Opaque authority for one packet whose retained sources replay semantically.
pub struct B4ReplayedTerminalEvidenceSourcesV1 {
    packet_identity: B4TerminalEvidencePacketIdentityV1,
}

/// Replay the exact retained producer sources and direct case-8 evidence.
///
/// This establishes current semantic closure only. It makes no claim about
/// the historical provenance of the retained bytes.
///
/// # Errors
///
/// Returns an error unless the packet statement binds the compiled profile,
/// all five retained sources authenticate, and both rederived direct case-8
/// byte roles equal the packet-owned pair.
pub fn replay_b4_terminal_evidence_sources(
    packet: &B4VerifiedTerminalEvidencePacketV1,
) -> Result<B4ReplayedTerminalEvidenceSourcesV1> {
    let view = packet.source_replay_view();
    let _profile = authenticate_compiled_terminal_evidence_profile(view.statement())
        .context("packet statement does not bind the compiled terminal-evidence profile")?;
    let authenticated = authenticate_b4_terminal_fixture_sources(
        view.guest_elf(),
        view.statement(),
        view.case0_lift15_receipt_oracle(),
        view.case8_terminal_join_recursive_oracle(),
        view.case9_terminal_resolve_recursive_oracle(),
    )
    .context("packet terminal-evidence sources failed semantic authentication")?;
    let derived = derive_case8_final_join_direct_evidence(&authenticated)
        .context("cannot rederive the packet case-8 final Join evidence")?;
    let direct_pair = view.case8_direct_pair();
    ensure!(
        derived.raw_seal() == direct_pair.raw_seal(),
        "rederived case-8 raw seal differs from the packet-owned direct seal"
    );
    ensure!(
        derived.receipt_oracle() == direct_pair.receipt_oracle(),
        "rederived case-8 receipt oracle differs from the packet-owned direct oracle"
    );
    Ok(B4ReplayedTerminalEvidenceSourcesV1 {
        packet_identity: packet.identity(),
    })
}

/// Require both fields of one terminal-packet identity to match.
pub(crate) fn require_terminal_packet_identity_binding(
    expected_manifest_byte_length: u64,
    expected_packet_id: &str,
    actual_manifest_byte_length: u64,
    actual_packet_id: &str,
) -> Result<()> {
    ensure!(
        expected_manifest_byte_length == actual_manifest_byte_length
            && expected_packet_id == actual_packet_id,
        "terminal packet identity fields differ"
    );
    Ok(())
}

/// Opaque authority for one lineaged, generation-bound published packet.
///
/// The authority cannot be constructed, serialized, or projected into packet,
/// source, or importer state by downstream callers.
///
/// ```compile_fail
/// use eip_0045_candidate_generator::terminal_evidence_export::
///     B4PublishedLineagedTerminalEvidenceAuthorityV1;
/// let _ = B4PublishedLineagedTerminalEvidenceAuthorityV1 {};
/// ```
///
/// ```compile_fail
/// use eip_0045_candidate_generator::terminal_evidence_export::
///     B4PublishedLineagedTerminalEvidenceAuthorityV1;
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<B4PublishedLineagedTerminalEvidenceAuthorityV1>();
/// ```
///
/// ```compile_fail
/// use eip_0045_candidate_generator::terminal_evidence_export::
///     B4PublishedLineagedTerminalEvidenceAuthorityV1;
/// fn forbidden(value: B4PublishedLineagedTerminalEvidenceAuthorityV1) {
///     let _ = value.into_packet();
/// }
/// ```
///
/// ```compile_fail
/// use eip_0045_candidate_generator::terminal_evidence_export::
///     B4PublishedLineagedTerminalEvidenceAuthorityV1;
/// fn forbidden(value: &B4PublishedLineagedTerminalEvidenceAuthorityV1) {
///     let _ = value.source();
/// }
/// ```
///
/// ```compile_fail
/// use eip_0045_candidate_generator::terminal_evidence_export::
///     B4PublishedLineagedTerminalEvidenceAuthorityV1;
/// fn forbidden(value: &B4PublishedLineagedTerminalEvidenceAuthorityV1) {
///     let _ = value.import_projection();
/// }
/// ```
///
/// ```compile_fail
/// use eip_0045_candidate_generator::terminal_evidence_export::
///     B4PublishedLineagedTerminalEvidenceAuthorityV1;
/// fn forbidden(value: &B4PublishedLineagedTerminalEvidenceAuthorityV1) {
///     let _ = value.lineage();
/// }
/// ```
#[allow(
    dead_code,
    reason = "packet, replay, and lineage custody are intentionally retained without public projections"
)]
pub struct B4PublishedLineagedTerminalEvidenceAuthorityV1 {
    packet: B4VerifiedTerminalEvidencePacketV1,
    replay: B4ReplayedTerminalEvidenceSourcesV1,
    lineage: B4TerminalSourceLineageAuthorityV1,
}

impl B4PublishedLineagedTerminalEvidenceAuthorityV1 {
    /// Return the final measured packet identity.
    #[must_use]
    pub fn identity(&self) -> B4TerminalEvidencePacketIdentityV1 {
        self.packet.identity()
    }

    /// Consume this generation-time authority and bind it to a separately
    /// reopened copy of the same semantically verified packet.
    ///
    /// The caller remains responsible for supplying the packet through the
    /// outer transaction's retained post-commit descriptor custody. This
    /// method independently requires the original identity, repeats semantic
    /// source replay, and rechecks the still-live official lineage before the
    /// authority can continue.
    ///
    /// # Errors
    ///
    /// Returns an error if the retained authority drifted internally, the
    /// reopened packet has another identity, semantic replay fails, or the
    /// reopened producer sources differ from official lineage.
    #[allow(
        dead_code,
        reason = "the E2 handler consumes this only after descriptor-rooted outer commit"
    )]
    pub(crate) fn rebind_postcommit_semantically_reopened_packet(
        mut self,
        packet: B4VerifiedTerminalEvidencePacketV1,
    ) -> Result<Self> {
        let retained_identity = self.packet.identity();
        let retained_replay_identity = self.replay.packet_identity;
        let retained_packet_id = hex::encode(retained_identity.packet_id());
        let retained_replay_packet_id = hex::encode(retained_replay_identity.packet_id());
        require_terminal_packet_identity_binding(
            retained_identity.manifest_byte_length(),
            &retained_packet_id,
            retained_replay_identity.manifest_byte_length(),
            &retained_replay_packet_id,
        )
        .context("retained lineaged authority replay identity drifted from its packet")?;

        let reopened_identity = packet.identity();
        let reopened_packet_id = hex::encode(reopened_identity.packet_id());
        require_terminal_packet_identity_binding(
            retained_identity.manifest_byte_length(),
            &retained_packet_id,
            reopened_identity.manifest_byte_length(),
            &reopened_packet_id,
        )
        .context("post-commit packet identity differs from the generation-time publication")?;
        let replay = replay_b4_terminal_evidence_sources(&packet)
            .context("post-commit packet failed semantic source replay")?;
        require_official_lineage_binding(&packet, &self.lineage)
            .context("post-commit packet differs from its live official source lineage")?;

        self.packet = packet;
        self.replay = replay;
        Ok(self)
    }
}

/// Opaque, affine authority for one V2-lineaged, generation-bound packet.
///
/// The V2 positive-generation and independently authenticated lineage
/// authorities remain retained together. Downstream callers can observe only
/// the unchanged packet identity; they cannot project packet bytes, producer
/// sources, either affine predecessor, or a V1 authority.
///
/// ```compile_fail
/// use eip_0045_candidate_generator::terminal_evidence_export::
///     B4PublishedLineagedTerminalEvidenceAuthorityV2;
/// fn require_clone<T: Clone>() {}
/// require_clone::<B4PublishedLineagedTerminalEvidenceAuthorityV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_candidate_generator::terminal_evidence_export::
///     B4PublishedLineagedTerminalEvidenceAuthorityV2;
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<B4PublishedLineagedTerminalEvidenceAuthorityV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_candidate_generator::terminal_evidence_export::
///     B4PublishedLineagedTerminalEvidenceAuthorityV2;
/// fn forbidden(value: &B4PublishedLineagedTerminalEvidenceAuthorityV2) {
///     let _ = value.source();
/// }
/// ```
///
/// ```compile_fail
/// use eip_0045_candidate_generator::terminal_evidence_export::
///     B4PublishedLineagedTerminalEvidenceAuthorityV2;
/// fn forbidden(value: &B4PublishedLineagedTerminalEvidenceAuthorityV2) {
///     let _ = value.packet();
/// }
/// ```
#[allow(
    dead_code,
    reason = "packet, replay, and both V2 authorities are intentionally retained without public projections"
)]
pub struct B4PublishedLineagedTerminalEvidenceAuthorityV2 {
    packet: B4VerifiedTerminalEvidencePacketV1,
    replay: B4ReplayedTerminalEvidenceSourcesV1,
    positive: B4PositiveGenerationAuthorityV2,
    lineage: B4TerminalSourceLineageAuthorityV2,
}

impl B4PublishedLineagedTerminalEvidenceAuthorityV2 {
    /// Return the unchanged final measured packet identity.
    #[must_use]
    pub fn identity(&self) -> B4TerminalEvidencePacketIdentityV1 {
        self.packet.identity()
    }

    pub(crate) fn positive_input_set_identity(&self) -> &B4ContractArtifactIdentityV1 {
        self.positive.positive_input_set_identity()
    }

    pub(crate) fn positive_generation_set_identity(&self) -> &B4ContractArtifactIdentityV1 {
        self.positive.positive_generation_set_identity()
    }

    /// Consume this authority and bind it to a descriptor-reopened packet while
    /// rechecking the retained campaign/V2-positive/V2-lineage join.
    pub(crate) fn rebind_postcommit_semantically_reopened_packet_v2(
        mut self,
        campaign: &B4CampaignPrecommitAuthorityV1,
        packet: B4VerifiedTerminalEvidencePacketV1,
    ) -> Result<Self> {
        let retained_identity = self.packet.identity();
        let retained_replay_identity = self.replay.packet_identity;
        let retained_packet_id = hex::encode(retained_identity.packet_id());
        let retained_replay_packet_id = hex::encode(retained_replay_identity.packet_id());
        require_terminal_packet_identity_binding(
            retained_identity.manifest_byte_length(),
            &retained_packet_id,
            retained_replay_identity.manifest_byte_length(),
            &retained_replay_packet_id,
        )
        .context("retained V2 lineaged authority replay identity drifted from its packet")?;

        let reopened_identity = packet.identity();
        let reopened_packet_id = hex::encode(reopened_identity.packet_id());
        require_terminal_packet_identity_binding(
            retained_identity.manifest_byte_length(),
            &retained_packet_id,
            reopened_identity.manifest_byte_length(),
            &reopened_packet_id,
        )
        .context("post-commit packet identity differs from the V2 generation-time publication")?;
        let replay = replay_b4_terminal_evidence_sources(&packet)
            .context("post-commit V2 packet failed semantic source replay")?;
        self.lineage
            .verify_authority_bindings(campaign, &self.positive)
            .context("post-commit V2 lineage differs from its retained live authorities")?;
        require_official_lineage_binding_v2(&packet, &self.lineage)
            .context("post-commit packet differs from its still-live V2 official source lineage")?;

        self.packet = packet;
        self.replay = replay;
        Ok(self)
    }
}

/// Opaque, single-use in-memory preparation for one lineaged packet publication.
///
/// This value carries no destination, filesystem capability, authority token,
/// public projection, serializer, or resume surface. Publication consumes it
/// by value.
pub(crate) struct B4PreparedLineagedTerminalEvidencePacketV1 {
    profile: B4AuthenticatedCompiledTerminalEvidenceProfileV1,
    authenticated: B4AuthenticatedTerminalFixtureSourcesV1,
    generated: B4GeneratedTerminalFixtureSetV1,
    direct: B4Case8FinalJoinDirectEvidenceV1,
    lineage: B4TerminalSourceLineageAuthorityV1,
}

/// Opaque single-use preparation retaining both V2 affine predecessors.
pub(crate) struct B4PreparedLineagedTerminalEvidencePacketV2 {
    profile: B4AuthenticatedCompiledTerminalEvidenceProfileV1,
    authenticated: B4AuthenticatedTerminalFixtureSourcesV1,
    generated: B4GeneratedTerminalFixtureSetV1,
    direct: B4Case8FinalJoinDirectEvidenceV1,
    positive: B4PositiveGenerationAuthorityV2,
    lineage: B4TerminalSourceLineageAuthorityV2,
}

/// Prepare one official-lineage packet entirely in memory.
///
/// # Errors
///
/// Returns an error for source-lineage, profile, generation, or direct-pair
/// non-substitution failure. This phase accepts no destination and performs no
/// campaign-filesystem operation or authority construction.
pub(crate) fn prepare_lineaged_b4_terminal_evidence_packet(
    prover: &LocalProver,
    lineage: B4TerminalSourceLineageAuthorityV1,
) -> Result<B4PreparedLineagedTerminalEvidencePacketV1> {
    let prepared_sources = authenticate_lineaged_b4_terminal_sources(&lineage)
        .context("cannot authenticate official terminal-source lineage")?;
    let profile =
        authenticate_compiled_terminal_evidence_profile(prepared_sources.sources().statement())
            .context("official terminal sources do not bind the compiled profile")?;
    let composition = compose_authenticated_b4_terminal_fixture_set(
        prover,
        prepared_sources.into_authenticated(),
    )
    .context("cannot compose the fixed terminal-fixture set")?;
    let (authenticated, generated, direct) = composition.into_parts();
    require_case8_direct_non_substitution(&generated, &direct)
        .context("case-8 direct evidence aliases a generated terminal fixture")?;

    Ok(B4PreparedLineagedTerminalEvidencePacketV1 {
        profile,
        authenticated,
        generated,
        direct,
        lineage,
    })
}

/// Prepare one V2-authorized official-lineage packet entirely in memory.
///
/// # Errors
///
/// Returns an error unless the independently retained lineage still matches
/// both the campaign and consumed V2 positive-generation authority before any
/// proof work completes, or if profile/generation/direct-pair checks fail.
pub(crate) fn prepare_lineaged_b4_terminal_evidence_packet_v2(
    prover: &LocalProver,
    campaign: &B4CampaignPrecommitAuthorityV1,
    positive: B4PositiveGenerationAuthorityV2,
    lineage: B4TerminalSourceLineageAuthorityV2,
) -> Result<B4PreparedLineagedTerminalEvidencePacketV2> {
    let prepared_sources =
        authenticate_lineaged_b4_terminal_sources_v2(campaign, &positive, &lineage)
            .context("cannot authenticate live V2 official terminal-source lineage")?;
    let profile =
        authenticate_compiled_terminal_evidence_profile(prepared_sources.sources().statement())
            .context("V2 official terminal sources do not bind the compiled profile")?;
    let composition = compose_authenticated_b4_terminal_fixture_set(
        prover,
        prepared_sources.into_authenticated(),
    )
    .context("cannot compose the fixed V2-lineaged terminal-fixture set")?;
    let (authenticated, generated, direct) = composition.into_parts();
    require_case8_direct_non_substitution(&generated, &direct)
        .context("V2 case-8 direct evidence aliases a generated terminal fixture")?;

    Ok(B4PreparedLineagedTerminalEvidencePacketV2 {
        profile,
        authenticated,
        generated,
        direct,
        positive,
        lineage,
    })
}

/// Publish one prepared packet after repeating live destination preflight.
///
/// # Errors
///
/// Returns an error for live preflight, publication, generation binding,
/// semantic replay, or official-lineage mismatch. This is the sole constructor
/// for [`B4PublishedLineagedTerminalEvidenceAuthorityV1`].
pub(crate) fn publish_prepared_lineaged_b4_terminal_evidence_packet(
    destination: &Path,
    prepared: B4PreparedLineagedTerminalEvidencePacketV1,
) -> Result<B4PublishedLineagedTerminalEvidenceAuthorityV1> {
    run_after_publication_preflight(destination, || {
        let packet = publish_prepared_b4_terminal_evidence_payloads(destination, &prepared)?;
        complete_prepared_lineaged_publication(packet, prepared)
    })
}

/// Publish one V2-authorized prepared packet after repeating live destination
/// and authority preflight.
pub(crate) fn publish_prepared_lineaged_b4_terminal_evidence_packet_v2(
    destination: &Path,
    campaign: &B4CampaignPrecommitAuthorityV1,
    prepared: B4PreparedLineagedTerminalEvidencePacketV2,
) -> Result<B4PublishedLineagedTerminalEvidenceAuthorityV2> {
    run_after_publication_preflight(destination, || {
        prepared
            .lineage
            .verify_authority_bindings(campaign, &prepared.positive)
            .context("V2 lineage changed before terminal-evidence publication")?;
        let packet = publish_prepared_b4_terminal_evidence_payloads_v2(destination, &prepared)?;
        complete_prepared_lineaged_publication_v2(packet, campaign, prepared)
    })
}

/// Publish one prepared packet relative to an already-retained parent directory.
///
/// This is the E2 nested-publication route. It consumes the same prepared
/// value and reaches the same binding/authority constructor as the standalone
/// pathname route, but never resolves the parent through a pathname.
#[cfg(unix)]
pub(crate) fn publish_prepared_lineaged_b4_terminal_evidence_packet_from_directory_descriptor(
    parent: BorrowedFd<'_>,
    final_component: &str,
    prepared: B4PreparedLineagedTerminalEvidencePacketV1,
) -> Result<B4PublishedLineagedTerminalEvidenceAuthorityV1> {
    preflight_b4_terminal_evidence_publication_from_directory_descriptor(parent, final_component)
        .context("descriptor-rooted terminal-evidence live preflight failed")?;
    let payloads = prepared_b4_terminal_evidence_payloads(&prepared)?;
    let packet = publish_b4_terminal_evidence_packet_from_directory_descriptor(
        parent,
        final_component,
        payloads,
    )
    .context("cannot publish and fully reopen the descriptor-rooted terminal-evidence packet")?;
    complete_prepared_lineaged_publication(packet, prepared)
}

/// Publish one V2-authorized prepared packet relative to an already-retained
/// parent directory, retaining and consuming both affine predecessors.
#[cfg(unix)]
pub(crate) fn publish_prepared_lineaged_b4_terminal_evidence_packet_from_directory_descriptor_v2(
    parent: BorrowedFd<'_>,
    final_component: &str,
    campaign: &B4CampaignPrecommitAuthorityV1,
    prepared: B4PreparedLineagedTerminalEvidencePacketV2,
) -> Result<B4PublishedLineagedTerminalEvidenceAuthorityV2> {
    preflight_b4_terminal_evidence_publication_from_directory_descriptor(parent, final_component)
        .context("descriptor-rooted V2 terminal-evidence live preflight failed")?;
    prepared
        .lineage
        .verify_authority_bindings(campaign, &prepared.positive)
        .context("V2 lineage changed before descriptor-rooted publication")?;
    let payloads = prepared_b4_terminal_evidence_payloads_v2(&prepared)?;
    let packet = publish_b4_terminal_evidence_packet_from_directory_descriptor(
        parent,
        final_component,
        payloads,
    )
    .context("cannot publish and fully reopen the descriptor-rooted V2 terminal packet")?;
    complete_prepared_lineaged_publication_v2(packet, campaign, prepared)
}

fn complete_prepared_lineaged_publication(
    packet: B4VerifiedTerminalEvidencePacketV1,
    prepared: B4PreparedLineagedTerminalEvidencePacketV1,
) -> Result<B4PublishedLineagedTerminalEvidenceAuthorityV1> {
    require_generation_binding(&packet, &prepared.authenticated, &prepared.direct)
        .context("published packet differs from the generating composition")?;
    let replay = replay_b4_terminal_evidence_sources(&packet)
        .context("generation-bound packet failed semantic source replay")?;
    require_official_lineage_binding(&packet, &prepared.lineage)
        .context("published packet differs from its live official source lineage")?;
    let B4PreparedLineagedTerminalEvidencePacketV1 { lineage, .. } = prepared;
    Ok(B4PublishedLineagedTerminalEvidenceAuthorityV1 {
        packet,
        replay,
        lineage,
    })
}

fn complete_prepared_lineaged_publication_v2(
    packet: B4VerifiedTerminalEvidencePacketV1,
    campaign: &B4CampaignPrecommitAuthorityV1,
    prepared: B4PreparedLineagedTerminalEvidencePacketV2,
) -> Result<B4PublishedLineagedTerminalEvidenceAuthorityV2> {
    require_generation_binding(&packet, &prepared.authenticated, &prepared.direct)
        .context("published V2 packet differs from the generating composition")?;
    let replay = replay_b4_terminal_evidence_sources(&packet)
        .context("generation-bound V2 packet failed semantic source replay")?;
    prepared
        .lineage
        .verify_authority_bindings(campaign, &prepared.positive)
        .context("published V2 packet lost its live campaign/positive lineage join")?;
    require_official_lineage_binding_v2(&packet, &prepared.lineage)
        .context("published packet differs from its still-live V2 official source lineage")?;
    let B4PreparedLineagedTerminalEvidencePacketV2 {
        positive, lineage, ..
    } = prepared;
    Ok(B4PublishedLineagedTerminalEvidenceAuthorityV2 {
        packet,
        replay,
        positive,
        lineage,
    })
}

/// Generate, publish, and bind one terminal-evidence packet to live official lineage.
///
/// # Errors
///
/// Returns an error at the first publication preflight, source-lineage,
/// profile, generation, publication, generation-binding, replay, or final
/// live-lineage mismatch.
pub fn generate_and_publish_lineaged_b4_terminal_evidence_packet(
    prover: &LocalProver,
    lineage: B4TerminalSourceLineageAuthorityV1,
    output_root: &Path,
) -> Result<B4PublishedLineagedTerminalEvidenceAuthorityV1> {
    run_after_publication_preflight(output_root, || {
        let prepared = prepare_lineaged_b4_terminal_evidence_packet(prover, lineage)?;
        publish_prepared_lineaged_b4_terminal_evidence_packet(output_root, prepared)
    })
}

/// Generate and publish one packet from consumed V2 generation and lineage
/// authorities while preserving the V1 packet wire format.
///
/// # Errors
///
/// Returns an error at the first destination, live-authority, source,
/// generation, publication, replay, or post-publication lineage mismatch.
pub fn generate_and_publish_lineaged_b4_terminal_evidence_packet_v2(
    prover: &LocalProver,
    campaign: &B4CampaignPrecommitAuthorityV1,
    positive: B4PositiveGenerationAuthorityV2,
    lineage: B4TerminalSourceLineageAuthorityV2,
    output_root: &Path,
) -> Result<B4PublishedLineagedTerminalEvidenceAuthorityV2> {
    run_after_publication_preflight(output_root, || {
        let prepared =
            prepare_lineaged_b4_terminal_evidence_packet_v2(prover, campaign, positive, lineage)?;
        publish_prepared_lineaged_b4_terminal_evidence_packet_v2(output_root, campaign, prepared)
    })
}

fn run_after_publication_preflight<T>(
    output_root: &Path,
    generate: impl FnOnce() -> Result<T>,
) -> Result<T> {
    preflight_b4_terminal_evidence_publication(output_root)
        .context("terminal-evidence publication preflight failed")?;
    generate()
}

fn publish_prepared_b4_terminal_evidence_payloads(
    destination: &Path,
    prepared: &B4PreparedLineagedTerminalEvidencePacketV1,
) -> Result<B4VerifiedTerminalEvidencePacketV1> {
    let payloads = prepared_b4_terminal_evidence_payloads(prepared)?;
    publish_b4_terminal_evidence_packet(destination, payloads)
        .context("cannot publish and fully reopen the terminal-evidence packet")
}

fn publish_prepared_b4_terminal_evidence_payloads_v2(
    destination: &Path,
    prepared: &B4PreparedLineagedTerminalEvidencePacketV2,
) -> Result<B4VerifiedTerminalEvidencePacketV1> {
    let payloads = prepared_b4_terminal_evidence_payloads_v2(prepared)?;
    publish_b4_terminal_evidence_packet(destination, payloads)
        .context("cannot publish and fully reopen the V2-lineaged terminal-evidence packet")
}

fn prepared_b4_terminal_evidence_payloads(
    prepared: &B4PreparedLineagedTerminalEvidencePacketV1,
) -> Result<B4TerminalEvidencePacketPayloadsV1<'_>> {
    let mut fixture_views = Vec::new();
    fixture_views
        .try_reserve_exact(B4_TERMINAL_FIXTURE_COUNT)
        .context("cannot allocate the fixed terminal fixture payload array")?;
    for layout in B4_TERMINAL_FIXTURE_LAYOUT {
        let raw_path = terminal_fixture_raw_seal_path(layout.fixture_id)?;
        let oracle_path = terminal_fixture_receipt_oracle_path(layout.fixture_id)?;
        fixture_views.push(B4TerminalEvidenceFixturePairPayloadV1::new(
            prepared
                .generated
                .raw_seals()
                .get(&raw_path)
                .context("generated fixture set is missing a fixed raw-seal path")?,
            prepared
                .generated
                .receipt_oracles()
                .get(&oracle_path)
                .context("generated fixture set is missing a fixed receipt-oracle path")?,
        )?);
    }
    let fixtures: [_; B4_TERMINAL_FIXTURE_COUNT] = fixture_views
        .try_into()
        .map_err(|_| anyhow::anyhow!("generated terminal fixture payload count drift"))?;
    B4TerminalEvidencePacketPayloadsV1::new(
        B4TerminalEvidenceProfilePayloadsV1::new(
            prepared.profile.manifest(),
            prepared.profile.algorithm(),
            prepared.profile.constants(),
        )?,
        B4TerminalEvidenceProducerSourcesV1::new(
            prepared.authenticated.guest_elf(),
            prepared.authenticated.statement(),
            prepared.authenticated.lift15_receipt_oracle(),
            prepared.authenticated.terminal_join_recursive_oracle(),
            prepared.authenticated.terminal_resolve_recursive_oracle(),
        )?,
        fixtures,
        prepared.generated.catalogue_jcs(),
        B4TerminalEvidenceDirectPairPayloadV1::new(
            prepared.direct.raw_seal(),
            prepared.direct.receipt_oracle(),
        )?,
    )
}

fn prepared_b4_terminal_evidence_payloads_v2(
    prepared: &B4PreparedLineagedTerminalEvidencePacketV2,
) -> Result<B4TerminalEvidencePacketPayloadsV1<'_>> {
    let mut fixture_views = Vec::new();
    fixture_views
        .try_reserve_exact(B4_TERMINAL_FIXTURE_COUNT)
        .context("cannot allocate the fixed V2 terminal fixture payload array")?;
    for layout in B4_TERMINAL_FIXTURE_LAYOUT {
        let raw_path = terminal_fixture_raw_seal_path(layout.fixture_id)?;
        let oracle_path = terminal_fixture_receipt_oracle_path(layout.fixture_id)?;
        fixture_views.push(B4TerminalEvidenceFixturePairPayloadV1::new(
            prepared
                .generated
                .raw_seals()
                .get(&raw_path)
                .context("V2 generated fixture set is missing a fixed raw-seal path")?,
            prepared
                .generated
                .receipt_oracles()
                .get(&oracle_path)
                .context("V2 generated fixture set is missing a fixed receipt-oracle path")?,
        )?);
    }
    let fixtures: [_; B4_TERMINAL_FIXTURE_COUNT] = fixture_views
        .try_into()
        .map_err(|_| anyhow::anyhow!("V2 generated terminal fixture payload count drift"))?;
    B4TerminalEvidencePacketPayloadsV1::new(
        B4TerminalEvidenceProfilePayloadsV1::new(
            prepared.profile.manifest(),
            prepared.profile.algorithm(),
            prepared.profile.constants(),
        )?,
        B4TerminalEvidenceProducerSourcesV1::new(
            prepared.authenticated.guest_elf(),
            prepared.authenticated.statement(),
            prepared.authenticated.lift15_receipt_oracle(),
            prepared.authenticated.terminal_join_recursive_oracle(),
            prepared.authenticated.terminal_resolve_recursive_oracle(),
        )?,
        fixtures,
        prepared.generated.catalogue_jcs(),
        B4TerminalEvidenceDirectPairPayloadV1::new(
            prepared.direct.raw_seal(),
            prepared.direct.receipt_oracle(),
        )?,
    )
}

fn require_case8_direct_non_substitution(
    generated: &B4GeneratedTerminalFixtureSetV1,
    direct: &B4Case8FinalJoinDirectEvidenceV1,
) -> Result<()> {
    for fixture_id in ["join-povw", "join-unwrap-povw", "allowed-terminal-non-ok"] {
        let raw_path = terminal_fixture_raw_seal_path(fixture_id)?;
        let oracle_path = terminal_fixture_receipt_oracle_path(fixture_id)?;
        ensure!(
            generated
                .raw_seals()
                .get(&raw_path)
                .context("generated fixture set lacks a non-substitution raw-seal role")?
                .as_slice()
                != direct.raw_seal(),
            "case-8 direct raw seal aliases the {fixture_id} fixture"
        );
        ensure!(
            generated
                .receipt_oracles()
                .get(&oracle_path)
                .context("generated fixture set lacks a non-substitution receipt-oracle role")?
                .as_slice()
                != direct.receipt_oracle(),
            "case-8 direct receipt oracle aliases the {fixture_id} fixture"
        );
    }
    Ok(())
}

fn require_generation_binding(
    packet: &B4VerifiedTerminalEvidencePacketV1,
    authenticated: &B4AuthenticatedTerminalFixtureSourcesV1,
    direct: &B4Case8FinalJoinDirectEvidenceV1,
) -> Result<()> {
    let view = packet.source_replay_view();
    ensure!(
        view.guest_elf() == authenticated.guest_elf()
            && view.statement() == authenticated.statement()
            && view.case0_lift15_receipt_oracle() == authenticated.lift15_receipt_oracle()
            && view.case8_terminal_join_recursive_oracle()
                == authenticated.terminal_join_recursive_oracle()
            && view.case9_terminal_resolve_recursive_oracle()
                == authenticated.terminal_resolve_recursive_oracle(),
        "published producer sources differ from the exact generating source"
    );
    let packet_direct = view.case8_direct_pair();
    ensure!(
        packet_direct.raw_seal() == direct.raw_seal()
            && packet_direct.receipt_oracle() == direct.receipt_oracle(),
        "published case-8 direct pair differs from the generated direct evidence"
    );
    Ok(())
}

fn require_official_lineage_binding(
    packet: &B4VerifiedTerminalEvidencePacketV1,
    lineage: &B4TerminalSourceLineageAuthorityV1,
) -> Result<()> {
    let final_view = packet.source_replay_view();
    let official = lineage.producer_source();
    ensure!(
        final_view.guest_elf() == official.guest_elf()
            && final_view.statement() == official.statement()
            && final_view.case0_lift15_receipt_oracle() == official.case0_lift15_receipt_oracle()
            && final_view.case8_terminal_join_recursive_oracle()
                == official.case8_terminal_join_recursive_oracle()
            && final_view.case9_terminal_resolve_recursive_oracle()
                == official.case9_terminal_resolve_recursive_oracle(),
        "final packet producer sources differ from the still-live official lineage"
    );
    Ok(())
}

fn require_official_lineage_binding_v2(
    packet: &B4VerifiedTerminalEvidencePacketV1,
    lineage: &B4TerminalSourceLineageAuthorityV2,
) -> Result<()> {
    let final_view = packet.source_replay_view();
    let official = lineage.producer_source();
    ensure!(
        final_view.guest_elf() == official.guest_elf()
            && final_view.statement() == official.statement()
            && final_view.case0_lift15_receipt_oracle() == official.case0_lift15_receipt_oracle()
            && final_view.case8_terminal_join_recursive_oracle()
                == official.case8_terminal_join_recursive_oracle()
            && final_view.case9_terminal_resolve_recursive_oracle()
                == official.case9_terminal_resolve_recursive_oracle(),
        "final packet producer sources differ from the still-live V2 official lineage"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::fd::BorrowedFd;
    use std::{
        cell::Cell,
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use anyhow::Result;
    #[cfg(feature = "embedded-method")]
    use eip_0045_reproduction::b4_terminal_evidence_packet::{
        preflight_b4_terminal_evidence_publication, project_b4_terminal_evidence_publication_layout,
    };
    use eip_0045_reproduction::{
        b4_campaign_contract::{B4CampaignPrecommitAuthorityV1, B4PositiveGenerationAuthorityV2},
        b4_terminal_evidence_packet::B4VerifiedTerminalEvidencePacketV1,
        b4_terminal_source_lineage::{
            B4TerminalSourceLineageAuthorityV1, B4TerminalSourceLineageAuthorityV2,
        },
    };
    use risc0_zkvm::LocalProver;

    #[cfg(unix)]
    use super::publish_prepared_lineaged_b4_terminal_evidence_packet_from_directory_descriptor;
    use super::{
        B4PreparedLineagedTerminalEvidencePacketV1, B4PreparedLineagedTerminalEvidencePacketV2,
        B4PublishedLineagedTerminalEvidenceAuthorityV1,
        B4PublishedLineagedTerminalEvidenceAuthorityV2, B4ReplayedTerminalEvidenceSourcesV1,
        generate_and_publish_lineaged_b4_terminal_evidence_packet,
        generate_and_publish_lineaged_b4_terminal_evidence_packet_v2,
        prepare_lineaged_b4_terminal_evidence_packet,
        prepare_lineaged_b4_terminal_evidence_packet_v2,
        publish_prepared_lineaged_b4_terminal_evidence_packet, replay_b4_terminal_evidence_sources,
        require_terminal_packet_identity_binding, run_after_publication_preflight,
    };

    #[test]
    fn packet_identity_binding_rejects_id_drift_at_equal_length() {
        assert!(require_terminal_packet_identity_binding(128, "00", 128, "00").is_ok());
        let error = require_terminal_packet_identity_binding(128, "00", 128, "01").unwrap_err();
        assert!(error.to_string().contains("identity fields differ"));
    }

    #[test]
    fn packet_identity_binding_rejects_length_drift_at_equal_id() {
        let error = require_terminal_packet_identity_binding(128, "00", 129, "00").unwrap_err();
        assert!(error.to_string().contains("identity fields differ"));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the E2 opaque-shape and ordered-edge audit remains linear for review"
    )]
    fn e2_private_phase_and_postcommit_rebind_shape_is_closed() {
        let source = include_str!("terminal_evidence_export.rs");
        let production_source = source.split("#[cfg(test)]").next().unwrap();

        let _: fn(
            &LocalProver,
            B4TerminalSourceLineageAuthorityV1,
        ) -> Result<B4PreparedLineagedTerminalEvidencePacketV1> =
            prepare_lineaged_b4_terminal_evidence_packet;
        let _: fn(
            &Path,
            B4PreparedLineagedTerminalEvidencePacketV1,
        ) -> Result<B4PublishedLineagedTerminalEvidenceAuthorityV1> =
            publish_prepared_lineaged_b4_terminal_evidence_packet;
        #[cfg(unix)]
        let _: fn(
            BorrowedFd<'_>,
            &str,
            B4PreparedLineagedTerminalEvidencePacketV1,
        ) -> Result<B4PublishedLineagedTerminalEvidenceAuthorityV1> =
            publish_prepared_lineaged_b4_terminal_evidence_packet_from_directory_descriptor;
        let _: fn(
            B4PublishedLineagedTerminalEvidenceAuthorityV1,
            B4VerifiedTerminalEvidencePacketV1,
        ) -> Result<B4PublishedLineagedTerminalEvidenceAuthorityV1> =
            B4PublishedLineagedTerminalEvidenceAuthorityV1::
                rebind_postcommit_semantically_reopened_packet;

        for required in [
            "pub(crate) struct B4PreparedLineagedTerminalEvidencePacketV1 {",
            "pub(crate) fn prepare_lineaged_b4_terminal_evidence_packet(",
            "pub(crate) fn publish_prepared_lineaged_b4_terminal_evidence_packet(",
            "pub(crate) fn publish_prepared_lineaged_b4_terminal_evidence_packet_from_directory_descriptor(",
            "pub(crate) fn rebind_postcommit_semantically_reopened_packet(",
        ] {
            assert!(
                production_source.contains(required),
                "E2 production shape is missing {required}"
            );
        }

        let prepared_fields: Vec<_> = production_source
            .split("pub(crate) struct B4PreparedLineagedTerminalEvidencePacketV1 {\n")
            .nth(1)
            .unwrap()
            .split("\n}\n\n/// Opaque single-use preparation")
            .next()
            .unwrap()
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(
            prepared_fields,
            [
                "profile: B4AuthenticatedCompiledTerminalEvidenceProfileV1,",
                "authenticated: B4AuthenticatedTerminalFixtureSourcesV1,",
                "generated: B4GeneratedTerminalFixtureSetV1,",
                "direct: B4Case8FinalJoinDirectEvidenceV1,",
                "lineage: B4TerminalSourceLineageAuthorityV1,",
            ]
        );
        for forbidden in [
            "impl B4PreparedLineagedTerminalEvidencePacketV1",
            "impl Clone for B4PreparedLineagedTerminalEvidencePacketV1",
            "impl core::fmt::Debug for B4PreparedLineagedTerminalEvidencePacketV1",
            "Serialize for B4PreparedLineagedTerminalEvidencePacketV1",
            "Deserialize for B4PreparedLineagedTerminalEvidencePacketV1",
        ] {
            assert!(
                !production_source.contains(forbidden),
                "prepared E2 value gained forbidden surface {forbidden}"
            );
        }
        let prepared_declaration = production_source
            .split("/// Opaque, single-use in-memory preparation")
            .nth(1)
            .unwrap()
            .split("/// Prepare one official-lineage")
            .next()
            .unwrap();
        assert!(
            !prepared_declaration.contains("#[derive("),
            "prepared E2 value gained a derived trait surface"
        );

        let preparation_source = production_source
            .split("pub(crate) fn prepare_lineaged_b4_terminal_evidence_packet(")
            .nth(1)
            .unwrap()
            .split("\n}\n\n/// Publish one prepared packet")
            .next()
            .unwrap();
        let preparation_signature = preparation_source.split('{').next().unwrap();
        for forbidden in ["destination", "output_root", "&Path", "PathBuf"] {
            assert!(
                !preparation_signature.contains(forbidden),
                "preparation signature gained campaign-filesystem input {forbidden}"
            );
        }

        let publication_source = production_source
            .split("pub(crate) fn publish_prepared_lineaged_b4_terminal_evidence_packet(")
            .nth(1)
            .unwrap()
            .split("\n}\n\n/// Publish one prepared packet relative")
            .next()
            .unwrap();
        assert!(
            publication_source
                .split('{')
                .nth(1)
                .unwrap()
                .trim_start()
                .starts_with("run_after_publication_preflight(destination, || "),
            "prepared publication no longer begins with live preflight"
        );

        let rebind_source = production_source
            .split("pub(crate) fn rebind_postcommit_semantically_reopened_packet(")
            .nth(1)
            .unwrap()
            .split("\n    }\n}\n\n/// Opaque, affine authority")
            .next()
            .unwrap();
        require_exact_ordered_edges(
            rebind_source,
            &[
                "let retained_identity = self.packet.identity()",
                "let retained_replay_identity = self.replay.packet_identity",
                "let reopened_identity = packet.identity()",
                "replay_b4_terminal_evidence_sources(&packet)",
                "require_official_lineage_binding(&packet, &self.lineage)",
                "self.packet = packet",
                "self.replay = replay",
                "Ok(self)",
            ],
        );
        assert_eq!(
            rebind_source
                .matches("require_terminal_packet_identity_binding(")
                .count(),
            2,
            "retained/replay and retained/reopened identity checks must share one predicate"
        );
    }

    #[test]
    fn retained_campaign_uses_the_reproduction_owned_publication_layout() {
        let source = include_str!("terminal_evidence_export.rs");
        let copied_staging_suffix = [".b4-terminal-evidence-", "publication-staging"].concat();
        let helper_signature = ["fn retained_", "staging_path(destination: &Path)"].concat();
        let next_item = ["struct RetainedPacket", "PayloadBytes"].concat();
        let projector_call = [
            "project_b4_terminal_evidence_",
            "publication_layout(destination)",
        ]
        .concat();
        let staging_getter = [".reserved_", "staging_path()"].concat();
        let helper_start = source.find(&helper_signature).unwrap();
        let helper_tail = &source[helper_start..];
        let helper_end = helper_tail.find(&next_item).unwrap();
        let helper_source = &helper_tail[..helper_end];

        assert!(!source.contains(&copied_staging_suffix));
        assert_eq!(helper_source.matches(&projector_call).count(), 1);
        assert_eq!(helper_source.matches(&staging_getter).count(), 1);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the exact public-surface and ordered-edge audit remains linear for review"
    )]
    fn export_api_and_feature_edges_are_exact() {
        let _: fn(
            &B4VerifiedTerminalEvidencePacketV1,
        ) -> anyhow::Result<B4ReplayedTerminalEvidenceSourcesV1> =
            replay_b4_terminal_evidence_sources;

        let mut feature_block = Vec::new();
        let mut collecting = false;
        for line in include_str!("../Cargo.toml").lines() {
            if line.starts_with("b4-terminal-evidence-export = [") {
                collecting = true;
            }
            if collecting {
                feature_block.push(line.trim());
                if line.trim() == "]" {
                    break;
                }
            }
        }
        assert_eq!(
            feature_block,
            [
                "b4-terminal-evidence-export = [",
                "\"b4-terminal-source-lineage\",",
                "\"eip-0045-reproduction/b4-terminal-evidence-publication\",",
                "]",
            ]
        );

        let lib = include_str!("lib.rs");
        let expected_modules = concat!(
            "#[cfg(feature = \"b4-terminal-evidence-export\")]\n",
            "pub mod terminal_evidence_export;\n",
            "#[cfg(feature = \"b4-terminal-evidence-export\")]\n",
            "mod terminal_evidence_profile;",
        );
        assert!(lib.contains(expected_modules));

        let source = include_str!("terminal_evidence_export.rs");
        let production_source = source.split("#[cfg(test)]").next().unwrap();
        let mut depth = 0_i32;
        let mut public_items = Vec::new();
        for line in production_source.lines() {
            let trimmed = line.trim();
            if depth == 0 && trimmed.starts_with("pub ") {
                public_items.push(trimmed);
            }
            if !trimmed.starts_with("///") {
                depth += i32::try_from(line.matches('{').count()).unwrap();
                depth -= i32::try_from(line.matches('}').count()).unwrap();
                assert!(depth >= 0, "production module brace depth underflow");
            }
        }
        assert_eq!(depth, 0, "production module brace depth drift");
        let production_code: String = production_source
            .lines()
            .filter(|line| !line.trim().starts_with("///"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            public_items,
            [
                "pub struct B4ReplayedTerminalEvidenceSourcesV1 {",
                "pub fn replay_b4_terminal_evidence_sources(",
                "pub struct B4PublishedLineagedTerminalEvidenceAuthorityV1 {",
                "pub struct B4PublishedLineagedTerminalEvidenceAuthorityV2 {",
                "pub fn generate_and_publish_lineaged_b4_terminal_evidence_packet(",
                "pub fn generate_and_publish_lineaged_b4_terminal_evidence_packet_v2(",
            ]
        );
        let replay_fields: Vec<_> = production_source
            .split("pub struct B4ReplayedTerminalEvidenceSourcesV1 {\n")
            .nth(1)
            .unwrap()
            .split("\n}\n\n/// Replay the exact retained")
            .next()
            .unwrap()
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(
            replay_fields,
            ["packet_identity: B4TerminalEvidencePacketIdentityV1,"]
        );
        for forbidden in [
            "#[derive(",
            "impl B4ReplayedTerminalEvidenceSourcesV1",
            "impl Clone for B4ReplayedTerminalEvidenceSourcesV1",
            "impl core::fmt::Debug for B4ReplayedTerminalEvidenceSourcesV1",
            "Serialize for B4ReplayedTerminalEvidenceSourcesV1",
            "Deserialize",
        ] {
            assert!(
                !production_source.contains(forbidden),
                "replay authority declaration gained forbidden surface {forbidden}"
            );
        }
        let replay_constructions: Vec<_> = production_code
            .lines()
            .map(str::trim)
            .filter(|line| {
                line.contains("B4ReplayedTerminalEvidenceSourcesV1 {")
                    && !line.starts_with("pub struct ")
                    && !line.starts_with("impl")
            })
            .collect();
        assert_eq!(
            replay_constructions,
            ["Ok(B4ReplayedTerminalEvidenceSourcesV1 {"],
            "replay authority construction site drift"
        );
        assert!(
            production_source.lines().all(|line| {
                let trimmed = line.trim();
                !trimmed.starts_with("impl")
                    || !trimmed.contains("B4ReplayedTerminalEvidenceSourcesV1")
            }),
            "replay authority gained an implementation surface"
        );
        let authority_fields: Vec<_> = production_source
            .split("pub struct B4PublishedLineagedTerminalEvidenceAuthorityV1 {\n")
            .nth(1)
            .unwrap()
            .split("\n}\n\nimpl B4PublishedLineagedTerminalEvidenceAuthorityV1")
            .next()
            .unwrap()
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(
            authority_fields,
            [
                "packet: B4VerifiedTerminalEvidencePacketV1,",
                "replay: B4ReplayedTerminalEvidenceSourcesV1,",
                "lineage: B4TerminalSourceLineageAuthorityV1,",
            ]
        );
        let lineaged_constructions: Vec<_> = production_code
            .lines()
            .map(str::trim)
            .filter(|line| {
                line.contains("B4PublishedLineagedTerminalEvidenceAuthorityV1 {")
                    && !line.starts_with("pub struct ")
                    && !line.starts_with("impl")
            })
            .collect();
        assert_eq!(
            lineaged_constructions,
            ["Ok(B4PublishedLineagedTerminalEvidenceAuthorityV1 {"],
            "lineaged authority construction site drift"
        );
        let authority_public_members: Vec<_> = production_source
            .split("impl B4PublishedLineagedTerminalEvidenceAuthorityV1 {\n")
            .nth(1)
            .unwrap()
            .split("\n}\n\n/// Opaque, affine authority")
            .next()
            .unwrap()
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("pub "))
            .collect();
        assert_eq!(
            authority_public_members,
            ["pub fn identity(&self) -> B4TerminalEvidencePacketIdentityV1 {"]
        );
        let authority_impl_headers: Vec<_> = production_source
            .lines()
            .map(str::trim)
            .filter(|line| {
                line.starts_with("impl")
                    && line.contains("B4PublishedLineagedTerminalEvidenceAuthorityV1")
            })
            .collect();
        assert_eq!(
            authority_impl_headers,
            ["impl B4PublishedLineagedTerminalEvidenceAuthorityV1 {"]
        );
        for forbidden in [
            "impl Clone for B4PublishedLineagedTerminalEvidenceAuthorityV1",
            "impl core::fmt::Debug for B4PublishedLineagedTerminalEvidenceAuthorityV1",
            "Serialize for B4PublishedLineagedTerminalEvidenceAuthorityV1",
            "Deserialize",
        ] {
            assert!(
                !production_source.contains(forbidden),
                "published lineage authority gained forbidden trait surface {forbidden}"
            );
        }
        let replay_source = production_source
            .split("pub fn replay_b4_terminal_evidence_sources(")
            .nth(1)
            .unwrap()
            .split("/// Opaque authority for one lineaged")
            .next()
            .unwrap();
        for required in [
            "packet.source_replay_view()",
            "authenticate_compiled_terminal_evidence_profile(view.statement())",
            "authenticate_b4_terminal_fixture_sources(",
            "view.guest_elf()",
            "view.case0_lift15_receipt_oracle()",
            "view.case8_terminal_join_recursive_oracle()",
            "view.case9_terminal_resolve_recursive_oracle()",
            "derive_case8_final_join_direct_evidence(&authenticated)",
            "view.case8_direct_pair()",
            "packet.identity()",
        ] {
            assert!(
                replay_source.contains(required),
                "source replay omitted fixed call-graph edge {required}",
            );
        }
        for forbidden in [
            "LocalProver",
            "generate_b4_terminal_fixture_set",
            "B4TerminalSourceLineageAuthorityV1",
            "pub fn new(",
            "pub fn payload",
            "pub fn source",
            "pub fn packet",
            "impl Clone for B4ReplayedTerminalEvidenceSourcesV1",
            "impl core::fmt::Debug for B4ReplayedTerminalEvidenceSourcesV1",
            "Serialize for B4ReplayedTerminalEvidenceSourcesV1",
            "Deserialize",
            "#[derive(",
        ] {
            assert!(
                !replay_source.contains(forbidden),
                "export API gained forbidden surface {forbidden}",
            );
        }
        assert!(production_source.contains("run_after_publication_preflight(output_root, ||"));
        assert!(production_source.contains("require_case8_direct_non_substitution("));
        assert!(production_source.contains("require_generation_binding("));
        assert!(production_source.contains("require_official_lineage_binding("));
        assert!(
            !production_source.contains("generate_b4_terminal_fixture_set"),
            "export module bypasses the single authenticated composition path"
        );

        let wrapper_source = production_source
            .split("pub fn generate_and_publish_lineaged_b4_terminal_evidence_packet(")
            .nth(1)
            .unwrap()
            .split("/// Generate and publish one packet from consumed V2")
            .next()
            .unwrap();
        let wrapper_edges = [
            "run_after_publication_preflight(output_root, ||",
            "prepare_lineaged_b4_terminal_evidence_packet(prover, lineage)",
            "publish_prepared_lineaged_b4_terminal_evidence_packet(output_root, prepared)",
        ];
        require_exact_ordered_edges(wrapper_source, &wrapper_edges);

        let preparation_source = production_source
            .split("pub(crate) fn prepare_lineaged_b4_terminal_evidence_packet(")
            .nth(1)
            .unwrap()
            .split("/// Prepare one V2-authorized official-lineage packet")
            .next()
            .unwrap();
        let preparation_edges = [
            "authenticate_lineaged_b4_terminal_sources(&lineage)",
            "authenticate_compiled_terminal_evidence_profile(prepared_sources.sources().statement())",
            "compose_authenticated_b4_terminal_fixture_set(",
            "prepared_sources.into_authenticated()",
            "composition.into_parts()",
            "require_case8_direct_non_substitution(&generated, &direct)",
            "Ok(B4PreparedLineagedTerminalEvidencePacketV1 {",
        ];
        require_exact_ordered_edges(preparation_source, &preparation_edges);

        let publication_source = production_source
            .split("pub(crate) fn publish_prepared_lineaged_b4_terminal_evidence_packet(")
            .nth(1)
            .unwrap()
            .split("\n}\n\n/// Publish one prepared packet relative")
            .next()
            .unwrap();
        let publication_edges = [
            "run_after_publication_preflight(destination, ||",
            "publish_prepared_b4_terminal_evidence_payloads(destination, &prepared)",
            "complete_prepared_lineaged_publication(packet, prepared)",
        ];
        require_exact_ordered_edges(publication_source, &publication_edges);

        let completion_source = production_source
            .split("fn complete_prepared_lineaged_publication(")
            .nth(1)
            .unwrap()
            .split("\n}\n\n/// Generate, publish")
            .next()
            .unwrap();
        require_exact_ordered_edges(
            completion_source,
            &[
                "require_generation_binding(&packet, &prepared.authenticated, &prepared.direct)",
                "replay_b4_terminal_evidence_sources(&packet)",
                "require_official_lineage_binding(&packet, &prepared.lineage)",
                "Ok(B4PublishedLineagedTerminalEvidenceAuthorityV1 {",
            ],
        );

        let pathname_payload_source = production_source
            .split("fn publish_prepared_b4_terminal_evidence_payloads(")
            .nth(1)
            .unwrap()
            .split("\nfn prepared_b4_terminal_evidence_payloads(")
            .next()
            .unwrap();
        require_exact_ordered_edges(
            pathname_payload_source,
            &[
                "prepared_b4_terminal_evidence_payloads(prepared)",
                "publish_b4_terminal_evidence_packet(destination, payloads)",
            ],
        );

        let payload_source = production_source
            .split("fn prepared_b4_terminal_evidence_payloads(")
            .nth(1)
            .unwrap()
            .split("\nfn require_case8_direct_non_substitution(")
            .next()
            .unwrap();
        require_exact_ordered_edges(
            payload_source,
            &["B4TerminalEvidencePacketPayloadsV1::new("],
        );

        let descriptor_publication_source = production_source
            .split(
                "pub(crate) fn publish_prepared_lineaged_b4_terminal_evidence_packet_from_directory_descriptor(",
            )
            .nth(1)
            .unwrap()
            .split("\n}\n\nfn complete_prepared_lineaged_publication(")
            .next()
            .unwrap();
        require_exact_ordered_edges(
            descriptor_publication_source,
            &[
                "preflight_b4_terminal_evidence_publication_from_directory_descriptor(",
                "prepared_b4_terminal_evidence_payloads(&prepared)",
                "publish_b4_terminal_evidence_packet_from_directory_descriptor(",
                "complete_prepared_lineaged_publication(packet, prepared)",
            ],
        );
    }

    #[test]
    fn publication_preflight_failure_never_enters_generation() {
        let entered = Cell::new(false);

        #[cfg(unix)]
        {
            let occupied = unique_test_root("occupied");
            fs::create_dir(&occupied).unwrap();
            let result = run_after_publication_preflight(&occupied, || {
                entered.set(true);
                Ok(())
            });
            assert!(result.is_err());
            assert!(!entered.get());
            fs::remove_dir(&occupied).unwrap();

            let dangling = unique_test_root("dangling");
            let missing_target = unique_test_root("missing-target");
            std::os::unix::fs::symlink(&missing_target, &dangling).unwrap();
            assert!(!retained_path_is_absent(&dangling).unwrap());
            assert!(!entered.get());
            fs::remove_file(&dangling).unwrap();
        }

        entered.set(false);
        let unsupported = unsupported_publication_root();
        let result = run_after_publication_preflight(&unsupported, || {
            entered.set(true);
            Ok(())
        });
        assert!(result.is_err());
        assert!(!entered.get());
    }

    #[test]
    fn published_lineage_authority_surface_is_minimal() {
        let _: fn(
            &B4PublishedLineagedTerminalEvidenceAuthorityV1,
        ) -> eip_0045_reproduction::b4_terminal_evidence_packet::B4TerminalEvidencePacketIdentityV1 =
            B4PublishedLineagedTerminalEvidenceAuthorityV1::identity;
        let _: fn(
            &LocalProver,
            B4TerminalSourceLineageAuthorityV1,
            &Path,
        ) -> Result<B4PublishedLineagedTerminalEvidenceAuthorityV1> =
            generate_and_publish_lineaged_b4_terminal_evidence_packet;
        let _: fn(
            &B4PublishedLineagedTerminalEvidenceAuthorityV2,
        ) -> eip_0045_reproduction::b4_terminal_evidence_packet::B4TerminalEvidencePacketIdentityV1 =
            B4PublishedLineagedTerminalEvidenceAuthorityV2::identity;
        let _: fn(
            &LocalProver,
            &B4CampaignPrecommitAuthorityV1,
            B4PositiveGenerationAuthorityV2,
            B4TerminalSourceLineageAuthorityV2,
            &Path,
        ) -> Result<B4PublishedLineagedTerminalEvidenceAuthorityV2> =
            generate_and_publish_lineaged_b4_terminal_evidence_packet_v2;
    }

    #[test]
    fn v2_publication_retains_both_affine_authorities_and_preserves_v1_wire_payloads() {
        let _: fn(
            &LocalProver,
            &B4CampaignPrecommitAuthorityV1,
            B4PositiveGenerationAuthorityV2,
            B4TerminalSourceLineageAuthorityV2,
        ) -> Result<B4PreparedLineagedTerminalEvidencePacketV2> =
            prepare_lineaged_b4_terminal_evidence_packet_v2;

        let source = include_str!("terminal_evidence_export.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let prepared = production
            .split("pub(crate) struct B4PreparedLineagedTerminalEvidencePacketV2 {")
            .nth(1)
            .unwrap()
            .split("\n}")
            .next()
            .unwrap();
        assert!(prepared.contains("positive: B4PositiveGenerationAuthorityV2,"));
        assert!(prepared.contains("lineage: B4TerminalSourceLineageAuthorityV2,"));
        let published = production
            .split("pub struct B4PublishedLineagedTerminalEvidenceAuthorityV2 {")
            .nth(1)
            .unwrap()
            .split("\n}")
            .next()
            .unwrap();
        assert!(published.contains("positive: B4PositiveGenerationAuthorityV2,"));
        assert!(published.contains("lineage: B4TerminalSourceLineageAuthorityV2,"));

        let v2_path = production
            .split("pub(crate) fn prepare_lineaged_b4_terminal_evidence_packet_v2(")
            .nth(1)
            .unwrap();
        for required in [
            "authenticate_lineaged_b4_terminal_sources_v2(campaign, &positive, &lineage)",
            ".verify_authority_bindings(campaign, &prepared.positive)",
            "require_official_lineage_binding_v2(&packet, &prepared.lineage)",
            "rebind_postcommit_semantically_reopened_packet_v2",
            "B4TerminalEvidencePacketPayloadsV1::new(",
        ] {
            assert!(v2_path.contains(required), "V2 publication lost {required}");
        }
        for forbidden in [
            "B4TerminalSourceLineageAuthorityV1::",
            "B4PositiveGenerationAuthorityV1::",
            "into_v1",
            "from_v2",
            "#[derive(Clone",
            "Serialize for B4PublishedLineagedTerminalEvidenceAuthorityV2",
        ] {
            assert!(
                !v2_path.contains(forbidden),
                "V2 publication gained {forbidden}"
            );
        }
    }

    fn require_exact_ordered_edges(source: &str, edges: &[&str]) {
        let mut previous = None;
        for edge in edges {
            assert_eq!(
                source.matches(edge).count(),
                1,
                "fixed orchestration edge count drift for {edge}"
            );
            let position = source.find(edge).unwrap();
            if let Some(previous) = previous {
                assert!(
                    previous < position,
                    "fixed orchestration order drift before {edge}"
                );
            }
            previous = Some(position);
        }
    }

    #[cfg(feature = "embedded-method")]
    #[test]
    fn retained_negative_publication_names_pass_layout_projection() {
        let parent = Path::new("proof-output");
        for suffix in [
            "negative-fixture-pair-swap",
            "negative-raw-seal-cross-fixture",
            "negative-receipt-oracle-cross-fixture",
            "negative-catalogue-row-drift",
            "negative-direct-raw-seal-substitution",
            "negative-direct-receipt-oracle-substitution",
            "negative-source-case0",
            "negative-source-case8",
            "negative-source-case9",
        ] {
            let destination = retained_negative_publication_path(parent, "packet", suffix);
            project_b4_terminal_evidence_publication_layout(&destination).unwrap();
        }
    }

    #[cfg(feature = "embedded-method")]
    #[test]
    #[ignore = "replays consumer-negative mutations from an authenticated retained packet"]
    fn retained_consumer_negative_replay_matches_native_boundaries() -> Result<()> {
        use anyhow::{Context as _, ensure};

        let source = std::env::var_os("EIP0045_B4_TERMINAL_EVIDENCE_REPLAY_SOURCE_ROOT")
            .map(PathBuf::from)
            .context("EIP0045_B4_TERMINAL_EVIDENCE_REPLAY_SOURCE_ROOT is required")?;
        let output_stem = std::env::var_os("EIP0045_B4_TERMINAL_EVIDENCE_REPLAY_OUTPUT_ROOT")
            .map(PathBuf::from)
            .context("EIP0045_B4_TERMINAL_EVIDENCE_REPLAY_OUTPUT_ROOT is required")?;
        ensure!(
            source != output_stem,
            "consumer-negative replay source and output stem must differ"
        );
        eip_0045_reproduction::b4_terminal_evidence_packet::reopen_b4_terminal_evidence_packet(
            &source,
        )
        .context("consumer-negative replay source did not reopen")?;

        let name = output_stem
            .file_name()
            .and_then(|value| value.to_str())
            .context("consumer-negative replay output stem needs a UTF-8 final component")?;
        ensure!(
            !name.is_empty()
                && name != "."
                && name != ".."
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
            "consumer-negative replay output stem has a nonportable final component"
        );
        let parent = output_stem
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));

        for mutation in ConsumerInvalidMutation::ALL {
            let suffix = format!("negative-{}", mutation.label());
            let destination = retained_negative_publication_path(parent, name, &suffix);
            project_b4_terminal_evidence_publication_layout(&destination)?;
            ensure!(
                retained_path_is_absent(&destination)?,
                "consumer-negative replay destination is occupied: {}",
                destination.display()
            );
            copy_and_mutate_retained_packet(&source, &destination, mutation)?;
            let Err(error) = eip_0045_reproduction::b4_terminal_evidence_packet::
                reopen_b4_terminal_evidence_packet(&destination)
            else {
                anyhow::bail!(
                    "consumer-negative replay {} unexpectedly reopened",
                    mutation.label()
                );
            };
            eprintln!(
                "EIP0045_B4_CONSUMER_NEGATIVE={} ERROR={error:#}",
                mutation.label()
            );
            require_expected_consumer_rejection(mutation, &error)?;
        }
        Ok(())
    }

    #[cfg(feature = "embedded-method")]
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the sole retained real-proof campaign keeps custody and negative assertions linear"
    )]
    #[ignore = "runs only in the retained isolated Linux campaign"]
    fn real_non_lineage_terminal_evidence_packet_publishes_and_reopens() -> Result<()> {
        run_real_non_lineage_terminal_evidence_campaign()
    }

    #[cfg(feature = "embedded-method")]
    #[allow(
        clippy::too_many_lines,
        reason = "the sole retained campaign keeps proof custody and mutation boundaries linear"
    )]
    fn run_real_non_lineage_terminal_evidence_campaign() -> Result<()> {
        use anyhow::{Context as _, ensure};
        use bincode::Options as _;
        use eip_0045_reproduction::{
            b4_terminal_oracle::replay_fixed_terminal_oracles,
            receipt_oracle_codec::receipt_oracle_bincode_options,
        };
        use risc0_zkvm::compute_image_id;

        use super::require_generation_binding;
        use crate::{
            receipt_oracle_wire::encode_succinct_receipt_oracle,
            recursive::{
                RecursiveFamily, encode_recursive_oracle, generate_recursive_oracle,
                observe_recursive_calibration_shape, prove_same_program_lift_15_assumption,
                validate_terminal_join_source_povw,
            },
            recursive_calibration::{
                RECURSIVE_CALIBRATION_SEGMENT_LIMIT_PO2, derive_recursive_calibration,
            },
            terminal_evidence_profile::authenticate_compiled_terminal_evidence_profile,
            terminal_fixtures::{
                authenticate_b4_terminal_fixture_sources, derive_case8_final_join_direct_evidence,
            },
        };

        ensure!(
            std::env::var_os("RISC0_DEV_MODE").is_none(),
            "RISC0_DEV_MODE must be absent for the retained campaign"
        );
        let roots = RetainedCampaignRoots::from_environment()?;
        roots.require_absent_and_preflight()?;
        eprintln!("EIP0045_B4_PHASE=campaign-preflight:complete");

        let elf = eip_0045_methods::EIP_0045_GUEST_ELF;
        let image_id = compute_image_id(elf)?;
        let profile_id: [u8; 32] =
            hex::decode("23c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383")?
                .try_into()
                .map_err(|_| anyhow::anyhow!("frozen profile ID width drift"))?;
        let mut statement = Vec::new();
        statement.extend_from_slice(eip_0045_reproduction::constants::ERGO_STATEMENT_DOMAIN);
        statement.push(1);
        statement.extend_from_slice(&[0x11; 32]);
        statement.extend_from_slice(&profile_id);
        statement.extend_from_slice(image_id.as_bytes());
        statement.extend_from_slice(&[0x33; 32]);
        statement.extend_from_slice(&0_u32.to_le_bytes());

        let prover = LocalProver::new("eip-0045-terminal-evidence-integration");
        eprintln!("EIP0045_B4_PHASE=lift15:start");
        let lift15 = prove_same_program_lift_15_assumption(&prover, elf, image_id, &statement)?;
        eprintln!("EIP0045_B4_PHASE=lift15:complete");
        let lift15_bytes = receipt_oracle_bincode_options().serialize(&lift15)?;
        let image_bytes: [u8; 32] = image_id.as_bytes().try_into()?;
        let make_oracle = |family: RecursiveFamily| -> Result<_> {
            eprintln!(
                "EIP0045_B4_PHASE=recursive-calibration-{}:start",
                family.as_str()
            );
            let calibration = derive_recursive_calibration(
                elf,
                &image_bytes,
                &statement,
                family.as_str(),
                |iterations| {
                    observe_recursive_calibration_shape(
                        &prover,
                        elf,
                        image_id,
                        &statement,
                        family,
                        RECURSIVE_CALIBRATION_SEGMENT_LIMIT_PO2,
                        iterations,
                    )
                },
            )?;
            eprintln!(
                "EIP0045_B4_PHASE=recursive-calibration-{}:complete",
                family.as_str()
            );
            eprintln!("EIP0045_B4_PHASE=recursive-proof-{}:start", family.as_str());
            let oracle = generate_recursive_oracle(
                &prover,
                elf,
                image_id,
                &statement,
                family,
                &calibration,
            )?;
            eprintln!(
                "EIP0045_B4_PHASE=recursive-proof-{}:complete",
                family.as_str()
            );
            Ok(oracle)
        };
        let join = make_oracle(RecursiveFamily::TerminalJoin)?;
        let resolve = make_oracle(RecursiveFamily::TerminalResolve)?;
        validate_terminal_join_source_povw(&join, image_id, &statement)?;
        let join_bytes = encode_recursive_oracle(&join)?;
        let resolve_bytes = encode_recursive_oracle(&resolve)?;

        let retained_authenticated = authenticate_b4_terminal_fixture_sources(
            elf,
            &statement,
            &lift15_bytes,
            &join_bytes,
            &resolve_bytes,
        )?;
        let retained_direct = derive_case8_final_join_direct_evidence(&retained_authenticated)?;
        let generated_authenticated = authenticate_b4_terminal_fixture_sources(
            elf,
            &statement,
            &lift15_bytes,
            &join_bytes,
            &resolve_bytes,
        )?;
        let profile = authenticate_compiled_terminal_evidence_profile(&statement)?;
        eprintln!("EIP0045_B4_PHASE=terminal-packet-generation:start");
        let published_packet = generate_and_publish_retained_non_lineage_packet(
            &prover,
            generated_authenticated,
            &profile,
            &roots.main,
        )?;
        eprintln!("EIP0045_B4_PHASE=terminal-packet-generation:complete");
        let independently_reopened =
            eip_0045_reproduction::b4_terminal_evidence_packet::reopen_b4_terminal_evidence_packet(
                &roots.main,
            )?;
        let published_identity = published_packet.identity();
        let independent_identity = independently_reopened.identity();
        ensure!(
            published_identity.manifest_byte_length()
                == independent_identity.manifest_byte_length()
                && published_identity.packet_id() == independent_identity.packet_id(),
            "independent final reopen identity differs from the publishing reopen"
        );
        super::replay_b4_terminal_evidence_sources(&independently_reopened)?;

        let pristine = RetainedPacketPayloadBytes::read(&roots.main)?;
        let raw_seals = pristine.fixture_raw_map()?;
        let receipt_oracles = pristine.fixture_oracle_map()?;
        let fixture_replay = replay_fixed_terminal_oracles(&raw_seals, &receipt_oracles)?;
        ensure!(
            fixture_replay.derived_catalogue_jcs()? == pristine.catalogue,
            "retained nine-fixture replay differs from the published catalogue"
        );
        let direct_step2_oracle = encode_succinct_receipt_oracle(&join.steps[2].receipt)?;
        ensure!(
            retained_direct.raw_seal() == join.steps[2].receipt.get_seal_bytes()
                && retained_direct.receipt_oracle() == direct_step2_oracle,
            "retained direct pair is not terminal Join step 2"
        );
        for mutation in ConsumerInvalidMutation::ALL {
            let destination = roots.consumer_root(mutation);
            copy_and_mutate_retained_packet(&roots.main, destination, mutation)?;
            let Err(error) = eip_0045_reproduction::b4_terminal_evidence_packet::
                reopen_b4_terminal_evidence_packet(destination)
            else {
                anyhow::bail!(
                    "consumer-invalid {} retained tree unexpectedly reopened",
                    mutation.label()
                );
            };
            require_expected_consumer_rejection(mutation, &error)?;
        }

        for mutation in ProducerSourceMutation::ALL {
            let destination = roots.producer_root(mutation);
            let mut payloads = RetainedPacketPayloadBytes::read(&roots.main)?;
            mutation.apply(&mut payloads);
            let packet = eip_0045_reproduction::b4_terminal_evidence_packet::
                publish_b4_terminal_evidence_packet(destination, payloads.packet_payloads()?)
                .with_context(|| {
                    format!(
                        "consumer-valid {} source mutation failed public publication",
                        mutation.label()
                    )
                })?;
            let mutation_identity = packet.identity();
            ensure!(
                mutation_identity.manifest_byte_length()
                    != published_identity.manifest_byte_length()
                    || mutation_identity.packet_id() != published_identity.packet_id(),
                "{} source mutation retained the pristine packet identity",
                mutation.label()
            );
            ensure!(
                require_generation_binding(&packet, &retained_authenticated, &retained_direct)
                    .is_err(),
                "{} source mutation reached generation-bound authority",
                mutation.label()
            );
            ensure!(
                super::replay_b4_terminal_evidence_sources(&packet).is_err(),
                "{} source mutation reached semantic source-replay authority",
                mutation.label()
            );
        }
        Ok(())
    }

    #[cfg(feature = "embedded-method")]
    fn generate_and_publish_retained_non_lineage_packet(
        prover: &LocalProver,
        authenticated: crate::terminal_fixtures::B4AuthenticatedTerminalFixtureSourcesV1,
        profile: &crate::terminal_evidence_profile::B4AuthenticatedCompiledTerminalEvidenceProfileV1,
        output_root: &Path,
    ) -> Result<B4VerifiedTerminalEvidencePacketV1> {
        use anyhow::Context as _;
        use eip_0045_reproduction::{
            b4_terminal::{
                B4_TERMINAL_FIXTURE_COUNT, B4_TERMINAL_FIXTURE_LAYOUT,
                terminal_fixture_raw_seal_path, terminal_fixture_receipt_oracle_path,
            },
            b4_terminal_evidence_packet::{
                B4TerminalEvidenceDirectPairPayloadV1, B4TerminalEvidenceFixturePairPayloadV1,
                B4TerminalEvidencePacketPayloadsV1, B4TerminalEvidenceProducerSourcesV1,
                B4TerminalEvidenceProfilePayloadsV1, publish_b4_terminal_evidence_packet,
            },
        };

        eprintln!("EIP0045_B4_PHASE=terminal-fixture-composition:start");
        let composition = crate::terminal_fixtures::compose_authenticated_b4_terminal_fixture_set(
            prover,
            authenticated,
        )?;
        eprintln!("EIP0045_B4_PHASE=terminal-fixture-composition:complete");
        let (authenticated, generated, direct) = composition.into_parts();
        super::require_case8_direct_non_substitution(&generated, &direct)?;

        let mut fixture_views = Vec::new();
        fixture_views.try_reserve_exact(B4_TERMINAL_FIXTURE_COUNT)?;
        for layout in B4_TERMINAL_FIXTURE_LAYOUT {
            let raw_path = terminal_fixture_raw_seal_path(layout.fixture_id)?;
            let oracle_path = terminal_fixture_receipt_oracle_path(layout.fixture_id)?;
            fixture_views.push(B4TerminalEvidenceFixturePairPayloadV1::new(
                generated
                    .raw_seals()
                    .get(&raw_path)
                    .context("generated fixture set is missing a fixed raw-seal path")?,
                generated
                    .receipt_oracles()
                    .get(&oracle_path)
                    .context("generated fixture set is missing a fixed receipt-oracle path")?,
            )?);
        }
        let fixtures: [_; B4_TERMINAL_FIXTURE_COUNT] = fixture_views
            .try_into()
            .map_err(|_| anyhow::anyhow!("generated terminal fixture payload count drift"))?;
        let payloads = B4TerminalEvidencePacketPayloadsV1::new(
            B4TerminalEvidenceProfilePayloadsV1::new(
                profile.manifest(),
                profile.algorithm(),
                profile.constants(),
            )?,
            B4TerminalEvidenceProducerSourcesV1::new(
                authenticated.guest_elf(),
                authenticated.statement(),
                authenticated.lift15_receipt_oracle(),
                authenticated.terminal_join_recursive_oracle(),
                authenticated.terminal_resolve_recursive_oracle(),
            )?,
            fixtures,
            generated.catalogue_jcs(),
            B4TerminalEvidenceDirectPairPayloadV1::new(direct.raw_seal(), direct.receipt_oracle())?,
        )?;
        let packet = publish_b4_terminal_evidence_packet(output_root, payloads)?;
        super::require_generation_binding(&packet, &authenticated, &direct)?;
        super::replay_b4_terminal_evidence_sources(&packet)?;
        Ok(packet)
    }

    #[cfg(feature = "embedded-method")]
    struct RetainedCampaignRoots {
        main: PathBuf,
        reserved_staging: [PathBuf; 4],
        consumer_invalid: [PathBuf; 6],
        producer_invalid: [PathBuf; 3],
    }

    #[cfg(feature = "embedded-method")]
    impl RetainedCampaignRoots {
        fn from_environment() -> Result<Self> {
            use anyhow::{Context as _, ensure};

            let main = std::env::var_os("EIP0045_B4_TERMINAL_EVIDENCE_OUTPUT_ROOT")
                .map(PathBuf::from)
                .context("EIP0045_B4_TERMINAL_EVIDENCE_OUTPUT_ROOT is required")?;
            let name = main
                .file_name()
                .and_then(|value| value.to_str())
                .context("terminal-evidence output root needs a UTF-8 final component")?;
            ensure!(
                !name.is_empty()
                    && name != "."
                    && name != ".."
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
                "terminal-evidence output root has a nonportable final component"
            );
            let parent = main
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let negative = |suffix: &str| retained_negative_publication_path(parent, name, suffix);
            let consumer_invalid = [
                negative("negative-fixture-pair-swap"),
                negative("negative-raw-seal-cross-fixture"),
                negative("negative-receipt-oracle-cross-fixture"),
                negative("negative-catalogue-row-drift"),
                negative("negative-direct-raw-seal-substitution"),
                negative("negative-direct-receipt-oracle-substitution"),
            ];
            let producer_invalid = [
                negative("negative-source-case0"),
                negative("negative-source-case8"),
                negative("negative-source-case9"),
            ];
            let reserved_staging = [
                retained_staging_path(&main)?,
                retained_staging_path(&producer_invalid[0])?,
                retained_staging_path(&producer_invalid[1])?,
                retained_staging_path(&producer_invalid[2])?,
            ];
            let roots = Self {
                main,
                reserved_staging,
                consumer_invalid,
                producer_invalid,
            };
            let all: Vec<_> = std::iter::once(&roots.main)
                .chain(roots.consumer_invalid.iter())
                .chain(roots.producer_invalid.iter())
                .chain(roots.reserved_staging.iter())
                .collect();
            let unique: std::collections::BTreeSet<_> = all.iter().copied().collect();
            ensure!(
                all.len() == 14 && unique.len() == 14,
                "retained campaign root table contains a collision"
            );
            Ok(roots)
        }

        fn require_absent_and_preflight(&self) -> Result<()> {
            use anyhow::{Context as _, ensure};

            for path in std::iter::once(&self.main)
                .chain(self.consumer_invalid.iter())
                .chain(self.producer_invalid.iter())
                .chain(self.reserved_staging.iter())
            {
                ensure!(
                    retained_path_is_absent(path)?,
                    "retained campaign root is already occupied: {}",
                    path.display()
                );
            }

            fs::create_dir(&self.reserved_staging[0]).with_context(|| {
                format!(
                    "cannot create disposable staging-collision probe {}",
                    self.reserved_staging[0].display()
                )
            })?;
            let collision_rejected =
                preflight_b4_terminal_evidence_publication(&self.main).is_err();
            fs::remove_dir(&self.reserved_staging[0]).with_context(|| {
                format!(
                    "cannot remove disposable staging-collision probe {}",
                    self.reserved_staging[0].display()
                )
            })?;
            ensure!(
                collision_rejected,
                "publication preflight accepted its reserved staging sibling"
            );

            for destination in std::iter::once(&self.main).chain(self.producer_invalid.iter()) {
                preflight_b4_terminal_evidence_publication(destination).with_context(|| {
                    format!(
                        "retained campaign publication preflight failed for {}",
                        destination.display()
                    )
                })?;
            }
            Ok(())
        }

        fn consumer_root(&self, mutation: ConsumerInvalidMutation) -> &Path {
            &self.consumer_invalid[mutation.index()]
        }

        fn producer_root(&self, mutation: ProducerSourceMutation) -> &Path {
            &self.producer_invalid[mutation.index()]
        }
    }

    #[cfg(feature = "embedded-method")]
    fn retained_negative_publication_path(parent: &Path, name: &str, suffix: &str) -> PathBuf {
        parent.join(format!("{name}.{suffix}"))
    }

    #[cfg(test)]
    fn retained_path_is_absent(path: &Path) -> Result<bool> {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error.into()),
            Ok(_) => Ok(false),
        }
    }

    #[cfg(feature = "embedded-method")]
    fn retained_staging_path(destination: &Path) -> Result<PathBuf> {
        Ok(
            project_b4_terminal_evidence_publication_layout(destination)?
                .reserved_staging_path()
                .to_path_buf(),
        )
    }

    #[cfg(feature = "embedded-method")]
    struct RetainedPacketPayloadBytes {
        manifest: Vec<u8>,
        algorithm: Vec<u8>,
        constants: Vec<u8>,
        guest_elf: Vec<u8>,
        statement: Vec<u8>,
        case0_lift15_receipt_oracle: Vec<u8>,
        case8_terminal_join_recursive_oracle: Vec<u8>,
        case9_terminal_resolve_recursive_oracle: Vec<u8>,
        fixtures: [(Vec<u8>, Vec<u8>); super::B4_TERMINAL_FIXTURE_COUNT],
        catalogue: Vec<u8>,
        case8_direct_raw_seal: Vec<u8>,
        case8_direct_receipt_oracle: Vec<u8>,
    }

    #[cfg(feature = "embedded-method")]
    impl RetainedPacketPayloadBytes {
        fn read(root: &Path) -> Result<Self> {
            let mut fixtures = Vec::new();
            fixtures.try_reserve_exact(super::B4_TERMINAL_FIXTURE_COUNT)?;
            for layout in super::B4_TERMINAL_FIXTURE_LAYOUT {
                fixtures.push((
                    read_packet_file(
                        root,
                        &super::terminal_fixture_raw_seal_path(layout.fixture_id)?,
                    )?,
                    read_packet_file(
                        root,
                        &super::terminal_fixture_receipt_oracle_path(layout.fixture_id)?,
                    )?,
                ));
            }
            Ok(Self {
                manifest: read_packet_file(root, "profiles/risc0-v3-succinct/manifest.bin")?,
                algorithm: read_packet_file(root, "profiles/risc0-v3-succinct/algorithm.txt")?,
                constants: read_packet_file(root, "profiles/risc0-v3-succinct/constants.bin")?,
                guest_elf: read_packet_file(root, "sources/guest.elf")?,
                statement: read_packet_file(root, "sources/statement.bin")?,
                case0_lift15_receipt_oracle: read_packet_file(
                    root,
                    "sources/case-0-lift-15.receipt-oracle.bincode",
                )?,
                case8_terminal_join_recursive_oracle: read_packet_file(
                    root,
                    "sources/case-8-terminal-join.recursive-oracle.borsh",
                )?,
                case9_terminal_resolve_recursive_oracle: read_packet_file(
                    root,
                    "sources/case-9-terminal-resolve.recursive-oracle.borsh",
                )?,
                fixtures: fixtures
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("retained terminal fixture count drift"))?,
                catalogue: read_packet_file(
                    root,
                    "reproduction/schema/b4-corpus-v1.candidate/bindings/terminal-fixture-catalog.json",
                )?,
                case8_direct_raw_seal: read_packet_file(
                    root,
                    "derived/case-8-terminal-join-final.raw-seal.bin",
                )?,
                case8_direct_receipt_oracle: read_packet_file(
                    root,
                    "derived/case-8-terminal-join-final.receipt-oracle.bincode",
                )?,
            })
        }

        fn packet_payloads(
            &self,
        ) -> Result<
            eip_0045_reproduction::b4_terminal_evidence_packet::B4TerminalEvidencePacketPayloadsV1<
                '_,
            >,
        > {
            use eip_0045_reproduction::b4_terminal_evidence_packet::{
                B4TerminalEvidenceDirectPairPayloadV1, B4TerminalEvidenceFixturePairPayloadV1,
                B4TerminalEvidencePacketPayloadsV1, B4TerminalEvidenceProducerSourcesV1,
                B4TerminalEvidenceProfilePayloadsV1,
            };

            let mut fixtures = Vec::new();
            fixtures.try_reserve_exact(super::B4_TERMINAL_FIXTURE_COUNT)?;
            for (raw_seal, receipt_oracle) in &self.fixtures {
                fixtures.push(B4TerminalEvidenceFixturePairPayloadV1::new(
                    raw_seal,
                    receipt_oracle,
                )?);
            }
            B4TerminalEvidencePacketPayloadsV1::new(
                B4TerminalEvidenceProfilePayloadsV1::new(
                    &self.manifest,
                    &self.algorithm,
                    &self.constants,
                )?,
                B4TerminalEvidenceProducerSourcesV1::new(
                    &self.guest_elf,
                    &self.statement,
                    &self.case0_lift15_receipt_oracle,
                    &self.case8_terminal_join_recursive_oracle,
                    &self.case9_terminal_resolve_recursive_oracle,
                )?,
                fixtures
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("borrowed terminal fixture count drift"))?,
                &self.catalogue,
                B4TerminalEvidenceDirectPairPayloadV1::new(
                    &self.case8_direct_raw_seal,
                    &self.case8_direct_receipt_oracle,
                )?,
            )
        }

        fn fixture_raw_map(&self) -> Result<std::collections::BTreeMap<String, Vec<u8>>> {
            let mut map = std::collections::BTreeMap::new();
            for (layout, pair) in super::B4_TERMINAL_FIXTURE_LAYOUT.iter().zip(&self.fixtures) {
                map.insert(
                    super::terminal_fixture_raw_seal_path(layout.fixture_id)?,
                    pair.0.clone(),
                );
            }
            Ok(map)
        }

        fn fixture_oracle_map(&self) -> Result<std::collections::BTreeMap<String, Vec<u8>>> {
            let mut map = std::collections::BTreeMap::new();
            for (layout, pair) in super::B4_TERMINAL_FIXTURE_LAYOUT.iter().zip(&self.fixtures) {
                map.insert(
                    super::terminal_fixture_receipt_oracle_path(layout.fixture_id)?,
                    pair.1.clone(),
                );
            }
            Ok(map)
        }
    }

    #[cfg(feature = "embedded-method")]
    #[derive(Clone, Copy)]
    enum ProducerSourceMutation {
        Case0,
        Case8,
        Case9,
    }

    #[cfg(feature = "embedded-method")]
    impl ProducerSourceMutation {
        const ALL: [Self; 3] = [Self::Case0, Self::Case8, Self::Case9];

        const fn index(self) -> usize {
            match self {
                Self::Case0 => 0,
                Self::Case8 => 1,
                Self::Case9 => 2,
            }
        }

        const fn label(self) -> &'static str {
            match self {
                Self::Case0 => "case-0",
                Self::Case8 => "case-8",
                Self::Case9 => "case-9",
            }
        }

        fn apply(self, payloads: &mut RetainedPacketPayloadBytes) {
            let bytes = match self {
                Self::Case0 => &mut payloads.case0_lift15_receipt_oracle,
                Self::Case8 => &mut payloads.case8_terminal_join_recursive_oracle,
                Self::Case9 => &mut payloads.case9_terminal_resolve_recursive_oracle,
            };
            flip_first(bytes);
        }
    }

    #[cfg(feature = "embedded-method")]
    #[derive(Clone, Copy)]
    enum ConsumerInvalidMutation {
        FixturePairSwap,
        RawSealCrossFixture,
        ReceiptOracleCrossFixture,
        CatalogueRowDrift,
        DirectRawSealSubstitution,
        DirectReceiptOracleSubstitution,
    }

    #[cfg(feature = "embedded-method")]
    impl ConsumerInvalidMutation {
        const ALL: [Self; 6] = [
            Self::FixturePairSwap,
            Self::RawSealCrossFixture,
            Self::ReceiptOracleCrossFixture,
            Self::CatalogueRowDrift,
            Self::DirectRawSealSubstitution,
            Self::DirectReceiptOracleSubstitution,
        ];

        const fn index(self) -> usize {
            match self {
                Self::FixturePairSwap => 0,
                Self::RawSealCrossFixture => 1,
                Self::ReceiptOracleCrossFixture => 2,
                Self::CatalogueRowDrift => 3,
                Self::DirectRawSealSubstitution => 4,
                Self::DirectReceiptOracleSubstitution => 5,
            }
        }

        const fn label(self) -> &'static str {
            match self {
                Self::FixturePairSwap => "fixture-pair-swap",
                Self::RawSealCrossFixture => "raw-seal-cross-fixture",
                Self::ReceiptOracleCrossFixture => "receipt-oracle-cross-fixture",
                Self::CatalogueRowDrift => "catalogue-row-drift",
                Self::DirectRawSealSubstitution => "direct-raw-seal-substitution",
                Self::DirectReceiptOracleSubstitution => "direct-receipt-oracle-substitution",
            }
        }

        const fn expected_rejection_markers(self) -> &'static [&'static str] {
            match self {
                Self::FixturePairSwap | Self::ReceiptOracleCrossFixture => &[
                    "ReceiptProfileShape for join-povw: receipt control does not match the fixed fixture family",
                ],
                Self::RawSealCrossFixture => &[
                    "ReceiptProfileShape for join-povw: raw-seal artifact is not the exact little-endian receipt seal",
                ],
                Self::CatalogueRowDrift => &["CandidateCatalogueInvalid:"],
                Self::DirectRawSealSubstitution => {
                    &["fixed case-8 positive root failed direct in-memory replay"]
                }
                Self::DirectReceiptOracleSubstitution => {
                    &["fixed case-8 direct stock receipt failed native replay"]
                }
            }
        }
    }

    #[cfg(feature = "embedded-method")]
    fn require_expected_consumer_rejection(
        mutation: ConsumerInvalidMutation,
        error: &anyhow::Error,
    ) -> Result<()> {
        let diagnostic = format!("{error:#}");
        anyhow::ensure!(
            mutation
                .expected_rejection_markers()
                .iter()
                .any(|marker| diagnostic.contains(marker)),
            "{} mutation rejected outside its native semantic boundary: {diagnostic}",
            mutation.label()
        );
        Ok(())
    }

    #[cfg(feature = "embedded-method")]
    fn copy_and_mutate_retained_packet(
        source: &Path,
        destination: &Path,
        mutation: ConsumerInvalidMutation,
    ) -> Result<()> {
        use anyhow::{Context as _, ensure};

        ensure!(
            retained_path_is_absent(destination)?,
            "consumer-invalid destination is already occupied: {}",
            destination.display()
        );
        copy_retained_tree_create_only(source, destination)?;
        match mutation {
            ConsumerInvalidMutation::FixturePairSwap => {
                let left_raw = super::terminal_fixture_raw_seal_path(
                    super::B4_TERMINAL_FIXTURE_LAYOUT[2].fixture_id,
                )?;
                let right_raw = super::terminal_fixture_raw_seal_path(
                    super::B4_TERMINAL_FIXTURE_LAYOUT[4].fixture_id,
                )?;
                let left_oracle = super::terminal_fixture_receipt_oracle_path(
                    super::B4_TERMINAL_FIXTURE_LAYOUT[2].fixture_id,
                )?;
                let right_oracle = super::terminal_fixture_receipt_oracle_path(
                    super::B4_TERMINAL_FIXTURE_LAYOUT[4].fixture_id,
                )?;
                swap_retained_files(destination, &left_raw, &right_raw)?;
                swap_retained_files(destination, &left_oracle, &right_oracle)?;
            }
            ConsumerInvalidMutation::RawSealCrossFixture => {
                substitute_retained_file(
                    destination,
                    &super::terminal_fixture_raw_seal_path(
                        super::B4_TERMINAL_FIXTURE_LAYOUT[2].fixture_id,
                    )?,
                    &super::terminal_fixture_raw_seal_path(
                        super::B4_TERMINAL_FIXTURE_LAYOUT[4].fixture_id,
                    )?,
                )?;
            }
            ConsumerInvalidMutation::ReceiptOracleCrossFixture => {
                substitute_retained_file(
                    destination,
                    &super::terminal_fixture_receipt_oracle_path(
                        super::B4_TERMINAL_FIXTURE_LAYOUT[2].fixture_id,
                    )?,
                    &super::terminal_fixture_receipt_oracle_path(
                        super::B4_TERMINAL_FIXTURE_LAYOUT[4].fixture_id,
                    )?,
                )?;
            }
            ConsumerInvalidMutation::CatalogueRowDrift => {
                let path = destination.join(
                    "reproduction/schema/b4-corpus-v1.candidate/bindings/terminal-fixture-catalog.json",
                );
                let source = fs::read(&path).with_context(|| {
                    format!("cannot read retained catalogue {}", path.display())
                })?;
                let mut value: serde_json::Value =
                    serde_json::from_slice(&source).context("cannot parse retained catalogue")?;
                value["fixtures"][0]["fixtureId"] =
                    serde_json::Value::String("lift-po2-13".to_owned());
                let canonical = eip_0045_reproduction::canonical::canonical_json_bytes(&value)?;
                fs::write(&path, canonical).with_context(|| {
                    format!("cannot write mutated retained catalogue {}", path.display())
                })?;
            }
            ConsumerInvalidMutation::DirectRawSealSubstitution => {
                substitute_retained_file(
                    destination,
                    "derived/case-8-terminal-join-final.raw-seal.bin",
                    &super::terminal_fixture_raw_seal_path("join-povw")?,
                )?;
            }
            ConsumerInvalidMutation::DirectReceiptOracleSubstitution => {
                substitute_retained_file(
                    destination,
                    "derived/case-8-terminal-join-final.receipt-oracle.bincode",
                    &super::terminal_fixture_receipt_oracle_path("join-unwrap-povw")?,
                )?;
            }
        }
        rebuild_retained_packet_documents(destination)
    }

    #[cfg(feature = "embedded-method")]
    fn copy_retained_tree_create_only(source: &Path, destination: &Path) -> Result<()> {
        use anyhow::{Context as _, ensure};
        use std::io::Write as _;

        fs::create_dir(destination).with_context(|| {
            format!(
                "cannot create retained mutation root {}",
                destination.display()
            )
        })?;
        let mut pending = vec![(source.to_path_buf(), destination.to_path_buf())];
        while let Some((source_dir, destination_dir)) = pending.pop() {
            for entry in fs::read_dir(&source_dir).with_context(|| {
                format!("cannot enumerate retained packet {}", source_dir.display())
            })? {
                let entry = entry?;
                let file_type = entry.file_type()?;
                let destination_path = destination_dir.join(entry.file_name());
                if file_type.is_dir() {
                    fs::create_dir(&destination_path).with_context(|| {
                        format!(
                            "cannot create retained mutation directory {}",
                            destination_path.display()
                        )
                    })?;
                    pending.push((entry.path(), destination_path));
                } else {
                    ensure!(
                        file_type.is_file(),
                        "retained packet contains a non-regular entry: {}",
                        entry.path().display()
                    );
                    let bytes = fs::read(entry.path())?;
                    let mut output = fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&destination_path)
                        .with_context(|| {
                            format!(
                                "cannot create retained mutation file {}",
                                destination_path.display()
                            )
                        })?;
                    output.write_all(&bytes)?;
                    output.sync_all()?;
                }
            }
        }
        Ok(())
    }

    #[cfg(feature = "embedded-method")]
    fn swap_retained_files(root: &Path, left: &str, right: &str) -> Result<()> {
        let left_bytes = read_packet_file(root, left)?;
        let right_bytes = read_packet_file(root, right)?;
        fs::write(root.join(left), right_bytes)?;
        fs::write(root.join(right), left_bytes)?;
        Ok(())
    }

    #[cfg(feature = "embedded-method")]
    fn substitute_retained_file(root: &Path, destination: &str, source: &str) -> Result<()> {
        fs::write(root.join(destination), read_packet_file(root, source)?)?;
        Ok(())
    }

    #[cfg(feature = "embedded-method")]
    fn rebuild_retained_packet_documents(root: &Path) -> Result<()> {
        use anyhow::{Context as _, ensure};
        use sha2::{Digest as _, Sha256};

        const MANIFEST: &str = "B4-TERMINAL-EVIDENCE-MANIFEST.json";
        const COMPLETION: &str = "B4-TERMINAL-EVIDENCE-COMPLETE.json";

        let manifest_path = root.join(MANIFEST);
        let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)
            .context("cannot parse retained terminal-evidence manifest")?;
        let files = manifest
            .get_mut("files")
            .and_then(serde_json::Value::as_array_mut)
            .context("retained terminal-evidence manifest has no files array")?;
        ensure!(
            files.len()
                == eip_0045_reproduction::b4_terminal_evidence_packet::
                    B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT,
            "retained terminal-evidence manifest payload count drift"
        );
        for row in files {
            let relative = row
                .get("path")
                .and_then(serde_json::Value::as_str)
                .context("retained terminal-evidence manifest row has no path")?;
            let bytes = read_packet_file(root, relative)?;
            row["byteLength"] = serde_json::Value::from(u64::try_from(bytes.len())?);
            row["sha256"] = serde_json::Value::String(hex::encode(Sha256::digest(&bytes)));
        }
        let manifest_bytes = eip_0045_reproduction::canonical::canonical_json_bytes(&manifest)?;
        fs::write(&manifest_path, &manifest_bytes)?;
        let completion = serde_json::json!({
            "format": "Eip0045B4TerminalEvidenceCompletionV1",
            "formatVersion": 1,
            "manifestPath": MANIFEST,
            "manifestByteLength": u64::try_from(manifest_bytes.len())?,
            "manifestSha256": hex::encode(Sha256::digest(&manifest_bytes)),
        });
        let completion_bytes = eip_0045_reproduction::canonical::canonical_json_bytes(&completion)?;
        fs::write(root.join(COMPLETION), completion_bytes)?;
        Ok(())
    }

    #[cfg(feature = "embedded-method")]
    fn read_packet_file(root: &Path, relative: &str) -> Result<Vec<u8>> {
        use anyhow::Context as _;

        fs::read(root.join(relative))
            .with_context(|| format!("cannot read retained packet role {relative}"))
    }

    #[cfg(feature = "embedded-method")]
    fn flip_first(bytes: &mut [u8]) {
        let first = bytes
            .first_mut()
            .expect("retained terminal source roles are nonempty");
        *first = first.wrapping_add(1);
    }

    #[cfg(unix)]
    fn unique_test_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "eip0045-task8-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[cfg(unix)]
    fn unsupported_publication_root() -> PathBuf {
        PathBuf::from("/proc/eip0045-task8-unsupported-publication")
    }

    #[cfg(not(unix))]
    fn unsupported_publication_root() -> PathBuf {
        PathBuf::from("unsupported-terminal-evidence-publication")
    }
}
