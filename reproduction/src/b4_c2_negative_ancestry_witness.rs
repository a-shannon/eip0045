//! Descriptor-rooted producers for the eleven authenticated ancestry-witness rows.
//!
//! The post-generation catalogue and its physical receipt bytes have already
//! passed the opaque derive-first authority and descriptor-rooted publication
//! checks before this module can receive a read set. This boundary nevertheless
//! rebinds every selected byte source, derives every projected claim again, and
//! reconstructs both the raw ancestry JCS and its exact verifier envelope from
//! the compiled row layout. No caller-provided selector participates.

use std::{collections::BTreeMap, fmt};

use anyhow::{Context as _, Result, bail, ensure};
use risc0_binfmt::compute_image_id;

use crate::{
    b4::{
        B4NegativeAncestryWitnessRecipeV1, B4NegativeCase, B4NegativeMaterialization,
        B4NegativeMutation, negative_ancestry_witness_recipe,
    },
    b4_campaign_contract::{B4ContractArtifactEncodingV1, B4ContractArtifactIdentityV1},
    b4_fixture_sources::{
        B4FixtureSourceResolverV1, B4MaterializationFixtureSourceResolverV2,
        B4RecursiveAncestrySourceViewV1, B4RecursiveAncestrySourceViewV2,
    },
    b4_materialization_set::{
        B4AuthenticatedMaterializationTopLevelV1, B4AuthenticatedMaterializationTopLevelV2,
        B4ClosedReconstructedExecutionV1, close_production_execution,
    },
    b4_mutation::B4MaterializationReplayAdapterV1,
    b4_negative_ancestry_publication::{
        B4NegativeAncestryPublicationReadSetV1, B4NegativeAncestryPublicationReadSetV2,
    },
    b4_negative_ancestry_witness::{
        B4NegativeAncestryLogicalPlacementV1, B4NegativeAncestryProducerRoleV1,
        B4NegativeAncestryWitnessEntryV1, B4NegativeAncestryWitnessIdV1,
        B4NegativeAncestryWitnessLayoutV1, Eip0045B4NegativeAncestryWitnessCatalogV1,
        compiled_negative_ancestry_witness_layout, expected_terminal,
    },
    b4_plan::{
        B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanExecutionV1,
        B4NegativePlanFixture, B4NegativeQaResultCode, Eip0045B4NegativePlanV1,
    },
    b4_recursive_auxiliary_map::{B4RecursiveAuxiliaryMapV1, encode_recursive_auxiliary_map},
    b4_subject_envelope::{ancestry_subject_envelope_contract, encode_subject_envelope},
    constants::DIGEST_BYTES,
    ergo_statement::{ErgoStatementFieldV1, ErgoStatementV1, parse_ergo_statement_v1},
    profile_manifest::StarkProfileManifestV1,
    recursive_ancestry::{
        RecursiveAncestryClaim, RecursiveAncestryFamily, RecursiveAncestryInventoryDefect,
        RecursiveAncestryProjection, RecursiveAncestrySemanticOutcome,
        RecursiveAncestrySourceInventory, classify_recursive_ancestry_semantics,
        derive_empty_assumption_ok_recursive_ancestry_claim,
        derive_recursive_ancestry_claim_with_inventory, parse_recursive_ancestry_jcs,
        recursive_ancestry_artifact_reference, recursive_ancestry_claim_digest,
        recursive_ancestry_to_jcs, validate_recursive_ancestry_artifacts,
        validate_recursive_ancestry_structure,
    },
};

trait B4NegativeAncestryReadSetViewV1 {
    fn catalog(&self) -> &Eip0045B4NegativeAncestryWitnessCatalogV1;
    fn alternate_guest_elf(&self) -> &[u8];
    fn compiled_row_witness(&self, expanded_row: u16) -> Result<(&[u8], &[u8])>;
}

impl B4NegativeAncestryReadSetViewV1 for B4NegativeAncestryPublicationReadSetV1 {
    fn catalog(&self) -> &Eip0045B4NegativeAncestryWitnessCatalogV1 {
        B4NegativeAncestryPublicationReadSetV1::catalog(self)
    }

    fn alternate_guest_elf(&self) -> &[u8] {
        B4NegativeAncestryPublicationReadSetV1::alternate_guest_elf(self)
    }

    fn compiled_row_witness(&self, expanded_row: u16) -> Result<(&[u8], &[u8])> {
        B4NegativeAncestryPublicationReadSetV1::compiled_row_witness(self, expanded_row)
    }
}

impl B4NegativeAncestryReadSetViewV1 for B4NegativeAncestryPublicationReadSetV2 {
    fn catalog(&self) -> &Eip0045B4NegativeAncestryWitnessCatalogV1 {
        B4NegativeAncestryPublicationReadSetV2::catalog(self)
    }

    fn alternate_guest_elf(&self) -> &[u8] {
        B4NegativeAncestryPublicationReadSetV2::alternate_guest_elf(self)
    }

    fn compiled_row_witness(&self, expanded_row: u16) -> Result<(&[u8], &[u8])> {
        B4NegativeAncestryPublicationReadSetV2::compiled_row_witness(self, expanded_row)
    }
}

struct NegativeAncestrySources<'a> {
    view: B4RecursiveAncestrySourceViewV1<'a>,
    negative_plan_jcs: &'a [u8],
    profile_id: [u8; DIGEST_BYTES],
    alternate_program_id: [u8; DIGEST_BYTES],
}

struct NegativeAncestrySourcesV2<'a> {
    view: B4RecursiveAncestrySourceViewV2<'a>,
    negative_plan_jcs: &'a [u8],
    profile_id: [u8; DIGEST_BYTES],
    alternate_program_id: [u8; DIGEST_BYTES],
}

trait AuthenticatedNegativeAncestrySources {
    fn negative_plan_jcs(&self) -> &[u8];
    fn profile_manifest_context(&self) -> &[u8];
    fn ancestry_jcs(&self) -> &[u8];
    fn projection(&self) -> &RecursiveAncestryProjection;
    fn statement(&self) -> &[u8];
    fn final_raw_seal(&self) -> &[u8];
    fn auxiliary_seals(&self) -> &B4RecursiveAuxiliaryMapV1<'_>;
    fn profile_id(&self) -> [u8; DIGEST_BYTES];
    fn alternate_program_id(&self) -> [u8; DIGEST_BYTES];
}

impl<'a> NegativeAncestrySources<'a> {
    fn authenticate<R: B4NegativeAncestryReadSetViewV1>(
        top_level: &'a B4AuthenticatedMaterializationTopLevelV1,
        layout: &B4NegativeAncestryWitnessLayoutV1,
        read_set: &R,
    ) -> Result<Self> {
        let resolver = B4FixtureSourceResolverV1::from_authenticated(top_level)
            .context("negative ancestry producer cannot authenticate fixture sources")?;
        let view = resolver
            .recursive_ancestry_source(layout.base_family)
            .context("negative ancestry producer cannot resolve its compiled positive family")?;
        let manifest = StarkProfileManifestV1::decode(view.profile_manifest_context())
            .context("negative ancestry producer cannot decode its authenticated manifest")?;
        manifest
            .validate_initial_profile_target()
            .context("negative ancestry producer manifest differs from the initial profile")?;
        let profile_id = manifest.profile_id()?;
        ensure!(
            view.family() == layout.base_family,
            "negative ancestry source family differs from the compiled row"
        );
        let alternate_program_id = compute_image_id(read_set.alternate_guest_elf())
            .context("negative ancestry alternate guest ELF has no RISC Zero image ID")?
            .into();
        Ok(Self {
            view,
            negative_plan_jcs: &top_level.negative_plan,
            profile_id,
            alternate_program_id,
        })
    }
}

impl AuthenticatedNegativeAncestrySources for NegativeAncestrySources<'_> {
    fn negative_plan_jcs(&self) -> &[u8] {
        self.negative_plan_jcs
    }

    fn profile_manifest_context(&self) -> &[u8] {
        self.view.profile_manifest_context()
    }

    fn ancestry_jcs(&self) -> &[u8] {
        self.view.ancestry_jcs()
    }

    fn projection(&self) -> &RecursiveAncestryProjection {
        self.view.projection()
    }

    fn statement(&self) -> &[u8] {
        self.view.statement()
    }

    fn final_raw_seal(&self) -> &[u8] {
        self.view.final_raw_seal()
    }

    fn auxiliary_seals(&self) -> &B4RecursiveAuxiliaryMapV1<'_> {
        self.view.auxiliary_seals()
    }

    fn profile_id(&self) -> [u8; DIGEST_BYTES] {
        self.profile_id
    }

    fn alternate_program_id(&self) -> [u8; DIGEST_BYTES] {
        self.alternate_program_id
    }
}

impl<'a> NegativeAncestrySourcesV2<'a> {
    fn authenticate(
        top_level: &'a B4AuthenticatedMaterializationTopLevelV2,
        layout: &B4NegativeAncestryWitnessLayoutV1,
        read_set: &B4NegativeAncestryPublicationReadSetV2,
    ) -> Result<Self> {
        let resolver = B4MaterializationFixtureSourceResolverV2::from_authenticated(top_level)
            .context("V2 negative ancestry producer cannot authenticate fixture sources")?;
        let view = resolver
            .recursive_ancestry_source(layout.base_family)
            .context("V2 negative ancestry producer cannot resolve its compiled positive family")?;
        let manifest = StarkProfileManifestV1::decode(view.profile_manifest_context())
            .context("V2 negative ancestry producer cannot decode its authenticated manifest")?;
        manifest
            .validate_initial_profile_target()
            .context("V2 negative ancestry producer manifest differs from the initial profile")?;
        let profile_id = manifest.profile_id()?;
        ensure!(
            view.family() == layout.base_family,
            "V2 negative ancestry source family differs from the compiled row"
        );
        let alternate_program_id = compute_image_id(read_set.alternate_guest_elf())
            .context("V2 negative ancestry alternate guest ELF has no RISC Zero image ID")?
            .into();
        Ok(Self {
            view,
            negative_plan_jcs: resolver.negative_plan_jcs(),
            profile_id,
            alternate_program_id,
        })
    }
}

impl AuthenticatedNegativeAncestrySources for NegativeAncestrySourcesV2<'_> {
    fn negative_plan_jcs(&self) -> &[u8] {
        self.negative_plan_jcs
    }

    fn profile_manifest_context(&self) -> &[u8] {
        self.view.profile_manifest_context()
    }

    fn ancestry_jcs(&self) -> &[u8] {
        self.view.ancestry_jcs()
    }

    fn projection(&self) -> &RecursiveAncestryProjection {
        self.view.projection()
    }

    fn statement(&self) -> &[u8] {
        self.view.statement()
    }

    fn final_raw_seal(&self) -> &[u8] {
        self.view.final_raw_seal()
    }

    fn auxiliary_seals(&self) -> &B4RecursiveAuxiliaryMapV1<'_> {
        self.view.auxiliary_seals()
    }

    fn profile_id(&self) -> [u8; DIGEST_BYTES] {
        self.profile_id
    }

    fn alternate_program_id(&self) -> [u8; DIGEST_BYTES] {
        self.alternate_program_id
    }
}

#[derive(Clone, Copy)]
enum AdapterOutput {
    RawAncestry,
    FinalEnvelope,
}

#[derive(Clone, Copy)]
struct NegativeAncestryReplayAdapter<'a, S, R> {
    slot: usize,
    layout: &'a B4NegativeAncestryWitnessLayoutV1,
    entry: &'a B4NegativeAncestryWitnessEntryV1,
    catalog: &'a Eip0045B4NegativeAncestryWitnessCatalogV1,
    sources: &'a S,
    negative_plan_jcs: &'a [u8],
    read_set: &'a R,
    raw_seal: &'a [u8],
    receipt_oracle: &'a [u8],
    materialization: &'a B4NegativeMaterialization,
    output: &'a [u8],
    output_kind: AdapterOutput,
}

impl<S, R> fmt::Debug for NegativeAncestryReplayAdapter<'_, S, R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NegativeAncestryReplayAdapter")
            .field("expanded_row", &self.layout.expanded_row)
            .finish_non_exhaustive()
    }
}

impl<S: AuthenticatedNegativeAncestrySources, R: B4NegativeAncestryReadSetViewV1>
    B4MaterializationReplayAdapterV1 for NegativeAncestryReplayAdapter<'_, S, R>
{
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::VerifierInput
    }

    fn base_bytes(&self) -> &[u8] {
        self.sources.ancestry_jcs()
    }

    fn output_bytes(&self) -> &[u8] {
        self.output
    }

    fn replay_recipe(
        &self,
        base_selector_id: &str,
        materialization: &B4NegativeMaterialization,
    ) -> Result<()> {
        ensure!(
            base_selector_id == expected_base_selector(self.layout)?
                && materialization == self.materialization,
            "negative ancestry replay received a selector or recipe outside its compiled row"
        );
        validate_row_authority(
            self.slot,
            self.layout,
            self.entry,
            self.catalog,
            self.sources,
            self.negative_plan_jcs,
            self.read_set,
            self.raw_seal,
            self.receipt_oracle,
        )?;
        let replayed =
            replay_witness_materialization(self.layout, self.entry, self.sources, self.raw_seal)
                .with_context(|| row_execution_context(self.layout, "replay failed"))?;
        let expected = match self.output_kind {
            AdapterOutput::RawAncestry => &replayed.raw_ancestry,
            AdapterOutput::FinalEnvelope => &replayed.final_subject,
        };
        ensure!(
            self.output == expected,
            "negative ancestry replay output differs from typed reconstruction"
        );
        Ok(())
    }
}

struct ReplayedNegativeAncestry {
    raw_ancestry: Vec<u8>,
    final_subject: Vec<u8>,
}

/// Reconstruct exactly rows 141, 142, 143, 145, 147, 148, and 150 through 154.
///
/// Selection is exclusively the compiled layout plus the authenticated
/// publication read set. Row 146 and every other plan row return `None`.
pub(crate) fn reconstruct_negative_ancestry_witness_execution(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
    read_set: &B4NegativeAncestryPublicationReadSetV1,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    let layout = compiled_negative_ancestry_witness_layout()?;
    let Some(slot) = layout
        .iter()
        .position(|candidate| usize::from(candidate.expanded_row) == execution_index)
    else {
        return Ok(None);
    };
    let selected = &layout[slot];
    let sources = NegativeAncestrySources::authenticate(top_level, selected, read_set)?;
    validate_planned_execution(
        execution_index,
        selected,
        planned,
        sources.negative_plan_jcs(),
    )?;
    reconstruct_negative_ancestry_witness_execution_from_sources(
        execution_index,
        planned,
        slot,
        selected,
        &sources,
        read_set,
    )
}

/// Reconstruct the fixed witness rows from V2 fixture and publication authorities.
pub(crate) fn reconstruct_negative_ancestry_witness_execution_v2(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV2,
    read_set: &B4NegativeAncestryPublicationReadSetV2,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    let layout = compiled_negative_ancestry_witness_layout()?;
    let Some(slot) = layout
        .iter()
        .position(|candidate| usize::from(candidate.expanded_row) == execution_index)
    else {
        return Ok(None);
    };
    let selected = &layout[slot];
    let sources = NegativeAncestrySourcesV2::authenticate(top_level, selected, read_set)?;
    validate_planned_execution(
        execution_index,
        selected,
        planned,
        sources.negative_plan_jcs(),
    )?;
    reconstruct_negative_ancestry_witness_execution_from_sources(
        execution_index,
        planned,
        slot,
        selected,
        &sources,
        read_set,
    )
}

fn reconstruct_negative_ancestry_witness_execution_from_sources<
    S: AuthenticatedNegativeAncestrySources,
    R: B4NegativeAncestryReadSetViewV1,
>(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    slot: usize,
    selected: &B4NegativeAncestryWitnessLayoutV1,
    sources: &S,
    read_set: &R,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    let catalog = read_set.catalog();
    let entry = catalog
        .entries
        .get(slot)
        .context("authenticated negative ancestry catalogue omits the compiled slot")?;
    let (raw_seal, receipt_oracle) = read_set
        .compiled_row_witness(selected.expanded_row)
        .context("authenticated negative ancestry read set omits the compiled row")?;
    validate_row_authority(
        slot,
        selected,
        entry,
        catalog,
        sources,
        sources.negative_plan_jcs(),
        read_set,
        raw_seal,
        receipt_oracle,
    )?;
    let replayed = replay_witness_materialization(selected, entry, sources, raw_seal)
        .with_context(|| row_execution_context(selected, "replay failed"))?;

    let materialization = B4NegativeMaterialization::Mutation {
        mutation: B4NegativeMutation::AncestryWitnessSubstitution {
            recipe: selected.recipe,
        },
    };
    let registry_row = B4NegativeCase {
        execution_id: selected.execution_id.clone(),
        base_selector_id: expected_base_selector(selected)?.to_owned(),
        materialization_domain: B4MaterializationDomain::VerifierInput,
        materialization,
    };
    let expected_materialization = registry_row.materialization.clone();
    let raw_adapter = NegativeAncestryReplayAdapter {
        slot,
        layout: selected,
        entry,
        catalog,
        sources,
        negative_plan_jcs: sources.negative_plan_jcs(),
        read_set,
        raw_seal,
        receipt_oracle,
        materialization: &expected_materialization,
        output: &replayed.raw_ancestry,
        output_kind: AdapterOutput::RawAncestry,
    };
    let final_adapter = NegativeAncestryReplayAdapter {
        output: &replayed.final_subject,
        output_kind: AdapterOutput::FinalEnvelope,
        ..raw_adapter
    };

    close_production_execution(
        execution_index,
        planned,
        sources.negative_plan_jcs(),
        registry_row,
        &raw_adapter,
        &final_adapter,
        replayed.final_subject.clone(),
        vec![sources.profile_manifest_context().to_vec()],
    )
    .map(Some)
}

fn validate_planned_execution(
    execution_index: usize,
    layout: &B4NegativeAncestryWitnessLayoutV1,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
) -> Result<()> {
    ensure!(
        usize::from(layout.expanded_row) == execution_index,
        "negative ancestry compiled row differs from its execution index"
    );
    let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(negative_plan_jcs)
        .context("negative ancestry producer plan is not canonical")?;
    let canonical = plan
        .groups
        .iter()
        .flat_map(|group| group.executions.iter())
        .nth(execution_index)
        .context("negative ancestry execution index is outside the canonical plan")?;
    let (variant, expected_fixture, expected_result) = expected_plan_contract(layout)?;
    ensure!(
        canonical == planned
            && planned.execution_id == layout.execution_id
            && planned.variant_id == variant
            && planned.base_selector_id == expected_base_selector(layout)?
            && planned.fixture == expected_fixture
            && planned.materialization_domain == B4MaterializationDomain::VerifierInput
            && planned.execution_surface == B4NegativeExecutionSurface::AncestryReplay
            && planned.qa_result_code == expected_result
            && planned.parser_truncation_words.is_none(),
        "negative ancestry execution differs from its exact canonical-plan contract"
    );
    Ok(())
}

fn expected_plan_contract(
    layout: &B4NegativeAncestryWitnessLayoutV1,
) -> Result<(&str, B4NegativePlanFixture, B4NegativeQaResultCode)> {
    let (_, variant) = layout
        .execution_id
        .split_once("--")
        .context("negative ancestry execution ID has no canonical group separator")?;
    let fixture = match layout.expanded_row {
        141..=143 => B4NegativePlanFixture::JoinResolveEdgeSetV1,
        145 | 147 | 148 | 153 | 154 => B4NegativePlanFixture::Case9TypedAncestryV1,
        150..=152 => B4NegativePlanFixture::Case10TypedAncestryV1,
        _ => bail!("expanded row is outside the eleven-row ancestry-witness layout"),
    };
    let qa_result = match expected_semantic_outcome(layout)? {
        RecursiveAncestrySemanticOutcome::ClaimEdge => {
            B4NegativeQaResultCode::B4AncestryClaimEdgeMismatch
        }
        RecursiveAncestrySemanticOutcome::ResolveExplicit => {
            B4NegativeQaResultCode::B4ResolveExplicitSemanticsMismatch
        }
        RecursiveAncestrySemanticOutcome::ResolveZeroRoot => {
            B4NegativeQaResultCode::B4ResolveZeroRootSemanticsMismatch
        }
        RecursiveAncestrySemanticOutcome::AssumptionInventory(_) => {
            B4NegativeQaResultCode::B4ResolveAssumptionInventoryInvalid
        }
        RecursiveAncestrySemanticOutcome::Canonical => {
            bail!("negative ancestry row cannot expect canonical semantics")
        }
    };
    Ok((variant, fixture, qa_result))
}

fn expected_base_selector(layout: &B4NegativeAncestryWitnessLayoutV1) -> Result<&str> {
    match layout.expanded_row {
        141..=143 => Ok(layout.base_family.case_id()),
        145 | 147 | 148 | 153 | 154 => Ok("case9-typed-ancestry-v1"),
        150..=152 => Ok("case10-typed-ancestry-v1"),
        _ => bail!("expanded row is outside the eleven-row ancestry-witness layout"),
    }
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "this row-authority boundary visibly rebinds every independent compiled, catalogue, source, and physical input"
)]
fn validate_row_authority<R: B4NegativeAncestryReadSetViewV1>(
    slot: usize,
    layout: &B4NegativeAncestryWitnessLayoutV1,
    entry: &B4NegativeAncestryWitnessEntryV1,
    catalog: &Eip0045B4NegativeAncestryWitnessCatalogV1,
    sources: &impl AuthenticatedNegativeAncestrySources,
    negative_plan_jcs: &[u8],
    read_set: &R,
    raw_seal: &[u8],
    receipt_oracle: &[u8],
) -> Result<()> {
    let compiled = compiled_negative_ancestry_witness_layout()?;
    let compiled_slot = compiled
        .iter()
        .position(|candidate| candidate.expanded_row == layout.expanded_row)
        .context("selected negative ancestry row is absent from compiled layout")?;
    ensure!(
        compiled.get(slot) == Some(layout)
            && catalog.entries.get(slot) == Some(entry)
            && compiled_slot == slot,
        "negative ancestry row, slot, or catalogue order differs from compiled authority"
    );
    ensure!(
        entry.expanded_row == layout.expanded_row
            && entry.execution_id == layout.execution_id
            && entry.base_family == layout.base_family
            && entry.witness_id == layout.witness_id
            && entry.producer_role == layout.producer_role
            && entry.logical_placement == layout.logical_placement
            && entry.recipe == layout.recipe
            && entry.logical_consumer_path == layout.logical_consumer_path
            && entry.first_public_rejection == layout.first_public_rejection,
        "negative ancestry catalogue entry differs from its compiled row"
    );
    ensure!(
        negative_ancestry_witness_recipe(&layout.execution_id) == Some(layout.recipe),
        "negative ancestry compiled recipe differs from the central registry table"
    );
    ensure!(
        entry.terminal == expected_terminal(layout.witness_id, layout.producer_role)?,
        "negative ancestry terminal differs from its witness role"
    );
    ensure!(
        entry.claim_digest == hex::encode(recursive_ancestry_claim_digest(&entry.claim)?),
        "negative ancestry claim digest differs from independent projection"
    );

    let measured_raw = B4ContractArtifactIdentityV1::from_bytes(
        &layout.raw_seal_path,
        B4ContractArtifactEncodingV1::RawBytes,
        raw_seal,
    )?;
    let measured_oracle = B4ContractArtifactIdentityV1::from_bytes(
        &layout.receipt_oracle_path,
        B4ContractArtifactEncodingV1::RawBytes,
        receipt_oracle,
    )?;
    ensure!(
        measured_raw == entry.raw_seal && measured_oracle == entry.receipt_oracle,
        "negative ancestry physical witness bytes differ from the authenticated catalogue"
    );
    let (selected_raw, selected_oracle) = read_set.compiled_row_witness(layout.expanded_row)?;
    ensure!(
        selected_raw == raw_seal && selected_oracle == receipt_oracle,
        "negative ancestry witness bytes differ from the selector-free read-set slot"
    );

    let measured_plan = B4ContractArtifactIdentityV1::from_bytes(
        &catalog.negative_plan.path,
        B4ContractArtifactEncodingV1::Rfc8785Jcs,
        negative_plan_jcs,
    )?;
    let measured_manifest = B4ContractArtifactIdentityV1::from_bytes(
        &catalog.profile_manifest.path,
        B4ContractArtifactEncodingV1::RawBytes,
        sources.profile_manifest_context(),
    )?;
    let measured_alternate_guest = B4ContractArtifactIdentityV1::from_bytes(
        &catalog.alternate_guest_elf.path,
        B4ContractArtifactEncodingV1::RawBytes,
        read_set.alternate_guest_elf(),
    )?;
    ensure!(
        measured_plan == catalog.negative_plan
            && measured_manifest == catalog.profile_manifest
            && measured_alternate_guest == catalog.alternate_guest_elf,
        "negative ancestry catalogue differs from its authenticated plan, profile, or alternate guest bytes"
    );
    ensure!(
        hex::encode(sources.alternate_program_id()) == catalog.alternate_program_id
            && catalog.alternate_program_id != catalog.consumer_program_id,
        "negative ancestry alternate program differs from its authenticated guest ELF or aliases the consumer"
    );
    validate_cross_row_physical_bindings(read_set)?;

    let manifest = StarkProfileManifestV1::decode(sources.profile_manifest_context())?;
    manifest.validate_initial_profile_target()?;
    let statement = parse_ergo_statement_v1(sources.statement())
        .context("negative ancestry source statement is invalid")?;
    ensure!(
        statement.encode()?.as_slice() == sources.statement()
            && statement.profile_id() == sources.profile_id()
            && hex::encode(statement.program_id()) == catalog.consumer_program_id
            && sources.projection().program_id == catalog.consumer_program_id
            && sources.projection().family == layout.base_family
            && hex::encode(manifest.inner_control_root()) == catalog.inner_control_root
            && entry.control_root == catalog.inner_control_root,
        "negative ancestry consumer profile, program, family, or control root drifted"
    );

    let expected_claim = derive_expected_witness_claim(layout, catalog, sources)?;
    ensure!(
        entry.claim == expected_claim
            && entry.producer_program_id == expected_claim.pre_state_digest
            && entry.claim.pre_state_digest == entry.producer_program_id,
        "negative ancestry producer claim or program differs from source-derived authority"
    );
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the claim derivation keeps every witness class and its exact statement-field isolation in one auditable match"
)]
fn derive_expected_witness_claim(
    layout: &B4NegativeAncestryWitnessLayoutV1,
    catalog: &Eip0045B4NegativeAncestryWitnessCatalogV1,
    sources: &impl AuthenticatedNegativeAncestrySources,
) -> Result<RecursiveAncestryClaim> {
    derive_expected_witness_claim_for_programs(
        layout, &catalog.consumer_program_id, &catalog.alternate_program_id, sources,
    )
}

#[allow(clippy::too_many_lines, reason = "one shared closed witness-claim derivation")]
fn derive_expected_witness_claim_for_programs(
    layout: &B4NegativeAncestryWitnessLayoutV1,
    expected_consumer_program: &str,
    expected_alternate_program: &str,
    sources: &impl AuthenticatedNegativeAncestrySources,
) -> Result<RecursiveAncestryClaim> {
    let statement = parse_ergo_statement_v1(sources.statement())?;
    let consumer_program_id = statement.program_id();
    ensure!(
        hex::encode(consumer_program_id) == expected_consumer_program,
        "negative ancestry consumer program differs from the authenticated catalogue"
    );
    let canonical = derive_empty_assumption_ok_recursive_ancestry_claim(
        &consumer_program_id,
        sources.statement(),
    )?;
    match layout.witness_id {
        B4NegativeAncestryWitnessIdV1::Case9AssumptionLift
        | B4NegativeAncestryWitnessIdV1::Case9FinalResolve => Ok(canonical),
        B4NegativeAncestryWitnessIdV1::AlternateStatementAssumptionLift
        | B4NegativeAncestryWitnessIdV1::AlternateStatementFinalResolve
        | B4NegativeAncestryWitnessIdV1::AlternateStatementFinalJoin => {
            let mut alternate_chain_domain = statement.chain_domain_id();
            alternate_chain_domain[0] ^= 0x01;
            let alternate = ErgoStatementV1::new(
                alternate_chain_domain,
                statement.profile_id(),
                consumer_program_id,
                statement.contract_id(),
                statement.application_payload(),
            )?
            .encode()?;
            require_only_statement_field_changed(
                sources.statement(),
                &alternate,
                ErgoStatementFieldV1::ChainDomainId,
                "alternate statement",
            )?;
            let parsed = parse_ergo_statement_v1(&alternate)?;
            ensure!(
                alternate != sources.statement()
                    && parsed.chain_domain_id() == alternate_chain_domain
                    && parsed.profile_id() == statement.profile_id()
                    && parsed.program_id() == consumer_program_id
                    && parsed.contract_id() == statement.contract_id()
                    && parsed.application_payload() == statement.application_payload(),
                "alternate statement changed a field outside chain-domain byte zero"
            );
            derive_empty_assumption_ok_recursive_ancestry_claim(&consumer_program_id, &alternate)
        }
        B4NegativeAncestryWitnessIdV1::AlternateProgramLift => {
            ensure!(
                hex::encode(sources.alternate_program_id()) == expected_alternate_program,
                "negative ancestry alternate program differs from its authenticated guest ELF"
            );
            let alternate = ErgoStatementV1::new(
                statement.chain_domain_id(),
                statement.profile_id(),
                sources.alternate_program_id(),
                statement.contract_id(),
                statement.application_payload(),
            )?
            .encode()?;
            require_only_statement_field_changed(
                sources.statement(),
                &alternate,
                ErgoStatementFieldV1::ProgramId,
                "alternate-program statement",
            )?;
            let parsed = parse_ergo_statement_v1(&alternate)?;
            ensure!(
                alternate != sources.statement()
                    && parsed.chain_domain_id() == statement.chain_domain_id()
                    && parsed.profile_id() == statement.profile_id()
                    && parsed.program_id() == sources.alternate_program_id()
                    && parsed.contract_id() == statement.contract_id()
                    && parsed.application_payload() == statement.application_payload(),
                "alternate-program statement changed a field outside the program ID"
            );
            derive_empty_assumption_ok_recursive_ancestry_claim(
                &sources.alternate_program_id(),
                &alternate,
            )
        }
        B4NegativeAncestryWitnessIdV1::DuplicateAssumptionLift => {
            ensure!(
                layout.expanded_row == 154
                    && layout.base_family == RecursiveAncestryFamily::TerminalResolve,
                "duplicated-inventory claim is outside its sole compiled row"
            );
            let canonical_inventory = &sources
                .projection()
                .assumption_receipt
                .as_ref()
                .context("duplicated-inventory row has no source assumption")?
                .source_inventory;
            let [head] = canonical_inventory.entries.as_slice() else {
                bail!("duplicated-inventory source does not contain exactly one head");
            };
            let duplicated = RecursiveAncestrySourceInventory {
                entries: vec![head.clone(), head.clone()],
            };
            derive_recursive_ancestry_claim_with_inventory(
                &canonical,
                sources.statement(),
                &duplicated,
            )
        }
    }
}

fn validate_cross_row_physical_bindings<R: B4NegativeAncestryReadSetViewV1>(
    read_set: &R,
) -> Result<()> {
    for (left, right) in [(141, 142), (141, 153), (145, 150), (147, 151)] {
        let (left_raw, left_oracle) = read_set.compiled_row_witness(left)?;
        let (right_raw, right_oracle) = read_set.compiled_row_witness(right)?;
        ensure!(
            left_raw == right_raw && left_oracle == right_oracle,
            "aliased negative ancestry rows {left} and {right} differ in physical witness bytes"
        );
    }

    let representatives = [141, 143, 145, 147, 148, 152, 154];
    for (position, left) in representatives.iter().copied().enumerate() {
        let (left_raw, left_oracle) = read_set.compiled_row_witness(left)?;
        for right in representatives.iter().copied().skip(position + 1) {
            let (right_raw, right_oracle) = read_set.compiled_row_witness(right)?;
            ensure!(
                left_raw != right_raw && left_oracle != right_oracle,
                "distinct negative ancestry rows {left} and {right} alias physical witness bytes"
            );
        }
    }
    Ok(())
}

fn require_only_statement_field_changed(
    original: &[u8],
    changed: &[u8],
    field: ErgoStatementFieldV1,
    label: &str,
) -> Result<()> {
    let parsed = parse_ergo_statement_v1(original)?;
    let span = parsed.layout()?.span(field);
    ensure!(
        original.len() == changed.len()
            && original[..span.start()] == changed[..span.start()]
            && original[span.end()..] == changed[span.end()..]
            && original[span.start()..span.end()] != changed[span.start()..span.end()],
        "{label} did not change exactly its one authorized statement field"
    );
    Ok(())
}

fn row_execution_context(layout: &B4NegativeAncestryWitnessLayoutV1, stage: &str) -> String {
    format!(
        "negative ancestry row {} ({}) {stage}",
        layout.expanded_row, layout.execution_id
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the replay keeps substitution, semantic classification, artifact closure, and exact subject framing in one audit unit"
)]
fn replay_witness_materialization(
    layout: &B4NegativeAncestryWitnessLayoutV1,
    entry: &B4NegativeAncestryWitnessEntryV1,
    sources: &impl AuthenticatedNegativeAncestrySources,
    raw_seal: &[u8],
) -> Result<ReplayedNegativeAncestry> {
    let source_projection = sources.projection();
    let mut projection = source_projection.clone();
    apply_inventory_recipe(layout, source_projection, &mut projection)?;
    substitute_witness(layout, entry, raw_seal, &mut projection)?;
    ensure!(
        projection.format == source_projection.format
            && projection.format_version == source_projection.format_version
            && projection.case_id == source_projection.case_id
            && projection.profile_id == source_projection.profile_id
            && projection.program_id == source_projection.program_id
            && projection.statement == source_projection.statement
            && projection.family == source_projection.family,
        "negative ancestry substitution changed consumer identity or family fields"
    );

    validate_replayed_semantic_outcome(
        layout,
        entry,
        sources,
        raw_seal,
        source_projection,
        &projection,
    )
    .with_context(|| row_execution_context(layout, "semantic classification failed"))?;
    let raw_ancestry = recursive_ancestry_to_jcs(&projection)?;
    ensure!(
        parse_recursive_ancestry_jcs(&raw_ancestry)? == projection,
        "negative ancestry projection does not round-trip byte-exactly"
    );

    let mut auxiliary_payloads = sources
        .auxiliary_seals()
        .iter()
        .map(|(path, bytes)| (path.to_owned(), bytes.to_vec()))
        .collect::<Vec<_>>();
    let mut final_raw_seal = sources.final_raw_seal().to_vec();
    if layout.logical_placement == B4NegativeAncestryLogicalPlacementV1::FinalReceipt {
        ensure!(
            projection
                .steps
                .last()
                .is_some_and(|step| step.raw_seal.path == layout.logical_consumer_path),
            "negative ancestry final placement differs from the compiled consumer path"
        );
        final_raw_seal = raw_seal.to_vec();
    } else {
        let mut matches = auxiliary_payloads
            .iter_mut()
            .filter(|(path, _)| path == &layout.logical_consumer_path);
        let (_, payload) = matches
            .next()
            .context("negative ancestry placement is absent from the auxiliary map")?;
        ensure!(
            matches.next().is_none(),
            "negative ancestry placement is duplicated in the auxiliary map"
        );
        *payload = raw_seal.to_vec();
    }

    let changed_auxiliary = auxiliary_payloads
        .iter()
        .zip(sources.auxiliary_seals().iter())
        .filter(|((path, bytes), (source_path, source_bytes))| {
            path.as_str() != *source_path || bytes.as_slice() != *source_bytes
        })
        .count();
    ensure!(
        match layout.logical_placement {
            B4NegativeAncestryLogicalPlacementV1::FinalReceipt => {
                changed_auxiliary == 0 && final_raw_seal.as_slice() == raw_seal
            }
            _ => {
                changed_auxiliary == 1 && final_raw_seal.as_slice() == sources.final_raw_seal()
            }
        },
        "negative ancestry witness changed bytes outside its sole compiled placement"
    );

    let borrowed_entries = auxiliary_payloads
        .iter()
        .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
        .collect::<Vec<_>>();
    let auxiliary_map =
        B4RecursiveAuxiliaryMapV1::from_exact_entries(layout.base_family, &borrowed_entries)
            .context("negative ancestry auxiliary map differs from its compiled family")?;
    let encoded_auxiliary = encode_recursive_auxiliary_map(&auxiliary_map)?;
    let artifacts = auxiliary_payloads
        .iter()
        .map(|(path, bytes)| (path.clone(), bytes.as_slice()))
        .collect::<BTreeMap<_, _>>();
    validate_recursive_ancestry_artifacts(
        &projection,
        sources.statement(),
        &final_raw_seal,
        &artifacts,
    )
    .context("negative ancestry substitution produced invalid artifact references")?;

    let final_subject = encode_subject_envelope(
        &[
            &raw_ancestry,
            sources.statement(),
            &final_raw_seal,
            &encoded_auxiliary,
        ],
        ancestry_subject_envelope_contract(),
    )
    .context("negative ancestry producer cannot encode its exact four-part subject")?;
    Ok(ReplayedNegativeAncestry {
        raw_ancestry,
        final_subject,
    })
}

fn validate_replayed_semantic_outcome(
    layout: &B4NegativeAncestryWitnessLayoutV1,
    entry: &B4NegativeAncestryWitnessEntryV1,
    sources: &impl AuthenticatedNegativeAncestrySources,
    raw_seal: &[u8],
    source_projection: &RecursiveAncestryProjection,
    projection: &RecursiveAncestryProjection,
) -> Result<()> {
    if layout.expanded_row == 147 {
        validate_row_147_alternate_program_step_zero(
            layout,
            entry,
            sources,
            raw_seal,
            source_projection,
            projection,
        )?;
    }

    let expected_outcome = expected_semantic_outcome(layout)?;
    let actual_outcome = classify_recursive_ancestry_semantics(
        projection,
        sources.statement(),
        sources.profile_id(),
    )
    .with_context(|| row_execution_context(layout, "generic classifier rejected the projection"))?;
    ensure!(
        actual_outcome == expected_outcome,
        "negative ancestry substitution did not isolate its planned semantic rejection"
    );
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the row-147 security boundary keeps source, compiled authority, authenticated producer, and exact projection visible"
)]
fn validate_row_147_alternate_program_step_zero(
    layout: &B4NegativeAncestryWitnessLayoutV1,
    entry: &B4NegativeAncestryWitnessEntryV1,
    sources: &impl AuthenticatedNegativeAncestrySources,
    raw_seal: &[u8],
    source_projection: &RecursiveAncestryProjection,
    projection: &RecursiveAncestryProjection,
) -> Result<()> {
    const EXECUTION_ID: &str = "resolve-explicit-field-sweep--program-id";

    ensure!(
        layout.expanded_row == 147
            && layout.execution_id == EXECUTION_ID
            && layout.base_family == RecursiveAncestryFamily::TerminalResolve
            && layout.witness_id == B4NegativeAncestryWitnessIdV1::AlternateProgramLift
            && layout.producer_role == B4NegativeAncestryProducerRoleV1::Lift
            && layout.logical_placement == B4NegativeAncestryLogicalPlacementV1::Step0
            && layout.recipe
                == B4NegativeAncestryWitnessRecipeV1::AlternateGuestLiftForTerminalResolve,
        "row 147 layout differs from its exact alternate-program Step0 contract"
    );
    ensure!(
        expected_semantic_outcome(layout)? == RecursiveAncestrySemanticOutcome::ResolveExplicit,
        "row 147 is not bound to its exact ResolveExplicit outcome"
    );
    ensure!(
        entry.expanded_row == 147
            && entry.execution_id == EXECUTION_ID
            && entry.base_family == layout.base_family
            && entry.witness_id == layout.witness_id
            && entry.producer_role == layout.producer_role
            && entry.logical_placement == layout.logical_placement
            && entry.recipe == layout.recipe
            && entry.logical_consumer_path == layout.logical_consumer_path,
        "row 147 catalogue binding differs from its exact compiled contract"
    );

    let source_outcome = classify_recursive_ancestry_semantics(
        source_projection,
        sources.statement(),
        sources.profile_id(),
    )
    .with_context(|| row_execution_context(layout, "source classifier rejected the projection"))?;
    ensure!(
        source_outcome == RecursiveAncestrySemanticOutcome::Canonical,
        "row 147 source projection is not canonical"
    );
    validate_recursive_ancestry_structure(projection, sources.statement(), sources.profile_id())
        .with_context(|| {
            row_execution_context(layout, "typed projection is structurally invalid")
        })?;

    let consumer_statement = parse_ergo_statement_v1(sources.statement())
        .context("row 147 consumer statement is invalid")?;
    let consumer_program_id = consumer_statement.program_id();
    ensure!(
        sources.alternate_program_id() != consumer_program_id
            && entry.producer_program_id == hex::encode(sources.alternate_program_id())
            && entry.claim.pre_state_digest == entry.producer_program_id
            && projection.program_id == hex::encode(consumer_program_id),
        "row 147 alternate producer program aliases or is not bound to the consumer"
    );
    let alternate_statement = ErgoStatementV1::new(
        consumer_statement.chain_domain_id(),
        consumer_statement.profile_id(),
        sources.alternate_program_id(),
        consumer_statement.contract_id(),
        consumer_statement.application_payload(),
    )?
    .encode()?;
    require_only_statement_field_changed(
        sources.statement(),
        &alternate_statement,
        ErgoStatementFieldV1::ProgramId,
        "row 147 alternate-program statement",
    )?;
    let alternate_statement_value = parse_ergo_statement_v1(&alternate_statement)?;
    ensure!(
        alternate_statement_value.program_id() == sources.alternate_program_id()
            && alternate_statement_value.chain_domain_id() == consumer_statement.chain_domain_id()
            && alternate_statement_value.profile_id() == consumer_statement.profile_id()
            && alternate_statement_value.contract_id() == consumer_statement.contract_id()
            && alternate_statement_value.application_payload()
                == consumer_statement.application_payload(),
        "row 147 alternate-program statement changed a non-program field"
    );
    let expected_claim = derive_empty_assumption_ok_recursive_ancestry_claim(
        &sources.alternate_program_id(),
        &alternate_statement,
    )?;
    ensure!(
        entry.claim == expected_claim,
        "row 147 catalogue claim differs from the authenticated alternate program"
    );

    let [source_step_zero, source_final] = source_projection.steps.as_slice() else {
        bail!("row 147 canonical source does not contain exactly Step0 and final");
    };
    ensure!(
        layout.logical_consumer_path == source_step_zero.raw_seal.path,
        "row 147 logical consumer path is not the canonical Step0 path"
    );
    let mut expected_projection = source_projection.clone();
    let expected_step_zero = expected_projection
        .steps
        .first_mut()
        .context("row 147 expected projection has no Step0")?;
    expected_step_zero.claim = expected_claim;
    expected_step_zero.terminal = expected_terminal(layout.witness_id, layout.producer_role)?;
    expected_step_zero.raw_seal =
        recursive_ancestry_artifact_reference(layout.logical_consumer_path.clone(), raw_seal)?;

    ensure!(
        projection == &expected_projection,
        "row 147 projection differs from canonical source plus its exact Step0 substitution"
    );
    let [projected_step_zero, projected_final] = projection.steps.as_slice() else {
        bail!("row 147 projection does not contain exactly Step0 and final");
    };
    ensure!(
        projection.assumption_receipt == source_projection.assumption_receipt
            && projected_final == source_final
            && projected_step_zero.ordinal == source_step_zero.ordinal
            && projected_step_zero.operation == source_step_zero.operation
            && projected_step_zero.claim.pre_state_digest
                == hex::encode(sources.alternate_program_id())
            && projected_step_zero.claim.pre_state_digest != projection.program_id,
        "row 147 changed inventory, final state, Step0 graph, or producer/consumer separation"
    );
    Ok(())
}

fn apply_inventory_recipe(
    layout: &B4NegativeAncestryWitnessLayoutV1,
    source: &RecursiveAncestryProjection,
    projection: &mut RecursiveAncestryProjection,
) -> Result<()> {
    match layout.expanded_row {
        153 => {
            projection
                .assumption_receipt
                .as_mut()
                .context("missing-inventory row has no assumption receipt")?
                .source_inventory
                .entries
                .clear();
        }
        154 => {
            let source_inventory = &source
                .assumption_receipt
                .as_ref()
                .context("extra-inventory row has no source assumption")?
                .source_inventory;
            let [head] = source_inventory.entries.as_slice() else {
                bail!("extra-inventory source does not contain exactly one revealed head");
            };
            projection
                .assumption_receipt
                .as_mut()
                .context("extra-inventory projection lost its assumption")?
                .source_inventory
                .entries = vec![head.clone(), head.clone()];
        }
        141 | 142 | 143 | 145 | 147 | 148 | 150 | 151 | 152 => {}
        _ => bail!("inventory dispatch is outside the eleven-row ancestry-witness layout"),
    }
    Ok(())
}

fn substitute_witness(
    layout: &B4NegativeAncestryWitnessLayoutV1,
    entry: &B4NegativeAncestryWitnessEntryV1,
    raw_seal: &[u8],
    projection: &mut RecursiveAncestryProjection,
) -> Result<()> {
    let reference =
        recursive_ancestry_artifact_reference(layout.logical_consumer_path.clone(), raw_seal)?;
    match layout.logical_placement {
        B4NegativeAncestryLogicalPlacementV1::AssumptionReceipt => {
            let assumption = projection
                .assumption_receipt
                .as_mut()
                .context("compiled assumption placement has no assumption receipt")?;
            ensure!(
                assumption.raw_seal.path == layout.logical_consumer_path,
                "compiled assumption placement differs from the positive source path"
            );
            assumption.claim = entry.claim.clone();
            assumption.terminal = entry.terminal.clone();
            assumption.raw_seal = reference;
        }
        B4NegativeAncestryLogicalPlacementV1::Step0 => {
            let step = projection
                .steps
                .get_mut(0)
                .context("compiled step-zero placement has no ancestry step zero")?;
            ensure!(
                step.raw_seal.path == layout.logical_consumer_path,
                "compiled step-zero placement differs from the positive source path"
            );
            step.claim = entry.claim.clone();
            step.terminal = entry.terminal.clone();
            step.raw_seal = reference;
        }
        B4NegativeAncestryLogicalPlacementV1::Step2 => {
            let step = projection
                .steps
                .get_mut(2)
                .context("compiled step-two placement has no ancestry step two")?;
            ensure!(
                step.raw_seal.path == layout.logical_consumer_path,
                "compiled step-two placement differs from the positive source path"
            );
            step.claim = entry.claim.clone();
            step.terminal = entry.terminal.clone();
            step.raw_seal = reference;
        }
        B4NegativeAncestryLogicalPlacementV1::FinalReceipt => {
            let step = projection
                .steps
                .last_mut()
                .context("compiled final placement has no final ancestry step")?;
            ensure!(
                step.raw_seal.path == layout.logical_consumer_path,
                "compiled final placement differs from the positive source path"
            );
            step.claim = entry.claim.clone();
            step.terminal = entry.terminal.clone();
            step.raw_seal = reference;
        }
    }
    Ok(())
}

fn expected_semantic_outcome(
    layout: &B4NegativeAncestryWitnessLayoutV1,
) -> Result<RecursiveAncestrySemanticOutcome> {
    match layout.expanded_row {
        141..=143 => Ok(RecursiveAncestrySemanticOutcome::ClaimEdge),
        145 | 147 | 148 => Ok(RecursiveAncestrySemanticOutcome::ResolveExplicit),
        150..=152 => Ok(RecursiveAncestrySemanticOutcome::ResolveZeroRoot),
        153 => Ok(RecursiveAncestrySemanticOutcome::AssumptionInventory(
            RecursiveAncestryInventoryDefect::Missing,
        )),
        154 => Ok(RecursiveAncestrySemanticOutcome::AssumptionInventory(
            RecursiveAncestryInventoryDefect::Extra,
        )),
        _ => bail!("semantic outcome is outside the eleven-row ancestry-witness layout"),
    }
}

/// Borrowed local diagnostic inputs, not a materialization or campaign authority.
#[cfg(test)]
pub(crate) struct LocalWitnessAncestryInput<'a> {
    pub(crate) ancestry: &'a [u8],
    pub(crate) statement: &'a [u8],
    pub(crate) final_raw_seal: &'a [u8],
    pub(crate) auxiliary_map: &'a [u8],
    pub(crate) manifest: &'a [u8],
    pub(crate) alternate_guest: &'a [u8],
}

#[cfg(test)]
struct LocalWitnessSources<'a> {
    input: LocalWitnessAncestryInput<'a>,
    plan: Vec<u8>,
    projection: RecursiveAncestryProjection,
    auxiliary: B4RecursiveAuxiliaryMapV1<'a>,
    profile: [u8; DIGEST_BYTES],
    alternate_program: [u8; DIGEST_BYTES],
}

#[cfg(test)]
impl AuthenticatedNegativeAncestrySources for LocalWitnessSources<'_> {
    fn negative_plan_jcs(&self) -> &[u8] { &self.plan }
    fn profile_manifest_context(&self) -> &[u8] { self.input.manifest }
    fn ancestry_jcs(&self) -> &[u8] { self.input.ancestry }
    fn projection(&self) -> &RecursiveAncestryProjection { &self.projection }
    fn statement(&self) -> &[u8] { self.input.statement }
    fn final_raw_seal(&self) -> &[u8] { self.input.final_raw_seal }
    fn auxiliary_seals(&self) -> &B4RecursiveAuxiliaryMapV1<'_> { &self.auxiliary }
    fn profile_id(&self) -> [u8; DIGEST_BYTES] { self.profile }
    fn alternate_program_id(&self) -> [u8; DIGEST_BYTES] { self.alternate_program }
}

/// Reuse the exact production mutation core, after local receipt authentication.
/// The caller must first authenticate the unmodified positive consumer subject.
/// Only envelope bytes escape; no catalogue, read-set, or campaign authority is minted.
#[cfg(test)]
pub(crate) fn reconstruct_genuine_witness_ancestry(
    index: usize,
    input: LocalWitnessAncestryInput<'_>,
    raw: &[u8],
    oracle: &[u8],
) -> Result<Vec<u8>> {
    let layout = compiled_negative_ancestry_witness_layout()?;
    let selected = layout.iter().find(|row| usize::from(row.expanded_row) == index)
        .context("local witness ancestry requires a compiled witness row")?;
    ensure!(input.manifest == include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin"),
        "local witness manifest differs from compiled profile");
    let manifest = StarkProfileManifestV1::decode(input.manifest)?;
    manifest.validate_initial_profile_target()?;
    let profile = manifest.profile_id()?;
    let projection = parse_recursive_ancestry_jcs(input.ancestry)?;
    ensure!(projection.family == selected.base_family
        && recursive_ancestry_to_jcs(&projection)? == input.ancestry,
        "local witness base family or canonical bytes differ");
    ensure!(classify_recursive_ancestry_semantics(&projection, input.statement, profile)?
        == RecursiveAncestrySemanticOutcome::Canonical,
        "local witness base is not canonical positive evidence");
    let auxiliary = crate::b4_recursive_auxiliary_map::decode_recursive_auxiliary_map(
        input.auxiliary_map, selected.base_family)?;
    let artifacts = auxiliary.iter().map(|(p, b)| (p.to_owned(), b)).collect::<BTreeMap<_, _>>();
    validate_recursive_ancestry_artifacts(&projection, input.statement,
        input.final_raw_seal, &artifacts)?;
    let alternate_program: [u8; DIGEST_BYTES] = compute_image_id(input.alternate_guest)?.into();
    let statement = parse_ergo_statement_v1(input.statement)?;
    let consumer = statement.program_id();
    ensure!(statement.encode()?.as_slice() == input.statement && statement.profile_id() == profile
        && projection.program_id == hex::encode(consumer) && alternate_program != consumer,
        "local witness statement, profile or alternate program differs");
    let sources = LocalWitnessSources { input, plan: Eip0045B4NegativePlanV1::canonical()?.to_canonical_jcs()?,
        projection, auxiliary, profile, alternate_program };
    let (claim, terminal, control_root) =
        crate::b4_negative_ancestry_authority::replay_local_ancestry_receipt(raw, oracle)?;
    ensure!(terminal == expected_terminal(selected.witness_id, selected.producer_role)?
        && control_root == hex::encode(manifest.inner_control_root()),
        "local witness receipt terminal or root differs from compiled row");
    let expected = derive_expected_witness_claim_for_programs(selected, &hex::encode(consumer),
        &hex::encode(alternate_program), &sources)?;
    ensure!(claim == expected, "local witness receipt claim differs from source-derived row");
    // This is an untrusted data projection, never a catalogue authority.
    let entry = B4NegativeAncestryWitnessEntryV1 {
        expanded_row: selected.expanded_row, execution_id: selected.execution_id.clone(),
        base_family: selected.base_family, witness_id: selected.witness_id,
        producer_role: selected.producer_role, logical_placement: selected.logical_placement,
        recipe: selected.recipe, logical_consumer_path: selected.logical_consumer_path.clone(),
        first_public_rejection: selected.first_public_rejection.clone(),
        claim_digest: hex::encode(recursive_ancestry_claim_digest(&claim)?),
        producer_program_id: claim.pre_state_digest.clone(), claim, terminal, control_root,
        raw_seal: B4ContractArtifactIdentityV1::from_bytes(&selected.raw_seal_path,
            B4ContractArtifactEncodingV1::RawBytes, raw)?,
        receipt_oracle: B4ContractArtifactIdentityV1::from_bytes(&selected.receipt_oracle_path,
            B4ContractArtifactEncodingV1::RawBytes, oracle)?,
    };
    Ok(replay_witness_materialization(selected, &entry, &sources, raw)?.final_subject)
}

#[cfg(test)]
mod tests {
    #[test]
    fn local_witness_seam_rejects_non_witness_rows_before_receipt_replay() {
        for index in [0, 140, 144, 146, 149, 155, 156, usize::MAX] {
            let input = super::LocalWitnessAncestryInput { ancestry: &[], statement: &[],
                final_raw_seal: &[], auxiliary_map: &[], manifest: &[], alternate_guest: &[] };
            assert_eq!(super::reconstruct_genuine_witness_ancestry(index, input, &[], &[])
                .unwrap_err().to_string(), "local witness ancestry requires a compiled witness row");
        }
        for index in [141, 142, 143, 145, 147, 148, 150, 151, 152, 153, 154] {
            let input = super::LocalWitnessAncestryInput { ancestry: &[], statement: &[],
                final_raw_seal: &[], auxiliary_map: &[], manifest: &[], alternate_guest: &[] };
            assert_eq!(super::reconstruct_genuine_witness_ancestry(index, input, &[], &[])
                .unwrap_err().to_string(), "local witness manifest differs from compiled profile");
        }
    }

    use anyhow::Context as _;

    use crate::{
        b4::{B4NegativeAncestryWitnessRecipeV1, B4NegativeMaterialization, B4NegativeMutation},
        b4_campaign_contract::{B4ContractArtifactEncodingV1, B4ContractArtifactIdentityV1},
        b4_fixture_sources::B4FixtureSourceResolverV1,
        b4_materialization_set::authority_tdd_tests::{
            B4NegativeAncestryProducerTestInputsV1, exact_negative_ancestry_producer_test_inputs,
        },
        b4_negative_ancestry_publication::B4NegativeAncestryPublicationReadSetV2,
        b4_negative_ancestry_witness::{
            B4NegativeAncestryLogicalPlacementV1, B4NegativeAncestryWitnessIdV1,
            compiled_negative_ancestry_witness_layout, expected_terminal,
        },
        b4_plan::{
            B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanFixture,
            B4NegativeQaResultCode, Eip0045B4NegativePlanV1,
        },
        b4_recursive_auxiliary_map::decode_recursive_auxiliary_map,
        b4_subject_envelope::{ancestry_subject_envelope_contract, decode_subject_envelope},
        recursive_ancestry::{
            RecursiveAncestryFamily, RecursiveAncestrySemanticOutcome,
            classify_recursive_ancestry_semantics, parse_recursive_ancestry_jcs,
        },
    };

    use super::{
        AuthenticatedNegativeAncestrySources, NegativeAncestrySources, apply_inventory_recipe,
        derive_expected_witness_claim, expected_semantic_outcome,
        reconstruct_negative_ancestry_witness_execution,
        reconstruct_negative_ancestry_witness_execution_v2, substitute_witness,
        validate_row_147_alternate_program_step_zero, validate_row_authority,
    };

    fn exact_fixture() -> B4NegativeAncestryProducerTestInputsV1 {
        exact_negative_ancestry_producer_test_inputs().unwrap()
    }

    #[test]
    fn v2_authority_entrypoint_requires_v2_top_level_family_and_read_set() {
        type ProducerV2 = fn(
            usize,
            &crate::b4_plan::B4NegativePlanExecutionV1,
            &crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV2,
            &B4NegativeAncestryPublicationReadSetV2,
        ) -> anyhow::Result<
            Option<crate::b4_materialization_set::B4ClosedReconstructedExecutionV1>,
        >;
        let producer: ProducerV2 = reconstruct_negative_ancestry_witness_execution_v2;
        std::hint::black_box(producer);

        let source = include_str!("b4_c2_negative_ancestry_witness.rs");
        let v2_entry = source
            .split("pub(crate) fn reconstruct_negative_ancestry_witness_execution_v2")
            .nth(1)
            .unwrap()
            .split("fn reconstruct_negative_ancestry_witness_execution_from_sources")
            .next()
            .unwrap();
        assert!(v2_entry.contains("B4AuthenticatedMaterializationTopLevelV2"));
        assert!(v2_entry.contains("B4NegativeAncestryPublicationReadSetV2"));
        assert!(v2_entry.contains("NegativeAncestrySourcesV2::authenticate"));
        assert!(!v2_entry.contains("B4FixtureSourceResolverV1"));

        let authentication = source
            .split("impl<'a> NegativeAncestrySourcesV2<'a>")
            .nth(1)
            .unwrap()
            .split("impl AuthenticatedNegativeAncestrySources for NegativeAncestrySourcesV2")
            .next()
            .unwrap();
        assert!(authentication.contains("B4MaterializationFixtureSourceResolverV2"));
        assert!(authentication.contains("recursive_ancestry_source(layout.base_family)"));
        assert!(authentication.contains("read_set.alternate_guest_elf()"));
        assert!(!authentication.contains("B4FixtureSourceResolverV1"));
        assert!(!source.contains(&["from_v2_read_set_", "v1_sources"].concat()));
        assert!(
            !source.contains(&["impl From<", "B4NegativeAncestryPublicationReadSetV2"].concat())
        );
        assert!(
            !source.contains(&["impl Into<", "B4NegativeAncestryPublicationReadSetV1"].concat())
        );
        assert!(
            !source.contains(&["impl From<", "B4AuthenticatedMaterializationTopLevelV2"].concat())
        );
        assert!(
            !source.contains(&["impl Into<", "B4AuthenticatedMaterializationTopLevelV1"].concat())
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the exact eleven-row matrix keeps every placement, consumer identity, and first semantic rejection visible"
    )]
    fn all_eleven_rows_reconstruct_only_the_compiled_witness_placement() {
        let fixture = exact_fixture();
        let plan =
            Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.top_level.negative_plan).unwrap();
        let planned = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .collect::<Vec<_>>();
        let resolver = B4FixtureSourceResolverV1::from_authenticated(&fixture.top_level).unwrap();

        for layout in compiled_negative_ancestry_witness_layout().unwrap() {
            let index = usize::from(layout.expanded_row);
            let source = resolver
                .recursive_ancestry_source(layout.base_family)
                .unwrap();
            let source_auxiliary = source.encoded_auxiliary_map().unwrap();
            let (selected_raw_seal, _) = fixture
                .read_set
                .compiled_row_witness(layout.expanded_row)
                .unwrap();
            let catalog_entry = fixture
                .read_set
                .catalog()
                .entries
                .iter()
                .find(|entry| entry.expanded_row == layout.expanded_row)
                .unwrap();

            let reconstructed = reconstruct_negative_ancestry_witness_execution(
                index,
                planned[index],
                &fixture.top_level,
                &fixture.read_set,
            )
            .unwrap()
            .unwrap();
            assert_eq!(reconstructed.base, source.ancestry_jcs());
            assert_eq!(
                reconstructed.contexts,
                vec![source.profile_manifest_context().to_vec()]
            );
            assert_eq!(
                reconstructed.derived_registry_row.materialization,
                B4NegativeMaterialization::Mutation {
                    mutation: B4NegativeMutation::AncestryWitnessSubstitution {
                        recipe: layout.recipe,
                    },
                }
            );

            let envelope = decode_subject_envelope(
                &reconstructed.subject,
                ancestry_subject_envelope_contract(),
            )
            .unwrap();
            let [ancestry, statement, final_raw_seal, auxiliary]: [&[u8]; 4] =
                envelope.parts().try_into().unwrap();
            let projection = parse_recursive_ancestry_jcs(ancestry).unwrap();
            assert_eq!(statement, source.statement());
            assert_eq!(projection.program_id, source.projection().program_id);
            assert_eq!(projection.statement, source.projection().statement);
            if layout.expanded_row == 147 {
                let sources = NegativeAncestrySources::authenticate(
                    &fixture.top_level,
                    &layout,
                    &fixture.read_set,
                )
                .unwrap();
                validate_row_147_alternate_program_step_zero(
                    &layout,
                    catalog_entry,
                    &sources,
                    selected_raw_seal,
                    source.projection(),
                    &projection,
                )
                .unwrap();
            }
            {
                assert_eq!(
                    classify_recursive_ancestry_semantics(
                        &projection,
                        statement,
                        hex::decode(&projection.profile_id)
                            .unwrap()
                            .try_into()
                            .unwrap(),
                    )
                    .with_context(|| {
                        format!(
                            "decoded negative ancestry row {} ({})",
                            layout.expanded_row, layout.execution_id
                        )
                    })
                    .unwrap(),
                    expected_semantic_outcome(&layout).unwrap()
                );
            }

            let decoded_auxiliary =
                decode_recursive_auxiliary_map(auxiliary, layout.base_family).unwrap();
            if layout.logical_placement == B4NegativeAncestryLogicalPlacementV1::FinalReceipt {
                assert_eq!(final_raw_seal, selected_raw_seal);
                assert_eq!(auxiliary, source_auxiliary);
            } else {
                assert_eq!(final_raw_seal, source.final_raw_seal());
                assert_eq!(
                    decoded_auxiliary
                        .get(&layout.logical_consumer_path)
                        .unwrap(),
                    selected_raw_seal
                );
                for (path, source_bytes) in source.auxiliary_seals().iter() {
                    let expected = if path == layout.logical_consumer_path {
                        selected_raw_seal
                    } else {
                        source_bytes
                    };
                    assert_eq!(decoded_auxiliary.get(path).unwrap(), expected);
                }
            }

            if layout.expanded_row == 153 {
                assert!(
                    projection
                        .assumption_receipt
                        .as_ref()
                        .unwrap()
                        .source_inventory
                        .entries
                        .is_empty()
                );
            }
            if layout.expanded_row == 154 {
                let entries = &projection
                    .assumption_receipt
                    .as_ref()
                    .unwrap()
                    .source_inventory
                    .entries;
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0], entries[1]);
            }
            if matches!(layout.expanded_row, 147 | 151) {
                assert_eq!(
                    projection.program_id,
                    fixture.read_set.catalog().consumer_program_id
                );
                assert_ne!(projection.program_id, catalog_entry.producer_program_id);
            }
        }
    }

    #[test]
    fn row_147_rejects_program_or_inventory_drift() {
        let fixture = exact_fixture();
        let layout = compiled_negative_ancestry_witness_layout().unwrap();
        let selected = layout
            .iter()
            .find(|candidate| candidate.expanded_row == 147)
            .unwrap();
        let entry = fixture
            .read_set
            .catalog()
            .entries
            .iter()
            .find(|candidate| candidate.expanded_row == 147)
            .unwrap();
        let sources =
            NegativeAncestrySources::authenticate(&fixture.top_level, selected, &fixture.read_set)
                .unwrap();
        let (raw_seal, _) = fixture.read_set.compiled_row_witness(147).unwrap();
        let source_projection = sources.view.projection();
        let mut projection = source_projection.clone();
        apply_inventory_recipe(selected, source_projection, &mut projection).unwrap();
        substitute_witness(selected, entry, raw_seal, &mut projection).unwrap();
        validate_row_147_alternate_program_step_zero(
            selected,
            entry,
            &sources,
            raw_seal,
            source_projection,
            &projection,
        )
        .unwrap();

        let mut program_drift = projection.clone();
        program_drift.steps[0].claim.pre_state_digest = source_projection.program_id.clone();
        assert!(
            validate_row_147_alternate_program_step_zero(
                selected,
                entry,
                &sources,
                raw_seal,
                source_projection,
                &program_drift,
            )
            .is_err()
        );

        let mut inventory_drift = projection.clone();
        inventory_drift
            .assumption_receipt
            .as_mut()
            .unwrap()
            .source_inventory
            .entries
            .clear();
        assert!(
            validate_row_147_alternate_program_step_zero(
                selected,
                entry,
                &sources,
                raw_seal,
                source_projection,
                &inventory_drift,
            )
            .is_err()
        );

        let mut coordinated_drift = projection;
        coordinated_drift.steps[0].claim.pre_state_digest = source_projection.program_id.clone();
        coordinated_drift
            .assumption_receipt
            .as_mut()
            .unwrap()
            .source_inventory
            .entries
            .clear();
        assert!(
            validate_row_147_alternate_program_step_zero(
                selected,
                entry,
                &sources,
                raw_seal,
                source_projection,
                &coordinated_drift,
            )
            .is_err()
        );
    }

    #[test]
    fn row_147_rejects_any_change_outside_step_zero() {
        let fixture = exact_fixture();
        let layout = compiled_negative_ancestry_witness_layout().unwrap();
        let selected = layout
            .iter()
            .find(|candidate| candidate.expanded_row == 147)
            .unwrap();
        let entry = fixture
            .read_set
            .catalog()
            .entries
            .iter()
            .find(|candidate| candidate.expanded_row == 147)
            .unwrap();
        let sources =
            NegativeAncestrySources::authenticate(&fixture.top_level, selected, &fixture.read_set)
                .unwrap();
        let (raw_seal, _) = fixture.read_set.compiled_row_witness(147).unwrap();
        let source_projection = sources.view.projection();
        let mut projection = source_projection.clone();
        apply_inventory_recipe(selected, source_projection, &mut projection).unwrap();
        substitute_witness(selected, entry, raw_seal, &mut projection).unwrap();

        projection.steps[1].claim.user_exit ^= 1;
        assert!(
            validate_row_147_alternate_program_step_zero(
                selected,
                entry,
                &sources,
                raw_seal,
                source_projection,
                &projection,
            )
            .is_err()
        );
    }

    #[test]
    fn producer_scope_excludes_row_146_and_plan_drift_fails_closed() {
        let fixture = exact_fixture();
        let plan =
            Eip0045B4NegativePlanV1::from_canonical_jcs(&fixture.top_level.negative_plan).unwrap();
        let planned = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .collect::<Vec<_>>();

        for index in [0, 140, 144, 146, 149, 155, 156, 253] {
            assert!(
                reconstruct_negative_ancestry_witness_execution(
                    index,
                    planned[index],
                    &fixture.top_level,
                    &fixture.read_set,
                )
                .unwrap()
                .is_none()
            );
        }

        let mut wrong = planned[141].clone();
        wrong.execution_id.push('x');
        assert!(
            reconstruct_negative_ancestry_witness_execution(
                141,
                &wrong,
                &fixture.top_level,
                &fixture.read_set,
            )
            .is_err()
        );

        let mut wrong = planned[145].clone();
        wrong.fixture = B4NegativePlanFixture::Case10TypedAncestryV1;
        assert!(
            reconstruct_negative_ancestry_witness_execution(
                145,
                &wrong,
                &fixture.top_level,
                &fixture.read_set,
            )
            .is_err()
        );

        let mut wrong = planned[147].clone();
        wrong.materialization_domain = B4MaterializationDomain::ArtifactValidator;
        assert!(
            reconstruct_negative_ancestry_witness_execution(
                147,
                &wrong,
                &fixture.top_level,
                &fixture.read_set,
            )
            .is_err()
        );

        let mut wrong = planned[150].clone();
        wrong.execution_surface = B4NegativeExecutionSurface::ReceiptClaimPolicy;
        assert!(
            reconstruct_negative_ancestry_witness_execution(
                150,
                &wrong,
                &fixture.top_level,
                &fixture.read_set,
            )
            .is_err()
        );

        let mut wrong = planned[153].clone();
        wrong.qa_result_code = B4NegativeQaResultCode::B4AncestryClaimEdgeMismatch;
        assert!(
            reconstruct_negative_ancestry_witness_execution(
                153,
                &wrong,
                &fixture.top_level,
                &fixture.read_set,
            )
            .is_err()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "each mutation isolates one row, recipe, placement, physical-byte, or catalogue-closure predicate"
    )]
    fn row_authority_rejects_identity_recipe_placement_and_cross_row_drift() {
        let fixture = exact_fixture();
        let layout = compiled_negative_ancestry_witness_layout().unwrap();
        let selected = &layout[0];
        let entry = &fixture.read_set.catalog().entries[0];
        let sources =
            NegativeAncestrySources::authenticate(&fixture.top_level, selected, &fixture.read_set)
                .unwrap();
        let (raw_seal, receipt_oracle) = fixture
            .read_set
            .compiled_row_witness(selected.expanded_row)
            .unwrap();

        validate_row_authority(
            0,
            selected,
            entry,
            fixture.read_set.catalog(),
            &sources,
            sources.negative_plan_jcs(),
            &fixture.read_set,
            raw_seal,
            receipt_oracle,
        )
        .unwrap();

        let mut wrong_layout = selected.clone();
        wrong_layout.expanded_row = 142;
        assert!(
            validate_row_authority(
                0,
                &wrong_layout,
                entry,
                fixture.read_set.catalog(),
                &sources,
                sources.negative_plan_jcs(),
                &fixture.read_set,
                raw_seal,
                receipt_oracle,
            )
            .is_err()
        );

        let mut wrong_layout = selected.clone();
        wrong_layout.execution_id.push('x');
        assert!(
            validate_row_authority(
                0,
                &wrong_layout,
                entry,
                fixture.read_set.catalog(),
                &sources,
                sources.negative_plan_jcs(),
                &fixture.read_set,
                raw_seal,
                receipt_oracle,
            )
            .is_err()
        );

        let mut wrong_layout = selected.clone();
        wrong_layout.recipe =
            B4NegativeAncestryWitnessRecipeV1::ReuseCase9AssumptionAtTerminalResolveStep0;
        assert!(
            validate_row_authority(
                0,
                &wrong_layout,
                entry,
                fixture.read_set.catalog(),
                &sources,
                sources.negative_plan_jcs(),
                &fixture.read_set,
                raw_seal,
                receipt_oracle,
            )
            .is_err()
        );

        let mut wrong_layout = selected.clone();
        wrong_layout.logical_placement = B4NegativeAncestryLogicalPlacementV1::Step2;
        assert!(
            validate_row_authority(
                0,
                &wrong_layout,
                entry,
                fixture.read_set.catalog(),
                &sources,
                sources.negative_plan_jcs(),
                &fixture.read_set,
                raw_seal,
                receipt_oracle,
            )
            .is_err()
        );

        let mut raw_drift = raw_seal.to_vec();
        raw_drift[0] ^= 1;
        assert!(
            validate_row_authority(
                0,
                selected,
                entry,
                fixture.read_set.catalog(),
                &sources,
                sources.negative_plan_jcs(),
                &fixture.read_set,
                &raw_drift,
                receipt_oracle,
            )
            .is_err()
        );

        let mut oracle_drift = receipt_oracle.to_vec();
        oracle_drift[0] ^= 1;
        assert!(
            validate_row_authority(
                0,
                selected,
                entry,
                fixture.read_set.catalog(),
                &sources,
                sources.negative_plan_jcs(),
                &fixture.read_set,
                raw_seal,
                &oracle_drift,
            )
            .is_err()
        );

        let (cross_row_raw, cross_row_oracle) = fixture
            .read_set
            .compiled_row_witness(layout[3].expanded_row)
            .unwrap();
        assert!(
            validate_row_authority(
                0,
                selected,
                entry,
                fixture.read_set.catalog(),
                &sources,
                sources.negative_plan_jcs(),
                &fixture.read_set,
                cross_row_raw,
                cross_row_oracle,
            )
            .is_err()
        );

        let mut coordinated_entry = entry.clone();
        coordinated_entry.raw_seal = B4ContractArtifactIdentityV1::from_bytes(
            &selected.raw_seal_path,
            B4ContractArtifactEncodingV1::RawBytes,
            &raw_drift,
        )
        .unwrap();
        assert!(
            validate_row_authority(
                0,
                selected,
                &coordinated_entry,
                fixture.read_set.catalog(),
                &sources,
                sources.negative_plan_jcs(),
                &fixture.read_set,
                &raw_drift,
                receipt_oracle,
            )
            .is_err()
        );
    }

    #[test]
    fn claim_terminal_program_and_control_derivations_are_row_exact() {
        let fixture = exact_fixture();
        let layout = compiled_negative_ancestry_witness_layout().unwrap();
        let resolver = B4FixtureSourceResolverV1::from_authenticated(&fixture.top_level).unwrap();
        let catalog = fixture.read_set.catalog();

        for (selected, entry) in layout.iter().zip(&catalog.entries) {
            let sources = NegativeAncestrySources::authenticate(
                &fixture.top_level,
                selected,
                &fixture.read_set,
            )
            .unwrap();
            assert_eq!(
                entry.claim,
                derive_expected_witness_claim(selected, catalog, &sources).unwrap()
            );
            assert_eq!(
                entry.terminal,
                expected_terminal(selected.witness_id, selected.producer_role).unwrap()
            );
            assert_eq!(entry.control_root, catalog.inner_control_root);
            assert_eq!(entry.producer_program_id, entry.claim.pre_state_digest);

            let source = resolver
                .recursive_ancestry_source(selected.base_family)
                .unwrap();
            if matches!(selected.expanded_row, 147 | 151) {
                assert_eq!(entry.producer_program_id, catalog.alternate_program_id);
                assert_eq!(source.projection().program_id, catalog.consumer_program_id);
            } else {
                assert_eq!(entry.producer_program_id, catalog.consumer_program_id);
            }
        }

        let claim = |row| {
            catalog
                .entries
                .iter()
                .find(|entry| entry.expanded_row == row)
                .unwrap()
                .claim
                .clone()
        };
        assert_eq!(claim(141), claim(142));
        assert_eq!(claim(141), claim(143));
        assert_eq!(claim(141), claim(153));
        assert_eq!(claim(145), claim(148));
        assert_eq!(claim(145), claim(150));
        assert_eq!(claim(145), claim(152));
        assert_eq!(claim(147), claim(151));
        assert_ne!(claim(141), claim(145));
        assert_ne!(claim(141), claim(147));
        assert_ne!(claim(141), claim(154));
        assert_eq!(
            catalog
                .entries
                .iter()
                .find(|entry| entry.expanded_row == 154)
                .unwrap()
                .witness_id,
            B4NegativeAncestryWitnessIdV1::DuplicateAssumptionLift
        );
        assert_eq!(
            expected_semantic_outcome(&layout[0]).unwrap(),
            RecursiveAncestrySemanticOutcome::ClaimEdge
        );
        assert_eq!(layout[0].base_family, RecursiveAncestryFamily::TerminalJoin);
    }
}
