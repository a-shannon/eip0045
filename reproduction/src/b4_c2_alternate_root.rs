//! Closed E6 producers for the sole fixed alternate-root witness.
//!
//! The proof authority is minted elsewhere only after receipt and raw-STARK
//! replay. This module can consume that authority for exactly two rows: the
//! direct raw-seal root mismatch and the case-9 assumption-root mismatch.

use std::{collections::BTreeMap, fmt};

use anyhow::{Context as _, Result, bail, ensure};
use sha2::{Digest as _, Sha256};

use crate::{
    b4::{B4NegativeCase, B4NegativeMaterialization, B4NegativeMutation},
    b4_alternate_root_authority::B4FixedAlternateRootProofAuthorityV1,
    b4_c2_opcode_sequence::{encode_opcode_subject, split_raw_seal},
    b4_fixture_sources::{
        B4FixtureSourceResolverV1, B4MaterializationFixtureSourceResolverV2,
        B4RecursiveAncestrySourceViewV1, B4RecursiveAncestrySourceViewV2,
    },
    b4_materialization_set::{
        B4AuthenticatedMaterializationTopLevelV1, B4AuthenticatedMaterializationTopLevelV2,
        B4ClosedReconstructedExecutionV1, close_production_execution,
    },
    b4_mutation::B4MaterializationReplayAdapterV1,
    b4_plan::{
        B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanExecutionV1,
        B4NegativePlanFixture, B4NegativeQaResultCode, Eip0045B4NegativePlanV1,
    },
    b4_recursive_auxiliary_map::{B4RecursiveAuxiliaryMapV1, encode_recursive_auxiliary_map},
    b4_subject_envelope::{ancestry_subject_envelope_contract, encode_subject_envelope},
    recursive_ancestry::{
        RecursiveAncestryFamily, RecursiveAncestrySemanticOutcome,
        classify_recursive_ancestry_semantics, parse_recursive_ancestry_jcs,
        recursive_ancestry_to_jcs, validate_recursive_ancestry_artifacts,
    },
};

const ROW_108_INDEX: usize = 108;
const ROW_108_EXECUTION_ID: &str = "terminal-inner-root-mismatch--inner-control-root";
const ROW_108_SELECTOR: &str = "alternate-root-lift-po2-15-v1";
const ROW_146_INDEX: usize = 146;
const ROW_146_EXECUTION_ID: &str = "resolve-explicit-field-sweep--assumption-receipt-root";
const ROW_146_SELECTOR: &str = "case9-typed-ancestry-v1";

#[derive(Clone, Copy)]
struct ExpectedRow {
    index: usize,
    execution_id: &'static str,
    variant_id: &'static str,
    selector: &'static str,
    fixture: B4NegativePlanFixture,
    surface: B4NegativeExecutionSurface,
    qa_result: B4NegativeQaResultCode,
}

const EXPECTED_ROWS: [ExpectedRow; 2] = [
    ExpectedRow {
        index: ROW_108_INDEX,
        execution_id: ROW_108_EXECUTION_ID,
        variant_id: "inner-control-root",
        selector: ROW_108_SELECTOR,
        fixture: B4NegativePlanFixture::AlternateRootLiftPo215V1,
        surface: B4NegativeExecutionSurface::RawSealShape,
        qa_result: B4NegativeQaResultCode::RawSealInnerControlRootMismatch,
    },
    ExpectedRow {
        index: ROW_146_INDEX,
        execution_id: ROW_146_EXECUTION_ID,
        variant_id: "assumption-receipt-root",
        selector: ROW_146_SELECTOR,
        fixture: B4NegativePlanFixture::Case9TypedAncestryV1,
        surface: B4NegativeExecutionSurface::AncestryReplay,
        qa_result: B4NegativeQaResultCode::B4ResolveExplicitSemanticsMismatch,
    },
];

#[cfg(test)]
pub(crate) const fn alternate_root_execution_indices() -> [usize; 2] {
    [EXPECTED_ROWS[0].index, EXPECTED_ROWS[1].index]
}

struct AlternateSources<'a> {
    negative_plan_jcs: &'a [u8],
    profile_manifest: &'a [u8],
    statement: &'a [u8],
    application_payload: &'a [u8],
    program_id: [u8; 32],
    profile_id: [u8; 32],
    case9: B4RecursiveAncestrySourceViewV1<'a>,
}

struct AlternateSourcesV2<'a> {
    negative_plan_jcs: &'a [u8],
    profile_manifest: &'a [u8],
    statement: &'a [u8],
    application_payload: &'a [u8],
    program_id: [u8; 32],
    profile_id: [u8; 32],
    case9: B4RecursiveAncestrySourceViewV2<'a>,
}

trait AuthenticatedAlternateSources {
    fn negative_plan_jcs(&self) -> &[u8];
    fn profile_manifest(&self) -> &[u8];
    fn statement(&self) -> &[u8];
    fn application_payload(&self) -> &[u8];
    fn program_id(&self) -> [u8; 32];
    fn profile_id(&self) -> [u8; 32];
    fn case9_ancestry_jcs(&self) -> &[u8];
    fn case9_projection(&self) -> &crate::recursive_ancestry::RecursiveAncestryProjection;
    fn case9_statement(&self) -> &[u8];
    fn case9_final_raw_seal(&self) -> &[u8];
    fn case9_auxiliary_seals(&self) -> &B4RecursiveAuxiliaryMapV1<'_>;
}

impl<'a> AlternateSources<'a> {
    fn authenticate(top_level: &'a B4AuthenticatedMaterializationTopLevelV1) -> Result<Self> {
        let resolver = B4FixtureSourceResolverV1::from_authenticated(top_level)
            .context("alternate-root producer cannot authenticate fixture sources")?;
        let input = resolver
            .positive_input()
            .context("alternate-root producer cannot authenticate the positive input")?;
        input
            .initial_profile_manifest()
            .context("alternate-root producer requires the exact initial profile")?;
        let reference = resolver
            .case_zero_reference_statement()
            .context("alternate-root producer cannot authenticate the global statement")?;
        let case9 = resolver
            .recursive_ancestry_source(RecursiveAncestryFamily::TerminalResolve)
            .context("alternate-root producer cannot authenticate case-9 ancestry")?;
        ensure!(
            case9.statement() == reference.statement_bytes(),
            "case-9 ancestry statement differs from the global alternate-root request"
        );
        Ok(Self {
            negative_plan_jcs: &top_level.negative_plan,
            profile_manifest: input.profile_manifest(),
            statement: reference.statement_bytes(),
            application_payload: reference.statement().application_payload(),
            program_id: reference.program_id(),
            profile_id: reference.profile_id(),
            case9,
        })
    }
}

impl AuthenticatedAlternateSources for AlternateSources<'_> {
    fn negative_plan_jcs(&self) -> &[u8] {
        self.negative_plan_jcs
    }

    fn profile_manifest(&self) -> &[u8] {
        self.profile_manifest
    }

    fn statement(&self) -> &[u8] {
        self.statement
    }

    fn application_payload(&self) -> &[u8] {
        self.application_payload
    }

    fn program_id(&self) -> [u8; 32] {
        self.program_id
    }

    fn profile_id(&self) -> [u8; 32] {
        self.profile_id
    }

    fn case9_ancestry_jcs(&self) -> &[u8] {
        self.case9.ancestry_jcs()
    }

    fn case9_projection(&self) -> &crate::recursive_ancestry::RecursiveAncestryProjection {
        self.case9.projection()
    }

    fn case9_statement(&self) -> &[u8] {
        self.case9.statement()
    }

    fn case9_final_raw_seal(&self) -> &[u8] {
        self.case9.final_raw_seal()
    }

    fn case9_auxiliary_seals(&self) -> &B4RecursiveAuxiliaryMapV1<'_> {
        self.case9.auxiliary_seals()
    }
}

impl<'a> AlternateSourcesV2<'a> {
    fn authenticate(top_level: &'a B4AuthenticatedMaterializationTopLevelV2) -> Result<Self> {
        let resolver = B4MaterializationFixtureSourceResolverV2::from_authenticated(top_level)
            .context("V2 alternate-root producer cannot authenticate fixture sources")?;
        let input = resolver
            .positive_input()
            .context("V2 alternate-root producer cannot authenticate the positive input")?;
        input
            .initial_profile_manifest()
            .context("V2 alternate-root producer requires the exact initial profile")?;
        let reference = resolver
            .case_zero_reference_statement()
            .context("V2 alternate-root producer cannot authenticate the global statement")?;
        let case9 = resolver
            .recursive_ancestry_source(RecursiveAncestryFamily::TerminalResolve)
            .context("V2 alternate-root producer cannot authenticate case-9 ancestry")?;
        ensure!(
            case9.statement() == reference.statement_bytes(),
            "V2 case-9 ancestry statement differs from the global alternate-root request"
        );
        Ok(Self {
            negative_plan_jcs: resolver.negative_plan_jcs(),
            profile_manifest: input.profile_manifest(),
            statement: reference.statement_bytes(),
            application_payload: reference.statement().application_payload(),
            program_id: reference.program_id(),
            profile_id: reference.profile_id(),
            case9,
        })
    }
}

impl AuthenticatedAlternateSources for AlternateSourcesV2<'_> {
    fn negative_plan_jcs(&self) -> &[u8] {
        self.negative_plan_jcs
    }

    fn profile_manifest(&self) -> &[u8] {
        self.profile_manifest
    }

    fn statement(&self) -> &[u8] {
        self.statement
    }

    fn application_payload(&self) -> &[u8] {
        self.application_payload
    }

    fn program_id(&self) -> [u8; 32] {
        self.program_id
    }

    fn profile_id(&self) -> [u8; 32] {
        self.profile_id
    }

    fn case9_ancestry_jcs(&self) -> &[u8] {
        self.case9.ancestry_jcs()
    }

    fn case9_projection(&self) -> &crate::recursive_ancestry::RecursiveAncestryProjection {
        self.case9.projection()
    }

    fn case9_statement(&self) -> &[u8] {
        self.case9.statement()
    }

    fn case9_final_raw_seal(&self) -> &[u8] {
        self.case9.final_raw_seal()
    }

    fn case9_auxiliary_seals(&self) -> &B4RecursiveAuxiliaryMapV1<'_> {
        self.case9.auxiliary_seals()
    }
}

struct ReplayedAlternateRoot {
    raw_output: Vec<u8>,
    final_subject: Vec<u8>,
}

#[derive(Clone, Copy)]
enum AdapterOutput {
    Raw,
    Final,
}

struct AlternateRootReplayAdapter<'a, 'authority, S> {
    expected: ExpectedRow,
    sources: &'a S,
    alternate: &'authority B4FixedAlternateRootProofAuthorityV1,
    materialization: &'a B4NegativeMaterialization,
    output: &'a [u8],
    output_kind: AdapterOutput,
}

impl<S> fmt::Debug for AlternateRootReplayAdapter<'_, '_, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AlternateRootReplayAdapter")
            .field("execution_index", &self.expected.index)
            .finish_non_exhaustive()
    }
}

impl<S: AuthenticatedAlternateSources> B4MaterializationReplayAdapterV1
    for AlternateRootReplayAdapter<'_, '_, S>
{
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::VerifierInput
    }

    fn base_bytes(&self) -> &[u8] {
        match self.expected.index {
            ROW_108_INDEX => self.alternate.raw_seal(),
            ROW_146_INDEX => self.sources.case9_ancestry_jcs(),
            _ => unreachable!("closed alternate-root adapter has a compiled row"),
        }
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
            base_selector_id == self.expected.selector && materialization == self.materialization,
            "alternate-root replay adapter received a selector or recipe outside its closed row"
        );
        let replayed = replay_materialization(
            self.expected,
            self.sources,
            self.alternate.raw_seal(),
            materialization,
        )?;
        let expected = match self.output_kind {
            AdapterOutput::Raw => &replayed.raw_output,
            AdapterOutput::Final => &replayed.final_subject,
        };
        ensure!(
            self.output == expected,
            "alternate-root replay adapter output differs from typed reconstruction"
        );
        Ok(())
    }
}

/// Reconstruct only E6 rows 108 and 146 from one retained alternate-root proof
/// authority.
pub(crate) fn reconstruct_alternate_root_execution(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
    alternate: &B4FixedAlternateRootProofAuthorityV1,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    let Some(expected) = expected_row(execution_index) else {
        return Ok(None);
    };
    let sources = AlternateSources::authenticate(top_level)?;
    validate_planned_execution(expected, planned, sources.negative_plan_jcs())?;
    reconstruct_alternate_root_execution_from_sources(
        execution_index,
        planned,
        alternate,
        expected,
        &sources,
    )
}

/// Reconstruct rows 108 and 146 from the V2-authenticated fixture source.
pub(crate) fn reconstruct_alternate_root_execution_v2(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV2,
    alternate: &B4FixedAlternateRootProofAuthorityV1,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    let Some(expected) = expected_row(execution_index) else {
        return Ok(None);
    };
    let sources = AlternateSourcesV2::authenticate(top_level)?;
    validate_planned_execution(expected, planned, sources.negative_plan_jcs())?;
    reconstruct_alternate_root_execution_from_sources(
        execution_index,
        planned,
        alternate,
        expected,
        &sources,
    )
}

fn reconstruct_alternate_root_execution_from_sources<S: AuthenticatedAlternateSources>(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    alternate: &B4FixedAlternateRootProofAuthorityV1,
    expected: ExpectedRow,
    sources: &S,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    ensure!(
        alternate.statement() == sources.statement(),
        "alternate-root authority statement differs from the authenticated materialization statement"
    );
    let materialization = expected_materialization(expected);
    let replayed =
        replay_materialization(expected, sources, alternate.raw_seal(), &materialization)?;
    let expected_materialization = materialization.clone();
    let registry_row = B4NegativeCase {
        execution_id: expected.execution_id.to_owned(),
        base_selector_id: expected.selector.to_owned(),
        materialization_domain: B4MaterializationDomain::VerifierInput,
        materialization,
    };
    let raw_adapter = AlternateRootReplayAdapter {
        expected,
        sources,
        alternate,
        materialization: &expected_materialization,
        output: &replayed.raw_output,
        output_kind: AdapterOutput::Raw,
    };
    let final_adapter = AlternateRootReplayAdapter {
        expected,
        sources,
        alternate,
        materialization: &expected_materialization,
        output: &replayed.final_subject,
        output_kind: AdapterOutput::Final,
    };
    close_production_execution(
        execution_index,
        planned,
        sources.negative_plan_jcs(),
        registry_row,
        &raw_adapter,
        &final_adapter,
        replayed.final_subject.clone(),
        vec![sources.profile_manifest().to_vec()],
    )
    .map(Some)
}

fn expected_row(index: usize) -> Option<ExpectedRow> {
    EXPECTED_ROWS
        .iter()
        .copied()
        .find(|expected| expected.index == index)
}

fn validate_planned_execution(
    expected: ExpectedRow,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
) -> Result<()> {
    let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(negative_plan_jcs)
        .context("alternate-root producer negative plan is not canonical")?;
    let canonical = plan
        .groups
        .iter()
        .flat_map(|group| group.executions.iter())
        .nth(expected.index)
        .context("alternate-root producer index is outside the canonical plan")?;
    ensure!(
        canonical == planned
            && planned.execution_id == expected.execution_id
            && planned.variant_id == expected.variant_id
            && planned.base_selector_id == expected.selector
            && planned.fixture == expected.fixture
            && planned.materialization_domain == B4MaterializationDomain::VerifierInput
            && planned.execution_surface == expected.surface
            && planned.qa_result_code == expected.qa_result
            && planned.parser_truncation_words.is_none(),
        "alternate-root execution differs from its exact canonical-plan contract"
    );
    Ok(())
}

fn expected_materialization(expected: ExpectedRow) -> B4NegativeMaterialization {
    match expected.index {
        ROW_108_INDEX => B4NegativeMaterialization::FixtureSelection {
            fixture_id: ROW_108_SELECTOR.to_owned(),
        },
        ROW_146_INDEX => B4NegativeMaterialization::Mutation {
            mutation: B4NegativeMutation::AlternateRootAssumptionSubstitution {},
        },
        _ => unreachable!("expected row is selected only from the two-row table"),
    }
}

fn replay_materialization(
    expected: ExpectedRow,
    sources: &impl AuthenticatedAlternateSources,
    alternate_raw_seal: &[u8],
    materialization: &B4NegativeMaterialization,
) -> Result<ReplayedAlternateRoot> {
    ensure!(
        materialization == &expected_materialization(expected),
        "alternate-root materialization differs from its sole closed recipe"
    );
    match expected.index {
        ROW_108_INDEX => {
            let chunks = split_raw_seal(alternate_raw_seal)
                .context("alternate-root row 108 raw seal has the wrong exact transport shape")?;
            let final_subject = encode_opcode_subject(
                &chunks,
                sources.application_payload(),
                &sources.program_id(),
                &sources.profile_id(),
            )
            .context("alternate-root row 108 cannot encode its exact opcode subject")?;
            Ok(ReplayedAlternateRoot {
                raw_output: alternate_raw_seal.to_vec(),
                final_subject,
            })
        }
        ROW_146_INDEX => replay_case9_assumption_substitution(sources, alternate_raw_seal),
        _ => bail!("alternate-root replay requested outside rows 108 and 146"),
    }
}

fn replay_case9_assumption_substitution(
    sources: &impl AuthenticatedAlternateSources,
    alternate_raw_seal: &[u8],
) -> Result<ReplayedAlternateRoot> {
    let original = sources.case9_projection();
    let mut projection = original.clone();
    let assumption = projection
        .assumption_receipt
        .as_mut()
        .context("case-9 alternate-root substitution has no assumption receipt")?;
    let assumption_path = assumption.raw_seal.path.clone();
    let original_digest = assumption.raw_seal.sha256.clone();
    ensure!(
        assumption.raw_seal.byte_length == u64::try_from(alternate_raw_seal.len())?,
        "alternate-root seal length differs from the case-9 assumption reference"
    );
    let alternate_digest = sha256_hex(alternate_raw_seal);
    ensure!(
        alternate_digest != original_digest,
        "alternate-root assumption substitution would be a no-op"
    );
    assumption.raw_seal.sha256.clone_from(&alternate_digest);

    let mut expected = original.clone();
    expected
        .assumption_receipt
        .as_mut()
        .context("case-9 expected projection lost its assumption receipt")?
        .raw_seal
        .sha256
        .clone_from(&alternate_digest);
    ensure!(
        projection == expected,
        "alternate-root assumption substitution changed another ancestry field"
    );
    let raw_output = recursive_ancestry_to_jcs(&projection)?;
    ensure!(
        parse_recursive_ancestry_jcs(&raw_output)? == projection,
        "alternate-root ancestry substitution does not reparse byte-exactly"
    );
    ensure!(
        classify_recursive_ancestry_semantics(
            &projection,
            sources.case9_statement(),
            sources.profile_id(),
        )? == RecursiveAncestrySemanticOutcome::Canonical,
        "alternate-root substitution changed a structural ancestry semantic before authenticated-root comparison"
    );

    let entries = sources
        .case9_auxiliary_seals()
        .iter()
        .map(|(path, bytes)| {
            if path == assumption_path {
                (path, alternate_raw_seal)
            } else {
                (path, bytes)
            }
        })
        .collect::<Vec<_>>();
    ensure!(
        entries
            .iter()
            .filter(|(path, bytes)| *path == assumption_path && *bytes == alternate_raw_seal)
            .count()
            == 1,
        "alternate-root substitution did not replace exactly one assumption auxiliary entry"
    );
    let auxiliary = B4RecursiveAuxiliaryMapV1::from_exact_entries(
        RecursiveAncestryFamily::TerminalResolve,
        &entries,
    )?;
    let auxiliary_map = encode_recursive_auxiliary_map(&auxiliary)?;
    let borrowed = auxiliary
        .iter()
        .map(|(path, bytes)| (path.to_owned(), bytes))
        .collect::<BTreeMap<_, _>>();
    validate_recursive_ancestry_artifacts(
        &projection,
        sources.case9_statement(),
        sources.case9_final_raw_seal(),
        &borrowed,
    )
    .context("alternate-root row 146 ancestry references do not match the updated auxiliary map")?;

    let final_subject = encode_subject_envelope(
        &[
            &raw_output,
            sources.case9_statement(),
            sources.case9_final_raw_seal(),
            &auxiliary_map,
        ],
        ancestry_subject_envelope_contract(),
    )
    .context("alternate-root row 146 cannot encode its exact ancestry subject")?;
    Ok(ReplayedAlternateRoot {
        raw_output,
        final_subject,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Local test join only: the caller authenticates all Resolve seals separately.
/// This adapter mints no top-level or campaign authority and uses the real E6 core.
#[cfg(test)]
pub(crate) fn reconstruct_genuine_alternate_root(
    execution_index: usize,
    alternate: &B4FixedAlternateRootProofAuthorityV1,
    ancestry: &[u8],
    statement: &[u8],
    final_seal: &[u8],
    auxiliary_map: &[u8],
    manifest: &[u8],
) -> Result<B4ClosedReconstructedExecutionV1> {
    let expected = expected_row(execution_index)
        .context("genuine alternate-root seam permits only rows 108 and 146")?;
    ensure!(manifest == include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin"),
        "genuine alternate-root manifest differs from the compiled initial profile");
    let decoded_manifest = crate::profile_manifest::StarkProfileManifestV1::decode(manifest)?;
    decoded_manifest.validate_initial_profile_target()?;
    let profile_id = decoded_manifest.profile_id()?;
    let decoded = crate::ergo_statement::parse_ergo_statement_v1(statement)?;
    ensure!(decoded.profile_id() == profile_id, "genuine alternate-root statement profile differs");
    let projection = parse_recursive_ancestry_jcs(ancestry)?;
    ensure!(projection.family == RecursiveAncestryFamily::TerminalResolve
        && recursive_ancestry_to_jcs(&projection)? == ancestry,
        "genuine alternate-root requires exact case-9 ancestry");
    ensure!(classify_recursive_ancestry_semantics(&projection, statement, profile_id)?
        == RecursiveAncestrySemanticOutcome::Canonical,
        "genuine alternate-root base is not canonical positive evidence");
    let assumption = projection.assumption_receipt.as_ref().context("case-9 assumption absent")?;
    ensure!(crate::recursive_ancestry::recursive_ancestry_claim_digest(&assumption.claim)?
        == alternate.claim_digest(), "genuine alternate-root assumption claim differs from authority");
    let auxiliary = crate::b4_recursive_auxiliary_map::decode_recursive_auxiliary_map(
        auxiliary_map, RecursiveAncestryFamily::TerminalResolve)?;
    let borrowed = auxiliary.iter().map(|(path, bytes)| (path.to_owned(), bytes)).collect();
    validate_recursive_ancestry_artifacts(&projection, statement, final_seal, &borrowed)?;
    let plan = Eip0045B4NegativePlanV1::canonical()?;
    let plan_jcs = plan.to_canonical_jcs()?;
    let planned = plan.groups.iter().flat_map(|group| group.executions.iter())
        .nth(execution_index).context("canonical alternate-root row absent")?;
    validate_planned_execution(expected, planned, &plan_jcs)?;
    let sources = GenuineAlternateSources { plan: &plan_jcs, manifest, statement,
        payload: decoded.application_payload(), program: decoded.program_id(), profile: profile_id,
        ancestry, projection, final_seal, auxiliary };
    reconstruct_alternate_root_execution_from_sources(execution_index, planned, alternate, expected, &sources)?
        .context("genuine alternate-root core omitted its closed row")
}

#[cfg(test)]
struct GenuineAlternateSources<'a> {
    plan: &'a [u8], manifest: &'a [u8], statement: &'a [u8], payload: &'a [u8],
    program: [u8; 32], profile: [u8; 32], ancestry: &'a [u8],
    projection: crate::recursive_ancestry::RecursiveAncestryProjection,
    final_seal: &'a [u8], auxiliary: B4RecursiveAuxiliaryMapV1<'a>,
}

#[cfg(test)]
impl AuthenticatedAlternateSources for GenuineAlternateSources<'_> {
    fn negative_plan_jcs(&self) -> &[u8] { self.plan }
    fn profile_manifest(&self) -> &[u8] { self.manifest }
    fn statement(&self) -> &[u8] { self.statement }
    fn application_payload(&self) -> &[u8] { self.payload }
    fn program_id(&self) -> [u8; 32] { self.program }
    fn profile_id(&self) -> [u8; 32] { self.profile }
    fn case9_ancestry_jcs(&self) -> &[u8] { self.ancestry }
    fn case9_projection(&self) -> &crate::recursive_ancestry::RecursiveAncestryProjection { &self.projection }
    fn case9_statement(&self) -> &[u8] { self.statement }
    fn case9_final_raw_seal(&self) -> &[u8] { self.final_seal }
    fn case9_auxiliary_seals(&self) -> &B4RecursiveAuxiliaryMapV1<'_> { &self.auxiliary }
}

#[cfg(test)]
mod tests {
    use crate::{
        b4::{B4NegativeMaterialization, B4NegativeMutation},
        b4_c2_opcode_sequence::decode_producer_opcode_subject,
        b4_fixture_sources::synthetic_valid_recursive_ancestry_top_level,
        b4_mutation::B4MaterializationReplayAdapterV1,
        b4_recursive_auxiliary_map::decode_recursive_auxiliary_map,
        b4_subject_envelope::{ancestry_subject_envelope_contract, decode_subject_envelope},
        constants::B4_ALTERNATE_CONTROL_ROOT_HEX,
        recursive_ancestry::{RecursiveAncestryFamily, parse_recursive_ancestry_jcs},
    };

    use super::{
        AdapterOutput, AlternateRootReplayAdapter, AlternateSources, ROW_108_INDEX, ROW_146_INDEX,
        ROW_146_SELECTOR, alternate_root_execution_indices, expected_materialization, expected_row,
        reconstruct_alternate_root_execution, reconstruct_alternate_root_execution_v2,
        replay_case9_assumption_substitution, replay_materialization, sha256_hex,
    };

    const ALTERNATE_RAW_SEAL: &[u8] = include_bytes!(
        "../../generator/testdata/alternate-root-lift-po2-15-v1/candidate-proof-export/proof-output/candidate-raw-seal.bin"
    );

    #[test]
    fn v2_entrypoint_requires_v2_input_case0_and_terminal_resolve_sources() {
        type ProducerV1 = fn(
            usize,
            &crate::b4_plan::B4NegativePlanExecutionV1,
            &crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1,
            &crate::b4_alternate_root_authority::B4FixedAlternateRootProofAuthorityV1,
        ) -> anyhow::Result<
            Option<crate::b4_materialization_set::B4ClosedReconstructedExecutionV1>,
        >;
        type ProducerV2 = fn(
            usize,
            &crate::b4_plan::B4NegativePlanExecutionV1,
            &crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV2,
            &crate::b4_alternate_root_authority::B4FixedAlternateRootProofAuthorityV1,
        ) -> anyhow::Result<
            Option<crate::b4_materialization_set::B4ClosedReconstructedExecutionV1>,
        >;
        let v1: ProducerV1 = reconstruct_alternate_root_execution;
        let v2: ProducerV2 = reconstruct_alternate_root_execution_v2;
        std::hint::black_box((v1, v2));

        let source = include_str!("b4_c2_alternate_root.rs");
        let authentication = source
            .split("impl<'a> AlternateSourcesV2<'a>")
            .nth(1)
            .unwrap()
            .split("impl AuthenticatedAlternateSources for AlternateSourcesV2")
            .next()
            .unwrap();
        assert!(authentication.contains("B4MaterializationFixtureSourceResolverV2"));
        assert!(authentication.contains(".positive_input()"));
        assert!(authentication.contains(".case_zero_reference_statement()"));
        assert!(authentication.contains("RecursiveAncestryFamily::TerminalResolve"));
        assert!(!authentication.contains("B4FixtureSourceResolverV1"));
        assert!(
            !source.contains(&["impl From<", "B4AuthenticatedMaterializationTopLevelV2"].concat())
        );
        assert!(
            !source.contains(&["impl Into<", "B4AuthenticatedMaterializationTopLevelV1"].concat())
        );
    }

    #[test]
    fn rows_108_and_146_are_the_only_alternate_root_consumers() {
        assert_eq!(
            alternate_root_execution_indices(),
            [ROW_108_INDEX, ROW_146_INDEX]
        );
        for index in 0..254 {
            assert_eq!(
                expected_row(index).is_some(),
                matches!(index, ROW_108_INDEX | ROW_146_INDEX),
                "alternate-root row table drift at index {index}"
            );
        }
        assert!(matches!(
            expected_materialization(expected_row(ROW_108_INDEX).unwrap()),
            B4NegativeMaterialization::FixtureSelection { ref fixture_id }
                if fixture_id == "alternate-root-lift-po2-15-v1"
        ));
        assert!(matches!(
            expected_materialization(expected_row(ROW_146_INDEX).unwrap()),
            B4NegativeMaterialization::Mutation {
                mutation: B4NegativeMutation::AlternateRootAssumptionSubstitution {},
            }
        ));
    }

    #[test]
    fn row_108_uses_only_the_authenticated_alternate_seal_and_global_opcode_inputs() {
        let top_level = synthetic_valid_recursive_ancestry_top_level();
        let sources = AlternateSources::authenticate(&top_level).unwrap();
        let expected = expected_row(ROW_108_INDEX).unwrap();
        let materialization = expected_materialization(expected);
        let replayed =
            replay_materialization(expected, &sources, ALTERNATE_RAW_SEAL, &materialization)
                .unwrap();

        assert_eq!(replayed.raw_output, ALTERNATE_RAW_SEAL);
        let decoded = decode_producer_opcode_subject(&replayed.final_subject).unwrap();
        assert_eq!(
            decoded
                .proof_chunks()
                .iter()
                .flat_map(|chunk| chunk.iter().copied())
                .collect::<Vec<_>>(),
            ALTERNATE_RAW_SEAL
        );
        assert_eq!(decoded.application_payload(), sources.application_payload);
        assert_eq!(decoded.program_id(), sources.program_id);
        assert_eq!(decoded.profile_id(), sources.profile_id);
    }

    #[test]
    fn row_146_replaces_only_the_case9_assumption_reference_and_matching_auxiliary_bytes() {
        let top_level = synthetic_valid_recursive_ancestry_top_level();
        let sources = AlternateSources::authenticate(&top_level).unwrap();
        let replayed = replay_case9_assumption_substitution(&sources, ALTERNATE_RAW_SEAL).unwrap();
        let decoded = decode_subject_envelope(
            &replayed.final_subject,
            ancestry_subject_envelope_contract(),
        )
        .unwrap();
        let [ancestry, statement, final_seal, auxiliary]: [&[u8]; 4] =
            decoded.parts().try_into().unwrap();
        assert_eq!(ancestry, replayed.raw_output);
        assert_eq!(statement, sources.case9.statement());
        assert_eq!(final_seal, sources.case9.final_raw_seal());

        let original = sources.case9.projection();
        let mutated = parse_recursive_ancestry_jcs(ancestry).unwrap();
        let mut expected = original.clone();
        let expected_assumption = expected.assumption_receipt.as_mut().unwrap();
        let assumption_path = expected_assumption.raw_seal.path.clone();
        expected_assumption.raw_seal.sha256 = sha256_hex(ALTERNATE_RAW_SEAL);
        assert_eq!(mutated, expected);
        assert_eq!(
            mutated
                .assumption_receipt
                .as_ref()
                .unwrap()
                .requested_control_root,
            original
                .assumption_receipt
                .as_ref()
                .unwrap()
                .requested_control_root
        );
        assert_eq!(mutated.steps, original.steps);

        let updated =
            decode_recursive_auxiliary_map(auxiliary, RecursiveAncestryFamily::TerminalResolve)
                .unwrap();
        let original_entries = sources.case9.auxiliary_seals().iter().collect::<Vec<_>>();
        let updated_entries = updated.iter().collect::<Vec<_>>();
        assert_eq!(updated_entries.len(), original_entries.len());
        for ((path, before), (updated_path, after)) in
            original_entries.into_iter().zip(updated_entries)
        {
            assert_eq!(path, updated_path);
            if path == assumption_path {
                assert_eq!(after, ALTERNATE_RAW_SEAL);
                assert_ne!(after, before);
            } else {
                assert_eq!(after, before);
            }
        }
    }

    #[test]
    fn row_146_replay_rejects_a_coordinated_requested_root_rewrite() {
        let top_level = synthetic_valid_recursive_ancestry_top_level();
        let sources = AlternateSources::authenticate(&top_level).unwrap();
        let alternate =
            crate::b4_alternate_root_authority::authenticate_retained_alternate_root_kat().unwrap();
        let expected = expected_row(ROW_146_INDEX).unwrap();
        let materialization = expected_materialization(expected);
        let replayed =
            replay_materialization(expected, &sources, ALTERNATE_RAW_SEAL, &materialization)
                .unwrap();
        let decoded = decode_subject_envelope(
            &replayed.final_subject,
            ancestry_subject_envelope_contract(),
        )
        .unwrap();
        let [ancestry, statement, final_seal, auxiliary]: [&[u8]; 4] =
            decoded.parts().try_into().unwrap();
        let mut coordinated = parse_recursive_ancestry_jcs(ancestry).unwrap();
        coordinated
            .assumption_receipt
            .as_mut()
            .unwrap()
            .requested_control_root = B4_ALTERNATE_CONTROL_ROOT_HEX.to_owned();
        let coordinated_ancestry =
            crate::recursive_ancestry::recursive_ancestry_to_jcs(&coordinated).unwrap();
        let coordinated_subject = crate::b4_subject_envelope::encode_subject_envelope(
            &[&coordinated_ancestry, statement, final_seal, auxiliary],
            ancestry_subject_envelope_contract(),
        )
        .unwrap();
        let adapter = AlternateRootReplayAdapter {
            expected,
            sources: &sources,
            alternate: &alternate,
            materialization: &materialization,
            output: &coordinated_subject,
            output_kind: AdapterOutput::Final,
        };

        let error = adapter
            .replay_recipe(ROW_146_SELECTOR, &materialization)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("output differs from typed reconstruction"),
            "{error:#}"
        );
    }
}
