//! Closed producers for recursive-ancestry rows with reusable seals.

use std::fmt;

use anyhow::{Context as _, Result, bail, ensure};

use crate::{
    b4::{
        B4AncestryInventoryOperation, B4AncestryInventoryTarget, B4ByteOperation, B4ByteTarget,
        B4NegativeCase, B4NegativeMaterialization, B4NegativeMutation,
    },
    b4_fixture_sources::{
        B4FixtureSourceResolverV1, B4MaterializationFixtureSourceResolverV2,
        B4RecursiveAncestrySourceViewV1, B4RecursiveAncestrySourceViewV2,
    },
    b4_materialization_set::{
        B4AuthenticatedMaterializationTopLevelV1, B4AuthenticatedMaterializationTopLevelV2,
        B4ClosedReconstructedExecutionV1, close_production_execution,
    },
    b4_mutation::{B4MaterializationReplayAdapterV1, reconstruct_byte_edit},
    b4_plan::{
        B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanExecutionV1,
        B4NegativePlanFixture, B4NegativeQaResultCode, Eip0045B4NegativePlanV1,
    },
    b4_subject_envelope::{ancestry_subject_envelope_contract, encode_subject_envelope},
    constants::{DIGEST_BYTES, RISC0_INNER_CONTROL_ROOT_HEX},
    profile_manifest::StarkProfileManifestV1,
    recursive_ancestry::{
        RecursiveAncestryFamily, RecursiveAncestryRevealedHeadWitness,
        RecursiveAncestrySemanticOutcome, classify_recursive_ancestry_semantics,
        parse_recursive_ancestry_jcs, prune_recursive_ancestry_revealed_head,
        recursive_ancestry_revealed_head_witness, recursive_ancestry_to_jcs,
    },
};

const REUSABLE_SEAL_ROWS: [usize; 3] = [144, 149, 155];

#[derive(Clone, Copy)]
struct ExpectedRow {
    index: usize,
    execution_id: &'static str,
    variant_id: &'static str,
    selector: &'static str,
    fixture: B4NegativePlanFixture,
    qa_result: B4NegativeQaResultCode,
    family: RecursiveAncestryFamily,
}

const EXPECTED_ROWS: [ExpectedRow; 3] = [
    ExpectedRow {
        index: 144,
        execution_id: "resolve-explicit-field-sweep--declared-explicit-root",
        variant_id: "declared-explicit-root",
        selector: "case9-typed-ancestry-v1",
        fixture: B4NegativePlanFixture::Case9TypedAncestryV1,
        qa_result: B4NegativeQaResultCode::B4ResolveExplicitSemanticsMismatch,
        family: RecursiveAncestryFamily::TerminalResolve,
    },
    ExpectedRow {
        index: 149,
        execution_id: "resolve-zero-root-field-sweep--substituted-nonzero-root",
        variant_id: "substituted-nonzero-root",
        selector: "case10-typed-ancestry-v1",
        fixture: B4NegativePlanFixture::Case10TypedAncestryV1,
        qa_result: B4NegativeQaResultCode::B4ResolveZeroRootSemanticsMismatch,
        family: RecursiveAncestryFamily::ResolveThenJoin,
    },
    ExpectedRow {
        index: 155,
        execution_id: "resolve-assumption-inventory-sweep--pruned-assumption",
        variant_id: "pruned-assumption",
        selector: "case9-typed-ancestry-v1",
        fixture: B4NegativePlanFixture::Case9TypedAncestryV1,
        qa_result: B4NegativeQaResultCode::B4ResolveAssumptionInventoryInvalid,
        family: RecursiveAncestryFamily::TerminalResolve,
    },
];

struct AncestrySources<'a> {
    view: B4RecursiveAncestrySourceViewV1<'a>,
    negative_plan_jcs: &'a [u8],
    profile_id: [u8; DIGEST_BYTES],
    auxiliary_map: Vec<u8>,
}

struct AncestrySourcesV2<'a> {
    view: B4RecursiveAncestrySourceViewV2<'a>,
    negative_plan_jcs: &'a [u8],
    profile_id: [u8; DIGEST_BYTES],
    auxiliary_map: Vec<u8>,
}

trait AuthenticatedAncestrySources {
    fn negative_plan_jcs(&self) -> &[u8];
    fn base(&self) -> &[u8];
    fn profile_manifest_context(&self) -> &[u8];
    fn projection(&self) -> &crate::recursive_ancestry::RecursiveAncestryProjection;
    fn statement(&self) -> &[u8];
    fn final_raw_seal(&self) -> &[u8];
    fn profile_id(&self) -> [u8; DIGEST_BYTES];
    fn auxiliary_map(&self) -> &[u8];
}

impl<'a> AncestrySources<'a> {
    fn authenticate(
        top_level: &'a B4AuthenticatedMaterializationTopLevelV1,
        family: RecursiveAncestryFamily,
    ) -> Result<Self> {
        let resolver = B4FixtureSourceResolverV1::from_authenticated(top_level)
            .context("ancestry producer cannot authenticate fixture sources")?;
        let view = resolver
            .recursive_ancestry_source(family)
            .context("ancestry producer cannot resolve its exact positive family")?;
        let manifest = StarkProfileManifestV1::decode(view.profile_manifest_context())
            .context("ancestry producer cannot decode its authenticated manifest")?;
        manifest
            .validate_initial_profile_target()
            .context("ancestry producer manifest differs from the initial profile")?;
        let profile_id = manifest.profile_id()?;
        let auxiliary_map = view
            .encoded_auxiliary_map()
            .context("ancestry producer cannot encode its authenticated auxiliary seals")?;
        Ok(Self {
            view,
            negative_plan_jcs: &top_level.negative_plan,
            profile_id,
            auxiliary_map,
        })
    }
}

impl AuthenticatedAncestrySources for AncestrySources<'_> {
    fn negative_plan_jcs(&self) -> &[u8] {
        self.negative_plan_jcs
    }

    fn base(&self) -> &[u8] {
        self.view.ancestry_jcs()
    }

    fn profile_manifest_context(&self) -> &[u8] {
        self.view.profile_manifest_context()
    }

    fn projection(&self) -> &crate::recursive_ancestry::RecursiveAncestryProjection {
        self.view.projection()
    }

    fn statement(&self) -> &[u8] {
        self.view.statement()
    }

    fn final_raw_seal(&self) -> &[u8] {
        self.view.final_raw_seal()
    }

    fn profile_id(&self) -> [u8; DIGEST_BYTES] {
        self.profile_id
    }

    fn auxiliary_map(&self) -> &[u8] {
        &self.auxiliary_map
    }
}

impl<'a> AncestrySourcesV2<'a> {
    fn authenticate(
        top_level: &'a B4AuthenticatedMaterializationTopLevelV2,
        family: RecursiveAncestryFamily,
    ) -> Result<Self> {
        let resolver = B4MaterializationFixtureSourceResolverV2::from_authenticated(top_level)
            .context("V2 ancestry producer cannot authenticate fixture sources")?;
        let view = resolver
            .recursive_ancestry_source(family)
            .context("V2 ancestry producer cannot resolve its exact positive family")?;
        let manifest = StarkProfileManifestV1::decode(view.profile_manifest_context())
            .context("V2 ancestry producer cannot decode its authenticated manifest")?;
        manifest
            .validate_initial_profile_target()
            .context("V2 ancestry producer manifest differs from the initial profile")?;
        let profile_id = manifest.profile_id()?;
        let auxiliary_map = view
            .encoded_auxiliary_map()
            .context("V2 ancestry producer cannot encode its authenticated auxiliary seals")?;
        Ok(Self {
            view,
            negative_plan_jcs: resolver.negative_plan_jcs(),
            profile_id,
            auxiliary_map,
        })
    }
}

impl AuthenticatedAncestrySources for AncestrySourcesV2<'_> {
    fn negative_plan_jcs(&self) -> &[u8] {
        self.negative_plan_jcs
    }

    fn base(&self) -> &[u8] {
        self.view.ancestry_jcs()
    }

    fn profile_manifest_context(&self) -> &[u8] {
        self.view.profile_manifest_context()
    }

    fn projection(&self) -> &crate::recursive_ancestry::RecursiveAncestryProjection {
        self.view.projection()
    }

    fn statement(&self) -> &[u8] {
        self.view.statement()
    }

    fn final_raw_seal(&self) -> &[u8] {
        self.view.final_raw_seal()
    }

    fn profile_id(&self) -> [u8; DIGEST_BYTES] {
        self.profile_id
    }

    fn auxiliary_map(&self) -> &[u8] {
        &self.auxiliary_map
    }
}

#[derive(Clone, Copy)]
enum AdapterOutput {
    Raw,
    Final,
}

#[derive(Clone, Copy)]
struct AncestryReplayAdapter<'sources, S> {
    expected: ExpectedRow,
    sources: &'sources S,
    materialization: &'sources B4NegativeMaterialization,
    output: &'sources [u8],
    output_kind: AdapterOutput,
}

impl<S> fmt::Debug for AncestryReplayAdapter<'_, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AncestryReplayAdapter")
            .field("execution_index", &self.expected.index)
            .finish_non_exhaustive()
    }
}

impl<S: AuthenticatedAncestrySources> B4MaterializationReplayAdapterV1
    for AncestryReplayAdapter<'_, S>
{
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::VerifierInput
    }

    fn base_bytes(&self) -> &[u8] {
        self.sources.base()
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
            "ancestry replay adapter received a selector or recipe outside its closed row"
        );
        let replayed = replay_materialization(self.expected, self.sources, materialization)?;
        let expected = match self.output_kind {
            AdapterOutput::Raw => &replayed.raw_ancestry,
            AdapterOutput::Final => &replayed.final_subject,
        };
        ensure!(
            self.output == expected,
            "ancestry replay adapter output differs from typed reconstruction"
        );
        Ok(())
    }
}

struct ReplayedAncestry {
    raw_ancestry: Vec<u8>,
    final_subject: Vec<u8>,
}

/// Reconstruct the three ancestry rows which reuse every positive seal.
#[cfg_attr(
    not(all(feature = "negative-materialization-set", target_os = "linux")),
    allow(
        dead_code,
        reason = "the production dispatcher is descriptor-rooted and Linux-only; other feature sets retain this producer for focused tests"
    )
)]
pub(crate) fn reconstruct_ancestry_execution(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    let Some(expected) = expected_row(execution_index) else {
        return Ok(None);
    };
    let sources = AncestrySources::authenticate(top_level, expected.family)?;
    validate_planned_execution(expected, planned, sources.negative_plan_jcs())?;
    reconstruct_ancestry_execution_from_sources(execution_index, planned, expected, &sources)
}

/// Reconstruct the fixed ancestry rows from the independently authenticated V2 fixture source.
pub(crate) fn reconstruct_ancestry_execution_v2(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV2,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    let Some(expected) = expected_row(execution_index) else {
        return Ok(None);
    };
    let sources = AncestrySourcesV2::authenticate(top_level, expected.family)?;
    validate_planned_execution(expected, planned, sources.negative_plan_jcs())?;
    reconstruct_ancestry_execution_from_sources(execution_index, planned, expected, &sources)
}

fn reconstruct_ancestry_execution_from_sources<S: AuthenticatedAncestrySources>(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    expected: ExpectedRow,
    sources: &S,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    let materialization = derive_materialization(expected, sources)?;
    let replayed = replay_materialization(expected, sources, &materialization)?;
    let registry_row = B4NegativeCase {
        execution_id: expected.execution_id.to_owned(),
        base_selector_id: expected.selector.to_owned(),
        materialization_domain: B4MaterializationDomain::VerifierInput,
        materialization,
    };
    let expected_materialization = registry_row.materialization.clone();
    let raw_adapter = AncestryReplayAdapter {
        expected,
        sources,
        materialization: &expected_materialization,
        output: &replayed.raw_ancestry,
        output_kind: AdapterOutput::Raw,
    };
    let final_adapter = AncestryReplayAdapter {
        expected,
        sources,
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
        vec![sources.profile_manifest_context().to_vec()],
    )
    .map(Some)
}

fn expected_row(index: usize) -> Option<ExpectedRow> {
    debug_assert_eq!(
        REUSABLE_SEAL_ROWS,
        EXPECTED_ROWS.map(|expected| expected.index)
    );
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
        .context("ancestry producer negative plan is not canonical")?;
    let canonical = plan
        .groups
        .iter()
        .flat_map(|group| group.executions.iter())
        .nth(expected.index)
        .context("ancestry producer index is outside the canonical plan")?;
    ensure!(
        canonical == planned
            && planned.execution_id == expected.execution_id
            && planned.variant_id == expected.variant_id
            && planned.base_selector_id == expected.selector
            && planned.fixture == expected.fixture
            && planned.materialization_domain == B4MaterializationDomain::VerifierInput
            && planned.execution_surface == B4NegativeExecutionSurface::AncestryReplay
            && planned.qa_result_code == expected.qa_result
            && planned.parser_truncation_words.is_none(),
        "ancestry execution differs from its exact canonical-plan contract"
    );
    Ok(())
}

fn derive_materialization(
    expected: ExpectedRow,
    sources: &impl AuthenticatedAncestrySources,
) -> Result<B4NegativeMaterialization> {
    let mutation = match expected.index {
        144 | 149 => B4NegativeMutation::ByteEdit {
            edit: requested_root_edit(expected.index, sources)?,
            target: B4ByteTarget::Ancestry,
        },
        155 => {
            let witness = recursive_ancestry_revealed_head_witness(sources.projection())?;
            B4NegativeMutation::AncestryInventoryEdit {
                edit: B4AncestryInventoryOperation::PruneRevealedHead {
                    before_claim_digest: hex::encode(witness.claim_digest),
                    before_control_root: hex::encode(witness.control_root),
                    exact_digest: hex::encode(witness.exact_digest),
                },
                target: B4AncestryInventoryTarget::AssumptionSourceInventoryHead,
            }
        }
        _ => bail!("ancestry materialization index is outside its closed row set"),
    };
    Ok(B4NegativeMaterialization::Mutation { mutation })
}

fn requested_root_edit(
    index: usize,
    sources: &impl AuthenticatedAncestrySources,
) -> Result<B4ByteOperation> {
    let before = &sources
        .projection()
        .assumption_receipt
        .as_ref()
        .context("ancestry root mutation has no assumption receipt")?
        .requested_control_root;
    let replacement = match index {
        144 => "00".repeat(DIGEST_BYTES),
        149 => RISC0_INNER_CONTROL_ROOT_HEX.to_owned(),
        _ => bail!("requested-root edit is outside rows 144 and 149"),
    };
    ensure!(
        before != &replacement && before.len() == DIGEST_BYTES * 2,
        "requested-root mutation is a no-op or has a malformed base"
    );
    let prefix = format!("\"requestedControlRoot\":\"{before}\"");
    let matches = sources
        .base()
        .windows(prefix.len())
        .enumerate()
        .filter_map(|(offset, bytes)| (bytes == prefix.as_bytes()).then_some(offset))
        .collect::<Vec<_>>();
    let [field_offset] = matches.as_slice() else {
        bail!("canonical ancestry has no unique requested-control-root field");
    };
    let value_offset = field_offset
        .checked_add("\"requestedControlRoot\":\"".len())
        .context("requested-control-root value offset overflows usize")?;
    Ok(B4ByteOperation::Replace {
        before_hex: hex::encode(before.as_bytes()),
        replacement_hex: hex::encode(replacement.as_bytes()),
        offset: u64::try_from(value_offset)?,
    })
}

fn replay_materialization(
    expected: ExpectedRow,
    sources: &impl AuthenticatedAncestrySources,
    materialization: &B4NegativeMaterialization,
) -> Result<ReplayedAncestry> {
    ensure!(
        materialization == &derive_materialization(expected, sources)?,
        "ancestry materialization differs from its source-derived exact recipe"
    );
    let raw_ancestry = match materialization {
        B4NegativeMaterialization::Mutation {
            mutation:
                B4NegativeMutation::ByteEdit {
                    edit,
                    target: B4ByteTarget::Ancestry,
                },
        } => replay_requested_root_edit(expected, sources, edit)?,
        B4NegativeMaterialization::Mutation {
            mutation:
                B4NegativeMutation::AncestryInventoryEdit {
                    edit:
                        B4AncestryInventoryOperation::PruneRevealedHead {
                            before_claim_digest,
                            before_control_root,
                            exact_digest,
                        },
                    target: B4AncestryInventoryTarget::AssumptionSourceInventoryHead,
                },
        } => replay_pruned_head(
            expected,
            sources,
            before_claim_digest,
            before_control_root,
            exact_digest,
        )?,
        _ => bail!("ancestry producer received a different mutation family or target"),
    };
    let final_subject = encode_subject_envelope(
        &[
            &raw_ancestry,
            sources.statement(),
            sources.final_raw_seal(),
            sources.auxiliary_map(),
        ],
        ancestry_subject_envelope_contract(),
    )
    .context("ancestry producer cannot encode its exact four-part subject")?;
    Ok(ReplayedAncestry {
        raw_ancestry,
        final_subject,
    })
}

fn replay_requested_root_edit(
    expected: ExpectedRow,
    sources: &impl AuthenticatedAncestrySources,
    edit: &B4ByteOperation,
) -> Result<Vec<u8>> {
    ensure!(
        matches!(expected.index, 144 | 149),
        "requested-root byte edit is outside its exact rows"
    );
    let output = reconstruct_byte_edit(sources.base(), edit)?;
    let parsed = parse_recursive_ancestry_jcs(&output)
        .context("requested-root edit did not preserve canonical ancestry JCS")?;
    let mut typed_expected = sources.projection().clone();
    typed_expected
        .assumption_receipt
        .as_mut()
        .context("requested-root typed projection lost its assumption receipt")?
        .requested_control_root = match expected.index {
        144 => "00".repeat(DIGEST_BYTES),
        149 => RISC0_INNER_CONTROL_ROOT_HEX.to_owned(),
        _ => unreachable!(),
    };
    ensure!(
        parsed == typed_expected && recursive_ancestry_to_jcs(&parsed)? == output,
        "requested-root byte edit changed another ancestry field"
    );
    let expected_outcome = match expected.index {
        144 => RecursiveAncestrySemanticOutcome::ResolveExplicit,
        149 => RecursiveAncestrySemanticOutcome::ResolveZeroRoot,
        _ => unreachable!(),
    };
    ensure!(
        classify_recursive_ancestry_semantics(&parsed, sources.statement(), sources.profile_id(),)?
            == expected_outcome,
        "requested-root mutation did not isolate its planned ancestry rejection"
    );
    Ok(output)
}

fn replay_pruned_head(
    expected: ExpectedRow,
    sources: &impl AuthenticatedAncestrySources,
    before_claim_digest: &str,
    before_control_root: &str,
    exact_digest: &str,
) -> Result<Vec<u8>> {
    ensure!(
        expected.index == 155,
        "pruned-head semantic edit is outside row 155"
    );
    let witness = RecursiveAncestryRevealedHeadWitness {
        claim_digest: decode_digest(before_claim_digest, "pruned-head claim digest")?,
        control_root: decode_digest(before_control_root, "pruned-head control root")?,
        exact_digest: decode_digest(exact_digest, "pruned-head exact digest")?,
    };
    let pruned = prune_recursive_ancestry_revealed_head(
        sources.projection(),
        sources.statement(),
        sources.profile_id(),
        witness,
    )?;
    recursive_ancestry_to_jcs(&pruned)
}

fn decode_digest(value: &str, label: &str) -> Result<[u8; DIGEST_BYTES]> {
    ensure!(
        value.len() == DIGEST_BYTES * 2
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} is not exactly 32 lowercase hexadecimal bytes"
    );
    let mut decoded = [0u8; DIGEST_BYTES];
    hex::decode_to_slice(value, &mut decoded).with_context(|| format!("cannot decode {label}"))?;
    Ok(decoded)
}

#[cfg(test)]
struct LocalTestAncestrySources<'a> {
    plan: &'a [u8],
    ancestry: &'a [u8],
    statement: &'a [u8],
    final_raw_seal: &'a [u8],
    auxiliary_map: &'a [u8],
    manifest: &'a [u8],
    projection: crate::recursive_ancestry::RecursiveAncestryProjection,
    profile_id: [u8; DIGEST_BYTES],
}

#[cfg(test)]
impl AuthenticatedAncestrySources for LocalTestAncestrySources<'_> {
    fn negative_plan_jcs(&self) -> &[u8] {
        self.plan
    }
    fn base(&self) -> &[u8] {
        self.ancestry
    }
    fn profile_manifest_context(&self) -> &[u8] {
        self.manifest
    }
    fn projection(&self) -> &crate::recursive_ancestry::RecursiveAncestryProjection {
        &self.projection
    }
    fn statement(&self) -> &[u8] {
        self.statement
    }
    fn final_raw_seal(&self) -> &[u8] {
        self.final_raw_seal
    }
    fn profile_id(&self) -> [u8; DIGEST_BYTES] {
        self.profile_id
    }
    fn auxiliary_map(&self) -> &[u8] {
        self.auxiliary_map
    }
}

/// Reconstruct only the local case-9 ancestry diagnostics from caller-authenticated bytes.
/// The caller must authenticate the three seals and their source bindings first;
/// this test seam grants neither top-level materialization nor campaign authority.
#[cfg(test)]
pub(crate) fn reconstruct_genuine_resolve_ancestry(
    execution_index: usize,
    ancestry: &[u8],
    statement: &[u8],
    final_raw_seal: &[u8],
    auxiliary_map: &[u8],
    manifest: &[u8],
) -> Result<B4ClosedReconstructedExecutionV1> {
    ensure!(
        matches!(execution_index, 144 | 155),
        "genuine resolve ancestry seam permits only rows 144 and 155"
    );
    ensure!(
        manifest == include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin"),
        "genuine resolve ancestry manifest differs from the compiled initial profile"
    );
    let decoded_manifest = StarkProfileManifestV1::decode(manifest)?;
    decoded_manifest.validate_initial_profile_target()?;
    let profile_id = decoded_manifest.profile_id()?;
    let projection = parse_recursive_ancestry_jcs(ancestry)?;
    ensure!(
        projection.family == RecursiveAncestryFamily::TerminalResolve
            && recursive_ancestry_to_jcs(&projection)? == ancestry,
        "genuine resolve ancestry differs from the exact case-9 projection"
    );
    ensure!(
        classify_recursive_ancestry_semantics(&projection, statement, profile_id)?
            == RecursiveAncestrySemanticOutcome::Canonical,
        "genuine resolve ancestry base is not canonical positive evidence"
    );
    let plan = Eip0045B4NegativePlanV1::canonical()?;
    let plan_jcs = plan.to_canonical_jcs()?;
    let planned = plan
        .groups
        .iter()
        .flat_map(|group| group.executions.iter())
        .nth(execution_index)
        .context("canonical plan has no selected resolve ancestry row")?;
    let expected = expected_row(execution_index).context("resolve ancestry row mapping absent")?;
    validate_planned_execution(expected, planned, &plan_jcs)?;

    let sources = LocalTestAncestrySources {
        plan: &plan_jcs,
        ancestry,
        statement,
        final_raw_seal,
        auxiliary_map,
        manifest,
        projection,
        profile_id,
    };
    reconstruct_ancestry_execution_from_sources(execution_index, planned, expected, &sources)?
        .context("resolve ancestry core did not reconstruct its selected row")
}

#[cfg(test)]
mod tests {
    use crate::{
        b4::{
            B4AncestryInventoryOperation, B4AncestryInventoryTarget, B4ByteTarget,
            B4NegativeMaterialization, B4NegativeMutation,
        },
        b4_fixture_sources::{
            B4FixtureSourceResolverV1, synthetic_valid_recursive_ancestry_top_level,
        },
        b4_plan::Eip0045B4NegativePlanV1,
        b4_subject_envelope::{ancestry_subject_envelope_contract, decode_subject_envelope},
        constants::{DIGEST_BYTES, RISC0_INNER_CONTROL_ROOT_HEX},
        recursive_ancestry::{
            RecursiveAncestryFamily, RecursiveAncestryInventoryDefect,
            RecursiveAncestryInventoryEntry, RecursiveAncestrySemanticOutcome,
            classify_recursive_ancestry_semantics, parse_recursive_ancestry_jcs,
            recursive_ancestry_revealed_head_witness,
        },
    };

    use super::{reconstruct_ancestry_execution, reconstruct_ancestry_execution_v2};

    #[test]
    fn genuine_resolve_seam_rejects_other_indices_before_reading_inputs() {
        for index in [0, 143, 145, 149, 154, 156, usize::MAX] {
            let error = super::reconstruct_genuine_resolve_ancestry(index, &[], &[], &[], &[], &[])
                .err()
                .expect("an index outside the exact case-9 pair must fail");
            assert_eq!(
                error.to_string(),
                "genuine resolve ancestry seam permits only rows 144 and 155"
            );
        }
    }

    #[test]
    fn synthetic_resolve_seam_matches_existing_core_without_crypto_evidence() {
        // This compares reconstruction only; the synthetic fixture is not a proof.
        let top_level = synthetic_valid_recursive_ancestry_top_level();
        let resolver = B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();
        let source = resolver
            .recursive_ancestry_source(RecursiveAncestryFamily::TerminalResolve)
            .unwrap();
        let auxiliary = source.encoded_auxiliary_map().unwrap();
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let flattened = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .collect::<Vec<_>>();
        for index in [144, 155] {
            let actual = super::reconstruct_genuine_resolve_ancestry(
                index,
                source.ancestry_jcs(),
                source.statement(),
                source.final_raw_seal(),
                &auxiliary,
                source.profile_manifest_context(),
            )
            .unwrap();
            let expected = reconstruct_ancestry_execution(index, flattened[index], &top_level)
                .unwrap()
                .unwrap();
            assert_eq!(actual.base, expected.base);
            assert_eq!(actual.subject, expected.subject);
            assert_eq!(actual.contexts, expected.contexts);
            assert_eq!(actual.derived_registry_row, expected.derived_registry_row);
            assert_eq!(
                actual.materialization_identity_jcs,
                expected.materialization_identity_jcs
            );
            assert_eq!(actual.negative_input_jcs, expected.negative_input_jcs);
        }
    }

    #[test]
    fn v2_entrypoint_requires_the_v2_top_level_and_has_no_v1_resolver_fallback() {
        type ProducerV1 = fn(
            usize,
            &crate::b4_plan::B4NegativePlanExecutionV1,
            &crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV1,
        ) -> anyhow::Result<
            Option<crate::b4_materialization_set::B4ClosedReconstructedExecutionV1>,
        >;
        type ProducerV2 = fn(
            usize,
            &crate::b4_plan::B4NegativePlanExecutionV1,
            &crate::b4_materialization_set::B4AuthenticatedMaterializationTopLevelV2,
        ) -> anyhow::Result<
            Option<crate::b4_materialization_set::B4ClosedReconstructedExecutionV1>,
        >;
        let v1: ProducerV1 = reconstruct_ancestry_execution;
        let v2: ProducerV2 = reconstruct_ancestry_execution_v2;
        std::hint::black_box((v1, v2));

        let source = include_str!("b4_c2_ancestry.rs");
        let v2_entry = source
            .split("pub(crate) fn reconstruct_ancestry_execution_v2")
            .nth(1)
            .unwrap()
            .split("fn reconstruct_ancestry_execution_from_sources")
            .next()
            .unwrap();
        assert!(v2_entry.contains("B4AuthenticatedMaterializationTopLevelV2"));
        assert!(v2_entry.contains("AncestrySourcesV2::authenticate(top_level"));
        assert!(!v2_entry.contains("B4FixtureSourceResolverV1"));
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
        reason = "the three-row matrix keeps shared seal reuse and each sole semantic delta visible in one regression"
    )]
    fn rows_144_149_and_155_reuse_only_authenticated_positive_seals() {
        let top_level = synthetic_valid_recursive_ancestry_top_level();
        let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(&top_level.negative_plan).unwrap();
        let flattened = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .collect::<Vec<_>>();
        let resolver = B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();

        for (index, family, expected_outcome) in [
            (
                144,
                RecursiveAncestryFamily::TerminalResolve,
                RecursiveAncestrySemanticOutcome::ResolveExplicit,
            ),
            (
                149,
                RecursiveAncestryFamily::ResolveThenJoin,
                RecursiveAncestrySemanticOutcome::ResolveZeroRoot,
            ),
            (
                155,
                RecursiveAncestryFamily::TerminalResolve,
                RecursiveAncestrySemanticOutcome::AssumptionInventory(
                    RecursiveAncestryInventoryDefect::Pruned,
                ),
            ),
        ] {
            let source = resolver.recursive_ancestry_source(family).unwrap();
            let expected_auxiliary = source.encoded_auxiliary_map().unwrap();
            let reconstructed = reconstruct_ancestry_execution(index, flattened[index], &top_level)
                .unwrap()
                .unwrap();

            assert_eq!(reconstructed.base, source.ancestry_jcs());
            assert_eq!(
                reconstructed.contexts,
                vec![source.profile_manifest_context().to_vec()]
            );
            let envelope = decode_subject_envelope(
                &reconstructed.subject,
                ancestry_subject_envelope_contract(),
            )
            .unwrap();
            let [ancestry, statement, final_seal, auxiliary]: [&[u8]; 4] =
                envelope.parts().try_into().unwrap();
            assert_eq!(statement, source.statement());
            assert_eq!(final_seal, source.final_raw_seal());
            assert_eq!(auxiliary, expected_auxiliary);

            let mutated = parse_recursive_ancestry_jcs(ancestry).unwrap();
            let profile_id: [u8; DIGEST_BYTES] = hex::decode(&mutated.profile_id)
                .unwrap()
                .try_into()
                .unwrap();
            assert_eq!(
                classify_recursive_ancestry_semantics(&mutated, source.statement(), profile_id,)
                    .unwrap(),
                expected_outcome
            );

            match index {
                144 => {
                    let mut expected = source.projection().clone();
                    expected
                        .assumption_receipt
                        .as_mut()
                        .unwrap()
                        .requested_control_root = "00".repeat(DIGEST_BYTES);
                    assert_eq!(mutated, expected);
                    assert!(matches!(
                        reconstructed.derived_registry_row.materialization,
                        B4NegativeMaterialization::Mutation {
                            mutation: B4NegativeMutation::ByteEdit {
                                target: B4ByteTarget::Ancestry,
                                ..
                            },
                        }
                    ));
                }
                149 => {
                    let mut expected = source.projection().clone();
                    expected
                        .assumption_receipt
                        .as_mut()
                        .unwrap()
                        .requested_control_root = RISC0_INNER_CONTROL_ROOT_HEX.to_owned();
                    assert_eq!(mutated, expected);
                    assert!(matches!(
                        reconstructed.derived_registry_row.materialization,
                        B4NegativeMaterialization::Mutation {
                            mutation: B4NegativeMutation::ByteEdit {
                                target: B4ByteTarget::Ancestry,
                                ..
                            },
                        }
                    ));
                }
                155 => {
                    let witness =
                        recursive_ancestry_revealed_head_witness(source.projection()).unwrap();
                    let entries = &mutated
                        .assumption_receipt
                        .as_ref()
                        .unwrap()
                        .source_inventory
                        .entries;
                    assert_eq!(
                        entries,
                        &[RecursiveAncestryInventoryEntry::Pruned {
                            digest: hex::encode(witness.exact_digest),
                        }]
                    );
                    assert!(matches!(
                        &reconstructed.derived_registry_row.materialization,
                        B4NegativeMaterialization::Mutation {
                            mutation: B4NegativeMutation::AncestryInventoryEdit {
                                target:
                                    B4AncestryInventoryTarget::AssumptionSourceInventoryHead,
                                edit:
                                    B4AncestryInventoryOperation::PruneRevealedHead {
                                        before_claim_digest,
                                        before_control_root,
                                        exact_digest,
                                    },
                            },
                        } if before_claim_digest.as_str()
                                == hex::encode(witness.claim_digest).as_str()
                            && before_control_root.as_str()
                                == hex::encode(witness.control_root).as_str()
                            && exact_digest.as_str()
                                == hex::encode(witness.exact_digest).as_str()
                    ));
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn ancestry_reusable_seal_producer_is_exactly_scoped_and_rejects_plan_drift() {
        let top_level = synthetic_valid_recursive_ancestry_top_level();
        let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(&top_level.negative_plan).unwrap();
        let flattened = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .collect::<Vec<_>>();

        for index in [143, 145, 148, 150, 154, 156] {
            assert!(
                reconstruct_ancestry_execution(index, flattened[index], &top_level)
                    .unwrap()
                    .is_none()
            );
        }

        let mut wrong = flattened[155].clone();
        wrong.base_selector_id = "case10-typed-ancestry-v1".to_owned();
        assert!(reconstruct_ancestry_execution(155, &wrong, &top_level).is_err());

        let mut wrong = flattened[149].clone();
        wrong.execution_id.push('x');
        assert!(reconstruct_ancestry_execution(149, &wrong, &top_level).is_err());
    }
}
