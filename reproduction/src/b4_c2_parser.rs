//! Closed C2 producers for the 36 internal-parser prefix rows.
//!
//! The producer authenticates the complete `lift-po2-15` raw seal and initial
//! profile manifest before deriving an exact word-aligned prefix. The
//! consumer's parser grammar is deliberately not imported: the canonical
//! negative plan is the sole authority for every truncation cut.

use anyhow::{Context, Result, bail, ensure};

use crate::{
    b4::{
        B4ByteOperation, B4ByteTarget, B4NegativeCase, B4NegativeMaterialization,
        B4NegativeMutation,
    },
    b4_fixture_sources::{B4FixtureSourceResolverV1, B4MaterializationFixtureSourceResolverV2},
    b4_materialization_set::{
        B4AuthenticatedMaterializationTopLevelV1, B4AuthenticatedMaterializationTopLevelV2,
        B4ClosedReconstructedExecutionV1, close_production_execution,
    },
    b4_mutation::{B4MaterializationReplayAdapterV1, reconstruct_byte_edit},
    b4_plan::{
        B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanExecutionV1,
        B4NegativePlanFixture, B4NegativeQaResultCode, Eip0045B4NegativePlanV1,
    },
    constants::{PROOF_BYTES, PROOF_WORDS},
};

const PARSER_FIRST_INDEX: usize = 72;
const PARSER_END_INDEX_EXCLUSIVE: usize = 108;
const PARSER_SELECTOR: &str = "lift-po2-15-parser-oracle";
const LIFT_CASE_ID: &str = "lift-po2-15";
const WORD_BYTES: usize = 4;

#[derive(Clone, Copy, Debug)]
struct ParserSources<'a> {
    raw_seal: &'a [u8],
    manifest: &'a [u8],
}

impl<'a> ParserSources<'a> {
    fn authenticate_v1(top_level: &'a B4AuthenticatedMaterializationTopLevelV1) -> Result<Self> {
        let resolver = B4FixtureSourceResolverV1::from_authenticated(top_level)
            .context("parser producer cannot authenticate the fixture source inventory")?;
        let positive = resolver
            .positive_case(0, LIFT_CASE_ID)
            .context("parser producer cannot select exact positive case zero")?;
        let input = resolver
            .positive_input()
            .context("parser producer cannot authenticate the positive input package")?;
        input
            .initial_profile_manifest()
            .context("parser producer initial profile manifest is invalid")?;
        Self::from_authenticated_parts(
            positive.case_index(),
            positive.case_id(),
            positive.raw_seal(),
            input.profile_manifest(),
        )
    }

    fn authenticate_v2(
        top_level: &'a B4AuthenticatedMaterializationTopLevelV2,
    ) -> Result<(Self, &'a [u8])> {
        let resolver = B4MaterializationFixtureSourceResolverV2::from_authenticated(top_level)
            .context("V2 parser producer cannot authenticate the fixture source inventory")?;
        let positive = resolver
            .positive_case(0, LIFT_CASE_ID)
            .context("V2 parser producer cannot select exact positive case zero")?;
        let input = resolver
            .positive_input()
            .context("V2 parser producer cannot authenticate the positive input package")?;
        input
            .initial_profile_manifest()
            .context("V2 parser producer initial profile manifest is invalid")?;
        let sources = Self::from_authenticated_parts(
            positive.case_index(),
            positive.case_id(),
            positive.raw_seal(),
            input.profile_manifest(),
        )?;
        Ok((sources, resolver.negative_plan_jcs()))
    }

    fn from_authenticated_parts(
        case_index: usize,
        case_id: &str,
        raw_seal: &'a [u8],
        manifest: &'a [u8],
    ) -> Result<Self> {
        ensure!(
            case_index == 0 && case_id == LIFT_CASE_ID,
            "parser producer selected a different positive case"
        );
        ensure!(
            raw_seal.len() == PROOF_BYTES
                && raw_seal.len() % WORD_BYTES == 0
                && raw_seal.len() / WORD_BYTES == PROOF_WORDS,
            "parser producer raw seal differs from the exact word-aligned proof shape"
        );
        Ok(Self { raw_seal, manifest })
    }
}

#[derive(Clone, Copy, Debug)]
struct ParserRawReplayAdapterV1<'a> {
    sources: ParserSources<'a>,
    expected_materialization: &'a B4NegativeMaterialization,
    output: &'a [u8],
}

impl B4MaterializationReplayAdapterV1 for ParserRawReplayAdapterV1<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::VerifierInput
    }

    fn base_bytes(&self) -> &[u8] {
        self.sources.raw_seal
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
            base_selector_id == PARSER_SELECTOR && materialization == self.expected_materialization,
            "parser replay received a selector or recipe outside its closed row"
        );
        let B4NegativeMaterialization::Mutation {
            mutation:
                B4NegativeMutation::ByteEdit {
                    target: B4ByteTarget::RawSeal,
                    edit,
                },
        } = materialization
        else {
            bail!("parser replay received a non-raw-seal truncation recipe");
        };
        ensure!(
            matches!(edit, B4ByteOperation::Truncate { .. }),
            "parser replay received a non-truncation byte edit"
        );
        let replayed = reconstruct_byte_edit(self.sources.raw_seal, edit)
            .context("parser replay cannot reconstruct the authenticated seal prefix")?;
        ensure!(
            replayed == self.output,
            "parser replay output differs from the authenticated seal prefix"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct ParserFinalReplayAdapterV1<'a> {
    sources: ParserSources<'a>,
    expected_materialization: &'a B4NegativeMaterialization,
    output: &'a [u8],
}

impl B4MaterializationReplayAdapterV1 for ParserFinalReplayAdapterV1<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::VerifierInput
    }

    fn base_bytes(&self) -> &[u8] {
        self.sources.raw_seal
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
            base_selector_id == PARSER_SELECTOR && materialization == self.expected_materialization,
            "parser final replay received a selector or recipe outside its closed row"
        );
        let B4NegativeMaterialization::Mutation {
            mutation:
                B4NegativeMutation::ByteEdit {
                    target: B4ByteTarget::RawSeal,
                    edit:
                        B4ByteOperation::Truncate {
                            before_hex,
                            new_length,
                            original_length,
                        },
                },
        } = materialization
        else {
            bail!("parser final replay received a non-raw-seal truncation recipe");
        };
        ensure!(
            *original_length == u64::try_from(PROOF_BYTES)?,
            "parser final replay original length differs from the authenticated seal"
        );
        let boundary =
            usize::try_from(*new_length).context("parser final boundary does not fit usize")?;
        let witness = hex::decode(before_hex).context("parser final witness is not valid hex")?;
        ensure!(
            witness.len() == WORD_BYTES,
            "parser final witness is not one complete word"
        );
        let witness_end = boundary
            .checked_add(WORD_BYTES)
            .context("parser final witness range overflows usize")?;
        ensure!(
            self.sources.raw_seal.get(boundary..witness_end) == Some(witness.as_slice()),
            "parser final witness differs from the authenticated boundary word"
        );
        ensure!(
            self.sources.raw_seal.get(..boundary) == Some(self.output),
            "parser final output is not the exact unframed authenticated seal prefix"
        );
        Ok(())
    }
}

/// Reconstruct one exact parser-prefix execution.
pub(crate) fn reconstruct_parser_execution(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    if !(PARSER_FIRST_INDEX..PARSER_END_INDEX_EXCLUSIVE).contains(&execution_index) {
        return Ok(None);
    }
    let sources = ParserSources::authenticate_v1(top_level)?;
    reconstruct_parser_execution_core(execution_index, planned, &top_level.negative_plan, sources)
        .map(Some)
}

/// Reconstruct one exact parser-prefix execution from V2-authenticated sources.
pub(crate) fn reconstruct_parser_execution_v2(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV2,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    if !(PARSER_FIRST_INDEX..PARSER_END_INDEX_EXCLUSIVE).contains(&execution_index) {
        return Ok(None);
    }
    let (sources, negative_plan_jcs) = ParserSources::authenticate_v2(top_level)?;
    reconstruct_parser_execution_core(execution_index, planned, negative_plan_jcs, sources)
        .map(Some)
}

fn reconstruct_parser_execution_core(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    sources: ParserSources<'_>,
) -> Result<B4ClosedReconstructedExecutionV1> {
    validate_planned_row(execution_index, planned, negative_plan_jcs)?;
    let cut_words = planned
        .parser_truncation_words
        .context("parser plan row lacks its exact truncation cut")?;
    let cut_words =
        usize::try_from(cut_words).context("parser truncation cut does not fit usize")?;
    ensure!(
        cut_words < PROOF_WORDS,
        "parser truncation cut must be strictly before the canonical proof EOF"
    );
    let new_length = cut_words
        .checked_mul(WORD_BYTES)
        .context("parser truncation byte boundary overflows usize")?;
    let witness_end = new_length
        .checked_add(WORD_BYTES)
        .context("parser truncation witness range overflows usize")?;
    let before = sources
        .raw_seal
        .get(new_length..witness_end)
        .context("parser truncation lacks one complete boundary word")?;
    let edit = B4ByteOperation::Truncate {
        before_hex: hex::encode(before),
        new_length: u64::try_from(new_length)
            .context("parser truncation byte boundary does not fit u64")?,
        original_length: u64::try_from(PROOF_BYTES)
            .context("canonical proof byte length does not fit u64")?,
    };
    let materialization = B4NegativeMaterialization::Mutation {
        mutation: B4NegativeMutation::ByteEdit {
            target: B4ByteTarget::RawSeal,
            edit: edit.clone(),
        },
    };
    let subject = reconstruct_byte_edit(sources.raw_seal, &edit)?;
    ensure!(
        subject == sources.raw_seal[..new_length],
        "parser subject differs from the exact authenticated seal prefix"
    );
    let registry_row = B4NegativeCase {
        execution_id: planned.execution_id.clone(),
        base_selector_id: PARSER_SELECTOR.to_owned(),
        materialization_domain: B4MaterializationDomain::VerifierInput,
        materialization,
    };
    let expected_materialization = registry_row.materialization.clone();
    let raw_adapter = ParserRawReplayAdapterV1 {
        sources,
        expected_materialization: &expected_materialization,
        output: &subject,
    };
    let final_adapter = ParserFinalReplayAdapterV1 {
        sources,
        expected_materialization: &expected_materialization,
        output: &subject,
    };
    close_production_execution(
        execution_index,
        planned,
        negative_plan_jcs,
        registry_row,
        &raw_adapter,
        &final_adapter,
        subject.clone(),
        vec![sources.manifest.to_vec()],
    )
}

fn validate_planned_row(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
) -> Result<()> {
    let canonical_plan = Eip0045B4NegativePlanV1::from_canonical_jcs(negative_plan_jcs)
        .context("parser producer negative plan is not canonical")?;
    let canonical_row = canonical_plan
        .groups
        .iter()
        .flat_map(|group| group.executions.iter())
        .nth(execution_index)
        .context("parser producer index is outside the canonical plan")?;
    ensure!(
        canonical_row == planned,
        "parser execution differs from its canonical-plan identity"
    );
    ensure!(
        planned.base_selector_id == PARSER_SELECTOR
            && planned.fixture == B4NegativePlanFixture::LiftPo215ParserOracle
            && planned.materialization_domain == B4MaterializationDomain::VerifierInput
            && planned.execution_surface == B4NegativeExecutionSurface::Risc0ParserInternal
            && planned.qa_result_code == B4NegativeQaResultCode::B4ParserUnexpectedEofAtPhase
            && planned.parser_truncation_words.is_some(),
        "parser execution differs from the exact parser-row contract"
    );
    Ok(())
}

/// Local producer/consumer seam. Authentication is reused from the genuine
/// stock Lift15 loader; no top-level authority or mutation search is created.
#[cfg(all(test, feature = "negative-materialization-set"))]
pub(crate) mod genuine_parser {
    use super::*;
    use std::path::Path;

    pub(crate) struct Fixture {
        source: crate::b4_c2_crypto::genuine_crypto_join::Fixture,
    }

    pub(crate) fn load_fixture(root: &Path) -> Result<Fixture> {
        Ok(Fixture { source: crate::b4_c2_crypto::genuine_crypto_join::load_fixture(root)? })
    }

    fn require_index(index: usize) -> Result<()> {
        ensure!((72..108).contains(&index), "genuine parser seam permits only rows 72 through 107");
        Ok(())
    }

    impl Fixture {
        pub(crate) fn raw(&self) -> &[u8] { &self.source.raw }
        pub(crate) fn manifest(&self) -> &[u8] { &self.source.manifest }

        pub(crate) fn reconstruct(&self, index: usize) -> Result<B4ClosedReconstructedExecutionV1> {
            require_index(index)?;
            let plan = Eip0045B4NegativePlanV1::canonical()?;
            let plan_jcs = plan.to_canonical_jcs()?;
            let planned = plan.groups.iter().flat_map(|group| group.executions.iter())
                .nth(index).context("canonical parser row absent")?;
            let sources = ParserSources::from_authenticated_parts(0, LIFT_CASE_ID,
                self.raw(), self.manifest())?;
            reconstruct_parser_execution_core(index, planned, &plan_jcs, sources)
        }
    }

    #[test]
    fn genuine_parser_seam_indices_and_late_cut_are_closed() {
        for index in 0..254 {
            match index {
                72..=107 => require_index(index).unwrap(),
                _ => assert_eq!(require_index(index).unwrap_err().to_string(),
                    "genuine parser seam permits only rows 72 through 107"),
            }
        }
        assert_eq!(require_index(usize::MAX).unwrap_err().to_string(),
            "genuine parser seam permits only rows 72 through 107");
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let row = plan.groups.iter().flat_map(|group| group.executions.iter()).nth(94).unwrap();
        assert_eq!(row.execution_id, "parser-phase-truncation-sweep--queries-at-last-required-word");
        assert_eq!(row.parser_truncation_words, Some(55_666));
        assert_eq!(row.execution_surface, B4NegativeExecutionSurface::Risc0ParserInternal);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        b4::{B4ByteOperation, B4NegativeMaterialization, B4NegativeMutation},
        b4_materialization_set::authority_tdd_tests::production_shaped_fixture_top_level,
        b4_mutation::Eip0045B4MaterializationIdentityV1,
        b4_negative_io::Eip0045B4NegativeVerifierInputV1,
        b4_plan::{
            B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanFixture,
            B4NegativeQaResultCode, Eip0045B4NegativePlanV1,
        },
        constants::PROOF_BYTES,
    };

    const EXPECTED_PARSER_ROWS: [(usize, &str, u32); 36] = [
        (72, "output-before-read", 0),
        (73, "output-at-last-required-word", 31),
        (74, "outer-po2-before-read", 32),
        (75, "code-top-before-read", 33),
        (76, "code-top-at-last-required-word", 288),
        (77, "data-top-before-read", 289),
        (78, "data-top-at-last-required-word", 544),
        (79, "accum-top-before-read", 545),
        (80, "accum-top-at-last-required-word", 800),
        (81, "check-top-before-read", 801),
        (82, "check-top-at-last-required-word", 1_056),
        (83, "coeff-u-before-read", 1_057),
        (84, "coeff-u-at-last-required-word", 3_692),
        (85, "fri-round-one-top-before-read", 3_693),
        (86, "fri-round-one-top-at-last-required-word", 3_948),
        (87, "fri-round-two-top-before-read", 3_949),
        (88, "fri-round-two-top-at-last-required-word", 4_204),
        (89, "fri-round-three-top-before-read", 4_205),
        (90, "fri-round-three-top-at-last-required-word", 4_460),
        (91, "final-coefficients-before-read", 4_461),
        (92, "final-coefficients-at-last-required-word", 4_716),
        (93, "queries-before-read", 4_717),
        (94, "queries-at-last-required-word", 55_666),
        (95, "query-zero-accum-opening-at-last-required-word", 4_848),
        (96, "query-zero-code-opening-before-read", 4_849),
        (97, "query-zero-code-opening-at-last-required-word", 4_991),
        (98, "query-zero-data-opening-before-read", 4_992),
        (99, "query-zero-data-opening-at-last-required-word", 5_239),
        (100, "query-zero-check-opening-before-read", 5_240),
        (101, "query-zero-check-opening-at-last-required-word", 5_375),
        (102, "query-zero-fri-round-one-opening-before-read", 5_376),
        (
            103,
            "query-zero-fri-round-one-opening-at-last-required-word",
            5_527,
        ),
        (104, "query-zero-fri-round-two-opening-before-read", 5_528),
        (
            105,
            "query-zero-fri-round-two-opening-at-last-required-word",
            5_647,
        ),
        (106, "query-zero-fri-round-three-opening-before-read", 5_648),
        (
            107,
            "query-zero-fri-round-three-opening-at-last-required-word",
            5_735,
        ),
    ];

    fn parser_top_level() -> B4AuthenticatedMaterializationTopLevelV1 {
        production_shaped_fixture_top_level()
    }

    fn flattened_plan() -> Vec<B4NegativePlanExecutionV1> {
        Eip0045B4NegativePlanV1::canonical()
            .unwrap()
            .groups
            .into_iter()
            .flat_map(|group| group.executions)
            .collect()
    }

    #[test]
    fn reconstructs_all_thirty_six_exact_parser_prefix_rows() {
        let top_level = parser_top_level();
        let plan = flattened_plan();
        let full_seal = &top_level.positive_exports[0].raw_seal;
        let manifest = top_level
            .source_artifacts
            .get("profiles/risc0-v3-succinct/manifest.bin")
            .unwrap();

        for (index, variant_id, expected_cut_words) in EXPECTED_PARSER_ROWS {
            let planned = &plan[index];
            assert_eq!(
                planned.execution_id,
                format!("parser-phase-truncation-sweep--{variant_id}")
            );
            assert_eq!(planned.parser_truncation_words, Some(expected_cut_words));
            let cut_words = usize::try_from(expected_cut_words).unwrap();
            let new_length = cut_words.checked_mul(4).unwrap();
            let reconstructed = reconstruct_parser_execution(index, planned, &top_level)
                .unwrap()
                .unwrap();
            assert_eq!(reconstructed.base, *full_seal);
            assert_eq!(reconstructed.subject, full_seal[..new_length]);
            assert_eq!(reconstructed.contexts, vec![manifest.clone()]);
            assert_eq!(
                reconstructed.derived_registry_row.execution_id,
                planned.execution_id
            );
            assert_eq!(
                reconstructed.derived_registry_row.base_selector_id,
                "lift-po2-15-parser-oracle"
            );
            assert_eq!(
                reconstructed.derived_registry_row.materialization_domain,
                B4MaterializationDomain::VerifierInput
            );
            let B4NegativeMaterialization::Mutation {
                mutation:
                    B4NegativeMutation::ByteEdit {
                        target,
                        edit:
                            B4ByteOperation::Truncate {
                                before_hex,
                                new_length: recipe_length,
                                original_length,
                            },
                    },
            } = &reconstructed.derived_registry_row.materialization
            else {
                panic!("parser row {index} has the wrong recipe");
            };
            assert_eq!(*target, crate::b4::B4ByteTarget::RawSeal);
            assert_eq!(*recipe_length, u64::try_from(new_length).unwrap());
            assert_eq!(*original_length, u64::try_from(PROOF_BYTES).unwrap());
            assert_eq!(
                before_hex,
                &hex::encode(&full_seal[new_length..new_length + 4])
            );

            let identity = Eip0045B4MaterializationIdentityV1::from_canonical_jcs(
                &reconstructed.materialization_identity_jcs,
            )
            .unwrap();
            assert_eq!(identity.execution_id, planned.execution_id);
            assert_eq!(
                identity.output_byte_length,
                u64::try_from(new_length).unwrap()
            );
            assert_eq!(
                identity.to_canonical_jcs().unwrap(),
                reconstructed.materialization_identity_jcs
            );
            let input = Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(
                &reconstructed.negative_input_jcs,
            )
            .unwrap();
            assert_eq!(
                input.validation_surface,
                B4NegativeExecutionSurface::Risc0ParserInternal
            );
            assert_eq!(input.context.len(), 1);
            assert_eq!(
                input.to_canonical_jcs().unwrap(),
                reconstructed.negative_input_jcs
            );
        }
    }

    #[test]
    fn zero_cut_and_outside_range_are_exact() {
        let top_level = parser_top_level();
        let plan = flattened_plan();
        let zero = reconstruct_parser_execution(72, &plan[72], &top_level)
            .unwrap()
            .unwrap();
        assert!(zero.subject.is_empty());
        let B4NegativeMaterialization::Mutation {
            mutation:
                B4NegativeMutation::ByteEdit {
                    edit:
                        B4ByteOperation::Truncate {
                            before_hex,
                            new_length,
                            ..
                        },
                    ..
                },
        } = zero.derived_registry_row.materialization
        else {
            panic!("zero parser row has the wrong recipe");
        };
        assert_eq!(new_length, 0);
        assert_eq!(
            before_hex,
            hex::encode(&top_level.positive_exports[0].raw_seal[..4])
        );
        for index in [0, 71, 108, 253, 254] {
            let planned = &plan[index.min(253)];
            assert!(
                reconstruct_parser_execution(index, planned, &top_level)
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn rejects_every_planned_field_drift_and_cut_drift() {
        let top_level = parser_top_level();
        let plan = flattened_plan();
        let source = &plan[72];
        let mut drifts = Vec::new();

        let mut wrong_id = source.clone();
        wrong_id.execution_id.push('x');
        drifts.push(wrong_id);
        let mut wrong_selector = source.clone();
        wrong_selector.base_selector_id = "lift-po2-15".to_owned();
        drifts.push(wrong_selector);
        let mut wrong_fixture = source.clone();
        wrong_fixture.fixture = B4NegativePlanFixture::LiftPo215;
        drifts.push(wrong_fixture);
        let mut wrong_domain = source.clone();
        wrong_domain.materialization_domain = B4MaterializationDomain::ArtifactValidator;
        drifts.push(wrong_domain);
        let mut wrong_surface = source.clone();
        wrong_surface.execution_surface = B4NegativeExecutionSurface::RawSealShape;
        drifts.push(wrong_surface);
        let mut wrong_qa = source.clone();
        wrong_qa.qa_result_code = B4NegativeQaResultCode::RawSealClaimMismatch;
        drifts.push(wrong_qa);
        let mut missing_cut = source.clone();
        missing_cut.parser_truncation_words = None;
        drifts.push(missing_cut);
        let mut wrong_cut = source.clone();
        wrong_cut.parser_truncation_words = Some(1);
        drifts.push(wrong_cut);

        for drift in drifts {
            assert!(reconstruct_parser_execution(72, &drift, &top_level).is_err());
        }
        assert!(reconstruct_parser_execution(73, source, &top_level).is_err());

        let mut wrong_plan_source = top_level.clone();
        let last = wrong_plan_source.negative_plan.len() - 1;
        wrong_plan_source.negative_plan[last] ^= 1;
        assert!(reconstruct_parser_execution(72, source, &wrong_plan_source).is_err());
    }

    #[test]
    fn rejects_truncated_and_drifted_authenticated_seal_sources() {
        let plan = flattened_plan();
        let mut truncated = parser_top_level();
        truncated.positive_exports[0].raw_seal.pop();
        assert!(reconstruct_parser_execution(72, &plan[72], &truncated).is_err());

        let mut drifted = parser_top_level();
        drifted.positive_exports[0].raw_seal[0] ^= 1;
        assert!(reconstruct_parser_execution(72, &plan[72], &drifted).is_err());
    }

    #[test]
    fn v2_entrypoint_uses_only_the_v2_wrapper_resolver_and_shared_core() {
        fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
            source
                .split(start)
                .nth(1)
                .unwrap()
                .split(end)
                .next()
                .unwrap()
        }

        let source = include_str!("b4_c2_parser.rs");
        let authentication = section(
            source,
            "fn authenticate_v2(",
            "fn from_authenticated_parts(",
        );
        assert!(authentication.contains("B4MaterializationFixtureSourceResolverV2"));
        assert!(authentication.contains("resolver.negative_plan_jcs()"));
        assert!(!authentication.contains("B4FixtureSourceResolverV1"));
        assert!(!authentication.contains(".storage()"));

        let entrypoint = section(
            source,
            "pub(crate) fn reconstruct_parser_execution_v2(",
            "fn reconstruct_parser_execution_core(",
        );
        assert!(entrypoint.contains("B4AuthenticatedMaterializationTopLevelV2"));
        assert!(entrypoint.contains("ParserSources::authenticate_v2(top_level)"));
        assert!(!entrypoint.contains("B4AuthenticatedMaterializationTopLevelV1"));
        assert!(!entrypoint.contains("B4FixtureSourceResolverV1"));
        assert!(!entrypoint.contains(".storage()"));

        let core = section(
            source,
            "fn reconstruct_parser_execution_core(",
            "fn validate_planned_row(",
        );
        assert!(core.contains("negative_plan_jcs: &[u8]"));
        assert!(!core.contains("B4AuthenticatedMaterializationTopLevel"));
        assert!(!core.contains("FixtureSourceResolver"));
    }
}
