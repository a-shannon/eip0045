//! Closed producer for the case-9 conditional receipt-claim row.

use anyhow::{Context as _, Result, ensure};

use crate::{
    b4::{B4NegativeCase, B4NegativeMaterialization},
    b4_fixture_sources::{B4FixtureSourceResolverV1, B4MaterializationFixtureSourceResolverV2},
    b4_materialization_set::{
        B4AuthenticatedMaterializationTopLevelV1, B4AuthenticatedMaterializationTopLevelV2,
        B4ClosedReconstructedExecutionV1, close_production_execution,
    },
    b4_mutation::B4FixtureSelectionReplayAdapterV1,
    b4_plan::{
        B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanExecutionV1,
        B4NegativePlanFixture, B4NegativeQaResultCode,
    },
};

const RECEIPT_CLAIM_ROW_INDEX: usize = 140;
const RECEIPT_CLAIM_EXECUTION_ID: &str = "claim-final-assumptions-nonempty--nonempty-assumptions";
const RECEIPT_CLAIM_VARIANT_ID: &str = "nonempty-assumptions";
const RECEIPT_CLAIM_FIXTURE_ID: &str = "case9-conditional-receipt-v1";

/// Reconstruct only the case-9 conditional receipt-claim row.
#[cfg_attr(
    not(all(feature = "negative-materialization-set", target_os = "linux")),
    allow(
        dead_code,
        reason = "the production dispatcher is descriptor-rooted and Linux-only; other feature sets retain this producer for focused tests"
    )
)]
pub(crate) fn reconstruct_receipt_claim_execution(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    if execution_index != RECEIPT_CLAIM_ROW_INDEX {
        return Ok(None);
    }
    let resolver = B4FixtureSourceResolverV1::from_authenticated(top_level)
        .context("receipt-claim producer cannot authenticate fixture sources")?;
    let source = resolver
        .case9_conditional_receipt_source()
        .context("receipt-claim producer cannot resolve exact case-9 step zero")?;
    reconstruct_receipt_claim_execution_core(
        execution_index,
        planned,
        &top_level.negative_plan,
        source.conditional_raw_seal(),
        source.profile_manifest_context(),
        source.statement_context(),
    )
    .map(Some)
}

/// Reconstruct the case-9 conditional receipt-claim row from V2-authenticated sources.
pub(crate) fn reconstruct_receipt_claim_execution_v2(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV2,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    if execution_index != RECEIPT_CLAIM_ROW_INDEX {
        return Ok(None);
    }
    let resolver = B4MaterializationFixtureSourceResolverV2::from_authenticated(top_level)
        .context("V2 receipt-claim producer cannot authenticate fixture sources")?;
    let source = resolver
        .case9_conditional_receipt_source()
        .context("V2 receipt-claim producer cannot resolve exact case-9 step zero")?;
    reconstruct_receipt_claim_execution_core(
        execution_index,
        planned,
        resolver.negative_plan_jcs(),
        source.conditional_raw_seal(),
        source.profile_manifest_context(),
        source.statement_context(),
    )
    .map(Some)
}

fn reconstruct_receipt_claim_execution_core(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    fixture: &[u8],
    profile_manifest_context: &[u8],
    statement_context: &[u8],
) -> Result<B4ClosedReconstructedExecutionV1> {
    validate_planned_execution(planned)?;
    let adapter = B4FixtureSelectionReplayAdapterV1 {
        materialization_domain: B4MaterializationDomain::VerifierInput,
        fixture,
    };
    let registry_row = B4NegativeCase {
        execution_id: RECEIPT_CLAIM_EXECUTION_ID.to_owned(),
        base_selector_id: RECEIPT_CLAIM_FIXTURE_ID.to_owned(),
        materialization_domain: B4MaterializationDomain::VerifierInput,
        materialization: B4NegativeMaterialization::FixtureSelection {
            fixture_id: RECEIPT_CLAIM_FIXTURE_ID.to_owned(),
        },
    };

    close_production_execution(
        execution_index,
        planned,
        negative_plan_jcs,
        registry_row,
        &adapter,
        &adapter,
        fixture.to_vec(),
        vec![
            profile_manifest_context.to_vec(),
            statement_context.to_vec(),
        ],
    )
}

fn validate_planned_execution(planned: &B4NegativePlanExecutionV1) -> Result<()> {
    ensure!(
        planned.execution_id == RECEIPT_CLAIM_EXECUTION_ID
            && planned.variant_id == RECEIPT_CLAIM_VARIANT_ID
            && planned.base_selector_id == RECEIPT_CLAIM_FIXTURE_ID
            && planned.fixture == B4NegativePlanFixture::Case9ConditionalReceiptV1
            && planned.materialization_domain == B4MaterializationDomain::VerifierInput
            && planned.execution_surface == B4NegativeExecutionSurface::ReceiptClaimPolicy
            && planned.qa_result_code == B4NegativeQaResultCode::RawSealClaimMismatch
            && planned.parser_truncation_words.is_none(),
        "canonical row 140 differs from the closed conditional receipt-claim mapping"
    );
    Ok(())
}

/// Local test seam for externally authenticated case-9 conditional receipt bytes.
/// This performs only canonical row reconstruction, not source authentication or
/// campaign authorization. The caller must authenticate all three inputs first.
#[cfg(test)]
pub(crate) fn reconstruct_genuine_case9(
    conditional_raw: &[u8],
    manifest: &[u8],
    statement: &[u8],
) -> Result<B4ClosedReconstructedExecutionV1> {
    let plan = crate::b4_plan::Eip0045B4NegativePlanV1::canonical()?;
    let plan_jcs = plan.to_canonical_jcs()?;
    let planned = plan
        .groups
        .iter()
        .flat_map(|group| group.executions.iter())
        .nth(RECEIPT_CLAIM_ROW_INDEX)
        .context("canonical plan has no case-9 conditional receipt row 140")?;
    reconstruct_receipt_claim_execution_core(
        RECEIPT_CLAIM_ROW_INDEX,
        planned,
        &plan_jcs,
        conditional_raw,
        manifest,
        statement,
    )
}

#[cfg(test)]
mod tests {
    use crate::{
        b4::B4NegativeMaterialization,
        b4_fixture_sources::{
            B4FixtureSourceResolverV1, synthetic_valid_recursive_ancestry_top_level,
        },
        b4_mutation::Eip0045B4MaterializationIdentityV1,
        b4_negative_io::Eip0045B4NegativeVerifierInputV1,
        b4_plan::{
            B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanFixture,
            B4NegativeQaResultCode, Eip0045B4NegativePlanV1,
        },
    };

    use super::reconstruct_receipt_claim_execution;

    const ROW_INDEX: usize = 140;

    #[test]
    fn row_140_selects_only_case9_step_zero_with_exact_context_order() {
        let top_level = synthetic_valid_recursive_ancestry_top_level();
        let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(&top_level.negative_plan).unwrap();
        let planned = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .nth(ROW_INDEX)
            .unwrap();
        let resolver = B4FixtureSourceResolverV1::from_authenticated(&top_level).unwrap();
        let source = resolver.case9_conditional_receipt_source().unwrap();
        let expected_subject = source.conditional_raw_seal().to_vec();
        let expected_contexts = vec![
            source.profile_manifest_context().to_vec(),
            source.statement_context().to_vec(),
        ];

        let reconstructed = reconstruct_receipt_claim_execution(ROW_INDEX, planned, &top_level)
            .unwrap()
            .unwrap();

        assert_eq!(reconstructed.base, expected_subject);
        assert_eq!(reconstructed.subject, expected_subject);
        assert_eq!(reconstructed.contexts, expected_contexts);
        assert_eq!(
            reconstructed.derived_registry_row.materialization,
            B4NegativeMaterialization::FixtureSelection {
                fixture_id: "case9-conditional-receipt-v1".to_owned(),
            }
        );
        let identity = Eip0045B4MaterializationIdentityV1::from_canonical_jcs(
            &reconstructed.materialization_identity_jcs,
        )
        .unwrap();
        assert_eq!(identity.base_sha256, identity.output_sha256);
        let input =
            Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(&reconstructed.negative_input_jcs)
                .unwrap();
        assert_eq!(input.context.len(), 2);
    }

    #[test]
    fn row_140_rejects_plan_drift_and_ignores_every_other_index() {
        let top_level = synthetic_valid_recursive_ancestry_top_level();
        let plan = Eip0045B4NegativePlanV1::from_canonical_jcs(&top_level.negative_plan).unwrap();
        let flattened = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter())
            .collect::<Vec<_>>();

        assert!(
            reconstruct_receipt_claim_execution(139, flattened[139], &top_level)
                .unwrap()
                .is_none()
        );
        assert!(
            reconstruct_receipt_claim_execution(141, flattened[141], &top_level)
                .unwrap()
                .is_none()
        );

        let mut wrong = flattened[ROW_INDEX].clone();
        wrong.base_selector_id = "wrong-fixture".to_owned();
        assert!(reconstruct_receipt_claim_execution(ROW_INDEX, &wrong, &top_level).is_err());

        let mut wrong = flattened[ROW_INDEX].clone();
        wrong.fixture = B4NegativePlanFixture::AllowedTerminalNonOkV1;
        assert!(reconstruct_receipt_claim_execution(ROW_INDEX, &wrong, &top_level).is_err());

        let mut wrong = flattened[ROW_INDEX].clone();
        wrong.materialization_domain = B4MaterializationDomain::ArtifactValidator;
        assert!(reconstruct_receipt_claim_execution(ROW_INDEX, &wrong, &top_level).is_err());

        let mut wrong = flattened[ROW_INDEX].clone();
        wrong.execution_surface = B4NegativeExecutionSurface::AncestryReplay;
        assert!(reconstruct_receipt_claim_execution(ROW_INDEX, &wrong, &top_level).is_err());

        let mut wrong = flattened[ROW_INDEX].clone();
        wrong.qa_result_code = B4NegativeQaResultCode::B4AncestryClaimEdgeMismatch;
        assert!(reconstruct_receipt_claim_execution(ROW_INDEX, &wrong, &top_level).is_err());
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

        let source = include_str!("b4_c2_receipt_claim.rs");
        let entrypoint = section(
            source,
            "pub(crate) fn reconstruct_receipt_claim_execution_v2(",
            "fn reconstruct_receipt_claim_execution_core(",
        );
        assert!(entrypoint.contains("B4AuthenticatedMaterializationTopLevelV2"));
        assert!(entrypoint.contains("B4MaterializationFixtureSourceResolverV2"));
        assert!(entrypoint.contains("resolver.negative_plan_jcs()"));
        assert!(!entrypoint.contains("B4AuthenticatedMaterializationTopLevelV1"));
        assert!(!entrypoint.contains("B4FixtureSourceResolverV1"));
        assert!(!entrypoint.contains(".storage()"));

        let core = section(
            source,
            "fn reconstruct_receipt_claim_execution_core(",
            "fn validate_planned_execution(",
        );
        assert!(core.contains("negative_plan_jcs: &[u8]"));
        assert!(!core.contains("B4AuthenticatedMaterializationTopLevel"));
        assert!(!core.contains("FixtureSourceResolver"));
    }
}
