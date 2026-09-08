// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Fixed terminal-fixture recipes admitted only through the opaque terminal import.

#![allow(
    dead_code,
    reason = "the staged-source seam remains available only to isolated producer tests"
)]

use std::fmt;

use anyhow::{Result, bail, ensure};

#[cfg(feature = "negative-materialization-set")]
use crate::b4_terminal_evidence_packet::{
    B4TerminalEvidenceImportAuthorityV1, B4TerminalEvidenceImportAuthorityV2,
};
use crate::{
    b4::{B4NegativeCase, B4NegativeMaterialization},
    b4_materialization_set::{B4ClosedReconstructedExecutionV1, close_production_execution},
    b4_mutation::B4MaterializationReplayAdapterV1,
    b4_plan::{
        B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanExecutionV1,
        B4NegativePlanFixture, B4NegativeQaResultCode,
    },
    b4_terminal::{B4_TERMINAL_FIXTURE_COUNT, B4_TERMINAL_FIXTURE_LAYOUT},
    constants::{MANIFEST_BYTES, PROOF_BYTES},
    profile_manifest::StarkProfileManifestV1,
};

const TERMINAL_FIXTURE_FIRST_INDEX: usize = 131;
const TERMINAL_FIXTURE_END_INDEX_EXCLUSIVE: usize = 140;
const ALLOWED_NON_OK_SELECTOR: &str = "allowed-terminal-non-ok-v1";

struct StagedTerminalFixtureRecipeSourceV1<'a> {
    profile_manifest: &'a [u8],
    reference_statement: &'a [u8],
    raw_seals: [&'a [u8]; B4_TERMINAL_FIXTURE_COUNT],
}

struct TerminalFixtureRawReplayAdapterV1<'a> {
    execution_index: usize,
    planned: &'a B4NegativePlanExecutionV1,
    source: &'a StagedTerminalFixtureRecipeSourceV1<'a>,
}

impl fmt::Debug for TerminalFixtureRawReplayAdapterV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TerminalFixtureRawReplayAdapterV1")
            .field("execution_index", &self.execution_index)
            .finish_non_exhaustive()
    }
}

impl B4MaterializationReplayAdapterV1 for TerminalFixtureRawReplayAdapterV1<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::VerifierInput
    }

    fn base_bytes(&self) -> &[u8] {
        self.source.raw_seals[self.execution_index - TERMINAL_FIXTURE_FIRST_INDEX]
    }

    fn output_bytes(&self) -> &[u8] {
        self.base_bytes()
    }

    fn replay_recipe(
        &self,
        base_selector_id: &str,
        materialization: &B4NegativeMaterialization,
    ) -> Result<()> {
        let expected = expected_row(self.execution_index)?;
        validate_planned_execution(self.planned, &expected)?;
        let expected_materialization = B4NegativeMaterialization::FixtureSelection {
            fixture_id: expected.selector.to_owned(),
        };
        let B4NegativeMaterialization::FixtureSelection { fixture_id } = materialization else {
            bail!("terminal-fixture raw replay received a mutation");
        };
        ensure!(
            base_selector_id == expected.selector
                && materialization == &expected_materialization
                && fixture_id == expected.selector,
            "terminal-fixture raw replay selected a different fixture"
        );
        Ok(())
    }
}

struct TerminalFixtureFinalReplayAdapterV1<'a> {
    execution_index: usize,
    planned: &'a B4NegativePlanExecutionV1,
    source: &'a StagedTerminalFixtureRecipeSourceV1<'a>,
    subject: &'a [u8],
}

impl fmt::Debug for TerminalFixtureFinalReplayAdapterV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TerminalFixtureFinalReplayAdapterV1")
            .field("execution_index", &self.execution_index)
            .finish_non_exhaustive()
    }
}

impl B4MaterializationReplayAdapterV1 for TerminalFixtureFinalReplayAdapterV1<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::VerifierInput
    }

    fn base_bytes(&self) -> &[u8] {
        self.source.raw_seals[self.execution_index - TERMINAL_FIXTURE_FIRST_INDEX]
    }

    fn output_bytes(&self) -> &[u8] {
        self.subject
    }

    fn replay_recipe(
        &self,
        base_selector_id: &str,
        materialization: &B4NegativeMaterialization,
    ) -> Result<()> {
        let expected = expected_row(self.execution_index)?;
        validate_planned_execution(self.planned, &expected)?;
        let expected_materialization = B4NegativeMaterialization::FixtureSelection {
            fixture_id: expected.selector.to_owned(),
        };
        let B4NegativeMaterialization::FixtureSelection { fixture_id } = materialization else {
            bail!("terminal-fixture final replay received a mutation");
        };
        ensure!(
            base_selector_id == expected.selector
                && materialization == &expected_materialization
                && fixture_id == expected.selector
                && self.subject == self.base_bytes(),
            "terminal-fixture final replay selected a different fixture"
        );
        Ok(())
    }
}

fn reconstruct_terminal_fixture_execution_from_staged_source(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    source: &StagedTerminalFixtureRecipeSourceV1<'_>,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    if !(TERMINAL_FIXTURE_FIRST_INDEX..TERMINAL_FIXTURE_END_INDEX_EXCLUSIVE)
        .contains(&execution_index)
    {
        return Ok(None);
    }
    let slot = execution_index - TERMINAL_FIXTURE_FIRST_INDEX;
    let expected = expected_row(execution_index)?;
    validate_planned_execution(planned, &expected)?;
    ensure!(
        source.profile_manifest.len() == MANIFEST_BYTES,
        "terminal-fixture profile manifest has the wrong byte length"
    );
    let manifest = StarkProfileManifestV1::decode(source.profile_manifest)?;
    manifest.validate_initial_profile_target()?;
    ensure!(
        execution_index != 139 || !source.reference_statement.is_empty(),
        "terminal-fixture non-OK row lacks its fixed reference statement"
    );
    let seal = source.raw_seals[slot];
    ensure!(
        seal.len() == PROOF_BYTES,
        "terminal-fixture raw seal has the wrong byte length"
    );
    let materialization = B4NegativeMaterialization::FixtureSelection {
        fixture_id: expected.selector.to_owned(),
    };
    let registry_row = B4NegativeCase {
        execution_id: expected.execution_id,
        base_selector_id: expected.selector.to_owned(),
        materialization_domain: B4MaterializationDomain::VerifierInput,
        materialization,
    };
    let subject = seal.to_vec();
    let raw_adapter = TerminalFixtureRawReplayAdapterV1 {
        execution_index,
        planned,
        source,
    };
    let final_adapter = TerminalFixtureFinalReplayAdapterV1 {
        execution_index,
        planned,
        source,
        subject: &subject,
    };
    let contexts = if execution_index == 139 {
        vec![
            source.profile_manifest.to_vec(),
            source.reference_statement.to_vec(),
        ]
    } else {
        vec![source.profile_manifest.to_vec()]
    };
    close_production_execution(
        execution_index,
        planned,
        negative_plan_jcs,
        registry_row,
        &raw_adapter,
        &final_adapter,
        subject.clone(),
        contexts,
    )
    .map(Some)
}

#[cfg(feature = "negative-materialization-set")]
pub(crate) fn reconstruct_terminal_fixture_execution(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    authority: &B4TerminalEvidenceImportAuthorityV1,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    let projection = authority.terminal_materialization_projection();
    let source = StagedTerminalFixtureRecipeSourceV1 {
        profile_manifest: projection.profile_manifest(),
        reference_statement: projection.reference_statement(),
        raw_seals: projection.raw_seals(),
    };
    reconstruct_terminal_fixture_execution_from_staged_source(
        execution_index,
        planned,
        negative_plan_jcs,
        &source,
    )
}

/// Reconstruct the same fixed fixture rows from the distinct V2 import.
///
/// The V2 authority supplies the exact manifest, statement, and nine seals;
/// this sibling exposes no selector, detached byte source, or V1 conversion.
#[cfg(feature = "negative-materialization-set")]
pub(crate) fn reconstruct_terminal_fixture_execution_v2(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    authority: &B4TerminalEvidenceImportAuthorityV2,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    let projection = authority.terminal_materialization_projection_v2();
    let source = StagedTerminalFixtureRecipeSourceV1 {
        profile_manifest: projection.profile_manifest(),
        reference_statement: projection.reference_statement(),
        raw_seals: projection.raw_seals(),
    };
    reconstruct_terminal_fixture_execution_from_staged_source(
        execution_index,
        planned,
        negative_plan_jcs,
        &source,
    )
}

struct ExpectedTerminalFixtureRow {
    execution_id: String,
    variant: &'static str,
    selector: &'static str,
    fixture: B4NegativePlanFixture,
    surface: B4NegativeExecutionSurface,
    qa: B4NegativeQaResultCode,
}

fn expected_row(execution_index: usize) -> Result<ExpectedTerminalFixtureRow> {
    if (131..=138).contains(&execution_index) {
        let slot = execution_index - 131;
        let fixture_id = B4_TERMINAL_FIXTURE_LAYOUT[slot].fixture_id;
        return Ok(ExpectedTerminalFixtureRow {
            execution_id: format!("terminal-excluded-shipping-family-sweep--{fixture_id}"),
            variant: fixture_id,
            selector: fixture_id,
            fixture: B4NegativePlanFixture::ExcludedFamilyReceiptsV1,
            surface: B4NegativeExecutionSurface::TerminalPolicy,
            qa: B4NegativeQaResultCode::RawSealControlIdNotAllowed,
        });
    }
    if execution_index == 139 {
        return Ok(ExpectedTerminalFixtureRow {
            execution_id: "claim-final-status-non-ok--non-ok-status".to_owned(),
            variant: "non-ok-status",
            selector: ALLOWED_NON_OK_SELECTOR,
            fixture: B4NegativePlanFixture::AllowedTerminalNonOkV1,
            surface: B4NegativeExecutionSurface::ReceiptClaimPolicy,
            qa: B4NegativeQaResultCode::RawSealClaimMismatch,
        });
    }
    bail!("terminal-fixture producer received an index outside its closed range")
}

fn validate_planned_execution(
    planned: &B4NegativePlanExecutionV1,
    expected: &ExpectedTerminalFixtureRow,
) -> Result<()> {
    ensure!(
        planned.execution_id == expected.execution_id
            && planned.variant_id == expected.variant
            && planned.base_selector_id == expected.selector
            && planned.fixture == expected.fixture
            && planned.materialization_domain == B4MaterializationDomain::VerifierInput
            && planned.execution_surface == expected.surface
            && planned.qa_result_code == expected.qa
            && planned.parser_truncation_words.is_none(),
        "canonical plan row differs from the staged terminal-fixture mapping"
    );
    Ok(())
}

/// Local reconstruction from a replayed nineteen-file export, never an import authority.
#[cfg(all(test, feature = "validator", feature = "materializer-replay"))]
pub(crate) mod genuine_terminal_policy {
    use super::*;
    use anyhow::Context as _;
    use std::collections::BTreeMap;
    use crate::{
        b4_c2_terminal_catalog::genuine_catalog_join::CATALOG_PATH,
        b4_plan::Eip0045B4NegativePlanV1,
        b4_terminal::terminal_fixture_raw_seal_path,
        b4_terminal_byte_map::{B4TerminalByteMapKind, terminal_byte_map_paths},
        b4_terminal_oracle::replay_fixed_terminal_oracles,
    };

    pub(crate) struct Joined {
        pub(crate) rows: Vec<B4ClosedReconstructedExecutionV1>,
        pub(crate) raw_seals: Vec<Vec<u8>>,
    }

    fn inventory(entries: Vec<(String, Vec<u8>)>) -> Result<BTreeMap<String, Vec<u8>>> {
        ensure!(entries.len() == 19, "terminal policy export requires nineteen files");
        let mut expected = vec![CATALOG_PATH.to_owned()];
        for kind in [B4TerminalByteMapKind::RawSeal, B4TerminalByteMapKind::ReceiptOracle] {
            expected.extend(terminal_byte_map_paths(kind).iter().map(|path| (*path).to_owned()));
        }
        expected.sort();
        let mut files = BTreeMap::new();
        for (path, bytes) in entries {
            ensure!(files.insert(path, bytes).is_none(), "terminal policy export duplicate path");
        }
        ensure!(files.keys().cloned().collect::<Vec<_>>() == expected, "terminal policy export path set");
        Ok(files)
    }

    fn replay_raw(entries: Vec<(String, Vec<u8>)>) -> Result<Vec<Vec<u8>>> {
        let files = inventory(entries)?;
        let map = |kind| terminal_byte_map_paths(kind).iter()
            .map(|path| ((*path).to_owned(), files[*path].clone())).collect::<BTreeMap<_, _>>();
        let raw = map(B4TerminalByteMapKind::RawSeal);
        let oracles = map(B4TerminalByteMapKind::ReceiptOracle);
        let replay = replay_fixed_terminal_oracles(&raw, &oracles)?;
        replay.bind_candidate_catalogue_jcs(&files[CATALOG_PATH])?;
        ensure!(replay.derived_catalogue_jcs()? == files[CATALOG_PATH], "terminal policy catalogue is not derived");
        let raw_seals = B4_TERMINAL_FIXTURE_LAYOUT.iter().map(|slot|
            Ok(raw[&terminal_fixture_raw_seal_path(slot.fixture_id)?].clone())
        ).collect::<Result<Vec<_>>>()?;
        Ok(raw_seals)
    }

    pub(crate) fn join(entries: Vec<(String, Vec<u8>)>) -> Result<Joined> {
        let raw_seals = replay_raw(entries)?;
        let staged = StagedTerminalFixtureRecipeSourceV1 {
            profile_manifest: include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin"),
            reference_statement: &[], // Only rows131-138 are reconstructed here.
            raw_seals: std::array::from_fn(|slot| raw_seals[slot].as_slice()),
        };
        let plan = Eip0045B4NegativePlanV1::canonical()?;
        let plan_jcs = plan.to_canonical_jcs()?;
        let planned = plan.groups.iter().flat_map(|group| &group.executions).collect::<Vec<_>>();
        let mut rows = Vec::new();
        for index in 131..139 {
            rows.push(reconstruct_terminal_fixture_execution_from_staged_source(
                index, planned[index], &plan_jcs, &staged,
            )?.context("terminal policy C2 row absent")?);
        }
        Ok(Joined { rows, raw_seals })
    }

    /// Local row139 seam; the original producer's statement is not a Resolve journal.
    pub(crate) fn join_receipt_claim(
        entries: Vec<(String, Vec<u8>)>, reference_statement: &[u8],
    ) -> Result<B4ClosedReconstructedExecutionV1> {
        use sha2::{Digest, Sha256};
        ensure!(reference_statement.len() == 160 && hex::encode(Sha256::digest(reference_statement))
            == "da4f3d7483d082324d1d11a3df67fd0dbfb662e0091ad741400be32ac3c15ae1",
            "terminal receipt-claim reference statement pin");
        let raw_seals = replay_raw(entries)?;
        let staged = StagedTerminalFixtureRecipeSourceV1 {
            profile_manifest: include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin"),
            reference_statement,
            raw_seals: std::array::from_fn(|slot| raw_seals[slot].as_slice()),
        };
        let plan = Eip0045B4NegativePlanV1::canonical()?;
        let plan_jcs = plan.to_canonical_jcs()?;
        let planned = plan.groups.iter().flat_map(|group| &group.executions).nth(139)
            .context("terminal receipt-claim canonical row absent")?;
        reconstruct_terminal_fixture_execution_from_staged_source(139, planned, &plan_jcs, &staged)?
            .context("terminal receipt-claim C2 row absent")
    }

    #[test]
    fn terminal_policy_export_inventory_is_exact() {
        let mut entries = vec![(CATALOG_PATH.to_owned(), vec![1])];
        for kind in [B4TerminalByteMapKind::RawSeal, B4TerminalByteMapKind::ReceiptOracle] {
            entries.extend(terminal_byte_map_paths(kind).iter().map(|path| ((*path).to_owned(), vec![1])));
        }
        inventory(entries.clone()).unwrap(); // Inventory-only fixture; never a proof.
        assert_eq!(inventory(entries[..18].to_vec()).unwrap_err().to_string(), "terminal policy export requires nineteen files");
        let mut wrong = entries.clone(); wrong[18] = wrong[0].clone();
        assert_eq!(inventory(wrong).unwrap_err().to_string(), "terminal policy export duplicate path");
        let mut wrong = entries; wrong[18].0.push_str(".extra");
        assert_eq!(inventory(wrong).unwrap_err().to_string(), "terminal policy export path set");
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use crate::{
        b4::B4NegativeMaterialization,
        b4_negative_io::{B4NegativeFileEncoding, Eip0045B4NegativeVerifierInputV1},
        b4_plan::{
            B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanExecutionV1,
            B4NegativePlanFixture, B4NegativeQaResultCode, Eip0045B4NegativePlanV1,
        },
        b4_terminal::{B4_TERMINAL_FIXTURE_COUNT, B4_TERMINAL_FIXTURE_LAYOUT},
        constants::{MANIFEST_BYTES, PROOF_BYTES},
    };

    use super::{
        StagedTerminalFixtureRecipeSourceV1,
        reconstruct_terminal_fixture_execution_from_staged_source,
    };
    #[cfg(feature = "negative-materialization-set")]
    use super::{
        reconstruct_terminal_fixture_execution, reconstruct_terminal_fixture_execution_v2,
    };
    #[cfg(feature = "negative-materialization-set")]
    use crate::{
        b4_materialization_set::B4ClosedReconstructedExecutionV1,
        b4_terminal_evidence_packet::{
            B4TerminalEvidenceImportAuthorityV1, B4TerminalEvidenceImportAuthorityV2,
        },
    };

    const MANIFEST: &[u8; MANIFEST_BYTES] =
        include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin");

    struct TestSources {
        statement: Vec<u8>,
        raw_seals: [Vec<u8>; B4_TERMINAL_FIXTURE_COUNT],
    }

    impl TestSources {
        fn staged(&self) -> StagedTerminalFixtureRecipeSourceV1<'_> {
            StagedTerminalFixtureRecipeSourceV1 {
                profile_manifest: MANIFEST,
                reference_statement: &self.statement,
                raw_seals: self.raw_seals.each_ref().map(Vec::as_slice),
            }
        }
    }

    fn sources() -> TestSources {
        TestSources {
            statement: vec![0x53; 192],
            raw_seals: std::array::from_fn(|index| {
                vec![u8::try_from(index + 1).unwrap(); PROOF_BYTES]
            }),
        }
    }

    fn plan_and_rows() -> (Vec<u8>, Vec<B4NegativePlanExecutionV1>) {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let source = plan.to_canonical_jcs().unwrap();
        let rows = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter().cloned())
            .collect();
        (source, rows)
    }

    #[test]
    fn staged_terminal_fixture_scaffold_closes_only_rows_131_through_139() {
        let (plan_source, rows) = plan_and_rows();
        let sources = sources();
        for (index, planned) in rows.iter().enumerate().take(140).skip(131) {
            assert!(
                reconstruct_terminal_fixture_execution_from_staged_source(
                    index,
                    planned,
                    &plan_source,
                    &sources.staged(),
                )
                .unwrap()
                .is_some()
            );
        }
        for index in [130, 140] {
            assert!(
                reconstruct_terminal_fixture_execution_from_staged_source(
                    index,
                    &rows[index],
                    &plan_source,
                    &sources.staged(),
                )
                .unwrap()
                .is_none()
            );
        }
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn production_entry_requires_only_the_opaque_terminal_import_authority() {
        type ProductionEntry = fn(
            usize,
            &B4NegativePlanExecutionV1,
            &[u8],
            &B4TerminalEvidenceImportAuthorityV1,
        )
            -> anyhow::Result<Option<B4ClosedReconstructedExecutionV1>>;
        let entry: ProductionEntry = reconstruct_terminal_fixture_execution;
        let _ = entry;

        let source = include_str!("b4_c2_terminal_fixture.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("authority.terminal_materialization_projection()"));
        assert!(production.contains("projection.profile_manifest()"));
        assert!(production.contains("projection.reference_statement()"));
        assert!(production.contains("projection.raw_seals()"));
        assert!(!production.contains("B4TerminalEvidenceImportAuthorityV1::"));
    }

    #[cfg(feature = "negative-materialization-set")]
    #[test]
    fn v2_production_entry_requires_the_distinct_opaque_import_authority() {
        type ProductionEntryV2 = fn(
            usize,
            &B4NegativePlanExecutionV1,
            &[u8],
            &B4TerminalEvidenceImportAuthorityV2,
        )
            -> anyhow::Result<Option<B4ClosedReconstructedExecutionV1>>;
        let entry: ProductionEntryV2 = reconstruct_terminal_fixture_execution_v2;
        let _ = entry;

        let production = include_str!("b4_c2_terminal_fixture.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(production.contains("authority.terminal_materialization_projection_v2()"));
        assert!(!production.contains("B4TerminalEvidenceImportAuthorityV2::"));
    }

    #[test]
    fn staged_terminal_fixture_scaffold_maps_fixed_slots_and_contexts() {
        let (plan_source, rows) = plan_and_rows();
        let sources = sources();
        for (index, planned) in rows.iter().enumerate().take(140).skip(131) {
            let slot = index - 131;
            let closed = reconstruct_terminal_fixture_execution_from_staged_source(
                index,
                planned,
                &plan_source,
                &sources.staged(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(closed.base, sources.raw_seals[slot]);
            assert_eq!(closed.subject, sources.raw_seals[slot]);
            let B4NegativeMaterialization::FixtureSelection { fixture_id } =
                &closed.derived_registry_row.materialization
            else {
                panic!("terminal-fixture row did not retain one fixed selection");
            };
            let expected_recipe_id = if index == 139 {
                "allowed-terminal-non-ok-v1"
            } else {
                B4_TERMINAL_FIXTURE_LAYOUT[slot].fixture_id
            };
            assert_eq!(fixture_id, expected_recipe_id);
            let expected_contexts = if index == 139 {
                vec![MANIFEST.to_vec(), sources.statement.clone()]
            } else {
                vec![MANIFEST.to_vec()]
            };
            assert_eq!(closed.contexts, expected_contexts);
            let input =
                Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(&closed.negative_input_jcs)
                    .unwrap();
            assert_eq!(input.context.len(), expected_contexts.len());
            for (context_index, (identity, bytes)) in
                input.context.iter().zip(&expected_contexts).enumerate()
            {
                assert_eq!(identity.role, format!("context-{context_index:02}"));
                assert_eq!(identity.path, format!("context/{context_index:02}.bin"));
                assert_eq!(identity.byte_length, u64::try_from(bytes.len()).unwrap());
                assert_eq!(identity.sha256, hex::encode(Sha256::digest(bytes)));
                assert_eq!(identity.encoding, B4NegativeFileEncoding::RawBytes);
            }
            assert_eq!(
                input.context[0].sha256,
                hex::encode(Sha256::digest(MANIFEST))
            );
            if index == 139 {
                assert_eq!(
                    input.context[1].sha256,
                    hex::encode(Sha256::digest(&sources.statement))
                );
                assert_ne!(input.context[0].sha256, input.context[1].sha256);
            }
        }
        assert_eq!(
            B4_TERMINAL_FIXTURE_LAYOUT[8].fixture_id,
            "allowed-terminal-non-ok"
        );

        let mut manifest_drift = MANIFEST.to_vec();
        manifest_drift[0] ^= 1;
        let staged_drift = StagedTerminalFixtureRecipeSourceV1 {
            profile_manifest: &manifest_drift,
            reference_statement: &sources.statement,
            raw_seals: sources.raw_seals.each_ref().map(Vec::as_slice),
        };
        assert!(
            reconstruct_terminal_fixture_execution_from_staged_source(
                139,
                &rows[139],
                &plan_source,
                &staged_drift,
            )
            .is_err()
        );

        let staged_inverted = StagedTerminalFixtureRecipeSourceV1 {
            profile_manifest: &sources.statement,
            reference_statement: MANIFEST,
            raw_seals: sources.raw_seals.each_ref().map(Vec::as_slice),
        };
        assert!(
            reconstruct_terminal_fixture_execution_from_staged_source(
                139,
                &rows[139],
                &plan_source,
                &staged_inverted,
            )
            .is_err()
        );
    }

    #[test]
    fn staged_terminal_fixture_scaffold_rejects_every_plan_field_drift() {
        let (plan_source, rows) = plan_and_rows();
        let sources = sources();
        for index in [131, 139] {
            let mut drifts = Vec::new();
            let mut row = rows[index].clone();
            row.execution_id.push('x');
            drifts.push(row);
            let mut row = rows[index].clone();
            row.variant_id.push('x');
            drifts.push(row);
            let mut row = rows[index].clone();
            row.base_selector_id.push('x');
            drifts.push(row);
            let mut row = rows[index].clone();
            row.fixture = B4NegativePlanFixture::LiftPo215;
            drifts.push(row);
            let mut row = rows[index].clone();
            row.materialization_domain = B4MaterializationDomain::ArtifactValidator;
            drifts.push(row);
            let mut row = rows[index].clone();
            row.execution_surface = B4NegativeExecutionSurface::TerminalMetadata;
            drifts.push(row);
            let mut row = rows[index].clone();
            row.qa_result_code = B4NegativeQaResultCode::B4TerminalMetadataMismatch;
            drifts.push(row);
            let mut row = rows[index].clone();
            row.parser_truncation_words = Some(1);
            drifts.push(row);
            for drift in drifts {
                assert!(
                    reconstruct_terminal_fixture_execution_from_staged_source(
                        index,
                        &drift,
                        &plan_source,
                        &sources.staged(),
                    )
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn staged_terminal_fixture_scaffold_has_no_selector_or_positive_ordinal_path() {
        let source = include_str!("b4_c2_terminal_fixture.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("positive_ordinal"));
        assert!(!production.contains("positive-case ordinal"));
        let staged_source = production
            .split("struct StagedTerminalFixtureRecipeSourceV1")
            .nth(1)
            .unwrap()
            .split('}')
            .next()
            .unwrap();
        assert!(!staged_source.contains("Option<"));
        assert!(!staged_source.contains("selector"));
        assert!(!staged_source.contains("fixture_id"));

        let (plan_source, rows) = plan_and_rows();
        let sources = sources();
        let mut wrong_plan = plan_source.clone();
        wrong_plan[0] ^= 1;
        assert!(
            reconstruct_terminal_fixture_execution_from_staged_source(
                139,
                &rows[139],
                &wrong_plan,
                &sources.staged(),
            )
            .is_err()
        );
    }
}
