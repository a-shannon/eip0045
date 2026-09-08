//! Import-authority producer for terminal-metadata rows `110..=112`.
//!
//! The historical 218-row dispatcher remains unchanged. The additive
//! terminal-aware dispatcher reaches this producer only through the opaque
//! import authority and its verified case-8 direct replay.

#![allow(
    dead_code,
    reason = "the staged-source seam remains available only to isolated producer tests"
)]

use anyhow::{Result, bail, ensure};

#[cfg(feature = "negative-materialization-set")]
use crate::b4_terminal_evidence_packet::{
    B4TerminalEvidenceImportAuthorityV1, B4TerminalEvidenceImportAuthorityV2,
};
use crate::{
    b4::{
        B4ByteOperation, B4ByteTarget, B4NegativeCase, B4NegativeMaterialization,
        B4NegativeMutation,
    },
    b4_case8_terminal_join_root::B4VerifiedCase8TerminalJoinReplayV1,
    b4_materialization_set::{B4ClosedReconstructedExecutionV1, close_production_execution},
    b4_mutation::{B4MaterializationReplayAdapterV1, reconstruct_byte_edit},
    b4_plan::{
        B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanExecutionV1,
        B4NegativePlanFixture, B4NegativeQaResultCode,
    },
    b4_subject_envelope::{encode_subject_envelope, terminal_metadata_subject_envelope_contract},
    constants::{MANIFEST_BYTES, MANIFEST_CONTROL_ENTRY_BYTES, TERMINAL_CONTROL_KIND_JOIN},
    profile_manifest::StarkProfileManifestV1,
};

const TERMINAL_METADATA_FIRST_INDEX: usize = 110;
const TERMINAL_METADATA_END_INDEX_EXCLUSIVE: usize = 113;
const TERMINAL_METADATA_SELECTOR: &str = "terminal-join";
const TERMINAL_METADATA_SUBJECT_BYTES: usize =
    12 + 2 * 4 + MANIFEST_BYTES + MANIFEST_CONTROL_ENTRY_BYTES;
trait TerminalMetadataVerifiedSourceV1 {
    fn terminal_metadata_record(&self) -> &[u8; MANIFEST_CONTROL_ENTRY_BYTES];
    fn contexts(&self) -> [&[u8]; 7];
}

struct TerminalMetadataImportProjectionV1<'authority> {
    terminal_metadata_record: &'authority [u8; MANIFEST_CONTROL_ENTRY_BYTES],
    contexts: [&'authority [u8]; 7],
}

impl TerminalMetadataVerifiedSourceV1 for TerminalMetadataImportProjectionV1<'_> {
    fn terminal_metadata_record(&self) -> &[u8; MANIFEST_CONTROL_ENTRY_BYTES] {
        self.terminal_metadata_record
    }

    fn contexts(&self) -> [&[u8]; 7] {
        self.contexts
    }
}

impl TerminalMetadataVerifiedSourceV1 for B4VerifiedCase8TerminalJoinReplayV1 {
    fn terminal_metadata_record(&self) -> &[u8; MANIFEST_CONTROL_ENTRY_BYTES] {
        self.terminal_metadata_record()
    }

    fn contexts(&self) -> [&[u8]; 7] {
        self.contexts()
    }
}

/// Reconstruct from the sole verified case-8 replay.
///
/// This entry point deliberately has no call from the historical
/// `ProductionRowProducer`; only the terminal-aware authority path calls it.
pub(crate) fn reconstruct_terminal_metadata_execution(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    replay: &B4VerifiedCase8TerminalJoinReplayV1,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    reconstruct_terminal_metadata_execution_from_source(
        execution_index,
        planned,
        negative_plan_jcs,
        replay,
    )
}

#[cfg(feature = "negative-materialization-set")]
pub(crate) fn reconstruct_terminal_metadata_execution_from_import(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    authority: &B4TerminalEvidenceImportAuthorityV1,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    let projection = authority.terminal_materialization_projection();
    let source = TerminalMetadataImportProjectionV1 {
        terminal_metadata_record: projection.terminal_metadata_record(),
        contexts: projection.terminal_metadata_contexts(),
    };
    reconstruct_terminal_metadata_execution_from_source(
        execution_index,
        planned,
        negative_plan_jcs,
        &source,
    )
}

/// Reconstruct the fixed metadata rows from the distinct V2 terminal import.
///
/// No selector, detached byte source, V1 conversion, or alternate replay enters
/// this sibling. The retained Join/0 record and seven contexts are borrowed
/// directly from the V2 projection.
#[cfg(feature = "negative-materialization-set")]
pub(crate) fn reconstruct_terminal_metadata_execution_from_import_v2(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    authority: &B4TerminalEvidenceImportAuthorityV2,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    let projection = authority.terminal_materialization_projection_v2();
    let source = TerminalMetadataImportProjectionV1 {
        terminal_metadata_record: projection.terminal_metadata_record(),
        contexts: projection.terminal_metadata_contexts(),
    };
    reconstruct_terminal_metadata_execution_from_source(
        execution_index,
        planned,
        negative_plan_jcs,
        &source,
    )
}

fn reconstruct_terminal_metadata_execution_from_source(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    source: &impl TerminalMetadataVerifiedSourceV1,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    if !(TERMINAL_METADATA_FIRST_INDEX..TERMINAL_METADATA_END_INDEX_EXCLUSIVE)
        .contains(&execution_index)
    {
        return Ok(None);
    }
    validate_planned_execution(execution_index, planned)?;

    let base = source.terminal_metadata_record();
    let contexts = source.contexts();
    authenticate_verified_record(base, contexts[1])?;
    let edit = terminal_metadata_edit(execution_index, base)?;
    let candidate = reconstruct_byte_edit(base, &edit)?;
    ensure!(
        candidate.len() == MANIFEST_CONTROL_ENTRY_BYTES,
        "terminal-metadata candidate is not exactly 34 bytes"
    );
    let materialization = B4NegativeMaterialization::Mutation {
        mutation: B4NegativeMutation::ByteEdit {
            edit: edit.clone(),
            target: B4ByteTarget::TerminalMetadataRecord,
        },
    };
    let registry_row = B4NegativeCase {
        execution_id: planned.execution_id.clone(),
        base_selector_id: TERMINAL_METADATA_SELECTOR.to_owned(),
        materialization_domain: B4MaterializationDomain::ArtifactValidator,
        materialization,
    };
    let subject = encode_terminal_metadata_subject(contexts[1], &candidate)?;
    let raw_adapter = TerminalMetadataRawReplayAdapterV1 {
        base,
        candidate: &candidate,
        edit: &edit,
    };
    let final_adapter = TerminalMetadataFinalReplayAdapterV1 {
        raw: raw_adapter,
        manifest: contexts[1],
        subject: &subject,
    };

    close_production_execution(
        execution_index,
        planned,
        negative_plan_jcs,
        registry_row,
        &raw_adapter,
        &final_adapter,
        subject.clone(),
        contexts.into_iter().map(<[u8]>::to_vec).collect::<Vec<_>>(),
    )
    .map(Some)
}

fn validate_planned_execution(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
) -> Result<()> {
    let expected_variant = match execution_index {
        110 => "kind",
        111 => "parameter",
        112 => "control-id",
        _ => bail!("terminal-metadata producer received an index outside its closed range"),
    };
    ensure!(
        planned.execution_id == format!("terminal-metadata-field-sweep--{expected_variant}")
            && planned.variant_id == expected_variant
            && planned.base_selector_id == TERMINAL_METADATA_SELECTOR
            && planned.fixture == B4NegativePlanFixture::TerminalJoin
            && planned.materialization_domain == B4MaterializationDomain::ArtifactValidator
            && planned.execution_surface == B4NegativeExecutionSurface::TerminalMetadata
            && planned.qa_result_code == B4NegativeQaResultCode::B4TerminalMetadataMismatch
            && planned.parser_truncation_words.is_none(),
        "canonical plan row differs from the staged terminal-metadata mapping"
    );
    Ok(())
}

fn authenticate_verified_record(
    record: &[u8; MANIFEST_CONTROL_ENTRY_BYTES],
    manifest_source: &[u8],
) -> Result<()> {
    ensure!(
        record[0] == TERMINAL_CONTROL_KIND_JOIN && record[1] == 0,
        "verified terminal-metadata base is not the exact Join/0 record"
    );
    let manifest = StarkProfileManifestV1::decode(manifest_source)?;
    manifest.validate_initial_profile_target()?;
    let matching_controls = manifest
        .terminal_controls()
        .iter()
        .filter(|control| {
            control.control_kind() == record[0]
                && control.parameter() == record[1]
                && control.control_id().as_slice() == &record[2..]
        })
        .count();
    ensure!(
        matching_controls == 1,
        "verified terminal-metadata base is not the sole matching manifest control"
    );
    Ok(())
}

fn terminal_metadata_edit(
    execution_index: usize,
    base: &[u8; MANIFEST_CONTROL_ENTRY_BYTES],
) -> Result<B4ByteOperation> {
    match execution_index {
        110 => Ok(B4ByteOperation::Replace {
            before_hex: hex::encode(&base[..1]),
            replacement_hex: "03".to_owned(),
            offset: 0,
        }),
        111 => Ok(B4ByteOperation::Replace {
            before_hex: hex::encode(&base[1..2]),
            replacement_hex: "01".to_owned(),
            offset: 1,
        }),
        112 => {
            let mut replacement: [u8; MANIFEST_CONTROL_ENTRY_BYTES - 2] = base[2..].try_into()?;
            replacement[0] ^= 1;
            Ok(B4ByteOperation::Replace {
                before_hex: hex::encode(&base[2..]),
                replacement_hex: hex::encode(replacement),
                offset: 2,
            })
        }
        _ => bail!("terminal-metadata producer received an index outside its closed range"),
    }
}

fn encode_terminal_metadata_subject(manifest: &[u8], candidate: &[u8]) -> Result<Vec<u8>> {
    let subject = encode_subject_envelope(
        &[manifest, candidate],
        terminal_metadata_subject_envelope_contract(),
    )?;
    ensure!(
        subject.len() == TERMINAL_METADATA_SUBJECT_BYTES,
        "terminal-metadata envelope is not exactly 512 bytes"
    );
    Ok(subject)
}

#[derive(Clone, Copy, Debug)]
struct TerminalMetadataRawReplayAdapterV1<'a> {
    base: &'a [u8; MANIFEST_CONTROL_ENTRY_BYTES],
    candidate: &'a [u8],
    edit: &'a B4ByteOperation,
}

impl B4MaterializationReplayAdapterV1 for TerminalMetadataRawReplayAdapterV1<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::ArtifactValidator
    }

    fn base_bytes(&self) -> &[u8] {
        self.base
    }

    fn output_bytes(&self) -> &[u8] {
        self.candidate
    }

    fn replay_recipe(
        &self,
        base_selector_id: &str,
        materialization: &B4NegativeMaterialization,
    ) -> Result<()> {
        ensure!(
            base_selector_id == TERMINAL_METADATA_SELECTOR,
            "terminal-metadata recipe selects a different positive root"
        );
        let B4NegativeMaterialization::Mutation {
            mutation: B4NegativeMutation::ByteEdit { edit, target },
        } = materialization
        else {
            bail!("terminal-metadata recipe is not one exact byte replacement");
        };
        ensure!(
            target == &B4ByteTarget::TerminalMetadataRecord && edit == self.edit,
            "terminal-metadata recipe differs from the exact record edit"
        );
        ensure!(
            reconstruct_byte_edit(self.base, edit)? == self.candidate,
            "terminal-metadata candidate differs from exact byte-edit replay"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct TerminalMetadataFinalReplayAdapterV1<'a> {
    raw: TerminalMetadataRawReplayAdapterV1<'a>,
    manifest: &'a [u8],
    subject: &'a [u8],
}

impl B4MaterializationReplayAdapterV1 for TerminalMetadataFinalReplayAdapterV1<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::ArtifactValidator
    }

    fn base_bytes(&self) -> &[u8] {
        self.raw.base_bytes()
    }

    fn output_bytes(&self) -> &[u8] {
        self.subject
    }

    fn replay_recipe(
        &self,
        base_selector_id: &str,
        materialization: &B4NegativeMaterialization,
    ) -> Result<()> {
        self.raw.replay_recipe(base_selector_id, materialization)?;
        ensure!(
            encode_terminal_metadata_subject(self.manifest, self.raw.candidate)? == self.subject,
            "terminal-metadata subject differs from the exact consumer envelope"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        b4::{B4ByteOperation, B4ByteTarget, B4NegativeMaterialization, B4NegativeMutation},
        b4_case8_terminal_join_root::B4VerifiedCase8TerminalJoinReplayV1,
        b4_materialization_set::B4ClosedReconstructedExecutionV1,
        b4_mutation::Eip0045B4MaterializationIdentityV1,
        b4_negative_io::Eip0045B4NegativeVerifierInputV1,
        b4_plan::{
            B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanExecutionV1,
            B4NegativePlanFixture, B4NegativeQaResultCode, Eip0045B4NegativePlanV1,
        },
        b4_subject_envelope::decode_subject_envelope,
        constants::{
            MANIFEST_BYTES, MANIFEST_CONTROL_ENTRY_BYTES, PROOF_BYTES, STATEMENT_PREFIX_BYTES,
            TERMINAL_CONTROL_KIND_JOIN,
        },
        profile_manifest::StarkProfileManifestV1,
    };

    use super::{
        TerminalMetadataVerifiedSourceV1, reconstruct_terminal_metadata_execution,
        reconstruct_terminal_metadata_execution_from_source,
    };
    #[cfg(feature = "negative-materialization-set")]
    use super::{
        reconstruct_terminal_metadata_execution_from_import,
        reconstruct_terminal_metadata_execution_from_import_v2,
    };
    #[cfg(feature = "negative-materialization-set")]
    use crate::b4_terminal_evidence_packet::{
        B4TerminalEvidenceImportAuthorityV1, B4TerminalEvidenceImportAuthorityV2,
    };

    const MANIFEST: &[u8; MANIFEST_BYTES] =
        include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin");

    struct SyntheticVerifiedSource {
        record: [u8; MANIFEST_CONTROL_ENTRY_BYTES],
        contexts: [Vec<u8>; 7],
    }

    impl TerminalMetadataVerifiedSourceV1 for SyntheticVerifiedSource {
        fn terminal_metadata_record(&self) -> &[u8; MANIFEST_CONTROL_ENTRY_BYTES] {
            &self.record
        }

        fn contexts(&self) -> [&[u8]; 7] {
            self.contexts.each_ref().map(Vec::as_slice)
        }
    }

    fn source() -> SyntheticVerifiedSource {
        let manifest = StarkProfileManifestV1::decode(MANIFEST).unwrap();
        manifest.validate_initial_profile_target().unwrap();
        let join = manifest
            .terminal_controls()
            .iter()
            .find(|control| {
                control.control_kind() == TERMINAL_CONTROL_KIND_JOIN && control.parameter() == 0
            })
            .unwrap();
        let mut record = [0_u8; MANIFEST_CONTROL_ENTRY_BYTES];
        record[0] = TERMINAL_CONTROL_KIND_JOIN;
        record[2..].copy_from_slice(&join.control_id());
        SyntheticVerifiedSource {
            record,
            contexts: [
                vec![0],
                MANIFEST.to_vec(),
                vec![0; crate::profile_algorithm::ALGORITHM_BYTES],
                vec![0; crate::constants_artifact::ARTIFACT_BYTES],
                vec![0],
                vec![0; STATEMENT_PREFIX_BYTES],
                vec![0; PROOF_BYTES],
            ],
        }
    }

    fn plan_and_rows() -> (
        Eip0045B4NegativePlanV1,
        Vec<u8>,
        Vec<B4NegativePlanExecutionV1>,
    ) {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let source = plan.to_canonical_jcs().unwrap();
        let rows = plan
            .groups
            .iter()
            .flat_map(|group| group.executions.iter().cloned())
            .collect();
        (plan, source, rows)
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the single checklist keeps all three staged recipes, exact framing, context order, identity, and non-dispatch boundaries auditable together"
    )]
    fn staged_production_adapter_closes_exact_terminal_metadata_field_envelopes() {
        let (_plan, plan_source, rows) = plan_and_rows();
        let source = source();

        for (index, planned) in rows.iter().enumerate().take(113).skip(110) {
            let closed = reconstruct_terminal_metadata_execution_from_source(
                index,
                planned,
                &plan_source,
                &source,
            )
            .unwrap()
            .unwrap();

            assert_eq!(closed.base, source.record);
            assert_eq!(closed.subject.len(), 512);
            assert_eq!(closed.contexts, source.contexts);
            let decoded = decode_subject_envelope(
                &closed.subject,
                crate::b4_subject_envelope::terminal_metadata_subject_envelope_contract(),
            )
            .unwrap();
            assert_eq!(decoded.parts()[0], MANIFEST);
            assert_eq!(decoded.parts()[1].len(), MANIFEST_CONTROL_ENTRY_BYTES);

            let B4NegativeMaterialization::Mutation {
                mutation:
                    B4NegativeMutation::ByteEdit {
                        edit:
                            B4ByteOperation::Replace {
                                before_hex,
                                replacement_hex,
                                offset,
                            },
                        target,
                    },
            } = &closed.derived_registry_row.materialization
            else {
                panic!("terminal-metadata row did not retain one replacement recipe");
            };
            assert_eq!(*target, B4ByteTarget::TerminalMetadataRecord);
            match index {
                110 => {
                    assert_eq!(
                        (*offset, before_hex.as_str(), replacement_hex.as_str()),
                        (0, "02", "03")
                    );
                }
                111 => {
                    assert_eq!(
                        (*offset, before_hex.as_str(), replacement_hex.as_str()),
                        (1, "00", "01")
                    );
                }
                112 => {
                    assert_eq!(*offset, 2);
                    assert_eq!(before_hex.len(), 64);
                    assert_eq!(replacement_hex.len(), 64);
                    assert_eq!(
                        before_hex
                            .bytes()
                            .zip(replacement_hex.bytes())
                            .filter(|(before, replacement)| before != replacement)
                            .count(),
                        1
                    );
                }
                _ => unreachable!(),
            }

            let candidate = decoded.parts()[1];
            match index {
                110 => assert_eq!(
                    (&candidate[..2], &candidate[2..]),
                    (&[3, 0][..], &source.record[2..])
                ),
                111 => assert_eq!(
                    (&candidate[..2], &candidate[2..]),
                    (&[2, 1][..], &source.record[2..])
                ),
                112 => {
                    assert_eq!(&candidate[..2], &source.record[..2]);
                    assert_ne!(&candidate[2..], &source.record[2..]);
                }
                _ => unreachable!(),
            }

            let identity = Eip0045B4MaterializationIdentityV1::from_canonical_jcs(
                &closed.materialization_identity_jcs,
            )
            .unwrap();
            assert_eq!(identity.base_byte_length, 34);
            assert_eq!(identity.output_byte_length, 512);
            let input =
                Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(&closed.negative_input_jcs)
                    .unwrap();
            assert_eq!(input.context.len(), 7);
        }

        assert!(
            reconstruct_terminal_metadata_execution_from_source(
                109,
                &rows[109],
                &plan_source,
                &source,
            )
            .unwrap()
            .is_none()
        );
        assert!(
            reconstruct_terminal_metadata_execution_from_source(
                113,
                &rows[113],
                &plan_source,
                &source,
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn terminal_metadata_staged_entry_rejects_every_plan_field_drift() {
        let (_plan, plan_source, rows) = plan_and_rows();
        let source = source();
        let mut drifts = Vec::new();
        let mut row = rows[110].clone();
        row.execution_id.push('x');
        drifts.push(row);
        let mut row = rows[110].clone();
        row.variant_id.push('x');
        drifts.push(row);
        let mut row = rows[110].clone();
        row.base_selector_id.push('x');
        drifts.push(row);
        let mut row = rows[110].clone();
        row.fixture = B4NegativePlanFixture::LiftPo215;
        drifts.push(row);
        let mut row = rows[110].clone();
        row.materialization_domain = B4MaterializationDomain::VerifierInput;
        drifts.push(row);
        let mut row = rows[110].clone();
        row.execution_surface = B4NegativeExecutionSurface::TerminalFixtureCatalog;
        drifts.push(row);
        let mut row = rows[110].clone();
        row.qa_result_code = B4NegativeQaResultCode::B4TerminalFixtureCatalogBindingMismatch;
        drifts.push(row);
        let mut row = rows[110].clone();
        row.parser_truncation_words = Some(1);
        drifts.push(row);
        for drift in drifts {
            assert!(
                reconstruct_terminal_metadata_execution_from_source(
                    110,
                    &drift,
                    &plan_source,
                    &source,
                )
                .is_err()
            );
        }
    }

    #[test]
    #[allow(
        clippy::type_complexity,
        reason = "the exact function-pointer type is the staged entry-point ABI assertion"
    )]
    fn terminal_metadata_staged_entry_keeps_exact_verified_case8_signature() {
        let entry: fn(
            usize,
            &B4NegativePlanExecutionV1,
            &[u8],
            &B4VerifiedCase8TerminalJoinReplayV1,
        ) -> anyhow::Result<Option<B4ClosedReconstructedExecutionV1>> =
            reconstruct_terminal_metadata_execution;
        let _ = entry;
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
        let entry: ProductionEntry = reconstruct_terminal_metadata_execution_from_import;
        let _ = entry;

        let source = include_str!("b4_c2_terminal_metadata.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("authority.terminal_materialization_projection()"));
        assert!(production.contains("projection.terminal_metadata_record()"));
        assert!(production.contains("projection.terminal_metadata_contexts()"));
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
        let entry: ProductionEntryV2 = reconstruct_terminal_metadata_execution_from_import_v2;
        let _ = entry;

        let production = include_str!("b4_c2_terminal_metadata.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(production.contains("authority.terminal_materialization_projection_v2()"));
        assert!(!production.contains("B4TerminalEvidenceImportAuthorityV2::"));
    }

    #[test]
    fn terminal_metadata_staged_entry_rejects_record_or_manifest_drift() {
        let (_plan, plan_source, rows) = plan_and_rows();
        for offset in [0, 1, 2] {
            let mut drift = source();
            drift.record[offset] ^= 1;
            assert!(
                reconstruct_terminal_metadata_execution_from_source(
                    110,
                    &rows[110],
                    &plan_source,
                    &drift,
                )
                .is_err()
            );
        }

        let mut manifest_drift = source();
        manifest_drift.contexts[1][0] ^= 1;
        assert!(
            reconstruct_terminal_metadata_execution_from_source(
                110,
                &rows[110],
                &plan_source,
                &manifest_drift,
            )
            .is_err()
        );

        let mut position_drift = source();
        position_drift.contexts.swap(0, 1);
        assert!(
            reconstruct_terminal_metadata_execution_from_source(
                110,
                &rows[110],
                &plan_source,
                &position_drift,
            )
            .is_err()
        );
    }

    #[test]
    fn terminal_metadata_staged_entry_remains_absent_from_historical_production_dispatcher() {
        let source = include_str!("b4_materialization_set.rs");
        let dispatcher = source
            .split("impl B4ClosedMaterializationRowProducerV1 for ProductionRowProducer")
            .nth(1)
            .unwrap()
            .split("struct TerminalAwareProductionRowProducer")
            .next()
            .unwrap();
        for staged in [
            "reconstruct_terminal_catalog_execution_from_staged_source",
            "reconstruct_terminal_fixture_execution_from_staged_source",
            "reconstruct_terminal_metadata_execution_from_source(",
        ] {
            assert!(!dispatcher.contains(staged));
        }
    }
}
