// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Terminal-catalogue recipes admitted only through the opaque terminal import.

#![allow(
    dead_code,
    reason = "the staged-source seam remains available only to isolated producer tests"
)]

use std::fmt;

use anyhow::{Context, Result, bail, ensure};

#[cfg(feature = "negative-materialization-set")]
use crate::b4_terminal_evidence_packet::{
    B4TerminalEvidenceImportAuthorityV1, B4TerminalEvidenceImportAuthorityV2,
};
use crate::{
    b4::{
        B4ByteOperation, B4ByteTarget, B4NegativeCase, B4NegativeMaterialization,
        B4NegativeMutation,
    },
    b4_materialization_set::{B4ClosedReconstructedExecutionV1, close_production_execution},
    b4_mutation::{B4MaterializationReplayAdapterV1, reconstruct_byte_edit},
    b4_plan::{
        B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanExecutionV1,
        B4NegativePlanFixture, B4NegativeQaResultCode,
    },
    b4_subject_envelope::{encode_subject_envelope, terminal_catalog_subject_envelope_contract},
    b4_terminal::{
        B4_TERMINAL_FIXTURE_COUNT, B4_TERMINAL_FIXTURE_LAYOUT, Eip0045B4TerminalFixtureCatalogV1,
    },
    b4_terminal_byte_map::{
        B4TerminalByteMapEntry, B4TerminalByteMapKind, encode_terminal_byte_map,
        terminal_byte_map_paths,
    },
    canonical::canonical_json_bytes,
};

const TERMINAL_CATALOG_FIRST_INDEX: usize = 11;
const TERMINAL_CATALOG_END_INDEX_EXCLUSIVE: usize = 14;
const TERMINAL_CATALOG_SELECTOR: &str = "terminal-fixture-catalog-v1";
const WIRE_TO_SEMANTIC_SLOT: [usize; B4_TERMINAL_FIXTURE_COUNT] = [8, 2, 3, 0, 1, 4, 5, 6, 7];

struct StagedTerminalCatalogRecipeSourceV1<'a> {
    catalogue: &'a [u8],
    raw_seals: [&'a [u8]; B4_TERMINAL_FIXTURE_COUNT],
    receipt_oracles: [&'a [u8]; B4_TERMINAL_FIXTURE_COUNT],
}

struct TerminalCatalogRawReplayAdapterV1<'a> {
    execution_index: usize,
    planned: &'a B4NegativePlanExecutionV1,
    source: &'a StagedTerminalCatalogRecipeSourceV1<'a>,
    candidate: &'a [u8],
}

impl fmt::Debug for TerminalCatalogRawReplayAdapterV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TerminalCatalogRawReplayAdapterV1")
            .field("execution_index", &self.execution_index)
            .finish_non_exhaustive()
    }
}

impl B4MaterializationReplayAdapterV1 for TerminalCatalogRawReplayAdapterV1<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::ArtifactValidator
    }

    fn base_bytes(&self) -> &[u8] {
        self.source.catalogue
    }

    fn output_bytes(&self) -> &[u8] {
        self.candidate
    }

    fn replay_recipe(
        &self,
        base_selector_id: &str,
        materialization: &B4NegativeMaterialization,
    ) -> Result<()> {
        validate_planned_execution(self.execution_index, self.planned)?;
        let (candidate, expected_materialization) =
            derive_candidate_materialization(self.execution_index, self.source.catalogue)?;
        ensure!(
            base_selector_id == TERMINAL_CATALOG_SELECTOR
                && materialization == &expected_materialization
                && candidate == self.candidate,
            "terminal-catalogue raw recipe differs from its independently derived staged row"
        );
        let B4NegativeMaterialization::Mutation {
            mutation: B4NegativeMutation::ByteEdit { edit, target },
        } = &expected_materialization
        else {
            bail!("terminal-catalogue recipe is not one exact byte replacement");
        };
        ensure!(
            target == &B4ByteTarget::TerminalFixtureCatalogEntry
                && matches!(edit, B4ByteOperation::Replace { .. })
                && reconstruct_byte_edit(self.source.catalogue, edit)? == candidate,
            "terminal-catalogue raw replay differs from its exact candidate"
        );
        Ok(())
    }
}

struct TerminalCatalogFinalReplayAdapterV1<'a> {
    execution_index: usize,
    planned: &'a B4NegativePlanExecutionV1,
    source: &'a StagedTerminalCatalogRecipeSourceV1<'a>,
    subject: &'a [u8],
}

impl fmt::Debug for TerminalCatalogFinalReplayAdapterV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TerminalCatalogFinalReplayAdapterV1")
            .field("execution_index", &self.execution_index)
            .finish_non_exhaustive()
    }
}

impl B4MaterializationReplayAdapterV1 for TerminalCatalogFinalReplayAdapterV1<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::ArtifactValidator
    }

    fn base_bytes(&self) -> &[u8] {
        self.source.catalogue
    }

    fn output_bytes(&self) -> &[u8] {
        self.subject
    }

    fn replay_recipe(
        &self,
        base_selector_id: &str,
        materialization: &B4NegativeMaterialization,
    ) -> Result<()> {
        validate_planned_execution(self.execution_index, self.planned)?;
        let (candidate, expected_materialization) =
            derive_candidate_materialization(self.execution_index, self.source.catalogue)?;
        ensure!(
            base_selector_id == TERMINAL_CATALOG_SELECTOR
                && materialization == &expected_materialization,
            "terminal-catalogue final recipe differs from its independently derived staged row"
        );
        let raw_map = encode_wire_map(B4TerminalByteMapKind::RawSeal, &self.source.raw_seals)?;
        let oracle_map = encode_wire_map(
            B4TerminalByteMapKind::ReceiptOracle,
            &self.source.receipt_oracles,
        )?;
        let reconstructed = encode_subject_envelope(
            &[&candidate, &raw_map, &oracle_map],
            terminal_catalog_subject_envelope_contract(),
        )?;
        ensure!(
            reconstructed == self.subject,
            "terminal-catalogue final replay differs from its exact consumer envelope"
        );
        Ok(())
    }
}

fn reconstruct_terminal_catalog_execution_from_staged_source(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    source: &StagedTerminalCatalogRecipeSourceV1<'_>,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    if !(TERMINAL_CATALOG_FIRST_INDEX..TERMINAL_CATALOG_END_INDEX_EXCLUSIVE)
        .contains(&execution_index)
    {
        return Ok(None);
    }
    validate_planned_execution(execution_index, planned)?;
    let (candidate, materialization) =
        derive_candidate_materialization(execution_index, source.catalogue)?;
    let raw_map = encode_wire_map(B4TerminalByteMapKind::RawSeal, &source.raw_seals)?;
    let oracle_map = encode_wire_map(
        B4TerminalByteMapKind::ReceiptOracle,
        &source.receipt_oracles,
    )?;
    let subject = encode_subject_envelope(
        &[&candidate, &raw_map, &oracle_map],
        terminal_catalog_subject_envelope_contract(),
    )?;
    let registry_row = B4NegativeCase {
        execution_id: planned.execution_id.clone(),
        base_selector_id: TERMINAL_CATALOG_SELECTOR.to_owned(),
        materialization_domain: B4MaterializationDomain::ArtifactValidator,
        materialization,
    };
    let raw_adapter = TerminalCatalogRawReplayAdapterV1 {
        execution_index,
        planned,
        source,
        candidate: &candidate,
    };
    let final_adapter = TerminalCatalogFinalReplayAdapterV1 {
        execution_index,
        planned,
        source,
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
        Vec::new(),
    )
    .map(Some)
}

#[cfg(feature = "negative-materialization-set")]
pub(crate) fn reconstruct_terminal_catalog_execution(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    authority: &B4TerminalEvidenceImportAuthorityV1,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    let projection = authority.terminal_materialization_projection();
    let source = StagedTerminalCatalogRecipeSourceV1 {
        catalogue: projection.terminal_fixture_catalog_jcs(),
        raw_seals: projection.raw_seals(),
        receipt_oracles: projection.receipt_oracles(),
    };
    reconstruct_terminal_catalog_execution_from_staged_source(
        execution_index,
        planned,
        negative_plan_jcs,
        &source,
    )
}

/// Reconstruct the same fixed catalogue rows from the distinct V2 import.
///
/// This concrete sibling accepts no row source, selector, detached bytes, or
/// V1 authority conversion. The plan-owned execution index is validated by the
/// same closed staged-source implementation as the preserved V1 path.
#[cfg(feature = "negative-materialization-set")]
pub(crate) fn reconstruct_terminal_catalog_execution_v2(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    negative_plan_jcs: &[u8],
    authority: &B4TerminalEvidenceImportAuthorityV2,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    let projection = authority.terminal_materialization_projection_v2();
    let source = StagedTerminalCatalogRecipeSourceV1 {
        catalogue: projection.terminal_fixture_catalog_jcs(),
        raw_seals: projection.raw_seals(),
        receipt_oracles: projection.receipt_oracles(),
    };
    reconstruct_terminal_catalog_execution_from_staged_source(
        execution_index,
        planned,
        negative_plan_jcs,
        &source,
    )
}

fn derive_candidate_materialization(
    execution_index: usize,
    catalogue_source: &[u8],
) -> Result<(Vec<u8>, B4NegativeMaterialization)> {
    let honest = Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(catalogue_source)?;
    ensure!(
        honest.fixtures.len() == B4_TERMINAL_FIXTURE_COUNT,
        "terminal-catalogue source does not contain the fixed fixture inventory"
    );
    let (candidate, edit) = mutate_catalogue(execution_index, &honest, catalogue_source)?;
    Ok((
        candidate,
        B4NegativeMaterialization::Mutation {
            mutation: B4NegativeMutation::ByteEdit {
                edit,
                target: B4ByteTarget::TerminalFixtureCatalogEntry,
            },
        },
    ))
}

fn validate_planned_execution(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
) -> Result<()> {
    let expected_variant = match execution_index {
        11 => "program-id",
        12 => "claim-digest",
        13 => "control-id",
        _ => bail!("terminal-catalogue producer received an index outside its closed range"),
    };
    ensure!(
        planned.execution_id
            == format!("terminal-fixture-catalog-binding-sweep--{expected_variant}")
            && planned.variant_id == expected_variant
            && planned.base_selector_id == TERMINAL_CATALOG_SELECTOR
            && planned.fixture == B4NegativePlanFixture::TerminalFixtureCatalogV1
            && planned.materialization_domain == B4MaterializationDomain::ArtifactValidator
            && planned.execution_surface == B4NegativeExecutionSurface::TerminalFixtureCatalog
            && planned.qa_result_code
                == B4NegativeQaResultCode::B4TerminalFixtureCatalogBindingMismatch
            && planned.parser_truncation_words.is_none(),
        "canonical plan row differs from the staged terminal-catalogue mapping"
    );
    Ok(())
}

fn mutate_catalogue(
    execution_index: usize,
    honest: &Eip0045B4TerminalFixtureCatalogV1,
    honest_source: &[u8],
) -> Result<(Vec<u8>, B4ByteOperation)> {
    let mut candidate = honest.clone();
    match execution_index {
        11 => toggle_first_ascii_hex(&mut candidate.program_id)?,
        12 => toggle_first_ascii_hex(
            &mut candidate
                .fixtures
                .get_mut(0)
                .context("terminal-catalogue lacks semantic fixture zero")?
                .claim_digest,
        )?,
        13 => toggle_first_ascii_hex(
            &mut candidate
                .fixtures
                .get_mut(0)
                .context("terminal-catalogue lacks semantic fixture zero")?
                .terminal
                .control_id,
        )?,
        _ => bail!("terminal-catalogue producer received an index outside its closed range"),
    }
    let candidate_source = canonical_json_bytes(&serde_json::to_value(candidate)?)?;
    let edit = one_ascii_byte_replacement(honest_source, &candidate_source)?;
    Ok((candidate_source, edit))
}

fn toggle_first_ascii_hex(value: &mut String) -> Result<()> {
    let first = value
        .as_bytes()
        .first()
        .copied()
        .context("terminal-catalogue digest is empty")?;
    ensure!(
        first.is_ascii_hexdigit(),
        "terminal-catalogue digest is not ASCII hex"
    );
    value.replace_range(..1, if first == b'0' { "1" } else { "0" });
    Ok(())
}

fn one_ascii_byte_replacement(before: &[u8], after: &[u8]) -> Result<B4ByteOperation> {
    ensure!(
        before.len() == after.len(),
        "terminal-catalogue mutation changed canonical byte length"
    );
    let differences = before
        .iter()
        .zip(after)
        .enumerate()
        .filter_map(|(index, (left, right))| (left != right).then_some((index, *left, *right)))
        .collect::<Vec<_>>();
    ensure!(
        differences.len() == 1,
        "terminal-catalogue mutation is not one ASCII-hex byte replacement"
    );
    let (offset, old, replacement) = differences[0];
    ensure!(
        old.is_ascii_hexdigit() && replacement.is_ascii_hexdigit(),
        "terminal-catalogue replacement is not ASCII hex"
    );
    Ok(B4ByteOperation::Replace {
        before_hex: format!("{old:02x}"),
        replacement_hex: format!("{replacement:02x}"),
        offset: u64::try_from(offset)?,
    })
}

fn encode_wire_map(
    kind: B4TerminalByteMapKind,
    semantic_payloads: &[&[u8]; B4_TERMINAL_FIXTURE_COUNT],
) -> Result<Vec<u8>> {
    let expected_ids = [
        "allowed-terminal-non-ok",
        "join-povw",
        "join-unwrap-povw",
        "lift-po2-14",
        "lift-povw-po2-18",
        "resolve-povw",
        "resolve-unwrap-povw",
        "union",
        "unwrap-povw",
    ];
    for (wire_index, semantic_index) in WIRE_TO_SEMANTIC_SLOT.iter().copied().enumerate() {
        ensure!(
            B4_TERMINAL_FIXTURE_LAYOUT[semantic_index].fixture_id == expected_ids[wire_index],
            "terminal-catalogue semantic-to-wire fixture mapping drift"
        );
    }
    let paths = terminal_byte_map_paths(kind);
    let entries: [B4TerminalByteMapEntry<'_>; B4_TERMINAL_FIXTURE_COUNT] =
        std::array::from_fn(|wire_index| {
            B4TerminalByteMapEntry::new(
                paths[wire_index],
                semantic_payloads[WIRE_TO_SEMANTIC_SLOT[wire_index]],
            )
        });
    encode_terminal_byte_map(kind, &entries).map_err(Into::into)
}

/// Test-only local export join; deliberately constructs no campaign authority.
#[cfg(all(test, feature = "validator"))]
pub(crate) mod genuine_catalog_join {
    use super::*;
    use std::{collections::BTreeMap, fs, io::Read, path::Path};
    use crate::{
        b4_plan::Eip0045B4NegativePlanV1,
        b4_subject_envelope::decode_subject_envelope,
        b4_terminal::{terminal_fixture_raw_seal_path, terminal_fixture_receipt_oracle_path},
        b4_terminal_oracle::replay_fixed_terminal_oracles,
    };

    pub(crate) const CATALOG_PATH: &str =
        "reproduction/schema/b4-corpus-v1.candidate/bindings/terminal-fixture-catalog.json";

    pub(crate) struct Joined {
        pub(crate) positive: Vec<u8>,
        pub(crate) rows: Vec<B4ClosedReconstructedExecutionV1>,
    }

    fn expected_paths() -> Vec<String> {
        let mut paths = vec![CATALOG_PATH.to_owned()];
        for kind in [B4TerminalByteMapKind::RawSeal, B4TerminalByteMapKind::ReceiptOracle] {
            paths.extend(terminal_byte_map_paths(kind).iter().map(|path| (*path).to_owned()));
        }
        paths.sort();
        paths
    }

    fn inventory(entries: Vec<(String, Vec<u8>)>) -> Result<BTreeMap<String, Vec<u8>>> {
        ensure!(entries.len() == 19, "local export must contain exactly nineteen files");
        let mut files = BTreeMap::new();
        for (path, bytes) in entries {
            ensure!(files.insert(path, bytes).is_none(), "duplicate local export path");
        }
        ensure!(files.keys().cloned().collect::<Vec<_>>() == expected_paths(), "local export path set drift");
        Ok(files)
    }

    fn read_bounded(reader: &mut impl Read, maximum: usize, expected_length: u64) -> Result<Vec<u8>> {
        ensure!(expected_length <= u64::try_from(maximum)?, "oversized local fixture metadata");
        let limit = u64::try_from(maximum)?.checked_add(1).context("fixture read bound overflow")?;
        let mut bytes = Vec::new();
        reader.take(limit).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= maximum, "local fixture grew beyond its read bound");
        ensure!(u64::try_from(bytes.len())? == expected_length, "local fixture length changed during read");
        Ok(bytes)
    }

    #[test]
    fn local_export_read_is_bounded_and_rejects_length_drift() {
        let mut exact = std::io::Cursor::new(vec![1; 3]);
        assert_eq!(read_bounded(&mut exact, 3, 3).unwrap(), vec![1; 3]);
        let mut growing = std::io::Cursor::new(vec![1; 100]);
        assert!(read_bounded(&mut growing, 3, 3).is_err());
        assert_eq!(growing.position(), 4); // never consumes the rest of a growing file
        assert!(read_bounded(&mut std::io::Cursor::new(vec![1; 2]), 3, 3).is_err());
        assert!(read_bounded(&mut std::io::Cursor::new(vec![1; 3]), 3, 2).is_err());
        let mut oversized = std::io::Cursor::new(vec![1; 4]);
        assert!(read_bounded(&mut oversized, 3, 4).is_err());
        assert_eq!(oversized.position(), 0);
    }

    pub(crate) fn read_export(root: &Path) -> Result<Vec<(String, Vec<u8>)>> {
        fn visit(root: &Path, directory: &Path, depth: usize, output: &mut Vec<(String, Vec<u8>)>) -> Result<()> {
            ensure!(depth <= 8, "local export directory depth exceeded");
            ensure!(fs::symlink_metadata(directory)?.file_type().is_dir(), "local export directory is redirected");
            for entry in fs::read_dir(directory)? {
                let entry = entry?;
                let kind = entry.file_type()?;
                ensure!(!kind.is_symlink(), "local export symlink");
                if kind.is_dir() {
                    let relative = entry.path().strip_prefix(root)?.to_str().context("non-UTF8 export directory")?.replace('\\', "/");
                    ensure!(expected_paths().iter().any(|path| path.starts_with(&format!("{relative}/"))), "unexpected local export directory");
                    visit(root, &entry.path(), depth + 1, output)?;
                } else {
                    ensure!(kind.is_file() && output.len() < 19, "local export file count/type drift");
                    let path = entry.path().strip_prefix(root)?.to_str().context("non-UTF8 export path")?.replace('\\', "/");
                    ensure!(expected_paths().contains(&path), "unexpected local export file");
                    let maximum = if path == CATALOG_PATH {
                        crate::b4_terminal::B4_TERMINAL_FIXTURE_CATALOG_MAX_BYTES
                    } else if path.ends_with(".raw-seal.bin") {
                        crate::constants::PROOF_BYTES
                    } else {
                        crate::receipt_oracle_codec::RECEIPT_ORACLE_MAX_BYTES
                    };
                    let mut file = fs::File::open(entry.path())?;
                    let before = file.metadata()?;
                    ensure!(before.is_file(), "local fixture opened as non-file");
                    let bytes = read_bounded(&mut file, maximum, before.len())?;
                    ensure!(file.metadata()?.len() == before.len(), "local fixture size changed after read");
                    output.push((path, bytes));
                }
            }
            Ok(())
        }
        let mut entries = Vec::new();
        visit(root, root, 0, &mut entries)?;
        Ok(entries)
    }

    pub(crate) fn join(entries: Vec<(String, Vec<u8>)>) -> Result<Joined> {
        let files = inventory(entries)?;
        let owned_map = |kind| terminal_byte_map_paths(kind).iter()
            .map(|path| ((*path).to_owned(), files[*path].clone())).collect::<BTreeMap<_, _>>();
        let raw = owned_map(B4TerminalByteMapKind::RawSeal);
        let oracles = owned_map(B4TerminalByteMapKind::ReceiptOracle);
        let replay = replay_fixed_terminal_oracles(&raw, &oracles)?;
        replay.bind_candidate_catalogue_jcs(&files[CATALOG_PATH])?;
        ensure!(replay.derived_catalogue_jcs()? == files[CATALOG_PATH], "honest catalogue is not derive-first exact");
        let raw_paths = B4_TERMINAL_FIXTURE_LAYOUT.iter().map(|slot| terminal_fixture_raw_seal_path(slot.fixture_id)).collect::<Result<Vec<_>>>()?;
        let oracle_paths = B4_TERMINAL_FIXTURE_LAYOUT.iter().map(|slot| terminal_fixture_receipt_oracle_path(slot.fixture_id)).collect::<Result<Vec<_>>>()?;
        let staged = StagedTerminalCatalogRecipeSourceV1 {
            catalogue: &files[CATALOG_PATH],
            raw_seals: std::array::from_fn(|index| raw[&raw_paths[index]].as_slice()),
            receipt_oracles: std::array::from_fn(|index| oracles[&oracle_paths[index]].as_slice()),
        };
        let raw_wire = encode_wire_map(B4TerminalByteMapKind::RawSeal, &staged.raw_seals)?;
        let oracle_wire = encode_wire_map(B4TerminalByteMapKind::ReceiptOracle, &staged.receipt_oracles)?;
        let positive = encode_subject_envelope(&[staged.catalogue, &raw_wire, &oracle_wire], terminal_catalog_subject_envelope_contract())?;
        let plan = Eip0045B4NegativePlanV1::canonical()?;
        let plan_bytes = plan.to_canonical_jcs()?;
        let planned = plan.groups.iter().flat_map(|group| group.executions.iter()).collect::<Vec<_>>();
        let mut rows = Vec::new();
        for index in 11..14 {
            let closed = reconstruct_terminal_catalog_execution_from_staged_source(index, planned[index], &plan_bytes, &staged)?.context("missing terminal catalogue row")?;
            ensure!(closed.contexts.is_empty(), "catalogue row acquired contexts");
            let parts = decode_subject_envelope(&closed.subject, terminal_catalog_subject_envelope_contract())?;
            let parts = parts.parts();
            ensure!(parts[1] == raw_wire && parts[2] == oracle_wire, "producer changed map bytes or wire order");
            let (candidate, materialization) = derive_candidate_materialization(index, staged.catalogue)?;
            ensure!(parts[0] == candidate && closed.derived_registry_row.materialization == materialization, "producer recipe drift");
            let edit = one_ascii_byte_replacement(staged.catalogue, parts[0])?;
            ensure!(reconstruct_byte_edit(staged.catalogue, &edit)? == parts[0], "non-isolated catalogue edit");
            let mut wrong = planned[index].clone();
            wrong.base_selector_id.push_str("-wrong");
            ensure!(reconstruct_terminal_catalog_execution_from_staged_source(index, &wrong, &plan_bytes, &staged).is_err(), "wrong plan selector accepted");
            rows.push(closed);
        }
        Ok(Joined { positive, rows })
    }

    #[test]
    fn local_export_inventory_rejects_omission_duplicate_and_extra_path() {
        let entries = expected_paths().into_iter().map(|path| (path, vec![1])).collect::<Vec<_>>();
        assert!(inventory(entries.clone()).is_ok()); // inventory only, never crypto acceptance
        assert!(inventory(entries[..18].to_vec()).is_err());
        let mut duplicate = entries.clone();
        duplicate[18] = duplicate[0].clone();
        assert!(inventory(duplicate).is_err());
        let mut extra = entries;
        extra[18].0.push_str(".extra");
        assert!(inventory(extra).is_err());
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        b4::{B4ByteOperation, B4ByteTarget, B4NegativeMaterialization, B4NegativeMutation},
        b4_materialization_set::close_production_execution,
        b4_mutation::{
            B4MaterializationReplayAdapterV1, Eip0045B4MaterializationIdentityV1,
            verify_materialization_identity_with_adapter,
        },
        b4_negative_io::Eip0045B4NegativeVerifierInputV1,
        b4_plan::{
            B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanExecutionV1,
            B4NegativePlanFixture, B4NegativeQaResultCode, Eip0045B4NegativePlanV1,
        },
        b4_subject_envelope::{
            decode_subject_envelope, encode_subject_envelope,
            terminal_catalog_subject_envelope_contract,
        },
        b4_terminal::{
            B4_TERMINAL_FIXTURE_COUNT, B4_TERMINAL_FIXTURE_LAYOUT,
            Eip0045B4TerminalFixtureCatalogV1, synthetic_terminal_fixture_catalog_source,
        },
        b4_terminal_byte_map::{
            B4TerminalByteMapEntry, B4TerminalByteMapKind, decode_terminal_byte_map,
            encode_terminal_byte_map, terminal_byte_map_paths,
        },
    };

    use super::{
        StagedTerminalCatalogRecipeSourceV1, TerminalCatalogFinalReplayAdapterV1,
        TerminalCatalogRawReplayAdapterV1, derive_candidate_materialization, encode_wire_map,
        reconstruct_terminal_catalog_execution_from_staged_source,
    };
    #[cfg(feature = "negative-materialization-set")]
    use super::{
        reconstruct_terminal_catalog_execution, reconstruct_terminal_catalog_execution_v2,
    };
    #[cfg(feature = "negative-materialization-set")]
    use crate::{
        b4_materialization_set::B4ClosedReconstructedExecutionV1,
        b4_terminal_evidence_packet::{
            B4TerminalEvidenceImportAuthorityV1, B4TerminalEvidenceImportAuthorityV2,
        },
    };

    struct TestSources {
        catalogue: Vec<u8>,
        raw_seals: [Vec<u8>; B4_TERMINAL_FIXTURE_COUNT],
        receipt_oracles: [Vec<u8>; B4_TERMINAL_FIXTURE_COUNT],
    }

    impl TestSources {
        fn staged(&self) -> StagedTerminalCatalogRecipeSourceV1<'_> {
            StagedTerminalCatalogRecipeSourceV1 {
                catalogue: &self.catalogue,
                raw_seals: self.raw_seals.each_ref().map(Vec::as_slice),
                receipt_oracles: self.receipt_oracles.each_ref().map(Vec::as_slice),
            }
        }
    }

    fn test_sources() -> TestSources {
        let (catalogue, artifacts) = synthetic_terminal_fixture_catalog_source().unwrap();
        let parsed = Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(&catalogue).unwrap();
        TestSources {
            catalogue,
            raw_seals: std::array::from_fn(|index| {
                artifacts[&parsed.fixtures[index].raw_seal.path].clone()
            }),
            receipt_oracles: std::array::from_fn(|index| {
                artifacts[&parsed.fixtures[index].receipt_oracle.path].clone()
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
    fn staged_terminal_catalog_uses_the_shared_subject_envelope_contract() {
        let parts = [b"catalogue".as_slice(), b"raw-map", b"oracle-map"];
        let encoded =
            encode_subject_envelope(&parts, terminal_catalog_subject_envelope_contract()).unwrap();
        let decoded =
            decode_subject_envelope(&encoded, terminal_catalog_subject_envelope_contract())
                .unwrap();
        assert_eq!(decoded.parts(), parts);
    }

    #[test]
    fn staged_terminal_catalog_scaffold_closes_only_rows_11_through_13() {
        let (plan_source, rows) = plan_and_rows();
        let sources = test_sources();
        for (index, planned) in rows.iter().enumerate().take(14).skip(11) {
            let closed = reconstruct_terminal_catalog_execution_from_staged_source(
                index,
                planned,
                &plan_source,
                &sources.staged(),
            )
            .unwrap()
            .unwrap();
            assert_eq!(
                closed.derived_registry_row.execution_id,
                planned.execution_id
            );
            assert!(closed.contexts.is_empty());
        }
        for index in [10, 14] {
            assert!(
                reconstruct_terminal_catalog_execution_from_staged_source(
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
        let entry: ProductionEntry = reconstruct_terminal_catalog_execution;
        let _ = entry;

        let source = include_str!("b4_c2_terminal_catalog.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("authority.terminal_materialization_projection()"));
        assert!(production.contains("projection.terminal_fixture_catalog_jcs()"));
        assert!(production.contains("projection.raw_seals()"));
        assert!(production.contains("projection.receipt_oracles()"));
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
        let entry: ProductionEntryV2 = reconstruct_terminal_catalog_execution_v2;
        let _ = entry;

        let production = include_str!("b4_c2_terminal_catalog.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(production.contains("authority.terminal_materialization_projection_v2()"));
        assert!(!production.contains("B4TerminalEvidenceImportAuthorityV2::"));
    }

    #[test]
    fn staged_terminal_catalog_scaffold_uses_wire_order_and_semantic_slot_zero() {
        let (plan_source, rows) = plan_and_rows();
        let sources = test_sources();
        let closed = reconstruct_terminal_catalog_execution_from_staged_source(
            12,
            &rows[12],
            &plan_source,
            &sources.staged(),
        )
        .unwrap()
        .unwrap();
        let parts = decode_subject_envelope(
            &closed.subject,
            terminal_catalog_subject_envelope_contract(),
        )
        .unwrap();
        let raw =
            decode_terminal_byte_map(B4TerminalByteMapKind::RawSeal, parts.parts()[1]).unwrap();
        let oracle =
            decode_terminal_byte_map(B4TerminalByteMapKind::ReceiptOracle, parts.parts()[2])
                .unwrap();
        assert_eq!(B4_TERMINAL_FIXTURE_LAYOUT[0].fixture_id, "lift-po2-14");
        assert_eq!(
            raw.entries()[3].path(),
            terminal_byte_map_paths(B4TerminalByteMapKind::RawSeal)[3]
        );
        assert_eq!(raw.entries()[3].payload(), sources.raw_seals[0]);
        assert_eq!(oracle.entries()[3].payload(), sources.receipt_oracles[0]);
        assert_ne!(raw.entries()[0].payload(), sources.raw_seals[0]);

        let honest =
            Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(&sources.catalogue).unwrap();
        let candidate: serde_json::Value = serde_json::from_slice(parts.parts()[0]).unwrap();
        assert_ne!(
            candidate["fixtures"][0]["claimDigest"].as_str(),
            Some(honest.fixtures[0].claim_digest.as_str())
        );
        let B4NegativeMaterialization::Mutation {
            mutation: B4NegativeMutation::ByteEdit { edit, target },
        } = &closed.derived_registry_row.materialization
        else {
            panic!("terminal-catalogue row did not retain one byte replacement");
        };
        assert_eq!(target, &B4ByteTarget::TerminalFixtureCatalogEntry);
        assert!(matches!(edit, B4ByteOperation::Replace { .. }));
    }

    #[test]
    fn staged_terminal_catalog_scaffold_rejects_every_plan_field_drift() {
        let (plan_source, rows) = plan_and_rows();
        let sources = test_sources();
        let mut drifts = Vec::new();
        let mut row = rows[11].clone();
        row.execution_id.push('x');
        drifts.push(row);
        let mut row = rows[11].clone();
        row.variant_id.push('x');
        drifts.push(row);
        let mut row = rows[11].clone();
        row.base_selector_id.push('x');
        drifts.push(row);
        let mut row = rows[11].clone();
        row.fixture = B4NegativePlanFixture::LiftPo215;
        drifts.push(row);
        let mut row = rows[11].clone();
        row.materialization_domain = B4MaterializationDomain::VerifierInput;
        drifts.push(row);
        let mut row = rows[11].clone();
        row.execution_surface = B4NegativeExecutionSurface::TerminalMetadata;
        drifts.push(row);
        let mut row = rows[11].clone();
        row.qa_result_code = B4NegativeQaResultCode::B4TerminalMetadataMismatch;
        drifts.push(row);
        let mut row = rows[11].clone();
        row.parser_truncation_words = Some(1);
        drifts.push(row);
        for drift in drifts {
            assert!(
                reconstruct_terminal_catalog_execution_from_staged_source(
                    11,
                    &drift,
                    &plan_source,
                    &sources.staged(),
                )
                .is_err()
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one adversarial matrix keeps recipe, field, map, order, envelope, identity, and neutral-input drift checks together"
    )]
    fn staged_terminal_catalog_scaffold_rejects_recipe_and_envelope_drift() {
        let (plan_source, rows) = plan_and_rows();
        let mut sources = test_sources();
        sources.catalogue.push(b' ');
        assert!(
            reconstruct_terminal_catalog_execution_from_staged_source(
                11,
                &rows[11],
                &plan_source,
                &sources.staged(),
            )
            .is_err()
        );

        let mut sources = test_sources();
        sources.raw_seals[0].pop();
        assert!(
            reconstruct_terminal_catalog_execution_from_staged_source(
                11,
                &rows[11],
                &plan_source,
                &sources.staged(),
            )
            .is_err()
        );

        let sources = test_sources();
        let mut wrong_plan = plan_source.clone();
        wrong_plan[0] ^= 1;
        assert!(
            reconstruct_terminal_catalog_execution_from_staged_source(
                11,
                &rows[11],
                &wrong_plan,
                &sources.staged(),
            )
            .is_err()
        );

        let sources = test_sources();
        let staged = sources.staged();
        let (candidate, materialization) =
            derive_candidate_materialization(11, staged.catalogue).unwrap();
        let raw_map = encode_wire_map(B4TerminalByteMapKind::RawSeal, &staged.raw_seals).unwrap();
        let oracle_map = encode_wire_map(
            B4TerminalByteMapKind::ReceiptOracle,
            &staged.receipt_oracles,
        )
        .unwrap();
        let subject = encode_subject_envelope(
            &[&candidate, &raw_map, &oracle_map],
            terminal_catalog_subject_envelope_contract(),
        )
        .unwrap();
        let raw_adapter = TerminalCatalogRawReplayAdapterV1 {
            execution_index: 11,
            planned: &rows[11],
            source: &staged,
            candidate: &candidate,
        };
        let final_adapter = TerminalCatalogFinalReplayAdapterV1 {
            execution_index: 11,
            planned: &rows[11],
            source: &staged,
            subject: &subject,
        };
        raw_adapter
            .replay_recipe("terminal-fixture-catalog-v1", &materialization)
            .unwrap();
        final_adapter
            .replay_recipe("terminal-fixture-catalog-v1", &materialization)
            .unwrap();

        let mut recipe_drift = materialization.clone();
        let B4NegativeMaterialization::Mutation {
            mutation: B4NegativeMutation::ByteEdit { target, .. },
        } = &mut recipe_drift
        else {
            unreachable!()
        };
        *target = B4ByteTarget::RawSeal;
        assert!(
            raw_adapter
                .replay_recipe("terminal-fixture-catalog-v1", &recipe_drift)
                .is_err()
        );
        assert!(
            raw_adapter
                .replay_recipe("terminal-fixture-catalog-v2", &materialization)
                .is_err()
        );

        let wrong_field_adapter = TerminalCatalogRawReplayAdapterV1 {
            execution_index: 12,
            planned: &rows[11],
            source: &staged,
            candidate: &candidate,
        };
        assert!(
            wrong_field_adapter
                .replay_recipe("terminal-fixture-catalog-v1", &materialization)
                .is_err()
        );
        let mut candidate_drift = candidate.clone();
        candidate_drift[0] ^= 1;
        let candidate_drift_adapter = TerminalCatalogRawReplayAdapterV1 {
            execution_index: 11,
            planned: &rows[11],
            source: &staged,
            candidate: &candidate_drift,
        };
        assert!(
            candidate_drift_adapter
                .replay_recipe("terminal-fixture-catalog-v1", &materialization)
                .is_err()
        );

        let mut raw_map_drift = raw_map.clone();
        *raw_map_drift.last_mut().unwrap() ^= 1;
        let map_drift_subject = encode_subject_envelope(
            &[&candidate, &raw_map_drift, &oracle_map],
            terminal_catalog_subject_envelope_contract(),
        )
        .unwrap();
        let map_drift_adapter = TerminalCatalogFinalReplayAdapterV1 {
            execution_index: 11,
            planned: &rows[11],
            source: &staged,
            subject: &map_drift_subject,
        };
        assert!(
            map_drift_adapter
                .replay_recipe("terminal-fixture-catalog-v1", &materialization)
                .is_err()
        );

        let paths = terminal_byte_map_paths(B4TerminalByteMapKind::RawSeal);
        let mut order_drift_entries =
            std::array::from_fn::<_, B4_TERMINAL_FIXTURE_COUNT, _>(|wire_index| {
                B4TerminalByteMapEntry::new(
                    paths[wire_index],
                    staged.raw_seals[super::WIRE_TO_SEMANTIC_SLOT[wire_index]],
                )
            });
        order_drift_entries.swap(0, 1);
        assert!(
            encode_terminal_byte_map(B4TerminalByteMapKind::RawSeal, &order_drift_entries).is_err()
        );

        let mut envelope_drift = subject.clone();
        envelope_drift.push(0);
        let envelope_drift_adapter = TerminalCatalogFinalReplayAdapterV1 {
            execution_index: 11,
            planned: &rows[11],
            source: &staged,
            subject: &envelope_drift,
        };
        assert!(
            envelope_drift_adapter
                .replay_recipe("terminal-fixture-catalog-v1", &materialization)
                .is_err()
        );

        let closed = reconstruct_terminal_catalog_execution_from_staged_source(
            11,
            &rows[11],
            &plan_source,
            &staged,
        )
        .unwrap()
        .unwrap();
        let identity = Eip0045B4MaterializationIdentityV1::from_canonical_jcs(
            &closed.materialization_identity_jcs,
        )
        .unwrap();
        verify_materialization_identity_with_adapter(
            &identity,
            &plan_source,
            &closed.derived_registry_row,
            &final_adapter,
        )
        .unwrap();
        let mut identity_drift = identity;
        let replacement = if identity_drift.output_sha256.starts_with('0') {
            "1"
        } else {
            "0"
        };
        identity_drift.output_sha256.replace_range(..1, replacement);
        assert!(
            verify_materialization_identity_with_adapter(
                &identity_drift,
                &plan_source,
                &closed.derived_registry_row,
                &final_adapter,
            )
            .is_err()
        );

        let input =
            Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(&closed.negative_input_jcs)
                .unwrap();
        assert_eq!(
            input.validation_surface,
            B4NegativeExecutionSurface::TerminalFixtureCatalog
        );
        assert!(input.context.is_empty());
        let mut input_binding_drift = rows[11].clone();
        input_binding_drift.execution_surface = B4NegativeExecutionSurface::TerminalMetadata;
        assert!(
            close_production_execution(
                11,
                &input_binding_drift,
                &plan_source,
                closed.derived_registry_row.clone(),
                &raw_adapter,
                &final_adapter,
                subject.clone(),
                Vec::new(),
            )
            .is_err()
        );
    }
}
