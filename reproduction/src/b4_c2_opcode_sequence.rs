//! Closed C2 producers for opcode-input and detached-sequence rows.
//!
//! The producer derives every mutation from already authenticated positive and
//! catalogue bytes.  External execution files are compared with its result by
//! the parent materialization authority and never influence a recipe, base, or
//! subject byte.

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    b4::{
        B4ArtifactEncoding, B4BoundaryShiftDirection, B4ByteOperation, B4ByteTarget,
        B4NegativeCase, B4NegativeMaterialization, B4NegativeMutation, B4PositiveArtifactRole,
        B4SequenceOperation, B4SequenceTarget,
    },
    b4_catalog::{B4SubjectProvenanceV1, Eip0045B4SubjectCatalogV1},
    b4_materialization_set::{
        B4AuthenticatedMaterializationTopLevelV1, B4ClosedReconstructedExecutionV1,
        close_production_execution,
    },
    b4_mutation::{
        B4MaterializationReplayAdapterV1, reconstruct_byte_edit, reconstruct_sequence_edit,
    },
    b4_plan::{B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanExecutionV1},
    b4_subject::{B4SequenceSubjectElement, Eip0045B4SequenceSubjectV1},
    b4_subject_envelope::{
        B4SubjectEnvelopeContract, B4SubjectEnvelopeKind, B4SubjectPartBounds,
        encode_subject_envelope,
    },
    canonical::{canonical_json_bytes, validate_canonical_json_source},
    constants::{
        MAX_APPLICATION_PAYLOAD_BYTES, PROOF_BYTES, PROOF_CHUNK_LENGTHS, STATEMENT_PREFIX_BYTES,
    },
    parse_ergo_statement_v1,
    profile_manifest::StarkProfileManifestV1,
};

const C2_OPCODE_FIRST_INDEX: usize = 7;
const C2_OPCODE_FIRST_END_EXCLUSIVE: usize = 11;
const C2_CATALOG_FIRST_INDEX: usize = 14;
const C2_OPCODE_SEQUENCE_END_EXCLUSIVE: usize = 29;
const C2_TRAILING_FIRST_INDEX: usize = 30;
const C2_TRAILING_END_EXCLUSIVE: usize = 33;

const OPCODE_SELECTOR: &str = "lift-po2-15-opcode-inputs-v1";
const LIFT_SELECTOR: &str = "lift-po2-15";
const CATALOG_SELECTOR: &str = "sequence-subject-catalog-v1";
const LIFT_CASE_ID: &str = "lift-po2-15";
const LIFT_PROOF_SUBJECT_ID: &str = "proof-chunks-lift-po2-15";

const OPCODE_PROOF_VECTOR_MIN_BYTES: usize = 2 + 3 * 4;
const OPCODE_PROOF_VECTOR_MAX_BYTES: usize = 2 + 5 * 4 + PROOF_BYTES + 4;
const PRODUCER_OPCODE_ENVELOPE_MAGIC: &[u8; 8] = b"EIP45B4S";
const PRODUCER_OPCODE_ENVELOPE_VERSION: u8 = 1;
const PRODUCER_OPCODE_ENVELOPE_KIND: u8 = 0x01;
const PRODUCER_OPCODE_ENVELOPE_PART_COUNT: usize = 4;
const PRODUCER_OPCODE_ENVELOPE_HEADER_BYTES: usize = 8 + 1 + 1 + 2;
const PRODUCER_OPCODE_PART_LENGTH_BOUNDS: [(usize, usize); 4] = [
    (OPCODE_PROOF_VECTOR_MIN_BYTES, OPCODE_PROOF_VECTOR_MAX_BYTES),
    (0, MAX_APPLICATION_PAYLOAD_BYTES + 1),
    (31, 33),
    (31, 33),
];
pub(crate) const OPCODE_PART_BOUNDS: [B4SubjectPartBounds; 4] = [
    B4SubjectPartBounds::new(
        PRODUCER_OPCODE_PART_LENGTH_BOUNDS[0].0,
        PRODUCER_OPCODE_PART_LENGTH_BOUNDS[0].1,
    ),
    B4SubjectPartBounds::new(
        PRODUCER_OPCODE_PART_LENGTH_BOUNDS[1].0,
        PRODUCER_OPCODE_PART_LENGTH_BOUNDS[1].1,
    ),
    B4SubjectPartBounds::new(
        PRODUCER_OPCODE_PART_LENGTH_BOUNDS[2].0,
        PRODUCER_OPCODE_PART_LENGTH_BOUNDS[2].1,
    ),
    B4SubjectPartBounds::new(
        PRODUCER_OPCODE_PART_LENGTH_BOUNDS[3].0,
        PRODUCER_OPCODE_PART_LENGTH_BOUNDS[3].1,
    ),
];
const CATALOG_PART_BOUNDS: [B4SubjectPartBounds; 1] = [B4SubjectPartBounds::new(1, 128 * 1024)];

const C2_EXECUTION_IDS: &[(usize, &str)] = &[
    (7, "opcode-profile-id-length-sweep--thirty-one-bytes"),
    (8, "opcode-profile-id-length-sweep--thirty-three-bytes"),
    (9, "opcode-program-id-length-sweep--thirty-one-bytes"),
    (10, "opcode-program-id-length-sweep--thirty-three-bytes"),
    (
        14,
        "sequence-subject-provenance-target-sweep--registry-positive-cases",
    ),
    (
        15,
        "sequence-subject-provenance-target-sweep--registry-negative-cases",
    ),
    (
        16,
        "sequence-subject-provenance-target-sweep--registry-negative-classes",
    ),
    (
        17,
        "sequence-subject-provenance-target-sweep--profile-package-files",
    ),
    (18, "sequence-subject-provenance-target-sweep--proof-chunks"),
    (19, "statement-payload-over-maximum--maximum-plus-one"),
    (20, "proof-chunk-count-sweep--three-chunks"),
    (21, "proof-chunk-count-sweep--five-chunks"),
    (22, "proof-empty-chunk--fourth-chunk-empty"),
    (
        23,
        "proof-boundary-shift-sweep--boundary-zero-left-short-right-long",
    ),
    (
        24,
        "proof-boundary-shift-sweep--boundary-zero-left-long-right-short",
    ),
    (
        25,
        "proof-boundary-shift-sweep--boundary-one-left-short-right-long",
    ),
    (
        26,
        "proof-boundary-shift-sweep--boundary-one-left-long-right-short",
    ),
    (
        27,
        "proof-boundary-shift-sweep--boundary-two-left-short-right-long",
    ),
    (
        28,
        "proof-boundary-shift-sweep--boundary-two-left-long-right-short",
    ),
    (30, "proof-seal-truncated-byte--last-chunk-short-one-byte"),
    (31, "proof-seal-trailing-byte--last-chunk-long-one-byte"),
    (32, "proof-seal-trailing-word--last-chunk-long-one-word"),
];

#[derive(Clone, Debug)]
struct C2Sources<'a> {
    manifest: &'a [u8],
    raw_seal: &'a [u8],
    subject_catalog: &'a [u8],
    proof_subject: Vec<u8>,
    preflight_payload: Vec<u8>,
    program_id: [u8; 32],
    profile_id: [u8; 32],
    opcode_base: Vec<u8>,
}

impl<'a> C2Sources<'a> {
    #[allow(
        clippy::too_many_lines,
        reason = "the source-authority checklist stays linear so reviewers can audit every authenticated edge in protocol order"
    )]
    fn authenticate(top_level: &'a B4AuthenticatedMaterializationTopLevelV1) -> Result<Self> {
        ensure!(
            top_level.positive_exports.len() == 11
                && top_level.expanded_registry.positive_cases.len() == 11,
            "C2 source authority does not contain exactly eleven positive cases"
        );
        let positive = &top_level.expanded_registry.positive_cases[0];
        let export = &top_level.positive_exports[0];
        ensure!(
            positive.index == 0
                && positive.case_id == LIFT_CASE_ID
                && export.case_index == 0
                && export.raw_seal.len() == PROOF_BYTES,
            "C2 source authority does not select the exact lift-po2-15 positive export"
        );

        let manifest_binding = &top_level.expanded_registry.profile.manifest;
        ensure!(
            manifest_binding.encoding == B4ArtifactEncoding::RawBytes,
            "C2 profile manifest binding is not raw bytes"
        );
        let manifest = authenticated_source(top_level, &manifest_binding.path)?;
        ensure!(
            u64::try_from(manifest.len())? == manifest_binding.byte_length
                && sha256_hex(manifest) == manifest_binding.sha256,
            "C2 profile manifest differs from its authenticated registry binding"
        );
        let decoded_manifest =
            StarkProfileManifestV1::decode(manifest).context("C2 profile manifest is malformed")?;
        decoded_manifest
            .validate_initial_profile_target()
            .context("C2 profile manifest differs from the initial profile")?;
        ensure!(
            decoded_manifest
                .encode()
                .context("cannot re-encode C2 profile manifest")?
                .as_slice()
                == manifest,
            "C2 profile manifest does not round-trip byte-exactly"
        );

        let journal_artifact = unique_positive_artifact(positive, B4PositiveArtifactRole::Journal)?;
        let statement_bytes = authenticated_source(top_level, &journal_artifact.path)?;
        ensure!(
            journal_artifact.encoding == B4ArtifactEncoding::RawBytes
                && u64::try_from(statement_bytes.len())? == journal_artifact.byte_length
                && sha256_hex(statement_bytes) == journal_artifact.sha256
                && sha256_hex(statement_bytes)
                    == top_level
                        .expanded_registry
                        .bindings
                        .reference_statement_bundle
                        .statement_sha256,
            "C2 reference statement differs from its authenticated positive bindings"
        );
        let statement = parse_ergo_statement_v1(statement_bytes)
            .context("C2 reference statement is invalid")?;
        ensure!(
            statement_bytes.len() == STATEMENT_PREFIX_BYTES + statement.application_payload().len(),
            "C2 reference statement has an inconsistent payload projection"
        );
        ensure!(
            statement.application_payload().len() <= MAX_APPLICATION_PAYLOAD_BYTES,
            "C2 reference statement exceeds the initial profile payload bound"
        );

        let manifest_profile_id = decoded_manifest
            .profile_id()
            .context("cannot derive C2 manifest profile ID")?;
        ensure!(
            statement.profile_id() == manifest_profile_id
                && hex::encode(manifest_profile_id)
                    == top_level.expanded_registry.profile.profile_id,
            "C2 statement, manifest, and registry bind different profile IDs"
        );
        ensure!(
            hex::encode(statement.program_id())
                == top_level.expanded_registry.bindings.guest.image_id,
            "C2 statement and authenticated guest bind different program IDs"
        );
        ensure!(
            hex::encode(statement.contract_id())
                == top_level
                    .expanded_registry
                    .bindings
                    .reference_statement_bundle
                    .contract_id,
            "C2 statement and registry bind different contract IDs"
        );

        let image_artifact = unique_positive_artifact(positive, B4PositiveArtifactRole::ImageId)?;
        let image_id = authenticated_source(top_level, &image_artifact.path)?;
        ensure!(
            image_artifact.encoding == B4ArtifactEncoding::RawBytes
                && image_id == statement.program_id().as_slice()
                && u64::try_from(image_id.len())? == image_artifact.byte_length
                && sha256_hex(image_id) == image_artifact.sha256,
            "C2 image-ID artifact differs from the statement program ID"
        );

        let raw_artifact = unique_positive_artifact(positive, B4PositiveArtifactRole::RawSeal)?;
        let raw_seal = export.raw_seal.as_slice();
        ensure!(
            raw_artifact.encoding == B4ArtifactEncoding::RawBytes
                && raw_artifact.byte_length == u64::try_from(PROOF_BYTES)?
                && u64::try_from(raw_seal.len())? == raw_artifact.byte_length
                && raw_artifact.sha256 == sha256_hex(raw_seal),
            "C2 lift-po2-15 raw seal differs from its positive registry identity"
        );

        let subject_catalog =
            Eip0045B4SubjectCatalogV1::from_canonical_jcs(&top_level.subject_catalog_jcs)
                .context("C2 subject catalog is not the exact closed catalogue")?;
        let proof_entry = subject_catalog
            .subjects
            .get(4)
            .context("C2 subject catalogue lacks lift-po2-15 proof chunks")?;
        ensure!(
            proof_entry.subject_id == LIFT_PROOF_SUBJECT_ID
                && proof_entry.target == B4SequenceTarget::ProofChunks,
            "C2 subject catalogue has the wrong lift-po2-15 chunk entry"
        );
        let proof_subject_source = authenticated_source(top_level, &proof_entry.artifact.path)?;
        ensure!(
            u64::try_from(proof_subject_source.len())? == proof_entry.artifact.byte_length
                && sha256_hex(proof_subject_source) == proof_entry.artifact.sha256,
            "C2 lift-po2-15 proof subject differs from its catalogue identity"
        );
        let derived_proof_subject = proof_subject_from_raw_seal(raw_seal)?;
        ensure!(
            proof_subject_source == derived_proof_subject.as_slice(),
            "C2 lift-po2-15 proof subject differs from the authenticated raw-seal projection"
        );

        // Opcode-preflight rows use one deterministic boundary fixture rather
        // than changing the authenticated receipt statement.  A maximum-size
        // zero payload passes the positive length boundary, lets row 19 cross
        // it with one bounded inserted byte, and keeps every rejection before
        // statement construction or proof verification.
        let preflight_payload = vec![0_u8; MAX_APPLICATION_PAYLOAD_BYTES];
        let program_id = statement.program_id();
        let profile_id = statement.profile_id();
        let canonical_chunks = split_raw_seal(raw_seal)?;
        let opcode_base = encode_opcode_subject(
            &canonical_chunks,
            &preflight_payload,
            &program_id,
            &profile_id,
        )?;

        Ok(Self {
            manifest,
            raw_seal,
            subject_catalog: &top_level.subject_catalog_jcs,
            proof_subject: derived_proof_subject,
            preflight_payload,
            program_id,
            profile_id,
            opcode_base,
        })
    }

    fn base_for(&self, execution_index: usize) -> Result<&[u8]> {
        match execution_index {
            7..=10 | 19 => Ok(&self.opcode_base),
            14..=18 => Ok(self.subject_catalog),
            20..=28 | 30..=32 => Ok(self.raw_seal),
            _ => bail!("C2 execution index is outside the closed producer set"),
        }
    }

    fn contexts_for(&self, execution_index: usize) -> Result<Vec<Vec<u8>>> {
        match execution_index {
            7..=10 | 19..=28 | 30..=32 => Ok(vec![self.manifest.to_vec()]),
            14..=18 => Ok(Vec::new()),
            _ => bail!("C2 execution index is outside the closed producer set"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum C2AdapterOutput {
    Raw,
    Final,
}

#[derive(Clone, Copy, Debug)]
struct C2ReplayAdapter<'sources, 'authenticated> {
    execution_index: usize,
    sources: &'sources C2Sources<'authenticated>,
    expected_materialization: &'sources B4NegativeMaterialization,
    output: &'sources [u8],
    output_kind: C2AdapterOutput,
}

impl B4MaterializationReplayAdapterV1 for C2ReplayAdapter<'_, '_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        domain_and_surface(self.execution_index)
            .expect("C2 replay adapter has a compile-time admitted index")
            .0
    }

    fn base_bytes(&self) -> &[u8] {
        self.sources
            .base_for(self.execution_index)
            .expect("C2 replay adapter has a compile-time admitted index")
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
            base_selector_id == selector_for(self.execution_index)?
                && materialization == self.expected_materialization,
            "C2 replay received a selector or recipe outside its closed row"
        );
        let replayed = replay_materialization(self.execution_index, self.sources, materialization)?;
        let expected = match self.output_kind {
            C2AdapterOutput::Raw => &replayed.raw_output,
            C2AdapterOutput::Final => &replayed.final_subject,
        };
        ensure!(
            self.output == expected,
            "C2 replay output differs from independent logical reconstruction"
        );
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct C2ReplayResult {
    raw_output: Vec<u8>,
    final_subject: Vec<u8>,
}

/// Reconstruct one of the twenty-two closed C2 opcode/sequence executions.
///
/// Returns `None` for every other canonical-plan index.  The function never
/// falls back to caller-supplied execution bytes.
pub(crate) fn reconstruct_opcode_sequence_execution(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    if !is_c2_index(execution_index) {
        return Ok(None);
    }
    validate_planned_row(execution_index, planned)?;
    let sources = C2Sources::authenticate(top_level)?;
    let materialization = derive_materialization(execution_index, &sources)?;
    let (materialization_domain, _) = domain_and_surface(execution_index)
        .context("C2 execution index is outside the closed producer set")?;
    let registry_row = B4NegativeCase {
        execution_id: expected_execution_id(execution_index)
            .context("C2 execution lacks its closed execution ID")?
            .to_owned(),
        base_selector_id: selector_for(execution_index)?.to_owned(),
        materialization_domain,
        materialization,
    };
    let expected_materialization = registry_row.materialization.clone();
    let replayed = replay_materialization(execution_index, &sources, &expected_materialization)?;
    let raw_adapter = C2ReplayAdapter {
        execution_index,
        sources: &sources,
        expected_materialization: &expected_materialization,
        output: &replayed.raw_output,
        output_kind: C2AdapterOutput::Raw,
    };
    let final_adapter = C2ReplayAdapter {
        execution_index,
        sources: &sources,
        expected_materialization: &expected_materialization,
        output: &replayed.final_subject,
        output_kind: C2AdapterOutput::Final,
    };
    let contexts = sources.contexts_for(execution_index)?;
    close_production_execution(
        execution_index,
        planned,
        &top_level.negative_plan,
        registry_row,
        &raw_adapter,
        &final_adapter,
        replayed.final_subject.clone(),
        contexts,
    )
    .map(Some)
}

fn is_c2_index(index: usize) -> bool {
    (C2_OPCODE_FIRST_INDEX..C2_OPCODE_FIRST_END_EXCLUSIVE).contains(&index)
        || (C2_CATALOG_FIRST_INDEX..C2_OPCODE_SEQUENCE_END_EXCLUSIVE).contains(&index)
        || (C2_TRAILING_FIRST_INDEX..C2_TRAILING_END_EXCLUSIVE).contains(&index)
}

fn expected_execution_id(index: usize) -> Option<&'static str> {
    C2_EXECUTION_IDS
        .iter()
        .find_map(|(candidate, id)| (*candidate == index).then_some(*id))
}

fn domain_and_surface(
    index: usize,
) -> Option<(B4MaterializationDomain, B4NegativeExecutionSurface)> {
    match index {
        7..=10 | 19..=28 | 30..=32 => Some((
            B4MaterializationDomain::VerifierInput,
            B4NegativeExecutionSurface::OpcodePreflight,
        )),
        14..=18 => Some((
            B4MaterializationDomain::ArtifactValidator,
            B4NegativeExecutionSurface::SequenceSubjectCatalog,
        )),
        _ => None,
    }
}

fn selector_for(index: usize) -> Result<&'static str> {
    match index {
        7..=10 | 19 => Ok(OPCODE_SELECTOR),
        14..=18 => Ok(CATALOG_SELECTOR),
        20..=28 | 30..=32 => Ok(LIFT_SELECTOR),
        _ => bail!("C2 execution index is outside the closed producer set"),
    }
}

fn validate_planned_row(index: usize, planned: &B4NegativePlanExecutionV1) -> Result<()> {
    let (domain, surface) = domain_and_surface(index)
        .context("C2 execution index is outside the closed producer set")?;
    ensure!(
        expected_execution_id(index) == Some(planned.execution_id.as_str())
            && selector_for(index)? == planned.base_selector_id
            && planned.materialization_domain == domain
            && planned.execution_surface == surface,
        "C2 execution differs from its exact canonical-plan position"
    );
    Ok(())
}

fn derive_materialization(
    execution_index: usize,
    sources: &C2Sources<'_>,
) -> Result<B4NegativeMaterialization> {
    let mutation = match execution_index {
        7 => byte_mutation(B4ByteTarget::ProfileId, truncate_last(&sources.profile_id)?),
        8 => byte_mutation(
            B4ByteTarget::ProfileId,
            append_authenticated_suffix(&sources.profile_id, 1)?,
        ),
        9 => byte_mutation(B4ByteTarget::ProgramId, truncate_last(&sources.program_id)?),
        10 => byte_mutation(
            B4ByteTarget::ProgramId,
            append_authenticated_suffix(&sources.program_id, 1)?,
        ),
        14..=18 => byte_mutation(
            B4ByteTarget::SubjectCatalogEntry,
            catalog_entry_edit(execution_index, sources.subject_catalog)?,
        ),
        19 => {
            ensure!(
                sources.preflight_payload.len() == MAX_APPLICATION_PAYLOAD_BYTES,
                "C2 payload boundary base is not exactly the admitted maximum"
            );
            byte_mutation(
                B4ByteTarget::ApplicationPayload,
                B4ByteOperation::Insert {
                    inserted_hex: "00".to_owned(),
                    offset: u64::try_from(sources.preflight_payload.len())?,
                },
            )
        }
        20 => {
            let subject = parsed_proof_subject(&sources.proof_subject)?;
            let element = subject
                .elements
                .get(3)
                .context("C2 proof subject lacks its fourth chunk")?;
            sequence_mutation(B4SequenceOperation::Omit {
                before_element_id: element.element_id.clone(),
                before_element_sha256: element.sha256.clone(),
                index: 3,
            })
        }
        21 => sequence_mutation(B4SequenceOperation::Insert {
            inserted_element: B4SequenceSubjectElement::from_bytes("chunk-04", b"")?,
            index: 4,
        }),
        22 => {
            let subject = parsed_proof_subject(&sources.proof_subject)?;
            let element = subject
                .elements
                .get(3)
                .context("C2 proof subject lacks its fourth chunk")?;
            sequence_mutation(B4SequenceOperation::Replace {
                before_element_id: element.element_id.clone(),
                before_element_sha256: element.sha256.clone(),
                index: 3,
                replacement_element: B4SequenceSubjectElement::from_bytes(
                    element.element_id.clone(),
                    b"",
                )?,
            })
        }
        23..=28 => {
            let relative = execution_index - 23;
            sequence_mutation(B4SequenceOperation::ShiftBoundary {
                byte_count: 1,
                direction: if relative.is_multiple_of(2) {
                    B4BoundaryShiftDirection::LeftToRight
                } else {
                    B4BoundaryShiftDirection::RightToLeft
                },
                left_chunk_index: u64::try_from(relative / 2)?,
            })
        }
        30 => byte_mutation(B4ByteTarget::RawSeal, truncate_last(sources.raw_seal)?),
        31 => byte_mutation(
            B4ByteTarget::RawSeal,
            append_authenticated_suffix(sources.raw_seal, 1)?,
        ),
        32 => byte_mutation(
            B4ByteTarget::RawSeal,
            append_authenticated_suffix(sources.raw_seal, 4)?,
        ),
        _ => bail!("C2 execution index is outside the closed producer set"),
    };
    Ok(B4NegativeMaterialization::Mutation { mutation })
}

fn byte_mutation(target: B4ByteTarget, edit: B4ByteOperation) -> B4NegativeMutation {
    B4NegativeMutation::ByteEdit { edit, target }
}

fn sequence_mutation(edit: B4SequenceOperation) -> B4NegativeMutation {
    B4NegativeMutation::SequenceEdit {
        edit,
        target: B4SequenceTarget::ProofChunks,
    }
}

fn truncate_last(source: &[u8]) -> Result<B4ByteOperation> {
    let last = source.last().context("cannot truncate an empty C2 base")?;
    Ok(B4ByteOperation::Truncate {
        before_hex: format!("{last:02x}"),
        new_length: u64::try_from(source.len() - 1)?,
        original_length: u64::try_from(source.len())?,
    })
}

fn append_authenticated_suffix(source: &[u8], byte_count: usize) -> Result<B4ByteOperation> {
    ensure!(
        byte_count > 0 && source.len() >= byte_count,
        "C2 append suffix is outside its authenticated base"
    );
    Ok(B4ByteOperation::Insert {
        inserted_hex: hex::encode(&source[source.len() - byte_count..]),
        offset: u64::try_from(source.len())?,
    })
}

fn replay_materialization(
    execution_index: usize,
    sources: &C2Sources<'_>,
    materialization: &B4NegativeMaterialization,
) -> Result<C2ReplayResult> {
    let B4NegativeMaterialization::Mutation { mutation } = materialization else {
        bail!("C2 producer received a fixture-selection recipe");
    };
    match (execution_index, mutation) {
        (
            7..=10 | 19,
            B4NegativeMutation::ByteEdit {
                edit,
                target:
                    target @ (B4ByteTarget::ProfileId
                    | B4ByteTarget::ProgramId
                    | B4ByteTarget::ApplicationPayload),
            },
        ) => replay_opcode_field_mutation(sources, *target, edit),
        (
            14..=18,
            B4NegativeMutation::ByteEdit {
                edit,
                target: B4ByteTarget::SubjectCatalogEntry,
            },
        ) => replay_catalog_mutation(execution_index, sources, edit),
        (
            20..=28,
            B4NegativeMutation::SequenceEdit {
                edit,
                target: B4SequenceTarget::ProofChunks,
            },
        ) => replay_proof_sequence_mutation(sources, edit),
        (
            30..=32,
            B4NegativeMutation::ByteEdit {
                edit,
                target: B4ByteTarget::RawSeal,
            },
        ) => replay_raw_seal_length_mutation(sources, edit),
        _ => bail!("C2 recipe family/target differs from its exact execution row"),
    }
}

fn replay_opcode_field_mutation(
    sources: &C2Sources<'_>,
    target: B4ByteTarget,
    edit: &B4ByteOperation,
) -> Result<C2ReplayResult> {
    let (base_field, field_position) = match target {
        B4ByteTarget::ApplicationPayload => (sources.preflight_payload.as_slice(), 1),
        B4ByteTarget::ProgramId => (sources.program_id.as_slice(), 2),
        B4ByteTarget::ProfileId => (sources.profile_id.as_slice(), 3),
        _ => bail!("C2 opcode field mutation has the wrong logical target"),
    };
    let mutated = reconstruct_byte_edit(base_field, edit)?;
    let chunks = split_raw_seal(sources.raw_seal)?;
    let mut payload = sources.preflight_payload.as_slice();
    let mut program_id = sources.program_id.as_slice();
    let mut profile_id = sources.profile_id.as_slice();
    match field_position {
        1 => payload = &mutated,
        2 => program_id = &mutated,
        3 => profile_id = &mutated,
        _ => unreachable!("closed opcode field position"),
    }
    let final_subject = encode_opcode_subject(&chunks, payload, program_id, profile_id)?;
    Ok(C2ReplayResult {
        raw_output: mutated,
        final_subject,
    })
}

fn replay_proof_sequence_mutation(
    sources: &C2Sources<'_>,
    edit: &B4SequenceOperation,
) -> Result<C2ReplayResult> {
    let raw_output =
        reconstruct_sequence_edit(&sources.proof_subject, B4SequenceTarget::ProofChunks, edit)?;
    let subject = parsed_proof_subject(&raw_output)?;
    let chunks = subject
        .elements
        .iter()
        .map(B4SequenceSubjectElement::decoded_bytes)
        .collect::<Result<Vec<_>>>()?;
    let final_subject = encode_opcode_subject(
        &chunks,
        &sources.preflight_payload,
        &sources.program_id,
        &sources.profile_id,
    )?;
    Ok(C2ReplayResult {
        raw_output,
        final_subject,
    })
}

fn replay_raw_seal_length_mutation(
    sources: &C2Sources<'_>,
    edit: &B4ByteOperation,
) -> Result<C2ReplayResult> {
    let raw_output = reconstruct_byte_edit(sources.raw_seal, edit)?;
    let chunks = split_length_mutated_raw_seal(&raw_output)?;
    let final_subject = encode_opcode_subject(
        &chunks,
        &sources.preflight_payload,
        &sources.program_id,
        &sources.profile_id,
    )?;
    Ok(C2ReplayResult {
        raw_output,
        final_subject,
    })
}

fn replay_catalog_mutation(
    execution_index: usize,
    sources: &C2Sources<'_>,
    edit: &B4ByteOperation,
) -> Result<C2ReplayResult> {
    let entry_index = execution_index - C2_CATALOG_FIRST_INDEX;
    let catalog = Eip0045B4SubjectCatalogV1::from_canonical_jcs(sources.subject_catalog)?;
    let entry = catalog
        .subjects
        .get(entry_index)
        .context("C2 catalog mutation entry is absent")?;
    let entry_source = canonical_json_bytes(&serde_json::to_value(entry)?)?;
    let mutated_entry_source = reconstruct_byte_edit(&entry_source, edit)?;
    let mutated_entry = validate_canonical_json_source(&mutated_entry_source)
        .context("C2 catalog entry mutation is not canonical JCS")?;

    let mut catalog_value = validate_canonical_json_source(sources.subject_catalog)?;
    let subjects = catalog_value
        .get_mut("subjects")
        .and_then(Value::as_array_mut)
        .context("C2 catalog source lacks its subject array")?;
    subjects[entry_index] = mutated_entry;
    let raw_output = canonical_json_bytes(&catalog_value)?;
    ensure!(
        raw_output != sources.subject_catalog,
        "C2 catalog mutation reconstructed a no-op"
    );
    let final_subject = encode_subject_envelope(
        &[&raw_output],
        B4SubjectEnvelopeContract::new(
            B4SubjectEnvelopeKind::SequenceCatalogBundle,
            &CATALOG_PART_BOUNDS,
        ),
    )?;
    Ok(C2ReplayResult {
        raw_output,
        final_subject,
    })
}

fn catalog_entry_edit(execution_index: usize, source: &[u8]) -> Result<B4ByteOperation> {
    let catalog = Eip0045B4SubjectCatalogV1::from_canonical_jcs(source)?;
    let entry_index = execution_index
        .checked_sub(C2_CATALOG_FIRST_INDEX)
        .context("C2 catalogue index underflows")?;
    let entry = catalog
        .subjects
        .get(entry_index)
        .context("C2 catalogue mutation entry is absent")?;
    let entry_source = canonical_json_bytes(&serde_json::to_value(entry)?)?;
    match execution_index {
        14 => unique_equal_length_replace(
            &entry_source,
            b"\"targetKind\":\"registry-positive-cases\"",
            b"\"targetKind\":\"registry-negative-cases\"",
        ),
        15 | 16 => {
            let (B4SubjectProvenanceV1::NegativePlan { plan_sha256 }
            | B4SubjectProvenanceV1::NegativeClasses { plan_sha256 }) = &entry.provenance
            else {
                bail!("C2 catalogue row lacks its exact negative-plan provenance");
            };
            let mut changed_sha256 = plan_sha256.clone().into_bytes();
            let first = changed_sha256
                .first_mut()
                .context("C2 plan digest is unexpectedly empty")?;
            *first = if *first == b'0' { b'1' } else { b'0' };
            let before = format!("\"planSha256\":\"{plan_sha256}\"");
            let replacement = format!(
                "\"planSha256\":\"{}\"",
                String::from_utf8(changed_sha256)
                    .context("C2 plan digest mutation is not UTF-8")?
            );
            unique_equal_length_replace(&entry_source, before.as_bytes(), replacement.as_bytes())
        }
        17 => unique_equal_length_replace(
            &entry_source,
            b"\"provenanceKind\":\"profile-package\"",
            b"\"provenanceKind\":\"profile-packagx\"",
        ),
        18 => unique_equal_length_replace(
            &entry_source,
            b"\"caseId\":\"lift-po2-15\"",
            b"\"caseId\":\"lift-po2-16\"",
        ),
        _ => bail!("C2 execution does not select a catalogue mutation"),
    }
}

fn unique_equal_length_replace(
    source: &[u8],
    before: &[u8],
    replacement: &[u8],
) -> Result<B4ByteOperation> {
    ensure!(
        !before.is_empty() && before.len() == replacement.len() && before != replacement,
        "C2 fixed replacement is empty, length-changing, or a no-op"
    );
    let matches = source
        .windows(before.len())
        .enumerate()
        .filter_map(|(index, window)| (window == before).then_some(index))
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "C2 fixed replacement witness is absent or ambiguous"
    );
    Ok(B4ByteOperation::Replace {
        before_hex: hex::encode(before),
        replacement_hex: hex::encode(replacement),
        offset: u64::try_from(matches[0])?,
    })
}

pub(crate) fn proof_subject_from_raw_seal(raw_seal: &[u8]) -> Result<Vec<u8>> {
    let chunks = split_raw_seal(raw_seal)?;
    let elements = chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| {
            B4SequenceSubjectElement::from_bytes(format!("chunk-{index:02}"), chunk)
        })
        .collect::<Result<Vec<_>>>()?;
    Eip0045B4SequenceSubjectV1::new(B4SequenceTarget::ProofChunks, elements)?.to_canonical_jcs()
}

fn parsed_proof_subject(source: &[u8]) -> Result<Eip0045B4SequenceSubjectV1> {
    let subject = Eip0045B4SequenceSubjectV1::from_canonical_jcs(source)?;
    ensure!(
        subject.target == B4SequenceTarget::ProofChunks,
        "C2 detached sequence is not a proof-chunk subject"
    );
    Ok(subject)
}

pub(crate) fn split_raw_seal(raw_seal: &[u8]) -> Result<Vec<Vec<u8>>> {
    ensure!(
        raw_seal.len() == PROOF_BYTES,
        "C2 canonical raw seal has the wrong exact length"
    );
    split_at_lengths(raw_seal, &PROOF_CHUNK_LENGTHS)
}

fn split_length_mutated_raw_seal(raw_seal: &[u8]) -> Result<Vec<Vec<u8>>> {
    let fixed_prefix = PROOF_CHUNK_LENGTHS[..3].iter().sum::<usize>();
    ensure!(
        raw_seal.len() >= fixed_prefix,
        "C2 length-mutated raw seal is shorter than the first three chunks"
    );
    let lengths = [
        PROOF_CHUNK_LENGTHS[0],
        PROOF_CHUNK_LENGTHS[1],
        PROOF_CHUNK_LENGTHS[2],
        raw_seal.len() - fixed_prefix,
    ];
    split_at_lengths(raw_seal, &lengths)
}

fn split_at_lengths(source: &[u8], lengths: &[usize]) -> Result<Vec<Vec<u8>>> {
    let mut offset = 0_usize;
    let mut chunks = Vec::with_capacity(lengths.len());
    for length in lengths {
        let end = offset
            .checked_add(*length)
            .context("C2 chunk boundary overflows usize")?;
        let chunk = source
            .get(offset..end)
            .context("C2 chunk boundary exceeds its source")?;
        chunks.push(chunk.to_vec());
        offset = end;
    }
    ensure!(offset == source.len(), "C2 chunking does not consume EOF");
    Ok(chunks)
}

pub(crate) fn encode_opcode_subject(
    chunks: &[Vec<u8>],
    application_payload: &[u8],
    program_id: &[u8],
    profile_id: &[u8],
) -> Result<Vec<u8>> {
    let proof_vector = encode_proof_vector(chunks)?;
    encode_subject_envelope(
        &[&proof_vector, application_payload, program_id, profile_id],
        B4SubjectEnvelopeContract::new(B4SubjectEnvelopeKind::OpcodeInputs, &OPCODE_PART_BOUNDS),
    )
    .map_err(Into::into)
}

pub(crate) fn encode_proof_vector(chunks: &[Vec<u8>]) -> Result<Vec<u8>> {
    ensure!(
        (3..=5).contains(&chunks.len()),
        "C2 proof-vector chunk count is outside the framing grammar"
    );
    let cumulative = chunks.iter().try_fold(0_usize, |total, chunk| {
        ensure!(
            chunk.len() <= 65_536,
            "C2 proof-vector chunk exceeds the framing bound"
        );
        total
            .checked_add(chunk.len())
            .context("C2 proof-vector payload length overflows")
    })?;
    ensure!(
        cumulative <= PROOF_BYTES + 4,
        "C2 proof-vector payload exceeds its framing bound"
    );
    let mut encoded = Vec::with_capacity(2 + chunks.len() * 4 + cumulative);
    encoded.extend_from_slice(&u16::try_from(chunks.len())?.to_le_bytes());
    for chunk in chunks {
        encoded.extend_from_slice(&u32::try_from(chunk.len())?.to_le_bytes());
        encoded.extend_from_slice(chunk);
    }
    Ok(encoded)
}

/// Producer-side borrowed decode of the four positional opcode inputs.
///
/// This is deliberately independent of the validator's consumer decoder.
#[derive(Clone, Debug)]
pub(crate) struct B4ProducerOpcodeInputsV1<'a> {
    proof_chunks: Vec<&'a [u8]>,
    application_payload: &'a [u8],
    program_id: &'a [u8],
    profile_id: &'a [u8],
}

#[allow(
    dead_code,
    reason = "the independent final adapter is consumed by the next raw-producer task"
)]
impl<'a> B4ProducerOpcodeInputsV1<'a> {
    /// Ordered proof chunks decoded from positional part zero.
    pub(crate) fn proof_chunks(&self) -> &[&'a [u8]] {
        &self.proof_chunks
    }

    /// Positional application payload.
    pub(crate) const fn application_payload(&self) -> &'a [u8] {
        self.application_payload
    }

    /// Positional guest program ID.
    pub(crate) const fn program_id(&self) -> &'a [u8] {
        self.program_id
    }

    /// Positional verifier profile ID.
    pub(crate) const fn profile_id(&self) -> &'a [u8] {
        self.profile_id
    }
}

/// Decode the exact four-part producer envelope and its nested proof vector.
///
/// # Errors
///
/// Returns an error for outer-envelope shape/order bounds, proof-vector count
/// or length violations, truncation, arithmetic overflow, or any trailing
/// byte at either framing layer.
#[allow(
    dead_code,
    reason = "the independent final adapter is consumed by the next raw-producer task"
)]
pub(crate) fn decode_producer_opcode_subject(
    subject: &[u8],
) -> Result<B4ProducerOpcodeInputsV1<'_>> {
    ensure!(
        subject.len() >= PRODUCER_OPCODE_ENVELOPE_HEADER_BYTES,
        "producer opcode-input envelope header is truncated"
    );
    ensure!(
        subject.get(..PRODUCER_OPCODE_ENVELOPE_MAGIC.len())
            == Some(PRODUCER_OPCODE_ENVELOPE_MAGIC.as_slice()),
        "producer opcode-input envelope magic is invalid"
    );
    ensure!(
        subject[PRODUCER_OPCODE_ENVELOPE_MAGIC.len()] == PRODUCER_OPCODE_ENVELOPE_VERSION,
        "producer opcode-input envelope version is invalid"
    );
    ensure!(
        subject[PRODUCER_OPCODE_ENVELOPE_MAGIC.len() + 1] == PRODUCER_OPCODE_ENVELOPE_KIND,
        "producer opcode-input envelope kind is not OpcodeInputs"
    );
    let count_start = PRODUCER_OPCODE_ENVELOPE_MAGIC.len() + 2;
    let count_end = count_start
        .checked_add(2)
        .context("producer opcode-input part-count offset overflows")?;
    let part_count = usize::from(u16::from_le_bytes(
        subject
            .get(count_start..count_end)
            .context("producer opcode-input part count is truncated")?
            .try_into()
            .context("producer opcode-input part count has the wrong width")?,
    ));
    ensure!(
        part_count == PRODUCER_OPCODE_ENVELOPE_PART_COUNT,
        "producer opcode-input envelope does not have exactly four ordered parts"
    );

    let mut cursor = count_end;
    let mut parts: [&[u8]; PRODUCER_OPCODE_ENVELOPE_PART_COUNT] =
        [&[]; PRODUCER_OPCODE_ENVELOPE_PART_COUNT];
    for (index, (minimum, maximum)) in PRODUCER_OPCODE_PART_LENGTH_BOUNDS.into_iter().enumerate() {
        let length_end = cursor
            .checked_add(4)
            .context("producer opcode-input part-length offset overflows")?;
        let length = usize::try_from(u32::from_le_bytes(
            subject
                .get(cursor..length_end)
                .with_context(|| format!("producer opcode-input part {index} length is truncated"))?
                .try_into()
                .with_context(|| {
                    format!("producer opcode-input part {index} length has the wrong width")
                })?,
        ))
        .context("producer opcode-input part length exceeds usize")?;
        ensure!(
            (minimum..=maximum).contains(&length),
            "producer opcode-input part {index} length is outside its exact bound"
        );
        cursor = length_end;
        let part_end = cursor
            .checked_add(length)
            .context("producer opcode-input part offset overflows")?;
        parts[index] = subject
            .get(cursor..part_end)
            .with_context(|| format!("producer opcode-input part {index} is truncated"))?;
        cursor = part_end;
    }
    ensure!(
        cursor == subject.len(),
        "producer opcode-input envelope did not consume exact EOF"
    );
    let proof_chunks = decode_producer_proof_vector(parts[0])?;
    Ok(B4ProducerOpcodeInputsV1 {
        proof_chunks,
        application_payload: parts[1],
        program_id: parts[2],
        profile_id: parts[3],
    })
}

/// Independently prove that an encoded opcode subject contains exactly the
/// expected proof chunks and unchanged positional fields.
///
/// # Errors
///
/// Returns an error for any framing failure, count/length/EOF failure, part
/// reordering, changed chunk, or changed payload/program/profile byte.
#[allow(
    dead_code,
    reason = "the independent final adapter is consumed by the next raw-producer task"
)]
pub(crate) fn verify_producer_opcode_subject_projection(
    subject: &[u8],
    expected_chunks: &[Vec<u8>],
    expected_application_payload: &[u8],
    expected_program_id: &[u8],
    expected_profile_id: &[u8],
) -> Result<()> {
    let decoded = decode_producer_opcode_subject(subject)?;
    ensure!(
        decoded.proof_chunks.len() == expected_chunks.len(),
        "producer opcode proof-vector count differs from the expected projection"
    );
    for (index, (actual, expected)) in decoded.proof_chunks.iter().zip(expected_chunks).enumerate()
    {
        ensure!(
            *actual == expected.as_slice(),
            "producer opcode proof chunk {index} differs from the expected projection"
        );
    }
    ensure!(
        decoded.application_payload == expected_application_payload,
        "producer opcode application payload differs from the unchanged source field"
    );
    ensure!(
        decoded.program_id == expected_program_id,
        "producer opcode program ID differs from the unchanged source field"
    );
    ensure!(
        decoded.profile_id == expected_profile_id,
        "producer opcode profile ID differs from the unchanged source field"
    );
    Ok(())
}

fn decode_producer_proof_vector(source: &[u8]) -> Result<Vec<&[u8]>> {
    let count_bytes = source
        .get(..2)
        .context("producer proof vector has a truncated chunk count")?;
    let count = usize::from(u16::from_le_bytes(
        count_bytes
            .try_into()
            .context("producer proof-vector count has the wrong width")?,
    ));
    ensure!(
        (3..=5).contains(&count),
        "producer proof-vector chunk count is outside the framing grammar"
    );
    let mut chunks = Vec::with_capacity(count);
    let mut cursor = 2_usize;
    let mut cumulative = 0_usize;
    for index in 0..count {
        let length_end = cursor
            .checked_add(4)
            .context("producer proof-vector length offset overflows")?;
        let length = usize::try_from(u32::from_le_bytes(
            source
                .get(cursor..length_end)
                .with_context(|| {
                    format!("producer proof-vector chunk {index} length is truncated")
                })?
                .try_into()
                .with_context(|| {
                    format!("producer proof-vector chunk {index} length has the wrong width")
                })?,
        ))
        .context("producer proof-vector chunk length exceeds usize")?;
        ensure!(
            length <= 65_536,
            "producer proof-vector chunk {index} exceeds the framing bound"
        );
        cumulative = cumulative
            .checked_add(length)
            .context("producer proof-vector cumulative payload overflows")?;
        ensure!(
            cumulative <= PROOF_BYTES + 4,
            "producer proof-vector cumulative payload exceeds the framing bound"
        );
        cursor = length_end;
        let chunk_end = cursor
            .checked_add(length)
            .context("producer proof-vector chunk offset overflows")?;
        let chunk = source
            .get(cursor..chunk_end)
            .with_context(|| format!("producer proof-vector chunk {index} is truncated"))?;
        chunks.push(chunk);
        cursor = chunk_end;
    }
    ensure!(
        cursor == source.len(),
        "producer proof-vector decoder did not consume exact EOF"
    );
    Ok(chunks)
}

fn authenticated_source<'a>(
    top_level: &'a B4AuthenticatedMaterializationTopLevelV1,
    path: &str,
) -> Result<&'a [u8]> {
    top_level
        .source_artifacts
        .get(path)
        .map(Vec::as_slice)
        .with_context(|| format!("C2 authenticated source is absent: {path}"))
}

fn unique_positive_artifact(
    positive: &crate::b4::B4PositiveCase,
    role: B4PositiveArtifactRole,
) -> Result<&crate::b4::B4PositiveArtifact> {
    let mut matches = positive
        .artifacts
        .iter()
        .filter(|artifact| artifact.role == role);
    let artifact = matches
        .next()
        .with_context(|| format!("C2 positive case lacks {role:?}"))?;
    ensure!(
        matches.next().is_none(),
        "C2 positive case duplicates {role:?}"
    );
    Ok(artifact)
}

fn sha256_hex(source: &[u8]) -> String {
    hex::encode(Sha256::digest(source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{b4_plan::Eip0045B4NegativePlanV1, b4_subject_envelope::decode_subject_envelope};

    fn encode_raw_opcode_envelope(parts: &[&[u8]]) -> Vec<u8> {
        let mut encoded = b"EIP45B4S\x01\x01".to_vec();
        encoded.extend_from_slice(&u16::try_from(parts.len()).unwrap().to_le_bytes());
        for part in parts {
            encoded.extend_from_slice(&u32::try_from(part.len()).unwrap().to_le_bytes());
            encoded.extend_from_slice(part);
        }
        encoded
    }

    fn planned() -> Vec<B4NegativePlanExecutionV1> {
        Eip0045B4NegativePlanV1::canonical()
            .unwrap()
            .groups
            .into_iter()
            .flat_map(|group| group.executions)
            .collect()
    }

    fn source_fixture() -> C2Sources<'static> {
        static MANIFEST: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin");
        let raw_seal = Box::leak(vec![0x5a; PROOF_BYTES].into_boxed_slice());
        let proof_subject = proof_subject_from_raw_seal(raw_seal).unwrap();
        let preflight_payload = vec![0_u8; MAX_APPLICATION_PAYLOAD_BYTES];
        let program_id = [0x44; 32];
        let manifest = StarkProfileManifestV1::decode(MANIFEST).unwrap();
        let profile_id = manifest.profile_id().unwrap();
        let opcode_base = encode_opcode_subject(
            &split_raw_seal(raw_seal).unwrap(),
            &preflight_payload,
            &program_id,
            &profile_id,
        )
        .unwrap();
        C2Sources {
            manifest: MANIFEST,
            raw_seal,
            subject_catalog: b"{}",
            proof_subject,
            preflight_payload,
            program_id,
            profile_id,
            opcode_base,
        }
    }

    #[test]
    fn exact_twenty_two_index_and_plan_contract_is_closed() {
        let plan = planned();
        let actual = (0..254)
            .filter(|index| is_c2_index(*index))
            .collect::<Vec<_>>();
        let expected = C2_EXECUTION_IDS
            .iter()
            .map(|(index, _)| *index)
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 22);
        for index in actual {
            validate_planned_row(index, &plan[index]).unwrap();
        }
    }

    #[test]
    fn selector_partitions_have_one_exact_base_each() {
        let sources = source_fixture();
        for indices in [
            &[7, 8, 9, 10, 19][..],
            &[14, 15, 16, 17, 18][..],
            &[20, 21, 22, 23, 24, 25, 26, 27, 28, 30, 31, 32][..],
        ] {
            let first = sha256_hex(sources.base_for(indices[0]).unwrap());
            for &index in indices {
                assert_eq!(sha256_hex(sources.base_for(index).unwrap()), first);
            }
        }
        assert_ne!(
            sha256_hex(sources.base_for(7).unwrap()),
            sha256_hex(sources.base_for(20).unwrap())
        );
        assert_ne!(
            sha256_hex(sources.base_for(7).unwrap()),
            sha256_hex(sources.base_for(14).unwrap())
        );
        assert_ne!(
            sha256_hex(sources.base_for(14).unwrap()),
            sha256_hex(sources.base_for(20).unwrap())
        );
    }

    #[test]
    fn opcode_and_proof_recipes_have_exact_isolated_shapes() {
        let sources = source_fixture();
        let decoded_base = decode_subject_envelope(
            &sources.opcode_base,
            B4SubjectEnvelopeContract::new(
                B4SubjectEnvelopeKind::OpcodeInputs,
                &OPCODE_PART_BOUNDS,
            ),
        )
        .unwrap();
        assert_eq!(decoded_base.parts()[1].len(), MAX_APPLICATION_PAYLOAD_BYTES);
        assert!(decoded_base.parts()[1].iter().all(|byte| *byte == 0));
        for index in [
            7, 8, 9, 10, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 30, 31, 32,
        ] {
            let materialization = derive_materialization(index, &sources).unwrap();
            let replayed = replay_materialization(index, &sources, &materialization).unwrap();
            assert_ne!(replayed.raw_output, sources.base_for(index).unwrap());
            assert!(!replayed.final_subject.is_empty());
        }

        let payload_recipe = derive_materialization(19, &sources).unwrap();
        let B4NegativeMaterialization::Mutation {
            mutation:
                B4NegativeMutation::ByteEdit {
                    edit:
                        B4ByteOperation::Insert {
                            inserted_hex,
                            offset,
                        },
                    target: B4ByteTarget::ApplicationPayload,
                },
        } = &payload_recipe
        else {
            panic!("row 19 did not derive the exact payload insertion");
        };
        assert_eq!(inserted_hex, "00");
        assert_eq!(
            *offset,
            u64::try_from(MAX_APPLICATION_PAYLOAD_BYTES).unwrap()
        );
        let payload = replay_materialization(19, &sources, &payload_recipe).unwrap();
        assert_eq!(payload.raw_output.len(), MAX_APPLICATION_PAYLOAD_BYTES + 1);
        let decoded_payload = decode_subject_envelope(
            &payload.final_subject,
            B4SubjectEnvelopeContract::new(
                B4SubjectEnvelopeKind::OpcodeInputs,
                &OPCODE_PART_BOUNDS,
            ),
        )
        .unwrap();
        assert_eq!(
            decoded_payload.parts()[1].len(),
            MAX_APPLICATION_PAYLOAD_BYTES + 1
        );
        assert!(payload.final_subject.len() <= 262_144);

        let short =
            replay_materialization(30, &sources, &derive_materialization(30, &sources).unwrap())
                .unwrap();
        let long_byte =
            replay_materialization(31, &sources, &derive_materialization(31, &sources).unwrap())
                .unwrap();
        let long_word =
            replay_materialization(32, &sources, &derive_materialization(32, &sources).unwrap())
                .unwrap();
        assert_eq!(short.raw_output.len(), PROOF_BYTES - 1);
        assert_eq!(long_byte.raw_output.len(), PROOF_BYTES + 1);
        assert_eq!(long_word.raw_output.len(), PROOF_BYTES + 4);
    }

    #[test]
    fn proof_recipe_cannot_be_replayed_against_changed_base_bytes() {
        let sources = source_fixture();
        let recipe = derive_materialization(23, &sources).unwrap();
        let expected = replay_materialization(23, &sources, &recipe).unwrap();
        let mut changed_raw = sources.raw_seal.to_vec();
        changed_raw[PROOF_CHUNK_LENGTHS[0] - 1] ^= 1;
        let changed_raw = Box::leak(changed_raw.into_boxed_slice());
        let mut changed = sources.clone();
        changed.raw_seal = changed_raw;
        changed.proof_subject = proof_subject_from_raw_seal(changed_raw).unwrap();
        let replayed = replay_materialization(23, &changed, &recipe).unwrap();
        assert_ne!(replayed.raw_output, expected.raw_output);
        assert_ne!(replayed.final_subject, expected.final_subject);
    }

    #[test]
    fn producer_opcode_decoder_proves_exact_part_order_and_unchanged_fields() {
        let chunks = split_raw_seal(&vec![0x5a; PROOF_BYTES]).unwrap();
        let payload = [0x11; 32];
        let program_id = [0x22; 32];
        let profile_id = [0x33; 32];
        let encoded = encode_opcode_subject(&chunks, &payload, &program_id, &profile_id).unwrap();

        let decoded = decode_producer_opcode_subject(&encoded).unwrap();
        assert_eq!(
            decoded
                .proof_chunks()
                .iter()
                .map(|chunk| chunk.len())
                .collect::<Vec<_>>(),
            PROOF_CHUNK_LENGTHS
        );
        assert_eq!(decoded.application_payload(), payload);
        assert_eq!(decoded.program_id(), program_id);
        assert_eq!(decoded.profile_id(), profile_id);
        verify_producer_opcode_subject_projection(
            &encoded,
            &chunks,
            &payload,
            &program_id,
            &profile_id,
        )
        .unwrap();

        let proof_vector = encode_proof_vector(&chunks).unwrap();
        let reordered = encode_subject_envelope(
            &[&proof_vector, &program_id, &payload, &profile_id],
            B4SubjectEnvelopeContract::new(
                B4SubjectEnvelopeKind::OpcodeInputs,
                &OPCODE_PART_BOUNDS,
            ),
        )
        .unwrap();
        assert!(decode_producer_opcode_subject(&reordered).is_ok());
        assert!(
            verify_producer_opcode_subject_projection(
                &reordered,
                &chunks,
                &payload,
                &program_id,
                &profile_id,
            )
            .is_err()
        );

        for changed_field in ["payload", "program", "profile"] {
            let mut changed_payload = payload;
            let mut changed_program = program_id;
            let mut changed_profile = profile_id;
            match changed_field {
                "payload" => changed_payload[0] ^= 1,
                "program" => changed_program[0] ^= 1,
                "profile" => changed_profile[0] ^= 1,
                _ => unreachable!(),
            }
            let changed = encode_opcode_subject(
                &chunks,
                &changed_payload,
                &changed_program,
                &changed_profile,
            )
            .unwrap();
            assert!(
                verify_producer_opcode_subject_projection(
                    &changed,
                    &chunks,
                    &payload,
                    &program_id,
                    &profile_id,
                )
                .is_err(),
                "accepted changed {changed_field}"
            );
        }

        let mut changed_chunks = chunks.clone();
        changed_chunks[0][0] ^= 1;
        let changed =
            encode_opcode_subject(&changed_chunks, &payload, &program_id, &profile_id).unwrap();
        assert!(
            verify_producer_opcode_subject_projection(
                &changed,
                &chunks,
                &payload,
                &program_id,
                &profile_id,
            )
            .is_err()
        );
    }

    #[test]
    fn producer_outer_decoder_is_mechanically_independent_from_the_shared_consumer_codec() {
        let source = include_str!("b4_c2_opcode_sequence.rs");
        let start = source
            .find("pub(crate) fn decode_producer_opcode_subject")
            .unwrap();
        let end = source[start..]
            .find("pub(crate) fn verify_producer_opcode_subject_projection")
            .map(|offset| start + offset)
            .unwrap();
        let producer_decoder = &source[start..end];
        assert!(
            !producer_decoder.contains("decode_subject_envelope"),
            "producer outer decode still delegates to the shared consumer codec"
        );
    }

    #[test]
    fn producer_outer_decoder_rejects_every_prefix_header_drift_part_bound_and_trailing_byte() {
        let chunks = vec![vec![1], vec![2], vec![3]];
        let proof_vector = encode_proof_vector(&chunks).unwrap();
        let payload = b"payload";
        let program_id = [0x22; 32];
        let profile_id = [0x33; 32];
        let canonical =
            encode_raw_opcode_envelope(&[&proof_vector, payload, &program_id, &profile_id]);
        assert!(decode_producer_opcode_subject(&canonical).is_ok());

        for cut in 0..canonical.len() {
            assert!(
                decode_producer_opcode_subject(&canonical[..cut]).is_err(),
                "accepted strict opcode-envelope prefix ending at byte {cut}"
            );
        }

        for index in 0..8 {
            let mut changed = canonical.clone();
            changed[index] ^= 1;
            assert!(
                decode_producer_opcode_subject(&changed).is_err(),
                "accepted magic drift at byte {index}"
            );
        }
        for (offset, value) in [(8, 2_u8), (9, 2), (9, 0xff)] {
            let mut changed = canonical.clone();
            changed[offset] = value;
            assert!(decode_producer_opcode_subject(&changed).is_err());
        }
        for count in [0_u16, 3, 5, u16::MAX] {
            let mut changed = canonical.clone();
            changed[10..12].copy_from_slice(&count.to_le_bytes());
            assert!(decode_producer_opcode_subject(&changed).is_err());
        }

        let valid_parts: [&[u8]; 4] = [&proof_vector, payload, &program_id, &profile_id];
        let bounds = [
            (OPCODE_PROOF_VECTOR_MIN_BYTES, OPCODE_PROOF_VECTOR_MAX_BYTES),
            (0, MAX_APPLICATION_PAYLOAD_BYTES + 1),
            (31, 33),
            (31, 33),
        ];
        for (part_index, (minimum, maximum)) in bounds.into_iter().enumerate() {
            let mut lengths = Vec::new();
            if minimum > 0 {
                lengths.push(minimum - 1);
            }
            lengths.push(maximum + 1);
            for length in lengths {
                let replacement = vec![0_u8; length];
                let mut parts = valid_parts;
                parts[part_index] = &replacement;
                let changed = encode_raw_opcode_envelope(&parts);
                assert!(
                    decode_producer_opcode_subject(&changed).is_err(),
                    "accepted part {part_index} length {length}"
                );
            }
        }

        let mut maximum_u32_length = canonical.clone();
        maximum_u32_length[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_producer_opcode_subject(&maximum_u32_length).is_err());

        let mut trailing = canonical;
        trailing.push(0);
        assert!(decode_producer_opcode_subject(&trailing).is_err());
    }

    #[test]
    fn producer_proof_vector_decoder_enforces_count_lengths_and_exact_eof() {
        let chunks = vec![vec![1, 2, 3], vec![], vec![4], vec![5, 6]];
        let encoded = encode_proof_vector(&chunks).unwrap();
        let decoded = decode_producer_proof_vector(&encoded).unwrap();
        assert_eq!(
            decoded,
            chunks.iter().map(Vec::as_slice).collect::<Vec<_>>()
        );

        let mut too_few = encoded.clone();
        too_few[..2].copy_from_slice(&2_u16.to_le_bytes());
        assert!(decode_producer_proof_vector(&too_few).is_err());

        let mut too_many = encoded.clone();
        too_many[..2].copy_from_slice(&5_u16.to_le_bytes());
        assert!(decode_producer_proof_vector(&too_many).is_err());

        let mut oversized_chunk = encoded.clone();
        oversized_chunk[2..6].copy_from_slice(&65_537_u32.to_le_bytes());
        assert!(decode_producer_proof_vector(&oversized_chunk).is_err());

        for cut in 0..encoded.len() {
            assert!(
                decode_producer_proof_vector(&encoded[..cut]).is_err(),
                "accepted strict proof-vector prefix ending at {cut}"
            );
        }

        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_producer_proof_vector(&trailing).is_err());
    }
}
