//! Closed C2 producers for the fifty profile-package negative rows.
//!
//! The producer consumes only profile bytes retained by the authenticated
//! materialization source map.  It derives each registry recipe, replays the
//! raw mutation, and independently reconstructs the exact subject framing
//! consumed by the selected validator surface.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail, ensure};

use crate::{
    b4::{
        B4ByteOperation, B4ByteTarget, B4NegativeCase, B4NegativeMaterialization,
        B4NegativeMutation, B4ProfileArtifact,
    },
    b4_materialization_set::{
        B4AuthenticatedMaterializationTopLevelV1, B4ClosedReconstructedExecutionV1,
        close_production_execution,
    },
    b4_mutation::{B4MaterializationReplayAdapterV1, reconstruct_byte_edit},
    b4_plan::{
        B4MaterializationDomain, B4NegativeExecutionSurface, B4NegativePlanExecutionV1,
        B4NegativePlanFixture,
    },
    b4_subject_envelope::{
        B4SubjectEnvelopeContract, B4SubjectEnvelopeKind, B4SubjectPartBounds,
        encode_subject_envelope,
    },
    constants::{DIGEST_BYTES, MANIFEST_BYTES, PROFILE_ID_PREIMAGE_BYTES},
    constants_artifact,
    profile_algorithm::{self, authenticate_profile_algorithm},
    profile_manifest::{ProfileArtifacts, StarkProfileManifestV1, validate_profile_package_v1},
};

const PROFILE_FIRST_INDEX: usize = 160;
const PROFILE_END_INDEX_EXCLUSIVE: usize = 210;

const CONTROL_TABLE_OFFSET: usize = 42;
const CONTROL_BYTES: usize = 34;
const CONTROL_ID_OFFSET: usize = 2;
const CONTROL_COUNT: usize = 10;
const ALGORITHM_REFERENCE_OFFSET: usize = 382;
const BINARY_REFERENCE_OFFSET: usize = 420;
const REFERENCE_BYTES: usize = 38;

const MANIFEST_PATH: &str = "profiles/risc0-v3-succinct/manifest.bin";
const ALGORITHM_PATH: &str = "profiles/risc0-v3-succinct/algorithm.txt";
const CONSTANTS_PATH: &str = "profiles/risc0-v3-succinct/constants.bin";
const PROFILE_ID_PATH: &str = "profiles/risc0-v3-succinct/profile-id.bin";
const PROFILE_ID_PREIMAGE_PATH: &str = "profiles/risc0-v3-succinct/profile-id-preimage.bin";

const MANIFEST_SELECTOR: &str = "risc0-v3-succinct-profile-manifest-v1";
const ALGORITHM_SELECTOR: &str = "risc0-v3-succinct-algorithm-artifact-v1";
const CONSTANTS_SELECTOR: &str = "risc0-v3-succinct-constants-artifact-v1";
const PACKAGE_SELECTOR: &str = "risc0-v3-succinct-package-v1";
const PREIMAGE_SELECTOR: &str = "risc0-v3-succinct-profile-id-preimage-v1";

const PROFILE_PACKAGE_PARTS: [B4SubjectPartBounds; 3] = [
    B4SubjectPartBounds::new(MANIFEST_BYTES, MANIFEST_BYTES),
    B4SubjectPartBounds::new(
        profile_algorithm::ALGORITHM_BYTES,
        profile_algorithm::ALGORITHM_BYTES,
    ),
    B4SubjectPartBounds::new(
        constants_artifact::ARTIFACT_BYTES,
        constants_artifact::ARTIFACT_BYTES,
    ),
];
const PROFILE_ID_PREIMAGE_PARTS: [B4SubjectPartBounds; 2] = [
    B4SubjectPartBounds::new(MANIFEST_BYTES, MANIFEST_BYTES),
    B4SubjectPartBounds::new(PROFILE_ID_PREIMAGE_BYTES, PROFILE_ID_PREIMAGE_BYTES),
];

const PROFILE_PACKAGE_SUBJECT_BYTES: usize = 12
    + 3 * 4
    + MANIFEST_BYTES
    + profile_algorithm::ALGORITHM_BYTES
    + constants_artifact::ARTIFACT_BYTES;
const PROFILE_ID_PREIMAGE_SUBJECT_BYTES: usize =
    12 + 2 * 4 + MANIFEST_BYTES + PROFILE_ID_PREIMAGE_BYTES;

const TERMINAL_NAMES: [&str; CONTROL_COUNT] = [
    "lift-po2-15",
    "lift-po2-16",
    "lift-po2-17",
    "lift-po2-18",
    "lift-po2-19",
    "lift-po2-20",
    "lift-po2-21",
    "lift-po2-22",
    "terminal-join",
    "terminal-resolve",
];

/// Reconstruct one of the exact fifty profile-focused C2 executions.
///
/// `None` is returned outside the closed zero-based range `160..210`.
pub(crate) fn reconstruct_profile_execution(
    execution_index: usize,
    planned: &B4NegativePlanExecutionV1,
    top_level: &B4AuthenticatedMaterializationTopLevelV1,
) -> Result<Option<B4ClosedReconstructedExecutionV1>> {
    if !(PROFILE_FIRST_INDEX..PROFILE_END_INDEX_EXCLUSIVE).contains(&execution_index) {
        return Ok(None);
    }

    let sources = authenticate_profile_source_map(&top_level.source_artifacts)?;
    let materialized = materialize_profile_row(execution_index, sources)?;
    materialized.validate_planned(planned)?;

    let registry_row = B4NegativeCase {
        execution_id: materialized.execution_id.clone(),
        base_selector_id: materialized.base_selector_id.to_owned(),
        materialization_domain: B4MaterializationDomain::ArtifactValidator,
        materialization: B4NegativeMaterialization::Mutation {
            mutation: B4NegativeMutation::ByteEdit {
                edit: materialized.edit.clone(),
                target: materialized.target,
            },
        },
    };
    let raw_adapter = ProfileRawReplayAdapter {
        base_selector_id: materialized.base_selector_id,
        base: materialized.base,
        output: &materialized.raw_output,
        target: materialized.target,
        edit: &materialized.edit,
    };
    let final_adapter = ProfileFinalReplayAdapter {
        raw: raw_adapter,
        framing: materialized.framing,
        sources,
        output: &materialized.subject,
    };

    Ok(Some(close_production_execution(
        execution_index,
        planned,
        &top_level.negative_plan,
        registry_row,
        &raw_adapter,
        &final_adapter,
        materialized.subject.clone(),
        materialized.contexts.clone(),
    )?))
}

#[derive(Clone, Copy, Debug)]
struct AuthenticatedProfileSources<'a> {
    manifest: &'a [u8],
    algorithm: &'a [u8],
    constants: &'a [u8],
    profile_id: &'a [u8],
    profile_id_preimage: &'a [u8],
}

fn authenticate_profile_source_map(
    source_artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<AuthenticatedProfileSources<'_>> {
    let sources = AuthenticatedProfileSources {
        manifest: required_source(source_artifacts, MANIFEST_PATH)?,
        algorithm: required_source(source_artifacts, ALGORITHM_PATH)?,
        constants: required_source(source_artifacts, CONSTANTS_PATH)?,
        profile_id: required_source(source_artifacts, PROFILE_ID_PATH)?,
        profile_id_preimage: required_source(source_artifacts, PROFILE_ID_PREIMAGE_PATH)?,
    };

    let manifest = StarkProfileManifestV1::decode(sources.manifest)
        .context("C2 cannot decode the authenticated profile manifest")?;
    ensure!(
        manifest.encode()?.as_slice() == sources.manifest,
        "C2 profile manifest changed under decode/re-encode"
    );
    manifest
        .validate_initial_profile_target()
        .context("C2 profile manifest differs from the initial target")?;
    let authenticated_algorithm = authenticate_profile_algorithm(sources.algorithm, &manifest)
        .context("C2 profile algorithm authentication failed")?;
    ensure!(
        authenticated_algorithm.bytes() == sources.algorithm
            && hex::encode(authenticated_algorithm.sha256()) == profile_algorithm::ALGORITHM_SHA256
            && authenticated_algorithm.artifact_reference() == manifest.algorithm_artifact()
            && hex::encode(authenticated_algorithm.preimage_sha256())
                == profile_algorithm::ALGORITHM_PREIMAGE_SHA256,
        "C2 profile algorithm authority projection is internally inconsistent"
    );
    constants_artifact::verify_canonical(sources.constants)
        .context("C2 profile constants authentication failed")?;

    let derived_profile_id = manifest.profile_id()?;
    ensure!(
        sources.profile_id == derived_profile_id.as_slice(),
        "C2 profile-id source differs from the authenticated manifest"
    );
    validate_profile_package_v1(
        sources.manifest,
        ProfileArtifacts {
            algorithm: sources.algorithm,
            binary_data: sources.constants,
        },
        &derived_profile_id,
    )
    .context("C2 authenticated profile package is invalid")?;

    let derived_preimage = manifest.profile_id_preimage()?;
    ensure!(
        sources.profile_id_preimage == derived_preimage.as_slice(),
        "C2 profile-ID preimage source differs from the authenticated manifest"
    );
    Ok(sources)
}

fn required_source<'a>(
    source_artifacts: &'a BTreeMap<String, Vec<u8>>,
    path: &str,
) -> Result<&'a [u8]> {
    source_artifacts
        .get(path)
        .map(Vec::as_slice)
        .with_context(|| format!("C2 authenticated source map lacks {path}"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProfileBase {
    Manifest,
    Algorithm,
    Constants,
    ProfileId,
    ProfileIdPreimage,
}

impl ProfileBase {
    fn bytes(self, sources: AuthenticatedProfileSources<'_>) -> &[u8] {
        match self {
            Self::Manifest => sources.manifest,
            Self::Algorithm => sources.algorithm,
            Self::Constants => sources.constants,
            Self::ProfileId => sources.profile_id,
            Self::ProfileIdPreimage => sources.profile_id_preimage,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProfileFraming {
    Raw,
    PackageManifest,
    PackageAlgorithm,
    PackageConstants,
    ProfileIdPreimage,
}

#[derive(Debug)]
struct ProfileRowMaterialization<'a> {
    execution_id: String,
    base_selector_id: &'static str,
    execution_surface: B4NegativeExecutionSurface,
    base: &'a [u8],
    target: B4ByteTarget,
    edit: B4ByteOperation,
    raw_output: Vec<u8>,
    framing: ProfileFraming,
    subject: Vec<u8>,
    contexts: Vec<Vec<u8>>,
}

impl ProfileRowMaterialization<'_> {
    fn validate_planned(&self, planned: &B4NegativePlanExecutionV1) -> Result<()> {
        ensure!(
            planned.execution_id == self.execution_id
                && planned.base_selector_id == self.base_selector_id
                && planned.fixture == B4NegativePlanFixture::Risc0V3SuccinctPackageV1
                && planned.materialization_domain == B4MaterializationDomain::ArtifactValidator
                && planned.execution_surface == self.execution_surface
                && planned.parser_truncation_words.is_none(),
            "C2 profile recipe differs from the exact canonical-plan row"
        );
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct ProfileRecipe {
    execution_id: String,
    base_selector_id: &'static str,
    execution_surface: B4NegativeExecutionSurface,
    base: ProfileBase,
    target: B4ByteTarget,
    edit: B4ByteOperation,
    framing: ProfileFraming,
    activated_contexts: bool,
}

fn materialize_profile_row(
    execution_index: usize,
    sources: AuthenticatedProfileSources<'_>,
) -> Result<ProfileRowMaterialization<'_>> {
    let recipe = profile_recipe(execution_index, sources)?
        .context("C2 profile index is outside its range")?;
    let base = recipe.base.bytes(sources);
    let raw_output = reconstruct_byte_edit(base, &recipe.edit)
        .context("C2 profile recipe does not replay against its authenticated base")?;
    let subject = frame_profile_subject(recipe.framing, &raw_output, sources)?;
    let contexts = if recipe.activated_contexts {
        vec![
            sources.manifest.to_vec(),
            sources.algorithm.to_vec(),
            sources.constants.to_vec(),
        ]
    } else {
        Vec::new()
    };
    Ok(ProfileRowMaterialization {
        execution_id: recipe.execution_id,
        base_selector_id: recipe.base_selector_id,
        execution_surface: recipe.execution_surface,
        base,
        target: recipe.target,
        edit: recipe.edit,
        raw_output,
        framing: recipe.framing,
        subject,
        contexts,
    })
}

#[allow(clippy::too_many_lines)] // Exact 50-row plan table is clearer kept in canonical order.
fn profile_recipe(
    execution_index: usize,
    sources: AuthenticatedProfileSources<'_>,
) -> Result<Option<ProfileRecipe>> {
    if !(PROFILE_FIRST_INDEX..PROFILE_END_INDEX_EXCLUSIVE).contains(&execution_index) {
        return Ok(None);
    }
    let manifest = sources.manifest;
    let manifest_target = B4ByteTarget::ProfileManifest;

    let recipe = match execution_index {
        160 => recipe(
            "profile-manifest-short--manifest-unexpected-eof",
            MANIFEST_SELECTOR,
            B4NegativeExecutionSurface::ProfileManifestCodec,
            ProfileBase::Manifest,
            manifest_target,
            B4ByteOperation::Truncate {
                before_hex: hex::encode(&manifest[MANIFEST_BYTES - 1..]),
                new_length: u64::try_from(MANIFEST_BYTES - 1)?,
                original_length: u64::try_from(MANIFEST_BYTES)?,
            },
            ProfileFraming::Raw,
        ),
        161 => recipe(
            "profile-manifest-trailing-byte--manifest-trailing-byte",
            MANIFEST_SELECTOR,
            B4NegativeExecutionSurface::ProfileManifestCodec,
            ProfileBase::Manifest,
            manifest_target,
            B4ByteOperation::Insert {
                inserted_hex: "00".to_owned(),
                offset: u64::try_from(MANIFEST_BYTES)?,
            },
            ProfileFraming::Raw,
        ),
        162 => manifest_xor_recipe(
            "profile-manifest-version--format-version",
            B4NegativeExecutionSurface::ProfileManifestCodec,
            0,
            manifest,
        )?,
        163 => manifest_xor_recipe(
            "profile-manifest-exact-proof-bytes--exact-proof-bytes",
            B4NegativeExecutionSurface::InitialProfileTarget,
            1,
            manifest,
        )?,
        164 => manifest_xor_recipe(
            "profile-manifest-maximum-payload--maximum-payload",
            B4NegativeExecutionSurface::InitialProfileTarget,
            5,
            manifest,
        )?,
        165 => manifest_xor_recipe(
            "profile-manifest-outer-po2--outer-po2",
            B4NegativeExecutionSurface::InitialProfileTarget,
            9,
            manifest,
        )?,
        166 => manifest_xor_recipe(
            "profile-manifest-inner-control-root--inner-control-root",
            B4NegativeExecutionSurface::InitialProfileTarget,
            10,
            manifest,
        )?,
        167..=196 => terminal_recipe(execution_index, manifest)?,
        197 => recipe(
            "profile-terminal-control-id-duplicate--first-two-control-ids",
            MANIFEST_SELECTOR,
            B4NegativeExecutionSurface::ProfileManifestCodec,
            ProfileBase::Manifest,
            manifest_target,
            replace_operation(
                manifest,
                CONTROL_TABLE_OFFSET + CONTROL_BYTES + CONTROL_ID_OFFSET,
                &manifest[CONTROL_TABLE_OFFSET + CONTROL_ID_OFFSET
                    ..CONTROL_TABLE_OFFSET + CONTROL_ID_OFFSET + DIGEST_BYTES],
            )?,
            ProfileFraming::Raw,
        ),
        198 => {
            let mut replacement = Vec::with_capacity(2 * CONTROL_BYTES);
            replacement.extend_from_slice(
                &manifest[CONTROL_TABLE_OFFSET + CONTROL_BYTES
                    ..CONTROL_TABLE_OFFSET + 2 * CONTROL_BYTES],
            );
            replacement.extend_from_slice(
                &manifest[CONTROL_TABLE_OFFSET..CONTROL_TABLE_OFFSET + CONTROL_BYTES],
            );
            recipe(
                "profile-terminal-controls-reordered--first-two-controls",
                MANIFEST_SELECTOR,
                B4NegativeExecutionSurface::ProfileManifestCodec,
                ProfileBase::Manifest,
                manifest_target,
                replace_operation(manifest, CONTROL_TABLE_OFFSET, &replacement)?,
                ProfileFraming::Raw,
            )
        }
        199 => recipe(
            "profile-artifact-ref-field-sweep--algorithm-kind",
            MANIFEST_SELECTOR,
            B4NegativeExecutionSurface::ProfileManifestCodec,
            ProfileBase::Manifest,
            manifest_target,
            replace_operation(manifest, ALGORITHM_REFERENCE_OFFSET, &2_u16.to_le_bytes())?,
            ProfileFraming::Raw,
        ),
        200 => artifact_reference_length_recipe(
            "profile-artifact-ref-field-sweep--algorithm-length",
            ALGORITHM_REFERENCE_OFFSET,
            ProfileFraming::PackageManifest,
            manifest,
        )?,
        201 => artifact_reference_digest_recipe(
            "profile-artifact-ref-field-sweep--algorithm-digest",
            ALGORITHM_REFERENCE_OFFSET,
            ProfileFraming::PackageManifest,
            manifest,
        )?,
        202 => recipe(
            "profile-artifact-ref-field-sweep--binary-data-kind",
            MANIFEST_SELECTOR,
            B4NegativeExecutionSurface::ProfileManifestCodec,
            ProfileBase::Manifest,
            manifest_target,
            replace_operation(manifest, BINARY_REFERENCE_OFFSET, &1_u16.to_le_bytes())?,
            ProfileFraming::Raw,
        ),
        203 => artifact_reference_length_recipe(
            "profile-artifact-ref-field-sweep--binary-data-length",
            BINARY_REFERENCE_OFFSET,
            ProfileFraming::PackageManifest,
            manifest,
        )?,
        204 => artifact_reference_digest_recipe(
            "profile-artifact-ref-field-sweep--binary-data-digest",
            BINARY_REFERENCE_OFFSET,
            ProfileFraming::PackageManifest,
            manifest,
        )?,
        205 => {
            let mut replacement = Vec::with_capacity(2 * REFERENCE_BYTES);
            replacement.extend_from_slice(
                &manifest[BINARY_REFERENCE_OFFSET..BINARY_REFERENCE_OFFSET + REFERENCE_BYTES],
            );
            replacement.extend_from_slice(
                &manifest[ALGORITHM_REFERENCE_OFFSET..ALGORITHM_REFERENCE_OFFSET + REFERENCE_BYTES],
            );
            recipe(
                "profile-artifact-refs-reordered--algorithm-and-binary-data",
                MANIFEST_SELECTOR,
                B4NegativeExecutionSurface::ProfileManifestCodec,
                ProfileBase::Manifest,
                manifest_target,
                replace_operation(manifest, ALGORITHM_REFERENCE_OFFSET, &replacement)?,
                ProfileFraming::Raw,
            )
        }
        206 => recipe(
            "profile-artifact-bytes-sweep--algorithm",
            ALGORITHM_SELECTOR,
            B4NegativeExecutionSurface::ProfileArtifactEnvelope,
            ProfileBase::Algorithm,
            B4ByteTarget::ProfileArtifact {
                artifact: B4ProfileArtifact::Algorithm,
            },
            xor_operation(sources.algorithm, 0)?,
            ProfileFraming::PackageAlgorithm,
        ),
        207 => recipe(
            "profile-artifact-bytes-sweep--constants",
            CONSTANTS_SELECTOR,
            B4NegativeExecutionSurface::ProfileArtifactEnvelope,
            ProfileBase::Constants,
            B4ByteTarget::ProfileArtifact {
                artifact: B4ProfileArtifact::Constants,
            },
            xor_operation(sources.constants, 0)?,
            ProfileFraming::PackageConstants,
        ),
        208 => {
            let mut row = recipe(
                "profile-id-mismatch--profile-id",
                PACKAGE_SELECTOR,
                B4NegativeExecutionSurface::ActivatedProfilePackage,
                ProfileBase::ProfileId,
                B4ByteTarget::ProfileArtifact {
                    artifact: B4ProfileArtifact::ProfileId,
                },
                xor_operation(sources.profile_id, 0)?,
                ProfileFraming::Raw,
            );
            row.activated_contexts = true;
            row
        }
        209 => recipe(
            "profile-id-preimage-mismatch--profile-id-preimage",
            PREIMAGE_SELECTOR,
            B4NegativeExecutionSurface::ProfileIdPreimage,
            ProfileBase::ProfileIdPreimage,
            B4ByteTarget::ProfileArtifact {
                artifact: B4ProfileArtifact::ProfileIdPreimage,
            },
            xor_operation(sources.profile_id_preimage, PROFILE_ID_PREIMAGE_BYTES - 1)?,
            ProfileFraming::ProfileIdPreimage,
        ),
        _ => unreachable!("profile range was checked before recipe dispatch"),
    };
    Ok(Some(recipe))
}

fn recipe(
    execution_id: &str,
    base_selector_id: &'static str,
    execution_surface: B4NegativeExecutionSurface,
    base: ProfileBase,
    target: B4ByteTarget,
    edit: B4ByteOperation,
    framing: ProfileFraming,
) -> ProfileRecipe {
    ProfileRecipe {
        execution_id: execution_id.to_owned(),
        base_selector_id,
        execution_surface,
        base,
        target,
        edit,
        framing,
        activated_contexts: false,
    }
}

fn manifest_xor_recipe(
    execution_id: &str,
    execution_surface: B4NegativeExecutionSurface,
    offset: usize,
    manifest: &[u8],
) -> Result<ProfileRecipe> {
    Ok(recipe(
        execution_id,
        MANIFEST_SELECTOR,
        execution_surface,
        ProfileBase::Manifest,
        B4ByteTarget::ProfileManifest,
        xor_operation(manifest, offset)?,
        ProfileFraming::Raw,
    ))
}

fn terminal_recipe(execution_index: usize, manifest: &[u8]) -> Result<ProfileRecipe> {
    let relative = execution_index - 167;
    let control_index = relative / 3;
    let field = relative % 3;
    ensure!(
        control_index < CONTROL_COUNT,
        "C2 terminal recipe index exceeds the control table"
    );
    let control_offset = CONTROL_TABLE_OFFSET + control_index * CONTROL_BYTES;
    let (suffix, surface, edit) = match field {
        0 => (
            "kind",
            B4NegativeExecutionSurface::ProfileManifestCodec,
            replace_operation(manifest, control_offset, &[u8::MAX])?,
        ),
        1 => {
            let replacement = if control_index == 0 {
                manifest[CONTROL_TABLE_OFFSET + CONTROL_BYTES + 1]
            } else if control_index < 8 {
                manifest[CONTROL_TABLE_OFFSET + (control_index - 1) * CONTROL_BYTES + 1]
            } else {
                1
            };
            (
                "parameter",
                B4NegativeExecutionSurface::ProfileManifestCodec,
                replace_operation(manifest, control_offset + 1, &[replacement])?,
            )
        }
        2 => (
            "control-id",
            B4NegativeExecutionSurface::InitialProfileTarget,
            xor_operation(manifest, control_offset + CONTROL_ID_OFFSET)?,
        ),
        _ => unreachable!(),
    };
    Ok(recipe(
        &format!(
            "profile-terminal-field-sweep--{}-{suffix}",
            TERMINAL_NAMES[control_index]
        ),
        MANIFEST_SELECTOR,
        surface,
        ProfileBase::Manifest,
        B4ByteTarget::ProfileManifest,
        edit,
        ProfileFraming::Raw,
    ))
}

fn artifact_reference_length_recipe(
    execution_id: &str,
    reference_offset: usize,
    framing: ProfileFraming,
    manifest: &[u8],
) -> Result<ProfileRecipe> {
    let offset = reference_offset + 2;
    let current = u32::from_le_bytes(
        manifest[offset..offset + 4]
            .try_into()
            .context("C2 artifact length field is not four bytes")?,
    );
    let replacement = current
        .checked_add(1)
        .context("C2 artifact length mutation overflows u32")?
        .to_le_bytes();
    Ok(recipe(
        execution_id,
        MANIFEST_SELECTOR,
        B4NegativeExecutionSurface::ProfileArtifactEnvelope,
        ProfileBase::Manifest,
        B4ByteTarget::ProfileManifest,
        replace_operation(manifest, offset, &replacement)?,
        framing,
    ))
}

fn artifact_reference_digest_recipe(
    execution_id: &str,
    reference_offset: usize,
    framing: ProfileFraming,
    manifest: &[u8],
) -> Result<ProfileRecipe> {
    Ok(recipe(
        execution_id,
        MANIFEST_SELECTOR,
        B4NegativeExecutionSurface::ProfileArtifactEnvelope,
        ProfileBase::Manifest,
        B4ByteTarget::ProfileManifest,
        xor_operation(manifest, reference_offset + 6)?,
        framing,
    ))
}

fn xor_operation(base: &[u8], offset: usize) -> Result<B4ByteOperation> {
    let before = *base
        .get(offset)
        .context("C2 byte mutation offset is outside its authenticated base")?;
    replace_operation(base, offset, &[before ^ 1])
}

fn replace_operation(base: &[u8], offset: usize, replacement: &[u8]) -> Result<B4ByteOperation> {
    ensure!(!replacement.is_empty(), "C2 replacement must be nonempty");
    let end = offset
        .checked_add(replacement.len())
        .context("C2 replacement range overflows usize")?;
    let before = base
        .get(offset..end)
        .context("C2 replacement range is outside its authenticated base")?;
    ensure!(
        before != replacement,
        "C2 replacement must change the authenticated base"
    );
    Ok(B4ByteOperation::Replace {
        before_hex: hex::encode(before),
        replacement_hex: hex::encode(replacement),
        offset: u64::try_from(offset)?,
    })
}

fn frame_profile_subject(
    framing: ProfileFraming,
    raw_output: &[u8],
    sources: AuthenticatedProfileSources<'_>,
) -> Result<Vec<u8>> {
    match framing {
        ProfileFraming::Raw => Ok(raw_output.to_vec()),
        ProfileFraming::PackageManifest => {
            encode_profile_package(raw_output, sources.algorithm, sources.constants)
        }
        ProfileFraming::PackageAlgorithm => {
            encode_profile_package(sources.manifest, raw_output, sources.constants)
        }
        ProfileFraming::PackageConstants => {
            encode_profile_package(sources.manifest, sources.algorithm, raw_output)
        }
        ProfileFraming::ProfileIdPreimage => {
            let subject = encode_subject_envelope(
                &[sources.manifest, raw_output],
                B4SubjectEnvelopeContract::new(
                    B4SubjectEnvelopeKind::ProfileIdPreimageBundle,
                    &PROFILE_ID_PREIMAGE_PARTS,
                ),
            )?;
            ensure!(
                subject.len() == PROFILE_ID_PREIMAGE_SUBJECT_BYTES,
                "C2 profile-ID preimage subject has the wrong exact length"
            );
            Ok(subject)
        }
    }
}

fn encode_profile_package(manifest: &[u8], algorithm: &[u8], constants: &[u8]) -> Result<Vec<u8>> {
    let subject = encode_subject_envelope(
        &[manifest, algorithm, constants],
        B4SubjectEnvelopeContract::new(
            B4SubjectEnvelopeKind::ProfilePackage,
            &PROFILE_PACKAGE_PARTS,
        ),
    )?;
    ensure!(
        subject.len() == PROFILE_PACKAGE_SUBJECT_BYTES,
        "C2 profile-package subject has the wrong exact length"
    );
    Ok(subject)
}

#[derive(Clone, Copy, Debug)]
struct ProfileRawReplayAdapter<'a> {
    base_selector_id: &'static str,
    base: &'a [u8],
    output: &'a [u8],
    target: B4ByteTarget,
    edit: &'a B4ByteOperation,
}

impl B4MaterializationReplayAdapterV1 for ProfileRawReplayAdapter<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        B4MaterializationDomain::ArtifactValidator
    }

    fn base_bytes(&self) -> &[u8] {
        self.base
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
            base_selector_id == self.base_selector_id,
            "C2 profile replay selected a different base"
        );
        let B4NegativeMaterialization::Mutation {
            mutation: B4NegativeMutation::ByteEdit { edit, target },
        } = materialization
        else {
            bail!("C2 profile replay received a non-byte materialization recipe");
        };
        ensure!(
            target == &self.target && edit == self.edit,
            "C2 profile replay received a different exact recipe"
        );
        ensure!(
            reconstruct_byte_edit(self.base, edit)? == self.output,
            "C2 profile raw mutation differs from independent replay"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct ProfileFinalReplayAdapter<'a> {
    raw: ProfileRawReplayAdapter<'a>,
    framing: ProfileFraming,
    sources: AuthenticatedProfileSources<'a>,
    output: &'a [u8],
}

impl B4MaterializationReplayAdapterV1 for ProfileFinalReplayAdapter<'_> {
    fn materialization_domain(&self) -> B4MaterializationDomain {
        self.raw.materialization_domain()
    }

    fn base_bytes(&self) -> &[u8] {
        self.raw.base_bytes()
    }

    fn output_bytes(&self) -> &[u8] {
        self.output
    }

    fn replay_recipe(
        &self,
        base_selector_id: &str,
        materialization: &B4NegativeMaterialization,
    ) -> Result<()> {
        self.raw.replay_recipe(base_selector_id, materialization)?;
        ensure!(
            frame_profile_subject(self.framing, self.raw.output, self.sources)? == self.output,
            "C2 profile final subject differs from independent framing"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{b4_plan::Eip0045B4NegativePlanV1, b4_subject_envelope::decode_subject_envelope};

    const TEST_MANIFEST: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin");
    const TEST_ALGORITHM: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/algorithm.txt");
    const TEST_CONSTANTS: &[u8] = include_bytes!("../../profiles/risc0-v3-succinct/constants.bin");
    const TEST_PROFILE_ID: &[u8] =
        include_bytes!("../../profiles/risc0-v3-succinct/profile-id.bin");
    const TEST_PROFILE_ID_PREIMAGE: &[u8] =
        include_bytes!("../../profiles/risc0-v3-succinct/profile-id-preimage.bin");

    fn source_map() -> BTreeMap<String, Vec<u8>> {
        [
            (MANIFEST_PATH, TEST_MANIFEST),
            (ALGORITHM_PATH, TEST_ALGORITHM),
            (CONSTANTS_PATH, TEST_CONSTANTS),
            (PROFILE_ID_PATH, TEST_PROFILE_ID),
            (PROFILE_ID_PREIMAGE_PATH, TEST_PROFILE_ID_PREIMAGE),
        ]
        .into_iter()
        .map(|(path, bytes)| (path.to_owned(), bytes.to_vec()))
        .collect()
    }

    fn sources(map: &BTreeMap<String, Vec<u8>>) -> AuthenticatedProfileSources<'_> {
        authenticate_profile_source_map(map).unwrap()
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
    fn profile_recipe_coverage_is_exactly_the_fifty_plan_rows() {
        let map = source_map();
        let sources = sources(&map);
        let plan = flattened_plan();
        let mut covered = 0;
        for (index, planned) in plan.iter().enumerate() {
            let recipe = profile_recipe(index, sources).unwrap();
            assert_eq!(
                recipe.is_some(),
                (PROFILE_FIRST_INDEX..PROFILE_END_INDEX_EXCLUSIVE).contains(&index)
            );
            if recipe.is_some() {
                let materialized = materialize_profile_row(index, sources).unwrap();
                materialized.validate_planned(planned).unwrap();
                covered += 1;
            }
        }
        assert_eq!(covered, 50);
        assert!(profile_recipe(159, sources).unwrap().is_none());
        assert!(profile_recipe(210, sources).unwrap().is_none());
    }

    #[test]
    fn exact_offsets_targets_and_recipe_families_are_frozen() {
        let map = source_map();
        let sources = sources(&map);
        for index in PROFILE_FIRST_INDEX..PROFILE_END_INDEX_EXCLUSIVE {
            let recipe = profile_recipe(index, sources).unwrap().unwrap();
            let expected_target = match index {
                160..=205 => B4ByteTarget::ProfileManifest,
                206 => B4ByteTarget::ProfileArtifact {
                    artifact: B4ProfileArtifact::Algorithm,
                },
                207 => B4ByteTarget::ProfileArtifact {
                    artifact: B4ProfileArtifact::Constants,
                },
                208 => B4ByteTarget::ProfileArtifact {
                    artifact: B4ProfileArtifact::ProfileId,
                },
                209 => B4ByteTarget::ProfileArtifact {
                    artifact: B4ProfileArtifact::ProfileIdPreimage,
                },
                _ => unreachable!(),
            };
            assert_eq!(recipe.target, expected_target);

            match (&recipe.edit, index) {
                (
                    B4ByteOperation::Truncate {
                        new_length,
                        original_length,
                        ..
                    },
                    160,
                ) => {
                    assert_eq!((*new_length, *original_length), (457, 458));
                }
                (
                    B4ByteOperation::Insert {
                        offset,
                        inserted_hex,
                    },
                    161,
                ) => {
                    assert_eq!((*offset, inserted_hex.as_str()), (458, "00"));
                }
                (B4ByteOperation::Replace { offset, .. }, 162..=166) => {
                    assert_eq!(*offset, [0, 1, 5, 9, 10][index - 162]);
                }
                (B4ByteOperation::Replace { offset, .. }, 167..=196) => {
                    let relative = index - 167;
                    assert_eq!(
                        *offset,
                        u64::try_from(
                            CONTROL_TABLE_OFFSET
                                + (relative / 3) * CONTROL_BYTES
                                + match relative % 3 {
                                    0 => 0,
                                    1 => 1,
                                    2 => CONTROL_ID_OFFSET,
                                    _ => unreachable!(),
                                }
                        )
                        .unwrap()
                    );
                }
                (B4ByteOperation::Replace { offset, .. }, 197) => assert_eq!(*offset, 78),
                (B4ByteOperation::Replace { offset, .. }, 198) => assert_eq!(*offset, 42),
                (B4ByteOperation::Replace { offset, .. }, 199 | 205) => {
                    assert_eq!(*offset, 382);
                }
                (B4ByteOperation::Replace { offset, .. }, 200) => assert_eq!(*offset, 384),
                (B4ByteOperation::Replace { offset, .. }, 201) => assert_eq!(*offset, 388),
                (B4ByteOperation::Replace { offset, .. }, 202) => assert_eq!(*offset, 420),
                (B4ByteOperation::Replace { offset, .. }, 203) => assert_eq!(*offset, 422),
                (B4ByteOperation::Replace { offset, .. }, 204) => assert_eq!(*offset, 426),
                (B4ByteOperation::Replace { offset, .. }, 206..=208) => {
                    assert_eq!(*offset, 0);
                }
                (B4ByteOperation::Replace { offset, .. }, 209) => assert_eq!(*offset, 484),
                _ => panic!("unexpected C2 recipe family at index {index}"),
            }
        }
    }

    #[test]
    fn headline_replacements_and_every_raw_edit_are_exact_and_isolated() {
        let map = source_map();
        let sources = sources(&map);
        let expected_replacements = [
            (162, "01", "00"),
            (163, "cc", "cd"),
            (164, "00", "01"),
            (165, "12", "13"),
            (166, "a5", "a4"),
            (199, "0100", "0200"),
            (200, "4d740000", "4e740000"),
            (201, "6e", "6f"),
            (202, "0200", "0100"),
            (203, "5ffe0000", "60fe0000"),
            (204, "dd", "dc"),
            (206, "45", "44"),
            (207, "01", "00"),
            (208, "23", "22"),
            (209, "b1", "b0"),
        ];
        for (index, expected_before, expected_after) in expected_replacements {
            let recipe = profile_recipe(index, sources).unwrap().unwrap();
            let B4ByteOperation::Replace {
                before_hex,
                replacement_hex,
                ..
            } = recipe.edit
            else {
                panic!("expected replacement recipe at index {index}");
            };
            assert_eq!(before_hex, expected_before);
            assert_eq!(replacement_hex, expected_after);
        }

        for index in PROFILE_FIRST_INDEX..PROFILE_END_INDEX_EXCLUSIVE {
            let row = materialize_profile_row(index, sources).unwrap();
            match &row.edit {
                B4ByteOperation::Replace {
                    before_hex,
                    replacement_hex,
                    offset,
                } => {
                    let before = hex::decode(before_hex).unwrap();
                    let replacement = hex::decode(replacement_hex).unwrap();
                    let offset = usize::try_from(*offset).unwrap();
                    assert_eq!(&row.base[offset..offset + before.len()], before);
                    assert_eq!(
                        &row.raw_output[offset..offset + replacement.len()],
                        replacement
                    );
                    assert_eq!(&row.raw_output[..offset], &row.base[..offset]);
                    assert_eq!(
                        &row.raw_output[offset + replacement.len()..],
                        &row.base[offset + before.len()..]
                    );
                }
                B4ByteOperation::Insert {
                    inserted_hex,
                    offset,
                } => {
                    let inserted = hex::decode(inserted_hex).unwrap();
                    let offset = usize::try_from(*offset).unwrap();
                    assert_eq!(&row.raw_output[..offset], &row.base[..offset]);
                    assert_eq!(&row.raw_output[offset..offset + inserted.len()], inserted);
                    assert_eq!(
                        &row.raw_output[offset + inserted.len()..],
                        &row.base[offset..]
                    );
                }
                B4ByteOperation::Truncate {
                    new_length,
                    original_length,
                    ..
                } => {
                    assert_eq!(usize::try_from(*original_length).unwrap(), row.base.len());
                    assert_eq!(usize::try_from(*new_length).unwrap(), row.raw_output.len());
                    assert_eq!(row.raw_output, &row.base[..row.raw_output.len()]);
                }
                B4ByteOperation::Delete { .. } => {
                    panic!("C2 profile recipes contain no delete operation")
                }
            }
        }
    }

    #[test]
    fn subjects_and_contexts_have_exact_closed_shapes() {
        let map = source_map();
        let sources = sources(&map);
        let package_rows = [200, 201, 203, 204, 206, 207];
        for index in PROFILE_FIRST_INDEX..PROFILE_END_INDEX_EXCLUSIVE {
            let row = materialize_profile_row(index, sources).unwrap();
            assert_eq!(row.contexts.is_empty(), index != 208);
            if index == 208 {
                assert_eq!(row.subject.len(), DIGEST_BYTES);
                assert_eq!(
                    row.contexts,
                    vec![
                        TEST_MANIFEST.to_vec(),
                        TEST_ALGORITHM.to_vec(),
                        TEST_CONSTANTS.to_vec()
                    ]
                );
            } else if package_rows.contains(&index) {
                assert_eq!(row.subject.len(), PROFILE_PACKAGE_SUBJECT_BYTES);
                let decoded = decode_subject_envelope(
                    &row.subject,
                    B4SubjectEnvelopeContract::new(
                        B4SubjectEnvelopeKind::ProfilePackage,
                        &PROFILE_PACKAGE_PARTS,
                    ),
                )
                .unwrap();
                assert_eq!(decoded.parts().len(), 3);
                match index {
                    200 | 201 | 203 | 204 => {
                        assert_eq!(decoded.parts()[0], row.raw_output);
                        assert_eq!(decoded.parts()[1], TEST_ALGORITHM);
                        assert_eq!(decoded.parts()[2], TEST_CONSTANTS);
                    }
                    206 => {
                        assert_eq!(decoded.parts()[0], TEST_MANIFEST);
                        assert_eq!(decoded.parts()[1], row.raw_output);
                        assert_eq!(decoded.parts()[2], TEST_CONSTANTS);
                    }
                    207 => {
                        assert_eq!(decoded.parts()[0], TEST_MANIFEST);
                        assert_eq!(decoded.parts()[1], TEST_ALGORITHM);
                        assert_eq!(decoded.parts()[2], row.raw_output);
                    }
                    _ => unreachable!(),
                }
            } else if index == 209 {
                assert_eq!(row.subject.len(), PROFILE_ID_PREIMAGE_SUBJECT_BYTES);
                let decoded = decode_subject_envelope(
                    &row.subject,
                    B4SubjectEnvelopeContract::new(
                        B4SubjectEnvelopeKind::ProfileIdPreimageBundle,
                        &PROFILE_ID_PREIMAGE_PARTS,
                    ),
                )
                .unwrap();
                assert_eq!(decoded.parts()[0], TEST_MANIFEST);
                assert_eq!(decoded.parts()[1], row.raw_output);
            } else {
                assert_eq!(row.subject, row.raw_output);
                assert!(
                    [MANIFEST_BYTES - 1, MANIFEST_BYTES, MANIFEST_BYTES + 1]
                        .contains(&row.subject.len())
                );
            }
        }
    }

    #[test]
    fn every_required_source_is_authenticated_and_drift_fails_closed() {
        for path in [
            MANIFEST_PATH,
            ALGORITHM_PATH,
            CONSTANTS_PATH,
            PROFILE_ID_PATH,
            PROFILE_ID_PREIMAGE_PATH,
        ] {
            let mut drift = source_map();
            let bytes = drift.get_mut(path).unwrap();
            let index = bytes.len() - 1;
            bytes[index] ^= 1;
            assert!(
                authenticate_profile_source_map(&drift).is_err(),
                "source drift was accepted for {path}"
            );
        }

        for missing in [
            MANIFEST_PATH,
            ALGORITHM_PATH,
            CONSTANTS_PATH,
            PROFILE_ID_PATH,
            PROFILE_ID_PREIMAGE_PATH,
        ] {
            let mut absent = source_map();
            absent.remove(missing);
            assert!(authenticate_profile_source_map(&absent).is_err());
        }
    }
}
