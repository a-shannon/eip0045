// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Shared physical authentication for one selected positive-generation case.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, ensure};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::{
    b4::{B4PositiveArtifactRole, canonical_positive_case_artifact_path},
    b4_campaign_contract::{
        B4ContractArtifactEncodingV1, B4ContractArtifactIdentityV1, b4_paths_conflict,
        validate_safe_relative_path,
    },
    b4_materialization_set::{
        compiled_positive_case_id, compiled_positive_generation_recipe, positive_artifact_encoding,
        positive_artifact_layout, positive_artifact_role_name, validate_positive_artifact_length,
    },
    b4_positive_gate::{B4PositiveGenerationCaseAuthorityV1, FileMeasurement},
    b4_recursive_auxiliary_paths::compiled_positive_auxiliary_artifact_paths,
    canonical::{canonical_json_bytes, validate_canonical_json_source},
    constants::{DIGEST_BYTES, PROOF_BYTES},
    manifest::{ManifestEntry, ProofOutputManifest, validate_manifest_shape},
};

#[derive(Clone, Copy, Debug)]
pub(crate) struct B4PositiveSourceBytesV1<'a> {
    pub(crate) path: &'a str,
    pub(crate) bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct B4PositiveCaseSourceV1<'bytes, 'view> {
    pub(crate) proof_output_manifest_jcs: &'bytes [u8],
    pub(crate) primary_artifacts: &'view [B4PositiveSourceBytesV1<'bytes>],
    pub(crate) auxiliary_artifacts: &'view [B4PositiveSourceBytesV1<'bytes>],
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct B4PositiveSourceBytesV2<'a> {
    pub(crate) path: &'a str,
    pub(crate) bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct B4PositiveCaseSourceV2<'bytes, 'view> {
    pub(crate) proof_output_manifest_jcs: &'bytes [u8],
    pub(crate) primary_artifacts: &'view [B4PositiveSourceBytesV2<'bytes>],
    pub(crate) auxiliary_artifacts: &'view [B4PositiveSourceBytesV2<'bytes>],
}

#[derive(Clone, Debug)]
pub(crate) struct B4AuthenticatedPositiveCaseSourceV1<'a> {
    case_index: usize,
    case_id: String,
    proof_output_manifest: FileMeasurement,
    primary_measurements: Vec<FileMeasurement>,
    auxiliary_measurements: Vec<FileMeasurement>,
    journal: &'a [u8],
    image_id: &'a [u8],
    raw_seal: &'a [u8],
    receipt_oracle: &'a [u8],
    auxiliary_artifacts: Vec<B4PositiveSourceBytesV1<'a>>,
}

impl<'a> B4AuthenticatedPositiveCaseSourceV1<'a> {
    pub(crate) const fn case_index(&self) -> usize {
        self.case_index
    }

    pub(crate) fn case_id(&self) -> &str {
        &self.case_id
    }

    pub(crate) const fn proof_output_manifest(&self) -> FileMeasurement {
        self.proof_output_manifest
    }

    pub(crate) fn primary_measurements(&self) -> &[FileMeasurement] {
        &self.primary_measurements
    }

    pub(crate) fn auxiliary_measurements(&self) -> &[FileMeasurement] {
        &self.auxiliary_measurements
    }

    pub(crate) const fn journal(&self) -> &'a [u8] {
        self.journal
    }

    pub(crate) const fn image_id(&self) -> &'a [u8] {
        self.image_id
    }

    pub(crate) const fn raw_seal(&self) -> &'a [u8] {
        self.raw_seal
    }

    pub(crate) const fn receipt_oracle(&self) -> &'a [u8] {
        self.receipt_oracle
    }

    pub(crate) fn auxiliary_artifacts(&self) -> &[B4PositiveSourceBytesV1<'a>] {
        &self.auxiliary_artifacts
    }
}

#[derive(Clone, Debug)]
pub(crate) struct B4AuthenticatedPositiveCaseSourceV2<'a> {
    case_index: usize,
    case_id: String,
    proof_output_manifest: FileMeasurement,
    primary_measurements: Vec<FileMeasurement>,
    auxiliary_measurements: Vec<FileMeasurement>,
    journal: &'a [u8],
    image_id: &'a [u8],
    raw_seal: &'a [u8],
    receipt_oracle: &'a [u8],
    auxiliary_artifacts: Vec<B4PositiveSourceBytesV2<'a>>,
}

impl<'a> B4AuthenticatedPositiveCaseSourceV2<'a> {
    pub(crate) const fn case_index(&self) -> usize {
        self.case_index
    }

    pub(crate) fn case_id(&self) -> &str {
        &self.case_id
    }

    pub(crate) const fn proof_output_manifest(&self) -> FileMeasurement {
        self.proof_output_manifest
    }

    pub(crate) fn primary_measurements(&self) -> &[FileMeasurement] {
        &self.primary_measurements
    }

    pub(crate) fn auxiliary_measurements(&self) -> &[FileMeasurement] {
        &self.auxiliary_measurements
    }

    pub(crate) const fn journal(&self) -> &'a [u8] {
        self.journal
    }

    pub(crate) const fn image_id(&self) -> &'a [u8] {
        self.image_id
    }

    pub(crate) const fn raw_seal(&self) -> &'a [u8] {
        self.raw_seal
    }

    pub(crate) const fn receipt_oracle(&self) -> &'a [u8] {
        self.receipt_oracle
    }

    pub(crate) fn auxiliary_artifacts(&self) -> &[B4PositiveSourceBytesV2<'a>] {
        &self.auxiliary_artifacts
    }
}

pub(crate) struct B4PositiveGenerationDocumentV1 {
    value: Value,
}

impl B4PositiveGenerationDocumentV1 {
    pub(crate) fn from_canonical_jcs(bytes: &[u8]) -> Result<Self> {
        let value = validate_canonical_json_source(bytes)
            .context("positive generation set is not exact canonical JCS")?;
        require_exact_json_keys(
            &value,
            &[
                "format",
                "formatVersion",
                "inputSetCommitment",
                "proofGeneratorArtifact",
                "cases",
            ],
            "positive generation set",
        )?;
        ensure!(
            json_string_field(&value, "format", "positive generation set")?
                == "Eip0045B4PositiveGenerationSetV1"
                && json_u64_field(&value, "formatVersion", "positive generation set")? == 1,
            "positive generation set has the wrong format identity"
        );
        ensure!(
            json_array_field(&value, "cases", "positive generation set")?.len() == 11,
            "positive generation set does not contain exactly eleven cases"
        );
        Ok(Self { value })
    }

    pub(crate) fn input_set_measurement(&self) -> Result<FileMeasurement> {
        let input = json_field(&self.value, "inputSetCommitment", "positive generation set")?;
        require_exact_json_keys(
            input,
            &["format", "byteLength", "sha256", "encoding"],
            "positive generation input-set commitment",
        )?;
        ensure!(
            json_string_field(input, "format", "positive generation input-set commitment")?
                == "Eip0045B4PositiveInputSetV1"
                && json_string_field(
                    input,
                    "encoding",
                    "positive generation input-set commitment"
                )? == "rfc8785-jcs",
            "positive generation input-set commitment has the wrong format or encoding"
        );
        measurement_from_value(input, "positive generation input-set commitment")
    }

    pub(crate) fn proof_generator_measurement(&self) -> Result<FileMeasurement> {
        let generator = json_field(
            &self.value,
            "proofGeneratorArtifact",
            "positive generation set",
        )?;
        require_exact_json_keys(
            generator,
            &["byteLength", "sha256", "encoding"],
            "positive generation proof-generator commitment",
        )?;
        ensure!(
            json_string_field(
                generator,
                "encoding",
                "positive generation proof-generator commitment"
            )? == "raw-bytes",
            "positive generation proof-generator commitment has the wrong encoding"
        );
        measurement_from_value(generator, "positive generation proof-generator commitment")
    }
}

pub(crate) struct B4PositiveGenerationDocumentV2 {
    value: Value,
}

impl B4PositiveGenerationDocumentV2 {
    pub(crate) fn from_canonical_jcs(bytes: &[u8]) -> Result<Self> {
        ensure!(
            (2..=1024 * 1024).contains(&bytes.len()),
            "V2 positive generation set is outside its closed byte bound"
        );
        let value = validate_canonical_json_source(bytes)
            .context("V2 positive generation set is not exact canonical JCS")?;
        require_exact_json_keys(
            &value,
            &[
                "format",
                "formatVersion",
                "inputSetCommitment",
                "proofGeneratorArtifact",
                "cases",
            ],
            "V2 positive generation set",
        )?;
        ensure!(
            json_string_field(&value, "format", "V2 positive generation set")?
                == "Eip0045B4PositiveGenerationSetV2"
                && json_u64_field(&value, "formatVersion", "V2 positive generation set")? == 2,
            "V2 positive generation set has the wrong format identity"
        );
        ensure!(
            json_array_field(&value, "cases", "V2 positive generation set")?.len() == 11,
            "V2 positive generation set does not contain exactly eleven cases"
        );
        Ok(Self { value })
    }

    pub(crate) fn authenticate_input_set(&self, source: &[u8]) -> Result<FileMeasurement> {
        ensure!(
            (2..=1024 * 1024).contains(&source.len()),
            "V2 positive input set is outside its closed byte bound"
        );
        let value = validate_canonical_json_source(source)
            .context("V2 positive input set is not exact canonical JCS")?;
        ensure!(
            json_string_field(&value, "format", "V2 positive input set")?
                == "Eip0045B4PositiveInputSetV2"
                && json_u64_field(&value, "formatVersion", "V2 positive input set")? == 2,
            "V2 positive input set has the wrong format identity"
        );
        let measured = measure_bytes(source)?;
        ensure!(
            measured == self.input_set_measurement()?,
            "V2 positive generation set binds different positive input-set bytes"
        );
        Ok(measured)
    }

    pub(crate) fn input_set_measurement(&self) -> Result<FileMeasurement> {
        let input = json_field(
            &self.value,
            "inputSetCommitment",
            "V2 positive generation set",
        )?;
        require_exact_json_keys(
            input,
            &["format", "byteLength", "sha256", "encoding"],
            "V2 positive generation input-set commitment",
        )?;
        ensure!(
            json_string_field(
                input,
                "format",
                "V2 positive generation input-set commitment"
            )? == "Eip0045B4PositiveInputSetV2"
                && json_string_field(
                    input,
                    "encoding",
                    "V2 positive generation input-set commitment"
                )? == "rfc8785-jcs",
            "V2 positive generation input-set commitment has the wrong format or encoding"
        );
        measurement_from_value(input, "V2 positive generation input-set commitment")
    }

    pub(crate) fn proof_generator_measurement(&self) -> Result<FileMeasurement> {
        let generator = json_field(
            &self.value,
            "proofGeneratorArtifact",
            "V2 positive generation set",
        )?;
        require_exact_json_keys(
            generator,
            &["byteLength", "sha256", "encoding"],
            "V2 positive generation proof-generator commitment",
        )?;
        ensure!(
            json_string_field(
                generator,
                "encoding",
                "V2 positive generation proof-generator commitment"
            )? == "raw-bytes",
            "V2 positive generation proof-generator commitment has the wrong encoding"
        );
        measurement_from_value(
            generator,
            "V2 positive generation proof-generator commitment",
        )
    }
}

pub(crate) fn merge_prior_paths(
    paths: &mut BTreeSet<String>,
    additional: &BTreeSet<String>,
) -> Result<()> {
    for path in additional {
        validate_safe_relative_path(path)?;
        if paths.contains(path) {
            continue;
        }
        ensure!(
            !paths
                .iter()
                .any(|existing| b4_paths_conflict(existing, path)),
            "prior authority paths form an ancestor/descendant conflict"
        );
        paths.insert(path.to_owned());
    }
    Ok(())
}

pub(crate) fn bind_external_path(
    paths: &mut BTreeSet<String>,
    path: &str,
    allow_exact_replay: bool,
    label: &str,
) -> Result<()> {
    validate_safe_relative_path(path).with_context(|| format!("invalid {label} path"))?;
    if paths.contains(path) {
        ensure!(
            allow_exact_replay,
            "{label} path duplicates an existing authority path"
        );
        return Ok(());
    }
    ensure!(
        !paths
            .iter()
            .any(|existing| b4_paths_conflict(existing, path)),
        "{label} path forms an ancestor/descendant conflict"
    );
    paths.insert(path.to_owned());
    Ok(())
}

pub(crate) fn authenticate_external_identity(
    external: B4PositiveSourceBytesV1<'_>,
    expected: &B4ContractArtifactIdentityV1,
    encoding: B4ContractArtifactEncodingV1,
    label: &str,
) -> Result<()> {
    ensure!(
        expected.encoding == encoding,
        "{label} prior authority uses the wrong encoding"
    );
    ensure!(
        B4ContractArtifactIdentityV1::from_bytes(external.path, encoding, external.bytes)?
            == *expected,
        "{label} path or bytes differ from the opaque prior authority"
    );
    Ok(())
}

pub(crate) fn authenticate_external_identity_v2(
    external: B4PositiveSourceBytesV2<'_>,
    expected: &B4ContractArtifactIdentityV1,
    encoding: B4ContractArtifactEncodingV1,
    label: &str,
) -> Result<()> {
    ensure!(
        expected.encoding == encoding,
        "{label} V2 source identity uses the wrong encoding"
    );
    ensure!(
        B4ContractArtifactIdentityV1::from_bytes(external.path, encoding, external.bytes)?
            == *expected,
        "{label} V2 source path or bytes differ from the reparsed identity"
    );
    Ok(())
}

pub(crate) fn authenticate_positive_case_source<'bytes>(
    generation: &B4PositiveGenerationDocumentV1,
    positive_case: &B4PositiveGenerationCaseAuthorityV1,
    case_index: usize,
    source: B4PositiveCaseSourceV1<'bytes, '_>,
    paths: &mut BTreeSet<String>,
) -> Result<B4AuthenticatedPositiveCaseSourceV1<'bytes>> {
    ensure!(
        usize::from(positive_case.case_index()) == case_index,
        "positive case authority ordinal differs from the selected case index"
    );
    let authenticated =
        authenticate_positive_case_source_bytes(&generation.value, case_index, source, paths)?;
    ensure!(
        authenticated.proof_output_manifest() == positive_case.proof_output_manifest(),
        "positive selected-case proof-output manifest differs from the opaque generation authority"
    );
    ensure!(
        measure_bytes(authenticated.raw_seal())? == positive_case.raw_seal(),
        "positive selected-case raw seal differs from the opaque generation authority"
    );
    Ok(authenticated)
}

pub(crate) fn authenticate_positive_case_source_v2<'bytes>(
    generation: &B4PositiveGenerationDocumentV2,
    case_index: usize,
    source: B4PositiveCaseSourceV2<'bytes, '_>,
    paths: &mut BTreeSet<String>,
) -> Result<B4AuthenticatedPositiveCaseSourceV2<'bytes>> {
    let primary = source
        .primary_artifacts
        .iter()
        .map(|artifact| B4PositiveSourceBytesV1 {
            path: artifact.path,
            bytes: artifact.bytes,
        })
        .collect::<Vec<_>>();
    let auxiliary = source
        .auxiliary_artifacts
        .iter()
        .map(|artifact| B4PositiveSourceBytesV1 {
            path: artifact.path,
            bytes: artifact.bytes,
        })
        .collect::<Vec<_>>();
    let authenticated = authenticate_positive_case_source_bytes(
        &generation.value,
        case_index,
        B4PositiveCaseSourceV1 {
            proof_output_manifest_jcs: source.proof_output_manifest_jcs,
            primary_artifacts: &primary,
            auxiliary_artifacts: &auxiliary,
        },
        paths,
    )?;
    let B4AuthenticatedPositiveCaseSourceV1 {
        case_index,
        case_id,
        proof_output_manifest,
        primary_measurements,
        auxiliary_measurements,
        journal,
        image_id,
        raw_seal,
        receipt_oracle,
        auxiliary_artifacts,
    } = authenticated;
    Ok(B4AuthenticatedPositiveCaseSourceV2 {
        case_index,
        case_id,
        proof_output_manifest,
        primary_measurements,
        auxiliary_measurements,
        journal,
        image_id,
        raw_seal,
        receipt_oracle,
        auxiliary_artifacts: auxiliary_artifacts
            .into_iter()
            .map(|artifact| B4PositiveSourceBytesV2 {
                path: artifact.path,
                bytes: artifact.bytes,
            })
            .collect(),
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "closed selected-case role, path, manifest, and opaque-authority bindings stay linear for auditability"
)]
fn authenticate_positive_case_source_bytes<'bytes>(
    generation_value: &Value,
    case_index: usize,
    source: B4PositiveCaseSourceV1<'bytes, '_>,
    paths: &mut BTreeSet<String>,
) -> Result<B4AuthenticatedPositiveCaseSourceV1<'bytes>> {
    let case_id = compiled_positive_case_id(case_index)?;
    let recipe = compiled_positive_generation_recipe(case_index)?;
    let generated_cases = json_array_field(generation_value, "cases", "positive generation set")?;
    let generated = generated_cases
        .get(case_index)
        .context("positive generation set lacks the selected case")?;
    require_exact_json_keys(
        generated,
        &[
            "caseIndex",
            "caseId",
            "generation",
            "proofOutputManifest",
            "artifacts",
        ],
        "positive generation selected case",
    )?;
    ensure!(
        json_u64_field(generated, "caseIndex", "positive generation selected case")?
            == u64::try_from(case_index)?
            && json_string_field(generated, "caseId", "positive generation selected case")?
                == case_id,
        "positive generation selected case differs from the compiled ordinal or ID"
    );
    ensure!(
        json_field(generated, "generation", "positive generation selected case")? == &recipe,
        "positive generation selected case differs from the compiled recipe"
    );

    let layout = positive_artifact_layout(case_index)?;
    let auxiliary_paths = compiled_positive_auxiliary_artifact_paths(case_index)?;
    ensure!(
        source.primary_artifacts.len() == layout.len(),
        "positive selected case has the wrong primary artifact cardinality"
    );
    ensure!(
        source.auxiliary_artifacts.len() == auxiliary_paths.len(),
        "positive selected case has the wrong auxiliary artifact cardinality"
    );
    for external in source
        .primary_artifacts
        .iter()
        .chain(source.auxiliary_artifacts)
    {
        bind_external_path(paths, external.path, false, "positive selected-case source")?;
    }

    let generated_artifacts =
        json_array_field(generated, "artifacts", "positive generation selected case")?;
    ensure!(
        generated_artifacts.len() == layout.len(),
        "positive generation selected case has the wrong primary artifact cardinality"
    );

    let mut manifest: ProofOutputManifest =
        Vec::with_capacity(source.primary_artifacts.len() + source.auxiliary_artifacts.len());
    let mut primary_measurements = Vec::with_capacity(source.primary_artifacts.len());
    for (position, (((role, basename), external), generated_artifact)) in layout
        .iter()
        .copied()
        .zip(source.primary_artifacts)
        .zip(generated_artifacts)
        .enumerate()
    {
        ensure!(
            external.path == canonical_positive_case_artifact_path(&case_id, basename),
            "positive selected-case primary physical path drift at position {position}"
        );
        let measurement = measure_bytes(external.bytes)?;
        validate_positive_artifact_length(case_index, role, measurement.byte_length)?;
        if matches!(
            role,
            B4PositiveArtifactRole::Ancestry
                | B4PositiveArtifactRole::Calibration
                | B4PositiveArtifactRole::Metadata
        ) {
            validate_canonical_json_source(external.bytes).with_context(|| {
                format!(
                    "positive selected-case {} artifact is not exact canonical JCS",
                    positive_artifact_role_name(role)
                )
            })?;
        }

        let expected_keys: &[&str] = if matches!(
            role,
            B4PositiveArtifactRole::ClaimDigest
                | B4PositiveArtifactRole::ControlId
                | B4PositiveArtifactRole::ImageId
        ) {
            &[
                "role",
                "sourceFile",
                "byteLength",
                "sha256",
                "encoding",
                "contentHex",
            ]
        } else if role == B4PositiveArtifactRole::ReceiptOracle {
            &[
                "role",
                "sourceFile",
                "byteLength",
                "sha256",
                "encoding",
                "codec",
            ]
        } else {
            &["role", "sourceFile", "byteLength", "sha256", "encoding"]
        };
        require_exact_json_keys(
            generated_artifact,
            expected_keys,
            "positive generation selected-case artifact",
        )?;
        let (encoding_name, _) = positive_artifact_encoding(role);
        let digest = hex::encode(measurement.sha256);
        ensure!(
            json_string_field(
                generated_artifact,
                "role",
                "positive generation selected-case artifact"
            )? == positive_artifact_role_name(role)
                && json_string_field(
                    generated_artifact,
                    "sourceFile",
                    "positive generation selected-case artifact"
                )? == basename
                && json_u64_field(
                    generated_artifact,
                    "byteLength",
                    "positive generation selected-case artifact"
                )? == measurement.byte_length
                && json_string_field(
                    generated_artifact,
                    "sha256",
                    "positive generation selected-case artifact"
                )? == digest
                && json_string_field(
                    generated_artifact,
                    "encoding",
                    "positive generation selected-case artifact"
                )? == encoding_name,
            "positive generation selected-case artifact identity differs at position {position}"
        );
        if matches!(
            role,
            B4PositiveArtifactRole::ClaimDigest
                | B4PositiveArtifactRole::ControlId
                | B4PositiveArtifactRole::ImageId
        ) {
            ensure!(
                json_string_field(
                    generated_artifact,
                    "contentHex",
                    "positive generation selected-case digest artifact"
                )? == hex::encode(external.bytes),
                "positive generation selected-case digest content differs at position {position}"
            );
        }
        if role == B4PositiveArtifactRole::ReceiptOracle {
            let expected_codec = if case_index < 8 {
                "bincode-1.3.3-little-endian-fixed-int-reject-trailing"
            } else {
                "eip0045-recursive-oracle-borsh-v1"
            };
            ensure!(
                json_string_field(
                    generated_artifact,
                    "codec",
                    "positive generation selected-case receipt oracle"
                )? == expected_codec,
                "positive generation selected-case receipt-oracle codec drifted"
            );
        }
        manifest.push(ManifestEntry {
            path: basename.to_owned(),
            length: measurement.byte_length.to_string(),
            sha256: digest,
        });
        primary_measurements.push(measurement);
    }

    let mut auxiliary_measurements = Vec::with_capacity(source.auxiliary_artifacts.len());
    for (position, (external, expected_path)) in source
        .auxiliary_artifacts
        .iter()
        .zip(auxiliary_paths)
        .enumerate()
    {
        ensure!(
            external.path == *expected_path,
            "positive selected-case auxiliary path/order drift at position {position}"
        );
        let measurement = measure_bytes(external.bytes)?;
        ensure!(
            measurement.byte_length == PROOF_BYTES as u64,
            "positive selected-case auxiliary seal has the wrong exact byte length"
        );
        manifest.push(ManifestEntry {
            path: (*expected_path).to_owned(),
            length: measurement.byte_length.to_string(),
            sha256: hex::encode(measurement.sha256),
        });
        auxiliary_measurements.push(measurement);
    }

    manifest.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
    validate_manifest_shape(&manifest)?;
    let reconstructed_manifest = canonical_json_bytes(
        &serde_json::to_value(&manifest)
            .context("cannot serialize reconstructed positive selected-case manifest")?,
    )?;
    ensure!(
        reconstructed_manifest == source.proof_output_manifest_jcs,
        "positive selected-case proof-output manifest differs from exact source bytes"
    );
    let manifest_measurement = measure_bytes(&reconstructed_manifest)?;
    let manifest_identity = json_field(
        generated,
        "proofOutputManifest",
        "positive generation selected case",
    )?;
    require_exact_json_keys(
        manifest_identity,
        &["fileName", "byteLength", "sha256", "encoding"],
        "positive generation selected-case manifest identity",
    )?;
    let expected_manifest_name = if case_index < 8 {
        "candidate-proof-output-manifest.json"
    } else {
        "candidate-recursive-output-manifest.json"
    };
    ensure!(
        json_string_field(
            manifest_identity,
            "fileName",
            "positive generation selected-case manifest identity"
        )? == expected_manifest_name
            && json_u64_field(
                manifest_identity,
                "byteLength",
                "positive generation selected-case manifest identity"
            )? == manifest_measurement.byte_length
            && json_string_field(
                manifest_identity,
                "sha256",
                "positive generation selected-case manifest identity"
            )? == hex::encode(manifest_measurement.sha256)
            && json_string_field(
                manifest_identity,
                "encoding",
                "positive generation selected-case manifest identity"
            )? == "rfc8785-jcs",
        "positive generation selected-case manifest identity differs from exact bytes"
    );
    let journal = borrowed_artifact(
        layout,
        source.primary_artifacts,
        B4PositiveArtifactRole::Journal,
    )?;
    let image_id = borrowed_artifact(
        layout,
        source.primary_artifacts,
        B4PositiveArtifactRole::ImageId,
    )?;
    let raw_seal = borrowed_artifact(
        layout,
        source.primary_artifacts,
        B4PositiveArtifactRole::RawSeal,
    )?;
    let receipt_oracle = borrowed_artifact(
        layout,
        source.primary_artifacts,
        B4PositiveArtifactRole::ReceiptOracle,
    )?;
    Ok(B4AuthenticatedPositiveCaseSourceV1 {
        case_index,
        case_id,
        proof_output_manifest: manifest_measurement,
        primary_measurements,
        auxiliary_measurements,
        journal,
        image_id,
        raw_seal,
        receipt_oracle,
        auxiliary_artifacts: source.auxiliary_artifacts.to_vec(),
    })
}

fn borrowed_artifact<'a>(
    layout: &[(B4PositiveArtifactRole, &str)],
    artifacts: &[B4PositiveSourceBytesV1<'a>],
    selected_role: B4PositiveArtifactRole,
) -> Result<&'a [u8]> {
    let mut positions = layout
        .iter()
        .enumerate()
        .filter(|(_, (role, _))| *role == selected_role)
        .map(|(position, _)| position);
    let position = positions
        .next()
        .with_context(|| format!("positive selected-case layout lacks {selected_role:?}"))?;
    ensure!(
        positions.next().is_none(),
        "positive selected-case layout duplicates {selected_role:?}"
    );
    artifacts
        .get(position)
        .map(|artifact| artifact.bytes)
        .with_context(|| format!("positive selected-case source lacks {selected_role:?}"))
}

fn measure_bytes(bytes: &[u8]) -> Result<FileMeasurement> {
    Ok(FileMeasurement {
        byte_length: u64::try_from(bytes.len())?,
        sha256: Sha256::digest(bytes).into(),
    })
}

fn measurement_from_value(value: &Value, label: &str) -> Result<FileMeasurement> {
    Ok(FileMeasurement {
        byte_length: json_u64_field(value, "byteLength", label)?,
        sha256: decode_hex32(json_string_field(value, "sha256", label)?, label)?,
    })
}

fn decode_hex32(value: &str, label: &str) -> Result<[u8; DIGEST_BYTES]> {
    let bytes =
        hex::decode(value).with_context(|| format!("{label} SHA-256 is not hexadecimal"))?;
    ensure!(
        value == hex::encode(&bytes),
        "{label} SHA-256 is not lowercase hexadecimal"
    );
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            "{label} SHA-256 has {} bytes instead of {DIGEST_BYTES}",
            bytes.len()
        )
    })
}

fn json_field<'a>(value: &'a Value, name: &str, label: &str) -> Result<&'a Value> {
    value
        .as_object()
        .with_context(|| format!("{label} is not an object"))?
        .get(name)
        .with_context(|| format!("{label} lacks {name}"))
}

fn json_string_field<'a>(value: &'a Value, name: &str, label: &str) -> Result<&'a str> {
    json_field(value, name, label)?
        .as_str()
        .with_context(|| format!("{label}.{name} is not a string"))
}

fn json_u64_field(value: &Value, name: &str, label: &str) -> Result<u64> {
    json_field(value, name, label)?
        .as_u64()
        .with_context(|| format!("{label}.{name} is not an unsigned integer"))
}

fn json_array_field<'a>(value: &'a Value, name: &str, label: &str) -> Result<&'a [Value]> {
    json_field(value, name, label)?
        .as_array()
        .map(Vec::as_slice)
        .with_context(|| format!("{label}.{name} is not an array"))
}

fn require_exact_json_keys(value: &Value, expected: &[&str], label: &str) -> Result<()> {
    let object = value
        .as_object()
        .with_context(|| format!("{label} is not an object"))?;
    ensure!(
        object.len() == expected.len() && expected.iter().all(|name| object.contains_key(*name)),
        "{label} has missing, extra, or renamed fields"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::measure_bytes;

    #[test]
    fn file_measurement_is_exact() {
        let measured = measure_bytes(b"case-9 manifest").unwrap();
        assert_eq!(measured.byte_length, 15);
        assert_eq!(
            hex::encode(measured.sha256),
            "06451b8ed03ed5b4c4b1fc0d5f59ec5243f183432f5283cd110f796604827803"
        );
    }
}
