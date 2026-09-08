// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Fixed official-lineage custody for terminal-producer source bytes.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, ensure};
use sha2::{Digest as _, Sha256};

use crate::{
    b4::{B4PositiveArtifactRole, canonical_positive_case_artifact_path},
    b4_campaign_contract::{
        B4CampaignPrecommitAuthorityV1, B4ContractArtifactEncodingV1, B4ContractArtifactIdentityV1,
        B4PositiveGenerationAuthorityV2,
    },
    b4_materialization_set::{
        compiled_positive_case_id, compiled_positive_generation_recipe,
        parse_positive_input_sources, parse_positive_input_sources_v2, positive_artifact_layout,
    },
    b4_positive_gate::{B4PositiveGenerationAuthorityV1, FileMeasurement},
    b4_positive_source_auth::{
        B4PositiveCaseSourceV1, B4PositiveCaseSourceV2, B4PositiveGenerationDocumentV1,
        B4PositiveGenerationDocumentV2, B4PositiveSourceBytesV1, B4PositiveSourceBytesV2,
        authenticate_external_identity, authenticate_external_identity_v2,
        authenticate_positive_case_source, bind_external_path, merge_prior_paths,
    },
    parse_ergo_statement_v1,
};

/// Exact external bytes at one physically named source path.
#[derive(Clone, Copy, Debug)]
pub struct B4TerminalSourceExternalBytesV1<'a> {
    /// Safe repository-relative physical path.
    pub path: &'a str,
    /// Exact source bytes.
    pub bytes: &'a [u8],
}

/// Exact manifest, primary artifacts, and auxiliary artifacts for one fixed case.
#[derive(Clone, Copy, Debug)]
pub struct B4TerminalSourceCaseExternalV1<'a> {
    /// Exact physical proof-output manifest.
    pub proof_output_manifest: B4TerminalSourceExternalBytesV1<'a>,
    /// Exact ordered primary artifacts.
    pub primary_artifacts: &'a [B4TerminalSourceExternalBytesV1<'a>],
    /// Exact ordered auxiliary artifacts.
    pub auxiliary_artifacts: &'a [B4TerminalSourceExternalBytesV1<'a>],
}

/// Exact fixed external closure for selected cases 0, 8, and 9.
#[derive(Clone, Copy, Debug)]
pub struct B4TerminalSourceExternalClosureV1<'a> {
    /// Exact positive input-set bytes.
    pub positive_input_set: B4TerminalSourceExternalBytesV1<'a>,
    /// Exact positive generation-set bytes.
    pub positive_generation_set: B4TerminalSourceExternalBytesV1<'a>,
    /// Exact consumer guest ELF bytes.
    pub guest_elf: B4TerminalSourceExternalBytesV1<'a>,
    /// Exact positive case-0 lift-15 closure.
    pub case0_lift15: B4TerminalSourceCaseExternalV1<'a>,
    /// Exact positive case-8 terminal-join closure.
    pub case8_terminal_join: B4TerminalSourceCaseExternalV1<'a>,
    /// Exact positive case-9 terminal-resolve closure.
    pub case9_terminal_resolve: B4TerminalSourceCaseExternalV1<'a>,
}

/// Exact external bytes at one V2 terminal-source path.
#[derive(Clone, Copy, Debug)]
pub struct B4TerminalSourceExternalBytesV2<'a> {
    /// Safe repository-relative physical path.
    pub path: &'a str,
    /// Exact source bytes.
    pub bytes: &'a [u8],
}

/// Exact V2 manifest, primary artifacts, and auxiliary artifacts for one case.
#[derive(Clone, Copy, Debug)]
pub struct B4TerminalSourceCaseExternalV2<'a> {
    /// Exact path-qualified proof-output manifest.
    pub proof_output_manifest: B4TerminalSourceExternalBytesV2<'a>,
    /// Exact ordered primary artifacts.
    pub primary_artifacts: &'a [B4TerminalSourceExternalBytesV2<'a>],
    /// Exact ordered auxiliary artifacts.
    pub auxiliary_artifacts: &'a [B4TerminalSourceExternalBytesV2<'a>],
}

/// Exact V2 terminal-source closure for selected cases 0, 8, and 9.
///
/// The shared campaign precommit remains V1; every positive document and
/// authority in this branch is explicitly V2.
#[derive(Clone, Copy, Debug)]
pub struct B4TerminalSourceExternalClosureV2<'a> {
    /// Exact path-qualified canonical V2 positive input set.
    pub positive_input_set: B4TerminalSourceExternalBytesV2<'a>,
    /// Exact path-qualified canonical V2 positive generation set.
    pub positive_generation_set: B4TerminalSourceExternalBytesV2<'a>,
    /// Exact consumer guest ELF bytes.
    pub guest_elf: B4TerminalSourceExternalBytesV2<'a>,
    /// Exact V2 positive case-0 lift-15 closure.
    pub case0_lift15: B4TerminalSourceCaseExternalV2<'a>,
    /// Exact V2 positive case-8 terminal-join closure.
    pub case8_terminal_join: B4TerminalSourceCaseExternalV2<'a>,
    /// Exact V2 positive case-9 terminal-resolve closure.
    pub case9_terminal_resolve: B4TerminalSourceCaseExternalV2<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct B4TerminalPathlessIdentityV1 {
    encoding: B4ContractArtifactEncodingV1,
    byte_length: u64,
    sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "private custody is intentionally retained without public measurement readers"
)]
struct B4TerminalCaseCustodyV1 {
    case_index: usize,
    case_id: String,
    proof_output_manifest: FileMeasurement,
    primary_measurements: Vec<FileMeasurement>,
    auxiliary_measurements: Vec<FileMeasurement>,
    opaque_proof_output_manifest: FileMeasurement,
    opaque_raw_seal: FileMeasurement,
}

#[allow(
    dead_code,
    reason = "private V2 custody is retained without public measurement readers"
)]
struct B4TerminalCaseCustodyV2 {
    case_index: usize,
    case_id: String,
    proof_output_manifest: FileMeasurement,
    primary_measurements: Vec<FileMeasurement>,
    auxiliary_measurements: Vec<FileMeasurement>,
}

#[derive(Clone, Copy, Debug)]
enum LineageFailureBoundary {
    CampaignPositiveInput,
    InputIdentity,
    GenerationIdentity,
    GeneratorExecutorContent,
    PriorPathMerge,
    GuestIdentity,
    GuestImageId,
    SelectedManifestPath,
    SelectedPhysicalCase,
    SelectedProgramIdentity,
    CommonStatement,
    StatementFields,
    RetainedCampaignAuthority,
    RetainedPositiveInputAuthority,
    RetainedPositiveGenerationAuthority,
    RetainedAuthorityProvenance,
    RetainedPositiveCaseCustody,
}

impl LineageFailureBoundary {
    const fn label(self) -> &'static str {
        match self {
            Self::CampaignPositiveInput => "CampaignPositiveInput",
            Self::InputIdentity => "InputIdentity",
            Self::GenerationIdentity => "GenerationIdentity",
            Self::GeneratorExecutorContent => "GeneratorExecutorContent",
            Self::PriorPathMerge => "PriorPathMerge",
            Self::GuestIdentity => "GuestIdentity",
            Self::GuestImageId => "GuestImageId",
            Self::SelectedManifestPath => "SelectedManifestPath",
            Self::SelectedPhysicalCase => "SelectedPhysicalCase",
            Self::SelectedProgramIdentity => "SelectedProgramIdentity",
            Self::CommonStatement => "CommonStatement",
            Self::StatementFields => "StatementFields",
            Self::RetainedCampaignAuthority => "RetainedCampaignAuthority",
            Self::RetainedPositiveInputAuthority => "RetainedPositiveInputAuthority",
            Self::RetainedPositiveGenerationAuthority => "RetainedPositiveGenerationAuthority",
            Self::RetainedAuthorityProvenance => "RetainedAuthorityProvenance",
            Self::RetainedPositiveCaseCustody => "RetainedPositiveCaseCustody",
        }
    }
}

/// Opaque fixed-lineage authority for the five terminal-producer byte strings.
///
/// The type is intentionally non-serializable and exposes no unchecked
/// constructor.
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_source_lineage::
///     B4TerminalSourceLineageAuthorityV1;
///
/// fn require_serialize<T: serde::Serialize>() {}
///
/// require_serialize::<B4TerminalSourceLineageAuthorityV1>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_source_lineage::
///     B4TerminalSourceLineageAuthorityV1;
///
/// fn require_deserialize<T: serde::de::DeserializeOwned>() {}
///
/// require_deserialize::<B4TerminalSourceLineageAuthorityV1>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_source_lineage::
///     B4TerminalSourceLineageAuthorityV1;
///
/// let _ = B4TerminalSourceLineageAuthorityV1::from_unchecked();
/// ```
#[allow(
    dead_code,
    reason = "opaque lineage measurements are retained without public readers"
)]
pub struct B4TerminalSourceLineageAuthorityV1 {
    campaign_precommit: B4TerminalPathlessIdentityV1,
    positive_input_set: B4TerminalPathlessIdentityV1,
    positive_generation_set: B4TerminalPathlessIdentityV1,
    profile_manifest: B4TerminalPathlessIdentityV1,
    profile_algorithm: B4TerminalPathlessIdentityV1,
    profile_constants: B4TerminalPathlessIdentityV1,
    proof_generator: B4TerminalPathlessIdentityV1,
    guest_identity: B4TerminalPathlessIdentityV1,
    statement_identity: B4TerminalPathlessIdentityV1,
    provenance_paths: BTreeSet<String>,
    case_custody: [B4TerminalCaseCustodyV1; 3],
    guest_elf: Vec<u8>,
    statement: Vec<u8>,
    case0_lift15_receipt_oracle: Vec<u8>,
    case8_terminal_join_recursive_oracle: Vec<u8>,
    case9_terminal_resolve_recursive_oracle: Vec<u8>,
}

impl B4TerminalSourceLineageAuthorityV1 {
    /// Authenticate the one fixed terminal-source lineage closure.
    ///
    /// # Errors
    ///
    /// Returns an error at the first failed opaque identity, physical custody,
    /// program identity, or common-statement boundary.
    #[allow(
        clippy::too_many_lines,
        reason = "the ordered 15-stage fail-closed lineage remains visible for auditability"
    )]
    pub fn from_external_closure(
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV1,
        source: B4TerminalSourceExternalClosureV1<'_>,
    ) -> Result<Self> {
        // 1. Bind the two opaque authorities to the same positive input.
        require_boundary(
            campaign.precommit().input_set == *positive.input_set(),
            LineageFailureBoundary::CampaignPositiveInput,
            "campaign and positive-generation authorities bind different positive input sets",
        )?;
        let campaign_precommit_jcs = campaign
            .to_canonical_precommit_jcs()
            .context(LineageFailureBoundary::CampaignPositiveInput.label())?;

        // 2. Authenticate exact external input and generation paths and bytes.
        authenticate_external_identity(
            positive_source(source.positive_input_set),
            positive.input_set(),
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            "terminal-source positive input set",
        )
        .context(LineageFailureBoundary::InputIdentity.label())?;
        authenticate_external_identity(
            positive_source(source.positive_generation_set),
            positive.generation_set(),
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            "terminal-source positive generation set",
        )
        .context(LineageFailureBoundary::GenerationIdentity.label())?;

        // 3. Parse only the already opaque-authenticated positive input bytes.
        let parsed = parse_positive_input_sources(source.positive_input_set.bytes)
            .context(LineageFailureBoundary::InputIdentity.label())?;

        // 4. Strictly parse generation bytes and bind their pathless input measurement.
        let generation = B4PositiveGenerationDocumentV1::from_canonical_jcs(
            source.positive_generation_set.bytes,
        )
        .context(LineageFailureBoundary::GenerationIdentity.label())?;
        require_measurement_matches_identity(
            generation
                .input_set_measurement()
                .context(LineageFailureBoundary::GenerationIdentity.label())?,
            positive.input_set(),
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            "positive generation input set",
        )
        .context(LineageFailureBoundary::GenerationIdentity.label())?;

        // 5. Compare generator/executor content without comparing their distinct paths.
        let generator_measurement = generation
            .proof_generator_measurement()
            .context(LineageFailureBoundary::GeneratorExecutorContent.label())?;
        require_measurement_matches_identity(
            generator_measurement,
            parsed.generator_identity(),
            B4ContractArtifactEncodingV1::RawBytes,
            "positive generation proof generator",
        )
        .context(LineageFailureBoundary::GeneratorExecutorContent.label())?;
        require_measurement_matches_identity(
            generator_measurement,
            &campaign.precommit().campaign_executor.artifact,
            B4ContractArtifactEncodingV1::RawBytes,
            "campaign executor",
        )
        .context(LineageFailureBoundary::GeneratorExecutorContent.label())?;
        require_same_raw_content(
            parsed.generator_identity(),
            &campaign.precommit().campaign_executor.artifact,
            "positive generator and campaign executor",
        )
        .context(LineageFailureBoundary::GeneratorExecutorContent.label())?;

        // 6. Merge both complete prior path antichains before selected paths.
        require_boundary(
            !campaign
                .artifact_paths()
                .contains(&positive.generation_set().path),
            LineageFailureBoundary::PriorPathMerge,
            "campaign preclaims/collides with the post-proof positive generation-set path",
        )?;
        let mut provenance_paths = BTreeSet::new();
        merge_prior_paths(&mut provenance_paths, campaign.artifact_paths())
            .context(LineageFailureBoundary::PriorPathMerge.label())?;
        merge_prior_paths(&mut provenance_paths, positive.provenance_paths())
            .context(LineageFailureBoundary::PriorPathMerge.label())?;

        // 7. Permit exact replay only for input, generation, and guest.
        authenticate_external_identity(
            positive_source(source.positive_input_set),
            positive.input_set(),
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            "terminal-source positive input replay",
        )
        .context(LineageFailureBoundary::InputIdentity.label())?;
        bind_external_path(
            &mut provenance_paths,
            source.positive_input_set.path,
            true,
            "terminal-source positive input replay",
        )
        .context(LineageFailureBoundary::InputIdentity.label())?;
        authenticate_external_identity(
            positive_source(source.positive_generation_set),
            positive.generation_set(),
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            "terminal-source positive generation replay",
        )
        .context(LineageFailureBoundary::GenerationIdentity.label())?;
        bind_external_path(
            &mut provenance_paths,
            source.positive_generation_set.path,
            true,
            "terminal-source positive generation replay",
        )
        .context(LineageFailureBoundary::GenerationIdentity.label())?;
        authenticate_external_identity(
            positive_source(source.guest_elf),
            parsed.guest_elf_identity(),
            B4ContractArtifactEncodingV1::RawBytes,
            "terminal-source guest ELF",
        )
        .context(LineageFailureBoundary::GuestIdentity.label())?;
        bind_external_path(
            &mut provenance_paths,
            source.guest_elf.path,
            true,
            "terminal-source guest ELF replay",
        )
        .context(LineageFailureBoundary::GuestIdentity.label())?;

        // 8. Bind the exact guest ELF to the positive-input image ID.
        let guest_image_id: [u8; 32] = risc0_binfmt::compute_image_id(source.guest_elf.bytes)
            .context(LineageFailureBoundary::GuestImageId.label())?
            .into();
        require_boundary(
            hex::encode(guest_image_id) == parsed.guest_image_id_hex(),
            LineageFailureBoundary::GuestImageId,
            "terminal-source guest ELF image ID differs from the positive input",
        )?;

        // 9. Bind named physical manifests, then authenticate literal cases 0, 8, and 9.
        bind_manifest_path(
            &mut provenance_paths,
            &crate::b4_materialization_set::compiled_positive_case_id(0)
                .context(LineageFailureBoundary::SelectedManifestPath.label())?,
            "candidate-proof-output-manifest.json",
            source.case0_lift15.proof_output_manifest,
        )
        .context(LineageFailureBoundary::SelectedManifestPath.label())?;
        let case0_primary = positive_case_sources(source.case0_lift15.primary_artifacts);
        let case0_auxiliary = positive_case_sources(source.case0_lift15.auxiliary_artifacts);
        let case0 = authenticate_positive_case_source(
            &generation,
            &positive.cases()[0],
            0,
            B4PositiveCaseSourceV1 {
                proof_output_manifest_jcs: source.case0_lift15.proof_output_manifest.bytes,
                primary_artifacts: &case0_primary,
                auxiliary_artifacts: &case0_auxiliary,
            },
            &mut provenance_paths,
        )
        .context(LineageFailureBoundary::SelectedPhysicalCase.label())?;

        bind_manifest_path(
            &mut provenance_paths,
            &crate::b4_materialization_set::compiled_positive_case_id(8)
                .context(LineageFailureBoundary::SelectedManifestPath.label())?,
            "candidate-recursive-output-manifest.json",
            source.case8_terminal_join.proof_output_manifest,
        )
        .context(LineageFailureBoundary::SelectedManifestPath.label())?;
        let case8_primary = positive_case_sources(source.case8_terminal_join.primary_artifacts);
        let case8_auxiliary = positive_case_sources(source.case8_terminal_join.auxiliary_artifacts);
        let case8 = authenticate_positive_case_source(
            &generation,
            &positive.cases()[8],
            8,
            B4PositiveCaseSourceV1 {
                proof_output_manifest_jcs: source.case8_terminal_join.proof_output_manifest.bytes,
                primary_artifacts: &case8_primary,
                auxiliary_artifacts: &case8_auxiliary,
            },
            &mut provenance_paths,
        )
        .context(LineageFailureBoundary::SelectedPhysicalCase.label())?;

        bind_manifest_path(
            &mut provenance_paths,
            &crate::b4_materialization_set::compiled_positive_case_id(9)
                .context(LineageFailureBoundary::SelectedManifestPath.label())?,
            "candidate-recursive-output-manifest.json",
            source.case9_terminal_resolve.proof_output_manifest,
        )
        .context(LineageFailureBoundary::SelectedManifestPath.label())?;
        let case9_primary = positive_case_sources(source.case9_terminal_resolve.primary_artifacts);
        let case9_auxiliary =
            positive_case_sources(source.case9_terminal_resolve.auxiliary_artifacts);
        let case9 = authenticate_positive_case_source(
            &generation,
            &positive.cases()[9],
            9,
            B4PositiveCaseSourceV1 {
                proof_output_manifest_jcs: source
                    .case9_terminal_resolve
                    .proof_output_manifest
                    .bytes,
                primary_artifacts: &case9_primary,
                auxiliary_artifacts: &case9_auxiliary,
            },
            &mut provenance_paths,
        )
        .context(LineageFailureBoundary::SelectedPhysicalCase.label())?;

        // 10. Require the three literal recipes and exact 7/0, 8/2, 8/2 shapes.
        require_boundary(
            compiled_positive_generation_recipe(0)?
                == serde_json::json!({"kind": "lift", "segmentPo2": 15})
                && compiled_positive_generation_recipe(8)?
                    == serde_json::json!({"kind": "recursive", "family": "terminal-join"})
                && compiled_positive_generation_recipe(9)?
                    == serde_json::json!({"kind": "recursive", "family": "terminal-resolve"})
                && case0.primary_measurements().len() == 7
                && case0.auxiliary_measurements().is_empty()
                && case8.primary_measurements().len() == 8
                && case8.auxiliary_measurements().len() == 2
                && case9.primary_measurements().len() == 8
                && case9.auxiliary_measurements().len() == 2,
            LineageFailureBoundary::SelectedPhysicalCase,
            "terminal-source selected cases differ from the fixed recipes or cardinalities",
        )?;

        // 11. Bind every selected image-ID artifact to the computed guest image ID.
        require_boundary(
            case0.image_id() == guest_image_id
                && case8.image_id() == guest_image_id
                && case9.image_id() == guest_image_id,
            LineageFailureBoundary::SelectedProgramIdentity,
            "terminal-source selected image IDs differ from the guest program",
        )?;

        // 12. Require byte-identical journals and the exact input-committed measurement.
        let common_journal = case0.journal();
        require_boundary(
            case8.journal() == common_journal && case9.journal() == common_journal,
            LineageFailureBoundary::CommonStatement,
            "terminal-source selected cases do not share one byte-identical statement",
        )?;
        let statement_measurement = measure_bytes(common_journal)?;
        require_boundary(
            statement_measurement.byte_length == parsed.reference_statement_byte_length()
                && hex::encode(statement_measurement.sha256) == parsed.reference_statement_sha256(),
            LineageFailureBoundary::CommonStatement,
            "terminal-source common statement differs from the positive input",
        )?;

        // 13. Canonically decode and compare every committed statement field.
        let statement = parse_ergo_statement_v1(common_journal)
            .context(LineageFailureBoundary::StatementFields.label())?;
        require_boundary(
            statement
                .encode()
                .context(LineageFailureBoundary::StatementFields.label())?
                == common_journal,
            LineageFailureBoundary::StatementFields,
            "terminal-source statement does not re-encode byte-identically",
        )?;
        require_boundary(
            hex::encode(statement.profile_id()) == parsed.profile_id
                && hex::encode(statement.program_id()) == parsed.guest_image_id_hex()
                && hex::encode(statement.contract_id()) == parsed.reference_contract_id()
                && hex::encode(statement.chain_domain_id()) == parsed.reference_chain_domain_id()
                && u64::try_from(statement.application_payload().len())?
                    == parsed.reference_application_payload_byte_length()
                && hex::encode(statement.application_payload_sha256())
                    == parsed.reference_application_payload_sha256(),
            LineageFailureBoundary::StatementFields,
            "terminal-source statement fields differ from the positive input",
        )?;

        // 14. Copy only the guest, statement, and three receipt-oracle byte strings.
        let guest_elf = source.guest_elf.bytes.to_vec();
        let statement = common_journal.to_vec();
        let case0_lift15_receipt_oracle = case0.receipt_oracle().to_vec();
        let case8_terminal_join_recursive_oracle = case8.receipt_oracle().to_vec();
        let case9_terminal_resolve_recursive_oracle = case9.receipt_oracle().to_vec();

        // 15. Construct only after every retained identity and custody record closes.
        Ok(Self {
            campaign_precommit: pathless_bytes(
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &campaign_precommit_jcs,
            )?,
            positive_input_set: pathless_identity(positive.input_set()),
            positive_generation_set: pathless_identity(positive.generation_set()),
            profile_manifest: pathless_identity(&parsed.profile_manifest),
            profile_algorithm: pathless_identity(&parsed.profile_algorithm),
            profile_constants: pathless_identity(&parsed.profile_constants),
            proof_generator: pathless_identity(parsed.generator_identity()),
            guest_identity: pathless_identity(parsed.guest_elf_identity()),
            statement_identity: pathless_measurement(
                B4ContractArtifactEncodingV1::RawBytes,
                statement_measurement,
            ),
            provenance_paths,
            case_custody: [
                case_custody(&case0, &positive.cases()[0]),
                case_custody(&case8, &positive.cases()[8]),
                case_custody(&case9, &positive.cases()[9]),
            ],
            guest_elf,
            statement,
            case0_lift15_receipt_oracle,
            case8_terminal_join_recursive_oracle,
            case9_terminal_resolve_recursive_oracle,
        })
    }

    /// Verify that this lineage remains bound to the exact supplied campaign
    /// and positive-generation authorities.
    ///
    /// This check returns no lineage projection and constructs no replacement
    /// authority. It remeasures the canonical campaign precommit, compares the
    /// retained pathless positive identities, rechecks the prior provenance
    /// closure, and binds the retained selected-case custody back to the
    /// positive-generation authority.
    ///
    /// # Errors
    ///
    /// Returns an error if either supplied authority differs from the
    /// construction-time authorities or if a comparable retained provenance or
    /// selected-case custody invariant no longer closes.
    pub fn verify_authority_bindings(
        &self,
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV1,
    ) -> Result<()> {
        let canonical_precommit = campaign
            .to_canonical_precommit_jcs()
            .context(LineageFailureBoundary::RetainedCampaignAuthority.label())?;
        require_boundary(
            pathless_bytes(
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &canonical_precommit,
            )? == self.campaign_precommit,
            LineageFailureBoundary::RetainedCampaignAuthority,
            "supplied campaign precommit differs from the retained terminal-source lineage",
        )?;
        require_boundary(
            pathless_identity(positive.input_set()) == self.positive_input_set,
            LineageFailureBoundary::RetainedPositiveInputAuthority,
            "supplied positive input identity differs from the retained terminal-source lineage",
        )?;
        require_boundary(
            pathless_identity(positive.generation_set()) == self.positive_generation_set,
            LineageFailureBoundary::RetainedPositiveGenerationAuthority,
            "supplied positive generation identity differs from the retained terminal-source lineage",
        )?;
        require_boundary(
            campaign.precommit().input_set == *positive.input_set(),
            LineageFailureBoundary::RetainedPositiveInputAuthority,
            "supplied campaign and positive-generation authorities bind different positive inputs",
        )?;
        require_boundary(
            pathless_identity(&campaign.precommit().campaign_executor.artifact)
                == self.proof_generator,
            LineageFailureBoundary::RetainedCampaignAuthority,
            "supplied campaign executor differs from the retained terminal-source proof generator",
        )?;

        let mut supplied_prior_paths = BTreeSet::new();
        merge_prior_paths(&mut supplied_prior_paths, campaign.artifact_paths())
            .context(LineageFailureBoundary::RetainedAuthorityProvenance.label())?;
        merge_prior_paths(&mut supplied_prior_paths, positive.provenance_paths())
            .context(LineageFailureBoundary::RetainedAuthorityProvenance.label())?;
        let mut retained_paths = BTreeSet::new();
        merge_prior_paths(&mut retained_paths, &self.provenance_paths)
            .context(LineageFailureBoundary::RetainedAuthorityProvenance.label())?;
        require_boundary(
            supplied_prior_paths.is_subset(&retained_paths),
            LineageFailureBoundary::RetainedAuthorityProvenance,
            "supplied authority provenance is absent from the retained terminal-source closure",
        )?;

        for (custody, case_index) in self.case_custody.iter().zip([0_usize, 8, 9]) {
            verify_retained_case_custody(custody, positive, case_index)?;
        }
        Ok(())
    }

    /// Borrow the exact five downstream terminal-producer sources.
    #[must_use]
    pub fn producer_source(&self) -> B4TerminalSourceProducerViewV1<'_> {
        B4TerminalSourceProducerViewV1 {
            guest_elf: &self.guest_elf,
            statement: &self.statement,
            case0_lift15_receipt_oracle: &self.case0_lift15_receipt_oracle,
            case8_terminal_join_recursive_oracle: &self.case8_terminal_join_recursive_oracle,
            case9_terminal_resolve_recursive_oracle: &self.case9_terminal_resolve_recursive_oracle,
        }
    }
}

/// Opaque fixed-lineage authority for the V2 terminal-producer sources.
///
/// This is a parallel affine branch. It cannot be serialized, decoded,
/// cloned, converted from V1, or supplied to a V1 terminal consumer.
/// It only carries the pre-acceptance V2 generation lineage and grants no
/// positive-gate, campaign-approval, live-session, or H0 authority.
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_source_lineage::
///     B4TerminalSourceLineageAuthorityV2;
/// fn require_clone<T: Clone>() {}
/// require_clone::<B4TerminalSourceLineageAuthorityV2>();
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_source_lineage::
///     B4TerminalSourceLineageAuthorityV2;
/// fn require_serialize<T: serde::Serialize>() {}
/// require_serialize::<B4TerminalSourceLineageAuthorityV2>();
/// ```
#[allow(
    dead_code,
    reason = "opaque V2 lineage measurements are retained without public readers"
)]
pub struct B4TerminalSourceLineageAuthorityV2 {
    campaign_precommit: B4TerminalPathlessIdentityV1,
    positive_input_set: B4TerminalPathlessIdentityV1,
    positive_generation_set: B4TerminalPathlessIdentityV1,
    profile_manifest: B4TerminalPathlessIdentityV1,
    profile_algorithm: B4TerminalPathlessIdentityV1,
    profile_constants: B4TerminalPathlessIdentityV1,
    proof_generator: B4TerminalPathlessIdentityV1,
    guest_identity: B4TerminalPathlessIdentityV1,
    statement_identity: B4TerminalPathlessIdentityV1,
    provenance_paths: BTreeSet<String>,
    case_custody: [B4TerminalCaseCustodyV2; 3],
    guest_elf: Vec<u8>,
    statement: Vec<u8>,
    case0_lift15_receipt_oracle: Vec<u8>,
    case8_terminal_join_recursive_oracle: Vec<u8>,
    case9_terminal_resolve_recursive_oracle: Vec<u8>,
}

impl B4TerminalSourceLineageAuthorityV2 {
    /// Authenticate one V2 terminal-source lineage against the shared campaign
    /// precommit and the affine V2 positive-generation authority.
    ///
    /// # Errors
    ///
    /// Returns an error at the first V2 document, authority, physical-source,
    /// program, statement, or path-custody mismatch.
    #[allow(
        clippy::too_many_lines,
        reason = "the explicit V2 lineage branch keeps its ordered fail-closed joins visible"
    )]
    pub fn from_external_closure(
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV2,
        source: B4TerminalSourceExternalClosureV2<'_>,
    ) -> Result<Self> {
        require_boundary(
            campaign.precommit().input_set == *positive.input_set(),
            LineageFailureBoundary::CampaignPositiveInput,
            "campaign and V2 positive-generation authorities bind different positive input sets",
        )?;
        let campaign_precommit_jcs = campaign
            .to_canonical_precommit_jcs()
            .context(LineageFailureBoundary::CampaignPositiveInput.label())?;

        authenticate_external_identity_v2(
            positive_source_v2(source.positive_input_set),
            positive.input_set(),
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            "terminal-source V2 positive input set",
        )
        .context(LineageFailureBoundary::InputIdentity.label())?;
        authenticate_external_identity_v2(
            positive_source_v2(source.positive_generation_set),
            positive.generation_set(),
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            "terminal-source V2 positive generation set",
        )
        .context(LineageFailureBoundary::GenerationIdentity.label())?;

        let parsed = parse_positive_input_sources_v2(source.positive_input_set.bytes)
            .context(LineageFailureBoundary::InputIdentity.label())?;
        let generation = B4PositiveGenerationDocumentV2::from_canonical_jcs(
            source.positive_generation_set.bytes,
        )
        .context(LineageFailureBoundary::GenerationIdentity.label())?;
        require_measurement_matches_identity(
            generation
                .input_set_measurement()
                .context(LineageFailureBoundary::GenerationIdentity.label())?,
            positive.input_set(),
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            "V2 positive generation input set",
        )
        .context(LineageFailureBoundary::GenerationIdentity.label())?;

        let generator_measurement = generation
            .proof_generator_measurement()
            .context(LineageFailureBoundary::GeneratorExecutorContent.label())?;
        require_measurement_matches_identity(
            generator_measurement,
            &parsed.generator,
            B4ContractArtifactEncodingV1::RawBytes,
            "V2 positive generation proof generator",
        )
        .context(LineageFailureBoundary::GeneratorExecutorContent.label())?;
        require_measurement_matches_identity(
            generator_measurement,
            &campaign.precommit().campaign_executor.artifact,
            B4ContractArtifactEncodingV1::RawBytes,
            "V2 campaign executor",
        )
        .context(LineageFailureBoundary::GeneratorExecutorContent.label())?;
        require_same_raw_content(
            &parsed.generator,
            &campaign.precommit().campaign_executor.artifact,
            "V2 positive generator and campaign executor",
        )
        .context(LineageFailureBoundary::GeneratorExecutorContent.label())?;

        let mut provenance_paths = BTreeSet::new();
        merge_prior_paths(&mut provenance_paths, campaign.artifact_paths())
            .context(LineageFailureBoundary::PriorPathMerge.label())?;
        merge_prior_paths(&mut provenance_paths, positive.provenance_paths())
            .context(LineageFailureBoundary::PriorPathMerge.label())?;

        authenticate_external_identity_v2(
            positive_source_v2(source.positive_input_set),
            positive.input_set(),
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            "terminal-source V2 positive input replay",
        )
        .context(LineageFailureBoundary::InputIdentity.label())?;
        bind_external_path(
            &mut provenance_paths,
            source.positive_input_set.path,
            true,
            "terminal-source V2 positive input replay",
        )?;
        authenticate_external_identity_v2(
            positive_source_v2(source.positive_generation_set),
            positive.generation_set(),
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            "terminal-source V2 positive generation replay",
        )
        .context(LineageFailureBoundary::GenerationIdentity.label())?;
        bind_external_path(
            &mut provenance_paths,
            source.positive_generation_set.path,
            true,
            "terminal-source V2 positive generation replay",
        )?;
        authenticate_external_identity_v2(
            positive_source_v2(source.guest_elf),
            &parsed.guest_elf,
            B4ContractArtifactEncodingV1::RawBytes,
            "terminal-source V2 guest ELF",
        )
        .context(LineageFailureBoundary::GuestIdentity.label())?;
        bind_external_path(
            &mut provenance_paths,
            source.guest_elf.path,
            true,
            "terminal-source V2 guest ELF replay",
        )?;

        let guest_image_id: [u8; 32] = risc0_binfmt::compute_image_id(source.guest_elf.bytes)
            .context(LineageFailureBoundary::GuestImageId.label())?
            .into();
        require_boundary(
            hex::encode(guest_image_id) == parsed.guest_image_id,
            LineageFailureBoundary::GuestImageId,
            "terminal-source V2 guest ELF image ID differs from the positive input",
        )?;

        let case0 = authenticate_terminal_v2_case(
            positive,
            0,
            "candidate-proof-output-manifest.json",
            source.case0_lift15,
            &mut provenance_paths,
        )?;
        let case8 = authenticate_terminal_v2_case(
            positive,
            8,
            "candidate-recursive-output-manifest.json",
            source.case8_terminal_join,
            &mut provenance_paths,
        )?;
        let case9 = authenticate_terminal_v2_case(
            positive,
            9,
            "candidate-recursive-output-manifest.json",
            source.case9_terminal_resolve,
            &mut provenance_paths,
        )?;

        require_boundary(
            compiled_positive_generation_recipe(0)?
                == serde_json::json!({"kind": "lift", "segmentPo2": 15})
                && compiled_positive_generation_recipe(8)?
                    == serde_json::json!({"kind": "recursive", "family": "terminal-join"})
                && compiled_positive_generation_recipe(9)?
                    == serde_json::json!({"kind": "recursive", "family": "terminal-resolve"})
                && case0.primary_measurements().len() == 7
                && case0.auxiliary_measurements().is_empty()
                && case8.primary_measurements().len() == 8
                && case8.auxiliary_measurements().len() == 2
                && case9.primary_measurements().len() == 8
                && case9.auxiliary_measurements().len() == 2,
            LineageFailureBoundary::SelectedPhysicalCase,
            "terminal-source V2 selected cases differ from fixed recipes or cardinalities",
        )?;
        require_boundary(
            case0.image_id() == guest_image_id
                && case8.image_id() == guest_image_id
                && case9.image_id() == guest_image_id,
            LineageFailureBoundary::SelectedProgramIdentity,
            "terminal-source V2 selected image IDs differ from the guest program",
        )?;

        let common_journal = case0.journal();
        require_boundary(
            case8.journal() == common_journal && case9.journal() == common_journal,
            LineageFailureBoundary::CommonStatement,
            "terminal-source V2 selected cases do not share one byte-identical statement",
        )?;
        let statement_measurement = measure_bytes(common_journal)?;
        require_boundary(
            statement_measurement.byte_length == parsed.reference_statement_byte_length()
                && hex::encode(statement_measurement.sha256) == parsed.reference_statement_sha256(),
            LineageFailureBoundary::CommonStatement,
            "terminal-source V2 common statement differs from the positive input",
        )?;
        let statement = parse_ergo_statement_v1(common_journal)
            .context(LineageFailureBoundary::StatementFields.label())?;
        require_boundary(
            statement
                .encode()
                .context(LineageFailureBoundary::StatementFields.label())?
                == common_journal,
            LineageFailureBoundary::StatementFields,
            "terminal-source V2 statement does not re-encode byte-identically",
        )?;
        require_boundary(
            hex::encode(statement.profile_id()) == parsed.profile_id
                && hex::encode(statement.program_id()) == parsed.guest_image_id
                && hex::encode(statement.contract_id()) == parsed.reference_contract_id()
                && hex::encode(statement.chain_domain_id()) == parsed.reference_chain_domain_id()
                && u64::try_from(statement.application_payload().len())?
                    == parsed.reference_application_payload_byte_length()
                && hex::encode(statement.application_payload_sha256())
                    == parsed.reference_application_payload_sha256(),
            LineageFailureBoundary::StatementFields,
            "terminal-source V2 statement fields differ from the positive input",
        )?;

        let guest_elf = source.guest_elf.bytes.to_vec();
        let statement = common_journal.to_vec();
        let case0_lift15_receipt_oracle = case0.receipt_oracle().to_vec();
        let case8_terminal_join_recursive_oracle = case8.receipt_oracle().to_vec();
        let case9_terminal_resolve_recursive_oracle = case9.receipt_oracle().to_vec();
        Ok(Self {
            campaign_precommit: pathless_bytes(
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &campaign_precommit_jcs,
            )?,
            positive_input_set: pathless_identity(positive.input_set()),
            positive_generation_set: pathless_identity(positive.generation_set()),
            profile_manifest: pathless_identity(&parsed.profile_manifest),
            profile_algorithm: pathless_identity(&parsed.profile_algorithm),
            profile_constants: pathless_identity(&parsed.profile_constants),
            proof_generator: pathless_identity(&parsed.generator),
            guest_identity: pathless_identity(&parsed.guest_elf),
            statement_identity: pathless_measurement(
                B4ContractArtifactEncodingV1::RawBytes,
                statement_measurement,
            ),
            provenance_paths,
            case_custody: [
                case_custody_v2(&case0),
                case_custody_v2(&case8),
                case_custody_v2(&case9),
            ],
            guest_elf,
            statement,
            case0_lift15_receipt_oracle,
            case8_terminal_join_recursive_oracle,
            case9_terminal_resolve_recursive_oracle,
        })
    }

    /// Recheck that this lineage remains bound to the exact campaign and V2
    /// generation authorities supplied at construction.
    pub fn verify_authority_bindings(
        &self,
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV2,
    ) -> Result<()> {
        let canonical_precommit = campaign
            .to_canonical_precommit_jcs()
            .context(LineageFailureBoundary::RetainedCampaignAuthority.label())?;
        require_boundary(
            pathless_bytes(
                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                &canonical_precommit,
            )? == self.campaign_precommit,
            LineageFailureBoundary::RetainedCampaignAuthority,
            "supplied campaign precommit differs from the retained V2 lineage",
        )?;
        require_boundary(
            pathless_identity(positive.input_set()) == self.positive_input_set
                && campaign.precommit().input_set == *positive.input_set(),
            LineageFailureBoundary::RetainedPositiveInputAuthority,
            "supplied V2 positive input authority differs from the retained lineage",
        )?;
        require_boundary(
            pathless_identity(positive.generation_set()) == self.positive_generation_set,
            LineageFailureBoundary::RetainedPositiveGenerationAuthority,
            "supplied V2 positive generation authority differs from the retained lineage",
        )?;
        require_boundary(
            pathless_identity(&campaign.precommit().campaign_executor.artifact)
                == self.proof_generator,
            LineageFailureBoundary::RetainedCampaignAuthority,
            "supplied campaign executor differs from the retained V2 proof generator",
        )?;
        let mut supplied_paths = BTreeSet::new();
        merge_prior_paths(&mut supplied_paths, campaign.artifact_paths())?;
        merge_prior_paths(&mut supplied_paths, positive.provenance_paths())?;
        require_boundary(
            supplied_paths.is_subset(&self.provenance_paths),
            LineageFailureBoundary::RetainedAuthorityProvenance,
            "supplied V2 authority provenance is absent from the retained lineage",
        )?;
        for (custody, case_index) in self.case_custody.iter().zip([0_usize, 8, 9]) {
            require_boundary(
                positive.case_custody_matches(
                    case_index,
                    &custody.case_id,
                    custody.proof_output_manifest,
                    &custody.primary_measurements,
                    &custody.auxiliary_measurements,
                ),
                LineageFailureBoundary::RetainedPositiveCaseCustody,
                "supplied V2 selected-case authority differs from retained lineage custody",
            )?;
        }
        Ok(())
    }

    /// Borrow the exact five V2 terminal-producer sources.
    #[must_use]
    pub fn producer_source(&self) -> B4TerminalSourceProducerViewV2<'_> {
        B4TerminalSourceProducerViewV2 {
            guest_elf: &self.guest_elf,
            statement: &self.statement,
            case0_lift15_receipt_oracle: &self.case0_lift15_receipt_oracle,
            case8_terminal_join_recursive_oracle: &self.case8_terminal_join_recursive_oracle,
            case9_terminal_resolve_recursive_oracle: &self.case9_terminal_resolve_recursive_oracle,
        }
    }
}

fn authenticate_terminal_v2_case<'a>(
    positive: &B4PositiveGenerationAuthorityV2,
    case_index: usize,
    manifest_name: &str,
    external: B4TerminalSourceCaseExternalV2<'a>,
    provenance_paths: &mut BTreeSet<String>,
) -> Result<crate::b4_positive_source_auth::B4AuthenticatedPositiveCaseSourceV2<'a>> {
    let case_id = compiled_positive_case_id(case_index)?;
    let expected_manifest_path = canonical_positive_case_artifact_path(&case_id, manifest_name);
    require_boundary(
        external.proof_output_manifest.path == expected_manifest_path,
        LineageFailureBoundary::SelectedManifestPath,
        "terminal-source V2 manifest path differs from its compiled case directory",
    )?;
    bind_external_path(
        provenance_paths,
        external.proof_output_manifest.path,
        true,
        "terminal-source V2 manifest replay",
    )?;
    for artifact in external
        .primary_artifacts
        .iter()
        .chain(external.auxiliary_artifacts)
    {
        bind_external_path(
            provenance_paths,
            artifact.path,
            true,
            "terminal-source V2 case replay",
        )?;
    }
    let primary = positive_case_sources_v2(external.primary_artifacts);
    let auxiliary = positive_case_sources_v2(external.auxiliary_artifacts);
    positive
        .authenticate_case(
            case_index,
            B4PositiveCaseSourceV2 {
                proof_output_manifest_jcs: external.proof_output_manifest.bytes,
                primary_artifacts: &primary,
                auxiliary_artifacts: &auxiliary,
            },
        )
        .context(LineageFailureBoundary::SelectedPhysicalCase.label())
}

fn positive_source_v2(
    external: B4TerminalSourceExternalBytesV2<'_>,
) -> B4PositiveSourceBytesV2<'_> {
    B4PositiveSourceBytesV2 {
        path: external.path,
        bytes: external.bytes,
    }
}

fn positive_case_sources_v2<'a>(
    external: &[B4TerminalSourceExternalBytesV2<'a>],
) -> Vec<B4PositiveSourceBytesV2<'a>> {
    external.iter().copied().map(positive_source_v2).collect()
}

fn case_custody_v2(
    case: &crate::b4_positive_source_auth::B4AuthenticatedPositiveCaseSourceV2<'_>,
) -> B4TerminalCaseCustodyV2 {
    B4TerminalCaseCustodyV2 {
        case_index: case.case_index(),
        case_id: case.case_id().to_owned(),
        proof_output_manifest: case.proof_output_manifest(),
        primary_measurements: case.primary_measurements().to_vec(),
        auxiliary_measurements: case.auxiliary_measurements().to_vec(),
    }
}

fn positive_source(external: B4TerminalSourceExternalBytesV1<'_>) -> B4PositiveSourceBytesV1<'_> {
    B4PositiveSourceBytesV1 {
        path: external.path,
        bytes: external.bytes,
    }
}

fn positive_case_sources<'a>(
    external: &[B4TerminalSourceExternalBytesV1<'a>],
) -> Vec<B4PositiveSourceBytesV1<'a>> {
    external.iter().copied().map(positive_source).collect()
}

fn require_same_raw_content(
    left: &B4ContractArtifactIdentityV1,
    right: &B4ContractArtifactIdentityV1,
    label: &str,
) -> Result<()> {
    ensure!(
        left.encoding == B4ContractArtifactEncodingV1::RawBytes
            && right.encoding == B4ContractArtifactEncodingV1::RawBytes
            && left.byte_length == right.byte_length
            && left.sha256 == right.sha256,
        "{label} content identity differs"
    );
    Ok(())
}

fn require_measurement_matches_identity(
    measured: FileMeasurement,
    identity: &B4ContractArtifactIdentityV1,
    encoding: B4ContractArtifactEncodingV1,
    label: &str,
) -> Result<()> {
    ensure!(
        identity.encoding == encoding
            && identity.byte_length == measured.byte_length
            && identity.sha256 == hex::encode(measured.sha256),
        "{label} content identity differs"
    );
    Ok(())
}

fn bind_manifest_path(
    paths: &mut BTreeSet<String>,
    case_id: &str,
    manifest_name: &str,
    external: B4TerminalSourceExternalBytesV1<'_>,
) -> Result<()> {
    let expected = canonical_positive_case_artifact_path(case_id, manifest_name);
    ensure!(
        external.path == expected,
        "terminal-source proof-output-manifest path differs from its compiled case directory"
    );
    bind_external_path(paths, external.path, false, "terminal-source manifest")
}

fn measure_bytes(bytes: &[u8]) -> Result<FileMeasurement> {
    Ok(FileMeasurement {
        byte_length: u64::try_from(bytes.len())?,
        sha256: Sha256::digest(bytes).into(),
    })
}

fn pathless_bytes(
    encoding: B4ContractArtifactEncodingV1,
    bytes: &[u8],
) -> Result<B4TerminalPathlessIdentityV1> {
    let measured = measure_bytes(bytes)?;
    Ok(pathless_measurement(encoding, measured))
}

fn pathless_identity(identity: &B4ContractArtifactIdentityV1) -> B4TerminalPathlessIdentityV1 {
    B4TerminalPathlessIdentityV1 {
        encoding: identity.encoding,
        byte_length: identity.byte_length,
        sha256: identity.sha256.clone(),
    }
}

fn require_boundary(
    condition: bool,
    boundary: LineageFailureBoundary,
    message: &'static str,
) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(anyhow::anyhow!(message)).context(boundary.label())
    }
}

fn pathless_measurement(
    encoding: B4ContractArtifactEncodingV1,
    measured: FileMeasurement,
) -> B4TerminalPathlessIdentityV1 {
    B4TerminalPathlessIdentityV1 {
        encoding,
        byte_length: measured.byte_length,
        sha256: hex::encode(measured.sha256),
    }
}

fn case_custody(
    case: &crate::b4_positive_source_auth::B4AuthenticatedPositiveCaseSourceV1<'_>,
    opaque: &crate::b4_positive_gate::B4PositiveGenerationCaseAuthorityV1,
) -> B4TerminalCaseCustodyV1 {
    B4TerminalCaseCustodyV1 {
        case_index: case.case_index(),
        case_id: case.case_id().to_owned(),
        proof_output_manifest: case.proof_output_manifest(),
        primary_measurements: case.primary_measurements().to_vec(),
        auxiliary_measurements: case.auxiliary_measurements().to_vec(),
        opaque_proof_output_manifest: opaque.proof_output_manifest(),
        opaque_raw_seal: opaque.raw_seal(),
    }
}

fn verify_retained_case_custody(
    custody: &B4TerminalCaseCustodyV1,
    positive: &B4PositiveGenerationAuthorityV1,
    case_index: usize,
) -> Result<()> {
    let positive_case = &positive.cases()[case_index];
    let primary_layout = positive_artifact_layout(case_index)
        .context(LineageFailureBoundary::RetainedPositiveCaseCustody.label())?;
    let raw_seal_position = primary_layout
        .iter()
        .position(|(role, _)| *role == B4PositiveArtifactRole::RawSeal)
        .context("fixed positive artifact layout has no raw-seal role")
        .context(LineageFailureBoundary::RetainedPositiveCaseCustody.label())?;
    let expected_auxiliary_count = usize::from(case_index != 0) * 2;
    require_boundary(
        custody.case_index == case_index
            && usize::from(positive_case.case_index()) == case_index
            && custody.case_id == compiled_positive_case_id(case_index)?
            && custody.primary_measurements.len() == primary_layout.len()
            && custody.auxiliary_measurements.len() == expected_auxiliary_count
            && custody.proof_output_manifest == positive_case.proof_output_manifest()
            && custody.opaque_proof_output_manifest == positive_case.proof_output_manifest()
            && custody.opaque_raw_seal == positive_case.raw_seal()
            && custody.primary_measurements.get(raw_seal_position)
                == Some(&positive_case.raw_seal()),
        LineageFailureBoundary::RetainedPositiveCaseCustody,
        "supplied positive selected-case authority differs from retained terminal-source custody",
    )
}

/// Borrowed five-byte-string projection for the existing terminal producer.
///
/// Its fields are private, and no manifest, auxiliary artifact, or raw seal is
/// exposed.
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_source_lineage::
///     B4TerminalSourceProducerViewV1;
///
/// let _ = B4TerminalSourceProducerViewV1 {
///     guest_elf: &[],
///     statement: &[],
///     case0_lift15_receipt_oracle: &[],
///     case8_terminal_join_recursive_oracle: &[],
///     case9_terminal_resolve_recursive_oracle: &[],
/// };
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_source_lineage::
///     B4TerminalSourceProducerViewV1;
///
/// fn forbidden(view: &B4TerminalSourceProducerViewV1<'_>) {
///     let _ = view.case0_lift15_raw_seal();
/// }
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_source_lineage::
///     B4TerminalSourceProducerViewV1;
///
/// fn forbidden(view: &B4TerminalSourceProducerViewV1<'_>) {
///     let _ = view.proof_output_manifest();
/// }
/// ```
///
/// ```compile_fail
/// use eip_0045_reproduction::b4_terminal_source_lineage::
///     B4TerminalSourceProducerViewV1;
///
/// fn forbidden(view: &B4TerminalSourceProducerViewV1<'_>) {
///     let _ = view.auxiliary_artifacts();
/// }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct B4TerminalSourceProducerViewV1<'a> {
    guest_elf: &'a [u8],
    statement: &'a [u8],
    case0_lift15_receipt_oracle: &'a [u8],
    case8_terminal_join_recursive_oracle: &'a [u8],
    case9_terminal_resolve_recursive_oracle: &'a [u8],
}

impl<'a> B4TerminalSourceProducerViewV1<'a> {
    /// Exact consumer guest ELF.
    #[must_use]
    pub const fn guest_elf(&self) -> &'a [u8] {
        self.guest_elf
    }

    /// Exact common `ErgoStatementV1` journal.
    #[must_use]
    pub const fn statement(&self) -> &'a [u8] {
        self.statement
    }

    /// Exact case-0 lift-15 receipt oracle.
    #[must_use]
    pub const fn case0_lift15_receipt_oracle(&self) -> &'a [u8] {
        self.case0_lift15_receipt_oracle
    }

    /// Exact case-8 terminal-join recursive oracle.
    #[must_use]
    pub const fn case8_terminal_join_recursive_oracle(&self) -> &'a [u8] {
        self.case8_terminal_join_recursive_oracle
    }

    /// Exact case-9 terminal-resolve recursive oracle.
    #[must_use]
    pub const fn case9_terminal_resolve_recursive_oracle(&self) -> &'a [u8] {
        self.case9_terminal_resolve_recursive_oracle
    }
}

/// Borrowed five-byte-string projection for the V2 terminal packet importer.
///
/// The projection is branch-specific and exposes no manifest, auxiliary seal,
/// raw seal, authority constructor, or conversion to the V1 producer view.
#[derive(Clone, Copy, Debug)]
pub struct B4TerminalSourceProducerViewV2<'a> {
    guest_elf: &'a [u8],
    statement: &'a [u8],
    case0_lift15_receipt_oracle: &'a [u8],
    case8_terminal_join_recursive_oracle: &'a [u8],
    case9_terminal_resolve_recursive_oracle: &'a [u8],
}

impl<'a> B4TerminalSourceProducerViewV2<'a> {
    /// Exact consumer guest ELF.
    #[must_use]
    pub const fn guest_elf(&self) -> &'a [u8] {
        self.guest_elf
    }

    /// Exact common `ErgoStatementV1` journal.
    #[must_use]
    pub const fn statement(&self) -> &'a [u8] {
        self.statement
    }

    /// Exact case-0 lift-15 receipt oracle.
    #[must_use]
    pub const fn case0_lift15_receipt_oracle(&self) -> &'a [u8] {
        self.case0_lift15_receipt_oracle
    }

    /// Exact case-8 terminal-join recursive oracle.
    #[must_use]
    pub const fn case8_terminal_join_recursive_oracle(&self) -> &'a [u8] {
        self.case8_terminal_join_recursive_oracle
    }

    /// Exact case-9 terminal-resolve recursive oracle.
    #[must_use]
    pub const fn case9_terminal_resolve_recursive_oracle(&self) -> &'a [u8] {
        self.case9_terminal_resolve_recursive_oracle
    }
}

#[cfg(all(test, feature = "recursive-ancestry", feature = "receipt-oracle"))]
mod tests {
    include!("b4_terminal_source_lineage_tests.rs");
}
