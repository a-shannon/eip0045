use super::*;

use std::{borrow::Cow, collections::BTreeSet, sync::OnceLock};

use crate::{
    b4::B4PositiveArtifactRole,
    b4_campaign_contract::test_support::{
        PositiveGenerationConstructorSourcesV2, TerminalLineageAlternateCampaignsV1,
        TerminalLineageConstructorTestSupportV1, TerminalLineageConstructorTestSupportV2,
        build_terminal_lineage_alternate_campaigns,
        build_terminal_lineage_constructor_test_support,
        build_terminal_lineage_constructor_test_support_v2,
        build_terminal_lineage_generation_path_collision_test_support,
    },
    b4_campaign_contract::{B4CampaignPrecommitAuthorityV1, B4PositiveGenerationAuthorityV2},
    b4_materialization_set::{compiled_positive_case_id, positive_artifact_layout},
    b4_positive_gate::{
        B4ValidatedPositiveGenerationPreacceptanceV2,
        test_support::OwnedPositiveAuthorityTestArtifactV1,
    },
    canonical::{canonical_json_bytes, parse_json_strict},
    manifest::{ManifestEntry, ProofOutputManifest},
};

#[test]
fn v2_generation_authority_consumes_only_semantic_predecessor() {
    let _: fn(B4ValidatedPositiveGenerationPreacceptanceV2) -> B4PositiveGenerationAuthorityV2 =
        B4PositiveGenerationAuthorityV2::from_validated;
    let _: for<'a> fn(
        &B4CampaignPrecommitAuthorityV1,
        &B4PositiveGenerationAuthorityV2,
        B4TerminalSourceExternalClosureV2<'a>,
    ) -> anyhow::Result<B4TerminalSourceLineageAuthorityV2> =
        B4TerminalSourceLineageAuthorityV2::from_external_closure;
}

fn terminal_lineage_v2_support() -> &'static TerminalLineageConstructorTestSupportV2 {
    static SUPPORT: OnceLock<TerminalLineageConstructorTestSupportV2> = OnceLock::new();
    SUPPORT.get_or_init(|| {
        build_terminal_lineage_constructor_test_support_v2()
            .expect("production-created campaign-V1 / positive-V2 support")
    })
}

fn mutate_first_byte(bytes: &mut [u8]) {
    bytes[0] ^= 1;
}

fn replace_v2_format(bytes: &mut Vec<u8>, format: &str, version: u8) {
    let mut value = crate::canonical::validate_canonical_json_source(bytes)
        .expect("canonical V2 test document");
    value["format"] = serde_json::json!(format);
    value["formatVersion"] = serde_json::json!(version);
    *bytes = canonical_json_bytes(&value).expect("canonical substituted test document");
}

fn replace_v2_calibrations(
    sources: &mut PositiveGenerationConstructorSourcesV2,
    mutate: impl FnOnce(&mut Vec<serde_json::Value>),
) {
    let mut value =
        crate::canonical::validate_canonical_json_source(&sources.positive_input_set.bytes)
            .expect("canonical V2 positive input set");
    let calibrations = value["recursiveCalibrations"]
        .as_array_mut()
        .expect("fixed recursive calibration array");
    mutate(calibrations);
    sources.positive_input_set.bytes =
        canonical_json_bytes(&value).expect("canonical mutated V2 positive input set");
}

fn require_v2_calibration_join_rejection(sources: &PositiveGenerationConstructorSourcesV2) {
    let error = match sources.validate_preacceptance() {
        Ok(_) => panic!("malformed calibration closure unexpectedly minted the predecessor"),
        Err(error) => error,
    };
    let message = format!("{error:#}");
    assert!(
        message.contains("V2 positive input set fails Draft 2020-12 schema"),
        "calibration mutant missed the semantic side of the full predecessor join: {message}"
    );
}

#[test]
fn v2_generation_authority_closes_all_eleven_physical_exports() {
    let support = terminal_lineage_v2_support();
    assert_eq!(support.sources.cases.len(), 11);
    let _authority = B4PositiveGenerationAuthorityV2::from_validated(
        support
            .sources
            .validate_preacceptance()
            .expect("all eleven V2 exports close through the semantic predecessor"),
    );
}

#[test]
fn v2_generation_authority_rejects_v1_input_format_substitution() {
    let mut sources = terminal_lineage_v2_support().sources.clone();
    replace_v2_format(
        &mut sources.positive_input_set.bytes,
        "Eip0045B4PositiveInputSetV1",
        1,
    );
    assert!(sources.validate_preacceptance().is_err());
}

#[test]
fn v2_generation_authority_rejects_v1_generation_format_substitution() {
    let mut sources = terminal_lineage_v2_support().sources.clone();
    replace_v2_format(
        &mut sources.positive_generation_set.bytes,
        "Eip0045B4PositiveGenerationSetV1",
        1,
    );
    assert!(sources.validate_preacceptance().is_err());
}

#[test]
fn v2_generation_authority_rejects_one_nested_source_substitution() {
    let mut sources = terminal_lineage_v2_support().sources.clone();
    mutate_first_byte(&mut sources.nested_input_sources[0].bytes);
    assert!(sources.validate_preacceptance().is_err());
}

#[test]
fn v2_generation_authority_rejects_proof_generator_substitution() {
    let mut sources = terminal_lineage_v2_support().sources.clone();
    mutate_first_byte(&mut sources.proof_generator.bytes);
    assert!(sources.validate_preacceptance().is_err());
}

#[test]
fn v2_generation_authority_rejects_each_of_eleven_physical_case_substitutions() {
    for case_index in 0..11 {
        let mut sources = terminal_lineage_v2_support().sources.clone();
        mutate_first_byte(&mut sources.cases[case_index].proof_output_manifest.bytes);
        assert!(
            sources.validate_preacceptance().is_err(),
            "physical substitution in V2 case {case_index} bypassed the predecessor"
        );
    }
}

#[test]
fn v2_generation_authority_rejects_missing_calibration_at_the_preacceptance_join() {
    let mut sources = terminal_lineage_v2_support().sources.clone();
    replace_v2_calibrations(&mut sources, |calibrations| {
        calibrations.pop();
    });
    require_v2_calibration_join_rejection(&sources);
}

#[test]
fn v2_generation_authority_rejects_extra_calibration_at_the_preacceptance_join() {
    let mut sources = terminal_lineage_v2_support().sources.clone();
    replace_v2_calibrations(&mut sources, |calibrations| {
        calibrations.push(calibrations[2].clone());
    });
    require_v2_calibration_join_rejection(&sources);
}

#[test]
fn v2_generation_authority_rejects_duplicate_calibration_at_the_preacceptance_join() {
    let mut sources = terminal_lineage_v2_support().sources.clone();
    replace_v2_calibrations(&mut sources, |calibrations| {
        calibrations[1] = calibrations[0].clone();
    });
    require_v2_calibration_join_rejection(&sources);
}

#[test]
fn v2_generation_authority_rejects_reordered_calibrations_at_the_preacceptance_join() {
    let mut sources = terminal_lineage_v2_support().sources.clone();
    replace_v2_calibrations(&mut sources, |calibrations| calibrations.swap(0, 1));
    require_v2_calibration_join_rejection(&sources);
}

fn with_v2_terminal_source_closure<T>(
    sources: &PositiveGenerationConstructorSourcesV2,
    use_closure: impl FnOnce(B4TerminalSourceExternalClosureV2<'_>) -> T,
) -> T {
    let terminal_cases = [0_usize, 8, 9];
    let primary: [Vec<_>; 3] = std::array::from_fn(|position| {
        sources.cases[terminal_cases[position]]
            .primary_artifacts
            .iter()
            .map(|artifact| B4TerminalSourceExternalBytesV2 {
                path: &artifact.path,
                bytes: &artifact.bytes,
            })
            .collect()
    });
    let auxiliary: [Vec<_>; 3] = std::array::from_fn(|position| {
        sources.cases[terminal_cases[position]]
            .auxiliary_artifacts
            .iter()
            .map(|artifact| B4TerminalSourceExternalBytesV2 {
                path: &artifact.path,
                bytes: &artifact.bytes,
            })
            .collect()
    });
    let case = |position: usize| B4TerminalSourceCaseExternalV2 {
        proof_output_manifest: B4TerminalSourceExternalBytesV2 {
            path: &sources.cases[terminal_cases[position]]
                .proof_output_manifest
                .path,
            bytes: &sources.cases[terminal_cases[position]]
                .proof_output_manifest
                .bytes,
        },
        primary_artifacts: &primary[position],
        auxiliary_artifacts: &auxiliary[position],
    };
    let guest = sources
        .nested_input_sources
        .iter()
        .find(|source| source.path == "methods/guest.elf")
        .expect("fixed V2 guest source");
    use_closure(B4TerminalSourceExternalClosureV2 {
        positive_input_set: B4TerminalSourceExternalBytesV2 {
            path: &sources.positive_input_set.path,
            bytes: &sources.positive_input_set.bytes,
        },
        positive_generation_set: B4TerminalSourceExternalBytesV2 {
            path: &sources.positive_generation_set.path,
            bytes: &sources.positive_generation_set.bytes,
        },
        guest_elf: B4TerminalSourceExternalBytesV2 {
            path: &guest.path,
            bytes: &guest.bytes,
        },
        case0_lift15: case(0),
        case8_terminal_join: case(1),
        case9_terminal_resolve: case(2),
    })
}

fn construct_v2_terminal_source_lineage(
    support: &TerminalLineageConstructorTestSupportV2,
    sources: &PositiveGenerationConstructorSourcesV2,
) -> Result<B4TerminalSourceLineageAuthorityV2> {
    with_v2_terminal_source_closure(sources, |source| {
        B4TerminalSourceLineageAuthorityV2::from_external_closure(
            &support.campaign_precommit_authority,
            &support.positive_generation_authority,
            source,
        )
    })
}

#[test]
fn terminal_source_lineage_v2_closes_the_five_exact_producer_sources() {
    let support = terminal_lineage_v2_support();
    let lineage = construct_v2_terminal_source_lineage(support, &support.sources)
        .expect("nominal V2 terminal lineage");
    lineage
        .verify_authority_bindings(
            &support.campaign_precommit_authority,
            &support.positive_generation_authority,
        )
        .expect("retained V2 terminal authority bindings");
    let producer = lineage.producer_source();
    let guest = support
        .sources
        .nested_input_sources
        .iter()
        .find(|source| source.path == "methods/guest.elf")
        .expect("fixed V2 guest source");
    let primary = |case_index: usize, role: B4PositiveArtifactRole| {
        let artifact_index = positive_artifact_layout(case_index)
            .expect("fixed V2 positive artifact layout")
            .iter()
            .position(|(candidate, _)| *candidate == role)
            .expect("fixed V2 producer artifact role");
        support.sources.cases[case_index].primary_artifacts[artifact_index]
            .bytes
            .as_slice()
    };
    assert_eq!(producer.guest_elf(), guest.bytes.as_slice());
    assert_eq!(
        producer.statement(),
        primary(0, B4PositiveArtifactRole::Journal)
    );
    assert_eq!(
        producer.case0_lift15_receipt_oracle(),
        primary(0, B4PositiveArtifactRole::ReceiptOracle)
    );
    assert_eq!(
        producer.case8_terminal_join_recursive_oracle(),
        primary(8, B4PositiveArtifactRole::ReceiptOracle)
    );
    assert_eq!(
        producer.case9_terminal_resolve_recursive_oracle(),
        primary(9, B4PositiveArtifactRole::ReceiptOracle)
    );
}

#[test]
fn terminal_source_lineage_v2_rejects_input_substitution() {
    let support = terminal_lineage_v2_support();
    let mut sources = support.sources.clone();
    mutate_first_byte(&mut sources.positive_input_set.bytes);
    assert!(construct_v2_terminal_source_lineage(support, &sources).is_err());
}

#[test]
fn terminal_source_lineage_v2_rejects_generation_substitution() {
    let support = terminal_lineage_v2_support();
    let mut sources = support.sources.clone();
    mutate_first_byte(&mut sources.positive_generation_set.bytes);
    assert!(construct_v2_terminal_source_lineage(support, &sources).is_err());
}

#[test]
fn terminal_source_lineage_v2_rejects_guest_substitution() {
    let support = terminal_lineage_v2_support();
    let mut sources = support.sources.clone();
    let guest = sources
        .nested_input_sources
        .iter_mut()
        .find(|source| source.path == "methods/guest.elf")
        .expect("fixed V2 guest source");
    mutate_first_byte(&mut guest.bytes);
    assert!(construct_v2_terminal_source_lineage(support, &sources).is_err());
}

#[test]
fn terminal_source_lineage_v2_rejects_selected_case9_substitution() {
    let support = terminal_lineage_v2_support();
    let mut sources = support.sources.clone();
    mutate_first_byte(&mut sources.cases[9].proof_output_manifest.bytes);
    assert!(construct_v2_terminal_source_lineage(support, &sources).is_err());
}

fn terminal_lineage_base_support() -> &'static TerminalLineageConstructorTestSupportV1 {
    static SUPPORT: OnceLock<TerminalLineageConstructorTestSupportV1> = OnceLock::new();
    SUPPORT.get_or_init(|| {
        build_terminal_lineage_constructor_test_support(
            crate::receipt_oracle_replay::test_support::alternate_raw_seal_bytes(),
        )
        .expect("real terminal-lineage constructor support")
    })
}

fn terminal_lineage_generation_path_collision_support()
-> &'static TerminalLineageConstructorTestSupportV1 {
    static SUPPORT: OnceLock<TerminalLineageConstructorTestSupportV1> = OnceLock::new();
    SUPPORT.get_or_init(|| {
        build_terminal_lineage_generation_path_collision_test_support(
            crate::receipt_oracle_replay::test_support::alternate_raw_seal_bytes(),
        )
        .expect("separately valid terminal-lineage generation-path collision support")
    })
}

fn terminal_lineage_alternate_campaigns() -> &'static TerminalLineageAlternateCampaignsV1 {
    static SUPPORT: OnceLock<TerminalLineageAlternateCampaignsV1> = OnceLock::new();
    SUPPORT.get_or_init(|| {
        build_terminal_lineage_alternate_campaigns(
            crate::receipt_oracle_replay::test_support::alternate_raw_seal_bytes(),
        )
        .expect("separately valid alternate terminal-lineage campaigns")
    })
}

fn terminal_lineage_alternate_positive_support() -> &'static TerminalLineageConstructorTestSupportV1
{
    static SUPPORT: OnceLock<TerminalLineageConstructorTestSupportV1> = OnceLock::new();
    SUPPORT.get_or_init(|| {
        let mut distinct_case9_raw_seal =
            crate::receipt_oracle_replay::test_support::alternate_raw_seal_bytes().to_vec();
        distinct_case9_raw_seal[0] ^= 1;
        build_terminal_lineage_constructor_test_support(&distinct_case9_raw_seal)
            .expect("separately valid alternate terminal-lineage positive authority")
    })
}

fn selected_artifact(
    artifacts: &[OwnedPositiveAuthorityTestArtifactV1],
    case_index: usize,
    role: B4PositiveArtifactRole,
) -> &[u8] {
    let position = positive_artifact_layout(case_index)
        .expect("fixed positive artifact layout")
        .iter()
        .position(|(candidate, _)| *candidate == role)
        .expect("fixed selected role");
    &artifacts[position].bytes
}

impl TerminalLineageConstructorTestSupportV1 {
    fn case0_journal(&self) -> &[u8] {
        selected_artifact(
            &self.case0_primary_artifacts,
            0,
            B4PositiveArtifactRole::Journal,
        )
    }

    fn case0_receipt_oracle(&self) -> &[u8] {
        selected_artifact(
            &self.case0_primary_artifacts,
            0,
            B4PositiveArtifactRole::ReceiptOracle,
        )
    }

    fn case8_receipt_oracle(&self) -> &[u8] {
        selected_artifact(
            &self.case8_primary_artifacts,
            8,
            B4PositiveArtifactRole::ReceiptOracle,
        )
    }

    fn case9_receipt_oracle(&self) -> &[u8] {
        selected_artifact(
            &self.case9_primary_artifacts,
            9,
            B4PositiveArtifactRole::ReceiptOracle,
        )
    }

    fn selected_raw_seals(&self) -> [&[u8]; 3] {
        [
            selected_artifact(
                &self.case0_primary_artifacts,
                0,
                B4PositiveArtifactRole::RawSeal,
            ),
            selected_artifact(
                &self.case8_primary_artifacts,
                8,
                B4PositiveArtifactRole::RawSeal,
            ),
            selected_artifact(
                &self.case9_primary_artifacts,
                9,
                B4PositiveArtifactRole::RawSeal,
            ),
        ]
    }
}

struct ExternalOverlay<'a> {
    path: Cow<'a, str>,
    bytes: Cow<'a, [u8]>,
}

impl<'a> ExternalOverlay<'a> {
    fn borrowed(source: &'a OwnedPositiveAuthorityTestArtifactV1) -> Self {
        Self {
            path: Cow::Borrowed(&source.path),
            bytes: Cow::Borrowed(&source.bytes),
        }
    }

    fn external(&self) -> B4TerminalSourceExternalBytesV1<'_> {
        B4TerminalSourceExternalBytesV1 {
            path: self.path.as_ref(),
            bytes: self.bytes.as_ref(),
        }
    }
}

struct CaseOverlay<'a> {
    manifest: ExternalOverlay<'a>,
    primary: Vec<ExternalOverlay<'a>>,
    auxiliary: Vec<ExternalOverlay<'a>>,
}

struct LineageFixture<'a> {
    support: &'a TerminalLineageConstructorTestSupportV1,
    input: ExternalOverlay<'a>,
    generation: ExternalOverlay<'a>,
    guest: ExternalOverlay<'a>,
    case0: CaseOverlay<'a>,
    case8: CaseOverlay<'a>,
    case9: CaseOverlay<'a>,
}

impl<'a> LineageFixture<'a> {
    fn nominal(support: &'a TerminalLineageConstructorTestSupportV1) -> Self {
        fn case<'a>(
            case_index: usize,
            manifest_basename: &str,
            manifest_bytes: &'a [u8],
            primary: &'a [OwnedPositiveAuthorityTestArtifactV1],
            auxiliary: &'a [OwnedPositiveAuthorityTestArtifactV1],
        ) -> CaseOverlay<'a> {
            let manifest_path = crate::b4::canonical_positive_case_artifact_path(
                &compiled_positive_case_id(case_index).expect("fixed positive case ID"),
                manifest_basename,
            );
            CaseOverlay {
                manifest: ExternalOverlay {
                    path: Cow::Owned(manifest_path),
                    bytes: Cow::Borrowed(manifest_bytes),
                },
                primary: primary.iter().map(ExternalOverlay::borrowed).collect(),
                auxiliary: auxiliary.iter().map(ExternalOverlay::borrowed).collect(),
            }
        }

        Self {
            support,
            input: ExternalOverlay::borrowed(&support.positive_input_set),
            generation: ExternalOverlay::borrowed(&support.positive_generation_set),
            guest: ExternalOverlay::borrowed(&support.consumer_guest_elf),
            case0: case(
                0,
                "candidate-proof-output-manifest.json",
                &support.case0_proof_output_manifest_jcs,
                &support.case0_primary_artifacts,
                &support.case0_auxiliary_artifacts,
            ),
            case8: case(
                8,
                "candidate-recursive-output-manifest.json",
                &support.case8_proof_output_manifest_jcs,
                &support.case8_primary_artifacts,
                &support.case8_auxiliary_artifacts,
            ),
            case9: case(
                9,
                "candidate-recursive-output-manifest.json",
                &support.case9_proof_output_manifest_jcs,
                &support.case9_primary_artifacts,
                &support.case9_auxiliary_artifacts,
            ),
        }
    }

    fn with_external_closure<T>(
        &self,
        use_closure: impl FnOnce(B4TerminalSourceExternalClosureV1<'_>) -> T,
    ) -> T {
        let case0_primary = self
            .case0
            .primary
            .iter()
            .map(ExternalOverlay::external)
            .collect::<Vec<_>>();
        let case0_auxiliary = self
            .case0
            .auxiliary
            .iter()
            .map(ExternalOverlay::external)
            .collect::<Vec<_>>();
        let case8_primary = self
            .case8
            .primary
            .iter()
            .map(ExternalOverlay::external)
            .collect::<Vec<_>>();
        let case8_auxiliary = self
            .case8
            .auxiliary
            .iter()
            .map(ExternalOverlay::external)
            .collect::<Vec<_>>();
        let case9_primary = self
            .case9
            .primary
            .iter()
            .map(ExternalOverlay::external)
            .collect::<Vec<_>>();
        let case9_auxiliary = self
            .case9
            .auxiliary
            .iter()
            .map(ExternalOverlay::external)
            .collect::<Vec<_>>();
        use_closure(B4TerminalSourceExternalClosureV1 {
            positive_input_set: self.input.external(),
            positive_generation_set: self.generation.external(),
            guest_elf: self.guest.external(),
            case0_lift15: B4TerminalSourceCaseExternalV1 {
                proof_output_manifest: self.case0.manifest.external(),
                primary_artifacts: &case0_primary,
                auxiliary_artifacts: &case0_auxiliary,
            },
            case8_terminal_join: B4TerminalSourceCaseExternalV1 {
                proof_output_manifest: self.case8.manifest.external(),
                primary_artifacts: &case8_primary,
                auxiliary_artifacts: &case8_auxiliary,
            },
            case9_terminal_resolve: B4TerminalSourceCaseExternalV1 {
                proof_output_manifest: self.case9.manifest.external(),
                primary_artifacts: &case9_primary,
                auxiliary_artifacts: &case9_auxiliary,
            },
        })
    }

    fn construct(
        &self,
        campaign: &B4CampaignPrecommitAuthorityV1,
    ) -> Result<B4TerminalSourceLineageAuthorityV1> {
        self.with_external_closure(|source| {
            B4TerminalSourceLineageAuthorityV1::from_external_closure(
                campaign,
                &self.support.positive_generation_authority,
                source,
            )
        })
    }
}

fn construct_nominal(
    support: &'static TerminalLineageConstructorTestSupportV1,
) -> Result<B4TerminalSourceLineageAuthorityV1> {
    let fixture = LineageFixture::nominal(support);
    fixture.construct(&support.campaign_precommit_authority)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum LineageMutation {
    CampaignPositiveInputMismatch,
    InputPath,
    InputByte,
    InputDuplicateKey,
    InputTrailingContent,
    InputUnknownField,
    InputNonCanonical,
    GenerationPath,
    GenerationByte,
    GenerationDuplicateKey,
    GenerationTrailingContent,
    GenerationUnknownField,
    GenerationNonCanonical,
    GenerationWrongCaseCount,
    GenerationInputCommitment,
    GenerationProofGenerator,
    CampaignExecutorContent,
    Case0WrongOrdinal,
    Case0WrongRecipe,
    Case8WrongId,
    Case8WrongRecipe,
    Case9WrongRecipe,
    Case0PrimaryMissing,
    Case0PrimaryExtra,
    Case0AuxiliaryExtra,
    Case8PrimaryReordered,
    Case8AuxiliaryReordered,
    Case9PrimaryDuplicated,
    Case9AuxiliaryMissing,
    ManifestAbsolutePath,
    ManifestWrongCaseDirectory,
    PrimaryEscapingPath,
    PrimaryDrivePrefix,
    PrimaryDotSegment,
    PrimaryBackslash,
    PrimaryWrongBasename,
    AuxiliaryCrossCasePath,
    SelectedPathDuplicate,
    SelectedPathAncestor,
    SelectedPathDescendant,
    Case0EachPrimaryByte,
    Case8EachPrimaryByte,
    Case9EachPrimaryByte,
    Case8EachAuxiliaryByte,
    Case9EachAuxiliaryByte,
    Case0ManifestByte,
    Case8ManifestByte,
    Case9ManifestByte,
    GeneratedRole,
    GeneratedEncoding,
    GeneratedLength,
    GeneratedContentHex,
    GeneratedCodec,
    ManifestEntryMissing,
    ManifestEntryExtra,
    ManifestEntryDuplicated,
    ManifestEntryReordered,
    CoordinatedSourceManifestRewrite,
    CoordinatedSourceManifestGenerationRewrite,
    GuestPath,
    GuestByte,
    GuestImageId,
    Case0ImageId,
    Case8ImageId,
    Case9ImageId,
    Case0Journal,
    Case8Journal,
    Case9Journal,
    StatementProfile,
    StatementProgram,
    StatementContract,
    StatementChain,
    StatementPayloadLength,
    StatementPayloadDigest,
}

const LINEAGE_MUTATIONS: [LineageMutation; 74] = [
    LineageMutation::CampaignPositiveInputMismatch,
    LineageMutation::InputPath,
    LineageMutation::InputByte,
    LineageMutation::InputDuplicateKey,
    LineageMutation::InputTrailingContent,
    LineageMutation::InputUnknownField,
    LineageMutation::InputNonCanonical,
    LineageMutation::GenerationPath,
    LineageMutation::GenerationByte,
    LineageMutation::GenerationDuplicateKey,
    LineageMutation::GenerationTrailingContent,
    LineageMutation::GenerationUnknownField,
    LineageMutation::GenerationNonCanonical,
    LineageMutation::GenerationWrongCaseCount,
    LineageMutation::GenerationInputCommitment,
    LineageMutation::GenerationProofGenerator,
    LineageMutation::CampaignExecutorContent,
    LineageMutation::Case0WrongOrdinal,
    LineageMutation::Case0WrongRecipe,
    LineageMutation::Case8WrongId,
    LineageMutation::Case8WrongRecipe,
    LineageMutation::Case9WrongRecipe,
    LineageMutation::Case0PrimaryMissing,
    LineageMutation::Case0PrimaryExtra,
    LineageMutation::Case0AuxiliaryExtra,
    LineageMutation::Case8PrimaryReordered,
    LineageMutation::Case8AuxiliaryReordered,
    LineageMutation::Case9PrimaryDuplicated,
    LineageMutation::Case9AuxiliaryMissing,
    LineageMutation::ManifestAbsolutePath,
    LineageMutation::ManifestWrongCaseDirectory,
    LineageMutation::PrimaryEscapingPath,
    LineageMutation::PrimaryDrivePrefix,
    LineageMutation::PrimaryDotSegment,
    LineageMutation::PrimaryBackslash,
    LineageMutation::PrimaryWrongBasename,
    LineageMutation::AuxiliaryCrossCasePath,
    LineageMutation::SelectedPathDuplicate,
    LineageMutation::SelectedPathAncestor,
    LineageMutation::SelectedPathDescendant,
    LineageMutation::Case0EachPrimaryByte,
    LineageMutation::Case8EachPrimaryByte,
    LineageMutation::Case9EachPrimaryByte,
    LineageMutation::Case8EachAuxiliaryByte,
    LineageMutation::Case9EachAuxiliaryByte,
    LineageMutation::Case0ManifestByte,
    LineageMutation::Case8ManifestByte,
    LineageMutation::Case9ManifestByte,
    LineageMutation::GeneratedRole,
    LineageMutation::GeneratedEncoding,
    LineageMutation::GeneratedLength,
    LineageMutation::GeneratedContentHex,
    LineageMutation::GeneratedCodec,
    LineageMutation::ManifestEntryMissing,
    LineageMutation::ManifestEntryExtra,
    LineageMutation::ManifestEntryDuplicated,
    LineageMutation::ManifestEntryReordered,
    LineageMutation::CoordinatedSourceManifestRewrite,
    LineageMutation::CoordinatedSourceManifestGenerationRewrite,
    LineageMutation::GuestPath,
    LineageMutation::GuestByte,
    LineageMutation::GuestImageId,
    LineageMutation::Case0ImageId,
    LineageMutation::Case8ImageId,
    LineageMutation::Case9ImageId,
    LineageMutation::Case0Journal,
    LineageMutation::Case8Journal,
    LineageMutation::Case9Journal,
    LineageMutation::StatementProfile,
    LineageMutation::StatementProgram,
    LineageMutation::StatementContract,
    LineageMutation::StatementChain,
    LineageMutation::StatementPayloadLength,
    LineageMutation::StatementPayloadDigest,
];

impl LineageMutation {
    const fn positional_attempts(self) -> usize {
        match self {
            Self::Case0EachPrimaryByte => 7,
            Self::Case8EachPrimaryByte | Self::Case9EachPrimaryByte => 8,
            Self::Case8EachAuxiliaryByte | Self::Case9EachAuxiliaryByte => 2,
            _ => 1,
        }
    }

    const fn expected_boundary(self) -> LineageFailureBoundary {
        match self {
            Self::CampaignPositiveInputMismatch => LineageFailureBoundary::CampaignPositiveInput,
            Self::InputPath
            | Self::InputByte
            | Self::InputDuplicateKey
            | Self::InputTrailingContent
            | Self::InputUnknownField
            | Self::InputNonCanonical
            | Self::GuestImageId
            | Self::StatementProfile
            | Self::StatementProgram
            | Self::StatementContract
            | Self::StatementChain
            | Self::StatementPayloadLength
            | Self::StatementPayloadDigest => LineageFailureBoundary::InputIdentity,
            Self::GenerationPath
            | Self::GenerationByte
            | Self::GenerationDuplicateKey
            | Self::GenerationTrailingContent
            | Self::GenerationUnknownField
            | Self::GenerationNonCanonical
            | Self::GenerationWrongCaseCount
            | Self::GenerationInputCommitment
            | Self::GenerationProofGenerator
            | Self::Case0WrongOrdinal
            | Self::Case0WrongRecipe
            | Self::Case8WrongId
            | Self::Case8WrongRecipe
            | Self::Case9WrongRecipe
            | Self::GeneratedRole
            | Self::GeneratedEncoding
            | Self::GeneratedLength
            | Self::GeneratedContentHex
            | Self::GeneratedCodec
            | Self::CoordinatedSourceManifestGenerationRewrite => {
                LineageFailureBoundary::GenerationIdentity
            }
            Self::CampaignExecutorContent => LineageFailureBoundary::GeneratorExecutorContent,
            Self::ManifestAbsolutePath | Self::ManifestWrongCaseDirectory => {
                LineageFailureBoundary::SelectedManifestPath
            }
            Self::Case0PrimaryMissing
            | Self::Case0PrimaryExtra
            | Self::Case0AuxiliaryExtra
            | Self::Case8PrimaryReordered
            | Self::Case8AuxiliaryReordered
            | Self::Case9PrimaryDuplicated
            | Self::Case9AuxiliaryMissing
            | Self::PrimaryEscapingPath
            | Self::PrimaryDrivePrefix
            | Self::PrimaryDotSegment
            | Self::PrimaryBackslash
            | Self::PrimaryWrongBasename
            | Self::AuxiliaryCrossCasePath
            | Self::SelectedPathDuplicate
            | Self::SelectedPathAncestor
            | Self::SelectedPathDescendant
            | Self::Case0EachPrimaryByte
            | Self::Case8EachPrimaryByte
            | Self::Case9EachPrimaryByte
            | Self::Case8EachAuxiliaryByte
            | Self::Case9EachAuxiliaryByte
            | Self::Case0ManifestByte
            | Self::Case8ManifestByte
            | Self::Case9ManifestByte
            | Self::ManifestEntryMissing
            | Self::ManifestEntryExtra
            | Self::ManifestEntryDuplicated
            | Self::ManifestEntryReordered
            | Self::CoordinatedSourceManifestRewrite
            | Self::Case0ImageId
            | Self::Case8ImageId
            | Self::Case9ImageId
            | Self::Case0Journal
            | Self::Case8Journal
            | Self::Case9Journal => LineageFailureBoundary::SelectedPhysicalCase,
            Self::GuestPath | Self::GuestByte => LineageFailureBoundary::GuestIdentity,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct LineageAttempt {
    mutation: LineageMutation,
    position: Option<usize>,
}

fn lineage_attempts() -> Vec<LineageAttempt> {
    let mut attempts = Vec::with_capacity(96);
    for mutation in LINEAGE_MUTATIONS {
        if mutation.positional_attempts() == 1 {
            attempts.push(LineageAttempt {
                mutation,
                position: None,
            });
        } else {
            attempts.extend(
                (0..mutation.positional_attempts()).map(|position| LineageAttempt {
                    mutation,
                    position: Some(position),
                }),
            );
        }
    }
    assert_eq!(attempts.len(), 96);
    assert_eq!(
        attempts
            .iter()
            .map(|attempt| (attempt.mutation, attempt.position))
            .collect::<BTreeSet<_>>()
            .len(),
        96,
    );
    for mutation in LINEAGE_MUTATIONS {
        let positions = attempts
            .iter()
            .filter(|attempt| attempt.mutation == mutation)
            .map(|attempt| attempt.position)
            .collect::<Vec<_>>();
        if mutation.positional_attempts() == 1 {
            assert_eq!(positions, [None]);
        } else {
            assert_eq!(
                positions,
                (0..mutation.positional_attempts())
                    .map(Some)
                    .collect::<Vec<_>>(),
            );
        }
    }
    attempts
}

enum MutationWitness {
    Authority(&'static str),
    Path {
        label: &'static str,
        before: String,
        after: String,
        bytes_unchanged: bool,
    },
    Bytes {
        label: &'static str,
        before_sha256: String,
        after_sha256: String,
        before_len: usize,
        after_len: usize,
        path_unchanged: bool,
        require_equal_length: bool,
    },
    Cardinality {
        label: &'static str,
        before: usize,
        after: usize,
    },
    Ordering {
        label: &'static str,
        before: Vec<String>,
        after: Vec<String>,
    },
    Json {
        label: &'static str,
        before: serde_json::Value,
        after: serde_json::Value,
        semantic_equality_required: bool,
    },
    Coordinated(&'static str),
}

impl MutationWitness {
    fn assert_applied(&self) {
        match self {
            Self::Authority(label) | Self::Coordinated(label) => assert!(!label.is_empty()),
            Self::Path {
                label,
                before,
                after,
                bytes_unchanged,
            } => {
                assert!(!label.is_empty());
                assert_ne!(before, after);
                assert!(*bytes_unchanged);
            }
            Self::Bytes {
                label,
                before_sha256,
                after_sha256,
                before_len,
                after_len,
                path_unchanged,
                require_equal_length,
            } => {
                assert!(!label.is_empty());
                assert_ne!(before_sha256, after_sha256);
                assert!(*path_unchanged);
                if *require_equal_length {
                    assert_eq!(before_len, after_len);
                }
            }
            Self::Cardinality {
                label,
                before,
                after,
            } => {
                assert!(!label.is_empty());
                assert_ne!(before, after);
            }
            Self::Ordering {
                label,
                before,
                after,
            } => {
                assert!(!label.is_empty());
                assert_eq!(before.len(), after.len());
                assert_ne!(before, after);
            }
            Self::Json {
                label,
                before,
                after,
                semantic_equality_required,
            } => {
                assert!(!label.is_empty());
                if *semantic_equality_required {
                    assert_eq!(before, after);
                } else {
                    assert_ne!(before, after);
                }
            }
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn path_witness(
    label: &'static str,
    before: &str,
    after: &str,
    bytes_unchanged: bool,
) -> MutationWitness {
    MutationWitness::Path {
        label,
        before: before.to_owned(),
        after: after.to_owned(),
        bytes_unchanged,
    }
}

fn bytes_witness(
    label: &'static str,
    before: &[u8],
    after: &[u8],
    path_unchanged: bool,
    require_equal_length: bool,
) -> MutationWitness {
    MutationWitness::Bytes {
        label,
        before_sha256: sha256_hex(before),
        after_sha256: sha256_hex(after),
        before_len: before.len(),
        after_len: after.len(),
        path_unchanged,
        require_equal_length,
    }
}

fn xor_first_byte(bytes: &[u8]) -> Vec<u8> {
    assert!(!bytes.is_empty());
    let mut changed = bytes.to_vec();
    changed[0] ^= 1;
    assert_ne!(changed, bytes);
    changed
}

fn canonical_mutation(
    bytes: &[u8],
    mutate: impl FnOnce(&mut serde_json::Value),
) -> (Vec<u8>, MutationWitness) {
    let before: serde_json::Value = serde_json::from_slice(bytes).expect("valid nominal JSON");
    let mut after = before.clone();
    mutate(&mut after);
    assert_ne!(before, after);
    let changed = canonical_json_bytes(&after).expect("canonical mutated JSON");
    assert_ne!(changed, bytes);
    (
        changed,
        MutationWitness::Json {
            label: "canonical semantic mutation",
            before,
            after,
            semantic_equality_required: false,
        },
    )
}

fn pretty_json(bytes: &[u8]) -> (Vec<u8>, MutationWitness) {
    let before: serde_json::Value = serde_json::from_slice(bytes).expect("valid nominal JSON");
    let pretty = serde_json::to_vec_pretty(&before).expect("pretty JSON");
    assert_ne!(pretty, bytes);
    let after: serde_json::Value = serde_json::from_slice(&pretty).expect("valid pretty JSON");
    (
        pretty,
        MutationWitness::Json {
            label: "noncanonical semantic-preserving JSON",
            before,
            after,
            semantic_equality_required: true,
        },
    )
}

fn duplicate_top_level_key(bytes: &[u8], key: &str) -> (Vec<u8>, MutationWitness) {
    let nominal: serde_json::Value = serde_json::from_slice(bytes).expect("valid nominal JSON");
    let serialized_value =
        serde_json::to_vec(&nominal[key]).expect("serializable duplicate JSON value");
    assert_eq!(bytes.first(), Some(&b'{'));
    let mut changed = Vec::with_capacity(bytes.len() + key.len() + serialized_value.len() + 4);
    changed.push(b'{');
    changed.extend_from_slice(format!("\"{key}\":").as_bytes());
    changed.extend_from_slice(&serialized_value);
    changed.push(b',');
    changed.extend_from_slice(&bytes[1..]);
    assert!(parse_json_strict(&changed).is_err());
    (
        changed.clone(),
        bytes_witness("duplicate top-level JSON key", bytes, &changed, true, false),
    )
}

fn flip_one_hex_digit(bytes: &[u8], marker: &[u8]) -> (Vec<u8>, MutationWitness) {
    let starts = bytes
        .windows(marker.len())
        .enumerate()
        .filter(|(_, candidate)| *candidate == marker)
        .map(|(position, _)| position)
        .collect::<Vec<_>>();
    assert_eq!(starts.len(), 1, "hex marker must be unique");
    let mut changed = bytes.to_vec();
    let tail = &bytes[starts[0] + marker.len()..];
    let digest_marker = b"\"sha256\":\"";
    let digest_offset = tail
        .windows(digest_marker.len())
        .position(|candidate| candidate == digest_marker)
        .unwrap_or(0);
    let mut position = starts[0] + marker.len() + digest_offset;
    if digest_offset != 0 {
        position += digest_marker.len();
    }
    while !changed[position].is_ascii_hexdigit() {
        position += 1;
    }
    changed[position] = if changed[position] == b'a' {
        b'b'
    } else {
        b'a'
    };
    assert!(serde_json::from_slice::<serde_json::Value>(&changed).is_ok());
    (
        changed.clone(),
        bytes_witness("single hexadecimal digit", bytes, &changed, true, true),
    )
}

fn role_position(case_index: usize, role: B4PositiveArtifactRole) -> usize {
    let positions = positive_artifact_layout(case_index)
        .expect("fixed positive artifact layout")
        .iter()
        .enumerate()
        .filter(|(_, (candidate, _))| *candidate == role)
        .map(|(position, _)| position)
        .collect::<Vec<_>>();
    assert_eq!(positions.len(), 1);
    positions[0]
}

fn replace_overlay_path(
    overlay: &mut ExternalOverlay<'_>,
    changed: impl Into<String>,
    label: &'static str,
) -> MutationWitness {
    let before = overlay.path.to_string();
    let before_bytes = sha256_hex(overlay.bytes.as_ref());
    overlay.path = Cow::Owned(changed.into());
    path_witness(
        label,
        &before,
        overlay.path.as_ref(),
        before_bytes == sha256_hex(overlay.bytes.as_ref()),
    )
}

fn replace_overlay_bytes(
    overlay: &mut ExternalOverlay<'_>,
    changed: Vec<u8>,
    label: &'static str,
    require_equal_length: bool,
) -> MutationWitness {
    let before = overlay.bytes.as_ref().to_vec();
    let before_path = overlay.path.to_string();
    overlay.bytes = Cow::Owned(changed);
    bytes_witness(
        label,
        &before,
        overlay.bytes.as_ref(),
        before_path == overlay.path,
        require_equal_length,
    )
}

fn mutate_overlay_json(
    overlay: &mut ExternalOverlay<'_>,
    mutate: impl FnOnce(&mut serde_json::Value),
) -> MutationWitness {
    let (changed, witness) = canonical_mutation(overlay.bytes.as_ref(), mutate);
    overlay.bytes = Cow::Owned(changed);
    witness
}

fn overlay_paths(overlays: &[ExternalOverlay<'_>]) -> Vec<String> {
    overlays
        .iter()
        .map(|overlay| overlay.path.to_string())
        .collect()
}

impl LineageFixture<'_> {
    fn rewrite_case8_receipt_closure(&mut self, rewrite_generation: bool) {
        let receipt_position = role_position(8, B4PositiveArtifactRole::ReceiptOracle);
        let nominal_receipt = self.case8.primary[receipt_position].bytes.as_ref().to_vec();
        let rewritten_receipt = xor_first_byte(&nominal_receipt);
        assert_eq!(nominal_receipt.len(), rewritten_receipt.len());
        self.case8.primary[receipt_position].bytes = Cow::Owned(rewritten_receipt.clone());

        let receipt_basename =
            positive_artifact_layout(8).expect("case 8 layout")[receipt_position].1;
        let mut manifest: ProofOutputManifest =
            serde_json::from_slice(self.case8.manifest.bytes.as_ref())
                .expect("nominal case-8 manifest");
        let receipt_entry = manifest
            .iter_mut()
            .find(|entry| entry.path == receipt_basename)
            .expect("case-8 receipt manifest entry");
        receipt_entry.length = rewritten_receipt.len().to_string();
        receipt_entry.sha256 = sha256_hex(&rewritten_receipt);
        manifest.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
        let rewritten_manifest =
            canonical_json_bytes(&serde_json::to_value(&manifest).expect("manifest value"))
                .expect("rewritten case-8 manifest");
        assert_ne!(rewritten_manifest, self.case8.manifest.bytes.as_ref());
        self.case8.manifest.bytes = Cow::Owned(rewritten_manifest.clone());

        if rewrite_generation {
            let (rewritten_generation, _) =
                canonical_mutation(self.generation.bytes.as_ref(), |value| {
                    let artifact = &mut value["cases"][8]["artifacts"][receipt_position];
                    artifact["byteLength"] =
                        serde_json::json!(u64::try_from(rewritten_receipt.len()).unwrap());
                    artifact["sha256"] = serde_json::json!(sha256_hex(&rewritten_receipt));
                    let manifest_identity = &mut value["cases"][8]["proofOutputManifest"];
                    manifest_identity["byteLength"] =
                        serde_json::json!(u64::try_from(rewritten_manifest.len()).unwrap());
                    manifest_identity["sha256"] =
                        serde_json::json!(sha256_hex(&rewritten_manifest));
                });
            self.generation.bytes = Cow::Owned(rewritten_generation);
        }

        let parsed_manifest: ProofOutputManifest =
            serde_json::from_slice(self.case8.manifest.bytes.as_ref())
                .expect("rewritten case-8 manifest");
        let entry = parsed_manifest
            .iter()
            .find(|entry| entry.path == receipt_basename)
            .expect("rewritten receipt entry");
        assert_eq!(entry.length, rewritten_receipt.len().to_string());
        assert_eq!(entry.sha256, sha256_hex(&rewritten_receipt));
        if rewrite_generation {
            let generation: serde_json::Value =
                serde_json::from_slice(self.generation.bytes.as_ref())
                    .expect("rewritten generation JSON");
            let artifact = &generation["cases"][8]["artifacts"][receipt_position];
            assert_eq!(
                artifact["byteLength"].as_u64(),
                Some(u64::try_from(rewritten_receipt.len()).unwrap()),
            );
            assert_eq!(
                artifact["sha256"].as_str(),
                Some(sha256_hex(&rewritten_receipt).as_str()),
            );
            let manifest_identity = &generation["cases"][8]["proofOutputManifest"];
            assert_eq!(
                manifest_identity["byteLength"].as_u64(),
                Some(u64::try_from(rewritten_manifest.len()).unwrap()),
            );
            assert_eq!(
                manifest_identity["sha256"].as_str(),
                Some(sha256_hex(&rewritten_manifest).as_str()),
            );
        }
    }

    #[allow(clippy::too_many_lines)]
    fn apply(&mut self, attempt: LineageAttempt) -> MutationWitness {
        let position = attempt.position;
        match attempt.mutation {
            LineageMutation::CampaignPositiveInputMismatch => {
                assert!(position.is_none());
                MutationWitness::Authority("different valid campaign input")
            }
            LineageMutation::InputPath => replace_overlay_path(
                &mut self.input,
                "reproduction/preproof/terminal-input-drift.json",
                "positive input path",
            ),
            LineageMutation::InputByte => {
                let (changed, witness) =
                    flip_one_hex_digit(self.input.bytes.as_ref(), b"\"referenceStatement\":");
                self.input.bytes = Cow::Owned(changed);
                witness
            }
            LineageMutation::InputDuplicateKey => {
                let (changed, witness) =
                    duplicate_top_level_key(self.input.bytes.as_ref(), "format");
                self.input.bytes = Cow::Owned(changed);
                witness
            }
            LineageMutation::InputTrailingContent => {
                let before = self.input.bytes.as_ref().to_vec();
                let mut changed = before.clone();
                changed.push(b'\n');
                assert_eq!(&changed[..before.len()], before);
                assert_eq!(changed.len(), before.len() + 1);
                replace_overlay_bytes(
                    &mut self.input,
                    changed,
                    "positive input trailing content",
                    false,
                )
            }
            LineageMutation::InputUnknownField => mutate_overlay_json(&mut self.input, |value| {
                value["terminalLineageUnknown"] = serde_json::json!(true);
                assert_eq!(value["terminalLineageUnknown"], true);
            }),
            LineageMutation::InputNonCanonical => {
                let (changed, witness) = pretty_json(self.input.bytes.as_ref());
                self.input.bytes = Cow::Owned(changed);
                witness
            }
            LineageMutation::GenerationPath => replace_overlay_path(
                &mut self.generation,
                "reproduction/positive-generation-drift.json",
                "positive generation path",
            ),
            LineageMutation::GenerationByte => {
                let (changed, witness) = flip_one_hex_digit(
                    self.generation.bytes.as_ref(),
                    b"\"proofGeneratorArtifact\":",
                );
                self.generation.bytes = Cow::Owned(changed);
                witness
            }
            LineageMutation::GenerationDuplicateKey => {
                let (changed, witness) =
                    duplicate_top_level_key(self.generation.bytes.as_ref(), "format");
                self.generation.bytes = Cow::Owned(changed);
                witness
            }
            LineageMutation::GenerationTrailingContent => {
                let before = self.generation.bytes.as_ref().to_vec();
                let mut changed = before.clone();
                changed.push(b'\n');
                assert_eq!(&changed[..before.len()], before);
                assert_eq!(changed.len(), before.len() + 1);
                replace_overlay_bytes(
                    &mut self.generation,
                    changed,
                    "positive generation trailing content",
                    false,
                )
            }
            LineageMutation::GenerationUnknownField => {
                mutate_overlay_json(&mut self.generation, |value| {
                    value["terminalLineageUnknown"] = serde_json::json!(true);
                    assert_eq!(value["terminalLineageUnknown"], true);
                })
            }
            LineageMutation::GenerationNonCanonical => {
                let (changed, witness) = pretty_json(self.generation.bytes.as_ref());
                self.generation.bytes = Cow::Owned(changed);
                witness
            }
            LineageMutation::GenerationWrongCaseCount => {
                mutate_overlay_json(&mut self.generation, |value| {
                    value["cases"].as_array_mut().unwrap().remove(10);
                    assert_eq!(value["cases"].as_array().unwrap().len(), 10);
                })
            }
            LineageMutation::GenerationInputCommitment => {
                mutate_overlay_json(&mut self.generation, |value| {
                    let before = value["inputSetCommitment"]["sha256"].clone();
                    value["inputSetCommitment"]["sha256"] = serde_json::json!("11".repeat(32));
                    assert_ne!(value["inputSetCommitment"]["sha256"], before);
                })
            }
            LineageMutation::GenerationProofGenerator => {
                mutate_overlay_json(&mut self.generation, |value| {
                    let before = value["proofGeneratorArtifact"].clone();
                    value["proofGeneratorArtifact"]["sha256"] = serde_json::json!("12".repeat(32));
                    assert_eq!(
                        value["proofGeneratorArtifact"]["encoding"],
                        before["encoding"]
                    );
                    assert_eq!(
                        value["proofGeneratorArtifact"]["byteLength"],
                        before["byteLength"]
                    );
                })
            }
            LineageMutation::CampaignExecutorContent => {
                assert!(position.is_none());
                MutationWitness::Authority("different valid campaign executor")
            }
            LineageMutation::Case0WrongOrdinal => {
                mutate_overlay_json(&mut self.generation, |value| {
                    let id = value["cases"][0]["caseId"].clone();
                    let recipe = value["cases"][0]["generation"].clone();
                    value["cases"][0]["caseIndex"] = serde_json::json!(1);
                    assert_eq!(value["cases"][0]["caseId"], id);
                    assert_eq!(value["cases"][0]["generation"], recipe);
                })
            }
            LineageMutation::Case0WrongRecipe => {
                mutate_overlay_json(&mut self.generation, |value| {
                    let ordinal = value["cases"][0]["caseIndex"].clone();
                    let id = value["cases"][0]["caseId"].clone();
                    value["cases"][0]["generation"]["segmentPo2"] = serde_json::json!(16);
                    assert_eq!(value["cases"][0]["caseIndex"], ordinal);
                    assert_eq!(value["cases"][0]["caseId"], id);
                })
            }
            LineageMutation::Case8WrongId => mutate_overlay_json(&mut self.generation, |value| {
                value["cases"][8]["caseId"] = serde_json::json!("terminal-resolve-explicit-root");
                assert_eq!(value["cases"][8]["caseIndex"], 8);
            }),
            LineageMutation::Case8WrongRecipe => {
                mutate_overlay_json(&mut self.generation, |value| {
                    let id = value["cases"][8]["caseId"].clone();
                    value["cases"][8]["generation"]["family"] =
                        serde_json::json!("terminal-resolve");
                    assert_eq!(value["cases"][8]["caseId"], id);
                })
            }
            LineageMutation::Case9WrongRecipe => {
                mutate_overlay_json(&mut self.generation, |value| {
                    let id = value["cases"][9]["caseId"].clone();
                    value["cases"][9]["generation"]["family"] = serde_json::json!("terminal-join");
                    assert_eq!(value["cases"][9]["caseId"], id);
                })
            }
            LineageMutation::Case0PrimaryMissing => {
                let before = self.case0.primary.len();
                self.case0.primary.remove(6);
                assert_eq!((before, self.case0.primary.len()), (7, 6));
                MutationWitness::Cardinality {
                    label: "case-0 primary missing",
                    before,
                    after: self.case0.primary.len(),
                }
            }
            LineageMutation::Case0PrimaryExtra => {
                let before = self.case0.primary.len();
                self.case0.primary.push(ExternalOverlay::borrowed(
                    &self.support.case0_primary_artifacts[0],
                ));
                assert_eq!((before, self.case0.primary.len()), (7, 8));
                MutationWitness::Cardinality {
                    label: "case-0 primary extra",
                    before,
                    after: self.case0.primary.len(),
                }
            }
            LineageMutation::Case0AuxiliaryExtra => {
                let before = self.case0.auxiliary.len();
                self.case0.auxiliary.push(ExternalOverlay::borrowed(
                    &self.support.case8_auxiliary_artifacts[0],
                ));
                assert_eq!((before, self.case0.auxiliary.len()), (0, 1));
                MutationWitness::Cardinality {
                    label: "case-0 auxiliary extra",
                    before,
                    after: self.case0.auxiliary.len(),
                }
            }
            LineageMutation::Case8PrimaryReordered => {
                let before = overlay_paths(&self.case8.primary);
                self.case8.primary.swap(0, 1);
                let after = overlay_paths(&self.case8.primary);
                assert_eq!(before.len(), after.len());
                MutationWitness::Ordering {
                    label: "case-8 primary reorder",
                    before,
                    after,
                }
            }
            LineageMutation::Case8AuxiliaryReordered => {
                let before = overlay_paths(&self.case8.auxiliary);
                self.case8.auxiliary.swap(0, 1);
                let after = overlay_paths(&self.case8.auxiliary);
                MutationWitness::Ordering {
                    label: "case-8 auxiliary reorder",
                    before,
                    after,
                }
            }
            LineageMutation::Case9PrimaryDuplicated => {
                let before = overlay_paths(&self.case9.primary);
                self.case9.primary[1] =
                    ExternalOverlay::borrowed(&self.support.case9_primary_artifacts[0]);
                let after = overlay_paths(&self.case9.primary);
                assert_eq!(after[0], after[1]);
                MutationWitness::Ordering {
                    label: "case-9 primary duplicate",
                    before,
                    after,
                }
            }
            LineageMutation::Case9AuxiliaryMissing => {
                let before = self.case9.auxiliary.len();
                self.case9.auxiliary.remove(1);
                assert_eq!((before, self.case9.auxiliary.len()), (2, 1));
                MutationWitness::Cardinality {
                    label: "case-9 auxiliary missing",
                    before,
                    after: self.case9.auxiliary.len(),
                }
            }
            LineageMutation::ManifestAbsolutePath => replace_overlay_path(
                &mut self.case8.manifest,
                "/tmp/candidate-recursive-output-manifest.json",
                "absolute manifest path",
            ),
            LineageMutation::ManifestWrongCaseDirectory => {
                let case9_id = compiled_positive_case_id(9).unwrap();
                replace_overlay_path(
                    &mut self.case8.manifest,
                    crate::b4::canonical_positive_case_artifact_path(
                        &case9_id,
                        "candidate-recursive-output-manifest.json",
                    ),
                    "wrong manifest case directory",
                )
            }
            LineageMutation::PrimaryEscapingPath => replace_overlay_path(
                &mut self.case8.primary[0],
                "../candidate-ancestry.json",
                "escaping primary path",
            ),
            LineageMutation::PrimaryDrivePrefix => replace_overlay_path(
                &mut self.case8.primary[0],
                "C:/candidate-ancestry.json",
                "drive-prefixed primary path",
            ),
            LineageMutation::PrimaryDotSegment => {
                let nominal = self.case8.primary[0].path.to_string();
                let slash = nominal.rfind('/').expect("case directory");
                let changed = format!("{}/./{}", &nominal[..slash], &nominal[slash + 1..]);
                assert!(changed.contains("/./"));
                replace_overlay_path(
                    &mut self.case8.primary[0],
                    changed,
                    "dot-segment primary path",
                )
            }
            LineageMutation::PrimaryBackslash => {
                let nominal = self.case8.primary[0].path.to_string();
                let changed = nominal.replacen('/', "\\", 1);
                assert!(changed.contains('\\'));
                replace_overlay_path(
                    &mut self.case8.primary[0],
                    changed,
                    "backslash primary path",
                )
            }
            LineageMutation::PrimaryWrongBasename => {
                let nominal = self.case8.primary[0].path.to_string();
                let slash = nominal.rfind('/').expect("case directory");
                let changed = format!("{}/candidate-ancestry-drift.json", &nominal[..slash]);
                replace_overlay_path(
                    &mut self.case8.primary[0],
                    changed,
                    "wrong primary basename",
                )
            }
            LineageMutation::AuxiliaryCrossCasePath => {
                let changed = self.support.case9_auxiliary_artifacts[0].path.clone();
                assert_ne!(changed, self.support.case8_auxiliary_artifacts[0].path);
                replace_overlay_path(
                    &mut self.case8.auxiliary[0],
                    changed,
                    "cross-case auxiliary path",
                )
            }
            LineageMutation::SelectedPathDuplicate => {
                let before = overlay_paths(&self.case8.primary);
                self.case8.primary[1] =
                    ExternalOverlay::borrowed(&self.support.case8_primary_artifacts[0]);
                let after = overlay_paths(&self.case8.primary);
                assert_eq!(after[0], after[1]);
                MutationWitness::Ordering {
                    label: "selected path duplicate",
                    before,
                    after,
                }
            }
            LineageMutation::SelectedPathAncestor => {
                let manifest = self.case8.manifest.path.to_string();
                let directory = manifest
                    .rsplit_once('/')
                    .expect("manifest case directory")
                    .0
                    .to_owned();
                assert!(crate::b4_campaign_contract::b4_paths_conflict(
                    &directory, &manifest
                ));
                replace_overlay_path(
                    &mut self.case8.primary[0],
                    directory,
                    "selected path ancestor",
                )
            }
            LineageMutation::SelectedPathDescendant => {
                let manifest = self.case8.manifest.path.to_string();
                let descendant = format!("{manifest}/child");
                assert!(crate::b4_campaign_contract::b4_paths_conflict(
                    &manifest,
                    &descendant
                ));
                replace_overlay_path(
                    &mut self.case8.primary[0],
                    descendant,
                    "selected path descendant",
                )
            }
            LineageMutation::Case0EachPrimaryByte => {
                let position = position.expect("case-0 primary position");
                let changed = xor_first_byte(self.case0.primary[position].bytes.as_ref());
                replace_overlay_bytes(
                    &mut self.case0.primary[position],
                    changed,
                    "case-0 primary byte",
                    true,
                )
            }
            LineageMutation::Case8EachPrimaryByte => {
                let position = position.expect("case-8 primary position");
                let changed = xor_first_byte(self.case8.primary[position].bytes.as_ref());
                replace_overlay_bytes(
                    &mut self.case8.primary[position],
                    changed,
                    "case-8 primary byte",
                    true,
                )
            }
            LineageMutation::Case9EachPrimaryByte => {
                let position = position.expect("case-9 primary position");
                let changed = xor_first_byte(self.case9.primary[position].bytes.as_ref());
                replace_overlay_bytes(
                    &mut self.case9.primary[position],
                    changed,
                    "case-9 primary byte",
                    true,
                )
            }
            LineageMutation::Case8EachAuxiliaryByte => {
                let position = position.expect("case-8 auxiliary position");
                let changed = xor_first_byte(self.case8.auxiliary[position].bytes.as_ref());
                replace_overlay_bytes(
                    &mut self.case8.auxiliary[position],
                    changed,
                    "case-8 auxiliary byte",
                    true,
                )
            }
            LineageMutation::Case9EachAuxiliaryByte => {
                let position = position.expect("case-9 auxiliary position");
                let changed = xor_first_byte(self.case9.auxiliary[position].bytes.as_ref());
                replace_overlay_bytes(
                    &mut self.case9.auxiliary[position],
                    changed,
                    "case-9 auxiliary byte",
                    true,
                )
            }
            LineageMutation::Case0ManifestByte => {
                let changed = xor_first_byte(self.case0.manifest.bytes.as_ref());
                replace_overlay_bytes(
                    &mut self.case0.manifest,
                    changed,
                    "case-0 manifest byte",
                    true,
                )
            }
            LineageMutation::Case8ManifestByte => {
                let changed = xor_first_byte(self.case8.manifest.bytes.as_ref());
                replace_overlay_bytes(
                    &mut self.case8.manifest,
                    changed,
                    "case-8 manifest byte",
                    true,
                )
            }
            LineageMutation::Case9ManifestByte => {
                let changed = xor_first_byte(self.case9.manifest.bytes.as_ref());
                replace_overlay_bytes(
                    &mut self.case9.manifest,
                    changed,
                    "case-9 manifest byte",
                    true,
                )
            }
            LineageMutation::GeneratedRole => mutate_overlay_json(&mut self.generation, |value| {
                let before = value["cases"][8]["artifacts"][0].clone();
                value["cases"][8]["artifacts"][0]["role"] = serde_json::json!("calibration");
                assert_eq!(
                    value["cases"][8]["artifacts"][0]["sourceFile"],
                    before["sourceFile"]
                );
                assert_eq!(
                    value["cases"][8]["artifacts"][0]["sha256"],
                    before["sha256"]
                );
            }),
            LineageMutation::GeneratedEncoding => {
                mutate_overlay_json(&mut self.generation, |value| {
                    let before = value["cases"][8]["artifacts"][0].clone();
                    value["cases"][8]["artifacts"][0]["encoding"] = serde_json::json!("raw-bytes");
                    assert_eq!(value["cases"][8]["artifacts"][0]["role"], before["role"]);
                    assert_eq!(
                        value["cases"][8]["artifacts"][0]["sourceFile"],
                        before["sourceFile"]
                    );
                })
            }
            LineageMutation::GeneratedLength => {
                mutate_overlay_json(&mut self.generation, |value| {
                    let artifact = &mut value["cases"][8]["artifacts"][5];
                    let digest = artifact["sha256"].clone();
                    artifact["byteLength"] =
                        serde_json::json!(artifact["byteLength"].as_u64().unwrap() + 1);
                    assert_eq!(artifact["sha256"], digest);
                })
            }
            LineageMutation::GeneratedContentHex => {
                mutate_overlay_json(&mut self.generation, |value| {
                    let artifact = &mut value["cases"][8]["artifacts"][4];
                    artifact["contentHex"] = serde_json::json!("13".repeat(32));
                    assert_eq!(artifact["role"], "image-id");
                })
            }
            LineageMutation::GeneratedCodec => mutate_overlay_json(&mut self.generation, |value| {
                let artifact = &mut value["cases"][8]["artifacts"][7];
                artifact["codec"] =
                    serde_json::json!("bincode-1.3.3-little-endian-fixed-int-reject-trailing");
                assert_eq!(artifact["role"], "receipt-oracle");
            }),
            LineageMutation::ManifestEntryMissing => {
                let before: ProofOutputManifest =
                    serde_json::from_slice(self.case8.manifest.bytes.as_ref()).unwrap();
                let mut after = before.clone();
                let receipt = positive_artifact_layout(8).unwrap()
                    [role_position(8, B4PositiveArtifactRole::ReceiptOracle)]
                .1;
                after.retain(|entry| entry.path != receipt);
                assert_eq!(after.len() + 1, before.len());
                self.case8.manifest.bytes = Cow::Owned(
                    canonical_json_bytes(&serde_json::to_value(&after).unwrap()).unwrap(),
                );
                MutationWitness::Cardinality {
                    label: "manifest entry missing",
                    before: before.len(),
                    after: after.len(),
                }
            }
            LineageMutation::ManifestEntryExtra => {
                let mut manifest: ProofOutputManifest =
                    serde_json::from_slice(self.case8.manifest.bytes.as_ref()).unwrap();
                let before = manifest.len();
                manifest.push(ManifestEntry {
                    path: "terminal-lineage-extra.bin".to_owned(),
                    length: "1".to_owned(),
                    sha256: sha256_hex(&[0xed]),
                });
                manifest.sort_by(|left, right| left.path.as_bytes().cmp(right.path.as_bytes()));
                assert_eq!(manifest.len(), before + 1);
                self.case8.manifest.bytes = Cow::Owned(
                    canonical_json_bytes(&serde_json::to_value(&manifest).unwrap()).unwrap(),
                );
                MutationWitness::Cardinality {
                    label: "manifest entry extra",
                    before,
                    after: manifest.len(),
                }
            }
            LineageMutation::ManifestEntryDuplicated => {
                let mut manifest: ProofOutputManifest =
                    serde_json::from_slice(self.case8.manifest.bytes.as_ref()).unwrap();
                let before = manifest.len();
                let journal = positive_artifact_layout(8).unwrap()
                    [role_position(8, B4PositiveArtifactRole::Journal)]
                .1;
                let duplicate = manifest
                    .iter()
                    .find(|entry| entry.path == journal)
                    .unwrap()
                    .clone();
                manifest.push(duplicate);
                assert_eq!(
                    manifest
                        .iter()
                        .filter(|entry| entry.path == journal)
                        .count(),
                    2
                );
                self.case8.manifest.bytes = Cow::Owned(
                    canonical_json_bytes(&serde_json::to_value(&manifest).unwrap()).unwrap(),
                );
                MutationWitness::Cardinality {
                    label: "manifest entry duplicate",
                    before,
                    after: manifest.len(),
                }
            }
            LineageMutation::ManifestEntryReordered => {
                let mut manifest: ProofOutputManifest =
                    serde_json::from_slice(self.case8.manifest.bytes.as_ref()).unwrap();
                let before = manifest.iter().map(|entry| entry.path.clone()).collect();
                manifest.swap(0, 1);
                let after = manifest.iter().map(|entry| entry.path.clone()).collect();
                self.case8.manifest.bytes = Cow::Owned(
                    canonical_json_bytes(&serde_json::to_value(&manifest).unwrap()).unwrap(),
                );
                MutationWitness::Ordering {
                    label: "manifest entry reorder",
                    before,
                    after,
                }
            }
            LineageMutation::CoordinatedSourceManifestRewrite => {
                let generation_before = self.generation.bytes.as_ref().to_vec();
                self.rewrite_case8_receipt_closure(false);
                assert_eq!(self.generation.bytes.as_ref(), generation_before);
                MutationWitness::Coordinated("source and manifest rewrite")
            }
            LineageMutation::CoordinatedSourceManifestGenerationRewrite => {
                let generation_before = self.generation.bytes.as_ref().to_vec();
                self.rewrite_case8_receipt_closure(true);
                assert_ne!(self.generation.bytes.as_ref(), generation_before);
                MutationWitness::Coordinated("source, manifest, and generation rewrite")
            }
            LineageMutation::GuestPath => {
                replace_overlay_path(&mut self.guest, "methods/guest-drift.elf", "guest ELF path")
            }
            LineageMutation::GuestByte => {
                let changed = xor_first_byte(self.guest.bytes.as_ref());
                replace_overlay_bytes(&mut self.guest, changed, "guest ELF byte", true)
            }
            LineageMutation::GuestImageId => mutate_overlay_json(&mut self.input, |value| {
                let elf = value["guest"]["elf"].clone();
                value["guest"]["imageId"] = serde_json::json!("14".repeat(32));
                assert_eq!(value["guest"]["elf"], elf);
            }),
            LineageMutation::Case0ImageId => {
                let position = role_position(0, B4PositiveArtifactRole::ImageId);
                let changed = xor_first_byte(self.case0.primary[position].bytes.as_ref());
                replace_overlay_bytes(
                    &mut self.case0.primary[position],
                    changed,
                    "case-0 image ID",
                    true,
                )
            }
            LineageMutation::Case8ImageId => {
                let position = role_position(8, B4PositiveArtifactRole::ImageId);
                let changed = xor_first_byte(self.case8.primary[position].bytes.as_ref());
                replace_overlay_bytes(
                    &mut self.case8.primary[position],
                    changed,
                    "case-8 image ID",
                    true,
                )
            }
            LineageMutation::Case9ImageId => {
                let position = role_position(9, B4PositiveArtifactRole::ImageId);
                let changed = xor_first_byte(self.case9.primary[position].bytes.as_ref());
                replace_overlay_bytes(
                    &mut self.case9.primary[position],
                    changed,
                    "case-9 image ID",
                    true,
                )
            }
            LineageMutation::Case0Journal => {
                let position = role_position(0, B4PositiveArtifactRole::Journal);
                let changed = xor_first_byte(self.case0.primary[position].bytes.as_ref());
                replace_overlay_bytes(
                    &mut self.case0.primary[position],
                    changed,
                    "case-0 journal",
                    true,
                )
            }
            LineageMutation::Case8Journal => {
                let position = role_position(8, B4PositiveArtifactRole::Journal);
                let changed = xor_first_byte(self.case8.primary[position].bytes.as_ref());
                replace_overlay_bytes(
                    &mut self.case8.primary[position],
                    changed,
                    "case-8 journal",
                    true,
                )
            }
            LineageMutation::Case9Journal => {
                let position = role_position(9, B4PositiveArtifactRole::Journal);
                let changed = xor_first_byte(self.case9.primary[position].bytes.as_ref());
                replace_overlay_bytes(
                    &mut self.case9.primary[position],
                    changed,
                    "case-9 journal",
                    true,
                )
            }
            LineageMutation::StatementProfile => mutate_overlay_json(&mut self.input, |value| {
                let profile = value["profile"].clone();
                value["profile"]["profileId"] = serde_json::json!("15".repeat(32));
                assert_eq!(value["profile"]["manifest"], profile["manifest"]);
                assert_eq!(value["profile"]["algorithm"], profile["algorithm"]);
                assert_eq!(value["profile"]["constants"], profile["constants"]);
            }),
            LineageMutation::StatementProgram => mutate_overlay_json(&mut self.input, |value| {
                let elf = value["guest"]["elf"].clone();
                value["guest"]["imageId"] = serde_json::json!("16".repeat(32));
                assert_eq!(value["guest"]["elf"], elf);
            }),
            LineageMutation::StatementContract => mutate_overlay_json(&mut self.input, |value| {
                value["referenceStatement"]["contractId"] = serde_json::json!("17".repeat(32));
            }),
            LineageMutation::StatementChain => mutate_overlay_json(&mut self.input, |value| {
                value["referenceStatement"]["chainDomainId"] = serde_json::json!("18".repeat(32));
            }),
            LineageMutation::StatementPayloadLength => {
                mutate_overlay_json(&mut self.input, |value| {
                    let statement = &mut value["referenceStatement"];
                    let digest = statement["applicationPayloadSha256"].clone();
                    statement["applicationPayloadByteLength"] = serde_json::json!(
                        statement["applicationPayloadByteLength"].as_u64().unwrap() + 1
                    );
                    assert_eq!(statement["applicationPayloadSha256"], digest);
                })
            }
            LineageMutation::StatementPayloadDigest => {
                mutate_overlay_json(&mut self.input, |value| {
                    let statement = &mut value["referenceStatement"];
                    let length = statement["applicationPayloadByteLength"].clone();
                    statement["applicationPayloadSha256"] = serde_json::json!("19".repeat(32));
                    assert_eq!(statement["applicationPayloadByteLength"], length);
                })
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the exhaustive mutation-to-valid-authority mapping remains explicit for auditability"
    )]
    fn campaign_for(&self, mutation: LineageMutation) -> &B4CampaignPrecommitAuthorityV1 {
        let nominal_input = self.support.positive_generation_authority.input_set();
        match mutation {
            LineageMutation::CampaignPositiveInputMismatch => {
                let alternate = terminal_lineage_alternate_campaigns();
                assert_ne!(
                    alternate.different_input.precommit().input_set,
                    *nominal_input
                );
                &alternate.different_input
            }
            LineageMutation::CampaignExecutorContent => {
                let alternate = terminal_lineage_alternate_campaigns();
                assert_eq!(
                    alternate.different_executor.precommit().input_set,
                    *nominal_input
                );
                let generation: serde_json::Value =
                    serde_json::from_slice(self.support.positive_generation_set.bytes.as_slice())
                        .expect("nominal generation JSON");
                let generator = &generation["proofGeneratorArtifact"];
                assert_ne!(
                    (
                        alternate
                            .different_executor
                            .precommit()
                            .campaign_executor
                            .artifact
                            .byte_length,
                        alternate
                            .different_executor
                            .precommit()
                            .campaign_executor
                            .artifact
                            .sha256
                            .as_str(),
                    ),
                    (
                        generator["byteLength"].as_u64().unwrap(),
                        generator["sha256"].as_str().unwrap(),
                    ),
                );
                assert!(
                    alternate
                        .different_executor
                        .precommit()
                        .campaign_executor
                        .artifact
                        .byte_length
                        > 0
                );
                &alternate.different_executor
            }
            LineageMutation::InputPath
            | LineageMutation::InputByte
            | LineageMutation::InputDuplicateKey
            | LineageMutation::InputTrailingContent
            | LineageMutation::InputUnknownField
            | LineageMutation::InputNonCanonical
            | LineageMutation::GenerationPath
            | LineageMutation::GenerationByte
            | LineageMutation::GenerationDuplicateKey
            | LineageMutation::GenerationTrailingContent
            | LineageMutation::GenerationUnknownField
            | LineageMutation::GenerationNonCanonical
            | LineageMutation::GenerationWrongCaseCount
            | LineageMutation::GenerationInputCommitment
            | LineageMutation::GenerationProofGenerator
            | LineageMutation::Case0WrongOrdinal
            | LineageMutation::Case0WrongRecipe
            | LineageMutation::Case8WrongId
            | LineageMutation::Case8WrongRecipe
            | LineageMutation::Case9WrongRecipe
            | LineageMutation::Case0PrimaryMissing
            | LineageMutation::Case0PrimaryExtra
            | LineageMutation::Case0AuxiliaryExtra
            | LineageMutation::Case8PrimaryReordered
            | LineageMutation::Case8AuxiliaryReordered
            | LineageMutation::Case9PrimaryDuplicated
            | LineageMutation::Case9AuxiliaryMissing
            | LineageMutation::ManifestAbsolutePath
            | LineageMutation::ManifestWrongCaseDirectory
            | LineageMutation::PrimaryEscapingPath
            | LineageMutation::PrimaryDrivePrefix
            | LineageMutation::PrimaryDotSegment
            | LineageMutation::PrimaryBackslash
            | LineageMutation::PrimaryWrongBasename
            | LineageMutation::AuxiliaryCrossCasePath
            | LineageMutation::SelectedPathDuplicate
            | LineageMutation::SelectedPathAncestor
            | LineageMutation::SelectedPathDescendant
            | LineageMutation::Case0EachPrimaryByte
            | LineageMutation::Case8EachPrimaryByte
            | LineageMutation::Case9EachPrimaryByte
            | LineageMutation::Case8EachAuxiliaryByte
            | LineageMutation::Case9EachAuxiliaryByte
            | LineageMutation::Case0ManifestByte
            | LineageMutation::Case8ManifestByte
            | LineageMutation::Case9ManifestByte
            | LineageMutation::GeneratedRole
            | LineageMutation::GeneratedEncoding
            | LineageMutation::GeneratedLength
            | LineageMutation::GeneratedContentHex
            | LineageMutation::GeneratedCodec
            | LineageMutation::ManifestEntryMissing
            | LineageMutation::ManifestEntryExtra
            | LineageMutation::ManifestEntryDuplicated
            | LineageMutation::ManifestEntryReordered
            | LineageMutation::CoordinatedSourceManifestRewrite
            | LineageMutation::CoordinatedSourceManifestGenerationRewrite
            | LineageMutation::GuestPath
            | LineageMutation::GuestByte
            | LineageMutation::GuestImageId
            | LineageMutation::Case0ImageId
            | LineageMutation::Case8ImageId
            | LineageMutation::Case9ImageId
            | LineageMutation::Case0Journal
            | LineageMutation::Case8Journal
            | LineageMutation::Case9Journal
            | LineageMutation::StatementProfile
            | LineageMutation::StatementProgram
            | LineageMutation::StatementContract
            | LineageMutation::StatementChain
            | LineageMutation::StatementPayloadLength
            | LineageMutation::StatementPayloadDigest => &self.support.campaign_precommit_authority,
        }
    }
}

#[test]
fn constructor_signature_is_fixed() {
    let _: for<'a> fn(
        &B4CampaignPrecommitAuthorityV1,
        &B4PositiveGenerationAuthorityV1,
        B4TerminalSourceExternalClosureV1<'a>,
    ) -> anyhow::Result<B4TerminalSourceLineageAuthorityV1> =
        B4TerminalSourceLineageAuthorityV1::from_external_closure;
}

#[test]
fn authority_binding_verifier_signature_is_non_projective() {
    let _: fn(
        &B4TerminalSourceLineageAuthorityV1,
        &B4CampaignPrecommitAuthorityV1,
        &B4PositiveGenerationAuthorityV1,
    ) -> anyhow::Result<()> = B4TerminalSourceLineageAuthorityV1::verify_authority_bindings;
}

#[test]
fn fixed_lineage_verifies_its_exact_authority_bindings() {
    let support = terminal_lineage_base_support();
    let authority = construct_nominal(support).expect("fixed terminal-source lineage");

    authority
        .verify_authority_bindings(
            &support.campaign_precommit_authority,
            &support.positive_generation_authority,
        )
        .expect("nominal lineage authority bindings");
}

#[test]
fn authority_binding_verifier_rejects_a_different_canonical_precommit() {
    let support = terminal_lineage_base_support();
    let authority = construct_nominal(support).expect("fixed terminal-source lineage");
    let alternate = terminal_lineage_alternate_campaigns();
    assert_eq!(
        alternate.different_executor.precommit().input_set,
        *support.positive_generation_authority.input_set(),
    );

    let error = authority
        .verify_authority_bindings(
            &alternate.different_executor,
            &support.positive_generation_authority,
        )
        .expect_err("different canonical precommit must not bind the retained lineage");
    assert!(
        format!("{error:#}").contains("RetainedCampaignAuthority"),
        "unexpected precommit-binding failure: {error:#}",
    );
}

#[test]
fn authority_binding_verifier_rejects_a_different_positive_generation() {
    let support = terminal_lineage_base_support();
    let alternate = terminal_lineage_alternate_positive_support();
    let authority = construct_nominal(support).expect("fixed terminal-source lineage");
    assert_eq!(
        alternate.positive_generation_authority.input_set(),
        support.positive_generation_authority.input_set(),
    );
    assert_ne!(
        alternate.positive_generation_authority.generation_set(),
        support.positive_generation_authority.generation_set(),
    );

    let error = authority
        .verify_authority_bindings(
            &support.campaign_precommit_authority,
            &alternate.positive_generation_authority,
        )
        .expect_err("different positive generation must not bind the retained lineage");
    assert!(
        format!("{error:#}").contains("RetainedPositiveGenerationAuthority"),
        "unexpected generation-binding failure: {error:#}",
    );
}

#[test]
fn authority_binding_verifier_rechecks_the_retained_positive_input_identity() {
    let support = terminal_lineage_base_support();
    let mut authority = construct_nominal(support).expect("fixed terminal-source lineage");
    authority.positive_input_set.sha256 = "00".repeat(32);

    let error = authority
        .verify_authority_bindings(
            &support.campaign_precommit_authority,
            &support.positive_generation_authority,
        )
        .expect_err("different retained positive input identity must not verify");
    assert!(
        format!("{error:#}").contains("RetainedPositiveInputAuthority"),
        "unexpected input-binding failure: {error:#}",
    );
}

#[test]
fn authority_binding_verifier_rechecks_the_retained_executor_measurement() {
    let support = terminal_lineage_base_support();
    let mut authority = construct_nominal(support).expect("fixed terminal-source lineage");
    authority.proof_generator.sha256 = "00".repeat(32);

    let error = authority
        .verify_authority_bindings(
            &support.campaign_precommit_authority,
            &support.positive_generation_authority,
        )
        .expect_err("different retained executor measurement must not verify");
    assert!(
        format!("{error:#}").contains(
            "supplied campaign executor differs from the retained terminal-source proof generator"
        ),
        "unexpected executor-binding failure: {error:#}",
    );
}

#[test]
fn authority_binding_verifier_rechecks_retained_provenance() {
    let support = terminal_lineage_base_support();
    let mut provenance_drift =
        construct_nominal(support).expect("fixed terminal-source lineage for provenance drift");
    let omitted = support
        .campaign_precommit_authority
        .artifact_paths()
        .iter()
        .next()
        .expect("nonempty campaign path closure");
    assert!(provenance_drift.provenance_paths.remove(omitted));
    let error = provenance_drift
        .verify_authority_bindings(
            &support.campaign_precommit_authority,
            &support.positive_generation_authority,
        )
        .expect_err("incomplete retained provenance must not verify");
    assert!(
        format!("{error:#}").contains("RetainedAuthorityProvenance"),
        "unexpected provenance-binding failure: {error:#}",
    );
}

#[test]
fn authority_binding_verifier_rechecks_retained_case_custody() {
    let support = terminal_lineage_base_support();
    let mut custody_drift =
        construct_nominal(support).expect("fixed terminal-source lineage for custody drift");
    custody_drift.case_custody.swap(0, 1);
    let error = custody_drift
        .verify_authority_bindings(
            &support.campaign_precommit_authority,
            &support.positive_generation_authority,
        )
        .expect_err("reordered retained case custody must not verify");
    assert!(
        format!("{error:#}").contains("RetainedPositiveCaseCustody"),
        "unexpected custody-binding failure: {error:#}",
    );
}

#[test]
fn authority_binding_verifier_rechecks_retained_case_manifest_measurement() {
    let support = terminal_lineage_base_support();
    let mut authority = construct_nominal(support).expect("fixed terminal-source lineage");
    authority.case_custody[0].proof_output_manifest.sha256[0] ^= 1;

    let error = authority
        .verify_authority_bindings(
            &support.campaign_precommit_authority,
            &support.positive_generation_authority,
        )
        .expect_err("different retained manifest measurement must not verify");
    assert!(
        format!("{error:#}").contains("RetainedPositiveCaseCustody"),
        "unexpected manifest-custody failure: {error:#}",
    );
}

#[test]
fn authority_binding_verifier_rechecks_retained_opaque_manifest_measurement() {
    let support = terminal_lineage_base_support();
    let mut authority = construct_nominal(support).expect("fixed terminal-source lineage");
    authority.case_custody[0]
        .opaque_proof_output_manifest
        .sha256[0] ^= 1;

    let error = authority
        .verify_authority_bindings(
            &support.campaign_precommit_authority,
            &support.positive_generation_authority,
        )
        .expect_err("different retained opaque manifest measurement must not verify");
    assert!(
        format!("{error:#}").contains("RetainedPositiveCaseCustody"),
        "unexpected opaque-manifest custody failure: {error:#}",
    );
}

#[test]
fn authority_binding_verifier_rechecks_retained_case_raw_seal_measurement() {
    let support = terminal_lineage_base_support();
    let mut authority = construct_nominal(support).expect("fixed terminal-source lineage");
    authority.case_custody[1].opaque_raw_seal.sha256[0] ^= 1;

    let error = authority
        .verify_authority_bindings(
            &support.campaign_precommit_authority,
            &support.positive_generation_authority,
        )
        .expect_err("different retained raw-seal measurement must not verify");
    assert!(
        format!("{error:#}").contains("RetainedPositiveCaseCustody"),
        "unexpected raw-seal custody failure: {error:#}",
    );
}

#[test]
fn authority_binding_verifier_rechecks_retained_physical_raw_seal_measurement() {
    let support = terminal_lineage_base_support();
    let mut authority = construct_nominal(support).expect("fixed terminal-source lineage");
    let raw_seal_position = role_position(8, B4PositiveArtifactRole::RawSeal);
    authority.case_custody[1].primary_measurements[raw_seal_position].sha256[0] ^= 1;

    let error = authority
        .verify_authority_bindings(
            &support.campaign_precommit_authority,
            &support.positive_generation_authority,
        )
        .expect_err("different retained physical raw-seal measurement must not verify");
    assert!(
        format!("{error:#}").contains("RetainedPositiveCaseCustody"),
        "unexpected physical raw-seal custody failure: {error:#}",
    );
}

#[test]
fn authority_binding_verifier_rechecks_retained_primary_cardinality() {
    let support = terminal_lineage_base_support();
    let mut authority = construct_nominal(support).expect("fixed terminal-source lineage");
    authority.case_custody[0]
        .primary_measurements
        .pop()
        .expect("nonempty selected primary custody");

    let error = authority
        .verify_authority_bindings(
            &support.campaign_precommit_authority,
            &support.positive_generation_authority,
        )
        .expect_err("different retained primary cardinality must not verify");
    assert!(
        format!("{error:#}").contains("RetainedPositiveCaseCustody"),
        "unexpected primary-cardinality failure: {error:#}",
    );
}

#[test]
fn authority_binding_verifier_rechecks_retained_auxiliary_cardinality() {
    let support = terminal_lineage_base_support();
    let mut authority = construct_nominal(support).expect("fixed terminal-source lineage");
    authority.case_custody[1]
        .auxiliary_measurements
        .pop()
        .expect("nonempty selected auxiliary custody");

    let error = authority
        .verify_authority_bindings(
            &support.campaign_precommit_authority,
            &support.positive_generation_authority,
        )
        .expect_err("different retained auxiliary cardinality must not verify");
    assert!(
        format!("{error:#}").contains("RetainedPositiveCaseCustody"),
        "unexpected auxiliary-cardinality failure: {error:#}",
    );
}

#[test]
fn fixed_real_authorities_construct_the_five_byte_view() {
    let support = terminal_lineage_base_support();
    let authority = construct_nominal(support).expect("fixed terminal-source lineage");
    let view = authority.producer_source();
    assert_eq!(view.guest_elf(), support.consumer_guest_elf.bytes);
    assert_eq!(view.statement(), support.case0_journal());
    assert_eq!(
        view.case0_lift15_receipt_oracle(),
        support.case0_receipt_oracle(),
    );
    assert_eq!(
        view.case8_terminal_join_recursive_oracle(),
        support.case8_receipt_oracle(),
    );
    assert_eq!(
        view.case9_terminal_resolve_recursive_oracle(),
        support.case9_receipt_oracle(),
    );
    for raw_seal in support.selected_raw_seals() {
        assert!(
            [
                view.case0_lift15_receipt_oracle(),
                view.case8_terminal_join_recursive_oracle(),
                view.case9_terminal_resolve_recursive_oracle(),
            ]
            .iter()
            .all(|oracle| *oracle != raw_seal)
        );
    }
}

#[test]
fn producer_view_excludes_manifests_auxiliaries_and_raw_seals() {
    let support = terminal_lineage_base_support();
    let authority = construct_nominal(support).expect("fixed terminal-source lineage");
    let view = authority.producer_source();
    let producer_oracles = [
        view.case0_lift15_receipt_oracle(),
        view.case8_terminal_join_recursive_oracle(),
        view.case9_terminal_resolve_recursive_oracle(),
    ];
    for raw_seal in support.selected_raw_seals() {
        assert!(
            producer_oracles.iter().all(|oracle| *oracle != raw_seal),
            "producer receipt-oracle view leaked a selected raw seal",
        );
    }
}

#[test]
fn campaign_cannot_preclaim_the_post_proof_generation_path() {
    let support = terminal_lineage_generation_path_collision_support();
    let Err(error) = construct_nominal(support) else {
        panic!(
            "generation-path collision authenticated instead of reaching {}",
            LineageFailureBoundary::PriorPathMerge.label(),
        );
    };
    let complete_chain = error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ");
    assert!(
        complete_chain.contains(LineageFailureBoundary::PriorPathMerge.label()),
        "generation-path collision expected {} in complete error chain, got: {}",
        LineageFailureBoundary::PriorPathMerge.label(),
        complete_chain,
    );
}

#[test]
fn coordinated_case8_rewrite_is_rejected_by_original_case_authority_in_shared_core() {
    let support = terminal_lineage_base_support();
    let mut fixture = LineageFixture::nominal(support);
    let nominal_generation = fixture.generation.bytes.as_ref().to_vec();
    let nominal_manifest = fixture.case8.manifest.bytes.as_ref().to_vec();
    let nominal_receipt_position = role_position(8, B4PositiveArtifactRole::ReceiptOracle);
    let nominal_receipt = fixture.case8.primary[nominal_receipt_position]
        .bytes
        .as_ref()
        .to_vec();
    fixture.rewrite_case8_receipt_closure(true);

    assert_eq!(
        fixture.guest.bytes.as_ref(),
        support.consumer_guest_elf.bytes
    );
    assert_ne!(fixture.generation.bytes.as_ref(), nominal_generation);
    assert_ne!(fixture.case8.manifest.bytes.as_ref(), nominal_manifest);
    assert_ne!(
        fixture.case8.primary[nominal_receipt_position]
            .bytes
            .as_ref(),
        nominal_receipt
    );
    assert_eq!(
        fixture.case8.primary[nominal_receipt_position].bytes.len(),
        nominal_receipt.len(),
    );
    for (position, source) in fixture.case8.primary.iter().enumerate() {
        if position != nominal_receipt_position {
            assert_eq!(
                source.bytes.as_ref(),
                support.case8_primary_artifacts[position].bytes,
                "non-receipt case-8 primary position {position} changed",
            );
        }
    }
    for (source, nominal) in fixture
        .case8
        .auxiliary
        .iter()
        .zip(&support.case8_auxiliary_artifacts)
    {
        assert_eq!(source.bytes.as_ref(), nominal.bytes);
    }
    for role in [
        B4PositiveArtifactRole::ImageId,
        B4PositiveArtifactRole::Journal,
        B4PositiveArtifactRole::RawSeal,
    ] {
        let position = role_position(8, role);
        assert_eq!(
            fixture.case8.primary[position].bytes.as_ref(),
            support.case8_primary_artifacts[position].bytes,
        );
    }

    let generation =
        B4PositiveGenerationDocumentV1::from_canonical_jcs(fixture.generation.bytes.as_ref())
            .expect("internally consistent rewritten generation JCS");
    let primary = fixture
        .case8
        .primary
        .iter()
        .map(|source| B4PositiveSourceBytesV1 {
            path: source.path.as_ref(),
            bytes: source.bytes.as_ref(),
        })
        .collect::<Vec<_>>();
    let auxiliary = fixture
        .case8
        .auxiliary
        .iter()
        .map(|source| B4PositiveSourceBytesV1 {
            path: source.path.as_ref(),
            bytes: source.bytes.as_ref(),
        })
        .collect::<Vec<_>>();
    let mut paths = BTreeSet::new();
    let original_case = &support.positive_generation_authority.cases()[8];
    assert_eq!(usize::from(original_case.case_index()), 8);

    let error = authenticate_positive_case_source(
        &generation,
        original_case,
        8,
        B4PositiveCaseSourceV1 {
            proof_output_manifest_jcs: fixture.case8.manifest.bytes.as_ref(),
            primary_artifacts: &primary,
            auxiliary_artifacts: &auxiliary,
        },
        &mut paths,
    )
    .expect_err("rewritten case 8 retained the original opaque authority");
    let chain = format!("{error:#}");
    assert!(
        chain.contains(
            "positive selected-case proof-output manifest differs from the opaque generation authority"
        ),
        "rewrite stopped before the opaque case authority: {chain}"
    );
}

#[test]
fn fixed_lineage_rejects_every_external_drift_class() {
    for attempt in lineage_attempts() {
        let expected = attempt.mutation.expected_boundary();
        let mut fixture = LineageFixture::nominal(terminal_lineage_base_support());
        let witness = fixture.apply(attempt);
        witness.assert_applied();
        let campaign = fixture.campaign_for(attempt.mutation);
        let Err(error) = fixture.construct(campaign) else {
            panic!(
                "{:?} position {:?} authenticated instead of reaching {}",
                attempt.mutation,
                attempt.position,
                expected.label(),
            );
        };
        let complete_chain = error
            .chain()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(": ");
        assert!(
            complete_chain.contains(expected.label()),
            "{:?} position {:?} expected {} in complete error chain, got: {}",
            attempt.mutation,
            attempt.position,
            expected.label(),
            complete_chain,
        );
    }
}
