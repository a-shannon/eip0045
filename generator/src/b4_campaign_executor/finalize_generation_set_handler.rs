//! Descriptor-rooted production handler for `finalize-generation-set`.

use std::path::Path;

use anyhow::{Context as _, Result, ensure};

use super::preflight::{ProjectedSingleFileCampaignLayout, project_single_file_campaign_layout};

const REPRODUCTION_ROOT_COMPONENT: &str = "reproduction";
const POSTPROOF_ROOT_COMPONENT: &str = "postproof";
const POSITIVE_GENERATION_SET_FILE: &str = "positive-generation-set-v2.json";
const POSITIVE_GENERATION_SET_CAMPAIGN_PATH: &str =
    "reproduction/postproof/positive-generation-set-v2.json";

fn project_finalize_generation_set_layout<const ROOTS: usize>(
    campaign_root: &Path,
    prior_roots: [&Path; ROOTS],
    outer_final_root: &Path,
) -> Result<ProjectedSingleFileCampaignLayout<ROOTS>> {
    ensure!(
        outer_final_root
            == campaign_root
                .join(REPRODUCTION_ROOT_COMPONENT)
                .join(POSTPROOF_ROOT_COMPONENT),
        "finalize-generation-set output root must be the canonical reproduction/postproof root"
    );
    project_single_file_campaign_layout(
        campaign_root,
        prior_roots,
        outer_final_root,
        POSITIVE_GENERATION_SET_FILE,
    )
    .context("cannot project finalize-generation-set campaign layout")
}

#[cfg(all(
    feature = "b4-finalize-generation-set-handler",
    any(target_os = "linux", test)
))]
mod execute {
    use std::{env, ffi::OsString, path::Path};

    use anyhow::{Context as _, Result, ensure};
    use eip_0045_reproduction::{
        b4_build_check::{AuthoritativeB4BuildProjection, B4BuildExpectations},
        b4_campaign_contract::{
            B4CampaignPrecommitAuthorityV1, B4ContractArtifactEncodingV1,
            B4ContractArtifactIdentityV1, B4PositiveGenerationAuthorityV2,
            Eip0045B4CampaignPrecommitV1,
            B4PositiveGenerationCaseExternalV2, B4PositiveGenerationExternalBytesV2,
            B4PositiveGenerationExternalClosureV2, MAX_CAMPAIGN_PRECOMMIT_BYTES,
            B4TrustedHostRequestV1, Eip0045B4TrustedHostCampaignPrecommitV1,
            validate_b4_campaign_command_invocation,
        },
        b4_positive_gate::{
            B4ValidatedPositiveGenerationPreacceptanceV2, GeneratedArtifactContents,
            GeneratedAuxiliaryArtifactContents, NamedCanonicalJcs, PositiveGenerationCaseDocuments,
            PositiveGenerationDocuments, construct_canonical_positive_generation_set_jcs_v2,
            construct_canonical_positive_generation_set_jcs_trusted_host_v1,
            validate_and_bind_v2_positive_generation_preacceptance,
        },
        b4_positive_input_set::{
            B4_POSITIVE_INPUT_SET_COMPLETION_MAX_BYTES, B4_POSITIVE_INPUT_SET_MAX_BYTES,
            B4PositiveInputSetPublicationBindingV2, B4PositiveInputSetPublicationPathsV2,
            bind_b4_positive_input_set_publication_v2,
            project_b4_positive_input_set_publication_paths_v2,
            validate_b4_positive_input_set_completion_jcs_v2,
            B4ValidatedTrustedHostInputSetCompletionV1,
            project_b4_trusted_host_input_set_paths_v1,
            validate_b4_trusted_host_input_set_completion_jcs_v1,
        },
    };

    use super::{
        POSITIVE_GENERATION_SET_CAMPAIGN_PATH, POSITIVE_GENERATION_SET_FILE,
        ProjectedSingleFileCampaignLayout, project_finalize_generation_set_layout,
    };
    use crate::b4_campaign_executor::{
        authenticated_preflight::{
            authenticate_campaign_precommit_file, derive_campaign_relative_artifact_path,
            require_current_executable_binding,
        },
        finalize_generation_set::coordinate_finalize_generation_set,
        typestate::{ExecutorExecuteContext, ExecutorPreflightContext},
    };

    const COMMAND: &str = "finalize-generation-set";
    const POSITIVE_INPUT_SET_FILE: &str = "positive-input-set.json";
    const POSITIVE_INPUT_SET_COMPLETION_FILE: &str = "positive-input-set-completion.json";
    const MAX_ROOTS: usize = 16;
    const MAX_NESTED_INPUT_SOURCES: usize = 4096;
    const MAX_POSITIVE_GENERATION_SET_BYTES: usize = 1024 * 1024;
    // Handler-local resource policy: custody admits at most 512 MiB per
    // retained proof artifact and this handler admits at most 1 GiB in total.
    const MAX_RETAINED_ARTIFACT_BYTES: usize = 512 * 1024 * 1024;
    const MAX_RETAINED_TOTAL_BYTES: usize = 1024 * 1024 * 1024;
    const LIFT_PRIMARY_SOURCE_FILES: [&str; 7] = [
        "candidate-claim-digest.bin",
        "candidate-control-id.bin",
        "candidate-image-id.bin",
        "candidate-journal.bin",
        "candidate-metadata.json",
        "candidate-raw-seal.bin",
        "candidate-receipt-oracle.bincode",
    ];
    const RECURSIVE_PRIMARY_SOURCE_FILES: [&str; 8] = [
        "candidate-ancestry.json",
        "candidate-recursive-calibration.json",
        "candidate-claim-digest.bin",
        "candidate-control-id.bin",
        "candidate-image-id.bin",
        "candidate-journal.bin",
        "candidate-raw-seal.bin",
        "candidate-recursive-oracle.borsh",
    ];
    const RECURSIVE_AUXILIARY_COUNTS: [usize; 3] = [2, 2, 4];

    /// One descriptor-rooted immutable input locator. It carries no bytes or authority.
    #[derive(Clone, Copy, Debug)]
    pub(crate) struct FinalizeGenerationSetArtifactLocatorV1<'source> {
        pub(crate) root_index: usize,
        pub(crate) root_relative_path: &'source str,
    }

    impl<'source> FinalizeGenerationSetArtifactLocatorV1<'source> {
        pub(crate) const fn new(root_index: usize, root_relative_path: &'source str) -> Self {
            Self {
                root_index,
                root_relative_path,
            }
        }
    }

    /// One primary proof-output locator with its closed source filename.
    #[derive(Clone, Copy, Debug)]
    pub(crate) struct FinalizeGenerationPrimaryArtifactLocatorV1<'source> {
        pub(crate) source_file: &'source str,
        pub(crate) artifact: FinalizeGenerationSetArtifactLocatorV1<'source>,
    }

    /// One recursive auxiliary locator with its manifest-relative source path.
    #[derive(Clone, Copy, Debug)]
    pub(crate) struct FinalizeGenerationAuxiliaryArtifactLocatorV1<'source> {
        pub(crate) relative_path: &'source str,
        pub(crate) artifact: FinalizeGenerationSetArtifactLocatorV1<'source>,
    }

    /// Fixed physical source shape for one of the eleven positive cases.
    pub(crate) enum FinalizeGenerationCaseSourcePlanV1<'source> {
        Lift {
            proof_output_manifest: FinalizeGenerationSetArtifactLocatorV1<'source>,
            primary_artifacts: [FinalizeGenerationPrimaryArtifactLocatorV1<'source>; 7],
        },
        Recursive {
            proof_output_manifest: FinalizeGenerationSetArtifactLocatorV1<'source>,
            primary_artifacts: [FinalizeGenerationPrimaryArtifactLocatorV1<'source>; 8],
            auxiliary_artifacts: &'source [FinalizeGenerationAuxiliaryArtifactLocatorV1<'source>],
        },
    }

    /// Complete locator-only source closure; no generation-set bytes enter this surface.
    pub(crate) struct FinalizeGenerationSetSourcePlanV1<'source> {
        pub(crate) positive_input_phase_root_index: usize,
        pub(crate) build_evidence_root_index: usize,
        pub(crate) proof_generator: FinalizeGenerationSetArtifactLocatorV1<'source>,
        pub(crate) runner_profiles: [FinalizeGenerationSetArtifactLocatorV1<'source>; 4],
        pub(crate) validator_descriptors: [FinalizeGenerationSetArtifactLocatorV1<'source>; 2],
        pub(crate) nested_input_sources:
            &'source [FinalizeGenerationSetArtifactLocatorV1<'source>],
        pub(crate) cases: [FinalizeGenerationCaseSourcePlanV1<'source>; 11],
    }

    /// Three mandatory caller-owned anchors for authoritative build validation.
    #[derive(Clone, Copy, Debug)]
    pub(crate) struct FinalizeGenerationSetBuildAnchorsV1<'source> {
        pub(crate) source_commit: &'source str,
        pub(crate) source_tree: &'source str,
        pub(crate) evidence_root: &'source str,
    }

    impl FinalizeGenerationSetBuildAnchorsV1<'_> {
        fn expectations(&self) -> B4BuildExpectations<'_> {
            B4BuildExpectations {
                expected_source_commit: Some(self.source_commit),
                expected_source_tree: Some(self.source_tree),
                expected_evidence_root: Some(self.evidence_root),
            }
        }
    }

    /// Typed byte-free inputs reconstructed by the private command dispatcher.
    pub(crate) struct FinalizeGenerationSetExecuteInputsV1<'authority, 'source, const ROOTS: usize> {
        configured_executor_artifact: &'authority Path,
        campaign_root: &'authority Path,
        prior_roots: [&'authority Path; ROOTS],
        outer_final_root: &'authority Path,
        campaign_precommit: &'authority B4CampaignPrecommitAuthorityV1,
        campaign_precommit_root_index: usize,
        campaign_precommit_root_relative_path: &'source str,
        build_anchors: FinalizeGenerationSetBuildAnchorsV1<'source>,
        source_plan: FinalizeGenerationSetSourcePlanV1<'source>,
    }

    impl<'authority, 'source, const ROOTS: usize>
        FinalizeGenerationSetExecuteInputsV1<'authority, 'source, ROOTS>
    {
        #[allow(
            clippy::too_many_arguments,
            reason = "the handler retains every independently captured root and authority explicitly"
        )]
        pub(crate) const fn new(
            configured_executor_artifact: &'authority Path,
            campaign_root: &'authority Path,
            prior_roots: [&'authority Path; ROOTS],
            outer_final_root: &'authority Path,
            campaign_precommit: &'authority B4CampaignPrecommitAuthorityV1,
            campaign_precommit_root_index: usize,
            campaign_precommit_root_relative_path: &'source str,
            build_anchors: FinalizeGenerationSetBuildAnchorsV1<'source>,
            source_plan: FinalizeGenerationSetSourcePlanV1<'source>,
        ) -> Self {
            Self {
                configured_executor_artifact,
                campaign_root,
                prior_roots,
                outer_final_root,
                campaign_precommit,
                campaign_precommit_root_index,
                campaign_precommit_root_relative_path,
                build_anchors,
                source_plan,
            }
        }
    }

    struct CapturedFinalizeGenerationSetInvocation {
        process_argv: Vec<OsString>,
        parsed_preflight_only: bool,
    }

    impl CapturedFinalizeGenerationSetInvocation {
        fn capture(parsed_preflight_only: bool) -> Result<Self> {
            let process_argv = env::args_os().collect::<Vec<_>>();
            validate_b4_campaign_command_invocation(&process_argv, COMMAND, parsed_preflight_only)
                .context("invalid retained finalize-generation-set invocation argv")?;
            Ok(Self {
                process_argv,
                parsed_preflight_only,
            })
        }

        fn revalidate(&self) -> Result<()> {
            validate_b4_campaign_command_invocation(
                &self.process_argv,
                COMMAND,
                self.parsed_preflight_only,
            )
            .context("retained finalize-generation-set invocation changed")
        }
    }

    struct RetainedArtifactV1 {
        campaign_relative_path: String,
        bytes: Vec<u8>,
    }

    impl RetainedArtifactV1 {
        fn as_external(&self) -> B4PositiveGenerationExternalBytesV2<'_> {
            B4PositiveGenerationExternalBytesV2 {
                path: &self.campaign_relative_path,
                bytes: &self.bytes,
            }
        }

        fn as_named_jcs(&self) -> NamedCanonicalJcs<'_> {
            NamedCanonicalJcs {
                relative_path: &self.campaign_relative_path,
                bytes: &self.bytes,
            }
        }
    }

    struct RetainedPrimaryArtifactV1 {
        source_file: String,
        artifact: RetainedArtifactV1,
    }

    struct RetainedAuxiliaryArtifactV1 {
        relative_path: String,
        artifact: RetainedArtifactV1,
    }

    struct RetainedCaseV1 {
        proof_output_manifest: RetainedArtifactV1,
        primary_artifacts: Vec<RetainedPrimaryArtifactV1>,
        auxiliary_artifacts: Vec<RetainedAuxiliaryArtifactV1>,
    }

    struct RetainedGenerationClosureV1 {
        positive_input_set: RetainedInputSet,
        proof_generator: RetainedArtifactV1,
        runner_profiles: [RetainedArtifactV1; 4],
        validator_descriptors: [RetainedArtifactV1; 2],
        nested_input_sources: Vec<RetainedArtifactV1>,
        cases: [RetainedCaseV1; 11],
    }

    enum RetainedInputSet {
        H0(B4PositiveInputSetPublicationBindingV2),
        TrustedHost {
            path: String,
            bytes: Vec<u8>,
            completion: B4ValidatedTrustedHostInputSetCompletionV1,
        },
    }

    impl RetainedInputSet {
        fn input_set_path(&self) -> &str {
            match self { Self::H0(binding) => binding.input_set_path(),
                Self::TrustedHost { path, .. } => path }
        }

        fn input_set_jcs(&self) -> &[u8] {
            match self { Self::H0(binding) => binding.input_set_jcs(),
                Self::TrustedHost { bytes, .. } => bytes }
        }

        fn construct_generation_set(&self, proof_generator: &[u8],
            cases: [PositiveGenerationCaseDocuments<'_>; 11]) -> Result<Vec<u8>> {
            match self {
                Self::H0(binding) => construct_canonical_positive_generation_set_jcs_v2(
                    binding, proof_generator, cases),
                Self::TrustedHost { path, bytes, completion } =>
                    construct_canonical_positive_generation_set_jcs_trusted_host_v1(
                        completion,
                        NamedCanonicalJcs { relative_path: path, bytes },
                        proof_generator, cases),
            }
        }
    }

    #[derive(Default)]
    struct RetainedByteBudget {
        total: usize,
    }

    impl RetainedByteBudget {
        fn add(&mut self, byte_length: usize) -> Result<()> {
            self.total = self
                .total
                .checked_add(byte_length)
                .context("retained finalize-generation-set byte count overflowed")?;
            ensure!(
                self.total <= MAX_RETAINED_TOTAL_BYTES,
                "retained finalize-generation-set inputs exceed the compiled total byte bound"
            );
            Ok(())
        }
    }

    fn require_locator_in_bounds<const ROOTS: usize>(
        locator: &FinalizeGenerationSetArtifactLocatorV1<'_>,
        label: &str,
    ) -> Result<()> {
        ensure!(
            locator.root_index < ROOTS,
            "{label} root index is outside the retained root set"
        );
        ensure!(
            !locator.root_relative_path.is_empty(),
            "{label} root-relative path is empty"
        );
        Ok(())
    }

    fn validate_source_plan<const ROOTS: usize>(
        plan: &FinalizeGenerationSetSourcePlanV1<'_>,
    ) -> Result<()> {
        ensure!(
            (1..=MAX_ROOTS).contains(&ROOTS),
            "finalize-generation-set root count is outside the compiled bound"
        );
        ensure!(
            plan.positive_input_phase_root_index < ROOTS,
            "positive input phase root index is outside the retained root set"
        );
        ensure!(
            plan.build_evidence_root_index < ROOTS,
            "build-evidence root index is outside the retained root set"
        );
        ensure!(
            plan.nested_input_sources.len() <= MAX_NESTED_INPUT_SOURCES,
            "nested positive-input source count exceeds the compiled bound"
        );
        require_locator_in_bounds::<ROOTS>(&plan.proof_generator, "proof generator")?;
        for locator in plan
            .runner_profiles
            .iter()
            .chain(&plan.validator_descriptors)
            .chain(plan.nested_input_sources)
        {
            require_locator_in_bounds::<ROOTS>(locator, "positive-generation input")?;
        }
        for (case_index, case) in plan.cases.iter().enumerate() {
            match (case_index, case) {
                (
                    0..=7,
                    FinalizeGenerationCaseSourcePlanV1::Lift {
                        proof_output_manifest,
                        primary_artifacts,
                    },
                ) => {
                    require_locator_in_bounds::<ROOTS>(
                        proof_output_manifest,
                        "lift proof-output manifest",
                    )?;
                    for (artifact, expected) in
                        primary_artifacts.iter().zip(LIFT_PRIMARY_SOURCE_FILES)
                    {
                        ensure!(
                            artifact.source_file == expected,
                            "lift primary source-file order drift at case {case_index}"
                        );
                        require_locator_in_bounds::<ROOTS>(
                            &artifact.artifact,
                            "lift primary artifact",
                        )?;
                    }
                }
                (
                    8..=10,
                    FinalizeGenerationCaseSourcePlanV1::Recursive {
                        proof_output_manifest,
                        primary_artifacts,
                        auxiliary_artifacts,
                    },
                ) => {
                    require_locator_in_bounds::<ROOTS>(
                        proof_output_manifest,
                        "recursive proof-output manifest",
                    )?;
                    for (artifact, expected) in
                        primary_artifacts.iter().zip(RECURSIVE_PRIMARY_SOURCE_FILES)
                    {
                        ensure!(
                            artifact.source_file == expected,
                            "recursive primary source-file order drift at case {case_index}"
                        );
                        require_locator_in_bounds::<ROOTS>(
                            &artifact.artifact,
                            "recursive primary artifact",
                        )?;
                    }
                    let expected_auxiliary = RECURSIVE_AUXILIARY_COUNTS[case_index - 8];
                    ensure!(
                        auxiliary_artifacts.len() == expected_auxiliary,
                        "recursive auxiliary cardinality drift at case {case_index}"
                    );
                    for artifact in *auxiliary_artifacts {
                        ensure!(
                            !artifact.relative_path.is_empty(),
                            "recursive auxiliary relative path is empty at case {case_index}"
                        );
                        require_locator_in_bounds::<ROOTS>(
                            &artifact.artifact,
                            "recursive auxiliary artifact",
                        )?;
                    }
                }
                _ => anyhow::bail!(
                    "positive case kind differs from the closed lift/recursive index partition at case {case_index}"
                ),
            }
        }
        Ok(())
    }

    fn retain_artifact<const ROOTS: usize, F>(
        campaign_root: &Path,
        prior_roots: [&Path; ROOTS],
        read: &mut F,
        budget: &mut RetainedByteBudget,
        locator: &FinalizeGenerationSetArtifactLocatorV1<'_>,
    ) -> Result<RetainedArtifactV1>
    where
        F: FnMut(usize, &str) -> Result<Vec<u8>>,
    {
        require_locator_in_bounds::<ROOTS>(locator, "retained artifact")?;
        let prior_root = *prior_roots
            .get(locator.root_index)
            .context("artifact root index is outside the retained root set")?;
        let campaign_relative_path = derive_campaign_relative_artifact_path(
            campaign_root,
            prior_root,
            locator.root_relative_path,
        )?;
        let bytes = read(locator.root_index, locator.root_relative_path).with_context(|| {
            format!(
                "cannot retain finalize-generation-set input through immutable-root custody: {}",
                locator.root_relative_path
            )
        })?;
        budget.add(bytes.len())?;
        Ok(RetainedArtifactV1 {
            campaign_relative_path,
            bytes,
        })
    }

    fn retain_artifact_array<const ROOTS: usize, const COUNT: usize, F>(
        campaign_root: &Path,
        prior_roots: [&Path; ROOTS],
        read: &mut F,
        budget: &mut RetainedByteBudget,
        locators: &[FinalizeGenerationSetArtifactLocatorV1<'_>; COUNT],
    ) -> Result<[RetainedArtifactV1; COUNT]>
    where
        F: FnMut(usize, &str) -> Result<Vec<u8>>,
    {
        locators
            .iter()
            .map(|locator| retain_artifact(campaign_root, prior_roots, read, budget, locator))
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("retained artifact-array cardinality drift"))
    }

    fn retain_case<const ROOTS: usize, F>(
        campaign_root: &Path,
        prior_roots: [&Path; ROOTS],
        read: &mut F,
        budget: &mut RetainedByteBudget,
        case: &FinalizeGenerationCaseSourcePlanV1<'_>,
    ) -> Result<RetainedCaseV1>
    where
        F: FnMut(usize, &str) -> Result<Vec<u8>>,
    {
        let (proof_output_manifest, primary, auxiliary): (
            _,
            &[FinalizeGenerationPrimaryArtifactLocatorV1<'_>],
            &[FinalizeGenerationAuxiliaryArtifactLocatorV1<'_>],
        ) = match case {
            FinalizeGenerationCaseSourcePlanV1::Lift {
                proof_output_manifest,
                primary_artifacts,
            } => (proof_output_manifest, primary_artifacts, &[]),
            FinalizeGenerationCaseSourcePlanV1::Recursive {
                proof_output_manifest,
                primary_artifacts,
                auxiliary_artifacts,
            } => (
                proof_output_manifest,
                primary_artifacts,
                auxiliary_artifacts,
            ),
        };
        Ok(RetainedCaseV1 {
            proof_output_manifest: retain_artifact(
                campaign_root,
                prior_roots,
                read,
                budget,
                proof_output_manifest,
            )?,
            primary_artifacts: primary
                .iter()
                .map(|located| {
                    Ok(RetainedPrimaryArtifactV1 {
                        source_file: located.source_file.to_owned(),
                        artifact: retain_artifact(
                            campaign_root,
                            prior_roots,
                            read,
                            budget,
                            &located.artifact,
                        )?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            auxiliary_artifacts: auxiliary
                .iter()
                .map(|located| {
                    Ok(RetainedAuxiliaryArtifactV1 {
                        relative_path: located.relative_path.to_owned(),
                        artifact: retain_artifact(
                            campaign_root,
                            prior_roots,
                            read,
                            budget,
                            &located.artifact,
                        )?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        })
    }

    fn authenticate_retained_campaign_precommit_with<const ROOTS: usize, F, A>(
        campaign_root: &Path,
        prior_roots: [&Path; ROOTS],
        root_index: usize,
        root_relative_path: &str,
        mut read: F,
        mut authenticate: A,
    ) -> Result<B4ContractArtifactIdentityV1>
    where
        F: FnMut(usize, &str) -> Result<Vec<u8>>,
        A: FnMut(&str, &[u8]) -> Result<B4ContractArtifactIdentityV1>,
    {
        let precommit_root = *prior_roots
            .get(root_index)
            .context("campaign-precommit root index is outside the retained root set")?;
        let campaign_relative_path = derive_campaign_relative_artifact_path(
            campaign_root,
            precommit_root,
            root_relative_path,
        )?;
        let retained_bytes = read(root_index, root_relative_path)
            .context("cannot read the campaign precommit under immutable-root custody")?;
        authenticate(&campaign_relative_path, &retained_bytes)
            .context("retained campaign precommit authentication failed")
    }

    fn authenticate_retained_campaign_precommit<const ROOTS: usize, F>(
        campaign_root: &Path,
        prior_roots: [&Path; ROOTS],
        root_index: usize,
        root_relative_path: &str,
        campaign_precommit: &B4CampaignPrecommitAuthorityV1,
        read: F,
    ) -> Result<B4ContractArtifactIdentityV1>
    where
        F: FnMut(usize, &str) -> Result<Vec<u8>>,
    {
        authenticate_retained_campaign_precommit_with(
            campaign_root,
            prior_roots,
            root_index,
            root_relative_path,
            read,
            |campaign_relative_path, retained_bytes| {
                authenticate_campaign_precommit_file(
                    campaign_relative_path,
                    campaign_precommit,
                    retained_bytes,
                )
            },
        )
    }

    fn require_stable_campaign_precommit_identity(
        actual: &B4ContractArtifactIdentityV1,
        expected: &B4ContractArtifactIdentityV1,
    ) -> Result<()> {
        ensure!(
            actual == expected,
            "execute campaign-precommit identity differs from authenticated preflight"
        );
        Ok(())
    }

    fn bind_retained_positive_input_documents(
        paths: &B4PositiveInputSetPublicationPathsV2,
        input_set_jcs: Vec<u8>,
        completion_jcs: Vec<u8>,
        budget: &mut RetainedByteBudget,
    ) -> Result<(
        B4PositiveInputSetPublicationBindingV2,
        B4ContractArtifactIdentityV1,
    )> {
        ensure!(
            (1..=B4_POSITIVE_INPUT_SET_MAX_BYTES).contains(&input_set_jcs.len()),
            "retained V2 positive input set is outside the handler byte bound"
        );
        budget.add(input_set_jcs.len())?;
        ensure!(
            (1..=B4_POSITIVE_INPUT_SET_COMPLETION_MAX_BYTES).contains(&completion_jcs.len()),
            "retained V2 positive input-set completion is outside the handler byte bound"
        );
        budget.add(completion_jcs.len())?;
        let positive_input_set = bind_b4_positive_input_set_publication_v2(paths, &input_set_jcs)
            .context("cannot bind the retained V2 positive input set")?;
        validate_b4_positive_input_set_completion_jcs_v2(&completion_jcs, &positive_input_set)
            .context("retained V2 positive input-set completion is stale")?;
        let input_identity = B4ContractArtifactIdentityV1::from_bytes(
            positive_input_set.input_set_path(),
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            positive_input_set.input_set_jcs(),
        )?;
        Ok((positive_input_set, input_identity))
    }

    fn require_campaign_input_identity(
        actual: &B4ContractArtifactIdentityV1,
        expected: &B4ContractArtifactIdentityV1,
    ) -> Result<()> {
        ensure!(
            actual == expected,
            "retained V2 positive input set differs from the campaign precommit"
        );
        Ok(())
    }

    fn bind_retained_trusted_host_input_documents(
        paths: &eip_0045_reproduction::b4_positive_input_set::B4TrustedHostInputSetPathsV1,
        input_set_jcs: Vec<u8>,
        completion_jcs: Vec<u8>,
        envelope: &Eip0045B4TrustedHostCampaignPrecommitV1,
        previous_request: &B4TrustedHostRequestV1,
        budget: &mut RetainedByteBudget,
    ) -> Result<(RetainedInputSet, B4ContractArtifactIdentityV1)> {
        ensure!((1..=B4_POSITIVE_INPUT_SET_MAX_BYTES).contains(&input_set_jcs.len())
            && (1..=B4_POSITIVE_INPUT_SET_COMPLETION_MAX_BYTES).contains(&completion_jcs.len()),
            "trusted-host retained input documents exceed their bounds");
        budget.add(input_set_jcs.len())?;
        budget.add(completion_jcs.len())?;
        let executor = &envelope.inner_precommit.campaign_executor.artifact;
        let completion = validate_b4_trusted_host_input_set_completion_jcs_v1(
            &completion_jcs, paths, &input_set_jcs,
            previous_request.input_set_request_byte_length
                .context("prior input-set request length is absent")?,
            previous_request.input_set_request_sha256.as_deref()
                .context("prior input-set request digest is absent")?,
            &envelope.build_evidence_root_sha256, executor,
        )?;
        let completion_identity = B4ContractArtifactIdentityV1::from_bytes(
            paths.completion_path(), B4ContractArtifactEncodingV1::Rfc8785Jcs, &completion_jcs)?;
        ensure!(completion_identity == envelope.completion,
            "trusted-host completion differs from the retained precommit envelope");
        let input_identity = B4ContractArtifactIdentityV1::from_bytes(
            paths.input_set_path(), B4ContractArtifactEncodingV1::Rfc8785Jcs, &input_set_jcs)?;
        ensure!(input_identity == envelope.inner_precommit.input_set,
            "trusted-host input set differs from the retained precommit");
        Ok((RetainedInputSet::TrustedHost {
            path: paths.input_set_path().to_owned(), bytes: input_set_jcs, completion,
        }, input_identity))
    }

    fn retain_generation_closure_trusted_host<const ROOTS: usize, F>(
        campaign_root: &Path,
        prior_roots: [&Path; ROOTS],
        input_set_jcs: Vec<u8>,
        completion_jcs: Vec<u8>,
        read: F,
        envelope: &Eip0045B4TrustedHostCampaignPrecommitV1,
        previous_request: &B4TrustedHostRequestV1,
        plan: &FinalizeGenerationSetSourcePlanV1<'_>,
    ) -> Result<RetainedGenerationClosureV1>
    where F: FnMut(usize, &str) -> Result<Vec<u8>>,
    {
        validate_source_plan::<ROOTS>(plan)?;
        let mut budget = RetainedByteBudget::default();
        let input_root = *prior_roots.get(plan.positive_input_phase_root_index)
            .context("trusted-host input phase root is outside the retained roots")?;
        let input_path = derive_campaign_relative_artifact_path(campaign_root, input_root,
            POSITIVE_INPUT_SET_FILE)?;
        let phase = input_path.strip_suffix("/positive-input-set.json")
            .context("trusted-host input set has no closed phase root")?;
        let paths = project_b4_trusted_host_input_set_paths_v1(phase)?;
        let completion_path = derive_campaign_relative_artifact_path(campaign_root, input_root,
            "trusted-host-input-set-completion.json")?;
        ensure!(paths.input_set_path() == input_path && paths.completion_path() == completion_path,
            "trusted-host input phase has a different file layout");
        let (positive_input_set, input_identity) = bind_retained_trusted_host_input_documents(
            &paths, input_set_jcs, completion_jcs, envelope, previous_request, &mut budget)?;
        require_campaign_input_identity(&input_identity, &envelope.inner_precommit.input_set)?;
        retain_generation_artifacts(campaign_root, prior_roots, read, budget, positive_input_set, plan)
    }

    fn retain_generation_closure<const ROOTS: usize, F>(
        campaign_root: &Path,
        prior_roots: [&Path; ROOTS],
        input_set_jcs: Vec<u8>,
        completion_jcs: Vec<u8>,
        mut read: F,
        campaign_precommit: &B4CampaignPrecommitAuthorityV1,
        plan: &FinalizeGenerationSetSourcePlanV1<'_>,
    ) -> Result<RetainedGenerationClosureV1>
    where
        F: FnMut(usize, &str) -> Result<Vec<u8>>,
    {
        validate_source_plan::<ROOTS>(plan)?;
        let mut budget = RetainedByteBudget::default();
        let input_phase_root = *prior_roots
            .get(plan.positive_input_phase_root_index)
            .context("positive input phase root index is outside the retained root set")?;
        let input_set_path = derive_campaign_relative_artifact_path(
            campaign_root,
            input_phase_root,
            POSITIVE_INPUT_SET_FILE,
        )?;
        let completion_path = derive_campaign_relative_artifact_path(
            campaign_root,
            input_phase_root,
            POSITIVE_INPUT_SET_COMPLETION_FILE,
        )?;
        let input_suffix = format!("/{POSITIVE_INPUT_SET_FILE}");
        let phase_root = input_set_path
            .strip_suffix(&input_suffix)
            .context("positive input-set path does not expose its closed phase root")?;
        let paths = project_b4_positive_input_set_publication_paths_v2(phase_root)?;
        ensure!(
            paths.input_set_path() == input_set_path && paths.completion_path() == completion_path,
            "positive input phase differs from the closed two-file V2 layout"
        );
        let (positive_input_set, input_identity) = bind_retained_positive_input_documents(
            &paths,
            input_set_jcs,
            completion_jcs,
            &mut budget,
        )?;
        require_campaign_input_identity(
            &input_identity,
            &campaign_precommit.precommit().input_set,
        )?;

        retain_generation_artifacts(campaign_root, prior_roots, read, budget,
            RetainedInputSet::H0(positive_input_set), plan)
    }

    fn retain_generation_artifacts<const ROOTS: usize, F>(
        campaign_root: &Path,
        prior_roots: [&Path; ROOTS],
        mut read: F,
        mut budget: RetainedByteBudget,
        positive_input_set: RetainedInputSet,
        plan: &FinalizeGenerationSetSourcePlanV1<'_>,
    ) -> Result<RetainedGenerationClosureV1>
    where F: FnMut(usize, &str) -> Result<Vec<u8>>,
    {
        let proof_generator = retain_artifact(
            campaign_root,
            prior_roots,
            &mut read,
            &mut budget,
            &plan.proof_generator,
        )?;
        let runner_profiles = retain_artifact_array(
            campaign_root,
            prior_roots,
            &mut read,
            &mut budget,
            &plan.runner_profiles,
        )?;
        let validator_descriptors = retain_artifact_array(
            campaign_root,
            prior_roots,
            &mut read,
            &mut budget,
            &plan.validator_descriptors,
        )?;
        let nested_input_sources = plan
            .nested_input_sources
            .iter()
            .map(|locator| {
                retain_artifact(campaign_root, prior_roots, &mut read, &mut budget, locator)
            })
            .collect::<Result<Vec<_>>>()?;
        let cases = plan
            .cases
            .iter()
            .map(|case| retain_case(campaign_root, prior_roots, &mut read, &mut budget, case))
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| {
                anyhow::anyhow!("retained positive-generation case count is not eleven")
            })?;

        Ok(RetainedGenerationClosureV1 {
            positive_input_set,
            proof_generator,
            runner_profiles,
            validator_descriptors,
            nested_input_sources,
            cases,
        })
    }

    struct ValidatedGenerationCandidateV1 {
        validated: B4ValidatedPositiveGenerationPreacceptanceV2,
        generation_set_jcs: Vec<u8>,
        expected_generation_identity: B4ContractArtifactIdentityV1,
    }

    struct AuthorizedGenerationCandidateV1 {
        authority: B4PositiveGenerationAuthorityV2,
        generation_set_jcs: Vec<u8>,
        expected_generation_identity: B4ContractArtifactIdentityV1,
    }

    fn validate_generation_candidate(
        authoritative_build: &AuthoritativeB4BuildProjection,
        retained: &RetainedGenerationClosureV1,
        generation_set_path: &str,
    ) -> Result<ValidatedGenerationCandidateV1> {
        let primary_views: [Vec<GeneratedArtifactContents<'_>>; 11] =
            std::array::from_fn(|case_index| {
                retained.cases[case_index]
                    .primary_artifacts
                    .iter()
                    .map(|artifact| GeneratedArtifactContents {
                        source_file: &artifact.source_file,
                        bytes: &artifact.artifact.bytes,
                    })
                    .collect()
            });
        let auxiliary_views: [Vec<GeneratedAuxiliaryArtifactContents<'_>>; 11] =
            std::array::from_fn(|case_index| {
                retained.cases[case_index]
                    .auxiliary_artifacts
                    .iter()
                    .map(|artifact| GeneratedAuxiliaryArtifactContents {
                        relative_path: &artifact.relative_path,
                        bytes: &artifact.artifact.bytes,
                    })
                    .collect()
            });
        let case_documents = std::array::from_fn(|case_index| PositiveGenerationCaseDocuments {
            proof_output_manifest_jcs: &retained.cases[case_index].proof_output_manifest.bytes,
            artifacts: &primary_views[case_index],
            auxiliary_artifacts: &auxiliary_views[case_index],
        });
        let generation_set_jcs = retained.positive_input_set.construct_generation_set(
            &retained.proof_generator.bytes,
            case_documents,
        )
        .context("cannot construct the canonical V2 positive generation set")?;
        ensure!(
            generation_set_jcs.len() <= MAX_POSITIVE_GENERATION_SET_BYTES,
            "constructed V2 positive generation set exceeds the handler byte bound"
        );

        let runner_profiles =
            std::array::from_fn(|index| retained.runner_profiles[index].as_named_jcs());
        let validator_descriptors =
            std::array::from_fn(|index| retained.validator_descriptors[index].as_named_jcs());
        let nested_input_sources = retained
            .nested_input_sources
            .iter()
            .map(RetainedArtifactV1::as_external)
            .collect::<Vec<_>>();
        let external_primary: [Vec<B4PositiveGenerationExternalBytesV2<'_>>; 11] =
            std::array::from_fn(|case_index| {
                retained.cases[case_index]
                    .primary_artifacts
                    .iter()
                    .map(|artifact| artifact.artifact.as_external())
                    .collect()
            });
        let external_auxiliary: [Vec<B4PositiveGenerationExternalBytesV2<'_>>; 11] =
            std::array::from_fn(|case_index| {
                retained.cases[case_index]
                    .auxiliary_artifacts
                    .iter()
                    .map(|artifact| artifact.artifact.as_external())
                    .collect()
            });
        let external_cases = std::array::from_fn(|case_index| B4PositiveGenerationCaseExternalV2 {
            proof_output_manifest: retained.cases[case_index]
                .proof_output_manifest
                .as_external(),
            primary_artifacts: &external_primary[case_index],
            auxiliary_artifacts: &external_auxiliary[case_index],
        });
        let generation_document = NamedCanonicalJcs {
            relative_path: generation_set_path,
            bytes: &generation_set_jcs,
        };
        let validated = validate_and_bind_v2_positive_generation_preacceptance(
            authoritative_build,
            NamedCanonicalJcs {
                relative_path: retained.positive_input_set.input_set_path(),
                bytes: retained.positive_input_set.input_set_jcs(),
            },
            runner_profiles,
            validator_descriptors,
            PositiveGenerationDocuments {
                generation_set: generation_document,
                proof_generator_artifact: &retained.proof_generator.bytes,
                cases: case_documents,
            },
            B4PositiveGenerationExternalClosureV2 {
                positive_input_set: B4PositiveGenerationExternalBytesV2 {
                    path: retained.positive_input_set.input_set_path(),
                    bytes: retained.positive_input_set.input_set_jcs(),
                },
                positive_generation_set: B4PositiveGenerationExternalBytesV2 {
                    path: generation_set_path,
                    bytes: &generation_set_jcs,
                },
                proof_generator: retained.proof_generator.as_external(),
                nested_input_sources: &nested_input_sources,
                cases: external_cases,
            },
        )
        .context("complete V2 positive-generation preacceptance failed")?;
        let expected_generation_identity = B4ContractArtifactIdentityV1::from_bytes(
            generation_set_path,
            B4ContractArtifactEncodingV1::Rfc8785Jcs,
            &generation_set_jcs,
        )?;
        Ok(ValidatedGenerationCandidateV1 {
            validated,
            generation_set_jcs,
            expected_generation_identity,
        })
    }

    fn mint_generation_authority(
        candidate: ValidatedGenerationCandidateV1,
    ) -> AuthorizedGenerationCandidateV1 {
        AuthorizedGenerationCandidateV1 {
            authority: B4PositiveGenerationAuthorityV2::from_validated(candidate.validated),
            generation_set_jcs: candidate.generation_set_jcs,
            expected_generation_identity: candidate.expected_generation_identity,
        }
    }

    fn verify_generation_authority_identity(
        candidate: &AuthorizedGenerationCandidateV1,
        campaign_precommit: &Eip0045B4CampaignPrecommitV1,
    ) -> Result<()> {
        ensure!(
            candidate.authority.positive_input_set_identity()
                == &campaign_precommit.input_set,
            "positive-generation authority input differs from the campaign precommit"
        );
        ensure!(
            candidate.authority.positive_generation_set_identity()
                == &candidate.expected_generation_identity,
            "positive-generation authority output differs from the constructed generation set"
        );
        Ok(())
    }

    /// Private authority retained only after the exact committed bytes reopen.
    pub(crate) struct FinalizedGenerationSetHandlerResultV1 {
        authority: B4PositiveGenerationAuthorityV2,
    }

    impl FinalizedGenerationSetHandlerResultV1 {
        pub(crate) fn authority(&self) -> &B4PositiveGenerationAuthorityV2 {
            &self.authority
        }
    }

    type FinalizeGenerationSetPreflightContext<const ROOTS: usize> =
        ExecutorPreflightContext<ROOTS, ProjectedSingleFileCampaignLayout<ROOTS>>;

    struct AuthenticatedFinalizeGenerationSetPreflightV1<const ROOTS: usize> {
        preflight: FinalizeGenerationSetPreflightContext<ROOTS>,
        invocation: CapturedFinalizeGenerationSetInvocation,
        campaign_precommit_identity: B4ContractArtifactIdentityV1,
    }

    fn published_generation_set_path<const ROOTS: usize>(
        inputs: &FinalizeGenerationSetExecuteInputsV1<'_, '_, ROOTS>,
    ) -> Result<String> {
        let path = derive_campaign_relative_artifact_path(
            inputs.campaign_root,
            inputs.outer_final_root,
            POSITIVE_GENERATION_SET_FILE,
        )?;
        ensure!(
            path == POSITIVE_GENERATION_SET_CAMPAIGN_PATH,
            "finalize-generation-set output path differs from the canonical V2 identity"
        );
        Ok(path)
    }

    fn authenticate_preflight<const ROOTS: usize>(
        inputs: &FinalizeGenerationSetExecuteInputsV1<'_, '_, ROOTS>,
        parsed_preflight_only: bool,
    ) -> Result<AuthenticatedFinalizeGenerationSetPreflightV1<ROOTS>> {
        validate_source_plan::<ROOTS>(&inputs.source_plan)?;
        let projected = project_finalize_generation_set_layout(
            inputs.campaign_root,
            inputs.prior_roots,
            inputs.outer_final_root,
        )?;
        let generation_set_path = published_generation_set_path(inputs)?;
        let preflight =
            ExecutorPreflightContext::capture(inputs.configured_executor_artifact, projected)
                .context("finalize-generation-set retained preflight failed")?;
        let campaign_precommit_identity = authenticate_retained_campaign_precommit(
            inputs.campaign_root,
            inputs.prior_roots,
            inputs.campaign_precommit_root_index,
            inputs.campaign_precommit_root_relative_path,
            inputs.campaign_precommit,
            |root_index, relative_path| {
                preflight
                    .read_immutable_file::<MAX_CAMPAIGN_PRECOMMIT_BYTES>(root_index, relative_path)
            },
        )?;
        let invocation = CapturedFinalizeGenerationSetInvocation::capture(parsed_preflight_only)?;
        require_current_executable_binding(preflight.executable(), inputs.campaign_precommit)?;
        let authoritative_build = preflight
            .authenticate_authoritative_b4_build_projection(
                inputs.source_plan.build_evidence_root_index,
                &inputs.build_anchors.expectations(),
            )
            .context("preflight authoritative B4 build projection failed")?;
        let input_set_jcs = preflight
            .read_immutable_file::<B4_POSITIVE_INPUT_SET_MAX_BYTES>(
                inputs.source_plan.positive_input_phase_root_index,
                POSITIVE_INPUT_SET_FILE,
            )
            .context("cannot retain the closed V2 positive input set")?;
        let completion_jcs = preflight
            .read_immutable_file::<B4_POSITIVE_INPUT_SET_COMPLETION_MAX_BYTES>(
                inputs.source_plan.positive_input_phase_root_index,
                POSITIVE_INPUT_SET_COMPLETION_FILE,
            )
            .context("cannot retain the closed V2 positive input-set completion")?;
        let retained = retain_generation_closure(
            inputs.campaign_root,
            inputs.prior_roots,
            input_set_jcs,
            completion_jcs,
            |root_index, relative_path| {
                preflight
                    .read_immutable_file::<MAX_RETAINED_ARTIFACT_BYTES>(root_index, relative_path)
            },
            inputs.campaign_precommit,
            &inputs.source_plan,
        )?;
        let candidate =
            validate_generation_candidate(&authoritative_build, &retained, &generation_set_path)?;
        let authorized = mint_generation_authority(candidate);
        verify_generation_authority_identity(&authorized, inputs.campaign_precommit.precommit())?;
        require_current_executable_binding(preflight.executable(), inputs.campaign_precommit)?;
        invocation.revalidate()?;
        Ok(AuthenticatedFinalizeGenerationSetPreflightV1 {
            preflight,
            invocation,
            campaign_precommit_identity,
        })
    }

    fn execute_generation_set_publication<const ROOTS: usize>(
        execute: &mut ExecutorExecuteContext<ROOTS, ProjectedSingleFileCampaignLayout<ROOTS>>,
        inputs: &FinalizeGenerationSetExecuteInputsV1<'_, '_, ROOTS>,
        invocation: &CapturedFinalizeGenerationSetInvocation,
        expected_campaign_precommit_identity: &B4ContractArtifactIdentityV1,
        generation_set_path: &str,
    ) -> Result<FinalizedGenerationSetHandlerResultV1> {
        invocation.revalidate()?;
        require_current_executable_binding(execute.executable(), inputs.campaign_precommit)?;
        let campaign_precommit_identity = authenticate_retained_campaign_precommit(
            inputs.campaign_root,
            inputs.prior_roots,
            inputs.campaign_precommit_root_index,
            inputs.campaign_precommit_root_relative_path,
            inputs.campaign_precommit,
            |root_index, relative_path| {
                execute
                    .read_immutable_file::<MAX_CAMPAIGN_PRECOMMIT_BYTES>(root_index, relative_path)
            },
        )?;
        require_stable_campaign_precommit_identity(
            &campaign_precommit_identity,
            expected_campaign_precommit_identity,
        )?;
        let authoritative_build = execute
            .authenticate_authoritative_b4_build_projection(
                inputs.source_plan.build_evidence_root_index,
                &inputs.build_anchors.expectations(),
            )
            .context("execute authoritative B4 build projection failed")?;
        let input_set_jcs = execute
            .read_immutable_file::<B4_POSITIVE_INPUT_SET_MAX_BYTES>(
                inputs.source_plan.positive_input_phase_root_index,
                POSITIVE_INPUT_SET_FILE,
            )
            .context("cannot retain the closed V2 positive input set during execute")?;
        let completion_jcs = execute
            .read_immutable_file::<B4_POSITIVE_INPUT_SET_COMPLETION_MAX_BYTES>(
                inputs.source_plan.positive_input_phase_root_index,
                POSITIVE_INPUT_SET_COMPLETION_FILE,
            )
            .context("cannot retain the closed V2 positive input-set completion during execute")?;
        let retained = retain_generation_closure(
            inputs.campaign_root,
            inputs.prior_roots,
            input_set_jcs,
            completion_jcs,
            |root_index, relative_path| {
                execute
                    .read_immutable_file::<MAX_RETAINED_ARTIFACT_BYTES>(root_index, relative_path)
            },
            inputs.campaign_precommit,
            &inputs.source_plan,
        )?;
        invocation.revalidate()?;
        publish_generation_candidate(execute, &authoritative_build, &retained,
            inputs.campaign_precommit.precommit(), generation_set_path)
    }

    fn publish_generation_candidate<const ROOTS: usize>(
        execute: &mut ExecutorExecuteContext<ROOTS, ProjectedSingleFileCampaignLayout<ROOTS>>,
        authoritative_build: &AuthoritativeB4BuildProjection,
        retained: &RetainedGenerationClosureV1,
        precommit: &Eip0045B4CampaignPrecommitV1,
        generation_set_path: &str,
    ) -> Result<FinalizedGenerationSetHandlerResultV1> {
        execute.with_mutation(|mutation| {
            coordinate_finalize_generation_set(
                || {
                    validate_generation_candidate(
                        &authoritative_build,
                        &retained,
                        generation_set_path,
                    )
                },
                |candidate| Ok(mint_generation_authority(candidate)),
                |candidate| {
                    verify_generation_authority_identity(candidate, precommit)
                },
                || mutation.begin_create_only_directory(),
                |mut transaction, candidate| {
                    transaction.create_file(
                        POSITIVE_GENERATION_SET_FILE,
                        &candidate.generation_set_jcs,
                        MAX_POSITIVE_GENERATION_SET_BYTES,
                    )?;
                    Ok((transaction, candidate))
                },
                |(transaction, candidate)| Ok((transaction.commit_durable()?, candidate)),
                |(committed, candidate)| {
                    let reopened_identity =
                        committed.reopen_with_postcommit_validation(|view| {
                            let reopened = view.read_file(
                                POSITIVE_GENERATION_SET_FILE,
                                MAX_POSITIVE_GENERATION_SET_BYTES,
                            )?;
                            ensure!(
                                reopened == candidate.generation_set_jcs,
                                "committed V2 positive generation-set bytes differ after reopen"
                            );
                            B4ContractArtifactIdentityV1::from_bytes(
                                generation_set_path,
                                B4ContractArtifactEncodingV1::Rfc8785Jcs,
                                &reopened,
                            )
                        })?;
                    ensure!(
                        reopened_identity == candidate.expected_generation_identity
                            && &reopened_identity
                                == candidate.authority.positive_generation_set_identity(),
                        "reopened V2 positive generation-set identity differs from its authority"
                    );
                    Ok(FinalizedGenerationSetHandlerResultV1 {
                        authority: candidate.authority,
                    })
                },
            )
        })
    }

    /// Reach the exact zero-effect boundary after every immutable source is rebound.
    pub(crate) fn preflight_finalize_generation_set_handler<const ROOTS: usize>(
        inputs: &FinalizeGenerationSetExecuteInputsV1<'_, '_, ROOTS>,
    ) -> Result<()> {
        let authenticated = authenticate_preflight(inputs, true)?;
        authenticated.invocation.revalidate()?;
        authenticated
            .preflight
            .finish_preflight()
            .context("finalize-generation-set authenticated preflight failed")
    }

    /// Construct, bind, mint, durably commit and descriptor-reopen the V2 set.
    pub(crate) fn execute_finalize_generation_set_handler<const ROOTS: usize>(
        inputs: FinalizeGenerationSetExecuteInputsV1<'_, '_, ROOTS>,
    ) -> Result<FinalizedGenerationSetHandlerResultV1> {
        let AuthenticatedFinalizeGenerationSetPreflightV1 {
            preflight,
            invocation,
            campaign_precommit_identity,
        } = authenticate_preflight(&inputs, false)?;
        let generation_set_path = published_generation_set_path(&inputs)?;
        preflight.execute(|execute| {
            execute_generation_set_publication(
                execute,
                &inputs,
                &invocation,
                &campaign_precommit_identity,
                &generation_set_path,
            )
        })
    }

    #[cfg(all(target_os = "linux", feature = "b4-prepare-input-set-kernel"))]
    pub(in crate::b4_campaign_executor) mod trusted_host {
        use super::*;
        use sha2::Digest as _;
        use crate::b4_campaign_executor::{
            authenticated_preflight::authenticate_trusted_host_campaign_precommit_file,
            custody::CurrentExecutableObservation,
            prepare_campaign_precommit::{PrecommitReadLimit,
                replay_trusted_host_precommit_for_finalizer},
        };
        use eip_0045_reproduction::b4_positive_gate::positive_auxiliary_artifact_paths;

        #[derive(Debug)]
        struct AuthenticatedPrecommit {
            identity: B4ContractArtifactIdentityV1,
            envelope: Eip0045B4TrustedHostCampaignPrecommitV1,
            previous_request: B4TrustedHostRequestV1,
        }

        fn locator<'a>(request: &'a B4TrustedHostRequestV1, name: &str)
            -> Result<FinalizeGenerationSetArtifactLocatorV1<'a>> {
            let source = request.locator(name)?;
            Ok(FinalizeGenerationSetArtifactLocatorV1::new(
                source.root_index, &source.relative_path))
        }

        fn with_source_plan<T>(request: &B4TrustedHostRequestV1,
            consume: impl FnOnce(&FinalizeGenerationSetSourcePlanV1<'_>) -> Result<T>) -> Result<T> {
            let input = locator(request, "inputSet")?;
            let completion = locator(request, "inputSetCompletion")?;
            ensure!(input.root_index == completion.root_index
                && input.root_relative_path == POSITIVE_INPUT_SET_FILE
                && completion.root_relative_path == "trusted-host-input-set-completion.json",
                "trusted-host generation input and completion do not share their closed phase root");
            let nested_count = request.sources.keys()
                .filter(|name| name.starts_with("nestedInput")).count();
            let nested = (0..nested_count).map(|i| locator(request, &format!("nestedInput{i}")))
                .collect::<Result<Vec<_>>>()?;
            let auxiliaries: [Vec<FinalizeGenerationAuxiliaryArtifactLocatorV1<'_>>; 3] =
                (8..11).map(|case| {
                    positive_auxiliary_artifact_paths(case)?.iter().enumerate().map(|(index, path)|
                        Ok(FinalizeGenerationAuxiliaryArtifactLocatorV1 {
                            relative_path: path,
                            artifact: locator(request, &format!("case{case}Aux{index}"))?,
                        })).collect::<Result<Vec<_>>>()
                }).collect::<Result<Vec<_>>>()?.try_into()
                    .map_err(|_| anyhow::anyhow!("trusted-host recursive auxiliary count drift"))?;
            let cases: [FinalizeGenerationCaseSourcePlanV1<'_>; 11] = (0..11).map(|case| {
                let proof_output_manifest = locator(request, &format!("case{case}Manifest"))?;
                if case < 8 {
                    let primary_artifacts = LIFT_PRIMARY_SOURCE_FILES.iter().enumerate()
                        .map(|(index, source_file)| Ok(FinalizeGenerationPrimaryArtifactLocatorV1 {
                            source_file,
                            artifact: locator(request, &format!("case{case}Primary{index}"))?,
                        })).collect::<Result<Vec<_>>>()?.try_into()
                        .map_err(|_| anyhow::anyhow!("trusted-host lift primary count drift"))?;
                    Ok(FinalizeGenerationCaseSourcePlanV1::Lift {
                        proof_output_manifest, primary_artifacts,
                    })
                } else {
                    let primary_artifacts = RECURSIVE_PRIMARY_SOURCE_FILES.iter().enumerate()
                        .map(|(index, source_file)| Ok(FinalizeGenerationPrimaryArtifactLocatorV1 {
                            source_file,
                            artifact: locator(request, &format!("case{case}Primary{index}"))?,
                        })).collect::<Result<Vec<_>>>()?.try_into()
                        .map_err(|_| anyhow::anyhow!("trusted-host recursive primary count drift"))?;
                    Ok(FinalizeGenerationCaseSourcePlanV1::Recursive {
                        proof_output_manifest, primary_artifacts,
                        auxiliary_artifacts: &auxiliaries[case - 8],
                    })
                }
            }).collect::<Result<Vec<_>>>()?.try_into()
                .map_err(|_| anyhow::anyhow!("trusted-host positive case count drift"))?;
            let plan = FinalizeGenerationSetSourcePlanV1 {
                positive_input_phase_root_index: input.root_index,
                build_evidence_root_index: request.build_evidence_root_index,
                proof_generator: locator(request, "proofGenerator")?,
                runner_profiles: [locator(request, "runnerProfile0")?, locator(request, "runnerProfile1")?,
                    locator(request, "runnerProfile2")?, locator(request, "runnerProfile3")?],
                validator_descriptors: [locator(request, "validatorDescriptor0")?,
                    locator(request, "validatorDescriptor1")?],
                nested_input_sources: &nested,
                cases,
            };
            validate_source_plan::<16>(&plan)?;
            consume(&plan)
        }

        fn authenticate_reopened<const ROOTS: usize, Replay>(
            request: &B4TrustedHostRequestV1,
            campaign_root: &Path,
            prior_roots: [&Path; ROOTS],
            retained_precommit: &[u8],
            retained_request: &[u8],
            observed: &CurrentExecutableObservation,
            build_evidence_root_sha256: &str,
            replay: Replay,
        ) -> Result<AuthenticatedPrecommit>
        where Replay: FnOnce(&B4TrustedHostRequestV1, u64, &str) -> Result<Vec<u8>>,
        {
            let precommit_locator = request.locator("campaignPrecommit")?;
            ensure!(precommit_locator.relative_path == "trusted-host/campaign-precommit.json",
                "trusted-host precommit locator is not the published file");
            let precommit_root = request.prior_roots.get(precommit_locator.root_index)
                .context("trusted-host precommit root index is invalid")?;
            let envelope = Eip0045B4TrustedHostCampaignPrecommitV1::from_canonical_jcs(
                retained_precommit)?;
            ensure!(retained_request.len() as u64 == envelope.request_byte_length
                && hex::encode(sha2::Sha256::digest(retained_request)) == envelope.request_sha256,
                "retained prior request differs from the trusted-host precommit pin");
            let previous_request = B4TrustedHostRequestV1::from_canonical_jcs(retained_request)?;
            ensure!(previous_request.command == "prepare-campaign-precommit"
                && previous_request.campaign_root == request.campaign_root
                && previous_request.configured_executor_artifact == request.configured_executor_artifact
                && previous_request.outer_final_root == *precommit_root,
                "retained prior request belongs to another trusted-host command or root");
            let previous_build_root = previous_request.prior_roots
                .get(previous_request.build_evidence_root_index)
                .context("prior request build root index is invalid")?;
            ensure!(Some(previous_build_root) == request.prior_roots.get(request.build_evidence_root_index),
                "prior and current trusted-host commands selected different build roots");
            ensure!(envelope.build_evidence_root_sha256 == build_evidence_root_sha256,
                "trusted-host precommit binds another authoritative build");
            let expected = replay(&previous_request,
                envelope.request_byte_length, &envelope.request_sha256)?;
            let campaign_relative_path = derive_campaign_relative_artifact_path(
                campaign_root, Path::new(precommit_root), &precommit_locator.relative_path)?;
            let (identity, rebound) = authenticate_trusted_host_campaign_precommit_file(
                &campaign_relative_path, retained_precommit, &expected, observed)?;
            ensure!(rebound == envelope, "trusted-host precommit changed during authentication");
            Ok(AuthenticatedPrecommit { identity, envelope, previous_request })
        }

        fn read_replay_preflight<const ROOTS: usize>(
            context: &ExecutorPreflightContext<ROOTS, ProjectedSingleFileCampaignLayout<ROOTS>>,
            index: usize, path: &str, limit: PrecommitReadLimit, remaining: u64,
        ) -> Result<Vec<u8>> {
            context.read_immutable_file_with_length_validation::<MAX_RETAINED_ARTIFACT_BYTES>(
                index, path, |length| {
                    ensure!(length <= limit.max_bytes() as u64 && length <= remaining,
                        "trusted-host precommit replay exceeds its role or aggregate byte bound");
                    Ok(())
                })
        }

        fn read_replay_execute<const ROOTS: usize>(
            context: &ExecutorExecuteContext<ROOTS, ProjectedSingleFileCampaignLayout<ROOTS>>,
            index: usize, path: &str, limit: PrecommitReadLimit, remaining: u64,
        ) -> Result<Vec<u8>> {
            context.read_immutable_file_with_length_validation::<MAX_RETAINED_ARTIFACT_BYTES>(
                index, path, |length| {
                    ensure!(length <= limit.max_bytes() as u64 && length <= remaining,
                        "trusted-host precommit replay exceeds its role or aggregate byte bound");
                    Ok(())
                })
        }

        pub(in crate::b4_campaign_executor) fn handle<const ROOTS: usize>(
            request: &B4TrustedHostRequestV1,
            expectations: &B4BuildExpectations<'_>,
            preflight_only: bool,
        ) -> Result<()> {
            ensure!(request.command == COMMAND && request.prior_roots.len() == ROOTS
                && (1..=MAX_ROOTS).contains(&ROOTS),
                "trusted-host finalizer command or root count drift");
            with_source_plan(request, |plan| {
                validate_source_plan::<ROOTS>(plan)?;
                let campaign_root = Path::new(&request.campaign_root);
                let prior_roots: [&Path; ROOTS] = std::array::from_fn(|i| Path::new(&request.prior_roots[i]));
                let final_root = Path::new(&request.outer_final_root);
                let layout = project_finalize_generation_set_layout(
                    campaign_root, prior_roots, final_root)?;
                let generation_set_path = derive_campaign_relative_artifact_path(
                    campaign_root, final_root, POSITIVE_GENERATION_SET_FILE)?;
                ensure!(generation_set_path == POSITIVE_GENERATION_SET_CAMPAIGN_PATH,
                    "trusted-host generation output is not the canonical V2 path");
                let preflight = ExecutorPreflightContext::capture(
                    Path::new(&request.configured_executor_artifact), layout)?;
                let build = preflight.authenticate_authoritative_b4_build_projection(
                    request.build_evidence_root_index, expectations)?;
                let precommit_loc = request.locator("campaignPrecommit")?;
                let prior_request_loc = request.locator("precommitRequest")?;
                let precommit = preflight.read_immutable_file::<{MAX_CAMPAIGN_PRECOMMIT_BYTES + 4096}>(
                    precommit_loc.root_index, &precommit_loc.relative_path)?;
                let prior_request = preflight.read_immutable_file::<65536>(
                    prior_request_loc.root_index, &prior_request_loc.relative_path)?;
                let authenticated = authenticate_reopened(request, campaign_root, prior_roots,
                    &precommit, &prior_request, preflight.executable(), build.evidence_root_sha256(),
                    |previous, length, digest| replay_trusted_host_precommit_for_finalizer(
                        previous, campaign_root, prior_roots, &build, length, digest,
                        |index, path, limit, remaining| read_replay_preflight(
                            &preflight, index, path, limit, remaining)))?;
                let input_jcs = preflight.read_immutable_file::<B4_POSITIVE_INPUT_SET_MAX_BYTES>(
                    plan.positive_input_phase_root_index, POSITIVE_INPUT_SET_FILE)?;
                let completion_jcs = preflight.read_immutable_file::<B4_POSITIVE_INPUT_SET_COMPLETION_MAX_BYTES>(
                    plan.positive_input_phase_root_index, "trusted-host-input-set-completion.json")?;
                let retained = retain_generation_closure_trusted_host(campaign_root, prior_roots,
                    input_jcs, completion_jcs,
                    |index, path| preflight.read_immutable_file::<MAX_RETAINED_ARTIFACT_BYTES>(index, path),
                    &authenticated.envelope, &authenticated.previous_request, plan)?;
                let candidate = validate_generation_candidate(&build, &retained, &generation_set_path)?;
                verify_generation_authority_identity(&mint_generation_authority(candidate),
                    &authenticated.envelope.inner_precommit)?;
                preflight.executable().require_artifact_identity(
                    &authenticated.envelope.inner_precommit.campaign_executor.artifact)?;
                if preflight_only { return preflight.finish_preflight(); }
                preflight.execute(|execute| {
                    let rebound_build = execute.authenticate_authoritative_b4_build_projection(
                        request.build_evidence_root_index, expectations)?;
                    ensure!(rebound_build == build,
                        "trusted-host authoritative build changed between preflight and execute");
                    let precommit = execute.read_immutable_file::<{MAX_CAMPAIGN_PRECOMMIT_BYTES + 4096}>(
                        precommit_loc.root_index, &precommit_loc.relative_path)?;
                    let prior_request = execute.read_immutable_file::<65536>(
                        prior_request_loc.root_index, &prior_request_loc.relative_path)?;
                    let rebound = authenticate_reopened(request, campaign_root, prior_roots,
                        &precommit, &prior_request, execute.executable(),
                        rebound_build.evidence_root_sha256(),
                        |previous, length, digest| replay_trusted_host_precommit_for_finalizer(
                            previous, campaign_root, prior_roots, &rebound_build, length, digest,
                            |index, path, limit, remaining| read_replay_execute(
                                execute, index, path, limit, remaining)))?;
                    ensure!(rebound.identity == authenticated.identity
                        && rebound.envelope == authenticated.envelope
                        && rebound.previous_request == authenticated.previous_request,
                        "trusted-host precommit identity changed between preflight and execute");
                    let input_jcs = execute.read_immutable_file::<B4_POSITIVE_INPUT_SET_MAX_BYTES>(
                        plan.positive_input_phase_root_index, POSITIVE_INPUT_SET_FILE)?;
                    let completion_jcs = execute.read_immutable_file::<B4_POSITIVE_INPUT_SET_COMPLETION_MAX_BYTES>(
                        plan.positive_input_phase_root_index, "trusted-host-input-set-completion.json")?;
                    let retained = retain_generation_closure_trusted_host(campaign_root, prior_roots,
                        input_jcs, completion_jcs,
                        |index, path| execute.read_immutable_file::<MAX_RETAINED_ARTIFACT_BYTES>(index, path),
                        &rebound.envelope, &rebound.previous_request, plan)?;
                    publish_generation_candidate(execute, &rebound_build, &retained,
                        &rebound.envelope.inner_precommit, &generation_set_path)?;
                    Ok(())
                })
            })
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use eip_0045_reproduction::{
                b4_campaign_contract::{
                    B4TrustedHostArtifactLocatorV1, B4CampaignExecutorBindingV1,
                    B4CampaignValidatorBindingV1, B4CampaignValidatorImplementationV1,
                    B4NamedContractArtifactIdentityV1, B4ReviewedSourceBindingV1,
                    B4_CAMPAIGN_FUTURE_OUTPUT_ROLES, B4_CAMPAIGN_RUNNER_ROLES,
                },
                canonical::canonical_json_bytes,
            };
            use sha2::Digest as _;
            use std::collections::BTreeMap;

            fn identity(path: &str, encoding: B4ContractArtifactEncodingV1,
                bytes: &[u8]) -> B4ContractArtifactIdentityV1 {
                B4ContractArtifactIdentityV1::from_bytes(path, encoding, bytes).unwrap()
            }

            fn reviewed(prefix: &str) -> B4ReviewedSourceBindingV1 {
                let (commit_digit, tree_digit) = match prefix {
                    "rust" => ('a', 'b'),
                    "jvm" => ('c', 'd'),
                    "campaign-executor" => ('e', 'f'),
                    _ => panic!("unexpected reviewed source fixture role"),
                };
                B4ReviewedSourceBindingV1 {
                    repository: "https://github.com/example/test.git".to_owned(),
                    commit: commit_digit.to_string().repeat(40),
                    tree: tree_digit.to_string().repeat(40),
                    archive: identity(&format!("reproduction/preproof/{prefix}-source.bundle"),
                        B4ContractArtifactEncodingV1::GitBundle, prefix.as_bytes()),
                }
            }

            fn inner_precommit(observed: &CurrentExecutableObservation)
                -> Eip0045B4CampaignPrecommitV1 {
                let named = |prefix: &str| B4_CAMPAIGN_RUNNER_ROLES.iter().enumerate()
                    .map(|(index, role)| B4NamedContractArtifactIdentityV1 {
                        role: (*role).to_owned(),
                        artifact: identity(&format!("reproduction/preproof/{prefix}-{index}.json"),
                            B4ContractArtifactEncodingV1::Rfc8785Jcs,
                            format!("{prefix}-{index}").as_bytes()),
                    }).collect();
                let validator = |prefix: &str, implementation| B4CampaignValidatorBindingV1 {
                    implementation,
                    build_descriptor: identity(&format!("reproduction/preproof/{prefix}-descriptor.json"),
                        B4ContractArtifactEncodingV1::Rfc8785Jcs, prefix.as_bytes()),
                    artifact: identity(&format!("reproduction/preproof/{prefix}-validator.bin"),
                        B4ContractArtifactEncodingV1::RawBytes, prefix.as_bytes()),
                    reviewed_source: reviewed(prefix),
                    lineage_sha256: (if prefix == "rust" { "1" } else { "2" }).repeat(64),
                };
                Eip0045B4CampaignPrecommitV1 {
                    format: "Eip0045B4CampaignPrecommitV1".to_owned(), format_version: 1,
                    input_set: identity("input/positive-input-set.json",
                        B4ContractArtifactEncodingV1::Rfc8785Jcs, b"{}"),
                    campaign_executor: B4CampaignExecutorBindingV1 {
                        artifact: B4ContractArtifactIdentityV1 {
                            path: "reproduction/preproof/campaign-executor".to_owned(),
                            byte_length: observed.observed_byte_length(),
                            sha256: hex::encode(observed.observed_sha256()),
                            encoding: B4ContractArtifactEncodingV1::RawBytes,
                        },
                        reviewed_source: reviewed("campaign-executor"),
                        build_descriptor: identity("reproduction/preproof/campaign-executor-build.json",
                            B4ContractArtifactEncodingV1::Rfc8785Jcs, b"build"),
                    },
                    executor_contract: identity("reproduction/preproof/executor-contract.json",
                        B4ContractArtifactEncodingV1::Rfc8785Jcs, b"executor"),
                    verifier_contract: identity("reproduction/preproof/verifier-contract.json",
                        B4ContractArtifactEncodingV1::Rfc8785Jcs, b"verifier"),
                    expectation_set: identity("reproduction/preproof/expectations.json",
                        B4ContractArtifactEncodingV1::Rfc8785Jcs, b"expectations"),
                    validators: vec![
                        validator("rust", B4CampaignValidatorImplementationV1::RustReference),
                        validator("jvm", B4CampaignValidatorImplementationV1::IndependentJvm),
                    ],
                    runner_profiles: named("runner"), seccomp_documents: named("seccomp"),
                    jvm_copy_only_inclusion_manifest: identity("reproduction/preproof/jvm-inclusion.json",
                        B4ContractArtifactEncodingV1::Rfc8785Jcs, b"inclusion"),
                    future_output_roles: B4_CAMPAIGN_FUTURE_OUTPUT_ROLES.iter()
                        .map(ToString::to_string).collect(),
                }
            }

            fn prior_request(executable: &str) -> B4TrustedHostRequestV1 {
                let mut names = vec!["inputSet".to_owned(), "inputSetCompletion".to_owned(),
                    "campaignExecutorArtifact".to_owned(), "executorSourceArchive".to_owned(),
                    "executorBuildDescriptor".to_owned(), "executorContract".to_owned(),
                    "verifierContract".to_owned(), "verifierCliSpec".to_owned(),
                    "negativePlan".to_owned(), "expectationSet".to_owned(), "jvmInclusion".to_owned()];
                for i in 0..20 { names.push(format!("schema{i}")); }
                for prefix in ["validatorDescriptor", "validatorArtifact", "validatorSourceArchive"] {
                    for i in 0..2 { names.push(format!("{prefix}{i}")); }
                }
                for prefix in ["runnerProfile", "seccomp"] {
                    for i in 0..4 { names.push(format!("{prefix}{i}")); }
                }
                let sources = names.into_iter().enumerate().map(|(index, name)|
                    (name, B4TrustedHostArtifactLocatorV1 { root_index: 0,
                        relative_path: format!("sources/{index}.bin") }))
                    .collect::<BTreeMap<_, _>>();
                assert_eq!(sources.len(), 45);
                B4TrustedHostRequestV1 {
                    format: "Eip0045B4TrustedHostRequestV1".to_owned(), format_version: 1,
                    realization: "trusted-host-v1".to_owned(),
                    command: "prepare-campaign-precommit".to_owned(),
                    campaign_root: "/campaign".to_owned(),
                    prior_roots: vec!["/campaign/input".to_owned(), "/campaign/build".to_owned()],
                    outer_final_root: "/campaign/precommit".to_owned(),
                    configured_executor_artifact: executable.to_owned(),
                    build_evidence_root_index: 1, input_set_path: None, guest_elf_path: None,
                    proof_generator_path: None, input_set_request_byte_length: Some(71),
                    input_set_request_sha256: Some("a".repeat(64)), sources,
                }
            }

            fn pinned_request_bytes(request: &B4TrustedHostRequestV1) -> Vec<u8> {
                let bytes = canonical_json_bytes(&serde_json::to_value(request).unwrap()).unwrap();
                assert_eq!(*request, B4TrustedHostRequestV1::from_canonical_jcs(&bytes).unwrap());
                bytes
            }

            fn authenticate_fixture(
                current: &B4TrustedHostRequestV1,
                observed: &CurrentExecutableObservation,
                retained_previous: &[u8],
                retained_envelope: &[u8],
                expected_build_digest: &str,
                independently_rederived: &[u8],
            ) -> Result<AuthenticatedPrecommit> {
                authenticate_reopened(current, Path::new("/campaign"),
                    [Path::new("/campaign/precommit"), Path::new("/campaign/input"),
                        Path::new("/campaign/build")],
                    retained_envelope, retained_previous, observed, expected_build_digest,
                    |_, _, _| Ok(independently_rederived.to_vec()))
            }

            #[test]
            fn trusted_host_reopen_authenticates_the_actual_join_and_isolated_faults() {
                let executable = std::fs::read_link("/proc/self/exe").unwrap();
                let observed = CurrentExecutableObservation::capture(&executable).unwrap();
                let executable = executable.to_str().unwrap();
                let previous = prior_request(executable);
                let previous_bytes = pinned_request_bytes(&previous);
                let mut current = request();
                current.prior_roots = vec!["/campaign/precommit".to_owned(),
                    "/campaign/input".to_owned(), "/campaign/build".to_owned()];
                current.build_evidence_root_index = 2;
                current.configured_executor_artifact = executable.to_owned();
                current.sources.get_mut("campaignPrecommit").unwrap().relative_path =
                    "trusted-host/campaign-precommit.json".to_owned();
                current.sources.get_mut("inputSet").unwrap().root_index = 1;
                current.sources.get_mut("inputSetCompletion").unwrap().root_index = 1;
                let build_digest = "b".repeat(64);
                let envelope = Eip0045B4TrustedHostCampaignPrecommitV1 {
                    format: "Eip0045B4TrustedHostCampaignPrecommitV1".to_owned(),
                    format_version: 1, realization: "trusted-host-v1".to_owned(),
                    completion: identity("input/trusted-host-input-set-completion.json",
                        B4ContractArtifactEncodingV1::Rfc8785Jcs, b"{}"),
                    request_byte_length: previous_bytes.len() as u64,
                    request_sha256: hex::encode(sha2::Sha256::digest(&previous_bytes)),
                    build_evidence_root_sha256: build_digest.clone(),
                    inner_precommit: inner_precommit(&observed),
                };
                let envelope_bytes = envelope.to_canonical_jcs().unwrap();
                let expected_path = "precommit/trusted-host/campaign-precommit.json";
                let direct = authenticate_trusted_host_campaign_precommit_file(
                    expected_path, &envelope_bytes, &envelope_bytes, &observed).unwrap();
                assert_eq!(direct.1, envelope);
                let healthy = authenticate_fixture(&current, &observed, &previous_bytes,
                    &envelope_bytes, &build_digest, &envelope_bytes).unwrap();
                assert_eq!(healthy.envelope, envelope);
                assert_eq!(healthy.previous_request, previous);
                assert_eq!(healthy.identity, direct.0);

                let mut changed = envelope.clone();
                changed.request_byte_length += 1;
                let bytes = changed.to_canonical_jcs().unwrap();
                assert!(format!("{:#}", authenticate_fixture(&current, &observed,
                    &previous_bytes, &bytes, &build_digest, &bytes).unwrap_err())
                    .contains("retained prior request differs"));
                changed = envelope.clone();
                changed.request_sha256 = "d".repeat(64);
                let bytes = changed.to_canonical_jcs().unwrap();
                assert!(format!("{:#}", authenticate_fixture(&current, &observed,
                    &previous_bytes, &bytes, &build_digest, &bytes).unwrap_err())
                    .contains("retained prior request differs"));

                for (label, mutate) in [
                    ("campaign", 0usize), ("executable", 1), ("final-root", 2),
                    ("build-root", 3),
                ] {
                    let mut selected = previous.clone();
                    match mutate {
                        0 => selected.campaign_root = "/other".to_owned(),
                        1 => selected.configured_executor_artifact = "/other/executor".to_owned(),
                        2 => selected.outer_final_root = "/campaign/other-precommit".to_owned(),
                        _ => selected.prior_roots[1] = "/campaign/other-build".to_owned(),
                    }
                    let selected_bytes = pinned_request_bytes(&selected);
                    let mut rebound = envelope.clone();
                    rebound.request_byte_length = selected_bytes.len() as u64;
                    rebound.request_sha256 = hex::encode(sha2::Sha256::digest(&selected_bytes));
                    let rebound_bytes = rebound.to_canonical_jcs().unwrap();
                    let error = authenticate_fixture(&current, &observed, &selected_bytes,
                        &rebound_bytes, &build_digest, &rebound_bytes).unwrap_err();
                    let expected = if mutate == 3 { "different build roots" }
                        else { "another trusted-host command or root" };
                    assert!(format!("{error:#}").contains(expected), "{label}: {error:#}");
                }

                let mut input_command = previous.clone();
                input_command.command = "prepare-input-set".to_owned();
                input_command.input_set_request_byte_length = None;
                input_command.input_set_request_sha256 = None;
                input_command.input_set_path = Some("phase/positive-input-set.json".to_owned());
                input_command.guest_elf_path = Some("sources/guest.elf".to_owned());
                input_command.proof_generator_path = Some("sources/proof-generator".to_owned());
                let names = ["profileManifest", "profileAlgorithm", "profileConstants",
                    "referenceStatementBundle", "sourceLock", "verifierContract",
                    "runnerProfile0", "runnerProfile1", "runnerProfile2", "runnerProfile3",
                    "seccomp0", "seccomp1", "seccomp2", "seccomp3",
                    "validatorDescriptor0", "validatorDescriptor1", "jvmInclusion",
                    "calibration0", "calibration1", "calibration2", "executorArtifact",
                    "executorBuildDescriptor"];
                input_command.sources = names.into_iter().enumerate().map(|(index, name)|
                    (name.to_owned(), B4TrustedHostArtifactLocatorV1 { root_index: 0,
                        relative_path: format!("sources/{index}.bin") })).collect();
                let input_command_bytes = pinned_request_bytes(&input_command);
                let mut rebound = envelope.clone();
                rebound.request_byte_length = input_command_bytes.len() as u64;
                rebound.request_sha256 = hex::encode(sha2::Sha256::digest(&input_command_bytes));
                let rebound_bytes = rebound.to_canonical_jcs().unwrap();
                assert!(format!("{:#}", authenticate_fixture(&current, &observed,
                    &input_command_bytes, &rebound_bytes, &build_digest, &rebound_bytes)
                    .unwrap_err()).contains("another trusted-host command or root"));

                changed = envelope.clone();
                changed.build_evidence_root_sha256 = "d".repeat(64);
                let bytes = changed.to_canonical_jcs().unwrap();
                assert!(format!("{:#}", authenticate_fixture(&current, &observed,
                    &previous_bytes, &bytes, &build_digest, &bytes).unwrap_err())
                    .contains("another authoritative build"));

                let mut different_replay = envelope_bytes.clone();
                different_replay.push(b' ');
                assert!(format!("{:#}", authenticate_fixture(&current, &observed,
                    &previous_bytes, &envelope_bytes, &build_digest, &different_replay)
                    .unwrap_err()).contains("differs from its rederived source closure"));
                assert!(authenticate_trusted_host_campaign_precommit_file(expected_path,
                    &envelope_bytes, &different_replay, &observed).is_err());

                changed = envelope.clone();
                changed.inner_precommit.campaign_executor.artifact.sha256 = "d".repeat(64);
                let bytes = changed.to_canonical_jcs().unwrap();
                assert!(format!("{:#}", authenticate_fixture(&current, &observed,
                    &previous_bytes, &bytes, &build_digest, &bytes).unwrap_err())
                    .contains("running executor differs"));
                assert!(authenticate_trusted_host_campaign_precommit_file(expected_path,
                    &bytes, &bytes, &observed).is_err());
            }

            fn request() -> B4TrustedHostRequestV1 {
                let mut names = vec!["campaignPrecommit".to_owned(), "precommitRequest".to_owned(),
                    "inputSet".to_owned(), "inputSetCompletion".to_owned(),
                    "proofGenerator".to_owned()];
                for i in 0..4 { names.push(format!("runnerProfile{i}")); }
                for i in 0..2 { names.push(format!("validatorDescriptor{i}")); }
                for case in 0..11 {
                    names.push(format!("case{case}Manifest"));
                    let count = if case < 8 { 7 } else { 8 };
                    for i in 0..count { names.push(format!("case{case}Primary{i}")); }
                    if case >= 8 {
                        for i in 0..[2, 2, 4][case - 8] {
                            names.push(format!("case{case}Aux{i}"));
                        }
                    }
                }
                let mut sources = names.into_iter().enumerate().map(|(index, name)|
                    (name, B4TrustedHostArtifactLocatorV1 { root_index: 0,
                        relative_path: format!("sources/{index}.bin") }))
                    .collect::<BTreeMap<_, _>>();
                sources.get_mut("inputSet").unwrap().relative_path = POSITIVE_INPUT_SET_FILE.to_owned();
                sources.get_mut("inputSetCompletion").unwrap().relative_path =
                    "trusted-host-input-set-completion.json".to_owned();
                B4TrustedHostRequestV1 {
                    format: "Eip0045B4TrustedHostRequestV1".to_owned(), format_version: 1,
                    realization: "trusted-host-v1".to_owned(),
                    command: "finalize-generation-set".to_owned(),
                    campaign_root: "/campaign".to_owned(),
                    prior_roots: vec!["/campaign/input".to_owned(), "/campaign/proof".to_owned()],
                    outer_final_root: "/campaign/reproduction/postproof".to_owned(),
                    configured_executor_artifact: "/campaign/bin/executor".to_owned(),
                    build_evidence_root_index: 0, input_set_path: None, guest_elf_path: None,
                    proof_generator_path: None, input_set_request_byte_length: None,
                    input_set_request_sha256: None, sources,
                }
            }

            #[test]
            fn trusted_host_finalizer_projects_the_closed_eleven_case_consumer_plan() {
                let selected = request();
                with_source_plan(&selected, |plan| {
                    assert_eq!(plan.cases.len(), 11);
                    assert_eq!(plan.positive_input_phase_root_index, 0);
                    assert_eq!(plan.nested_input_sources.len(), 0);
                    assert!(matches!(&plan.cases[10], FinalizeGenerationCaseSourcePlanV1::Recursive {
                        auxiliary_artifacts, .. } if auxiliary_artifacts.len() == 4));
                    Ok(())
                }).unwrap();
            }

            #[test]
            fn trusted_host_finalizer_rejects_input_completion_root_or_filename_substitution() {
                let mut selected = request();
                selected.sources.get_mut("inputSetCompletion").unwrap().root_index = 1;
                assert!(with_source_plan(&selected, |_| Ok(())).is_err());
                selected = request();
                selected.sources.get_mut("inputSetCompletion").unwrap().relative_path =
                    "positive-input-set-completion.json".to_owned();
                assert!(with_source_plan(&selected, |_| Ok(())).is_err());
            }
        }
    }

    #[cfg(test)]
    mod behavioral_tests {
        use super::*;

        fn locator(path: &'static str) -> FinalizeGenerationSetArtifactLocatorV1<'static> {
            FinalizeGenerationSetArtifactLocatorV1::new(0, path)
        }

        fn primary(
            source_file: &'static str,
        ) -> FinalizeGenerationPrimaryArtifactLocatorV1<'static> {
            FinalizeGenerationPrimaryArtifactLocatorV1 {
                source_file,
                artifact: locator(source_file),
            }
        }

        fn auxiliary(
            relative_path: &'static str,
        ) -> FinalizeGenerationAuxiliaryArtifactLocatorV1<'static> {
            FinalizeGenerationAuxiliaryArtifactLocatorV1 {
                relative_path,
                artifact: locator(relative_path),
            }
        }

        fn lift_case<'source>() -> FinalizeGenerationCaseSourcePlanV1<'source> {
            FinalizeGenerationCaseSourcePlanV1::Lift {
                proof_output_manifest: locator("lift-proof-output.json"),
                primary_artifacts: LIFT_PRIMARY_SOURCE_FILES.map(primary),
            }
        }

        fn recursive_case<'source>(
            auxiliary_artifacts: &'source [FinalizeGenerationAuxiliaryArtifactLocatorV1<'source>],
        ) -> FinalizeGenerationCaseSourcePlanV1<'source> {
            FinalizeGenerationCaseSourcePlanV1::Recursive {
                proof_output_manifest: locator("recursive-proof-output.json"),
                primary_artifacts: RECURSIVE_PRIMARY_SOURCE_FILES.map(primary),
                auxiliary_artifacts,
            }
        }

        fn valid_plan<'source>(
            recursive_two_a: &'source [FinalizeGenerationAuxiliaryArtifactLocatorV1<'source>; 2],
            recursive_two_b: &'source [FinalizeGenerationAuxiliaryArtifactLocatorV1<'source>; 2],
            recursive_four: &'source [FinalizeGenerationAuxiliaryArtifactLocatorV1<'source>; 4],
        ) -> FinalizeGenerationSetSourcePlanV1<'source> {
            FinalizeGenerationSetSourcePlanV1 {
                positive_input_phase_root_index: 0,
                build_evidence_root_index: 0,
                proof_generator: locator("generator.bin"),
                runner_profiles: [
                    locator("runner-0.json"),
                    locator("runner-1.json"),
                    locator("runner-2.json"),
                    locator("runner-3.json"),
                ],
                validator_descriptors: [locator("validator-0.json"), locator("validator-1.json")],
                nested_input_sources: &[],
                cases: [
                    lift_case(),
                    lift_case(),
                    lift_case(),
                    lift_case(),
                    lift_case(),
                    lift_case(),
                    lift_case(),
                    lift_case(),
                    recursive_case(recursive_two_a),
                    recursive_case(recursive_two_b),
                    recursive_case(recursive_four),
                ],
            }
        }

        fn auxiliary_sets() -> (
            [FinalizeGenerationAuxiliaryArtifactLocatorV1<'static>; 2],
            [FinalizeGenerationAuxiliaryArtifactLocatorV1<'static>; 2],
            [FinalizeGenerationAuxiliaryArtifactLocatorV1<'static>; 4],
        ) {
            (
                [auxiliary("aux-a-0.bin"), auxiliary("aux-a-1.bin")],
                [auxiliary("aux-b-0.bin"), auxiliary("aux-b-1.bin")],
                [
                    auxiliary("aux-c-0.bin"),
                    auxiliary("aux-c-1.bin"),
                    auxiliary("aux-c-2.bin"),
                    auxiliary("aux-c-3.bin"),
                ],
            )
        }

        #[test]
        fn h4_source_plan_accepts_only_the_closed_eight_plus_three_partition() {
            let (two_a, two_b, four) = auxiliary_sets();
            let valid = valid_plan(&two_a, &two_b, &four);
            validate_source_plan::<1>(&valid).unwrap();

            let mut recursive_in_lift_slot = valid_plan(&two_a, &two_b, &four);
            recursive_in_lift_slot.cases[0] = recursive_case(&two_a);
            assert!(validate_source_plan::<1>(&recursive_in_lift_slot).is_err());

            let mut lift_in_recursive_slot = valid_plan(&two_a, &two_b, &four);
            lift_in_recursive_slot.cases[8] = lift_case();
            assert!(validate_source_plan::<1>(&lift_in_recursive_slot).is_err());
        }

        #[test]
        fn h4_source_plan_rejects_primary_order_and_each_recursive_auxiliary_count() {
            let (two_a, two_b, four) = auxiliary_sets();

            let mut wrong_primary = valid_plan(&two_a, &two_b, &four);
            let FinalizeGenerationCaseSourcePlanV1::Lift {
                primary_artifacts, ..
            } = &mut wrong_primary.cases[3]
            else {
                unreachable!()
            };
            primary_artifacts[2].source_file = "wrong-primary.bin";
            assert!(validate_source_plan::<1>(&wrong_primary).is_err());

            let mut wrong_first_recursive = valid_plan(&two_a, &two_b, &four);
            wrong_first_recursive.cases[8] = recursive_case(&four);
            assert!(validate_source_plan::<1>(&wrong_first_recursive).is_err());

            let mut wrong_second_recursive = valid_plan(&two_a, &two_b, &four);
            wrong_second_recursive.cases[9] = recursive_case(&four);
            assert!(validate_source_plan::<1>(&wrong_second_recursive).is_err());

            let mut wrong_third_recursive = valid_plan(&two_a, &two_b, &four);
            wrong_third_recursive.cases[10] = recursive_case(&two_a);
            assert!(validate_source_plan::<1>(&wrong_third_recursive).is_err());
        }

        #[test]
        fn h4_source_plan_rejects_every_unbounded_or_empty_locator_surface() {
            let (two_a, two_b, four) = auxiliary_sets();

            let mut bad_input_root = valid_plan(&two_a, &two_b, &four);
            bad_input_root.positive_input_phase_root_index = 1;
            assert!(validate_source_plan::<1>(&bad_input_root).is_err());

            let mut bad_build_root = valid_plan(&two_a, &two_b, &four);
            bad_build_root.build_evidence_root_index = 1;
            assert!(validate_source_plan::<1>(&bad_build_root).is_err());

            let mut bad_artifact_root = valid_plan(&two_a, &two_b, &four);
            bad_artifact_root.proof_generator.root_index = 1;
            assert!(validate_source_plan::<1>(&bad_artifact_root).is_err());

            let mut empty_artifact_path = valid_plan(&two_a, &two_b, &four);
            empty_artifact_path.runner_profiles[0].root_relative_path = "";
            assert!(validate_source_plan::<1>(&empty_artifact_path).is_err());

            let mut invalid_four = four.to_vec();
            invalid_four[0].relative_path = "";
            let mut empty_auxiliary_path = valid_plan(&two_a, &two_b, &four);
            empty_auxiliary_path.cases[10] = recursive_case(&invalid_four);
            assert!(validate_source_plan::<1>(&empty_auxiliary_path).is_err());

            let excessive_nested =
                vec![locator("nested.bin"); MAX_NESTED_INPUT_SOURCES.saturating_add(1)];
            let mut too_many_nested = valid_plan(&two_a, &two_b, &four);
            too_many_nested.nested_input_sources = &excessive_nested;
            assert!(validate_source_plan::<1>(&too_many_nested).is_err());

            let zero_root_plan = valid_plan(&two_a, &two_b, &four);
            assert!(validate_source_plan::<0>(&zero_root_plan).is_err());
        }

        #[test]
        fn h4_retained_byte_budget_fails_closed_on_overflow_and_excess() {
            let mut exact = RetainedByteBudget::default();
            exact.add(MAX_RETAINED_TOTAL_BYTES).unwrap();
            assert!(exact.add(1).is_err());

            let mut overflow = RetainedByteBudget { total: usize::MAX };
            assert!(overflow.add(1).is_err());
        }

        #[test]
        fn h4_campaign_precommit_rejects_root_index_before_read_or_authentication() {
            let campaign_root = Path::new("campaign");
            let retained_root = Path::new("campaign/retained");
            let mut read_called = false;
            let mut authenticate_called = false;

            let result = authenticate_retained_campaign_precommit_with::<1, _, _>(
                campaign_root,
                [retained_root],
                1,
                "campaign-precommit.json",
                |_, _| {
                    read_called = true;
                    Ok(b"unreachable".to_vec())
                },
                |_, _| {
                    authenticate_called = true;
                    B4ContractArtifactIdentityV1::from_bytes(
                        "unreachable.json",
                        B4ContractArtifactEncodingV1::Rfc8785Jcs,
                        b"unreachable",
                    )
                },
            );

            assert!(result.is_err());
            assert!(!read_called);
            assert!(!authenticate_called);
        }

        #[test]
        fn h4_campaign_precommit_rejects_path_escape_before_read_or_authentication() {
            let campaign_root = Path::new("campaign");
            let retained_root = Path::new("campaign/retained");
            let mut read_called = false;
            let mut authenticate_called = false;

            let result = authenticate_retained_campaign_precommit_with::<1, _, _>(
                campaign_root,
                [retained_root],
                0,
                "../escape.json",
                |_, _| {
                    read_called = true;
                    Ok(b"unreachable".to_vec())
                },
                |_, _| {
                    authenticate_called = true;
                    B4ContractArtifactIdentityV1::from_bytes(
                        "unreachable.json",
                        B4ContractArtifactEncodingV1::Rfc8785Jcs,
                        b"unreachable",
                    )
                },
            );

            assert!(result.is_err());
            assert!(!read_called);
            assert!(!authenticate_called);
        }

        #[test]
        fn h4_campaign_precommit_accepts_a_stable_campaign_selected_phase_root() {
            let campaign_root = Path::new("campaign");
            let relocated_root = Path::new("campaign/relocated");
            let mut read_called = false;
            let mut authenticate_called = false;
            let bytes = b"byte-identical-precommit";

            let identity = authenticate_retained_campaign_precommit_with::<1, _, _>(
                campaign_root,
                [relocated_root],
                0,
                "campaign-precommit.json",
                |_, _| {
                    read_called = true;
                    Ok(bytes.to_vec())
                },
                |campaign_relative_path, retained_bytes| {
                    authenticate_called = true;
                    B4ContractArtifactIdentityV1::from_bytes(
                        campaign_relative_path,
                        B4ContractArtifactEncodingV1::Rfc8785Jcs,
                        retained_bytes,
                    )
                },
            )
            .unwrap();

            assert!(read_called);
            assert!(authenticate_called);
            assert_eq!(identity.path, "relocated/campaign-precommit.json");
        }

        #[test]
        fn h4_campaign_precommit_passes_exact_path_and_bytes_to_authenticator() {
            let campaign_root = Path::new("campaign");
            let retained_root = Path::new("campaign/phases/prepare");
            let mut observed_path = None;
            let mut observed_bytes = None;

            let result = authenticate_retained_campaign_precommit_with::<1, _, _>(
                campaign_root,
                [retained_root],
                0,
                "contracts/campaign-precommit.json",
                |root_index, relative_path| {
                    assert_eq!(root_index, 0);
                    assert_eq!(relative_path, "contracts/campaign-precommit.json");
                    Ok(b"wrong-precommit".to_vec())
                },
                |campaign_relative_path, retained_bytes| {
                    observed_path = Some(campaign_relative_path.to_owned());
                    observed_bytes = Some(retained_bytes.to_vec());
                    anyhow::bail!("fixture bytes are not the authenticated precommit")
                },
            );

            assert!(result.is_err());
            assert_eq!(
                observed_path.as_deref(),
                Some("phases/prepare/contracts/campaign-precommit.json")
            );
            assert_eq!(
                observed_bytes.as_deref(),
                Some(b"wrong-precommit".as_slice())
            );
        }

        #[test]
        fn h4_campaign_precommit_rejects_location_change_between_preflight_and_execute() {
            let campaign_root = Path::new("campaign");
            let preflight_root = Path::new("campaign/phases/prepare");
            let execute_root = Path::new("campaign/phases/relocated");
            let bytes = b"stable-precommit-bytes";

            let preflight_identity = authenticate_retained_campaign_precommit_with::<1, _, _>(
                campaign_root,
                [preflight_root],
                0,
                "contracts/campaign-precommit.json",
                |_, _| Ok(bytes.to_vec()),
                |campaign_relative_path, retained_bytes| {
                    B4ContractArtifactIdentityV1::from_bytes(
                        campaign_relative_path,
                        B4ContractArtifactEncodingV1::Rfc8785Jcs,
                        retained_bytes,
                    )
                },
            )
            .unwrap();
            let execute_identity = authenticate_retained_campaign_precommit_with::<1, _, _>(
                campaign_root,
                [execute_root],
                0,
                "contracts/campaign-precommit.json",
                |_, _| Ok(bytes.to_vec()),
                |campaign_relative_path, retained_bytes| {
                    B4ContractArtifactIdentityV1::from_bytes(
                        campaign_relative_path,
                        B4ContractArtifactEncodingV1::Rfc8785Jcs,
                        retained_bytes,
                    )
                },
            )
            .unwrap();

            assert!(
                require_stable_campaign_precommit_identity(&execute_identity, &preflight_identity,)
                    .is_err()
            );
            require_stable_campaign_precommit_identity(&preflight_identity, &preflight_identity)
                .unwrap();
        }

        #[test]
        fn h4_positive_input_documents_reject_stale_completion_and_precommit_identity() {
            const INPUT_A: &[u8] = br#"{"format":"Eip0045B4PositiveInputSetV2","formatVersion":2}"#;
            const INPUT_B: &[u8] =
                br#"{"format":"Eip0045B4PositiveInputSetV2","formatVersion":2,"variant":"stale"}"#;

            let paths = project_b4_positive_input_set_publication_paths_v2("phase").unwrap();
            let binding_a = bind_b4_positive_input_set_publication_v2(&paths, INPUT_A).unwrap();
            let completion_a = eip_0045_reproduction::b4_positive_input_set::derive_b4_positive_input_set_completion_jcs_v2(&binding_a).unwrap();

            let mut stale_budget = RetainedByteBudget::default();
            assert!(
                bind_retained_positive_input_documents(
                    &paths,
                    INPUT_B.to_vec(),
                    completion_a,
                    &mut stale_budget,
                )
                .is_err()
            );

            let binding_b = bind_b4_positive_input_set_publication_v2(&paths, INPUT_B).unwrap();
            let completion_b = eip_0045_reproduction::b4_positive_input_set::derive_b4_positive_input_set_completion_jcs_v2(&binding_b).unwrap();
            let mut budget_a = RetainedByteBudget::default();
            let (_, identity_a) = bind_retained_positive_input_documents(
                &paths,
                INPUT_A.to_vec(),
                eip_0045_reproduction::b4_positive_input_set::derive_b4_positive_input_set_completion_jcs_v2(&binding_a).unwrap(),
                &mut budget_a,
            )
            .unwrap();
            let mut budget_b = RetainedByteBudget::default();
            let (_, identity_b) = bind_retained_positive_input_documents(
                &paths,
                INPUT_B.to_vec(),
                completion_b,
                &mut budget_b,
            )
            .unwrap();

            assert!(require_campaign_input_identity(&identity_b, &identity_a).is_err());
        }
    }
}

#[cfg(all(target_os = "linux", feature = "b4-finalize-generation-set-handler"))]
pub(crate) use execute::{
    FinalizeGenerationAuxiliaryArtifactLocatorV1, FinalizeGenerationCaseSourcePlanV1,
    FinalizeGenerationPrimaryArtifactLocatorV1, FinalizeGenerationSetArtifactLocatorV1,
    FinalizeGenerationSetBuildAnchorsV1, FinalizeGenerationSetExecuteInputsV1,
    FinalizeGenerationSetSourcePlanV1, FinalizedGenerationSetHandlerResultV1,
    execute_finalize_generation_set_handler, preflight_finalize_generation_set_handler,
};

#[cfg(all(target_os = "linux", feature = "b4-finalize-generation-set-handler",
    feature = "b4-prepare-input-set-kernel"))]
pub(super) use execute::trusted_host::handle as handle_trusted_host_finalize;

#[cfg(test)]
mod tests {
    #[test]
    fn h4_handler_surface_is_locator_only_and_case_closed() {
        let source = include_str!("finalize_generation_set_handler.rs").replace("\r\n", "\n");
        let production = source.split("#[cfg(test)]").next().unwrap();

        for required in [
            "pub(crate) struct FinalizeGenerationSetArtifactLocatorV1",
            "pub(crate) enum FinalizeGenerationCaseSourcePlanV1",
            "pub(crate) struct FinalizeGenerationSetSourcePlanV1",
            "pub(crate) struct FinalizeGenerationSetExecuteInputsV1",
            "cases: [FinalizeGenerationCaseSourcePlanV1<'source>; 11]",
            "nested_input_sources:",
            "&'source [FinalizeGenerationSetArtifactLocatorV1<'source>]",
            "campaign_precommit_root_index: usize",
            "campaign_precommit_root_relative_path: &'source str",
            "campaign_precommit: &'authority B4CampaignPrecommitAuthorityV1",
        ] {
            assert!(
                production.contains(required),
                "missing closed handler surface: {required}"
            );
        }

        let inputs = production
            .split("pub(crate) struct FinalizeGenerationSetExecuteInputsV1")
            .nth(1)
            .unwrap()
            .split("\n    }\n")
            .next()
            .unwrap();
        for forbidden in [
            "B4PositiveInputSetPublicationBindingV2",
            "AuthoritativeB4BuildProjection",
            "generation_set_jcs",
            "positive_generation_set",
            "B4ContractArtifactIdentityV1",
        ] {
            assert!(
                !inputs.contains(forbidden),
                "detached authority entered handler inputs: {forbidden}"
            );
        }
        assert!(production.contains("require_stable_campaign_precommit_identity("));
    }

    #[test]
    fn h4_handler_builds_validates_mints_then_durably_reopens() {
        let source = include_str!("finalize_generation_set_handler.rs").replace("\r\n", "\n");
        let production = source.split("#[cfg(test)]").next().unwrap();

        let gate = production
            .split("fn validate_generation_candidate(")
            .nth(1)
            .expect("missing concrete V2 generation gate")
            .split("fn mint_generation_authority(")
            .next()
            .unwrap();
        let construct = gate
            .find("retained.positive_input_set.construct_generation_set(")
            .unwrap();
        let validate = gate
            .find("validate_and_bind_v2_positive_generation_preacceptance(")
            .unwrap();
        assert!(construct < validate);

        let authenticated_preflight = production
            .split("fn authenticate_preflight")
            .nth(1)
            .expect("missing authenticated handler preflight")
            .split("fn execute_generation_set_publication")
            .next()
            .unwrap();
        let physical_precommit = authenticated_preflight
            .find("authenticate_retained_campaign_precommit(")
            .unwrap();
        let generation_validation = authenticated_preflight
            .find("validate_generation_candidate(")
            .unwrap();
        assert!(physical_precommit < generation_validation);

        let publication = production
            .split("fn execute_generation_set_publication")
            .nth(1)
            .expect("missing concrete create-only publication")
            .split("pub(crate) fn preflight_finalize_generation_set_handler")
            .next()
            .unwrap();
        let coordinate = publication
            .find("coordinate_finalize_generation_set(")
            .unwrap();
        let mint = publication
            .find("mint_generation_authority(candidate)")
            .unwrap();
        let staging = publication.find("begin_create_only_directory()").unwrap();
        let write = publication.find("create_file(").unwrap();
        let commit = publication.find("commit_durable()").unwrap();
        let reopen = publication
            .find("reopen_with_postcommit_validation(")
            .unwrap();
        assert!(
            coordinate < mint
                && mint < staging
                && staging < write
                && write < commit
                && commit < reopen
        );
    }

    #[test]
    fn h4_output_and_effect_surface_remain_exact() {
        let source = include_str!("finalize_generation_set_handler.rs").replace("\r\n", "\n");
        let production = source
            .split("pub(in crate::b4_campaign_executor) mod trusted_host")
            .next().unwrap();
        assert!(production.contains("reproduction/postproof/positive-generation-set-v2.json"));
        assert!(production.contains("campaign_root\n                .join(REPRODUCTION_ROOT_COMPONENT)\n                .join(POSTPROOF_ROOT_COMPONENT)"));
        assert!(production.contains("validate_b4_positive_input_set_completion_jcs_v2("));
        assert!(production.contains("authenticate_authoritative_b4_build_projection("));
        assert!(production.contains("authenticate_campaign_precommit_file("));
        assert!(!production.contains("transaction.create_directory("));
        assert_eq!(
            production
                .matches("authenticate_retained_campaign_precommit(")
                .count(),
            2,
            "the physical precommit must be authenticated in preflight and execute"
        );
        assert_eq!(
            production
                .matches("read_immutable_file::<MAX_CAMPAIGN_PRECOMMIT_BYTES>")
                .count(),
            2
        );
        assert_eq!(
            production
                .matches("read_immutable_file::<B4_POSITIVE_INPUT_SET_MAX_BYTES>")
                .count(),
            2
        );
        assert_eq!(
            production
                .matches("read_immutable_file::<B4_POSITIVE_INPUT_SET_COMPLETION_MAX_BYTES>",)
                .count(),
            2
        );
        let retained_input_binding = production
            .split("fn retain_generation_closure")
            .nth(1)
            .unwrap()
            .split("let proof_generator")
            .next()
            .unwrap();
        assert!(
            !retained_input_binding.contains("read("),
            "bounded H0 documents must be read before the broad artifact reader enters"
        );
        for forbidden in [
            "std::process",
            "Command::",
            "LocalProver",
            "risc0_zkvm",
            "publish_and_adopt_directory_tree",
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden handler surface: {forbidden}"
            );
        }
    }

    #[test]
    fn trusted_host_preflight_and_execute_keep_the_qualified_replay_calls() {
        let source = include_str!("finalize_generation_set_handler.rs").replace("\r\n", "\n");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert_eq!(production.matches("replay_trusted_host_precommit_for_finalizer(").count(), 2);
        assert!(production.contains("previous, campaign_root, prior_roots, &build, length, digest"));
        assert!(production.contains("previous, campaign_root, prior_roots, &rebound_build, length, digest"));
        assert!(production.contains("preflight.executable(), build.evidence_root_sha256()"));
        assert!(production.contains("rebound_build.evidence_root_sha256()"));
    }
}
