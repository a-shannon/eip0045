//! Real descriptor-rooted `prepare-campaign-precommit` production handler.

use std::path::Path;

use anyhow::{Context as _, Result};

use super::preflight::{
    ProjectedSingleSubtreeCampaignLayout, project_single_subtree_campaign_layout,
};
#[cfg(any(target_os = "linux", test))]
use super::typestate::ExecutorPreflightContext;

const CONTRACTS_SUBTREE: &str = "contracts";
const CAMPAIGN_PRECOMMIT_FILE: &str = "contracts/campaign-precommit.json";

fn project_prepare_campaign_precommit_layout<const ROOTS: usize>(
    campaign_root: &Path,
    prior_roots: [&Path; ROOTS],
    outer_final_root: &Path,
) -> Result<ProjectedSingleSubtreeCampaignLayout<ROOTS>> {
    project_single_subtree_campaign_layout(
        campaign_root,
        prior_roots,
        outer_final_root,
        CONTRACTS_SUBTREE,
    )
    .context("cannot project prepare-campaign-precommit campaign layout")
}

#[cfg(any(target_os = "linux", test))]
mod execute {
    use std::{env, ffi::OsString, path::Path};

    use anyhow::{Context as _, Result, ensure};
    use eip_0045_reproduction::{
        b4_build_check::{AuthoritativeB4BuildProjection, B4BuildExpectations},
        b4_campaign_contract::{
            B4_VERIFIER_SCHEMA_ROLES, B4CampaignPrecommitAuthorityV2,
            B4CampaignPrecommitExternalInputsV2, B4ContractArtifactEncodingV1,
            B4ExternalArtifactV1, B4ExternalReviewedSourceV1, B4ExternalSchemaDocumentV1,
            B4PositivePrecommitAuthorityV2, B4VerifierContractAuthorityV1,
            Eip0045B4CampaignExecutorBuildDescriptorV1, MAX_CAMPAIGN_PRECOMMIT_BYTES,
            validate_b4_campaign_command_invocation,
        },
        b4_positive_gate::{
            B4PositivePrecommitDocumentsV2, NamedCanonicalJcs,
            validate_and_bind_positive_precommit_v2,
        },
        b4_positive_input_set::{
            B4_POSITIVE_INPUT_SET_COMPLETION_MAX_BYTES, B4_POSITIVE_INPUT_SET_MAX_BYTES,
            B4ValidatedPositiveInputSetCompletionV2, bind_b4_positive_input_set_publication_v2,
            project_b4_positive_input_set_publication_paths_v2,
            validate_b4_positive_input_set_completion_jcs_v2,
        },
    };

    use super::{
        CAMPAIGN_PRECOMMIT_FILE, CONTRACTS_SUBTREE, ExecutorPreflightContext,
        ProjectedSingleSubtreeCampaignLayout, project_prepare_campaign_precommit_layout,
        project_single_subtree_campaign_layout,
    };
    use crate::b4_campaign_executor::{
        authenticated_preflight::{
            authenticate_campaign_precommit_file_v2, derive_campaign_relative_artifact_path,
            require_current_executable_binding_v2,
        },
        custody::MAX_BUFFERED_IMMUTABLE_FILE_BYTES,
        typestate::ExecutorExecuteContext,
    };

    const COMMAND: &str = "prepare-campaign-precommit";
    const POSITIVE_INPUT_SET_FILE: &str = "positive-input-set.json";
    const POSITIVE_INPUT_SET_COMPLETION_FILE: &str = "positive-input-set-completion.json";
    const MAX_VERIFIER_CONTRACT_BYTES: usize = 1024 * 1024;
    const MAX_EXECUTOR_CONTRACT_BYTES: usize = 64 * 1024;
    const MAX_CLI_SPEC_BYTES: usize = 1024 * 1024;
    const MAX_NEGATIVE_PLAN_BYTES: usize = 128 * 1024;
    const MAX_EXPECTATION_SET_BYTES: usize = 256 * 1024;
    const MAX_SCHEMA_DOCUMENT_BYTES: usize = 1024 * 1024;
    const MAX_DESCRIPTOR_BYTES: usize = 1024 * 1024;
    const MAX_RUNNER_PROFILE_BYTES: usize = 1024 * 1024;
    const MAX_SECCOMP_DOCUMENT_BYTES: usize = 1024 * 1024;
    const MAX_JVM_INCLUSION_MANIFEST_BYTES: usize = 1024 * 1024;
    const MAX_VALIDATOR_ARTIFACT_BYTES: usize = MAX_BUFFERED_IMMUTABLE_FILE_BYTES;
    const MAX_EXECUTOR_ARTIFACT_BYTES: usize = MAX_BUFFERED_IMMUTABLE_FILE_BYTES;
    const MAX_SOURCE_ARCHIVE_BYTES: usize = MAX_BUFFERED_IMMUTABLE_FILE_BYTES;
    const MAX_RETAINED_CLOSURE_BYTES: u64 = 1024 * 1024 * 1024;

    /// One descriptor-rooted immutable input locator. It carries no artifact bytes.
    pub(crate) struct PrepareCampaignPrecommitArtifactLocatorV1<'source> {
        pub(crate) root_index: usize,
        pub(crate) root_relative_path: &'source str,
    }

    impl<'source> PrepareCampaignPrecommitArtifactLocatorV1<'source> {
        pub(crate) const fn new(root_index: usize, root_relative_path: &'source str) -> Self {
            Self {
                root_index,
                root_relative_path,
            }
        }
    }

    /// Complete locator-only external closure required by the precommit constructor.
    pub(crate) struct PrepareCampaignPrecommitSourcePlanV1<'source> {
        pub(crate) input_set: PrepareCampaignPrecommitArtifactLocatorV1<'source>,
        pub(crate) input_set_completion: PrepareCampaignPrecommitArtifactLocatorV1<'source>,
        pub(crate) build_evidence_root_index: usize,
        pub(crate) campaign_executor_artifact: PrepareCampaignPrecommitArtifactLocatorV1<'source>,
        pub(crate) campaign_executor_source_archive:
            PrepareCampaignPrecommitArtifactLocatorV1<'source>,
        pub(crate) campaign_executor_build_descriptor:
            PrepareCampaignPrecommitArtifactLocatorV1<'source>,
        pub(crate) executor_contract: PrepareCampaignPrecommitArtifactLocatorV1<'source>,
        pub(crate) verifier_contract: PrepareCampaignPrecommitArtifactLocatorV1<'source>,
        pub(crate) verifier_cli_spec: PrepareCampaignPrecommitArtifactLocatorV1<'source>,
        pub(crate) negative_plan: PrepareCampaignPrecommitArtifactLocatorV1<'source>,
        pub(crate) expectation_set: PrepareCampaignPrecommitArtifactLocatorV1<'source>,
        pub(crate) verifier_schema_documents:
            [PrepareCampaignPrecommitArtifactLocatorV1<'source>; B4_VERIFIER_SCHEMA_ROLES.len()],
        pub(crate) validator_build_descriptors:
            [PrepareCampaignPrecommitArtifactLocatorV1<'source>; 2],
        pub(crate) validator_artifacts: [PrepareCampaignPrecommitArtifactLocatorV1<'source>; 2],
        pub(crate) validator_source_archives:
            [PrepareCampaignPrecommitArtifactLocatorV1<'source>; 2],
        pub(crate) runner_profiles: [PrepareCampaignPrecommitArtifactLocatorV1<'source>; 4],
        pub(crate) seccomp_documents: [PrepareCampaignPrecommitArtifactLocatorV1<'source>; 4],
        pub(crate) jvm_copy_only_inclusion_manifest:
            PrepareCampaignPrecommitArtifactLocatorV1<'source>,
    }

    /// Three caller-held anchors required by descriptor-rooted build custody.
    #[derive(Clone, Copy, Debug)]
    pub(crate) struct PrepareCampaignPrecommitBuildAnchorsV1<'source> {
        pub(crate) source_commit: &'source str,
        pub(crate) source_tree: &'source str,
        pub(crate) evidence_root: &'source str,
    }

    impl PrepareCampaignPrecommitBuildAnchorsV1<'_> {
        fn expectations(&self) -> B4BuildExpectations<'_> {
            B4BuildExpectations {
                expected_source_commit: Some(self.source_commit),
                expected_source_tree: Some(self.source_tree),
                expected_evidence_root: Some(self.evidence_root),
            }
        }
    }

    /// Typed, byte-free inputs reconstructed before the production handler.
    pub(crate) struct PrepareCampaignPrecommitExecuteInputsV1<
        'authority,
        'source,
        const ROOTS: usize,
    > {
        configured_executor_artifact: &'authority Path,
        campaign_root: &'authority Path,
        prior_roots: [&'authority Path; ROOTS],
        outer_final_root: &'authority Path,
        verifier_authority: &'authority B4VerifierContractAuthorityV1,
        build_anchors: PrepareCampaignPrecommitBuildAnchorsV1<'source>,
        source_plan: PrepareCampaignPrecommitSourcePlanV1<'source>,
    }

    impl<'authority, 'source, const ROOTS: usize>
        PrepareCampaignPrecommitExecuteInputsV1<'authority, 'source, ROOTS>
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
            verifier_authority: &'authority B4VerifierContractAuthorityV1,
            build_anchors: PrepareCampaignPrecommitBuildAnchorsV1<'source>,
            source_plan: PrepareCampaignPrecommitSourcePlanV1<'source>,
        ) -> Self {
            Self {
                configured_executor_artifact,
                campaign_root,
                prior_roots,
                outer_final_root,
                verifier_authority,
                build_anchors,
                source_plan,
            }
        }
    }

    /// Private complete result retained only after descriptor-rooted reopen.
    pub(crate) struct PreparedCampaignPrecommitHandlerResultV1 {
        authority: B4CampaignPrecommitAuthorityV2,
    }

    impl PreparedCampaignPrecommitHandlerResultV1 {
        fn authority(&self) -> &B4CampaignPrecommitAuthorityV2 {
            &self.authority
        }
    }

    struct CapturedPrepareCampaignPrecommitInvocation {
        process_argv: Vec<OsString>,
        parsed_preflight_only: bool,
    }

    impl CapturedPrepareCampaignPrecommitInvocation {
        fn capture(parsed_preflight_only: bool) -> Result<Self> {
            let process_argv = env::args_os().collect::<Vec<_>>();
            validate_b4_campaign_command_invocation(&process_argv, COMMAND, parsed_preflight_only)
                .context("invalid retained prepare-campaign-precommit invocation argv")?;
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
            .context("retained prepare-campaign-precommit invocation changed")
        }
    }

    struct RetainedExternalArtifactV1 {
        campaign_relative_path: String,
        bytes: Vec<u8>,
    }

    impl RetainedExternalArtifactV1 {
        fn as_external(&self, encoding: B4ContractArtifactEncodingV1) -> B4ExternalArtifactV1<'_> {
            B4ExternalArtifactV1 {
                path: &self.campaign_relative_path,
                bytes: &self.bytes,
                encoding,
            }
        }

        fn as_named_jcs(&self) -> NamedCanonicalJcs<'_> {
            NamedCanonicalJcs {
                relative_path: &self.campaign_relative_path,
                bytes: &self.bytes,
            }
        }
    }

    struct RetainedCampaignPrecommitExternalClosureV1 {
        input_set: RetainedExternalArtifactV1,
        input_set_completion: RetainedExternalArtifactV1,
        campaign_executor_artifact: RetainedExternalArtifactV1,
        campaign_executor_source_archive: RetainedExternalArtifactV1,
        campaign_executor_build_descriptor: RetainedExternalArtifactV1,
        parsed_campaign_executor_build_descriptor: Eip0045B4CampaignExecutorBuildDescriptorV1,
        executor_contract: RetainedExternalArtifactV1,
        verifier_contract: RetainedExternalArtifactV1,
        verifier_cli_spec: RetainedExternalArtifactV1,
        negative_plan: RetainedExternalArtifactV1,
        expectation_set: RetainedExternalArtifactV1,
        verifier_schema_documents: [RetainedExternalArtifactV1; B4_VERIFIER_SCHEMA_ROLES.len()],
        validator_build_descriptors: [RetainedExternalArtifactV1; 2],
        validator_artifacts: [RetainedExternalArtifactV1; 2],
        validator_source_archives: [RetainedExternalArtifactV1; 2],
        runner_profiles: [RetainedExternalArtifactV1; 4],
        seccomp_documents: [RetainedExternalArtifactV1; 4],
        jvm_copy_only_inclusion_manifest: RetainedExternalArtifactV1,
    }

    impl RetainedCampaignPrecommitExternalClosureV1 {
        fn as_external(
            &self,
            positive_input_set_completion: B4ValidatedPositiveInputSetCompletionV2,
        ) -> B4CampaignPrecommitExternalInputsV2<'_> {
            let descriptor = &self.parsed_campaign_executor_build_descriptor;
            B4CampaignPrecommitExternalInputsV2 {
                input_set: self
                    .input_set
                    .as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs),
                positive_input_set_completion,
                campaign_executor_artifact: self
                    .campaign_executor_artifact
                    .as_external(B4ContractArtifactEncodingV1::RawBytes),
                campaign_executor_reviewed_source: B4ExternalReviewedSourceV1 {
                    repository: &descriptor.reviewed_source.repository,
                    commit: &descriptor.reviewed_source.commit,
                    tree: &descriptor.reviewed_source.tree,
                    archive: self
                        .campaign_executor_source_archive
                        .as_external(B4ContractArtifactEncodingV1::GitBundle),
                },
                campaign_executor_build_descriptor: self
                    .campaign_executor_build_descriptor
                    .as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs),
                executor_contract: self
                    .executor_contract
                    .as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs),
                verifier_contract: self
                    .verifier_contract
                    .as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs),
                verifier_cli_spec: self
                    .verifier_cli_spec
                    .as_external(B4ContractArtifactEncodingV1::RawBytes),
                negative_plan: self
                    .negative_plan
                    .as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs),
                expectation_set: self
                    .expectation_set
                    .as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs),
                verifier_schema_documents: std::array::from_fn(|index| {
                    B4ExternalSchemaDocumentV1 {
                        role: B4_VERIFIER_SCHEMA_ROLES[index],
                        document: self.verifier_schema_documents[index]
                            .as_external(B4ContractArtifactEncodingV1::RawBytes),
                    }
                }),
                validator_build_descriptors: std::array::from_fn(|index| {
                    self.validator_build_descriptors[index]
                        .as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs)
                }),
                validator_artifacts: std::array::from_fn(|index| {
                    self.validator_artifacts[index]
                        .as_external(B4ContractArtifactEncodingV1::RawBytes)
                }),
                validator_source_archives: std::array::from_fn(|index| {
                    self.validator_source_archives[index]
                        .as_external(B4ContractArtifactEncodingV1::GitBundle)
                }),
                runner_profiles: std::array::from_fn(|index| {
                    self.runner_profiles[index]
                        .as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs)
                }),
                seccomp_documents: std::array::from_fn(|index| {
                    self.seccomp_documents[index]
                        .as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs)
                }),
                jvm_copy_only_inclusion_manifest: self
                    .jvm_copy_only_inclusion_manifest
                    .as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs),
            }
        }

        fn positive_precommit_documents(&self) -> B4PositivePrecommitDocumentsV2<'_> {
            B4PositivePrecommitDocumentsV2 {
                input_set: self.input_set.as_named_jcs(),
                verifier_contract: self.verifier_contract.as_named_jcs(),
                runner_profiles: std::array::from_fn(|index| {
                    self.runner_profiles[index].as_named_jcs()
                }),
                seccomp_documents: std::array::from_fn(|index| {
                    self.seccomp_documents[index].as_named_jcs()
                }),
                validator_descriptors: std::array::from_fn(|index| {
                    self.validator_build_descriptors[index].as_named_jcs()
                }),
                jvm_copy_only_inclusion_manifest: self
                    .jvm_copy_only_inclusion_manifest
                    .as_named_jcs(),
            }
        }
    }

    #[derive(Clone, Copy)]
    pub(in crate::b4_campaign_executor) enum RetainedArtifactReadLimit {
        PositiveInputSet,
        PositiveInputSetCompletion,
        ExecutorArtifact,
        SourceArchive,
        Descriptor,
        ExecutorContract,
        VerifierContract,
        CliSpec,
        NegativePlan,
        ExpectationSet,
        SchemaDocument,
        ValidatorArtifact,
        RunnerProfile,
        SeccompDocument,
        JvmInclusionManifest,
    }

    impl RetainedArtifactReadLimit {
        pub(in crate::b4_campaign_executor) const fn max_bytes(self) -> usize {
            match self {
                Self::PositiveInputSet => B4_POSITIVE_INPUT_SET_MAX_BYTES,
                Self::PositiveInputSetCompletion => B4_POSITIVE_INPUT_SET_COMPLETION_MAX_BYTES,
                Self::ExecutorArtifact => MAX_EXECUTOR_ARTIFACT_BYTES,
                Self::SourceArchive => MAX_SOURCE_ARCHIVE_BYTES,
                Self::Descriptor => MAX_DESCRIPTOR_BYTES,
                Self::ExecutorContract => MAX_EXECUTOR_CONTRACT_BYTES,
                Self::VerifierContract => MAX_VERIFIER_CONTRACT_BYTES,
                Self::CliSpec => MAX_CLI_SPEC_BYTES,
                Self::NegativePlan => MAX_NEGATIVE_PLAN_BYTES,
                Self::ExpectationSet => MAX_EXPECTATION_SET_BYTES,
                Self::SchemaDocument => MAX_SCHEMA_DOCUMENT_BYTES,
                Self::ValidatorArtifact => MAX_VALIDATOR_ARTIFACT_BYTES,
                Self::RunnerProfile => MAX_RUNNER_PROFILE_BYTES,
                Self::SeccompDocument => MAX_SECCOMP_DOCUMENT_BYTES,
                Self::JvmInclusionManifest => MAX_JVM_INCLUSION_MANIFEST_BYTES,
            }
        }
    }

    #[derive(Default)]
    struct RetainedByteBudget {
        retained_bytes: u64,
    }

    impl RetainedByteBudget {
        fn remaining(&self) -> Result<u64> {
            MAX_RETAINED_CLOSURE_BYTES
                .checked_sub(self.retained_bytes)
                .context("retained campaign-precommit byte budget invariant failed")
        }

        fn validate_next(&self, byte_length: u64) -> Result<()> {
            validate_retained_artifact_length(byte_length, self.remaining()?)
        }

        fn add(&mut self, byte_length: usize) -> Result<()> {
            let byte_length = u64::try_from(byte_length)
                .context("retained campaign-precommit byte length exceeds u64")?;
            self.validate_next(byte_length)?;
            self.retained_bytes = self
                .retained_bytes
                .checked_add(byte_length)
                .context("retained campaign-precommit byte accounting overflow")?;
            Ok(())
        }
    }

    fn validate_retained_artifact_length(byte_length: u64, remaining: u64) -> Result<()> {
        ensure!(
            byte_length <= remaining,
            "retained campaign-precommit closure exceeds its aggregate byte budget"
        );
        Ok(())
    }

    macro_rules! read_retained_artifact {
        ($custody:expr, $root_index:expr, $relative_path:expr, $limit:expr, $remaining:expr) => {
            match $limit {
                RetainedArtifactReadLimit::PositiveInputSet => $custody
                    .read_immutable_file_with_length_validation::<B4_POSITIVE_INPUT_SET_MAX_BYTES>(
                        $root_index,
                        $relative_path,
                        |byte_length| validate_retained_artifact_length(byte_length, $remaining),
                    ),
                RetainedArtifactReadLimit::PositiveInputSetCompletion => {
                    $custody.read_immutable_file_with_length_validation::<
                        B4_POSITIVE_INPUT_SET_COMPLETION_MAX_BYTES,
                    >($root_index, $relative_path, |byte_length| {
                        validate_retained_artifact_length(byte_length, $remaining)
                    })
                }
                RetainedArtifactReadLimit::ExecutorArtifact => $custody
                    .read_immutable_file_with_length_validation::<MAX_EXECUTOR_ARTIFACT_BYTES>(
                        $root_index,
                        $relative_path,
                        |byte_length| validate_retained_artifact_length(byte_length, $remaining),
                    ),
                RetainedArtifactReadLimit::SourceArchive => $custody
                    .read_immutable_file_with_length_validation::<MAX_SOURCE_ARCHIVE_BYTES>(
                        $root_index,
                        $relative_path,
                        |byte_length| validate_retained_artifact_length(byte_length, $remaining),
                    ),
                RetainedArtifactReadLimit::Descriptor => $custody
                    .read_immutable_file_with_length_validation::<MAX_DESCRIPTOR_BYTES>(
                        $root_index,
                        $relative_path,
                        |byte_length| validate_retained_artifact_length(byte_length, $remaining),
                    ),
                RetainedArtifactReadLimit::ExecutorContract => $custody
                    .read_immutable_file_with_length_validation::<MAX_EXECUTOR_CONTRACT_BYTES>(
                        $root_index,
                        $relative_path,
                        |byte_length| validate_retained_artifact_length(byte_length, $remaining),
                    ),
                RetainedArtifactReadLimit::VerifierContract => $custody
                    .read_immutable_file_with_length_validation::<MAX_VERIFIER_CONTRACT_BYTES>(
                        $root_index,
                        $relative_path,
                        |byte_length| validate_retained_artifact_length(byte_length, $remaining),
                    ),
                RetainedArtifactReadLimit::CliSpec => $custody
                    .read_immutable_file_with_length_validation::<MAX_CLI_SPEC_BYTES>(
                        $root_index,
                        $relative_path,
                        |byte_length| validate_retained_artifact_length(byte_length, $remaining),
                    ),
                RetainedArtifactReadLimit::NegativePlan => $custody
                    .read_immutable_file_with_length_validation::<MAX_NEGATIVE_PLAN_BYTES>(
                        $root_index,
                        $relative_path,
                        |byte_length| validate_retained_artifact_length(byte_length, $remaining),
                    ),
                RetainedArtifactReadLimit::ExpectationSet => $custody
                    .read_immutable_file_with_length_validation::<MAX_EXPECTATION_SET_BYTES>(
                        $root_index,
                        $relative_path,
                        |byte_length| validate_retained_artifact_length(byte_length, $remaining),
                    ),
                RetainedArtifactReadLimit::SchemaDocument => $custody
                    .read_immutable_file_with_length_validation::<MAX_SCHEMA_DOCUMENT_BYTES>(
                        $root_index,
                        $relative_path,
                        |byte_length| validate_retained_artifact_length(byte_length, $remaining),
                    ),
                RetainedArtifactReadLimit::ValidatorArtifact => $custody
                    .read_immutable_file_with_length_validation::<MAX_VALIDATOR_ARTIFACT_BYTES>(
                        $root_index,
                        $relative_path,
                        |byte_length| validate_retained_artifact_length(byte_length, $remaining),
                    ),
                RetainedArtifactReadLimit::RunnerProfile => $custody
                    .read_immutable_file_with_length_validation::<MAX_RUNNER_PROFILE_BYTES>(
                        $root_index,
                        $relative_path,
                        |byte_length| validate_retained_artifact_length(byte_length, $remaining),
                    ),
                RetainedArtifactReadLimit::SeccompDocument => $custody
                    .read_immutable_file_with_length_validation::<MAX_SECCOMP_DOCUMENT_BYTES>(
                        $root_index,
                        $relative_path,
                        |byte_length| validate_retained_artifact_length(byte_length, $remaining),
                    ),
                RetainedArtifactReadLimit::JvmInclusionManifest => $custody
                    .read_immutable_file_with_length_validation::<MAX_JVM_INCLUSION_MANIFEST_BYTES>(
                        $root_index,
                        $relative_path,
                        |byte_length| validate_retained_artifact_length(byte_length, $remaining),
                    ),
            }
        };
    }

    fn retain_artifact<const ROOTS: usize, F>(
        campaign_root: &Path,
        prior_roots: [&Path; ROOTS],
        read: &mut F,
        locator: &PrepareCampaignPrecommitArtifactLocatorV1<'_>,
        limit: RetainedArtifactReadLimit,
    ) -> Result<RetainedExternalArtifactV1>
    where
        F: for<'path> FnMut(usize, &'path str, RetainedArtifactReadLimit) -> Result<Vec<u8>>,
    {
        let prior_root = *prior_roots
            .get(locator.root_index)
            .context("precommit artifact root index is outside the retained root set")?;
        let campaign_relative_path = derive_campaign_relative_artifact_path(
            campaign_root,
            prior_root,
            locator.root_relative_path,
        )?;
        let bytes =
            read(locator.root_index, locator.root_relative_path, limit).with_context(|| {
                format!(
                    "cannot retain precommit artifact through immutable-root custody: {}",
                    locator.root_relative_path
                )
            })?;
        Ok(RetainedExternalArtifactV1 {
            campaign_relative_path,
            bytes,
        })
    }

    fn retain_array<const ROOTS: usize, const COUNT: usize, F>(
        campaign_root: &Path,
        prior_roots: [&Path; ROOTS],
        read: &mut F,
        locators: &[PrepareCampaignPrecommitArtifactLocatorV1<'_>; COUNT],
        limit: RetainedArtifactReadLimit,
    ) -> Result<[RetainedExternalArtifactV1; COUNT]>
    where
        F: for<'path> FnMut(usize, &'path str, RetainedArtifactReadLimit) -> Result<Vec<u8>>,
    {
        locators
            .iter()
            .map(|locator| retain_artifact(campaign_root, prior_roots, read, locator, limit))
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("retained precommit artifact cardinality drift"))
    }

    fn retain_external_closure<const ROOTS: usize, F>(
        campaign_root: &Path,
        prior_roots: [&Path; ROOTS],
        read: F,
        plan: &PrepareCampaignPrecommitSourcePlanV1<'_>,
    ) -> Result<RetainedCampaignPrecommitExternalClosureV1>
    where
        F: for<'path> FnMut(usize, &'path str, RetainedArtifactReadLimit, u64) -> Result<Vec<u8>>,
    {
        let mut source_read = read;
        let mut budget = RetainedByteBudget::default();
        let mut read = |root_index: usize,
                        relative_path: &str,
                        limit: RetainedArtifactReadLimit|
         -> Result<Vec<u8>> {
            let remaining = budget.remaining()?;
            let bytes = source_read(root_index, relative_path, limit, remaining)?;
            budget.add(bytes.len())?;
            Ok(bytes)
        };
        let campaign_executor_build_descriptor = retain_artifact(
            campaign_root,
            prior_roots,
            &mut read,
            &plan.campaign_executor_build_descriptor,
            RetainedArtifactReadLimit::Descriptor,
        )?;
        let parsed_campaign_executor_build_descriptor =
            Eip0045B4CampaignExecutorBuildDescriptorV1::from_canonical_jcs(
                &campaign_executor_build_descriptor.bytes,
            )
            .context("retained campaign-executor build descriptor is invalid")?;
        Ok(RetainedCampaignPrecommitExternalClosureV1 {
            input_set: retain_artifact(
                campaign_root,
                prior_roots,
                &mut read,
                &plan.input_set,
                RetainedArtifactReadLimit::PositiveInputSet,
            )?,
            input_set_completion: retain_artifact(
                campaign_root,
                prior_roots,
                &mut read,
                &plan.input_set_completion,
                RetainedArtifactReadLimit::PositiveInputSetCompletion,
            )?,
            campaign_executor_artifact: retain_artifact(
                campaign_root,
                prior_roots,
                &mut read,
                &plan.campaign_executor_artifact,
                RetainedArtifactReadLimit::ExecutorArtifact,
            )?,
            campaign_executor_source_archive: retain_artifact(
                campaign_root,
                prior_roots,
                &mut read,
                &plan.campaign_executor_source_archive,
                RetainedArtifactReadLimit::SourceArchive,
            )?,
            campaign_executor_build_descriptor,
            parsed_campaign_executor_build_descriptor,
            executor_contract: retain_artifact(
                campaign_root,
                prior_roots,
                &mut read,
                &plan.executor_contract,
                RetainedArtifactReadLimit::ExecutorContract,
            )?,
            verifier_contract: retain_artifact(
                campaign_root,
                prior_roots,
                &mut read,
                &plan.verifier_contract,
                RetainedArtifactReadLimit::VerifierContract,
            )?,
            verifier_cli_spec: retain_artifact(
                campaign_root,
                prior_roots,
                &mut read,
                &plan.verifier_cli_spec,
                RetainedArtifactReadLimit::CliSpec,
            )?,
            negative_plan: retain_artifact(
                campaign_root,
                prior_roots,
                &mut read,
                &plan.negative_plan,
                RetainedArtifactReadLimit::NegativePlan,
            )?,
            expectation_set: retain_artifact(
                campaign_root,
                prior_roots,
                &mut read,
                &plan.expectation_set,
                RetainedArtifactReadLimit::ExpectationSet,
            )?,
            verifier_schema_documents: retain_array(
                campaign_root,
                prior_roots,
                &mut read,
                &plan.verifier_schema_documents,
                RetainedArtifactReadLimit::SchemaDocument,
            )?,
            validator_build_descriptors: retain_array(
                campaign_root,
                prior_roots,
                &mut read,
                &plan.validator_build_descriptors,
                RetainedArtifactReadLimit::Descriptor,
            )?,
            validator_artifacts: retain_array(
                campaign_root,
                prior_roots,
                &mut read,
                &plan.validator_artifacts,
                RetainedArtifactReadLimit::ValidatorArtifact,
            )?,
            validator_source_archives: retain_array(
                campaign_root,
                prior_roots,
                &mut read,
                &plan.validator_source_archives,
                RetainedArtifactReadLimit::SourceArchive,
            )?,
            runner_profiles: retain_array(
                campaign_root,
                prior_roots,
                &mut read,
                &plan.runner_profiles,
                RetainedArtifactReadLimit::RunnerProfile,
            )?,
            seccomp_documents: retain_array(
                campaign_root,
                prior_roots,
                &mut read,
                &plan.seccomp_documents,
                RetainedArtifactReadLimit::SeccompDocument,
            )?,
            jvm_copy_only_inclusion_manifest: retain_artifact(
                campaign_root,
                prior_roots,
                &mut read,
                &plan.jvm_copy_only_inclusion_manifest,
                RetainedArtifactReadLimit::JvmInclusionManifest,
            )?,
        })
    }

    fn validate_source_plan<const ROOTS: usize>(
        plan: &PrepareCampaignPrecommitSourcePlanV1<'_>,
    ) -> Result<()> {
        ensure!(
            ROOTS > 0,
            "prepare-campaign-precommit requires immutable roots"
        );
        ensure!(
            plan.build_evidence_root_index < ROOTS,
            "build-evidence root index is outside the retained root set"
        );
        Ok(())
    }

    fn validate_retained_h0_v2_publication(
        retained: &RetainedCampaignPrecommitExternalClosureV1,
    ) -> Result<B4ValidatedPositiveInputSetCompletionV2> {
        let input_suffix = format!("/{POSITIVE_INPUT_SET_FILE}");
        let phase_root = retained
            .input_set
            .campaign_relative_path
            .strip_suffix(&input_suffix)
            .context("retained V2 input-set path does not expose its closed phase root")?;
        let paths = project_b4_positive_input_set_publication_paths_v2(phase_root)
            .context("cannot project retained H0 V2 publication paths")?;
        ensure!(
            paths.input_set_path() == retained.input_set.campaign_relative_path
                && paths.completion_path() == retained.input_set_completion.campaign_relative_path,
            "retained H0 V2 input and completion differ from the closed two-file layout"
        );
        ensure!(
            retained
                .input_set_completion
                .campaign_relative_path
                .ends_with(POSITIVE_INPUT_SET_COMPLETION_FILE),
            "retained H0 V2 completion path has the wrong filename"
        );
        let binding = bind_b4_positive_input_set_publication_v2(&paths, &retained.input_set.bytes)
            .context("cannot bind retained H0 V2 input set")?;
        validate_b4_positive_input_set_completion_jcs_v2(
            &retained.input_set_completion.bytes,
            &binding,
        )
        .context("retained H0 V2 completion is stale")
    }

    fn reconstruct_positive_precommit_authority_v2(
        authoritative_build: &AuthoritativeB4BuildProjection,
        retained: &RetainedCampaignPrecommitExternalClosureV1,
    ) -> Result<(
        B4PositivePrecommitAuthorityV2,
        B4ValidatedPositiveInputSetCompletionV2,
    )> {
        let positive_input_set_completion = validate_retained_h0_v2_publication(retained)?;
        let positive_precommit = validate_and_bind_positive_precommit_v2(
            authoritative_build,
            retained.positive_precommit_documents(),
        )
        .context("cannot reconstruct the descriptor-rooted V2 positive-precommit authority")?;
        Ok((positive_precommit, positive_input_set_completion))
    }

    type PrepareCampaignPrecommitPreflightContext<const ROOTS: usize> =
        ExecutorPreflightContext<ROOTS, ProjectedSingleSubtreeCampaignLayout<ROOTS>>;

    struct AuthenticatedPrepareCampaignPrecommitPreflightV1<const ROOTS: usize> {
        preflight: PrepareCampaignPrecommitPreflightContext<ROOTS>,
        invocation: CapturedPrepareCampaignPrecommitInvocation,
    }

    fn authenticate_preflight<const ROOTS: usize>(
        inputs: &PrepareCampaignPrecommitExecuteInputsV1<'_, '_, ROOTS>,
        parsed_preflight_only: bool,
    ) -> Result<AuthenticatedPrepareCampaignPrecommitPreflightV1<ROOTS>> {
        validate_source_plan::<ROOTS>(&inputs.source_plan)?;
        let projected = project_prepare_campaign_precommit_layout(
            inputs.campaign_root,
            inputs.prior_roots,
            inputs.outer_final_root,
        )?;
        let preflight =
            ExecutorPreflightContext::capture(inputs.configured_executor_artifact, projected)
                .context("prepare-campaign-precommit retained preflight failed")?;
        let invocation =
            CapturedPrepareCampaignPrecommitInvocation::capture(parsed_preflight_only)?;
        let retained = retain_external_closure(
            inputs.campaign_root,
            inputs.prior_roots,
            |root_index, relative_path, limit, remaining| {
                read_retained_artifact!(preflight, root_index, relative_path, limit, remaining)
            },
            &inputs.source_plan,
        )?;
        preflight
            .executable()
            .require_artifact_identity(&retained.parsed_campaign_executor_build_descriptor.artifact)
            .context("running executable differs from retained build descriptor")?;
        let authoritative_build = preflight
            .authenticate_authoritative_b4_build_projection(
                inputs.source_plan.build_evidence_root_index,
                &inputs.build_anchors.expectations(),
            )
            .context("preflight authoritative B4 build projection failed")?;
        reconstruct_positive_precommit_authority_v2(&authoritative_build, &retained)?;
        invocation.revalidate()?;
        Ok(AuthenticatedPrepareCampaignPrecommitPreflightV1 {
            preflight,
            invocation,
        })
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum PrepareCampaignPrecommitTransition {
        RetainExternalClosure,
        BindExecutableToDescriptor,
        ConstructAuthority,
        RebindExecutableToAuthority,
        PublishAndReopen,
        FinalExecutableRebind,
    }

    trait PrepareCampaignPrecommitTransitionObserver {
        fn before(&mut self, transition: PrepareCampaignPrecommitTransition) -> Result<()>;
        fn after(&mut self, transition: PrepareCampaignPrecommitTransition);
    }

    struct NoopPrepareCampaignPrecommitTransitionObserver;

    impl PrepareCampaignPrecommitTransitionObserver for NoopPrepareCampaignPrecommitTransitionObserver {
        fn before(&mut self, _transition: PrepareCampaignPrecommitTransition) -> Result<()> {
            Ok(())
        }

        fn after(&mut self, _transition: PrepareCampaignPrecommitTransition) {}
    }

    trait PrepareCampaignPrecommitCoordinator {
        type Retained;
        type Authority;
        type Published;

        fn retain_external_closure(&mut self) -> Result<Self::Retained>;
        fn bind_executable_to_descriptor(&mut self, retained: &Self::Retained) -> Result<()>;
        fn construct_authority(&mut self, retained: Self::Retained) -> Result<Self::Authority>;
        fn rebind_executable_to_authority(&mut self, authority: &Self::Authority) -> Result<()>;
        fn publish_and_reopen(&mut self, authority: Self::Authority) -> Result<Self::Published>;
        fn final_executable_rebind(&mut self, published: &Self::Published) -> Result<()>;
    }

    fn execute_prepare_campaign_precommit_pipeline<C, O>(
        coordinator: &mut C,
        observer: &mut O,
    ) -> Result<C::Published>
    where
        C: PrepareCampaignPrecommitCoordinator,
        O: PrepareCampaignPrecommitTransitionObserver,
    {
        observer.before(PrepareCampaignPrecommitTransition::RetainExternalClosure)?;
        let retained = coordinator.retain_external_closure()?;
        observer.after(PrepareCampaignPrecommitTransition::RetainExternalClosure);

        observer.before(PrepareCampaignPrecommitTransition::BindExecutableToDescriptor)?;
        coordinator.bind_executable_to_descriptor(&retained)?;
        observer.after(PrepareCampaignPrecommitTransition::BindExecutableToDescriptor);

        observer.before(PrepareCampaignPrecommitTransition::ConstructAuthority)?;
        let authority = coordinator.construct_authority(retained)?;
        observer.after(PrepareCampaignPrecommitTransition::ConstructAuthority);

        observer.before(PrepareCampaignPrecommitTransition::RebindExecutableToAuthority)?;
        coordinator.rebind_executable_to_authority(&authority)?;
        observer.after(PrepareCampaignPrecommitTransition::RebindExecutableToAuthority);

        observer.before(PrepareCampaignPrecommitTransition::PublishAndReopen)?;
        let published = coordinator.publish_and_reopen(authority)?;
        observer.after(PrepareCampaignPrecommitTransition::PublishAndReopen);

        observer.before(PrepareCampaignPrecommitTransition::FinalExecutableRebind)?;
        coordinator.final_executable_rebind(&published)?;
        observer.after(PrepareCampaignPrecommitTransition::FinalExecutableRebind);
        Ok(published)
    }

    struct RealPrepareCampaignPrecommitCoordinator<
        'execute,
        'input,
        'authority,
        'source,
        const ROOTS: usize,
    > {
        execute: &'execute mut ExecutorExecuteContext<
            ROOTS,
            ProjectedSingleSubtreeCampaignLayout<ROOTS>,
        >,
        inputs: &'input PrepareCampaignPrecommitExecuteInputsV1<'authority, 'source, ROOTS>,
        invocation: &'input CapturedPrepareCampaignPrecommitInvocation,
        published_campaign_relative_path: String,
    }

    impl<const ROOTS: usize> PrepareCampaignPrecommitCoordinator
        for RealPrepareCampaignPrecommitCoordinator<'_, '_, '_, '_, ROOTS>
    {
        type Retained = RetainedCampaignPrecommitExternalClosureV1;
        type Authority = B4CampaignPrecommitAuthorityV2;
        type Published = PreparedCampaignPrecommitHandlerResultV1;

        fn retain_external_closure(&mut self) -> Result<Self::Retained> {
            self.invocation.revalidate()?;
            retain_external_closure(
                self.inputs.campaign_root,
                self.inputs.prior_roots,
                |root_index, relative_path, limit, remaining| {
                    read_retained_artifact!(
                        self.execute,
                        root_index,
                        relative_path,
                        limit,
                        remaining
                    )
                },
                &self.inputs.source_plan,
            )
        }

        fn bind_executable_to_descriptor(&mut self, retained: &Self::Retained) -> Result<()> {
            self.execute
                .executable()
                .require_artifact_identity(
                    &retained.parsed_campaign_executor_build_descriptor.artifact,
                )
                .context("running executable differs from retained build descriptor")
        }

        fn construct_authority(&mut self, retained: Self::Retained) -> Result<Self::Authority> {
            let authoritative_build = self
                .execute
                .authenticate_authoritative_b4_build_projection(
                    self.inputs.source_plan.build_evidence_root_index,
                    &self.inputs.build_anchors.expectations(),
                )
                .context("execute authoritative B4 build projection failed")?;
            let (positive_precommit, positive_input_set_completion) =
                reconstruct_positive_precommit_authority_v2(&authoritative_build, &retained)?;
            B4CampaignPrecommitAuthorityV2::from_external_closure(
                positive_precommit,
                self.inputs.verifier_authority,
                retained.as_external(positive_input_set_completion),
            )
            .context("cannot construct the descriptor-rooted campaign-precommit authority")
        }

        fn rebind_executable_to_authority(&mut self, authority: &Self::Authority) -> Result<()> {
            self.invocation.revalidate()?;
            require_current_executable_binding_v2(self.execute.executable(), authority)
        }

        fn publish_and_reopen(&mut self, authority: Self::Authority) -> Result<Self::Published> {
            let canonical_precommit = authority.to_canonical_precommit_jcs()?;
            let published_campaign_relative_path = &self.published_campaign_relative_path;
            self.execute.with_mutation(|mutation| {
                let mut transaction = mutation.begin_create_only_directory()?;
                transaction.create_directory(CONTRACTS_SUBTREE)?;
                transaction.create_file(
                    CAMPAIGN_PRECOMMIT_FILE,
                    &canonical_precommit,
                    MAX_CAMPAIGN_PRECOMMIT_BYTES,
                )?;
                transaction.commit_with_postcommit_validation(|committed| {
                    let reopened = committed
                        .read_file(CAMPAIGN_PRECOMMIT_FILE, MAX_CAMPAIGN_PRECOMMIT_BYTES)?;
                    authenticate_campaign_precommit_file_v2(
                        published_campaign_relative_path,
                        &authority,
                        &reopened,
                    )?;
                    Ok(())
                })
            })?;
            Ok(PreparedCampaignPrecommitHandlerResultV1 { authority })
        }

        fn final_executable_rebind(&mut self, published: &Self::Published) -> Result<()> {
            self.invocation.revalidate()?;
            require_current_executable_binding_v2(self.execute.executable(), published.authority())
        }
    }

    /// Reach the exact zero-effect boundary after every immutable input is reopened.
    pub(crate) fn preflight_prepare_campaign_precommit_handler<const ROOTS: usize>(
        inputs: &PrepareCampaignPrecommitExecuteInputsV1<'_, '_, ROOTS>,
    ) -> Result<()> {
        let authenticated = authenticate_preflight(inputs, true)?;
        authenticated.invocation.revalidate()?;
        authenticated
            .preflight
            .finish_preflight()
            .context("prepare-campaign-precommit authenticated preflight failed")
    }

    /// Execute the real authority constructor and distinct create-only publication.
    pub(crate) fn execute_prepare_campaign_precommit_handler<const ROOTS: usize>(
        inputs: PrepareCampaignPrecommitExecuteInputsV1<'_, '_, ROOTS>,
    ) -> Result<PreparedCampaignPrecommitHandlerResultV1> {
        let AuthenticatedPrepareCampaignPrecommitPreflightV1 {
            preflight,
            invocation,
        } = authenticate_preflight(&inputs, false)?;
        let published_campaign_relative_path = derive_campaign_relative_artifact_path(
            inputs.campaign_root,
            inputs.outer_final_root,
            CAMPAIGN_PRECOMMIT_FILE,
        )?;
        preflight.execute(|execute| {
            let mut coordinator = RealPrepareCampaignPrecommitCoordinator {
                execute,
                inputs: &inputs,
                invocation: &invocation,
                published_campaign_relative_path,
            };
            let mut observer = NoopPrepareCampaignPrecommitTransitionObserver;
            execute_prepare_campaign_precommit_pipeline(&mut coordinator, &mut observer)
        })
    }

    #[cfg(all(target_os = "linux", feature = "b4-authoritative-build-custody"))]
    pub(in crate::b4_campaign_executor) mod trusted_host {
        use super::*;
        use eip_0045_reproduction::{
            b4_campaign_contract::{B4CampaignPrecommitExternalInputsV1, B4ContractArtifactIdentityV1,
                B4ExternalReviewedSourceV1, B4ExternalSchemaDocumentV1,
                B4TrustedHostCampaignPrecommitAuthorityV1, B4TrustedHostRequestV1,
                derive_b4_trusted_host_campaign_precommit_jcs_v1,
                Eip0045B4TrustedHostCampaignPrecommitV1},
            b4_positive_input_set::{project_b4_trusted_host_input_set_paths_v1,
                validate_b4_trusted_host_input_set_completion_jcs_v1},
        };

        fn locator<'a>(request: &'a B4TrustedHostRequestV1, name: &str)
            -> Result<PrepareCampaignPrecommitArtifactLocatorV1<'a>> {
            let source = request.locator(name)?;
            Ok(PrepareCampaignPrecommitArtifactLocatorV1::new(
                source.root_index, &source.relative_path))
        }

        fn plan(request: &B4TrustedHostRequestV1) -> Result<PrepareCampaignPrecommitSourcePlanV1<'_>> {
            let schemas: [PrepareCampaignPrecommitArtifactLocatorV1<'_>; B4_VERIFIER_SCHEMA_ROLES.len()] =
                (0..B4_VERIFIER_SCHEMA_ROLES.len()).map(|i| locator(request, &format!("schema{i}")))
                    .collect::<Result<Vec<_>>>()?.try_into()
                    .map_err(|_| anyhow::anyhow!("trusted-host schema locator count drift"))?;
            Ok(PrepareCampaignPrecommitSourcePlanV1 {
                input_set: locator(request, "inputSet")?,
                input_set_completion: locator(request, "inputSetCompletion")?,
                build_evidence_root_index: request.build_evidence_root_index,
                campaign_executor_artifact: locator(request, "campaignExecutorArtifact")?,
                campaign_executor_source_archive: locator(request, "executorSourceArchive")?,
                campaign_executor_build_descriptor: locator(request, "executorBuildDescriptor")?,
                executor_contract: locator(request, "executorContract")?,
                verifier_contract: locator(request, "verifierContract")?,
                verifier_cli_spec: locator(request, "verifierCliSpec")?,
                negative_plan: locator(request, "negativePlan")?,
                expectation_set: locator(request, "expectationSet")?,
                verifier_schema_documents: schemas,
                validator_build_descriptors: [locator(request, "validatorDescriptor0")?, locator(request, "validatorDescriptor1")?],
                validator_artifacts: [locator(request, "validatorArtifact0")?, locator(request, "validatorArtifact1")?],
                validator_source_archives: [locator(request, "validatorSourceArchive0")?, locator(request, "validatorSourceArchive1")?],
                runner_profiles: [locator(request, "runnerProfile0")?, locator(request, "runnerProfile1")?,
                    locator(request, "runnerProfile2")?, locator(request, "runnerProfile3")?],
                seccomp_documents: [locator(request, "seccomp0")?, locator(request, "seccomp1")?,
                    locator(request, "seccomp2")?, locator(request, "seccomp3")?],
                jvm_copy_only_inclusion_manifest: locator(request, "jvmInclusion")?,
            })
        }

        impl RetainedCampaignPrecommitExternalClosureV1 {
            fn trusted_common(&self) -> B4CampaignPrecommitExternalInputsV1<'_> {
                let descriptor = &self.parsed_campaign_executor_build_descriptor;
                B4CampaignPrecommitExternalInputsV1 {
                    input_set: self.input_set.as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs),
                    campaign_executor_artifact: self.campaign_executor_artifact.as_external(B4ContractArtifactEncodingV1::RawBytes),
                    campaign_executor_reviewed_source: B4ExternalReviewedSourceV1 {
                        repository: &descriptor.reviewed_source.repository,
                        commit: &descriptor.reviewed_source.commit,
                        tree: &descriptor.reviewed_source.tree,
                        archive: self.campaign_executor_source_archive.as_external(B4ContractArtifactEncodingV1::GitBundle),
                    },
                    campaign_executor_build_descriptor: self.campaign_executor_build_descriptor.as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs),
                    executor_contract: self.executor_contract.as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs),
                    verifier_contract: self.verifier_contract.as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs),
                    verifier_cli_spec: self.verifier_cli_spec.as_external(B4ContractArtifactEncodingV1::RawBytes),
                    negative_plan: self.negative_plan.as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs),
                    expectation_set: self.expectation_set.as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs),
                    verifier_schema_documents: std::array::from_fn(|i| B4ExternalSchemaDocumentV1 {
                        role: B4_VERIFIER_SCHEMA_ROLES[i],
                        document: self.verifier_schema_documents[i].as_external(B4ContractArtifactEncodingV1::RawBytes),
                    }),
                    validator_build_descriptors: std::array::from_fn(|i| self.validator_build_descriptors[i]
                        .as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs)),
                    validator_artifacts: std::array::from_fn(|i| self.validator_artifacts[i]
                        .as_external(B4ContractArtifactEncodingV1::RawBytes)),
                    validator_source_archives: std::array::from_fn(|i| self.validator_source_archives[i]
                        .as_external(B4ContractArtifactEncodingV1::GitBundle)),
                    runner_profiles: std::array::from_fn(|i| self.runner_profiles[i]
                        .as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs)),
                    seccomp_documents: std::array::from_fn(|i| self.seccomp_documents[i]
                        .as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs)),
                    jvm_copy_only_inclusion_manifest: self.jvm_copy_only_inclusion_manifest
                        .as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs),
                }
            }
        }

        fn derive(retained: &RetainedCampaignPrecommitExternalClosureV1,
            build: &AuthoritativeB4BuildProjection, request: &B4TrustedHostRequestV1,
            request_bytes: u64, request_sha256: &str) -> Result<Vec<u8>> {
            let descriptor = &retained.parsed_campaign_executor_build_descriptor;
            let executor = B4ContractArtifactIdentityV1::from_bytes(
                &retained.campaign_executor_artifact.campaign_relative_path,
                B4ContractArtifactEncodingV1::RawBytes, &retained.campaign_executor_artifact.bytes)?;
            ensure!(executor == descriptor.artifact, "trusted-host executor differs from its retained descriptor");
            let phase = retained.input_set.campaign_relative_path
                .strip_suffix("/positive-input-set.json").context("trusted-host input-set filename drift")?;
            let paths = project_b4_trusted_host_input_set_paths_v1(phase)?;
            ensure!(paths.input_set_path() == retained.input_set.campaign_relative_path
                && paths.completion_path() == retained.input_set_completion.campaign_relative_path,
                "trusted-host input and completion paths differ from their closed projection");
            let completion = validate_b4_trusted_host_input_set_completion_jcs_v1(
                &retained.input_set_completion.bytes, &paths, &retained.input_set.bytes,
                request.input_set_request_byte_length.context("missing input-set request length")?,
                request.input_set_request_sha256.as_deref().context("missing input-set request digest")?,
                build.evidence_root_sha256(), &executor)?;
            let positive = validate_and_bind_positive_precommit_v2(build,
                retained.positive_precommit_documents())?;
            let verifier = B4VerifierContractAuthorityV1::from_external_documents(
                retained.verifier_cli_spec.as_external(B4ContractArtifactEncodingV1::RawBytes),
                retained.negative_plan.as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs),
                retained.expectation_set.as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs),
                std::array::from_fn(|i| B4ExternalSchemaDocumentV1 {
                    role: B4_VERIFIER_SCHEMA_ROLES[i],
                    document: retained.verifier_schema_documents[i].as_external(B4ContractArtifactEncodingV1::RawBytes),
                }))?;
            derive_b4_trusted_host_campaign_precommit_jcs_v1(positive, &verifier,
                retained.trusted_common(), completion,
                retained.input_set_completion.as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs),
                request_bytes, request_sha256)
        }

        fn derive_terminal_authorities(
            retained: &RetainedCampaignPrecommitExternalClosureV1,
            build: &AuthoritativeB4BuildProjection,
            previous: &B4TrustedHostRequestV1,
            request_source: B4ExternalArtifactV1<'_>,
            request_bytes: u64,
            request_sha256: &str,
        ) -> Result<(B4TrustedHostCampaignPrecommitAuthorityV1, B4VerifierContractAuthorityV1)> {
            let parsed_request = B4TrustedHostRequestV1::from_canonical_jcs(request_source.bytes)
                .context("terminal replay prior request source is not canonical")?;
            ensure!(parsed_request == *previous,
                "terminal replay prior request differs from its selected parsed request");
            let expected = derive(retained, build, previous, request_bytes, request_sha256)?;
            let descriptor = &retained.parsed_campaign_executor_build_descriptor;
            let executor = B4ContractArtifactIdentityV1::from_bytes(
                &retained.campaign_executor_artifact.campaign_relative_path,
                B4ContractArtifactEncodingV1::RawBytes,
                &retained.campaign_executor_artifact.bytes)?;
            ensure!(executor == descriptor.artifact,
                "terminal replay executor differs from its retained descriptor");
            let phase = retained.input_set.campaign_relative_path
                .strip_suffix("/positive-input-set.json")
                .context("terminal replay input-set filename drift")?;
            let paths = project_b4_trusted_host_input_set_paths_v1(phase)?;
            ensure!(paths.input_set_path() == retained.input_set.campaign_relative_path
                && paths.completion_path() == retained.input_set_completion.campaign_relative_path,
                "terminal replay input and completion paths differ from the closed projection");
            let completion = validate_b4_trusted_host_input_set_completion_jcs_v1(
                &retained.input_set_completion.bytes, &paths, &retained.input_set.bytes,
                previous.input_set_request_byte_length.context("missing input-set request length")?,
                previous.input_set_request_sha256.as_deref().context("missing input-set request digest")?,
                build.evidence_root_sha256(), &executor)?;
            let positive = validate_and_bind_positive_precommit_v2(build,
                retained.positive_precommit_documents())?;
            let verifier = B4VerifierContractAuthorityV1::from_external_documents(
                retained.verifier_cli_spec.as_external(B4ContractArtifactEncodingV1::RawBytes),
                retained.negative_plan.as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs),
                retained.expectation_set.as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs),
                std::array::from_fn(|i| B4ExternalSchemaDocumentV1 {
                    role: B4_VERIFIER_SCHEMA_ROLES[i],
                    document: retained.verifier_schema_documents[i]
                        .as_external(B4ContractArtifactEncodingV1::RawBytes),
                }))?;
            let authority = B4TrustedHostCampaignPrecommitAuthorityV1::from_external_closure(
                positive, &verifier, retained.trusted_common(), completion,
                retained.input_set_completion.as_external(B4ContractArtifactEncodingV1::Rfc8785Jcs),
                request_source, request_bytes, request_sha256, build.evidence_root_sha256())?;
            authority.verify_candidate_jcs(&expected)
                .context("terminal replay authority differs from the byte-rederived envelope")?;
            Ok((authority, verifier))
        }

        fn map_previous_precommit_roots<const ROOTS: usize>(
            previous: &B4TrustedHostRequestV1,
            current_roots: [&Path; ROOTS],
        ) -> Result<B4TrustedHostRequestV1> {
            let mut mapped = previous.clone();
            for source in mapped.sources.values_mut() {
                let previous_root = previous.prior_roots.get(source.root_index)
                    .context("prior precommit source root index is invalid")?;
                source.root_index = current_roots.iter()
                    .position(|root| root.to_str() == Some(previous_root.as_str()))
                    .context("prior precommit source root is not retained by finalize-generation-set")?;
            }
            let previous_build_root = previous.prior_roots.get(previous.build_evidence_root_index)
                .context("prior precommit build root index is invalid")?;
            mapped.build_evidence_root_index = current_roots.iter()
                .position(|root| root.to_str() == Some(previous_build_root.as_str()))
                .context("prior precommit build root is not retained by finalize-generation-set")?;
            mapped.prior_roots = current_roots.iter().map(|root| root.to_str()
                .context("finalize-generation-set root is not UTF-8").map(str::to_owned))
                .collect::<Result<Vec<_>>>()?;
            Ok(mapped)
        }

        /// Reconstruct the prior command from immutable roots selected by the
        /// next command. No root is padded, merged, or replaced by a parent.
        pub(in crate::b4_campaign_executor) fn replay_for_finalizer<const ROOTS: usize, F>(
            previous: &B4TrustedHostRequestV1,
            campaign_root: &Path,
            current_roots: [&Path; ROOTS],
            build: &AuthoritativeB4BuildProjection,
            request_bytes: u64,
            request_sha256: &str,
            read: F,
        ) -> Result<Vec<u8>>
        where
            F: for<'path> FnMut(usize, &'path str, RetainedArtifactReadLimit, u64) -> Result<Vec<u8>>,
        {
            ensure!(previous.command == "prepare-campaign-precommit"
                && previous.campaign_root == campaign_root.to_str().context("campaign root is not UTF-8")?,
                "prior trusted-host request is not the selected precommit command");
            let mapped = map_previous_precommit_roots(previous, current_roots)?;
            let plan = plan(&mapped)?;
            let retained = retain_external_closure(campaign_root, current_roots, read, &plan)?;
            derive(&retained, build, previous, request_bytes, request_sha256)
        }

        /// Reconstruct the distinct trusted-host authority for terminal
        /// publication from the same immutable-root closure as the finalizer.
        /// The caller separately binds the retained envelope to the running
        /// executable and supplies the physically held prior-request source.
        #[allow(clippy::too_many_arguments)]
        pub(in crate::b4_campaign_executor) fn replay_authority_for_terminal<const ROOTS: usize, F>(
            previous: &B4TrustedHostRequestV1,
            request_source: B4ExternalArtifactV1<'_>,
            campaign_root: &Path,
            current_roots: [&Path; ROOTS],
            build: &AuthoritativeB4BuildProjection,
            request_bytes: u64,
            request_sha256: &str,
            read: F,
        ) -> Result<B4TrustedHostCampaignPrecommitAuthorityV1>
        where
            F: for<'path> FnMut(usize, &'path str, RetainedArtifactReadLimit, u64) -> Result<Vec<u8>>,
        {
            ensure!(previous.command == "prepare-campaign-precommit"
                && previous.campaign_root == campaign_root.to_str().context("campaign root is not UTF-8")?,
                "terminal replay prior request is not the selected precommit command");
            let mapped = map_previous_precommit_roots(previous, current_roots)?;
            let plan = plan(&mapped)?;
            let retained = retain_external_closure(campaign_root, current_roots, read, &plan)?;
            derive_terminal_authorities(&retained, build, previous, request_source,
                request_bytes, request_sha256).map(|(precommit, _verifier)| precommit)
        }

        /// Replay one immutable prior-request closure for the ancestry producer.
        /// Keep the distinct verifier authority that the negative-plan bytes
        /// require; the TH precommit envelope retains only its identity.
        #[allow(clippy::too_many_arguments)]
        pub(in crate::b4_campaign_executor) fn replay_authorities_for_negative_ancestry<const ROOTS: usize, F>(
            previous: &B4TrustedHostRequestV1,
            request_source: B4ExternalArtifactV1<'_>,
            campaign_root: &Path,
            current_roots: [&Path; ROOTS],
            build: &AuthoritativeB4BuildProjection,
            request_bytes: u64,
            request_sha256: &str,
            read: F,
        ) -> Result<(B4TrustedHostCampaignPrecommitAuthorityV1, B4VerifierContractAuthorityV1)>
        where
            F: for<'path> FnMut(usize, &'path str, RetainedArtifactReadLimit, u64) -> Result<Vec<u8>>,
        {
            ensure!(previous.command == "prepare-campaign-precommit"
                && previous.campaign_root == campaign_root.to_str().context("campaign root is not UTF-8")?,
                "ancestry replay prior request is not the selected precommit command");
            let mapped = map_previous_precommit_roots(previous, current_roots)?;
            let plan = plan(&mapped)?;
            let retained = retain_external_closure(campaign_root, current_roots, read, &plan)?;
            derive_terminal_authorities(&retained, build, previous, request_source,
                request_bytes, request_sha256)
        }

        #[cfg(test)]
        mod finalizer_replay_tests {
            use super::*;
            use eip_0045_reproduction::b4_campaign_contract::B4TrustedHostArtifactLocatorV1;
            use std::collections::BTreeMap;

            #[test]
            fn remaps_source_and_build_roots_without_padding_or_aliasing() {
                let mut sources = BTreeMap::new();
                sources.insert("inputSet".to_owned(), B4TrustedHostArtifactLocatorV1 {
                    root_index: 0, relative_path: "positive-input-set.json".to_owned(),
                });
                let previous = B4TrustedHostRequestV1 {
                    format: "Eip0045B4TrustedHostRequestV1".to_owned(), format_version: 1,
                    realization: "trusted-host-v1".to_owned(),
                    command: "prepare-campaign-precommit".to_owned(),
                    campaign_root: "/campaign".to_owned(),
                    prior_roots: vec!["/campaign/input".to_owned(), "/campaign/build".to_owned()],
                    outer_final_root: "/campaign/precommit".to_owned(),
                    configured_executor_artifact: "/campaign/executor".to_owned(),
                    build_evidence_root_index: 1, input_set_path: None, guest_elf_path: None,
                    proof_generator_path: None, input_set_request_byte_length: Some(1),
                    input_set_request_sha256: Some("a".repeat(64)), sources,
                };
                let mapped = map_previous_precommit_roots(&previous,
                    [Path::new("/campaign/build"), Path::new("/campaign/input")]).unwrap();
                assert_eq!(mapped.build_evidence_root_index, 0);
                assert_eq!(mapped.sources["inputSet"].root_index, 1);
                assert_eq!(mapped.prior_roots.len(), 2);
                assert_eq!(previous.build_evidence_root_index, 1);
                assert!(map_previous_precommit_roots(&previous,
                    [Path::new("/campaign/input")]).is_err());
            }
        }

        /// Affine live TH precommit; construction stays inside one retained execute session.
        struct TrustedHostPrecommit<'a, const ROOTS: usize> {
            execute: &'a mut ExecutorExecuteContext<ROOTS, ProjectedSingleSubtreeCampaignLayout<ROOTS>>,
            envelope: Vec<u8>,
            request_sha256: &'a str,
            completion_path: String,
            final_path: String,
        }

        impl<const ROOTS: usize> TrustedHostPrecommit<'_, ROOTS> {
            fn publish(self) -> Result<()> {
                let Self { execute, envelope, request_sha256, completion_path, final_path } = self;
                execute.with_mutation(|mutation| {
                    let mut transaction = mutation.begin_create_only_directory()?;
                    transaction.create_directory("trusted-host")?;
                    transaction.create_file("trusted-host/campaign-precommit.json", &envelope,
                        eip_0045_reproduction::b4_campaign_contract::MAX_CAMPAIGN_PRECOMMIT_BYTES + 4096)?;
                    transaction.commit_with_postcommit_validation(|committed| {
                        let reopened = committed.read_file("trusted-host/campaign-precommit.json",
                            eip_0045_reproduction::b4_campaign_contract::MAX_CAMPAIGN_PRECOMMIT_BYTES + 4096)?;
                        ensure!(reopened == envelope, "trusted-host precommit changed on reopen");
                        let parsed = Eip0045B4TrustedHostCampaignPrecommitV1::from_canonical_jcs(&reopened)?;
                        ensure!(parsed.request_sha256 == request_sha256
                            && parsed.completion.path == completion_path,
                            "trusted-host precommit lost request or completion binding");
                        B4ContractArtifactIdentityV1::from_bytes(&final_path,
                            B4ContractArtifactEncodingV1::Rfc8785Jcs, &reopened)?;
                        Ok(())
                    })
                })
            }
        }

        pub(in crate::b4_campaign_executor) fn handle<const ROOTS: usize>(request: &B4TrustedHostRequestV1,
            request_bytes: u64, request_sha256: &str, expectations: &B4BuildExpectations<'_>,
            preflight_only: bool) -> Result<()> {
            ensure!(request.command == "prepare-campaign-precommit" && request.prior_roots.len() == ROOTS,
                "trusted-host precommit command or root count drift");
            let campaign = Path::new(&request.campaign_root);
            let prior: [&Path; ROOTS] = std::array::from_fn(|i| Path::new(&request.prior_roots[i]));
            let final_root = Path::new(&request.outer_final_root);
            let plan = plan(request)?;
            let layout = project_single_subtree_campaign_layout(campaign, prior, final_root, "trusted-host")?;
            let preflight = ExecutorPreflightContext::capture(
                Path::new(&request.configured_executor_artifact), layout)?;
            let first = retain_external_closure(campaign, prior,
                |index, path, limit, remaining| read_retained_artifact!(preflight, index, path, limit, remaining),
                &plan)?;
            preflight.executable().require_artifact_identity(
                &first.parsed_campaign_executor_build_descriptor.artifact)?;
            let build = preflight.authenticate_authoritative_b4_build_projection(
                request.build_evidence_root_index, expectations)?;
            let expected = derive(&first, &build, request, request_bytes, request_sha256)?;
            if preflight_only { return preflight.finish_preflight(); }
            preflight.execute(|execute| {
                let retained = retain_external_closure(campaign, prior,
                    |index, path, limit, remaining| read_retained_artifact!(execute, index, path, limit, remaining),
                    &plan)?;
                execute.executable().require_artifact_identity(
                    &retained.parsed_campaign_executor_build_descriptor.artifact)?;
                let rebound = execute.authenticate_authoritative_b4_build_projection(
                    request.build_evidence_root_index, expectations)?;
                ensure!(rebound == build, "trusted-host build changed between preflight and execute");
                let envelope = derive(&retained, &rebound, request, request_bytes, request_sha256)?;
                ensure!(envelope == expected, "trusted-host precommit changed between preflight and execute");
                let completion_path = retained.input_set_completion.campaign_relative_path.clone();
                let final_path = derive_campaign_relative_artifact_path(campaign, final_root,
                    "trusted-host/campaign-precommit.json")?;
                TrustedHostPrecommit { execute, envelope, request_sha256,
                    completion_path, final_path }.publish()
            })
        }
    }

    #[cfg(test)]
    mod transition_tests {
        use std::path::Path;

        use anyhow::{Result, bail};
        use eip_0045_reproduction::{
            b4_campaign_contract::{
                B4_CAMPAIGN_EXECUTOR_COMMANDS, B4ContractArtifactEncodingV1,
                B4ContractArtifactIdentityV1, B4ReviewedSourceBindingV1,
                Eip0045B4CampaignExecutorBuildDescriptorV1,
            },
            b4_positive_input_set::{
                bind_b4_positive_input_set_publication_v2,
                derive_b4_positive_input_set_completion_jcs_v2,
                project_b4_positive_input_set_publication_paths_v2,
            },
        };

        use super::{
            MAX_EXECUTOR_ARTIFACT_BYTES, MAX_RETAINED_CLOSURE_BYTES, MAX_SOURCE_ARCHIVE_BYTES,
            MAX_VALIDATOR_ARTIFACT_BYTES, PrepareCampaignPrecommitArtifactLocatorV1,
            PrepareCampaignPrecommitCoordinator, PrepareCampaignPrecommitSourcePlanV1,
            PrepareCampaignPrecommitTransition, PrepareCampaignPrecommitTransitionObserver,
            RetainedArtifactReadLimit, RetainedByteBudget,
            execute_prepare_campaign_precommit_pipeline, retain_external_closure,
            validate_retained_h0_v2_publication,
        };
        use crate::b4_campaign_executor::custody::MAX_BUFFERED_IMMUTABLE_FILE_BYTES;

        #[derive(Default)]
        struct RecordingCoordinator {
            calls: Vec<PrepareCampaignPrecommitTransition>,
        }

        impl PrepareCampaignPrecommitCoordinator for RecordingCoordinator {
            type Retained = ();
            type Authority = ();
            type Published = ();

            fn retain_external_closure(&mut self) -> Result<Self::Retained> {
                self.calls
                    .push(PrepareCampaignPrecommitTransition::RetainExternalClosure);
                Ok(())
            }

            fn bind_executable_to_descriptor(&mut self, _retained: &Self::Retained) -> Result<()> {
                self.calls
                    .push(PrepareCampaignPrecommitTransition::BindExecutableToDescriptor);
                Ok(())
            }

            fn construct_authority(
                &mut self,
                _retained: Self::Retained,
            ) -> Result<Self::Authority> {
                self.calls
                    .push(PrepareCampaignPrecommitTransition::ConstructAuthority);
                Ok(())
            }

            fn rebind_executable_to_authority(
                &mut self,
                _authority: &Self::Authority,
            ) -> Result<()> {
                self.calls
                    .push(PrepareCampaignPrecommitTransition::RebindExecutableToAuthority);
                Ok(())
            }

            fn publish_and_reopen(
                &mut self,
                _authority: Self::Authority,
            ) -> Result<Self::Published> {
                self.calls
                    .push(PrepareCampaignPrecommitTransition::PublishAndReopen);
                Ok(())
            }

            fn final_executable_rebind(&mut self, _published: &Self::Published) -> Result<()> {
                self.calls
                    .push(PrepareCampaignPrecommitTransition::FinalExecutableRebind);
                Ok(())
            }
        }

        struct FailingObserver {
            fault: Option<PrepareCampaignPrecommitTransition>,
            completed: Vec<PrepareCampaignPrecommitTransition>,
        }

        impl PrepareCampaignPrecommitTransitionObserver for FailingObserver {
            fn before(&mut self, transition: PrepareCampaignPrecommitTransition) -> Result<()> {
                if self.fault == Some(transition) {
                    bail!("injected {transition:?} failure");
                }
                Ok(())
            }

            fn after(&mut self, transition: PrepareCampaignPrecommitTransition) {
                self.completed.push(transition);
            }
        }

        #[test]
        fn handler_transition_trace_is_exact_and_every_boundary_fails_closed() {
            let expected = [
                PrepareCampaignPrecommitTransition::RetainExternalClosure,
                PrepareCampaignPrecommitTransition::BindExecutableToDescriptor,
                PrepareCampaignPrecommitTransition::ConstructAuthority,
                PrepareCampaignPrecommitTransition::RebindExecutableToAuthority,
                PrepareCampaignPrecommitTransition::PublishAndReopen,
                PrepareCampaignPrecommitTransition::FinalExecutableRebind,
            ];
            let mut coordinator = RecordingCoordinator::default();
            let mut observer = FailingObserver {
                fault: None,
                completed: Vec::new(),
            };
            execute_prepare_campaign_precommit_pipeline(&mut coordinator, &mut observer).unwrap();
            assert_eq!(coordinator.calls, expected);
            assert_eq!(observer.completed, expected);

            for (index, fault) in expected.into_iter().enumerate() {
                let mut coordinator = RecordingCoordinator::default();
                let mut observer = FailingObserver {
                    fault: Some(fault),
                    completed: Vec::new(),
                };
                assert!(
                    execute_prepare_campaign_precommit_pipeline(&mut coordinator, &mut observer)
                        .is_err()
                );
                assert_eq!(coordinator.calls, expected[..index]);
                assert_eq!(observer.completed, expected[..index]);
            }
        }

        #[test]
        fn retained_closure_limits_match_custody_and_the_aggregate_budget_is_exact() {
            assert_eq!(
                MAX_EXECUTOR_ARTIFACT_BYTES,
                MAX_BUFFERED_IMMUTABLE_FILE_BYTES
            );
            assert_eq!(
                MAX_VALIDATOR_ARTIFACT_BYTES,
                MAX_BUFFERED_IMMUTABLE_FILE_BYTES
            );
            assert_eq!(MAX_SOURCE_ARCHIVE_BYTES, MAX_BUFFERED_IMMUTABLE_FILE_BYTES);
            assert_eq!(MAX_RETAINED_CLOSURE_BYTES, 1_073_741_824);
        }

        #[test]
        fn retained_closure_budget_accepts_the_bound_and_rejects_the_next_byte() {
            let mut budget = RetainedByteBudget::default();
            budget
                .add(usize::try_from(MAX_RETAINED_CLOSURE_BYTES).unwrap())
                .unwrap();
            assert_eq!(budget.remaining().unwrap(), 0);
            assert!(budget.validate_next(1).is_err());
            assert!(budget.add(1).is_err());
        }

        #[test]
        fn retained_closure_budget_rejects_cumulative_and_invalid_accounting() {
            let mut budget = RetainedByteBudget {
                retained_bytes: MAX_RETAINED_CLOSURE_BYTES - 7,
            };
            budget.validate_next(7).unwrap();
            assert!(budget.validate_next(8).is_err());
            budget.add(7).unwrap();
            assert!(budget.add(1).is_err());

            let invalid = RetainedByteBudget {
                retained_bytes: u64::MAX,
            };
            assert!(invalid.remaining().is_err());
        }

        #[test]
        fn retained_h0_completion_is_read_from_its_own_locator_and_validated_causally() {
            let input_set =
                br#"{"format":"Eip0045B4PositiveInputSetV2","formatVersion":2}"#.to_vec();
            let h0_paths =
                project_b4_positive_input_set_publication_paths_v2("h0/prepare-001").unwrap();
            let h0_binding =
                bind_b4_positive_input_set_publication_v2(&h0_paths, &input_set).unwrap();
            let completion = derive_b4_positive_input_set_completion_jcs_v2(&h0_binding).unwrap();
            assert_ne!(input_set, completion);

            let descriptor = Eip0045B4CampaignExecutorBuildDescriptorV1 {
                format: "Eip0045B4CampaignExecutorBuildDescriptorV1".to_owned(),
                format_version: 1,
                artifact: B4ContractArtifactIdentityV1::from_bytes(
                    "build/campaign-executor",
                    B4ContractArtifactEncodingV1::RawBytes,
                    b"executor",
                )
                .unwrap(),
                reviewed_source: B4ReviewedSourceBindingV1 {
                    repository: "https://github.com/ergoplatform/eips.git".to_owned(),
                    commit: "11".repeat(20),
                    tree: "22".repeat(20),
                    archive: B4ContractArtifactIdentityV1::from_bytes(
                        "build/campaign-executor-source.bundle",
                        B4ContractArtifactEncodingV1::GitBundle,
                        b"source",
                    )
                    .unwrap(),
                },
                executor_contract: B4ContractArtifactIdentityV1::from_bytes(
                    "build/executor-contract.json",
                    B4ContractArtifactEncodingV1::Rfc8785Jcs,
                    b"{}",
                )
                .unwrap(),
                commands: B4_CAMPAIGN_EXECUTOR_COMMANDS
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            }
            .to_canonical_jcs()
            .unwrap();

            let schema_paths = (0..20)
                .map(|index| format!("schema-{index}.json"))
                .collect::<Vec<_>>();
            let validator_descriptor_paths = ["validator-rust.json", "validator-jvm.json"];
            let validator_artifact_paths = ["validator-rust.bin", "validator-jvm.bin"];
            let validator_source_paths = ["validator-rust.bundle", "validator-jvm.bundle"];
            let runner_paths = [
                "runner-rust.json",
                "runner-jvm.json",
                "runner-rust-recursive.json",
                "runner-jvm-recursive.json",
            ];
            let seccomp_paths = [
                "seccomp-rust.json",
                "seccomp-jvm.json",
                "seccomp-rust-recursive.json",
                "seccomp-jvm-recursive.json",
            ];
            let plan = PrepareCampaignPrecommitSourcePlanV1 {
                input_set: PrepareCampaignPrecommitArtifactLocatorV1::new(
                    0,
                    "positive-input-set.json",
                ),
                input_set_completion: PrepareCampaignPrecommitArtifactLocatorV1::new(
                    0,
                    "positive-input-set-completion.json",
                ),
                build_evidence_root_index: 0,
                campaign_executor_artifact: PrepareCampaignPrecommitArtifactLocatorV1::new(
                    0,
                    "campaign-executor",
                ),
                campaign_executor_source_archive: PrepareCampaignPrecommitArtifactLocatorV1::new(
                    0,
                    "campaign-executor-source.bundle",
                ),
                campaign_executor_build_descriptor: PrepareCampaignPrecommitArtifactLocatorV1::new(
                    0,
                    "campaign-executor-build.json",
                ),
                executor_contract: PrepareCampaignPrecommitArtifactLocatorV1::new(
                    0,
                    "executor-contract.json",
                ),
                verifier_contract: PrepareCampaignPrecommitArtifactLocatorV1::new(
                    0,
                    "verifier-contract.json",
                ),
                verifier_cli_spec: PrepareCampaignPrecommitArtifactLocatorV1::new(
                    0,
                    "verifier-cli.md",
                ),
                negative_plan: PrepareCampaignPrecommitArtifactLocatorV1::new(
                    0,
                    "negative-plan.json",
                ),
                expectation_set: PrepareCampaignPrecommitArtifactLocatorV1::new(
                    0,
                    "expectation-set.json",
                ),
                verifier_schema_documents: std::array::from_fn(|index| {
                    PrepareCampaignPrecommitArtifactLocatorV1::new(0, &schema_paths[index])
                }),
                validator_build_descriptors: std::array::from_fn(|index| {
                    PrepareCampaignPrecommitArtifactLocatorV1::new(
                        0,
                        validator_descriptor_paths[index],
                    )
                }),
                validator_artifacts: std::array::from_fn(|index| {
                    PrepareCampaignPrecommitArtifactLocatorV1::new(
                        0,
                        validator_artifact_paths[index],
                    )
                }),
                validator_source_archives: std::array::from_fn(|index| {
                    PrepareCampaignPrecommitArtifactLocatorV1::new(0, validator_source_paths[index])
                }),
                runner_profiles: std::array::from_fn(|index| {
                    PrepareCampaignPrecommitArtifactLocatorV1::new(0, runner_paths[index])
                }),
                seccomp_documents: std::array::from_fn(|index| {
                    PrepareCampaignPrecommitArtifactLocatorV1::new(0, seccomp_paths[index])
                }),
                jvm_copy_only_inclusion_manifest: PrepareCampaignPrecommitArtifactLocatorV1::new(
                    0,
                    "jvm-inclusion.json",
                ),
            };
            let retained = retain_external_closure(
                Path::new("campaign"),
                [Path::new("campaign/h0/prepare-001")],
                |_, relative_path, limit, remaining| {
                    let bytes = match relative_path {
                        "campaign-executor-build.json" => descriptor.clone(),
                        "positive-input-set.json" => {
                            assert!(matches!(limit, RetainedArtifactReadLimit::PositiveInputSet));
                            input_set.clone()
                        }
                        "positive-input-set-completion.json" => {
                            assert!(matches!(
                                limit,
                                RetainedArtifactReadLimit::PositiveInputSetCompletion
                            ));
                            completion.clone()
                        }
                        _ => format!("sentinel:{relative_path}").into_bytes(),
                    };
                    assert!(u64::try_from(bytes.len()).unwrap() <= remaining);
                    Ok(bytes)
                },
                &plan,
            )
            .unwrap();

            assert_eq!(retained.input_set.bytes, input_set);
            assert_eq!(retained.input_set_completion.bytes, completion);
            let validated = validate_retained_h0_v2_publication(&retained).unwrap();
            assert_eq!(validated.completion_path(), h0_paths.completion_path());

            let mut wrong_role_bytes = retained;
            wrong_role_bytes.input_set_completion.bytes = wrong_role_bytes.input_set.bytes.clone();
            assert!(validate_retained_h0_v2_publication(&wrong_role_bytes).is_err());
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(
    unused_imports,
    reason = "the real handler is frozen before the E8 registry consumes it"
)]
pub(crate) use execute::{
    PrepareCampaignPrecommitArtifactLocatorV1, PrepareCampaignPrecommitBuildAnchorsV1,
    PrepareCampaignPrecommitExecuteInputsV1, PrepareCampaignPrecommitSourcePlanV1,
    PreparedCampaignPrecommitHandlerResultV1, execute_prepare_campaign_precommit_handler,
    preflight_prepare_campaign_precommit_handler,
};

#[cfg(all(target_os = "linux", feature = "b4-authoritative-build-custody"))]
pub(super) use execute::trusted_host::handle as handle_trusted_host_precommit;
#[cfg(all(target_os = "linux", feature = "b4-authoritative-build-custody"))]
pub(in crate::b4_campaign_executor) use execute::trusted_host::replay_for_finalizer as replay_trusted_host_precommit_for_finalizer;
#[cfg(all(target_os = "linux", feature = "b4-authoritative-build-custody"))]
pub(in crate::b4_campaign_executor) use execute::trusted_host::replay_authority_for_terminal as replay_trusted_host_precommit_for_terminal;
#[cfg(all(target_os = "linux", feature = "b4-authoritative-build-custody"))]
pub(in crate::b4_campaign_executor) use execute::trusted_host::replay_authorities_for_negative_ancestry as replay_trusted_host_authorities_for_negative_ancestry;
#[cfg(all(target_os = "linux", feature = "b4-authoritative-build-custody"))]
pub(in crate::b4_campaign_executor) use execute::RetainedArtifactReadLimit as PrecommitReadLimit;

#[cfg(test)]
mod source_shape_tests {
    const DATAFLOW_EDGES: &[(&str, usize)] = &[
        ("read_immutable_file_with_length_validation::<", 15),
        (
            "validate_retained_artifact_length(byte_length, $remaining)",
            15,
        ),
        ("budget.add(bytes.len())?;", 1),
        ("&plan.input_set_completion,", 1),
        ("&retained.input_set_completion.bytes,", 1),
        ("validate_b4_positive_input_set_completion_jcs_v2(", 1),
        ("validate_and_bind_positive_precommit_v2(", 1),
        ("B4CampaignPrecommitAuthorityV2::from_external_closure(", 1),
        (
            "let positive_input_set_completion = validate_retained_h0_v2_publication(retained)?;",
            1,
        ),
        ("Ok((positive_precommit, positive_input_set_completion))", 1),
        (
            "let (positive_precommit, positive_input_set_completion) =",
            1,
        ),
        ("retained.as_external(positive_input_set_completion)", 1),
        ("authenticate_campaign_precommit_file_v2(", 1),
        ("require_current_executable_binding_v2(", 2),
    ];

    fn production_source(source: &str) -> &str {
        source.split("#[cfg(test)]").next().unwrap()
    }

    fn production_dataflow_oracle(production: &str) -> bool {
        DATAFLOW_EDGES
            .iter()
            .all(|(edge, expected)| production.matches(edge).count() == *expected)
    }

    #[test]
    fn preflight_stops_before_authority_or_mutation_and_execute_uses_the_sole_constructor() {
        let source = include_str!("prepare_campaign_precommit.rs").replace("\r\n", "\n");
        let production = production_source(&source);
        let preflight = production
            .split("pub(crate) fn preflight_prepare_campaign_precommit_handler")
            .nth(1)
            .unwrap()
            .split("pub(crate) fn execute_prepare_campaign_precommit_handler")
            .next()
            .unwrap();
        assert!(!preflight.contains("from_external_closure"));
        assert!(!preflight.contains("with_mutation"));
        assert!(!preflight.contains("begin_create_only_directory"));
        assert_eq!(
            production
                .matches("B4CampaignPrecommitAuthorityV2::from_external_closure(")
                .count(),
            1
        );
        assert!(!production.contains("B4CampaignPrecommitAuthorityV1::from_external_closure("));
    }

    #[test]
    fn inputs_are_locator_only_and_publication_is_descriptor_reopened() {
        let source = include_str!("prepare_campaign_precommit.rs").replace("\r\n", "\n");
        let production = production_source(&source);
        let input_shape = production
            .split("pub(crate) struct PrepareCampaignPrecommitExecuteInputsV1")
            .nth(1)
            .unwrap()
            .split("impl<'authority")
            .next()
            .unwrap();
        assert!(!input_shape.contains("bytes:"));
        assert!(!input_shape.contains("B4PositiveGateAuthorityV1"));
        assert!(!input_shape.contains("B4PositivePrecommitAuthorityV2"));
        assert!(input_shape.contains("build_anchors: PrepareCampaignPrecommitBuildAnchorsV1"));
        for required in [
            "input_set_completion: PrepareCampaignPrecommitArtifactLocatorV1",
            "build_evidence_root_index: usize",
            "MAX_VALIDATOR_ARTIFACT_BYTES: usize = MAX_BUFFERED_IMMUTABLE_FILE_BYTES",
            "MAX_EXECUTOR_ARTIFACT_BYTES: usize = MAX_BUFFERED_IMMUTABLE_FILE_BYTES",
            "MAX_SOURCE_ARCHIVE_BYTES: usize = MAX_BUFFERED_IMMUTABLE_FILE_BYTES",
            "MAX_RETAINED_CLOSURE_BYTES: u64 = 1024 * 1024 * 1024",
            "validate_b4_positive_input_set_completion_jcs_v2(",
            "validate_and_bind_positive_precommit_v2(",
            "mutation.begin_create_only_directory()?",
            "transaction.create_directory(CONTRACTS_SUBTREE)?",
            "transaction.create_file(",
            "transaction.commit_with_postcommit_validation",
            ".read_file(CAMPAIGN_PRECOMMIT_FILE, MAX_CAMPAIGN_PRECOMMIT_BYTES)?",
            "authenticate_campaign_precommit_file_v2(",
        ] {
            assert!(
                production.contains(required),
                "missing production edge: {required}"
            );
        }
        assert!(production_dataflow_oracle(production));
    }

    #[test]
    fn production_dataflow_mutants_are_rejected_by_the_oracle() {
        let source = include_str!("prepare_campaign_precommit.rs").replace("\r\n", "\n");
        let production = production_source(&source);
        assert!(production_dataflow_oracle(production));
        assert!(!production.contains("positive_input_set_completion_path"));

        for (edge, _) in DATAFLOW_EDGES {
            let mutant = production.replacen(edge, "removed_dataflow_edge", 1);
            assert_ne!(mutant, production, "missing mutation target: {edge}");
            assert!(
                !production_dataflow_oracle(&mutant),
                "oracle accepted a removed production edge: {edge}"
            );
        }

        for (original, replacement) in [
            ("&plan.input_set_completion,", "&plan.input_set,"),
            (
                "&retained.input_set_completion.bytes,",
                "&retained.input_set.bytes,",
            ),
        ] {
            let mutant = production.replacen(original, replacement, 1);
            assert_ne!(
                mutant, production,
                "missing causal mutation target: {original}"
            );
            assert!(
                !production_dataflow_oracle(&mutant),
                "oracle accepted causal substitution: {original} -> {replacement}"
            );
        }
    }

    #[test]
    fn command_result_and_e8_boundaries_remain_closed() {
        let source = include_str!("prepare_campaign_precommit.rs").replace("\r\n", "\n");
        let production = production_source(&source);
        assert!(production.contains("const COMMAND: &str = \"prepare-campaign-precommit\";"));
        assert!(production.contains("env::args_os().collect::<Vec<_>>()"));
        assert!(production.contains("validate_b4_campaign_command_invocation("));
        assert!(production.contains("require_current_executable_binding_v2("));
        assert!(!production.contains("registry::"));
        assert!(!production.contains("cli::"));
        assert!(!production.contains("Command::PrepareCampaignPrecommit"));

        let result = production
            .split("pub(crate) struct PreparedCampaignPrecommitHandlerResultV1")
            .nth(1)
            .unwrap()
            .split("impl PreparedCampaignPrecommitHandlerResultV1")
            .next()
            .unwrap();
        assert!(result.contains("authority: B4CampaignPrecommitAuthorityV2"));
        assert!(!result.contains("pub authority"));
        assert!(!result.contains("derive("));
    }

    #[test]
    fn authoritative_build_custody_feature_is_shared_without_proving() {
        let manifest = include_str!("../../Cargo.toml").replace("\r\n", "\n");
        let shared = manifest
            .split("b4-authoritative-build-custody = [")
            .nth(1)
            .unwrap()
            .split("\n]")
            .next()
            .unwrap();
        assert!(shared.contains("eip-0045-reproduction/b4-descriptor-build-check"));
        for forbidden in ["embedded-method", "proof-generation", "risc0-zkvm/prove"] {
            assert!(!shared.contains(forbidden));
        }
        let campaign = manifest
            .split("b4-campaign-executor = [")
            .nth(1)
            .unwrap()
            .split("\n]")
            .next()
            .unwrap();
        assert!(campaign.contains("b4-authoritative-build-custody"));
    }
}
