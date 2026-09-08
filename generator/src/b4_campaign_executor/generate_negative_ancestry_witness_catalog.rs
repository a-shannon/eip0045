//! Real linked `generate-negative-ancestry-witness-catalog` production handler.

use std::path::Path;

use anyhow::{Context as _, Result};

use super::{
    preflight::{ProjectedSingleSubtreeCampaignLayout, project_single_subtree_campaign_layout},
    typestate::ExecutorPreflightContext,
};

const REPRODUCTION_SUBTREE: &str = "reproduction";

fn project_generate_negative_ancestry_witness_catalog_layout<const ROOTS: usize>(
    campaign_root: &Path,
    prior_roots: [&Path; ROOTS],
    outer_final_root: &Path,
) -> Result<ProjectedSingleSubtreeCampaignLayout<ROOTS>> {
    project_single_subtree_campaign_layout(
        campaign_root,
        prior_roots,
        outer_final_root,
        REPRODUCTION_SUBTREE,
    )
    .context("cannot project generate-negative-ancestry-witness-catalog campaign layout")
}

#[cfg(target_os = "linux")]
mod execute {
    use std::{env, ffi::OsString, os::fd::BorrowedFd, path::Path};

    use anyhow::{Context as _, Result, ensure};
    use eip_0045_reproduction::{
        b4_campaign_contract::{
            B4CampaignPrecommitAuthorityV1, B4PositiveGenerationAuthorityV2,
            MAX_CAMPAIGN_PRECOMMIT_BYTES, validate_b4_campaign_command_invocation,
        },
        b4_negative_ancestry_authority::{
            B4NegativeAncestrySourceAuthorityV1, B4NegativeAncestrySourceAuthorityV2,
            B4NegativeAncestryWitnessCatalogAuthorityV1,
            B4NegativeAncestryWitnessCatalogAuthorityV2,
        },
        b4_negative_ancestry_publication::{
            materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor,
            materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor_v2,
            validate_published_b4_negative_ancestry_witness_catalog_from_directory_descriptor,
            validate_published_b4_negative_ancestry_witness_catalog_from_directory_descriptor_v2,
        },
        b4_positive_gate::B4PositiveGenerationAuthorityV1,
    };
    use risc0_zkvm::LocalProver;

    use crate::{
        b4_campaign_executor::authenticated_preflight::{
            authenticate_campaign_precommit_file, derive_campaign_relative_artifact_path,
            require_current_executable_binding,
        },
        locked_negative_ancestry_guest::{
            require_locked_negative_ancestry_source, require_locked_negative_ancestry_source_v2,
        },
        recursive::{
            prove_and_finalize_b4_negative_ancestry_witness_catalog,
            prove_and_finalize_b4_negative_ancestry_witness_catalog_v2,
        },
    };

    use super::{
        ExecutorPreflightContext, ProjectedSingleSubtreeCampaignLayout, REPRODUCTION_SUBTREE,
        project_generate_negative_ancestry_witness_catalog_layout,
    };

    const COMMAND: &str = "generate-negative-ancestry-witness-catalog";

    /// Typed inputs reconstructed before the execute-only production branch.
    pub(crate) struct GenerateNegativeAncestryWitnessCatalogExecuteInputsV1<
        'authority,
        const ROOTS: usize,
    > {
        configured_executor_artifact: &'authority Path,
        campaign_root: &'authority Path,
        prior_roots: [&'authority Path; ROOTS],
        outer_final_root: &'authority Path,
        campaign_precommit_root_index: usize,
        campaign_precommit_root_relative_path: &'authority str,
        campaign: &'authority B4CampaignPrecommitAuthorityV1,
        positive: &'authority B4PositiveGenerationAuthorityV1,
        source: B4NegativeAncestrySourceAuthorityV1,
    }

    impl<'authority, const ROOTS: usize>
        GenerateNegativeAncestryWitnessCatalogExecuteInputsV1<'authority, ROOTS>
    {
        #[allow(
            clippy::too_many_arguments,
            reason = "the handler retains every independently reconstructed authority and root explicitly"
        )]
        pub(crate) const fn new(
            configured_executor_artifact: &'authority Path,
            campaign_root: &'authority Path,
            prior_roots: [&'authority Path; ROOTS],
            outer_final_root: &'authority Path,
            campaign_precommit_root_index: usize,
            campaign_precommit_root_relative_path: &'authority str,
            campaign: &'authority B4CampaignPrecommitAuthorityV1,
            positive: &'authority B4PositiveGenerationAuthorityV1,
            source: B4NegativeAncestrySourceAuthorityV1,
        ) -> Self {
            Self {
                configured_executor_artifact,
                campaign_root,
                prior_roots,
                outer_final_root,
                campaign_precommit_root_index,
                campaign_precommit_root_relative_path,
                campaign,
                positive,
                source,
            }
        }
    }

    /// Private complete result retained only after descriptor-rooted reopen.
    pub(crate) struct PublishedNegativeAncestryCatalogHandlerResultV1 {
        _authority: B4NegativeAncestryWitnessCatalogAuthorityV1,
    }

    /// Typed V2 inputs reconstructed before the execute-only production branch.
    pub(crate) struct GenerateNegativeAncestryWitnessCatalogExecuteInputsV2<
        'authority,
        const ROOTS: usize,
    > {
        configured_executor_artifact: &'authority Path,
        campaign_root: &'authority Path,
        prior_roots: [&'authority Path; ROOTS],
        outer_final_root: &'authority Path,
        campaign_precommit_root_index: usize,
        campaign_precommit_root_relative_path: &'authority str,
        campaign: &'authority B4CampaignPrecommitAuthorityV1,
        positive: &'authority B4PositiveGenerationAuthorityV2,
        source: B4NegativeAncestrySourceAuthorityV2,
    }

    impl<'authority, const ROOTS: usize>
        GenerateNegativeAncestryWitnessCatalogExecuteInputsV2<'authority, ROOTS>
    {
        #[allow(
            clippy::too_many_arguments,
            reason = "the V2 handler retains every authority and descriptor root explicitly"
        )]
        pub(crate) const fn new(
            configured_executor_artifact: &'authority Path,
            campaign_root: &'authority Path,
            prior_roots: [&'authority Path; ROOTS],
            outer_final_root: &'authority Path,
            campaign_precommit_root_index: usize,
            campaign_precommit_root_relative_path: &'authority str,
            campaign: &'authority B4CampaignPrecommitAuthorityV1,
            positive: &'authority B4PositiveGenerationAuthorityV2,
            source: B4NegativeAncestrySourceAuthorityV2,
        ) -> Self {
            Self {
                configured_executor_artifact,
                campaign_root,
                prior_roots,
                outer_final_root,
                campaign_precommit_root_index,
                campaign_precommit_root_relative_path,
                campaign,
                positive,
                source,
            }
        }
    }

    /// Private V2 result retained only after descriptor-rooted reopen.
    pub(crate) struct PublishedNegativeAncestryCatalogHandlerResultV2 {
        _authority: B4NegativeAncestryWitnessCatalogAuthorityV2,
    }

    struct CapturedExecuteInvocation {
        process_argv: Vec<OsString>,
        parsed_preflight_only: bool,
    }

    impl CapturedExecuteInvocation {
        fn capture(parsed_preflight_only: bool) -> Result<Self> {
            ensure!(
                env::var_os("RISC0_DEV_MODE").is_none(),
                "RISC0_DEV_MODE must be absent before negative-ancestry proof work"
            );
            let process_argv = env::args_os().collect::<Vec<_>>();
            validate_b4_campaign_command_invocation(&process_argv, COMMAND, parsed_preflight_only)
                .context(
                    "invalid retained generate-negative-ancestry-witness-catalog invocation argv",
                )?;
            Ok(Self {
                process_argv,
                parsed_preflight_only,
            })
        }

        fn revalidate(&self) -> Result<()> {
            ensure!(
                env::var_os("RISC0_DEV_MODE").is_none(),
                "RISC0_DEV_MODE appeared after negative-ancestry preflight"
            );
            validate_b4_campaign_command_invocation(
                &self.process_argv,
                COMMAND,
                self.parsed_preflight_only,
            )
            .context("retained negative-ancestry invocation changed")
        }
    }

    type NegativeAncestryPreflightContext<const ROOTS: usize> =
        ExecutorPreflightContext<ROOTS, ProjectedSingleSubtreeCampaignLayout<ROOTS>>;

    struct AuthenticatedNegativeAncestryPreflightV1<const ROOTS: usize> {
        preflight: NegativeAncestryPreflightContext<ROOTS>,
        invocation: CapturedExecuteInvocation,
    }

    struct AuthenticatedNegativeAncestryPreflightV2<const ROOTS: usize> {
        preflight: NegativeAncestryPreflightContext<ROOTS>,
        invocation: CapturedExecuteInvocation,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum GenerateNegativeAncestryTransition {
        ProveAndFinalize,
        BeginOuterStaging,
        DescriptorRootedMaterialization,
        OuterCommitAndPostcommitValidation,
    }

    trait GenerateNegativeAncestryTransitionObserver {
        fn before(&mut self, transition: GenerateNegativeAncestryTransition) -> Result<()>;
    }

    struct NoopGenerateNegativeAncestryTransitionObserver;

    impl GenerateNegativeAncestryTransitionObserver for NoopGenerateNegativeAncestryTransitionObserver {
        fn before(&mut self, _transition: GenerateNegativeAncestryTransition) -> Result<()> {
            Ok(())
        }
    }

    fn coordinate_generate_negative_ancestry<State, Prepared, Output>(
        state: &mut State,
        observer: &mut impl GenerateNegativeAncestryTransitionObserver,
        prove_and_finalize: impl FnOnce(&mut State) -> Result<Prepared>,
        mutate: impl FnOnce(
            &mut State,
            Prepared,
            &mut dyn GenerateNegativeAncestryTransitionObserver,
        ) -> Result<Output>,
    ) -> Result<Output> {
        observer.before(GenerateNegativeAncestryTransition::ProveAndFinalize)?;
        let prepared = prove_and_finalize(state)?;
        mutate(state, prepared, observer)
    }

    fn coordinate_generate_negative_ancestry_mutation<Transaction, Prepared, Published, Output>(
        observer: &mut dyn GenerateNegativeAncestryTransitionObserver,
        prepared: Prepared,
        begin_outer_staging: impl FnOnce() -> Result<Transaction>,
        materialize: impl FnOnce(&mut Transaction, Prepared) -> Result<Published>,
        commit_and_validate: impl FnOnce(Transaction, Published) -> Result<Output>,
    ) -> Result<Output> {
        observer.before(GenerateNegativeAncestryTransition::BeginOuterStaging)?;
        let mut transaction = begin_outer_staging()?;
        observer.before(GenerateNegativeAncestryTransition::DescriptorRootedMaterialization)?;
        let published = materialize(&mut transaction, prepared)?;
        observer.before(GenerateNegativeAncestryTransition::OuterCommitAndPostcommitValidation)?;
        commit_and_validate(transaction, published)
    }

    /// Consume the real affine executor and descriptor-rooted transaction kernel.
    ///
    /// Production supplies only its fixed linked producer, materializer, and
    /// postcommit authority predicates. The test-only seam below supplies
    /// fixtures to this same private kernel; it cannot construct or export a
    /// production handler input.
    fn execute_descriptor_rooted_negative_ancestry_pipeline<
        const ROOTS: usize,
        Prepared,
        Output,
    >(
        preflight: NegativeAncestryPreflightContext<ROOTS>,
        observer: &mut impl GenerateNegativeAncestryTransitionObserver,
        rebind_before_execute: impl FnOnce() -> Result<()>,
        prove_and_finalize: impl FnOnce() -> Result<Prepared>,
        materialize: impl for<'descriptor> FnOnce(BorrowedFd<'descriptor>, &Prepared) -> Result<()>,
        validate_and_rebind_postcommit: impl for<'descriptor> FnOnce(
            BorrowedFd<'descriptor>,
            Prepared,
        ) -> Result<Output>,
    ) -> Result<Output> {
        rebind_before_execute()?;
        preflight.execute(move |execute| {
            coordinate_generate_negative_ancestry(
                execute,
                observer,
                |execute| execute.with_proof(|_capability| prove_and_finalize()),
                |execute, authority, observer| {
                    execute.with_mutation(move |capability| {
                        coordinate_generate_negative_ancestry_mutation(
                            observer,
                            authority,
                            || capability.begin_create_only_directory(),
                            |transaction, authority| {
                                transaction.publish_and_adopt_directory_tree(
                                    REPRODUCTION_SUBTREE,
                                    |root| materialize(root, &authority),
                                )?;
                                Ok(authority)
                            },
                            |transaction, authority| {
                                transaction.commit_with_postcommit_validation(move |committed| {
                                    validate_and_rebind_postcommit(
                                        committed.root_directory_descriptor()?,
                                        authority,
                                    )
                                })
                            },
                        )
                    })
                },
            )
        })
    }

    fn authenticate_generate_negative_ancestry_preflight<const ROOTS: usize>(
        inputs: &GenerateNegativeAncestryWitnessCatalogExecuteInputsV1<'_, ROOTS>,
        parsed_preflight_only: bool,
    ) -> Result<AuthenticatedNegativeAncestryPreflightV1<ROOTS>> {
        let projected = project_generate_negative_ancestry_witness_catalog_layout(
            inputs.campaign_root,
            inputs.prior_roots,
            inputs.outer_final_root,
        )?;
        let preflight =
            ExecutorPreflightContext::capture(inputs.configured_executor_artifact, projected)
                .context("generate-negative-ancestry-witness-catalog retained preflight failed")?;
        let campaign_precommit_root = *inputs
            .prior_roots
            .get(inputs.campaign_precommit_root_index)
            .context("campaign-precommit root index is outside the retained prior-root set")?;
        let campaign_precommit_identity_path = derive_campaign_relative_artifact_path(
            inputs.campaign_root,
            campaign_precommit_root,
            inputs.campaign_precommit_root_relative_path,
        )?;
        let campaign_precommit_bytes = preflight
            .read_immutable_file::<MAX_CAMPAIGN_PRECOMMIT_BYTES>(
                inputs.campaign_precommit_root_index,
                inputs.campaign_precommit_root_relative_path,
            )
            .context("cannot read the campaign precommit under immutable-root custody")?;
        authenticate_campaign_precommit_file(
            &campaign_precommit_identity_path,
            inputs.campaign,
            &campaign_precommit_bytes,
        )?;
        let invocation = CapturedExecuteInvocation::capture(parsed_preflight_only)?;
        inputs
            .source
            .verify_authority_bindings(inputs.campaign, inputs.positive)
            .context("negative-ancestry source differs from execute authorities")?;
        require_locked_negative_ancestry_source(&inputs.source)
            .context("negative-ancestry source does not use the locked alternate guest")?;
        require_current_executable_binding(preflight.executable(), inputs.campaign)?;
        invocation.revalidate()?;
        Ok(AuthenticatedNegativeAncestryPreflightV1 {
            preflight,
            invocation,
        })
    }

    /// Reach the exact zero-effect production boundary for global preflight mode.
    pub(crate) fn preflight_generate_negative_ancestry_witness_catalog_handler<
        const ROOTS: usize,
    >(
        inputs: &GenerateNegativeAncestryWitnessCatalogExecuteInputsV1<'_, ROOTS>,
    ) -> Result<()> {
        let authenticated = authenticate_generate_negative_ancestry_preflight(inputs, true)?;
        authenticated.invocation.revalidate()?;
        authenticated
            .preflight
            .finish_preflight()
            .context("generate-negative-ancestry-witness-catalog authenticated preflight failed")
    }

    /// Execute the real linked producer and descriptor-rooted create-only publication.
    #[allow(
        clippy::too_many_lines,
        reason = "the security-sensitive proof/publication/commit order remains one audit unit"
    )]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "execute mode consumes the owned opaque source authority instead of accepting reusable caller state"
    )]
    pub(crate) fn execute_generate_negative_ancestry_witness_catalog_handler<const ROOTS: usize>(
        inputs: GenerateNegativeAncestryWitnessCatalogExecuteInputsV1<'_, ROOTS>,
    ) -> Result<PublishedNegativeAncestryCatalogHandlerResultV1> {
        let AuthenticatedNegativeAncestryPreflightV1 {
            preflight,
            invocation,
        } = authenticate_generate_negative_ancestry_preflight(&inputs, false)?;
        let source_authority = &inputs.source;
        let campaign_authority = inputs.campaign;
        let positive_authority = inputs.positive;
        let retained_invocation = &invocation;
        let mut observer = NoopGenerateNegativeAncestryTransitionObserver;

        execute_descriptor_rooted_negative_ancestry_pipeline(
            preflight,
            &mut observer,
            || {
                retained_invocation.revalidate()?;
                source_authority
                    .verify_authority_bindings(campaign_authority, positive_authority)
                    .context("negative-ancestry source changed after authenticated preflight")?;
                require_locked_negative_ancestry_source(source_authority).context(
                    "negative-ancestry source lost its locked alternate guest after preflight",
                )
            },
            || {
                retained_invocation.revalidate()?;
                let prover = LocalProver::new("eip-0045-b4-generate-negative-ancestry-catalog");
                prove_and_finalize_b4_negative_ancestry_witness_catalog(&prover, source_authority)
            },
            |root, authority| {
                materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor(
                    root, authority,
                )
            },
            |root, authority| {
                validate_published_b4_negative_ancestry_witness_catalog_from_directory_descriptor(
                    root, &authority,
                )
                .context("cannot semantically reopen committed negative-ancestry catalogue")?;
                source_authority
                    .verify_authority_bindings(campaign_authority, positive_authority)
                    .context(
                        "postcommit negative-ancestry source differs from execute authorities",
                    )?;
                require_locked_negative_ancestry_source(source_authority).context(
                    "postcommit negative-ancestry source no longer uses the locked alternate guest",
                )?;
                retained_invocation.revalidate()?;
                Ok(PublishedNegativeAncestryCatalogHandlerResultV1 {
                    _authority: authority,
                })
            },
        )
    }

    fn authenticate_generate_negative_ancestry_preflight_v2<const ROOTS: usize>(
        inputs: &GenerateNegativeAncestryWitnessCatalogExecuteInputsV2<'_, ROOTS>,
        parsed_preflight_only: bool,
    ) -> Result<AuthenticatedNegativeAncestryPreflightV2<ROOTS>> {
        let projected = project_generate_negative_ancestry_witness_catalog_layout(
            inputs.campaign_root,
            inputs.prior_roots,
            inputs.outer_final_root,
        )?;
        let preflight =
            ExecutorPreflightContext::capture(inputs.configured_executor_artifact, projected)
                .context("V2 generate-negative-ancestry retained preflight failed")?;
        let campaign_precommit_root = *inputs
            .prior_roots
            .get(inputs.campaign_precommit_root_index)
            .context("V2 campaign-precommit root index is outside the retained roots")?;
        let campaign_precommit_identity_path = derive_campaign_relative_artifact_path(
            inputs.campaign_root,
            campaign_precommit_root,
            inputs.campaign_precommit_root_relative_path,
        )?;
        let campaign_precommit_bytes = preflight
            .read_immutable_file::<MAX_CAMPAIGN_PRECOMMIT_BYTES>(
                inputs.campaign_precommit_root_index,
                inputs.campaign_precommit_root_relative_path,
            )
            .context("cannot read the V2 campaign precommit under immutable-root custody")?;
        authenticate_campaign_precommit_file(
            &campaign_precommit_identity_path,
            inputs.campaign,
            &campaign_precommit_bytes,
        )?;
        let invocation = CapturedExecuteInvocation::capture(parsed_preflight_only)?;
        inputs
            .source
            .verify_authority_bindings(inputs.campaign, inputs.positive)
            .context("V2 negative-ancestry source differs from execute authorities")?;
        require_locked_negative_ancestry_source_v2(&inputs.source)
            .context("V2 negative-ancestry source does not use the locked guests")?;
        require_current_executable_binding(preflight.executable(), inputs.campaign)?;
        invocation.revalidate()?;
        Ok(AuthenticatedNegativeAncestryPreflightV2 {
            preflight,
            invocation,
        })
    }

    /// Reach the exact zero-effect V2 production boundary for global preflight mode.
    pub(crate) fn preflight_generate_negative_ancestry_witness_catalog_handler_v2<
        const ROOTS: usize,
    >(
        inputs: &GenerateNegativeAncestryWitnessCatalogExecuteInputsV2<'_, ROOTS>,
    ) -> Result<()> {
        let authenticated = authenticate_generate_negative_ancestry_preflight_v2(inputs, true)?;
        authenticated.invocation.revalidate()?;
        authenticated
            .preflight
            .finish_preflight()
            .context("V2 generate-negative-ancestry authenticated preflight failed")
    }

    /// Execute the V2 producer and descriptor-rooted create-only publication.
    #[allow(
        clippy::too_many_lines,
        reason = "the V2 proof/publication/commit/reopen order remains one audit unit"
    )]
    #[allow(
        clippy::needless_pass_by_value,
        reason = "execute mode consumes the affine V2 source authority"
    )]
    pub(crate) fn execute_generate_negative_ancestry_witness_catalog_handler_v2<
        const ROOTS: usize,
    >(
        inputs: GenerateNegativeAncestryWitnessCatalogExecuteInputsV2<'_, ROOTS>,
    ) -> Result<PublishedNegativeAncestryCatalogHandlerResultV2> {
        let AuthenticatedNegativeAncestryPreflightV2 {
            preflight,
            invocation,
        } = authenticate_generate_negative_ancestry_preflight_v2(&inputs, false)?;
        let source_authority = &inputs.source;
        let campaign_authority = inputs.campaign;
        let positive_authority = inputs.positive;
        let retained_invocation = &invocation;
        let mut observer = NoopGenerateNegativeAncestryTransitionObserver;

        execute_descriptor_rooted_negative_ancestry_pipeline(
            preflight,
            &mut observer,
            || {
                retained_invocation.revalidate()?;
                source_authority
                    .verify_authority_bindings(campaign_authority, positive_authority)
                    .context("V2 ancestry source changed after authenticated preflight")?;
                require_locked_negative_ancestry_source_v2(source_authority)
                    .context("V2 ancestry source lost its locked guests after preflight")
            },
            || {
                retained_invocation.revalidate()?;
                let prover = LocalProver::new("eip-0045-b4-generate-negative-ancestry-catalog-v2");
                prove_and_finalize_b4_negative_ancestry_witness_catalog_v2(
                    &prover,
                    source_authority,
                )
            },
            |root, authority| {
                materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor_v2(
                    root, authority,
                )
            },
            |root, authority| {
                validate_published_b4_negative_ancestry_witness_catalog_from_directory_descriptor_v2(
                    root, &authority,
                )
                .context("cannot reopen the committed V2 negative-ancestry catalogue")?;
                authority
                    .verify_prior_authority_lineage(campaign_authority, positive_authority)
                    .context("reopened V2 catalogue differs from its prior authorities")?;
                source_authority
                    .verify_authority_bindings(campaign_authority, positive_authority)
                    .context("postcommit V2 ancestry source differs from execute authorities")?;
                require_locked_negative_ancestry_source_v2(source_authority)
                    .context("postcommit V2 ancestry source no longer uses the locked guests")?;
                retained_invocation.revalidate()?;
                Ok(PublishedNegativeAncestryCatalogHandlerResultV2 {
                    _authority: authority,
                })
            },
        )
    }

    #[cfg(test)]
    mod transition_tests {
        use std::{
            cell::RefCell,
            fs::{self, File},
            io::{Read as _, Write as _},
            os::fd::{AsFd as _, BorrowedFd},
            rc::Rc,
        };

        use anyhow::{Context as _, Result, ensure};

        use super::{
            ExecutorPreflightContext, GenerateNegativeAncestryTransition,
            GenerateNegativeAncestryTransitionObserver, REPRODUCTION_SUBTREE,
            coordinate_generate_negative_ancestry, coordinate_generate_negative_ancestry_mutation,
            execute_descriptor_rooted_negative_ancestry_pipeline,
            project_generate_negative_ancestry_witness_catalog_layout,
        };

        const ORDER: [GenerateNegativeAncestryTransition; 4] = [
            GenerateNegativeAncestryTransition::ProveAndFinalize,
            GenerateNegativeAncestryTransition::BeginOuterStaging,
            GenerateNegativeAncestryTransition::DescriptorRootedMaterialization,
            GenerateNegativeAncestryTransition::OuterCommitAndPostcommitValidation,
        ];

        struct Recorder {
            events: Vec<GenerateNegativeAncestryTransition>,
            fail_before: Option<GenerateNegativeAncestryTransition>,
        }

        impl GenerateNegativeAncestryTransitionObserver for Recorder {
            fn before(&mut self, transition: GenerateNegativeAncestryTransition) -> Result<()> {
                self.events.push(transition);
                if self.fail_before == Some(transition) {
                    anyhow::bail!("injected transition failure before {transition:?}");
                }
                Ok(())
            }
        }

        struct DropWitness(Rc<std::cell::Cell<usize>>);

        impl Drop for DropWitness {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum TestSeamFault {
            None,
            PreExecuteRebind,
            ProofFinalization,
            DescriptorMaterialization,
            DescriptorValidation,
            PostcommitRebind,
        }

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum TestSeamOperation {
            PreExecuteRebind,
            ProofFinalization,
            DescriptorMaterialization,
            DescriptorValidation,
            PostcommitRebind,
        }

        const TEST_CATALOG_FILE: &str = "catalog.jcs";
        const TEST_CATALOG_BYTES: &[u8] = br#"{"fixture":"descriptor-rooted-e3"}"#;

        fn materialize_test_catalog_from_descriptor(
            root: BorrowedFd<'_>,
            bytes: &[u8],
        ) -> Result<()> {
            let directory_mode = rustix::fs::Mode::RWXU;
            let file_mode = rustix::fs::Mode::RUSR.union(rustix::fs::Mode::WUSR);
            let resolve = rustix::fs::ResolveFlags::BENEATH
                .union(rustix::fs::ResolveFlags::NO_SYMLINKS)
                .union(rustix::fs::ResolveFlags::NO_MAGICLINKS)
                .union(rustix::fs::ResolveFlags::NO_XDEV);
            rustix::fs::mkdirat(root, REPRODUCTION_SUBTREE, directory_mode)
                .context("test seam cannot create the reproduction subtree")?;
            let subtree = rustix::fs::openat2(
                root,
                REPRODUCTION_SUBTREE,
                rustix::fs::OFlags::RDONLY
                    .union(rustix::fs::OFlags::DIRECTORY)
                    .union(rustix::fs::OFlags::NOFOLLOW)
                    .union(rustix::fs::OFlags::CLOEXEC),
                rustix::fs::Mode::empty(),
                resolve,
            )
            .context("test seam cannot retain the reproduction subtree")?;
            let descriptor = rustix::fs::openat2(
                subtree.as_fd(),
                TEST_CATALOG_FILE,
                rustix::fs::OFlags::WRONLY
                    .union(rustix::fs::OFlags::CREATE)
                    .union(rustix::fs::OFlags::EXCL)
                    .union(rustix::fs::OFlags::NOFOLLOW)
                    .union(rustix::fs::OFlags::CLOEXEC),
                file_mode,
                resolve,
            )
            .context("test seam cannot create the catalogue fixture")?;
            let mut file = File::from(descriptor);
            file.write_all(bytes)
                .context("test seam cannot write the catalogue fixture")?;
            file.sync_all()
                .context("test seam cannot synchronize the catalogue fixture")?;
            rustix::fs::fsync(subtree.as_fd())
                .context("test seam cannot synchronize the reproduction subtree")?;
            rustix::fs::fsync(root).context("test seam cannot synchronize the staging root")
        }

        fn reopen_test_catalog_from_descriptor(root: BorrowedFd<'_>) -> Result<Vec<u8>> {
            let resolve = rustix::fs::ResolveFlags::BENEATH
                .union(rustix::fs::ResolveFlags::NO_SYMLINKS)
                .union(rustix::fs::ResolveFlags::NO_MAGICLINKS)
                .union(rustix::fs::ResolveFlags::NO_XDEV);
            let subtree = rustix::fs::openat2(
                root,
                REPRODUCTION_SUBTREE,
                rustix::fs::OFlags::RDONLY
                    .union(rustix::fs::OFlags::DIRECTORY)
                    .union(rustix::fs::OFlags::NOFOLLOW)
                    .union(rustix::fs::OFlags::CLOEXEC),
                rustix::fs::Mode::empty(),
                resolve,
            )
            .context("test seam cannot reopen the reproduction subtree")?;
            let descriptor = rustix::fs::openat2(
                subtree.as_fd(),
                TEST_CATALOG_FILE,
                rustix::fs::OFlags::RDONLY
                    .union(rustix::fs::OFlags::NOFOLLOW)
                    .union(rustix::fs::OFlags::NONBLOCK)
                    .union(rustix::fs::OFlags::CLOEXEC),
                rustix::fs::Mode::empty(),
                resolve,
            )
            .context("test seam cannot reopen the catalogue fixture")?;
            let mut bytes = Vec::new();
            File::from(descriptor)
                .take(1025)
                .read_to_end(&mut bytes)
                .context("test seam cannot read the catalogue fixture")?;
            ensure!(
                bytes.len() <= 1024,
                "test seam catalogue fixture exceeds its fixed bound"
            );
            Ok(bytes)
        }

        #[allow(
            clippy::too_many_lines,
            reason = "one test-only seam closes success and every domain callback failure around the real affine transaction"
        )]
        fn execute_descriptor_rooted_negative_ancestry_test_seam() {
            let cases = [
                TestSeamFault::None,
                TestSeamFault::PreExecuteRebind,
                TestSeamFault::ProofFinalization,
                TestSeamFault::DescriptorMaterialization,
                TestSeamFault::DescriptorValidation,
                TestSeamFault::PostcommitRebind,
            ];

            for fault in cases {
                let temp = tempfile::tempdir().unwrap();
                let campaign = temp.path().join("campaign");
                let prior = campaign.join("prior");
                let outer_parent = campaign.join("runs");
                let outer = outer_parent.join("negative-ancestry");
                fs::create_dir_all(&prior).unwrap();
                fs::create_dir_all(&outer_parent).unwrap();

                let projected = project_generate_negative_ancestry_witness_catalog_layout(
                    &campaign,
                    [&prior],
                    &outer,
                )
                .unwrap();
                let staging = projected.outer_staging_root().to_path_buf();
                let preflight =
                    ExecutorPreflightContext::capture(&std::env::current_exe().unwrap(), projected)
                        .unwrap();
                let operations = Rc::new(RefCell::new(Vec::new()));
                let mut observer = Recorder {
                    events: Vec::new(),
                    fail_before: None,
                };

                let before_operations = Rc::clone(&operations);
                let proof_operations = Rc::clone(&operations);
                let materialize_operations = Rc::clone(&operations);
                let validate_operations = Rc::clone(&operations);
                let result = execute_descriptor_rooted_negative_ancestry_pipeline(
                    preflight,
                    &mut observer,
                    move || {
                        before_operations
                            .borrow_mut()
                            .push(TestSeamOperation::PreExecuteRebind);
                        if fault == TestSeamFault::PreExecuteRebind {
                            anyhow::bail!("injected pre-execute authority rebind failure");
                        }
                        Ok(())
                    },
                    move || {
                        proof_operations
                            .borrow_mut()
                            .push(TestSeamOperation::ProofFinalization);
                        if fault == TestSeamFault::ProofFinalization {
                            anyhow::bail!("injected proof finalization failure");
                        }
                        Ok(TEST_CATALOG_BYTES.to_vec())
                    },
                    move |root, authority| {
                        materialize_operations
                            .borrow_mut()
                            .push(TestSeamOperation::DescriptorMaterialization);
                        materialize_test_catalog_from_descriptor(root, authority)?;
                        if fault == TestSeamFault::DescriptorMaterialization {
                            anyhow::bail!("injected descriptor materialization failure");
                        }
                        Ok(())
                    },
                    move |root, authority| {
                        validate_operations
                            .borrow_mut()
                            .push(TestSeamOperation::DescriptorValidation);
                        let reopened = reopen_test_catalog_from_descriptor(root)?;
                        if fault == TestSeamFault::DescriptorValidation {
                            ensure!(
                                reopened == b"isolated semantic mismatch",
                                "injected descriptor semantic validation failure"
                            );
                        }
                        ensure!(
                            reopened == authority,
                            "descriptor-reopened catalogue differs from proof authority"
                        );
                        validate_operations
                            .borrow_mut()
                            .push(TestSeamOperation::PostcommitRebind);
                        if fault == TestSeamFault::PostcommitRebind {
                            anyhow::bail!("injected postcommit authority rebind failure");
                        }
                        Ok(reopened)
                    },
                );

                let (expected_operations, expected_transitions, committed, staging_retained) =
                    match fault {
                        TestSeamFault::None | TestSeamFault::PostcommitRebind => (
                            &[
                                TestSeamOperation::PreExecuteRebind,
                                TestSeamOperation::ProofFinalization,
                                TestSeamOperation::DescriptorMaterialization,
                                TestSeamOperation::DescriptorValidation,
                                TestSeamOperation::PostcommitRebind,
                            ][..],
                            &ORDER[..],
                            true,
                            false,
                        ),
                        TestSeamFault::PreExecuteRebind => (
                            &[TestSeamOperation::PreExecuteRebind][..],
                            &ORDER[..0],
                            false,
                            false,
                        ),
                        TestSeamFault::ProofFinalization => (
                            &[
                                TestSeamOperation::PreExecuteRebind,
                                TestSeamOperation::ProofFinalization,
                            ][..],
                            &ORDER[..1],
                            false,
                            false,
                        ),
                        TestSeamFault::DescriptorMaterialization => (
                            &[
                                TestSeamOperation::PreExecuteRebind,
                                TestSeamOperation::ProofFinalization,
                                TestSeamOperation::DescriptorMaterialization,
                            ][..],
                            &ORDER[..3],
                            false,
                            true,
                        ),
                        TestSeamFault::DescriptorValidation => (
                            &[
                                TestSeamOperation::PreExecuteRebind,
                                TestSeamOperation::ProofFinalization,
                                TestSeamOperation::DescriptorMaterialization,
                                TestSeamOperation::DescriptorValidation,
                            ][..],
                            &ORDER[..],
                            true,
                            false,
                        ),
                    };

                assert_eq!(
                    operations.borrow().as_slice(),
                    expected_operations,
                    "test-only handler seam operation trace drifted for {fault:?}"
                );
                assert_eq!(
                    observer.events.as_slice(),
                    expected_transitions,
                    "real affine handler transition trace drifted for {fault:?}"
                );
                assert_eq!(
                    result.is_ok(),
                    fault == TestSeamFault::None,
                    "test-only handler seam result drifted for {fault:?}: {result:?}"
                );
                assert_eq!(
                    outer.exists(),
                    committed,
                    "commit state drifted for {fault:?}"
                );
                assert_eq!(
                    staging.exists(),
                    staging_retained,
                    "reserved staging recovery state drifted for {fault:?}"
                );
                if committed {
                    assert_eq!(
                        fs::read(outer.join(REPRODUCTION_SUBTREE).join(TEST_CATALOG_FILE)).unwrap(),
                        TEST_CATALOG_BYTES,
                        "committed descriptor-rooted bytes drifted for {fault:?}"
                    );
                }
                if staging_retained {
                    assert_eq!(
                        fs::read(staging.join(REPRODUCTION_SUBTREE).join(TEST_CATALOG_FILE))
                            .unwrap(),
                        TEST_CATALOG_BYTES,
                        "retained fail-closed staging bytes drifted for {fault:?}"
                    );
                }
                if let Ok(bytes) = result {
                    assert_eq!(bytes, TEST_CATALOG_BYTES);
                }
            }
        }

        fn run_pipeline(
            observer: &mut Recorder,
            operations: &RefCell<Vec<GenerateNegativeAncestryTransition>>,
            drops: &Rc<std::cell::Cell<usize>>,
        ) -> Result<()> {
            coordinate_generate_negative_ancestry(
                &mut (),
                observer,
                |_state| {
                    operations
                        .borrow_mut()
                        .push(GenerateNegativeAncestryTransition::ProveAndFinalize);
                    Ok(DropWitness(Rc::clone(drops)))
                },
                |_state, prepared, observer| {
                    coordinate_generate_negative_ancestry_mutation(
                        observer,
                        prepared,
                        || {
                            operations
                                .borrow_mut()
                                .push(GenerateNegativeAncestryTransition::BeginOuterStaging);
                            Ok(DropWitness(Rc::clone(drops)))
                        },
                        |_transaction, prepared| {
                            operations.borrow_mut().push(
                                GenerateNegativeAncestryTransition::DescriptorRootedMaterialization,
                            );
                            Ok(prepared)
                        },
                        |_transaction, _prepared| {
                            operations.borrow_mut().push(
                                GenerateNegativeAncestryTransition::OuterCommitAndPostcommitValidation,
                            );
                            Ok(())
                        },
                    )
                },
            )
        }

        #[test]
        fn handler_transition_trace_is_exact_and_every_injected_boundary_fails_closed() {
            let success_operations = RefCell::new(Vec::new());
            let success_drops = Rc::new(std::cell::Cell::new(0));
            let mut success = Recorder {
                events: Vec::new(),
                fail_before: None,
            };
            run_pipeline(&mut success, &success_operations, &success_drops).unwrap();
            assert_eq!(success.events, ORDER);
            assert_eq!(*success_operations.borrow(), ORDER);
            assert_eq!(success_drops.get(), 2);

            for (index, transition) in ORDER.into_iter().enumerate() {
                let operations = RefCell::new(Vec::new());
                let drops = Rc::new(std::cell::Cell::new(0));
                let mut recorder = Recorder {
                    events: Vec::new(),
                    fail_before: Some(transition),
                };

                let error = run_pipeline(&mut recorder, &operations, &drops).unwrap_err();

                assert!(format!("{error:#}").contains("injected transition failure"));
                assert_eq!(recorder.events, ORDER[..=index]);
                assert_eq!(*operations.borrow(), ORDER[..index]);
                assert_eq!(
                    drops.get(),
                    usize::from(index >= 1) + usize::from(index >= 2),
                    "all affine values created before {transition:?} must be suppressed"
                );
            }
        }

        #[test]
        fn real_descriptor_rooted_handler_kernel_is_exercised_by_a_test_only_seam() {
            execute_descriptor_rooted_negative_ancestry_test_seam();
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(
    unused_imports,
    reason = "E3 exposes the real handler to the parent before the E8 registry consumes it"
)]
pub(super) use execute::{
    GenerateNegativeAncestryWitnessCatalogExecuteInputsV1,
    GenerateNegativeAncestryWitnessCatalogExecuteInputsV2,
    PublishedNegativeAncestryCatalogHandlerResultV1,
    PublishedNegativeAncestryCatalogHandlerResultV2,
    execute_generate_negative_ancestry_witness_catalog_handler,
    execute_generate_negative_ancestry_witness_catalog_handler_v2,
    preflight_generate_negative_ancestry_witness_catalog_handler,
    preflight_generate_negative_ancestry_witness_catalog_handler_v2,
};

#[cfg(test)]
mod tests {
    use super::project_generate_negative_ancestry_witness_catalog_layout;

    #[test]
    fn projected_layout_has_exactly_one_reproduction_subtree() {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let prior = campaign.join("positive");
        let outer = campaign.join("runs").join("negative-ancestry");

        let projected =
            project_generate_negative_ancestry_witness_catalog_layout(&campaign, [&prior], &outer)
                .unwrap();

        assert_eq!(
            projected.required_outer_top_level_entries(),
            ["reproduction"]
        );
        assert_eq!(
            projected.required_outer_top_level_directories(),
            ["reproduction"]
        );
        assert_eq!(
            projected
                .staged_subtree_path()
                .file_name()
                .and_then(|name| name.to_str()),
            Some("reproduction")
        );
        assert_eq!(
            projected
                .projected_subtree_path()
                .file_name()
                .and_then(|name| name.to_str()),
            Some("reproduction")
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one source-shape regression binds the production callbacks to every affine kernel gate"
    )]
    fn execute_source_preserves_private_descriptor_rooted_one_way_order() {
        let source = include_str!("generate_negative_ancestry_witness_catalog.rs");
        let production_source = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source must end before test-only modules");
        let kernel_source = production_source
            .split("fn execute_descriptor_rooted_negative_ancestry_pipeline")
            .nth(1)
            .expect("real descriptor-rooted E3 kernel must exist")
            .split("fn authenticate_generate_negative_ancestry_preflight")
            .next()
            .expect("real descriptor-rooted E3 kernel must end before authentication");
        let execute_source = production_source
            .split("pub(crate) fn execute_generate_negative_ancestry_witness_catalog_handler")
            .nth(1)
            .expect("real E3 execute handler must exist");

        let authenticated = execute_source
            .find("authenticate_generate_negative_ancestry_preflight(&inputs, false)")
            .expect("execute must traverse the shared authenticated boundary");
        let kernel_call = execute_source
            .find("execute_descriptor_rooted_negative_ancestry_pipeline(")
            .expect("execute must consume the sole descriptor-rooted kernel");
        let prove = execute_source
            .find("prove_and_finalize_b4_negative_ancestry_witness_catalog(")
            .expect("handler must bind the linked fixed producer");
        let descriptor_materialize = execute_source
            .find(
                "materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor(",
            )
            .expect("handler must bind descriptor-rooted materialization");
        let descriptor_validate = execute_source
            .find(
                "validate_published_b4_negative_ancestry_witness_catalog_from_directory_descriptor(",
            )
            .expect("handler must bind descriptor-rooted validation");
        let rebind = execute_source
            .rfind(".verify_authority_bindings(")
            .expect("handler must rebind source authority after reopen");

        let pre_execute_rebind = kernel_source
            .find("rebind_before_execute()?;")
            .expect("kernel must rebind after authenticated preflight");
        let execute_gate = kernel_source
            .find("preflight.execute(")
            .expect("execute must consume the affine preflight context");
        let proof_gate = kernel_source
            .find("execute.with_proof(")
            .expect("proof production must remain behind the proof capability");
        let proof_callback = kernel_source
            .find("prove_and_finalize())")
            .expect("kernel must consume proof output only inside the proof capability");
        let mutation_gate = kernel_source
            .find("execute.with_mutation(")
            .expect("publication must remain behind the mutation capability");
        let begin = kernel_source
            .find("begin_create_only_directory()")
            .expect("handler must begin through the create-only kernel");
        let descriptor_publish = kernel_source
            .find("publish_and_adopt_directory_tree(")
            .expect("kernel must publish through retained descriptor custody");
        let materialize_callback = kernel_source
            .find("materialize(root, &authority)")
            .expect("kernel must materialize only from the borrowed staging descriptor");
        let commit = kernel_source
            .find("commit_with_postcommit_validation(")
            .expect("handler must retain postcommit custody");
        let root_descriptor = kernel_source
            .find("committed.root_directory_descriptor()?")
            .expect("handler must reopen from the retained committed root");
        let postcommit_callback = kernel_source
            .find("validate_and_rebind_postcommit(")
            .expect("kernel must validate and rebind before returning authority");

        assert!(
            pre_execute_rebind < execute_gate
                && execute_gate < proof_gate
                && proof_gate < proof_callback
                && proof_callback < mutation_gate
                && mutation_gate < begin
                && begin < descriptor_publish
                && descriptor_publish < materialize_callback
                && materialize_callback < commit
                && commit < postcommit_callback
                && postcommit_callback < root_descriptor
        );
        assert!(
            authenticated < kernel_call
                && kernel_call < prove
                && prove < descriptor_materialize
                && descriptor_materialize < descriptor_validate
                && descriptor_validate < rebind,
            "production bindings escaped or reordered around the shared affine kernel"
        );
        assert_eq!(
            execute_source
                .matches("prove_and_finalize_b4_negative_ancestry_witness_catalog(")
                .count(),
            1
        );
        assert!(
            !execute_source.contains("publish_b4_negative_ancestry_witness_catalog(")
                && !execute_source
                    .contains("prove_finalize_and_publish_b4_negative_ancestry_witness_catalog(")
        );
        assert!(
            !production_source
                .contains("pub struct PublishedNegativeAncestryCatalogHandlerResultV1")
        );
        assert!(
            !production_source.contains("execute_descriptor_rooted_negative_ancestry_test_seam")
        );
    }

    #[test]
    fn handler_has_no_guest_path_cli_or_registry_input() {
        let source = include_str!("generate_negative_ancestry_witness_catalog.rs");
        let production_source = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source must end before test-only modules");
        let input_shape = production_source
            .split("pub(crate) struct GenerateNegativeAncestryWitnessCatalogExecuteInputsV1")
            .nth(1)
            .expect("E3 input type must exist")
            .split("impl<'authority")
            .next()
            .expect("input type must end before its constructor");

        assert!(input_shape.contains("source: B4NegativeAncestrySourceAuthorityV1"));
        for forbidden in [
            "guest_elf:",
            "alternate_elf:",
            "image_id:",
            "guest_path:",
            "registry:",
            "command:",
        ] {
            assert!(
                !input_shape.contains(forbidden),
                "caller-selected field escaped into E3 inputs: {forbidden}"
            );
        }
        assert!(
            production_source.contains("require_locked_negative_ancestry_source(&inputs.source)")
                && production_source.contains("validate_b4_campaign_command_invocation(")
        );
    }

    #[test]
    fn v2_handler_is_affine_ordered_and_has_no_v1_conversion_or_proof_selectors() {
        let source = include_str!("generate_negative_ancestry_witness_catalog.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let input_shape = production
            .split("pub(crate) struct GenerateNegativeAncestryWitnessCatalogExecuteInputsV2")
            .nth(1)
            .unwrap()
            .split("impl<'authority")
            .next()
            .unwrap();
        assert!(input_shape.contains("positive: &'authority B4PositiveGenerationAuthorityV2"));
        assert!(input_shape.contains("source: B4NegativeAncestrySourceAuthorityV2"));
        for forbidden in [
            "statement:",
            "guest_elf:",
            "image_id:",
            "family:",
            "terminal:",
            "segment:",
            "packet:",
            "receipt:",
        ] {
            assert!(
                !input_shape.contains(forbidden),
                "caller-selected field escaped into V2 ancestry inputs: {forbidden}"
            );
        }

        let handler = production
            .split("pub(crate) fn execute_generate_negative_ancestry_witness_catalog_handler_v2")
            .nth(1)
            .unwrap();
        let preflight = handler
            .find("authenticate_generate_negative_ancestry_preflight_v2(&inputs, false)")
            .unwrap();
        let proof = handler
            .find("prove_and_finalize_b4_negative_ancestry_witness_catalog_v2(")
            .unwrap();
        let materialize = handler
            .find("materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor_v2(")
            .unwrap();
        let reopen = handler
            .find("validate_published_b4_negative_ancestry_witness_catalog_from_directory_descriptor_v2(")
            .unwrap();
        let lineage = handler
            .find(".verify_prior_authority_lineage(campaign_authority, positive_authority)")
            .unwrap();
        let final_rebind = handler.rfind(".verify_authority_bindings(").unwrap();
        assert!(
            preflight < proof
                && proof < materialize
                && materialize < reopen
                && reopen < lineage
                && lineage < final_rebind
        );
        for forbidden in [
            ["From<B4NegativeAncestrySourceAuthorityV2", ">"].concat(),
            ["Into<B4NegativeAncestrySourceAuthorityV1", ">"].concat(),
            ["B4NegativeAncestrySourceAuthorityV2", "::into_v1"].concat(),
            ["B4NegativeAncestryWitnessCatalogAuthorityV2", "::into_v1"].concat(),
        ] {
            assert!(
                !production.contains(&forbidden),
                "V2 ancestry handler contains forbidden conversion {forbidden}"
            );
        }
    }
}
