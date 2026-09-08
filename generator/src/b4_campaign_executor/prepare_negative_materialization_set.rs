//! Real linked `prepare-negative-materialization-set` production handler.

use std::path::Path;

use anyhow::{Context as _, Result};

use super::preflight::{
    ProjectedSingleSubtreeCampaignLayout, project_single_subtree_campaign_layout,
};
#[cfg(target_os = "linux")]
use super::typestate::ExecutorPreflightContext;

const REPRODUCTION_SUBTREE: &str = "reproduction";
const NEGATIVE_MATERIALIZATION_SET_RELATIVE: &str =
    "reproduction/negative-materialization-set.json";
const MAX_NEGATIVE_MATERIALIZATION_SET_BYTES: usize = 8 * 1024 * 1024;

/// Affine role plan retained for the legacy V1 custody adapter.
pub(super) struct NegativeMaterializationDescriptorRootPlanV1 {
    terminal_campaign_root_index: usize,
    negative_ancestry_root_index: usize,
}

impl NegativeMaterializationDescriptorRootPlanV1 {
    pub(super) const fn into_root_indices(self) -> (usize, usize) {
        (
            self.terminal_campaign_root_index,
            self.negative_ancestry_root_index,
        )
    }
}

/// Affine role plan minted only after both descriptor-root indices enter the
/// retained preflight topology for the V2 materialization closure.
///
/// The fixed custody adapter consumes this value and returns a semantic
/// materialization authority. No raw root descriptor crosses the handler
/// boundary.
pub(super) struct NegativeMaterializationDescriptorRootPlanV2 {
    terminal_campaign_root_index: usize,
    negative_ancestry_root_index: usize,
}

impl NegativeMaterializationDescriptorRootPlanV2 {
    fn from_authenticated_preflight(
        campaign_precommit_root_index: usize,
        terminal_campaign_root_index: usize,
        negative_ancestry_root_index: usize,
    ) -> Result<Self> {
        anyhow::ensure!(
            campaign_precommit_root_index != terminal_campaign_root_index
                && campaign_precommit_root_index != negative_ancestry_root_index
                && terminal_campaign_root_index != negative_ancestry_root_index,
            "campaign-precommit, terminal-campaign, and negative-ancestry roles must use three distinct retained roots"
        );
        Ok(Self {
            terminal_campaign_root_index,
            negative_ancestry_root_index,
        })
    }

    pub(super) const fn into_root_indices(self) -> (usize, usize) {
        (
            self.terminal_campaign_root_index,
            self.negative_ancestry_root_index,
        )
    }
}

fn project_prepare_negative_materialization_set_layout<const ROOTS: usize>(
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
    .context("cannot project prepare-negative-materialization-set campaign layout")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrepareNegativeMaterializationTransition {
    DescriptorRootedAuthorityPreparation,
    BeginOuterStaging,
    WriteMaterializationSet,
    OuterCommitAndPostcommitValidation,
}

trait PrepareNegativeMaterializationTransitionObserver {
    fn before(&mut self, transition: PrepareNegativeMaterializationTransition) -> Result<()>;
}

fn coordinate_prepare_negative_materialization_set<State, Prepared, Output>(
    state: &mut State,
    observer: &mut impl PrepareNegativeMaterializationTransitionObserver,
    prepare: impl FnOnce(&mut State) -> Result<Prepared>,
    mutate: impl FnOnce(
        &mut State,
        Prepared,
        &mut dyn PrepareNegativeMaterializationTransitionObserver,
    ) -> Result<Output>,
) -> Result<Output> {
    observer
        .before(PrepareNegativeMaterializationTransition::DescriptorRootedAuthorityPreparation)?;
    let prepared = prepare(state)?;
    mutate(state, prepared, observer)
}

#[cfg(all(target_os = "linux", feature = "b4-negative-materialization-handler"))]
mod execute {
    use std::{env, ffi::OsString, path::Path};

    use anyhow::{Context as _, Result, ensure};
    use eip_0045_reproduction::{
        b4_campaign_contract::{
            B4CampaignPrecommitAuthorityV1, B4ContractArtifactIdentityV1,
            B4PositiveGenerationAuthorityV2, MAX_CAMPAIGN_PRECOMMIT_BYTES,
            validate_b4_campaign_command_invocation,
        },
        b4_materialization_set::{
            B4NegativeMaterializationSetAuthorityV2, B4NegativeMaterializationSetExternalInputsV1,
        },
        b4_negative_ancestry_authority::B4NegativeAncestryWitnessCatalogAuthorityV2,
        b4_terminal_source_lineage::B4TerminalSourceLineageAuthorityV2,
    };

    use crate::b4_campaign_executor::authenticated_preflight::{
        authenticate_campaign_precommit_file, derive_campaign_relative_artifact_path,
        require_current_executable_binding,
    };

    use super::{
        ExecutorPreflightContext, MAX_NEGATIVE_MATERIALIZATION_SET_BYTES,
        NEGATIVE_MATERIALIZATION_SET_RELATIVE, PrepareNegativeMaterializationTransition,
        PrepareNegativeMaterializationTransitionObserver, ProjectedSingleSubtreeCampaignLayout,
        REPRODUCTION_SUBTREE, coordinate_prepare_negative_materialization_set,
        project_prepare_negative_materialization_set_layout,
    };

    const COMMAND: &str = "prepare-negative-materialization-set";

    /// Typed inputs reconstructed before the execute-only production branch.
    pub(crate) struct PrepareNegativeMaterializationSetExecuteInputsV2<
        'authority,
        const ROOTS: usize,
    > {
        configured_executor_artifact: &'authority Path,
        campaign_root: &'authority Path,
        prior_roots: [&'authority Path; ROOTS],
        outer_final_root: &'authority Path,
        campaign_precommit_root_index: usize,
        campaign_precommit_root_relative_path: &'authority str,
        terminal_campaign_root_index: usize,
        negative_ancestry_root_index: usize,
        campaign: &'authority B4CampaignPrecommitAuthorityV1,
        positive: &'authority B4PositiveGenerationAuthorityV2,
        lineage: B4TerminalSourceLineageAuthorityV2,
        ancestry: B4NegativeAncestryWitnessCatalogAuthorityV2,
        external: B4NegativeMaterializationSetExternalInputsV1<'authority>,
    }

    impl<'authority, const ROOTS: usize>
        PrepareNegativeMaterializationSetExecuteInputsV2<'authority, ROOTS>
    {
        #[allow(
            clippy::too_many_arguments,
            reason = "the handler retains every independently reconstructed authority and immutable root explicitly"
        )]
        #[allow(
            clippy::large_types_passed_by_value,
            reason = "the affine handler must consume the complete externally authenticated input bundle"
        )]
        pub(crate) const fn new(
            configured_executor_artifact: &'authority Path,
            campaign_root: &'authority Path,
            prior_roots: [&'authority Path; ROOTS],
            outer_final_root: &'authority Path,
            campaign_precommit_root_index: usize,
            campaign_precommit_root_relative_path: &'authority str,
            terminal_campaign_root_index: usize,
            negative_ancestry_root_index: usize,
            campaign: &'authority B4CampaignPrecommitAuthorityV1,
            positive: &'authority B4PositiveGenerationAuthorityV2,
            lineage: B4TerminalSourceLineageAuthorityV2,
            ancestry: B4NegativeAncestryWitnessCatalogAuthorityV2,
            external: B4NegativeMaterializationSetExternalInputsV1<'authority>,
        ) -> Self {
            Self {
                configured_executor_artifact,
                campaign_root,
                prior_roots,
                outer_final_root,
                campaign_precommit_root_index,
                campaign_precommit_root_relative_path,
                terminal_campaign_root_index,
                negative_ancestry_root_index,
                campaign,
                positive,
                lineage,
                ancestry,
                external,
            }
        }
    }

    /// Private complete result retained only after byte-exact postcommit reopen.
    pub(crate) struct PreparedNegativeMaterializationSetHandlerResultV2 {
        _authority: B4NegativeMaterializationSetAuthorityV2,
    }

    struct CapturedExecuteInvocation {
        process_argv: Vec<OsString>,
        parsed_preflight_only: bool,
    }

    impl CapturedExecuteInvocation {
        fn capture(parsed_preflight_only: bool) -> Result<Self> {
            ensure!(
                env::var_os("RISC0_DEV_MODE").is_none(),
                "RISC0_DEV_MODE must be absent before negative-materialization preparation"
            );
            let process_argv = env::args_os().collect::<Vec<_>>();
            validate_b4_campaign_command_invocation(&process_argv, COMMAND, parsed_preflight_only)
                .context("invalid retained prepare-negative-materialization-set invocation argv")?;
            Ok(Self {
                process_argv,
                parsed_preflight_only,
            })
        }

        fn revalidate(&self) -> Result<()> {
            ensure!(
                env::var_os("RISC0_DEV_MODE").is_none(),
                "RISC0_DEV_MODE appeared after negative-materialization preflight"
            );
            validate_b4_campaign_command_invocation(
                &self.process_argv,
                COMMAND,
                self.parsed_preflight_only,
            )
            .context("retained prepare-negative-materialization-set invocation changed")
        }
    }

    type NegativeMaterializationPreflightContext<const ROOTS: usize> =
        ExecutorPreflightContext<ROOTS, ProjectedSingleSubtreeCampaignLayout<ROOTS>>;

    struct AuthenticatedNegativeMaterializationPreflightV2<const ROOTS: usize> {
        preflight: NegativeMaterializationPreflightContext<ROOTS>,
        campaign_precommit_identity: B4ContractArtifactIdentityV1,
        descriptor_root_plan: super::NegativeMaterializationDescriptorRootPlanV2,
        invocation: CapturedExecuteInvocation,
    }

    struct NoopPrepareNegativeMaterializationTransitionObserver;

    impl PrepareNegativeMaterializationTransitionObserver
        for NoopPrepareNegativeMaterializationTransitionObserver
    {
        fn before(&mut self, _transition: PrepareNegativeMaterializationTransition) -> Result<()> {
            Ok(())
        }
    }

    fn coordinate_prepare_negative_materialization_mutation<Transaction, Authority, Output>(
        observer: &mut dyn PrepareNegativeMaterializationTransitionObserver,
        authority: Authority,
        begin_outer_staging: impl FnOnce() -> Result<Transaction>,
        write_materialization_set: impl FnOnce(&mut Transaction, &Authority) -> Result<()>,
        commit_and_validate: impl FnOnce(Transaction, Authority) -> Result<Output>,
    ) -> Result<Output> {
        observer.before(PrepareNegativeMaterializationTransition::BeginOuterStaging)?;
        let mut transaction = begin_outer_staging()?;
        observer.before(PrepareNegativeMaterializationTransition::WriteMaterializationSet)?;
        write_materialization_set(&mut transaction, &authority)?;
        observer
            .before(PrepareNegativeMaterializationTransition::OuterCommitAndPostcommitValidation)?;
        commit_and_validate(transaction, authority)
    }

    fn authenticate_prepare_negative_materialization_preflight<const ROOTS: usize>(
        inputs: &PrepareNegativeMaterializationSetExecuteInputsV2<'_, ROOTS>,
        parsed_preflight_only: bool,
    ) -> Result<AuthenticatedNegativeMaterializationPreflightV2<ROOTS>> {
        let projected = project_prepare_negative_materialization_set_layout(
            inputs.campaign_root,
            inputs.prior_roots,
            inputs.outer_final_root,
        )?;
        let preflight =
            ExecutorPreflightContext::capture(inputs.configured_executor_artifact, projected)
                .context("prepare-negative-materialization-set retained preflight failed")?;
        let campaign_precommit_root = *inputs
            .prior_roots
            .get(inputs.campaign_precommit_root_index)
            .context("campaign-precommit root index is outside the retained prior-root set")?;
        inputs
            .prior_roots
            .get(inputs.terminal_campaign_root_index)
            .context("terminal-campaign root index is outside the retained prior-root set")?;
        inputs
            .prior_roots
            .get(inputs.negative_ancestry_root_index)
            .context("negative-ancestry root index is outside the retained prior-root set")?;
        let descriptor_root_plan =
            super::NegativeMaterializationDescriptorRootPlanV2::from_authenticated_preflight(
                inputs.campaign_precommit_root_index,
                inputs.terminal_campaign_root_index,
                inputs.negative_ancestry_root_index,
            )?;
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
        let campaign_precommit_identity = authenticate_campaign_precommit_file(
            &campaign_precommit_identity_path,
            inputs.campaign,
            &campaign_precommit_bytes,
        )?;
        let invocation = CapturedExecuteInvocation::capture(parsed_preflight_only)?;
        inputs
            .lineage
            .verify_authority_bindings(inputs.campaign, inputs.positive)
            .context("terminal-source lineage differs from execute authorities")?;
        inputs
            .ancestry
            .verify_prior_authority_lineage(inputs.campaign, inputs.positive)
            .context("negative-ancestry authority differs from execute authorities")?;
        require_current_executable_binding(preflight.executable(), inputs.campaign)?;
        invocation.revalidate()?;
        Ok(AuthenticatedNegativeMaterializationPreflightV2 {
            preflight,
            campaign_precommit_identity,
            descriptor_root_plan,
            invocation,
        })
    }

    /// Reach the exact zero-effect production boundary for global preflight mode.
    pub(crate) fn preflight_prepare_negative_materialization_set_handler<const ROOTS: usize>(
        inputs: &PrepareNegativeMaterializationSetExecuteInputsV2<'_, ROOTS>,
    ) -> Result<()> {
        let authenticated = authenticate_prepare_negative_materialization_preflight(inputs, true)?;
        authenticated.invocation.revalidate()?;
        authenticated
            .preflight
            .finish_preflight()
            .context("prepare-negative-materialization-set authenticated preflight failed")
    }

    /// Assemble the descriptor-rooted authority before opening mutation custody.
    #[allow(
        clippy::too_many_lines,
        reason = "the security-sensitive import/closure/publication/commit order remains one audit unit"
    )]
    pub(crate) fn execute_prepare_negative_materialization_set_handler<const ROOTS: usize>(
        inputs: PrepareNegativeMaterializationSetExecuteInputsV2<'_, ROOTS>,
    ) -> Result<PreparedNegativeMaterializationSetHandlerResultV2> {
        let AuthenticatedNegativeMaterializationPreflightV2 {
            preflight,
            campaign_precommit_identity,
            descriptor_root_plan,
            invocation,
        } = authenticate_prepare_negative_materialization_preflight(&inputs, false)?;
        let PrepareNegativeMaterializationSetExecuteInputsV2 {
            configured_executor_artifact,
            campaign_root: _,
            prior_roots: _,
            outer_final_root: _,
            campaign_precommit_root_index: _,
            campaign_precommit_root_relative_path: _,
            terminal_campaign_root_index: _,
            negative_ancestry_root_index: _,
            campaign,
            positive,
            lineage,
            ancestry,
            external,
        } = inputs;

        preflight.execute(move |execute| {
            let mut observer = NoopPrepareNegativeMaterializationTransitionObserver;
            coordinate_prepare_negative_materialization_set(
                execute,
                &mut observer,
                |execute| {
                    execute.with_proof(|capability| {
                        ancestry
                            .verify_prior_authority_lineage(campaign, positive)
                            .context("negative-ancestry authority changed after preflight")?;
                        capability.close_negative_materialization_authority_v2(
                            descriptor_root_plan,
                            configured_executor_artifact,
                            &campaign_precommit_identity,
                            campaign,
                            positive,
                            lineage,
                            &ancestry,
                            &external,
                        )
                    })
                },
                |execute, authority, observer| {
                    invocation.revalidate()?;
                    execute.with_mutation(move |capability| {
                        coordinate_prepare_negative_materialization_mutation(
                            observer,
                            authority,
                            || capability.begin_create_only_directory(),
                            |transaction, authority| {
                                transaction.create_directory(REPRODUCTION_SUBTREE)?;
                                transaction.create_file(
                                    NEGATIVE_MATERIALIZATION_SET_RELATIVE,
                                    authority.canonical_materialization_set_jcs(),
                                    MAX_NEGATIVE_MATERIALIZATION_SET_BYTES,
                                )
                            },
                            |transaction, authority| {
                                transaction.commit_with_postcommit_validation(move |committed| {
                                    let reopened = committed.read_file(
                                        NEGATIVE_MATERIALIZATION_SET_RELATIVE,
                                        MAX_NEGATIVE_MATERIALIZATION_SET_BYTES,
                                    )?;
                                    ensure!(
                                        reopened == authority.canonical_materialization_set_jcs(),
                                        "postcommit negative materialization set differs from its retained authority"
                                    );
                                    authority
                                        .verify_candidate_jcs(&reopened)
                                        .context(
                                            "cannot semantically reopen committed negative materialization set",
                                        )?;
                                    invocation.revalidate()?;
                                    Ok(PreparedNegativeMaterializationSetHandlerResultV2 {
                                        _authority: authority,
                                    })
                                })
                            },
                        )
                    })
                },
            )
        })
    }
}

#[cfg(all(target_os = "linux", feature = "b4-negative-materialization-handler"))]
#[allow(
    unused_imports,
    reason = "E5 keeps the private handler available to the parent before the E8 command table consumes it"
)]
pub(super) use execute::{
    PrepareNegativeMaterializationSetExecuteInputsV2,
    PreparedNegativeMaterializationSetHandlerResultV2,
    execute_prepare_negative_materialization_set_handler,
    preflight_prepare_negative_materialization_set_handler,
};

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use anyhow::Result;

    use super::{
        NegativeMaterializationDescriptorRootPlanV2, PrepareNegativeMaterializationTransition,
        PrepareNegativeMaterializationTransitionObserver,
        coordinate_prepare_negative_materialization_set,
        project_prepare_negative_materialization_set_layout,
    };

    struct Recorder {
        events: Vec<PrepareNegativeMaterializationTransition>,
    }

    impl PrepareNegativeMaterializationTransitionObserver for Recorder {
        fn before(&mut self, transition: PrepareNegativeMaterializationTransition) -> Result<()> {
            self.events.push(transition);
            Ok(())
        }
    }

    #[test]
    fn synthetic_error_250_of_254_stops_before_mutation_and_staging() {
        let mutation_entered = Cell::new(false);
        let staging_started = Cell::new(false);
        let mut state = ();
        let mut recorder = Recorder { events: Vec::new() };

        let error = coordinate_prepare_negative_materialization_set(
            &mut state,
            &mut recorder,
            |_state| -> Result<()> {
                anyhow::bail!(
                    "closed negative materialization producers reconstructed only 250/254 executions"
                )
            },
            |_state, (), _observer| {
                mutation_entered.set(true);
                staging_started.set(true);
                Ok(())
            },
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("250/254"));
        assert_eq!(
            recorder.events,
            [PrepareNegativeMaterializationTransition::DescriptorRootedAuthorityPreparation]
        );
        assert!(!mutation_entered.get());
        assert!(!staging_started.get());
    }

    #[test]
    fn projected_layout_has_exactly_one_reproduction_subtree() {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let prior = campaign.join("terminal-campaign");
        let outer = campaign.join("runs").join("negative-materialization");

        let projected =
            project_prepare_negative_materialization_set_layout(&campaign, [&prior], &outer)
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
    fn source_freezes_one_file_phase_topology_without_a_completion_marker() {
        let source = include_str!("prepare_negative_materialization_set.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let execute = production
            .split("pub(crate) fn execute_prepare_negative_materialization_set_handler")
            .nth(1)
            .unwrap();

        assert!(production.contains("const NEGATIVE_MATERIALIZATION_SET_RELATIVE: &str"));
        assert_eq!(
            production
                .matches("\"reproduction/negative-materialization-set.json\"")
                .count(),
            1
        );
        assert_eq!(execute.matches("transaction.create_directory(").count(), 1);
        assert!(execute.contains("transaction.create_directory(REPRODUCTION_SUBTREE)?"));
        assert_eq!(execute.matches("transaction.create_file(").count(), 1);
        assert_eq!(
            execute
                .matches("transaction.commit_with_postcommit_validation(")
                .count(),
            1
        );
        assert_eq!(execute.matches("committed.read_file(").count(), 1);
        assert_eq!(
            execute
                .matches("NEGATIVE_MATERIALIZATION_SET_RELATIVE")
                .count(),
            2
        );
        assert!(execute.contains("reopened == authority.canonical_materialization_set_jcs()"));
        assert_eq!(
            execute.matches(".verify_candidate_jcs(&reopened)").count(),
            1
        );

        let create_directory = execute
            .find("transaction.create_directory(REPRODUCTION_SUBTREE)?")
            .unwrap();
        let create_file = execute.find("transaction.create_file(").unwrap();
        let commit = execute
            .find("transaction.commit_with_postcommit_validation(")
            .unwrap();
        let reopen = execute.find("committed.read_file(").unwrap();
        let byte_equality = execute
            .find("reopened == authority.canonical_materialization_set_jcs()")
            .unwrap();
        let semantic_revalidation = execute.find(".verify_candidate_jcs(&reopened)").unwrap();
        assert!(
            create_directory < create_file
                && create_file < commit
                && commit < reopen
                && reopen < byte_equality
                && byte_equality < semantic_revalidation
        );
        assert!(!execute.contains("COMPLETE"));
        assert!(!execute.contains("completion_marker"));
    }

    #[test]
    fn source_has_no_command_entrypoint_or_registration_surface() {
        let source = include_str!("prepare_negative_materialization_set.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();

        assert!(!production.contains("fn main("));
        assert!(!production.contains("register_handler"));
        assert!(!production.contains("command_registry"));
        assert!(!production.contains("Command::"));
    }

    #[test]
    fn test_only_coordination_compile_cannot_open_the_linux_execute_surface() {
        let parent = include_str!("mod.rs");
        let module_gate = parent
            .split("mod prepare_negative_materialization_set;")
            .next()
            .unwrap()
            .rsplit("#[cfg(")
            .next()
            .unwrap();
        assert!(module_gate.contains("test"));
        assert!(module_gate.contains("feature = \"b4-negative-materialization-handler\""));

        let source = include_str!("prepare_negative_materialization_set.rs");
        for marker in ["mod execute {", "pub(super) use execute::"] {
            let gate = source
                .split(marker)
                .next()
                .unwrap()
                .rsplit("#[cfg(")
                .next()
                .unwrap();
            assert!(gate.contains("target_os = \"linux\""));
            assert!(gate.contains("feature = \"b4-negative-materialization-handler\""));
            assert!(!gate.contains("test"));
        }
    }

    #[test]
    fn source_orders_descriptor_authority_before_mutation_and_create_only_staging() {
        let source = include_str!("prepare_negative_materialization_set.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let execute = production
            .split("pub(crate) fn execute_prepare_negative_materialization_set_handler")
            .nth(1)
            .unwrap();

        let proof = execute.find("execute.with_proof(").unwrap();
        let fixed_descriptor_close = execute
            .find("capability.close_negative_materialization_authority_v2(")
            .unwrap();
        let mutation = execute.find("execute.with_mutation(").unwrap();
        let begin = execute.find("begin_create_only_directory()").unwrap();

        assert!(
            proof < fixed_descriptor_close && fixed_descriptor_close < mutation && mutation < begin
        );
        assert!(!execute.contains("BorrowedFd"));
        assert!(!execute.contains("with_immutable_root_descriptor"));
        assert!(!execute.contains("with_root_descriptor"));
        assert!(
            !execute.contains("authenticate_b4_terminal_evidence_import_from_directory_descriptor")
        );
        assert!(!execute.contains(
            "B4NegativeMaterializationSetAuthorityV2::from_descriptor_rooted_cryptographic_closure_v2"
        ));
        assert!(!execute.contains("generate_fixed_alternate_root_proof_bundle"));
        assert!(!execute.contains("LocalProver"));
        assert!(!execute.contains("prove_and_finalize"));
    }

    #[test]
    fn descriptor_root_plan_is_affine_and_has_one_private_mint() {
        let reversed =
            NegativeMaterializationDescriptorRootPlanV2::from_authenticated_preflight(2, 1, 0)
                .unwrap();
        assert_eq!(reversed.into_root_indices(), (1, 0));

        trait AmbiguousIfClone<Marker> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfClone<()> for T {}
        impl<T: ?Sized + Clone> AmbiguousIfClone<u8> for T {}

        trait AmbiguousIfCopy<Marker> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfCopy<()> for T {}
        impl<T: ?Sized + Copy> AmbiguousIfCopy<u8> for T {}

        <NegativeMaterializationDescriptorRootPlanV2 as AmbiguousIfClone<_>>::marker();
        <NegativeMaterializationDescriptorRootPlanV2 as AmbiguousIfCopy<_>>::marker();

        let source = include_str!("prepare_negative_materialization_set.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert_eq!(
            production
                .matches(
                    "NegativeMaterializationDescriptorRootPlanV2::from_authenticated_preflight("
                )
                .count(),
            1
        );
        assert!(!production.contains("pub fn from_authenticated_preflight"));
        assert!(!production.contains("pub(super) fn from_authenticated_preflight"));
        assert!(!production.contains("BorrowedFd"));
        assert!(!production.contains("AsRawFd"));
        assert!(!production.contains("RawFd"));
    }

    #[test]
    fn descriptor_root_plan_rejects_every_role_alias() {
        for (campaign_precommit, terminal_campaign, negative_ancestry) in
            [(0, 0, 1), (0, 1, 0), (1, 0, 0)]
        {
            let error = NegativeMaterializationDescriptorRootPlanV2::from_authenticated_preflight(
                campaign_precommit,
                terminal_campaign,
                negative_ancestry,
            )
            .err()
            .expect("aliased retained-root roles must fail before authority mint");
            assert!(format!("{error:#}").contains("three distinct retained roots"));
        }
    }
}
