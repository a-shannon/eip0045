//! Descriptor-rooted custody and real production handlers for the B4 executor.

#![allow(
    dead_code,
    reason = "E2 and E3 freeze real handlers before the E8 registry consumes them"
)]

mod amd64_elf_inspection;
mod artifact_import;
mod artifact_import_contract;
mod authenticated_preflight;
mod create_only;
mod custody;

#[cfg(target_os = "linux")]
fn compile_only_child_endpoint_exports_are_public(
    _generator: &eip0045_h0_linux_abi::ancillary::GeneratorEndpointV1,
    _worker: &eip0045_h0_linux_abi::ancillary::WorkerEndpointV1,
) {
}

#[cfg(any(test, feature = "b4-finalize-generation-set-handler"))]
mod finalize_generation_set;
#[cfg(any(test, feature = "b4-finalize-generation-set-handler"))]
mod finalize_generation_set_handler;
#[cfg(feature = "b4-negative-ancestry-handler")]
mod generate_negative_ancestry_witness_catalog;
mod git_bundle_import;
mod oci_image_layout_import;
mod preflight;
mod prepare_campaign_precommit;
#[cfg(feature = "b4-prepare-input-set-kernel")]
mod prepare_input_set;
#[cfg(any(test, feature = "b4-negative-materialization-handler"))]
mod prepare_negative_materialization_set;
#[cfg(feature = "b4-terminal-evidence-export")]
mod publish_terminal_evidence;

mod typestate {
    use std::path::Path;

    use anyhow::{Context as _, Result};

    #[cfg(all(
        any(target_os = "linux", test),
        feature = "b4-authoritative-build-custody"
    ))]
    use eip_0045_reproduction::b4_build_check::{
        AuthoritativeB4BuildProjection, B4BuildExpectations,
    };

    use super::{
        capability, create_only,
        custody::{CampaignRootCustody, CurrentExecutableObservation, ImmutableRootCustody},
        oci_image_layout_import::{
            AuthenticatedOciOuterUstarInventoryV1, AuthenticatedOciRetainedHostRootfsInventoryV1,
            import_authenticated_oci_outer_ustar_inventory,
        },
        preflight::{
            AuthenticatedPrepareInputSetOciTopologyV1, ProjectedCampaignLayout,
            ProjectedOciImageLayoutCaptureSlotV1, ProjectedOuterCampaignLayout,
            ProjectedPrepareInputSetCampaignLayout, ProjectedPrepareInputSetOciCaptureV1,
        },
    };

    /// Effect-free context retained throughout one production preflight.
    #[must_use = "preflight custody must be consumed by the affine execute runner"]
    pub(super) struct ExecutorPreflightContext<
        const ROOTS: usize,
        Layout = ProjectedOuterCampaignLayout<ROOTS>,
    >
    where
        Layout: ProjectedCampaignLayout<ROOTS>,
    {
        executable: CurrentExecutableObservation,
        campaign_root: CampaignRootCustody,
        immutable_roots: ImmutableRootCustody<ROOTS>,
        projected_layout: Layout,
    }

    /// Affine H0 preflight which retains the four role-bound import slots until
    /// the matching descriptor-root custody enters execute mode.
    #[must_use = "the authenticated OCI preflight and its import slots must be executed together"]
    pub(super) struct AuthenticatedPrepareInputSetOciPreflightContext<const ROOTS: usize> {
        context: ExecutorPreflightContext<ROOTS, ProjectedPrepareInputSetCampaignLayout<ROOTS>>,
        import_inventory: AuthenticatedOciOuterUstarInventoryV1,
    }

    /// Borrowed replay continuation retained inside one execute session.
    ///
    /// Its private fields bind the retained host-rootfs custody to the exclusive
    /// execute borrow; sibling modules cannot access either authority independently.
    /// This is a host-side custody boundary, not evidence of a runtime start,
    /// mount namespace, loader execution, or process completion.
    #[must_use = "the authenticated OCI replay must continue inside the retained execute session"]
    pub(super) struct AuthenticatedOciReplayContinuationV1<'execute, 'rootfs, const ROOTS: usize> {
        execute: &'execute mut ExecutorExecuteContext<
            ROOTS,
            ProjectedPrepareInputSetCampaignLayout<ROOTS>,
        >,
        _retained_rootfs: &'rootfs mut AuthenticatedOciRetainedHostRootfsInventoryV1,
    }

    /// Non-forgeable proof that the complete prepare-input-set execution chain
    /// consumed the replay continuation inside the same execute session.
    #[must_use = "the authenticated prepare-input-set execution completion must be consumed"]
    pub(super) struct AuthenticatedPrepareInputSetExecutionCompletionV1<
        'execute,
        const ROOTS: usize,
    > {
        _execute: &'execute mut ExecutorExecuteContext<
            ROOTS,
            ProjectedPrepareInputSetCampaignLayout<ROOTS>,
        >,
        _private: (),
    }

    /// Unforgeable authority for the sole topology-to-custody split. Its field
    /// is private to typestate, so sibling modules can name but cannot mint it.
    pub(super) struct OciTopologyCustodyBridgePermitV1 {
        _private: (),
    }

    impl<const ROOTS: usize, Layout> ExecutorPreflightContext<ROOTS, Layout>
    where
        Layout: ProjectedCampaignLayout<ROOTS>,
    {
        /// Enter qualifying Linux custody using exactly the projected prior roots.
        pub(super) fn capture(
            configured_artifact: &Path,
            projected_layout: Layout,
        ) -> Result<Self> {
            Self::capture_inner(configured_artifact, projected_layout, None)
        }

        fn capture_inner(
            configured_artifact: &Path,
            projected_layout: Layout,
            projected_oci_slots: Option<Vec<ProjectedOciImageLayoutCaptureSlotV1>>,
        ) -> Result<Self> {
            let executable = CurrentExecutableObservation::capture(configured_artifact)?;
            let campaign_root = CampaignRootCustody::capture(projected_layout.campaign_root())?;
            let immutable_roots = match projected_oci_slots {
                Some(slots) => ImmutableRootCustody::capture_with_projected_oci(
                    &campaign_root,
                    projected_layout.prior_roots(),
                    slots,
                )?,
                None => {
                    ImmutableRootCustody::capture(&campaign_root, projected_layout.prior_roots())?
                }
            };
            executable.recheck()?;
            campaign_root.recheck()?;
            immutable_roots.recheck()?;
            campaign_root.recheck()?;
            executable.recheck()?;
            create_only::preflight_create_only_directory_transaction(
                projected_layout.outer_create_only_layout(),
                |identities| {
                    campaign_root.require_directory_chain(
                        projected_layout.outer_create_only_layout().parent(),
                        identities,
                    )?;
                    immutable_roots.reject_physical_directory_aliases(identities)
                },
            )?;
            executable.recheck()?;
            campaign_root.recheck()?;
            immutable_roots.recheck()?;
            Ok(Self {
                executable,
                campaign_root,
                immutable_roots,
                projected_layout,
            })
        }

        /// Run execute mode affinely and force the final custody check on every exit.
        pub(super) fn execute<T>(
            self,
            effect: impl FnOnce(&mut ExecutorExecuteContext<ROOTS, Layout>) -> Result<T>,
        ) -> Result<T> {
            self.recheck()?;
            let mut execute = ExecutorExecuteContext {
                executable: self.executable,
                campaign_root: self.campaign_root,
                immutable_roots: self.immutable_roots,
                projected_layout: self.projected_layout,
            };
            execute.recheck()?;
            let outcome = effect(&mut execute);
            capability::finish_outcome(
                outcome,
                execute.recheck(),
                capability::CustodyPostcheckBoundaryV1::ExecutorCompletion,
            )
        }

        /// Read one bounded prior-root file through retained descriptor custody.
        pub(super) fn read_immutable_file<const MAX_BYTES: usize>(
            &self,
            root_index: usize,
            relative: &str,
        ) -> Result<Vec<u8>> {
            self.immutable_roots
                .read_file::<MAX_BYTES>(root_index, relative)
        }

        /// Read one bounded prior-root file after a pre-allocation length check.
        pub(super) fn read_immutable_file_with_length_validation<const MAX_BYTES: usize>(
            &self,
            root_index: usize,
            relative: &str,
            validate_length: impl FnOnce(u64) -> Result<()>,
        ) -> Result<Vec<u8>> {
            self.immutable_roots
                .read_file_with_length_validation::<MAX_BYTES>(
                    root_index,
                    relative,
                    validate_length,
                )
        }

        /// Authenticate one fixed build-evidence root during zero-effect preflight.
        #[cfg(all(
            any(target_os = "linux", test),
            feature = "b4-authoritative-build-custody"
        ))]
        pub(super) fn authenticate_authoritative_b4_build_projection(
            &self,
            root_index: usize,
            expectations: &B4BuildExpectations<'_>,
        ) -> Result<AuthoritativeB4BuildProjection> {
            #[cfg(target_os = "linux")]
            {
                self.immutable_roots
                    .authenticate_authoritative_b4_build_projection(root_index, expectations)
            }
            #[cfg(all(test, not(target_os = "linux")))]
            {
                let _ = (root_index, expectations);
                anyhow::bail!("authoritative B4 build projection requires Linux descriptor custody")
            }
        }

        /// Retained current-executable observation at the final safe boundary.
        pub(super) const fn executable(&self) -> &CurrentExecutableObservation {
            &self.executable
        }

        /// Close global preflight at its final zero-effect custody boundary.
        pub(super) fn finish_preflight(self) -> Result<()> {
            self.recheck()
        }

        fn recheck(&self) -> Result<()> {
            self.executable.recheck()?;
            self.campaign_root.recheck()?;
            self.immutable_roots.recheck()?;
            self.campaign_root.recheck()?;
            self.executable.recheck()
        }
    }

    impl<const ROOTS: usize>
        ExecutorPreflightContext<ROOTS, ProjectedPrepareInputSetCampaignLayout<ROOTS>>
    {
        /// Capture the exact projected H0 layout and its closed OCI role plan together.
        pub(super) fn capture_with_projected_oci(
            configured_artifact: &Path,
            projected: ProjectedPrepareInputSetOciCaptureV1<ROOTS>,
        ) -> Result<Self> {
            let (layout, slots) = projected.into_parts();
            Self::capture_inner(configured_artifact, layout, Some(slots))
        }

        /// Enter custody from the sole gate-rooted H0 OCI topology and retain
        /// its semantic import slots for the same affine execute session.
        pub(super) fn capture_with_authenticated_oci(
            configured_artifact: &Path,
            authenticated: AuthenticatedPrepareInputSetOciTopologyV1<ROOTS>,
        ) -> Result<AuthenticatedPrepareInputSetOciPreflightContext<ROOTS>> {
            let (layout, capture_slots, import_inventory) =
                authenticated.into_custody_parts(OciTopologyCustodyBridgePermitV1 { _private: () });
            let context =
                Self::capture_inner(configured_artifact, layout, Some(Vec::from(capture_slots)))?;
            Ok(AuthenticatedPrepareInputSetOciPreflightContext {
                context,
                import_inventory,
            })
        }
    }

    impl<const ROOTS: usize> AuthenticatedPrepareInputSetOciPreflightContext<ROOTS> {
        /// Replay and retain the canonical host-rootfs inventory, reauthenticate
        /// its static dependencies around the continuation, then clean it up.
        ///
        /// This method does not launch a runtime or characterize its namespace,
        /// loader, auxiliary vector, mappings, or exit state.
        pub(super) fn with_authenticated_oci_replay<Continue>(
            self,
            continue_with: Continue,
        ) -> Result<()>
        where
            Continue: for<'execute, 'rootfs> FnOnce(
                AuthenticatedOciReplayContinuationV1<'execute, 'rootfs, ROOTS>,
            ) -> Result<
                AuthenticatedPrepareInputSetExecutionCompletionV1<'execute, ROOTS>,
            >,
        {
            let Self {
                context,
                import_inventory,
            } = self;
            context.execute(move |execute| {
                let mut retained_rootfs = execute.with_retained_mutation(
                    move |capability| {
                        import_authenticated_oci_outer_ustar_inventory(
                            capability,
                            import_inventory,
                        )?
                        .authenticate_physical_rootfs_inventory_and_retain()
                        .map_err(anyhow::Error::new)
                    },
                    |retained_rootfs| {
                        retained_rootfs
                            .cleanup()
                            .map(drop)
                            .map_err(anyhow::Error::new)
                    },
                )?;
                let outcome = match retained_rootfs
                    .reauthenticate_static_startup_dependencies()
                    .context("retained host rootfs entry reauthentication failed")
                {
                    Ok(()) => {
                        let continuation = AuthenticatedOciReplayContinuationV1 {
                            execute,
                            _retained_rootfs: &mut retained_rootfs,
                        };
                        let outcome = continue_with(continuation).map(drop);
                        capability::finish_outcome(
                            outcome,
                            retained_rootfs.reauthenticate_static_startup_dependencies(),
                            capability::CustodyPostcheckBoundaryV1::RetainedHostRootfsContinuationReauthentication,
                        )
                    }
                    Err(error) => Err(error),
                };
                let cleanup = retained_rootfs
                    .cleanup()
                    .map(drop)
                    .map_err(anyhow::Error::new);
                capability::finish_outcome(
                    outcome,
                    cleanup,
                    capability::CustodyPostcheckBoundaryV1::RetainedHostRootfsCleanup,
                )
            })
        }
    }

    /// Execute-only context available solely inside the affine runner callback.
    pub(super) struct ExecutorExecuteContext<
        const ROOTS: usize,
        Layout = ProjectedOuterCampaignLayout<ROOTS>,
    >
    where
        Layout: ProjectedCampaignLayout<ROOTS>,
    {
        executable: CurrentExecutableObservation,
        campaign_root: CampaignRootCustody,
        immutable_roots: ImmutableRootCustody<ROOTS>,
        projected_layout: Layout,
    }

    impl<const ROOTS: usize, Layout> ExecutorExecuteContext<ROOTS, Layout>
    where
        Layout: ProjectedCampaignLayout<ROOTS>,
    {
        /// Pure projected layout retained from preflight.
        pub(super) const fn projected_layout(&self) -> &Layout {
            &self.projected_layout
        }

        pub(super) const fn immutable_roots(&self) -> &ImmutableRootCustody<ROOTS> {
            &self.immutable_roots
        }

        pub(super) const fn executable(&self) -> &CurrentExecutableObservation {
            &self.executable
        }

        pub(super) const fn campaign_root(&self) -> &CampaignRootCustody {
            &self.campaign_root
        }

        /// Read one bounded prior-root file through retained descriptor custody.
        pub(super) fn read_immutable_file<const MAX_BYTES: usize>(
            &self,
            root_index: usize,
            relative: &str,
        ) -> Result<Vec<u8>> {
            self.immutable_roots
                .read_file::<MAX_BYTES>(root_index, relative)
        }

        /// Read one bounded prior-root file after a pre-allocation length check.
        pub(super) fn read_immutable_file_with_length_validation<const MAX_BYTES: usize>(
            &self,
            root_index: usize,
            relative: &str,
            validate_length: impl FnOnce(u64) -> Result<()>,
        ) -> Result<Vec<u8>> {
            self.immutable_roots
                .read_file_with_length_validation::<MAX_BYTES>(
                    root_index,
                    relative,
                    validate_length,
                )
        }

        /// Reauthenticate one fixed build-evidence root inside execute custody.
        #[cfg(all(
            any(target_os = "linux", test),
            feature = "b4-authoritative-build-custody"
        ))]
        pub(super) fn authenticate_authoritative_b4_build_projection(
            &self,
            root_index: usize,
            expectations: &B4BuildExpectations<'_>,
        ) -> Result<AuthoritativeB4BuildProjection> {
            #[cfg(target_os = "linux")]
            {
                self.immutable_roots
                    .authenticate_authoritative_b4_build_projection(root_index, expectations)
            }
            #[cfg(all(test, not(target_os = "linux")))]
            {
                let _ = (root_index, expectations);
                anyhow::bail!("authoritative B4 build projection requires Linux descriptor custody")
            }
        }

        /// Run one proof-producing effect inside an entry/exit custody sandwich.
        pub(super) fn with_proof<T>(
            &mut self,
            effect: impl FnOnce(&mut capability::ProofCapability<'_, ROOTS>) -> Result<T>,
        ) -> Result<T> {
            capability::with_proof(self, effect)
        }

        /// Run one filesystem mutation inside an entry/exit custody sandwich.
        pub(super) fn with_mutation<T>(
            &mut self,
            effect: impl FnOnce(&mut capability::MutationCapability<'_, ROOTS, Layout>) -> Result<T>,
        ) -> Result<T> {
            capability::with_mutation(self, effect)
        }

        /// Retain a mutation result only after its custody postcheck succeeds.
        ///
        /// If that postcheck fails after a successful effect, `cleanup` consumes
        /// the retained value explicitly and both failures remain observable.
        pub(super) fn with_retained_mutation<T>(
            &mut self,
            effect: impl FnOnce(&mut capability::MutationCapability<'_, ROOTS, Layout>) -> Result<T>,
            cleanup: impl FnOnce(T) -> Result<()>,
        ) -> Result<T> {
            capability::with_retained_mutation(self, effect, cleanup)
        }

        /// Run one bound-child launch inside an entry/exit custody sandwich.
        pub(super) fn with_child_launch<T>(
            &mut self,
            effect: impl FnOnce(&mut capability::ChildLaunchCapability) -> Result<T>,
        ) -> Result<T> {
            capability::with_child_launch(self, effect)
        }

        pub(super) fn recheck(&self) -> Result<()> {
            self.executable.recheck()?;
            self.campaign_root.recheck()?;
            self.immutable_roots.recheck()?;
            self.campaign_root.recheck()?;
            self.executable.recheck()
        }
    }
}

mod capability {
    use std::fmt;

    #[cfg(all(target_os = "linux", feature = "b4-negative-materialization-handler"))]
    use std::path::Path;

    use anyhow::{Context as _, Result};

    #[cfg(all(target_os = "linux", feature = "b4-negative-materialization-handler"))]
    use eip_0045_reproduction::{
        b4_campaign_contract::{
            B4CampaignPrecommitAuthorityV1, B4ContractArtifactIdentityV1,
            B4PositiveGenerationAuthorityV2,
        },
        b4_materialization_set::{
            B4NegativeMaterializationSetAuthorityV1, B4NegativeMaterializationSetAuthorityV2,
            B4NegativeMaterializationSetExternalInputsV1,
        },
        b4_negative_ancestry_authority::{
            B4NegativeAncestryWitnessCatalogAuthorityV1,
            B4NegativeAncestryWitnessCatalogAuthorityV2,
        },
        b4_positive_gate::B4PositiveGenerationAuthorityV1,
        b4_terminal_evidence_packet::B4TerminalEvidenceImportAuthorityV2,
        b4_terminal_source_lineage::{
            B4TerminalSourceLineageAuthorityV1, B4TerminalSourceLineageAuthorityV2,
        },
    };

    use super::{
        create_only,
        custody::{CampaignRootCustody, CurrentExecutableObservation, ImmutableRootCustody},
        preflight::{
            GenericCreateOnlyCampaignLayout, ProjectedCampaignLayout, ProjectedOuterCampaignLayout,
        },
        typestate::ExecutorExecuteContext,
    };

    #[cfg(all(target_os = "linux", feature = "b4-negative-materialization-handler"))]
    use super::prepare_negative_materialization_set::{
        NegativeMaterializationDescriptorRootPlanV1, NegativeMaterializationDescriptorRootPlanV2,
    };

    /// Typed executor boundary whose effect and custody postcheck can fail together.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum CustodyPostcheckBoundaryV1 {
        /// Final affine executor completion boundary.
        ExecutorCompletion,
        /// Proof-effect custody boundary.
        ProofEffect,
        /// Filesystem-mutation custody boundary.
        MutationEffect,
        /// Bound-child-launch custody boundary.
        ChildLaunchEffect,
        /// Retained host-rootfs reauthentication after the continuation window.
        RetainedHostRootfsContinuationReauthentication,
        /// Explicit retained host-rootfs cleanup after every continuation outcome.
        RetainedHostRootfsCleanup,
        /// Cleanup of a retained host-rootfs value after mutation postcheck failure.
        RetainedHostRootfsMutationPostcheckCleanup,
    }

    impl CustodyPostcheckBoundaryV1 {
        const fn label(self) -> &'static str {
            match self {
                Self::ExecutorCompletion => "executor completion",
                Self::ProofEffect => "proof effect",
                Self::MutationEffect => "mutation effect",
                Self::ChildLaunchEffect => "child-launch effect",
                Self::RetainedHostRootfsContinuationReauthentication => {
                    "retained host-rootfs continuation reauthentication"
                }
                Self::RetainedHostRootfsCleanup => "retained host-rootfs cleanup",
                Self::RetainedHostRootfsMutationPostcheckCleanup => {
                    "retained host-rootfs mutation-postcheck cleanup"
                }
            }
        }
    }

    /// Retains both typed errors when an executor effect and its postcheck fail.
    #[derive(Debug)]
    pub(super) struct CustodyPostcheckCombinedFailureV1 {
        boundary: CustodyPostcheckBoundaryV1,
        effect: anyhow::Error,
        postcheck: anyhow::Error,
    }

    impl CustodyPostcheckCombinedFailureV1 {
        /// Return the executor boundary which observed both failures.
        pub(super) const fn boundary(&self) -> CustodyPostcheckBoundaryV1 {
            self.boundary
        }

        /// Return the typed effect failure.
        pub(super) const fn effect(&self) -> &anyhow::Error {
            &self.effect
        }

        /// Return the typed custody-postcheck failure.
        pub(super) const fn postcheck(&self) -> &anyhow::Error {
            &self.postcheck
        }

        /// Consume the combined failure and return both owned error branches.
        ///
        /// Returning the pair in one transition prevents a caller from
        /// extracting one retry custody while implicitly dropping the other.
        pub(super) fn into_parts(
            self,
        ) -> (CustodyPostcheckBoundaryV1, anyhow::Error, anyhow::Error) {
            (self.boundary, self.effect, self.postcheck)
        }
    }

    impl fmt::Display for CustodyPostcheckCombinedFailureV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "{} failed ({:#}) and its custody postcheck also failed ({:#})",
                self.boundary.label(),
                self.effect,
                self.postcheck
            )
        }
    }

    impl std::error::Error for CustodyPostcheckCombinedFailureV1 {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(self.postcheck.as_ref())
        }
    }

    /// Unforgeable proof-effect token available only inside the checked wrapper.
    pub(super) struct ProofCapability<'context, const ROOTS: usize> {
        immutable_roots: &'context ImmutableRootCustody<ROOTS>,
        _private: (),
    }

    /// Unforgeable mutation token available only inside the checked wrapper.
    pub(super) struct MutationCapability<
        'context,
        const ROOTS: usize,
        Layout = ProjectedOuterCampaignLayout<ROOTS>,
    >
    where
        Layout: ProjectedCampaignLayout<ROOTS>,
    {
        executable: &'context CurrentExecutableObservation,
        campaign_root: &'context CampaignRootCustody,
        projected_layout: &'context Layout,
        immutable_roots: &'context ImmutableRootCustody<ROOTS>,
        _private: (),
    }

    /// Unforgeable child-launch token available only inside the checked wrapper.
    pub(super) struct ChildLaunchCapability {
        _private: (),
    }

    pub(super) fn with_proof<const ROOTS: usize, Layout, T>(
        context: &mut ExecutorExecuteContext<ROOTS, Layout>,
        effect: impl FnOnce(&mut ProofCapability<'_, ROOTS>) -> Result<T>,
    ) -> Result<T>
    where
        Layout: ProjectedCampaignLayout<ROOTS>,
    {
        context.recheck()?;
        let outcome = {
            let mut capability = ProofCapability {
                immutable_roots: context.immutable_roots(),
                _private: (),
            };
            effect(&mut capability)
        };
        finish_outcome(
            outcome,
            context.recheck(),
            CustodyPostcheckBoundaryV1::ProofEffect,
        )
    }

    pub(super) fn with_mutation<const ROOTS: usize, Layout, T>(
        context: &mut ExecutorExecuteContext<ROOTS, Layout>,
        effect: impl FnOnce(&mut MutationCapability<'_, ROOTS, Layout>) -> Result<T>,
    ) -> Result<T>
    where
        Layout: ProjectedCampaignLayout<ROOTS>,
    {
        context.recheck()?;
        let mut capability = MutationCapability {
            executable: context.executable(),
            campaign_root: context.campaign_root(),
            projected_layout: context.projected_layout(),
            immutable_roots: context.immutable_roots(),
            _private: (),
        };
        let outcome = effect(&mut capability);
        finish_outcome(
            outcome,
            context.recheck(),
            CustodyPostcheckBoundaryV1::MutationEffect,
        )
    }

    pub(super) fn with_retained_mutation<const ROOTS: usize, Layout, T>(
        context: &mut ExecutorExecuteContext<ROOTS, Layout>,
        effect: impl FnOnce(&mut MutationCapability<'_, ROOTS, Layout>) -> Result<T>,
        cleanup: impl FnOnce(T) -> Result<()>,
    ) -> Result<T>
    where
        Layout: ProjectedCampaignLayout<ROOTS>,
    {
        context.recheck()?;
        let mut capability = MutationCapability {
            executable: context.executable(),
            campaign_root: context.campaign_root(),
            projected_layout: context.projected_layout(),
            immutable_roots: context.immutable_roots(),
            _private: (),
        };
        let outcome = effect(&mut capability);
        finish_retained_mutation_outcome(outcome, context.recheck(), cleanup)
    }

    pub(super) fn finish_retained_mutation_outcome<T>(
        outcome: Result<T>,
        postcheck: Result<()>,
        cleanup: impl FnOnce(T) -> Result<()>,
    ) -> Result<T> {
        match (outcome, postcheck) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), postcheck) => finish_outcome(
                Err(error),
                postcheck,
                CustodyPostcheckBoundaryV1::MutationEffect,
            ),
            (Ok(value), Err(postcheck)) => {
                let mutation_postcheck = postcheck.context(format!(
                    "{} completed but its custody postcheck failed",
                    CustodyPostcheckBoundaryV1::MutationEffect.label()
                ));
                finish_outcome(
                    Err(mutation_postcheck),
                    cleanup(value),
                    CustodyPostcheckBoundaryV1::RetainedHostRootfsMutationPostcheckCleanup,
                )
            }
        }
    }

    pub(super) fn with_child_launch<const ROOTS: usize, Layout, T>(
        context: &mut ExecutorExecuteContext<ROOTS, Layout>,
        effect: impl FnOnce(&mut ChildLaunchCapability) -> Result<T>,
    ) -> Result<T>
    where
        Layout: ProjectedCampaignLayout<ROOTS>,
    {
        context.recheck()?;
        let mut capability = ChildLaunchCapability { _private: () };
        let outcome = effect(&mut capability);
        finish_outcome(
            outcome,
            context.recheck(),
            CustodyPostcheckBoundaryV1::ChildLaunchEffect,
        )
    }

    pub(super) fn finish_outcome<T>(
        outcome: Result<T>,
        postcheck: Result<()>,
        boundary: CustodyPostcheckBoundaryV1,
    ) -> Result<T> {
        match (outcome, postcheck) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(postcheck)) => Err(postcheck).context(format!(
                "{} completed but its custody postcheck failed",
                boundary.label()
            )),
            (Err(effect), Err(postcheck)) => {
                Err(anyhow::Error::new(CustodyPostcheckCombinedFailureV1 {
                    boundary,
                    effect,
                    postcheck,
                }))
            }
        }
    }

    impl<'context, const ROOTS: usize, Layout> MutationCapability<'context, ROOTS, Layout>
    where
        Layout: ProjectedCampaignLayout<ROOTS>,
    {
        /// Begin the exact descriptor-rooted outer transaction bound at preflight.
        pub(super) fn begin_create_only_directory(
            &mut self,
        ) -> Result<create_only::CreateOnlyDirectoryTransaction<'_>>
        where
            Layout: GenericCreateOnlyCampaignLayout<ROOTS>,
        {
            create_only::begin_create_only_directory_transaction(self)
        }

        pub(super) const fn projected_layout(&self) -> &'context Layout {
            self.projected_layout
        }

        pub(super) const fn immutable_roots(&self) -> &'context ImmutableRootCustody<ROOTS> {
            self.immutable_roots
        }

        pub(super) const fn campaign_root(&self) -> &'context CampaignRootCustody {
            self.campaign_root
        }

        pub(super) fn recheck(&self) -> Result<()> {
            self.executable.recheck()?;
            self.campaign_root.recheck()?;
            self.immutable_roots.recheck()?;
            self.campaign_root.recheck()?;
            self.executable.recheck()
        }
    }

    impl<const ROOTS: usize> ProofCapability<'_, ROOTS> {
        /// Close the fixed E5 terminal/ancestry proof operation without lending
        /// raw descriptor authority to the handler callback.
        #[cfg(all(target_os = "linux", feature = "b4-negative-materialization-handler"))]
        #[allow(
            clippy::too_many_arguments,
            reason = "the fixed operation retains every independently authenticated semantic authority"
        )]
        pub(super) fn close_negative_materialization_authority(
            &self,
            root_plan: NegativeMaterializationDescriptorRootPlanV1,
            configured_executor_artifact: &Path,
            campaign_precommit_identity: &B4ContractArtifactIdentityV1,
            campaign: &B4CampaignPrecommitAuthorityV1,
            positive: &B4PositiveGenerationAuthorityV1,
            lineage: B4TerminalSourceLineageAuthorityV1,
            ancestry: &B4NegativeAncestryWitnessCatalogAuthorityV1,
            external: &B4NegativeMaterializationSetExternalInputsV1<'_>,
        ) -> Result<B4NegativeMaterializationSetAuthorityV1> {
            self.immutable_roots
                .close_negative_materialization_authority(
                    root_plan,
                    configured_executor_artifact,
                    campaign_precommit_identity,
                    campaign,
                    positive,
                    lineage,
                    ancestry,
                    external,
                )
        }

        /// Close the V2 fixed terminal/ancestry proof operation without lending
        /// raw descriptor authority to the handler callback.
        #[cfg(all(target_os = "linux", feature = "b4-negative-materialization-handler"))]
        #[allow(
            clippy::too_many_arguments,
            reason = "the fixed V2 operation retains every independently authenticated semantic authority"
        )]
        pub(super) fn close_negative_materialization_authority_v2(
            &self,
            root_plan: NegativeMaterializationDescriptorRootPlanV2,
            configured_executor_artifact: &Path,
            campaign_precommit_identity: &B4ContractArtifactIdentityV1,
            campaign: &B4CampaignPrecommitAuthorityV1,
            positive: &B4PositiveGenerationAuthorityV2,
            lineage: B4TerminalSourceLineageAuthorityV2,
            ancestry: &B4NegativeAncestryWitnessCatalogAuthorityV2,
            external: &B4NegativeMaterializationSetExternalInputsV1<'_>,
        ) -> Result<B4NegativeMaterializationSetAuthorityV2> {
            self.immutable_roots
                .close_negative_materialization_authority_v2(
                    root_plan,
                    configured_executor_artifact,
                    campaign_precommit_identity,
                    campaign,
                    positive,
                    lineage,
                    ancestry,
                    external,
                )
        }

        /// Authenticate the V2 terminal import without widening proof custody
        /// to the still-V1 negative-ancestry authority.
        #[cfg(all(target_os = "linux", feature = "b4-negative-materialization-handler"))]
        #[allow(
            clippy::too_many_arguments,
            reason = "the V2 terminal import retains every independently authenticated semantic authority"
        )]
        pub(super) fn close_terminal_import_authority_v2(
            &self,
            terminal_campaign_root_index: usize,
            configured_executor_artifact: &Path,
            campaign_precommit_identity: &B4ContractArtifactIdentityV1,
            campaign: &B4CampaignPrecommitAuthorityV1,
            positive: &B4PositiveGenerationAuthorityV2,
            lineage: B4TerminalSourceLineageAuthorityV2,
        ) -> Result<B4TerminalEvidenceImportAuthorityV2> {
            self.immutable_roots.close_terminal_import_authority_v2(
                terminal_campaign_root_index,
                configured_executor_artifact,
                campaign_precommit_identity,
                campaign,
                positive,
                lineage,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use syn::visit::Visit as _;

    #[cfg(target_os = "linux")]
    use super::preflight::project_single_subtree_campaign_layout;
    use super::{
        capability::{
            CustodyPostcheckBoundaryV1, CustodyPostcheckCombinedFailureV1, finish_outcome,
            finish_retained_mutation_outcome,
        },
        create_only::project_create_only_directory_layout,
        oci_image_layout_import::{
            AuthenticatedOciOuterUstarImportCompletionV1,
            AuthenticatedOciRetainedHostRootfsInventoryV1,
            AuthenticatedOciRootfsIdentityCompletionV1,
        },
        preflight::{
            AuthenticatedPrepareInputSetOciTopologyV1, GenericCreateOnlyCampaignLayout,
            ProjectedOciImageLayoutCaptureSlotV1, ProjectedOuterCampaignLayout,
            ProjectedPrepareInputSetCampaignLayout, ProjectedPrepareInputSetOciCaptureV1,
            ProjectedSingleSubtreeCampaignLayout, project_outer_campaign_layout,
            project_prepare_input_set_campaign_layout,
            project_prepare_input_set_oci_capture_test_only,
        },
        typestate::{
            AuthenticatedOciReplayContinuationV1,
            AuthenticatedPrepareInputSetExecutionCompletionV1,
            AuthenticatedPrepareInputSetOciPreflightContext, ExecutorPreflightContext,
        },
    };

    fn token_string_v1(value: &(impl quote::ToTokens + ?Sized)) -> String {
        value.to_token_stream().to_string()
    }

    fn non_doc_attribute_tokens_v1(attributes: &[syn::Attribute]) -> Vec<String> {
        attributes
            .iter()
            .filter(|attribute| !attribute.path().is_ident("doc"))
            .map(token_string_v1)
            .collect()
    }

    fn parsed_outer_attribute_tokens_v1(source: &str) -> Vec<String> {
        let file = syn::parse_file(&format!("{source}\nfn attribute_fixture_v1() {{}}"))
            .expect("expected Rust outer attributes must parse");
        let syn::Item::Fn(function) = &file.items[0] else {
            panic!("attribute fixture must parse as a function");
        };
        non_doc_attribute_tokens_v1(&function.attrs)
    }

    fn parsed_file_attribute_tokens_v1(source: &str) -> Vec<String> {
        let file = syn::parse_file(source).expect("expected Rust file attributes must parse");
        non_doc_attribute_tokens_v1(&file.attrs)
    }

    fn assert_exact_non_doc_attributes_v1(
        actual: &[syn::Attribute],
        expected_source: &str,
        description: &str,
    ) {
        assert_eq!(
            non_doc_attribute_tokens_v1(actual),
            parsed_outer_attribute_tokens_v1(expected_source),
            "{description} attribute closure drift"
        );
    }

    fn assert_exact_file_attributes_v1(
        actual: &syn::File,
        expected_source: &str,
        description: &str,
    ) {
        assert_eq!(
            non_doc_attribute_tokens_v1(&actual.attrs),
            parsed_file_attribute_tokens_v1(expected_source),
            "{description} file attribute closure drift"
        );
    }

    fn assert_visibility_v1(actual: &syn::Visibility, expected_source: &str, description: &str) {
        let expected = syn::parse_str::<syn::ItemFn>(&format!(
            "{expected_source} fn visibility_fixture_v1() {{}}"
        ))
        .expect("expected Rust visibility must parse");
        assert_eq!(
            token_string_v1(actual),
            token_string_v1(&expected.vis),
            "{description} visibility drift"
        );
    }

    fn unique_direct_module_v1<'a>(items: &'a [syn::Item], name: &str) -> &'a syn::ItemMod {
        let matches = items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Mod(module) if module.ident == name => Some(module),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "expected one direct module item: {name}");
        matches[0]
    }

    fn unique_direct_function_v1<'a>(items: &'a [syn::Item], name: &str) -> &'a syn::ItemFn {
        let matches = items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Fn(function) if function.sig.ident == name => Some(function),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            matches.len(),
            1,
            "expected one direct function item: {name}"
        );
        matches[0]
    }

    fn unique_direct_macro_v1<'a>(items: &'a [syn::Item], name: &str) -> &'a syn::ItemMacro {
        let matches = items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Macro(item_macro) if item_macro.mac.path.is_ident(name) => {
                    Some(item_macro)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "expected one direct macro item: {name}");
        matches[0]
    }

    fn unique_direct_struct_v1<'a>(items: &'a [syn::Item], name: &str) -> &'a syn::ItemStruct {
        let matches = items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Struct(item_struct) if item_struct.ident == name => Some(item_struct),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "expected one direct struct item: {name}");
        matches[0]
    }

    fn inline_module_items_v1<'a>(module: &'a syn::ItemMod, name: &str) -> &'a [syn::Item] {
        &module
            .content
            .as_ref()
            .unwrap_or_else(|| panic!("module must remain inline: {name}"))
            .1
    }

    fn parsed_function_v1(source: &str) -> syn::ItemFn {
        syn::parse_str(source).expect("expected Rust function must parse")
    }

    fn assert_exact_function_v1(actual: &syn::ItemFn, expected_source: &str, description: &str) {
        let expected = parsed_function_v1(expected_source);
        assert_function_signature_v1(actual, expected_source, description);
        assert_eq!(
            token_string_v1(actual.block.as_ref()),
            token_string_v1(expected.block.as_ref()),
            "{description} body drift"
        );
    }

    fn assert_function_signature_v1(
        actual: &syn::ItemFn,
        expected_source: &str,
        description: &str,
    ) {
        let expected = parsed_function_v1(expected_source);
        assert_eq!(
            token_string_v1(&actual.sig),
            token_string_v1(&expected.sig),
            "{description} signature drift"
        );
    }

    #[derive(Default)]
    struct ConditionalInnerAttributeVisitorV1 {
        count: usize,
    }

    impl<'ast> syn::visit::Visit<'ast> for ConditionalInnerAttributeVisitorV1 {
        fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
            if matches!(attribute.style, syn::AttrStyle::Inner(_))
                && (attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr"))
            {
                self.count += 1;
            }
        }
    }

    fn assert_no_conditional_inner_attributes_v1(file: &syn::File, description: &str) {
        let mut visitor = ConditionalInnerAttributeVisitorV1::default();
        visitor.visit_file(file);
        assert_eq!(
            visitor.count, 0,
            "{description} must not contain inner cfg or cfg_attr attributes"
        );
    }

    #[derive(Default)]
    struct ProductionItemMacroInventoryV1 {
        count: usize,
    }

    impl<'ast> syn::visit::Visit<'ast> for ProductionItemMacroInventoryV1 {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            if !is_test_only_item_v1(&item.attrs) {
                syn::visit::visit_item_mod(self, item);
            }
        }

        fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
            if !is_test_only_item_v1(&item.attrs) {
                self.count += 1;
            }
        }

        fn visit_impl_item_macro(&mut self, item: &'ast syn::ImplItemMacro) {
            if !is_test_only_item_v1(&item.attrs) {
                self.count += 1;
            }
        }

        fn visit_trait_item_macro(&mut self, item: &'ast syn::TraitItemMacro) {
            if !is_test_only_item_v1(&item.attrs) {
                self.count += 1;
            }
        }

        fn visit_foreign_item_macro(&mut self, item: &'ast syn::ForeignItemMacro) {
            if !is_test_only_item_v1(&item.attrs) {
                self.count += 1;
            }
        }
    }

    fn assert_no_production_item_macros_v1(items: &[syn::Item], description: &str) {
        let mut inventory = ProductionItemMacroInventoryV1::default();
        for item in items {
            inventory.visit_item(item);
        }
        assert_eq!(
            inventory.count, 0,
            "{description} must not contain opaque item macros"
        );
    }

    fn is_test_only_item_v1(attributes: &[syn::Attribute]) -> bool {
        non_doc_attribute_tokens_v1(attributes)
            .iter()
            .any(|attribute| attribute == "# [cfg (test)]")
    }

    fn use_tree_mentions_ident_v1(tree: &syn::UseTree, target: &str) -> bool {
        match tree {
            syn::UseTree::Name(name) => name.ident == target,
            syn::UseTree::Rename(rename) => rename.ident == target || rename.rename == target,
            syn::UseTree::Path(path) => {
                path.ident == target || use_tree_mentions_ident_v1(path.tree.as_ref(), target)
            }
            syn::UseTree::Group(group) => group
                .items
                .iter()
                .any(|item| use_tree_mentions_ident_v1(item, target)),
            syn::UseTree::Glob(_) => false,
        }
    }

    fn use_tree_name_count_v1(tree: &syn::UseTree, target: &str) -> usize {
        match tree {
            syn::UseTree::Name(name) => usize::from(name.ident == target),
            syn::UseTree::Rename(rename) => usize::from(rename.ident == target),
            syn::UseTree::Path(path) => use_tree_name_count_v1(path.tree.as_ref(), target),
            syn::UseTree::Group(group) => group
                .items
                .iter()
                .map(|item| use_tree_name_count_v1(item, target))
                .sum(),
            syn::UseTree::Glob(_) => 0,
        }
    }

    fn use_tree_rename_count_v1(tree: &syn::UseTree, target: &str) -> usize {
        match tree {
            syn::UseTree::Rename(rename) => {
                usize::from(rename.ident == target || rename.rename == target)
            }
            syn::UseTree::Path(path) => use_tree_rename_count_v1(path.tree.as_ref(), target),
            syn::UseTree::Group(group) => group
                .items
                .iter()
                .map(|item| use_tree_rename_count_v1(item, target))
                .sum(),
            syn::UseTree::Name(_) | syn::UseTree::Glob(_) => 0,
        }
    }

    fn use_tree_glob_count_v1(tree: &syn::UseTree) -> usize {
        match tree {
            syn::UseTree::Path(path) => use_tree_glob_count_v1(path.tree.as_ref()),
            syn::UseTree::Group(group) => group.items.iter().map(use_tree_glob_count_v1).sum(),
            syn::UseTree::Glob(_) => 1,
            syn::UseTree::Name(_) | syn::UseTree::Rename(_) => 0,
        }
    }

    #[derive(Default)]
    struct PublicUseInventoryV1 {
        count: usize,
        glob_count: usize,
    }

    impl<'ast> syn::visit::Visit<'ast> for PublicUseInventoryV1 {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            if !is_test_only_item_v1(&item.attrs) {
                syn::visit::visit_item_mod(self, item);
            }
        }

        fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
            if !is_test_only_item_v1(&item.attrs) {
                if matches!(item.vis, syn::Visibility::Public(_)) {
                    self.count += 1;
                    self.glob_count += use_tree_glob_count_v1(&item.tree);
                }
                syn::visit::visit_item_use(self, item);
            }
        }
    }

    fn collect_dependency_table_v1<'a>(
        bindings: &mut Vec<(String, String, String, &'a toml::Value)>,
        scope: &str,
        dependencies: &'a toml::Table,
        canonical_package: &str,
    ) {
        for (dependency_key, specification) in dependencies {
            let effective_package = specification
                .as_table()
                .and_then(|table| table.get("package"))
                .map_or(dependency_key.as_str(), |package| {
                    package
                        .as_str()
                        .expect("Cargo dependency package override must be a string")
                });
            if dependency_key == canonical_package || effective_package == canonical_package {
                bindings.push((
                    scope.to_owned(),
                    dependency_key.clone(),
                    effective_package.to_owned(),
                    specification,
                ));
            }
        }
    }

    fn cargo_dependency_bindings_v1<'a>(
        manifest: &'a toml::Value,
        canonical_package: &str,
    ) -> Vec<(String, String, String, &'a toml::Value)> {
        let manifest = manifest
            .as_table()
            .expect("Generator Cargo.toml root must be a table");
        let mut bindings = Vec::new();
        for table_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
            if let Some(dependencies) = manifest.get(table_name) {
                collect_dependency_table_v1(
                    &mut bindings,
                    table_name,
                    dependencies
                        .as_table()
                        .unwrap_or_else(|| panic!("Cargo {table_name} must be a table")),
                    canonical_package,
                );
            }
        }
        if let Some(targets) = manifest.get("target") {
            for (target_name, target) in targets.as_table().expect("Cargo target must be a table") {
                let target = target
                    .as_table()
                    .unwrap_or_else(|| panic!("Cargo target {target_name} must be a table"));
                for table_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
                    if let Some(dependencies) = target.get(table_name) {
                        collect_dependency_table_v1(
                            &mut bindings,
                            &format!("target.{target_name}.{table_name}"),
                            dependencies.as_table().unwrap_or_else(|| {
                                panic!("Cargo target {target_name} {table_name} must be a table")
                            }),
                            canonical_package,
                        );
                    }
                }
            }
        }
        if let Some(workspace_dependencies) = manifest
            .get("workspace")
            .and_then(toml::Value::as_table)
            .and_then(|workspace| workspace.get("dependencies"))
        {
            collect_dependency_table_v1(
                &mut bindings,
                "workspace.dependencies",
                workspace_dependencies
                    .as_table()
                    .expect("Cargo workspace dependencies must be a table"),
                canonical_package,
            );
        }
        bindings
    }

    fn unique_locked_package_v1<'a>(
        lock: &'a toml::Value,
        name: &str,
        version: &str,
    ) -> &'a toml::Table {
        let packages = lock
            .get("package")
            .and_then(toml::Value::as_array)
            .expect("Cargo.lock package inventory must be an array");
        let matches = packages
            .iter()
            .filter_map(toml::Value::as_table)
            .filter(|package| {
                package.get("name").and_then(toml::Value::as_str) == Some(name)
                    && package.get("version").and_then(toml::Value::as_str) == Some(version)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            matches.len(),
            1,
            "expected one Cargo.lock package {name} {version}"
        );
        matches[0]
    }

    #[derive(Debug)]
    struct RetryCustodySentinelV1(u8);

    impl RetryCustodySentinelV1 {
        const fn retry_cleanup(self) -> u8 {
            self.0
        }
    }

    impl std::fmt::Display for RetryCustodySentinelV1 {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "retry custody sentinel {}", self.0)
        }
    }

    impl std::error::Error for RetryCustodySentinelV1 {}

    #[test]
    fn preflight_context_is_a_distinct_effect_free_type() {
        fn accepts_preflight<const ROOTS: usize>(_context: &ExecutorPreflightContext<ROOTS>) {}

        let _ = accepts_preflight::<1>;
    }

    #[test]
    fn single_subtree_projection_has_the_same_affine_capture_type() {
        let capture: fn(
            &std::path::Path,
            ProjectedSingleSubtreeCampaignLayout<1>,
        ) -> anyhow::Result<
            ExecutorPreflightContext<1, ProjectedSingleSubtreeCampaignLayout<1>>,
        > = ExecutorPreflightContext::capture;
        let _ = capture;
    }

    #[test]
    fn projected_oci_capture_has_one_exact_affine_preflight_signature() {
        let capture: fn(
            &std::path::Path,
            ProjectedPrepareInputSetOciCaptureV1<1>,
        ) -> anyhow::Result<
            ExecutorPreflightContext<1, ProjectedPrepareInputSetCampaignLayout<1>>,
        > = ExecutorPreflightContext::capture_with_projected_oci;
        let _ = capture;
    }

    #[test]
    fn authenticated_oci_capture_retains_import_slots_in_one_affine_context() {
        trait AmbiguousIfClone<Marker> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfClone<()> for T {}
        impl<T: Clone> AmbiguousIfClone<u8> for T {}

        trait AmbiguousIfCopy<Marker> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfCopy<()> for T {}
        impl<T: Copy> AmbiguousIfCopy<u8> for T {}

        type ExactContinuation = for<'execute, 'rootfs> fn(
            AuthenticatedOciReplayContinuationV1<'execute, 'rootfs, 1>,
        ) -> anyhow::Result<
            AuthenticatedPrepareInputSetExecutionCompletionV1<'execute, 1>,
        >;
        type ExactReplayContinuation = fn(
            AuthenticatedPrepareInputSetOciPreflightContext<1>,
            ExactContinuation,
        ) -> anyhow::Result<()>;

        let capture: fn(
            &std::path::Path,
            AuthenticatedPrepareInputSetOciTopologyV1<1>,
        )
            -> anyhow::Result<AuthenticatedPrepareInputSetOciPreflightContext<1>> =
            ExecutorPreflightContext::capture_with_authenticated_oci;
        let _ = capture;

        <AuthenticatedPrepareInputSetOciPreflightContext<1> as AmbiguousIfClone<_>>::marker();
        <AuthenticatedPrepareInputSetOciPreflightContext<1> as AmbiguousIfCopy<_>>::marker();
        <AuthenticatedOciOuterUstarImportCompletionV1<'_> as AmbiguousIfClone<_>>::marker();
        <AuthenticatedOciOuterUstarImportCompletionV1<'_> as AmbiguousIfCopy<_>>::marker();
        <AuthenticatedOciRootfsIdentityCompletionV1 as AmbiguousIfClone<_>>::marker();
        <AuthenticatedOciRootfsIdentityCompletionV1 as AmbiguousIfCopy<_>>::marker();
        <AuthenticatedOciRetainedHostRootfsInventoryV1 as AmbiguousIfClone<_>>::marker();
        <AuthenticatedOciRetainedHostRootfsInventoryV1 as AmbiguousIfCopy<_>>::marker();
        <AuthenticatedOciReplayContinuationV1<'_, '_, 1> as AmbiguousIfClone<_>>::marker();
        <AuthenticatedOciReplayContinuationV1<'_, '_, 1> as AmbiguousIfCopy<_>>::marker();
        <AuthenticatedPrepareInputSetExecutionCompletionV1<'_, 1> as AmbiguousIfClone<_>>::marker();
        <AuthenticatedPrepareInputSetExecutionCompletionV1<'_, 1> as AmbiguousIfCopy<_>>::marker();

        let fixed_replay: ExactReplayContinuation =
            AuthenticatedPrepareInputSetOciPreflightContext::with_authenticated_oci_replay::<
                ExactContinuation,
            >;
        std::hint::black_box(fixed_replay);
    }

    #[test]
    fn projected_oci_capture_inventory_is_not_cloneable_or_copyable() {
        trait AmbiguousIfClone<Marker> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfClone<()> for T {}
        impl<T: Clone> AmbiguousIfClone<u8> for T {}

        <ProjectedOciImageLayoutCaptureSlotV1 as AmbiguousIfClone<_>>::marker();
        <ProjectedPrepareInputSetOciCaptureV1<1> as AmbiguousIfClone<_>>::marker();
    }

    #[test]
    fn authenticated_oci_capture_has_one_tokenized_fixed_inventory_bridge() {
        let production = include_str!("mod.rs").split("#[cfg(test)]").next().unwrap();

        assert_eq!(production.matches("projected.into_parts()").count(), 1);
        assert!(!production.contains("authenticated.into_parts()"));
        assert_eq!(production.matches(".into_custody_parts(").count(), 1);
        assert_eq!(
            production
                .matches("OciTopologyCustodyBridgePermitV1 { _private: () }")
                .count(),
            1
        );
        assert_eq!(
            production.matches("Some(Vec::from(capture_slots))").count(),
            1
        );
        assert_eq!(
            production
                .matches("import_authenticated_oci_outer_ustar_inventory(")
                .count(),
            1
        );
        assert!(!production.contains("fn import_authenticated_oci_inventory("));
        let replay_continuation = production
            .split("pub(super) fn with_authenticated_oci_replay")
            .nth(1)
            .unwrap()
            .split("/// Execute-only context")
            .next()
            .unwrap();
        let mutation_postcheck = replay_continuation
            .find("let mut retained_rootfs = execute.with_retained_mutation")
            .unwrap();
        let continuation = replay_continuation
            .find("continue_with(continuation)")
            .unwrap();
        assert!(mutation_postcheck < continuation);
        assert!(!replay_continuation.contains("-> Result<T>"));
        assert!(!replay_continuation.contains("&mut ExecutorExecuteContext"));
        let compact_replay_continuation =
            replay_continuation.split_whitespace().collect::<String>();
        assert!(compact_replay_continuation.contains(
            "Continue:for<'execute,'rootfs>FnOnce(AuthenticatedOciReplayContinuationV1<'execute,'rootfs,ROOTS>,)->Result<AuthenticatedPrepareInputSetExecutionCompletionV1<'execute,ROOTS>"
        ));
        assert!(!replay_continuation.contains("continue_with(execute, completion)"));
        assert!(!replay_continuation.contains("continue_with(execute,"));
        assert!(!production.contains("[OciOuterUstarSlotV1;"));
        assert!(!production.contains("effect(execute, import_slots)"));
        assert_eq!(
            production
                .matches("Self::capture_inner(configured_artifact, layout, Some(slots))")
                .count(),
            1
        );
        assert_eq!(
            production
                .matches("Self::capture_inner(configured_artifact, projected_layout, None)")
                .count(),
            1
        );
    }

    #[test]
    fn authenticated_oci_replay_retains_physical_rootfs_in_the_same_mutation_session() {
        let production = include_str!("mod.rs").split("#[cfg(test)]").next().unwrap();
        let continuation_type = production
            .split("pub(super) struct AuthenticatedOciReplayContinuationV1")
            .nth(1)
            .unwrap()
            .split("/// Non-forgeable proof")
            .next()
            .unwrap();
        let compact_continuation_type = continuation_type.split_whitespace().collect::<String>();
        assert!(compact_continuation_type.contains(
            "_retained_rootfs:&'rootfsmutAuthenticatedOciRetainedHostRootfsInventoryV1,"
        ));
        assert!(!continuation_type.contains("AuthenticatedOciOuterUstarImportCompletionV1"));
        assert!(!continuation_type.contains("AuthenticatedOciRootfsIdentityCompletionV1"));

        let replay = production
            .split("pub(super) fn with_authenticated_oci_replay")
            .nth(1)
            .unwrap()
            .split("/// Execute-only context")
            .next()
            .unwrap();
        assert_eq!(replay.matches("execute.with_retained_mutation").count(), 1);
        assert!(!replay.contains("execute.with_mutation("));
        let compact_replay = replay.split_whitespace().collect::<String>();
        assert!(compact_replay.contains("letmutretained_rootfs=execute.with_retained_mutation("));
        assert!(compact_replay.contains(
            "|retained_rootfs|{retained_rootfs.cleanup().map(drop).map_err(anyhow::Error::new)},)?;"
        ));
        assert_eq!(replay.matches(".map_err(anyhow::Error::new)").count(), 3);
        assert_eq!(
            replay
                .matches(".authenticate_physical_rootfs_inventory_and_retain()")
                .count(),
            1
        );
        assert!(!replay.contains(".authenticate_physical_rootfs_inventory()"));
    }

    #[test]
    fn authenticated_oci_replay_borrows_retained_host_rootfs_until_owner_cleanup() {
        let production = include_str!("mod.rs").split("#[cfg(test)]").next().unwrap();
        let continuation_type = production
            .split("pub(super) struct AuthenticatedOciReplayContinuationV1")
            .nth(1)
            .unwrap()
            .split("/// Non-forgeable proof")
            .next()
            .unwrap();
        let compact_continuation = continuation_type.split_whitespace().collect::<String>();
        assert!(compact_continuation.contains(
            "_retained_rootfs:&'rootfsmutAuthenticatedOciRetainedHostRootfsInventoryV1,"
        ));
        assert!(!continuation_type.contains("AuthenticatedOciRootfsIdentityCompletionV1"));

        let replay = production
            .split("pub(super) fn with_authenticated_oci_replay")
            .nth(1)
            .unwrap()
            .split("/// Execute-only context")
            .next()
            .unwrap();
        let compact_replay = replay.split_whitespace().collect::<String>();
        let retain = compact_replay
            .find("authenticate_physical_rootfs_inventory_and_retain")
            .unwrap();
        assert_eq!(
            compact_replay
                .matches("reauthenticate_static_startup_dependencies()")
                .count(),
            2
        );
        let entry_reauthentication = compact_replay
            .find("reauthenticate_static_startup_dependencies()")
            .unwrap();
        let continuation = compact_replay.find("continue_with(continuation)").unwrap();
        let continuation_reauthentication = compact_replay
            .rfind("reauthenticate_static_startup_dependencies()")
            .unwrap();
        assert_eq!(
            compact_replay.matches("retained_rootfs.cleanup()").count(),
            2
        );
        assert_eq!(
            compact_replay
                .matches(".map_err(anyhow::Error::new)")
                .count(),
            3
        );
        let cleanup = compact_replay.rfind("retained_rootfs.cleanup()").unwrap();
        assert!(
            retain < entry_reauthentication
                && entry_reauthentication < continuation
                && continuation < continuation_reauthentication
                && continuation_reauthentication < cleanup
        );
        assert!(replay.contains("_retained_rootfs: &mut retained_rootfs"));
        assert!(replay.contains("continue_with(continuation).map(drop)"));
        assert!(replay.contains("capability::finish_outcome("));
    }

    #[test]
    fn retained_mutation_outcome_cleans_success_value_when_postcheck_fails() {
        use std::cell::Cell;

        let cleaned = Cell::new(false);
        let value = finish_retained_mutation_outcome(Ok(7_u8), Ok(()), |_| {
            cleaned.set(true);
            Ok(())
        })
        .unwrap();
        assert_eq!(value, 7);
        assert!(!cleaned.get());

        let cleaned = Cell::new(false);
        let error = finish_retained_mutation_outcome(
            Err::<u8, _>(anyhow::anyhow!("injected retained mutation failure")),
            Ok(()),
            |_| {
                cleaned.set(true);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("injected retained mutation failure"));
        assert!(!cleaned.get());

        let cleaned = Cell::new(false);
        let error = finish_retained_mutation_outcome(
            Ok(7_u8),
            Err(anyhow::anyhow!(
                "injected retained mutation postcheck failure"
            )),
            |_| {
                cleaned.set(true);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(cleaned.get());
        assert!(format!("{error:#}").contains("injected retained mutation postcheck failure"));

        let cleaned = Cell::new(false);
        let error = finish_retained_mutation_outcome(
            Ok(7_u8),
            Err(anyhow::anyhow!(
                "injected retained mutation postcheck failure"
            )),
            |_| {
                cleaned.set(true);
                Err(anyhow::anyhow!("injected retained cleanup failure"))
            },
        )
        .unwrap_err();
        assert!(cleaned.get());
        let combined = error
            .downcast_ref::<CustodyPostcheckCombinedFailureV1>()
            .unwrap();
        assert_eq!(
            combined.boundary(),
            CustodyPostcheckBoundaryV1::RetainedHostRootfsMutationPostcheckCleanup
        );
        assert!(format!("{:#}", combined.effect()).contains("postcheck failure"));
        assert!(format!("{:#}", combined.postcheck()).contains("cleanup failure"));
    }

    #[test]
    fn combined_custody_failure_returns_both_owned_branches_for_retry() {
        let error = finish_outcome::<()>(
            Err(anyhow::Error::new(RetryCustodySentinelV1(7))),
            Err(anyhow::Error::new(RetryCustodySentinelV1(9))),
            CustodyPostcheckBoundaryV1::RetainedHostRootfsCleanup,
        )
        .unwrap_err();
        let combined = error
            .downcast::<CustodyPostcheckCombinedFailureV1>()
            .expect("combined custody failure lost its owned type");
        let (boundary, effect, postcheck) = combined.into_parts();

        assert_eq!(
            boundary,
            CustodyPostcheckBoundaryV1::RetainedHostRootfsCleanup
        );
        assert_eq!(
            effect
                .downcast::<RetryCustodySentinelV1>()
                .expect("effect retry custody was not returned by value")
                .retry_cleanup(),
            7
        );
        assert_eq!(
            postcheck
                .downcast::<RetryCustodySentinelV1>()
                .expect("postcheck retry custody was not returned by value")
                .retry_cleanup(),
            9
        );
    }

    #[test]
    fn nested_combined_custody_failure_returns_every_owned_branch_for_retry() {
        let inner = finish_outcome::<()>(
            Err(anyhow::Error::new(RetryCustodySentinelV1(11))),
            Err(anyhow::Error::new(RetryCustodySentinelV1(12))),
            CustodyPostcheckBoundaryV1::RetainedHostRootfsMutationPostcheckCleanup,
        )
        .unwrap_err();
        let outer = finish_outcome::<()>(
            Err(anyhow::Error::new(RetryCustodySentinelV1(10))),
            Err(inner),
            CustodyPostcheckBoundaryV1::RetainedHostRootfsCleanup,
        )
        .unwrap_err();
        let outer = outer
            .downcast::<CustodyPostcheckCombinedFailureV1>()
            .expect("outer combined custody failure lost its owned type");
        let (outer_boundary, outer_effect, outer_postcheck) = outer.into_parts();
        let inner = outer_postcheck
            .downcast::<CustodyPostcheckCombinedFailureV1>()
            .expect("nested combined custody failure was not returned by value");
        let (inner_boundary, inner_effect, inner_postcheck) = inner.into_parts();

        assert_eq!(
            outer_boundary,
            CustodyPostcheckBoundaryV1::RetainedHostRootfsCleanup
        );
        assert_eq!(
            inner_boundary,
            CustodyPostcheckBoundaryV1::RetainedHostRootfsMutationPostcheckCleanup
        );
        assert_eq!(
            outer_effect
                .downcast::<RetryCustodySentinelV1>()
                .unwrap()
                .retry_cleanup(),
            10
        );
        assert_eq!(
            inner_effect
                .downcast::<RetryCustodySentinelV1>()
                .unwrap()
                .retry_cleanup(),
            11
        );
        assert_eq!(
            inner_postcheck
                .downcast::<RetryCustodySentinelV1>()
                .unwrap()
                .retry_cleanup(),
            12
        );
    }

    #[test]
    fn authenticated_oci_custody_parts_are_consumed_by_one_production_bridge_recursively() {
        use std::{fs, path::Path};

        let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/b4_campaign_executor");
        let origin = source_root.join("mod.rs");
        let projected_call = ["projected", ".", "into_parts", "()"].concat();
        let authenticated_call = [".", "into_custody_parts", "("].concat();
        let associated_call = ["::", "into_parts"].concat();
        let mut pending = vec![source_root];
        let mut total_projected_calls = 0_usize;
        let mut total_authenticated_calls = 0_usize;
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                let file_type = entry.file_type().unwrap();
                assert!(!file_type.is_symlink(), "OCI source audit rejects symlinks");
                let path = entry.path();
                if file_type.is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
                    continue;
                }
                let source = fs::read_to_string(&path).unwrap().replace("\r\n", "\n");
                let test_module_start = source
                    .match_indices("#[cfg(test)]")
                    .filter_map(|(index, _)| {
                        source[index + "#[cfg(test)]".len()..]
                            .trim_start()
                            .starts_with("mod tests")
                            .then_some(index)
                    })
                    .last()
                    .unwrap_or(source.len());
                let production = &source[..test_module_start];
                let projected_calls = production.matches(&projected_call).count();
                let authenticated_calls = production.matches(&authenticated_call).count();
                let associated_calls = production.matches(&associated_call).count();
                if path == origin {
                    assert_eq!(projected_calls, 1);
                    assert_eq!(authenticated_calls, 1);
                } else {
                    assert_eq!(
                        projected_calls,
                        0,
                        "unexpected projected OCI bridge in {}",
                        path.display()
                    );
                    assert_eq!(
                        authenticated_calls,
                        0,
                        "unexpected authenticated OCI bridge in {}",
                        path.display()
                    );
                }
                assert_eq!(
                    associated_calls,
                    0,
                    "unexpected associated OCI bridge in {}",
                    path.display()
                );
                total_projected_calls = total_projected_calls.checked_add(projected_calls).unwrap();
                total_authenticated_calls = total_authenticated_calls
                    .checked_add(authenticated_calls)
                    .unwrap();
            }
        }
        assert_eq!(total_projected_calls, 1);
        assert_eq!(total_authenticated_calls, 1);
    }

    #[test]
    fn e5_immutable_root_adapter_has_no_raw_descriptor_escape_recursively() {
        use std::{fs, path::Path};

        let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/b4_campaign_executor");
        let mut pending = vec![source_root.clone()];
        let mut raw_root_callback_definitions = Vec::new();
        let mut raw_root_callback_calls = 0_usize;
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                let file_type = entry.file_type().unwrap();
                assert!(
                    !file_type.is_symlink(),
                    "root-descriptor source audit rejects symlinks"
                );
                let path = entry.path();
                if file_type.is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
                    continue;
                }
                let source = fs::read_to_string(&path).unwrap().replace("\r\n", "\n");
                let test_module_start = source
                    .match_indices("#[cfg(test)]")
                    .filter_map(|(index, _)| {
                        source[index + "#[cfg(test)]".len()..]
                            .trim_start()
                            .starts_with("mod tests")
                            .then_some(index)
                    })
                    .last()
                    .unwrap_or(source.len());
                let production = &source[..test_module_start];
                let relative = path
                    .strip_prefix(&source_root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");

                assert!(
                    !production.contains("with_immutable_root_descriptor"),
                    "generic immutable-root descriptor callback remains in {relative}"
                );
                if production.contains("fn with_root_descriptor<") {
                    raw_root_callback_definitions.push(relative.clone());
                }
                raw_root_callback_calls = raw_root_callback_calls
                    .checked_add(production.matches(".with_root_descriptor(").count())
                    .unwrap();
                if relative != "custody.rs" {
                    assert!(
                        !production.contains(".with_root_descriptor("),
                        "raw root-descriptor callback escapes custody through {relative}"
                    );
                }
                if relative == "mod.rs" {
                    let capability = production.split("mod capability {").nth(1).unwrap();
                    assert!(!capability.contains("BorrowedFd"));
                    assert!(!capability.contains("with_root_descriptor"));
                }
            }
        }
        assert_eq!(raw_root_callback_definitions, ["custody.rs"]);
        assert_eq!(
            raw_root_callback_calls, 6,
            "the four fixed adapters must borrow only their declared roots (2 + 2 + 1 + 1)"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn projected_oci_capture_rechecks_the_retained_exact_role_plan() {
        use std::fs;

        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let inputs = campaign.join("inputs");
        let outer_final = campaign.join("runs").join("run-001");
        fs::create_dir_all(&inputs).unwrap();
        fs::create_dir_all(outer_final.parent().unwrap()).unwrap();
        fs::write(inputs.join("layout.oci.tar"), [0x45_u8; 6_144]).unwrap();
        let layout =
            project_prepare_input_set_campaign_layout(&campaign, [&inputs], &outer_final).unwrap();
        let projected =
            project_prepare_input_set_oci_capture_test_only(layout, &[(0, "layout.oci.tar")])
                .unwrap();
        let executable = fs::read_link("/proc/self/exe").unwrap();

        let preflight =
            ExecutorPreflightContext::capture_with_projected_oci(&executable, projected).unwrap();
        let generic_read = preflight
            .read_immutable_file::<6_144>(0, "layout.oci.tar")
            .unwrap_err();
        assert!(format!("{generic_read:#}").contains("projected OCI"));

        fs::write(inputs.join("layout.oci.tar"), [0x46_u8; 6_145]).unwrap();
        let error = preflight.finish_preflight().unwrap_err();
        assert!(format!("{error:#}").contains("multiple"), "{error:#}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn projected_oci_role_is_bound_to_one_exact_root_index() {
        use std::fs;

        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let first = campaign.join("inputs-first");
        let second = campaign.join("inputs-second");
        let outer_final = campaign.join("runs").join("run-001");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        fs::create_dir_all(outer_final.parent().unwrap()).unwrap();
        fs::write(first.join("layout.oci.tar"), [0x45_u8; 6_144]).unwrap();
        fs::write(second.join("layout.oci.tar"), [0x46_u8; 6_144]).unwrap();
        let layout =
            project_prepare_input_set_campaign_layout(&campaign, [&first, &second], &outer_final)
                .unwrap();
        let projected =
            project_prepare_input_set_oci_capture_test_only(layout, &[(0, "layout.oci.tar")])
                .unwrap();
        let executable = fs::read_link("/proc/self/exe").unwrap();

        let preflight =
            ExecutorPreflightContext::capture_with_projected_oci(&executable, projected).unwrap();
        let role_error = preflight
            .read_immutable_file::<6_144>(0, "layout.oci.tar")
            .unwrap_err();
        assert!(format!("{role_error:#}").contains("projected OCI"));
        assert_eq!(
            preflight
                .read_immutable_file::<6_144>(1, "layout.oci.tar")
                .unwrap(),
            [0x46_u8; 6_144]
        );
        preflight.finish_preflight().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn projected_oci_capture_rejects_same_length_bytes_and_ancestor_replacement() {
        use std::fs;

        for replace_ancestor in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let campaign = temp.path().join("campaign");
            let inputs = campaign.join("inputs");
            let images = inputs.join("images");
            let outer_final = campaign.join("runs").join("run-001");
            fs::create_dir_all(&images).unwrap();
            fs::create_dir_all(outer_final.parent().unwrap()).unwrap();
            fs::write(images.join("layout.oci.tar"), [0x45_u8; 6_144]).unwrap();
            let layout =
                project_prepare_input_set_campaign_layout(&campaign, [&inputs], &outer_final)
                    .unwrap();
            let projected = project_prepare_input_set_oci_capture_test_only(
                layout,
                &[(0, "images/layout.oci.tar")],
            )
            .unwrap();
            let executable = fs::read_link("/proc/self/exe").unwrap();
            let preflight =
                ExecutorPreflightContext::capture_with_projected_oci(&executable, projected)
                    .unwrap();

            if replace_ancestor {
                fs::rename(&images, inputs.join("images-old")).unwrap();
                fs::create_dir(&images).unwrap();
                fs::write(images.join("layout.oci.tar"), [0x45_u8; 6_144]).unwrap();
            } else {
                fs::write(images.join("layout.oci.tar"), [0x46_u8; 6_144]).unwrap();
            }
            let error = preflight.finish_preflight().unwrap_err();
            assert!(format!("{error:#}").contains("immutable root"), "{error:#}");
        }
    }

    #[test]
    fn projected_oci_capture_is_linux_only_before_path_inspection() {
        if cfg!(target_os = "linux") {
            return;
        }

        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let prior = campaign.join("inputs");
        let outer_final = campaign.join("runs").join("run-001");
        let layout =
            project_prepare_input_set_campaign_layout(&campaign, [&prior], &outer_final).unwrap();
        let projected =
            project_prepare_input_set_oci_capture_test_only(layout, &[(0, "layout.oci.tar")])
                .unwrap();
        let Err(error) = ExecutorPreflightContext::capture_with_projected_oci(
            std::path::Path::new("missing-relative-executable"),
            projected,
        ) else {
            panic!("projected OCI capture unexpectedly passed outside Linux");
        };
        assert!(error.to_string().contains("requires Linux"));
    }

    #[test]
    fn generic_create_only_gate_excludes_the_ordered_h0_layout() {
        trait AmbiguousIfGeneric<Marker> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfGeneric<()> for T {}
        impl<T: ?Sized + GenericCreateOnlyCampaignLayout<1>> AmbiguousIfGeneric<u8> for T {}

        fn accepts_generic<const ROOTS: usize, Layout>()
        where
            Layout: GenericCreateOnlyCampaignLayout<ROOTS>,
        {
        }

        let _ = accepts_generic::<1, ProjectedOuterCampaignLayout<1>>;
        let _ = accepts_generic::<1, ProjectedSingleSubtreeCampaignLayout<1>>;

        <ProjectedPrepareInputSetCampaignLayout<1> as AmbiguousIfGeneric<_>>::marker();
    }

    #[test]
    fn outer_projection_and_create_only_layout_share_one_outer_staging_path() {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let outer_final = campaign.join("runs").join("run-001");
        let projection = project_outer_campaign_layout(
            &campaign,
            [&campaign.join("inputs")],
            &outer_final,
            [
                "terminal-evidence-campaign-receipt.json",
                "run-summary.json",
            ],
        )
        .unwrap();
        let create_only = project_create_only_directory_layout(&outer_final).unwrap();

        assert_eq!(
            projection.outer_staging_root(),
            create_only.reserved_staging_path()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn single_subtree_projection_reaches_the_shared_create_only_gate() {
        use std::fs;

        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let inputs = campaign.join("inputs");
        let outer_final = campaign.join("runs").join("run-001");
        fs::create_dir_all(&inputs).unwrap();
        fs::create_dir_all(outer_final.parent().unwrap()).unwrap();
        fs::write(inputs.join("source.bin"), b"stable").unwrap();
        let layout = project_single_subtree_campaign_layout(
            &campaign,
            [&inputs],
            &outer_final,
            "reproduction",
        )
        .unwrap();
        let executable = fs::read_link("/proc/self/exe").unwrap();
        let preflight = ExecutorPreflightContext::capture(&executable, layout).unwrap();

        preflight
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    assert_eq!(
                        capability.projected_layout().staged_subtree_path(),
                        capability
                            .projected_layout()
                            .outer_staging_root()
                            .join("reproduction")
                    );
                    let mut transaction = capability.begin_create_only_directory()?;
                    transaction.create_directory("reproduction")?;
                    transaction.commit()
                })
            })
            .unwrap();

        let entries = fs::read_dir(&outer_final)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries, [std::ffi::OsString::from("reproduction")]);
        assert!(outer_final.join("reproduction").is_dir());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_preflight_rejects_occupied_outer_names_before_execute_mode() {
        use std::fs;

        for occupy_staging in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let campaign = temp.path().join("campaign");
            let inputs = campaign.join("inputs");
            let outer_final = campaign.join("runs").join("run-001");
            fs::create_dir_all(&inputs).unwrap();
            fs::create_dir_all(outer_final.parent().unwrap()).unwrap();
            fs::write(inputs.join("source.bin"), b"stable").unwrap();
            let layout =
                project_outer_campaign_layout(&campaign, [&inputs], &outer_final, ["receipt.json"])
                    .unwrap();
            let occupied = if occupy_staging {
                layout.outer_staging_root()
            } else {
                layout.outer_final_root()
            };
            fs::create_dir(occupied).unwrap();
            let before = fs::read_dir(outer_final.parent().unwrap())
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>();
            let executable = fs::read_link("/proc/self/exe").unwrap();

            let Err(error) = ExecutorPreflightContext::capture(&executable, layout) else {
                panic!("occupied outer name unexpectedly passed retained preflight");
            };

            assert!(format!("{error:#}").contains("occupied"));
            assert_eq!(
                fs::read_dir(outer_final.parent().unwrap())
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name())
                    .collect::<Vec<_>>(),
                before
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn execute_effects_and_final_outcomes_always_repeat_custody_checks() {
        use std::fs;

        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let inputs = campaign.join("inputs");
        fs::create_dir_all(&inputs).unwrap();
        fs::write(inputs.join("source.bin"), b"stable").unwrap();
        let outer_final = campaign.join("runs").join("run-001");
        fs::create_dir_all(outer_final.parent().unwrap()).unwrap();
        let layout =
            project_outer_campaign_layout(&campaign, [&inputs], &outer_final, ["receipt.json"])
                .unwrap();
        let executable = fs::read_link("/proc/self/exe").unwrap();
        let preflight = ExecutorPreflightContext::capture(&executable, layout).unwrap();
        let error = preflight
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    let mut transaction = capability.begin_create_only_directory()?;
                    transaction.create_directory("terminal-evidence-packet")?;
                    transaction.create_file("receipt.json", b"marker", 64)?;
                    transaction.commit()
                })?;
                assert_eq!(
                    fs::read(outer_final.join("receipt.json")).unwrap(),
                    b"marker"
                );

                execute.with_proof(|_capability| -> anyhow::Result<()> {
                    fs::write(inputs.join("source.bin"), b"changed")?;
                    anyhow::bail!("injected proof failure")
                })
            })
            .unwrap_err();
        assert!(
            error.to_string().contains("executor completion")
                || error.to_string().contains("custody postcheck")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn projected_prior_roots_are_the_only_roots_captured_by_the_runner() {
        use std::fs;

        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let projected = campaign.join("projected");
        let unrelated = campaign.join("unrelated");
        let outer_final = campaign.join("runs").join("run-001");
        fs::create_dir_all(&projected).unwrap();
        fs::create_dir_all(&unrelated).unwrap();
        fs::create_dir_all(outer_final.parent().unwrap()).unwrap();
        fs::write(projected.join("source.bin"), b"projected").unwrap();
        fs::write(unrelated.join("source.bin"), b"unrelated").unwrap();
        let layout =
            project_outer_campaign_layout(&campaign, [&projected], &outer_final, ["marker.bin"])
                .unwrap();
        let executable = fs::read_link("/proc/self/exe").unwrap();
        let preflight = ExecutorPreflightContext::capture(&executable, layout).unwrap();

        let error = preflight
            .execute(|execute| {
                fs::write(projected.join("source.bin"), b"changed")?;
                execute.with_proof(|_capability| Ok(()))
            })
            .unwrap_err();
        assert!(error.to_string().contains("immutable root"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn campaign_swap_inside_mutation_gate_is_rejected_before_staging_creation() {
        use std::fs;

        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let inputs = campaign.join("inputs");
        let outer_final = campaign.join("runs").join("run-001");
        fs::create_dir_all(&inputs).unwrap();
        fs::create_dir_all(outer_final.parent().unwrap()).unwrap();
        fs::write(inputs.join("source.bin"), b"stable").unwrap();
        let layout =
            project_outer_campaign_layout(&campaign, [&inputs], &outer_final, ["receipt.json"])
                .unwrap();
        let executable = fs::read_link("/proc/self/exe").unwrap();
        let preflight = ExecutorPreflightContext::capture(&executable, layout).unwrap();
        let retained_campaign = temp.path().join("campaign-old");

        preflight
            .execute(|execute| {
                let error = execute
                    .with_mutation(|capability| {
                        fs::rename(&campaign, &retained_campaign)?;
                        fs::create_dir_all(campaign.join("runs"))?;
                        fs::create_dir_all(campaign.join("inputs"))?;
                        let error = capability.begin_create_only_directory().unwrap_err();
                        fs::remove_dir_all(&campaign)?;
                        fs::rename(&retained_campaign, &campaign)?;
                        Err::<(), _>(error)
                    })
                    .unwrap_err();
                assert!(
                    error.to_string().contains("campaign") || error.to_string().contains("custody")
                );
                assert!(!outer_final.exists());
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn supervisor_custody_exports_are_absent_v1() {
        let custody = include_str!("custody.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let module = include_str!("mod.rs").split("#[cfg(test)]").next().unwrap();
        let facade = include_str!("../lib.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let production = [custody, module, facade].join("\n");

        assert!(
            !facade.contains("pub use b4_campaign_executor"),
            "the generator root must not re-export any supervisor-side campaign item"
        );

        for forbidden in [
            "RetainedExecutableSnapshotV2",
            "RetainedExecutableCoreV2",
            "GeneratorExecutableSpawnInputsV2",
            "WorkerExecutableSpawnInputsV2",
            "RetainedMeasuredGeneratorExecutableV2",
            "RetainedMeasuredWorkerExecutableV2",
            "GeneratorExecutableReauthenticatedBeforeExecV2",
            "WorkerExecutableReauthenticatedBeforeExecV2",
            "GeneratorChildExecutableCustodyV2",
            "GeneratorExitedExecutableCustodyV2",
            "WorkerBlockedExecutableCustodyV2",
            "WorkerChildExecutableCustodyV2",
            "WorkerExitedExecutableCustodyV2",
            "retain_measured_generator_executable_v2",
            "retain_measured_worker_executable_v2",
            "GeneratorSpawnPlanV1",
            "WorkerSpawnPlanV1",
            "BlockedWorkerV1",
            "RunningChildV1",
            "spawn_generator_once_v1",
            "spawn_worker_once_v1",
            "release_after_checked_maps",
        ] {
            assert!(
                !production.contains(forbidden),
                "superseded supervisor custody survived E4b: {forbidden}"
            );
        }
    }

    #[test]
    fn linux_child_side_compile_closure_v1() {
        // Evidence ceiling: this test binds E4c source, manifest, lock, module,
        // export and probe topology. It does not compile the selected musl
        // dependency or prove ancillary receive/credential behavior; those
        // claims belong to the exact-musl gate and linux-abi owner tests.
        const MUSL_TARGET_ATTRIBUTE_V1: &str =
            "#[cfg(all(target_arch = \"x86_64\", target_os = \"linux\", target_env = \"musl\"))]";
        const TEST_OR_MUSL_ATTRIBUTE_V1: &str = "#[cfg(any(
    test,
    all(target_arch = \"x86_64\", target_os = \"linux\", target_env = \"musl\")
))]";
        let manifest_source = include_str!("../../Cargo.toml").replace("\r\n", "\n");
        let manifest = toml::from_str::<toml::Value>(&manifest_source)
            .expect("Generator Cargo.toml must parse structurally");
        let manifest_root = manifest
            .as_table()
            .expect("Generator Cargo.toml root must be a table");
        assert!(
            !manifest_root.contains_key("patch"),
            "Generator manifest must not override dependency sources through [patch]"
        );
        assert!(
            !manifest_root.contains_key("replace"),
            "Generator manifest must not override dependency sources through [replace]"
        );
        assert!(
            !manifest_root.contains_key("lib"),
            "Generator library target must remain the implicit src/lib.rs target"
        );
        let mut actual_root_keys = manifest_root.keys().map(String::as_str).collect::<Vec<_>>();
        actual_root_keys.sort_unstable();
        let mut expected_root_keys = vec![
            "bin",
            "dependencies",
            "dev-dependencies",
            "features",
            "lints",
            "package",
            "target",
            "workspace",
        ];
        expected_root_keys.sort_unstable();
        assert_eq!(
            actual_root_keys, expected_root_keys,
            "Generator manifest root topology drift"
        );
        let package = manifest_root
            .get("package")
            .and_then(toml::Value::as_table)
            .expect("Generator package table must remain explicit");
        assert_eq!(
            package.get("build").and_then(toml::Value::as_bool),
            Some(false),
            "Generator package must disable implicit build.rs discovery"
        );
        let library_source = include_str!("../lib.rs").replace("\r\n", "\n");
        let library_file =
            syn::parse_file(&library_source).expect("Generator src/lib.rs must parse as Rust");
        assert_no_conditional_inner_attributes_v1(&library_file, "Generator library source");
        assert_no_production_item_macros_v1(&library_file.items, "Generator library source");
        let campaign_module = unique_direct_module_v1(&library_file.items, "b4_campaign_executor");
        assert_visibility_v1(
            &campaign_module.vis,
            "pub(crate)",
            "Generator campaign module",
        );
        assert_exact_non_doc_attributes_v1(
            &campaign_module.attrs,
            "#[cfg(feature = \"b4-campaign-executor\")]",
            "Generator campaign module",
        );
        assert!(
            campaign_module.content.is_none() && campaign_module.semi.is_some(),
            "Generator campaign module must remain the direct out-of-line module at src/b4_campaign_executor/mod.rs"
        );
        let workspace = manifest_root
            .get("workspace")
            .and_then(toml::Value::as_table)
            .expect("Generator workspace table must remain explicit");
        assert_eq!(
            workspace.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["resolver"],
            "Generator workspace must not acquire inherited dependency sources"
        );
        assert_eq!(
            workspace.get("resolver").and_then(toml::Value::as_str),
            Some("3"),
            "Generator workspace resolver drift"
        );
        let features = manifest
            .get("features")
            .and_then(toml::Value::as_table)
            .expect("missing Generator feature table");
        let campaign_features = features
            .get("b4-campaign-executor")
            .and_then(toml::Value::as_array)
            .expect("missing b4-campaign-executor feature array");
        let mut actual_campaign_features = campaign_features
            .iter()
            .map(|feature| {
                feature
                    .as_str()
                    .expect("b4-campaign-executor feature entries must be strings")
            })
            .collect::<Vec<_>>();
        actual_campaign_features.sort_unstable();
        let mut expected_campaign_features = vec![
            "b4-authoritative-build-custody",
            "dep:crc32fast",
            "dep:eip0045-h0-contract",
            "dep:eip0045-h0-linux-abi",
            "dep:flate2",
            "eip-0045-reproduction/b4-terminal-evidence-packet",
            "eip-0045-reproduction/positive-gate",
        ];
        expected_campaign_features.sort_unstable();
        assert_eq!(
            actual_campaign_features, expected_campaign_features,
            "b4-campaign-executor must retain its exact seven-member feature closure"
        );
        let canonical_linux_abi = "eip0045-h0-linux-abi";
        let linux_abi_bindings = cargo_dependency_bindings_v1(&manifest, canonical_linux_abi);
        let mut dependency_keys = linux_abi_bindings
            .iter()
            .map(|(_, key, _, _)| key.as_str())
            .collect::<Vec<_>>();
        dependency_keys.push(canonical_linux_abi);
        dependency_keys.sort_unstable();
        dependency_keys.dedup();
        let mut linux_abi_feature_references = Vec::new();
        for (feature_name, feature_members) in features {
            let feature_members = feature_members
                .as_array()
                .unwrap_or_else(|| panic!("Cargo feature {feature_name} must be an array"));
            for feature_member in feature_members {
                let feature_member = feature_member.as_str().unwrap_or_else(|| {
                    panic!("Cargo feature {feature_name} entry must be a string")
                });
                if dependency_keys.iter().any(|dependency_key| {
                    feature_member == *dependency_key
                        || feature_member == format!("dep:{dependency_key}")
                        || feature_member
                            .strip_prefix(*dependency_key)
                            .is_some_and(|suffix| {
                                suffix.starts_with('/') || suffix.starts_with("?/")
                            })
                }) {
                    linux_abi_feature_references.push((feature_name.as_str(), feature_member));
                }
            }
        }
        assert_eq!(
            linux_abi_feature_references,
            vec![("b4-campaign-executor", "dep:eip0045-h0-linux-abi")],
            "Linux ABI dependency must have one exact feature reference and no subfeature expansion"
        );
        assert_eq!(
            linux_abi_bindings.len(),
            1,
            "Linux ABI package identity must have exactly one dependency binding"
        );
        let (scope, dependency_key, effective_package, linux_abi_binding) = &linux_abi_bindings[0];
        assert_eq!(scope, r#"target.cfg(target_os = "linux").dependencies"#);
        assert_eq!(dependency_key, canonical_linux_abi);
        assert_eq!(effective_package, canonical_linux_abi);
        let linux_abi_binding = linux_abi_binding
            .as_table()
            .expect("Linux ABI dependency must use an inline table");
        assert_eq!(
            linux_abi_binding.len(),
            4,
            "Linux ABI dependency table must not carry an alternate package, registry, git source, or feature closure"
        );
        assert_eq!(
            linux_abi_binding
                .get("version")
                .and_then(toml::Value::as_str),
            Some("=0.1.0")
        );
        assert_eq!(
            linux_abi_binding.get("path").and_then(toml::Value::as_str),
            Some("../appliance/h0-tmpfs-provider/crates/linux-abi")
        );
        assert_eq!(
            linux_abi_binding
                .get("default-features")
                .and_then(toml::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            linux_abi_binding
                .get("optional")
                .and_then(toml::Value::as_bool),
            Some(true)
        );

        let linux_abi_manifest_source =
            include_str!("../../../appliance/h0-tmpfs-provider/crates/linux-abi/Cargo.toml")
                .replace("\r\n", "\n");
        let linux_abi_manifest = toml::from_str::<toml::Value>(&linux_abi_manifest_source)
            .expect("Linux ABI Cargo.toml must parse structurally");
        let linux_abi_manifest_root = linux_abi_manifest
            .as_table()
            .expect("Linux ABI Cargo.toml root must be a table");
        assert!(
            !linux_abi_manifest_root.contains_key("lib"),
            "Linux ABI library target must remain the implicit src/lib.rs target"
        );
        assert!(
            !linux_abi_manifest_root.contains_key("patch")
                && !linux_abi_manifest_root.contains_key("replace"),
            "Linux ABI manifest must not override dependency sources"
        );
        let linux_abi_package = linux_abi_manifest_root
            .get("package")
            .and_then(toml::Value::as_table)
            .expect("Linux ABI package table must remain explicit");
        assert_eq!(
            linux_abi_package.get("name").and_then(toml::Value::as_str),
            Some("eip0045-h0-linux-abi"),
            "Linux ABI package identity drift"
        );
        assert_eq!(
            linux_abi_package
                .get("build")
                .and_then(toml::Value::as_bool),
            Some(false),
            "Linux ABI package must disable implicit build.rs discovery"
        );
        assert_eq!(
            linux_abi_package
                .get("workspace")
                .and_then(toml::Value::as_str),
            Some("../.."),
            "Linux ABI workspace root drift"
        );
        assert!(
            !linux_abi_package.contains_key("autolib"),
            "Linux ABI package must retain implicit library discovery"
        );
        let linux_abi_library_source =
            include_str!("../../../appliance/h0-tmpfs-provider/crates/linux-abi/src/lib.rs")
                .replace("\r\n", "\n");
        let linux_abi_library_file = syn::parse_file(&linux_abi_library_source)
            .expect("Linux ABI src/lib.rs must parse as Rust");
        assert_exact_file_attributes_v1(
            &linux_abi_library_file,
            r#"#![deny(unsafe_op_in_unsafe_fn)]
                #![cfg_attr(
                    not(all(
                        target_arch = "x86_64",
                        target_os = "linux",
                        target_env = "musl"
                    )),
                    forbid(unsafe_code)
                )]"#,
            "Linux ABI library source",
        );
        let linux_abi_target_guard =
            unique_direct_macro_v1(&linux_abi_library_file.items, "compile_error");
        let expected_linux_abi_target_guard = syn::parse_str::<syn::ItemMacro>(
            r#"#[cfg(all(
                    target_os = "linux",
                    not(all(target_arch = "x86_64", target_env = "musl"))
                ))]
                compile_error!("the H0 Linux ABI is selected only for x86_64-unknown-linux-musl");"#,
        )
        .expect("expected Linux ABI target guard must parse as a direct macro item");
        assert_eq!(
            token_string_v1(linux_abi_target_guard),
            token_string_v1(&expected_linux_abi_target_guard),
            "Linux ABI non-selected Linux target guard drift"
        );
        let linux_abi_ancillary_module =
            unique_direct_module_v1(&linux_abi_library_file.items, "ancillary");
        assert_visibility_v1(
            &linux_abi_ancillary_module.vis,
            "pub",
            "Linux ABI ancillary module",
        );
        assert_exact_non_doc_attributes_v1(
            &linux_abi_ancillary_module.attrs,
            "",
            "Linux ABI ancillary module",
        );
        assert!(
            linux_abi_ancillary_module.content.is_none()
                && linux_abi_ancillary_module.semi.is_some(),
            "Linux ABI ancillary module must remain the direct out-of-line src/ancillary.rs module"
        );

        let canonical_contract = "eip0045-h0-contract";
        let contract_bindings = cargo_dependency_bindings_v1(&manifest, canonical_contract);
        let mut contract_dependency_keys = contract_bindings
            .iter()
            .map(|(_, key, _, _)| key.as_str())
            .collect::<Vec<_>>();
        contract_dependency_keys.push(canonical_contract);
        contract_dependency_keys.sort_unstable();
        contract_dependency_keys.dedup();
        let mut contract_feature_references = Vec::new();
        for (feature_name, feature_members) in features {
            let feature_members = feature_members
                .as_array()
                .unwrap_or_else(|| panic!("Cargo feature {feature_name} must be an array"));
            for feature_member in feature_members {
                let feature_member = feature_member.as_str().unwrap_or_else(|| {
                    panic!("Cargo feature {feature_name} entry must be a string")
                });
                if contract_dependency_keys.iter().any(|dependency_key| {
                    feature_member == *dependency_key
                        || feature_member == format!("dep:{dependency_key}")
                        || feature_member
                            .strip_prefix(*dependency_key)
                            .is_some_and(|suffix| {
                                suffix.starts_with('/') || suffix.starts_with("?/")
                            })
                }) {
                    contract_feature_references.push((feature_name.as_str(), feature_member));
                }
            }
        }
        assert_eq!(
            contract_feature_references,
            vec![("b4-campaign-executor", "dep:eip0045-h0-contract")],
            "H0 contract dependency must have one exact feature reference"
        );
        assert_eq!(
            contract_bindings.len(),
            1,
            "H0 contract package identity must have exactly one dependency binding"
        );
        let (scope, dependency_key, effective_package, contract_binding) = &contract_bindings[0];
        assert_eq!(scope, "dependencies");
        assert_eq!(dependency_key, canonical_contract);
        assert_eq!(effective_package, canonical_contract);
        let contract_binding = contract_binding
            .as_table()
            .expect("H0 contract dependency must use an inline table");
        assert_eq!(
            contract_binding.len(),
            4,
            "H0 contract dependency table must not carry an alternate package, registry, git source, or feature closure"
        );
        assert_eq!(
            contract_binding
                .get("version")
                .and_then(toml::Value::as_str),
            Some("=0.1.0")
        );
        assert_eq!(
            contract_binding.get("path").and_then(toml::Value::as_str),
            Some("../appliance/h0-tmpfs-provider/crates/contract")
        );
        assert_eq!(
            contract_binding
                .get("default-features")
                .and_then(toml::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            contract_binding
                .get("optional")
                .and_then(toml::Value::as_bool),
            Some(true)
        );

        let lock_source = include_str!("../../Cargo.lock").replace("\r\n", "\n");
        let lock = toml::from_str::<toml::Value>(&lock_source)
            .expect("Generator Cargo.lock must parse structurally");
        let generator_package =
            unique_locked_package_v1(&lock, "eip-0045-candidate-generator", "0.1.0");
        let generator_dependencies = generator_package
            .get("dependencies")
            .and_then(toml::Value::as_array)
            .expect("Generator Cargo.lock dependency inventory must be an array")
            .iter()
            .map(|dependency| {
                dependency
                    .as_str()
                    .expect("Generator Cargo.lock dependencies must be strings")
            })
            .collect::<Vec<_>>();
        for required in [
            "eip0045-h0-contract",
            "eip0045-h0-linux-abi",
            "quote",
            "syn 2.0.106",
        ] {
            assert!(
                generator_dependencies.contains(&required),
                "Generator Cargo.lock lost direct test dependency edge {required}"
            );
        }
        for (name, version, checksum) in [
            (
                "quote",
                "1.0.40",
                "1885c039570dc00dcb4ff087a89e185fd56bae234ddc7f056a945bf36467248d",
            ),
            (
                "syn",
                "2.0.106",
                "ede7c438028d4436d71104916910f5bb611972c5cfd7f89b8300a8186e6fada6",
            ),
        ] {
            let package = unique_locked_package_v1(&lock, name, version);
            assert_eq!(
                package.get("source").and_then(toml::Value::as_str),
                Some("registry+https://github.com/rust-lang/crates.io-index"),
                "Generator AST dependency source drift: {name} {version}"
            );
            assert_eq!(
                package.get("checksum").and_then(toml::Value::as_str),
                Some(checksum),
                "Generator AST dependency checksum drift: {name} {version}"
            );
        }
        for name in ["eip0045-h0-contract", "eip0045-h0-linux-abi"] {
            let package = unique_locked_package_v1(&lock, name, "0.1.0");
            assert!(
                !package.contains_key("source") && !package.contains_key("checksum"),
                "Generator local protocol dependency must remain a path package: {name}"
            );
        }

        let module_source = include_str!("mod.rs").replace("\r\n", "\n");
        let module_file =
            syn::parse_file(&module_source).expect("complete Generator source must parse as Rust");
        let test_modules = module_file
            .items
            .iter()
            .enumerate()
            .filter_map(|(index, item)| match item {
                syn::Item::Mod(module) if module.ident == "tests" => Some((index, module)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            test_modules.len(),
            1,
            "Generator source must contain one direct tests module"
        );
        let (tests_index, tests_module) = test_modules[0];
        assert_eq!(
            tests_index + 1,
            module_file.items.len(),
            "Generator tests module must remain the final root item"
        );
        assert_visibility_v1(&tests_module.vis, "", "Generator tests module");
        assert_exact_non_doc_attributes_v1(
            &tests_module.attrs,
            "#[cfg(test)]",
            "Generator tests module",
        );
        let _ = inline_module_items_v1(tests_module, "tests");
        let module_production_items = &module_file.items[..tests_index];
        let ancillary_source =
            include_str!("../../../appliance/h0-tmpfs-provider/crates/linux-abi/src/ancillary.rs")
                .replace("\r\n", "\n");
        let ancillary_file =
            syn::parse_file(&ancillary_source).expect("Linux ancillary source must parse as Rust");
        assert_no_conditional_inner_attributes_v1(&module_file, "Generator source");
        assert_no_conditional_inner_attributes_v1(&ancillary_file, "Linux ancillary source");
        assert_no_production_item_macros_v1(module_production_items, "Generator production root");
        assert_no_production_item_macros_v1(&ancillary_file.items, "Linux ancillary root");

        let strict_model = unique_direct_module_v1(&ancillary_file.items, "strict_model");
        assert_visibility_v1(&strict_model.vis, "", "strict model");
        assert_exact_non_doc_attributes_v1(
            &strict_model.attrs,
            TEST_OR_MUSL_ATTRIBUTE_V1,
            "strict model",
        );
        let strict_items = inline_module_items_v1(strict_model, "strict_model");
        assert_no_production_item_macros_v1(strict_items, "strict ancillary model");
        let selected_target = unique_direct_module_v1(strict_items, "selected_target");
        assert_visibility_v1(&selected_target.vis, "pub(super)", "selected target");
        assert_exact_non_doc_attributes_v1(
            &selected_target.attrs,
            MUSL_TARGET_ATTRIBUTE_V1,
            "selected target",
        );
        let selected_items = inline_module_items_v1(selected_target, "selected_target");
        assert_no_production_item_macros_v1(selected_items, "selected Linux target");

        let mut public_uses = PublicUseInventoryV1::default();
        public_uses.visit_file(&ancillary_file);
        assert_eq!(
            public_uses.count, 2,
            "Linux ancillary source must retain exactly two production public use routes"
        );
        assert_eq!(
            public_uses.glob_count, 0,
            "Linux ancillary public exports must not contain globs"
        );

        let endpoint_exports = ancillary_file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Use(item_use)
                    if ["GeneratorEndpointV1", "WorkerEndpointV1"]
                        .iter()
                        .any(|name| use_tree_mentions_ident_v1(&item_use.tree, name)) =>
                {
                    Some(item_use)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            endpoint_exports.len(),
            1,
            "typed child endpoints must share one direct public export"
        );
        let endpoint_export = endpoint_exports[0];
        assert!(
            endpoint_export.leading_colon.is_none(),
            "typed endpoint export must remain crate-relative"
        );
        assert_visibility_v1(&endpoint_export.vis, "pub", "typed endpoint export");
        assert_exact_non_doc_attributes_v1(
            &endpoint_export.attrs,
            MUSL_TARGET_ATTRIBUTE_V1,
            "typed endpoint export",
        );
        let syn::UseTree::Path(strict_export_path) = &endpoint_export.tree else {
            panic!("typed endpoint export must start at strict_model");
        };
        assert_eq!(strict_export_path.ident, "strict_model");
        let syn::UseTree::Path(selected_export_path) = strict_export_path.tree.as_ref() else {
            panic!("typed endpoint export must descend through selected_target");
        };
        assert_eq!(selected_export_path.ident, "selected_target");
        assert!(
            matches!(selected_export_path.tree.as_ref(), syn::UseTree::Group(_)),
            "typed child endpoints must share one grouped export"
        );
        for endpoint in ["GeneratorEndpointV1", "WorkerEndpointV1"] {
            assert_eq!(
                use_tree_name_count_v1(&endpoint_export.tree, endpoint),
                1,
                "missing or duplicated exact public child endpoint export: {endpoint}"
            );
            assert_eq!(
                use_tree_rename_count_v1(&endpoint_export.tree, endpoint),
                0,
                "typed child endpoint export must not be renamed: {endpoint}"
            );
            let total_mentions = ancillary_file
                .items
                .iter()
                .filter_map(|item| match item {
                    syn::Item::Use(item_use) => Some(&item_use.tree),
                    _ => None,
                })
                .map(|tree| use_tree_name_count_v1(tree, endpoint))
                .sum::<usize>();
            assert_eq!(
                total_mentions, 1,
                "typed child endpoint must have one root export mention: {endpoint}"
            );
        }

        for endpoint in ["GeneratorEndpointV1", "WorkerEndpointV1"] {
            let declaration = unique_direct_struct_v1(selected_items, endpoint);
            assert_visibility_v1(&declaration.vis, "pub", endpoint);
            assert_exact_non_doc_attributes_v1(&declaration.attrs, "", endpoint);
            assert!(declaration.generics.params.is_empty());
            assert!(declaration.generics.where_clause.is_none());
            assert!(
                declaration.semi_token.is_some(),
                "typed child endpoint must remain a tuple struct: {endpoint}"
            );
            let syn::Fields::Unnamed(fields) = &declaration.fields else {
                panic!("typed child endpoint must have one unnamed field: {endpoint}");
            };
            assert_eq!(fields.unnamed.len(), 1);
            let field = &fields.unnamed[0];
            assert_visibility_v1(&field.vis, "", endpoint);
            assert_exact_non_doc_attributes_v1(&field.attrs, "", endpoint);
            assert_eq!(
                token_string_v1(&field.ty),
                "SeqpacketEndpointV1",
                "typed child endpoint field drift: {endpoint}"
            );
        }

        let probe = unique_direct_function_v1(
            module_production_items,
            "compile_only_child_endpoint_exports_are_public",
        );
        assert_visibility_v1(&probe.vis, "", "compile-only endpoint probe");
        assert_exact_non_doc_attributes_v1(
            &probe.attrs,
            "#[cfg(target_os = \"linux\")]",
            "compile-only endpoint probe",
        );
        assert_exact_function_v1(
            probe,
            r#"fn compile_only_child_endpoint_exports_are_public(
                _generator: &eip0045_h0_linux_abi::ancillary::GeneratorEndpointV1,
                _worker: &eip0045_h0_linux_abi::ancillary::WorkerEndpointV1,
            ) {}"#,
            "compile-only endpoint probe",
        );
    }

    #[test]
    fn proof_capability_v2_terminal_join_stops_before_negative_materialization() {
        let production = include_str!("mod.rs").split("#[cfg(test)]").next().unwrap();
        let sibling = production
            .split("pub(super) fn close_terminal_import_authority_v2(")
            .nth(1)
            .unwrap();

        assert!(sibling.contains("B4PositiveGenerationAuthorityV2"));
        assert!(sibling.contains("B4TerminalSourceLineageAuthorityV2"));
        assert!(sibling.contains("Result<B4TerminalEvidenceImportAuthorityV2>"));
        assert_eq!(
            sibling
                .matches(".close_terminal_import_authority_v2(")
                .count(),
            1
        );
        assert!(!sibling.contains("B4PositiveGenerationAuthorityV1"));
        assert!(!sibling.contains("B4NegativeAncestryWitnessCatalogAuthorityV1"));
        assert!(!sibling.contains("from_descriptor_rooted_cryptographic_closure"));
    }

    #[test]
    fn proof_capability_v2_negative_materialization_bridge_is_full_and_version_isolated() {
        let production = include_str!("mod.rs").split("#[cfg(test)]").next().unwrap();
        let bridge = production
            .split("pub(super) fn close_negative_materialization_authority_v2(")
            .nth(1)
            .unwrap()
            .split("/// Authenticate the V2 terminal import")
            .next()
            .unwrap();

        for required in [
            "NegativeMaterializationDescriptorRootPlanV2",
            "B4PositiveGenerationAuthorityV2",
            "B4TerminalSourceLineageAuthorityV2",
            "B4NegativeAncestryWitnessCatalogAuthorityV2",
            "B4NegativeMaterializationSetAuthorityV2",
            ".close_negative_materialization_authority_v2(",
        ] {
            assert!(
                bridge.contains(required),
                "missing V2 bridge surface: {required}"
            );
        }
        assert!(!bridge.contains("B4PositiveGenerationAuthorityV1"));
        assert!(!bridge.contains("B4TerminalSourceLineageAuthorityV1"));
        assert!(!bridge.contains("B4NegativeAncestryWitnessCatalogAuthorityV1"));
        assert!(!bridge.contains("B4NegativeMaterializationSetAuthorityV1"));
        assert!(!bridge.contains("from_descriptor_rooted_cryptographic_closure"));
    }

    #[test]
    fn h3_build_projection_typestate_delegations_are_narrow_and_phase_bound() {
        let production = include_str!("mod.rs").split("#[cfg(test)]").next().unwrap();
        assert_eq!(
            production
                .matches("pub(super) fn authenticate_authoritative_b4_build_projection(")
                .count(),
            2,
            "preflight and execute must each expose exactly one fixed delegation"
        );
        assert_eq!(
            production
                .matches(".authenticate_authoritative_b4_build_projection(")
                .count(),
            2
        );
        assert!(!production.contains("BorrowedFd"));
    }
}
