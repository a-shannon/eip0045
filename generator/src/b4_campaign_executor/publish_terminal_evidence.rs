//! Real linked `publish-terminal-evidence` production handler.

use std::path::Path;

use anyhow::{Context as _, Result};

use super::{
    preflight::{ProjectedOuterCampaignLayout, project_outer_campaign_layout},
    typestate::ExecutorPreflightContext,
};

const TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_FILE: &str = "terminal-evidence-campaign-receipt.json";

fn project_publish_terminal_evidence_layout<const ROOTS: usize>(
    campaign_root: &Path,
    prior_roots: [&Path; ROOTS],
    outer_final_root: &Path,
) -> Result<ProjectedOuterCampaignLayout<ROOTS>> {
    project_outer_campaign_layout(
        campaign_root,
        prior_roots,
        outer_final_root,
        [TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_FILE],
    )
    .context("cannot project publish-terminal-evidence campaign layout")
}

#[cfg(target_os = "linux")]
pub(super) mod execute {
    use std::{
        env,
        ffi::OsString,
        path::{Component, Path, PathBuf},
    };

    use anyhow::{Context as _, Result, ensure};
    use eip_0045_reproduction::{
        b4_campaign_contract::{
            B4CampaignPrecommitAuthorityV1, B4ContractArtifactIdentityV1,
            B4PositiveGenerationAuthorityV2, B4TerminalEvidenceCampaignReceiptInputsV1,
            Eip0045B4TerminalEvidenceCampaignReceiptV1, MAX_CAMPAIGN_PRECOMMIT_BYTES,
            MAX_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES,
            validate_b4_publish_terminal_evidence_invocation,
        },
        b4_terminal_evidence_packet::{
            B4TerminalEvidencePacketIdentityV1,
            reopen_b4_terminal_evidence_packet_from_directory_descriptor,
        },
        b4_terminal_source_lineage::B4TerminalSourceLineageAuthorityV2,
    };
    use risc0_zkvm::LocalProver;

    use crate::terminal_evidence_export::{
        B4PublishedLineagedTerminalEvidenceAuthorityV2,
        prepare_lineaged_b4_terminal_evidence_packet_v2,
        publish_prepared_lineaged_b4_terminal_evidence_packet_from_directory_descriptor_v2,
        require_terminal_packet_identity_binding,
    };

    use super::{
        ExecutorPreflightContext, ProjectedOuterCampaignLayout,
        project_publish_terminal_evidence_layout,
    };
    use crate::b4_campaign_executor::authenticated_preflight::{
        authenticate_campaign_precommit_file, derive_campaign_relative_artifact_path,
        require_current_executable_binding,
    };

    /// Typed inputs reconstructed before the execute-only production branch.
    pub(crate) struct PublishTerminalEvidenceExecuteInputsV2<'authority, const ROOTS: usize> {
        configured_executor_artifact: &'authority Path,
        campaign_root: &'authority Path,
        prior_roots: [&'authority Path; ROOTS],
        outer_final_root: &'authority Path,
        campaign_precommit_root_index: usize,
        campaign_precommit_root_relative_path: &'authority str,
        campaign: &'authority B4CampaignPrecommitAuthorityV1,
        positive: B4PositiveGenerationAuthorityV2,
        lineage: B4TerminalSourceLineageAuthorityV2,
    }

    impl<'authority, const ROOTS: usize> PublishTerminalEvidenceExecuteInputsV2<'authority, ROOTS> {
        #[allow(
            clippy::too_many_arguments,
            reason = "the handler retains each independently reconstructed authority and root explicitly"
        )]
        pub(crate) const fn new(
            configured_executor_artifact: &'authority Path,
            campaign_root: &'authority Path,
            prior_roots: [&'authority Path; ROOTS],
            outer_final_root: &'authority Path,
            campaign_precommit_root_index: usize,
            campaign_precommit_root_relative_path: &'authority str,
            campaign: &'authority B4CampaignPrecommitAuthorityV1,
            positive: B4PositiveGenerationAuthorityV2,
            lineage: B4TerminalSourceLineageAuthorityV2,
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
                lineage,
            }
        }
    }

    /// Private complete result retained only after semantic and physical reopen.
    pub(crate) struct PublishedTerminalEvidenceHandlerResultV2 {
        _authority: B4PublishedLineagedTerminalEvidenceAuthorityV2,
        _receipt: Eip0045B4TerminalEvidenceCampaignReceiptV1,
    }

    struct CapturedExecuteInvocation {
        process_argv: Vec<OsString>,
        parsed_preflight_only: bool,
        risc0_dev_mode: Option<OsString>,
    }

    impl CapturedExecuteInvocation {
        fn capture(parsed_preflight_only: bool) -> Result<Self> {
            let process_argv = env::args_os().collect::<Vec<_>>();
            let risc0_dev_mode = env::var_os("RISC0_DEV_MODE");
            ensure!(
                risc0_dev_mode.is_none(),
                "RISC0_DEV_MODE must be absent before terminal-evidence proof work"
            );
            validate_b4_publish_terminal_evidence_invocation(&process_argv, parsed_preflight_only)
                .context("invalid retained publish-terminal-evidence invocation argv")?;
            Ok(Self {
                process_argv,
                parsed_preflight_only,
                risc0_dev_mode,
            })
        }
    }

    struct AuthenticatedPublishTerminalEvidencePreflightV1<const ROOTS: usize> {
        preflight: ExecutorPreflightContext<ROOTS>,
        campaign_precommit_identity: B4ContractArtifactIdentityV1,
        invocation: CapturedExecuteInvocation,
    }

    #[derive(Clone)]
    struct ProjectedPublishLeaves {
        outer_staging_root: PathBuf,
        outer_final_root: PathBuf,
        staged_packet: PathBuf,
        published_packet: PathBuf,
        staged_reserved_inner: PathBuf,
        published_reserved_inner: PathBuf,
        staged_receipt: PathBuf,
        published_receipt: PathBuf,
        packet_relative: String,
        reserved_inner_relative: String,
        receipt_relative: String,
    }

    impl ProjectedPublishLeaves {
        fn from_layout<const ROOTS: usize>(
            layout: &ProjectedOuterCampaignLayout<ROOTS>,
        ) -> Result<Self> {
            ensure!(
                layout.staged_additional_top_level_leaves().len() == 1
                    && layout.projected_additional_top_level_leaves().len() == 1,
                "publish-terminal-evidence layout must contain exactly one receipt leaf"
            );
            let mut projected = Self {
                outer_staging_root: layout.outer_staging_root().to_path_buf(),
                outer_final_root: layout.outer_final_root().to_path_buf(),
                staged_packet: layout.staged_inner_final_path().to_path_buf(),
                published_packet: layout.projected_inner_final_path().to_path_buf(),
                staged_reserved_inner: layout.staged_inner_staging_path().to_path_buf(),
                published_reserved_inner: layout.projected_inner_staging_path().to_path_buf(),
                staged_receipt: layout.staged_additional_top_level_leaves()[0].clone(),
                published_receipt: layout.projected_additional_top_level_leaves()[0].clone(),
                packet_relative: String::new(),
                reserved_inner_relative: String::new(),
                receipt_relative: String::new(),
            };
            projected.packet_relative = projected.require_equivalent_direct_leaf(
                &projected.staged_packet,
                &projected.published_packet,
                "terminal packet",
            )?;
            projected.reserved_inner_relative = projected.require_equivalent_direct_leaf(
                &projected.staged_reserved_inner,
                &projected.published_reserved_inner,
                "reserved inner staging",
            )?;
            projected.receipt_relative = projected.require_equivalent_direct_leaf(
                &projected.staged_receipt,
                &projected.published_receipt,
                "terminal campaign receipt",
            )?;
            ensure!(
                projected.receipt_relative == super::TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_FILE,
                "projected terminal campaign receipt role drifted"
            );
            ensure!(
                projected.packet_relative != projected.reserved_inner_relative
                    && projected.packet_relative != projected.receipt_relative
                    && projected.reserved_inner_relative != projected.receipt_relative,
                "projected publish-terminal-evidence leaves overlap"
            );
            Ok(projected)
        }

        fn revalidate_published_projection(&self) -> Result<()> {
            ensure!(
                self.require_equivalent_direct_leaf(
                    &self.staged_packet,
                    &self.published_packet,
                    "terminal packet",
                )? == self.packet_relative
                    && self.require_equivalent_direct_leaf(
                        &self.staged_reserved_inner,
                        &self.published_reserved_inner,
                        "reserved inner staging",
                    )? == self.reserved_inner_relative
                    && self.require_equivalent_direct_leaf(
                        &self.staged_receipt,
                        &self.published_receipt,
                        "terminal campaign receipt",
                    )? == self.receipt_relative,
                "published leaf projection changed after outer commit"
            );
            Ok(())
        }

        fn require_equivalent_direct_leaf(
            &self,
            staged: &Path,
            published: &Path,
            label: &str,
        ) -> Result<String> {
            let staged_relative = staged
                .strip_prefix(&self.outer_staging_root)
                .with_context(|| format!("{label} escaped the outer staging root"))?;
            let published_relative = published
                .strip_prefix(&self.outer_final_root)
                .with_context(|| format!("{label} escaped the outer final root"))?;
            ensure!(
                staged_relative == published_relative
                    && staged_relative.components().count() == 1
                    && matches!(
                        staged_relative.components().next(),
                        Some(Component::Normal(_))
                    ),
                "{label} is not an equivalent direct leaf across outer publication"
            );
            staged_relative
                .to_str()
                .context("projected publish-terminal-evidence leaf is not UTF-8")
                .map(ToOwned::to_owned)
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum PublishTerminalEvidenceTransition {
        Prepare,
        BeginOuterStaging,
        LiveInnerPublication,
        WriteReceipt,
        OuterCommitAndPostcommitValidation,
    }

    trait PublishTerminalEvidenceTransitionObserver {
        fn before(&mut self, transition: PublishTerminalEvidenceTransition) -> Result<()>;
    }

    struct NoopPublishTerminalEvidenceTransitionObserver;

    impl PublishTerminalEvidenceTransitionObserver for NoopPublishTerminalEvidenceTransitionObserver {
        fn before(&mut self, _transition: PublishTerminalEvidenceTransition) -> Result<()> {
            Ok(())
        }
    }

    fn coordinate_publish_terminal_evidence<State, Prepared, Output>(
        state: &mut State,
        observer: &mut impl PublishTerminalEvidenceTransitionObserver,
        prepare: impl FnOnce(&mut State) -> Result<Prepared>,
        mutate: impl FnOnce(
            &mut State,
            Prepared,
            &mut dyn PublishTerminalEvidenceTransitionObserver,
        ) -> Result<Output>,
    ) -> Result<Output> {
        observer.before(PublishTerminalEvidenceTransition::Prepare)?;
        let prepared = prepare(state)?;
        mutate(state, prepared, observer)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the affine handler transition coordinator keeps every one-way boundary explicit"
    )]
    fn coordinate_publish_terminal_evidence_mutation<
        Transaction,
        Prepared,
        Published,
        Receipt,
        Output,
    >(
        observer: &mut dyn PublishTerminalEvidenceTransitionObserver,
        prepared: Prepared,
        begin_outer_staging: impl FnOnce() -> Result<Transaction>,
        publish_inner: impl FnOnce(&mut Transaction, Prepared) -> Result<Published>,
        write_receipt: impl FnOnce(&mut Transaction, &Published) -> Result<Receipt>,
        commit_and_validate: impl FnOnce(Transaction, Published, Receipt) -> Result<Output>,
    ) -> Result<Output> {
        observer.before(PublishTerminalEvidenceTransition::BeginOuterStaging)?;
        let mut transaction = begin_outer_staging()?;
        observer.before(PublishTerminalEvidenceTransition::LiveInnerPublication)?;
        let published = publish_inner(&mut transaction, prepared)?;
        observer.before(PublishTerminalEvidenceTransition::WriteReceipt)?;
        let receipt = write_receipt(&mut transaction, &published)?;
        observer.before(PublishTerminalEvidenceTransition::OuterCommitAndPostcommitValidation)?;
        commit_and_validate(transaction, published, receipt)
    }

    fn authenticate_publish_terminal_evidence_preflight<const ROOTS: usize>(
        inputs: &PublishTerminalEvidenceExecuteInputsV2<'_, ROOTS>,
        parsed_preflight_only: bool,
    ) -> Result<AuthenticatedPublishTerminalEvidencePreflightV1<ROOTS>> {
        let projected = project_publish_terminal_evidence_layout(
            inputs.campaign_root,
            inputs.prior_roots,
            inputs.outer_final_root,
        )?;
        let preflight =
            ExecutorPreflightContext::capture(inputs.configured_executor_artifact, projected)
                .context("publish-terminal-evidence retained preflight failed")?;
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
        let campaign_precommit_identity = authenticate_campaign_precommit_file(
            &campaign_precommit_identity_path,
            inputs.campaign,
            &campaign_precommit_bytes,
        )?;
        let invocation = CapturedExecuteInvocation::capture(parsed_preflight_only)?;
        inputs
            .lineage
            .verify_authority_bindings(inputs.campaign, &inputs.positive)
            .context("terminal-source lineage differs from execute authorities")?;
        require_current_executable_binding(preflight.executable(), inputs.campaign)?;
        Ok(AuthenticatedPublishTerminalEvidencePreflightV1 {
            preflight,
            campaign_precommit_identity,
            invocation,
        })
    }

    /// Reach the exact zero-effect production boundary for global preflight mode.
    pub(crate) fn preflight_publish_terminal_evidence_handler<const ROOTS: usize>(
        inputs: &PublishTerminalEvidenceExecuteInputsV2<'_, ROOTS>,
    ) -> Result<()> {
        authenticate_publish_terminal_evidence_preflight(inputs, true)?
            .preflight
            .finish_preflight()
            .context("publish-terminal-evidence authenticated preflight failed")
    }

    /// Execute the real linked producer and nested create-only publication.
    #[allow(
        clippy::too_many_lines,
        reason = "the security-sensitive preparation/publication/commit order remains one audit unit"
    )]
    pub(crate) fn execute_publish_terminal_evidence_handler<const ROOTS: usize>(
        inputs: PublishTerminalEvidenceExecuteInputsV2<'_, ROOTS>,
    ) -> Result<PublishedTerminalEvidenceHandlerResultV2> {
        let AuthenticatedPublishTerminalEvidencePreflightV1 {
            preflight,
            campaign_precommit_identity,
            invocation,
        } = authenticate_publish_terminal_evidence_preflight(&inputs, false)?;
        let campaign = inputs.campaign;
        let positive = inputs.positive;
        let lineage = inputs.lineage;

        preflight.execute(move |execute| {
            let mut observer = NoopPublishTerminalEvidenceTransitionObserver;
            coordinate_publish_terminal_evidence(
                execute,
                &mut observer,
                |execute| {
                    execute.with_proof(|_capability| {
                        let prover =
                            LocalProver::new("eip-0045-b4-campaign-publish-terminal-evidence");
                        prepare_lineaged_b4_terminal_evidence_packet_v2(
                            &prover, campaign, positive, lineage,
                        )
                    })
                },
                |execute, prepared, observer| {
                    execute.with_mutation(move |capability| {
                        let leaves =
                            ProjectedPublishLeaves::from_layout(capability.projected_layout())?;
                        let publish_leaves = leaves.clone();
                        let receipt_leaves = leaves.clone();
                        coordinate_publish_terminal_evidence_mutation(
                            observer,
                            prepared,
                            || capability.begin_create_only_directory(),
                            |transaction, prepared| {
                                transaction.publish_and_adopt_directory_tree(
                                    &publish_leaves.packet_relative,
                                    |staging_root| {
                                        publish_prepared_lineaged_b4_terminal_evidence_packet_from_directory_descriptor_v2(
                                            staging_root,
                                            &publish_leaves.packet_relative,
                                            campaign,
                                            prepared,
                                        )
                                    },
                                )
                            },
                            |transaction, published| {
                                let packet_identity = published.identity();
                                let receipt = construct_receipt(
                                    &campaign_precommit_identity,
                                    campaign,
                                    published.positive_input_set_identity(),
                                    published.positive_generation_set_identity(),
                                    &invocation,
                                    packet_identity,
                                )?;
                                let receipt_bytes = receipt.to_canonical_jcs()?;
                                transaction.create_file(
                                    &receipt_leaves.receipt_relative,
                                    &receipt_bytes,
                                    MAX_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES,
                                )?;
                                Ok((receipt, packet_identity))
                            },
                            |transaction, published, (receipt, packet_identity)| {
                                transaction.commit_with_postcommit_validation(move |committed| {
                                    leaves.revalidate_published_projection()?;
                                    committed.require_absent(&leaves.reserved_inner_relative)?;
                                    let reopened_packet =
                                        reopen_b4_terminal_evidence_packet_from_directory_descriptor(
                                            committed.directory_descriptor(&leaves.packet_relative)?,
                                        )
                                        .context(
                                            "cannot semantically reopen committed terminal packet",
                                        )?;
                                    let authority = published
                                        .rebind_postcommit_semantically_reopened_packet_v2(
                                            campaign,
                                            reopened_packet,
                                        )?;
                                    let reopened_receipt =
                                        Eip0045B4TerminalEvidenceCampaignReceiptV1::from_canonical_jcs(
                                            &committed.read_file(
                                                &leaves.receipt_relative,
                                                MAX_TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_BYTES,
                                            )?,
                                        )?;
                                    ensure!(
                                        reopened_receipt == receipt,
                                        "post-commit terminal campaign receipt differs from its retained candidate"
                                    );
                                    require_receipt_packet_binding(
                                        &reopened_receipt,
                                        packet_identity,
                                    )?;
                                    Ok(PublishedTerminalEvidenceHandlerResultV2 {
                                        _authority: authority,
                                        _receipt: reopened_receipt,
                                    })
                                })
                            },
                        )
                    })
                },
            )
        })
    }

    fn construct_receipt(
        campaign_precommit_identity: &B4ContractArtifactIdentityV1,
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive_input_set: &B4ContractArtifactIdentityV1,
        positive_generation_set: &B4ContractArtifactIdentityV1,
        invocation: &CapturedExecuteInvocation,
        packet_identity: B4TerminalEvidencePacketIdentityV1,
    ) -> Result<Eip0045B4TerminalEvidenceCampaignReceiptV1> {
        let packet_id = hex::encode(packet_identity.packet_id());
        Eip0045B4TerminalEvidenceCampaignReceiptV1::new(B4TerminalEvidenceCampaignReceiptInputsV1 {
            campaign_precommit: campaign_precommit_identity,
            positive_input_set,
            positive_generation_set,
            executor_artifact: &campaign.precommit().campaign_executor.artifact,
            executor_build_descriptor: &campaign.precommit().campaign_executor.build_descriptor,
            executor_contract: &campaign.precommit().executor_contract,
            process_argv: &invocation.process_argv,
            parsed_preflight_only: invocation.parsed_preflight_only,
            risc0_dev_mode: invocation.risc0_dev_mode.as_deref(),
            terminal_packet_manifest_byte_length: usize::try_from(
                packet_identity.manifest_byte_length(),
            )
            .context("terminal packet manifest length does not fit usize")?,
            terminal_packet_id: &packet_id,
        })
    }

    fn require_receipt_packet_binding(
        receipt: &Eip0045B4TerminalEvidenceCampaignReceiptV1,
        packet_identity: B4TerminalEvidencePacketIdentityV1,
    ) -> Result<()> {
        let packet_id = hex::encode(packet_identity.packet_id());
        require_terminal_packet_identity_binding(
            receipt.terminal_packet_manifest_byte_length(),
            receipt.terminal_packet_id(),
            packet_identity.manifest_byte_length(),
            &packet_id,
        )
        .context("terminal campaign receipt differs from the semantically reopened packet")
    }

    #[cfg(test)]
    mod transition_tests {
        use std::{cell::RefCell, rc::Rc};

        use anyhow::Result;

        use super::{
            PublishTerminalEvidenceTransition, PublishTerminalEvidenceTransitionObserver,
            coordinate_publish_terminal_evidence, coordinate_publish_terminal_evidence_mutation,
        };

        const ORDER: [PublishTerminalEvidenceTransition; 5] = [
            PublishTerminalEvidenceTransition::Prepare,
            PublishTerminalEvidenceTransition::BeginOuterStaging,
            PublishTerminalEvidenceTransition::LiveInnerPublication,
            PublishTerminalEvidenceTransition::WriteReceipt,
            PublishTerminalEvidenceTransition::OuterCommitAndPostcommitValidation,
        ];

        struct Recorder {
            events: Vec<PublishTerminalEvidenceTransition>,
            fail_before: Option<PublishTerminalEvidenceTransition>,
        }

        impl PublishTerminalEvidenceTransitionObserver for Recorder {
            fn before(&mut self, transition: PublishTerminalEvidenceTransition) -> Result<()> {
                self.events.push(transition);
                if self.fail_before == Some(transition) {
                    anyhow::bail!("injected transition failure: {transition:?}");
                }
                Ok(())
            }
        }

        #[derive(Clone)]
        struct DropWitness(Rc<std::cell::Cell<usize>>);

        impl Drop for DropWitness {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }

        fn run_pipeline(
            recorder: &mut Recorder,
            operations: &RefCell<Vec<PublishTerminalEvidenceTransition>>,
            drops: &Rc<std::cell::Cell<usize>>,
        ) -> Result<()> {
            coordinate_publish_terminal_evidence(
                &mut (),
                recorder,
                |_state| {
                    operations
                        .borrow_mut()
                        .push(PublishTerminalEvidenceTransition::Prepare);
                    Ok(DropWitness(Rc::clone(drops)))
                },
                |_state, prepared, observer| {
                    coordinate_publish_terminal_evidence_mutation(
                        observer,
                        prepared,
                        || {
                            operations
                                .borrow_mut()
                                .push(PublishTerminalEvidenceTransition::BeginOuterStaging);
                            Ok(DropWitness(Rc::clone(drops)))
                        },
                        |_transaction, _prepared| {
                            operations
                                .borrow_mut()
                                .push(PublishTerminalEvidenceTransition::LiveInnerPublication);
                            Ok(DropWitness(Rc::clone(drops)))
                        },
                        |_transaction, _published| {
                            operations
                                .borrow_mut()
                                .push(PublishTerminalEvidenceTransition::WriteReceipt);
                            Ok(DropWitness(Rc::clone(drops)))
                        },
                        |_transaction, _published, _receipt| {
                            operations.borrow_mut().push(
                                PublishTerminalEvidenceTransition::OuterCommitAndPostcommitValidation,
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
            assert_eq!(success_drops.get(), 4);

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
                    index.min(4),
                    "all values created before {transition:?} must be suppressed"
                );
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(
    unused_imports,
    reason = "E2 exposes the real handler to the parent before the E8 registry consumes it"
)]
pub(super) use execute::{
    PublishTerminalEvidenceExecuteInputsV2, PublishedTerminalEvidenceHandlerResultV2,
    execute_publish_terminal_evidence_handler, preflight_publish_terminal_evidence_handler,
};

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::fs;

    #[cfg(target_os = "linux")]
    use super::{ExecutorPreflightContext, project_publish_terminal_evidence_layout};
    #[cfg(target_os = "linux")]
    use crate::b4_campaign_executor::authenticated_preflight::derive_campaign_relative_artifact_path;
    #[cfg(target_os = "linux")]
    use eip_0045_reproduction::b4_campaign_contract::MAX_CAMPAIGN_PRECOMMIT_BYTES;

    #[cfg(target_os = "linux")]
    #[test]
    fn projected_preflight_stops_before_authority_proof_or_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let prior = campaign.join("inputs");
        let runs = campaign.join("runs");
        let outer_final = runs.join("run-001");
        fs::create_dir_all(&prior).unwrap();
        fs::create_dir_all(&runs).unwrap();
        fs::write(prior.join("source.bin"), b"stable").unwrap();
        let executable = fs::read_link("/proc/self/exe").unwrap();

        let projected =
            project_publish_terminal_evidence_layout(&campaign, [&prior], &outer_final).unwrap();
        ExecutorPreflightContext::capture(&executable, projected)
            .unwrap()
            .finish_preflight()
            .unwrap();

        assert!(!outer_final.exists());
        assert_eq!(
            fs::read_dir(&runs)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>(),
            Vec::<std::ffi::OsString>::new()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn precommit_locator_derives_one_canonical_campaign_global_path() {
        let campaign = std::path::Path::new("/campaign");
        let prior = std::path::Path::new("/campaign/precommit-root");
        assert_eq!(
            derive_campaign_relative_artifact_path(
                campaign,
                prior,
                "contracts/campaign-precommit.json",
            )
            .unwrap(),
            "precommit-root/contracts/campaign-precommit.json"
        );

        for (root, locator) in [
            (prior, "../campaign-precommit.json"),
            (prior, "contracts//campaign-precommit.json"),
            (prior, "/campaign-precommit.json"),
            (
                std::path::Path::new("/other/precommit-root"),
                "campaign-precommit.json",
            ),
        ] {
            assert!(
                derive_campaign_relative_artifact_path(campaign, root, locator).is_err(),
                "noncanonical or non-campaign locator unexpectedly passed: {locator}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn precommit_locator_read_failures_stop_inside_effect_free_custody() {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let prior = campaign.join("precommit-root");
        let runs = campaign.join("runs");
        let outer_final = runs.join("run-001");
        fs::create_dir_all(&prior).unwrap();
        fs::create_dir_all(&runs).unwrap();
        fs::write(prior.join("campaign-precommit.json"), b"candidate").unwrap();
        fs::write(
            prior.join("oversized.json"),
            vec![b'x'; MAX_CAMPAIGN_PRECOMMIT_BYTES + 1],
        )
        .unwrap();
        let executable = fs::read_link("/proc/self/exe").unwrap();
        let projected =
            project_publish_terminal_evidence_layout(&campaign, [&prior], &outer_final).unwrap();
        let preflight = ExecutorPreflightContext::capture(&executable, projected).unwrap();

        assert!(
            preflight
                .read_immutable_file::<MAX_CAMPAIGN_PRECOMMIT_BYTES>(1, "campaign-precommit.json",)
                .is_err()
        );
        assert!(
            preflight
                .read_immutable_file::<MAX_CAMPAIGN_PRECOMMIT_BYTES>(0, "missing.json")
                .is_err()
        );
        assert!(
            preflight
                .read_immutable_file::<MAX_CAMPAIGN_PRECOMMIT_BYTES>(0, "oversized.json")
                .is_err()
        );
        assert!(!outer_final.exists());
        assert_eq!(
            fs::read_dir(&runs)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<Vec<_>>(),
            Vec::<std::ffi::OsString>::new()
        );
    }

    #[test]
    fn execute_source_keeps_the_required_one_way_order_and_private_result() {
        let source = include_str!("publish_terminal_evidence.rs");
        let authenticated_source = source
            .split("fn authenticate_publish_terminal_evidence_preflight")
            .nth(1)
            .expect("shared authenticated preflight must exist")
            .split("/// Reach the exact zero-effect production boundary")
            .next()
            .expect("authenticated preflight must end before the mode wrappers");
        let execute_source = source
            .split("pub(crate) fn execute_publish_terminal_evidence_handler")
            .nth(1)
            .expect("real execute handler must exist")
            .split("fn construct_receipt(")
            .next()
            .expect("execute handler must end before receipt construction");
        let projection = authenticated_source
            .find("project_publish_terminal_evidence_layout(")
            .expect("shared preflight must begin from the exported projector");
        let retained_preflight = authenticated_source
            .find("ExecutorPreflightContext::capture(")
            .expect("shared preflight must enter retained outer custody");
        let executable_binding = authenticated_source
            .find("require_current_executable_binding(")
            .expect("shared preflight must bind the running executable");
        assert!(projection < retained_preflight && retained_preflight < executable_binding);

        let authenticated_call = execute_source
            .find("authenticate_publish_terminal_evidence_preflight(&inputs, false)")
            .expect("execute must traverse the shared final safe boundary");
        let execute_gate = execute_source
            .find("preflight.execute(")
            .expect("handler must consume the affine preflight context");
        let coordinator = execute_source
            .find("coordinate_publish_terminal_evidence(")
            .expect("handler must use the instrumented one-way coordinator");
        let preparation = execute_source
            .find("prepare_lineaged_b4_terminal_evidence_packet_v2(")
            .expect("handler must use the linked preparation phase");
        let staging = execute_source
            .find("begin_create_only_directory()")
            .expect("handler must create outer staging through E1");
        let transactional_publication = execute_source
            .find("publish_and_adopt_directory_tree(")
            .expect("handler must publish and adopt under one retained outer descriptor");
        let descriptor_publication = execute_source
            .find(
                "publish_prepared_lineaged_b4_terminal_evidence_packet_from_directory_descriptor_v2(",
            )
            .expect("handler must use the consuming descriptor-rooted publication phase");
        let outer_commit = execute_source
            .find("commit_with_postcommit_validation(")
            .expect("handler must retain post-commit validation custody");
        let semantic_reopen = execute_source
            .find("reopen_b4_terminal_evidence_packet_from_directory_descriptor(")
            .expect("handler must semantically reopen from the retained directory");
        let rebind = execute_source
            .find("rebind_postcommit_semantically_reopened_packet(")
            .expect("handler must rebind the generation authority after reopen");

        assert!(
            authenticated_call < execute_gate
                && execute_gate < coordinator
                && coordinator < preparation
                && preparation < staging
                && staging < transactional_publication
                && transactional_publication < descriptor_publication
                && descriptor_publication < outer_commit
                && outer_commit < semantic_reopen
                && semantic_reopen < rebind
        );
        assert_eq!(
            execute_source
                .matches("coordinate_publish_terminal_evidence(")
                .count(),
            1,
            "the real handler must call the sole outer coordinator exactly once"
        );
        assert_eq!(
            execute_source
                .matches("coordinate_publish_terminal_evidence_mutation(")
                .count(),
            1,
            "the real handler must call the sole mutation coordinator exactly once"
        );
        assert!(
            !execute_source.contains("staged_inner_final_path().to_path_buf()")
                && !execute_source
                    .contains("publish_prepared_lineaged_b4_terminal_evidence_packet(&"),
            "nested publication must not regain a pathname parent"
        );
        let private_declaration = [
            "pub(crate) struct ",
            "PublishedTerminalEvidenceHandlerResultV2",
        ]
        .concat();
        let public_declaration =
            ["pub struct ", "PublishedTerminalEvidenceHandlerResultV2"].concat();
        assert!(source.contains(&private_declaration));
        assert!(!source.contains(&public_declaration));
    }

    #[test]
    fn receipt_binding_uses_the_shared_terminal_packet_identity_predicate() {
        let source = include_str!("publish_terminal_evidence.rs");
        let receipt_binding_source = source
            .split("fn require_receipt_packet_binding")
            .nth(1)
            .expect("post-commit receipt binding must exist")
            .split("#[cfg(test)]")
            .next()
            .expect("receipt binding must end before transition tests");
        assert_eq!(
            receipt_binding_source
                .matches("require_terminal_packet_identity_binding(")
                .count(),
            1
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn execute_physically_authenticates_precommit_and_constructs_prover_only_in_gate() {
        let source = include_str!("publish_terminal_evidence.rs");
        let invocation_capture_source = source
            .split("impl CapturedExecuteInvocation")
            .nth(1)
            .expect("retained invocation capture must exist")
            .split("struct AuthenticatedPublishTerminalEvidencePreflightV1")
            .next()
            .expect("invocation capture must end before authenticated preflight state");
        let authenticated_source = source
            .split("fn authenticate_publish_terminal_evidence_preflight")
            .nth(1)
            .expect("shared authenticated preflight must exist")
            .split("/// Reach the exact zero-effect production boundary")
            .next()
            .expect("authenticated preflight must end before the mode wrappers");
        let preflight_source = source
            .split("pub(crate) fn preflight_publish_terminal_evidence_handler")
            .nth(1)
            .expect("real preflight handler must exist")
            .split("/// Execute the real linked producer")
            .next()
            .expect("preflight handler must end before execute mode");
        let execute_source = source
            .split("pub(crate) fn execute_publish_terminal_evidence_handler")
            .nth(1)
            .expect("real execute handler must exist")
            .split("fn construct_receipt(")
            .next()
            .expect("execute handler must end before receipt construction");

        let identity_path = authenticated_source
            .find("derive_campaign_relative_artifact_path(")
            .expect("receipt path must be derived from retained campaign/root topology");
        let retained_read = authenticated_source
            .find("read_immutable_file::<MAX_CAMPAIGN_PRECOMMIT_BYTES>")
            .expect("campaign precommit must be read below immutable-root custody");
        let precommit_authentication = authenticated_source
            .find("let campaign_precommit_identity = authenticate_campaign_precommit_file(")
            .expect("retained bytes must construct the sole owned precommit identity");
        let invocation = authenticated_source
            .find("CapturedExecuteInvocation::capture(parsed_preflight_only)")
            .expect("argv and RISC0_DEV_MODE must be captured before proof work");
        let lineage = authenticated_source
            .find(".verify_authority_bindings(")
            .expect("complete terminal lineage must be rebound before proof work");
        let executable_binding = authenticated_source
            .find("require_current_executable_binding(")
            .expect("handler must bind the running executable");
        let authenticated_return = authenticated_source
            .find("Ok(AuthenticatedPublishTerminalEvidencePreflightV1 {")
            .expect("shared preflight must return only after every safe check");
        let proof_gate = execute_source
            .find("execute.with_proof(")
            .expect("proof work must remain behind the proof capability");
        let prover = execute_source
            .find("LocalProver::new(")
            .expect("real handler must construct the linked prover");
        let mutation_gate = execute_source
            .find("execute.with_mutation(")
            .expect("publication must remain behind the mutation capability");
        let receipt_binding = execute_source
            .find("&campaign_precommit_identity,")
            .expect("receipt must consume the identity rebuilt from retained bytes");

        assert!(
            identity_path < retained_read
                && retained_read < precommit_authentication
                && precommit_authentication < invocation
                && invocation < lineage
                && lineage < executable_binding
                && executable_binding < authenticated_return,
            "shared preflight locator, custody, authority, argv, or executable order drifted"
        );
        assert!(
            proof_gate < prover && prover < mutation_gate && mutation_gate < receipt_binding,
            "prover construction or mutation order drifted"
        );
        assert!(
            preflight_source
                .contains("authenticate_publish_terminal_evidence_preflight(inputs, true)")
                && preflight_source.contains(".finish_preflight()"),
            "global preflight no longer traverses the shared final safe boundary"
        );
        assert!(
            invocation_capture_source.contains("validate_b4_publish_terminal_evidence_invocation(")
                && !invocation_capture_source
                    .contains("b4_publish_terminal_evidence_canonical_argv_sha256("),
            "preflight invocation capture must use the dual-mode validator, not the execute-only receipt hasher"
        );
        assert!(
            execute_source
                .contains("authenticate_publish_terminal_evidence_preflight(&inputs, false)"),
            "execute no longer traverses the same shared final safe boundary"
        );
        assert_eq!(
            execute_source.matches("LocalProver::new(").count(),
            1,
            "the handler must construct exactly one prover inside the proof gate"
        );
        let proof_body = execute_source
            .split("execute.with_proof(|_capability| {")
            .nth(1)
            .expect("proof gate closure must retain the prover construction")
            .split("})")
            .next()
            .expect("proof gate closure must end before mutation");
        let gated_prover = proof_body
            .find("LocalProver::new(")
            .expect("prover construction escaped the proof gate");
        let gated_preparation = proof_body
            .find("prepare_lineaged_b4_terminal_evidence_packet_v2(")
            .expect("linked preparation escaped the proof gate");
        assert!(gated_prover < gated_preparation);
        let input_shape = source
            .split("pub(crate) struct PublishTerminalEvidenceExecuteInputsV2")
            .nth(1)
            .unwrap()
            .split("impl<'authority")
            .next()
            .unwrap();
        assert!(input_shape.contains("campaign_precommit_root_relative_path:"));
        assert!(input_shape.contains("positive: B4PositiveGenerationAuthorityV2,"));
        assert!(input_shape.contains("lineage: B4TerminalSourceLineageAuthorityV2,"));
        assert!(!input_shape.contains("positive: &'authority"));
        assert!(
            !input_shape.contains("campaign_precommit_identity:"),
            "execute inputs must not accept a caller-certified precommit identity"
        );
        assert!(!source.contains("b4_positive_gate::B4PositiveGenerationAuthorityV1"));
        assert!(!source.contains("B4TerminalSourceLineageAuthorityV1"));
        assert!(execute_source.contains("published.positive_input_set_identity()"));
        assert!(execute_source.contains("published.positive_generation_set_identity()"));
        assert!(execute_source.contains(".rebind_postcommit_semantically_reopened_packet_v2("));
    }
}
