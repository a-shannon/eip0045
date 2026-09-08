//! Descriptor-rooted physical import of reviewed Git bundle bytes.

use std::io::{Read, Result as IoResult};

use anyhow::{Result, ensure};

use super::{
    artifact_import_contract::{ArtifactImportLimitsV1, B4ImmutableArtifactRoleV1},
    capability::MutationCapability,
    preflight::ProjectedPrepareInputSetCampaignLayout,
};

const REVIEWED_GIT_BUNDLE_MAX_BYTES: u64 = 1_073_741_824;

/// Affine permit constructible only by this module's closed import route.
///
/// The custody layer consumes it together with the exact prepare-input-set
/// mutation capability, so no sibling module can call the role-specialized
/// stream primitive with a caller-selected root or path.
pub(super) struct ReviewedGitBundleCustodyPermitV1 {
    _private: (),
}

/// One H0-plan slot for a reviewed Git bundle.
///
/// There is intentionally no production constructor yet: the final closed H0
/// topology must derive each slot rather than accept a caller-selected path.
pub(super) struct ReviewedGitBundleSlotV1 {
    root_index: usize,
    relative_path: String,
}

impl ReviewedGitBundleSlotV1 {
    #[cfg(test)]
    fn test_only(root_index: usize, relative_path: &str) -> Self {
        Self {
            root_index,
            relative_path: relative_path.to_owned(),
        }
    }
}

/// Forward-only, descriptor-rooted stream available only to one inspector.
///
/// The stream has no seek or descriptor escape. Its reported identity is the
/// retained snapshot expectation; it becomes an authenticated measurement only
/// after the inspector consumes exact EOF and custody completes every postcheck.
pub(super) struct ReviewedGitBundleInspectionStreamV1<'reader> {
    reader: &'reader mut (dyn Read + 'reader),
    byte_length: u64,
    sha256: [u8; 32],
}

impl ReviewedGitBundleInspectionStreamV1<'_> {
    pub(super) const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    pub(super) const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

impl Read for ReviewedGitBundleInspectionStreamV1<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> IoResult<usize> {
        self.reader.read(buffer)
    }
}

/// Inert post-custody view of one authenticated physical Git bundle.
///
/// This view proves only exact descriptor-rooted bytes, length and SHA-256. It
/// does not prove Git syntax, commit/tree reachability, source inventory, H0,
/// or any publication authority.
pub(super) struct ImportedReviewedGitBundleViewV1<'inspection, Inspection> {
    inspection: &'inspection Inspection,
    byte_length: u64,
    sha256: [u8; 32],
}

impl<'inspection, Inspection> ImportedReviewedGitBundleViewV1<'inspection, Inspection> {
    pub(super) const fn inspection(&self) -> &'inspection Inspection {
        self.inspection
    }

    pub(super) const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    pub(super) const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

/// Inspect one reviewed bundle from a retained descriptor, then deliver the
/// owned inspection result only after exact EOF, hash, repin and root rechecks.
pub(super) fn with_imported_reviewed_git_bundle<const ROOTS: usize, Inspection, T>(
    capability: &mut MutationCapability<'_, ROOTS, ProjectedPrepareInputSetCampaignLayout<ROOTS>>,
    slot: &ReviewedGitBundleSlotV1,
    inspect: impl for<'reader> FnOnce(
        ReviewedGitBundleInspectionStreamV1<'reader>,
    ) -> Result<Inspection>,
    effect: impl for<'inspection> FnOnce(
        ImportedReviewedGitBundleViewV1<'inspection, Inspection>,
    ) -> Result<T>,
) -> Result<T> {
    checked_reviewed_git_bundle_limits()?;
    capability.with_authenticated_reviewed_git_bundle_stream(
        ReviewedGitBundleCustodyPermitV1 { _private: () },
        slot.root_index,
        &slot.relative_path,
        move |byte_length, sha256, reader| {
            inspect(ReviewedGitBundleInspectionStreamV1 {
                reader,
                byte_length,
                sha256,
            })
        },
        move |byte_length, sha256, inspection| {
            effect(ImportedReviewedGitBundleViewV1 {
                inspection,
                byte_length,
                sha256,
            })
        },
    )
}

fn checked_reviewed_git_bundle_limits() -> Result<ArtifactImportLimitsV1> {
    let limits = B4ImmutableArtifactRoleV1::ReviewedGitBundle.limits();
    let (minimum, maximum) = limits.encoded_byte_range();
    ensure!(
        minimum == 1 && maximum == REVIEWED_GIT_BUNDLE_MAX_BYTES,
        "reviewed Git bundle custody ceiling differs from its closed role contract"
    );
    Ok(limits)
}

#[cfg(all(test, target_os = "linux"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReviewedGitBundleImportStage {
    PathPinned,
    DataOpened,
    BytesRead,
    FileRepinned,
}

#[cfg(all(test, target_os = "linux"))]
fn with_imported_reviewed_git_bundle_test_hook<const ROOTS: usize, Inspection, T>(
    capability: &mut MutationCapability<'_, ROOTS, ProjectedPrepareInputSetCampaignLayout<ROOTS>>,
    slot: &ReviewedGitBundleSlotV1,
    mut hook: impl FnMut(ReviewedGitBundleImportStage) -> Result<()>,
    inspect: impl for<'reader> FnOnce(
        ReviewedGitBundleInspectionStreamV1<'reader>,
    ) -> Result<Inspection>,
    effect: impl for<'inspection> FnOnce(
        ImportedReviewedGitBundleViewV1<'inspection, Inspection>,
    ) -> Result<T>,
) -> Result<T> {
    use super::custody::ImmutableFileReadStage;

    checked_reviewed_git_bundle_limits()?;
    capability.with_authenticated_reviewed_git_bundle_stream_test_hook(
        ReviewedGitBundleCustodyPermitV1 { _private: () },
        slot.root_index,
        &slot.relative_path,
        move |stage| {
            hook(match stage {
                ImmutableFileReadStage::PathPinned => ReviewedGitBundleImportStage::PathPinned,
                ImmutableFileReadStage::DataOpened => ReviewedGitBundleImportStage::DataOpened,
                ImmutableFileReadStage::BytesRead => ReviewedGitBundleImportStage::BytesRead,
                ImmutableFileReadStage::FileRepinned => ReviewedGitBundleImportStage::FileRepinned,
            })
        },
        move |byte_length, sha256, reader| {
            inspect(ReviewedGitBundleInspectionStreamV1 {
                reader,
                byte_length,
                sha256,
            })
        },
        move |byte_length, sha256, inspection| {
            effect(ImportedReviewedGitBundleViewV1 {
                inspection,
                byte_length,
                sha256,
            })
        },
    )
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        fs,
        io::{ErrorKind, Read as _},
        os::unix::fs::MetadataExt as _,
        path::{Path, PathBuf},
        rc::Rc,
    };

    use anyhow::{Result, bail};
    use sha2::{Digest as _, Sha256};

    use super::{
        ImportedReviewedGitBundleViewV1, MutationCapability, ReviewedGitBundleCustodyPermitV1,
        ReviewedGitBundleImportStage, ReviewedGitBundleInspectionStreamV1, ReviewedGitBundleSlotV1,
        checked_reviewed_git_bundle_limits, with_imported_reviewed_git_bundle,
        with_imported_reviewed_git_bundle_test_hook,
    };
    use crate::b4_campaign_executor::{
        capability::{CustodyPostcheckBoundaryV1, CustodyPostcheckCombinedFailureV1},
        custody::{AuthenticatedStreamCombinedFailureV1, AuthenticatedStreamFailurePairV1},
        preflight::{
            ProjectedPrepareInputSetCampaignLayout, project_prepare_input_set_campaign_layout,
        },
        typestate::ExecutorPreflightContext,
    };

    type TestContext = ExecutorPreflightContext<1, ProjectedPrepareInputSetCampaignLayout<1>>;

    const BUNDLE: &[u8] = b"# v2 git bundle\n0123456789abcdef0123456789abcdef01234567 HEAD\n\nPACK";

    struct NominalSubstitutionGuard {
        nominal: PathBuf,
        retained: PathBuf,
        active: bool,
    }

    impl NominalSubstitutionGuard {
        fn new(nominal: PathBuf) -> Self {
            let retained = nominal.with_extension("retained");
            Self {
                nominal,
                retained,
                active: false,
            }
        }

        fn substitute(&mut self, replacement: &[u8]) -> Result<()> {
            fs::rename(&self.nominal, &self.retained)?;
            self.active = true;
            fs::write(&self.nominal, replacement)?;
            Ok(())
        }

        fn restore(&mut self) -> Result<()> {
            if self.active {
                if self.nominal.try_exists()? {
                    fs::remove_file(&self.nominal)?;
                }
                fs::rename(&self.retained, &self.nominal)?;
                self.active = false;
            }
            Ok(())
        }
    }

    impl Drop for NominalSubstitutionGuard {
        fn drop(&mut self) {
            let _ = self.restore();
        }
    }

    fn captured_context(files: &[(&str, &[u8])]) -> (tempfile::TempDir, PathBuf, TestContext) {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let prior = campaign.join("authoritative-inputs");
        let output = campaign.join("phases/prepare-001");
        fs::create_dir_all(&prior).unwrap();
        fs::create_dir_all(output.parent().unwrap()).unwrap();
        for (relative, bytes) in files {
            fs::write(prior.join(relative), bytes).unwrap();
        }
        let layout =
            project_prepare_input_set_campaign_layout(&campaign, [&prior], &output).unwrap();
        let executable = fs::read_link("/proc/self/exe").unwrap();
        let context = ExecutorPreflightContext::capture(&executable, layout).unwrap();
        (temp, prior, context)
    }

    #[test]
    fn reviewed_git_bundle_import_streams_exact_descriptor_rooted_bytes_under_closed_role() {
        let expected_sha256: [u8; 32] = Sha256::digest(BUNDLE).into();
        let (_temp, prior, context) = captured_context(&[("reviewed.bundle", BUNDLE)]);
        let output = prior.parent().unwrap().join("phases/prepare-001");
        let slot = ReviewedGitBundleSlotV1::test_only(0, "reviewed.bundle");

        context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_reviewed_git_bundle(
                        capability,
                        &slot,
                        |mut stream| {
                            assert_eq!(stream.byte_length(), u64::try_from(BUNDLE.len())?);
                            assert_eq!(stream.sha256(), expected_sha256);
                            let mut observed = vec![0_u8; BUNDLE.len()];
                            stream.read_exact(&mut observed)?;
                            Ok(observed)
                        },
                        |view| {
                            assert_eq!(view.byte_length(), u64::try_from(BUNDLE.len())?);
                            assert_eq!(view.sha256(), expected_sha256);
                            assert_eq!(view.inspection().as_slice(), BUNDLE);
                            Ok(())
                        },
                    )
                })
            })
            .unwrap();
        assert!(!output.exists());
    }

    #[test]
    fn reviewed_git_bundle_stream_ceiling_is_crosslocked_to_the_closed_role() {
        let limits = checked_reviewed_git_bundle_limits().unwrap();
        assert_eq!(limits.encoded_byte_range(), (1, 1_073_741_824));
        limits
            .validate_encoded_length(1_073_741_824, "reviewed Git bundle")
            .unwrap();
        assert!(
            limits
                .validate_encoded_length(1_073_741_825, "reviewed Git bundle")
                .is_err()
        );
    }

    #[test]
    fn reviewed_git_bundle_import_rejects_an_inspector_that_returns_before_exact_length() {
        let (_temp, _prior, context) = captured_context(&[("reviewed.bundle", BUNDLE)]);
        let slot = ReviewedGitBundleSlotV1::test_only(0, "reviewed.bundle");
        let delivered = Rc::new(Cell::new(false));
        let effect_delivered = Rc::clone(&delivered);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_reviewed_git_bundle(
                        capability,
                        &slot,
                        |mut stream| {
                            let mut prefix = [0_u8; 4];
                            stream.read_exact(&mut prefix)?;
                            Ok(prefix)
                        },
                        move |_view| {
                            effect_delivered.set(true);
                            Ok(())
                        },
                    )
                })
            })
            .unwrap_err();

        assert!(
            format!("{error:#}").contains("not consumed to its retained length"),
            "{error:#}"
        );
        assert!(!delivered.get());
    }

    #[test]
    fn reviewed_git_bundle_inspection_failure_still_repins_before_returning() {
        let (_temp, _prior, context) = captured_context(&[("reviewed.bundle", BUNDLE)]);
        let slot = ReviewedGitBundleSlotV1::test_only(0, "reviewed.bundle");
        let stages = Rc::new(RefCell::new(Vec::new()));
        let hook_stages = Rc::clone(&stages);
        let delivery_reached = Rc::new(Cell::new(false));
        let delivery_flag = Rc::clone(&delivery_reached);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_reviewed_git_bundle_test_hook(
                        capability,
                        &slot,
                        move |stage| {
                            hook_stages.borrow_mut().push(stage);
                            Ok(())
                        },
                        |_stream| -> Result<()> { bail!("injected Git inspection failure") },
                        move |_view| {
                            delivery_flag.set(true);
                            Ok(())
                        },
                    )
                })
            })
            .unwrap_err();

        assert!(
            format!("{error:#}").contains("injected Git inspection failure"),
            "{error:#}"
        );
        assert_eq!(
            stages.borrow().as_slice(),
            [
                ReviewedGitBundleImportStage::PathPinned,
                ReviewedGitBundleImportStage::DataOpened,
                ReviewedGitBundleImportStage::FileRepinned,
            ]
        );
        assert!(!delivery_reached.get());
    }

    #[test]
    fn reviewed_git_bundle_inspection_error_preserves_a_sticky_stream_failure() {
        let (_temp, prior, context) = captured_context(&[("reviewed.bundle", BUNDLE)]);
        let bundle_path = prior.join("reviewed.bundle");
        let slot = ReviewedGitBundleSlotV1::test_only(0, "reviewed.bundle");
        let delivery_reached = Rc::new(Cell::new(false));
        let delivery_flag = Rc::clone(&delivery_reached);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_reviewed_git_bundle(
                        capability,
                        &slot,
                        |mut stream| -> Result<()> {
                            let mut prefix = [0_u8; 4];
                            stream.read_exact(&mut prefix)?;
                            fs::OpenOptions::new()
                                .write(true)
                                .open(&bundle_path)?
                                .set_len(0)?;
                            let mut next = [0_u8; 1];
                            let first = stream.read(&mut next).unwrap_err();
                            assert_eq!(first.kind(), ErrorKind::UnexpectedEof);
                            let replayed = stream.read(&mut next).unwrap_err();
                            assert_eq!(replayed.kind(), ErrorKind::UnexpectedEof);
                            bail!("injected Git parse failure after read error")
                        },
                        move |_view| {
                            delivery_flag.set(true);
                            Ok(())
                        },
                    )
                })
            })
            .unwrap_err();

        let message = format!("{error:#}");
        assert!(
            message.contains("injected Git parse failure after read error"),
            "{message}"
        );
        assert!(
            message.contains("ended before its retained length"),
            "{message}"
        );
        assert!(!delivery_reached.get());
    }

    #[test]
    fn reviewed_git_bundle_import_rejects_growth_before_the_exact_eof_probe() {
        let (_temp, prior, context) = captured_context(&[("reviewed.bundle", BUNDLE)]);
        let bundle_path = prior.join("reviewed.bundle");
        let slot = ReviewedGitBundleSlotV1::test_only(0, "reviewed.bundle");
        let delivery_reached = Rc::new(Cell::new(false));
        let delivery_flag = Rc::clone(&delivery_reached);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_reviewed_git_bundle(
                        capability,
                        &slot,
                        |mut stream| {
                            let mut observed = vec![0_u8; BUNDLE.len()];
                            stream.read_exact(&mut observed)?;
                            fs::OpenOptions::new()
                                .write(true)
                                .open(&bundle_path)?
                                .set_len(u64::try_from(BUNDLE.len() + 1)?)?;
                            Ok(observed)
                        },
                        move |_view| {
                            delivery_flag.set(true);
                            Ok(())
                        },
                    )
                })
            })
            .unwrap_err();

        assert!(
            format!("{error:#}").contains("grew beyond its retained length"),
            "{error:#}"
        );
        assert!(!delivery_reached.get());
    }

    #[test]
    fn reviewed_git_bundle_import_rejects_same_inode_same_length_mutation_during_streaming() {
        let (_temp, prior, context) = captured_context(&[("reviewed.bundle", BUNDLE)]);
        let bundle_path = prior.join("reviewed.bundle");
        let slot = ReviewedGitBundleSlotV1::test_only(0, "reviewed.bundle");
        let delivery_reached = Rc::new(Cell::new(false));
        let delivery_flag = Rc::clone(&delivery_reached);
        let mut mutated = BUNDLE.to_vec();
        mutated[4] ^= 1;

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_reviewed_git_bundle(
                        capability,
                        &slot,
                        |mut stream| {
                            let before = fs::metadata(&bundle_path)?;
                            let mut prefix = [0_u8; 4];
                            stream.read_exact(&mut prefix)?;
                            fs::write(&bundle_path, &mutated)?;
                            let after = fs::metadata(&bundle_path)?;
                            assert_eq!(before.dev(), after.dev());
                            assert_eq!(before.ino(), after.ino());
                            assert_eq!(before.len(), after.len());
                            let mut suffix = Vec::new();
                            stream.read_to_end(&mut suffix)?;
                            Ok((prefix, suffix))
                        },
                        move |_view| {
                            delivery_flag.set(true);
                            Ok(())
                        },
                    )
                })
            })
            .unwrap_err();

        assert!(
            format!("{error:#}").contains("digest differs from retained custody"),
            "{error:#}"
        );
        assert!(!delivery_reached.get());
    }

    #[test]
    fn reviewed_git_bundle_import_rechecks_the_file_after_bytes_read() {
        let (_temp, prior, context) = captured_context(&[("reviewed.bundle", BUNDLE)]);
        let bundle_path = prior.join("reviewed.bundle");
        let slot = ReviewedGitBundleSlotV1::test_only(0, "reviewed.bundle");
        let bytes_read_reached = Rc::new(Cell::new(false));
        let hook_flag = Rc::clone(&bytes_read_reached);
        let delivery_reached = Rc::new(Cell::new(false));
        let delivery_flag = Rc::clone(&delivery_reached);
        let mut mutated = BUNDLE.to_vec();
        mutated[4] ^= 1;

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_reviewed_git_bundle_test_hook(
                        capability,
                        &slot,
                        move |stage| {
                            if stage == ReviewedGitBundleImportStage::BytesRead {
                                let before = fs::metadata(&bundle_path)?;
                                fs::write(&bundle_path, &mutated)?;
                                let after = fs::metadata(&bundle_path)?;
                                assert_eq!(before.dev(), after.dev());
                                assert_eq!(before.ino(), after.ino());
                                assert_eq!(before.len(), after.len());
                                hook_flag.set(true);
                            }
                            Ok(())
                        },
                        |mut stream| {
                            let mut observed = Vec::new();
                            stream.read_to_end(&mut observed)?;
                            Ok(observed)
                        },
                        move |_view| {
                            delivery_flag.set(true);
                            Ok(())
                        },
                    )
                })
            })
            .unwrap_err();

        assert!(bytes_read_reached.get());
        assert!(
            format!("{error:#}").contains("no longer matches its retained snapshot"),
            "{error:#}"
        );
        assert!(!delivery_reached.get());
    }

    #[test]
    fn reviewed_git_bundle_role_length_rejects_empty_before_any_file_open_or_callback() {
        let empty = b"";
        let (_temp, _prior, context) = captured_context(&[("empty.bundle", empty)]);
        let slot = ReviewedGitBundleSlotV1::test_only(0, "empty.bundle");
        let stage_reached = Rc::new(Cell::new(false));
        let inspector_reached = Rc::new(Cell::new(false));
        let delivery_reached = Rc::new(Cell::new(false));
        let hook_flag = Rc::clone(&stage_reached);
        let inspect_flag = Rc::clone(&inspector_reached);
        let delivery_flag = Rc::clone(&delivery_reached);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_reviewed_git_bundle_test_hook(
                        capability,
                        &slot,
                        move |_stage| {
                            hook_flag.set(true);
                            Ok(())
                        },
                        move |_stream| {
                            inspect_flag.set(true);
                            Ok(())
                        },
                        move |_view| {
                            delivery_flag.set(true);
                            Ok(())
                        },
                    )
                })
            })
            .unwrap_err();

        assert!(
            format!("{error:#}").contains("role-specific range"),
            "{error:#}"
        );
        assert!(!stage_reached.get());
        assert!(!inspector_reached.get());
        assert!(!delivery_reached.get());
    }

    #[test]
    fn reviewed_git_bundle_import_rejects_path_substitution_before_data_open() {
        let (_temp, prior, context) = captured_context(&[("reviewed.bundle", BUNDLE)]);
        let bundle_path = prior.join("reviewed.bundle");
        let slot = ReviewedGitBundleSlotV1::test_only(0, "reviewed.bundle");
        let inspector_reached = Rc::new(Cell::new(false));
        let delivery_reached = Rc::new(Cell::new(false));
        let inspect_flag = Rc::clone(&inspector_reached);
        let delivery_flag = Rc::clone(&delivery_reached);
        let mut substitution = NominalSubstitutionGuard::new(bundle_path);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_reviewed_git_bundle_test_hook(
                        capability,
                        &slot,
                        move |stage| {
                            if stage == ReviewedGitBundleImportStage::PathPinned {
                                substitution.substitute(BUNDLE)?;
                            }
                            Ok(())
                        },
                        move |_stream| {
                            inspect_flag.set(true);
                            Ok(())
                        },
                        move |_view| {
                            delivery_flag.set(true);
                            Ok(())
                        },
                    )
                })
            })
            .unwrap_err();

        assert!(
            format!("{error:#}").contains("changed while opening its data descriptor"),
            "{error:#}"
        );
        assert!(!inspector_reached.get());
        assert!(!delivery_reached.get());
    }

    #[test]
    fn reviewed_git_bundle_import_rejects_byte_identical_inode_substitution_before_repin() {
        let (_temp, prior, context) = captured_context(&[("reviewed.bundle", BUNDLE)]);
        let bundle_path = prior.join("reviewed.bundle");
        let slot = ReviewedGitBundleSlotV1::test_only(0, "reviewed.bundle");
        let delivery_reached = Rc::new(Cell::new(false));
        let delivery_flag = Rc::clone(&delivery_reached);
        let mut substitution = NominalSubstitutionGuard::new(bundle_path);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_reviewed_git_bundle_test_hook(
                        capability,
                        &slot,
                        move |stage| {
                            if stage == ReviewedGitBundleImportStage::DataOpened {
                                substitution.substitute(BUNDLE)?;
                            }
                            Ok(())
                        },
                        |mut stream| {
                            let mut observed = Vec::new();
                            stream.read_to_end(&mut observed)?;
                            Ok(observed)
                        },
                        move |_view| {
                            delivery_flag.set(true);
                            Ok(())
                        },
                    )
                })
            })
            .unwrap_err();

        let message = format!("{error:#}");
        assert!(
            message.contains("no longer matches") || message.contains("no longer identifies"),
            "{message}"
        );
        assert!(!delivery_reached.get());
    }

    #[test]
    fn reviewed_git_bundle_import_rechecks_the_whole_root_before_delivery() {
        let companion = b"stable companion";
        let (_temp, prior, context) =
            captured_context(&[("reviewed.bundle", BUNDLE), ("companion.bin", companion)]);
        let companion_path = prior.join("companion.bin");
        let slot = ReviewedGitBundleSlotV1::test_only(0, "reviewed.bundle");
        let delivery_reached = Rc::new(Cell::new(false));
        let delivery_flag = Rc::clone(&delivery_reached);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_reviewed_git_bundle_test_hook(
                        capability,
                        &slot,
                        move |stage| {
                            if stage == ReviewedGitBundleImportStage::FileRepinned {
                                fs::write(&companion_path, b"changed companion")?;
                            }
                            Ok(())
                        },
                        |mut stream| {
                            let mut observed = Vec::new();
                            stream.read_to_end(&mut observed)?;
                            Ok(observed)
                        },
                        move |_view| {
                            delivery_flag.set(true);
                            Ok(())
                        },
                    )
                })
            })
            .unwrap_err();

        assert!(
            format!("{error:#}").contains("pre-delivery postcheck failed"),
            "{error:#}"
        );
        assert!(!delivery_reached.get());
    }

    #[test]
    fn reviewed_git_bundle_inspection_and_file_postcheck_failures_are_both_preserved() {
        let (_temp, prior, context) = captured_context(&[("reviewed.bundle", BUNDLE)]);
        let bundle_path = prior.join("reviewed.bundle");
        let slot = ReviewedGitBundleSlotV1::test_only(0, "reviewed.bundle");
        let delivery_reached = Rc::new(Cell::new(false));
        let delivery_flag = Rc::clone(&delivery_reached);
        let mut substitution = NominalSubstitutionGuard::new(bundle_path);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_reviewed_git_bundle_test_hook(
                        capability,
                        &slot,
                        move |stage| {
                            if stage == ReviewedGitBundleImportStage::DataOpened {
                                substitution.substitute(BUNDLE)?;
                            }
                            Ok(())
                        },
                        |_stream| -> Result<()> { bail!("injected Git inspection failure") },
                        move |_view| {
                            delivery_flag.set(true);
                            Ok(())
                        },
                    )
                })
            })
            .unwrap_err();

        let message = format!("{error:#}");
        assert!(
            message.contains("injected Git inspection failure"),
            "{message}"
        );
        assert!(message.contains("file postcheck also failed"), "{message}");
        assert!(
            message.contains("pre-delivery postcheck also failed"),
            "{message}"
        );
        assert!(!delivery_reached.get());
    }

    #[test]
    fn reviewed_git_bundle_delivery_error_is_returned_after_a_clean_postcheck() {
        let (_temp, _prior, context) = captured_context(&[("reviewed.bundle", BUNDLE)]);
        let slot = ReviewedGitBundleSlotV1::test_only(0, "reviewed.bundle");
        let delivery_reached = Cell::new(false);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_reviewed_git_bundle(
                        capability,
                        &slot,
                        |mut stream| {
                            let mut observed = Vec::new();
                            stream.read_to_end(&mut observed)?;
                            Ok(observed)
                        },
                        |_view| -> Result<u8> {
                            delivery_reached.set(true);
                            bail!("injected Git delivery failure")
                        },
                    )
                })
            })
            .unwrap_err();

        assert!(delivery_reached.get());
        assert!(
            format!("{error:#}").contains("injected Git delivery failure"),
            "{error:#}"
        );
        assert!(!format!("{error:#}").contains("postcheck also failed"));
    }

    #[test]
    fn reviewed_git_bundle_delivery_and_root_failures_are_both_preserved() {
        let (_temp, prior, context) = captured_context(&[("reviewed.bundle", BUNDLE)]);
        let bundle_path = prior.join("reviewed.bundle");
        let slot = ReviewedGitBundleSlotV1::test_only(0, "reviewed.bundle");
        let delivery_reached = Cell::new(false);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_reviewed_git_bundle(
                        capability,
                        &slot,
                        |mut stream| {
                            let mut observed = Vec::new();
                            stream.read_to_end(&mut observed)?;
                            Ok(observed)
                        },
                        |_view| -> Result<u8> {
                            delivery_reached.set(true);
                            fs::write(&bundle_path, b"changed during failed delivery")?;
                            bail!("injected Git delivery failure after mutation")
                        },
                    )
                })
            })
            .unwrap_err();

        assert!(delivery_reached.get());
        let executor_failure = error
            .downcast_ref::<CustodyPostcheckCombinedFailureV1>()
            .expect("executor completion must preserve its typed effect failure");
        assert_eq!(
            executor_failure.boundary(),
            CustodyPostcheckBoundaryV1::ExecutorCompletion
        );
        let mutation_failure = executor_failure
            .effect()
            .downcast_ref::<CustodyPostcheckCombinedFailureV1>()
            .expect("mutation boundary must preserve the typed Git import failure");
        assert_eq!(
            mutation_failure.boundary(),
            CustodyPostcheckBoundaryV1::MutationEffect
        );
        let stream_failure = mutation_failure
            .effect()
            .downcast_ref::<AuthenticatedStreamCombinedFailureV1>()
            .expect("Git import must preserve the typed delivery/postcheck pair");
        assert_eq!(
            stream_failure.pair(),
            AuthenticatedStreamFailurePairV1::DeliveryAndPostcheck
        );
        assert!(
            format!("{:#}", stream_failure.earlier())
                .contains("injected Git delivery failure after mutation")
        );
        assert!(!format!("{:#}", stream_failure.later()).is_empty());
        assert!(!format!("{:#}", mutation_failure.postcheck()).is_empty());
        assert!(!format!("{:#}", executor_failure.postcheck()).is_empty());
        let message = format!("{error:#}");
        assert!(
            message.contains("injected Git delivery failure after mutation"),
            "{message}"
        );
        assert!(message.contains("postcheck also failed"), "{message}");
    }

    #[test]
    fn reviewed_git_bundle_delivery_result_is_rejected_when_the_root_changes() {
        let (_temp, prior, context) = captured_context(&[("reviewed.bundle", BUNDLE)]);
        let bundle_path = prior.join("reviewed.bundle");
        let slot = ReviewedGitBundleSlotV1::test_only(0, "reviewed.bundle");
        let delivery_reached = Cell::new(false);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_reviewed_git_bundle(
                        capability,
                        &slot,
                        |mut stream| {
                            let mut observed = Vec::new();
                            stream.read_to_end(&mut observed)?;
                            Ok(observed)
                        },
                        |_view| {
                            delivery_reached.set(true);
                            fs::write(&bundle_path, b"changed after authentication")?;
                            Ok(0x45_u8)
                        },
                    )
                })
            })
            .unwrap_err();

        assert!(delivery_reached.get());
        assert!(
            format!("{error:#}").contains("delivery completed but its postcheck failed"),
            "{error:#}"
        );
    }

    fn is_rust_identifier_byte(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || byte == b'_' || byte >= 0x80
    }

    fn standalone_keyword_count(source: &str, keyword: &str) -> usize {
        let bytes = source.as_bytes();
        source
            .match_indices(keyword)
            .filter(|(start, _)| {
                let start = *start;
                let end = start + keyword.len();
                let is_raw_identifier = start >= 2 && &bytes[start - 2..start] == b"r#";
                !is_raw_identifier
                    && (start == 0 || !is_rust_identifier_byte(bytes[start - 1]))
                    && (end == bytes.len() || !is_rust_identifier_byte(bytes[end]))
            })
            .count()
    }

    fn standalone_identifier_reference_count(source: &str, identifier: &str) -> usize {
        let bytes = source.as_bytes();
        source
            .match_indices(identifier)
            .filter(|(start, _)| {
                let start = *start;
                let end = start + identifier.len();
                (start == 0 || !is_rust_identifier_byte(bytes[start - 1]))
                    && (end == bytes.len() || !is_rust_identifier_byte(bytes[end]))
            })
            .count()
    }

    #[test]
    fn source_audit_counts_all_explicit_visibility_and_impl_forms() {
        let visibility_forms = concat!(
            "pub fn a() {} pub unsafe fn b() {} pub async fn c() {} ",
            "pub extern \"C\" fn d() {} pub union E { value: u8 } ",
            "pub extern crate f; pub macro g() {} pub(in super) fn h() {} ",
            "pub(crate) fn i() {} pub(super) fn j() {}"
        );
        assert_eq!(standalone_keyword_count(visibility_forms, "pub"), 10);
        assert_eq!(
            standalone_keyword_count("publication pub_name r#pub pubé", "pub"),
            0
        );
        assert_eq!(
            standalone_keyword_count(
                "impl A {} impl Trait for A {} value: impl Iterator<Item = u8> r#impl",
                "impl"
            ),
            3
        );
        assert_eq!(
            standalone_identifier_reference_count("route r#route route_suffix", "route"),
            2
        );
    }

    fn assert_closed_git_bundle_exports(production: &str, compact: &str) {
        for required in [
            "pub(super)structReviewedGitBundleSlotV1",
            "pub(super)structReviewedGitBundleCustodyPermitV1",
            "pub(super)structReviewedGitBundleInspectionStreamV1<'reader>",
            "pub(super)structImportedReviewedGitBundleViewV1<'inspection,Inspection>",
            "pub(super)fnwith_imported_reviewed_git_bundle<constROOTS:usize,Inspection,T>(",
            "implReviewedGitBundleSlotV1{",
            "implReviewedGitBundleInspectionStreamV1<'_>{",
            "implReadforReviewedGitBundleInspectionStreamV1<'_>{",
            "impl<'inspection,Inspection>ImportedReviewedGitBundleViewV1<'inspection,Inspection>{",
            "capability:&mutMutationCapability<'_,ROOTS,ProjectedPrepareInputSetCampaignLayout<ROOTS>>",
            "B4ImmutableArtifactRoleV1::ReviewedGitBundle",
            "with_authenticated_reviewed_git_bundle_stream",
            "implfor<'reader>FnOnce(ReviewedGitBundleInspectionStreamV1<'reader>",
            "implfor<'inspection>FnOnce(ImportedReviewedGitBundleViewV1<'inspection,Inspection>",
            "#[cfg(test)]fntest_only(",
        ] {
            assert!(compact.contains(required), "missing {required}");
        }
        assert_eq!(
            production.matches("impl ReviewedGitBundleSlotV1 {").count(),
            1
        );
        assert_eq!(production.matches("pub(super)").count(), 10);
        assert_eq!(standalone_keyword_count(production, "pub"), 10);
        assert_eq!(standalone_keyword_count(production, "impl"), 6);
        assert_eq!(standalone_keyword_count(production, "mod"), 0);
        assert_eq!(production.matches('#').count(), 1);
        assert_eq!(production.matches('!').count(), 2);
        assert!(production.starts_with("//! Descriptor-rooted physical import"));
        assert_eq!(compact.matches("ensure!(").count(), 1);
        assert_eq!(compact.matches("pub(super)struct").count(), 4);
        assert_eq!(
            compact
                .matches("pub(super)constfnbyte_length(&self)->u64")
                .count(),
            2
        );
        assert_eq!(
            compact
                .matches("pub(super)constfnsha256(&self)->[u8;32]")
                .count(),
            2
        );
        assert_eq!(
            compact
                .matches("pub(super)constfninspection(&self)->&'inspectionInspection")
                .count(),
            1
        );
        for forbidden in [
            "include!",
            "#[macro_export]",
            "macro_rules!",
            "no_mangle",
            "export_name",
        ] {
            assert!(!compact.contains(forbidden), "broadened export {forbidden}");
        }
    }

    fn assert_git_bundle_origin_has_no_ambient_authority(production: &str, slot_impl: &str) {
        assert_eq!(slot_impl.matches("fn ").count(), 1);
        assert_eq!(production.matches("ReviewedGitBundleSlotV1 {").count(), 2);
        assert_eq!(
            production
                .matches("ReviewedGitBundleCustodyPermitV1 {")
                .count(),
            2
        );
        for forbidden in [
            "pubstructReviewedGitBundle",
            "pub(crate)structReviewedGitBundle",
            "fnnew(",
            "fnfrom_path(",
            "std::fs",
            "fs::",
            "File::open",
            "OpenOptions",
            "std::path",
            "path::Path",
            "PathBuf",
            "include_bytes!",
            "canonicalize(",
            "/proc/self/fd",
            "std::process",
            "Command::new",
            "AsFd",
            "AsRawFd",
            "into_inner",
            "Seek",
            "PositiveGateBindings",
            "AuthenticatedPrepareInputSetSourceV1",
            "PrepareInputSetPublicationSource",
            "PrepareInputSetPublicationGuard",
            "PrepareInputSetCreateOnlyPermit",
            "Serialize",
            "Deserialize",
        ] {
            assert!(!production.contains(forbidden), "forbidden {forbidden}");
        }
    }

    fn assert_no_git_bundle_bridge_outside_origin() {
        let parent_module = include_str!("mod.rs");
        assert!(
            parent_module
                .lines()
                .any(|line| line.trim() == "mod git_bundle_import;")
        );
        assert!(!parent_module.contains("pub mod git_bundle_import;"));
        assert!(!parent_module.contains("pub(crate) mod git_bundle_import;"));

        let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/b4_campaign_executor");
        let origin = source_root.join("git_bundle_import.rs");
        let parent = source_root.join("mod.rs");
        let custody = source_root.join("custody.rs");
        let forbidden_references = [
            "ImportedReviewedGitBundleViewV1",
            "ReviewedGitBundleInspectionStreamV1",
            "ReviewedGitBundleCustodyPermitV1",
            "with_imported_reviewed_git_bundle",
            "with_authenticated_reviewed_git_bundle_stream",
            "with_authenticated_reviewed_git_bundle_stream_test_hook",
            "ReviewedGitBundleSlotV1",
            "git_bundle_import",
        ];
        let mut pending_directories = vec![source_root];
        let mut audited_sources = Vec::new();
        while let Some(directory) = pending_directories.pop() {
            for entry in fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                let file_type = entry.file_type().unwrap();
                assert!(!file_type.is_symlink(), "source audit rejects symlinks");
                let path = entry.path();
                if file_type.is_dir() {
                    pending_directories.push(path);
                } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
                    audited_sources.push(path);
                }
            }
        }
        audited_sources.sort();
        assert!(audited_sources.len() >= 2);
        for path in audited_sources {
            if path == origin {
                continue;
            }
            let source = fs::read_to_string(&path).unwrap();
            for forbidden in forbidden_references {
                let expected = if path == parent && forbidden == "git_bundle_import" {
                    1
                } else if path == custody && forbidden == "ReviewedGitBundleCustodyPermitV1" {
                    3
                } else if path == custody
                    && matches!(
                        forbidden,
                        "with_authenticated_reviewed_git_bundle_stream"
                            | "with_authenticated_reviewed_git_bundle_stream_test_hook"
                            | "git_bundle_import"
                    )
                {
                    1
                } else {
                    0
                };
                assert_eq!(
                    standalone_identifier_reference_count(&source, forbidden),
                    expected,
                    "unexpected Git bundle bridge `{forbidden}` in {}",
                    path.display()
                );
            }
        }
    }

    #[test]
    fn reviewed_git_bundle_custody_boundary_requires_unforgeable_affine_route() {
        let origin = include_str!("git_bundle_import.rs")
            .split("#[cfg(all(test, target_os = \"linux\"))]")
            .next()
            .unwrap();
        let custody = include_str!("custody.rs");
        let origin_compact = origin.split_whitespace().collect::<String>();
        let custody_compact = custody.split_whitespace().collect::<String>();

        assert!(
            origin_compact
                .contains("pub(super)structReviewedGitBundleCustodyPermitV1{_private:(),}")
        );
        assert!(origin_compact.contains("ReviewedGitBundleCustodyPermitV1{_private:(),}"));
        assert!(custody_compact.contains(
            "impl<'context,constROOTS:usize>MutationCapability<'context,ROOTS,ProjectedPrepareInputSetCampaignLayout<ROOTS>>{"
        ));
        assert!(custody_compact.contains(
            "pub(super)fnwith_authenticated_reviewed_git_bundle_stream<Parsed,T>(&mutself,_permit:ReviewedGitBundleCustodyPermitV1,"
        ));
        assert!(!custody_compact.contains(
            "pub(super)fnwith_authenticated_reviewed_git_bundle_stream<Parsed,T>(&self,"
        ));
    }

    #[test]
    fn reviewed_git_bundle_import_surface_is_private_affine_and_non_authorizing() {
        let production = include_str!("git_bundle_import.rs")
            .split("#[cfg(all(test, target_os = \"linux\"))]")
            .next()
            .unwrap();
        let compact = production.split_whitespace().collect::<String>();
        let slot_impl = production
            .split("impl ReviewedGitBundleSlotV1 {")
            .nth(1)
            .unwrap()
            .split("/// Forward-only")
            .next()
            .unwrap();

        assert_closed_git_bundle_exports(production, &compact);
        assert_git_bundle_origin_has_no_ambient_authority(production, slot_impl);
        assert_no_git_bundle_bridge_outside_origin();
    }

    #[test]
    fn reviewed_git_bundle_types_do_not_gain_copy_seek_or_descriptor_traits() {
        use std::{
            io::Seek,
            os::fd::{AsFd, AsRawFd},
        };

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

        trait AmbiguousIfSeek<Marker> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfSeek<()> for T {}
        impl<T: ?Sized + Seek> AmbiguousIfSeek<u8> for T {}

        trait AmbiguousIfAsFd<Marker> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfAsFd<()> for T {}
        impl<T: ?Sized + AsFd> AmbiguousIfAsFd<u8> for T {}

        trait AmbiguousIfAsRawFd<Marker> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfAsRawFd<()> for T {}
        impl<T: ?Sized + AsRawFd> AmbiguousIfAsRawFd<u8> for T {}

        <ReviewedGitBundleSlotV1 as AmbiguousIfClone<_>>::marker();
        <ReviewedGitBundleSlotV1 as AmbiguousIfCopy<_>>::marker();
        <ReviewedGitBundleCustodyPermitV1 as AmbiguousIfClone<_>>::marker();
        <ReviewedGitBundleCustodyPermitV1 as AmbiguousIfCopy<_>>::marker();
        <ReviewedGitBundleInspectionStreamV1<'static> as AmbiguousIfClone<_>>::marker();
        <ReviewedGitBundleInspectionStreamV1<'static> as AmbiguousIfCopy<_>>::marker();
        <ReviewedGitBundleInspectionStreamV1<'static> as AmbiguousIfSeek<_>>::marker();
        <ReviewedGitBundleInspectionStreamV1<'static> as AmbiguousIfAsFd<_>>::marker();
        <ReviewedGitBundleInspectionStreamV1<'static> as AmbiguousIfAsRawFd<_>>::marker();
        <ImportedReviewedGitBundleViewV1<'static, ()> as AmbiguousIfClone<_>>::marker();
        <ImportedReviewedGitBundleViewV1<'static, ()> as AmbiguousIfCopy<_>>::marker();
    }

    #[test]
    fn reviewed_git_bundle_import_signature_is_layout_affine_and_higher_ranked() {
        type ExactImportSignature = for<'borrow, 'context, 'slot> fn(
            &'borrow mut MutationCapability<'context, 1, ProjectedPrepareInputSetCampaignLayout<1>>,
            &'slot ReviewedGitBundleSlotV1,
            for<'reader> fn(ReviewedGitBundleInspectionStreamV1<'reader>) -> Result<()>,
            for<'inspection> fn(ImportedReviewedGitBundleViewV1<'inspection, ()>) -> Result<()>,
        ) -> Result<()>;

        let exact: ExactImportSignature = with_imported_reviewed_git_bundle::<1, (), ()>;
        std::hint::black_box(exact);
    }
}
