//! Descriptor-rooted physical import of one bounded AMD64 ELF artifact.

use anyhow::{Context as _, Result, ensure};

use super::{Amd64ElfCommonInspectionV1, InspectedAmd64ElfV1, inspect_runtime_amd64_elf};
use crate::b4_campaign_executor::{
    artifact_import_contract::{
        Amd64ElfPolicyV1, ArtifactImportLimitsV1, B4ImmutableArtifactRoleV1,
    },
    capability::MutationCapability,
    preflight::ProjectedPrepareInputSetCampaignLayout,
};

const AMD64_ELF_MAX_BYTES: u64 = 1_073_741_824;
// The closed parser requires random access to one exact slice, so this
// role-specific temporary image deliberately exceeds generic custody's 512-MiB
// buffered helper. No production slot exists until H0 also binds a compatible
// process-memory budget; this ceiling must never become an ambient read limit.
const MAX_BUFFERED_AMD64_ELF_INSPECTION_BYTES: u64 = AMD64_ELF_MAX_BYTES;

/// Affine permit constructible only by this module's closed import route.
///
/// Custody consumes it together with the exact prepare-input-set mutation
/// capability. Its private field prevents sibling modules from selecting an
/// ambient root, path, policy, or parser.
pub(in crate::b4_campaign_executor) struct Amd64ElfCustodyPermitV1 {
    _private: (),
}

/// One pre-H0 slot for a native AMD64 ELF and its closed linkage policy.
///
/// There is intentionally no production constructor yet: the final H0
/// topology must derive every slot rather than accept a caller-selected path.
pub(in crate::b4_campaign_executor) struct Amd64ElfSlotV1 {
    root_index: usize,
    relative_path: String,
    policy: Amd64ElfPolicyV1,
}

impl Amd64ElfSlotV1 {
    #[cfg(test)]
    fn test_only(root_index: usize, relative_path: &str, policy: Amd64ElfPolicyV1) -> Self {
        Self {
            root_index,
            relative_path: relative_path.to_owned(),
            policy,
        }
    }
}

/// Owned runtime-linkage fields copied from the authenticated borrowed body.
#[derive(Debug, Eq, PartialEq)]
pub(in crate::b4_campaign_executor) struct ImportedRuntimeAmd64ElfInspectionV1 {
    interpreter_path: String,
    dynamic_entry_count: u64,
    needed_library_count: u64,
}

impl ImportedRuntimeAmd64ElfInspectionV1 {
    pub(in crate::b4_campaign_executor) fn interpreter_path(&self) -> &str {
        &self.interpreter_path
    }

    pub(in crate::b4_campaign_executor) const fn dynamic_entry_count(&self) -> u64 {
        self.dynamic_entry_count
    }

    pub(in crate::b4_campaign_executor) const fn needed_library_count(&self) -> u64 {
        self.needed_library_count
    }
}

/// Owned linkage projection which carries no ELF body, descriptor, or custody
/// path. The runtime variant retains only the bounded interpreter path parsed
/// from the ELF itself.
#[derive(Debug, Eq, PartialEq)]
pub(in crate::b4_campaign_executor) enum ImportedAmd64ElfLinkageV1 {
    Static,
    Runtime(ImportedRuntimeAmd64ElfInspectionV1),
}

struct OwnedAmd64ElfInspectionV1 {
    policy: Amd64ElfPolicyV1,
    byte_length: u64,
    sha256: [u8; 32],
    common: Option<Amd64ElfCommonInspectionV1>,
    linkage: ImportedAmd64ElfLinkageV1,
}

/// Inert post-custody view of one authenticated and structurally inspected ELF.
///
/// Its backing inspection is borrowed only after exact EOF, digest, descriptor,
/// nominal repin, and complete-root checks succeed. No file body, custody path,
/// handle, stream, launch capability, or H0 authority is exposed.
pub(in crate::b4_campaign_executor) struct ImportedAmd64ElfViewV1<'inspection> {
    inspection: &'inspection OwnedAmd64ElfInspectionV1,
}

impl ImportedAmd64ElfViewV1<'_> {
    pub(in crate::b4_campaign_executor) const fn policy(&self) -> Amd64ElfPolicyV1 {
        self.inspection.policy
    }

    pub(in crate::b4_campaign_executor) const fn byte_length(&self) -> u64 {
        self.inspection.byte_length
    }

    pub(in crate::b4_campaign_executor) const fn sha256(&self) -> [u8; 32] {
        self.inspection.sha256
    }

    pub(in crate::b4_campaign_executor) const fn common(
        &self,
    ) -> Option<&Amd64ElfCommonInspectionV1> {
        self.inspection.common.as_ref()
    }

    pub(in crate::b4_campaign_executor) const fn linkage(&self) -> &ImportedAmd64ElfLinkageV1 {
        &self.inspection.linkage
    }
}

/// Import, inspect, authenticate, and lend one inert AMD64 ELF projection.
///
/// The role-specific temporary body is retained only inside the authenticated
/// stream inspection callback. It cannot escape to delivery, which begins only
/// after custody has completed its file and complete-root prechecks.
pub(in crate::b4_campaign_executor) fn with_imported_amd64_elf<const ROOTS: usize, T>(
    capability: &mut MutationCapability<'_, ROOTS, ProjectedPrepareInputSetCampaignLayout<ROOTS>>,
    slot: Amd64ElfSlotV1,
    effect: impl for<'inspection> FnOnce(ImportedAmd64ElfViewV1<'inspection>) -> Result<T>,
) -> Result<T> {
    let Amd64ElfSlotV1 {
        root_index,
        relative_path,
        policy,
    } = slot;
    checked_amd64_elf_limits(policy)?;
    capability.with_authenticated_amd64_elf_stream(
        Amd64ElfCustodyPermitV1 { _private: () },
        policy,
        root_index,
        &relative_path,
        move |byte_length, sha256, reader| {
            inspect_authenticated_amd64_elf_body(byte_length, sha256, policy, reader)
        },
        move |byte_length, sha256, inspection| {
            ensure!(
                inspection.byte_length == byte_length && inspection.sha256 == sha256,
                "authenticated AMD64 ELF projection differs from physical custody"
            );
            effect(ImportedAmd64ElfViewV1 { inspection })
        },
    )
}

fn checked_amd64_elf_limits(policy: Amd64ElfPolicyV1) -> Result<ArtifactImportLimitsV1> {
    let limits = B4ImmutableArtifactRoleV1::Amd64Elf(policy).limits();
    let (minimum, maximum) = limits.encoded_byte_range();
    ensure!(
        minimum == 64
            && maximum == AMD64_ELF_MAX_BYTES
            && maximum == MAX_BUFFERED_AMD64_ELF_INSPECTION_BYTES
            && limits.encoded_byte_multiple().is_none(),
        "AMD64 ELF custody ceiling differs from its closed role contract"
    );
    Ok(limits)
}

fn inspect_authenticated_amd64_elf_body(
    byte_length: u64,
    expected_sha256: [u8; 32],
    policy: Amd64ElfPolicyV1,
    reader: &mut dyn std::io::Read,
) -> Result<OwnedAmd64ElfInspectionV1> {
    ensure!(
        byte_length <= MAX_BUFFERED_AMD64_ELF_INSPECTION_BYTES,
        "AMD64 ELF exceeds its dedicated inspection-buffer ceiling"
    );
    let body_length =
        usize::try_from(byte_length).context("AMD64 ELF length does not fit memory addressing")?;
    let mut body = Vec::new();
    body.try_reserve_exact(body_length)
        .context("cannot reserve the role-bounded AMD64 ELF inspection body")?;
    body.resize(body_length, 0);
    reader
        .read_exact(&mut body)
        .context("cannot read the complete authenticated AMD64 ELF body")?;
    let (common, linkage) = match policy {
        Amd64ElfPolicyV1::Static => {
            eip0045_h0_contract::executable::inspect_retained_static_amd64_elf_v2(
                &body,
                byte_length,
                expected_sha256,
            )?;
            (None, ImportedAmd64ElfLinkageV1::Static)
        }
        Amd64ElfPolicyV1::Runtime => {
            let inspected = inspect_runtime_amd64_elf(&body)?;
            ensure!(
                inspected.byte_length() == byte_length && inspected.sha256() == expected_sha256,
                "AMD64 ELF parser identity differs from retained physical custody"
            );
            let runtime = own_runtime_amd64_elf_inspection(&inspected)?;
            (
                Some(*inspected.common()),
                ImportedAmd64ElfLinkageV1::Runtime(runtime),
            )
        }
    };
    Ok(OwnedAmd64ElfInspectionV1 {
        policy,
        byte_length,
        sha256: expected_sha256,
        common,
        linkage,
    })
}

fn own_runtime_amd64_elf_inspection(
    inspected: &InspectedAmd64ElfV1<'_>,
) -> Result<ImportedRuntimeAmd64ElfInspectionV1> {
    let runtime = inspected.runtime();
    let mut interpreter_path = String::new();
    interpreter_path
        .try_reserve_exact(runtime.interpreter_path().len())
        .context("cannot retain bounded AMD64 interpreter path")?;
    interpreter_path.push_str(runtime.interpreter_path());
    Ok(ImportedRuntimeAmd64ElfInspectionV1 {
        interpreter_path,
        dynamic_entry_count: runtime.dynamic_entry_count(),
        needed_library_count: runtime.needed_library_count(),
    })
}

#[cfg(test)]
mod e4c_static_validator_dedup_tests {
    #[test]
    fn amd64_elf_import_static_validator_is_unique_v1() {
        let import = include_str!("amd64_elf_import.rs")
            .split("#[cfg(test)]\nmod e4c_static_validator_dedup_tests")
            .next()
            .unwrap();
        let inspection = include_str!("amd64_elf_inspection.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let executor_module = include_str!("mod.rs");
        let manifest = include_str!("../../Cargo.toml");
        let linux_abi_manifest =
            include_str!("../../../appliance/h0-tmpfs-provider/crates/linux-abi/Cargo.toml");

        assert!(manifest.contains("\"dep:eip0045-h0-contract\""));
        assert!(manifest.contains("\"dep:eip0045-h0-linux-abi\""));
        assert!(manifest.contains(
            "eip0045-h0-contract = { version = \"=0.1.0\", path = \"../appliance/h0-tmpfs-provider/crates/contract\", default-features = false, optional = true }"
        ));
        assert!(manifest.contains(
            "eip0045-h0-linux-abi = { version = \"=0.1.0\", path = \"../appliance/h0-tmpfs-provider/crates/linux-abi\", default-features = false, optional = true }"
        ));
        assert!(linux_abi_manifest.contains("workspace = \"../..\""));
        assert!(linux_abi_manifest.contains(
            "eip0045-h0-contract = { path = \"../contract\", default-features = false }"
        ));
        for forbidden in [
            "pub struct GeneratorExecutableExpectationV2",
            "pub struct WorkerExecutableExpectationV2",
        ] {
            assert!(
                !import.contains(forbidden),
                "duplicate C4 type survived: {forbidden}"
            );
            assert!(
                !executor_module.contains(forbidden.trim_start_matches("pub struct ")),
                "removed C4 type is still re-exported: {forbidden}"
            );
        }
        assert!(
            import
                .contains("eip0045_h0_contract::executable::inspect_retained_static_amd64_elf_v2(")
        );
        assert!(import.contains("inspect_runtime_amd64_elf(&body)"));
        assert!(!inspection.contains("fn inspect_retained_static_amd64_elf_v2("));
        assert!(!inspection.contains("Amd64ElfPolicyV1::Static =>"));
        assert!(!inspection.contains("fn inspect_amd64_elf("));
        assert!(inspection.contains("fn inspect_runtime_amd64_elf(bytes: &[u8])"));

        let static_branch = import
            .split("Amd64ElfPolicyV1::Static => {")
            .nth(1)
            .expect("static import branch must exist")
            .split("Amd64ElfPolicyV1::Runtime => {")
            .next()
            .unwrap();
        assert!(static_branch.contains("inspect_retained_static_amd64_elf_v2"));
        assert!(!static_branch.contains("inspect_runtime_amd64_elf"));
    }
}

#[cfg(all(test, target_os = "linux"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Amd64ElfImportStage {
    PathPinned,
    DataOpened,
    BytesRead,
    FileRepinned,
}

#[cfg(all(test, target_os = "linux"))]
fn with_imported_amd64_elf_test_hook<const ROOTS: usize, T>(
    capability: &mut MutationCapability<'_, ROOTS, ProjectedPrepareInputSetCampaignLayout<ROOTS>>,
    slot: Amd64ElfSlotV1,
    mut hook: impl FnMut(Amd64ElfImportStage) -> Result<()>,
    effect: impl for<'inspection> FnOnce(ImportedAmd64ElfViewV1<'inspection>) -> Result<T>,
) -> Result<T> {
    use crate::b4_campaign_executor::custody::ImmutableFileReadStage;

    let Amd64ElfSlotV1 {
        root_index,
        relative_path,
        policy,
    } = slot;
    checked_amd64_elf_limits(policy)?;
    capability.with_authenticated_amd64_elf_stream_test_hook(
        Amd64ElfCustodyPermitV1 { _private: () },
        policy,
        root_index,
        &relative_path,
        move |stage| {
            hook(match stage {
                ImmutableFileReadStage::PathPinned => Amd64ElfImportStage::PathPinned,
                ImmutableFileReadStage::DataOpened => Amd64ElfImportStage::DataOpened,
                ImmutableFileReadStage::BytesRead => Amd64ElfImportStage::BytesRead,
                ImmutableFileReadStage::FileRepinned => Amd64ElfImportStage::FileRepinned,
            })
        },
        move |byte_length, sha256, reader| {
            inspect_authenticated_amd64_elf_body(byte_length, sha256, policy, reader)
        },
        move |byte_length, sha256, inspection| {
            ensure!(
                inspection.byte_length == byte_length && inspection.sha256 == sha256,
                "authenticated AMD64 ELF projection differs from physical custody"
            );
            effect(ImportedAmd64ElfViewV1 { inspection })
        },
    )
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        fs,
        os::unix::fs::MetadataExt as _,
        path::{Path, PathBuf},
        rc::Rc,
    };

    use sha2::{Digest as _, Sha256};

    use super::{
        Amd64ElfCustodyPermitV1, Amd64ElfImportStage, Amd64ElfPolicyV1, Amd64ElfSlotV1,
        ImportedAmd64ElfLinkageV1, ImportedAmd64ElfViewV1, checked_amd64_elf_limits,
        with_imported_amd64_elf, with_imported_amd64_elf_test_hook,
    };
    use crate::b4_campaign_executor::{
        amd64_elf_inspection::tests::{runtime_elf, static_elf},
        capability::{
            CustodyPostcheckBoundaryV1, CustodyPostcheckCombinedFailureV1, MutationCapability,
        },
        custody::{AuthenticatedStreamCombinedFailureV1, AuthenticatedStreamFailurePairV1},
        preflight::{
            ProjectedPrepareInputSetCampaignLayout, project_prepare_input_set_campaign_layout,
        },
        typestate::ExecutorPreflightContext,
    };

    type TestContext = ExecutorPreflightContext<1, ProjectedPrepareInputSetCampaignLayout<1>>;

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

        fn substitute(&mut self, replacement: &[u8]) -> anyhow::Result<()> {
            fs::rename(&self.nominal, &self.retained)?;
            self.active = true;
            fs::write(&self.nominal, replacement)?;
            Ok(())
        }

        fn restore(&mut self) -> anyhow::Result<()> {
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
    fn amd64_elf_import_delivers_only_an_authenticated_owned_projection() {
        let bytes = static_elf();
        let expected_sha256: [u8; 32] = Sha256::digest(&bytes).into();
        let (_temp, prior, context) = captured_context(&[("validator", &bytes)]);
        let output = prior.parent().unwrap().join("phases/prepare-001");
        let slot = Amd64ElfSlotV1::test_only(0, "validator", Amd64ElfPolicyV1::Static);

        context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_amd64_elf(capability, slot, |view| {
                        assert_eq!(view.policy(), Amd64ElfPolicyV1::Static);
                        assert_eq!(view.byte_length(), bytes.len() as u64);
                        assert_eq!(view.sha256(), expected_sha256);
                        assert!(view.common().is_none());
                        assert!(matches!(view.linkage(), ImportedAmd64ElfLinkageV1::Static));
                        Ok(())
                    })
                })
            })
            .unwrap();
        assert!(!output.exists());
    }

    #[test]
    fn runtime_amd64_elf_import_owns_interpreter_and_dynamic_projection() {
        let fixture = runtime_elf(1);
        let expected_sha256: [u8; 32] = Sha256::digest(&fixture.bytes).into();
        let (_temp, _prior, context) = captured_context(&[("java", &fixture.bytes)]);
        let slot = Amd64ElfSlotV1::test_only(0, "java", Amd64ElfPolicyV1::Runtime);

        context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_amd64_elf(capability, slot, |view| {
                        assert_eq!(view.policy(), Amd64ElfPolicyV1::Runtime);
                        assert_eq!(view.byte_length(), fixture.bytes.len() as u64);
                        assert_eq!(view.sha256(), expected_sha256);
                        assert_eq!(view.common().unwrap().program_header_count(), 4);
                        let ImportedAmd64ElfLinkageV1::Runtime(runtime) = view.linkage() else {
                            panic!("runtime slot produced a static physical projection")
                        };
                        assert_eq!(runtime.interpreter_path(), "/lib64/ld-linux-x86-64.so.2");
                        assert_eq!(runtime.dynamic_entry_count(), 4);
                        assert_eq!(runtime.needed_library_count(), 1);
                        Ok(())
                    })
                })
            })
            .unwrap();
    }

    #[test]
    fn amd64_elf_stream_ceiling_is_role_specific_and_not_the_generic_buffer_ceiling() {
        for policy in [Amd64ElfPolicyV1::Static, Amd64ElfPolicyV1::Runtime] {
            let limits = checked_amd64_elf_limits(policy).unwrap();
            assert_eq!(limits.encoded_byte_range(), (64, 1_073_741_824));
            limits
                .validate_encoded_length(536_870_913, "AMD64 ELF")
                .unwrap();
            limits
                .validate_encoded_length(1_073_741_824, "AMD64 ELF")
                .unwrap();
            assert!(
                limits
                    .validate_encoded_length(1_073_741_825, "AMD64 ELF")
                    .is_err()
            );
        }
        let production = include_str!("amd64_elf_import.rs")
            .split("#[cfg(all(test, target_os = \"linux\"))]")
            .next()
            .unwrap();
        assert!(!production.contains("with_authenticated_file_bytes"));
        assert!(
            production.contains(
                "const MAX_BUFFERED_AMD64_ELF_INSPECTION_BYTES: u64 = AMD64_ELF_MAX_BYTES;"
            )
        );
        assert!(production.contains("try_reserve_exact(body_length)"));
    }

    #[test]
    fn amd64_elf_policy_is_selected_by_the_consumed_slot_before_delivery() {
        let bytes = static_elf();
        let (_temp, _prior, context) = captured_context(&[("validator", &bytes)]);
        let slot = Amd64ElfSlotV1::test_only(0, "validator", Amd64ElfPolicyV1::Runtime);
        let delivered = Rc::new(Cell::new(false));
        let delivery_flag = Rc::clone(&delivered);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_amd64_elf(capability, slot, move |_view| {
                        delivery_flag.set(true);
                        Ok(())
                    })
                })
            })
            .unwrap_err();

        assert!(
            format!("{error:#}").contains("runtime ELF does not contain exactly one interpreter"),
            "{error:#}"
        );
        assert!(!delivered.get());
    }

    #[test]
    fn amd64_elf_role_length_rejects_before_open_read_or_delivery() {
        let bytes = [0_u8; 63];
        let (_temp, _prior, context) = captured_context(&[("validator", &bytes)]);
        let slot = Amd64ElfSlotV1::test_only(0, "validator", Amd64ElfPolicyV1::Static);
        let stage_reached = Rc::new(Cell::new(false));
        let delivered = Rc::new(Cell::new(false));
        let stage_flag = Rc::clone(&stage_reached);
        let delivery_flag = Rc::clone(&delivered);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_amd64_elf_test_hook(
                        capability,
                        slot,
                        move |_stage| {
                            stage_flag.set(true);
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
        assert!(!delivered.get());
    }

    #[test]
    fn amd64_elf_import_rejects_growth_before_the_exact_eof_probe() {
        let bytes = static_elf();
        let (_temp, prior, context) = captured_context(&[("validator", &bytes)]);
        let path = prior.join("validator");
        let slot = Amd64ElfSlotV1::test_only(0, "validator", Amd64ElfPolicyV1::Static);
        let delivered = Rc::new(Cell::new(false));
        let delivery_flag = Rc::clone(&delivered);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_amd64_elf_test_hook(
                        capability,
                        slot,
                        move |stage| {
                            if stage == Amd64ElfImportStage::DataOpened {
                                fs::OpenOptions::new()
                                    .write(true)
                                    .open(&path)?
                                    .set_len(u64::try_from(bytes.len() + 1)?)?;
                            }
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
            format!("{error:#}").contains("grew beyond its retained length"),
            "{error:#}"
        );
        assert!(!delivered.get());
    }

    #[test]
    fn amd64_elf_truncation_preserves_the_sticky_inspection_read_failure() {
        let bytes = static_elf();
        let (_temp, prior, context) = captured_context(&[("validator", &bytes)]);
        let path = prior.join("validator");
        let slot = Amd64ElfSlotV1::test_only(0, "validator", Amd64ElfPolicyV1::Static);
        let delivered = Rc::new(Cell::new(false));
        let delivery_flag = Rc::clone(&delivered);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_amd64_elf_test_hook(
                        capability,
                        slot,
                        move |stage| {
                            if stage == Amd64ElfImportStage::DataOpened {
                                fs::OpenOptions::new()
                                    .write(true)
                                    .open(&path)?
                                    .set_len(32)?;
                            }
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

        let executor_failure = error
            .downcast_ref::<CustodyPostcheckCombinedFailureV1>()
            .expect("executor completion must preserve the AMD64 read failure");
        let mutation_failure = executor_failure
            .effect()
            .downcast_ref::<CustodyPostcheckCombinedFailureV1>()
            .expect("mutation boundary must preserve the AMD64 read failure");
        let root_pair = mutation_failure
            .effect()
            .downcast_ref::<AuthenticatedStreamCombinedFailureV1>()
            .expect("AMD64 import must preserve its inspection/root-precheck pair");
        assert_eq!(
            root_pair.pair(),
            AuthenticatedStreamFailurePairV1::InspectionAndPreDeliveryPostcheck
        );
        let file_pair = root_pair
            .earlier()
            .downcast_ref::<AuthenticatedStreamCombinedFailureV1>()
            .expect("AMD64 import must preserve its inspection/file-postcheck pair");
        assert_eq!(
            file_pair.pair(),
            AuthenticatedStreamFailurePairV1::InspectionAndFilePostcheck
        );
        let read_pair = file_pair
            .earlier()
            .downcast_ref::<AuthenticatedStreamCombinedFailureV1>()
            .expect("AMD64 import must preserve its sticky inspection/read pair");
        assert_eq!(
            read_pair.pair(),
            AuthenticatedStreamFailurePairV1::InspectionAndRead
        );
        assert!(
            format!("{:#}", read_pair.earlier())
                .contains("cannot read the complete authenticated AMD64 ELF body")
        );
        assert!(format!("{:#}", read_pair.later()).contains("ended before its retained length"));
        assert!(!delivered.get());
    }

    #[test]
    fn amd64_elf_import_rejects_same_inode_mutation_after_authenticated_read() {
        let bytes = static_elf();
        let (_temp, prior, context) = captured_context(&[("validator", &bytes)]);
        let path = prior.join("validator");
        let slot = Amd64ElfSlotV1::test_only(0, "validator", Amd64ElfPolicyV1::Static);
        let delivered = Rc::new(Cell::new(false));
        let delivery_flag = Rc::clone(&delivered);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_amd64_elf_test_hook(
                        capability,
                        slot,
                        move |stage| {
                            if stage == Amd64ElfImportStage::BytesRead {
                                let mut changed = bytes.clone();
                                let last = changed.len() - 1;
                                changed[last] ^= 1;
                                fs::write(&path, changed)?;
                            }
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
            format!("{error:#}").contains("no longer matches"),
            "{error:#}"
        );
        assert!(!delivered.get());
    }

    #[test]
    fn amd64_elf_import_rejects_path_substitution_before_data_open() {
        let bytes = static_elf();
        let (_temp, prior, context) = captured_context(&[("validator", &bytes)]);
        let slot = Amd64ElfSlotV1::test_only(0, "validator", Amd64ElfPolicyV1::Static);
        let delivered = Rc::new(Cell::new(false));
        let delivery_flag = Rc::clone(&delivered);
        let mut substitution = NominalSubstitutionGuard::new(prior.join("validator"));

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_amd64_elf_test_hook(
                        capability,
                        slot,
                        move |stage| {
                            if stage == Amd64ElfImportStage::PathPinned {
                                substitution.substitute(&bytes)?;
                            }
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
        assert!(!delivered.get());
    }

    #[test]
    fn amd64_elf_import_rejects_byte_identical_inode_substitution_before_repin() {
        let bytes = static_elf();
        let (_temp, prior, context) = captured_context(&[("validator", &bytes)]);
        let path = prior.join("validator");
        let slot = Amd64ElfSlotV1::test_only(0, "validator", Amd64ElfPolicyV1::Static);
        let delivered = Rc::new(Cell::new(false));
        let delivery_flag = Rc::clone(&delivered);
        let mut substitution = NominalSubstitutionGuard::new(path.clone());

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_amd64_elf_test_hook(
                        capability,
                        slot,
                        move |stage| {
                            if stage == Amd64ElfImportStage::BytesRead {
                                let before = fs::metadata(&path)?;
                                substitution.substitute(&bytes)?;
                                let after = fs::metadata(&path)?;
                                assert_eq!(before.dev(), after.dev());
                                assert_eq!(before.len(), after.len());
                                assert_ne!(before.ino(), after.ino());
                            }
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

        let message = format!("{error:#}");
        assert!(
            message.contains("no longer matches") || message.contains("no longer identifies"),
            "{message}"
        );
        assert!(!delivered.get());
    }

    #[test]
    fn amd64_elf_inspection_failure_still_repins_before_returning() {
        let invalid = [0_u8; 64];
        let (_temp, _prior, context) = captured_context(&[("validator", &invalid)]);
        let slot = Amd64ElfSlotV1::test_only(0, "validator", Amd64ElfPolicyV1::Static);
        let stages = Rc::new(RefCell::new(Vec::new()));
        let observed_stages = Rc::clone(&stages);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_amd64_elf_test_hook(
                        capability,
                        slot,
                        move |stage| {
                            observed_stages.borrow_mut().push(stage);
                            Ok(())
                        },
                        |_view| Ok(()),
                    )
                })
            })
            .unwrap_err();

        assert!(
            format!("{error:#}").contains("magic is invalid"),
            "{error:#}"
        );
        assert_eq!(
            stages.borrow().as_slice(),
            [
                Amd64ElfImportStage::PathPinned,
                Amd64ElfImportStage::DataOpened,
                Amd64ElfImportStage::FileRepinned,
            ]
        );
    }

    #[test]
    fn amd64_elf_inspection_and_file_postcheck_failures_are_both_preserved() {
        let invalid = [0_u8; 64];
        let (_temp, prior, context) = captured_context(&[("validator", &invalid)]);
        let slot = Amd64ElfSlotV1::test_only(0, "validator", Amd64ElfPolicyV1::Static);
        let delivered = Rc::new(Cell::new(false));
        let delivery_flag = Rc::clone(&delivered);
        let mut substitution = NominalSubstitutionGuard::new(prior.join("validator"));

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_amd64_elf_test_hook(
                        capability,
                        slot,
                        move |stage| {
                            if stage == Amd64ElfImportStage::DataOpened {
                                substitution.substitute(&invalid)?;
                            }
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

        let executor_failure = error
            .downcast_ref::<CustodyPostcheckCombinedFailureV1>()
            .expect("executor completion must preserve the AMD64 import failure");
        assert_eq!(
            executor_failure.boundary(),
            CustodyPostcheckBoundaryV1::ExecutorCompletion
        );
        let mutation_failure = executor_failure
            .effect()
            .downcast_ref::<CustodyPostcheckCombinedFailureV1>()
            .expect("mutation boundary must preserve the AMD64 import failure");
        assert_eq!(
            mutation_failure.boundary(),
            CustodyPostcheckBoundaryV1::MutationEffect
        );
        let root_pair = mutation_failure
            .effect()
            .downcast_ref::<AuthenticatedStreamCombinedFailureV1>()
            .expect("AMD64 import must preserve its inspection/root-precheck pair");
        assert_eq!(
            root_pair.pair(),
            AuthenticatedStreamFailurePairV1::InspectionAndPreDeliveryPostcheck
        );
        let file_pair = root_pair
            .earlier()
            .downcast_ref::<AuthenticatedStreamCombinedFailureV1>()
            .expect("AMD64 import must preserve its nested inspection/file-postcheck pair");
        assert_eq!(
            file_pair.pair(),
            AuthenticatedStreamFailurePairV1::InspectionAndFilePostcheck
        );
        assert!(format!("{:#}", file_pair.earlier()).contains("magic is invalid"));
        assert!(!format!("{:#}", file_pair.later()).is_empty());
        assert!(!format!("{:#}", root_pair.later()).is_empty());
        assert!(!delivered.get());
    }

    #[test]
    fn amd64_elf_import_rechecks_the_complete_root_before_delivery() {
        let bytes = static_elf();
        let companion = b"stable companion";
        let (_temp, prior, context) =
            captured_context(&[("validator", &bytes), ("companion", companion)]);
        let companion_path = prior.join("companion");
        let slot = Amd64ElfSlotV1::test_only(0, "validator", Amd64ElfPolicyV1::Static);
        let delivered = Rc::new(Cell::new(false));
        let delivery_flag = Rc::clone(&delivered);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_amd64_elf_test_hook(
                        capability,
                        slot,
                        move |stage| {
                            if stage == Amd64ElfImportStage::FileRepinned {
                                fs::write(&companion_path, b"changed companion")?;
                            }
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

        assert!(format!("{error:#}").contains("immutable-root"), "{error:#}");
        assert!(!delivered.get());
    }

    #[test]
    fn amd64_elf_delivery_error_is_returned_after_a_clean_postcheck() {
        let bytes = static_elf();
        let (_temp, _prior, context) = captured_context(&[("validator", &bytes)]);
        let slot = Amd64ElfSlotV1::test_only(0, "validator", Amd64ElfPolicyV1::Static);
        let delivered = Cell::new(false);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_amd64_elf(capability, slot, |_view| -> anyhow::Result<u8> {
                        delivered.set(true);
                        anyhow::bail!("injected AMD64 delivery failure")
                    })
                })
            })
            .unwrap_err();

        assert!(delivered.get());
        assert!(
            format!("{error:#}").contains("injected AMD64 delivery failure"),
            "{error:#}"
        );
        assert!(!format!("{error:#}").contains("postcheck also failed"));
    }

    #[test]
    fn amd64_elf_delivery_result_is_rejected_when_the_root_changes() {
        let bytes = static_elf();
        let companion = b"stable companion";
        let (_temp, prior, context) =
            captured_context(&[("validator", &bytes), ("companion", companion)]);
        let companion_path = prior.join("companion");
        let slot = Amd64ElfSlotV1::test_only(0, "validator", Amd64ElfPolicyV1::Static);
        let delivered = Rc::new(Cell::new(false));
        let delivery_flag = Rc::clone(&delivered);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_amd64_elf(capability, slot, move |_view| {
                        delivery_flag.set(true);
                        fs::write(&companion_path, b"changed companion")?;
                        Ok(())
                    })
                })
            })
            .unwrap_err();

        assert!(
            format!("{error:#}").contains("postcheck failed"),
            "{error:#}"
        );
        assert!(delivered.get());
    }

    #[test]
    fn amd64_elf_delivery_and_root_failures_are_both_preserved() {
        let bytes = static_elf();
        let (_temp, prior, context) = captured_context(&[("validator", &bytes)]);
        let path = prior.join("validator");
        let slot = Amd64ElfSlotV1::test_only(0, "validator", Amd64ElfPolicyV1::Static);
        let delivered = Cell::new(false);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_amd64_elf(capability, slot, |_view| -> anyhow::Result<u8> {
                        delivered.set(true);
                        fs::write(&path, b"changed during failed AMD64 delivery")?;
                        anyhow::bail!("injected AMD64 delivery failure after mutation")
                    })
                })
            })
            .unwrap_err();

        assert!(delivered.get());
        let executor_failure = error
            .downcast_ref::<CustodyPostcheckCombinedFailureV1>()
            .expect("executor completion must preserve its typed AMD64 delivery failure");
        assert_eq!(
            executor_failure.boundary(),
            CustodyPostcheckBoundaryV1::ExecutorCompletion
        );
        let mutation_failure = executor_failure
            .effect()
            .downcast_ref::<CustodyPostcheckCombinedFailureV1>()
            .expect("mutation boundary must preserve the AMD64 delivery failure");
        assert_eq!(
            mutation_failure.boundary(),
            CustodyPostcheckBoundaryV1::MutationEffect
        );
        let stream_failure = mutation_failure
            .effect()
            .downcast_ref::<AuthenticatedStreamCombinedFailureV1>()
            .expect("AMD64 import must preserve the typed delivery/postcheck pair");
        assert_eq!(
            stream_failure.pair(),
            AuthenticatedStreamFailurePairV1::DeliveryAndPostcheck
        );
        assert!(
            format!("{:#}", stream_failure.earlier())
                .contains("injected AMD64 delivery failure after mutation")
        );
        assert!(!format!("{:#}", stream_failure.later()).is_empty());
        assert!(!format!("{:#}", mutation_failure.postcheck()).is_empty());
        assert!(!format!("{:#}", executor_failure.postcheck()).is_empty());
    }

    fn is_rust_identifier_byte(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || byte == b'_' || byte >= 0x80
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

    fn assert_no_amd64_elf_bridge_outside_origin() {
        let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/b4_campaign_executor");
        let origin = source_root.join("amd64_elf_import.rs");
        let parent = source_root.join("amd64_elf_inspection.rs");
        let custody = source_root.join("custody.rs");
        let parent_reexports = [
            "Amd64ElfCustodyPermitV1",
            "Amd64ElfSlotV1",
            "ImportedAmd64ElfLinkageV1",
            "ImportedAmd64ElfViewV1",
            "ImportedRuntimeAmd64ElfInspectionV1",
            "with_imported_amd64_elf",
            "amd64_elf_import",
        ];
        let forbidden_references = [
            "Amd64ElfCustodyPermitV1",
            "Amd64ElfSlotV1",
            "ImportedAmd64ElfLinkageV1",
            "ImportedAmd64ElfViewV1",
            "ImportedRuntimeAmd64ElfInspectionV1",
            "OwnedAmd64ElfInspectionV1",
            "with_imported_amd64_elf",
            "with_authenticated_amd64_elf_stream",
            "with_authenticated_amd64_elf_stream_test_hook",
            "inspect_authenticated_amd64_elf_body",
            "own_amd64_elf_inspection",
            "amd64_elf_import",
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
        assert!(audited_sources.len() >= 3);
        for path in audited_sources {
            if path == origin {
                continue;
            }
            let source = fs::read_to_string(&path).unwrap();
            let audited = if path == parent {
                source.split("#[cfg(test)]").next().unwrap()
            } else if path == custody {
                source
                    .split("fn compile_only_observe_amd64_view_from_custody_sibling(")
                    .next()
                    .unwrap()
            } else {
                source.as_str()
            };
            for forbidden in forbidden_references {
                let expected = if path == parent && parent_reexports.contains(&forbidden) {
                    1
                } else if path == custody && forbidden == "Amd64ElfCustodyPermitV1" {
                    3
                } else {
                    usize::from(
                        path == custody
                            && matches!(
                                forbidden,
                                "with_authenticated_amd64_elf_stream"
                                    | "with_authenticated_amd64_elf_stream_test_hook"
                            ),
                    )
                };
                assert_eq!(
                    standalone_identifier_reference_count(audited, forbidden),
                    expected,
                    "unexpected AMD64 ELF bridge `{forbidden}` in {}",
                    path.display()
                );
            }
        }
    }

    #[test]
    fn amd64_elf_import_surface_is_private_affine_and_non_authorizing() {
        let production = include_str!("amd64_elf_import.rs")
            .split("#[cfg(all(test, target_os = \"linux\"))]")
            .next()
            .unwrap();
        let compact = production.split_whitespace().collect::<String>();
        let slot_impl = production
            .split("impl Amd64ElfSlotV1 {")
            .nth(1)
            .unwrap()
            .split("/// Owned runtime-linkage fields")
            .next()
            .unwrap();
        let owned_inspection = production
            .split("struct OwnedAmd64ElfInspectionV1 {")
            .nth(1)
            .unwrap()
            .split("/// Inert post-custody view")
            .next()
            .unwrap();
        let custody = include_str!("custody.rs");
        let custody_compact = custody.split_whitespace().collect::<String>();

        for required in [
            "Amd64ElfCustodyPermitV1{_private:(),}",
            "slot:Amd64ElfSlotV1",
            "&mutMutationCapability<'_,ROOTS,ProjectedPrepareInputSetCampaignLayout<ROOTS>>",
            "with_authenticated_amd64_elf_stream(",
            "try_reserve_exact(body_length)",
            "read_exact(&mutbody)",
            "inspect_retained_static_amd64_elf_v2(",
            "inspect_runtime_amd64_elf(&body)",
            "implfor<'inspection>FnOnce(ImportedAmd64ElfViewV1<'inspection>)",
            "pub(incrate::b4_campaign_executor)fninterpreter_path(&self)->&str",
            "pub(incrate::b4_campaign_executor)constfndynamic_entry_count(&self)->u64",
            "pub(incrate::b4_campaign_executor)constfnneeded_library_count(&self)->u64",
            "pub(incrate::b4_campaign_executor)constfnpolicy(&self)->Amd64ElfPolicyV1",
            "pub(incrate::b4_campaign_executor)constfnbyte_length(&self)->u64",
            "pub(incrate::b4_campaign_executor)constfnsha256(&self)->[u8;32]",
            "pub(incrate::b4_campaign_executor)constfncommon(&self)->Option<&Amd64ElfCommonInspectionV1>",
            "pub(incrate::b4_campaign_executor)constfnlinkage(&self)->&ImportedAmd64ElfLinkageV1",
        ] {
            assert!(compact.contains(required), "missing {required}");
        }
        assert_eq!(production.matches("Amd64ElfCustodyPermitV1 {").count(), 2);
        assert_eq!(production.matches("Amd64ElfSlotV1 {").count(), 3);
        assert_eq!(production.matches("impl Amd64ElfSlotV1 {").count(), 1);
        assert_eq!(slot_impl.matches("fn ").count(), 1);
        assert!(slot_impl.contains("#[cfg(test)]\n    fn test_only("));
        for forbidden in ["fnnew(", "fnfrom_path(", "implDefaultforAmd64ElfSlotV1"] {
            assert!(
                !compact.contains(forbidden),
                "forbidden slot constructor {forbidden}"
            );
        }
        assert!(!owned_inspection.contains("Vec<"));
        assert!(!owned_inspection.contains("String"));
        assert!(!owned_inspection.contains("&["));
        assert!(compact.contains(
            "structOwnedAmd64ElfInspectionV1{policy:Amd64ElfPolicyV1,byte_length:u64,sha256:[u8;32],common:Option<Amd64ElfCommonInspectionV1>,linkage:ImportedAmd64ElfLinkageV1,}"
        ));
        for forbidden in [
            "with_authenticated_file_bytes",
            "with_root_descriptor",
            "include!",
            "include_bytes!",
            "#[macro_export]",
            "macro_rules!",
            "no_mangle",
            "export_name",
            "std::fs",
            "fs::",
            "std::path",
            "path::Path",
            "PathBuf",
            "File::open",
            "OpenOptions",
            "BorrowedFd",
            "OwnedFd",
            "rustix",
            "openat(",
            "openat2(",
            "canonicalize(",
            "/proc/self/fd",
            "Seek",
            "AsFd",
            "AsRawFd",
            "into_inner",
            "std::process",
            "Command::new",
            "Serialize",
            "Deserialize",
            "AuthenticatedPrepareInputSetSourceV1",
            "PrepareInputSetPublicationGuard",
            "bytes(&self)",
            "body(&self)",
            "as_slice(&self)",
            "raw_bytes",
            "elf_bytes",
            "body:Vec<u8>",
            "bytes:Vec<u8>",
            "->&[u8]",
        ] {
            assert!(
                !production.contains(forbidden) && !compact.contains(forbidden),
                "forbidden {forbidden}"
            );
        }
        assert!(custody_compact.contains(
            "fnwith_authenticated_amd64_elf_stream<Inspection,T>(&mutself,_permit:Amd64ElfCustodyPermitV1"
        ));
        assert_no_amd64_elf_bridge_outside_origin();
    }

    #[test]
    fn amd64_elf_affine_types_do_not_gain_clone_or_copy() {
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

        <Amd64ElfSlotV1 as AmbiguousIfClone<_>>::marker();
        <Amd64ElfSlotV1 as AmbiguousIfCopy<_>>::marker();
        <Amd64ElfCustodyPermitV1 as AmbiguousIfClone<_>>::marker();
        <Amd64ElfCustodyPermitV1 as AmbiguousIfCopy<_>>::marker();
        <ImportedAmd64ElfViewV1<'static> as AmbiguousIfClone<_>>::marker();
        <ImportedAmd64ElfViewV1<'static> as AmbiguousIfCopy<_>>::marker();
    }

    #[test]
    fn amd64_elf_import_signature_consumes_one_layout_affine_slot() {
        type ExactImportSignature = for<'borrow, 'context> fn(
            &'borrow mut MutationCapability<'context, 1, ProjectedPrepareInputSetCampaignLayout<1>>,
            Amd64ElfSlotV1,
            for<'inspection> fn(ImportedAmd64ElfViewV1<'inspection>) -> anyhow::Result<()>,
        ) -> anyhow::Result<()>;

        let exact: ExactImportSignature = with_imported_amd64_elf::<1, ()>;
        std::hint::black_box(exact);
    }
}
