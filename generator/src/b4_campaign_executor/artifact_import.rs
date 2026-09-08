//! Descriptor-rooted physical artifact import for the B4 H0 session.

use anyhow::{Context as _, Result, ensure};
use elf::{ElfBytes, endian::LittleEndian};
use risc0_binfmt::ProgramBinary;
use sha2::{Digest as _, Sha256};

use super::{
    artifact_import_contract::{
        ArtifactImportLimitsV1, B4ImmutableArtifactRoleV1, Risc0GuestElfImportLimitsV1,
    },
    capability::MutationCapability,
    preflight::ProjectedPrepareInputSetCampaignLayout,
};

const RISC0_GUEST_ELF_MAX_BYTES: usize = 4_194_304;

/// One H0-plan slot for the unique RISC Zero guest ELF.
///
/// There is intentionally no production constructor yet: the final closed H0
/// topology must derive this slot rather than accept a caller-selected path.
pub(super) struct Risc0GuestElfSlotV1 {
    root_index: usize,
    relative_path: String,
}

impl Risc0GuestElfSlotV1 {
    #[cfg(test)]
    fn test_only(root_index: usize, relative_path: &str) -> Self {
        Self {
            root_index,
            relative_path: relative_path.to_owned(),
        }
    }
}

/// Borrowed, non-authorizing view derived from the exact descriptor bytes.
///
/// The byte lifetime cannot outlive the custody callback. Length, SHA-256 and
/// image ID are inert measurements; none of them can mint H0 independently.
pub(super) struct ImportedRisc0GuestElfViewV1<'bytes> {
    bytes: &'bytes [u8],
    byte_length: u64,
    sha256: [u8; 32],
    image_id: [u8; 32],
}

impl ImportedRisc0GuestElfViewV1<'_> {
    pub(super) const fn bytes(&self) -> &[u8] {
        self.bytes
    }

    pub(super) const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    pub(super) const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    pub(super) const fn image_id(&self) -> [u8; 32] {
        self.image_id
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Risc0GuestElfImportStage {
    PathPinned,
    DataOpened,
    BytesRead,
    FileRepinned,
}

/// Import the unique guest ELF without allowing its borrowed bytes to escape.
pub(super) fn with_imported_risc0_guest_elf<const ROOTS: usize, T>(
    capability: &mut MutationCapability<'_, ROOTS, ProjectedPrepareInputSetCampaignLayout<ROOTS>>,
    slot: &Risc0GuestElfSlotV1,
    effect: impl for<'bytes> FnOnce(ImportedRisc0GuestElfViewV1<'bytes>) -> Result<T>,
) -> Result<T> {
    let limits = checked_risc0_guest_elf_limits()?;
    capability
        .immutable_roots()
        .with_authenticated_file_bytes::<RISC0_GUEST_ELF_MAX_BYTES, _>(
            slot.root_index,
            &slot.relative_path,
            move |byte_length| limits.validate_encoded_length(byte_length, "RISC Zero guest ELF"),
            move |bytes| deliver_risc0_guest_elf_view(bytes, effect),
        )
}

#[cfg(all(test, target_os = "linux"))]
fn with_imported_risc0_guest_elf_test_hook<const ROOTS: usize, T>(
    capability: &mut MutationCapability<'_, ROOTS, ProjectedPrepareInputSetCampaignLayout<ROOTS>>,
    slot: &Risc0GuestElfSlotV1,
    mut hook: impl FnMut(Risc0GuestElfImportStage) -> Result<()>,
    effect: impl for<'bytes> FnOnce(ImportedRisc0GuestElfViewV1<'bytes>) -> Result<T>,
) -> Result<T> {
    use super::custody::ImmutableFileReadStage;

    let limits = checked_risc0_guest_elf_limits()?;
    capability
        .immutable_roots()
        .with_authenticated_file_bytes_test_hook::<RISC0_GUEST_ELF_MAX_BYTES, _>(
            slot.root_index,
            &slot.relative_path,
            move |byte_length| limits.validate_encoded_length(byte_length, "RISC Zero guest ELF"),
            move |stage| {
                hook(match stage {
                    ImmutableFileReadStage::PathPinned => Risc0GuestElfImportStage::PathPinned,
                    ImmutableFileReadStage::DataOpened => Risc0GuestElfImportStage::DataOpened,
                    ImmutableFileReadStage::BytesRead => Risc0GuestElfImportStage::BytesRead,
                    ImmutableFileReadStage::FileRepinned => Risc0GuestElfImportStage::FileRepinned,
                })
            },
            move |bytes| deliver_risc0_guest_elf_view(bytes, effect),
        )
}

fn checked_risc0_guest_elf_limits() -> Result<ArtifactImportLimitsV1> {
    let limits = B4ImmutableArtifactRoleV1::Risc0GuestElf.limits();
    let (_minimum, maximum) = limits.encoded_byte_range();
    ensure!(
        maximum == u64::try_from(RISC0_GUEST_ELF_MAX_BYTES)?,
        "RISC Zero guest ELF custody ceiling differs from its closed role contract"
    );
    Ok(limits)
}

fn deliver_risc0_guest_elf_view<T>(
    bytes: &[u8],
    effect: impl for<'bytes> FnOnce(ImportedRisc0GuestElfViewV1<'bytes>) -> Result<T>,
) -> Result<T> {
    let byte_length = u64::try_from(bytes.len()).context("guest ELF length does not fit u64")?;
    let sha256 = Sha256::digest(bytes).into();
    let image_id = derive_risc0_guest_elf_image_id(bytes)?;
    effect(ImportedRisc0GuestElfViewV1 {
        bytes,
        byte_length,
        sha256,
        image_id,
    })
}

fn derive_risc0_guest_elf_image_id(bytes: &[u8]) -> Result<[u8; 32]> {
    derive_risc0_guest_elf_image_id_with(bytes, |program| {
        program
            .compute_image_id()
            .context("cannot derive descriptor-rooted RISC Zero guest image ID")
            .map(Into::into)
    })
}

fn derive_risc0_guest_elf_image_id_with(
    bytes: &[u8],
    image_id_oracle: impl FnOnce(&ProgramBinary<'_>) -> Result<[u8; 32]>,
) -> Result<[u8; 32]> {
    let limits = checked_risc0_guest_elf_limits()?;
    limits.validate_encoded_length(
        u64::try_from(bytes.len()).context("guest ProgramBinary length does not fit u64")?,
        "RISC Zero guest ELF",
    )?;
    let program = ProgramBinary::decode(bytes)
        .context("cannot decode descriptor-rooted RISC Zero ProgramBinary")?;
    validate_risc0_guest_elf_load_work(
        &program,
        limits.require_risc0_guest_elf("RISC Zero guest ELF")?,
    )?;
    image_id_oracle(&program)
}

fn validate_risc0_guest_elf_load_work(
    program: &ProgramBinary<'_>,
    limits: Risc0GuestElfImportLimitsV1,
) -> Result<()> {
    let loaded_words =
        checked_inner_elf_loaded_words(program.user_elf, "RISC Zero user ELF", limits, 0)?;
    checked_inner_elf_loaded_words(
        program.kernel_elf,
        "RISC Zero kernel ELF",
        limits,
        loaded_words,
    )?;
    Ok(())
}

fn checked_inner_elf_loaded_words(
    bytes: &[u8],
    label: &str,
    limits: Risc0GuestElfImportLimitsV1,
    initial_loaded_words: u64,
) -> Result<u64> {
    let elf = ElfBytes::<LittleEndian>::minimal_parse(bytes)
        .with_context(|| format!("cannot parse {label}"))?;
    let segments = elf
        .segments()
        .with_context(|| format!("{label} has no program-header table"))?;
    ensure!(
        segments.len() <= 256,
        "{label} has more than 256 program headers"
    );

    let mut loaded_words = initial_loaded_words;
    for segment in segments
        .iter()
        .filter(|segment| segment.p_type == elf::abi::PT_LOAD)
    {
        loaded_words = limits.checked_add_loaded_words(
            loaded_words,
            segment.p_memsz.div_ceil(4),
            "RISC Zero guest ELF",
        )?;
    }
    Ok(loaded_words)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{
        cell::Cell,
        fs,
        os::unix::fs::MetadataExt as _,
        path::{Path, PathBuf},
        rc::Rc,
    };

    use anyhow::Result;
    use risc0_binfmt::compute_image_id;
    use sha2::{Digest as _, Sha256};

    use super::{
        Risc0GuestElfImportStage, Risc0GuestElfSlotV1, derive_risc0_guest_elf_image_id_with,
        with_imported_risc0_guest_elf, with_imported_risc0_guest_elf_test_hook,
    };
    use crate::b4_campaign_executor::{
        preflight::project_prepare_input_set_campaign_layout, typestate::ExecutorPreflightContext,
    };

    fn push_u16(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn minimal_riscv32_elf_with_load_size(
        entry: u32,
        instruction: u32,
        file_size: u32,
        memory_size: u32,
    ) -> Vec<u8> {
        const ELF_HEADER_BYTES: u16 = 52;
        const PROGRAM_HEADER_BYTES: u16 = 32;
        const SEGMENT_OFFSET: u32 = 84;

        let mut elf = Vec::with_capacity((SEGMENT_OFFSET + 4) as usize);
        elf.extend_from_slice(&[0x7f, b'E', b'L', b'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        push_u16(&mut elf, 2);
        push_u16(&mut elf, 243);
        push_u32(&mut elf, 1);
        push_u32(&mut elf, entry);
        push_u32(&mut elf, u32::from(ELF_HEADER_BYTES));
        push_u32(&mut elf, 0);
        push_u32(&mut elf, 0);
        push_u16(&mut elf, ELF_HEADER_BYTES);
        push_u16(&mut elf, PROGRAM_HEADER_BYTES);
        push_u16(&mut elf, 1);
        push_u16(&mut elf, 0);
        push_u16(&mut elf, 0);
        push_u16(&mut elf, 0);
        assert_eq!(elf.len(), usize::from(ELF_HEADER_BYTES));

        push_u32(&mut elf, 1);
        push_u32(&mut elf, SEGMENT_OFFSET);
        push_u32(&mut elf, entry);
        push_u32(&mut elf, entry);
        push_u32(&mut elf, file_size);
        push_u32(&mut elf, memory_size);
        push_u32(&mut elf, 5);
        push_u32(&mut elf, 4);
        assert_eq!(elf.len(), SEGMENT_OFFSET as usize);
        push_u32(&mut elf, instruction);
        elf
    }

    fn minimal_riscv32_elf(entry: u32, instruction: u32) -> Vec<u8> {
        minimal_riscv32_elf_with_load_size(entry, instruction, 4, 4)
    }

    fn valid_guest_elf() -> Vec<u8> {
        let user = minimal_riscv32_elf(0x0001_0000, 0x0000_0013);
        let kernel = minimal_riscv32_elf(0xc000_0000, 0x0010_0073);
        risc0_binfmt::ProgramBinary::new(&user, &kernel).encode()
    }

    fn guest_elf_with_loaded_memory_sizes(user_bytes: u32, kernel_bytes: u32) -> Vec<u8> {
        let user = minimal_riscv32_elf_with_load_size(0x0001_0000, 0, 0, user_bytes);
        let kernel = minimal_riscv32_elf_with_load_size(0xc000_0000, 0, 0, kernel_bytes);
        risc0_binfmt::ProgramBinary::new(&user, &kernel).encode()
    }

    fn physical_identity(path: &Path) -> Result<(u64, u64)> {
        let metadata = fs::metadata(path)?;
        Ok((metadata.dev(), metadata.ino()))
    }

    struct NominalSubstitutionGuard {
        nominal: PathBuf,
        retained: PathBuf,
        active: bool,
    }

    impl NominalSubstitutionGuard {
        fn new(nominal: PathBuf, retained: PathBuf) -> Self {
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
            if self.active {
                let _ = fs::remove_file(&self.nominal);
                let _ = fs::rename(&self.retained, &self.nominal);
                self.active = false;
            }
        }
    }

    fn captured_context(
        files: &[(&str, &[u8])],
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        ExecutorPreflightContext<
            1,
            crate::b4_campaign_executor::preflight::ProjectedPrepareInputSetCampaignLayout<1>,
        >,
    ) {
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
    fn risc0_guest_elf_import_derives_length_sha256_and_image_id_from_one_borrowed_view() {
        let guest = valid_guest_elf();
        let expected_sha256: [u8; 32] = Sha256::digest(&guest).into();
        let expected_image_id: [u8; 32] = compute_image_id(&guest).unwrap().into();
        let (_temp, prior, context) = captured_context(&[("guest.elf", &guest)]);
        let output = prior.parent().unwrap().join("phases/prepare-001");
        let slot = Risc0GuestElfSlotV1::test_only(0, "guest.elf");

        context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_risc0_guest_elf(capability, &slot, |view| {
                        assert_eq!(view.bytes(), guest);
                        assert_eq!(view.byte_length(), u64::try_from(guest.len())?);
                        assert_eq!(view.sha256(), expected_sha256);
                        assert_eq!(view.image_id(), expected_image_id);
                        Ok(())
                    })
                })
            })
            .unwrap();
        assert!(!output.exists());
    }

    #[test]
    fn risc0_guest_elf_import_rejects_role_length_bounds_and_invalid_programs() {
        let empty = Vec::new();
        let oversized = vec![0_u8; 4_194_305];
        let invalid = b"not a RISC Zero guest ELF".to_vec();
        let cases = [
            ("empty.elf", empty.as_slice(), "role-specific range", false),
            (
                "oversized.elf",
                oversized.as_slice(),
                "role-specific range",
                false,
            ),
            ("invalid.elf", invalid.as_slice(), "ProgramBinary", true),
        ];
        let files = cases.map(|(relative, bytes, _expected, _expected_stage)| (relative, bytes));
        let (_temp, prior, context) = captured_context(&files);
        let output = prior.parent().unwrap().join("phases/prepare-001");

        context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    for (relative, _bytes, expected, expected_stage) in cases {
                        let slot = Risc0GuestElfSlotV1::test_only(0, relative);
                        let stage_reached = Cell::new(false);
                        let error = with_imported_risc0_guest_elf_test_hook(
                            capability,
                            &slot,
                            |_stage| {
                                stage_reached.set(true);
                                Ok(())
                            },
                            |_view| -> Result<()> { Ok(()) },
                        )
                        .unwrap_err();
                        assert!(format!("{error:#}").contains(expected), "{error:#}");
                        assert_eq!(stage_reached.get(), expected_stage);
                    }
                    Ok(())
                })
            })
            .unwrap();
        assert!(!output.exists());
    }

    #[test]
    fn risc0_guest_elf_expansion_bound_rejects_maximum_plus_one_before_image_oracle() {
        let maximum = guest_elf_with_loaded_memory_sizes(4, 4_194_300);
        let maximum_plus_one = guest_elf_with_loaded_memory_sizes(4, 4_194_304);
        let oracle_called = Cell::new(false);

        let image_id = derive_risc0_guest_elf_image_id_with(&maximum, |_program| {
            oracle_called.set(true);
            Ok([0x5a; 32])
        })
        .unwrap();
        assert_eq!(image_id, [0x5a; 32]);
        assert!(oracle_called.replace(false));

        let error = derive_risc0_guest_elf_image_id_with(&maximum_plus_one, |_program| {
            oracle_called.set(true);
            Ok([0xa5; 32])
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("loaded-word"), "{error:#}");
        assert!(!oracle_called.get());
    }

    #[test]
    fn risc0_guest_elf_import_rejects_path_pinned_substitution_before_data_open_stage() {
        let guest = valid_guest_elf();
        let (_temp, prior, context) = captured_context(&[("guest.elf", &guest)]);
        let guest_path = prior.join("guest.elf");
        let original_identity = physical_identity(&guest_path).unwrap();
        let output = prior.parent().unwrap().join("phases/prepare-001");
        let retained_path = guest_path.with_extension("retained");
        let slot = Risc0GuestElfSlotV1::test_only(0, "guest.elf");
        let saw_data_opened = Rc::new(Cell::new(false));
        let saw_bytes_read = Rc::new(Cell::new(false));
        let view_delivered = Rc::new(Cell::new(false));
        let hook_saw_data_opened = Rc::clone(&saw_data_opened);
        let hook_saw_bytes_read = Rc::clone(&saw_bytes_read);
        let effect_view_delivered = Rc::clone(&view_delivered);
        let mut substitution =
            NominalSubstitutionGuard::new(guest_path.clone(), retained_path.clone());
        let hook_guest = guest.clone();
        let hook_guest_path = guest_path.clone();

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_risc0_guest_elf_test_hook(
                        capability,
                        &slot,
                        move |stage| {
                            match stage {
                                Risc0GuestElfImportStage::PathPinned => {
                                    substitution.substitute(&hook_guest)?;
                                    assert_eq!(fs::read(&hook_guest_path)?, hook_guest);
                                    assert_ne!(
                                        physical_identity(&hook_guest_path)?,
                                        original_identity
                                    );
                                }
                                Risc0GuestElfImportStage::DataOpened => {
                                    hook_saw_data_opened.set(true);
                                }
                                Risc0GuestElfImportStage::BytesRead => {
                                    hook_saw_bytes_read.set(true);
                                    substitution.restore()?;
                                }
                                Risc0GuestElfImportStage::FileRepinned => {}
                            }
                            Ok(())
                        },
                        move |_view| -> Result<()> {
                            effect_view_delivered.set(true);
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
        assert!(!saw_data_opened.get());
        assert!(!saw_bytes_read.get());
        assert!(!view_delivered.get());
        assert_eq!(fs::read(&guest_path).unwrap(), guest);
        assert!(!retained_path.exists());
        assert!(!output.exists());
    }

    #[test]
    fn risc0_guest_elf_import_final_repin_rejects_byte_identical_inode_substitution() {
        let guest = valid_guest_elf();
        let (_temp, prior, context) = captured_context(&[("guest.elf", &guest)]);
        let guest_path = prior.join("guest.elf");
        let output = prior.parent().unwrap().join("phases/prepare-001");
        let retained_path = guest_path.with_extension("retained");
        let slot = Risc0GuestElfSlotV1::test_only(0, "guest.elf");
        let view_delivered = Cell::new(false);
        let mut substituted = false;

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_risc0_guest_elf_test_hook(
                        capability,
                        &slot,
                        |stage| {
                            if stage == Risc0GuestElfImportStage::DataOpened && !substituted {
                                fs::rename(&guest_path, &retained_path)?;
                                fs::write(&guest_path, &guest)?;
                                assert_eq!(fs::read(&guest_path)?, guest);
                                substituted = true;
                            }
                            Ok(())
                        },
                        |_view| -> Result<()> {
                            view_delivered.set(true);
                            Ok(())
                        },
                    )
                })
            })
            .unwrap_err();

        assert!(substituted);
        assert!(!view_delivered.get());
        let message = format!("{error:#}");
        assert!(
            message.contains("no longer matches") || message.contains("no longer identifies"),
            "{message}"
        );
        assert!(!output.exists());
    }

    #[test]
    fn physical_import_production_surface_has_no_ambient_path_reader() {
        let production = include_str!("artifact_import.rs")
            .split("#[cfg(all(test, target_os = \"linux\"))]\nmod tests")
            .next()
            .unwrap();
        let compact_production = production.split_whitespace().collect::<String>();

        for required in [
            "with_authenticated_file_bytes",
            "validate_risc0_guest_elf_load_work(",
            "program.compute_image_id()",
            "Sha256::digest(bytes)",
        ] {
            assert!(compact_production.contains(required), "missing {required}");
        }
        for forbidden in [
            "std::fs::read",
            "fs::read(",
            "canonicalize(",
            "/proc/self/fd",
        ] {
            assert!(!production.contains(forbidden), "forbidden {forbidden}");
        }
    }
}
