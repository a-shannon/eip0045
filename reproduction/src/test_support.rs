//! Dependency-free temporary directories used only by crate tests.

use std::io;
use std::path::{Path, PathBuf};
#[cfg(feature = "profile")]
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "profile")]
use risc0_binfmt::{ProgramBinary, compute_image_id};

const PREFIX: &str = "eip0045-reproduction-test-";
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

/// One uniquely created test directory removed when its owner is dropped.
pub(crate) struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Return the physical path owned by this guard.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let expected_parent = std::env::temp_dir();
        let has_prefix = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(PREFIX));
        if self.path.parent() == Some(expected_parent.as_path()) && has_prefix {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Atomically create an empty process-local test directory.
pub(crate) fn tempdir() -> io::Result<TempDir> {
    let root = std::env::temp_dir();
    for _ in 0..1_024 {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = root.join(format!("{PREFIX}{}-{sequence}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(TempDir { path }),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not reserve a unique EIP-0045 test directory",
    ))
}

#[cfg(feature = "profile")]
fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[cfg(feature = "profile")]
fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

#[cfg(feature = "profile")]
fn minimal_riscv32_elf(entry: u32, instruction: u32) -> Vec<u8> {
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
    push_u32(&mut elf, 4);
    push_u32(&mut elf, 4);
    push_u32(&mut elf, 5);
    push_u32(&mut elf, 4);
    assert_eq!(elf.len(), SEGMENT_OFFSET as usize);
    push_u32(&mut elf, instruction);
    elf
}

/// Return one deterministic, valid encoded RISC Zero program and image ID.
#[cfg(feature = "profile")]
pub(crate) fn program_binary(user_instruction: u32, kernel_instruction: u32) -> Vec<u8> {
    let user = minimal_riscv32_elf(0x0001_0000, user_instruction);
    let kernel = minimal_riscv32_elf(0xc000_0000, kernel_instruction);
    ProgramBinary::new(&user, &kernel).encode()
}

/// Return one deterministic, valid encoded RISC Zero program and image ID.
#[cfg(feature = "profile")]
pub(crate) fn valid_program_fixture() -> (Vec<u8>, [u8; 32]) {
    static FIXTURE: OnceLock<(Vec<u8>, [u8; 32])> = OnceLock::new();
    let (guest, image_id) = FIXTURE.get_or_init(|| {
        let guest = program_binary(0x0000_0013, 0x0010_0073);
        let image_id = compute_image_id(&guest).unwrap().into();
        (guest, image_id)
    });
    (guest.clone(), *image_id)
}
