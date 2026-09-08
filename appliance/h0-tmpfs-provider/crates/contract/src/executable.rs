//! Pure, bounded policy for retained H0 execution-image bytes.

use anyhow::{Context as _, Result, ensure};
use elf::{
    abi,
    endian::LittleEndian,
    file::{Class, FileHeader, parse_ident},
    section::{SectionHeader, SectionHeaderTable},
    segment::{ProgramHeader, SegmentTable},
};
use sha2::{Digest as _, Sha256};

/// Smallest encoded image accepted by the retained static-ELF policy.
pub const RETAINED_STATIC_AMD64_ELF_MIN_BYTES_V2: u64 = 64;
/// Largest encoded image accepted by the retained static-ELF policy.
pub const RETAINED_STATIC_AMD64_ELF_MAX_BYTES_V2: u64 = 1_073_741_824;
/// Largest program-header count inspected under the retained static-ELF policy.
pub const RETAINED_STATIC_AMD64_ELF_MAX_PROGRAM_HEADERS_V2: u64 = 65_534;
/// Largest section-header count inspected under the retained static-ELF policy.
pub const RETAINED_STATIC_AMD64_ELF_MAX_SECTION_HEADERS_V2: u64 = 65_279;

const ELF64_HEADER_BYTES: usize = 64;
const ELF64_PROGRAM_HEADER_BYTES: u16 = 56;
const ELF64_SECTION_HEADER_BYTES: u16 = 64;
const ELF_SHN_LORESERVE: u16 = 0xff00;

/// Non-authorizing expected identity for the measured H0 generator image.
///
/// This value contains no descriptor, path, execution permission, or custody
/// state. A separate Linux owner must bind it to one already-retained object.
pub struct GeneratorExecutableExpectationV2 {
    device: u64,
    inode: u64,
    mount_id: u64,
    byte_length: u64,
    sha256: [u8; 32],
}

impl GeneratorExecutableExpectationV2 {
    /// Binds the qualified generator physical identity, length, and SHA-256.
    #[must_use]
    pub const fn new(
        device: u64,
        inode: u64,
        mount_id: u64,
        byte_length: u64,
        sha256: [u8; 32],
    ) -> Self {
        Self {
            device,
            inode,
            mount_id,
            byte_length,
            sha256,
        }
    }

    /// Returns the qualified device identity.
    #[must_use]
    pub const fn device(&self) -> u64 {
        self.device
    }

    /// Returns the qualified inode identity.
    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    /// Returns the qualified mount identity.
    #[must_use]
    pub const fn mount_id(&self) -> u64 {
        self.mount_id
    }

    /// Returns the qualified encoded byte length.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// Returns the qualified SHA-256 digest.
    #[must_use]
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

/// Non-authorizing expected identity for the measured H0 worker image.
///
/// This is deliberately a different concrete type from
/// [`GeneratorExecutableExpectationV2`], so callers cannot select a role with
/// one generic discriminant.
pub struct WorkerExecutableExpectationV2 {
    device: u64,
    inode: u64,
    mount_id: u64,
    byte_length: u64,
    sha256: [u8; 32],
}

impl WorkerExecutableExpectationV2 {
    /// Binds the qualified worker physical identity, length, and SHA-256.
    #[must_use]
    pub const fn new(
        device: u64,
        inode: u64,
        mount_id: u64,
        byte_length: u64,
        sha256: [u8; 32],
    ) -> Self {
        Self {
            device,
            inode,
            mount_id,
            byte_length,
            sha256,
        }
    }

    /// Returns the qualified device identity.
    #[must_use]
    pub const fn device(&self) -> u64 {
        self.device
    }

    /// Returns the qualified inode identity.
    #[must_use]
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    /// Returns the qualified mount identity.
    #[must_use]
    pub const fn mount_id(&self) -> u64 {
        self.mount_id
    }

    /// Returns the qualified encoded byte length.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// Returns the qualified SHA-256 digest.
    #[must_use]
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

/// Revalidates one exact byte slice under the fixed retained static AMD64 ELF
/// policy and joins it to the expected length and SHA-256.
///
/// A successful result is only a pure statement about the supplied bytes. It
/// carries no object lifetime, physical identity, or execution capability.
///
/// # Errors
///
/// Returns an error when the supplied slice differs from the expected length
/// or digest, exceeds a fixed parser bound, is not a closed ELF64
/// little-endian AMD64 image, or violates the static load/stack policy.
pub fn inspect_retained_static_amd64_elf_v2(
    bytes: &[u8],
    expected_byte_length: u64,
    expected_sha256: [u8; 32],
) -> Result<()> {
    let byte_length =
        u64::try_from(bytes.len()).context("retained AMD64 ELF length does not fit u64")?;
    ensure!(
        byte_length == expected_byte_length,
        "retained AMD64 ELF length differs from its role-specific expectation"
    );
    validate_encoded_length_v2(byte_length)?;
    validate_static_amd64_elf_v2(bytes)?;
    let actual_sha256: [u8; 32] = Sha256::digest(bytes).into();
    ensure!(
        actual_sha256 == expected_sha256,
        "retained AMD64 ELF digest differs from its role-specific expectation"
    );
    Ok(())
}

fn validate_encoded_length_v2(byte_length: u64) -> Result<()> {
    ensure!(
        (RETAINED_STATIC_AMD64_ELF_MIN_BYTES_V2..=RETAINED_STATIC_AMD64_ELF_MAX_BYTES_V2)
            .contains(&byte_length),
        "static AMD64 ELF encoded byte length is outside its role-specific range"
    );
    Ok(())
}

fn validate_static_amd64_elf_v2(bytes: &[u8]) -> Result<()> {
    let header = parse_closed_elf64_header(bytes)?;
    let analysis = inspect_common_structure(bytes, &header)?;
    ensure!(
        analysis.entry_point_in_executable_load,
        "AMD64 ELF entry point is not in an executable PT_LOAD"
    );
    ensure!(
        analysis.interpreter.is_none() && analysis.dynamic.is_none(),
        "static ELF contains an interpreter or dynamic segment"
    );
    Ok(())
}

fn parse_closed_elf64_header(bytes: &[u8]) -> Result<FileHeader<LittleEndian>> {
    ensure!(&bytes[..4] == b"\x7fELF", "AMD64 ELF magic is invalid");
    ensure!(bytes[4] == abi::ELFCLASS64, "AMD64 ELF is not ELF64");
    ensure!(
        bytes[5] == abi::ELFDATA2LSB,
        "AMD64 ELF is not little-endian"
    );
    ensure!(
        bytes[6] == abi::EV_CURRENT,
        "AMD64 ELF ident version is not current"
    );
    ensure!(
        matches!(bytes[7], abi::ELFOSABI_SYSV | abi::ELFOSABI_LINUX),
        "AMD64 ELF OS ABI is not System V or Linux"
    );
    ensure!(bytes[8] == 0, "AMD64 ELF ABI version is not zero");
    ensure!(
        bytes[9..16].iter().all(|byte| *byte == 0),
        "AMD64 ELF ident padding is not all zero"
    );

    let ident = parse_ident::<LittleEndian>(&bytes[..16])
        .map_err(|error| anyhow::anyhow!("cannot parse AMD64 ELF ident: {error:?}"))?;
    ensure!(ident.1 == Class::ELF64, "AMD64 ELF is not ELF64");
    let header = FileHeader::parse_tail(ident, &bytes[16..ELF64_HEADER_BYTES])
        .map_err(|error| anyhow::anyhow!("cannot parse AMD64 ELF header: {error:?}"))?;
    ensure!(
        matches!(header.e_type, abi::ET_EXEC | abi::ET_DYN),
        "AMD64 ELF type is not ET_EXEC or ET_DYN"
    );
    ensure!(
        header.e_machine == abi::EM_X86_64,
        "ELF machine is not AMD64"
    );
    ensure!(
        header.version == u32::from(abi::EV_CURRENT),
        "AMD64 ELF header version is not current"
    );
    ensure!(
        usize::from(header.e_ehsize) == ELF64_HEADER_BYTES,
        "AMD64 ELF header size is not 64"
    );
    Ok(header)
}

struct CommonElfAnalysis {
    entry_point_in_executable_load: bool,
    interpreter: Option<ProgramHeader>,
    dynamic: Option<ProgramHeader>,
}

fn inspect_common_structure(
    bytes: &[u8],
    header: &FileHeader<LittleEndian>,
) -> Result<CommonElfAnalysis> {
    let program_header_count = u64::from(header.e_phnum);
    ensure!(
        (1..=RETAINED_STATIC_AMD64_ELF_MAX_PROGRAM_HEADERS_V2).contains(&program_header_count),
        "AMD64 ELF program-header count is outside its role-specific range"
    );
    ensure!(
        header.e_phentsize == ELF64_PROGRAM_HEADER_BYTES,
        "AMD64 ELF program-header entry size is not 56"
    );
    let program_table_bytes = program_header_count
        .checked_mul(u64::from(ELF64_PROGRAM_HEADER_BYTES))
        .context("AMD64 ELF program-header table size overflowed")?;
    let program_table = checked_file_range(
        bytes,
        header.e_phoff,
        program_table_bytes,
        "program-header table",
    )?;
    let mut program_headers = Vec::new();
    program_headers
        .try_reserve_exact(usize::from(header.e_phnum))
        .context("cannot retain bounded AMD64 program headers")?;
    program_headers.extend(
        SegmentTable::new(LittleEndian, Class::ELF64, program_table)
            .iter()
            .take(usize::from(header.e_phnum)),
    );
    ensure!(
        program_headers.len() == usize::from(header.e_phnum),
        "AMD64 ELF program-header table did not parse completely"
    );

    parse_and_validate_section_headers(bytes, header)?;
    inspect_load_and_linkage_segments(bytes, header, &program_headers)
}

#[allow(
    clippy::too_many_lines,
    reason = "the closed load-segment predicates remain linear for review"
)]
fn inspect_load_and_linkage_segments(
    bytes: &[u8],
    header: &FileHeader<LittleEndian>,
    program_headers: &[ProgramHeader],
) -> Result<CommonElfAnalysis> {
    let mut load_segment_count = 0_u64;
    let mut readable_load_exists = false;
    let mut entry_point_in_executable_load = false;
    let mut load_file_ranges = Vec::<(u64, u64)>::new();
    load_file_ranges
        .try_reserve_exact(program_headers.len())
        .context("cannot retain bounded AMD64 PT_LOAD ranges")?;
    let mut interpreter = None;
    let mut dynamic = None;
    let mut gnu_stack_segment_count = 0_u64;

    for segment in program_headers {
        let file_end = checked_file_end(
            bytes,
            segment.p_offset,
            segment.p_filesz,
            "program-header file range",
        )?;
        match segment.p_type {
            abi::PT_LOAD => {
                ensure!(
                    segment.p_filesz <= segment.p_memsz,
                    "AMD64 ELF PT_LOAD file size exceeds memory size"
                );
                ensure!(
                    segment.p_align <= 1 || segment.p_align.is_power_of_two(),
                    "AMD64 ELF PT_LOAD alignment is not zero, one, or a power of two"
                );
                if segment.p_align > 1 {
                    ensure!(
                        segment.p_vaddr % segment.p_align == segment.p_offset % segment.p_align,
                        "AMD64 ELF PT_LOAD virtual address and file offset are incongruent"
                    );
                }
                let memory_end = segment
                    .p_vaddr
                    .checked_add(segment.p_memsz)
                    .context("AMD64 ELF PT_LOAD memory range overflowed")?;
                let readable = segment.p_flags & abi::PF_R != 0;
                let writable = segment.p_flags & abi::PF_W != 0;
                let executable = segment.p_flags & abi::PF_X != 0;
                ensure!(
                    !(writable && executable),
                    "AMD64 ELF PT_LOAD is both writable and executable"
                );
                load_segment_count += 1;
                readable_load_exists |= readable;
                if executable {
                    entry_point_in_executable_load |=
                        segment.p_vaddr <= header.e_entry && header.e_entry < memory_end;
                }
                if segment.p_filesz != 0 {
                    load_file_ranges.push((segment.p_offset, file_end));
                }
            }
            abi::PT_INTERP => {
                ensure!(
                    interpreter.replace(*segment).is_none(),
                    "AMD64 ELF contains more than one interpreter segment"
                );
            }
            abi::PT_DYNAMIC => {
                ensure!(
                    dynamic.replace(*segment).is_none(),
                    "AMD64 ELF contains more than one dynamic segment"
                );
            }
            abi::PT_GNU_STACK => {
                gnu_stack_segment_count += 1;
                ensure!(
                    gnu_stack_segment_count == 1 && segment.p_flags & abi::PF_X == 0,
                    "AMD64 ELF GNU stack is duplicated or executable"
                );
            }
            abi::PT_SHLIB => anyhow::bail!("AMD64 ELF contains a rejected PT_SHLIB segment"),
            _ => {}
        }
    }

    ensure!(load_segment_count != 0, "AMD64 ELF has no PT_LOAD segment");
    ensure!(
        readable_load_exists,
        "AMD64 ELF has no readable PT_LOAD segment"
    );
    ensure!(
        gnu_stack_segment_count == 1,
        "AMD64 ELF does not contain exactly one non-executable GNU stack"
    );
    load_file_ranges.sort_unstable();
    let mut previous_end = 0_u64;
    let mut have_previous = false;
    for (start, end) in load_file_ranges {
        ensure!(
            !have_previous || start >= previous_end,
            "AMD64 ELF PT_LOAD file ranges overlap"
        );
        previous_end = previous_end.max(end);
        have_previous = true;
    }

    Ok(CommonElfAnalysis {
        entry_point_in_executable_load,
        interpreter,
        dynamic,
    })
}

fn parse_and_validate_section_headers(
    bytes: &[u8],
    header: &FileHeader<LittleEndian>,
) -> Result<()> {
    if header.e_shoff == 0 {
        ensure!(
            (header.e_shentsize, header.e_shnum, header.e_shstrndx) == (0, 0, 0),
            "absent AMD64 ELF section table does not use the exact zero tuple"
        );
        return Ok(());
    }
    ensure!(
        header.e_shnum != 0
            && header.e_shnum < ELF_SHN_LORESERVE
            && header.e_shstrndx != abi::SHN_XINDEX,
        "AMD64 ELF extended section numbering is rejected"
    );
    let section_header_count = u64::from(header.e_shnum);
    ensure!(
        section_header_count <= RETAINED_STATIC_AMD64_ELF_MAX_SECTION_HEADERS_V2,
        "AMD64 ELF section-header count exceeds its role-specific range"
    );
    ensure!(
        header.e_shentsize == ELF64_SECTION_HEADER_BYTES,
        "AMD64 ELF section-header entry size is not 64"
    );
    ensure!(
        header.e_shstrndx == abi::SHN_UNDEF
            || (header.e_shstrndx < ELF_SHN_LORESERVE && header.e_shstrndx < header.e_shnum),
        "AMD64 ELF section-name string-table index is outside the section table"
    );
    let section_table_bytes = section_header_count
        .checked_mul(u64::from(ELF64_SECTION_HEADER_BYTES))
        .context("AMD64 ELF section-header table size overflowed")?;
    let section_table = checked_file_range(
        bytes,
        header.e_shoff,
        section_table_bytes,
        "section-header table",
    )?;
    let mut sections = Vec::new();
    sections
        .try_reserve_exact(usize::from(header.e_shnum))
        .context("cannot retain bounded AMD64 section headers")?;
    sections.extend(
        SectionHeaderTable::new(LittleEndian, Class::ELF64, section_table)
            .iter()
            .take(usize::from(header.e_shnum)),
    );
    ensure!(
        sections.len() == usize::from(header.e_shnum),
        "AMD64 ELF section-header table did not parse completely"
    );
    validate_sections(bytes, header, &sections)
}

fn validate_sections(
    bytes: &[u8],
    header: &FileHeader<LittleEndian>,
    sections: &[SectionHeader],
) -> Result<()> {
    let section_zero = &sections[0];
    ensure!(
        section_zero.sh_name == 0
            && section_zero.sh_type == abi::SHT_NULL
            && section_zero.sh_flags == 0
            && section_zero.sh_addr == 0
            && section_zero.sh_offset == 0
            && section_zero.sh_size == 0
            && section_zero.sh_link == 0
            && section_zero.sh_info == 0
            && section_zero.sh_addralign == 0
            && section_zero.sh_entsize == 0,
        "AMD64 ELF section zero is not the exact null header"
    );

    let section_header_count = u64::try_from(sections.len())?;
    for section in sections {
        if section.sh_type != abi::SHT_NOBITS {
            checked_file_end(
                bytes,
                section.sh_offset,
                section.sh_size,
                "section file range",
            )?;
        }
        if section_link_is_section_index(section.sh_type)
            || section.sh_flags & u64::from(abi::SHF_LINK_ORDER) != 0
        {
            ensure!(
                u64::from(section.sh_link) < section_header_count,
                "AMD64 ELF section sh_link index is outside the section table"
            );
        }
        if matches!(section.sh_type, abi::SHT_REL | abi::SHT_RELA)
            || section.sh_flags & u64::from(abi::SHF_INFO_LINK) != 0
        {
            ensure!(
                u64::from(section.sh_info) < section_header_count,
                "AMD64 ELF section sh_info index is outside the section table"
            );
        }
    }

    if header.e_shstrndx != abi::SHN_UNDEF {
        validate_section_name_table(bytes, header, sections)?;
    }
    Ok(())
}

fn validate_section_name_table(
    bytes: &[u8],
    header: &FileHeader<LittleEndian>,
    sections: &[SectionHeader],
) -> Result<()> {
    let string_header = &sections[usize::from(header.e_shstrndx)];
    ensure!(
        string_header.sh_type == abi::SHT_STRTAB,
        "AMD64 ELF selected section-name table is not SHT_STRTAB"
    );
    let string_table = checked_file_range(
        bytes,
        string_header.sh_offset,
        string_header.sh_size,
        "section-name string table",
    )?;
    ensure!(
        string_table.first() == Some(&0) && string_table.last() == Some(&0),
        "AMD64 ELF section-name string table is not NUL-bounded through its declared end"
    );
    for section in sections {
        ensure!(
            usize::try_from(section.sh_name)
                .ok()
                .is_some_and(|offset| offset < string_table.len()),
            "AMD64 ELF section name offset is outside the selected string table"
        );
    }
    Ok(())
}

fn section_link_is_section_index(section_type: u32) -> bool {
    matches!(
        section_type,
        abi::SHT_SYMTAB
            | abi::SHT_RELA
            | abi::SHT_HASH
            | abi::SHT_DYNAMIC
            | abi::SHT_REL
            | abi::SHT_DYNSYM
            | abi::SHT_GROUP
            | abi::SHT_SYMTAB_SHNDX
            | abi::SHT_GNU_HASH
            | abi::SHT_GNU_LIBLIST
            | abi::SHT_GNU_VERDEF
            | abi::SHT_GNU_VERNEED
            | abi::SHT_GNU_VERSYM
    )
}

fn checked_file_end(bytes: &[u8], offset: u64, size: u64, label: &str) -> Result<u64> {
    let end = offset
        .checked_add(size)
        .with_context(|| format!("AMD64 ELF {label} overflowed"))?;
    ensure!(
        end <= u64::try_from(bytes.len())?,
        "AMD64 ELF {label} is outside the file"
    );
    Ok(end)
}

fn checked_file_range<'bytes>(
    bytes: &'bytes [u8],
    offset: u64,
    size: u64,
    label: &str,
) -> Result<&'bytes [u8]> {
    let end = checked_file_end(bytes, offset, size, label)?;
    let start = usize::try_from(offset)
        .with_context(|| format!("AMD64 ELF {label} start does not fit memory addressing"))?;
    let end = usize::try_from(end)
        .with_context(|| format!("AMD64 ELF {label} end does not fit memory addressing"))?;
    Ok(&bytes[start..end])
}

#[cfg(test)]
mod executable_expectation_v2 {
    use super::{GeneratorExecutableExpectationV2, WorkerExecutableExpectationV2};

    #[test]
    fn role_expectations_retain_distinct_exact_fields() {
        let generator = GeneratorExecutableExpectationV2::new(1, 2, 3, 4, [5; 32]);
        let worker = WorkerExecutableExpectationV2::new(6, 7, 8, 9, [10; 32]);

        assert_eq!(
            (
                generator.device(),
                generator.inode(),
                generator.mount_id(),
                generator.byte_length(),
                generator.sha256(),
            ),
            (1, 2, 3, 4, [5; 32])
        );
        assert_eq!(
            (
                worker.device(),
                worker.inode(),
                worker.mount_id(),
                worker.byte_length(),
                worker.sha256(),
            ),
            (6, 7, 8, 9, [10; 32])
        );
    }

    #[test]
    fn role_expectations_are_not_clone_copy_or_default() {
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

        trait AmbiguousIfDefault<Marker> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfDefault<()> for T {}
        impl<T: Default> AmbiguousIfDefault<u8> for T {}

        type GeneratorConstructor =
            fn(u64, u64, u64, u64, [u8; 32]) -> GeneratorExecutableExpectationV2;
        type WorkerConstructor = fn(u64, u64, u64, u64, [u8; 32]) -> WorkerExecutableExpectationV2;

        let generator: GeneratorConstructor = GeneratorExecutableExpectationV2::new;
        let worker: WorkerConstructor = WorkerExecutableExpectationV2::new;
        std::hint::black_box((generator, worker));

        <GeneratorExecutableExpectationV2 as AmbiguousIfClone<_>>::marker();
        <GeneratorExecutableExpectationV2 as AmbiguousIfCopy<_>>::marker();
        <GeneratorExecutableExpectationV2 as AmbiguousIfDefault<_>>::marker();
        <WorkerExecutableExpectationV2 as AmbiguousIfClone<_>>::marker();
        <WorkerExecutableExpectationV2 as AmbiguousIfCopy<_>>::marker();
        <WorkerExecutableExpectationV2 as AmbiguousIfDefault<_>>::marker();
    }
}

#[cfg(test)]
mod retained_static_elf_policy_v2 {
    use elf::abi;
    use sha2::{Digest as _, Sha256};

    use super::{
        RETAINED_STATIC_AMD64_ELF_MAX_BYTES_V2, RETAINED_STATIC_AMD64_ELF_MAX_PROGRAM_HEADERS_V2,
        RETAINED_STATIC_AMD64_ELF_MAX_SECTION_HEADERS_V2, RETAINED_STATIC_AMD64_ELF_MIN_BYTES_V2,
        inspect_retained_static_amd64_elf_v2, validate_encoded_length_v2,
    };

    const ELF_HEADER_BYTES: usize = 64;
    const PROGRAM_HEADER_BYTES: usize = 56;
    const LOAD_VIRTUAL_ADDRESS: u64 = 0x0040_0000;

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn program_header_offset(index: usize) -> usize {
        ELF_HEADER_BYTES + index * PROGRAM_HEADER_BYTES
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the helper mirrors the eight fixed Elf64_Phdr fields"
    )]
    fn set_program_header(
        bytes: &mut [u8],
        index: usize,
        segment_type: u32,
        flags: u32,
        file_offset: u64,
        virtual_address: u64,
        physical_address: u64,
        file_size: u64,
        memory_size: u64,
        alignment: u64,
    ) {
        let offset = program_header_offset(index);
        write_u32(bytes, offset, segment_type);
        write_u32(bytes, offset + 4, flags);
        write_u64(bytes, offset + 8, file_offset);
        write_u64(bytes, offset + 16, virtual_address);
        write_u64(bytes, offset + 24, physical_address);
        write_u64(bytes, offset + 32, file_size);
        write_u64(bytes, offset + 40, memory_size);
        write_u64(bytes, offset + 48, alignment);
    }

    fn static_elf_with_program_headers(program_header_count: u16) -> Vec<u8> {
        let byte_length =
            ELF_HEADER_BYTES + usize::from(program_header_count) * PROGRAM_HEADER_BYTES;
        let mut bytes = vec![0_u8; byte_length];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = abi::ELFCLASS64;
        bytes[5] = abi::ELFDATA2LSB;
        bytes[6] = abi::EV_CURRENT;
        bytes[7] = abi::ELFOSABI_SYSV;
        write_u16(&mut bytes, 16, abi::ET_EXEC);
        write_u16(&mut bytes, 18, abi::EM_X86_64);
        write_u32(&mut bytes, 20, u32::from(abi::EV_CURRENT));
        write_u64(&mut bytes, 24, LOAD_VIRTUAL_ADDRESS);
        write_u64(&mut bytes, 32, ELF_HEADER_BYTES as u64);
        write_u16(&mut bytes, 52, u16::try_from(ELF_HEADER_BYTES).unwrap());
        write_u16(&mut bytes, 54, u16::try_from(PROGRAM_HEADER_BYTES).unwrap());
        write_u16(&mut bytes, 56, program_header_count);
        set_program_header(
            &mut bytes,
            0,
            abi::PT_LOAD,
            abi::PF_R | abi::PF_X,
            0,
            LOAD_VIRTUAL_ADDRESS,
            LOAD_VIRTUAL_ADDRESS,
            byte_length as u64,
            byte_length as u64,
            0x1000,
        );
        set_program_header(
            &mut bytes,
            usize::from(program_header_count) - 1,
            abi::PT_GNU_STACK,
            abi::PF_R | abi::PF_W,
            0,
            0,
            0,
            0,
            0,
            16,
        );
        bytes
    }

    fn static_elf() -> Vec<u8> {
        static_elf_with_program_headers(2)
    }

    fn static_elf_with_null_section() -> Vec<u8> {
        let mut bytes = static_elf();
        let section_offset = bytes.len();
        bytes.resize(section_offset + 64, 0);
        write_u64(&mut bytes, 40, section_offset as u64);
        write_u16(&mut bytes, 58, 64);
        write_u16(&mut bytes, 60, 1);
        let byte_length = bytes.len() as u64;
        let load = program_header_offset(0);
        write_u64(&mut bytes, load + 32, byte_length);
        write_u64(&mut bytes, load + 40, byte_length);
        bytes
    }

    fn static_elf_with_section_headers(section_header_count: u16) -> Vec<u8> {
        let mut bytes = static_elf();
        let section_offset = bytes.len();
        bytes.resize(section_offset + usize::from(section_header_count) * 64, 0);
        write_u64(&mut bytes, 40, section_offset as u64);
        write_u16(&mut bytes, 58, 64);
        write_u16(&mut bytes, 60, section_header_count);
        bytes
    }

    fn assert_policy_rejected(bytes: &[u8], expected: &str) {
        let byte_length = u64::try_from(bytes.len()).unwrap();
        let sha256: [u8; 32] = Sha256::digest(bytes).into();
        let error = inspect_retained_static_amd64_elf_v2(bytes, byte_length, sha256).unwrap_err();
        assert!(format!("{error:#}").contains(expected), "{error:#}");
    }

    #[test]
    fn retained_static_elf_policy_v2_joins_exact_length_digest_and_structure() {
        let bytes = static_elf();
        let byte_length = u64::try_from(bytes.len()).unwrap();
        let sha256: [u8; 32] = Sha256::digest(&bytes).into();

        inspect_retained_static_amd64_elf_v2(&bytes, byte_length, sha256).unwrap();

        let length_error =
            inspect_retained_static_amd64_elf_v2(&bytes, byte_length + 1, sha256).unwrap_err();
        assert!(format!("{length_error:#}").contains("length differs"));

        let mut wrong_sha256 = sha256;
        wrong_sha256[0] ^= 1;
        let digest_error =
            inspect_retained_static_amd64_elf_v2(&bytes, byte_length, wrong_sha256).unwrap_err();
        assert!(format!("{digest_error:#}").contains("digest differs"));
    }

    #[test]
    fn retained_static_elf_policy_v2_fixes_parser_work_limits() {
        assert_eq!(RETAINED_STATIC_AMD64_ELF_MIN_BYTES_V2, 64);
        assert_eq!(RETAINED_STATIC_AMD64_ELF_MAX_BYTES_V2, 1_073_741_824);
        assert_eq!(RETAINED_STATIC_AMD64_ELF_MAX_PROGRAM_HEADERS_V2, 65_534);
        assert_eq!(RETAINED_STATIC_AMD64_ELF_MAX_SECTION_HEADERS_V2, 65_279);
        validate_encoded_length_v2(RETAINED_STATIC_AMD64_ELF_MIN_BYTES_V2).unwrap();
        validate_encoded_length_v2(RETAINED_STATIC_AMD64_ELF_MAX_BYTES_V2).unwrap();
        assert!(validate_encoded_length_v2(63).is_err());
        assert!(validate_encoded_length_v2(1_073_741_825).is_err());
    }

    #[test]
    fn retained_static_elf_policy_v2_rejects_header_mutants_independently() {
        let baseline = static_elf();
        let mut cases = Vec::<(&str, Vec<u8>, &str)>::new();

        cases.push(("short", vec![0_u8; 63], "encoded byte length"));
        let mut magic = baseline.clone();
        magic[0] ^= 1;
        cases.push(("magic", magic, "magic"));
        let mut class = baseline.clone();
        class[4] = abi::ELFCLASS32;
        cases.push(("class", class, "ELF64"));
        let mut endian = baseline.clone();
        endian[5] = abi::ELFDATA2MSB;
        cases.push(("endian", endian, "little-endian"));
        let mut machine = baseline.clone();
        write_u16(&mut machine, 18, 3);
        cases.push(("machine", machine, "not AMD64"));
        let mut elf_type = baseline.clone();
        write_u16(&mut elf_type, 16, abi::ET_REL);
        cases.push(("type", elf_type, "ET_EXEC or ET_DYN"));
        let mut header_size = baseline.clone();
        write_u16(&mut header_size, 52, 63);
        cases.push(("header size", header_size, "header size"));

        for (label, bytes, expected) in cases {
            let result = std::panic::catch_unwind(|| assert_policy_rejected(&bytes, expected));
            assert!(result.is_ok(), "header mutant {label} was not isolated");
        }
    }

    #[test]
    fn retained_static_elf_policy_v2_rejects_load_mutants_independently() {
        let baseline = static_elf();
        let load = program_header_offset(0);
        let mut cases = Vec::<(&str, Vec<u8>, &str)>::new();

        let mut file_larger_than_memory = baseline.clone();
        write_u64(
            &mut file_larger_than_memory,
            load + 40,
            u64::try_from(baseline.len() - 1).unwrap(),
        );
        cases.push((
            "file larger than memory",
            file_larger_than_memory,
            "file size exceeds memory size",
        ));
        let mut alignment = baseline.clone();
        write_u64(&mut alignment, load + 48, 3);
        cases.push(("alignment", alignment, "alignment"));
        let mut congruence = baseline.clone();
        write_u64(&mut congruence, load + 16, LOAD_VIRTUAL_ADDRESS + 1);
        cases.push(("congruence", congruence, "incongruent"));
        let mut write_execute = baseline.clone();
        write_u32(
            &mut write_execute,
            load + 4,
            abi::PF_R | abi::PF_W | abi::PF_X,
        );
        cases.push(("write execute", write_execute, "writable and executable"));
        let mut unreadable = baseline.clone();
        write_u32(&mut unreadable, load + 4, abi::PF_X);
        cases.push(("unreadable", unreadable, "no readable"));
        let mut entry = baseline.clone();
        write_u64(&mut entry, 24, LOAD_VIRTUAL_ADDRESS + baseline.len() as u64);
        cases.push(("entry", entry, "entry point"));

        for (label, bytes, expected) in cases {
            let result = std::panic::catch_unwind(|| assert_policy_rejected(&bytes, expected));
            assert!(result.is_ok(), "load mutant {label} was not isolated");
        }
    }

    #[test]
    fn retained_static_elf_policy_v2_rejects_segment_shape_mutants() {
        let baseline = static_elf();
        let stack = program_header_offset(1);

        let mut no_load = baseline.clone();
        write_u32(&mut no_load, program_header_offset(0), abi::PT_NULL);
        assert_policy_rejected(&no_load, "no PT_LOAD");

        let mut no_stack = baseline.clone();
        write_u32(&mut no_stack, stack, abi::PT_NULL);
        assert_policy_rejected(&no_stack, "exactly one non-executable GNU stack");

        let mut executable_stack = baseline.clone();
        write_u32(
            &mut executable_stack,
            stack + 4,
            abi::PF_R | abi::PF_W | abi::PF_X,
        );
        assert_policy_rejected(&executable_stack, "duplicated or executable");

        for (segment_type, expected) in [
            (abi::PT_INTERP, "static ELF"),
            (abi::PT_DYNAMIC, "static ELF"),
            (abi::PT_SHLIB, "PT_SHLIB"),
        ] {
            let mut bytes = static_elf_with_program_headers(3);
            set_program_header(&mut bytes, 1, segment_type, abi::PF_R, 0, 0, 0, 0, 0, 1);
            assert_policy_rejected(&bytes, expected);
        }

        let mut duplicate_stack = static_elf_with_program_headers(3);
        set_program_header(
            &mut duplicate_stack,
            1,
            abi::PT_GNU_STACK,
            abi::PF_R | abi::PF_W,
            0,
            0,
            0,
            0,
            0,
            16,
        );
        assert_policy_rejected(&duplicate_stack, "duplicated or executable");

        let mut overlapping_loads = static_elf_with_program_headers(3);
        set_program_header(
            &mut overlapping_loads,
            1,
            abi::PT_LOAD,
            abi::PF_R,
            64,
            LOAD_VIRTUAL_ADDRESS + 0x1040,
            LOAD_VIRTUAL_ADDRESS + 0x1040,
            1,
            1,
            0x1000,
        );
        assert_policy_rejected(&overlapping_loads, "file ranges overlap");
    }

    #[test]
    fn retained_static_elf_policy_v2_rejects_header_table_bounds() {
        let baseline = static_elf();

        let mut zero_program_headers = baseline.clone();
        write_u16(&mut zero_program_headers, 56, 0);
        assert_policy_rejected(&zero_program_headers, "program-header count");

        let mut excessive_program_headers = baseline.clone();
        write_u16(&mut excessive_program_headers, 56, u16::MAX);
        assert_policy_rejected(&excessive_program_headers, "program-header count");

        let mut wrong_program_entry_size = baseline.clone();
        write_u16(&mut wrong_program_entry_size, 54, 55);
        assert_policy_rejected(&wrong_program_entry_size, "entry size");

        let mut program_table_outside = baseline.clone();
        write_u64(&mut program_table_outside, 32, baseline.len() as u64);
        assert_policy_rejected(&program_table_outside, "program-header table is outside");

        let mut absent_section_tuple = baseline.clone();
        write_u16(&mut absent_section_tuple, 58, 64);
        assert_policy_rejected(&absent_section_tuple, "exact zero tuple");

        let sectioned = static_elf_with_null_section();
        let mut section_table_outside = sectioned.clone();
        write_u64(&mut section_table_outside, 40, sectioned.len() as u64);
        assert_policy_rejected(&section_table_outside, "section-header table is outside");

        let mut wrong_section_entry_size = sectioned.clone();
        write_u16(&mut wrong_section_entry_size, 58, 63);
        assert_policy_rejected(&wrong_section_entry_size, "section-header entry size");

        let mut non_null_section_zero = sectioned;
        let section_offset = u64::from_le_bytes(non_null_section_zero[40..48].try_into().unwrap());
        write_u32(
            &mut non_null_section_zero,
            usize::try_from(section_offset).unwrap() + 4,
            abi::SHT_PROGBITS,
        );
        assert_policy_rejected(&non_null_section_zero, "section zero");
    }

    #[test]
    fn retained_static_elf_policy_v2_accepts_exact_header_count_ceilings() {
        let maximum_program_headers = static_elf_with_program_headers(
            u16::try_from(RETAINED_STATIC_AMD64_ELF_MAX_PROGRAM_HEADERS_V2).unwrap(),
        );
        let maximum_program_length = u64::try_from(maximum_program_headers.len()).unwrap();
        let maximum_program_sha256: [u8; 32] = Sha256::digest(&maximum_program_headers).into();
        inspect_retained_static_amd64_elf_v2(
            &maximum_program_headers,
            maximum_program_length,
            maximum_program_sha256,
        )
        .unwrap();

        let maximum_section_headers = static_elf_with_section_headers(
            u16::try_from(RETAINED_STATIC_AMD64_ELF_MAX_SECTION_HEADERS_V2).unwrap(),
        );
        let maximum_section_length = u64::try_from(maximum_section_headers.len()).unwrap();
        let maximum_section_sha256: [u8; 32] = Sha256::digest(&maximum_section_headers).into();
        inspect_retained_static_amd64_elf_v2(
            &maximum_section_headers,
            maximum_section_length,
            maximum_section_sha256,
        )
        .unwrap();

        let mut excessive_section_headers = static_elf_with_null_section();
        write_u16(
            &mut excessive_section_headers,
            60,
            u16::try_from(RETAINED_STATIC_AMD64_ELF_MAX_SECTION_HEADERS_V2 + 1).unwrap(),
        );
        assert_policy_rejected(&excessive_section_headers, "extended section numbering");
    }
}

#[cfg(test)]
mod executable_policy_is_non_authorizing_v1 {
    #[test]
    fn production_surface_contains_only_bytes_identity_and_policy() {
        let source = include_str!("executable.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let compact = production.split_whitespace().collect::<String>();

        for required in [
            "pubstructGeneratorExecutableExpectationV2",
            "pubstructWorkerExecutableExpectationV2",
            "pubfninspect_retained_static_amd64_elf_v2(",
            "bytes:&[u8]",
            "expected_byte_length:u64",
            "expected_sha256:[u8;32]",
        ] {
            assert!(
                compact.contains(required),
                "missing closed surface {required}"
            );
        }
        for forbidden in [
            "std::fs",
            "OwnedFd",
            "BorrowedFd",
            "RawFd",
            "Path",
            "Statx",
            "statx",
            "std::process",
            "Command",
            "spawn",
            "execve",
            "release",
            "cursor",
            "Serialize",
            "Deserialize",
            "decode",
            "unsafe",
            "implClone",
            "implCopy",
            "implDefault",
        ] {
            assert!(
                !compact.contains(forbidden),
                "forbidden executable-policy surface {forbidden}"
            );
        }
    }
}
