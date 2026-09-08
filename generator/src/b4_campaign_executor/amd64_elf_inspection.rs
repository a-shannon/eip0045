//! Topology-free inspection of exact borrowed AMD64 ELF bytes.

#![allow(
    dead_code,
    reason = "the physical importer lands before the closed H0 topology consumes it"
)]
#![allow(
    clippy::too_many_lines,
    reason = "the security parser and causal fault matrices stay linear for auditability"
)]

use std::fmt;

use anyhow::{Context as _, Result, ensure};
use elf::{
    abi,
    endian::LittleEndian,
    file::{Class, FileHeader, parse_ident},
    section::{SectionHeader, SectionHeaderTable},
    segment::{ProgramHeader, SegmentTable},
};
use sha2::{Digest as _, Sha256};

use super::artifact_import_contract::{
    Amd64ElfImportLimitsV1, Amd64ElfPolicyV1, B4ImmutableArtifactRoleV1,
    RuntimeAmd64ElfImportLimitsV1, startup_dependency_closure_limits_v1,
};

const ELF64_HEADER_BYTES: usize = 64;
const ELF64_PROGRAM_HEADER_BYTES: u16 = 56;
const ELF64_SECTION_HEADER_BYTES: u16 = 64;
const ELF64_DYNAMIC_ENTRY_BYTES: usize = 16;
const ELF_SHN_LORESERVE: u16 = 0xff00;
const ELF_DT_AUXILIARY: i64 = 0x7fff_fffd;
const ELF_DT_FILTER: i64 = 0x7fff_ffff;

/// Closed ELF type carried by the machine-readable structural projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Amd64ElfTypeV1 {
    Executable,
    SharedObject,
}

/// Closed OS ABI carried by the machine-readable structural projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Amd64ElfOsAbiV1 {
    SystemV,
    Linux,
}

/// Common successful structural projection. Violation counters are zero by
/// construction and are not represented as caller-controlled values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Amd64ElfCommonInspectionV1 {
    elf_type: Amd64ElfTypeV1,
    os_abi: Amd64ElfOsAbiV1,
    program_header_count: u64,
    section_header_count: u64,
    load_segment_count: u64,
    executable_load_segment_count: u64,
    entry_point_is_zero: bool,
    entry_point_in_executable_load: bool,
    interpreter_segment_count: u64,
    dynamic_segment_count: u64,
    gnu_stack_segment_count: u64,
}

impl Amd64ElfCommonInspectionV1 {
    pub(super) const fn elf_type(&self) -> Amd64ElfTypeV1 {
        self.elf_type
    }

    pub(super) const fn os_abi(&self) -> Amd64ElfOsAbiV1 {
        self.os_abi
    }

    pub(super) const fn program_header_count(&self) -> u64 {
        self.program_header_count
    }

    pub(super) const fn section_header_count(&self) -> u64 {
        self.section_header_count
    }

    pub(super) const fn load_segment_count(&self) -> u64 {
        self.load_segment_count
    }

    pub(super) const fn executable_load_segment_count(&self) -> u64 {
        self.executable_load_segment_count
    }

    pub(in crate::b4_campaign_executor) const fn entry_point_is_zero(&self) -> bool {
        self.entry_point_is_zero
    }

    pub(in crate::b4_campaign_executor) const fn entry_point_in_executable_load(&self) -> bool {
        self.entry_point_in_executable_load
    }

    pub(super) const fn interpreter_segment_count(&self) -> u64 {
        self.interpreter_segment_count
    }

    pub(super) const fn dynamic_segment_count(&self) -> u64 {
        self.dynamic_segment_count
    }

    pub(super) const fn gnu_stack_segment_count(&self) -> u64 {
        self.gnu_stack_segment_count
    }
}

/// Closed dynamic-tag identity retained in exact dynamic-array order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::b4_campaign_executor) enum Amd64ElfAcceptedDynamicTagV1 {
    Null,
    Needed,
    PltRelSize,
    PltGot,
    Hash,
    StringTable,
    SymbolTable,
    Rela,
    RelaSize,
    RelaEntrySize,
    StringTableSize,
    SymbolEntrySize,
    Init,
    Fini,
    Soname,
    Rel,
    RelSize,
    RelEntrySize,
    PltRel,
    Debug,
    JumpRel,
    BindNow,
    InitArray,
    FiniArray,
    InitArraySize,
    FiniArraySize,
    Runpath,
    Flags,
    PreinitArray,
    PreinitArraySize,
    SymbolTableSectionIndex,
    GnuHash,
    VersionSymbol,
    RelaCount,
    RelCount,
    Flags1,
    VersionDefinition,
    VersionDefinitionCount,
    VersionNeed,
    VersionNeedCount,
}

/// One exact accepted `Elf64_Dyn` record. The containing slice preserves every
/// raw `(d_tag, d_un)` pair from ordinal zero through the first `DT_NULL`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::b4_campaign_executor) struct Amd64ElfDynamicRecordV1 {
    d_tag: i64,
    d_un: u64,
}

impl Amd64ElfDynamicRecordV1 {
    pub(in crate::b4_campaign_executor) const fn d_tag(self) -> i64 {
        self.d_tag
    }

    pub(in crate::b4_campaign_executor) const fn d_un(self) -> u64 {
        self.d_un
    }
}

/// One validated `DT_NEEDED` edge request in dynamic-array order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::b4_campaign_executor) struct Amd64ElfNeededLibraryV1<'bytes> {
    dynamic_ordinal: u64,
    requested_name: &'bytes str,
}

impl Amd64ElfNeededLibraryV1<'_> {
    pub(in crate::b4_campaign_executor) const fn dynamic_ordinal(&self) -> u64 {
        self.dynamic_ordinal
    }

    pub(in crate::b4_campaign_executor) const fn requested_name(&self) -> &str {
        self.requested_name
    }
}

/// One lexically validated RUNPATH component. Filesystem resolution and the
/// symlink-sensitive `$ORIGIN` rule remain descriptor-rooted consumer work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::b4_campaign_executor) enum Amd64ElfRunpathComponentV1<'bytes> {
    Absolute(&'bytes str),
    OriginRelative {
        raw: &'bytes str,
        suffix: &'bytes str,
    },
}

impl Amd64ElfRunpathComponentV1<'_> {
    pub(in crate::b4_campaign_executor) const fn raw(&self) -> &str {
        match self {
            Self::Absolute(raw) | Self::OriginRelative { raw, .. } => raw,
        }
    }

    pub(in crate::b4_campaign_executor) const fn origin_relative_suffix(&self) -> Option<&str> {
        match self {
            Self::Absolute(_) => None,
            Self::OriginRelative { suffix, .. } => Some(suffix),
        }
    }
}

/// One exact validated `DT_RUNPATH` value and its textual-order components.
#[derive(Debug, Eq, PartialEq)]
pub(in crate::b4_campaign_executor) struct Amd64ElfValidatedRunpathV1<'bytes> {
    raw: &'bytes str,
    components: Vec<Amd64ElfRunpathComponentV1<'bytes>>,
}

impl Amd64ElfValidatedRunpathV1<'_> {
    pub(in crate::b4_campaign_executor) const fn raw(&self) -> &str {
        self.raw
    }

    pub(in crate::b4_campaign_executor) fn components(&self) -> &[Amd64ElfRunpathComponentV1<'_>] {
        &self.components
    }
}

/// Closed dependency-selection projection borrowed from one exact ELF body.
#[derive(Debug, Eq, PartialEq)]
pub(in crate::b4_campaign_executor) struct Amd64ElfStartupDynamicInspectionV1<'bytes> {
    accepted_records: Vec<Amd64ElfDynamicRecordV1>,
    accepted_tags: Vec<Amd64ElfAcceptedDynamicTagV1>,
    needed_libraries: Vec<Amd64ElfNeededLibraryV1<'bytes>>,
    soname: Option<&'bytes str>,
    runpath: Option<Amd64ElfValidatedRunpathV1<'bytes>>,
}

impl Amd64ElfStartupDynamicInspectionV1<'_> {
    pub(in crate::b4_campaign_executor) fn accepted_records(&self) -> &[Amd64ElfDynamicRecordV1] {
        &self.accepted_records
    }

    pub(in crate::b4_campaign_executor) fn accepted_tags(&self) -> &[Amd64ElfAcceptedDynamicTagV1] {
        &self.accepted_tags
    }

    pub(in crate::b4_campaign_executor) fn needed_libraries(
        &self,
    ) -> &[Amd64ElfNeededLibraryV1<'_>] {
        &self.needed_libraries
    }

    pub(in crate::b4_campaign_executor) const fn soname(&self) -> Option<&str> {
        self.soname
    }

    pub(in crate::b4_campaign_executor) const fn runpath(
        &self,
    ) -> Option<&Amd64ElfValidatedRunpathV1<'_>> {
        self.runpath.as_ref()
    }
}

/// Runtime-only fields rederived from the exact borrowed ELF body.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct RuntimeAmd64ElfInspectionV1<'bytes> {
    interpreter_path: &'bytes str,
    dynamic_entry_count: u64,
    needed_library_count: u64,
    startup_dynamic: Amd64ElfStartupDynamicInspectionV1<'bytes>,
}

impl RuntimeAmd64ElfInspectionV1<'_> {
    pub(super) const fn interpreter_path(&self) -> &str {
        self.interpreter_path
    }

    pub(super) const fn dynamic_entry_count(&self) -> u64 {
        self.dynamic_entry_count
    }

    pub(super) const fn needed_library_count(&self) -> u64 {
        self.needed_library_count
    }

    pub(in crate::b4_campaign_executor) const fn startup_dynamic(
        &self,
    ) -> &Amd64ElfStartupDynamicInspectionV1<'_> {
        &self.startup_dynamic
    }
}

/// Inert view over one exact borrowed body and its rederived measurements.
///
/// This is not descriptor custody, a physical slot, or H0 authority. Its byte
/// lifetime remains tied to the caller-owned slice.
pub(super) struct InspectedAmd64ElfV1<'bytes> {
    bytes: &'bytes [u8],
    byte_length: u64,
    sha256: [u8; 32],
    common: Amd64ElfCommonInspectionV1,
    runtime: RuntimeAmd64ElfInspectionV1<'bytes>,
}

impl fmt::Debug for InspectedAmd64ElfV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InspectedAmd64ElfV1")
            .field("byte_length", &self.byte_length)
            .field("sha256", &self.sha256)
            .field("common", &self.common)
            .field("runtime", &self.runtime)
            .finish_non_exhaustive()
    }
}

impl<'bytes> InspectedAmd64ElfV1<'bytes> {
    pub(super) const fn bytes(&self) -> &'bytes [u8] {
        self.bytes
    }

    pub(super) const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    pub(super) const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    pub(super) const fn common(&self) -> &Amd64ElfCommonInspectionV1 {
        &self.common
    }

    pub(super) const fn runtime(&self) -> &RuntimeAmd64ElfInspectionV1<'bytes> {
        &self.runtime
    }
}

/// Inert topology-free projection of one startup dependency DSO.
///
/// The body, descriptor, rootfs path, and any authorization remain with the
/// caller. Borrowed dynamic strings cannot outlive the supplied exact bytes.
#[derive(Debug)]
pub(in crate::b4_campaign_executor) struct StartupDependencyAmd64ElfDsoInspectionV1<'bytes> {
    byte_length: u64,
    sha256: [u8; 32],
    common: Amd64ElfCommonInspectionV1,
    dynamic: Amd64ElfStartupDynamicInspectionV1<'bytes>,
}

impl StartupDependencyAmd64ElfDsoInspectionV1<'_> {
    pub(in crate::b4_campaign_executor) const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    pub(in crate::b4_campaign_executor) const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    pub(in crate::b4_campaign_executor) const fn entry_point_is_zero(&self) -> bool {
        self.common.entry_point_is_zero()
    }

    pub(in crate::b4_campaign_executor) const fn common(&self) -> &Amd64ElfCommonInspectionV1 {
        &self.common
    }

    pub(in crate::b4_campaign_executor) const fn soname(&self) -> &str {
        self.dynamic
            .soname
            .expect("accepted startup DSO construction fixed one SONAME")
    }

    pub(in crate::b4_campaign_executor) const fn dynamic(
        &self,
    ) -> &Amd64ElfStartupDynamicInspectionV1<'_> {
        &self.dynamic
    }
}

struct CommonElfAnalysis {
    common: Amd64ElfCommonInspectionV1,
    program_headers: Vec<ProgramHeader>,
    interpreter: Option<ProgramHeader>,
    dynamic: Option<ProgramHeader>,
}

/// Inspect one exact borrowed ELF body under the closed runtime policy.
fn inspect_runtime_amd64_elf(bytes: &[u8]) -> Result<InspectedAmd64ElfV1<'_>> {
    let role_limits = B4ImmutableArtifactRoleV1::Amd64Elf(Amd64ElfPolicyV1::Runtime).limits();
    let byte_length = u64::try_from(bytes.len()).context("AMD64 ELF length does not fit u64")?;
    role_limits.validate_encoded_length(byte_length, "AMD64 ELF")?;
    let work_limits = role_limits.require_amd64_elf("AMD64 ELF")?;
    let header = parse_closed_elf64_header(bytes)?;
    let analysis = inspect_common_structure(bytes, &header, work_limits)?;
    ensure!(
        analysis.common.entry_point_in_executable_load,
        "AMD64 ELF entry point is not in an executable PT_LOAD"
    );
    let runtime = inspect_runtime_linkage(
        bytes,
        &analysis,
        work_limits.require_runtime_linkage("runtime AMD64 ELF")?,
    )?;
    Ok(InspectedAmd64ElfV1 {
        bytes,
        byte_length,
        sha256: Sha256::digest(bytes).into(),
        common: analysis.common,
        runtime,
    })
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

    let ident =
        parse_ident::<LittleEndian>(&bytes[..16]).context("cannot parse AMD64 ELF ident")?;
    ensure!(ident.1 == Class::ELF64, "AMD64 ELF is not ELF64");
    let header = FileHeader::parse_tail(ident, &bytes[16..ELF64_HEADER_BYTES])
        .context("cannot parse AMD64 ELF header")?;
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

fn inspect_common_structure(
    bytes: &[u8],
    header: &FileHeader<LittleEndian>,
    limits: Amd64ElfImportLimitsV1,
) -> Result<CommonElfAnalysis> {
    let program_header_count = u64::from(header.e_phnum);
    limits.validate_program_header_count(program_header_count, "AMD64 ELF")?;
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

    let section_headers = parse_and_validate_section_headers(bytes, header, limits)?;
    let mut load_segment_count = 0_u64;
    let mut executable_load_segment_count = 0_u64;
    let mut readable_load_exists = false;
    let mut entry_point_in_executable_load = false;
    let mut load_file_ranges = Vec::<(u64, u64)>::new();
    load_file_ranges
        .try_reserve_exact(program_headers.len())
        .context("cannot retain bounded AMD64 PT_LOAD ranges")?;
    let mut interpreter = None;
    let mut dynamic = None;
    let mut gnu_stack_segment_count = 0_u64;

    for segment in &program_headers {
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
                    executable_load_segment_count += 1;
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
        common: Amd64ElfCommonInspectionV1 {
            elf_type: match header.e_type {
                abi::ET_EXEC => Amd64ElfTypeV1::Executable,
                abi::ET_DYN => Amd64ElfTypeV1::SharedObject,
                _ => unreachable!("closed header validation fixed the ELF type"),
            },
            os_abi: match header.osabi {
                abi::ELFOSABI_SYSV => Amd64ElfOsAbiV1::SystemV,
                abi::ELFOSABI_LINUX => Amd64ElfOsAbiV1::Linux,
                _ => unreachable!("closed header validation fixed the OS ABI"),
            },
            program_header_count,
            section_header_count: u64::try_from(section_headers.len())?,
            load_segment_count,
            executable_load_segment_count,
            entry_point_is_zero: header.e_entry == 0,
            entry_point_in_executable_load,
            interpreter_segment_count: u64::from(interpreter.is_some()),
            dynamic_segment_count: u64::from(dynamic.is_some()),
            gnu_stack_segment_count,
        },
        program_headers,
        interpreter,
        dynamic,
    })
}

fn parse_and_validate_section_headers(
    bytes: &[u8],
    header: &FileHeader<LittleEndian>,
    limits: Amd64ElfImportLimitsV1,
) -> Result<Vec<SectionHeader>> {
    if header.e_shoff == 0 {
        ensure!(
            (header.e_shentsize, header.e_shnum, header.e_shstrndx) == (0, 0, 0),
            "absent AMD64 ELF section table does not use the exact zero tuple"
        );
        return Ok(Vec::new());
    }
    ensure!(
        header.e_shnum != 0
            && header.e_shnum < ELF_SHN_LORESERVE
            && header.e_shstrndx != abi::SHN_XINDEX,
        "AMD64 ELF extended section numbering is rejected"
    );
    let section_header_count = u64::from(header.e_shnum);
    limits.validate_section_header_count(section_header_count, "AMD64 ELF")?;
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

    for section in &sections {
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
        for section in &sections {
            ensure!(
                usize::try_from(section.sh_name)
                    .ok()
                    .is_some_and(|offset| offset < string_table.len()),
                "AMD64 ELF section name offset is outside the selected string table"
            );
        }
    }
    Ok(sections)
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

fn inspect_runtime_linkage<'bytes>(
    bytes: &'bytes [u8],
    analysis: &CommonElfAnalysis,
    limits: RuntimeAmd64ElfImportLimitsV1,
) -> Result<RuntimeAmd64ElfInspectionV1<'bytes>> {
    let interpreter = analysis
        .interpreter
        .context("runtime ELF does not contain exactly one interpreter segment")?;
    analysis
        .dynamic
        .context("runtime ELF does not contain exactly one dynamic segment")?;
    let interpreter_bytes = checked_file_range(
        bytes,
        interpreter.p_offset,
        interpreter.p_filesz,
        "runtime interpreter payload",
    )?;
    ensure!(
        (2..=241).contains(&interpreter_bytes.len())
            && interpreter_bytes.last() == Some(&0)
            && !interpreter_bytes[..interpreter_bytes.len() - 1].contains(&0),
        "runtime ELF interpreter path is not one exact NUL-terminated payload"
    );
    let interpreter_path = std::str::from_utf8(&interpreter_bytes[..interpreter_bytes.len() - 1])
        .context("runtime ELF interpreter path is not ASCII")?;
    validate_interpreter_path(interpreter_path)?;

    let startup_dynamic = inspect_startup_dynamic_linkage(bytes, analysis, limits)?;
    ensure!(
        startup_dynamic.soname().is_none(),
        "runtime executable carries a rejected DT_SONAME"
    );
    let dynamic_entry_count = u64::try_from(startup_dynamic.accepted_records().len())?;
    let needed_library_count = u64::try_from(startup_dynamic.needed_libraries().len())?;
    Ok(RuntimeAmd64ElfInspectionV1 {
        interpreter_path,
        dynamic_entry_count,
        needed_library_count,
        startup_dynamic,
    })
}

fn inspect_startup_dynamic_linkage<'bytes>(
    bytes: &'bytes [u8],
    analysis: &CommonElfAnalysis,
    limits: RuntimeAmd64ElfImportLimitsV1,
) -> Result<Amd64ElfStartupDynamicInspectionV1<'bytes>> {
    let dynamic_bytes = checked_file_range(
        bytes,
        analysis
            .dynamic
            .context("dynamic startup ELF does not contain exactly one dynamic segment")?
            .p_offset,
        analysis
            .dynamic
            .expect("dynamic segment was fixed above")
            .p_filesz,
        "runtime dynamic array",
    )?;
    ensure!(
        !dynamic_bytes.is_empty() && dynamic_bytes.len() % ELF64_DYNAMIC_ENTRY_BYTES == 0,
        "runtime ELF dynamic array is not composed of complete 16-byte entries"
    );
    let parsed = parse_startup_dynamic_records(dynamic_bytes, limits)?;
    let string_table = resolve_startup_dynamic_string_table(bytes, analysis, &parsed)?;
    let needed_libraries = resolve_needed_libraries(parsed.needed_offsets, string_table)?;
    let soname = parsed
        .soname_offset
        .map(|(_, offset)| {
            let soname = dynamic_string_at(
                string_table.expect("DT_SONAME fixed one dynamic string table"),
                offset,
                "DT_SONAME",
            )?;
            validate_dynamic_basename(soname, "startup ELF DT_SONAME")?;
            Ok::<&str, anyhow::Error>(soname)
        })
        .transpose()?;
    let runpath = parsed
        .runpath_offset
        .map(|(_, offset)| {
            let runpath = dynamic_string_at(
                string_table.expect("DT_RUNPATH fixed one dynamic string table"),
                offset,
                "DT_RUNPATH",
            )?;
            validate_runpath(runpath, startup_dependency_closure_limits_v1())
        })
        .transpose()?;

    Ok(Amd64ElfStartupDynamicInspectionV1 {
        accepted_records: parsed.accepted_records,
        accepted_tags: parsed.accepted_tags,
        needed_libraries,
        soname,
        runpath,
    })
}

struct ParsedStartupDynamicRecordsV1 {
    accepted_records: Vec<Amd64ElfDynamicRecordV1>,
    accepted_tags: Vec<Amd64ElfAcceptedDynamicTagV1>,
    needed_offsets: Vec<(u64, u64)>,
    soname_offset: Option<(u64, u64)>,
    runpath_offset: Option<(u64, u64)>,
    string_table_address: Option<u64>,
    string_table_size: Option<u64>,
    needed_library_count: u64,
}

fn parse_startup_dynamic_records(
    dynamic_bytes: &[u8],
    limits: RuntimeAmd64ElfImportLimitsV1,
) -> Result<ParsedStartupDynamicRecordsV1> {
    let maximum_entries = usize::try_from(limits.maximum_dynamic_entries())?;
    let declared_entries = dynamic_bytes.len() / ELF64_DYNAMIC_ENTRY_BYTES;
    let mut parsed = ParsedStartupDynamicRecordsV1 {
        accepted_records: Vec::new(),
        accepted_tags: Vec::new(),
        needed_offsets: Vec::new(),
        soname_offset: None,
        runpath_offset: None,
        string_table_address: None,
        string_table_size: None,
        needed_library_count: 0,
    };
    parsed
        .needed_offsets
        .try_reserve(declared_entries.min(maximum_entries))
        .context("cannot retain bounded AMD64 DT_NEEDED offsets")?;
    parsed
        .accepted_records
        .try_reserve(declared_entries.min(maximum_entries))
        .context("cannot retain bounded AMD64 dynamic records")?;
    parsed
        .accepted_tags
        .try_reserve(declared_entries.min(maximum_entries))
        .context("cannot retain bounded AMD64 dynamic tags")?;
    let mut found_null = false;

    for index in 0..declared_entries.min(maximum_entries) {
        let offset = index * ELF64_DYNAMIC_ENTRY_BYTES;
        let tag = i64::from_le_bytes(dynamic_bytes[offset..offset + 8].try_into()?);
        let value = u64::from_le_bytes(dynamic_bytes[offset + 8..offset + 16].try_into()?);
        let dynamic_ordinal = u64::try_from(index)?;
        let accepted_tag = classify_startup_dynamic_tag(tag)?;
        if retain_startup_dynamic_record(
            &mut parsed,
            tag,
            value,
            dynamic_ordinal,
            accepted_tag,
            limits,
        )? {
            found_null = true;
            break;
        }
    }
    ensure!(
        found_null,
        "runtime ELF dynamic array has no bounded DT_NULL"
    );
    let dynamic_entry_count = u64::try_from(parsed.accepted_records.len())?;
    limits.validate_dynamic_entry_count(dynamic_entry_count, "runtime ELF")?;
    Ok(parsed)
}

fn retain_startup_dynamic_record(
    parsed: &mut ParsedStartupDynamicRecordsV1,
    tag: i64,
    value: u64,
    dynamic_ordinal: u64,
    accepted_tag: Amd64ElfAcceptedDynamicTagV1,
    limits: RuntimeAmd64ElfImportLimitsV1,
) -> Result<bool> {
    validate_startup_dynamic_flags(tag, value)?;
    parsed.accepted_records.push(Amd64ElfDynamicRecordV1 {
        d_tag: tag,
        d_un: value,
    });
    parsed.accepted_tags.push(accepted_tag);
    match tag {
        abi::DT_NULL => return Ok(true),
        abi::DT_STRTAB => ensure!(
            parsed.string_table_address.replace(value).is_none(),
            "runtime ELF dynamic array repeats DT_STRTAB"
        ),
        abi::DT_STRSZ => ensure!(
            parsed.string_table_size.replace(value).is_none(),
            "runtime ELF dynamic array repeats DT_STRSZ"
        ),
        abi::DT_NEEDED => {
            parsed.needed_library_count = parsed
                .needed_library_count
                .checked_add(1)
                .context("runtime ELF DT_NEEDED count overflowed")?;
            limits.validate_needed_library_count(parsed.needed_library_count, "runtime ELF")?;
            parsed.needed_offsets.push((dynamic_ordinal, value));
        }
        abi::DT_SONAME => ensure!(
            parsed
                .soname_offset
                .replace((dynamic_ordinal, value))
                .is_none(),
            "startup ELF dynamic array repeats DT_SONAME"
        ),
        abi::DT_RUNPATH => ensure!(
            parsed
                .runpath_offset
                .replace((dynamic_ordinal, value))
                .is_none(),
            "startup ELF dynamic array repeats DT_RUNPATH"
        ),
        _ => {}
    }
    Ok(false)
}

fn validate_startup_dynamic_flags(tag: i64, value: u64) -> Result<()> {
    match tag {
        abi::DT_FLAGS => ensure!(
            value & !allowed_dt_flags_mask() == 0,
            "startup ELF DT_FLAGS contains a rejected flag bit"
        ),
        abi::DT_FLAGS_1 => ensure!(
            value & !allowed_dt_flags_1_mask() == 0,
            "startup ELF DT_FLAGS_1 contains a rejected flag bit"
        ),
        _ => {}
    }
    Ok(())
}

fn resolve_startup_dynamic_string_table<'bytes>(
    bytes: &'bytes [u8],
    analysis: &CommonElfAnalysis,
    parsed: &ParsedStartupDynamicRecordsV1,
) -> Result<Option<&'bytes [u8]>> {
    let has_dynamic_strings = !parsed.needed_offsets.is_empty()
        || parsed.soname_offset.is_some()
        || parsed.runpath_offset.is_some();
    let string_table = if has_dynamic_strings {
        let address = parsed
            .string_table_address
            .context("runtime ELF dynamic strings are referenced without one DT_STRTAB")?;
        let size = parsed
            .string_table_size
            .context("runtime ELF dynamic strings are referenced without one DT_STRSZ")?;
        Some(map_virtual_file_range(
            bytes,
            &analysis.program_headers,
            address,
            size,
            "runtime dynamic string table",
        )?)
    } else {
        None
    };
    if let Some(string_table) = string_table {
        string_table
            .iter()
            .rposition(|byte| *byte == 0)
            .context("runtime ELF dynamic string table contains no NUL terminator")?;
    }
    Ok(string_table)
}

fn resolve_needed_libraries(
    needed_offsets: Vec<(u64, u64)>,
    string_table: Option<&[u8]>,
) -> Result<Vec<Amd64ElfNeededLibraryV1<'_>>> {
    let mut needed_libraries = Vec::new();
    needed_libraries
        .try_reserve_exact(needed_offsets.len())
        .context("cannot retain bounded AMD64 DT_NEEDED strings")?;
    let mut sorted_needed = Vec::new();
    sorted_needed
        .try_reserve_exact(needed_offsets.len())
        .context("cannot retain bounded AMD64 DT_NEEDED uniqueness index")?;
    for (dynamic_ordinal, string_offset) in needed_offsets {
        let requested_name = dynamic_string_at(
            string_table.expect("DT_NEEDED fixed one dynamic string table"),
            string_offset,
            "DT_NEEDED",
        )?;
        validate_dynamic_basename(requested_name, "startup ELF DT_NEEDED")?;
        sorted_needed.push(requested_name);
        needed_libraries.push(Amd64ElfNeededLibraryV1 {
            dynamic_ordinal,
            requested_name,
        });
    }
    sorted_needed.sort_unstable();
    ensure!(
        sorted_needed.windows(2).all(|pair| pair[0] != pair[1]),
        "startup ELF repeats a DT_NEEDED basename"
    );
    Ok(needed_libraries)
}

fn classify_startup_dynamic_tag(tag: i64) -> Result<Amd64ElfAcceptedDynamicTagV1> {
    let accepted = match tag {
        abi::DT_NULL => Amd64ElfAcceptedDynamicTagV1::Null,
        abi::DT_NEEDED => Amd64ElfAcceptedDynamicTagV1::Needed,
        abi::DT_PLTRELSZ => Amd64ElfAcceptedDynamicTagV1::PltRelSize,
        abi::DT_PLTGOT => Amd64ElfAcceptedDynamicTagV1::PltGot,
        abi::DT_HASH => Amd64ElfAcceptedDynamicTagV1::Hash,
        abi::DT_STRTAB => Amd64ElfAcceptedDynamicTagV1::StringTable,
        abi::DT_SYMTAB => Amd64ElfAcceptedDynamicTagV1::SymbolTable,
        abi::DT_RELA => Amd64ElfAcceptedDynamicTagV1::Rela,
        abi::DT_RELASZ => Amd64ElfAcceptedDynamicTagV1::RelaSize,
        abi::DT_RELAENT => Amd64ElfAcceptedDynamicTagV1::RelaEntrySize,
        abi::DT_STRSZ => Amd64ElfAcceptedDynamicTagV1::StringTableSize,
        abi::DT_SYMENT => Amd64ElfAcceptedDynamicTagV1::SymbolEntrySize,
        abi::DT_INIT => Amd64ElfAcceptedDynamicTagV1::Init,
        abi::DT_FINI => Amd64ElfAcceptedDynamicTagV1::Fini,
        abi::DT_SONAME => Amd64ElfAcceptedDynamicTagV1::Soname,
        abi::DT_REL => Amd64ElfAcceptedDynamicTagV1::Rel,
        abi::DT_RELSZ => Amd64ElfAcceptedDynamicTagV1::RelSize,
        abi::DT_RELENT => Amd64ElfAcceptedDynamicTagV1::RelEntrySize,
        abi::DT_PLTREL => Amd64ElfAcceptedDynamicTagV1::PltRel,
        abi::DT_DEBUG => Amd64ElfAcceptedDynamicTagV1::Debug,
        abi::DT_JMPREL => Amd64ElfAcceptedDynamicTagV1::JumpRel,
        abi::DT_BIND_NOW => Amd64ElfAcceptedDynamicTagV1::BindNow,
        abi::DT_INIT_ARRAY => Amd64ElfAcceptedDynamicTagV1::InitArray,
        abi::DT_FINI_ARRAY => Amd64ElfAcceptedDynamicTagV1::FiniArray,
        abi::DT_INIT_ARRAYSZ => Amd64ElfAcceptedDynamicTagV1::InitArraySize,
        abi::DT_FINI_ARRAYSZ => Amd64ElfAcceptedDynamicTagV1::FiniArraySize,
        abi::DT_RUNPATH => Amd64ElfAcceptedDynamicTagV1::Runpath,
        abi::DT_FLAGS => Amd64ElfAcceptedDynamicTagV1::Flags,
        abi::DT_PREINIT_ARRAY => Amd64ElfAcceptedDynamicTagV1::PreinitArray,
        abi::DT_PREINIT_ARRAYSZ => Amd64ElfAcceptedDynamicTagV1::PreinitArraySize,
        abi::DT_SYMTAB_SHNDX => Amd64ElfAcceptedDynamicTagV1::SymbolTableSectionIndex,
        abi::DT_GNU_HASH => Amd64ElfAcceptedDynamicTagV1::GnuHash,
        abi::DT_VERSYM => Amd64ElfAcceptedDynamicTagV1::VersionSymbol,
        abi::DT_RELACOUNT => Amd64ElfAcceptedDynamicTagV1::RelaCount,
        abi::DT_RELCOUNT => Amd64ElfAcceptedDynamicTagV1::RelCount,
        abi::DT_FLAGS_1 => Amd64ElfAcceptedDynamicTagV1::Flags1,
        abi::DT_VERDEF => Amd64ElfAcceptedDynamicTagV1::VersionDefinition,
        abi::DT_VERDEFNUM => Amd64ElfAcceptedDynamicTagV1::VersionDefinitionCount,
        abi::DT_VERNEED => Amd64ElfAcceptedDynamicTagV1::VersionNeed,
        abi::DT_VERNEEDNUM => Amd64ElfAcceptedDynamicTagV1::VersionNeedCount,
        abi::DT_CONFIG | abi::DT_DEPAUDIT | abi::DT_AUDIT | ELF_DT_AUXILIARY | ELF_DT_FILTER => {
            anyhow::bail!("runtime ELF contains a rejected dynamic loader tag {tag:#x}")
        }
        abi::DT_RPATH => anyhow::bail!("startup ELF contains rejected DT_RPATH"),
        _ => anyhow::bail!("startup ELF contains unlisted dynamic tag {tag:#x}"),
    };
    Ok(accepted)
}

const fn allowed_dt_flags_mask() -> u64 {
    (abi::DF_BIND_NOW | abi::DF_ORIGIN | abi::DF_STATIC_TLS) as u64
}

const fn allowed_dt_flags_1_mask() -> u64 {
    (abi::DF_1_NOW
        | abi::DF_1_NODELETE
        | abi::DF_1_INITFIRST
        | abi::DF_1_NOOPEN
        | abi::DF_1_ORIGIN
        | abi::DF_1_NODUMP
        | abi::DF_1_PIE) as u64
}

fn dynamic_string_at<'bytes>(
    string_table: &'bytes [u8],
    offset: u64,
    label: &str,
) -> Result<&'bytes str> {
    let offset = usize::try_from(offset)
        .with_context(|| format!("startup ELF {label} string offset does not fit memory"))?;
    let tail = string_table
        .get(offset..)
        .with_context(|| format!("startup ELF {label} string offset is outside DT_STRSZ"))?;
    let length = tail
        .iter()
        .position(|byte| *byte == 0)
        .with_context(|| format!("startup ELF {label} string is not NUL-terminated"))?;
    std::str::from_utf8(&tail[..length])
        .with_context(|| format!("startup ELF {label} string is not ASCII"))
}

fn validate_dynamic_basename(value: &str, label: &str) -> Result<()> {
    let limits = startup_dependency_closure_limits_v1();
    limits.validate_dynamic_basename_bytes(u64::try_from(value.len())?, label)?;
    ensure!(
        value
            .bytes()
            .all(|byte| (0x20..=0x7e).contains(&byte) && !matches!(byte, b'/' | b'\\')),
        "{label} is not one printable-ASCII basename"
    );
    Ok(())
}

fn validate_runpath(
    raw: &str,
    limits: super::artifact_import_contract::StartupDependencyClosureLimitsV1,
) -> Result<Amd64ElfValidatedRunpathV1<'_>> {
    ensure!(
        raw.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
            && !raw.contains(';')
            && !raw.contains('\\'),
        "startup ELF DT_RUNPATH is not closed printable ASCII"
    );
    let component_count = u64::try_from(raw.split(':').count())?;
    limits.validate_runpath_component_count(component_count, "startup ELF DT_RUNPATH")?;
    let mut components = Vec::new();
    components
        .try_reserve_exact(usize::try_from(component_count)?)
        .context("cannot retain bounded DT_RUNPATH components")?;
    for component in raw.split(':') {
        limits.validate_runpath_component_bytes(
            u64::try_from(component.len())?,
            "startup ELF DT_RUNPATH",
        )?;
        if component.starts_with('/') {
            validate_absolute_runpath_component(component)?;
            components.push(Amd64ElfRunpathComponentV1::Absolute(component));
            continue;
        }
        let suffix = component
            .strip_prefix("$ORIGIN")
            .or_else(|| component.strip_prefix("${ORIGIN}"))
            .context("startup ELF DT_RUNPATH component has an unrecognized form")?;
        ensure!(
            suffix.is_empty() || suffix.starts_with('/'),
            "startup ELF DT_RUNPATH embeds its ORIGIN token"
        );
        ensure!(
            !suffix.contains('$'),
            "startup ELF DT_RUNPATH repeats or combines an expansion token"
        );
        if let Some(path) = suffix.strip_prefix('/') {
            for segment in path.split('/') {
                ensure!(
                    !segment.is_empty()
                        && segment != "."
                        && segment.bytes().all(|byte| {
                            (0x20..=0x7e).contains(&byte) && !matches!(byte, b'/' | b'\\' | b'$')
                        }),
                    "startup ELF DT_RUNPATH ORIGIN suffix is noncanonical"
                );
            }
        }
        components.push(Amd64ElfRunpathComponentV1::OriginRelative {
            raw: component,
            suffix,
        });
    }
    Ok(Amd64ElfValidatedRunpathV1 { raw, components })
}

fn validate_absolute_runpath_component(component: &str) -> Result<()> {
    ensure!(
        !component.contains('$'),
        "startup ELF DT_RUNPATH absolute component contains an expansion token"
    );
    for segment in component[1..].split('/') {
        ensure!(
            !segment.is_empty()
                && !matches!(segment, "." | "..")
                && segment
                    .bytes()
                    .all(|byte| (0x20..=0x7e).contains(&byte) && byte != b'/'),
            "startup ELF DT_RUNPATH absolute component is noncanonical"
        );
    }
    Ok(())
}

fn inspect_startup_dependency_amd64_dso(
    bytes: &[u8],
) -> Result<StartupDependencyAmd64ElfDsoInspectionV1<'_>> {
    let role_limits = B4ImmutableArtifactRoleV1::Amd64Elf(Amd64ElfPolicyV1::Runtime).limits();
    let byte_length = u64::try_from(bytes.len()).context("startup DSO length does not fit u64")?;
    role_limits.validate_encoded_length(byte_length, "startup DSO")?;
    let work_limits = role_limits.require_amd64_elf("startup DSO")?;
    let header = parse_closed_elf64_header(bytes)?;
    ensure!(header.e_type == abi::ET_DYN, "startup DSO is not ET_DYN");
    let analysis = inspect_common_structure(bytes, &header, work_limits)?;
    ensure!(
        analysis.interpreter.is_none() && analysis.dynamic.is_some(),
        "startup DSO must omit PT_INTERP and contain exactly one PT_DYNAMIC"
    );
    ensure!(
        header.e_entry == 0 || analysis.common.entry_point_in_executable_load,
        "startup DSO nonzero entry point is not in an executable PT_LOAD"
    );
    let dynamic = inspect_startup_dynamic_linkage(
        bytes,
        &analysis,
        work_limits.require_runtime_linkage("startup DSO")?,
    )?;
    ensure!(
        dynamic.soname().is_some(),
        "startup DSO does not contain exactly one DT_SONAME"
    );
    Ok(StartupDependencyAmd64ElfDsoInspectionV1 {
        byte_length,
        sha256: Sha256::digest(bytes).into(),
        common: analysis.common,
        dynamic,
    })
}

fn validate_interpreter_path(path: &str) -> Result<()> {
    ensure!(
        (2..=240).contains(&path.len()) && path.starts_with('/'),
        "runtime ELF interpreter path is not canonical absolute ASCII"
    );
    for component in path[1..].split('/') {
        ensure!(
            !component.is_empty()
                && !matches!(component, "." | "..")
                && component
                    .bytes()
                    .all(|byte| (0x20..=0x7e).contains(&byte) && byte != b'/'),
            "runtime ELF interpreter path contains a noncanonical component"
        );
    }
    Ok(())
}

fn map_virtual_file_range<'bytes>(
    bytes: &'bytes [u8],
    program_headers: &[ProgramHeader],
    virtual_address: u64,
    byte_length: u64,
    label: &str,
) -> Result<&'bytes [u8]> {
    let virtual_end = virtual_address
        .checked_add(byte_length)
        .with_context(|| format!("{label} virtual range overflowed"))?;
    let mut mapped_file_offset = None;
    for load in program_headers
        .iter()
        .filter(|segment| segment.p_type == abi::PT_LOAD)
    {
        let load_file_virtual_end = load
            .p_vaddr
            .checked_add(load.p_filesz)
            .with_context(|| format!("{label} PT_LOAD virtual range overflowed"))?;
        if load.p_vaddr <= virtual_address && virtual_end <= load_file_virtual_end {
            let relative = virtual_address - load.p_vaddr;
            let file_offset = load
                .p_offset
                .checked_add(relative)
                .with_context(|| format!("{label} file offset overflowed"))?;
            ensure!(
                mapped_file_offset.replace(file_offset).is_none(),
                "{label} maps through more than one file-backed PT_LOAD"
            );
        }
    }
    checked_file_range(
        bytes,
        mapped_file_offset.context(format!(
            "{label} does not map through exactly one file-backed PT_LOAD"
        ))?,
        byte_length,
        label,
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

#[path = "amd64_elf_import.rs"]
mod physical_import;
pub(super) use physical_import::Amd64ElfCustodyPermitV1;
#[allow(
    unused_imports,
    reason = "the physical importer lands before the closed H0 topology consumes it"
)]
pub(super) use physical_import::with_imported_amd64_elf;
#[allow(
    unused_imports,
    reason = "the closed H0 topology will derive AMD64 slots and consume imported views"
)]
pub(super) use physical_import::{
    Amd64ElfSlotV1, ImportedAmd64ElfLinkageV1, ImportedAmd64ElfViewV1,
    ImportedRuntimeAmd64ElfInspectionV1,
};
/// Reinspect exact rootfs bytes and compare the complete runtime-ELF
/// projection with the opaque positive-gate identity before lending the inert
/// common, interpreter, and startup-dynamic projections to the rootfs resolver.
pub(in crate::b4_campaign_executor) fn with_gate_bound_runtime_amd64_elf(
    bytes: &[u8],
    expected: &eip_0045_reproduction::b4_positive_gate::B4PositiveRuntimeElfIdentityV1,
    effect: impl FnOnce(
        &str,
        &Amd64ElfCommonInspectionV1,
        &Amd64ElfStartupDynamicInspectionV1<'_>,
    ) -> Result<()>,
) -> Result<()> {
    let inspected = inspect_runtime_amd64_elf(bytes)?;
    let common = inspected.common();
    let expected_elf_type = match common.elf_type() {
        Amd64ElfTypeV1::Executable => "et-exec",
        Amd64ElfTypeV1::SharedObject => "et-dyn",
    };
    let expected_os_abi = match common.os_abi() {
        Amd64ElfOsAbiV1::SystemV => "sysv",
        Amd64ElfOsAbiV1::Linux => "linux",
    };
    let runtime = inspected.runtime();
    ensure!(
        inspected.byte_length() == expected.byte_length()
            && inspected.sha256() == expected.sha256()
            && expected_elf_type == expected.elf_type()
            && expected_os_abi == expected.os_abi()
            && common.program_header_count() == expected.program_header_count()
            && common.section_header_count() == expected.section_header_count()
            && common.load_segment_count() == expected.load_segment_count()
            && common.executable_load_segment_count() == expected.executable_load_segment_count()
            && common.interpreter_segment_count() == 1
            && common.dynamic_segment_count() == 1
            && runtime.interpreter_path() == expected.interpreter_path()
            && runtime.dynamic_entry_count() == expected.dynamic_entry_count()
            && runtime.needed_library_count() == expected.needed_library_count()
            && common.gnu_stack_segment_count() == expected.gnu_stack_segment_count(),
        "measured rootfs runtime ELF projection differs from its positive gate"
    );
    effect(
        runtime.interpreter_path(),
        common,
        runtime.startup_dynamic(),
    )
}

/// Inspect one exact borrowed startup DSO and lend only its inert projection.
/// Descriptor-rooted selection, SONAME matching, custody, and graph authority
/// remain with the caller.
pub(in crate::b4_campaign_executor) fn with_inspected_startup_dependency_amd64_dso(
    bytes: &[u8],
    effect: impl FnOnce(&StartupDependencyAmd64ElfDsoInspectionV1<'_>) -> Result<()>,
) -> Result<()> {
    let inspected = inspect_startup_dependency_amd64_dso(bytes)?;
    effect(&inspected)
}

#[cfg(test)]
pub(in crate::b4_campaign_executor) fn with_test_inspected_runtime_amd64_elf(
    bytes: &[u8],
    effect: impl FnOnce(
        &str,
        &Amd64ElfCommonInspectionV1,
        &Amd64ElfStartupDynamicInspectionV1<'_>,
    ) -> Result<()>,
) -> Result<()> {
    let inspected = inspect_runtime_amd64_elf(bytes)?;
    let runtime = inspected.runtime();
    effect(
        runtime.interpreter_path(),
        inspected.common(),
        runtime.startup_dynamic(),
    )
}

#[cfg(test)]
pub(in crate::b4_campaign_executor) mod tests {
    use elf::abi;
    use sha2::{Digest as _, Sha256};

    use super::{
        Amd64ElfAcceptedDynamicTagV1, Amd64ElfRunpathComponentV1, Amd64ElfTypeV1, ELF_DT_AUXILIARY,
        ELF_DT_FILTER, inspect_runtime_amd64_elf, inspect_startup_dependency_amd64_dso,
    };

    const ELF_HEADER_BYTES: usize = 64;
    const PROGRAM_HEADER_BYTES: usize = 56;
    const LOAD_VIRTUAL_ADDRESS: u64 = 0x0040_0000;
    // Independent System V / GNU ABI oracle. Keep these literal values separate
    // from the production masks so an accidental bit addition or removal is
    // observable here.
    const NORMATIVE_DT_FLAGS_BITS: [(&str, u64); 3] = [
        ("DF_ORIGIN", 0x0000_0001),
        ("DF_BIND_NOW", 0x0000_0008),
        ("DF_STATIC_TLS", 0x0000_0010),
    ];
    const NORMATIVE_DT_FLAGS_MASK: u64 = 0x0000_0019;
    const NORMATIVE_DT_FLAGS_1_BITS: [(&str, u64); 7] = [
        ("DF_1_NOW", 0x0000_0001),
        ("DF_1_NODELETE", 0x0000_0008),
        ("DF_1_INITFIRST", 0x0000_0020),
        ("DF_1_NOOPEN", 0x0000_0040),
        ("DF_1_ORIGIN", 0x0000_0080),
        ("DF_1_NODUMP", 0x0000_1000),
        ("DF_1_PIE", 0x0800_0000),
    ];
    const NORMATIVE_DT_FLAGS_1_MASK: u64 = 0x0800_10e9;

    #[test]
    fn gate_bound_runtime_comparison_consumes_every_elf_getter_once() {
        let source = include_str!("amd64_elf_inspection.rs").replace("\r\n", "\n");
        let (_, tail) = source
            .split_once("pub(in crate::b4_campaign_executor) fn with_gate_bound_runtime_amd64_elf(")
            .expect("gate-bound runtime comparator");
        let (comparison, _) = tail
            .split_once(
                "\n#[cfg(test)]\npub(in crate::b4_campaign_executor) fn with_test_inspected_runtime_amd64_elf(",
            )
            .expect("gate-bound runtime comparator end sentinel");
        for getter in [
            "byte_length",
            "sha256",
            "elf_type",
            "os_abi",
            "program_header_count",
            "section_header_count",
            "load_segment_count",
            "executable_load_segment_count",
            "interpreter_path",
            "dynamic_entry_count",
            "needed_library_count",
            "gnu_stack_segment_count",
        ] {
            assert_eq!(
                comparison.matches(&format!("expected.{getter}()")).count(),
                1,
                "positive-gate runtime ELF getter must be consumed exactly once: {getter}"
            );
        }
        for invariant in [
            "common.interpreter_segment_count() == 1",
            "common.dynamic_segment_count() == 1",
        ] {
            assert_eq!(
                comparison.matches(invariant).count(),
                1,
                "fixed runtime parser invariant must be checked exactly once: {invariant}"
            );
        }
    }

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

    fn base_elf(program_header_count: u16, elf_type: u16) -> Vec<u8> {
        let mut bytes =
            vec![0_u8; ELF_HEADER_BYTES + usize::from(program_header_count) * PROGRAM_HEADER_BYTES];
        bytes[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        write_u16(&mut bytes, 16, elf_type);
        write_u16(&mut bytes, 18, 62);
        write_u32(&mut bytes, 20, 1);
        write_u64(&mut bytes, 24, LOAD_VIRTUAL_ADDRESS + 64);
        write_u64(&mut bytes, 32, ELF_HEADER_BYTES as u64);
        write_u64(&mut bytes, 40, 0);
        write_u32(&mut bytes, 48, 0);
        write_u16(
            &mut bytes,
            52,
            u16::try_from(ELF_HEADER_BYTES).expect("fixed ELF header size fits u16"),
        );
        write_u16(
            &mut bytes,
            54,
            u16::try_from(PROGRAM_HEADER_BYTES).expect("fixed program-header size fits u16"),
        );
        write_u16(&mut bytes, 56, program_header_count);
        write_u16(&mut bytes, 58, 0);
        write_u16(&mut bytes, 60, 0);
        write_u16(&mut bytes, 62, 0);
        bytes
    }

    #[allow(clippy::too_many_arguments)]
    fn set_program_header(
        bytes: &mut [u8],
        index: usize,
        segment_type: u32,
        flags: u32,
        file_offset: u64,
        virtual_address: u64,
        file_size: u64,
        memory_size: u64,
        alignment: u64,
    ) {
        let offset = ELF_HEADER_BYTES + index * PROGRAM_HEADER_BYTES;
        write_u32(bytes, offset, segment_type);
        write_u32(bytes, offset + 4, flags);
        write_u64(bytes, offset + 8, file_offset);
        write_u64(bytes, offset + 16, virtual_address);
        write_u64(bytes, offset + 24, virtual_address);
        write_u64(bytes, offset + 32, file_size);
        write_u64(bytes, offset + 40, memory_size);
        write_u64(bytes, offset + 48, alignment);
    }

    pub(super) fn static_elf() -> Vec<u8> {
        static_elf_with_program_headers(2)
    }

    fn static_elf_with_program_headers(program_header_count: u16) -> Vec<u8> {
        assert!(program_header_count >= 2);
        let mut bytes = base_elf(program_header_count, abi::ET_EXEC);
        let byte_length = bytes.len() as u64;
        set_program_header(
            &mut bytes,
            0,
            1,
            5,
            0,
            LOAD_VIRTUAL_ADDRESS,
            byte_length,
            byte_length,
            0x1000,
        );
        set_program_header(
            &mut bytes,
            1,
            abi::PT_GNU_STACK,
            abi::PF_R | abi::PF_W,
            0,
            0,
            0,
            0,
            16,
        );
        bytes
    }

    pub(super) struct RuntimeElfFixture {
        pub(super) bytes: Vec<u8>,
        interpreter_offset: usize,
        interpreter_payload_length: usize,
        dynamic_offset: usize,
        dynamic_entry_count: usize,
        string_table_offset: usize,
        string_table_length: usize,
    }

    pub(super) fn runtime_elf(needed_library_count: usize) -> RuntimeElfFixture {
        runtime_elf_with_padding(needed_library_count, 0, 0)
    }

    pub(in crate::b4_campaign_executor) fn runtime_elf_bytes(
        needed_library_count: usize,
    ) -> Vec<u8> {
        runtime_elf(needed_library_count).bytes
    }

    pub(in crate::b4_campaign_executor) fn startup_runtime_elf_bytes(
        needed: &[&str],
        runpath: Option<&str>,
    ) -> Vec<u8> {
        startup_runtime_elf_bytes_with_entry_point(needed, runpath, false)
    }

    pub(in crate::b4_campaign_executor) fn startup_runtime_zero_entry_elf_bytes(
        needed: &[&str],
        runpath: Option<&str>,
    ) -> Vec<u8> {
        startup_runtime_elf_bytes_with_entry_point(needed, runpath, true)
    }

    fn startup_runtime_elf_bytes_with_entry_point(
        needed: &[&str],
        runpath: Option<&str>,
        zero_entry_point: bool,
    ) -> Vec<u8> {
        fn push_dynamic_string(table: &mut Vec<u8>, value: &str) -> u64 {
            let offset = u64::try_from(table.len()).expect("fixture string table fits u64");
            table.extend_from_slice(value.as_bytes());
            table.push(0);
            offset
        }

        let interpreter = b"/lib64/ld-linux-x86-64.so.2\0";
        let mut string_table = Vec::new();
        let needed_offsets = needed
            .iter()
            .map(|value| push_dynamic_string(&mut string_table, value))
            .collect::<Vec<_>>();
        let runpath_offset = runpath.map(|value| push_dynamic_string(&mut string_table, value));
        let dynamic_entry_count = 3 + needed_offsets.len() + usize::from(runpath_offset.is_some());
        let program_header_count = if zero_entry_point { 5 } else { 4 };
        let mut bytes = base_elf(program_header_count, abi::ET_DYN);
        if zero_entry_point {
            write_u64(&mut bytes, 24, 0);
        }
        let interpreter_offset = bytes.len();
        bytes.extend_from_slice(interpreter);
        while !bytes.len().is_multiple_of(8) {
            bytes.push(0);
        }
        let dynamic_offset = bytes.len();
        let string_table_offset = dynamic_offset + dynamic_entry_count * 16;
        let mut dynamic_entries = vec![
            (
                abi::DT_STRTAB,
                LOAD_VIRTUAL_ADDRESS + u64::try_from(string_table_offset).unwrap(),
            ),
            (abi::DT_STRSZ, u64::try_from(string_table.len()).unwrap()),
        ];
        dynamic_entries.extend(
            needed_offsets
                .into_iter()
                .map(|offset| (abi::DT_NEEDED, offset)),
        );
        if let Some(offset) = runpath_offset {
            dynamic_entries.push((abi::DT_RUNPATH, offset));
        }
        dynamic_entries.push((abi::DT_NULL, 0));
        for (tag, value) in dynamic_entries {
            bytes.extend_from_slice(&tag.to_le_bytes());
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&string_table);

        let byte_length = u64::try_from(bytes.len()).unwrap();
        set_program_header(
            &mut bytes,
            0,
            abi::PT_LOAD,
            abi::PF_R | abi::PF_X,
            0,
            LOAD_VIRTUAL_ADDRESS,
            byte_length,
            byte_length,
            0x1000,
        );
        set_program_header(
            &mut bytes,
            1,
            abi::PT_INTERP,
            abi::PF_R,
            u64::try_from(interpreter_offset).unwrap(),
            LOAD_VIRTUAL_ADDRESS + u64::try_from(interpreter_offset).unwrap(),
            u64::try_from(interpreter.len()).unwrap(),
            u64::try_from(interpreter.len()).unwrap(),
            1,
        );
        set_program_header(
            &mut bytes,
            2,
            abi::PT_DYNAMIC,
            abi::PF_R | abi::PF_W,
            u64::try_from(dynamic_offset).unwrap(),
            LOAD_VIRTUAL_ADDRESS + u64::try_from(dynamic_offset).unwrap(),
            u64::try_from(dynamic_entry_count * 16).unwrap(),
            u64::try_from(dynamic_entry_count * 16).unwrap(),
            8,
        );
        set_program_header(
            &mut bytes,
            3,
            abi::PT_GNU_STACK,
            abi::PF_R | abi::PF_W,
            0,
            0,
            0,
            0,
            16,
        );
        if zero_entry_point {
            set_program_header(&mut bytes, 4, abi::PT_LOAD, abi::PF_X, 0, 0, 0, 1, 1);
        }
        bytes
    }

    pub(in crate::b4_campaign_executor) fn startup_dso_bytes(
        soname: &str,
        needed: &[&str],
        runpath: Option<&str>,
    ) -> Vec<u8> {
        fn push_dynamic_string(table: &mut Vec<u8>, value: &str) -> u64 {
            let offset = u64::try_from(table.len()).expect("fixture string table fits u64");
            table.extend_from_slice(value.as_bytes());
            table.push(0);
            offset
        }

        let mut string_table = Vec::new();
        let soname_offset = push_dynamic_string(&mut string_table, soname);
        let needed_offsets = needed
            .iter()
            .map(|value| push_dynamic_string(&mut string_table, value))
            .collect::<Vec<_>>();
        let runpath_offset = runpath.map(|value| push_dynamic_string(&mut string_table, value));
        let dynamic_entry_count = 4 + needed_offsets.len() + usize::from(runpath_offset.is_some());
        let mut bytes = base_elf(3, abi::ET_DYN);
        let dynamic_offset = bytes.len();
        let string_table_offset = dynamic_offset + dynamic_entry_count * 16;
        let mut dynamic_entries = vec![
            (
                abi::DT_STRTAB,
                LOAD_VIRTUAL_ADDRESS + u64::try_from(string_table_offset).unwrap(),
            ),
            (abi::DT_STRSZ, u64::try_from(string_table.len()).unwrap()),
            (abi::DT_SONAME, soname_offset),
        ];
        dynamic_entries.extend(
            needed_offsets
                .into_iter()
                .map(|offset| (abi::DT_NEEDED, offset)),
        );
        if let Some(offset) = runpath_offset {
            dynamic_entries.push((abi::DT_RUNPATH, offset));
        }
        dynamic_entries.push((abi::DT_NULL, 0));
        for (tag, value) in dynamic_entries {
            bytes.extend_from_slice(&tag.to_le_bytes());
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes.extend_from_slice(&string_table);

        let byte_length = u64::try_from(bytes.len()).unwrap();
        set_program_header(
            &mut bytes,
            0,
            abi::PT_LOAD,
            abi::PF_R | abi::PF_X,
            0,
            LOAD_VIRTUAL_ADDRESS,
            byte_length,
            byte_length,
            0x1000,
        );
        set_program_header(
            &mut bytes,
            1,
            abi::PT_DYNAMIC,
            abi::PF_R | abi::PF_W,
            u64::try_from(dynamic_offset).unwrap(),
            LOAD_VIRTUAL_ADDRESS + u64::try_from(dynamic_offset).unwrap(),
            u64::try_from(dynamic_entry_count * 16).unwrap(),
            u64::try_from(dynamic_entry_count * 16).unwrap(),
            8,
        );
        set_program_header(
            &mut bytes,
            2,
            abi::PT_GNU_STACK,
            abi::PF_R | abi::PF_W,
            0,
            0,
            0,
            0,
            16,
        );
        bytes
    }

    fn runtime_elf_with_padding(
        needed_library_count: usize,
        inert_dynamic_entry_count: usize,
        extra_program_header_count: u16,
    ) -> RuntimeElfFixture {
        runtime_elf_with_interpreter(
            needed_library_count,
            inert_dynamic_entry_count,
            extra_program_header_count,
            b"/lib64/ld-linux-x86-64.so.2\0",
        )
    }

    fn runtime_elf_with_interpreter(
        needed_library_count: usize,
        inert_dynamic_entry_count: usize,
        extra_program_header_count: u16,
        interpreter: &[u8],
    ) -> RuntimeElfFixture {
        let program_header_count = 4_u16.checked_add(extra_program_header_count).unwrap();
        let mut bytes = base_elf(program_header_count, abi::ET_DYN);
        let interpreter_offset = bytes.len();
        bytes.extend_from_slice(interpreter);
        while !bytes.len().is_multiple_of(8) {
            bytes.push(0);
        }
        let dynamic_offset = bytes.len();
        let dynamic_entry_count = needed_library_count + inert_dynamic_entry_count + 3;
        let string_table_offset = dynamic_offset + dynamic_entry_count * 16;
        let string_table = b"libc.so.6\0";

        for (tag, value) in [
            (5_u64, LOAD_VIRTUAL_ADDRESS + string_table_offset as u64),
            (10, string_table.len() as u64),
        ] {
            bytes.extend_from_slice(&tag.to_le_bytes());
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        for _ in 0..inert_dynamic_entry_count {
            bytes.extend_from_slice(&(abi::DT_DEBUG as u64).to_le_bytes());
            bytes.extend_from_slice(&0_u64.to_le_bytes());
        }
        for _ in 0..needed_library_count {
            bytes.extend_from_slice(&(abi::DT_NEEDED as u64).to_le_bytes());
            bytes.extend_from_slice(&0_u64.to_le_bytes());
        }
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(string_table);

        let byte_length = bytes.len() as u64;
        set_program_header(
            &mut bytes,
            0,
            1,
            5,
            0,
            LOAD_VIRTUAL_ADDRESS,
            byte_length,
            byte_length,
            0x1000,
        );
        set_program_header(
            &mut bytes,
            1,
            3,
            4,
            interpreter_offset as u64,
            LOAD_VIRTUAL_ADDRESS + interpreter_offset as u64,
            interpreter.len() as u64,
            interpreter.len() as u64,
            1,
        );
        set_program_header(
            &mut bytes,
            2,
            2,
            6,
            dynamic_offset as u64,
            LOAD_VIRTUAL_ADDRESS + dynamic_offset as u64,
            (dynamic_entry_count * 16) as u64,
            (dynamic_entry_count * 16) as u64,
            8,
        );
        set_program_header(&mut bytes, 3, 0x6474_e551, 6, 0, 0, 0, 0, 16);

        RuntimeElfFixture {
            bytes,
            interpreter_offset,
            interpreter_payload_length: interpreter.len(),
            dynamic_offset,
            dynamic_entry_count,
            string_table_offset,
            string_table_length: string_table.len(),
        }
    }

    fn dynamic_tag_offset(fixture: &RuntimeElfFixture, index: usize) -> usize {
        fixture.dynamic_offset + index * 16
    }

    fn write_dynamic_tag(fixture: &mut RuntimeElfFixture, index: usize, tag: i64) {
        let offset = dynamic_tag_offset(fixture, index);
        fixture.bytes[offset..offset + 8].copy_from_slice(&tag.to_le_bytes());
    }

    fn write_dynamic_value(fixture: &mut RuntimeElfFixture, index: usize, value: u64) {
        let offset = dynamic_tag_offset(fixture, index) + 8;
        write_u64(&mut fixture.bytes, offset, value);
    }

    fn read_u64(bytes: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
    }

    fn dynamic_array_offset(bytes: &[u8], program_header_index: usize) -> usize {
        usize::try_from(read_u64(
            bytes,
            program_header_offset(program_header_index) + 8,
        ))
        .unwrap()
    }

    fn write_dynamic_tag_at(bytes: &mut [u8], program_header_index: usize, index: usize, tag: i64) {
        let offset = dynamic_array_offset(bytes, program_header_index) + index * 16;
        bytes[offset..offset + 8].copy_from_slice(&tag.to_le_bytes());
    }

    fn write_dynamic_value_at(
        bytes: &mut [u8],
        program_header_index: usize,
        index: usize,
        value: u64,
    ) {
        let offset = dynamic_array_offset(bytes, program_header_index) + index * 16 + 8;
        write_u64(bytes, offset, value);
    }

    fn raw_dynamic_records(bytes: &[u8], program_header_index: usize) -> Vec<(i64, u64)> {
        let mut records = Vec::new();
        let dynamic_offset = dynamic_array_offset(bytes, program_header_index);
        for index in 0..65_534 {
            let offset = dynamic_offset + index * 16;
            let tag = i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            let value = read_u64(bytes, offset + 8);
            records.push((tag, value));
            if tag == abi::DT_NULL {
                return records;
            }
        }
        panic!("fixture dynamic array has no DT_NULL")
    }

    fn assert_runtime_rejected(bytes: &[u8], expected: &str) {
        let error = inspect_runtime_amd64_elf(bytes).unwrap_err();
        assert!(
            format!("{error:#}").contains(expected),
            "expected {expected:?}, got {error:#}"
        );
    }

    #[test]
    fn runtime_amd64_elf_inspection_closes_interpreter_and_dynamic_counts() {
        let fixture = runtime_elf(1);
        let inspected = inspect_runtime_amd64_elf(&fixture.bytes).unwrap();
        let common = inspected.common();
        assert_eq!(common.elf_type(), Amd64ElfTypeV1::SharedObject);
        assert_eq!(common.interpreter_segment_count(), 1);
        assert_eq!(common.dynamic_segment_count(), 1);
        let runtime = inspected.runtime();
        assert_eq!(runtime.interpreter_path(), "/lib64/ld-linux-x86-64.so.2");
        assert_eq!(runtime.dynamic_entry_count(), 4);
        assert_eq!(runtime.needed_library_count(), 1);
        assert_eq!(
            runtime
                .startup_dynamic()
                .needed_libraries()
                .iter()
                .map(|needed| (needed.dynamic_ordinal(), needed.requested_name()))
                .collect::<Vec<_>>(),
            vec![(2, "libc.so.6")]
        );
        assert_eq!(
            runtime.startup_dynamic().accepted_tags(),
            &[
                Amd64ElfAcceptedDynamicTagV1::StringTable,
                Amd64ElfAcceptedDynamicTagV1::StringTableSize,
                Amd64ElfAcceptedDynamicTagV1::Needed,
                Amd64ElfAcceptedDynamicTagV1::Null,
            ]
        );
    }

    #[test]
    fn runtime_common_projection_retains_zero_entry_inside_executable_load() {
        let bytes = startup_runtime_zero_entry_elf_bytes(&[], None);
        let inspected = inspect_runtime_amd64_elf(&bytes).unwrap();
        assert!(inspected.common().entry_point_is_zero());
        assert!(inspected.common().entry_point_in_executable_load());
    }

    #[test]
    fn startup_dso_projection_retains_ordered_tags_needed_runpath_and_ordinals() {
        let bytes = startup_dso_bytes(
            "libalpha.so.1",
            &["libc.so.6", "libpthread.so.0"],
            Some("$ORIGIN/../lib:/lib64"),
        );
        let inspected = inspect_startup_dependency_amd64_dso(&bytes).unwrap();
        assert_eq!(inspected.byte_length(), bytes.len() as u64);
        let expected_sha256: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(inspected.sha256(), expected_sha256);
        assert_eq!(inspected.soname(), "libalpha.so.1");
        assert_eq!(
            inspected
                .dynamic()
                .needed_libraries()
                .iter()
                .map(|needed| (needed.dynamic_ordinal(), needed.requested_name()))
                .collect::<Vec<_>>(),
            vec![(3, "libc.so.6"), (4, "libpthread.so.0")]
        );
        assert_eq!(
            inspected.dynamic().accepted_tags(),
            &[
                Amd64ElfAcceptedDynamicTagV1::StringTable,
                Amd64ElfAcceptedDynamicTagV1::StringTableSize,
                Amd64ElfAcceptedDynamicTagV1::Soname,
                Amd64ElfAcceptedDynamicTagV1::Needed,
                Amd64ElfAcceptedDynamicTagV1::Needed,
                Amd64ElfAcceptedDynamicTagV1::Runpath,
                Amd64ElfAcceptedDynamicTagV1::Null,
            ]
        );
        assert_eq!(
            inspected
                .dynamic()
                .accepted_records()
                .iter()
                .map(|record| (record.d_tag(), record.d_un()))
                .collect::<Vec<_>>(),
            raw_dynamic_records(&bytes, 1)
        );
        assert_eq!(
            inspected
                .dynamic()
                .accepted_records()
                .last()
                .unwrap()
                .d_tag(),
            abi::DT_NULL
        );
        let runpath = inspected.dynamic().runpath().unwrap();
        assert_eq!(runpath.raw(), "$ORIGIN/../lib:/lib64");
        assert_eq!(runpath.components().len(), 2);
        assert!(matches!(
            runpath.components()[0],
            Amd64ElfRunpathComponentV1::OriginRelative {
                suffix: "/../lib",
                ..
            }
        ));
        assert!(matches!(
            runpath.components()[1],
            Amd64ElfRunpathComponentV1::Absolute("/lib64")
        ));
    }

    #[test]
    fn startup_runpath_accepts_both_closed_origin_spellings() {
        for raw in ["$ORIGIN/../lib", "${ORIGIN}/../lib"] {
            let bytes = startup_dso_bytes("libalpha.so.1", &[], Some(raw));
            let inspected = inspect_startup_dependency_amd64_dso(&bytes).unwrap();
            let runpath = inspected.dynamic().runpath().unwrap();
            assert_eq!(runpath.raw(), raw);
            assert!(matches!(
                runpath.components(),
                [Amd64ElfRunpathComponentV1::OriginRelative {
                    raw: observed,
                    suffix: "/../lib",
                }] if *observed == raw
            ));
        }
    }

    #[test]
    fn startup_dso_accepts_zero_entry_and_rejects_nonzero_entry_outside_executable_load() {
        let nonzero_entry = startup_dso_bytes("libalpha.so.1", &[], None);
        let inspected = inspect_startup_dependency_amd64_dso(&nonzero_entry).unwrap();
        assert!(!inspected.entry_point_is_zero());
        assert!(inspected.common().entry_point_in_executable_load());

        let mut zero_entry = startup_dso_bytes("libalpha.so.1", &[], None);
        write_u64(&mut zero_entry, 24, 0);
        let inspected = inspect_startup_dependency_amd64_dso(&zero_entry).unwrap();
        assert!(inspected.entry_point_is_zero());
        assert!(!inspected.common().entry_point_in_executable_load());

        let mut outside = startup_dso_bytes("libalpha.so.1", &[], None);
        write_u64(&mut outside, 24, u64::MAX - 1);
        let error = inspect_startup_dependency_amd64_dso(&outside).unwrap_err();
        assert!(
            format!("{error:#}").contains("nonzero entry point"),
            "{error:#}"
        );
    }

    #[test]
    fn startup_dynamic_names_reject_each_noncanonical_or_duplicate_value() {
        for (label, value) in [
            ("empty", ""),
            ("nonprintable", "lib\u{1}.so"),
            ("slash", "lib/alpha.so"),
            ("backslash", "lib\\alpha.so"),
        ] {
            let runtime = startup_runtime_elf_bytes(&[value], None);
            let error = inspect_runtime_amd64_elf(&runtime).unwrap_err();
            assert!(
                format!("{error:#}").contains("DT_NEEDED"),
                "{label}: {error:#}"
            );
            let dso = startup_dso_bytes(value, &[], None);
            let error = inspect_startup_dependency_amd64_dso(&dso).unwrap_err();
            assert!(
                format!("{error:#}").contains("DT_SONAME"),
                "{label}: {error:#}"
            );
        }

        let oversized = "a".repeat(241);
        let runtime = startup_runtime_elf_bytes(&[&oversized], None);
        let error = inspect_runtime_amd64_elf(&runtime).unwrap_err();
        assert!(format!("{error:#}").contains("byte length"), "{error:#}");
        let dso = startup_dso_bytes(&oversized, &[], None);
        let error = inspect_startup_dependency_amd64_dso(&dso).unwrap_err();
        assert!(format!("{error:#}").contains("byte length"), "{error:#}");

        let duplicate_needed = startup_runtime_elf_bytes(&["libc.so.6", "libc.so.6"], None);
        assert_runtime_rejected(&duplicate_needed, "repeats a DT_NEEDED basename");

        let mut duplicate_soname = startup_dso_bytes("libalpha.so.1", &["libbeta.so.1"], None);
        write_dynamic_tag_at(&mut duplicate_soname, 1, 3, abi::DT_SONAME);
        let error = inspect_startup_dependency_amd64_dso(&duplicate_soname).unwrap_err();
        assert!(format!("{error:#}").contains("repeats DT_SONAME"));
    }

    #[test]
    fn startup_runpath_rejects_each_closed_grammar_fault() {
        let seventeen = std::iter::repeat_n("/lib", 17)
            .collect::<Vec<_>>()
            .join(":");
        let oversized = format!("/{}", "a".repeat(240));
        for (label, runpath) in [
            ("empty", String::new()),
            ("root only", "/".to_owned()),
            ("seventeenth", seventeen),
            ("oversized", oversized),
            ("empty component", "/lib::/usr/lib".to_owned()),
            ("semicolon", "/lib;/usr/lib".to_owned()),
            ("LIB token", "$LIB".to_owned()),
            ("PLATFORM token", "$PLATFORM".to_owned()),
            ("embedded ORIGIN", "prefix$ORIGIN/lib".to_owned()),
            ("repeated ORIGIN", "$ORIGIN/$ORIGIN".to_owned()),
            ("dot suffix", "$ORIGIN/./lib".to_owned()),
            ("empty suffix segment", "$ORIGIN//lib".to_owned()),
            ("backslash", "$ORIGIN\\lib".to_owned()),
        ] {
            let bytes = startup_dso_bytes("libalpha.so.1", &[], Some(&runpath));
            let error = inspect_startup_dependency_amd64_dso(&bytes).unwrap_err();
            assert!(
                format!("{error:#}").contains("RUNPATH"),
                "{label}: {error:#}"
            );
        }

        let mut duplicate = startup_dso_bytes("libalpha.so.1", &["/other"], Some("/lib64"));
        write_dynamic_tag_at(&mut duplicate, 1, 3, abi::DT_RUNPATH);
        let error = inspect_startup_dependency_amd64_dso(&duplicate).unwrap_err();
        assert!(format!("{error:#}").contains("repeats DT_RUNPATH"));
    }

    #[test]
    fn startup_dso_closes_type_interp_and_soname_cardinality() {
        let runtime = startup_runtime_elf_bytes(&[], None);
        let error = inspect_startup_dependency_amd64_dso(&runtime).unwrap_err();
        assert!(format!("{error:#}").contains("omit PT_INTERP"));

        let mut executable = startup_dso_bytes("libalpha.so.1", &[], None);
        write_u16(&mut executable, 16, abi::ET_EXEC);
        let error = inspect_startup_dependency_amd64_dso(&executable).unwrap_err();
        assert!(format!("{error:#}").contains("not ET_DYN"));

        let mut missing_soname = startup_dso_bytes("libalpha.so.1", &[], None);
        write_dynamic_tag_at(&mut missing_soname, 1, 2, abi::DT_DEBUG);
        let error = inspect_startup_dependency_amd64_dso(&missing_soname).unwrap_err();
        assert!(format!("{error:#}").contains("exactly one DT_SONAME"));
    }

    #[test]
    fn startup_dynamic_accepts_every_closed_inert_tag_and_permitted_flag_mask() {
        for tag in [
            abi::DT_PLTRELSZ,
            abi::DT_PLTGOT,
            abi::DT_HASH,
            abi::DT_SYMTAB,
            abi::DT_RELA,
            abi::DT_RELASZ,
            abi::DT_RELAENT,
            abi::DT_REL,
            abi::DT_RELSZ,
            abi::DT_RELENT,
            abi::DT_SYMENT,
            abi::DT_INIT,
            abi::DT_FINI,
            abi::DT_PLTREL,
            abi::DT_DEBUG,
            abi::DT_JMPREL,
            abi::DT_BIND_NOW,
            abi::DT_INIT_ARRAY,
            abi::DT_FINI_ARRAY,
            abi::DT_INIT_ARRAYSZ,
            abi::DT_FINI_ARRAYSZ,
            abi::DT_PREINIT_ARRAY,
            abi::DT_PREINIT_ARRAYSZ,
            abi::DT_SYMTAB_SHNDX,
            abi::DT_GNU_HASH,
            abi::DT_VERSYM,
            abi::DT_RELACOUNT,
            abi::DT_RELCOUNT,
            abi::DT_VERDEF,
            abi::DT_VERDEFNUM,
            abi::DT_VERNEED,
            abi::DT_VERNEEDNUM,
        ] {
            let mut bytes = startup_dso_bytes("libalpha.so.1", &["libbeta.so.1"], None);
            write_dynamic_tag_at(&mut bytes, 1, 3, tag);
            let inspected = inspect_startup_dependency_amd64_dso(&bytes).unwrap();
            assert_eq!(inspected.dynamic().accepted_records()[3].d_tag(), tag);
            assert_eq!(inspected.dynamic().accepted_records()[3].d_un(), 14);
        }

        for (tag, value) in [
            (abi::DT_FLAGS, NORMATIVE_DT_FLAGS_MASK),
            (abi::DT_FLAGS_1, NORMATIVE_DT_FLAGS_1_MASK),
        ] {
            let mut bytes = startup_dso_bytes("libalpha.so.1", &["libbeta.so.1"], None);
            write_dynamic_tag_at(&mut bytes, 1, 3, tag);
            write_dynamic_value_at(&mut bytes, 1, 3, value);
            let inspected = inspect_startup_dependency_amd64_dso(&bytes).unwrap();
            assert_eq!(
                (
                    inspected.dynamic().accepted_records()[3].d_tag(),
                    inspected.dynamic().accepted_records()[3].d_un(),
                ),
                (tag, value)
            );
        }
    }

    #[test]
    fn startup_dynamic_flag_masks_kill_each_normative_addition_and_removal_mutant() {
        for (tag_label, tag, normative_mask, normative_bits) in [
            (
                "DT_FLAGS",
                abi::DT_FLAGS,
                NORMATIVE_DT_FLAGS_MASK,
                NORMATIVE_DT_FLAGS_BITS.as_slice(),
            ),
            (
                "DT_FLAGS_1",
                abi::DT_FLAGS_1,
                NORMATIVE_DT_FLAGS_1_MASK,
                NORMATIVE_DT_FLAGS_1_BITS.as_slice(),
            ),
        ] {
            assert_eq!(
                normative_bits
                    .iter()
                    .fold(0_u64, |mask, (_, bit)| mask | bit),
                normative_mask,
                "{tag_label} normative bit list and mask diverged"
            );

            for (bit_label, bit) in normative_bits {
                for (mutant_label, value) in [
                    ("isolated permitted bit", *bit),
                    ("permitted-bit removal", normative_mask & !bit),
                ] {
                    let mut bytes = startup_dso_bytes("libalpha.so.1", &["libbeta.so.1"], None);
                    write_dynamic_tag_at(&mut bytes, 1, 3, tag);
                    write_dynamic_value_at(&mut bytes, 1, 3, value);
                    inspect_startup_dependency_amd64_dso(&bytes).unwrap_or_else(|error| {
                        panic!(
                            "{tag_label} {mutant_label} for {bit_label} ({value:#x}) must remain accepted: {error:#}"
                        )
                    });
                }
            }

            for bit_index in 0..u64::BITS {
                let added_bit = 1_u64 << bit_index;
                if normative_mask & added_bit != 0 {
                    continue;
                }
                let value = normative_mask | added_bit;
                let mut bytes = startup_dso_bytes("libalpha.so.1", &["libbeta.so.1"], None);
                write_dynamic_tag_at(&mut bytes, 1, 3, tag);
                write_dynamic_value_at(&mut bytes, 1, 3, value);
                let error = inspect_startup_dependency_amd64_dso(&bytes).unwrap_err();
                assert!(
                    format!("{error:#}")
                        .contains(&format!("{tag_label} contains a rejected flag bit")),
                    "{tag_label} rejected-bit addition {added_bit:#x}: {error:#}"
                );
            }
        }
    }

    #[test]
    fn startup_dynamic_rejects_named_symbolic_textrel_and_gnu_prelink_table_tags() {
        for (label, tag) in [
            ("DT_SYMBOLIC", abi::DT_SYMBOLIC),
            ("DT_TEXTREL", abi::DT_TEXTREL),
            ("DT_GNU_PRELINKED", abi::DT_GNU_PRELINKED),
            ("DT_GNU_CONFLICTSZ", abi::DT_GNU_CONFLICTSZ),
            ("DT_GNU_LIBLISTSZ", abi::DT_GNU_LIBLISTSZ),
            ("DT_GNU_CONFLICT", abi::DT_GNU_CONFLICT),
            ("DT_GNU_LIBLIST", abi::DT_GNU_LIBLIST),
        ] {
            let mut bytes = startup_dso_bytes("libalpha.so.1", &["libbeta.so.1"], None);
            write_dynamic_tag_at(&mut bytes, 1, 3, tag);
            let error = inspect_startup_dependency_amd64_dso(&bytes).unwrap_err();
            assert!(
                format!("{error:#}").contains("unlisted dynamic tag"),
                "{label} ({tag:#x}): {error:#}"
            );
        }
    }

    #[test]
    fn runtime_amd64_elf_rejects_static_and_runtime_table_faults() {
        let static_bytes = static_elf();
        let error = inspect_runtime_amd64_elf(&static_bytes).unwrap_err();
        assert!(format!("{error:#}").contains("runtime ELF"), "{error:#}");

        let mut relative_interpreter = runtime_elf(1);
        relative_interpreter.bytes[relative_interpreter.interpreter_offset] = b'x';
        let error = inspect_runtime_amd64_elf(&relative_interpreter.bytes).unwrap_err();
        assert!(
            format!("{error:#}").contains("interpreter path"),
            "{error:#}"
        );

        let mut missing_null = runtime_elf(1);
        let null_tag_offset =
            missing_null.dynamic_offset + (missing_null.dynamic_entry_count - 1) * 16;
        write_u64(&mut missing_null.bytes, null_tag_offset, 21);
        let error = inspect_runtime_amd64_elf(&missing_null.bytes).unwrap_err();
        assert!(format!("{error:#}").contains("DT_NULL"), "{error:#}");
    }

    #[test]
    fn runtime_linkage_requires_each_segment_independently() {
        let mut interpreter_only = runtime_elf(0);
        write_u32(
            &mut interpreter_only.bytes,
            program_header_offset(2),
            abi::PT_NOTE,
        );
        assert_runtime_rejected(&interpreter_only.bytes, "dynamic segment");

        let mut dynamic_only = runtime_elf(0);
        write_u32(
            &mut dynamic_only.bytes,
            program_header_offset(1),
            abi::PT_NOTE,
        );
        assert_runtime_rejected(&dynamic_only.bytes, "interpreter segment");
    }

    #[test]
    fn runtime_interpreter_payload_and_path_are_closed_at_each_boundary() {
        let baseline = runtime_elf(0);
        let mut cases = Vec::<(&str, Vec<u8>, &str)>::new();

        let mut missing_terminal_nul = runtime_elf(0);
        let terminal = missing_terminal_nul.interpreter_offset
            + missing_terminal_nul.interpreter_payload_length
            - 1;
        missing_terminal_nul.bytes[terminal] = b'x';
        cases.push((
            "terminal NUL",
            missing_terminal_nul.bytes,
            "exact NUL-terminated payload",
        ));
        let mut interior_nul = runtime_elf(0);
        interior_nul.bytes[interior_nul.interpreter_offset + 2] = 0;
        cases.push((
            "interior NUL",
            interior_nul.bytes,
            "exact NUL-terminated payload",
        ));
        let mut invalid_utf8 = runtime_elf(0);
        invalid_utf8.bytes[invalid_utf8.interpreter_offset + 1] = 0xff;
        cases.push(("UTF-8", invalid_utf8.bytes, "not ASCII"));
        let mut empty_component = runtime_elf(0);
        empty_component.bytes[empty_component.interpreter_offset + 1] = b'/';
        cases.push((
            "empty component",
            empty_component.bytes,
            "noncanonical component",
        ));
        let mut dot_component = runtime_elf(0);
        let start = dot_component.interpreter_offset;
        dot_component.bytes[start + 1] = b'.';
        dot_component.bytes[start + 2] = b'/';
        cases.push((
            "dot component",
            dot_component.bytes,
            "noncanonical component",
        ));
        let mut dot_dot_component = runtime_elf(0);
        let start = dot_dot_component.interpreter_offset;
        dot_dot_component.bytes[start + 1] = b'.';
        dot_dot_component.bytes[start + 2] = b'.';
        dot_dot_component.bytes[start + 3] = b'/';
        cases.push((
            "dot-dot component",
            dot_dot_component.bytes,
            "noncanonical component",
        ));
        let mut nonprintable = runtime_elf(0);
        nonprintable.bytes[nonprintable.interpreter_offset + 1] = 0x1f;
        cases.push((
            "nonprintable component",
            nonprintable.bytes,
            "noncanonical component",
        ));
        let mut one_byte_payload = baseline;
        write_u64(
            &mut one_byte_payload.bytes,
            program_header_offset(1) + 32,
            1,
        );
        cases.push((
            "one-byte payload",
            one_byte_payload.bytes,
            "exact NUL-terminated payload",
        ));

        for (label, bytes, expected) in cases {
            let error = inspect_runtime_amd64_elf(&bytes).unwrap_err();
            assert!(
                format!("{error:#}").contains(expected),
                "{label}: expected {expected:?}, got {error:#}"
            );
        }

        let mut maximum_path = vec![b'/'];
        maximum_path.resize(240, b'a');
        maximum_path.push(0);
        let maximum = runtime_elf_with_interpreter(0, 0, 0, &maximum_path);
        let inspected = inspect_runtime_amd64_elf(&maximum.bytes).unwrap();
        let runtime = inspected.runtime();
        assert_eq!(runtime.interpreter_path().len(), 240);

        let mut oversized_path = vec![b'/'];
        oversized_path.resize(241, b'a');
        oversized_path.push(0);
        let oversized = runtime_elf_with_interpreter(0, 0, 0, &oversized_path);
        assert_runtime_rejected(&oversized.bytes, "exact NUL-terminated payload");
    }

    #[test]
    fn runtime_dynamic_array_closes_exact_count_and_string_tag_boundaries() {
        let mut first_null = runtime_elf(0);
        write_dynamic_tag(&mut first_null, 0, abi::DT_NULL);
        write_dynamic_tag(&mut first_null, 1, abi::DT_CONFIG);
        let inspected = inspect_runtime_amd64_elf(&first_null.bytes).unwrap();
        let runtime = inspected.runtime();
        assert_eq!(runtime.dynamic_entry_count(), 1);
        assert_eq!(runtime.needed_library_count(), 0);

        let mut root_soname = runtime_elf(1);
        write_dynamic_tag(&mut root_soname, 2, abi::DT_SONAME);
        assert_runtime_rejected(&root_soname.bytes, "rejected DT_SONAME");

        let mut rpath = runtime_elf(1);
        write_dynamic_tag(&mut rpath, 2, abi::DT_RPATH);
        assert_runtime_rejected(&rpath.bytes, "rejected DT_RPATH");

        let runpath = startup_runtime_elf_bytes(&["libc.so.6"], Some("$ORIGIN/../lib:/lib64"));
        let inspected = inspect_runtime_amd64_elf(&runpath).unwrap();
        let runtime = inspected.runtime();
        assert_eq!(runtime.needed_library_count(), 1);
        assert_eq!(
            runtime.startup_dynamic().runpath().unwrap().raw(),
            "$ORIGIN/../lib:/lib64"
        );

        for rejected_tag in [
            abi::DT_CONFIG,
            abi::DT_DEPAUDIT,
            abi::DT_AUDIT,
            ELF_DT_AUXILIARY,
            ELF_DT_FILTER,
        ] {
            let mut rejected = runtime_elf(1);
            write_dynamic_tag(&mut rejected, 2, rejected_tag);
            assert_runtime_rejected(&rejected.bytes, "rejected dynamic loader tag");
        }

        let mut unknown = startup_runtime_elf_bytes(&["libc.so.6"], None);
        write_dynamic_tag_at(&mut unknown, 2, 2, 0x1234_5678);
        assert_runtime_rejected(&unknown, "unlisted dynamic tag");

        let mut rejected_flags = startup_runtime_elf_bytes(&["libc.so.6"], None);
        write_dynamic_tag_at(&mut rejected_flags, 2, 2, abi::DT_FLAGS);
        write_dynamic_value_at(
            &mut rejected_flags,
            2,
            2,
            u64::try_from(abi::DF_SYMBOLIC).unwrap(),
        );
        assert_runtime_rejected(&rejected_flags, "DT_FLAGS contains a rejected flag bit");

        let mut rejected_flags_1 = startup_runtime_elf_bytes(&["libc.so.6"], None);
        write_dynamic_tag_at(&mut rejected_flags_1, 2, 2, abi::DT_FLAGS_1);
        write_dynamic_value_at(
            &mut rejected_flags_1,
            2,
            2,
            u64::try_from(abi::DF_1_NODEFLIB).unwrap(),
        );
        assert_runtime_rejected(&rejected_flags_1, "DT_FLAGS_1 contains a rejected flag bit");

        let exact_dynamic_maximum = runtime_elf_with_padding(0, 65_531, 0);
        let inspected = inspect_runtime_amd64_elf(&exact_dynamic_maximum.bytes).unwrap();
        let runtime = inspected.runtime();
        assert_eq!(runtime.dynamic_entry_count(), 65_534);

        let over_dynamic_maximum = runtime_elf_with_padding(0, 65_532, 0);
        assert_runtime_rejected(&over_dynamic_maximum.bytes, "DT_NULL");

        let mut names = (0..4_096)
            .map(|index| format!("lib{index:04x}.so"))
            .collect::<Vec<_>>();
        let name_refs = names.iter().map(String::as_str).collect::<Vec<_>>();
        let exact_needed_maximum = startup_runtime_elf_bytes(&name_refs, None);
        let inspected = inspect_runtime_amd64_elf(&exact_needed_maximum).unwrap();
        let runtime = inspected.runtime();
        assert_eq!(runtime.needed_library_count(), 4_096);

        names.push("lib1000.so".to_owned());
        let name_refs = names.iter().map(String::as_str).collect::<Vec<_>>();
        let over_needed_maximum = startup_runtime_elf_bytes(&name_refs, None);
        assert_runtime_rejected(&over_needed_maximum, "DT_NEEDED count exceeds");
    }

    #[test]
    fn runtime_dynamic_strings_reject_each_isolated_table_and_offset_fault() {
        let mut cases = Vec::<(&str, Vec<u8>, &str)>::new();

        let mut empty_dynamic = runtime_elf(1);
        write_u64(&mut empty_dynamic.bytes, program_header_offset(2) + 32, 0);
        cases.push((
            "empty dynamic array",
            empty_dynamic.bytes,
            "complete 16-byte entries",
        ));
        let mut incomplete_dynamic = runtime_elf(1);
        write_u64(
            &mut incomplete_dynamic.bytes,
            program_header_offset(2) + 32,
            17,
        );
        cases.push((
            "incomplete dynamic array",
            incomplete_dynamic.bytes,
            "complete 16-byte entries",
        ));
        let mut duplicate_strtab = runtime_elf(1);
        write_dynamic_tag(&mut duplicate_strtab, 1, abi::DT_STRTAB);
        cases.push((
            "duplicate DT_STRTAB",
            duplicate_strtab.bytes,
            "repeats DT_STRTAB",
        ));
        let mut duplicate_strsz = runtime_elf(1);
        write_dynamic_tag(&mut duplicate_strsz, 0, abi::DT_STRSZ);
        cases.push((
            "duplicate DT_STRSZ",
            duplicate_strsz.bytes,
            "repeats DT_STRSZ",
        ));
        let mut missing_strtab = runtime_elf(1);
        write_dynamic_tag(&mut missing_strtab, 0, abi::DT_DEBUG);
        cases.push((
            "missing DT_STRTAB",
            missing_strtab.bytes,
            "without one DT_STRTAB",
        ));
        let mut missing_strsz = runtime_elf(1);
        write_dynamic_tag(&mut missing_strsz, 1, abi::DT_DEBUG);
        cases.push((
            "missing DT_STRSZ",
            missing_strsz.bytes,
            "without one DT_STRSZ",
        ));
        let mut unmapped_strtab = runtime_elf(1);
        let unmapped_address = LOAD_VIRTUAL_ADDRESS + unmapped_strtab.bytes.len() as u64 + 1;
        write_dynamic_value(&mut unmapped_strtab, 0, unmapped_address);
        cases.push(("unmapped DT_STRTAB", unmapped_strtab.bytes, "does not map"));
        let mut oversized_strsz = runtime_elf(1);
        let oversized_size = oversized_strsz.string_table_length as u64 + 1;
        write_dynamic_value(&mut oversized_strsz, 1, oversized_size);
        cases.push(("oversized DT_STRSZ", oversized_strsz.bytes, "does not map"));
        let mut offset_outside = runtime_elf(1);
        let outside_offset = offset_outside.string_table_length as u64 + 1;
        write_dynamic_value(&mut offset_outside, 2, outside_offset);
        cases.push((
            "dynamic string offset",
            offset_outside.bytes,
            "DT_NEEDED string offset is outside DT_STRSZ",
        ));
        let mut soname_offset_outside = runtime_elf(1);
        write_dynamic_tag(&mut soname_offset_outside, 2, abi::DT_SONAME);
        let outside_offset = soname_offset_outside.string_table_length as u64 + 1;
        write_dynamic_value(&mut soname_offset_outside, 2, outside_offset);
        cases.push((
            "DT_SONAME string offset",
            soname_offset_outside.bytes,
            "DT_SONAME string offset is outside DT_STRSZ",
        ));
        let mut missing_string_nul = runtime_elf(1);
        let final_byte =
            missing_string_nul.string_table_offset + missing_string_nul.string_table_length - 1;
        missing_string_nul.bytes[final_byte] = b'x';
        cases.push((
            "dynamic string NUL",
            missing_string_nul.bytes,
            "contains no NUL terminator",
        ));
        let mut multiply_mapped_strtab = runtime_elf_with_padding(1, 0, 1);
        write_u64(
            &mut multiply_mapped_strtab.bytes,
            program_header_offset(0) + 32,
            200,
        );
        write_u64(
            &mut multiply_mapped_strtab.bytes,
            program_header_offset(0) + 40,
            200,
        );
        set_program_header(
            &mut multiply_mapped_strtab.bytes,
            4,
            abi::PT_LOAD,
            abi::PF_R,
            200,
            LOAD_VIRTUAL_ADDRESS + 50,
            100,
            100,
            1,
        );
        write_dynamic_value(&mut multiply_mapped_strtab, 0, LOAD_VIRTUAL_ADDRESS + 100);
        cases.push((
            "multiply mapped DT_STRTAB",
            multiply_mapped_strtab.bytes,
            "more than one file-backed PT_LOAD",
        ));

        for (label, bytes, expected) in cases {
            let error = inspect_runtime_amd64_elf(&bytes).unwrap_err();
            assert!(
                format!("{error:#}").contains(expected),
                "{label}: expected {expected:?}, got {error:#}"
            );
        }
    }

    #[test]
    fn topology_free_inspector_has_no_physical_or_authorizing_surface() {
        let production = include_str!("amd64_elf_inspection.rs")
            .split("#[path = \"amd64_elf_import.rs\"]")
            .next()
            .unwrap();
        let normalized = production.replace("\r\n", "\n");
        let compact = production.split_whitespace().collect::<String>();
        let module_declaration = include_str!("mod.rs");

        assert!(normalized.contains(
            "/// Inspect one exact borrowed ELF body under the closed runtime policy.\n\
             fn inspect_runtime_amd64_elf(bytes: &[u8])"
        ));
        for required in [
            "fninspect_runtime_amd64_elf(",
            "parse_ident",
            "SegmentTable::new",
            "SectionHeaderTable::new",
            "Sha256::digest(bytes)",
            ".rposition(",
            "bytes:&'bytes[u8]",
        ] {
            assert!(compact.contains(required), "missing {required}");
        }
        assert!(module_declaration.contains("mod amd64_elf_inspection;"));
        assert!(!module_declaration.contains("pub mod amd64_elf_inspection;"));
        for forbidden in [
            "pubfninspect_runtime_amd64_elf(",
            "pub(crate)fninspect_runtime_amd64_elf(",
            "pub(super)fninspect_runtime_amd64_elf(",
            "pub(incrate::b4_campaign_executor)fninspect_runtime_amd64_elf(",
            "pubfninspect_startup_dependency_amd64_dso(",
            "pub(crate)fninspect_startup_dependency_amd64_dso(",
            "pub(super)fninspect_startup_dependency_amd64_dso(",
            "pub(incrate::b4_campaign_executor)fninspect_startup_dependency_amd64_dso(",
            "std::fs",
            "std::path",
            "BorrowedFd",
            "OwnedFd",
            "MutationCapability",
            "AuthenticatedPrepareInputSetSourceV1",
            "Serialize",
            "Deserialize",
            "SlotV1",
            "string_table[offset..].contains",
        ] {
            assert!(!compact.contains(forbidden), "forbidden {forbidden}");
        }
    }

    #[test]
    fn amd64_physical_import_requires_one_private_affine_custody_route() {
        let inspection_module = include_str!("amd64_elf_inspection.rs");
        let executor_module = include_str!("mod.rs");
        let custody_module = include_str!("custody.rs");

        assert!(
            inspection_module.contains("#[path = \"amd64_elf_import.rs\"]\nmod physical_import;")
        );
        assert!(
            inspection_module.contains("pub(super) use physical_import::with_imported_amd64_elf;")
        );
        assert!(!executor_module.contains("mod amd64_elf_import;"));
        assert!(custody_module.contains("fn with_authenticated_amd64_elf_stream<Inspection, T>("));
        assert!(custody_module.contains("_permit: Amd64ElfCustodyPermitV1"));
        assert!(
            custody_module.contains("fn compile_only_observe_amd64_view_from_custody_sibling(")
        );
    }
}
