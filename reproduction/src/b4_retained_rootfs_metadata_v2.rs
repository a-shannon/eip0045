// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Pure Linux/`tmpfs` metadata theorem and physical-packet shape for V2.
//!
//! This module freezes identities and validates caller-supplied records. It
//! performs no I/O and returns no authority token. In particular, equality to
//! these declarations does not authenticate a boot image, a live filesystem,
//! a descriptor, or an observation.

#![allow(
    clippy::module_name_repetitions,
    clippy::struct_field_names,
    reason = "V2 names and explicit SHA-256 field suffixes are protocol identity boundaries"
)]

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::b4_positive_gate::PositiveRunnerRole;

/// Exact Linux source commit selected by the V2 theorem.
pub const LINUX_COMMIT_V2: &str = "25c76bea853d0db65b51fb4697a47cbfd9e35e76";
/// Frozen SHA-256 of the framed theorem-basis preimage.
pub const THEOREM_BASIS_SHA256_HEX_V2: &str =
    "fb46e22d46c37aeb3ea81a5e2544bffb15d1fc6e5ca183ddf2c78f412fa2f9c9";
/// Frozen SHA-256 of the theorem-bound 55-entry expected-mode table.
pub const EXPECTED_MODE_TABLE_SHA256_HEX_V2: &str =
    "8c2406b15049b145567f1ee9e5d9c2491dc81d8d3984fb47279fdf5553d32744";

/// Linux `statx` bit for an immutable inode.
pub const STATX_ATTR_IMMUTABLE: u64 = 0x0000_0010;
/// Linux `statx` bit for an append-only inode.
pub const STATX_ATTR_APPEND: u64 = 0x0000_0020;

/// Number of prohibited metadata classes in the closed theorem.
pub const PROHIBITED_METADATA_CLASS_COUNT_V2: usize = 11;
/// Number of subject kinds in the closed theorem.
pub const METADATA_SUBJECT_KIND_COUNT_V2: usize = 5;
/// Number of entries in the closed class-by-kind expected-mode table.
pub const EXPECTED_MODE_ENTRY_COUNT_V2: usize =
    PROHIBITED_METADATA_CLASS_COUNT_V2 * METADATA_SUBJECT_KIND_COUNT_V2;

const THEOREM_DOMAIN_V2: &[u8] = b"eip0045.retained-rootfs-metadata.theorem.v2";
const TABLE_DOMAIN_V2: &[u8] = b"eip0045.retained-rootfs-metadata.expected-mode-table.v2";
const PROFILE_DOMAIN_V2: &[u8] = b"eip0045.retained-rootfs-metadata.profile.v2";
const FILESYSTEM_TYPE_V2: &[u8] = b"tmpfs";

/// Canonical runner roles, in the only accepted order.
pub const CANONICAL_ROLES: [PositiveRunnerRole; 4] = [
    PositiveRunnerRole::RustValidatorBuild,
    PositiveRunnerRole::JvmValidatorBuild,
    PositiveRunnerRole::RustVerifier,
    PositiveRunnerRole::JvmVerifier,
];

/// One required Linux configuration state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum KernelConfigStateV2 {
    /// The symbol must resolve to built-in support.
    Enabled = 1,
    /// The symbol must resolve to disabled support.
    Disabled = 0,
}

impl KernelConfigStateV2 {
    /// Return the opposite state for isolated configuration mutants.
    #[must_use]
    pub const fn flipped(self) -> Self {
        match self {
            Self::Enabled => Self::Disabled,
            Self::Disabled => Self::Enabled,
        }
    }
}

/// One compiled Linux configuration requirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelConfigRequirementV2 {
    /// Exact Kconfig symbol.
    pub symbol: &'static str,
    /// Required resolved state.
    pub state: KernelConfigStateV2,
}

/// Complete ordered minimum configuration bound by the theorem.
pub const REQUIRED_KERNEL_CONFIG_V2: [KernelConfigRequirementV2; 27] = [
    config("CONFIG_SHMEM", KernelConfigStateV2::Enabled),
    config("CONFIG_TMPFS", KernelConfigStateV2::Enabled),
    config("CONFIG_NAMESPACES", KernelConfigStateV2::Enabled),
    config("CONFIG_USER_NS", KernelConfigStateV2::Enabled),
    config("CONFIG_PROC_FS", KernelConfigStateV2::Enabled),
    config("CONFIG_SECCOMP", KernelConfigStateV2::Enabled),
    config("CONFIG_SECCOMP_FILTER", KernelConfigStateV2::Enabled),
    config("CONFIG_MEMFD_CREATE", KernelConfigStateV2::Enabled),
    config("CONFIG_CGROUP_PIDS", KernelConfigStateV2::Enabled),
    config("CONFIG_NET", KernelConfigStateV2::Enabled),
    config("CONFIG_UNIX", KernelConfigStateV2::Enabled),
    config("CONFIG_EXT4_FS", KernelConfigStateV2::Enabled),
    config("CONFIG_TMPFS_XATTR", KernelConfigStateV2::Disabled),
    config("CONFIG_TMPFS_POSIX_ACL", KernelConfigStateV2::Disabled),
    config("CONFIG_TMPFS_QUOTA", KernelConfigStateV2::Disabled),
    config("CONFIG_FS_POSIX_ACL", KernelConfigStateV2::Disabled),
    config("CONFIG_SECURITY", KernelConfigStateV2::Disabled),
    config("CONFIG_UNICODE", KernelConfigStateV2::Disabled),
    config("CONFIG_FS_ENCRYPTION", KernelConfigStateV2::Disabled),
    config("CONFIG_FS_VERITY", KernelConfigStateV2::Disabled),
    config("CONFIG_SWAP", KernelConfigStateV2::Disabled),
    config("CONFIG_MODULES", KernelConfigStateV2::Disabled),
    config("CONFIG_LIVEPATCH", KernelConfigStateV2::Disabled),
    config("CONFIG_KEXEC", KernelConfigStateV2::Disabled),
    config("CONFIG_KEXEC_FILE", KernelConfigStateV2::Disabled),
    config("CONFIG_CGROUPS", KernelConfigStateV2::Enabled),
    config("CONFIG_BPF_SYSCALL", KernelConfigStateV2::Disabled),
];

const fn config(symbol: &'static str, state: KernelConfigStateV2) -> KernelConfigRequirementV2 {
    KernelConfigRequirementV2 { symbol, state }
}

/// One exact whole-file source pin supporting the compiled theorem.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxSourceRequirementV2 {
    /// Path relative to the pinned Linux source root.
    pub path: &'static str,
    /// Lowercase SHA-256 of the complete file bytes.
    pub sha256_hex: &'static str,
}

/// Ordered source files whose exact bytes support the theorem declaration.
pub const LINUX_SOURCE_PINS_V2: [LinuxSourceRequirementV2; 8] = [
    source(
        "mm/shmem.c",
        "b6462a0834cce236b13d6ba0357550f2d41f344590cb463579d208cfad1b9605",
    ),
    source(
        "fs/Kconfig",
        "88b6592d03f0664a56bb43eb0f40d7fb4de11a149d3cdd4d9b0dbc78d204f153",
    ),
    source(
        "init/Kconfig",
        "15023b82d127c96ce83464147614cab94242d83194b1c88b9f1eefe6c5a7c417",
    ),
    source(
        "fs/posix_acl.c",
        "cb2b8cad247420b554bfd0af5a249398abbe949505f774ecfc6f9e028bdd44bd",
    ),
    source(
        "include/linux/security.h",
        "f0899dbbc2d8dfff5d5c3b1d5c320b9e83dfc8553d712bf9da3364678e5cbf9e",
    ),
    source(
        "fs/xattr.c",
        "d9ee8ddf6ed05ad95706ec9669b3acc45797bfa955dbcdbd7a543a21cf8091fd",
    ),
    source(
        "fs/stat.c",
        "47d331643ef846d014684819266beb580fd6da3e9430b0cdedebed53e99d9078",
    ),
    source(
        "include/uapi/linux/stat.h",
        "c900a05e031d999074db5ac3567f651ce2cf2f9f9e0a686810d6453c9f8b9526",
    ),
];

const fn source(path: &'static str, sha256_hex: &'static str) -> LinuxSourceRequirementV2 {
    LinuxSourceRequirementV2 { path, sha256_hex }
}

/// One prohibited metadata class, in canonical table order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProhibitedMetadataClassV2 {
    /// Any extended-attribute name.
    XattrNameSet = 0,
    /// POSIX access ACL metadata.
    PosixAccessAcl = 1,
    /// POSIX default ACL metadata.
    PosixDefaultAcl = 2,
    /// Linux file capability metadata.
    LinuxFileCapability = 3,
    /// Immutable inode attribute.
    Immutable = 4,
    /// Append-only inode attribute.
    AppendOnly = 5,
    /// Filesystem encryption metadata.
    Encrypted = 6,
    /// Filesystem verity metadata.
    Verity = 7,
    /// Case-folding metadata.
    Casefold = 8,
    /// A nonzero project identifier.
    NonzeroProjectId = 9,
    /// Project-inherit metadata.
    ProjectInherit = 10,
}

impl ProhibitedMetadataClassV2 {
    /// Return the required `statx` attribute bit for directly observed rows.
    #[must_use]
    pub const fn observed_statx_bit(self) -> Option<u64> {
        match self {
            Self::Immutable => Some(STATX_ATTR_IMMUTABLE),
            Self::AppendOnly => Some(STATX_ATTR_APPEND),
            Self::XattrNameSet
            | Self::PosixAccessAcl
            | Self::PosixDefaultAcl
            | Self::LinuxFileCapability
            | Self::Encrypted
            | Self::Verity
            | Self::Casefold
            | Self::NonzeroProjectId
            | Self::ProjectInherit => None,
        }
    }
}

/// Closed class order used by every subject.
pub const PROHIBITED_METADATA_CLASSES_V2: [ProhibitedMetadataClassV2;
    PROHIBITED_METADATA_CLASS_COUNT_V2] = [
    ProhibitedMetadataClassV2::XattrNameSet,
    ProhibitedMetadataClassV2::PosixAccessAcl,
    ProhibitedMetadataClassV2::PosixDefaultAcl,
    ProhibitedMetadataClassV2::LinuxFileCapability,
    ProhibitedMetadataClassV2::Immutable,
    ProhibitedMetadataClassV2::AppendOnly,
    ProhibitedMetadataClassV2::Encrypted,
    ProhibitedMetadataClassV2::Verity,
    ProhibitedMetadataClassV2::Casefold,
    ProhibitedMetadataClassV2::NonzeroProjectId,
    ProhibitedMetadataClassV2::ProjectInherit,
];

/// One subject kind in the closed expected-mode table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MetadataSubjectKindV2 {
    /// The sole superblock root `M`.
    MountRoot = 0,
    /// One role-bound retained root `R_i`.
    RoleRoot = 1,
    /// One retained directory `D_i,j`.
    RetainedDirectory = 2,
    /// One retained regular file `F_i,j`.
    RetainedRegularFile = 3,
    /// One retained symbolic link `L_i,j`.
    RetainedSymbolicLink = 4,
}

/// Closed subject-kind order used by the expected-mode table.
pub const METADATA_SUBJECT_KINDS_V2: [MetadataSubjectKindV2; METADATA_SUBJECT_KIND_COUNT_V2] = [
    MetadataSubjectKindV2::MountRoot,
    MetadataSubjectKindV2::RoleRoot,
    MetadataSubjectKindV2::RetainedDirectory,
    MetadataSubjectKindV2::RetainedRegularFile,
    MetadataSubjectKindV2::RetainedSymbolicLink,
];

/// The only two expected modes admitted by the V2 table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExpectedMetadataModeV2 {
    /// The known `statx` bit is supported, present in the mask, and zero.
    ObservedAbsentComplete = 0,
    /// The pinned source and complete configuration have no producer.
    StructurallyUnrepresentable = 1,
}

/// One entry in the closed class-by-kind expected-mode table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedModeCellV2 {
    /// Prohibited metadata class.
    pub class: ProhibitedMetadataClassV2,
    /// Physical subject kind.
    pub kind: MetadataSubjectKindV2,
    /// Sole expected result for this class and kind.
    pub mode: ExpectedMetadataModeV2,
}

/// Return the compiled expected mode for one class-by-kind entry.
#[must_use]
pub const fn expected_metadata_mode_v2(
    class: ProhibitedMetadataClassV2,
    _kind: MetadataSubjectKindV2,
) -> ExpectedMetadataModeV2 {
    match class {
        ProhibitedMetadataClassV2::Immutable | ProhibitedMetadataClassV2::AppendOnly => {
            ExpectedMetadataModeV2::ObservedAbsentComplete
        }
        ProhibitedMetadataClassV2::XattrNameSet
        | ProhibitedMetadataClassV2::PosixAccessAcl
        | ProhibitedMetadataClassV2::PosixDefaultAcl
        | ProhibitedMetadataClassV2::LinuxFileCapability
        | ProhibitedMetadataClassV2::Encrypted
        | ProhibitedMetadataClassV2::Verity
        | ProhibitedMetadataClassV2::Casefold
        | ProhibitedMetadataClassV2::NonzeroProjectId
        | ProhibitedMetadataClassV2::ProjectInherit => {
            ExpectedMetadataModeV2::StructurallyUnrepresentable
        }
    }
}

/// Complete 55-entry expected-mode table in class-major, kind-minor order.
pub const EXPECTED_MODE_TABLE_V2: [ExpectedModeCellV2; EXPECTED_MODE_ENTRY_COUNT_V2] =
    compile_expected_mode_table_v2();

const fn compile_expected_mode_table_v2() -> [ExpectedModeCellV2; EXPECTED_MODE_ENTRY_COUNT_V2] {
    let mut table = [ExpectedModeCellV2 {
        class: ProhibitedMetadataClassV2::XattrNameSet,
        kind: MetadataSubjectKindV2::MountRoot,
        mode: ExpectedMetadataModeV2::StructurallyUnrepresentable,
    }; EXPECTED_MODE_ENTRY_COUNT_V2];
    let mut class_index = 0;
    while class_index < PROHIBITED_METADATA_CLASSES_V2.len() {
        let mut kind_index = 0;
        while kind_index < METADATA_SUBJECT_KINDS_V2.len() {
            let class = PROHIBITED_METADATA_CLASSES_V2[class_index];
            let kind = METADATA_SUBJECT_KINDS_V2[kind_index];
            let ordinal = class_index * METADATA_SUBJECT_KINDS_V2.len() + kind_index;
            table[ordinal] = ExpectedModeCellV2 {
                class,
                kind,
                mode: expected_metadata_mode_v2(class, kind),
            };
            kind_index += 1;
        }
        class_index += 1;
    }
    table
}

/// Owned configuration row supplied for exact theorem comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelConfigBindingV2 {
    /// Exact Kconfig symbol.
    pub symbol: String,
    /// Resolved state.
    pub state: KernelConfigStateV2,
}

/// Owned source pin supplied for exact theorem comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxSourceBindingV2 {
    /// Path relative to the Linux source root.
    pub path: String,
    /// Lowercase SHA-256 of the complete file bytes.
    pub sha256_hex: String,
}

/// Complete caller-supplied theorem material compared to the compiled model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataTheoremCandidateV2 {
    /// Exact 40-character Linux commit.
    pub linux_commit: String,
    /// Complete ordered minimum configuration.
    pub required_config: Vec<KernelConfigBindingV2>,
    /// Complete ordered source-file pin set.
    pub source_pins: Vec<LinuxSourceBindingV2>,
}

/// Return an owned copy of the canonical theorem declaration.
///
/// This helper reproduces the compiled declaration only; it does not inspect
/// source files or establish runtime identity.
#[must_use]
pub fn canonical_metadata_theorem_candidate_v2() -> MetadataTheoremCandidateV2 {
    MetadataTheoremCandidateV2 {
        linux_commit: LINUX_COMMIT_V2.to_owned(),
        required_config: REQUIRED_KERNEL_CONFIG_V2
            .iter()
            .map(|requirement| KernelConfigBindingV2 {
                symbol: requirement.symbol.to_owned(),
                state: requirement.state,
            })
            .collect(),
        source_pins: LINUX_SOURCE_PINS_V2
            .iter()
            .map(|requirement| LinuxSourceBindingV2 {
                path: requirement.path.to_owned(),
                sha256_hex: requirement.sha256_hex.to_owned(),
            })
            .collect(),
    }
}

/// Opaque result of exact equality with the compiled theorem declaration.
///
/// This value is an identity projection, not runtime or observation evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompiledMetadataTheoremV2 {
    theorem_basis_sha256: [u8; 32],
    expected_mode_table_sha256: [u8; 32],
}

impl CompiledMetadataTheoremV2 {
    /// Digest of the Linux commit, ordered configuration, and source pins.
    #[must_use]
    pub const fn theorem_basis_sha256(self) -> [u8; 32] {
        self.theorem_basis_sha256
    }

    /// Profile-bound digest of all 55 expected-mode entries.
    #[must_use]
    pub const fn expected_mode_table_sha256(self) -> [u8; 32] {
        self.expected_mode_table_sha256
    }
}

/// Bind the theorem to exact image-level identity digests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataProfileBindingV2 {
    /// Exact theorem declaration to compare with the compiled model.
    pub theorem: MetadataTheoremCandidateV2,
    /// Digest of the complete resolved kernel configuration.
    pub resolved_config_sha256: [u8; 32],
    /// Digest of the exact boot image containing the selected kernel.
    pub boot_image_sha256: [u8; 32],
    /// Digest of the externally qualified empty dynamic-extension state.
    pub dynamic_extension_state_sha256: [u8; 32],
}

/// Opaque, pure identity of one theorem-bound metadata profile.
///
/// The value has no serialization implementation and carries no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataProfileIdentityV2 {
    theorem_basis_sha256: [u8; 32],
    expected_mode_table_sha256: [u8; 32],
    resolved_config_sha256: [u8; 32],
    boot_image_sha256: [u8; 32],
    dynamic_extension_state_sha256: [u8; 32],
    profile_identity_sha256: [u8; 32],
}

impl MetadataProfileIdentityV2 {
    /// Digest of the complete profile identity preimage.
    #[must_use]
    pub const fn profile_identity_sha256(self) -> [u8; 32] {
        self.profile_identity_sha256
    }

    /// Digest of the compiled 55-entry table.
    #[must_use]
    pub const fn expected_mode_table_sha256(self) -> [u8; 32] {
        self.expected_mode_table_sha256
    }

    /// Digest of the theorem basis.
    #[must_use]
    pub const fn theorem_basis_sha256(self) -> [u8; 32] {
        self.theorem_basis_sha256
    }

    /// Digest of the complete resolved kernel configuration.
    #[must_use]
    pub const fn resolved_config_sha256(self) -> [u8; 32] {
        self.resolved_config_sha256
    }

    /// Digest of the exact boot image.
    #[must_use]
    pub const fn boot_image_sha256(self) -> [u8; 32] {
        self.boot_image_sha256
    }

    /// Digest of the qualified dynamic-extension state.
    #[must_use]
    pub const fn dynamic_extension_state_sha256(self) -> [u8; 32] {
        self.dynamic_extension_state_sha256
    }
}

/// Exact descriptor identity copied into each subject record.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DescriptorIdentityV2 {
    /// Unique mount identifier returned by the selected `statx` ABI.
    pub mount_id_unique: u64,
    /// Device major number.
    pub device_major: u32,
    /// Device minor number.
    pub device_minor: u32,
    /// Inode number on the selected device and mount.
    pub inode: u64,
}

/// One physical subject in canonical packet order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataSubjectIdentityV2 {
    /// Closed subject kind.
    pub kind: MetadataSubjectKindV2,
    /// Canonical runner role for every subject other than `M`.
    pub role: Option<PositiveRunnerRole>,
    /// Per-role, per-kind zero-based index for dynamic `D/F/L` subjects.
    pub entry_index: Option<u64>,
    /// Exact descriptor identity.
    pub descriptor: DescriptorIdentityV2,
    /// Exact nonzero mount epoch shared by the complete packet.
    pub mount_epoch: [u8; 32],
}

/// Required zero seed for the sole mount root `M`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MountRootSeedV2 {
    /// Initial inode flags.
    pub inode_flags: u32,
    /// Initial shmem filesystem flags.
    pub shmem_fsflags: u32,
}

/// Aggregate dynamic subject counts rederived from all four roles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DynamicSubjectCountsV2 {
    /// Total retained directories across the four roles.
    pub retained_directories: usize,
    /// Total retained regular files across the four roles.
    pub retained_regular_files: usize,
    /// Total retained symbolic links across the four roles.
    pub retained_symbolic_links: usize,
}

/// One physical class-by-subject cell record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataCellRecordV2 {
    /// Digest of the complete profile identity.
    pub profile_identity_sha256: [u8; 32],
    /// Digest of the profile-bound expected-mode table.
    pub expected_mode_table_sha256: [u8; 32],
    /// Complete repeated subject binding.
    pub subject: MetadataSubjectIdentityV2,
    /// Prohibited class at this canonical table position.
    pub class: ProhibitedMetadataClassV2,
    /// Exact compiled expected mode.
    pub mode: ExpectedMetadataModeV2,
    /// Full observed `statx` attribute mask for an observed row only.
    pub attribute_mask: Option<u64>,
    /// Full observed `statx` attribute value for an observed row only.
    pub attributes: Option<u64>,
}

/// Complete pure packet submitted to the structural validator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedRootfsMetadataPacketV2 {
    /// Exact theorem- and image-bound profile identity.
    pub profile: MetadataProfileIdentityV2,
    /// Mandatory zero seed of the sole mount root.
    pub root_seed: Option<MountRootSeedV2>,
    /// Aggregate dynamic subject counts.
    pub claimed_counts: DynamicSubjectCountsV2,
    /// Canonically ordered physical subjects.
    pub subjects: Vec<MetadataSubjectIdentityV2>,
    /// Eleven canonically ordered cells for every physical subject.
    pub cells: Vec<MetadataCellRecordV2>,
}

/// Closed structural validation failures for the V2 model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataModelErrorV2 {
    /// Linux commit differs from the compiled pin.
    LinuxCommitBinding,
    /// Configuration row count differs from the compiled set.
    ConfigurationCardinality,
    /// Configuration row differs at the named index.
    ConfigurationBinding {
        /// First mismatching row.
        index: usize,
    },
    /// Source-pin row count differs from the compiled set.
    SourceCardinality,
    /// Source path or file digest differs at the named index.
    SourceBinding {
        /// First mismatching row.
        index: usize,
    },
    /// Recomputed compiled identity differs from its frozen digest.
    CompiledIdentityDrift,
    /// One image-level profile digest is all zero.
    ProfileDigestMissing,
    /// The required root seed is absent.
    MountRootSeedMissing,
    /// One root-seed field is nonzero.
    MountRootSeedNonzero,
    /// The first and sole `M` subject is absent.
    MountRootSubjectMissing,
    /// A subject has an impossible role/index shape.
    SubjectShape {
        /// Subject ordinal.
        ordinal: usize,
    },
    /// A subject identity is zero or otherwise incomplete.
    SubjectIdentity {
        /// Subject ordinal.
        ordinal: usize,
    },
    /// A subject is not bound to the `M` mount and epoch.
    SubjectMountBinding {
        /// Subject ordinal.
        ordinal: usize,
    },
    /// A subject aliases an earlier descriptor identity.
    SubjectAlias {
        /// Later aliased subject ordinal.
        ordinal: usize,
    },
    /// A role, kind, or entry index violates canonical subject order.
    SubjectOrder {
        /// First unexpected subject ordinal.
        ordinal: usize,
    },
    /// Aggregate dynamic counts differ from the rederived inventory.
    DynamicSubjectCount,
    /// Checked packet cardinality overflowed.
    CardinalityOverflow,
    /// Physical cell count differs from both inventory and claimed counts.
    CellCardinality,
    /// A cell repeats a subject other than the expected subject.
    CellSubjectBinding {
        /// Cell ordinal.
        ordinal: usize,
    },
    /// A cell class violates canonical class order.
    CellClassOrder {
        /// Cell ordinal.
        ordinal: usize,
    },
    /// A cell mode differs from the compiled class-by-kind result.
    CellMode {
        /// Cell ordinal.
        ordinal: usize,
    },
    /// A cell carries the wrong expected-mode-table digest.
    CellTableBinding {
        /// Cell ordinal.
        ordinal: usize,
    },
    /// A cell carries the wrong complete profile digest.
    CellProfileBinding {
        /// Cell ordinal.
        ordinal: usize,
    },
    /// An observed row omits its attribute mask or attribute value.
    ObservedMaskMissing {
        /// Cell ordinal.
        ordinal: usize,
    },
    /// The required class bit is absent from the known attribute mask.
    ObservedMaskUnknown {
        /// Cell ordinal.
        ordinal: usize,
    },
    /// The prohibited observed attribute bit is set.
    ObservedAttributePresent {
        /// Cell ordinal.
        ordinal: usize,
    },
    /// A structural row improperly carries observation fields.
    StructuralObservationPresent {
        /// Cell ordinal.
        ordinal: usize,
    },
}

/// Validate exact equality with the compiled theorem declaration.
///
/// # Errors
///
/// Returns the first commit, configuration, or source-pin mismatch.
pub fn validate_metadata_theorem_candidate_v2(
    candidate: &MetadataTheoremCandidateV2,
) -> Result<CompiledMetadataTheoremV2, MetadataModelErrorV2> {
    if candidate.linux_commit != LINUX_COMMIT_V2 {
        return Err(MetadataModelErrorV2::LinuxCommitBinding);
    }
    if candidate.required_config.len() != REQUIRED_KERNEL_CONFIG_V2.len() {
        return Err(MetadataModelErrorV2::ConfigurationCardinality);
    }
    for (index, (actual, expected)) in candidate
        .required_config
        .iter()
        .zip(REQUIRED_KERNEL_CONFIG_V2)
        .enumerate()
    {
        if actual.symbol != expected.symbol || actual.state != expected.state {
            return Err(MetadataModelErrorV2::ConfigurationBinding { index });
        }
    }
    if candidate.source_pins.len() != LINUX_SOURCE_PINS_V2.len() {
        return Err(MetadataModelErrorV2::SourceCardinality);
    }
    for (index, (actual, expected)) in candidate
        .source_pins
        .iter()
        .zip(LINUX_SOURCE_PINS_V2)
        .enumerate()
    {
        if actual.path != expected.path || actual.sha256_hex != expected.sha256_hex {
            return Err(MetadataModelErrorV2::SourceBinding { index });
        }
    }

    let theorem_basis_sha256 = theorem_basis_sha256();
    if hex::encode(theorem_basis_sha256) != THEOREM_BASIS_SHA256_HEX_V2 {
        return Err(MetadataModelErrorV2::CompiledIdentityDrift);
    }
    let expected_mode_table_sha256 = expected_mode_table_sha256(theorem_basis_sha256);
    if hex::encode(expected_mode_table_sha256) != EXPECTED_MODE_TABLE_SHA256_HEX_V2 {
        return Err(MetadataModelErrorV2::CompiledIdentityDrift);
    }
    Ok(CompiledMetadataTheoremV2 {
        theorem_basis_sha256,
        expected_mode_table_sha256,
    })
}

/// Bind a compiled theorem declaration to exact nonzero image identities.
///
/// The result records equality and digest bindings only. It authenticates none
/// of the supplied digests and cannot authorize any runtime transition.
///
/// # Errors
///
/// Returns the first theorem mismatch or an all-zero image identity digest.
pub fn bind_metadata_profile_v2(
    binding: &MetadataProfileBindingV2,
) -> Result<MetadataProfileIdentityV2, MetadataModelErrorV2> {
    let theorem = validate_metadata_theorem_candidate_v2(&binding.theorem)?;
    if [
        binding.resolved_config_sha256,
        binding.boot_image_sha256,
        binding.dynamic_extension_state_sha256,
    ]
    .contains(&[0; 32])
    {
        return Err(MetadataModelErrorV2::ProfileDigestMissing);
    }

    let mut hasher = Sha256::new();
    hash_field(&mut hasher, PROFILE_DOMAIN_V2);
    hash_field(&mut hasher, FILESYSTEM_TYPE_V2);
    hash_field(&mut hasher, &theorem.theorem_basis_sha256);
    hash_field(&mut hasher, &theorem.expected_mode_table_sha256);
    hash_field(&mut hasher, &binding.resolved_config_sha256);
    hash_field(&mut hasher, &binding.boot_image_sha256);
    hash_field(&mut hasher, &binding.dynamic_extension_state_sha256);
    let profile_identity_sha256 = finish_sha256(hasher);

    Ok(MetadataProfileIdentityV2 {
        theorem_basis_sha256: theorem.theorem_basis_sha256,
        expected_mode_table_sha256: theorem.expected_mode_table_sha256,
        resolved_config_sha256: binding.resolved_config_sha256,
        boot_image_sha256: binding.boot_image_sha256,
        dynamic_extension_state_sha256: binding.dynamic_extension_state_sha256,
        profile_identity_sha256,
    })
}

/// Compute `11 * (1 + 4 + N_D + N_F + N_L)` with checked arithmetic.
///
/// # Errors
///
/// Returns [`MetadataModelErrorV2::CardinalityOverflow`] on any overflow.
pub fn expected_physical_cell_count_v2(
    counts: DynamicSubjectCountsV2,
) -> Result<usize, MetadataModelErrorV2> {
    let dynamic = counts
        .retained_directories
        .checked_add(counts.retained_regular_files)
        .and_then(|value| value.checked_add(counts.retained_symbolic_links))
        .ok_or(MetadataModelErrorV2::CardinalityOverflow)?;
    let subjects = 1_usize
        .checked_add(CANONICAL_ROLES.len())
        .and_then(|value| value.checked_add(dynamic))
        .ok_or(MetadataModelErrorV2::CardinalityOverflow)?;
    subjects
        .checked_mul(PROHIBITED_METADATA_CLASSES_V2.len())
        .ok_or(MetadataModelErrorV2::CardinalityOverflow)
}

/// Validate the complete pure physical-packet shape against the compiled V2
/// theorem and profile bindings.
///
/// Success proves only internal structural agreement of the supplied values.
/// It does not prove that any filesystem or descriptor existed.
///
/// # Errors
///
/// Returns the first root-seed, subject, cardinality, binding, mode, mask, or
/// attribute failure.
pub fn validate_retained_rootfs_metadata_packet_v2(
    packet: &RetainedRootfsMetadataPacketV2,
) -> Result<(), MetadataModelErrorV2> {
    validate_root_seed(packet.root_seed)?;
    let counts = validate_subjects(&packet.subjects)?;
    if counts != packet.claimed_counts {
        return Err(MetadataModelErrorV2::DynamicSubjectCount);
    }

    let claimed_cells = expected_physical_cell_count_v2(packet.claimed_counts)?;
    let inventory_cells = packet
        .subjects
        .len()
        .checked_mul(PROHIBITED_METADATA_CLASSES_V2.len())
        .ok_or(MetadataModelErrorV2::CardinalityOverflow)?;
    if claimed_cells != inventory_cells || packet.cells.len() != inventory_cells {
        return Err(MetadataModelErrorV2::CellCardinality);
    }

    for (subject_ordinal, subject) in packet.subjects.iter().enumerate() {
        for (class_ordinal, class) in PROHIBITED_METADATA_CLASSES_V2.into_iter().enumerate() {
            let ordinal = subject_ordinal
                .checked_mul(PROHIBITED_METADATA_CLASSES_V2.len())
                .and_then(|value| value.checked_add(class_ordinal))
                .ok_or(MetadataModelErrorV2::CardinalityOverflow)?;
            validate_cell(packet, &packet.cells[ordinal], subject, class, ordinal)?;
        }
    }
    Ok(())
}

fn validate_root_seed(seed: Option<MountRootSeedV2>) -> Result<(), MetadataModelErrorV2> {
    let seed = seed.ok_or(MetadataModelErrorV2::MountRootSeedMissing)?;
    if seed.inode_flags != 0 || seed.shmem_fsflags != 0 {
        return Err(MetadataModelErrorV2::MountRootSeedNonzero);
    }
    Ok(())
}

fn validate_subjects(
    subjects: &[MetadataSubjectIdentityV2],
) -> Result<DynamicSubjectCountsV2, MetadataModelErrorV2> {
    let mount_root = subjects
        .first()
        .ok_or(MetadataModelErrorV2::MountRootSubjectMissing)?;
    if mount_root.kind != MetadataSubjectKindV2::MountRoot {
        return Err(MetadataModelErrorV2::MountRootSubjectMissing);
    }

    let mut identities = BTreeSet::new();
    for (ordinal, subject) in subjects.iter().enumerate() {
        validate_subject_shape(subject, ordinal)?;
        if subject.descriptor.mount_id_unique == 0
            || subject.descriptor.inode == 0
            || subject.mount_epoch == [0; 32]
        {
            return Err(MetadataModelErrorV2::SubjectIdentity { ordinal });
        }
        if subject.descriptor.mount_id_unique != mount_root.descriptor.mount_id_unique
            || subject.descriptor.device_major != mount_root.descriptor.device_major
            || subject.descriptor.device_minor != mount_root.descriptor.device_minor
            || subject.mount_epoch != mount_root.mount_epoch
        {
            return Err(MetadataModelErrorV2::SubjectMountBinding { ordinal });
        }
        if !identities.insert(subject.descriptor) {
            return Err(MetadataModelErrorV2::SubjectAlias { ordinal });
        }
    }

    let mut cursor = 1_usize;
    let mut counts = DynamicSubjectCountsV2 {
        retained_directories: 0,
        retained_regular_files: 0,
        retained_symbolic_links: 0,
    };
    for role in CANONICAL_ROLES {
        require_subject(
            subjects,
            cursor,
            MetadataSubjectKindV2::RoleRoot,
            role,
            None,
        )?;
        cursor += 1;
        cursor = consume_dynamic_kind(
            subjects,
            cursor,
            role,
            MetadataSubjectKindV2::RetainedDirectory,
            &mut counts.retained_directories,
        )?;
        cursor = consume_dynamic_kind(
            subjects,
            cursor,
            role,
            MetadataSubjectKindV2::RetainedRegularFile,
            &mut counts.retained_regular_files,
        )?;
        cursor = consume_dynamic_kind(
            subjects,
            cursor,
            role,
            MetadataSubjectKindV2::RetainedSymbolicLink,
            &mut counts.retained_symbolic_links,
        )?;
    }
    if cursor != subjects.len() {
        return Err(MetadataModelErrorV2::SubjectOrder { ordinal: cursor });
    }
    Ok(counts)
}

fn validate_subject_shape(
    subject: &MetadataSubjectIdentityV2,
    ordinal: usize,
) -> Result<(), MetadataModelErrorV2> {
    let valid = match subject.kind {
        MetadataSubjectKindV2::MountRoot => subject.role.is_none() && subject.entry_index.is_none(),
        MetadataSubjectKindV2::RoleRoot => subject.role.is_some() && subject.entry_index.is_none(),
        MetadataSubjectKindV2::RetainedDirectory
        | MetadataSubjectKindV2::RetainedRegularFile
        | MetadataSubjectKindV2::RetainedSymbolicLink => {
            subject.role.is_some() && subject.entry_index.is_some()
        }
    };
    if !valid {
        return Err(MetadataModelErrorV2::SubjectShape { ordinal });
    }
    Ok(())
}

fn require_subject(
    subjects: &[MetadataSubjectIdentityV2],
    ordinal: usize,
    kind: MetadataSubjectKindV2,
    role: PositiveRunnerRole,
    entry_index: Option<u64>,
) -> Result<(), MetadataModelErrorV2> {
    let Some(subject) = subjects.get(ordinal) else {
        return Err(MetadataModelErrorV2::SubjectOrder { ordinal });
    };
    if subject.kind != kind || subject.role != Some(role) || subject.entry_index != entry_index {
        return Err(MetadataModelErrorV2::SubjectOrder { ordinal });
    }
    Ok(())
}

fn consume_dynamic_kind(
    subjects: &[MetadataSubjectIdentityV2],
    mut cursor: usize,
    role: PositiveRunnerRole,
    kind: MetadataSubjectKindV2,
    aggregate_count: &mut usize,
) -> Result<usize, MetadataModelErrorV2> {
    let mut entry_index = 0_u64;
    while let Some(subject) = subjects.get(cursor) {
        if subject.kind != kind || subject.role != Some(role) {
            break;
        }
        if subject.entry_index != Some(entry_index) {
            return Err(MetadataModelErrorV2::SubjectOrder { ordinal: cursor });
        }
        *aggregate_count = aggregate_count
            .checked_add(1)
            .ok_or(MetadataModelErrorV2::CardinalityOverflow)?;
        entry_index = entry_index
            .checked_add(1)
            .ok_or(MetadataModelErrorV2::CardinalityOverflow)?;
        cursor = cursor
            .checked_add(1)
            .ok_or(MetadataModelErrorV2::CardinalityOverflow)?;
    }
    Ok(cursor)
}

fn validate_cell(
    packet: &RetainedRootfsMetadataPacketV2,
    cell: &MetadataCellRecordV2,
    subject: &MetadataSubjectIdentityV2,
    class: ProhibitedMetadataClassV2,
    ordinal: usize,
) -> Result<(), MetadataModelErrorV2> {
    if cell.subject != *subject {
        return Err(MetadataModelErrorV2::CellSubjectBinding { ordinal });
    }
    if cell.class != class {
        return Err(MetadataModelErrorV2::CellClassOrder { ordinal });
    }
    if cell.expected_mode_table_sha256 != packet.profile.expected_mode_table_sha256 {
        return Err(MetadataModelErrorV2::CellTableBinding { ordinal });
    }
    if cell.profile_identity_sha256 != packet.profile.profile_identity_sha256 {
        return Err(MetadataModelErrorV2::CellProfileBinding { ordinal });
    }
    let expected_mode = expected_metadata_mode_v2(class, subject.kind);
    if cell.mode != expected_mode {
        return Err(MetadataModelErrorV2::CellMode { ordinal });
    }

    match expected_mode {
        ExpectedMetadataModeV2::ObservedAbsentComplete => {
            let Some(mask) = cell.attribute_mask else {
                return Err(MetadataModelErrorV2::ObservedMaskMissing { ordinal });
            };
            let Some(attributes) = cell.attributes else {
                return Err(MetadataModelErrorV2::ObservedMaskMissing { ordinal });
            };
            let bit = class
                .observed_statx_bit()
                .ok_or(MetadataModelErrorV2::ObservedMaskUnknown { ordinal })?;
            if mask & bit != bit {
                return Err(MetadataModelErrorV2::ObservedMaskUnknown { ordinal });
            }
            if attributes & bit != 0 {
                return Err(MetadataModelErrorV2::ObservedAttributePresent { ordinal });
            }
        }
        ExpectedMetadataModeV2::StructurallyUnrepresentable => {
            if cell.attribute_mask.is_some() || cell.attributes.is_some() {
                return Err(MetadataModelErrorV2::StructuralObservationPresent { ordinal });
            }
        }
    }
    Ok(())
}

fn theorem_basis_sha256() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, THEOREM_DOMAIN_V2);
    hash_field(&mut hasher, LINUX_COMMIT_V2.as_bytes());
    for requirement in REQUIRED_KERNEL_CONFIG_V2 {
        hash_field(&mut hasher, requirement.symbol.as_bytes());
        hash_field(&mut hasher, &[requirement.state as u8]);
    }
    for requirement in LINUX_SOURCE_PINS_V2 {
        hash_field(&mut hasher, requirement.path.as_bytes());
        hash_field(&mut hasher, requirement.sha256_hex.as_bytes());
    }
    finish_sha256(hasher)
}

fn expected_mode_table_sha256(theorem_basis_sha256: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, TABLE_DOMAIN_V2);
    hash_field(&mut hasher, &theorem_basis_sha256);
    for cell in EXPECTED_MODE_TABLE_V2 {
        hash_field(&mut hasher, &[cell.class as u8]);
        hash_field(&mut hasher, &[cell.kind as u8]);
        hash_field(&mut hasher, &[cell.mode as u8]);
    }
    finish_sha256(hasher)
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    let length = u128::try_from(bytes.len()).expect("usize always fits in u128");
    hasher.update(length.to_le_bytes());
    hasher.update(bytes);
}

fn finish_sha256(hasher: Sha256) -> [u8; 32] {
    let digest = hasher.finalize();
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    output
}
