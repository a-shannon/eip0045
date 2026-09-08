#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Safe, non-authorizing values shared by the H0 appliance roles.

pub mod executable;
pub mod mount;
pub mod state;
pub mod wire;

pub use wire::{encode_fd_commitment_v1, encoded_fd_commitment_len_v1};

use core::fmt;

/// The only provider-profile identity selected by the H0 V2 design.
pub const PROVIDER_PROFILE_ID_V1: &str = "eip0045-b4-tmpfs-metadata-provider-v1";

/// The exact number of role-ordered replay plans in one aggregate attempt.
pub const REPLAY_PLAN_COUNT: usize = 4;

const MOUNT_ROOT_INODES: u64 = 1;
const ROLE_ROOT_INODES: u64 = REPLAY_PLAN_COUNT as u64;
const TMPFS_INTERNAL_RESERVE_PAGES: u64 = 1;

/// A scalar whose checked operation failed while deriving capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityTermV2 {
    /// Number of retained OCI entries.
    EntryCount,
    /// Sum of content bytes within one replay plan.
    PlanContentBytes,
    /// Per-entry content length rounded to the authenticated page size.
    RoundedContentBytes,
    /// Sum of rounded payload pages.
    PayloadPages,
    /// Permanent inode count for the mount root, role roots, and entries.
    FinalInodes,
    /// Permanent plus qualified transient inode count.
    InodeLimit,
    /// Permanent, qualified transient, and tmpfs-internal reserve pages.
    ReservePages,
    /// Payload plus reserve pages.
    AllocatedPages,
    /// Exact tmpfs byte limit.
    SizeBytes,
    /// Tmpfs byte limit plus the measured process reserve.
    RequiredMemoryBytes,
}

/// A malformed fixed-profile field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileFieldV2 {
    /// Authenticated page size.
    PageSize,
    /// Minimum hardware memory guaranteed by the selected profile.
    MinimumHardwareMemoryBytes,
    /// Attempt cgroup memory ceiling.
    CgroupMemoryCeilingBytes,
    /// Maximum entries in one role-specific logical plan.
    MaximumEntries,
    /// Maximum bytes in one regular-file or symbolic-link payload.
    MaximumContentBytesPerEntry,
}

/// A fail-closed capacity or profile error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityErrorV2 {
    /// A fixed profile field is zero or internally inconsistent.
    InvalidProfileField(ProfileFieldV2),
    /// The aggregate does not contain exactly four plans.
    PlanCount {
        /// Observed plan count.
        actual: usize,
        /// Required plan count.
        expected: usize,
    },
    /// A plan appears at the wrong canonical role ordinal.
    PlanRoleOrder {
        /// Plan ordinal.
        index: usize,
        /// Role required at this ordinal.
        expected: ReplayRoleV2,
        /// Role supplied at this ordinal.
        actual: ReplayRoleV2,
    },
    /// A plan was projected under different provider-capacity terms.
    PlanProfileDrift {
        /// Role of the mismatched plan.
        role: ReplayRoleV2,
    },
    /// One plan contains more entries than its role-specific logical bound.
    PlanEntryLimitExceeded {
        /// Role of the rejected plan.
        role: ReplayRoleV2,
        /// Observed entry count.
        actual: u64,
        /// Role-specific maximum.
        maximum: u64,
    },
    /// One payload is larger than its role-specific logical bound.
    EntryContentLimitExceeded {
        /// Role of the rejected plan.
        role: ReplayRoleV2,
        /// Zero-based entry ordinal.
        entry_index: usize,
        /// Observed payload length.
        actual: u64,
        /// Role-specific maximum.
        maximum: u64,
    },
    /// One plan's summed payload bytes exceed its logical bound.
    PlanContentLimitExceeded {
        /// Role of the rejected plan.
        role: ReplayRoleV2,
        /// Observed payload-byte sum.
        actual: u64,
        /// Role-specific maximum.
        maximum: u64,
    },
    /// The four-plan entry sum exceeds the provider-profile aggregate bound.
    AggregateEntryLimitExceeded {
        /// Observed aggregate entry count.
        actual: u64,
        /// Profile-fixed aggregate maximum.
        maximum: u64,
    },
    /// The four-plan payload-byte sum exceeds the provider-profile aggregate bound.
    AggregateContentLimitExceeded {
        /// Observed aggregate payload-byte sum.
        actual: u64,
        /// Profile-fixed aggregate maximum.
        maximum: u64,
    },
    /// A named checked arithmetic operation overflowed.
    ArithmeticOverflow(CapacityTermV2),
    /// The request plus process reserve exceeds the profile's hardware minimum.
    HardwareMemoryAdmission {
        /// Bytes required by tmpfs and the measured processes.
        required: u64,
        /// Bytes guaranteed by the profile's minimum hardware declaration.
        minimum: u64,
    },
    /// The request plus process reserve exceeds the attempt cgroup ceiling.
    CgroupMemoryAdmission {
        /// Bytes required by tmpfs and the measured processes.
        required: u64,
        /// Profile-fixed cgroup ceiling.
        ceiling: u64,
    },
}

impl fmt::Display for CapacityErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "H0 capacity contract rejected input: {self:?}")
    }
}

impl std::error::Error for CapacityErrorV2 {}

/// Logical OCI bounds for one canonical replay role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogicalPlanBoundsV2 {
    entries: u64,
    content_bytes_per_entry: u64,
    content_bytes: u64,
}

impl LogicalPlanBoundsV2 {
    /// Validates one closed role-specific logical bound.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityErrorV2::InvalidProfileField`] when the entry bound is
    /// zero or the per-entry payload bound exceeds the complete-plan bound.
    pub const fn try_new(
        maximum_entries: u64,
        maximum_content_bytes_per_entry: u64,
        maximum_content_bytes: u64,
    ) -> Result<Self, CapacityErrorV2> {
        if maximum_entries == 0 {
            return Err(CapacityErrorV2::InvalidProfileField(
                ProfileFieldV2::MaximumEntries,
            ));
        }
        if maximum_content_bytes_per_entry > maximum_content_bytes {
            return Err(CapacityErrorV2::InvalidProfileField(
                ProfileFieldV2::MaximumContentBytesPerEntry,
            ));
        }
        Ok(Self {
            entries: maximum_entries,
            content_bytes_per_entry: maximum_content_bytes_per_entry,
            content_bytes: maximum_content_bytes,
        })
    }

    /// Returns the maximum entry count.
    #[must_use]
    pub const fn maximum_entries(self) -> u64 {
        self.entries
    }

    /// Returns the maximum payload length of one entry.
    #[must_use]
    pub const fn maximum_content_bytes_per_entry(self) -> u64 {
        self.content_bytes_per_entry
    }

    /// Returns the maximum summed payload bytes of one plan.
    #[must_use]
    pub const fn maximum_content_bytes(self) -> u64 {
        self.content_bytes
    }
}

/// Exact non-authorizing capacity inputs copied from a qualified provider profile.
///
/// Constructing this value does not authenticate a profile. The runtime owner
/// must bind these fields to the externally qualified profile before using the
/// resulting request in a live session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderCapacityParametersV2 {
    /// Authenticated kernel page size.
    pub page_size: u64,
    /// Peak transient inode count rederived from the serial replay schedule.
    pub qualified_peak_transient_inodes: u64,
    /// Peak transient page count rederived from the serial replay schedule.
    pub qualified_peak_transient_pages: u64,
    /// Memory guaranteed by the profile's minimum supported hardware.
    pub minimum_hardware_memory_bytes: u64,
    /// Memory ceiling of one attempt cgroup.
    pub cgroup_memory_ceiling_bytes: u64,
    /// Measured aggregate reserve for the supervisor, generator, and worker.
    pub process_reserve_bytes: u64,
    /// Logical bounds in canonical replay-role order.
    pub logical_plan_bounds: [LogicalPlanBoundsV2; REPLAY_PLAN_COUNT],
    /// Maximum retained entries across all four role plans.
    pub maximum_aggregate_entries: u64,
    /// Maximum payload bytes across all four role plans.
    pub maximum_aggregate_content_bytes: u64,
}

/// Validated capacity terms for the selected provider profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderCapacityProfileV2 {
    parameters: ProviderCapacityParametersV2,
}

impl ProviderCapacityProfileV2 {
    /// Validates the scalar shape of exact externally qualified profile terms.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityErrorV2::InvalidProfileField`] when page size, minimum
    /// hardware memory, or the cgroup ceiling is zero.
    pub const fn try_new(
        parameters: ProviderCapacityParametersV2,
    ) -> Result<Self, CapacityErrorV2> {
        if parameters.page_size == 0 {
            return Err(CapacityErrorV2::InvalidProfileField(
                ProfileFieldV2::PageSize,
            ));
        }
        if parameters.minimum_hardware_memory_bytes == 0 {
            return Err(CapacityErrorV2::InvalidProfileField(
                ProfileFieldV2::MinimumHardwareMemoryBytes,
            ));
        }
        if parameters.cgroup_memory_ceiling_bytes == 0 {
            return Err(CapacityErrorV2::InvalidProfileField(
                ProfileFieldV2::CgroupMemoryCeilingBytes,
            ));
        }
        Ok(Self { parameters })
    }

    /// Returns the fixed provider-profile identity.
    #[must_use]
    pub const fn identity(&self) -> &'static str {
        PROVIDER_PROFILE_ID_V1
    }

    /// Returns the authenticated page size.
    #[must_use]
    pub const fn page_size(&self) -> u64 {
        self.parameters.page_size
    }

    /// Returns the profile-fixed transient inode peak.
    #[must_use]
    pub const fn qualified_peak_transient_inodes(&self) -> u64 {
        self.parameters.qualified_peak_transient_inodes
    }

    /// Returns the profile-fixed transient page peak.
    #[must_use]
    pub const fn qualified_peak_transient_pages(&self) -> u64 {
        self.parameters.qualified_peak_transient_pages
    }

    /// Returns the profile's minimum supported hardware memory.
    #[must_use]
    pub const fn minimum_hardware_memory_bytes(&self) -> u64 {
        self.parameters.minimum_hardware_memory_bytes
    }

    /// Returns the profile-fixed attempt cgroup ceiling.
    #[must_use]
    pub const fn cgroup_memory_ceiling_bytes(&self) -> u64 {
        self.parameters.cgroup_memory_ceiling_bytes
    }

    /// Returns the measured supervisor/generator/worker process reserve.
    #[must_use]
    pub const fn process_reserve_bytes(&self) -> u64 {
        self.parameters.process_reserve_bytes
    }

    /// Returns the profile-fixed four-plan entry maximum.
    #[must_use]
    pub const fn maximum_aggregate_entries(&self) -> u64 {
        self.parameters.maximum_aggregate_entries
    }

    /// Returns the profile-fixed four-plan payload-byte maximum.
    #[must_use]
    pub const fn maximum_aggregate_content_bytes(&self) -> u64 {
        self.parameters.maximum_aggregate_content_bytes
    }

    /// Returns the logical bound for one canonical replay role.
    #[must_use]
    pub const fn logical_bounds(&self, role: ReplayRoleV2) -> LogicalPlanBoundsV2 {
        self.parameters.logical_plan_bounds[role.ordinal()]
    }
}

/// Canonical role of one authenticated replay plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayRoleV2 {
    /// Rust validator build rootfs.
    RustValidatorBuild,
    /// JVM validator build rootfs.
    JvmValidatorBuild,
    /// Rust verifier rootfs.
    RustVerifier,
    /// JVM verifier rootfs.
    JvmVerifier,
}

impl ReplayRoleV2 {
    /// Roles in the only accepted aggregate order.
    pub const ALL: [Self; REPLAY_PLAN_COUNT] = [
        Self::RustValidatorBuild,
        Self::JvmValidatorBuild,
        Self::RustVerifier,
        Self::JvmVerifier,
    ];

    const fn ordinal(self) -> usize {
        match self {
            Self::RustValidatorBuild => 0,
            Self::JvmValidatorBuild => 1,
            Self::RustVerifier => 2,
            Self::JvmVerifier => 3,
        }
    }
}

/// The capacity contribution of one retained OCI entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayEntryCapacityV2 {
    /// A directory contributes one inode and no payload page.
    Directory,
    /// A regular file contributes one inode and its authenticated byte length.
    RegularFile {
        /// Authenticated content length.
        content_length: u64,
    },
    /// A symbolic link contributes one inode and its authenticated target length.
    SymbolicLink {
        /// Authenticated target length.
        content_length: u64,
    },
}

impl ReplayEntryCapacityV2 {
    const fn content_length(self) -> u64 {
        match self {
            Self::Directory => 0,
            Self::RegularFile { content_length } | Self::SymbolicLink { content_length } => {
                content_length
            }
        }
    }
}

/// A role-bound, non-authorizing projection of one complete replay-plan inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayPlanCapacityV2 {
    profile: ProviderCapacityProfileV2,
    role: ReplayRoleV2,
    entry_count: u64,
    content_bytes: u64,
    payload_pages: u64,
}

impl ReplayPlanCapacityV2 {
    /// Projects a complete role inventory under exact provider-profile terms.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`CapacityErrorV2`] when entry cardinality, an
    /// individual payload, the plan payload sum, page rounding, or page-count
    /// accumulation violates the exact profile.
    pub fn try_from_entries(
        profile: &ProviderCapacityProfileV2,
        role: ReplayRoleV2,
        entries: &[ReplayEntryCapacityV2],
    ) -> Result<Self, CapacityErrorV2> {
        let bounds = profile.logical_bounds(role);
        let entry_count = u64::try_from(entries.len())
            .map_err(|_| CapacityErrorV2::ArithmeticOverflow(CapacityTermV2::EntryCount))?;
        if entry_count > bounds.maximum_entries() {
            return Err(CapacityErrorV2::PlanEntryLimitExceeded {
                role,
                actual: entry_count,
                maximum: bounds.maximum_entries(),
            });
        }

        let mut content_bytes = 0_u64;
        let mut payload_pages = 0_u64;
        for (entry_index, entry) in entries.iter().copied().enumerate() {
            let content_length = entry.content_length();
            if content_length > bounds.maximum_content_bytes_per_entry() {
                return Err(CapacityErrorV2::EntryContentLimitExceeded {
                    role,
                    entry_index,
                    actual: content_length,
                    maximum: bounds.maximum_content_bytes_per_entry(),
                });
            }
            content_bytes = checked_add(
                content_bytes,
                content_length,
                CapacityTermV2::PlanContentBytes,
            )?;
            if content_bytes > bounds.maximum_content_bytes() {
                return Err(CapacityErrorV2::PlanContentLimitExceeded {
                    role,
                    actual: content_bytes,
                    maximum: bounds.maximum_content_bytes(),
                });
            }
            let rounded = checked_round_up(
                content_length,
                profile.page_size(),
                CapacityTermV2::RoundedContentBytes,
            )?;
            payload_pages = checked_add(
                payload_pages,
                rounded / profile.page_size(),
                CapacityTermV2::PayloadPages,
            )?;
        }

        Ok(Self {
            profile: *profile,
            role,
            entry_count,
            content_bytes,
            payload_pages,
        })
    }

    /// Returns this plan's canonical role.
    #[must_use]
    pub const fn role(&self) -> ReplayRoleV2 {
        self.role
    }

    /// Returns the complete retained-entry count.
    #[must_use]
    pub const fn entry_count(&self) -> u64 {
        self.entry_count
    }

    /// Returns the summed regular-file and symbolic-link content bytes.
    #[must_use]
    pub const fn content_bytes(&self) -> u64 {
        self.content_bytes
    }

    /// Returns the sum of independently rounded content pages.
    #[must_use]
    pub const fn payload_pages(&self) -> u64 {
        self.payload_pages
    }
}

/// Checked aggregate terms from which the fixed tmpfs request is derived.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityTermsV2 {
    profile: ProviderCapacityProfileV2,
    entry_count: u64,
    final_inodes: u64,
    inode_limit: u64,
    payload_pages: u64,
    reserve_pages: u64,
    size_bytes: u64,
    required_memory_bytes: u64,
}

impl CapacityTermsV2 {
    /// Returns the exact provider-capacity profile used for this derivation.
    #[must_use]
    pub const fn profile(&self) -> &ProviderCapacityProfileV2 {
        &self.profile
    }

    /// Returns the complete entry count across four roles.
    #[must_use]
    pub const fn entry_count(&self) -> u64 {
        self.entry_count
    }

    /// Returns `1 M + 4 R_i + |E|`.
    #[must_use]
    pub const fn final_inodes(&self) -> u64 {
        self.final_inodes
    }

    /// Returns permanent plus qualified transient inodes.
    #[must_use]
    pub const fn inode_limit(&self) -> u64 {
        self.inode_limit
    }

    /// Returns the sum of per-entry rounded payload pages.
    #[must_use]
    pub const fn payload_pages(&self) -> u64 {
        self.payload_pages
    }

    /// Returns permanent, qualified transient, and internal reserve pages.
    #[must_use]
    pub const fn reserve_pages(&self) -> u64 {
        self.reserve_pages
    }

    /// Returns the exact tmpfs byte limit.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Returns tmpfs bytes plus the measured S/G/W process reserve.
    #[must_use]
    pub const fn required_memory_bytes(&self) -> u64 {
        self.required_memory_bytes
    }
}

fn derive_capacity_terms_v2(
    profile: &ProviderCapacityProfileV2,
    plans: &[ReplayPlanCapacityV2],
) -> Result<CapacityTermsV2, CapacityErrorV2> {
    let aggregate = aggregate_replay_plans(profile, plans)?;

    let permanent_roots = checked_add(
        MOUNT_ROOT_INODES,
        ROLE_ROOT_INODES,
        CapacityTermV2::FinalInodes,
    )?;
    let final_inodes = checked_add(
        permanent_roots,
        aggregate.entry_count,
        CapacityTermV2::FinalInodes,
    )?;
    let inode_limit = checked_add(
        final_inodes,
        profile.qualified_peak_transient_inodes(),
        CapacityTermV2::InodeLimit,
    )?;
    let reserve_pages = checked_add(
        checked_add(
            final_inodes,
            profile.qualified_peak_transient_pages(),
            CapacityTermV2::ReservePages,
        )?,
        TMPFS_INTERNAL_RESERVE_PAGES,
        CapacityTermV2::ReservePages,
    )?;
    let allocated_pages = checked_add(
        aggregate.payload_pages,
        reserve_pages,
        CapacityTermV2::AllocatedPages,
    )?;
    let size_bytes = checked_mul(
        allocated_pages,
        profile.page_size(),
        CapacityTermV2::SizeBytes,
    )?;
    let required_memory_bytes = checked_add(
        size_bytes,
        profile.process_reserve_bytes(),
        CapacityTermV2::RequiredMemoryBytes,
    )?;

    admit_memory(profile, required_memory_bytes)?;

    Ok(CapacityTermsV2 {
        profile: *profile,
        entry_count: aggregate.entry_count,
        final_inodes,
        inode_limit,
        payload_pages: aggregate.payload_pages,
        reserve_pages,
        size_bytes,
        required_memory_bytes,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AggregateCapacityV2 {
    entry_count: u64,
    payload_pages: u64,
}

fn aggregate_replay_plans(
    profile: &ProviderCapacityProfileV2,
    plans: &[ReplayPlanCapacityV2],
) -> Result<AggregateCapacityV2, CapacityErrorV2> {
    if plans.len() != REPLAY_PLAN_COUNT {
        return Err(CapacityErrorV2::PlanCount {
            actual: plans.len(),
            expected: REPLAY_PLAN_COUNT,
        });
    }

    let mut entry_count = 0_u64;
    let mut aggregate_content_bytes = 0_u64;
    let mut payload_pages = 0_u64;
    for (index, (plan, expected_role)) in plans
        .iter()
        .zip(ReplayRoleV2::ALL.iter().copied())
        .enumerate()
    {
        if plan.role != expected_role {
            return Err(CapacityErrorV2::PlanRoleOrder {
                index,
                expected: expected_role,
                actual: plan.role,
            });
        }
        if plan.profile != *profile {
            return Err(CapacityErrorV2::PlanProfileDrift { role: plan.role });
        }

        let bounds = profile.logical_bounds(plan.role);
        if plan.entry_count > bounds.maximum_entries() {
            return Err(CapacityErrorV2::PlanEntryLimitExceeded {
                role: plan.role,
                actual: plan.entry_count,
                maximum: bounds.maximum_entries(),
            });
        }
        if plan.content_bytes > bounds.maximum_content_bytes() {
            return Err(CapacityErrorV2::PlanContentLimitExceeded {
                role: plan.role,
                actual: plan.content_bytes,
                maximum: bounds.maximum_content_bytes(),
            });
        }

        entry_count = checked_add(entry_count, plan.entry_count, CapacityTermV2::EntryCount)?;
        aggregate_content_bytes = checked_add(
            aggregate_content_bytes,
            plan.content_bytes,
            CapacityTermV2::PlanContentBytes,
        )?;
        payload_pages = checked_add(
            payload_pages,
            plan.payload_pages,
            CapacityTermV2::PayloadPages,
        )?;
    }

    if entry_count > profile.maximum_aggregate_entries() {
        return Err(CapacityErrorV2::AggregateEntryLimitExceeded {
            actual: entry_count,
            maximum: profile.maximum_aggregate_entries(),
        });
    }
    if aggregate_content_bytes > profile.maximum_aggregate_content_bytes() {
        return Err(CapacityErrorV2::AggregateContentLimitExceeded {
            actual: aggregate_content_bytes,
            maximum: profile.maximum_aggregate_content_bytes(),
        });
    }

    Ok(AggregateCapacityV2 {
        entry_count,
        payload_pages,
    })
}

fn admit_memory(
    profile: &ProviderCapacityProfileV2,
    required_memory_bytes: u64,
) -> Result<(), CapacityErrorV2> {
    if required_memory_bytes > profile.minimum_hardware_memory_bytes() {
        return Err(CapacityErrorV2::HardwareMemoryAdmission {
            required: required_memory_bytes,
            minimum: profile.minimum_hardware_memory_bytes(),
        });
    }
    if required_memory_bytes > profile.cgroup_memory_ceiling_bytes() {
        return Err(CapacityErrorV2::CgroupMemoryAdmission {
            required: required_memory_bytes,
            ceiling: profile.cgroup_memory_ceiling_bytes(),
        });
    }

    Ok(())
}

fn checked_add(left: u64, right: u64, term: CapacityTermV2) -> Result<u64, CapacityErrorV2> {
    left.checked_add(right)
        .ok_or(CapacityErrorV2::ArithmeticOverflow(term))
}

fn checked_mul(left: u64, right: u64, term: CapacityTermV2) -> Result<u64, CapacityErrorV2> {
    left.checked_mul(right)
        .ok_or(CapacityErrorV2::ArithmeticOverflow(term))
}

fn checked_round_up(
    value: u64,
    multiple: u64,
    term: CapacityTermV2,
) -> Result<u64, CapacityErrorV2> {
    if multiple == 0 {
        return Err(CapacityErrorV2::InvalidProfileField(
            ProfileFieldV2::PageSize,
        ));
    }
    let remainder = value % multiple;
    if remainder == 0 {
        return Ok(value);
    }
    checked_add(value, multiple - remainder, term)
}

/// Filesystem type fixed by the H0 provider profile.
pub const TMPFS_FILESYSTEM_TYPE_V2: &str = "tmpfs";
/// Root mode fixed by the H0 provider profile.
pub const TMPFS_ROOT_MODE_V2: u16 = 0o700;
/// Inner user and group owner fixed by the H0 provider profile.
pub const TMPFS_INNER_OWNER_V2: u32 = 0;

const MOUNT_VFS_FLAG_COUNT: usize = 4;
const MOUNT_DATA_OPTION_COUNT: usize = 5;

/// One member of the exact ordered VFS-mode projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountVfsFlagV2 {
    /// The mount is read-write.
    ReadWrite,
    /// Set-user-ID and set-group-ID bits are not honored.
    NoSuid,
    /// Device special files cannot be used.
    NoDev,
    /// Files cannot be executed from the mount.
    NoExec,
}

const FIXED_MOUNT_VFS_FLAGS: [MountVfsFlagV2; MOUNT_VFS_FLAG_COUNT] = [
    MountVfsFlagV2::ReadWrite,
    MountVfsFlagV2::NoSuid,
    MountVfsFlagV2::NoDev,
    MountVfsFlagV2::NoExec,
];

/// One member of the exact ordered tmpfs data-option projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountDataOptionV2 {
    /// Exact checked tmpfs byte capacity.
    SizeBytes(u64),
    /// Exact checked inode capacity.
    InodeLimit(u64),
    /// Exact root mode.
    Mode(u16),
    /// Exact inner root user ID.
    Uid(u32),
    /// Exact inner root group ID.
    Gid(u32),
}

/// A fail-closed error while constructing or revalidating a fixed mount request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MountRequestErrorV2 {
    /// Checked capacity derivation failed.
    Capacity(CapacityErrorV2),
    /// The filesystem type is not exactly `tmpfs`.
    FilesystemTypeDrift,
    /// The ordered VFS mode differs from `rw,nosuid,nodev,noexec`.
    VfsFlagsDrift,
    /// The fixed option array differs from the rederived capacity and owners.
    DataOptionsDrift,
    /// The root mode differs from `0700`.
    RootModeDrift,
    /// The inner UID or GID differs from zero.
    InnerOwnerDrift,
    /// Stored capacity differs from a fresh derivation over the retained plans.
    CapacityDrift,
}

impl From<CapacityErrorV2> for MountRequestErrorV2 {
    fn from(error: CapacityErrorV2) -> Self {
        Self::Capacity(error)
    }
}

impl fmt::Display for MountRequestErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "H0 mount request rejected input: {self:?}")
    }
}

impl std::error::Error for MountRequestErrorV2 {}

/// A provider-fixed, non-authorizing tmpfs request value.
///
/// Its constructor accepts no filesystem name, VFS flag, mount option,
/// capacity estimate, transient peak, or owner from its caller. It performs no
/// syscall and conveys no boot, session, kernel-object, or publication
/// authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountRequestV2 {
    filesystem_type: &'static str,
    vfs_flags: [MountVfsFlagV2; MOUNT_VFS_FLAG_COUNT],
    data_options: [MountDataOptionV2; MOUNT_DATA_OPTION_COUNT],
    root_mode: u16,
    inner_owner_uid: u32,
    inner_owner_gid: u32,
    capacity: CapacityTermsV2,
    plan_bindings: [ReplayPlanCapacityV2; REPLAY_PLAN_COUNT],
}

impl MountRequestV2 {
    /// Derives the only admitted request from four role-ordered plan projections.
    ///
    /// # Errors
    ///
    /// Returns [`MountRequestErrorV2::Capacity`] for a rejected plan or checked
    /// capacity term. A canonical-shape error is returned if internal request
    /// construction ever drifts from the compiled filesystem, flags, options,
    /// mode, owners, or freshly rederived capacity.
    pub fn try_from_replay_plans(
        profile: &ProviderCapacityProfileV2,
        plans: &[ReplayPlanCapacityV2],
    ) -> Result<Self, MountRequestErrorV2> {
        let capacity = derive_capacity_terms_v2(profile, plans)?;
        let plan_bindings =
            <[ReplayPlanCapacityV2; REPLAY_PLAN_COUNT]>::try_from(plans).map_err(|_| {
                MountRequestErrorV2::Capacity(CapacityErrorV2::PlanCount {
                    actual: plans.len(),
                    expected: REPLAY_PLAN_COUNT,
                })
            })?;
        let request = Self {
            filesystem_type: TMPFS_FILESYSTEM_TYPE_V2,
            vfs_flags: FIXED_MOUNT_VFS_FLAGS,
            data_options: fixed_mount_data_options(capacity),
            root_mode: TMPFS_ROOT_MODE_V2,
            inner_owner_uid: TMPFS_INNER_OWNER_V2,
            inner_owner_gid: TMPFS_INNER_OWNER_V2,
            capacity,
            plan_bindings,
        };
        request.validate_canonical()?;
        Ok(request)
    }

    /// Returns the fixed provider-profile identity.
    #[must_use]
    pub const fn provider_profile_id(&self) -> &'static str {
        self.capacity.profile.identity()
    }

    /// Returns the fixed filesystem type.
    #[must_use]
    pub const fn filesystem_type(&self) -> &'static str {
        self.filesystem_type
    }

    /// Returns the exact ordered VFS-mode projection.
    #[must_use]
    pub const fn vfs_flags(&self) -> &[MountVfsFlagV2; MOUNT_VFS_FLAG_COUNT] {
        &self.vfs_flags
    }

    /// Returns the exact ordered data-option projection.
    #[must_use]
    pub const fn data_options(&self) -> &[MountDataOptionV2; MOUNT_DATA_OPTION_COUNT] {
        &self.data_options
    }

    /// Returns the fixed root mode.
    #[must_use]
    pub const fn root_mode(&self) -> u16 {
        self.root_mode
    }

    /// Returns the fixed inner root user ID.
    #[must_use]
    pub const fn inner_owner_uid(&self) -> u32 {
        self.inner_owner_uid
    }

    /// Returns the fixed inner root group ID.
    #[must_use]
    pub const fn inner_owner_gid(&self) -> u32 {
        self.inner_owner_gid
    }

    /// Returns the checked capacity derivation bound to this request.
    #[must_use]
    pub const fn capacity(&self) -> &CapacityTermsV2 {
        &self.capacity
    }

    /// Formats the five fixed tmpfs data options in their compiled order.
    #[must_use]
    pub fn canonical_data_options(&self) -> String {
        format!(
            "size={},nr_inodes={},mode=0700,uid=0,gid=0",
            self.capacity.size_bytes, self.capacity.inode_limit
        )
    }

    fn validate_canonical(&self) -> Result<(), MountRequestErrorV2> {
        let capacity = derive_capacity_terms_v2(&self.capacity.profile, &self.plan_bindings)?;
        if self.capacity != capacity {
            return Err(MountRequestErrorV2::CapacityDrift);
        }
        if self.filesystem_type != TMPFS_FILESYSTEM_TYPE_V2 {
            return Err(MountRequestErrorV2::FilesystemTypeDrift);
        }
        if self.vfs_flags != FIXED_MOUNT_VFS_FLAGS {
            return Err(MountRequestErrorV2::VfsFlagsDrift);
        }
        if self.root_mode != TMPFS_ROOT_MODE_V2 {
            return Err(MountRequestErrorV2::RootModeDrift);
        }
        if self.inner_owner_uid != TMPFS_INNER_OWNER_V2
            || self.inner_owner_gid != TMPFS_INNER_OWNER_V2
        {
            return Err(MountRequestErrorV2::InnerOwnerDrift);
        }
        if self.data_options != fixed_mount_data_options(capacity) {
            return Err(MountRequestErrorV2::DataOptionsDrift);
        }
        Ok(())
    }
}

const fn fixed_mount_data_options(
    capacity: CapacityTermsV2,
) -> [MountDataOptionV2; MOUNT_DATA_OPTION_COUNT] {
    [
        MountDataOptionV2::SizeBytes(capacity.size_bytes),
        MountDataOptionV2::InodeLimit(capacity.inode_limit),
        MountDataOptionV2::Mode(TMPFS_ROOT_MODE_V2),
        MountDataOptionV2::Uid(TMPFS_INNER_OWNER_V2),
        MountDataOptionV2::Gid(TMPFS_INNER_OWNER_V2),
    ]
}

#[cfg(test)]
pub(crate) fn assert_wire_source_full_pin_v1() {
    use sha2::Digest as _;

    let source = include_bytes!("wire.rs");
    assert_eq!(source.len(), 339_983, "complete wire source length drift");
    let digest: [u8; 32] = sha2::Sha256::digest(source).into();
    assert_eq!(
        digest,
        [
            0xbd, 0x51, 0x35, 0x20, 0x62, 0xec, 0x28, 0xc1, 0x40, 0x86, 0xc1, 0x9e, 0x7d, 0x25,
            0xc4, 0xe0, 0x7a, 0xb3, 0xf6, 0x3f, 0xa7, 0x95, 0x05, 0x54, 0x64, 0xaf, 0xd0, 0xf5,
            0x1d, 0x4f, 0x1b, 0xe6,
        ],
        "complete wire source digest drift"
    );
}

#[cfg(test)]
mod checked_capacity_terms {
    use super::*;

    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;

    fn bounds(
        maximum_entries: u64,
        maximum_content_bytes_per_entry: u64,
        maximum_content_bytes: u64,
    ) -> LogicalPlanBoundsV2 {
        LogicalPlanBoundsV2::try_new(
            maximum_entries,
            maximum_content_bytes_per_entry,
            maximum_content_bytes,
        )
        .unwrap()
    }

    fn parameters(page_size: u64) -> ProviderCapacityParametersV2 {
        ProviderCapacityParametersV2 {
            page_size,
            qualified_peak_transient_inodes: 3,
            qualified_peak_transient_pages: 2,
            minimum_hardware_memory_bytes: MIB,
            cgroup_memory_ceiling_bytes: MIB,
            process_reserve_bytes: 64 * KIB,
            logical_plan_bounds: [bounds(16, 8 * KIB, 16 * KIB); REPLAY_PLAN_COUNT],
            maximum_aggregate_entries: 64,
            maximum_aggregate_content_bytes: 64 * KIB,
        }
    }

    fn profile(page_size: u64) -> ProviderCapacityProfileV2 {
        ProviderCapacityProfileV2::try_new(parameters(page_size)).unwrap()
    }

    fn canonical_plans(profile: &ProviderCapacityProfileV2) -> [ReplayPlanCapacityV2; 4] {
        [
            ReplayPlanCapacityV2::try_from_entries(
                profile,
                ReplayRoleV2::RustValidatorBuild,
                &[
                    ReplayEntryCapacityV2::Directory,
                    ReplayEntryCapacityV2::RegularFile { content_length: 1 },
                    ReplayEntryCapacityV2::SymbolicLink {
                        content_length: 4097,
                    },
                ],
            )
            .unwrap(),
            ReplayPlanCapacityV2::try_from_entries(
                profile,
                ReplayRoleV2::JvmValidatorBuild,
                &[ReplayEntryCapacityV2::RegularFile {
                    content_length: 4096,
                }],
            )
            .unwrap(),
            ReplayPlanCapacityV2::try_from_entries(
                profile,
                ReplayRoleV2::RustVerifier,
                &[ReplayEntryCapacityV2::Directory],
            )
            .unwrap(),
            ReplayPlanCapacityV2::try_from_entries(
                profile,
                ReplayRoleV2::JvmVerifier,
                &[ReplayEntryCapacityV2::SymbolicLink { content_length: 0 }],
            )
            .unwrap(),
        ]
    }

    #[test]
    fn checked_capacity_terms_primitives_cover_zero_maximum_and_overflow() {
        assert_eq!(checked_add(0, 0, CapacityTermV2::EntryCount).unwrap(), 0);
        assert_eq!(
            checked_add(u64::MAX, 0, CapacityTermV2::EntryCount).unwrap(),
            u64::MAX
        );
        assert_eq!(
            checked_add(u64::MAX, 1, CapacityTermV2::EntryCount),
            Err(CapacityErrorV2::ArithmeticOverflow(
                CapacityTermV2::EntryCount
            ))
        );
        assert_eq!(
            checked_mul(u64::MAX, 1, CapacityTermV2::SizeBytes).unwrap(),
            u64::MAX
        );
        assert_eq!(
            checked_mul(u64::MAX, 2, CapacityTermV2::SizeBytes),
            Err(CapacityErrorV2::ArithmeticOverflow(
                CapacityTermV2::SizeBytes
            ))
        );
        assert_eq!(
            checked_round_up(0, 4096, CapacityTermV2::RoundedContentBytes).unwrap(),
            0
        );
        assert_eq!(
            checked_round_up(u64::MAX, 1, CapacityTermV2::RoundedContentBytes).unwrap(),
            u64::MAX
        );
        assert_eq!(
            checked_round_up(u64::MAX, 2, CapacityTermV2::RoundedContentBytes),
            Err(CapacityErrorV2::ArithmeticOverflow(
                CapacityTermV2::RoundedContentBytes
            ))
        );
    }

    #[test]
    fn checked_capacity_terms_use_the_exact_formula_and_per_entry_rounding() {
        let profile = profile(4096);
        let plans = canonical_plans(&profile);
        let capacity = derive_capacity_terms_v2(&profile, &plans).unwrap();

        assert_eq!(capacity.entry_count(), 6);
        assert_eq!(capacity.final_inodes(), 11);
        assert_eq!(capacity.inode_limit(), 14);
        assert_eq!(capacity.payload_pages(), 4);
        assert_eq!(capacity.reserve_pages(), 14);
        assert_eq!(capacity.size_bytes(), 18 * 4096);
        assert_eq!(capacity.required_memory_bytes(), 18 * 4096 + 64 * KIB);
    }

    #[test]
    fn checked_capacity_terms_isolate_logical_plan_bounds() {
        let mut count_parameters = parameters(4096);
        count_parameters.logical_plan_bounds[0] = bounds(1, 8 * KIB, 16 * KIB);
        let count_profile = ProviderCapacityProfileV2::try_new(count_parameters).unwrap();
        assert_eq!(
            ReplayPlanCapacityV2::try_from_entries(
                &count_profile,
                ReplayRoleV2::RustValidatorBuild,
                &[
                    ReplayEntryCapacityV2::Directory,
                    ReplayEntryCapacityV2::Directory,
                ],
            ),
            Err(CapacityErrorV2::PlanEntryLimitExceeded {
                role: ReplayRoleV2::RustValidatorBuild,
                actual: 2,
                maximum: 1,
            })
        );

        let mut entry_parameters = parameters(4096);
        entry_parameters.logical_plan_bounds[0] = bounds(2, 4, 8);
        let entry_profile = ProviderCapacityProfileV2::try_new(entry_parameters).unwrap();
        assert_eq!(
            ReplayPlanCapacityV2::try_from_entries(
                &entry_profile,
                ReplayRoleV2::RustValidatorBuild,
                &[ReplayEntryCapacityV2::RegularFile { content_length: 5 }],
            ),
            Err(CapacityErrorV2::EntryContentLimitExceeded {
                role: ReplayRoleV2::RustValidatorBuild,
                entry_index: 0,
                actual: 5,
                maximum: 4,
            })
        );

        let mut total_parameters = parameters(4096);
        total_parameters.logical_plan_bounds[0] = bounds(2, 4, 5);
        let total_profile = ProviderCapacityProfileV2::try_new(total_parameters).unwrap();
        assert_eq!(
            ReplayPlanCapacityV2::try_from_entries(
                &total_profile,
                ReplayRoleV2::RustValidatorBuild,
                &[
                    ReplayEntryCapacityV2::RegularFile { content_length: 3 },
                    ReplayEntryCapacityV2::SymbolicLink { content_length: 3 },
                ],
            ),
            Err(CapacityErrorV2::PlanContentLimitExceeded {
                role: ReplayRoleV2::RustValidatorBuild,
                actual: 6,
                maximum: 5,
            })
        );
    }

    #[test]
    fn checked_capacity_terms_isolate_four_plan_aggregate_bounds() {
        let mut entry_parameters = parameters(4096);
        entry_parameters.maximum_aggregate_entries = 3;
        let entry_profile = ProviderCapacityProfileV2::try_new(entry_parameters).unwrap();
        let entry_plans = ReplayRoleV2::ALL.map(|role| {
            ReplayPlanCapacityV2::try_from_entries(
                &entry_profile,
                role,
                &[ReplayEntryCapacityV2::Directory],
            )
            .unwrap()
        });
        assert_eq!(
            derive_capacity_terms_v2(&entry_profile, &entry_plans),
            Err(CapacityErrorV2::AggregateEntryLimitExceeded {
                actual: 4,
                maximum: 3,
            })
        );

        let mut content_parameters = parameters(4096);
        content_parameters.maximum_aggregate_content_bytes = 3;
        let content_profile = ProviderCapacityProfileV2::try_new(content_parameters).unwrap();
        let content_plans = ReplayRoleV2::ALL.map(|role| {
            ReplayPlanCapacityV2::try_from_entries(
                &content_profile,
                role,
                &[ReplayEntryCapacityV2::RegularFile { content_length: 1 }],
            )
            .unwrap()
        });
        assert_eq!(
            derive_capacity_terms_v2(&content_profile, &content_plans),
            Err(CapacityErrorV2::AggregateContentLimitExceeded {
                actual: 4,
                maximum: 3,
            })
        );
    }

    #[test]
    fn checked_capacity_terms_reject_plan_count_order_and_profile_drift() {
        let base_profile = profile(4096);
        let plans = canonical_plans(&base_profile);
        assert_eq!(
            derive_capacity_terms_v2(&base_profile, &plans[..3]),
            Err(CapacityErrorV2::PlanCount {
                actual: 3,
                expected: REPLAY_PLAN_COUNT,
            })
        );

        let mut reordered = plans;
        reordered.swap(0, 1);
        assert_eq!(
            derive_capacity_terms_v2(&base_profile, &reordered),
            Err(CapacityErrorV2::PlanRoleOrder {
                index: 0,
                expected: ReplayRoleV2::RustValidatorBuild,
                actual: ReplayRoleV2::JvmValidatorBuild,
            })
        );

        let drifted_profile = profile(2048);
        assert_eq!(
            derive_capacity_terms_v2(&drifted_profile, &plans),
            Err(CapacityErrorV2::PlanProfileDrift {
                role: ReplayRoleV2::RustValidatorBuild,
            })
        );
    }

    #[test]
    fn checked_capacity_terms_reject_rounding_size_and_reserve_overflow() {
        let mut rounding_parameters = parameters(2);
        rounding_parameters.logical_plan_bounds =
            [bounds(1, u64::MAX, u64::MAX); REPLAY_PLAN_COUNT];
        rounding_parameters.minimum_hardware_memory_bytes = u64::MAX;
        rounding_parameters.cgroup_memory_ceiling_bytes = u64::MAX;
        let rounding_profile = ProviderCapacityProfileV2::try_new(rounding_parameters).unwrap();
        assert_eq!(
            ReplayPlanCapacityV2::try_from_entries(
                &rounding_profile,
                ReplayRoleV2::RustValidatorBuild,
                &[ReplayEntryCapacityV2::RegularFile {
                    content_length: u64::MAX,
                }],
            ),
            Err(CapacityErrorV2::ArithmeticOverflow(
                CapacityTermV2::RoundedContentBytes
            ))
        );

        let mut size_parameters = parameters(u64::MAX);
        size_parameters.logical_plan_bounds = [bounds(1, 1, 1); REPLAY_PLAN_COUNT];
        size_parameters.minimum_hardware_memory_bytes = u64::MAX;
        size_parameters.cgroup_memory_ceiling_bytes = u64::MAX;
        size_parameters.process_reserve_bytes = 0;
        let size_profile = ProviderCapacityProfileV2::try_new(size_parameters).unwrap();
        let size_plans = [
            ReplayPlanCapacityV2::try_from_entries(
                &size_profile,
                ReplayRoleV2::RustValidatorBuild,
                &[],
            )
            .unwrap(),
            ReplayPlanCapacityV2::try_from_entries(
                &size_profile,
                ReplayRoleV2::JvmValidatorBuild,
                &[],
            )
            .unwrap(),
            ReplayPlanCapacityV2::try_from_entries(&size_profile, ReplayRoleV2::RustVerifier, &[])
                .unwrap(),
            ReplayPlanCapacityV2::try_from_entries(&size_profile, ReplayRoleV2::JvmVerifier, &[])
                .unwrap(),
        ];
        assert_eq!(
            derive_capacity_terms_v2(&size_profile, &size_plans),
            Err(CapacityErrorV2::ArithmeticOverflow(
                CapacityTermV2::SizeBytes
            ))
        );

        let mut reserve_parameters = parameters(1);
        reserve_parameters.logical_plan_bounds = [bounds(1, 1, 1); REPLAY_PLAN_COUNT];
        reserve_parameters.minimum_hardware_memory_bytes = u64::MAX;
        reserve_parameters.cgroup_memory_ceiling_bytes = u64::MAX;
        reserve_parameters.process_reserve_bytes = u64::MAX;
        let reserve_profile = ProviderCapacityProfileV2::try_new(reserve_parameters).unwrap();
        let reserve_plans = canonical_empty_plans(&reserve_profile);
        assert_eq!(
            derive_capacity_terms_v2(&reserve_profile, &reserve_plans),
            Err(CapacityErrorV2::ArithmeticOverflow(
                CapacityTermV2::RequiredMemoryBytes
            ))
        );
    }

    fn canonical_empty_plans(
        profile: &ProviderCapacityProfileV2,
    ) -> [ReplayPlanCapacityV2; REPLAY_PLAN_COUNT] {
        ReplayRoleV2::ALL
            .map(|role| ReplayPlanCapacityV2::try_from_entries(profile, role, &[]).unwrap())
    }

    #[test]
    fn checked_capacity_terms_isolate_hardware_cgroup_and_process_reserve() {
        let mut hardware_parameters = parameters(1);
        hardware_parameters.logical_plan_bounds = [bounds(1, 1, 1); REPLAY_PLAN_COUNT];
        hardware_parameters.minimum_hardware_memory_bytes = 7;
        hardware_parameters.cgroup_memory_ceiling_bytes = u64::MAX;
        hardware_parameters.process_reserve_bytes = 0;
        let hardware_profile = ProviderCapacityProfileV2::try_new(hardware_parameters).unwrap();
        let hardware_plans = canonical_empty_plans(&hardware_profile);
        assert_eq!(
            derive_capacity_terms_v2(&hardware_profile, &hardware_plans),
            Err(CapacityErrorV2::HardwareMemoryAdmission {
                required: 8,
                minimum: 7,
            })
        );

        let mut cgroup_parameters = parameters(1);
        cgroup_parameters.logical_plan_bounds = [bounds(1, 1, 1); REPLAY_PLAN_COUNT];
        cgroup_parameters.minimum_hardware_memory_bytes = u64::MAX;
        cgroup_parameters.cgroup_memory_ceiling_bytes = 7;
        cgroup_parameters.process_reserve_bytes = 0;
        let cgroup_profile = ProviderCapacityProfileV2::try_new(cgroup_parameters).unwrap();
        let cgroup_plans = canonical_empty_plans(&cgroup_profile);
        assert_eq!(
            derive_capacity_terms_v2(&cgroup_profile, &cgroup_plans),
            Err(CapacityErrorV2::CgroupMemoryAdmission {
                required: 8,
                ceiling: 7,
            })
        );

        let mut reserve_parameters = parameters(1);
        reserve_parameters.logical_plan_bounds = [bounds(1, 1, 1); REPLAY_PLAN_COUNT];
        reserve_parameters.minimum_hardware_memory_bytes = 8;
        reserve_parameters.cgroup_memory_ceiling_bytes = 8;
        reserve_parameters.process_reserve_bytes = 1;
        let reserve_profile = ProviderCapacityProfileV2::try_new(reserve_parameters).unwrap();
        let reserve_plans = canonical_empty_plans(&reserve_profile);
        assert_eq!(
            derive_capacity_terms_v2(&reserve_profile, &reserve_plans),
            Err(CapacityErrorV2::HardwareMemoryAdmission {
                required: 9,
                minimum: 8,
            })
        );
    }
}

#[cfg(test)]
mod checked_capacity_terms_workspace_policy {
    #[test]
    fn checked_capacity_terms_workspace_has_exact_sha2_dependency_policy() {
        let workspace = include_str!("../../../Cargo.toml");
        let package = include_str!("../Cargo.toml");
        let source = include_str!("lib.rs");

        assert!(workspace.contains("members = [\"crates/contract\", \"crates/linux-abi\"]"));
        assert!(workspace.contains("resolver = \"3\""));
        assert!(workspace.contains("rust-version = \"1.89.0\""));
        assert!(workspace.contains("unsafe_code = \"forbid\""));
        assert!(workspace.contains(
            "[workspace.dependencies]\nsha2 = { version = \"=0.10.9\", default-features = false }"
        ));
        assert_eq!(workspace.matches("sha2").count(), 1);
        assert!(package.contains("name = \"eip0045-h0-contract\""));
        assert!(package.contains("default = []"));
        assert!(package.contains("[dependencies]\nsha2.workspace = true"));
        assert_eq!(package.matches("sha2").count(), 1);
        assert!(source.starts_with("#![forbid(unsafe_code)]"));
    }
}

#[cfg(test)]
mod mount_request_v2 {
    use super::*;

    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;

    fn profile() -> ProviderCapacityProfileV2 {
        let bounds = LogicalPlanBoundsV2::try_new(8, 8 * KIB, 16 * KIB).unwrap();
        ProviderCapacityProfileV2::try_new(ProviderCapacityParametersV2 {
            page_size: 4096,
            qualified_peak_transient_inodes: 3,
            qualified_peak_transient_pages: 2,
            minimum_hardware_memory_bytes: MIB,
            cgroup_memory_ceiling_bytes: MIB,
            process_reserve_bytes: 64 * KIB,
            logical_plan_bounds: [bounds; REPLAY_PLAN_COUNT],
            maximum_aggregate_entries: 32,
            maximum_aggregate_content_bytes: 64 * KIB,
        })
        .unwrap()
    }

    fn plans(profile: &ProviderCapacityProfileV2) -> [ReplayPlanCapacityV2; 4] {
        ReplayRoleV2::ALL.map(|role| {
            ReplayPlanCapacityV2::try_from_entries(
                profile,
                role,
                &[ReplayEntryCapacityV2::RegularFile { content_length: 1 }],
            )
            .unwrap()
        })
    }

    fn request() -> MountRequestV2 {
        let profile = profile();
        MountRequestV2::try_from_replay_plans(&profile, &plans(&profile)).unwrap()
    }

    #[test]
    fn mount_request_v2_is_provider_fixed_and_capacity_derived() {
        let request = request();

        assert_eq!(request.provider_profile_id(), PROVIDER_PROFILE_ID_V1);
        assert_eq!(request.filesystem_type(), "tmpfs");
        assert_eq!(
            request.vfs_flags(),
            &[
                MountVfsFlagV2::ReadWrite,
                MountVfsFlagV2::NoSuid,
                MountVfsFlagV2::NoDev,
                MountVfsFlagV2::NoExec,
            ]
        );
        assert_eq!(request.root_mode(), 0o700);
        assert_eq!(request.inner_owner_uid(), 0);
        assert_eq!(request.inner_owner_gid(), 0);
        assert_eq!(request.capacity().entry_count(), 4);
        assert_eq!(request.capacity().final_inodes(), 9);
        assert_eq!(request.capacity().inode_limit(), 12);
        assert_eq!(request.capacity().payload_pages(), 4);
        assert_eq!(request.capacity().reserve_pages(), 12);
        assert_eq!(request.capacity().size_bytes(), 16 * 4096);
        assert_eq!(
            request.data_options(),
            &[
                MountDataOptionV2::SizeBytes(16 * 4096),
                MountDataOptionV2::InodeLimit(12),
                MountDataOptionV2::Mode(0o700),
                MountDataOptionV2::Uid(0),
                MountDataOptionV2::Gid(0),
            ]
        );
        assert_eq!(
            request.canonical_data_options(),
            "size=65536,nr_inodes=12,mode=0700,uid=0,gid=0"
        );
        assert_eq!(request.validate_canonical(), Ok(()));
    }

    #[test]
    fn mount_request_v2_rejects_filesystem_flag_and_option_drift() {
        let mut filesystem = request();
        filesystem.filesystem_type = "ext4";
        assert_eq!(
            filesystem.validate_canonical(),
            Err(MountRequestErrorV2::FilesystemTypeDrift)
        );

        let mut flags = request();
        flags.vfs_flags[3] = MountVfsFlagV2::NoDev;
        assert_eq!(
            flags.validate_canonical(),
            Err(MountRequestErrorV2::VfsFlagsDrift)
        );

        let mut options = request();
        options.data_options[1] = options.data_options[0];
        assert_eq!(
            options.validate_canonical(),
            Err(MountRequestErrorV2::DataOptionsDrift)
        );

        let mut size = request();
        size.data_options[0] = MountDataOptionV2::SizeBytes(65_535);
        assert_eq!(
            size.validate_canonical(),
            Err(MountRequestErrorV2::DataOptionsDrift)
        );
    }

    #[test]
    fn mount_request_v2_rejects_mode_owner_and_capacity_drift() {
        let mut mode = request();
        mode.root_mode = 0o755;
        assert_eq!(
            mode.validate_canonical(),
            Err(MountRequestErrorV2::RootModeDrift)
        );

        let mut uid = request();
        uid.inner_owner_uid = 1;
        assert_eq!(
            uid.validate_canonical(),
            Err(MountRequestErrorV2::InnerOwnerDrift)
        );

        let mut gid = request();
        gid.inner_owner_gid = 1;
        assert_eq!(
            gid.validate_canonical(),
            Err(MountRequestErrorV2::InnerOwnerDrift)
        );

        let mut capacity = request();
        capacity.capacity.size_bytes += capacity.capacity.profile.page_size();
        assert_eq!(
            capacity.validate_canonical(),
            Err(MountRequestErrorV2::CapacityDrift)
        );
    }

    #[test]
    fn mount_request_v2_propagates_plan_count_and_profile_drift() {
        let profile = profile();
        let plans = plans(&profile);
        assert_eq!(
            MountRequestV2::try_from_replay_plans(&profile, &plans[..3]),
            Err(MountRequestErrorV2::Capacity(CapacityErrorV2::PlanCount {
                actual: 3,
                expected: REPLAY_PLAN_COUNT,
            }))
        );

        let mut changed_parameters = profile.parameters;
        changed_parameters.qualified_peak_transient_pages += 1;
        let changed_profile = ProviderCapacityProfileV2::try_new(changed_parameters).unwrap();
        assert_eq!(
            MountRequestV2::try_from_replay_plans(&changed_profile, &plans),
            Err(MountRequestErrorV2::Capacity(
                CapacityErrorV2::PlanProfileDrift {
                    role: ReplayRoleV2::RustValidatorBuild,
                }
            ))
        );
    }
}
