//! Closed process-creation contract for the selected H0 appliance.

use core::fmt;

/// `CLONE_VM` from the pinned Linux UAPI.
pub const CLONE_VM_V1: u64 = 0x0000_0100;
/// `CLONE_FS` from the pinned Linux UAPI.
pub const CLONE_FS_V1: u64 = 0x0000_0200;
/// `CLONE_FILES` from the pinned Linux UAPI.
pub const CLONE_FILES_V1: u64 = 0x0000_0400;
/// `CLONE_PIDFD` from the pinned Linux UAPI.
pub const CLONE_PIDFD_V1: u64 = 0x0000_1000;
/// `CLONE_VFORK` from the pinned Linux UAPI.
pub const CLONE_VFORK_V1: u64 = 0x0000_4000;
/// `CLONE_PARENT` from the pinned Linux UAPI.
pub const CLONE_PARENT_V1: u64 = 0x0000_8000;
/// `CLONE_THREAD` from the pinned Linux UAPI.
pub const CLONE_THREAD_V1: u64 = 0x0001_0000;
/// `CLONE_NEWNS` from the pinned Linux UAPI.
pub const CLONE_NEWNS_V1: u64 = 0x0002_0000;
/// `CLONE_NEWUSER` from the pinned Linux UAPI.
pub const CLONE_NEWUSER_V1: u64 = 0x1000_0000;
/// `CLONE_NEWPID` from the pinned Linux UAPI.
pub const CLONE_NEWPID_V1: u64 = 0x2000_0000;
/// `CLONE_INTO_CGROUP` from the pinned Linux UAPI.
pub const CLONE_INTO_CGROUP_V1: u64 = 1_u64 << 33;
/// `SIGCHLD` from the selected x86-64 Linux ABI.
pub const SIGCHLD_V1: u64 = 17;

/// Exact generator clone flags. The public spawn function accepts no flags.
pub const GENERATOR_CLONE_FLAGS_V1: u64 = CLONE_PIDFD_V1 | CLONE_INTO_CGROUP_V1;
/// Exact worker clone flags. The public spawn function accepts no flags.
pub const WORKER_CLONE_FLAGS_V1: u64 =
    CLONE_NEWUSER_V1 | CLONE_NEWNS_V1 | CLONE_PIDFD_V1 | CLONE_INTO_CGROUP_V1;
/// Independently rejected generator clone mutations.
pub const FORBIDDEN_GENERATOR_CLONE_FLAGS_V1: [u64; 9] = [
    CLONE_VM_V1,
    CLONE_FS_V1,
    CLONE_FILES_V1,
    CLONE_VFORK_V1,
    CLONE_PARENT_V1,
    CLONE_THREAD_V1,
    CLONE_NEWNS_V1,
    CLONE_NEWUSER_V1,
    CLONE_NEWPID_V1,
];
/// Independently rejected worker clone mutations.
pub const FORBIDDEN_WORKER_CLONE_FLAGS_V1: [u64; 7] = [
    CLONE_VM_V1,
    CLONE_FS_V1,
    CLONE_FILES_V1,
    CLONE_VFORK_V1,
    CLONE_PARENT_V1,
    CLONE_THREAD_V1,
    CLONE_NEWPID_V1,
];

/// Reserved descriptor carrying the supervisor/worker endpoint after exec.
pub const WORKER_ENDPOINT_FD_V1: i32 = 3;
/// Reserved descriptor carrying the supervisor/generator endpoint after exec.
pub const GENERATOR_ENDPOINT_FD_V1: i32 = 3;
/// Reserved descriptor carrying the supervisor pidfd in the generator.
pub const GENERATOR_SUPERVISOR_PIDFD_V1: i32 = 4;
/// Reserved descriptor carrying the publication-root capability in the generator.
pub const GENERATOR_PUBLICATION_ROOT_FD_V1: i32 = 5;
/// First reserved descriptor for sealed generator ingress.
pub const GENERATOR_FIRST_INGRESS_FD_V1: i32 = 6;
/// Maximum number of sealed ingress descriptors.
pub const MAX_GENERATOR_INGRESS_FDS_V1: usize = 16;
/// Highest descriptor number reserved by the generator entry ABI.
pub const LAST_RESERVED_DESCRIPTOR_V1: i32 = 21;
/// Maximum exact pre-clone descriptor inventory.
pub const MAX_PROCESS_FDS_V1: usize = 64;
/// Maximum prebuilt argument count, excluding the terminating null pointer.
pub const MAX_EXEC_ARGUMENTS_V1: usize = 32;
/// Maximum prebuilt environment count, excluding the terminating null pointer.
pub const MAX_EXEC_ENVIRONMENT_V1: usize = 64;

/// `WEXITED | WNOWAIT`, used only for pidfd-bound observation.
pub const PIDFD_OBSERVE_OPTIONS_V1: u32 = 0x0100_0004;
/// `WEXITED`, used only to reap the same pidfd-bound child.
pub const PIDFD_REAP_OPTIONS_V1: u32 = 0x0000_0004;
/// `WEXITED | WNOHANG | WNOWAIT`, used only for a nonconsuming live-child check.
#[cfg(test)]
const PIDFD_REQUIRE_LIVE_OPTIONS_V1: u32 = 0x0100_0005;

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
#[repr(C)]
struct CloneArgsV1 {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const _: [(); 88] = [(); core::mem::size_of::<CloneArgsV1>()];
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const _: [(); 8] = [(); core::mem::align_of::<CloneArgsV1>()];
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const _: [(); 0] = [(); core::mem::offset_of!(CloneArgsV1, flags)];
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const _: [(); 8] = [(); core::mem::offset_of!(CloneArgsV1, pidfd)];
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const _: [(); 16] = [(); core::mem::offset_of!(CloneArgsV1, child_tid)];
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const _: [(); 24] = [(); core::mem::offset_of!(CloneArgsV1, parent_tid)];
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const _: [(); 32] = [(); core::mem::offset_of!(CloneArgsV1, exit_signal)];
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const _: [(); 40] = [(); core::mem::offset_of!(CloneArgsV1, stack)];
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const _: [(); 48] = [(); core::mem::offset_of!(CloneArgsV1, stack_size)];
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const _: [(); 56] = [(); core::mem::offset_of!(CloneArgsV1, tls)];
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const _: [(); 64] = [(); core::mem::offset_of!(CloneArgsV1, set_tid)];
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const _: [(); 72] = [(); core::mem::offset_of!(CloneArgsV1, set_tid_size)];
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const _: [(); 80] = [(); core::mem::offset_of!(CloneArgsV1, cgroup)];

/// Rejection returned before any process is created or released.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessContractErrorV1 {
    /// Clone flags differ from the provider-compiled role constant.
    CloneFlags,
    /// Exit notification differs from `SIGCHLD`.
    ExitSignal,
    /// The clone pidfd output slot is absent.
    PidfdSlot,
    /// The exact cgroup descriptor is absent.
    Cgroup,
    /// A service UID or GID is zero.
    ServiceIdentity,
    /// The inherited supplementary-group inventory is not empty.
    SupplementaryGroups,
    /// The live procfs descriptor inventory is missing, duplicated, or surplus.
    DescriptorInventory,
    /// A source overlaps the provider-reserved post-exec descriptor range.
    ReservedDescriptorOverlap,
    /// A source descriptor is not close-on-exec before clone.
    DescriptorNotCloseOnExec,
    /// The post-clone sequence differs from the provider-compiled sequence.
    TrampolineOrder,
    /// The user-namespace UID map differs from the exact one-line map.
    UidMap,
    /// The `setgroups` readback differs from `deny`.
    SetgroupsMap,
    /// The user-namespace GID map differs from the exact one-line map.
    GidMap,
    /// User-namespace writes or readbacks were reordered.
    NamespaceMapOrder,
    /// The supplied descriptor is not a procfs root.
    ProcfsRoot,
    /// The retained procfs view does not identify this exact process/thread.
    ProcfsIdentity,
    /// The live process was not single-threaded at both bracket snapshots.
    ThreadMultiplicity,
    /// The calling thread differed from the process leader or from its bracket.
    ThreadIdentity,
    /// The signal-mask bracket could not be installed or restored exactly.
    SignalMask,
    /// An argument or environment bound was exceeded or `argv[0]` is absent.
    ExecVectorBounds,
    /// The checked map snapshot belongs to a different child.
    ChildIdentity,
    /// Pidfd wait options or observation/reap ordering drifted.
    WaitOptions,
    /// A selected-target kernel operation failed with this errno.
    Kernel(i32),
    /// A successful clone returned an invalid pid or pidfd.
    KernelInvariant,
}

impl fmt::Display for ProcessContractErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "H0 process contract rejected: {self:?}")
    }
}

impl std::error::Error for ProcessContractErrorV1 {}

#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
impl From<crate::ancillary::AncillarySendErrorV1> for ProcessContractErrorV1 {
    fn from(_: crate::ancillary::AncillarySendErrorV1) -> Self {
        Self::KernelInvariant
    }
}

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
fn validate_single_thread_snapshots(
    process_id: i32,
    thread_id: i32,
    first: &[i32],
    second: &[i32],
) -> Result<(), ProcessContractErrorV1> {
    if process_id <= 0 || thread_id != process_id {
        return Err(ProcessContractErrorV1::ThreadIdentity);
    }
    if first != [thread_id] || second != [thread_id] {
        return Err(ProcessContractErrorV1::ThreadMultiplicity);
    }
    Ok(())
}

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const GENERATOR_UID_V1: u32 = 20_001;
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const GENERATOR_GID_V1: u32 = 20_001;
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
pub(crate) const WORKER_OUTER_UID_V1: u32 = 20_002;
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
pub(crate) const WORKER_OUTER_GID_V1: u32 = 20_002;

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildIdentityTransitionV1 {
    GeneratorService,
    WorkerInnerZero,
}

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
impl ChildIdentityTransitionV1 {
    const fn target_ids(self) -> (u32, u32) {
        match self {
            Self::GeneratorService => (GENERATOR_UID_V1, GENERATOR_GID_V1),
            Self::WorkerInnerZero => (0, 0),
        }
    }
}

/// Exact namespace-map operation order while the worker remains blocked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceMapStageV1 {
    /// Write the one-line UID map.
    WriteUidMap,
    /// Reread the complete UID map.
    ReadUidMap,
    /// Write `deny` to `setgroups`.
    WriteSetgroupsDeny,
    /// Reread `setgroups`.
    ReadSetgroupsDeny,
    /// Write the one-line GID map.
    WriteGidMap,
    /// Reread the complete GID map.
    ReadGidMap,
}

/// Provider-compiled namespace-map operation order.
pub const WORKER_MAP_STAGES_V1: [NamespaceMapStageV1; 6] = [
    NamespaceMapStageV1::WriteUidMap,
    NamespaceMapStageV1::ReadUidMap,
    NamespaceMapStageV1::WriteSetgroupsDeny,
    NamespaceMapStageV1::ReadSetgroupsDeny,
    NamespaceMapStageV1::WriteGidMap,
    NamespaceMapStageV1::ReadGidMap,
];

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const MAX_MAP_LINE_BYTES_V1: usize = 16;

/// Exact provider-compiled one-line worker UID/GID maps.
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WorkerNamespaceMapsV1 {
    uid_map: [u8; MAX_MAP_LINE_BYTES_V1],
    uid_map_len: usize,
    gid_map: [u8; MAX_MAP_LINE_BYTES_V1],
    gid_map_len: usize,
}

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
impl WorkerNamespaceMapsV1 {
    fn fixed_worker_v1() -> Self {
        let (uid_map, uid_map_len) = format_single_id_map(WORKER_OUTER_UID_V1);
        let (gid_map, gid_map_len) = format_single_id_map(WORKER_OUTER_GID_V1);
        Self {
            uid_map,
            uid_map_len,
            gid_map,
            gid_map_len,
        }
    }

    /// Exact bytes to write and reread for `uid_map`.
    #[must_use]
    fn uid_map(&self) -> &[u8] {
        &self.uid_map[..self.uid_map_len]
    }

    /// Exact bytes to write and reread for `setgroups`.
    #[must_use]
    const fn setgroups() -> &'static [u8] {
        b"deny\n"
    }

    /// Exact bytes to write and reread for `gid_map`.
    #[must_use]
    fn gid_map(&self) -> &[u8] {
        &self.gid_map[..self.gid_map_len]
    }

    /// Checks complete readbacks and order; this is byte validation, not authority.
    ///
    /// # Errors
    ///
    /// Rejects any content, ordering, or supplementary-group drift.
    fn verify_readback(
        &self,
        uid_map: &[u8],
        setgroups: &[u8],
        gid_map: &[u8],
        stages: &[NamespaceMapStageV1],
        supplementary_group_count: usize,
    ) -> Result<(), ProcessContractErrorV1> {
        if *self != Self::fixed_worker_v1() {
            return Err(ProcessContractErrorV1::ChildIdentity);
        }
        if stages != WORKER_MAP_STAGES_V1 {
            return Err(ProcessContractErrorV1::NamespaceMapOrder);
        }
        if supplementary_group_count != 0 {
            return Err(ProcessContractErrorV1::SupplementaryGroups);
        }
        if parse_single_id_map(uid_map) != Some((0, WORKER_OUTER_UID_V1, 1)) {
            return Err(ProcessContractErrorV1::UidMap);
        }
        if setgroups != Self::setgroups() {
            return Err(ProcessContractErrorV1::SetgroupsMap);
        }
        if parse_single_id_map(gid_map) != Some((0, WORKER_OUTER_GID_V1, 1)) {
            return Err(ProcessContractErrorV1::GidMap);
        }
        Ok(())
    }

    fn inner_zero_maps_to_worker_outer_v1(&self) -> bool {
        translate_inner_to_outer_v1(self.uid_map(), 0) == Some(WORKER_OUTER_UID_V1)
            && translate_inner_to_outer_v1(self.gid_map(), 0) == Some(WORKER_OUTER_GID_V1)
    }

    fn supervisor_outer_root_is_unmapped_v1(&self) -> bool {
        translate_outer_to_inner_v1(self.uid_map(), 0).is_none()
            && translate_outer_to_inner_v1(self.gid_map(), 0).is_none()
    }
}

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
fn translate_inner_to_outer_v1(bytes: &[u8], inner: u32) -> Option<u32> {
    let (inner_first, outer_first, count) = parse_single_id_map(bytes)?;
    let offset = inner.checked_sub(inner_first)?;
    if offset >= count {
        return None;
    }
    outer_first.checked_add(offset)
}

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
fn translate_outer_to_inner_v1(bytes: &[u8], outer: u32) -> Option<u32> {
    let (inner_first, outer_first, count) = parse_single_id_map(bytes)?;
    let offset = outer.checked_sub(outer_first)?;
    if offset >= count {
        return None;
    }
    inner_first.checked_add(offset)
}

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
fn parse_single_id_map(bytes: &[u8]) -> Option<(u32, u32, u32)> {
    let body = bytes.strip_suffix(b"\n")?;
    if body.is_empty()
        || body.last() == Some(&b' ')
        || body
            .iter()
            .any(|byte| !byte.is_ascii_digit() && *byte != b' ')
    {
        return None;
    }
    let mut fields = body
        .split(|byte| *byte == b' ')
        .filter(|field| !field.is_empty());
    let first = parse_canonical_decimal(fields.next()?)?;
    let second = parse_canonical_decimal(fields.next()?)?;
    let count = parse_canonical_decimal(fields.next()?)?;
    if fields.next().is_some() {
        return None;
    }
    Some((first, second, count))
}

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
fn parse_canonical_decimal(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || (bytes.len() > 1 && bytes[0] == b'0') {
        return None;
    }
    let mut value = 0_u32;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value
            .checked_mul(10)?
            .checked_add(u32::from(*byte - b'0'))?;
    }
    Some(value)
}

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
fn format_single_id_map(id: u32) -> ([u8; MAX_MAP_LINE_BYTES_V1], usize) {
    let mut output = [0_u8; MAX_MAP_LINE_BYTES_V1];
    output[0] = b'0';
    output[1] = b' ';

    let mut digits = [0_u8; 10];
    let mut value = id;
    let mut count = 0_usize;
    loop {
        digits[count] = b'0' + u8::try_from(value % 10).expect("one decimal digit fits u8");
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for index in 0..count {
        output[2 + index] = digits[count - index - 1];
    }
    let suffix = 2 + count;
    output[suffix] = b' ';
    output[suffix + 1] = b'1';
    output[suffix + 2] = b'\n';
    (output, suffix + 3)
}

/// Allocation-free child-side actions in auditable order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrampolineActionV1 {
    /// Block until the parent has checked the worker namespace maps.
    WaitForVerifiedMaps,
    /// Duplicate every exact source onto its reserved descriptor.
    RemapReservedDescriptors,
    /// Close all descriptors other than the retained executable and reserved set.
    CloseSurplusDescriptors,
    /// Clear the generator supplementary-group set.
    DropSupplementaryGroups,
    /// Set all generator GID slots to the dedicated service GID.
    SetResGid,
    /// Set all generator UID slots to the dedicated service UID.
    SetResUid,
    /// Parse the current thread's descriptor-rooted status and check every identity slot.
    VerifyCurrentIdentity,
    /// Tell the parent that the fixed identity transition has completed.
    SignalIdentityReady,
    /// Remain blocked until the parent reauthenticates the retained executable OFD.
    WaitForExecRelease,
    /// Execute only the retained descriptor with `AT_EMPTY_PATH`.
    RetainedExecveat,
}

/// Exact generator child-side sequence.
pub const GENERATOR_TRAMPOLINE_ACTIONS_V1: [TrampolineActionV1; 9] = [
    TrampolineActionV1::RemapReservedDescriptors,
    TrampolineActionV1::CloseSurplusDescriptors,
    TrampolineActionV1::DropSupplementaryGroups,
    TrampolineActionV1::SetResGid,
    TrampolineActionV1::SetResUid,
    TrampolineActionV1::VerifyCurrentIdentity,
    TrampolineActionV1::SignalIdentityReady,
    TrampolineActionV1::WaitForExecRelease,
    TrampolineActionV1::RetainedExecveat,
];
/// Exact worker child-side sequence.
pub const WORKER_TRAMPOLINE_ACTIONS_V1: [TrampolineActionV1; 9] = [
    TrampolineActionV1::WaitForVerifiedMaps,
    TrampolineActionV1::RemapReservedDescriptors,
    TrampolineActionV1::CloseSurplusDescriptors,
    TrampolineActionV1::SetResGid,
    TrampolineActionV1::SetResUid,
    TrampolineActionV1::VerifyCurrentIdentity,
    TrampolineActionV1::SignalIdentityReady,
    TrampolineActionV1::WaitForExecRelease,
    TrampolineActionV1::RetainedExecveat,
];

#[cfg(test)]
#[derive(Clone, Copy)]
struct CloneSnapshotV1 {
    flags: u64,
    exit_signal: u64,
    pidfd_slot: bool,
    cgroup: bool,
}

#[cfg(test)]
const fn generator_clone_snapshot_for_test() -> CloneSnapshotV1 {
    CloneSnapshotV1 {
        flags: GENERATOR_CLONE_FLAGS_V1,
        exit_signal: SIGCHLD_V1,
        pidfd_slot: true,
        cgroup: true,
    }
}

#[cfg(test)]
const fn worker_clone_snapshot_for_test() -> CloneSnapshotV1 {
    CloneSnapshotV1 {
        flags: WORKER_CLONE_FLAGS_V1,
        exit_signal: SIGCHLD_V1,
        pidfd_slot: true,
        cgroup: true,
    }
}

#[cfg(test)]
fn validate_clone_for_test(
    snapshot: CloneSnapshotV1,
    exact_flags: u64,
) -> Result<(), ProcessContractErrorV1> {
    if snapshot.flags != exact_flags {
        return Err(ProcessContractErrorV1::CloneFlags);
    }
    if snapshot.exit_signal != SIGCHLD_V1 {
        return Err(ProcessContractErrorV1::ExitSignal);
    }
    if !snapshot.pidfd_slot {
        return Err(ProcessContractErrorV1::PidfdSlot);
    }
    if !snapshot.cgroup {
        return Err(ProcessContractErrorV1::Cgroup);
    }
    Ok(())
}

#[cfg(test)]
fn validate_generator_clone_for_test(
    snapshot: CloneSnapshotV1,
) -> Result<(), ProcessContractErrorV1> {
    validate_clone_for_test(snapshot, GENERATOR_CLONE_FLAGS_V1)
}

#[cfg(test)]
fn validate_worker_clone_for_test(snapshot: CloneSnapshotV1) -> Result<(), ProcessContractErrorV1> {
    validate_clone_for_test(snapshot, WORKER_CLONE_FLAGS_V1)
}

#[cfg(test)]
const fn generator_fd_snapshot_for_test() -> [i32; 5] {
    [22, 23, 24, 25, 26]
}

#[cfg(test)]
const fn worker_fd_snapshot_for_test() -> [i32; 3] {
    [22, 23, 24]
}

#[cfg(test)]
fn validate_fd_snapshot_for_test(
    observed: &[i32],
    exact: &[i32],
) -> Result<(), ProcessContractErrorV1> {
    if observed
        .iter()
        .any(|descriptor| *descriptor <= LAST_RESERVED_DESCRIPTOR_V1)
    {
        return Err(ProcessContractErrorV1::ReservedDescriptorOverlap);
    }
    if observed != exact {
        return Err(ProcessContractErrorV1::DescriptorInventory);
    }
    Ok(())
}

#[cfg(test)]
fn validate_generator_fds_for_test(observed: &[i32]) -> Result<(), ProcessContractErrorV1> {
    validate_fd_snapshot_for_test(observed, &generator_fd_snapshot_for_test())
}

#[cfg(test)]
fn validate_worker_fds_for_test(observed: &[i32]) -> Result<(), ProcessContractErrorV1> {
    validate_fd_snapshot_for_test(observed, &worker_fd_snapshot_for_test())
}

#[cfg(test)]
fn validate_generator_trampoline_for_test(
    actions: &[TrampolineActionV1],
) -> Result<(), ProcessContractErrorV1> {
    if actions == GENERATOR_TRAMPOLINE_ACTIONS_V1 {
        Ok(())
    } else {
        Err(ProcessContractErrorV1::TrampolineOrder)
    }
}

#[cfg(test)]
fn validate_pidfd_wait_for_test(options: u32, reap: bool) -> Result<(), ProcessContractErrorV1> {
    let expected = if reap {
        PIDFD_REAP_OPTIONS_V1
    } else {
        PIDFD_OBSERVE_OPTIONS_V1
    };
    if options == expected {
        Ok(())
    } else {
        Err(ProcessContractErrorV1::WaitOptions)
    }
}

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PidfdContainmentEventV1 {
    SignalDelivered,
    SignalInterrupted,
    SignalNoSuchProcess,
    SignalUnexpected,
    WaitReaped,
    WaitEmpty,
    WaitInterrupted,
    WaitWouldBlock,
    WaitNoChild,
    WaitUnexpected,
}

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PidfdContainmentActionV1 {
    AwaitExit,
    RetrySignal,
    RetryWait,
    Reaped,
    FailClosed,
}

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const fn pidfd_containment_action_v1(event: PidfdContainmentEventV1) -> PidfdContainmentActionV1 {
    match event {
        PidfdContainmentEventV1::SignalDelivered => PidfdContainmentActionV1::AwaitExit,
        PidfdContainmentEventV1::SignalInterrupted => PidfdContainmentActionV1::RetrySignal,
        PidfdContainmentEventV1::SignalNoSuchProcess
        | PidfdContainmentEventV1::WaitReaped
        | PidfdContainmentEventV1::WaitNoChild => PidfdContainmentActionV1::Reaped,
        PidfdContainmentEventV1::WaitEmpty
        | PidfdContainmentEventV1::WaitInterrupted
        | PidfdContainmentEventV1::WaitWouldBlock => PidfdContainmentActionV1::RetryWait,
        PidfdContainmentEventV1::SignalUnexpected | PidfdContainmentEventV1::WaitUnexpected => {
            PidfdContainmentActionV1::FailClosed
        }
    }
}

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const fn pidfd_live_checkpoint_accepts_v1(terminal_status_present: bool) -> bool {
    !terminal_status_present
}

#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
mod selected_target {
    use super::{
        ChildIdentityTransitionV1, CloneArgsV1, GENERATOR_CLONE_FLAGS_V1, GENERATOR_ENDPOINT_FD_V1,
        GENERATOR_FIRST_INGRESS_FD_V1, GENERATOR_GID_V1, GENERATOR_PUBLICATION_ROOT_FD_V1,
        GENERATOR_SUPERVISOR_PIDFD_V1, GENERATOR_UID_V1, LAST_RESERVED_DESCRIPTOR_V1,
        MAX_EXEC_ARGUMENTS_V1, MAX_EXEC_ENVIRONMENT_V1, MAX_GENERATOR_INGRESS_FDS_V1,
        MAX_PROCESS_FDS_V1, PidfdContainmentActionV1, PidfdContainmentEventV1,
        ProcessContractErrorV1, SIGCHLD_V1, WORKER_CLONE_FLAGS_V1, WORKER_ENDPOINT_FD_V1,
        WORKER_MAP_STAGES_V1, WORKER_OUTER_GID_V1, WORKER_OUTER_UID_V1, WorkerNamespaceMapsV1,
        parse_canonical_decimal, pidfd_containment_action_v1, pidfd_live_checkpoint_accepts_v1,
        translate_inner_to_outer_v1, validate_single_thread_snapshots,
    };
    use crate::{
        SupervisorReceiveProjectionV1, WorkerBootstrapProjectionV1,
        ancillary::{
            ExpectedPeerCredentialsV1, GeneratorEndpointV1, SupervisorGeneratorSendOpV1,
            SupervisorGeneratorSentEndpointV1, SupervisorWorkerBootstrapSendOpV1,
            WorkerBootstrapEnqueuedEndpointV1, WorkerEndpointV1,
        },
    };
    use core::ffi::{CStr, c_char, c_long, c_void};
    use core::marker::PhantomData;
    use core::ptr;
    use eip0045_h0_contract::wire::{DescriptorIdentityV1, PeerCredentialsV1};
    use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
    use rustix::io::{FdFlags, fcntl_dupfd_cloexec, fcntl_getfd, read, write};
    use rustix::net::{AddressFamily, SendFlags, SocketFlags, SocketType, UCred, send, socketpair};
    use rustix::process::{Gid, Uid, WaitId, WaitIdOptions, WaitIdStatus, waitid};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::rc::Rc;

    const SYS_READ: c_long = 0;
    const SYS_WRITE: c_long = 1;
    const SYS_RT_SIGACTION: c_long = 13;
    const SYS_RT_SIGPROCMASK: c_long = 14;
    const SYS_SCHED_YIELD: c_long = 24;
    const SYS_CLOSE_RANGE: c_long = 436;
    const SYS_DUP3: c_long = 292;
    const SYS_SETGROUPS: c_long = 116;
    const SYS_SETRESUID: c_long = 117;
    const SYS_SETRESGID: c_long = 119;
    const SYS_EXIT: c_long = 60;
    const SYS_EXIT_GROUP: c_long = 231;
    const SYS_KILL: c_long = 62;
    const SYS_WAIT4: c_long = 61;
    const SYS_EXECVEAT: c_long = 322;
    const SYS_OPENAT: c_long = 257;
    const SYS_CLONE3: c_long = 435;
    const AT_EMPTY_PATH: c_long = 0x1000;
    const O_RDONLY: c_long = 0;
    const O_NOFOLLOW: c_long = 0x20_000;
    const O_DIRECTORY: c_long = 0x10_000;
    const O_CLOEXEC: c_long = 0x80_000;
    const SIGKILL: c_long = 9;
    const SIGSTOP: c_long = 19;
    const SIG_SETMASK: c_long = 2;
    const MAX_KERNEL_SIGNAL_V1: c_long = 64;
    const CHILD_FAILURE_EXIT: c_long = 127;
    const TRANSITION_RELEASE_V1: u8 = 0x54;
    const IDENTITY_READY_V1: u8 = 0x49;
    const EXEC_RELEASE_V1: u8 = 0x45;
    const MAX_MAPPINGS: usize = 3 + MAX_GENERATOR_INGRESS_FDS_V1;
    const MAX_ALLOWED_AFTER_REMAP: usize = MAX_MAPPINGS + 1;
    const MAX_TEMPORARY_ALLOWED_V1: usize = MAX_ALLOWED_AFTER_REMAP + 2;
    const MAX_PROC_ENTRY_PATH_BYTES: usize = 32;
    const MAX_PROC_READBACK_BYTES: usize = 128;
    const MAX_PROC_STAT_BYTES: usize = 4096;
    const MAX_PROC_STATUS_BYTES_V1: usize = 8192;
    const MAX_STATUS_GROUPS_V1: usize = 64;

    unsafe extern "C" {
        fn syscall(number: c_long, ...) -> c_long;
    }

    #[derive(Clone, Copy)]
    struct FdMappingV1 {
        source: i32,
        target: i32,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct ProcfsFileIdentityV1 {
        device_major: u32,
        device_minor: u32,
        inode: u64,
        unique_mount_id: u64,
        file_type: rustix::fs::FileType,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct ProcfsThreadSnapshotV1 {
        pub(crate) process_id: i32,
        pub(crate) thread_id: i32,
        pub(crate) process_starttime: u64,
        pub(crate) thread_starttime: u64,
        pub(crate) pid_namespace: ProcfsFileIdentityV1,
        user_namespace: ProcfsFileIdentityV1,
        threads: [i32; MAX_PROCESS_FDS_V1],
        thread_count: usize,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ProcStatusSnapshotV1 {
        pid: u32,
        tgid: u32,
        threads: u32,
        uids: [u32; 4],
        gids: [u32; 4],
        groups: [u32; MAX_STATUS_GROUPS_V1],
        group_count: usize,
        cap_inheritable: u64,
        cap_permitted: u64,
        cap_effective: u64,
        cap_bounding: u64,
        cap_ambient: u64,
        no_new_privs: bool,
    }

    #[derive(Default)]
    struct ProcStatusFieldsV1 {
        process_id: Option<u32>,
        thread_group_id: Option<u32>,
        thread_count: Option<u32>,
        uids: Option<[u32; 4]>,
        gids: Option<[u32; 4]>,
        groups: Option<([u32; MAX_STATUS_GROUPS_V1], usize)>,
        cap_inheritable: Option<u64>,
        cap_permitted: Option<u64>,
        cap_effective: Option<u64>,
        cap_bounding: Option<u64>,
        cap_ambient: Option<u64>,
        no_new_privs: Option<bool>,
    }

    impl ProcStatusFieldsV1 {
        fn finish(self) -> Result<ProcStatusSnapshotV1, ProcessContractErrorV1> {
            let (groups, group_count) = self.groups.ok_or(ProcessContractErrorV1::ChildIdentity)?;
            Ok(ProcStatusSnapshotV1 {
                pid: self
                    .process_id
                    .ok_or(ProcessContractErrorV1::ChildIdentity)?,
                tgid: self
                    .thread_group_id
                    .ok_or(ProcessContractErrorV1::ChildIdentity)?,
                threads: self
                    .thread_count
                    .ok_or(ProcessContractErrorV1::ChildIdentity)?,
                uids: self.uids.ok_or(ProcessContractErrorV1::ChildIdentity)?,
                gids: self.gids.ok_or(ProcessContractErrorV1::ChildIdentity)?,
                groups,
                group_count,
                cap_inheritable: self
                    .cap_inheritable
                    .ok_or(ProcessContractErrorV1::ChildIdentity)?,
                cap_permitted: self
                    .cap_permitted
                    .ok_or(ProcessContractErrorV1::ChildIdentity)?,
                cap_effective: self
                    .cap_effective
                    .ok_or(ProcessContractErrorV1::ChildIdentity)?,
                cap_bounding: self
                    .cap_bounding
                    .ok_or(ProcessContractErrorV1::ChildIdentity)?,
                cap_ambient: self
                    .cap_ambient
                    .ok_or(ProcessContractErrorV1::ChildIdentity)?,
                no_new_privs: self
                    .no_new_privs
                    .ok_or(ProcessContractErrorV1::ChildIdentity)?,
            })
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SupervisorRuntimeSnapshotV1 {
        threads: ProcfsThreadSnapshotV1,
        status: ProcStatusSnapshotV1,
        securebits: u32,
    }

    /// Owned, opaque authority for one exact procfs mount and its live caller view.
    ///
    /// The descriptor is consumed, remains close-on-exec, is never exposed by a
    /// public getter, and is revalidated against `self`, `thread-self`, process
    /// start times, and the PID namespace at every observation.
    pub struct ProcfsAuthorityV1 {
        root: OwnedFd,
        root_identity: ProcfsFileIdentityV1,
        supervisor_runtime: SupervisorRuntimeSnapshotV1,
        _thread_bound: PhantomData<Rc<()>>,
    }

    impl ProcfsAuthorityV1 {
        /// Consumes and validates one close-on-exec procfs root descriptor.
        ///
        /// # Errors
        ///
        /// Rejects a non-procfs descriptor, a non-directory, missing CLOEXEC,
        /// or a view that does not resolve the current process and thread.
        pub fn new(root: OwnedFd) -> Result<Self, ProcessContractErrorV1> {
            let flags = fcntl_getfd(&root).map_err(kernel_error)?;
            if !flags.contains(FdFlags::CLOEXEC) {
                return Err(ProcessContractErrorV1::DescriptorNotCloseOnExec);
            }
            validate_procfs_filesystem(root.as_fd())?;
            let root_identity = procfs_file_identity(root.as_fd())?;
            if root_identity.file_type != rustix::fs::FileType::Directory {
                return Err(ProcessContractErrorV1::ProcfsRoot);
            }
            let supervisor_runtime = capture_supervisor_runtime_v1(root.as_fd(), root_identity)?;
            validate_supervisor_runtime_constraints_v1(&supervisor_runtime)?;
            Ok(Self {
                root,
                root_identity,
                supervisor_runtime,
                _thread_bound: PhantomData,
            })
        }

        fn root(&self) -> BorrowedFd<'_> {
            self.root.as_fd()
        }

        pub(crate) fn snapshot_current_threads(
            &self,
        ) -> Result<ProcfsThreadSnapshotV1, ProcessContractErrorV1> {
            snapshot_current_threads_v1(self.root(), self.root_identity)
        }

        pub(crate) fn reauthenticate_supervisor_runtime(
            &self,
        ) -> Result<ProcfsThreadSnapshotV1, ProcessContractErrorV1> {
            let observed = capture_supervisor_runtime_v1(self.root(), self.root_identity)?;
            validate_supervisor_runtime_constraints_v1(&observed)?;
            if observed != self.supervisor_runtime {
                return Err(ProcessContractErrorV1::ChildIdentity);
            }
            Ok(observed.threads)
        }
    }

    fn snapshot_current_threads_v1(
        procfs_root: BorrowedFd<'_>,
        root_identity: ProcfsFileIdentityV1,
    ) -> Result<ProcfsThreadSnapshotV1, ProcessContractErrorV1> {
        if procfs_file_identity(procfs_root)? != root_identity {
            return Err(ProcessContractErrorV1::ProcfsIdentity);
        }

        let process_id = rustix::process::getpid().as_raw_pid();
        let thread_id = rustix::thread::gettid().as_raw_pid();
        let process_id_u32 =
            u32::try_from(process_id).map_err(|_| ProcessContractErrorV1::ThreadIdentity)?;
        let thread_id_u32 =
            u32::try_from(thread_id).map_err(|_| ProcessContractErrorV1::ThreadIdentity)?;

        let magic_process = open_proc_magic_directory(procfs_root, c"self")?;
        let magic_thread = open_proc_magic_directory(procfs_root, c"thread-self")?;
        let process_path = ProcEntryPathV1::new(process_id_u32, b"\0")?;
        let numeric_process = open_proc_directory(procfs_root, &process_path)?;
        let thread_path = ProcEntryPathV1::new_process_thread(process_id_u32, thread_id_u32)?;
        let numeric_thread = open_proc_directory(procfs_root, &thread_path)?;

        if procfs_file_identity(magic_process.as_fd())?
            != procfs_file_identity(numeric_process.as_fd())?
            || procfs_file_identity(magic_thread.as_fd())?
                != procfs_file_identity(numeric_thread.as_fd())?
        {
            return Err(ProcessContractErrorV1::ProcfsIdentity);
        }

        let process_starttime = read_proc_starttime(magic_process.as_fd(), process_id_u32)?;
        let numeric_process_starttime =
            read_proc_starttime(numeric_process.as_fd(), process_id_u32)?;
        let thread_starttime = read_proc_starttime(magic_thread.as_fd(), thread_id_u32)?;
        let numeric_thread_starttime = read_proc_starttime(numeric_thread.as_fd(), thread_id_u32)?;
        if process_starttime != numeric_process_starttime
            || thread_starttime != numeric_thread_starttime
        {
            return Err(ProcessContractErrorV1::ProcfsIdentity);
        }

        let process_namespace = open_proc_pid_namespace(magic_process.as_fd())?;
        let numeric_process_namespace = open_proc_pid_namespace(numeric_process.as_fd())?;
        let thread_namespace = open_proc_pid_namespace(magic_thread.as_fd())?;
        let numeric_thread_namespace = open_proc_pid_namespace(numeric_thread.as_fd())?;
        let pid_namespace = procfs_file_identity(process_namespace.as_fd())?;
        if pid_namespace != procfs_file_identity(numeric_process_namespace.as_fd())?
            || pid_namespace != procfs_file_identity(thread_namespace.as_fd())?
            || pid_namespace != procfs_file_identity(numeric_thread_namespace.as_fd())?
        {
            return Err(ProcessContractErrorV1::ProcfsIdentity);
        }
        let process_user_namespace = open_proc_user_namespace(magic_process.as_fd())?;
        let numeric_process_user_namespace = open_proc_user_namespace(numeric_process.as_fd())?;
        let thread_user_namespace = open_proc_user_namespace(magic_thread.as_fd())?;
        let numeric_thread_user_namespace = open_proc_user_namespace(numeric_thread.as_fd())?;
        let user_namespace = procfs_file_identity(process_user_namespace.as_fd())?;
        if user_namespace != procfs_file_identity(numeric_process_user_namespace.as_fd())?
            || user_namespace != procfs_file_identity(thread_user_namespace.as_fd())?
            || user_namespace != procfs_file_identity(numeric_thread_user_namespace.as_fd())?
        {
            return Err(ProcessContractErrorV1::ProcfsIdentity);
        }

        let (threads, thread_count) = snapshot_threads(procfs_root, process_id_u32)?;
        Ok(ProcfsThreadSnapshotV1 {
            process_id,
            thread_id,
            process_starttime,
            thread_starttime,
            pid_namespace,
            user_namespace,
            threads,
            thread_count,
        })
    }

    fn capture_supervisor_runtime_v1(
        procfs_root: BorrowedFd<'_>,
        root_identity: ProcfsFileIdentityV1,
    ) -> Result<SupervisorRuntimeSnapshotV1, ProcessContractErrorV1> {
        let threads = snapshot_current_threads_v1(procfs_root, root_identity)?;
        let status = read_thread_self_status_v1(procfs_root)?;
        let capabilities = rustix::thread::capabilities(None).map_err(kernel_error)?;
        let securebits = rustix::thread::capabilities_secure_bits().map_err(kernel_error)?;
        let no_new_privs = rustix::thread::no_new_privs().map_err(kernel_error)?;

        let second_capabilities = rustix::thread::capabilities(None).map_err(kernel_error)?;
        let second_securebits = rustix::thread::capabilities_secure_bits().map_err(kernel_error)?;
        let second_no_new_privs = rustix::thread::no_new_privs().map_err(kernel_error)?;
        let second_status = read_thread_self_status_v1(procfs_root)?;
        let second_threads = snapshot_current_threads_v1(procfs_root, root_identity)?;
        validate_procfs_thread_snapshots(&threads, &second_threads)?;
        if status != second_status
            || capabilities != second_capabilities
            || securebits != second_securebits
            || no_new_privs != second_no_new_privs
        {
            return Err(ProcessContractErrorV1::ChildIdentity);
        }
        validate_proc_status_against_rustix_v1(&status, capabilities, no_new_privs)?;
        Ok(SupervisorRuntimeSnapshotV1 {
            threads,
            status,
            securebits: securebits.bits(),
        })
    }

    fn validate_proc_status_against_rustix_v1(
        status: &ProcStatusSnapshotV1,
        capabilities: rustix::thread::CapabilitySets,
        no_new_privs: bool,
    ) -> Result<(), ProcessContractErrorV1> {
        if status.uids[0] != rustix::process::getuid().as_raw()
            || status.uids[1] != rustix::process::geteuid().as_raw()
            || status.gids[0] != rustix::process::getgid().as_raw()
            || status.gids[1] != rustix::process::getegid().as_raw()
            || status.cap_effective != capabilities.effective.bits()
            || status.cap_permitted != capabilities.permitted.bits()
            || status.cap_inheritable != capabilities.inheritable.bits()
            || status.no_new_privs != no_new_privs
        {
            return Err(ProcessContractErrorV1::ChildIdentity);
        }
        let groups = rustix::process::getgroups().map_err(kernel_error)?;
        if groups.len() != status.group_count
            || groups
                .iter()
                .zip(&status.groups[..status.group_count])
                .any(|(observed, expected)| observed.as_raw() != *expected)
        {
            return Err(ProcessContractErrorV1::SupplementaryGroups);
        }
        Ok(())
    }

    fn validate_supervisor_runtime_constraints_v1(
        snapshot: &SupervisorRuntimeSnapshotV1,
    ) -> Result<(), ProcessContractErrorV1> {
        let status = &snapshot.status;
        let pid = u32::try_from(snapshot.threads.thread_id)
            .map_err(|_| ProcessContractErrorV1::ThreadIdentity)?;
        let tgid = u32::try_from(snapshot.threads.process_id)
            .map_err(|_| ProcessContractErrorV1::ThreadIdentity)?;
        let thread_count = u32::try_from(snapshot.threads.thread_count)
            .map_err(|_| ProcessContractErrorV1::ThreadMultiplicity)?;
        let required =
            (rustix::thread::CapabilitySet::SETUID | rustix::thread::CapabilitySet::SETGID).bits();
        let forbidden_securebits = (rustix::thread::CapabilitiesSecureBits::KEEP_CAPS
            | rustix::thread::CapabilitiesSecureBits::NO_SETUID_FIXUP)
            .bits();
        if snapshot.threads.process_id != snapshot.threads.thread_id
            || snapshot.threads.thread_count != 1
            || snapshot.threads.threads[0] != snapshot.threads.thread_id
            || status.pid != pid
            || status.tgid != tgid
            || status.threads != thread_count
            || thread_count != 1
            || status.uids != [0; 4]
            || status.gids != [0; 4]
            || status.group_count != 0
            || status.cap_inheritable != 0
            || status.cap_ambient != 0
            || status.cap_effective & required != required
            || status.cap_permitted & required != required
            || snapshot.securebits & forbidden_securebits != 0
        {
            return Err(ProcessContractErrorV1::ChildIdentity);
        }
        Ok(())
    }

    fn read_thread_self_status_v1(
        procfs_root: BorrowedFd<'_>,
    ) -> Result<ProcStatusSnapshotV1, ProcessContractErrorV1> {
        let thread = open_proc_magic_directory(procfs_root, c"thread-self")?;
        read_status_from_directory_v1(thread.as_fd())
    }

    fn read_child_status_v1(
        process_directory: BorrowedFd<'_>,
    ) -> Result<ProcStatusSnapshotV1, ProcessContractErrorV1> {
        read_status_from_directory_v1(process_directory)
    }

    fn read_status_from_directory_v1(
        process_directory: BorrowedFd<'_>,
    ) -> Result<ProcStatusSnapshotV1, ProcessContractErrorV1> {
        let descriptor = open_relative_proc_entry(process_directory, c"status", false)?;
        let mut bytes = [0_u8; MAX_PROC_STATUS_BYTES_V1];
        let mut len = 0_usize;
        loop {
            if len == bytes.len() {
                let mut surplus = [0_u8; 1];
                if read(&descriptor, &mut surplus).map_err(kernel_error)? != 0 {
                    return Err(ProcessContractErrorV1::KernelInvariant);
                }
                break;
            }
            let count = read(&descriptor, &mut bytes[len..]).map_err(kernel_error)?;
            if count == 0 {
                break;
            }
            len = len
                .checked_add(count)
                .ok_or(ProcessContractErrorV1::KernelInvariant)?;
        }
        parse_proc_status_v1(&bytes[..len])
    }

    fn parse_proc_status_v1(bytes: &[u8]) -> Result<ProcStatusSnapshotV1, ProcessContractErrorV1> {
        if !bytes.ends_with(b"\n") || bytes.contains(&b'\r') || bytes.contains(&0) {
            return Err(ProcessContractErrorV1::ChildIdentity);
        }
        let mut fields = ProcStatusFieldsV1::default();

        for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
            if let Some(value) = line.strip_prefix(b"Pid:") {
                set_unique_status_field_v1(
                    &mut fields.process_id,
                    parse_canonical_decimal(trim_ascii_v1(value))
                        .ok_or(ProcessContractErrorV1::ChildIdentity)?,
                )?;
            } else if let Some(value) = line.strip_prefix(b"Tgid:") {
                set_unique_status_field_v1(
                    &mut fields.thread_group_id,
                    parse_canonical_decimal(trim_ascii_v1(value))
                        .ok_or(ProcessContractErrorV1::ChildIdentity)?,
                )?;
            } else if let Some(value) = line.strip_prefix(b"Threads:") {
                set_unique_status_field_v1(
                    &mut fields.thread_count,
                    parse_canonical_decimal(trim_ascii_v1(value))
                        .ok_or(ProcessContractErrorV1::ChildIdentity)?,
                )?;
            } else if let Some(value) = line.strip_prefix(b"Uid:") {
                set_unique_status_field_v1(
                    &mut fields.uids,
                    parse_four_decimals_v1(value).ok_or(ProcessContractErrorV1::ChildIdentity)?,
                )?;
            } else if let Some(value) = line.strip_prefix(b"Gid:") {
                set_unique_status_field_v1(
                    &mut fields.gids,
                    parse_four_decimals_v1(value).ok_or(ProcessContractErrorV1::ChildIdentity)?,
                )?;
            } else if let Some(value) = line.strip_prefix(b"Groups:") {
                set_unique_status_field_v1(
                    &mut fields.groups,
                    parse_status_groups_v1(value).ok_or(ProcessContractErrorV1::ChildIdentity)?,
                )?;
            } else if let Some(value) = line.strip_prefix(b"CapInh:") {
                set_unique_status_field_v1(
                    &mut fields.cap_inheritable,
                    parse_fixed_hex_u64_v1(trim_ascii_v1(value))
                        .ok_or(ProcessContractErrorV1::ChildIdentity)?,
                )?;
            } else if let Some(value) = line.strip_prefix(b"CapPrm:") {
                set_unique_status_field_v1(
                    &mut fields.cap_permitted,
                    parse_fixed_hex_u64_v1(trim_ascii_v1(value))
                        .ok_or(ProcessContractErrorV1::ChildIdentity)?,
                )?;
            } else if let Some(value) = line.strip_prefix(b"CapEff:") {
                set_unique_status_field_v1(
                    &mut fields.cap_effective,
                    parse_fixed_hex_u64_v1(trim_ascii_v1(value))
                        .ok_or(ProcessContractErrorV1::ChildIdentity)?,
                )?;
            } else if let Some(value) = line.strip_prefix(b"CapBnd:") {
                set_unique_status_field_v1(
                    &mut fields.cap_bounding,
                    parse_fixed_hex_u64_v1(trim_ascii_v1(value))
                        .ok_or(ProcessContractErrorV1::ChildIdentity)?,
                )?;
            } else if let Some(value) = line.strip_prefix(b"CapAmb:") {
                set_unique_status_field_v1(
                    &mut fields.cap_ambient,
                    parse_fixed_hex_u64_v1(trim_ascii_v1(value))
                        .ok_or(ProcessContractErrorV1::ChildIdentity)?,
                )?;
            } else if let Some(value) = line.strip_prefix(b"NoNewPrivs:") {
                let parsed = match trim_ascii_v1(value) {
                    b"0" => false,
                    b"1" => true,
                    _ => return Err(ProcessContractErrorV1::ChildIdentity),
                };
                set_unique_status_field_v1(&mut fields.no_new_privs, parsed)?;
            }
        }
        fields.finish()
    }

    fn set_unique_status_field_v1<T>(
        slot: &mut Option<T>,
        value: T,
    ) -> Result<(), ProcessContractErrorV1> {
        if slot.replace(value).is_some() {
            return Err(ProcessContractErrorV1::ChildIdentity);
        }
        Ok(())
    }

    fn trim_ascii_v1(mut bytes: &[u8]) -> &[u8] {
        while bytes.first().is_some_and(u8::is_ascii_whitespace) {
            bytes = &bytes[1..];
        }
        while bytes.last().is_some_and(u8::is_ascii_whitespace) {
            bytes = &bytes[..bytes.len() - 1];
        }
        bytes
    }

    fn parse_four_decimals_v1(bytes: &[u8]) -> Option<[u32; 4]> {
        let mut output = [0_u32; 4];
        let mut fields = bytes
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty());
        for slot in &mut output {
            *slot = parse_canonical_decimal(fields.next()?)?;
        }
        if fields.next().is_some() {
            return None;
        }
        Some(output)
    }

    fn parse_status_groups_v1(bytes: &[u8]) -> Option<([u32; MAX_STATUS_GROUPS_V1], usize)> {
        let mut output = [0_u32; MAX_STATUS_GROUPS_V1];
        let mut count = 0_usize;
        for field in bytes
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty())
        {
            *output.get_mut(count)? = parse_canonical_decimal(field)?;
            count = count.checked_add(1)?;
        }
        Some((output, count))
    }

    fn parse_fixed_hex_u64_v1(bytes: &[u8]) -> Option<u64> {
        if bytes.len() != 16 {
            return None;
        }
        let mut value = 0_u64;
        for byte in bytes {
            let digit = match byte {
                b'0'..=b'9' => u64::from(*byte - b'0'),
                b'a'..=b'f' => u64::from(*byte - b'a' + 10),
                _ => return None,
            };
            value = value.checked_mul(16)?.checked_add(digit)?;
        }
        Some(value)
    }

    fn verify_current_thread_identity_v1(
        status: &ProcStatusSnapshotV1,
        transition: ChildIdentityTransitionV1,
    ) -> bool {
        let (uid, gid) = transition.target_ids();
        let identity_matches = status.pid == status.tgid
            && status.pid != 0
            && status.threads == 1
            && status.uids == [uid; 4]
            && status.gids == [gid; 4]
            && status.group_count == 0
            && status.cap_inheritable == 0
            && status.cap_ambient == 0;
        if !identity_matches {
            return false;
        }
        match transition {
            ChildIdentityTransitionV1::GeneratorService => {
                status.cap_effective == 0 && status.cap_permitted == 0
            }
            ChildIdentityTransitionV1::WorkerInnerZero => true,
        }
    }

    const fn transition_clears_supplementary_groups_v1(
        transition: ChildIdentityTransitionV1,
    ) -> bool {
        matches!(transition, ChildIdentityTransitionV1::GeneratorService)
    }

    fn verify_child_identity_v1(
        status: &ProcStatusSnapshotV1,
        child_pid: u32,
        transition: ChildIdentityTransitionV1,
    ) -> bool {
        let (uid, gid) = match transition {
            ChildIdentityTransitionV1::GeneratorService => (GENERATOR_UID_V1, GENERATOR_GID_V1),
            ChildIdentityTransitionV1::WorkerInnerZero => {
                (WORKER_OUTER_UID_V1, WORKER_OUTER_GID_V1)
            }
        };
        status.pid == child_pid
            && status.tgid == child_pid
            && status.threads == 1
            && status.uids == [uid; 4]
            && status.gids == [gid; 4]
            && status.group_count == 0
    }

    pub(crate) fn validate_procfs_thread_snapshots(
        first: &ProcfsThreadSnapshotV1,
        second: &ProcfsThreadSnapshotV1,
    ) -> Result<i32, ProcessContractErrorV1> {
        validate_single_thread_snapshots(
            first.process_id,
            first.thread_id,
            &first.threads[..first.thread_count],
            &second.threads[..second.thread_count],
        )?;
        if first.process_id != second.process_id || first.thread_id != second.thread_id {
            return Err(ProcessContractErrorV1::ThreadIdentity);
        }
        if first.process_starttime != second.process_starttime
            || first.thread_starttime != second.thread_starttime
            || first.pid_namespace != second.pid_namespace
            || first.user_namespace != second.user_namespace
        {
            return Err(ProcessContractErrorV1::ProcfsIdentity);
        }
        Ok(first.thread_id)
    }

    struct PreparedExecV1<'a> {
        executable: i32,
        argv: [*const c_char; MAX_EXEC_ARGUMENTS_V1 + 1],
        envp: [*const c_char; MAX_EXEC_ENVIRONMENT_V1 + 1],
        _borrows: PhantomData<&'a CStr>,
    }

    impl<'a> PreparedExecV1<'a> {
        fn new(
            executable: BorrowedFd<'a>,
            argv: &'a [&'a CStr],
            envp: &'a [&'a CStr],
        ) -> Result<Self, ProcessContractErrorV1> {
            if argv.is_empty()
                || argv.len() > MAX_EXEC_ARGUMENTS_V1
                || envp.len() > MAX_EXEC_ENVIRONMENT_V1
            {
                return Err(ProcessContractErrorV1::ExecVectorBounds);
            }
            let mut argv_raw = [ptr::null(); MAX_EXEC_ARGUMENTS_V1 + 1];
            let mut envp_raw = [ptr::null(); MAX_EXEC_ENVIRONMENT_V1 + 1];
            for (output, value) in argv_raw.iter_mut().zip(argv.iter()) {
                *output = value.as_ptr();
            }
            for (output, value) in envp_raw.iter_mut().zip(envp.iter()) {
                *output = value.as_ptr();
            }
            Ok(Self {
                executable: executable.as_raw_fd(),
                argv: argv_raw,
                envp: envp_raw,
                _borrows: PhantomData,
            })
        }
    }

    struct PreparedSpawnV1<'a> {
        exec: PreparedExecV1<'a>,
        cgroup: i32,
        authority: ProcfsAuthorityV1,
        sources: [BorrowedFd<'a>; MAX_PROCESS_FDS_V1],
        source_count: usize,
        mappings: [FdMappingV1; MAX_MAPPINGS],
        mapping_count: usize,
        allowed_after_remap: [u32; MAX_ALLOWED_AFTER_REMAP],
        allowed_count: usize,
        identity_transition: ChildIdentityTransitionV1,
    }

    /// Consumed-once generator spawn plan holding borrowed capabilities, the
    /// owned child endpoint, and one owned opaque procfs authority.
    pub(crate) struct GeneratorSpawnPlanV1<'a> {
        prepared: PreparedSpawnV1<'a>,
        endpoint: GeneratorEndpointV1,
    }

    impl<'a> GeneratorSpawnPlanV1<'a> {
        /// Prevalidates the fixed generator launch while consuming the opaque
        /// endpoint minted by D4's role-specific socketpair ledger.
        ///
        /// # Errors
        ///
        /// Rejects an ingress or execution-vector bound drift.
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn new_with_endpoint(
            retained_executable: BorrowedFd<'a>,
            cgroup: BorrowedFd<'a>,
            endpoint: GeneratorEndpointV1,
            supervisor_pidfd: BorrowedFd<'a>,
            publication_root: BorrowedFd<'a>,
            ingress: &'a [BorrowedFd<'a>],
            authority: ProcfsAuthorityV1,
            argv: &'a [&'a CStr],
            envp: &'a [&'a CStr],
        ) -> Result<Self, ProcessContractErrorV1> {
            let endpoint_descriptor = endpoint.descriptor();
            let prepared = Self::prepare_spawn(
                retained_executable,
                cgroup,
                endpoint_descriptor,
                supervisor_pidfd,
                publication_root,
                ingress,
                authority,
                argv,
                envp,
            )?;
            Ok(Self { prepared, endpoint })
        }

        /// Prevalidates fixed bounds and retains every source borrow for the
        /// live descriptor observation immediately joined to `clone3`.
        ///
        /// # Errors
        ///
        /// Rejects an ingress or execution-vector bound drift.
        #[allow(clippy::too_many_arguments)]
        fn prepare_spawn(
            retained_executable: BorrowedFd<'a>,
            cgroup: BorrowedFd<'a>,
            endpoint: BorrowedFd<'_>,
            supervisor_pidfd: BorrowedFd<'a>,
            publication_root: BorrowedFd<'a>,
            ingress: &'a [BorrowedFd<'a>],
            authority: ProcfsAuthorityV1,
            argv: &'a [&'a CStr],
            envp: &'a [&'a CStr],
        ) -> Result<PreparedSpawnV1<'a>, ProcessContractErrorV1> {
            if ingress.len() > MAX_GENERATOR_INGRESS_FDS_V1 {
                return Err(ProcessContractErrorV1::DescriptorInventory);
            }
            let mut sources = [retained_executable; MAX_PROCESS_FDS_V1];
            let fixed = [
                retained_executable,
                cgroup,
                supervisor_pidfd,
                publication_root,
            ];
            sources[..fixed.len()].copy_from_slice(&fixed);
            sources[fixed.len()..fixed.len() + ingress.len()].copy_from_slice(ingress);
            let source_count = fixed.len() + ingress.len();

            let mut mappings = [FdMappingV1 {
                source: -1,
                target: -1,
            }; MAX_MAPPINGS];
            mappings[0] = FdMappingV1 {
                source: endpoint.as_raw_fd(),
                target: GENERATOR_ENDPOINT_FD_V1,
            };
            mappings[1] = FdMappingV1 {
                source: supervisor_pidfd.as_raw_fd(),
                target: GENERATOR_SUPERVISOR_PIDFD_V1,
            };
            mappings[2] = FdMappingV1 {
                source: publication_root.as_raw_fd(),
                target: GENERATOR_PUBLICATION_ROOT_FD_V1,
            };
            for (index, descriptor) in ingress.iter().enumerate() {
                let target_offset = i32::try_from(index)
                    .map_err(|_| ProcessContractErrorV1::DescriptorInventory)?;
                mappings[3 + index] = FdMappingV1 {
                    source: descriptor.as_raw_fd(),
                    target: GENERATOR_FIRST_INGRESS_FD_V1 + target_offset,
                };
            }
            let exec = PreparedExecV1::new(retained_executable, argv, envp)?;
            let mapping_count = 3 + ingress.len();
            let (allowed_after_remap, allowed_count) =
                prepare_allowed_after_remap(exec.executable, &mappings, mapping_count)?;
            Ok(PreparedSpawnV1 {
                exec,
                cgroup: cgroup.as_raw_fd(),
                authority,
                sources,
                source_count,
                mappings,
                mapping_count,
                allowed_after_remap,
                allowed_count,
                identity_transition: ChildIdentityTransitionV1::GeneratorService,
            })
        }
    }

    /// Consumed-once worker spawn plan holding borrowed capabilities and one
    /// owned opaque procfs authority.
    pub(crate) struct WorkerSpawnPlanV1<'a> {
        prepared: PreparedSpawnV1<'a>,
        endpoint: WorkerEndpointV1,
        maps: WorkerNamespaceMapsV1,
    }

    impl<'a> WorkerSpawnPlanV1<'a> {
        /// Prevalidates the fixed worker launch while consuming the opaque
        /// endpoint minted by D4's role-specific socketpair ledger.
        ///
        /// # Errors
        ///
        /// Rejects identity, group, or execution-vector drift.
        #[allow(clippy::too_many_arguments)]
        pub(crate) fn new_with_endpoint(
            retained_executable: BorrowedFd<'a>,
            cgroup: BorrowedFd<'a>,
            endpoint: WorkerEndpointV1,
            authority: ProcfsAuthorityV1,
            argv: &'a [&'a CStr],
            envp: &'a [&'a CStr],
        ) -> Result<Self, ProcessContractErrorV1> {
            let endpoint_descriptor = endpoint.descriptor();
            let (prepared, maps) = Self::prepare_spawn(
                retained_executable,
                cgroup,
                endpoint_descriptor,
                authority,
                argv,
                envp,
            )?;
            Ok(Self {
                prepared,
                endpoint,
                maps,
            })
        }

        /// Prevalidates exact clone inputs and retains every source borrow for
        /// the live descriptor observation immediately joined to `clone3`.
        ///
        /// # Errors
        ///
        /// Rejects identity, group, or execution-vector drift.
        #[allow(clippy::too_many_arguments)]
        fn prepare_spawn(
            retained_executable: BorrowedFd<'a>,
            cgroup: BorrowedFd<'a>,
            endpoint: BorrowedFd<'_>,
            authority: ProcfsAuthorityV1,
            argv: &'a [&'a CStr],
            envp: &'a [&'a CStr],
        ) -> Result<(PreparedSpawnV1<'a>, WorkerNamespaceMapsV1), ProcessContractErrorV1> {
            let mut sources = [retained_executable; MAX_PROCESS_FDS_V1];
            let fixed = [retained_executable, cgroup];
            sources[..fixed.len()].copy_from_slice(&fixed);
            let mut mappings = [FdMappingV1 {
                source: -1,
                target: -1,
            }; MAX_MAPPINGS];
            mappings[0] = FdMappingV1 {
                source: endpoint.as_raw_fd(),
                target: WORKER_ENDPOINT_FD_V1,
            };
            let exec = PreparedExecV1::new(retained_executable, argv, envp)?;
            let (allowed_after_remap, allowed_count) =
                prepare_allowed_after_remap(exec.executable, &mappings, 1)?;
            Ok((
                PreparedSpawnV1 {
                    exec,
                    cgroup: cgroup.as_raw_fd(),
                    authority,
                    sources,
                    source_count: fixed.len(),
                    mappings,
                    mapping_count: 1,
                    allowed_after_remap,
                    allowed_count,
                    identity_transition: ChildIdentityTransitionV1::WorkerInnerZero,
                },
                WorkerNamespaceMapsV1::fixed_worker_v1(),
            ))
        }
    }

    enum OwnedChildEndpointV1 {
        Generator(GeneratorEndpointV1),
        Worker(WorkerEndpointV1),
    }

    impl OwnedChildEndpointV1 {
        fn descriptor(&self) -> BorrowedFd<'_> {
            match self {
                Self::Generator(endpoint) => endpoint.descriptor(),
                Self::Worker(endpoint) => endpoint.descriptor(),
            }
        }
    }

    fn validate_source_descriptors(
        sources: &[BorrowedFd<'_>],
    ) -> Result<(), ProcessContractErrorV1> {
        if sources.is_empty() || sources.len() > MAX_PROCESS_FDS_V1 {
            return Err(ProcessContractErrorV1::DescriptorInventory);
        }
        for (index, descriptor) in sources.iter().enumerate() {
            let raw = descriptor.as_raw_fd();
            if sources[..index]
                .iter()
                .any(|prior| prior.as_raw_fd() == raw)
                || raw <= LAST_RESERVED_DESCRIPTOR_V1
            {
                return Err(if raw <= LAST_RESERVED_DESCRIPTOR_V1 {
                    ProcessContractErrorV1::ReservedDescriptorOverlap
                } else {
                    ProcessContractErrorV1::DescriptorInventory
                });
            }
            let flags = fcntl_getfd(*descriptor).map_err(kernel_error)?;
            if !flags.contains(FdFlags::CLOEXEC) {
                return Err(ProcessContractErrorV1::DescriptorNotCloseOnExec);
            }
        }
        Ok(())
    }

    fn prepare_allowed_after_remap(
        executable: i32,
        mappings: &[FdMappingV1; MAX_MAPPINGS],
        mapping_count: usize,
    ) -> Result<([u32; MAX_ALLOWED_AFTER_REMAP], usize), ProcessContractErrorV1> {
        let mut allowed = [u32::MAX; MAX_ALLOWED_AFTER_REMAP];
        for (slot, mapping) in allowed.iter_mut().zip(&mappings[..mapping_count]) {
            *slot = u32::try_from(mapping.target)
                .map_err(|_| ProcessContractErrorV1::DescriptorInventory)?;
        }
        allowed[mapping_count] =
            u32::try_from(executable).map_err(|_| ProcessContractErrorV1::DescriptorInventory)?;
        let allowed_count = mapping_count + 1;
        allowed[..allowed_count].sort_unstable();
        if allowed[..allowed_count]
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(ProcessContractErrorV1::DescriptorInventory);
        }
        Ok((allowed, allowed_count))
    }

    fn kernel_error(error: rustix::io::Errno) -> ProcessContractErrorV1 {
        ProcessContractErrorV1::Kernel(error.raw_os_error())
    }

    fn write_control_byte_v1(
        descriptor: BorrowedFd<'_>,
        byte: u8,
    ) -> Result<(), ProcessContractErrorV1> {
        loop {
            match send(descriptor, &[byte], SendFlags::NOSIGNAL) {
                Ok(1) => return Ok(()),
                Ok(_) => return Err(ProcessContractErrorV1::KernelInvariant),
                Err(error) if error == rustix::io::Errno::INTR => {}
                Err(error) => return Err(kernel_error(error)),
            }
        }
    }

    fn read_control_byte_v1(
        descriptor: BorrowedFd<'_>,
        expected: u8,
    ) -> Result<(), ProcessContractErrorV1> {
        let mut byte = 0_u8;
        loop {
            match read(descriptor, core::slice::from_mut(&mut byte)) {
                Ok(1) if byte == expected => return Ok(()),
                Ok(_) => return Err(ProcessContractErrorV1::KernelInvariant),
                Err(error) if error == rustix::io::Errno::INTR => {}
                Err(error) => return Err(kernel_error(error)),
            }
        }
    }

    fn create_identity_barrier_v1() -> Result<(OwnedFd, OwnedFd), ProcessContractErrorV1> {
        let (local, remote) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(kernel_error)?;
        let child =
            fcntl_dupfd_cloexec(&local, LAST_RESERVED_DESCRIPTOR_V1 + 1).map_err(kernel_error)?;
        let parent =
            fcntl_dupfd_cloexec(&remote, LAST_RESERVED_DESCRIPTOR_V1 + 1).map_err(kernel_error)?;
        Ok((child, parent))
    }

    const BLOCKED_CATCHABLE_SIGNALS_V1: u64 =
        u64::MAX & !(1_u64 << (SIGKILL - 1)) & !(1_u64 << (SIGSTOP - 1));

    #[repr(C)]
    struct KernelSigactionV1 {
        handler: u64,
        flags: u64,
        restorer: u64,
        mask: u64,
    }

    const _: [(); 32] = [(); core::mem::size_of::<KernelSigactionV1>()];
    const _: [(); 8] = [(); core::mem::align_of::<KernelSigactionV1>()];
    const _: [(); 0] = [(); core::mem::offset_of!(KernelSigactionV1, handler)];
    const _: [(); 8] = [(); core::mem::offset_of!(KernelSigactionV1, flags)];
    const _: [(); 16] = [(); core::mem::offset_of!(KernelSigactionV1, restorer)];
    const _: [(); 24] = [(); core::mem::offset_of!(KernelSigactionV1, mask)];

    fn query_signal_mask() -> Result<u64, ProcessContractErrorV1> {
        let mut current = 0_u64;
        // SAFETY: the output points to one aligned eight-byte kernel signal set;
        // the null input requests observation without mutation.
        let result = unsafe {
            syscall(
                SYS_RT_SIGPROCMASK,
                SIG_SETMASK,
                ptr::null::<u64>(),
                &raw mut current,
                core::mem::size_of::<u64>(),
            )
        };
        if result == 0 {
            Ok(current)
        } else {
            Err(ProcessContractErrorV1::SignalMask)
        }
    }

    fn replace_signal_mask(
        new_mask: &u64,
        old_mask: Option<&mut u64>,
    ) -> Result<(), ProcessContractErrorV1> {
        let old_pointer = old_mask.map_or(ptr::null_mut(), ptr::from_mut);
        // SAFETY: x86-64 Linux uses one eight-byte kernel signal set; both
        // non-null pointers refer to live aligned `u64` values.
        let result = unsafe {
            syscall(
                SYS_RT_SIGPROCMASK,
                SIG_SETMASK,
                ptr::from_ref(new_mask),
                old_pointer,
                core::mem::size_of::<u64>(),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(ProcessContractErrorV1::SignalMask)
        }
    }

    struct SignalMaskGuardV1 {
        previous: u64,
        active: bool,
    }

    impl SignalMaskGuardV1 {
        fn block_all() -> Result<Self, ProcessContractErrorV1> {
            let mut previous = 0_u64;
            replace_signal_mask(&u64::MAX, Some(&mut previous))?;
            if query_signal_mask() != Ok(BLOCKED_CATCHABLE_SIGNALS_V1) {
                let _ = replace_signal_mask(&previous, None);
                return Err(ProcessContractErrorV1::SignalMask);
            }
            Ok(Self {
                previous,
                active: true,
            })
        }

        fn restore(mut self) -> Result<(), ProcessContractErrorV1> {
            replace_signal_mask(&self.previous, None)?;
            if query_signal_mask()? != self.previous {
                return Err(ProcessContractErrorV1::SignalMask);
            }
            self.active = false;
            Ok(())
        }
    }

    impl Drop for SignalMaskGuardV1 {
        fn drop(&mut self) {
            if self.active
                && replace_signal_mask(&self.previous, None).is_ok()
                && query_signal_mask() == Ok(self.previous)
            {
                self.active = false;
            }
        }
    }

    /// Role of a pidfd-bound direct child.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum SpawnedRoleV1 {
        /// Measured generator child.
        Generator,
        /// Attempt-local worker child.
        Worker,
    }

    /// Exact terminal status observed and later reaped through one pidfd.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum ExitObservationV1 {
        /// Normal exit status.
        Exited(i32),
        /// Fatal signal without a core dump.
        Killed(i32),
        /// Fatal signal with a core dump.
        Dumped(i32),
    }

    /// Owned pidfd for one direct child; it is intentionally not cloneable.
    pub(crate) struct RunningChildV1 {
        role: SpawnedRoleV1,
        pid: u32,
        pidfd: OwnedFd,
        reaped: bool,
    }

    impl RunningChildV1 {
        /// Returns the fixed role used at clone time.
        #[must_use]
        pub(crate) const fn role(&self) -> SpawnedRoleV1 {
            self.role
        }

        /// Returns the PID used only for exact namespace-map addressing.
        #[must_use]
        pub(crate) const fn pid(&self) -> u32 {
            self.pid
        }

        /// Requires that this pidfd has no pending terminal status without consuming it.
        ///
        /// # Errors
        ///
        /// Rejects an already reaped child, a terminal-but-unreaped child, or a kernel error.
        pub(crate) fn require_live(&self) -> Result<(), ProcessContractErrorV1> {
            if self.reaped {
                return Err(ProcessContractErrorV1::WaitOptions);
            }
            let status = waitid_retry(
                self.pidfd.as_fd(),
                WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
            )?;
            if !pidfd_live_checkpoint_accepts_v1(status.is_some()) {
                return Err(ProcessContractErrorV1::ChildIdentity);
            }
            Ok(())
        }

        /// Observes terminal status with exactly `P_PIDFD, WEXITED | WNOWAIT`.
        ///
        /// # Errors
        ///
        /// Returns a kernel error or rejects a nonterminal/impossible status.
        pub(crate) fn observe_exit(&self) -> Result<ExitObservationV1, ProcessContractErrorV1> {
            if self.reaped {
                return Err(ProcessContractErrorV1::WaitOptions);
            }
            let status = waitid_retry(
                self.pidfd.as_fd(),
                WaitIdOptions::EXITED | WaitIdOptions::NOWAIT,
            )?
            .ok_or(ProcessContractErrorV1::KernelInvariant)?;
            decode_exit(status)
        }

        /// Reaps the same pidfd and requires byte-equivalent terminal status.
        ///
        /// # Errors
        ///
        /// Returns a kernel error or rejects status drift between observe and reap.
        pub(crate) fn reap_exact(
            &mut self,
            observed: ExitObservationV1,
        ) -> Result<ExitObservationV1, ProcessContractErrorV1> {
            if self.reaped {
                return Err(ProcessContractErrorV1::WaitOptions);
            }
            let status = waitid_retry(self.pidfd.as_fd(), WaitIdOptions::EXITED)?
                .ok_or(ProcessContractErrorV1::KernelInvariant)?;
            self.reaped = true;
            let reaped = decode_exit(status)?;
            if reaped != observed {
                return Err(ProcessContractErrorV1::KernelInvariant);
            }
            Ok(reaped)
        }

        #[cfg(test)]
        fn set_pidfd_nonblocking_for_test(
            &self,
        ) -> Result<rustix::fs::OFlags, ProcessContractErrorV1> {
            let original = rustix::fs::fcntl_getfl(self.pidfd.as_fd()).map_err(kernel_error)?;
            rustix::fs::fcntl_setfl(
                self.pidfd.as_fd(),
                original.union(rustix::fs::OFlags::NONBLOCK),
            )
            .map_err(kernel_error)?;
            Ok(original)
        }
    }

    fn waitid_retry(
        pidfd: BorrowedFd<'_>,
        options: WaitIdOptions,
    ) -> Result<Option<WaitIdStatus>, ProcessContractErrorV1> {
        loop {
            match waitid(WaitId::PidFd(pidfd), options) {
                Ok(status) => return Ok(status),
                Err(error)
                    if error == rustix::io::Errno::INTR || error == rustix::io::Errno::AGAIN =>
                {
                    yield_containment();
                }
                Err(error) => return Err(kernel_error(error)),
            }
        }
    }

    fn pidfd_send_signal_retry(pidfd: BorrowedFd<'_>) -> PidfdContainmentActionV1 {
        loop {
            let event =
                match rustix::process::pidfd_send_signal(pidfd, rustix::process::Signal::KILL) {
                    Ok(()) => PidfdContainmentEventV1::SignalDelivered,
                    Err(error) if error == rustix::io::Errno::INTR => {
                        PidfdContainmentEventV1::SignalInterrupted
                    }
                    Err(error) if error == rustix::io::Errno::SRCH => {
                        PidfdContainmentEventV1::SignalNoSuchProcess
                    }
                    Err(_) => PidfdContainmentEventV1::SignalUnexpected,
                };
            let action = pidfd_containment_action_v1(event);
            if action != PidfdContainmentActionV1::RetrySignal {
                return action;
            }
        }
    }

    fn yield_containment() {
        // SAFETY: `sched_yield` has no arguments and is only a bounded retry aid.
        unsafe {
            let _ = syscall(SYS_SCHED_YIELD);
        }
    }

    impl Drop for RunningChildV1 {
        fn drop(&mut self) {
            if self.reaped {
                return;
            }
            match pidfd_send_signal_retry(self.pidfd.as_fd()) {
                PidfdContainmentActionV1::AwaitExit => {}
                PidfdContainmentActionV1::Reaped => {
                    self.reaped = true;
                    return;
                }
                PidfdContainmentActionV1::RetrySignal
                | PidfdContainmentActionV1::RetryWait
                | PidfdContainmentActionV1::FailClosed => containment_failure_exit_forever(),
            }
            loop {
                let event = match waitid(WaitId::PidFd(self.pidfd.as_fd()), WaitIdOptions::EXITED) {
                    Ok(Some(_)) => PidfdContainmentEventV1::WaitReaped,
                    Ok(None) => PidfdContainmentEventV1::WaitEmpty,
                    Err(error) if error == rustix::io::Errno::INTR => {
                        PidfdContainmentEventV1::WaitInterrupted
                    }
                    Err(error) if error == rustix::io::Errno::AGAIN => {
                        PidfdContainmentEventV1::WaitWouldBlock
                    }
                    Err(error) if error == rustix::io::Errno::CHILD => {
                        PidfdContainmentEventV1::WaitNoChild
                    }
                    Err(_) => PidfdContainmentEventV1::WaitUnexpected,
                };
                match pidfd_containment_action_v1(event) {
                    PidfdContainmentActionV1::Reaped => {
                        self.reaped = true;
                        break;
                    }
                    PidfdContainmentActionV1::RetryWait => yield_containment(),
                    PidfdContainmentActionV1::AwaitExit
                    | PidfdContainmentActionV1::RetrySignal
                    | PidfdContainmentActionV1::FailClosed => containment_failure_exit_forever(),
                }
            }
        }
    }

    #[cfg(test)]
    mod nonblocking_pidfd_mutant {
        use super::*;

        #[test]
        fn safe_fcntl_setfl_mutant_is_bound_to_private_pidfd_custody() {
            let mutation: fn(
                &RunningChildV1,
            ) -> Result<rustix::fs::OFlags, ProcessContractErrorV1> =
                RunningChildV1::set_pidfd_nonblocking_for_test;
            let _ = mutation;
        }
    }

    fn decode_exit(status: WaitIdStatus) -> Result<ExitObservationV1, ProcessContractErrorV1> {
        if let Some(code) = status.exit_status() {
            return Ok(ExitObservationV1::Exited(code));
        }
        if let Some(signal) = status.terminating_signal() {
            return Ok(if status.dumped() {
                ExitObservationV1::Dumped(signal)
            } else {
                ExitObservationV1::Killed(signal)
            });
        }
        Err(ProcessContractErrorV1::KernelInvariant)
    }

    /// Kernel-reread map snapshot tied to one still-blocked worker PID.
    ///
    /// This token records equality only; it is not session or execution authority.
    pub(crate) struct CheckedWorkerMapsV1 {
        pid: u32,
        directory_identity: ProcfsFileIdentityV1,
        process_starttime: u64,
        pid_namespace: ProcfsFileIdentityV1,
    }

    /// Generator whose fixed identity transition is complete and whose child
    /// remains blocked until the retained executable is reauthenticated.
    pub(crate) struct GeneratorIdentityReadyV1 {
        control: OwnedFd,
        child: RetainedChildProcessV1,
    }

    impl GeneratorIdentityReadyV1 {
        pub(crate) fn release_after_executable_reauthenticated_v1(
            self,
        ) -> Result<RetainedChildProcessV1, ProcessContractErrorV1> {
            write_control_byte_v1(self.control.as_fd(), EXEC_RELEASE_V1)?;
            let child = self.child;
            child.reauthenticate_live()?;
            Ok(child)
        }
    }

    /// Worker held behind an internal CLOEXEC socket barrier.
    pub(crate) struct BlockedWorkerV1 {
        release: OwnedFd,
        child: RetainedChildProcessV1,
        maps: WorkerNamespaceMapsV1,
    }

    /// Worker whose inner-zero transition is complete and whose child remains
    /// blocked until the retained executable is reauthenticated.
    pub(crate) struct WorkerIdentityReadyV1 {
        control: OwnedFd,
        child: RetainedChildProcessV1,
    }

    impl WorkerIdentityReadyV1 {
        pub(crate) fn release_after_executable_reauthenticated_v1(
            self,
        ) -> Result<PostReleaseWorkerV1, WorkerReleaseErrorV1> {
            if let Err(error) = write_control_byte_v1(self.control.as_fd(), EXEC_RELEASE_V1) {
                return Err(WorkerReleaseErrorV1 { error });
            }
            let retained = self.child;
            if let Err(error) = retained.reauthenticate_live() {
                return Err(WorkerReleaseErrorV1 { error });
            }
            Ok(PostReleaseWorkerV1(retained))
        }
    }

    impl BlockedWorkerV1 {
        pub(crate) fn reauthenticate_live(&self) -> Result<(), ProcessContractErrorV1> {
            self.child.reauthenticate_live()
        }

        /// Writes and rereads the exact maps through the retained child directory.
        ///
        /// The worker remains blocked throughout UID write/read, `setgroups`
        /// deny write/read, and GID write/read. The child directory was opened
        /// once beneath the owned authority and is revalidated before use.
        ///
        /// # Errors
        ///
        /// Rejects procfs identity, I/O, bounds, or semantic readback drift.
        pub(crate) fn configure_namespace_maps(
            &self,
        ) -> Result<CheckedWorkerMapsV1, ProcessContractErrorV1> {
            self.child.reauthenticate_live()?;
            let child_directory = self.child.projections.child_procfs.directory.as_fd();

            write_relative_proc_entry(child_directory, c"uid_map", self.maps.uid_map())?;
            let (uid_readback, uid_len) = read_relative_proc_entry(child_directory, c"uid_map")?;
            write_relative_proc_entry(
                child_directory,
                c"setgroups",
                WorkerNamespaceMapsV1::setgroups(),
            )?;
            let (setgroups_readback, setgroups_len) =
                read_relative_proc_entry(child_directory, c"setgroups")?;
            write_relative_proc_entry(child_directory, c"gid_map", self.maps.gid_map())?;
            let (gid_readback, gid_len) = read_relative_proc_entry(child_directory, c"gid_map")?;

            self.maps.verify_readback(
                &uid_readback[..uid_len],
                &setgroups_readback[..setgroups_len],
                &gid_readback[..gid_len],
                &WORKER_MAP_STAGES_V1,
                0,
            )?;
            Ok(CheckedWorkerMapsV1 {
                pid: self.child.pid(),
                directory_identity: self.child.projections.child_procfs.directory_identity,
                process_starttime: self.child.projections.child_procfs.process_starttime,
                pid_namespace: self.child.projections.child_procfs.pid_namespace,
            })
        }

        fn reread_namespace_maps_v1(&self) -> Result<(u32, u32), ProcessContractErrorV1> {
            self.child.reauthenticate_live()?;
            let child_directory = self.child.projections.child_procfs.directory.as_fd();
            let (uid_readback, uid_len) = read_relative_proc_entry(child_directory, c"uid_map")?;
            let (setgroups_readback, setgroups_len) =
                read_relative_proc_entry(child_directory, c"setgroups")?;
            let (gid_readback, gid_len) = read_relative_proc_entry(child_directory, c"gid_map")?;
            self.maps.verify_readback(
                &uid_readback[..uid_len],
                &setgroups_readback[..setgroups_len],
                &gid_readback[..gid_len],
                &WORKER_MAP_STAGES_V1,
                0,
            )?;
            if !self.maps.inner_zero_maps_to_worker_outer_v1()
                || !self.maps.supervisor_outer_root_is_unmapped_v1()
            {
                return Err(ProcessContractErrorV1::ChildIdentity);
            }
            let outer_uid = translate_inner_to_outer_v1(&uid_readback[..uid_len], 0)
                .ok_or(ProcessContractErrorV1::UidMap)?;
            let outer_gid = translate_inner_to_outer_v1(&gid_readback[..gid_len], 0)
                .ok_or(ProcessContractErrorV1::GidMap)?;
            Ok((outer_uid, outer_gid))
        }

        pub(crate) fn worker_bootstrap_projection_v1(
            &self,
            checked: &CheckedWorkerMapsV1,
        ) -> Result<WorkerBootstrapProjectionV1, ProcessContractErrorV1> {
            if checked.pid != self.child.pid()
                || checked.directory_identity
                    != self.child.projections.child_procfs.directory_identity
                || checked.process_starttime
                    != self.child.projections.child_procfs.process_starttime
                || checked.pid_namespace != self.child.projections.child_procfs.pid_namespace
            {
                return Err(ProcessContractErrorV1::ChildIdentity);
            }
            let (outer_uid, outer_gid) = self.reread_namespace_maps_v1()?;
            self.child.require_live()?;
            let supervisor = self.child.projections.reauthenticate(self.child.pid())?;
            let supervisor_pid = u32::try_from(supervisor.process_id)
                .map_err(|_| ProcessContractErrorV1::ChildIdentity)?;
            let worker_user_namespace = descriptor_identity_v1(
                self.child.projections.child_procfs.user_namespace_identity,
            )?;
            let supervisor_user_namespace = descriptor_identity_v1(
                self.child
                    .projections
                    .supervisor_receiver_user_namespace_identity,
            )?;
            let supervisor_to_worker_credentials =
                PeerCredentialsV1::try_new(supervisor_pid, 0, 0, worker_user_namespace)
                    .map_err(|_| ProcessContractErrorV1::ChildIdentity)?;
            Ok(WorkerBootstrapProjectionV1 {
                supervisor_to_worker_credentials,
                worker_receiver_view_uid: outer_uid,
                worker_receiver_view_gid: outer_gid,
                supervisor_receiver_user_namespace_identity: supervisor_user_namespace,
            })
        }

        fn worker_bootstrap_projection_from_snapshot_v1(
            &self,
            checked: &CheckedWorkerMapsV1,
            supervisor: ProcfsThreadSnapshotV1,
        ) -> Result<WorkerBootstrapProjectionV1, ProcessContractErrorV1> {
            if checked.pid != self.child.pid()
                || checked.directory_identity
                    != self.child.projections.child_procfs.directory_identity
                || checked.process_starttime
                    != self.child.projections.child_procfs.process_starttime
                || checked.pid_namespace != self.child.projections.child_procfs.pid_namespace
            {
                return Err(ProcessContractErrorV1::ChildIdentity);
            }
            let (outer_uid, outer_gid) = self.reread_namespace_maps_v1()?;
            self.child.require_live()?;
            let supervisor_pid = u32::try_from(supervisor.process_id)
                .map_err(|_| ProcessContractErrorV1::ChildIdentity)?;
            let worker_user_namespace = descriptor_identity_v1(
                self.child.projections.child_procfs.user_namespace_identity,
            )?;
            let supervisor_user_namespace = descriptor_identity_v1(
                self.child
                    .projections
                    .supervisor_receiver_user_namespace_identity,
            )?;
            let supervisor_to_worker_credentials =
                PeerCredentialsV1::try_new(supervisor_pid, 0, 0, worker_user_namespace)
                    .map_err(|_| ProcessContractErrorV1::ChildIdentity)?;
            Ok(WorkerBootstrapProjectionV1 {
                supervisor_to_worker_credentials,
                worker_receiver_view_uid: outer_uid,
                worker_receiver_view_gid: outer_gid,
                supervisor_receiver_user_namespace_identity: supervisor_user_namespace,
            })
        }

        /// Emits a kernel-delivered and kernel-validated privileged channel-identity claim.
        /// It is not proof of S's actual UID/GID; receiver cardinality is not sender construction proof.
        #[rustfmt::skip]
        pub(crate) fn enqueue_supervisor_bootstrap_once_v1(&self, checked: &CheckedWorkerMapsV1, op: SupervisorWorkerBootstrapSendOpV1,) -> Result<(WorkerBootstrapProjectionV1, WorkerBootstrapEnqueuedEndpointV1), ProcessContractErrorV1> {
            let before = self.child.reauthenticate_live_snapshot_v1()?;
            let projection = self.worker_bootstrap_projection_from_snapshot_v1(checked, before)?;
            let supervisor_pid = rustix::process::Pid::from_raw(before.process_id)
                .ok_or(ProcessContractErrorV1::ChildIdentity)?;
            let credentials = UCred {
                pid: supervisor_pid,
                uid: Uid::from_raw(WORKER_OUTER_UID_V1),
                gid: Gid::from_raw(WORKER_OUTER_GID_V1),
            };
            let endpoint = op.enqueue_once_v1(credentials)?;
            let after = self.child.reauthenticate_live_snapshot_v1()?;
            if before != after {
                return Err(ProcessContractErrorV1::ChildIdentity);
            }
            Ok((projection, endpoint))
        }

        /// Releases exactly one byte only after the opaque bootstrap enqueue.
        ///
        /// # Errors
        ///
        /// Returns an opaque error after consuming custody. On every error, the
        /// remaining custody is contained and reaped by its internal `Drop`.
        ///
        /// Borrowing `bootstrap_enqueued` proves that an enqueue-success token
        /// exists. The future private G0 composite is the sole owner that can
        /// join that token to this exact worker channel; E4d does not infer
        /// same-channel identity from the opaque token alone.
        #[allow(
            dead_code,
            clippy::needless_pass_by_value,
            reason = "the non-Copy checked snapshot is consumed as release authority"
        )]
        pub(crate) fn release_after_bootstrap_enqueued_v1(
            self,
            checked: CheckedWorkerMapsV1,
            bootstrap_enqueued: &WorkerBootstrapEnqueuedEndpointV1,
        ) -> Result<WorkerIdentityReadyV1, WorkerReleaseErrorV1> {
            let _ = bootstrap_enqueued;
            if checked.pid != self.child.pid()
                || checked.directory_identity
                    != self.child.projections.child_procfs.directory_identity
                || checked.process_starttime
                    != self.child.projections.child_procfs.process_starttime
                || checked.pid_namespace != self.child.projections.child_procfs.pid_namespace
                || self.child.reauthenticate_live().is_err()
                || self.reread_namespace_maps_v1().is_err()
            {
                return Err(WorkerReleaseErrorV1 {
                    error: ProcessContractErrorV1::ChildIdentity,
                });
            }
            if let Err(error) = write_control_byte_v1(self.release.as_fd(), TRANSITION_RELEASE_V1) {
                return Err(WorkerReleaseErrorV1 { error });
            }
            if let Err(error) = read_control_byte_v1(self.release.as_fd(), IDENTITY_READY_V1) {
                return Err(WorkerReleaseErrorV1 { error });
            }
            if let Err(error) = self.child.validate_child_identity_ready_v1() {
                return Err(WorkerReleaseErrorV1 { error });
            }
            Ok(WorkerIdentityReadyV1 {
                control: self.release,
                child: self.child,
            })
        }
    }

    struct ProcEntryPathV1 {
        bytes: [u8; MAX_PROC_ENTRY_PATH_BYTES],
        len: usize,
    }

    impl ProcEntryPathV1 {
        fn new(pid: u32, suffix_with_nul: &[u8]) -> Result<Self, ProcessContractErrorV1> {
            if suffix_with_nul.last() != Some(&0) {
                return Err(ProcessContractErrorV1::KernelInvariant);
            }
            let mut digits = [0_u8; 10];
            let mut value = pid;
            let mut digit_count = 0_usize;
            loop {
                digits[digit_count] = b'0'
                    + u8::try_from(value % 10)
                        .map_err(|_| ProcessContractErrorV1::KernelInvariant)?;
                digit_count += 1;
                value /= 10;
                if value == 0 {
                    break;
                }
            }
            let len = digit_count
                .checked_add(suffix_with_nul.len())
                .ok_or(ProcessContractErrorV1::KernelInvariant)?;
            if len > MAX_PROC_ENTRY_PATH_BYTES {
                return Err(ProcessContractErrorV1::KernelInvariant);
            }
            let mut bytes = [0_u8; MAX_PROC_ENTRY_PATH_BYTES];
            for index in 0..digit_count {
                bytes[index] = digits[digit_count - index - 1];
            }
            bytes[digit_count..len].copy_from_slice(suffix_with_nul);
            Ok(Self { bytes, len })
        }

        fn as_c_str(&self) -> Result<&CStr, ProcessContractErrorV1> {
            CStr::from_bytes_with_nul(&self.bytes[..self.len])
                .map_err(|_| ProcessContractErrorV1::KernelInvariant)
        }

        fn new_process_thread(
            process_id: u32,
            thread_id: u32,
        ) -> Result<Self, ProcessContractErrorV1> {
            let mut process_digits = [0_u8; 10];
            let mut process_value = process_id;
            let mut process_count = 0_usize;
            loop {
                process_digits[process_count] = b'0'
                    + u8::try_from(process_value % 10)
                        .map_err(|_| ProcessContractErrorV1::KernelInvariant)?;
                process_count += 1;
                process_value /= 10;
                if process_value == 0 {
                    break;
                }
            }
            let mut thread_digits = [0_u8; 10];
            let mut thread_value = thread_id;
            let mut thread_count = 0_usize;
            loop {
                thread_digits[thread_count] = b'0'
                    + u8::try_from(thread_value % 10)
                        .map_err(|_| ProcessContractErrorV1::KernelInvariant)?;
                thread_count += 1;
                thread_value /= 10;
                if thread_value == 0 {
                    break;
                }
            }
            let len = process_count
                .checked_add(b"/task/".len())
                .and_then(|value| value.checked_add(thread_count))
                .and_then(|value| value.checked_add(1))
                .ok_or(ProcessContractErrorV1::KernelInvariant)?;
            if len > MAX_PROC_ENTRY_PATH_BYTES {
                return Err(ProcessContractErrorV1::KernelInvariant);
            }
            let mut bytes = [0_u8; MAX_PROC_ENTRY_PATH_BYTES];
            for index in 0..process_count {
                bytes[index] = process_digits[process_count - index - 1];
            }
            let mut cursor = process_count;
            bytes[cursor..cursor + b"/task/".len()].copy_from_slice(b"/task/");
            cursor += b"/task/".len();
            for index in 0..thread_count {
                bytes[cursor + index] = thread_digits[thread_count - index - 1];
            }
            bytes[len - 1] = 0;
            Ok(Self { bytes, len })
        }
    }

    fn validate_procfs_filesystem(
        descriptor: BorrowedFd<'_>,
    ) -> Result<(), ProcessContractErrorV1> {
        let filesystem = rustix::fs::fstatfs(descriptor).map_err(kernel_error)?;
        if filesystem.f_type == rustix::fs::PROC_SUPER_MAGIC {
            Ok(())
        } else {
            Err(ProcessContractErrorV1::ProcfsRoot)
        }
    }

    fn procfs_file_identity(
        descriptor: BorrowedFd<'_>,
    ) -> Result<ProcfsFileIdentityV1, ProcessContractErrorV1> {
        const STATX_MNT_ID_UNIQUE_V1: u32 = 0x4000;
        let flags = rustix::fs::AtFlags::EMPTY_PATH
            .union(rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
            .union(rustix::fs::AtFlags::NO_AUTOMOUNT);
        let requested = rustix::fs::StatxFlags::BASIC_STATS.union(
            rustix::fs::StatxFlags::from_bits_retain(STATX_MNT_ID_UNIQUE_V1),
        );
        let metadata =
            rustix::fs::statx(descriptor, c"", flags, requested).map_err(kernel_error)?;
        if metadata.stx_mask & requested.bits() != requested.bits() {
            return Err(ProcessContractErrorV1::ProcfsIdentity);
        }
        Ok(ProcfsFileIdentityV1 {
            device_major: metadata.stx_dev_major,
            device_minor: metadata.stx_dev_minor,
            inode: metadata.stx_ino,
            unique_mount_id: metadata.stx_mnt_id,
            file_type: rustix::fs::FileType::from_raw_mode(u32::from(metadata.stx_mode)),
        })
    }

    fn descriptor_identity_v1(
        observed: ProcfsFileIdentityV1,
    ) -> Result<DescriptorIdentityV1, ProcessContractErrorV1> {
        DescriptorIdentityV1::try_new(
            (u64::from(observed.device_major) << 32) | u64::from(observed.device_minor),
            observed.inode,
            observed.unique_mount_id,
        )
        .map_err(|_| ProcessContractErrorV1::ProcfsIdentity)
    }

    fn open_proc_magic_directory(
        procfs_root: BorrowedFd<'_>,
        name: &CStr,
    ) -> Result<OwnedFd, ProcessContractErrorV1> {
        let flags = rustix::fs::OFlags::PATH
            .union(rustix::fs::OFlags::DIRECTORY)
            .union(rustix::fs::OFlags::CLOEXEC);
        rustix::fs::openat(procfs_root, name, flags, rustix::fs::Mode::empty())
            .map_err(kernel_error)
    }

    fn open_proc_pid_namespace(
        process_directory: BorrowedFd<'_>,
    ) -> Result<OwnedFd, ProcessContractErrorV1> {
        let flags = rustix::fs::OFlags::PATH.union(rustix::fs::OFlags::CLOEXEC);
        rustix::fs::openat(
            process_directory,
            c"ns/pid",
            flags,
            rustix::fs::Mode::empty(),
        )
        .map_err(kernel_error)
    }

    fn open_proc_user_namespace(
        process_directory: BorrowedFd<'_>,
    ) -> Result<OwnedFd, ProcessContractErrorV1> {
        let flags = rustix::fs::OFlags::PATH.union(rustix::fs::OFlags::CLOEXEC);
        rustix::fs::openat(
            process_directory,
            c"ns/user",
            flags,
            rustix::fs::Mode::empty(),
        )
        .map_err(kernel_error)
    }

    fn read_proc_starttime(
        process_directory: BorrowedFd<'_>,
        expected_id: u32,
    ) -> Result<u64, ProcessContractErrorV1> {
        let flags = rustix::fs::OFlags::RDONLY
            .union(rustix::fs::OFlags::NOFOLLOW)
            .union(rustix::fs::OFlags::CLOEXEC);
        let resolve = rustix::fs::ResolveFlags::BENEATH
            .union(rustix::fs::ResolveFlags::NO_SYMLINKS)
            .union(rustix::fs::ResolveFlags::NO_MAGICLINKS)
            .union(rustix::fs::ResolveFlags::NO_XDEV);
        let descriptor = rustix::fs::openat2(
            process_directory,
            c"stat",
            flags,
            rustix::fs::Mode::empty(),
            resolve,
        )
        .map_err(kernel_error)?;
        let mut bytes = [0_u8; MAX_PROC_STAT_BYTES];
        let mut len = 0_usize;
        loop {
            if len == bytes.len() {
                let mut surplus = [0_u8; 1];
                if read(&descriptor, &mut surplus).map_err(kernel_error)? != 0 {
                    return Err(ProcessContractErrorV1::ProcfsIdentity);
                }
                break;
            }
            let count = read(&descriptor, &mut bytes[len..]).map_err(kernel_error)?;
            if count == 0 {
                break;
            }
            len = len
                .checked_add(count)
                .ok_or(ProcessContractErrorV1::KernelInvariant)?;
        }
        parse_proc_starttime(&bytes[..len], expected_id)
            .ok_or(ProcessContractErrorV1::ProcfsIdentity)
    }

    fn parse_proc_starttime(bytes: &[u8], expected_id: u32) -> Option<u64> {
        let first_space = bytes.iter().position(|byte| *byte == b' ')?;
        if parse_canonical_decimal(bytes.get(..first_space)?)? != expected_id
            || bytes.get(first_space + 1) != Some(&b'(')
        {
            return None;
        }
        let closing_parenthesis = bytes.iter().rposition(|byte| *byte == b')')?;
        let fields = bytes.get(closing_parenthesis + 1..)?;
        let starttime = fields
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty())
            .nth(19)?;
        parse_canonical_u64(starttime)
    }

    fn parse_canonical_u64(bytes: &[u8]) -> Option<u64> {
        if bytes.is_empty() || (bytes.len() > 1 && bytes[0] == b'0') {
            return None;
        }
        let mut value = 0_u64;
        for byte in bytes {
            if !byte.is_ascii_digit() {
                return None;
            }
            value = value
                .checked_mul(10)?
                .checked_add(u64::from(*byte - b'0'))?;
        }
        Some(value)
    }

    struct ValidatedChildProcfsV1 {
        directory: OwnedFd,
        directory_identity: ProcfsFileIdentityV1,
        process_starttime: u64,
        pid_namespace: ProcfsFileIdentityV1,
        receiver_user_namespace: OwnedFd,
        user_namespace_identity: ProcfsFileIdentityV1,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ReceiverUserNamespaceRelationV1 {
        SameAsSupervisor,
        DistinctFromSupervisor,
    }

    struct RetainedSessionProjectionsV1 {
        authority: ProcfsAuthorityV1,
        child_procfs: ValidatedChildProcfsV1,
        supervisor_receiver_user_namespace: OwnedFd,
        supervisor_receiver_user_namespace_identity: ProcfsFileIdentityV1,
        receiver_relation: ReceiverUserNamespaceRelationV1,
        identity_transition: ChildIdentityTransitionV1,
    }

    impl RetainedSessionProjectionsV1 {
        fn capture(
            authority: ProcfsAuthorityV1,
            child_pid: u32,
            receiver_relation: ReceiverUserNamespaceRelationV1,
            identity_transition: ChildIdentityTransitionV1,
        ) -> Result<Self, ProcessContractErrorV1> {
            let caller = authority.reauthenticate_supervisor_runtime()?;
            let supervisor_process = open_proc_magic_directory(authority.root(), c"self")?;
            let supervisor_receiver_user_namespace =
                open_proc_user_namespace(supervisor_process.as_fd())?;
            let supervisor_receiver_user_namespace_identity =
                procfs_file_identity(supervisor_receiver_user_namespace.as_fd())?;
            if supervisor_receiver_user_namespace_identity != caller.user_namespace {
                return Err(ProcessContractErrorV1::ProcfsIdentity);
            }
            let child_procfs = authority.open_child_directory(child_pid)?;
            let retained = Self {
                authority,
                child_procfs,
                supervisor_receiver_user_namespace,
                supervisor_receiver_user_namespace_identity,
                receiver_relation,
                identity_transition,
            };
            retained.reauthenticate(child_pid)?;
            Ok(retained)
        }

        fn reauthenticate(
            &self,
            child_pid: u32,
        ) -> Result<ProcfsThreadSnapshotV1, ProcessContractErrorV1> {
            let caller = self.authority.reauthenticate_supervisor_runtime()?;
            if procfs_file_identity(self.supervisor_receiver_user_namespace.as_fd())?
                != self.supervisor_receiver_user_namespace_identity
                || caller.user_namespace != self.supervisor_receiver_user_namespace_identity
            {
                return Err(ProcessContractErrorV1::ChildIdentity);
            }
            self.authority
                .revalidate_child_directory(child_pid, &self.child_procfs)?;
            self.revalidate_receiver_user_namespace_relation(caller.user_namespace)?;
            Ok(caller)
        }

        fn revalidate_receiver_user_namespace_relation(
            &self,
            supervisor_user_namespace: ProcfsFileIdentityV1,
        ) -> Result<(), ProcessContractErrorV1> {
            let receiver_user_namespace =
                procfs_file_identity(self.child_procfs.receiver_user_namespace.as_fd())?;
            if receiver_user_namespace != self.child_procfs.user_namespace_identity {
                return Err(ProcessContractErrorV1::ChildIdentity);
            }
            let relation_matches = match self.receiver_relation {
                ReceiverUserNamespaceRelationV1::SameAsSupervisor => {
                    receiver_user_namespace == supervisor_user_namespace
                }
                ReceiverUserNamespaceRelationV1::DistinctFromSupervisor => {
                    receiver_user_namespace != supervisor_user_namespace
                }
            };
            if !relation_matches {
                return Err(ProcessContractErrorV1::ChildIdentity);
            }
            Ok(())
        }
    }

    /// Direct-child and process-observation authority retained as one private owner.
    pub(crate) struct RetainedChildProcessV1 {
        child: RunningChildV1,
        projections: RetainedSessionProjectionsV1,
    }

    impl RetainedChildProcessV1 {
        fn new(
            outcome: SpawnOutcomeV1,
            receiver_relation: ReceiverUserNamespaceRelationV1,
        ) -> Result<Self, ProcessContractErrorV1> {
            let child_pid = outcome.child.pid();
            let projections = RetainedSessionProjectionsV1::capture(
                outcome.authority,
                child_pid,
                receiver_relation,
                outcome.identity_transition,
            )?;
            let retained = Self {
                child: outcome.child,
                projections,
            };
            retained.reauthenticate_live()?;
            Ok(retained)
        }

        pub(crate) const fn pid(&self) -> u32 {
            self.child.pid()
        }

        fn require_live(&self) -> Result<(), ProcessContractErrorV1> {
            self.child.require_live()
        }

        fn reauthenticate_live_snapshot_v1(
            &self,
        ) -> Result<ProcfsThreadSnapshotV1, ProcessContractErrorV1> {
            let role_matches = matches!(
                (self.child.role(), self.projections.receiver_relation),
                (
                    SpawnedRoleV1::Generator,
                    ReceiverUserNamespaceRelationV1::SameAsSupervisor
                ) | (
                    SpawnedRoleV1::Worker,
                    ReceiverUserNamespaceRelationV1::DistinctFromSupervisor
                )
            );
            if !role_matches {
                return Err(ProcessContractErrorV1::ChildIdentity);
            }
            self.child.require_live()?;
            self.projections.reauthenticate(self.child.pid())
        }

        pub(crate) fn reauthenticate_live(&self) -> Result<(), ProcessContractErrorV1> {
            let _ = self.reauthenticate_live_snapshot_v1()?;
            Ok(())
        }

        pub(crate) fn supervisor_receive_projection_v1(
            &self,
        ) -> Result<SupervisorReceiveProjectionV1, ProcessContractErrorV1> {
            let supervisor = self.reauthenticate_live_snapshot_v1()?;
            self.supervisor_receive_projection_from_snapshot_v1(supervisor)
        }

        fn supervisor_receive_projection_from_snapshot_v1(
            &self,
            supervisor: ProcfsThreadSnapshotV1,
        ) -> Result<SupervisorReceiveProjectionV1, ProcessContractErrorV1> {
            let supervisor_pid = u32::try_from(supervisor.process_id)
                .map_err(|_| ProcessContractErrorV1::ChildIdentity)?;
            let supervisor_user_namespace = descriptor_identity_v1(
                self.projections.supervisor_receiver_user_namespace_identity,
            )?;
            let child_pid = self.child.pid();
            let (user_id, group_id, supervisor_to_generator) = match self.child.role() {
                SpawnedRoleV1::Generator => (
                    GENERATOR_UID_V1,
                    GENERATOR_GID_V1,
                    Some(
                        PeerCredentialsV1::try_new(
                            supervisor_pid,
                            WORKER_OUTER_UID_V1,
                            WORKER_OUTER_GID_V1,
                            supervisor_user_namespace,
                        )
                        .map_err(|_| ProcessContractErrorV1::ChildIdentity)?,
                    ),
                ),
                SpawnedRoleV1::Worker => (WORKER_OUTER_UID_V1, WORKER_OUTER_GID_V1, None),
            };
            let child_to_supervisor_expected =
                ExpectedPeerCredentialsV1::try_new(child_pid, user_id, group_id)
                    .map_err(|_| ProcessContractErrorV1::ChildIdentity)?;
            let child_to_supervisor_credentials =
                PeerCredentialsV1::try_new(child_pid, user_id, group_id, supervisor_user_namespace)
                    .map_err(|_| ProcessContractErrorV1::ChildIdentity)?;
            Ok(SupervisorReceiveProjectionV1 {
                child_to_supervisor_expected,
                child_to_supervisor_credentials,
                supervisor_receiver_user_namespace_identity: supervisor_user_namespace,
                supervisor_to_generator,
            })
        }

        /// Emits the same bounded claim for the retained generator route.
        #[rustfmt::skip]
        pub(crate) fn enqueue_supervisor_generator_once_v1(&self, op: SupervisorGeneratorSendOpV1,) -> Result<(SupervisorReceiveProjectionV1, SupervisorGeneratorSentEndpointV1), ProcessContractErrorV1> {
            let before = self.reauthenticate_live_snapshot_v1()?;
            let projection = self.supervisor_receive_projection_from_snapshot_v1(before)?;
            let supervisor_pid = rustix::process::Pid::from_raw(before.process_id)
                .ok_or(ProcessContractErrorV1::ChildIdentity)?;
            let credentials = UCred {
                pid: supervisor_pid,
                uid: Uid::from_raw(WORKER_OUTER_UID_V1),
                gid: Gid::from_raw(WORKER_OUTER_GID_V1),
            };
            let endpoint = op.enqueue_once_v1(credentials)?;
            let after = self.reauthenticate_live_snapshot_v1()?;
            if before != after {
                return Err(ProcessContractErrorV1::ChildIdentity);
            }
            Ok((projection, endpoint))
        }

        fn validate_child_identity_ready_v1(&self) -> Result<(), ProcessContractErrorV1> {
            self.reauthenticate_live()?;
            let first_status =
                read_child_status_v1(self.projections.child_procfs.directory.as_fd())?;
            let second_status =
                read_child_status_v1(self.projections.child_procfs.directory.as_fd())?;
            if first_status != second_status {
                return Err(ProcessContractErrorV1::ChildIdentity);
            }
            if !verify_child_identity_v1(
                &first_status,
                self.child.pid(),
                self.projections.identity_transition,
            ) {
                return Err(ProcessContractErrorV1::ChildIdentity);
            }
            Ok(())
        }

        pub(crate) fn observe_exit(&self) -> Result<ExitObservationV1, ProcessContractErrorV1> {
            self.projections.reauthenticate(self.child.pid())?;
            self.child.observe_exit()
        }

        pub(crate) fn reap_exact(
            &mut self,
            observed: ExitObservationV1,
        ) -> Result<ExitObservationV1, ProcessContractErrorV1> {
            self.projections.reauthenticate(self.child.pid())?;
            self.child.reap_exact(observed)
        }
    }

    /// Opaque worker custody after the bootstrap-gated release transition.
    pub(crate) struct PostReleaseWorkerV1(RetainedChildProcessV1);

    impl PostReleaseWorkerV1 {
        pub(crate) fn reauthenticate_live(&self) -> Result<(), ProcessContractErrorV1> {
            self.0.reauthenticate_live()
        }

        pub(crate) fn supervisor_receive_projection_v1(
            &self,
        ) -> Result<SupervisorReceiveProjectionV1, ProcessContractErrorV1> {
            self.0.supervisor_receive_projection_v1()
        }

        pub(crate) fn observe_exit(&self) -> Result<ExitObservationV1, ProcessContractErrorV1> {
            self.0.observe_exit()
        }

        pub(crate) fn reap_exact(
            &mut self,
            observed: ExitObservationV1,
        ) -> Result<ExitObservationV1, ProcessContractErrorV1> {
            self.0.reap_exact(observed)
        }
    }

    impl ProcfsAuthorityV1 {
        fn open_child_directory(
            &self,
            child_pid: u32,
        ) -> Result<ValidatedChildProcfsV1, ProcessContractErrorV1> {
            let caller = self.snapshot_current_threads()?;
            let child_path = ProcEntryPathV1::new(child_pid, b"\0")?;
            let directory = open_proc_directory(self.root(), &child_path)?;
            let directory_identity = procfs_file_identity(directory.as_fd())?;
            if directory_identity.file_type != rustix::fs::FileType::Directory {
                return Err(ProcessContractErrorV1::ProcfsIdentity);
            }
            let process_starttime = read_proc_starttime(directory.as_fd(), child_pid)?;
            let namespace = open_proc_pid_namespace(directory.as_fd())?;
            let pid_namespace = procfs_file_identity(namespace.as_fd())?;
            if pid_namespace != caller.pid_namespace {
                return Err(ProcessContractErrorV1::ProcfsIdentity);
            }
            let receiver_user_namespace = open_proc_user_namespace(directory.as_fd())?;
            let user_namespace_identity = procfs_file_identity(receiver_user_namespace.as_fd())?;
            Ok(ValidatedChildProcfsV1 {
                directory,
                directory_identity,
                process_starttime,
                pid_namespace,
                receiver_user_namespace,
                user_namespace_identity,
            })
        }

        fn revalidate_child_directory(
            &self,
            child_pid: u32,
            child: &ValidatedChildProcfsV1,
        ) -> Result<(), ProcessContractErrorV1> {
            let caller = self.snapshot_current_threads()?;
            if procfs_file_identity(child.directory.as_fd())? != child.directory_identity
                || read_proc_starttime(child.directory.as_fd(), child_pid)?
                    != child.process_starttime
            {
                return Err(ProcessContractErrorV1::ChildIdentity);
            }
            let namespace = open_proc_pid_namespace(child.directory.as_fd())?;
            let pid_namespace = procfs_file_identity(namespace.as_fd())?;
            if pid_namespace != child.pid_namespace || pid_namespace != caller.pid_namespace {
                return Err(ProcessContractErrorV1::ChildIdentity);
            }
            Self::revalidate_receiver_user_namespace(child)?;
            Ok(())
        }

        fn revalidate_receiver_user_namespace(
            child: &ValidatedChildProcfsV1,
        ) -> Result<(), ProcessContractErrorV1> {
            if procfs_file_identity(child.receiver_user_namespace.as_fd())?
                != child.user_namespace_identity
            {
                return Err(ProcessContractErrorV1::ChildIdentity);
            }
            let reread = open_proc_user_namespace(child.directory.as_fd())?;
            if procfs_file_identity(reread.as_fd())? != child.user_namespace_identity {
                return Err(ProcessContractErrorV1::ChildIdentity);
            }
            Ok(())
        }
    }

    fn open_relative_proc_entry(
        process_directory: BorrowedFd<'_>,
        name: &CStr,
        write_access: bool,
    ) -> Result<OwnedFd, ProcessContractErrorV1> {
        let access = if write_access {
            rustix::fs::OFlags::WRONLY
        } else {
            rustix::fs::OFlags::RDONLY
        };
        let flags = access
            .union(rustix::fs::OFlags::NOFOLLOW)
            .union(rustix::fs::OFlags::CLOEXEC);
        let resolve = rustix::fs::ResolveFlags::BENEATH
            .union(rustix::fs::ResolveFlags::NO_SYMLINKS)
            .union(rustix::fs::ResolveFlags::NO_MAGICLINKS)
            .union(rustix::fs::ResolveFlags::NO_XDEV);
        rustix::fs::openat2(
            process_directory,
            name,
            flags,
            rustix::fs::Mode::empty(),
            resolve,
        )
        .map_err(kernel_error)
    }

    fn write_relative_proc_entry(
        process_directory: BorrowedFd<'_>,
        name: &CStr,
        bytes: &[u8],
    ) -> Result<(), ProcessContractErrorV1> {
        let descriptor = open_relative_proc_entry(process_directory, name, true)?;
        if write(&descriptor, bytes).map_err(kernel_error)? != bytes.len() {
            return Err(ProcessContractErrorV1::KernelInvariant);
        }
        Ok(())
    }

    fn read_relative_proc_entry(
        process_directory: BorrowedFd<'_>,
        name: &CStr,
    ) -> Result<([u8; MAX_PROC_READBACK_BYTES], usize), ProcessContractErrorV1> {
        let descriptor = open_relative_proc_entry(process_directory, name, false)?;
        let mut bytes = [0_u8; MAX_PROC_READBACK_BYTES];
        let mut len = 0_usize;
        loop {
            if len == bytes.len() {
                let mut surplus = [0_u8; 1];
                if read(&descriptor, &mut surplus[..]).map_err(kernel_error)? != 0 {
                    return Err(ProcessContractErrorV1::KernelInvariant);
                }
                break;
            }
            let count = read(&descriptor, &mut bytes[len..]).map_err(kernel_error)?;
            if count == 0 {
                break;
            }
            len = len
                .checked_add(count)
                .ok_or(ProcessContractErrorV1::KernelInvariant)?;
        }
        Ok((bytes, len))
    }

    fn open_proc_directory(
        procfs_root: BorrowedFd<'_>,
        path: &ProcEntryPathV1,
    ) -> Result<OwnedFd, ProcessContractErrorV1> {
        let flags = rustix::fs::OFlags::RDONLY
            .union(rustix::fs::OFlags::DIRECTORY)
            .union(rustix::fs::OFlags::CLOEXEC);
        let resolve = rustix::fs::ResolveFlags::BENEATH
            .union(rustix::fs::ResolveFlags::NO_SYMLINKS)
            .union(rustix::fs::ResolveFlags::NO_MAGICLINKS)
            .union(rustix::fs::ResolveFlags::NO_XDEV);
        rustix::fs::openat2(
            procfs_root,
            path.as_c_str()?,
            flags,
            rustix::fs::Mode::empty(),
            resolve,
        )
        .map_err(kernel_error)
    }

    fn read_numeric_directory(
        directory: &mut rustix::fs::Dir,
        ignored_descriptor: Option<i32>,
        overflow_error: ProcessContractErrorV1,
    ) -> Result<([i32; MAX_PROCESS_FDS_V1], usize), ProcessContractErrorV1> {
        let mut observed = [0_i32; MAX_PROCESS_FDS_V1];
        let mut count = 0_usize;
        while let Some(entry) = directory.read() {
            let entry = entry.map_err(kernel_error)?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let value = parse_canonical_decimal(name)
                .and_then(|number| i32::try_from(number).ok())
                .ok_or(ProcessContractErrorV1::KernelInvariant)?;
            if ignored_descriptor == Some(value) {
                continue;
            }
            let slot = observed.get_mut(count).ok_or(overflow_error)?;
            *slot = value;
            count += 1;
        }
        observed[..count].sort_unstable();
        if observed[..count].windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ProcessContractErrorV1::KernelInvariant);
        }
        Ok((observed, count))
    }

    fn snapshot_threads(
        procfs_root: BorrowedFd<'_>,
        process_id: u32,
    ) -> Result<([i32; MAX_PROCESS_FDS_V1], usize), ProcessContractErrorV1> {
        let path = ProcEntryPathV1::new(process_id, b"/task\0")?;
        let descriptor = open_proc_directory(procfs_root, &path)?;
        let mut directory = rustix::fs::Dir::new(descriptor).map_err(kernel_error)?;
        read_numeric_directory(
            &mut directory,
            None,
            ProcessContractErrorV1::ThreadMultiplicity,
        )
    }

    fn observe_live_descriptor_inventory(
        prepared: &PreparedSpawnV1<'_>,
        endpoint: BorrowedFd<'_>,
        additional_sources: &[BorrowedFd<'_>],
    ) -> Result<(), ProcessContractErrorV1> {
        let total = prepared
            .source_count
            .checked_add(additional_sources.len())
            .and_then(|count| count.checked_add(2))
            .ok_or(ProcessContractErrorV1::DescriptorInventory)?;
        if total > MAX_PROCESS_FDS_V1 {
            return Err(ProcessContractErrorV1::DescriptorInventory);
        }
        let authority_root = prepared.authority.root();
        let mut sources = [authority_root; MAX_PROCESS_FDS_V1];
        sources[..prepared.source_count]
            .copy_from_slice(&prepared.sources[..prepared.source_count]);
        let endpoint_index = prepared.source_count;
        sources[endpoint_index] = endpoint;
        let additional_start = endpoint_index + 1;
        let additional_end = additional_start + additional_sources.len();
        sources[additional_start..additional_end].copy_from_slice(additional_sources);
        sources[additional_end] = authority_root;
        validate_source_descriptors(&sources[..total])?;

        let first = prepared.authority.snapshot_current_threads()?;
        let process_id_u32 =
            u32::try_from(first.process_id).map_err(|_| ProcessContractErrorV1::ThreadIdentity)?;

        let fd_path = ProcEntryPathV1::new(process_id_u32, b"/fd\0")?;
        let fd_directory = open_proc_directory(authority_root, &fd_path)?;
        let mut directory = rustix::fs::Dir::new(fd_directory).map_err(kernel_error)?;
        let enumeration_descriptor = directory.fd().map_err(kernel_error)?.as_raw_fd();
        let (observed, observed_count) = read_numeric_directory(
            &mut directory,
            Some(enumeration_descriptor),
            ProcessContractErrorV1::DescriptorInventory,
        )?;
        drop(directory);

        let second = prepared.authority.snapshot_current_threads()?;
        let _ = validate_procfs_thread_snapshots(&first, &second)?;

        let mut expected = [0_i32; MAX_PROCESS_FDS_V1];
        for (slot, descriptor) in expected.iter_mut().zip(&sources[..total]) {
            *slot = descriptor.as_raw_fd();
        }
        expected[..total].sort_unstable();
        if observed_count != total || observed[..observed_count] != expected[..total] {
            return Err(ProcessContractErrorV1::DescriptorInventory);
        }
        Ok(())
    }

    /// Opaque release failure returned after consuming custody.
    ///
    /// On every error, the remaining custody is contained and reaped by its
    /// internal `Drop`.
    #[allow(dead_code)]
    pub(crate) struct WorkerReleaseErrorV1 {
        error: ProcessContractErrorV1,
    }

    #[allow(dead_code)]
    impl WorkerReleaseErrorV1 {
        /// Returns the exact release failure.
        #[must_use]
        pub(crate) const fn error(&self) -> ProcessContractErrorV1 {
            self.error
        }
    }

    struct SpawnOutcomeV1 {
        child: RunningChildV1,
        authority: ProcfsAuthorityV1,
        identity_transition: ChildIdentityTransitionV1,
    }

    fn restore_before_error(
        guard: SignalMaskGuardV1,
        operation_error: ProcessContractErrorV1,
    ) -> ProcessContractErrorV1 {
        match guard.restore() {
            Ok(()) => operation_error,
            Err(restore_error) => restore_error,
        }
    }

    /// Creates one direct generator child with fixed flags, cgroup, and pidfd.
    ///
    /// # Errors
    ///
    /// Returns a pre-clone or kernel error without manufacturing a child handle.
    pub(crate) fn spawn_generator_once_v1(
        plan: GeneratorSpawnPlanV1<'_>,
    ) -> Result<GeneratorIdentityReadyV1, ProcessContractErrorV1> {
        let GeneratorSpawnPlanV1 { prepared, endpoint } = plan;
        let (child_control, parent_control) = create_identity_barrier_v1()?;
        let child_control_raw = child_control.as_raw_fd();
        let parent_control_raw = parent_control.as_raw_fd();
        let controls = [child_control.as_fd(), parent_control.as_fd()];
        let outcome = spawn_exact(
            prepared,
            OwnedChildEndpointV1::Generator(endpoint),
            GENERATOR_CLONE_FLAGS_V1,
            Some((child_control_raw, parent_control_raw)),
            &controls,
        )?;
        drop(child_control);
        let child = RetainedChildProcessV1::new(
            outcome,
            ReceiverUserNamespaceRelationV1::SameAsSupervisor,
        )?;
        write_control_byte_v1(parent_control.as_fd(), TRANSITION_RELEASE_V1)?;
        read_control_byte_v1(parent_control.as_fd(), IDENTITY_READY_V1)?;
        child.validate_child_identity_ready_v1()?;
        Ok(GeneratorIdentityReadyV1 {
            control: parent_control,
            child,
        })
    }

    /// Creates one blocked worker with the fixed user/mount namespace flags.
    ///
    /// # Errors
    ///
    /// Returns a pre-clone or kernel error; any created child fails closed.
    pub(crate) fn spawn_worker_once_v1(
        plan: WorkerSpawnPlanV1<'_>,
    ) -> Result<BlockedWorkerV1, ProcessContractErrorV1> {
        let WorkerSpawnPlanV1 {
            prepared,
            endpoint,
            maps,
        } = plan;
        let (child_barrier, parent_barrier) = create_identity_barrier_v1()?;
        let child_barrier_raw = child_barrier.as_raw_fd();
        let parent_barrier_raw = parent_barrier.as_raw_fd();
        let barriers = [child_barrier.as_fd(), parent_barrier.as_fd()];
        let outcome = spawn_exact(
            prepared,
            OwnedChildEndpointV1::Worker(endpoint),
            WORKER_CLONE_FLAGS_V1,
            Some((child_barrier_raw, parent_barrier_raw)),
            &barriers,
        )?;
        drop(child_barrier);
        let retained = match RetainedChildProcessV1::new(
            outcome,
            ReceiverUserNamespaceRelationV1::DistinctFromSupervisor,
        ) {
            Ok(retained) => retained,
            Err(error) => {
                return Err(error);
            }
        };
        Ok(BlockedWorkerV1 {
            release: parent_barrier,
            child: retained,
            maps,
        })
    }

    fn spawn_exact(
        prepared: PreparedSpawnV1<'_>,
        endpoint: OwnedChildEndpointV1,
        flags: u64,
        barrier: Option<(i32, i32)>,
        additional_sources: &[BorrowedFd<'_>],
    ) -> Result<SpawnOutcomeV1, ProcessContractErrorV1> {
        let signal_mask = SignalMaskGuardV1::block_all()?;
        if let Err(error) =
            observe_live_descriptor_inventory(&prepared, endpoint.descriptor(), additional_sources)
        {
            return Err(restore_before_error(signal_mask, error));
        }
        let mut pidfd_raw = -1_i32;
        let args = CloneArgsV1 {
            flags,
            pidfd: u64::try_from((&raw mut pidfd_raw).addr())
                .map_err(|_| ProcessContractErrorV1::KernelInvariant)?,
            child_tid: 0,
            parent_tid: 0,
            exit_signal: SIGCHLD_V1,
            stack: 0,
            stack_size: 0,
            tls: 0,
            set_tid: 0,
            set_tid_size: 0,
            cgroup: u64::try_from(prepared.cgroup).map_err(|_| ProcessContractErrorV1::Cgroup)?,
        };

        // SAFETY: `CloneArgsV1` exactly matches pinned `clone_args` v2 (88 bytes),
        // all pointer-bearing fields are zero except the live aligned pidfd slot,
        // flags are role constants, and the child enters only `child_trampoline`.
        let result = unsafe {
            syscall(
                SYS_CLONE3,
                (&raw const args).cast::<c_void>(),
                core::mem::size_of::<CloneArgsV1>(),
            )
        };
        if result < 0 {
            let error = ProcessContractErrorV1::Kernel(
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            );
            return Err(restore_before_error(signal_mask, error));
        }
        if result == 0 {
            child_trampoline(&prepared, barrier, signal_mask.previous);
        }

        drop(endpoint);

        if pidfd_raw < 0 {
            contain_child_without_pidfd(result);
            return Err(restore_before_error(
                signal_mask,
                ProcessContractErrorV1::KernelInvariant,
            ));
        }
        // SAFETY: successful `CLONE_PIDFD` initialized this unique nonnegative fd.
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_raw) };
        let Ok(pid) = u32::try_from(result) else {
            containment_failure_exit_forever()
        };
        let role = if flags == GENERATOR_CLONE_FLAGS_V1 {
            SpawnedRoleV1::Generator
        } else if flags == WORKER_CLONE_FLAGS_V1 {
            SpawnedRoleV1::Worker
        } else {
            containment_failure_exit_forever()
        };
        let child = RunningChildV1 {
            role,
            pid,
            pidfd,
            reaped: false,
        };
        if let Err(error) = signal_mask.restore() {
            drop(child);
            return Err(error);
        }
        Ok(SpawnOutcomeV1 {
            child,
            authority: prepared.authority,
            identity_transition: prepared.identity_transition,
        })
    }

    fn read_child_thread_self_status_raw_v1(procfs_root: i32) -> ProcStatusSnapshotV1 {
        // SAFETY: the post-clone child has all signals blocked and supplies its
        // retained, prevalidated procfs root. This helper performs fixed raw
        // syscalls over stack-resident buffers, closes every temporary fd, and
        // exits the child terminally on every malformed or incomplete result.
        unsafe {
            let thread_self = b"thread-self\0";
            let status_name = b"status\0";
            let thread_directory = syscall(
                SYS_OPENAT,
                procfs_root,
                thread_self.as_ptr().cast::<c_char>(),
                O_RDONLY | O_DIRECTORY | O_CLOEXEC,
                0,
            );
            if thread_directory < 0 {
                child_failure_exit_forever();
            }
            let status_descriptor = syscall(
                SYS_OPENAT,
                thread_directory,
                status_name.as_ptr().cast::<c_char>(),
                O_RDONLY | O_NOFOLLOW | O_CLOEXEC,
                0,
            );
            if syscall(SYS_CLOSE_RANGE, thread_directory, thread_directory, 0) != 0 {
                child_failure_exit_forever();
            }
            if status_descriptor < 0 {
                child_failure_exit_forever();
            }
            let mut status_bytes = [0_u8; MAX_PROC_STATUS_BYTES_V1];
            let mut status_len = 0_usize;
            loop {
                if status_len == status_bytes.len() {
                    let mut surplus = 0_u8;
                    if syscall(
                        SYS_READ,
                        status_descriptor,
                        (&raw mut surplus).cast::<c_void>(),
                        1_usize,
                    ) != 0
                    {
                        child_failure_exit_forever();
                    }
                    break;
                }
                let count = syscall(
                    SYS_READ,
                    status_descriptor,
                    status_bytes[status_len..].as_mut_ptr().cast::<c_void>(),
                    status_bytes.len() - status_len,
                );
                if count < 0 {
                    child_failure_exit_forever();
                }
                if count == 0 {
                    break;
                }
                let Ok(count) = usize::try_from(count) else {
                    child_failure_exit_forever();
                };
                let Some(next) = status_len.checked_add(count) else {
                    child_failure_exit_forever();
                };
                status_len = next;
            }
            if syscall(SYS_CLOSE_RANGE, status_descriptor, status_descriptor, 0) != 0 {
                child_failure_exit_forever();
            }
            let Ok(status) = parse_proc_status_v1(&status_bytes[..status_len]) else {
                child_failure_exit_forever();
            };
            status
        }
    }

    fn child_trampoline(
        prepared: &PreparedSpawnV1<'_>,
        barrier: Option<(i32, i32)>,
        previous_signal_mask: u64,
    ) -> ! {
        let barrier_reader = barrier.map_or(-1, |pair| pair.0);
        let barrier_writer = barrier.map_or(-1, |pair| pair.1);
        let mut release_byte = 0_u8;
        let procfs_root = prepared.authority.root.as_raw_fd();
        if !reset_child_signal_dispositions() {
            child_failure_exit_forever();
        }
        // SAFETY: after clone this block performs only fixed Linux syscalls over
        // prevalidated integers and stack-resident arrays. It allocates nothing,
        // takes no lock, returns nowhere, and exits immediately on any drift.
        unsafe {
            if barrier_reader < 0 || barrier_writer < 0 {
                child_failure_exit_forever();
            }
            if syscall(SYS_CLOSE_RANGE, barrier_writer, barrier_writer, 0) != 0 {
                child_failure_exit_forever();
            }
            if syscall(
                SYS_READ,
                barrier_reader,
                (&raw mut release_byte).cast::<c_void>(),
                1_usize,
            ) != 1
                || release_byte != TRANSITION_RELEASE_V1
            {
                child_failure_exit_forever();
            }

            for mapping in &prepared.mappings[..prepared.mapping_count] {
                if syscall(SYS_DUP3, mapping.source, mapping.target, 0) != mapping.target.into() {
                    child_failure_exit_forever();
                }
            }
            if !close_every_surplus(prepared, &[barrier_reader, procfs_root]) {
                child_failure_exit_forever();
            }
            let (uid, gid) = prepared.identity_transition.target_ids();
            if transition_clears_supplementary_groups_v1(prepared.identity_transition)
                && syscall(SYS_SETGROUPS, 0_usize, ptr::null::<u32>()) != 0
            {
                child_failure_exit_forever();
            }
            if syscall(SYS_SETRESGID, gid, gid, gid) != 0
                || syscall(SYS_SETRESUID, uid, uid, uid) != 0
            {
                child_failure_exit_forever();
            }
            let status = read_child_thread_self_status_raw_v1(procfs_root);
            if !verify_current_thread_identity_v1(&status, prepared.identity_transition) {
                child_failure_exit_forever();
            }
            let ready = IDENTITY_READY_V1;
            if syscall(
                SYS_WRITE,
                barrier_reader,
                (&raw const ready).cast::<c_void>(),
                1_usize,
            ) != 1
            {
                child_failure_exit_forever();
            }
            release_byte = 0;
            if syscall(
                SYS_READ,
                barrier_reader,
                (&raw mut release_byte).cast::<c_void>(),
                1_usize,
            ) != 1
                || release_byte != EXEC_RELEASE_V1
                || !close_every_surplus(prepared, &[])
            {
                child_failure_exit_forever();
            }
            let empty = [0_u8];
            if !restore_child_signal_mask(previous_signal_mask) {
                child_failure_exit_forever();
            }
            let _ = syscall(
                SYS_EXECVEAT,
                prepared.exec.executable,
                empty.as_ptr().cast::<c_char>(),
                prepared.exec.argv.as_ptr(),
                prepared.exec.envp.as_ptr(),
                AT_EMPTY_PATH,
            );
            child_failure_exit_forever();
        }
    }

    fn reset_child_signal_dispositions() -> bool {
        let default_action = KernelSigactionV1 {
            handler: 0,
            flags: 0,
            restorer: 0,
            mask: 0,
        };
        for signal in 1..=MAX_KERNEL_SIGNAL_V1 {
            if signal == SIGKILL || signal == SIGSTOP {
                continue;
            }
            // SAFETY: the child inherited all catchable signals blocked. This
            // pinned x86-64 kernel layout installs SIG_DFL without allocation.
            let result = unsafe {
                syscall(
                    SYS_RT_SIGACTION,
                    signal,
                    &raw const default_action,
                    ptr::null_mut::<KernelSigactionV1>(),
                    core::mem::size_of::<u64>(),
                )
            };
            if result != 0 {
                return false;
            }
        }
        true
    }

    fn restore_child_signal_mask(previous: u64) -> bool {
        let mut observed = 0_u64;
        // SAFETY: both pointers address aligned eight-byte kernel signal sets;
        // inherited dispositions have already been replaced by SIG_DFL.
        let restored = unsafe {
            syscall(
                SYS_RT_SIGPROCMASK,
                SIG_SETMASK,
                &raw const previous,
                ptr::null_mut::<u64>(),
                core::mem::size_of::<u64>(),
            )
        };
        if restored != 0 {
            return false;
        }
        // SAFETY: null input observes the exact child mask into `observed`.
        let queried = unsafe {
            syscall(
                SYS_RT_SIGPROCMASK,
                SIG_SETMASK,
                ptr::null::<u64>(),
                &raw mut observed,
                core::mem::size_of::<u64>(),
            )
        };
        queried == 0 && observed == previous
    }

    fn child_failure_exit_forever() -> ! {
        loop {
            // SAFETY: both calls use the fixed termination status. The loop is
            // the defined fallback if either kernel exit primitive returns.
            unsafe {
                let _ = syscall(SYS_EXIT_GROUP, CHILD_FAILURE_EXIT);
                let _ = syscall(SYS_EXIT, CHILD_FAILURE_EXIT);
            }
        }
    }

    fn containment_failure_exit_forever() -> ! {
        child_failure_exit_forever()
    }

    unsafe fn close_every_surplus(prepared: &PreparedSpawnV1<'_>, temporary: &[i32]) -> bool {
        if temporary.len() > 2 {
            return false;
        }
        let mut allowed = [u32::MAX; MAX_TEMPORARY_ALLOWED_V1];
        allowed[..prepared.allowed_count]
            .copy_from_slice(&prepared.allowed_after_remap[..prepared.allowed_count]);
        let mut allowed_count = prepared.allowed_count;
        for descriptor in temporary {
            let Ok(descriptor) = u32::try_from(*descriptor) else {
                return false;
            };
            allowed[allowed_count] = descriptor;
            allowed_count += 1;
        }
        for index in 1..allowed_count {
            let mut cursor = index;
            while cursor > 0 && allowed[cursor] < allowed[cursor - 1] {
                allowed.swap(cursor, cursor - 1);
                cursor -= 1;
            }
        }
        if allowed[..allowed_count]
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return false;
        }
        let mut first = 0_u32;
        for descriptor in &allowed[..allowed_count] {
            if first < *descriptor {
                // SAFETY: fixed `close_range(first, descriptor - 1, 0)`; neither
                // endpoint contains an allowed descriptor after sorting.
                if unsafe { syscall(SYS_CLOSE_RANGE, first, descriptor - 1, 0) } != 0 {
                    return false;
                }
            }
            first = descriptor.saturating_add(1);
        }
        if first != u32::MAX {
            // SAFETY: the final range contains no allowed descriptor.
            if unsafe { syscall(SYS_CLOSE_RANGE, first, u32::MAX, 0) } != 0 {
                return false;
            }
        }
        true
    }

    #[cfg(test)]
    mod e4i_selected_target_tests {
        use super::*;

        const EXACT_STATUS_V1: &[u8] = b"Name:\teip0045\nTgid:\t41\nPid:\t41\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t \nThreads:\t1\nCapInh:\t0000000000000000\nCapPrm:\t00000000000000c0\nCapEff:\t00000000000000c0\nCapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\n";

        #[test]
        fn proc_status_identity_parser_is_strict_and_field_complete_v1() {
            let exact = parse_proc_status_v1(EXACT_STATUS_V1).expect("exact status must parse");
            assert_eq!(exact.pid, 41);
            assert_eq!(exact.tgid, 41);
            assert_eq!(exact.threads, 1);
            assert_eq!(exact.uids, [0; 4]);
            assert_eq!(exact.gids, [0; 4]);
            assert_eq!(exact.group_count, 0);
            assert_eq!(exact.cap_permitted, 0xc0);
            assert_eq!(exact.cap_effective, 0xc0);
            assert!(!exact.no_new_privs);

            for required_line in [
                b"Tgid:\t41\n".as_slice(),
                b"Pid:\t41\n".as_slice(),
                b"Uid:\t0\t0\t0\t0\n".as_slice(),
                b"Gid:\t0\t0\t0\t0\n".as_slice(),
                b"Groups:\t \n".as_slice(),
                b"Threads:\t1\n".as_slice(),
                b"CapInh:\t0000000000000000\n".as_slice(),
                b"CapPrm:\t00000000000000c0\n".as_slice(),
                b"CapEff:\t00000000000000c0\n".as_slice(),
                b"CapBnd:\t000001ffffffffff\n".as_slice(),
                b"CapAmb:\t0000000000000000\n".as_slice(),
                b"NoNewPrivs:\t0\n".as_slice(),
            ] {
                let start = EXACT_STATUS_V1
                    .windows(required_line.len())
                    .position(|window| window == required_line)
                    .expect("required status line");
                let mut missing = EXACT_STATUS_V1.to_vec();
                missing.drain(start..start + required_line.len());
                assert!(parse_proc_status_v1(&missing).is_err());

                let mut duplicate = EXACT_STATUS_V1.to_vec();
                duplicate.extend_from_slice(required_line);
                assert!(parse_proc_status_v1(&duplicate).is_err());
            }

            for (needle, replacement) in [
                (
                    b"Uid:\t0\t0\t0\t0".as_slice(),
                    b"Uid:\t00\t0\t0\t0".as_slice(),
                ),
                (
                    b"CapEff:\t00000000000000c0".as_slice(),
                    b"CapEff:\t00000000000000C0".as_slice(),
                ),
                (b"NoNewPrivs:\t0".as_slice(), b"NoNewPrivs:\t2".as_slice()),
            ] {
                let start = EXACT_STATUS_V1
                    .windows(needle.len())
                    .position(|window| window == needle)
                    .expect("mutation needle");
                let mut mutant = EXACT_STATUS_V1.to_vec();
                mutant.splice(start..start + needle.len(), replacement.iter().copied());
                assert!(parse_proc_status_v1(&mutant).is_err());
            }

            let mut no_final_lf = EXACT_STATUS_V1.to_vec();
            assert_eq!(no_final_lf.pop(), Some(b'\n'));
            assert!(parse_proc_status_v1(&no_final_lf).is_err());
            let mut nul = EXACT_STATUS_V1.to_vec();
            nul[0] = 0;
            assert!(parse_proc_status_v1(&nul).is_err());

            let groups_needle = b"Groups:\t \n";
            let groups_start = EXACT_STATUS_V1
                .windows(groups_needle.len())
                .position(|window| window == groups_needle)
                .expect("groups mutation needle");
            let surplus_groups =
                format!("Groups:\t{}\n", ["0"; MAX_STATUS_GROUPS_V1 + 1].join(" "));
            let mut too_many_groups = EXACT_STATUS_V1.to_vec();
            too_many_groups.splice(
                groups_start..groups_start + groups_needle.len(),
                surplus_groups.bytes(),
            );
            assert!(parse_proc_status_v1(&too_many_groups).is_err());

            let threads_needle = b"Threads:\t1";
            let threads_start = EXACT_STATUS_V1
                .windows(threads_needle.len())
                .position(|window| window == threads_needle)
                .expect("threads mutation needle");
            let mut multiple_threads = EXACT_STATUS_V1.to_vec();
            multiple_threads.splice(
                threads_start..threads_start + threads_needle.len(),
                b"Threads:\t2".iter().copied(),
            );
            assert_eq!(
                parse_proc_status_v1(&multiple_threads)
                    .expect("thread count is a semantic constraint")
                    .threads,
                2
            );
        }

        fn status_for_transition_v1(
            transition: ChildIdentityTransitionV1,
            parent_view: bool,
        ) -> ProcStatusSnapshotV1 {
            let mut status = parse_proc_status_v1(EXACT_STATUS_V1).expect("exact status");
            let (uid, gid) = if parent_view {
                match transition {
                    ChildIdentityTransitionV1::GeneratorService => {
                        (GENERATOR_UID_V1, GENERATOR_GID_V1)
                    }
                    ChildIdentityTransitionV1::WorkerInnerZero => {
                        (WORKER_OUTER_UID_V1, WORKER_OUTER_GID_V1)
                    }
                }
            } else {
                transition.target_ids()
            };
            status.uids = [uid; 4];
            status.gids = [gid; 4];
            if matches!(transition, ChildIdentityTransitionV1::GeneratorService) {
                status.cap_effective = 0;
                status.cap_permitted = 0;
            }
            status
        }

        #[test]
        fn identity_validators_reject_each_uid_gid_slot_and_role_v1() {
            for transition in [
                ChildIdentityTransitionV1::GeneratorService,
                ChildIdentityTransitionV1::WorkerInnerZero,
            ] {
                let self_status = status_for_transition_v1(transition, false);
                assert!(verify_current_thread_identity_v1(&self_status, transition));
                let parent_status = status_for_transition_v1(transition, true);
                assert!(verify_child_identity_v1(&parent_status, 41, transition));

                for slot in 0..4 {
                    let mut mutant = self_status;
                    mutant.uids[slot] ^= 1;
                    assert!(!verify_current_thread_identity_v1(&mutant, transition));
                    let mut mutant = self_status;
                    mutant.gids[slot] ^= 1;
                    assert!(!verify_current_thread_identity_v1(&mutant, transition));

                    let mut mutant = parent_status;
                    mutant.uids[slot] ^= 1;
                    assert!(!verify_child_identity_v1(&mutant, 41, transition));
                    let mut mutant = parent_status;
                    mutant.gids[slot] ^= 1;
                    assert!(!verify_child_identity_v1(&mutant, 41, transition));
                }
            }
        }

        fn exact_supervisor_runtime_v1() -> SupervisorRuntimeSnapshotV1 {
            let namespace = ProcfsFileIdentityV1 {
                device_major: 1,
                device_minor: 2,
                inode: 3,
                unique_mount_id: 4,
                file_type: rustix::fs::FileType::Directory,
            };
            let mut threads = [0_i32; MAX_PROCESS_FDS_V1];
            threads[0] = 41;
            SupervisorRuntimeSnapshotV1 {
                threads: ProcfsThreadSnapshotV1 {
                    process_id: 41,
                    thread_id: 41,
                    process_starttime: 5,
                    thread_starttime: 5,
                    pid_namespace: namespace,
                    user_namespace: namespace,
                    threads,
                    thread_count: 1,
                },
                status: parse_proc_status_v1(EXACT_STATUS_V1).expect("exact status"),
                securebits: 0,
            }
        }

        #[test]
        fn supervisor_runtime_constraints_isolate_each_security_branch_v1() {
            let exact = exact_supervisor_runtime_v1();
            assert_eq!(validate_supervisor_runtime_constraints_v1(&exact), Ok(()));

            for slot in 0..4 {
                let mut mutant = exact;
                mutant.status.uids[slot] = 1;
                assert!(validate_supervisor_runtime_constraints_v1(&mutant).is_err());
                let mut mutant = exact;
                mutant.status.gids[slot] = 1;
                assert!(validate_supervisor_runtime_constraints_v1(&mutant).is_err());
            }
            for capability in [
                rustix::thread::CapabilitySet::SETUID.bits(),
                rustix::thread::CapabilitySet::SETGID.bits(),
            ] {
                let mut mutant = exact;
                mutant.status.cap_effective &= !capability;
                assert!(validate_supervisor_runtime_constraints_v1(&mutant).is_err());
                let mut mutant = exact;
                mutant.status.cap_permitted &= !capability;
                assert!(validate_supervisor_runtime_constraints_v1(&mutant).is_err());
            }
            let mut mutant = exact;
            mutant.status.cap_inheritable = 1;
            assert!(validate_supervisor_runtime_constraints_v1(&mutant).is_err());
            let mut mutant = exact;
            mutant.status.cap_ambient = 1;
            assert!(validate_supervisor_runtime_constraints_v1(&mutant).is_err());
            let mut mutant = exact;
            mutant.status.group_count = 1;
            assert!(validate_supervisor_runtime_constraints_v1(&mutant).is_err());
            for securebit in [
                rustix::thread::CapabilitiesSecureBits::KEEP_CAPS.bits(),
                rustix::thread::CapabilitiesSecureBits::NO_SETUID_FIXUP.bits(),
            ] {
                let mut mutant = exact;
                mutant.securebits = securebit;
                assert!(validate_supervisor_runtime_constraints_v1(&mutant).is_err());
            }

            for mutate in [
                |snapshot: &mut SupervisorRuntimeSnapshotV1| snapshot.status.cap_bounding ^= 1,
                |snapshot: &mut SupervisorRuntimeSnapshotV1| snapshot.status.no_new_privs = true,
                |snapshot: &mut SupervisorRuntimeSnapshotV1| {
                    snapshot.threads.process_starttime += 1;
                },
                |snapshot: &mut SupervisorRuntimeSnapshotV1| {
                    snapshot.threads.thread_starttime += 1;
                },
                |snapshot: &mut SupervisorRuntimeSnapshotV1| {
                    snapshot.threads.pid_namespace.inode += 1;
                },
                |snapshot: &mut SupervisorRuntimeSnapshotV1| {
                    snapshot.threads.user_namespace.inode += 1;
                },
            ] {
                let mut mutant = exact;
                mutate(&mut mutant);
                assert_ne!(mutant, exact, "retained snapshot drift must be visible");
            }
        }

        #[test]
        fn supplementary_group_clear_is_generator_only_v1() {
            assert!(transition_clears_supplementary_groups_v1(
                ChildIdentityTransitionV1::GeneratorService
            ));
            assert!(!transition_clears_supplementary_groups_v1(
                ChildIdentityTransitionV1::WorkerInnerZero
            ));
        }

        #[test]
        fn control_write_survives_peer_close_without_sigpipe_v1() {
            const CHILD_ENV: &str = "EIP0045_E4I_SIGPIPE_CHILD";
            assert_ne!(TRANSITION_RELEASE_V1, IDENTITY_READY_V1);
            assert_ne!(TRANSITION_RELEASE_V1, EXEC_RELEASE_V1);
            assert_ne!(IDENTITY_READY_V1, EXEC_RELEASE_V1);

            if std::env::var_os(CHILD_ENV).is_none() {
                let output = std::process::Command::new(
                    std::env::current_exe().expect("current musl test executable"),
                )
                .arg("control_write_survives_peer_close_without_sigpipe_v1")
                .arg("--nocapture")
                .env(CHILD_ENV, "1")
                .output()
                .expect("run fresh SIGPIPE subprocess");
                assert!(
                    output.status.success(),
                    "fresh SIGPIPE subprocess failed: status={:?}, stderr={}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                );
                return;
            }

            assert!(reset_child_signal_dispositions());
            assert!(restore_child_signal_mask(0));
            let (local, remote) = create_identity_barrier_v1().expect("create control pair");
            drop(remote);
            let error = write_control_byte_v1(local.as_fd(), EXEC_RELEASE_V1)
                .expect_err("closed peer must reject the release byte");
            assert!(matches!(error, ProcessContractErrorV1::Kernel(_)));

            let (reader, writer) = create_identity_barrier_v1().expect("create wrong-byte pair");
            write_control_byte_v1(writer.as_fd(), IDENTITY_READY_V1).expect("write wrong byte");
            assert_eq!(
                read_control_byte_v1(reader.as_fd(), EXEC_RELEASE_V1),
                Err(ProcessContractErrorV1::KernelInvariant)
            );

            let (reader, writer) = create_identity_barrier_v1().expect("create EOF pair");
            drop(writer);
            assert_eq!(
                read_control_byte_v1(reader.as_fd(), EXEC_RELEASE_V1),
                Err(ProcessContractErrorV1::KernelInvariant)
            );
        }

        #[test]
        fn supervisor_runtime_snapshot_rejects_multithreaded_test_harness_v1() {
            let root = rustix::fs::open(
                c"/proc",
                rustix::fs::OFlags::PATH
                    .union(rustix::fs::OFlags::DIRECTORY)
                    .union(rustix::fs::OFlags::CLOEXEC),
                rustix::fs::Mode::empty(),
            )
            .expect("open procfs root");
            assert_eq!(
                ProcfsAuthorityV1::new(root).err(),
                Some(ProcessContractErrorV1::ThreadIdentity)
            );
        }
    }

    fn contain_child_without_pidfd(pid: c_long) {
        if pid <= 0 {
            return;
        }
        // SAFETY: this fail-closed path sends SIGKILL to the exact positive PID
        // returned by clone3 and reaps that unreaped direct child. EINTR never
        // causes either containment operation to be abandoned.
        unsafe {
            loop {
                if syscall(SYS_KILL, pid, SIGKILL) == 0 {
                    break;
                }
                let error = std::io::Error::last_os_error().raw_os_error();
                if error == Some(3) {
                    break;
                }
                let _ = syscall(SYS_SCHED_YIELD);
            }
            loop {
                let waited = syscall(
                    SYS_WAIT4,
                    pid,
                    ptr::null_mut::<i32>(),
                    0,
                    ptr::null_mut::<c_void>(),
                );
                if waited == pid {
                    break;
                }
                if waited < 0 {
                    let error = std::io::Error::last_os_error().raw_os_error();
                    if error == Some(10) {
                        break;
                    }
                }
                let _ = syscall(SYS_SCHED_YIELD);
            }
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
pub use selected_target::ProcfsAuthorityV1;

#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
pub(crate) use selected_target::{
    BlockedWorkerV1, CheckedWorkerMapsV1, ExitObservationV1, GeneratorSpawnPlanV1,
    PostReleaseWorkerV1, RetainedChildProcessV1, WorkerSpawnPlanV1, spawn_generator_once_v1,
    spawn_worker_once_v1,
};

#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
pub(crate) use selected_target::validate_procfs_thread_snapshots;

#[cfg(test)]
mod exact_generator_spawn {
    use super::*;

    #[test]
    fn generator_requires_each_exact_clone_term() {
        let exact = generator_clone_snapshot_for_test();
        assert!(validate_generator_clone_for_test(exact).is_ok());
        for removed in [CLONE_PIDFD_V1, CLONE_INTO_CGROUP_V1] {
            let mut candidate = exact;
            candidate.flags &= !removed;
            assert_eq!(
                validate_generator_clone_for_test(candidate),
                Err(ProcessContractErrorV1::CloneFlags)
            );
        }
    }

    #[test]
    fn generator_rejects_every_forbidden_clone_flag_independently() {
        let exact = generator_clone_snapshot_for_test();
        for forbidden in FORBIDDEN_GENERATOR_CLONE_FLAGS_V1 {
            let mut candidate = exact;
            candidate.flags |= forbidden;
            assert_eq!(
                validate_generator_clone_for_test(candidate),
                Err(ProcessContractErrorV1::CloneFlags)
            );
        }
    }

    #[test]
    fn generator_requires_sigchld_pidfd_cgroup_and_direct_parentage() {
        let exact = generator_clone_snapshot_for_test();
        let mut wrong_signal = exact;
        wrong_signal.exit_signal = 0;
        assert_eq!(
            validate_generator_clone_for_test(wrong_signal),
            Err(ProcessContractErrorV1::ExitSignal)
        );
        let mut no_pidfd = exact;
        no_pidfd.pidfd_slot = false;
        assert_eq!(
            validate_generator_clone_for_test(no_pidfd),
            Err(ProcessContractErrorV1::PidfdSlot)
        );
        let mut no_cgroup = exact;
        no_cgroup.cgroup = false;
        assert_eq!(
            validate_generator_clone_for_test(no_cgroup),
            Err(ProcessContractErrorV1::Cgroup)
        );
    }

    #[test]
    fn generator_rejects_credential_and_descriptor_drift_independently() {
        assert_eq!(
            ChildIdentityTransitionV1::GeneratorService.target_ids(),
            (GENERATOR_UID_V1, GENERATOR_GID_V1)
        );
        assert_ne!(GENERATOR_UID_V1, WORKER_OUTER_UID_V1);
        assert_ne!(GENERATOR_GID_V1, WORKER_OUTER_GID_V1);

        let exact = generator_fd_snapshot_for_test();
        assert!(validate_generator_fds_for_test(&exact).is_ok());
        assert_eq!(
            validate_generator_fds_for_test(&exact[..exact.len() - 1]),
            Err(ProcessContractErrorV1::DescriptorInventory)
        );
        let mut surplus = exact.to_vec();
        surplus.push(99);
        assert_eq!(
            validate_generator_fds_for_test(&surplus),
            Err(ProcessContractErrorV1::DescriptorInventory)
        );
    }

    #[test]
    fn generator_trampoline_order_is_closed_and_allocation_free() {
        assert_eq!(
            GENERATOR_TRAMPOLINE_ACTIONS_V1,
            [
                TrampolineActionV1::RemapReservedDescriptors,
                TrampolineActionV1::CloseSurplusDescriptors,
                TrampolineActionV1::DropSupplementaryGroups,
                TrampolineActionV1::SetResGid,
                TrampolineActionV1::SetResUid,
                TrampolineActionV1::VerifyCurrentIdentity,
                TrampolineActionV1::SignalIdentityReady,
                TrampolineActionV1::WaitForExecRelease,
                TrampolineActionV1::RetainedExecveat,
            ]
        );
        for index in 0..GENERATOR_TRAMPOLINE_ACTIONS_V1.len() - 1 {
            let mut candidate = GENERATOR_TRAMPOLINE_ACTIONS_V1;
            candidate.swap(index, index + 1);
            assert_eq!(
                validate_generator_trampoline_for_test(&candidate),
                Err(ProcessContractErrorV1::TrampolineOrder)
            );
        }
    }
}

#[cfg(test)]
mod exact_worker_spawn {
    use super::*;

    #[test]
    fn worker_requires_each_exact_clone_flag() {
        let exact = worker_clone_snapshot_for_test();
        assert!(validate_worker_clone_for_test(exact).is_ok());
        for removed in [
            CLONE_NEWUSER_V1,
            CLONE_NEWNS_V1,
            CLONE_PIDFD_V1,
            CLONE_INTO_CGROUP_V1,
        ] {
            let mut candidate = exact;
            candidate.flags &= !removed;
            assert_eq!(
                validate_worker_clone_for_test(candidate),
                Err(ProcessContractErrorV1::CloneFlags)
            );
        }
    }

    #[test]
    fn worker_rejects_every_forbidden_clone_flag_independently() {
        let exact = worker_clone_snapshot_for_test();
        for forbidden in FORBIDDEN_WORKER_CLONE_FLAGS_V1 {
            let mut candidate = exact;
            candidate.flags |= forbidden;
            assert_eq!(
                validate_worker_clone_for_test(candidate),
                Err(ProcessContractErrorV1::CloneFlags)
            );
        }
    }

    #[test]
    fn worker_requires_sigchld_pidfd_and_clone_into_exact_cgroup() {
        let exact = worker_clone_snapshot_for_test();
        let mut wrong_signal = exact;
        wrong_signal.exit_signal = 0;
        assert_eq!(
            validate_worker_clone_for_test(wrong_signal),
            Err(ProcessContractErrorV1::ExitSignal)
        );
        let mut no_pidfd = exact;
        no_pidfd.pidfd_slot = false;
        assert_eq!(
            validate_worker_clone_for_test(no_pidfd),
            Err(ProcessContractErrorV1::PidfdSlot)
        );
        let mut no_cgroup = exact;
        no_cgroup.cgroup = false;
        assert_eq!(
            validate_worker_clone_for_test(no_cgroup),
            Err(ProcessContractErrorV1::Cgroup)
        );
    }

    #[test]
    fn worker_namespace_maps_reject_identity_content_and_order_drift() {
        let maps = WorkerNamespaceMapsV1::fixed_worker_v1();
        assert_eq!(maps.uid_map(), b"0 20002 1\n");
        assert_eq!(WorkerNamespaceMapsV1::setgroups(), b"deny\n");
        assert_eq!(maps.gid_map(), b"0 20002 1\n");
        let mut forged = maps;
        forged.uid_map[2] = b'1';
        assert_eq!(
            forged.verify_readback(
                b"0 20002 1\n",
                b"deny\n",
                b"0 20002 1\n",
                &WORKER_MAP_STAGES_V1,
                0,
            ),
            Err(ProcessContractErrorV1::ChildIdentity)
        );
        assert!(
            maps.verify_readback(
                b"         0      20002          1\n",
                b"deny\n",
                b"         0      20002          1\n",
                &WORKER_MAP_STAGES_V1,
                0,
            )
            .is_ok()
        );
        assert_eq!(
            maps.verify_readback(
                b"0 20003 1\n",
                b"deny\n",
                b"0 20002 1\n",
                &WORKER_MAP_STAGES_V1,
                0,
            ),
            Err(ProcessContractErrorV1::UidMap)
        );
        assert_eq!(
            maps.verify_readback(
                b"         0      20002          1\n         1      20003          1\n",
                b"deny\n",
                b"         0      20002          1\n",
                &WORKER_MAP_STAGES_V1,
                0,
            ),
            Err(ProcessContractErrorV1::UidMap)
        );
        assert_eq!(
            maps.verify_readback(
                b"00 20002 1\n",
                b"deny\n",
                b"0 20002 1\n",
                &WORKER_MAP_STAGES_V1,
                0,
            ),
            Err(ProcessContractErrorV1::UidMap)
        );
        assert_eq!(
            maps.verify_readback(
                b"0 20002 1\n",
                b"allow\n",
                b"0 20002 1\n",
                &WORKER_MAP_STAGES_V1,
                0,
            ),
            Err(ProcessContractErrorV1::SetgroupsMap)
        );
        assert_eq!(
            maps.verify_readback(
                b"0 20002 1\n",
                b"deny\n",
                b"0 20003 1\n",
                &WORKER_MAP_STAGES_V1,
                0,
            ),
            Err(ProcessContractErrorV1::GidMap)
        );
        let mut reordered = WORKER_MAP_STAGES_V1;
        reordered.swap(1, 2);
        assert_eq!(
            maps.verify_readback(b"0 20002 1\n", b"deny\n", b"0 20002 1\n", &reordered, 0,),
            Err(ProcessContractErrorV1::NamespaceMapOrder)
        );
        assert_eq!(
            maps.verify_readback(
                b"0 20002 1\n",
                b"deny\n",
                b"0 20002 1\n",
                &WORKER_MAP_STAGES_V1,
                1,
            ),
            Err(ProcessContractErrorV1::SupplementaryGroups)
        );
    }

    #[test]
    fn worker_inner_root_and_unmapped_supervisor_are_distinct_v1() {
        let maps = WorkerNamespaceMapsV1::fixed_worker_v1();
        assert_eq!(
            ChildIdentityTransitionV1::WorkerInnerZero.target_ids(),
            (0, 0)
        );
        assert!(maps.inner_zero_maps_to_worker_outer_v1());
        assert!(maps.supervisor_outer_root_is_unmapped_v1());
        assert_eq!(
            translate_inner_to_outer_v1(maps.uid_map(), 0),
            Some(WORKER_OUTER_UID_V1)
        );
        assert_eq!(
            translate_inner_to_outer_v1(maps.gid_map(), 0),
            Some(WORKER_OUTER_GID_V1)
        );
        assert_eq!(translate_inner_to_outer_v1(maps.uid_map(), 1), None);
        assert_eq!(translate_outer_to_inner_v1(maps.uid_map(), 0), None);
        assert_eq!(translate_outer_to_inner_v1(maps.gid_map(), 0), None);
    }

    #[test]
    fn worker_rejects_missing_surplus_and_reserved_source_descriptors() {
        let exact = worker_fd_snapshot_for_test();
        assert!(validate_worker_fds_for_test(&exact).is_ok());
        assert_eq!(
            validate_worker_fds_for_test(&exact[..exact.len() - 1]),
            Err(ProcessContractErrorV1::DescriptorInventory)
        );
        let mut surplus = exact.to_vec();
        surplus.push(99);
        assert_eq!(
            validate_worker_fds_for_test(&surplus),
            Err(ProcessContractErrorV1::DescriptorInventory)
        );
        let mut reserved = exact;
        reserved[0] = WORKER_ENDPOINT_FD_V1;
        assert_eq!(
            validate_worker_fds_for_test(&reserved),
            Err(ProcessContractErrorV1::ReservedDescriptorOverlap)
        );
    }

    #[test]
    fn worker_kernel_map_io_is_descriptor_rooted_and_cannot_mint_from_bytes() {
        let source = include_str!("process.rs");
        let byte_only_mint = ["pub fn check_", "namespace_maps"].concat();
        assert!(source.contains("pub(crate) fn configure_namespace_maps"));
        assert!(!source.contains(&byte_only_mint));
        assert!(source.contains("revalidate_child_directory"));
        assert!(source.contains("child_procfs.directory.as_fd()"));
        assert!(source.contains("rustix::fs::openat2("));
        assert!(source.contains("rustix::process::getgroups()"));

        let uid_write = source
            .find("write_relative_proc_entry(child_directory, c\"uid_map\"")
            .unwrap();
        let uid_read = source
            .find("read_relative_proc_entry(child_directory, c\"uid_map\"")
            .unwrap();
        let setgroups_write = source.find("WorkerNamespaceMapsV1::setgroups()").unwrap();
        let setgroups_read = source
            .find("read_relative_proc_entry(child_directory, c\"setgroups\"")
            .unwrap();
        let gid_write = source
            .find("write_relative_proc_entry(child_directory, c\"gid_map\"")
            .unwrap();
        let gid_read = source
            .find("read_relative_proc_entry(child_directory, c\"gid_map\"")
            .unwrap();
        assert!(uid_write < uid_read);
        assert!(uid_read < setgroups_write);
        assert!(setgroups_write < setgroups_read);
        assert!(setgroups_read < gid_write);
        assert!(gid_write < gid_read);
    }

    #[test]
    fn worker_trampoline_and_pidfd_wait_sequences_are_exact() {
        assert_eq!(
            WORKER_TRAMPOLINE_ACTIONS_V1,
            [
                TrampolineActionV1::WaitForVerifiedMaps,
                TrampolineActionV1::RemapReservedDescriptors,
                TrampolineActionV1::CloseSurplusDescriptors,
                TrampolineActionV1::SetResGid,
                TrampolineActionV1::SetResUid,
                TrampolineActionV1::VerifyCurrentIdentity,
                TrampolineActionV1::SignalIdentityReady,
                TrampolineActionV1::WaitForExecRelease,
                TrampolineActionV1::RetainedExecveat,
            ]
        );
        assert!(validate_pidfd_wait_for_test(PIDFD_OBSERVE_OPTIONS_V1, false).is_ok());
        assert!(validate_pidfd_wait_for_test(PIDFD_REAP_OPTIONS_V1, true).is_ok());
        assert_eq!(
            validate_pidfd_wait_for_test(PIDFD_REAP_OPTIONS_V1, false),
            Err(ProcessContractErrorV1::WaitOptions)
        );
        assert_eq!(
            validate_pidfd_wait_for_test(PIDFD_OBSERVE_OPTIONS_V1, true),
            Err(ProcessContractErrorV1::WaitOptions)
        );
    }

    #[test]
    fn pidfd_live_checkpoint_rejects_terminal_non_reaped_status() {
        assert!(pidfd_live_checkpoint_accepts_v1(false));
        assert!(!pidfd_live_checkpoint_accepts_v1(true));
        assert_eq!(PIDFD_REQUIRE_LIVE_OPTIONS_V1, 0x0100_0005);

        let source = include_str!("process.rs");
        let start = source.find("pub(crate) fn require_live(&self)").unwrap();
        let end = source[start..]
            .find("/// Observes terminal status")
            .unwrap()
            + start;
        let body = &source[start..end];
        for required in [
            "WaitIdOptions::EXITED",
            "WaitIdOptions::NOHANG",
            "WaitIdOptions::NOWAIT",
            "status.is_some()",
            "ProcessContractErrorV1::ChildIdentity",
        ] {
            assert!(
                body.contains(required),
                "missing live checkpoint {required}"
            );
        }
    }

    #[test]
    fn live_spawn_bracket_rejects_each_thread_snapshot_drift() {
        assert!(validate_single_thread_snapshots(41, 41, &[41], &[41]).is_ok());
        assert_eq!(
            validate_single_thread_snapshots(41, 42, &[42], &[42]),
            Err(ProcessContractErrorV1::ThreadIdentity)
        );
        assert_eq!(
            validate_single_thread_snapshots(41, 41, &[41, 42], &[41]),
            Err(ProcessContractErrorV1::ThreadMultiplicity)
        );
        assert_eq!(
            validate_single_thread_snapshots(41, 41, &[41], &[41, 42]),
            Err(ProcessContractErrorV1::ThreadMultiplicity)
        );
    }
}

#[cfg(test)]
mod pidfd_only_containment {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TerminalForTestV1 {
        Incomplete,
        Reaped,
        FailClosed,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ContainmentTraceForTestV1 {
        numeric_pid_reused: bool,
        signal_attempts: usize,
        wait_attempts: usize,
        retry_count: usize,
        numeric_kill_attempts: usize,
        numeric_wait4_attempts: usize,
        terminal: TerminalForTestV1,
    }

    fn simulate_pidfd_containment_for_test(
        events: &[PidfdContainmentEventV1],
        numeric_pid_reused: bool,
    ) -> ContainmentTraceForTestV1 {
        let mut trace = ContainmentTraceForTestV1 {
            numeric_pid_reused,
            signal_attempts: 0,
            wait_attempts: 0,
            retry_count: 0,
            numeric_kill_attempts: 0,
            numeric_wait4_attempts: 0,
            terminal: TerminalForTestV1::Incomplete,
        };
        let mut awaiting_exit = false;
        for event in events {
            if matches!(
                event,
                PidfdContainmentEventV1::SignalDelivered
                    | PidfdContainmentEventV1::SignalInterrupted
                    | PidfdContainmentEventV1::SignalNoSuchProcess
                    | PidfdContainmentEventV1::SignalUnexpected
            ) {
                trace.signal_attempts += 1;
            } else {
                trace.wait_attempts += 1;
            }
            match (awaiting_exit, pidfd_containment_action_v1(*event)) {
                (false, PidfdContainmentActionV1::AwaitExit) => awaiting_exit = true,
                (false, PidfdContainmentActionV1::RetrySignal)
                | (true, PidfdContainmentActionV1::RetryWait) => trace.retry_count += 1,
                (_, PidfdContainmentActionV1::Reaped) => {
                    trace.terminal = TerminalForTestV1::Reaped;
                    return trace;
                }
                (_, PidfdContainmentActionV1::FailClosed)
                | (false, PidfdContainmentActionV1::RetryWait)
                | (
                    true,
                    PidfdContainmentActionV1::AwaitExit | PidfdContainmentActionV1::RetrySignal,
                ) => {
                    trace.terminal = TerminalForTestV1::FailClosed;
                    return trace;
                }
            }
        }
        trace
    }

    #[test]
    fn pidfd_containment_esrch_ignores_a_reused_numeric_pid() {
        let trace = simulate_pidfd_containment_for_test(
            &[PidfdContainmentEventV1::SignalNoSuchProcess],
            true,
        );
        assert!(trace.numeric_pid_reused);
        assert_eq!(trace.terminal, TerminalForTestV1::Reaped);
        assert_eq!(trace.signal_attempts, 1);
        assert_eq!(trace.wait_attempts, 0);
        assert_eq!(trace.numeric_kill_attempts, 0);
        assert_eq!(trace.numeric_wait4_attempts, 0);
    }

    #[test]
    fn pidfd_containment_echild_never_falls_back_to_numeric_wait() {
        let trace = simulate_pidfd_containment_for_test(
            &[
                PidfdContainmentEventV1::SignalDelivered,
                PidfdContainmentEventV1::WaitNoChild,
            ],
            false,
        );
        assert_eq!(trace.terminal, TerminalForTestV1::Reaped);
        assert_eq!(trace.signal_attempts, 1);
        assert_eq!(trace.wait_attempts, 1);
        assert_eq!(trace.numeric_kill_attempts, 0);
        assert_eq!(trace.numeric_wait4_attempts, 0);
    }

    #[test]
    fn pidfd_containment_unexpected_errors_are_fail_closed() {
        let signal =
            simulate_pidfd_containment_for_test(&[PidfdContainmentEventV1::SignalUnexpected], true);
        let wait = simulate_pidfd_containment_for_test(
            &[
                PidfdContainmentEventV1::SignalDelivered,
                PidfdContainmentEventV1::WaitUnexpected,
            ],
            true,
        );
        for trace in [signal, wait] {
            assert_eq!(trace.terminal, TerminalForTestV1::FailClosed);
            assert_eq!(trace.numeric_kill_attempts, 0);
            assert_eq!(trace.numeric_wait4_attempts, 0);
        }
    }

    #[test]
    fn pidfd_containment_retries_eintr_eagain_and_empty_waits() {
        let trace = simulate_pidfd_containment_for_test(
            &[
                PidfdContainmentEventV1::SignalInterrupted,
                PidfdContainmentEventV1::SignalDelivered,
                PidfdContainmentEventV1::WaitInterrupted,
                PidfdContainmentEventV1::WaitWouldBlock,
                PidfdContainmentEventV1::WaitEmpty,
                PidfdContainmentEventV1::WaitReaped,
            ],
            false,
        );
        assert_eq!(trace.terminal, TerminalForTestV1::Reaped);
        assert_eq!(trace.signal_attempts, 2);
        assert_eq!(trace.wait_attempts, 4);
        assert_eq!(trace.retry_count, 4);
        assert_eq!(trace.numeric_kill_attempts, 0);
        assert_eq!(trace.numeric_wait4_attempts, 0);
    }
}
