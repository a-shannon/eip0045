//! Provider-fixed monotone seccomp contracts for generator and worker roles.

use core::fmt;

/// Closed syscall inventory used to build provider-owned filters.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SeccompSyscallV1 {
    Read = 0,
    Write = 1,
    Open = 2,
    Close = 3,
    Fstat = 5,
    Poll = 7,
    Lseek = 8,
    Mmap = 9,
    Mprotect = 10,
    Munmap = 11,
    Brk = 12,
    RtSigaction = 13,
    RtSigprocmask = 14,
    RtSigreturn = 15,
    Ioctl = 16,
    Pread64 = 17,
    Pwrite64 = 18,
    Readv = 19,
    Writev = 20,
    SchedYield = 24,
    Mremap = 25,
    Madvise = 28,
    Dup = 32,
    Dup2 = 33,
    Getpid = 39,
    Getppid = 110,
    Fstatfs = 138,
    Socket = 41,
    Accept = 43,
    Sendmsg = 46,
    Recvmsg = 47,
    Shutdown = 48,
    Socketpair = 53,
    Clone = 56,
    Fork = 57,
    Vfork = 58,
    Execve = 59,
    Exit = 60,
    Fcntl = 72,
    Fsync = 74,
    Fdatasync = 75,
    Ftruncate = 77,
    Ptrace = 101,
    SetTidAddress = 218,
    ClockGettime = 228,
    ClockNanosleep = 230,
    ExitGroup = 231,
    Openat = 257,
    Mkdirat = 258,
    Fchownat = 260,
    Unlinkat = 263,
    Linkat = 265,
    Fchmodat = 268,
    Ppoll = 271,
    Unshare = 272,
    Setns = 308,
    SetRobustList = 273,
    Dup3 = 292,
    Prlimit64 = 302,
    Accept4 = 288,
    Prctl = 157,
    Mount = 165,
    Umount2 = 166,
    Futex = 202,
    Gettid = 186,
    Getdents64 = 217,
    ProcessVmReadv = 310,
    ProcessVmWritev = 311,
    Renameat2 = 316,
    Seccomp = 317,
    Getrandom = 318,
    Execveat = 322,
    CopyFileRange = 326,
    Statx = 332,
    Rseq = 334,
    Fsopen = 430,
    Fsconfig = 431,
    Fsmount = 432,
    MoveMount = 429,
    OpenTree = 428,
    Clone3 = 435,
    CloseRange = 436,
    Openat2 = 437,
    PidfdGetfd = 438,
}

/// Role selected by a provider-owned initial filter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeccompRoleV1 {
    /// Measured generator.
    Generator,
    /// Attempt worker.
    Worker,
}

/// Monotone filter phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeccompPhaseV1 {
    /// Role-specific process seal.
    Initial,
    /// Strict worker cleanup phase with acquisition removed.
    NoAcquire,
}

/// Provider-fixed action for unmatched syscalls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeccompDefaultActionV1 {
    /// Terminate the complete process.
    KillProcess,
    /// A forbidden relaxed mutant used only by negative tests.
    Allow,
}

/// Worker `umount2` argument policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UmountRuleV1 {
    /// No special argument restriction in the initial materialization phase.
    InitialPhase,
    /// One borrowed immutable target pointer and numeric flags zero.
    ExactTargetAndZeroFlags,
}

/// Immutable provider policy; callers cannot construct or modify one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeccompPolicyV1 {
    role: SeccompRoleV1,
    phase: SeccompPhaseV1,
    allowed: &'static [SeccompSyscallV1],
    default_action: SeccompDefaultActionV1,
    umount_rule: UmountRuleV1,
}

const GENERATOR_ALLOWED_V1: &[SeccompSyscallV1] = &[
    SeccompSyscallV1::Read,
    SeccompSyscallV1::Write,
    SeccompSyscallV1::Close,
    SeccompSyscallV1::Poll,
    SeccompSyscallV1::Lseek,
    SeccompSyscallV1::Mmap,
    SeccompSyscallV1::Mprotect,
    SeccompSyscallV1::Munmap,
    SeccompSyscallV1::Brk,
    SeccompSyscallV1::RtSigaction,
    SeccompSyscallV1::RtSigprocmask,
    SeccompSyscallV1::RtSigreturn,
    SeccompSyscallV1::Pread64,
    SeccompSyscallV1::Pwrite64,
    SeccompSyscallV1::Readv,
    SeccompSyscallV1::Writev,
    SeccompSyscallV1::SchedYield,
    SeccompSyscallV1::Madvise,
    SeccompSyscallV1::Getpid,
    SeccompSyscallV1::Sendmsg,
    SeccompSyscallV1::Recvmsg,
    SeccompSyscallV1::Shutdown,
    SeccompSyscallV1::Exit,
    SeccompSyscallV1::Fsync,
    SeccompSyscallV1::Fdatasync,
    SeccompSyscallV1::Ftruncate,
    SeccompSyscallV1::Futex,
    SeccompSyscallV1::Gettid,
    SeccompSyscallV1::Getdents64,
    SeccompSyscallV1::SetTidAddress,
    SeccompSyscallV1::ClockGettime,
    SeccompSyscallV1::ClockNanosleep,
    SeccompSyscallV1::ExitGroup,
    SeccompSyscallV1::Openat,
    SeccompSyscallV1::Mkdirat,
    SeccompSyscallV1::Fchownat,
    SeccompSyscallV1::Unlinkat,
    SeccompSyscallV1::Linkat,
    SeccompSyscallV1::Fchmodat,
    SeccompSyscallV1::Renameat2,
    SeccompSyscallV1::CopyFileRange,
    SeccompSyscallV1::Statx,
    SeccompSyscallV1::Rseq,
    SeccompSyscallV1::CloseRange,
    SeccompSyscallV1::Openat2,
];

const WORKER_INITIAL_ALLOWED_V1: &[SeccompSyscallV1] = &[
    SeccompSyscallV1::Read,
    SeccompSyscallV1::Write,
    SeccompSyscallV1::Close,
    SeccompSyscallV1::Fstat,
    SeccompSyscallV1::Poll,
    SeccompSyscallV1::Lseek,
    SeccompSyscallV1::Mmap,
    SeccompSyscallV1::Mprotect,
    SeccompSyscallV1::Munmap,
    SeccompSyscallV1::Brk,
    SeccompSyscallV1::RtSigaction,
    SeccompSyscallV1::RtSigprocmask,
    SeccompSyscallV1::RtSigreturn,
    SeccompSyscallV1::Pread64,
    SeccompSyscallV1::Pwrite64,
    SeccompSyscallV1::Readv,
    SeccompSyscallV1::Writev,
    SeccompSyscallV1::SchedYield,
    SeccompSyscallV1::Madvise,
    SeccompSyscallV1::Getpid,
    SeccompSyscallV1::Getppid,
    SeccompSyscallV1::Fstatfs,
    SeccompSyscallV1::Sendmsg,
    SeccompSyscallV1::Recvmsg,
    SeccompSyscallV1::Shutdown,
    SeccompSyscallV1::Exit,
    SeccompSyscallV1::Fsync,
    SeccompSyscallV1::Fdatasync,
    SeccompSyscallV1::Ftruncate,
    SeccompSyscallV1::Fcntl,
    SeccompSyscallV1::Futex,
    SeccompSyscallV1::Gettid,
    SeccompSyscallV1::Getdents64,
    SeccompSyscallV1::SetTidAddress,
    SeccompSyscallV1::SetRobustList,
    SeccompSyscallV1::ClockGettime,
    SeccompSyscallV1::ClockNanosleep,
    SeccompSyscallV1::ExitGroup,
    SeccompSyscallV1::Openat,
    SeccompSyscallV1::Mkdirat,
    SeccompSyscallV1::Fchownat,
    SeccompSyscallV1::Unlinkat,
    SeccompSyscallV1::Linkat,
    SeccompSyscallV1::Fchmodat,
    SeccompSyscallV1::Ppoll,
    SeccompSyscallV1::Mount,
    SeccompSyscallV1::Umount2,
    SeccompSyscallV1::Renameat2,
    SeccompSyscallV1::Prctl,
    SeccompSyscallV1::Seccomp,
    SeccompSyscallV1::Getrandom,
    SeccompSyscallV1::CopyFileRange,
    SeccompSyscallV1::Statx,
    SeccompSyscallV1::Prlimit64,
    SeccompSyscallV1::Rseq,
    SeccompSyscallV1::OpenTree,
    SeccompSyscallV1::MoveMount,
    SeccompSyscallV1::Fsopen,
    SeccompSyscallV1::Fsconfig,
    SeccompSyscallV1::Fsmount,
    SeccompSyscallV1::CloseRange,
    SeccompSyscallV1::Openat2,
];

const WORKER_NO_ACQUIRE_ALLOWED_V1: &[SeccompSyscallV1] = &[
    SeccompSyscallV1::Read,
    SeccompSyscallV1::Write,
    SeccompSyscallV1::Close,
    SeccompSyscallV1::Poll,
    SeccompSyscallV1::Lseek,
    SeccompSyscallV1::Munmap,
    SeccompSyscallV1::RtSigaction,
    SeccompSyscallV1::RtSigprocmask,
    SeccompSyscallV1::RtSigreturn,
    SeccompSyscallV1::Pread64,
    SeccompSyscallV1::Pwrite64,
    SeccompSyscallV1::Readv,
    SeccompSyscallV1::Writev,
    SeccompSyscallV1::SchedYield,
    SeccompSyscallV1::Getpid,
    SeccompSyscallV1::Sendmsg,
    SeccompSyscallV1::Shutdown,
    SeccompSyscallV1::Exit,
    SeccompSyscallV1::Fsync,
    SeccompSyscallV1::Fdatasync,
    SeccompSyscallV1::Futex,
    SeccompSyscallV1::Gettid,
    SeccompSyscallV1::ClockGettime,
    SeccompSyscallV1::ClockNanosleep,
    SeccompSyscallV1::ExitGroup,
    SeccompSyscallV1::Umount2,
];

/// Exact generator process seal metadata.
pub const GENERATOR_INITIAL_POLICY_V1: SeccompPolicyV1 = SeccompPolicyV1 {
    role: SeccompRoleV1::Generator,
    phase: SeccompPhaseV1::Initial,
    allowed: GENERATOR_ALLOWED_V1,
    default_action: SeccompDefaultActionV1::KillProcess,
    umount_rule: UmountRuleV1::InitialPhase,
};
/// Exact worker process seal metadata.
pub const WORKER_INITIAL_POLICY_V1: SeccompPolicyV1 = SeccompPolicyV1 {
    role: SeccompRoleV1::Worker,
    phase: SeccompPhaseV1::Initial,
    allowed: WORKER_INITIAL_ALLOWED_V1,
    default_action: SeccompDefaultActionV1::KillProcess,
    umount_rule: UmountRuleV1::InitialPhase,
};
/// Strict stacked worker cleanup seal metadata.
pub const WORKER_NO_ACQUIRE_POLICY_V1: SeccompPolicyV1 = SeccompPolicyV1 {
    role: SeccompRoleV1::Worker,
    phase: SeccompPhaseV1::NoAcquire,
    allowed: WORKER_NO_ACQUIRE_ALLOWED_V1,
    default_action: SeccompDefaultActionV1::KillProcess,
    umount_rule: UmountRuleV1::ExactTargetAndZeroFlags,
};

/// Process/thread, exec, namespace, tracing, socket, and FD acquisition denials for G.
pub const REQUIRED_GENERATOR_DENIALS_V1: [SeccompSyscallV1; 20] = [
    SeccompSyscallV1::Clone,
    SeccompSyscallV1::Clone3,
    SeccompSyscallV1::Fork,
    SeccompSyscallV1::Vfork,
    SeccompSyscallV1::Execve,
    SeccompSyscallV1::Execveat,
    SeccompSyscallV1::Unshare,
    SeccompSyscallV1::Setns,
    SeccompSyscallV1::Ptrace,
    SeccompSyscallV1::ProcessVmReadv,
    SeccompSyscallV1::ProcessVmWritev,
    SeccompSyscallV1::PidfdGetfd,
    SeccompSyscallV1::Socket,
    SeccompSyscallV1::Socketpair,
    SeccompSyscallV1::Accept,
    SeccompSyscallV1::Accept4,
    SeccompSyscallV1::Dup,
    SeccompSyscallV1::Dup2,
    SeccompSyscallV1::Dup3,
    SeccompSyscallV1::Fcntl,
];
/// Process/thread, exec, namespace, tracing, and unexpected channel denials for W.
pub const REQUIRED_WORKER_INITIAL_DENIALS_V1: [SeccompSyscallV1; 16] = [
    SeccompSyscallV1::Clone,
    SeccompSyscallV1::Clone3,
    SeccompSyscallV1::Fork,
    SeccompSyscallV1::Vfork,
    SeccompSyscallV1::Execve,
    SeccompSyscallV1::Execveat,
    SeccompSyscallV1::Unshare,
    SeccompSyscallV1::Setns,
    SeccompSyscallV1::Ptrace,
    SeccompSyscallV1::ProcessVmReadv,
    SeccompSyscallV1::ProcessVmWritev,
    SeccompSyscallV1::PidfdGetfd,
    SeccompSyscallV1::Socket,
    SeccompSyscallV1::Socketpair,
    SeccompSyscallV1::Accept,
    SeccompSyscallV1::Accept4,
];
/// Additional acquisitions and mount mutations removed by the stacked W seal.
pub const REQUIRED_WORKER_NO_ACQUIRE_DENIALS_V1: [SeccompSyscallV1; 18] = [
    SeccompSyscallV1::Open,
    SeccompSyscallV1::Openat,
    SeccompSyscallV1::Openat2,
    SeccompSyscallV1::Mmap,
    SeccompSyscallV1::Mprotect,
    SeccompSyscallV1::Mremap,
    SeccompSyscallV1::Brk,
    SeccompSyscallV1::Dup,
    SeccompSyscallV1::Dup2,
    SeccompSyscallV1::Dup3,
    SeccompSyscallV1::Fcntl,
    SeccompSyscallV1::Recvmsg,
    SeccompSyscallV1::Mount,
    SeccompSyscallV1::OpenTree,
    SeccompSyscallV1::MoveMount,
    SeccompSyscallV1::Fsopen,
    SeccompSyscallV1::Fsconfig,
    SeccompSyscallV1::Fsmount,
];

/// Seccomp installation or policy rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeccompContractErrorV1 {
    /// A forbidden syscall was added to an exact policy.
    RelaxedPolicy,
    /// A required syscall was removed from an exact policy.
    MissingRequiredSyscall,
    /// The default kill action was relaxed.
    RelaxedDefaultAction,
    /// The initial/no-acquire stack order drifted.
    PhaseOrder,
    /// Seccomp install flags were not exactly zero.
    InstallFlags,
    /// The immutable ordinary-unmount target was empty, relative, or overlong.
    InvalidUmountTarget,
    /// The supplied descriptor was not a usable procfs root.
    ProcfsRoot,
    /// The live process was not single-threaded in both exact snapshots.
    ThreadMultiplicity,
    /// The installing or unmounting thread differed from the sealed leader TID.
    ThreadIdentity,
    /// The signal-mask bracket could not be installed or restored exactly.
    SignalMask,
    /// A selected-target kernel operation failed with this errno.
    Kernel(i32),
    /// The pinned filter exceeded its fixed stack allocation.
    FilterBounds,
    /// A successful safe prerequisite returned an impossible state.
    KernelInvariant,
}

impl fmt::Display for SeccompContractErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "H0 seccomp contract rejected: {self:?}")
    }
}

impl std::error::Error for SeccompContractErrorV1 {}

/// The only accepted `seccomp(SECCOMP_SET_MODE_FILTER, flags, ...)` flags.
pub const SECCOMP_INSTALL_FLAGS_V1: u32 = 0;

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
fn validate_single_thread_snapshots(
    process_id: i32,
    thread_id: i32,
    first: &[i32],
    second: &[i32],
) -> Result<(), SeccompContractErrorV1> {
    if process_id <= 0 || thread_id != process_id {
        return Err(SeccompContractErrorV1::ThreadIdentity);
    }
    if first != [thread_id] || second != [thread_id] {
        return Err(SeccompContractErrorV1::ThreadMultiplicity);
    }
    Ok(())
}

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
fn ensure_current_tid(expected: i32, current: i32) -> Result<(), SeccompContractErrorV1> {
    if expected == current {
        Ok(())
    } else {
        Err(SeccompContractErrorV1::ThreadIdentity)
    }
}

#[cfg(test)]
#[derive(Clone, Debug)]
struct TestPolicyV1 {
    role: SeccompRoleV1,
    phase: SeccompPhaseV1,
    allowed: Vec<SeccompSyscallV1>,
    default_action: SeccompDefaultActionV1,
    umount_rule: UmountRuleV1,
}

#[cfg(test)]
fn policy_with_extra_allow_for_test(
    policy: SeccompPolicyV1,
    syscall: SeccompSyscallV1,
) -> TestPolicyV1 {
    let mut allowed = policy.allowed.to_vec();
    if !allowed.contains(&syscall) {
        allowed.push(syscall);
    }
    TestPolicyV1 {
        role: policy.role,
        phase: policy.phase,
        allowed,
        default_action: policy.default_action,
        umount_rule: policy.umount_rule,
    }
}

#[cfg(test)]
fn policy_with_removed_allow_for_test(
    policy: SeccompPolicyV1,
    syscall: SeccompSyscallV1,
) -> TestPolicyV1 {
    TestPolicyV1 {
        role: policy.role,
        phase: policy.phase,
        allowed: policy
            .allowed
            .iter()
            .copied()
            .filter(|candidate| *candidate != syscall)
            .collect(),
        default_action: policy.default_action,
        umount_rule: policy.umount_rule,
    }
}

#[cfg(test)]
fn policy_with_default_action_for_test(
    policy: SeccompPolicyV1,
    default_action: SeccompDefaultActionV1,
) -> TestPolicyV1 {
    TestPolicyV1 {
        role: policy.role,
        phase: policy.phase,
        allowed: policy.allowed.to_vec(),
        default_action,
        umount_rule: policy.umount_rule,
    }
}

#[cfg(test)]
fn validate_policy_for_test(policy: &TestPolicyV1) -> Result<(), SeccompContractErrorV1> {
    if policy.default_action != SeccompDefaultActionV1::KillProcess {
        return Err(SeccompContractErrorV1::RelaxedDefaultAction);
    }
    let exact = match (policy.role, policy.phase) {
        (SeccompRoleV1::Generator, SeccompPhaseV1::Initial) => GENERATOR_INITIAL_POLICY_V1,
        (SeccompRoleV1::Worker, SeccompPhaseV1::Initial) => WORKER_INITIAL_POLICY_V1,
        (SeccompRoleV1::Worker, SeccompPhaseV1::NoAcquire) => WORKER_NO_ACQUIRE_POLICY_V1,
        (SeccompRoleV1::Generator, SeccompPhaseV1::NoAcquire) => {
            return Err(SeccompContractErrorV1::PhaseOrder);
        }
    };
    if policy
        .allowed
        .iter()
        .any(|syscall| !exact.allowed.contains(syscall))
        || policy.umount_rule != exact.umount_rule
    {
        return Err(SeccompContractErrorV1::RelaxedPolicy);
    }
    if exact
        .allowed
        .iter()
        .any(|syscall| !policy.allowed.contains(syscall))
    {
        return Err(SeccompContractErrorV1::MissingRequiredSyscall);
    }
    Ok(())
}

#[cfg(test)]
fn is_strict_subset_for_test(subset: &[SeccompSyscallV1], superset: &[SeccompSyscallV1]) -> bool {
    subset.len() < superset.len() && subset.iter().all(|item| superset.contains(item))
}

#[cfg(test)]
fn validate_install_sequence_for_test(
    phases: &[SeccompPhaseV1],
) -> Result<(), SeccompContractErrorV1> {
    if phases == [SeccompPhaseV1::Initial, SeccompPhaseV1::NoAcquire] {
        Ok(())
    } else {
        Err(SeccompContractErrorV1::PhaseOrder)
    }
}

#[cfg(test)]
const fn validate_install_flags_for_test(flags: u32) -> Result<(), SeccompContractErrorV1> {
    if flags == SECCOMP_INSTALL_FLAGS_V1 {
        Ok(())
    } else {
        Err(SeccompContractErrorV1::InstallFlags)
    }
}

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
mod filter_model {
    use super::*;
    use core::ffi::CStr;

    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_DATA_NR_OFFSET: u32 = 0;
    const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
    const SECCOMP_DATA_ARG0_LOW_OFFSET: u32 = 16;
    const SECCOMP_DATA_ARG0_HIGH_OFFSET: u32 = 20;
    const SECCOMP_DATA_ARG1_LOW_OFFSET: u32 = 24;
    const SECCOMP_DATA_ARG1_HIGH_OFFSET: u32 = 28;
    const MAX_FILTER_INSTRUCTIONS: usize = 160;

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub(super) struct SockFilterV1 {
        pub(super) code: u16,
        pub(super) jt: u8,
        pub(super) jf: u8,
        pub(super) k: u32,
    }

    const _: [(); 8] = [(); core::mem::size_of::<SockFilterV1>()];
    const _: [(); 4] = [(); core::mem::align_of::<SockFilterV1>()];
    const _: [(); 0] = [(); core::mem::offset_of!(SockFilterV1, code)];
    const _: [(); 2] = [(); core::mem::offset_of!(SockFilterV1, jt)];
    const _: [(); 3] = [(); core::mem::offset_of!(SockFilterV1, jf)];
    const _: [(); 4] = [(); core::mem::offset_of!(SockFilterV1, k)];

    const EMPTY_FILTER: SockFilterV1 = SockFilterV1 {
        code: 0,
        jt: 0,
        jf: 0,
        k: 0,
    };

    #[repr(C)]
    pub(super) struct SockFprogV1 {
        pub(super) len: u16,
        pub(super) filter: *const SockFilterV1,
    }

    #[cfg(target_pointer_width = "64")]
    const _: [(); 16] = [(); core::mem::size_of::<SockFprogV1>()];
    #[cfg(target_pointer_width = "64")]
    const _: [(); 8] = [(); core::mem::align_of::<SockFprogV1>()];
    const _: [(); 0] = [(); core::mem::offset_of!(SockFprogV1, len)];
    #[cfg(target_pointer_width = "64")]
    const _: [(); 8] = [(); core::mem::offset_of!(SockFprogV1, filter)];

    pub(super) struct FilterProgramV1 {
        pub(super) instructions: [SockFilterV1; MAX_FILTER_INSTRUCTIONS],
        pub(super) len: usize,
    }

    impl FilterProgramV1 {
        const fn new() -> Self {
            Self {
                instructions: [EMPTY_FILTER; MAX_FILTER_INSTRUCTIONS],
                len: 0,
            }
        }

        fn push(&mut self, instruction: SockFilterV1) -> Result<(), SeccompContractErrorV1> {
            let slot = self
                .instructions
                .get_mut(self.len)
                .ok_or(SeccompContractErrorV1::FilterBounds)?;
            *slot = instruction;
            self.len += 1;
            Ok(())
        }
    }

    const fn statement(code: u16, value: u32) -> SockFilterV1 {
        SockFilterV1 {
            code,
            jt: 0,
            jf: 0,
            k: value,
        }
    }

    const fn jump(value: u32, true_skip: u8, false_skip: u8) -> SockFilterV1 {
        SockFilterV1 {
            code: BPF_JMP_JEQ_K,
            jt: true_skip,
            jf: false_skip,
            k: value,
        }
    }

    pub(super) fn build_filter(
        policy: SeccompPolicyV1,
        exact_umount_target: Option<&CStr>,
    ) -> Result<FilterProgramV1, SeccompContractErrorV1> {
        let mut program = FilterProgramV1::new();
        program.push(statement(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET))?;
        program.push(jump(AUDIT_ARCH_X86_64, 1, 0))?;
        program.push(statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS))?;
        program.push(statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET))?;
        for syscall in policy.allowed {
            if exact_umount_target.is_some() && *syscall == SeccompSyscallV1::Umount2 {
                continue;
            }
            let number = *syscall as u32;
            program.push(jump(number, 0, 1))?;
            program.push(statement(BPF_RET_K, SECCOMP_RET_ALLOW))?;
        }
        if let Some(target) = exact_umount_target {
            let pointer = u64::try_from(target.as_ptr().addr())
                .map_err(|_| SeccompContractErrorV1::FilterBounds)?;
            let low = u32::try_from(pointer & u64::from(u32::MAX))
                .map_err(|_| SeccompContractErrorV1::FilterBounds)?;
            let high =
                u32::try_from(pointer >> 32).map_err(|_| SeccompContractErrorV1::FilterBounds)?;
            program.push(jump(SeccompSyscallV1::Umount2 as u32, 0, 9))?;
            program.push(statement(BPF_LD_W_ABS, SECCOMP_DATA_ARG0_LOW_OFFSET))?;
            program.push(jump(low, 0, 7))?;
            program.push(statement(BPF_LD_W_ABS, SECCOMP_DATA_ARG0_HIGH_OFFSET))?;
            program.push(jump(high, 0, 5))?;
            program.push(statement(BPF_LD_W_ABS, SECCOMP_DATA_ARG1_LOW_OFFSET))?;
            program.push(jump(0, 0, 3))?;
            program.push(statement(BPF_LD_W_ABS, SECCOMP_DATA_ARG1_HIGH_OFFSET))?;
            program.push(jump(0, 0, 1))?;
            program.push(statement(BPF_RET_K, SECCOMP_RET_ALLOW))?;
        }
        program.push(statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS))?;
        Ok(program)
    }

    #[cfg(test)]
    #[derive(Clone, Copy)]
    struct SeccompDataForTestV1 {
        syscall: u32,
        architecture: u32,
        argument_0: u64,
        argument_1: u64,
    }

    #[cfg(test)]
    fn interpret_filter_for_test(
        program: &FilterProgramV1,
        data: SeccompDataForTestV1,
    ) -> Result<u32, SeccompContractErrorV1> {
        let mut accumulator = 0_u32;
        let mut program_counter = 0_usize;
        loop {
            let instruction = program
                .instructions
                .get(program_counter)
                .filter(|_| program_counter < program.len)
                .ok_or(SeccompContractErrorV1::FilterBounds)?;
            match instruction.code {
                BPF_LD_W_ABS => {
                    accumulator = match instruction.k {
                        SECCOMP_DATA_NR_OFFSET => data.syscall,
                        SECCOMP_DATA_ARCH_OFFSET => data.architecture,
                        SECCOMP_DATA_ARG0_LOW_OFFSET => {
                            u32::try_from(data.argument_0 & u64::from(u32::MAX))
                                .map_err(|_| SeccompContractErrorV1::KernelInvariant)?
                        }
                        SECCOMP_DATA_ARG0_HIGH_OFFSET => u32::try_from(data.argument_0 >> 32)
                            .map_err(|_| SeccompContractErrorV1::KernelInvariant)?,
                        SECCOMP_DATA_ARG1_LOW_OFFSET => {
                            u32::try_from(data.argument_1 & u64::from(u32::MAX))
                                .map_err(|_| SeccompContractErrorV1::KernelInvariant)?
                        }
                        SECCOMP_DATA_ARG1_HIGH_OFFSET => u32::try_from(data.argument_1 >> 32)
                            .map_err(|_| SeccompContractErrorV1::KernelInvariant)?,
                        _ => return Err(SeccompContractErrorV1::KernelInvariant),
                    };
                    program_counter = program_counter
                        .checked_add(1)
                        .ok_or(SeccompContractErrorV1::FilterBounds)?;
                }
                BPF_JMP_JEQ_K => {
                    let skip = if accumulator == instruction.k {
                        instruction.jt
                    } else {
                        instruction.jf
                    };
                    program_counter = program_counter
                        .checked_add(1)
                        .and_then(|value| value.checked_add(usize::from(skip)))
                        .ok_or(SeccompContractErrorV1::FilterBounds)?;
                }
                BPF_RET_K => return Ok(instruction.k),
                _ => return Err(SeccompContractErrorV1::KernelInvariant),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn bpf_builder_emits_exact_arch_allow_and_terminal_kill_shape() {
            let program = build_filter(GENERATOR_INITIAL_POLICY_V1, None).unwrap();
            assert_eq!(program.len, 5 + 2 * GENERATOR_ALLOWED_V1.len());
            assert_eq!(program.instructions[0].code, BPF_LD_W_ABS);
            assert_eq!(program.instructions[0].k, SECCOMP_DATA_ARCH_OFFSET);
            assert_eq!(program.instructions[1].code, BPF_JMP_JEQ_K);
            assert_eq!(program.instructions[1].k, AUDIT_ARCH_X86_64);
            assert_eq!(program.instructions[2].k, SECCOMP_RET_KILL_PROCESS);
            assert_eq!(program.instructions[3].k, SECCOMP_DATA_NR_OFFSET);
            assert_eq!(
                program.instructions[program.len - 1].k,
                SECCOMP_RET_KILL_PROCESS
            );
            for (index, syscall) in GENERATOR_ALLOWED_V1.iter().enumerate() {
                assert_eq!(program.instructions[4 + index * 2].k, *syscall as u32);
                assert_eq!(program.instructions[5 + index * 2].k, SECCOMP_RET_ALLOW);
            }
        }

        #[test]
        fn bpf_builder_gates_umount_by_exact_pointer_and_zero_flags() {
            let program = build_filter(WORKER_NO_ACQUIRE_POLICY_V1, Some(c"/worker-root")).unwrap();
            assert_eq!(
                program.len,
                15 + 2 * (WORKER_NO_ACQUIRE_ALLOWED_V1.len() - 1)
            );
            assert_eq!(
                program.instructions[program.len - 1].k,
                SECCOMP_RET_KILL_PROCESS
            );
            assert_eq!(
                program.instructions[program.len - 11].k,
                SeccompSyscallV1::Umount2 as u32
            );
            assert_eq!(program.instructions[program.len - 2].k, SECCOMP_RET_ALLOW);
        }

        fn umount_data(target: &CStr, pointer: u64, flags: u64) -> SeccompDataForTestV1 {
            let _ = target;
            SeccompDataForTestV1 {
                syscall: SeccompSyscallV1::Umount2 as u32,
                architecture: AUDIT_ARCH_X86_64,
                argument_0: pointer,
                argument_1: flags,
            }
        }

        #[test]
        fn bpf_interpreter_executes_arch_and_syscall_jumps() {
            let program = build_filter(GENERATOR_INITIAL_POLICY_V1, None).unwrap();
            let allowed = SeccompDataForTestV1 {
                syscall: SeccompSyscallV1::Read as u32,
                architecture: AUDIT_ARCH_X86_64,
                argument_0: 0,
                argument_1: 0,
            };
            assert_eq!(
                interpret_filter_for_test(&program, allowed).unwrap(),
                SECCOMP_RET_ALLOW
            );
            assert_eq!(
                interpret_filter_for_test(
                    &program,
                    SeccompDataForTestV1 {
                        syscall: SeccompSyscallV1::Clone3 as u32,
                        ..allowed
                    },
                )
                .unwrap(),
                SECCOMP_RET_KILL_PROCESS
            );
            assert_eq!(
                interpret_filter_for_test(
                    &program,
                    SeccompDataForTestV1 {
                        architecture: 0,
                        ..allowed
                    },
                )
                .unwrap(),
                SECCOMP_RET_KILL_PROCESS
            );
        }

        #[test]
        fn bpf_interpreter_rejects_wrong_pointer_low() {
            let target = c"/worker-root";
            let pointer = target.as_ptr().addr() as u64;
            let program = build_filter(WORKER_NO_ACQUIRE_POLICY_V1, Some(target)).unwrap();
            let wrong_pointer_low = pointer ^ 1;
            assert_eq!(
                interpret_filter_for_test(&program, umount_data(target, wrong_pointer_low, 0))
                    .unwrap(),
                SECCOMP_RET_KILL_PROCESS
            );
        }

        #[test]
        fn bpf_interpreter_rejects_wrong_pointer_high() {
            let target = c"/worker-root";
            let pointer = target.as_ptr().addr() as u64;
            let program = build_filter(WORKER_NO_ACQUIRE_POLICY_V1, Some(target)).unwrap();
            let wrong_pointer_high = pointer ^ (1_u64 << 32);
            assert_eq!(
                interpret_filter_for_test(&program, umount_data(target, wrong_pointer_high, 0))
                    .unwrap(),
                SECCOMP_RET_KILL_PROCESS
            );
        }

        #[test]
        fn bpf_interpreter_rejects_wrong_flags_low() {
            let target = c"/worker-root";
            let pointer = target.as_ptr().addr() as u64;
            let program = build_filter(WORKER_NO_ACQUIRE_POLICY_V1, Some(target)).unwrap();
            let wrong_flags_low = 1_u64;
            assert_eq!(
                interpret_filter_for_test(&program, umount_data(target, pointer, wrong_flags_low),)
                    .unwrap(),
                SECCOMP_RET_KILL_PROCESS
            );
        }

        #[test]
        fn bpf_interpreter_rejects_wrong_flags_high() {
            let target = c"/worker-root";
            let pointer = target.as_ptr().addr() as u64;
            let program = build_filter(WORKER_NO_ACQUIRE_POLICY_V1, Some(target)).unwrap();
            let wrong_flags_high = 1_u64 << 32;
            assert_eq!(
                interpret_filter_for_test(
                    &program,
                    umount_data(target, pointer, wrong_flags_high),
                )
                .unwrap(),
                SECCOMP_RET_KILL_PROCESS
            );
        }

        #[test]
        fn bpf_interpreter_detects_offset_and_jump_mutants() {
            let target = c"/worker-root";
            let pointer = target.as_ptr().addr() as u64;
            let mut wrong_offset = build_filter(WORKER_NO_ACQUIRE_POLICY_V1, Some(target)).unwrap();
            let gate = wrong_offset.len - 11;
            wrong_offset.instructions[gate + 1].k = SECCOMP_DATA_ARG1_LOW_OFFSET;
            assert_eq!(
                interpret_filter_for_test(&wrong_offset, umount_data(target, pointer, 0)).unwrap(),
                SECCOMP_RET_KILL_PROCESS
            );

            let mut relaxed_jump = build_filter(WORKER_NO_ACQUIRE_POLICY_V1, Some(target)).unwrap();
            relaxed_jump.instructions[gate + 2].jf = 0;
            assert_eq!(
                interpret_filter_for_test(&relaxed_jump, umount_data(target, pointer ^ 1, 0))
                    .unwrap(),
                SECCOMP_RET_ALLOW
            );
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
mod selected_target {
    use super::filter_model::{SockFprogV1, build_filter};
    use super::*;
    use crate::process::{
        ProcessContractErrorV1, ProcfsAuthorityV1, validate_procfs_thread_snapshots,
    };
    use core::ffi::{CStr, c_long, c_void};
    use core::marker::PhantomData;
    use std::rc::Rc;

    const SYS_SECCOMP: c_long = 317;
    const SYS_RT_SIGPROCMASK: c_long = 14;
    const SECCOMP_SET_MODE_FILTER: c_long = 1;
    const SIG_SETMASK: c_long = 2;
    const SIGKILL: c_long = 9;
    const SIGSTOP: c_long = 19;
    const BLOCKED_CATCHABLE_SIGNALS_V1: u64 =
        u64::MAX & !(1_u64 << (SIGKILL - 1)) & !(1_u64 << (SIGSTOP - 1));

    unsafe extern "C" {
        fn syscall(number: c_long, ...) -> c_long;
    }

    fn kernel_error(error: rustix::io::Errno) -> SeccompContractErrorV1 {
        SeccompContractErrorV1::Kernel(error.raw_os_error())
    }

    fn process_error(error: ProcessContractErrorV1) -> SeccompContractErrorV1 {
        match error {
            ProcessContractErrorV1::ProcfsRoot
            | ProcessContractErrorV1::ProcfsIdentity
            | ProcessContractErrorV1::DescriptorNotCloseOnExec => {
                SeccompContractErrorV1::ProcfsRoot
            }
            ProcessContractErrorV1::ThreadMultiplicity => {
                SeccompContractErrorV1::ThreadMultiplicity
            }
            ProcessContractErrorV1::ThreadIdentity => SeccompContractErrorV1::ThreadIdentity,
            ProcessContractErrorV1::SignalMask => SeccompContractErrorV1::SignalMask,
            ProcessContractErrorV1::Kernel(errno) => SeccompContractErrorV1::Kernel(errno),
            _ => SeccompContractErrorV1::KernelInvariant,
        }
    }

    fn replace_signal_mask(
        new_mask: &u64,
        old_mask: Option<&mut u64>,
    ) -> Result<(), SeccompContractErrorV1> {
        let old_pointer = old_mask.map_or(core::ptr::null_mut(), |mask| mask as *mut u64);
        // SAFETY: x86-64 Linux has an eight-byte kernel signal set. Both
        // pointers, when non-null, refer to live aligned `u64` values.
        let result = unsafe {
            syscall(
                SYS_RT_SIGPROCMASK,
                SIG_SETMASK,
                new_mask as *const u64,
                old_pointer,
                core::mem::size_of::<u64>(),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(SeccompContractErrorV1::SignalMask)
        }
    }

    fn query_signal_mask() -> Result<u64, SeccompContractErrorV1> {
        let mut current = 0_u64;
        // SAFETY: the output is one aligned eight-byte kernel signal set and
        // the null input requests observation without mutation.
        let result = unsafe {
            syscall(
                SYS_RT_SIGPROCMASK,
                SIG_SETMASK,
                core::ptr::null::<u64>(),
                &raw mut current,
                core::mem::size_of::<u64>(),
            )
        };
        if result == 0 {
            Ok(current)
        } else {
            Err(SeccompContractErrorV1::SignalMask)
        }
    }

    struct SignalMaskGuardV1 {
        previous: u64,
        active: bool,
    }

    impl SignalMaskGuardV1 {
        fn block_all() -> Result<Self, SeccompContractErrorV1> {
            let mut previous = 0_u64;
            replace_signal_mask(&u64::MAX, Some(&mut previous))?;
            if query_signal_mask() != Ok(BLOCKED_CATCHABLE_SIGNALS_V1) {
                let _ = replace_signal_mask(&previous, None);
                return Err(SeccompContractErrorV1::SignalMask);
            }
            Ok(Self {
                previous,
                active: true,
            })
        }

        fn restore(mut self) -> Result<(), SeccompContractErrorV1> {
            replace_signal_mask(&self.previous, None)?;
            if query_signal_mask()? != self.previous {
                return Err(SeccompContractErrorV1::SignalMask);
            }
            self.active = false;
            Ok(())
        }
    }

    impl Drop for SignalMaskGuardV1 {
        fn drop(&mut self) {
            if self.active {
                if replace_signal_mask(&self.previous, None).is_ok()
                    && query_signal_mask() == Ok(self.previous)
                {
                    self.active = false;
                }
            }
        }
    }

    fn install_filter_on_single_thread(
        authority: &ProcfsAuthorityV1,
        policy: SeccompPolicyV1,
        exact_umount_target: Option<&CStr>,
    ) -> Result<i32, SeccompContractErrorV1> {
        // With every catchable signal blocked, a first snapshot containing
        // only this caller proves there is no peer thread able to create a new
        // thread before the flags-zero filter denies clone and clone3.
        let signal_mask = SignalMaskGuardV1::block_all()?;
        let operation = (|| {
            let first = authority
                .snapshot_current_threads()
                .map_err(process_error)?;
            let second = authority
                .snapshot_current_threads()
                .map_err(process_error)?;
            let thread_id =
                validate_procfs_thread_snapshots(&first, &second).map_err(process_error)?;
            install_filter(policy, exact_umount_target)?;
            ensure_current_tid(thread_id, rustix::thread::gettid().as_raw_pid())?;
            Ok(thread_id)
        })();
        match signal_mask.restore() {
            Ok(()) => operation,
            Err(restore_error) => Err(restore_error),
        }
    }

    fn install_filter(
        policy: SeccompPolicyV1,
        exact_umount_target: Option<&CStr>,
    ) -> Result<(), SeccompContractErrorV1> {
        rustix::thread::set_no_new_privs(true).map_err(kernel_error)?;
        if !rustix::thread::no_new_privs().map_err(kernel_error)? {
            return Err(SeccompContractErrorV1::KernelInvariant);
        }
        let program = build_filter(policy, exact_umount_target)?;
        let descriptor = SockFprogV1 {
            len: u16::try_from(program.len).map_err(|_| SeccompContractErrorV1::FilterBounds)?,
            filter: program.instructions.as_ptr(),
        };
        // SAFETY: the BPF array and descriptor remain live for the call; the
        // operation and flags are constants and the program is locally built.
        let result = unsafe {
            syscall(
                SYS_SECCOMP,
                SECCOMP_SET_MODE_FILTER,
                SECCOMP_INSTALL_FLAGS_V1,
                (&raw const descriptor).cast::<c_void>(),
            )
        };
        if result != 0 {
            return Err(SeccompContractErrorV1::Kernel(
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            ));
        }
        Ok(())
    }

    /// Installed generator process seal; affine, opaque, and thread-bound.
    pub struct GeneratorSeccompSealV1 {
        _tid: i32,
        _thread_bound: PhantomData<Rc<()>>,
    }
    /// Installed worker process seal; consumed on its installing thread only.
    pub struct WorkerInitialSeccompSealV1 {
        tid: i32,
        _thread_bound: PhantomData<Rc<()>>,
    }
    /// Stacked cleanup seal retaining the exact target bytes and installer TID.
    pub struct WorkerNoAcquireSeccompSealV1<'a> {
        target: &'a CStr,
        target_bytes: &'a [u8],
        tid: i32,
        _thread_bound: PhantomData<Rc<()>>,
    }

    /// Installs the sole provider-owned generator filter with flags zero.
    ///
    /// # Errors
    ///
    /// Returns an exact build, prerequisite, or kernel installation error.
    pub fn install_generator_initial_seccomp_v1(
        authority: &ProcfsAuthorityV1,
    ) -> Result<GeneratorSeccompSealV1, SeccompContractErrorV1> {
        let tid = install_filter_on_single_thread(authority, GENERATOR_INITIAL_POLICY_V1, None)?;
        Ok(GeneratorSeccompSealV1 {
            _tid: tid,
            _thread_bound: PhantomData,
        })
    }

    /// Installs the sole provider-owned worker process filter with flags zero.
    ///
    /// # Errors
    ///
    /// Returns an exact build, prerequisite, or kernel installation error.
    pub fn install_worker_initial_seccomp_v1(
        authority: &ProcfsAuthorityV1,
    ) -> Result<WorkerInitialSeccompSealV1, SeccompContractErrorV1> {
        let tid = install_filter_on_single_thread(authority, WORKER_INITIAL_POLICY_V1, None)?;
        Ok(WorkerInitialSeccompSealV1 {
            tid,
            _thread_bound: PhantomData,
        })
    }

    /// Stacks the strict no-acquire filter over an installed worker filter.
    ///
    /// # Errors
    ///
    /// Rejects the target or returns an exact build/prerequisite/kernel error.
    pub fn install_worker_no_acquire_seccomp_v1<'a>(
        initial: WorkerInitialSeccompSealV1,
        authority: &ProcfsAuthorityV1,
        exact_umount_target: &'a CStr,
    ) -> Result<WorkerNoAcquireSeccompSealV1<'a>, SeccompContractErrorV1> {
        let bytes = exact_umount_target.to_bytes();
        if bytes.is_empty() || bytes[0] != b'/' || bytes.len() > 4096 {
            return Err(SeccompContractErrorV1::InvalidUmountTarget);
        }
        ensure_current_tid(initial.tid, rustix::thread::gettid().as_raw_pid())?;
        let tid = install_filter_on_single_thread(
            authority,
            WORKER_NO_ACQUIRE_POLICY_V1,
            Some(exact_umount_target),
        )?;
        ensure_current_tid(initial.tid, tid)?;
        Ok(WorkerNoAcquireSeccompSealV1 {
            target: exact_umount_target,
            target_bytes: bytes,
            tid,
            _thread_bound: PhantomData,
        })
    }

    impl WorkerNoAcquireSeccompSealV1<'_> {
        /// Consumes the wrapper to call `umount2` once with the borrowed target
        /// pointer and numeric flags zero.
        ///
        /// The filter checks only those syscall arguments. It does not prove
        /// mount identity or state; immutable target bytes are a measured-code
        /// invariant retained by this borrow until the consumed call.
        ///
        /// # Errors
        ///
        /// Returns the exact kernel unmount errno.
        pub fn unmount_exact_once(self) -> Result<(), SeccompContractErrorV1> {
            ensure_current_tid(self.tid, rustix::thread::gettid().as_raw_pid())?;
            if self.target.to_bytes() != self.target_bytes {
                return Err(SeccompContractErrorV1::KernelInvariant);
            }
            rustix::mount::unmount(self.target, rustix::mount::UnmountFlags::empty())
                .map_err(kernel_error)
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
pub use selected_target::{
    GeneratorSeccompSealV1, WorkerInitialSeccompSealV1, WorkerNoAcquireSeccompSealV1,
    install_generator_initial_seccomp_v1, install_worker_initial_seccomp_v1,
    install_worker_no_acquire_seccomp_v1,
};

#[cfg(test)]
mod monotone_seccomp {
    use super::*;

    #[test]
    fn generator_and_worker_profiles_are_closed_and_role_specific() {
        assert_ne!(GENERATOR_INITIAL_POLICY_V1, WORKER_INITIAL_POLICY_V1);
        assert_eq!(GENERATOR_INITIAL_POLICY_V1.role, SeccompRoleV1::Generator);
        assert_eq!(WORKER_INITIAL_POLICY_V1.role, SeccompRoleV1::Worker);
        assert_eq!(WORKER_NO_ACQUIRE_POLICY_V1.role, SeccompRoleV1::Worker);
        assert_eq!(WORKER_NO_ACQUIRE_POLICY_V1.phase, SeccompPhaseV1::NoAcquire);
    }

    #[test]
    fn worker_initial_profile_allows_exact_bootstrap_observation_syscalls_v1() {
        for (syscall, number, name) in [
            (SeccompSyscallV1::Fstat, 5, "fstat"),
            (SeccompSyscallV1::Fcntl, 72, "fcntl"),
            (SeccompSyscallV1::Getppid, 110, "getppid"),
            (SeccompSyscallV1::Fstatfs, 138, "fstatfs"),
            (SeccompSyscallV1::Ppoll, 271, "ppoll"),
            (SeccompSyscallV1::Prlimit64, 302, "prlimit64"),
        ] {
            assert_eq!(syscall as u32, number, "wrong x86_64 number for {name}");
            assert!(
                WORKER_INITIAL_ALLOWED_V1.contains(&syscall),
                "Worker initial seccomp omitted {name}={number}"
            );
            assert!(
                !GENERATOR_ALLOWED_V1.contains(&syscall),
                "generator seccomp unexpectedly gained Worker-only {name}={number}"
            );
            assert!(
                !WORKER_NO_ACQUIRE_ALLOWED_V1.contains(&syscall),
                "Worker no-acquire seccomp retained bootstrap-only {name}={number}"
            );
        }
        assert!(!WORKER_NO_ACQUIRE_ALLOWED_V1.contains(&SeccompSyscallV1::Recvmsg));
    }

    #[test]
    fn every_required_denial_is_independently_checked() {
        for syscall in REQUIRED_GENERATOR_DENIALS_V1 {
            let relaxed = policy_with_extra_allow_for_test(GENERATOR_INITIAL_POLICY_V1, syscall);
            assert_eq!(
                validate_policy_for_test(&relaxed),
                Err(SeccompContractErrorV1::RelaxedPolicy)
            );
        }
        for syscall in REQUIRED_WORKER_INITIAL_DENIALS_V1 {
            let relaxed = policy_with_extra_allow_for_test(WORKER_INITIAL_POLICY_V1, syscall);
            assert_eq!(
                validate_policy_for_test(&relaxed),
                Err(SeccompContractErrorV1::RelaxedPolicy)
            );
        }
        for syscall in REQUIRED_WORKER_NO_ACQUIRE_DENIALS_V1 {
            let relaxed = policy_with_extra_allow_for_test(WORKER_NO_ACQUIRE_POLICY_V1, syscall);
            assert_eq!(
                validate_policy_for_test(&relaxed),
                Err(SeccompContractErrorV1::RelaxedPolicy)
            );
        }
    }

    #[test]
    fn removed_required_syscall_and_changed_default_action_reject() {
        let missing = policy_with_removed_allow_for_test(
            WORKER_NO_ACQUIRE_POLICY_V1,
            SeccompSyscallV1::Umount2,
        );
        assert_eq!(
            validate_policy_for_test(&missing),
            Err(SeccompContractErrorV1::MissingRequiredSyscall)
        );
        let relaxed_default = policy_with_default_action_for_test(
            WORKER_NO_ACQUIRE_POLICY_V1,
            SeccompDefaultActionV1::Allow,
        );
        assert_eq!(
            validate_policy_for_test(&relaxed_default),
            Err(SeccompContractErrorV1::RelaxedDefaultAction)
        );
    }

    #[test]
    fn no_acquire_is_a_strict_monotone_reduction() {
        assert!(is_strict_subset_for_test(
            WORKER_NO_ACQUIRE_POLICY_V1.allowed,
            WORKER_INITIAL_POLICY_V1.allowed,
        ));
        for forbidden in REQUIRED_WORKER_NO_ACQUIRE_DENIALS_V1 {
            assert!(!WORKER_NO_ACQUIRE_POLICY_V1.allowed.contains(&forbidden));
        }
        assert_eq!(
            WORKER_NO_ACQUIRE_POLICY_V1.umount_rule,
            UmountRuleV1::ExactTargetAndZeroFlags
        );
    }

    #[test]
    fn installation_sequence_and_filter_flags_are_not_relaxable() {
        assert!(
            validate_install_sequence_for_test(&[
                SeccompPhaseV1::Initial,
                SeccompPhaseV1::NoAcquire,
            ])
            .is_ok()
        );
        assert_eq!(
            validate_install_sequence_for_test(&[SeccompPhaseV1::NoAcquire]),
            Err(SeccompContractErrorV1::PhaseOrder)
        );
        assert_eq!(
            validate_install_flags_for_test(1),
            Err(SeccompContractErrorV1::InstallFlags)
        );
        assert!(validate_install_flags_for_test(SECCOMP_INSTALL_FLAGS_V1).is_ok());
    }

    #[test]
    fn single_thread_proof_rejects_each_identity_and_snapshot_drift() {
        assert!(validate_single_thread_snapshots(41, 41, &[41], &[41]).is_ok());
        assert_eq!(
            validate_single_thread_snapshots(41, 42, &[42], &[42]),
            Err(SeccompContractErrorV1::ThreadIdentity)
        );
        assert_eq!(
            validate_single_thread_snapshots(41, 41, &[41, 42], &[41]),
            Err(SeccompContractErrorV1::ThreadMultiplicity)
        );
        assert_eq!(
            validate_single_thread_snapshots(41, 41, &[41], &[41, 42]),
            Err(SeccompContractErrorV1::ThreadMultiplicity)
        );
        assert!(ensure_current_tid(41, 41).is_ok());
        assert_eq!(
            ensure_current_tid(41, 42),
            Err(SeccompContractErrorV1::ThreadIdentity)
        );
    }

    #[test]
    fn flags_zero_profiles_keep_clone_and_clone3_denied_after_every_seal() {
        assert_eq!(SECCOMP_INSTALL_FLAGS_V1, 0);
        for policy in [
            GENERATOR_INITIAL_POLICY_V1,
            WORKER_INITIAL_POLICY_V1,
            WORKER_NO_ACQUIRE_POLICY_V1,
        ] {
            assert!(!policy.allowed.contains(&SeccompSyscallV1::Clone));
            assert!(!policy.allowed.contains(&SeccompSyscallV1::Clone3));
        }
    }
}
