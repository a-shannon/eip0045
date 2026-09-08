//! Specialized private physical successor for an authenticated logical rootfs.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ffi::{OsStr, OsString},
    fs::File,
    io::Read as _,
    os::{
        fd::{AsFd as _, BorrowedFd, OwnedFd},
        unix::{ffi::OsStrExt as _, fs::FileExt as _},
    },
    path::Path,
    sync::Mutex,
};

#[cfg(test)]
use std::cell::Cell;

use anyhow::{Context as _, Result, ensure};
#[cfg(test)]
use eip_0045_reproduction::b4_positive_gate::B4PositiveJvmExecutableClosureV1;
use eip_0045_reproduction::b4_positive_gate::{
    B4PositiveJvmReleaseIdentityV1, B4PositiveOciImageLayoutV1, B4PositiveRuntimeElfIdentityV1,
    PositiveRunnerRole,
};
use sha2::{Digest as _, Sha256};

use crate::b4_campaign_executor::{
    amd64_elf_inspection::{
        Amd64ElfAcceptedDynamicTagV1, Amd64ElfCommonInspectionV1, Amd64ElfOsAbiV1,
        Amd64ElfRunpathComponentV1, Amd64ElfStartupDynamicInspectionV1, Amd64ElfTypeV1,
        with_gate_bound_runtime_amd64_elf, with_inspected_startup_dependency_amd64_dso,
    },
    artifact_import_contract::{
        Amd64ElfPolicyV1, B4ImmutableArtifactRoleV1, StartupDependencyClosureLimitsV1,
        startup_dependency_closure_limits_v1,
    },
};

use super::{
    AuthenticatedPrivateOciRootfsProjectionV1, DirectoryIdentity, FileIdentity,
    OCI_LAYER_PATH_MAX_BYTES, OCI_REPLAY_CHUNK_MAX_BYTES, OciRootfsLiveCountersV1,
    PERMISSION_AND_SPECIAL_BITS, PINNED_DIRECTORY_FLAGS, PrivateOciRootfsAbandonedV1,
    PrivateOciRootfsFailedV1, PrivateOciRootfsStagingTransactionV1, SHA256_BYTES,
    StagedRegularExtentV1, StagedRootfsOperationKindV1, StagedRootfsOperationV1,
    directory_identity, ensure_absent, finish_rootfs_abandonment,
    positive_runner_role_identity_tag, regular_file_observation,
};

const PRIVATE_MATERIALIZED_DIRECTORY_MODE: rustix::fs::Mode = rustix::fs::Mode::RWXU;
const PRIVATE_MATERIALIZED_FILE_MODE: rustix::fs::Mode =
    rustix::fs::Mode::RUSR.union(rustix::fs::Mode::WUSR);
const MATERIALIZED_READ_ONLY_MODE: rustix::fs::Mode = rustix::fs::Mode::RUSR
    .union(rustix::fs::Mode::RGRP)
    .union(rustix::fs::Mode::ROTH);
const MATERIALIZED_READ_EXECUTE_MODE: rustix::fs::Mode = MATERIALIZED_READ_ONLY_MODE
    .union(rustix::fs::Mode::XUSR)
    .union(rustix::fs::Mode::XGRP)
    .union(rustix::fs::Mode::XOTH);
const MATERIALIZED_ZERO_MTIME: rustix::fs::Timestamps = rustix::fs::Timestamps {
    last_access: rustix::fs::Timespec {
        tv_sec: 0,
        tv_nsec: rustix::fs::UTIME_OMIT,
    },
    last_modification: rustix::fs::Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    },
};
const MATERIALIZED_REGULAR_CREATE_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDWR
    .union(rustix::fs::OFlags::CREATE)
    .union(rustix::fs::OFlags::EXCL)
    .union(rustix::fs::OFlags::NOFOLLOW)
    .union(rustix::fs::OFlags::CLOEXEC);
const MATERIALIZED_RESOLVE_FLAGS: rustix::fs::ResolveFlags = rustix::fs::ResolveFlags::BENEATH
    .union(rustix::fs::ResolveFlags::NO_SYMLINKS)
    .union(rustix::fs::ResolveFlags::NO_MAGICLINKS)
    .union(rustix::fs::ResolveFlags::NO_XDEV);
const CURRENT_THREAD_MOUNT_NAMESPACE_PATH: &str = "/proc/thread-self/ns/mnt";
const CURRENT_THREAD_USER_NAMESPACE_PATH: &str = "/proc/thread-self/ns/user";
const CURRENT_THREAD_UID_MAP_PATH: &str = "/proc/thread-self/uid_map";
const CURRENT_THREAD_GID_MAP_PATH: &str = "/proc/thread-self/gid_map";
const CURRENT_THREAD_STATUS_PATH: &str = "/proc/thread-self/status";
const NSFS_MAGIC: rustix::fs::FsWord = 0x6e73_6673;
const MOUNT_NAMESPACE_OPEN_FLAGS: rustix::fs::OFlags =
    rustix::fs::OFlags::RDONLY.union(rustix::fs::OFlags::CLOEXEC);
const USER_NAMESPACE_MAP_MAX_BYTES: usize = 16 * 1_024;
// Covers Linux's maximum supplementary-group record plus the remaining status fields.
const CURRENT_THREAD_STATUS_MAX_BYTES: usize = 1_024 * 1_024;
const LINUX_SUPPLEMENTARY_GROUPS_MAX: usize = 65_536;
const ROOTFS_SYMBOLIC_LINK_MAX_HOPS: u8 = 40;
const STARTUP_DEPENDENCY_POLICY_ID: &str = "eip0045-b4-elf64-amd64-startup-dependency-closure-v1";
const STARTUP_DEFAULT_SEARCH_DIRECTORIES: [&str; 6] = [
    "/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
    "/lib64",
    "/usr/lib64",
    "/lib",
    "/usr/lib",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MountNamespaceIdentityV1 {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UserNamespaceIdentityV1 {
    device: u64,
    inode: u64,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestOnlyMountNamespaceIdentityMutationV1 {
    Device,
    Inode,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestOnlyUserNamespaceIdentityMutationV1 {
    Device,
    Inode,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestOnlyUserNamespaceMapMutationV1 {
    UidMismatch,
    GidMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CallingThreadFilesystemCredentialsV1 {
    fsuid: u32,
    fsgid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CallingThreadStatusCredentialsV1 {
    uids: [u32; 4],
    gids: [u32; 4],
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestOnlyFilesystemCredentialMutationV1 {
    Fsuid,
    Fsgid,
}

/// Opaque live custody of the mount and user namespaces used by the calling thread.
///
/// The retained, non-empty `uid_map` and `gid_map` bytes, order-normalized
/// numerical supplementary-group multiset, and numerical `fsuid`/`fsgid`
/// qualify only continuity at explicit checkpoints. They do not distinguish
/// overflow IDs from mapped IDs or prove namespace ancestry, host ownership,
/// mount idmaps, group mappedness, `setgroups` policy, capabilities, LSM
/// context, continuity between checkpoints, freshness, exclusivity, a private
/// mount graph, H0, or B4.
pub(super) struct PinnedCurrentMountNamespaceV1 {
    proc_root: OwnedFd,
    namespace: OwnedFd,
    identity: MountNamespaceIdentityV1,
    user_namespace: OwnedFd,
    user_namespace_identity: UserNamespaceIdentityV1,
    uid_map: Vec<u8>,
    gid_map: Vec<u8>,
    supplementary_groups: Vec<u32>,
    filesystem_credentials: CallingThreadFilesystemCredentialsV1,
    #[cfg(test)]
    test_only_next_reauthentication_identity_mismatch:
        Cell<Option<TestOnlyMountNamespaceIdentityMutationV1>>,
    #[cfg(test)]
    test_only_next_user_namespace_identity_mismatch:
        Cell<Option<TestOnlyUserNamespaceIdentityMutationV1>>,
    #[cfg(test)]
    test_only_next_user_namespace_map_mismatch: Cell<Option<TestOnlyUserNamespaceMapMutationV1>>,
    #[cfg(test)]
    test_only_next_supplementary_groups_mismatch: Cell<bool>,
    #[cfg(test)]
    test_only_next_filesystem_credential_mismatch:
        Cell<Option<TestOnlyFilesystemCredentialMutationV1>>,
}

impl PinnedCurrentMountNamespaceV1 {
    pub(super) fn capture() -> Result<Self> {
        let proc_root = rustix::fs::open(
            Path::new("/proc"),
            PINNED_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
        )
        .context("cannot retain procfs for mount-namespace custody")?;
        validate_procfs(proc_root.as_fd())?;
        let namespace = open_current_thread_mount_namespace(proc_root.as_fd())?;
        let identity = mount_namespace_identity(namespace.as_fd())?;
        let user_namespace = open_current_thread_user_namespace(proc_root.as_fd())?;
        let user_namespace_identity = user_namespace_identity(user_namespace.as_fd())?;
        let uid_map = read_current_thread_user_namespace_map(
            proc_root.as_fd(),
            CURRENT_THREAD_UID_MAP_PATH,
            "uid_map",
        )?;
        let gid_map = read_current_thread_user_namespace_map(
            proc_root.as_fd(),
            CURRENT_THREAD_GID_MAP_PATH,
            "gid_map",
        )?;
        let supplementary_groups = read_stable_current_thread_supplementary_groups()?;
        let filesystem_credentials =
            read_stable_current_thread_filesystem_credentials(proc_root.as_fd())?;
        let pinned = Self {
            proc_root,
            namespace,
            identity,
            user_namespace,
            user_namespace_identity,
            uid_map,
            gid_map,
            supplementary_groups,
            filesystem_credentials,
            #[cfg(test)]
            test_only_next_reauthentication_identity_mismatch: Cell::new(None),
            #[cfg(test)]
            test_only_next_user_namespace_identity_mismatch: Cell::new(None),
            #[cfg(test)]
            test_only_next_user_namespace_map_mismatch: Cell::new(None),
            #[cfg(test)]
            test_only_next_supplementary_groups_mismatch: Cell::new(false),
            #[cfg(test)]
            test_only_next_filesystem_credential_mismatch: Cell::new(None),
        };
        pinned.reauthenticate()?;
        Ok(pinned)
    }

    pub(super) fn reauthenticate(&self) -> Result<()> {
        #[cfg(test)]
        if let Some(mutation) = self
            .test_only_next_reauthentication_identity_mismatch
            .take()
        {
            return self.test_only_validate_mutated_identity(mutation);
        }
        validate_procfs(self.proc_root.as_fd())?;
        ensure!(
            mount_namespace_identity(self.namespace.as_fd())? == self.identity,
            "retained OCI mount-namespace handle identity changed"
        );
        let current = open_current_thread_mount_namespace(self.proc_root.as_fd())?;
        ensure!(
            mount_namespace_identity(current.as_fd())? == self.identity,
            "OCI rootfs calling-thread mount namespace changed"
        );
        ensure!(
            user_namespace_identity(self.user_namespace.as_fd())? == self.user_namespace_identity,
            "retained OCI user-namespace handle identity changed"
        );
        let current_user_namespace = open_current_thread_user_namespace(self.proc_root.as_fd())?;
        let expected_user_namespace_identity = self.user_namespace_identity;
        #[cfg(test)]
        let expected_user_namespace_identity = self
            .test_only_next_user_namespace_identity_mismatch
            .take()
            .map_or(expected_user_namespace_identity, |mutation| {
                Self::test_only_mutated_user_namespace_identity(
                    mutation,
                    expected_user_namespace_identity,
                )
            });
        ensure!(
            user_namespace_identity(current_user_namespace.as_fd())?
                == expected_user_namespace_identity,
            "OCI rootfs calling-thread user namespace changed"
        );
        let observed_user_map = read_current_thread_user_namespace_map(
            self.proc_root.as_fd(),
            CURRENT_THREAD_UID_MAP_PATH,
            "uid_map",
        )?;
        #[cfg(test)]
        let observed_user_map = self.test_only_mutated_user_namespace_map(
            TestOnlyUserNamespaceMapMutationV1::UidMismatch,
            observed_user_map,
        );
        ensure!(
            observed_user_map == self.uid_map,
            "OCI rootfs calling-thread uid_map changed"
        );
        let observed_group_map = read_current_thread_user_namespace_map(
            self.proc_root.as_fd(),
            CURRENT_THREAD_GID_MAP_PATH,
            "gid_map",
        )?;
        #[cfg(test)]
        let observed_group_map = self.test_only_mutated_user_namespace_map(
            TestOnlyUserNamespaceMapMutationV1::GidMismatch,
            observed_group_map,
        );
        ensure!(
            observed_group_map == self.gid_map,
            "OCI rootfs calling-thread gid_map changed"
        );
        let observed_supplementary_groups = read_stable_current_thread_supplementary_groups()?;
        #[cfg(test)]
        let observed_supplementary_groups =
            self.test_only_mutated_supplementary_groups(observed_supplementary_groups);
        ensure!(
            observed_supplementary_groups == self.supplementary_groups,
            "OCI rootfs calling-thread supplementary groups changed"
        );
        let observed_filesystem_credentials =
            read_stable_current_thread_filesystem_credentials(self.proc_root.as_fd())?;
        #[cfg(test)]
        let observed_filesystem_credentials =
            self.test_only_mutated_filesystem_credentials(observed_filesystem_credentials);
        ensure!(
            observed_filesystem_credentials.fsuid == self.filesystem_credentials.fsuid,
            "OCI rootfs calling-thread fsuid changed"
        );
        ensure!(
            observed_filesystem_credentials.fsgid == self.filesystem_credentials.fsgid,
            "OCI rootfs calling-thread fsgid changed"
        );
        let current_user_namespace = open_current_thread_user_namespace(self.proc_root.as_fd())?;
        ensure!(
            user_namespace_identity(current_user_namespace.as_fd())?
                == self.user_namespace_identity,
            "OCI rootfs calling-thread user namespace changed while reading its ID maps, supplementary groups, and filesystem credentials"
        );
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn test_only_arm_next_reauthentication_identity_mismatch(&self) {
        self.test_only_arm_next_reauthentication_identity_mutation(
            TestOnlyMountNamespaceIdentityMutationV1::Inode,
        );
    }

    #[cfg(test)]
    fn test_only_arm_next_reauthentication_identity_mutation(
        &self,
        mutation: TestOnlyMountNamespaceIdentityMutationV1,
    ) {
        assert!(
            self.test_only_next_reauthentication_identity_mismatch
                .replace(Some(mutation))
                .is_none(),
            "test-only mount namespace mismatch was already armed"
        );
    }

    #[cfg(test)]
    fn test_only_validate_mutated_identity(
        &self,
        mutation: TestOnlyMountNamespaceIdentityMutationV1,
    ) -> Result<()> {
        let mut expected = self.identity;
        match mutation {
            TestOnlyMountNamespaceIdentityMutationV1::Device => {
                expected.device = expected.device.wrapping_add(1);
            }
            TestOnlyMountNamespaceIdentityMutationV1::Inode => {
                expected.inode = expected.inode.wrapping_add(1);
            }
        }
        let current = open_current_thread_mount_namespace(self.proc_root.as_fd())?;
        ensure!(
            mount_namespace_identity(current.as_fd())? == expected,
            "OCI rootfs calling-thread mount namespace changed"
        );
        Ok(())
    }

    #[cfg(test)]
    fn test_only_arm_next_user_namespace_identity_mutation(
        &self,
        mutation: TestOnlyUserNamespaceIdentityMutationV1,
    ) {
        assert!(
            self.test_only_next_user_namespace_identity_mismatch
                .replace(Some(mutation))
                .is_none(),
            "test-only user namespace mismatch was already armed"
        );
    }

    #[cfg(test)]
    fn test_only_arm_next_user_namespace_map_mismatch(
        &self,
        mutation: TestOnlyUserNamespaceMapMutationV1,
    ) {
        assert!(
            self.test_only_next_user_namespace_map_mismatch
                .replace(Some(mutation))
                .is_none(),
            "test-only user namespace map mismatch was already armed"
        );
    }

    #[cfg(test)]
    fn test_only_arm_next_supplementary_groups_mismatch(&self) {
        assert!(
            !self
                .test_only_next_supplementary_groups_mismatch
                .replace(true),
            "test-only supplementary-group mismatch was already armed"
        );
    }

    #[cfg(test)]
    fn test_only_arm_next_filesystem_credential_mismatch(
        &self,
        mutation: TestOnlyFilesystemCredentialMutationV1,
    ) {
        assert!(
            self.test_only_next_filesystem_credential_mismatch
                .replace(Some(mutation))
                .is_none(),
            "test-only filesystem-credential mismatch was already armed"
        );
    }

    #[cfg(test)]
    fn test_only_mutated_user_namespace_identity(
        mutation: TestOnlyUserNamespaceIdentityMutationV1,
        mut expected: UserNamespaceIdentityV1,
    ) -> UserNamespaceIdentityV1 {
        match mutation {
            TestOnlyUserNamespaceIdentityMutationV1::Device => {
                expected.device = expected.device.wrapping_add(1);
            }
            TestOnlyUserNamespaceIdentityMutationV1::Inode => {
                expected.inode = expected.inode.wrapping_add(1);
            }
        }
        expected
    }

    #[cfg(test)]
    fn test_only_mutated_user_namespace_map(
        &self,
        mutation: TestOnlyUserNamespaceMapMutationV1,
        mut current: Vec<u8>,
    ) -> Vec<u8> {
        if self.test_only_next_user_namespace_map_mismatch.get() == Some(mutation) {
            self.test_only_next_user_namespace_map_mismatch.set(None);
            current.push(b' ');
        }
        current
    }

    #[cfg(test)]
    fn test_only_mutated_supplementary_groups(&self, mut current: Vec<u32>) -> Vec<u32> {
        if self
            .test_only_next_supplementary_groups_mismatch
            .replace(false)
        {
            current.push(current.last().copied().unwrap_or(0));
        }
        current
    }

    #[cfg(test)]
    fn test_only_mutated_filesystem_credentials(
        &self,
        mut current: CallingThreadFilesystemCredentialsV1,
    ) -> CallingThreadFilesystemCredentialsV1 {
        match self.test_only_next_filesystem_credential_mismatch.take() {
            Some(TestOnlyFilesystemCredentialMutationV1::Fsuid) => {
                current.fsuid = current.fsuid.wrapping_add(1);
            }
            Some(TestOnlyFilesystemCredentialMutationV1::Fsgid) => {
                current.fsgid = current.fsgid.wrapping_add(1);
            }
            None => {}
        }
        current
    }
}

fn parse_calling_thread_status_fields(suffix: &[u8], label: &str) -> Result<[u32; 4]> {
    ensure!(
        suffix
            .first()
            .is_some_and(|byte| matches!(*byte, b' ' | b'\t')),
        "calling-thread status {label} record has no field delimiter"
    );
    ensure!(
        suffix
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(*byte, b' ' | b'\t')),
        "calling-thread status {label} record contains a non-decimal field"
    );
    let fields = suffix
        .split(|byte| matches!(*byte, b' ' | b'\t'))
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    ensure!(
        fields.len() == 4,
        "calling-thread status {label} record does not contain four fields"
    );
    let mut parsed = [0_u32; 4];
    for (index, field) in fields.into_iter().enumerate() {
        let field = std::str::from_utf8(field).expect("validated ASCII decimal status field");
        parsed[index] = field
            .parse::<u32>()
            .with_context(|| format!("calling-thread status {label} field is malformed"))?;
    }
    Ok(parsed)
}

fn parse_calling_thread_status_credentials(
    bytes: &[u8],
) -> Result<CallingThreadStatusCredentialsV1> {
    ensure!(
        bytes.len() <= CURRENT_THREAD_STATUS_MAX_BYTES,
        "calling-thread status exceeds its compiled byte bound"
    );
    ensure!(!bytes.is_empty(), "calling-thread status is empty");
    ensure!(
        bytes.ends_with(b"\n"),
        "calling-thread status has no terminal newline"
    );
    let mut uids = None;
    let mut gids = None;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        if let Some(suffix) = line.strip_prefix(b"Uid:") {
            ensure!(
                uids.is_none(),
                "calling-thread status contains duplicate Uid records"
            );
            uids = Some(parse_calling_thread_status_fields(suffix, "Uid")?);
        } else if let Some(suffix) = line.strip_prefix(b"Gid:") {
            ensure!(
                gids.is_none(),
                "calling-thread status contains duplicate Gid records"
            );
            gids = Some(parse_calling_thread_status_fields(suffix, "Gid")?);
        }
    }
    let uids = uids.context("calling-thread status has no Uid record")?;
    let gids = gids.context("calling-thread status has no Gid record")?;
    Ok(CallingThreadStatusCredentialsV1 { uids, gids })
}

fn project_calling_thread_filesystem_credentials(
    status: CallingThreadStatusCredentialsV1,
    live_user_id: u32,
    live_group_id: u32,
) -> Result<CallingThreadFilesystemCredentialsV1> {
    ensure!(
        status.uids[1] == live_user_id,
        "calling-thread status effective UID disagrees with geteuid"
    );
    ensure!(
        status.gids[1] == live_group_id,
        "calling-thread status effective GID disagrees with getegid"
    );
    Ok(CallingThreadFilesystemCredentialsV1 {
        fsuid: status.uids[3],
        fsgid: status.gids[3],
    })
}

fn read_current_thread_filesystem_credentials_once(
    proc_root: BorrowedFd<'_>,
) -> Result<CallingThreadFilesystemCredentialsV1> {
    let initial_user_id = rustix::process::geteuid().as_raw();
    let initial_group_id = rustix::process::getegid().as_raw();
    let relative = Path::new(CURRENT_THREAD_STATUS_PATH)
        .strip_prefix("/proc")
        .expect("fixed calling-thread status path is procfs-relative");
    let descriptor = rustix::fs::openat(
        proc_root,
        relative,
        MOUNT_NAMESPACE_OPEN_FLAGS,
        rustix::fs::Mode::empty(),
    )
    .context("cannot open calling-thread status")?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(CURRENT_THREAD_STATUS_MAX_BYTES + 1)
        .context("cannot reserve bounded calling-thread status")?;
    File::from(descriptor)
        .take((CURRENT_THREAD_STATUS_MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("cannot read calling-thread status")?;
    let status = parse_calling_thread_status_credentials(&bytes)?;
    let final_user_id = rustix::process::geteuid().as_raw();
    let final_group_id = rustix::process::getegid().as_raw();
    ensure!(
        initial_user_id == final_user_id && initial_group_id == final_group_id,
        "OCI rootfs calling-thread effective credentials changed while reading status"
    );
    project_calling_thread_filesystem_credentials(status, final_user_id, final_group_id)
}

fn require_stable_calling_thread_filesystem_credentials(
    first: CallingThreadFilesystemCredentialsV1,
    second: CallingThreadFilesystemCredentialsV1,
) -> Result<CallingThreadFilesystemCredentialsV1> {
    ensure!(
        first == second,
        "OCI rootfs calling-thread filesystem credentials changed while reading"
    );
    Ok(second)
}

fn read_stable_current_thread_filesystem_credentials(
    proc_root: BorrowedFd<'_>,
) -> Result<CallingThreadFilesystemCredentialsV1> {
    let first = read_current_thread_filesystem_credentials_once(proc_root)?;
    let second = read_current_thread_filesystem_credentials_once(proc_root)?;
    require_stable_calling_thread_filesystem_credentials(first, second)
}

#[cfg(test)]
mod filesystem_credential_projection_tests {
    use super::*;

    fn status(uid: &str, gid: &str) -> Vec<u8> {
        format!("Name:\tworker\nUid:\t{uid}\nGid:\t{gid}\nThreads:\t1\n").into_bytes()
    }

    #[test]
    fn parses_four_fields_and_projects_filesystem_ids() -> Result<()> {
        let parsed = parse_calling_thread_status_credentials(&status(
            "1000\t1001\t1002\t1003",
            "2000\t2001\t2002\t2003",
        ))?;
        assert_eq!(parsed.uids, [1000, 1001, 1002, 1003]);
        assert_eq!(parsed.gids, [2000, 2001, 2002, 2003]);
        assert_eq!(
            project_calling_thread_filesystem_credentials(parsed, 1001, 2001)?,
            CallingThreadFilesystemCredentialsV1 {
                fsuid: 1003,
                fsgid: 2003,
            }
        );
        Ok(())
    }

    #[test]
    fn rejects_absent_duplicate_malformed_and_truncated_records() {
        let mut repeated_user_record = status("1\t1\t1\t1", "2\t2\t2\t2");
        repeated_user_record.extend_from_slice(b"Uid:\t1\t1\t1\t1\n");
        let mut repeated_group_record = status("1\t1\t1\t1", "2\t2\t2\t2");
        repeated_group_record.extend_from_slice(b"Gid:\t2\t2\t2\t2\n");
        for (bytes, expected) in [
            (
                b"Name:\tworker\nGid:\t2\t2\t2\t2\n".to_vec(),
                "no Uid record",
            ),
            (
                b"Name:\tworker\nUid:\t1\t1\t1\t1\n".to_vec(),
                "no Gid record",
            ),
            (repeated_user_record, "duplicate Uid records"),
            (repeated_group_record, "duplicate Gid records"),
            (
                b"Uid:1\t1\t1\t1\nGid:\t2\t2\t2\t2\n".to_vec(),
                "Uid record has no field delimiter",
            ),
            (
                status("1\t1\t1", "2\t2\t2\t2"),
                "Uid record does not contain four fields",
            ),
            (
                status("1\t1\t1\t1\t1", "2\t2\t2\t2"),
                "Uid record does not contain four fields",
            ),
            (
                status("1\t1\tx\t1", "2\t2\t2\t2"),
                "Uid record contains a non-decimal field",
            ),
            (
                status("1\t1\t1\t4294967296", "2\t2\t2\t2"),
                "Uid field is malformed",
            ),
            (
                status("1\t1\t1\t1", "2\t2\tx\t2"),
                "Gid record contains a non-decimal field",
            ),
            (
                status("1\t1\t1\t1", "2\t2\t2\t4294967296"),
                "Gid field is malformed",
            ),
            (
                b"Uid:\t1\t1\t1\t1\nGid:\t2\t2\t2\t2".to_vec(),
                "no terminal newline",
            ),
        ] {
            let error = parse_calling_thread_status_credentials(&bytes)
                .expect_err("malformed calling-thread status must fail closed");
            assert!(format!("{error:#}").contains(expected), "{error:#}");
        }
    }

    #[test]
    fn rejects_effective_id_mismatch_and_unstable_snapshots() -> Result<()> {
        let parsed = parse_calling_thread_status_credentials(&status(
            "1000\t1001\t1002\t1003",
            "2000\t2001\t2002\t2003",
        ))?;
        for (uid, gid, expected) in [
            (1000, 2001, "effective UID disagrees"),
            (1001, 2000, "effective GID disagrees"),
        ] {
            let error = project_calling_thread_filesystem_credentials(parsed, uid, gid)
                .expect_err("effective-ID disagreement must fail closed");
            assert!(format!("{error:#}").contains(expected), "{error:#}");
        }
        for second in [
            CallingThreadFilesystemCredentialsV1 {
                fsuid: 1004,
                fsgid: 2003,
            },
            CallingThreadFilesystemCredentialsV1 {
                fsuid: 1003,
                fsgid: 2004,
            },
        ] {
            let error = require_stable_calling_thread_filesystem_credentials(
                CallingThreadFilesystemCredentialsV1 {
                    fsuid: 1003,
                    fsgid: 2003,
                },
                second,
            )
            .expect_err("filesystem-credential drift must fail closed");
            assert!(
                format!("{error:#}").contains("filesystem credentials changed while reading"),
                "{error:#}"
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_status_larger_than_compiled_bound() {
        let oversized = vec![b'x'; CURRENT_THREAD_STATUS_MAX_BYTES + 1];
        let error = parse_calling_thread_status_credentials(&oversized)
            .expect_err("oversized calling-thread status must fail closed");
        assert!(format!("{error:#}").contains("exceeds its compiled byte bound"));
    }
}

fn normalize_linux_supplementary_group_projection(
    groups: Vec<rustix::process::Gid>,
) -> Result<Vec<u32>> {
    ensure!(
        groups.len() <= LINUX_SUPPLEMENTARY_GROUPS_MAX,
        "calling-thread supplementary groups exceed Linux limit of {LINUX_SUPPLEMENTARY_GROUPS_MAX}"
    );
    let mut groups = groups
        .into_iter()
        .map(rustix::fs::Gid::as_raw)
        .collect::<Vec<_>>();
    groups.sort_unstable();
    Ok(groups)
}

fn require_stable_supplementary_group_projection(
    first: &[u32],
    second: Vec<u32>,
) -> Result<Vec<u32>> {
    ensure!(
        first == second,
        "OCI rootfs calling-thread supplementary groups changed while reading"
    );
    Ok(second)
}

fn read_current_thread_supplementary_groups_once() -> Result<Vec<u32>> {
    let groups =
        rustix::process::getgroups().context("cannot read calling-thread supplementary groups")?;
    normalize_linux_supplementary_group_projection(groups)
}

fn read_stable_current_thread_supplementary_groups() -> Result<Vec<u32>> {
    let first = read_current_thread_supplementary_groups_once()?;
    let second = read_current_thread_supplementary_groups_once()?;
    require_stable_supplementary_group_projection(&first, second)
}

#[cfg(test)]
mod supplementary_group_projection_tests {
    use super::*;

    fn gids(raw: &[u32]) -> Vec<rustix::process::Gid> {
        raw.iter()
            .copied()
            .map(rustix::process::Gid::from_raw)
            .collect()
    }

    #[test]
    fn normalizes_order_preserves_multiplicity_and_accepts_empty() -> Result<()> {
        assert_eq!(
            normalize_linux_supplementary_group_projection(gids(&[7, 3, 7]))?,
            vec![3, 7, 7]
        );
        assert_eq!(
            normalize_linux_supplementary_group_projection(Vec::new())?,
            Vec::<u32>::new()
        );
        let first = normalize_linux_supplementary_group_projection(gids(&[7, 3, 7]))?;
        let second = normalize_linux_supplementary_group_projection(gids(&[7, 7, 3]))?;
        assert_eq!(
            require_stable_supplementary_group_projection(&first, second)?,
            vec![3, 7, 7]
        );
        Ok(())
    }

    #[test]
    fn rejects_value_multiplicity_and_shrink_tail_drift() {
        for (first, second) in [
            (vec![3, 7], vec![3, 8]),
            (vec![3, 7, 7], vec![3, 7]),
            (vec![4, 5, 6], vec![0, 0, 4]),
        ] {
            let error = require_stable_supplementary_group_projection(&first, second)
                .expect_err("supplementary-group drift must fail closed");
            assert!(
                error
                    .to_string()
                    .contains("calling-thread supplementary groups changed"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn rejects_more_than_linux_supplementary_group_limit() {
        let groups = (0..=LINUX_SUPPLEMENTARY_GROUPS_MAX)
            .map(|raw| rustix::process::Gid::from_raw(raw as u32))
            .collect();
        let error = normalize_linux_supplementary_group_projection(groups)
            .expect_err("a snapshot larger than the Linux limit must fail closed");
        assert!(
            error
                .to_string()
                .contains("supplementary groups exceed Linux limit of 65536"),
            "{error:#}"
        );
    }
}

fn validate_procfs(descriptor: BorrowedFd<'_>) -> Result<()> {
    let statfs = rustix::fs::fstatfs(descriptor)
        .context("cannot inspect retained procfs for mount-namespace custody")?;
    ensure!(
        statfs.f_type == rustix::fs::PROC_SUPER_MAGIC,
        "retained OCI mount-namespace observer is not procfs"
    );
    Ok(())
}

fn open_current_thread_mount_namespace(proc_root: BorrowedFd<'_>) -> Result<OwnedFd> {
    let relative = Path::new(CURRENT_THREAD_MOUNT_NAMESPACE_PATH)
        .strip_prefix("/proc")
        .expect("fixed mount-namespace path is procfs-relative");
    let descriptor = rustix::fs::openat(
        proc_root,
        relative,
        MOUNT_NAMESPACE_OPEN_FLAGS,
        rustix::fs::Mode::empty(),
    )
    .context("cannot retain calling-thread mount namespace")?;
    mount_namespace_identity(descriptor.as_fd())?;
    Ok(descriptor)
}

fn mount_namespace_identity(descriptor: BorrowedFd<'_>) -> Result<MountNamespaceIdentityV1> {
    let statfs = rustix::fs::fstatfs(descriptor)
        .context("cannot inspect retained OCI mount namespace filesystem")?;
    ensure!(
        statfs.f_type == NSFS_MAGIC,
        "retained OCI mount-namespace handle is not nsfs"
    );
    let stat = rustix::fs::fstat(descriptor)
        .context("cannot inspect retained OCI mount-namespace identity")?;
    Ok(MountNamespaceIdentityV1 {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

fn open_current_thread_user_namespace(proc_root: BorrowedFd<'_>) -> Result<OwnedFd> {
    let relative = Path::new(CURRENT_THREAD_USER_NAMESPACE_PATH)
        .strip_prefix("/proc")
        .expect("fixed user-namespace path is procfs-relative");
    let descriptor = rustix::fs::openat(
        proc_root,
        relative,
        MOUNT_NAMESPACE_OPEN_FLAGS,
        rustix::fs::Mode::empty(),
    )
    .context("cannot retain calling-thread user namespace")?;
    user_namespace_identity(descriptor.as_fd())?;
    Ok(descriptor)
}

fn user_namespace_identity(descriptor: BorrowedFd<'_>) -> Result<UserNamespaceIdentityV1> {
    let statfs = rustix::fs::fstatfs(descriptor)
        .context("cannot inspect retained OCI user namespace filesystem")?;
    ensure!(
        statfs.f_type == NSFS_MAGIC,
        "retained OCI user-namespace handle is not nsfs"
    );
    let stat = rustix::fs::fstat(descriptor)
        .context("cannot inspect retained OCI user-namespace identity")?;
    Ok(UserNamespaceIdentityV1 {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

fn read_current_thread_user_namespace_map(
    proc_root: BorrowedFd<'_>,
    path: &str,
    label: &str,
) -> Result<Vec<u8>> {
    let relative = Path::new(path)
        .strip_prefix("/proc")
        .expect("fixed user-namespace map path is procfs-relative");
    let descriptor = rustix::fs::openat(
        proc_root,
        relative,
        MOUNT_NAMESPACE_OPEN_FLAGS,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| format!("cannot open calling-thread {label}"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(USER_NAMESPACE_MAP_MAX_BYTES + 1)
        .with_context(|| format!("cannot reserve bounded calling-thread {label}"))?;
    File::from(descriptor)
        .take((USER_NAMESPACE_MAP_MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read calling-thread {label}"))?;
    ensure!(
        bytes.len() <= USER_NAMESPACE_MAP_MAX_BYTES,
        "calling-thread {label} exceeds its compiled byte bound"
    );
    validate_user_namespace_map(&bytes, label)?;
    Ok(bytes)
}

fn validate_user_namespace_map(bytes: &[u8], label: &str) -> Result<()> {
    ensure!(!bytes.is_empty(), "calling-thread {label} is empty");
    let text = std::str::from_utf8(bytes)
        .with_context(|| format!("calling-thread {label} is not UTF-8"))?;
    ensure!(
        text.ends_with('\n'),
        "calling-thread {label} has no terminal newline"
    );
    let mut records = 0_u64;
    for line in text.lines() {
        ensure!(
            !line.is_empty(),
            "calling-thread {label} has an empty record"
        );
        ensure!(
            line.bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b' ' | b'\t')),
            "calling-thread {label} contains a non-decimal record"
        );
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        ensure!(
            fields.len() == 3,
            "calling-thread {label} record does not contain three fields"
        );
        let inside = u64::from(
            fields[0]
                .parse::<u32>()
                .with_context(|| format!("calling-thread {label} inside ID is malformed"))?,
        );
        let outside = u64::from(
            fields[1]
                .parse::<u32>()
                .with_context(|| format!("calling-thread {label} outside ID is malformed"))?,
        );
        let length = u64::from(
            fields[2]
                .parse::<u32>()
                .with_context(|| format!("calling-thread {label} length is malformed"))?,
        );
        ensure!(
            length != 0,
            "calling-thread {label} has a zero-length range"
        );
        let id_space_end = u64::from(u32::MAX);
        ensure!(
            inside
                .checked_add(length)
                .is_some_and(|end| end <= id_space_end)
                && outside
                    .checked_add(length)
                    .is_some_and(|end| end <= id_space_end),
            "calling-thread {label} range leaves the Linux ID space"
        );
        records = records
            .checked_add(1)
            .context("calling-thread user-namespace map record count overflowed")?;
    }
    ensure!(records != 0, "calling-thread {label} has no records");
    Ok(())
}

#[cfg(test)]
pub(super) fn test_only_validate_user_namespace_map(bytes: &[u8], label: &str) -> Result<()> {
    validate_user_namespace_map(bytes, label)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedRootfsPathV1 {
    canonical_path: String,
    final_path: String,
    position: Option<usize>,
    symbolic_link_chain: Vec<ResolvedRootfsSymbolicLinkHopV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedRootfsSymbolicLinkHopV1 {
    canonical_link_path: String,
    exact_target: String,
    normalized_target_path: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootfsResolutionFinalKindV1 {
    Directory,
    Regular,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StartupNeededLibraryV1 {
    dynamic_ordinal: u64,
    requested_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StartupRunpathComponentV1 {
    Absolute(String),
    OriginRelative { raw: String, suffix: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StartupDynamicProjectionV1 {
    accepted_records: Vec<(i64, u64)>,
    accepted_tags: Vec<Amd64ElfAcceptedDynamicTagV1>,
    needed_libraries: Vec<StartupNeededLibraryV1>,
    soname: Option<String>,
    runpath_raw: Option<String>,
    runpath_components: Vec<StartupRunpathComponentV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StartupElfProjectionV1 {
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct StaticStartupDependencyNodeV1 {
    resolution: ResolvedRootfsPathV1,
    byte_length: u64,
    sha256: [u8; SHA256_BYTES],
    elf: StartupElfProjectionV1,
    dynamic: StartupDynamicProjectionV1,
    depth: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StaticStartupDependencyResolutionKindV1 {
    LoadedSoname,
    RootfsSearch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GateRootedStartupExecutableV1 {
    Launcher,
    Compiler,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StaticStartupDependencyEdgeV1 {
    requester: usize,
    dynamic_ordinal: u64,
    requested_name: String,
    resolution_kind: StaticStartupDependencyResolutionKindV1,
    selected: usize,
}

#[derive(Debug, Eq, PartialEq)]
struct StaticStartupDependencyClosureV1 {
    nodes: Vec<StaticStartupDependencyNodeV1>,
    edges: Vec<StaticStartupDependencyEdgeV1>,
}

/// Exact per-executable startup closures retained under one physical rootfs.
///
/// The fixed launcher/compiler shape prevents a caller from reordering or
/// relabelling an untyped collection. Native roles retain two explicit
/// absences; JVM verification retains only the launcher; JVM build retains
/// both closures.
#[derive(Debug, Eq, PartialEq)]
struct StaticStartupDependencyBaselinesV1 {
    launcher: Option<StaticStartupDependencyClosureV1>,
    compiler: Option<StaticStartupDependencyClosureV1>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct StaticStartupDependencyCountersV1 {
    distinct_objects: u64,
    dependency_edges: u64,
    aggregate_distinct_object_bytes: u64,
}

struct StaticStartupDependencyDerivationStateV1 {
    nodes: Vec<StaticStartupDependencyNodeV1>,
    loaded_soname_nodes: Vec<usize>,
    edges: Vec<StaticStartupDependencyEdgeV1>,
    queue: VecDeque<usize>,
    counters: StaticStartupDependencyCountersV1,
}

struct StartupDependencyDsoInspectionV1<'a> {
    resolution: ResolvedRootfsPathV1,
    selected_basename: &'a str,
    required_modes: &'a [u32],
    depth: u64,
    limits: StartupDependencyClosureLimitsV1,
    label: &'a str,
}

struct AuthenticatedRootfsResolutionStateV1 {
    pending: VecDeque<String>,
    resolved: Vec<String>,
    followed_paths: BTreeSet<String>,
    followed_inodes: BTreeSet<(u32, u32, u64, u64)>,
    symbolic_link_chain: Vec<ResolvedRootfsSymbolicLinkHopV1>,
    symbolic_link_hops: u8,
}

#[cfg(test)]
pub(super) type StartupClosureExpectedEdgeV1<'a> = (usize, u64, &'a str, &'a str, usize, u64);

#[cfg(test)]
pub(super) struct StartupClosureTestExpectationV1<'a> {
    pub(super) image_path: &'a str,
    pub(super) additional_independent_image_paths: &'a [&'a str],
    pub(super) mount_targets: &'a [&'a str],
    pub(super) expected_canonical_node_order: Option<&'a [&'a str]>,
    pub(super) expected_edges: Option<&'a [StartupClosureExpectedEdgeV1<'a>]>,
    pub(super) expected_aggregate_distinct_object_bytes: Option<u64>,
    pub(super) expected_root_entry_point_is_zero: Option<bool>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TestOnlyRetainedStartupBaselineV1 {
    Launcher,
    Compiler,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TestOnlyPrivateMaterializationFailpointV1 {
    ReadyBeforeStagingRootCreation,
    BeforeFirstEffectMountNamespaceMismatch,
    BeforeFirstEffectUserNamespaceMismatch,
    BeforeFirstEffectUidMapMismatch,
    BeforeFirstEffectGidMapMismatch,
    BeforeFirstEffectSupplementaryGroupsMismatch,
    BeforeFirstEffectFsuidMismatch,
    BeforeFirstEffectFsgidMismatch,
    BeforeFirstEffectFinalizerEffectiveUidMismatch,
    BeforeFirstEffectFinalizerEffectiveGidMismatch,
    LogicalSpoolCustodyDriftBeforeAbandonment,
    StagingRootNamedBeforePin,
    StagingRootMappedOwnerMismatch,
    StagingRootMappedGroupMismatch,
    StagingRootIdentityCaptured,
    DirectoryNamedBeforePin {
        operation_index: usize,
    },
    DirectoryIdentityRecorded {
        operation_index: usize,
    },
    DirectoryMappedOwnerMismatch {
        operation_index: usize,
    },
    DirectoryMappedGroupMismatch {
        operation_index: usize,
    },
    RegularFileDescriptorRecorded {
        operation_index: usize,
    },
    RegularFileDescriptorRecordedWithSameNameSubstitution {
        operation_index: usize,
        holding_name: &'static str,
    },
    RegularIdentityRecorded {
        operation_index: usize,
    },
    RegularMappedOwnerMismatch {
        operation_index: usize,
    },
    RegularMappedGroupMismatch {
        operation_index: usize,
    },
    RegularModeSealRecorded {
        operation_index: usize,
    },
    RegularSealRecorded {
        operation_index: usize,
    },
    SymbolicLinkNamedBeforeIdentity {
        operation_index: usize,
    },
    SymbolicLinkIdentityRecorded {
        operation_index: usize,
    },
    SymbolicLinkMappedOwnerMismatch {
        operation_index: usize,
    },
    SymbolicLinkMappedGroupMismatch {
        operation_index: usize,
    },
    SymbolicLinkSealRecorded {
        operation_index: usize,
    },
    DirectoryMtimeRecorded {
        operation_index: usize,
    },
    DirectorySealRecorded {
        operation_index: usize,
    },
    StagingRootMtimeRecorded,
    StagingRootSealRecorded,
    AfterMaterializationFsyncFinalizerEffectiveUidMismatch,
    AfterMaterializationFsyncFinalizerEffectiveGidMismatch,
    StagingRootUnlinked,
    StagingRootUnlinkedWithNextMountNamespaceMismatch,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TestOnlyPrivateCleanupFailpointV1 {
    StagingRootReopened,
    AfterFirstEntryUnlinkedMountNamespaceMismatch,
    AfterFirstEntryUnlinkedUserNamespaceMismatch,
    AfterFirstEntryUnlinkedSupplementaryGroupsMismatch,
    AfterFirstEntryUnlinkedFsuidMismatch,
    AfterFirstEntryUnlinkedFsgidMismatch,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TestOnlyPhysicalCustodyMutationV1 {
    MountNamespaceDevice,
    MountNamespaceInode,
    UserNamespaceDevice,
    UserNamespaceInode,
    FinalizerEffectiveUid,
    FinalizerEffectiveGid,
    StagingDevice,
    StagingInode,
    StagingMount,
    StagingGroup,
    StagingStableUnexpectedOwner,
    StagingStableUnexpectedGroup,
    StagingObservedMode,
    StagingObservedMtimeSeconds,
    StagingObservedMtimeNanoseconds,
    StagingObservedOwner,
    StagingExpectedCardinality,
    DirectoryDevice { operation_index: usize },
    DirectoryInode { operation_index: usize },
    DirectoryMount { operation_index: usize },
    DirectoryGroup { operation_index: usize },
    DirectoryStableUnexpectedOwner { operation_index: usize },
    DirectoryStableUnexpectedGroup { operation_index: usize },
    DirectoryObservedMode { operation_index: usize },
    DirectoryObservedMtimeSeconds { operation_index: usize },
    DirectoryObservedMtimeNanoseconds { operation_index: usize },
    DirectoryObservedOwner { operation_index: usize },
    DirectoryExpectedCardinality { operation_index: usize },
    RegularDevice { operation_index: usize },
    RegularInode { operation_index: usize },
    RegularMount { operation_index: usize },
    RegularGroup { operation_index: usize },
    RegularStableUnexpectedOwner { operation_index: usize },
    RegularStableUnexpectedGroup { operation_index: usize },
    RegularObservedMtimeSeconds { operation_index: usize },
    RegularObservedMtimeNanoseconds { operation_index: usize },
    RegularObservedOwner { operation_index: usize },
    SymbolicLinkDeviceMajor { operation_index: usize },
    SymbolicLinkDeviceMinor { operation_index: usize },
    SymbolicLinkInode { operation_index: usize },
    SymbolicLinkMount { operation_index: usize },
    SymbolicLinkGroup { operation_index: usize },
    SymbolicLinkStableUnexpectedOwner { operation_index: usize },
    SymbolicLinkStableUnexpectedGroup { operation_index: usize },
    SymbolicLinkObservedHardLinkCount { operation_index: usize },
    SymbolicLinkObservedMode { operation_index: usize },
    SymbolicLinkObservedMtimeSeconds { operation_index: usize },
    SymbolicLinkObservedMtimeNanoseconds { operation_index: usize },
    SymbolicLinkObservedOwner { operation_index: usize },
    SymbolicLinkExpectedTarget { operation_index: usize },
}

struct FinalizerEffectiveIdsV1 {
    uid: u64,
    gid: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum FinalizerEffectiveIdsObservationMutationV1 {
    Unchanged,
    #[cfg(test)]
    Uid,
    #[cfg(test)]
    Gid,
}

#[cfg(test)]
fn take_test_only_finalizer_effective_ids_observation_mutation(
    armed: &mut Option<TestOnlyPrivateMaterializationFailpointV1>,
    uid_checkpoint: TestOnlyPrivateMaterializationFailpointV1,
    gid_checkpoint: TestOnlyPrivateMaterializationFailpointV1,
) -> FinalizerEffectiveIdsObservationMutationV1 {
    let mutation = if *armed == Some(uid_checkpoint) {
        FinalizerEffectiveIdsObservationMutationV1::Uid
    } else if *armed == Some(gid_checkpoint) {
        FinalizerEffectiveIdsObservationMutationV1::Gid
    } else {
        FinalizerEffectiveIdsObservationMutationV1::Unchanged
    };
    if mutation != FinalizerEffectiveIdsObservationMutationV1::Unchanged {
        *armed = None;
    }
    mutation
}

#[derive(Clone, Copy)]
struct MaterializedDirectoryStateV1 {
    identity: DirectoryIdentity,
    owner: u64,
    group: u64,
    sealed: bool,
}

#[derive(Clone, Copy)]
struct MaterializedRegularStateV1 {
    identity: FileIdentity,
    owner: u64,
    group: u64,
    complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SymbolicLinkIdentityV1 {
    device_major: u32,
    device_minor: u32,
    inode: u64,
    mount_id: u64,
}

#[derive(Clone, Copy)]
struct MaterializedSymbolicLinkStateV1 {
    identity: SymbolicLinkIdentityV1,
    owner: u64,
    group: u64,
    complete: bool,
}

#[derive(Clone, Copy)]
enum MaterializedEntryStateV1 {
    Directory(MaterializedDirectoryStateV1),
    Regular(MaterializedRegularStateV1),
    SymbolicLink(MaterializedSymbolicLinkStateV1),
}

enum MaterializedEntryPhaseV1 {
    Planned,
    NamedUnidentified,
    RegularCreatorFd(File),
    Identified(MaterializedEntryStateV1),
}

struct MaterializedEntryV1 {
    operation_index: usize,
    parent_position: Option<usize>,
    expected_child_count: usize,
    created_child_count: usize,
    phase: MaterializedEntryPhaseV1,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StagingRootBootstrapPhaseV1 {
    Absent,
    NamedUnidentified,
}

/// Affine quarantine custody established before the root namespace effect.
struct PrivateOciRootfsBootstrapCustodyV1 {
    transaction: PrivateOciRootfsStagingTransactionV1,
    finalizer_effective_ids: FinalizerEffectiveIdsV1,
    canonical_live_operation_indices: Vec<usize>,
    counters: OciRootfsLiveCountersV1,
    authenticated_logical_projection_sha256: [u8; SHA256_BYTES],
    staging_name: OsString,
    root_expected_child_count: usize,
    entries: Vec<MaterializedEntryV1>,
    directory_seal_order: Vec<usize>,
    root_phase: StagingRootBootstrapPhaseV1,
    #[cfg(test)]
    test_only_materialization_failpoint: Option<TestOnlyPrivateMaterializationFailpointV1>,
}

/// Affine custody of one private, authenticated, non-published physical rootfs.
///
/// Its retained host-rootfs mapped-owner prerequisite authenticates only
/// numeric equality between inode UID/GID and the finalizer effective IDs as
/// visible through the current user-namespace and idmapped-mount view at each
/// observation instant. It does not approve a raw host mapping, `fsuid`/`fsgid`,
/// supplementary groups, initial-user-namespace ownership, container-visible
/// UID/GID 65532, or any user-namespace mapping.
/// The root-mode-and-mtime seal does not authenticate extended attributes,
/// ACLs, file capabilities, mounts, or execution/session state.
#[must_use = "private physical OCI rootfs custody must be explicitly cleaned"]
pub(super) struct AuthenticatedPrivateOciRootfsMaterializationV1 {
    transaction: PrivateOciRootfsStagingTransactionV1,
    finalizer_effective_ids: FinalizerEffectiveIdsV1,
    canonical_live_operation_indices: Vec<usize>,
    counters: OciRootfsLiveCountersV1,
    authenticated_logical_projection_sha256: [u8; SHA256_BYTES],
    staging_name: OsString,
    staging_root: OwnedFd,
    staging_root_identity: DirectoryIdentity,
    staging_root_owner: u64,
    staging_root_group: u64,
    root_expected_child_count: usize,
    root_created_child_count: usize,
    entries: Vec<MaterializedEntryV1>,
    directory_seal_order: Vec<usize>,
    staging_root_sealed: bool,
    cleanup_started: bool,
    staging_root_unlinked: bool,
    #[cfg(test)]
    test_only_materialization_failpoint: Option<TestOnlyPrivateMaterializationFailpointV1>,
    #[cfg(test)]
    test_only_cleanup_custody_mutation: Cell<Option<TestOnlyPhysicalCustodyMutationV1>>,
    #[cfg(test)]
    test_only_cleanup_failpoint: Cell<Option<TestOnlyPrivateCleanupFailpointV1>>,
    #[cfg(test)]
    test_only_runtime_metadata_seal_order: Vec<String>,
}

/// Affine physical rootfs custody with its exact authenticated startup baseline.
///
/// This value retains the host rootfs name and descriptors only for a later
/// checked executor boundary. It is not mount, child-launch, execution,
/// observation, publication, or completion authority.
#[must_use = "retained physical OCI rootfs custody must be reauthenticated and explicitly cleaned"]
pub(super) struct AuthenticatedPrivateOciRetainedPhysicalRootfsV1 {
    rootfs: AuthenticatedPrivateOciRootfsMaterializationV1,
    static_startup_dependencies: StaticStartupDependencyBaselinesV1,
}

/// Affine failure that retains retry custody while named physical state remains.
#[must_use = "failed private OCI rootfs cleanup retains owned retry custody"]
pub(super) struct PrivateOciRootfsCleanupFailureV1 {
    error: anyhow::Error,
    retry_custody: Option<Box<Mutex<PrivateOciRootfsRetryCustodyV1>>>,
}

enum PrivateOciRootfsRetryCustodyV1 {
    NamedUnidentifiedRoot(PrivateOciRootfsBootstrapCustodyV1),
    Materialized(AuthenticatedPrivateOciRootfsMaterializationV1),
}

impl PrivateOciRootfsCleanupFailureV1 {
    fn recoverable(
        error: anyhow::Error,
        recovery: AuthenticatedPrivateOciRootfsMaterializationV1,
    ) -> Self {
        Self {
            error,
            retry_custody: Some(Box::new(Mutex::new(
                PrivateOciRootfsRetryCustodyV1::Materialized(recovery),
            ))),
        }
    }

    fn quarantined_root(
        error: anyhow::Error,
        recovery: PrivateOciRootfsBootstrapCustodyV1,
    ) -> Self {
        debug_assert!(recovery.root_phase == StagingRootBootstrapPhaseV1::NamedUnidentified);
        Self {
            error,
            retry_custody: Some(Box::new(Mutex::new(
                PrivateOciRootfsRetryCustodyV1::NamedUnidentifiedRoot(recovery),
            ))),
        }
    }

    fn recoverable_custody(error: anyhow::Error, recovery: PrivateOciRootfsRetryCustodyV1) -> Self {
        Self {
            error,
            retry_custody: Some(Box::new(Mutex::new(recovery))),
        }
    }

    fn terminal(error: anyhow::Error) -> Self {
        Self {
            error,
            retry_custody: None,
        }
    }

    pub(super) fn retry_cleanup(self) -> std::result::Result<PrivateOciRootfsAbandonedV1, Self> {
        self.retry_cleanup_preserving_error()
            .map(|(abandonment, _error)| abandonment)
    }

    pub(super) fn retry_cleanup_preserving_error(
        mut self,
    ) -> std::result::Result<(PrivateOciRootfsAbandonedV1, anyhow::Error), Self> {
        let Some(recovery) = self.retry_custody.take() else {
            return Err(self);
        };
        let recovery = match (*recovery).into_inner() {
            Ok(recovery) => recovery,
            Err(poisoned) => poisoned.into_inner(),
        };
        match recovery {
            PrivateOciRootfsRetryCustodyV1::NamedUnidentifiedRoot(recovery) => {
                Err(Self::recoverable_custody(
                    self.error.context(
                        "private OCI rootfs staging identity was not captured; quarantined name cannot be safely deleted",
                    ),
                    PrivateOciRootfsRetryCustodyV1::NamedUnidentifiedRoot(recovery),
                ))
            }
            PrivateOciRootfsRetryCustodyV1::Materialized(recovery) => match recovery.cleanup() {
                Ok(abandoned) => Ok((abandoned, self.error)),
                Err(mut retry_failure) => {
                    let retry_error = std::mem::replace(
                        &mut retry_failure.error,
                        anyhow::anyhow!("private OCI rootfs retry cleanup failed"),
                    );
                    retry_failure.error = self.error.context(format!(
                        "private OCI rootfs retry cleanup remains incomplete: {retry_error:#}"
                    ));
                    Err(retry_failure)
                }
            },
        }
    }
}

impl std::fmt::Display for PrivateOciRootfsCleanupFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.error, formatter)
    }
}

impl std::fmt::Debug for PrivateOciRootfsCleanupFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let error = format!("{:#}", self.error);
        formatter
            .debug_struct("PrivateOciRootfsCleanupFailureV1")
            .field("error", &error)
            .field("retains_retry_custody", &self.retry_custody.is_some())
            .finish()
    }
}

impl std::error::Error for PrivateOciRootfsCleanupFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref())
    }
}

impl PrivateOciRootfsBootstrapCustodyV1 {
    fn fail_before_named_effect(self, primary: anyhow::Error) -> anyhow::Error {
        debug_assert!(self.root_phase == StagingRootBootstrapPhaseV1::Absent);
        let Self {
            transaction,
            finalizer_effective_ids: _,
            canonical_live_operation_indices,
            counters,
            authenticated_logical_projection_sha256,
            staging_name: _,
            root_expected_child_count: _,
            entries: _,
            directory_seal_order: _,
            root_phase: _,
            #[cfg(test)]
            test_only_materialization_failpoint,
        } = self;
        AuthenticatedPrivateOciRootfsProjectionV1 {
            transaction,
            canonical_live_operation_indices,
            counters,
            authenticated_logical_projection_sha256,
            #[cfg(test)]
            test_only_physical_materialization_failpoint: test_only_materialization_failpoint,
        }
        .discard_after_error(primary)
    }

    #[cfg(test)]
    fn take_before_first_effect_finalizer_ids_observation_mutation(
        &mut self,
    ) -> FinalizerEffectiveIdsObservationMutationV1 {
        take_test_only_finalizer_effective_ids_observation_mutation(
            &mut self.test_only_materialization_failpoint,
            TestOnlyPrivateMaterializationFailpointV1::BeforeFirstEffectFinalizerEffectiveUidMismatch,
            TestOnlyPrivateMaterializationFailpointV1::BeforeFirstEffectFinalizerEffectiveGidMismatch,
        )
    }

    #[cfg(test)]
    fn trigger_test_failpoint(
        &mut self,
        reached: TestOnlyPrivateMaterializationFailpointV1,
    ) -> Result<()> {
        if self.test_only_materialization_failpoint == Some(reached) {
            self.test_only_materialization_failpoint = None;
            anyhow::bail!("injected private OCI rootfs materialization failure at {reached:?}")
        }
        Ok(())
    }
}

impl AuthenticatedPrivateOciRootfsProjectionV1 {
    fn fail_before_named_effect(self, primary: anyhow::Error) -> anyhow::Error {
        self.discard_after_error(primary)
    }

    fn into_private_materialization_bootstrap(
        self,
        finalizer_effective_ids: FinalizerEffectiveIdsV1,
    ) -> Result<PrivateOciRootfsBootstrapCustodyV1> {
        let (entries, directory_seal_order, root_expected_child_count) =
            match preflight_private_materialization(
                &self.transaction,
                &self.canonical_live_operation_indices,
                self.counters,
            ) {
                Ok(preflight) => preflight,
                Err(primary) => return Err(self.fail_before_named_effect(primary)),
            };
        let Self {
            transaction,
            canonical_live_operation_indices,
            counters,
            authenticated_logical_projection_sha256,
            #[cfg(test)]
            test_only_physical_materialization_failpoint,
        } = self;
        let staging_name =
            private_staging_name(&transaction, authenticated_logical_projection_sha256);
        Ok(PrivateOciRootfsBootstrapCustodyV1 {
            transaction,
            finalizer_effective_ids,
            canonical_live_operation_indices,
            counters,
            authenticated_logical_projection_sha256,
            staging_name,
            root_expected_child_count,
            entries,
            directory_seal_order,
            root_phase: StagingRootBootstrapPhaseV1::Absent,
            #[cfg(test)]
            test_only_materialization_failpoint: test_only_physical_materialization_failpoint,
        })
    }

    pub(super) fn materialize_private(
        self,
    ) -> Result<AuthenticatedPrivateOciRootfsMaterializationV1> {
        self.transaction.current_mount_namespace.reauthenticate()?;
        let finalizer_effective_ids = capture_finalizer_effective_ids();
        self.transaction.current_mount_namespace.reauthenticate()?;
        let mut bootstrap = self.into_private_materialization_bootstrap(finalizer_effective_ids)?;

        let pre_effect = (|| {
            #[cfg(test)]
            if bootstrap.test_only_materialization_failpoint
                == Some(TestOnlyPrivateMaterializationFailpointV1::BeforeFirstEffectMountNamespaceMismatch)
            {
                bootstrap.test_only_materialization_failpoint = None;
                bootstrap
                    .transaction
                    .current_mount_namespace
                    .test_only_arm_next_reauthentication_identity_mismatch();
            }
            #[cfg(test)]
            if bootstrap.test_only_materialization_failpoint
                == Some(TestOnlyPrivateMaterializationFailpointV1::BeforeFirstEffectUserNamespaceMismatch)
            {
                bootstrap.test_only_materialization_failpoint = None;
                bootstrap
                    .transaction
                    .current_mount_namespace
                    .test_only_arm_next_user_namespace_identity_mutation(
                        TestOnlyUserNamespaceIdentityMutationV1::Inode,
                    );
            }
            #[cfg(test)]
            if matches!(
                bootstrap.test_only_materialization_failpoint,
                Some(
                    TestOnlyPrivateMaterializationFailpointV1::BeforeFirstEffectUidMapMismatch
                        | TestOnlyPrivateMaterializationFailpointV1::BeforeFirstEffectGidMapMismatch
                )
            ) {
                let mutation = if bootstrap.test_only_materialization_failpoint
                    == Some(
                        TestOnlyPrivateMaterializationFailpointV1::BeforeFirstEffectUidMapMismatch,
                    ) {
                    TestOnlyUserNamespaceMapMutationV1::UidMismatch
                } else {
                    TestOnlyUserNamespaceMapMutationV1::GidMismatch
                };
                bootstrap.test_only_materialization_failpoint = None;
                bootstrap
                    .transaction
                    .current_mount_namespace
                    .test_only_arm_next_user_namespace_map_mismatch(mutation);
            }
            #[cfg(test)]
            if bootstrap.test_only_materialization_failpoint
                == Some(
                    TestOnlyPrivateMaterializationFailpointV1::BeforeFirstEffectSupplementaryGroupsMismatch,
                )
            {
                bootstrap.test_only_materialization_failpoint = None;
                bootstrap
                    .transaction
                    .current_mount_namespace
                    .test_only_arm_next_supplementary_groups_mismatch();
            }
            #[cfg(test)]
            if matches!(
                bootstrap.test_only_materialization_failpoint,
                Some(
                    TestOnlyPrivateMaterializationFailpointV1::BeforeFirstEffectFsuidMismatch
                        | TestOnlyPrivateMaterializationFailpointV1::BeforeFirstEffectFsgidMismatch
                )
            ) {
                let mutation = if bootstrap.test_only_materialization_failpoint
                    == Some(
                        TestOnlyPrivateMaterializationFailpointV1::BeforeFirstEffectFsuidMismatch,
                    ) {
                    TestOnlyFilesystemCredentialMutationV1::Fsuid
                } else {
                    TestOnlyFilesystemCredentialMutationV1::Fsgid
                };
                bootstrap.test_only_materialization_failpoint = None;
                bootstrap
                    .transaction
                    .current_mount_namespace
                    .test_only_arm_next_filesystem_credential_mismatch(mutation);
            }
            bootstrap
                .transaction
                .current_mount_namespace
                .reauthenticate()?;
            validate_current_finalizer_effective_ids(
                &bootstrap.finalizer_effective_ids,
                FinalizerEffectiveIdsObservationMutationV1::Unchanged,
            )?;
            bootstrap.transaction.parent.reauthenticate()?;
            ensure_absent(
                bootstrap.transaction.parent.descriptor(),
                &bootstrap.staging_name,
                "reserved private OCI rootfs staging before retained projection validation",
            )?;
            bootstrap.transaction.revalidate_authenticated_projection(
                &bootstrap.canonical_live_operation_indices,
                bootstrap.counters,
                bootstrap.authenticated_logical_projection_sha256,
            )?;
            bootstrap.transaction.parent.reauthenticate()?;
            ensure_absent(
                bootstrap.transaction.parent.descriptor(),
                &bootstrap.staging_name,
                "reserved private OCI rootfs staging immediately before creation",
            )?;
            #[cfg(test)]
            let effective_ids_mutation =
                bootstrap.take_before_first_effect_finalizer_ids_observation_mutation();
            #[cfg(not(test))]
            let effective_ids_mutation = FinalizerEffectiveIdsObservationMutationV1::Unchanged;
            validate_current_finalizer_effective_ids(
                &bootstrap.finalizer_effective_ids,
                effective_ids_mutation,
            )?;
            bootstrap
                .transaction
                .current_mount_namespace
                .reauthenticate()?;
            #[cfg(test)]
            bootstrap.trigger_test_failpoint(
                TestOnlyPrivateMaterializationFailpointV1::ReadyBeforeStagingRootCreation,
            )?;
            Ok(())
        })();
        if let Err(primary) = pre_effect {
            return Err(bootstrap.fail_before_named_effect(primary));
        }

        if let Err(primary) = rustix::fs::mkdirat(
            bootstrap.transaction.parent.descriptor(),
            &bootstrap.staging_name,
            PRIVATE_MATERIALIZED_DIRECTORY_MODE,
        )
        .context("cannot create reserved private OCI rootfs staging")
        {
            return Err(bootstrap.fail_before_named_effect(primary));
        }
        // This assignment is the first instruction after the successful named
        // effect. No observation is allowed to fail before quarantine custody
        // records that the name exists without an authenticated identity.
        bootstrap.root_phase = StagingRootBootstrapPhaseV1::NamedUnidentified;
        #[cfg(test)]
        if let Err(primary) = bootstrap.trigger_test_failpoint(
            TestOnlyPrivateMaterializationFailpointV1::StagingRootNamedBeforePin,
        ) {
            return Err(anyhow::Error::new(
                PrivateOciRootfsCleanupFailureV1::quarantined_root(primary, bootstrap),
            ));
        }
        let staging_root = match rustix::fs::openat2(
            bootstrap.transaction.parent.descriptor(),
            &bootstrap.staging_name,
            PINNED_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
            MATERIALIZED_RESOLVE_FLAGS,
        )
        .context("cannot retain newly created private OCI rootfs staging")
        {
            Ok(descriptor) => descriptor,
            Err(primary) => {
                return Err(anyhow::Error::new(
                    PrivateOciRootfsCleanupFailureV1::quarantined_root(primary, bootstrap),
                ));
            }
        };
        let staging_root_observation = match bootstrap
            .transaction
            .current_mount_namespace
            .reauthenticate()
            .and_then(|()| directory_observation(staging_root.as_fd()))
        {
            Ok(observation) => observation,
            Err(primary) => {
                return Err(anyhow::Error::new(
                    PrivateOciRootfsCleanupFailureV1::quarantined_root(primary, bootstrap),
                ));
            }
        };

        let PrivateOciRootfsBootstrapCustodyV1 {
            transaction,
            finalizer_effective_ids,
            canonical_live_operation_indices,
            counters,
            authenticated_logical_projection_sha256,
            staging_name,
            root_expected_child_count,
            entries,
            directory_seal_order,
            root_phase,
            #[cfg(test)]
            test_only_materialization_failpoint,
        } = bootstrap;
        debug_assert!(root_phase == StagingRootBootstrapPhaseV1::NamedUnidentified);

        let mut materialized = AuthenticatedPrivateOciRootfsMaterializationV1 {
            transaction,
            finalizer_effective_ids,
            canonical_live_operation_indices,
            counters,
            authenticated_logical_projection_sha256,
            staging_name,
            staging_root,
            staging_root_identity: staging_root_observation.identity,
            staging_root_owner: staging_root_observation.owner,
            staging_root_group: staging_root_observation.group,
            root_expected_child_count,
            root_created_child_count: 0,
            entries,
            directory_seal_order,
            staging_root_sealed: false,
            cleanup_started: false,
            staging_root_unlinked: false,
            #[cfg(test)]
            test_only_materialization_failpoint,
            #[cfg(test)]
            test_only_cleanup_custody_mutation: Cell::new(None),
            #[cfg(test)]
            test_only_cleanup_failpoint: Cell::new(None),
            #[cfg(test)]
            test_only_runtime_metadata_seal_order: Vec::new(),
        };
        let named_result = materialized.finish_private_materialization();
        if let Err(primary) = named_result {
            return Err(materialized.fail_after_named_effect(primary));
        }
        Ok(materialized)
    }
}

impl AuthenticatedPrivateOciRootfsMaterializationV1 {
    fn finish_private_materialization(&mut self) -> Result<()> {
        #[cfg(test)]
        self.trigger_test_failpoint(
            TestOnlyPrivateMaterializationFailpointV1::StagingRootIdentityCaptured,
        )?;
        rustix::fs::fchmod(
            self.staging_root.as_fd(),
            PRIVATE_MATERIALIZED_DIRECTORY_MODE,
        )
        .context("cannot set private OCI rootfs staging mode")?;
        validate_private_staging_root(
            self.staging_root.as_fd(),
            self.staging_root_identity,
            self.staging_root_owner,
            self.staging_root_group,
            false,
            self.transaction.parent.identity().mount_id,
            0,
        )?;
        self.validate_initial_staging_root_mapped_owner_prerequisite()?;
        self.materialize_live_tree()?;
        self.seal_directories_deepest_first()?;
        self.seal_staging_root()?;
        self.validate_retained_tree(true)?;
        rustix::fs::fsync(self.staging_root.as_fd())
            .context("cannot synchronize private OCI rootfs staging")?;
        rustix::fs::fsync(self.transaction.parent.descriptor())
            .context("cannot synchronize private OCI rootfs staging parent")?;
        #[cfg(test)]
        let effective_ids_mutation =
            self.take_after_materialization_fsync_finalizer_ids_observation_mutation();
        #[cfg(not(test))]
        let effective_ids_mutation = FinalizerEffectiveIdsObservationMutationV1::Unchanged;
        validate_current_finalizer_effective_ids(
            &self.finalizer_effective_ids,
            effective_ids_mutation,
        )?;
        Ok(())
    }

    #[cfg(test)]
    fn take_after_materialization_fsync_finalizer_ids_observation_mutation(
        &mut self,
    ) -> FinalizerEffectiveIdsObservationMutationV1 {
        take_test_only_finalizer_effective_ids_observation_mutation(
            &mut self.test_only_materialization_failpoint,
            TestOnlyPrivateMaterializationFailpointV1::AfterMaterializationFsyncFinalizerEffectiveUidMismatch,
            TestOnlyPrivateMaterializationFailpointV1::AfterMaterializationFsyncFinalizerEffectiveGidMismatch,
        )
    }

    #[cfg(test)]
    fn inject_test_only_mapped_owner_mismatch(
        &mut self,
        owner_checkpoint: TestOnlyPrivateMaterializationFailpointV1,
        group_checkpoint: TestOnlyPrivateMaterializationFailpointV1,
        mapped_owner: &mut u64,
        mapped_group: &mut u64,
    ) {
        if self.test_only_materialization_failpoint == Some(owner_checkpoint) {
            self.test_only_materialization_failpoint = None;
            *mapped_owner = (*mapped_owner).wrapping_add(1);
        } else if self.test_only_materialization_failpoint == Some(group_checkpoint) {
            self.test_only_materialization_failpoint = None;
            *mapped_group = (*mapped_group).wrapping_add(1);
        }
    }

    fn validate_initial_staging_root_mapped_owner_prerequisite(&mut self) -> Result<()> {
        validate_current_finalizer_effective_ids(
            &self.finalizer_effective_ids,
            FinalizerEffectiveIdsObservationMutationV1::Unchanged,
        )?;
        #[cfg(not(test))]
        let (mapped_owner, mapped_group) = (self.staging_root_owner, self.staging_root_group);
        #[cfg(test)]
        let (mapped_owner, mapped_group) = {
            let mut mapped_owner = self.staging_root_owner;
            let mut mapped_group = self.staging_root_group;
            self.inject_test_only_mapped_owner_mismatch(
                TestOnlyPrivateMaterializationFailpointV1::StagingRootMappedOwnerMismatch,
                TestOnlyPrivateMaterializationFailpointV1::StagingRootMappedGroupMismatch,
                &mut mapped_owner,
                &mut mapped_group,
            );
            (mapped_owner, mapped_group)
        };
        validate_mapped_owner_prerequisite(
            mapped_owner,
            mapped_group,
            &self.finalizer_effective_ids,
            "private OCI rootfs staging root",
        )
    }

    fn validate_recorded_mapped_owner_prerequisite(&self) -> Result<()> {
        validate_current_finalizer_effective_ids(
            &self.finalizer_effective_ids,
            FinalizerEffectiveIdsObservationMutationV1::Unchanged,
        )?;
        validate_mapped_owner_prerequisite(
            self.staging_root_owner,
            self.staging_root_group,
            &self.finalizer_effective_ids,
            "private OCI rootfs staging root",
        )?;
        for entry in &self.entries {
            let (owner, group, label) = match &entry.phase {
                MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::Directory(
                    state,
                )) => (state.owner, state.group, "private OCI rootfs directory"),
                MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::Regular(state)) => {
                    (state.owner, state.group, "private OCI rootfs regular file")
                }
                MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::SymbolicLink(
                    state,
                )) => (state.owner, state.group, "private OCI rootfs symbolic link"),
                _ => anyhow::bail!(
                    "retained host-rootfs mapped-owner prerequisite has incomplete custody"
                ),
            };
            validate_mapped_owner_prerequisite(owner, group, &self.finalizer_effective_ids, label)?;
        }
        Ok(())
    }

    pub(super) fn authenticate_physical_rootfs_and_cleanup(
        self,
        expectation: &B4PositiveOciImageLayoutV1,
    ) -> Result<PrivateOciRootfsAbandonedV1> {
        Ok(self
            .authenticate_physical_rootfs_and_retain(expectation)?
            .cleanup()?)
    }

    pub(super) fn authenticate_physical_rootfs_and_retain(
        self,
        expectation: &B4PositiveOciImageLayoutV1,
    ) -> Result<AuthenticatedPrivateOciRetainedPhysicalRootfsV1> {
        let validation = self.authenticate_expected_rootfs_identity(expectation);
        match validation {
            Ok(static_startup_dependencies) => {
                Ok(AuthenticatedPrivateOciRetainedPhysicalRootfsV1 {
                    rootfs: self,
                    static_startup_dependencies,
                })
            }
            Err(primary) => Err(self.fail_after_named_effect(primary)),
        }
    }

    fn authenticate_expected_rootfs_identity(
        &self,
        expectation: &B4PositiveOciImageLayoutV1,
    ) -> Result<StaticStartupDependencyBaselinesV1> {
        let validation = (|| {
            self.validate_retained_tree(true)?;
            self.validate_live_entry_ordering()?;
            ensure!(
                self.transaction.role == expectation.role(),
                "physical OCI rootfs role differs from its positive gate"
            );
            self.authenticate_gate_rootfs_path_requirements(expectation)?;
            self.authenticate_expected_jvm_identity(expectation)
        })();
        merge_rootfs_revalidation(
            validation,
            self.validate_retained_tree(true),
            "private OCI rootfs revalidation also failed",
        )
    }

    fn authenticate_expected_jvm_identity(
        &self,
        expectation: &B4PositiveOciImageLayoutV1,
    ) -> Result<StaticStartupDependencyBaselinesV1> {
        let jvm_executables = expectation.jvm_executables();
        let jvm_release = expectation.jvm_release();
        match (self.transaction.role, jvm_executables, jvm_release) {
            (
                PositiveRunnerRole::RustValidatorBuild | PositiveRunnerRole::RustVerifier,
                None,
                None,
            ) => {}
            (PositiveRunnerRole::JvmValidatorBuild, Some(closure), Some(release)) => {
                ensure!(
                    closure.compiler().is_some(),
                    "JVM build rootfs omits its profile-bound compiler"
                );
                self.authenticate_java_release(release)?;
            }
            (PositiveRunnerRole::JvmVerifier, Some(closure), Some(release)) => {
                ensure!(
                    closure.compiler().is_none(),
                    "JVM verifier rootfs unexpectedly carries a compiler"
                );
                self.authenticate_java_release(release)?;
            }
            (
                PositiveRunnerRole::RustValidatorBuild | PositiveRunnerRole::RustVerifier,
                Some(_),
                _,
            ) => anyhow::bail!("Rust rootfs unexpectedly carries JVM executable identities"),
            (
                PositiveRunnerRole::RustValidatorBuild | PositiveRunnerRole::RustVerifier,
                None,
                Some(_),
            ) => anyhow::bail!("Rust rootfs unexpectedly carries a JVM release identity"),
            (PositiveRunnerRole::JvmValidatorBuild | PositiveRunnerRole::JvmVerifier, None, _) => {
                anyhow::bail!("JVM rootfs omits its profile-bound executable identities")
            }
            (PositiveRunnerRole::JvmValidatorBuild | PositiveRunnerRole::JvmVerifier, _, None) => {
                anyhow::bail!("JVM rootfs omits its profile-bound release identity")
            }
        }
        let launcher = jvm_executables
            .map(|_| {
                self.authenticate_static_startup_dependency_closure(
                    expectation,
                    GateRootedStartupExecutableV1::Launcher,
                )
            })
            .transpose()?;
        let compiler = jvm_executables
            .and_then(|closure| closure.compiler())
            .map(|_| {
                self.authenticate_static_startup_dependency_closure(
                    expectation,
                    GateRootedStartupExecutableV1::Compiler,
                )
            })
            .transpose()?;
        Ok(StaticStartupDependencyBaselinesV1 { launcher, compiler })
    }

    fn authenticate_gate_rootfs_path_requirements(
        &self,
        expectation: &B4PositiveOciImageLayoutV1,
    ) -> Result<()> {
        let mut requirements = Vec::with_capacity(expectation.rootfs_path_requirements().len());
        for requirement in expectation.rootfs_path_requirements() {
            ensure!(
                requirement.requires_directory() != requirement.requires_empty_regular(),
                "positive OCI rootfs path requirement has an ambiguous kind"
            );
            requirements.push((requirement.image_path(), requirement.requires_directory()));
        }
        self.authenticate_rootfs_path_requirements(&requirements)
    }

    fn authenticate_rootfs_path_requirements(&self, requirements: &[(&str, bool)]) -> Result<()> {
        let mut previous = None;
        for &(image_path, requires_directory) in requirements {
            if let Some(previous) = previous {
                ensure!(
                    previous < image_path,
                    "positive OCI rootfs path requirements are not strictly sorted"
                );
            }
            previous = Some(image_path);
            if requires_directory {
                self.authenticate_no_follow_directory_path(image_path)?;
            } else {
                self.authenticate_no_follow_empty_regular_path(image_path)?;
            }
        }
        self.authenticate_exact_dev_inventory(requirements)
    }

    fn authenticate_no_follow_directory_path(&self, absolute_path: &str) -> Result<()> {
        let components = canonical_rootfs_requirement_components(absolute_path)?;
        for end in 1..=components.len() {
            self.authenticate_exact_directory(&components[..end].join("/"))?;
        }
        Ok(())
    }

    fn authenticate_no_follow_empty_regular_path(&self, absolute_path: &str) -> Result<()> {
        let components = canonical_rootfs_requirement_components(absolute_path)?;
        for end in 1..components.len() {
            self.authenticate_exact_directory(&components[..end].join("/"))?;
        }
        self.authenticate_exact_empty_regular(&components.join("/"))
    }

    fn authenticate_exact_directory(&self, relative_path: &str) -> Result<()> {
        let position = self.live_entry_position(relative_path)?;
        let entry = self
            .entries
            .get(position)
            .context("required rootfs directory left the physical journal")?;
        let operation = self
            .transaction
            .operations
            .get(entry.operation_index)
            .context("required rootfs directory left the authenticated journal")?;
        let state = match (&operation.kind, &entry.phase) {
            (
                StagedRootfsOperationKindV1::Directory,
                MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::Directory(state)),
            ) => *state,
            _ => anyhow::bail!("required rootfs path is not a no-follow directory"),
        };
        ensure!(
            operation.mode == 0o555 && state.sealed,
            "required rootfs directory is not sealed mode 0555"
        );
        let descriptor = open_materialized_directory(self.staging_root.as_fd(), relative_path)?;
        validate_materialized_directory(
            descriptor.as_fd(),
            state.identity,
            state.owner,
            state.group,
            true,
            self.staging_root_identity.mount_id,
            entry.created_child_count,
        )
    }

    fn authenticate_exact_empty_regular(&self, relative_path: &str) -> Result<()> {
        let position = self.live_entry_position(relative_path)?;
        let entry = self
            .entries
            .get(position)
            .context("required rootfs placeholder left the physical journal")?;
        let operation = self
            .transaction
            .operations
            .get(entry.operation_index)
            .context("required rootfs placeholder left the authenticated journal")?;
        let (extent_index, state) = match (&operation.kind, &entry.phase) {
            (
                StagedRootfsOperationKindV1::Regular { extent_index },
                MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::Regular(state)),
            ) => (*extent_index, *state),
            _ => anyhow::bail!("required rootfs placeholder is not a regular file"),
        };
        ensure!(
            matches!(operation.mode, 0o444 | 0o555),
            "required rootfs placeholder has an unsupported mode"
        );
        let extent = self
            .transaction
            .physical_regular_extents
            .get(extent_index)
            .context("required rootfs placeholder left its authenticated extent")?;
        ensure!(
            extent.byte_length == 0,
            "required rootfs placeholder is not empty"
        );
        let descriptor = rustix::fs::openat2(
            self.staging_root.as_fd(),
            relative_path,
            PINNED_REGULAR_FLAGS,
            rustix::fs::Mode::empty(),
            MATERIALIZED_RESOLVE_FLAGS,
        )
        .with_context(|| format!("cannot open required rootfs placeholder {relative_path}"))?;
        let file = File::from(descriptor);
        validate_materialized_regular(
            &file,
            state.identity,
            state.owner,
            state.group,
            operation.mode,
            extent,
            self.staging_root_identity.mount_id,
        )
    }

    fn authenticate_exact_dev_inventory(&self, requirements: &[(&str, bool)]) -> Result<()> {
        const EXPECTED: [(&str, bool); 6] = [
            ("/dev", true),
            ("/dev/full", false),
            ("/dev/null", false),
            ("/dev/random", false),
            ("/dev/urandom", false),
            ("/dev/zero", false),
        ];
        let expected = requirements
            .iter()
            .copied()
            .filter(|(path, _)| *path == "/dev" || path.starts_with("/dev/"))
            .collect::<Vec<_>>();
        ensure!(
            expected == EXPECTED,
            "positive gate carries an unexpected rootfs /dev inventory"
        );
        let mut observed = Vec::new();
        for entry in &self.entries {
            let operation = self
                .transaction
                .operations
                .get(entry.operation_index)
                .context("rootfs /dev inventory left the authenticated journal")?;
            if operation.path == "dev" || operation.path.starts_with("dev/") {
                observed.push(operation.path.as_str());
            }
        }
        ensure!(
            observed
                == [
                    "dev",
                    "dev/full",
                    "dev/null",
                    "dev/random",
                    "dev/urandom",
                    "dev/zero",
                ],
            "rootfs /dev inventory differs from its positive gate"
        );
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn test_only_authenticate_rootfs_paths_and_cleanup(
        self,
        role: PositiveRunnerRole,
        requirements: &[(&str, bool)],
    ) -> Result<PrivateOciRootfsAbandonedV1> {
        let validation = (|| {
            self.validate_retained_tree(true)?;
            self.validate_live_entry_ordering()?;
            ensure!(
                self.transaction.role == role,
                "test rootfs role differs from its expectation"
            );
            self.authenticate_rootfs_path_requirements(requirements)
        })();
        let validation = merge_rootfs_revalidation(
            validation,
            self.validate_retained_tree(true),
            "private OCI rootfs test revalidation also failed",
        );
        match validation {
            Ok(()) => self.cleanup().map_err(anyhow::Error::new),
            Err(primary) => Err(self.fail_after_named_effect(primary)),
        }
    }

    #[cfg(test)]
    pub(super) fn test_only_authenticate_jvm_executables_and_cleanup(
        self,
        jvm_executables: Option<&B4PositiveJvmExecutableClosureV1>,
    ) -> Result<PrivateOciRootfsAbandonedV1> {
        let validation = (|| {
            self.validate_retained_tree(true)?;
            self.validate_live_entry_ordering()?;
            match (self.transaction.role, jvm_executables) {
                (
                    PositiveRunnerRole::RustValidatorBuild | PositiveRunnerRole::RustVerifier,
                    None,
                ) => {}
                (PositiveRunnerRole::JvmValidatorBuild, Some(closure)) => {
                    ensure!(
                        closure.compiler().is_some(),
                        "JVM build rootfs omits its profile-bound compiler"
                    );
                }
                (PositiveRunnerRole::JvmVerifier, Some(closure)) => {
                    ensure!(
                        closure.compiler().is_none(),
                        "JVM verifier rootfs unexpectedly carries a compiler"
                    );
                }
                (
                    PositiveRunnerRole::RustValidatorBuild | PositiveRunnerRole::RustVerifier,
                    Some(_),
                ) => {
                    anyhow::bail!("Rust rootfs unexpectedly carries JVM executable identities")
                }
                (PositiveRunnerRole::JvmValidatorBuild | PositiveRunnerRole::JvmVerifier, None) => {
                    anyhow::bail!("JVM rootfs omits its profile-bound executable identities")
                }
            }
            if let Some(closure) = jvm_executables {
                self.authenticate_runtime_elf(closure.launcher())?;
                if let Some(compiler) = closure.compiler() {
                    self.authenticate_runtime_elf(compiler)?;
                }
            }
            Ok(())
        })();
        let validation = merge_rootfs_revalidation(
            validation,
            self.validate_retained_tree(true),
            "private OCI rootfs test revalidation also failed",
        );
        match validation {
            Ok(()) => self.cleanup().map_err(anyhow::Error::new),
            Err(primary) => Err(self.fail_after_named_effect(primary)),
        }
    }

    fn authenticate_static_startup_dependency_closure(
        &self,
        expectation: &B4PositiveOciImageLayoutV1,
        executable: GateRootedStartupExecutableV1,
    ) -> Result<StaticStartupDependencyClosureV1> {
        let closure = expectation
            .jvm_executables()
            .context("gate-rooted startup closure omits JVM executable identities")?;
        let expected = match executable {
            GateRootedStartupExecutableV1::Launcher => closure.launcher(),
            GateRootedStartupExecutableV1::Compiler => closure
                .compiler()
                .context("gate-rooted startup closure omits its compiler")?,
        };
        ensure!(
            closure.startup_dependency_policy().policy_id() == STARTUP_DEPENDENCY_POLICY_ID,
            "rootfs startup dependency policy differs from its closed positive gate"
        );
        self.authenticate_startup_loader_exclusions()?;
        let rootfs_path_requirements = expectation.rootfs_path_requirements();
        let mut mount_targets = Vec::new();
        mount_targets
            .try_reserve_exact(rootfs_path_requirements.len())
            .context("cannot reserve gate-rooted runtime mount-target projection")?;
        for requirement in rootfs_path_requirements {
            if requirement.image_path() != "/dev" {
                mount_targets.push(requirement.image_path());
            }
        }
        let limits = startup_dependency_closure_limits_v1();
        let executable_resolution = self.resolve_startup_rootfs_regular_path(
            expected.image_path(),
            &mount_targets,
            "startup executable",
        )?;
        Self::authenticate_startup_resolution_antichain(
            &executable_resolution,
            &mount_targets,
            "startup executable",
        )?;
        let executable_byte_length = self.authenticated_regular_byte_length(
            &executable_resolution,
            &[0o555],
            "startup executable",
        )?;
        let mut counters = StaticStartupDependencyCountersV1::default();
        reserve_startup_object(
            limits,
            &mut counters,
            executable_byte_length,
            "startup executable",
        )?;
        let mut executable_linkage = None;
        self.with_authenticated_resolved_rootfs_regular_modes(
            &executable_resolution,
            &[0o555],
            |file, byte_length| {
                let bytes = read_complete_materialized_regular(
                    file,
                    byte_length,
                    "profile-bound startup executable",
                )?;
                with_gate_bound_runtime_amd64_elf(
                    &bytes,
                    expected,
                    |interpreter_path, common, dynamic| {
                        executable_linkage = Some((
                            interpreter_path.to_owned(),
                            own_startup_elf_projection(common),
                            own_startup_dynamic_projection(dynamic)?,
                        ));
                        Ok(())
                    },
                )
            },
        )?;
        let (interpreter_path, executable_elf, executable_dynamic) = executable_linkage
            .context("startup executable inspection omitted its closed dynamic projection")?;
        ensure!(
            executable_dynamic.soname.is_none(),
            "startup executable unexpectedly carries DT_SONAME"
        );
        validate_owned_startup_dynamic_for_resolution(&executable_resolution, &executable_dynamic)?;
        let executable = StaticStartupDependencyNodeV1 {
            resolution: executable_resolution,
            byte_length: executable_byte_length,
            sha256: expected.sha256(),
            elf: executable_elf,
            dynamic: executable_dynamic,
            depth: 0,
        };
        self.derive_static_startup_dependency_closure(
            executable,
            interpreter_path.as_str(),
            &mount_targets,
            limits,
            counters,
        )
    }

    #[cfg(test)]
    fn authenticate_test_static_startup_dependency_closure(
        &self,
        image_path: &str,
        mount_targets: &[&str],
    ) -> Result<StaticStartupDependencyClosureV1> {
        self.authenticate_startup_loader_exclusions()?;
        let limits = startup_dependency_closure_limits_v1();
        let executable_resolution = self.resolve_startup_rootfs_regular_path(
            image_path,
            mount_targets,
            "test startup executable",
        )?;
        Self::authenticate_startup_resolution_antichain(
            &executable_resolution,
            mount_targets,
            "test startup executable",
        )?;
        let executable_byte_length = self.authenticated_regular_byte_length(
            &executable_resolution,
            &[0o555],
            "test startup executable",
        )?;
        let mut counters = StaticStartupDependencyCountersV1::default();
        reserve_startup_object(
            limits,
            &mut counters,
            executable_byte_length,
            "test startup executable",
        )?;
        let mut executable_linkage = None;
        let mut executable_sha256 = None;
        self.with_authenticated_resolved_rootfs_regular_modes(
            &executable_resolution,
            &[0o555],
            |file, byte_length| {
                let bytes = read_complete_materialized_regular(
                    file,
                    byte_length,
                    "test startup executable",
                )?;
                executable_sha256 = Some(Sha256::digest(&bytes).into());
                crate::b4_campaign_executor::amd64_elf_inspection::with_test_inspected_runtime_amd64_elf(
                    &bytes,
                    |interpreter_path, common, dynamic| {
                        executable_linkage = Some((
                            interpreter_path.to_owned(),
                            own_startup_elf_projection(common),
                            own_startup_dynamic_projection(dynamic)?,
                        ));
                        Ok(())
                    },
                )
            },
        )?;
        let (interpreter_path, executable_elf, executable_dynamic) = executable_linkage
            .context("test startup executable omitted its closed dynamic projection")?;
        ensure!(
            executable_dynamic.soname.is_none(),
            "test startup executable unexpectedly carries DT_SONAME"
        );
        validate_owned_startup_dynamic_for_resolution(&executable_resolution, &executable_dynamic)?;
        let executable = StaticStartupDependencyNodeV1 {
            resolution: executable_resolution,
            byte_length: executable_byte_length,
            sha256: executable_sha256.context("test startup executable omitted its digest")?,
            elf: executable_elf,
            dynamic: executable_dynamic,
            depth: 0,
        };
        self.derive_static_startup_dependency_closure(
            executable,
            interpreter_path.as_str(),
            mount_targets,
            limits,
            counters,
        )
    }

    fn derive_static_startup_dependency_closure(
        &self,
        executable: StaticStartupDependencyNodeV1,
        interpreter_path: &str,
        mount_targets: &[&str],
        limits: StartupDependencyClosureLimitsV1,
        mut counters: StaticStartupDependencyCountersV1,
    ) -> Result<StaticStartupDependencyClosureV1> {
        let interpreter = self.inspect_static_startup_interpreter(
            interpreter_path,
            mount_targets,
            limits,
            &mut counters,
        )?;
        let mut state = Self::initialize_static_startup_dependency_derivation(
            executable,
            interpreter,
            limits,
            counters,
        )?;
        self.complete_static_startup_dependency_derivation(&mut state, mount_targets, limits)?;
        Self::finish_static_startup_dependency_derivation(state)
    }

    fn inspect_static_startup_interpreter(
        &self,
        interpreter_path: &str,
        mount_targets: &[&str],
        limits: StartupDependencyClosureLimitsV1,
        counters: &mut StaticStartupDependencyCountersV1,
    ) -> Result<StaticStartupDependencyNodeV1> {
        limits.checked_add_distinct_objects(counters.distinct_objects, 1, "startup interpreter")?;
        let interpreter_basename = canonical_rootfs_basename(interpreter_path)?;
        limits.validate_dynamic_basename_bytes(
            u64::try_from(interpreter_basename.len())?,
            "startup interpreter",
        )?;
        let interpreter_resolution = self.resolve_startup_rootfs_regular_path(
            interpreter_path,
            mount_targets,
            "startup interpreter",
        )?;
        Self::authenticate_startup_resolution_antichain(
            &interpreter_resolution,
            mount_targets,
            "startup interpreter",
        )?;
        self.inspect_startup_dependency_dso(
            StartupDependencyDsoInspectionV1 {
                resolution: interpreter_resolution,
                selected_basename: interpreter_basename,
                required_modes: &[0o555],
                depth: 0,
                limits,
                label: "startup interpreter",
            },
            counters,
        )
    }

    fn initialize_static_startup_dependency_derivation(
        executable: StaticStartupDependencyNodeV1,
        interpreter: StaticStartupDependencyNodeV1,
        limits: StartupDependencyClosureLimitsV1,
        counters: StaticStartupDependencyCountersV1,
    ) -> Result<StaticStartupDependencyDerivationStateV1> {
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(usize::try_from(limits.maximum_distinct_objects())?)
            .context("cannot reserve bounded startup node vector")?;
        nodes.extend([executable, interpreter]);
        let mut loaded_soname_nodes = Vec::new();
        loaded_soname_nodes
            .try_reserve_exact(usize::try_from(limits.maximum_distinct_objects())?)
            .context("cannot reserve bounded loaded-SONAME table")?;
        loaded_soname_nodes.push(1_usize);
        let mut edges = Vec::new();
        edges
            .try_reserve_exact(usize::try_from(limits.maximum_dependency_edges())?)
            .context("cannot reserve bounded startup edge vector")?;
        let mut queue = VecDeque::new();
        queue
            .try_reserve_exact(usize::try_from(limits.maximum_distinct_objects())?)
            .context("cannot reserve bounded startup FIFO")?;
        queue.extend([0_usize, 1_usize]);

        Ok(StaticStartupDependencyDerivationStateV1 {
            nodes,
            loaded_soname_nodes,
            edges,
            queue,
            counters,
        })
    }

    fn complete_static_startup_dependency_derivation(
        &self,
        state: &mut StaticStartupDependencyDerivationStateV1,
        mount_targets: &[&str],
        limits: StartupDependencyClosureLimitsV1,
    ) -> Result<()> {
        let mut basename_index = None;

        while let Some(requester_index) = state.queue.pop_front() {
            let needed_count = state
                .nodes
                .get(requester_index)
                .context("startup dependency queue left its node vector")?
                .dynamic
                .needed_libraries
                .len();
            for needed_index in 0..needed_count {
                self.append_static_startup_dependency_request(
                    state,
                    requester_index,
                    needed_index,
                    mount_targets,
                    limits,
                    &mut basename_index,
                )?;
            }
        }
        Ok(())
    }

    fn append_static_startup_dependency_request<'a>(
        &'a self,
        state: &mut StaticStartupDependencyDerivationStateV1,
        requester_index: usize,
        needed_index: usize,
        mount_targets: &[&str],
        limits: StartupDependencyClosureLimitsV1,
        basename_index: &mut Option<Vec<(&'a str, usize)>>,
    ) -> Result<()> {
        let (dynamic_ordinal, requested_name) = {
            let needed = state
                .nodes
                .get(requester_index)
                .and_then(|requester| requester.dynamic.needed_libraries.get(needed_index))
                .context("startup dependency request left its node projection")?;
            (
                needed.dynamic_ordinal,
                try_owned_startup_string(needed.requested_name.as_str(), "dependency edge name")?,
            )
        };
        state.counters.dependency_edges = limits.checked_add_dependency_edges(
            state.counters.dependency_edges,
            1,
            "static startup dependency closure",
        )?;
        let loaded_selection = state.loaded_soname_nodes.iter().copied().find(|selected| {
            state
                .nodes
                .get(*selected)
                .and_then(|node| node.dynamic.soname.as_deref())
                == Some(requested_name.as_str())
        });
        if let Some(selected) = loaded_selection {
            state.edges.push(StaticStartupDependencyEdgeV1 {
                requester: requester_index,
                dynamic_ordinal,
                requested_name,
                resolution_kind: StaticStartupDependencyResolutionKindV1::LoadedSoname,
                selected,
            });
            return Ok(());
        }

        let dependency_depth = state.nodes[requester_index]
            .depth
            .checked_add(1)
            .context("startup dependency depth overflowed")?;
        limits.validate_depth(dependency_depth, "static startup dependency closure")?;
        limits.checked_add_distinct_objects(
            state.counters.distinct_objects,
            1,
            "static startup dependency closure",
        )?;
        if basename_index.is_none() {
            *basename_index = Some(self.build_startup_basename_index()?);
        }
        let basename_index = basename_index
            .as_deref()
            .expect("startup basename index was just constructed");
        let selected_resolution = self.resolve_startup_dependency_search(
            &state.nodes[requester_index],
            requested_name.as_str(),
            mount_targets,
            basename_index,
        )?;
        let selected_node = self.inspect_startup_dependency_dso(
            StartupDependencyDsoInspectionV1 {
                resolution: selected_resolution,
                selected_basename: requested_name.as_str(),
                required_modes: &[0o444, 0o555],
                depth: dependency_depth,
                limits,
                label: "selected startup dependency",
            },
            &mut state.counters,
        )?;
        let selected = state.nodes.len();
        ensure!(
            state.loaded_soname_nodes.iter().all(|loaded| {
                state
                    .nodes
                    .get(*loaded)
                    .and_then(|node| node.dynamic.soname.as_deref())
                    != Some(requested_name.as_str())
            }),
            "two distinct startup nodes carry the same SONAME"
        );
        state.nodes.push(selected_node);
        state.loaded_soname_nodes.push(selected);
        state.edges.push(StaticStartupDependencyEdgeV1 {
            requester: requester_index,
            dynamic_ordinal,
            requested_name,
            resolution_kind: StaticStartupDependencyResolutionKindV1::RootfsSearch,
            selected,
        });
        state.queue.push_back(selected);
        Ok(())
    }

    fn finish_static_startup_dependency_derivation(
        state: StaticStartupDependencyDerivationStateV1,
    ) -> Result<StaticStartupDependencyClosureV1> {
        ensure!(
            u64::try_from(state.nodes.len())? == state.counters.distinct_objects
                && u64::try_from(state.edges.len())? == state.counters.dependency_edges
                && state
                    .nodes
                    .iter()
                    .try_fold(0_u64, |sum, node| sum.checked_add(node.byte_length))
                    == Some(state.counters.aggregate_distinct_object_bytes),
            "static startup dependency closure counters differ from their ordered result"
        );
        let closure = StaticStartupDependencyClosureV1 {
            nodes: state.nodes,
            edges: state.edges,
        };
        validate_static_startup_dependency_closure_identity(&closure)?;
        Ok(closure)
    }

    fn inspect_startup_dependency_dso(
        &self,
        inspection: StartupDependencyDsoInspectionV1<'_>,
        counters: &mut StaticStartupDependencyCountersV1,
    ) -> Result<StaticStartupDependencyNodeV1> {
        let StartupDependencyDsoInspectionV1 {
            resolution,
            selected_basename,
            required_modes,
            depth,
            limits,
            label,
        } = inspection;
        let byte_length =
            self.authenticated_regular_byte_length(&resolution, required_modes, label)?;
        reserve_startup_object(limits, counters, byte_length, label)?;
        let mut inspected_projection = None;
        self.with_authenticated_resolved_rootfs_regular_modes(
            &resolution,
            required_modes,
            |file, authenticated_byte_length| {
                let bytes =
                    read_complete_materialized_regular(file, authenticated_byte_length, label)?;
                with_inspected_startup_dependency_amd64_dso(&bytes, |inspected| {
                    ensure!(
                        inspected.soname() == selected_basename,
                        "selected startup DSO SONAME differs from its requested basename"
                    );
                    inspected_projection = Some((
                        inspected.sha256(),
                        own_startup_elf_projection(inspected.common()),
                        own_startup_dynamic_projection(inspected.dynamic())?,
                    ));
                    Ok(())
                })
            },
        )?;
        let (sha256, elf, dynamic) = inspected_projection
            .context("startup DSO inspection omitted its closed dynamic projection")?;
        validate_owned_startup_dynamic_for_resolution(&resolution, &dynamic)?;
        Ok(StaticStartupDependencyNodeV1 {
            resolution,
            byte_length,
            sha256,
            elf,
            dynamic,
            depth,
        })
    }

    fn resolve_startup_dependency_search(
        &self,
        requester: &StaticStartupDependencyNodeV1,
        requested_name: &str,
        mount_targets: &[&str],
        basename_index: &[(&str, usize)],
    ) -> Result<ResolvedRootfsPathV1> {
        let limits = startup_dependency_closure_limits_v1();
        limits.validate_dynamic_basename_bytes(
            u64::try_from(requested_name.len())?,
            "startup dependency request",
        )?;
        let search_directories = expanded_startup_search_directories(requester)?;
        let mut resolved_directories = Vec::new();
        resolved_directories
            .try_reserve_exact(search_directories.len())
            .context("cannot retain bounded startup search directories")?;
        for directory in &search_directories {
            let resolved = self.resolve_startup_rootfs_directory_path(
                directory,
                mount_targets,
                "startup search directory",
            )?;
            self.authenticate_resolved_rootfs_directory(&resolved)?;
            Self::authenticate_startup_resolution_antichain(
                &resolved,
                mount_targets,
                "startup search directory",
            )?;
            resolved_directories.push(resolved);
        }

        let range_start =
            basename_index.partition_point(|(basename, _)| *basename < requested_name);
        let range_end = basename_index.partition_point(|(basename, _)| *basename <= requested_name);
        let basename_count = range_end - range_start;
        ensure!(
            basename_count == 1,
            "unresolved DT_NEEDED {requested_name}: expected one rootfs basename, observed {}",
            basename_count
        );
        let unique_position = basename_index[range_start].1;
        let unique_entry = self
            .entries
            .get(unique_position)
            .context("unique startup dependency left the physical journal")?;
        let unique_operation = self
            .transaction
            .operations
            .get(unique_entry.operation_index)
            .context("unique startup dependency left the authenticated journal")?;
        let actual_parent = unique_operation
            .path
            .rsplit_once('/')
            .map_or("/", |(parent, _)| parent);
        let actual_parent = if actual_parent == "/" {
            "/".to_owned()
        } else {
            format!("/{actual_parent}")
        };
        let selected_directory = resolved_directories
            .iter()
            .position(|directory| directory.final_path == actual_parent)
            .context(format!(
                "unresolved DT_NEEDED {requested_name}: unique basename is outside the closed search directories"
            ))?;
        let textual_directory = &search_directories[selected_directory];
        let canonical_path = if textual_directory == "/" {
            format!("/{requested_name}")
        } else {
            format!("{textual_directory}/{requested_name}")
        };
        let selected = self.resolve_startup_rootfs_regular_path(
            &canonical_path,
            mount_targets,
            "selected startup dependency",
        )?;
        Self::authenticate_startup_resolution_antichain(
            &selected,
            mount_targets,
            "selected startup dependency",
        )?;
        Ok(selected)
    }

    fn authenticate_startup_loader_exclusions(&self) -> Result<()> {
        for path in ["/etc/ld.so.cache", "/etc/ld.so.preload"] {
            ensure!(
                !self.authenticated_rootfs_visible_leaf_exists(path)?,
                "startup rootfs contains forbidden loader path {path}"
            );
        }
        for entry in &self.entries {
            let operation = self
                .transaction
                .operations
                .get(entry.operation_index)
                .context("startup exclusion scan left the authenticated journal")?;
            ensure!(
                operation.path.rsplit('/').next() != Some("glibc-hwcaps"),
                "startup rootfs contains forbidden glibc-hwcaps basename"
            );
        }
        Ok(())
    }

    fn authenticate_startup_resolution_antichain(
        resolution: &ResolvedRootfsPathV1,
        mount_targets: &[&str],
        label: &str,
    ) -> Result<()> {
        for path in std::iter::once(resolution.canonical_path.as_str())
            .chain(resolution.symbolic_link_chain.iter().flat_map(|hop| {
                [
                    hop.canonical_link_path.as_str(),
                    hop.normalized_target_path.as_str(),
                ]
            }))
            .chain(std::iter::once(resolution.final_path.as_str()))
        {
            for mount_target in mount_targets {
                ensure!(
                    !component_paths_overlap(path, mount_target),
                    "{label} path {path} overlaps runtime mount target {mount_target}"
                );
            }
        }
        Ok(())
    }

    fn build_startup_basename_index(&self) -> Result<Vec<(&str, usize)>> {
        let mut index = Vec::new();
        index
            .try_reserve_exact(self.entries.len())
            .context("cannot reserve bounded startup basename index")?;
        for (position, entry) in self.entries.iter().enumerate() {
            let operation = self
                .transaction
                .operations
                .get(entry.operation_index)
                .context("startup basename scan left the authenticated journal")?;
            let basename = operation
                .path
                .rsplit('/')
                .next()
                .context("startup journal path has no basename")?;
            index.push((basename, position));
        }
        index.sort_unstable_by(|left, right| left.0.cmp(right.0).then(left.1.cmp(&right.1)));
        Ok(index)
    }

    #[cfg(test)]
    pub(super) fn test_only_authenticate_startup_dependency_closure_and_cleanup(
        self,
        expectation: &StartupClosureTestExpectationV1<'_>,
    ) -> Result<PrivateOciRootfsAbandonedV1> {
        Ok(self
            .test_only_authenticate_startup_dependency_closure_and_retain(expectation)?
            .cleanup()?)
    }

    #[cfg(test)]
    pub(super) fn test_only_authenticate_startup_dependency_closure_and_retain(
        self,
        expectation: &StartupClosureTestExpectationV1<'_>,
    ) -> Result<AuthenticatedPrivateOciRetainedPhysicalRootfsV1> {
        let validation = self.authenticate_test_static_startup_dependency_identity(expectation);
        match validation {
            Ok(static_startup_dependencies) => {
                Ok(AuthenticatedPrivateOciRetainedPhysicalRootfsV1 {
                    rootfs: self,
                    static_startup_dependencies,
                })
            }
            Err(primary) => Err(self.fail_after_named_effect(primary)),
        }
    }

    #[cfg(test)]
    fn authenticate_test_static_startup_dependency_identity(
        &self,
        expectation: &StartupClosureTestExpectationV1<'_>,
    ) -> Result<StaticStartupDependencyBaselinesV1> {
        let validation = (|| {
            self.validate_retained_tree(true)?;
            self.validate_live_entry_ordering()?;
            self.authenticate_test_static_startup_dependency_baselines(expectation)
        })();
        merge_rootfs_revalidation(
            validation,
            self.validate_retained_tree(true),
            "private OCI rootfs startup-closure revalidation also failed",
        )
    }

    #[cfg(test)]
    fn authenticate_test_static_startup_dependency_baselines(
        &self,
        expectation: &StartupClosureTestExpectationV1<'_>,
    ) -> Result<StaticStartupDependencyBaselinesV1> {
        ensure!(
            expectation.additional_independent_image_paths.len() <= 1,
            "test startup dependency baseline has more than one compiler closure"
        );
        let launcher = self.authenticate_test_static_startup_dependency_closure(
            expectation.image_path,
            expectation.mount_targets,
        )?;
        Self::validate_test_static_startup_dependency_expectation(&launcher, expectation)?;
        let compiler = expectation
            .additional_independent_image_paths
            .first()
            .map(|image_path| {
                self.authenticate_test_static_startup_dependency_closure(
                    image_path,
                    expectation.mount_targets,
                )
            })
            .transpose()?;
        Ok(StaticStartupDependencyBaselinesV1 {
            launcher: Some(launcher),
            compiler,
        })
    }

    #[cfg(test)]
    fn validate_test_static_startup_dependency_expectation(
        closure: &StaticStartupDependencyClosureV1,
        expectation: &StartupClosureTestExpectationV1<'_>,
    ) -> Result<()> {
        if let Some(expected) = expectation.expected_canonical_node_order {
            ensure!(
                closure
                    .nodes
                    .iter()
                    .map(|node| node.resolution.canonical_path.as_str())
                    .eq(expected.iter().copied()),
                "test startup dependency node order differs from FIFO expectation"
            );
        }
        if let Some(expected) = expectation.expected_edges {
            ensure!(
                closure.edges.len() == expected.len()
                    && closure.edges.iter().zip(expected).all(|(edge, expected)| {
                        let resolution_kind = match edge.resolution_kind {
                            StaticStartupDependencyResolutionKindV1::LoadedSoname => {
                                "loaded-soname"
                            }
                            StaticStartupDependencyResolutionKindV1::RootfsSearch => {
                                "rootfs-search"
                            }
                        };
                        edge.requester == expected.0
                            && edge.dynamic_ordinal == expected.1
                            && edge.requested_name == expected.2
                            && resolution_kind == expected.3
                            && edge.selected == expected.4
                            && closure
                                .nodes
                                .get(edge.selected)
                                .is_some_and(|node| node.depth == expected.5)
                    }),
                "test startup dependency edges differ from their exact expectation"
            );
        }
        if let Some(expected) = expectation.expected_aggregate_distinct_object_bytes {
            let observed = closure.nodes.iter().try_fold(0_u64, |sum, node| {
                sum.checked_add(node.byte_length)
                    .context("test startup dependency byte sum overflowed")
            })?;
            ensure!(
                observed == expected,
                "test startup dependency aggregate byte count differs from expectation"
            );
        }
        if let Some(expected) = expectation.expected_root_entry_point_is_zero {
            ensure!(
                closure
                    .nodes
                    .first()
                    .is_some_and(|node| node.elf.entry_point_is_zero == expected),
                "test startup executable entry-zero identity differs from expectation"
            );
        }
        Ok(())
    }

    fn authenticate_runtime_elf(&self, expected: &B4PositiveRuntimeElfIdentityV1) -> Result<()> {
        self.with_authenticated_rootfs_regular(expected.image_path(), 0o555, |file, byte_length| {
            ensure!(
                byte_length == expected.byte_length(),
                "rootfs runtime ELF length differs from its positive gate"
            );
            let bytes = read_complete_materialized_regular(
                file,
                byte_length,
                "profile-bound rootfs runtime ELF",
            )?;
            with_gate_bound_runtime_amd64_elf(
                &bytes,
                expected,
                |interpreter_path, _common, _dynamic| {
                    self.with_authenticated_rootfs_regular(
                        interpreter_path,
                        0o555,
                        |_interpreter, _byte_length| Ok(()),
                    )
                },
            )
        })
    }

    fn authenticate_java_release(&self, expected: &B4PositiveJvmReleaseIdentityV1) -> Result<()> {
        self.authenticate_java_release_fields(
            expected.image_path(),
            expected.byte_length(),
            expected.sha256(),
            expected.feature_version(),
            expected.vendor(),
            expected.version(),
        )
    }

    fn authenticate_java_release_fields(
        &self,
        image_path: &str,
        expected_byte_length: u64,
        expected_sha256: [u8; SHA256_BYTES],
        feature_version: u64,
        expected_vendor: &str,
        expected_version: &str,
    ) -> Result<()> {
        ensure!(
            (1..=65_536).contains(&expected_byte_length),
            "Java release length is outside its closed bound"
        );
        self.with_authenticated_rootfs_regular_modes(
            image_path,
            &[0o444, 0o555],
            |file, byte_length| {
                ensure!(
                    byte_length == expected_byte_length,
                    "Java release length differs from its positive gate"
                );
                let bytes = read_complete_materialized_regular(
                    file,
                    byte_length,
                    "profile-bound Java release file",
                )?;
                let digest: [u8; SHA256_BYTES] = Sha256::digest(&bytes).into();
                ensure!(
                    digest == expected_sha256,
                    "Java release digest differs from its positive gate"
                );
                validate_openjdk_release_file(
                    &bytes,
                    feature_version,
                    expected_vendor,
                    expected_version,
                )
            },
        )
    }

    #[cfg(test)]
    #[allow(
        clippy::too_many_arguments,
        reason = "test-only seam isolates every gate-bound Java release field"
    )]
    pub(super) fn test_only_authenticate_java_release_and_cleanup(
        self,
        role: PositiveRunnerRole,
        image_path: &str,
        expected_byte_length: u64,
        expected_sha256: [u8; SHA256_BYTES],
        feature_version: u64,
        expected_vendor: &str,
        expected_version: &str,
    ) -> Result<PrivateOciRootfsAbandonedV1> {
        let validation = (|| {
            self.validate_retained_tree(true)?;
            self.validate_live_entry_ordering()?;
            ensure!(
                self.transaction.role == role
                    && matches!(
                        role,
                        PositiveRunnerRole::JvmValidatorBuild | PositiveRunnerRole::JvmVerifier
                    ),
                "test Java release expectation has a non-JVM or mismatched role"
            );
            self.authenticate_java_release_fields(
                image_path,
                expected_byte_length,
                expected_sha256,
                feature_version,
                expected_vendor,
                expected_version,
            )
        })();
        let validation = merge_rootfs_revalidation(
            validation,
            self.validate_retained_tree(true),
            "private OCI rootfs test revalidation also failed",
        );
        match validation {
            Ok(()) => self.cleanup().map_err(anyhow::Error::new),
            Err(primary) => Err(self.fail_after_named_effect(primary)),
        }
    }

    #[cfg(test)]
    pub(super) fn test_only_authenticate_runtime_elf(&self, image_path: &str) -> Result<()> {
        let validation = (|| {
            self.validate_retained_tree(true)?;
            self.validate_live_entry_ordering()?;
            self.with_authenticated_rootfs_regular(
                image_path,
                0o555,
                |file, byte_length| {
                    let bytes = read_complete_materialized_regular(
                        file,
                        byte_length,
                        "test rootfs runtime ELF",
                    )?;
                    crate::b4_campaign_executor::amd64_elf_inspection::with_test_inspected_runtime_amd64_elf(
                        &bytes,
                        |interpreter_path, _common, _dynamic| {
                            self.with_authenticated_rootfs_regular(
                                interpreter_path,
                                0o555,
                                |_interpreter, _byte_length| Ok(()),
                            )
                        },
                    )
                },
            )
        })();
        let revalidation = self.validate_retained_tree(true);
        match (validation, revalidation) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(primary), Ok(())) => Err(primary),
            (Ok(()), Err(revalidation)) => Err(revalidation),
            (Err(primary), Err(revalidation)) => Err(primary.context(format!(
                "private OCI rootfs test revalidation also failed: {revalidation:#}"
            ))),
        }
    }

    fn with_authenticated_rootfs_regular(
        &self,
        absolute_path: &str,
        required_mode: u32,
        effect: impl FnOnce(&File, u64) -> Result<()>,
    ) -> Result<()> {
        self.with_authenticated_rootfs_regular_modes(absolute_path, &[required_mode], effect)
    }

    fn with_authenticated_rootfs_regular_modes(
        &self,
        absolute_path: &str,
        required_modes: &[u32],
        effect: impl FnOnce(&File, u64) -> Result<()>,
    ) -> Result<()> {
        let resolution = self.resolve_authenticated_rootfs_regular_path(absolute_path)?;
        self.with_authenticated_resolved_rootfs_regular_modes(&resolution, required_modes, effect)
    }

    fn authenticated_regular_byte_length(
        &self,
        resolution: &ResolvedRootfsPathV1,
        required_modes: &[u32],
        label: &str,
    ) -> Result<u64> {
        let position = resolution
            .position
            .context("resolved rootfs regular unexpectedly names the implicit root")?;
        let entry = self
            .entries
            .get(position)
            .context("resolved rootfs entry left the physical journal")?;
        let operation = self
            .transaction
            .operations
            .get(entry.operation_index)
            .context("resolved rootfs entry left the authenticated journal")?;
        let extent_index = match (&operation.kind, &entry.phase) {
            (
                StagedRootfsOperationKindV1::Regular { extent_index },
                MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::Regular(_)),
            ) => *extent_index,
            _ => anyhow::bail!("resolved authenticated rootfs target is not a regular file"),
        };
        ensure!(
            required_modes.contains(&operation.mode),
            "resolved authenticated rootfs regular mode differs from its bound use: {label}"
        );
        let extent = self
            .transaction
            .physical_regular_extents
            .get(extent_index)
            .context("resolved rootfs regular left its authenticated extent")?;
        ensure!(
            resolution.final_path == format!("/{}", operation.path),
            "resolved rootfs regular final path differs from its journal position"
        );
        Ok(extent.byte_length)
    }

    fn with_authenticated_resolved_rootfs_regular_modes(
        &self,
        resolution: &ResolvedRootfsPathV1,
        required_modes: &[u32],
        effect: impl FnOnce(&File, u64) -> Result<()>,
    ) -> Result<()> {
        let position = resolution
            .position
            .context("resolved rootfs regular unexpectedly names the implicit root")?;
        let entry = self
            .entries
            .get(position)
            .context("resolved rootfs entry left the physical journal")?;
        let operation = self
            .transaction
            .operations
            .get(entry.operation_index)
            .context("resolved rootfs entry left the authenticated journal")?;
        let (extent_index, state) = match (&operation.kind, &entry.phase) {
            (
                StagedRootfsOperationKindV1::Regular { extent_index },
                MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::Regular(state)),
            ) => (*extent_index, *state),
            _ => anyhow::bail!("resolved authenticated rootfs target is not a regular file"),
        };
        ensure!(
            required_modes.contains(&operation.mode),
            "resolved authenticated rootfs regular mode differs from its bound use"
        );
        let extent = self
            .transaction
            .physical_regular_extents
            .get(extent_index)
            .context("resolved rootfs regular left its authenticated extent")?;
        ensure!(
            resolution.final_path == format!("/{}", operation.path),
            "resolved rootfs regular final path differs from its journal position"
        );
        let descriptor = rustix::fs::openat2(
            self.staging_root.as_fd(),
            operation.path.as_str(),
            PINNED_REGULAR_FLAGS,
            rustix::fs::Mode::empty(),
            MATERIALIZED_RESOLVE_FLAGS,
        )
        .with_context(|| {
            format!(
                "cannot open resolved authenticated rootfs regular {}",
                operation.path
            )
        })?;
        let file = File::from(descriptor);
        validate_materialized_regular(
            &file,
            state.identity,
            state.owner,
            state.group,
            operation.mode,
            extent,
            self.staging_root_identity.mount_id,
        )?;
        let effect_result = effect(&file, extent.byte_length);
        let revalidation = validate_materialized_regular(
            &file,
            state.identity,
            state.owner,
            state.group,
            operation.mode,
            extent,
            self.staging_root_identity.mount_id,
        );
        match (effect_result, revalidation) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(primary), Ok(())) => Err(primary),
            (Ok(()), Err(revalidation)) => Err(revalidation),
            (Err(primary), Err(revalidation)) => Err(primary.context(format!(
                "resolved authenticated rootfs regular revalidation also failed: {revalidation:#}"
            ))),
        }
    }

    fn resolve_authenticated_rootfs_regular(&self, absolute_path: &str) -> Result<usize> {
        self.resolve_authenticated_rootfs_regular_path(absolute_path)?
            .position
            .context("resolved rootfs regular unexpectedly names the implicit root")
    }

    fn resolve_authenticated_rootfs_regular_path(
        &self,
        absolute_path: &str,
    ) -> Result<ResolvedRootfsPathV1> {
        self.resolve_authenticated_rootfs_path(
            absolute_path,
            RootfsResolutionFinalKindV1::Regular,
            None,
        )
    }

    fn resolve_startup_rootfs_regular_path(
        &self,
        absolute_path: &str,
        mount_targets: &[&str],
        label: &str,
    ) -> Result<ResolvedRootfsPathV1> {
        self.resolve_authenticated_rootfs_path(
            absolute_path,
            RootfsResolutionFinalKindV1::Regular,
            Some((mount_targets, label)),
        )
    }

    fn resolve_startup_rootfs_directory_path(
        &self,
        absolute_path: &str,
        mount_targets: &[&str],
        label: &str,
    ) -> Result<ResolvedRootfsPathV1> {
        self.resolve_authenticated_rootfs_path(
            absolute_path,
            RootfsResolutionFinalKindV1::Directory,
            Some((mount_targets, label)),
        )
    }

    fn resolve_authenticated_rootfs_path(
        &self,
        absolute_path: &str,
        final_kind: RootfsResolutionFinalKindV1,
        startup_antichain: Option<(&[&str], &str)>,
    ) -> Result<ResolvedRootfsPathV1> {
        let mut state = Self::initialize_authenticated_rootfs_resolution(absolute_path)?;

        while let Some(component) = state.pending.pop_front() {
            state
                .resolved
                .try_reserve(1)
                .context("cannot extend bounded rootfs resolved component stack")?;
            if !apply_rootfs_resolution_component(&mut state.resolved, &component)? {
                if !state.pending.is_empty() {
                    continue;
                }
                return self.resolve_terminal_authenticated_rootfs_directory(
                    absolute_path,
                    final_kind,
                    startup_antichain,
                    state,
                );
            }
            let normalized = state.resolved.join("/");
            ensure!(
                !normalized.is_empty() && normalized.len() <= OCI_LAYER_PATH_MAX_BYTES,
                "authenticated rootfs resolution exceeds its normalized path bound"
            );
            Self::authenticate_startup_resolution_prefix(normalized.as_str(), startup_antichain)?;
            let position = self.live_entry_position(normalized.as_str())?;
            let entry = self
                .entries
                .get(position)
                .context("resolved rootfs entry left the physical journal")?;
            let operation = self
                .transaction
                .operations
                .get(entry.operation_index)
                .context("resolved rootfs entry left the authenticated journal")?;
            match (&operation.kind, &entry.phase) {
                (
                    StagedRootfsOperationKindV1::Directory,
                    MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::Directory(_)),
                ) => {
                    if state.pending.is_empty() {
                        ensure!(
                            final_kind == RootfsResolutionFinalKindV1::Directory,
                            "resolved authenticated rootfs final target is non-regular"
                        );
                        return Self::finish_authenticated_rootfs_resolution(
                            absolute_path,
                            format!("/{}", operation.path),
                            Some(position),
                            state,
                        );
                    }
                }
                (
                    StagedRootfsOperationKindV1::Regular { .. },
                    MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::Regular(_)),
                ) => {
                    ensure!(
                        state.pending.is_empty(),
                        "authenticated rootfs path traverses a non-directory regular file"
                    );
                    ensure!(
                        final_kind == RootfsResolutionFinalKindV1::Regular,
                        "resolved authenticated rootfs final target is non-directory"
                    );
                    return Self::finish_authenticated_rootfs_resolution(
                        absolute_path,
                        format!("/{}", operation.path),
                        Some(position),
                        state,
                    );
                }
                (
                    StagedRootfsOperationKindV1::SymbolicLink { target },
                    MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::SymbolicLink(
                        symbolic_link,
                    )),
                ) => Self::follow_authenticated_rootfs_symbolic_link(
                    &mut state,
                    normalized.as_str(),
                    target,
                    symbolic_link.identity,
                )?,
                _ => anyhow::bail!("authenticated rootfs journal kind or custody changed"),
            }
        }
        anyhow::bail!("resolved authenticated rootfs target is absent")
    }

    fn initialize_authenticated_rootfs_resolution(
        absolute_path: &str,
    ) -> Result<AuthenticatedRootfsResolutionStateV1> {
        ensure!(
            absolute_path.starts_with('/')
                && absolute_path.len() > 1
                && absolute_path.len() <= OCI_LAYER_PATH_MAX_BYTES + 1
                && !absolute_path.as_bytes().contains(&0),
            "bound rootfs path is not canonical absolute POSIX"
        );
        ensure!(
            absolute_path[1..]
                .split('/')
                .all(|component| !component.is_empty() && !matches!(component, "." | "..")),
            "bound rootfs path is not canonical absolute POSIX"
        );
        let initial_components = absolute_path[1..].split('/').count();
        let mut pending = VecDeque::new();
        pending
            .try_reserve_exact(initial_components)
            .context("cannot reserve bounded rootfs resolution queue")?;
        for component in absolute_path[1..].split('/') {
            pending.push_back(try_owned_startup_string(
                component,
                "rootfs resolution component",
            )?);
        }
        let mut resolved = Vec::<String>::new();
        resolved
            .try_reserve_exact(initial_components)
            .context("cannot reserve bounded rootfs resolved component stack")?;
        let followed_paths = BTreeSet::<String>::new();
        let followed_inodes = BTreeSet::<(u32, u32, u64, u64)>::new();
        let mut symbolic_link_chain = Vec::new();
        symbolic_link_chain
            .try_reserve_exact(usize::from(ROOTFS_SYMBOLIC_LINK_MAX_HOPS))
            .context("cannot reserve bounded rootfs symbolic-link chain")?;
        Ok(AuthenticatedRootfsResolutionStateV1 {
            pending,
            resolved,
            followed_paths,
            followed_inodes,
            symbolic_link_chain,
            symbolic_link_hops: 0,
        })
    }

    fn resolve_terminal_authenticated_rootfs_directory(
        &self,
        absolute_path: &str,
        final_kind: RootfsResolutionFinalKindV1,
        startup_antichain: Option<(&[&str], &str)>,
        state: AuthenticatedRootfsResolutionStateV1,
    ) -> Result<ResolvedRootfsPathV1> {
        ensure!(
            final_kind == RootfsResolutionFinalKindV1::Directory,
            "resolved authenticated rootfs final target is non-regular"
        );
        if state.resolved.is_empty() {
            return Self::finish_authenticated_rootfs_resolution(
                absolute_path,
                "/".to_owned(),
                None,
                state,
            );
        }
        let normalized = state.resolved.join("/");
        ensure!(
            normalized.len() <= OCI_LAYER_PATH_MAX_BYTES,
            "authenticated rootfs resolution exceeds its normalized path bound"
        );
        Self::authenticate_startup_resolution_prefix(normalized.as_str(), startup_antichain)?;
        let position = self.live_entry_position(normalized.as_str())?;
        let entry = self
            .entries
            .get(position)
            .context("resolved rootfs entry left the physical journal")?;
        let operation = self
            .transaction
            .operations
            .get(entry.operation_index)
            .context("resolved rootfs entry left the authenticated journal")?;
        ensure!(
            matches!(
                (&operation.kind, &entry.phase),
                (
                    StagedRootfsOperationKindV1::Directory,
                    MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::Directory(_))
                )
            ),
            "authenticated rootfs journal kind or custody changed"
        );
        Self::finish_authenticated_rootfs_resolution(
            absolute_path,
            format!("/{}", operation.path),
            Some(position),
            state,
        )
    }

    fn authenticate_startup_resolution_prefix(
        normalized: &str,
        startup_antichain: Option<(&[&str], &str)>,
    ) -> Result<()> {
        if let Some((mount_targets, label)) = startup_antichain {
            for mount_target in mount_targets {
                ensure!(
                    !runtime_mount_overlays_relative_component_path(normalized, mount_target),
                    "{label} path /{normalized} overlaps runtime mount target {mount_target}"
                );
            }
        }
        Ok(())
    }

    fn finish_authenticated_rootfs_resolution(
        absolute_path: &str,
        final_path: String,
        position: Option<usize>,
        state: AuthenticatedRootfsResolutionStateV1,
    ) -> Result<ResolvedRootfsPathV1> {
        Ok(ResolvedRootfsPathV1 {
            canonical_path: try_owned_startup_string(absolute_path, "canonical rootfs path")?,
            final_path,
            position,
            symbolic_link_chain: state.symbolic_link_chain,
        })
    }

    fn follow_authenticated_rootfs_symbolic_link(
        state: &mut AuthenticatedRootfsResolutionStateV1,
        normalized: &str,
        target: &str,
        identity: SymbolicLinkIdentityV1,
    ) -> Result<()> {
        state.symbolic_link_hops = state
            .symbolic_link_hops
            .checked_add(1)
            .context("authenticated rootfs symbolic-link hop count overflowed")?;
        ensure!(
            state.symbolic_link_hops <= ROOTFS_SYMBOLIC_LINK_MAX_HOPS,
            "authenticated rootfs resolution reaches symbolic-link hop 41"
        );
        ensure!(
            state.followed_paths.insert(normalized.to_owned()),
            "authenticated rootfs resolution repeats a normalized path"
        );
        ensure!(
            state.followed_inodes.insert((
                identity.device_major,
                identity.device_minor,
                identity.inode,
                identity.mount_id,
            )),
            "authenticated rootfs resolution repeats an inode identity"
        );
        let retained_parent_components = if target.starts_with('/') {
            0
        } else {
            state.resolved.len() - 1
        };
        let mut normalized_target = Vec::new();
        normalized_target
            .try_reserve_exact(
                retained_parent_components
                    .checked_add(target.split('/').count())
                    .context("rootfs symbolic-link target component overflowed")?,
            )
            .context("cannot reserve bounded normalized symbolic-link target")?;
        for component in &state.resolved[..retained_parent_components] {
            normalized_target.push(try_owned_startup_string(
                component,
                "retained symbolic-link parent component",
            )?);
        }
        for target_component in target.split('/') {
            apply_rootfs_resolution_component(&mut normalized_target, target_component)?;
        }
        let normalized_target_path = if normalized_target.is_empty() {
            "/".to_owned()
        } else {
            format!("/{}", normalized_target.join("/"))
        };
        state
            .symbolic_link_chain
            .push(ResolvedRootfsSymbolicLinkHopV1 {
                canonical_link_path: format!("/{normalized}"),
                exact_target: try_owned_startup_string(target, "symbolic-link target")?,
                normalized_target_path,
            });
        state.resolved.pop();
        if target.starts_with('/') {
            state.resolved.clear();
        }
        state
            .pending
            .try_reserve(target.split('/').count())
            .context("cannot extend bounded rootfs resolution queue")?;
        for target_component in target.split('/').rev() {
            state.pending.push_front(try_owned_startup_string(
                target_component,
                "symbolic-link resolution component",
            )?);
        }
        Ok(())
    }

    fn authenticate_resolved_rootfs_directory(
        &self,
        resolution: &ResolvedRootfsPathV1,
    ) -> Result<()> {
        let position = resolution
            .position
            .context("startup search directory unexpectedly names the implicit root")?;
        let entry = self
            .entries
            .get(position)
            .context("startup search directory left the physical journal")?;
        let operation = self
            .transaction
            .operations
            .get(entry.operation_index)
            .context("startup search directory left the authenticated journal")?;
        let state = match (&operation.kind, &entry.phase) {
            (
                StagedRootfsOperationKindV1::Directory,
                MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::Directory(state)),
            ) => *state,
            _ => anyhow::bail!("startup search path is not a retained directory"),
        };
        ensure!(
            operation.mode == 0o555 && state.sealed,
            "startup search directory is not sealed mode 0555"
        );
        ensure!(
            resolution.final_path == format!("/{}", operation.path),
            "startup search directory final path differs from its journal position"
        );
        let descriptor = open_materialized_directory(self.staging_root.as_fd(), &operation.path)?;
        validate_materialized_directory(
            descriptor.as_fd(),
            state.identity,
            state.owner,
            state.group,
            true,
            self.staging_root_identity.mount_id,
            entry.created_child_count,
        )
    }

    fn authenticated_rootfs_visible_leaf_exists(&self, absolute_path: &str) -> Result<bool> {
        let components = canonical_rootfs_requirement_components(absolute_path)?;
        let mut pending = components
            .into_iter()
            .map(str::to_owned)
            .collect::<VecDeque<_>>();
        let mut resolved = Vec::<String>::new();
        let mut followed_paths = BTreeSet::<String>::new();
        let mut followed_inodes = BTreeSet::<(u32, u32, u64, u64)>::new();
        let mut symbolic_link_hops = 0_u8;
        while let Some(component) = pending.pop_front() {
            if !apply_rootfs_resolution_component(&mut resolved, &component)? {
                continue;
            }
            let normalized = resolved.join("/");
            let Some(position) = self.live_entry_position_optional(normalized.as_str())? else {
                return Ok(false);
            };
            let entry = self
                .entries
                .get(position)
                .context("loader exclusion lookup left the physical journal")?;
            let operation = self
                .transaction
                .operations
                .get(entry.operation_index)
                .context("loader exclusion lookup left the authenticated journal")?;
            if pending.is_empty() {
                return Ok(true);
            }
            match (&operation.kind, &entry.phase) {
                (
                    StagedRootfsOperationKindV1::Directory,
                    MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::Directory(_)),
                ) => {}
                (
                    StagedRootfsOperationKindV1::SymbolicLink { target },
                    MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::SymbolicLink(
                        state,
                    )),
                ) => {
                    symbolic_link_hops = symbolic_link_hops
                        .checked_add(1)
                        .context("loader exclusion symbolic-link hop count overflowed")?;
                    ensure!(
                        symbolic_link_hops <= ROOTFS_SYMBOLIC_LINK_MAX_HOPS,
                        "loader exclusion lookup reaches symbolic-link hop 41"
                    );
                    ensure!(
                        followed_paths.insert(normalized),
                        "loader exclusion lookup repeats a normalized path"
                    );
                    ensure!(
                        followed_inodes.insert((
                            state.identity.device_major,
                            state.identity.device_minor,
                            state.identity.inode,
                            state.identity.mount_id,
                        )),
                        "loader exclusion lookup repeats an inode identity"
                    );
                    resolved.pop();
                    if target.starts_with('/') {
                        resolved.clear();
                    }
                    for target_component in target.split('/').rev() {
                        pending.push_front(target_component.to_owned());
                    }
                }
                _ => anyhow::bail!(
                    "loader exclusion lookup is blocked by a present non-directory component"
                ),
            }
        }
        Ok(false)
    }

    fn validate_live_entry_ordering(&self) -> Result<()> {
        let mut previous = None;
        for (position, entry) in self.entries.iter().enumerate() {
            ensure!(
                self.canonical_live_operation_indices.get(position) == Some(&entry.operation_index),
                "authenticated rootfs lookup journal left canonical index order"
            );
            let operation = self
                .transaction
                .operations
                .get(entry.operation_index)
                .context("authenticated rootfs lookup left its operation journal")?;
            if let Some(previous) = previous {
                ensure!(
                    previous < operation.path.as_str(),
                    "authenticated rootfs lookup journal is not strictly path-sorted"
                );
            }
            previous = Some(operation.path.as_str());
        }
        Ok(())
    }

    fn live_entry_position(&self, path: &str) -> Result<usize> {
        self.live_entry_position_optional(path)?
            .with_context(|| format!("authenticated rootfs path is dangling: {path}"))
    }

    fn live_entry_position_optional(&self, path: &str) -> Result<Option<usize>> {
        // `validate_live_entry_ordering` runs under the same immutable borrow
        // before any resolver call. The private journal cannot be mutated
        // between that check and this bounded binary search.
        let mut start = 0_usize;
        let mut end = self.entries.len();
        while start < end {
            let middle = start + (end - start) / 2;
            let entry = self
                .entries
                .get(middle)
                .context("authenticated rootfs lookup left its physical journal")?;
            let operation = self
                .transaction
                .operations
                .get(entry.operation_index)
                .context("authenticated rootfs lookup left its operation journal")?;
            match operation.path.as_str().cmp(path) {
                std::cmp::Ordering::Less => start = middle + 1,
                std::cmp::Ordering::Greater => end = middle,
                std::cmp::Ordering::Equal => return Ok(Some(middle)),
            }
        }
        Ok(None)
    }

    pub(super) fn cleanup(
        mut self,
    ) -> std::result::Result<PrivateOciRootfsAbandonedV1, PrivateOciRootfsCleanupFailureV1> {
        let physical_cleanup = if self.cleanup_started {
            self.cleanup_named_tree()
        } else {
            self.validate_retained_tree(true)
                .and_then(|()| self.cleanup_named_tree())
        };
        if let Err(error) = physical_cleanup {
            return Err(PrivateOciRootfsCleanupFailureV1::recoverable(error, self));
        }
        self.finish_logical_abandonment().map_err(|failure| {
            PrivateOciRootfsCleanupFailureV1::terminal(anyhow::Error::new(*failure))
        })
    }

    #[cfg(test)]
    fn trigger_test_failpoint(
        &mut self,
        reached: TestOnlyPrivateMaterializationFailpointV1,
    ) -> Result<()> {
        if self.test_only_materialization_failpoint == Some(reached) {
            self.test_only_materialization_failpoint = None;
            anyhow::bail!("injected private OCI rootfs materialization failure at {reached:?}")
        }
        Ok(())
    }

    #[cfg(test)]
    fn trigger_regular_creator_substitution_test_failpoint(
        &mut self,
        operation_index: usize,
        parent_path: &str,
        leaf: &str,
    ) -> Result<()> {
        let Some(
            TestOnlyPrivateMaterializationFailpointV1::RegularFileDescriptorRecordedWithSameNameSubstitution {
                operation_index: expected_operation_index,
                holding_name,
            },
        ) = self.test_only_materialization_failpoint
        else {
            return Ok(());
        };
        if expected_operation_index != operation_index {
            return Ok(());
        }
        self.test_only_materialization_failpoint = None;

        let parent = open_beneath_directory(self.staging_root.as_fd(), parent_path)?;
        ensure_absent(
            self.transaction.parent.descriptor(),
            OsStr::new(holding_name),
            "test-only regular creator holding name before substitution",
        )?;
        rustix::fs::renameat(
            parent.descriptor(),
            leaf,
            self.transaction.parent.descriptor(),
            holding_name,
        )
        .context("cannot move test-only regular creator outside staging")?;
        let replacement = rustix::fs::openat2(
            parent.descriptor(),
            leaf,
            MATERIALIZED_REGULAR_CREATE_FLAGS,
            PRIVATE_MATERIALIZED_FILE_MODE,
            MATERIALIZED_RESOLVE_FLAGS,
        )
        .context("cannot create test-only same-name regular replacement")?;
        rustix::fs::fchmod(&replacement, PRIVATE_MATERIALIZED_FILE_MODE)
            .context("cannot set test-only regular replacement mode")?;
        anyhow::bail!(
            "injected private OCI rootfs materialization failure at {:?}",
            TestOnlyPrivateMaterializationFailpointV1::RegularFileDescriptorRecordedWithSameNameSubstitution {
                operation_index,
                holding_name,
            }
        )
    }

    #[cfg(test)]
    pub(super) fn test_only_arm_cleanup_custody_mutation(
        &self,
        mutation: TestOnlyPhysicalCustodyMutationV1,
    ) {
        assert!(
            self.test_only_cleanup_custody_mutation
                .replace(Some(mutation))
                .is_none(),
            "test-only cleanup custody mutation was already armed"
        );
    }

    #[cfg(test)]
    pub(super) fn test_only_arm_cleanup_failpoint(
        &self,
        failpoint: TestOnlyPrivateCleanupFailpointV1,
    ) {
        assert!(
            self.test_only_cleanup_failpoint
                .replace(Some(failpoint))
                .is_none(),
            "test-only cleanup failpoint was already armed"
        );
    }

    #[cfg(test)]
    pub(super) fn test_only_runtime_metadata_seal_order(&self) -> &[String] {
        &self.test_only_runtime_metadata_seal_order
    }

    #[cfg(test)]
    pub(super) fn test_only_fail_after_named_effect(self, primary: anyhow::Error) -> anyhow::Error {
        self.fail_after_named_effect(primary)
    }

    #[cfg(test)]
    fn test_only_validate_mutated_expected_custody(
        &self,
        mutation: TestOnlyPhysicalCustodyMutationV1,
    ) -> Result<()> {
        use TestOnlyPhysicalCustodyMutationV1 as Mutation;

        match mutation {
            Mutation::MountNamespaceDevice | Mutation::MountNamespaceInode => {
                let identity_mutation = match mutation {
                    Mutation::MountNamespaceDevice => {
                        TestOnlyMountNamespaceIdentityMutationV1::Device
                    }
                    Mutation::MountNamespaceInode => {
                        TestOnlyMountNamespaceIdentityMutationV1::Inode
                    }
                    _ => unreachable!("mount-namespace mutation was prefiltered"),
                };
                self.transaction
                    .current_mount_namespace
                    .test_only_arm_next_reauthentication_identity_mutation(identity_mutation);
                Ok(())
            }
            Mutation::UserNamespaceDevice | Mutation::UserNamespaceInode => {
                let identity_mutation = match mutation {
                    Mutation::UserNamespaceDevice => {
                        TestOnlyUserNamespaceIdentityMutationV1::Device
                    }
                    Mutation::UserNamespaceInode => TestOnlyUserNamespaceIdentityMutationV1::Inode,
                    _ => unreachable!("user-namespace mutation was prefiltered"),
                };
                self.transaction
                    .current_mount_namespace
                    .test_only_arm_next_user_namespace_identity_mutation(identity_mutation);
                Ok(())
            }
            Mutation::FinalizerEffectiveUid
            | Mutation::FinalizerEffectiveGid
            | Mutation::StagingStableUnexpectedOwner
            | Mutation::StagingStableUnexpectedGroup
            | Mutation::DirectoryStableUnexpectedOwner { .. }
            | Mutation::DirectoryStableUnexpectedGroup { .. }
            | Mutation::RegularStableUnexpectedOwner { .. }
            | Mutation::RegularStableUnexpectedGroup { .. }
            | Mutation::SymbolicLinkStableUnexpectedOwner { .. }
            | Mutation::SymbolicLinkStableUnexpectedGroup { .. } => {
                self.test_only_validate_mutated_mapped_owner_prerequisite(mutation)
            }
            Mutation::StagingDevice
            | Mutation::StagingInode
            | Mutation::StagingMount
            | Mutation::StagingGroup
            | Mutation::StagingObservedMode
            | Mutation::StagingObservedMtimeSeconds
            | Mutation::StagingObservedMtimeNanoseconds
            | Mutation::StagingObservedOwner
            | Mutation::StagingExpectedCardinality => {
                self.test_only_validate_mutated_staging_custody(mutation)
            }
            _ => self.test_only_validate_mutated_entry_custody(mutation),
        }
    }

    #[cfg(test)]
    fn test_only_validate_mutated_entry_custody(
        &self,
        mutation: TestOnlyPhysicalCustodyMutationV1,
    ) -> Result<()> {
        use TestOnlyPhysicalCustodyMutationV1 as Mutation;

        let (kind, field, operation_index) = match mutation {
            Mutation::DirectoryDevice { operation_index } => (0_u8, 0_u8, operation_index),
            Mutation::DirectoryInode { operation_index } => (0, 1, operation_index),
            Mutation::DirectoryMount { operation_index } => (0, 2, operation_index),
            Mutation::DirectoryGroup { operation_index } => (0, 3, operation_index),
            Mutation::DirectoryObservedMode { operation_index } => (0, 4, operation_index),
            Mutation::DirectoryObservedOwner { operation_index } => (0, 5, operation_index),
            Mutation::DirectoryExpectedCardinality { operation_index } => (0, 6, operation_index),
            Mutation::DirectoryObservedMtimeSeconds { operation_index } => (0, 7, operation_index),
            Mutation::DirectoryObservedMtimeNanoseconds { operation_index } => {
                (0, 8, operation_index)
            }
            Mutation::RegularDevice { operation_index } => (1, 0, operation_index),
            Mutation::RegularInode { operation_index } => (1, 1, operation_index),
            Mutation::RegularMount { operation_index } => (1, 2, operation_index),
            Mutation::RegularGroup { operation_index } => (1, 3, operation_index),
            Mutation::RegularObservedOwner { operation_index } => (1, 4, operation_index),
            Mutation::RegularObservedMtimeSeconds { operation_index } => (1, 5, operation_index),
            Mutation::RegularObservedMtimeNanoseconds { operation_index } => {
                (1, 6, operation_index)
            }
            Mutation::SymbolicLinkDeviceMajor { operation_index } => (2, 0, operation_index),
            Mutation::SymbolicLinkDeviceMinor { operation_index } => (2, 1, operation_index),
            Mutation::SymbolicLinkInode { operation_index } => (2, 2, operation_index),
            Mutation::SymbolicLinkMount { operation_index } => (2, 3, operation_index),
            Mutation::SymbolicLinkGroup { operation_index } => (2, 4, operation_index),
            Mutation::SymbolicLinkObservedHardLinkCount { operation_index } => {
                (2, 5, operation_index)
            }
            Mutation::SymbolicLinkObservedMode { operation_index } => (2, 6, operation_index),
            Mutation::SymbolicLinkObservedOwner { operation_index } => (2, 7, operation_index),
            Mutation::SymbolicLinkExpectedTarget { operation_index } => (2, 8, operation_index),
            Mutation::SymbolicLinkObservedMtimeSeconds { operation_index } => {
                (2, 9, operation_index)
            }
            Mutation::SymbolicLinkObservedMtimeNanoseconds { operation_index } => {
                (2, 10, operation_index)
            }
            _ => unreachable!("non-entry custody mutation was prefiltered"),
        };
        let position = self
            .entries
            .iter()
            .position(|entry| entry.operation_index == operation_index)
            .context("test-only physical custody mutation left the materialization journal")?;
        let operation = self
            .transaction
            .operations
            .get(operation_index)
            .context("test-only physical custody mutation left the operation journal")?;

        match (kind, &self.entries[position].phase, &operation.kind) {
            (
                0,
                MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::Directory(state)),
                StagedRootfsOperationKindV1::Directory,
            ) => self.test_only_validate_mutated_directory_custody(
                position,
                operation.path.as_str(),
                *state,
                field,
            ),
            (
                1,
                MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::Regular(state)),
                StagedRootfsOperationKindV1::Regular { extent_index },
            ) => self.test_only_validate_mutated_regular_custody(
                operation.path.as_str(),
                operation.mode,
                *extent_index,
                *state,
                field,
            ),
            (
                2,
                MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::SymbolicLink(state)),
                StagedRootfsOperationKindV1::SymbolicLink { target },
            ) => self.test_only_validate_mutated_symbolic_link_custody(
                operation.path.as_str(),
                target,
                *state,
                field,
            ),
            _ => anyhow::bail!("test-only physical custody mutation changed entry kind"),
        }
    }

    #[cfg(test)]
    fn test_only_validate_mutated_mapped_owner_prerequisite(
        &self,
        mutation: TestOnlyPhysicalCustodyMutationV1,
    ) -> Result<()> {
        use TestOnlyPhysicalCustodyMutationV1 as Mutation;

        if matches!(
            mutation,
            Mutation::FinalizerEffectiveUid | Mutation::FinalizerEffectiveGid
        ) {
            let mut expected = FinalizerEffectiveIdsV1 {
                uid: self.finalizer_effective_ids.uid,
                gid: self.finalizer_effective_ids.gid,
            };
            if mutation == Mutation::FinalizerEffectiveUid {
                expected.uid = expected.uid.wrapping_add(1);
            } else {
                expected.gid = expected.gid.wrapping_add(1);
            }
            return validate_current_finalizer_effective_ids(
                &expected,
                FinalizerEffectiveIdsObservationMutationV1::Unchanged,
            );
        }

        let (kind, operation_index, mutate_owner) = match mutation {
            Mutation::StagingStableUnexpectedOwner => (0_u8, None, true),
            Mutation::StagingStableUnexpectedGroup => (0, None, false),
            Mutation::DirectoryStableUnexpectedOwner { operation_index } => {
                (1, Some(operation_index), true)
            }
            Mutation::DirectoryStableUnexpectedGroup { operation_index } => {
                (1, Some(operation_index), false)
            }
            Mutation::RegularStableUnexpectedOwner { operation_index } => {
                (2, Some(operation_index), true)
            }
            Mutation::RegularStableUnexpectedGroup { operation_index } => {
                (2, Some(operation_index), false)
            }
            Mutation::SymbolicLinkStableUnexpectedOwner { operation_index } => {
                (3, Some(operation_index), true)
            }
            Mutation::SymbolicLinkStableUnexpectedGroup { operation_index } => {
                (3, Some(operation_index), false)
            }
            _ => unreachable!("mapped-owner mutation was prefiltered"),
        };
        let (mut owner, mut group, label) = if let Some(operation_index) = operation_index {
            let entry = self
                .entries
                .iter()
                .find(|entry| entry.operation_index == operation_index)
                .context("mapped-owner mutation left the materialization journal")?;
            match (kind, &entry.phase) {
                (
                    1,
                    MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::Directory(
                        state,
                    )),
                ) => (state.owner, state.group, "private OCI rootfs directory"),
                (
                    2,
                    MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::Regular(state)),
                ) => (state.owner, state.group, "private OCI rootfs regular file"),
                (
                    3,
                    MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::SymbolicLink(
                        state,
                    )),
                ) => (state.owner, state.group, "private OCI rootfs symbolic link"),
                _ => anyhow::bail!("mapped-owner mutation changed entry kind"),
            }
        } else {
            (
                self.staging_root_owner,
                self.staging_root_group,
                "private OCI rootfs staging root",
            )
        };
        if mutate_owner {
            owner = owner.wrapping_add(1);
        } else {
            group = group.wrapping_add(1);
        }
        // Model a stable unexpected inode and its matching physical custody
        // locally; leave the real baseline untouched so retry can clean it.
        validate_physical_owner_group_custody(owner, group, owner, group, label)?;
        validate_mapped_owner_prerequisite(owner, group, &self.finalizer_effective_ids, label)
    }

    #[cfg(test)]
    fn test_only_validate_mutated_staging_custody(
        &self,
        mutation: TestOnlyPhysicalCustodyMutationV1,
    ) -> Result<()> {
        use TestOnlyPhysicalCustodyMutationV1 as Mutation;

        let mut identity = self.staging_root_identity;
        let owner = self.staging_root_owner;
        let mut group = self.staging_root_group;
        let mut observed = directory_observation(self.staging_root.as_fd())?;
        let mut expected_entries = self.root_created_child_count;
        match mutation {
            Mutation::StagingDevice => identity.device = identity.device.wrapping_add(1),
            Mutation::StagingInode => identity.inode = identity.inode.wrapping_add(1),
            Mutation::StagingMount => identity.mount_id = identity.mount_id.wrapping_add(1),
            Mutation::StagingGroup => group = group.wrapping_add(1),
            Mutation::StagingObservedMode => observed.mode ^= 0o077,
            Mutation::StagingObservedMtimeSeconds => observed.modification_time_seconds = 1,
            Mutation::StagingObservedMtimeNanoseconds => {
                observed.modification_time_nanoseconds = 1;
            }
            Mutation::StagingObservedOwner => observed.owner = observed.owner.wrapping_add(1),
            Mutation::StagingExpectedCardinality => {
                expected_entries = expected_entries.saturating_add(1);
            }
            _ => unreachable!("staging mutation was prefiltered"),
        }
        validate_private_staging_root_observation(
            self.staging_root.as_fd(),
            observed,
            identity,
            (owner, group),
            self.staging_root_sealed,
            self.transaction.parent.identity().mount_id,
            expected_entries,
        )
    }

    #[cfg(test)]
    fn test_only_validate_mutated_directory_custody(
        &self,
        position: usize,
        path: &str,
        state: MaterializedDirectoryStateV1,
        field: u8,
    ) -> Result<()> {
        let mut identity = state.identity;
        let owner = state.owner;
        let mut group = state.group;
        let descriptor = open_materialized_directory(self.staging_root.as_fd(), path)?;
        let mut observed = directory_observation(descriptor.as_fd())?;
        let mut expected_entries = self.entries[position].created_child_count;
        match field {
            0 => identity.device = identity.device.wrapping_add(1),
            1 => identity.inode = identity.inode.wrapping_add(1),
            2 => identity.mount_id = identity.mount_id.wrapping_add(1),
            3 => group = group.wrapping_add(1),
            4 => observed.mode ^= 0o077,
            5 => observed.owner = observed.owner.wrapping_add(1),
            6 => expected_entries = expected_entries.saturating_add(1),
            7 => observed.modification_time_seconds = 1,
            8 => observed.modification_time_nanoseconds = 1,
            _ => unreachable!("directory field is bounded by the mutation enum"),
        }
        validate_materialized_directory_observation(
            descriptor.as_fd(),
            observed,
            identity,
            (owner, group),
            state.sealed,
            self.staging_root_identity.mount_id,
            expected_entries,
        )
    }

    #[cfg(test)]
    fn test_only_validate_mutated_regular_custody(
        &self,
        path: &str,
        mode: u32,
        extent_index: usize,
        state: MaterializedRegularStateV1,
        field: u8,
    ) -> Result<()> {
        let mut identity = state.identity;
        let owner = state.owner;
        let mut group = state.group;
        match field {
            0 => identity.device = identity.device.wrapping_add(1),
            1 => identity.inode = identity.inode.wrapping_add(1),
            2 => identity.mount_id = identity.mount_id.wrapping_add(1),
            3 => group = group.wrapping_add(1),
            4..=6 => {}
            _ => unreachable!("regular field is bounded by the mutation enum"),
        }
        let descriptor = rustix::fs::openat2(
            self.staging_root.as_fd(),
            path,
            PINNED_REGULAR_FLAGS,
            rustix::fs::Mode::empty(),
            MATERIALIZED_RESOLVE_FLAGS,
        )?;
        let file = File::from(descriptor);
        let extent = self
            .transaction
            .physical_regular_extents
            .get(extent_index)
            .context("test-only regular mutation left the extent journal")?;
        if matches!(field, 4..=6) {
            let mut observed = regular_file_observation(&file)?;
            if field == 4 {
                observed.owner = observed.owner.wrapping_add(1);
            } else if field == 5 {
                observed.modification_time_seconds = 1;
            } else {
                observed.modification_time_nanoseconds = 1;
            }
            return validate_materialized_regular_metadata(
                &observed,
                identity,
                owner,
                group,
                mode,
                extent,
                self.staging_root_identity.mount_id,
            );
        }
        validate_materialized_regular(
            &file,
            identity,
            owner,
            group,
            mode,
            extent,
            self.staging_root_identity.mount_id,
        )
    }

    #[cfg(test)]
    fn test_only_validate_mutated_symbolic_link_custody(
        &self,
        path: &str,
        target: &str,
        state: MaterializedSymbolicLinkStateV1,
        field: u8,
    ) -> Result<()> {
        let mut identity = state.identity;
        let owner = state.owner;
        let mut group = state.group;
        let (parent_path, leaf) = parent_and_leaf(path)?;
        let parent = open_beneath_directory(self.staging_root.as_fd(), parent_path)?;
        let mut observed = symbolic_link_observation(parent.descriptor(), leaf)?;
        let mut expected_target = target.to_owned();
        match field {
            0 => identity.device_major = identity.device_major.wrapping_add(1),
            1 => identity.device_minor = identity.device_minor.wrapping_add(1),
            2 => identity.inode = identity.inode.wrapping_add(1),
            3 => identity.mount_id = identity.mount_id.wrapping_add(1),
            4 => group = group.wrapping_add(1),
            5 => observed.hard_link_count = observed.hard_link_count.wrapping_add(1),
            6 => observed.mode ^= 0o077,
            7 => observed.owner = observed.owner.wrapping_add(1),
            8 => expected_target.push_str(".test-only-mutated"),
            9 => observed.modification_time_seconds = 1,
            10 => observed.modification_time_nanoseconds = 1,
            _ => unreachable!("symbolic-link field is bounded by the mutation enum"),
        }
        validate_materialized_symbolic_link_observation(
            parent.descriptor(),
            leaf,
            observed,
            identity,
            (owner, group),
            &expected_target,
            self.staging_root_identity.mount_id,
        )
    }

    fn materialize_live_tree(&mut self) -> Result<()> {
        for position in 0..self.entries.len() {
            let operation_index = self.entries[position].operation_index;
            let kind = match &self
                .transaction
                .operations
                .get(operation_index)
                .context("private materializer operation left its authenticated journal")?
                .kind
            {
                StagedRootfsOperationKindV1::Directory => 0,
                StagedRootfsOperationKindV1::Regular { .. } => 1,
                StagedRootfsOperationKindV1::SymbolicLink { .. } => 2,
                StagedRootfsOperationKindV1::Remove { .. }
                | StagedRootfsOperationKindV1::OpaqueDirectory { .. } => 3,
            };
            match kind {
                0 => {
                    self.materialize_directory(position)?;
                }
                1 => {
                    self.materialize_regular(position)?;
                }
                2 => {
                    self.materialize_symbolic_link(position)?;
                }
                _ => {
                    anyhow::bail!("private rootfs materializer received a non-live marker")
                }
            }
        }
        Ok(())
    }

    fn directory_materialization_plan(&self, position: usize) -> Result<(usize, String)> {
        let operation_index = self.entries[position].operation_index;
        let operation = self
            .transaction
            .operations
            .get(operation_index)
            .context("private materializer operation left its authenticated journal")?;
        ensure!(
            matches!(operation.kind, StagedRootfsOperationKindV1::Directory),
            "private directory plan changed kind"
        );
        Ok((operation_index, operation.path.as_str().to_owned()))
    }

    fn regular_materialization_plan(&self, position: usize) -> Result<(usize, String, usize, u32)> {
        let operation_index = self.entries[position].operation_index;
        let operation = self
            .transaction
            .operations
            .get(operation_index)
            .context("private materializer operation left its authenticated journal")?;
        let StagedRootfsOperationKindV1::Regular { extent_index } = operation.kind else {
            anyhow::bail!("private regular plan changed kind")
        };
        Ok((
            operation_index,
            operation.path.as_str().to_owned(),
            extent_index,
            operation.mode,
        ))
    }

    fn symbolic_link_materialization_plan(
        &self,
        position: usize,
    ) -> Result<(usize, String, String)> {
        let operation_index = self.entries[position].operation_index;
        let operation = self
            .transaction
            .operations
            .get(operation_index)
            .context("private materializer operation left its authenticated journal")?;
        let StagedRootfsOperationKindV1::SymbolicLink { target } = &operation.kind else {
            anyhow::bail!("private symbolic-link plan changed kind")
        };
        Ok((
            operation_index,
            operation.path.as_str().to_owned(),
            target.as_str().to_owned(),
        ))
    }

    fn create_materialized_symbolic_link(
        &self,
        parent_path: &str,
        leaf: &str,
        target: &str,
        materialized_path: &str,
    ) -> Result<()> {
        let parent = open_beneath_directory(self.staging_root.as_fd(), parent_path)?;
        ensure_absent(
            parent.descriptor(),
            OsStr::new(leaf),
            "private OCI rootfs symbolic link immediately before creation",
        )?;
        rustix::fs::symlinkat(target, parent.descriptor(), leaf).with_context(|| {
            format!(
                "cannot create private materialized OCI rootfs symbolic link {materialized_path}"
            )
        })
    }

    fn materialize_directory(&mut self, position: usize) -> Result<()> {
        self.preflight_named_entry_effect(position)?;
        let (operation_index, path) = self.directory_materialization_plan(position)?;
        #[cfg(not(test))]
        let _ = operation_index;
        let (parent_path, leaf) = parent_and_leaf(path.as_str())?;
        {
            let parent = open_beneath_directory(self.staging_root.as_fd(), parent_path)?;
            ensure_absent(
                parent.descriptor(),
                OsStr::new(leaf),
                "private OCI rootfs directory immediately before creation",
            )?;
            rustix::fs::mkdirat(
                parent.descriptor(),
                leaf,
                PRIVATE_MATERIALIZED_DIRECTORY_MODE,
            )
            .with_context(|| {
                format!("cannot create private materialized OCI rootfs directory {path}")
            })?;
        }
        self.record_named_entry_infallibly(position, MaterializedEntryPhaseV1::NamedUnidentified);
        #[cfg(test)]
        self.trigger_test_failpoint(
            TestOnlyPrivateMaterializationFailpointV1::DirectoryNamedBeforePin { operation_index },
        )?;
        let parent = open_beneath_directory(self.staging_root.as_fd(), parent_path)?;
        let descriptor = rustix::fs::openat2(
            parent.descriptor(),
            leaf,
            PINNED_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
            MATERIALIZED_RESOLVE_FLAGS,
        )
        .with_context(|| {
            format!("cannot retain private materialized OCI rootfs directory {path}")
        })?;
        let created = directory_observation(descriptor.as_fd())?;
        ensure!(
            created.identity.mount_id == self.staging_root_identity.mount_id,
            "private materialized OCI rootfs directory crossed its staging mount"
        );
        self.transition_named_entry_to_identified(
            position,
            MaterializedEntryStateV1::Directory(MaterializedDirectoryStateV1 {
                identity: created.identity,
                owner: created.owner,
                group: created.group,
                sealed: false,
            }),
        )?;
        #[cfg(test)]
        self.trigger_test_failpoint(
            TestOnlyPrivateMaterializationFailpointV1::DirectoryIdentityRecorded {
                operation_index,
            },
        )?;
        rustix::fs::fchmod(descriptor.as_fd(), PRIVATE_MATERIALIZED_DIRECTORY_MODE)
            .context("cannot set private OCI rootfs directory construction mode")?;
        validate_materialized_directory(
            descriptor.as_fd(),
            created.identity,
            created.owner,
            created.group,
            false,
            self.staging_root_identity.mount_id,
            0,
        )?;
        validate_current_finalizer_effective_ids(
            &self.finalizer_effective_ids,
            FinalizerEffectiveIdsObservationMutationV1::Unchanged,
        )?;
        #[cfg(not(test))]
        let (mapped_owner, mapped_group) = (created.owner, created.group);
        #[cfg(test)]
        let (mapped_owner, mapped_group) = {
            let mut mapped_owner = created.owner;
            let mut mapped_group = created.group;
            self.inject_test_only_mapped_owner_mismatch(
                TestOnlyPrivateMaterializationFailpointV1::DirectoryMappedOwnerMismatch {
                    operation_index,
                },
                TestOnlyPrivateMaterializationFailpointV1::DirectoryMappedGroupMismatch {
                    operation_index,
                },
                &mut mapped_owner,
                &mut mapped_group,
            );
            (mapped_owner, mapped_group)
        };
        validate_mapped_owner_prerequisite(
            mapped_owner,
            mapped_group,
            &self.finalizer_effective_ids,
            "private OCI rootfs directory",
        )
    }

    fn copy_and_seal_regular_mode(
        &self,
        file: &File,
        extent_index: usize,
        mode: u32,
    ) -> Result<()> {
        rustix::fs::fchmod(file, PRIVATE_MATERIALIZED_FILE_MODE)
            .context("cannot set private OCI rootfs regular-file copy mode")?;
        let extent = self
            .transaction
            .physical_regular_extents
            .get(extent_index)
            .context("private materializer extent left its authenticated journal")?;
        copy_regular_extent(&self.transaction.spool, file, extent)?;
        let sealed_mode = sealed_regular_mode(mode)?;
        rustix::fs::fchmod(file, sealed_mode)
            .context("cannot seal materialized OCI rootfs regular-file mode")
    }

    fn finish_materialized_regular(
        &mut self,
        position: usize,
        file: &File,
        extent_index: usize,
        mode: u32,
        created: super::FileObservation,
    ) -> Result<()> {
        #[cfg(test)]
        let operation_index = self.entries[position].operation_index;
        self.copy_and_seal_regular_mode(file, extent_index, mode)?;
        #[cfg(test)]
        self.trigger_test_failpoint(
            TestOnlyPrivateMaterializationFailpointV1::RegularModeSealRecorded { operation_index },
        )?;
        normalize_descriptor_mtime(file.as_fd(), "materialized OCI rootfs regular file")?;
        let MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::Regular(state)) =
            &mut self.entries[position].phase
        else {
            anyhow::bail!("private regular cleanup journal changed kind")
        };
        state.complete = true;
        #[cfg(test)]
        self.trigger_test_failpoint(
            TestOnlyPrivateMaterializationFailpointV1::RegularSealRecorded { operation_index },
        )?;
        file.sync_all()
            .context("cannot synchronize materialized OCI rootfs regular file")?;
        let extent = self
            .transaction
            .physical_regular_extents
            .get(extent_index)
            .context("private materializer extent left its authenticated journal")?;
        validate_materialized_regular(
            file,
            created.identity,
            created.owner,
            created.group,
            mode,
            extent,
            self.staging_root_identity.mount_id,
        )
    }

    fn materialize_regular(&mut self, position: usize) -> Result<()> {
        self.preflight_named_entry_effect(position)?;
        let (operation_index, path, extent_index, mode) =
            self.regular_materialization_plan(position)?;
        #[cfg(not(test))]
        let _ = operation_index;
        let (parent_path, leaf) = parent_and_leaf(path.as_str())?;
        let parent = open_beneath_directory(self.staging_root.as_fd(), parent_path)?;
        ensure_absent(
            parent.descriptor(),
            OsStr::new(leaf),
            "private OCI rootfs regular file immediately before creation",
        )?;
        let descriptor = rustix::fs::openat2(
            parent.descriptor(),
            leaf,
            MATERIALIZED_REGULAR_CREATE_FLAGS,
            PRIVATE_MATERIALIZED_FILE_MODE,
            MATERIALIZED_RESOLVE_FLAGS,
        )
        .with_context(|| {
            format!("cannot create private materialized OCI rootfs regular file {path}")
        })?;
        let file = File::from(descriptor);
        self.record_named_entry_infallibly(
            position,
            MaterializedEntryPhaseV1::RegularCreatorFd(file),
        );
        #[cfg(test)]
        self.trigger_test_failpoint(
            TestOnlyPrivateMaterializationFailpointV1::RegularFileDescriptorRecorded {
                operation_index,
            },
        )?;
        #[cfg(test)]
        self.trigger_regular_creator_substitution_test_failpoint(
            operation_index,
            parent_path,
            leaf,
        )?;
        let created = {
            let MaterializedEntryPhaseV1::RegularCreatorFd(file) = &self.entries[position].phase
            else {
                anyhow::bail!("private regular creator descriptor left its journal")
            };
            regular_file_observation(file)?
        };
        ensure!(
            created.identity.mount_id == self.staging_root_identity.mount_id,
            "private materialized OCI rootfs regular file crossed its staging mount"
        );
        ensure!(
            created.hard_link_count == 1,
            "private materialized OCI rootfs regular file does not have one link"
        );
        let file = self.transition_regular_creator_to_identified(
            position,
            MaterializedEntryStateV1::Regular(MaterializedRegularStateV1 {
                identity: created.identity,
                owner: created.owner,
                group: created.group,
                complete: false,
            }),
        )?;
        validate_current_finalizer_effective_ids(
            &self.finalizer_effective_ids,
            FinalizerEffectiveIdsObservationMutationV1::Unchanged,
        )?;
        #[cfg(not(test))]
        let (mapped_owner, mapped_group) = (created.owner, created.group);
        #[cfg(test)]
        let (mapped_owner, mapped_group) = {
            let mut mapped_owner = created.owner;
            let mut mapped_group = created.group;
            self.inject_test_only_mapped_owner_mismatch(
                TestOnlyPrivateMaterializationFailpointV1::RegularMappedOwnerMismatch {
                    operation_index,
                },
                TestOnlyPrivateMaterializationFailpointV1::RegularMappedGroupMismatch {
                    operation_index,
                },
                &mut mapped_owner,
                &mut mapped_group,
            );
            (mapped_owner, mapped_group)
        };
        validate_mapped_owner_prerequisite(
            mapped_owner,
            mapped_group,
            &self.finalizer_effective_ids,
            "private OCI rootfs regular file",
        )?;
        #[cfg(test)]
        self.trigger_test_failpoint(
            TestOnlyPrivateMaterializationFailpointV1::RegularIdentityRecorded { operation_index },
        )?;

        self.finish_materialized_regular(position, &file, extent_index, mode, created)
    }

    fn materialize_symbolic_link(&mut self, position: usize) -> Result<()> {
        self.preflight_named_entry_effect(position)?;
        let (operation_index, path, target) = self.symbolic_link_materialization_plan(position)?;
        #[cfg(not(test))]
        let _ = operation_index;
        let (parent_path, leaf) = parent_and_leaf(path.as_str())?;
        self.create_materialized_symbolic_link(parent_path, leaf, target.as_str(), path.as_str())?;
        self.record_named_entry_infallibly(position, MaterializedEntryPhaseV1::NamedUnidentified);
        #[cfg(test)]
        self.trigger_test_failpoint(
            TestOnlyPrivateMaterializationFailpointV1::SymbolicLinkNamedBeforeIdentity {
                operation_index,
            },
        )?;
        let created = {
            let parent = open_beneath_directory(self.staging_root.as_fd(), parent_path)?;
            symbolic_link_observation(parent.descriptor(), leaf)?
        };
        ensure!(
            created.identity.mount_id == self.staging_root_identity.mount_id,
            "private materialized OCI rootfs symbolic link crossed its staging mount"
        );
        self.transition_named_entry_to_identified(
            position,
            MaterializedEntryStateV1::SymbolicLink(MaterializedSymbolicLinkStateV1 {
                identity: created.identity,
                owner: created.owner,
                group: created.group,
                complete: false,
            }),
        )?;
        validate_current_finalizer_effective_ids(
            &self.finalizer_effective_ids,
            FinalizerEffectiveIdsObservationMutationV1::Unchanged,
        )?;
        #[cfg(not(test))]
        let (mapped_owner, mapped_group) = (created.owner, created.group);
        #[cfg(test)]
        let (mapped_owner, mapped_group) = {
            let mut mapped_owner = created.owner;
            let mut mapped_group = created.group;
            self.inject_test_only_mapped_owner_mismatch(
                TestOnlyPrivateMaterializationFailpointV1::SymbolicLinkMappedOwnerMismatch {
                    operation_index,
                },
                TestOnlyPrivateMaterializationFailpointV1::SymbolicLinkMappedGroupMismatch {
                    operation_index,
                },
                &mut mapped_owner,
                &mut mapped_group,
            );
            (mapped_owner, mapped_group)
        };
        validate_mapped_owner_prerequisite(
            mapped_owner,
            mapped_group,
            &self.finalizer_effective_ids,
            "private OCI rootfs symbolic link",
        )?;
        #[cfg(test)]
        self.trigger_test_failpoint(
            TestOnlyPrivateMaterializationFailpointV1::SymbolicLinkIdentityRecorded {
                operation_index,
            },
        )?;
        {
            let parent = open_beneath_directory(self.staging_root.as_fd(), parent_path)?;
            normalize_symbolic_link_mtime(parent.descriptor(), leaf)?;
        }
        let MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::SymbolicLink(state)) =
            &mut self.entries[position].phase
        else {
            anyhow::bail!("private symbolic-link cleanup journal changed kind")
        };
        state.complete = true;
        {
            let parent = open_beneath_directory(self.staging_root.as_fd(), parent_path)?;
            ensure!(
                symbolic_link_observation(parent.descriptor(), leaf)?.identity == created.identity,
                "private materialized OCI rootfs symbolic-link identity changed while normalizing mtime"
            );
        }
        #[cfg(test)]
        self.trigger_test_failpoint(
            TestOnlyPrivateMaterializationFailpointV1::SymbolicLinkSealRecorded { operation_index },
        )?;
        let parent = open_beneath_directory(self.staging_root.as_fd(), parent_path)?;
        validate_materialized_symbolic_link(
            parent.descriptor(),
            leaf,
            created.identity,
            created.owner,
            created.group,
            target.as_str(),
            self.staging_root_identity.mount_id,
        )
    }

    fn preflight_named_entry_effect(&self, position: usize) -> Result<()> {
        self.transaction.current_mount_namespace.reauthenticate()?;
        validate_current_finalizer_effective_ids(
            &self.finalizer_effective_ids,
            FinalizerEffectiveIdsObservationMutationV1::Unchanged,
        )?;
        let entry = self
            .entries
            .get(position)
            .context("private OCI rootfs creation left its preallocated journal")?;
        ensure!(
            matches!(&entry.phase, MaterializedEntryPhaseV1::Planned),
            "private OCI rootfs creation journal was reused"
        );
        if let Some(parent_position) = entry.parent_position {
            let parent = self
                .entries
                .get(parent_position)
                .context("private OCI rootfs parent left its preallocated journal")?;
            ensure!(
                matches!(
                    &parent.phase,
                    MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::Directory(_))
                ),
                "private OCI rootfs creation parent is not an identified directory"
            );
            ensure!(
                parent.created_child_count < parent.expected_child_count,
                "private OCI rootfs parent exhausted its authenticated child count"
            );
        } else {
            ensure!(
                self.root_created_child_count < self.root_expected_child_count,
                "private OCI rootfs staging exhausted its authenticated child count"
            );
        }
        Ok(())
    }

    fn record_named_entry_infallibly(&mut self, position: usize, phase: MaterializedEntryPhaseV1) {
        debug_assert!(matches!(
            &self.entries[position].phase,
            MaterializedEntryPhaseV1::Planned
        ));
        debug_assert!(matches!(
            &phase,
            MaterializedEntryPhaseV1::NamedUnidentified
                | MaterializedEntryPhaseV1::RegularCreatorFd(_)
        ));
        self.entries[position].phase = phase;
        let parent_position = self.entries[position].parent_position;
        if let Some(parent_position) = parent_position {
            let parent = &mut self.entries[parent_position];
            parent.created_child_count = parent
                .created_child_count
                .checked_add(1)
                .expect("preflight bounded the private OCI rootfs child count");
            debug_assert!(
                parent.created_child_count <= parent.expected_child_count,
                "private OCI rootfs parent exceeded its authenticated child count",
            );
        } else {
            self.root_created_child_count = self
                .root_created_child_count
                .checked_add(1)
                .expect("preflight bounded the private OCI rootfs root child count");
            debug_assert!(
                self.root_created_child_count <= self.root_expected_child_count,
                "private OCI rootfs staging exceeded its authenticated child count",
            );
        }
    }

    fn transition_named_entry_to_identified(
        &mut self,
        position: usize,
        state: MaterializedEntryStateV1,
    ) -> Result<()> {
        ensure!(
            matches!(
                &self.entries[position].phase,
                MaterializedEntryPhaseV1::NamedUnidentified
            ),
            "private OCI rootfs unidentified entry left its journal"
        );
        self.entries[position].phase = MaterializedEntryPhaseV1::Identified(state);
        Ok(())
    }

    fn transition_regular_creator_to_identified(
        &mut self,
        position: usize,
        state: MaterializedEntryStateV1,
    ) -> Result<File> {
        let previous = std::mem::replace(
            &mut self.entries[position].phase,
            MaterializedEntryPhaseV1::Identified(state),
        );
        let MaterializedEntryPhaseV1::RegularCreatorFd(file) = previous else {
            self.entries[position].phase = previous;
            anyhow::bail!("private regular creator descriptor left its journal")
        };
        Ok(file)
    }

    fn seal_directories_deepest_first(&mut self) -> Result<()> {
        for order_position in 0..self.directory_seal_order.len() {
            let position = self.directory_seal_order[order_position];
            #[cfg(test)]
            let operation_index = self.entries[position].operation_index;
            let mut state = match &self.entries[position].phase {
                MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::Directory(
                    state,
                )) => *state,
                _ => anyhow::bail!("private OCI rootfs directory seal journal is incomplete"),
            };
            let operation = self
                .transaction
                .operations
                .get(self.entries[position].operation_index)
                .context("private directory seal operation left its journal")?;
            #[cfg(test)]
            let operation_path = operation.path.clone();
            ensure!(
                matches!(operation.kind, StagedRootfsOperationKindV1::Directory),
                "private directory seal journal changed kind"
            );
            ensure!(
                self.entries[position].created_child_count
                    == self.entries[position].expected_child_count,
                "private OCI rootfs directory is incomplete before sealing"
            );
            let descriptor =
                open_materialized_directory(self.staging_root.as_fd(), operation.path.as_str())?;
            validate_materialized_directory(
                descriptor.as_fd(),
                state.identity,
                state.owner,
                state.group,
                false,
                self.staging_root_identity.mount_id,
                self.entries[position].created_child_count,
            )?;
            normalize_descriptor_mtime(descriptor.as_fd(), "materialized OCI rootfs directory")?;
            #[cfg(test)]
            self.trigger_test_failpoint(
                TestOnlyPrivateMaterializationFailpointV1::DirectoryMtimeRecorded {
                    operation_index,
                },
            )?;
            rustix::fs::fchmod(descriptor.as_fd(), MATERIALIZED_READ_EXECUTE_MODE)
                .context("cannot seal materialized OCI rootfs directory mode")?;
            state.sealed = true;
            self.entries[position].phase =
                MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::Directory(state));
            #[cfg(test)]
            self.test_only_runtime_metadata_seal_order
                .push(operation_path);
            #[cfg(test)]
            self.trigger_test_failpoint(
                TestOnlyPrivateMaterializationFailpointV1::DirectorySealRecorded {
                    operation_index,
                },
            )?;
            validate_materialized_directory(
                descriptor.as_fd(),
                state.identity,
                state.owner,
                state.group,
                true,
                self.staging_root_identity.mount_id,
                self.entries[position].created_child_count,
            )?;
            rustix::fs::fsync(descriptor.as_fd())
                .context("cannot synchronize materialized OCI rootfs directory")?;
        }
        Ok(())
    }

    fn seal_staging_root(&mut self) -> Result<()> {
        ensure!(
            self.root_created_child_count == self.root_expected_child_count,
            "private OCI rootfs root inventory is incomplete before sealing"
        );
        validate_private_staging_root(
            self.staging_root.as_fd(),
            self.staging_root_identity,
            self.staging_root_owner,
            self.staging_root_group,
            false,
            self.transaction.parent.identity().mount_id,
            self.root_created_child_count,
        )?;
        normalize_descriptor_mtime(self.staging_root.as_fd(), "private OCI rootfs staging root")?;
        #[cfg(test)]
        self.trigger_test_failpoint(
            TestOnlyPrivateMaterializationFailpointV1::StagingRootMtimeRecorded,
        )?;
        rustix::fs::fchmod(self.staging_root.as_fd(), MATERIALIZED_READ_EXECUTE_MODE)
            .context("cannot seal private OCI rootfs staging-root mode")?;
        // Record the successful effect before any fallible postcondition so a
        // later failure retains enough state to reopen the root for cleanup.
        self.staging_root_sealed = true;
        #[cfg(test)]
        self.test_only_runtime_metadata_seal_order
            .push("/".to_owned());
        #[cfg(test)]
        self.trigger_test_failpoint(
            TestOnlyPrivateMaterializationFailpointV1::StagingRootSealRecorded,
        )?;
        validate_private_staging_root(
            self.staging_root.as_fd(),
            self.staging_root_identity,
            self.staging_root_owner,
            self.staging_root_group,
            true,
            self.transaction.parent.identity().mount_id,
            self.root_created_child_count,
        )
    }

    fn validate_retained_tree(&self, require_complete: bool) -> Result<()> {
        #[cfg(test)]
        if let Some(mutation) = self.test_only_cleanup_custody_mutation.take() {
            self.test_only_validate_mutated_expected_custody(mutation)?;
        }
        self.transaction.current_mount_namespace.reauthenticate()?;
        self.transaction.parent.reauthenticate()?;
        ensure_absent(
            self.transaction.parent.descriptor(),
            &self.transaction.final_name,
            "OCI rootfs final destination while private materialization is retained",
        )?;
        let reopened = rustix::fs::openat2(
            self.transaction.parent.descriptor(),
            &self.staging_name,
            PINNED_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
            MATERIALIZED_RESOLVE_FLAGS,
        )
        .context("private OCI rootfs staging name is no longer a retained directory")?;
        ensure!(
            directory_identity(reopened.as_fd())? == self.staging_root_identity,
            "private OCI rootfs staging identity changed"
        );
        validate_private_staging_root(
            self.staging_root.as_fd(),
            self.staging_root_identity,
            self.staging_root_owner,
            self.staging_root_group,
            self.staging_root_sealed,
            self.transaction.parent.identity().mount_id,
            self.root_created_child_count,
        )?;
        ensure!(
            self.entries.len() == self.canonical_live_operation_indices.len(),
            "private OCI rootfs materialization journal changed length"
        );
        if require_complete {
            ensure!(
                self.staging_root_sealed,
                "private OCI rootfs staging root is not sealed"
            );
            ensure!(
                self.root_created_child_count == self.root_expected_child_count,
                "private OCI rootfs root inventory is incomplete"
            );
        }
        for (position, entry) in self.entries.iter().enumerate() {
            self.validate_retained_entry(position, entry, require_complete)?;
        }
        if require_complete {
            self.validate_recorded_mapped_owner_prerequisite()?;
        }
        Ok(())
    }

    fn validate_retained_entry(
        &self,
        position: usize,
        entry: &MaterializedEntryV1,
        require_complete: bool,
    ) -> Result<()> {
        ensure!(
            self.canonical_live_operation_indices.get(position) == Some(&entry.operation_index),
            "private OCI rootfs cleanup journal left its authenticated ordering"
        );
        let operation = self
            .transaction
            .operations
            .get(entry.operation_index)
            .context("materialized operation left its journal")?;
        if require_complete {
            ensure!(
                matches!(&entry.phase, MaterializedEntryPhaseV1::Identified(_)),
                "private OCI rootfs materialization is incomplete"
            );
            ensure!(
                entry.created_child_count == entry.expected_child_count,
                "private OCI rootfs directory inventory is incomplete"
            );
        }
        let state = match &entry.phase {
            MaterializedEntryPhaseV1::Planned => return Ok(()),
            MaterializedEntryPhaseV1::NamedUnidentified => {
                anyhow::bail!(
                    "private OCI rootfs named entry identity was not captured; quarantined name cannot be safely inspected or deleted"
                )
            }
            MaterializedEntryPhaseV1::RegularCreatorFd(_) => {
                anyhow::bail!("private OCI rootfs regular creator descriptor was not reconciled")
            }
            MaterializedEntryPhaseV1::Identified(state) => *state,
        };
        match (state, &operation.kind) {
            (
                MaterializedEntryStateV1::Directory(state),
                StagedRootfsOperationKindV1::Directory,
            ) => {
                let descriptor = open_materialized_directory(
                    self.staging_root.as_fd(),
                    operation.path.as_str(),
                )?;
                validate_materialized_directory(
                    descriptor.as_fd(),
                    state.identity,
                    state.owner,
                    state.group,
                    state.sealed,
                    self.staging_root_identity.mount_id,
                    entry.created_child_count,
                )?;
            }
            (
                MaterializedEntryStateV1::Regular(state),
                StagedRootfsOperationKindV1::Regular { extent_index },
            ) => self.validate_retained_regular(
                operation.path.as_str(),
                operation.mode,
                *extent_index,
                state,
                require_complete,
            )?,
            (
                MaterializedEntryStateV1::SymbolicLink(state),
                StagedRootfsOperationKindV1::SymbolicLink { target },
            ) => {
                if require_complete {
                    ensure!(
                        state.complete,
                        "private OCI rootfs symbolic link is incomplete"
                    );
                }
                let (parent_path, leaf) = parent_and_leaf(operation.path.as_str())?;
                let parent = open_beneath_directory(self.staging_root.as_fd(), parent_path)?;
                if require_complete || state.complete {
                    validate_materialized_symbolic_link(
                        parent.descriptor(),
                        leaf,
                        state.identity,
                        state.owner,
                        state.group,
                        target,
                        self.staging_root_identity.mount_id,
                    )?;
                } else {
                    validate_owned_materialized_symbolic_link(
                        parent.descriptor(),
                        leaf,
                        state.identity,
                        state.owner,
                        state.group,
                        target,
                        self.staging_root_identity.mount_id,
                    )?;
                }
            }
            _ => anyhow::bail!("private OCI rootfs cleanup journal changed kind"),
        }
        Ok(())
    }

    fn validate_retained_regular(
        &self,
        path: &str,
        mode: u32,
        extent_index: usize,
        state: MaterializedRegularStateV1,
        require_complete: bool,
    ) -> Result<()> {
        let descriptor = rustix::fs::openat2(
            self.staging_root.as_fd(),
            path,
            PINNED_REGULAR_FLAGS,
            rustix::fs::Mode::empty(),
            MATERIALIZED_RESOLVE_FLAGS,
        )
        .with_context(|| format!("cannot reopen materialized regular file {path}"))?;
        let file = File::from(descriptor);
        validate_owned_materialized_regular(
            &file,
            state.identity,
            state.owner,
            state.group,
            self.staging_root_identity.mount_id,
        )?;
        if require_complete || state.complete {
            ensure!(
                state.complete,
                "private OCI rootfs regular file is incomplete"
            );
            let extent = self
                .transaction
                .physical_regular_extents
                .get(extent_index)
                .context("materialized regular extent left its journal")?;
            validate_materialized_regular(
                &file,
                state.identity,
                state.owner,
                state.group,
                mode,
                extent,
                self.staging_root_identity.mount_id,
            )?;
        }
        Ok(())
    }

    fn refuse_unidentified_entry_custody(&self) -> Result<()> {
        ensure!(
            !self
                .entries
                .iter()
                .any(|entry| matches!(&entry.phase, MaterializedEntryPhaseV1::NamedUnidentified)),
            "private OCI rootfs named entry identity was not captured; quarantined name cannot be safely inspected or deleted"
        );
        Ok(())
    }

    fn reconcile_regular_creator_descriptors(&mut self) -> Result<()> {
        for position in 0..self.entries.len() {
            if !matches!(
                &self.entries[position].phase,
                MaterializedEntryPhaseV1::RegularCreatorFd(_)
            ) {
                continue;
            }
            let (identity, owner, group) = {
                let operation = self
                    .transaction
                    .operations
                    .get(self.entries[position].operation_index)
                    .context("regular creator cleanup operation left its journal")?;
                ensure!(
                    matches!(operation.kind, StagedRootfsOperationKindV1::Regular { .. }),
                    "regular creator cleanup journal changed kind"
                );
                let (parent_path, leaf) = parent_and_leaf(operation.path.as_str())?;
                let parent = open_beneath_directory(self.staging_root.as_fd(), parent_path)?;
                let reopened = rustix::fs::openat2(
                    parent.descriptor(),
                    leaf,
                    PINNED_REGULAR_FLAGS,
                    rustix::fs::Mode::empty(),
                    MATERIALIZED_RESOLVE_FLAGS,
                )
                .with_context(|| {
                    format!(
                        "cannot reconcile private OCI rootfs regular creator name {}",
                        operation.path
                    )
                })?;
                let reopened = File::from(reopened);
                let MaterializedEntryPhaseV1::RegularCreatorFd(creator) =
                    &self.entries[position].phase
                else {
                    anyhow::bail!("private regular creator descriptor left its journal")
                };
                let retained = regular_file_observation(creator)?;
                let named = regular_file_observation(&reopened)?;
                ensure!(
                    retained.identity == named.identity
                        && retained.identity.mount_id == self.staging_root_identity.mount_id
                        && retained.byte_length == named.byte_length
                        && retained.hard_link_count == 1
                        && named.hard_link_count == 1
                        && retained.mode == named.mode
                        && retained.owner == named.owner
                        && retained.group == named.group,
                    "private OCI rootfs regular creator descriptor does not identify the current name"
                );
                (retained.identity, retained.owner, retained.group)
            };
            let creator = self.transition_regular_creator_to_identified(
                position,
                MaterializedEntryStateV1::Regular(MaterializedRegularStateV1 {
                    identity,
                    owner,
                    group,
                    complete: false,
                }),
            )?;
            drop(creator);
        }
        Ok(())
    }

    fn cleanup_named_tree(&mut self) -> Result<()> {
        self.cleanup_started = true;
        self.transaction.current_mount_namespace.reauthenticate()?;
        if self.staging_root_unlinked {
            return self.finish_unlinked_staging_cleanup_retry();
        }
        self.refuse_unidentified_entry_custody()?;
        self.reconcile_regular_creator_descriptors()?;
        self.validate_retained_tree(false)?;
        self.reopen_staging_root_for_cleanup()?;
        self.reopen_directories_for_cleanup()?;
        self.validate_retained_tree(false)?;
        self.cleanup_owned_entries_postorder()?;
        self.cleanup_empty_staging_root()
    }

    fn finish_unlinked_staging_cleanup_retry(&self) -> Result<()> {
        self.transaction.current_mount_namespace.reauthenticate()?;
        self.transaction.parent.reauthenticate()?;
        ensure_absent(
            self.transaction.parent.descriptor(),
            &self.staging_name,
            "private OCI rootfs staging after cleanup retry",
        )?;
        rustix::fs::fsync(self.transaction.parent.descriptor())
            .context("cannot synchronize private OCI rootfs parent after cleanup retry")?;
        Ok(())
    }

    fn reopen_directories_for_cleanup(&mut self) -> Result<()> {
        // Reopen directory permissions from the root downward so every later
        // postorder removal remains descriptor-rooted even after successful seal.
        for order_position in (0..self.directory_seal_order.len()).rev() {
            let position = self.directory_seal_order[order_position];
            let mut state = match &self.entries[position].phase {
                MaterializedEntryPhaseV1::Identified(MaterializedEntryStateV1::Directory(
                    state,
                )) => *state,
                _ => continue,
            };
            let operation = self
                .transaction
                .operations
                .get(self.entries[position].operation_index)
                .context("cleanup directory operation left its authenticated journal")?;
            let descriptor =
                open_materialized_directory(self.staging_root.as_fd(), operation.path.as_str())?;
            validate_materialized_directory(
                descriptor.as_fd(),
                state.identity,
                state.owner,
                state.group,
                state.sealed,
                self.staging_root_identity.mount_id,
                self.entries[position].created_child_count,
            )?;
            if state.sealed {
                rustix::fs::fchmod(descriptor.as_fd(), PRIVATE_MATERIALIZED_DIRECTORY_MODE)
                    .context("cannot reopen owned OCI rootfs directory for cleanup")?;
                state.sealed = false;
                self.entries[position].phase = MaterializedEntryPhaseV1::Identified(
                    MaterializedEntryStateV1::Directory(state),
                );
                validate_materialized_directory(
                    descriptor.as_fd(),
                    state.identity,
                    state.owner,
                    state.group,
                    false,
                    self.staging_root_identity.mount_id,
                    self.entries[position].created_child_count,
                )?;
            }
        }
        Ok(())
    }

    fn reopen_staging_root_for_cleanup(&mut self) -> Result<()> {
        validate_private_staging_root(
            self.staging_root.as_fd(),
            self.staging_root_identity,
            self.staging_root_owner,
            self.staging_root_group,
            self.staging_root_sealed,
            self.transaction.parent.identity().mount_id,
            self.root_created_child_count,
        )?;
        if self.staging_root_sealed {
            rustix::fs::fchmod(
                self.staging_root.as_fd(),
                PRIVATE_MATERIALIZED_DIRECTORY_MODE,
            )
            .context("cannot reopen owned OCI rootfs staging root for cleanup")?;
            // As at seal time, advance custody before the first fallible
            // postcondition so a retry observes the current root mode.
            self.staging_root_sealed = false;
            #[cfg(test)]
            self.trigger_test_cleanup_failpoint(
                TestOnlyPrivateCleanupFailpointV1::StagingRootReopened,
            )?;
            validate_private_staging_root(
                self.staging_root.as_fd(),
                self.staging_root_identity,
                self.staging_root_owner,
                self.staging_root_group,
                false,
                self.transaction.parent.identity().mount_id,
                self.root_created_child_count,
            )?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn trigger_test_cleanup_failpoint(
        &self,
        reached: TestOnlyPrivateCleanupFailpointV1,
    ) -> Result<()> {
        if self.test_only_cleanup_failpoint.get() == Some(reached) {
            self.test_only_cleanup_failpoint.set(None);
            anyhow::bail!("injected private OCI rootfs cleanup failure at {reached:?}")
        }
        Ok(())
    }

    fn cleanup_owned_entries_postorder(&mut self) -> Result<()> {
        for position in (0..self.entries.len()).rev() {
            self.cleanup_owned_entry(position)?;
            #[cfg(test)]
            if self.test_only_cleanup_failpoint.get()
                == Some(
                    TestOnlyPrivateCleanupFailpointV1::AfterFirstEntryUnlinkedMountNamespaceMismatch,
                )
            {
                self.test_only_cleanup_failpoint.set(None);
                self.transaction
                    .current_mount_namespace
                    .test_only_arm_next_reauthentication_identity_mismatch();
            } else if self.test_only_cleanup_failpoint.get()
                == Some(
                    TestOnlyPrivateCleanupFailpointV1::AfterFirstEntryUnlinkedUserNamespaceMismatch,
                )
            {
                self.test_only_cleanup_failpoint.set(None);
                self.transaction
                    .current_mount_namespace
                    .test_only_arm_next_user_namespace_identity_mutation(
                        TestOnlyUserNamespaceIdentityMutationV1::Inode,
                    );
            } else if self.test_only_cleanup_failpoint.get()
                == Some(
                    TestOnlyPrivateCleanupFailpointV1::AfterFirstEntryUnlinkedSupplementaryGroupsMismatch,
                )
            {
                self.test_only_cleanup_failpoint.set(None);
                self.transaction
                    .current_mount_namespace
                    .test_only_arm_next_supplementary_groups_mismatch();
            } else if matches!(
                self.test_only_cleanup_failpoint.get(),
                Some(
                    TestOnlyPrivateCleanupFailpointV1::AfterFirstEntryUnlinkedFsuidMismatch
                        | TestOnlyPrivateCleanupFailpointV1::AfterFirstEntryUnlinkedFsgidMismatch
                )
            ) {
                let mutation = if self.test_only_cleanup_failpoint.get()
                    == Some(TestOnlyPrivateCleanupFailpointV1::AfterFirstEntryUnlinkedFsuidMismatch)
                {
                    TestOnlyFilesystemCredentialMutationV1::Fsuid
                } else {
                    TestOnlyFilesystemCredentialMutationV1::Fsgid
                };
                self.test_only_cleanup_failpoint.set(None);
                self.transaction
                    .current_mount_namespace
                    .test_only_arm_next_filesystem_credential_mismatch(mutation);
            }
        }
        Ok(())
    }

    fn cleanup_owned_entry(&mut self, position: usize) -> Result<()> {
        let state = match &self.entries[position].phase {
            MaterializedEntryPhaseV1::Planned => return Ok(()),
            MaterializedEntryPhaseV1::NamedUnidentified => {
                anyhow::bail!(
                    "private OCI rootfs named entry identity was not captured; quarantined name cannot be safely deleted"
                )
            }
            MaterializedEntryPhaseV1::RegularCreatorFd(_) => {
                anyhow::bail!("private OCI rootfs regular creator descriptor was not reconciled")
            }
            MaterializedEntryPhaseV1::Identified(state) => *state,
        };
        self.transaction.current_mount_namespace.reauthenticate()?;
        let operation = self
            .transaction
            .operations
            .get(self.entries[position].operation_index)
            .context("cleanup operation left its authenticated journal")?;
        let (parent_path, leaf) = parent_and_leaf(operation.path.as_str())?;
        let parent = open_beneath_directory(self.staging_root.as_fd(), parent_path)?;
        let unlink_flags = self.validated_cleanup_unlink_flags(
            position,
            state,
            operation,
            parent.descriptor(),
            leaf,
        )?;
        self.transaction.current_mount_namespace.reauthenticate()?;

        // Linux has no unlink-by-open-handle primitive. Revalidate the
        // descriptor/statx identity immediately before unlinkat; a process
        // able to mutate this 0700 same-user tree could still race the name
        // between that check and the syscall, so observed substitutions are
        // refused but the kernel cannot eliminate the final name race here.
        rustix::fs::unlinkat(parent.descriptor(), leaf, unlink_flags)
            .with_context(|| format!("cannot unlink owned cleanup entry {}", operation.path))?;
        // Advance custody before the first fallible post-unlink observation,
        // so retry never targets a name whose owned inode was already removed.
        let parent_position = self.entries[position].parent_position;
        self.entries[position].phase = MaterializedEntryPhaseV1::Planned;
        if let Some(parent_position) = parent_position {
            self.entries[parent_position].created_child_count = self.entries[parent_position]
                .created_child_count
                .checked_sub(1)
                .expect("authenticated cleanup parent count remains positive");
        } else {
            self.root_created_child_count = self
                .root_created_child_count
                .checked_sub(1)
                .expect("authenticated cleanup root count remains positive");
        }
        ensure_absent(
            parent.descriptor(),
            OsStr::new(leaf),
            "owned private OCI rootfs cleanup entry after unlink",
        )?;
        Ok(())
    }

    fn validated_cleanup_unlink_flags(
        &self,
        position: usize,
        state: MaterializedEntryStateV1,
        operation: &StagedRootfsOperationV1,
        parent: BorrowedFd<'_>,
        leaf: &str,
    ) -> Result<rustix::fs::AtFlags> {
        let unlink_flags = match (state, &operation.kind) {
            (
                MaterializedEntryStateV1::Directory(state),
                StagedRootfsOperationKindV1::Directory,
            ) => {
                ensure!(
                    self.entries[position].created_child_count == 0,
                    "owned private OCI rootfs cleanup directory is not postorder-empty"
                );
                let descriptor = rustix::fs::openat2(
                    parent,
                    leaf,
                    PINNED_DIRECTORY_FLAGS,
                    rustix::fs::Mode::empty(),
                    MATERIALIZED_RESOLVE_FLAGS,
                )
                .with_context(|| {
                    format!("cannot pin owned cleanup directory {}", operation.path)
                })?;
                validate_materialized_directory(
                    descriptor.as_fd(),
                    state.identity,
                    state.owner,
                    state.group,
                    false,
                    self.staging_root_identity.mount_id,
                    0,
                )?;
                rustix::fs::AtFlags::REMOVEDIR
            }
            (
                MaterializedEntryStateV1::Regular(state),
                StagedRootfsOperationKindV1::Regular { .. },
            ) => {
                let descriptor = rustix::fs::openat2(
                    parent,
                    leaf,
                    PINNED_REGULAR_FLAGS,
                    rustix::fs::Mode::empty(),
                    MATERIALIZED_RESOLVE_FLAGS,
                )
                .with_context(|| format!("cannot pin owned cleanup file {}", operation.path))?;
                let file = File::from(descriptor);
                validate_owned_materialized_regular(
                    &file,
                    state.identity,
                    state.owner,
                    state.group,
                    self.staging_root_identity.mount_id,
                )?;
                rustix::fs::AtFlags::empty()
            }
            (
                MaterializedEntryStateV1::SymbolicLink(state),
                StagedRootfsOperationKindV1::SymbolicLink { target },
            ) => {
                validate_owned_materialized_symbolic_link(
                    parent,
                    leaf,
                    state.identity,
                    state.owner,
                    state.group,
                    target,
                    self.staging_root_identity.mount_id,
                )?;
                rustix::fs::AtFlags::empty()
            }
            _ => anyhow::bail!("owned private OCI rootfs cleanup journal changed kind"),
        };
        Ok(unlink_flags)
    }

    fn cleanup_empty_staging_root(&mut self) -> Result<()> {
        self.transaction.current_mount_namespace.reauthenticate()?;
        ensure!(
            self.root_created_child_count == 0
                && directory_entry_count(self.staging_root.as_fd(), 0)? == 0,
            "private OCI rootfs staging is not empty after owned cleanup"
        );
        rustix::fs::fsync(self.staging_root.as_fd())
            .context("cannot synchronize cleaned private OCI rootfs staging")?;
        self.transaction.parent.reauthenticate()?;
        ensure_absent(
            self.transaction.parent.descriptor(),
            &self.transaction.final_name,
            "OCI rootfs final destination before private staging cleanup",
        )?;
        let reopened = rustix::fs::openat2(
            self.transaction.parent.descriptor(),
            &self.staging_name,
            PINNED_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
            MATERIALIZED_RESOLVE_FLAGS,
        )
        .context("cannot reauthenticate private OCI rootfs staging before cleanup")?;
        ensure!(
            directory_identity(reopened.as_fd())? == self.staging_root_identity,
            "private OCI rootfs staging identity changed before cleanup"
        );
        validate_private_staging_root(
            reopened.as_fd(),
            self.staging_root_identity,
            self.staging_root_owner,
            self.staging_root_group,
            false,
            self.transaction.parent.identity().mount_id,
            0,
        )?;
        self.transaction.current_mount_namespace.reauthenticate()?;
        rustix::fs::unlinkat(
            self.transaction.parent.descriptor(),
            &self.staging_name,
            rustix::fs::AtFlags::REMOVEDIR,
        )
        .context("cannot unlink empty private OCI rootfs staging")?;
        // From this point retry may observe the name but must never unlink it:
        // a same-user process could already have installed a replacement.
        self.staging_root_unlinked = true;
        #[cfg(test)]
        if self.test_only_materialization_failpoint
            == Some(
                TestOnlyPrivateMaterializationFailpointV1::StagingRootUnlinkedWithNextMountNamespaceMismatch,
            )
        {
            self.test_only_materialization_failpoint = None;
            self.transaction
                .current_mount_namespace
                .test_only_arm_next_reauthentication_identity_mismatch();
            anyhow::bail!(
                "injected private OCI rootfs materialization failure at {:?}",
                TestOnlyPrivateMaterializationFailpointV1::StagingRootUnlinkedWithNextMountNamespaceMismatch
            );
        }
        #[cfg(test)]
        self.trigger_test_failpoint(
            TestOnlyPrivateMaterializationFailpointV1::StagingRootUnlinked,
        )?;
        ensure_absent(
            self.transaction.parent.descriptor(),
            &self.staging_name,
            "private OCI rootfs staging after cleanup",
        )?;
        rustix::fs::fsync(self.transaction.parent.descriptor())
            .context("cannot synchronize private OCI rootfs parent after cleanup")?;
        Ok(())
    }

    fn fail_after_named_effect(mut self, primary: anyhow::Error) -> anyhow::Error {
        if let Err(cleanup) = self.cleanup_named_tree() {
            return anyhow::Error::new(PrivateOciRootfsCleanupFailureV1::recoverable(
                primary.context(format!(
                    "private OCI rootfs materialization cleanup is incomplete: {cleanup:#}"
                )),
                self,
            ));
        }
        match self.finish_logical_abandonment() {
            Ok(_) => primary,
            Err(failure) => {
                let PrivateOciRootfsFailedV1 {
                    error: abandonment_error,
                    abandonment,
                } = *failure;
                anyhow::Error::new(PrivateOciRootfsFailedV1 {
                    error: primary.context(format!(
                        "private OCI rootfs logical abandonment also failed: {abandonment_error:#}"
                    )),
                    abandonment,
                })
            }
        }
    }

    fn finish_logical_abandonment(
        self,
    ) -> std::result::Result<PrivateOciRootfsAbandonedV1, Box<PrivateOciRootfsFailedV1>> {
        let Self {
            mut transaction,
            finalizer_effective_ids: _,
            canonical_live_operation_indices,
            counters,
            authenticated_logical_projection_sha256,
            staging_name: _,
            staging_root: _,
            staging_root_identity: _,
            staging_root_owner: _,
            staging_root_group: _,
            root_expected_child_count: _,
            root_created_child_count: _,
            entries: _,
            directory_seal_order: _,
            staging_root_sealed: _,
            cleanup_started: _,
            staging_root_unlinked: _,
            #[cfg(test)]
            test_only_materialization_failpoint,
            #[cfg(test)]
                test_only_cleanup_custody_mutation: _,
            #[cfg(test)]
                test_only_cleanup_failpoint: _,
            #[cfg(test)]
                test_only_runtime_metadata_seal_order: _,
        } = self;
        let authenticated_live_entries = u64::try_from(canonical_live_operation_indices.len())
            .expect("Linux usize always fits in u64");
        #[cfg(test)]
        let injected = if test_only_materialization_failpoint
            == Some(TestOnlyPrivateMaterializationFailpointV1::LogicalSpoolCustodyDriftBeforeAbandonment)
        {
            rustix::fs::fchmod(
                transaction.spool.as_fd(),
                rustix::fs::Mode::RUSR
                    | rustix::fs::Mode::WUSR
                    | rustix::fs::Mode::RGRP,
            )
            .context("cannot inject logical spool custody drift before abandonment")
        } else {
            Ok(())
        };
        #[cfg(not(test))]
        let injected: Result<()> = Ok(());
        let candidate = injected.and_then(|()| {
            transaction.revalidate_authenticated_projection(
                &canonical_live_operation_indices,
                counters,
                authenticated_logical_projection_sha256,
            )
        });
        let mut abandonment = transaction.abandon();
        abandonment.authenticated_live_entries = Some(authenticated_live_entries);
        abandonment.authenticated_logical_projection_sha256 =
            Some(authenticated_logical_projection_sha256);
        finish_rootfs_abandonment(candidate, abandonment)
    }
}

impl AuthenticatedPrivateOciRetainedPhysicalRootfsV1 {
    pub(super) fn reauthenticate_static_startup_dependencies(
        &self,
        expectation: &B4PositiveOciImageLayoutV1,
    ) -> Result<()> {
        let validation = (|| {
            let rederived = self
                .rootfs
                .authenticate_expected_rootfs_identity(expectation)?;
            ensure!(
                rederived == self.static_startup_dependencies,
                "retained static startup dependency closure differs from its rederived identity"
            );
            Ok(())
        })();
        merge_rootfs_revalidation(
            validation,
            self.rootfs.validate_retained_tree(true),
            "retained private OCI rootfs final revalidation also failed",
        )
    }

    #[cfg(test)]
    pub(super) fn test_only_reauthenticate_static_startup_dependencies(
        &self,
        expectation: &StartupClosureTestExpectationV1<'_>,
    ) -> Result<()> {
        let validation = (|| {
            let rederived = self
                .rootfs
                .authenticate_test_static_startup_dependency_identity(expectation)?;
            ensure!(
                rederived == self.static_startup_dependencies,
                "retained static startup dependency closure differs from its rederived identity"
            );
            Ok(())
        })();
        merge_rootfs_revalidation(
            validation,
            self.rootfs.validate_retained_tree(true),
            "retained private OCI rootfs test final revalidation also failed",
        )
    }

    #[cfg(test)]
    pub(super) fn test_only_mutate_startup_baseline_sha256(
        &mut self,
        baseline: TestOnlyRetainedStartupBaselineV1,
    ) {
        let closure = match baseline {
            TestOnlyRetainedStartupBaselineV1::Launcher => {
                &mut self.static_startup_dependencies.launcher
            }
            TestOnlyRetainedStartupBaselineV1::Compiler => {
                &mut self.static_startup_dependencies.compiler
            }
        }
        .as_mut()
        .expect("test retained rootfs has the selected startup baseline");
        let root = closure
            .nodes
            .first_mut()
            .expect("test retained startup baseline has one root node");
        root.sha256[0] ^= 1;
    }

    #[cfg(test)]
    pub(super) fn test_only_arm_regular_owner_custody_mutation(
        &self,
        relative_path: &str,
    ) -> Result<()> {
        let position = self.rootfs.live_entry_position(relative_path)?;
        let entry = self
            .rootfs
            .entries
            .get(position)
            .context("test retained regular mutation left the materialization journal")?;
        let operation = self
            .rootfs
            .transaction
            .operations
            .get(entry.operation_index)
            .context("test retained regular mutation left the operation journal")?;
        ensure!(
            matches!(operation.kind, StagedRootfsOperationKindV1::Regular { .. }),
            "test retained regular mutation selected a non-regular entry"
        );
        self.rootfs.test_only_arm_cleanup_custody_mutation(
            TestOnlyPhysicalCustodyMutationV1::RegularObservedOwner {
                operation_index: entry.operation_index,
            },
        );
        Ok(())
    }

    pub(super) fn cleanup(
        self,
    ) -> std::result::Result<PrivateOciRootfsAbandonedV1, PrivateOciRootfsCleanupFailureV1> {
        self.rootfs.cleanup()
    }
}

fn reserve_startup_object(
    limits: StartupDependencyClosureLimitsV1,
    counters: &mut StaticStartupDependencyCountersV1,
    byte_length: u64,
    label: &str,
) -> Result<()> {
    let distinct_objects =
        limits.checked_add_distinct_objects(counters.distinct_objects, 1, label)?;
    let aggregate_distinct_object_bytes = limits.checked_add_distinct_object_bytes(
        counters.aggregate_distinct_object_bytes,
        byte_length,
        label,
    )?;
    counters.distinct_objects = distinct_objects;
    counters.aggregate_distinct_object_bytes = aggregate_distinct_object_bytes;
    Ok(())
}

#[cfg(test)]
mod startup_counter_tests {
    use super::{StaticStartupDependencyCountersV1, reserve_startup_object};
    use crate::b4_campaign_executor::artifact_import_contract::startup_dependency_closure_limits_v1;

    #[test]
    fn startup_consumer_counters_accept_exact_bounds_and_reject_max_plus_one() {
        let limits = startup_dependency_closure_limits_v1();

        let mut objects = StaticStartupDependencyCountersV1::default();
        for _ in 0..limits.maximum_distinct_objects() {
            reserve_startup_object(limits, &mut objects, 0, "object-bound fixture").unwrap();
        }
        assert!(reserve_startup_object(limits, &mut objects, 0, "object-bound fixture").is_err());

        let mut bytes = StaticStartupDependencyCountersV1::default();
        reserve_startup_object(
            limits,
            &mut bytes,
            limits.maximum_aggregate_distinct_object_bytes(),
            "byte-bound fixture",
        )
        .unwrap();
        assert!(reserve_startup_object(limits, &mut bytes, 1, "byte-bound fixture").is_err());

        assert_eq!(
            limits
                .checked_add_dependency_edges(
                    limits.maximum_dependency_edges() - 1,
                    1,
                    "edge-bound fixture",
                )
                .unwrap(),
            limits.maximum_dependency_edges()
        );
        assert!(
            limits
                .checked_add_dependency_edges(
                    limits.maximum_dependency_edges(),
                    1,
                    "edge-bound fixture",
                )
                .is_err()
        );
        limits
            .validate_depth(limits.maximum_depth(), "depth-bound fixture")
            .unwrap();
        assert!(
            limits
                .validate_depth(limits.maximum_depth() + 1, "depth-bound fixture")
                .is_err()
        );
    }
}

fn own_startup_elf_projection(common: &Amd64ElfCommonInspectionV1) -> StartupElfProjectionV1 {
    StartupElfProjectionV1 {
        elf_type: common.elf_type(),
        os_abi: common.os_abi(),
        program_header_count: common.program_header_count(),
        section_header_count: common.section_header_count(),
        load_segment_count: common.load_segment_count(),
        executable_load_segment_count: common.executable_load_segment_count(),
        entry_point_is_zero: common.entry_point_is_zero(),
        entry_point_in_executable_load: common.entry_point_in_executable_load(),
        interpreter_segment_count: common.interpreter_segment_count(),
        dynamic_segment_count: common.dynamic_segment_count(),
        gnu_stack_segment_count: common.gnu_stack_segment_count(),
    }
}

fn own_startup_dynamic_projection(
    dynamic: &Amd64ElfStartupDynamicInspectionV1<'_>,
) -> Result<StartupDynamicProjectionV1> {
    let mut accepted_records = Vec::new();
    accepted_records
        .try_reserve_exact(dynamic.accepted_records().len())
        .context("cannot reserve bounded startup dynamic-record projection")?;
    for record in dynamic.accepted_records() {
        accepted_records.push((record.d_tag(), record.d_un()));
    }
    let mut accepted_tags = Vec::new();
    accepted_tags
        .try_reserve_exact(dynamic.accepted_tags().len())
        .context("cannot reserve bounded startup typed dynamic-tag projection")?;
    for tag in dynamic.accepted_tags() {
        accepted_tags.push(*tag);
    }
    let mut needed_libraries = Vec::new();
    needed_libraries
        .try_reserve_exact(dynamic.needed_libraries().len())
        .context("cannot reserve bounded startup DT_NEEDED projection")?;
    for needed in dynamic.needed_libraries() {
        needed_libraries.push(StartupNeededLibraryV1 {
            dynamic_ordinal: needed.dynamic_ordinal(),
            requested_name: try_owned_startup_string(needed.requested_name(), "DT_NEEDED name")?,
        });
    }
    let (runpath_raw, runpath_components) = match dynamic.runpath() {
        Some(runpath) => {
            let mut components = Vec::new();
            components
                .try_reserve_exact(runpath.components().len())
                .context("cannot reserve bounded startup RUNPATH projection")?;
            for component in runpath.components() {
                components.push(match component {
                    Amd64ElfRunpathComponentV1::Absolute(path) => {
                        StartupRunpathComponentV1::Absolute(try_owned_startup_string(
                            path,
                            "absolute RUNPATH component",
                        )?)
                    }
                    Amd64ElfRunpathComponentV1::OriginRelative { raw, suffix } => {
                        StartupRunpathComponentV1::OriginRelative {
                            raw: try_owned_startup_string(raw, "ORIGIN RUNPATH component")?,
                            suffix: try_owned_startup_string(suffix, "ORIGIN RUNPATH suffix")?,
                        }
                    }
                });
            }
            (
                Some(try_owned_startup_string(runpath.raw(), "DT_RUNPATH value")?),
                components,
            )
        }
        None => (None, Vec::new()),
    };
    Ok(StartupDynamicProjectionV1 {
        accepted_records,
        accepted_tags,
        needed_libraries,
        soname: dynamic
            .soname()
            .map(|soname| try_owned_startup_string(soname, "DT_SONAME value"))
            .transpose()?,
        runpath_raw,
        runpath_components,
    })
}

fn try_owned_startup_string(value: &str, label: &str) -> Result<String> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .with_context(|| format!("cannot reserve bounded startup {label}"))?;
    owned.push_str(value);
    Ok(owned)
}

fn expanded_startup_search_directories(
    requester: &StaticStartupDependencyNodeV1,
) -> Result<Vec<String>> {
    let mut directories = Vec::new();
    directories
        .try_reserve_exact(
            requester
                .dynamic
                .runpath_components
                .len()
                .checked_add(STARTUP_DEFAULT_SEARCH_DIRECTORIES.len())
                .context("startup search directory count overflowed")?,
        )
        .context("cannot retain bounded startup search directories")?;
    for component in &requester.dynamic.runpath_components {
        match component {
            StartupRunpathComponentV1::Absolute(path) => directories.push(path.clone()),
            StartupRunpathComponentV1::OriginRelative { raw, suffix } => {
                ensure!(
                    requester.resolution.symbolic_link_chain.is_empty(),
                    "startup object reached through a symbolic link cannot use {raw}"
                );
                let (origin, _) = requester
                    .resolution
                    .final_path
                    .rsplit_once('/')
                    .context("startup object final path has no parent")?;
                let origin = if origin.is_empty() { "/" } else { origin };
                directories.push(normalize_origin_runpath(origin, suffix)?);
            }
        }
    }
    directories.extend(
        STARTUP_DEFAULT_SEARCH_DIRECTORIES
            .into_iter()
            .map(str::to_owned),
    );
    Ok(directories)
}

fn validate_owned_startup_dynamic_for_resolution(
    resolution: &ResolvedRootfsPathV1,
    dynamic: &StartupDynamicProjectionV1,
) -> Result<()> {
    let uses_origin = dynamic
        .runpath_components
        .iter()
        .any(|component| matches!(component, StartupRunpathComponentV1::OriginRelative { .. }));
    ensure!(
        !uses_origin || resolution.symbolic_link_chain.is_empty(),
        "startup object reached through a symbolic link cannot use ORIGIN"
    );
    if uses_origin {
        let (origin, _) = resolution
            .final_path
            .rsplit_once('/')
            .context("startup object final path has no parent")?;
        let origin = if origin.is_empty() { "/" } else { origin };
        for component in &dynamic.runpath_components {
            if let StartupRunpathComponentV1::OriginRelative { suffix, .. } = component {
                normalize_origin_runpath(origin, suffix)?;
            }
        }
    }
    Ok(())
}

fn normalize_origin_runpath(origin: &str, suffix: &str) -> Result<String> {
    let mut components = if origin == "/" {
        Vec::new()
    } else {
        origin[1..].split('/').map(str::to_owned).collect()
    };
    if let Some(suffix) = suffix.strip_prefix('/') {
        for component in suffix.split('/') {
            apply_rootfs_resolution_component(&mut components, component)?;
        }
    } else {
        ensure!(
            suffix.is_empty(),
            "ORIGIN RUNPATH suffix is not slash-prefixed"
        );
    }
    ensure!(
        !components.is_empty(),
        "ORIGIN RUNPATH normalizes to the unsealed implicit root directory"
    );
    Ok(format!("/{}", components.join("/")))
}

fn canonical_rootfs_basename(absolute_path: &str) -> Result<&str> {
    let components = canonical_rootfs_requirement_components(absolute_path)?;
    components
        .last()
        .copied()
        .context("canonical rootfs path has no basename")
}

fn component_paths_overlap(left: &str, right: &str) -> bool {
    fn contains_or_equals(parent: &str, child: &str) -> bool {
        parent == child
            || parent == "/"
            || child
                .strip_prefix(parent)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }
    contains_or_equals(left, right) || contains_or_equals(right, left)
}

fn runtime_mount_overlays_relative_component_path(
    relative_walked_path: &str,
    absolute_mount_target: &str,
) -> bool {
    let Some(relative_mount_target) = absolute_mount_target.strip_prefix('/') else {
        return true;
    };
    relative_mount_target.is_empty()
        || relative_mount_target == relative_walked_path
        || relative_walked_path
            .strip_prefix(relative_mount_target)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn startup_dynamic_tag_matches_raw(
    raw_tag: i64,
    accepted_tag: Amd64ElfAcceptedDynamicTagV1,
) -> bool {
    match accepted_tag {
        Amd64ElfAcceptedDynamicTagV1::Null => raw_tag == elf::abi::DT_NULL,
        Amd64ElfAcceptedDynamicTagV1::Needed => raw_tag == elf::abi::DT_NEEDED,
        Amd64ElfAcceptedDynamicTagV1::PltRelSize => raw_tag == elf::abi::DT_PLTRELSZ,
        Amd64ElfAcceptedDynamicTagV1::PltGot => raw_tag == elf::abi::DT_PLTGOT,
        Amd64ElfAcceptedDynamicTagV1::Hash => raw_tag == elf::abi::DT_HASH,
        Amd64ElfAcceptedDynamicTagV1::StringTable => raw_tag == elf::abi::DT_STRTAB,
        Amd64ElfAcceptedDynamicTagV1::SymbolTable => raw_tag == elf::abi::DT_SYMTAB,
        Amd64ElfAcceptedDynamicTagV1::Rela => raw_tag == elf::abi::DT_RELA,
        Amd64ElfAcceptedDynamicTagV1::RelaSize => raw_tag == elf::abi::DT_RELASZ,
        Amd64ElfAcceptedDynamicTagV1::RelaEntrySize => raw_tag == elf::abi::DT_RELAENT,
        Amd64ElfAcceptedDynamicTagV1::StringTableSize => raw_tag == elf::abi::DT_STRSZ,
        Amd64ElfAcceptedDynamicTagV1::SymbolEntrySize => raw_tag == elf::abi::DT_SYMENT,
        Amd64ElfAcceptedDynamicTagV1::Init => raw_tag == elf::abi::DT_INIT,
        Amd64ElfAcceptedDynamicTagV1::Fini => raw_tag == elf::abi::DT_FINI,
        Amd64ElfAcceptedDynamicTagV1::Soname => raw_tag == elf::abi::DT_SONAME,
        Amd64ElfAcceptedDynamicTagV1::Rel => raw_tag == elf::abi::DT_REL,
        Amd64ElfAcceptedDynamicTagV1::RelSize => raw_tag == elf::abi::DT_RELSZ,
        Amd64ElfAcceptedDynamicTagV1::RelEntrySize => raw_tag == elf::abi::DT_RELENT,
        Amd64ElfAcceptedDynamicTagV1::PltRel => raw_tag == elf::abi::DT_PLTREL,
        Amd64ElfAcceptedDynamicTagV1::Debug => raw_tag == elf::abi::DT_DEBUG,
        Amd64ElfAcceptedDynamicTagV1::JumpRel => raw_tag == elf::abi::DT_JMPREL,
        Amd64ElfAcceptedDynamicTagV1::BindNow => raw_tag == elf::abi::DT_BIND_NOW,
        Amd64ElfAcceptedDynamicTagV1::InitArray => raw_tag == elf::abi::DT_INIT_ARRAY,
        Amd64ElfAcceptedDynamicTagV1::FiniArray => raw_tag == elf::abi::DT_FINI_ARRAY,
        Amd64ElfAcceptedDynamicTagV1::InitArraySize => raw_tag == elf::abi::DT_INIT_ARRAYSZ,
        Amd64ElfAcceptedDynamicTagV1::FiniArraySize => raw_tag == elf::abi::DT_FINI_ARRAYSZ,
        Amd64ElfAcceptedDynamicTagV1::Runpath => raw_tag == elf::abi::DT_RUNPATH,
        Amd64ElfAcceptedDynamicTagV1::Flags => raw_tag == elf::abi::DT_FLAGS,
        Amd64ElfAcceptedDynamicTagV1::PreinitArray => raw_tag == elf::abi::DT_PREINIT_ARRAY,
        Amd64ElfAcceptedDynamicTagV1::PreinitArraySize => raw_tag == elf::abi::DT_PREINIT_ARRAYSZ,
        Amd64ElfAcceptedDynamicTagV1::SymbolTableSectionIndex => {
            raw_tag == elf::abi::DT_SYMTAB_SHNDX
        }
        Amd64ElfAcceptedDynamicTagV1::GnuHash => raw_tag == elf::abi::DT_GNU_HASH,
        Amd64ElfAcceptedDynamicTagV1::VersionSymbol => raw_tag == elf::abi::DT_VERSYM,
        Amd64ElfAcceptedDynamicTagV1::RelaCount => raw_tag == elf::abi::DT_RELACOUNT,
        Amd64ElfAcceptedDynamicTagV1::RelCount => raw_tag == elf::abi::DT_RELCOUNT,
        Amd64ElfAcceptedDynamicTagV1::Flags1 => raw_tag == elf::abi::DT_FLAGS_1,
        Amd64ElfAcceptedDynamicTagV1::VersionDefinition => raw_tag == elf::abi::DT_VERDEF,
        Amd64ElfAcceptedDynamicTagV1::VersionDefinitionCount => raw_tag == elf::abi::DT_VERDEFNUM,
        Amd64ElfAcceptedDynamicTagV1::VersionNeed => raw_tag == elf::abi::DT_VERNEED,
        Amd64ElfAcceptedDynamicTagV1::VersionNeedCount => raw_tag == elf::abi::DT_VERNEEDNUM,
    }
}

fn validate_static_startup_dependency_closure_identity(
    closure: &StaticStartupDependencyClosureV1,
) -> Result<()> {
    ensure!(
        closure.nodes.len() >= 2,
        "static startup dependency closure omits a seed node"
    );
    for (index, node) in closure.nodes.iter().enumerate() {
        validate_static_startup_dependency_node_identity(index, node)?;
    }
    for edge in &closure.edges {
        validate_static_startup_dependency_edge_identity(closure, edge)?;
    }
    Ok(())
}

fn validate_static_startup_dependency_node_identity(
    index: usize,
    node: &StaticStartupDependencyNodeV1,
) -> Result<()> {
    ensure!(
        node.byte_length > 0
            && node.sha256.len() == SHA256_BYTES
            && node.elf.program_header_count >= node.elf.load_segment_count
            && node.elf.load_segment_count >= node.elf.executable_load_segment_count
            && node.elf.dynamic_segment_count == 1
            && node.elf.gnu_stack_segment_count == 1
            && matches!(
                node.elf.os_abi,
                Amd64ElfOsAbiV1::SystemV | Amd64ElfOsAbiV1::Linux
            )
            && node.dynamic.accepted_records.len() == node.dynamic.accepted_tags.len()
            && node
                .dynamic
                .accepted_records
                .iter()
                .zip(&node.dynamic.accepted_tags)
                .all(|((raw_tag, _), accepted_tag)| {
                    startup_dynamic_tag_matches_raw(*raw_tag, *accepted_tag)
                })
            && node
                .dynamic
                .accepted_records
                .last()
                .is_some_and(|(tag, _)| *tag == elf::abi::DT_NULL)
            && node.dynamic.accepted_tags.last() == Some(&Amd64ElfAcceptedDynamicTagV1::Null),
        "static startup node omits part of its closed ELF projection"
    );
    B4ImmutableArtifactRoleV1::Amd64Elf(Amd64ElfPolicyV1::Runtime)
        .limits()
        .require_amd64_elf("static startup node")?
        .validate_section_header_count(node.elf.section_header_count, "static startup node")?;
    if index == 0 {
        ensure!(
            matches!(
                node.elf.elf_type,
                Amd64ElfTypeV1::Executable | Amd64ElfTypeV1::SharedObject
            ) && node.elf.executable_load_segment_count >= 1
                && node.elf.entry_point_in_executable_load
                && node.elf.interpreter_segment_count == 1
                && node.dynamic.soname.is_none(),
            "startup executable node differs from its runtime ELF projection"
        );
    } else {
        ensure!(
            node.elf.elf_type == Amd64ElfTypeV1::SharedObject
                && node.elf.interpreter_segment_count == 0
                && (node.elf.entry_point_is_zero || node.elf.entry_point_in_executable_load)
                && node.dynamic.soname.is_some(),
            "startup DSO node differs from its DSO ELF projection"
        );
    }
    ensure!(
        node.resolution.symbolic_link_chain.iter().all(|hop| {
            hop.canonical_link_path.starts_with('/')
                && !hop.exact_target.is_empty()
                && hop.normalized_target_path.starts_with('/')
        }),
        "startup node symbolic-link chain is incomplete"
    );
    let expected_runpath = node
        .dynamic
        .runpath_raw
        .as_ref()
        .map_or(0, |raw| raw.split(':').count());
    ensure!(
        expected_runpath == node.dynamic.runpath_components.len(),
        "startup node RUNPATH raw value differs from its typed components"
    );
    Ok(())
}

fn validate_static_startup_dependency_edge_identity(
    closure: &StaticStartupDependencyClosureV1,
    edge: &StaticStartupDependencyEdgeV1,
) -> Result<()> {
    let requester = closure
        .nodes
        .get(edge.requester)
        .context("startup edge requester is outside the node vector")?;
    let selected = closure
        .nodes
        .get(edge.selected)
        .context("startup edge selection is outside the node vector")?;
    ensure!(
        selected.dynamic.soname.as_deref() == Some(edge.requested_name.as_str()),
        "startup edge selected node SONAME differs from its request"
    );
    ensure!(
        requester.dynamic.needed_libraries.iter().any(|needed| {
            needed.dynamic_ordinal == edge.dynamic_ordinal
                && needed.requested_name == edge.requested_name
        }),
        "startup edge differs from its requesting DT_NEEDED record"
    );
    match edge.resolution_kind {
        StaticStartupDependencyResolutionKindV1::LoadedSoname
        | StaticStartupDependencyResolutionKindV1::RootfsSearch => {}
    }
    Ok(())
}

fn merge_rootfs_revalidation<T>(
    validation: Result<T>,
    revalidation: Result<()>,
    label: &str,
) -> Result<T> {
    match (validation, revalidation) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(revalidation)) => Err(revalidation),
        (Err(primary), Err(revalidation)) => {
            Err(primary.context(format!("{label}: {revalidation:#}")))
        }
    }
}

fn canonical_rootfs_requirement_components(absolute_path: &str) -> Result<Vec<&str>> {
    ensure!(
        absolute_path.starts_with('/')
            && absolute_path.len() > 1
            && absolute_path.len() <= OCI_LAYER_PATH_MAX_BYTES + 1
            && !absolute_path.as_bytes().contains(&0),
        "positive OCI rootfs requirement is not canonical absolute POSIX"
    );
    let components = absolute_path[1..].split('/').collect::<Vec<_>>();
    ensure!(
        components
            .iter()
            .all(|component| !component.is_empty() && !matches!(*component, "." | "..")),
        "positive OCI rootfs requirement is not canonical absolute POSIX"
    );
    Ok(components)
}

fn validate_openjdk_release_file(
    bytes: &[u8],
    feature_version: u64,
    expected_vendor: &str,
    expected_version: &str,
) -> Result<()> {
    ensure!(
        !bytes.starts_with(&[0xef, 0xbb, 0xbf]),
        "Java release file carries a UTF-8 BOM"
    );
    let source = std::str::from_utf8(bytes).context("Java release file is not strict UTF-8")?;
    ensure!(
        !source.contains('\r'),
        "Java release file contains CR instead of LF"
    );
    let body = source
        .strip_suffix('\n')
        .context("Java release file lacks its terminal LF")?;
    ensure!(
        !body.is_empty() && !body.ends_with('\n'),
        "Java release file does not end in exactly one LF"
    );

    let mut previous_key = None;
    let mut implementor = None;
    let mut java_version = None;
    for line in body.split('\n') {
        ensure!(
            !line.is_empty() && !line.starts_with('#'),
            "Java release file contains an empty or comment line"
        );
        let (key, quoted_value) = line
            .split_once('=')
            .context("Java release line is not KEY=\"VALUE\"")?;
        let mut key_bytes = key.bytes();
        ensure!(
            key_bytes
                .next()
                .is_some_and(|byte| byte.is_ascii_uppercase())
                && key_bytes
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'),
            "Java release key is not canonical uppercase ASCII"
        );
        if let Some(previous_key) = previous_key {
            ensure!(
                previous_key < key,
                "Java release keys are not unique and strictly ASCII-sorted"
            );
        }
        previous_key = Some(key);
        let value = parse_openjdk_release_value(quoted_value)?;
        match key {
            "IMPLEMENTOR" => implementor = Some(value),
            "JAVA_VERSION" => java_version = Some(value),
            _ => {}
        }
    }

    ensure!(
        feature_version == 21,
        "Java release feature version differs from Java 21"
    );
    validate_printable_ascii_release_projection(expected_vendor, "Java release vendor", 1)?;
    validate_printable_ascii_release_projection(expected_version, "Java release version", 2)?;
    validate_java_21_version_projection(expected_version)?;
    ensure!(
        implementor.as_deref() == Some(expected_vendor),
        "Java release IMPLEMENTOR differs from its positive gate"
    );
    ensure!(
        java_version.as_deref() == Some(expected_version),
        "Java release JAVA_VERSION differs from its positive gate"
    );
    Ok(())
}

fn parse_openjdk_release_value(quoted_value: &str) -> Result<String> {
    ensure!(
        quoted_value.len() >= 2 && quoted_value.starts_with('"') && quoted_value.ends_with('"'),
        "Java release value is not completely quoted"
    );
    let inner = &quoted_value[1..quoted_value.len() - 1];
    let mut value = String::with_capacity(inner.len());
    let mut characters = inner.chars();
    while let Some(character) = characters.next() {
        if character == '\\' {
            let escaped = characters
                .next()
                .context("Java release value ends in an incomplete escape")?;
            ensure!(
                matches!(escaped, '\\' | '"'),
                "Java release value uses an unknown escape"
            );
            value.push(escaped);
            continue;
        }
        ensure!(
            character != '"' && character != '$' && character != '`' && !character.is_control(),
            "Java release value contains an unescaped control, quote, or substitution syntax"
        );
        value.push(character);
    }
    Ok(value)
}

fn validate_printable_ascii_release_projection(
    value: &str,
    label: &str,
    minimum_length: usize,
) -> Result<()> {
    ensure!(
        (minimum_length..=128).contains(&value.len())
            && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)),
        "{label} is outside its printable-ASCII bound"
    );
    Ok(())
}

fn validate_java_21_version_projection(version: &str) -> Result<()> {
    let version_number = version
        .split(['-', '+'])
        .next()
        .context("Java release version lacks its numeric component")?;
    let mut components = version_number.split('.');
    ensure!(
        components.next() == Some("21"),
        "Java release version does not identify feature 21"
    );
    let remaining = components.collect::<Vec<_>>();
    ensure!(
        remaining.len() <= 3
            && remaining.iter().all(|component| {
                !component.is_empty()
                    && component.bytes().all(|byte| byte.is_ascii_digit())
                    && (*component == "0" || !component.starts_with('0'))
            })
            && remaining.last().is_none_or(|component| *component != "0"),
        "Java release version number is not canonical"
    );
    Ok(())
}

fn read_complete_materialized_regular(
    file: &File,
    byte_length: u64,
    label: &str,
) -> Result<Vec<u8>> {
    let length = usize::try_from(byte_length)
        .with_context(|| format!("{label} length does not fit memory addressing"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .with_context(|| format!("cannot reserve bounded {label} bytes"))?;
    bytes.resize(length, 0);
    let mut consumed = 0_usize;
    while consumed < bytes.len() {
        let offset = u64::try_from(consumed).expect("bounded rootfs read offset fits u64");
        let read = file
            .read_at(&mut bytes[consumed..], offset)
            .with_context(|| format!("cannot read complete {label}"))?;
        ensure!(read != 0, "{label} ended before its authenticated length");
        consumed = consumed
            .checked_add(read)
            .context("authenticated rootfs read offset overflowed")?;
    }
    let mut trailing = [0_u8; 1];
    ensure!(
        file.read_at(&mut trailing, byte_length)
            .with_context(|| format!("cannot check exact {label} EOF"))?
            == 0,
        "{label} continues beyond its authenticated length"
    );
    Ok(bytes)
}

fn apply_rootfs_resolution_component(resolved: &mut Vec<String>, component: &str) -> Result<bool> {
    if component.is_empty() || component == "." {
        return Ok(false);
    }
    if component == ".." {
        ensure!(
            resolved.pop().is_some(),
            "authenticated rootfs resolution steps above the root"
        );
        return Ok(false);
    }
    resolved.push(component.to_owned());
    Ok(true)
}

#[cfg(test)]
mod resolution_tests {
    #[test]
    fn symbolic_link_target_cannot_step_above_the_root() {
        let mut resolved = Vec::new();
        let error = super::apply_rootfs_resolution_component(&mut resolved, "..").unwrap_err();
        assert!(format!("{error:#}").contains("above the root"), "{error:#}");
    }
}

const PINNED_REGULAR_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY
    .union(rustix::fs::OFlags::NOFOLLOW)
    .union(rustix::fs::OFlags::CLOEXEC);

enum MaterializedParentDescriptorV1<'descriptor> {
    Root(BorrowedFd<'descriptor>),
    Nested(OwnedFd),
}

impl MaterializedParentDescriptorV1<'_> {
    fn descriptor(&self) -> BorrowedFd<'_> {
        match self {
            Self::Root(descriptor) => *descriptor,
            Self::Nested(descriptor) => descriptor.as_fd(),
        }
    }
}

#[derive(Clone, Copy)]
struct DirectoryObservationV1 {
    identity: DirectoryIdentity,
    mode: u32,
    owner: u64,
    group: u64,
    modification_time_seconds: i64,
    modification_time_nanoseconds: i64,
}

#[derive(Clone, Copy)]
struct SymbolicLinkObservationV1 {
    identity: SymbolicLinkIdentityV1,
    hard_link_count: u64,
    mode: u32,
    owner: u64,
    group: u64,
    modification_time_seconds: i64,
    modification_time_nanoseconds: i64,
}

fn parent_and_leaf(path: &str) -> Result<(&str, &str)> {
    let (parent, leaf) = path.rsplit_once('/').unwrap_or(("", path));
    ensure!(
        !leaf.is_empty() && !matches!(leaf, "." | ".."),
        "private OCI rootfs path has no canonical leaf"
    );
    Ok((parent, leaf))
}

fn open_beneath_directory<'descriptor>(
    root: BorrowedFd<'descriptor>,
    path: &str,
) -> Result<MaterializedParentDescriptorV1<'descriptor>> {
    if path.is_empty() {
        return Ok(MaterializedParentDescriptorV1::Root(root));
    }
    let descriptor = rustix::fs::openat2(
        root,
        path,
        PINNED_DIRECTORY_FLAGS,
        rustix::fs::Mode::empty(),
        MATERIALIZED_RESOLVE_FLAGS,
    )
    .with_context(|| format!("cannot retain private OCI rootfs directory {path}"))?;
    Ok(MaterializedParentDescriptorV1::Nested(descriptor))
}

fn open_materialized_directory(root: BorrowedFd<'_>, path: &str) -> Result<OwnedFd> {
    rustix::fs::openat2(
        root,
        path,
        PINNED_DIRECTORY_FLAGS,
        rustix::fs::Mode::empty(),
        MATERIALIZED_RESOLVE_FLAGS,
    )
    .with_context(|| format!("cannot reopen materialized OCI rootfs directory {path}"))
}

fn normalize_descriptor_mtime(descriptor: BorrowedFd<'_>, label: &str) -> Result<()> {
    rustix::fs::futimens(descriptor, &MATERIALIZED_ZERO_MTIME)
        .with_context(|| format!("cannot normalize {label} mtime to zero"))
}

fn normalize_symbolic_link_mtime(parent: BorrowedFd<'_>, leaf: &str) -> Result<()> {
    rustix::fs::utimensat(
        parent,
        leaf,
        &MATERIALIZED_ZERO_MTIME,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
    )
    .context("cannot normalize materialized OCI rootfs symbolic-link mtime to zero")
}

fn directory_observation(descriptor: BorrowedFd<'_>) -> Result<DirectoryObservationV1> {
    let identity = directory_identity(descriptor)?;
    let stat = rustix::fs::fstat(descriptor)
        .context("cannot inspect private OCI rootfs directory metadata")?;
    Ok(DirectoryObservationV1 {
        identity,
        mode: stat.st_mode,
        owner: u64::from(stat.st_uid),
        group: u64::from(stat.st_gid),
        modification_time_seconds: stat.st_mtime,
        modification_time_nanoseconds: i64::try_from(stat.st_mtime_nsec)
            .context("private OCI rootfs directory mtime nanoseconds do not fit i64")?,
    })
}

fn symbolic_link_observation(
    parent: BorrowedFd<'_>,
    leaf: &str,
) -> Result<SymbolicLinkObservationV1> {
    let statx = rustix::fs::statx(
        parent,
        leaf,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        rustix::fs::StatxFlags::BASIC_STATS | rustix::fs::StatxFlags::MNT_ID,
    )
    .context("cannot inspect private OCI rootfs symbolic-link metadata")?;
    let returned = rustix::fs::StatxFlags::from_bits_retain(statx.stx_mask);
    ensure!(
        returned.contains(rustix::fs::StatxFlags::BASIC_STATS)
            && returned.contains(rustix::fs::StatxFlags::MNT_ID),
        "Linux statx did not return complete symbolic-link identity"
    );
    let mode = u32::from(statx.stx_mode);
    ensure!(
        rustix::fs::FileType::from_raw_mode(mode).is_symlink(),
        "private OCI rootfs symbolic-link name changed type"
    );
    Ok(SymbolicLinkObservationV1 {
        identity: SymbolicLinkIdentityV1 {
            device_major: statx.stx_dev_major,
            device_minor: statx.stx_dev_minor,
            inode: statx.stx_ino,
            mount_id: statx.stx_mnt_id,
        },
        hard_link_count: u64::from(statx.stx_nlink),
        mode,
        owner: u64::from(statx.stx_uid),
        group: u64::from(statx.stx_gid),
        modification_time_seconds: statx.stx_mtime.tv_sec,
        modification_time_nanoseconds: i64::from(statx.stx_mtime.tv_nsec),
    })
}

fn private_materialization_parent_position(
    transaction: &PrivateOciRootfsStagingTransactionV1,
    entries: &[MaterializedEntryV1],
    positions: &BTreeMap<&str, usize>,
    parent_path: &str,
) -> Result<Option<usize>> {
    if parent_path.is_empty() {
        return Ok(None);
    }
    let parent_position = positions
        .get(parent_path)
        .copied()
        .context("private rootfs materializer path lost its live parent")?;
    let parent_operation = transaction
        .operations
        .get(entries[parent_position].operation_index)
        .context("private rootfs materializer parent left the operation journal")?;
    ensure!(
        matches!(
            parent_operation.kind,
            StagedRootfsOperationKindV1::Directory
        ),
        "private rootfs materializer path parent is not a live directory"
    );
    Ok(Some(parent_position))
}

fn account_private_materialization_operation(
    transaction: &PrivateOciRootfsStagingTransactionV1,
    operation: &StagedRootfsOperationV1,
    position: usize,
    observed: &mut OciRootfsLiveCountersV1,
    directory_seal_order: &mut Vec<usize>,
) -> Result<()> {
    observed.entry_count = observed
        .entry_count
        .checked_add(1)
        .context("private OCI rootfs live-entry count overflowed")?;
    match &operation.kind {
        StagedRootfsOperationKindV1::Directory => {
            ensure!(
                operation.mode == 0o555 && operation.byte_length == 0,
                "private OCI rootfs directory left exact 0555/zero-length identity"
            );
            observed.directory_count = observed
                .directory_count
                .checked_add(1)
                .context("private OCI rootfs directory count overflowed")?;
            directory_seal_order.push(position);
        }
        StagedRootfsOperationKindV1::Regular { extent_index } => {
            ensure!(
                matches!(operation.mode, 0o444 | 0o555),
                "private OCI rootfs regular mode left 0444/0555"
            );
            let extent = transaction
                .physical_regular_extents
                .get(*extent_index)
                .context("private materializer extent left its authenticated journal")?;
            ensure!(
                extent.byte_length == operation.byte_length && extent.mode == operation.mode,
                "private OCI rootfs regular extent left its live operation"
            );
            observed.regular_file_count = observed
                .regular_file_count
                .checked_add(1)
                .context("private OCI rootfs regular-file count overflowed")?;
            observed.regular_file_bytes = observed
                .regular_file_bytes
                .checked_add(operation.byte_length)
                .context("private OCI rootfs regular-file bytes overflowed")?;
        }
        StagedRootfsOperationKindV1::SymbolicLink { .. } => {
            ensure!(
                operation.mode == 0o777 && operation.byte_length == 0,
                "private OCI rootfs symbolic link left exact 0777/zero-length identity"
            );
            observed.symbolic_link_count = observed
                .symbolic_link_count
                .checked_add(1)
                .context("private OCI rootfs symbolic-link count overflowed")?;
        }
        StagedRootfsOperationKindV1::Remove { .. }
        | StagedRootfsOperationKindV1::OpaqueDirectory { .. } => {
            anyhow::bail!("private rootfs materializer received a non-live marker")
        }
    }
    Ok(())
}

fn sort_directory_seal_order_deepest_first(
    transaction: &PrivateOciRootfsStagingTransactionV1,
    entries: &[MaterializedEntryV1],
    directory_seal_order: &mut [usize],
) {
    directory_seal_order.sort_unstable_by(|left, right| {
        let left_path = transaction.operations[entries[*left].operation_index]
            .path
            .as_str();
        let right_path = transaction.operations[entries[*right].operation_index]
            .path
            .as_str();
        right_path
            .split('/')
            .count()
            .cmp(&left_path.split('/').count())
            .then_with(|| right_path.cmp(left_path))
    });
}

fn preflight_private_materialization(
    transaction: &PrivateOciRootfsStagingTransactionV1,
    canonical_live_operation_indices: &[usize],
    counters: OciRootfsLiveCountersV1,
) -> Result<(Vec<MaterializedEntryV1>, Vec<usize>, usize)> {
    ensure!(
        u64::try_from(canonical_live_operation_indices.len())
            .context("private rootfs live-operation count does not fit u64")?
            == counters.entry_count,
        "private rootfs materializer live-operation count changed"
    );
    let mut entries = Vec::<MaterializedEntryV1>::new();
    entries
        .try_reserve_exact(canonical_live_operation_indices.len())
        .context("cannot reserve private OCI rootfs ownership journal")?;
    let mut directory_seal_order = Vec::new();
    directory_seal_order
        .try_reserve_exact(
            usize::try_from(counters.directory_count)
                .context("private OCI rootfs directory count does not fit usize")?,
        )
        .context("cannot reserve private OCI rootfs directory seal journal")?;
    let mut positions = BTreeMap::<&str, usize>::new();
    let mut observed = OciRootfsLiveCountersV1::default();
    let mut root_expected_child_count = 0_usize;
    let mut previous_path: Option<&str> = None;

    for operation_index in canonical_live_operation_indices {
        let operation = transaction
            .operations
            .get(*operation_index)
            .context("private materializer index left the operation journal")?;
        if let Some(previous_path) = previous_path {
            ensure!(
                previous_path < operation.path.as_str(),
                "private rootfs materializer live paths are not canonical and unique"
            );
        }
        previous_path = Some(operation.path.as_str());
        let (parent_path, _) = parent_and_leaf(operation.path.as_str())?;
        let parent_position = private_materialization_parent_position(
            transaction,
            &entries,
            &positions,
            parent_path,
        )?;
        if let Some(parent_position) = parent_position {
            entries[parent_position].expected_child_count = entries[parent_position]
                .expected_child_count
                .checked_add(1)
                .context("private OCI rootfs expected-child count overflowed")?;
        } else {
            root_expected_child_count = root_expected_child_count
                .checked_add(1)
                .context("private OCI rootfs root child count overflowed")?;
        }

        let position = entries.len();
        account_private_materialization_operation(
            transaction,
            operation,
            position,
            &mut observed,
            &mut directory_seal_order,
        )?;
        ensure!(
            positions
                .insert(operation.path.as_str(), position)
                .is_none(),
            "private rootfs materializer live path was duplicated"
        );
        entries.push(MaterializedEntryV1 {
            operation_index: *operation_index,
            parent_position,
            expected_child_count: 0,
            created_child_count: 0,
            phase: MaterializedEntryPhaseV1::Planned,
        });
    }
    ensure!(
        observed == counters,
        "private rootfs materializer counters differ from the authenticated projection"
    );
    sort_directory_seal_order_deepest_first(transaction, &entries, &mut directory_seal_order);
    Ok((entries, directory_seal_order, root_expected_child_count))
}

fn private_staging_name(
    transaction: &PrivateOciRootfsStagingTransactionV1,
    authenticated_logical_projection_sha256: [u8; SHA256_BYTES],
) -> OsString {
    let role = positive_runner_role_identity_tag(transaction.role);
    let mut identity = Sha256::new();
    identity.update(b"eip0045-private-physical-rootfs-staging-v1\0");
    identity.update([role]);
    identity.update(transaction.final_name.as_bytes());
    identity.update(authenticated_logical_projection_sha256);
    OsString::from(format!(
        ".eip0045-rootfs-v1-r{role}-{}",
        hex::encode(identity.finalize())
    ))
}

fn sealed_regular_mode(mode: u32) -> Result<rustix::fs::Mode> {
    match mode {
        0o444 => Ok(MATERIALIZED_READ_ONLY_MODE),
        0o555 => Ok(MATERIALIZED_READ_EXECUTE_MODE),
        _ => anyhow::bail!("materialized OCI rootfs regular mode left 0444/0555"),
    }
}

fn copy_regular_extent(
    spool: &File,
    destination: &File,
    extent: &StagedRegularExtentV1,
) -> Result<()> {
    let mut digest = Sha256::new();
    let mut consumed = 0_u64;
    let mut buffer = [0_u8; OCI_REPLAY_CHUNK_MAX_BYTES];
    while consumed < extent.byte_length {
        let remaining = extent
            .byte_length
            .checked_sub(consumed)
            .expect("consumed copy bytes remain bounded");
        let wanted = usize::try_from(remaining.min(OCI_REPLAY_CHUNK_MAX_BYTES as u64))
            .expect("bounded physical copy read fits usize");
        let source_offset = extent
            .offset
            .checked_add(consumed)
            .context("physical OCI rootfs spool offset overflowed")?;
        let read = spool
            .read_at(&mut buffer[..wanted], source_offset)
            .context("cannot read authenticated OCI rootfs spool during physical copy")?;
        ensure!(
            read != 0,
            "authenticated OCI rootfs spool ended during physical copy"
        );
        digest.update(&buffer[..read]);
        write_physical_all_at(destination, &buffer[..read], consumed)?;
        consumed = consumed
            .checked_add(u64::try_from(read).expect("bounded copy read fits u64"))
            .context("physical OCI rootfs copy length overflowed")?;
    }
    ensure!(
        <[u8; SHA256_BYTES]>::from(digest.finalize()) == extent.sha256,
        "authenticated OCI rootfs spool digest changed during physical copy"
    );
    Ok(())
}

fn write_physical_all_at(file: &File, mut bytes: &[u8], mut offset: u64) -> Result<()> {
    while !bytes.is_empty() {
        let written = file
            .write_at(bytes, offset)
            .context("materialized OCI rootfs pwrite failed")?;
        ensure!(
            written != 0,
            "materialized OCI rootfs pwrite made no progress"
        );
        offset = offset
            .checked_add(u64::try_from(written).expect("bounded pwrite fits u64"))
            .context("materialized OCI rootfs pwrite offset overflowed")?;
        bytes = &bytes[written..];
    }
    Ok(())
}

fn capture_finalizer_effective_ids() -> FinalizerEffectiveIdsV1 {
    FinalizerEffectiveIdsV1 {
        uid: u64::from(rustix::process::geteuid().as_raw()),
        gid: u64::from(rustix::process::getegid().as_raw()),
    }
}

fn validate_current_finalizer_effective_ids(
    expected: &FinalizerEffectiveIdsV1,
    mutation: FinalizerEffectiveIdsObservationMutationV1,
) -> Result<()> {
    let observed = match mutation {
        FinalizerEffectiveIdsObservationMutationV1::Unchanged => capture_finalizer_effective_ids(),
        #[cfg(test)]
        FinalizerEffectiveIdsObservationMutationV1::Uid => {
            let mut observed = capture_finalizer_effective_ids();
            observed.uid = observed.uid.wrapping_add(1);
            observed
        }
        #[cfg(test)]
        FinalizerEffectiveIdsObservationMutationV1::Gid => {
            let mut observed = capture_finalizer_effective_ids();
            observed.gid = observed.gid.wrapping_add(1);
            observed
        }
    };
    ensure!(
        observed.uid == expected.uid,
        "retained host-rootfs mapped-owner prerequisite finalizer effective UID drifted"
    );
    ensure!(
        observed.gid == expected.gid,
        "retained host-rootfs mapped-owner prerequisite finalizer effective GID drifted"
    );
    Ok(())
}

fn validate_mapped_owner_prerequisite(
    observed_owner: u64,
    observed_group: u64,
    expected: &FinalizerEffectiveIdsV1,
    label: &str,
) -> Result<()> {
    ensure!(
        observed_owner == expected.uid,
        "{label} owner differs from the retained host-rootfs mapped-owner prerequisite finalizer effective UID"
    );
    ensure!(
        observed_group == expected.gid,
        "{label} group differs from the retained host-rootfs mapped-owner prerequisite finalizer effective GID"
    );
    Ok(())
}

fn validate_physical_owner_group_custody(
    observed_owner: u64,
    observed_group: u64,
    expected_owner: u64,
    expected_group: u64,
    label: &str,
) -> Result<()> {
    ensure!(
        observed_owner == expected_owner && observed_group == expected_group,
        "{label} physical owner/group differs from its captured cleanup custody"
    );
    Ok(())
}

fn validate_materialized_regular(
    file: &File,
    expected_identity: FileIdentity,
    expected_owner: u64,
    expected_group: u64,
    expected_mode: u32,
    extent: &StagedRegularExtentV1,
    expected_mount_id: u64,
) -> Result<()> {
    let before = regular_file_observation(file)?;
    validate_materialized_regular_metadata(
        &before,
        expected_identity,
        expected_owner,
        expected_group,
        expected_mode,
        extent,
        expected_mount_id,
    )?;
    let observed_sha256 = super::digest_extent(
        file,
        0,
        extent.byte_length,
        "materialized OCI rootfs regular file",
    )?;
    ensure!(
        observed_sha256 == extent.sha256,
        "materialized OCI rootfs regular digest differs from its authenticated projection"
    );
    let after = regular_file_observation(file)?;
    validate_physical_owner_group_custody(
        after.owner,
        after.group,
        expected_owner,
        expected_group,
        "materialized OCI rootfs regular file after digest validation",
    )?;
    ensure!(
        after.identity == before.identity,
        "materialized OCI rootfs regular identity changed during validation"
    );
    Ok(())
}

fn validate_materialized_regular_metadata(
    observed: &super::FileObservation,
    expected_identity: FileIdentity,
    expected_owner: u64,
    expected_group: u64,
    expected_mode: u32,
    extent: &StagedRegularExtentV1,
    expected_mount_id: u64,
) -> Result<()> {
    validate_physical_owner_group_custody(
        observed.owner,
        observed.group,
        expected_owner,
        expected_group,
        "materialized OCI rootfs regular file",
    )?;
    ensure!(
        observed.identity == expected_identity
            && observed.identity.mount_id == expected_mount_id
            && observed.hard_link_count == 1
            && observed.byte_length == extent.byte_length
            && observed.mode & PERMISSION_AND_SPECIAL_BITS == expected_mode
            && observed.modification_time_seconds == 0
            && observed.modification_time_nanoseconds == 0,
        "materialized OCI rootfs regular metadata differs from its authenticated projection"
    );
    Ok(())
}

fn validate_owned_materialized_regular(
    file: &File,
    expected_identity: FileIdentity,
    expected_owner: u64,
    expected_group: u64,
    expected_mount_id: u64,
) -> Result<()> {
    let observed = regular_file_observation(file)?;
    validate_physical_owner_group_custody(
        observed.owner,
        observed.group,
        expected_owner,
        expected_group,
        "owned private OCI rootfs regular file",
    )?;
    ensure!(
        observed.identity == expected_identity
            && observed.identity.mount_id == expected_mount_id
            && observed.hard_link_count == 1
            && matches!(
                observed.mode & PERMISSION_AND_SPECIAL_BITS,
                0o600 | 0o444 | 0o555
            ),
        "owned private OCI rootfs regular-file identity changed"
    );
    Ok(())
}

fn validate_materialized_directory(
    descriptor: BorrowedFd<'_>,
    expected_identity: DirectoryIdentity,
    expected_owner: u64,
    expected_group: u64,
    sealed: bool,
    expected_mount_id: u64,
    expected_entries: usize,
) -> Result<()> {
    let observed = directory_observation(descriptor)?;
    validate_materialized_directory_observation(
        descriptor,
        observed,
        expected_identity,
        (expected_owner, expected_group),
        sealed,
        expected_mount_id,
        expected_entries,
    )
}

fn validate_materialized_directory_observation(
    descriptor: BorrowedFd<'_>,
    observed: DirectoryObservationV1,
    expected_identity: DirectoryIdentity,
    expected_owner_group: (u64, u64),
    sealed: bool,
    expected_mount_id: u64,
    expected_entries: usize,
) -> Result<()> {
    let (expected_owner, expected_group) = expected_owner_group;
    let expected_mode = if sealed {
        MATERIALIZED_READ_EXECUTE_MODE.bits()
    } else {
        PRIVATE_MATERIALIZED_DIRECTORY_MODE.bits()
    };
    validate_physical_owner_group_custody(
        observed.owner,
        observed.group,
        expected_owner,
        expected_group,
        "materialized OCI rootfs directory",
    )?;
    ensure!(
        observed.identity == expected_identity
            && observed.identity.mount_id == expected_mount_id
            && observed.mode & PERMISSION_AND_SPECIAL_BITS == expected_mode
            && (!sealed
                || (observed.modification_time_seconds == 0
                    && observed.modification_time_nanoseconds == 0)),
        "materialized OCI rootfs directory identity or mode changed, or sealed mtime changed"
    );
    ensure!(
        directory_entry_count(descriptor, expected_entries)? == expected_entries,
        "materialized OCI rootfs directory inventory has an unexpected cardinality"
    );
    let after = directory_observation(descriptor)?;
    validate_physical_owner_group_custody(
        after.owner,
        after.group,
        expected_owner,
        expected_group,
        "materialized OCI rootfs directory after inventory validation",
    )?;
    ensure!(
        after.identity == observed.identity,
        "materialized OCI rootfs directory identity changed during validation"
    );
    Ok(())
}

fn validate_materialized_symbolic_link(
    parent: BorrowedFd<'_>,
    leaf: &str,
    expected_identity: SymbolicLinkIdentityV1,
    expected_owner: u64,
    expected_group: u64,
    expected_target: &str,
    expected_mount_id: u64,
) -> Result<()> {
    let before = symbolic_link_observation(parent, leaf)?;
    validate_materialized_symbolic_link_observation(
        parent,
        leaf,
        before,
        expected_identity,
        (expected_owner, expected_group),
        expected_target,
        expected_mount_id,
    )
}

fn validate_owned_materialized_symbolic_link(
    parent: BorrowedFd<'_>,
    leaf: &str,
    expected_identity: SymbolicLinkIdentityV1,
    expected_owner: u64,
    expected_group: u64,
    expected_target: &str,
    expected_mount_id: u64,
) -> Result<()> {
    let before = symbolic_link_observation(parent, leaf)?;
    validate_symbolic_link_metadata(
        before,
        expected_identity,
        expected_owner,
        expected_group,
        expected_mount_id,
        false,
    )?;
    validate_symbolic_link_target_and_stability(
        parent,
        leaf,
        before,
        expected_owner,
        expected_group,
        expected_target,
    )
}

fn validate_materialized_symbolic_link_observation(
    parent: BorrowedFd<'_>,
    leaf: &str,
    before: SymbolicLinkObservationV1,
    expected_identity: SymbolicLinkIdentityV1,
    expected_owner_group: (u64, u64),
    expected_target: &str,
    expected_mount_id: u64,
) -> Result<()> {
    let (expected_owner, expected_group) = expected_owner_group;
    validate_symbolic_link_metadata(
        before,
        expected_identity,
        expected_owner,
        expected_group,
        expected_mount_id,
        true,
    )?;
    validate_symbolic_link_target_and_stability(
        parent,
        leaf,
        before,
        expected_owner,
        expected_group,
        expected_target,
    )
}

fn validate_symbolic_link_metadata(
    observed: SymbolicLinkObservationV1,
    expected_identity: SymbolicLinkIdentityV1,
    expected_owner: u64,
    expected_group: u64,
    expected_mount_id: u64,
    require_zero_mtime: bool,
) -> Result<()> {
    validate_physical_owner_group_custody(
        observed.owner,
        observed.group,
        expected_owner,
        expected_group,
        "materialized OCI rootfs symbolic link",
    )?;
    ensure!(
        observed.identity == expected_identity
            && observed.identity.mount_id == expected_mount_id
            && observed.hard_link_count == 1
            && observed.mode & PERMISSION_AND_SPECIAL_BITS == 0o777
            && (!require_zero_mtime
                || (observed.modification_time_seconds == 0
                    && observed.modification_time_nanoseconds == 0)),
        "materialized OCI rootfs symbolic-link identity changed or sealed mtime changed"
    );
    Ok(())
}

fn validate_symbolic_link_target_and_stability(
    parent: BorrowedFd<'_>,
    leaf: &str,
    before: SymbolicLinkObservationV1,
    expected_owner: u64,
    expected_group: u64,
    expected_target: &str,
) -> Result<()> {
    let observed_target = rustix::fs::readlinkat(parent, leaf, Vec::new())
        .context("cannot read private OCI rootfs symbolic-link target")?;
    ensure!(
        observed_target.as_bytes() == expected_target.as_bytes(),
        "materialized OCI rootfs symbolic-link target changed"
    );
    let after = symbolic_link_observation(parent, leaf)?;
    validate_physical_owner_group_custody(
        after.owner,
        after.group,
        expected_owner,
        expected_group,
        "materialized OCI rootfs symbolic link after target validation",
    )?;
    ensure!(
        after.identity == before.identity,
        "materialized OCI rootfs symbolic-link identity changed during validation"
    );
    Ok(())
}

fn validate_private_staging_root(
    descriptor: BorrowedFd<'_>,
    expected_identity: DirectoryIdentity,
    expected_owner: u64,
    expected_group: u64,
    sealed: bool,
    expected_mount_id: u64,
    expected_entries: usize,
) -> Result<()> {
    let observed = directory_observation(descriptor)?;
    validate_private_staging_root_observation(
        descriptor,
        observed,
        expected_identity,
        (expected_owner, expected_group),
        sealed,
        expected_mount_id,
        expected_entries,
    )
}

fn validate_private_staging_root_observation(
    descriptor: BorrowedFd<'_>,
    observed: DirectoryObservationV1,
    expected_identity: DirectoryIdentity,
    expected_owner_group: (u64, u64),
    sealed: bool,
    expected_mount_id: u64,
    expected_entries: usize,
) -> Result<()> {
    let (expected_owner, expected_group) = expected_owner_group;
    let expected_mode = if sealed {
        MATERIALIZED_READ_EXECUTE_MODE.bits()
    } else {
        PRIVATE_MATERIALIZED_DIRECTORY_MODE.bits()
    };
    validate_physical_owner_group_custody(
        observed.owner,
        observed.group,
        expected_owner,
        expected_group,
        "private OCI rootfs staging root",
    )?;
    ensure!(
        observed.identity == expected_identity
            && observed.identity.mount_id == expected_mount_id
            && observed.mode & PERMISSION_AND_SPECIAL_BITS == expected_mode
            && (!sealed
                || (observed.modification_time_seconds == 0
                    && observed.modification_time_nanoseconds == 0)),
        "private OCI rootfs staging directory identity or mode changed, or sealed mtime changed"
    );
    ensure!(
        directory_entry_count(descriptor, expected_entries)? == expected_entries,
        "private OCI rootfs staging inventory has an unexpected cardinality"
    );
    let after = directory_observation(descriptor)?;
    validate_physical_owner_group_custody(
        after.owner,
        after.group,
        expected_owner,
        expected_group,
        "private OCI rootfs staging root after inventory validation",
    )?;
    ensure!(
        after.identity == observed.identity,
        "private OCI rootfs staging identity changed during validation"
    );
    Ok(())
}

fn directory_entry_count(descriptor: BorrowedFd<'_>, maximum: usize) -> Result<usize> {
    let mut directory = rustix::fs::Dir::read_from(descriptor)
        .context("cannot enumerate private OCI rootfs staging")?;
    let mut count = 0_usize;
    for entry in &mut directory {
        let entry = entry.context("cannot read private OCI rootfs staging entry")?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        ensure!(
            count < maximum,
            "private OCI rootfs staging exceeds its authenticated inventory"
        );
        count = count
            .checked_add(1)
            .context("private OCI rootfs directory-entry count overflowed")?;
    }
    Ok(count)
}
