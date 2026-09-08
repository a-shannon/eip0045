// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Create-only custody for the authenticated B4 negative-ancestry catalogue.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::Read as _,
    path::Path,
};
#[cfg(unix)]
use std::{io::ErrorKind, path::PathBuf};

use anyhow::{Context as _, Result, bail, ensure};

use crate::{
    b4_campaign_contract::B4ContractArtifactIdentityV1,
    b4_negative_ancestry_authority::{
        B4NegativeAncestryWitnessCatalogAuthorityV1, B4NegativeAncestryWitnessCatalogAuthorityV2,
        B4RetainedNegativeAncestryWitnessEntryV1,
    },
    b4_negative_ancestry_witness::{
        B4_NEGATIVE_ANCESTRY_ALTERNATE_GUEST_ELF_PATH, B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT,
        B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_PATH, Eip0045B4NegativeAncestryWitnessCatalogV1,
        compiled_negative_ancestry_publication_paths, compiled_negative_ancestry_witness_layout,
    },
};

trait B4NegativeAncestryPublicationAuthority {
    fn verify_candidate_jcs(&self, source: &[u8]) -> Result<()>;
    fn canonical_catalog_jcs(&self) -> &[u8];
    fn alternate_guest_elf(&self) -> &[u8];
    fn retained_entries(&self) -> &[B4RetainedNegativeAncestryWitnessEntryV1];
}

impl B4NegativeAncestryPublicationAuthority for B4NegativeAncestryWitnessCatalogAuthorityV1 {
    fn verify_candidate_jcs(&self, source: &[u8]) -> Result<()> {
        self.verify_candidate_jcs(source)
    }

    fn canonical_catalog_jcs(&self) -> &[u8] {
        self.canonical_catalog_jcs()
    }

    fn alternate_guest_elf(&self) -> &[u8] {
        self.alternate_guest_elf()
    }

    fn retained_entries(&self) -> &[B4RetainedNegativeAncestryWitnessEntryV1] {
        self.retained_entries()
    }
}

impl B4NegativeAncestryPublicationAuthority for B4NegativeAncestryWitnessCatalogAuthorityV2 {
    fn verify_candidate_jcs(&self, source: &[u8]) -> Result<()> {
        self.verify_candidate_jcs(source)
    }

    fn canonical_catalog_jcs(&self) -> &[u8] {
        self.canonical_catalog_jcs()
    }

    fn alternate_guest_elf(&self) -> &[u8] {
        self.alternate_guest_elf()
    }

    fn retained_entries(&self) -> &[B4RetainedNegativeAncestryWitnessEntryV1] {
        self.retained_entries()
    }
}

#[cfg(target_os = "linux")]
mod descriptor_rooted_linux {
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs::File,
        io::Write as _,
        os::fd::{AsFd as _, BorrowedFd, OwnedFd},
        os::unix::fs::FileExt as _,
    };

    use anyhow::{Context as _, Result, bail, ensure};

    use super::{
        B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT, B4AuthenticatedPublishedFileV1,
        B4NegativeAncestryPublicationAuthority, B4NegativeAncestryPublicationEntryV1,
        B4NegativeAncestryPublicationReadSetV1, B4NegativeAncestryWitnessCatalogAuthorityV1,
    };

    const PATH_DIRECTORY_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::PATH
        .union(rustix::fs::OFlags::DIRECTORY)
        .union(rustix::fs::OFlags::NOFOLLOW)
        .union(rustix::fs::OFlags::CLOEXEC);
    const READ_DIRECTORY_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY
        .union(rustix::fs::OFlags::DIRECTORY)
        .union(rustix::fs::OFlags::NOFOLLOW)
        .union(rustix::fs::OFlags::CLOEXEC);
    const PATH_FILE_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::PATH
        .union(rustix::fs::OFlags::NOFOLLOW)
        .union(rustix::fs::OFlags::CLOEXEC);
    const READ_FILE_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY
        .union(rustix::fs::OFlags::NOFOLLOW)
        .union(rustix::fs::OFlags::NONBLOCK)
        .union(rustix::fs::OFlags::CLOEXEC);
    const CREATE_FILE_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDWR
        .union(rustix::fs::OFlags::CREATE)
        .union(rustix::fs::OFlags::EXCL)
        .union(rustix::fs::OFlags::NOFOLLOW)
        .union(rustix::fs::OFlags::CLOEXEC);
    const RESOLVE_FLAGS: rustix::fs::ResolveFlags = rustix::fs::ResolveFlags::BENEATH
        .union(rustix::fs::ResolveFlags::NO_SYMLINKS)
        .union(rustix::fs::ResolveFlags::NO_MAGICLINKS)
        .union(rustix::fs::ResolveFlags::NO_XDEV);
    const PRIVATE_DIRECTORY_MODE: rustix::fs::Mode = rustix::fs::Mode::RWXU;
    const PRIVATE_FILE_MODE: rustix::fs::Mode =
        rustix::fs::Mode::RUSR.union(rustix::fs::Mode::WUSR);
    const PERMISSION_AND_SPECIAL_BITS: u32 = 0o7777;
    const MAX_DIRECTORY_ENTRIES: usize = B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT + 2;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct LinuxIdentity {
        device: u64,
        inode: u64,
        mount_id: u64,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct LinuxDirectoryState {
        identity: LinuxIdentity,
        hard_link_count: u64,
        mode: u32,
        owner: u64,
        group: u64,
        modified_seconds: i64,
        modified_nanoseconds: u64,
        changed_seconds: i64,
        changed_nanoseconds: u64,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct LinuxFileState {
        identity: LinuxIdentity,
        byte_length: u64,
        hard_link_count: u64,
        mode: u32,
        owner: u64,
        group: u64,
        modified_seconds: i64,
        modified_nanoseconds: u64,
        changed_seconds: i64,
        changed_nanoseconds: u64,
    }

    struct PinnedLinuxDirectory {
        path_descriptor: OwnedFd,
        read_descriptor: OwnedFd,
        state: LinuxDirectoryState,
        relative: String,
    }

    struct PinnedLinuxFile {
        path_descriptor: OwnedFd,
        data_descriptor: File,
        state: LinuxFileState,
        relative: String,
    }

    struct PinnedNegativeAncestryTree {
        root: PinnedLinuxDirectory,
        directories: BTreeMap<String, PinnedLinuxDirectory>,
        expected_inventories: BTreeMap<String, BTreeSet<String>>,
    }

    #[derive(Clone, Copy)]
    enum DescriptorDirectoryDurabilityRole {
        Witnesses,
        Reproduction,
        Root,
    }

    impl DescriptorDirectoryDurabilityRole {
        const fn diagnostic(self) -> &'static str {
            match self {
                Self::Witnesses => "negative-ancestry witness directory",
                Self::Reproduction => "negative-ancestry reproduction directory",
                Self::Root => "negative-ancestry publication root",
            }
        }
    }

    trait DescriptorDurability {
        fn synchronize_file(&mut self, file: &File, relative: &str) -> Result<()>;

        fn synchronize_directory(
            &mut self,
            directory: BorrowedFd<'_>,
            role: DescriptorDirectoryDurabilityRole,
        ) -> Result<()>;
    }

    struct RealDescriptorDurability;

    impl DescriptorDurability for RealDescriptorDurability {
        fn synchronize_file(&mut self, file: &File, relative: &str) -> Result<()> {
            file.sync_all()
                .with_context(|| format!("cannot synchronize publication file {relative}"))
        }

        fn synchronize_directory(
            &mut self,
            directory: BorrowedFd<'_>,
            role: DescriptorDirectoryDurabilityRole,
        ) -> Result<()> {
            rustix::fs::fsync(directory)
                .with_context(|| format!("cannot synchronize {}", role.diagnostic()))
        }
    }

    #[cfg(test)]
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub(super) enum DescriptorDurabilityEvent {
        File(String),
        WitnessDirectory,
        ReproductionDirectory,
        RootDirectory,
    }

    #[cfg(test)]
    struct HookedDescriptorDurability<Hook> {
        hook: Hook,
        real: RealDescriptorDurability,
    }

    #[cfg(test)]
    impl<Hook> DescriptorDurability for HookedDescriptorDurability<Hook>
    where
        Hook: FnMut(DescriptorDurabilityEvent) -> Result<()>,
    {
        fn synchronize_file(&mut self, file: &File, relative: &str) -> Result<()> {
            (self.hook)(DescriptorDurabilityEvent::File(relative.to_owned()))?;
            self.real.synchronize_file(file, relative)
        }

        fn synchronize_directory(
            &mut self,
            directory: BorrowedFd<'_>,
            role: DescriptorDirectoryDurabilityRole,
        ) -> Result<()> {
            let event = match role {
                DescriptorDirectoryDurabilityRole::Witnesses => {
                    DescriptorDurabilityEvent::WitnessDirectory
                }
                DescriptorDirectoryDurabilityRole::Reproduction => {
                    DescriptorDurabilityEvent::ReproductionDirectory
                }
                DescriptorDirectoryDurabilityRole::Root => DescriptorDurabilityEvent::RootDirectory,
            };
            (self.hook)(event)?;
            self.real.synchronize_directory(directory, role)
        }
    }

    fn checked_u64<T>(value: T, error: &'static str) -> Result<u64>
    where
        u64: TryFrom<T>,
    {
        u64::try_from(value).map_err(|_| anyhow::Error::msg(error))
    }

    fn descriptor_mount_id(descriptor: BorrowedFd<'_>) -> Result<u64> {
        let statx = rustix::fs::statx(
            descriptor,
            "",
            rustix::fs::AtFlags::EMPTY_PATH,
            rustix::fs::StatxFlags::BASIC_STATS | rustix::fs::StatxFlags::MNT_ID,
        )
        .context("cannot obtain retained negative-ancestry mount identity")?;
        ensure!(
            rustix::fs::StatxFlags::from_bits_retain(statx.stx_mask)
                .contains(rustix::fs::StatxFlags::MNT_ID),
            "Linux statx did not return a negative-ancestry mount identity"
        );
        Ok(statx.stx_mnt_id)
    }

    fn directory_state(
        descriptor: impl std::os::fd::AsFd,
        label: &str,
    ) -> Result<LinuxDirectoryState> {
        let descriptor = descriptor.as_fd();
        let stat = rustix::fs::fstat(descriptor)
            .with_context(|| format!("cannot inspect retained directory {label}"))?;
        ensure!(
            rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir(),
            "{label} is not an ordinary directory"
        );
        Ok(LinuxDirectoryState {
            identity: LinuxIdentity {
                device: checked_u64(stat.st_dev, "directory device identity does not fit u64")?,
                inode: checked_u64(stat.st_ino, "directory inode identity does not fit u64")?,
                mount_id: descriptor_mount_id(descriptor)?,
            },
            hard_link_count: checked_u64(stat.st_nlink, "directory link count does not fit u64")?,
            mode: stat.st_mode,
            owner: checked_u64(stat.st_uid, "directory owner identity does not fit u64")?,
            group: checked_u64(stat.st_gid, "directory group identity does not fit u64")?,
            modified_seconds: stat.st_mtime,
            modified_nanoseconds: stat.st_mtime_nsec,
            changed_seconds: stat.st_ctime,
            changed_nanoseconds: stat.st_ctime_nsec,
        })
    }

    fn file_state(descriptor: impl std::os::fd::AsFd, label: &str) -> Result<LinuxFileState> {
        let descriptor = descriptor.as_fd();
        let stat = rustix::fs::fstat(descriptor)
            .with_context(|| format!("cannot inspect retained file {label}"))?;
        ensure!(
            rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file(),
            "{label} is not an ordinary regular file"
        );
        let hard_link_count = checked_u64(stat.st_nlink, "file link count does not fit u64")?;
        ensure!(
            hard_link_count == 1,
            "{label} must have exactly one hard link"
        );
        Ok(LinuxFileState {
            identity: LinuxIdentity {
                device: checked_u64(stat.st_dev, "file device identity does not fit u64")?,
                inode: checked_u64(stat.st_ino, "file inode identity does not fit u64")?,
                mount_id: descriptor_mount_id(descriptor)?,
            },
            byte_length: checked_u64(stat.st_size, "file byte length does not fit u64")?,
            hard_link_count,
            mode: stat.st_mode,
            owner: checked_u64(stat.st_uid, "file owner identity does not fit u64")?,
            group: checked_u64(stat.st_gid, "file group identity does not fit u64")?,
            modified_seconds: stat.st_mtime,
            modified_nanoseconds: stat.st_mtime_nsec,
            changed_seconds: stat.st_ctime,
            changed_nanoseconds: stat.st_ctime_nsec,
        })
    }

    fn validate_private_directory_policy(
        state: LinuxDirectoryState,
        expected_hard_links: u64,
        label: &str,
    ) -> Result<()> {
        ensure!(
            state.mode & PERMISSION_AND_SPECIAL_BITS == PRIVATE_DIRECTORY_MODE.bits(),
            "{label} does not have exact owner-only directory permissions"
        );
        ensure!(
            state.hard_link_count == expected_hard_links,
            "{label} has an unexpected directory link count"
        );
        Ok(())
    }

    fn validate_private_file_policy(
        state: LinuxFileState,
        expected_length: usize,
        label: &str,
    ) -> Result<()> {
        ensure!(
            state.mode & PERMISSION_AND_SPECIAL_BITS == PRIVATE_FILE_MODE.bits(),
            "{label} does not have exact owner-only file permissions"
        );
        ensure!(
            state.byte_length == u64::try_from(expected_length)?,
            "{label} has an unexpected byte length"
        );
        Ok(())
    }

    fn open_directory_beneath(
        root: BorrowedFd<'_>,
        relative: &str,
    ) -> Result<PinnedLinuxDirectory> {
        let path = if relative.is_empty() { "." } else { relative };
        let label = if relative.is_empty() {
            "negative-ancestry publication root"
        } else {
            relative
        };
        let path_descriptor = rustix::fs::openat2(
            root,
            path,
            PATH_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
            RESOLVE_FLAGS,
        )
        .with_context(|| format!("cannot pin directory {label} beneath retained custody"))?;
        let initial = directory_state(&path_descriptor, label)?;
        let read_descriptor = rustix::fs::openat2(
            root,
            path,
            READ_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
            RESOLVE_FLAGS,
        )
        .with_context(|| format!("cannot open directory {label} for exact inventory"))?;
        ensure!(
            directory_state(&read_descriptor, label)? == initial,
            "{label} changed while its inventory descriptor was opened"
        );
        Ok(PinnedLinuxDirectory {
            path_descriptor,
            read_descriptor,
            state: initial,
            relative: relative.to_owned(),
        })
    }

    fn enumerate_directory(descriptor: BorrowedFd<'_>, label: &str) -> Result<BTreeSet<String>> {
        let mut directory = rustix::fs::Dir::read_from(descriptor)
            .with_context(|| format!("cannot enumerate retained directory {label}"))?;
        let mut entries = BTreeSet::new();
        for entry in &mut directory {
            let entry = entry
                .with_context(|| format!("cannot read retained directory entry in {label}"))?;
            let name = entry
                .file_name()
                .to_str()
                .with_context(|| format!("{label} contains a non-UTF-8 entry name"))?;
            if matches!(name, "." | "..") {
                continue;
            }
            ensure!(
                entries.len() < MAX_DIRECTORY_ENTRIES,
                "{label} exceeds the compiled directory-entry bound"
            );
            ensure!(
                entries.insert(name.to_owned()),
                "{label} contains a duplicate directory entry"
            );
        }
        Ok(entries)
    }

    fn expected_directory_inventories(
        entries: &[B4NegativeAncestryPublicationEntryV1<'_>;
             B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT],
    ) -> Result<BTreeMap<String, BTreeSet<String>>> {
        let mut directories = BTreeMap::<String, BTreeSet<String>>::new();
        directories.insert(String::new(), BTreeSet::new());
        for entry in entries {
            let components = entry.path.split('/').collect::<Vec<_>>();
            ensure!(
                !components.is_empty()
                    && components.iter().all(|component| {
                        !component.is_empty() && *component != "." && *component != ".."
                    }),
                "compiled negative-ancestry path is not component-normal"
            );
            let mut parent = String::new();
            for component in &components[..components.len() - 1] {
                directories
                    .entry(parent.clone())
                    .or_default()
                    .insert((*component).to_owned());
                if !parent.is_empty() {
                    parent.push('/');
                }
                parent.push_str(component);
                directories.entry(parent.clone()).or_default();
            }
            ensure!(
                directories
                    .entry(parent)
                    .or_default()
                    .insert(components[components.len() - 1].to_owned()),
                "compiled negative-ancestry file entry is duplicated"
            );
        }
        ensure!(
            directories.keys().map(String::as_str).eq([
                "",
                "reproduction",
                "reproduction/negative-ancestry-witnesses",
            ]),
            "compiled negative-ancestry directory inventory drifted"
        );
        Ok(directories)
    }

    fn expected_directory_link_count(
        relative: &str,
        inventories: &BTreeMap<String, BTreeSet<String>>,
    ) -> Result<u64> {
        let entries = inventories
            .get(relative)
            .with_context(|| format!("missing expected directory inventory for {relative}"))?;
        let child_directories = entries
            .iter()
            .filter(|name| {
                let child = if relative.is_empty() {
                    (*name).clone()
                } else {
                    format!("{relative}/{name}")
                };
                inventories.contains_key(&child)
            })
            .count();
        2_u64
            .checked_add(u64::try_from(child_directories)?)
            .context("expected directory link count overflowed")
    }

    impl PinnedLinuxDirectory {
        fn validate_inventory(&self, expected: &BTreeSet<String>) -> Result<()> {
            let label = if self.relative.is_empty() {
                "negative-ancestry publication root"
            } else {
                self.relative.as_str()
            };
            ensure!(
                enumerate_directory(self.read_descriptor.as_fd(), label)? == *expected,
                "{label} does not have the exact negative-ancestry inventory"
            );
            Ok(())
        }

        fn reauthenticate_beneath(&self, root: BorrowedFd<'_>) -> Result<()> {
            let label = if self.relative.is_empty() {
                "negative-ancestry publication root"
            } else {
                self.relative.as_str()
            };
            ensure!(
                directory_state(&self.path_descriptor, label)? == self.state,
                "retained directory metadata changed for {label}"
            );
            ensure!(
                directory_state(&self.read_descriptor, label)? == self.state,
                "retained directory inventory descriptor changed for {label}"
            );
            let reopened = open_directory_beneath(root, &self.relative)?;
            ensure!(
                reopened.state == self.state,
                "named directory no longer identifies the retained directory for {label}"
            );
            Ok(())
        }

        fn refresh_after_expected_mutation(&mut self) -> Result<()> {
            let label = if self.relative.is_empty() {
                "negative-ancestry publication root"
            } else {
                self.relative.as_str()
            };
            let current = directory_state(&self.path_descriptor, label)?;
            ensure!(
                directory_state(&self.read_descriptor, label)? == current,
                "{label} changed while refreshing expected directory metadata"
            );
            ensure!(
                current.identity == self.state.identity
                    && current.mode == self.state.mode
                    && current.owner == self.state.owner
                    && current.group == self.state.group,
                "{label} changed identity or policy during materialization"
            );
            self.state = current;
            Ok(())
        }
    }

    fn read_stable_exact_bytes(
        file: &File,
        expected_state: LinuxFileState,
        expected: &[u8],
        label: &str,
    ) -> Result<Vec<u8>> {
        let before = file_state(file, label)?;
        ensure!(
            before == expected_state,
            "retained file metadata changed before reading {label}"
        );
        validate_private_file_policy(before, expected.len(), label)?;

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(expected.len())
            .with_context(|| format!("cannot allocate bounded file buffer for {label}"))?;
        bytes.resize(expected.len(), 0);
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let read = file
                .read_at(
                    &mut bytes[offset..],
                    u64::try_from(offset).context("negative-ancestry read offset overflowed")?,
                )
                .with_context(|| format!("cannot read retained file {label}"))?;
            ensure!(read != 0, "retained file ended early while reading {label}");
            offset = offset
                .checked_add(read)
                .context("negative-ancestry read offset overflowed")?;
        }
        let mut trailing = [0_u8; 1];
        ensure!(
            file.read_at(&mut trailing, u64::try_from(expected.len())?)
                .with_context(|| format!("cannot verify EOF for {label}"))?
                == 0,
            "retained file has trailing bytes at {label}"
        );
        ensure!(
            bytes.as_slice() == expected,
            "retained file bytes differ from authenticated authority at {label}"
        );
        ensure!(
            file_state(file, label)? == before,
            "retained file metadata changed while reading {label}"
        );
        Ok(bytes)
    }

    impl PinnedLinuxFile {
        fn open_and_read(
            root: BorrowedFd<'_>,
            relative: &str,
            expected: &[u8],
        ) -> Result<(Self, Vec<u8>)> {
            let path_descriptor = rustix::fs::openat2(
                root,
                relative,
                PATH_FILE_FLAGS,
                rustix::fs::Mode::empty(),
                RESOLVE_FLAGS,
            )
            .with_context(|| format!("cannot pin negative-ancestry file {relative}"))?;
            let path_state = file_state(&path_descriptor, relative)?;
            validate_private_file_policy(path_state, expected.len(), relative)?;

            let data_descriptor = rustix::fs::openat2(
                root,
                relative,
                READ_FILE_FLAGS,
                rustix::fs::Mode::empty(),
                RESOLVE_FLAGS,
            )
            .with_context(|| format!("cannot open negative-ancestry file {relative}"))?;
            let data_descriptor = File::from(data_descriptor);
            ensure!(
                file_state(&data_descriptor, relative)? == path_state,
                "{relative} changed while its data descriptor was opened"
            );
            let bytes = read_stable_exact_bytes(&data_descriptor, path_state, expected, relative)?;
            Ok((
                Self {
                    path_descriptor,
                    data_descriptor,
                    state: path_state,
                    relative: relative.to_owned(),
                },
                bytes,
            ))
        }

        fn reauthenticate_beneath(&self, root: BorrowedFd<'_>, expected: &[u8]) -> Result<()> {
            ensure!(
                file_state(&self.path_descriptor, &self.relative)? == self.state,
                "retained path descriptor metadata changed for {}",
                self.relative
            );
            ensure!(
                file_state(&self.data_descriptor, &self.relative)? == self.state,
                "retained data descriptor metadata changed for {}",
                self.relative
            );
            read_stable_exact_bytes(&self.data_descriptor, self.state, expected, &self.relative)?;

            let (reopened, reopened_bytes) = Self::open_and_read(root, &self.relative, expected)?;
            ensure!(
                reopened.state == self.state && reopened_bytes.as_slice() == expected,
                "named file no longer identifies the retained file for {}",
                self.relative
            );
            read_stable_exact_bytes(&self.data_descriptor, self.state, expected, &self.relative)?;
            Ok(())
        }
    }

    impl PinnedNegativeAncestryTree {
        fn open(
            root: BorrowedFd<'_>,
            entries: &[B4NegativeAncestryPublicationEntryV1<'_>;
                 B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT],
        ) -> Result<Self> {
            let expected_inventories = expected_directory_inventories(entries)?;
            let root = open_directory_beneath(root, "")?;
            let root_mount = root.state.identity.mount_id;
            let mut directories = BTreeMap::new();
            for relative in expected_inventories.keys().filter(|path| !path.is_empty()) {
                let directory = open_directory_beneath(root.path_descriptor.as_fd(), relative)?;
                ensure!(
                    directory.state.identity.mount_id == root_mount,
                    "{relative} crossed the retained publication mount"
                );
                ensure!(
                    directories.insert(relative.clone(), directory).is_none(),
                    "duplicate retained negative-ancestry directory"
                );
            }
            let tree = Self {
                root,
                directories,
                expected_inventories,
            };
            tree.validate_exact_inventories_and_policy()?;
            tree.reauthenticate()?;
            Ok(tree)
        }

        fn directory(&self, relative: &str) -> Result<&PinnedLinuxDirectory> {
            if relative.is_empty() {
                Ok(&self.root)
            } else {
                self.directories
                    .get(relative)
                    .with_context(|| format!("retained directory is absent: {relative}"))
            }
        }

        fn validate_exact_inventories_and_policy(&self) -> Result<()> {
            for (relative, expected) in &self.expected_inventories {
                let directory = self.directory(relative)?;
                let label = if relative.is_empty() {
                    "negative-ancestry publication root"
                } else {
                    relative
                };
                validate_private_directory_policy(
                    directory.state,
                    expected_directory_link_count(relative, &self.expected_inventories)?,
                    label,
                )?;
                directory.validate_inventory(expected)?;
            }
            Ok(())
        }

        fn reauthenticate(&self) -> Result<()> {
            self.root
                .reauthenticate_beneath(self.root.path_descriptor.as_fd())?;
            for directory in self.directories.values() {
                directory.reauthenticate_beneath(self.root.path_descriptor.as_fd())?;
            }
            self.validate_exact_inventories_and_policy()
        }
    }

    pub(super) fn authenticate(
        root: BorrowedFd<'_>,
        authority: &dyn B4NegativeAncestryPublicationAuthority,
    ) -> Result<B4NegativeAncestryPublicationReadSetV1> {
        authenticate_with_hook(root, authority, || {})
    }

    fn authenticate_with_hook<AfterInitialReads>(
        root: BorrowedFd<'_>,
        authority: &dyn B4NegativeAncestryPublicationAuthority,
        after_initial_reads: AfterInitialReads,
    ) -> Result<B4NegativeAncestryPublicationReadSetV1>
    where
        AfterInitialReads: FnOnce(),
    {
        let entries = super::negative_ancestry_publication_entries(authority)?;
        let tree = PinnedNegativeAncestryTree::open(root, &entries)?;
        let mut retained_files = Vec::new();
        let mut authenticated_files = Vec::new();
        retained_files
            .try_reserve_exact(B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT)
            .context("cannot retain negative-ancestry file descriptors")?;
        authenticated_files
            .try_reserve_exact(B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT)
            .context("cannot retain authenticated negative-ancestry bytes")?;

        for entry in &entries {
            let (file, bytes) = PinnedLinuxFile::open_and_read(
                tree.root.path_descriptor.as_fd(),
                &entry.path,
                entry.bytes,
            )
            .with_context(|| format!("invalid descriptor-rooted file {}", entry.path))?;
            retained_files.push(file);
            authenticated_files.push(B4AuthenticatedPublishedFileV1 {
                path: entry.path.clone(),
                bytes,
            });
        }

        after_initial_reads();
        tree.reauthenticate()
            .context("negative-ancestry directory tree changed after initial reads")?;
        for (file, entry) in retained_files.iter().zip(&entries) {
            file.reauthenticate_beneath(tree.root.path_descriptor.as_fd(), entry.bytes)
                .with_context(|| format!("{} changed during final reauthentication", entry.path))?;
        }
        tree.reauthenticate()
            .context("negative-ancestry directory tree changed after file reauthentication")?;

        let authenticated_files = authenticated_files.try_into().map_err(
            |files: Vec<B4AuthenticatedPublishedFileV1>| {
                anyhow::anyhow!(
                    "descriptor-rooted read set has {} files instead of {}",
                    files.len(),
                    B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT
                )
            },
        )?;
        B4NegativeAncestryPublicationReadSetV1::from_authenticated_files(
            authenticated_files,
            authority,
        )
    }

    #[cfg(test)]
    pub(super) fn authenticate_with_test_hook<AfterInitialReads>(
        root: BorrowedFd<'_>,
        authority: &B4NegativeAncestryWitnessCatalogAuthorityV1,
        after_initial_reads: AfterInitialReads,
    ) -> Result<B4NegativeAncestryPublicationReadSetV1>
    where
        AfterInitialReads: FnOnce(),
    {
        authenticate_with_hook(root, authority, after_initial_reads)
    }

    fn create_private_directory(
        parent: BorrowedFd<'_>,
        name: &str,
        relative: &str,
    ) -> Result<PinnedLinuxDirectory> {
        if let Err(error) = rustix::fs::mkdirat(parent, name, PRIVATE_DIRECTORY_MODE) {
            if error == rustix::io::Errno::EXIST {
                bail!("descriptor-rooted publication entry is occupied: {relative}");
            }
            return Err(anyhow::Error::from(error))
                .with_context(|| format!("cannot create publication directory {relative}"));
        }
        let path_descriptor = rustix::fs::openat2(
            parent,
            name,
            PATH_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
            RESOLVE_FLAGS,
        )
        .with_context(|| format!("cannot pin created publication directory {relative}"))?;
        let read_descriptor = rustix::fs::openat2(
            parent,
            name,
            READ_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
            RESOLVE_FLAGS,
        )
        .with_context(|| format!("cannot retain created publication directory {relative}"))?;
        rustix::fs::fchmod(&read_descriptor, PRIVATE_DIRECTORY_MODE)
            .with_context(|| format!("cannot seal publication directory {relative}"))?;
        let state = directory_state(&path_descriptor, relative)?;
        ensure!(
            directory_state(&read_descriptor, relative)? == state,
            "created directory changed while being retained: {relative}"
        );
        validate_private_directory_policy(state, 2, relative)?;
        ensure!(
            enumerate_directory(read_descriptor.as_fd(), relative)?.is_empty(),
            "created publication directory was not empty: {relative}"
        );
        Ok(PinnedLinuxDirectory {
            path_descriptor,
            read_descriptor,
            state,
            relative: relative.to_owned(),
        })
    }

    fn create_private_file<Durability>(
        parent: BorrowedFd<'_>,
        name: &str,
        relative: &str,
        bytes: &[u8],
        durability: &mut Durability,
    ) -> Result<PinnedLinuxFile>
    where
        Durability: DescriptorDurability,
    {
        let descriptor = match rustix::fs::openat2(
            parent,
            name,
            CREATE_FILE_FLAGS,
            PRIVATE_FILE_MODE,
            RESOLVE_FLAGS,
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::EXIST => {
                bail!("descriptor-rooted publication entry is occupied: {relative}");
            }
            Err(error) => {
                return Err(anyhow::Error::from(error))
                    .with_context(|| format!("cannot create publication file {relative}"));
            }
        };
        let mut data_descriptor = File::from(descriptor);
        rustix::fs::fchmod(&data_descriptor, PRIVATE_FILE_MODE)
            .with_context(|| format!("cannot seal publication file {relative}"))?;
        validate_private_file_policy(file_state(&data_descriptor, relative)?, 0, relative)?;
        data_descriptor
            .write_all(bytes)
            .with_context(|| format!("cannot write publication file {relative}"))?;
        data_descriptor
            .flush()
            .with_context(|| format!("cannot flush publication file {relative}"))?;
        durability.synchronize_file(&data_descriptor, relative)?;
        let state = file_state(&data_descriptor, relative)?;
        validate_private_file_policy(state, bytes.len(), relative)?;
        read_stable_exact_bytes(&data_descriptor, state, bytes, relative)?;

        let path_descriptor = rustix::fs::openat2(
            parent,
            name,
            PATH_FILE_FLAGS,
            rustix::fs::Mode::empty(),
            RESOLVE_FLAGS,
        )
        .with_context(|| format!("cannot re-pin created publication file {relative}"))?;
        ensure!(
            file_state(&path_descriptor, relative)? == state,
            "created publication file changed while its path descriptor was retained: {relative}"
        );
        Ok(PinnedLinuxFile {
            path_descriptor,
            data_descriptor,
            state,
            relative: relative.to_owned(),
        })
    }

    pub(super) fn materialize(
        root: BorrowedFd<'_>,
        authority: &dyn B4NegativeAncestryPublicationAuthority,
    ) -> Result<()> {
        let mut durability = RealDescriptorDurability;
        materialize_with_durability(root, authority, &mut durability)
    }

    #[cfg(test)]
    pub(super) fn materialize_with_test_durability_hook<Hook>(
        root: BorrowedFd<'_>,
        authority: &B4NegativeAncestryWitnessCatalogAuthorityV1,
        hook: Hook,
    ) -> Result<()>
    where
        Hook: FnMut(DescriptorDurabilityEvent) -> Result<()>,
    {
        let mut durability = HookedDescriptorDurability {
            hook,
            real: RealDescriptorDurability,
        };
        materialize_with_durability(root, authority, &mut durability)
    }

    fn materialize_with_durability<Durability>(
        root: BorrowedFd<'_>,
        authority: &dyn B4NegativeAncestryPublicationAuthority,
        durability: &mut Durability,
    ) -> Result<()>
    where
        Durability: DescriptorDurability,
    {
        let entries = super::negative_ancestry_publication_entries(authority)?;
        let expected_inventories = expected_directory_inventories(&entries)?;
        let mut retained_root = open_directory_beneath(root, "")?;
        validate_private_directory_policy(retained_root.state, 2, "publication root")?;
        ensure!(
            enumerate_directory(
                retained_root.read_descriptor.as_fd(),
                "negative-ancestry publication root",
            )?
            .is_empty(),
            "descriptor-rooted negative-ancestry publication requires an empty root"
        );
        retained_root.reauthenticate_beneath(retained_root.path_descriptor.as_fd())?;
        let initial_root = retained_root.state;

        let mut reproduction = create_private_directory(
            retained_root.path_descriptor.as_fd(),
            "reproduction",
            "reproduction",
        )?;
        let mut witnesses = create_private_directory(
            reproduction.path_descriptor.as_fd(),
            "negative-ancestry-witnesses",
            "reproduction/negative-ancestry-witnesses",
        )?;
        ensure!(
            reproduction.state.identity.mount_id == initial_root.identity.mount_id
                && witnesses.state.identity.mount_id == initial_root.identity.mount_id,
            "created negative-ancestry directories crossed the retained root mount"
        );

        let mut retained_files = Vec::new();
        retained_files
            .try_reserve_exact(B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT)
            .context("cannot retain created negative-ancestry files")?;
        for entry in &entries {
            let (parent, name) = entry
                .path
                .rsplit_once('/')
                .context("compiled publication path has no parent")?;
            let parent_descriptor = match parent {
                "reproduction" => reproduction.path_descriptor.as_fd(),
                "reproduction/negative-ancestry-witnesses" => witnesses.path_descriptor.as_fd(),
                _ => bail!("compiled publication parent drifted: {parent}"),
            };
            let file = create_private_file(
                parent_descriptor,
                name,
                &entry.path,
                entry.bytes,
                durability,
            )?;
            ensure!(
                file.state.identity.mount_id == initial_root.identity.mount_id,
                "{} crossed the retained publication mount",
                entry.path
            );
            retained_files.push(file);
        }

        retained_root.refresh_after_expected_mutation()?;
        reproduction.refresh_after_expected_mutation()?;
        witnesses.refresh_after_expected_mutation()?;
        validate_private_directory_policy(
            retained_root.state,
            expected_directory_link_count("", &expected_inventories)?,
            "negative-ancestry publication root",
        )?;
        validate_private_directory_policy(
            reproduction.state,
            expected_directory_link_count("reproduction", &expected_inventories)?,
            "reproduction",
        )?;
        validate_private_directory_policy(
            witnesses.state,
            expected_directory_link_count(
                "reproduction/negative-ancestry-witnesses",
                &expected_inventories,
            )?,
            "reproduction/negative-ancestry-witnesses",
        )?;

        durability.synchronize_directory(
            witnesses.read_descriptor.as_fd(),
            DescriptorDirectoryDurabilityRole::Witnesses,
        )?;
        durability.synchronize_directory(
            reproduction.read_descriptor.as_fd(),
            DescriptorDirectoryDurabilityRole::Reproduction,
        )?;
        durability.synchronize_directory(
            retained_root.read_descriptor.as_fd(),
            DescriptorDirectoryDurabilityRole::Root,
        )?;

        authenticate(retained_root.path_descriptor.as_fd(), authority)
            .context("cannot reopen descriptor-rooted negative-ancestry publication")?;
        retained_root.reauthenticate_beneath(retained_root.path_descriptor.as_fd())?;
        reproduction.reauthenticate_beneath(retained_root.path_descriptor.as_fd())?;
        witnesses.reauthenticate_beneath(retained_root.path_descriptor.as_fd())?;
        for (file, entry) in retained_files.iter().zip(&entries) {
            file.reauthenticate_beneath(retained_root.path_descriptor.as_fd(), entry.bytes)
                .with_context(|| {
                    format!("created file changed before custody return: {}", entry.path)
                })?;
        }
        retained_root.reauthenticate_beneath(retained_root.path_descriptor.as_fd())?;
        Ok(())
    }
}

struct B4NegativeAncestryPublicationEntryV1<'a> {
    path: String,
    bytes: &'a [u8],
}

struct B4AuthenticatedPublishedFileV1 {
    path: String,
    bytes: Vec<u8>,
}

pub(crate) struct B4NegativeAncestryPublicationReadSetV1 {
    catalog: Eip0045B4NegativeAncestryWitnessCatalogV1,
    files: [B4AuthenticatedPublishedFileV1; B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT],
}

/// Distinct reopened read-set authenticated only by a V2 catalogue authority.
pub(crate) struct B4NegativeAncestryPublicationReadSetV2 {
    inner: B4NegativeAncestryPublicationReadSetV1,
}

#[allow(
    dead_code,
    reason = "the accessors are consumed by the V2 materialization and custody joins"
)]
impl B4NegativeAncestryPublicationReadSetV2 {
    pub(crate) const fn catalog(&self) -> &Eip0045B4NegativeAncestryWitnessCatalogV1 {
        self.inner.catalog()
    }

    pub(crate) fn catalog_jcs(&self) -> &[u8] {
        self.inner.catalog_jcs()
    }

    pub(crate) fn alternate_guest_elf(&self) -> &[u8] {
        self.inner.alternate_guest_elf()
    }

    pub(crate) fn compiled_row_witness(&self, expanded_row: u16) -> Result<(&[u8], &[u8])> {
        self.inner.compiled_row_witness(expanded_row)
    }

    pub(crate) fn ordered_files(&self) -> impl ExactSizeIterator<Item = (&str, &[u8])> {
        self.inner.ordered_files()
    }
}

#[allow(
    dead_code,
    reason = "the read-only accessors are consumed by subsequent authenticated B4 reproduction tasks"
)]
impl B4NegativeAncestryPublicationReadSetV1 {
    pub(crate) const fn catalog(&self) -> &Eip0045B4NegativeAncestryWitnessCatalogV1 {
        &self.catalog
    }

    pub(crate) fn catalog_jcs(&self) -> &[u8] {
        &self.files[0].bytes
    }

    pub(crate) fn alternate_guest_elf(&self) -> &[u8] {
        &self.files[1].bytes
    }

    pub(crate) fn compiled_row_witness(&self, expanded_row: u16) -> Result<(&[u8], &[u8])> {
        let slot = compiled_negative_ancestry_witness_layout()?
            .into_iter()
            .position(|slot| slot.expanded_row == expanded_row)
            .context("expanded row is absent from the compiled negative-ancestry layout")?;
        let raw_seal = 2 + slot * 2;
        Ok((&self.files[raw_seal].bytes, &self.files[raw_seal + 1].bytes))
    }

    pub(crate) fn ordered_files(&self) -> impl ExactSizeIterator<Item = (&str, &[u8])> {
        self.files
            .iter()
            .map(|file| (file.path.as_str(), file.bytes.as_slice()))
    }

    fn from_authenticated_files(
        files: [B4AuthenticatedPublishedFileV1; B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT],
        authority: &dyn B4NegativeAncestryPublicationAuthority,
    ) -> Result<Self> {
        ensure!(
            files[0].path == B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_PATH,
            "authenticated publication index zero is not the compiled catalogue path"
        );
        let catalog =
            Eip0045B4NegativeAncestryWitnessCatalogV1::from_canonical_jcs(&files[0].bytes)
                .context("cannot parse reopened negative-ancestry catalogue")?;
        authority
            .verify_candidate_jcs(&files[0].bytes)
            .context("reopened negative-ancestry catalogue is unauthorized")?;

        remeasure_authenticated_file(
            &files[1],
            B4_NEGATIVE_ANCESTRY_ALTERNATE_GUEST_ELF_PATH,
            &catalog.alternate_guest_elf,
            "alternate guest ELF",
        )?;

        let layout = compiled_negative_ancestry_witness_layout()?;
        ensure!(
            catalog.entries.len() == layout.len(),
            "reopened negative-ancestry catalogue row count differs from compiled layout"
        );
        for (slot, (expected, entry)) in layout.iter().zip(&catalog.entries).enumerate() {
            ensure!(
                entry.expanded_row == expected.expanded_row,
                "reopened negative-ancestry catalogue row order differs from compiled layout"
            );
            remeasure_authenticated_file(
                &files[2 + slot * 2],
                &expected.raw_seal_path,
                &entry.raw_seal,
                "negative-ancestry raw seal",
            )?;
            remeasure_authenticated_file(
                &files[3 + slot * 2],
                &expected.receipt_oracle_path,
                &entry.receipt_oracle,
                "negative-ancestry receipt oracle",
            )?;
        }

        Ok(Self { catalog, files })
    }
}

fn remeasure_authenticated_file(
    file: &B4AuthenticatedPublishedFileV1,
    compiled_path: &str,
    expected: &B4ContractArtifactIdentityV1,
    label: &str,
) -> Result<()> {
    ensure!(
        file.path == compiled_path && expected.path == compiled_path,
        "{label} path differs from the compiled publication inventory"
    );
    let measured =
        B4ContractArtifactIdentityV1::from_bytes(&file.path, expected.encoding, &file.bytes)?;
    ensure!(
        measured == *expected,
        "{label} differs from the reopened catalogue identity"
    );
    Ok(())
}

fn negative_ancestry_publication_entries(
    authority: &dyn B4NegativeAncestryPublicationAuthority,
) -> Result<[B4NegativeAncestryPublicationEntryV1<'_>; B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT]>
{
    let expected_paths = compiled_negative_ancestry_publication_paths()?;
    let layout = compiled_negative_ancestry_witness_layout()?;
    let retained = authority.retained_entries();
    ensure!(
        retained.len() == layout.len(),
        "retained negative-ancestry row count differs from compiled layout"
    );

    let mut entries = Vec::with_capacity(B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT);
    entries.push(B4NegativeAncestryPublicationEntryV1 {
        path: B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_PATH.to_owned(),
        bytes: authority.canonical_catalog_jcs(),
    });
    entries.push(B4NegativeAncestryPublicationEntryV1 {
        path: B4_NEGATIVE_ANCESTRY_ALTERNATE_GUEST_ELF_PATH.to_owned(),
        bytes: authority.alternate_guest_elf(),
    });
    for (slot, retained) in layout.into_iter().zip(retained) {
        ensure!(
            slot.expanded_row == retained.expanded_row,
            "retained negative-ancestry row differs from compiled layout"
        );
        entries.push(B4NegativeAncestryPublicationEntryV1 {
            path: slot.raw_seal_path,
            bytes: &retained.raw_seal,
        });
        entries.push(B4NegativeAncestryPublicationEntryV1 {
            path: slot.receipt_oracle_path,
            bytes: &retained.receipt_oracle,
        });
    }
    ensure!(
        entries
            .iter()
            .map(|entry| entry.path.as_str())
            .eq(expected_paths.iter().map(String::as_str)),
        "authority publication projection differs from compiled path inventory"
    );
    entries.try_into().map_err(|entries: Vec<_>| {
        anyhow::anyhow!(
            "authority publication projection has {} files instead of {}",
            entries.len(),
            B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT
        )
    })
}

/// Validate one complete, authenticated B4 negative-ancestry publication root.
///
/// Consumers must revalidate before use. Custody assumes trusted ownership of
/// the publication parent; this function does not make the tree immutable.
///
/// # Errors
///
/// Returns an error for authority inconsistency, any missing or extra entry,
/// unsafe filesystem object, identity race, non-single-link file, or byte
/// mismatch.
pub fn validate_published_b4_negative_ancestry_witness_catalog(
    output_root: &Path,
    authority: &B4NegativeAncestryWitnessCatalogAuthorityV1,
) -> Result<()> {
    authenticate_published_b4_negative_ancestry_read_set(output_root, authority)?;
    Ok(())
}

/// Validate one complete publication against a V2-derived catalogue authority.
///
/// # Errors
///
/// Returns the first filesystem, identity, inventory, or authority mismatch.
pub fn validate_published_b4_negative_ancestry_witness_catalog_v2(
    output_root: &Path,
    authority: &B4NegativeAncestryWitnessCatalogAuthorityV2,
) -> Result<()> {
    authenticate_published_b4_negative_ancestry_read_set_v2(output_root, authority)?;
    Ok(())
}

/// Validate one exact publication beneath an already retained Linux directory
/// descriptor.
///
/// No ambient pathname is used to locate the supplied root. Every descendant
/// is resolved beneath that retained descriptor.
///
/// # Errors
///
/// Returns an error for unsupported `openat2` resolution, unsafe objects,
/// inventory or permission drift, unstable identity or bytes, or authority
/// mismatch.
#[doc(hidden)]
#[cfg(target_os = "linux")]
pub fn validate_published_b4_negative_ancestry_witness_catalog_from_directory_descriptor(
    root: std::os::fd::BorrowedFd<'_>,
    authority: &B4NegativeAncestryWitnessCatalogAuthorityV1,
) -> Result<()> {
    authenticate_published_b4_negative_ancestry_read_set_from_directory_descriptor(
        root, authority,
    )?;
    Ok(())
}

/// Validate one descriptor-rooted publication against a V2 authority.
///
/// # Errors
///
/// Returns the first descriptor, inventory, identity, or authority mismatch.
#[doc(hidden)]
#[cfg(target_os = "linux")]
pub fn validate_published_b4_negative_ancestry_witness_catalog_from_directory_descriptor_v2(
    root: std::os::fd::BorrowedFd<'_>,
    authority: &B4NegativeAncestryWitnessCatalogAuthorityV2,
) -> Result<()> {
    authenticate_published_b4_negative_ancestry_read_set_from_directory_descriptor_v2(
        root, authority,
    )?;
    Ok(())
}

/// Reopen and retain the complete authenticated publication read-set beneath a
/// retained Linux directory descriptor.
#[cfg(target_os = "linux")]
pub(crate) fn authenticate_published_b4_negative_ancestry_read_set_from_directory_descriptor(
    root: std::os::fd::BorrowedFd<'_>,
    authority: &B4NegativeAncestryWitnessCatalogAuthorityV1,
) -> Result<B4NegativeAncestryPublicationReadSetV1> {
    descriptor_rooted_linux::authenticate(root, authority)
}

#[cfg(target_os = "linux")]
pub(crate) fn authenticate_published_b4_negative_ancestry_read_set_from_directory_descriptor_v2(
    root: std::os::fd::BorrowedFd<'_>,
    authority: &B4NegativeAncestryWitnessCatalogAuthorityV2,
) -> Result<B4NegativeAncestryPublicationReadSetV2> {
    Ok(B4NegativeAncestryPublicationReadSetV2 {
        inner: descriptor_rooted_linux::authenticate(root, authority)?,
    })
}

/// Materialize the exact publication into one empty retained Linux directory.
///
/// This operation performs no ambient-path effect and no inner rename. Its
/// caller owns the outer create-only commit.
///
/// # Errors
///
/// Returns an error before the first effect unless `root` is an empty private
/// directory. Later errors retain any partial tree for outer custody.
#[doc(hidden)]
#[cfg(target_os = "linux")]
pub fn materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor(
    root: std::os::fd::BorrowedFd<'_>,
    authority: &B4NegativeAncestryWitnessCatalogAuthorityV1,
) -> Result<()> {
    descriptor_rooted_linux::materialize(root, authority)
}

/// Materialize the exact V1 wire selected by a V2 authority into an empty descriptor root.
///
/// # Errors
///
/// Returns the first preflight, creation, write, durability, or reopen failure.
#[doc(hidden)]
#[cfg(target_os = "linux")]
pub fn materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor_v2(
    root: std::os::fd::BorrowedFd<'_>,
    authority: &B4NegativeAncestryWitnessCatalogAuthorityV2,
) -> Result<()> {
    descriptor_rooted_linux::materialize(root, authority)
}

pub(crate) fn authenticate_published_b4_negative_ancestry_read_set(
    output_root: &Path,
    authority: &B4NegativeAncestryWitnessCatalogAuthorityV1,
) -> Result<B4NegativeAncestryPublicationReadSetV1> {
    authenticate_published_b4_negative_ancestry_read_set_core(output_root, authority)
}

pub(crate) fn authenticate_published_b4_negative_ancestry_read_set_v2(
    output_root: &Path,
    authority: &B4NegativeAncestryWitnessCatalogAuthorityV2,
) -> Result<B4NegativeAncestryPublicationReadSetV2> {
    Ok(B4NegativeAncestryPublicationReadSetV2 {
        inner: authenticate_published_b4_negative_ancestry_read_set_core(output_root, authority)?,
    })
}

fn authenticate_published_b4_negative_ancestry_read_set_core(
    output_root: &Path,
    authority: &dyn B4NegativeAncestryPublicationAuthority,
) -> Result<B4NegativeAncestryPublicationReadSetV1> {
    let entries = negative_ancestry_publication_entries(authority)?;
    validate_negative_ancestry_publication_shape(output_root, &entries)?;

    let mut files = Vec::with_capacity(B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT);
    for entry in entries {
        let bytes = read_validated_exact_file(&output_root.join(&entry.path), entry.bytes)
            .with_context(|| format!("invalid published file {}", entry.path))?;
        files.push(B4AuthenticatedPublishedFileV1 {
            path: entry.path,
            bytes,
        });
    }
    let files = files.try_into().map_err(|files: Vec<_>| {
        anyhow::anyhow!(
            "authenticated publication read set has {} files instead of {}",
            files.len(),
            B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT
        )
    })?;
    B4NegativeAncestryPublicationReadSetV1::from_authenticated_files(files, authority)
}

fn validate_negative_ancestry_publication_shape(
    output_root: &Path,
    entries: &[B4NegativeAncestryPublicationEntryV1<'_>;
         B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT],
) -> Result<()> {
    let reproduction = output_root.join("reproduction");
    let witness_root = reproduction.join("negative-ancestry-witnesses");

    validate_ordinary_directory(output_root)?;
    validate_ordinary_directory(&reproduction)?;
    validate_ordinary_directory(&witness_root)?;
    validate_exact_directory_entries(output_root, &["reproduction"])?;
    validate_exact_directory_entries(
        &reproduction,
        &[
            "negative-ancestry-witness-catalog.json",
            "negative-ancestry-witnesses",
        ],
    )?;

    let witness_names = entries
        .iter()
        .skip(1)
        .map(|entry| {
            Path::new(&entry.path)
                .file_name()
                .and_then(|name| name.to_str())
                .context("compiled publication path has no portable file name")
        })
        .collect::<Result<Vec<_>>>()?;
    validate_exact_directory_entries(&witness_root, &witness_names)?;
    Ok(())
}

/// Materialize one B4 negative-ancestry publication root without replacement.
///
/// Publication requires a trusted parent and supported atomic no-replace
/// filesystem semantics. A later consumer must revalidate before use.
///
/// # Errors
///
/// Returns an error for an unsupported platform or filesystem, occupied path,
/// authority inconsistency, write or durability failure, rename failure, or
/// post-publication validation failure. A failure after rename may leave the
/// destination committed.
pub fn publish_b4_negative_ancestry_witness_catalog(
    output_root: &Path,
    authority: &B4NegativeAncestryWitnessCatalogAuthorityV1,
) -> Result<()> {
    #[cfg(unix)]
    {
        let mut instrumentation = RealPublicationInstrumentation;
        publish_b4_negative_ancestry_witness_catalog_impl(
            output_root,
            authority,
            &mut instrumentation,
            |_staging, _destination| Ok(()),
            |_staging, _destination| Ok(()),
        )
    }
    #[cfg(not(unix))]
    {
        let _ = (output_root, authority);
        bail!("B4 negative-ancestry publication requires Unix no-replace rename semantics")
    }
}

/// Publish the exact V1 wire selected by a distinct V2 authority.
///
/// # Errors
///
/// Returns the first filesystem, durability, atomicity, or reopen failure.
pub fn publish_b4_negative_ancestry_witness_catalog_v2(
    output_root: &Path,
    authority: &B4NegativeAncestryWitnessCatalogAuthorityV2,
) -> Result<()> {
    #[cfg(unix)]
    {
        let mut instrumentation = RealPublicationInstrumentation;
        publish_b4_negative_ancestry_witness_catalog_impl(
            output_root,
            authority,
            &mut instrumentation,
            |_staging, _destination| Ok(()),
            |_staging, _destination| Ok(()),
        )
    }
    #[cfg(not(unix))]
    {
        let _ = (output_root, authority);
        bail!("B4 V2 negative-ancestry publication requires Unix no-replace rename semantics")
    }
}

fn validate_ordinary_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect directory {}", path.display()))?;
    ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "{} is not an ordinary directory",
        path.display()
    );
    ensure!(
        !metadata_is_reparse_point(&metadata),
        "{} is a reparse point",
        path.display()
    );
    Ok(())
}

fn validate_exact_directory_entries(path: &Path, expected: &[&str]) -> Result<()> {
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for entry in
        fs::read_dir(path).with_context(|| format!("cannot read directory {}", path.display()))?
    {
        let entry =
            entry.with_context(|| format!("cannot read directory entry in {}", path.display()))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("{} contains a non-UTF-8 entry name", path.display()))?;
        ensure!(
            actual.insert(name),
            "{} contains a duplicate entry name",
            path.display()
        );
    }
    ensure!(
        actual
            == expected
                .into_iter()
                .map(str::to_owned)
                .collect::<BTreeSet<_>>(),
        "{} does not have the exact compiled publication shape",
        path.display()
    );
    Ok(())
}

fn read_validated_exact_file(path: &Path, expected: &[u8]) -> Result<Vec<u8>> {
    let path_before = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect file {}", path.display()))?;
    validate_ordinary_file_metadata(path, &path_before)?;

    let mut file = open_validation_file(path)
        .with_context(|| format!("cannot open file {}", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("cannot inspect opened file {}", path.display()))?;
    validate_opened_file(path, &file, &opened)?;
    let opened_identity = file_identity(&file, &opened)?;
    #[cfg(unix)]
    ensure!(
        file_identity(&file, &path_before)? == opened_identity,
        "{} changed between path inspection and open",
        path.display()
    );

    let read_limit = u64::try_from(expected.len())
        .context("expected publication file length does not fit u64")?
        .checked_add(1)
        .context("expected publication file length is too large")?;
    let mut actual = Vec::with_capacity(expected.len().saturating_add(1));
    std::io::Read::by_ref(&mut file)
        .take(read_limit)
        .read_to_end(&mut actual)
        .with_context(|| format!("cannot read file {}", path.display()))?;
    ensure!(
        actual.as_slice() == expected,
        "{} bytes differ from authenticated authority",
        path.display()
    );

    let path_after = fs::symlink_metadata(path)
        .with_context(|| format!("cannot re-inspect file {}", path.display()))?;
    validate_ordinary_file_metadata(path, &path_after)?;
    let reopened = open_validation_file(path)
        .with_context(|| format!("cannot reopen file {}", path.display()))?;
    let reopened_metadata = reopened
        .metadata()
        .with_context(|| format!("cannot inspect reopened file {}", path.display()))?;
    validate_opened_file(path, &reopened, &reopened_metadata)?;
    ensure!(
        opened_identity == file_identity(&reopened, &reopened_metadata)?,
        "{} changed while it was being validated",
        path.display()
    );
    Ok(actual)
}

fn validate_ordinary_file_metadata(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "{} is not an ordinary regular file",
        path.display()
    );
    ensure!(
        !metadata_is_reparse_point(metadata),
        "{} is a reparse point",
        path.display()
    );
    Ok(())
}

fn validate_opened_file(path: &Path, file: &File, metadata: &fs::Metadata) -> Result<()> {
    validate_ordinary_file_metadata(path, metadata)?;
    ensure!(
        metadata_link_count(file, metadata)? == 1,
        "{} must have exactly one hard link",
        path.display()
    );
    #[cfg(windows)]
    validate_opened_windows_disk_file(path, file)?;
    Ok(())
}

#[cfg(unix)]
fn file_identity(_file: &File, metadata: &fs::Metadata) -> Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;

    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn file_identity(file: &File, _metadata: &fs::Metadata) -> Result<(u64, u64)> {
    let information = winapi_util::file::information(file)
        .context("cannot query opened Windows file identity")?;
    Ok((information.volume_serial_number(), information.file_index()))
}

#[cfg(not(any(unix, windows)))]
fn file_identity(_file: &File, _metadata: &fs::Metadata) -> Result<(u8, u8)> {
    bail!("publication validation has no file-identity implementation on this platform")
}

#[cfg(unix)]
fn metadata_link_count(_file: &File, metadata: &fs::Metadata) -> Result<u64> {
    use std::os::unix::fs::MetadataExt as _;

    Ok(metadata.nlink())
}

#[cfg(windows)]
fn metadata_link_count(file: &File, _metadata: &fs::Metadata) -> Result<u64> {
    Ok(winapi_util::file::information(file)
        .context("cannot query opened Windows hard-link count")?
        .number_of_links())
}

#[cfg(not(any(unix, windows)))]
fn metadata_link_count(_file: &File, _metadata: &fs::Metadata) -> Result<u64> {
    bail!("publication validation has no hard-link-count implementation on this platform")
}

#[cfg(windows)]
fn validate_opened_windows_disk_file(path: &Path, file: &File) -> Result<()> {
    let information = winapi_util::file::information(file)
        .with_context(|| format!("cannot query opened Windows file {}", path.display()))?;
    ensure!(
        information.file_attributes() & 0x0400 == 0,
        "{} is a reparse point",
        path.display()
    );
    ensure!(
        winapi_util::file::typ(file)
            .with_context(|| format!("cannot query opened Windows file {}", path.display()))?
            .is_disk(),
        "{} is not a disk file",
        path.display()
    );
    ensure!(
        information.number_of_links() == 1,
        "{} must have exactly one hard link",
        path.display()
    );
    Ok(())
}

#[cfg(windows)]
fn open_validation_file(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(windows))]
fn open_validation_file(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn negative_ancestry_staging_path(output_root: &Path) -> Result<PathBuf> {
    let parent = usable_parent(output_root);
    let name = output_root
        .file_name()
        .and_then(|name| name.to_str())
        .context("publication output root must have a portable final component")?;
    ensure!(
        !name.is_empty(),
        "publication output root must have a final component"
    );
    Ok(parent.join(format!(".{name}.negative-ancestry-publication-staging")))
}

#[cfg(unix)]
fn usable_parent(path: &Path) -> &Path {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    }
}

#[cfg(unix)]
fn ensure_path_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("cannot inspect publication path {}", path.display())),
        Ok(_) => bail!("publication path is already occupied: {}", path.display()),
    }
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum PublicationOperation<'a> {
    AtomicSupportPreflight,
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "the relative path is consumed only by the private test recorder"
        )
    )]
    FileSynced(&'a str),
    StagedValidated,
    WitnessDirectorySynced,
    ReproductionDirectorySynced,
    StagingDirectorySynced,
    ExclusiveRenamed,
    ParentDirectorySynced,
    FinalValidated,
}

#[cfg(unix)]
trait PublicationInstrumentation {
    fn before_observed_transition(&mut self, operation: PublicationOperation<'_>) -> Result<()>;
    fn atomic_support(&mut self, parent: &Path) -> Result<bool>;
    fn observe(&mut self, operation: PublicationOperation<'_>);
}

#[cfg(unix)]
struct RealPublicationInstrumentation;

#[cfg(unix)]
impl PublicationInstrumentation for RealPublicationInstrumentation {
    fn before_observed_transition(&mut self, _operation: PublicationOperation<'_>) -> Result<()> {
        Ok(())
    }

    fn atomic_support(&mut self, parent: &Path) -> Result<bool> {
        Ok(renamore::rename_exclusive_is_atomic(parent)?)
    }

    fn observe(&mut self, _operation: PublicationOperation<'_>) {}
}

#[cfg(unix)]
fn perform_observed_publication_transition<Instrumentation, Transition>(
    instrumentation: &mut Instrumentation,
    operation: PublicationOperation<'_>,
    transition: Transition,
) -> Result<()>
where
    Instrumentation: PublicationInstrumentation,
    Transition: FnOnce() -> Result<()>,
{
    instrumentation.before_observed_transition(operation)?;
    transition()?;
    instrumentation.observe(operation);
    Ok(())
}

#[cfg(unix)]
fn perform_observed_atomic_support_preflight<Instrumentation>(
    instrumentation: &mut Instrumentation,
    parent: &Path,
) -> Result<bool>
where
    Instrumentation: PublicationInstrumentation,
{
    let operation = PublicationOperation::AtomicSupportPreflight;
    instrumentation.before_observed_transition(operation)?;
    let supported = instrumentation.atomic_support(parent)?;
    instrumentation.observe(operation);
    Ok(supported)
}

#[cfg(unix)]
fn publish_b4_negative_ancestry_witness_catalog_impl<Instrumentation, PreRename, PostRename>(
    output_root: &Path,
    authority: &dyn B4NegativeAncestryPublicationAuthority,
    instrumentation: &mut Instrumentation,
    pre_rename: PreRename,
    post_rename: PostRename,
) -> Result<()>
where
    Instrumentation: PublicationInstrumentation,
    PreRename: FnOnce(&Path, &Path) -> Result<()>,
    PostRename: FnOnce(&Path, &Path) -> Result<()>,
{
    use std::os::unix::fs::OpenOptionsExt as _;

    let parent = usable_parent(output_root);
    validate_ordinary_directory(parent)?;
    ensure!(
        perform_observed_atomic_support_preflight(instrumentation, parent).with_context(|| {
            format!(
                "cannot establish atomic no-replace support for {}",
                parent.display()
            )
        })?,
        "{} does not support atomic no-replace publication",
        parent.display()
    );
    let staging = negative_ancestry_staging_path(output_root)?;
    ensure_path_absent(output_root)?;
    ensure_path_absent(&staging)?;

    create_private_directory(&staging)
        .with_context(|| format!("cannot create staging root {}", staging.display()))?;
    let reproduction = staging.join("reproduction");
    create_private_directory(&reproduction)
        .with_context(|| format!("cannot create {}", reproduction.display()))?;
    let witness_root = reproduction.join("negative-ancestry-witnesses");
    create_private_directory(&witness_root)
        .with_context(|| format!("cannot create {}", witness_root.display()))?;

    for entry in negative_ancestry_publication_entries(authority)? {
        let path = staging.join(&entry.path);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("cannot create publication file {}", path.display()))?;
        std::io::Write::write_all(&mut file, entry.bytes)
            .with_context(|| format!("cannot write publication file {}", path.display()))?;
        perform_observed_publication_transition(
            instrumentation,
            PublicationOperation::FileSynced(&entry.path),
            || {
                file.sync_all()
                    .with_context(|| format!("cannot sync publication file {}", path.display()))
            },
        )?;
    }

    perform_observed_publication_transition(
        instrumentation,
        PublicationOperation::StagedValidated,
        || {
            authenticate_published_b4_negative_ancestry_read_set_core(&staging, authority)
                .map(|_| ())
        },
    )?;
    perform_observed_publication_transition(
        instrumentation,
        PublicationOperation::WitnessDirectorySynced,
        || sync_directory(&witness_root),
    )?;
    perform_observed_publication_transition(
        instrumentation,
        PublicationOperation::ReproductionDirectorySynced,
        || sync_directory(&reproduction),
    )?;
    perform_observed_publication_transition(
        instrumentation,
        PublicationOperation::StagingDirectorySynced,
        || sync_directory(&staging),
    )?;
    pre_rename(&staging, output_root)?;
    perform_observed_publication_transition(
        instrumentation,
        PublicationOperation::ExclusiveRenamed,
        || {
            renamore::rename_exclusive(&staging, output_root).with_context(|| {
                format!(
                    "cannot publish {} create-only at {}",
                    staging.display(),
                    output_root.display()
                )
            })
        },
    )?;
    perform_observed_publication_transition(
        instrumentation,
        PublicationOperation::ParentDirectorySynced,
        || sync_directory(parent),
    )?;
    post_rename(&staging, output_root)?;
    perform_observed_publication_transition(
        instrumentation,
        PublicationOperation::FinalValidated,
        || {
            authenticate_published_b4_negative_ancestry_read_set_core(output_root, authority)
                .map(|_| ())
        },
    )?;
    Ok(())
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("cannot open directory {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("cannot sync directory {}", path.display()))
}

#[cfg(all(test, unix))]
fn publish_b4_negative_ancestry_witness_catalog_with_test_hooks<PreRename, PostRename>(
    output_root: &Path,
    authority: &B4NegativeAncestryWitnessCatalogAuthorityV1,
    pre_rename: PreRename,
    post_rename: PostRename,
) -> Result<()>
where
    PreRename: FnOnce(&Path, &Path) -> Result<()>,
    PostRename: FnOnce(&Path, &Path) -> Result<()>,
{
    let mut instrumentation = RealPublicationInstrumentation;
    publish_b4_negative_ancestry_witness_catalog_impl(
        output_root,
        authority,
        &mut instrumentation,
        pre_rename,
        post_rename,
    )
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) fn write_exact_test_publication(
        root: &Path,
        authority: &B4NegativeAncestryWitnessCatalogAuthorityV1,
    ) -> Result<()> {
        write_exact_test_publication_core(root, authority)?;
        validate_published_b4_negative_ancestry_witness_catalog(root, authority)
    }

    pub(crate) fn write_exact_test_publication_v2(
        root: &Path,
        authority: &B4NegativeAncestryWitnessCatalogAuthorityV2,
    ) -> Result<()> {
        write_exact_test_publication_core(root, authority)?;
        validate_published_b4_negative_ancestry_witness_catalog_v2(root, authority)
    }

    fn write_exact_test_publication_core(
        root: &Path,
        authority: &dyn B4NegativeAncestryPublicationAuthority,
    ) -> Result<()> {
        fs::create_dir(root)
            .with_context(|| format!("cannot create test publication root {}", root.display()))?;
        let reproduction = root.join("reproduction");
        fs::create_dir(&reproduction)
            .with_context(|| format!("cannot create {}", reproduction.display()))?;
        let witnesses = reproduction.join("negative-ancestry-witnesses");
        fs::create_dir(&witnesses)
            .with_context(|| format!("cannot create {}", witnesses.display()))?;
        for entry in negative_ancestry_publication_entries(authority)? {
            fs::write(root.join(&entry.path), entry.bytes)
                .with_context(|| format!("cannot write test publication file {}", entry.path))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    #[cfg(unix)]
    use anyhow::bail;
    #[cfg(unix)]
    use sha2::{Digest as _, Sha256};
    #[cfg(unix)]
    use std::collections::BTreeSet;
    #[cfg(target_os = "linux")]
    use std::os::{
        fd::{AsFd as _, OwnedFd},
        unix::{
            fs::{MetadataExt as _, PermissionsExt as _},
            net::UnixListener,
        },
    };
    use tempfile::tempdir;

    use super::*;
    use crate::b4_campaign_contract::{B4ContractArtifactEncodingV1, B4ContractArtifactIdentityV1};

    fn synthetic_authority() -> B4NegativeAncestryWitnessCatalogAuthorityV1 {
        B4NegativeAncestryWitnessCatalogAuthorityV1::synthetic_for_publication_tests()
    }

    fn write_exact_tree(root: &Path, authority: &B4NegativeAncestryWitnessCatalogAuthorityV1) {
        test_support::write_exact_test_publication(root, authority).unwrap();
    }

    #[cfg(target_os = "linux")]
    fn create_private_descriptor_root(root: &Path) -> OwnedFd {
        fs::create_dir(root).unwrap();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        rustix::fs::open(
            root,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .unwrap()
    }

    #[cfg(target_os = "linux")]
    fn expected_descriptor_durability_events()
    -> Vec<descriptor_rooted_linux::DescriptorDurabilityEvent> {
        let mut events = compiled_negative_ancestry_publication_paths()
            .unwrap()
            .into_iter()
            .map(descriptor_rooted_linux::DescriptorDurabilityEvent::File)
            .collect::<Vec<_>>();
        events.extend([
            descriptor_rooted_linux::DescriptorDurabilityEvent::WitnessDirectory,
            descriptor_rooted_linux::DescriptorDurabilityEvent::ReproductionDirectory,
            descriptor_rooted_linux::DescriptorDurabilityEvent::RootDirectory,
        ]);
        events
    }

    fn expected_bytes<'a>(
        authority: &'a B4NegativeAncestryWitnessCatalogAuthorityV1,
        relative: &str,
    ) -> &'a [u8] {
        negative_ancestry_publication_entries(authority)
            .unwrap()
            .into_iter()
            .find(|entry| entry.path == relative)
            .unwrap()
            .bytes
    }

    #[cfg(all(unix, target_os = "linux"))]
    fn publication_tempdir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("eip0045-publication-")
            .tempdir_in("/dev/shm")
            .unwrap()
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    fn publication_tempdir() -> tempfile::TempDir {
        tempdir().unwrap()
    }

    #[cfg(unix)]
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum RecordedPublicationOperation {
        AtomicSupportPreflight,
        FileSynced(String),
        StagedValidated,
        WitnessDirectorySynced,
        ReproductionDirectorySynced,
        StagingDirectorySynced,
        ExclusiveRenamed,
        ParentDirectorySynced,
        FinalValidated,
    }

    #[cfg(unix)]
    struct RecordingPublicationInstrumentation {
        atomic_support: bool,
        operations: Vec<RecordedPublicationOperation>,
        fail_before_transition: Option<usize>,
        attempted_transitions: usize,
        completed_transitions: usize,
    }

    #[cfg(unix)]
    impl PublicationInstrumentation for RecordingPublicationInstrumentation {
        fn before_observed_transition(
            &mut self,
            _operation: PublicationOperation<'_>,
        ) -> Result<()> {
            let transition = self.attempted_transitions;
            self.attempted_transitions += 1;
            if self.fail_before_transition == Some(transition) {
                bail!("injected failure before publication transition {transition}");
            }
            Ok(())
        }

        fn atomic_support(&mut self, parent: &Path) -> Result<bool> {
            if self.atomic_support {
                Ok(renamore::rename_exclusive_is_atomic(parent)?)
            } else {
                Ok(false)
            }
        }

        fn observe(&mut self, operation: PublicationOperation<'_>) {
            let operation = match operation {
                PublicationOperation::AtomicSupportPreflight => {
                    RecordedPublicationOperation::AtomicSupportPreflight
                }
                PublicationOperation::FileSynced(path) => {
                    RecordedPublicationOperation::FileSynced(path.to_owned())
                }
                PublicationOperation::StagedValidated => {
                    RecordedPublicationOperation::StagedValidated
                }
                PublicationOperation::WitnessDirectorySynced => {
                    RecordedPublicationOperation::WitnessDirectorySynced
                }
                PublicationOperation::ReproductionDirectorySynced => {
                    RecordedPublicationOperation::ReproductionDirectorySynced
                }
                PublicationOperation::StagingDirectorySynced => {
                    RecordedPublicationOperation::StagingDirectorySynced
                }
                PublicationOperation::ExclusiveRenamed => {
                    RecordedPublicationOperation::ExclusiveRenamed
                }
                PublicationOperation::ParentDirectorySynced => {
                    RecordedPublicationOperation::ParentDirectorySynced
                }
                PublicationOperation::FinalValidated => {
                    RecordedPublicationOperation::FinalValidated
                }
            };
            assert_ne!(
                self.fail_before_transition,
                Some(self.completed_transitions),
                "injected transition reached its success observation"
            );
            self.completed_transitions += 1;
            self.operations.push(operation);
        }
    }

    #[test]
    fn authority_projects_exactly_twenty_four_files_without_public_byte_access() {
        let authority = synthetic_authority();
        let entries = negative_ancestry_publication_entries(&authority).unwrap();
        let expected_paths = compiled_negative_ancestry_publication_paths().unwrap();

        authority.catalog().validate().unwrap();
        authority
            .verify_candidate_jcs(authority.canonical_catalog_jcs())
            .unwrap();
        assert_eq!(
            authority.catalog().entries.len(),
            crate::b4_negative_ancestry_witness::B4_NEGATIVE_ANCESTRY_BINDING_COUNT
        );
        assert_eq!(entries.len(), B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT);
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            expected_paths
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        );
        assert_eq!(entries[0].path, B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_PATH);
        assert_eq!(entries[0].bytes, authority.canonical_catalog_jcs());
        assert_eq!(
            entries[1].path,
            B4_NEGATIVE_ANCESTRY_ALTERNATE_GUEST_ELF_PATH
        );
        assert!(!entries[1].bytes.is_empty());
        assert!(entries.iter().all(|entry| !entry.bytes.is_empty()));
    }

    #[test]
    fn authenticated_read_set_owns_exact_twenty_four_reopened_files() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("published");
        let authority = synthetic_authority();
        write_exact_tree(&root, &authority);

        let read_set =
            authenticate_published_b4_negative_ancestry_read_set(&root, &authority).unwrap();
        let expected_paths = compiled_negative_ancestry_publication_paths().unwrap();
        let before = read_set
            .ordered_files()
            .map(|(path, bytes)| (path.to_owned(), bytes.to_vec()))
            .collect::<Vec<_>>();

        assert_eq!(before.len(), B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT);
        assert_eq!(
            before
                .iter()
                .map(|(path, _)| path.as_str())
                .collect::<Vec<_>>(),
            expected_paths
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        );
        assert_eq!(read_set.catalog_jcs(), authority.canonical_catalog_jcs());
        authority
            .verify_candidate_jcs(read_set.catalog_jcs())
            .unwrap();
        assert_eq!(
            read_set.alternate_guest_elf(),
            authority.alternate_guest_elf()
        );

        fs::write(root.join(&expected_paths[1]), b"later mutation").unwrap();
        let after = read_set
            .ordered_files()
            .map(|(path, bytes)| (path.to_owned(), bytes.to_vec()))
            .collect::<Vec<_>>();
        assert_eq!(after, before);
        assert!(
            validate_published_b4_negative_ancestry_witness_catalog(&root, &authority).is_err()
        );
    }

    #[test]
    fn authenticated_read_set_rejects_coordinated_catalog_and_payload_rewrite() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("published");
        let authority = synthetic_authority();
        write_exact_tree(&root, &authority);
        let legitimate_read_set =
            authenticate_published_b4_negative_ancestry_read_set(&root, &authority).unwrap();

        let mut rewritten_catalog = authority.catalog().clone();
        let rewritten_payload =
            vec![0xa7; usize::try_from(rewritten_catalog.entries[2].raw_seal.byte_length).unwrap()];
        let rewritten_path = rewritten_catalog.entries[2].raw_seal.path.clone();
        rewritten_catalog.entries[2].raw_seal = B4ContractArtifactIdentityV1::from_bytes(
            &rewritten_path,
            B4ContractArtifactEncodingV1::RawBytes,
            &rewritten_payload,
        )
        .unwrap();
        let rewritten_catalog_jcs = rewritten_catalog.to_canonical_jcs().unwrap();
        assert_eq!(
            Eip0045B4NegativeAncestryWitnessCatalogV1::from_canonical_jcs(&rewritten_catalog_jcs)
                .unwrap(),
            rewritten_catalog
        );
        fs::write(root.join(&rewritten_path), &rewritten_payload).unwrap();
        fs::write(
            root.join(B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_PATH),
            &rewritten_catalog_jcs,
        )
        .unwrap();

        assert!(authenticate_published_b4_negative_ancestry_read_set(&root, &authority).is_err());

        let B4NegativeAncestryPublicationReadSetV1 {
            catalog: _,
            mut files,
        } = legitimate_read_set;
        files[0].bytes = rewritten_catalog_jcs;
        files
            .iter_mut()
            .find(|file| file.path == rewritten_path)
            .unwrap()
            .bytes = rewritten_payload;
        let Err(authorization_error) =
            B4NegativeAncestryPublicationReadSetV1::from_authenticated_files(files, &authority)
        else {
            panic!("coordinated rewrite bypassed reopened catalogue authority");
        };
        assert_eq!(
            authorization_error.to_string(),
            "reopened negative-ancestry catalogue is unauthorized"
        );
    }

    #[test]
    fn validator_accepts_one_exact_root_and_rejects_each_missing_file() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("published");
        let authority = synthetic_authority();
        write_exact_tree(&root, &authority);
        validate_published_b4_negative_ancestry_witness_catalog(&root, &authority).unwrap();

        for relative in compiled_negative_ancestry_publication_paths().unwrap() {
            let path = root.join(&relative);
            fs::remove_file(&path).unwrap();
            assert!(
                validate_published_b4_negative_ancestry_witness_catalog(&root, &authority).is_err(),
                "missing {relative} was accepted"
            );
            fs::write(path, expected_bytes(&authority, &relative)).unwrap();
        }
        validate_published_b4_negative_ancestry_witness_catalog(&root, &authority).unwrap();
    }

    #[test]
    fn validator_rejects_extra_files_directories_and_changed_bytes() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("published");
        let authority = synthetic_authority();
        write_exact_tree(&root, &authority);

        let extra_file = root.join("extra");
        fs::write(&extra_file, b"extra").unwrap();
        assert!(
            validate_published_b4_negative_ancestry_witness_catalog(&root, &authority).is_err()
        );
        fs::remove_file(extra_file).unwrap();
        let extra_directory = root.join("reproduction/extra");
        fs::create_dir(&extra_directory).unwrap();
        assert!(
            validate_published_b4_negative_ancestry_witness_catalog(&root, &authority).is_err()
        );
        fs::remove_dir(extra_directory).unwrap();

        for relative in compiled_negative_ancestry_publication_paths().unwrap() {
            let path = root.join(&relative);
            let expected = expected_bytes(&authority, &relative);
            let mut changed = expected.to_vec();
            changed[0] ^= 0x01;
            fs::write(&path, changed).unwrap();
            assert!(
                validate_published_b4_negative_ancestry_witness_catalog(&root, &authority).is_err(),
                "byte change in {relative} was accepted"
            );
            fs::write(&path, expected).unwrap();
            fs::write(&path, [expected, b"x"].concat()).unwrap();
            assert!(
                validate_published_b4_negative_ancestry_witness_catalog(&root, &authority).is_err(),
                "length change in {relative} was accepted"
            );
            fs::write(path, expected).unwrap();
        }
        validate_published_b4_negative_ancestry_witness_catalog(&root, &authority).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn validator_rejects_symbolic_hard_and_special_file_substitutions() {
        use std::{os::unix::fs::symlink, os::unix::net::UnixListener};

        let temp = tempdir().unwrap();
        let authority = synthetic_authority();
        let paths = compiled_negative_ancestry_publication_paths().unwrap();
        let victim = &paths[2];

        let symbolic_root = temp.path().join("symbolic");
        write_exact_tree(&symbolic_root, &authority);
        let symbolic_target = temp.path().join("symbolic-target");
        fs::write(&symbolic_target, expected_bytes(&authority, victim)).unwrap();
        fs::remove_file(symbolic_root.join(victim)).unwrap();
        symlink(&symbolic_target, symbolic_root.join(victim)).unwrap();
        assert!(
            validate_published_b4_negative_ancestry_witness_catalog(&symbolic_root, &authority)
                .is_err()
        );

        let hard_root = temp.path().join("hard");
        write_exact_tree(&hard_root, &authority);
        fs::hard_link(
            hard_root.join(victim),
            temp.path().join("hard-external-link"),
        )
        .unwrap();
        assert!(
            validate_published_b4_negative_ancestry_witness_catalog(&hard_root, &authority)
                .is_err()
        );

        let special_root = temp.path().join("special");
        write_exact_tree(&special_root, &authority);
        fs::remove_file(special_root.join(victim)).unwrap();
        let _socket = UnixListener::bind(special_root.join(victim)).unwrap();
        assert!(
            validate_published_b4_negative_ancestry_witness_catalog(&special_root, &authority)
                .is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn validator_rejects_same_byte_windows_hardlink_substitution() {
        let temp = tempdir().unwrap();
        let authority = synthetic_authority();
        let victim = &compiled_negative_ancestry_publication_paths().unwrap()[2];

        let hard_root = temp.path().join("hard");
        write_exact_tree(&hard_root, &authority);
        fs::hard_link(
            hard_root.join(victim),
            temp.path().join("hard-external-link"),
        )
        .unwrap();
        assert!(
            validate_published_b4_negative_ancestry_witness_catalog(&hard_root, &authority)
                .is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn validator_rejects_same_tree_windows_junction_substitution() {
        use std::process::Command;

        let temp = tempdir().unwrap();
        let authority = synthetic_authority();
        let symbolic_root = temp.path().join("symbolic");
        write_exact_tree(&symbolic_root, &authority);
        let witness_root = symbolic_root
            .join("reproduction")
            .join("negative-ancestry-witnesses");
        let external_witness_root = temp.path().join("external-witnesses");
        fs::rename(&witness_root, &external_witness_root).unwrap();
        let output = Command::new("cmd")
            .args(["/d", "/c", "mklink", "/j"])
            .arg(&witness_root)
            .arg(&external_witness_root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "Windows junction capability is required for reparse-point falsification: status={:?}, stdout={}, stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            validate_published_b4_negative_ancestry_witness_catalog(&symbolic_root, &authority)
                .is_err(),
            "same-tree Windows junction substitution was accepted"
        );
        fs::remove_dir(&witness_root).unwrap_or_else(|error| {
            panic!("cannot remove Windows junction after reparse-point falsification: {error}")
        });
    }

    #[cfg(unix)]
    #[test]
    fn publisher_atomic_support_preflight_fails_before_any_mutation() {
        let temp = publication_tempdir();
        let authority = synthetic_authority();
        let published = temp.path().join("unsupported");
        let staging = negative_ancestry_staging_path(&published).unwrap();
        let mut instrumentation = RecordingPublicationInstrumentation {
            atomic_support: false,
            operations: Vec::new(),
            fail_before_transition: None,
            attempted_transitions: 0,
            completed_transitions: 0,
        };

        assert!(
            publish_b4_negative_ancestry_witness_catalog_impl(
                &published,
                &authority,
                &mut instrumentation,
                |_staging, _destination| Ok(()),
                |_staging, _destination| Ok(()),
            )
            .is_err()
        );
        assert_eq!(
            instrumentation.operations,
            [RecordedPublicationOperation::AtomicSupportPreflight]
        );
        assert_eq!(instrumentation.attempted_transitions, 1);
        assert_eq!(instrumentation.completed_transitions, 1);
        assert_eq!(
            fs::symlink_metadata(&published).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        assert_eq!(
            fs::symlink_metadata(&staging).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[cfg(unix)]
    #[test]
    fn publisher_validator_rejects_cross_identity_payload_copy() {
        let temp = publication_tempdir();
        let authority = synthetic_authority();
        let published = temp.path().join("cross-identity");
        write_exact_tree(&published, &authority);
        let paths = compiled_negative_ancestry_publication_paths().unwrap();
        let victim = &paths[2];
        let foreign = &paths[6];
        let victim_bytes = expected_bytes(&authority, victim);
        let foreign_bytes = expected_bytes(&authority, foreign);
        assert_eq!(victim_bytes.len(), foreign_bytes.len());
        assert_ne!(victim_bytes, foreign_bytes);

        fs::write(published.join(victim), foreign_bytes).unwrap();
        assert!(
            validate_published_b4_negative_ancestry_witness_catalog(&published, &authority)
                .is_err(),
            "cross-identity payload copy was accepted"
        );
    }

    #[cfg(unix)]
    #[test]
    fn publisher_records_exact_successful_durable_transition_order() {
        let temp = publication_tempdir();
        let authority = synthetic_authority();
        let published = temp.path().join("ordered");
        let mut instrumentation = RecordingPublicationInstrumentation {
            atomic_support: true,
            operations: Vec::new(),
            fail_before_transition: None,
            attempted_transitions: 0,
            completed_transitions: 0,
        };

        publish_b4_negative_ancestry_witness_catalog_impl(
            &published,
            &authority,
            &mut instrumentation,
            |_staging, _destination| Ok(()),
            |_staging, _destination| Ok(()),
        )
        .unwrap();

        let mut expected = vec![RecordedPublicationOperation::AtomicSupportPreflight];
        expected.extend(
            compiled_negative_ancestry_publication_paths()
                .unwrap()
                .map(RecordedPublicationOperation::FileSynced),
        );
        expected.extend([
            RecordedPublicationOperation::StagedValidated,
            RecordedPublicationOperation::WitnessDirectorySynced,
            RecordedPublicationOperation::ReproductionDirectorySynced,
            RecordedPublicationOperation::StagingDirectorySynced,
            RecordedPublicationOperation::ExclusiveRenamed,
            RecordedPublicationOperation::ParentDirectorySynced,
            RecordedPublicationOperation::FinalValidated,
        ]);
        assert_eq!(instrumentation.operations, expected);
    }

    #[cfg(unix)]
    #[test]
    fn observed_transition_helper_runs_each_operation_once_before_success_observation() {
        use std::{cell::Cell, rc::Rc};

        struct HelperInstrumentation(Rc<Cell<u8>>);

        impl PublicationInstrumentation for HelperInstrumentation {
            fn before_observed_transition(
                &mut self,
                _operation: PublicationOperation<'_>,
            ) -> Result<()> {
                assert_eq!(self.0.get(), 0, "before hook was reordered");
                self.0.set(1);
                Ok(())
            }

            fn atomic_support(&mut self, _parent: &Path) -> Result<bool> {
                unreachable!("the direct helper test supplies its own transition closure")
            }

            fn observe(&mut self, _operation: PublicationOperation<'_>) {
                assert_eq!(self.0.get(), 2, "success observation skipped transition");
                self.0.set(3);
            }
        }

        let operations = [
            PublicationOperation::AtomicSupportPreflight,
            PublicationOperation::FileSynced("sentinel"),
            PublicationOperation::StagedValidated,
            PublicationOperation::WitnessDirectorySynced,
            PublicationOperation::ReproductionDirectorySynced,
            PublicationOperation::StagingDirectorySynced,
            PublicationOperation::ExclusiveRenamed,
            PublicationOperation::ParentDirectorySynced,
            PublicationOperation::FinalValidated,
        ];

        for (index, operation) in operations.into_iter().enumerate() {
            let success_state = Rc::new(Cell::new(0));
            let mut success_instrumentation = HelperInstrumentation(Rc::clone(&success_state));
            perform_observed_publication_transition(
                &mut success_instrumentation,
                operation,
                || {
                    assert_eq!(success_state.get(), 1, "transition ran before its hook");
                    success_state.set(2);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(
                success_state.get(),
                3,
                "operation variant {index} skipped or reordered its successful transition"
            );

            let error_state = Rc::new(Cell::new(0));
            let mut error_instrumentation = HelperInstrumentation(Rc::clone(&error_state));
            let error = perform_observed_publication_transition(
                &mut error_instrumentation,
                operation,
                || {
                    assert_eq!(error_state.get(), 1, "transition ran before its hook");
                    error_state.set(2);
                    bail!("sentinel transition failure {index}")
                },
            )
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("sentinel transition failure {index}")
            );
            assert_eq!(
                error_state.get(),
                2,
                "operation variant {index} observed success after its transition failed"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn publisher_stops_at_every_injected_durable_transition_failure() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let authority = synthetic_authority();
        let mut durable_transitions = vec![RecordedPublicationOperation::AtomicSupportPreflight];
        durable_transitions.extend(
            compiled_negative_ancestry_publication_paths()
                .unwrap()
                .into_iter()
                .map(RecordedPublicationOperation::FileSynced),
        );
        durable_transitions.extend([
            RecordedPublicationOperation::StagedValidated,
            RecordedPublicationOperation::WitnessDirectorySynced,
            RecordedPublicationOperation::ReproductionDirectorySynced,
            RecordedPublicationOperation::StagingDirectorySynced,
            RecordedPublicationOperation::ExclusiveRenamed,
            RecordedPublicationOperation::ParentDirectorySynced,
            RecordedPublicationOperation::FinalValidated,
        ]);
        let rename_index = durable_transitions
            .iter()
            .position(|operation| {
                matches!(operation, RecordedPublicationOperation::ExclusiveRenamed)
            })
            .unwrap();

        for fail_before_transition in 0..durable_transitions.len() {
            let temp = publication_tempdir();
            let published = temp.path().join("cutoff");
            let staging = negative_ancestry_staging_path(&published).unwrap();
            let mut instrumentation = RecordingPublicationInstrumentation {
                atomic_support: true,
                operations: Vec::new(),
                fail_before_transition: Some(fail_before_transition),
                attempted_transitions: 0,
                completed_transitions: 0,
            };

            let execution = catch_unwind(AssertUnwindSafe(|| {
                publish_b4_negative_ancestry_witness_catalog_impl(
                    &published,
                    &authority,
                    &mut instrumentation,
                    |_staging, _destination| Ok(()),
                    |_staging, _destination| Ok(()),
                )
            }));
            assert!(
                execution.is_ok(),
                "transition {fail_before_transition} reached observation instead of failing before its real operation"
            );
            assert!(
                execution.unwrap().is_err(),
                "transition {fail_before_transition} did not inject a failure"
            );

            let expected = durable_transitions
                .iter()
                .take(fail_before_transition)
                .cloned()
                .collect::<Vec<_>>();
            assert_eq!(
                instrumentation.operations, expected,
                "transition {fail_before_transition} allowed a later observation"
            );
            assert_eq!(
                instrumentation.attempted_transitions,
                fail_before_transition + 1
            );
            assert_eq!(
                instrumentation.completed_transitions,
                fail_before_transition
            );
            if fail_before_transition == 0 {
                assert!(!published.exists());
                assert!(!staging.exists());
            } else if fail_before_transition <= rename_index {
                assert!(!published.exists());
                assert!(staging.is_dir());
            } else {
                assert!(published.is_dir());
                assert!(!staging.exists());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn publisher_is_create_only_and_refuses_occupied_or_retried_roots() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = publication_tempdir();
        let authority = synthetic_authority();

        let published = temp.path().join("published");
        publish_b4_negative_ancestry_witness_catalog(&published, &authority).unwrap();
        validate_published_b4_negative_ancestry_witness_catalog(&published, &authority).unwrap();
        for directory in [
            published.clone(),
            published.join("reproduction"),
            published.join("reproduction/negative-ancestry-witnesses"),
        ] {
            assert_eq!(
                fs::metadata(directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        for relative in compiled_negative_ancestry_publication_paths().unwrap() {
            assert_eq!(
                fs::metadata(published.join(relative))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert!(!negative_ancestry_staging_path(&published).unwrap().exists());
        assert!(publish_b4_negative_ancestry_witness_catalog(&published, &authority).is_err());
        validate_published_b4_negative_ancestry_witness_catalog(&published, &authority).unwrap();

        let abandoned = temp.path().join("abandoned");
        let abandoned_staging = negative_ancestry_staging_path(&abandoned).unwrap();
        fs::create_dir(&abandoned_staging).unwrap();
        assert!(publish_b4_negative_ancestry_witness_catalog(&abandoned, &authority).is_err());
        assert!(!abandoned.exists());
        assert!(abandoned_staging.is_dir());

        let occupied = temp.path().join("occupied");
        fs::create_dir(&occupied).unwrap();
        assert!(publish_b4_negative_ancestry_witness_catalog(&occupied, &authority).is_err());
        assert!(occupied.is_dir());
        assert!(!negative_ancestry_staging_path(&occupied).unwrap().exists());
    }

    #[cfg(unix)]
    #[test]
    fn publisher_preserves_staging_and_winning_destination_across_pre_rename_failures() {
        use std::os::unix::fs::MetadataExt as _;

        let temp = publication_tempdir();
        let authority = synthetic_authority();

        let injected = temp.path().join("injected");
        let injected_staging = negative_ancestry_staging_path(&injected).unwrap();
        assert!(
            publish_b4_negative_ancestry_witness_catalog_with_test_hooks(
                &injected,
                &authority,
                |_staging, _destination| bail!("injected pre-rename failure"),
                |_staging, _destination| Ok(()),
            )
            .is_err()
        );
        assert!(!injected.exists());
        assert!(injected_staging.is_dir());
        assert!(publish_b4_negative_ancestry_witness_catalog(&injected, &authority).is_err());

        let raced = temp.path().join("raced");
        let raced_staging = negative_ancestry_staging_path(&raced).unwrap();
        let mut raced_identity = None;
        assert!(
            publish_b4_negative_ancestry_witness_catalog_with_test_hooks(
                &raced,
                &authority,
                |_staging, destination| {
                    fs::create_dir(destination)?;
                    let metadata = fs::symlink_metadata(destination)?;
                    raced_identity = Some((metadata.dev(), metadata.ino()));
                    Ok(())
                },
                |_staging, _destination| Ok(()),
            )
            .is_err()
        );
        let retained = fs::symlink_metadata(&raced).unwrap();
        assert_eq!(
            (retained.dev(), retained.ino()),
            raced_identity.expect("raced destination identity must be recorded")
        );
        assert_eq!(fs::read_dir(&raced).unwrap().count(), 0);
        assert!(raced_staging.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn publisher_retains_a_post_rename_validation_failure() {
        let temp = publication_tempdir();
        let authority = synthetic_authority();
        let published = temp.path().join("published");
        let changed = compiled_negative_ancestry_publication_paths().unwrap()[0].clone();

        assert!(
            publish_b4_negative_ancestry_witness_catalog_with_test_hooks(
                &published,
                &authority,
                |_staging, _destination| Ok(()),
                |_staging, destination| {
                    fs::write(destination.join(&changed), b"post-rename corruption")?;
                    Ok(())
                },
            )
            .is_err()
        );
        assert!(published.is_dir());
        assert!(!negative_ancestry_staging_path(&published).unwrap().exists());
        assert!(
            validate_published_b4_negative_ancestry_witness_catalog(&published, &authority)
                .is_err()
        );
        assert!(publish_b4_negative_ancestry_witness_catalog(&published, &authority).is_err());
    }

    #[cfg(unix)]
    fn ordered_identity(root: &Path) -> (Vec<(String, u64, [u8; 32])>, BTreeSet<(u64, u64)>) {
        use std::os::unix::fs::MetadataExt as _;

        let mut inventory = Vec::new();
        let mut file_identities = BTreeSet::new();
        for relative in compiled_negative_ancestry_publication_paths().unwrap() {
            let bytes = fs::read(root.join(&relative)).unwrap();
            let metadata = fs::metadata(root.join(&relative)).unwrap();
            assert_eq!(metadata.nlink(), 1);
            file_identities.insert((metadata.dev(), metadata.ino()));
            inventory.push((
                relative,
                u64::try_from(bytes.len()).unwrap(),
                Sha256::digest(bytes).into(),
            ));
        }
        (inventory, file_identities)
    }

    #[cfg(unix)]
    #[test]
    fn two_publications_are_byte_identical_with_independent_file_identities() {
        let temp = publication_tempdir();
        let authority = synthetic_authority();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        publish_b4_negative_ancestry_witness_catalog(&first, &authority).unwrap();
        publish_b4_negative_ancestry_witness_catalog(&second, &authority).unwrap();

        let (first_inventory, first_ids) = ordered_identity(&first);
        let (second_inventory, second_ids) = ordered_identity(&second);
        assert_eq!(first_inventory, second_inventory);
        assert_eq!(
            first_inventory.len(),
            B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT
        );
        assert_eq!(first_ids.len(), B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT);
        assert_eq!(
            second_ids.len(),
            B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT
        );
        assert!(first_ids.is_disjoint(&second_ids));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_materializer_requires_an_empty_root_before_first_effect() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("occupied");
        let descriptor = create_private_descriptor_root(&root);
        fs::write(root.join("sentinel"), b"retained").unwrap();
        let authority = synthetic_authority();

        let error =
            materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor(
                descriptor.as_fd(),
                &authority,
            )
            .unwrap_err();

        assert!(format!("{error:#}").contains("empty"));
        assert_eq!(fs::read(root.join("sentinel")).unwrap(), b"retained");
        assert!(!root.join("reproduction").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_materializer_rejects_non_private_root_before_first_effect() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("non-private");
        let descriptor = create_private_descriptor_root(&root);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
        let authority = synthetic_authority();

        let error =
            materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor(
                descriptor.as_fd(),
                &authority,
            )
            .unwrap_err();

        assert!(format!("{error:#}").contains("owner-only directory permissions"));
        assert!(fs::read_dir(&root).unwrap().next().is_none());
        assert!(!root.join("reproduction").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_materializer_projects_and_reopens_exactly_twenty_four_files() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("published");
        let descriptor = create_private_descriptor_root(&root);
        let authority = synthetic_authority();

        materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor(
            descriptor.as_fd(),
            &authority,
        )
        .unwrap();
        validate_published_b4_negative_ancestry_witness_catalog_from_directory_descriptor(
            descriptor.as_fd(),
            &authority,
        )
        .unwrap();

        let paths = compiled_negative_ancestry_publication_paths().unwrap();
        assert_eq!(paths.len(), B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT);
        for relative in paths {
            let metadata = fs::metadata(root.join(relative)).unwrap();
            assert!(metadata.is_file());
            assert_eq!(metadata.mode() & 0o7777, 0o600);
            assert_eq!(metadata.nlink(), 1);
        }
        for (relative, expected_links) in [
            ("", 3_u64),
            ("reproduction", 3),
            ("reproduction/negative-ancestry-witnesses", 2),
        ] {
            let metadata = fs::metadata(root.join(relative)).unwrap();
            assert!(metadata.is_dir());
            assert_eq!(metadata.mode() & 0o7777, 0o700);
            assert_eq!(metadata.nlink(), expected_links);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_reopen_rejects_root_mode_drift() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("root-mode");
        let descriptor = create_private_descriptor_root(&root);
        let authority = synthetic_authority();
        materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor(
            descriptor.as_fd(),
            &authority,
        )
        .unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();

        let error =
            validate_published_b4_negative_ancestry_witness_catalog_from_directory_descriptor(
                descriptor.as_fd(),
                &authority,
            )
            .unwrap_err();
        assert!(format!("{error:#}").contains("owner-only directory permissions"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_reopen_rejects_witness_directory_mode_drift() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("witness-mode");
        let descriptor = create_private_descriptor_root(&root);
        let authority = synthetic_authority();
        materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor(
            descriptor.as_fd(),
            &authority,
        )
        .unwrap();
        fs::set_permissions(
            root.join("reproduction")
                .join("negative-ancestry-witnesses"),
            fs::Permissions::from_mode(0o750),
        )
        .unwrap();

        let error =
            validate_published_b4_negative_ancestry_witness_catalog_from_directory_descriptor(
                descriptor.as_fd(),
                &authority,
            )
            .unwrap_err();
        assert!(format!("{error:#}").contains("owner-only directory permissions"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_reopen_rejects_file_mode_drift() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("file-mode");
        let descriptor = create_private_descriptor_root(&root);
        let authority = synthetic_authority();
        materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor(
            descriptor.as_fd(),
            &authority,
        )
        .unwrap();
        let victim = compiled_negative_ancestry_publication_paths().unwrap()[2].clone();
        fs::set_permissions(root.join(victim), fs::Permissions::from_mode(0o640)).unwrap();

        let error =
            validate_published_b4_negative_ancestry_witness_catalog_from_directory_descriptor(
                descriptor.as_fd(),
                &authority,
            )
            .unwrap_err();
        assert!(format!("{error:#}").contains("owner-only file permissions"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_reopen_rejects_witness_directory_link_count_drift() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("witness-links");
        let descriptor = create_private_descriptor_root(&root);
        let authority = synthetic_authority();
        materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor(
            descriptor.as_fd(),
            &authority,
        )
        .unwrap();
        let unexpected = root
            .join("reproduction")
            .join("negative-ancestry-witnesses")
            .join("unexpected-directory");
        fs::create_dir(&unexpected).unwrap();
        fs::set_permissions(unexpected, fs::Permissions::from_mode(0o700)).unwrap();

        let error =
            validate_published_b4_negative_ancestry_witness_catalog_from_directory_descriptor(
                descriptor.as_fd(),
                &authority,
            )
            .unwrap_err();
        assert!(format!("{error:#}").contains("unexpected directory link count"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_materializer_records_and_stops_at_each_durability_event() {
        let authority = synthetic_authority();
        let expected = expected_descriptor_durability_events();
        assert_eq!(
            expected.len(),
            B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT + 3
        );
        assert_eq!(expected.len(), 27);

        let success_temp = tempdir().unwrap();
        let success_root = success_temp.path().join("success");
        let success_descriptor = create_private_descriptor_root(&success_root);
        let mut complete_trace = Vec::new();
        descriptor_rooted_linux::materialize_with_test_durability_hook(
            success_descriptor.as_fd(),
            &authority,
            |event| {
                complete_trace.push(event);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(complete_trace, expected);

        for injected_index in 0..expected.len() {
            let temp = tempdir().unwrap();
            let root = temp.path().join(format!("fault-{injected_index}"));
            let descriptor = create_private_descriptor_root(&root);
            let mut trace = Vec::new();
            let error = descriptor_rooted_linux::materialize_with_test_durability_hook(
                descriptor.as_fd(),
                &authority,
                |event| {
                    trace.push(event);
                    if trace.len() == injected_index + 1 {
                        bail!("injected descriptor durability failure at {injected_index}");
                    }
                    Ok(())
                },
            )
            .unwrap_err();

            assert!(format!("{error:#}").contains(&format!(
                "injected descriptor durability failure at {injected_index}"
            )));
            assert_eq!(trace.as_slice(), &expected[..=injected_index]);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_materializer_writes_only_to_retained_root_after_pathname_swap() {
        let temp = tempdir().unwrap();
        let named = temp.path().join("named");
        let retained = temp.path().join("retained");
        let descriptor = create_private_descriptor_root(&named);
        fs::rename(&named, &retained).unwrap();
        let decoy = create_private_descriptor_root(&named);
        let authority = synthetic_authority();

        materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor(
            descriptor.as_fd(),
            &authority,
        )
        .unwrap();
        validate_published_b4_negative_ancestry_witness_catalog_from_directory_descriptor(
            descriptor.as_fd(),
            &authority,
        )
        .unwrap();

        assert!(retained.join("reproduction").is_dir());
        assert!(fs::read_dir(&named).unwrap().next().is_none());
        assert!(rustix::fs::fstat(decoy).unwrap().st_nlink >= 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_reopen_rejects_missing_extra_symlink_hardlink_and_special_entries() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let authority = synthetic_authority();
        let victim = compiled_negative_ancestry_publication_paths().unwrap()[2].clone();

        let missing = temp.path().join("missing");
        let missing_descriptor = create_private_descriptor_root(&missing);
        materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor(
            missing_descriptor.as_fd(),
            &authority,
        )
        .unwrap();
        fs::remove_file(missing.join(&victim)).unwrap();
        assert!(
            validate_published_b4_negative_ancestry_witness_catalog_from_directory_descriptor(
                missing_descriptor.as_fd(),
                &authority,
            )
            .is_err()
        );

        let extra = temp.path().join("extra");
        let extra_descriptor = create_private_descriptor_root(&extra);
        materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor(
            extra_descriptor.as_fd(),
            &authority,
        )
        .unwrap();
        fs::write(extra.join("unexpected"), b"unexpected").unwrap();
        assert!(
            validate_published_b4_negative_ancestry_witness_catalog_from_directory_descriptor(
                extra_descriptor.as_fd(),
                &authority,
            )
            .is_err()
        );

        let symbolic = temp.path().join("symbolic");
        let symbolic_descriptor = create_private_descriptor_root(&symbolic);
        materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor(
            symbolic_descriptor.as_fd(),
            &authority,
        )
        .unwrap();
        let symbolic_target = temp.path().join("symbolic-target");
        fs::write(&symbolic_target, expected_bytes(&authority, &victim)).unwrap();
        fs::remove_file(symbolic.join(&victim)).unwrap();
        symlink(&symbolic_target, symbolic.join(&victim)).unwrap();
        assert!(
            validate_published_b4_negative_ancestry_witness_catalog_from_directory_descriptor(
                symbolic_descriptor.as_fd(),
                &authority,
            )
            .is_err()
        );

        let hard = temp.path().join("hard");
        let hard_descriptor = create_private_descriptor_root(&hard);
        materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor(
            hard_descriptor.as_fd(),
            &authority,
        )
        .unwrap();
        fs::hard_link(hard.join(&victim), temp.path().join("hard-external-link")).unwrap();
        assert!(
            validate_published_b4_negative_ancestry_witness_catalog_from_directory_descriptor(
                hard_descriptor.as_fd(),
                &authority,
            )
            .is_err()
        );

        let special = temp.path().join("special");
        let special_descriptor = create_private_descriptor_root(&special);
        materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor(
            special_descriptor.as_fd(),
            &authority,
        )
        .unwrap();
        fs::remove_file(special.join(&victim)).unwrap();
        let _socket = UnixListener::bind(special.join(&victim)).unwrap();
        assert!(
            validate_published_b4_negative_ancestry_witness_catalog_from_directory_descriptor(
                special_descriptor.as_fd(),
                &authority,
            )
            .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_reopen_rejects_coordinated_catalog_and_payload_drift() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("coordinated");
        let descriptor = create_private_descriptor_root(&root);
        let authority = synthetic_authority();
        materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor(
            descriptor.as_fd(),
            &authority,
        )
        .unwrap();

        let mut rewritten_catalog = authority.catalog().clone();
        let rewritten_payload =
            vec![0xa7; usize::try_from(rewritten_catalog.entries[2].raw_seal.byte_length).unwrap()];
        let rewritten_path = rewritten_catalog.entries[2].raw_seal.path.clone();
        rewritten_catalog.entries[2].raw_seal = B4ContractArtifactIdentityV1::from_bytes(
            &rewritten_path,
            B4ContractArtifactEncodingV1::RawBytes,
            &rewritten_payload,
        )
        .unwrap();
        fs::write(root.join(&rewritten_path), rewritten_payload).unwrap();
        fs::write(
            root.join(B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_PATH),
            rewritten_catalog.to_canonical_jcs().unwrap(),
        )
        .unwrap();

        assert!(
            validate_published_b4_negative_ancestry_witness_catalog_from_directory_descriptor(
                descriptor.as_fd(),
                &authority,
            )
            .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_reopen_rejects_file_and_directory_changes_after_initial_reads() {
        let temp = tempdir().unwrap();
        let authority = synthetic_authority();
        let victim = compiled_negative_ancestry_publication_paths().unwrap()[2].clone();
        let expected = expected_bytes(&authority, &victim).to_vec();

        let replaced = temp.path().join("replaced");
        let replaced_descriptor = create_private_descriptor_root(&replaced);
        materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor(
            replaced_descriptor.as_fd(),
            &authority,
        )
        .unwrap();
        let displaced = temp.path().join("displaced");
        let replacement_error = descriptor_rooted_linux::authenticate_with_test_hook(
            replaced_descriptor.as_fd(),
            &authority,
            || {
                fs::rename(replaced.join(&victim), &displaced).unwrap();
                fs::write(replaced.join(&victim), &expected).unwrap();
                fs::set_permissions(replaced.join(&victim), fs::Permissions::from_mode(0o600))
                    .unwrap();
            },
        )
        .err()
        .expect("same-name replacement after initial reads must be rejected");
        assert!(format!("{replacement_error:#}").contains("changed"));

        let mutated = temp.path().join("mutated");
        let mutated_descriptor = create_private_descriptor_root(&mutated);
        materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor(
            mutated_descriptor.as_fd(),
            &authority,
        )
        .unwrap();
        let mutation_error = descriptor_rooted_linux::authenticate_with_test_hook(
            mutated_descriptor.as_fd(),
            &authority,
            || {
                let mut changed = expected.clone();
                changed[0] ^= 1;
                fs::write(mutated.join(&victim), changed).unwrap();
            },
        )
        .err()
        .expect("in-place mutation after initial reads must be rejected");
        assert!(format!("{mutation_error:#}").contains("changed"));

        let swapped_directory = temp.path().join("swapped-directory");
        let swapped_directory_descriptor = create_private_descriptor_root(&swapped_directory);
        materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor(
            swapped_directory_descriptor.as_fd(),
            &authority,
        )
        .unwrap();
        let witness_directory = swapped_directory
            .join("reproduction")
            .join("negative-ancestry-witnesses");
        let displaced_witness_directory = temp.path().join("displaced-witness-directory");
        let directory_error = descriptor_rooted_linux::authenticate_with_test_hook(
            swapped_directory_descriptor.as_fd(),
            &authority,
            || {
                fs::rename(&witness_directory, &displaced_witness_directory).unwrap();
                fs::create_dir(&witness_directory).unwrap();
                fs::set_permissions(&witness_directory, fs::Permissions::from_mode(0o700)).unwrap();
            },
        )
        .err()
        .expect("same-name directory replacement after initial reads must be rejected");
        assert!(format!("{directory_error:#}").contains("changed"));
    }

    #[test]
    fn v2_path_publication_boundaries_accept_only_v2_authority() {
        let _: fn(&Path, &B4NegativeAncestryWitnessCatalogAuthorityV2) -> Result<()> =
            validate_published_b4_negative_ancestry_witness_catalog_v2;
        let _: fn(&Path, &B4NegativeAncestryWitnessCatalogAuthorityV2) -> Result<()> =
            publish_b4_negative_ancestry_witness_catalog_v2;
    }

    #[test]
    fn v2_source_finalize_lineage_and_publication_reject_catalog_and_readset_swaps() {
        let support = crate::b4_negative_ancestry_authority::test_support::
            fixed_negative_ancestry_lineage_test_support_v2()
            .unwrap();
        support
            .ancestry
            .verify_prior_authority_lineage(
                &support.prior.campaign_precommit_authority,
                &support.prior.positive_generation_authority,
            )
            .unwrap();

        let temp = tempdir().unwrap();
        let exact = temp.path().join("v2-exact");
        test_support::write_exact_test_publication_v2(&exact, &support.ancestry).unwrap();
        let read_set =
            authenticate_published_b4_negative_ancestry_read_set_v2(&exact, &support.ancestry)
                .unwrap();
        assert_eq!(
            read_set.catalog_jcs(),
            support.ancestry.canonical_catalog_jcs()
        );
        assert_eq!(
            read_set.ordered_files().len(),
            B4_NEGATIVE_ANCESTRY_PUBLICATION_FILE_COUNT
        );

        let catalog_mutant = temp.path().join("v2-catalog-mutant");
        test_support::write_exact_test_publication_v2(&catalog_mutant, &support.ancestry).unwrap();
        let catalog_path = catalog_mutant.join(B4_NEGATIVE_ANCESTRY_WITNESS_CATALOG_PATH);
        let mut catalog_bytes = fs::read(&catalog_path).unwrap();
        catalog_bytes[0] ^= 1;
        fs::write(&catalog_path, catalog_bytes).unwrap();
        assert!(
            validate_published_b4_negative_ancestry_witness_catalog_v2(
                &catalog_mutant,
                &support.ancestry,
            )
            .is_err()
        );

        let readset_swap = temp.path().join("v2-readset-swap");
        test_support::write_exact_test_publication_v2(&readset_swap, &support.ancestry).unwrap();
        let layout = compiled_negative_ancestry_witness_layout().unwrap();
        let left = readset_swap.join(&layout[3].raw_seal_path);
        let right = readset_swap.join(&layout[4].raw_seal_path);
        let left_bytes = fs::read(&left).unwrap();
        let right_bytes = fs::read(&right).unwrap();
        assert_eq!(left_bytes.len(), right_bytes.len());
        fs::write(&left, &right_bytes).unwrap();
        fs::write(&right, &left_bytes).unwrap();
        assert!(
            authenticate_published_b4_negative_ancestry_read_set_v2(
                &readset_swap,
                &support.ancestry,
            )
            .is_err()
        );
    }

    #[test]
    fn v2_publication_surface_has_no_v1_authority_parameter() {
        let source = include_str!("b4_negative_ancestry_publication.rs");
        for function in [
            "pub fn validate_published_b4_negative_ancestry_witness_catalog_v2",
            "pub fn publish_b4_negative_ancestry_witness_catalog_v2",
            "pub fn materialize_b4_negative_ancestry_witness_catalog_into_empty_directory_descriptor_v2",
        ] {
            let signature = source
                .split(function)
                .nth(1)
                .unwrap()
                .split("{")
                .next()
                .unwrap();
            assert!(signature.contains("B4NegativeAncestryWitnessCatalogAuthorityV2"));
            assert!(!signature.contains("B4NegativeAncestryWitnessCatalogAuthorityV1"));
        }
    }
}
