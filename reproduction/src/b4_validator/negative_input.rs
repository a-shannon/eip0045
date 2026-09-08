// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Linux-only, descriptor-pinned custody for one B4 negative verification.
//!
//! The neutral input selects only a reviewed domain/surface pair. Production
//! contract lookup is internal and non-injectable. Every payload path is fixed
//! by this module, resolved below retained directory descriptors with
//! `openat2(2)`, inspected through an `O_PATH` descriptor, and reauthenticated
//! after a final read from the retained data descriptor.

#![cfg_attr(
    not(all(target_os = "linux", target_arch = "x86_64")),
    allow(
        dead_code,
        reason = "physical negative-root custody is deliberately Linux/x86_64-only"
    )
)]

use std::path::Path;

use anyhow::{Result, ensure};

use crate::{
    b4_negative_handler_contract::B4NegativeCustodyContract,
    b4_negative_io::Eip0045B4NegativeVerifierInputV1,
};

/// Canonical neutral negative-input filename.
pub const NEGATIVE_INPUT_FILE: &str = "negative-input.json";
/// Fixed negative-subject filename.
pub(super) const NEGATIVE_SUBJECT_FILE: &str = "subject.bin";
/// Fixed directory containing the positional context prefix.
pub(super) const NEGATIVE_CONTEXT_DIRECTORY: &str = "context";

impl B4NegativeCustodyContract {
    fn validate_input(
        self,
        input_length: u64,
        input: &Eip0045B4NegativeVerifierInputV1,
    ) -> Result<()> {
        self.validate()?;
        ensure!(
            input.materialization_domain == self.materialization_domain()
                && input.validation_surface == self.validation_surface(),
            "negative input domain/surface pair differs from the frozen handler contract"
        );
        ensure!(
            input.context.len() == self.contexts().len(),
            "negative input context cardinality differs from the frozen handler contract"
        );
        ensure!(
            input.subject.path == NEGATIVE_SUBJECT_FILE,
            "negative subject descriptor path is not the fixed custody path"
        );
        ensure!(
            self.subject().contains(input.subject.byte_length),
            "negative subject declared length is outside the handler custody bound"
        );
        for (index, (identity, bounds)) in input
            .context
            .iter()
            .zip(self.contexts().iter().copied())
            .enumerate()
        {
            ensure!(
                identity.path == context_relative_path(index),
                "negative context {index:02} descriptor path is not its fixed custody path"
            );
            ensure!(
                bounds.contains(identity.byte_length),
                "negative context {index:02} declared length is outside its handler custody bound"
            );
        }
        checked_cumulative_allocation(
            input_length,
            input.subject.byte_length,
            input.context.iter().map(|identity| identity.byte_length),
            self.total_allocation_cap(),
        )?;
        Ok(())
    }
}

/// Bytes measured from one fixed path and authenticated against its descriptor.
#[derive(Clone, Debug)]
pub(super) struct B4MeasuredNegativeFile {
    bytes: Vec<u8>,
    sha256: [u8; 32],
}

impl B4MeasuredNegativeFile {
    /// Exact bytes read from the retained, reauthenticated descriptor.
    #[must_use]
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// SHA-256 of the exact returned bytes.
    #[must_use]
    pub(super) const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

/// Complete neutral negative root after physical authentication.
#[derive(Clone, Debug)]
pub(super) struct B4NegativeVerifierRoot {
    negative_input_file: B4MeasuredNegativeFile,
    input: Eip0045B4NegativeVerifierInputV1,
    subject: B4MeasuredNegativeFile,
    contexts: Vec<B4MeasuredNegativeFile>,
}

impl B4NegativeVerifierRoot {
    /// Authenticated canonical `negative-input.json` bytes and digest.
    #[must_use]
    pub(super) const fn negative_input_file(&self) -> &B4MeasuredNegativeFile {
        &self.negative_input_file
    }

    /// Parsed authority-minimal neutral input.
    #[must_use]
    pub(super) const fn input(&self) -> &Eip0045B4NegativeVerifierInputV1 {
        &self.input
    }

    /// Authenticated independently materialized subject.
    #[must_use]
    pub(super) const fn subject(&self) -> &B4MeasuredNegativeFile {
        &self.subject
    }

    /// Authenticated contexts in exact positional order.
    #[must_use]
    pub(super) fn contexts(&self) -> &[B4MeasuredNegativeFile] {
        &self.contexts
    }
}

/// Authenticate a negative verifier root against the sole frozen handler table.
///
/// # Errors
///
/// Returns an error on unsupported platforms before inspecting `root`. On
/// `Linux/x86_64`, returns an error for an unavailable `openat2(2)` facility, an
/// unresolved handler, any inventory, link, mount, type, size, identity, path,
/// digest, allocation, read, or final reauthentication violation.
pub(super) fn load_negative_verifier_root(root: &Path) -> Result<B4NegativeVerifierRoot> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        return linux::load(root);
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        let _ = root;
        anyhow::bail!("B4 negative custody requires Linux/x86_64 with openat2 support")
    }
}

fn checked_cumulative_allocation(
    input_length: u64,
    subject_length: u64,
    context_lengths: impl IntoIterator<Item = u64>,
    cap: u64,
) -> Result<u64> {
    let mut total = input_length
        .checked_add(subject_length)
        .ok_or_else(|| anyhow::anyhow!("negative root allocation length overflows u64"))?;
    for length in context_lengths {
        total = total
            .checked_add(length)
            .ok_or_else(|| anyhow::anyhow!("negative root allocation length overflows u64"))?;
    }
    ensure!(
        total <= cap,
        "negative root cumulative allocation exceeds the handler custody cap"
    );
    Ok(total)
}

fn context_relative_path(index: usize) -> String {
    format!("{NEGATIVE_CONTEXT_DIRECTORY}/{index:02}.bin")
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use std::{
        fs::File,
        io::{Read as _, Seek as _, SeekFrom},
        os::fd::OwnedFd,
        path::{Component, Path, PathBuf},
    };

    use anyhow::{Context as _, Result, bail, ensure};
    use rustix::fs::{Dir, FileType, Mode, OFlags, ResolveFlags, Stat, fstat, open, openat2};
    use sha2::{Digest as _, Sha256};

    use super::{
        B4MeasuredNegativeFile, B4NegativeCustodyContract, B4NegativeVerifierRoot,
        NEGATIVE_CONTEXT_DIRECTORY, NEGATIVE_INPUT_FILE, NEGATIVE_SUBJECT_FILE,
        context_relative_path,
    };
    use crate::{
        b4_negative_handler_contract::{
            MAX_NEGATIVE_CONTEXT_FILES, NEGATIVE_INPUT_MAX_BYTES, frozen_negative_custody_contract,
        },
        b4_negative_io::Eip0045B4NegativeVerifierInputV1,
        b4_plan::{B4MaterializationDomain, B4NegativeExecutionSurface},
    };

    // Locating the caller-supplied root may legitimately cross onto the
    // dedicated `/input` bind mount. Once that root descriptor is pinned,
    // every descendant resolution additionally forbids mount crossings.
    const ROOT_RESOLVE_POLICY: ResolveFlags = ResolveFlags::BENEATH
        .union(ResolveFlags::NO_SYMLINKS)
        .union(ResolveFlags::NO_MAGICLINKS);
    const RESOLVE_POLICY: ResolveFlags = ROOT_RESOLVE_POLICY.union(ResolveFlags::NO_XDEV);
    const PATH_DIRECTORY_FLAGS: OFlags = OFlags::PATH
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);
    const READ_DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);
    const PATH_FILE_FLAGS: OFlags = OFlags::PATH.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);
    const READ_FILE_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);
    const READ_CHUNK_BYTES: usize = 64 * 1024;

    #[derive(Clone, Copy)]
    enum ContractAuthority {
        Frozen,
        #[cfg(test)]
        Test(B4NegativeCustodyContract),
    }

    impl ContractAuthority {
        fn resolve(
            self,
            domain: B4MaterializationDomain,
            surface: B4NegativeExecutionSurface,
        ) -> Result<Option<B4NegativeCustodyContract>> {
            match self {
                Self::Frozen => frozen_negative_custody_contract(domain, surface),
                #[cfg(test)]
                Self::Test(contract) => Ok((contract.materialization_domain() == domain
                    && contract.validation_surface() == surface)
                    .then_some(contract)),
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct StableIdentity {
        device: u64,
        inode: u64,
    }

    impl StableIdentity {
        const fn from_stat(stat: &Stat) -> Self {
            Self {
                device: stat.st_dev,
                inode: stat.st_ino,
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct StableDirectoryState {
        identity: StableIdentity,
        mode: u32,
        owner: u32,
        group: u32,
        modified_seconds: i64,
        modified_nanoseconds: u64,
        changed_seconds: i64,
        changed_nanoseconds: u64,
    }

    impl StableDirectoryState {
        fn from_validated_stat(stat: &Stat, label: &str) -> Result<Self> {
            validate_directory_stat(stat, label)?;
            Ok(Self {
                identity: StableIdentity::from_stat(stat),
                mode: stat.st_mode,
                owner: stat.st_uid,
                group: stat.st_gid,
                modified_seconds: stat.st_mtime,
                modified_nanoseconds: stat.st_mtime_nsec,
                changed_seconds: stat.st_ctime,
                changed_nanoseconds: stat.st_ctime_nsec,
            })
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct StableFileState {
        identity: StableIdentity,
        length: u64,
        mode: u32,
        owner: u32,
        group: u32,
        modified_seconds: i64,
        modified_nanoseconds: u64,
        changed_seconds: i64,
        changed_nanoseconds: u64,
    }

    impl StableFileState {
        fn from_validated_stat(
            stat: &Stat,
            minimum: u64,
            maximum: u64,
            label: &str,
        ) -> Result<Self> {
            let length = validate_file_stat(stat, minimum, maximum, label)?;
            Ok(Self {
                identity: StableIdentity::from_stat(stat),
                length,
                mode: stat.st_mode,
                owner: stat.st_uid,
                group: stat.st_gid,
                modified_seconds: stat.st_mtime,
                modified_nanoseconds: stat.st_mtime_nsec,
                changed_seconds: stat.st_ctime,
                changed_nanoseconds: stat.st_ctime_nsec,
            })
        }
    }

    struct PinnedRoot {
        base_descriptor: OwnedFd,
        relative_path: PathBuf,
        descriptor: OwnedFd,
        read_descriptor: OwnedFd,
        initial_state: StableDirectoryState,
    }

    impl PinnedRoot {
        fn open(source_path: &Path) -> Result<Self> {
            let (base_path, relative_path) = split_root_path(source_path)?;
            let base_descriptor = open(base_path, PATH_DIRECTORY_FLAGS, Mode::empty())
                .context("cannot pin negative verifier root anchor")?;
            let descriptor = openat2(
                &base_descriptor,
                &relative_path,
                PATH_DIRECTORY_FLAGS,
                Mode::empty(),
                ROOT_RESOLVE_POLICY,
            )
            .with_context(|| {
                format!(
                    "cannot pin negative verifier root {} with the closed resolver policy",
                    source_path.display()
                )
            })?;
            let stat =
                fstat(&descriptor).context("cannot inspect pinned negative verifier root")?;
            let initial_state =
                StableDirectoryState::from_validated_stat(&stat, "negative verifier root")?;
            let read_descriptor = openat2(
                &base_descriptor,
                &relative_path,
                READ_DIRECTORY_FLAGS,
                Mode::empty(),
                ROOT_RESOLVE_POLICY,
            )
            .context("cannot open pinned negative verifier root for inventory")?;
            let read_stat = fstat(&read_descriptor)
                .context("cannot inspect negative verifier root inventory descriptor")?;
            let read_state =
                StableDirectoryState::from_validated_stat(&read_stat, "negative verifier root")?;
            ensure!(
                read_state == initial_state,
                "negative verifier root changed while opening inventory descriptor"
            );
            Ok(PinnedRoot {
                base_descriptor,
                relative_path,
                descriptor,
                read_descriptor,
                initial_state,
            })
        }

        fn open_directory(&self, path: &str, label: &str) -> Result<PinnedDirectory> {
            let descriptor = openat2(
                &self.descriptor,
                path,
                PATH_DIRECTORY_FLAGS,
                Mode::empty(),
                RESOLVE_POLICY,
            )
            .with_context(|| format!("cannot pin {label} with the closed resolver policy"))?;
            let stat =
                fstat(&descriptor).with_context(|| format!("cannot inspect pinned {label}"))?;
            let initial_state = StableDirectoryState::from_validated_stat(&stat, label)?;
            let read_descriptor = openat2(
                &self.descriptor,
                path,
                READ_DIRECTORY_FLAGS,
                Mode::empty(),
                RESOLVE_POLICY,
            )
            .with_context(|| format!("cannot open pinned {label} for inventory"))?;
            let read_stat = fstat(&read_descriptor)
                .with_context(|| format!("cannot inspect {label} inventory descriptor"))?;
            let read_state = StableDirectoryState::from_validated_stat(&read_stat, label)?;
            ensure!(
                read_state == initial_state,
                "{label} changed while opening inventory descriptor"
            );
            Ok(PinnedDirectory {
                descriptor,
                read_descriptor,
                initial_state,
            })
        }

        fn reauthenticate(&self) -> Result<()> {
            let current = fstat(&self.descriptor)
                .context("cannot re-inspect pinned negative verifier root")?;
            let current_state =
                StableDirectoryState::from_validated_stat(&current, "negative verifier root")?;
            ensure!(
                current_state == self.initial_state,
                "pinned negative verifier root metadata drifted"
            );
            let read_current = fstat(&self.read_descriptor)
                .context("cannot re-inspect negative verifier root inventory descriptor")?;
            let read_current_state =
                StableDirectoryState::from_validated_stat(&read_current, "negative verifier root")?;
            ensure!(
                read_current_state == self.initial_state,
                "negative verifier root inventory descriptor metadata drifted"
            );
            let reopened = openat2(
                &self.base_descriptor,
                &self.relative_path,
                PATH_DIRECTORY_FLAGS,
                Mode::empty(),
                ROOT_RESOLVE_POLICY,
            )
            .context(
                "cannot re-open negative verifier root path with the closed resolver policy",
            )?;
            let reopened_stat =
                fstat(&reopened).context("cannot inspect re-opened negative verifier root path")?;
            let reopened_state = StableDirectoryState::from_validated_stat(
                &reopened_stat,
                "negative verifier root",
            )?;
            ensure!(
                reopened_state == self.initial_state,
                "negative verifier root path no longer names the pinned directory"
            );
            Ok(())
        }
    }

    struct PinnedDirectory {
        descriptor: OwnedFd,
        read_descriptor: OwnedFd,
        initial_state: StableDirectoryState,
    }

    impl PinnedDirectory {
        fn reauthenticate_below(&self, root: &PinnedRoot, path: &str, label: &str) -> Result<()> {
            let current = fstat(&self.descriptor)
                .with_context(|| format!("cannot re-inspect pinned {label}"))?;
            let current_state = StableDirectoryState::from_validated_stat(&current, label)?;
            ensure!(
                current_state == self.initial_state,
                "pinned {label} metadata drifted"
            );
            let read_current = fstat(&self.read_descriptor)
                .with_context(|| format!("cannot re-inspect {label} inventory descriptor"))?;
            let read_current_state =
                StableDirectoryState::from_validated_stat(&read_current, label)?;
            ensure!(
                read_current_state == self.initial_state,
                "{label} inventory descriptor metadata drifted"
            );
            let reopened = root.open_directory(path, label)?;
            ensure!(
                reopened.initial_state == self.initial_state,
                "{label} path no longer names the pinned directory"
            );
            Ok(())
        }
    }

    fn split_root_path(source_path: &Path) -> Result<(&'static Path, PathBuf)> {
        ensure!(
            !source_path.as_os_str().is_empty(),
            "negative verifier root path is empty"
        );
        let absolute = source_path.is_absolute();
        let mut relative = PathBuf::new();
        for component in source_path.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(component) => relative.push(component),
                Component::ParentDir => {
                    bail!("negative verifier root path contains a parent traversal")
                }
                Component::Prefix(_) => {
                    bail!("negative verifier root path contains an unsupported prefix")
                }
            }
        }
        if relative.as_os_str().is_empty() {
            relative.push(".");
        }
        Ok((
            if absolute {
                Path::new("/")
            } else {
                Path::new(".")
            },
            relative,
        ))
    }

    struct PinnedFile {
        path_descriptor: OwnedFd,
        data_descriptor: File,
        initial_state: StableFileState,
        measured: B4MeasuredNegativeFile,
        label: String,
        relative_path: String,
    }

    impl PinnedFile {
        fn open_and_read(
            parent: &OwnedFd,
            relative_path: &str,
            minimum: u64,
            maximum: u64,
            expected_sha256: Option<&str>,
            label: &str,
        ) -> Result<Self> {
            ensure!(
                minimum <= maximum,
                "{label} has an inconsistent internal read bound"
            );
            let path_descriptor = openat2(
                parent,
                relative_path,
                PATH_FILE_FLAGS,
                Mode::empty(),
                RESOLVE_POLICY,
            )
            .with_context(|| format!("cannot pin negative verifier file {label}"))?;
            let path_stat = fstat(&path_descriptor)
                .with_context(|| format!("cannot inspect pinned {label}"))?;
            let initial_state =
                StableFileState::from_validated_stat(&path_stat, minimum, maximum, label)?;

            let data_descriptor = openat2(
                parent,
                relative_path,
                READ_FILE_FLAGS,
                Mode::empty(),
                RESOLVE_POLICY,
            )
            .with_context(|| format!("cannot open negative verifier file {label} for reading"))?;
            let data_stat =
                fstat(&data_descriptor).with_context(|| format!("cannot inspect open {label}"))?;
            let data_state =
                StableFileState::from_validated_stat(&data_stat, minimum, maximum, label)?;
            ensure!(
                data_state == initial_state,
                "negative verifier file {label} changed while opening"
            );

            let mut data_descriptor = File::from(data_descriptor);
            let measured = read_bounded_file(
                &mut data_descriptor,
                initial_state.length,
                expected_sha256,
                label,
            )?;
            Ok(Self {
                path_descriptor,
                data_descriptor,
                initial_state,
                measured,
                label: label.to_owned(),
                relative_path: relative_path.to_owned(),
            })
        }

        fn reauthenticate(&mut self, parent: &OwnedFd) -> Result<()> {
            let path_stat = fstat(&self.path_descriptor)
                .with_context(|| format!("cannot re-inspect pinned {}", self.label))?;
            let path_state = StableFileState::from_validated_stat(
                &path_stat,
                self.initial_state.length,
                self.initial_state.length,
                &self.label,
            )?;
            ensure!(
                path_state == self.initial_state,
                "pinned negative verifier file {} drifted",
                self.label
            );

            let data_stat = fstat(&self.data_descriptor)
                .with_context(|| format!("cannot re-inspect open {}", self.label))?;
            let data_state = StableFileState::from_validated_stat(
                &data_stat,
                self.initial_state.length,
                self.initial_state.length,
                &self.label,
            )?;
            ensure!(
                data_state == self.initial_state,
                "open negative verifier file {} drifted",
                self.label
            );

            verify_retained_bytes(&mut self.data_descriptor, &self.measured, &self.label)?;

            let reopened = openat2(
                parent,
                self.relative_path.as_str(),
                PATH_FILE_FLAGS,
                Mode::empty(),
                RESOLVE_POLICY,
            )
            .with_context(|| format!("cannot re-open negative verifier path {}", self.label))?;
            let reopened_stat = fstat(&reopened)
                .with_context(|| format!("cannot inspect re-opened {}", self.label))?;
            let reopened_state = StableFileState::from_validated_stat(
                &reopened_stat,
                self.initial_state.length,
                self.initial_state.length,
                &self.label,
            )?;
            ensure!(
                reopened_state == self.initial_state,
                "negative verifier path {} no longer names the pinned file",
                self.label
            );
            Ok(())
        }
    }

    pub(super) fn load(root_path: &Path) -> Result<B4NegativeVerifierRoot> {
        load_with_authority(root_path, ContractAuthority::Frozen, || {})
    }

    #[cfg(test)]
    pub(super) fn load_for_test<H: FnOnce()>(
        root_path: &Path,
        contract: B4NegativeCustodyContract,
        after_initial_reads: H,
    ) -> Result<B4NegativeVerifierRoot> {
        load_with_authority(
            root_path,
            ContractAuthority::Test(contract),
            after_initial_reads,
        )
    }

    fn load_with_authority<H: FnOnce()>(
        root_path: &Path,
        authority: ContractAuthority,
        after_initial_reads: H,
    ) -> Result<B4NegativeVerifierRoot> {
        let root = PinnedRoot::open(root_path)?;
        let mut negative_input = PinnedFile::open_and_read(
            &root.descriptor,
            NEGATIVE_INPUT_FILE,
            1,
            NEGATIVE_INPUT_MAX_BYTES,
            None,
            NEGATIVE_INPUT_FILE,
        )?;
        let input =
            Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(negative_input.measured.bytes())?;
        let contract = authority
            .resolve(input.materialization_domain, input.validation_surface)?
            .context("negative handler custody contract is not frozen for the input pair")?;
        contract.validate_input(negative_input.initial_state.length, &input)?;

        let context_directory = if input.context.is_empty() {
            None
        } else {
            Some(root.open_directory(NEGATIVE_CONTEXT_DIRECTORY, "negative context directory")?)
        };
        validate_exact_root_inventory(&root.read_descriptor, context_directory.is_some())?;
        if let Some(context) = &context_directory {
            validate_exact_context_inventory(&context.read_descriptor, input.context.len())?;
        }

        let mut subject = PinnedFile::open_and_read(
            &root.descriptor,
            NEGATIVE_SUBJECT_FILE,
            input.subject.byte_length,
            input.subject.byte_length,
            Some(&input.subject.sha256),
            NEGATIVE_SUBJECT_FILE,
        )?;
        let mut contexts = Vec::new();
        contexts
            .try_reserve_exact(input.context.len())
            .context("cannot reserve bounded negative context custody")?;
        if let Some(context_directory) = &context_directory {
            for (index, identity) in input.context.iter().enumerate() {
                contexts.push(PinnedFile::open_and_read(
                    &context_directory.descriptor,
                    &format!("{index:02}.bin"),
                    identity.byte_length,
                    identity.byte_length,
                    Some(&identity.sha256),
                    &context_relative_path(index),
                )?);
            }
        }

        after_initial_reads();

        negative_input.reauthenticate(&root.descriptor)?;
        subject.reauthenticate(&root.descriptor)?;
        if let Some(context_directory) = &context_directory {
            for context in &mut contexts {
                context.reauthenticate(&context_directory.descriptor)?;
            }
            context_directory.reauthenticate_below(
                &root,
                NEGATIVE_CONTEXT_DIRECTORY,
                "negative context directory",
            )?;
            validate_exact_context_inventory(
                &context_directory.read_descriptor,
                input.context.len(),
            )?;
        }
        validate_exact_root_inventory(&root.read_descriptor, context_directory.is_some())?;
        root.reauthenticate()?;

        let mut measured_contexts = Vec::new();
        measured_contexts
            .try_reserve_exact(contexts.len())
            .context("cannot reserve authenticated negative context result")?;
        for context in contexts {
            measured_contexts.push(context.measured);
        }
        Ok(B4NegativeVerifierRoot {
            negative_input_file: negative_input.measured,
            input,
            subject: subject.measured,
            contexts: measured_contexts,
        })
    }

    fn read_bounded_file(
        file: &mut File,
        length: u64,
        expected_sha256: Option<&str>,
        label: &str,
    ) -> Result<B4MeasuredNegativeFile> {
        let length_usize = usize::try_from(length)
            .with_context(|| format!("negative verifier file {label} exceeds usize"))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length_usize)
            .with_context(|| format!("cannot reserve negative verifier file {label}"))?;
        bytes.resize(length_usize, 0);

        let mut hasher = Sha256::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let end = offset.saturating_add(READ_CHUNK_BYTES).min(bytes.len());
            file.read_exact(&mut bytes[offset..end])
                .with_context(|| format!("negative verifier file {label} ended early"))?;
            hasher.update(&bytes[offset..end]);
            offset = end;
        }
        let mut trailing = [0_u8; 1];
        ensure!(
            file.read(&mut trailing)
                .with_context(|| format!("cannot check EOF for {label}"))?
                == 0,
            "negative verifier file {label} has trailing bytes"
        );
        let sha256: [u8; 32] = hasher.finalize().into();
        if let Some(expected) = expected_sha256 {
            ensure!(
                hex::encode(sha256) == expected,
                "negative verifier file {label} SHA-256 differs from its descriptor"
            );
        }
        Ok(B4MeasuredNegativeFile { bytes, sha256 })
    }

    fn verify_retained_bytes(
        file: &mut File,
        measured: &B4MeasuredNegativeFile,
        label: &str,
    ) -> Result<()> {
        file.seek(SeekFrom::Start(0))
            .with_context(|| format!("cannot rewind retained negative verifier file {label}"))?;
        let mut buffer = [0_u8; READ_CHUNK_BYTES];
        let mut offset = 0;
        let mut hasher = Sha256::new();
        while offset < measured.bytes.len() {
            let count = (measured.bytes.len() - offset).min(buffer.len());
            file.read_exact(&mut buffer[..count])
                .with_context(|| format!("retained negative verifier file {label} ended early"))?;
            ensure!(
                buffer[..count] == measured.bytes[offset..offset + count],
                "negative verifier file {label} bytes changed after initial authentication"
            );
            hasher.update(&buffer[..count]);
            offset += count;
        }
        let mut trailing = [0_u8; 1];
        ensure!(
            file.read(&mut trailing)
                .with_context(|| format!("cannot re-check EOF for {label}"))?
                == 0,
            "retained negative verifier file {label} gained trailing bytes"
        );
        let digest: [u8; 32] = hasher.finalize().into();
        ensure!(
            digest == measured.sha256,
            "negative verifier file {label} digest changed after initial authentication"
        );
        Ok(())
    }

    fn validate_file_stat(stat: &Stat, minimum: u64, maximum: u64, label: &str) -> Result<u64> {
        ensure!(
            FileType::from_raw_mode(stat.st_mode).is_file(),
            "negative verifier path is not a regular file: {label}"
        );
        ensure!(
            stat.st_nlink == 1,
            "hard-linked negative verifier file is forbidden: {label}"
        );
        let length = u64::try_from(stat.st_size)
            .with_context(|| format!("negative verifier file {label} has a negative size"))?;
        ensure!(
            (minimum..=maximum).contains(&length),
            "negative verifier file {label} length is outside its bound"
        );
        Ok(length)
    }

    fn validate_directory_stat(stat: &Stat, label: &str) -> Result<()> {
        ensure!(
            FileType::from_raw_mode(stat.st_mode).is_dir(),
            "{label} is not an ordinary directory"
        );
        Ok(())
    }

    fn validate_exact_root_inventory(root: &OwnedFd, expect_context: bool) -> Result<()> {
        let mut input_seen = false;
        let mut subject_seen = false;
        let mut context_seen = false;
        let mut directory =
            Dir::read_from(root).context("cannot enumerate pinned negative root")?;
        for entry in &mut directory {
            let entry = entry.context("cannot read pinned negative root entry")?;
            match entry.file_name().to_bytes() {
                b"." | b".." => {}
                name if name == NEGATIVE_INPUT_FILE.as_bytes() && !input_seen => input_seen = true,
                name if name == NEGATIVE_SUBJECT_FILE.as_bytes() && !subject_seen => {
                    subject_seen = true;
                }
                name if name == NEGATIVE_CONTEXT_DIRECTORY.as_bytes()
                    && expect_context
                    && !context_seen =>
                {
                    context_seen = true;
                }
                _ => bail!("negative verifier root contains an unexpected or duplicate entry"),
            }
        }
        ensure!(
            input_seen && subject_seen && context_seen == expect_context,
            "negative verifier root does not contain the exact V1 inventory"
        );
        Ok(())
    }

    fn validate_exact_context_inventory(context: &OwnedFd, expected_count: usize) -> Result<()> {
        ensure!(
            expected_count <= MAX_NEGATIVE_CONTEXT_FILES,
            "negative context prefix exceeds the V1 positional limit"
        );
        let mut observed = 0_u64;
        let mut directory =
            Dir::read_from(context).context("cannot enumerate pinned negative context")?;
        for entry in &mut directory {
            let entry = entry.context("cannot read pinned negative context entry")?;
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            let index = parse_context_filename(name)?;
            ensure!(
                index < expected_count,
                "negative context entry lies outside the exact positional prefix"
            );
            let bit = 1_u64 << index;
            ensure!(
                observed & bit == 0,
                "negative context contains a duplicate positional entry"
            );
            observed |= bit;
        }
        let expected = if expected_count == 64 {
            u64::MAX
        } else {
            (1_u64 << expected_count) - 1
        };
        ensure!(
            observed == expected,
            "negative context directory is not the exact NN.bin positional prefix"
        );
        Ok(())
    }

    fn parse_context_filename(name: &[u8]) -> Result<usize> {
        ensure!(
            name.len() == 6 && &name[2..] == b".bin",
            "negative context filename is not exact NN.bin"
        );
        ensure!(
            name[0].is_ascii_digit() && name[1].is_ascii_digit(),
            "negative context filename is not exact NN.bin"
        );
        let index = usize::from(name[0] - b'0') * 10 + usize::from(name[1] - b'0');
        ensure!(
            index < MAX_NEGATIVE_CONTEXT_FILES,
            "negative context position exceeds the V1 limit"
        );
        Ok(index)
    }
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
fn load_negative_verifier_root_for_test<H: FnOnce()>(
    root: &Path,
    contract: B4NegativeCustodyContract,
    after_initial_reads: H,
) -> Result<B4NegativeVerifierRoot> {
    linux::load_for_test(root, contract, after_initial_reads)
}

#[cfg(test)]
mod tests {
    #![cfg_attr(
        not(all(target_os = "linux", target_arch = "x86_64")),
        allow(
            dead_code,
            unused_imports,
            reason = "physical custody fixtures execute only on Linux/x86_64"
        )
    )]

    use super::*;
    use crate::{
        b4_negative_handler_contract::B4NegativeByteBounds,
        b4_negative_io::{
            B4_NEGATIVE_VERIFIER_INPUT_FORMAT, B4_NEGATIVE_VERIFIER_INPUT_FORMAT_VERSION,
            B4NegativeFileEncoding, B4NegativeNamedIdentityV1,
        },
        b4_plan::{B4MaterializationDomain, B4NegativeExecutionSurface},
    };
    use sha2::{Digest as _, Sha256};
    use std::{fs, path::Path};

    const SUBJECT_BOUNDS: B4NegativeByteBounds = B4NegativeByteBounds::new(1, 16);
    const CONTEXT_BOUNDS: [B4NegativeByteBounds; 2] = [
        B4NegativeByteBounds::new(1, 8),
        B4NegativeByteBounds::new(2, 8),
    ];

    fn sha256(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn identity(role: &str, path: &str, bytes: &[u8]) -> B4NegativeNamedIdentityV1 {
        B4NegativeNamedIdentityV1 {
            role: role.to_owned(),
            path: path.to_owned(),
            byte_length: u64::try_from(bytes.len()).unwrap(),
            sha256: sha256(bytes),
            encoding: B4NegativeFileEncoding::RawBytes,
        }
    }

    fn default_contract() -> B4NegativeCustodyContract {
        B4NegativeCustodyContract::new(
            B4MaterializationDomain::VerifierInput,
            B4NegativeExecutionSurface::RawSealShape,
            SUBJECT_BOUNDS,
            &CONTEXT_BOUNDS,
            65_568,
        )
    }

    fn write_fixture(root: &Path) {
        let subject = b"subject";
        let first = b"first";
        let second = b"second";
        fs::create_dir_all(root.join(NEGATIVE_CONTEXT_DIRECTORY)).unwrap();
        fs::write(root.join(NEGATIVE_SUBJECT_FILE), subject).unwrap();
        fs::write(root.join("context/00.bin"), first).unwrap();
        fs::write(root.join("context/01.bin"), second).unwrap();
        let input = Eip0045B4NegativeVerifierInputV1 {
            format: B4_NEGATIVE_VERIFIER_INPUT_FORMAT.to_owned(),
            format_version: B4_NEGATIVE_VERIFIER_INPUT_FORMAT_VERSION,
            materialization_domain: B4MaterializationDomain::VerifierInput,
            validation_surface: B4NegativeExecutionSurface::RawSealShape,
            subject: identity("subject", NEGATIVE_SUBJECT_FILE, subject),
            context: vec![
                identity("context-00", "context/00.bin", first),
                identity("context-01", "context/01.bin", second),
            ],
        };
        fs::write(
            root.join(NEGATIVE_INPUT_FILE),
            input.to_canonical_jcs().unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn allocation_arithmetic_is_checked() {
        assert!(checked_cumulative_allocation(u64::MAX, 1, [], u64::MAX).is_err());
        assert!(checked_cumulative_allocation(1, u64::MAX - 1, [1], u64::MAX).is_err());
        assert_eq!(checked_cumulative_allocation(1, 2, [3, 4], 10).unwrap(), 10);
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    #[test]
    fn unsupported_platform_fails_before_inspecting_the_path() {
        let error = load_negative_verifier_root(Path::new(
            "this-path-must-not-be-inspected-before-platform-gate",
        ))
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires Linux/x86_64 with openat2 support")
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn load_for_test<H: FnOnce()>(
        root: &Path,
        after_initial_reads: H,
    ) -> Result<B4NegativeVerifierRoot> {
        load_negative_verifier_root_for_test(root, default_contract(), after_initial_reads)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn valid_root_is_read_twice_from_retained_descriptors() {
        let temp = crate::test_support::tempdir().unwrap();
        write_fixture(temp.path());
        let loaded = load_for_test(temp.path(), || {}).unwrap();
        assert_eq!(loaded.subject().bytes(), b"subject");
        assert_eq!(loaded.contexts()[0].bytes(), b"first");
        assert_eq!(loaded.contexts()[1].bytes(), b"second");
        assert_eq!(loaded.input().context.len(), 2);
        let expected_input_sha256: [u8; 32] =
            Sha256::digest(loaded.negative_input_file().bytes()).into();
        assert_eq!(loaded.negative_input_file().sha256(), expected_input_sha256);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn symlink_and_hardlink_payloads_are_rejected() {
        use std::os::unix::fs::symlink;

        let root_target = crate::test_support::tempdir().unwrap();
        write_fixture(root_target.path());
        let root_parent = crate::test_support::tempdir().unwrap();
        let linked_root = root_parent.path().join("linked-root");
        symlink(root_target.path(), &linked_root).unwrap();
        assert!(load_for_test(&linked_root, || {}).is_err());

        let symlinked = crate::test_support::tempdir().unwrap();
        let external = crate::test_support::tempdir().unwrap();
        write_fixture(symlinked.path());
        let target = external.path().join("target.bin");
        fs::write(&target, b"subject").unwrap();
        fs::remove_file(symlinked.path().join(NEGATIVE_SUBJECT_FILE)).unwrap();
        symlink(&target, symlinked.path().join(NEGATIVE_SUBJECT_FILE)).unwrap();
        assert!(load_for_test(symlinked.path(), || {}).is_err());

        let context_linked = crate::test_support::tempdir().unwrap();
        let external_context = crate::test_support::tempdir().unwrap();
        write_fixture(context_linked.path());
        fs::write(external_context.path().join("00.bin"), b"first").unwrap();
        fs::write(external_context.path().join("01.bin"), b"second").unwrap();
        fs::remove_dir_all(context_linked.path().join(NEGATIVE_CONTEXT_DIRECTORY)).unwrap();
        symlink(
            external_context.path(),
            context_linked.path().join(NEGATIVE_CONTEXT_DIRECTORY),
        )
        .unwrap();
        assert!(load_for_test(context_linked.path(), || {}).is_err());

        let hard_linked = crate::test_support::tempdir().unwrap();
        write_fixture(hard_linked.path());
        let alias = external.path().join("alias.bin");
        fs::hard_link(hard_linked.path().join(NEGATIVE_SUBJECT_FILE), alias).unwrap();
        assert!(load_for_test(hard_linked.path(), || {}).is_err());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn same_name_replacement_after_initial_read_is_rejected() {
        let temp = crate::test_support::tempdir().unwrap();
        let external = crate::test_support::tempdir().unwrap();
        write_fixture(temp.path());
        let subject_path = temp.path().join(NEGATIVE_SUBJECT_FILE);
        let retained_elsewhere = external.path().join("retained-subject.bin");
        let result = load_for_test(temp.path(), || {
            fs::rename(&subject_path, &retained_elsewhere).unwrap();
            fs::write(&subject_path, b"subject").unwrap();
        });
        assert!(result.is_err());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn in_place_mutation_after_initial_read_is_rejected() {
        let temp = crate::test_support::tempdir().unwrap();
        write_fixture(temp.path());
        let subject_path = temp.path().join(NEGATIVE_SUBJECT_FILE);
        let result = load_for_test(temp.path(), || {
            fs::write(subject_path, b"mutated").unwrap();
        });
        assert!(result.is_err());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn root_and_context_directory_replacements_are_rejected() {
        let parent = crate::test_support::tempdir().unwrap();
        let root = parent.path().join("root");
        fs::create_dir(&root).unwrap();
        write_fixture(&root);
        let moved = parent.path().join("moved-root");
        let result = load_for_test(&root, || {
            fs::rename(&root, &moved).unwrap();
            fs::create_dir(&root).unwrap();
        });
        assert!(result.is_err());

        let temp = crate::test_support::tempdir().unwrap();
        let external = crate::test_support::tempdir().unwrap();
        write_fixture(temp.path());
        let context_path = temp.path().join(NEGATIVE_CONTEXT_DIRECTORY);
        let moved_context = external.path().join("moved-context");
        let result = load_for_test(temp.path(), || {
            fs::rename(&context_path, &moved_context).unwrap();
            fs::create_dir(&context_path).unwrap();
            fs::write(context_path.join("00.bin"), b"first").unwrap();
            fs::write(context_path.join("01.bin"), b"second").unwrap();
        });
        assert!(result.is_err());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn directory_metadata_and_transient_inventory_mutations_are_rejected() {
        use std::os::unix::fs::PermissionsExt as _;

        let metadata = crate::test_support::tempdir().unwrap();
        write_fixture(metadata.path());
        let result = load_for_test(metadata.path(), || {
            let mut permissions = fs::metadata(metadata.path()).unwrap().permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(metadata.path(), permissions).unwrap();
        });
        assert!(result.is_err());

        let inventory = crate::test_support::tempdir().unwrap();
        write_fixture(inventory.path());
        let transient = inventory.path().join("transient.bin");
        let result = load_for_test(inventory.path(), || {
            fs::write(&transient, b"transient").unwrap();
            fs::remove_file(&transient).unwrap();
        });
        assert!(result.is_err());

        let context = crate::test_support::tempdir().unwrap();
        write_fixture(context.path());
        let transient = context
            .path()
            .join(NEGATIVE_CONTEXT_DIRECTORY)
            .join("transient.bin");
        let result = load_for_test(context.path(), || {
            fs::write(&transient, b"transient").unwrap();
            fs::remove_file(&transient).unwrap();
        });
        assert!(result.is_err());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn descriptor_paths_and_exact_inventory_are_closed() {
        let wrong_path = crate::test_support::tempdir().unwrap();
        write_fixture(wrong_path.path());
        let input_path = wrong_path.path().join(NEGATIVE_INPUT_FILE);
        let source = String::from_utf8(fs::read(&input_path).unwrap()).unwrap();
        let invalid = source.replacen("\"path\":\"subject.bin\"", "\"path\":\"otherxx.bin\"", 1);
        assert_ne!(invalid, source);
        fs::write(input_path, invalid).unwrap();
        assert!(load_for_test(wrong_path.path(), || {}).is_err());

        let extra = crate::test_support::tempdir().unwrap();
        write_fixture(extra.path());
        fs::write(extra.path().join("extra.bin"), b"extra").unwrap();
        assert!(load_for_test(extra.path(), || {}).is_err());
    }
}
