//! Descriptor-rooted create-only directory transactions.

#[cfg(not(target_os = "linux"))]
use std::marker::PhantomData;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use eip_0045_reproduction::b4_terminal_evidence_packet::project_b4_terminal_evidence_publication_layout;

#[cfg(feature = "b4-prepare-input-set-kernel")]
use super::prepare_input_set::{
    PrepareInputSetCreateOnlyPermit, PrepareInputSetCreateOnlyPermitV2,
};
use super::{
    capability::MutationCapability,
    preflight::{GenericCreateOnlyCampaignLayout, ProjectedCampaignLayout},
};

#[cfg(target_os = "linux")]
use sha2::{Digest as _, Sha256};
#[cfg(target_os = "linux")]
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fmt,
    fs::File,
    io::Write as _,
    os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd},
    os::unix::ffi::OsStrExt as _,
    os::unix::fs::FileExt as _,
};

#[cfg(target_os = "linux")]
const PINNED_DIRECTORY_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY
    .union(rustix::fs::OFlags::DIRECTORY)
    .union(rustix::fs::OFlags::NOFOLLOW)
    .union(rustix::fs::OFlags::CLOEXEC);
#[cfg(target_os = "linux")]
const PINNED_FILE_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY
    .union(rustix::fs::OFlags::NOFOLLOW)
    .union(rustix::fs::OFlags::NONBLOCK)
    .union(rustix::fs::OFlags::CLOEXEC);
#[cfg(target_os = "linux")]
const CREATE_FILE_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDWR
    .union(rustix::fs::OFlags::CREATE)
    .union(rustix::fs::OFlags::EXCL)
    .union(rustix::fs::OFlags::NOFOLLOW)
    .union(rustix::fs::OFlags::CLOEXEC);
#[cfg(target_os = "linux")]
const MAX_PORTABLE_RELATIVE_PATH_BYTES: usize = 240;
#[cfg(target_os = "linux")]
const MAX_ABSOLUTE_PATH_BYTES: usize = 4096;
#[cfg(target_os = "linux")]
const MAX_ABSOLUTE_PATH_COMPONENTS: usize = 64;
#[cfg(target_os = "linux")]
const MAX_CREATE_ONLY_ENTRIES: usize = 4096;
#[cfg(target_os = "linux")]
const MAX_CREATE_ONLY_DEPTH: usize = 64;
#[cfg(target_os = "linux")]
const MAX_CREATE_ONLY_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_CREATE_ONLY_FILE_BYTES: u64 = 512 * 1024 * 1024;
#[cfg(target_os = "linux")]
const PRIVATE_DIRECTORY_MODE: rustix::fs::Mode = rustix::fs::Mode::RWXU;
#[cfg(target_os = "linux")]
const PRIVATE_FILE_MODE: rustix::fs::Mode = rustix::fs::Mode::RUSR.union(rustix::fs::Mode::WUSR);
#[cfg(target_os = "linux")]
const PERMISSION_AND_SPECIAL_BITS: u32 = 0o7777;
#[cfg(target_os = "linux")]
const PATH_COMPONENT_RESOLVE_FLAGS: rustix::fs::ResolveFlags = rustix::fs::ResolveFlags::BENEATH
    .union(rustix::fs::ResolveFlags::NO_SYMLINKS)
    .union(rustix::fs::ResolveFlags::NO_MAGICLINKS);
#[cfg(target_os = "linux")]
const TREE_ENTRY_RESOLVE_FLAGS: rustix::fs::ResolveFlags =
    PATH_COMPONENT_RESOLVE_FLAGS.union(rustix::fs::ResolveFlags::NO_XDEV);

trait MutationCustody {
    fn recheck(&self) -> Result<()>;
}

impl<const ROOTS: usize, Layout> MutationCustody for MutationCapability<'_, ROOTS, Layout>
where
    Layout: ProjectedCampaignLayout<ROOTS>,
{
    fn recheck(&self) -> Result<()> {
        MutationCapability::recheck(self)
    }
}

/// Pure projected final, parent and reserved-staging paths.
///
/// This type carries no filesystem authority and is intentionally not
/// serializable.
#[derive(Clone, Debug)]
pub(super) struct CreateOnlyDirectoryLayout {
    final_path: PathBuf,
    parent: PathBuf,
    reserved_staging_path: PathBuf,
}

impl CreateOnlyDirectoryLayout {
    /// Intended final path.
    #[must_use]
    pub(super) fn final_path(&self) -> &Path {
        &self.final_path
    }

    /// Existing parent required by the live transaction.
    #[must_use]
    pub(super) fn parent(&self) -> &Path {
        &self.parent
    }

    /// Deterministic create-only staging sibling.
    #[must_use]
    pub(super) fn reserved_staging_path(&self) -> &Path {
        &self.reserved_staging_path
    }
}

/// Purely project one normalized absolute create-only directory layout.
pub(super) fn project_create_only_directory_layout(
    destination: &Path,
) -> Result<CreateOnlyDirectoryLayout> {
    validate_normalized_absolute_path(destination)?;
    let canonical = project_b4_terminal_evidence_publication_layout(destination)
        .context("create-only destination basename is not portable")?;
    ensure!(
        canonical.final_path() == destination,
        "create-only final-path projection drift"
    );
    Ok(CreateOnlyDirectoryLayout {
        final_path: canonical.final_path().to_path_buf(),
        parent: canonical.parent().to_path_buf(),
        reserved_staging_path: canonical.reserved_staging_path().to_path_buf(),
    })
}

/// Check the exact outer create-only parent before proof work.
///
/// The check pins and reauthenticates the parent chain, binds it to campaign
/// and immutable-root custody, proves atomic no-replace support, and requires
/// both the final and reserved staging names to be absent. It creates no
/// retained transaction state.
pub(super) fn preflight_create_only_directory_transaction(
    layout: &CreateOnlyDirectoryLayout,
    authenticate_parent: impl FnOnce(&[(u64, u64, u64)]) -> Result<()>,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let _parent = pin_and_preflight_create_only_parent(
            layout,
            authenticate_parent,
            probe_atomic_no_replace,
        )?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (layout, authenticate_parent);
        anyhow::bail!("create-only directory preflight requires Linux")
    }
}

fn validate_normalized_absolute_path(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute(),
        "create-only destination must be an absolute path"
    );
    let mut rebuilt = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => rebuilt.push(prefix.as_os_str()),
            Component::RootDir => rebuilt.push(component.as_os_str()),
            Component::Normal(name) => rebuilt.push(name),
            Component::CurDir | Component::ParentDir => {
                anyhow::bail!("create-only destination must be a normalized absolute path");
            }
        }
    }
    ensure!(
        rebuilt.as_os_str() == path.as_os_str(),
        "create-only destination must be a normalized absolute path"
    );
    Ok(())
}

/// In-progress create-only directory transaction.
///
/// The transaction is a private effect capability, not publication authority.
#[cfg(target_os = "linux")]
pub(super) struct CreateOnlyDirectoryTransaction<'capability> {
    guard: &'capability dyn MutationCustody,
    layout: CreateOnlyDirectoryLayout,
    parent: PinnedAbsoluteDirectoryPath,
    final_name: OsString,
    staging_name: OsString,
    staging_root: OwnedFd,
    staging_observation: DirectoryObservation,
    directories: BTreeMap<String, RetainedDirectory>,
    directory_order: Vec<String>,
    files: BTreeMap<String, RetainedFile>,
    expected_entries: BTreeMap<String, BTreeSet<String>>,
    required_top_level_entries: BTreeSet<String>,
    required_top_level_directories: BTreeSet<String>,
    entry_count: usize,
    byte_length: u64,
    poisoned: bool,
}

/// Durably committed create-only tree that still retains descriptor custody.
///
/// This typestate separates the irreversible commit from the later semantic
/// reopen. It is not publication authority and yields no result until the
/// committed tree has been reauthenticated around the designated validator.
#[cfg(target_os = "linux")]
#[must_use = "the committed tree must be reopened and validated before authority is retained"]
pub(super) struct CommittedCreateOnlyDirectoryTransaction<'capability> {
    transaction: CreateOnlyDirectoryTransaction<'capability>,
}

/// Borrowed, descriptor-rooted view of one durably committed tree.
///
/// The view cannot outlive the transaction and exposes no owned descriptor.
#[cfg(target_os = "linux")]
pub(super) struct CommittedCreateOnlyDirectoryView<'transaction, 'capability> {
    transaction: &'transaction CreateOnlyDirectoryTransaction<'capability>,
}

#[cfg(target_os = "linux")]
impl CommittedCreateOnlyDirectoryView<'_, '_> {
    /// Read one retained file only after the committed pathname is reauthenticated.
    pub(super) fn read_file(&self, relative: &str, maximum: usize) -> Result<Vec<u8>> {
        validate_portable_relative_path(relative)?;
        self.transaction.reauthenticate_final().with_context(|| {
            format!("committed file pre-read reauthentication failed: {relative}")
        })?;
        let outcome = (|| {
            let retained = self
                .transaction
                .files
                .get(relative)
                .with_context(|| format!("retained committed file is absent: {relative}"))?;
            let bytes = read_stable_bytes(&retained.file, retained.observation, maximum)
                .with_context(|| format!("cannot read retained committed file: {relative}"))?;
            let expected_sha256 = retained
                .expected_sha256
                .context("retained committed file has no sealed digest")?;
            ensure!(
                <[u8; 32]>::from(Sha256::digest(&bytes)) == expected_sha256,
                "retained committed file bytes changed: {relative}"
            );
            Ok(bytes)
        })();
        finish_guarded_outcome(
            outcome,
            self.transaction.reauthenticate_final(),
            "committed file read",
        )
    }

    /// Borrow the retained committed root for an immediate semantic reopen.
    pub(super) fn root_directory_descriptor(&self) -> Result<BorrowedFd<'_>> {
        self.transaction
            .reauthenticate_final()
            .context("committed root pre-borrow reauthentication failed")?;
        Ok(self.transaction.staging_root.as_fd())
    }

    /// Borrow one retained committed directory descriptor for an immediate semantic reopen.
    pub(super) fn directory_descriptor(&self, relative: &str) -> Result<BorrowedFd<'_>> {
        validate_portable_relative_path(relative)?;
        self.transaction.reauthenticate_final().with_context(|| {
            format!("committed directory pre-borrow reauthentication failed: {relative}")
        })?;
        self.transaction
            .directories
            .get(relative)
            .map(|directory| directory.descriptor.as_fd())
            .with_context(|| format!("retained committed directory is absent: {relative}"))
    }

    /// Require one portable descendant to remain absent beneath retained custody.
    pub(super) fn require_absent(&self, relative: &str) -> Result<()> {
        let entry = PortableRelativeEntry::parse(relative)?;
        self.transaction
            .reauthenticate_final()
            .with_context(|| format!("committed absence precheck failed: {relative}"))?;
        let outcome = ensure_absent(
            self.transaction.directory_descriptor(&entry.parent)?,
            entry.name.as_os_str(),
            &self.transaction.layout.final_path().join(relative),
            "reserved committed descendant",
        );
        finish_guarded_outcome(
            outcome,
            self.transaction.reauthenticate_final(),
            "committed absence check",
        )
    }
}

#[cfg(target_os = "linux")]
impl<'capability> CommittedCreateOnlyDirectoryTransaction<'capability> {
    /// Semantically reopen through retained descriptors, then reauthenticate.
    ///
    /// The returned value cannot borrow the committed view, so no borrowed
    /// publication view can escape before the final physical custody check succeeds.
    pub(super) fn reopen_with_postcommit_validation<T, F>(self, validate: F) -> Result<T>
    where
        F: for<'transaction> FnOnce(
            CommittedCreateOnlyDirectoryView<'transaction, 'capability>,
        ) -> Result<T>,
    {
        self.transaction
            .reauthenticate_final()
            .context("committed tree changed before semantic validation")?;
        self.transaction
            .guard
            .recheck()
            .context("committed-tree validation custody precheck failed")?;
        let outcome = validate(CommittedCreateOnlyDirectoryView {
            transaction: &self.transaction,
        });
        let postcheck = self
            .transaction
            .reauthenticate_final()
            .context("committed tree changed after semantic validation")
            .and_then(|()| {
                self.transaction
                    .guard
                    .recheck()
                    .context("committed-tree validation custody postcheck failed")
            })
            .and_then(|()| {
                self.transaction
                    .reauthenticate_final()
                    .context("committed tree changed during final custody postcheck")
            });
        finish_guarded_outcome(outcome, postcheck, "committed-tree semantic validation")
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for CreateOnlyDirectoryTransaction<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateOnlyDirectoryTransaction")
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

#[cfg(target_os = "linux")]
impl<'capability> CreateOnlyDirectoryTransaction<'capability> {
    /// Begin one exclusive staging transaction.
    fn begin(
        guard: &'capability dyn MutationCustody,
        layout: &CreateOnlyDirectoryLayout,
        required_top_level_entries: &[String],
        required_top_level_directories: &[String],
        authenticate_parent: impl FnOnce(&[(u64, u64, u64)]) -> Result<()>,
    ) -> Result<Self> {
        guard.recheck()?;
        let (required, required_directories) = validate_required_top_level_inventory(
            required_top_level_entries,
            required_top_level_directories,
        )?;
        let PreflightedCreateOnlyParent {
            parent,
            final_name,
            staging_name,
        } = pin_and_preflight_create_only_parent(
            layout,
            authenticate_parent,
            probe_atomic_no_replace,
        )?;
        if let Err(error) =
            rustix::fs::mkdirat(parent.descriptor(), &staging_name, PRIVATE_DIRECTORY_MODE)
        {
            if error == rustix::io::Errno::EXIST {
                anyhow::bail!(
                    "reserved create-only staging is occupied: {}",
                    layout.reserved_staging_path().display()
                );
            }
            return Err(anyhow::Error::from(error)).with_context(|| {
                format!(
                    "cannot create reserved staging {}",
                    layout.reserved_staging_path().display()
                )
            });
        }

        let staging_root = rustix::fs::openat2(
            parent.descriptor(),
            &staging_name,
            PINNED_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
            TREE_ENTRY_RESOLVE_FLAGS,
        )
        .with_context(|| {
            format!(
                "created staging pathname changed before it could be retained: {}",
                layout.reserved_staging_path().display()
            )
        })?;
        let staging_observation =
            prepare_private_created_directory(&staging_root, layout.reserved_staging_path())?;
        let mut expected_entries = BTreeMap::new();
        expected_entries.insert(String::new(), BTreeSet::new());
        let transaction = Self {
            guard,
            layout: layout.clone(),
            parent,
            final_name,
            staging_name,
            staging_root,
            staging_observation,
            directories: BTreeMap::new(),
            directory_order: Vec::new(),
            files: BTreeMap::new(),
            expected_entries,
            required_top_level_entries: required,
            required_top_level_directories: required_directories,
            entry_count: 0,
            byte_length: 0,
            poisoned: false,
        };
        transaction
            .reauthenticate_staging()
            .context("created staging no longer names its retained directory")?;
        transaction.guard.recheck()?;
        Ok(transaction)
    }

    /// Create and retain one portable descendant directory.
    pub(super) fn create_directory(&mut self, relative: &str) -> Result<()> {
        ensure!(!self.poisoned, "create-only transaction is poisoned");
        if let Err(error) = self.guard.recheck() {
            self.poisoned = true;
            return Err(error).context("create-only directory custody precheck failed");
        }
        let outcome = self.create_directory_inner(relative);
        let result = finish_guarded_outcome(
            outcome,
            self.guard.recheck(),
            "create-only directory effect",
        );
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// Create, write, synchronize and retain one bounded portable file.
    pub(super) fn create_file(
        &mut self,
        relative: &str,
        bytes: &[u8],
        maximum: usize,
    ) -> Result<()> {
        ensure!(!self.poisoned, "create-only transaction is poisoned");
        if let Err(error) = self.guard.recheck() {
            self.poisoned = true;
            return Err(error).context("create-only file custody precheck failed");
        }
        let outcome = self.create_file_inner(relative, bytes, maximum);
        let result =
            finish_guarded_outcome(outcome, self.guard.recheck(), "create-only file effect");
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// Publish one private subtree through retained staging custody, then adopt it.
    ///
    /// The publisher receives only a borrowed descriptor after the projected slot
    /// and the empty retained staging root have both been reauthenticated. Its
    /// return value is withheld until the created subtree has been descriptor-root
    /// adopted and every custody postcheck succeeds.
    pub(super) fn publish_and_adopt_directory_tree<T, F>(
        &mut self,
        relative: &str,
        publish: F,
    ) -> Result<T>
    where
        F: for<'staging> FnOnce(BorrowedFd<'staging>) -> Result<T>,
    {
        ensure!(!self.poisoned, "create-only transaction is poisoned");
        if let Err(error) = self.guard.recheck() {
            self.poisoned = true;
            return Err(error).context("descriptor-rooted publication custody precheck failed");
        }
        let outcome = self.publish_and_adopt_directory_tree_inner(relative, publish);
        let result = finish_guarded_outcome(
            outcome,
            self.guard.recheck(),
            "descriptor-rooted publication effect",
        );
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// Test-only entrypoint for independently exercising adoption rejection.
    #[cfg(test)]
    pub(super) fn adopt_published_directory_tree(&mut self, relative: &str) -> Result<()> {
        ensure!(!self.poisoned, "create-only transaction is poisoned");
        if let Err(error) = self.guard.recheck() {
            self.poisoned = true;
            return Err(error).context("published-tree adoption custody precheck failed");
        }
        let outcome = self.adopt_published_directory_tree_inner(relative);
        let result = finish_guarded_outcome(
            outcome,
            self.guard.recheck(),
            "published-tree adoption effect",
        );
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// Durably commit the staging directory without replacing any destination.
    pub(super) fn commit(self) -> Result<()> {
        self.commit_durable()?
            .reopen_with_postcommit_validation(|_| Ok(()))
    }

    /// Durably commit while retaining the exact descriptors for a later semantic reopen.
    pub(super) fn commit_durable(
        mut self,
    ) -> Result<CommittedCreateOnlyDirectoryTransaction<'capability>> {
        ensure!(!self.poisoned, "create-only transaction is poisoned");
        self.guard.recheck()?;
        finish_guarded_outcome(
            self.commit_inner(),
            self.guard.recheck(),
            "create-only commit",
        )?;
        Ok(CommittedCreateOnlyDirectoryTransaction { transaction: self })
    }

    /// Commit, semantically reopen through retained descriptors, then reauthenticate.
    ///
    /// The returned value cannot borrow the committed view, so no borrowed
    /// publication view can escape before the final physical custody check succeeds.
    pub(super) fn commit_with_postcommit_validation<T, F>(self, validate: F) -> Result<T>
    where
        F: for<'transaction> FnOnce(
            CommittedCreateOnlyDirectoryView<'transaction, 'capability>,
        ) -> Result<T>,
    {
        self.commit_durable()?
            .reopen_with_postcommit_validation(validate)
    }

    fn create_directory_inner(&mut self, relative: &str) -> Result<()> {
        self.validate_new_directory(relative)?;
        let entry = PortableRelativeEntry::parse(relative)?;
        ensure!(
            !self.directories.contains_key(relative) && !self.files.contains_key(relative),
            "create-only descendant is already occupied: {relative}"
        );
        self.ensure_retained_parent(&entry.parent)?;
        self.reauthenticate_staging()?;

        let parent_descriptor = self.directory_descriptor(&entry.parent)?;
        if let Err(error) = rustix::fs::mkdirat(
            parent_descriptor,
            entry.name.as_os_str(),
            PRIVATE_DIRECTORY_MODE,
        ) {
            if error == rustix::io::Errno::EXIST {
                anyhow::bail!("create-only descendant is occupied: {relative}");
            }
            return Err(anyhow::Error::from(error))
                .with_context(|| format!("cannot create directory {relative}"));
        }
        let descriptor = rustix::fs::openat2(
            parent_descriptor,
            entry.name.as_os_str(),
            PINNED_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
            TREE_ENTRY_RESOLVE_FLAGS,
        )
        .with_context(|| format!("created directory pathname changed for {relative}"))?;
        let observation = prepare_private_created_directory(
            &descriptor,
            &self.layout.reserved_staging_path().join(relative),
        )?;

        ensure!(
            self.directories
                .insert(
                    relative.to_owned(),
                    RetainedDirectory {
                        parent: entry.parent.clone(),
                        name: entry.name,
                        descriptor,
                        observation,
                    },
                )
                .is_none(),
            "duplicate retained directory {relative}"
        );
        self.directory_order.push(relative.to_owned());
        ensure!(
            self.expected_entries
                .insert(relative.to_owned(), BTreeSet::new())
                .is_none(),
            "duplicate directory inventory {relative}"
        );
        self.record_expected_entry(&entry.parent, &entry.name_text)?;
        self.refresh_directory_observation(&entry.parent, 1)?;
        self.reauthenticate_staging()
            .with_context(|| format!("created directory pathname changed for {relative}"))?;
        self.entry_count = self
            .entry_count
            .checked_add(1)
            .context("create-only entry count overflowed")?;
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one create-only file effect keeps its full precheck/write/sync/reopen order visible"
    )]
    fn create_file_inner(&mut self, relative: &str, bytes: &[u8], maximum: usize) -> Result<()> {
        self.validate_new_file(relative, bytes.len(), maximum)?;
        let expected_length =
            u64::try_from(bytes.len()).context("create-only file byte length does not fit u64")?;
        let entry = PortableRelativeEntry::parse(relative)?;
        ensure!(
            !self.directories.contains_key(relative) && !self.files.contains_key(relative),
            "create-only descendant is already occupied: {relative}"
        );
        self.ensure_retained_parent(&entry.parent)?;
        self.reauthenticate_staging()?;

        let parent_descriptor = self.directory_descriptor(&entry.parent)?;
        let descriptor = match rustix::fs::openat2(
            parent_descriptor,
            entry.name.as_os_str(),
            CREATE_FILE_FLAGS,
            PRIVATE_FILE_MODE,
            TREE_ENTRY_RESOLVE_FLAGS,
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::EXIST => {
                anyhow::bail!("create-only descendant is occupied: {relative}");
            }
            Err(error) => {
                return Err(anyhow::Error::from(error))
                    .with_context(|| format!("cannot create file {relative}"));
            }
        };
        let file = File::from(descriptor);
        let observed = prepare_private_created_file(&file, relative)?;
        ensure!(
            self.files
                .insert(
                    relative.to_owned(),
                    RetainedFile {
                        parent: entry.parent.clone(),
                        name: entry.name,
                        file,
                        observation: observed,
                        expected_sha256: None,
                    },
                )
                .is_none(),
            "duplicate retained file {relative}"
        );
        self.record_expected_entry(&entry.parent, &entry.name_text)?;
        self.refresh_directory_observation(&entry.parent, 0)?;

        self.reauthenticate_staging()
            .with_context(|| format!("created file pathname changed before write: {relative}"))?;
        self.files
            .get_mut(relative)
            .context("retained create-only file disappeared")?
            .file
            .write_all(bytes)
            .with_context(|| format!("cannot write create-only file {relative}"))?;

        let observed = file_observation(
            &self
                .files
                .get(relative)
                .context("retained create-only file disappeared")?
                .file,
        )?;
        let retained = self
            .files
            .get_mut(relative)
            .context("retained create-only file disappeared")?;
        ensure!(
            observed.identity == retained.observation.identity
                && observed.hard_link_count == retained.observation.hard_link_count
                && observed.mode == retained.observation.mode
                && observed.owner == retained.observation.owner
                && observed.group == retained.observation.group
                && observed.byte_length == expected_length,
            "create-only file identity, policy metadata, or length changed after write: {relative}"
        );
        retained.observation = observed;
        self.reauthenticate_staging()
            .with_context(|| format!("created file pathname changed before flush: {relative}"))?;
        self.files
            .get_mut(relative)
            .context("retained create-only file disappeared")?
            .file
            .flush()
            .with_context(|| format!("cannot flush create-only file {relative}"))?;

        self.reauthenticate_staging().with_context(|| {
            format!("created file pathname changed before synchronization: {relative}")
        })?;
        self.files
            .get(relative)
            .context("retained create-only file disappeared")?
            .file
            .sync_all()
            .with_context(|| format!("cannot synchronize create-only file {relative}"))?;

        let observed = file_observation(
            &self
                .files
                .get(relative)
                .context("retained create-only file disappeared")?
                .file,
        )?;
        let retained = self
            .files
            .get_mut(relative)
            .context("retained create-only file disappeared")?;
        ensure!(
            observed == retained.observation && observed.byte_length == expected_length,
            "create-only file metadata changed after write: {relative}"
        );
        retained.expected_sha256 = Some(Sha256::digest(bytes).into());
        self.reauthenticate_staging()
            .with_context(|| format!("created file pathname changed after write: {relative}"))?;
        self.entry_count = self
            .entry_count
            .checked_add(1)
            .context("create-only entry count overflowed")?;
        self.byte_length = self
            .byte_length
            .checked_add(expected_length)
            .context("create-only byte count overflowed")?;
        Ok(())
    }

    fn publish_and_adopt_directory_tree_inner<T, F>(
        &mut self,
        relative: &str,
        publish: F,
    ) -> Result<T>
    where
        F: for<'staging> FnOnce(BorrowedFd<'staging>) -> Result<T>,
    {
        self.validate_descriptor_rooted_publication_preconditions(relative)?;
        self.guard
            .recheck()
            .context("descriptor-rooted publication callback custody precheck failed")?;
        let value = publish(self.staging_root.as_fd())
            .context("descriptor-rooted publication callback failed")?;
        self.guard
            .recheck()
            .context("descriptor-rooted publication callback custody postcheck failed")?;
        self.adopt_published_directory_tree_inner(relative)
            .context("descriptor-rooted published subtree adoption failed")?;
        Ok(value)
    }

    fn validate_descriptor_rooted_publication_preconditions(&self, relative: &str) -> Result<()> {
        self.validate_new_directory(relative)?;
        ensure!(
            !relative.contains('/'),
            "descriptor-rooted publication is restricted to one projected top-level directory"
        );
        ensure!(
            self.entry_count == 0
                && self.byte_length == 0
                && self.directories.is_empty()
                && self.directory_order.is_empty()
                && self.files.is_empty()
                && self.expected_entries.len() == 1
                && self
                    .expected_entries
                    .get("")
                    .is_some_and(BTreeSet::is_empty),
            "descriptor-rooted publication must be the first create-only transaction effect"
        );
        self.reauthenticate_staging()
            .context("descriptor-rooted publication staging precheck failed")?;
        ensure!(
            directory_entries(
                self.staging_root.as_fd(),
                self.layout.reserved_staging_path(),
                MAX_CREATE_ONLY_ENTRIES,
            )?
            .is_empty(),
            "descriptor-rooted publication requires an empty retained staging root"
        );
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "descriptor-rooted adoption keeps its bounded scan and exact merge visible"
    )]
    fn adopt_published_directory_tree_inner(&mut self, relative: &str) -> Result<()> {
        self.validate_new_directory(relative)?;
        ensure!(
            !relative.contains('/'),
            "published subtree adoption is restricted to one projected top-level directory"
        );
        ensure!(
            self.entry_count == 0
                && self.directories.is_empty()
                && self.files.is_empty()
                && self
                    .expected_entries
                    .get("")
                    .is_some_and(BTreeSet::is_empty),
            "published subtree must be the first create-only transaction effect"
        );
        let entry = PortableRelativeEntry::parse(relative)?;

        let mut actual_root_entries = directory_entries(
            self.staging_root.as_fd(),
            self.layout.reserved_staging_path(),
            MAX_CREATE_ONLY_ENTRIES,
        )?;
        ensure!(
            actual_root_entries.remove(relative) && actual_root_entries.is_empty(),
            "create-only staging root contains entries outside the published subtree"
        );

        let adopted_root_observation = directory_observation(&self.staging_root)?;
        let expected_root_links = self
            .staging_observation
            .hard_link_count
            .checked_add(1)
            .context("published-tree root link-count expectation overflowed")?;
        ensure!(
            adopted_root_observation.identity == self.staging_observation.identity
                && adopted_root_observation.hard_link_count == expected_root_links
                && adopted_root_observation.mode == self.staging_observation.mode
                && adopted_root_observation.owner == self.staging_observation.owner
                && adopted_root_observation.group == self.staging_observation.group,
            "create-only staging root identity or policy changed during external publication"
        );
        self.parent
            .with_reauthenticated_descriptor(|parent_descriptor| {
                ensure_absent(
                    parent_descriptor,
                    &self.final_name,
                    self.layout.final_path(),
                    "create-only final destination",
                )?;
                let reopened = rustix::fs::openat2(
                    parent_descriptor,
                    &self.staging_name,
                    PINNED_DIRECTORY_FLAGS,
                    rustix::fs::Mode::empty(),
                    TREE_ENTRY_RESOLVE_FLAGS,
                )
                .context("published-tree staging pathname changed before adoption")?;
                ensure!(
                    directory_observation(&reopened)? == adopted_root_observation,
                    "published-tree staging pathname no longer names the retained root"
                );
                let mut entries = directory_entries(
                    reopened.as_fd(),
                    self.layout.reserved_staging_path(),
                    MAX_CREATE_ONLY_ENTRIES,
                )?;
                ensure!(
                    entries.remove(relative) && entries.is_empty(),
                    "named staging root contains entries outside the published subtree"
                );
                Ok(())
            })?;

        let descriptor = rustix::fs::openat2(
            self.staging_root.as_fd(),
            entry.name.as_os_str(),
            PINNED_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
            TREE_ENTRY_RESOLVE_FLAGS,
        )
        .with_context(|| format!("cannot retain published subtree root: {relative}"))?;
        let mut adopted = AdoptedDirectoryTree::new(adopted_root_observation.identity);
        collect_adopted_directory(
            relative,
            entry.parent,
            entry.name,
            descriptor,
            &self.layout.reserved_staging_path().join(relative),
            1,
            &mut adopted,
        )?;

        ensure!(
            adopted.entry_count <= MAX_CREATE_ONLY_ENTRIES,
            "published subtree exceeds the compiled entry bound"
        );
        ensure!(
            adopted.byte_length <= MAX_CREATE_ONLY_TOTAL_BYTES,
            "published subtree exceeds the compiled total byte bound"
        );
        self.staging_observation = adopted_root_observation;
        self.record_expected_entry("", relative)?;
        self.directories = adopted.directories;
        self.directory_order = adopted.directory_order;
        self.files = adopted.files;
        for (directory, entries) in adopted.expected_entries {
            ensure!(
                self.expected_entries.insert(directory, entries).is_none(),
                "duplicate adopted directory inventory"
            );
        }
        self.entry_count = adopted.entry_count;
        self.byte_length = adopted.byte_length;
        self.reauthenticate_staging()
            .context("adopted published subtree changed before custody transfer completed")
    }

    fn validate_new_entry(&self, relative: &str) -> Result<()> {
        validate_portable_relative_path(relative)?;
        ensure!(
            self.entry_count < MAX_CREATE_ONLY_ENTRIES,
            "create-only transaction exceeds its compiled entry bound"
        );
        ensure!(
            relative.split('/').count() <= MAX_CREATE_ONLY_DEPTH,
            "create-only descendant exceeds its compiled depth bound"
        );
        let top_level = relative
            .split('/')
            .next()
            .context("create-only relative path has no top-level component")?;
        ensure!(
            self.required_top_level_entries.contains(top_level),
            "create-only descendant is outside the projected top-level inventory: {relative}"
        );
        Ok(())
    }

    fn validate_new_directory(&self, relative: &str) -> Result<()> {
        self.validate_new_entry(relative)?;
        ensure!(
            relative.contains('/') || self.required_top_level_directories.contains(relative),
            "projected top-level file cannot be created as a directory: {relative}"
        );
        Ok(())
    }

    fn validate_new_file(&self, relative: &str, length: usize, maximum: usize) -> Result<()> {
        self.validate_new_entry(relative)?;
        ensure!(
            relative.contains('/') || !self.required_top_level_directories.contains(relative),
            "projected top-level directory cannot be created as a file: {relative}"
        );
        ensure!(
            length <= maximum,
            "{relative} exceeds its caller-supplied byte bound"
        );
        let length =
            u64::try_from(length).context("create-only file byte length does not fit u64")?;
        ensure!(
            length <= MAX_CREATE_ONLY_FILE_BYTES,
            "{relative} exceeds the compiled per-file byte bound"
        );
        let total = self
            .byte_length
            .checked_add(length)
            .context("create-only total byte length overflowed")?;
        ensure!(
            total <= MAX_CREATE_ONLY_TOTAL_BYTES,
            "create-only transaction exceeds its compiled total byte bound"
        );
        Ok(())
    }

    fn commit_inner(&mut self) -> Result<()> {
        ensure!(
            self.expected_entries
                .get("")
                .is_some_and(|entries| entries == &self.required_top_level_entries),
            "create-only root inventory does not match the projected top-level closure"
        );
        ensure!(
            self.required_top_level_directories
                .iter()
                .all(|entry| self.directories.contains_key(entry)),
            "create-only root directory kinds do not match the projected top-level closure"
        );
        ensure!(
            self.required_top_level_entries
                .difference(&self.required_top_level_directories)
                .all(|entry| self.files.contains_key(entry)),
            "create-only root file kinds do not match the projected top-level closure"
        );
        ensure!(
            self.entry_count == self.directories.len() + self.files.len(),
            "create-only retained entry accounting drifted"
        );
        let files = self.files.keys().cloned().collect::<Vec<_>>();
        for relative in files {
            self.reauthenticate_staging().with_context(|| {
                format!("create-only tree changed before final file sync: {relative}")
            })?;
            self.files
                .get(&relative)
                .context("retained create-only file disappeared")?
                .file
                .sync_all()
                .with_context(|| format!("cannot finalize file durability: {relative}"))?;
        }

        let directories = self
            .directory_order
            .iter()
            .rev()
            .cloned()
            .collect::<Vec<_>>();
        for relative in directories {
            self.reauthenticate_staging().with_context(|| {
                format!("create-only tree changed before directory sync: {relative}")
            })?;
            rustix::fs::fsync(self.directory_descriptor(&relative)?)
                .with_context(|| format!("cannot synchronize directory {relative}"))?;
        }
        self.reauthenticate_staging()
            .context("create-only tree changed before staging-root sync")?;
        rustix::fs::fsync(self.staging_root.as_fd())
            .context("cannot synchronize create-only staging root")?;

        self.reauthenticate_staging()
            .context("create-only tree changed before exclusive rename")?;
        if let Err(error) = rustix::fs::renameat_with(
            self.parent.descriptor(),
            &self.staging_name,
            self.parent.descriptor(),
            &self.final_name,
            rustix::fs::RenameFlags::NOREPLACE,
        ) {
            return Err(anyhow::Error::from(error)).with_context(|| {
                format!(
                    "create-only final destination is occupied or cannot be renamed: {}",
                    self.layout.final_path().display()
                )
            });
        }

        self.refresh_directory_observation("", 0)
            .context("renamed create-only root metadata changed unexpectedly")?;
        self.reauthenticate_final()
            .context("renamed create-only tree changed before parent synchronization")?;
        rustix::fs::fsync(self.parent.descriptor()).with_context(|| {
            format!(
                "cannot synchronize create-only parent {}",
                self.layout.parent().display()
            )
        })?;
        self.reauthenticate_final()
            .context("final create-only tree changed after parent synchronization")
    }

    fn directory_descriptor(&self, relative: &str) -> Result<BorrowedFd<'_>> {
        if relative.is_empty() {
            Ok(self.staging_root.as_fd())
        } else {
            self.directories
                .get(relative)
                .map(|directory| directory.descriptor.as_fd())
                .with_context(|| format!("retained parent directory is absent: {relative}"))
        }
    }

    fn ensure_retained_parent(&self, relative: &str) -> Result<()> {
        if relative.is_empty() || self.directories.contains_key(relative) {
            Ok(())
        } else {
            anyhow::bail!("retained parent directory is absent: {relative}");
        }
    }

    fn record_expected_entry(&mut self, parent: &str, name: &str) -> Result<()> {
        ensure!(
            self.expected_entries
                .get_mut(parent)
                .with_context(|| format!("expected parent inventory is absent: {parent}"))?
                .insert(name.to_owned()),
            "duplicate expected create-only entry {name}"
        );
        Ok(())
    }

    fn refresh_directory_observation(
        &mut self,
        relative: &str,
        expected_link_increase: u64,
    ) -> Result<()> {
        let observed = {
            let descriptor = self.directory_descriptor(relative)?;
            directory_observation(descriptor)?
        };
        if relative.is_empty() {
            let expected_links = self
                .staging_observation
                .hard_link_count
                .checked_add(expected_link_increase)
                .context("create-only root link-count expectation overflowed")?;
            ensure!(
                observed.identity == self.staging_observation.identity
                    && observed.hard_link_count == expected_links
                    && observed.mode == self.staging_observation.mode
                    && observed.owner == self.staging_observation.owner
                    && observed.group == self.staging_observation.group,
                "create-only root identity or policy metadata changed during an authorized effect"
            );
            self.staging_observation = observed;
        } else {
            let retained = self
                .directories
                .get_mut(relative)
                .with_context(|| format!("retained directory is absent: {relative}"))?;
            let expected_links = retained
                .observation
                .hard_link_count
                .checked_add(expected_link_increase)
                .context("retained directory link-count expectation overflowed")?;
            ensure!(
                observed.identity == retained.observation.identity
                    && observed.hard_link_count == expected_links
                    && observed.mode == retained.observation.mode
                    && observed.owner == retained.observation.owner
                    && observed.group == retained.observation.group,
                "retained directory identity or policy metadata changed during an authorized effect: {relative}"
            );
            retained.observation = observed;
        }
        Ok(())
    }

    fn reauthenticate_staging(&self) -> Result<()> {
        self.parent
            .with_reauthenticated_descriptor(|parent_descriptor| {
                ensure_absent(
                    parent_descriptor,
                    &self.final_name,
                    self.layout.final_path(),
                    "create-only final destination",
                )?;
                self.verify_tree_named_from(
                    parent_descriptor,
                    &self.staging_name,
                    self.layout.reserved_staging_path(),
                )
            })
            .with_context(|| {
                format!(
                    "create-only parent/descendant pathname changed or no longer names retained objects beneath {}",
                    self.layout.parent().display()
                )
            })
    }

    fn reauthenticate_final(&self) -> Result<()> {
        self.parent
            .with_reauthenticated_descriptor(|parent_descriptor| {
                ensure_absent(
                    parent_descriptor,
                    &self.staging_name,
                    self.layout.reserved_staging_path(),
                    "reserved create-only staging",
                )?;
                self.verify_tree_named_from(
                    parent_descriptor,
                    &self.final_name,
                    self.layout.final_path(),
                )
            })
            .with_context(|| {
                format!(
                    "create-only parent/descendant pathname changed or no longer names retained objects beneath {}",
                    self.layout.parent().display()
                )
            })
    }

    fn verify_tree_named_from(
        &self,
        parent_descriptor: BorrowedFd<'_>,
        root_name: &OsStr,
        diagnostic_root: &Path,
    ) -> Result<()> {
        self.verify_tree_named_once(parent_descriptor, root_name, diagnostic_root)?;
        self.verify_tree_named_once(parent_descriptor, root_name, diagnostic_root)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the complete retained-versus-named inventory comparison is one audit unit"
    )]
    fn verify_tree_named_once(
        &self,
        parent_descriptor: BorrowedFd<'_>,
        root_name: &OsStr,
        diagnostic_root: &Path,
    ) -> Result<()> {
        ensure!(
            directory_observation(&self.staging_root)? == self.staging_observation,
            "retained create-only root metadata changed"
        );
        for (relative, retained) in &self.directories {
            ensure!(
                directory_observation(&retained.descriptor)? == retained.observation,
                "retained directory metadata changed for {relative}"
            );
        }
        for (relative, retained) in &self.files {
            let observed = file_observation(&retained.file)?;
            ensure!(
                observed == retained.observation,
                "retained file metadata changed for {relative}"
            );
            if let Some(expected_sha256) = retained.expected_sha256 {
                let measured = read_stable_sha256(&retained.file, retained.observation)
                    .with_context(|| format!("cannot remeasure retained file handle {relative}"))?;
                ensure!(
                    measured == expected_sha256,
                    "retained file-handle bytes changed for {relative}"
                );
            }
        }

        let reopened_root = rustix::fs::openat2(
            parent_descriptor,
            root_name,
            PINNED_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
            TREE_ENTRY_RESOLVE_FLAGS,
        )
        .with_context(|| {
            format!(
                "create-only root pathname changed: {}",
                diagnostic_root.display()
            )
        })?;
        ensure!(
            directory_observation(&reopened_root)? == self.staging_observation,
            "create-only root pathname changed metadata"
        );

        let mut reopened_directories = BTreeMap::new();
        for relative in &self.directory_order {
            let retained = self
                .directories
                .get(relative)
                .context("retained directory order drift")?;
            let parent = fresh_directory_descriptor(
                &reopened_root,
                &reopened_directories,
                &retained.parent,
            )?;
            let reopened = rustix::fs::openat2(
                parent,
                retained.name.as_os_str(),
                PINNED_DIRECTORY_FLAGS,
                rustix::fs::Mode::empty(),
                TREE_ENTRY_RESOLVE_FLAGS,
            )
            .with_context(|| format!("retained descendant pathname changed for {relative}"))?;
            ensure!(
                directory_observation(&reopened)? == retained.observation,
                "retained descendant pathname changed metadata for {relative}"
            );
            ensure!(
                reopened_directories
                    .insert(relative.clone(), reopened)
                    .is_none(),
                "duplicate reopened create-only directory {relative}"
            );
        }

        for (relative, expected) in &self.expected_entries {
            let descriptor =
                fresh_directory_descriptor(&reopened_root, &reopened_directories, relative)?;
            let observed = directory_entries(
                descriptor,
                &if relative.is_empty() {
                    diagnostic_root.to_path_buf()
                } else {
                    diagnostic_root.join(relative)
                },
                MAX_CREATE_ONLY_ENTRIES,
            )?;
            ensure!(
                observed == *expected,
                "create-only directory inventory changed for {relative}"
            );
        }

        for (relative, retained) in &self.files {
            let parent = fresh_directory_descriptor(
                &reopened_root,
                &reopened_directories,
                &retained.parent,
            )?;
            let descriptor = rustix::fs::openat2(
                parent,
                retained.name.as_os_str(),
                PINNED_FILE_FLAGS,
                rustix::fs::Mode::empty(),
                TREE_ENTRY_RESOLVE_FLAGS,
            )
            .with_context(|| format!("retained file pathname changed for {relative}"))?;
            let reopened = File::from(descriptor);
            let observed = file_observation(&reopened)?;
            ensure!(
                observed == retained.observation,
                "retained file pathname changed metadata for {relative}"
            );
            if let Some(expected_sha256) = retained.expected_sha256 {
                let measured = read_stable_sha256(&reopened, retained.observation)
                    .with_context(|| format!("cannot remeasure retained file {relative}"))?;
                ensure!(
                    measured == expected_sha256,
                    "retained file bytes changed for {relative}"
                );
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn validate_required_top_level_inventory(
    entries: &[String],
    directories: &[String],
) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    ensure!(
        !entries.is_empty() && entries.len() <= MAX_CREATE_ONLY_ENTRIES,
        "create-only required top-level inventory is outside its compiled bound"
    );
    let mut required = BTreeSet::new();
    for entry in entries {
        validate_portable_relative_path(entry)?;
        ensure!(
            !entry.contains('/') && required.insert(entry.clone()),
            "create-only required top-level inventory is invalid or duplicated"
        );
    }
    let mut required_directories = BTreeSet::new();
    for entry in directories {
        ensure!(
            required.contains(entry) && required_directories.insert(entry.clone()),
            "create-only required directory inventory is invalid or duplicated"
        );
    }
    Ok((required, required_directories))
}

#[cfg(target_os = "linux")]
fn finish_guarded_outcome<T>(outcome: Result<T>, postcheck: Result<()>, label: &str) -> Result<T> {
    match (outcome, postcheck) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(postcheck)) => Err(postcheck).context(format!(
            "{label} completed but its custody postcheck failed"
        )),
        (Err(effect), Err(postcheck)) => Err(postcheck).context(format!(
            "{label} failed ({effect:#}) and its custody postcheck also failed"
        )),
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    mount_id: u64,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Eq, PartialEq)]
struct DirectoryObservation {
    identity: DirectoryIdentity,
    hard_link_count: u64,
    mode: u32,
    owner: u64,
    group: u64,
    modified_seconds: i64,
    modified_nanoseconds: u64,
    changed_seconds: i64,
    changed_nanoseconds: u64,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    mount_id: u64,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Eq, PartialEq)]
struct FileObservation {
    identity: FileIdentity,
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

#[cfg(target_os = "linux")]
struct RetainedDirectory {
    parent: String,
    name: OsString,
    descriptor: OwnedFd,
    observation: DirectoryObservation,
}

#[cfg(target_os = "linux")]
struct RetainedFile {
    parent: String,
    name: OsString,
    file: File,
    observation: FileObservation,
    expected_sha256: Option<[u8; 32]>,
}

#[cfg(target_os = "linux")]
struct AdoptedDirectoryTree {
    root_identity: DirectoryIdentity,
    directory_identities: Vec<DirectoryIdentity>,
    directories: BTreeMap<String, RetainedDirectory>,
    directory_order: Vec<String>,
    files: BTreeMap<String, RetainedFile>,
    expected_entries: BTreeMap<String, BTreeSet<String>>,
    entry_count: usize,
    byte_length: u64,
}

#[cfg(target_os = "linux")]
impl AdoptedDirectoryTree {
    fn new(root_identity: DirectoryIdentity) -> Self {
        Self {
            root_identity,
            directory_identities: vec![root_identity],
            directories: BTreeMap::new(),
            directory_order: Vec::new(),
            files: BTreeMap::new(),
            expected_entries: BTreeMap::new(),
            entry_count: 0,
            byte_length: 0,
        }
    }

    fn retain_entry(&mut self) -> Result<()> {
        self.entry_count = self
            .entry_count
            .checked_add(1)
            .context("published-tree entry count overflowed")?;
        ensure!(
            self.entry_count <= MAX_CREATE_ONLY_ENTRIES,
            "published subtree exceeds the compiled entry bound"
        );
        Ok(())
    }

    fn retain_file_bytes(&mut self, length: u64) -> Result<()> {
        ensure!(
            length <= MAX_CREATE_ONLY_FILE_BYTES,
            "published subtree file exceeds the compiled per-file byte bound"
        );
        self.byte_length = self
            .byte_length
            .checked_add(length)
            .context("published-tree byte count overflowed")?;
        ensure!(
            self.byte_length <= MAX_CREATE_ONLY_TOTAL_BYTES,
            "published subtree exceeds the compiled total byte bound"
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[allow(
    clippy::too_many_arguments,
    reason = "the bounded adopted-tree walk carries explicit retained path and budget state"
)]
#[allow(
    clippy::too_many_lines,
    reason = "the descriptor-open, policy, digest and repeated-stat sequence is one audit unit"
)]
fn collect_adopted_directory(
    relative: &str,
    parent: String,
    name: OsString,
    descriptor: OwnedFd,
    diagnostic: &Path,
    depth: usize,
    adopted: &mut AdoptedDirectoryTree,
) -> Result<()> {
    ensure!(
        depth <= MAX_CREATE_ONLY_DEPTH,
        "published subtree exceeds the compiled directory-depth bound"
    );
    validate_portable_relative_path(relative)?;
    let observation = directory_observation(&descriptor)?;
    validate_adopted_directory_policy(observation, adopted.root_identity.mount_id, relative)?;
    ensure!(
        !adopted.directory_identities.contains(&observation.identity),
        "published subtree contains a physical directory alias: {relative}"
    );
    adopted
        .directory_identities
        .try_reserve(1)
        .context("cannot retain bounded published-tree directory identity")?;
    adopted.directory_identities.push(observation.identity);
    adopted.retain_entry()?;
    adopted
        .directory_order
        .try_reserve(1)
        .context("cannot retain bounded published-tree directory order")?;
    adopted.directory_order.push(relative.to_owned());

    let names = directory_entries(descriptor.as_fd(), diagnostic, MAX_CREATE_ONLY_ENTRIES)?;
    ensure!(
        adopted
            .expected_entries
            .insert(relative.to_owned(), names.clone())
            .is_none(),
        "published subtree directory appeared twice: {relative}"
    );

    let mut immediate_directory_count = 0_u64;
    for child_name in names {
        let child_relative = format!("{relative}/{child_name}");
        validate_portable_relative_path(&child_relative)?;
        ensure!(
            child_relative.split('/').count() <= MAX_CREATE_ONLY_DEPTH,
            "published subtree descendant exceeds the compiled depth bound"
        );
        let child_diagnostic = diagnostic.join(&child_name);
        let before = rustix::fs::statat(
            descriptor.as_fd(),
            child_name.as_str(),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .with_context(|| format!("cannot inspect published subtree entry: {child_relative}"))?;
        let file_type = rustix::fs::FileType::from_raw_mode(before.st_mode);
        if file_type.is_dir() {
            immediate_directory_count = immediate_directory_count
                .checked_add(1)
                .context("published-tree immediate directory count overflowed")?;
            let child = rustix::fs::openat2(
                descriptor.as_fd(),
                child_name.as_str(),
                PINNED_DIRECTORY_FLAGS,
                rustix::fs::Mode::empty(),
                TREE_ENTRY_RESOLVE_FLAGS,
            )
            .with_context(|| {
                format!("cannot retain published subtree directory: {child_relative}")
            })?;
            let child_observation = directory_observation(&child)?;
            ensure!(
                named_stat_matches_directory(&before, child_observation)?,
                "published subtree directory changed while being retained: {child_relative}"
            );
            collect_adopted_directory(
                &child_relative,
                relative.to_owned(),
                OsString::from(&child_name),
                child,
                &child_diagnostic,
                depth + 1,
                adopted,
            )?;
        } else if file_type.is_file() {
            let child = rustix::fs::openat2(
                descriptor.as_fd(),
                child_name.as_str(),
                PINNED_FILE_FLAGS,
                rustix::fs::Mode::empty(),
                TREE_ENTRY_RESOLVE_FLAGS,
            )
            .with_context(|| format!("cannot retain published subtree file: {child_relative}"))?;
            let file = File::from(child);
            let file_observation = file_observation(&file)?;
            validate_adopted_file_policy(
                file_observation,
                adopted.root_identity.mount_id,
                &child_relative,
            )?;
            ensure!(
                named_stat_matches_file(&before, file_observation)?,
                "published subtree file changed while being retained: {child_relative}"
            );
            adopted.retain_entry()?;
            adopted.retain_file_bytes(file_observation.byte_length)?;
            let expected_sha256 = read_stable_sha256(&file, file_observation)
                .with_context(|| format!("cannot seal published subtree file: {child_relative}"))?;
            ensure!(
                adopted
                    .files
                    .insert(
                        child_relative.clone(),
                        RetainedFile {
                            parent: relative.to_owned(),
                            name: OsString::from(&child_name),
                            file,
                            observation: file_observation,
                            expected_sha256: Some(expected_sha256),
                        },
                    )
                    .is_none(),
                "published subtree file appeared twice: {child_relative}"
            );
        } else {
            anyhow::bail!("published subtree contains a symlink or special file: {child_relative}");
        }
        let repeated = rustix::fs::statat(
            descriptor.as_fd(),
            child_name.as_str(),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .with_context(|| format!("cannot repeat published entry inspection: {child_relative}"))?;
        ensure!(
            named_stats_equal(&before, &repeated),
            "published subtree entry changed while being retained: {child_relative}"
        );
    }
    require_closed_directory_link_count(observation, immediate_directory_count, relative)?;
    ensure!(
        directory_observation(&descriptor)? == observation,
        "published subtree directory changed while being enumerated: {relative}"
    );
    ensure!(
        adopted
            .directories
            .insert(
                relative.to_owned(),
                RetainedDirectory {
                    parent,
                    name,
                    descriptor,
                    observation,
                },
            )
            .is_none(),
        "published subtree directory appeared twice: {relative}"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_adopted_directory_policy(
    observation: DirectoryObservation,
    root_mount_id: u64,
    relative: &str,
) -> Result<()> {
    ensure!(
        observation.identity.mount_id == root_mount_id,
        "published subtree crosses a mount boundary: {relative}"
    );
    ensure!(
        observation.owner == u64::from(rustix::process::geteuid().as_raw()),
        "published subtree directory has an unexpected owner: {relative}"
    );
    ensure!(
        observation.mode & PERMISSION_AND_SPECIAL_BITS == PRIVATE_DIRECTORY_MODE.bits(),
        "published subtree directory lacks exact owner-only permissions: {relative}"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_adopted_file_policy(
    observation: FileObservation,
    root_mount_id: u64,
    relative: &str,
) -> Result<()> {
    ensure!(
        observation.identity.mount_id == root_mount_id,
        "published subtree file crosses a mount boundary: {relative}"
    );
    ensure!(
        observation.owner == u64::from(rustix::process::geteuid().as_raw()),
        "published subtree file has an unexpected owner: {relative}"
    );
    ensure!(
        observation.mode & PERMISSION_AND_SPECIAL_BITS == PRIVATE_FILE_MODE.bits(),
        "published subtree file lacks exact owner-only permissions: {relative}"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_closed_directory_link_count(
    observation: DirectoryObservation,
    immediate_directory_count: u64,
    relative: &str,
) -> Result<()> {
    let expected = immediate_directory_count
        .checked_add(2)
        .context("published-tree directory link-count expectation overflowed")?;
    ensure!(
        observation.hard_link_count == expected,
        "published subtree directory has an external physical alias: {relative}"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn named_stat_matches_directory(
    stat: &rustix::fs::Stat,
    observation: DirectoryObservation,
) -> Result<bool> {
    Ok(
        checked_identity_component(stat.st_dev, "directory device does not fit u64")?
            == observation.identity.device
            && checked_identity_component(stat.st_ino, "directory inode does not fit u64")?
                == observation.identity.inode
            && checked_identity_component(stat.st_nlink, "directory links do not fit u64")?
                == observation.hard_link_count
            && stat.st_mode == observation.mode
            && checked_identity_component(stat.st_uid, "directory owner does not fit u64")?
                == observation.owner
            && checked_identity_component(stat.st_gid, "directory group does not fit u64")?
                == observation.group
            && stat.st_mtime == observation.modified_seconds
            && stat.st_mtime_nsec == observation.modified_nanoseconds
            && stat.st_ctime == observation.changed_seconds
            && stat.st_ctime_nsec == observation.changed_nanoseconds,
    )
}

#[cfg(target_os = "linux")]
fn named_stat_matches_file(stat: &rustix::fs::Stat, observation: FileObservation) -> Result<bool> {
    Ok(
        checked_identity_component(stat.st_dev, "file device does not fit u64")?
            == observation.identity.device
            && checked_identity_component(stat.st_ino, "file inode does not fit u64")?
                == observation.identity.inode
            && checked_identity_component(stat.st_nlink, "file links do not fit u64")?
                == observation.hard_link_count
            && checked_identity_component(stat.st_size, "file length does not fit u64")?
                == observation.byte_length
            && stat.st_mode == observation.mode
            && checked_identity_component(stat.st_uid, "file owner does not fit u64")?
                == observation.owner
            && checked_identity_component(stat.st_gid, "file group does not fit u64")?
                == observation.group
            && stat.st_mtime == observation.modified_seconds
            && stat.st_mtime_nsec == observation.modified_nanoseconds
            && stat.st_ctime == observation.changed_seconds
            && stat.st_ctime_nsec == observation.changed_nanoseconds,
    )
}

#[cfg(target_os = "linux")]
fn named_stats_equal(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_mode == right.st_mode
        && left.st_nlink == right.st_nlink
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}

#[cfg(target_os = "linux")]
struct PortableRelativeEntry {
    parent: String,
    name: OsString,
    name_text: String,
}

#[cfg(target_os = "linux")]
impl PortableRelativeEntry {
    fn parse(relative: &str) -> Result<Self> {
        validate_portable_relative_path(relative)?;
        let (parent, name) = relative
            .rsplit_once('/')
            .map_or(("", relative), |(parent, name)| (parent, name));
        Ok(Self {
            parent: parent.to_owned(),
            name: OsString::from(name),
            name_text: name.to_owned(),
        })
    }
}

#[cfg(target_os = "linux")]
struct PreflightedCreateOnlyParent {
    parent: PinnedAbsoluteDirectoryPath,
    final_name: OsString,
    staging_name: OsString,
}

#[cfg(target_os = "linux")]
fn pin_and_preflight_create_only_parent(
    layout: &CreateOnlyDirectoryLayout,
    authenticate_parent: impl FnOnce(&[(u64, u64, u64)]) -> Result<()>,
    atomic_probe: impl FnOnce(BorrowedFd<'_>) -> Result<bool>,
) -> Result<PreflightedCreateOnlyParent> {
    let final_name = layout
        .final_path()
        .file_name()
        .context("create-only final path has no basename")?
        .to_os_string();
    let staging_name = layout
        .reserved_staging_path()
        .file_name()
        .context("create-only staging path has no basename")?
        .to_os_string();
    let parent = PinnedAbsoluteDirectoryPath::open(layout.parent())
        .context("cannot pin create-only parent")?;
    authenticate_parent(&parent.component_identity_triples())?;
    parent.with_reauthenticated_descriptor(|parent_descriptor| {
        ensure!(
            atomic_probe(parent_descriptor)?,
            "{} does not support atomic no-replace publication",
            layout.parent().display()
        );
        ensure_absent(
            parent_descriptor,
            &final_name,
            layout.final_path(),
            "create-only final destination",
        )?;
        ensure_absent(
            parent_descriptor,
            &staging_name,
            layout.reserved_staging_path(),
            "reserved create-only staging",
        )
    })?;
    parent.reauthenticate()?;
    Ok(PreflightedCreateOnlyParent {
        parent,
        final_name,
        staging_name,
    })
}

#[cfg(target_os = "linux")]
fn probe_atomic_no_replace(parent: BorrowedFd<'_>) -> Result<bool> {
    let diagnostic = PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd())).join(".");
    if renamore::rename_exclusive_is_atomic(&diagnostic).with_context(|| {
        format!(
            "cannot establish atomic no-replace support for retained parent {}",
            diagnostic.display()
        )
    })? {
        return Ok(true);
    }

    match rustix::fs::renameat_with(parent, ".", parent, ".", rustix::fs::RenameFlags::NOREPLACE) {
        Err(error) if error == rustix::io::Errno::BUSY || error == rustix::io::Errno::EXIST => {
            Ok(true)
        }
        Err(error) if error == rustix::io::Errno::INVAL || error == rustix::io::Errno::NOTSUP => {
            Ok(false)
        }
        Err(error) => Err(anyhow::Error::from(error)).with_context(|| {
            format!(
                "cannot probe atomic no-replace support for retained parent {}",
                diagnostic.display()
            )
        }),
        Ok(()) => anyhow::bail!(
            "atomic no-replace capability probe unexpectedly renamed the retained parent"
        ),
    }
}

#[cfg(target_os = "linux")]
struct PinnedAbsoluteDirectoryPath {
    anchor: OwnedFd,
    anchor_identity: DirectoryIdentity,
    components: Vec<OsString>,
    descriptors: Vec<OwnedFd>,
    identities: Vec<DirectoryIdentity>,
    diagnostic: PathBuf,
}

#[cfg(target_os = "linux")]
impl PinnedAbsoluteDirectoryPath {
    fn open(path: &Path) -> Result<Self> {
        ensure!(path.is_absolute(), "pinned directory path must be absolute");
        ensure!(
            path.as_os_str().as_bytes().len() <= MAX_ABSOLUTE_PATH_BYTES,
            "pinned directory path exceeds its compiled byte bound"
        );
        let anchor = rustix::fs::open(
            Path::new("/"),
            PINNED_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
        )
        .context("cannot open filesystem root anchor")?;
        let anchor_identity = directory_identity(&anchor)?;
        let mut components = Vec::new();
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    ensure!(
                        components.len() < MAX_ABSOLUTE_PATH_COMPONENTS,
                        "pinned directory path exceeds its compiled component bound"
                    );
                    components
                        .try_reserve(1)
                        .context("cannot retain bounded parent-path component")?;
                    components.push(name.to_os_string());
                }
                Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                    anyhow::bail!("pinned directory path is not normalized absolute");
                }
            }
        }

        let mut descriptors: Vec<OwnedFd> = Vec::new();
        let mut identities = Vec::new();
        descriptors
            .try_reserve_exact(components.len())
            .context("cannot retain parent component descriptors")?;
        identities
            .try_reserve_exact(components.len())
            .context("cannot retain parent component identities")?;
        for (index, component) in components.iter().enumerate() {
            let parent = descriptors
                .last()
                .map_or_else(|| anchor.as_fd(), OwnedFd::as_fd);
            let descriptor = rustix::fs::openat2(
                parent,
                component.as_os_str(),
                PINNED_DIRECTORY_FLAGS,
                rustix::fs::Mode::empty(),
                PATH_COMPONENT_RESOLVE_FLAGS,
            )
            .with_context(|| {
                format!(
                    "cannot pin parent component {index} beneath {}",
                    path.display()
                )
            })?;
            identities.push(directory_identity(&descriptor)?);
            descriptors.push(descriptor);
        }
        Ok(Self {
            anchor,
            anchor_identity,
            components,
            descriptors,
            identities,
            diagnostic: path.to_path_buf(),
        })
    }

    fn descriptor(&self) -> BorrowedFd<'_> {
        self.descriptors
            .last()
            .map_or_else(|| self.anchor.as_fd(), OwnedFd::as_fd)
    }

    fn component_identity_triples(&self) -> Vec<(u64, u64, u64)> {
        self.identities
            .iter()
            .map(|identity| (identity.device, identity.inode, identity.mount_id))
            .collect()
    }

    fn reauthenticate(&self) -> Result<()> {
        self.with_reauthenticated_descriptor(|_descriptor| Ok(()))
    }

    fn with_reauthenticated_descriptor<T>(
        &self,
        use_descriptor: impl FnOnce(BorrowedFd<'_>) -> Result<T>,
    ) -> Result<T> {
        ensure!(
            directory_identity(&self.anchor)? == self.anchor_identity,
            "retained filesystem anchor identity changed"
        );
        for (index, (descriptor, identity)) in
            self.descriptors.iter().zip(&self.identities).enumerate()
        {
            ensure!(
                directory_identity(descriptor)? == *identity,
                "retained parent component {index} identity changed"
            );
        }

        let reopened_anchor = rustix::fs::openat2(
            self.anchor.as_fd(),
            ".",
            PINNED_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
            PATH_COMPONENT_RESOLVE_FLAGS,
        )
        .with_context(|| {
            format!(
                "parent pathname {} no longer names the retained anchor",
                self.diagnostic.display()
            )
        })?;
        ensure!(
            directory_identity(&reopened_anchor)? == self.anchor_identity,
            "parent pathname no longer names the retained anchor"
        );
        let mut reopened: Vec<OwnedFd> = Vec::new();
        reopened
            .try_reserve_exact(self.components.len())
            .context("cannot retain reauthenticated parent chain")?;
        for (index, (component, identity)) in
            self.components.iter().zip(&self.identities).enumerate()
        {
            let parent = reopened
                .last()
                .map_or_else(|| reopened_anchor.as_fd(), OwnedFd::as_fd);
            let descriptor = rustix::fs::openat2(
                parent,
                component.as_os_str(),
                PINNED_DIRECTORY_FLAGS,
                rustix::fs::Mode::empty(),
                PATH_COMPONENT_RESOLVE_FLAGS,
            )
            .with_context(|| {
                format!(
                    "parent pathname {} no longer names retained component {index}",
                    self.diagnostic.display()
                )
            })?;
            ensure!(
                directory_identity(&descriptor)? == *identity,
                "parent pathname no longer names retained component {index}"
            );
            reopened.push(descriptor);
        }
        let descriptor = reopened
            .last()
            .map_or_else(|| reopened_anchor.as_fd(), OwnedFd::as_fd);
        use_descriptor(descriptor)
    }
}

#[cfg(target_os = "linux")]
fn validate_portable_relative_path(path: &str) -> Result<()> {
    ensure!(
        (1..=MAX_PORTABLE_RELATIVE_PATH_BYTES).contains(&path.len()),
        "create-only relative path is outside its byte bound"
    );
    ensure!(
        path.is_ascii(),
        "create-only relative path must use portable ASCII"
    );
    ensure!(
        path.as_bytes()[0].is_ascii_lowercase() || path.as_bytes()[0].is_ascii_digit(),
        "create-only relative path must start with lowercase ASCII or a digit"
    );
    ensure!(
        path.as_bytes().iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-' | b'/')
        }),
        "create-only relative path contains a non-portable character"
    );
    ensure!(
        !path.ends_with('/') && !path.contains("//"),
        "create-only relative path has a non-canonical separator"
    );
    for component in path.split('/') {
        ensure!(
            !component.is_empty()
                && component != "."
                && component != ".."
                && !component.ends_with('.'),
            "create-only relative path has a non-portable component"
        );
        ensure!(
            component.as_bytes()[0].is_ascii_lowercase()
                || component.as_bytes()[0].is_ascii_digit(),
            "create-only relative component has a non-portable first byte"
        );
        let device_stem = component.split('.').next().unwrap_or(component);
        ensure!(
            !is_windows_device_name(device_stem),
            "create-only relative path contains a reserved device component"
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_windows_device_name(value: &str) -> bool {
    matches!(value, "con" | "prn" | "aux" | "nul" | "conin$" | "conout$")
        || value
            .strip_prefix("com")
            .or_else(|| value.strip_prefix("lpt"))
            .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'))
}

#[cfg(target_os = "linux")]
fn ensure_absent(
    descriptor: BorrowedFd<'_>,
    name: &OsStr,
    diagnostic: &Path,
    label: &str,
) -> Result<()> {
    match rustix::fs::statat(descriptor, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(error) => Err(anyhow::Error::from(error))
            .with_context(|| format!("cannot inspect {label} {}", diagnostic.display())),
        Ok(_) => anyhow::bail!("{label} is occupied: {}", diagnostic.display()),
    }
}

#[cfg(target_os = "linux")]
fn directory_identity(descriptor: impl std::os::fd::AsFd) -> Result<DirectoryIdentity> {
    Ok(directory_observation(descriptor)?.identity)
}

#[cfg(target_os = "linux")]
fn directory_observation(descriptor: impl std::os::fd::AsFd) -> Result<DirectoryObservation> {
    let descriptor = descriptor.as_fd();
    let stat = rustix::fs::fstat(descriptor).context("cannot inspect retained directory")?;
    ensure!(
        rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir(),
        "retained descriptor is not an ordinary directory"
    );
    Ok(DirectoryObservation {
        identity: DirectoryIdentity {
            device: checked_identity_component(
                stat.st_dev,
                "directory device identity does not fit u64",
            )?,
            inode: checked_identity_component(
                stat.st_ino,
                "directory inode identity does not fit u64",
            )?,
            mount_id: descriptor_mount_id(descriptor)?,
        },
        hard_link_count: checked_identity_component(
            stat.st_nlink,
            "directory link count does not fit u64",
        )?,
        mode: stat.st_mode,
        owner: checked_identity_component(
            stat.st_uid,
            "directory owner identity does not fit u64",
        )?,
        group: checked_identity_component(
            stat.st_gid,
            "directory group identity does not fit u64",
        )?,
        modified_seconds: stat.st_mtime,
        modified_nanoseconds: stat.st_mtime_nsec,
        changed_seconds: stat.st_ctime,
        changed_nanoseconds: stat.st_ctime_nsec,
    })
}

#[cfg(target_os = "linux")]
fn prepare_private_created_directory(
    descriptor: impl std::os::fd::AsFd,
    diagnostic: &Path,
) -> Result<DirectoryObservation> {
    let descriptor = descriptor.as_fd();
    rustix::fs::fchmod(descriptor, PRIVATE_DIRECTORY_MODE)
        .with_context(|| format!("cannot seal private directory {}", diagnostic.display()))?;
    let observed = directory_observation(descriptor)?;
    ensure!(
        observed.owner == u64::from(rustix::process::geteuid().as_raw()),
        "created private directory has an unexpected owner: {}",
        diagnostic.display()
    );
    ensure!(
        observed.mode & PERMISSION_AND_SPECIAL_BITS == PRIVATE_DIRECTORY_MODE.bits(),
        "created private directory does not have exact owner-only permissions: {}",
        diagnostic.display()
    );
    ensure!(
        directory_entries(descriptor, diagnostic, MAX_CREATE_ONLY_ENTRIES)?.is_empty(),
        "created private directory was not empty when retained: {}",
        diagnostic.display()
    );
    Ok(observed)
}

#[cfg(target_os = "linux")]
fn file_observation(file: &File) -> Result<FileObservation> {
    let stat = rustix::fs::fstat(file).context("cannot inspect retained file")?;
    ensure!(
        rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file(),
        "retained descriptor is not an ordinary regular file"
    );
    let hard_link_count =
        checked_identity_component(stat.st_nlink, "file link count does not fit u64")?;
    ensure!(
        hard_link_count == 1,
        "retained create-only file must have exactly one hard link"
    );
    Ok(FileObservation {
        identity: FileIdentity {
            device: checked_identity_component(
                stat.st_dev,
                "file device identity does not fit u64",
            )?,
            inode: checked_identity_component(stat.st_ino, "file inode identity does not fit u64")?,
            mount_id: descriptor_mount_id(file.as_fd())?,
        },
        byte_length: checked_identity_component(stat.st_size, "file byte length does not fit u64")?,
        hard_link_count,
        mode: stat.st_mode,
        owner: checked_identity_component(stat.st_uid, "file owner identity does not fit u64")?,
        group: checked_identity_component(stat.st_gid, "file group identity does not fit u64")?,
        modified_seconds: stat.st_mtime,
        modified_nanoseconds: stat.st_mtime_nsec,
        changed_seconds: stat.st_ctime,
        changed_nanoseconds: stat.st_ctime_nsec,
    })
}

#[cfg(target_os = "linux")]
fn prepare_private_created_file(file: &File, relative: &str) -> Result<FileObservation> {
    rustix::fs::fchmod(file, PRIVATE_FILE_MODE)
        .with_context(|| format!("cannot seal private create-only file {relative}"))?;
    let observed = file_observation(file)?;
    ensure!(
        observed.owner == u64::from(rustix::process::geteuid().as_raw()),
        "new create-only file has an unexpected owner: {relative}"
    );
    ensure!(
        observed.mode & PERMISSION_AND_SPECIAL_BITS == PRIVATE_FILE_MODE.bits(),
        "new create-only file does not have exact owner-only permissions: {relative}"
    );
    ensure!(
        observed.byte_length == 0,
        "new create-only file was not empty: {relative}"
    );
    Ok(observed)
}

#[cfg(target_os = "linux")]
fn descriptor_mount_id(descriptor: BorrowedFd<'_>) -> Result<u64> {
    let statx = rustix::fs::statx(
        descriptor,
        "",
        rustix::fs::AtFlags::EMPTY_PATH,
        rustix::fs::StatxFlags::BASIC_STATS | rustix::fs::StatxFlags::MNT_ID,
    )
    .context("cannot obtain retained create-only mount identity")?;
    ensure!(
        rustix::fs::StatxFlags::from_bits_retain(statx.stx_mask)
            .contains(rustix::fs::StatxFlags::MNT_ID),
        "Linux statx did not return a create-only mount identity"
    );
    Ok(statx.stx_mnt_id)
}

#[cfg(target_os = "linux")]
fn read_stable_sha256(file: &File, expected: FileObservation) -> Result<[u8; 32]> {
    let before = file_observation(file)?;
    ensure!(
        before == expected,
        "retained file metadata changed before remeasurement"
    );
    let read_limit = expected
        .byte_length
        .checked_add(1)
        .context("retained file read bound overflows u64")?;
    let mut remaining = read_limit;
    let mut measured_length = 0_u64;
    let mut buffer = [0_u8; 8192];
    let mut digest = Sha256::new();
    while remaining != 0 {
        let limit = usize::try_from(remaining.min(u64::try_from(buffer.len())?))?;
        let read = file
            .read_at(&mut buffer[..limit], measured_length)
            .context("cannot read retained create-only file")?;
        if read == 0 {
            break;
        }
        let read_u64 = u64::try_from(read)?;
        measured_length = measured_length
            .checked_add(read_u64)
            .context("retained file measured length overflow")?;
        remaining -= read_u64;
        digest.update(&buffer[..read]);
    }
    ensure!(
        measured_length == expected.byte_length,
        "retained file changed size during remeasurement"
    );
    let after = file_observation(file)?;
    ensure!(
        before == after && after == expected,
        "retained file metadata changed during remeasurement"
    );
    Ok(digest.finalize().into())
}

#[cfg(target_os = "linux")]
fn read_stable_bytes(file: &File, expected: FileObservation, maximum: usize) -> Result<Vec<u8>> {
    let before = file_observation(file)?;
    ensure!(
        before == expected,
        "retained file metadata changed before bounded read"
    );
    let expected_length =
        usize::try_from(expected.byte_length).context("retained file length does not fit usize")?;
    ensure!(
        expected_length <= maximum,
        "retained file exceeds its caller-supplied byte bound"
    );
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected_length)
        .context("cannot allocate bounded retained-file buffer")?;
    bytes.resize(expected_length, 0);
    let mut offset = 0_usize;
    while offset < expected_length {
        let read = file
            .read_at(
                &mut bytes[offset..],
                u64::try_from(offset).context("retained-file offset does not fit u64")?,
            )
            .context("cannot read retained create-only file")?;
        ensure!(read != 0, "retained file ended before its sealed length");
        offset = offset
            .checked_add(read)
            .context("retained-file read offset overflowed")?;
    }
    let mut extra = [0_u8; 1];
    ensure!(
        file.read_at(&mut extra, expected.byte_length)
            .context("cannot verify retained-file end")?
            == 0,
        "retained file grew beyond its sealed length"
    );
    let after = file_observation(file)?;
    ensure!(
        before == after && after == expected,
        "retained file metadata changed during bounded read"
    );
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn checked_identity_component<T>(value: T, error: &'static str) -> Result<u64>
where
    u64: TryFrom<T>,
{
    u64::try_from(value).map_err(|_| anyhow::Error::msg(error))
}

#[cfg(target_os = "linux")]
fn fresh_directory_descriptor<'a>(
    root: &'a OwnedFd,
    directories: &'a BTreeMap<String, OwnedFd>,
    relative: &str,
) -> Result<BorrowedFd<'a>> {
    if relative.is_empty() {
        Ok(root.as_fd())
    } else {
        directories
            .get(relative)
            .map(OwnedFd::as_fd)
            .with_context(|| format!("reopened parent directory is absent: {relative}"))
    }
}

#[cfg(target_os = "linux")]
fn directory_entries(
    descriptor: BorrowedFd<'_>,
    diagnostic: &Path,
    maximum: usize,
) -> Result<BTreeSet<String>> {
    let mut directory = rustix::fs::Dir::read_from(descriptor)
        .with_context(|| format!("cannot enumerate {}", diagnostic.display()))?;
    let mut entries = BTreeSet::new();
    for entry in &mut directory {
        let entry =
            entry.with_context(|| format!("cannot read an entry in {}", diagnostic.display()))?;
        let name = entry.file_name().to_str().with_context(|| {
            format!(
                "non-portable entry appeared in create-only directory {}",
                diagnostic.display()
            )
        })?;
        if matches!(name, "." | "..") {
            continue;
        }
        ensure!(
            entries.len() < maximum,
            "create-only directory exceeds its compiled inventory bound: {}",
            diagnostic.display()
        );
        ensure!(
            entries.insert(name.to_owned()),
            "duplicate directory entry appeared in {}",
            diagnostic.display()
        );
    }
    Ok(entries)
}

/// Non-Linux stub which cannot inspect or mutate a supplied layout.
#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub(super) struct CreateOnlyDirectoryTransaction<'capability> {
    capability_borrow: PhantomData<&'capability mut ()>,
}

/// Non-Linux committed typestate stub; no value can be minted on this platform.
#[cfg(not(target_os = "linux"))]
#[must_use = "the committed tree must be reopened and validated before authority is retained"]
pub(super) struct CommittedCreateOnlyDirectoryTransaction<'capability> {
    transaction: CreateOnlyDirectoryTransaction<'capability>,
}

#[cfg(not(target_os = "linux"))]
pub(super) struct CommittedCreateOnlyDirectoryView<'transaction, 'capability> {
    lifetime: PhantomData<(&'transaction (), &'capability ())>,
}

#[cfg(not(target_os = "linux"))]
impl CommittedCreateOnlyDirectoryView<'_, '_> {
    /// Fail without inspecting a requested path or byte bound.
    pub(super) fn read_file(&self, _relative: &str, _maximum: usize) -> Result<Vec<u8>> {
        let _ = self;
        anyhow::bail!("create-only directory transactions require Linux")
    }
}

#[cfg(not(target_os = "linux"))]
impl<'capability> CommittedCreateOnlyDirectoryTransaction<'capability> {
    /// Fail before invoking a semantic validator or inspecting a committed path.
    pub(super) fn reopen_with_postcommit_validation<T, F>(self, _validate: F) -> Result<T>
    where
        F: for<'transaction> FnOnce(
            CommittedCreateOnlyDirectoryView<'transaction, 'capability>,
        ) -> Result<T>,
    {
        let _ = self.transaction;
        anyhow::bail!("create-only directory transactions require Linux")
    }
}

#[cfg(not(target_os = "linux"))]
impl<'capability> CreateOnlyDirectoryTransaction<'capability> {
    /// Fail without inspecting the requested path.
    pub(super) fn create_directory(&mut self, _relative: &str) -> Result<()> {
        let _ = self;
        anyhow::bail!("create-only directory transactions require Linux")
    }

    /// Fail without inspecting the requested path or bytes.
    pub(super) fn create_file(
        &mut self,
        _relative: &str,
        _bytes: &[u8],
        _maximum: usize,
    ) -> Result<()> {
        let _ = self;
        anyhow::bail!("create-only directory transactions require Linux")
    }

    /// Test-only fail-closed adoption seam.
    #[cfg(test)]
    pub(super) fn adopt_published_directory_tree(&mut self, _relative: &str) -> Result<()> {
        let _ = self;
        anyhow::bail!("create-only directory transactions require Linux")
    }

    /// Fail without performing a commit inspection.
    pub(super) fn commit(self) -> Result<()> {
        self.commit_durable()?
            .reopen_with_postcommit_validation(|_| Ok(()))
    }

    /// Fail without minting a committed typestate.
    pub(super) fn commit_durable(
        self,
    ) -> Result<CommittedCreateOnlyDirectoryTransaction<'capability>> {
        let _ = self;
        anyhow::bail!("create-only directory transactions require Linux")
    }

    /// Fail before invoking a semantic validator or inspecting a committed path.
    pub(super) fn commit_with_postcommit_validation<T, F>(self, _validate: F) -> Result<T>
    where
        F: for<'transaction> FnOnce(
            CommittedCreateOnlyDirectoryView<'transaction, 'capability>,
        ) -> Result<T>,
    {
        self.commit_durable()?
            .reopen_with_postcommit_validation(_validate)
    }
}

/// Begin a create-only transaction only from the checked execute mutation gate.
pub(super) fn begin_create_only_directory_transaction<'capability, const ROOTS: usize, Layout>(
    capability: &'capability mut MutationCapability<'_, ROOTS, Layout>,
) -> Result<CreateOnlyDirectoryTransaction<'capability>>
where
    Layout: GenericCreateOnlyCampaignLayout<ROOTS>,
{
    begin_projected_create_only_directory_transaction(capability)
}

/// H0-only gateway guarded by an unconstructable sibling-module permit.
#[cfg(feature = "b4-prepare-input-set-kernel")]
pub(super) fn begin_prepare_input_set_directory_transaction<'capability, const ROOTS: usize>(
    permit: PrepareInputSetCreateOnlyPermit<'capability, '_, ROOTS>,
) -> Result<CreateOnlyDirectoryTransaction<'capability>> {
    begin_projected_create_only_directory_transaction(permit.into_capability())
}

/// H0 V2-only gateway guarded by an unconstructable sibling-module permit.
#[cfg(feature = "b4-prepare-input-set-kernel")]
pub(super) fn begin_prepare_input_set_directory_transaction_v2<'capability, const ROOTS: usize>(
    permit: PrepareInputSetCreateOnlyPermitV2<'capability, '_, ROOTS>,
) -> Result<CreateOnlyDirectoryTransaction<'capability>> {
    begin_projected_create_only_directory_transaction(permit.into_capability())
}

fn begin_projected_create_only_directory_transaction<'capability, const ROOTS: usize, Layout>(
    capability: &'capability mut MutationCapability<'_, ROOTS, Layout>,
) -> Result<CreateOnlyDirectoryTransaction<'capability>>
where
    Layout: ProjectedCampaignLayout<ROOTS>,
{
    #[cfg(target_os = "linux")]
    {
        let projected = capability.projected_layout();
        let campaign_root = capability.campaign_root();
        let immutable_roots = capability.immutable_roots();
        CreateOnlyDirectoryTransaction::begin(
            capability,
            projected.outer_create_only_layout(),
            projected.required_outer_top_level_entries(),
            projected.required_outer_top_level_directories(),
            |identities| {
                campaign_root.require_directory_chain(
                    projected.outer_create_only_layout().parent(),
                    identities,
                )?;
                immutable_roots.reject_physical_directory_aliases(identities)
            },
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = capability;
        anyhow::bail!("create-only directory transactions require Linux")
    }
}

#[cfg(all(test, target_os = "linux"))]
struct TestMutationCustody;

#[cfg(all(test, target_os = "linux"))]
impl MutationCustody for TestMutationCustody {
    fn recheck(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
static TEST_MUTATION_CUSTODY: TestMutationCustody = TestMutationCustody;

#[cfg(all(test, target_os = "linux"))]
fn begin_test_transaction(
    layout: &CreateOnlyDirectoryLayout,
    required_top_level_entries: &[&str],
) -> Result<CreateOnlyDirectoryTransaction<'static>> {
    begin_test_transaction_with_directories(layout, required_top_level_entries, &[])
}

#[cfg(all(test, target_os = "linux"))]
fn begin_test_transaction_with_directories(
    layout: &CreateOnlyDirectoryLayout,
    required_top_level_entries: &[&str],
    required_top_level_directories: &[&str],
) -> Result<CreateOnlyDirectoryTransaction<'static>> {
    let required = required_top_level_entries
        .iter()
        .map(|entry| (*entry).to_owned())
        .collect::<Vec<_>>();
    let required_directories = required_top_level_directories
        .iter()
        .map(|entry| (*entry).to_owned())
        .collect::<Vec<_>>();
    CreateOnlyDirectoryTransaction::begin(
        &TEST_MUTATION_CUSTODY,
        layout,
        &required,
        &required_directories,
        |_identities| Ok(()),
    )
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    #[cfg(target_os = "linux")]
    use std::{cell::Cell, fs, path::PathBuf, rc::Rc};
    #[cfg(not(target_os = "linux"))]
    use std::{cell::Cell, marker::PhantomData};

    use super::project_create_only_directory_layout;
    #[cfg(not(target_os = "linux"))]
    use super::{CommittedCreateOnlyDirectoryTransaction, CreateOnlyDirectoryTransaction};
    #[cfg(target_os = "linux")]
    use super::{
        CreateOnlyDirectoryLayout, CreateOnlyDirectoryTransaction, DirectoryObservation,
        MAX_CREATE_ONLY_DEPTH, MAX_CREATE_ONLY_FILE_BYTES, PINNED_DIRECTORY_FLAGS,
        begin_test_transaction, begin_test_transaction_with_directories, directory_observation,
        pin_and_preflight_create_only_parent, require_closed_directory_link_count,
    };

    #[cfg(target_os = "linux")]
    fn begin_packet_adoption_case(
        label: &str,
    ) -> (
        tempfile::TempDir,
        CreateOnlyDirectoryLayout,
        CreateOnlyDirectoryTransaction<'static>,
        PathBuf,
    ) {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let final_path = temp.path().join(label);
        let layout = project_create_only_directory_layout(&final_path).unwrap();
        let transaction = begin_test_transaction_with_directories(
            &layout,
            &["packet", "receipt.json"],
            &["packet"],
        )
        .unwrap();
        let packet = layout.reserved_staging_path().join("packet");
        fs::create_dir(&packet).unwrap();
        fs::set_permissions(&packet, fs::Permissions::from_mode(0o700)).unwrap();
        (temp, layout, transaction, packet)
    }

    #[cfg(target_os = "linux")]
    #[derive(Debug)]
    struct DropWitness(Rc<Cell<usize>>);

    #[cfg(target_os = "linux")]
    impl Drop for DropWitness {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[cfg(target_os = "linux")]
    fn assert_postcommit_mutation_rejected(
        label: &str,
        mutate: impl FnOnce(&Path) -> anyhow::Result<()>,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let final_path = temp.path().join(label);
        let layout = project_create_only_directory_layout(&final_path).unwrap();
        let mut transaction = begin_test_transaction(&layout, &["payload.bin"]).unwrap();
        transaction
            .create_file("payload.bin", b"payload", 64)
            .unwrap();
        let drops = Rc::new(Cell::new(0));
        let returned = DropWitness(Rc::clone(&drops));

        let result = transaction.commit_with_postcommit_validation(|_committed| {
            mutate(&final_path)?;
            Ok(returned)
        });

        assert!(result.is_err(), "{label} mutation unexpectedly authorized");
        assert_eq!(
            drops.get(),
            1,
            "{label} returned value was not suppressed and dropped"
        );
        assert!(format!("{:#}", result.unwrap_err()).contains("changed"));
    }

    #[cfg(target_os = "linux")]
    fn write_test_packet_from_descriptor(
        staging_root: std::os::fd::BorrowedFd<'_>,
    ) -> anyhow::Result<()> {
        use std::{io::Write as _, os::fd::AsFd as _};

        rustix::fs::mkdirat(staging_root, "packet", super::PRIVATE_DIRECTORY_MODE)?;
        let packet = rustix::fs::openat2(
            staging_root,
            "packet",
            super::PINNED_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
            super::TREE_ENTRY_RESOLVE_FLAGS,
        )?;
        rustix::fs::fchmod(&packet, super::PRIVATE_DIRECTORY_MODE)?;
        let payload = rustix::fs::openat2(
            packet.as_fd(),
            "payload.bin",
            super::CREATE_FILE_FLAGS,
            super::PRIVATE_FILE_MODE,
            super::TREE_ENTRY_RESOLVE_FLAGS,
        )?;
        let mut payload = fs::File::from(payload);
        rustix::fs::fchmod(&payload, super::PRIVATE_FILE_MODE)?;
        payload.write_all(b"packet")?;
        Ok(())
    }

    #[test]
    fn create_only_layout_requires_a_normalized_absolute_destination() {
        for invalid in [
            Path::new("relative/output"),
            Path::new("/campaign/../output"),
            Path::new("/campaign/Output"),
            Path::new("/campaign/con"),
        ] {
            assert!(project_create_only_directory_layout(invalid).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn create_only_preflight_rejects_missing_atomic_no_replace_support_without_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let final_path = temp.path().join("atomic-preflight");
        let layout = project_create_only_directory_layout(&final_path).unwrap();
        let before = fs::read_dir(temp.path()).unwrap().count();

        let Err(error) = pin_and_preflight_create_only_parent(
            &layout,
            |_identities| Ok(()),
            |_parent| Ok(false),
        ) else {
            panic!("unsupported atomic no-replace unexpectedly passed preflight");
        };

        assert!(format!("{error:#}").contains("atomic no-replace"));
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), before);
        assert!(!layout.final_path().exists());
        assert!(!layout.reserved_staging_path().exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn create_only_commit_is_durable_and_never_replaces() {
        let temp = tempfile::tempdir().unwrap();
        let final_path = temp.path().join("published");
        let layout = project_create_only_directory_layout(&final_path).unwrap();
        let mut transaction =
            begin_test_transaction_with_directories(&layout, &["nested"], &["nested"]).unwrap();
        transaction.create_directory("nested").unwrap();
        transaction
            .create_file("nested/payload.bin", b"payload", 64)
            .unwrap();
        transaction.commit().unwrap();

        assert_eq!(
            fs::read(final_path.join("nested/payload.bin")).unwrap(),
            b"payload"
        );
        assert!(!layout.reserved_staging_path().exists());

        let error = begin_test_transaction(&layout, &["nested"]).unwrap_err();
        assert!(error.to_string().contains("occupied"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn create_only_parent_swap_cannot_redirect_an_effect() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("parent");
        let evil = temp.path().join("evil");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&evil).unwrap();
        let final_path = parent.join("published");
        let layout = project_create_only_directory_layout(&final_path).unwrap();
        let mut transaction = begin_test_transaction(&layout, &["payload.bin"]).unwrap();

        let retained_parent = temp.path().join("parent-old");
        fs::rename(&parent, &retained_parent).unwrap();
        symlink(&evil, &parent).unwrap();

        let error = transaction
            .create_file("payload.bin", b"must-not-land", 64)
            .unwrap_err();
        assert!(error.to_string().contains("no longer names"));
        assert!(!evil.join("payload.bin").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn create_only_descendant_swap_cannot_redirect_an_effect() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let final_path = temp.path().join("published");
        let evil = temp.path().join("evil");
        fs::create_dir(&evil).unwrap();
        let layout = project_create_only_directory_layout(&final_path).unwrap();
        let mut transaction =
            begin_test_transaction_with_directories(&layout, &["nested"], &["nested"]).unwrap();
        transaction.create_directory("nested").unwrap();

        let nested = layout.reserved_staging_path().join("nested");
        fs::rename(&nested, layout.reserved_staging_path().join("nested-old")).unwrap();
        symlink(&evil, &nested).unwrap();

        let error = transaction
            .create_file("nested/payload.bin", b"must-not-land", 64)
            .unwrap_err();
        assert!(error.to_string().contains("changed"));
        assert!(!evil.join("payload.bin").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn two_create_only_writers_have_exactly_one_winner() {
        let temp = tempfile::tempdir().unwrap();
        let final_path = temp.path().join("published");
        let layout = project_create_only_directory_layout(&final_path).unwrap();

        let first = begin_test_transaction(&layout, &["winner.bin"]);
        let second = begin_test_transaction(&layout, &["winner.bin"]);
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);

        let mut winner = first.or(second).unwrap();
        winner.create_file("winner.bin", b"winner", 64).unwrap();
        winner.commit().unwrap();
        assert_eq!(fs::read(final_path.join("winner.bin")).unwrap(), b"winner");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn projected_inventory_and_compiled_bounds_reject_before_commit_or_effect() {
        let temp = tempfile::tempdir().unwrap();

        let wrong_kind_final = temp.path().join("wrong-kind");
        let wrong_kind_layout = project_create_only_directory_layout(&wrong_kind_final).unwrap();
        let mut wrong_kind = begin_test_transaction_with_directories(
            &wrong_kind_layout,
            &["terminal-evidence-packet"],
            &["terminal-evidence-packet"],
        )
        .unwrap();
        let error = wrong_kind
            .create_file("terminal-evidence-packet", b"not-a-directory", 64)
            .unwrap_err();
        assert!(error.to_string().contains("cannot be created as a file"));
        assert!(
            !wrong_kind_layout
                .reserved_staging_path()
                .join("terminal-evidence-packet")
                .exists()
        );

        let wrong_file_kind_final = temp.path().join("wrong-file-kind");
        let wrong_file_kind_layout =
            project_create_only_directory_layout(&wrong_file_kind_final).unwrap();
        let mut wrong_file_kind =
            begin_test_transaction(&wrong_file_kind_layout, &["receipt.json"]).unwrap();
        let error = wrong_file_kind
            .create_directory("receipt.json")
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cannot be created as a directory")
        );
        assert!(
            !wrong_file_kind_layout
                .reserved_staging_path()
                .join("receipt.json")
                .exists()
        );

        let missing_final = temp.path().join("missing-required");
        let missing_layout = project_create_only_directory_layout(&missing_final).unwrap();
        let missing = begin_test_transaction(&missing_layout, &["required.bin"]).unwrap();
        let error = missing.commit().unwrap_err();
        assert!(error.to_string().contains("projected top-level closure"));
        assert!(!missing_final.exists());

        let extra_final = temp.path().join("extra-leaf");
        let extra_layout = project_create_only_directory_layout(&extra_final).unwrap();
        let mut extra = begin_test_transaction(&extra_layout, &["required.bin"]).unwrap();
        let error = extra.create_file("extra.bin", b"extra", 64).unwrap_err();
        assert!(error.to_string().contains("outside the projected"));
        assert!(
            !extra_layout
                .reserved_staging_path()
                .join("extra.bin")
                .exists()
        );

        let deep_final = temp.path().join("deep-leaf");
        let deep_layout = project_create_only_directory_layout(&deep_final).unwrap();
        let mut deep = begin_test_transaction(&deep_layout, &["a"]).unwrap();
        let too_deep = vec!["a"; MAX_CREATE_ONLY_DEPTH + 1].join("/");
        let error = deep.create_directory(&too_deep).unwrap_err();
        assert!(error.to_string().contains("depth bound"));
        assert!(!deep_layout.reserved_staging_path().join("a").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn create_only_metadata_and_hard_link_races_fail_closed() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        use std::time::Duration;

        let temp = tempfile::tempdir().unwrap();

        let rewrite_final = temp.path().join("same-bytes-rewrite");
        let rewrite_layout = project_create_only_directory_layout(&rewrite_final).unwrap();
        let mut rewrite = begin_test_transaction(&rewrite_layout, &["payload.bin"]).unwrap();
        rewrite.create_file("payload.bin", b"payload", 64).unwrap();
        let rewrite_path = rewrite_layout.reserved_staging_path().join("payload.bin");
        let before = fs::metadata(&rewrite_path).unwrap();
        std::thread::sleep(Duration::from_millis(2));
        fs::write(&rewrite_path, b"payload").unwrap();
        let after = fs::metadata(&rewrite_path).unwrap();
        assert_eq!(fs::read(&rewrite_path).unwrap(), b"payload");
        assert_ne!(
            (before.ctime(), before.ctime_nsec()),
            (after.ctime(), after.ctime_nsec())
        );
        let error = rewrite.commit().unwrap_err();
        assert!(format!("{error:#}").contains("metadata changed"));
        assert!(!rewrite_final.exists());

        let mode_final = temp.path().join("mode-change");
        let mode_layout = project_create_only_directory_layout(&mode_final).unwrap();
        let mut mode = begin_test_transaction(&mode_layout, &["payload.bin"]).unwrap();
        mode.create_file("payload.bin", b"payload", 64).unwrap();
        let mode_path = mode_layout.reserved_staging_path().join("payload.bin");
        let metadata = fs::metadata(&mode_path).unwrap();
        let mut permissions = metadata.permissions();
        permissions.set_mode((metadata.mode() & 0o7777) ^ 0o100);
        fs::set_permissions(&mode_path, permissions).unwrap();
        let error = mode.commit().unwrap_err();
        assert!(format!("{error:#}").contains("metadata changed"));
        assert!(!mode_final.exists());

        let hard_link_final = temp.path().join("hard-link");
        let hard_link_layout = project_create_only_directory_layout(&hard_link_final).unwrap();
        let mut hard_link = begin_test_transaction(&hard_link_layout, &["payload.bin"]).unwrap();
        hard_link
            .create_file("payload.bin", b"payload", 64)
            .unwrap();
        fs::hard_link(
            hard_link_layout.reserved_staging_path().join("payload.bin"),
            temp.path().join("payload-alias.bin"),
        )
        .unwrap();
        let error = hard_link.commit().unwrap_err();
        assert!(format!("{error:#}").contains("exactly one hard link"));
        assert!(!hard_link_final.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn postcommit_validation_reads_only_the_retained_committed_tree() {
        let temp = tempfile::tempdir().unwrap();
        let final_path = temp.path().join("published");
        let moved_path = temp.path().join("published-retained");
        let layout = project_create_only_directory_layout(&final_path).unwrap();
        let mut transaction = begin_test_transaction(&layout, &["payload.bin"]).unwrap();
        transaction
            .create_file("payload.bin", b"retained", 64)
            .unwrap();
        let validation_entered = std::cell::Cell::new(false);

        let result = transaction.commit_with_postcommit_validation(|committed| {
            validation_entered.set(true);
            assert_eq!(
                committed.read_file("payload.bin", 64)?,
                b"retained".to_vec()
            );
            fs::rename(&final_path, &moved_path)?;
            fs::create_dir(&final_path)?;
            fs::write(final_path.join("payload.bin"), b"decoy")?;
            Ok("must-not-escape")
        });

        assert!(validation_entered.get());
        assert!(result.is_err());
        assert_eq!(fs::read(final_path.join("payload.bin")).unwrap(), b"decoy");
        assert_eq!(
            fs::read(moved_path.join("payload.bin")).unwrap(),
            b"retained"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_commit_typestate_separates_durable_commit_from_semantic_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let final_path = temp.path().join("published");
        let layout = project_create_only_directory_layout(&final_path).unwrap();
        let mut transaction = begin_test_transaction(&layout, &["payload.bin"]).unwrap();
        transaction
            .create_file("payload.bin", b"retained", 64)
            .unwrap();

        let committed = transaction.commit_durable().unwrap();
        assert_eq!(
            fs::read(final_path.join("payload.bin")).unwrap(),
            b"retained"
        );
        assert!(!layout.reserved_staging_path().exists());

        let reopened = committed
            .reopen_with_postcommit_validation(|view| view.read_file("payload.bin", 64))
            .unwrap();
        assert_eq!(reopened, b"retained");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_commit_typestate_rejects_path_swap_before_semantic_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let final_path = temp.path().join("published");
        let moved_path = temp.path().join("published-retained");
        let layout = project_create_only_directory_layout(&final_path).unwrap();
        let mut transaction = begin_test_transaction(&layout, &["payload.bin"]).unwrap();
        transaction
            .create_file("payload.bin", b"retained", 64)
            .unwrap();

        let committed = transaction.commit_durable().unwrap();
        fs::rename(&final_path, &moved_path).unwrap();
        fs::create_dir(&final_path).unwrap();
        fs::write(final_path.join("payload.bin"), b"decoy").unwrap();
        let callback_entered = Cell::new(false);

        let result: anyhow::Result<Vec<u8>> = committed.reopen_with_postcommit_validation(|view| {
            callback_entered.set(true);
            view.read_file("payload.bin", 64)
        });

        assert!(result.is_err());
        assert!(!callback_entered.get());
        assert_eq!(fs::read(final_path.join("payload.bin")).unwrap(), b"decoy");
        assert_eq!(
            fs::read(moved_path.join("payload.bin")).unwrap(),
            b"retained"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_committed_stub_fails_before_semantic_validator() {
        let committed = CommittedCreateOnlyDirectoryTransaction {
            transaction: CreateOnlyDirectoryTransaction {
                capability_borrow: PhantomData,
            },
        };
        let callback_entered = Cell::new(false);

        let result: anyhow::Result<()> = committed.reopen_with_postcommit_validation(|_| {
            callback_entered.set(true);
            Ok(())
        });

        assert!(result.is_err());
        assert!(!callback_entered.get());
    }

    #[test]
    fn retained_commit_typestate_api_is_additive_and_two_phase() {
        let source = include_str!("create_only.rs").replace("\r\n", "\n");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        for required in [
            "struct CommittedCreateOnlyDirectoryTransaction",
            "fn commit_durable(",
            "fn reopen_with_postcommit_validation",
            "self.commit_durable()?",
        ] {
            assert!(
                production.contains(required),
                "create-only typestate API omits {required}"
            );
        }
        assert_eq!(production.matches("fn commit_durable(").count(), 2);
        assert_eq!(
            production
                .matches("fn reopen_with_postcommit_validation")
                .count(),
            2
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_postcommit_semantics_leave_the_root_but_return_no_value() {
        let temp = tempfile::tempdir().unwrap();
        let final_path = temp.path().join("published");
        let layout = project_create_only_directory_layout(&final_path).unwrap();
        let mut transaction = begin_test_transaction(&layout, &["payload.bin"]).unwrap();
        transaction
            .create_file("payload.bin", b"retained", 64)
            .unwrap();

        let result: anyhow::Result<()> =
            transaction.commit_with_postcommit_validation(|committed| {
                assert_eq!(
                    committed.read_file("payload.bin", 64)?,
                    b"retained".to_vec()
                );
                anyhow::bail!("injected semantic reopen failure")
            });

        let error = result.unwrap_err();
        assert!(format!("{error:#}").contains("injected semantic reopen failure"));
        assert_eq!(
            fs::read(final_path.join("payload.bin")).unwrap(),
            b"retained"
        );
        assert!(!layout.reserved_staging_path().exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn published_subtree_is_adopted_under_retained_descriptor_custody() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let final_path = temp.path().join("published");
        let layout = project_create_only_directory_layout(&final_path).unwrap();
        let mut transaction = begin_test_transaction_with_directories(
            &layout,
            &["packet", "receipt.json"],
            &["packet"],
        )
        .unwrap();
        let packet = layout.reserved_staging_path().join("packet");
        let sources = packet.join("sources");
        fs::create_dir(&packet).unwrap();
        fs::set_permissions(&packet, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(&sources).unwrap();
        fs::set_permissions(&sources, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(sources.join("payload.bin"), b"packet").unwrap();
        fs::set_permissions(
            sources.join("payload.bin"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        transaction
            .adopt_published_directory_tree("packet")
            .unwrap();
        transaction
            .create_file("receipt.json", b"receipt", 64)
            .unwrap();
        let bytes = transaction
            .commit_with_postcommit_validation(|committed| {
                let packet_descriptor = committed.directory_descriptor("packet")?;
                let metadata = rustix::fs::fstat(packet_descriptor)?;
                assert!(rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_dir());
                committed.read_file("receipt.json", 64)
            })
            .unwrap();

        assert_eq!(bytes, b"receipt");
        assert_eq!(
            fs::read(final_path.join("packet/sources/payload.bin")).unwrap(),
            b"packet"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn committed_root_descriptor_is_reauthenticated_and_identity_bound() {
        let temp = tempfile::tempdir().unwrap();
        let final_path = temp.path().join("published");
        let layout = project_create_only_directory_layout(&final_path).unwrap();
        let mut transaction =
            begin_test_transaction_with_directories(&layout, &["reproduction"], &["reproduction"])
                .unwrap();
        transaction.create_directory("reproduction").unwrap();

        let root_identity = transaction
            .commit_with_postcommit_validation(|committed| {
                let root = rustix::fs::fstat(committed.root_directory_descriptor()?)?;
                let subtree = rustix::fs::fstat(committed.directory_descriptor("reproduction")?)?;
                assert!(rustix::fs::FileType::from_raw_mode(root.st_mode).is_dir());
                assert!(rustix::fs::FileType::from_raw_mode(subtree.st_mode).is_dir());
                assert_ne!((root.st_dev, root.st_ino), (subtree.st_dev, subtree.st_ino));
                Ok((root.st_dev, root.st_ino))
            })
            .unwrap();

        let named = fs::metadata(&final_path).unwrap();
        use std::os::unix::fs::MetadataExt as _;
        assert_eq!(root_identity, (named.dev(), named.ino()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn adopted_directory_link_count_must_close_its_exact_child_inventory() {
        let temp = tempfile::tempdir().unwrap();
        let packet = temp.path().join("packet");
        fs::create_dir(&packet).unwrap();
        fs::create_dir(packet.join("sources")).unwrap();
        let descriptor =
            rustix::fs::open(&packet, PINNED_DIRECTORY_FLAGS, rustix::fs::Mode::empty()).unwrap();
        let observation = directory_observation(&descriptor).unwrap();
        require_closed_directory_link_count(observation, 1, "packet").unwrap();

        let aliased = DirectoryObservation {
            hard_link_count: observation.hard_link_count + 1,
            ..observation
        };
        let error = require_closed_directory_link_count(aliased, 1, "packet").unwrap_err();
        assert!(error.to_string().contains("external physical alias"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn published_subtree_rejects_symlink_special_and_hard_link_entries() {
        use std::os::unix::{fs::PermissionsExt as _, net::UnixListener};

        let (_temp, _layout, mut symlink_transaction, symlink_packet) =
            begin_packet_adoption_case("symlink-case");
        std::os::unix::fs::symlink("missing-target", symlink_packet.join("link")).unwrap();
        let error = symlink_transaction
            .adopt_published_directory_tree("packet")
            .unwrap_err();
        assert!(format!("{error:#}").contains("symlink or special"));

        let (_temp, _layout, mut special_transaction, special_packet) =
            begin_packet_adoption_case("special-case");
        let _listener = UnixListener::bind(special_packet.join("socket")).unwrap();
        let error = special_transaction
            .adopt_published_directory_tree("packet")
            .unwrap_err();
        assert!(format!("{error:#}").contains("symlink or special"));

        let (temp, _layout, mut hard_link_transaction, hard_link_packet) =
            begin_packet_adoption_case("hard-link-case");
        let payload = hard_link_packet.join("payload.bin");
        fs::write(&payload, b"payload").unwrap();
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&payload, temp.path().join("payload-alias.bin")).unwrap();
        let error = hard_link_transaction
            .adopt_published_directory_tree("packet")
            .unwrap_err();
        assert!(format!("{error:#}").contains("exactly one hard link"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn published_subtree_rejects_non_private_modes_and_extra_root_inventory() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_temp, _layout, mut directory_mode_transaction, directory_mode_packet) =
            begin_packet_adoption_case("directory-mode-case");
        fs::set_permissions(&directory_mode_packet, fs::Permissions::from_mode(0o755)).unwrap();
        let error = directory_mode_transaction
            .adopt_published_directory_tree("packet")
            .unwrap_err();
        assert!(format!("{error:#}").contains("owner-only permissions"));

        let (_temp, _layout, mut file_mode_transaction, file_mode_packet) =
            begin_packet_adoption_case("file-mode-case");
        let payload = file_mode_packet.join("payload.bin");
        fs::write(&payload, b"payload").unwrap();
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o644)).unwrap();
        let error = file_mode_transaction
            .adopt_published_directory_tree("packet")
            .unwrap_err();
        assert!(format!("{error:#}").contains("owner-only permissions"));

        let (_temp, layout, mut extra_transaction, _extra_packet) =
            begin_packet_adoption_case("extra-root-case");
        fs::write(
            layout.reserved_staging_path().join("unexpected.bin"),
            b"unexpected",
        )
        .unwrap();
        let error = extra_transaction
            .adopt_published_directory_tree("packet")
            .unwrap_err();
        assert!(format!("{error:#}").contains("outside the published subtree"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn published_subtree_rejects_depth_and_sparse_file_budget_overflow() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_temp, _layout, mut depth_transaction, depth_packet) =
            begin_packet_adoption_case("depth-case");
        let mut descendant = depth_packet;
        for _ in 0..MAX_CREATE_ONLY_DEPTH {
            descendant = descendant.join("a");
            fs::create_dir(&descendant).unwrap();
            fs::set_permissions(&descendant, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let error = depth_transaction
            .adopt_published_directory_tree("packet")
            .unwrap_err();
        assert!(format!("{error:#}").contains("depth bound"));

        let (_temp, _layout, mut budget_transaction, budget_packet) =
            begin_packet_adoption_case("budget-case");
        let payload = budget_packet.join("payload.bin");
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&payload)
            .unwrap();
        file.set_len(MAX_CREATE_ONLY_FILE_BYTES + 1).unwrap();
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o600)).unwrap();
        let error = budget_transaction
            .adopt_published_directory_tree("packet")
            .unwrap_err();
        assert!(format!("{error:#}").contains("per-file byte bound"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn adopted_subtree_inventory_change_poisons_before_the_next_effect() {
        use std::os::unix::fs::PermissionsExt as _;

        let (_temp, layout, mut transaction, packet) =
            begin_packet_adoption_case("inventory-change-case");
        let payload = packet.join("payload.bin");
        fs::write(&payload, b"payload").unwrap();
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o600)).unwrap();
        transaction
            .adopt_published_directory_tree("packet")
            .unwrap();

        let unexpected = packet.join("unexpected.bin");
        fs::write(&unexpected, b"unexpected").unwrap();
        fs::set_permissions(&unexpected, fs::Permissions::from_mode(0o600)).unwrap();
        let error = transaction
            .create_file("receipt.json", b"must-not-land", 64)
            .unwrap_err();
        assert!(format!("{error:#}").contains("changed"));
        assert!(!layout.reserved_staging_path().join("receipt.json").exists());

        let error = transaction.commit().unwrap_err();
        assert!(format!("{error:#}").contains("poisoned"));
        assert!(!layout.final_path().exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn postcommit_mutations_suppress_success_values() {
        use std::os::unix::fs::PermissionsExt as _;

        assert_postcommit_mutation_rejected("postcommit-bytes", |root| {
            fs::write(root.join("payload.bin"), b"changed")?;
            Ok(())
        });
        assert_postcommit_mutation_rejected("postcommit-mode", |root| {
            fs::set_permissions(root.join("payload.bin"), fs::Permissions::from_mode(0o400))?;
            Ok(())
        });
        assert_postcommit_mutation_rejected("postcommit-inventory", |root| {
            fs::write(root.join("unexpected.bin"), b"unexpected")?;
            Ok(())
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn occupied_absence_requirement_and_failed_commit_return_no_value() {
        let temp = tempfile::tempdir().unwrap();
        let absence_final = temp.path().join("absence-case");
        let absence_layout = project_create_only_directory_layout(&absence_final).unwrap();
        let mut absence_transaction =
            begin_test_transaction(&absence_layout, &["payload.bin"]).unwrap();
        absence_transaction
            .create_file("payload.bin", b"payload", 64)
            .unwrap();
        let result: anyhow::Result<&'static str> = absence_transaction
            .commit_with_postcommit_validation(|committed| {
                committed.require_absent("payload.bin")?;
                Ok("must-not-escape")
            });
        let error = result.unwrap_err();
        assert!(format!("{error:#}").contains("occupied"));

        let failed_final = temp.path().join("failed-commit-case");
        let failed_layout = project_create_only_directory_layout(&failed_final).unwrap();
        let mut failed_transaction =
            begin_test_transaction(&failed_layout, &["payload.bin"]).unwrap();
        failed_transaction
            .create_file("payload.bin", b"payload", 64)
            .unwrap();
        fs::create_dir(&failed_final).unwrap();
        let callback_entered = Cell::new(false);
        let result: anyhow::Result<()> =
            failed_transaction.commit_with_postcommit_validation(|_committed| {
                callback_entered.set(true);
                Ok(())
            });
        assert!(result.is_err());
        assert!(!callback_entered.get());
        assert!(failed_final.is_dir());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_staging_descriptor_cannot_be_redirected_before_publication() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = tempfile::tempdir().unwrap();
        let final_path = temp.path().join("published");
        let moved_staging = temp.path().join("retained-staging");
        let layout = project_create_only_directory_layout(&final_path).unwrap();
        let mut transaction = begin_test_transaction_with_directories(
            &layout,
            &["packet", "receipt.json"],
            &["packet"],
        )
        .unwrap();
        let named_staging = layout.reserved_staging_path().to_path_buf();
        let drops = Rc::new(Cell::new(0));
        let returned = DropWitness(Rc::clone(&drops));
        let decoy_observation = Cell::new(None);

        let result = transaction.publish_and_adopt_directory_tree("packet", |staging_root| {
            fs::rename(&named_staging, &moved_staging)?;
            fs::create_dir(&named_staging)?;
            fs::set_permissions(&named_staging, fs::Permissions::from_mode(0o700))?;
            let decoy = rustix::fs::open(
                &named_staging,
                PINNED_DIRECTORY_FLAGS,
                rustix::fs::Mode::empty(),
            )?;
            decoy_observation.set(Some(directory_observation(&decoy)?));
            write_test_packet_from_descriptor(staging_root)?;
            Ok(returned)
        });

        assert!(result.is_err());
        assert_eq!(drops.get(), 1, "publication value escaped a failed recheck");
        let decoy = rustix::fs::open(
            &named_staging,
            PINNED_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        assert!(
            Some(directory_observation(&decoy).unwrap()) == decoy_observation.get(),
            "decoy staging metadata changed"
        );
        assert!(
            fs::read_dir(&named_staging).unwrap().next().is_none(),
            "decoy staging pathname was modified"
        );
        assert_eq!(
            fs::read(moved_staging.join("packet/payload.bin")).unwrap(),
            b"packet"
        );
        assert!(!final_path.exists());
        let error = transaction.commit().unwrap_err();
        assert!(format!("{error:#}").contains("poisoned"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_rooted_publication_adopts_before_returning_success() {
        let temp = tempfile::tempdir().unwrap();
        let final_path = temp.path().join("published");
        let layout = project_create_only_directory_layout(&final_path).unwrap();
        let mut transaction = begin_test_transaction_with_directories(
            &layout,
            &["packet", "receipt.json"],
            &["packet"],
        )
        .unwrap();

        let returned = transaction
            .publish_and_adopt_directory_tree("packet", |staging_root| {
                write_test_packet_from_descriptor(staging_root)?;
                Ok("published")
            })
            .unwrap();
        assert_eq!(returned, "published");
        transaction
            .create_file("receipt.json", b"receipt", 64)
            .unwrap();
        transaction.commit().unwrap();

        assert_eq!(
            fs::read(final_path.join("packet/payload.bin")).unwrap(),
            b"packet"
        );
        assert_eq!(
            fs::read(final_path.join("receipt.json")).unwrap(),
            b"receipt"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_rooted_publication_callback_waits_for_all_preconditions() {
        let temp = tempfile::tempdir().unwrap();

        let wrong_kind_final = temp.path().join("wrong-kind");
        let wrong_kind_layout = project_create_only_directory_layout(&wrong_kind_final).unwrap();
        let mut wrong_kind = begin_test_transaction_with_directories(
            &wrong_kind_layout,
            &["packet", "receipt.json"],
            &["packet"],
        )
        .unwrap();
        let wrong_kind_called = Cell::new(false);
        let result: anyhow::Result<()> =
            wrong_kind.publish_and_adopt_directory_tree("receipt.json", |_staging_root| {
                wrong_kind_called.set(true);
                Ok(())
            });
        assert!(result.is_err());
        assert!(!wrong_kind_called.get());

        let second_effect_final = temp.path().join("second-effect");
        let second_effect_layout =
            project_create_only_directory_layout(&second_effect_final).unwrap();
        let mut second_effect = begin_test_transaction_with_directories(
            &second_effect_layout,
            &["packet", "receipt.json"],
            &["packet"],
        )
        .unwrap();
        second_effect
            .create_file("receipt.json", b"receipt", 64)
            .unwrap();
        let second_effect_called = Cell::new(false);
        let result: anyhow::Result<()> =
            second_effect.publish_and_adopt_directory_tree("packet", |_staging_root| {
                second_effect_called.set(true);
                Ok(())
            });
        assert!(result.is_err());
        assert!(!second_effect_called.get());
    }
}
