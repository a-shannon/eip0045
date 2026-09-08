//! Descriptor-rooted custody of the executable image used by a B4 campaign.

use std::{fmt, path::Path};

use anyhow::Result;

use crate::b4_campaign_contract::{B4ContractArtifactEncodingV1, B4ContractArtifactIdentityV1};

/// Opaque retained observation of the image executing the current process.
///
/// Capturing this value authenticates the configured absolute path against
/// `/proc/self/exe`, retains both the executing image and every configured-path
/// directory descriptor, and requires the executable to have exactly one hard
/// link. The observation is deliberately neither serializable nor clonable:
/// authority remains tied to the retained live descriptors.
pub struct B4CurrentExecutableObservationV1 {
    #[cfg(target_os = "linux")]
    state: linux::CurrentExecutableState,
}

impl fmt::Debug for B4CurrentExecutableObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("B4CurrentExecutableObservationV1")
            .finish_non_exhaustive()
    }
}

impl B4CurrentExecutableObservationV1 {
    /// Capture and authenticate the currently executing image.
    ///
    /// # Errors
    ///
    /// Returns an error outside Linux, for a non-canonical configured path,
    /// for a symlink, mount escape, hard-link alias, identity mismatch, or any
    /// instability observed while measuring the executable.
    pub fn capture(configured_artifact: &Path) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                state: linux::CurrentExecutableState::capture(configured_artifact)?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = configured_artifact;
            anyhow::bail!("qualifying B4 executor custody requires Linux")
        }
    }

    /// Reauthenticate the retained image and the complete configured path.
    ///
    /// # Errors
    ///
    /// Returns an error if the retained image changed or the configured path
    /// no longer resolves through the retained directory chain to that image.
    pub fn recheck(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.state.recheck()
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self;
            anyhow::bail!("qualifying B4 executor custody requires Linux")
        }
    }

    /// Borrow the exact retained executing-image bytes for one callback.
    ///
    /// The bytes are authenticated against the captured descriptor-rooted
    /// observation before the callback runs. They are not independent review
    /// evidence, and a value derived by the callback is not authorizing until
    /// this method returns successfully. The lifetime prevents the borrowed
    /// slice itself from escaping, but the callback can deliberately return an
    /// owned copy. On every normal `Result` exit after the entry check, custody
    /// is checked again; panic unwinding is outside that guarantee.
    ///
    /// The callback borrow cannot escape:
    ///
    /// ```compile_fail
    /// # use eip_0045_reproduction::b4_executor_custody::B4CurrentExecutableObservationV1;
    /// # fn cannot_escape(observation: &B4CurrentExecutableObservationV1) {
    /// let escaped: &[u8] = observation
    ///     .with_authenticated_bytes(|bytes| Ok(bytes))
    ///     .unwrap();
    /// # let _ = escaped;
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error outside Linux, if the retained bytes no longer match
    /// the captured observation, if the callback fails, or if the exit custody
    /// check fails.
    pub fn with_authenticated_bytes<T>(
        &self,
        effect: impl for<'bytes> FnOnce(&'bytes [u8]) -> Result<T>,
    ) -> Result<T> {
        #[cfg(target_os = "linux")]
        {
            self.state.with_authenticated_bytes(effect)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, effect);
            anyhow::bail!("qualifying B4 executor custody requires Linux")
        }
    }

    /// Require the retained image to match one authenticated raw artifact.
    ///
    /// The comparison is followed by a descriptor-rooted recheck so a matching
    /// digest alone cannot authorize a stale or substituted configured path.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid or non-raw artifact identity, a byte
    /// length or SHA-256 mismatch, or a failed custody recheck.
    pub fn require_artifact_identity(&self, expected: &B4ContractArtifactIdentityV1) -> Result<()> {
        expected.validate()?;
        anyhow::ensure!(
            expected.encoding == B4ContractArtifactEncodingV1::RawBytes,
            "campaign executor artifact must use raw-bytes encoding"
        );
        #[cfg(target_os = "linux")]
        {
            anyhow::ensure!(
                expected.byte_length == self.observed_byte_length(),
                "executing image byte length does not match the authenticated campaign artifact"
            );
            anyhow::ensure!(
                expected.sha256 == hex::encode(self.observed_sha256()),
                "executing image SHA-256 does not match the authenticated campaign artifact"
            );
            self.recheck()
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self;
            anyhow::bail!("qualifying B4 executor custody requires Linux")
        }
    }

    /// Observed executable SHA-256. It is not independently authorizing.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub const fn observed_sha256(&self) -> [u8; 32] {
        self.state.observed_sha256()
    }

    /// Observed executable byte length. It is not independently authorizing.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub const fn observed_byte_length(&self) -> u64 {
        self.state.observed_byte_length()
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        ffi::OsString,
        fs::File,
        os::{
            fd::{AsFd as _, BorrowedFd, OwnedFd},
            unix::{
                ffi::OsStrExt as _,
                fs::{FileExt as _, MetadataExt as _},
            },
        },
        path::{Component, Path, PathBuf},
    };

    use anyhow::{Context as _, Result, ensure};
    use sha2::{Digest as _, Sha256};

    const DIRECTORY_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY
        .union(rustix::fs::OFlags::DIRECTORY)
        .union(rustix::fs::OFlags::NOFOLLOW)
        .union(rustix::fs::OFlags::CLOEXEC);
    const FILE_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY
        .union(rustix::fs::OFlags::NOFOLLOW)
        .union(rustix::fs::OFlags::NONBLOCK)
        .union(rustix::fs::OFlags::CLOEXEC);
    const EXECUTING_IMAGE_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY
        .union(rustix::fs::OFlags::NONBLOCK)
        .union(rustix::fs::OFlags::CLOEXEC);
    const PATH_COMPONENT_RESOLVE_FLAGS: rustix::fs::ResolveFlags =
        rustix::fs::ResolveFlags::BENEATH
            .union(rustix::fs::ResolveFlags::NO_SYMLINKS)
            .union(rustix::fs::ResolveFlags::NO_MAGICLINKS);
    const FILE_RESOLVE_FLAGS: rustix::fs::ResolveFlags =
        PATH_COMPONENT_RESOLVE_FLAGS.union(rustix::fs::ResolveFlags::NO_XDEV);
    const MAX_CURRENT_EXECUTABLE_BYTES: u64 = 1024 * 1024 * 1024;
    const EXECUTABLE_MEASUREMENT_CHUNK_BYTES: usize = 256 * 1024;
    const MAX_ABSOLUTE_PATH_BYTES: usize = 4096;
    const MAX_ABSOLUTE_PATH_COMPONENTS: usize = 64;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct PhysicalIdentity {
        device: u64,
        inode: u64,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FileMetadata {
        identity: PhysicalIdentity,
        mount_id: u64,
        byte_length: u64,
        hard_link_count: u64,
        mode: u32,
        modified_seconds: i64,
        modified_nanoseconds: u64,
        changed_seconds: i64,
        changed_nanoseconds: u64,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct StableFileSnapshot {
        metadata: FileMetadata,
        sha256: [u8; 32],
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct DirectoryIdentity {
        physical: PhysicalIdentity,
        mount_id: u64,
    }

    pub(super) struct CurrentExecutableState {
        retained_image: File,
        configured_path: PinnedAbsoluteFilePath,
        snapshot: StableFileSnapshot,
    }

    impl CurrentExecutableState {
        pub(super) fn capture(configured_artifact: &Path) -> Result<Self> {
            let actual_descriptor = rustix::fs::open(
                "/proc/self/exe",
                EXECUTING_IMAGE_FLAGS,
                rustix::fs::Mode::empty(),
            )
            .context("cannot retain the Linux executing image through /proc/self/exe")?;
            let retained_image = File::from(actual_descriptor);
            let first = measure_open_file(
                &retained_image,
                Path::new("/proc/self/exe"),
                MAX_CURRENT_EXECUTABLE_BYTES,
            )?;
            let second = measure_open_file(
                &retained_image,
                Path::new("/proc/self/exe"),
                MAX_CURRENT_EXECUTABLE_BYTES,
            )?;
            ensure!(
                first == second,
                "executing image changed between retained measurements"
            );

            let configured_path =
                PinnedAbsoluteFilePath::open(configured_artifact, "configured executor artifact")?;
            let configured_file = configured_path.open_file()?;
            let configured = measure_open_file(
                &configured_file,
                configured_artifact,
                MAX_CURRENT_EXECUTABLE_BYTES,
            )?;
            ensure!(
                configured == second,
                "configured executor artifact does not name the executing image"
            );

            let final_retained = measure_open_file(
                &retained_image,
                Path::new("/proc/self/exe"),
                MAX_CURRENT_EXECUTABLE_BYTES,
            )?;
            ensure!(
                final_retained == second,
                "executing image changed while its configured path was authenticated"
            );
            let state = Self {
                retained_image,
                configured_path,
                snapshot: second,
            };
            state.recheck()?;
            Ok(state)
        }

        pub(super) fn recheck(&self) -> Result<()> {
            let before = measure_open_file(
                &self.retained_image,
                Path::new("/proc/self/exe"),
                MAX_CURRENT_EXECUTABLE_BYTES,
            )?;
            ensure!(
                before == self.snapshot,
                "retained executing-image observation changed"
            );

            self.configured_path.parent.reauthenticate()?;
            let configured = self.configured_path.open_file()?;
            let named = measure_open_file(
                &configured,
                &self.configured_path.diagnostic_path,
                MAX_CURRENT_EXECUTABLE_BYTES,
            )?;
            ensure!(
                named == self.snapshot,
                "configured executor artifact no longer names the executing image"
            );

            let after = measure_open_file(
                &self.retained_image,
                Path::new("/proc/self/exe"),
                MAX_CURRENT_EXECUTABLE_BYTES,
            )?;
            ensure!(
                after == self.snapshot,
                "retained executing-image observation changed during recheck"
            );
            self.configured_path.parent.reauthenticate()
        }

        pub(super) fn with_authenticated_bytes<T>(
            &self,
            effect: impl for<'bytes> FnOnce(&'bytes [u8]) -> Result<T>,
        ) -> Result<T> {
            self.recheck()?;
            let outcome = (|| {
                let (snapshot, bytes) = read_open_file_bytes(
                    &self.retained_image,
                    Path::new("/proc/self/exe"),
                    MAX_CURRENT_EXECUTABLE_BYTES,
                )?;
                ensure!(
                    snapshot == self.snapshot,
                    "retained executing-image bytes no longer match the captured observation"
                );
                effect(&bytes)
            })();
            let postcheck = self.recheck();
            match (outcome, postcheck) {
                (Ok(value), Ok(())) => Ok(value),
                (Err(error), Ok(())) => Err(error),
                (Ok(_), Err(postcheck)) => Err(postcheck)
                    .context("executable-byte callback completed but its custody postcheck failed"),
                (Err(effect), Err(postcheck)) => Err(postcheck).context(format!(
                    "executable-byte callback failed ({effect:#}) and its custody postcheck also failed"
                )),
            }
        }

        pub(super) const fn observed_sha256(&self) -> [u8; 32] {
            self.snapshot.sha256
        }

        pub(super) const fn observed_byte_length(&self) -> u64 {
            self.snapshot.metadata.byte_length
        }
    }

    struct PinnedAbsoluteFilePath {
        parent: PinnedAbsoluteDirectory,
        file_name: OsString,
        diagnostic_path: PathBuf,
    }

    impl PinnedAbsoluteFilePath {
        fn open(path: &Path, label: &str) -> Result<Self> {
            validate_absolute_lexical_path(path, label)?;
            let parent_path = path
                .parent()
                .context("configured executable path has no parent")?;
            let file_name = path
                .file_name()
                .context("configured executable path has no final component")?
                .to_os_string();
            let parent = PinnedAbsoluteDirectory::open(parent_path, label)?;
            let result = Self {
                parent,
                file_name,
                diagnostic_path: path.to_path_buf(),
            };
            let file = result.open_file()?;
            let metadata = opened_file_metadata(&file)?;
            ensure!(
                metadata.hard_link_count == 1,
                "{label} must have exactly one hard link"
            );
            Ok(result)
        }

        fn open_file(&self) -> Result<File> {
            let descriptor = rustix::fs::openat2(
                self.parent.descriptor(),
                self.file_name.as_os_str(),
                FILE_FLAGS,
                rustix::fs::Mode::empty(),
                FILE_RESOLVE_FLAGS,
            )
            .with_context(|| {
                format!(
                    "cannot open configured executor artifact {}",
                    self.diagnostic_path.display()
                )
            })?;
            Ok(File::from(descriptor))
        }
    }

    struct PinnedAbsoluteDirectory {
        anchor: OwnedFd,
        anchor_identity: DirectoryIdentity,
        components: Vec<OsString>,
        descriptors: Vec<OwnedFd>,
        identities: Vec<DirectoryIdentity>,
        diagnostic_path: PathBuf,
    }

    impl PinnedAbsoluteDirectory {
        fn open(path: &Path, label: &str) -> Result<Self> {
            validate_absolute_lexical_directory(path, label)?;
            let anchor = rustix::fs::open("/", DIRECTORY_FLAGS, rustix::fs::Mode::empty())
                .with_context(|| format!("cannot pin {label} filesystem anchor"))?;
            let anchor_identity = directory_identity(anchor.as_fd())?;
            let components = path
                .components()
                .filter_map(|component| match component {
                    Component::Normal(value) => Some(value.to_os_string()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let mut descriptors = Vec::new();
            let mut identities = Vec::new();
            descriptors
                .try_reserve_exact(components.len())
                .with_context(|| format!("cannot retain {label} descriptor chain"))?;
            identities
                .try_reserve_exact(components.len())
                .with_context(|| format!("cannot retain {label} identity chain"))?;
            for (index, component) in components.iter().enumerate() {
                let parent = descriptors
                    .last()
                    .map_or_else(|| anchor.as_fd(), OwnedFd::as_fd);
                let descriptor = rustix::fs::openat2(
                    parent,
                    component.as_os_str(),
                    DIRECTORY_FLAGS,
                    rustix::fs::Mode::empty(),
                    PATH_COMPONENT_RESOLVE_FLAGS,
                )
                .with_context(|| {
                    format!(
                        "cannot pin {label} component {index} beneath {}",
                        path.display()
                    )
                })?;
                identities.push(directory_identity(descriptor.as_fd())?);
                descriptors.push(descriptor);
            }
            Ok(Self {
                anchor,
                anchor_identity,
                components,
                descriptors,
                identities,
                diagnostic_path: path.to_path_buf(),
            })
        }

        fn descriptor(&self) -> BorrowedFd<'_> {
            self.descriptors
                .last()
                .map_or_else(|| self.anchor.as_fd(), OwnedFd::as_fd)
        }

        fn reauthenticate(&self) -> Result<()> {
            ensure!(
                directory_identity(self.anchor.as_fd())? == self.anchor_identity,
                "retained directory anchor identity changed for {}",
                self.diagnostic_path.display()
            );
            for (index, (descriptor, identity)) in
                self.descriptors.iter().zip(&self.identities).enumerate()
            {
                ensure!(
                    directory_identity(descriptor.as_fd())? == *identity,
                    "retained directory component {index} changed for {}",
                    self.diagnostic_path.display()
                );
            }

            let reopened_anchor = rustix::fs::openat2(
                self.anchor.as_fd(),
                ".",
                DIRECTORY_FLAGS,
                rustix::fs::Mode::empty(),
                FILE_RESOLVE_FLAGS,
            )
            .with_context(|| {
                format!(
                    "cannot reopen directory anchor for {}",
                    self.diagnostic_path.display()
                )
            })?;
            ensure!(
                directory_identity(reopened_anchor.as_fd())? == self.anchor_identity,
                "directory anchor no longer names retained identity for {}",
                self.diagnostic_path.display()
            );
            let mut reopened = Vec::new();
            reopened
                .try_reserve_exact(self.components.len())
                .context("cannot retain reauthenticated directory chain")?;
            for (index, (component, identity)) in
                self.components.iter().zip(&self.identities).enumerate()
            {
                let parent = reopened
                    .last()
                    .map_or_else(|| reopened_anchor.as_fd(), OwnedFd::as_fd);
                let descriptor = rustix::fs::openat2(
                    parent,
                    component.as_os_str(),
                    DIRECTORY_FLAGS,
                    rustix::fs::Mode::empty(),
                    PATH_COMPONENT_RESOLVE_FLAGS,
                )
                .with_context(|| {
                    format!(
                        "cannot reopen directory component {index} for {}",
                        self.diagnostic_path.display()
                    )
                })?;
                ensure!(
                    directory_identity(descriptor.as_fd())? == *identity,
                    "directory path no longer names retained component {index} for {}",
                    self.diagnostic_path.display()
                );
                reopened.push(descriptor);
            }
            Ok(())
        }
    }

    fn validate_absolute_lexical_path(path: &Path, label: &str) -> Result<()> {
        validate_absolute_lexical(path, label)?;
        ensure!(
            path.as_os_str().as_bytes() != b"/",
            "{label} path is too broad"
        );
        Ok(())
    }

    fn validate_absolute_lexical_directory(path: &Path, label: &str) -> Result<()> {
        validate_absolute_lexical(path, label)
    }

    fn validate_absolute_lexical(path: &Path, label: &str) -> Result<()> {
        let bytes = path.as_os_str().as_bytes();
        ensure!(path.is_absolute(), "{label} path must be absolute");
        ensure!(
            bytes.starts_with(b"/"),
            "{label} path has an unsupported prefix"
        );
        ensure!(
            bytes.len() <= MAX_ABSOLUTE_PATH_BYTES,
            "{label} path exceeds the compiled byte bound"
        );
        ensure!(
            bytes == b"/" || !bytes.ends_with(b"/"),
            "{label} path has a trailing separator"
        );
        ensure!(
            !bytes.windows(2).any(|pair| pair == b"//"),
            "{label} path has an empty component"
        );
        let mut component_count = 0_usize;
        for component in bytes.split(|byte| *byte == b'/').skip(1) {
            ensure!(
                component != b"." && component != b"..",
                "{label} path contains a dot or parent component"
            );
            component_count = component_count
                .checked_add(1)
                .context("absolute path component count overflowed")?;
        }
        ensure!(
            component_count <= MAX_ABSOLUTE_PATH_COMPONENTS,
            "{label} path exceeds the compiled component bound"
        );
        Ok(())
    }

    fn directory_identity(descriptor: BorrowedFd<'_>) -> Result<DirectoryIdentity> {
        let stat = rustix::fs::fstat(descriptor).context("cannot inspect opened directory")?;
        ensure!(
            rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir(),
            "opened descriptor is not an ordinary directory"
        );
        Ok(DirectoryIdentity {
            physical: PhysicalIdentity {
                device: stat.st_dev,
                inode: stat.st_ino,
            },
            mount_id: descriptor_mount_id(descriptor)?,
        })
    }

    fn opened_file_metadata(file: &File) -> Result<FileMetadata> {
        let metadata = file.metadata().context("cannot inspect opened file")?;
        ensure!(
            metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
            "opened descriptor is not an ordinary regular file"
        );
        ensure!(
            metadata.nlink() == 1,
            "opened ordinary file must have exactly one hard link"
        );
        Ok(FileMetadata {
            identity: PhysicalIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            mount_id: descriptor_mount_id(file.as_fd())?,
            byte_length: metadata.len(),
            hard_link_count: metadata.nlink(),
            mode: metadata.mode(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: u64::try_from(metadata.mtime_nsec())
                .context("file modification nanoseconds are negative")?,
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: u64::try_from(metadata.ctime_nsec())
                .context("file change nanoseconds are negative")?,
        })
    }

    fn descriptor_mount_id(descriptor: BorrowedFd<'_>) -> Result<u64> {
        let statx = rustix::fs::statx(
            descriptor,
            "",
            rustix::fs::AtFlags::EMPTY_PATH,
            rustix::fs::StatxFlags::BASIC_STATS | rustix::fs::StatxFlags::MNT_ID,
        )
        .context("cannot obtain the opened descriptor mount identity")?;
        ensure!(
            rustix::fs::StatxFlags::from_bits_retain(statx.stx_mask)
                .contains(rustix::fs::StatxFlags::MNT_ID),
            "Linux statx did not return a mount identity"
        );
        Ok(statx.stx_mnt_id)
    }

    #[cfg(test)]
    mod measurement_tests {
        use std::io::Write as _;

        use super::*;

        #[test]
        fn measurement_digest_and_length_cross_chunk_boundaries() {
            assert_eq!(EXECUTABLE_MEASUREMENT_CHUNK_BYTES, 256 * 1024);
            for byte_length in [
                EXECUTABLE_MEASUREMENT_CHUNK_BYTES - 1,
                EXECUTABLE_MEASUREMENT_CHUNK_BYTES,
                EXECUTABLE_MEASUREMENT_CHUNK_BYTES + 17,
            ] {
                let bytes = (0..byte_length)
                    .map(|index| u8::try_from((index * 31 + 7) % 251).unwrap())
                    .collect::<Vec<_>>();
                let mut file = tempfile::NamedTempFile::new().unwrap();
                file.write_all(&bytes).unwrap();
                file.as_file().sync_all().unwrap();

                let snapshot = measure_open_file(
                    file.as_file(),
                    file.path(),
                    u64::try_from(byte_length).unwrap(),
                )
                .unwrap();
                let expected_sha256: [u8; 32] = Sha256::digest(&bytes).into();
                assert_eq!(
                    snapshot.metadata.byte_length,
                    u64::try_from(byte_length).unwrap()
                );
                assert_eq!(snapshot.sha256, expected_sha256);
            }
        }
    }

    fn measure_open_file(
        file: &File,
        diagnostic: &Path,
        maximum: u64,
    ) -> Result<StableFileSnapshot> {
        let before = opened_file_metadata(file)?;
        ensure!(
            before.byte_length <= maximum,
            "{} exceeds its compiled custody bound",
            diagnostic.display()
        );
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; EXECUTABLE_MEASUREMENT_CHUNK_BYTES];
        let mut observed_length = 0_u64;
        loop {
            let count = file
                .read_at(&mut buffer, observed_length)
                .with_context(|| format!("cannot read {}", diagnostic.display()))?;
            if count == 0 {
                break;
            }
            observed_length = observed_length
                .checked_add(u64::try_from(count)?)
                .context("opened-file byte count overflowed")?;
            ensure!(
                observed_length <= maximum,
                "{} exceeds its compiled custody bound",
                diagnostic.display()
            );
            hasher.update(&buffer[..count]);
        }
        let after = opened_file_metadata(file)?;
        ensure!(
            before == after && observed_length == before.byte_length,
            "{} changed while being measured",
            diagnostic.display()
        );
        Ok(StableFileSnapshot {
            metadata: after,
            sha256: hasher.finalize().into(),
        })
    }

    fn read_open_file_bytes(
        file: &File,
        diagnostic: &Path,
        maximum: u64,
    ) -> Result<(StableFileSnapshot, Vec<u8>)> {
        let before = opened_file_metadata(file)?;
        ensure!(
            before.byte_length <= maximum,
            "{} exceeds its compiled custody bound",
            diagnostic.display()
        );
        let expected_length = usize::try_from(before.byte_length)
            .context("opened-file byte length does not fit in memory")?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(expected_length)
            .with_context(|| format!("cannot reserve bytes for {}", diagnostic.display()))?;
        bytes.resize(expected_length, 0);

        let mut offset = 0_usize;
        while offset < expected_length {
            let descriptor_offset =
                u64::try_from(offset).context("opened-file byte offset does not fit in u64")?;
            let count = file
                .read_at(&mut bytes[offset..], descriptor_offset)
                .with_context(|| format!("cannot read {}", diagnostic.display()))?;
            ensure!(
                count != 0,
                "{} changed while being read",
                diagnostic.display()
            );
            offset = offset
                .checked_add(count)
                .context("opened-file byte count overflowed")?;
        }

        let mut trailing = [0_u8; 1];
        let trailing_count = file
            .read_at(&mut trailing, before.byte_length)
            .with_context(|| format!("cannot verify the end of {}", diagnostic.display()))?;
        let after = opened_file_metadata(file)?;
        ensure!(
            before == after && trailing_count == 0,
            "{} changed while being read",
            diagnostic.display()
        );
        let snapshot = StableFileSnapshot {
            metadata: after,
            sha256: Sha256::digest(&bytes).into(),
        };
        Ok((snapshot, bytes))
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::B4CurrentExecutableObservationV1;

    #[test]
    fn custody_requires_linux_before_path_inspection() {
        if cfg!(target_os = "linux") {
            return;
        }
        let error =
            B4CurrentExecutableObservationV1::capture(Path::new("missing-relative-executable"))
                .unwrap_err();
        assert!(error.to_string().contains("requires Linux"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn wrong_configured_path_is_rejected() {
        use crate::b4_campaign_contract::{
            B4ContractArtifactEncodingV1, B4ContractArtifactIdentityV1,
        };

        let executable = std::fs::read_link("/proc/self/exe").unwrap();
        let observation = B4CurrentExecutableObservationV1::capture(&executable).unwrap();
        observation.recheck().unwrap();
        let executable_bytes = std::fs::read(&executable).unwrap();
        let identity = B4ContractArtifactIdentityV1::from_bytes(
            "executor",
            B4ContractArtifactEncodingV1::RawBytes,
            &executable_bytes,
        )
        .unwrap();
        observation.require_artifact_identity(&identity).unwrap();
        let wrong_identity = B4ContractArtifactIdentityV1::from_bytes(
            "executor",
            B4ContractArtifactEncodingV1::RawBytes,
            b"not-the-executing-image",
        )
        .unwrap();
        let identity_error = observation
            .require_artifact_identity(&wrong_identity)
            .unwrap_err();
        assert!(
            identity_error.to_string().contains("byte length")
                || identity_error.to_string().contains("SHA-256")
        );

        let temp = tempfile::tempdir().unwrap();
        let copied = temp.path().join("wrong-executable");
        std::fs::copy(executable, &copied).unwrap();
        let error = B4CurrentExecutableObservationV1::capture(&copied).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not name the executing image")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_executable_bytes_are_exact_and_callback_scoped() {
        use sha2::{Digest as _, Sha256};

        let executable = std::fs::read_link("/proc/self/exe").unwrap();
        let expected = std::fs::read(&executable).unwrap();
        let observation = B4CurrentExecutableObservationV1::capture(&executable).unwrap();

        let (observed_length, observed_sha256) = observation
            .with_authenticated_bytes(|bytes| {
                assert_eq!(bytes, expected);
                Ok((bytes.len(), <[u8; 32]>::from(Sha256::digest(bytes))))
            })
            .unwrap();

        assert_eq!(observed_length as u64, observation.observed_byte_length());
        assert_eq!(observed_sha256, observation.observed_sha256());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authenticated_byte_callback_error_is_propagated_after_green_postcheck() {
        use std::cell::Cell;

        use sha2::{Digest as _, Sha256};

        let executable = std::fs::read_link("/proc/self/exe").unwrap();
        let observation = B4CurrentExecutableObservationV1::capture(&executable).unwrap();
        let invocation_count = Cell::new(0_u8);

        let error = observation
            .with_authenticated_bytes(|bytes| -> anyhow::Result<()> {
                invocation_count.set(invocation_count.get() + 1);
                assert_eq!(bytes.len() as u64, observation.observed_byte_length());
                assert_eq!(
                    <[u8; 32]>::from(Sha256::digest(bytes)),
                    observation.observed_sha256()
                );
                anyhow::bail!("injected executable-byte callback failure")
            })
            .unwrap_err();

        assert_eq!(invocation_count.get(), 1);
        assert_eq!(
            error.to_string(),
            "injected executable-byte callback failure"
        );
        observation.recheck().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn concurrent_rechecks_and_authenticated_byte_callbacks_are_offset_independent() {
        use std::sync::{Arc, Barrier};

        use sha2::{Digest as _, Sha256};

        let executable = std::fs::read_link("/proc/self/exe").unwrap();
        let observation = B4CurrentExecutableObservationV1::capture(&executable).unwrap();
        let barrier = Arc::new(Barrier::new(4));

        std::thread::scope(|scope| {
            for _ in 0..3 {
                let barrier = Arc::clone(&barrier);
                let observation = &observation;
                scope.spawn(move || {
                    barrier.wait();
                    observation
                        .with_authenticated_bytes(|bytes| {
                            assert_eq!(bytes.len() as u64, observation.observed_byte_length());
                            assert_eq!(
                                <[u8; 32]>::from(Sha256::digest(bytes)),
                                observation.observed_sha256()
                            );
                            Ok(())
                        })
                        .unwrap();
                });
            }
            barrier.wait();
            observation.recheck().unwrap();
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authenticated_byte_callback_error_still_runs_failing_path_postcheck() {
        use std::process::Command;

        use sha2::{Digest as _, Sha256};

        const CHILD_MARKER: &str = "EIP0045_B4_EXECUTABLE_BYTE_POSTCHECK_CHILD";
        if let Some(mode) = std::env::var_os(CHILD_MARKER) {
            let executable = std::fs::read_link("/proc/self/exe").unwrap();
            let observation = B4CurrentExecutableObservationV1::capture(&executable).unwrap();
            let retained_name = executable.with_extension("callback-retained-image");

            let error = observation
                .with_authenticated_bytes(|bytes| -> anyhow::Result<u8> {
                    assert_eq!(bytes.len() as u64, observation.observed_byte_length());
                    assert_eq!(
                        <[u8; 32]>::from(Sha256::digest(bytes)),
                        observation.observed_sha256()
                    );
                    std::fs::rename(&executable, &retained_name).unwrap();
                    std::fs::copy(&retained_name, &executable).unwrap();
                    if mode == "error" {
                        anyhow::bail!("injected executable-byte callback failure")
                    }
                    Ok(73)
                })
                .unwrap_err();

            std::fs::remove_file(&executable).unwrap();
            std::fs::rename(&retained_name, &executable).unwrap();
            let message = format!("{error:#}");
            if mode == "error" {
                assert!(
                    message.contains("injected executable-byte callback failure"),
                    "callback error missing from combined failure: {message}"
                );
                assert!(
                    message.contains("custody postcheck also failed"),
                    "postcheck context missing from combined failure: {message}"
                );
            } else {
                assert!(
                    message.contains("callback completed but its custody postcheck failed"),
                    "successful callback value was not suppressed by its postcheck: {message}"
                );
            }
            assert!(
                message.contains("retained executing-image observation changed")
                    || message.contains("no longer names the executing image"),
                "executable-custody failure missing from combined failure: {message}"
            );
            return;
        }

        let temp = tempfile::tempdir().unwrap();
        let copied_runner = temp.path().join("byte-postcheck-test-runner");
        std::fs::copy(
            std::fs::read_link("/proc/self/exe").unwrap(),
            &copied_runner,
        )
        .unwrap();
        for mode in ["error", "success"] {
            let status = Command::new(&copied_runner)
                .env(CHILD_MARKER, mode)
                .args([
                    "b4_executor_custody::tests::authenticated_byte_callback_error_still_runs_failing_path_postcheck",
                    "--exact",
                    "--test-threads=1",
                ])
                .status()
                .unwrap();
            assert!(status.success(), "{mode} child failed");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authenticated_byte_callback_is_descriptor_rooted_and_positionally_read() {
        fn between<'source>(source: &'source str, start: &str, end: &str) -> &'source str {
            let (_, remainder) = source.split_once(start).unwrap();
            let (section, _) = remainder.split_once(end).unwrap();
            section
        }

        let source = include_str!("b4_executor_custody.rs");
        let state_method = between(
            source,
            "        pub(super) fn with_authenticated_bytes<T>(",
            "        pub(super) const fn observed_sha256",
        );
        assert!(state_method.contains("self.recheck()?;"));
        assert!(state_method.contains("read_open_file_bytes("));
        assert!(state_method.contains("&self.retained_image"));
        assert!(state_method.contains("let postcheck = self.recheck();"));
        let normalized_state_method = state_method
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(normalized_state_method.contains(
            "read_open_file_bytes( &self.retained_image, Path::new(\"/proc/self/exe\"),"
        ));
        for forbidden in [
            "configured_path",
            "std::fs::read",
            "fs::read",
            "File::open",
            "OpenOptions",
            "rustix::fs::open",
            "try_clone",
            ".read(",
            ".seek(",
            "SeekFrom",
        ] {
            assert!(
                !state_method.contains(forbidden),
                "authenticated byte callback must not contain {forbidden}"
            );
        }

        let measurement = between(
            source,
            "    fn measure_open_file(",
            "    fn read_open_file_bytes(",
        );
        let byte_reader = between(
            source,
            "    fn read_open_file_bytes(",
            "\n}\n\n#[cfg(test)]",
        );
        assert!(measurement.contains(".read_at("));
        assert!(byte_reader.matches(".read_at(").count() >= 2);
        for forbidden in [
            "std::fs::read",
            "fs::read",
            "File::open",
            "OpenOptions",
            "rustix::fs::open",
            "try_clone",
            ".read(",
            ".seek(",
            "SeekFrom",
        ] {
            assert!(!measurement.contains(forbidden));
            assert!(!byte_reader.contains(forbidden));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn hardlink_and_path_replacement_are_rejected() {
        use std::process::Command;

        const CHILD_MARKER: &str = "EIP0045_B4_EXECUTABLE_CUSTODY_CHILD";
        if std::env::var_os(CHILD_MARKER).is_some() {
            let executable = std::fs::read_link("/proc/self/exe").unwrap();
            let hardlink = executable.with_extension("hardlink");
            std::fs::hard_link(&executable, &hardlink).unwrap();
            let error = B4CurrentExecutableObservationV1::capture(&executable).unwrap_err();
            std::fs::remove_file(&hardlink).unwrap();
            assert!(error.to_string().contains("exactly one hard link"));

            let observation = B4CurrentExecutableObservationV1::capture(&executable).unwrap();
            let retained_name = executable.with_extension("retained-image");
            std::fs::rename(&executable, &retained_name).unwrap();
            std::fs::copy(&retained_name, &executable).unwrap();
            let error = observation.recheck().unwrap_err();
            let callback_invoked = std::cell::Cell::new(false);
            let callback_error = observation
                .with_authenticated_bytes(|_bytes| {
                    callback_invoked.set(true);
                    Ok(())
                })
                .unwrap_err();
            assert!(!callback_invoked.get());
            std::fs::remove_file(&executable).unwrap();
            std::fs::rename(&retained_name, &executable).unwrap();
            let message = error.to_string();
            assert!(
                message.contains("retained executing-image observation changed")
                    || message.contains("no longer names the executing image"),
                "unexpected executable-replacement rejection: {error:#}"
            );
            let callback_message = callback_error.to_string();
            assert!(
                callback_message.contains("retained executing-image observation changed")
                    || callback_message.contains("no longer names the executing image"),
                "unexpected callback entry rejection: {callback_error:#}"
            );
            return;
        }

        let temp = tempfile::tempdir().unwrap();
        let copied_runner = temp.path().join("custody-test-runner");
        std::fs::copy(
            std::fs::read_link("/proc/self/exe").unwrap(),
            &copied_runner,
        )
        .unwrap();
        let status = Command::new(&copied_runner)
            .env(CHILD_MARKER, "1")
            .args([
                "b4_executor_custody::tests::hardlink_and_path_replacement_are_rejected",
                "--exact",
                "--test-threads=1",
            ])
            .status()
            .unwrap();
        assert!(status.success());
    }
}
