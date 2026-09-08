//! Private descriptor-rooted logical staging for authenticated OCI root filesystems.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs::File,
    ops::Bound,
    os::{
        fd::{AsFd as _, BorrowedFd, OwnedFd},
        unix::{ffi::OsStrExt as _, fs::FileExt as _},
    },
    path::{Component, Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use eip_0045_reproduction::b4_positive_gate::{B4PositiveOciImageLayoutV1, PositiveRunnerRole};
use sha2::{Digest as _, Sha256};

#[cfg(test)]
use std::cell::Cell;

use super::super::artifact_import_contract::B4ImmutableArtifactRoleV1;
use super::{
    AuthenticatedOciLayerSealV1,
    json::OciExpectedRootfsV1,
    layer::{
        ChangesetTranscriptV1, OciLayerReplayEntryKindV1, OciLayerReplayEntryV1,
        OciLayerReplaySinkV1, OciLayerReplayWhiteoutV1,
    },
};

mod physical;

const PINNED_DIRECTORY_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY
    .union(rustix::fs::OFlags::DIRECTORY)
    .union(rustix::fs::OFlags::NOFOLLOW)
    .union(rustix::fs::OFlags::CLOEXEC);
const ANONYMOUS_SPOOL_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDWR
    .union(rustix::fs::OFlags::TMPFILE)
    .union(rustix::fs::OFlags::EXCL)
    .union(rustix::fs::OFlags::CLOEXEC);
const PRIVATE_SPOOL_MODE: rustix::fs::Mode = rustix::fs::Mode::RUSR.union(rustix::fs::Mode::WUSR);
const PERMISSION_AND_SPECIAL_BITS: u32 = 0o7777;
const PARENT_COMPONENT_RESOLVE_FLAGS: rustix::fs::ResolveFlags = rustix::fs::ResolveFlags::BENEATH
    .union(rustix::fs::ResolveFlags::NO_SYMLINKS)
    .union(rustix::fs::ResolveFlags::NO_MAGICLINKS);
const ANONYMOUS_SPOOL_RESOLVE_FLAGS: rustix::fs::ResolveFlags =
    PARENT_COMPONENT_RESOLVE_FLAGS.union(rustix::fs::ResolveFlags::NO_XDEV);
const OCI_ROOTFS_PARENT_MAX_BYTES: usize = 4_096;
const OCI_ROOTFS_PARENT_MAX_COMPONENTS: usize = 64;
const OCI_ROOTFS_NAME_MAX_BYTES: usize = 255;
const OCI_LAYER_PATH_MAX_BYTES: usize = 240;
const OCI_SYMLINK_TARGET_MAX_BYTES: usize = 100;
const OCI_REPLAY_CHUNK_MAX_BYTES: usize = 16 * 1_024;
const SHA256_BYTES: usize = 32;
// This is a conservative logical reservation policy, not a portable heap or
// RSS measurement. It intentionally reserves geometric Vec slack, one
// candidate-tree slot per operation, fixed layer state and validation scratch.
const OCI_ROOTFS_LOGICAL_METADATA_MAX_BYTES: u64 = 896 * 1_024 * 1_024;
const OCI_ROOTFS_LOGICAL_METADATA_BASE_RESERVATION_BYTES: u64 = 128 * 1_024;
const OCI_ROOTFS_OPERATION_METADATA_RESERVATION_BYTES: u64 = 192;
const OCI_ROOTFS_SOURCE_INDEX_METADATA_RESERVATION_BYTES: u64 = 16;
const OCI_ROOTFS_LIVE_INDEX_METADATA_RESERVATION_BYTES: u64 = 16;
const OCI_ROOTFS_OWNED_STRING_METADATA_RESERVATION_BYTES: u64 = 32;
const OCI_ROOTFS_CANDIDATE_NODE_METADATA_RESERVATION_BYTES: u64 = 256;
const OCI_ROOTFS_REGULAR_EXTENT_METADATA_RESERVATION_BYTES: u64 = 160;

/// Pure, affine projection of one private logical rootfs destination.
///
/// The absolute path is consumed while its parent chain is pinned. The live
/// transaction retains the components only to detect nominal-parent drift;
/// every filesystem effect remains rooted at retained descriptors.
struct OciRootfsStagingLayoutV1 {
    role: PositiveRunnerRole,
    parent: PathBuf,
    final_name: OsString,
}

/// Source position authenticated by the manifest layer order and the layer ustar.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct OciRootfsSourceOrdinalV1 {
    semantic_layer_index: u64,
    archive_entry_index: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum OciRootfsEffectPhaseV1 {
    Whiteout,
    Entry,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct OciRootfsEffectOrdinalV1 {
    semantic_layer_index: u64,
    phase: OciRootfsEffectPhaseV1,
    archive_entry_index: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OciRootfsEffectReferenceV1 {
    operation_index: usize,
    ordinal: OciRootfsEffectOrdinalV1,
}

#[derive(Debug)]
enum StagedRootfsOperationKindV1 {
    Regular { extent_index: usize },
    Directory,
    SymbolicLink { target: String },
    Remove { target: String },
    OpaqueDirectory { path: String },
}

#[derive(Clone, Copy)]
enum StagedRootfsOperationKindRefV1<'value> {
    Regular { extent_index: usize },
    Directory,
    SymbolicLink { target: &'value str },
    Remove { target: &'value str },
    OpaqueDirectory { path: &'value str },
}

impl StagedRootfsOperationKindV1 {
    fn as_ref(&self) -> StagedRootfsOperationKindRefV1<'_> {
        match self {
            Self::Regular { extent_index } => StagedRootfsOperationKindRefV1::Regular {
                extent_index: *extent_index,
            },
            Self::Directory => StagedRootfsOperationKindRefV1::Directory,
            Self::SymbolicLink { target } => {
                StagedRootfsOperationKindRefV1::SymbolicLink { target }
            }
            Self::Remove { target } => StagedRootfsOperationKindRefV1::Remove { target },
            Self::OpaqueDirectory { path } => {
                StagedRootfsOperationKindRefV1::OpaqueDirectory { path }
            }
        }
    }
}

impl<'value> StagedRootfsOperationKindRefV1<'value> {
    fn metadata_parts(self) -> (Option<&'value str>, bool) {
        match self {
            Self::Regular { .. } => (None, true),
            Self::Directory => (None, false),
            Self::SymbolicLink { target } | Self::Remove { target } => (Some(target), false),
            Self::OpaqueDirectory { path } => (Some(path), false),
        }
    }

    fn try_to_owned(self) -> Result<StagedRootfsOperationKindV1> {
        Ok(match self {
            Self::Regular { extent_index } => StagedRootfsOperationKindV1::Regular { extent_index },
            Self::Directory => StagedRootfsOperationKindV1::Directory,
            Self::SymbolicLink { target } => StagedRootfsOperationKindV1::SymbolicLink {
                target: try_owned_rootfs_string(target, "OCI rootfs symbolic-link target")?,
            },
            Self::Remove { target } => StagedRootfsOperationKindV1::Remove {
                target: try_owned_rootfs_string(target, "OCI rootfs whiteout target")?,
            },
            Self::OpaqueDirectory { path } => StagedRootfsOperationKindV1::OpaqueDirectory {
                path: try_owned_rootfs_string(path, "OCI rootfs opaque whiteout subject")?,
            },
        })
    }
}

#[derive(Debug)]
struct StagedRootfsOperationV1 {
    source: OciRootfsSourceOrdinalV1,
    path: String,
    mode: u32,
    byte_length: u64,
    kind: StagedRootfsOperationKindV1,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct OciRootfsLiveCountersV1 {
    entry_count: u64,
    regular_file_count: u64,
    directory_count: u64,
    symbolic_link_count: u64,
    regular_file_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootfsPathProjectionV1 {
    live_definition: usize,
    last_effect: OciRootfsEffectReferenceV1,
}

#[derive(Debug, Default)]
struct RootfsProjectionV1<'journal> {
    paths: BTreeMap<&'journal str, RootfsPathProjectionV1>,
    root_last_effect: Option<OciRootfsEffectReferenceV1>,
    counters: OciRootfsLiveCountersV1,
    #[cfg(test)]
    subtree_candidate_visits: u64,
    #[cfg(test)]
    definitions_inserted: u64,
}

struct ValidatedOciRootfsProjectionV1 {
    canonical_live_operation_indices: Vec<usize>,
    counters: OciRootfsLiveCountersV1,
    authenticated_logical_projection_sha256: [u8; SHA256_BYTES],
}

impl OciRootfsStagingLayoutV1 {
    fn project(role: PositiveRunnerRole, final_rootfs: &Path) -> Result<Self> {
        validate_normalized_absolute_rootfs_path(final_rootfs)?;
        let parent = final_rootfs
            .parent()
            .context("OCI rootfs final path has no parent")?
            .to_path_buf();
        let final_name = final_rootfs
            .file_name()
            .context("OCI rootfs final path has no basename")?;
        let final_text = final_name
            .to_str()
            .context("OCI rootfs final basename is not UTF-8")?;
        validate_root_leaf(final_text, "OCI rootfs final basename")?;
        ensure!(
            final_name.as_bytes().len() <= OCI_ROOTFS_NAME_MAX_BYTES,
            "OCI rootfs final basename exceeds its compiled byte bound"
        );
        Ok(Self {
            role,
            parent,
            final_name: final_name.to_os_string(),
        })
    }
}

/// In-progress private logical OCI rootfs transaction.
///
/// All regular-file bytes share one anonymous, unlinkable spool. Paths, modes
/// and extents remain inert logical data. The calling thread's retained mount
/// namespace qualifies every numeric mount ID without granting namespace
/// creation, deletion, rename, linking or final-name transition authority.
#[must_use = "private OCI rootfs staging must be explicitly discarded"]
pub(super) struct PrivateOciRootfsStagingTransactionV1 {
    role: PositiveRunnerRole,
    current_mount_namespace: physical::PinnedCurrentMountNamespaceV1,
    parent: PinnedAbsoluteDirectoryPath,
    final_name: OsString,
    spool: File,
    spool_identity: FileIdentity,
    spool_owner: u64,
    spool_group: u64,
    expected_semantic_layers: u64,
    captured_layer_entries: Vec<u64>,
    sealed_layer_entries: Vec<Option<u64>>,
    captured_layer_transcripts: Vec<Sha256>,
    sealed_layer_transcripts: Vec<Option<[u8; SHA256_BYTES]>>,
    captured_canonical_layer_transcripts: Vec<ChangesetTranscriptV1>,
    authenticated_canonical_layer_transcripts: Vec<Option<[u8; SHA256_BYTES]>>,
    physical_regular_extents: Vec<StagedRegularExtentV1>,
    operations: Vec<StagedRootfsOperationV1>,
    operations_by_source: Vec<Vec<usize>>,
    open_regular: Option<OpenRegularExtentV1>,
    open_inert_entry: bool,
    physical_regular_bytes: u64,
    logical_metadata_bytes: u64,
    validated_live_rootfs: Option<OciRootfsLiveCountersV1>,
    poisoned: bool,
    #[cfg(test)]
    descriptor_observations: Cell<u64>,
    #[cfg(test)]
    candidate_sync_calls: Cell<u64>,
    #[cfg(test)]
    candidate_extent_bytes_read: Cell<u64>,
}

/// Affine, namespace-qualified custody of one authenticated logical OCI rootfs.
///
/// The retained transaction owns the anonymous regular-file spool and the
/// complete authenticated journal. Canonical live indices and the versioned
/// logical identity are inert private data for the future specialized
/// materializer; no path, descriptor, reader or generic replay capability is
/// exposed through this type.
#[must_use = "the authenticated OCI rootfs projection must be consumed"]
pub(super) struct AuthenticatedPrivateOciRootfsProjectionV1 {
    transaction: PrivateOciRootfsStagingTransactionV1,
    canonical_live_operation_indices: Vec<usize>,
    counters: OciRootfsLiveCountersV1,
    authenticated_logical_projection_sha256: [u8; SHA256_BYTES],
    #[cfg(test)]
    test_only_physical_materialization_failpoint:
        Option<physical::TestOnlyPrivateMaterializationFailpointV1>,
}

/// Affine custody of one authenticated host rootfs and its startup baseline.
///
/// This non-authorizing wrapper exposes only exact static-dependency
/// reauthentication and explicit cleanup. It grants no mount, child-launch,
/// execution, observation, publication, or completion authority.
#[must_use = "retained OCI host-rootfs custody must be reauthenticated and explicitly cleaned"]
pub(super) struct AuthenticatedPrivateOciRetainedRootfsV1 {
    physical: physical::AuthenticatedPrivateOciRetainedPhysicalRootfsV1,
}

/// Affine failure while acquiring one authenticated retained host rootfs.
///
/// This non-authorizing wrapper distinguishes an already-closed rejection from
/// retry custody without exposing physical state. A caller must consume it to
/// recover the complete structured rejection after any required cleanup.
#[must_use = "failed retained OCI rootfs acquisition must be explicitly closed"]
pub(super) struct PrivateOciRetainedRootfsAcquisitionFailureV1 {
    state: PrivateOciRetainedRootfsAcquisitionFailureStateV1,
}

enum PrivateOciRetainedRootfsAcquisitionFailureStateV1 {
    NonRetry(anyhow::Error),
    RetryCustody(physical::PrivateOciRootfsCleanupFailureV1),
}

/// Affine cleanup failure that preserves the structured closeout outcome and
/// may retain private retained-rootfs retry custody.
///
/// This non-authorizing wrapper exposes only a consuming cleanup transition;
/// a terminal failure remains owned without implying retry custody. It carries
/// no mount, child-launch, execution, observation, or publication authority.
#[must_use = "failed retained OCI rootfs cleanup must be explicitly consumed or retained"]
pub(super) struct PrivateOciRetainedRootfsCleanupFailureV1 {
    physical: physical::PrivateOciRootfsCleanupFailureV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OciRootfsReplayEntryStateV1 {
    None,
    Regular,
    Inert,
}

struct PrivateOciRootfsLayerReplaySinkV1<'transaction> {
    transaction: &'transaction mut PrivateOciRootfsStagingTransactionV1,
    semantic_layer_index: u64,
    entry_state: OciRootfsReplayEntryStateV1,
}

struct OciRootfsLayerJournalsV1 {
    captured_layer_entries: Vec<u64>,
    sealed_layer_entries: Vec<Option<u64>>,
    captured_layer_transcripts: Vec<Sha256>,
    sealed_layer_transcripts: Vec<Option<[u8; SHA256_BYTES]>>,
    captured_canonical_layer_transcripts: Vec<ChangesetTranscriptV1>,
    authenticated_canonical_layer_transcripts: Vec<Option<[u8; SHA256_BYTES]>>,
    operations_by_source: Vec<Vec<usize>>,
}

/// Affine evidence that this transaction consumed and dropped its owned descriptors.
///
/// A successful final observation records `nlink == 0` immediately before the
/// owned spool descriptor is dropped. The receipt does not establish globally
/// unique descriptor ownership, inter-process inaccessibility, writeback
/// durability, block reclamation, candidate validity or publication.
/// The observation skips candidate sync, byte scans and pathname lookups, but
/// teardown still destroys entry collections, closes retained directory
/// descriptors and releases the anonymous inode; no constant latency is claimed.
#[derive(Debug)]
#[must_use = "abandonment evidence must remain in the closed OCI orchestration"]
pub(super) struct PrivateOciRootfsAbandonedV1 {
    role: PositiveRunnerRole,
    spool_identity: FileIdentity,
    completed_physical_regular_extents: u64,
    completed_physical_regular_bytes: u64,
    completed_operations: u64,
    live_regular_files: u64,
    live_regular_bytes: u64,
    validated_live_rootfs: Option<OciRootfsLiveCountersV1>,
    authenticated_live_entries: Option<u64>,
    authenticated_logical_projection_sha256: Option<[u8; SHA256_BYTES]>,
    final_unlinked_observed: bool,
    final_observation_error: Option<String>,
    _private: (),
}

#[derive(Debug)]
#[must_use = "failed OCI staging retains both its primary error and abandonment evidence"]
struct PrivateOciRootfsFailedV1 {
    error: anyhow::Error,
    abandonment: PrivateOciRootfsAbandonedV1,
}

impl std::fmt::Display for PrivateOciRootfsFailedV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.error, formatter)
    }
}

impl std::error::Error for PrivateOciRootfsFailedV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref())
    }
}

struct OpenRegularExtentV1 {
    source: OciRootfsSourceOrdinalV1,
    path: String,
    offset: u64,
    expected_byte_length: u64,
    written_byte_length: u64,
    mode: u32,
    digest: Sha256,
}

struct StagedRegularExtentV1 {
    source: OciRootfsSourceOrdinalV1,
    offset: u64,
    byte_length: u64,
    mode: u32,
    sha256: [u8; SHA256_BYTES],
}

fn checked_rootfs_metadata_reservation(current: u64, additional: u64) -> Result<u64> {
    let total = current
        .checked_add(additional)
        .context("OCI rootfs logical metadata reservation overflowed")?;
    ensure!(
        total <= OCI_ROOTFS_LOGICAL_METADATA_MAX_BYTES,
        "OCI rootfs logical metadata reservation exceeds its compiled byte bound"
    );
    Ok(total)
}

fn owned_string_metadata_reservation(value: &str) -> Result<u64> {
    OCI_ROOTFS_OWNED_STRING_METADATA_RESERVATION_BYTES
        .checked_add(
            u64::try_from(value.len())
                .context("OCI rootfs logical string length does not fit u64")?,
        )
        .context("OCI rootfs logical string metadata reservation overflowed")
}

fn staged_operation_metadata_reservation(
    path: &str,
    kind: &StagedRootfsOperationKindV1,
) -> Result<u64> {
    let (target, regular_extent) = kind.as_ref().metadata_parts();
    staged_operation_metadata_reservation_parts(path, target, regular_extent)
}

fn staged_operation_metadata_reservation_parts(
    path: &str,
    target: Option<&str>,
    regular_extent: bool,
) -> Result<u64> {
    let mut reservation = OCI_ROOTFS_OPERATION_METADATA_RESERVATION_BYTES
        .checked_add(OCI_ROOTFS_SOURCE_INDEX_METADATA_RESERVATION_BYTES)
        .and_then(|value| value.checked_add(OCI_ROOTFS_LIVE_INDEX_METADATA_RESERVATION_BYTES))
        .and_then(|value| value.checked_add(OCI_ROOTFS_CANDIDATE_NODE_METADATA_RESERVATION_BYTES))
        .context("OCI rootfs operation metadata reservation overflowed")?;
    reservation = reservation
        .checked_add(owned_string_metadata_reservation(path)?)
        .context("OCI rootfs path metadata reservation overflowed")?;
    let kind_reservation = if regular_extent {
        OCI_ROOTFS_REGULAR_EXTENT_METADATA_RESERVATION_BYTES
    } else if let Some(target) = target {
        owned_string_metadata_reservation(target)?
    } else {
        0
    };
    reservation
        .checked_add(kind_reservation)
        .context("OCI rootfs operation-kind metadata reservation overflowed")
}

fn try_owned_rootfs_string(value: &str, label: &str) -> Result<String> {
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .with_context(|| format!("cannot reserve {label}"))?;
    owned.push_str(value);
    Ok(owned)
}

fn try_filled_rootfs_vec<T: Clone>(length: usize, value: T, label: &str) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .with_context(|| format!("cannot reserve {label}"))?;
    values.resize(length, value);
    Ok(values)
}

fn initialize_rootfs_layer_journals(
    expected_semantic_layers: u64,
) -> Result<OciRootfsLayerJournalsV1> {
    let oci_limits = B4ImmutableArtifactRoleV1::OciImageLayoutUstar
        .limits()
        .require_oci("OCI rootfs staging")?;
    ensure!(
        expected_semantic_layers != 0,
        "OCI rootfs staging requires a nonempty semantic layer sequence"
    );
    oci_limits.layer_stream().checked_add_layer(
        0,
        expected_semantic_layers,
        "OCI rootfs semantic layers",
    )?;
    let expected_layer_capacity = usize::try_from(expected_semantic_layers)
        .context("OCI rootfs semantic layer count does not fit usize")?;
    let mut captured_layer_transcripts = Vec::new();
    captured_layer_transcripts
        .try_reserve_exact(expected_layer_capacity)
        .context("cannot reserve OCI rootfs captured layer transcripts")?;
    for semantic_layer_index in 0..expected_semantic_layers {
        captured_layer_transcripts.push(new_layer_operation_transcript(semantic_layer_index));
    }
    let mut captured_canonical_layer_transcripts = Vec::new();
    captured_canonical_layer_transcripts
        .try_reserve_exact(expected_layer_capacity)
        .context("cannot reserve OCI rootfs canonical layer transcripts")?;
    captured_canonical_layer_transcripts
        .resize_with(expected_layer_capacity, ChangesetTranscriptV1::new);
    let captured_layer_entries = try_filled_rootfs_vec(
        expected_layer_capacity,
        0,
        "OCI rootfs captured layer counts",
    )?;
    let sealed_layer_entries = try_filled_rootfs_vec(
        expected_layer_capacity,
        None,
        "OCI rootfs sealed layer counts",
    )?;
    let sealed_layer_transcripts = try_filled_rootfs_vec(
        expected_layer_capacity,
        None,
        "OCI rootfs sealed layer transcripts",
    )?;
    let authenticated_canonical_layer_transcripts = try_filled_rootfs_vec(
        expected_layer_capacity,
        None,
        "OCI rootfs authenticated canonical layer transcripts",
    )?;
    let mut operations_by_source = Vec::new();
    operations_by_source
        .try_reserve_exact(expected_layer_capacity)
        .context("cannot reserve OCI rootfs per-layer source journals")?;
    operations_by_source.resize_with(expected_layer_capacity, Vec::new);
    Ok(OciRootfsLayerJournalsV1 {
        captured_layer_entries,
        sealed_layer_entries,
        captured_layer_transcripts,
        sealed_layer_transcripts,
        captured_canonical_layer_transcripts,
        authenticated_canonical_layer_transcripts,
        operations_by_source,
    })
}

fn open_private_anonymous_rootfs_spool(
    parent: &PinnedAbsoluteDirectoryPath,
) -> Result<(File, FileObservation)> {
    let descriptor = rustix::fs::openat2(
        parent.descriptor(),
        ".",
        ANONYMOUS_SPOOL_FLAGS,
        PRIVATE_SPOOL_MODE,
        ANONYMOUS_SPOOL_RESOLVE_FLAGS,
    )
    .context(
        "cannot create unlinkable OCI replay spool with O_TMPFILE|O_EXCL on the exact parent mount",
    )?;
    let spool = File::from(descriptor);
    rustix::fs::fchmod(spool.as_fd(), PRIVATE_SPOOL_MODE)
        .context("cannot seal anonymous OCI replay spool mode")?;
    let opened_spool = regular_file_observation(&spool)?;
    ensure!(
        opened_spool.owner == u64::from(rustix::process::geteuid().as_raw()),
        "anonymous OCI replay spool was not created for the effective user"
    );
    Ok((spool, opened_spool))
}

pub(super) fn begin_private_oci_rootfs_staging(
    role: PositiveRunnerRole,
    final_guard: &Path,
    expected_semantic_layers: u64,
) -> Result<PrivateOciRootfsStagingTransactionV1> {
    let layout = OciRootfsStagingLayoutV1::project(role, final_guard)?;
    PrivateOciRootfsStagingTransactionV1::begin(layout, expected_semantic_layers)
}

impl PrivateOciRootfsStagingTransactionV1 {
    fn begin(layout: OciRootfsStagingLayoutV1, expected_semantic_layers: u64) -> Result<Self> {
        let OciRootfsStagingLayoutV1 {
            role,
            parent: parent_path,
            final_name,
        } = layout;
        let OciRootfsLayerJournalsV1 {
            captured_layer_entries,
            sealed_layer_entries,
            captured_layer_transcripts,
            sealed_layer_transcripts,
            captured_canonical_layer_transcripts,
            authenticated_canonical_layer_transcripts,
            operations_by_source,
        } = initialize_rootfs_layer_journals(expected_semantic_layers)?;
        let current_mount_namespace = physical::PinnedCurrentMountNamespaceV1::capture()
            .context("cannot pin private OCI rootfs calling-thread mount namespace")?;
        let parent = PinnedAbsoluteDirectoryPath::open(&parent_path)
            .context("cannot pin private OCI rootfs spool parent")?;
        current_mount_namespace.reauthenticate()?;
        parent.reauthenticate()?;
        ensure_absent(
            parent.descriptor(),
            &final_name,
            "OCI rootfs final destination",
        )?;

        current_mount_namespace.reauthenticate()?;
        let (spool, opened_spool) = open_private_anonymous_rootfs_spool(&parent)?;

        let transaction = Self {
            role,
            current_mount_namespace,
            parent,
            final_name,
            spool,
            spool_identity: opened_spool.identity,
            spool_owner: opened_spool.owner,
            spool_group: opened_spool.group,
            expected_semantic_layers,
            captured_layer_entries,
            sealed_layer_entries,
            captured_layer_transcripts,
            sealed_layer_transcripts,
            captured_canonical_layer_transcripts,
            authenticated_canonical_layer_transcripts,
            physical_regular_extents: Vec::new(),
            operations: Vec::new(),
            operations_by_source,
            open_regular: None,
            open_inert_entry: false,
            physical_regular_bytes: 0,
            logical_metadata_bytes: OCI_ROOTFS_LOGICAL_METADATA_BASE_RESERVATION_BYTES,
            validated_live_rootfs: None,
            poisoned: false,
            #[cfg(test)]
            descriptor_observations: Cell::new(0),
            #[cfg(test)]
            candidate_sync_calls: Cell::new(0),
            #[cfg(test)]
            candidate_extent_bytes_read: Cell::new(0),
        };
        transaction.validate_spool_descriptor(0)?;
        transaction.current_mount_namespace.reauthenticate()?;
        transaction.parent.reauthenticate()?;
        ensure_absent(
            transaction.parent.descriptor(),
            &transaction.final_name,
            "OCI rootfs final destination after anonymous spool creation",
        )?;
        Ok(transaction)
    }

    pub(super) fn replay_semantic_layer_sink(
        &mut self,
        semantic_layer_index: u64,
    ) -> Result<impl OciLayerReplaySinkV1 + '_> {
        ensure!(!self.poisoned, "private OCI rootfs staging is poisoned");
        let layer = self.semantic_layer_slot(semantic_layer_index)?;
        ensure!(
            self.sealed_layer_entries[layer].is_none(),
            "OCI rootfs replay targets an already sealed semantic layer"
        );
        ensure!(
            self.open_regular.is_none(),
            "OCI rootfs replay cannot switch semantic layers with an open entry"
        );
        ensure!(
            !self.open_inert_entry,
            "OCI rootfs replay cannot switch semantic layers with an unfinished inert entry"
        );
        Ok(PrivateOciRootfsLayerReplaySinkV1 {
            transaction: self,
            semantic_layer_index,
            entry_state: OciRootfsReplayEntryStateV1::None,
        })
    }

    fn begin_regular(
        &mut self,
        source: OciRootfsSourceOrdinalV1,
        path: &str,
        mode: u64,
        byte_length: u64,
    ) -> Result<()> {
        ensure!(!self.poisoned, "private OCI rootfs staging is poisoned");
        if let Err(error) = self.pre_effect_check() {
            self.poisoned = true;
            return Err(error).context("OCI rootfs regular-file begin precheck failed");
        }
        let result = self.begin_regular_inner(source, path, mode, byte_length);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    #[cfg(test)]
    fn begin_root_regular(&mut self, path: &str, mode: u64, byte_length: u64) -> Result<()> {
        let source = OciRootfsSourceOrdinalV1 {
            semantic_layer_index: 0,
            archive_entry_index: self.captured_layer_entries[0],
        };
        self.begin_regular(source, path, mode, byte_length)
    }

    fn write_regular_chunk(&mut self, chunk: &[u8]) -> Result<()> {
        ensure!(!self.poisoned, "private OCI rootfs staging is poisoned");
        let result = self.write_regular_chunk_inner(chunk);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn finish_entry(&mut self) -> Result<()> {
        ensure!(!self.poisoned, "private OCI rootfs staging is poisoned");
        let result = self.finish_entry_inner();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn stage_directory(
        &mut self,
        source: OciRootfsSourceOrdinalV1,
        path: &str,
        mode: u64,
        byte_length: u64,
    ) -> Result<()> {
        self.stage_inert_operation(
            source,
            path,
            mode,
            byte_length,
            StagedRootfsOperationKindRefV1::Directory,
        )
    }

    fn stage_symbolic_link(
        &mut self,
        source: OciRootfsSourceOrdinalV1,
        path: &str,
        mode: u64,
        byte_length: u64,
        target: &str,
    ) -> Result<()> {
        self.stage_inert_operation(
            source,
            path,
            mode,
            byte_length,
            StagedRootfsOperationKindRefV1::SymbolicLink { target },
        )
    }

    fn stage_remove(
        &mut self,
        source: OciRootfsSourceOrdinalV1,
        marker_path: &str,
        mode: u64,
        byte_length: u64,
        target: &str,
    ) -> Result<()> {
        self.stage_inert_operation(
            source,
            marker_path,
            mode,
            byte_length,
            StagedRootfsOperationKindRefV1::Remove { target },
        )
    }

    fn stage_opaque_directory(
        &mut self,
        source: OciRootfsSourceOrdinalV1,
        marker_path: &str,
        mode: u64,
        byte_length: u64,
        path: &str,
    ) -> Result<()> {
        self.stage_inert_operation(
            source,
            marker_path,
            mode,
            byte_length,
            StagedRootfsOperationKindRefV1::OpaqueDirectory { path },
        )
    }

    fn stage_inert_operation(
        &mut self,
        source: OciRootfsSourceOrdinalV1,
        path: &str,
        mode: u64,
        byte_length: u64,
        kind: StagedRootfsOperationKindRefV1<'_>,
    ) -> Result<()> {
        ensure!(!self.poisoned, "private OCI rootfs staging is poisoned");
        let result = self.stage_inert_operation_inner(source, path, mode, byte_length, kind);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    #[cfg(test)]
    fn seal_semantic_layer(
        &mut self,
        semantic_layer_index: u64,
        authenticated_entry_count: u64,
    ) -> Result<()> {
        let result = (|| {
            let layer = self.semantic_layer_slot(semantic_layer_index)?;
            let changeset_transcript_sha256 = self.captured_canonical_layer_transcripts[layer]
                .clone()
                .finish()?;
            self.seal_authenticated_semantic_layer(AuthenticatedOciLayerSealV1 {
                semantic_layer_index,
                authenticated_entry_count,
                changeset_transcript_sha256,
                _private: (),
            })
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn seal_authenticated_semantic_layer(
        &mut self,
        seal: AuthenticatedOciLayerSealV1,
    ) -> Result<()> {
        ensure!(!self.poisoned, "private OCI rootfs staging is poisoned");
        let result = self.seal_authenticated_semantic_layer_inner(seal);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub(super) fn authenticate_and_retain(
        mut self,
        seals: Vec<AuthenticatedOciLayerSealV1>,
        expected_live_rootfs: OciExpectedRootfsV1,
    ) -> Result<AuthenticatedPrivateOciRootfsProjectionV1> {
        let sealing = (|| {
            let expected_layer_count = usize::try_from(self.expected_semantic_layers)
                .context("OCI rootfs semantic layer count does not fit usize")?;
            ensure!(
                seals.len() == expected_layer_count,
                "authenticated OCI rootfs layer-seal cardinality differs from the manifest"
            );
            for (expected_semantic_layer_index, seal) in seals.into_iter().enumerate() {
                let expected_semantic_layer_index = u64::try_from(expected_semantic_layer_index)
                    .context("OCI rootfs seal position does not fit u64")?;
                ensure!(
                    seal.semantic_layer_index == expected_semantic_layer_index,
                    "authenticated OCI rootfs layer seals differ from semantic layer order"
                );
                self.seal_authenticated_semantic_layer(seal)?;
            }
            Ok(())
        })();
        if let Err(error) = sealing {
            return Err(anyhow::Error::new(self.discard_after(error)));
        }

        let validated =
            match self.validate_completed_candidate_with_expected(Some(expected_live_rootfs)) {
                Ok(validated) => validated,
                Err(error) => return Err(anyhow::Error::new(self.discard_after(error))),
            };
        Ok(AuthenticatedPrivateOciRootfsProjectionV1 {
            transaction: self,
            canonical_live_operation_indices: validated.canonical_live_operation_indices,
            counters: validated.counters,
            authenticated_logical_projection_sha256: validated
                .authenticated_logical_projection_sha256,
            #[cfg(test)]
            test_only_physical_materialization_failpoint: None,
        })
    }

    pub(super) fn discard_after_error(self, primary: anyhow::Error) -> anyhow::Error {
        anyhow::Error::new(self.discard_after(primary))
    }

    fn discard(
        mut self,
    ) -> std::result::Result<PrivateOciRootfsAbandonedV1, Box<PrivateOciRootfsFailedV1>> {
        let candidate = self.validate_completed_candidate();
        self.finish_discard(candidate)
    }

    fn finish_discard(
        self,
        candidate: Result<()>,
    ) -> std::result::Result<PrivateOciRootfsAbandonedV1, Box<PrivateOciRootfsFailedV1>> {
        let abandonment = self.abandon();
        finish_rootfs_abandonment(candidate, abandonment)
    }

    fn discard_after(self, primary: anyhow::Error) -> PrivateOciRootfsFailedV1 {
        let abandonment = self.abandon();
        let error = match abandonment.final_observation_error.as_deref() {
            None => primary,
            Some(observation) => primary.context(format!(
                "final unlinked-spool observation also failed before owned descriptor drop: {observation}"
            )),
        };
        PrivateOciRootfsFailedV1 { error, abandonment }
    }

    fn validate_completed_candidate(&mut self) -> Result<()> {
        self.validate_completed_candidate_with_expected(None)
            .map(|_| ())
    }

    fn validate_completed_candidate_with_expected(
        &mut self,
        expected_live_rootfs: Option<OciExpectedRootfsV1>,
    ) -> Result<ValidatedOciRootfsProjectionV1> {
        ensure!(!self.poisoned, "private OCI rootfs candidate is poisoned");
        ensure!(
            self.open_regular.is_none(),
            "private OCI rootfs candidate has an unfinished entry"
        );
        ensure!(
            !self.open_inert_entry,
            "private OCI rootfs candidate has an unfinished inert entry"
        );
        let validated = {
            let projection = self.validate_logical_projection_with_layer_seals(true)?;
            if let Some(expected) = expected_live_rootfs {
                validate_expected_live_rootfs(projection.counters, expected)?;
            }
            validated_logical_projection(
                self.role,
                &projection,
                &self.operations,
                &self.physical_regular_extents,
            )?
        };
        self.parent.reauthenticate()?;
        ensure_absent(
            self.parent.descriptor(),
            &self.final_name,
            "OCI rootfs final destination before anonymous spool validation",
        )?;
        self.validate_spool_descriptor(self.physical_regular_bytes)?;
        #[cfg(test)]
        self.candidate_sync_calls
            .set(self.candidate_sync_calls.get().saturating_add(1));
        self.spool
            .sync_all()
            .context("cannot synchronize anonymous OCI replay spool before candidate validation")?;
        self.validate_physical_regular_extents()?;
        self.validate_spool_descriptor(self.physical_regular_bytes)?;
        self.parent.reauthenticate()?;
        ensure_absent(
            self.parent.descriptor(),
            &self.final_name,
            "OCI rootfs final destination after anonymous spool validation",
        )?;
        self.validated_live_rootfs = Some(validated.counters);
        Ok(validated)
    }

    fn revalidate_authenticated_projection(
        &mut self,
        expected_live_operation_indices: &[usize],
        expected_counters: OciRootfsLiveCountersV1,
        expected_logical_projection_sha256: [u8; SHA256_BYTES],
    ) -> Result<()> {
        ensure!(
            self.validated_live_rootfs == Some(expected_counters),
            "retained OCI rootfs counters differ from the authenticated candidate"
        );
        let observed = {
            let projection = self.validate_logical_projection_with_layer_seals(true)?;
            validated_logical_projection(
                self.role,
                &projection,
                &self.operations,
                &self.physical_regular_extents,
            )?
        };
        ensure!(
            observed.canonical_live_operation_indices == expected_live_operation_indices,
            "retained OCI rootfs live definitions differ from the authenticated projection"
        );
        ensure!(
            observed.counters == expected_counters,
            "retained OCI rootfs live counters differ from the authenticated projection"
        );
        ensure!(
            observed.authenticated_logical_projection_sha256 == expected_logical_projection_sha256,
            "retained OCI rootfs logical identity differs from the authenticated projection"
        );
        self.parent.reauthenticate()?;
        ensure_absent(
            self.parent.descriptor(),
            &self.final_name,
            "OCI rootfs final destination before retained projection validation",
        )?;
        self.validate_spool_descriptor(self.physical_regular_bytes)?;
        self.validate_physical_regular_extents()?;
        self.validate_spool_descriptor(self.physical_regular_bytes)?;
        self.parent.reauthenticate()?;
        ensure_absent(
            self.parent.descriptor(),
            &self.final_name,
            "OCI rootfs final destination after retained projection validation",
        )?;
        Ok(())
    }

    fn abandon(self) -> PrivateOciRootfsAbandonedV1 {
        let final_observation_error = self
            .validate_spool_custody()
            .err()
            .map(|error| format!("{error:#}"));
        let role = self.role;
        let spool_identity = self.spool_identity;
        let completed_physical_regular_extents = u64::try_from(self.physical_regular_extents.len())
            .expect("Linux usize always fits in u64");
        let completed_physical_regular_bytes = self.physical_regular_bytes;
        let completed_operations =
            u64::try_from(self.operations.len()).expect("Linux usize always fits in u64");
        let validated_live_rootfs = self.validated_live_rootfs;
        let live_regular_files = validated_live_rootfs.map_or(0, |state| state.regular_file_count);
        let live_regular_bytes = validated_live_rootfs.map_or(0, |state| state.regular_file_bytes);
        let final_unlinked_observed = final_observation_error.is_none();
        drop(self);
        PrivateOciRootfsAbandonedV1 {
            role,
            spool_identity,
            completed_physical_regular_extents,
            completed_physical_regular_bytes,
            completed_operations,
            live_regular_files,
            live_regular_bytes,
            validated_live_rootfs,
            authenticated_live_entries: None,
            authenticated_logical_projection_sha256: None,
            final_unlinked_observed,
            final_observation_error,
            _private: (),
        }
    }

    fn pre_effect_check(&self) -> Result<()> {
        // The only mutable effect is the upcoming pwrite stream through this
        // retained anonymous FD. Logical operations cannot redirect it; the
        // descriptor is checked again when the extent closes and at candidate
        // boundaries, while parent path/name custody is closed at candidate.
        self.validate_spool_descriptor(self.physical_spool_byte_length()?)
    }

    fn validate_spool_descriptor(&self, expected_byte_length: u64) -> Result<()> {
        self.current_mount_namespace.reauthenticate()?;
        #[cfg(test)]
        self.descriptor_observations
            .set(self.descriptor_observations.get().saturating_add(1));
        let observed = regular_file_observation(&self.spool)?;
        validate_spool_custody_observation(
            &observed,
            self.spool_identity,
            self.parent.identity().mount_id,
            self.spool_owner,
            self.spool_group,
        )?;
        ensure!(
            observed.byte_length == expected_byte_length,
            "anonymous OCI replay spool length changed"
        );
        Ok(())
    }

    fn validate_spool_custody(&self) -> Result<()> {
        self.current_mount_namespace.reauthenticate()?;
        let observed = regular_file_observation(&self.spool)?;
        validate_spool_custody_observation(
            &observed,
            self.spool_identity,
            self.parent.identity().mount_id,
            self.spool_owner,
            self.spool_group,
        )
    }

    fn physical_spool_byte_length(&self) -> Result<u64> {
        let open_bytes = self
            .open_regular
            .as_ref()
            .map_or(0, |open| open.written_byte_length);
        self.physical_regular_bytes
            .checked_add(open_bytes)
            .context("physical OCI replay spool length overflowed")
    }

    fn begin_regular_inner(
        &mut self,
        source: OciRootfsSourceOrdinalV1,
        path: &str,
        mode: u64,
        byte_length: u64,
    ) -> Result<()> {
        ensure!(
            self.open_regular.is_none(),
            "OCI rootfs staging already has an open entry"
        );
        ensure!(
            !self.open_inert_entry,
            "OCI rootfs staging already has an unfinished inert entry"
        );
        self.validate_next_source(source)?;
        let metadata_reservation = staged_operation_metadata_reservation_parts(path, None, true)?;
        let next_logical_metadata =
            checked_rootfs_metadata_reservation(self.logical_metadata_bytes, metadata_reservation)?;
        validate_normalized_rootfs_path(path, "OCI rootfs regular-file path")?;
        ensure!(
            parse_rootfs_whiteout(path)?.is_none(),
            "OCI rootfs regular-file path uses reserved whiteout syntax"
        );
        ensure!(
            matches!(mode, 0o444 | 0o555),
            "OCI rootfs regular-file mode is outside 0444/0555"
        );
        let oci_limits = B4ImmutableArtifactRoleV1::OciImageLayoutUstar
            .limits()
            .require_oci("OCI rootfs staging")?;
        let layer_stream_limits = oci_limits.layer_stream();
        layer_stream_limits
            .validate_regular_file_payload_bytes(byte_length, "OCI rootfs staging")?;
        layer_stream_limits.checked_add_tar_entries(
            u64::try_from(self.operations.len())
                .context("physical OCI rootfs operation count does not fit u64")?,
            1,
            "physical OCI rootfs operations",
        )?;
        layer_stream_limits.checked_add_uncompressed_tar_bytes(
            self.physical_regular_bytes,
            byte_length,
            "physical OCI rootfs regular payload bytes",
        )?;
        let owned_path = try_owned_rootfs_string(path, "OCI rootfs regular-file path")?;
        self.physical_regular_extents
            .try_reserve(1)
            .context("cannot reserve the physical OCI rootfs extent journal")?;
        self.operations
            .try_reserve(1)
            .context("cannot reserve the physical OCI rootfs operation journal")?;
        let layer = self.semantic_layer_slot(source.semantic_layer_index)?;
        self.captured_canonical_layer_transcripts[layer].begin_entry(
            &OciLayerReplayEntryV1::regular_file(path, mode, byte_length),
        )?;
        self.open_regular = Some(OpenRegularExtentV1 {
            source,
            path: owned_path,
            offset: self.physical_regular_bytes,
            expected_byte_length: byte_length,
            written_byte_length: 0,
            mode: u32::try_from(mode).expect("closed OCI mode fits u32"),
            digest: Sha256::new(),
        });
        self.logical_metadata_bytes = next_logical_metadata;
        Ok(())
    }

    fn stage_inert_operation_inner(
        &mut self,
        source: OciRootfsSourceOrdinalV1,
        path: &str,
        mode: u64,
        byte_length: u64,
        kind: StagedRootfsOperationKindRefV1<'_>,
    ) -> Result<()> {
        ensure!(
            self.open_regular.is_none(),
            "OCI rootfs staging already has an open entry"
        );
        ensure!(
            !self.open_inert_entry,
            "OCI rootfs staging already has an unfinished inert entry"
        );
        self.validate_next_source(source)?;
        let mode = u32::try_from(mode).context("OCI rootfs logical mode does not fit u32")?;
        let (target, regular_extent) = kind.metadata_parts();
        let metadata_reservation =
            staged_operation_metadata_reservation_parts(path, target, regular_extent)?;
        let next_logical_metadata =
            checked_rootfs_metadata_reservation(self.logical_metadata_bytes, metadata_reservation)?;
        validate_staged_operation_identity_ref(path, mode, byte_length, kind)?;
        let limits = B4ImmutableArtifactRoleV1::OciImageLayoutUstar
            .limits()
            .require_oci("OCI rootfs staging")?
            .layer_stream();
        limits.checked_add_tar_entries(
            u64::try_from(self.operations.len())
                .context("physical OCI rootfs operation count does not fit u64")?,
            1,
            "physical OCI rootfs operations",
        )?;
        self.operations
            .try_reserve(1)
            .context("cannot reserve the physical OCI rootfs operation journal")?;
        let operation = StagedRootfsOperationV1 {
            source,
            path: try_owned_rootfs_string(path, "OCI rootfs operation path")?,
            mode,
            byte_length,
            kind: kind.try_to_owned()?,
        };
        let layer = self.semantic_layer_slot(source.semantic_layer_index)?;
        let canonical = canonical_replay_entry(path, u64::from(mode), byte_length, kind);
        self.captured_canonical_layer_transcripts[layer].begin_entry(&canonical)?;
        self.captured_canonical_layer_transcripts[layer].finish_entry()?;
        self.push_completed_operation(operation)?;
        self.logical_metadata_bytes = next_logical_metadata;
        Ok(())
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "the non-Clone seal is consumed here to preserve the affine authentication transition"
    )]
    fn seal_authenticated_semantic_layer_inner(
        &mut self,
        seal: AuthenticatedOciLayerSealV1,
    ) -> Result<()> {
        let AuthenticatedOciLayerSealV1 {
            semantic_layer_index,
            authenticated_entry_count,
            changeset_transcript_sha256: authenticated_changeset_transcript,
            _private: (),
        } = seal;
        ensure!(
            self.open_regular.is_none(),
            "OCI rootfs semantic layer ended with an open entry"
        );
        ensure!(
            !self.open_inert_entry,
            "OCI rootfs semantic layer ended with an unfinished inert entry"
        );
        let layer = self.semantic_layer_slot(semantic_layer_index)?;
        ensure!(
            self.sealed_layer_entries[layer].is_none(),
            "OCI rootfs semantic layer was sealed more than once"
        );
        ensure!(
            self.authenticated_canonical_layer_transcripts[layer].is_none(),
            "OCI rootfs semantic-layer authenticated transcript was sealed more than once"
        );
        let limits = B4ImmutableArtifactRoleV1::OciImageLayoutUstar
            .limits()
            .require_oci("OCI rootfs staging")?
            .layer_stream();
        limits.checked_add_tar_entries(
            0,
            authenticated_entry_count,
            "authenticated OCI rootfs semantic-layer entries",
        )?;
        ensure!(
            self.captured_layer_entries[layer] == authenticated_entry_count,
            "OCI rootfs semantic-layer captured entry count differs from its authenticated receipt"
        );
        let captured_changeset_transcript = self.captured_canonical_layer_transcripts[layer]
            .clone()
            .finish()?;
        ensure!(
            captured_changeset_transcript == authenticated_changeset_transcript,
            "OCI rootfs changeset transcript differs from its authenticated layer seal"
        );
        let transcript: [u8; SHA256_BYTES] = self.captured_layer_transcripts[layer]
            .clone()
            .finalize()
            .into();
        self.sealed_layer_entries[layer] = Some(authenticated_entry_count);
        self.sealed_layer_transcripts[layer] = Some(transcript);
        self.authenticated_canonical_layer_transcripts[layer] =
            Some(authenticated_changeset_transcript);
        Ok(())
    }

    fn semantic_layer_slot(&self, semantic_layer_index: u64) -> Result<usize> {
        ensure!(
            semantic_layer_index < self.expected_semantic_layers,
            "OCI rootfs semantic layer index is outside the authenticated manifest"
        );
        usize::try_from(semantic_layer_index)
            .context("OCI rootfs semantic layer index does not fit usize")
    }

    fn validate_next_source(&self, source: OciRootfsSourceOrdinalV1) -> Result<()> {
        let layer = self.semantic_layer_slot(source.semantic_layer_index)?;
        ensure!(
            self.sealed_layer_entries[layer].is_none(),
            "OCI rootfs operation targets an already sealed semantic layer"
        );
        ensure!(
            source.archive_entry_index == self.captured_layer_entries[layer],
            "OCI rootfs source ordinal is not the next archive entry in its semantic layer"
        );
        let indexed_entries = self
            .operations_by_source
            .get(layer)
            .context("OCI rootfs source-index layer is absent")?;
        ensure!(
            u64::try_from(indexed_entries.len())
                .context("OCI rootfs source-index length does not fit u64")?
                == source.archive_entry_index,
            "OCI rootfs source ordinal was captured more than once or out of order"
        );
        Ok(())
    }

    fn push_completed_operation(&mut self, operation: StagedRootfsOperationV1) -> Result<()> {
        self.validate_next_source(operation.source)?;
        let layer = self.semantic_layer_slot(operation.source.semantic_layer_index)?;
        let operation_index = self.operations.len();
        let mut captured_transcript = self.captured_layer_transcripts[layer].clone();
        update_layer_operation_transcript(
            &mut captured_transcript,
            &operation,
            &self.physical_regular_extents,
        )?;
        self.operations_by_source[layer]
            .try_reserve(1)
            .context("cannot reserve the OCI rootfs per-layer source index")?;
        self.operations_by_source[layer].push(operation_index);
        self.operations.push(operation);
        self.captured_layer_transcripts[layer] = captured_transcript;
        self.captured_layer_entries[layer] = self.captured_layer_entries[layer]
            .checked_add(1)
            .context("OCI rootfs semantic-layer captured entry count overflowed")?;
        Ok(())
    }

    fn write_regular_chunk_inner(&mut self, chunk: &[u8]) -> Result<()> {
        ensure!(
            (1..=OCI_REPLAY_CHUNK_MAX_BYTES).contains(&chunk.len()),
            "OCI rootfs replay chunk is outside its fixed streaming range"
        );
        self.current_mount_namespace.reauthenticate()?;
        let semantic_layer_index = self
            .open_regular
            .as_ref()
            .context("OCI rootfs staging has no open regular file")?
            .source
            .semantic_layer_index;
        let layer = self.semantic_layer_slot(semantic_layer_index)?;
        let spool = &self.spool;
        let open = self
            .open_regular
            .as_mut()
            .context("OCI rootfs staging has no open regular file")?;
        let chunk_bytes = u64::try_from(chunk.len()).expect("bounded replay chunk fits u64");
        let written = open
            .written_byte_length
            .checked_add(chunk_bytes)
            .context("OCI rootfs regular-file written length overflowed")?;
        ensure!(
            written <= open.expected_byte_length,
            "OCI rootfs replay emitted more bytes than the regular file declared"
        );
        let write_offset = open
            .offset
            .checked_add(open.written_byte_length)
            .context("OCI rootfs spool write offset overflowed")?;
        write_all_at(spool, chunk, write_offset)
            .with_context(|| format!("cannot stream OCI rootfs regular file {}", open.path))?;
        open.digest.update(chunk);
        open.written_byte_length = written;
        self.captured_canonical_layer_transcripts[layer].write_regular_file_chunk(chunk)?;
        Ok(())
    }

    fn finish_entry_inner(&mut self) -> Result<()> {
        let open = self
            .open_regular
            .as_ref()
            .context("OCI rootfs staging has no open entry")?;
        ensure!(
            open.written_byte_length == open.expected_byte_length,
            "OCI rootfs regular file ended before its declared payload"
        );
        let completed_physical_regular_bytes =
            open.offset
                .checked_add(open.expected_byte_length)
                .context("completed physical OCI rootfs regular-file bytes overflowed")?;
        ensure!(
            completed_physical_regular_bytes == self.physical_spool_byte_length()?,
            "finished OCI rootfs regular file is not the terminal spool extent"
        );
        let expected_sha256: [u8; SHA256_BYTES] = open.digest.clone().finalize().into();
        self.validate_spool_descriptor(completed_physical_regular_bytes)?;
        let open = self
            .open_regular
            .take()
            .expect("validated OCI rootfs regular extent remains open");
        let extent_index = self.physical_regular_extents.len();
        let staged = StagedRegularExtentV1 {
            source: open.source,
            offset: open.offset,
            byte_length: open.expected_byte_length,
            mode: open.mode,
            sha256: expected_sha256,
        };
        self.physical_regular_extents.push(staged);
        self.push_completed_operation(StagedRootfsOperationV1 {
            source: open.source,
            path: open.path,
            mode: open.mode,
            byte_length: open.expected_byte_length,
            kind: StagedRootfsOperationKindV1::Regular { extent_index },
        })?;
        let layer = self.semantic_layer_slot(open.source.semantic_layer_index)?;
        self.captured_canonical_layer_transcripts[layer].finish_entry()?;
        self.physical_regular_bytes = completed_physical_regular_bytes;
        Ok(())
    }

    #[cfg(test)]
    fn validate_spooled_projection(&self) -> Result<RootfsProjectionV1<'_>> {
        self.validate_spooled_projection_with_layer_seals(true)
    }

    #[cfg(test)]
    fn validate_spooled_projection_with_layer_seals(
        &self,
        require_all_layer_seals: bool,
    ) -> Result<RootfsProjectionV1<'_>> {
        let projection =
            self.validate_logical_projection_with_layer_seals(require_all_layer_seals)?;
        self.validate_physical_regular_extents()?;
        Ok(projection)
    }

    fn validate_logical_projection_with_layer_seals(
        &self,
        require_all_layer_seals: bool,
    ) -> Result<RootfsProjectionV1<'_>> {
        let physical_entry_count = self.validate_logical_journal_envelope()?;
        self.validate_operation_extent_references()?;
        let layer_entry_counts = self
            .validate_layer_seals_and_transcripts(require_all_layer_seals, physical_entry_count)?;
        let projection = self.project_operation_journal(&layer_entry_counts)?;
        validate_projection_effect_references(&projection, &self.operations)?;
        self.validate_open_regular_identity()?;
        Ok(projection)
    }

    fn validate_logical_journal_envelope(&self) -> Result<u64> {
        let expected_layer_count = usize::try_from(self.expected_semantic_layers)
            .context("OCI rootfs semantic layer count does not fit usize")?;
        ensure!(
            self.captured_layer_entries.len() == expected_layer_count
                && self.sealed_layer_entries.len() == expected_layer_count
                && self.captured_layer_transcripts.len() == expected_layer_count
                && self.sealed_layer_transcripts.len() == expected_layer_count
                && self.captured_canonical_layer_transcripts.len() == expected_layer_count
                && self.authenticated_canonical_layer_transcripts.len() == expected_layer_count
                && self.operations_by_source.len() == expected_layer_count,
            "OCI rootfs semantic-layer journal cardinality changed"
        );
        let mut recomputed_metadata = OCI_ROOTFS_LOGICAL_METADATA_BASE_RESERVATION_BYTES;
        for operation in &self.operations {
            recomputed_metadata = checked_rootfs_metadata_reservation(
                recomputed_metadata,
                staged_operation_metadata_reservation(&operation.path, &operation.kind)?,
            )?;
        }
        if let Some(open) = &self.open_regular {
            recomputed_metadata = checked_rootfs_metadata_reservation(
                recomputed_metadata,
                staged_operation_metadata_reservation_parts(&open.path, None, true)?,
            )?;
        }
        ensure!(
            recomputed_metadata == self.logical_metadata_bytes,
            "OCI rootfs logical metadata reservation differs from its journal"
        );
        let mut next_offset = 0_u64;
        for extent in &self.physical_regular_extents {
            ensure!(
                extent.offset == next_offset,
                "physical OCI rootfs regular extents are not in append order"
            );
            ensure!(
                matches!(extent.mode, 0o444 | 0o555),
                "physical OCI rootfs regular extent has an invalid logical mode"
            );
            next_offset = next_offset
                .checked_add(extent.byte_length)
                .context("completed OCI rootfs extent closure overflowed")?;
        }
        ensure!(
            next_offset == self.physical_regular_bytes,
            "physical OCI rootfs extent journal length changed"
        );
        let physical_entry_count = u64::try_from(self.operations.len())
            .context("physical OCI rootfs operation count does not fit u64")?;
        let oci_limits = B4ImmutableArtifactRoleV1::OciImageLayoutUstar
            .limits()
            .require_oci("OCI rootfs staging validation")?;
        oci_limits.layer_stream().checked_add_tar_entries(
            0,
            physical_entry_count,
            "physical OCI rootfs operations",
        )?;
        oci_limits
            .layer_stream()
            .checked_add_uncompressed_tar_bytes(
                0,
                self.physical_regular_bytes,
                "physical OCI rootfs regular payload bytes",
            )?;

        let indexed_operation_count =
            self.operations_by_source
                .iter()
                .try_fold(0_usize, |count, layer| {
                    count
                        .checked_add(layer.len())
                        .context("OCI rootfs source-index cardinality overflowed")
                })?;
        ensure!(
            indexed_operation_count == self.operations.len(),
            "OCI rootfs source index cardinality differs from its operation journal"
        );
        Ok(physical_entry_count)
    }

    fn validate_operation_extent_references(&self) -> Result<()> {
        let mut referenced_extents = Vec::new();
        referenced_extents
            .try_reserve_exact(self.physical_regular_extents.len())
            .context("cannot reserve OCI rootfs extent-reference validation scratch")?;
        referenced_extents.resize(self.physical_regular_extents.len(), false);
        for (operation_index, operation) in self.operations.iter().enumerate() {
            validate_staged_operation_identity(
                &operation.path,
                operation.mode,
                operation.byte_length,
                &operation.kind,
            )?;
            let layer = self.semantic_layer_slot(operation.source.semantic_layer_index)?;
            let entry = usize::try_from(operation.source.archive_entry_index)
                .context("OCI rootfs archive source index does not fit usize")?;
            ensure!(
                self.operations_by_source[layer].get(entry) == Some(&operation_index),
                "OCI rootfs source index names a different physical operation"
            );
            ensure!(
                operation.source.archive_entry_index < self.captured_layer_entries[layer],
                "OCI rootfs operation archive index exceeds its captured layer"
            );
            if let StagedRootfsOperationKindV1::Regular { extent_index } = operation.kind {
                let referenced = referenced_extents
                    .get_mut(extent_index)
                    .context("OCI rootfs regular operation references an absent physical extent")?;
                ensure!(
                    !*referenced,
                    "OCI rootfs physical regular extent is referenced more than once"
                );
                *referenced = true;
                let extent = &self.physical_regular_extents[extent_index];
                ensure!(
                    operation.mode == extent.mode && operation.byte_length == extent.byte_length,
                    "OCI rootfs regular operation differs from its physical extent identity"
                );
                ensure!(
                    operation.source == extent.source,
                    "OCI rootfs regular operation differs from its physical extent source identity"
                );
            }
        }
        ensure!(
            referenced_extents.iter().all(|referenced| *referenced),
            "OCI rootfs physical regular extent is orphaned from the operation journal"
        );
        Ok(())
    }

    fn validate_layer_seals_and_transcripts(
        &self,
        require_all_layer_seals: bool,
        physical_entry_count: u64,
    ) -> Result<Vec<u64>> {
        let mut observed_operations = 0_u64;
        let mut layer_entry_counts = Vec::new();
        layer_entry_counts
            .try_reserve_exact(self.captured_layer_entries.len())
            .context("cannot reserve OCI rootfs layer-count validation scratch")?;
        for (layer, captured) in self.captured_layer_entries.iter().copied().enumerate() {
            let sealed = self.sealed_layer_entries[layer];
            if require_all_layer_seals {
                ensure!(
                    sealed.is_some(),
                    "OCI rootfs semantic layer is not authenticated and sealed"
                );
            }
            let expected = sealed.unwrap_or(captured);
            ensure!(
                expected == captured,
                "OCI rootfs sealed semantic-layer entry count changed"
            );
            let mut previous_path: Option<&str> = None;
            let semantic_layer_index =
                u64::try_from(layer).context("OCI rootfs semantic layer slot does not fit u64")?;
            let mut observed_transcript = new_layer_operation_transcript(semantic_layer_index);
            for archive_entry_index in 0..expected {
                let entry = usize::try_from(archive_entry_index)
                    .context("OCI rootfs archive source index does not fit usize")?;
                let operation_index = *self.operations_by_source[layer]
                    .get(entry)
                    .context("OCI rootfs semantic layer has a gap in archive source order")?;
                let operation = self
                    .operations
                    .get(operation_index)
                    .context("OCI rootfs semantic source left its operation journal")?;
                if let Some(previous) = previous_path {
                    ensure!(
                        previous < operation.path.as_str(),
                        "OCI rootfs semantic layer violates strict source path order"
                    );
                }
                previous_path = Some(&operation.path);
                update_layer_operation_transcript(
                    &mut observed_transcript,
                    operation,
                    &self.physical_regular_extents,
                )?;
            }
            let observed_transcript: [u8; SHA256_BYTES] = observed_transcript.finalize().into();
            let captured_transcript: [u8; SHA256_BYTES] = self.captured_layer_transcripts[layer]
                .clone()
                .finalize()
                .into();
            if let Some(sealed_transcript) = self.sealed_layer_transcripts[layer] {
                ensure!(
                    observed_transcript == sealed_transcript,
                    "OCI rootfs operation journal differs from its sealed semantic-layer transcript"
                );
            } else if require_all_layer_seals {
                anyhow::bail!("OCI rootfs semantic-layer transcript is not sealed");
            }
            ensure!(
                observed_transcript == captured_transcript,
                "OCI rootfs semantic-layer operation journal differs from its captured transcript"
            );
            let captured_canonical_transcript = self.captured_canonical_layer_transcripts[layer]
                .clone()
                .finish()?;
            if let Some(authenticated_canonical_transcript) =
                self.authenticated_canonical_layer_transcripts[layer]
            {
                ensure!(
                    captured_canonical_transcript == authenticated_canonical_transcript,
                    "OCI rootfs canonical changeset transcript differs from its authenticated layer seal"
                );
            } else if require_all_layer_seals {
                anyhow::bail!("OCI rootfs canonical changeset transcript is not authenticated");
            }
            observed_operations = observed_operations
                .checked_add(expected)
                .context("OCI rootfs semantic-layer operation count overflowed")?;
            layer_entry_counts.push(expected);
        }
        ensure!(
            observed_operations == physical_entry_count,
            "OCI rootfs semantic-layer entries do not cover the physical operation journal"
        );
        Ok(layer_entry_counts)
    }

    fn validate_physical_regular_extents(&self) -> Result<()> {
        for extent in &self.physical_regular_extents {
            #[cfg(test)]
            self.candidate_extent_bytes_read.set(
                self.candidate_extent_bytes_read
                    .get()
                    .saturating_add(extent.byte_length),
            );
            let observed = digest_extent(
                &self.spool,
                extent.offset,
                extent.byte_length,
                "physical OCI rootfs regular extent",
            )?;
            ensure!(
                observed == extent.sha256,
                "physical OCI rootfs regular extent digest changed"
            );
        }
        self.validate_open_regular_projection()
    }

    fn project_operation_journal<'journal>(
        &'journal self,
        layer_entry_counts: &[u64],
    ) -> Result<RootfsProjectionV1<'journal>> {
        let mut projection = RootfsProjectionV1::default();
        for (layer, entry_count) in layer_entry_counts.iter().copied().enumerate() {
            let semantic_layer_index =
                u64::try_from(layer).context("OCI rootfs semantic layer slot does not fit u64")?;
            self.validate_layer_whiteouts_against_lower_snapshot(
                &projection,
                semantic_layer_index,
                entry_count,
            )?;
            self.apply_layer_whiteout_phase(&mut projection, semantic_layer_index, entry_count)?;
            self.apply_layer_entry_phase(&mut projection, semantic_layer_index, entry_count)?;
            validate_live_counters(projection.counters)?;
        }
        Ok(projection)
    }

    fn validate_layer_whiteouts_against_lower_snapshot(
        &self,
        projection: &RootfsProjectionV1<'_>,
        semantic_layer_index: u64,
        entry_count: u64,
    ) -> Result<()> {
        let mut whiteout_subjects = BTreeSet::new();
        for archive_entry_index in 0..entry_count {
            let (operation_index, operation) =
                self.operation_at_source(semantic_layer_index, archive_entry_index)?;
            match &operation.kind {
                StagedRootfsOperationKindV1::Remove { target } => {
                    insert_nonoverlapping_whiteout(&mut whiteout_subjects, target)?;
                    ensure!(
                        projection_live_definition(projection, target).is_some(),
                        "OCI rootfs remove whiteout target is absent from the lower snapshot"
                    );
                }
                StagedRootfsOperationKindV1::OpaqueDirectory { path } => {
                    insert_nonoverlapping_whiteout(&mut whiteout_subjects, path)?;
                    if !path.is_empty() {
                        let definition = projection_live_definition(projection, path).context(
                            "OCI rootfs opaque whiteout path is absent from the lower snapshot",
                        )?;
                        ensure!(
                            matches!(
                                self.operations[definition].kind,
                                StagedRootfsOperationKindV1::Directory
                            ),
                            "OCI rootfs opaque whiteout path is not a lower-snapshot directory"
                        );
                    }
                }
                StagedRootfsOperationKindV1::Regular { .. }
                | StagedRootfsOperationKindV1::Directory
                | StagedRootfsOperationKindV1::SymbolicLink { .. } => {}
            }
            ensure!(
                operation_index < self.operations.len(),
                "OCI rootfs operation index escaped its journal"
            );
        }
        Ok(())
    }

    fn apply_layer_whiteout_phase<'journal>(
        &'journal self,
        projection: &mut RootfsProjectionV1<'journal>,
        semantic_layer_index: u64,
        entry_count: u64,
    ) -> Result<()> {
        for archive_entry_index in 0..entry_count {
            let (operation_index, operation) =
                self.operation_at_source(semantic_layer_index, archive_entry_index)?;
            let effect =
                effect_reference(operation_index, operation, OciRootfsEffectPhaseV1::Whiteout);
            match &operation.kind {
                StagedRootfsOperationKindV1::Remove { target } => {
                    remove_projection_subtree(
                        projection,
                        target,
                        true,
                        &self.operations,
                        &self.physical_regular_extents,
                    )?;
                }
                StagedRootfsOperationKindV1::OpaqueDirectory { path } => {
                    if path.is_empty() {
                        remove_projection_subtree(
                            projection,
                            "",
                            false,
                            &self.operations,
                            &self.physical_regular_extents,
                        )?;
                        projection.root_last_effect = Some(effect);
                    } else {
                        remove_projection_subtree(
                            projection,
                            path,
                            false,
                            &self.operations,
                            &self.physical_regular_extents,
                        )?;
                        projection
                            .paths
                            .get_mut(path.as_str())
                            .expect("validated opaque subject remains known")
                            .last_effect = effect;
                    }
                }
                StagedRootfsOperationKindV1::Regular { .. }
                | StagedRootfsOperationKindV1::Directory
                | StagedRootfsOperationKindV1::SymbolicLink { .. } => {}
            }
        }
        Ok(())
    }

    fn apply_layer_entry_phase<'journal>(
        &'journal self,
        projection: &mut RootfsProjectionV1<'journal>,
        semantic_layer_index: u64,
        entry_count: u64,
    ) -> Result<()> {
        for archive_entry_index in 0..entry_count {
            let (operation_index, operation) =
                self.operation_at_source(semantic_layer_index, archive_entry_index)?;
            if matches!(
                operation.kind,
                StagedRootfsOperationKindV1::Remove { .. }
                    | StagedRootfsOperationKindV1::OpaqueDirectory { .. }
            ) {
                continue;
            }
            validate_projection_parent(projection, &operation.path, &self.operations)?;
            let effect =
                effect_reference(operation_index, operation, OciRootfsEffectPhaseV1::Entry);
            match operation.kind {
                StagedRootfsOperationKindV1::Directory => {
                    if let Some(previous) = projection_live_definition(projection, &operation.path)
                    {
                        ensure!(
                            matches!(
                                self.operations[previous].kind,
                                StagedRootfsOperationKindV1::Directory
                            ),
                            "OCI rootfs incoming directory has a type conflict"
                        );
                    }
                    set_projection_definition(
                        projection,
                        &operation.path,
                        operation_index,
                        effect,
                        &self.operations,
                        &self.physical_regular_extents,
                    )?;
                }
                StagedRootfsOperationKindV1::Regular { .. }
                | StagedRootfsOperationKindV1::SymbolicLink { .. } => {
                    remove_projection_subtree(
                        projection,
                        &operation.path,
                        true,
                        &self.operations,
                        &self.physical_regular_extents,
                    )?;
                    set_projection_definition(
                        projection,
                        &operation.path,
                        operation_index,
                        effect,
                        &self.operations,
                        &self.physical_regular_extents,
                    )?;
                }
                StagedRootfsOperationKindV1::Remove { .. }
                | StagedRootfsOperationKindV1::OpaqueDirectory { .. } => unreachable!(),
            }
        }
        Ok(())
    }

    fn operation_at_source(
        &self,
        semantic_layer_index: u64,
        archive_entry_index: u64,
    ) -> Result<(usize, &StagedRootfsOperationV1)> {
        let source = OciRootfsSourceOrdinalV1 {
            semantic_layer_index,
            archive_entry_index,
        };
        let layer = self.semantic_layer_slot(semantic_layer_index)?;
        let entry = usize::try_from(archive_entry_index)
            .context("OCI rootfs archive source index does not fit usize")?;
        let operation_index = *self.operations_by_source[layer]
            .get(entry)
            .context("OCI rootfs source ordinal is absent from its journal")?;
        let operation = self
            .operations
            .get(operation_index)
            .context("OCI rootfs source ordinal left its operation journal")?;
        ensure!(
            operation.source == source,
            "OCI rootfs source ordinal names a different operation"
        );
        Ok((operation_index, operation))
    }

    fn validate_open_regular_identity(&self) -> Result<()> {
        let Some(open) = &self.open_regular else {
            return Ok(());
        };
        ensure!(
            open.offset == self.physical_regular_bytes,
            "open OCI rootfs regular extent is not terminal"
        );
        Ok(())
    }

    fn validate_open_regular_projection(&self) -> Result<()> {
        self.validate_open_regular_identity()?;
        let Some(open) = &self.open_regular else {
            return Ok(());
        };
        let expected: [u8; SHA256_BYTES] = open.digest.clone().finalize().into();
        let observed = digest_extent(
            &self.spool,
            open.offset,
            open.written_byte_length,
            "open OCI rootfs regular extent",
        )?;
        ensure!(
            observed == expected,
            "open OCI rootfs regular extent digest changed"
        );
        Ok(())
    }

    #[cfg(test)]
    fn anonymous_spool_observation(&self) -> Result<FileObservation> {
        regular_file_observation(&self.spool)
    }

    #[cfg(test)]
    fn read_completed_regular(&self, path: &str) -> Result<Vec<u8>> {
        let staged = self
            .test_live_regular_extent(path)?
            .with_context(|| format!("completed OCI rootfs test file is absent: {path}"))?;
        let bytes = read_extent_to_vec(&self.spool, staged.offset, staged.byte_length)?;
        ensure!(
            Sha256::digest(&bytes).as_slice() == staged.sha256,
            "retained OCI rootfs test extent digest changed"
        );
        Ok(bytes)
    }

    #[cfg(test)]
    fn completed_live_regular(&self, path: &str) -> Result<&StagedRegularExtentV1> {
        self.test_live_regular_extent(path)?
            .with_context(|| format!("completed live OCI rootfs test file is absent: {path}"))
    }

    #[cfg(test)]
    fn test_live_regular_extent(&self, path: &str) -> Result<Option<&StagedRegularExtentV1>> {
        let projection = self.validate_spooled_projection_with_layer_seals(false)?;
        let Some(definition) = projection_live_definition(&projection, path) else {
            return Ok(None);
        };
        let operation = self
            .operations
            .get(definition)
            .context("live OCI rootfs test definition left the operation journal")?;
        let StagedRootfsOperationKindV1::Regular { extent_index } = operation.kind else {
            return Ok(None);
        };
        self.physical_regular_extents
            .get(extent_index)
            .map(Some)
            .context("live OCI rootfs test definition left the extent journal")
    }
}

fn finish_rootfs_abandonment(
    candidate: Result<()>,
    abandonment: PrivateOciRootfsAbandonedV1,
) -> std::result::Result<PrivateOciRootfsAbandonedV1, Box<PrivateOciRootfsFailedV1>> {
    match (candidate, abandonment.final_observation_error.as_deref()) {
        (Ok(()), None) => Ok(abandonment),
        (Ok(()), Some(observation)) => Err(Box::new(PrivateOciRootfsFailedV1 {
            error: anyhow::anyhow!(
                "final unlinked-spool observation failed before owned descriptor drop: {observation}"
            ),
            abandonment,
        })),
        (Err(candidate), None) => Err(Box::new(PrivateOciRootfsFailedV1 {
            error: candidate,
            abandonment,
        })),
        (Err(candidate), Some(observation)) => Err(Box::new(PrivateOciRootfsFailedV1 {
            error: candidate.context(format!(
                "final unlinked-spool observation also failed before owned descriptor drop: {observation}"
            )),
            abandonment,
        })),
    }
}

impl PrivateOciRetainedRootfsAcquisitionFailureV1 {
    fn classify(error: anyhow::Error) -> Self {
        let state = match error.downcast::<physical::PrivateOciRootfsCleanupFailureV1>() {
            Ok(physical) => {
                PrivateOciRetainedRootfsAcquisitionFailureStateV1::RetryCustody(physical)
            }
            Err(primary) => PrivateOciRetainedRootfsAcquisitionFailureStateV1::NonRetry(primary),
        };
        Self { state }
    }

    pub(super) fn retry_cleanup(self) -> std::result::Result<anyhow::Error, Self> {
        match self.state {
            PrivateOciRetainedRootfsAcquisitionFailureStateV1::NonRetry(primary) => Ok(primary),
            PrivateOciRetainedRootfsAcquisitionFailureStateV1::RetryCustody(physical) => {
                match physical.retry_cleanup_preserving_error() {
                    Ok((_abandonment, preserved_error)) => Ok(preserved_error),
                    Err(physical) => Err(Self {
                        state: PrivateOciRetainedRootfsAcquisitionFailureStateV1::RetryCustody(
                            physical,
                        ),
                    }),
                }
            }
        }
    }
}

impl std::fmt::Debug for PrivateOciRetainedRootfsAcquisitionFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.state {
            PrivateOciRetainedRootfsAcquisitionFailureStateV1::NonRetry(primary) => {
                std::fmt::Debug::fmt(primary, formatter)
            }
            PrivateOciRetainedRootfsAcquisitionFailureStateV1::RetryCustody(physical) => {
                std::fmt::Debug::fmt(physical, formatter)
            }
        }
    }
}

impl std::fmt::Display for PrivateOciRetainedRootfsAcquisitionFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.state {
            PrivateOciRetainedRootfsAcquisitionFailureStateV1::NonRetry(primary) => {
                std::fmt::Display::fmt(primary, formatter)
            }
            PrivateOciRetainedRootfsAcquisitionFailureStateV1::RetryCustody(physical) => {
                std::fmt::Display::fmt(physical, formatter)
            }
        }
    }
}

impl std::error::Error for PrivateOciRetainedRootfsAcquisitionFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.state {
            PrivateOciRetainedRootfsAcquisitionFailureStateV1::NonRetry(primary) => {
                Some(primary.as_ref())
            }
            PrivateOciRetainedRootfsAcquisitionFailureStateV1::RetryCustody(physical) => {
                Some(physical)
            }
        }
    }
}

impl PrivateOciRetainedRootfsCleanupFailureV1 {
    pub(super) fn retry_cleanup(self) -> std::result::Result<PrivateOciRootfsAbandonedV1, Self> {
        self.physical
            .retry_cleanup()
            .map_err(|physical| Self { physical })
    }
}

impl std::fmt::Debug for PrivateOciRetainedRootfsCleanupFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.physical, formatter)
    }
}

impl std::fmt::Display for PrivateOciRetainedRootfsCleanupFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.physical, formatter)
    }
}

impl std::error::Error for PrivateOciRetainedRootfsCleanupFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.physical)
    }
}

impl AuthenticatedPrivateOciRetainedRootfsV1 {
    pub(super) fn reauthenticate_static_startup_dependencies(
        &self,
        expectation: &B4PositiveOciImageLayoutV1,
    ) -> Result<()> {
        self.physical
            .reauthenticate_static_startup_dependencies(expectation)
    }

    pub(super) fn cleanup(
        self,
    ) -> std::result::Result<PrivateOciRootfsAbandonedV1, PrivateOciRetainedRootfsCleanupFailureV1>
    {
        self.physical
            .cleanup()
            .map_err(|physical| PrivateOciRetainedRootfsCleanupFailureV1 { physical })
    }
}

impl AuthenticatedPrivateOciRootfsProjectionV1 {
    pub(super) fn authenticate_physical_rootfs_and_cleanup(
        self,
        expectation: &B4PositiveOciImageLayoutV1,
    ) -> Result<PrivateOciRootfsAbandonedV1> {
        self.materialize_private()?
            .authenticate_physical_rootfs_and_cleanup(expectation)
    }

    pub(super) fn authenticate_physical_rootfs_and_retain(
        self,
        expectation: &B4PositiveOciImageLayoutV1,
    ) -> std::result::Result<
        AuthenticatedPrivateOciRetainedRootfsV1,
        PrivateOciRetainedRootfsAcquisitionFailureV1,
    > {
        let materialized = self
            .materialize_private()
            .map_err(PrivateOciRetainedRootfsAcquisitionFailureV1::classify)?;
        materialized
            .authenticate_physical_rootfs_and_retain(expectation)
            .map(|physical| AuthenticatedPrivateOciRetainedRootfsV1 { physical })
            .map_err(PrivateOciRetainedRootfsAcquisitionFailureV1::classify)
    }

    pub(super) fn discard_after_error(self, primary: anyhow::Error) -> anyhow::Error {
        match self.abandon() {
            Ok(_) => primary,
            Err(failure) => {
                let PrivateOciRootfsFailedV1 {
                    error: abandonment_error,
                    abandonment,
                } = *failure;
                anyhow::Error::new(PrivateOciRootfsFailedV1 {
                    error: primary.context(format!(
                        "authenticated OCI rootfs abandonment also failed: {abandonment_error:#}"
                    )),
                    abandonment,
                })
            }
        }
    }

    #[cfg(test)]
    pub(super) fn test_only_retained_evidence(
        &self,
    ) -> Result<(u64, [u64; 5], [u8; SHA256_BYTES])> {
        let spool = regular_file_observation(&self.transaction.spool)?;
        validate_spool_custody_observation(
            &spool,
            self.transaction.spool_identity,
            self.transaction.parent.identity().mount_id,
            self.transaction.spool_owner,
            self.transaction.spool_group,
        )?;
        Ok((
            spool.hard_link_count,
            [
                self.counters.entry_count,
                self.counters.regular_file_count,
                self.counters.directory_count,
                self.counters.symbolic_link_count,
                self.counters.regular_file_bytes,
            ],
            self.authenticated_logical_projection_sha256,
        ))
    }

    fn abandon(
        self,
    ) -> std::result::Result<PrivateOciRootfsAbandonedV1, Box<PrivateOciRootfsFailedV1>> {
        let Self {
            mut transaction,
            canonical_live_operation_indices,
            counters,
            authenticated_logical_projection_sha256,
            #[cfg(test)]
                test_only_physical_materialization_failpoint: _,
        } = self;
        let authenticated_live_entries = u64::try_from(canonical_live_operation_indices.len())
            .expect("Linux usize always fits in u64");
        let candidate = transaction.revalidate_authenticated_projection(
            &canonical_live_operation_indices,
            counters,
            authenticated_logical_projection_sha256,
        );
        let mut abandonment = transaction.abandon();
        abandonment.authenticated_live_entries = Some(authenticated_live_entries);
        abandonment.authenticated_logical_projection_sha256 =
            Some(authenticated_logical_projection_sha256);
        finish_rootfs_abandonment(candidate, abandonment)
    }
}

impl OciLayerReplaySinkV1 for PrivateOciRootfsLayerReplaySinkV1<'_> {
    fn begin_entry(&mut self, entry: &OciLayerReplayEntryV1<'_>) -> Result<()> {
        ensure!(
            self.entry_state == OciRootfsReplayEntryStateV1::None,
            "OCI rootfs replay sink already has an open entry"
        );
        let layer = self
            .transaction
            .semantic_layer_slot(self.semantic_layer_index)?;
        let source = OciRootfsSourceOrdinalV1 {
            semantic_layer_index: self.semantic_layer_index,
            archive_entry_index: self.transaction.captured_layer_entries[layer],
        };
        let state = match entry.kind() {
            OciLayerReplayEntryKindV1::RegularFile { mode, byte_length } => {
                self.transaction
                    .begin_regular(source, entry.path(), *mode, *byte_length)?;
                OciRootfsReplayEntryStateV1::Regular
            }
            OciLayerReplayEntryKindV1::Directory { mode, byte_length } => {
                self.transaction
                    .stage_directory(source, entry.path(), *mode, *byte_length)?;
                OciRootfsReplayEntryStateV1::Inert
            }
            OciLayerReplayEntryKindV1::SymbolicLink {
                mode,
                byte_length,
                target,
            } => {
                self.transaction.stage_symbolic_link(
                    source,
                    entry.path(),
                    *mode,
                    *byte_length,
                    target,
                )?;
                OciRootfsReplayEntryStateV1::Inert
            }
            OciLayerReplayEntryKindV1::Whiteout {
                mode,
                byte_length,
                operation: OciLayerReplayWhiteoutV1::Remove { target },
            } => {
                self.transaction
                    .stage_remove(source, entry.path(), *mode, *byte_length, target)?;
                OciRootfsReplayEntryStateV1::Inert
            }
            OciLayerReplayEntryKindV1::Whiteout {
                mode,
                byte_length,
                operation: OciLayerReplayWhiteoutV1::OpaqueDirectory { path },
            } => {
                self.transaction.stage_opaque_directory(
                    source,
                    entry.path(),
                    *mode,
                    *byte_length,
                    path,
                )?;
                OciRootfsReplayEntryStateV1::Inert
            }
        };
        if state == OciRootfsReplayEntryStateV1::Inert {
            self.transaction.open_inert_entry = true;
        }
        self.entry_state = state;
        Ok(())
    }

    fn write_regular_file_chunk(&mut self, chunk: &[u8]) -> Result<()> {
        ensure!(
            self.entry_state == OciRootfsReplayEntryStateV1::Regular,
            "OCI rootfs replay sink payload does not belong to a regular entry"
        );
        self.transaction.write_regular_chunk(chunk)
    }

    fn finish_entry(&mut self) -> Result<()> {
        match self.entry_state {
            OciRootfsReplayEntryStateV1::Regular => self.transaction.finish_entry()?,
            OciRootfsReplayEntryStateV1::Inert => {
                ensure!(
                    self.transaction.open_inert_entry,
                    "OCI rootfs replay inert-entry state was lost"
                );
                self.transaction.open_inert_entry = false;
            }
            OciRootfsReplayEntryStateV1::None => {
                anyhow::bail!("OCI rootfs replay sink has no open entry")
            }
        }
        self.entry_state = OciRootfsReplayEntryStateV1::None;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
enum ParsedRootfsWhiteoutV1<'path> {
    Remove {
        parent: &'path str,
        target_name: &'path str,
    },
    OpaqueDirectory(&'path str),
}

fn canonical_replay_entry<'entry>(
    path: &'entry str,
    mode: u64,
    byte_length: u64,
    kind: StagedRootfsOperationKindRefV1<'entry>,
) -> OciLayerReplayEntryV1<'entry> {
    match kind {
        StagedRootfsOperationKindRefV1::Regular { .. } => {
            OciLayerReplayEntryV1::regular_file(path, mode, byte_length)
        }
        StagedRootfsOperationKindRefV1::Directory => {
            OciLayerReplayEntryV1::directory(path, mode, byte_length)
        }
        StagedRootfsOperationKindRefV1::SymbolicLink { target } => {
            OciLayerReplayEntryV1::symbolic_link(path, mode, byte_length, target)
        }
        StagedRootfsOperationKindRefV1::Remove { target } => {
            OciLayerReplayEntryV1::remove(path, mode, byte_length, target)
        }
        StagedRootfsOperationKindRefV1::OpaqueDirectory { path: subject } => {
            OciLayerReplayEntryV1::opaque_directory(path, mode, byte_length, subject)
        }
    }
}

fn new_layer_operation_transcript(semantic_layer_index: u64) -> Sha256 {
    let mut transcript = Sha256::new();
    transcript.update(b"eip0045-b4-oci-rootfs-operation-transcript-v1\0");
    transcript.update(semantic_layer_index.to_be_bytes());
    transcript
}

fn update_layer_operation_transcript(
    transcript: &mut Sha256,
    operation: &StagedRootfsOperationV1,
    extents: &[StagedRegularExtentV1],
) -> Result<()> {
    transcript.update(operation.source.semantic_layer_index.to_be_bytes());
    transcript.update(operation.source.archive_entry_index.to_be_bytes());
    transcript_update_bytes(transcript, operation.path.as_bytes())?;
    transcript.update(operation.mode.to_be_bytes());
    transcript.update(operation.byte_length.to_be_bytes());
    match &operation.kind {
        StagedRootfsOperationKindV1::Regular { extent_index } => {
            transcript.update([0]);
            let extent = extents
                .get(*extent_index)
                .context("OCI rootfs transcript references an absent regular extent")?;
            ensure!(
                extent.source == operation.source,
                "OCI rootfs transcript regular extent differs from its source identity"
            );
            transcript.update(extent.sha256);
        }
        StagedRootfsOperationKindV1::Directory => transcript.update([1]),
        StagedRootfsOperationKindV1::SymbolicLink { target } => {
            transcript.update([2]);
            transcript_update_bytes(transcript, target.as_bytes())?;
        }
        StagedRootfsOperationKindV1::Remove { target } => {
            transcript.update([3]);
            transcript_update_bytes(transcript, target.as_bytes())?;
        }
        StagedRootfsOperationKindV1::OpaqueDirectory { path } => {
            transcript.update([4]);
            transcript_update_bytes(transcript, path.as_bytes())?;
        }
    }
    Ok(())
}

fn transcript_update_bytes(transcript: &mut Sha256, value: &[u8]) -> Result<()> {
    let byte_length = u64::try_from(value.len())
        .context("OCI rootfs transcript field length does not fit u64")?;
    transcript.update(byte_length.to_be_bytes());
    transcript.update(value);
    Ok(())
}

fn validated_logical_projection(
    role: PositiveRunnerRole,
    projection: &RootfsProjectionV1<'_>,
    operations: &[StagedRootfsOperationV1],
    extents: &[StagedRegularExtentV1],
) -> Result<ValidatedOciRootfsProjectionV1> {
    let mut canonical_live_operation_indices = Vec::new();
    canonical_live_operation_indices
        .try_reserve_exact(projection.paths.len())
        .context("cannot reserve authenticated OCI rootfs live-definition index")?;

    let mut identity = Sha256::new();
    identity.update(b"eip0045-b4-authenticated-logical-rootfs-projection-v1\0");
    identity.update([positive_runner_role_identity_tag(role)]);
    identity.update(projection.counters.entry_count.to_be_bytes());
    identity.update(projection.counters.regular_file_count.to_be_bytes());
    identity.update(projection.counters.directory_count.to_be_bytes());
    identity.update(projection.counters.symbolic_link_count.to_be_bytes());
    identity.update(projection.counters.regular_file_bytes.to_be_bytes());

    for (path, state) in &projection.paths {
        let operation = operations
            .get(state.live_definition)
            .context("authenticated OCI rootfs live definition left its operation journal")?;
        ensure!(
            operation.path.as_str() == *path,
            "authenticated OCI rootfs live definition names a different path"
        );
        canonical_live_operation_indices.push(state.live_definition);
        transcript_update_bytes(&mut identity, path.as_bytes())?;
        match &operation.kind {
            StagedRootfsOperationKindV1::Regular { extent_index } => {
                identity.update([0]);
                identity.update(operation.mode.to_be_bytes());
                identity.update(operation.byte_length.to_be_bytes());
                let extent = extents.get(*extent_index).context(
                    "authenticated OCI rootfs regular definition left its extent journal",
                )?;
                ensure!(
                    extent.mode == operation.mode
                        && extent.byte_length == operation.byte_length
                        && extent.source == operation.source,
                    "authenticated OCI rootfs regular definition differs from its extent identity"
                );
                identity.update(extent.sha256);
            }
            StagedRootfsOperationKindV1::Directory => {
                identity.update([1]);
                identity.update(operation.mode.to_be_bytes());
            }
            StagedRootfsOperationKindV1::SymbolicLink { target } => {
                identity.update([2]);
                identity.update(operation.mode.to_be_bytes());
                transcript_update_bytes(&mut identity, target.as_bytes())?;
            }
            StagedRootfsOperationKindV1::Remove { .. }
            | StagedRootfsOperationKindV1::OpaqueDirectory { .. } => {
                anyhow::bail!("authenticated OCI rootfs live definition names a whiteout")
            }
        }
    }
    ensure!(
        u64::try_from(canonical_live_operation_indices.len())
            .context("authenticated OCI rootfs live-definition count does not fit u64")?
            == projection.counters.entry_count,
        "authenticated OCI rootfs live-definition count differs from its counters"
    );
    Ok(ValidatedOciRootfsProjectionV1 {
        canonical_live_operation_indices,
        counters: projection.counters,
        authenticated_logical_projection_sha256: identity.finalize().into(),
    })
}

const fn positive_runner_role_identity_tag(role: PositiveRunnerRole) -> u8 {
    match role {
        PositiveRunnerRole::RustValidatorBuild => 0,
        PositiveRunnerRole::JvmValidatorBuild => 1,
        PositiveRunnerRole::RustVerifier => 2,
        PositiveRunnerRole::JvmVerifier => 3,
    }
}

fn parse_rootfs_whiteout(path: &str) -> Result<Option<ParsedRootfsWhiteoutV1<'_>>> {
    let (parent, basename) = path.rsplit_once('/').unwrap_or(("", path));
    if !basename.starts_with(".wh.") {
        return Ok(None);
    }
    if basename == ".wh..wh..opq" {
        return Ok(Some(ParsedRootfsWhiteoutV1::OpaqueDirectory(parent)));
    }
    let target_name = &basename[4..];
    ensure!(
        !target_name.is_empty(),
        "OCI rootfs whiteout basename is outside the closed syntax"
    );
    ensure!(
        parent
            .len()
            .checked_add(usize::from(!parent.is_empty()))
            .and_then(|length| length.checked_add(target_name.len()))
            .is_some_and(|length| length <= OCI_LAYER_PATH_MAX_BYTES),
        "OCI rootfs whiteout target length is outside its closed range"
    );
    Ok(Some(ParsedRootfsWhiteoutV1::Remove {
        parent,
        target_name,
    }))
}

fn parsed_whiteout_remove_matches(
    parsed: Option<ParsedRootfsWhiteoutV1<'_>>,
    target: &str,
) -> bool {
    let Some(ParsedRootfsWhiteoutV1::Remove {
        parent,
        target_name,
    }) = parsed
    else {
        return false;
    };
    if parent.is_empty() {
        target == target_name
    } else {
        target
            .strip_prefix(parent)
            .and_then(|suffix| suffix.strip_prefix('/'))
            == Some(target_name)
    }
}

fn validate_staged_operation_identity(
    path: &str,
    mode: u32,
    byte_length: u64,
    kind: &StagedRootfsOperationKindV1,
) -> Result<()> {
    validate_staged_operation_identity_ref(path, mode, byte_length, kind.as_ref())
}

fn validate_staged_operation_identity_ref(
    path: &str,
    mode: u32,
    byte_length: u64,
    kind: StagedRootfsOperationKindRefV1<'_>,
) -> Result<()> {
    validate_normalized_rootfs_path(path, "OCI rootfs operation path")?;
    let parsed_whiteout = parse_rootfs_whiteout(path)?;
    match kind {
        StagedRootfsOperationKindRefV1::Regular { .. } => {
            ensure!(
                parsed_whiteout.is_none(),
                "OCI rootfs regular operation uses reserved whiteout syntax"
            );
            ensure!(
                matches!(mode, 0o444 | 0o555),
                "OCI rootfs regular operation mode is outside 0444/0555"
            );
            B4ImmutableArtifactRoleV1::OciImageLayoutUstar
                .limits()
                .require_oci("OCI rootfs operation validation")?
                .layer_stream()
                .validate_regular_file_payload_bytes(
                    byte_length,
                    "OCI rootfs operation validation",
                )?;
        }
        StagedRootfsOperationKindRefV1::Directory => {
            ensure!(
                parsed_whiteout.is_none(),
                "OCI rootfs directory operation uses reserved whiteout syntax"
            );
            ensure!(mode == 0o555, "OCI rootfs directory mode is not 0555");
            ensure!(
                byte_length == 0,
                "OCI rootfs directory payload is not empty"
            );
        }
        StagedRootfsOperationKindRefV1::SymbolicLink { target } => {
            ensure!(
                parsed_whiteout.is_none(),
                "OCI rootfs symbolic-link operation uses reserved whiteout syntax"
            );
            ensure!(mode == 0o777, "OCI rootfs symbolic-link mode is not 0777");
            ensure!(
                byte_length == 0,
                "OCI rootfs symbolic-link payload is not empty"
            );
            validate_symlink_target(path, target)?;
        }
        StagedRootfsOperationKindRefV1::Remove { target } => {
            ensure!(mode == 0, "OCI rootfs whiteout mode is not 0000");
            ensure!(byte_length == 0, "OCI rootfs whiteout payload is not empty");
            ensure!(
                parsed_whiteout_remove_matches(parsed_whiteout, target),
                "OCI rootfs remove whiteout target is not derived exactly from its marker"
            );
        }
        StagedRootfsOperationKindRefV1::OpaqueDirectory { path: subject } => {
            ensure!(mode == 0, "OCI rootfs whiteout mode is not 0000");
            ensure!(byte_length == 0, "OCI rootfs whiteout payload is not empty");
            if !subject.is_empty() {
                validate_normalized_rootfs_path(subject, "OCI rootfs opaque whiteout subject")?;
            }
            ensure!(
                matches!(
                    parsed_whiteout,
                    Some(ParsedRootfsWhiteoutV1::OpaqueDirectory(parsed_subject))
                        if parsed_subject == subject
                ),
                "OCI rootfs opaque whiteout subject is not derived exactly from its marker"
            );
        }
    }
    Ok(())
}

fn validate_symlink_target(entry_path: &str, target: &str) -> Result<()> {
    ensure!(
        !target.is_empty(),
        "OCI rootfs symbolic-link target is empty"
    );
    ensure!(
        target.len() <= OCI_SYMLINK_TARGET_MAX_BYTES,
        "OCI rootfs symbolic-link target exceeds its ustar field bound"
    );
    ensure!(
        !target.as_bytes().contains(&0),
        "OCI rootfs symbolic-link target contains a NUL byte"
    );
    let mut resolved: Vec<&str> = if target.starts_with('/') {
        Vec::new()
    } else {
        let mut parent: Vec<&str> = entry_path.split('/').collect();
        parent.pop();
        parent
    };
    for component in target.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            ensure!(
                resolved.pop().is_some(),
                "OCI rootfs symbolic-link target escapes the layer root"
            );
        } else {
            resolved.push(component);
        }
    }
    Ok(())
}

fn insert_nonoverlapping_whiteout<'journal>(
    existing: &mut BTreeSet<&'journal str>,
    candidate: &'journal str,
) -> Result<()> {
    ensure!(
        !existing.contains(candidate),
        "OCI rootfs whiteout conflicts with an intra-layer whiteout subtree"
    );
    if candidate.is_empty() {
        ensure!(
            existing.is_empty(),
            "OCI rootfs whiteout conflicts with an intra-layer whiteout subtree"
        );
    } else {
        ensure!(
            !existing.contains(""),
            "OCI rootfs whiteout conflicts with an intra-layer whiteout subtree"
        );
        for (separator, _) in candidate.match_indices('/') {
            ensure!(
                !existing.contains(&candidate[..separator]),
                "OCI rootfs whiteout conflicts with an intra-layer whiteout subtree"
            );
        }
        let descendant_prefix = format!("{candidate}/");
        if let Some(descendant) = existing
            .range::<str, _>((
                Bound::Included(descendant_prefix.as_str()),
                Bound::Unbounded,
            ))
            .next()
        {
            ensure!(
                !descendant.starts_with(&descendant_prefix),
                "OCI rootfs whiteout conflicts with an intra-layer whiteout subtree"
            );
        }
    }
    existing.insert(candidate);
    Ok(())
}

fn effect_reference(
    operation_index: usize,
    operation: &StagedRootfsOperationV1,
    phase: OciRootfsEffectPhaseV1,
) -> OciRootfsEffectReferenceV1 {
    OciRootfsEffectReferenceV1 {
        operation_index,
        ordinal: OciRootfsEffectOrdinalV1 {
            semantic_layer_index: operation.source.semantic_layer_index,
            phase,
            archive_entry_index: operation.source.archive_entry_index,
        },
    }
}

fn projection_live_definition(projection: &RootfsProjectionV1<'_>, path: &str) -> Option<usize> {
    projection
        .paths
        .get(path)
        .map(|state| state.live_definition)
}

fn validate_projection_effect_references(
    projection: &RootfsProjectionV1<'_>,
    operations: &[StagedRootfsOperationV1],
) -> Result<()> {
    validate_live_projection_effect_references(projection, operations)?;
    validate_root_projection_effect_reference(projection, operations)?;
    validate_projection_effect_temporal_maxima(projection, operations)
}

fn validate_live_projection_effect_references(
    projection: &RootfsProjectionV1<'_>,
    operations: &[StagedRootfsOperationV1],
) -> Result<()> {
    for (path, state) in &projection.paths {
        let live_operation = operations
            .get(state.live_definition)
            .context("live OCI rootfs projection definition left the operation journal")?;
        ensure!(
            live_operation.path.as_str() == *path,
            "live OCI rootfs projection definition names a different path"
        );
        let effect_operation = operations
            .get(state.last_effect.operation_index)
            .context("live OCI rootfs projection effect left the operation journal")?;
        ensure!(
            state.last_effect
                == effect_reference(
                    state.last_effect.operation_index,
                    effect_operation,
                    state.last_effect.ordinal.phase,
                ),
            "live OCI rootfs projection effect ordinal differs from its operation"
        );
        match state.last_effect.ordinal.phase {
            OciRootfsEffectPhaseV1::Entry => {
                ensure!(
                    state.last_effect.operation_index == state.live_definition,
                    "live OCI rootfs entry effect differs from its definition"
                );
                ensure!(
                    !matches!(
                        effect_operation.kind,
                        StagedRootfsOperationKindV1::Remove { .. }
                            | StagedRootfsOperationKindV1::OpaqueDirectory { .. }
                    ),
                    "live OCI rootfs entry effect names a whiteout"
                );
            }
            OciRootfsEffectPhaseV1::Whiteout => {
                ensure!(
                    matches!(live_operation.kind, StagedRootfsOperationKindV1::Directory),
                    "live OCI rootfs whiteout effect did not retain a directory"
                );
                ensure!(
                    matches!(
                        &effect_operation.kind,
                        StagedRootfsOperationKindV1::OpaqueDirectory { path: subject }
                            if subject.as_str() == *path
                    ),
                    "live OCI rootfs whiteout effect is not its exact opaque directory"
                );
            }
        }
    }
    Ok(())
}

fn validate_root_projection_effect_reference(
    projection: &RootfsProjectionV1<'_>,
    operations: &[StagedRootfsOperationV1],
) -> Result<()> {
    if let Some(effect) = projection.root_last_effect {
        let operation = operations
            .get(effect.operation_index)
            .context("OCI rootfs root effect left the operation journal")?;
        ensure!(
            effect
                == effect_reference(
                    effect.operation_index,
                    operation,
                    OciRootfsEffectPhaseV1::Whiteout,
                ),
            "OCI rootfs root effect ordinal differs from its operation"
        );
        ensure!(
            matches!(
                &operation.kind,
                StagedRootfsOperationKindV1::OpaqueDirectory { path } if path.is_empty()
            ),
            "OCI rootfs root effect is not an exact root opaque whiteout"
        );
    }
    Ok(())
}

fn validate_projection_effect_temporal_maxima(
    projection: &RootfsProjectionV1<'_>,
    operations: &[StagedRootfsOperationV1],
) -> Result<()> {
    let mut latest_root_opaque = None;
    for (operation_index, operation) in operations.iter().enumerate() {
        match &operation.kind {
            StagedRootfsOperationKindV1::Regular { .. }
            | StagedRootfsOperationKindV1::Directory
            | StagedRootfsOperationKindV1::SymbolicLink { .. } => {
                let Some(state) = projection.paths.get(operation.path.as_str()) else {
                    continue;
                };
                let candidate =
                    effect_reference(operation_index, operation, OciRootfsEffectPhaseV1::Entry);
                let live_definition = operations
                    .get(state.live_definition)
                    .context("live OCI rootfs temporal definition left the operation journal")?;
                let live_definition_effect = effect_reference(
                    state.live_definition,
                    live_definition,
                    OciRootfsEffectPhaseV1::Entry,
                );
                ensure!(
                    live_definition_effect.ordinal >= candidate.ordinal,
                    "live OCI rootfs projection definition is not temporally latest"
                );
                ensure!(
                    state.last_effect.ordinal >= candidate.ordinal,
                    "live OCI rootfs projection effect is not temporally maximal"
                );
            }
            StagedRootfsOperationKindV1::OpaqueDirectory { path } if path.is_empty() => {
                let candidate =
                    effect_reference(operation_index, operation, OciRootfsEffectPhaseV1::Whiteout);
                if latest_root_opaque.is_none_or(|latest: OciRootfsEffectReferenceV1| {
                    latest.ordinal < candidate.ordinal
                }) {
                    latest_root_opaque = Some(candidate);
                }
            }
            StagedRootfsOperationKindV1::OpaqueDirectory { path } => {
                let Some(state) = projection.paths.get(path.as_str()) else {
                    continue;
                };
                let candidate =
                    effect_reference(operation_index, operation, OciRootfsEffectPhaseV1::Whiteout);
                ensure!(
                    state.last_effect.ordinal >= candidate.ordinal,
                    "live OCI rootfs projection effect is not temporally maximal"
                );
            }
            StagedRootfsOperationKindV1::Remove { .. } => {}
        }
    }
    ensure!(
        projection.root_last_effect == latest_root_opaque,
        "OCI rootfs root effect is not the temporally latest root opaque whiteout"
    );
    Ok(())
}

fn validate_projection_parent(
    projection: &RootfsProjectionV1<'_>,
    path: &str,
    operations: &[StagedRootfsOperationV1],
) -> Result<()> {
    let Some((parent, _)) = path.rsplit_once('/') else {
        return Ok(());
    };
    let definition = projection_live_definition(projection, parent)
        .context("OCI rootfs entry parent directory is absent")?;
    ensure!(
        matches!(
            operations[definition].kind,
            StagedRootfsOperationKindV1::Directory
        ),
        "OCI rootfs entry parent directory is not a live directory"
    );
    Ok(())
}

fn remove_projection_subtree(
    projection: &mut RootfsProjectionV1<'_>,
    subject: &str,
    include_subject: bool,
    operations: &[StagedRootfsOperationV1],
    extents: &[StagedRegularExtentV1],
) -> Result<()> {
    if subject.is_empty() {
        let live_paths = std::mem::take(&mut projection.paths);
        for (_, state) in live_paths {
            remove_projection_state(projection, state, operations, extents)?;
        }
        return Ok(());
    }

    let exact_definition = projection_live_definition(projection, subject);
    let has_descendants = exact_definition.is_some_and(|definition| {
        matches!(
            operations[definition].kind,
            StagedRootfsOperationKindV1::Directory
        )
    });
    if include_subject {
        let Some(state) = projection.paths.remove(subject) else {
            return Ok(());
        };
        remove_projection_state(projection, state, operations, extents)?;
    }
    if !has_descendants {
        return Ok(());
    }

    let descendant_prefix = format!("{subject}/");
    loop {
        let next_descendant = projection
            .paths
            .range::<str, _>((
                Bound::Included(descendant_prefix.as_str()),
                Bound::Unbounded,
            ))
            .next()
            .filter(|(candidate, _)| candidate.starts_with(&descendant_prefix))
            .map(|(candidate, _)| *candidate);
        let Some(path) = next_descendant else {
            break;
        };
        let state = projection
            .paths
            .remove(&path)
            .expect("selected live OCI rootfs descendant remains present");
        remove_projection_state(projection, state, operations, extents)?;
    }
    Ok(())
}

fn remove_projection_state(
    projection: &mut RootfsProjectionV1<'_>,
    state: RootfsPathProjectionV1,
    operations: &[StagedRootfsOperationV1],
    extents: &[StagedRegularExtentV1],
) -> Result<()> {
    remove_live_counter(
        &mut projection.counters,
        &operations[state.live_definition],
        extents,
    )?;
    #[cfg(test)]
    {
        projection.subtree_candidate_visits = projection
            .subtree_candidate_visits
            .checked_add(1)
            .expect("bounded OCI rootfs projection visit count fits u64");
        assert!(projection.subtree_candidate_visits <= projection.definitions_inserted);
    }
    Ok(())
}

fn set_projection_definition<'journal>(
    projection: &mut RootfsProjectionV1<'journal>,
    path: &'journal str,
    definition: usize,
    effect: OciRootfsEffectReferenceV1,
    operations: &[StagedRootfsOperationV1],
    extents: &[StagedRegularExtentV1],
) -> Result<()> {
    if let Some(previous) = projection_live_definition(projection, path) {
        remove_live_counter(&mut projection.counters, &operations[previous], extents)?;
    }
    add_live_counter(&mut projection.counters, &operations[definition], extents)?;
    projection.paths.insert(
        path,
        RootfsPathProjectionV1 {
            live_definition: definition,
            last_effect: effect,
        },
    );
    #[cfg(test)]
    {
        projection.definitions_inserted = projection
            .definitions_inserted
            .checked_add(1)
            .expect("bounded OCI rootfs projection insertion count fits u64");
    }
    Ok(())
}

fn add_live_counter(
    counters: &mut OciRootfsLiveCountersV1,
    operation: &StagedRootfsOperationV1,
    extents: &[StagedRegularExtentV1],
) -> Result<()> {
    counters.entry_count = counters
        .entry_count
        .checked_add(1)
        .context("live OCI rootfs entry count overflowed")?;
    match operation.kind {
        StagedRootfsOperationKindV1::Regular { extent_index } => {
            let extent = extents
                .get(extent_index)
                .context("live OCI rootfs regular definition left the extent journal")?;
            counters.regular_file_count = counters
                .regular_file_count
                .checked_add(1)
                .context("live OCI rootfs regular-file count overflowed")?;
            counters.regular_file_bytes = counters
                .regular_file_bytes
                .checked_add(extent.byte_length)
                .context("live OCI rootfs regular-file bytes overflowed")?;
        }
        StagedRootfsOperationKindV1::Directory => {
            counters.directory_count = counters
                .directory_count
                .checked_add(1)
                .context("live OCI rootfs directory count overflowed")?;
        }
        StagedRootfsOperationKindV1::SymbolicLink { .. } => {
            counters.symbolic_link_count = counters
                .symbolic_link_count
                .checked_add(1)
                .context("live OCI rootfs symbolic-link count overflowed")?;
        }
        StagedRootfsOperationKindV1::Remove { .. }
        | StagedRootfsOperationKindV1::OpaqueDirectory { .. } => {
            anyhow::bail!("OCI rootfs whiteout cannot become a live definition")
        }
    }
    Ok(())
}

fn remove_live_counter(
    counters: &mut OciRootfsLiveCountersV1,
    operation: &StagedRootfsOperationV1,
    extents: &[StagedRegularExtentV1],
) -> Result<()> {
    counters.entry_count = counters
        .entry_count
        .checked_sub(1)
        .context("live OCI rootfs entry count underflowed")?;
    match operation.kind {
        StagedRootfsOperationKindV1::Regular { extent_index } => {
            let extent = extents
                .get(extent_index)
                .context("live OCI rootfs regular definition left the extent journal")?;
            counters.regular_file_count = counters
                .regular_file_count
                .checked_sub(1)
                .context("live OCI rootfs regular-file count underflowed")?;
            counters.regular_file_bytes = counters
                .regular_file_bytes
                .checked_sub(extent.byte_length)
                .context("live OCI rootfs regular-file bytes underflowed")?;
        }
        StagedRootfsOperationKindV1::Directory => {
            counters.directory_count = counters
                .directory_count
                .checked_sub(1)
                .context("live OCI rootfs directory count underflowed")?;
        }
        StagedRootfsOperationKindV1::SymbolicLink { .. } => {
            counters.symbolic_link_count = counters
                .symbolic_link_count
                .checked_sub(1)
                .context("live OCI rootfs symbolic-link count underflowed")?;
        }
        StagedRootfsOperationKindV1::Remove { .. }
        | StagedRootfsOperationKindV1::OpaqueDirectory { .. } => {
            anyhow::bail!("OCI rootfs whiteout cannot be removed from live counters")
        }
    }
    Ok(())
}

fn validate_live_counters(counters: OciRootfsLiveCountersV1) -> Result<()> {
    let typed_total = counters
        .regular_file_count
        .checked_add(counters.directory_count)
        .and_then(|count| count.checked_add(counters.symbolic_link_count))
        .context("typed live OCI rootfs entry count overflowed")?;
    ensure!(
        counters.entry_count == typed_total,
        "live OCI rootfs entry count differs from its typed counts"
    );
    let limits = B4ImmutableArtifactRoleV1::OciImageLayoutUstar
        .limits()
        .require_oci("OCI rootfs staging validation")?
        .post_changeset_rootfs();
    limits.validate_final_entry_count(counters.entry_count, "OCI rootfs staging validation")?;
    limits.validate_final_regular_file_bytes(
        counters.regular_file_bytes,
        "OCI rootfs staging validation",
    )
}

fn validate_expected_live_rootfs(
    observed: OciRootfsLiveCountersV1,
    expected: OciExpectedRootfsV1,
) -> Result<()> {
    ensure!(
        observed.entry_count == expected.entry_count(),
        "OCI rootfs live entry count differs from its authenticated expectation"
    );
    ensure!(
        observed.regular_file_count == expected.regular_file_count(),
        "OCI rootfs live regular-file count differs from its authenticated expectation"
    );
    ensure!(
        observed.directory_count == expected.directory_count(),
        "OCI rootfs live directory count differs from its authenticated expectation"
    );
    ensure!(
        observed.symbolic_link_count == expected.symbolic_link_count(),
        "OCI rootfs live symbolic-link count differs from its authenticated expectation"
    );
    ensure!(
        observed.regular_file_bytes == expected.regular_file_bytes(),
        "OCI rootfs live regular-file bytes differ from its authenticated expectation"
    );
    Ok(())
}

fn write_all_at(file: &File, mut bytes: &[u8], mut offset: u64) -> Result<()> {
    while !bytes.is_empty() {
        let written = file
            .write_at(bytes, offset)
            .context("anonymous OCI spool pwrite failed")?;
        ensure!(written != 0, "anonymous OCI spool pwrite made no progress");
        let written_u64 = u64::try_from(written).expect("written slice length fits u64");
        offset = offset
            .checked_add(written_u64)
            .context("anonymous OCI spool pwrite offset overflowed")?;
        bytes = &bytes[written..];
    }
    Ok(())
}

fn digest_extent(file: &File, start: u64, byte_length: u64, label: &str) -> Result<[u8; 32]> {
    let mut digest = Sha256::new();
    let mut consumed = 0_u64;
    let mut buffer = [0_u8; OCI_REPLAY_CHUNK_MAX_BYTES];
    while consumed < byte_length {
        let remaining = byte_length
            .checked_sub(consumed)
            .expect("consumed extent bytes remain bounded");
        let wanted = usize::try_from(remaining.min(OCI_REPLAY_CHUNK_MAX_BYTES as u64))
            .expect("bounded extent read fits usize");
        let offset = start
            .checked_add(consumed)
            .context("OCI replay extent read offset overflowed")?;
        let read = file
            .read_at(&mut buffer[..wanted], offset)
            .with_context(|| format!("cannot reread {label}"))?;
        ensure!(read != 0, "{label} ended before its declared length");
        digest.update(&buffer[..read]);
        consumed = consumed
            .checked_add(u64::try_from(read).expect("bounded extent read fits u64"))
            .context("OCI replay extent read length overflowed")?;
    }
    Ok(digest.finalize().into())
}

#[cfg(test)]
fn read_extent_to_vec(file: &File, start: u64, byte_length: u64) -> Result<Vec<u8>> {
    let length = usize::try_from(byte_length).context("test extent length does not fit memory")?;
    let mut bytes = vec![0_u8; length];
    let mut consumed = 0_usize;
    while consumed < bytes.len() {
        let offset = start
            .checked_add(u64::try_from(consumed).expect("test offset fits u64"))
            .context("test extent offset overflowed")?;
        let read = file
            .read_at(&mut bytes[consumed..], offset)
            .context("cannot read retained OCI rootfs test extent")?;
        ensure!(read != 0, "retained OCI rootfs test extent ended early");
        consumed = consumed
            .checked_add(read)
            .context("retained OCI rootfs test read offset overflowed")?;
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    mount_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    mount_id: u64,
}

#[derive(Clone, Copy, Debug)]
struct FileObservation {
    identity: FileIdentity,
    byte_length: u64,
    hard_link_count: u64,
    mode: u32,
    owner: u64,
    group: u64,
    modification_time_seconds: i64,
    modification_time_nanoseconds: i64,
}

fn validate_spool_custody_observation(
    observed: &FileObservation,
    expected_identity: FileIdentity,
    expected_parent_mount_id: u64,
    expected_owner: u64,
    expected_group: u64,
) -> Result<()> {
    ensure!(
        observed.identity == expected_identity,
        "anonymous OCI replay spool identity changed"
    );
    ensure!(
        observed.identity.mount_id == expected_parent_mount_id,
        "anonymous OCI replay spool crossed its retained parent mount"
    );
    ensure!(
        observed.hard_link_count == 0,
        "anonymous OCI replay spool acquired a namespace link"
    );
    ensure!(
        observed.owner == expected_owner && observed.group == expected_group,
        "anonymous OCI replay spool ownership changed"
    );
    ensure!(
        observed.mode & PERMISSION_AND_SPECIAL_BITS == PRIVATE_SPOOL_MODE.bits(),
        "anonymous OCI replay spool is not exact private mode 0600"
    );
    Ok(())
}

fn directory_identity(descriptor: BorrowedFd<'_>) -> Result<DirectoryIdentity> {
    let stat = rustix::fs::fstat(descriptor).context("cannot inspect retained OCI directory")?;
    ensure!(
        rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir(),
        "retained OCI descriptor is not an ordinary directory"
    );
    Ok(DirectoryIdentity {
        device: checked_identity_component(stat.st_dev, "directory device does not fit u64")?,
        inode: checked_identity_component(stat.st_ino, "directory inode does not fit u64")?,
        mount_id: descriptor_mount_id(descriptor)?,
    })
}

fn regular_file_observation(file: &File) -> Result<FileObservation> {
    let stat = rustix::fs::fstat(file).context("cannot inspect retained OCI regular file")?;
    ensure!(
        rustix::fs::FileType::from_raw_mode(stat.st_mode).is_file(),
        "retained OCI descriptor is not an ordinary regular file"
    );
    Ok(FileObservation {
        identity: FileIdentity {
            device: checked_identity_component(stat.st_dev, "file device does not fit u64")?,
            inode: checked_identity_component(stat.st_ino, "file inode does not fit u64")?,
            mount_id: descriptor_mount_id(file.as_fd())?,
        },
        byte_length: checked_identity_component(stat.st_size, "file length does not fit u64")?,
        hard_link_count: checked_identity_component(
            stat.st_nlink,
            "file link count does not fit u64",
        )?,
        mode: stat.st_mode,
        owner: checked_identity_component(stat.st_uid, "file owner does not fit u64")?,
        group: checked_identity_component(stat.st_gid, "file group does not fit u64")?,
        modification_time_seconds: stat.st_mtime,
        modification_time_nanoseconds: i64::try_from(stat.st_mtime_nsec)
            .context("retained OCI regular-file mtime nanoseconds do not fit i64")?,
    })
}

fn descriptor_mount_id(descriptor: BorrowedFd<'_>) -> Result<u64> {
    let statx = rustix::fs::statx(
        descriptor,
        "",
        rustix::fs::AtFlags::EMPTY_PATH,
        rustix::fs::StatxFlags::BASIC_STATS | rustix::fs::StatxFlags::MNT_ID,
    )
    .context("cannot obtain retained OCI mount identity")?;
    ensure!(
        rustix::fs::StatxFlags::from_bits_retain(statx.stx_mask)
            .contains(rustix::fs::StatxFlags::MNT_ID),
        "Linux statx did not return an OCI mount identity"
    );
    Ok(statx.stx_mnt_id)
}

fn checked_identity_component<T>(value: T, error: &'static str) -> Result<u64>
where
    u64: TryFrom<T>,
{
    u64::try_from(value).map_err(|_| anyhow::Error::msg(error))
}

fn ensure_absent(descriptor: BorrowedFd<'_>, name: &OsStr, label: &str) -> Result<()> {
    match rustix::fs::statat(descriptor, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(error) => {
            Err(anyhow::Error::from(error)).with_context(|| format!("cannot inspect {label}"))
        }
        Ok(_) => anyhow::bail!("{label} is occupied"),
    }
}

struct PinnedAbsoluteDirectoryPath {
    anchor: OwnedFd,
    anchor_identity: DirectoryIdentity,
    components: Vec<OsString>,
    descriptors: Vec<OwnedFd>,
    identities: Vec<DirectoryIdentity>,
}

impl PinnedAbsoluteDirectoryPath {
    fn open(path: &Path) -> Result<Self> {
        validate_normalized_absolute_parent(path)?;
        let anchor = rustix::fs::open(
            Path::new("/"),
            PINNED_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
        )
        .context("cannot open OCI filesystem root anchor")?;
        let anchor_identity = directory_identity(anchor.as_fd())?;
        let mut components = Vec::new();
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => components.push(name.to_os_string()),
                Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                    anyhow::bail!("OCI spool parent is not normalized absolute")
                }
            }
        }
        let mut descriptors = Vec::new();
        let mut identities = Vec::new();
        descriptors
            .try_reserve_exact(components.len())
            .context("cannot retain OCI spool parent descriptors")?;
        identities
            .try_reserve_exact(components.len())
            .context("cannot retain OCI spool parent identities")?;
        for (index, component) in components.iter().enumerate() {
            let parent = descriptors
                .last()
                .map_or_else(|| anchor.as_fd(), OwnedFd::as_fd);
            let descriptor = rustix::fs::openat2(
                parent,
                component.as_os_str(),
                PINNED_DIRECTORY_FLAGS,
                rustix::fs::Mode::empty(),
                PARENT_COMPONENT_RESOLVE_FLAGS,
            )
            .with_context(|| format!("cannot pin OCI spool parent component {index}"))?;
            identities.push(directory_identity(descriptor.as_fd())?);
            descriptors.push(descriptor);
        }
        Ok(Self {
            anchor,
            anchor_identity,
            components,
            descriptors,
            identities,
        })
    }

    fn descriptor(&self) -> BorrowedFd<'_> {
        self.descriptors
            .last()
            .map_or_else(|| self.anchor.as_fd(), OwnedFd::as_fd)
    }

    fn identity(&self) -> DirectoryIdentity {
        self.identities
            .last()
            .copied()
            .unwrap_or(self.anchor_identity)
    }

    fn reauthenticate(&self) -> Result<()> {
        ensure!(
            directory_identity(self.anchor.as_fd())? == self.anchor_identity,
            "retained OCI filesystem anchor identity changed"
        );
        for (index, (descriptor, identity)) in
            self.descriptors.iter().zip(&self.identities).enumerate()
        {
            ensure!(
                directory_identity(descriptor.as_fd())? == *identity,
                "retained OCI spool parent component {index} identity changed"
            );
        }
        let reopened_anchor = rustix::fs::openat2(
            self.anchor.as_fd(),
            ".",
            PINNED_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
            PARENT_COMPONENT_RESOLVE_FLAGS,
        )
        .context("OCI spool parent pathname no longer names its anchor")?;
        ensure!(
            directory_identity(reopened_anchor.as_fd())? == self.anchor_identity,
            "OCI spool parent pathname changed its anchor identity"
        );
        let mut reopened: Vec<OwnedFd> = Vec::new();
        reopened
            .try_reserve_exact(self.components.len())
            .context("cannot retain reauthenticated OCI spool parent")?;
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
                PARENT_COMPONENT_RESOLVE_FLAGS,
            )
            .with_context(|| format!("OCI spool parent pathname changed at component {index}"))?;
            ensure!(
                directory_identity(descriptor.as_fd())? == *identity,
                "OCI spool parent pathname changed component {index} identity"
            );
            reopened.push(descriptor);
        }
        Ok(())
    }
}

fn validate_normalized_absolute_rootfs_path(path: &Path) -> Result<()> {
    ensure!(
        path.as_os_str().as_bytes().len() <= OCI_ROOTFS_PARENT_MAX_BYTES,
        "OCI rootfs final path exceeds its compiled byte bound"
    );
    validate_normalized_absolute_parent(path)
}

fn validate_normalized_absolute_parent(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "OCI spool path must be absolute");
    ensure!(
        path.as_os_str().as_bytes().len() <= OCI_ROOTFS_PARENT_MAX_BYTES,
        "OCI spool path exceeds its compiled byte bound"
    );
    let mut rebuilt = PathBuf::new();
    let mut normal_components = 0_usize;
    for component in path.components() {
        match component {
            Component::RootDir => rebuilt.push(component.as_os_str()),
            Component::Normal(name) => {
                normal_components = normal_components
                    .checked_add(1)
                    .context("OCI spool path component count overflowed")?;
                ensure!(
                    normal_components <= OCI_ROOTFS_PARENT_MAX_COMPONENTS,
                    "OCI spool path exceeds its compiled component bound"
                );
                rebuilt.push(name);
            }
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                anyhow::bail!("OCI spool path must be normalized absolute")
            }
        }
    }
    ensure!(
        rebuilt.as_os_str() == path.as_os_str(),
        "OCI spool path must be normalized absolute"
    );
    Ok(())
}

fn validate_root_leaf(path: &str, label: &str) -> Result<()> {
    ensure!(
        (1..=OCI_LAYER_PATH_MAX_BYTES).contains(&path.len()),
        "{label} length is outside its closed range"
    );
    ensure!(!path.as_bytes().contains(&0), "{label} contains a NUL byte");
    ensure!(
        !path.contains('/') && !matches!(path, "." | ".."),
        "{label} is not a root-level canonical name"
    );
    Ok(())
}

fn validate_normalized_rootfs_path(path: &str, label: &str) -> Result<()> {
    ensure!(
        (1..=OCI_LAYER_PATH_MAX_BYTES).contains(&path.len()),
        "{label} length is outside its closed range"
    );
    ensure!(!path.as_bytes().contains(&0), "{label} contains a NUL byte");
    ensure!(!path.starts_with('/'), "{label} is not relative POSIX");
    ensure!(
        path.split('/')
            .all(|component| !component.is_empty() && component != "." && component != ".."),
        "{label} is not lexically root-contained and canonical"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        ffi::{OsStr, OsString},
        fs::{self, File},
        os::{
            fd::AsFd as _,
            unix::fs::{FileExt as _, MetadataExt as _, PermissionsExt as _},
        },
        path::{Path, PathBuf},
    };

    use anyhow::Result;
    use eip_0045_reproduction::b4_positive_gate::PositiveRunnerRole;
    use rustix::path::DecInt;
    use sha2::{Digest as _, Sha256};

    use super::{
        AuthenticatedPrivateOciRetainedRootfsV1, AuthenticatedPrivateOciRootfsProjectionV1,
        OCI_REPLAY_CHUNK_MAX_BYTES, OciLayerReplayEntryV1, OciRootfsLiveCountersV1,
        OciRootfsSourceOrdinalV1, OciRootfsStagingLayoutV1,
        PrivateOciRetainedRootfsAcquisitionFailureV1, PrivateOciRetainedRootfsCleanupFailureV1,
        PrivateOciRootfsAbandonedV1, PrivateOciRootfsFailedV1,
        PrivateOciRootfsStagingTransactionV1,
        physical::{
            StartupClosureExpectedEdgeV1, StartupClosureTestExpectationV1,
            TestOnlyRetainedStartupBaselineV1,
        },
    };

    trait AmbiguousIfClone<A> {
        fn marker() {}
    }
    impl<T> AmbiguousIfClone<()> for T {}
    impl<T: Clone> AmbiguousIfClone<u8> for T {}

    trait AmbiguousIfCopy<A> {
        fn marker() {}
    }
    impl<T> AmbiguousIfCopy<()> for T {}
    impl<T: Copy> AmbiguousIfCopy<u8> for T {}

    const FORBIDDEN_STAGING_SURFACES: &[&str] = &[
        "pub ",
        "OFlags::CREATE",
        "OFlags::TRUNC",
        "OFlags::APPEND",
        "OpenOptions",
        "File::create",
        "File::options",
        "fs::write(",
        "fs::copy(",
        "create_dir(",
        "create_dir_all(",
        "mkdir(",
        "hard_link(",
        "symlink(",
        "rename(",
        "remove_file(",
        "remove_dir(",
        "remove_dir_all(",
        "mknod",
        "mkfifo",
        "NamedTempFile",
        "TempDir",
        "tempfile(",
        "tempfile_in(",
        "persist(",
        "persist_noclobber(",
        ".keep(",
        "shm_open",
        "memfd_create",
        "libc::",
        "syscall(",
        "mount(",
        "move_mount",
        "fsmount",
        "open_tree",
        "umount",
        "chmodat",
        "chownat",
        "utimensat",
        "set_permissions(",
        "mkdirat(",
        "linkat(",
        "renameat",
        "unlinkat(",
        "symlinkat(",
        "fn commit",
        "fn publish",
        "/proc/",
        "try_clone",
        "dup(",
        "dup2(",
        "dup3(",
        "pidfd_getfd",
        "fork(",
        "Command::",
        "Stdio",
        "impl Drop",
        "Deref",
        "into_parts",
        "as_raw_fd",
        "FromRawFd",
        "IntoRawFd",
        "into_raw_fd",
        "ManuallyDrop",
        "mem::forget",
        "SCM_RIGHTS",
        "posix_spawn",
        "execve",
        "std::process",
        "ExecutorExecuteContext",
        "MutationCapability",
        "Permit",
        "Completion",
        "Authority",
    ];

    fn projected(
        parent: &Path,
        final_name: &str,
    ) -> Result<(PathBuf, PathBuf, OciRootfsStagingLayoutV1)> {
        let final_path = parent.join(final_name);
        let former_named_staging = parent.join(format!(".{final_name}.reserved-staging-lure"));
        let layout =
            OciRootfsStagingLayoutV1::project(PositiveRunnerRole::RustValidatorBuild, &final_path)?;
        Ok((final_path, former_named_staging, layout))
    }

    fn source(semantic_layer_index: u64, archive_entry_index: u64) -> OciRootfsSourceOrdinalV1 {
        OciRootfsSourceOrdinalV1 {
            semantic_layer_index,
            archive_entry_index,
        }
    }

    fn logical_operation(
        semantic_layer_index: u64,
        archive_entry_index: u64,
        path: &str,
        kind: super::StagedRootfsOperationKindV1,
    ) -> super::StagedRootfsOperationV1 {
        super::StagedRootfsOperationV1 {
            source: source(semantic_layer_index, archive_entry_index),
            path: path.to_owned(),
            mode: match &kind {
                super::StagedRootfsOperationKindV1::Directory => 0o555,
                super::StagedRootfsOperationKindV1::OpaqueDirectory { .. }
                | super::StagedRootfsOperationKindV1::Remove { .. } => 0,
                super::StagedRootfsOperationKindV1::Regular { .. } => 0o444,
                super::StagedRootfsOperationKindV1::SymbolicLink { .. } => 0o777,
            },
            byte_length: 0,
            kind,
        }
    }

    fn stage_regular(
        transaction: &mut PrivateOciRootfsStagingTransactionV1,
        ordinal: OciRootfsSourceOrdinalV1,
        path: &str,
        mode: u64,
        payload: &[u8],
    ) -> Result<()> {
        transaction.begin_regular(ordinal, path, mode, u64::try_from(payload.len())?)?;
        if !payload.is_empty() {
            transaction.write_regular_chunk(payload)?;
        }
        transaction.finish_entry()
    }

    fn authenticated_single_regular_projection(
        parent: &Path,
        final_name: &str,
    ) -> Result<(PathBuf, AuthenticatedPrivateOciRootfsProjectionV1)> {
        let seal = super::super::layer::test_only_authenticated_regular_layer_seal(
            0, "artifact", 0o444, b"AAA",
        )?;
        let (final_path, _, layout) = projected(parent, final_name)?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        stage_regular(&mut transaction, source(0, 0), "artifact", 0o444, b"AAA")?;
        let retained =
            transaction.authenticate_and_retain(vec![seal], expected_rootfs(1, 1, 0, 0, 3))?;
        Ok((final_path, retained))
    }

    fn authenticated_mixed_projection(
        parent: &Path,
        final_name: &str,
    ) -> Result<(PathBuf, AuthenticatedPrivateOciRootfsProjectionV1)> {
        let lower_bin = OciLayerReplayEntryV1::directory("bin", 0o555, 0);
        let lower_old = OciLayerReplayEntryV1::regular_file("bin/old", 0o444, 3);
        let lower_gone = OciLayerReplayEntryV1::regular_file("gone", 0o444, 4);
        let remove_gone = OciLayerReplayEntryV1::remove(".wh.gone", 0, 0, "gone");
        let opaque_bin = OciLayerReplayEntryV1::opaque_directory("bin/.wh..wh..opq", 0, 0, "bin");
        let live_tool = OciLayerReplayEntryV1::regular_file("bin/tool", 0o555, 4);
        let live_link = OciLayerReplayEntryV1::symbolic_link("bin/tool-link", 0o777, 0, "tool");
        let live_notice = OciLayerReplayEntryV1::regular_file("notice", 0o444, 4);
        let lower_entries: [(&OciLayerReplayEntryV1<'_>, &[u8]); 3] = [
            (&lower_bin, &[]),
            (&lower_old, b"OLD"),
            (&lower_gone, b"GONE"),
        ];
        let upper_entries: [(&OciLayerReplayEntryV1<'_>, &[u8]); 5] = [
            (&remove_gone, &[]),
            (&opaque_bin, &[]),
            (&live_tool, b"EXEC"),
            (&live_link, &[]),
            (&live_notice, b"READ"),
        ];
        let seals = vec![
            authenticated_layer_seal(0, &lower_entries)?,
            authenticated_layer_seal(1, &upper_entries)?,
        ];
        let (final_path, _, layout) = projected(parent, final_name)?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 2)?;
        transaction.stage_directory(source(0, 0), "bin", 0o555, 0)?;
        stage_regular(&mut transaction, source(0, 1), "bin/old", 0o444, b"OLD")?;
        stage_regular(&mut transaction, source(0, 2), "gone", 0o444, b"GONE")?;
        transaction.stage_remove(source(1, 0), ".wh.gone", 0, 0, "gone")?;
        transaction.stage_opaque_directory(source(1, 1), "bin/.wh..wh..opq", 0, 0, "bin")?;
        stage_regular(&mut transaction, source(1, 2), "bin/tool", 0o555, b"EXEC")?;
        transaction.stage_symbolic_link(source(1, 3), "bin/tool-link", 0o777, 0, "tool")?;
        stage_regular(&mut transaction, source(1, 4), "notice", 0o444, b"READ")?;
        let retained =
            transaction.authenticate_and_retain(seals, expected_rootfs(4, 2, 1, 1, 8))?;
        assert_eq!(retained.canonical_live_operation_indices, [0, 5, 6, 7]);
        Ok((final_path, retained))
    }

    fn authenticated_nested_directory_projection(
        parent: &Path,
        final_name: &str,
    ) -> Result<(PathBuf, AuthenticatedPrivateOciRootfsProjectionV1)> {
        let first = OciLayerReplayEntryV1::directory("a", 0o555, 0);
        let second = OciLayerReplayEntryV1::directory("a/b", 0o555, 0);
        let third = OciLayerReplayEntryV1::directory("a/b/c", 0o555, 0);
        let entries: [(&OciLayerReplayEntryV1<'_>, &[u8]); 3] =
            [(&first, &[]), (&second, &[]), (&third, &[])];
        let seals = vec![authenticated_layer_seal(0, &entries)?];
        let (final_path, _, layout) = projected(parent, final_name)?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        transaction.stage_directory(source(0, 0), "a", 0o555, 0)?;
        transaction.stage_directory(source(0, 1), "a/b", 0o555, 0)?;
        transaction.stage_directory(source(0, 2), "a/b/c", 0o555, 0)?;
        let retained =
            transaction.authenticate_and_retain(seals, expected_rootfs(3, 0, 3, 0, 0))?;
        Ok((final_path, retained))
    }

    #[derive(Clone)]
    enum RuntimeRootfsFixtureKindV1 {
        Directory,
        Regular { mode: u64, payload: Vec<u8> },
        SymbolicLink { target: String },
    }

    #[derive(Clone)]
    struct RuntimeRootfsFixtureEntryV1 {
        path: String,
        kind: RuntimeRootfsFixtureKindV1,
    }

    struct PrivateStartupDependencyFixtureExpectationV1<'a> {
        mount_targets: &'a [&'a str],
        expected_canonical_node_order: Option<&'a [&'a str]>,
        expected_edges: Option<&'a [StartupClosureExpectedEdgeV1<'a>]>,
        expected_aggregate_distinct_object_bytes: Option<u64>,
        expected_error_fragment: Option<&'a str>,
    }

    impl RuntimeRootfsFixtureEntryV1 {
        fn directory(path: impl Into<String>) -> Self {
            Self {
                path: path.into(),
                kind: RuntimeRootfsFixtureKindV1::Directory,
            }
        }

        fn regular(path: impl Into<String>, mode: u64, payload: &[u8]) -> Self {
            Self {
                path: path.into(),
                kind: RuntimeRootfsFixtureKindV1::Regular {
                    mode,
                    payload: payload.to_vec(),
                },
            }
        }

        fn symbolic_link(path: impl Into<String>, target: impl Into<String>) -> Self {
            Self {
                path: path.into(),
                kind: RuntimeRootfsFixtureKindV1::SymbolicLink {
                    target: target.into(),
                },
            }
        }

        fn replay_entry(&self) -> Result<OciLayerReplayEntryV1<'_>> {
            Ok(match &self.kind {
                RuntimeRootfsFixtureKindV1::Directory => {
                    OciLayerReplayEntryV1::directory(&self.path, 0o555, 0)
                }
                RuntimeRootfsFixtureKindV1::Regular { mode, payload } => {
                    OciLayerReplayEntryV1::regular_file(
                        &self.path,
                        *mode,
                        u64::try_from(payload.len())?,
                    )
                }
                RuntimeRootfsFixtureKindV1::SymbolicLink { target } => {
                    OciLayerReplayEntryV1::symbolic_link(&self.path, 0o777, 0, target.as_str())
                }
            })
        }

        fn payload(&self) -> &[u8] {
            match &self.kind {
                RuntimeRootfsFixtureKindV1::Regular { payload, .. } => payload,
                RuntimeRootfsFixtureKindV1::Directory
                | RuntimeRootfsFixtureKindV1::SymbolicLink { .. } => &[],
            }
        }

        fn stage(
            &self,
            transaction: &mut PrivateOciRootfsStagingTransactionV1,
            ordinal: OciRootfsSourceOrdinalV1,
        ) -> Result<()> {
            match &self.kind {
                RuntimeRootfsFixtureKindV1::Directory => {
                    transaction.stage_directory(ordinal, &self.path, 0o555, 0)
                }
                RuntimeRootfsFixtureKindV1::Regular { mode, payload } => {
                    stage_regular(transaction, ordinal, &self.path, *mode, payload)
                }
                RuntimeRootfsFixtureKindV1::SymbolicLink { target } => {
                    transaction.stage_symbolic_link(ordinal, &self.path, 0o777, 0, target.as_str())
                }
            }
        }
    }

    fn authenticated_runtime_elf_projection(
        parent: &Path,
        final_name: &str,
        runtime_elf: &[u8],
    ) -> Result<(PathBuf, AuthenticatedPrivateOciRootfsProjectionV1)> {
        authenticated_runtime_elf_projection_with_entries(parent, final_name, runtime_elf, &[])
    }

    fn authenticated_runtime_elf_projection_with_entries(
        parent: &Path,
        final_name: &str,
        runtime_elf: &[u8],
        extra_entries: &[RuntimeRootfsFixtureEntryV1],
    ) -> Result<(PathBuf, AuthenticatedPrivateOciRootfsProjectionV1)> {
        authenticated_runtime_elf_projection_with_role_and_entries(
            parent,
            final_name,
            PositiveRunnerRole::JvmVerifier,
            runtime_elf,
            extra_entries,
        )
    }

    fn authenticated_runtime_elf_projection_with_role_and_entries(
        parent: &Path,
        final_name: &str,
        role: PositiveRunnerRole,
        runtime_elf: &[u8],
        extra_entries: &[RuntimeRootfsFixtureEntryV1],
    ) -> Result<(PathBuf, AuthenticatedPrivateOciRootfsProjectionV1)> {
        let mut entries = vec![
            RuntimeRootfsFixtureEntryV1::directory("runtime"),
            RuntimeRootfsFixtureEntryV1::directory("runtime/bin"),
            RuntimeRootfsFixtureEntryV1::regular("runtime/bin/java", 0o555, runtime_elf),
        ];
        entries.extend_from_slice(extra_entries);
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        anyhow::ensure!(
            entries.windows(2).all(|pair| pair[0].path < pair[1].path),
            "runtime rootfs fixture paths are not unique"
        );
        let replay_entries = entries
            .iter()
            .map(RuntimeRootfsFixtureEntryV1::replay_entry)
            .collect::<Result<Vec<_>>>()?;
        let transcript_entries = replay_entries
            .iter()
            .zip(&entries)
            .map(|(entry, fixture)| (entry, fixture.payload()))
            .collect::<Vec<_>>();
        let seals = vec![authenticated_layer_seal(0, &transcript_entries)?];
        let final_path = parent.join(final_name);
        let layout = OciRootfsStagingLayoutV1::project(role, &final_path)?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        for (entry_index, entry) in entries.iter().enumerate() {
            entry.stage(&mut transaction, source(0, u64::try_from(entry_index)?))?;
        }
        let entry_count = u64::try_from(entries.len())?;
        let regular_file_count = u64::try_from(
            entries
                .iter()
                .filter(|entry| matches!(&entry.kind, RuntimeRootfsFixtureKindV1::Regular { .. }))
                .count(),
        )?;
        let directory_count = u64::try_from(
            entries
                .iter()
                .filter(|entry| matches!(&entry.kind, RuntimeRootfsFixtureKindV1::Directory))
                .count(),
        )?;
        let symbolic_link_count = u64::try_from(
            entries
                .iter()
                .filter(|entry| {
                    matches!(&entry.kind, RuntimeRootfsFixtureKindV1::SymbolicLink { .. })
                })
                .count(),
        )?;
        let regular_file_bytes = entries.iter().try_fold(0_u64, |total, entry| {
            let RuntimeRootfsFixtureKindV1::Regular { payload, .. } = &entry.kind else {
                return Ok(total);
            };
            total
                .checked_add(u64::try_from(payload.len())?)
                .ok_or_else(|| anyhow::anyhow!("runtime rootfs fixture byte count overflowed"))
        })?;
        let retained = transaction.authenticate_and_retain(
            seals,
            expected_rootfs(
                entry_count,
                regular_file_count,
                directory_count,
                symbolic_link_count,
                regular_file_bytes,
            ),
        )?;
        Ok((final_path, retained))
    }

    fn physical_rootfs_path_fixture(
        role: PositiveRunnerRole,
    ) -> (Vec<RuntimeRootfsFixtureEntryV1>, Vec<(&'static str, bool)>) {
        let mut entries = vec![
            RuntimeRootfsFixtureEntryV1::directory("dev"),
            RuntimeRootfsFixtureEntryV1::regular("dev/full", 0o444, b""),
            RuntimeRootfsFixtureEntryV1::regular("dev/null", 0o444, b""),
            RuntimeRootfsFixtureEntryV1::regular("dev/random", 0o444, b""),
            RuntimeRootfsFixtureEntryV1::regular("dev/urandom", 0o444, b""),
            RuntimeRootfsFixtureEntryV1::regular("dev/zero", 0o444, b""),
            RuntimeRootfsFixtureEntryV1::directory("proc"),
            RuntimeRootfsFixtureEntryV1::directory("tmp"),
        ];
        let mut requirements = vec![
            ("/dev", true),
            ("/dev/full", false),
            ("/dev/null", false),
            ("/dev/random", false),
            ("/dev/urandom", false),
            ("/dev/zero", false),
        ];
        match role {
            PositiveRunnerRole::RustValidatorBuild => {
                entries.extend([
                    RuntimeRootfsFixtureEntryV1::directory("deps"),
                    RuntimeRootfsFixtureEntryV1::directory("out"),
                    RuntimeRootfsFixtureEntryV1::directory("src"),
                ]);
                requirements.splice(0..0, [("/deps", true)]);
                requirements.extend([
                    ("/out", true),
                    ("/proc", true),
                    ("/src", true),
                    ("/tmp", true),
                ]);
            }
            PositiveRunnerRole::JvmValidatorBuild => {
                entries.extend([
                    RuntimeRootfsFixtureEntryV1::directory("deps"),
                    RuntimeRootfsFixtureEntryV1::directory("out"),
                    RuntimeRootfsFixtureEntryV1::directory("phase-input"),
                    RuntimeRootfsFixtureEntryV1::directory("src"),
                ]);
                requirements.splice(0..0, [("/deps", true)]);
                requirements.extend([
                    ("/out", true),
                    ("/phase-input", true),
                    ("/proc", true),
                    ("/src", true),
                    ("/tmp", true),
                ]);
            }
            PositiveRunnerRole::RustVerifier => {
                entries.extend([
                    RuntimeRootfsFixtureEntryV1::directory("input"),
                    RuntimeRootfsFixtureEntryV1::directory("validator"),
                    RuntimeRootfsFixtureEntryV1::regular("validator/validator", 0o444, b""),
                ]);
                requirements.extend([
                    ("/input", true),
                    ("/proc", true),
                    ("/tmp", true),
                    ("/validator/validator", false),
                ]);
            }
            PositiveRunnerRole::JvmVerifier => {
                entries.extend([
                    RuntimeRootfsFixtureEntryV1::directory("input"),
                    RuntimeRootfsFixtureEntryV1::directory("validator"),
                    RuntimeRootfsFixtureEntryV1::regular("validator/validator.jar", 0o555, b""),
                ]);
                requirements.extend([
                    ("/input", true),
                    ("/proc", true),
                    ("/tmp", true),
                    ("/validator/validator.jar", false),
                ]);
            }
        }
        (entries, requirements)
    }

    fn exercise_private_rootfs_path_fixture(
        suffix: &str,
        actual_role: PositiveRunnerRole,
        expected_role: PositiveRunnerRole,
        entries: &[RuntimeRootfsFixtureEntryV1],
        requirements: &[(&str, bool)],
        expected_error: Option<&str>,
    ) -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
        let final_name = format!("physical-rootfs-path-{suffix}");
        let (final_path, retained) = authenticated_runtime_elf_projection_with_role_and_entries(
            temp.path(),
            &final_name,
            actual_role,
            &runtime_elf,
            entries,
        )?;
        let result = retained
            .materialize_private()?
            .test_only_authenticate_rootfs_paths_and_cleanup(expected_role, requirements);
        match (result, expected_error) {
            (Ok(abandonment), None) => assert!(abandonment.final_unlinked_observed),
            (Err(error), Some(fragment)) => assert!(
                format!("{error:#}").contains(fragment),
                "expected {fragment:?}, observed {error:#}"
            ),
            (Ok(_), Some(fragment)) => {
                anyhow::bail!("rootfs path fixture unexpectedly accepted {fragment}")
            }
            (Err(error), None) => return Err(error),
        }
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "isolated release fixtures vary each bound identity field independently"
    )]
    fn exercise_private_java_release_fixture(
        release: &[u8],
        expected_byte_length: u64,
        expected_sha256: [u8; super::SHA256_BYTES],
        feature_version: u64,
        vendor: &str,
        version: &str,
        expected_error: Option<&str>,
    ) -> Result<()> {
        exercise_private_java_release_fixture_with_mode(
            0o444,
            release,
            expected_byte_length,
            expected_sha256,
            feature_version,
            vendor,
            version,
            expected_error,
        )
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "isolated release fixtures also prove both allowed physical modes"
    )]
    fn exercise_private_java_release_fixture_with_mode(
        mode: u64,
        release: &[u8],
        expected_byte_length: u64,
        expected_sha256: [u8; super::SHA256_BYTES],
        feature_version: u64,
        vendor: &str,
        version: &str,
        expected_error: Option<&str>,
    ) -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
        let (final_path, retained) = authenticated_runtime_elf_projection_with_entries(
            temp.path(),
            "physical-java-release-fixture",
            &runtime_elf,
            &[RuntimeRootfsFixtureEntryV1::regular(
                "runtime/release",
                mode,
                release,
            )],
        )?;
        let result = retained
            .materialize_private()?
            .test_only_authenticate_java_release_and_cleanup(
                PositiveRunnerRole::JvmVerifier,
                "/runtime/release",
                expected_byte_length,
                expected_sha256,
                feature_version,
                vendor,
                version,
            );
        match (result, expected_error) {
            (Ok(abandonment), None) => assert!(abandonment.final_unlinked_observed),
            (Err(error), Some(fragment)) => assert!(
                format!("{error:#}").contains(fragment),
                "expected {fragment:?}, observed {error:#}"
            ),
            (Ok(_), Some(fragment)) => {
                anyhow::bail!("Java release fixture unexpectedly accepted {fragment}")
            }
            (Err(error), None) => return Err(error),
        }
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    fn exercise_private_java_release_malformed_cases<const CASES: usize>(
        cases: [(Vec<u8>, &'static str); CASES],
    ) -> Result<()> {
        for (bytes, expected_error) in cases {
            exercise_private_java_release_fixture(
                &bytes,
                u64::try_from(bytes.len())?,
                Sha256::digest(&bytes).into(),
                21,
                "Fixture JVM",
                "21.0.1",
                Some(expected_error),
            )?;
        }
        Ok(())
    }

    fn expected_rootfs(
        entry_count: u64,
        regular_file_count: u64,
        directory_count: u64,
        symbolic_link_count: u64,
        regular_file_bytes: u64,
    ) -> super::super::json::OciExpectedRootfsV1 {
        super::super::json::OciExpectedRootfsV1::test_only(
            entry_count,
            regular_file_count,
            directory_count,
            symbolic_link_count,
            regular_file_bytes,
        )
    }

    fn authenticated_layer_seal(
        semantic_layer_index: u64,
        entries: &[(&super::super::layer::OciLayerReplayEntryV1<'_>, &[u8])],
    ) -> Result<super::super::AuthenticatedOciLayerSealV1> {
        let mut transcript = super::super::layer::ChangesetTranscriptV1::new();
        for (entry, payload) in entries {
            transcript.begin_entry(entry)?;
            for chunk in payload.chunks(OCI_REPLAY_CHUNK_MAX_BYTES) {
                transcript.write_regular_file_chunk(chunk)?;
            }
            transcript.finish_entry()?;
        }
        Ok(super::super::AuthenticatedOciLayerSealV1 {
            semantic_layer_index,
            authenticated_entry_count: u64::try_from(entries.len())?,
            changeset_transcript_sha256: transcript.finish()?,
            _private: (),
        })
    }

    #[derive(Clone, Copy)]
    enum LogicalIdentityFixtureKindV1<'fixture> {
        Regular {
            byte_length: u64,
            sha256: [u8; super::SHA256_BYTES],
        },
        Directory,
        SymbolicLink(&'fixture str),
    }

    #[derive(Clone, Copy)]
    struct LogicalIdentityFixtureV1<'fixture> {
        role: PositiveRunnerRole,
        path: &'fixture str,
        mode: u32,
        kind: LogicalIdentityFixtureKindV1<'fixture>,
        counters: OciRootfsLiveCountersV1,
        operation_source: OciRootfsSourceOrdinalV1,
        extent_offset: u64,
        superseded_history: bool,
    }

    impl LogicalIdentityFixtureV1<'_> {
        fn identity(self) -> Result<[u8; super::SHA256_BYTES]> {
            let mut extents = Vec::new();
            let (kind, byte_length) = match self.kind {
                LogicalIdentityFixtureKindV1::Regular {
                    byte_length,
                    sha256,
                } => {
                    extents.push(super::StagedRegularExtentV1 {
                        source: self.operation_source,
                        offset: self.extent_offset,
                        byte_length,
                        mode: self.mode,
                        sha256,
                    });
                    (
                        super::StagedRootfsOperationKindV1::Regular { extent_index: 0 },
                        byte_length,
                    )
                }
                LogicalIdentityFixtureKindV1::Directory => {
                    (super::StagedRootfsOperationKindV1::Directory, 0)
                }
                LogicalIdentityFixtureKindV1::SymbolicLink(target) => (
                    super::StagedRootfsOperationKindV1::SymbolicLink {
                        target: target.to_owned(),
                    },
                    0,
                ),
            };
            let mut operations = Vec::new();
            if self.superseded_history {
                operations.push(logical_operation(
                    0,
                    0,
                    self.path,
                    super::StagedRootfsOperationKindV1::Directory,
                ));
            }
            let live_definition = operations.len();
            operations.push(super::StagedRootfsOperationV1 {
                source: self.operation_source,
                path: self.path.to_owned(),
                mode: self.mode,
                byte_length,
                kind,
            });
            let live_operation = &operations[live_definition];
            let mut projection = super::RootfsProjectionV1 {
                counters: self.counters,
                ..super::RootfsProjectionV1::default()
            };
            projection.paths.insert(
                live_operation.path.as_str(),
                super::RootfsPathProjectionV1 {
                    live_definition,
                    last_effect: super::effect_reference(
                        live_definition,
                        live_operation,
                        super::OciRootfsEffectPhaseV1::Entry,
                    ),
                },
            );
            Ok(
                super::validated_logical_projection(self.role, &projection, &operations, &extents)?
                    .authenticated_logical_projection_sha256,
            )
        }
    }

    fn regular_logical_identity_fixture(
        sha256: [u8; super::SHA256_BYTES],
    ) -> LogicalIdentityFixtureV1<'static> {
        LogicalIdentityFixtureV1 {
            role: PositiveRunnerRole::RustValidatorBuild,
            path: "artifact",
            mode: 0o444,
            kind: LogicalIdentityFixtureKindV1::Regular {
                byte_length: 3,
                sha256,
            },
            counters: OciRootfsLiveCountersV1 {
                entry_count: 1,
                regular_file_count: 1,
                directory_count: 0,
                symbolic_link_count: 0,
                regular_file_bytes: 3,
            },
            operation_source: source(0, 0),
            extent_offset: 0,
            superseded_history: false,
        }
    }

    fn assert_shared_rootfs_transcript(
        parent: &Path,
        final_name: &str,
        entry: &super::super::layer::OciLayerReplayEntryV1<'_>,
        payload: &[u8],
        rootfs_chunk_bytes: usize,
        encoder_chunk_bytes: usize,
    ) -> Result<()> {
        let mut expected = super::super::layer::ChangesetTranscriptV1::new();
        expected.begin_entry(entry)?;
        for chunk in payload.chunks(encoder_chunk_bytes) {
            expected.write_regular_file_chunk(chunk)?;
        }
        expected.finish_entry()?;
        let expected = expected.finish()?;

        let (_, _, layout) = projected(parent, final_name)?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        {
            let mut sink = transaction.replay_semantic_layer_sink(0)?;
            super::super::layer::OciLayerReplaySinkV1::begin_entry(&mut sink, entry)?;
            for chunk in payload.chunks(rootfs_chunk_bytes) {
                super::super::layer::OciLayerReplaySinkV1::write_regular_file_chunk(
                    &mut sink, chunk,
                )?;
            }
            super::super::layer::OciLayerReplaySinkV1::finish_entry(&mut sink)?;
        }
        let observed = transaction.captured_canonical_layer_transcripts[0]
            .clone()
            .finish()?;
        assert_eq!(observed, expected, "{final_name}");
        assert!(transaction.abandon().final_unlinked_observed);
        Ok(())
    }

    fn discard_single_layer(
        mut transaction: PrivateOciRootfsStagingTransactionV1,
    ) -> std::result::Result<PrivateOciRootfsAbandonedV1, Box<PrivateOciRootfsFailedV1>> {
        let entry_count = transaction.captured_layer_entries[0];
        transaction
            .seal_semantic_layer(0, entry_count)
            .expect("single-layer test journal must seal");
        transaction.discard()
    }

    fn expect_error<T>(result: Result<T>) -> anyhow::Error {
        match result {
            Ok(_) => panic!("operation unexpectedly succeeded"),
            Err(error) => error,
        }
    }

    fn expect_physical_cleanup_failure(
        error: anyhow::Error,
    ) -> super::physical::PrivateOciRootfsCleanupFailureV1 {
        match error.downcast::<super::physical::PrivateOciRootfsCleanupFailureV1>() {
            Ok(failure) => failure,
            Err(error) => panic!("expected typed physical cleanup custody: {error:#}"),
        }
    }

    fn directory_names(path: &Path) -> Result<BTreeSet<OsString>> {
        fs::read_dir(path)?
            .map(|entry| Ok(entry?.file_name()))
            .collect()
    }

    fn normalize_test_path_mtime(path: &Path) -> Result<()> {
        let descriptor = File::open(path)?;
        rustix::fs::futimens(
            descriptor.as_fd(),
            &rustix::fs::Timestamps {
                last_access: rustix::fs::Timespec {
                    tv_sec: 0,
                    tv_nsec: rustix::fs::UTIME_OMIT,
                },
                last_modification: rustix::fs::Timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
            },
        )?;
        Ok(())
    }

    fn reopen_test_sealed_directory(path: &Path) -> Result<()> {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn reseal_test_directory(path: &Path) -> Result<()> {
        normalize_test_path_mtime(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o555))?;
        Ok(())
    }

    fn exercise_private_runtime_elf_fixture(
        parent: &Path,
        final_name: &str,
        extra_entries: &[RuntimeRootfsFixtureEntryV1],
        expected_error_fragment: Option<&str>,
    ) -> Result<()> {
        let before = directory_names(parent)?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
        let (final_path, retained) = authenticated_runtime_elf_projection_with_entries(
            parent,
            final_name,
            &runtime_elf,
            extra_entries,
        )?;
        let materialized = retained.materialize_private()?;
        let validation = materialized.test_only_authenticate_runtime_elf("/runtime/bin/java");
        match expected_error_fragment {
            Some(fragment) => {
                let error = validation.unwrap_err();
                assert!(format!("{error:#}").contains(fragment), "{error:#}");
            }
            None => validation?,
        }
        let abandonment = materialized.cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(parent)?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    fn startup_default_directory_entries() -> Vec<RuntimeRootfsFixtureEntryV1> {
        [
            "lib",
            "lib/x86_64-linux-gnu",
            "lib64",
            "usr",
            "usr/lib",
            "usr/lib/x86_64-linux-gnu",
            "usr/lib64",
        ]
        .into_iter()
        .map(RuntimeRootfsFixtureEntryV1::directory)
        .collect()
    }

    fn startup_base_entries(
        interpreter: &[u8],
        interpreter_mode: u64,
    ) -> Vec<RuntimeRootfsFixtureEntryV1> {
        let mut entries = startup_default_directory_entries();
        entries.push(RuntimeRootfsFixtureEntryV1::regular(
            "lib64/ld-linux-x86-64.so.2",
            interpreter_mode,
            interpreter,
        ));
        entries
    }

    fn startup_search_directory_symlink_chain(
        directory_hops: usize,
        dependency: &[u8],
    ) -> Vec<RuntimeRootfsFixtureEntryV1> {
        assert!(directory_hops >= 1);
        let mut entries = vec![
            RuntimeRootfsFixtureEntryV1::symbolic_link("alias", "/search-links/00"),
            RuntimeRootfsFixtureEntryV1::directory("search-links"),
            RuntimeRootfsFixtureEntryV1::directory("actual-search"),
            RuntimeRootfsFixtureEntryV1::directory("payload"),
        ];
        for index in 0..directory_hops - 1 {
            entries.push(RuntimeRootfsFixtureEntryV1::symbolic_link(
                format!("search-links/{index:02}"),
                format!("{:02}", index + 1),
            ));
        }
        entries.push(RuntimeRootfsFixtureEntryV1::symbolic_link(
            format!("search-links/{:02}", directory_hops - 1),
            "/actual-search",
        ));
        entries.push(RuntimeRootfsFixtureEntryV1::symbolic_link(
            "actual-search/libc.so.6",
            "/payload/object",
        ));
        entries.push(RuntimeRootfsFixtureEntryV1::regular(
            "payload/object",
            0o444,
            dependency,
        ));
        entries
    }

    fn startup_linear_dependency_fixture(
        dependency_count: usize,
        interpreter: &[u8],
    ) -> (Vec<u8>, Vec<RuntimeRootfsFixtureEntryV1>) {
        assert!(dependency_count >= 1);
        let names = (0..dependency_count)
            .map(|index| format!("libdepth-{index:03}.so"))
            .collect::<Vec<_>>();
        let runtime =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_runtime_elf_bytes(
                &[names[0].as_str()],
                None,
            );
        let mut entries = startup_base_entries(interpreter, 0o555);
        for (index, name) in names.iter().enumerate() {
            let needed = names
                .get(index + 1)
                .map_or_else(Vec::new, |next| vec![next.as_str()]);
            let dso = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                name, &needed, None,
            );
            entries.push(RuntimeRootfsFixtureEntryV1::regular(
                format!("lib/x86_64-linux-gnu/{name}"),
                0o444,
                &dso,
            ));
        }
        (runtime, entries)
    }

    fn startup_wide_loaded_graph_fixture(
        dependency_count: usize,
        total_edge_count: usize,
        interpreter: &[u8],
    ) -> (Vec<u8>, Vec<RuntimeRootfsFixtureEntryV1>) {
        assert!(total_edge_count >= dependency_count);
        let names = (0..dependency_count)
            .map(|index| format!("libwide-{index:03}.so"))
            .collect::<Vec<_>>();
        let root_needed = names.iter().map(String::as_str).collect::<Vec<_>>();
        let runtime =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_runtime_elf_bytes(
                &root_needed,
                None,
            );
        let mut remaining_reuse_edges = total_edge_count - dependency_count;
        let mut entries = startup_base_entries(interpreter, 0o555);
        for name in &names {
            let needed_count = remaining_reuse_edges.min(names.len());
            remaining_reuse_edges -= needed_count;
            let needed = names
                .iter()
                .take(needed_count)
                .map(String::as_str)
                .collect::<Vec<_>>();
            let dso = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                name, &needed, None,
            );
            entries.push(RuntimeRootfsFixtureEntryV1::regular(
                format!("lib/x86_64-linux-gnu/{name}"),
                0o444,
                &dso,
            ));
        }
        assert_eq!(remaining_reuse_edges, 0);
        (runtime, entries)
    }

    fn exercise_private_startup_dependency_fixture(
        parent: &Path,
        final_name: &str,
        runtime_elf: &[u8],
        extra_entries: &[RuntimeRootfsFixtureEntryV1],
        mount_targets: &[&str],
        expected_error_fragment: Option<&str>,
    ) -> Result<()> {
        exercise_private_startup_dependency_fixture_with_expected_order(
            parent,
            final_name,
            runtime_elf,
            extra_entries,
            &PrivateStartupDependencyFixtureExpectationV1 {
                mount_targets,
                expected_canonical_node_order: None,
                expected_edges: None,
                expected_aggregate_distinct_object_bytes: None,
                expected_error_fragment,
            },
        )
    }

    fn exercise_private_startup_dependency_fixture_with_expected_order(
        parent: &Path,
        final_name: &str,
        runtime_elf: &[u8],
        extra_entries: &[RuntimeRootfsFixtureEntryV1],
        expectation: &PrivateStartupDependencyFixtureExpectationV1<'_>,
    ) -> Result<()> {
        let mount_targets = expectation.mount_targets;
        let expected_canonical_node_order = expectation.expected_canonical_node_order;
        let expected_edges = expectation.expected_edges;
        let expected_aggregate_distinct_object_bytes =
            expectation.expected_aggregate_distinct_object_bytes;
        let expected_error_fragment = expectation.expected_error_fragment;
        let before = directory_names(parent)?;
        let (final_path, retained) = authenticated_runtime_elf_projection_with_entries(
            parent,
            final_name,
            runtime_elf,
            extra_entries,
        )?;
        let startup_expectation = StartupClosureTestExpectationV1 {
            image_path: "/runtime/bin/java",
            additional_independent_image_paths: &[],
            mount_targets,
            expected_canonical_node_order,
            expected_edges,
            expected_aggregate_distinct_object_bytes,
            expected_root_entry_point_is_zero: None,
        };
        let result = retained
            .materialize_private()?
            .test_only_authenticate_startup_dependency_closure_and_retain(&startup_expectation);
        match (result, expected_error_fragment) {
            (Ok(retained), None) => {
                retained
                    .test_only_reauthenticate_static_startup_dependencies(&startup_expectation)?;
                let abandonment = retained.cleanup()?;
                assert!(abandonment.final_unlinked_observed);
            }
            (Err(error), Some(fragment)) => assert!(
                format!("{error:#}").contains(fragment),
                "expected {fragment:?}, observed {error:#}"
            ),
            (Ok(_), Some(fragment)) => {
                anyhow::bail!("startup dependency fixture unexpectedly accepted {fragment}")
            }
            (Err(error), None) => return Err(error),
        }
        assert_eq!(directory_names(parent)?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    fn pt_interp_symlink_chain(total_hops: usize) -> Vec<RuntimeRootfsFixtureEntryV1> {
        assert!(total_hops >= 1);
        let mut entries = vec![
            RuntimeRootfsFixtureEntryV1::directory("lib64"),
            RuntimeRootfsFixtureEntryV1::symbolic_link("lib64/ld-linux-x86-64.so.2", "/links/00"),
            RuntimeRootfsFixtureEntryV1::directory("links"),
        ];
        for index in 0..total_hops - 1 {
            entries.push(RuntimeRootfsFixtureEntryV1::symbolic_link(
                format!("links/{index:02}"),
                format!("{:02}", index + 1),
            ));
        }
        entries.push(RuntimeRootfsFixtureEntryV1::regular(
            format!("links/{:02}", total_hops - 1),
            0o555,
            b"LOADER",
        ));
        entries
    }

    #[test]
    fn oci_rootfs_staging_contract_is_private_affine_anonymous_and_projection_only() {
        fn assert_error_bounds<T: std::error::Error + Send + Sync + 'static>() {}

        type Project =
            for<'path> fn(PositiveRunnerRole, &'path Path) -> Result<OciRootfsStagingLayoutV1>;
        type Begin =
            fn(OciRootfsStagingLayoutV1, u64) -> Result<PrivateOciRootfsStagingTransactionV1>;

        let project: Project = OciRootfsStagingLayoutV1::project;
        let begin: Begin = PrivateOciRootfsStagingTransactionV1::begin;
        let _ = (project, begin);

        <OciRootfsStagingLayoutV1 as AmbiguousIfClone<_>>::marker();
        <OciRootfsStagingLayoutV1 as AmbiguousIfCopy<_>>::marker();
        <PrivateOciRootfsStagingTransactionV1 as AmbiguousIfClone<_>>::marker();
        <PrivateOciRootfsStagingTransactionV1 as AmbiguousIfCopy<_>>::marker();
        <AuthenticatedPrivateOciRootfsProjectionV1 as AmbiguousIfClone<_>>::marker();
        <AuthenticatedPrivateOciRootfsProjectionV1 as AmbiguousIfCopy<_>>::marker();
        <AuthenticatedPrivateOciRetainedRootfsV1 as AmbiguousIfClone<_>>::marker();
        <AuthenticatedPrivateOciRetainedRootfsV1 as AmbiguousIfCopy<_>>::marker();
        <PrivateOciRetainedRootfsAcquisitionFailureV1 as AmbiguousIfClone<_>>::marker();
        <PrivateOciRetainedRootfsAcquisitionFailureV1 as AmbiguousIfCopy<_>>::marker();
        <PrivateOciRetainedRootfsCleanupFailureV1 as AmbiguousIfClone<_>>::marker();
        <PrivateOciRetainedRootfsCleanupFailureV1 as AmbiguousIfCopy<_>>::marker();
        <PrivateOciRootfsAbandonedV1 as AmbiguousIfClone<_>>::marker();
        <PrivateOciRootfsAbandonedV1 as AmbiguousIfCopy<_>>::marker();
        assert_error_bounds::<PrivateOciRetainedRootfsAcquisitionFailureV1>();

        let source_text = include_str!("rootfs.rs").replace("\r\n", "\n");
        let (production, _tests) = source_text
            .split_once("#[cfg(test)]\nmod tests {")
            .expect("terminal rootfs test-module boundary");
        assert!(
            production.contains("fn validate_root_leaf"),
            "production scan did not reach its end sentinel"
        );
        assert!(production.contains("OFlags::TMPFILE"));
        assert!(production.contains("OFlags::EXCL"));
        assert!(production.contains("OFlags::CLOEXEC"));
        assert!(production.contains("observed.hard_link_count == 0"));
        assert_eq!(
            production.matches(".sync_all()").count(),
            1,
            "only the completed-candidate boundary may force writeback"
        );
        assert!(super::ANONYMOUS_SPOOL_FLAGS.contains(rustix::fs::OFlags::TMPFILE));
        assert!(super::ANONYMOUS_SPOOL_FLAGS.contains(rustix::fs::OFlags::EXCL));
        assert!(super::ANONYMOUS_SPOOL_FLAGS.contains(rustix::fs::OFlags::RDWR));
        assert!(super::ANONYMOUS_SPOOL_FLAGS.contains(rustix::fs::OFlags::CLOEXEC));
        assert!(!super::ANONYMOUS_SPOOL_FLAGS.intersects(
            rustix::fs::OFlags::CREATE | rustix::fs::OFlags::TRUNC | rustix::fs::OFlags::APPEND
        ));
        for forbidden in FORBIDDEN_STAGING_SURFACES {
            assert!(
                !production.contains(forbidden),
                "private logical staging exposed forbidden surface: {forbidden}"
            );
        }
        let exposed = production
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("pub"))
            .collect::<Vec<_>>();
        assert_eq!(
            exposed,
            [
                "pub(super) struct PrivateOciRootfsStagingTransactionV1 {",
                "pub(super) struct AuthenticatedPrivateOciRootfsProjectionV1 {",
                "pub(super) struct AuthenticatedPrivateOciRetainedRootfsV1 {",
                "pub(super) struct PrivateOciRetainedRootfsAcquisitionFailureV1 {",
                "pub(super) struct PrivateOciRetainedRootfsCleanupFailureV1 {",
                "pub(super) struct PrivateOciRootfsAbandonedV1 {",
                "pub(super) fn begin_private_oci_rootfs_staging(",
                "pub(super) fn replay_semantic_layer_sink(",
                "pub(super) fn authenticate_and_retain(",
                "pub(super) fn discard_after_error(self, primary: anyhow::Error) -> anyhow::Error {",
                "pub(super) fn retry_cleanup(self) -> std::result::Result<anyhow::Error, Self> {",
                "pub(super) fn retry_cleanup(self) -> std::result::Result<PrivateOciRootfsAbandonedV1, Self> {",
                "pub(super) fn reauthenticate_static_startup_dependencies(",
                "pub(super) fn cleanup(",
                "pub(super) fn authenticate_physical_rootfs_and_cleanup(",
                "pub(super) fn authenticate_physical_rootfs_and_retain(",
                "pub(super) fn discard_after_error(self, primary: anyhow::Error) -> anyhow::Error {",
                "pub(super) fn test_only_retained_evidence(",
            ],
            "private rootfs sibling surface changed without an explicit review"
        );
    }

    #[test]
    fn retained_rootfs_acquisition_failure_classifies_both_owned_stages_without_stringifying() {
        let source = include_str!("rootfs.rs").replace("\r\n", "\n");
        let production = source
            .split_once("#[cfg(test)]\nmod tests {")
            .expect("terminal rootfs test-module boundary")
            .0;
        let acquisition = production
            .split("impl PrivateOciRetainedRootfsAcquisitionFailureV1 {")
            .nth(1)
            .expect("retained rootfs acquisition failure implementation")
            .split("impl PrivateOciRetainedRootfsCleanupFailureV1 {")
            .next()
            .expect("retained rootfs acquisition failure end sentinel");
        let compact_acquisition = acquisition.split_whitespace().collect::<String>();
        assert!(
            compact_acquisition.contains(
                "pub(super)fnretry_cleanup(self)->std::result::Result<anyhow::Error,Self>"
            )
        );
        assert!(compact_acquisition.contains("physical.retry_cleanup_preserving_error()"));
        assert!(
            compact_acquisition.contains("Ok((_abandonment,preserved_error))=>Ok(preserved_error)")
        );
        assert!(!acquisition.contains("format!("));
        assert!(!acquisition.contains(".to_string()"));

        let retained_join = production
            .split("pub(super) fn authenticate_physical_rootfs_and_retain(")
            .nth(1)
            .expect("retained physical rootfs join")
            .split("pub(super) fn discard_after_error(")
            .next()
            .expect("retained physical rootfs join end sentinel");
        assert_eq!(
            retained_join
                .matches("PrivateOciRetainedRootfsAcquisitionFailureV1::classify")
                .count(),
            2,
            "materialization and authentication must both classify owned failures"
        );
        let compact_join = retained_join.split_whitespace().collect::<String>();
        assert!(compact_join.contains("self.materialize_private().map_err("));
        assert!(compact_join.contains(
            ".authenticate_physical_rootfs_and_retain(expectation).map(|physical|AuthenticatedPrivateOciRetainedRootfsV1{physical}).map_err("
        ));
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one source-contract test closes the ordered pre-effect custody joins"
    )]
    fn assert_physical_materialization_pre_effect_order(source_text: &str) {
        let (_, bootstrap_tail) = source_text
            .split_once("fn into_private_materialization_bootstrap(")
            .expect("private materializer bootstrap entry point");
        let (bootstrap, _) = bootstrap_tail
            .split_once("\n    pub(super) fn materialize_private(")
            .expect("private materializer bootstrap end sentinel");
        assert_eq!(
            bootstrap
                .matches("Err(primary) => return Err(self.fail_before_named_effect(primary))")
                .count(),
            1,
            "private materializer preflight failure must abandon pre-effect custody"
        );
        let (_, method) = source_text
            .split_once("pub(super) fn materialize_private(")
            .expect("private materializer entry point");
        let (method, _) = method
            .split_once("\n}\n\nimpl AuthenticatedPrivateOciRootfsMaterializationV1")
            .expect("private materializer end sentinel");
        let capture = method
            .find("let finalizer_effective_ids = capture_finalizer_effective_ids();")
            .expect("finalizer effective IDs captured before materialization");
        let bootstrap = method
            .find("self.into_private_materialization_bootstrap(finalizer_effective_ids)?;")
            .expect("captured finalizer effective IDs transferred into affine bootstrap");
        let first_effect = method
            .find("rustix::fs::mkdirat(")
            .expect("private materializer first named effect");
        assert!(capture < bootstrap && bootstrap < first_effect);
        assert_eq!(
            method.matches("capture_finalizer_effective_ids()").count(),
            1
        );
        assert_eq!(
            method
                .matches("return Err(bootstrap.fail_before_named_effect(primary));")
                .count(),
            2,
            "pre-effect validation and mkdir failure must both abandon bootstrap custody"
        );
        let (prologue, _) = method
            .split_once("rustix::fs::mkdirat(")
            .expect("private materializer first named effect");
        let compact_prologue = prologue.split_whitespace().collect::<String>();
        assert_eq!(
            prologue
                .matches("bootstrap.transaction.parent.reauthenticate()?;")
                .count(),
            2,
            "private materializer must reauthenticate twice before mkdirat"
        );
        assert_eq!(
            compact_prologue
                .matches("bootstrap.transaction.current_mount_namespace.reauthenticate()?;")
                .count(),
            2,
            "private materializer must reauthenticate twice before mkdirat"
        );
        let armed_namespace_mismatch = compact_prologue
            .find("test_only_arm_next_reauthentication_identity_mismatch();")
            .expect("pre-mkdir mount-namespace mismatch must arm the production join");
        let first_namespace_reauthentication = armed_namespace_mismatch
            + compact_prologue[armed_namespace_mismatch..]
                .find("bootstrap.transaction.current_mount_namespace.reauthenticate()?;")
                .expect("pre-mkdir mount-namespace production join");
        assert!(armed_namespace_mismatch < first_namespace_reauthentication);
        assert_eq!(
            prologue
                .matches("bootstrap.transaction.revalidate_authenticated_projection(")
                .count(),
            1,
            "private materializer must revalidate exactly once before mkdirat"
        );
        assert_eq!(
            compact_prologue
                .matches("validate_current_finalizer_effective_ids(")
                .count(),
            2,
            "private materializer must bind credentials before and immediately before mkdirat"
        );
        assert!(compact_prologue.contains(
            "validate_current_finalizer_effective_ids(&bootstrap.finalizer_effective_ids,FinalizerEffectiveIdsObservationMutationV1::Unchanged,)?;"
        ));
        let injected_checkpoint = compact_prologue
            .find("bootstrap.take_before_first_effect_finalizer_ids_observation_mutation();")
            .expect("pre-mkdir effective-ID checkpoint injection");
        let injected_validation = compact_prologue
            .rfind("validate_current_finalizer_effective_ids(&bootstrap.finalizer_effective_ids,effective_ids_mutation,)?;")
            .expect("pre-mkdir effective-ID checkpoint validation");
        assert!(injected_checkpoint < injected_validation);
        let mut remainder = prologue;
        for step in [
            "bootstrap.transaction.parent.reauthenticate()?;",
            "reserved private OCI rootfs staging before retained projection validation",
            "bootstrap.transaction.revalidate_authenticated_projection(",
            "bootstrap.transaction.parent.reauthenticate()?;",
            "reserved private OCI rootfs staging immediately before creation",
        ] {
            let position = remainder
                .find(step)
                .unwrap_or_else(|| panic!("private materializer pre-effect step missing: {step}"));
            remainder = &remainder[position + step.len()..];
        }
    }

    fn assert_physical_materialization_forbidden_surface(source_text: &str) {
        const ALLOWED_PROC_PATHS: [&str; 5] = [
            "/proc/thread-self/ns/mnt",
            "/proc/thread-self/ns/user",
            "/proc/thread-self/uid_map",
            "/proc/thread-self/gid_map",
            "/proc/thread-self/status",
        ];
        for path in ALLOWED_PROC_PATHS {
            assert_eq!(
                source_text.matches(path).count(),
                1,
                "unexpected proc path: {path}"
            );
        }
        assert!(!source_text.contains("/proc/self/ns/mnt"));
        assert!(!source_text.contains("/proc/self/ns/user"));
        assert!(!source_text.contains("/proc/self/fd"));
        let source_without_namespaces = ALLOWED_PROC_PATHS
            .into_iter()
            .fold(source_text.to_owned(), |source, path| {
                source.replacen(path, "", 1)
            });
        for forbidden in [
            "pub(crate)",
            "pub fn ",
            "std::fs::",
            "OpenOptions",
            "File::create",
            "create_dir_all(",
            "remove_dir_all(",
            "renameat2",
            "/proc/",
            "Command::",
            "std::process",
            "process::Command",
            "posix_spawn",
            "execve",
            "fork(",
            "concat!",
            "setns",
            "unshare",
            "impl Deref",
            "impl Drop",
            "impl std::ops::Drop",
            "AsRawFd",
            "IntoRawFd",
            "as_raw_fd",
            "into_raw_fd",
            "fn publish",
            "fn commit",
        ] {
            assert!(
                !source_without_namespaces.contains(forbidden),
                "private physical materialization exposed forbidden surface: {forbidden}"
            );
        }
        let lowercase_source = source_text.to_ascii_lowercase();
        for forbidden_token in ["chown", "xattr"] {
            assert!(
                !lowercase_source.contains(forbidden_token),
                "private physical materialization contains forbidden token or alias: {forbidden_token}"
            );
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one source-contract test closes the ordered mount-namespace custody joins"
    )]
    fn assert_mount_namespace_custody_source_contract(
        rootfs_source_text: &str,
        physical_source_text: &str,
    ) {
        let compact_physical = physical_source_text.split_whitespace().collect::<String>();
        assert_eq!(
            physical_source_text
                .matches("CURRENT_THREAD_MOUNT_NAMESPACE_PATH")
                .count(),
            2,
            "mount-namespace path constant must have one declaration and one direct use"
        );
        assert_eq!(
            compact_physical.matches("letrelative=").count(),
            4,
            "namespace, ID-map, and status relative paths must not be shadowed"
        );
        for required in [
            "constMOUNT_NAMESPACE_OPEN_FLAGS:rustix::fs::OFlags=rustix::fs::OFlags::RDONLY.union(rustix::fs::OFlags::CLOEXEC);",
            "structMountNamespaceIdentityV1{device:u64,inode:u64,}",
            "letrelative=Path::new(CURRENT_THREAD_MOUNT_NAMESPACE_PATH).strip_prefix(\"/proc\").expect(\"fixedmount-namespacepathisprocfs-relative\");letdescriptor=rustix::fs::openat(proc_root,relative,MOUNT_NAMESPACE_OPEN_FLAGS,rustix::fs::Mode::empty(),)",
            "statfs.f_type==rustix::fs::PROC_SUPER_MAGIC",
            "statfs.f_type==NSFS_MAGIC",
            "mount_namespace_identity(self.namespace.as_fd())?==self.identity",
            "mount_namespace_identity(current.as_fd())?==self.identity",
            "constCURRENT_THREAD_USER_NAMESPACE_PATH:&str=\"/proc/thread-self/ns/user\";",
            "constCURRENT_THREAD_UID_MAP_PATH:&str=\"/proc/thread-self/uid_map\";",
            "constCURRENT_THREAD_GID_MAP_PATH:&str=\"/proc/thread-self/gid_map\";",
            "constCURRENT_THREAD_STATUS_PATH:&str=\"/proc/thread-self/status\";",
            "constCURRENT_THREAD_STATUS_MAX_BYTES:usize=1_024*1_024;",
            "constLINUX_SUPPLEMENTARY_GROUPS_MAX:usize=65_536;",
            "user_namespace_identity(self.user_namespace.as_fd())?==self.user_namespace_identity",
            "observed_user_map==self.uid_map",
            "observed_group_map==self.gid_map",
            "supplementary_groups:Vec<u32>,",
            "observed_supplementary_groups==self.supplementary_groups",
            "filesystem_credentials:CallingThreadFilesystemCredentialsV1,",
            "observed_filesystem_credentials.fsuid==self.filesystem_credentials.fsuid",
            "observed_filesystem_credentials.fsgid==self.filesystem_credentials.fsgid",
            "current.push(current.last().copied().unwrap_or(0));",
        ] {
            assert!(
                compact_physical.contains(required),
                "mount-namespace custody source contract missing: {required}"
            );
        }

        let map_reader = physical_source_text
            .split_once("fn read_current_thread_user_namespace_map(")
            .expect("user-namespace map reader")
            .1
            .split_once("fn validate_user_namespace_map(")
            .expect("user-namespace map reader end")
            .0
            .split_whitespace()
            .collect::<String>();
        let map_relative = map_reader
            .find("letrelative=Path::new(path).strip_prefix(\"/proc\")")
            .expect("ID-map path must become a procfs-relative path");
        let map_open = map_reader
            .find("letdescriptor=rustix::fs::openat(proc_root,relative,MOUNT_NAMESPACE_OPEN_FLAGS,rustix::fs::Mode::empty(),)")
            .expect("ID-map reader must open its relative path");
        let map_validate = map_reader
            .find("validate_user_namespace_map(&bytes,label)?;")
            .expect("bounded ID-map reader must validate the bytes it returns");
        assert!(map_relative < map_open && map_open < map_validate);

        let status_reader = physical_source_text
            .split_once("fn read_current_thread_filesystem_credentials_once(")
            .expect("calling-thread filesystem-credential reader")
            .1
            .split_once("fn require_stable_calling_thread_filesystem_credentials(")
            .expect("calling-thread filesystem-credential reader end")
            .0
            .split_whitespace()
            .collect::<String>();
        let status_relative = status_reader
            .find("letrelative=Path::new(CURRENT_THREAD_STATUS_PATH).strip_prefix(\"/proc\")")
            .expect("calling-thread status path must become procfs-relative");
        let effective_before = status_reader
            .find("letinitial_user_id=rustix::process::geteuid().as_raw();letinitial_group_id=rustix::process::getegid().as_raw();")
            .expect("effective IDs before calling-thread status read");
        let status_open = status_reader
            .find("letdescriptor=rustix::fs::openat(proc_root,relative,MOUNT_NAMESPACE_OPEN_FLAGS,rustix::fs::Mode::empty(),)")
            .expect("calling-thread status reader must open its relative path");
        let bounded_status_read = status_reader
            .find(".take((CURRENT_THREAD_STATUS_MAX_BYTES+1)asu64).read_to_end(&mutbytes)")
            .expect("calling-thread status reader must enforce its byte bound");
        let status_parse = status_reader
            .find("letstatus=parse_calling_thread_status_credentials(&bytes)?;")
            .expect("calling-thread status reader must parse the bounded bytes");
        let effective_after = status_reader
            .find("letfinal_user_id=rustix::process::geteuid().as_raw();letfinal_group_id=rustix::process::getegid().as_raw();")
            .expect("effective IDs after calling-thread status read");
        let status_effective_join = status_reader
            .find("initial_user_id==final_user_id&&initial_group_id==final_group_id")
            .expect("calling-thread status must bracket live effective IDs");
        assert!(
            effective_before < status_relative
                && status_relative < status_open
                && status_open < bounded_status_read
                && bounded_status_read < status_parse
                && status_parse < effective_after
                && effective_after < status_effective_join
        );

        let stable_group_reader = physical_source_text
            .split_once(
                "fn read_stable_current_thread_supplementary_groups() -> Result<Vec<u32>> {",
            )
            .expect("stable supplementary-group reader")
            .1
            .split_once("\n}\n\n#[cfg(test)]\nmod supplementary_group_projection_tests")
            .expect("stable supplementary-group reader end")
            .0
            .split_whitespace()
            .collect::<String>();
        assert_eq!(
            stable_group_reader
                .matches("read_current_thread_supplementary_groups_once()?")
                .count(),
            2,
            "supplementary groups must be read exactly twice without retry"
        );
        let first_group_read = stable_group_reader
            .find("letfirst=read_current_thread_supplementary_groups_once()?;")
            .expect("first supplementary-group read");
        let second_group_read = stable_group_reader
            .find("letsecond=read_current_thread_supplementary_groups_once()?;")
            .expect("second supplementary-group read");
        let stable_group_join = stable_group_reader
            .find("require_stable_supplementary_group_projection(&first,second)")
            .expect("stable supplementary-group join");
        assert!(first_group_read < second_group_read && second_group_read < stable_group_join);

        let stable_filesystem_credential_reader = physical_source_text
            .split_once(
                "fn read_stable_current_thread_filesystem_credentials(\n    proc_root: BorrowedFd<'_>,\n) -> Result<CallingThreadFilesystemCredentialsV1> {",
            )
            .expect("stable calling-thread filesystem-credential reader")
            .1
            .split_once("\n}\n\n#[cfg(test)]\nmod filesystem_credential_projection_tests")
            .expect("stable calling-thread filesystem-credential reader end")
            .0
            .split_whitespace()
            .collect::<String>();
        assert_eq!(
            stable_filesystem_credential_reader
                .matches("read_current_thread_filesystem_credentials_once(proc_root)?")
                .count(),
            2,
            "filesystem credentials must be read exactly twice without retry"
        );
        let first_filesystem_credential_read = stable_filesystem_credential_reader
            .find("letfirst=read_current_thread_filesystem_credentials_once(proc_root)?;")
            .expect("first filesystem-credential read");
        let second_filesystem_credential_read = stable_filesystem_credential_reader
            .find("letsecond=read_current_thread_filesystem_credentials_once(proc_root)?;")
            .expect("second filesystem-credential read");
        let stable_filesystem_credential_join = stable_filesystem_credential_reader
            .find("require_stable_calling_thread_filesystem_credentials(first,second)")
            .expect("stable filesystem-credential join");
        assert!(
            first_filesystem_credential_read < second_filesystem_credential_read
                && second_filesystem_credential_read < stable_filesystem_credential_join
        );

        let group_normalizer = physical_source_text
            .split_once("fn normalize_linux_supplementary_group_projection(")
            .expect("supplementary-group normalizer")
            .1
            .split_once("fn require_stable_supplementary_group_projection(")
            .expect("supplementary-group normalizer end")
            .0
            .split_whitespace()
            .collect::<String>();
        assert!(group_normalizer.contains("groups.len()<=LINUX_SUPPLEMENTARY_GROUPS_MAX"));
        assert!(group_normalizer.contains(".map(rustix::fs::Gid::as_raw)"));
        assert!(group_normalizer.contains("groups.sort_unstable();"));
        assert!(!group_normalizer.contains("dedup"));

        let reauthenticate = physical_source_text
            .split_once("pub(super) fn reauthenticate(&self) -> Result<()> {")
            .expect("namespace reauthentication")
            .1
            .split_once("pub(super) fn test_only_arm_next_reauthentication_identity_mismatch(")
            .expect("namespace reauthentication end")
            .0;
        let compact_reauthenticate = reauthenticate.split_whitespace().collect::<String>();
        let first_current_user_identity = "user_namespace_identity(current_user_namespace.as_fd())?==expected_user_namespace_identity";
        let second_current_user_identity = "user_namespace_identity(current_user_namespace.as_fd())?==self.user_namespace_identity";
        let first_user_identity = compact_reauthenticate
            .find(first_current_user_identity)
            .expect("current user namespace before ID-map reads");
        let uid_map = compact_reauthenticate
            .find("letobserved_user_map=read_current_thread_user_namespace_map(self.proc_root.as_fd(),CURRENT_THREAD_UID_MAP_PATH,\"uid_map\",)?;")
            .expect("exact current uid_map join");
        let uid_map_join = compact_reauthenticate
            .find("observed_user_map==self.uid_map")
            .expect("exact current uid_map comparison");
        let gid_map = compact_reauthenticate
            .find("letobserved_group_map=read_current_thread_user_namespace_map(self.proc_root.as_fd(),CURRENT_THREAD_GID_MAP_PATH,\"gid_map\",)?;")
            .expect("exact current gid_map join");
        let gid_map_join = compact_reauthenticate
            .find("observed_group_map==self.gid_map")
            .expect("exact current gid_map comparison");
        let supplementary_groups = compact_reauthenticate
            .find("letobserved_supplementary_groups=read_stable_current_thread_supplementary_groups()?;")
            .expect("stable current supplementary-group join");
        let supplementary_groups_join = compact_reauthenticate
            .find("observed_supplementary_groups==self.supplementary_groups")
            .expect("exact current supplementary-group comparison");
        let filesystem_credentials = compact_reauthenticate
            .find("letobserved_filesystem_credentials=read_stable_current_thread_filesystem_credentials(self.proc_root.as_fd())?;")
            .expect("stable current filesystem-credential join");
        let filesystem_user_join = compact_reauthenticate
            .find("observed_filesystem_credentials.fsuid==self.filesystem_credentials.fsuid")
            .expect("exact current fsuid comparison");
        let filesystem_group_join = compact_reauthenticate
            .find("observed_filesystem_credentials.fsgid==self.filesystem_credentials.fsgid")
            .expect("exact current fsgid comparison");
        let second_user_identity = compact_reauthenticate
            .rfind(second_current_user_identity)
            .expect("current user namespace after ID-map reads");
        assert!(
            first_user_identity < uid_map
                && uid_map < uid_map_join
                && uid_map_join < gid_map
                && gid_map < gid_map_join
                && gid_map_join < supplementary_groups
                && supplementary_groups < supplementary_groups_join
                && supplementary_groups_join < filesystem_credentials
                && filesystem_credentials < filesystem_user_join
                && filesystem_user_join < filesystem_group_join
                && filesystem_group_join < second_user_identity,
            "current user namespace must remain stable across exact ID-map, supplementary-group, and filesystem-credential reads"
        );

        let capture = physical_source_text
            .split_once("pub(super) fn capture() -> Result<Self> {")
            .expect("namespace custody capture")
            .1
            .split_once("pub(super) fn reauthenticate(&self) -> Result<()> {")
            .expect("namespace custody capture end")
            .0
            .split_whitespace()
            .collect::<String>();
        let capture_gid_map = capture
            .find("letgid_map=read_current_thread_user_namespace_map(")
            .expect("capture gid_map");
        let capture_groups = capture
            .find("letsupplementary_groups=read_stable_current_thread_supplementary_groups()?;")
            .expect("capture supplementary groups");
        let capture_groups_field = capture
            .find("supplementary_groups,")
            .expect("captured supplementary groups retained in custody");
        let capture_filesystem_credentials = capture
            .find("letfilesystem_credentials=read_stable_current_thread_filesystem_credentials(proc_root.as_fd())?;")
            .expect("capture filesystem credentials");
        let capture_filesystem_credentials_field = capture
            .find("filesystem_credentials,")
            .expect("captured filesystem credentials retained in custody");
        let capture_reauthentication = capture
            .find("pinned.reauthenticate()?;")
            .expect("capture reauthentication");
        assert_eq!(capture.matches("supplementary_groups,").count(), 1);
        assert_eq!(capture.matches("filesystem_credentials,").count(), 1);
        assert!(
            capture_gid_map < capture_groups
                && capture_groups < capture_filesystem_credentials
                && capture_filesystem_credentials < capture_groups_field
                && capture_filesystem_credentials < capture_filesystem_credentials_field
                && capture_groups_field < capture_filesystem_credentials_field
                && capture_filesystem_credentials_field < capture_reauthentication
        );

        let named_entry_preflight = physical_source_text
            .split_once("fn preflight_named_entry_effect(&self, position: usize) -> Result<()> {")
            .expect("named-entry preflight")
            .1
            .split_once("fn record_named_entry_infallibly(")
            .expect("named-entry preflight end")
            .0
            .split_whitespace()
            .collect::<String>();
        assert!(
            named_entry_preflight
                .find("self.transaction.current_mount_namespace.reauthenticate()?;")
                .expect("named-entry namespace join")
                < named_entry_preflight
                    .find("validate_current_finalizer_effective_ids(")
                    .expect("named-entry effective-ID validation")
        );

        let materialize_preamble = physical_source_text
            .split_once("pub(super) fn materialize_private(")
            .expect("private physical materialization")
            .1
            .split_once("let pre_effect =")
            .expect("private physical materialization pre-effect boundary")
            .0
            .split_whitespace()
            .collect::<String>();
        let materialize_reauthentication =
            "self.transaction.current_mount_namespace.reauthenticate()?;";
        assert_eq!(
            materialize_preamble
                .matches(materialize_reauthentication)
                .count(),
            2,
            "effective IDs must be bracketed by namespace reauthentication"
        );
        let before_ids = materialize_preamble
            .find(materialize_reauthentication)
            .expect("namespace join before effective-ID capture");
        let capture_ids = materialize_preamble
            .find("letfinalizer_effective_ids=capture_finalizer_effective_ids();")
            .expect("effective-ID capture");
        let after_ids = materialize_preamble
            .rfind(materialize_reauthentication)
            .expect("namespace join after effective-ID capture");
        let into_bootstrap = materialize_preamble
            .find("self.into_private_materialization_bootstrap(finalizer_effective_ids)?;")
            .expect("effective-ID bootstrap join");
        assert!(before_ids < capture_ids && capture_ids < after_ids && after_ids < into_bootstrap);

        let staging_observation = physical_source_text
            .split_once("let staging_root_observation = match")
            .expect("staging-root observation")
            .1
            .split_once("let PrivateOciRootfsBootstrapCustodyV1 {")
            .expect("staging-root observation end")
            .0
            .split_whitespace()
            .collect::<String>();
        assert!(
            staging_observation
                .find(".current_mount_namespace.reauthenticate()")
                .expect("staging-root namespace join")
                < staging_observation
                    .find("directory_observation(staging_root.as_fd())")
                    .expect("staging-root owner/group observation")
        );

        let begin = rootfs_source_text
            .split_once(
                "fn begin(layout: OciRootfsStagingLayoutV1, expected_semantic_layers: u64) -> Result<Self> {",
            )
            .expect("logical staging begin")
            .1
            .split_once("pub(super) fn replay_semantic_layer_sink(")
            .expect("logical staging begin end")
            .0;
        let capture = begin
            .find("PinnedCurrentMountNamespaceV1::capture()")
            .expect("mount-namespace capture before logical staging");
        let parent = begin
            .find("PinnedAbsoluteDirectoryPath::open(&parent_path)")
            .expect("logical staging parent pin");
        let spool = begin
            .find("open_private_anonymous_rootfs_spool(&parent)")
            .expect("logical staging anonymous spool creation");
        assert!(capture < parent && parent < spool);
        assert_eq!(
            begin[capture..spool]
                .matches("current_mount_namespace.reauthenticate()?;")
                .count(),
            2,
            "mount namespace must be captured and joined twice before O_TMPFILE"
        );

        let write_chunk = rootfs_source_text
            .split_once("fn write_regular_chunk_inner(&mut self, chunk: &[u8]) -> Result<()> {")
            .expect("regular chunk writer")
            .1
            .split_once("fn finish_entry_inner(&mut self) -> Result<()> {")
            .expect("regular chunk writer end")
            .0;
        let compact_write_chunk = write_chunk.split_whitespace().collect::<String>();
        assert!(
            compact_write_chunk
                .find("self.current_mount_namespace.reauthenticate()?;")
                .expect("chunk mount-namespace join")
                < compact_write_chunk
                    .find("write_all_at(")
                    .expect("anonymous spool write effect")
        );

        let retained_tree = physical_source_text
            .split_once("fn validate_retained_tree(&self, require_complete: bool) -> Result<()> {")
            .expect("retained-tree validation")
            .1
            .split_once("fn validate_mapped_owner_prerequisite(")
            .expect("retained-tree validation end")
            .0;
        let compact_retained_tree = retained_tree.split_whitespace().collect::<String>();
        assert!(compact_retained_tree.contains(
            "self.test_only_validate_mutated_expected_custody(mutation)?;}self.transaction.current_mount_namespace.reauthenticate()?;"
        ));

        let cleanup_named_tree = physical_source_text
            .split_once("fn cleanup_named_tree(&mut self) -> Result<()> {")
            .expect("named-tree cleanup")
            .1
            .split_once("fn finish_unlinked_staging_cleanup_retry(")
            .expect("named-tree cleanup end")
            .0
            .split_whitespace()
            .collect::<String>();
        assert!(
            cleanup_named_tree
                .find("self.transaction.current_mount_namespace.reauthenticate()?;")
                .expect("cleanup entry mount-namespace join")
                < cleanup_named_tree
                    .find("self.reconcile_regular_creator_descriptors()?;")
                    .expect("cleanup creator-descriptor reconciliation")
        );

        let cleanup_entries = physical_source_text
            .split_once("fn cleanup_owned_entries_postorder(&mut self) -> Result<()> {")
            .expect("owned cleanup loop")
            .1
            .split_once("fn validated_cleanup_unlink_flags(")
            .expect("owned cleanup loop end")
            .0;
        let compact_cleanup_entries = cleanup_entries.split_whitespace().collect::<String>();
        assert!(
            compact_cleanup_entries
                .contains("test_only_arm_next_reauthentication_identity_mismatch();")
        );
        assert!(
            compact_cleanup_entries.contains("test_only_arm_next_supplementary_groups_mismatch();")
        );
        assert!(!compact_cleanup_entries.contains("test_only_validate_mutated_identity("));
        let entry_join = compact_cleanup_entries
            .find("self.transaction.current_mount_namespace.reauthenticate()?;")
            .expect("per-entry mount-namespace join");
        let entry_open = compact_cleanup_entries
            .find("open_beneath_directory(")
            .expect("per-entry descriptor-rooted open");
        assert!(entry_join < entry_open);

        let cleanup_entry = physical_source_text
            .split_once("fn cleanup_owned_entry(&mut self, position: usize) -> Result<()> {")
            .expect("owned cleanup entry")
            .1
            .split_once("fn validated_cleanup_unlink_flags(")
            .expect("owned cleanup entry end")
            .0
            .split_whitespace()
            .collect::<String>();
        assert_eq!(
            cleanup_entry
                .matches("self.transaction.current_mount_namespace.reauthenticate()?;")
                .count(),
            2,
            "owned cleanup entry must join before inspection and immediately before unlink"
        );
        let validated_flags = cleanup_entry
            .find("self.validated_cleanup_unlink_flags(")
            .expect("owned cleanup validated flags");
        let final_entry_join = cleanup_entry
            .rfind("self.transaction.current_mount_namespace.reauthenticate()?;")
            .expect("owned cleanup final namespace join");
        let unlink = cleanup_entry
            .find("rustix::fs::unlinkat(")
            .expect("owned cleanup unlink");
        assert!(validated_flags < final_entry_join && final_entry_join < unlink);

        let cleanup_root = physical_source_text
            .split_once("fn cleanup_empty_staging_root(&mut self) -> Result<()> {")
            .expect("empty staging cleanup")
            .1
            .split_once("fn fail_after_named_effect(")
            .expect("empty staging cleanup end")
            .0;
        let compact_cleanup_root = cleanup_root.split_whitespace().collect::<String>();
        assert_eq!(
            compact_cleanup_root
                .matches("self.transaction.current_mount_namespace.reauthenticate()?;")
                .count(),
            2,
            "empty-root cleanup must join before observation and immediately before unlink"
        );
        assert!(
            compact_cleanup_root
                .rfind("self.transaction.current_mount_namespace.reauthenticate()?;")
                .expect("final root-unlink namespace join")
                < compact_cleanup_root
                    .find("rustix::fs::unlinkat(")
                    .expect("empty staging root unlink")
        );

        let unlinked_retry = physical_source_text
            .split_once("fn finish_unlinked_staging_cleanup_retry(&self) -> Result<()> {")
            .expect("unlinked staging retry")
            .1
            .split_once("fn reopen_directories_for_cleanup(")
            .expect("unlinked staging retry end")
            .0;
        let compact_unlinked_retry = unlinked_retry.split_whitespace().collect::<String>();
        assert!(
            compact_unlinked_retry
                .find("self.transaction.current_mount_namespace.reauthenticate()?;")
                .expect("unlinked retry mount-namespace join")
                < compact_unlinked_retry
                    .find("self.transaction.parent.reauthenticate()?;")
                    .expect("unlinked retry parent join")
        );
    }

    fn assert_physical_mapped_owner_production_join(
        source_text: &str,
        start: &str,
        end: &str,
        baseline_marker: Option<&str>,
        owner_checkpoint: &str,
        group_checkpoint: &str,
    ) {
        let section = source_text
            .split_once(start)
            .unwrap_or_else(|| panic!("mapped-owner start missing: {start}"))
            .1
            .split_once(end)
            .unwrap_or_else(|| panic!("mapped-owner end missing: {end}"))
            .0;
        let injection = section
            .find("inject_test_only_mapped_owner_mismatch(")
            .expect("mapped-owner production-path injection");
        if let Some(marker) = baseline_marker {
            assert!(section.find(marker).expect("physical baseline capture") < injection);
        }
        assert!(section.contains(owner_checkpoint));
        assert!(section.contains(group_checkpoint));
        let validation = section
            .find("validate_mapped_owner_prerequisite(")
            .expect("mapped-owner production validation");
        assert!(injection < validation);
        let compact = section.split_whitespace().collect::<String>();
        assert!(compact.contains(
            "validate_mapped_owner_prerequisite(mapped_owner,mapped_group,&self.finalizer_effective_ids,"
        ));
    }

    fn assert_physical_effective_id_checkpoint_joins(source_text: &str) {
        let finish = source_text
            .split_once("fn finish_private_materialization(&mut self) -> Result<()> {")
            .expect("private materialization finish")
            .1
            .split_once("fn take_after_materialization_fsync_finalizer_ids_observation_mutation(")
            .expect("post-fsync checkpoint end")
            .0;
        let parent_fsync = finish
            .find("rustix::fs::fsync(self.transaction.parent.descriptor())")
            .expect("staging-parent fsync");
        let checkpoint = finish
            .find("self.take_after_materialization_fsync_finalizer_ids_observation_mutation();")
            .expect("post-fsync effective-ID checkpoint injection");
        let validation = finish
            .rfind("validate_current_finalizer_effective_ids(")
            .expect("post-fsync effective-ID checkpoint validation");
        assert!(parent_fsync < checkpoint && checkpoint < validation);

        let root_baseline = finish
            .find("validate_private_staging_root(")
            .expect("root physical baseline validation");
        let root_policy = finish
            .find("self.validate_initial_staging_root_mapped_owner_prerequisite()?;")
            .expect("root mapped-owner policy join");
        assert!(root_baseline < root_policy);
    }

    fn assert_physical_mapped_owner_field_roles(source_text: &str) {
        let compact_source = source_text.split_whitespace().collect::<String>();
        for exact_role in [
            "FinalizerEffectiveIdsV1{uid:u64::from(rustix::process::geteuid().as_raw()),gid:u64::from(rustix::process::getegid().as_raw()),}",
            "Some(owner_checkpoint){self.test_only_materialization_failpoint=None;*mapped_owner=(*mapped_owner).wrapping_add(1);}elseifself.test_only_materialization_failpoint==Some(group_checkpoint){self.test_only_materialization_failpoint=None;*mapped_group=(*mapped_group).wrapping_add(1);}",
        ] {
            assert!(
                compact_source.contains(exact_role),
                "mapped-owner source changed field role: {exact_role}"
            );
        }

        let validators = source_text
            .split_once("fn validate_current_finalizer_effective_ids(")
            .expect("effective-ID validator")
            .1
            .split_once("fn validate_physical_owner_group_custody(")
            .expect("mapped-owner validator end")
            .0
            .split_whitespace()
            .collect::<String>();
        for exact_role in [
            "FinalizerEffectiveIdsObservationMutationV1::Uid=>{letmutobserved=capture_finalizer_effective_ids();observed.uid=observed.uid.wrapping_add(1);observed}",
            "FinalizerEffectiveIdsObservationMutationV1::Gid=>{letmutobserved=capture_finalizer_effective_ids();observed.gid=observed.gid.wrapping_add(1);observed}",
            "ensure!(observed.uid==expected.uid,\"retainedhost-rootfsmapped-ownerprerequisitefinalizereffectiveUIDdrifted\");",
            "ensure!(observed.gid==expected.gid,\"retainedhost-rootfsmapped-ownerprerequisitefinalizereffectiveGIDdrifted\");",
            "ensure!(observed_owner==expected.uid,\"{label}ownerdiffersfromtheretainedhost-rootfsmapped-ownerprerequisitefinalizereffectiveUID\");",
            "ensure!(observed_group==expected.gid,\"{label}groupdiffersfromtheretainedhost-rootfsmapped-ownerprerequisitefinalizereffectiveGID\");",
        ] {
            assert!(
                validators.contains(exact_role),
                "mapped-owner validation changed field role: {exact_role}"
            );
        }
    }

    fn assert_physical_mapped_owner_source_contract(source_text: &str) {
        let compact_source = source_text
            .split_whitespace()
            .filter(|token| *token != "///")
            .collect::<String>();
        for required_nonclaim in [
            "Itsretainedhost-rootfsmapped-ownerprerequisiteauthenticatesonlynumericequalitybetweeninodeUID/GIDandthefinalizereffectiveIDsasvisiblethroughthecurrentuser-namespaceandidmapped-mountviewateachobservationinstant.",
            "Itdoesnotapprovearawhostmapping,`fsuid`/`fsgid`,supplementarygroups,initial-user-namespaceownership,container-visibleUID/GID65532,oranyuser-namespacemapping.",
            "Theroot-mode-and-mtimesealdoesnotauthenticateextendedattributes,ACLs,filecapabilities,mounts,orexecution/sessionstate.",
        ] {
            assert!(
                compact_source.contains(required_nonclaim),
                "physical rootfs mapped-owner nonclaim changed: {required_nonclaim}"
            );
        }
        let finalizer_struct = source_text
            .split_once("struct FinalizerEffectiveIdsV1 {")
            .expect("private finalizer effective-ID snapshot")
            .0
            .rsplit_once("\n\n")
            .map_or("", |(_, preceding)| preceding);
        assert!(!finalizer_struct.contains("#[derive"));
        assert!(!source_text.contains("impl Clone for FinalizerEffectiveIdsV1"));
        assert!(!source_text.contains("impl Copy for FinalizerEffectiveIdsV1"));
        assert_physical_effective_id_checkpoint_joins(source_text);
        assert_physical_mapped_owner_field_roles(source_text);
        for (start, end, baseline, owner, group) in [
            (
                "fn validate_initial_staging_root_mapped_owner_prerequisite(",
                "fn validate_recorded_mapped_owner_prerequisite(",
                None,
                "StagingRootMappedOwnerMismatch",
                "StagingRootMappedGroupMismatch",
            ),
            (
                "fn materialize_directory(",
                "fn copy_and_seal_regular_mode(",
                Some("transition_named_entry_to_identified("),
                "DirectoryMappedOwnerMismatch",
                "DirectoryMappedGroupMismatch",
            ),
            (
                "fn materialize_regular(",
                "fn materialize_symbolic_link(",
                Some("transition_regular_creator_to_identified("),
                "RegularMappedOwnerMismatch",
                "RegularMappedGroupMismatch",
            ),
            (
                "fn materialize_symbolic_link(",
                "fn preflight_named_entry_effect(",
                Some("transition_named_entry_to_identified("),
                "SymbolicLinkMappedOwnerMismatch",
                "SymbolicLinkMappedGroupMismatch",
            ),
        ] {
            assert_physical_mapped_owner_production_join(
                source_text,
                start,
                end,
                baseline,
                owner,
                group,
            );
        }
    }

    #[test]
    fn physical_materialization_surface_is_private_affine_and_nonpublishing() {
        use super::physical::{
            AuthenticatedPrivateOciRetainedPhysicalRootfsV1,
            AuthenticatedPrivateOciRootfsMaterializationV1, PinnedCurrentMountNamespaceV1,
            PrivateOciRootfsCleanupFailureV1,
        };

        <PinnedCurrentMountNamespaceV1 as AmbiguousIfClone<_>>::marker();
        <PinnedCurrentMountNamespaceV1 as AmbiguousIfCopy<_>>::marker();
        <AuthenticatedPrivateOciRootfsMaterializationV1 as AmbiguousIfClone<_>>::marker();
        <AuthenticatedPrivateOciRootfsMaterializationV1 as AmbiguousIfCopy<_>>::marker();
        <AuthenticatedPrivateOciRetainedPhysicalRootfsV1 as AmbiguousIfClone<_>>::marker();
        <AuthenticatedPrivateOciRetainedPhysicalRootfsV1 as AmbiguousIfCopy<_>>::marker();
        <PrivateOciRootfsCleanupFailureV1 as AmbiguousIfClone<_>>::marker();
        <PrivateOciRootfsCleanupFailureV1 as AmbiguousIfCopy<_>>::marker();

        let source_text = include_str!("rootfs/physical.rs").replace("\r\n", "\n");
        let rootfs_source_text = include_str!("rootfs.rs").replace("\r\n", "\n");
        assert!(
            source_text.contains("fn validate_private_staging_root"),
            "physical source scan did not reach its end sentinel"
        );
        assert_physical_materialization_pre_effect_order(&source_text);
        assert_physical_materialization_forbidden_surface(&source_text);
        assert_mount_namespace_custody_source_contract(&rootfs_source_text, &source_text);
        assert_physical_mapped_owner_source_contract(&source_text);
        let exposed = source_text
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("pub"))
            .collect::<Vec<_>>();
        assert_eq!(
            exposed,
            [
                "pub(super) struct PinnedCurrentMountNamespaceV1 {",
                "pub(super) fn capture() -> Result<Self> {",
                "pub(super) fn reauthenticate(&self) -> Result<()> {",
                "pub(super) fn test_only_arm_next_reauthentication_identity_mismatch(&self) {",
                "pub(super) fn test_only_validate_user_namespace_map(bytes: &[u8], label: &str) -> Result<()> {",
                "pub(super) type StartupClosureExpectedEdgeV1<'a> = (usize, u64, &'a str, &'a str, usize, u64);",
                "pub(super) struct StartupClosureTestExpectationV1<'a> {",
                "pub(super) image_path: &'a str,",
                "pub(super) additional_independent_image_paths: &'a [&'a str],",
                "pub(super) mount_targets: &'a [&'a str],",
                "pub(super) expected_canonical_node_order: Option<&'a [&'a str]>,",
                "pub(super) expected_edges: Option<&'a [StartupClosureExpectedEdgeV1<'a>]>,",
                "pub(super) expected_aggregate_distinct_object_bytes: Option<u64>,",
                "pub(super) expected_root_entry_point_is_zero: Option<bool>,",
                "pub(super) enum TestOnlyRetainedStartupBaselineV1 {",
                "pub(super) enum TestOnlyPrivateMaterializationFailpointV1 {",
                "pub(super) enum TestOnlyPrivateCleanupFailpointV1 {",
                "pub(super) enum TestOnlyPhysicalCustodyMutationV1 {",
                "pub(super) struct AuthenticatedPrivateOciRootfsMaterializationV1 {",
                "pub(super) struct AuthenticatedPrivateOciRetainedPhysicalRootfsV1 {",
                "pub(super) struct PrivateOciRootfsCleanupFailureV1 {",
                "pub(super) fn retry_cleanup(self) -> std::result::Result<PrivateOciRootfsAbandonedV1, Self> {",
                "pub(super) fn retry_cleanup_preserving_error(",
                "pub(super) fn materialize_private(",
                "pub(super) fn authenticate_physical_rootfs_and_cleanup(",
                "pub(super) fn authenticate_physical_rootfs_and_retain(",
                "pub(super) fn test_only_authenticate_rootfs_paths_and_cleanup(",
                "pub(super) fn test_only_authenticate_jvm_executables_and_cleanup(",
                "pub(super) fn test_only_authenticate_startup_dependency_closure_and_cleanup(",
                "pub(super) fn test_only_authenticate_startup_dependency_closure_and_retain(",
                "pub(super) fn test_only_authenticate_java_release_and_cleanup(",
                "pub(super) fn test_only_authenticate_runtime_elf(&self, image_path: &str) -> Result<()> {",
                "pub(super) fn cleanup(",
                "pub(super) fn test_only_arm_cleanup_custody_mutation(",
                "pub(super) fn test_only_arm_cleanup_failpoint(",
                "pub(super) fn test_only_runtime_metadata_seal_order(&self) -> &[String] {",
                "pub(super) fn test_only_fail_after_named_effect(self, primary: anyhow::Error) -> anyhow::Error {",
                "pub(super) fn reauthenticate_static_startup_dependencies(",
                "pub(super) fn test_only_reauthenticate_static_startup_dependencies(",
                "pub(super) fn test_only_mutate_startup_baseline_sha256(",
                "pub(super) fn test_only_arm_regular_owner_custody_mutation(",
                "pub(super) fn cleanup(",
            ],
            "private physical sibling surface changed without an explicit review"
        );

        let (_, hook_tail) = source_text
            .split_once(
                "    #[cfg(test)]\n    fn trigger_regular_creator_substitution_test_failpoint(",
            )
            .expect("test-only regular substitution hook");
        let (hook, _) = hook_tail
            .split_once(
                "\n    #[cfg(test)]\n    pub(super) fn test_only_arm_cleanup_custody_mutation(",
            )
            .expect("test-only regular substitution hook end sentinel");
        assert_eq!(
            source_text.matches("rustix::fs::renameat(").count(),
            1,
            "only the test-only substitution hook may rename"
        );
        assert_eq!(
            hook.matches("rustix::fs::renameat(").count(),
            1,
            "the sole rename must remain inside the test-only substitution hook"
        );
    }

    #[test]
    fn physical_rootfs_identity_join_is_gate_rooted_and_revalidated() {
        let source = include_str!("rootfs/physical.rs").replace("\r\n", "\n");
        let identity_join = source
            .split("fn authenticate_expected_rootfs_identity(")
            .nth(1)
            .unwrap()
            .split("fn authenticate_expected_jvm_identity(")
            .next()
            .unwrap();
        assert_eq!(
            identity_join
                .matches("authenticate_gate_rootfs_path_requirements(expectation)")
                .count(),
            1
        );
        assert_eq!(
            identity_join
                .matches("self.authenticate_expected_jvm_identity(")
                .count(),
            1
        );
        let compact_join = identity_join.split_whitespace().collect::<String>();
        let mut remainder = compact_join.as_str();
        for step in [
            "self.validate_retained_tree(true)?;",
            "self.validate_live_entry_ordering()?;",
            "self.transaction.role==expectation.role()",
            "self.authenticate_gate_rootfs_path_requirements(expectation)?;",
            "self.authenticate_expected_jvm_identity(expectation)",
            "merge_rootfs_revalidation(validation,self.validate_retained_tree(true),",
        ] {
            let position = remainder
                .find(step)
                .unwrap_or_else(|| panic!("physical rootfs identity join step missing: {step}"));
            remainder = &remainder[position + step.len()..];
        }
    }

    #[test]
    fn physical_rootfs_gate_path_projection_consumer_is_exhaustive() {
        let source = include_str!("rootfs/physical.rs").replace("\r\n", "\n");
        let rootfs_paths = source
            .split("fn authenticate_gate_rootfs_path_requirements(")
            .nth(1)
            .unwrap()
            .split("fn authenticate_rootfs_path_requirements(")
            .next()
            .unwrap();
        assert_eq!(
            rootfs_paths
                .matches("expectation.rootfs_path_requirements()")
                .count(),
            2
        );
        assert_eq!(rootfs_paths.matches("requirement.image_path()").count(), 1);
        assert_eq!(
            rootfs_paths
                .matches("requirement.requires_directory()")
                .count(),
            2
        );
        assert_eq!(
            rootfs_paths
                .matches("requirement.requires_empty_regular()")
                .count(),
            1
        );
        assert!(!rootfs_paths.contains("\"/dev\""));
        let compact_paths = rootfs_paths.split_whitespace().collect::<String>();
        let mut remainder = compact_paths.as_str();
        for step in [
            "Vec::with_capacity(expectation.rootfs_path_requirements().len())",
            "forrequirementinexpectation.rootfs_path_requirements(){",
            "requirement.requires_directory()!=requirement.requires_empty_regular()",
            "requirements.push((requirement.image_path(),requirement.requires_directory()));",
            "self.authenticate_rootfs_path_requirements(&requirements)",
        ] {
            let position = remainder
                .find(step)
                .unwrap_or_else(|| panic!("gate-rooted rootfs path step missing: {step}"));
            remainder = &remainder[position + step.len()..];
        }
    }

    #[test]
    fn physical_rootfs_jvm_release_projection_consumers_are_exhaustive() {
        let source = include_str!("rootfs/physical.rs").replace("\r\n", "\n");
        let jvm_identity = source
            .split("fn authenticate_expected_jvm_identity(")
            .nth(1)
            .unwrap()
            .split("fn authenticate_gate_rootfs_path_requirements(")
            .next()
            .unwrap();
        assert_eq!(
            jvm_identity
                .matches("self.authenticate_java_release(release)?;")
                .count(),
            2
        );
        assert_eq!(
            jvm_identity
                .matches("self.authenticate_static_startup_dependency_closure(")
                .count(),
            2
        );
        let compact_jvm = jvm_identity.split_whitespace().collect::<String>();
        let mut remainder = compact_jvm.as_str();
        for step in [
            "PositiveRunnerRole::JvmValidatorBuild,Some(closure),Some(release)",
            "closure.compiler().is_some()",
            "self.authenticate_java_release(release)?;",
            "PositiveRunnerRole::JvmVerifier,Some(closure),Some(release)",
            "closure.compiler().is_none()",
            "self.authenticate_java_release(release)?;",
            "letlauncher=jvm_executables.map(|_|{",
            "self.authenticate_static_startup_dependency_closure(expectation,GateRootedStartupExecutableV1::Launcher,)",
            ".transpose()?;",
            "letcompiler=jvm_executables.and_then(|closure|closure.compiler()).map(|_|{",
            "self.authenticate_static_startup_dependency_closure(expectation,GateRootedStartupExecutableV1::Compiler,)",
            ".transpose()?;",
            "Ok(StaticStartupDependencyBaselinesV1{launcher,compiler})",
        ] {
            let position = remainder
                .find(step)
                .unwrap_or_else(|| panic!("gate-rooted JVM identity step missing: {step}"));
            remainder = &remainder[position + step.len()..];
        }

        let runtime_identity = source
            .split("fn authenticate_runtime_elf(")
            .nth(1)
            .unwrap()
            .split("fn authenticate_java_release(")
            .next()
            .unwrap();
        for getter in ["expected.image_path()", "expected.byte_length()"] {
            assert_eq!(runtime_identity.matches(getter).count(), 1, "{getter}");
        }
        let release_identity = source
            .split("fn authenticate_java_release(")
            .nth(1)
            .unwrap()
            .split("fn authenticate_java_release_fields(")
            .next()
            .unwrap();
        for getter in [
            "expected.image_path()",
            "expected.byte_length()",
            "expected.sha256()",
            "expected.feature_version()",
            "expected.vendor()",
            "expected.version()",
        ] {
            assert_eq!(release_identity.matches(getter).count(), 1, "{getter}");
        }
        let release_fields = source
            .split("fn authenticate_java_release_fields(")
            .nth(1)
            .unwrap()
            .split("#[cfg(test)]")
            .next()
            .unwrap()
            .split_whitespace()
            .collect::<String>();
        assert!(release_fields.contains("&[0o444,0o555]"));
    }

    #[test]
    fn physical_static_startup_default_search_directory_order_is_exact() {
        let source = include_str!("rootfs/physical.rs").replace("\r\n", "\n");
        let literal = source
            .split("const STARTUP_DEFAULT_SEARCH_DIRECTORIES: [&str; 6] = [")
            .nth(1)
            .expect("startup default-directory constant")
            .split("];\n")
            .next()
            .expect("startup default-directory constant terminator");
        let observed = literal
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(|entry| entry.trim_matches('"'))
            .collect::<Vec<_>>();
        assert_eq!(
            observed,
            [
                "/lib/x86_64-linux-gnu",
                "/usr/lib/x86_64-linux-gnu",
                "/lib64",
                "/usr/lib64",
                "/lib",
                "/usr/lib",
            ]
        );
    }

    fn assert_physical_static_startup_gate_rooting(source: &str) {
        let production = source
            .split("fn authenticate_static_startup_dependency_closure(")
            .nth(1)
            .unwrap()
            .split("#[cfg(test)]\n    fn authenticate_test_static_startup_dependency_closure(")
            .next()
            .unwrap();
        let compact_production = production.split_whitespace().collect::<String>();
        for required in [
            "expectation.jvm_executables()",
            "closure.startup_dependency_policy().policy_id()",
            "expectation.rootfs_path_requirements()",
            "requirement.image_path()!=\"/dev\"",
            "resolve_startup_rootfs_regular_path(",
            "with_gate_bound_runtime_amd64_elf(",
            "own_startup_elf_projection(common)",
            "own_startup_dynamic_projection(dynamic)?",
            "reserve_startup_object(",
            "derive_static_startup_dependency_closure(",
        ] {
            assert!(
                compact_production.contains(required),
                "missing startup join: {required}"
            );
        }
    }

    fn assert_physical_static_startup_derivation(source: &str) {
        let derivation = source
            .split("fn derive_static_startup_dependency_closure(")
            .nth(1)
            .unwrap()
            .split("fn inspect_startup_dependency_dso(")
            .next()
            .unwrap();
        assert_eq!(
            derivation
                .matches("self.build_startup_basename_index()?")
                .count(),
            1,
            "basename index must be built at most once per process closure"
        );
        for required in [
            "try_reserve_exact(usize::try_from(limits.maximum_distinct_objects())?)",
            "try_reserve_exact(usize::try_from(limits.maximum_dependency_edges())?)",
            "VecDeque::new()",
            "StaticStartupDependencyResolutionKindV1::LoadedSoname",
            "StaticStartupDependencyResolutionKindV1::RootfsSearch",
            "limits.checked_add_distinct_objects(",
            "limits.checked_add_dependency_edges(",
            "limits.validate_depth(",
            "validate_static_startup_dependency_closure_identity(&closure)?",
        ] {
            assert!(
                derivation.contains(required),
                "missing bounded derivation: {required}"
            );
        }
        let compact_derivation = derivation.split_whitespace().collect::<String>();
        for required in [
            "u64::try_from(state.nodes.len())?==state.counters.distinct_objects",
            "u64::try_from(state.edges.len())?==state.counters.dependency_edges",
            "==Some(state.counters.aggregate_distinct_object_bytes)",
        ] {
            assert!(
                compact_derivation.contains(required),
                "missing startup counter reconciliation: {required}"
            );
        }
    }

    fn assert_physical_static_startup_projection(source: &str, compact_source: &str) {
        for required in [
            "accepted_tags: Vec<Amd64ElfAcceptedDynamicTagV1>",
            ".try_reserve_exact(dynamic.accepted_tags().len())",
            ".zip(&node.dynamic.accepted_tags)",
            "startup_dynamic_tag_matches_raw(",
            "B4ImmutableArtifactRoleV1::Amd64Elf(Amd64ElfPolicyV1::Runtime)",
            ".validate_section_header_count(",
        ] {
            assert!(
                source.contains(required),
                "missing owned typed dynamic-tag projection: {required}"
            );
        }
        for required in [
            "accepted_records:Vec<(i64,u64)>",
            ".try_reserve_exact(dynamic.accepted_records().len())",
            "accepted_records.push((record.d_tag(),record.d_un()));",
        ] {
            assert!(
                compact_source.contains(required),
                "missing exact owned raw dynamic-record projection: {required}"
            );
        }

        let owned_elf = source
            .split("fn own_startup_elf_projection(")
            .nth(1)
            .unwrap()
            .split("fn own_startup_dynamic_projection(")
            .next()
            .unwrap();
        let compact_owned_elf = owned_elf.split_whitespace().collect::<String>();
        assert!(!owned_elf.contains("entry_point_is_zero: bool"));
        assert!(compact_owned_elf.contains("entry_point_is_zero:common.entry_point_is_zero(),"));

        let dso = source
            .split("fn inspect_startup_dependency_dso(")
            .nth(1)
            .unwrap()
            .split("fn resolve_startup_dependency_search(")
            .next()
            .unwrap();
        for required in [
            "with_inspected_startup_dependency_amd64_dso(",
            "own_startup_elf_projection(inspected.common())",
            "own_startup_dynamic_projection(inspected.dynamic())?",
            "validate_owned_startup_dynamic_for_resolution(&resolution, &dynamic)?",
        ] {
            assert!(
                dso.contains(required),
                "missing DSO identity join: {required}"
            );
        }
    }

    fn assert_physical_static_startup_antichain(source: &str) {
        let antichain = source
            .split("fn authenticate_startup_resolution_antichain(")
            .nth(1)
            .unwrap()
            .split("fn build_startup_basename_index(")
            .next()
            .unwrap();
        assert!(antichain.contains("hop.canonical_link_path.as_str()"));
        assert!(antichain.contains("hop.normalized_target_path.as_str()"));

        let resolver = source
            .split("fn resolve_authenticated_rootfs_path(")
            .nth(1)
            .unwrap()
            .split("fn authenticate_resolved_rootfs_directory(")
            .next()
            .unwrap();
        let prefix_antichain = resolver
            .find("Self::authenticate_startup_resolution_prefix(")
            .expect("startup resolver must check each walked component inline");
        let journal_lookup = resolver
            .find("self.live_entry_position(normalized.as_str())?")
            .expect("startup resolver journal lookup");
        assert!(prefix_antichain < journal_lookup);
        assert!(!source.contains("walked_paths"));
    }

    fn assert_physical_static_startup_retained_reauthentication(source: &str) {
        let retained = source
            .split("impl AuthenticatedPrivateOciRetainedPhysicalRootfsV1 {")
            .nth(1)
            .unwrap()
            .split("fn reserve_startup_object(")
            .next()
            .unwrap();
        assert_eq!(
            retained
                .matches(".authenticate_expected_rootfs_identity(expectation)?;")
                .count(),
            1
        );
        assert_eq!(
            retained
                .matches(".authenticate_test_static_startup_dependency_identity(expectation)?;")
                .count(),
            1
        );
        assert_eq!(
            retained
                .matches(
                    "retained static startup dependency closure differs from its rederived identity"
                )
                .count(),
            2
        );
        assert_eq!(
            retained
                .matches("self.rootfs.validate_retained_tree(true)")
                .count(),
            2,
            "each retained reauthentication must finish with tree validation"
        );
    }

    fn assert_physical_static_startup_consuming_seam(source: &str) {
        let retain = source
            .split("pub(super) fn test_only_authenticate_startup_dependency_closure_and_retain(")
            .nth(1)
            .unwrap()
            .split("fn authenticate_test_static_startup_dependency_identity(")
            .next()
            .unwrap();
        let compact_retain = retain.split_whitespace().collect::<String>();
        for required in [
            "self.authenticate_test_static_startup_dependency_identity(expectation)",
            "Ok(static_startup_dependencies)=>{Ok(AuthenticatedPrivateOciRetainedPhysicalRootfsV1{rootfs:self,static_startup_dependencies,})}",
            "Err(primary)=>Err(self.fail_after_named_effect(primary))",
        ] {
            assert!(
                compact_retain.contains(required),
                "missing retained startup seam step: {required}"
            );
        }

        let producer = source
            .split("fn authenticate_test_static_startup_dependency_identity(")
            .nth(1)
            .unwrap()
            .split("fn authenticate_test_static_startup_dependency_baselines(")
            .next()
            .unwrap();
        let compact_producer = producer.split_whitespace().collect::<String>();
        for required in [
            "self.validate_retained_tree(true)?;",
            "self.validate_live_entry_ordering()?;",
            "self.authenticate_test_static_startup_dependency_baselines(expectation)",
            "merge_rootfs_revalidation(",
            "self.validate_retained_tree(true)",
        ] {
            assert!(
                compact_producer.contains(required),
                "missing startup identity producer step: {required}"
            );
        }

        let baselines = source
            .split("fn authenticate_test_static_startup_dependency_baselines(")
            .nth(1)
            .unwrap()
            .split("fn validate_test_static_startup_dependency_expectation(")
            .next()
            .unwrap();
        let compact_baselines = baselines.split_whitespace().collect::<String>();
        for required in [
            "additional_independent_image_paths.len()<=1",
            "letlauncher=self.authenticate_test_static_startup_dependency_closure(expectation.image_path,expectation.mount_targets,)?;",
            "letcompiler=expectation.additional_independent_image_paths.first()",
            "Ok(StaticStartupDependencyBaselinesV1{launcher:Some(launcher),compiler,})",
        ] {
            assert!(
                compact_baselines.contains(required),
                "missing fixed startup baseline step: {required}"
            );
        }

        let expectation = source
            .split("fn validate_test_static_startup_dependency_expectation(")
            .nth(1)
            .unwrap()
            .split("fn authenticate_runtime_elf(")
            .next()
            .unwrap();
        let compact_expectation = expectation.split_whitespace().collect::<String>();
        for required in [
            "expected_aggregate_distinct_object_bytes",
            "sum.checked_add(node.byte_length)",
            "expected_root_entry_point_is_zero",
            "node.elf.entry_point_is_zero==expected",
        ] {
            assert!(
                compact_expectation.contains(required),
                "missing startup expectation step: {required}"
            );
        }

        assert_physical_static_startup_retained_reauthentication(source);
    }

    #[test]
    fn physical_static_startup_closure_is_gate_rooted_bounded_and_descriptor_rooted() {
        let source = include_str!("rootfs/physical.rs").replace("\r\n", "\n");
        let compact_source = source.split_whitespace().collect::<String>();
        assert_physical_static_startup_gate_rooting(&source);
        assert_physical_static_startup_derivation(&source);
        assert_physical_static_startup_projection(&source, &compact_source);
        assert_physical_static_startup_antichain(&source);
        assert_physical_static_startup_consuming_seam(&source);
    }

    fn assert_host_rootfs_mapped_owner_mutation_retries(
        temp: &Path,
        before: &BTreeSet<OsString>,
        label: &str,
        mutation: super::physical::TestOnlyPhysicalCustodyMutationV1,
        expected_error: &str,
    ) -> Result<()> {
        let (final_path, retained) = authenticated_mixed_projection(
            temp,
            &format!("host-rootfs-mapped-owner-{label}-mutant"),
        )?;
        let materialized = retained.materialize_private()?;
        materialized.test_only_arm_cleanup_custody_mutation(mutation);
        let Err(failure) = materialized.cleanup() else {
            panic!("{label} mutant must fail the mapped-owner prerequisite")
        };
        assert!(
            format!("{failure:#}").contains(expected_error),
            "{label}: {failure:#}"
        );

        let abandonment = failure.retry_cleanup()?;
        assert!(abandonment.final_unlinked_observed, "{label}");
        assert_eq!(directory_names(temp)?, *before, "{label}");
        assert!(fs::symlink_metadata(&final_path).is_err(), "{label}");
        Ok(())
    }

    #[test]
    fn host_rootfs_mapped_owner_prerequisite_covers_each_entry_kind() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, retained) =
            authenticated_mixed_projection(temp.path(), "host-rootfs-mapped-owner-positive")?;
        let materialized = retained.materialize_private()?;
        let during = directory_names(temp.path())?;
        let added = during.difference(&before).collect::<Vec<_>>();
        assert_eq!(added.len(), 1);
        let staging = temp.path().join(added[0]);
        let expected_owner = rustix::process::geteuid().as_raw();
        let expected_group = rustix::process::getegid().as_raw();

        for path in [
            staging.clone(),
            staging.join("bin"),
            staging.join("bin/tool"),
            staging.join("bin/tool-link"),
        ] {
            let metadata = fs::symlink_metadata(&path)?;
            assert_eq!(metadata.uid(), expected_owner, "{}", path.display());
            assert_eq!(metadata.gid(), expected_group, "{}", path.display());
        }

        let abandonment = materialized.cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn host_rootfs_mapped_owner_prerequisite_rejects_each_owner_and_group_mutant_then_retries()
    -> Result<()> {
        use super::physical::TestOnlyPhysicalCustodyMutationV1 as Mutation;

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        for (label, mutation, expected_error) in [
            (
                "root-owner",
                Mutation::StagingStableUnexpectedOwner,
                "owner differs from the retained host-rootfs mapped-owner prerequisite finalizer effective UID",
            ),
            (
                "root-group",
                Mutation::StagingStableUnexpectedGroup,
                "group differs from the retained host-rootfs mapped-owner prerequisite finalizer effective GID",
            ),
            (
                "directory-owner",
                Mutation::DirectoryStableUnexpectedOwner { operation_index: 0 },
                "owner differs from the retained host-rootfs mapped-owner prerequisite finalizer effective UID",
            ),
            (
                "directory-group",
                Mutation::DirectoryStableUnexpectedGroup { operation_index: 0 },
                "group differs from the retained host-rootfs mapped-owner prerequisite finalizer effective GID",
            ),
            (
                "regular-owner",
                Mutation::RegularStableUnexpectedOwner { operation_index: 5 },
                "owner differs from the retained host-rootfs mapped-owner prerequisite finalizer effective UID",
            ),
            (
                "regular-group",
                Mutation::RegularStableUnexpectedGroup { operation_index: 5 },
                "group differs from the retained host-rootfs mapped-owner prerequisite finalizer effective GID",
            ),
            (
                "symbolic-link-owner",
                Mutation::SymbolicLinkStableUnexpectedOwner { operation_index: 6 },
                "owner differs from the retained host-rootfs mapped-owner prerequisite finalizer effective UID",
            ),
            (
                "symbolic-link-group",
                Mutation::SymbolicLinkStableUnexpectedGroup { operation_index: 6 },
                "group differs from the retained host-rootfs mapped-owner prerequisite finalizer effective GID",
            ),
        ] {
            assert_host_rootfs_mapped_owner_mutation_retries(
                temp.path(),
                &before,
                label,
                mutation,
                expected_error,
            )?;
        }
        Ok(())
    }

    #[test]
    fn host_rootfs_mapped_owner_prerequisite_rejects_each_effective_id_snapshot_drift_then_retries()
    -> Result<()> {
        use super::physical::TestOnlyPhysicalCustodyMutationV1 as Mutation;

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        for (label, mutation, expected_error) in [
            (
                "effective-uid-snapshot",
                Mutation::FinalizerEffectiveUid,
                "finalizer effective UID drifted",
            ),
            (
                "effective-gid-snapshot",
                Mutation::FinalizerEffectiveGid,
                "finalizer effective GID drifted",
            ),
        ] {
            assert_host_rootfs_mapped_owner_mutation_retries(
                temp.path(),
                &before,
                label,
                mutation,
                expected_error,
            )?;
        }
        Ok(())
    }

    fn assert_host_rootfs_mapped_owner_materialization_failure_auto_cleans(
        temp: &Path,
        before: &BTreeSet<OsString>,
        label: &str,
        failpoint: super::physical::TestOnlyPrivateMaterializationFailpointV1,
        expected_error: &str,
    ) -> Result<()> {
        let (final_path, mut retained) = authenticated_mixed_projection(
            temp,
            &format!("host-rootfs-mapped-owner-production-{label}"),
        )?;
        retained.test_only_physical_materialization_failpoint = Some(failpoint);

        let error = expect_error(retained.materialize_private());
        assert!(format!("{error:#}").contains(expected_error), "{error:#}");
        assert!(
            error
                .downcast_ref::<super::physical::PrivateOciRootfsCleanupFailureV1>()
                .is_none(),
            "{label} unexpectedly lost automatic cleanup: {error:#}"
        );
        assert_eq!(directory_names(temp)?, *before);
        assert!(fs::symlink_metadata(&final_path).is_err());
        Ok(())
    }

    #[test]
    fn host_rootfs_mapped_owner_prerequisite_rejects_each_production_owner_and_group_mismatch_and_auto_cleans()
    -> Result<()> {
        use super::physical::TestOnlyPrivateMaterializationFailpointV1 as Failpoint;

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        for (label, failpoint, expected_error) in [
            (
                "root-owner",
                Failpoint::StagingRootMappedOwnerMismatch,
                "owner differs from the retained host-rootfs mapped-owner prerequisite finalizer effective UID",
            ),
            (
                "root-group",
                Failpoint::StagingRootMappedGroupMismatch,
                "group differs from the retained host-rootfs mapped-owner prerequisite finalizer effective GID",
            ),
            (
                "directory-owner",
                Failpoint::DirectoryMappedOwnerMismatch { operation_index: 0 },
                "owner differs from the retained host-rootfs mapped-owner prerequisite finalizer effective UID",
            ),
            (
                "directory-group",
                Failpoint::DirectoryMappedGroupMismatch { operation_index: 0 },
                "group differs from the retained host-rootfs mapped-owner prerequisite finalizer effective GID",
            ),
            (
                "regular-owner",
                Failpoint::RegularMappedOwnerMismatch { operation_index: 5 },
                "owner differs from the retained host-rootfs mapped-owner prerequisite finalizer effective UID",
            ),
            (
                "regular-group",
                Failpoint::RegularMappedGroupMismatch { operation_index: 5 },
                "group differs from the retained host-rootfs mapped-owner prerequisite finalizer effective GID",
            ),
            (
                "symbolic-link-owner",
                Failpoint::SymbolicLinkMappedOwnerMismatch { operation_index: 6 },
                "owner differs from the retained host-rootfs mapped-owner prerequisite finalizer effective UID",
            ),
            (
                "symbolic-link-group",
                Failpoint::SymbolicLinkMappedGroupMismatch { operation_index: 6 },
                "group differs from the retained host-rootfs mapped-owner prerequisite finalizer effective GID",
            ),
        ] {
            assert_host_rootfs_mapped_owner_materialization_failure_auto_cleans(
                temp.path(),
                &before,
                label,
                failpoint,
                expected_error,
            )?;
        }
        Ok(())
    }

    #[test]
    fn host_rootfs_mapped_owner_prerequisite_rejects_pre_first_effective_id_drift_before_mkdir()
    -> Result<()> {
        use super::physical::TestOnlyPrivateMaterializationFailpointV1 as Failpoint;

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        for (label, failpoint, expected_error) in [
            (
                "pre-first-effective-uid",
                Failpoint::BeforeFirstEffectFinalizerEffectiveUidMismatch,
                "finalizer effective UID drifted",
            ),
            (
                "pre-first-effective-gid",
                Failpoint::BeforeFirstEffectFinalizerEffectiveGidMismatch,
                "finalizer effective GID drifted",
            ),
        ] {
            assert_host_rootfs_mapped_owner_materialization_failure_auto_cleans(
                temp.path(),
                &before,
                label,
                failpoint,
                expected_error,
            )?;
        }
        Ok(())
    }

    #[test]
    fn calling_thread_namespace_id_map_and_filesystem_credential_drift_reject_before_first_named_effect()
    -> Result<()> {
        use super::physical::TestOnlyPrivateMaterializationFailpointV1 as Failpoint;

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        for (label, failpoint, expected) in [
            (
                "pre-first-mount-namespace",
                Failpoint::BeforeFirstEffectMountNamespaceMismatch,
                "calling-thread mount namespace changed",
            ),
            (
                "pre-first-user-namespace",
                Failpoint::BeforeFirstEffectUserNamespaceMismatch,
                "calling-thread user namespace changed",
            ),
            (
                "pre-first-mismatched-uid-map",
                Failpoint::BeforeFirstEffectUidMapMismatch,
                "calling-thread uid_map changed",
            ),
            (
                "pre-first-mismatched-gid-map",
                Failpoint::BeforeFirstEffectGidMapMismatch,
                "calling-thread gid_map changed",
            ),
            (
                "pre-first-mismatched-supplementary-groups",
                Failpoint::BeforeFirstEffectSupplementaryGroupsMismatch,
                "calling-thread supplementary groups changed",
            ),
            (
                "pre-first-mismatched-fsuid",
                Failpoint::BeforeFirstEffectFsuidMismatch,
                "calling-thread fsuid changed",
            ),
            (
                "pre-first-mismatched-fsgid",
                Failpoint::BeforeFirstEffectFsgidMismatch,
                "calling-thread fsgid changed",
            ),
        ] {
            assert_host_rootfs_mapped_owner_materialization_failure_auto_cleans(
                temp.path(),
                &before,
                label,
                failpoint,
                expected,
            )?;
        }
        Ok(())
    }

    #[test]
    fn user_namespace_map_parser_rejects_linux_id_sentinel_ranges() {
        super::physical::test_only_validate_user_namespace_map(b"0 0 4294967295\n", "uid_map")
            .expect("the largest sentinel-excluding Linux ID range is valid");

        for (bytes, expected) in [
            (&b""[..], "calling-thread uid_map is empty"),
            (
                &b"0 0 4294967296\n"[..],
                "calling-thread uid_map length is malformed",
            ),
            (
                &b"1 0 4294967295\n"[..],
                "calling-thread uid_map range leaves the Linux ID space",
            ),
            (
                &b"0 1 4294967295\n"[..],
                "calling-thread uid_map range leaves the Linux ID space",
            ),
        ] {
            let error = super::physical::test_only_validate_user_namespace_map(bytes, "uid_map")
                .unwrap_err();
            assert!(format!("{error:#}").contains(expected), "{error:#}");
        }
    }

    #[test]
    fn regular_chunk_reauthenticates_mount_namespace_before_anonymous_spool_effect() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, _, layout) = projected(temp.path(), "chunk-namespace-drift")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        transaction.begin_root_regular("artifact", 0o444, 3)?;
        assert_eq!(transaction.anonymous_spool_observation()?.byte_length, 0);
        transaction
            .current_mount_namespace
            .test_only_arm_next_reauthentication_identity_mismatch();

        let error = transaction.write_regular_chunk(b"abc").unwrap_err();
        assert!(
            format!("{error:#}").contains("calling-thread mount namespace changed"),
            "{error:#}"
        );
        assert_eq!(transaction.anonymous_spool_observation()?.byte_length, 0);
        let abandonment = transaction.abandon();
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(fs::symlink_metadata(&final_path).is_err());
        Ok(())
    }

    #[test]
    fn host_rootfs_mapped_owner_prerequisite_rejects_post_fsync_effective_id_drift_and_auto_cleans()
    -> Result<()> {
        use super::physical::TestOnlyPrivateMaterializationFailpointV1 as Failpoint;

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        for (label, failpoint, expected_error) in [
            (
                "post-fsync-effective-uid",
                Failpoint::AfterMaterializationFsyncFinalizerEffectiveUidMismatch,
                "finalizer effective UID drifted",
            ),
            (
                "post-fsync-effective-gid",
                Failpoint::AfterMaterializationFsyncFinalizerEffectiveGidMismatch,
                "finalizer effective GID drifted",
            ),
        ] {
            assert_host_rootfs_mapped_owner_materialization_failure_auto_cleans(
                temp.path(),
                &before,
                label,
                failpoint,
                expected_error,
            )?;
        }
        Ok(())
    }

    #[test]
    fn host_rootfs_root_mode_and_mtime_runtime_metadata_seal_covers_each_entry_kind() -> Result<()>
    {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, retained) = authenticated_mixed_projection(
            temp.path(),
            "host-rootfs-runtime-metadata-seal-positive",
        )?;

        let materialized = retained.materialize_private()?;
        assert!(!final_path.exists());
        let during = directory_names(temp.path())?;
        let added = during.difference(&before).collect::<Vec<_>>();
        assert_eq!(added.len(), 1);
        let staging = temp.path().join(added[0]);
        let root_metadata = fs::symlink_metadata(&staging)?;
        assert!(root_metadata.is_dir());
        assert_eq!(root_metadata.permissions().mode() & 0o7777, 0o555);
        assert_eq!((root_metadata.mtime(), root_metadata.mtime_nsec()), (0, 0));
        assert_eq!(
            directory_names(&staging)?,
            BTreeSet::from([OsString::from("bin"), OsString::from("notice")])
        );
        let directory = fs::symlink_metadata(staging.join("bin"))?;
        assert!(directory.is_dir());
        assert_eq!(directory.permissions().mode() & 0o7777, 0o555);
        assert_eq!((directory.mtime(), directory.mtime_nsec()), (0, 0));
        let regular = fs::symlink_metadata(staging.join("bin/tool"))?;
        assert!(regular.is_file());
        assert_eq!(regular.nlink(), 1);
        assert_eq!(regular.permissions().mode() & 0o7777, 0o555);
        assert_eq!((regular.mtime(), regular.mtime_nsec()), (0, 0));
        assert_eq!(fs::read(staging.join("bin/tool"))?, b"EXEC");
        let symbolic_link = fs::symlink_metadata(staging.join("bin/tool-link"))?;
        assert!(symbolic_link.file_type().is_symlink());
        assert_eq!((symbolic_link.mtime(), symbolic_link.mtime_nsec()), (0, 0));
        assert_eq!(
            fs::read_link(staging.join("bin/tool-link"))?,
            PathBuf::from("tool")
        );
        let root_regular = fs::symlink_metadata(staging.join("notice"))?;
        assert!(root_regular.is_file());
        assert_eq!(root_regular.permissions().mode() & 0o7777, 0o444);
        assert_eq!((root_regular.mtime(), root_regular.mtime_nsec()), (0, 0));

        let abandonment = materialized.cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn host_rootfs_root_mode_and_mtime_runtime_metadata_seal_is_deepest_first_then_root()
    -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, retained) = authenticated_nested_directory_projection(
            temp.path(),
            "host-rootfs-runtime-metadata-seal-order",
        )?;

        let materialized = retained.materialize_private()?;
        assert!(
            materialized
                .test_only_runtime_metadata_seal_order()
                .iter()
                .map(String::as_str)
                .eq(["a/b/c", "a/b", "a", "/"])
        );
        let abandonment = materialized.cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(fs::symlink_metadata(&final_path).is_err());
        Ok(())
    }

    #[test]
    fn host_rootfs_root_mode_and_mtime_runtime_metadata_seal_rejects_each_mtime_mutant_and_retries()
    -> Result<()> {
        use super::physical::TestOnlyPhysicalCustodyMutationV1 as Mutation;

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        for (label, mutation) in [
            ("root-seconds", Mutation::StagingObservedMtimeSeconds),
            (
                "root-nanoseconds",
                Mutation::StagingObservedMtimeNanoseconds,
            ),
            (
                "directory-seconds",
                Mutation::DirectoryObservedMtimeSeconds { operation_index: 0 },
            ),
            (
                "directory-nanoseconds",
                Mutation::DirectoryObservedMtimeNanoseconds { operation_index: 0 },
            ),
            (
                "regular-seconds",
                Mutation::RegularObservedMtimeSeconds { operation_index: 5 },
            ),
            (
                "regular-nanoseconds",
                Mutation::RegularObservedMtimeNanoseconds { operation_index: 5 },
            ),
            (
                "symbolic-link-seconds",
                Mutation::SymbolicLinkObservedMtimeSeconds { operation_index: 6 },
            ),
            (
                "symbolic-link-nanoseconds",
                Mutation::SymbolicLinkObservedMtimeNanoseconds { operation_index: 6 },
            ),
        ] {
            let (final_path, retained) = authenticated_mixed_projection(
                temp.path(),
                &format!("host-rootfs-runtime-metadata-seal-{label}-mutant"),
            )?;
            let materialized = retained.materialize_private()?;
            materialized.test_only_arm_cleanup_custody_mutation(mutation);
            let Err(failure) = materialized.cleanup() else {
                panic!("{label} mtime mutant must prevent cleanup")
            };
            let error = format!("{failure:#}");
            assert!(
                error.contains("changed") || error.contains("differs"),
                "{label}: {error}"
            );
            let abandonment = failure.retry_cleanup()?;
            assert!(abandonment.final_unlinked_observed, "{label}");
            assert_eq!(directory_names(temp.path())?, before, "{label}");
            assert!(fs::symlink_metadata(&final_path).is_err(), "{label}");
        }
        Ok(())
    }

    #[test]
    fn host_rootfs_root_mode_and_mtime_runtime_metadata_seal_rejects_root_mode_drift_then_reopens_for_retry()
    -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, retained) = authenticated_mixed_projection(
            temp.path(),
            "host-rootfs-runtime-metadata-seal-root-mode-drift",
        )?;
        let materialized = retained.materialize_private()?;
        let during = directory_names(temp.path())?;
        let added = during.difference(&before).cloned().collect::<Vec<_>>();
        assert_eq!(added.len(), 1);
        let staging = temp.path().join(&added[0]);
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))?;

        let Err(failure) = materialized.cleanup() else {
            panic!("root-mode drift must prevent cleanup")
        };
        assert!(
            format!("{failure:#}").contains("staging directory identity or mode changed"),
            "{failure:#}"
        );
        assert!(staging.join("bin/tool").is_file());
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o555))?;

        let abandonment = failure.retry_cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(fs::symlink_metadata(&final_path).is_err());
        Ok(())
    }

    #[test]
    fn host_rootfs_root_mode_and_mtime_runtime_metadata_seal_retries_after_root_reopen_postcondition_failure()
    -> Result<()> {
        use super::physical::TestOnlyPrivateCleanupFailpointV1 as CleanupFailpoint;

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, retained) = authenticated_mixed_projection(
            temp.path(),
            "host-rootfs-runtime-metadata-seal-root-reopen-failpoint",
        )?;
        let materialized = retained.materialize_private()?;
        materialized.test_only_arm_cleanup_failpoint(CleanupFailpoint::StagingRootReopened);

        let Err(failure) = materialized.cleanup() else {
            panic!("root reopen postcondition failpoint must retain retry custody")
        };
        assert!(
            format!("{failure:#}").contains("StagingRootReopened"),
            "{failure:#}"
        );
        let abandonment = failure.retry_cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(fs::symlink_metadata(&final_path).is_err());
        Ok(())
    }

    #[test]
    fn host_rootfs_root_mode_and_mtime_runtime_metadata_seal_cleans_after_root_seal_failpoint()
    -> Result<()> {
        use super::physical::TestOnlyPrivateMaterializationFailpointV1 as Failpoint;

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, mut retained) = authenticated_mixed_projection(
            temp.path(),
            "host-rootfs-runtime-metadata-seal-root-seal-failpoint",
        )?;
        retained.test_only_physical_materialization_failpoint =
            Some(Failpoint::StagingRootSealRecorded);

        let error = expect_error(retained.materialize_private());
        assert!(
            format!("{error:#}").contains("StagingRootSealRecorded"),
            "{error:#}"
        );
        assert!(
            error
                .downcast_ref::<super::physical::PrivateOciRootfsCleanupFailureV1>()
                .is_none(),
            "recorded root-seal failure unexpectedly lost cleanup: {error:#}"
        );
        assert_eq!(directory_names(temp.path())?, before);
        assert!(fs::symlink_metadata(&final_path).is_err());
        Ok(())
    }

    #[test]
    fn private_runtime_elf_rejects_a_dangling_pt_interp_inside_the_same_rootfs() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
        let (final_path, retained) = authenticated_runtime_elf_projection(
            temp.path(),
            "physical-runtime-dangling-interpreter",
            &runtime_elf,
        )?;
        let materialized = retained.materialize_private()?;

        let error = materialized
            .test_only_authenticate_runtime_elf("/runtime/bin/java")
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("authenticated rootfs path is dangling"),
            "{error:#}"
        );

        let abandonment = materialized.cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn private_runtime_elf_accepts_a_direct_pt_interp_inside_the_same_rootfs() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        exercise_private_runtime_elf_fixture(
            temp.path(),
            "physical-runtime-direct-interpreter",
            &[
                RuntimeRootfsFixtureEntryV1::directory("lib64"),
                RuntimeRootfsFixtureEntryV1::regular(
                    "lib64/ld-linux-x86-64.so.2",
                    0o555,
                    &interpreter,
                ),
            ],
            None,
        )
    }

    #[test]
    fn private_runtime_elf_rejects_missing_direct_dt_needed_and_cleans_up() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let mut entries = startup_default_directory_entries();
        entries.push(RuntimeRootfsFixtureEntryV1::regular(
            "lib64/ld-linux-x86-64.so.2",
            0o555,
            &interpreter,
        ));
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-runtime-missing-direct-needed",
            &runtime_elf,
            &entries,
            &[],
            Some("unresolved DT_NEEDED libc.so.6"),
        )
    }

    #[test]
    fn private_startup_dependency_closure_accepts_direct_dt_needed_and_cleans_up() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let libc = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libc.so.6",
            &[],
            None,
        );
        let expected_aggregate_distinct_object_bytes = u64::try_from(runtime_elf.len())?
            .checked_add(u64::try_from(interpreter.len())?)
            .and_then(|sum| sum.checked_add(u64::try_from(libc.len()).ok()?))
            .ok_or_else(|| anyhow::anyhow!("startup fixture byte sum overflowed"))?;
        let mut entries = startup_default_directory_entries();
        entries.extend([
            RuntimeRootfsFixtureEntryV1::regular("lib64/ld-linux-x86-64.so.2", 0o555, &interpreter),
            RuntimeRootfsFixtureEntryV1::regular("lib/x86_64-linux-gnu/libc.so.6", 0o444, &libc),
        ]);
        exercise_private_startup_dependency_fixture_with_expected_order(
            temp.path(),
            "physical-startup-direct-needed",
            &runtime_elf,
            &entries,
            &PrivateStartupDependencyFixtureExpectationV1 {
                mount_targets: &[],
                expected_canonical_node_order: Some(&[
                    "/runtime/bin/java",
                    "/lib64/ld-linux-x86-64.so.2",
                    "/lib/x86_64-linux-gnu/libc.so.6",
                ]),
                expected_edges: Some(&[(0, 2, "libc.so.6", "rootfs-search", 2, 1)]),
                expected_aggregate_distinct_object_bytes: Some(
                    expected_aggregate_distinct_object_bytes,
                ),
                expected_error_fragment: None,
            },
        )
    }

    #[derive(Debug)]
    struct TestOnlyRetainedRootfsAcquisitionPrimaryV1;

    impl std::fmt::Display for TestOnlyRetainedRootfsAcquisitionPrimaryV1 {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("test-only retained rootfs acquisition primary")
        }
    }

    impl std::error::Error for TestOnlyRetainedRootfsAcquisitionPrimaryV1 {}

    #[test]
    fn retained_rootfs_acquisition_retry_preserves_typed_primary_and_cleans_current_custody()
    -> Result<()> {
        use super::physical::TestOnlyPhysicalCustodyMutationV1 as Mutation;

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, projection) =
            authenticated_mixed_projection(temp.path(), "retained-acquisition-current-custody")?;
        let materialized = projection.materialize_private()?;
        materialized.test_only_arm_cleanup_custody_mutation(Mutation::StagingObservedOwner);
        let error = materialized.test_only_fail_after_named_effect(anyhow::Error::new(
            TestOnlyRetainedRootfsAcquisitionPrimaryV1,
        ));
        let failure = PrivateOciRetainedRootfsAcquisitionFailureV1::classify(error);
        assert!(matches!(
            &failure.state,
            super::PrivateOciRetainedRootfsAcquisitionFailureStateV1::RetryCustody(_)
        ));
        let before_retry = format!("{failure:#}");
        assert!(
            before_retry.contains("test-only retained rootfs acquisition primary"),
            "{before_retry}"
        );
        assert!(
            before_retry.contains("materialization cleanup is incomplete"),
            "{before_retry}"
        );

        let preserved_error = failure.retry_cleanup().map_err(anyhow::Error::new)?;
        assert!(
            preserved_error
                .downcast_ref::<TestOnlyRetainedRootfsAcquisitionPrimaryV1>()
                .is_some(),
            "{preserved_error:#}"
        );
        assert!(
            format!("{preserved_error:#}").contains("materialization cleanup is incomplete"),
            "{preserved_error:#}"
        );
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn retained_rootfs_acquisition_classifies_closed_materialization_failure_as_nonretry()
    -> Result<()> {
        use super::physical::TestOnlyPrivateMaterializationFailpointV1 as Failpoint;

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, mut projection) = authenticated_mixed_projection(
            temp.path(),
            "retained-acquisition-materialize-failure",
        )?;
        projection.test_only_physical_materialization_failpoint =
            Some(Failpoint::StagingRootIdentityCaptured);
        let error = expect_error(projection.materialize_private());
        let failure = PrivateOciRetainedRootfsAcquisitionFailureV1::classify(error);
        assert!(matches!(
            &failure.state,
            super::PrivateOciRetainedRootfsAcquisitionFailureStateV1::NonRetry(_)
        ));
        let primary = failure.retry_cleanup().map_err(anyhow::Error::new)?;
        assert!(
            format!("{primary:#}").contains("StagingRootIdentityCaptured"),
            "{primary:#}"
        );
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn retained_java_and_javac_startup_dependencies_reject_each_baseline_sha_drift_and_clean_up()
    -> Result<()> {
        for baseline in [
            TestOnlyRetainedStartupBaselineV1::Launcher,
            TestOnlyRetainedStartupBaselineV1::Compiler,
        ] {
            let temp = tempfile::tempdir()?;
            let before = directory_names(temp.path())?;
            let java =
                crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
            let javac =
                crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
            let interpreter =
                crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                    "ld-linux-x86-64.so.2",
                    &[],
                    None,
                );
            let libc = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "libc.so.6",
                &[],
                None,
            );
            let mut entries = startup_default_directory_entries();
            entries.extend([
                RuntimeRootfsFixtureEntryV1::regular(
                    "lib64/ld-linux-x86-64.so.2",
                    0o555,
                    &interpreter,
                ),
                RuntimeRootfsFixtureEntryV1::regular(
                    "lib/x86_64-linux-gnu/libc.so.6",
                    0o444,
                    &libc,
                ),
                RuntimeRootfsFixtureEntryV1::regular("runtime/bin/javac", 0o555, &javac),
            ]);
            let (final_path, retained) = authenticated_runtime_elf_projection_with_entries(
                temp.path(),
                &format!("physical-startup-retained-java-javac-{baseline:?}"),
                &java,
                &entries,
            )?;
            let expectation = StartupClosureTestExpectationV1 {
                image_path: "/runtime/bin/java",
                additional_independent_image_paths: &["/runtime/bin/javac"],
                mount_targets: &[],
                expected_canonical_node_order: None,
                expected_edges: None,
                expected_aggregate_distinct_object_bytes: None,
                expected_root_entry_point_is_zero: None,
            };
            let mut retained = retained
                .materialize_private()?
                .test_only_authenticate_startup_dependency_closure_and_retain(&expectation)?;
            retained.test_only_reauthenticate_static_startup_dependencies(&expectation)?;
            retained.test_only_mutate_startup_baseline_sha256(baseline);

            let error = expect_error(
                retained.test_only_reauthenticate_static_startup_dependencies(&expectation),
            );
            assert!(
                format!("{error:#}").contains(
                    "retained static startup dependency closure differs from its rederived identity"
                ),
                "{baseline:?}: {error:#}"
            );
            let abandonment = retained.cleanup()?;
            assert!(abandonment.final_unlinked_observed, "{baseline:?}");
            assert_eq!(directory_names(temp.path())?, before, "{baseline:?}");
            assert!(!final_path.exists(), "{baseline:?}");
        }
        Ok(())
    }

    #[test]
    fn retained_physical_tree_drift_between_reauthentications_is_rejected_and_cleaned_up()
    -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let java = crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let libc = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libc.so.6",
            &[],
            None,
        );
        let mut entries = startup_default_directory_entries();
        entries.extend([
            RuntimeRootfsFixtureEntryV1::regular("lib64/ld-linux-x86-64.so.2", 0o555, &interpreter),
            RuntimeRootfsFixtureEntryV1::regular("lib/x86_64-linux-gnu/libc.so.6", 0o444, &libc),
        ]);
        let (final_path, retained) = authenticated_runtime_elf_projection_with_entries(
            temp.path(),
            "physical-startup-retained-tree-drift",
            &java,
            &entries,
        )?;
        let expectation = StartupClosureTestExpectationV1 {
            image_path: "/runtime/bin/java",
            additional_independent_image_paths: &[],
            mount_targets: &[],
            expected_canonical_node_order: None,
            expected_edges: None,
            expected_aggregate_distinct_object_bytes: None,
            expected_root_entry_point_is_zero: None,
        };
        let retained = retained
            .materialize_private()?
            .test_only_authenticate_startup_dependency_closure_and_retain(&expectation)?;
        retained.test_only_reauthenticate_static_startup_dependencies(&expectation)?;
        retained.test_only_arm_regular_owner_custody_mutation("runtime/bin/java")?;

        let error = expect_error(
            retained.test_only_reauthenticate_static_startup_dependencies(&expectation),
        );
        assert!(
            format!("{error:#}").contains(
                "materialized OCI rootfs regular file physical owner/group differs from its captured cleanup custody"
            ),
            "{error:#}"
        );
        let abandonment = retained.cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn private_startup_dependency_closure_accepts_zero_entry_runtime() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let runtime_elf = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_runtime_zero_entry_elf_bytes(
            &[], None,
        );
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let entries = startup_base_entries(&interpreter, 0o555);
        let (final_path, retained) = authenticated_runtime_elf_projection_with_entries(
            temp.path(),
            "physical-startup-zero-entry-runtime",
            &runtime_elf,
            &entries,
        )?;
        let abandonment = retained
            .materialize_private()?
            .test_only_authenticate_startup_dependency_closure_and_cleanup(
                &StartupClosureTestExpectationV1 {
                    image_path: "/runtime/bin/java",
                    additional_independent_image_paths: &[],
                    mount_targets: &[],
                    expected_canonical_node_order: Some(&[
                        "/runtime/bin/java",
                        "/lib64/ld-linux-x86-64.so.2",
                    ]),
                    expected_edges: None,
                    expected_aggregate_distinct_object_bytes: None,
                    expected_root_entry_point_is_zero: Some(true),
                },
            )?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn private_startup_dependency_closure_rejects_missing_transitive_dt_needed() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let libc = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libc.so.6",
            &["libm.so.6"],
            None,
        );
        let mut entries = startup_default_directory_entries();
        entries.extend([
            RuntimeRootfsFixtureEntryV1::regular("lib64/ld-linux-x86-64.so.2", 0o555, &interpreter),
            RuntimeRootfsFixtureEntryV1::regular("lib/x86_64-linux-gnu/libc.so.6", 0o444, &libc),
        ]);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-missing-transitive",
            &runtime_elf,
            &entries,
            &[],
            Some("unresolved DT_NEEDED libm.so.6"),
        )
    }

    #[test]
    fn private_startup_dependency_closure_accepts_transitive_dt_needed() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let c_runtime_dso =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "libc.so.6",
                &["libm.so.6"],
                None,
            );
        let math_dso = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libm.so.6",
            &[],
            None,
        );
        let mut entries = startup_default_directory_entries();
        entries.extend([
            RuntimeRootfsFixtureEntryV1::regular("lib64/ld-linux-x86-64.so.2", 0o555, &interpreter),
            RuntimeRootfsFixtureEntryV1::regular(
                "lib/x86_64-linux-gnu/libc.so.6",
                0o444,
                &c_runtime_dso,
            ),
            RuntimeRootfsFixtureEntryV1::regular(
                "usr/lib/x86_64-linux-gnu/libm.so.6",
                0o555,
                &math_dso,
            ),
        ]);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-transitive",
            &runtime_elf,
            &entries,
            &[],
            None,
        )
    }

    #[test]
    fn private_startup_dependency_closure_rejects_duplicate_rootfs_basename() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let libc = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libc.so.6",
            &[],
            None,
        );
        let mut entries = startup_default_directory_entries();
        entries.extend([
            RuntimeRootfsFixtureEntryV1::regular("lib64/ld-linux-x86-64.so.2", 0o555, &interpreter),
            RuntimeRootfsFixtureEntryV1::regular("lib/x86_64-linux-gnu/libc.so.6", 0o444, &libc),
            RuntimeRootfsFixtureEntryV1::symbolic_link(
                "usr/lib/x86_64-linux-gnu/libc.so.6",
                "/lib/x86_64-linux-gnu/libc.so.6",
            ),
        ]);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-duplicate-basename",
            &runtime_elf,
            &entries,
            &[],
            Some("expected one rootfs basename, observed 2"),
        )
    }

    #[test]
    fn private_startup_dependency_closure_accepts_origin_runpath() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_runtime_elf_bytes(
                &["libc.so.6"],
                Some("$ORIGIN/../lib"),
            );
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let libc = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libc.so.6",
            &[],
            None,
        );
        let mut entries = startup_default_directory_entries();
        entries.extend([
            RuntimeRootfsFixtureEntryV1::directory("runtime/lib"),
            RuntimeRootfsFixtureEntryV1::regular("runtime/lib/libc.so.6", 0o444, &libc),
            RuntimeRootfsFixtureEntryV1::regular("lib64/ld-linux-x86-64.so.2", 0o555, &interpreter),
        ]);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-origin-runpath",
            &runtime_elf,
            &entries,
            &[],
            None,
        )
    }

    #[test]
    fn private_startup_dependency_closure_rejects_mode_0444_interpreter() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(0);
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let mut entries = startup_default_directory_entries();
        entries.push(RuntimeRootfsFixtureEntryV1::regular(
            "lib64/ld-linux-x86-64.so.2",
            0o444,
            &interpreter,
        ));
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-interpreter-mode",
            &runtime_elf,
            &entries,
            &[],
            Some("regular mode differs from its bound use"),
        )
    }

    #[test]
    fn private_startup_dependency_closure_accepts_entry_zero_nonexecuting_dso() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let mut libc = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libc.so.6",
            &[],
            None,
        );
        libc[24..32].copy_from_slice(&0_u64.to_le_bytes());
        libc[68..72].copy_from_slice(&4_u32.to_le_bytes());
        let mut entries = startup_default_directory_entries();
        entries.extend([
            RuntimeRootfsFixtureEntryV1::regular("lib64/ld-linux-x86-64.so.2", 0o555, &interpreter),
            RuntimeRootfsFixtureEntryV1::regular("lib/x86_64-linux-gnu/libc.so.6", 0o444, &libc),
        ]);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-entry-zero-dso",
            &runtime_elf,
            &entries,
            &[],
            None,
        )
    }

    #[test]
    fn private_startup_dependency_closure_rejects_origin_on_symlinked_dso_without_children()
    -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let libc = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libc.so.6",
            &[],
            Some("$ORIGIN"),
        );
        let mut entries = startup_default_directory_entries();
        entries.extend([
            RuntimeRootfsFixtureEntryV1::regular("lib64/ld-linux-x86-64.so.2", 0o555, &interpreter),
            RuntimeRootfsFixtureEntryV1::symbolic_link(
                "lib/x86_64-linux-gnu/libc.so.6",
                "/real/payload",
            ),
            RuntimeRootfsFixtureEntryV1::directory("real"),
            RuntimeRootfsFixtureEntryV1::regular("real/payload", 0o444, &libc),
        ]);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-symlink-origin",
            &runtime_elf,
            &entries,
            &[],
            Some("reached through a symbolic link cannot use ORIGIN"),
        )
    }

    #[test]
    fn private_startup_dependency_closure_rejects_loader_cache_through_parent_alias() -> Result<()>
    {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(0);
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let mut entries = startup_default_directory_entries();
        entries.extend([
            RuntimeRootfsFixtureEntryV1::regular("lib64/ld-linux-x86-64.so.2", 0o555, &interpreter),
            RuntimeRootfsFixtureEntryV1::symbolic_link("etc", "/loader-state"),
            RuntimeRootfsFixtureEntryV1::directory("loader-state"),
            RuntimeRootfsFixtureEntryV1::regular("loader-state/ld.so.cache", 0o444, b"cache"),
        ]);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-cache-alias",
            &runtime_elf,
            &entries,
            &[],
            Some("forbidden loader path /etc/ld.so.cache"),
        )
    }

    #[test]
    fn private_startup_dependency_closure_rejects_non_directory_loader_lookup_component()
    -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(0);
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let mut entries = startup_default_directory_entries();
        entries.extend([
            RuntimeRootfsFixtureEntryV1::regular("lib64/ld-linux-x86-64.so.2", 0o555, &interpreter),
            RuntimeRootfsFixtureEntryV1::regular("etc", 0o444, b"not-a-directory"),
        ]);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-loader-enotdir",
            &runtime_elf,
            &entries,
            &[],
            Some("blocked by a present non-directory component"),
        )
    }

    #[test]
    fn private_startup_dependency_antichain_checks_every_walked_symlink_target_component()
    -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_runtime_elf_bytes(
                &["libc.so.6"],
                Some("/alias"),
            );
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let libc = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libc.so.6",
            &[],
            None,
        );
        let mut entries = startup_default_directory_entries();
        entries.extend([
            RuntimeRootfsFixtureEntryV1::regular("lib64/ld-linux-x86-64.so.2", 0o555, &interpreter),
            RuntimeRootfsFixtureEntryV1::symbolic_link("alias", "/mnt/../safe"),
            RuntimeRootfsFixtureEntryV1::directory("mnt"),
            RuntimeRootfsFixtureEntryV1::directory("safe"),
            RuntimeRootfsFixtureEntryV1::regular("safe/libc.so.6", 0o444, &libc),
        ]);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-walked-antichain",
            &runtime_elf,
            &entries,
            &["/mnt"],
            Some("overlaps runtime mount target /mnt"),
        )
    }

    #[test]
    fn private_startup_dependency_antichain_checks_normalized_root_symlink_target() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(0);
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let entries = [
            RuntimeRootfsFixtureEntryV1::symbolic_link("lib64", "/mnt/.."),
            RuntimeRootfsFixtureEntryV1::directory("mnt"),
            RuntimeRootfsFixtureEntryV1::directory("unrelated"),
            RuntimeRootfsFixtureEntryV1::regular("ld-linux-x86-64.so.2", 0o555, &interpreter),
        ];
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-root-normalized-antichain",
            &runtime_elf,
            &entries,
            &["/unrelated"],
            Some("overlaps runtime mount target /unrelated"),
        )
    }

    #[test]
    fn private_startup_dependency_antichain_accepts_sibling_mount_outside_walk() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(0);
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let mut entries = startup_base_entries(&interpreter, 0o555);
        entries.push(RuntimeRootfsFixtureEntryV1::directory("runtime/other"));
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-sibling-mount",
            &runtime_elf,
            &entries,
            &["/runtime/other"],
            None,
        )
    }

    #[test]
    fn private_startup_dependency_closure_rejects_origin_normalized_to_root() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_runtime_elf_bytes(
                &[],
                Some("$ORIGIN/../.."),
            );
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let mut entries = startup_default_directory_entries();
        entries.push(RuntimeRootfsFixtureEntryV1::regular(
            "lib64/ld-linux-x86-64.so.2",
            0o555,
            &interpreter,
        ));
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-origin-root",
            &runtime_elf,
            &entries,
            &[],
            Some("normalizes to the unsealed implicit root directory"),
        )
    }

    #[test]
    fn private_startup_dependency_closure_rejects_origin_escape_above_root() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_runtime_elf_bytes(
                &[],
                Some("$ORIGIN/../../.."),
            );
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let entries = startup_base_entries(&interpreter, 0o555);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-origin-escape",
            &runtime_elf,
            &entries,
            &[],
            Some("steps above the root"),
        )
    }

    #[test]
    fn private_startup_dependency_closure_requires_every_default_search_directory() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let libc = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libc.so.6",
            &[],
            None,
        );
        let mut entries = startup_base_entries(&interpreter, 0o555);
        entries.retain(|entry| entry.path != "usr/lib64");
        entries.push(RuntimeRootfsFixtureEntryV1::regular(
            "lib/x86_64-linux-gnu/libc.so.6",
            0o444,
            &libc,
        ));
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-missing-default-directory",
            &runtime_elf,
            &entries,
            &[],
            Some("authenticated rootfs path is dangling: usr/lib64"),
        )
    }

    #[test]
    fn private_startup_dependency_closure_requires_every_runpath_directory() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_runtime_elf_bytes(
                &["libc.so.6"],
                Some("/absent"),
            );
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let libc = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libc.so.6",
            &[],
            None,
        );
        let mut entries = startup_base_entries(&interpreter, 0o555);
        entries.push(RuntimeRootfsFixtureEntryV1::regular(
            "lib/x86_64-linux-gnu/libc.so.6",
            0o444,
            &libc,
        ));
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-missing-runpath-directory",
            &runtime_elf,
            &entries,
            &[],
            Some("authenticated rootfs path is dangling: absent"),
        )
    }

    #[test]
    fn private_startup_dependency_closure_rejects_unique_candidate_outside_search_dirs()
    -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let libc = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libc.so.6",
            &[],
            None,
        );
        let mut entries = startup_base_entries(&interpreter, 0o555);
        entries.extend([
            RuntimeRootfsFixtureEntryV1::directory("outside"),
            RuntimeRootfsFixtureEntryV1::regular("outside/libc.so.6", 0o444, &libc),
        ]);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-candidate-outside-search",
            &runtime_elf,
            &entries,
            &[],
            Some("unique basename is outside the closed search directories"),
        )
    }

    #[test]
    fn private_startup_dependency_closure_rejects_selected_dso_soname_mismatch() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let wrong = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libwrong.so.1",
            &[],
            None,
        );
        let mut entries = startup_base_entries(&interpreter, 0o555);
        entries.push(RuntimeRootfsFixtureEntryV1::regular(
            "lib/x86_64-linux-gnu/libc.so.6",
            0o444,
            &wrong,
        ));
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-soname-mismatch",
            &runtime_elf,
            &entries,
            &[],
            Some("SONAME differs from its requested basename"),
        )
    }

    #[test]
    fn private_startup_dependency_closure_does_not_reuse_a_physical_path_alias() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_runtime_elf_bytes(
                &["liba.so.1", "libb.so.1"],
                None,
            );
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let liba = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "liba.so.1",
            &[],
            None,
        );
        let mut entries = startup_base_entries(&interpreter, 0o555);
        entries.extend([
            RuntimeRootfsFixtureEntryV1::directory("payload"),
            RuntimeRootfsFixtureEntryV1::symbolic_link(
                "lib/x86_64-linux-gnu/liba.so.1",
                "/payload/object",
            ),
            RuntimeRootfsFixtureEntryV1::symbolic_link(
                "usr/lib/x86_64-linux-gnu/libb.so.1",
                "/payload/object",
            ),
            RuntimeRootfsFixtureEntryV1::regular("payload/object", 0o444, &liba),
        ]);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-no-physical-alias-reuse",
            &runtime_elf,
            &entries,
            &[],
            Some("SONAME differs from its requested basename"),
        )
    }

    #[test]
    fn private_startup_dependency_closure_uses_first_default_directory_alias() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let libc = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libc.so.6",
            &[],
            None,
        );
        let mut entries = startup_base_entries(&interpreter, 0o555);
        entries.retain(|entry| {
            !matches!(
                entry.path.as_str(),
                "lib/x86_64-linux-gnu" | "usr/lib/x86_64-linux-gnu"
            )
        });
        entries.extend([
            RuntimeRootfsFixtureEntryV1::symbolic_link("lib/x86_64-linux-gnu", "/custom"),
            RuntimeRootfsFixtureEntryV1::symbolic_link("usr/lib/x86_64-linux-gnu", "/custom"),
            RuntimeRootfsFixtureEntryV1::directory("custom"),
            RuntimeRootfsFixtureEntryV1::regular("custom/libc.so.6", 0o444, &libc),
        ]);
        exercise_private_startup_dependency_fixture_with_expected_order(
            temp.path(),
            "physical-startup-default-order",
            &runtime_elf,
            &entries,
            &PrivateStartupDependencyFixtureExpectationV1 {
                mount_targets: &[],
                expected_canonical_node_order: Some(&[
                    "/runtime/bin/java",
                    "/lib64/ld-linux-x86-64.so.2",
                    "/lib/x86_64-linux-gnu/libc.so.6",
                ]),
                expected_edges: Some(&[(0, 2, "libc.so.6", "rootfs-search", 2, 1)]),
                expected_aggregate_distinct_object_bytes: None,
                expected_error_fragment: None,
            },
        )
    }

    #[test]
    fn private_startup_dependency_closure_reaches_last_default_directory() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_runtime_elf_bytes(
                &["liblast-default.so"],
                None,
            );
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let dependency =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "liblast-default.so",
                &[],
                None,
            );
        let mut entries = startup_base_entries(&interpreter, 0o555);
        entries.push(RuntimeRootfsFixtureEntryV1::regular(
            "usr/lib/liblast-default.so",
            0o444,
            &dependency,
        ));
        exercise_private_startup_dependency_fixture_with_expected_order(
            temp.path(),
            "physical-startup-last-default-directory",
            &runtime_elf,
            &entries,
            &PrivateStartupDependencyFixtureExpectationV1 {
                mount_targets: &[],
                expected_canonical_node_order: Some(&[
                    "/runtime/bin/java",
                    "/lib64/ld-linux-x86-64.so.2",
                    "/usr/lib/liblast-default.so",
                ]),
                expected_edges: Some(&[(0, 2, "liblast-default.so", "rootfs-search", 2, 1)]),
                expected_aggregate_distinct_object_bytes: None,
                expected_error_fragment: None,
            },
        )
    }

    #[test]
    fn private_startup_dependency_closure_accepts_search_directory_alias() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_runtime_elf_bytes(
                &["libc.so.6"],
                Some("/alias1:/alias2"),
            );
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let libc = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libc.so.6",
            &[],
            None,
        );
        let mut entries = startup_base_entries(&interpreter, 0o555);
        entries.extend([
            RuntimeRootfsFixtureEntryV1::symbolic_link("alias1", "/custom"),
            RuntimeRootfsFixtureEntryV1::symbolic_link("alias2", "/custom"),
            RuntimeRootfsFixtureEntryV1::directory("custom"),
            RuntimeRootfsFixtureEntryV1::regular("custom/libc.so.6", 0o444, &libc),
        ]);
        exercise_private_startup_dependency_fixture_with_expected_order(
            temp.path(),
            "physical-startup-search-alias",
            &runtime_elf,
            &entries,
            &PrivateStartupDependencyFixtureExpectationV1 {
                mount_targets: &[],
                expected_canonical_node_order: Some(&[
                    "/runtime/bin/java",
                    "/lib64/ld-linux-x86-64.so.2",
                    "/alias1/libc.so.6",
                ]),
                expected_edges: Some(&[(0, 2, "libc.so.6", "rootfs-search", 2, 1)]),
                expected_aggregate_distinct_object_bytes: None,
                expected_error_fragment: None,
            },
        )
    }

    #[test]
    fn private_startup_dependency_closure_accepts_search_directory_alias_trailing_dot() -> Result<()>
    {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_runtime_elf_bytes(
                &["libc.so.6"],
                Some("/alias"),
            );
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let libc = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libc.so.6",
            &[],
            None,
        );
        let mut entries = startup_base_entries(&interpreter, 0o555);
        entries.extend([
            RuntimeRootfsFixtureEntryV1::symbolic_link("alias", "/custom/."),
            RuntimeRootfsFixtureEntryV1::directory("custom"),
            RuntimeRootfsFixtureEntryV1::regular("custom/libc.so.6", 0o444, &libc),
        ]);
        exercise_private_startup_dependency_fixture_with_expected_order(
            temp.path(),
            "physical-startup-search-alias-trailing-dot",
            &runtime_elf,
            &entries,
            &PrivateStartupDependencyFixtureExpectationV1 {
                mount_targets: &[],
                expected_canonical_node_order: Some(&[
                    "/runtime/bin/java",
                    "/lib64/ld-linux-x86-64.so.2",
                    "/alias/libc.so.6",
                ]),
                expected_edges: Some(&[(0, 2, "libc.so.6", "rootfs-search", 2, 1)]),
                expected_aggregate_distinct_object_bytes: None,
                expected_error_fragment: None,
            },
        )
    }

    #[test]
    fn private_startup_dependency_closure_accepts_search_directory_alias_trailing_parent()
    -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_runtime_elf_bytes(
                &["libc.so.6"],
                Some("/alias"),
            );
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let libc = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libc.so.6",
            &[],
            None,
        );
        let mut entries = startup_base_entries(&interpreter, 0o555);
        entries.extend([
            RuntimeRootfsFixtureEntryV1::symbolic_link("alias", "/custom/sub/.."),
            RuntimeRootfsFixtureEntryV1::directory("custom"),
            RuntimeRootfsFixtureEntryV1::directory("custom/sub"),
            RuntimeRootfsFixtureEntryV1::regular("custom/libc.so.6", 0o444, &libc),
        ]);
        exercise_private_startup_dependency_fixture_with_expected_order(
            temp.path(),
            "physical-startup-search-alias-trailing-parent",
            &runtime_elf,
            &entries,
            &PrivateStartupDependencyFixtureExpectationV1 {
                mount_targets: &[],
                expected_canonical_node_order: Some(&[
                    "/runtime/bin/java",
                    "/lib64/ld-linux-x86-64.so.2",
                    "/alias/libc.so.6",
                ]),
                expected_edges: Some(&[(0, 2, "libc.so.6", "rootfs-search", 2, 1)]),
                expected_aggregate_distinct_object_bytes: None,
                expected_error_fragment: None,
            },
        )
    }

    #[test]
    fn private_startup_dependency_closure_accepts_exactly_40_cumulative_search_hops() -> Result<()>
    {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_runtime_elf_bytes(
                &["libc.so.6"],
                Some("/alias"),
            );
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let libc = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libc.so.6",
            &[],
            None,
        );
        let mut entries = startup_base_entries(&interpreter, 0o555);
        entries.extend(startup_search_directory_symlink_chain(38, &libc));
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-search-hop-40",
            &runtime_elf,
            &entries,
            &[],
            None,
        )
    }

    #[test]
    fn private_startup_dependency_closure_rejects_cumulative_search_hop_41() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_runtime_elf_bytes(
                &["libc.so.6"],
                Some("/alias"),
            );
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let libc = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libc.so.6",
            &[],
            None,
        );
        let mut entries = startup_base_entries(&interpreter, 0o555);
        entries.extend(startup_search_directory_symlink_chain(39, &libc));
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-search-hop-41",
            &runtime_elf,
            &entries,
            &[],
            Some("symbolic-link hop 41"),
        )
    }

    #[test]
    fn private_startup_dependency_antichain_rejects_root_executable_overlap() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(0);
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let entries = startup_base_entries(&interpreter, 0o555);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-root-antichain",
            &runtime_elf,
            &entries,
            &["/runtime"],
            Some("overlaps runtime mount target /runtime"),
        )
    }

    #[test]
    fn private_startup_dependency_antichain_rejects_selected_final_path_overlap() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let libc = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libc.so.6",
            &[],
            None,
        );
        let mut entries = startup_base_entries(&interpreter, 0o555);
        entries.extend([
            RuntimeRootfsFixtureEntryV1::symbolic_link(
                "lib/x86_64-linux-gnu/libc.so.6",
                "/mounted/object",
            ),
            RuntimeRootfsFixtureEntryV1::directory("mounted"),
            RuntimeRootfsFixtureEntryV1::regular("mounted/object", 0o444, &libc),
        ]);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-final-antichain",
            &runtime_elf,
            &entries,
            &["/mounted"],
            Some("overlaps runtime mount target /mounted"),
        )
    }

    #[test]
    fn private_startup_dependency_closure_rejects_direct_loader_cache_and_preload() -> Result<()> {
        for (suffix, forbidden_path) in [
            ("cache", "etc/ld.so.cache"),
            ("preload", "etc/ld.so.preload"),
        ] {
            let temp = tempfile::tempdir()?;
            let runtime_elf =
                crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(0);
            let interpreter =
                crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                    "ld-linux-x86-64.so.2",
                    &[],
                    None,
                );
            let mut entries = startup_base_entries(&interpreter, 0o555);
            entries.extend([
                RuntimeRootfsFixtureEntryV1::directory("etc"),
                RuntimeRootfsFixtureEntryV1::regular(forbidden_path, 0o444, b"forbidden"),
            ]);
            exercise_private_startup_dependency_fixture(
                temp.path(),
                &format!("physical-startup-direct-{suffix}"),
                &runtime_elf,
                &entries,
                &[],
                Some("startup rootfs contains forbidden loader path"),
            )?;
        }
        Ok(())
    }

    #[test]
    fn private_startup_dependency_closure_rejects_glibc_hwcaps_of_any_type() -> Result<()> {
        for (suffix, forbidden) in [
            (
                "directory",
                RuntimeRootfsFixtureEntryV1::directory("usr/glibc-hwcaps"),
            ),
            (
                "regular",
                RuntimeRootfsFixtureEntryV1::regular(
                    "usr/glibc-hwcaps",
                    0o444,
                    b"not-even-a-directory",
                ),
            ),
            (
                "symlink",
                RuntimeRootfsFixtureEntryV1::symbolic_link("usr/glibc-hwcaps", "/missing"),
            ),
        ] {
            let temp = tempfile::tempdir()?;
            let runtime_elf =
                crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(0);
            let interpreter =
                crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                    "ld-linux-x86-64.so.2",
                    &[],
                    None,
                );
            let mut entries = startup_base_entries(&interpreter, 0o555);
            entries.push(forbidden);
            exercise_private_startup_dependency_fixture(
                temp.path(),
                &format!("physical-startup-glibc-hwcaps-{suffix}"),
                &runtime_elf,
                &entries,
                &[],
                Some("forbidden glibc-hwcaps basename"),
            )?;
        }
        Ok(())
    }

    #[test]
    fn private_startup_dependency_closure_reuses_loaded_soname_without_recursion() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let libc = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libc.so.6",
            &["libc.so.6"],
            None,
        );
        let mut entries = startup_base_entries(&interpreter, 0o555);
        entries.push(RuntimeRootfsFixtureEntryV1::regular(
            "lib/x86_64-linux-gnu/libc.so.6",
            0o444,
            &libc,
        ));
        exercise_private_startup_dependency_fixture_with_expected_order(
            temp.path(),
            "physical-startup-soname-cycle",
            &runtime_elf,
            &entries,
            &PrivateStartupDependencyFixtureExpectationV1 {
                mount_targets: &[],
                expected_canonical_node_order: Some(&[
                    "/runtime/bin/java",
                    "/lib64/ld-linux-x86-64.so.2",
                    "/lib/x86_64-linux-gnu/libc.so.6",
                ]),
                expected_edges: Some(&[
                    (0, 2, "libc.so.6", "rootfs-search", 2, 1),
                    (2, 3, "libc.so.6", "loaded-soname", 2, 1),
                ]),
                expected_aggregate_distinct_object_bytes: None,
                expected_error_fragment: None,
            },
        )
    }

    #[test]
    fn private_startup_dependency_closure_seeds_loaded_soname_with_interpreter() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_runtime_elf_bytes(
                &["ld-linux-x86-64.so.2"],
                None,
            );
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let mut entries = startup_base_entries(&interpreter, 0o555);
        entries.retain(|entry| entry.path != "usr/lib64");
        exercise_private_startup_dependency_fixture_with_expected_order(
            temp.path(),
            "physical-startup-interpreter-reuse",
            &runtime_elf,
            &entries,
            &PrivateStartupDependencyFixtureExpectationV1 {
                mount_targets: &[],
                expected_canonical_node_order: Some(&[
                    "/runtime/bin/java",
                    "/lib64/ld-linux-x86-64.so.2",
                ]),
                expected_edges: Some(&[(0, 2, "ld-linux-x86-64.so.2", "loaded-soname", 1, 0)]),
                expected_aggregate_distinct_object_bytes: None,
                expected_error_fragment: None,
            },
        )
    }

    #[test]
    fn private_startup_dependency_closure_retains_fifo_first_discovery_order() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_runtime_elf_bytes(
                &["liba.so.1", "libb.so.1"],
                None,
            );
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &["libinterp.so.1"],
                None,
            );
        let first_branch_dso =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "liba.so.1",
                &["libcdep.so.1"],
                None,
            );
        let second_branch_dso =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "libb.so.1",
                &[],
                None,
            );
        let child_dependency_dso =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "libcdep.so.1",
                &[],
                None,
            );
        let interpreter_dependency_dso =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "libinterp.so.1",
                &[],
                None,
            );
        let mut entries = startup_base_entries(&interpreter, 0o555);
        entries.extend([
            RuntimeRootfsFixtureEntryV1::regular(
                "lib/x86_64-linux-gnu/liba.so.1",
                0o444,
                &first_branch_dso,
            ),
            RuntimeRootfsFixtureEntryV1::regular(
                "usr/lib/x86_64-linux-gnu/libb.so.1",
                0o444,
                &second_branch_dso,
            ),
            RuntimeRootfsFixtureEntryV1::regular(
                "usr/lib64/libcdep.so.1",
                0o444,
                &child_dependency_dso,
            ),
            RuntimeRootfsFixtureEntryV1::regular(
                "lib/libinterp.so.1",
                0o444,
                &interpreter_dependency_dso,
            ),
        ]);
        exercise_private_startup_dependency_fixture_with_expected_order(
            temp.path(),
            "physical-startup-fifo",
            &runtime_elf,
            &entries,
            &PrivateStartupDependencyFixtureExpectationV1 {
                mount_targets: &[],
                expected_canonical_node_order: Some(&[
                    "/runtime/bin/java",
                    "/lib64/ld-linux-x86-64.so.2",
                    "/lib/x86_64-linux-gnu/liba.so.1",
                    "/usr/lib/x86_64-linux-gnu/libb.so.1",
                    "/lib/libinterp.so.1",
                    "/usr/lib64/libcdep.so.1",
                ]),
                expected_edges: Some(&[
                    (0, 2, "liba.so.1", "rootfs-search", 2, 1),
                    (0, 3, "libb.so.1", "rootfs-search", 3, 1),
                    (1, 3, "libinterp.so.1", "rootfs-search", 4, 1),
                    (2, 3, "libcdep.so.1", "rootfs-search", 5, 2),
                ]),
                expected_aggregate_distinct_object_bytes: None,
                expected_error_fragment: None,
            },
        )
    }

    #[test]
    fn private_startup_dependency_closure_keeps_java_and_javac_soname_tables_independent()
    -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let java =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_runtime_elf_bytes(
                &["libprivate.so.1"],
                Some("/private"),
            );
        let javac =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_runtime_elf_bytes(
                &["libprivate.so.1"],
                None,
            );
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let private = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libprivate.so.1",
            &[],
            None,
        );
        let mut entries = startup_base_entries(&interpreter, 0o555);
        entries.extend([
            RuntimeRootfsFixtureEntryV1::regular("runtime/bin/javac", 0o555, &javac),
            RuntimeRootfsFixtureEntryV1::directory("private"),
            RuntimeRootfsFixtureEntryV1::regular("private/libprivate.so.1", 0o444, &private),
        ]);
        let (final_path, retained) = authenticated_runtime_elf_projection_with_entries(
            temp.path(),
            "physical-startup-java-javac-isolation",
            &java,
            &entries,
        )?;
        let error = retained
            .materialize_private()?
            .test_only_authenticate_startup_dependency_closure_and_cleanup(
                &StartupClosureTestExpectationV1 {
                    image_path: "/runtime/bin/java",
                    additional_independent_image_paths: &["/runtime/bin/javac"],
                    mount_targets: &[],
                    expected_canonical_node_order: None,
                    expected_edges: None,
                    expected_aggregate_distinct_object_bytes: None,
                    expected_root_entry_point_is_zero: None,
                },
            )
            .unwrap_err();
        assert!(
            format!("{error:#}")
                .contains("unique basename is outside the closed search directories"),
            "{error:#}"
        );
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn private_startup_dependency_closure_accepts_two_node_soname_cycle() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_runtime_elf_bytes(
                &["liba.so.1"],
                Some("/private-cycle"),
            );
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let cycle_entry_dso =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "liba.so.1",
                &["libb.so.1"],
                None,
            );
        let cycle_peer_dso =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "libb.so.1",
                &["liba.so.1"],
                None,
            );
        let mut entries = startup_base_entries(&interpreter, 0o555);
        entries.extend([
            RuntimeRootfsFixtureEntryV1::directory("private-cycle"),
            RuntimeRootfsFixtureEntryV1::regular(
                "private-cycle/liba.so.1",
                0o444,
                &cycle_entry_dso,
            ),
            RuntimeRootfsFixtureEntryV1::regular(
                "usr/lib/x86_64-linux-gnu/libb.so.1",
                0o444,
                &cycle_peer_dso,
            ),
        ]);
        exercise_private_startup_dependency_fixture_with_expected_order(
            temp.path(),
            "physical-startup-two-node-cycle",
            &runtime_elf,
            &entries,
            &PrivateStartupDependencyFixtureExpectationV1 {
                mount_targets: &[],
                expected_canonical_node_order: Some(&[
                    "/runtime/bin/java",
                    "/lib64/ld-linux-x86-64.so.2",
                    "/private-cycle/liba.so.1",
                    "/usr/lib/x86_64-linux-gnu/libb.so.1",
                ]),
                expected_edges: Some(&[
                    (0, 2, "liba.so.1", "rootfs-search", 2, 1),
                    (2, 3, "libb.so.1", "rootfs-search", 3, 2),
                    (3, 3, "liba.so.1", "loaded-soname", 2, 1),
                ]),
                expected_aggregate_distinct_object_bytes: None,
                expected_error_fragment: None,
            },
        )
    }

    #[test]
    fn private_startup_dependency_closure_applies_each_childs_own_runpath() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_runtime_elf_bytes(
                &["liba.so.1"],
                None,
            );
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let liba = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "liba.so.1",
            &["libprivate.so.1"],
            Some("/private"),
        );
        let private = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libprivate.so.1",
            &[],
            None,
        );
        let mut entries = startup_base_entries(&interpreter, 0o555);
        entries.extend([
            RuntimeRootfsFixtureEntryV1::regular("lib/x86_64-linux-gnu/liba.so.1", 0o444, &liba),
            RuntimeRootfsFixtureEntryV1::directory("private"),
            RuntimeRootfsFixtureEntryV1::regular("private/libprivate.so.1", 0o444, &private),
        ]);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-child-runpath",
            &runtime_elf,
            &entries,
            &[],
            None,
        )
    }

    #[test]
    fn private_startup_dependency_closure_does_not_inherit_parent_runpath() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_runtime_elf_bytes(
                &["liba.so.1"],
                Some("/private-parent"),
            );
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let liba = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "liba.so.1",
            &["libchild.so.1"],
            None,
        );
        let child = crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
            "libchild.so.1",
            &[],
            None,
        );
        let mut entries = startup_base_entries(&interpreter, 0o555);
        entries.extend([
            RuntimeRootfsFixtureEntryV1::directory("private-parent"),
            RuntimeRootfsFixtureEntryV1::regular("private-parent/liba.so.1", 0o444, &liba),
            RuntimeRootfsFixtureEntryV1::regular("private-parent/libchild.so.1", 0o444, &child),
        ]);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-no-parent-runpath-inheritance",
            &runtime_elf,
            &entries,
            &[],
            Some("unique basename is outside the closed search directories"),
        )
    }

    #[test]
    fn private_startup_dependency_closure_rejects_non_dso_selected_objects() -> Result<()> {
        let mut not_elf = vec![0_u8; 64];
        not_elf[..7].copy_from_slice(b"NOT-ELF");
        for (suffix, payload, expected) in [
            ("not-elf", not_elf, "AMD64 ELF magic is invalid"),
            (
                "runtime-elf",
                crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(0),
                "startup DSO must omit PT_INTERP and contain exactly one PT_DYNAMIC",
            ),
        ] {
            let temp = tempfile::tempdir()?;
            let runtime_elf =
                crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
            let interpreter =
                crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                    "ld-linux-x86-64.so.2",
                    &[],
                    None,
                );
            let mut entries = startup_base_entries(&interpreter, 0o555);
            entries.push(RuntimeRootfsFixtureEntryV1::regular(
                "lib/x86_64-linux-gnu/libc.so.6",
                0o444,
                &payload,
            ));
            exercise_private_startup_dependency_fixture(
                temp.path(),
                &format!("physical-startup-selected-{suffix}"),
                &runtime_elf,
                &entries,
                &[],
                Some(expected),
            )?;
        }
        Ok(())
    }

    #[test]
    fn private_startup_dependency_antichain_rejects_interpreter_overlap() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(0);
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let entries = startup_base_entries(&interpreter, 0o555);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-interpreter-antichain",
            &runtime_elf,
            &entries,
            &["/lib64"],
            Some("startup interpreter path /lib64 overlaps runtime mount target /lib64"),
        )
    }

    #[test]
    fn private_startup_dependency_closure_rejects_dangling_loader_leaf_symlinks() -> Result<()> {
        for forbidden_leaf in ["etc/ld.so.cache", "etc/ld.so.preload"] {
            let temp = tempfile::tempdir()?;
            let runtime_elf =
                crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(0);
            let interpreter =
                crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                    "ld-linux-x86-64.so.2",
                    &[],
                    None,
                );
            let mut entries = startup_base_entries(&interpreter, 0o555);
            entries.extend([
                RuntimeRootfsFixtureEntryV1::directory("etc"),
                RuntimeRootfsFixtureEntryV1::symbolic_link(forbidden_leaf, "/missing"),
            ]);
            exercise_private_startup_dependency_fixture(
                temp.path(),
                "physical-startup-dangling-loader-leaf",
                &runtime_elf,
                &entries,
                &[],
                Some("startup rootfs contains forbidden loader path"),
            )?;
        }
        Ok(())
    }

    #[test]
    fn private_startup_dependency_closure_accepts_exact_depth_64() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let (runtime_elf, entries) = startup_linear_dependency_fixture(64, &interpreter);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-depth-64",
            &runtime_elf,
            &entries,
            &[],
            None,
        )
    }

    #[test]
    fn private_startup_dependency_closure_rejects_depth_65() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let (runtime_elf, entries) = startup_linear_dependency_fixture(65, &interpreter);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-depth-65",
            &runtime_elf,
            &entries,
            &[],
            Some("exceeds its role-specific startup dependency depth budget"),
        )
    }

    #[test]
    fn private_startup_dependency_closure_accepts_exactly_512_objects() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let (runtime_elf, entries) = startup_wide_loaded_graph_fixture(510, 510, &interpreter);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-objects-512",
            &runtime_elf,
            &entries,
            &[],
            None,
        )
    }

    #[test]
    fn private_startup_dependency_closure_rejects_object_513() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let (runtime_elf, entries) = startup_wide_loaded_graph_fixture(511, 511, &interpreter);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-object-513",
            &runtime_elf,
            &entries,
            &[],
            Some("exceeds its role-specific distinct startup object budget"),
        )
    }

    #[test]
    fn private_startup_dependency_closure_accepts_exactly_4096_edges() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let (runtime_elf, entries) = startup_wide_loaded_graph_fixture(510, 4_096, &interpreter);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-edges-4096",
            &runtime_elf,
            &entries,
            &[],
            None,
        )
    }

    #[test]
    fn private_startup_dependency_closure_rejects_edge_4097() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let interpreter =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::startup_dso_bytes(
                "ld-linux-x86-64.so.2",
                &[],
                None,
            );
        let (runtime_elf, entries) = startup_wide_loaded_graph_fixture(510, 4_097, &interpreter);
        exercise_private_startup_dependency_fixture(
            temp.path(),
            "physical-startup-edge-4097",
            &runtime_elf,
            &entries,
            &[],
            Some("exceeds its role-specific startup dependency edge budget"),
        )
    }

    #[test]
    fn private_runtime_elf_accepts_an_absolute_pt_interp_symlink_inside_the_same_rootfs()
    -> Result<()> {
        let temp = tempfile::tempdir()?;
        exercise_private_runtime_elf_fixture(
            temp.path(),
            "physical-runtime-absolute-interpreter",
            &[
                RuntimeRootfsFixtureEntryV1::directory("lib64"),
                RuntimeRootfsFixtureEntryV1::symbolic_link(
                    "lib64/ld-linux-x86-64.so.2",
                    "/loader/ld.so",
                ),
                RuntimeRootfsFixtureEntryV1::directory("loader"),
                RuntimeRootfsFixtureEntryV1::regular("loader/ld.so", 0o555, b"LOADER"),
            ],
            None,
        )
    }

    #[test]
    fn private_runtime_elf_accepts_a_relative_pt_interp_symlink_from_its_parent() -> Result<()> {
        let temp = tempfile::tempdir()?;
        exercise_private_runtime_elf_fixture(
            temp.path(),
            "physical-runtime-relative-interpreter",
            &[
                RuntimeRootfsFixtureEntryV1::directory("lib64"),
                RuntimeRootfsFixtureEntryV1::symbolic_link(
                    "lib64/ld-linux-x86-64.so.2",
                    "../loader/ld.so",
                ),
                RuntimeRootfsFixtureEntryV1::directory("loader"),
                RuntimeRootfsFixtureEntryV1::regular("loader/ld.so", 0o555, b"LOADER"),
            ],
            None,
        )
    }

    #[test]
    fn private_runtime_elf_rejects_a_repeated_symlink_path_cycle() -> Result<()> {
        let temp = tempfile::tempdir()?;
        exercise_private_runtime_elf_fixture(
            temp.path(),
            "physical-runtime-interpreter-cycle",
            &[
                RuntimeRootfsFixtureEntryV1::directory("lib64"),
                RuntimeRootfsFixtureEntryV1::symbolic_link(
                    "lib64/ld-linux-x86-64.so.2",
                    "/loader/ld.so",
                ),
                RuntimeRootfsFixtureEntryV1::directory("loader"),
                RuntimeRootfsFixtureEntryV1::symbolic_link(
                    "loader/ld.so",
                    "/lib64/ld-linux-x86-64.so.2",
                ),
            ],
            Some("repeats a normalized path"),
        )
    }

    #[test]
    fn private_runtime_elf_rejects_symbolic_link_hop_41() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let entries = pt_interp_symlink_chain(41);
        exercise_private_runtime_elf_fixture(
            temp.path(),
            "physical-runtime-interpreter-hop-41",
            &entries,
            Some("symbolic-link hop 41"),
        )
    }

    #[test]
    fn private_runtime_elf_accepts_exactly_40_symbolic_link_hops() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let entries = pt_interp_symlink_chain(40);
        exercise_private_runtime_elf_fixture(
            temp.path(),
            "physical-runtime-interpreter-hop-40",
            &entries,
            None,
        )
    }

    #[test]
    fn private_runtime_elf_rejects_a_nonregular_pt_interp_target() -> Result<()> {
        let temp = tempfile::tempdir()?;
        exercise_private_runtime_elf_fixture(
            temp.path(),
            "physical-runtime-nonregular-interpreter",
            &[
                RuntimeRootfsFixtureEntryV1::directory("lib64"),
                RuntimeRootfsFixtureEntryV1::directory("lib64/ld-linux-x86-64.so.2"),
            ],
            Some("final target is non-regular"),
        )
    }

    #[test]
    fn private_runtime_elf_rejects_a_pt_interp_without_mode_0555() -> Result<()> {
        let temp = tempfile::tempdir()?;
        exercise_private_runtime_elf_fixture(
            temp.path(),
            "physical-runtime-interpreter-mode",
            &[
                RuntimeRootfsFixtureEntryV1::directory("lib64"),
                RuntimeRootfsFixtureEntryV1::regular(
                    "lib64/ld-linux-x86-64.so.2",
                    0o444,
                    b"LOADER",
                ),
            ],
            Some("regular mode differs from its bound use"),
        )
    }

    #[test]
    fn physical_rootfs_rejects_an_extra_dev_descendant_and_cleans_up() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
        let (final_path, retained) = authenticated_runtime_elf_projection_with_entries(
            temp.path(),
            "physical-extra-dev-descendant",
            &runtime_elf,
            &[
                RuntimeRootfsFixtureEntryV1::directory("dev"),
                RuntimeRootfsFixtureEntryV1::regular("dev/full", 0o444, b""),
                RuntimeRootfsFixtureEntryV1::regular("dev/null", 0o444, b""),
                RuntimeRootfsFixtureEntryV1::regular("dev/random", 0o444, b""),
                RuntimeRootfsFixtureEntryV1::regular("dev/tty", 0o444, b""),
                RuntimeRootfsFixtureEntryV1::regular("dev/urandom", 0o444, b""),
                RuntimeRootfsFixtureEntryV1::regular("dev/zero", 0o444, b""),
            ],
        )?;

        let error = retained
            .materialize_private()?
            .test_only_authenticate_rootfs_paths_and_cleanup(
                PositiveRunnerRole::JvmVerifier,
                &[
                    ("/dev", true),
                    ("/dev/full", false),
                    ("/dev/null", false),
                    ("/dev/random", false),
                    ("/dev/urandom", false),
                    ("/dev/zero", false),
                ],
            )
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("rootfs /dev inventory differs from its positive gate"),
            "{error:#}"
        );
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn physical_rootfs_path_requirements_accept_all_four_canonical_roles() -> Result<()> {
        for (index, role) in [
            PositiveRunnerRole::RustValidatorBuild,
            PositiveRunnerRole::JvmValidatorBuild,
            PositiveRunnerRole::RustVerifier,
            PositiveRunnerRole::JvmVerifier,
        ]
        .into_iter()
        .enumerate()
        {
            let (entries, requirements) = physical_rootfs_path_fixture(role);
            exercise_private_rootfs_path_fixture(
                &format!("canonical-role-{index}"),
                role,
                role,
                &entries,
                &requirements,
                None,
            )?;
        }
        Ok(())
    }

    #[test]
    fn physical_rootfs_path_requirements_reject_missing_type_and_symlink_drifts() -> Result<()> {
        let (baseline, requirements) =
            physical_rootfs_path_fixture(PositiveRunnerRole::JvmVerifier);

        let mut missing_dev = baseline.clone();
        missing_dev.retain(|entry| entry.path != "dev/full");
        exercise_private_rootfs_path_fixture(
            "missing-dev",
            PositiveRunnerRole::JvmVerifier,
            PositiveRunnerRole::JvmVerifier,
            &missing_dev,
            &requirements,
            Some("authenticated rootfs path is dangling: dev/full"),
        )?;

        let mut missing_role_target = baseline.clone();
        missing_role_target.retain(|entry| entry.path != "input");
        exercise_private_rootfs_path_fixture(
            "missing-role-target",
            PositiveRunnerRole::JvmVerifier,
            PositiveRunnerRole::JvmVerifier,
            &missing_role_target,
            &requirements,
            Some("authenticated rootfs path is dangling: input"),
        )?;

        let mut directory_symlink = baseline.clone();
        directory_symlink.retain(|entry| entry.path != "input");
        directory_symlink.push(RuntimeRootfsFixtureEntryV1::symbolic_link("input", "/tmp"));
        exercise_private_rootfs_path_fixture(
            "directory-symlink",
            PositiveRunnerRole::JvmVerifier,
            PositiveRunnerRole::JvmVerifier,
            &directory_symlink,
            &requirements,
            Some("required rootfs path is not a no-follow directory"),
        )?;

        let mut leaf_directory = baseline.clone();
        leaf_directory.retain(|entry| entry.path != "validator/validator.jar");
        leaf_directory.push(RuntimeRootfsFixtureEntryV1::directory(
            "validator/validator.jar",
        ));
        exercise_private_rootfs_path_fixture(
            "leaf-directory",
            PositiveRunnerRole::JvmVerifier,
            PositiveRunnerRole::JvmVerifier,
            &leaf_directory,
            &requirements,
            Some("required rootfs placeholder is not a regular file"),
        )?;

        let mut nonempty_leaf = baseline.clone();
        nonempty_leaf.retain(|entry| entry.path != "validator/validator.jar");
        nonempty_leaf.push(RuntimeRootfsFixtureEntryV1::regular(
            "validator/validator.jar",
            0o444,
            b"payload",
        ));
        exercise_private_rootfs_path_fixture(
            "nonempty-leaf",
            PositiveRunnerRole::JvmVerifier,
            PositiveRunnerRole::JvmVerifier,
            &nonempty_leaf,
            &requirements,
            Some("required rootfs placeholder is not empty"),
        )?;

        let mut parent_symlink = baseline.clone();
        parent_symlink.retain(|entry| {
            !matches!(entry.path.as_str(), "validator" | "validator/validator.jar")
        });
        parent_symlink.push(RuntimeRootfsFixtureEntryV1::symbolic_link(
            "validator",
            "/tmp",
        ));
        exercise_private_rootfs_path_fixture(
            "parent-symlink",
            PositiveRunnerRole::JvmVerifier,
            PositiveRunnerRole::JvmVerifier,
            &parent_symlink,
            &requirements,
            Some("required rootfs path is not a no-follow directory"),
        )
    }

    #[test]
    fn physical_rootfs_path_requirements_reject_inventory_gate_and_role_drifts() -> Result<()> {
        let (baseline, requirements) =
            physical_rootfs_path_fixture(PositiveRunnerRole::JvmVerifier);

        let mut nested_dev = baseline.clone();
        nested_dev.extend([
            RuntimeRootfsFixtureEntryV1::directory("dev/pts"),
            RuntimeRootfsFixtureEntryV1::regular("dev/pts/0", 0o444, b""),
        ]);
        exercise_private_rootfs_path_fixture(
            "nested-dev",
            PositiveRunnerRole::JvmVerifier,
            PositiveRunnerRole::JvmVerifier,
            &nested_dev,
            &requirements,
            Some("rootfs /dev inventory differs from its positive gate"),
        )?;

        let mut incomplete_gate = requirements.clone();
        incomplete_gate.retain(|(path, _)| *path != "/dev/zero");
        exercise_private_rootfs_path_fixture(
            "incomplete-gate-dev",
            PositiveRunnerRole::JvmVerifier,
            PositiveRunnerRole::JvmVerifier,
            &baseline,
            &incomplete_gate,
            Some("positive gate carries an unexpected rootfs /dev inventory"),
        )?;

        let mut unsorted = requirements.clone();
        unsorted.swap(0, 1);
        exercise_private_rootfs_path_fixture(
            "unsorted-gate",
            PositiveRunnerRole::JvmVerifier,
            PositiveRunnerRole::JvmVerifier,
            &baseline,
            &unsorted,
            Some("positive OCI rootfs path requirements are not strictly sorted"),
        )?;

        let mut noncanonical = requirements.clone();
        let input = noncanonical
            .iter_mut()
            .find(|(path, _)| *path == "/input")
            .ok_or_else(|| anyhow::anyhow!("input requirement fixture is absent"))?;
        input.0 = "/input/../tmp";
        exercise_private_rootfs_path_fixture(
            "noncanonical-gate",
            PositiveRunnerRole::JvmVerifier,
            PositiveRunnerRole::JvmVerifier,
            &baseline,
            &noncanonical,
            Some("positive OCI rootfs requirement is not canonical absolute POSIX"),
        )?;

        exercise_private_rootfs_path_fixture(
            "role-mismatch",
            PositiveRunnerRole::JvmVerifier,
            PositiveRunnerRole::RustVerifier,
            &baseline,
            &requirements,
            Some("test rootfs role differs from its expectation"),
        )
    }

    #[test]
    fn physical_java_release_rejects_unsorted_keys_and_cleans_up() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
        let release = b"JAVA_VERSION=\"21.0.1\"\nIMPLEMENTOR=\"Fixture JVM\"\n";
        let release_sha256: [u8; super::SHA256_BYTES] = Sha256::digest(release).into();
        let (final_path, retained) = authenticated_runtime_elf_projection_with_entries(
            temp.path(),
            "physical-unsorted-java-release",
            &runtime_elf,
            &[RuntimeRootfsFixtureEntryV1::regular(
                "runtime/release",
                0o444,
                release,
            )],
        )?;

        let error = retained
            .materialize_private()?
            .test_only_authenticate_java_release_and_cleanup(
                PositiveRunnerRole::JvmVerifier,
                "/runtime/release",
                u64::try_from(release.len())?,
                release_sha256,
                21,
                "Fixture JVM",
                "21.0.1",
            )
            .unwrap_err();
        assert!(
            format!("{error:#}")
                .contains("Java release keys are not unique and strictly ASCII-sorted"),
            "{error:#}"
        );
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn physical_java_release_accepts_closed_encoding_and_rejects_identity_bounds() -> Result<()> {
        fn digest(bytes: &[u8]) -> [u8; super::SHA256_BYTES] {
            Sha256::digest(bytes).into()
        }

        let canonical = b"IMPLEMENTOR=\"Fixture JVM\"\nJAVA_VERSION=\"21.0.1\"\n";
        exercise_private_java_release_fixture(
            canonical,
            u64::try_from(canonical.len())?,
            digest(canonical),
            21,
            "Fixture JVM",
            "21.0.1",
            None,
        )?;
        let escaped = b"IMPLEMENTOR=\"Fixture \\\"JVM\\\"\\\\\"\nJAVA_VERSION=\"21.0.1\"\n";
        exercise_private_java_release_fixture(
            escaped,
            u64::try_from(escaped.len())?,
            digest(escaped),
            21,
            "Fixture \"JVM\"\\",
            "21.0.1",
            None,
        )?;
        exercise_private_java_release_fixture_with_mode(
            0o555,
            canonical,
            u64::try_from(canonical.len())?,
            digest(canonical),
            21,
            "Fixture JVM",
            "21.0.1",
            None,
        )?;
        let unknown_key =
            b"IMPLEMENTOR=\"Fixture JVM\"\nJAVA_VERSION=\"21.0.1\"\nOS_NAME=\"Linux\"\n";
        exercise_private_java_release_fixture(
            unknown_key,
            u64::try_from(unknown_key.len())?,
            digest(unknown_key),
            21,
            "Fixture JVM",
            "21.0.1",
            None,
        )?;

        for expected_length in [0, 65_537] {
            exercise_private_java_release_fixture(
                canonical,
                expected_length,
                digest(canonical),
                21,
                "Fixture JVM",
                "21.0.1",
                Some("Java release length is outside its closed bound"),
            )?;
        }
        exercise_private_java_release_fixture(
            canonical,
            u64::try_from(canonical.len())? + 1,
            digest(canonical),
            21,
            "Fixture JVM",
            "21.0.1",
            Some("Java release length differs from its positive gate"),
        )?;
        let mut wrong_digest = digest(canonical);
        wrong_digest[0] ^= 1;
        exercise_private_java_release_fixture(
            canonical,
            u64::try_from(canonical.len())?,
            wrong_digest,
            21,
            "Fixture JVM",
            "21.0.1",
            Some("Java release digest differs from its positive gate"),
        )?;
        Ok(())
    }

    #[test]
    fn physical_java_release_rejects_file_shape_and_line_drifts() -> Result<()> {
        let canonical = b"IMPLEMENTOR=\"Fixture JVM\"\nJAVA_VERSION=\"21.0.1\"\n";
        let mut bom = vec![0xef, 0xbb, 0xbf];
        bom.extend_from_slice(canonical);
        let mut invalid_utf8 = b"IMPLEMENTOR=\"".to_vec();
        invalid_utf8.push(0xff);
        invalid_utf8.extend_from_slice(b"\"\nJAVA_VERSION=\"21.0.1\"\n");
        let mut missing_lf = canonical.to_vec();
        missing_lf.pop();
        let mut double_lf = canonical.to_vec();
        double_lf.push(b'\n');
        exercise_private_java_release_malformed_cases([
            (bom, "Java release file carries a UTF-8 BOM"),
            (invalid_utf8, "Java release file is not strict UTF-8"),
            (
                b"IMPLEMENTOR=\"Fixture JVM\"\r\nJAVA_VERSION=\"21.0.1\"\r\n".to_vec(),
                "Java release file contains CR instead of LF",
            ),
            (missing_lf, "Java release file lacks its terminal LF"),
            (
                double_lf,
                "Java release file does not end in exactly one LF",
            ),
            (
                b"IMPLEMENTOR=\"Fixture JVM\"\n\nJAVA_VERSION=\"21.0.1\"\n".to_vec(),
                "Java release file contains an empty or comment line",
            ),
            (
                b"#COMMENT\nIMPLEMENTOR=\"Fixture JVM\"\nJAVA_VERSION=\"21.0.1\"\n".to_vec(),
                "Java release file contains an empty or comment line",
            ),
            (
                b"IMPLEMENTOR=Fixture JVM\nJAVA_VERSION=\"21.0.1\"\n".to_vec(),
                "Java release value is not completely quoted",
            ),
            (
                b"IMPLEMENTOR=\"Fixture JVM\" \nJAVA_VERSION=\"21.0.1\"\n".to_vec(),
                "Java release value is not completely quoted",
            ),
        ])
    }

    #[test]
    fn physical_java_release_rejects_value_escape_and_key_drifts() -> Result<()> {
        let mut incomplete_escape = b"IMPLEMENTOR=\"Fixture JVM\\".to_vec();
        incomplete_escape.extend_from_slice(b"\"\nJAVA_VERSION=\"21.0.1\"\n");
        exercise_private_java_release_malformed_cases([
            (
                b"IMPLEMENTOR=\"Fixture \\qJVM\"\nJAVA_VERSION=\"21.0.1\"\n".to_vec(),
                "Java release value uses an unknown escape",
            ),
            (
                incomplete_escape,
                "Java release value ends in an incomplete escape",
            ),
            (
                b"IMPLEMENTOR=\"Fixture \"JVM\"\"\nJAVA_VERSION=\"21.0.1\"\n".to_vec(),
                "unescaped control, quote, or substitution syntax",
            ),
            (
                b"IMPLEMENTOR=\"Fixture\tJVM\"\nJAVA_VERSION=\"21.0.1\"\n".to_vec(),
                "unescaped control, quote, or substitution syntax",
            ),
            (
                b"IMPLEMENTOR=\"`fixture`\"\nJAVA_VERSION=\"21.0.1\"\n".to_vec(),
                "unescaped control, quote, or substitution syntax",
            ),
            (
                b"IMPLEMENTOR=\"$(fixture)\"\nJAVA_VERSION=\"21.0.1\"\n".to_vec(),
                "substitution syntax",
            ),
            (
                b"IMPLEMENTOR=\"Fixture JVM\"\nIMPLEMENTOR=\"Fixture JVM\"\nJAVA_VERSION=\"21.0.1\"\n".to_vec(),
                "Java release keys are not unique and strictly ASCII-sorted",
            ),
            (
                b"Implementor=\"Fixture JVM\"\nJAVA_VERSION=\"21.0.1\"\n".to_vec(),
                "Java release key is not canonical uppercase ASCII",
            ),
        ])
    }

    #[test]
    fn physical_java_release_rejects_semantic_projection_drifts() -> Result<()> {
        fn digest(bytes: &[u8]) -> [u8; super::SHA256_BYTES] {
            Sha256::digest(bytes).into()
        }

        let canonical = b"IMPLEMENTOR=\"Fixture JVM\"\nJAVA_VERSION=\"21.0.1\"\n";
        for (bytes, feature, vendor, version, expected_error) in [
            (
                b"JAVA_VERSION=\"21.0.1\"\n".as_slice(),
                21,
                "Fixture JVM",
                "21.0.1",
                "Java release IMPLEMENTOR differs from its positive gate",
            ),
            (
                b"IMPLEMENTOR=\"Fixture JVM\"\n".as_slice(),
                21,
                "Fixture JVM",
                "21.0.1",
                "Java release JAVA_VERSION differs from its positive gate",
            ),
            (
                b"IMPLEMENTOR=\"Other JVM\"\nJAVA_VERSION=\"21.0.1\"\n".as_slice(),
                21,
                "Fixture JVM",
                "21.0.1",
                "Java release IMPLEMENTOR differs from its positive gate",
            ),
            (
                b"IMPLEMENTOR=\"Fixture JVM\"\nJAVA_VERSION=\"21.0.2\"\n".as_slice(),
                21,
                "Fixture JVM",
                "21.0.1",
                "Java release JAVA_VERSION differs from its positive gate",
            ),
            (
                canonical.as_slice(),
                22,
                "Fixture JVM",
                "21.0.1",
                "Java release feature version differs from Java 21",
            ),
            (
                b"IMPLEMENTOR=\"Fixture JVM\"\nJAVA_VERSION=\"21.0\"\n".as_slice(),
                21,
                "Fixture JVM",
                "21.0",
                "Java release version number is not canonical",
            ),
        ] {
            exercise_private_java_release_fixture(
                bytes,
                u64::try_from(bytes.len())?,
                digest(bytes),
                feature,
                vendor,
                version,
                Some(expected_error),
            )?;
        }
        Ok(())
    }

    #[test]
    fn physical_java_release_rejects_absent_or_nonregular_targets_and_cleans_up() -> Result<()> {
        let release = b"IMPLEMENTOR=\"Fixture JVM\"\nJAVA_VERSION=\"21.0.1\"\n";
        let release_sha256: [u8; super::SHA256_BYTES] = Sha256::digest(release).into();
        for (suffix, entries, expected_error) in [
            (
                "absent",
                Vec::new(),
                "authenticated rootfs path is dangling: runtime/release",
            ),
            (
                "directory",
                vec![RuntimeRootfsFixtureEntryV1::directory("runtime/release")],
                "resolved authenticated rootfs final target is non-regular",
            ),
        ] {
            let temp = tempfile::tempdir()?;
            let before = directory_names(temp.path())?;
            let runtime_elf =
                crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
            let final_name = format!("physical-java-release-{suffix}");
            let (final_path, retained) = authenticated_runtime_elf_projection_with_entries(
                temp.path(),
                &final_name,
                &runtime_elf,
                &entries,
            )?;
            let error = retained
                .materialize_private()?
                .test_only_authenticate_java_release_and_cleanup(
                    PositiveRunnerRole::JvmVerifier,
                    "/runtime/release",
                    u64::try_from(release.len())?,
                    release_sha256,
                    21,
                    "Fixture JVM",
                    "21.0.1",
                )
                .unwrap_err();
            assert!(
                format!("{error:#}").contains(expected_error),
                "expected {expected_error:?}, observed {error:#}"
            );
            assert_eq!(directory_names(temp.path())?, before);
            assert!(!final_path.exists());
        }
        Ok(())
    }

    #[test]
    fn private_runtime_elf_jvm_verifier_cannot_omit_its_profile_bound_executable_identity()
    -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
        let (final_path, retained) = authenticated_runtime_elf_projection(
            temp.path(),
            "physical-runtime-missing-gate-identity",
            &runtime_elf,
        )?;

        let error = retained
            .materialize_private()?
            .test_only_authenticate_jvm_executables_and_cleanup(None)
            .unwrap_err();
        assert!(
            format!("{error:#}")
                .contains("JVM rootfs omits its profile-bound executable identities"),
            "{error:#}"
        );
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn private_runtime_elf_validation_and_logical_abandonment_double_fault_retains_typed_observations()
    -> Result<()> {
        use super::physical::TestOnlyPrivateMaterializationFailpointV1 as Failpoint;

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let runtime_elf =
            crate::b4_campaign_executor::amd64_elf_inspection::tests::runtime_elf_bytes(1);
        let (final_path, mut retained) = authenticated_runtime_elf_projection(
            temp.path(),
            "physical-runtime-double-fault",
            &runtime_elf,
        )?;
        retained.test_only_physical_materialization_failpoint =
            Some(Failpoint::LogicalSpoolCustodyDriftBeforeAbandonment);

        let error = retained
            .materialize_private()?
            .test_only_authenticate_jvm_executables_and_cleanup(None)
            .unwrap_err();
        let failure = error
            .downcast::<PrivateOciRootfsFailedV1>()
            .unwrap_or_else(|error| panic!("missing typed logical abandonment: {error:#}"));
        let message = format!("{failure:#}");
        assert!(
            message.contains("JVM rootfs omits its profile-bound executable identities"),
            "{message}"
        );
        assert!(
            message.contains("logical abandonment also failed"),
            "{message}"
        );
        assert!(
            failure.abandonment.final_observation_error.is_some(),
            "{message}"
        );
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn private_materialization_preeffect_failure_abandons_and_allows_fresh_replay() -> Result<()> {
        use super::physical::TestOnlyPrivateMaterializationFailpointV1 as Failpoint;

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let final_name = "physical-preeffect-abandonment";
        let (final_path, mut retained) =
            authenticated_single_regular_projection(temp.path(), final_name)?;
        retained.test_only_physical_materialization_failpoint =
            Some(Failpoint::ReadyBeforeStagingRootCreation);

        let error = retained
            .materialize_private()
            .err()
            .ok_or_else(|| anyhow::anyhow!("expected private materialization preeffect failure"))?;
        assert!(
            format!("{error:#}").contains("ReadyBeforeStagingRootCreation"),
            "{error:#}"
        );
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());

        let (replay_final_path, replay) =
            authenticated_single_regular_projection(temp.path(), final_name)?;
        let abandonment = replay.materialize_private()?.cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!replay_final_path.exists());
        Ok(())
    }

    #[test]
    fn private_materialization_preeffect_custody_anomaly_retains_abandonment_observation()
    -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, retained) = authenticated_single_regular_projection(
            temp.path(),
            "physical-preeffect-custody-anomaly",
        )?;
        rustix::fs::fchmod(
            retained.transaction.spool.as_fd(),
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::RGRP,
        )?;

        let error = retained
            .materialize_private()
            .err()
            .ok_or_else(|| anyhow::anyhow!("expected private materialization custody failure"))?;
        let failure = error
            .downcast::<PrivateOciRootfsFailedV1>()
            .unwrap_or_else(|error| panic!("missing typed preeffect abandonment: {error:#}"));
        let message = format!("{failure:#}");
        assert!(message.contains("mode 0600"), "{message}");
        assert!(
            failure
                .abandonment
                .final_observation_error
                .as_deref()
                .is_some_and(|observation| observation.contains("mode 0600")),
            "{message}"
        );
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn private_materialization_realizes_exact_canonical_live_tree() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, retained) = authenticated_mixed_projection(temp.path(), "physical-mixed")?;

        let materialized = retained.materialize_private()?;
        assert!(!final_path.exists());
        let during = directory_names(temp.path())?;
        let added = during.difference(&before).collect::<Vec<_>>();
        assert_eq!(added.len(), 1);
        let staging = temp.path().join(added[0]);
        assert_eq!(
            directory_names(&staging)?,
            BTreeSet::from([OsString::from("bin"), OsString::from("notice")])
        );
        assert_eq!(
            directory_names(&staging.join("bin"))?,
            BTreeSet::from([OsString::from("tool"), OsString::from("tool-link")])
        );
        assert_eq!(
            fs::symlink_metadata(staging.join("bin"))?
                .permissions()
                .mode()
                & 0o7777,
            0o555
        );
        assert_eq!(fs::read(staging.join("bin/tool"))?, b"EXEC");
        assert_eq!(
            fs::symlink_metadata(staging.join("bin/tool"))?
                .permissions()
                .mode()
                & 0o7777,
            0o555
        );
        assert_eq!(fs::read(staging.join("notice"))?, b"READ");
        assert_eq!(
            fs::symlink_metadata(staging.join("notice"))?
                .permissions()
                .mode()
                & 0o7777,
            0o444
        );
        let link = fs::symlink_metadata(staging.join("bin/tool-link"))?;
        assert!(link.file_type().is_symlink());
        assert_eq!(link.permissions().mode() & 0o7777, 0o777);
        assert_eq!(
            fs::read_link(staging.join("bin/tool-link"))?,
            PathBuf::from("tool")
        );
        for absent in ["gone", ".wh.gone", "bin/old", "bin/.wh..wh..opq"] {
            assert!(!staging.join(absent).exists(), "{absent}");
        }

        let abandonment = materialized.cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn each_recorded_named_effect_failure_auto_cleans_without_cross_projection_state() -> Result<()>
    {
        use super::physical::TestOnlyPrivateMaterializationFailpointV1 as Failpoint;

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let cases = [
            ("staging-root", Failpoint::StagingRootIdentityCaptured),
            (
                "directory",
                Failpoint::DirectoryIdentityRecorded { operation_index: 0 },
            ),
            (
                "regular",
                Failpoint::RegularIdentityRecorded { operation_index: 5 },
            ),
            (
                "regular-mode-seal",
                Failpoint::RegularModeSealRecorded { operation_index: 5 },
            ),
            (
                "regular-seal",
                Failpoint::RegularSealRecorded { operation_index: 5 },
            ),
            (
                "symbolic-link",
                Failpoint::SymbolicLinkIdentityRecorded { operation_index: 6 },
            ),
            (
                "symbolic-link-seal",
                Failpoint::SymbolicLinkSealRecorded { operation_index: 6 },
            ),
            (
                "directory-mtime",
                Failpoint::DirectoryMtimeRecorded { operation_index: 0 },
            ),
            (
                "directory-seal",
                Failpoint::DirectorySealRecorded { operation_index: 0 },
            ),
            ("staging-root-mtime", Failpoint::StagingRootMtimeRecorded),
            ("staging-root-seal", Failpoint::StagingRootSealRecorded),
        ];

        for (label, failpoint) in cases {
            let (final_path, mut retained) = authenticated_mixed_projection(
                temp.path(),
                &format!("physical-failpoint-{label}"),
            )?;
            retained.test_only_physical_materialization_failpoint = Some(failpoint);

            let error = expect_error(retained.materialize_private());
            assert!(
                format!("{error:#}").contains(&format!(
                    "injected private OCI rootfs materialization failure at {failpoint:?}"
                )),
                "{error:#}"
            );
            assert!(
                error
                    .downcast_ref::<super::physical::PrivateOciRootfsCleanupFailureV1>()
                    .is_none(),
                "safe recorded failpoint unexpectedly required typed recovery: {error:#}"
            );
            assert_eq!(directory_names(temp.path())?, before, "{failpoint:?}");
            assert!(!final_path.exists(), "{failpoint:?}");
        }

        let (final_path, retained) =
            authenticated_mixed_projection(temp.path(), "physical-failpoint-locality")?;
        let materialized = retained.materialize_private()?;
        let abandonment = materialized.cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn each_physical_custody_identity_field_is_required_by_cleanup() -> Result<()> {
        use super::physical::TestOnlyPhysicalCustodyMutationV1 as Mutation;

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let mutations = [
            Mutation::MountNamespaceDevice,
            Mutation::MountNamespaceInode,
            Mutation::UserNamespaceDevice,
            Mutation::UserNamespaceInode,
            Mutation::StagingDevice,
            Mutation::StagingInode,
            Mutation::StagingMount,
            Mutation::StagingGroup,
            Mutation::StagingObservedMode,
            Mutation::StagingObservedMtimeSeconds,
            Mutation::StagingObservedMtimeNanoseconds,
            Mutation::StagingObservedOwner,
            Mutation::StagingExpectedCardinality,
            Mutation::DirectoryDevice { operation_index: 0 },
            Mutation::DirectoryInode { operation_index: 0 },
            Mutation::DirectoryMount { operation_index: 0 },
            Mutation::DirectoryGroup { operation_index: 0 },
            Mutation::DirectoryObservedMode { operation_index: 0 },
            Mutation::DirectoryObservedMtimeSeconds { operation_index: 0 },
            Mutation::DirectoryObservedMtimeNanoseconds { operation_index: 0 },
            Mutation::DirectoryObservedOwner { operation_index: 0 },
            Mutation::DirectoryExpectedCardinality { operation_index: 0 },
            Mutation::RegularDevice { operation_index: 5 },
            Mutation::RegularInode { operation_index: 5 },
            Mutation::RegularMount { operation_index: 5 },
            Mutation::RegularGroup { operation_index: 5 },
            Mutation::RegularObservedMtimeSeconds { operation_index: 5 },
            Mutation::RegularObservedMtimeNanoseconds { operation_index: 5 },
            Mutation::RegularObservedOwner { operation_index: 5 },
            Mutation::SymbolicLinkDeviceMajor { operation_index: 6 },
            Mutation::SymbolicLinkDeviceMinor { operation_index: 6 },
            Mutation::SymbolicLinkInode { operation_index: 6 },
            Mutation::SymbolicLinkMount { operation_index: 6 },
            Mutation::SymbolicLinkGroup { operation_index: 6 },
            Mutation::SymbolicLinkObservedHardLinkCount { operation_index: 6 },
            Mutation::SymbolicLinkObservedMode { operation_index: 6 },
            Mutation::SymbolicLinkObservedMtimeSeconds { operation_index: 6 },
            Mutation::SymbolicLinkObservedMtimeNanoseconds { operation_index: 6 },
            Mutation::SymbolicLinkObservedOwner { operation_index: 6 },
            Mutation::SymbolicLinkExpectedTarget { operation_index: 6 },
        ];

        for mutation in mutations {
            let (final_path, retained) = authenticated_mixed_projection(
                temp.path(),
                &format!("physical-custody-field-{mutation:?}"),
            )?;
            let materialized = retained.materialize_private()?;
            let during = directory_names(temp.path())?;
            let added = during.difference(&before).cloned().collect::<Vec<_>>();
            assert_eq!(added.len(), 1, "{mutation:?}");
            let staging = temp.path().join(&added[0]);
            materialized.test_only_arm_cleanup_custody_mutation(mutation);
            let Err(failure) = materialized.cleanup() else {
                panic!("{mutation:?} must prevent owned cleanup")
            };
            let error = format!("{failure:#}");
            assert!(
                error.contains("changed")
                    || error.contains("differs")
                    || error.contains("unexpected cardinality"),
                "{mutation:?}: {error}"
            );
            assert_eq!(fs::read(staging.join("bin/tool"))?, b"EXEC", "{mutation:?}");
            assert_eq!(
                fs::read_link(staging.join("bin/tool-link"))?,
                PathBuf::from("tool"),
                "{mutation:?}"
            );

            let abandonment = failure.retry_cleanup()?;
            assert!(abandonment.final_unlinked_observed, "{mutation:?}");
            assert_eq!(directory_names(temp.path())?, before, "{mutation:?}");
            assert!(fs::symlink_metadata(&final_path).is_err(), "{mutation:?}");
        }
        Ok(())
    }

    #[test]
    fn mount_namespace_mismatch_after_partial_cleanup_preserves_retry_custody() -> Result<()> {
        use super::physical::TestOnlyPrivateCleanupFailpointV1 as Failpoint;

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, retained) =
            authenticated_mixed_projection(temp.path(), "partial-cleanup-namespace-drift")?;
        let materialized = retained.materialize_private()?;
        let staging = sole_physical_staging_path(temp.path(), &before)?;
        materialized.test_only_arm_cleanup_failpoint(
            Failpoint::AfterFirstEntryUnlinkedMountNamespaceMismatch,
        );

        let Err(failure) = materialized.cleanup() else {
            panic!("mount namespace mismatch after partial cleanup must retain retry custody")
        };
        assert!(
            format!("{failure:#}").contains("calling-thread mount namespace changed"),
            "{failure:#}"
        );
        assert!(fs::symlink_metadata(staging.join("notice")).is_err());
        assert_eq!(fs::read(staging.join("bin/tool"))?, b"EXEC");
        assert_eq!(
            fs::read_link(staging.join("bin/tool-link"))?,
            PathBuf::from("tool")
        );

        fs::write(staging.join("notice"), b"replacement")?;
        let Err(failure) = failure.retry_cleanup() else {
            panic!("a replacement outside retry custody must prevent cleanup")
        };
        assert_eq!(fs::read(staging.join("notice"))?, b"replacement");
        fs::remove_file(staging.join("notice"))?;

        let abandonment = failure.retry_cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(fs::symlink_metadata(&final_path).is_err());
        Ok(())
    }

    #[test]
    fn user_namespace_mismatch_after_partial_cleanup_preserves_retry_custody() -> Result<()> {
        use super::physical::TestOnlyPrivateCleanupFailpointV1 as Failpoint;

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, retained) =
            authenticated_mixed_projection(temp.path(), "partial-cleanup-user-namespace-drift")?;
        let materialized = retained.materialize_private()?;
        let staging = sole_physical_staging_path(temp.path(), &before)?;
        materialized.test_only_arm_cleanup_failpoint(
            Failpoint::AfterFirstEntryUnlinkedUserNamespaceMismatch,
        );
        let Err(failure) = materialized.cleanup() else {
            panic!("user namespace mismatch after partial cleanup must retain retry custody")
        };
        assert!(
            format!("{failure:#}").contains("calling-thread user namespace changed"),
            "{failure:#}"
        );
        assert!(fs::symlink_metadata(staging.join("notice")).is_err());
        assert_eq!(fs::read(staging.join("bin/tool"))?, b"EXEC");
        let abandonment = failure.retry_cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(fs::symlink_metadata(&final_path).is_err());
        Ok(())
    }

    #[test]
    fn supplementary_group_mismatch_after_partial_cleanup_preserves_retry_custody() -> Result<()> {
        use super::physical::TestOnlyPrivateCleanupFailpointV1 as Failpoint;

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, retained) = authenticated_mixed_projection(
            temp.path(),
            "partial-cleanup-supplementary-group-drift",
        )?;
        let materialized = retained.materialize_private()?;
        let staging = sole_physical_staging_path(temp.path(), &before)?;
        materialized.test_only_arm_cleanup_failpoint(
            Failpoint::AfterFirstEntryUnlinkedSupplementaryGroupsMismatch,
        );
        let Err(failure) = materialized.cleanup() else {
            panic!("supplementary-group mismatch after partial cleanup must retain retry custody")
        };
        assert!(
            format!("{failure:#}").contains("calling-thread supplementary groups changed"),
            "{failure:#}"
        );
        assert!(fs::symlink_metadata(staging.join("notice")).is_err());
        assert_eq!(fs::read(staging.join("bin/tool"))?, b"EXEC");
        let abandonment = failure.retry_cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(fs::symlink_metadata(&final_path).is_err());
        Ok(())
    }

    #[test]
    fn filesystem_credential_mismatch_after_partial_cleanup_preserves_retry_custody() -> Result<()>
    {
        use super::physical::TestOnlyPrivateCleanupFailpointV1 as Failpoint;

        for (label, failpoint, expected) in [
            (
                "partial-cleanup-fsuid-drift",
                Failpoint::AfterFirstEntryUnlinkedFsuidMismatch,
                "calling-thread fsuid changed",
            ),
            (
                "partial-cleanup-fsgid-drift",
                Failpoint::AfterFirstEntryUnlinkedFsgidMismatch,
                "calling-thread fsgid changed",
            ),
        ] {
            let temp = tempfile::tempdir()?;
            let before = directory_names(temp.path())?;
            let (final_path, retained) = authenticated_mixed_projection(temp.path(), label)?;
            let materialized = retained.materialize_private()?;
            let staging = sole_physical_staging_path(temp.path(), &before)?;
            materialized.test_only_arm_cleanup_failpoint(failpoint);
            let Err(failure) = materialized.cleanup() else {
                panic!("{label} after partial cleanup must retain retry custody")
            };
            assert!(format!("{failure:#}").contains(expected), "{failure:#}");
            assert!(fs::symlink_metadata(staging.join("notice")).is_err());
            assert_eq!(fs::read(staging.join("bin/tool"))?, b"EXEC");
            let abandonment = failure.retry_cleanup()?;
            assert!(abandonment.final_unlinked_observed);
            assert_eq!(directory_names(temp.path())?, before);
            assert!(fs::symlink_metadata(&final_path).is_err());
        }
        Ok(())
    }

    #[test]
    fn retained_thread_namespaces_accept_transfer_to_another_thread_in_the_same_namespaces()
    -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, retained) =
            authenticated_single_regular_projection(temp.path(), "same-namespace-thread")?;
        let (returned_final_path, abandonment) = std::thread::spawn(move || {
            let abandonment = retained.materialize_private()?.cleanup()?;
            Ok::<_, anyhow::Error>((final_path, abandonment))
        })
        .join()
        .map_err(|_| anyhow::anyhow!("same-namespace rootfs worker panicked"))??;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!returned_final_path.exists());
        Ok(())
    }

    #[derive(Clone, Copy, Debug)]
    enum PhysicalRegularDrift {
        Mode,
        Type,
        HardLinkCount,
        ByteLength,
        Digest,
    }

    fn apply_physical_regular_drift(
        drift: PhysicalRegularDrift,
        staging: &Path,
        artifact: &Path,
        held: &Path,
        held_name: &str,
    ) -> Result<()> {
        if matches!(drift, PhysicalRegularDrift::Type) {
            reopen_test_sealed_directory(staging)?;
        }
        match drift {
            PhysicalRegularDrift::Mode => {
                fs::set_permissions(artifact, fs::Permissions::from_mode(0o644))?;
            }
            PhysicalRegularDrift::Type => {
                fs::rename(artifact, held)?;
                std::os::unix::fs::symlink(PathBuf::from("..").join(held_name), artifact)?;
            }
            PhysicalRegularDrift::HardLinkCount => fs::hard_link(artifact, held)?,
            PhysicalRegularDrift::ByteLength => {
                fs::set_permissions(artifact, fs::Permissions::from_mode(0o644))?;
                fs::write(artifact, b"AAAA")?;
                fs::set_permissions(artifact, fs::Permissions::from_mode(0o444))?;
                normalize_test_path_mtime(artifact)?;
            }
            PhysicalRegularDrift::Digest => {
                fs::set_permissions(artifact, fs::Permissions::from_mode(0o644))?;
                fs::write(artifact, b"BBB")?;
                fs::set_permissions(artifact, fs::Permissions::from_mode(0o444))?;
                normalize_test_path_mtime(artifact)?;
            }
        }
        if matches!(drift, PhysicalRegularDrift::Type) {
            reseal_test_directory(staging)?;
        }
        Ok(())
    }

    fn restore_physical_regular_drift(
        drift: PhysicalRegularDrift,
        staging: &Path,
        artifact: &Path,
        held: &Path,
    ) -> Result<()> {
        if matches!(drift, PhysicalRegularDrift::Type) {
            reopen_test_sealed_directory(staging)?;
        }
        match drift {
            PhysicalRegularDrift::Mode => {
                assert_eq!(
                    fs::symlink_metadata(artifact)?.permissions().mode() & 0o7777,
                    0o644
                );
                fs::set_permissions(artifact, fs::Permissions::from_mode(0o444))?;
            }
            PhysicalRegularDrift::Type => {
                assert!(fs::symlink_metadata(artifact)?.file_type().is_symlink());
                assert!(fs::symlink_metadata(held)?.is_file());
                fs::remove_file(artifact)?;
                fs::rename(held, artifact)?;
            }
            PhysicalRegularDrift::HardLinkCount => {
                assert_eq!(fs::symlink_metadata(artifact)?.nlink(), 2);
                assert_eq!(fs::symlink_metadata(held)?.nlink(), 2);
                fs::remove_file(held)?;
            }
            PhysicalRegularDrift::ByteLength => {
                assert_eq!(fs::read(artifact)?, b"AAAA");
                fs::set_permissions(artifact, fs::Permissions::from_mode(0o644))?;
                fs::write(artifact, b"AAA")?;
                fs::set_permissions(artifact, fs::Permissions::from_mode(0o444))?;
                normalize_test_path_mtime(artifact)?;
            }
            PhysicalRegularDrift::Digest => {
                assert_eq!(fs::read(artifact)?, b"BBB");
                fs::set_permissions(artifact, fs::Permissions::from_mode(0o644))?;
                fs::write(artifact, b"AAA")?;
                fs::set_permissions(artifact, fs::Permissions::from_mode(0o444))?;
                normalize_test_path_mtime(artifact)?;
            }
        }
        if matches!(drift, PhysicalRegularDrift::Type) {
            reseal_test_directory(staging)?;
        }
        Ok(())
    }

    fn assert_physical_regular_drift_is_recoverable(drift: PhysicalRegularDrift) -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, retained) = authenticated_single_regular_projection(
            temp.path(),
            &format!("physical-regular-drift-{drift:?}"),
        )?;
        let materialized = retained.materialize_private()?;
        let during = directory_names(temp.path())?;
        let added = during.difference(&before).cloned().collect::<Vec<_>>();
        assert_eq!(added.len(), 1);
        let staging = temp.path().join(&added[0]);
        let artifact = staging.join("artifact");
        let held_name = format!("held-physical-regular-{drift:?}");
        let held = temp.path().join(&held_name);

        apply_physical_regular_drift(drift, &staging, &artifact, &held, &held_name)?;

        let Err(failure) = materialized.cleanup() else {
            panic!("{drift:?} drift must prevent owned cleanup")
        };
        let expected = match drift {
            PhysicalRegularDrift::Mode | PhysicalRegularDrift::HardLinkCount => {
                "regular-file identity changed"
            }
            PhysicalRegularDrift::Type => "cannot reopen materialized regular file",
            PhysicalRegularDrift::ByteLength => "regular metadata differs",
            PhysicalRegularDrift::Digest => "regular digest differs",
        };
        assert!(
            format!("{failure:#}").contains(expected),
            "{drift:?}: {failure:#}"
        );
        assert!(fs::symlink_metadata(&final_path).is_err());

        restore_physical_regular_drift(drift, &staging, &artifact, &held)?;

        let abandonment = failure.retry_cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(fs::symlink_metadata(&final_path).is_err());
        Ok(())
    }

    #[test]
    fn physical_regular_cleanup_rejects_mode_drift() -> Result<()> {
        assert_physical_regular_drift_is_recoverable(PhysicalRegularDrift::Mode)
    }

    #[test]
    fn physical_regular_cleanup_rejects_type_drift() -> Result<()> {
        assert_physical_regular_drift_is_recoverable(PhysicalRegularDrift::Type)
    }

    #[test]
    fn physical_regular_cleanup_rejects_hard_link_count_drift() -> Result<()> {
        assert_physical_regular_drift_is_recoverable(PhysicalRegularDrift::HardLinkCount)
    }

    #[test]
    fn physical_regular_cleanup_rejects_byte_length_drift() -> Result<()> {
        assert_physical_regular_drift_is_recoverable(PhysicalRegularDrift::ByteLength)
    }

    #[test]
    fn physical_regular_cleanup_rejects_digest_drift() -> Result<()> {
        assert_physical_regular_drift_is_recoverable(PhysicalRegularDrift::Digest)
    }

    fn assert_unidentified_staging_root_substitution_is_quarantined() -> Result<()> {
        use super::physical::TestOnlyPrivateMaterializationFailpointV1 as Failpoint;

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, mut retained) =
            authenticated_mixed_projection(temp.path(), "unidentified-staging-root")?;
        retained.test_only_physical_materialization_failpoint =
            Some(Failpoint::StagingRootNamedBeforePin);
        let error = expect_error(retained.materialize_private());
        let during = directory_names(temp.path())?;
        let added = during.difference(&before).cloned().collect::<Vec<_>>();
        assert_eq!(added.len(), 1);
        let staging = temp.path().join(&added[0]);
        let held = temp.path().join("held-unidentified-staging-root");
        fs::rename(&staging, &held)?;
        let held_metadata = fs::symlink_metadata(&held)?;
        fs::create_dir(&staging)?;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))?;
        let replacement_metadata = fs::symlink_metadata(&staging)?;
        assert_ne!(
            (replacement_metadata.dev(), replacement_metadata.ino()),
            (held_metadata.dev(), held_metadata.ino())
        );

        let failure = expect_physical_cleanup_failure(error);
        assert!(
            format!("{failure:#}").contains("StagingRootNamedBeforePin"),
            "{failure:#}"
        );
        let Err(failure) = failure.retry_cleanup() else {
            panic!("unidentified staging root must remain quarantined")
        };
        assert!(
            format!("{failure:#}").contains("identity was not captured"),
            "{failure:#}"
        );
        assert!(fs::symlink_metadata(&staging)?.is_dir());
        assert!(fs::symlink_metadata(&final_path).is_err());

        drop(failure);
        fs::remove_dir(&staging)?;
        fs::remove_dir(&held)?;
        assert_eq!(directory_names(temp.path())?, before);
        Ok(())
    }

    #[test]
    fn unidentified_directory_like_effects_return_quarantine_custody_and_preserve_substitutions()
    -> Result<()> {
        use super::physical::TestOnlyPrivateMaterializationFailpointV1 as Failpoint;

        assert_unidentified_staging_root_substitution_is_quarantined()?;

        {
            let temp = tempfile::tempdir()?;
            let before = directory_names(temp.path())?;
            let (final_path, mut retained) =
                authenticated_mixed_projection(temp.path(), "unidentified-directory")?;
            retained.test_only_physical_materialization_failpoint =
                Some(Failpoint::DirectoryNamedBeforePin { operation_index: 0 });
            let error = expect_error(retained.materialize_private());
            let during = directory_names(temp.path())?;
            let added = during.difference(&before).cloned().collect::<Vec<_>>();
            assert_eq!(added.len(), 1);
            let staging = temp.path().join(&added[0]);
            let directory = staging.join("bin");
            let held = temp.path().join("held-unidentified-directory");
            fs::rename(&directory, &held)?;
            let held_metadata = fs::symlink_metadata(&held)?;
            fs::create_dir(&directory)?;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
            let replacement_metadata = fs::symlink_metadata(&directory)?;
            assert_ne!(
                (replacement_metadata.dev(), replacement_metadata.ino()),
                (held_metadata.dev(), held_metadata.ino())
            );

            let failure = expect_physical_cleanup_failure(error);
            assert!(
                format!("{failure:#}").contains("DirectoryNamedBeforePin"),
                "{failure:#}"
            );
            let Err(failure) = failure.retry_cleanup() else {
                panic!("unidentified directory must remain quarantined")
            };
            assert!(
                format!("{failure:#}").contains("identity was not captured"),
                "{failure:#}"
            );
            assert!(fs::symlink_metadata(&directory)?.is_dir());
            assert!(fs::symlink_metadata(&final_path).is_err());

            drop(failure);
            fs::remove_dir_all(&staging)?;
            fs::remove_dir(&held)?;
            assert_eq!(directory_names(temp.path())?, before);
        }

        {
            let temp = tempfile::tempdir()?;
            let before = directory_names(temp.path())?;
            let (final_path, mut retained) =
                authenticated_mixed_projection(temp.path(), "unidentified-symbolic-link")?;
            retained.test_only_physical_materialization_failpoint =
                Some(Failpoint::SymbolicLinkNamedBeforeIdentity { operation_index: 6 });
            let error = expect_error(retained.materialize_private());
            let during = directory_names(temp.path())?;
            let added = during.difference(&before).cloned().collect::<Vec<_>>();
            assert_eq!(added.len(), 1);
            let staging = temp.path().join(&added[0]);
            let symbolic_link = staging.join("bin/tool-link");
            let held = temp.path().join("held-unidentified-symbolic-link");
            fs::rename(&symbolic_link, &held)?;
            std::os::unix::fs::symlink("tool", &symbolic_link)?;

            let failure = expect_physical_cleanup_failure(error);
            assert!(
                format!("{failure:#}").contains("SymbolicLinkNamedBeforeIdentity"),
                "{failure:#}"
            );
            let Err(failure) = failure.retry_cleanup() else {
                panic!("unidentified symbolic link must remain quarantined")
            };
            assert!(
                format!("{failure:#}").contains("identity was not captured"),
                "{failure:#}"
            );
            assert_eq!(fs::read_link(&symbolic_link)?, PathBuf::from("tool"));
            assert_eq!(fs::read_link(&held)?, PathBuf::from("tool"));
            assert!(fs::symlink_metadata(&final_path).is_err());

            drop(failure);
            fs::remove_dir_all(&staging)?;
            fs::remove_file(&held)?;
            assert_eq!(directory_names(temp.path())?, before);
        }
        Ok(())
    }

    #[test]
    fn regular_creator_fd_survives_pre_identity_failure_and_auto_cleans() -> Result<()> {
        use super::physical::TestOnlyPrivateMaterializationFailpointV1 as Failpoint;

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, mut retained) =
            authenticated_mixed_projection(temp.path(), "unidentified-regular")?;
        retained.test_only_physical_materialization_failpoint =
            Some(Failpoint::RegularFileDescriptorRecorded { operation_index: 5 });

        let error = expect_error(retained.materialize_private());
        assert!(
            format!("{error:#}").contains("RegularFileDescriptorRecorded"),
            "{error:#}"
        );
        assert!(
            error
                .downcast_ref::<super::physical::PrivateOciRootfsCleanupFailureV1>()
                .is_none(),
            "owned regular creator FD should have auto-cleaned: {error:#}"
        );
        assert_eq!(directory_names(temp.path())?, before);
        assert!(fs::symlink_metadata(&final_path).is_err());
        Ok(())
    }

    #[test]
    fn regular_creator_fd_refuses_pre_identity_same_name_substitution_then_retries() -> Result<()> {
        use super::physical::TestOnlyPrivateMaterializationFailpointV1 as Failpoint;

        const HOLDING_NAME: &str = "held-unidentified-regular-creator";

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, mut retained) =
            authenticated_mixed_projection(temp.path(), "unidentified-regular-substitution")?;
        retained.test_only_physical_materialization_failpoint = Some(
            Failpoint::RegularFileDescriptorRecordedWithSameNameSubstitution {
                operation_index: 5,
                holding_name: HOLDING_NAME,
            },
        );

        let error = expect_error(retained.materialize_private());
        let failure = expect_physical_cleanup_failure(error);
        assert!(
            format!("{failure:#}")
                .contains("RegularFileDescriptorRecordedWithSameNameSubstitution"),
            "{failure:#}"
        );
        assert!(
            format!("{failure:#}")
                .contains("regular creator descriptor does not identify the current name"),
            "{failure:#}"
        );

        let during = directory_names(temp.path())?;
        let added = during.difference(&before).cloned().collect::<Vec<_>>();
        assert_eq!(added.len(), 2);
        assert!(added.contains(&OsString::from(HOLDING_NAME)));
        let staging_name = added
            .iter()
            .find(|name| name.as_os_str() != OsStr::new(HOLDING_NAME))
            .expect("one non-holding staging name");
        let staging = temp.path().join(staging_name);
        let artifact = staging.join("bin/tool");
        let held = temp.path().join(HOLDING_NAME);
        let artifact_metadata = fs::symlink_metadata(&artifact)?;
        let held_metadata = fs::symlink_metadata(&held)?;
        assert!(artifact_metadata.is_file());
        assert!(held_metadata.is_file());
        assert_eq!(artifact_metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(held_metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(artifact_metadata.len(), 0);
        assert_eq!(held_metadata.len(), 0);
        assert_ne!(
            (artifact_metadata.dev(), artifact_metadata.ino()),
            (held_metadata.dev(), held_metadata.ino())
        );

        let Err(failure) = failure.retry_cleanup() else {
            panic!("regular replacement must keep creator-FD retry custody")
        };
        assert!(fs::symlink_metadata(&artifact)?.is_file());
        assert!(fs::symlink_metadata(&held)?.is_file());
        assert!(fs::symlink_metadata(&final_path).is_err());

        fs::remove_file(&artifact)?;
        fs::rename(&held, &artifact)?;
        let abandonment = failure.retry_cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(fs::symlink_metadata(&final_path).is_err());
        Ok(())
    }

    #[test]
    fn authenticated_projection_revalidates_immediately_before_first_named_effect() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, retained) =
            authenticated_single_regular_projection(temp.path(), "pre-effect-spool-drift")?;
        retained.transaction.spool.write_all_at(b"BBB", 0)?;

        let error = expect_error(retained.materialize_private());
        assert!(
            format!("{error:#}").contains("physical OCI rootfs regular extent digest changed"),
            "{error:#}"
        );
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn private_materialization_refuses_occupied_staging_name_without_modification() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (first_final_path, first_retained) =
            authenticated_single_regular_projection(temp.path(), "occupied-physical-staging")?;
        let first_materialized = first_retained.materialize_private()?;
        let during = directory_names(temp.path())?;
        let added = during.difference(&before).cloned().collect::<Vec<_>>();
        assert_eq!(added.len(), 1);
        let staging = temp.path().join(&added[0]);
        let first_abandonment = first_materialized.cleanup()?;
        assert!(first_abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!first_final_path.exists());

        fs::create_dir(&staging)?;
        fs::write(staging.join("sentinel"), b"owned elsewhere")?;
        let occupied = directory_names(temp.path())?;
        let (final_path, retained) =
            authenticated_single_regular_projection(temp.path(), "occupied-physical-staging")?;
        assert_eq!(final_path, first_final_path);

        let error = expect_error(retained.materialize_private());
        assert!(
            format!("{error:#}").contains(
                "reserved private OCI rootfs staging before retained projection validation is occupied"
            ),
            "{error:#}"
        );
        assert_eq!(fs::read(staging.join("sentinel"))?, b"owned elsewhere");
        assert_eq!(directory_names(temp.path())?, occupied);
        assert!(!final_path.exists());

        fs::remove_file(staging.join("sentinel"))?;
        fs::remove_dir(staging)?;
        assert_eq!(directory_names(temp.path())?, before);
        Ok(())
    }

    #[test]
    fn cleanup_refuses_unexpected_entry_and_returns_owned_retry_custody() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, retained) =
            authenticated_single_regular_projection(temp.path(), "cleanup-retry-custody")?;
        let materialized = retained.materialize_private()?;
        let during = directory_names(temp.path())?;
        let added = during.difference(&before).cloned().collect::<Vec<_>>();
        assert_eq!(added.len(), 1);
        let staging = temp.path().join(&added[0]);
        reopen_test_sealed_directory(&staging)?;
        fs::write(staging.join("sentinel"), b"owned elsewhere")?;
        reseal_test_directory(&staging)?;

        let Err(failure) = materialized.cleanup() else {
            panic!("unexpected entry must prevent owned cleanup")
        };
        assert!(
            format!("{failure:#}").contains("exceeds its authenticated inventory"),
            "{failure:#}"
        );
        assert_eq!(fs::read(staging.join("artifact"))?, b"AAA");
        assert_eq!(fs::read(staging.join("sentinel"))?, b"owned elsewhere");
        assert!(!final_path.exists());

        reopen_test_sealed_directory(&staging)?;
        fs::remove_file(staging.join("sentinel"))?;
        reseal_test_directory(&staging)?;
        let abandonment = failure.retry_cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn cleanup_refuses_same_name_identity_substitution_and_returns_owned_retry_custody()
    -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, retained) =
            authenticated_single_regular_projection(temp.path(), "cleanup-identity-substitution")?;
        let materialized = retained.materialize_private()?;
        let during = directory_names(temp.path())?;
        let added = during.difference(&before).cloned().collect::<Vec<_>>();
        assert_eq!(added.len(), 1);
        let staging = temp.path().join(&added[0]);
        let artifact = staging.join("artifact");
        let held_owned_artifact = temp.path().join("held-owned-artifact");
        let owned_metadata = fs::metadata(&artifact)?;

        reopen_test_sealed_directory(&staging)?;
        fs::rename(&artifact, &held_owned_artifact)?;
        fs::write(&artifact, b"AAA")?;
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o444))?;
        reseal_test_directory(&staging)?;
        let replacement_metadata = fs::metadata(&artifact)?;
        assert_ne!(
            (replacement_metadata.dev(), replacement_metadata.ino()),
            (owned_metadata.dev(), owned_metadata.ino())
        );

        let Err(failure) = materialized.cleanup() else {
            panic!("same-name identity substitution must prevent owned cleanup")
        };
        assert!(
            format!("{failure:#}")
                .contains("owned private OCI rootfs regular-file identity changed"),
            "{failure:#}"
        );
        assert_eq!(fs::read(&artifact)?, b"AAA");
        assert_eq!(fs::read(&held_owned_artifact)?, b"AAA");
        assert!(!final_path.exists());

        reopen_test_sealed_directory(&staging)?;
        fs::remove_file(&artifact)?;
        fs::rename(&held_owned_artifact, &artifact)?;
        reseal_test_directory(&staging)?;
        let abandonment = failure.retry_cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    fn sole_physical_staging_path(parent: &Path, before: &BTreeSet<OsString>) -> Result<PathBuf> {
        let during = directory_names(parent)?;
        let added = during.difference(before).cloned().collect::<Vec<_>>();
        anyhow::ensure!(
            added.len() == 1,
            "expected exactly one private staging root"
        );
        Ok(parent.join(&added[0]))
    }

    #[test]
    fn cleanup_refuses_physical_staging_root_identity_substitution_and_retries() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, retained) =
            authenticated_single_regular_projection(temp.path(), "staging-root-substitution")?;
        let materialized = retained.materialize_private()?;
        let staging = sole_physical_staging_path(temp.path(), &before)?;
        let held = temp.path().join("held-owned-staging-root");
        let owned_metadata = fs::symlink_metadata(&staging)?;

        fs::rename(&staging, &held)?;
        fs::create_dir(&staging)?;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))?;
        let replacement_metadata = fs::symlink_metadata(&staging)?;
        assert_ne!(
            (replacement_metadata.dev(), replacement_metadata.ino()),
            (owned_metadata.dev(), owned_metadata.ino())
        );

        let Err(failure) = materialized.cleanup() else {
            panic!("staging-root identity substitution must prevent cleanup")
        };
        assert!(format!("{failure:#}").contains("staging identity changed"));
        let Err(failure) = failure.retry_cleanup() else {
            panic!("staging-root replacement must remain outside retry custody")
        };
        assert!(fs::symlink_metadata(&staging)?.is_dir());
        assert_eq!(fs::read(held.join("artifact"))?, b"AAA");
        assert!(fs::symlink_metadata(&final_path).is_err());

        fs::remove_dir(&staging)?;
        fs::rename(&held, &staging)?;
        let abandonment = failure.retry_cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        Ok(())
    }

    #[test]
    fn cleanup_refuses_physical_directory_identity_substitution_and_retries() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, retained) =
            authenticated_mixed_projection(temp.path(), "directory-substitution")?;
        let materialized = retained.materialize_private()?;
        let staging = sole_physical_staging_path(temp.path(), &before)?;
        let directory = staging.join("bin");
        let held = temp.path().join("held-owned-materialized-directory");

        reopen_test_sealed_directory(&staging)?;
        fs::rename(&directory, &held)?;
        fs::create_dir(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o555))?;
        reseal_test_directory(&staging)?;
        let Err(failure) = materialized.cleanup() else {
            panic!("directory identity substitution must prevent cleanup")
        };
        assert!(format!("{failure:#}").contains("directory identity or mode changed"));
        let Err(failure) = failure.retry_cleanup() else {
            panic!("directory replacement must remain outside retry custody")
        };
        assert!(fs::symlink_metadata(&directory)?.is_dir());
        assert_eq!(fs::read(held.join("tool"))?, b"EXEC");
        assert_eq!(
            fs::read_link(held.join("tool-link"))?,
            PathBuf::from("tool")
        );
        assert!(fs::symlink_metadata(&final_path).is_err());

        reopen_test_sealed_directory(&staging)?;
        fs::remove_dir(&directory)?;
        fs::rename(&held, &directory)?;
        reseal_test_directory(&staging)?;
        let abandonment = failure.retry_cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        Ok(())
    }

    #[test]
    fn cleanup_refuses_physical_symbolic_link_identity_substitution_and_retries() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, retained) =
            authenticated_mixed_projection(temp.path(), "symbolic-link-substitution")?;
        let materialized = retained.materialize_private()?;
        let staging = sole_physical_staging_path(temp.path(), &before)?;
        let symbolic_link = staging.join("bin/tool-link");
        let held = temp.path().join("held-owned-materialized-symbolic-link");
        let directory = staging.join("bin");

        reopen_test_sealed_directory(&directory)?;
        fs::rename(&symbolic_link, &held)?;
        std::os::unix::fs::symlink("tool", &symbolic_link)?;
        reseal_test_directory(&directory)?;
        let Err(failure) = materialized.cleanup() else {
            panic!("symbolic-link identity substitution must prevent cleanup")
        };
        assert!(format!("{failure:#}").contains("symbolic-link identity changed"));
        let Err(failure) = failure.retry_cleanup() else {
            panic!("symbolic-link replacement must remain outside retry custody")
        };
        assert_eq!(fs::read_link(&symbolic_link)?, PathBuf::from("tool"));
        assert_eq!(fs::read_link(&held)?, PathBuf::from("tool"));
        assert!(fs::symlink_metadata(&final_path).is_err());

        reopen_test_sealed_directory(&directory)?;
        fs::remove_file(&symbolic_link)?;
        fs::rename(&held, &symbolic_link)?;
        reseal_test_directory(&directory)?;
        let abandonment = failure.retry_cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        Ok(())
    }

    #[test]
    fn physical_boundary_final_occupation_before_materialization_is_nonmutating() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (final_path, retained) =
            authenticated_single_regular_projection(temp.path(), "late-physical-final")?;
        fs::write(&final_path, b"owned elsewhere")?;
        let occupied = directory_names(temp.path())?;

        let error = expect_error(retained.materialize_private());
        assert!(
            format!("{error:#}").contains("final destination"),
            "{error:#}"
        );
        assert_eq!(fs::read(&final_path)?, b"owned elsewhere");
        assert_eq!(directory_names(temp.path())?, occupied);

        fs::remove_file(&final_path)?;
        assert!(directory_names(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn physical_boundary_parent_substitution_before_materialization_is_nonmutating() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let nominal_parent = temp.path().join("nominal-physical-parent");
        let retained_parent = temp.path().join("retained-physical-parent");
        fs::create_dir(&nominal_parent)?;
        let (final_path, retained) =
            authenticated_single_regular_projection(&nominal_parent, "rootfs")?;
        fs::rename(&nominal_parent, &retained_parent)?;
        fs::create_dir(&nominal_parent)?;
        fs::write(nominal_parent.join("sentinel"), b"lure")?;
        let retained_before = directory_names(&retained_parent)?;

        let error = expect_error(retained.materialize_private());
        assert!(format!("{error:#}").contains("path"), "{error:#}");
        assert_eq!(fs::read(nominal_parent.join("sentinel"))?, b"lure");
        assert_eq!(directory_names(&retained_parent)?, retained_before);
        assert!(fs::symlink_metadata(&final_path).is_err());

        fs::remove_file(nominal_parent.join("sentinel"))?;
        fs::remove_dir(&nominal_parent)?;
        fs::remove_dir(&retained_parent)?;
        Ok(())
    }

    #[test]
    fn physical_boundary_final_occupation_before_cleanup_is_recoverable() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, retained) =
            authenticated_single_regular_projection(temp.path(), "cleanup-final-occupation")?;
        let materialized = retained.materialize_private()?;
        let staging = sole_physical_staging_path(temp.path(), &before)?;
        fs::write(&final_path, b"owned elsewhere")?;

        let Err(failure) = materialized.cleanup() else {
            panic!("final-name occupation must prevent physical cleanup")
        };
        assert!(format!("{failure:#}").contains("final destination"));
        assert_eq!(fs::read(&final_path)?, b"owned elsewhere");
        assert_eq!(fs::read(staging.join("artifact"))?, b"AAA");

        fs::remove_file(&final_path)?;
        let abandonment = failure.retry_cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        Ok(())
    }

    #[test]
    fn physical_boundary_parent_substitution_before_cleanup_is_recoverable() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let nominal_parent = temp.path().join("nominal-cleanup-parent");
        let retained_parent = temp.path().join("retained-cleanup-parent");
        fs::create_dir(&nominal_parent)?;
        let before = directory_names(&nominal_parent)?;
        let (final_path, retained) =
            authenticated_single_regular_projection(&nominal_parent, "rootfs")?;
        let materialized = retained.materialize_private()?;
        let staging = sole_physical_staging_path(&nominal_parent, &before)?;
        let staging_name = staging
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("private staging path has no file name"))?
            .to_os_string();

        fs::rename(&nominal_parent, &retained_parent)?;
        fs::create_dir(&nominal_parent)?;
        fs::write(nominal_parent.join("sentinel"), b"lure")?;
        let Err(failure) = materialized.cleanup() else {
            panic!("parent substitution must prevent physical cleanup")
        };
        let Err(failure) = failure.retry_cleanup() else {
            panic!("parent lure must remain outside retry custody")
        };
        assert_eq!(fs::read(nominal_parent.join("sentinel"))?, b"lure");
        assert_eq!(
            fs::read(retained_parent.join(&staging_name).join("artifact"))?,
            b"AAA"
        );
        assert!(fs::symlink_metadata(&final_path).is_err());

        fs::remove_file(nominal_parent.join("sentinel"))?;
        fs::remove_dir(&nominal_parent)?;
        fs::rename(&retained_parent, &nominal_parent)?;
        let abandonment = failure.retry_cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(&nominal_parent)?, before);
        Ok(())
    }

    #[test]
    fn cleanup_retry_never_unlinks_a_post_unlink_replacement() -> Result<()> {
        use super::physical::TestOnlyPrivateMaterializationFailpointV1 as Failpoint;

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, mut retained) =
            authenticated_single_regular_projection(temp.path(), "post-root-unlink-retry")?;
        retained.test_only_physical_materialization_failpoint =
            Some(Failpoint::StagingRootUnlinked);
        let materialized = retained.materialize_private()?;
        let during = directory_names(temp.path())?;
        let added = during.difference(&before).cloned().collect::<Vec<_>>();
        assert_eq!(added.len(), 1);
        let staging = temp.path().join(&added[0]);
        let owned_metadata = fs::symlink_metadata(&staging)?;

        let Err(failure) = materialized.cleanup() else {
            panic!("post-root-unlink failpoint must retain retry custody")
        };
        assert!(
            format!("{failure:#}").contains("StagingRootUnlinked"),
            "{failure:#}"
        );
        assert!(fs::symlink_metadata(&staging).is_err());

        fs::create_dir(&staging)?;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))?;
        let replacement_metadata = fs::symlink_metadata(&staging)?;
        assert_ne!(
            (replacement_metadata.dev(), replacement_metadata.ino()),
            (owned_metadata.dev(), owned_metadata.ino())
        );
        let Err(failure) = failure.retry_cleanup() else {
            panic!("post-unlink replacement must remain outside retry custody")
        };
        assert!(
            format!("{failure:#}").contains("staging after cleanup retry is occupied"),
            "{failure:#}"
        );
        let preserved_metadata = fs::symlink_metadata(&staging)?;
        assert_eq!(
            (preserved_metadata.dev(), preserved_metadata.ino()),
            (replacement_metadata.dev(), replacement_metadata.ino())
        );
        assert!(fs::symlink_metadata(&final_path).is_err());

        fs::remove_dir(&staging)?;
        let abandonment = failure.retry_cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(fs::symlink_metadata(&final_path).is_err());
        Ok(())
    }

    #[test]
    fn unlinked_staging_retry_reauthenticates_mount_namespace() -> Result<()> {
        use super::physical::TestOnlyPrivateMaterializationFailpointV1 as Failpoint;

        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, mut retained) =
            authenticated_single_regular_projection(temp.path(), "unlinked-retry-namespace")?;
        retained.test_only_physical_materialization_failpoint =
            Some(Failpoint::StagingRootUnlinkedWithNextMountNamespaceMismatch);
        let materialized = retained.materialize_private()?;
        let during = directory_names(temp.path())?;
        let added = during.difference(&before).cloned().collect::<Vec<_>>();
        assert_eq!(added.len(), 1);
        let staging = temp.path().join(&added[0]);

        let Err(failure) = materialized.cleanup() else {
            panic!("post-unlink namespace failpoint must retain retry custody")
        };
        assert!(fs::symlink_metadata(&staging).is_err());
        let Err(failure) = failure.retry_cleanup() else {
            panic!("unlinked-staging retry must reauthenticate the mount namespace")
        };
        assert!(
            format!("{failure:#}").contains("calling-thread mount namespace changed"),
            "{failure:#}"
        );
        assert!(fs::symlink_metadata(&staging).is_err());

        let abandonment = failure.retry_cleanup()?;
        assert!(abandonment.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(fs::symlink_metadata(&final_path).is_err());
        Ok(())
    }

    #[test]
    fn inherited_setgid_group_is_accepted_only_while_the_baseline_is_stable() {
        let identity = super::FileIdentity {
            device: 5,
            inode: 11,
            mount_id: 17,
        };
        let observed = super::FileObservation {
            identity,
            byte_length: 0,
            hard_link_count: 0,
            mode: super::PRIVATE_SPOOL_MODE.bits(),
            owner: 1_000,
            group: 4_242,
            modification_time_seconds: 0,
            modification_time_nanoseconds: 0,
        };
        super::validate_spool_custody_observation(&observed, identity, 17, 1_000, 4_242).unwrap();

        let changed_group = super::FileObservation {
            group: 4_243,
            ..observed
        };
        assert!(
            super::validate_spool_custody_observation(&changed_group, identity, 17, 1_000, 4_242,)
                .unwrap_err()
                .to_string()
                .contains("ownership changed")
        );
    }

    #[test]
    fn anonymous_spool_never_creates_or_accepts_a_namespace_entry() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, former_staging, layout) = projected(temp.path(), "anonymous")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;

        let opened = transaction.anonymous_spool_observation()?;
        assert_eq!(opened.hard_link_count, 0);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!former_staging.exists());

        let proc_link_flags = rustix::fs::AtFlags::SYMLINK_FOLLOW;
        assert!(!proc_link_flags.contains(rustix::fs::AtFlags::EMPTY_PATH));
        let linkable_descriptor = rustix::fs::openat2(
            transaction.parent.descriptor(),
            ".",
            super::ANONYMOUS_SPOOL_FLAGS.difference(rustix::fs::OFlags::EXCL),
            super::PRIVATE_SPOOL_MODE,
            super::ANONYMOUS_SPOOL_RESOLVE_FLAGS,
        )?;
        let linkable = File::from(linkable_descriptor);
        assert_eq!(
            super::regular_file_observation(&linkable)?.hard_link_count,
            0
        );
        let linkable_proc_path = format!("/proc/self/fd/{}", DecInt::from_fd(&linkable).as_str());
        rustix::fs::linkat(
            rustix::fs::CWD,
            linkable_proc_path.as_str(),
            transaction.parent.descriptor(),
            "linkable-control",
            proc_link_flags,
        )?;
        assert_eq!(
            super::regular_file_observation(&linkable)?.hard_link_count,
            1
        );
        assert!(temp.path().join("linkable-control").is_file());
        fs::remove_file(temp.path().join("linkable-control"))?;
        assert_eq!(
            super::regular_file_observation(&linkable)?.hard_link_count,
            0
        );

        let protected_proc_path = format!(
            "/proc/self/fd/{}",
            DecInt::from_fd(&transaction.spool).as_str()
        );
        let link_error = rustix::fs::linkat(
            rustix::fs::CWD,
            protected_proc_path.as_str(),
            transaction.parent.descriptor(),
            "forbidden-link",
            proc_link_flags,
        )
        .expect_err("O_TMPFILE|O_EXCL spool unexpectedly accepted a hard link");
        assert_eq!(link_error, rustix::io::Errno::NOENT);
        assert_eq!(
            transaction.anonymous_spool_observation()?.hard_link_count,
            0
        );
        assert!(!temp.path().join("forbidden-link").exists());
        assert_eq!(directory_names(temp.path())?, before);

        transaction.begin_root_regular("artifact", 0o444, 3)?;
        transaction.write_regular_chunk(b"abc")?;
        transaction.finish_entry()?;
        let finished = transaction.anonymous_spool_observation()?;
        assert_eq!(finished.identity, opened.identity);
        assert_eq!(finished.hard_link_count, 0);
        assert_eq!(directory_names(temp.path())?, before);

        let abandoned = discard_single_layer(transaction)?;
        assert_eq!(abandoned.spool_identity, opened.identity);
        assert!(abandoned.final_unlinked_observed);
        assert!(abandoned.final_observation_error.is_none());
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn root_regular_stream_is_bounded_digest_bound_and_abandon_only() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let before = directory_names(temp.path())?;
        let (final_path, former_staging, layout) = projected(temp.path(), "rootfs-a")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        assert_eq!(transaction.role, PositiveRunnerRole::RustValidatorBuild);
        assert!(!final_path.exists());

        let mut payload = vec![0x5a; OCI_REPLAY_CHUNK_MAX_BYTES];
        payload.extend_from_slice(b"tail");
        transaction.begin_root_regular("artifact", 0o444, u64::try_from(payload.len())?)?;
        transaction.write_regular_chunk(&payload[..OCI_REPLAY_CHUNK_MAX_BYTES])?;
        transaction.write_regular_chunk(&payload[OCI_REPLAY_CHUNK_MAX_BYTES..])?;
        transaction.finish_entry()?;
        transaction.begin_root_regular("executable", 0o555, 0)?;
        transaction.finish_entry()?;

        assert_eq!(transaction.read_completed_regular("artifact")?, payload);
        assert_eq!(
            transaction.read_completed_regular("executable")?,
            Vec::<u8>::new()
        );
        let artifact = transaction.completed_live_regular("artifact")?;
        assert_eq!(artifact.mode, 0o444);
        let expected_artifact_sha256: [u8; 32] = Sha256::digest(&payload).into();
        assert_eq!(artifact.sha256, expected_artifact_sha256);
        let executable = transaction.completed_live_regular("executable")?;
        assert_eq!(executable.mode, 0o555);
        assert_eq!(executable.offset, u64::try_from(payload.len())?);
        let expected_empty_sha256: [u8; 32] = Sha256::digest([]).into();
        assert_eq!(executable.sha256, expected_empty_sha256);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!former_staging.exists());

        let abandoned = discard_single_layer(transaction)?;
        assert_eq!(abandoned.role, PositiveRunnerRole::RustValidatorBuild);
        assert_eq!(abandoned.completed_physical_regular_extents, 2);
        assert_eq!(
            abandoned.completed_physical_regular_bytes,
            u64::try_from(payload.len())?
        );
        assert_eq!(abandoned.live_regular_files, 2);
        assert_eq!(abandoned.live_regular_bytes, u64::try_from(payload.len())?);
        assert!(abandoned.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, before);
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn zero_length_extents_are_validated_in_physical_append_order() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "zero-order")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        transaction.begin_root_regular("a-empty", 0o444, 0)?;
        transaction.finish_entry()?;
        transaction.begin_root_regular("z-data", 0o444, 3)?;
        transaction.write_regular_chunk(b"abc")?;
        transaction.finish_entry()?;

        assert_eq!(transaction.physical_regular_extents[0].offset, 0);
        assert_eq!(transaction.physical_regular_extents[1].offset, 0);
        let abandoned = discard_single_layer(transaction)?;
        assert_eq!(abandoned.completed_physical_regular_extents, 2);
        assert_eq!(abandoned.completed_physical_regular_bytes, 3);
        assert_eq!(abandoned.live_regular_files, 2);
        assert_eq!(abandoned.live_regular_bytes, 3);
        assert!(directory_names(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn regular_overwrite_separates_physical_and_live_state() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "overwrite")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 3)?;
        for (layer, payload) in [b"old".as_slice(), b"".as_slice(), b"new".as_slice()]
            .into_iter()
            .enumerate()
        {
            transaction.begin_regular(
                source(u64::try_from(layer)?, 0),
                "artifact",
                0o444,
                u64::try_from(payload.len())?,
            )?;
            if !payload.is_empty() {
                transaction.write_regular_chunk(payload)?;
            }
            transaction.finish_entry()?;
            transaction.seal_semantic_layer(u64::try_from(layer)?, 1)?;
        }

        assert_eq!(transaction.read_completed_regular("artifact")?, b"new");
        assert_eq!(
            transaction
                .physical_regular_extents
                .iter()
                .map(|extent| extent.offset)
                .collect::<Vec<_>>(),
            [0, 3, 3]
        );
        let abandoned = transaction.discard()?;
        assert_eq!(abandoned.completed_physical_regular_extents, 3);
        assert_eq!(abandoned.completed_physical_regular_bytes, 6);
        assert_eq!(abandoned.live_regular_files, 1);
        assert_eq!(abandoned.live_regular_bytes, 3);
        assert!(directory_names(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn superseded_physical_extent_tamper_is_still_detected() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "superseded-tamper")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 2)?;
        for (layer, payload) in [b"old".as_slice(), b"new".as_slice()]
            .into_iter()
            .enumerate()
        {
            transaction.begin_regular(source(u64::try_from(layer)?, 0), "artifact", 0o444, 3)?;
            transaction.write_regular_chunk(payload)?;
            transaction.finish_entry()?;
            transaction.seal_semantic_layer(u64::try_from(layer)?, 1)?;
        }
        assert_eq!(transaction.read_completed_regular("artifact")?, b"new");
        assert_eq!(transaction.spool.write_at(b"x", 0)?, 1);

        let failure = transaction.discard().unwrap_err();
        assert!(format!("{failure:#}").contains("physical OCI rootfs regular extent digest"));
        assert!(failure.abandonment.final_unlinked_observed);
        assert!(directory_names(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn source_index_must_point_to_its_exact_physical_operation() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "stale-live-map")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 2)?;
        for (layer, payload) in [b"old".as_slice(), b"new".as_slice()]
            .into_iter()
            .enumerate()
        {
            transaction.begin_regular(source(u64::try_from(layer)?, 0), "artifact", 0o444, 3)?;
            transaction.write_regular_chunk(payload)?;
            transaction.finish_entry()?;
            transaction.seal_semantic_layer(u64::try_from(layer)?, 1)?;
        }
        transaction.operations_by_source[1][0] = 0;

        let failure = transaction.discard().unwrap_err();
        assert!(format!("{failure:#}").contains("names a different physical operation"));
        assert!(failure.abandonment.final_unlinked_observed);
        assert!(directory_names(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn chunk_segmentation_has_one_destination_digest() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (_, _, layout_a) = projected(temp.path(), "segmentation-a")?;
        let (_, _, layout_b) = projected(temp.path(), "segmentation-b")?;
        let mut a = PrivateOciRootfsStagingTransactionV1::begin(layout_a, 1)?;
        let mut b = PrivateOciRootfsStagingTransactionV1::begin(layout_b, 1)?;
        a.begin_root_regular("artifact", 0o444, 6)?;
        a.write_regular_chunk(b"abcdef")?;
        a.finish_entry()?;
        b.begin_root_regular("artifact", 0o444, 6)?;
        for chunk in [b"a".as_slice(), b"bc", b"def"] {
            b.write_regular_chunk(chunk)?;
        }
        b.finish_entry()?;
        assert_eq!(
            a.completed_live_regular("artifact")?.sha256,
            b.completed_live_regular("artifact")?.sha256
        );
        let _ = discard_single_layer(a)?;
        let _ = discard_single_layer(b)?;
        assert!(directory_names(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn short_extra_empty_and_oversized_streams_poison_then_abandon() -> Result<()> {
        let temp = tempfile::tempdir()?;

        let (_, _, short_layout) = projected(temp.path(), "short")?;
        let mut short = PrivateOciRootfsStagingTransactionV1::begin(short_layout, 1)?;
        short.begin_root_regular("artifact", 0o444, 3)?;
        short.write_regular_chunk(b"ab")?;
        assert!(
            short
                .finish_entry()
                .unwrap_err()
                .to_string()
                .contains("ended before")
        );
        assert!(short.poisoned);
        assert!(
            short
                .write_regular_chunk(b"c")
                .unwrap_err()
                .to_string()
                .contains("poisoned")
        );
        let abandoned = short.abandon();
        assert!(abandoned.final_unlinked_observed);

        let (_, _, extra_layout) = projected(temp.path(), "extra")?;
        let mut extra = PrivateOciRootfsStagingTransactionV1::begin(extra_layout, 1)?;
        extra.begin_root_regular("artifact", 0o444, 1)?;
        assert!(
            extra
                .write_regular_chunk(b"ab")
                .unwrap_err()
                .to_string()
                .contains("more bytes")
        );
        assert!(extra.poisoned);
        let abandoned = extra.abandon();
        assert!(abandoned.final_unlinked_observed);

        let (_, _, empty_layout) = projected(temp.path(), "empty-chunk")?;
        let mut empty = PrivateOciRootfsStagingTransactionV1::begin(empty_layout, 1)?;
        empty.begin_root_regular("artifact", 0o444, 1)?;
        assert!(
            empty
                .write_regular_chunk(&[])
                .unwrap_err()
                .to_string()
                .contains("streaming range")
        );
        assert!(empty.poisoned);
        assert_eq!(empty.anonymous_spool_observation()?.byte_length, 0);
        let abandoned = empty.abandon();
        assert!(abandoned.final_unlinked_observed);

        let (_, _, large_layout) = projected(temp.path(), "large-chunk")?;
        let mut large = PrivateOciRootfsStagingTransactionV1::begin(large_layout, 1)?;
        large.begin_root_regular(
            "artifact",
            0o444,
            u64::try_from(OCI_REPLAY_CHUNK_MAX_BYTES + 1)?,
        )?;
        assert!(
            large
                .write_regular_chunk(&vec![0_u8; OCI_REPLAY_CHUNK_MAX_BYTES + 1])
                .unwrap_err()
                .to_string()
                .contains("streaming range")
        );
        assert!(large.poisoned);
        assert_eq!(large.anonymous_spool_observation()?.byte_length, 0);
        let abandoned = large.abandon();
        assert!(abandoned.final_unlinked_observed);
        assert!(directory_names(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn invalid_paths_modes_lengths_and_state_transitions_fail_closed() -> Result<()> {
        let temp = tempfile::tempdir()?;
        for (final_name, path, mode, length, expected) in [
            ("nested", "dir//file", 0o444, 0, "canonical"),
            ("dot", ".", 0o444, 0, "canonical"),
            ("mode", "artifact", 0o644, 0, "0444/0555"),
            (
                "length",
                "artifact",
                0o444,
                1_073_741_825,
                "layer regular-file payload",
            ),
        ] {
            let (_, _, layout) = projected(temp.path(), final_name)?;
            let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
            let error = transaction
                .begin_root_regular(path, mode, length)
                .unwrap_err();
            assert!(error.to_string().contains(expected), "{error:#}");
            assert!(transaction.poisoned);
            let abandoned = transaction.abandon();
            assert!(abandoned.final_unlinked_observed);
        }

        let (_, _, layout) = projected(temp.path(), "state")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        assert!(
            transaction
                .finish_entry()
                .unwrap_err()
                .to_string()
                .contains("no open entry")
        );
        assert!(transaction.poisoned);
        let abandoned = transaction.abandon();
        assert!(abandoned.final_unlinked_observed);

        let (_, _, layout) = projected(temp.path(), "double-finish")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        transaction.begin_root_regular("artifact", 0o444, 0)?;
        transaction.finish_entry()?;
        assert!(
            transaction
                .finish_entry()
                .unwrap_err()
                .to_string()
                .contains("no open entry")
        );
        assert!(transaction.poisoned);
        let abandoned = transaction.abandon();
        assert!(abandoned.final_unlinked_observed);
        assert!(directory_names(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn occupied_final_and_unrelated_names_are_never_modified() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (final_path, former_staging, layout) = projected(temp.path(), "occupied-final")?;
        fs::write(&final_path, b"sentinel")?;
        assert!(
            expect_error(PrivateOciRootfsStagingTransactionV1::begin(layout, 1))
                .to_string()
                .contains("final destination is occupied")
        );
        assert_eq!(fs::read(&final_path)?, b"sentinel");
        fs::remove_file(&final_path)?;

        fs::create_dir(&former_staging)?;
        fs::write(former_staging.join("sentinel"), b"owned elsewhere")?;
        let (_, _, layout) = projected(temp.path(), "unrelated-name")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        transaction.begin_root_regular("artifact", 0o444, 0)?;
        transaction.finish_entry()?;
        let _ = discard_single_layer(transaction)?;
        assert_eq!(
            fs::read(former_staging.join("sentinel"))?,
            b"owned elsewhere"
        );

        let (final_path, _, layout) = projected(temp.path(), "late-final")?;
        let target = temp.path().join("outside-target");
        fs::write(&target, b"outside")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        std::os::unix::fs::symlink(&target, &final_path)?;
        transaction.begin_root_regular("artifact", 0o444, 0)?;
        transaction.finish_entry()?;
        let failure = discard_single_layer(transaction)
            .expect_err("late final-name occupation accepted a completed candidate");
        let message = format!("{failure:#}");
        assert!(message.contains("final destination"), "{message}");
        assert!(message.contains("is occupied"), "{message}");
        assert!(failure.abandonment.final_unlinked_observed);
        assert_eq!(fs::read(&target)?, b"outside");
        assert!(final_path.symlink_metadata().is_ok());

        fs::remove_file(&final_path)?;
        fs::remove_file(&target)?;
        fs::remove_file(former_staging.join("sentinel"))?;
        fs::remove_dir(&former_staging)?;
        Ok(())
    }

    #[test]
    fn nominal_parent_substitution_cannot_redirect_spool_and_fails_candidate_boundary() -> Result<()>
    {
        let temp = tempfile::tempdir()?;
        let nominal_parent = temp.path().join("nominal-parent");
        let retained_parent = temp.path().join("retained-parent");
        fs::create_dir(&nominal_parent)?;
        let (_, _, layout) = projected(&nominal_parent, "rootfs")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        transaction.begin_root_regular("artifact", 0o444, 3)?;
        transaction.write_regular_chunk(b"a")?;

        fs::rename(&nominal_parent, &retained_parent)?;
        fs::create_dir(&nominal_parent)?;
        fs::write(nominal_parent.join("sentinel"), b"lure")?;
        transaction.write_regular_chunk(b"bc")?;
        transaction.finish_entry()?;
        let observation = transaction.anonymous_spool_observation()?;
        assert_eq!(observation.byte_length, 3);
        let mut retained = [0_u8; 3];
        assert_eq!(transaction.spool.read_at(&mut retained, 0)?, 3);
        assert_eq!(&retained, b"abc");
        let failure = discard_single_layer(transaction)
            .expect_err("nominal parent substitution accepted a completed candidate");
        let message = format!("{failure:#}");
        assert!(message.contains("path"), "{message}");
        assert!(failure.abandonment.final_unlinked_observed);
        assert!(failure.abandonment.final_observation_error.is_none());
        assert_eq!(fs::read(nominal_parent.join("sentinel"))?, b"lure");
        assert!(directory_names(&retained_parent)?.is_empty());

        fs::remove_file(nominal_parent.join("sentinel"))?;
        fs::remove_dir(&nominal_parent)?;
        fs::remove_dir(&retained_parent)?;
        Ok(())
    }

    #[test]
    fn error_abandonment_skips_candidate_io_and_preserves_primary() -> Result<()> {
        let source_text = include_str!("rootfs.rs").replace("\r\n", "\n");
        let (production, _tests) = source_text
            .split_once("#[cfg(test)]\nmod tests {")
            .expect("terminal rootfs test-module boundary");
        let (_, discard_after_tail) = production
            .split_once("    fn discard_after(self, primary: anyhow::Error)")
            .expect("discard_after body");
        let (discard_after, _) = discard_after_tail
            .split_once("\n    fn validate_completed_candidate")
            .expect("discard_after end sentinel");
        let (_, abandon_tail) = production
            .split_once("    fn abandon(self)")
            .expect("abandon body");
        let (abandon, _) = abandon_tail
            .split_once("\n    fn pre_effect_check")
            .expect("abandon end sentinel");
        for forbidden in [
            ".sync_all()",
            "digest_extent(",
            "validate_spooled_projection(",
            ".reauthenticate()",
            "ensure_absent(",
            ".read_at(",
        ] {
            assert!(
                !discard_after.contains(forbidden) && !abandon.contains(forbidden),
                "error abandonment performs forbidden candidate I/O: {forbidden}"
            );
        }

        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "error-abandonment")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        transaction.begin_root_regular("completed", 0o444, 3)?;
        transaction.write_regular_chunk(b"abc")?;
        transaction.finish_entry()?;
        transaction.begin_root_regular("artifact", 0o444, 3)?;
        transaction.write_regular_chunk(b"ab")?;
        assert!(
            transaction
                .finish_entry()
                .unwrap_err()
                .to_string()
                .contains("ended before")
        );
        assert!(transaction.poisoned);
        assert_eq!(transaction.spool.write_at(b"x", 0)?, 1);
        transaction.spool.set_len(99)?;

        let failure = transaction.discard_after(anyhow::anyhow!("primary replay failure"));
        let message = format!("{failure:#}");
        assert_eq!(message, "primary replay failure");
        assert!(failure.abandonment.final_unlinked_observed);
        assert!(failure.abandonment.final_observation_error.is_none());
        assert_eq!(failure.abandonment.completed_physical_regular_extents, 1);
        assert_eq!(failure.abandonment.completed_physical_regular_bytes, 3);
        assert_eq!(failure.abandonment.completed_operations, 1);
        assert!(failure.abandonment.validated_live_rootfs.is_none());
        assert_eq!(failure.abandonment.live_regular_files, 0);
        assert_eq!(failure.abandonment.live_regular_bytes, 0);
        assert!(directory_names(temp.path())?.is_empty());

        let (_, _, late_layout) = projected(temp.path(), "late-outer-error")?;
        let mut late = PrivateOciRootfsStagingTransactionV1::begin(late_layout, 1)?;
        stage_regular(&mut late, source(0, 0), "artifact", 0o444, b"abc")?;
        late.seal_semantic_layer(0, 1)?;
        assert!(!late.poisoned);
        assert_eq!(late.candidate_sync_calls.get(), 0);
        assert_eq!(late.candidate_extent_bytes_read.get(), 0);
        let failure = late.discard_after(anyhow::anyhow!("late outer CRC failure"));
        assert_eq!(format!("{failure:#}"), "late outer CRC failure");
        assert!(failure.abandonment.final_unlinked_observed);
        assert!(failure.abandonment.validated_live_rootfs.is_none());
        assert_eq!(failure.abandonment.completed_operations, 1);
        Ok(())
    }

    #[test]
    fn final_custody_anomaly_is_retained_without_losing_the_primary_error() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "custody-anomaly")?;
        let transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        rustix::fs::fchmod(
            transaction.spool.as_fd(),
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::RGRP,
        )?;

        let failure = transaction.discard_after(anyhow::anyhow!("primary replay failure"));
        let message = format!("{failure:#}");
        assert!(message.contains("primary replay failure"), "{message}");
        assert!(message.contains("mode 0600"), "{message}");
        assert!(!failure.abandonment.final_unlinked_observed);
        assert!(
            failure
                .abandonment
                .final_observation_error
                .as_deref()
                .is_some_and(|error| error.contains("mode 0600"))
        );
        assert!(directory_names(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn destination_tamper_and_extension_are_detected_before_abandonment() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "tamper-before-finish")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        transaction.begin_root_regular("artifact", 0o444, 3)?;
        transaction.write_regular_chunk(b"abc")?;
        assert_eq!(transaction.spool.write_at(b"x", 1)?, 1);
        transaction.finish_entry()?;
        transaction.seal_semantic_layer(0, 1)?;
        let failure = transaction.discard().unwrap_err();
        assert!(format!("{failure:#}").contains("digest"));
        assert!(failure.abandonment.final_unlinked_observed);

        let (_, _, layout) = projected(temp.path(), "tamper-after-finish")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        transaction.begin_root_regular("artifact", 0o444, 3)?;
        transaction.write_regular_chunk(b"abc")?;
        transaction.finish_entry()?;
        transaction.seal_semantic_layer(0, 1)?;
        assert_eq!(transaction.spool.write_at(b"x", 1)?, 1);
        let failure = transaction.discard().unwrap_err();
        assert!(format!("{failure:#}").contains("digest"));
        assert!(failure.abandonment.final_unlinked_observed);

        let (_, _, layout) = projected(temp.path(), "extension")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        transaction.begin_root_regular("artifact", 0o444, 3)?;
        transaction.write_regular_chunk(b"abc")?;
        transaction.finish_entry()?;
        transaction.seal_semantic_layer(0, 1)?;
        transaction.spool.set_len(4)?;
        let failure = transaction.discard().unwrap_err();
        assert!(format!("{failure:#}").contains("length changed"));
        assert!(failure.abandonment.final_unlinked_observed);
        assert!(directory_names(temp.path())?.is_empty());
        Ok(())
    }

    #[test]
    fn unsupported_tmpfile_mount_fails_without_a_named_fallback() -> Result<()> {
        let final_path = Path::new("/proc/eip0045-anonymous-spool-must-not-exist");
        assert!(!final_path.exists());
        let layout =
            OciRootfsStagingLayoutV1::project(PositiveRunnerRole::RustValidatorBuild, final_path)?;
        let error = expect_error(PrivateOciRootfsStagingTransactionV1::begin(layout, 1));
        assert!(format!("{error:#}").contains("O_TMPFILE|O_EXCL"));
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn semantic_layer_order_and_whiteout_effect_phase_drive_projection() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "semantic-journal")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 2)?;

        // Capture the upper layer first, in physical digest order. Its regular
        // entry sorts before the opaque marker in archive order, but the
        // whiteout must still affect only the lower snapshot before recreation.
        stage_regular(&mut transaction, source(1, 0), "d/!new", 0o444, b"new")?;
        transaction.stage_opaque_directory(source(1, 1), "d/.wh..wh..opq", 0, 0, "d")?;
        transaction.seal_semantic_layer(1, 2)?;

        transaction.stage_directory(source(0, 0), "d", 0o555, 0)?;
        stage_regular(&mut transaction, source(0, 1), "d/old", 0o444, b"old")?;
        transaction.seal_semantic_layer(0, 2)?;

        assert_eq!(transaction.read_completed_regular("d/!new")?, b"new");
        assert!(
            transaction
                .read_completed_regular("d/old")
                .unwrap_err()
                .to_string()
                .contains("absent")
        );
        let abandoned = transaction.discard()?;
        let counters = abandoned
            .validated_live_rootfs
            .expect("successful discard must retain validated live counters");
        assert_eq!(counters.entry_count, 2);
        assert_eq!(counters.regular_file_count, 1);
        assert_eq!(counters.directory_count, 1);
        assert_eq!(counters.symbolic_link_count, 0);
        assert_eq!(counters.regular_file_bytes, 3);
        Ok(())
    }

    #[test]
    fn whiteouts_require_the_lower_snapshot_and_allow_same_layer_recreation() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (_, _, missing_layout) = projected(temp.path(), "missing-whiteout")?;
        let mut missing = PrivateOciRootfsStagingTransactionV1::begin(missing_layout, 1)?;
        missing.stage_remove(source(0, 0), ".wh.x", 0, 0, "x")?;
        stage_regular(&mut missing, source(0, 1), "x", 0o444, b"new")?;
        missing.seal_semantic_layer(0, 2)?;
        let failure = missing
            .discard()
            .expect_err("same-layer recreation made an absent lower whiteout valid");
        assert!(format!("{failure:#}").contains("lower snapshot"));
        assert!(failure.abandonment.final_unlinked_observed);

        let (_, _, valid_layout) = projected(temp.path(), "valid-whiteout")?;
        let mut valid = PrivateOciRootfsStagingTransactionV1::begin(valid_layout, 2)?;
        valid.stage_remove(source(1, 0), ".wh.x", 0, 0, "x")?;
        stage_regular(&mut valid, source(1, 1), "x", 0o444, b"new")?;
        valid.seal_semantic_layer(1, 2)?;
        stage_regular(&mut valid, source(0, 0), "x", 0o444, b"old")?;
        valid.seal_semantic_layer(0, 1)?;
        assert_eq!(valid.read_completed_regular("x")?, b"new");
        let abandoned = valid.discard()?;
        assert_eq!(
            abandoned
                .validated_live_rootfs
                .expect("validated counters")
                .regular_file_bytes,
            3
        );
        Ok(())
    }

    #[test]
    fn root_opaque_clears_the_lower_snapshot_before_same_layer_recreation() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "root-opaque-recreation")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 2)?;
        stage_regular(&mut transaction, source(0, 0), "a", 0o444, b"old")?;
        transaction.stage_directory(source(0, 1), "d", 0o555, 0)?;
        stage_regular(&mut transaction, source(0, 2), "d/old", 0o444, b"old")?;
        transaction.stage_symbolic_link(source(0, 3), "z", 0o777, 0, "a")?;
        transaction.seal_semantic_layer(0, 4)?;

        transaction.stage_opaque_directory(source(1, 0), ".wh..wh..opq", 0, 0, "")?;
        transaction.stage_directory(source(1, 1), "d", 0o555, 0)?;
        stage_regular(&mut transaction, source(1, 2), "d/new", 0o444, b"new")?;
        transaction.seal_semantic_layer(1, 3)?;

        let projection = transaction.validate_spooled_projection()?;
        assert_eq!(
            projection.paths.keys().copied().collect::<Vec<_>>(),
            ["d", "d/new"]
        );
        assert_eq!(projection.counters.entry_count, 2);
        assert_eq!(projection.counters.regular_file_count, 1);
        assert_eq!(projection.counters.directory_count, 1);
        assert_eq!(projection.counters.symbolic_link_count, 0);
        assert_eq!(projection.counters.regular_file_bytes, 3);
        let abandoned = transaction.discard()?;
        assert!(abandoned.final_unlinked_observed);
        Ok(())
    }

    #[test]
    fn opaque_and_overlapping_whiteouts_fail_closed_against_the_lower_snapshot() -> Result<()> {
        let temp = tempfile::tempdir()?;

        let (_, _, absent_layout) = projected(temp.path(), "opaque-absent")?;
        let mut absent = PrivateOciRootfsStagingTransactionV1::begin(absent_layout, 1)?;
        absent.stage_opaque_directory(source(0, 0), "d/.wh..wh..opq", 0, 0, "d")?;
        absent.seal_semantic_layer(0, 1)?;
        assert!(format!("{:#}", absent.discard().unwrap_err()).contains("lower snapshot"));

        let (_, _, non_directory_layout) = projected(temp.path(), "opaque-nondirectory")?;
        let mut non_directory =
            PrivateOciRootfsStagingTransactionV1::begin(non_directory_layout, 2)?;
        stage_regular(&mut non_directory, source(0, 0), "x", 0o444, b"x")?;
        non_directory.seal_semantic_layer(0, 1)?;
        non_directory.stage_opaque_directory(source(1, 0), "x/.wh..wh..opq", 0, 0, "x")?;
        non_directory.seal_semantic_layer(1, 1)?;
        assert!(
            format!("{:#}", non_directory.discard().unwrap_err())
                .contains("not a lower-snapshot directory")
        );

        let (_, _, overlap_layout) = projected(temp.path(), "whiteout-overlap")?;
        let mut overlap = PrivateOciRootfsStagingTransactionV1::begin(overlap_layout, 2)?;
        overlap.stage_directory(source(0, 0), "d", 0o555, 0)?;
        stage_regular(&mut overlap, source(0, 1), "d/x", 0o444, b"x")?;
        overlap.seal_semantic_layer(0, 2)?;
        overlap.stage_remove(source(1, 0), ".wh.d", 0, 0, "d")?;
        overlap.stage_remove(source(1, 1), "d/.wh.x", 0, 0, "d/x")?;
        overlap.seal_semantic_layer(1, 2)?;
        assert!(
            format!("{:#}", overlap.discard().unwrap_err())
                .contains("intra-layer whiteout subtree")
        );
        Ok(())
    }

    #[test]
    fn named_directory_whiteout_is_component_aware_and_removes_its_subtree() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "named-directory-whiteout")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 2)?;
        transaction.stage_directory(source(0, 0), "a", 0o555, 0)?;
        stage_regular(&mut transaction, source(0, 1), "a/old", 0o444, b"old")?;
        stage_regular(&mut transaction, source(0, 2), "ab", 0o444, b"keep")?;
        transaction.seal_semantic_layer(0, 3)?;
        transaction.stage_remove(source(1, 0), ".wh.a", 0, 0, "a")?;
        transaction.seal_semantic_layer(1, 1)?;

        let projection = transaction.validate_spooled_projection()?;
        assert_eq!(projection.paths.keys().copied().collect::<Vec<_>>(), ["ab"]);
        assert_eq!(transaction.read_completed_regular("ab")?, b"keep");
        let counters = transaction
            .discard()?
            .validated_live_rootfs
            .expect("validated counters");
        assert_eq!(counters.entry_count, 1);
        assert_eq!(counters.regular_file_count, 1);
        assert_eq!(counters.regular_file_bytes, 4);
        Ok(())
    }

    #[test]
    fn typed_tree_projection_enforces_parents_and_directory_transitions() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "typed-transitions")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 2)?;
        transaction.stage_directory(source(0, 0), "d", 0o555, 0)?;
        transaction.stage_symbolic_link(source(0, 1), "d/link", 0o777, 0, "sub/file")?;
        transaction.stage_directory(source(0, 2), "d/sub", 0o555, 0)?;
        stage_regular(
            &mut transaction,
            source(0, 3),
            "d/sub/file",
            0o444,
            b"payload",
        )?;
        transaction.seal_semantic_layer(0, 4)?;

        // B4 permits a non-directory to replace a directory. The complete
        // prior subtree must disappear so no child remains beneath a file.
        stage_regular(&mut transaction, source(1, 0), "d", 0o555, b"top")?;
        transaction.seal_semantic_layer(1, 1)?;
        assert_eq!(transaction.read_completed_regular("d")?, b"top");
        assert!(
            transaction
                .read_completed_regular("d/sub/file")
                .unwrap_err()
                .to_string()
                .contains("absent")
        );
        let counters = transaction
            .discard()?
            .validated_live_rootfs
            .expect("validated counters");
        assert_eq!(counters.entry_count, 1);
        assert_eq!(counters.regular_file_count, 1);
        assert_eq!(counters.directory_count, 0);
        assert_eq!(counters.symbolic_link_count, 0);
        assert_eq!(counters.regular_file_bytes, 3);

        let (_, _, conflict_layout) = projected(temp.path(), "directory-conflict")?;
        let mut conflict = PrivateOciRootfsStagingTransactionV1::begin(conflict_layout, 2)?;
        stage_regular(&mut conflict, source(0, 0), "x", 0o444, b"x")?;
        conflict.seal_semantic_layer(0, 1)?;
        conflict.stage_directory(source(1, 0), "x", 0o555, 0)?;
        conflict.seal_semantic_layer(1, 1)?;
        assert!(format!("{:#}", conflict.discard().unwrap_err()).contains("type conflict"));

        let (_, _, parent_layout) = projected(temp.path(), "missing-parent")?;
        let mut parent = PrivateOciRootfsStagingTransactionV1::begin(parent_layout, 1)?;
        stage_regular(&mut parent, source(0, 0), "missing/child", 0o444, b"x")?;
        parent.seal_semantic_layer(0, 1)?;
        assert!(format!("{:#}", parent.discard().unwrap_err()).contains("parent directory"));
        Ok(())
    }

    #[test]
    fn whiteout_parent_and_opaque_symlink_cannot_host_incoming_children() -> Result<()> {
        let temp = tempfile::tempdir()?;

        let (_, _, removed_parent_layout) = projected(temp.path(), "removed-parent")?;
        let mut removed_parent =
            PrivateOciRootfsStagingTransactionV1::begin(removed_parent_layout, 2)?;
        removed_parent.stage_directory(source(0, 0), "d", 0o555, 0)?;
        stage_regular(&mut removed_parent, source(0, 1), "d/old", 0o444, b"old")?;
        removed_parent.seal_semantic_layer(0, 2)?;
        removed_parent.stage_remove(source(1, 0), ".wh.d", 0, 0, "d")?;
        stage_regular(&mut removed_parent, source(1, 1), "d/new", 0o444, b"new")?;
        removed_parent.seal_semantic_layer(1, 2)?;
        let failure = removed_parent.discard().unwrap_err();
        assert!(format!("{failure:#}").contains("parent directory"));
        assert!(failure.abandonment.final_unlinked_observed);

        let (_, _, opaque_symlink_layout) = projected(temp.path(), "opaque-symlink")?;
        let mut opaque_symlink =
            PrivateOciRootfsStagingTransactionV1::begin(opaque_symlink_layout, 2)?;
        opaque_symlink.stage_symbolic_link(source(0, 0), "d", 0o777, 0, "target")?;
        opaque_symlink.seal_semantic_layer(0, 1)?;
        opaque_symlink.stage_opaque_directory(source(1, 0), "d/.wh..wh..opq", 0, 0, "d")?;
        opaque_symlink.seal_semantic_layer(1, 1)?;
        let failure = opaque_symlink.discard().unwrap_err();
        assert!(format!("{failure:#}").contains("not a lower-snapshot directory"));
        assert!(failure.abandonment.final_unlinked_observed);

        let (_, _, link_overwrite_layout) = projected(temp.path(), "link-overwrite")?;
        let mut link_overwrite =
            PrivateOciRootfsStagingTransactionV1::begin(link_overwrite_layout, 2)?;
        link_overwrite.stage_symbolic_link(source(0, 0), "link", 0o777, 0, "old")?;
        link_overwrite.seal_semantic_layer(0, 1)?;
        link_overwrite.stage_symbolic_link(source(1, 0), "link", 0o777, 0, "new")?;
        link_overwrite.seal_semantic_layer(1, 1)?;
        let projection = link_overwrite.validate_spooled_projection()?;
        assert_eq!(projection.counters.symbolic_link_count, 1);
        assert_eq!(projection.counters.entry_count, 1);
        assert!(link_overwrite.discard()?.final_unlinked_observed);
        Ok(())
    }

    #[test]
    fn typed_transition_matrix_preserves_only_valid_live_definitions() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "typed-matrix")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 2)?;
        stage_regular(&mut transaction, source(0, 0), "a", 0o444, b"a")?;
        transaction.stage_symbolic_link(source(0, 1), "b", 0o777, 0, "a")?;
        transaction.stage_directory(source(0, 2), "c", 0o555, 0)?;
        stage_regular(&mut transaction, source(0, 3), "c/k", 0o444, b"c")?;
        transaction.stage_directory(source(0, 4), "d", 0o555, 0)?;
        stage_regular(&mut transaction, source(0, 5), "d/k", 0o444, b"d")?;
        transaction.seal_semantic_layer(0, 6)?;

        transaction.stage_symbolic_link(source(1, 0), "a", 0o777, 0, "b")?;
        stage_regular(&mut transaction, source(1, 1), "b", 0o444, b"b")?;
        transaction.stage_symbolic_link(source(1, 2), "c", 0o777, 0, "a")?;
        transaction.stage_directory(source(1, 3), "d", 0o555, 0)?;
        transaction.seal_semantic_layer(1, 4)?;

        let projection = transaction.validate_spooled_projection()?;
        assert_eq!(
            projection.paths.keys().copied().collect::<Vec<_>>(),
            ["a", "b", "c", "d", "d/k"]
        );
        assert_eq!(projection.counters.entry_count, 5);
        assert_eq!(projection.counters.regular_file_count, 2);
        assert_eq!(projection.counters.directory_count, 1);
        assert_eq!(projection.counters.symbolic_link_count, 2);
        assert_eq!(projection.counters.regular_file_bytes, 2);
        assert_eq!(transaction.read_completed_regular("b")?, b"b");
        assert_eq!(transaction.read_completed_regular("d/k")?, b"d");
        assert!(transaction.read_completed_regular("c/k").is_err());
        let abandoned = transaction.discard()?;
        assert!(abandoned.final_unlinked_observed);

        let (_, _, conflict_layout) = projected(temp.path(), "symlink-directory-conflict")?;
        let mut conflict = PrivateOciRootfsStagingTransactionV1::begin(conflict_layout, 2)?;
        conflict.stage_symbolic_link(source(0, 0), "x", 0o777, 0, "y")?;
        conflict.seal_semantic_layer(0, 1)?;
        conflict.stage_directory(source(1, 0), "x", 0o555, 0)?;
        conflict.seal_semantic_layer(1, 1)?;
        assert!(format!("{:#}", conflict.discard().unwrap_err()).contains("type conflict"));

        let (_, _, parent_layout) = projected(temp.path(), "symlink-parent")?;
        let mut parent = PrivateOciRootfsStagingTransactionV1::begin(parent_layout, 2)?;
        parent.stage_symbolic_link(source(0, 0), "x", 0o777, 0, "y")?;
        parent.seal_semantic_layer(0, 1)?;
        stage_regular(&mut parent, source(1, 0), "x/child", 0o444, b"x")?;
        parent.seal_semantic_layer(1, 1)?;
        assert!(format!("{:#}", parent.discard().unwrap_err()).contains("parent directory"));
        Ok(())
    }

    #[test]
    fn projection_effect_references_are_temporally_maximal() {
        let operations = vec![
            logical_operation(0, 0, "d", super::StagedRootfsOperationKindV1::Directory),
            logical_operation(1, 0, "d", super::StagedRootfsOperationKindV1::Directory),
            logical_operation(
                2,
                0,
                "d/.wh..wh..opq",
                super::StagedRootfsOperationKindV1::OpaqueDirectory {
                    path: "d".to_owned(),
                },
            ),
            logical_operation(
                3,
                0,
                "d/.wh..wh..opq",
                super::StagedRootfsOperationKindV1::OpaqueDirectory {
                    path: "d".to_owned(),
                },
            ),
        ];
        let newest_opaque =
            super::effect_reference(3, &operations[3], super::OciRootfsEffectPhaseV1::Whiteout);
        let mut projection = super::RootfsProjectionV1::default();
        projection.paths.insert(
            "d",
            super::RootfsPathProjectionV1 {
                live_definition: 1,
                last_effect: newest_opaque,
            },
        );
        super::validate_projection_effect_references(&projection, &operations).unwrap();

        projection.paths.get_mut("d").unwrap().last_effect =
            super::effect_reference(2, &operations[2], super::OciRootfsEffectPhaseV1::Whiteout);
        assert!(
            super::validate_projection_effect_references(&projection, &operations)
                .unwrap_err()
                .to_string()
                .contains("temporally maximal")
        );

        let state = projection.paths.get_mut("d").unwrap();
        state.live_definition = 0;
        state.last_effect = newest_opaque;
        assert!(
            super::validate_projection_effect_references(&projection, &operations)
                .unwrap_err()
                .to_string()
                .contains("temporally latest")
        );

        let same_layer = vec![
            logical_operation(0, 0, "d", super::StagedRootfsOperationKindV1::Directory),
            logical_operation(
                1,
                1,
                "d/.wh..wh..opq",
                super::StagedRootfsOperationKindV1::OpaqueDirectory {
                    path: "d".to_owned(),
                },
            ),
            logical_operation(1, 0, "d", super::StagedRootfsOperationKindV1::Directory),
        ];
        let mut same_layer_projection = super::RootfsProjectionV1::default();
        same_layer_projection.paths.insert(
            "d",
            super::RootfsPathProjectionV1 {
                live_definition: 2,
                last_effect: super::effect_reference(
                    2,
                    &same_layer[2],
                    super::OciRootfsEffectPhaseV1::Entry,
                ),
            },
        );
        super::validate_projection_effect_references(&same_layer_projection, &same_layer).unwrap();
        same_layer_projection
            .paths
            .get_mut("d")
            .unwrap()
            .last_effect =
            super::effect_reference(1, &same_layer[1], super::OciRootfsEffectPhaseV1::Whiteout);
        assert!(
            super::validate_projection_effect_references(&same_layer_projection, &same_layer)
                .unwrap_err()
                .to_string()
                .contains("temporally maximal")
        );
    }

    #[test]
    fn root_projection_effect_is_exactly_the_latest_root_opaque() {
        let operations = vec![
            logical_operation(
                0,
                0,
                ".wh..wh..opq",
                super::StagedRootfsOperationKindV1::OpaqueDirectory {
                    path: String::new(),
                },
            ),
            logical_operation(
                1,
                0,
                ".wh..wh..opq",
                super::StagedRootfsOperationKindV1::OpaqueDirectory {
                    path: String::new(),
                },
            ),
        ];
        let newest =
            super::effect_reference(1, &operations[1], super::OciRootfsEffectPhaseV1::Whiteout);
        let mut projection = super::RootfsProjectionV1 {
            root_last_effect: Some(newest),
            ..Default::default()
        };
        super::validate_projection_effect_references(&projection, &operations).unwrap();

        projection.root_last_effect = Some(super::effect_reference(
            0,
            &operations[0],
            super::OciRootfsEffectPhaseV1::Whiteout,
        ));
        assert!(
            super::validate_projection_effect_references(&projection, &operations)
                .unwrap_err()
                .to_string()
                .contains("latest root opaque")
        );
        projection.root_last_effect = None;
        assert!(
            super::validate_projection_effect_references(&projection, &operations)
                .unwrap_err()
                .to_string()
                .contains("latest root opaque")
        );
        super::validate_projection_effect_references(&super::RootfsProjectionV1::default(), &[])
            .unwrap();
    }

    #[test]
    fn semantic_layer_lifecycle_requires_exactly_one_seal_including_empty_layers() -> Result<()> {
        let temp = tempfile::tempdir()?;

        let (_, _, missing_layout) = projected(temp.path(), "missing-layer-seal")?;
        let mut missing = PrivateOciRootfsStagingTransactionV1::begin(missing_layout, 2)?;
        missing.seal_semantic_layer(0, 0)?;
        assert!(
            format!("{:#}", missing.discard().unwrap_err())
                .contains("not authenticated and sealed")
        );

        let (_, _, duplicate_layout) = projected(temp.path(), "duplicate-layer-seal")?;
        let mut duplicate = PrivateOciRootfsStagingTransactionV1::begin(duplicate_layout, 1)?;
        duplicate.seal_semantic_layer(0, 0)?;
        assert!(duplicate.seal_semantic_layer(0, 0).is_err());
        assert!(duplicate.poisoned);
        assert!(duplicate.abandon().final_unlinked_observed);

        let (_, _, empty_layout) = projected(temp.path(), "empty-layers")?;
        let mut empty = PrivateOciRootfsStagingTransactionV1::begin(empty_layout, 2)?;
        empty.seal_semantic_layer(0, 0)?;
        empty.seal_semantic_layer(1, 0)?;
        let counters = empty
            .discard()?
            .validated_live_rootfs
            .expect("validated empty counters");
        assert_eq!(counters, super::OciRootfsLiveCountersV1::default());

        let (_, _, capture_after_layout) = projected(temp.path(), "capture-after-seal")?;
        let mut capture_after =
            PrivateOciRootfsStagingTransactionV1::begin(capture_after_layout, 1)?;
        capture_after.seal_semantic_layer(0, 0)?;
        assert!(
            capture_after
                .stage_directory(source(0, 0), "d", 0o555, 0)
                .unwrap_err()
                .to_string()
                .contains("already sealed")
        );
        assert!(capture_after.poisoned);
        assert!(capture_after.abandon().final_unlinked_observed);

        let (_, _, open_layout) = projected(temp.path(), "seal-open-entry")?;
        let mut open = PrivateOciRootfsStagingTransactionV1::begin(open_layout, 1)?;
        open.begin_root_regular("a", 0o444, 1)?;
        assert!(
            open.seal_semantic_layer(0, 0)
                .unwrap_err()
                .to_string()
                .contains("open entry")
        );
        assert!(open.poisoned);
        assert!(open.abandon().final_unlinked_observed);

        let (_, _, count_layout) = projected(temp.path(), "seal-count-mismatch")?;
        let mut count = PrivateOciRootfsStagingTransactionV1::begin(count_layout, 1)?;
        count.stage_directory(source(0, 0), "d", 0o555, 0)?;
        assert!(
            count
                .seal_semantic_layer(0, 0)
                .unwrap_err()
                .to_string()
                .contains("captured entry count")
        );
        assert!(count.poisoned);
        assert!(count.abandon().final_unlinked_observed);

        let (_, _, outside_layout) = projected(temp.path(), "outside-layer-index")?;
        let mut outside = PrivateOciRootfsStagingTransactionV1::begin(outside_layout, 1)?;
        assert!(
            outside
                .stage_directory(source(1, 0), "d", 0o555, 0)
                .unwrap_err()
                .to_string()
                .contains("outside the authenticated manifest")
        );
        assert!(outside.poisoned);
        assert!(outside.abandon().final_unlinked_observed);

        let (_, _, gap_layout) = projected(temp.path(), "source-ordinal-gap")?;
        let mut gap = PrivateOciRootfsStagingTransactionV1::begin(gap_layout, 1)?;
        assert!(
            gap.stage_directory(source(0, 1), "d", 0o555, 0)
                .unwrap_err()
                .to_string()
                .contains("next archive entry")
        );
        assert!(gap.poisoned);
        assert!(gap.abandon().final_unlinked_observed);
        Ok(())
    }

    #[test]
    fn authenticated_layer_seal_rejects_equal_length_payload_drift() -> Result<()> {
        let pass_a = super::super::layer::test_only_authenticated_regular_layer_seal(
            0, "artifact", 0o444, b"AAA",
        )?;
        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "pass-a-rootfs-drift")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        stage_regular(&mut transaction, source(0, 0), "artifact", 0o444, b"BBB")?;

        let error = transaction
            .seal_authenticated_semantic_layer(pass_a)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "OCI rootfs changeset transcript differs from its authenticated layer seal"
        );
        assert!(transaction.poisoned);
        assert!(transaction.abandon().final_unlinked_observed);
        Ok(())
    }

    #[test]
    fn rootfs_replay_mapping_uses_the_shared_encoder_for_every_entry_kind() -> Result<()> {
        use super::super::layer::OciLayerReplayEntryV1;

        let temp = tempfile::tempdir()?;
        assert_shared_rootfs_transcript(
            temp.path(),
            "shared-regular",
            &OciLayerReplayEntryV1::regular_file("artifact", 0o444, 3),
            b"ABC",
            1,
            2,
        )?;
        assert_shared_rootfs_transcript(
            temp.path(),
            "shared-directory",
            &OciLayerReplayEntryV1::directory("dir", 0o555, 0),
            &[],
            1,
            1,
        )?;
        assert_shared_rootfs_transcript(
            temp.path(),
            "shared-symlink",
            &OciLayerReplayEntryV1::symbolic_link("link", 0o777, 0, "artifact"),
            &[],
            1,
            1,
        )?;
        assert_shared_rootfs_transcript(
            temp.path(),
            "shared-remove",
            &OciLayerReplayEntryV1::remove(".wh.old", 0, 0, "old"),
            &[],
            1,
            1,
        )?;
        assert_shared_rootfs_transcript(
            temp.path(),
            "shared-opaque",
            &OciLayerReplayEntryV1::opaque_directory(".wh..wh..opq", 0, 0, ""),
            &[],
            1,
            1,
        )?;
        Ok(())
    }

    #[test]
    fn authenticated_rootfs_retains_exact_final_projection_until_consumed() -> Result<()> {
        let seals = vec![
            super::super::layer::test_only_authenticated_regular_layer_seal(0, "a", 0o444, b"OLD")?,
            super::super::layer::test_only_authenticated_regular_layer_seal(
                1, "z", 0o444, b"KEEP",
            )?,
            super::super::layer::test_only_authenticated_regular_layer_seal(2, "a", 0o444, b"NEW")?,
        ];
        let temp = tempfile::tempdir()?;
        let parent_names = directory_names(temp.path())?;
        let (final_path, _, layout) = projected(temp.path(), "retained-final-projection")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 3)?;
        stage_regular(&mut transaction, source(0, 0), "a", 0o444, b"OLD")?;
        stage_regular(&mut transaction, source(1, 0), "z", 0o444, b"KEEP")?;
        stage_regular(&mut transaction, source(2, 0), "a", 0o444, b"NEW")?;

        let retained =
            transaction.authenticate_and_retain(seals, expected_rootfs(2, 2, 0, 0, 7))?;
        assert_eq!(
            retained.counters,
            OciRootfsLiveCountersV1 {
                entry_count: 2,
                regular_file_count: 2,
                directory_count: 0,
                symbolic_link_count: 0,
                regular_file_bytes: 7,
            }
        );
        assert_eq!(retained.canonical_live_operation_indices, [2, 1]);
        assert_eq!(
            hex::encode(retained.authenticated_logical_projection_sha256),
            "7ecbf305134639c84fb3ab14478b5c7b33df618fc015446d32b9e3b8a31e9b2e"
        );
        assert_eq!(
            retained
                .transaction
                .anonymous_spool_observation()?
                .hard_link_count,
            0
        );
        assert_eq!(directory_names(temp.path())?, parent_names);
        assert!(!final_path.exists());
        let authenticated_identity = retained.authenticated_logical_projection_sha256;
        let receipt = retained.abandon()?;
        assert!(
            receipt.final_unlinked_observed,
            "explicit affine abandonment did not observe the anonymous spool"
        );
        assert_eq!(receipt.authenticated_live_entries, Some(2));
        assert_eq!(
            receipt.authenticated_logical_projection_sha256,
            Some(authenticated_identity)
        );
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn authenticated_projection_excludes_whiteout_markers_from_owned_identity() -> Result<()> {
        let old_entry = OciLayerReplayEntryV1::regular_file("x", 0o444, 3);
        let remove_entry = OciLayerReplayEntryV1::remove(".wh.x", 0, 0, "x");
        let new_entry = OciLayerReplayEntryV1::regular_file("x", 0o444, 3);
        let with_history_seals = vec![
            authenticated_layer_seal(0, &[(&old_entry, b"old")])?,
            authenticated_layer_seal(1, &[(&remove_entry, &[]), (&new_entry, b"new")])?,
        ];
        let without_history_seal = authenticated_layer_seal(0, &[(&new_entry, b"new")])?;
        let temp = tempfile::tempdir()?;
        let parent_names = directory_names(temp.path())?;

        let (_, _, with_history_layout) = projected(temp.path(), "whiteout-history")?;
        let mut with_history = PrivateOciRootfsStagingTransactionV1::begin(with_history_layout, 2)?;
        stage_regular(&mut with_history, source(0, 0), "x", 0o444, b"old")?;
        with_history.stage_remove(source(1, 0), ".wh.x", 0, 0, "x")?;
        stage_regular(&mut with_history, source(1, 1), "x", 0o444, b"new")?;
        let with_history = with_history
            .authenticate_and_retain(with_history_seals, expected_rootfs(1, 1, 0, 0, 3))?;
        assert_eq!(with_history.canonical_live_operation_indices, [2]);
        let with_history_identity = with_history.authenticated_logical_projection_sha256;
        assert!(with_history.abandon()?.final_unlinked_observed);

        let (_, _, without_history_layout) = projected(temp.path(), "whiteout-free")?;
        let mut without_history =
            PrivateOciRootfsStagingTransactionV1::begin(without_history_layout, 1)?;
        stage_regular(&mut without_history, source(0, 0), "x", 0o444, b"new")?;
        let without_history = without_history
            .authenticate_and_retain(vec![without_history_seal], expected_rootfs(1, 1, 0, 0, 3))?;
        assert_eq!(without_history.canonical_live_operation_indices, [0]);
        assert_eq!(
            without_history.authenticated_logical_projection_sha256,
            with_history_identity
        );
        assert!(without_history.abandon()?.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, parent_names);
        Ok(())
    }

    #[test]
    fn authenticated_projection_excludes_opaque_markers_from_owned_identity() -> Result<()> {
        let old_entry = OciLayerReplayEntryV1::regular_file("x", 0o444, 3);
        let opaque_entry = OciLayerReplayEntryV1::opaque_directory(".wh..wh..opq", 0, 0, "");
        let new_entry = OciLayerReplayEntryV1::regular_file("x", 0o444, 3);
        let with_history_seals = vec![
            authenticated_layer_seal(0, &[(&old_entry, b"old")])?,
            authenticated_layer_seal(1, &[(&opaque_entry, &[]), (&new_entry, b"new")])?,
        ];
        let without_history_seal = authenticated_layer_seal(0, &[(&new_entry, b"new")])?;
        let temp = tempfile::tempdir()?;
        let parent_names = directory_names(temp.path())?;

        let (_, _, with_history_layout) = projected(temp.path(), "opaque-history")?;
        let mut with_history = PrivateOciRootfsStagingTransactionV1::begin(with_history_layout, 2)?;
        stage_regular(&mut with_history, source(0, 0), "x", 0o444, b"old")?;
        with_history.stage_opaque_directory(source(1, 0), ".wh..wh..opq", 0, 0, "")?;
        stage_regular(&mut with_history, source(1, 1), "x", 0o444, b"new")?;
        let with_history = with_history
            .authenticate_and_retain(with_history_seals, expected_rootfs(1, 1, 0, 0, 3))?;
        assert_eq!(with_history.canonical_live_operation_indices, [2]);
        let with_history_identity = with_history.authenticated_logical_projection_sha256;
        assert!(with_history.abandon()?.final_unlinked_observed);

        let (_, _, without_history_layout) = projected(temp.path(), "opaque-free")?;
        let mut without_history =
            PrivateOciRootfsStagingTransactionV1::begin(without_history_layout, 1)?;
        stage_regular(&mut without_history, source(0, 0), "x", 0o444, b"new")?;
        let without_history = without_history
            .authenticate_and_retain(vec![without_history_seal], expected_rootfs(1, 1, 0, 0, 3))?;
        assert_eq!(without_history.canonical_live_operation_indices, [0]);
        assert_eq!(
            without_history.authenticated_logical_projection_sha256,
            with_history_identity
        );
        assert!(without_history.abandon()?.final_unlinked_observed);
        assert_eq!(directory_names(temp.path())?, parent_names);
        Ok(())
    }

    #[test]
    fn authenticated_logical_projection_identity_binds_live_fields_not_history_coordinates()
    -> Result<()> {
        let aaa: [u8; super::SHA256_BYTES] = Sha256::digest(b"AAA").into();
        let bbb: [u8; super::SHA256_BYTES] = Sha256::digest(b"BBB").into();
        let base_fixture = regular_logical_identity_fixture(aaa);
        let base = base_fixture.identity()?;
        let history_only = LogicalIdentityFixtureV1 {
            operation_source: source(9, 17),
            extent_offset: 4_096,
            superseded_history: true,
            ..base_fixture
        }
        .identity()?;
        assert_eq!(history_only, base);

        let live_field_mutants = [
            LogicalIdentityFixtureV1 {
                role: PositiveRunnerRole::JvmValidatorBuild,
                ..base_fixture
            }
            .identity()?,
            LogicalIdentityFixtureV1 {
                path: "artifact-2",
                ..base_fixture
            }
            .identity()?,
            LogicalIdentityFixtureV1 {
                mode: 0o555,
                ..base_fixture
            }
            .identity()?,
            LogicalIdentityFixtureV1 {
                kind: LogicalIdentityFixtureKindV1::Regular {
                    byte_length: 4,
                    sha256: aaa,
                },
                ..base_fixture
            }
            .identity()?,
            LogicalIdentityFixtureV1 {
                kind: LogicalIdentityFixtureKindV1::Regular {
                    byte_length: 3,
                    sha256: bbb,
                },
                ..base_fixture
            }
            .identity()?,
            LogicalIdentityFixtureV1 {
                kind: LogicalIdentityFixtureKindV1::Directory,
                ..base_fixture
            }
            .identity()?,
        ];
        assert!(live_field_mutants.into_iter().all(|mutant| mutant != base));
        Ok(())
    }

    #[test]
    fn authenticated_logical_projection_identity_binds_every_counter() -> Result<()> {
        let aaa: [u8; super::SHA256_BYTES] = Sha256::digest(b"AAA").into();
        let base_fixture = regular_logical_identity_fixture(aaa);
        let base = base_fixture.identity()?;
        for counter_mutant in [
            OciRootfsLiveCountersV1 {
                regular_file_count: 2,
                ..base_fixture.counters
            },
            OciRootfsLiveCountersV1 {
                directory_count: 1,
                ..base_fixture.counters
            },
            OciRootfsLiveCountersV1 {
                symbolic_link_count: 1,
                ..base_fixture.counters
            },
            OciRootfsLiveCountersV1 {
                regular_file_bytes: 4,
                ..base_fixture.counters
            },
        ] {
            assert_ne!(
                LogicalIdentityFixtureV1 {
                    counters: counter_mutant,
                    ..base_fixture
                }
                .identity()?,
                base
            );
        }
        let entry_count_error = LogicalIdentityFixtureV1 {
            counters: OciRootfsLiveCountersV1 {
                entry_count: 2,
                ..base_fixture.counters
            },
            ..base_fixture
        }
        .identity()
        .unwrap_err();
        assert!(
            entry_count_error
                .to_string()
                .contains("live-definition count differs"),
            "{entry_count_error:#}"
        );
        Ok(())
    }

    #[test]
    fn authenticated_logical_projection_identity_binds_symbolic_link_target() -> Result<()> {
        let symlink_counters = OciRootfsLiveCountersV1 {
            entry_count: 1,
            regular_file_count: 0,
            directory_count: 0,
            symbolic_link_count: 1,
            regular_file_bytes: 0,
        };
        let link_a_fixture = LogicalIdentityFixtureV1 {
            role: PositiveRunnerRole::RustValidatorBuild,
            path: "link",
            mode: 0o777,
            kind: LogicalIdentityFixtureKindV1::SymbolicLink("target-a"),
            counters: symlink_counters,
            operation_source: source(0, 0),
            extent_offset: 0,
            superseded_history: false,
        };
        let link_a = link_a_fixture.identity()?;
        let link_b = LogicalIdentityFixtureV1 {
            kind: LogicalIdentityFixtureKindV1::SymbolicLink("target-b"),
            ..link_a_fixture
        }
        .identity()?;
        assert_ne!(link_a, link_b);
        Ok(())
    }

    #[test]
    fn authenticated_logical_projection_identity_has_exact_role_tags() -> Result<()> {
        let aaa: [u8; super::SHA256_BYTES] = Sha256::digest(b"AAA").into();
        let base_fixture = regular_logical_identity_fixture(aaa);
        for (label, role, expected) in [
            (
                "rust-validator-build",
                PositiveRunnerRole::RustValidatorBuild,
                "7e104df3f61546255855792ac30173c585b069ead51fa0cfbd40c64bc4fa085b",
            ),
            (
                "jvm-validator-build",
                PositiveRunnerRole::JvmValidatorBuild,
                "163b5acfacf568acbe6bd74078aba60ebd9ea190c8c7a0e6961a964663471bcc",
            ),
            (
                "rust-verifier",
                PositiveRunnerRole::RustVerifier,
                "d9c9d6b8b930ceb7ec303fedd8f601acb5406fe8de23d0d8a2b4bedf23844605",
            ),
            (
                "jvm-verifier",
                PositiveRunnerRole::JvmVerifier,
                "db20e854a65c94fae1083b662d19bc2fedbcd1287d5f450d680e5ef41901aa21",
            ),
        ] {
            let observed = LogicalIdentityFixtureV1 {
                role,
                ..base_fixture
            }
            .identity()?;
            assert_eq!(hex::encode(observed), expected, "{label}");
        }
        Ok(())
    }

    #[test]
    fn authenticated_logical_projection_identity_has_exact_kind_and_mode_tags() -> Result<()> {
        let aaa: [u8; super::SHA256_BYTES] = Sha256::digest(b"AAA").into();
        let regular_fixture = LogicalIdentityFixtureV1 {
            path: "node",
            ..regular_logical_identity_fixture(aaa)
        };
        let regular = regular_fixture.identity()?;
        assert_eq!(
            hex::encode(regular),
            "540819896b3ea69f68f1d47379c00de19f884c423b9efda1777177bd3fe2ddad"
        );

        let directory_counters = OciRootfsLiveCountersV1 {
            entry_count: 1,
            regular_file_count: 0,
            directory_count: 1,
            symbolic_link_count: 0,
            regular_file_bytes: 0,
        };
        let directory_fixture = LogicalIdentityFixtureV1 {
            mode: 0o555,
            kind: LogicalIdentityFixtureKindV1::Directory,
            counters: directory_counters,
            ..regular_fixture
        };
        let directory = directory_fixture.identity()?;
        assert_eq!(
            hex::encode(directory),
            "f42799605c2bc0b6c2905a99d5e619f775ace2fcd9008ca5701df5f13c171918"
        );
        let directory_mode_mutant = LogicalIdentityFixtureV1 {
            mode: 0o755,
            ..directory_fixture
        }
        .identity()?;
        assert_ne!(directory_mode_mutant, directory);

        let symbolic_link_counters = OciRootfsLiveCountersV1 {
            entry_count: 1,
            regular_file_count: 0,
            directory_count: 0,
            symbolic_link_count: 1,
            regular_file_bytes: 0,
        };
        let symbolic_link_fixture = LogicalIdentityFixtureV1 {
            mode: 0o777,
            kind: LogicalIdentityFixtureKindV1::SymbolicLink("target-a"),
            counters: symbolic_link_counters,
            ..regular_fixture
        };
        let symbolic_link = symbolic_link_fixture.identity()?;
        assert_eq!(
            hex::encode(symbolic_link),
            "b9fa87887fa76ebe682f3894a0af6a58b67e53ab0cacc1667b3757cf77b6a0c5"
        );
        let symbolic_link_mode_mutant = LogicalIdentityFixtureV1 {
            mode: 0o755,
            ..symbolic_link_fixture
        }
        .identity()?;
        assert_ne!(symbolic_link_mode_mutant, symbolic_link);
        Ok(())
    }

    #[test]
    fn authenticated_projection_abandonment_rejects_late_spool_mutation() -> Result<()> {
        let pass_a = super::super::layer::test_only_authenticated_regular_layer_seal(
            0, "artifact", 0o444, b"AAA",
        )?;
        let temp = tempfile::tempdir()?;
        let parent_names = directory_names(temp.path())?;
        let (final_path, _, layout) = projected(temp.path(), "late-retained-spool-mutation")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        stage_regular(&mut transaction, source(0, 0), "artifact", 0o444, b"AAA")?;
        let retained =
            transaction.authenticate_and_retain(vec![pass_a], expected_rootfs(1, 1, 0, 0, 3))?;
        let authenticated_identity = retained.authenticated_logical_projection_sha256;
        retained.transaction.spool.write_all_at(b"BBB", 0)?;

        let failure = retained
            .abandon()
            .expect_err("late retained-spool mutation was accepted");
        assert!(
            format!("{failure:#}").contains("physical OCI rootfs regular extent digest changed"),
            "{failure:#}"
        );
        assert!(failure.abandonment.final_unlinked_observed);
        assert_eq!(failure.abandonment.authenticated_live_entries, Some(1));
        assert_eq!(
            failure.abandonment.authenticated_logical_projection_sha256,
            Some(authenticated_identity)
        );
        assert_eq!(directory_names(temp.path())?, parent_names);
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn authenticated_projection_revalidation_rejects_retained_metadata_and_destination_drift()
    -> Result<()> {
        let temp = tempfile::tempdir()?;

        let (_, mut indices) =
            authenticated_single_regular_projection(temp.path(), "late-index-drift")?;
        indices.canonical_live_operation_indices[0] = usize::MAX;
        let failure = indices
            .abandon()
            .expect_err("retained live-index drift was accepted");
        assert!(
            format!("{failure:#}").contains("live definitions differ"),
            "{failure:#}"
        );
        assert!(failure.abandonment.final_unlinked_observed);

        let (_, mut identity) =
            authenticated_single_regular_projection(temp.path(), "late-identity-drift")?;
        identity.authenticated_logical_projection_sha256[0] ^= 1;
        let failure = identity
            .abandon()
            .expect_err("retained logical-identity drift was accepted");
        assert!(
            format!("{failure:#}").contains("logical identity differs"),
            "{failure:#}"
        );
        assert!(failure.abandonment.final_unlinked_observed);

        let (_, mut counters) =
            authenticated_single_regular_projection(temp.path(), "late-counter-drift")?;
        counters.counters.regular_file_bytes += 1;
        counters.transaction.validated_live_rootfs = Some(counters.counters);
        let failure = counters
            .abandon()
            .expect_err("retained live-counter drift was accepted");
        assert!(
            format!("{failure:#}").contains("live counters differ"),
            "{failure:#}"
        );
        assert!(failure.abandonment.final_unlinked_observed);

        let (final_path, destination) =
            authenticated_single_regular_projection(temp.path(), "late-destination-drift")?;
        std::fs::write(&final_path, b"late occupant")?;
        let failure = destination
            .abandon()
            .expect_err("late final-destination occupation was accepted");
        assert!(
            format!("{failure:#}")
                .contains("final destination before retained projection validation"),
            "{failure:#}"
        );
        assert!(failure.abandonment.final_unlinked_observed);
        assert_eq!(std::fs::read(final_path)?, b"late occupant");
        Ok(())
    }

    #[test]
    fn authenticated_rootfs_rejects_swapped_layer_seal_order() -> Result<()> {
        let seal_0 = super::super::layer::test_only_authenticated_regular_layer_seal(
            0, "alpha", 0o444, b"AAA",
        )?;
        let seal_1 = super::super::layer::test_only_authenticated_regular_layer_seal(
            1, "beta", 0o444, b"BBB",
        )?;
        let temp = tempfile::tempdir()?;
        let (final_path, _, layout) = projected(temp.path(), "swapped-layer-seals")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 2)?;
        stage_regular(&mut transaction, source(0, 0), "alpha", 0o444, b"AAA")?;
        stage_regular(&mut transaction, source(1, 0), "beta", 0o444, b"BBB")?;

        let error = expect_error(
            transaction
                .authenticate_and_retain(vec![seal_1, seal_0], expected_rootfs(2, 2, 0, 0, 6)),
        );
        assert!(
            format!("{error:#}").contains("semantic layer order"),
            "{error:#}"
        );
        assert!(!final_path.exists());
        Ok(())
    }

    #[test]
    fn authenticated_rootfs_rejects_missing_and_extra_layer_seals() -> Result<()> {
        let extra_0 = super::super::layer::test_only_authenticated_regular_layer_seal(
            0, "artifact", 0o444, b"AAA",
        )?;
        let extra_1 = super::super::layer::test_only_authenticated_regular_layer_seal(
            0, "artifact", 0o444, b"AAA",
        )?;
        let cases = [("missing", Vec::new()), ("extra", vec![extra_0, extra_1])];
        let temp = tempfile::tempdir()?;

        for (name, seals) in cases {
            let (final_path, _, layout) = projected(temp.path(), &format!("{name}-layer-seals"))?;
            let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
            stage_regular(&mut transaction, source(0, 0), "artifact", 0o444, b"AAA")?;
            let error = expect_error(
                transaction.authenticate_and_retain(seals, expected_rootfs(1, 1, 0, 0, 3)),
            );
            assert!(
                format!("{error:#}").contains("layer-seal cardinality"),
                "{name}: {error:#}"
            );
            assert!(!final_path.exists(), "{name} left a named rootfs");
        }
        Ok(())
    }

    #[test]
    fn authenticated_rootfs_rejects_each_final_counter_independently() -> Result<()> {
        let cases = [
            (
                "entry",
                expected_rootfs(2, 1, 0, 0, 3),
                "live entry count differs",
            ),
            (
                "regular",
                expected_rootfs(1, 2, 0, 0, 3),
                "live regular-file count differs",
            ),
            (
                "directory",
                expected_rootfs(1, 1, 1, 0, 3),
                "live directory count differs",
            ),
            (
                "symlink",
                expected_rootfs(1, 1, 0, 1, 3),
                "live symbolic-link count differs",
            ),
            (
                "bytes",
                expected_rootfs(1, 1, 0, 0, 4),
                "live regular-file bytes differ",
            ),
        ];

        let temp = tempfile::tempdir()?;
        for (name, expected, message) in cases {
            let pass_a = super::super::layer::test_only_authenticated_regular_layer_seal(
                0, "artifact", 0o444, b"AAA",
            )?;
            let (final_path, _, layout) = projected(temp.path(), &format!("counter-{name}"))?;
            let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
            stage_regular(&mut transaction, source(0, 0), "artifact", 0o444, b"AAA")?;
            let error = expect_error(transaction.authenticate_and_retain(vec![pass_a], expected));
            assert!(format!("{error:#}").contains(message), "{name}: {error:#}");
            assert!(!final_path.exists(), "{name} left a named rootfs");
        }
        Ok(())
    }

    #[test]
    fn semantic_layer_source_paths_must_be_strictly_increasing() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "source-path-order")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        stage_regular(&mut transaction, source(0, 0), "b", 0o444, b"b")?;
        stage_regular(&mut transaction, source(0, 1), "a", 0o444, b"a")?;
        transaction.seal_semantic_layer(0, 2)?;
        let failure = transaction
            .discard()
            .expect_err("out-of-order normalized layer paths were accepted");
        assert!(format!("{failure:#}").contains("strict source path order"));
        assert!(failure.abandonment.final_unlinked_observed);

        let (_, _, duplicate_layout) = projected(temp.path(), "duplicate-source-path")?;
        let mut duplicate = PrivateOciRootfsStagingTransactionV1::begin(duplicate_layout, 1)?;
        stage_regular(&mut duplicate, source(0, 0), "a", 0o444, b"a")?;
        stage_regular(&mut duplicate, source(0, 1), "a", 0o444, b"b")?;
        duplicate.seal_semantic_layer(0, 2)?;
        assert!(
            format!("{:#}", duplicate.discard().unwrap_err()).contains("strict source path order")
        );
        Ok(())
    }

    #[test]
    fn invalid_symlink_identity_poisons_the_transaction() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "symlink-poison")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        let error = transaction
            .stage_symbolic_link(source(0, 0), "link", 0o777, 0, "../../escape")
            .unwrap_err();
        assert!(error.to_string().contains("escapes the layer root"));
        assert!(transaction.poisoned);
        let abandoned = transaction.abandon();
        assert!(abandoned.final_unlinked_observed);
        Ok(())
    }

    #[test]
    fn inert_operation_identity_rejects_each_mode_payload_and_whiteout_mismatch() {
        use super::StagedRootfsOperationKindRefV1 as Kind;

        let cases = [
            ("d", 0o444, 0, Kind::Directory, "directory mode"),
            ("d", 0o555, 1, Kind::Directory, "directory payload"),
            (
                ".wh.d",
                0o555,
                0,
                Kind::Directory,
                "reserved whiteout syntax",
            ),
            (
                "link",
                0o555,
                0,
                Kind::SymbolicLink { target: "target" },
                "symbolic-link mode",
            ),
            (
                "link",
                0o777,
                1,
                Kind::SymbolicLink { target: "target" },
                "symbolic-link payload",
            ),
            (
                ".wh.a",
                0o444,
                0,
                Kind::Remove { target: "a" },
                "whiteout mode",
            ),
            (
                ".wh.a",
                0,
                1,
                Kind::Remove { target: "a" },
                "whiteout payload",
            ),
            (
                ".wh.a",
                0,
                0,
                Kind::Remove { target: "b" },
                "derived exactly",
            ),
            (
                "d/.wh..wh..opq",
                0o555,
                0,
                Kind::OpaqueDirectory { path: "d" },
                "whiteout mode",
            ),
            (
                "d/.wh..wh..opq",
                0,
                1,
                Kind::OpaqueDirectory { path: "d" },
                "whiteout payload",
            ),
            (
                "d/.wh..wh..opq",
                0,
                0,
                Kind::OpaqueDirectory { path: "e" },
                "derived exactly",
            ),
        ];
        for (path, mode, byte_length, kind, expected) in cases {
            let error =
                super::validate_staged_operation_identity_ref(path, mode, byte_length, kind)
                    .unwrap_err();
            assert!(format!("{error:#}").contains(expected), "{error:#}");
        }
    }

    #[test]
    fn candidate_identity_revalidates_the_regular_file_ceiling() {
        let error = super::validate_staged_operation_identity(
            "artifact",
            0o444,
            1_073_741_825,
            &super::StagedRootfsOperationKindV1::Regular { extent_index: 0 },
        )
        .unwrap_err();
        assert!(error.to_string().contains("layer regular-file payload"));
    }

    #[test]
    fn regular_extent_reference_is_bound_to_its_source_identity() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "extent-source-binding")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        stage_regular(&mut transaction, source(0, 0), "a", 0o444, b"AAA")?;
        stage_regular(&mut transaction, source(0, 1), "b", 0o444, b"BBB")?;
        transaction.seal_semantic_layer(0, 2)?;

        transaction.operations[0].kind =
            super::StagedRootfsOperationKindV1::Regular { extent_index: 1 };
        transaction.operations[1].kind =
            super::StagedRootfsOperationKindV1::Regular { extent_index: 0 };

        let failure = transaction
            .discard()
            .expect_err("regular extent references were exchangeable between source paths");
        assert!(format!("{failure:#}").contains("source identity"));
        assert!(failure.abandonment.final_unlinked_observed);
        Ok(())
    }

    #[test]
    fn sealed_layer_transcript_rejects_valid_operation_identity_mutation() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "sealed-operation-transcript")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        stage_regular(&mut transaction, source(0, 0), "a", 0o444, b"AAA")?;
        transaction.seal_semantic_layer(0, 1)?;

        transaction.operations[0].path = "b".to_owned();

        let failure = transaction
            .discard()
            .expect_err("a valid post-seal path mutation escaped the captured transcript");
        assert!(format!("{failure:#}").contains("sealed semantic-layer transcript"));
        assert!(failure.abandonment.final_unlinked_observed);
        Ok(())
    }

    #[test]
    fn sealed_whiteout_transcript_rejects_coordinated_valid_identity_mutations() -> Result<()> {
        let temp = tempfile::tempdir()?;

        let (_, _, remove_layout) = projected(temp.path(), "sealed-remove-target")?;
        let mut remove = PrivateOciRootfsStagingTransactionV1::begin(remove_layout, 2)?;
        stage_regular(&mut remove, source(0, 0), "a", 0o444, b"a")?;
        stage_regular(&mut remove, source(0, 1), "b", 0o444, b"b")?;
        remove.seal_semantic_layer(0, 2)?;
        remove.stage_remove(source(1, 0), ".wh.a", 0, 0, "a")?;
        remove.seal_semantic_layer(1, 1)?;
        remove.operations[2].path = ".wh.b".to_owned();
        let super::StagedRootfsOperationKindV1::Remove { target } = &mut remove.operations[2].kind
        else {
            panic!("remove operation kind changed")
        };
        *target = "b".to_owned();
        let failure = remove.discard().unwrap_err();
        assert!(format!("{failure:#}").contains("sealed semantic-layer transcript"));
        assert!(failure.abandonment.final_unlinked_observed);

        let (_, _, opaque_layout) = projected(temp.path(), "sealed-opaque-subject")?;
        let mut opaque = PrivateOciRootfsStagingTransactionV1::begin(opaque_layout, 2)?;
        opaque.stage_directory(source(0, 0), "d", 0o555, 0)?;
        opaque.stage_directory(source(0, 1), "e", 0o555, 0)?;
        opaque.seal_semantic_layer(0, 2)?;
        opaque.stage_opaque_directory(source(1, 0), "d/.wh..wh..opq", 0, 0, "d")?;
        opaque.seal_semantic_layer(1, 1)?;
        opaque.operations[2].path = "e/.wh..wh..opq".to_owned();
        let super::StagedRootfsOperationKindV1::OpaqueDirectory { path } =
            &mut opaque.operations[2].kind
        else {
            panic!("opaque operation kind changed")
        };
        *path = "e".to_owned();
        let failure = opaque.discard().unwrap_err();
        assert!(format!("{failure:#}").contains("sealed semantic-layer transcript"));
        assert!(failure.abandonment.final_unlinked_observed);
        Ok(())
    }

    #[test]
    fn metadata_reservation_formula_covers_compiled_type_layout() -> Result<()> {
        let path = "p".repeat(super::OCI_LAYER_PATH_MAX_BYTES);
        let target = "t".repeat(super::OCI_LAYER_PATH_MAX_BYTES);
        let regular = super::staged_operation_metadata_reservation(
            &path,
            &super::StagedRootfsOperationKindV1::Regular { extent_index: 0 },
        )?;
        let whiteout = super::staged_operation_metadata_reservation(
            &path,
            &super::StagedRootfsOperationKindV1::Remove { target },
        )?;

        assert!(
            u64::try_from(2 * std::mem::size_of::<super::StagedRootfsOperationV1>())?
                <= super::OCI_ROOTFS_OPERATION_METADATA_RESERVATION_BYTES
        );
        assert!(
            u64::try_from(2 * std::mem::size_of::<super::StagedRegularExtentV1>() + 1)?
                <= super::OCI_ROOTFS_REGULAR_EXTENT_METADATA_RESERVATION_BYTES
        );
        assert!(
            u64::try_from(2 * std::mem::size_of::<usize>())?
                <= super::OCI_ROOTFS_LIVE_INDEX_METADATA_RESERVATION_BYTES
        );
        assert_eq!(regular, 912);
        assert_eq!(whiteout, 1_024);
        assert!(
            super::OCI_ROOTFS_LOGICAL_METADATA_BASE_RESERVATION_BYTES + 1_000_000_u64 * whiteout
                > super::OCI_ROOTFS_LOGICAL_METADATA_MAX_BYTES
        );
        Ok(())
    }

    #[test]
    fn metadata_budget_is_exact_checked_and_rejects_without_journal_growth() -> Result<()> {
        assert_eq!(
            super::checked_rootfs_metadata_reservation(
                super::OCI_ROOTFS_LOGICAL_METADATA_MAX_BYTES - 1,
                1,
            )?,
            super::OCI_ROOTFS_LOGICAL_METADATA_MAX_BYTES
        );
        assert!(
            super::checked_rootfs_metadata_reservation(
                super::OCI_ROOTFS_LOGICAL_METADATA_MAX_BYTES,
                1,
            )
            .unwrap_err()
            .to_string()
            .contains("metadata reservation")
        );
        assert!(
            super::checked_rootfs_metadata_reservation(u64::MAX, 1)
                .unwrap_err()
                .to_string()
                .contains("overflowed")
        );

        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "metadata-budget")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        transaction.logical_metadata_bytes = super::OCI_ROOTFS_LOGICAL_METADATA_MAX_BYTES;
        let before_observations = transaction.descriptor_observations.get();
        let error = transaction
            .stage_directory(source(0, 0), "a", 0o555, 0)
            .unwrap_err();
        assert!(format!("{error:#}").contains("metadata reservation"));
        assert!(transaction.poisoned);
        assert!(transaction.operations.is_empty());
        assert!(transaction.operations_by_source[0].is_empty());
        assert_eq!(transaction.captured_layer_entries[0], 0);
        assert_eq!(
            transaction.logical_metadata_bytes,
            super::OCI_ROOTFS_LOGICAL_METADATA_MAX_BYTES
        );
        assert_eq!(
            transaction.descriptor_observations.get(),
            before_observations
        );
        assert!(transaction.abandon().final_unlinked_observed);
        Ok(())
    }

    #[test]
    fn distinct_root_files_do_not_scan_existing_projection_subtrees() -> Result<()> {
        const FILES: u64 = 4_096;

        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "root-file-cost")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        for index in 0..FILES {
            let path = format!("f{index:04}");
            stage_regular(&mut transaction, source(0, index), &path, 0o444, b"")?;
        }
        transaction.seal_semantic_layer(0, FILES)?;

        let projection = transaction.validate_spooled_projection()?;
        assert_eq!(projection.subtree_candidate_visits, 0);
        assert_eq!(projection.counters.entry_count, FILES);
        let abandoned = transaction.abandon();
        assert!(abandoned.final_unlinked_observed);
        Ok(())
    }

    #[test]
    fn leaf_whiteouts_drain_each_live_key_once_without_tombstones() -> Result<()> {
        const FILES: u64 = 1_024;

        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "leaf-whiteout-cost")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 2)?;
        for index in 0..FILES {
            let path = format!("f{index:04}");
            stage_regular(&mut transaction, source(0, index), &path, 0o444, b"")?;
        }
        transaction.seal_semantic_layer(0, FILES)?;
        for index in 0..FILES {
            let target = format!("f{index:04}");
            let marker = format!(".wh.{target}");
            transaction.stage_remove(source(1, index), &marker, 0, 0, &target)?;
        }
        transaction.seal_semantic_layer(1, FILES)?;

        let projection = transaction.validate_spooled_projection()?;
        assert_eq!(projection.subtree_candidate_visits, FILES);
        assert_eq!(projection.definitions_inserted, FILES);
        assert_eq!(
            projection.counters,
            super::OciRootfsLiveCountersV1::default()
        );
        assert!(projection.paths.is_empty());
        let abandoned = transaction.abandon();
        assert!(abandoned.final_unlinked_observed);
        Ok(())
    }

    #[test]
    fn directory_replacement_drains_only_its_live_subtree() -> Result<()> {
        const CHILDREN: u64 = 1_024;

        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "directory-replacement-cost")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 2)?;
        transaction.stage_directory(source(0, 0), "d", 0o555, 0)?;
        for index in 0..CHILDREN {
            let path = format!("d/c{index:04}");
            stage_regular(&mut transaction, source(0, index + 1), &path, 0o444, b"")?;
        }
        transaction.seal_semantic_layer(0, CHILDREN + 1)?;
        stage_regular(&mut transaction, source(1, 0), "d", 0o444, b"new")?;
        transaction.seal_semantic_layer(1, 1)?;

        let projection = transaction.validate_spooled_projection()?;
        assert_eq!(projection.subtree_candidate_visits, CHILDREN + 1);
        assert_eq!(projection.definitions_inserted, CHILDREN + 2);
        assert_eq!(projection.counters.entry_count, 1);
        assert_eq!(projection.counters.regular_file_count, 1);
        assert_eq!(projection.counters.regular_file_bytes, 3);
        let abandoned = transaction.abandon();
        assert!(abandoned.final_unlinked_observed);
        Ok(())
    }

    #[test]
    fn repeated_root_opaque_whiteouts_do_not_revisit_history() -> Result<()> {
        const FILES: u64 = 1_024;

        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "root-opaque-cost")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 3)?;
        for index in 0..FILES {
            let path = format!("f{index:04}");
            stage_regular(&mut transaction, source(0, index), &path, 0o444, b"")?;
        }
        transaction.seal_semantic_layer(0, FILES)?;
        for layer in 1..=2 {
            transaction.stage_opaque_directory(source(layer, 0), ".wh..wh..opq", 0, 0, "")?;
            transaction.seal_semantic_layer(layer, 1)?;
        }

        let projection = transaction.validate_spooled_projection()?;
        assert_eq!(projection.subtree_candidate_visits, FILES);
        assert_eq!(projection.definitions_inserted, FILES);
        assert_eq!(
            projection.counters,
            super::OciRootfsLiveCountersV1::default()
        );
        assert!(projection.paths.is_empty());
        let abandoned = transaction.abandon();
        assert!(abandoned.final_unlinked_observed);
        Ok(())
    }

    #[test]
    fn logical_journal_failure_precedes_candidate_sync_and_extent_reads() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let (_, _, layout) = projected(temp.path(), "logical-before-physical")?;
        let mut transaction = PrivateOciRootfsStagingTransactionV1::begin(layout, 1)?;
        stage_regular(&mut transaction, source(0, 0), "a", 0o444, b"AAA")?;
        transaction.seal_semantic_layer(0, 1)?;

        transaction.operations[0].path = "b".to_owned();
        assert_eq!(transaction.spool.write_at(b"X", 0)?, 1);

        let error = transaction.validate_completed_candidate().unwrap_err();
        assert!(
            format!("{error:#}").contains("sealed semantic-layer transcript"),
            "{error:#}"
        );
        assert_eq!(transaction.candidate_sync_calls.get(), 0);
        assert_eq!(transaction.candidate_extent_bytes_read.get(), 0);
        assert!(transaction.abandon().final_unlinked_observed);
        Ok(())
    }

    #[test]
    fn successful_candidate_syncs_once_and_reads_each_extent_once() -> Result<()> {
        const BYTES: usize = 128;
        const INERT_OPERATIONS: u64 = 1_024;
        let byte_length = u64::try_from(BYTES)?;

        let temp = tempfile::tempdir()?;
        let (_, _, one_chunk_layout) = projected(temp.path(), "one-chunk-candidate-io")?;
        let mut one_chunk = PrivateOciRootfsStagingTransactionV1::begin(one_chunk_layout, 1)?;
        one_chunk.begin_root_regular("artifact", 0o444, byte_length)?;
        one_chunk.write_regular_chunk(&[7_u8; BYTES])?;
        one_chunk.finish_entry()?;
        one_chunk.stage_directory(source(0, 1), "z", 0o555, 0)?;
        one_chunk.seal_semantic_layer(0, 2)?;
        one_chunk.validate_completed_candidate()?;
        assert_eq!(one_chunk.candidate_sync_calls.get(), 1);
        assert_eq!(one_chunk.candidate_extent_bytes_read.get(), byte_length);
        assert!(one_chunk.abandon().final_unlinked_observed);

        let (_, _, many_chunks_layout) = projected(temp.path(), "many-chunk-candidate-io")?;
        let mut many_chunks = PrivateOciRootfsStagingTransactionV1::begin(many_chunks_layout, 1)?;
        many_chunks.begin_root_regular("artifact", 0o444, byte_length)?;
        for _ in 0..BYTES {
            many_chunks.write_regular_chunk(&[7])?;
        }
        many_chunks.finish_entry()?;
        for index in 0..INERT_OPERATIONS {
            many_chunks.stage_directory(source(0, index + 1), &format!("d{index:04}"), 0o555, 0)?;
        }
        many_chunks.seal_semantic_layer(0, INERT_OPERATIONS + 1)?;
        many_chunks.validate_completed_candidate()?;
        assert_eq!(many_chunks.candidate_sync_calls.get(), 1);
        assert_eq!(many_chunks.candidate_extent_bytes_read.get(), byte_length);
        assert!(many_chunks.abandon().final_unlinked_observed);
        Ok(())
    }

    #[test]
    fn descriptor_observations_are_independent_of_chunk_and_inert_operation_counts() -> Result<()> {
        const CHUNKS: usize = 128;
        const INERT_OPERATIONS: u64 = 4_096;
        let chunk_count = u64::try_from(CHUNKS)?;

        let temp = tempfile::tempdir()?;
        let (_, _, one_chunk_layout) = projected(temp.path(), "one-chunk-observations")?;
        let mut one_chunk = PrivateOciRootfsStagingTransactionV1::begin(one_chunk_layout, 1)?;
        one_chunk.begin_root_regular("artifact", 0o444, chunk_count)?;
        one_chunk.write_regular_chunk(&[0_u8; CHUNKS])?;
        one_chunk.finish_entry()?;
        let one_chunk_observations = one_chunk.descriptor_observations.get();
        assert!(one_chunk.abandon().final_unlinked_observed);

        let (_, _, many_chunks_layout) = projected(temp.path(), "many-chunk-observations")?;
        let mut many_chunks = PrivateOciRootfsStagingTransactionV1::begin(many_chunks_layout, 1)?;
        many_chunks.begin_root_regular("artifact", 0o444, chunk_count)?;
        for _ in 0..CHUNKS {
            many_chunks.write_regular_chunk(&[0])?;
        }
        many_chunks.finish_entry()?;
        let many_chunk_observations = many_chunks.descriptor_observations.get();
        assert_eq!(many_chunk_observations, one_chunk_observations);
        assert!(many_chunks.abandon().final_unlinked_observed);

        let (_, _, one_inert_layout) = projected(temp.path(), "one-inert-observation")?;
        let mut one_inert = PrivateOciRootfsStagingTransactionV1::begin(one_inert_layout, 1)?;
        one_inert.stage_directory(source(0, 0), "d0000", 0o555, 0)?;
        one_inert.seal_semantic_layer(0, 1)?;
        let one_inert_observations = one_inert.descriptor_observations.get();
        assert!(one_inert.abandon().final_unlinked_observed);

        let (_, _, many_inert_layout) = projected(temp.path(), "many-inert-observations")?;
        let mut many_inert = PrivateOciRootfsStagingTransactionV1::begin(many_inert_layout, 1)?;
        for index in 0..INERT_OPERATIONS {
            let path = format!("d{index:04}");
            many_inert.stage_directory(source(0, index), &path, 0o555, 0)?;
        }
        many_inert.seal_semantic_layer(0, INERT_OPERATIONS)?;
        assert_eq!(
            many_inert.descriptor_observations.get(),
            one_inert_observations
        );
        assert!(many_inert.abandon().final_unlinked_observed);
        Ok(())
    }
}
