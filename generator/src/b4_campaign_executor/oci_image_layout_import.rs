//! Descriptor-rooted import and bounded inspection of one OCI image-layout ustar.

mod json;
mod layer;
#[cfg(target_os = "linux")]
mod rootfs;

use std::{
    io::{self, Read},
    marker::PhantomData,
    path::Path,
};

use anyhow::{Context as _, Result, ensure};
#[cfg(target_os = "linux")]
use eip_0045_reproduction::b4_positive_gate::B4PositiveOciImageLayoutV1;
use eip_0045_reproduction::b4_positive_gate::{PositiveGateBindings, PositiveRunnerRole};
use sha2::{Digest as _, Sha256};

use super::{
    artifact_import_contract::{B4ImmutableArtifactRoleV1, OciLayerStreamLimitsV1},
    capability::MutationCapability,
    preflight::{
        AuthenticatedOciSlotConstructionPermitV1, ProjectedCampaignLayout,
        ProjectedPrepareInputSetCampaignLayout,
    },
};

const AUTHENTICATED_OCI_INVENTORY_SIZE: usize = 4;

#[cfg(all(test, target_os = "linux"))]
std::thread_local! {
    static EXPLICIT_REPLAYED_ROOTFS_DISCARDS: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
}

const USTAR_BLOCK_BYTES: usize = 512;
const USTAR_BLOCK_BYTES_U64: u64 = 512;
const OCI_OUTER_USTAR_MIN_BYTES: u64 = 6_144;
const OCI_OUTER_USTAR_MAX_BYTES: u64 = 17_179_869_184;
const OCI_OUTER_USTAR_MAX_MEMBER_BYTES: u64 = 8_589_934_591;
const OCI_OUTER_USTAR_MIN_BLOBS: usize = 3;
const OCI_OUTER_USTAR_MAX_BLOBS: usize = 130;
const OCI_OUTER_USTAR_MAX_MEMBERS: usize = OCI_OUTER_USTAR_MAX_BLOBS + 2;
const OCI_INDEX_JSON_MIN_BYTES: u64 = 2;
const OCI_INDEX_JSON_MAX_BYTES: u64 = 1_048_576;
const OCI_LAYOUT_BYTES: &[u8] = br#"{"imageLayoutVersion":"1.0.0"}"#;
const MEMBER_IO_BUFFER_BYTES: usize = 16 * 1024;

#[cfg(target_os = "linux")]
type ActiveOciRootfsReplayTransactionV1 = rootfs::PrivateOciRootfsStagingTransactionV1;
#[cfg(not(target_os = "linux"))]
struct ActiveOciRootfsReplayTransactionV1;

/// Affine permit constructible only by this module's fixed OCI import route.
pub(super) struct OciOuterUstarCustodyPermitV1 {
    _private: (),
}

/// One pre-H0 slot for an image-layout archive already selected at capture.
///
/// The sole production projection consumes the affine preflight permit and the
/// exact authenticated profile together; no detached locator constructor exists.
struct OciOuterUstarSlotV1 {
    role: PositiveRunnerRole,
    root_index: usize,
    relative_path: String,
    expectation: OciOuterUstarExpectationV1,
}

/// Complete pre-H0 image identity required before the first archive read.
///
/// Production values are projected only from the authenticated positive
/// profile consumed by the slot bridge.
struct OciOuterUstarExpectationV1 {
    archive_byte_length: u64,
    archive_sha256: [u8; 32],
    image: json::OciImageExpectationV1,
}

/// One closed four-role inventory. The exact non-cloneable gate remains inside
/// this value from pre-custody projection until the fixed import completes.
#[must_use = "the authenticated OCI inventory must be imported as one affine value"]
pub(super) struct AuthenticatedOciOuterUstarInventoryV1 {
    gate: PositiveGateBindings,
    slots: [OciOuterUstarSlotV1; AUTHENTICATED_OCI_INVENTORY_SIZE],
}

/// Owned evidence for one completed descriptor-rooted outer-ustar import.
struct ImportedOciOuterUstarReceiptV1 {
    role: PositiveRunnerRole,
    post_changeset_rootfs: json::OciExpectedRootfsV1,
    archive_byte_length: u64,
    archive_sha256: [u8; 32],
    blob_count: usize,
    index_json_byte_length: u64,
    index_json_sha256: [u8; 32],
    layers: Vec<ImportedOciLayerObservationV1>,
    observed_layer_uncompressed_bytes: u64,
    observed_layer_tar_entries: u64,
}

/// Affine pass-A identity for one semantic OCI layer changeset.
///
/// The sole production mint is the successful A/B receipt transition below.
/// No source path, descriptor, reader, payload or publication authority is
/// retained in this seal.
#[must_use = "the authenticated OCI layer seal must be consumed by rootfs replay"]
struct AuthenticatedOciLayerSealV1 {
    semantic_layer_index: u64,
    authenticated_entry_count: u64,
    changeset_transcript_sha256: [u8; 32],
    _private: (),
}

/// Affine proof that one inert receipt was reproduced by a second complete,
/// authenticated pass through the same retained OCI archive. On Linux it owns
/// the authenticated logical rootfs projection for the next closed boundary.
struct ReplayedOciOuterUstarReceiptV1 {
    receipt: ImportedOciOuterUstarReceiptV1,
    #[cfg(target_os = "linux")]
    rootfs: rootfs::AuthenticatedPrivateOciRootfsProjectionV1,
}

struct AuthenticatedOciReplayTransitionV1 {
    receipt: ImportedOciOuterUstarReceiptV1,
    layer_seals: Vec<AuthenticatedOciLayerSealV1>,
}

impl std::ops::Deref for ReplayedOciOuterUstarReceiptV1 {
    type Target = ImportedOciOuterUstarReceiptV1;

    fn deref(&self) -> &Self::Target {
        &self.receipt
    }
}

impl ReplayedOciOuterUstarReceiptV1 {
    fn discard_after_error(self, error: anyhow::Error) -> anyhow::Error {
        #[cfg(all(test, target_os = "linux"))]
        EXPLICIT_REPLAYED_ROOTFS_DISCARDS.with(|count| count.set(count.get() + 1));
        #[cfg(target_os = "linux")]
        {
            let Self { receipt: _, rootfs } = self;
            rootfs.discard_after_error(error)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let Self { receipt: _ } = self;
            error
        }
    }
}

/// Inert owned observation of one structurally validated, DiffID-authenticated
/// layer, retained in manifest semantic order rather than digest-sorted
/// outer-archive order.
#[derive(Debug, Eq, PartialEq)]
struct ImportedOciLayerObservationV1 {
    semantic_index: usize,
    compressed_byte_length: u64,
    compressed_sha256: [u8; 32],
    uncompressed_byte_length: u64,
    observed_uncompressed_sha256: [u8; 32],
    entry_count: u64,
    regular_file_count: u64,
    directory_count: u64,
    symbolic_link_count: u64,
    whiteout_count: u64,
    regular_file_bytes: u64,
    changeset_transcript_sha256: [u8; 32],
}

impl ImportedOciLayerObservationV1 {
    fn from_layer_receipt(
        semantic_index: usize,
        receipt: &layer::ImportedOciLayerReceiptV1,
    ) -> Self {
        Self {
            semantic_index,
            compressed_byte_length: receipt.compressed_byte_length(),
            compressed_sha256: receipt.compressed_sha256(),
            uncompressed_byte_length: receipt.uncompressed_byte_length(),
            observed_uncompressed_sha256: receipt.observed_uncompressed_sha256(),
            entry_count: receipt.entry_count(),
            regular_file_count: receipt.regular_file_count(),
            directory_count: receipt.directory_count(),
            symbolic_link_count: receipt.symbolic_link_count(),
            whiteout_count: receipt.whiteout_count(),
            regular_file_bytes: receipt.regular_file_bytes(),
            changeset_transcript_sha256: receipt.changeset_transcript_sha256(),
        }
    }

    fn copy_inert(&self) -> Self {
        Self {
            semantic_index: self.semantic_index,
            compressed_byte_length: self.compressed_byte_length,
            compressed_sha256: self.compressed_sha256,
            uncompressed_byte_length: self.uncompressed_byte_length,
            observed_uncompressed_sha256: self.observed_uncompressed_sha256,
            entry_count: self.entry_count,
            regular_file_count: self.regular_file_count,
            directory_count: self.directory_count,
            symbolic_link_count: self.symbolic_link_count,
            whiteout_count: self.whiteout_count,
            regular_file_bytes: self.regular_file_bytes,
            changeset_transcript_sha256: self.changeset_transcript_sha256,
        }
    }
}

/// Affine completion of the exact four-role inventory. It retains the same
/// non-cloneable gate, owned inspection receipts and the four private logical
/// rootfs projections. The invariant brand binds it to the exact mutable
/// capability borrow which imported that inventory.
#[must_use = "the authenticated OCI completion retains the exact positive gate"]
pub(super) struct AuthenticatedOciOuterUstarImportCompletionV1<'session> {
    gate: PositiveGateBindings,
    receipts: [ReplayedOciOuterUstarReceiptV1; AUTHENTICATED_OCI_INVENTORY_SIZE],
    _session: PhantomData<fn(&'session mut ()) -> &'session mut ()>,
}

/// Affine proof that all four gate-bound OCI rootfs projections were
/// authenticated physically in canonical role order and explicitly cleaned
/// in reverse acquisition order.
///
/// The exact gate and inert abandonment observations remain private. This type
/// exposes no path, descriptor, rootfs projection, generic read capability or
/// detached JVM expectation.
#[must_use = "the authenticated physical OCI rootfs identity must remain session-affine"]
pub(super) struct AuthenticatedOciRootfsIdentityCompletionV1 {
    #[allow(dead_code, reason = "the exact gate remains owned affine evidence")]
    gate: PositiveGateBindings,
    #[cfg(target_os = "linux")]
    #[allow(
        dead_code,
        reason = "the four cleanup observations remain owned affine evidence"
    )]
    rootfs_abandonments: [rootfs::PrivateOciRootfsAbandonedV1; AUTHENTICATED_OCI_INVENTORY_SIZE],
}

/// Affine custody of all four gate-bound physical rootfs projections after
/// their static startup dependencies were authenticated. The exact positive
/// gate remains co-owned until a caller explicitly reauthenticates or cleans
/// the complete inventory.
#[must_use = "the retained host rootfs inventory must be reauthenticated and explicitly cleaned"]
pub(super) struct AuthenticatedOciRetainedHostRootfsInventoryV1 {
    gate: PositiveGateBindings,
    #[cfg(target_os = "linux")]
    retained_rootfs:
        [rootfs::AuthenticatedPrivateOciRetainedRootfsV1; AUTHENTICATED_OCI_INVENTORY_SIZE],
}

/// Affine failure while acquiring the complete retained-rootfs inventory.
/// The current-slot acquisition outcome, successful prior-slot cleanup
/// observations, incomplete prior-slot cleanup outcomes, the exact gate and
/// every structured error remain owned until a bounded consuming transition
/// either resolves the pending closeouts or returns the complete aggregate.
#[must_use = "failed retained-rootfs acquisition must be explicitly consumed or retained"]
pub(super) struct AuthenticatedOciRootfsInventoryAcquisitionFailureV1 {
    #[allow(dead_code, reason = "the exact gate remains owned affine evidence")]
    gate: Box<PositiveGateBindings>,
    #[cfg(target_os = "linux")]
    cleanup: Box<
        PhysicalRootfsInventoryAcquisitionFailureV1<
            rootfs::PrivateOciRootfsAbandonedV1,
            rootfs::PrivateOciRetainedRootfsCleanupFailureV1,
            rootfs::PrivateOciRetainedRootfsAcquisitionFailureV1,
        >,
    >,
    #[cfg(not(target_os = "linux"))]
    primary: anyhow::Error,
}

/// Affine failure while explicitly cleaning the complete retained-rootfs
/// inventory. Every canonical slot outcome remains owned across consuming
/// closeout transitions.
#[must_use = "failed retained-rootfs cleanup must be explicitly consumed or retained"]
pub(super) struct AuthenticatedOciRootfsInventoryCleanupFailureV1 {
    #[allow(dead_code, reason = "the exact gate remains owned affine evidence")]
    gate: Box<PositiveGateBindings>,
    #[cfg(target_os = "linux")]
    cleanup: Box<
        PhysicalRootfsInventoryCleanupFailureV1<
            rootfs::PrivateOciRootfsAbandonedV1,
            rootfs::PrivateOciRetainedRootfsCleanupFailureV1,
        >,
    >,
}

mod physical_rootfs_inventory_slot_seal {
    pub(super) trait Sealed {}
}

mod retained_physical_rootfs_inventory_slot_seal {
    pub(super) trait Sealed {}
}

mod physical_rootfs_inventory_cleanup_failure_seal {
    pub(super) trait Sealed {}
}

mod physical_rootfs_inventory_acquisition_failure_seal {
    pub(super) trait Sealed {}
}

trait RetryablePhysicalRootfsInventoryAcquisitionFailureV1:
    physical_rootfs_inventory_acquisition_failure_seal::Sealed
    + std::fmt::Debug
    + std::fmt::Display
    + std::error::Error
    + Send
    + Sync
    + Sized
    + 'static
{
    fn retry_cleanup(self) -> std::result::Result<anyhow::Error, Self>;
}

trait RetryablePhysicalRootfsInventoryCleanupFailureV1:
    physical_rootfs_inventory_cleanup_failure_seal::Sealed
    + std::fmt::Debug
    + std::fmt::Display
    + std::error::Error
    + Send
    + Sync
    + Sized
    + 'static
{
    type Abandonment;

    fn retry_cleanup(self) -> std::result::Result<Self::Abandonment, Self>;
}

trait RetainedPhysicalRootfsInventorySlotV1:
    retained_physical_rootfs_inventory_slot_seal::Sealed + Sized
{
    type Abandonment;
    type CleanupFailure: RetryablePhysicalRootfsInventoryCleanupFailureV1<
        Abandonment = Self::Abandonment,
    >;

    fn cleanup(self) -> std::result::Result<Self::Abandonment, Self::CleanupFailure>;
}

/// Private affine adapter consumed by the fixed four-slot physical rootfs
/// orchestrator. The sealed trait exposes no callback or authority outside this
/// module; its test implementation drives the exact production loop.
trait PhysicalRootfsInventorySlotV1: physical_rootfs_inventory_slot_seal::Sealed + Sized {
    type Expectation;
    type Retained: RetainedPhysicalRootfsInventorySlotV1;
    type AcquisitionFailure: RetryablePhysicalRootfsInventoryAcquisitionFailureV1;

    fn role(&self) -> PositiveRunnerRole;
    fn expectation_role(expectation: &Self::Expectation) -> PositiveRunnerRole;
    fn authenticate_and_retain(
        self,
        expectation: &Self::Expectation,
    ) -> std::result::Result<Self::Retained, Self::AcquisitionFailure>;
    fn discard_after_error(self, primary: anyhow::Error) -> anyhow::Error;
}

type PhysicalRootfsInventoryRetainedSlotV1<Slot> =
    <Slot as PhysicalRootfsInventorySlotV1>::Retained;
type PhysicalRootfsInventoryAcquisitionFailureForSlotV1<Slot> =
    PhysicalRootfsInventoryAcquisitionFailureV1<
        <PhysicalRootfsInventoryRetainedSlotV1<Slot> as RetainedPhysicalRootfsInventorySlotV1>::Abandonment,
        <PhysicalRootfsInventoryRetainedSlotV1<Slot> as RetainedPhysicalRootfsInventorySlotV1>::CleanupFailure,
        <Slot as PhysicalRootfsInventorySlotV1>::AcquisitionFailure,
    >;
type PhysicalRootfsInventoryAcquisitionResultV1<Slot> = std::result::Result<
    [PhysicalRootfsInventoryRetainedSlotV1<Slot>; AUTHENTICATED_OCI_INVENTORY_SIZE],
    PhysicalRootfsInventoryAcquisitionFailureForSlotV1<Slot>,
>;

type PhysicalRootfsInventoryAbandonmentV1<Retained> =
    <Retained as RetainedPhysicalRootfsInventorySlotV1>::Abandonment;
type PhysicalRootfsInventoryCleanupFailureForRetainedV1<Retained> =
    PhysicalRootfsInventoryCleanupFailureV1<
        PhysicalRootfsInventoryAbandonmentV1<Retained>,
        <Retained as RetainedPhysicalRootfsInventorySlotV1>::CleanupFailure,
    >;
type PhysicalRootfsInventoryCleanupResultV1<Retained> = std::result::Result<
    [PhysicalRootfsInventoryAbandonmentV1<Retained>; AUTHENTICATED_OCI_INVENTORY_SIZE],
    PhysicalRootfsInventoryCleanupFailureForRetainedV1<Retained>,
>;

#[cfg(target_os = "linux")]
impl retained_physical_rootfs_inventory_slot_seal::Sealed
    for rootfs::AuthenticatedPrivateOciRetainedRootfsV1
{
}

#[cfg(target_os = "linux")]
impl physical_rootfs_inventory_cleanup_failure_seal::Sealed
    for rootfs::PrivateOciRetainedRootfsCleanupFailureV1
{
}

#[cfg(target_os = "linux")]
impl physical_rootfs_inventory_acquisition_failure_seal::Sealed
    for rootfs::PrivateOciRetainedRootfsAcquisitionFailureV1
{
}

#[cfg(target_os = "linux")]
impl RetryablePhysicalRootfsInventoryAcquisitionFailureV1
    for rootfs::PrivateOciRetainedRootfsAcquisitionFailureV1
{
    fn retry_cleanup(self) -> std::result::Result<anyhow::Error, Self> {
        rootfs::PrivateOciRetainedRootfsAcquisitionFailureV1::retry_cleanup(self)
    }
}

#[cfg(target_os = "linux")]
impl RetryablePhysicalRootfsInventoryCleanupFailureV1
    for rootfs::PrivateOciRetainedRootfsCleanupFailureV1
{
    type Abandonment = rootfs::PrivateOciRootfsAbandonedV1;

    fn retry_cleanup(self) -> std::result::Result<Self::Abandonment, Self> {
        rootfs::PrivateOciRetainedRootfsCleanupFailureV1::retry_cleanup(self)
    }
}

#[cfg(target_os = "linux")]
impl RetainedPhysicalRootfsInventorySlotV1 for rootfs::AuthenticatedPrivateOciRetainedRootfsV1 {
    type Abandonment = rootfs::PrivateOciRootfsAbandonedV1;
    type CleanupFailure = rootfs::PrivateOciRetainedRootfsCleanupFailureV1;

    fn cleanup(self) -> std::result::Result<Self::Abandonment, Self::CleanupFailure> {
        rootfs::AuthenticatedPrivateOciRetainedRootfsV1::cleanup(self)
    }
}

#[cfg(target_os = "linux")]
impl physical_rootfs_inventory_slot_seal::Sealed for ReplayedOciOuterUstarReceiptV1 {}

#[cfg(target_os = "linux")]
impl PhysicalRootfsInventorySlotV1 for ReplayedOciOuterUstarReceiptV1 {
    type Expectation = B4PositiveOciImageLayoutV1;
    type Retained = rootfs::AuthenticatedPrivateOciRetainedRootfsV1;
    type AcquisitionFailure = rootfs::PrivateOciRetainedRootfsAcquisitionFailureV1;

    fn role(&self) -> PositiveRunnerRole {
        self.receipt.role
    }

    fn expectation_role(expectation: &Self::Expectation) -> PositiveRunnerRole {
        expectation.role()
    }

    fn authenticate_and_retain(
        self,
        expectation: &Self::Expectation,
    ) -> std::result::Result<Self::Retained, Self::AcquisitionFailure> {
        let Self { receipt: _, rootfs } = self;
        rootfs.authenticate_physical_rootfs_and_retain(expectation)
    }

    fn discard_after_error(self, primary: anyhow::Error) -> anyhow::Error {
        ReplayedOciOuterUstarReceiptV1::discard_after_error(self, primary)
    }
}

/// Execute the fixed four-slot physical identity transition in canonical role
/// order. On any slot failure, every later affine slot is explicitly discarded
/// in reverse order while the current-slot outcome and every prior-slot
/// closeout outcome remain owned by one typed aggregate.
fn authenticate_physical_rootfs_inventory_slots<Slot>(
    slots: [Slot; AUTHENTICATED_OCI_INVENTORY_SIZE],
    expectations: &[Slot::Expectation; AUTHENTICATED_OCI_INVENTORY_SIZE],
) -> PhysicalRootfsInventoryAcquisitionResultV1<Slot>
where
    Slot: PhysicalRootfsInventorySlotV1,
{
    let slot_roles = slots.each_ref().map(Slot::role);
    let expectation_roles =
        std::array::from_fn(|index| Slot::expectation_role(&expectations[index]));
    let precheck: Result<()> = (|| {
        validate_canonical_inventory_roles(slot_roles)?;
        validate_canonical_inventory_roles(expectation_roles)?;
        ensure!(
            slot_roles == expectation_roles,
            "authenticated OCI rootfs slots differ from gate image roles"
        );
        Ok(())
    })();
    if let Err(error) = precheck {
        let primary = discard_physical_rootfs_slots_after_error(Vec::from(slots), error);
        return Err(PhysicalRootfsInventoryAcquisitionFailureV1::without_retained(primary));
    }

    let mut remaining = slots
        .into_iter()
        .zip(canonical_positive_runner_roles())
        .enumerate();
    let mut retained_rootfs = Vec::with_capacity(AUTHENTICATED_OCI_INVENTORY_SIZE);
    while let Some((index, (slot, expected_role))) = remaining.next() {
        if slot.role() != expected_role {
            let mut unconsumed = vec![slot];
            unconsumed.extend(remaining.map(|(_, (slot, _))| slot));
            let primary = discard_physical_rootfs_slots_after_error(
                unconsumed,
                anyhow::anyhow!("authenticated OCI rootfs slot order changed after prevalidation"),
            );
            return Err(cleanup_retained_physical_rootfs_slots_preserving_primary(
                retained_rootfs,
                PhysicalRootfsInventoryAcquisitionPrimaryStateV1::<Slot::AcquisitionFailure>::NonRetry(
                    primary,
                ),
                Vec::new(),
            ));
        }
        match slot.authenticate_and_retain(&expectations[index]) {
            Ok(retained) => retained_rootfs.push(retained),
            Err(current_slot) => {
                let secondary = discard_remaining_physical_rootfs_slots(
                    remaining.map(|(_, (slot, _))| slot).collect(),
                );
                return Err(cleanup_retained_physical_rootfs_slots_preserving_primary(
                    retained_rootfs,
                    PhysicalRootfsInventoryAcquisitionPrimaryStateV1::CurrentSlot(current_slot),
                    secondary,
                ));
            }
        }
    }
    match retained_rootfs.try_into() {
        Ok(retained_rootfs) => Ok(retained_rootfs),
        Err(retained_rootfs) => Err(cleanup_retained_physical_rootfs_slots_preserving_primary(
            retained_rootfs,
            PhysicalRootfsInventoryAcquisitionPrimaryStateV1::<Slot::AcquisitionFailure>::NonRetry(
                anyhow::anyhow!("authenticated OCI retained-rootfs cardinality drift"),
            ),
            Vec::new(),
        )),
    }
}

fn discard_physical_rootfs_slots_after_error<Slot>(
    slots: Vec<Slot>,
    mut error: anyhow::Error,
) -> anyhow::Error
where
    Slot: PhysicalRootfsInventorySlotV1,
{
    for slot in slots.into_iter().rev() {
        error = slot.discard_after_error(error);
    }
    error
}

fn discard_remaining_physical_rootfs_slots_preserving_primary<Slot>(
    slots: Vec<Slot>,
    primary: anyhow::Error,
) -> anyhow::Error
where
    Slot: PhysicalRootfsInventorySlotV1,
{
    own_physical_rootfs_inventory_failures(primary, discard_remaining_physical_rootfs_slots(slots))
}

fn discard_remaining_physical_rootfs_slots<Slot>(slots: Vec<Slot>) -> Vec<anyhow::Error>
where
    Slot: PhysicalRootfsInventorySlotV1,
{
    if slots.is_empty() {
        Vec::new()
    } else {
        vec![discard_physical_rootfs_slots_after_error(
            slots,
            anyhow::anyhow!("discarding unconsumed OCI rootfs projections after physical failure"),
        )]
    }
}

#[derive(Debug)]
struct PhysicalRootfsInventoryOwnedFailuresV1 {
    secondary: Vec<anyhow::Error>,
}

impl std::fmt::Display for PhysicalRootfsInventoryOwnedFailuresV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("secondary physical rootfs closure outcomes were retained")?;
        for secondary in &self.secondary {
            write!(formatter, ": {secondary:#}")?;
        }
        Ok(())
    }
}

fn own_physical_rootfs_inventory_failures(
    primary: anyhow::Error,
    secondary: Vec<anyhow::Error>,
) -> anyhow::Error {
    if secondary.is_empty() {
        primary
    } else {
        primary.context(PhysicalRootfsInventoryOwnedFailuresV1 { secondary })
    }
}

enum PhysicalRootfsInventoryAcquisitionPrimaryStateV1<AcquisitionFailure> {
    NonRetry(anyhow::Error),
    CurrentSlot(AcquisitionFailure),
}

struct PhysicalRootfsInventoryAcquisitionFailureV1<Abandonment, CleanupFailure, AcquisitionFailure>
{
    primary: PhysicalRootfsInventoryAcquisitionPrimaryStateV1<AcquisitionFailure>,
    secondary: Vec<anyhow::Error>,
    cleanup_outcomes: [Option<std::result::Result<Abandonment, CleanupFailure>>;
        AUTHENTICATED_OCI_INVENTORY_SIZE],
}

impl<Abandonment, CleanupFailure, AcquisitionFailure>
    PhysicalRootfsInventoryAcquisitionFailureV1<Abandonment, CleanupFailure, AcquisitionFailure>
where
    CleanupFailure: RetryablePhysicalRootfsInventoryCleanupFailureV1<Abandonment = Abandonment>,
    AcquisitionFailure: RetryablePhysicalRootfsInventoryAcquisitionFailureV1,
{
    fn without_retained(primary: anyhow::Error) -> Self {
        Self {
            primary: PhysicalRootfsInventoryAcquisitionPrimaryStateV1::NonRetry(primary),
            secondary: Vec::new(),
            cleanup_outcomes: std::array::from_fn(|_| None),
        }
    }

    fn retry_cleanup(self) -> std::result::Result<anyhow::Error, Self> {
        let Self {
            primary,
            secondary,
            mut cleanup_outcomes,
        } = self;
        let primary = match primary {
            PhysicalRootfsInventoryAcquisitionPrimaryStateV1::NonRetry(primary) => {
                PhysicalRootfsInventoryAcquisitionPrimaryStateV1::NonRetry(primary)
            }
            PhysicalRootfsInventoryAcquisitionPrimaryStateV1::CurrentSlot(failure) => match failure
                .retry_cleanup()
            {
                Ok(primary) => PhysicalRootfsInventoryAcquisitionPrimaryStateV1::NonRetry(primary),
                Err(failure) => {
                    PhysicalRootfsInventoryAcquisitionPrimaryStateV1::CurrentSlot(failure)
                }
            },
        };
        for index in (0..AUTHENTICATED_OCI_INVENTORY_SIZE).rev() {
            let Some(outcome) = cleanup_outcomes[index].take() else {
                continue;
            };
            cleanup_outcomes[index] = Some(match outcome {
                Ok(abandonment) => Ok(abandonment),
                Err(failure) => failure.retry_cleanup(),
            });
        }
        if matches!(
            &primary,
            PhysicalRootfsInventoryAcquisitionPrimaryStateV1::CurrentSlot(_)
        ) || cleanup_outcomes
            .iter()
            .flatten()
            .any(std::result::Result::is_err)
        {
            Err(Self {
                primary,
                secondary,
                cleanup_outcomes,
            })
        } else {
            let PhysicalRootfsInventoryAcquisitionPrimaryStateV1::NonRetry(primary) = primary
            else {
                unreachable!("prechecked current-slot closure state changed")
            };
            Ok(own_physical_rootfs_inventory_failures(primary, secondary))
        }
    }

    fn pending_closure_count(&self) -> usize {
        usize::from(matches!(
            &self.primary,
            PhysicalRootfsInventoryAcquisitionPrimaryStateV1::CurrentSlot(_)
        )) + self
            .cleanup_outcomes
            .iter()
            .flatten()
            .filter(|outcome| outcome.is_err())
            .count()
    }

    fn primary_error(&self) -> Option<&anyhow::Error> {
        match &self.primary {
            PhysicalRootfsInventoryAcquisitionPrimaryStateV1::NonRetry(primary) => Some(primary),
            PhysicalRootfsInventoryAcquisitionPrimaryStateV1::CurrentSlot(_) => None,
        }
    }
}

impl<Abandonment, CleanupFailure, AcquisitionFailure> std::fmt::Debug
    for PhysicalRootfsInventoryAcquisitionFailureV1<Abandonment, CleanupFailure, AcquisitionFailure>
where
    CleanupFailure: RetryablePhysicalRootfsInventoryCleanupFailureV1<Abandonment = Abandonment>,
    AcquisitionFailure: RetryablePhysicalRootfsInventoryAcquisitionFailureV1,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("PhysicalRootfsInventoryAcquisitionFailureV1");
        match &self.primary {
            PhysicalRootfsInventoryAcquisitionPrimaryStateV1::NonRetry(primary) => {
                debug.field("primary", &format_args!("{primary:#}"));
            }
            PhysicalRootfsInventoryAcquisitionPrimaryStateV1::CurrentSlot(failure) => {
                debug.field("current_slot", failure);
            }
        }
        debug
            .field("secondary_failures", &self.secondary.len())
            .field("pending_consuming_closures", &self.pending_closure_count())
            .finish_non_exhaustive()
    }
}

impl<Abandonment, CleanupFailure, AcquisitionFailure> std::fmt::Display
    for PhysicalRootfsInventoryAcquisitionFailureV1<Abandonment, CleanupFailure, AcquisitionFailure>
where
    CleanupFailure: RetryablePhysicalRootfsInventoryCleanupFailureV1<Abandonment = Abandonment>,
    AcquisitionFailure: RetryablePhysicalRootfsInventoryAcquisitionFailureV1,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.primary {
            PhysicalRootfsInventoryAcquisitionPrimaryStateV1::NonRetry(primary) => {
                if formatter.alternate() {
                    write!(formatter, "{primary:#}")?;
                } else {
                    write!(formatter, "{primary}")?;
                }
            }
            PhysicalRootfsInventoryAcquisitionPrimaryStateV1::CurrentSlot(failure) => {
                write!(
                    formatter,
                    "current rootfs acquisition outcome awaits consuming closure: {failure}"
                )?;
            }
        }
        for secondary in &self.secondary {
            write!(
                formatter,
                "; secondary rootfs closure failure: {secondary:#}"
            )?;
        }
        for outcome in self.cleanup_outcomes.iter().rev().flatten() {
            if let Err(failure) = outcome {
                write!(
                    formatter,
                    "; retained rootfs cleanup remains incomplete: {failure}"
                )?;
            }
        }
        Ok(())
    }
}

impl<Abandonment, CleanupFailure, AcquisitionFailure> std::error::Error
    for PhysicalRootfsInventoryAcquisitionFailureV1<Abandonment, CleanupFailure, AcquisitionFailure>
where
    Abandonment: 'static,
    CleanupFailure: RetryablePhysicalRootfsInventoryCleanupFailureV1<Abandonment = Abandonment>,
    AcquisitionFailure: RetryablePhysicalRootfsInventoryAcquisitionFailureV1,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.primary {
            PhysicalRootfsInventoryAcquisitionPrimaryStateV1::NonRetry(primary) => {
                Some(primary.as_ref())
            }
            PhysicalRootfsInventoryAcquisitionPrimaryStateV1::CurrentSlot(failure) => Some(failure),
        }
    }
}

struct PhysicalRootfsInventoryCleanupFailureV1<Abandonment, CleanupFailure> {
    outcomes: [std::result::Result<Abandonment, CleanupFailure>; AUTHENTICATED_OCI_INVENTORY_SIZE],
}

impl<Abandonment, CleanupFailure>
    PhysicalRootfsInventoryCleanupFailureV1<Abandonment, CleanupFailure>
where
    CleanupFailure: RetryablePhysicalRootfsInventoryCleanupFailureV1<Abandonment = Abandonment>,
{
    fn retry_cleanup(
        self,
    ) -> std::result::Result<[Abandonment; AUTHENTICATED_OCI_INVENTORY_SIZE], Self> {
        let [slot_zero, slot_one, slot_two, slot_three] = self.outcomes;
        let slot_three = retry_physical_rootfs_cleanup_outcome(slot_three);
        let slot_two = retry_physical_rootfs_cleanup_outcome(slot_two);
        let slot_one = retry_physical_rootfs_cleanup_outcome(slot_one);
        let slot_zero = retry_physical_rootfs_cleanup_outcome(slot_zero);
        finish_physical_rootfs_inventory_cleanup([slot_zero, slot_one, slot_two, slot_three])
    }

    fn pending_closure_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| outcome.is_err())
            .count()
    }

    fn first_failure(&self) -> Option<&CleanupFailure> {
        self.outcomes
            .iter()
            .rev()
            .find_map(|outcome| outcome.as_ref().err())
    }
}

impl<Abandonment, CleanupFailure> std::fmt::Debug
    for PhysicalRootfsInventoryCleanupFailureV1<Abandonment, CleanupFailure>
where
    CleanupFailure: RetryablePhysicalRootfsInventoryCleanupFailureV1<Abandonment = Abandonment>,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PhysicalRootfsInventoryCleanupFailureV1")
            .field("pending_cleanup_closures", &self.pending_closure_count())
            .finish()
    }
}

impl<Abandonment, CleanupFailure> std::fmt::Display
    for PhysicalRootfsInventoryCleanupFailureV1<Abandonment, CleanupFailure>
where
    CleanupFailure: RetryablePhysicalRootfsInventoryCleanupFailureV1<Abandonment = Abandonment>,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("retained rootfs inventory cleanup remains incomplete")?;
        for outcome in self.outcomes.iter().rev() {
            if let Err(failure) = outcome {
                write!(formatter, ": {failure}")?;
            }
        }
        Ok(())
    }
}

impl<Abandonment, CleanupFailure> std::error::Error
    for PhysicalRootfsInventoryCleanupFailureV1<Abandonment, CleanupFailure>
where
    Abandonment: 'static,
    CleanupFailure: RetryablePhysicalRootfsInventoryCleanupFailureV1<Abandonment = Abandonment>,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.first_failure()
            .map(|failure| failure as &(dyn std::error::Error + 'static))
    }
}

fn retry_physical_rootfs_cleanup_outcome<Abandonment, CleanupFailure>(
    outcome: std::result::Result<Abandonment, CleanupFailure>,
) -> std::result::Result<Abandonment, CleanupFailure>
where
    CleanupFailure: RetryablePhysicalRootfsInventoryCleanupFailureV1<Abandonment = Abandonment>,
{
    match outcome {
        Ok(abandonment) => Ok(abandonment),
        Err(failure) => failure.retry_cleanup(),
    }
}

fn finish_physical_rootfs_inventory_cleanup<Abandonment, CleanupFailure>(
    outcomes: [std::result::Result<Abandonment, CleanupFailure>; AUTHENTICATED_OCI_INVENTORY_SIZE],
) -> std::result::Result<
    [Abandonment; AUTHENTICATED_OCI_INVENTORY_SIZE],
    PhysicalRootfsInventoryCleanupFailureV1<Abandonment, CleanupFailure>,
>
where
    CleanupFailure: RetryablePhysicalRootfsInventoryCleanupFailureV1<Abandonment = Abandonment>,
{
    if outcomes.iter().any(std::result::Result::is_err) {
        return Err(PhysicalRootfsInventoryCleanupFailureV1 { outcomes });
    }
    Ok(outcomes.map(|outcome| match outcome {
        Ok(abandonment) => abandonment,
        Err(_) => unreachable!("prechecked physical rootfs cleanup outcome changed"),
    }))
}

fn cleanup_retained_physical_rootfs_slots_preserving_primary<Retained, AcquisitionFailure>(
    retained_rootfs: Vec<Retained>,
    primary: PhysicalRootfsInventoryAcquisitionPrimaryStateV1<AcquisitionFailure>,
    secondary: Vec<anyhow::Error>,
) -> PhysicalRootfsInventoryAcquisitionFailureV1<
    Retained::Abandonment,
    Retained::CleanupFailure,
    AcquisitionFailure,
>
where
    Retained: RetainedPhysicalRootfsInventorySlotV1,
    AcquisitionFailure: RetryablePhysicalRootfsInventoryAcquisitionFailureV1,
{
    let mut cleanup_outcomes = std::array::from_fn(|_| None);
    for (index, retained) in retained_rootfs.into_iter().enumerate().rev() {
        cleanup_outcomes[index] = Some(retained.cleanup());
    }
    PhysicalRootfsInventoryAcquisitionFailureV1 {
        primary,
        secondary,
        cleanup_outcomes,
    }
}

fn cleanup_retained_physical_rootfs_inventory_slots<Retained>(
    retained_rootfs: [Retained; AUTHENTICATED_OCI_INVENTORY_SIZE],
) -> PhysicalRootfsInventoryCleanupResultV1<Retained>
where
    Retained: RetainedPhysicalRootfsInventorySlotV1,
{
    let [slot_zero, slot_one, slot_two, slot_three] = retained_rootfs;
    let slot_three = slot_three.cleanup();
    let slot_two = slot_two.cleanup();
    let slot_one = slot_one.cleanup();
    let slot_zero = slot_zero.cleanup();
    finish_physical_rootfs_inventory_cleanup([slot_zero, slot_one, slot_two, slot_three])
}

impl AuthenticatedOciOuterUstarImportCompletionV1<'_> {
    /// Borrow the exact successful positive gate retained across custody.
    pub(super) const fn positive_gate(&self) -> &PositiveGateBindings {
        &self.gate
    }

    /// Canonical roles of the four completed imports, in fixed inventory order.
    pub(super) fn imported_roles(&self) -> [PositiveRunnerRole; AUTHENTICATED_OCI_INVENTORY_SIZE] {
        self.receipts
            .each_ref()
            .map(|replayed| replayed.receipt.role)
    }

    /// Consume the exact logical completion under the same mutation session
    /// and retain each physically authenticated rootfs together with the gate
    /// needed to rederive its static startup dependencies.
    pub(super) fn authenticate_physical_rootfs_inventory_and_retain(
        self,
    ) -> std::result::Result<
        AuthenticatedOciRetainedHostRootfsInventoryV1,
        AuthenticatedOciRootfsInventoryAcquisitionFailureV1,
    > {
        #[cfg(not(target_os = "linux"))]
        {
            let Self {
                gate,
                receipts: _,
                _session: _,
            } = self;
            Err(AuthenticatedOciRootfsInventoryAcquisitionFailureV1 {
                gate: Box::new(gate),
                primary: anyhow::anyhow!(
                    "physical OCI rootfs identity authentication requires Linux"
                ),
            })
        }
        #[cfg(target_os = "linux")]
        {
            let Self {
                gate,
                receipts,
                _session: _,
            } = self;
            let retained_rootfs = match authenticate_physical_rootfs_inventory_slots(
                receipts,
                gate.oci_image_layouts(),
            ) {
                Ok(retained_rootfs) => retained_rootfs,
                Err(cleanup) => {
                    return Err(AuthenticatedOciRootfsInventoryAcquisitionFailureV1 {
                        gate: Box::new(gate),
                        cleanup: Box::new(cleanup),
                    });
                }
            };
            Ok(AuthenticatedOciRetainedHostRootfsInventoryV1 {
                gate,
                retained_rootfs,
            })
        }
    }
}

impl AuthenticatedOciRootfsInventoryAcquisitionFailureV1 {
    /// Consume the current acquisition outcome, then advance every pending
    /// prior-slot cleanup closeout once in reverse canonical order. An
    /// incomplete closeout returns the complete affine aggregate again;
    /// otherwise the exact stored primary error is returned unchanged.
    pub(super) fn retry_cleanup(self) -> std::result::Result<anyhow::Error, Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let Self { gate: _, primary } = self;
            Ok(primary)
        }
        #[cfg(target_os = "linux")]
        {
            let Self { gate, cleanup } = self;
            match (*cleanup).retry_cleanup() {
                Ok(primary) => Ok(primary),
                Err(cleanup) => Err(Self {
                    gate,
                    cleanup: Box::new(cleanup),
                }),
            }
        }
    }
}

impl std::fmt::Debug for AuthenticatedOciRootfsInventoryAcquisitionFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(not(target_os = "linux"))]
        {
            formatter
                .debug_struct("AuthenticatedOciRootfsInventoryAcquisitionFailureV1")
                .field("primary", &format_args!("{:#}", self.primary))
                .finish_non_exhaustive()
        }
        #[cfg(target_os = "linux")]
        {
            formatter
                .debug_struct("AuthenticatedOciRootfsInventoryAcquisitionFailureV1")
                .field("cleanup", self.cleanup.as_ref())
                .finish_non_exhaustive()
        }
    }
}

impl std::fmt::Display for AuthenticatedOciRootfsInventoryAcquisitionFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(not(target_os = "linux"))]
        {
            std::fmt::Display::fmt(&self.primary, formatter)
        }
        #[cfg(target_os = "linux")]
        {
            std::fmt::Display::fmt(self.cleanup.as_ref(), formatter)
        }
    }
}

impl std::error::Error for AuthenticatedOciRootfsInventoryAcquisitionFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[cfg(not(target_os = "linux"))]
        {
            Some(self.primary.as_ref())
        }
        #[cfg(target_os = "linux")]
        {
            Some(self.cleanup.as_ref())
        }
    }
}

impl AuthenticatedOciRootfsInventoryCleanupFailureV1 {
    /// Advance every pending physical cleanup closeout once, in reverse
    /// canonical order. Incomplete closeouts retain all slot outcomes.
    pub(super) fn retry_cleanup(
        self,
    ) -> std::result::Result<
        AuthenticatedOciRootfsIdentityCompletionV1,
        AuthenticatedOciRootfsInventoryCleanupFailureV1,
    > {
        #[cfg(not(target_os = "linux"))]
        {
            let Self { gate } = self;
            Ok(AuthenticatedOciRootfsIdentityCompletionV1 { gate: *gate })
        }
        #[cfg(target_os = "linux")]
        {
            let Self { gate, cleanup } = self;
            match (*cleanup).retry_cleanup() {
                Ok(rootfs_abandonments) => Ok(AuthenticatedOciRootfsIdentityCompletionV1 {
                    gate: *gate,
                    rootfs_abandonments,
                }),
                Err(cleanup) => Err(Self {
                    gate,
                    cleanup: Box::new(cleanup),
                }),
            }
        }
    }
}

impl std::fmt::Debug for AuthenticatedOciRootfsInventoryCleanupFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(not(target_os = "linux"))]
        {
            formatter
                .debug_struct("AuthenticatedOciRootfsInventoryCleanupFailureV1")
                .finish_non_exhaustive()
        }
        #[cfg(target_os = "linux")]
        {
            formatter
                .debug_struct("AuthenticatedOciRootfsInventoryCleanupFailureV1")
                .field("cleanup", self.cleanup.as_ref())
                .finish_non_exhaustive()
        }
    }
}

impl std::fmt::Display for AuthenticatedOciRootfsInventoryCleanupFailureV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(not(target_os = "linux"))]
        {
            formatter.write_str("retained rootfs inventory cleanup remains incomplete")
        }
        #[cfg(target_os = "linux")]
        {
            std::fmt::Display::fmt(self.cleanup.as_ref(), formatter)
        }
    }
}

impl std::error::Error for AuthenticatedOciRootfsInventoryCleanupFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
        #[cfg(target_os = "linux")]
        {
            Some(self.cleanup.as_ref())
        }
    }
}

impl AuthenticatedOciRetainedHostRootfsInventoryV1 {
    /// Rederive every role-local static startup dependency closure from the
    /// still-retained host rootfs and compare it to its authenticated baseline.
    pub(super) fn reauthenticate_static_startup_dependencies(&self) -> Result<()> {
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("retained OCI rootfs reauthentication requires Linux")
        }
        #[cfg(target_os = "linux")]
        {
            for (retained_rootfs, expectation) in self
                .retained_rootfs
                .iter()
                .zip(self.gate.oci_image_layouts())
            {
                retained_rootfs.reauthenticate_static_startup_dependencies(expectation)?;
            }
            Ok(())
        }
    }

    /// Explicitly clean the complete inventory in reverse acquisition order.
    /// A failure retains all successful observations and incomplete slot
    /// closeout outcomes.
    pub(super) fn cleanup(
        self,
    ) -> std::result::Result<
        AuthenticatedOciRootfsIdentityCompletionV1,
        AuthenticatedOciRootfsInventoryCleanupFailureV1,
    > {
        #[cfg(not(target_os = "linux"))]
        {
            let Self { gate } = self;
            Ok(AuthenticatedOciRootfsIdentityCompletionV1 { gate })
        }
        #[cfg(target_os = "linux")]
        {
            let Self {
                gate,
                retained_rootfs,
            } = self;
            match cleanup_retained_physical_rootfs_inventory_slots(retained_rootfs) {
                Ok(rootfs_abandonments) => Ok(AuthenticatedOciRootfsIdentityCompletionV1 {
                    gate,
                    rootfs_abandonments,
                }),
                Err(cleanup) => Err(AuthenticatedOciRootfsInventoryCleanupFailureV1 {
                    gate: Box::new(gate),
                    cleanup: Box::new(cleanup),
                }),
            }
        }
    }
}

fn discard_replayed_receipts_after_error(
    receipts: Vec<ReplayedOciOuterUstarReceiptV1>,
    mut error: anyhow::Error,
) -> anyhow::Error {
    for receipt in receipts.into_iter().rev() {
        error = receipt.discard_after_error(error);
    }
    error
}

const fn canonical_positive_runner_roles() -> [PositiveRunnerRole; AUTHENTICATED_OCI_INVENTORY_SIZE]
{
    [
        PositiveRunnerRole::RustValidatorBuild,
        PositiveRunnerRole::JvmValidatorBuild,
        PositiveRunnerRole::RustVerifier,
        PositiveRunnerRole::JvmVerifier,
    ]
}

fn validate_canonical_inventory_roles(
    roles: [PositiveRunnerRole; AUTHENTICATED_OCI_INVENTORY_SIZE],
) -> Result<()> {
    ensure!(
        roles == canonical_positive_runner_roles(),
        "authenticated OCI inventory is outside canonical runner order"
    );
    Ok(())
}

impl AuthenticatedOciOuterUstarInventoryV1 {
    fn roles(&self) -> [PositiveRunnerRole; AUTHENTICATED_OCI_INVENTORY_SIZE] {
        self.slots.each_ref().map(|slot| slot.role)
    }
}

/// Consume one authenticated physical locator whose permit already owns the
/// exact full positive profile. No detached profile argument can be paired with
/// the locator at this bridge.
fn project_authenticated_oci_outer_ustar_slot(
    permit: AuthenticatedOciSlotConstructionPermitV1,
) -> Result<OciOuterUstarSlotV1> {
    let (root_index, relative_path, profile) = permit.into_parts();
    let expectation = OciOuterUstarExpectationV1 {
        archive_byte_length: profile.archive_byte_length(),
        archive_sha256: profile.archive_sha256(),
        image: json::project_authenticated_oci_image_expectation(&profile)?,
    };
    validate_outer_ustar_expectation(&expectation)?;
    Ok(OciOuterUstarSlotV1 {
        role: profile.role(),
        root_index,
        relative_path,
        expectation,
    })
}

/// Bind exactly four locator/profile permits to the exact gate which produced
/// their cloned profiles. The returned inventory owns the gate and has no raw
/// slot projection.
pub(super) fn project_authenticated_oci_outer_ustar_inventory(
    permits: [AuthenticatedOciSlotConstructionPermitV1; AUTHENTICATED_OCI_INVENTORY_SIZE],
    gate: PositiveGateBindings,
) -> Result<AuthenticatedOciOuterUstarInventoryV1> {
    let mut slots = Vec::with_capacity(AUTHENTICATED_OCI_INVENTORY_SIZE);
    for ((permit, gate_profile), expected_role) in permits
        .into_iter()
        .zip(gate.oci_image_layouts())
        .zip(canonical_positive_runner_roles())
    {
        ensure!(
            permit.profile() == gate_profile,
            "authenticated OCI permit profile differs from its retained positive gate"
        );
        ensure!(
            gate_profile.role() == expected_role,
            "retained positive gate is outside canonical OCI runner order"
        );
        let slot = project_authenticated_oci_outer_ustar_slot(permit)?;
        ensure!(
            slot.role == expected_role,
            "authenticated OCI slot is outside canonical runner order"
        );
        slots.push(slot);
    }
    let slots = slots
        .try_into()
        .map_err(|_| anyhow::anyhow!("authenticated OCI inventory cardinality drift"))?;
    let inventory = AuthenticatedOciOuterUstarInventoryV1 { gate, slots };
    validate_canonical_inventory_roles(inventory.roles())?;
    Ok(inventory)
}

impl OciOuterUstarSlotV1 {
    #[cfg(test)]
    fn test_only(
        root_index: usize,
        relative_path: &str,
        expectation: OciOuterUstarExpectationV1,
    ) -> Self {
        Self::test_only_for_role(
            PositiveRunnerRole::RustValidatorBuild,
            root_index,
            relative_path,
            expectation,
        )
    }

    #[cfg(test)]
    fn test_only_for_role(
        role: PositiveRunnerRole,
        root_index: usize,
        relative_path: &str,
        expectation: OciOuterUstarExpectationV1,
    ) -> Self {
        Self {
            role,
            root_index,
            relative_path: relative_path.to_owned(),
            expectation,
        }
    }
}

impl OciOuterUstarExpectationV1 {
    #[cfg(test)]
    fn test_only(
        archive_byte_length: u64,
        archive_sha256: [u8; 32],
        image: json::OciImageExpectationV1,
    ) -> Self {
        Self {
            archive_byte_length,
            archive_sha256,
            image,
        }
    }
}

#[derive(Debug)]
struct OwnedOciBlobMemberV1 {
    digest: [u8; 32],
    byte_length: u64,
}

#[derive(Debug)]
struct OwnedOciOuterUstarInspectionV1 {
    archive_byte_length: u64,
    archive_sha256: [u8; 32],
    blobs: Vec<OwnedOciBlobMemberV1>,
    index_json_byte_length: u64,
    index_json_sha256: [u8; 32],
    validated_layer_count: Option<usize>,
    layers: Vec<ImportedOciLayerObservationV1>,
    observed_layer_uncompressed_bytes: u64,
    observed_layer_tar_entries: u64,
}

struct ReplayedOciOuterUstarWithRootfsV1 {
    inspection: OwnedOciOuterUstarInspectionV1,
    #[cfg(target_os = "linux")]
    rootfs: rootfs::PrivateOciRootfsStagingTransactionV1,
}

impl ReplayedOciOuterUstarWithRootfsV1 {
    fn discard_after_error(self, error: anyhow::Error) -> anyhow::Error {
        #[cfg(target_os = "linux")]
        {
            let Self {
                inspection: _,
                rootfs,
            } = self;
            rootfs.discard_after_error(error)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self;
            error
        }
    }
}

/// Inert post-custody view of one structurally authenticated outer archive.
///
/// It exposes fixed-size identities and counts only. No archive payload,
/// custody path, reader, descriptor, extraction or launch authority escapes.
struct ImportedOciOuterUstarViewV1<'inspection> {
    role: PositiveRunnerRole,
    post_changeset_rootfs: json::OciExpectedRootfsV1,
    inspection: &'inspection OwnedOciOuterUstarInspectionV1,
}

impl ImportedOciOuterUstarViewV1<'_> {
    const fn role(&self) -> PositiveRunnerRole {
        self.role
    }

    const fn post_changeset_entry_count(&self) -> u64 {
        self.post_changeset_rootfs.entry_count()
    }

    const fn post_changeset_regular_file_count(&self) -> u64 {
        self.post_changeset_rootfs.regular_file_count()
    }

    const fn post_changeset_directory_count(&self) -> u64 {
        self.post_changeset_rootfs.directory_count()
    }

    const fn post_changeset_symbolic_link_count(&self) -> u64 {
        self.post_changeset_rootfs.symbolic_link_count()
    }

    const fn post_changeset_regular_file_bytes(&self) -> u64 {
        self.post_changeset_rootfs.regular_file_bytes()
    }

    const fn archive_byte_length(&self) -> u64 {
        self.inspection.archive_byte_length
    }

    const fn archive_sha256(&self) -> [u8; 32] {
        self.inspection.archive_sha256
    }

    fn blob_count(&self) -> usize {
        self.inspection.blobs.len()
    }

    const fn index_json_byte_length(&self) -> u64 {
        self.inspection.index_json_byte_length
    }

    const fn index_json_sha256(&self) -> [u8; 32] {
        self.inspection.index_json_sha256
    }

    fn layers(&self) -> &[ImportedOciLayerObservationV1] {
        &self.inspection.layers
    }

    fn observed_layer_uncompressed_bytes(&self) -> u64 {
        self.inspection.observed_layer_uncompressed_bytes
    }

    fn observed_layer_tar_entries(&self) -> u64 {
        self.inspection.observed_layer_tar_entries
    }
}

/// Authenticate one affine OCI slot twice before returning any replay-typed
/// completion. Pass A inspects the archive; pass B independently reopens it and
/// drives the private anonymous rootfs staging sink and retains its authenticated
/// logical projection for the next closed continuation boundary.
fn with_replayed_oci_outer_ustar<const ROOTS: usize, T>(
    capability: &mut MutationCapability<'_, ROOTS, ProjectedPrepareInputSetCampaignLayout<ROOTS>>,
    slot: OciOuterUstarSlotV1,
    effect: impl for<'replay> FnOnce(
        ImportedOciOuterUstarViewV1<'replay>,
        ReplayedOciOuterUstarReceiptV1,
    ) -> Result<T>,
) -> Result<T> {
    let OciOuterUstarSlotV1 {
        role,
        root_index,
        relative_path,
        expectation,
    } = slot;
    validate_outer_ustar_expectation(&expectation)?;
    let expected_archive_byte_length = expectation.archive_byte_length;
    let post_changeset_rootfs = expectation.image.post_changeset_rootfs();
    let rootfs_final_guard = capability
        .projected_layout()
        .outer_create_only_layout()
        .final_path()
        .to_path_buf();
    capability.with_authenticated_oci_image_layout_ustar_replay_streams(
        OciOuterUstarCustodyPermitV1 { _private: () },
        root_index,
        &relative_path,
        expected_archive_byte_length,
        |byte_length, sha256, reader| {
            inspect_authenticated_oci_outer_ustar(&expectation, byte_length, sha256, reader)
        },
        |byte_length, sha256, inspection| {
            ensure!(
                inspection.archive_byte_length == byte_length
                    && inspection.archive_sha256 == sha256,
                "OCI outer-ustar inspection identity differs from retained physical custody"
            );
            Ok(ImportedOciOuterUstarReceiptV1::from_view(
                &ImportedOciOuterUstarViewV1 {
                    role,
                    post_changeset_rootfs,
                    inspection,
                },
            ))
        },
        |byte_length, sha256, reader| {
            replay_authenticated_oci_outer_ustar_with_rootfs(
                &expectation,
                role,
                &rootfs_final_guard,
                byte_length,
                sha256,
                reader,
            )
        },
        ReplayedOciOuterUstarWithRootfsV1::discard_after_error,
        move |inspected, byte_length, sha256, replay| {
            let ReplayedOciOuterUstarWithRootfsV1 {
                inspection,
                #[cfg(target_os = "linux")]
                rootfs,
            } = replay;
            if inspection.archive_byte_length != byte_length || inspection.archive_sha256 != sha256
            {
                let error = anyhow::anyhow!(
                    "OCI outer-ustar replay identity differs from retained physical custody"
                );
                #[cfg(target_os = "linux")]
                return Err(rootfs.discard_after_error(error));
                #[cfg(not(target_os = "linux"))]
                return Err(error);
            }
            let view = ImportedOciOuterUstarViewV1 {
                role,
                post_changeset_rootfs,
                inspection: &inspection,
            };
            #[cfg(target_os = "linux")]
            let transition = match inspected.into_authenticated_replay_transition(&view) {
                Ok(transition) => transition,
                Err(error) => return Err(rootfs.discard_after_error(error)),
            };
            #[cfg(not(target_os = "linux"))]
            let transition = inspected.into_authenticated_replay_transition(&view)?;
            #[cfg(target_os = "linux")]
            let receipt = transition.authenticate_rootfs(rootfs, post_changeset_rootfs)?;
            #[cfg(not(target_os = "linux"))]
            let receipt = ReplayedOciOuterUstarReceiptV1 {
                receipt: transition.receipt,
            };
            effect(view, receipt)
        },
    )
}

impl ImportedOciOuterUstarReceiptV1 {
    fn from_view(view: &ImportedOciOuterUstarViewV1<'_>) -> Self {
        Self {
            role: view.role(),
            post_changeset_rootfs: view.post_changeset_rootfs,
            archive_byte_length: view.archive_byte_length(),
            archive_sha256: view.archive_sha256(),
            blob_count: view.blob_count(),
            index_json_byte_length: view.index_json_byte_length(),
            index_json_sha256: view.index_json_sha256(),
            layers: view
                .layers()
                .iter()
                .map(ImportedOciLayerObservationV1::copy_inert)
                .collect(),
            observed_layer_uncompressed_bytes: view.observed_layer_uncompressed_bytes(),
            observed_layer_tar_entries: view.observed_layer_tar_entries(),
        }
    }

    fn replay_matches_inspection(&self, replay: &ImportedOciOuterUstarViewV1<'_>) -> Result<()> {
        ensure!(
            self.role == replay.role(),
            "OCI replay role differs from its inspected role"
        );
        ensure!(
            self.post_changeset_rootfs.entry_count() == replay.post_changeset_entry_count(),
            "OCI replay expected rootfs entry count differs from inspection"
        );
        ensure!(
            self.post_changeset_rootfs.regular_file_count()
                == replay.post_changeset_regular_file_count(),
            "OCI replay expected rootfs regular-file count differs from inspection"
        );
        ensure!(
            self.post_changeset_rootfs.directory_count() == replay.post_changeset_directory_count(),
            "OCI replay expected rootfs directory count differs from inspection"
        );
        ensure!(
            self.post_changeset_rootfs.symbolic_link_count()
                == replay.post_changeset_symbolic_link_count(),
            "OCI replay expected rootfs symbolic-link count differs from inspection"
        );
        ensure!(
            self.post_changeset_rootfs.regular_file_bytes()
                == replay.post_changeset_regular_file_bytes(),
            "OCI replay expected rootfs regular-file bytes differ from inspection"
        );
        ensure!(
            self.archive_byte_length == replay.archive_byte_length(),
            "OCI replay archive length differs from inspection"
        );
        ensure!(
            self.archive_sha256 == replay.archive_sha256(),
            "OCI replay archive SHA-256 differs from inspection"
        );
        ensure!(
            self.blob_count == replay.blob_count(),
            "OCI replay blob count differs from inspection"
        );
        ensure!(
            self.index_json_byte_length == replay.index_json_byte_length(),
            "OCI replay index.json length differs from inspection"
        );
        ensure!(
            self.index_json_sha256 == replay.index_json_sha256(),
            "OCI replay index.json SHA-256 differs from inspection"
        );
        ensure!(
            self.layers.len() == replay.layers().len(),
            "OCI replay layer count differs from inspection"
        );
        self.replay_layers_match_inspection(replay)?;
        ensure!(
            self.observed_layer_uncompressed_bytes == replay.observed_layer_uncompressed_bytes(),
            "OCI replay aggregate layer bytes differ from inspection"
        );
        ensure!(
            self.observed_layer_tar_entries == replay.observed_layer_tar_entries(),
            "OCI replay aggregate layer entries differ from inspection"
        );
        Ok(())
    }

    fn replay_layers_match_inspection(
        &self,
        replay: &ImportedOciOuterUstarViewV1<'_>,
    ) -> Result<()> {
        for (inspected, replayed) in self.layers.iter().zip(replay.layers()) {
            ensure!(
                inspected.semantic_index == replayed.semantic_index,
                "OCI replay layer semantic index differs from inspection"
            );
            ensure!(
                inspected.compressed_byte_length == replayed.compressed_byte_length,
                "OCI replay layer compressed length differs from inspection"
            );
            ensure!(
                inspected.compressed_sha256 == replayed.compressed_sha256,
                "OCI replay layer compressed SHA-256 differs from inspection"
            );
            ensure!(
                inspected.uncompressed_byte_length == replayed.uncompressed_byte_length,
                "OCI replay layer uncompressed length differs from inspection"
            );
            ensure!(
                inspected.observed_uncompressed_sha256 == replayed.observed_uncompressed_sha256,
                "OCI replay layer DiffID differs from inspection"
            );
            ensure!(
                inspected.entry_count == replayed.entry_count,
                "OCI replay layer entry count differs from inspection"
            );
            ensure!(
                inspected.regular_file_count == replayed.regular_file_count,
                "OCI replay layer regular-file count differs from inspection"
            );
            ensure!(
                inspected.directory_count == replayed.directory_count,
                "OCI replay layer directory count differs from inspection"
            );
            ensure!(
                inspected.symbolic_link_count == replayed.symbolic_link_count,
                "OCI replay layer symbolic-link count differs from inspection"
            );
            ensure!(
                inspected.whiteout_count == replayed.whiteout_count,
                "OCI replay layer whiteout count differs from inspection"
            );
            ensure!(
                inspected.regular_file_bytes == replayed.regular_file_bytes,
                "OCI replay layer regular-file bytes differ from inspection"
            );
            ensure!(
                inspected.changeset_transcript_sha256 == replayed.changeset_transcript_sha256,
                "OCI replay layer changeset transcript differs from inspection"
            );
        }
        Ok(())
    }

    fn into_authenticated_replay_transition(
        self,
        replay: &ImportedOciOuterUstarViewV1<'_>,
    ) -> Result<AuthenticatedOciReplayTransitionV1> {
        self.replay_matches_inspection(replay)?;
        let mut layer_seals = Vec::new();
        layer_seals
            .try_reserve_exact(self.layers.len())
            .context("cannot reserve authenticated OCI layer seals")?;
        for layer in &self.layers {
            layer_seals.push(AuthenticatedOciLayerSealV1 {
                semantic_layer_index: u64::try_from(layer.semantic_index)
                    .context("OCI semantic layer index does not fit u64")?,
                authenticated_entry_count: layer.entry_count,
                changeset_transcript_sha256: layer.changeset_transcript_sha256,
                _private: (),
            });
        }
        Ok(AuthenticatedOciReplayTransitionV1 {
            receipt: self,
            layer_seals,
        })
    }
}

#[cfg(target_os = "linux")]
impl AuthenticatedOciReplayTransitionV1 {
    fn authenticate_rootfs(
        self,
        rootfs: rootfs::PrivateOciRootfsStagingTransactionV1,
        expected: json::OciExpectedRootfsV1,
    ) -> Result<ReplayedOciOuterUstarReceiptV1> {
        let rootfs = rootfs.authenticate_and_retain(self.layer_seals, expected)?;
        Ok(ReplayedOciOuterUstarReceiptV1 {
            receipt: self.receipt,
            rootfs,
        })
    }
}

/// Import the complete gate-bound inventory in canonical order. Canonical role
/// order is checked for the whole affine array before the first descriptor-
/// rooted read; success is possible only after all four slots were consumed.
#[allow(
    clippy::elidable_lifetime_names,
    reason = "the explicit session lifetime pins the invariant brand to the exact mutation-capability borrow"
)]
pub(super) fn import_authenticated_oci_outer_ustar_inventory<
    'session,
    'context,
    const ROOTS: usize,
>(
    capability: &'session mut MutationCapability<
        'context,
        ROOTS,
        ProjectedPrepareInputSetCampaignLayout<ROOTS>,
    >,
    inventory: AuthenticatedOciOuterUstarInventoryV1,
) -> Result<AuthenticatedOciOuterUstarImportCompletionV1<'session>> {
    validate_canonical_inventory_roles(inventory.roles())?;
    let AuthenticatedOciOuterUstarInventoryV1 { gate, slots } = inventory;
    let receipts = import_authenticated_oci_outer_ustar_slots(capability, slots)?;
    Ok(AuthenticatedOciOuterUstarImportCompletionV1 {
        gate,
        receipts,
        _session: PhantomData,
    })
}

fn import_authenticated_oci_outer_ustar_slots<const ROOTS: usize>(
    capability: &mut MutationCapability<'_, ROOTS, ProjectedPrepareInputSetCampaignLayout<ROOTS>>,
    slots: [OciOuterUstarSlotV1; AUTHENTICATED_OCI_INVENTORY_SIZE],
) -> Result<[ReplayedOciOuterUstarReceiptV1; AUTHENTICATED_OCI_INVENTORY_SIZE]> {
    validate_canonical_inventory_roles(slots.each_ref().map(|slot| slot.role))?;
    let mut receipts = Vec::with_capacity(AUTHENTICATED_OCI_INVENTORY_SIZE);
    for (slot, expected_role) in slots.into_iter().zip(canonical_positive_runner_roles()) {
        let imported = (|| {
            ensure!(
                slot.role == expected_role,
                "authenticated OCI slot order changed after inventory prevalidation"
            );
            with_replayed_oci_outer_ustar(capability, slot, move |view, receipt| {
                if view.role() != expected_role {
                    return Err(receipt.discard_after_error(anyhow::anyhow!(
                        "imported OCI receipt role differs from canonical inventory order"
                    )));
                }
                Ok(receipt)
            })
        })();
        match imported {
            Ok(receipt) => receipts.push(receipt),
            Err(error) => {
                return Err(discard_replayed_receipts_after_error(receipts, error));
            }
        }
    }
    match receipts.try_into() {
        Ok(receipts) => Ok(receipts),
        Err(receipts) => Err(discard_replayed_receipts_after_error(
            receipts,
            anyhow::anyhow!("authenticated OCI receipt cardinality drift"),
        )),
    }
}

#[cfg(all(test, target_os = "linux"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OciOuterUstarImportStageV1 {
    PathPinned,
    DataOpened,
    BytesRead,
    FileRepinned,
}

#[cfg(all(test, target_os = "linux"))]
fn with_imported_oci_outer_ustar_test_hook<const ROOTS: usize, T>(
    capability: &mut MutationCapability<'_, ROOTS, ProjectedPrepareInputSetCampaignLayout<ROOTS>>,
    slot: OciOuterUstarSlotV1,
    mut hook: impl FnMut(OciOuterUstarImportStageV1) -> Result<()>,
    effect: impl for<'inspection> FnOnce(ImportedOciOuterUstarViewV1<'inspection>) -> Result<T>,
) -> Result<T> {
    use super::custody::ImmutableFileReadStage;

    let OciOuterUstarSlotV1 {
        role,
        root_index,
        relative_path,
        expectation,
    } = slot;
    validate_outer_ustar_expectation(&expectation)?;
    let expected_archive_byte_length = expectation.archive_byte_length;
    let post_changeset_rootfs = expectation.image.post_changeset_rootfs();
    capability.with_authenticated_oci_image_layout_ustar_stream_test_hook(
        OciOuterUstarCustodyPermitV1 { _private: () },
        root_index,
        &relative_path,
        expected_archive_byte_length,
        move |stage| {
            hook(match stage {
                ImmutableFileReadStage::PathPinned => OciOuterUstarImportStageV1::PathPinned,
                ImmutableFileReadStage::DataOpened => OciOuterUstarImportStageV1::DataOpened,
                ImmutableFileReadStage::BytesRead => OciOuterUstarImportStageV1::BytesRead,
                ImmutableFileReadStage::FileRepinned => OciOuterUstarImportStageV1::FileRepinned,
            })
        },
        move |byte_length, sha256, reader| {
            inspect_authenticated_oci_outer_ustar(&expectation, byte_length, sha256, reader)
        },
        move |byte_length, sha256, inspection| {
            ensure!(
                inspection.archive_byte_length == byte_length
                    && inspection.archive_sha256 == sha256,
                "OCI outer-ustar parser identity differs from retained physical custody"
            );
            effect(ImportedOciOuterUstarViewV1 {
                role,
                post_changeset_rootfs,
                inspection,
            })
        },
    )
}

enum ParsedOuterMemberNameV1 {
    Blob([u8; 32]),
    IndexJson,
    OciLayout,
}

struct ParsedOuterHeaderV1 {
    name: String,
    member: ParsedOuterMemberNameV1,
    payload_bytes: u64,
}

enum OuterArchiveStageV1 {
    Blobs,
    IndexSeen,
    LayoutSeen,
}

#[derive(Clone, Copy)]
enum OciLayerPassV1 {
    Inspection,
    AuthenticatedReplay,
}

#[derive(Clone, Copy)]
enum ExpectedOciBlobRoleV1 {
    Manifest,
    Config,
    Layer(usize),
}

struct OciGraphStreamStateV1<'expectation> {
    expectation: &'expectation json::OciImageExpectationV1,
    expected_index_json_byte_length: u64,
    manifest_seen: bool,
    config_seen: bool,
    layers_seen: Vec<bool>,
    layers: Vec<Option<ImportedOciLayerObservationV1>>,
    observed_layer_count: u64,
    observed_layer_uncompressed_bytes: u64,
    observed_layer_tar_entries: u64,
}

struct CompletedOciLayerSetV1 {
    layers: Vec<ImportedOciLayerObservationV1>,
    observed_layer_uncompressed_bytes: u64,
    observed_layer_tar_entries: u64,
}

impl<'expectation> OciGraphStreamStateV1<'expectation> {
    fn new(expectation: &'expectation json::OciImageExpectationV1) -> Result<Self> {
        json::validate_oci_image_expectation(expectation)?;
        let expected_index_json_byte_length = json::expected_index_json_byte_length(expectation)?;
        let mut layers_seen = Vec::new();
        layers_seen
            .try_reserve_exact(expectation.layers().len())
            .context("cannot reserve bounded OCI layer reachability state")?;
        layers_seen.resize(expectation.layers().len(), false);
        let mut layers = Vec::new();
        layers
            .try_reserve_exact(expectation.layers().len())
            .context("cannot reserve bounded OCI layer receipt state")?;
        layers.extend((0..expectation.layers().len()).map(|_| None));
        Ok(Self {
            expectation,
            expected_index_json_byte_length,
            manifest_seen: false,
            config_seen: false,
            layers_seen,
            layers,
            observed_layer_count: 0,
            observed_layer_uncompressed_bytes: 0,
            observed_layer_tar_entries: 0,
        })
    }

    fn require_blob(
        &mut self,
        digest: [u8; 32],
        byte_length: u64,
    ) -> Result<ExpectedOciBlobRoleV1> {
        let (role, expected, seen) = if digest == self.expectation.manifest().digest() {
            (
                ExpectedOciBlobRoleV1::Manifest,
                self.expectation.manifest(),
                &mut self.manifest_seen,
            )
        } else if digest == self.expectation.config().digest() {
            (
                ExpectedOciBlobRoleV1::Config,
                self.expectation.config(),
                &mut self.config_seen,
            )
        } else {
            let (index, layer) = self
                .expectation
                .layers()
                .iter()
                .enumerate()
                .find(|(_index, layer)| layer.compressed().digest() == digest)
                .context("OCI outer-ustar contains a blob outside the expected reachable graph")?;
            (
                ExpectedOciBlobRoleV1::Layer(index),
                layer.compressed(),
                self.layers_seen
                    .get_mut(index)
                    .context("OCI layer reachability index is outside its closed bound")?,
            )
        };
        ensure!(!*seen, "OCI reachable blob appears more than once");
        ensure!(
            byte_length == expected.byte_length(),
            "OCI blob member length differs from its expected descriptor"
        );
        *seen = true;
        Ok(role)
    }

    fn validate_json_payload(&self, role: ExpectedOciBlobRoleV1, source: &[u8]) -> Result<()> {
        match role {
            ExpectedOciBlobRoleV1::Manifest => {
                json::validate_manifest_json_source(source, self.expectation)
            }
            ExpectedOciBlobRoleV1::Config => {
                json::validate_config_json_source(source, self.expectation)
            }
            ExpectedOciBlobRoleV1::Layer(index) => {
                ensure!(
                    source.is_empty(),
                    "OCI layer {index} payload escaped its streaming route"
                );
                Ok(())
            }
        }
    }

    fn layer_expectation(&self, semantic_index: usize) -> Result<&json::OciExpectedLayerV1> {
        self.expectation
            .layers()
            .get(semantic_index)
            .context("OCI layer semantic index is outside its authenticated profile")
    }

    fn retain_layer_receipt(
        &mut self,
        semantic_index: usize,
        receipt: &layer::ImportedOciLayerReceiptV1,
        limits: OciLayerStreamLimitsV1,
    ) -> Result<()> {
        let expected_diff_id = self.layer_expectation(semantic_index)?.diff_id();
        let slot = self
            .layers
            .get_mut(semantic_index)
            .context("OCI layer receipt index is outside its closed bound")?;
        ensure!(
            slot.is_none(),
            "OCI layer receipt was retained more than once"
        );
        ensure!(
            receipt.observed_uncompressed_sha256() == expected_diff_id,
            "OCI layer semantic index {semantic_index} observed DiffID differs from its authenticated profile tuple"
        );
        self.observed_layer_count = limits.checked_add_layer(
            self.observed_layer_count,
            1,
            "authenticated OCI layer set",
        )?;
        self.observed_layer_uncompressed_bytes = limits.checked_add_uncompressed_tar_bytes(
            self.observed_layer_uncompressed_bytes,
            receipt.uncompressed_byte_length(),
            "authenticated OCI layer set",
        )?;
        self.observed_layer_tar_entries = limits.checked_add_tar_entries(
            self.observed_layer_tar_entries,
            receipt.entry_count(),
            "authenticated OCI layer set",
        )?;
        *slot = Some(ImportedOciLayerObservationV1::from_layer_receipt(
            semantic_index,
            receipt,
        ));
        Ok(())
    }

    fn require_complete(&self) -> Result<()> {
        ensure!(
            self.manifest_seen
                && self.config_seen
                && self.layers_seen.iter().all(|seen| *seen)
                && self.layers.iter().all(Option::is_some),
            "OCI outer-ustar is missing a blob from the expected reachable graph"
        );
        Ok(())
    }

    fn finish(self, limits: OciLayerStreamLimitsV1) -> Result<CompletedOciLayerSetV1> {
        self.require_complete()?;
        let expected_layer_count = u64::try_from(self.expectation.layers().len())?;
        ensure!(
            self.observed_layer_count == expected_layer_count,
            "OCI observed layer count differs from the authenticated profile"
        );
        let expected_uncompressed_bytes =
            self.expectation
                .layers()
                .iter()
                .try_fold(0_u64, |current, expected| {
                    limits.checked_add_uncompressed_tar_bytes(
                        current,
                        expected.uncompressed_byte_length(),
                        "authenticated OCI layer declarations",
                    )
                })?;
        ensure!(
            self.observed_layer_uncompressed_bytes == expected_uncompressed_bytes,
            "OCI observed aggregate uncompressed bytes differ from authenticated declarations"
        );
        let layers = self
            .layers
            .into_iter()
            .map(|layer| layer.context("OCI authenticated layer receipt is incomplete"))
            .collect::<Result<Vec<_>>>()?;
        Ok(CompletedOciLayerSetV1 {
            layers,
            observed_layer_uncompressed_bytes: self.observed_layer_uncompressed_bytes,
            observed_layer_tar_entries: self.observed_layer_tar_entries,
        })
    }
}

enum OciGraphValidationV1<'expectation> {
    Authenticated(OciGraphStreamStateV1<'expectation>),
    #[cfg(test)]
    StructuralTestOnly,
}

impl<'expectation> OciGraphValidationV1<'expectation> {
    fn authenticated(expectation: &'expectation json::OciImageExpectationV1) -> Result<Self> {
        Ok(Self::Authenticated(OciGraphStreamStateV1::new(
            expectation,
        )?))
    }

    #[cfg(test)]
    const fn structural_test_only() -> Self {
        Self::StructuralTestOnly
    }

    #[cfg_attr(not(test), allow(clippy::unnecessary_wraps))]
    fn state(&self) -> Option<&OciGraphStreamStateV1<'expectation>> {
        match self {
            Self::Authenticated(state) => Some(state),
            #[cfg(test)]
            Self::StructuralTestOnly => None,
        }
    }

    #[cfg_attr(not(test), allow(clippy::unnecessary_wraps))]
    fn state_mut(&mut self) -> Option<&mut OciGraphStreamStateV1<'expectation>> {
        match self {
            Self::Authenticated(state) => Some(state),
            #[cfg(test)]
            Self::StructuralTestOnly => None,
        }
    }

    fn finish(self, limits: OciLayerStreamLimitsV1) -> Result<CompletedOciLayerSetV1> {
        match self {
            Self::Authenticated(state) => state.finish(limits),
            #[cfg(test)]
            Self::StructuralTestOnly => Ok(CompletedOciLayerSetV1 {
                layers: Vec::new(),
                observed_layer_uncompressed_bytes: 0,
                observed_layer_tar_entries: 0,
            }),
        }
    }
}

struct HashedArchiveReaderV1<'reader> {
    reader: &'reader mut (dyn Read + 'reader),
    observed_bytes: u64,
    hasher: Sha256,
}

/// Exact-member streaming adapter. It cannot read past one authenticated
/// outer-ustar member, and every byte it does read advances the enclosing
/// archive identity before reaching the private layer parser.
struct ExactOuterMemberReaderV1<'archive, 'reader> {
    archive: &'archive mut HashedArchiveReaderV1<'reader>,
    remaining: u64,
}

struct InspectedMemberPayloadV1 {
    sha256: [u8; 32],
    captured: Option<Vec<u8>>,
}

impl<'reader> HashedArchiveReaderV1<'reader> {
    fn new(reader: &'reader mut (dyn Read + 'reader)) -> Self {
        Self {
            reader,
            observed_bytes: 0,
            hasher: Sha256::new(),
        }
    }

    fn read_hashed(&mut self, destination: &mut [u8]) -> io::Result<usize> {
        let read = self.reader.read(destination)?;
        self.observed_bytes = self
            .observed_bytes
            .checked_add(u64::try_from(read).expect("read length fits in u64"))
            .ok_or_else(|| io::Error::other("OCI outer-ustar observed length overflowed"))?;
        self.hasher.update(&destination[..read]);
        Ok(read)
    }

    fn read_exact_hashed(&mut self, destination: &mut [u8], label: &str) -> Result<()> {
        let mut offset = 0_usize;
        while offset < destination.len() {
            let read = self
                .read_hashed(&mut destination[offset..])
                .with_context(|| format!("cannot read exact {label}"))?;
            ensure!(read != 0, "cannot read exact {label}: unexpected EOF");
            offset = offset
                .checked_add(read)
                .context("OCI exact-read offset overflowed")?;
        }
        Ok(())
    }

    fn inspect_layer_payload(
        &mut self,
        payload_bytes: u64,
        expectation: &json::OciExpectedLayerV1,
        pass: OciLayerPassV1,
    ) -> Result<layer::ImportedOciLayerReceiptV1> {
        self.inspect_layer_payload_inner(payload_bytes, expectation, pass, None)
    }

    fn replay_layer_payload_with_sink(
        &mut self,
        payload_bytes: u64,
        expectation: &json::OciExpectedLayerV1,
        sink: &mut dyn layer::OciLayerReplaySinkV1,
    ) -> Result<layer::ImportedOciLayerReceiptV1> {
        self.inspect_layer_payload_inner(
            payload_bytes,
            expectation,
            OciLayerPassV1::AuthenticatedReplay,
            Some(sink),
        )
    }

    fn inspect_layer_payload_inner(
        &mut self,
        payload_bytes: u64,
        expectation: &json::OciExpectedLayerV1,
        pass: OciLayerPassV1,
        replay_sink: Option<&mut dyn layer::OciLayerReplaySinkV1>,
    ) -> Result<layer::ImportedOciLayerReceiptV1> {
        ensure!(
            expectation.compressed().byte_length() == payload_bytes,
            "OCI layer member length differs from its authenticated descriptor"
        );
        let mut member = ExactOuterMemberReaderV1 {
            archive: self,
            remaining: payload_bytes,
        };
        let receipt = match pass {
            OciLayerPassV1::Inspection => {
                ensure!(
                    replay_sink.is_none(),
                    "OCI inspection cannot drive a rootfs replay sink"
                );
                layer::inspect_authenticated_oci_layer(&mut member, expectation)?
            }
            OciLayerPassV1::AuthenticatedReplay => match replay_sink {
                Some(sink) => {
                    layer::replay_authenticated_oci_layer_with_sink(&mut member, expectation, sink)?
                }
                None => layer::replay_authenticated_oci_layer(&mut member, expectation)?,
            },
        };
        member.require_complete()?;
        self.consume_zero_member_padding(payload_bytes)?;
        Ok(receipt)
    }

    fn consume_zero_member_padding(&mut self, payload_bytes: u64) -> Result<()> {
        let padding_bytes =
            (USTAR_BLOCK_BYTES_U64 - payload_bytes % USTAR_BLOCK_BYTES_U64) % USTAR_BLOCK_BYTES_U64;
        if padding_bytes == 0 {
            return Ok(());
        }
        let mut padding = [0_u8; USTAR_BLOCK_BYTES];
        let padding_length = usize::try_from(padding_bytes)?;
        self.read_exact_hashed(
            &mut padding[..padding_length],
            "OCI outer-ustar member padding",
        )?;
        ensure!(
            padding[..padding_length].iter().all(|byte| *byte == 0),
            "OCI outer-ustar member padding is not zero"
        );
        Ok(())
    }

    fn inspect_payload(
        &mut self,
        payload_bytes: u64,
        exact_payload: Option<&[u8]>,
        capture: bool,
    ) -> Result<InspectedMemberPayloadV1> {
        if let Some(exact) = exact_payload {
            ensure!(
                u64::try_from(exact.len())? == payload_bytes,
                "OCI outer-ustar fixed payload length differs from its header"
            );
        }
        let mut captured = if capture {
            ensure!(
                payload_bytes <= OCI_INDEX_JSON_MAX_BYTES,
                "captured OCI JSON payload exceeds its closed byte bound"
            );
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(usize::try_from(payload_bytes)?)
                .context("cannot reserve bounded OCI JSON payload")?;
            Some(bytes)
        } else {
            None
        };
        let mut payload_hasher = Sha256::new();
        let mut buffer = [0_u8; MEMBER_IO_BUFFER_BYTES];
        let mut remaining = payload_bytes;
        let mut exact_offset = 0_usize;
        while remaining > 0 {
            let request = usize::try_from(remaining.min(u64::try_from(buffer.len())?))?;
            self.read_exact_hashed(&mut buffer[..request], "OCI outer-ustar member payload")?;
            if let Some(exact) = exact_payload {
                let exact_end = exact_offset
                    .checked_add(request)
                    .context("OCI fixed-payload offset overflowed")?;
                ensure!(
                    buffer[..request] == exact[exact_offset..exact_end],
                    "OCI outer-ustar oci-layout payload is not exact"
                );
                exact_offset = exact_end;
            }
            payload_hasher.update(&buffer[..request]);
            if let Some(bytes) = captured.as_mut() {
                bytes.extend_from_slice(&buffer[..request]);
            }
            remaining -= u64::try_from(request)?;
        }

        self.consume_zero_member_padding(payload_bytes)?;
        Ok(InspectedMemberPayloadV1 {
            sha256: payload_hasher.finalize().into(),
            captured,
        })
    }

    fn require_exact_eof(&mut self) -> Result<()> {
        let mut probe = [0_u8; 1];
        let count = self
            .reader
            .read(&mut probe)
            .context("cannot probe OCI outer-ustar EOF")?;
        ensure!(
            count == 0,
            "OCI outer-ustar has bytes after its exact two-block terminator"
        );
        Ok(())
    }

    fn finish(self, byte_length: u64, expected_sha256: [u8; 32]) -> Result<[u8; 32]> {
        ensure!(
            self.observed_bytes == byte_length,
            "OCI outer-ustar consumed length differs from its retained archive length"
        );
        let observed_sha256: [u8; 32] = self.hasher.finalize().into();
        ensure!(
            observed_sha256 == expected_sha256,
            "OCI outer-ustar SHA-256 differs from retained physical custody"
        );
        Ok(observed_sha256)
    }
}

impl ExactOuterMemberReaderV1<'_, '_> {
    fn require_complete(self) -> Result<()> {
        ensure!(
            self.remaining == 0,
            "OCI layer parser did not consume its exact outer-ustar member"
        );
        Ok(())
    }
}

impl Read for ExactOuterMemberReaderV1<'_, '_> {
    fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
        if destination.is_empty() || self.remaining == 0 {
            return Ok(0);
        }
        let request = destination
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let read = self.archive.read_hashed(&mut destination[..request])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "OCI outer-ustar layer member is truncated",
            ));
        }
        self.remaining -= u64::try_from(read).expect("read length fits in u64");
        Ok(read)
    }
}

fn validate_oci_outer_ustar_role_contract(
    byte_length: u64,
) -> Result<super::artifact_import_contract::OciArtifactImportLimitsV1> {
    let limits = B4ImmutableArtifactRoleV1::OciImageLayoutUstar.limits();
    let (minimum, maximum) = limits.encoded_byte_range();
    let nested = limits.require_oci("OCI image-layout ustar")?;
    let maximum_layers = nested.layer_stream().maximum_layers();
    ensure!(
        minimum == OCI_OUTER_USTAR_MIN_BYTES
            && maximum == OCI_OUTER_USTAR_MAX_BYTES
            && limits.encoded_byte_multiple() == Some(USTAR_BLOCK_BYTES_U64)
            && nested.maximum_outer_ustar_member_payload_bytes()
                == OCI_OUTER_USTAR_MAX_MEMBER_BYTES
            && maximum_layers == 128
            && OCI_OUTER_USTAR_MIN_BLOBS == 3
            && u64::try_from(OCI_OUTER_USTAR_MAX_BLOBS)? == maximum_layers + 2,
        "OCI outer-ustar parser ceilings differ from the closed role contract"
    );
    limits.validate_encoded_length(byte_length, "OCI image-layout ustar")?;
    Ok(nested)
}

fn outer_ustar_member_extent(payload_bytes: u64) -> Result<u64> {
    let padded_payload_bytes = payload_bytes
        .checked_add(USTAR_BLOCK_BYTES_U64 - 1)
        .context("OCI outer-ustar payload rounding overflowed")?
        .checked_div(USTAR_BLOCK_BYTES_U64)
        .context("OCI outer-ustar block size cannot be zero")?
        .checked_mul(USTAR_BLOCK_BYTES_U64)
        .context("OCI outer-ustar padded payload length overflowed")?;
    USTAR_BLOCK_BYTES_U64
        .checked_add(padded_payload_bytes)
        .context("OCI outer-ustar member extent overflowed")
}

fn validate_outer_ustar_expectation(expectation: &OciOuterUstarExpectationV1) -> Result<()> {
    let nested = validate_oci_outer_ustar_role_contract(expectation.archive_byte_length)?;
    ensure!(
        nested.maximum_json_bytes() == OCI_INDEX_JSON_MAX_BYTES,
        "OCI JSON ceiling differs from the closed role contract"
    );
    json::validate_oci_image_expectation(&expectation.image)?;
    let index_json_byte_length = json::expected_index_json_byte_length(&expectation.image)?;
    nested.validate_json_bytes(index_json_byte_length, "expected OCI index.json")?;

    let mut expected_archive_byte_length = 2_u64
        .checked_mul(USTAR_BLOCK_BYTES_U64)
        .context("OCI outer-ustar terminator length overflowed")?;
    for payload_bytes in [
        u64::try_from(OCI_LAYOUT_BYTES.len())?,
        index_json_byte_length,
        expectation.image.manifest().byte_length(),
        expectation.image.config().byte_length(),
    ] {
        expected_archive_byte_length = expected_archive_byte_length
            .checked_add(outer_ustar_member_extent(payload_bytes)?)
            .context("OCI outer-ustar fixed-member footprint overflowed")?;
    }
    for layer in expectation.image.layers() {
        expected_archive_byte_length = expected_archive_byte_length
            .checked_add(outer_ustar_member_extent(layer.compressed().byte_length())?)
            .context("OCI outer-ustar layer footprint overflowed")?;
    }
    ensure!(
        expected_archive_byte_length == expectation.archive_byte_length,
        "OCI archive byte length differs from the exact closed-ustar footprint"
    );
    Ok(())
}

fn finish_oci_outer_ustar_terminator(
    mut archive: HashedArchiveReaderV1<'_>,
    byte_length: u64,
    expected_sha256: [u8; 32],
    stage: &OuterArchiveStageV1,
    blob_count: usize,
) -> Result<[u8; 32]> {
    let mut second_terminator = [0_u8; USTAR_BLOCK_BYTES];
    archive.read_exact_hashed(
        &mut second_terminator,
        "OCI outer-ustar second terminator block",
    )?;
    ensure!(
        second_terminator.iter().all(|byte| *byte == 0),
        "OCI outer-ustar second terminator block is not zero"
    );
    ensure!(
        matches!(stage, OuterArchiveStageV1::LayoutSeen),
        "OCI outer-ustar terminated before index.json and oci-layout"
    );
    ensure!(
        (OCI_OUTER_USTAR_MIN_BLOBS..=OCI_OUTER_USTAR_MAX_BLOBS).contains(&blob_count),
        "OCI outer-ustar blob count is outside the closed range"
    );
    archive.require_exact_eof()?;
    archive.finish(byte_length, expected_sha256)
}

fn inspect_authenticated_oci_outer_ustar(
    expectation: &OciOuterUstarExpectationV1,
    byte_length: u64,
    expected_sha256: [u8; 32],
    reader: &mut dyn Read,
) -> Result<OwnedOciOuterUstarInspectionV1> {
    validate_outer_ustar_expectation(expectation)?;
    ensure!(
        byte_length == expectation.archive_byte_length,
        "OCI archive length differs from its expected profile identity"
    );
    ensure!(
        expected_sha256 == expectation.archive_sha256,
        "OCI archive SHA-256 differs from its expected profile identity"
    );
    inspect_oci_outer_ustar_impl(
        OciGraphValidationV1::authenticated(&expectation.image)?,
        OciLayerPassV1::Inspection,
        byte_length,
        expected_sha256,
        reader,
        None,
    )
}

fn replay_authenticated_oci_outer_ustar(
    expectation: &OciOuterUstarExpectationV1,
    byte_length: u64,
    expected_sha256: [u8; 32],
    reader: &mut dyn Read,
) -> Result<OwnedOciOuterUstarInspectionV1> {
    validate_outer_ustar_expectation(expectation)?;
    ensure!(
        byte_length == expectation.archive_byte_length,
        "OCI replay archive length differs from its expected profile identity"
    );
    ensure!(
        expected_sha256 == expectation.archive_sha256,
        "OCI replay archive SHA-256 differs from its expected profile identity"
    );
    inspect_oci_outer_ustar_impl(
        OciGraphValidationV1::authenticated(&expectation.image)?,
        OciLayerPassV1::AuthenticatedReplay,
        byte_length,
        expected_sha256,
        reader,
        None,
    )
}

#[cfg(target_os = "linux")]
fn replay_authenticated_oci_outer_ustar_with_rootfs(
    expectation: &OciOuterUstarExpectationV1,
    role: PositiveRunnerRole,
    final_guard: &Path,
    byte_length: u64,
    expected_sha256: [u8; 32],
    reader: &mut dyn Read,
) -> Result<ReplayedOciOuterUstarWithRootfsV1> {
    validate_outer_ustar_expectation(expectation)?;
    ensure!(
        byte_length == expectation.archive_byte_length,
        "OCI replay archive length differs from its expected profile identity"
    );
    ensure!(
        expected_sha256 == expectation.archive_sha256,
        "OCI replay archive SHA-256 differs from its expected profile identity"
    );
    let expected_semantic_layers = u64::try_from(expectation.image.layers().len())
        .context("OCI semantic layer count does not fit u64")?;
    let graph = OciGraphValidationV1::authenticated(&expectation.image)?;
    let mut rootfs =
        rootfs::begin_private_oci_rootfs_staging(role, final_guard, expected_semantic_layers)?;
    let replay = inspect_oci_outer_ustar_impl(
        graph,
        OciLayerPassV1::AuthenticatedReplay,
        byte_length,
        expected_sha256,
        reader,
        Some(&mut rootfs),
    );
    match replay {
        Ok(inspection) => Ok(ReplayedOciOuterUstarWithRootfsV1 { inspection, rootfs }),
        Err(error) => Err(rootfs.discard_after_error(error)),
    }
}

#[cfg(not(target_os = "linux"))]
fn replay_authenticated_oci_outer_ustar_with_rootfs(
    expectation: &OciOuterUstarExpectationV1,
    role: PositiveRunnerRole,
    final_guard: &Path,
    byte_length: u64,
    expected_sha256: [u8; 32],
    reader: &mut dyn Read,
) -> Result<ReplayedOciOuterUstarWithRootfsV1> {
    let _ = (role, final_guard);
    Ok(ReplayedOciOuterUstarWithRootfsV1 {
        inspection: replay_authenticated_oci_outer_ustar(
            expectation,
            byte_length,
            expected_sha256,
            reader,
        )?,
    })
}

#[cfg(test)]
fn inspect_structural_oci_outer_ustar(
    byte_length: u64,
    expected_sha256: [u8; 32],
    reader: &mut dyn Read,
) -> Result<OwnedOciOuterUstarInspectionV1> {
    inspect_oci_outer_ustar_impl(
        OciGraphValidationV1::structural_test_only(),
        OciLayerPassV1::Inspection,
        byte_length,
        expected_sha256,
        reader,
        None,
    )
}

#[allow(clippy::too_many_lines)]
fn inspect_oci_outer_ustar_impl(
    mut graph: OciGraphValidationV1<'_>,
    layer_pass: OciLayerPassV1,
    byte_length: u64,
    expected_sha256: [u8; 32],
    reader: &mut dyn Read,
    mut rootfs: Option<&mut ActiveOciRootfsReplayTransactionV1>,
) -> Result<OwnedOciOuterUstarInspectionV1> {
    let nested = validate_oci_outer_ustar_role_contract(byte_length)?;

    let mut archive = HashedArchiveReaderV1::new(reader);
    let mut blobs = Vec::new();
    blobs
        .try_reserve_exact(OCI_OUTER_USTAR_MAX_BLOBS)
        .context("cannot reserve the bounded OCI blob identity set")?;
    let mut previous_name: Option<String> = None;
    let mut stage = OuterArchiveStageV1::Blobs;
    let mut member_count = 0_usize;
    let mut index_json_byte_length = None;
    let mut index_json_sha256 = None;

    loop {
        let mut header = [0_u8; USTAR_BLOCK_BYTES];
        archive.read_exact_hashed(&mut header, "OCI outer-ustar header or terminator")?;
        if header.iter().all(|byte| *byte == 0) {
            let validated_layer_count = graph.state().map(|state| state.expectation.layers().len());
            let completed_layers = graph.finish(nested.layer_stream())?;
            let CompletedOciLayerSetV1 {
                layers,
                observed_layer_uncompressed_bytes,
                observed_layer_tar_entries,
            } = completed_layers;
            let archive_sha256 = finish_oci_outer_ustar_terminator(
                archive,
                byte_length,
                expected_sha256,
                &stage,
                blobs.len(),
            )?;
            return Ok(OwnedOciOuterUstarInspectionV1 {
                archive_byte_length: byte_length,
                archive_sha256,
                blobs,
                index_json_byte_length: index_json_byte_length
                    .context("OCI outer-ustar index.json identity is absent")?,
                index_json_sha256: index_json_sha256
                    .context("OCI outer-ustar index.json digest is absent")?,
                validated_layer_count,
                layers,
                observed_layer_uncompressed_bytes,
                observed_layer_tar_entries,
            });
        }

        ensure!(
            member_count < OCI_OUTER_USTAR_MAX_MEMBERS,
            "OCI outer-ustar member count exceeds the closed range"
        );
        member_count += 1;
        let parsed = parse_outer_ustar_header(&header, nested)?;
        if let Some(previous) = previous_name.as_ref() {
            ensure!(
                previous.as_bytes() < parsed.name.as_bytes(),
                "OCI outer-ustar member names are not strictly increasing"
            );
        }
        previous_name = Some(parsed.name);

        match parsed.member {
            ParsedOuterMemberNameV1::Blob(digest) => {
                ensure!(
                    matches!(stage, OuterArchiveStageV1::Blobs),
                    "OCI outer-ustar blob appears after a metadata member"
                );
                ensure!(
                    blobs.len() < OCI_OUTER_USTAR_MAX_BLOBS,
                    "OCI outer-ustar blob count exceeds the closed range"
                );
                let expected_role = graph
                    .state_mut()
                    .map(|state| state.require_blob(digest, parsed.payload_bytes))
                    .transpose()?;
                let capture = matches!(
                    expected_role,
                    Some(ExpectedOciBlobRoleV1::Manifest | ExpectedOciBlobRoleV1::Config)
                );
                match expected_role {
                    Some(ExpectedOciBlobRoleV1::Layer(semantic_index)) => {
                        let expectation = graph
                            .state()
                            .context("authenticated OCI layer state is absent")?
                            .layer_expectation(semantic_index)?;
                        #[cfg(target_os = "linux")]
                        let receipt = if let Some(transaction) = rootfs.as_deref_mut() {
                            ensure!(
                                matches!(layer_pass, OciLayerPassV1::AuthenticatedReplay),
                                "OCI rootfs sink cannot run during inspection"
                            );
                            let semantic_layer_index = u64::try_from(semantic_index)
                                .context("OCI semantic layer index does not fit u64")?;
                            let mut sink =
                                transaction.replay_semantic_layer_sink(semantic_layer_index)?;
                            archive.replay_layer_payload_with_sink(
                                parsed.payload_bytes,
                                expectation,
                                &mut sink,
                            )?
                        } else {
                            archive.inspect_layer_payload(
                                parsed.payload_bytes,
                                expectation,
                                layer_pass,
                            )?
                        };
                        #[cfg(not(target_os = "linux"))]
                        let receipt = {
                            let _ = &mut rootfs;
                            archive.inspect_layer_payload(
                                parsed.payload_bytes,
                                expectation,
                                layer_pass,
                            )?
                        };
                        ensure!(
                            receipt.compressed_sha256() == digest,
                            "OCI layer payload digest differs from its outer member name"
                        );
                        graph
                            .state_mut()
                            .context("authenticated OCI layer state is absent")?
                            .retain_layer_receipt(
                                semantic_index,
                                &receipt,
                                nested.layer_stream(),
                            )?;
                    }
                    role => {
                        let inspected =
                            archive.inspect_payload(parsed.payload_bytes, None, capture)?;
                        ensure!(
                            inspected.sha256 == digest,
                            "OCI outer-ustar blob payload digest differs from its member name"
                        );
                        if let (Some(state), Some(role)) = (graph.state(), role) {
                            let source = inspected.captured.as_deref().unwrap_or(&[]);
                            state.validate_json_payload(role, source)?;
                        }
                    }
                }
                blobs.push(OwnedOciBlobMemberV1 {
                    digest,
                    byte_length: parsed.payload_bytes,
                });
            }
            ParsedOuterMemberNameV1::IndexJson => {
                ensure!(
                    matches!(stage, OuterArchiveStageV1::Blobs),
                    "OCI outer-ustar index.json appears more than once or out of order"
                );
                ensure!(
                    (OCI_OUTER_USTAR_MIN_BLOBS..=OCI_OUTER_USTAR_MAX_BLOBS).contains(&blobs.len()),
                    "OCI outer-ustar index.json appears before the closed blob set"
                );
                ensure!(
                    (OCI_INDEX_JSON_MIN_BYTES..=OCI_INDEX_JSON_MAX_BYTES)
                        .contains(&parsed.payload_bytes),
                    "OCI outer-ustar index.json length is outside its closed range"
                );
                if let Some(state) = graph.state() {
                    ensure!(
                        parsed.payload_bytes == state.expected_index_json_byte_length,
                        "OCI outer-ustar index.json length differs from its profile-derived document"
                    );
                }
                let inspected =
                    archive.inspect_payload(parsed.payload_bytes, None, graph.state().is_some())?;
                if let Some(state) = graph.state() {
                    json::validate_index_json_source(
                        inspected
                            .captured
                            .as_deref()
                            .context("captured OCI index.json payload is absent")?,
                        state.expectation,
                    )?;
                }
                index_json_byte_length = Some(parsed.payload_bytes);
                index_json_sha256 = Some(inspected.sha256);
                stage = OuterArchiveStageV1::IndexSeen;
            }
            ParsedOuterMemberNameV1::OciLayout => {
                ensure!(
                    matches!(stage, OuterArchiveStageV1::IndexSeen),
                    "OCI outer-ustar oci-layout does not immediately follow index.json"
                );
                ensure!(
                    parsed.payload_bytes == u64::try_from(OCI_LAYOUT_BYTES.len())?,
                    "OCI outer-ustar oci-layout length is not exact"
                );
                archive.inspect_payload(parsed.payload_bytes, Some(OCI_LAYOUT_BYTES), false)?;
                stage = OuterArchiveStageV1::LayoutSeen;
            }
        }
    }
}

fn parse_outer_ustar_header(
    header: &[u8; USTAR_BLOCK_BYTES],
    limits: super::artifact_import_contract::OciArtifactImportLimitsV1,
) -> Result<ParsedOuterHeaderV1> {
    let declared_checksum = parse_checksum_field(&header[148..156])?;
    let observed_checksum = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum::<u64>();
    ensure!(
        declared_checksum == observed_checksum,
        "OCI outer-ustar header checksum is invalid"
    );

    ensure!(
        header[100..108] == *b"0000644\0",
        "OCI outer-ustar mode is not canonical 0644"
    );
    ensure!(
        header[108..116] == *b"0000000\0",
        "OCI outer-ustar uid is not canonical zero"
    );
    ensure!(
        header[116..124] == *b"0000000\0",
        "OCI outer-ustar gid is not canonical zero"
    );
    let payload_bytes = parse_exact_octal_field(&header[124..136], 11, "size")?;
    limits.validate_outer_ustar_member_payload_bytes(payload_bytes, "OCI outer-ustar member")?;
    ensure!(
        header[136..148] == *b"00000000000\0",
        "OCI outer-ustar mtime is not canonical zero"
    );
    ensure!(
        header[156] == b'0',
        "OCI outer-ustar member is not a regular file"
    );
    ensure!(
        header[157..257].iter().all(|byte| *byte == 0),
        "OCI outer-ustar linkname is not empty"
    );
    ensure!(
        header[257..263] == *b"ustar\0",
        "OCI outer-ustar magic is not exact"
    );
    ensure!(
        header[263..265] == *b"00",
        "OCI outer-ustar version is not exact"
    );
    ensure!(
        header[265..297].iter().all(|byte| *byte == 0),
        "OCI outer-ustar uname is not empty"
    );
    ensure!(
        header[297..329].iter().all(|byte| *byte == 0),
        "OCI outer-ustar gname is not empty"
    );
    ensure!(
        header[329..337] == *b"0000000\0",
        "OCI outer-ustar device-major is not canonical zero"
    );
    ensure!(
        header[337..345] == *b"0000000\0",
        "OCI outer-ustar device-minor is not canonical zero"
    );
    ensure!(
        header[345..500].iter().all(|byte| *byte == 0),
        "OCI outer-ustar prefix is not empty"
    );
    ensure!(
        header[500..512].iter().all(|byte| *byte == 0),
        "OCI outer-ustar unused header bytes are not zero"
    );

    let name_end = header[..100]
        .iter()
        .position(|byte| *byte == 0)
        .context("OCI outer-ustar name is not NUL-terminated")?;
    ensure!(name_end > 0, "OCI outer-ustar member name is empty");
    ensure!(
        header[name_end..100].iter().all(|byte| *byte == 0),
        "OCI outer-ustar unused name bytes are not zero"
    );
    let name_bytes = &header[..name_end];
    ensure!(
        name_bytes.is_ascii(),
        "OCI outer-ustar member name is not ASCII"
    );
    let name = std::str::from_utf8(name_bytes)
        .context("OCI outer-ustar member name is not UTF-8")?
        .to_owned();
    let member = parse_outer_member_name(&name)?;
    Ok(ParsedOuterHeaderV1 {
        name,
        member,
        payload_bytes,
    })
}

fn parse_outer_member_name(name: &str) -> Result<ParsedOuterMemberNameV1> {
    if name == "index.json" {
        return Ok(ParsedOuterMemberNameV1::IndexJson);
    }
    if name == "oci-layout" {
        return Ok(ParsedOuterMemberNameV1::OciLayout);
    }
    let encoded = name
        .strip_prefix("blobs/sha256/")
        .context("OCI outer-ustar member name is outside the closed inventory")?;
    ensure!(
        encoded.len() == 64
            && encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "OCI outer-ustar blob name is not a lowercase SHA-256 digest"
    );
    let mut digest = [0_u8; 32];
    hex::decode_to_slice(encoded, &mut digest)
        .context("cannot decode OCI outer-ustar blob-name digest")?;
    Ok(ParsedOuterMemberNameV1::Blob(digest))
}

fn parse_checksum_field(field: &[u8]) -> Result<u64> {
    ensure!(
        field.len() == 8 && field[6] == 0 && field[7] == b' ',
        "OCI outer-ustar checksum field is not canonically terminated"
    );
    parse_octal_digits(&field[..6], "checksum")
}

fn parse_exact_octal_field(field: &[u8], digits: usize, label: &str) -> Result<u64> {
    ensure!(
        field.len() == digits + 1 && field[digits] == 0,
        "OCI outer-ustar {label} field is not canonically NUL-terminated"
    );
    parse_octal_digits(&field[..digits], label)
}

fn parse_octal_digits(digits: &[u8], label: &str) -> Result<u64> {
    let mut value = 0_u64;
    for digit in digits {
        ensure!(
            (b'0'..=b'7').contains(digit),
            "OCI outer-ustar {label} field is not canonical octal"
        );
        value = value
            .checked_mul(8)
            .and_then(|current| current.checked_add(u64::from(*digit - b'0')))
            .with_context(|| format!("OCI outer-ustar {label} field overflowed"))?;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        fs,
        io::Cursor,
        path::Path,
        sync::{Arc, Mutex},
    };

    #[cfg(target_os = "linux")]
    use std::{cell::RefCell, path::PathBuf, rc::Rc};

    use serde_json::json;
    use sha2::{Digest as _, Sha256};

    use eip_0045_reproduction::canonical::canonical_json_bytes;

    use super::{
        B4ImmutableArtifactRoleV1, OCI_INDEX_JSON_MAX_BYTES, OCI_LAYOUT_BYTES,
        OCI_OUTER_USTAR_MAX_BLOBS, OCI_OUTER_USTAR_MAX_MEMBER_BYTES, USTAR_BLOCK_BYTES,
        inspect_authenticated_oci_outer_ustar, inspect_structural_oci_outer_ustar,
        parse_exact_octal_field, parse_outer_ustar_header,
    };

    #[cfg(target_os = "linux")]
    use super::{
        OciOuterUstarImportStageV1, OciOuterUstarSlotV1,
        import_authenticated_oci_outer_ustar_slots, rootfs,
        with_imported_oci_outer_ustar_test_hook, with_replayed_oci_outer_ustar,
    };

    #[cfg(target_os = "linux")]
    use crate::b4_campaign_executor::{
        capability::CustodyPostcheckCombinedFailureV1,
        custody::{AuthenticatedStreamCombinedFailureV1, AuthenticatedStreamFailurePairV1},
        preflight::{
            ProjectedPrepareInputSetCampaignLayout, project_prepare_input_set_campaign_layout,
            project_prepare_input_set_oci_capture_test_only,
        },
        typestate::ExecutorPreflightContext,
    };

    struct FixtureMember {
        name: String,
        header_offset: usize,
        payload_offset: usize,
        payload_length: usize,
    }

    struct ArchiveFixture {
        bytes: Vec<u8>,
        members: Vec<FixtureMember>,
    }

    #[derive(Debug, Eq, PartialEq)]
    enum FakePhysicalInventoryEventV1 {
        Retained(usize),
        RetainFailed(usize),
        AcquisitionCleanupRetried(usize),
        AcquisitionCleanupRetryFailed(usize),
        AcquisitionCleanupRetrySucceeded(usize),
        Cleaned(usize),
        CleanupFailed(usize),
        CleanupRetried(usize),
        CleanupRetryFailed(usize),
        CleanupRetrySucceeded(usize),
        Discarded(usize),
    }

    struct FakePhysicalInventoryExpectationV1 {
        role: eip_0045_reproduction::b4_positive_gate::PositiveRunnerRole,
    }

    #[derive(Clone, Copy)]
    enum FakePhysicalInventoryToggleV1 {
        Disabled,
        Enabled,
    }

    impl FakePhysicalInventoryToggleV1 {
        const fn when(condition: bool) -> Self {
            if condition {
                Self::Enabled
            } else {
                Self::Disabled
            }
        }

        const fn is_enabled(self) -> bool {
            matches!(self, Self::Enabled)
        }
    }

    struct FakePhysicalInventorySlotV1 {
        index: usize,
        role: eip_0045_reproduction::b4_positive_gate::PositiveRunnerRole,
        postcheck_role_drift: FakePhysicalInventoryToggleV1,
        role_reads: Cell<u8>,
        retain_failure: FakePhysicalInventoryToggleV1,
        acquisition_retry_failures_remaining: u8,
        cleanup_failure: FakePhysicalInventoryToggleV1,
        retry_failures_remaining: u8,
        discard_failure: FakePhysicalInventoryToggleV1,
        events: Arc<Mutex<Vec<FakePhysicalInventoryEventV1>>>,
    }

    #[derive(Debug)]
    struct FakeRetainedPhysicalInventorySlotV1 {
        index: usize,
        fail_cleanup: bool,
        retry_failures_remaining: u8,
        events: Arc<Mutex<Vec<FakePhysicalInventoryEventV1>>>,
    }

    #[derive(Debug)]
    struct FakePhysicalInventoryPrimaryErrorV1;

    impl std::fmt::Display for FakePhysicalInventoryPrimaryErrorV1 {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("fake physical inventory primary failure")
        }
    }

    impl std::error::Error for FakePhysicalInventoryPrimaryErrorV1 {}

    #[derive(Debug)]
    struct FakePhysicalInventoryAcquisitionErrorV1 {
        index: usize,
        retry_failures_remaining: u8,
        primary: anyhow::Error,
        events: Arc<Mutex<Vec<FakePhysicalInventoryEventV1>>>,
    }

    impl std::fmt::Display for FakePhysicalInventoryAcquisitionErrorV1 {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "fake current-slot acquisition cleanup failure for slot {}: {}",
                self.index, self.primary
            )
        }
    }

    impl std::error::Error for FakePhysicalInventoryAcquisitionErrorV1 {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(self.primary.as_ref())
        }
    }

    impl super::physical_rootfs_inventory_acquisition_failure_seal::Sealed
        for FakePhysicalInventoryAcquisitionErrorV1
    {
    }

    impl super::RetryablePhysicalRootfsInventoryAcquisitionFailureV1
        for FakePhysicalInventoryAcquisitionErrorV1
    {
        fn retry_cleanup(mut self) -> std::result::Result<anyhow::Error, Self> {
            self.events.lock().unwrap().push(
                FakePhysicalInventoryEventV1::AcquisitionCleanupRetried(self.index),
            );
            if self.retry_failures_remaining > 0 {
                self.retry_failures_remaining -= 1;
                self.events.lock().unwrap().push(
                    FakePhysicalInventoryEventV1::AcquisitionCleanupRetryFailed(self.index),
                );
                Err(self)
            } else {
                self.events.lock().unwrap().push(
                    FakePhysicalInventoryEventV1::AcquisitionCleanupRetrySucceeded(self.index),
                );
                Ok(self.primary)
            }
        }
    }

    #[derive(Debug)]
    struct FakePhysicalInventoryCleanupErrorV1 {
        index: usize,
        retry_failures_remaining: u8,
        events: Arc<Mutex<Vec<FakePhysicalInventoryEventV1>>>,
    }

    impl std::fmt::Display for FakePhysicalInventoryCleanupErrorV1 {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "fake retained physical inventory cleanup failure for slot {}",
                self.index
            )
        }
    }

    impl std::error::Error for FakePhysicalInventoryCleanupErrorV1 {}

    impl super::physical_rootfs_inventory_cleanup_failure_seal::Sealed
        for FakePhysicalInventoryCleanupErrorV1
    {
    }

    impl super::RetryablePhysicalRootfsInventoryCleanupFailureV1
        for FakePhysicalInventoryCleanupErrorV1
    {
        type Abandonment = usize;

        fn retry_cleanup(mut self) -> std::result::Result<Self::Abandonment, Self> {
            self.events
                .lock()
                .unwrap()
                .push(FakePhysicalInventoryEventV1::CleanupRetried(self.index));
            if self.retry_failures_remaining > 0 {
                self.retry_failures_remaining -= 1;
                self.events
                    .lock()
                    .unwrap()
                    .push(FakePhysicalInventoryEventV1::CleanupRetryFailed(self.index));
                Err(self)
            } else {
                self.events.lock().unwrap().push(
                    FakePhysicalInventoryEventV1::CleanupRetrySucceeded(self.index),
                );
                Ok(self.index)
            }
        }
    }

    impl super::physical_rootfs_inventory_slot_seal::Sealed for FakePhysicalInventorySlotV1 {}

    impl super::retained_physical_rootfs_inventory_slot_seal::Sealed
        for FakeRetainedPhysicalInventorySlotV1
    {
    }

    impl super::RetainedPhysicalRootfsInventorySlotV1 for FakeRetainedPhysicalInventorySlotV1 {
        type Abandonment = usize;
        type CleanupFailure = FakePhysicalInventoryCleanupErrorV1;

        fn cleanup(self) -> std::result::Result<Self::Abandonment, Self::CleanupFailure> {
            if self.fail_cleanup {
                self.events
                    .lock()
                    .unwrap()
                    .push(FakePhysicalInventoryEventV1::CleanupFailed(self.index));
                return Err(FakePhysicalInventoryCleanupErrorV1 {
                    index: self.index,
                    retry_failures_remaining: self.retry_failures_remaining,
                    events: self.events,
                });
            }
            self.events
                .lock()
                .unwrap()
                .push(FakePhysicalInventoryEventV1::Cleaned(self.index));
            Ok(self.index)
        }
    }

    impl super::PhysicalRootfsInventorySlotV1 for FakePhysicalInventorySlotV1 {
        type Expectation = FakePhysicalInventoryExpectationV1;
        type Retained = FakeRetainedPhysicalInventorySlotV1;
        type AcquisitionFailure = FakePhysicalInventoryAcquisitionErrorV1;

        fn role(&self) -> eip_0045_reproduction::b4_positive_gate::PositiveRunnerRole {
            let previous_reads = self.role_reads.get();
            self.role_reads.set(previous_reads + 1);
            if self.postcheck_role_drift.is_enabled() && previous_reads > 0 {
                super::canonical_positive_runner_roles()
                    [(self.index + 1) % super::AUTHENTICATED_OCI_INVENTORY_SIZE]
            } else {
                self.role
            }
        }

        fn expectation_role(
            expectation: &Self::Expectation,
        ) -> eip_0045_reproduction::b4_positive_gate::PositiveRunnerRole {
            expectation.role
        }

        fn authenticate_and_retain(
            self,
            _expectation: &Self::Expectation,
        ) -> std::result::Result<Self::Retained, Self::AcquisitionFailure> {
            if self.retain_failure.is_enabled() {
                self.events
                    .lock()
                    .unwrap()
                    .push(FakePhysicalInventoryEventV1::RetainFailed(self.index));
                return Err(FakePhysicalInventoryAcquisitionErrorV1 {
                    index: self.index,
                    retry_failures_remaining: self.acquisition_retry_failures_remaining,
                    primary: FakePhysicalInventoryPrimaryErrorV1.into(),
                    events: self.events,
                });
            }
            self.events
                .lock()
                .unwrap()
                .push(FakePhysicalInventoryEventV1::Retained(self.index));
            Ok(FakeRetainedPhysicalInventorySlotV1 {
                index: self.index,
                fail_cleanup: self.cleanup_failure.is_enabled(),
                retry_failures_remaining: self.retry_failures_remaining,
                events: self.events,
            })
        }

        fn discard_after_error(self, primary: anyhow::Error) -> anyhow::Error {
            self.events
                .lock()
                .unwrap()
                .push(FakePhysicalInventoryEventV1::Discarded(self.index));
            if self.discard_failure.is_enabled() {
                primary.context(format!(
                    "fake secondary discard failure for slot {}",
                    self.index
                ))
            } else {
                primary
            }
        }
    }

    impl ArchiveFixture {
        fn member(&self, name: &str) -> &FixtureMember {
            self.members
                .iter()
                .find(|member| member.name == name)
                .unwrap()
        }
    }

    fn canonical_octal<const WIDTH: usize>(value: u64) -> [u8; WIDTH] {
        let digits = format!("{value:0width$o}", width = WIDTH - 1);
        assert_eq!(digits.len(), WIDTH - 1);
        let mut field = [0_u8; WIDTH];
        field[..WIDTH - 1].copy_from_slice(digits.as_bytes());
        field
    }

    fn refresh_checksum(header: &mut [u8]) {
        header[148..156].fill(b' ');
        let checksum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
        let checksum_digits = format!("{checksum:06o}");
        assert_eq!(checksum_digits.len(), 6);
        header[148..154].copy_from_slice(checksum_digits.as_bytes());
        header[154] = 0;
        header[155] = b' ';
    }

    fn canonical_header(name: &str, payload_bytes: u64) -> [u8; USTAR_BLOCK_BYTES] {
        assert!(name.len() < 100);
        let mut header = [0_u8; USTAR_BLOCK_BYTES];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(&canonical_octal::<12>(payload_bytes));
        header[136..148].copy_from_slice(b"00000000000\0");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        header[329..337].copy_from_slice(b"0000000\0");
        header[337..345].copy_from_slice(b"0000000\0");
        refresh_checksum(&mut header);
        header
    }

    fn canonical_member(name: &str, payload: &[u8]) -> Vec<u8> {
        let header = canonical_header(name, payload.len() as u64);
        let mut member = header.to_vec();
        member.extend_from_slice(payload);
        let padding = (USTAR_BLOCK_BYTES - payload.len() % USTAR_BLOCK_BYTES) % USTAR_BLOCK_BYTES;
        member.resize(member.len() + padding, 0);
        member
    }

    fn blob_member(payload: Vec<u8>) -> (String, Vec<u8>) {
        let digest: [u8; 32] = Sha256::digest(&payload).into();
        (format!("blobs/sha256/{}", hex::encode(digest)), payload)
    }

    fn oci_digest(digest: [u8; 32]) -> String {
        format!("sha256:{}", hex::encode(digest))
    }

    fn blob_identity(payload: &[u8]) -> super::json::OciBlobIdentityV1 {
        super::json::OciBlobIdentityV1::test_only(
            Sha256::digest(payload).into(),
            u64::try_from(payload.len()).unwrap(),
        )
    }

    struct TestLayerMaterial {
        payload: Vec<u8>,
        uncompressed_byte_length: u64,
        diff_id: [u8; 32],
    }

    struct PreparedTestLayerMaterial {
        payload: Vec<u8>,
        digest: [u8; 32],
        byte_length: u64,
        uncompressed_byte_length: u64,
        diff_id: [u8; 32],
    }

    #[derive(Clone, Copy)]
    enum TestJsonRouteMutationV1 {
        None,
        IndexArchitecture,
        ManifestMediaType,
        ConfigArchitecture,
    }

    fn graph_material(
        layers: Vec<TestLayerMaterial>,
    ) -> (Vec<(String, Vec<u8>)>, super::json::OciImageExpectationV1) {
        graph_material_with_json_mutation(layers, TestJsonRouteMutationV1::None)
    }

    fn graph_material_with_json_mutation(
        layers: Vec<TestLayerMaterial>,
        mutation: TestJsonRouteMutationV1,
    ) -> (Vec<(String, Vec<u8>)>, super::json::OciImageExpectationV1) {
        let prepared = layers
            .into_iter()
            .map(|layer| PreparedTestLayerMaterial {
                digest: Sha256::digest(&layer.payload).into(),
                byte_length: u64::try_from(layer.payload.len()).unwrap(),
                payload: layer.payload,
                uncompressed_byte_length: layer.uncompressed_byte_length,
                diff_id: layer.diff_id,
            })
            .collect::<Vec<_>>();
        let mut config = json!({
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {
                "diff_ids": prepared
                    .iter()
                    .map(|layer| oci_digest(layer.diff_id))
                    .collect::<Vec<_>>(),
                "type": "layers"
            }
        });
        if matches!(mutation, TestJsonRouteMutationV1::ConfigArchitecture) {
            config["architecture"] = json!("arm64");
        }
        let config_payload = canonical_json_bytes(&config).unwrap();
        let config_identity = blob_identity(&config_payload);
        let mut manifest = json!({
            "config": {
                "digest": oci_digest(config_identity.digest()),
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "size": config_identity.byte_length()
            },
            "layers": prepared
                .iter()
                .map(|layer| json!({
                    "digest": oci_digest(layer.digest),
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "size": layer.byte_length
                }))
                .collect::<Vec<_>>(),
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "schemaVersion": 2
        });
        if matches!(mutation, TestJsonRouteMutationV1::ManifestMediaType) {
            manifest["mediaType"] = json!("application/vnd.oci.image.index.v1+json");
        }
        let manifest_payload = canonical_json_bytes(&manifest).unwrap();
        let manifest_identity = blob_identity(&manifest_payload);
        let mut index = json!({
            "manifests": [{
                "digest": oci_digest(manifest_identity.digest()),
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "platform": {"architecture": "amd64", "os": "linux"},
                "size": manifest_identity.byte_length()
            }],
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "schemaVersion": 2
        });
        if matches!(mutation, TestJsonRouteMutationV1::IndexArchitecture) {
            index["manifests"][0]["platform"]["architecture"] = json!("arm64");
        }
        let index_payload = canonical_json_bytes(&index).unwrap();
        let expected_layers = prepared
            .iter()
            .map(|layer| {
                super::json::OciExpectedLayerV1::test_only(
                    super::json::OciBlobIdentityV1::test_only(layer.digest, layer.byte_length),
                    layer.uncompressed_byte_length,
                    layer.diff_id,
                )
            })
            .collect::<Vec<_>>();
        let expectation = super::json::OciImageExpectationV1::test_only(
            manifest_identity,
            config_identity,
            expected_layers,
        );
        let mut blobs = vec![blob_member(config_payload), blob_member(manifest_payload)];
        blobs.extend(prepared.into_iter().map(|layer| blob_member(layer.payload)));
        blobs.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        blobs.extend([
            ("index.json".to_owned(), index_payload),
            ("oci-layout".to_owned(), OCI_LAYOUT_BYTES.to_vec()),
        ]);
        (blobs, expectation)
    }

    fn minimal_graph_material() -> (Vec<(String, Vec<u8>)>, super::json::OciImageExpectationV1) {
        let (members, image) = graph_material(minimal_test_layers());
        let expected_rootfs = super::json::OciExpectedRootfsV1::test_only(1, 1, 0, 0, 28);
        (
            members,
            image.test_only_with_post_changeset_rootfs(expected_rootfs),
        )
    }

    fn canonical_test_layer(path: &str, payload: &[u8], executable: bool) -> TestLayerMaterial {
        let (payload, expectation) =
            super::layer::test_only_canonical_one_regular_file_layer(path, payload, executable)
                .unwrap();
        TestLayerMaterial {
            payload,
            uncompressed_byte_length: expectation.uncompressed_byte_length(),
            diff_id: expectation.diff_id(),
        }
    }

    fn minimal_test_layers() -> Vec<TestLayerMaterial> {
        vec![canonical_test_layer(
            "validator",
            b"minimal authenticated layer\n",
            true,
        )]
    }

    fn reverse_physical_digest_order_layers() -> Vec<TestLayerMaterial> {
        let mut layers = vec![
            canonical_test_layer("alpha", b"semantic layer alpha", false),
            canonical_test_layer("beta", b"semantic layer beta", true),
        ];
        layers.sort_by(|left, right| {
            let left_digest: [u8; 32] = Sha256::digest(&left.payload).into();
            let right_digest: [u8; 32] = Sha256::digest(&right.payload).into();
            right_digest.cmp(&left_digest)
        });
        let semantic_digests = layers
            .iter()
            .map(|layer| <[u8; 32]>::from(Sha256::digest(&layer.payload)))
            .collect::<Vec<_>>();
        assert!(semantic_digests[0] > semantic_digests[1]);
        layers
    }

    fn minimal_members() -> Vec<(String, Vec<u8>)> {
        graph_material(vec![TestLayerMaterial {
            payload: b"01234567890123456789".to_vec(),
            uncompressed_byte_length: 1_024,
            diff_id: Sha256::digest(b"structural-only-uncompressed-layer").into(),
        }])
        .0
    }

    fn build_archive(members: Vec<(String, Vec<u8>)>) -> ArchiveFixture {
        let mut bytes = Vec::new();
        let mut retained = Vec::new();
        for (name, payload) in members {
            let header_offset = bytes.len();
            let payload_offset = header_offset + USTAR_BLOCK_BYTES;
            let payload_length = payload.len();
            bytes.extend_from_slice(&canonical_member(&name, &payload));
            retained.push(FixtureMember {
                name,
                header_offset,
                payload_offset,
                payload_length,
            });
        }
        bytes.resize(bytes.len() + 2 * USTAR_BLOCK_BYTES, 0);
        ArchiveFixture {
            bytes,
            members: retained,
        }
    }

    fn minimal_canonical_archive() -> ArchiveFixture {
        build_archive(minimal_members())
    }

    fn minimal_authenticated_archive() -> ArchiveFixture {
        build_archive(minimal_graph_material().0)
    }

    fn minimal_outer_expectation(bytes: &[u8]) -> super::OciOuterUstarExpectationV1 {
        outer_expectation(bytes, minimal_graph_material().1)
    }

    fn outer_expectation(
        bytes: &[u8],
        image: super::json::OciImageExpectationV1,
    ) -> super::OciOuterUstarExpectationV1 {
        super::OciOuterUstarExpectationV1::test_only(
            u64::try_from(bytes.len()).unwrap(),
            Sha256::digest(bytes).into(),
            image,
        )
    }

    #[cfg(target_os = "linux")]
    type TestContext = ExecutorPreflightContext<1, ProjectedPrepareInputSetCampaignLayout<1>>;

    #[cfg(target_os = "linux")]
    fn captured_context(
        files: &[(&str, &[u8])],
        oci_paths: &[&str],
    ) -> (tempfile::TempDir, PathBuf, TestContext) {
        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let prior = campaign.join("authoritative-inputs");
        let output = campaign.join("phases/prepare-001");
        fs::create_dir_all(&prior).unwrap();
        fs::create_dir_all(output.parent().unwrap()).unwrap();
        for (relative, bytes) in files {
            let path = prior.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, bytes).unwrap();
        }
        let layout =
            project_prepare_input_set_campaign_layout(&campaign, [&prior], &output).unwrap();
        let slots = oci_paths
            .iter()
            .map(|relative| (0_usize, *relative))
            .collect::<Vec<_>>();
        let projected = project_prepare_input_set_oci_capture_test_only(layout, &slots).unwrap();
        let executable = fs::read_link("/proc/self/exe").unwrap();
        let context =
            ExecutorPreflightContext::capture_with_projected_oci(&executable, projected).unwrap();
        (temp, prior, context)
    }

    #[cfg(target_os = "linux")]
    struct NominalSubstitutionGuard {
        nominal: PathBuf,
        displaced: PathBuf,
        active: bool,
    }

    #[cfg(target_os = "linux")]
    impl NominalSubstitutionGuard {
        fn substitute(nominal: &Path, replacement: &[u8]) -> anyhow::Result<Self> {
            let displaced = nominal.with_extension("oci-displaced");
            fs::rename(nominal, &displaced)?;
            if let Err(error) = fs::write(nominal, replacement) {
                let _ = fs::rename(&displaced, nominal);
                return Err(error.into());
            }
            Ok(Self {
                nominal: nominal.to_path_buf(),
                displaced,
                active: true,
            })
        }

        fn restore(&mut self) -> anyhow::Result<()> {
            if self.active {
                fs::remove_file(&self.nominal)?;
                fs::rename(&self.displaced, &self.nominal)?;
                self.active = false;
            }
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for NominalSubstitutionGuard {
        fn drop(&mut self) {
            let _ = self.restore();
        }
    }

    #[cfg(target_os = "linux")]
    fn stream_failure_with_pair(
        error: &anyhow::Error,
        expected: AuthenticatedStreamFailurePairV1,
    ) -> &AuthenticatedStreamCombinedFailureV1 {
        fn find(
            error: &anyhow::Error,
            expected: AuthenticatedStreamFailurePairV1,
            depth: usize,
        ) -> Option<&AuthenticatedStreamCombinedFailureV1> {
            if depth > 12 {
                return None;
            }
            for cause in error.chain() {
                if let Some(stream) = cause.downcast_ref::<AuthenticatedStreamCombinedFailureV1>() {
                    if stream.pair() == expected {
                        return Some(stream);
                    }
                    if let Some(found) = find(stream.earlier(), expected, depth + 1) {
                        return Some(found);
                    }
                    if let Some(found) = find(stream.later(), expected, depth + 1) {
                        return Some(found);
                    }
                }
                if let Some(custody) = cause.downcast_ref::<CustodyPostcheckCombinedFailureV1>() {
                    if let Some(found) = find(custody.effect(), expected, depth + 1) {
                        return Some(found);
                    }
                    if let Some(found) = find(custody.postcheck(), expected, depth + 1) {
                        return Some(found);
                    }
                }
            }
            None
        }

        find(error, expected, 0)
            .expect("authenticated OCI stream failure pair is absent from the typed error tree")
    }

    fn inspect(bytes: &[u8]) -> anyhow::Result<super::OwnedOciOuterUstarInspectionV1> {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let mut reader = Cursor::new(bytes);
        inspect_structural_oci_outer_ustar(bytes.len() as u64, digest, &mut reader)
    }

    fn inspect_expected(
        bytes: &[u8],
        expectation: &super::OciOuterUstarExpectationV1,
    ) -> anyhow::Result<super::OwnedOciOuterUstarInspectionV1> {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let mut reader = Cursor::new(bytes);
        inspect_authenticated_oci_outer_ustar(
            expectation,
            u64::try_from(bytes.len()).unwrap(),
            digest,
            &mut reader,
        )
    }

    fn replay_expected(
        bytes: &[u8],
        expectation: &super::OciOuterUstarExpectationV1,
    ) -> anyhow::Result<super::OwnedOciOuterUstarInspectionV1> {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let mut reader = Cursor::new(bytes);
        super::replay_authenticated_oci_outer_ustar(
            expectation,
            u64::try_from(bytes.len()).unwrap(),
            digest,
            &mut reader,
        )
    }

    fn inspect_minimal_graph(
        bytes: &[u8],
    ) -> anyhow::Result<super::OwnedOciOuterUstarInspectionV1> {
        inspect_expected(bytes, &minimal_outer_expectation(bytes))
    }

    fn inspect_declared(
        bytes: &[u8],
        declared_length: u64,
    ) -> anyhow::Result<super::OwnedOciOuterUstarInspectionV1> {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let mut reader = Cursor::new(bytes);
        inspect_structural_oci_outer_ustar(declared_length, digest, &mut reader)
    }

    fn error_message(bytes: &[u8]) -> String {
        format!("{:#}", inspect(bytes).unwrap_err())
    }

    fn replace_name(fixture: &mut ArchiveFixture, member_index: usize, replacement: &[u8]) {
        let offset = fixture.members[member_index].header_offset;
        let header = &mut fixture.bytes[offset..offset + USTAR_BLOCK_BYTES];
        header[..100].fill(0);
        header[..replacement.len()].copy_from_slice(replacement);
        refresh_checksum(header);
    }

    fn collect_rust_sources_without_links(directory: &Path, sources: &mut Vec<std::path::PathBuf>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert!(
                !metadata.file_type().is_symlink(),
                "source authority scan refuses link {}",
                path.display()
            );
            if metadata.is_dir() {
                collect_rust_sources_without_links(&path, sources);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                sources.push(path);
            }
        }
    }

    fn rust_identifier_count(source: &str, identifier: &str) -> usize {
        fn continues_identifier(byte: u8) -> bool {
            byte.is_ascii_alphanumeric() || byte == b'_' || byte >= 0x80
        }

        source
            .match_indices(identifier)
            .filter(|(offset, _)| {
                let bytes = source.as_bytes();
                let start = *offset;
                let end = start + identifier.len();
                (start == 0 || !continues_identifier(bytes[start - 1]))
                    && (end == bytes.len() || !continues_identifier(bytes[end]))
            })
            .count()
    }

    fn production_before_test_module(source: &str) -> &str {
        let normalized_test_start = source
            .match_indices("#[cfg(test)]")
            .filter_map(|(index, _)| {
                source[index + "#[cfg(test)]".len()..]
                    .trim_start()
                    .starts_with("mod tests")
                    .then_some(index)
            })
            .last()
            .unwrap_or(source.len());
        &source[..normalized_test_start]
    }

    fn declared_fn_names(source: &str) -> Vec<&str> {
        source
            .match_indices("fn ")
            .map(|(offset, _)| {
                let tail = &source[offset + 3..];
                let end = tail.find(['(', '<']).unwrap();
                &tail[..end]
            })
            .collect()
    }

    #[test]
    fn outer_inspection_layer_evidence_is_explicit_for_structural_and_authenticated_routes() {
        let structural_fixture = minimal_canonical_archive();
        let structural = inspect(&structural_fixture.bytes).unwrap();
        let structural_debug = format!("{structural:?}");
        assert!(
            structural_debug.contains("layers: []"),
            "{structural_debug}"
        );
        assert!(
            structural_debug.contains("observed_layer_uncompressed_bytes: 0"),
            "{structural_debug}"
        );
        assert!(
            structural_debug.contains("observed_layer_tar_entries: 0"),
            "{structural_debug}"
        );

        let authenticated_fixture = minimal_authenticated_archive();
        let authenticated = inspect_minimal_graph(&authenticated_fixture.bytes).unwrap();
        let authenticated_debug = format!("{authenticated:?}");
        assert!(
            authenticated_debug.contains("layers: [ImportedOciLayerObservationV1"),
            "{authenticated_debug}"
        );
        assert!(!authenticated_debug.contains("layers: Some"));
    }

    #[test]
    fn production_layer_evidence_has_no_optional_or_default_masking() {
        let source = include_str!("oci_image_layout_import.rs").replace("\r\n", "\n");
        let production = source.split("\n#[cfg(test)]\nmod tests").next().unwrap();
        let inspection_fields = production
            .split("struct OwnedOciOuterUstarInspectionV1 {")
            .nth(1)
            .unwrap()
            .split("\n}")
            .next()
            .unwrap();
        assert!(
            !inspection_fields.contains("layers: Option"),
            "{inspection_fields}"
        );
        assert!(
            !inspection_fields.contains("observed_layer_uncompressed_bytes: Option"),
            "{inspection_fields}"
        );
        assert!(
            !inspection_fields.contains("observed_layer_tar_entries: Option"),
            "{inspection_fields}"
        );
        let view_impl = production
            .split("impl ImportedOciOuterUstarViewV1<'_> {")
            .nth(1)
            .unwrap()
            .split("\n}")
            .next()
            .unwrap();
        assert!(!view_impl.contains("unwrap_or"), "{view_impl}");
        assert!(!production.contains("Result<Option<CompletedOciLayerSetV1>>"));
    }

    #[test]
    fn canonical_minimal_outer_ustar_is_accepted() {
        let fixture = minimal_authenticated_archive();
        assert_eq!(fixture.bytes.len() % USTAR_BLOCK_BYTES, 0);
        let inspection = inspect_minimal_graph(&fixture.bytes).unwrap();
        let expected_archive_sha256: [u8; 32] = Sha256::digest(&fixture.bytes).into();
        let index = fixture.member("index.json");
        let expected_index_sha256: [u8; 32] = Sha256::digest(
            &fixture.bytes[index.payload_offset..index.payload_offset + index.payload_length],
        )
        .into();
        assert_eq!(inspection.archive_byte_length, fixture.bytes.len() as u64);
        assert_eq!(inspection.archive_sha256, expected_archive_sha256);
        assert_eq!(inspection.blobs.len(), 3);
        assert_eq!(
            inspection.index_json_byte_length,
            u64::try_from(index.payload_length).unwrap()
        );
        assert_eq!(inspection.index_json_sha256, expected_index_sha256);
        assert_eq!(inspection.validated_layer_count, Some(1));
        let layers = &inspection.layers;
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].semantic_index, 0);
        assert_eq!(layers[0].entry_count, 1);
        assert_eq!(inspection.observed_layer_tar_entries, 1);
        assert_eq!(
            inspection.observed_layer_uncompressed_bytes,
            layers[0].uncompressed_byte_length
        );
        assert_eq!(
            inspection
                .blobs
                .iter()
                .map(|blob| blob.byte_length)
                .sum::<u64>(),
            fixture
                .members
                .iter()
                .filter(|member| member.name.starts_with("blobs/sha256/"))
                .map(|member| u64::try_from(member.payload_length).unwrap())
                .sum::<u64>()
        );
        assert!(
            inspection
                .blobs
                .iter()
                .all(|blob| blob.digest != [0_u8; 32])
        );
    }

    #[test]
    fn authenticated_reachable_layer_rejects_structurally_invalid_gzip_ustar() {
        let structurally_invalid_layer = TestLayerMaterial {
            payload: b"01234567890123456789".to_vec(),
            uncompressed_byte_length: 1_024,
            diff_id: Sha256::digest(b"coherent-but-invalid-uncompressed-layer").into(),
        };
        let (members, image) = graph_material(vec![structurally_invalid_layer]);
        let fixture = build_archive(members);
        let expectation = outer_expectation(&fixture.bytes, image);

        let error = inspect_expected(&fixture.bytes, &expectation).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("gzip"), "{message}");
        assert!(!message.contains("DiffID"), "{message}");
    }

    #[test]
    fn authenticated_layer_outer_padding_is_validated_after_exact_stream_consumption() {
        let (members, image) = minimal_graph_material();
        let layer_name = format!(
            "blobs/sha256/{}",
            hex::encode(image.layers()[0].compressed().digest())
        );
        let mut fixture = build_archive(members);
        let member = fixture.member(&layer_name);
        let padding_offset = member.payload_offset + member.payload_length;
        assert_ne!(member.payload_length % USTAR_BLOCK_BYTES, 0);
        fixture.bytes[padding_offset] = 1;
        let expectation = outer_expectation(&fixture.bytes, image);

        let error = inspect_expected(&fixture.bytes, &expectation).unwrap_err();
        assert!(format!("{error:#}").contains("member padding is not zero"));
    }

    #[test]
    fn authenticated_layer_rejects_a_mismatching_semantic_diff_id() {
        let mut layer = canonical_test_layer("artifact", b"future DiffID boundary", false);
        let declared_diff_id = [0xa5; 32];
        assert_ne!(layer.diff_id, declared_diff_id);
        layer.diff_id = declared_diff_id;
        let (members, image) = graph_material(vec![layer]);
        let fixture = build_archive(members);
        let expectation = outer_expectation(&fixture.bytes, image);

        let error = inspect_expected(&fixture.bytes, &expectation).unwrap_err();
        assert_eq!(
            error.to_string(),
            "OCI layer semantic index 0 observed DiffID differs from its authenticated profile tuple"
        );
    }

    #[test]
    fn mismatching_diff_id_does_not_mutate_semantic_layer_state() {
        let mut layer = canonical_test_layer("artifact", b"atomic DiffID boundary", false);
        let payload = layer.payload.clone();
        layer.diff_id = [0xa6; 32];
        let (_members, image) = graph_material(vec![layer]);
        let expected = &image.layers()[0];
        let mut reader = Cursor::new(payload);
        let receipt = super::layer::inspect_authenticated_oci_layer(&mut reader, expected).unwrap();
        let limits = B4ImmutableArtifactRoleV1::OciImageLayoutUstar
            .limits()
            .require_oci("OCI DiffID atomicity test")
            .unwrap()
            .layer_stream();
        let mut state = super::OciGraphStreamStateV1::new(&image).unwrap();

        let error = state.retain_layer_receipt(0, &receipt, limits).unwrap_err();
        assert_eq!(
            error.to_string(),
            "OCI layer semantic index 0 observed DiffID differs from its authenticated profile tuple"
        );
        assert_eq!(state.observed_layer_count, 0);
        assert_eq!(state.observed_layer_uncompressed_bytes, 0);
        assert_eq!(state.observed_layer_tar_entries, 0);
        assert!(state.layers[0].is_none());
    }

    #[test]
    fn each_semantic_layer_diff_id_is_checked_independently() {
        for semantic_index in 0..2 {
            let mut layers = reverse_physical_digest_order_layers();
            let mismatching_diff_id = [0xb0 + u8::try_from(semantic_index).unwrap(); 32];
            assert!(
                layers
                    .iter()
                    .all(|layer| layer.diff_id != mismatching_diff_id)
            );
            layers[semantic_index].diff_id = mismatching_diff_id;
            let (members, image) = graph_material(layers);
            let fixture = build_archive(members);
            let expectation = outer_expectation(&fixture.bytes, image);

            let error = inspect_expected(&fixture.bytes, &expectation).unwrap_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "OCI layer semantic index {semantic_index} observed DiffID differs from its authenticated profile tuple"
                )
            );
        }
    }

    #[test]
    fn same_length_recompressed_layer_cannot_reuse_a_prior_diff_id() {
        let prior = canonical_test_layer("artifact", b"prior payload A", false);
        let mut replacement = canonical_test_layer("artifact", b"other payload B", false);
        assert_eq!(prior.payload.len(), replacement.payload.len());
        assert_ne!(
            Sha256::digest(&prior.payload),
            Sha256::digest(&replacement.payload)
        );
        assert_ne!(prior.diff_id, replacement.diff_id);
        replacement.diff_id = prior.diff_id;
        let (members, image) = graph_material(vec![replacement]);
        let fixture = build_archive(members);
        let expectation = outer_expectation(&fixture.bytes, image);

        let error = inspect_expected(&fixture.bytes, &expectation).unwrap_err();
        assert_eq!(
            error.to_string(),
            "OCI layer semantic index 0 observed DiffID differs from its authenticated profile tuple"
        );
    }

    #[test]
    fn matching_layer_receipt_is_retained_once_and_replay_is_atomic() {
        let layer = canonical_test_layer("artifact", b"one semantic receipt", false);
        let payload = layer.payload.clone();
        let (_members, image) = graph_material(vec![layer]);
        let expected = &image.layers()[0];
        let mut reader = Cursor::new(payload);
        let receipt = super::layer::inspect_authenticated_oci_layer(&mut reader, expected).unwrap();
        let limits = B4ImmutableArtifactRoleV1::OciImageLayoutUstar
            .limits()
            .require_oci("OCI DiffID replay test")
            .unwrap()
            .layer_stream();
        let mut state = super::OciGraphStreamStateV1::new(&image).unwrap();

        state.retain_layer_receipt(0, &receipt, limits).unwrap();
        let retained = (
            state.observed_layer_count,
            state.observed_layer_uncompressed_bytes,
            state.observed_layer_tar_entries,
        );
        let error = state.retain_layer_receipt(0, &receipt, limits).unwrap_err();
        assert_eq!(
            error.to_string(),
            "OCI layer receipt was retained more than once"
        );
        assert_eq!(
            (
                state.observed_layer_count,
                state.observed_layer_uncompressed_bytes,
                state.observed_layer_tar_entries,
            ),
            retained
        );
        assert!(state.layers[0].is_some());
    }

    #[test]
    fn parent_rejects_multi_layer_tar_entry_aggregate_at_the_closed_budget() {
        let layer = canonical_test_layer("artifact", b"one bounded entry", false);
        let (payload, image) = {
            let payload = layer.payload.clone();
            let (_members, image) = graph_material(vec![layer]);
            (payload, image)
        };
        let expected = &image.layers()[0];
        let mut reader = Cursor::new(&payload);
        let receipt = super::layer::inspect_authenticated_oci_layer(&mut reader, expected).unwrap();
        assert_eq!(receipt.entry_count(), 1);

        let limits = B4ImmutableArtifactRoleV1::OciImageLayoutUstar
            .limits()
            .require_oci("OCI parent aggregate test")
            .unwrap()
            .layer_stream();
        let mut state = super::OciGraphStreamStateV1::new(&image).unwrap();
        state.observed_layer_tar_entries = limits.maximum_tar_entries();
        let error = state.retain_layer_receipt(0, &receipt, limits).unwrap_err();
        assert_eq!(
            error.to_string(),
            "authenticated OCI layer set exceeds its role-specific layer-tar entry budget"
        );
    }

    #[test]
    fn two_layer_semantic_order_is_independent_from_physical_digest_order() {
        let layers = reverse_physical_digest_order_layers();
        let semantic_digests = layers
            .iter()
            .map(|layer| <[u8; 32]>::from(Sha256::digest(&layer.payload)))
            .collect::<Vec<_>>();
        assert!(semantic_digests[0] > semantic_digests[1]);

        let (members, image) = graph_material(layers);
        let fixture = build_archive(members);
        let expected_diff_ids = image
            .layers()
            .iter()
            .map(super::json::OciExpectedLayerV1::diff_id)
            .collect::<Vec<_>>();
        let first_name = format!("blobs/sha256/{}", hex::encode(semantic_digests[0]));
        let second_name = format!("blobs/sha256/{}", hex::encode(semantic_digests[1]));
        let first_physical = fixture
            .members
            .iter()
            .position(|member| member.name == first_name)
            .unwrap();
        let second_physical = fixture
            .members
            .iter()
            .position(|member| member.name == second_name)
            .unwrap();
        assert!(second_physical < first_physical);

        let expectation = outer_expectation(&fixture.bytes, image);
        let inspection = inspect_expected(&fixture.bytes, &expectation).unwrap();
        assert_eq!(inspection.validated_layer_count, Some(2));
        assert_eq!(inspection.blobs.len(), 4);
        let observed = &inspection.layers;
        assert_eq!(
            observed
                .iter()
                .map(|layer| layer.semantic_index)
                .collect::<Vec<_>>(),
            [0, 1]
        );
        assert_eq!(
            observed
                .iter()
                .map(|layer| layer.compressed_sha256)
                .collect::<Vec<_>>(),
            semantic_digests
        );

        let replay = replay_expected(&fixture.bytes, &expectation).unwrap();
        let post_changeset_rootfs = expectation.image.post_changeset_rootfs();
        let inspected_receipt =
            super::ImportedOciOuterUstarReceiptV1::from_view(&super::ImportedOciOuterUstarViewV1 {
                role: super::PositiveRunnerRole::RustValidatorBuild,
                post_changeset_rootfs,
                inspection: &inspection,
            });
        inspected_receipt
            .replay_matches_inspection(&super::ImportedOciOuterUstarViewV1 {
                role: super::PositiveRunnerRole::RustValidatorBuild,
                post_changeset_rootfs,
                inspection: &replay,
            })
            .unwrap();
        assert_eq!(
            observed
                .iter()
                .map(|layer| layer.observed_uncompressed_sha256)
                .collect::<Vec<_>>(),
            expected_diff_ids
        );
        assert_eq!(inspection.observed_layer_tar_entries, 2);
        assert_eq!(
            inspection.observed_layer_uncompressed_bytes,
            observed
                .iter()
                .map(|layer| layer.uncompressed_byte_length)
                .sum::<u64>()
        );
        assert!(observed.iter().all(|layer| {
            layer.entry_count == 1
                && layer.regular_file_count == 1
                && layer.directory_count == 0
                && layer.symbolic_link_count == 0
                && layer.whiteout_count == 0
                && layer.regular_file_bytes != 0
                && layer.observed_uncompressed_sha256 != [0_u8; 32]
        }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn two_layer_reverse_physical_order_reaches_authenticated_rootfs_sink() {
        let layers = reverse_physical_digest_order_layers();
        let semantic_digests = layers
            .iter()
            .map(|layer| <[u8; 32]>::from(Sha256::digest(&layer.payload)))
            .collect::<Vec<_>>();
        let (members, image) = graph_material(layers);
        let image = image.test_only_with_post_changeset_rootfs(
            super::json::OciExpectedRootfsV1::test_only(2, 2, 0, 0, 39),
        );
        let fixture = build_archive(members);
        let first_name = format!("blobs/sha256/{}", hex::encode(semantic_digests[0]));
        let second_name = format!("blobs/sha256/{}", hex::encode(semantic_digests[1]));
        let first_physical = fixture
            .members
            .iter()
            .position(|member| member.name == first_name)
            .unwrap();
        let second_physical = fixture
            .members
            .iter()
            .position(|member| member.name == second_name)
            .unwrap();
        assert!(second_physical < first_physical);

        let expectation = outer_expectation(&fixture.bytes, image);
        let (_temp, prior, context) =
            captured_context(&[("layout.oci.tar", &fixture.bytes)], &["layout.oci.tar"]);
        let output = prior.parent().unwrap().join("phases/prepare-001");
        let slot = OciOuterUstarSlotV1::test_only(0, "layout.oci.tar", expectation);

        context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_replayed_oci_outer_ustar(capability, slot, |view, receipt| {
                        assert_eq!(
                            view.layers()
                                .iter()
                                .map(|layer| layer.semantic_index)
                                .collect::<Vec<_>>(),
                            [0, 1]
                        );
                        assert_eq!(
                            view.layers()
                                .iter()
                                .map(|layer| layer.compressed_sha256)
                                .collect::<Vec<_>>(),
                            semantic_digests
                        );
                        assert_eq!(view.post_changeset_entry_count(), 2);
                        assert_eq!(view.post_changeset_regular_file_count(), 2);
                        assert_eq!(view.post_changeset_directory_count(), 0);
                        assert_eq!(view.post_changeset_symbolic_link_count(), 0);
                        assert_eq!(view.post_changeset_regular_file_bytes(), 39);
                        assert_eq!(receipt.layers.len(), 2);
                        let retained: &rootfs::AuthenticatedPrivateOciRootfsProjectionV1 =
                            &receipt.rootfs;
                        let (hard_link_count, counters, identity) =
                            retained.test_only_retained_evidence()?;
                        assert_eq!(hard_link_count, 0);
                        assert_eq!(counters, [2, 2, 0, 0, 39]);
                        assert_ne!(identity, [0_u8; 32]);
                        Ok(())
                    })
                })
            })
            .unwrap();
        assert!(!output.exists());
    }

    #[test]
    fn replay_comparison_rejects_a_transcript_only_drift() {
        let fixture = minimal_authenticated_archive();
        let expectation = minimal_outer_expectation(&fixture.bytes);
        let inspection = inspect_expected(&fixture.bytes, &expectation).unwrap();
        let mut replay = replay_expected(&fixture.bytes, &expectation).unwrap();
        replay.layers[0].changeset_transcript_sha256[0] ^= 1;
        let post_changeset_rootfs = expectation.image.post_changeset_rootfs();
        let inspected_receipt =
            super::ImportedOciOuterUstarReceiptV1::from_view(&super::ImportedOciOuterUstarViewV1 {
                role: super::PositiveRunnerRole::RustValidatorBuild,
                post_changeset_rootfs,
                inspection: &inspection,
            });

        let error = inspected_receipt
            .replay_matches_inspection(&super::ImportedOciOuterUstarViewV1 {
                role: super::PositiveRunnerRole::RustValidatorBuild,
                post_changeset_rootfs,
                inspection: &replay,
            })
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "OCI replay layer changeset transcript differs from inspection"
        );
    }

    #[test]
    fn archive_with_unreachable_blobs_is_rejected_by_the_closed_oci_graph() {
        let (mut members, image) = minimal_graph_material();
        let expected_layer_name = format!(
            "blobs/sha256/{}",
            hex::encode(image.layers()[0].compressed().digest())
        );
        let layer = members
            .iter()
            .position(|(name, _payload)| name == &expected_layer_name)
            .unwrap();
        // This opaque replacement is rejected by graph identity before its
        // bytes can reach the authenticated layer parser.
        let mut unreachable_payload = members[layer].1.clone();
        unreachable_payload[0] ^= 0x01;
        members[layer] = blob_member(unreachable_payload);
        let blob_count = members.len() - 2;
        members[..blob_count].sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        let fixture = build_archive(members);
        let expectation = outer_expectation(&fixture.bytes, image);

        let error = inspect_expected(&fixture.bytes, &expectation).unwrap_err();
        assert!(
            format!("{error:#}").contains("outside the expected reachable graph"),
            "{error:#}"
        );
    }

    #[test]
    fn missing_reachable_blob_is_rejected_at_graph_completion() {
        let layers = vec![
            canonical_test_layer("alpha", b"present layer", false),
            canonical_test_layer("beta", b"missing layer", false),
        ];
        let missing_name = format!(
            "blobs/sha256/{}",
            hex::encode(Sha256::digest(&layers[1].payload))
        );
        let (mut members, image) = graph_material(layers);
        let full_archive_length = build_archive(members.clone()).bytes.len();
        let missing = members
            .iter()
            .position(|(name, _payload)| name == &missing_name)
            .unwrap();
        members.remove(missing);
        let mut fixture = build_archive(members);
        fixture.bytes.resize(full_archive_length, 0);
        let expectation = outer_expectation(&fixture.bytes, image);

        let error = inspect_expected(&fixture.bytes, &expectation).unwrap_err();
        assert!(
            format!("{error:#}").contains("missing a blob from the expected reachable graph"),
            "{error:#}"
        );
    }

    #[test]
    fn archive_routes_each_selected_json_document_through_semantic_binding() {
        for (mutation, expected) in [
            (TestJsonRouteMutationV1::IndexArchitecture, "architecture"),
            (TestJsonRouteMutationV1::ManifestMediaType, "mediaType"),
            (TestJsonRouteMutationV1::ConfigArchitecture, "architecture"),
        ] {
            let (members, image) =
                graph_material_with_json_mutation(minimal_test_layers(), mutation);
            let fixture = build_archive(members);
            let expectation = outer_expectation(&fixture.bytes, image);

            let error = inspect_expected(&fixture.bytes, &expectation).unwrap_err();
            assert!(
                format!("{error:#}").contains(expected),
                "{expected}: {error:#}"
            );
        }
    }

    struct CountingReader<'bytes> {
        bytes: &'bytes [u8],
        reads: Cell<usize>,
    }

    impl std::io::Read for CountingReader<'_> {
        fn read(&mut self, destination: &mut [u8]) -> std::io::Result<usize> {
            self.reads.set(self.reads.get() + 1);
            let count = destination.len().min(self.bytes.len());
            destination[..count].copy_from_slice(&self.bytes[..count]);
            self.bytes = &self.bytes[count..];
            Ok(count)
        }
    }

    struct RequestBoundedReader<'bytes> {
        bytes: &'bytes [u8],
        reads: Cell<usize>,
        maximum_request: Cell<usize>,
    }

    impl std::io::Read for RequestBoundedReader<'_> {
        fn read(&mut self, destination: &mut [u8]) -> std::io::Result<usize> {
            self.reads.set(self.reads.get() + 1);
            self.maximum_request
                .set(self.maximum_request.get().max(destination.len()));
            let count = destination.len().min(self.bytes.len());
            destination[..count].copy_from_slice(&self.bytes[..count]);
            self.bytes = &self.bytes[count..];
            Ok(count)
        }
    }

    #[test]
    fn profile_archive_identity_and_footprint_reject_before_first_read() {
        let fixture = minimal_authenticated_archive();
        let byte_length = u64::try_from(fixture.bytes.len()).unwrap();
        let archive_sha256: [u8; 32] = Sha256::digest(&fixture.bytes).into();

        let expectation = minimal_outer_expectation(&fixture.bytes);
        let mut reader = CountingReader {
            bytes: &fixture.bytes,
            reads: Cell::new(0),
        };
        let error = inspect_authenticated_oci_outer_ustar(
            &expectation,
            byte_length,
            [0_u8; 32],
            &mut reader,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("expected profile identity"));
        assert_eq!(reader.reads.get(), 0);

        let expectation = minimal_outer_expectation(&fixture.bytes);
        let mut reader = CountingReader {
            bytes: &fixture.bytes,
            reads: Cell::new(0),
        };
        let error = inspect_authenticated_oci_outer_ustar(
            &expectation,
            byte_length + USTAR_BLOCK_BYTES as u64,
            archive_sha256,
            &mut reader,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("expected profile identity"));
        assert_eq!(reader.reads.get(), 0);

        let wrong_footprint = super::OciOuterUstarExpectationV1::test_only(
            byte_length + USTAR_BLOCK_BYTES as u64,
            archive_sha256,
            minimal_graph_material().1,
        );
        let mut reader = CountingReader {
            bytes: &fixture.bytes,
            reads: Cell::new(0),
        };
        let error = inspect_authenticated_oci_outer_ustar(
            &wrong_footprint,
            byte_length + USTAR_BLOCK_BYTES as u64,
            archive_sha256,
            &mut reader,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("exact closed-ustar footprint"));
        assert_eq!(reader.reads.get(), 0);
    }

    #[test]
    fn large_layer_payload_is_consumed_through_the_fixed_streaming_buffer() {
        let payload = vec![0x5a; 1_048_577];
        let layer = canonical_test_layer("artifact", &payload, false);
        let (members, image) = graph_material(vec![layer]);
        let fixture = build_archive(members);
        let expectation = outer_expectation(&fixture.bytes, image);
        let digest: [u8; 32] = Sha256::digest(&fixture.bytes).into();
        let mut reader = RequestBoundedReader {
            bytes: &fixture.bytes,
            reads: Cell::new(0),
            maximum_request: Cell::new(0),
        };

        let inspection = inspect_authenticated_oci_outer_ustar(
            &expectation,
            u64::try_from(fixture.bytes.len()).unwrap(),
            digest,
            &mut reader,
        )
        .unwrap();
        assert_eq!(inspection.validated_layer_count, Some(1));
        let layer = &inspection.layers[0];
        assert_eq!(layer.semantic_index, 0);
        assert_eq!(layer.regular_file_bytes, payload.len() as u64);
        assert!(layer.compressed_byte_length > 1_048_576);
        assert!(reader.reads.get() > 64);
        assert_eq!(reader.maximum_request.get(), super::MEMBER_IO_BUFFER_BYTES);
    }

    #[test]
    fn invalid_archive_lengths_reject_before_any_read() {
        for rejected in [6_143_u64, 6_145, 17_179_869_184 + 512] {
            let reads = Cell::new(0);
            let mut reader = CountingReader { bytes: &[], reads };
            let error =
                inspect_structural_oci_outer_ustar(rejected, [0_u8; 32], &mut reader).unwrap_err();
            assert!(format!("{error:#}").contains("encoded byte length"));
            assert_eq!(reader.reads.get(), 0);
        }
    }

    #[test]
    fn member_size_field_has_exact_octal_boundary() {
        assert_eq!(
            parse_exact_octal_field(b"77777777777\0", 11, "size").unwrap(),
            OCI_OUTER_USTAR_MAX_MEMBER_BYTES
        );
        for rejected in [
            b"100000000000".as_slice(),
            b"77777777777 ".as_slice(),
            b"00000000008\0".as_slice(),
            b"\x80\0\0\0\0\0\0\0\0\0\0\0".as_slice(),
        ] {
            assert!(parse_exact_octal_field(rejected, 11, "size").is_err());
        }

        let limits = B4ImmutableArtifactRoleV1::OciImageLayoutUstar
            .limits()
            .require_oci("OCI image-layout ustar")
            .unwrap();
        let member_name = blob_member(b"header-boundary".to_vec()).0;
        let maximum = canonical_header(&member_name, OCI_OUTER_USTAR_MAX_MEMBER_BYTES);
        assert_eq!(
            parse_outer_ustar_header(&maximum, limits)
                .unwrap()
                .payload_bytes,
            OCI_OUTER_USTAR_MAX_MEMBER_BYTES
        );

        let mut over_maximum = maximum;
        over_maximum[124..136].copy_from_slice(b"100000000000");
        refresh_checksum(&mut over_maximum);
        let message = format!(
            "{:#}",
            parse_outer_ustar_header(&over_maximum, limits)
                .err()
                .unwrap()
        );
        assert!(message.contains("size field"), "{message}");
    }

    #[test]
    fn every_fixed_header_field_is_isolated() {
        let cases: &[(usize, &[u8], &str)] = &[
            (100, b"0000600\0", "mode"),
            (108, b"0000001\0", "uid"),
            (116, b"0000001\0", "gid"),
            (136, b"00000000001\0", "mtime"),
            (156, b"5", "regular file"),
            (157, b"x", "linkname"),
            (257, b"ustar ", "magic"),
            (263, b"01", "version"),
            (265, b"u", "uname"),
            (297, b"g", "gname"),
            (329, b"0000001\0", "device-major"),
            (337, b"0000001\0", "device-minor"),
            (345, b"p", "prefix"),
            (500, b"x", "unused header"),
        ];
        for (offset, replacement, expected) in cases {
            let mut fixture = minimal_canonical_archive();
            let header = &mut fixture.bytes[..USTAR_BLOCK_BYTES];
            header[*offset..*offset + replacement.len()].copy_from_slice(replacement);
            refresh_checksum(header);
            let message = error_message(&fixture.bytes);
            assert!(message.contains(expected), "{expected}: {message}");
        }
    }

    #[test]
    fn checksum_and_name_encodings_are_exact() {
        let mut bad_checksum = minimal_canonical_archive();
        bad_checksum.bytes[148] = b'7';
        assert!(error_message(&bad_checksum.bytes).contains("checksum"));

        let mut reversed_checksum_terminator = minimal_canonical_archive();
        reversed_checksum_terminator.bytes[154] = b' ';
        reversed_checksum_terminator.bytes[155] = 0;
        assert!(
            error_message(&reversed_checksum_terminator.bytes).contains("canonically terminated")
        );

        let mut non_octal_checksum = minimal_canonical_archive();
        non_octal_checksum.bytes[148] = b'8';
        assert!(error_message(&non_octal_checksum.bytes).contains("canonical octal"));

        for replacement in [
            b"/blobs/sha256/00".as_slice(),
            b"./blobs/sha256/00".as_slice(),
            b"extra.json".as_slice(),
            b"blobs/sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                .as_slice(),
            b"blobs/sha256/0".as_slice(),
        ] {
            let mut fixture = minimal_canonical_archive();
            replace_name(&mut fixture, 0, replacement);
            let message = error_message(&fixture.bytes);
            assert!(message.contains("name"), "{message}");
        }

        let mut non_ascii = minimal_canonical_archive();
        replace_name(&mut non_ascii, 0, &[0xff]);
        assert!(error_message(&non_ascii.bytes).contains("not ASCII"));

        let mut nonzero_name_tail = minimal_canonical_archive();
        nonzero_name_tail.bytes[99] = b'x';
        refresh_checksum(&mut nonzero_name_tail.bytes[..USTAR_BLOCK_BYTES]);
        assert!(error_message(&nonzero_name_tail.bytes).contains("unused name"));
    }

    #[test]
    fn member_inventory_and_order_are_closed() {
        let mut swapped = minimal_members();
        swapped.swap(0, 1);
        assert!(error_message(&build_archive(swapped).bytes).contains("strictly increasing"));

        let mut duplicate = minimal_members();
        duplicate[1] = duplicate[0].clone();
        assert!(error_message(&build_archive(duplicate).bytes).contains("strictly increasing"));

        let mut extra = minimal_members();
        extra.insert(3, ("extra.json".to_owned(), b"{}".to_vec()));
        assert!(error_message(&build_archive(extra).bytes).contains("closed inventory"));

        let mut blob_after_index = minimal_members();
        blob_after_index.insert(4, blob_member(b"late-blob".to_vec()));
        let message = error_message(&build_archive(blob_after_index).bytes);
        assert!(message.contains("strictly increasing"), "{message}");
    }

    #[test]
    fn blob_digest_and_oci_layout_payload_are_authenticated() {
        let mut blob = minimal_canonical_archive();
        let payload_offset = blob.members[0].payload_offset;
        blob.bytes[payload_offset] ^= 1;
        assert!(error_message(&blob.bytes).contains("payload digest"));

        let mut layout = minimal_canonical_archive();
        let payload_offset = layout.member("oci-layout").payload_offset;
        layout.bytes[payload_offset] ^= 1;
        assert!(error_message(&layout.bytes).contains("oci-layout payload"));

        let mut wrong_layout_length = minimal_canonical_archive();
        let header_offset = wrong_layout_length.member("oci-layout").header_offset;
        let header =
            &mut wrong_layout_length.bytes[header_offset..header_offset + USTAR_BLOCK_BYTES];
        header[124..136].copy_from_slice(&canonical_octal::<12>(
            u64::try_from(OCI_LAYOUT_BYTES.len()).unwrap() + 1,
        ));
        refresh_checksum(header);
        assert!(error_message(&wrong_layout_length.bytes).contains("length is not exact"));
    }

    #[test]
    fn payload_and_padding_truncation_or_mutation_rejects_causally() {
        let mut padding = minimal_canonical_archive();
        let first = &padding.members[0];
        let padding_offset = first.payload_offset + first.payload_length;
        padding.bytes[padding_offset] = 1;
        assert!(error_message(&padding.bytes).contains("padding is not zero"));

        let mut truncated_payload = minimal_canonical_archive();
        let first = &truncated_payload.members[0];
        truncated_payload
            .bytes
            .truncate(first.payload_offset + first.payload_length - 1);
        let message = format!(
            "{:#}",
            inspect_declared(&truncated_payload.bytes, 6_144).unwrap_err()
        );
        assert!(message.contains("member payload"), "{message}");

        let mut truncated_padding = minimal_canonical_archive();
        let first = &truncated_padding.members[0];
        truncated_padding
            .bytes
            .truncate(first.payload_offset + first.payload_length + 1);
        let message = format!(
            "{:#}",
            inspect_declared(&truncated_padding.bytes, 6_144).unwrap_err()
        );
        assert!(message.contains("member padding"), "{message}");
    }

    #[test]
    fn exact_two_block_terminator_and_immediate_eof_are_required() {
        let canonical = minimal_canonical_archive();

        let mut one_block = canonical.bytes.clone();
        one_block.truncate(one_block.len() - USTAR_BLOCK_BYTES);
        assert!(
            format!("{:#}", inspect_declared(&one_block, 6_144).unwrap_err())
                .contains("second terminator")
        );

        let mut nonzero_second = canonical.bytes.clone();
        let last_block = nonzero_second.len() - USTAR_BLOCK_BYTES;
        nonzero_second[last_block] = 1;
        assert!(error_message(&nonzero_second).contains("second terminator block is not zero"));

        let mut third_block = canonical.bytes.clone();
        third_block.resize(third_block.len() + USTAR_BLOCK_BYTES, 0);
        assert!(error_message(&third_block).contains("bytes after"));

        let mut suffix = canonical.bytes.clone();
        suffix.push(0x45);
        assert!(
            format!("{:#}", inspect_declared(&suffix, 6_144).unwrap_err()).contains("bytes after")
        );

        let mut prefix = vec![0x45; USTAR_BLOCK_BYTES];
        prefix.extend_from_slice(&canonical.bytes);
        assert!(error_message(&prefix).contains("checksum"));
    }

    #[test]
    fn metadata_members_and_blob_count_are_bounded() {
        let mut missing_layout = minimal_canonical_archive();
        let layout_header = missing_layout.member("oci-layout").header_offset;
        missing_layout.bytes[layout_header..layout_header + 2 * USTAR_BLOCK_BYTES].fill(0);
        assert!(error_message(&missing_layout.bytes).contains("terminated before"));

        let mut too_few_members = vec![blob_member(b"a".to_vec()), blob_member(b"b".to_vec())];
        too_few_members.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        too_few_members.extend([
            ("index.json".to_owned(), b"{}".to_vec()),
            ("oci-layout".to_owned(), OCI_LAYOUT_BYTES.to_vec()),
        ]);
        let too_few = build_archive(too_few_members);
        assert!(
            format!("{:#}", inspect_declared(&too_few.bytes, 6_144).unwrap_err())
                .contains("closed blob set")
        );

        let mut blobs = (0..=OCI_OUTER_USTAR_MAX_BLOBS)
            .map(|index| blob_member(format!("blob-{index}").into_bytes()))
            .collect::<Vec<_>>();
        blobs.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        blobs.extend([
            ("index.json".to_owned(), b"{}".to_vec()),
            ("oci-layout".to_owned(), OCI_LAYOUT_BYTES.to_vec()),
        ]);
        assert!(error_message(&build_archive(blobs).bytes).contains("count exceeds"));
    }

    #[test]
    fn index_length_and_archive_digest_are_exact() {
        let mut tiny_index = minimal_members();
        tiny_index[3].1 = b"x".to_vec();
        assert!(error_message(&build_archive(tiny_index).bytes).contains("index.json length"));

        let mut maximal_index = minimal_members();
        maximal_index[3].1 = vec![b' '; usize::try_from(OCI_INDEX_JSON_MAX_BYTES).unwrap()];
        let maximal = build_archive(maximal_index);
        assert_eq!(
            inspect(&maximal.bytes).unwrap().index_json_byte_length,
            OCI_INDEX_JSON_MAX_BYTES
        );

        let mut oversized_index = minimal_members();
        oversized_index[3].1 = vec![b' '; usize::try_from(OCI_INDEX_JSON_MAX_BYTES + 1).unwrap()];
        assert!(error_message(&build_archive(oversized_index).bytes).contains("index.json length"));

        let fixture = minimal_canonical_archive();
        let mut reader = Cursor::new(&fixture.bytes);
        let error = inspect_structural_oci_outer_ustar(6_144, [0_u8; 32], &mut reader).unwrap_err();
        assert!(format!("{error:#}").contains("SHA-256"));

        let error = inspect_declared(&fixture.bytes, 6_144 + USTAR_BLOCK_BYTES as u64).unwrap_err();
        assert!(
            format!("{error:#}").contains("consumed length differs"),
            "{error:#}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn projected_oci_archive_is_replayed_only_through_descriptor_custody() {
        let fixture = minimal_authenticated_archive();
        let expected_sha256: [u8; 32] = Sha256::digest(&fixture.bytes).into();
        let (_temp, prior, context) =
            captured_context(&[("layout.oci.tar", &fixture.bytes)], &["layout.oci.tar"]);
        let output = prior.parent().unwrap().join("phases/prepare-001");
        let slot = OciOuterUstarSlotV1::test_only(
            0,
            "layout.oci.tar",
            minimal_outer_expectation(&fixture.bytes),
        );

        context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_replayed_oci_outer_ustar(capability, slot, |view, _receipt| {
                        assert_eq!(view.archive_byte_length(), fixture.bytes.len() as u64);
                        assert_eq!(view.archive_sha256(), expected_sha256);
                        assert_eq!(view.blob_count(), 3);
                        assert_eq!(
                            view.index_json_byte_length(),
                            u64::try_from(fixture.member("index.json").payload_length).unwrap()
                        );
                        assert_ne!(view.index_json_sha256(), [0_u8; 32]);
                        Ok(())
                    })
                })
            })
            .unwrap();
        assert!(!output.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fixed_four_role_inventory_imports_once_in_order_and_rejects_reorder_before_reads() {
        let fixture = minimal_authenticated_archive();
        let expected_sha256: [u8; 32] = Sha256::digest(&fixture.bytes).into();
        let index_member = fixture.member("index.json");
        let expected_index_json_byte_length = index_member.payload_length as u64;
        let expected_index_json_sha256: [u8; 32] = Sha256::digest(
            &fixture.bytes[index_member.payload_offset
                ..index_member.payload_offset + index_member.payload_length],
        )
        .into();
        let paths = [
            "rust-build.oci.tar",
            "jvm-build.oci.tar",
            "rust-verify.oci.tar",
            "jvm-verify.oci.tar",
        ];
        let files = paths.map(|path| (path, fixture.bytes.as_slice()));
        let roles = super::canonical_positive_runner_roles();
        let make_slots = || {
            std::array::from_fn(|index| {
                OciOuterUstarSlotV1::test_only_for_role(
                    roles[index],
                    0,
                    paths[index],
                    minimal_outer_expectation(&fixture.bytes),
                )
            })
        };

        let (_temp, _prior, context) = captured_context(&files, &paths);
        let receipts = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    import_authenticated_oci_outer_ustar_slots(capability, make_slots())
                })
            })
            .unwrap();
        assert_eq!(receipts.each_ref().map(|receipt| receipt.role), roles);
        for receipt in &receipts {
            assert_eq!(receipt.archive_byte_length, fixture.bytes.len() as u64);
            assert_eq!(receipt.archive_sha256, expected_sha256);
            assert_eq!(receipt.blob_count, 3);
            assert_eq!(
                receipt.index_json_byte_length,
                expected_index_json_byte_length
            );
            assert_eq!(receipt.index_json_sha256, expected_index_json_sha256);
            assert_eq!(receipt.layers.len(), 1);
            assert_eq!(receipt.layers[0].semantic_index, 0);
            assert_eq!(receipt.layers[0].entry_count, 1);
            assert_eq!(receipt.observed_layer_tar_entries, 1);
            assert_eq!(
                receipt.observed_layer_uncompressed_bytes,
                receipt.layers[0].uncompressed_byte_length
            );
            assert_eq!(receipt.post_changeset_rootfs.entry_count(), 1);
            assert_eq!(receipt.post_changeset_rootfs.regular_file_count(), 1);
            assert_eq!(receipt.post_changeset_rootfs.directory_count(), 0);
            assert_eq!(receipt.post_changeset_rootfs.symbolic_link_count(), 0);
            assert_eq!(receipt.post_changeset_rootfs.regular_file_bytes(), 28);
        }

        let (_temp, _prior, context) = captured_context(&files, &paths);
        let mut reordered = make_slots();
        reordered.swap(0, 1);
        let error = match context.execute(|execute| {
            execute.with_mutation(|capability| {
                import_authenticated_oci_outer_ustar_slots(capability, reordered)
            })
        }) {
            Ok(_) => panic!("reordered OCI inventory unexpectedly imported"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("outside canonical runner order"),
            "{error:#}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn later_inventory_slot_failure_explicitly_discards_every_prior_rootfs() {
        let fixture = minimal_authenticated_archive();
        let mut drifted = fixture.bytes.clone();
        let payload = fixture.member("index.json").payload_offset;
        drifted[payload] ^= 0x01;
        let paths = [
            "rust-build.oci.tar",
            "jvm-build.oci.tar",
            "rust-verify.oci.tar",
            "jvm-verify.oci.tar",
        ];
        let files = [
            (paths[0], fixture.bytes.as_slice()),
            (paths[1], drifted.as_slice()),
            (paths[2], fixture.bytes.as_slice()),
            (paths[3], fixture.bytes.as_slice()),
        ];
        let roles = super::canonical_positive_runner_roles();
        let slots = std::array::from_fn(|index| {
            OciOuterUstarSlotV1::test_only_for_role(
                roles[index],
                0,
                paths[index],
                minimal_outer_expectation(&fixture.bytes),
            )
        });
        let (_temp, _prior, context) = captured_context(&files, &paths);
        super::EXPLICIT_REPLAYED_ROOTFS_DISCARDS.with(|count| count.set(0));

        let error = match context.execute(|execute| {
            execute.with_mutation(|capability| {
                import_authenticated_oci_outer_ustar_slots(capability, slots)
            })
        }) {
            Ok(_) => panic!("drifted second OCI inventory slot unexpectedly imported"),
            Err(error) => error,
        };

        assert!(format!("{error:#}").contains("SHA-256"), "{error:#}");
        assert_eq!(
            super::EXPLICIT_REPLAYED_ROOTFS_DISCARDS.with(std::cell::Cell::get),
            1,
            "the first authenticated logical rootfs must be explicitly discarded when slot two fails"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn profile_footprint_mismatch_precedes_call_local_recheck_and_stream_open() {
        let captured = minimal_authenticated_archive();
        // These opaque expected bytes are never opened: the deliberately
        // different exact outer footprint rejects before descriptor custody.
        let (expected_members, expected_image) = graph_material(vec![TestLayerMaterial {
            payload: vec![0x6b; 513],
            uncompressed_byte_length: 1_024,
            diff_id: [0xd4; 32],
        }]);
        let expected = build_archive(expected_members);
        assert_ne!(captured.bytes.len(), expected.bytes.len());
        let slot = OciOuterUstarSlotV1::test_only(
            0,
            "layout.oci.tar",
            outer_expectation(&expected.bytes, expected_image),
        );
        let (_temp, prior, context) =
            captured_context(&[("layout.oci.tar", &captured.bytes)], &["layout.oci.tar"]);
        let mut changed_after_capture = captured.bytes.clone();
        changed_after_capture[0] ^= 0x01;
        let archive_path = prior.join("layout.oci.tar");
        let observed_stages = Cell::new(0_usize);
        let delivered = Cell::new(false);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    fs::write(&archive_path, &changed_after_capture)?;
                    let outcome = with_imported_oci_outer_ustar_test_hook(
                        capability,
                        slot,
                        |_stage| {
                            observed_stages.set(observed_stages.get() + 1);
                            Ok(())
                        },
                        |_view| {
                            delivered.set(true);
                            Ok(())
                        },
                    );
                    fs::write(&archive_path, &captured.bytes)?;
                    outcome
                })
            })
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("retained length differs from the profile footprint"),
            "{error:#}"
        );
        assert_eq!(observed_stages.get(), 0);
        assert!(!delivered.get());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn oci_import_rejects_wrong_role_path_and_root_before_delivery() {
        let fixture = minimal_authenticated_archive();
        let (_temp, _prior, context) = captured_context(
            &[
                ("selected.oci.tar", &fixture.bytes),
                ("generic.oci.tar", &fixture.bytes),
            ],
            &["selected.oci.tar"],
        );
        let delivered = Cell::new(false);

        context
            .execute(|execute| {
                for (slot, expected) in [
                    (
                        OciOuterUstarSlotV1::test_only(
                            0,
                            "generic.oci.tar",
                            minimal_outer_expectation(&fixture.bytes),
                        ),
                        "role differs",
                    ),
                    (
                        OciOuterUstarSlotV1::test_only(
                            0,
                            "selected.oci.tar.bak",
                            minimal_outer_expectation(&fixture.bytes),
                        ),
                        "absent from the retained snapshot",
                    ),
                    (
                        OciOuterUstarSlotV1::test_only(
                            1,
                            "selected.oci.tar",
                            minimal_outer_expectation(&fixture.bytes),
                        ),
                        "outside the fixed root set",
                    ),
                ] {
                    let error = execute
                        .with_mutation(|capability| {
                            with_replayed_oci_outer_ustar(capability, slot, |_view, _receipt| {
                                delivered.set(true);
                                Ok(())
                            })
                        })
                        .unwrap_err();
                    let message = format!("{error:#}");
                    assert!(message.contains(expected), "{expected}: {message}");
                }
                Ok(())
            })
            .unwrap();
        assert!(!delivered.get());
    }

    #[cfg(target_os = "linux")]
    fn assert_nominal_substitution_rejects(stage: OciOuterUstarImportStageV1) {
        let fixture = minimal_authenticated_archive();
        let (_temp, prior, context) =
            captured_context(&[("layout.oci.tar", &fixture.bytes)], &["layout.oci.tar"]);
        let nominal = prior.join("layout.oci.tar");
        let delivered = Cell::new(false);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    let substitution = RefCell::new(None);
                    with_imported_oci_outer_ustar_test_hook(
                        capability,
                        OciOuterUstarSlotV1::test_only(
                            0,
                            "layout.oci.tar",
                            minimal_outer_expectation(&fixture.bytes),
                        ),
                        move |observed| {
                            if observed == stage {
                                substitution.replace(Some(NominalSubstitutionGuard::substitute(
                                    &nominal,
                                    &fixture.bytes,
                                )?));
                            }
                            Ok(())
                        },
                        |_view| {
                            delivered.set(true);
                            Ok(())
                        },
                    )
                })
            })
            .unwrap_err();

        let message = format!("{error:#}");
        assert!(
            message.contains("retained identity")
                || message.contains("retained snapshot")
                || message.contains("retained custody")
                || message.contains("changed while opening its data descriptor")
                || message.contains("pre-delivery postcheck failed"),
            "{message}"
        );
        assert!(!delivered.get());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn oci_import_rejects_nominal_substitution_after_path_pin() {
        assert_nominal_substitution_rejects(OciOuterUstarImportStageV1::PathPinned);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn oci_import_rejects_nominal_substitution_after_data_open() {
        assert_nominal_substitution_rejects(OciOuterUstarImportStageV1::DataOpened);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn oci_import_rejects_nominal_substitution_after_read_and_file_repin() {
        for stage in [
            OciOuterUstarImportStageV1::BytesRead,
            OciOuterUstarImportStageV1::FileRepinned,
        ] {
            assert_nominal_substitution_rejects(stage);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn oci_import_preserves_typed_read_failure_for_same_inode_length_changes() {
        for (replacement, expected) in [
            {
                let fixture = minimal_authenticated_archive();
                let mut grown = fixture.bytes;
                grown.push(0x45);
                (grown, "grew beyond its retained length")
            },
            {
                let fixture = minimal_authenticated_archive();
                let mut truncated = fixture.bytes;
                truncated.pop();
                (truncated, "ended before its retained length")
            },
        ] {
            let fixture = minimal_authenticated_archive();
            let (_temp, prior, context) =
                captured_context(&[("layout.oci.tar", &fixture.bytes)], &["layout.oci.tar"]);
            let nominal = prior.join("layout.oci.tar");
            let hook_nominal = nominal.clone();
            let delivered = Cell::new(false);

            let error = context
                .execute(|execute| {
                    execute.with_mutation(|capability| {
                        with_imported_oci_outer_ustar_test_hook(
                            capability,
                            OciOuterUstarSlotV1::test_only(
                                0,
                                "layout.oci.tar",
                                minimal_outer_expectation(&fixture.bytes),
                            ),
                            move |stage| {
                                if stage == OciOuterUstarImportStageV1::DataOpened {
                                    fs::write(&hook_nominal, &replacement)?;
                                }
                                Ok(())
                            },
                            |_view| {
                                delivered.set(true);
                                Ok(())
                            },
                        )
                    })
                })
                .unwrap_err();
            fs::write(&nominal, &fixture.bytes).unwrap();

            let combined = stream_failure_with_pair(
                &error,
                AuthenticatedStreamFailurePairV1::InspectionAndRead,
            );
            assert!(
                format!("{:#}", combined.later()).contains(expected),
                "{:#}",
                combined.later()
            );
            assert!(!delivered.get());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn oci_parser_and_file_postcheck_failures_are_both_typed() {
        let invalid = vec![0x45_u8; minimal_authenticated_archive().bytes.len()];
        let (_temp, prior, context) =
            captured_context(&[("invalid.oci.tar", &invalid)], &["invalid.oci.tar"]);
        let nominal = prior.join("invalid.oci.tar");
        let delivered = Cell::new(false);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    let substitution = RefCell::new(None);
                    with_imported_oci_outer_ustar_test_hook(
                        capability,
                        OciOuterUstarSlotV1::test_only(
                            0,
                            "invalid.oci.tar",
                            minimal_outer_expectation(&invalid),
                        ),
                        move |stage| {
                            if stage == OciOuterUstarImportStageV1::DataOpened {
                                substitution.replace(Some(NominalSubstitutionGuard::substitute(
                                    &nominal, &invalid,
                                )?));
                            }
                            Ok(())
                        },
                        |_view| {
                            delivered.set(true);
                            Ok(())
                        },
                    )
                })
            })
            .unwrap_err();

        let combined = stream_failure_with_pair(
            &error,
            AuthenticatedStreamFailurePairV1::InspectionAndFilePostcheck,
        );
        assert!(format!("{:#}", combined.earlier()).contains("checksum"));
        assert!(!format!("{:#}", combined.later()).is_empty());
        assert!(!delivered.get());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn oci_delivery_result_is_rejected_when_a_companion_changes() {
        let fixture = minimal_authenticated_archive();
        let companion = b"retained companion";
        let (_temp, prior, context) = captured_context(
            &[
                ("layout.oci.tar", &fixture.bytes),
                ("companion.bin", companion),
            ],
            &["layout.oci.tar"],
        );
        let companion_path = prior.join("companion.bin");
        let substitution = Rc::new(RefCell::new(None));
        let effect_substitution = Rc::clone(&substitution);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_replayed_oci_outer_ustar(
                        capability,
                        OciOuterUstarSlotV1::test_only(
                            0,
                            "layout.oci.tar",
                            minimal_outer_expectation(&fixture.bytes),
                        ),
                        |_view, _receipt| {
                            *effect_substitution.borrow_mut() = Some(
                                NominalSubstitutionGuard::substitute(&companion_path, companion)?,
                            );
                            Ok(())
                        },
                    )
                })
            })
            .unwrap_err();
        substitution.borrow_mut().take().unwrap().restore().unwrap();

        assert!(
            format!("{error:#}").contains("delivery completed but its postcheck failed"),
            "{error:#}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn oci_companion_change_after_file_repin_rejects_before_delivery() {
        let fixture = minimal_authenticated_archive();
        let companion = b"retained companion";
        let (_temp, prior, context) = captured_context(
            &[
                ("layout.oci.tar", &fixture.bytes),
                ("companion.bin", companion),
            ],
            &["layout.oci.tar"],
        );
        let companion_path = prior.join("companion.bin");
        let substitution = Rc::new(RefCell::new(None));
        let hook_substitution = Rc::clone(&substitution);
        let delivered = Cell::new(false);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_imported_oci_outer_ustar_test_hook(
                        capability,
                        OciOuterUstarSlotV1::test_only(
                            0,
                            "layout.oci.tar",
                            minimal_outer_expectation(&fixture.bytes),
                        ),
                        move |stage| {
                            if stage == OciOuterUstarImportStageV1::FileRepinned {
                                *hook_substitution.borrow_mut() =
                                    Some(NominalSubstitutionGuard::substitute(
                                        &companion_path,
                                        companion,
                                    )?);
                            }
                            Ok(())
                        },
                        |_view| {
                            delivered.set(true);
                            Ok(())
                        },
                    )
                })
            })
            .unwrap_err();
        substitution.borrow_mut().take().unwrap().restore().unwrap();

        assert!(
            format!("{error:#}").contains("pre-delivery postcheck failed"),
            "{error:#}"
        );
        assert!(!delivered.get());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn oci_delivery_and_root_failures_are_both_typed() {
        let fixture = minimal_authenticated_archive();
        let companion = b"retained companion";
        let (_temp, prior, context) = captured_context(
            &[
                ("layout.oci.tar", &fixture.bytes),
                ("companion.bin", companion),
            ],
            &["layout.oci.tar"],
        );
        let companion_path = prior.join("companion.bin");
        let substitution = Rc::new(RefCell::new(None));
        let effect_substitution = Rc::clone(&substitution);

        let error = context
            .execute(|execute| {
                execute.with_mutation(|capability| {
                    with_replayed_oci_outer_ustar(
                        capability,
                        OciOuterUstarSlotV1::test_only(
                            0,
                            "layout.oci.tar",
                            minimal_outer_expectation(&fixture.bytes),
                        ),
                        |_view, _receipt| -> anyhow::Result<()> {
                            *effect_substitution.borrow_mut() = Some(
                                NominalSubstitutionGuard::substitute(&companion_path, companion)?,
                            );
                            anyhow::bail!("injected OCI delivery failure")
                        },
                    )
                })
            })
            .unwrap_err();
        substitution.borrow_mut().take().unwrap().restore().unwrap();

        let combined = stream_failure_with_pair(
            &error,
            AuthenticatedStreamFailurePairV1::DeliveryAndPostcheck,
        );
        assert!(format!("{:#}", combined.earlier()).contains("injected OCI delivery failure"));
        assert!(!format!("{:#}", combined.later()).is_empty());
    }

    #[test]
    fn oci_import_types_are_non_cloneable_non_copyable_and_signature_affine() {
        trait AmbiguousIfClone<Marker> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfClone<()> for T {}
        impl<T: Clone> AmbiguousIfClone<u8> for T {}

        trait AmbiguousIfCopy<Marker> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfCopy<()> for T {}
        impl<T: Copy> AmbiguousIfCopy<u8> for T {}

        type ExactSlotProjectionSignature = fn(
            crate::b4_campaign_executor::preflight::AuthenticatedOciSlotConstructionPermitV1,
        )
            -> anyhow::Result<super::OciOuterUstarSlotV1>;
        type ExactReplaySignature = for<'borrow, 'context> fn(
            &'borrow mut super::MutationCapability<
                'context,
                1,
                super::ProjectedPrepareInputSetCampaignLayout<1>,
            >,
            super::OciOuterUstarSlotV1,
            for<'replay> fn(
                super::ImportedOciOuterUstarViewV1<'replay>,
                super::ReplayedOciOuterUstarReceiptV1,
            ) -> anyhow::Result<()>,
        ) -> anyhow::Result<()>;
        type ExactInventoryImportSignature = for<'borrow, 'context> fn(
            &'borrow mut super::MutationCapability<
                'context,
                1,
                super::ProjectedPrepareInputSetCampaignLayout<1>,
            >,
            super::AuthenticatedOciOuterUstarInventoryV1,
        ) -> anyhow::Result<
            super::AuthenticatedOciOuterUstarImportCompletionV1<'borrow>,
        >;

        fn assert_opaque_error<T>()
        where
            T: std::fmt::Debug + std::fmt::Display + std::error::Error + Send + Sync + 'static,
        {
        }

        <super::OciOuterUstarCustodyPermitV1 as AmbiguousIfClone<_>>::marker();
        <super::OciOuterUstarCustodyPermitV1 as AmbiguousIfCopy<_>>::marker();
        <super::OciOuterUstarSlotV1 as AmbiguousIfClone<_>>::marker();
        <super::OciOuterUstarSlotV1 as AmbiguousIfCopy<_>>::marker();
        <super::ImportedOciOuterUstarViewV1<'static> as AmbiguousIfClone<_>>::marker();
        <super::ImportedOciOuterUstarViewV1<'static> as AmbiguousIfCopy<_>>::marker();
        <super::ImportedOciLayerObservationV1 as AmbiguousIfClone<_>>::marker();
        <super::ImportedOciLayerObservationV1 as AmbiguousIfCopy<_>>::marker();
        <super::ImportedOciOuterUstarReceiptV1 as AmbiguousIfClone<_>>::marker();
        <super::ImportedOciOuterUstarReceiptV1 as AmbiguousIfCopy<_>>::marker();
        <super::AuthenticatedOciLayerSealV1 as AmbiguousIfClone<_>>::marker();
        <super::AuthenticatedOciLayerSealV1 as AmbiguousIfCopy<_>>::marker();
        <super::AuthenticatedOciReplayTransitionV1 as AmbiguousIfClone<_>>::marker();
        <super::AuthenticatedOciReplayTransitionV1 as AmbiguousIfCopy<_>>::marker();
        <super::ReplayedOciOuterUstarReceiptV1 as AmbiguousIfClone<_>>::marker();
        <super::ReplayedOciOuterUstarReceiptV1 as AmbiguousIfCopy<_>>::marker();
        <super::AuthenticatedOciOuterUstarInventoryV1 as AmbiguousIfClone<_>>::marker();
        <super::AuthenticatedOciOuterUstarInventoryV1 as AmbiguousIfCopy<_>>::marker();
        <super::AuthenticatedOciOuterUstarImportCompletionV1<'_> as AmbiguousIfClone<_>>::marker();
        <super::AuthenticatedOciOuterUstarImportCompletionV1<'_> as AmbiguousIfCopy<_>>::marker();
        <super::AuthenticatedOciRetainedHostRootfsInventoryV1 as AmbiguousIfClone<_>>::marker();
        <super::AuthenticatedOciRetainedHostRootfsInventoryV1 as AmbiguousIfCopy<_>>::marker();
        <super::AuthenticatedOciRootfsInventoryAcquisitionFailureV1 as AmbiguousIfClone<_>>::marker(
        );
        <super::AuthenticatedOciRootfsInventoryAcquisitionFailureV1 as AmbiguousIfCopy<_>>::marker(
        );
        <super::AuthenticatedOciRootfsInventoryCleanupFailureV1 as AmbiguousIfClone<_>>::marker();
        <super::AuthenticatedOciRootfsInventoryCleanupFailureV1 as AmbiguousIfCopy<_>>::marker();

        assert_opaque_error::<super::AuthenticatedOciRootfsInventoryAcquisitionFailureV1>();
        assert_opaque_error::<super::AuthenticatedOciRootfsInventoryCleanupFailureV1>();
        let acquisition_retry: fn(
            super::AuthenticatedOciRootfsInventoryAcquisitionFailureV1,
        ) -> std::result::Result<
            anyhow::Error,
            super::AuthenticatedOciRootfsInventoryAcquisitionFailureV1,
        > = super::AuthenticatedOciRootfsInventoryAcquisitionFailureV1::retry_cleanup;
        let final_retry: fn(
            super::AuthenticatedOciRootfsInventoryCleanupFailureV1,
        ) -> std::result::Result<
            super::AuthenticatedOciRootfsIdentityCompletionV1,
            super::AuthenticatedOciRootfsInventoryCleanupFailureV1,
        > = super::AuthenticatedOciRootfsInventoryCleanupFailureV1::retry_cleanup;
        std::hint::black_box((acquisition_retry, final_retry));
        let exact_replay: ExactReplaySignature = super::with_replayed_oci_outer_ustar::<1, ()>;
        std::hint::black_box(exact_replay);
        let exact_projection: ExactSlotProjectionSignature =
            super::project_authenticated_oci_outer_ustar_slot;
        std::hint::black_box(exact_projection);
        let exact_inventory_import: ExactInventoryImportSignature =
            super::import_authenticated_oci_outer_ustar_inventory::<1>;
        std::hint::black_box(exact_inventory_import);
    }

    #[test]
    fn logical_inventory_completion_is_invariantly_branded_to_one_mutation_session() {
        let source = include_str!("oci_image_layout_import.rs");
        let production = source.split("\n#[cfg(test)]\nmod tests").next().unwrap();
        let completion = production
            .split("pub(super) struct AuthenticatedOciOuterUstarImportCompletionV1")
            .nth(1)
            .unwrap()
            .split("/// Affine proof that all four gate-bound OCI rootfs projections")
            .next()
            .unwrap();
        let compact_completion = completion.split_whitespace().collect::<String>();
        assert!(compact_completion.starts_with("<'session>{"));
        assert!(
            compact_completion
                .contains("_session:PhantomData<fn(&'sessionmut())->&'sessionmut()>,")
        );

        let import = production
            .split("pub(super) fn import_authenticated_oci_outer_ustar_inventory")
            .nth(1)
            .unwrap()
            .split("fn import_authenticated_oci_outer_ustar_slots")
            .next()
            .unwrap();
        let compact_import = import.split_whitespace().collect::<String>();
        assert!(compact_import.starts_with("<'session,'context,constROOTS:usize,>("));
        assert!(compact_import.contains(
            "capability:&'sessionmutMutationCapability<'context,ROOTS,ProjectedPrepareInputSetCampaignLayout<ROOTS>,>"
        ));
        assert!(
            compact_import
                .contains(")->Result<AuthenticatedOciOuterUstarImportCompletionV1<'session>>{")
        );
        assert!(compact_import.contains("_session:PhantomData,"));

        let physical = production
            .split("pub(super) fn authenticate_physical_rootfs_inventory_and_retain")
            .nth(1)
            .unwrap()
            .split("fn discard_replayed_receipts_after_error")
            .next()
            .unwrap();
        assert!(!physical.contains("MutationCapability"));
        assert!(!physical.contains("capability:"));
    }

    #[test]
    fn invariant_session_brand_compile_fails_if_it_escapes_to_a_second_mutation() {
        let fixture = r"
use std::marker::PhantomData;

struct MutationCapability;

struct Completion<'session> {
    _session: PhantomData<fn(&'session mut ()) -> &'session mut ()>,
}

fn import<'session>(_: &'session mut MutationCapability) -> Completion<'session> {
    Completion { _session: PhantomData }
}

fn with_mutation<T>(effect: impl FnOnce(&mut MutationCapability) -> T) -> T {
    let mut capability = MutationCapability;
    effect(&mut capability)
}

fn cross_session_escape() {
    let completion = with_mutation(|first| import(first));
    with_mutation(|_second| drop(completion));
}
";
        let temp = tempfile::tempdir().unwrap();
        let fixture_path = temp.path().join("session_brand_escape.rs");
        std::fs::write(&fixture_path, fixture).unwrap();
        let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| std::ffi::OsString::from("rustc"));
        let output = std::process::Command::new(rustc)
            .arg("--edition=2024")
            .arg("--crate-name=session_brand_escape")
            .arg("--crate-type=lib")
            .arg("--emit=metadata")
            .arg("--out-dir")
            .arg(temp.path())
            .arg(&fixture_path)
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "cross-session brand escape compiled"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("lifetime may not live long enough")
                || stderr.contains("borrowed data escapes outside of closure")
                || stderr.contains("does not live long enough"),
            "unexpected compile-fail diagnostic: {stderr}"
        );
    }

    #[test]
    fn physical_inventory_loop_retains_canonical_slots_then_cleans_in_reverse_order() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let roles = super::canonical_positive_runner_roles();
        let slots = std::array::from_fn(|index| FakePhysicalInventorySlotV1 {
            index,
            role: roles[index],
            postcheck_role_drift: FakePhysicalInventoryToggleV1::Disabled,
            role_reads: Cell::new(0),
            retain_failure: FakePhysicalInventoryToggleV1::Disabled,
            acquisition_retry_failures_remaining: 0,
            cleanup_failure: FakePhysicalInventoryToggleV1::Disabled,
            retry_failures_remaining: 0,
            discard_failure: FakePhysicalInventoryToggleV1::Disabled,
            events: Arc::clone(&events),
        });
        let expectations = roles.map(|role| FakePhysicalInventoryExpectationV1 { role });

        let retained =
            super::authenticate_physical_rootfs_inventory_slots(slots, &expectations).unwrap();
        let abandonments =
            super::cleanup_retained_physical_rootfs_inventory_slots(retained).unwrap();

        assert_eq!(abandonments, [0, 1, 2, 3]);
        assert_eq!(
            *events.lock().unwrap(),
            [
                FakePhysicalInventoryEventV1::Retained(0),
                FakePhysicalInventoryEventV1::Retained(1),
                FakePhysicalInventoryEventV1::Retained(2),
                FakePhysicalInventoryEventV1::Retained(3),
                FakePhysicalInventoryEventV1::Cleaned(3),
                FakePhysicalInventoryEventV1::Cleaned(2),
                FakePhysicalInventoryEventV1::Cleaned(1),
                FakePhysicalInventoryEventV1::Cleaned(0),
            ]
        );
    }

    #[test]
    fn physical_inventory_postcheck_role_drift_cleans_prior_and_future_custody() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let roles = super::canonical_positive_runner_roles();
        let slots = std::array::from_fn(|index| FakePhysicalInventorySlotV1 {
            index,
            role: roles[index],
            postcheck_role_drift: FakePhysicalInventoryToggleV1::when(index == 1),
            role_reads: Cell::new(0),
            retain_failure: FakePhysicalInventoryToggleV1::Disabled,
            acquisition_retry_failures_remaining: 0,
            cleanup_failure: FakePhysicalInventoryToggleV1::Disabled,
            retry_failures_remaining: 0,
            discard_failure: FakePhysicalInventoryToggleV1::Disabled,
            events: Arc::clone(&events),
        });
        let expectations = roles.map(|role| FakePhysicalInventoryExpectationV1 { role });

        let error =
            super::authenticate_physical_rootfs_inventory_slots(slots, &expectations).unwrap_err();

        assert!(
            format!("{error:#}")
                .contains("authenticated OCI rootfs slot order changed after prevalidation"),
            "postcheck role drift returned the wrong authority: {error:#}"
        );
        assert_eq!(
            *events.lock().unwrap(),
            [
                FakePhysicalInventoryEventV1::Retained(0),
                FakePhysicalInventoryEventV1::Discarded(3),
                FakePhysicalInventoryEventV1::Discarded(2),
                FakePhysicalInventoryEventV1::Discarded(1),
                FakePhysicalInventoryEventV1::Cleaned(0),
            ]
        );
    }

    #[test]
    fn physical_inventory_slot_two_failure_closes_every_other_slot_and_preserves_all_errors() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let roles = super::canonical_positive_runner_roles();
        let slots = std::array::from_fn(|index| FakePhysicalInventorySlotV1 {
            index,
            role: roles[index],
            postcheck_role_drift: FakePhysicalInventoryToggleV1::Disabled,
            role_reads: Cell::new(0),
            retain_failure: FakePhysicalInventoryToggleV1::when(index == 1),
            acquisition_retry_failures_remaining: 0,
            cleanup_failure: FakePhysicalInventoryToggleV1::when(index == 0),
            retry_failures_remaining: 0,
            discard_failure: FakePhysicalInventoryToggleV1::when(index >= 2),
            events: Arc::clone(&events),
        });
        let expectations = roles.map(|role| FakePhysicalInventoryExpectationV1 { role });

        let error =
            super::authenticate_physical_rootfs_inventory_slots(slots, &expectations).unwrap_err();

        assert_eq!(error.pending_closure_count(), 2);
        assert!(error.primary_error().is_none());
        assert_eq!(
            *events.lock().unwrap(),
            [
                FakePhysicalInventoryEventV1::Retained(0),
                FakePhysicalInventoryEventV1::RetainFailed(1),
                FakePhysicalInventoryEventV1::Discarded(3),
                FakePhysicalInventoryEventV1::Discarded(2),
                FakePhysicalInventoryEventV1::CleanupFailed(0),
            ]
        );
        let rendered = format!("{error:#}");
        assert!(rendered.contains("current rootfs acquisition outcome awaits consuming closure"));
        assert!(!rendered.contains("current rootfs acquisition cleanup remains retryable"));
        assert!(rendered.contains("fake secondary discard failure for slot 2"));
        assert!(rendered.contains("fake secondary discard failure for slot 3"));
        assert!(rendered.contains("fake retained physical inventory cleanup failure for slot 0"));
        let debug = format!("{error:?}");
        assert!(debug.contains("pending_consuming_closures"));
        assert!(!debug.contains("retryable_cleanup_failures"));
        let primary = error.retry_cleanup().unwrap();
        assert!(
            primary
                .downcast_ref::<FakePhysicalInventoryPrimaryErrorV1>()
                .is_some(),
            "current-slot cleanup retry erased the primary typed failure"
        );
        assert_eq!(
            *events.lock().unwrap(),
            [
                FakePhysicalInventoryEventV1::Retained(0),
                FakePhysicalInventoryEventV1::RetainFailed(1),
                FakePhysicalInventoryEventV1::Discarded(3),
                FakePhysicalInventoryEventV1::Discarded(2),
                FakePhysicalInventoryEventV1::CleanupFailed(0),
                FakePhysicalInventoryEventV1::AcquisitionCleanupRetried(1),
                FakePhysicalInventoryEventV1::AcquisitionCleanupRetrySucceeded(1),
                FakePhysicalInventoryEventV1::CleanupRetried(0),
                FakePhysicalInventoryEventV1::CleanupRetrySucceeded(0),
            ]
        );
    }

    #[test]
    fn physical_inventory_acquisition_failure_survives_opaque_transport_and_retries_all_custodies()
    {
        type Failure = super::PhysicalRootfsInventoryAcquisitionFailureV1<
            usize,
            FakePhysicalInventoryCleanupErrorV1,
            FakePhysicalInventoryAcquisitionErrorV1,
        >;

        let events = Arc::new(Mutex::new(Vec::new()));
        let roles = super::canonical_positive_runner_roles();
        let slots = std::array::from_fn(|index| FakePhysicalInventorySlotV1 {
            index,
            role: roles[index],
            postcheck_role_drift: FakePhysicalInventoryToggleV1::Disabled,
            role_reads: Cell::new(0),
            retain_failure: FakePhysicalInventoryToggleV1::when(index == 2),
            acquisition_retry_failures_remaining: 0,
            cleanup_failure: FakePhysicalInventoryToggleV1::when(index < 2),
            retry_failures_remaining: 0,
            discard_failure: FakePhysicalInventoryToggleV1::Disabled,
            events: Arc::clone(&events),
        });
        let expectations = roles.map(|role| FakePhysicalInventoryExpectationV1 { role });

        let failure =
            super::authenticate_physical_rootfs_inventory_slots(slots, &expectations).unwrap_err();
        assert_eq!(failure.pending_closure_count(), 3);
        assert!(failure.primary_error().is_none());

        let opaque = anyhow::Error::new(failure);
        let failure = opaque
            .downcast::<Failure>()
            .expect("typed acquisition retry custody was erased by opaque transport");
        let primary = failure.retry_cleanup().unwrap();

        assert!(
            primary
                .downcast_ref::<FakePhysicalInventoryPrimaryErrorV1>()
                .is_some(),
            "successful aggregate retry did not return the stored primary error"
        );
        assert_eq!(
            *events.lock().unwrap(),
            [
                FakePhysicalInventoryEventV1::Retained(0),
                FakePhysicalInventoryEventV1::Retained(1),
                FakePhysicalInventoryEventV1::RetainFailed(2),
                FakePhysicalInventoryEventV1::Discarded(3),
                FakePhysicalInventoryEventV1::CleanupFailed(1),
                FakePhysicalInventoryEventV1::CleanupFailed(0),
                FakePhysicalInventoryEventV1::AcquisitionCleanupRetried(2),
                FakePhysicalInventoryEventV1::AcquisitionCleanupRetrySucceeded(2),
                FakePhysicalInventoryEventV1::CleanupRetried(1),
                FakePhysicalInventoryEventV1::CleanupRetrySucceeded(1),
                FakePhysicalInventoryEventV1::CleanupRetried(0),
                FakePhysicalInventoryEventV1::CleanupRetrySucceeded(0),
            ]
        );
    }

    #[test]
    fn physical_inventory_acquisition_retry_retains_persistent_custody_and_skips_closed_slots() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let roles = super::canonical_positive_runner_roles();
        let slots = std::array::from_fn(|index| FakePhysicalInventorySlotV1 {
            index,
            role: roles[index],
            postcheck_role_drift: FakePhysicalInventoryToggleV1::Disabled,
            role_reads: Cell::new(0),
            retain_failure: FakePhysicalInventoryToggleV1::when(index == 2),
            acquisition_retry_failures_remaining: u8::from(index == 2),
            cleanup_failure: FakePhysicalInventoryToggleV1::when(index < 2),
            retry_failures_remaining: u8::from(index == 1),
            discard_failure: FakePhysicalInventoryToggleV1::Disabled,
            events: Arc::clone(&events),
        });
        let expectations = roles.map(|role| FakePhysicalInventoryExpectationV1 { role });

        let failure =
            super::authenticate_physical_rootfs_inventory_slots(slots, &expectations).unwrap_err();
        let failure = failure
            .retry_cleanup()
            .expect_err("current slot and slot one must retain custody after their first retry");

        assert_eq!(failure.pending_closure_count(), 2);
        assert!(failure.primary_error().is_none());
        let primary = failure.retry_cleanup().unwrap();
        assert!(
            primary
                .downcast_ref::<FakePhysicalInventoryPrimaryErrorV1>()
                .is_some()
        );
        assert_eq!(
            *events.lock().unwrap(),
            [
                FakePhysicalInventoryEventV1::Retained(0),
                FakePhysicalInventoryEventV1::Retained(1),
                FakePhysicalInventoryEventV1::RetainFailed(2),
                FakePhysicalInventoryEventV1::Discarded(3),
                FakePhysicalInventoryEventV1::CleanupFailed(1),
                FakePhysicalInventoryEventV1::CleanupFailed(0),
                FakePhysicalInventoryEventV1::AcquisitionCleanupRetried(2),
                FakePhysicalInventoryEventV1::AcquisitionCleanupRetryFailed(2),
                FakePhysicalInventoryEventV1::CleanupRetried(1),
                FakePhysicalInventoryEventV1::CleanupRetryFailed(1),
                FakePhysicalInventoryEventV1::CleanupRetried(0),
                FakePhysicalInventoryEventV1::CleanupRetrySucceeded(0),
                FakePhysicalInventoryEventV1::AcquisitionCleanupRetried(2),
                FakePhysicalInventoryEventV1::AcquisitionCleanupRetrySucceeded(2),
                FakePhysicalInventoryEventV1::CleanupRetried(1),
                FakePhysicalInventoryEventV1::CleanupRetrySucceeded(1),
            ]
        );
    }

    #[test]
    fn explicit_physical_inventory_cleanup_retries_two_failures_and_closes_all_custody() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let retained = std::array::from_fn(|index| FakeRetainedPhysicalInventorySlotV1 {
            index,
            fail_cleanup: index == 2 || index == 0,
            retry_failures_remaining: 0,
            events: Arc::clone(&events),
        });

        let error = super::cleanup_retained_physical_rootfs_inventory_slots(retained).unwrap_err();

        assert_eq!(
            *events.lock().unwrap(),
            [
                FakePhysicalInventoryEventV1::Cleaned(3),
                FakePhysicalInventoryEventV1::CleanupFailed(2),
                FakePhysicalInventoryEventV1::Cleaned(1),
                FakePhysicalInventoryEventV1::CleanupFailed(0),
            ]
        );
        assert!(
            error
                .first_failure()
                .is_some_and(|failure| failure.index == 2),
            "first reverse-order cleanup failure was erased: {error:#}"
        );
        let rendered = format!("{error:#}");
        assert!(rendered.contains("cleanup failure for slot 2"));
        assert!(rendered.contains("cleanup failure for slot 0"));

        let abandonments = error.retry_cleanup().unwrap();
        assert_eq!(abandonments, [0, 1, 2, 3]);
        assert_eq!(
            *events.lock().unwrap(),
            [
                FakePhysicalInventoryEventV1::Cleaned(3),
                FakePhysicalInventoryEventV1::CleanupFailed(2),
                FakePhysicalInventoryEventV1::Cleaned(1),
                FakePhysicalInventoryEventV1::CleanupFailed(0),
                FakePhysicalInventoryEventV1::CleanupRetried(2),
                FakePhysicalInventoryEventV1::CleanupRetrySucceeded(2),
                FakePhysicalInventoryEventV1::CleanupRetried(0),
                FakePhysicalInventoryEventV1::CleanupRetrySucceeded(0),
            ]
        );
    }

    #[test]
    fn explicit_physical_inventory_cleanup_retry_retains_only_persistent_custody() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let retained = std::array::from_fn(|index| FakeRetainedPhysicalInventorySlotV1 {
            index,
            fail_cleanup: index == 2 || index == 0,
            retry_failures_remaining: u8::from(index == 2),
            events: Arc::clone(&events),
        });

        let failure =
            super::cleanup_retained_physical_rootfs_inventory_slots(retained).unwrap_err();
        let failure = failure
            .retry_cleanup()
            .expect_err("slot two must retain custody after its first retry");

        assert_eq!(failure.pending_closure_count(), 1);
        assert_eq!(
            failure.first_failure().map(|failure| failure.index),
            Some(2)
        );
        let debug = format!("{failure:?}");
        assert!(debug.contains("pending_cleanup_closures"));
        assert!(!debug.contains("retryable_cleanup_failures"));
        let abandonments = failure.retry_cleanup().unwrap();
        assert_eq!(abandonments, [0, 1, 2, 3]);
        assert_eq!(
            *events.lock().unwrap(),
            [
                FakePhysicalInventoryEventV1::Cleaned(3),
                FakePhysicalInventoryEventV1::CleanupFailed(2),
                FakePhysicalInventoryEventV1::Cleaned(1),
                FakePhysicalInventoryEventV1::CleanupFailed(0),
                FakePhysicalInventoryEventV1::CleanupRetried(2),
                FakePhysicalInventoryEventV1::CleanupRetryFailed(2),
                FakePhysicalInventoryEventV1::CleanupRetried(0),
                FakePhysicalInventoryEventV1::CleanupRetrySucceeded(0),
                FakePhysicalInventoryEventV1::CleanupRetried(2),
                FakePhysicalInventoryEventV1::CleanupRetrySucceeded(2),
            ]
        );
    }

    #[test]
    fn production_inventory_projection_and_import_are_fixed_and_affine() {
        let source = include_str!("oci_image_layout_import.rs");
        let production = source.split("\n#[cfg(test)]\nmod tests").next().unwrap();

        assert!(production.contains("fn project_authenticated_oci_outer_ustar_slot("));
        assert!(!production.contains("pub(super) fn project_authenticated_oci_outer_ustar_slot("));
        assert!(production.contains("AuthenticatedOciSlotConstructionPermitV1"));
        assert!(production.contains("let (root_index, relative_path, profile) ="));
        assert!(production.contains("permit.into_parts();"));
        assert!(production.contains("role: profile.role(),"));
        assert!(
            production.contains("pub(super) fn project_authenticated_oci_outer_ustar_inventory(")
        );
        assert!(
            production.contains("pub(super) fn import_authenticated_oci_outer_ustar_inventory")
        );
        assert!(production.contains("canonical_positive_runner_roles()"));
        let fixed_import = production
            .split("pub(super) fn import_authenticated_oci_outer_ustar_inventory")
            .nth(1)
            .unwrap();
        let role_precheck = fixed_import
            .find("validate_canonical_inventory_roles")
            .unwrap();
        let first_read = fixed_import.find("with_replayed_oci_outer_ustar(").unwrap();
        assert!(role_precheck < first_read);
        assert!(!production.contains("fn with_imported_oci_outer_ustar<"));
        assert!(production.contains("role: PositiveRunnerRole,"));
        assert!(production.contains("const fn role(&self) -> PositiveRunnerRole"));
        for getter in [
            "post_changeset_entry_count",
            "post_changeset_regular_file_count",
            "post_changeset_directory_count",
            "post_changeset_symbolic_link_count",
            "post_changeset_regular_file_bytes",
        ] {
            assert!(production.contains(getter), "missing retained {getter}");
        }

        let slot_impl = production
            .split("impl OciOuterUstarSlotV1 {")
            .nth(1)
            .unwrap()
            .split("impl OciOuterUstarExpectationV1 {")
            .next()
            .unwrap();
        assert_eq!(
            declared_fn_names(slot_impl),
            ["test_only", "test_only_for_role"]
        );
    }

    #[test]
    fn production_inventory_failure_paths_explicitly_close_affine_rootfs_custody() {
        let source = include_str!("oci_image_layout_import.rs");
        let production = source.split("\n#[cfg(test)]\nmod tests").next().unwrap();
        let fixed_import = production
            .split("fn import_authenticated_oci_outer_ustar_slots")
            .nth(1)
            .unwrap()
            .split("#[cfg(all(test, target_os = \"linux\"))]")
            .next()
            .unwrap();

        assert!(production.contains("fn discard_replayed_receipts_after_error("));
        assert!(production.contains("receipt.discard_after_error(error)"));
        assert!(fixed_import.contains("discard_replayed_receipts_after_error(receipts, error)"));
        assert!(
            !fixed_import.contains("with_replayed_oci_outer_ustar(capability, slot, move |")
                || !fixed_import.contains("})?;"),
            "a later slot error must not implicitly drop earlier affine receipts"
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one source-contract test audits the complete private physical-inventory boundary"
    )]
    fn physical_rootfs_inventory_is_gate_rooted_affine_and_non_linux_fail_closed() {
        let source = include_str!("oci_image_layout_import.rs");
        let production = source.split("\n#[cfg(test)]\nmod tests").next().unwrap();
        let token = production
            .split("pub(super) struct AuthenticatedOciRootfsIdentityCompletionV1")
            .nth(1)
            .unwrap()
            .split("mod physical_rootfs_inventory_slot_seal")
            .next()
            .unwrap();
        assert!(token.contains("gate: PositiveGateBindings"));
        assert!(token.contains("[rootfs::PrivateOciRootfsAbandonedV1;"));
        for forbidden in [
            "PathBuf",
            "OwnedFd",
            "rootfs: AuthenticatedPrivateOciRootfs",
            "pub gate",
            "pub rootfs",
        ] {
            assert!(!token.contains(forbidden), "token exposes {forbidden}");
        }

        let closure = production
            .split("pub(super) fn authenticate_physical_rootfs_inventory_and_retain")
            .nth(1)
            .unwrap()
            .split("impl AuthenticatedOciRootfsInventoryAcquisitionFailureV1")
            .next()
            .unwrap();
        assert!(closure.contains("physical OCI rootfs identity authentication requires Linux"));
        assert_eq!(
            closure
                .matches("authenticate_physical_rootfs_inventory_slots(")
                .count(),
            1
        );
        let compact_closure = closure.split_whitespace().collect::<String>();
        assert!(compact_closure.contains(
            "matchauthenticate_physical_rootfs_inventory_slots(receipts,gate.oci_image_layouts(),)"
        ));
        assert!(compact_closure.contains(
            "Err(cleanup)=>{returnErr(AuthenticatedOciRootfsInventoryAcquisitionFailureV1{gate:Box::new(gate),cleanup:Box::new(cleanup),});}"
        ));
        assert!(compact_closure.contains(
            "std::result::Result<AuthenticatedOciRetainedHostRootfsInventoryV1,AuthenticatedOciRootfsInventoryAcquisitionFailureV1,>"
        ));
        assert!(closure.contains("retained_rootfs"));
        assert!(!closure.contains("authenticate_physical_rootfs_and_cleanup("));
        assert!(!closure.contains("while let Some"));
        assert!(!closure.contains(".clone()"));

        assert!(production.contains(
            "mod physical_rootfs_inventory_slot_seal {\n    pub(super) trait Sealed {}\n}"
        ));
        assert!(production.contains(
            "trait PhysicalRootfsInventorySlotV1: physical_rootfs_inventory_slot_seal::Sealed"
        ));
        assert!(production.contains("trait RetryablePhysicalRootfsInventoryAcquisitionFailureV1:"));
        assert!(production.contains(
            "type AcquisitionFailure: RetryablePhysicalRootfsInventoryAcquisitionFailureV1;"
        ));
        assert!(
            production
                .contains(") -> std::result::Result<Self::Retained, Self::AcquisitionFailure>;")
        );
        assert!(!production.contains("pub(super) trait PhysicalRootfsInventorySlotV1"));
        assert!(!production.contains("pub(super) fn authenticate_physical_rootfs_inventory_slots"));
        assert!(!production.contains("pub fn authenticate_physical_rootfs_inventory_slots"));

        let production_adapter = production
            .split("impl PhysicalRootfsInventorySlotV1 for ReplayedOciOuterUstarReceiptV1")
            .nth(1)
            .unwrap()
            .split("/// Execute the fixed four-slot physical identity transition")
            .next()
            .unwrap();
        assert_eq!(production_adapter.matches(".jvm_executables()").count(), 0);
        assert_eq!(
            production_adapter
                .matches("authenticate_physical_rootfs_and_retain(")
                .count(),
            1
        );
        assert!(
            production_adapter
                .contains("ReplayedOciOuterUstarReceiptV1::discard_after_error(self, primary)")
        );

        let orchestrator = production
            .split("fn authenticate_physical_rootfs_inventory_slots<Slot>(")
            .nth(1)
            .unwrap()
            .split("fn discard_physical_rootfs_slots_after_error<Slot>(")
            .next()
            .unwrap();
        assert!(orchestrator.contains("Slot: PhysicalRootfsInventorySlotV1"));
        assert!(orchestrator.contains("-> PhysicalRootfsInventoryAcquisitionResultV1<Slot>"));
        assert_eq!(
            orchestrator
                .matches("validate_canonical_inventory_roles(")
                .count(),
            2
        );
        assert!(orchestrator.contains("slot_roles == expectation_roles"));
        assert!(orchestrator.contains(".zip(canonical_positive_runner_roles())"));
        assert!(orchestrator.contains("slot.authenticate_and_retain(&expectations[index])"));
        assert!(orchestrator.contains("discard_remaining_physical_rootfs_slots("));
        assert!(orchestrator.contains(
            "PhysicalRootfsInventoryAcquisitionPrimaryStateV1::CurrentSlot(current_slot)"
        ));
        assert!(
            orchestrator.contains("cleanup_retained_physical_rootfs_slots_preserving_primary(")
        );
        assert_eq!(
            orchestrator
                .matches("cleanup_retained_physical_rootfs_slots_preserving_primary(")
                .count(),
            3,
            "slot failure, postcheck drift and cardinality drift must all close retained custody"
        );
        assert!(orchestrator.contains("match retained_rootfs.try_into()"));
        for forbidden in ["impl Fn", "FnOnce", "callback"] {
            assert!(
                !orchestrator.contains(forbidden),
                "private physical orchestrator exposes {forbidden}"
            );
        }

        let physical_discard = production
            .split("fn discard_physical_rootfs_slots_after_error<Slot>(")
            .nth(1)
            .unwrap()
            .split("fn discard_remaining_physical_rootfs_slots_preserving_primary<Slot>(")
            .next()
            .unwrap();
        assert!(physical_discard.contains("slots.into_iter().rev()"));
        assert!(physical_discard.contains("slot.discard_after_error(error)"));

        let physical_failure_cleanup = production
            .split("fn discard_remaining_physical_rootfs_slots_preserving_primary<Slot>(")
            .nth(1)
            .unwrap()
            .split("impl AuthenticatedOciOuterUstarImportCompletionV1")
            .next()
            .unwrap();
        assert!(physical_failure_cleanup.contains("primary.context("));
        assert!(physical_failure_cleanup.contains("discard_physical_rootfs_slots_after_error("));
        assert!(physical_failure_cleanup.contains("PhysicalRootfsInventoryOwnedFailuresV1"));
        assert!(
            physical_failure_cleanup.contains(
                "enum PhysicalRootfsInventoryAcquisitionPrimaryStateV1<AcquisitionFailure>"
            )
        );
        assert!(physical_failure_cleanup.contains("NonRetry(anyhow::Error)"));
        assert!(physical_failure_cleanup.contains("CurrentSlot(AcquisitionFailure)"));
        assert!(physical_failure_cleanup.contains("secondary: Vec<anyhow::Error>"));
        assert!(physical_failure_cleanup.contains("retained_rootfs.into_iter().enumerate().rev()"));
        let compact_failure_cleanup = physical_failure_cleanup
            .split_whitespace()
            .collect::<String>();
        assert!(
            compact_failure_cleanup.contains("cleanup_outcomes[index]=Some(retained.cleanup())")
        );
        assert!(
            compact_failure_cleanup
                .contains("Option<std::result::Result<Abandonment,CleanupFailure>>")
        );
        assert!(
            compact_failure_cleanup.contains("[std::result::Result<Abandonment,CleanupFailure>;")
        );
        assert!(
            physical_failure_cleanup
                .contains("for index in (0..AUTHENTICATED_OCI_INVENTORY_SIZE).rev()")
        );
        let current_retry = compact_failure_cleanup
            .find("CurrentSlot(failure)=>matchfailure.retry_cleanup()")
            .unwrap();
        let prior_retry = compact_failure_cleanup
            .find("forindexin(0..AUTHENTICATED_OCI_INVENTORY_SIZE).rev()")
            .unwrap();
        assert!(current_retry < prior_retry);
        assert!(!physical_failure_cleanup.contains("secondary.push(error)"));
    }

    #[test]
    fn physical_rootfs_inventory_adapter_passes_one_complete_gate_expectation() {
        let source = include_str!("oci_image_layout_import.rs");
        let production = source.split("\n#[cfg(test)]\nmod tests").next().unwrap();
        let adapter = production
            .split("impl PhysicalRootfsInventorySlotV1 for ReplayedOciOuterUstarReceiptV1")
            .nth(1)
            .unwrap()
            .split("/// Execute the fixed four-slot physical identity transition")
            .next()
            .unwrap();
        assert!(adapter.contains("type Expectation = B4PositiveOciImageLayoutV1;"));
        assert!(adapter.contains(
            "type AcquisitionFailure = rootfs::PrivateOciRetainedRootfsAcquisitionFailureV1;"
        ));
        let compact = adapter.split_whitespace().collect::<String>();
        assert!(compact.contains("rootfs.authenticate_physical_rootfs_and_retain(expectation)"));
        assert!(compact.contains("std::result::Result<Self::Retained,Self::AcquisitionFailure>"));
        assert!(!adapter.contains(".jvm_executables()"));
    }

    #[test]
    fn physical_rootfs_inventory_retains_host_custody_before_explicit_cleanup() {
        let source = include_str!("oci_image_layout_import.rs");
        let production = source.split("\n#[cfg(test)]\nmod tests").next().unwrap();
        let retained = production
            .split("pub(super) struct AuthenticatedOciRetainedHostRootfsInventoryV1")
            .nth(1)
            .unwrap()
            .split("/// Affine failure while acquiring the complete retained-rootfs inventory.")
            .next()
            .unwrap();
        let compact = retained.split_whitespace().collect::<String>();
        assert!(compact.contains("gate:PositiveGateBindings,"));
        assert!(compact.contains(
            "retained_rootfs:[rootfs::AuthenticatedPrivateOciRetainedRootfsV1;AUTHENTICATED_OCI_INVENTORY_SIZE],"
        ));
        assert!(!retained.contains("PrivateOciRootfsAbandonedV1"));

        let production_adapter = production
            .split("impl PhysicalRootfsInventorySlotV1 for ReplayedOciOuterUstarReceiptV1")
            .nth(1)
            .unwrap()
            .split("/// Execute the fixed four-slot physical identity transition")
            .next()
            .unwrap();
        assert!(production_adapter.contains("authenticate_physical_rootfs_and_retain"));
        assert!(!production_adapter.contains("authenticate_physical_rootfs_and_cleanup"));

        let retained_impl = production
            .split("impl AuthenticatedOciRetainedHostRootfsInventoryV1")
            .nth(1)
            .unwrap()
            .split("fn discard_replayed_receipts_after_error")
            .next()
            .unwrap();
        assert!(retained_impl.contains("reauthenticate_static_startup_dependencies"));
        assert!(retained_impl.contains("pub(super) fn cleanup("));
        let compact_impl = retained_impl.split_whitespace().collect::<String>();
        assert!(
            compact_impl.contains(".retained_rootfs.iter().zip(self.gate.oci_image_layouts())")
        );
        assert!(
            retained_impl
                .contains("cleanup_retained_physical_rootfs_inventory_slots(retained_rootfs)")
        );
        assert!(compact_impl.contains(
            "std::result::Result<AuthenticatedOciRootfsIdentityCompletionV1,AuthenticatedOciRootfsInventoryCleanupFailureV1,>"
        ));

        let cleanup = production
            .split("fn cleanup_retained_physical_rootfs_inventory_slots<Retained>(")
            .nth(1)
            .unwrap()
            .split("impl AuthenticatedOciOuterUstarImportCompletionV1")
            .next()
            .unwrap();
        assert!(cleanup.contains("-> PhysicalRootfsInventoryCleanupResultV1<Retained>"));
        assert!(
            cleanup.contains("let [slot_zero, slot_one, slot_two, slot_three] = retained_rootfs")
        );
        let cleanup_three = cleanup
            .find("let slot_three = slot_three.cleanup()")
            .unwrap();
        let cleanup_two = cleanup.find("let slot_two = slot_two.cleanup()").unwrap();
        let cleanup_one = cleanup.find("let slot_one = slot_one.cleanup()").unwrap();
        let cleanup_zero = cleanup.find("let slot_zero = slot_zero.cleanup()").unwrap();
        assert!(cleanup_three < cleanup_two);
        assert!(cleanup_two < cleanup_one);
        assert!(cleanup_one < cleanup_zero);
        assert!(cleanup.contains("finish_physical_rootfs_inventory_cleanup(["));
        assert!(!cleanup.contains("Vec<anyhow::Error>"));
        assert!(!cleanup.contains("failures.push(error)"));
        assert!(!cleanup.contains("reversed_abandonments"));
    }

    #[test]
    fn physical_rootfs_inventory_failures_own_typed_retry_custody_without_stringifying_it() {
        let source = include_str!("oci_image_layout_import.rs");
        let production = source.split("\n#[cfg(test)]\nmod tests").next().unwrap();

        let failure_types = production
            .split("pub(super) struct AuthenticatedOciRootfsInventoryAcquisitionFailureV1")
            .nth(1)
            .unwrap()
            .split("mod physical_rootfs_inventory_slot_seal")
            .next()
            .unwrap();
        let compact_types = failure_types.split_whitespace().collect::<String>();
        assert_eq!(
            compact_types
                .matches("gate:Box<PositiveGateBindings>,")
                .count(),
            2
        );
        assert!(compact_types.contains(
            "cleanup:Box<PhysicalRootfsInventoryAcquisitionFailureV1<rootfs::PrivateOciRootfsAbandonedV1,rootfs::PrivateOciRetainedRootfsCleanupFailureV1,rootfs::PrivateOciRetainedRootfsAcquisitionFailureV1,>,>,")
        );
        assert!(
            compact_types
                .contains("pub(super)structAuthenticatedOciRootfsInventoryCleanupFailureV1")
        );
        assert!(compact_types.contains(
            "cleanup:Box<PhysicalRootfsInventoryCleanupFailureV1<rootfs::PrivateOciRootfsAbandonedV1,rootfs::PrivateOciRetainedRootfsCleanupFailureV1,>,>,")
        );
        assert!(!failure_types.contains("#[derive(Clone"));
        assert!(!failure_types.contains("#[derive(Copy"));

        let acquisition_retry = production
            .split("impl AuthenticatedOciRootfsInventoryAcquisitionFailureV1 {")
            .nth(1)
            .unwrap()
            .split("impl std::fmt::Debug for AuthenticatedOciRootfsInventoryAcquisitionFailureV1")
            .next()
            .unwrap();
        let compact_acquisition_retry = acquisition_retry.split_whitespace().collect::<String>();
        assert!(
            compact_acquisition_retry.contains(
                "pub(super)fnretry_cleanup(self)->std::result::Result<anyhow::Error,Self>"
            )
        );
        assert!(compact_acquisition_retry.contains("match(*cleanup).retry_cleanup()"));
        assert!(compact_acquisition_retry.contains("Ok(primary)=>Ok(primary)"));
        assert!(
            compact_acquisition_retry
                .contains("Err(cleanup)=>Err(Self{gate,cleanup:Box::new(cleanup),})")
        );

        let final_retry = production
            .split("impl AuthenticatedOciRootfsInventoryCleanupFailureV1 {")
            .nth(1)
            .unwrap()
            .split("impl std::fmt::Debug for AuthenticatedOciRootfsInventoryCleanupFailureV1")
            .next()
            .unwrap();
        let compact_final_retry = final_retry.split_whitespace().collect::<String>();
        assert!(compact_final_retry.contains("match(*cleanup).retry_cleanup()"));
        assert!(
            compact_final_retry
                .contains("Err(cleanup)=>Err(Self{gate,cleanup:Box::new(cleanup),})")
        );
        assert!(compact_final_retry.contains("AuthenticatedOciRootfsIdentityCompletionV1"));

        for typed_retry in [acquisition_retry, final_retry] {
            assert!(!typed_retry.contains("format!("));
            assert!(!typed_retry.contains(".to_string()"));
            assert!(!typed_retry.contains("anyhow!("));
            assert!(!typed_retry.contains(".context("));
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the single source-authority guard keeps the complete replay-to-seal closure auditable"
    )]
    fn production_inventory_requires_two_authenticated_passes_before_completion() {
        let source = include_str!("oci_image_layout_import.rs");
        let production = source.split("\n#[cfg(test)]\nmod tests").next().unwrap();
        assert!(production.contains("fn with_replayed_oci_outer_ustar"));
        assert!(!production.contains("fn with_imported_oci_outer_ustar<const"));
        assert!(
            !include_str!("custody.rs")
                .contains("pub(super) fn with_authenticated_oci_image_layout_ustar_stream<")
        );

        let fixed_import = production
            .split("fn import_authenticated_oci_outer_ustar_slots")
            .nth(1)
            .unwrap()
            .split("#[cfg(all(test, target_os = \"linux\"))]")
            .next()
            .unwrap();
        assert!(fixed_import.contains("with_replayed_oci_outer_ustar("));

        let replay = production
            .split("fn with_replayed_oci_outer_ustar")
            .nth(1)
            .unwrap()
            .split("\nimpl ImportedOciOuterUstarReceiptV1 {")
            .next()
            .unwrap();
        assert_eq!(
            replay
                .matches("with_authenticated_oci_image_layout_ustar_replay_streams(")
                .count(),
            1
        );
        assert_eq!(
            replay
                .matches("inspect_authenticated_oci_outer_ustar(")
                .count(),
            1
        );
        assert_eq!(
            replay
                .matches("replay_authenticated_oci_outer_ustar_with_rootfs(")
                .count(),
            1
        );
        assert_eq!(
            replay
                .matches("into_authenticated_replay_transition(")
                .count(),
            2,
            "the Linux and non-Linux branches must each consume pass A exactly once"
        );
        assert_eq!(replay.matches("transition.authenticate_rootfs(").count(), 1);
        assert!(replay.contains("ReplayedOciOuterUstarWithRootfsV1::discard_after_error"));

        let outer_replay = production
            .split("fn replay_authenticated_oci_outer_ustar_with_rootfs")
            .nth(1)
            .unwrap()
            .split("\n#[cfg(not(target_os = \"linux\"))]")
            .next()
            .unwrap();
        assert!(outer_replay.contains("OciLayerPassV1::AuthenticatedReplay"));
        assert!(outer_replay.contains("Some(&mut rootfs)"));
        assert!(production.contains("archive.replay_layer_payload_with_sink("));
        assert!(production.contains("layer::replay_authenticated_oci_layer_with_sink("));

        assert_eq!(
            production.matches("AuthenticatedOciLayerSealV1 {").count(),
            2,
            "the parent module must contain one type definition and one production mint"
        );
        let transition = production
            .split("fn into_authenticated_replay_transition(")
            .nth(1)
            .unwrap()
            .split("\n}\n\n#[cfg(target_os = \"linux\")]")
            .next()
            .unwrap();
        assert_eq!(
            transition.matches("AuthenticatedOciLayerSealV1 {").count(),
            1
        );
        assert!(
            transition.find("replay_matches_inspection").unwrap()
                < transition.find("AuthenticatedOciLayerSealV1 {").unwrap()
        );

        let rootfs_source = include_str!("oci_image_layout_import/rootfs.rs").replace("\r\n", "\n");
        let rootfs_production = rootfs_source
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .unwrap();
        assert_eq!(
            rootfs_production
                .matches("AuthenticatedOciLayerSealV1 {")
                .count(),
            2,
            "rootfs may contain only one cfg(test) mint and one runtime destructure"
        );
        assert!(rootfs_production.contains("#[cfg(test)]\n    fn seal_semantic_layer("));
        assert_eq!(
            rootfs_production
                .matches("self.seal_authenticated_semantic_layer(AuthenticatedOciLayerSealV1 {")
                .count(),
            1
        );
        assert!(rootfs_production.contains("let AuthenticatedOciLayerSealV1 {"));
        assert!(rootfs_production.contains("pub(super) fn authenticate_and_retain("));
        assert!(!rootfs_production.contains("pub(super) fn authenticate_and_discard("));
        let json_descendant = include_str!("oci_image_layout_import/json.rs").replace("\r\n", "\n");
        assert!(!json_descendant.contains("AuthenticatedOciLayerSealV1 {"));

        let layer_descendant =
            include_str!("oci_image_layout_import/layer.rs").replace("\r\n", "\n");
        let (layer_before_test_seal, layer_test_seal_and_remainder) = layer_descendant
            .split_once("#[cfg(test)]\npub(super) fn test_only_authenticated_regular_layer_seal(")
            .expect("test-only layer-seal constructor boundary");
        assert!(!layer_before_test_seal.contains("AuthenticatedOciLayerSealV1 {"));
        assert_eq!(
            layer_test_seal_and_remainder
                .matches("AuthenticatedOciLayerSealV1 {")
                .count(),
            1
        );
        assert_eq!(
            layer_descendant
                .matches("AuthenticatedOciLayerSealV1 {")
                .count(),
            1
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn oci_import_origin_has_no_ambient_descriptor_or_parser_authority() {
        let source = include_str!("oci_image_layout_import.rs");
        let production = source.split("\n#[cfg(test)]\nmod tests").next().unwrap();
        let normalized = source.replace("\r\n", "\n");
        let json_source = include_str!("oci_image_layout_import/json.rs");
        let json_production = json_source
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .unwrap();
        let layer_source = include_str!("oci_image_layout_import/layer.rs").replace("\r\n", "\n");
        let layer_production = layer_source.split("\n#[cfg(test)]\n").next().unwrap();
        let parent = include_str!("mod.rs");
        let custody_source = include_str!("custody.rs");
        assert!(
            parent
                .lines()
                .any(|line| line.trim() == "mod oci_image_layout_import;")
        );
        assert!(!parent.contains("pub mod oci_image_layout_import;"));
        assert!(!parent.contains("pub(crate) mod oci_image_layout_import;"));
        let specialized_custody = custody_source
            .split("pub(super) fn with_authenticated_oci_image_layout_ustar_replay_streams")
            .nth(1)
            .unwrap()
            .split("#[cfg(all(test, target_os = \"linux\"))]")
            .next()
            .unwrap();
        assert!(
            specialized_custody
                .find("validate_retained_oci_image_layout_ustar_length")
                .unwrap()
                < specialized_custody
                    .find("with_authenticated_file_replay_streams_impl")
                    .unwrap()
        );
        for forbidden in [
            "ProofCapability",
            "BorrowedFd",
            "AsFd",
            "AsRawFd",
            "OwnedFd",
            "File::open",
            "OpenOptions",
            "openat",
            "Seek",
            "std::fs",
            "with_root_descriptor",
            "with_immutable_root_descriptor",
            "read_immutable_file",
            "with_authenticated_file_stream_impl",
            "include_bytes!",
            "Serialize",
            "Deserialize",
            "Command::new",
        ] {
            assert!(!production.contains(forbidden), "forbidden {forbidden}");
            assert!(
                !json_production.contains(forbidden),
                "forbidden {forbidden} in private OCI JSON codec"
            );
            assert!(
                !layer_production.contains(forbidden),
                "forbidden {forbidden} in private OCI layer parser"
            );
        }
        assert!(!layer_production.contains("diff_id"));
        assert!(
            layer_production.contains("fn consume_payload_and_padding("),
            "private OCI production scan must reach the final production helper"
        );
        assert_eq!(production.matches(".diff_id()").count(), 1);
        assert!(production.contains("receipt.observed_uncompressed_sha256() == expected_diff_id"));
        assert!(!layer_production.contains("Vec<u8>"));
        assert!(layer_production.contains("pub(super) fn inspect_authenticated_oci_layer("));
        assert!(layer_production.contains("Result<ImportedOciLayerReceiptV1>"));
        assert!(production.contains("struct ExactOuterMemberReaderV1<'archive, 'reader>"));
        assert!(production.contains("layer::inspect_authenticated_oci_layer(&mut member"));
        assert!(production.contains("member.require_complete()?;"));
        assert!(production.contains("self.consume_zero_member_padding(payload_bytes)?;"));
        assert!(production.contains("checked_add_layer("));
        assert!(production.contains("checked_add_uncompressed_tar_bytes("));
        assert!(production.contains("checked_add_tar_entries("));
        let exact_member_fields = production
            .split("struct ExactOuterMemberReaderV1<'archive, 'reader> {")
            .nth(1)
            .unwrap()
            .split("\n}")
            .next()
            .unwrap();
        assert!(!exact_member_fields.contains("Vec"));
        assert!(!exact_member_fields.contains("path"));
        assert!(!exact_member_fields.contains("descriptor"));
        assert!(exact_member_fields.contains("archive:"));
        assert!(exact_member_fields.contains("remaining: u64"));
        let inert_layer_observation = production
            .split("struct ImportedOciLayerObservationV1 {")
            .nth(1)
            .unwrap()
            .split("\n}\n\nimpl ImportedOciLayerObservationV1")
            .next()
            .unwrap();
        for forbidden in ["path", "descriptor", "reader", "payload", "rootfs"] {
            assert!(
                !inert_layer_observation.contains(forbidden),
                "layer observation retains forbidden authority {forbidden}"
            );
        }
        assert!(production.contains("OciOuterUstarCustodyPermitV1 { _private: () }"));
        assert!(production.contains("OciOuterUstarSlotV1"));
        assert!(production.contains("#[cfg(test)]\n    fn test_only("));
        assert!(normalized.contains("#[cfg(test)]\n    StructuralTestOnly,"));
        assert!(normalized.contains("#[cfg(test)]\n    const fn structural_test_only() -> Self"));
        assert!(!production.contains("image_expectation: Option"));
        assert!(!production.contains("inspect_oci_outer_ustar_impl(None"));
        let slot_impl = production
            .split("impl OciOuterUstarSlotV1 {")
            .nth(1)
            .unwrap()
            .split("impl OciOuterUstarExpectationV1 {")
            .next()
            .unwrap();
        assert_eq!(
            declared_fn_names(slot_impl),
            ["test_only", "test_only_for_role"]
        );
        let expectation_impl = production
            .split("impl OciOuterUstarExpectationV1 {")
            .nth(1)
            .unwrap()
            .split("#[derive(Debug)]")
            .next()
            .unwrap();
        assert_eq!(declared_fn_names(expectation_impl), ["test_only"]);
        assert_eq!(production.matches("OciOuterUstarSlotV1 {").count(), 5);
        assert_eq!(
            production.matches("OciOuterUstarExpectationV1 {").count(),
            3
        );

        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/b4_campaign_executor");
        let json_root = root.join("oci_image_layout_import");
        let mut json_entries = fs::read_dir(&json_root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        json_entries.sort();
        assert_eq!(json_entries, ["json.rs", "layer.rs", "rootfs", "rootfs.rs"]);
        let mut rust_sources = Vec::new();
        collect_rust_sources_without_links(&root, &mut rust_sources);
        rust_sources.sort();
        let mut saw_origin = false;
        let mut saw_json_origin = false;
        let mut saw_layer_origin = false;
        let mut saw_custody = false;
        let mut saw_parent = false;
        for path in rust_sources {
            let relative = path
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if relative == "oci_image_layout_import.rs" {
                saw_origin = true;
                continue;
            }
            if relative == "oci_image_layout_import/json.rs" {
                saw_json_origin = true;
                continue;
            }
            if relative == "oci_image_layout_import/layer.rs" {
                saw_layer_origin = true;
                continue;
            }
            saw_custody |= relative == "custody.rs";
            saw_parent |= relative == "mod.rs";
            let sibling = fs::read_to_string(&path).unwrap().replace("\r\n", "\n");
            let sibling = production_before_test_module(&sibling);
            for private_identifier in [
                "OciOuterUstarSlotV1",
                "OciOuterUstarExpectationV1",
                "ImportedOciOuterUstarViewV1",
                "ImportedOciOuterUstarReceiptV1",
                "ImportedOciLayerObservationV1",
                "ExactOuterMemberReaderV1",
                "with_replayed_oci_outer_ustar",
                "project_authenticated_oci_outer_ustar_slot",
            ] {
                assert_eq!(
                    rust_identifier_count(sibling, private_identifier),
                    0,
                    "private OCI authority {private_identifier} escaped through {relative}"
                );
            }
            assert_eq!(
                sibling
                    .matches("project_authenticated_oci_outer_ustar_inventory(")
                    .count(),
                usize::from(relative == "preflight.rs"),
                "fixed OCI inventory projection call drifted in {relative}"
            );
            assert_eq!(
                sibling
                    .matches("import_authenticated_oci_outer_ustar_inventory(")
                    .count(),
                usize::from(relative == "mod.rs"),
                "fixed OCI inventory import call drifted in {relative}"
            );
            if !matches!(relative.as_str(), "mod.rs" | "preflight.rs") {
                for boundary_identifier in [
                    "AuthenticatedOciOuterUstarInventoryV1",
                    "AuthenticatedOciOuterUstarImportCompletionV1",
                    "AuthenticatedOciSlotConstructionPermitV1",
                ] {
                    assert_eq!(
                        rust_identifier_count(sibling, boundary_identifier),
                        0,
                        "OCI boundary {boundary_identifier} escaped through {relative}"
                    );
                }
            }
        }
        assert!(saw_origin && saw_json_origin && saw_layer_origin && saw_custody && saw_parent);
    }
}
