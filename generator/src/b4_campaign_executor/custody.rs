//! Retained executable and immutable-root observations.

use std::{fmt, path::Path};

#[cfg(target_os = "linux")]
use std::os::fd::BorrowedFd;

#[cfg(target_os = "linux")]
use anyhow::Context as _;
use anyhow::Result;

#[cfg(all(target_os = "linux", feature = "b4-negative-materialization-handler"))]
use eip_0045_reproduction::{
    b4_campaign_contract::{
        B4CampaignPrecommitAuthorityV1, B4ContractArtifactIdentityV1,
        B4PositiveGenerationAuthorityV2,
    },
    b4_materialization_set::{
        B4NegativeMaterializationSetAuthorityV1, B4NegativeMaterializationSetAuthorityV2,
        B4NegativeMaterializationSetExternalInputsV1,
    },
    b4_negative_ancestry_authority::{
        B4NegativeAncestryWitnessCatalogAuthorityV1, B4NegativeAncestryWitnessCatalogAuthorityV2,
    },
    b4_positive_gate::B4PositiveGenerationAuthorityV1,
    b4_terminal_evidence_packet::{
        B4TerminalEvidenceImportAuthorityV2,
        authenticate_b4_terminal_evidence_import_from_directory_descriptor,
        authenticate_b4_terminal_evidence_import_from_directory_descriptor_v2,
    },
    b4_terminal_source_lineage::{
        B4TerminalSourceLineageAuthorityV1, B4TerminalSourceLineageAuthorityV2,
    },
};

#[cfg(all(target_os = "linux", feature = "b4-authoritative-build-custody"))]
use eip_0045_reproduction::b4_build_check::{
    AuthoritativeB4BuildProjection, B4BuildExpectations,
    validate_published_b4_build_from_directory_descriptor,
};

#[cfg(all(target_os = "linux", feature = "b4-negative-materialization-handler"))]
use crate::alternate_root_candidate::generate_fixed_alternate_root_proof_bundle;

use super::{
    amd64_elf_inspection::Amd64ElfCustodyPermitV1,
    artifact_import_contract::{Amd64ElfPolicyV1, B4ImmutableArtifactRoleV1},
    capability::MutationCapability,
    git_bundle_import::ReviewedGitBundleCustodyPermitV1,
    oci_image_layout_import::OciOuterUstarCustodyPermitV1,
    preflight::{ProjectedOciImageLayoutCaptureSlotV1, ProjectedPrepareInputSetCampaignLayout},
};

#[cfg(all(target_os = "linux", feature = "b4-negative-materialization-handler"))]
use super::prepare_negative_materialization_set::{
    NegativeMaterializationDescriptorRootPlanV1, NegativeMaterializationDescriptorRootPlanV2,
};

#[cfg(target_os = "linux")]
use super::preflight::MAX_PROJECTED_OCI_IMAGE_LAYOUT_CAPTURE_SLOTS;

pub(super) use eip_0045_reproduction::b4_executor_custody::B4CurrentExecutableObservationV1 as CurrentExecutableObservation;

const AMD64_ELF_MAX_BYTES: u64 = 1_073_741_824;
const REVIEWED_GIT_BUNDLE_MAX_BYTES: u64 = 1_073_741_824;
const OCI_OUTER_USTAR_MAX_BYTES: u64 = 17_179_869_184;
pub(super) const MAX_BUFFERED_IMMUTABLE_FILE_BYTES: usize = 512 * 1024 * 1024;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthenticatedStreamRoleV1 {
    Generic,
    OciImageLayoutUstar,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuthenticatedFileStreamRequestV1<'a> {
    role: AuthenticatedStreamRoleV1,
    root_index: usize,
    relative: &'a str,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ImmutableFileReadStage {
    PathPinned,
    DataOpened,
    BytesRead,
    FileRepinned,
}

/// Two authenticated-stream stages which failed during one fail-closed exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthenticatedStreamFailurePairV1 {
    /// Inspection failed after the retained stream recorded a physical read failure.
    InspectionAndRead,
    /// Inspection and the descriptor-local file postcheck both failed.
    InspectionAndFilePostcheck,
    /// Inspection and the complete immutable-root pre-delivery postcheck both failed.
    InspectionAndPreDeliveryPostcheck,
    /// Delivery and the complete immutable-root post-delivery check both failed.
    DeliveryAndPostcheck,
}

/// Stage-tagged pair which retains both typed failures rather than stringifying either one.
#[derive(Debug)]
pub(super) struct AuthenticatedStreamCombinedFailureV1 {
    pair: AuthenticatedStreamFailurePairV1,
    earlier: anyhow::Error,
    later: anyhow::Error,
}

impl AuthenticatedStreamCombinedFailureV1 {
    /// Return the two stages represented by this failure.
    pub(super) const fn pair(&self) -> AuthenticatedStreamFailurePairV1 {
        self.pair
    }

    /// Return the earlier typed failure.
    pub(super) const fn earlier(&self) -> &anyhow::Error {
        &self.earlier
    }

    /// Return the later typed failure.
    pub(super) const fn later(&self) -> &anyhow::Error {
        &self.later
    }
}

impl fmt::Display for AuthenticatedStreamCombinedFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (earlier, later) = match self.pair {
            AuthenticatedStreamFailurePairV1::InspectionAndRead => {
                ("immutable-root stream inspection", "its read")
            }
            AuthenticatedStreamFailurePairV1::InspectionAndFilePostcheck => {
                ("immutable-root stream inspection", "its file postcheck")
            }
            AuthenticatedStreamFailurePairV1::InspectionAndPreDeliveryPostcheck => (
                "immutable-root stream inspection",
                "its pre-delivery postcheck",
            ),
            AuthenticatedStreamFailurePairV1::DeliveryAndPostcheck => (
                "authenticated immutable-root stream delivery",
                "its postcheck",
            ),
        };
        write!(
            formatter,
            "{earlier} failed ({:#}) and {later} also failed ({:#})",
            self.earlier, self.later
        )
    }
}

impl std::error::Error for AuthenticatedStreamCombinedFailureV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.later.as_ref())
    }
}

fn combine_authenticated_stream_failures(
    pair: AuthenticatedStreamFailurePairV1,
    earlier: anyhow::Error,
    later: anyhow::Error,
) -> anyhow::Error {
    anyhow::Error::new(AuthenticatedStreamCombinedFailureV1 {
        pair,
        earlier,
        later,
    })
}

/// Retained, non-authorizing custody of the one campaign root namespace.
pub(super) struct CampaignRootCustody {
    #[cfg(target_os = "linux")]
    state: linux::PinnedCampaignRoot,
}

impl fmt::Debug for CampaignRootCustody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CampaignRootCustody")
            .finish_non_exhaustive()
    }
}

impl CampaignRootCustody {
    pub(super) fn capture(path: &Path) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                state: linux::PinnedCampaignRoot::capture(path)?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            anyhow::bail!("qualifying B4 campaign-root custody requires Linux")
        }
    }

    pub(super) fn recheck(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.state.recheck()
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self;
            anyhow::bail!("qualifying B4 campaign-root custody requires Linux")
        }
    }

    pub(super) fn require_directory_chain(
        &self,
        path: &Path,
        component_identities: &[(u64, u64, u64)],
    ) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.recheck()?;
            self.state
                .require_external_descendant(path, component_identities)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, path, component_identities);
            anyhow::bail!("qualifying B4 campaign-root custody requires Linux")
        }
    }
}

/// Fixed-cardinality, non-authorizing custody of immutable input roots.
pub(super) struct ImmutableRootCustody<const ROOTS: usize> {
    #[cfg(target_os = "linux")]
    roots: [linux::PinnedImmutableRoot; ROOTS],
}

impl<const ROOTS: usize> fmt::Debug for ImmutableRootCustody<ROOTS> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImmutableRootCustody")
            .field("root_count", &ROOTS)
            .finish_non_exhaustive()
    }
}

impl<const ROOTS: usize> ImmutableRootCustody<ROOTS> {
    /// Pin a fixed-size root set and take two identical bounded tree snapshots.
    pub(super) fn capture(
        campaign_root: &CampaignRootCustody,
        paths: [&Path; ROOTS],
    ) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                roots: linux::capture_immutable_roots(&campaign_root.state, paths)?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (campaign_root, paths);
            anyhow::bail!("qualifying B4 immutable-root custody requires Linux")
        }
    }

    /// Pin the exact projected OCI image-layout paths before any immutable-root
    /// snapshot is taken. The slots are unforgeable outside the pure H0
    /// projection and are consumed into retained custody on every exit.
    pub(super) fn capture_with_projected_oci(
        campaign_root: &CampaignRootCustody,
        paths: [&Path; ROOTS],
        slots: Vec<ProjectedOciImageLayoutCaptureSlotV1>,
    ) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                roots: linux::capture_immutable_roots_with_projected_oci(
                    &campaign_root.state,
                    paths,
                    slots,
                )?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (campaign_root, paths, slots);
            anyhow::bail!("qualifying B4 projected OCI immutable-root custody requires Linux")
        }
    }

    /// Reauthenticate every path and require exact bounded tree equality.
    pub(super) fn recheck(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            linux::recheck_immutable_roots(&self.roots)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = self;
            anyhow::bail!("qualifying B4 immutable-root custody requires Linux")
        }
    }

    /// Reject an OCI profile-footprint mismatch from the retained in-memory
    /// snapshot before this import call performs a root replay or stream open.
    #[cfg(target_os = "linux")]
    fn validate_retained_oci_image_layout_ustar_length(
        &self,
        root_index: usize,
        relative: &str,
        expected_byte_length: u64,
    ) -> Result<()> {
        let root = self
            .roots
            .get(root_index)
            .context("immutable-root index is outside the fixed root set")?;
        linux::validate_retained_oci_image_layout_ustar_length(root, relative, expected_byte_length)
    }

    /// Reject a publication-parent chain which aliases any directory in custody.
    pub(super) fn reject_physical_directory_aliases(
        &self,
        candidates: &[(u64, u64, u64)],
    ) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.recheck()?;
            linux::reject_physical_directory_aliases(&self.roots, candidates)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, candidates);
            anyhow::bail!("qualifying B4 immutable-root custody requires Linux")
        }
    }

    /// Read one bounded file relative to a retained immutable-root descriptor.
    pub(super) fn read_file<const MAX_BYTES: usize>(
        &self,
        root_index: usize,
        relative: &str,
    ) -> Result<Vec<u8>> {
        self.read_file_with_length_validation::<MAX_BYTES>(root_index, relative, |_byte_length| {
            Ok(())
        })
    }

    /// Read one bounded file after validating its retained length before allocation.
    pub(super) fn read_file_with_length_validation<const MAX_BYTES: usize>(
        &self,
        root_index: usize,
        relative: &str,
        validate_length: impl FnOnce(u64) -> Result<()>,
    ) -> Result<Vec<u8>> {
        #[cfg(target_os = "linux")]
        {
            self.recheck()?;
            let outcome = linux::read_immutable_root_file_with_hook::<MAX_BYTES, _, _>(
                self.roots
                    .get(root_index)
                    .context("immutable-root index is outside the fixed root set")?,
                relative,
                validate_length,
                |_stage| Ok(()),
            );
            let postcheck = self.recheck();
            match (outcome, postcheck) {
                (Ok(bytes), Ok(())) => Ok(bytes),
                (Err(error), Ok(())) => Err(error),
                (Ok(_), Err(postcheck)) => {
                    Err(postcheck).context("immutable-root read completed but its postcheck failed")
                }
                (Err(read), Err(postcheck)) => Err(postcheck).context(format!(
                    "immutable-root read failed ({read:#}) and its postcheck also failed"
                )),
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, root_index, relative, validate_length);
            anyhow::bail!("qualifying B4 immutable-root custody requires Linux")
        }
    }

    /// Borrow one bounded file body only after its retained descriptor identity,
    /// role-selected length, streamed SHA-256, exact EOF, and nominal repin all
    /// agree with the immutable-root snapshot.
    pub(super) fn with_authenticated_file_bytes<const MAX_BYTES: usize, T>(
        &self,
        root_index: usize,
        relative: &str,
        validate_length: impl FnOnce(u64) -> Result<()>,
        effect: impl for<'bytes> FnOnce(&'bytes [u8]) -> Result<T>,
    ) -> Result<T> {
        #[cfg(target_os = "linux")]
        {
            self.with_authenticated_file_bytes_impl::<MAX_BYTES, _, _, _>(
                root_index,
                relative,
                validate_length,
                |_stage| Ok(()),
                effect,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, root_index, relative, validate_length, effect);
            anyhow::bail!("qualifying B4 immutable-root file import requires Linux")
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn with_authenticated_file_bytes_test_hook<const MAX_BYTES: usize, T>(
        &self,
        root_index: usize,
        relative: &str,
        validate_length: impl FnOnce(u64) -> Result<()>,
        hook: impl FnMut(ImmutableFileReadStage) -> Result<()>,
        effect: impl for<'bytes> FnOnce(&'bytes [u8]) -> Result<T>,
    ) -> Result<T> {
        self.with_authenticated_file_bytes_impl::<MAX_BYTES, _, _, _>(
            root_index,
            relative,
            validate_length,
            hook,
            effect,
        )
    }

    #[cfg(target_os = "linux")]
    fn with_authenticated_file_bytes_impl<const MAX_BYTES: usize, T, Validate, Hook>(
        &self,
        root_index: usize,
        relative: &str,
        validate_length: Validate,
        hook: Hook,
        effect: impl for<'bytes> FnOnce(&'bytes [u8]) -> Result<T>,
    ) -> Result<T>
    where
        Validate: FnOnce(u64) -> Result<()>,
        Hook: FnMut(ImmutableFileReadStage) -> Result<()>,
    {
        let root = self
            .roots
            .get(root_index)
            .context("immutable-root index is outside the fixed root set")?;
        self.recheck()?;
        let outcome = (|| {
            let bytes = linux::read_immutable_root_file_with_hook::<MAX_BYTES, _, _>(
                root,
                relative,
                validate_length,
                hook,
            )?;
            effect(&bytes)
        })();
        let postcheck = self.recheck();
        match (outcome, postcheck) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(postcheck)) => Err(postcheck)
                .context("authenticated immutable-root callback completed but its postcheck failed"),
            (Err(effect), Err(postcheck)) => Err(postcheck).context(format!(
                "authenticated immutable-root callback failed ({effect:#}) and its postcheck also failed"
            )),
        }
    }

    #[cfg(target_os = "linux")]
    fn with_authenticated_file_stream_impl<
        const MAX_BYTES: u64,
        Parsed,
        T,
        Validate,
        Hook,
        Inspect,
        Deliver,
    >(
        &self,
        request: AuthenticatedFileStreamRequestV1<'_>,
        validate_length: Validate,
        hook: Hook,
        inspect: Inspect,
        deliver: Deliver,
    ) -> Result<T>
    where
        Validate: FnOnce(u64) -> Result<()>,
        Hook: FnMut(ImmutableFileReadStage) -> Result<()>,
        Inspect: for<'reader> FnOnce(
            u64,
            [u8; 32],
            &'reader mut (dyn std::io::Read + 'reader),
        ) -> Result<Parsed>,
        Deliver: FnOnce(u64, [u8; 32], Parsed) -> Result<T>,
    {
        self.with_authenticated_file_stream_impl_with_rejection::<
            MAX_BYTES,
            Parsed,
            T,
            Validate,
            Hook,
            Inspect,
            _,
            Deliver,
        >(
            request,
            validate_length,
            hook,
            inspect,
            |_parsed, error| error,
            deliver,
        )
    }

    #[cfg(target_os = "linux")]
    #[allow(
        clippy::too_many_arguments,
        reason = "owned inspection rejection is explicit so affine resources can close before delivery"
    )]
    fn with_authenticated_file_stream_impl_with_rejection<
        const MAX_BYTES: u64,
        Parsed,
        T,
        Validate,
        Hook,
        Inspect,
        Reject,
        Deliver,
    >(
        &self,
        request: AuthenticatedFileStreamRequestV1<'_>,
        validate_length: Validate,
        hook: Hook,
        inspect: Inspect,
        reject: Reject,
        deliver: Deliver,
    ) -> Result<T>
    where
        Validate: FnOnce(u64) -> Result<()>,
        Hook: FnMut(ImmutableFileReadStage) -> Result<()>,
        Inspect: for<'reader> FnOnce(
            u64,
            [u8; 32],
            &'reader mut (dyn std::io::Read + 'reader),
        ) -> Result<Parsed>,
        Reject: FnOnce(Parsed, anyhow::Error) -> anyhow::Error,
        Deliver: FnOnce(u64, [u8; 32], Parsed) -> Result<T>,
    {
        let root = self
            .roots
            .get(request.root_index)
            .context("immutable-root index is outside the fixed root set")?;
        self.recheck()?;
        let inspection =
            linux::inspect_authenticated_immutable_root_file_stream::<MAX_BYTES, _, _, _, _>(
                root,
                request.role,
                request.relative,
                validate_length,
                hook,
                inspect,
            );
        let authentication_postcheck = self.recheck();
        let (byte_length, sha256, parsed) = match (inspection, authentication_postcheck) {
            (Ok(authenticated), Ok(())) => authenticated,
            (Err(error), Ok(())) => return Err(error),
            (Ok((_byte_length, _sha256, parsed)), Err(postcheck)) => {
                let error = postcheck.context(
                    "immutable-root stream authenticated but its pre-delivery postcheck failed",
                );
                return Err(reject(parsed, error));
            }
            (Err(inspection), Err(postcheck)) => {
                return Err(combine_authenticated_stream_failures(
                    AuthenticatedStreamFailurePairV1::InspectionAndPreDeliveryPostcheck,
                    inspection,
                    postcheck,
                ));
            }
        };
        let outcome = deliver(byte_length, sha256, parsed);
        let delivery_postcheck = self.recheck();
        match (outcome, delivery_postcheck) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(postcheck)) => Err(postcheck).context(
                "authenticated immutable-root stream delivery completed but its postcheck failed",
            ),
            (Err(delivery), Err(postcheck)) => Err(combine_authenticated_stream_failures(
                AuthenticatedStreamFailurePairV1::DeliveryAndPostcheck,
                delivery,
                postcheck,
            )),
        }
    }

    #[cfg(target_os = "linux")]
    #[allow(
        clippy::too_many_arguments,
        reason = "the two authenticated replays keep their independent inspectors, hooks, and delivery roles explicit"
    )]
    fn with_authenticated_file_replay_streams_impl<
        const MAX_BYTES: u64,
        FirstInspection,
        RetainedFirst,
        ReplayInspection,
        T,
        ValidateFirst,
        FirstHook,
        InspectFirst,
        RetainFirst,
        BetweenReplays,
        ValidateReplay,
        ReplayHook,
        InspectReplay,
        Deliver,
    >(
        &self,
        request: AuthenticatedFileStreamRequestV1<'_>,
        validate_first_length: ValidateFirst,
        first_hook: FirstHook,
        inspect_first: InspectFirst,
        retain_first: RetainFirst,
        between_replays: BetweenReplays,
        validate_replay_length: ValidateReplay,
        replay_hook: ReplayHook,
        inspect_replay: InspectReplay,
        deliver: Deliver,
    ) -> Result<T>
    where
        ValidateFirst: FnOnce(u64) -> Result<()>,
        FirstHook: FnMut(ImmutableFileReadStage) -> Result<()>,
        InspectFirst: for<'reader> FnOnce(
            u64,
            [u8; 32],
            &'reader mut (dyn std::io::Read + 'reader),
        ) -> Result<FirstInspection>,
        RetainFirst: for<'inspection> FnOnce(
            u64,
            [u8; 32],
            &'inspection FirstInspection,
        ) -> Result<RetainedFirst>,
        BetweenReplays: FnOnce() -> Result<()>,
        ValidateReplay: FnOnce(u64) -> Result<()>,
        ReplayHook: FnMut(ImmutableFileReadStage) -> Result<()>,
        InspectReplay: for<'reader> FnOnce(
            u64,
            [u8; 32],
            &'reader mut (dyn std::io::Read + 'reader),
        ) -> Result<ReplayInspection>,
        Deliver: FnOnce(RetainedFirst, u64, [u8; 32], ReplayInspection) -> Result<T>,
    {
        self.with_authenticated_file_replay_streams_impl_with_rejection::<
            MAX_BYTES,
            FirstInspection,
            RetainedFirst,
            ReplayInspection,
            T,
            ValidateFirst,
            FirstHook,
            InspectFirst,
            RetainFirst,
            BetweenReplays,
            ValidateReplay,
            ReplayHook,
            InspectReplay,
            _,
            Deliver,
        >(
            request,
            validate_first_length,
            first_hook,
            inspect_first,
            retain_first,
            between_replays,
            validate_replay_length,
            replay_hook,
            inspect_replay,
            |_replay, error| error,
            deliver,
        )
    }

    #[cfg(target_os = "linux")]
    #[allow(
        clippy::too_many_arguments,
        reason = "the two authenticated replays keep rejection, inspectors, hooks, and delivery roles explicit"
    )]
    fn with_authenticated_file_replay_streams_impl_with_rejection<
        const MAX_BYTES: u64,
        FirstInspection,
        RetainedFirst,
        ReplayInspection,
        T,
        ValidateFirst,
        FirstHook,
        InspectFirst,
        RetainFirst,
        BetweenReplays,
        ValidateReplay,
        ReplayHook,
        InspectReplay,
        RejectReplay,
        Deliver,
    >(
        &self,
        request: AuthenticatedFileStreamRequestV1<'_>,
        validate_first_length: ValidateFirst,
        first_hook: FirstHook,
        inspect_first: InspectFirst,
        retain_first: RetainFirst,
        between_replays: BetweenReplays,
        validate_replay_length: ValidateReplay,
        replay_hook: ReplayHook,
        inspect_replay: InspectReplay,
        reject_replay: RejectReplay,
        deliver: Deliver,
    ) -> Result<T>
    where
        ValidateFirst: FnOnce(u64) -> Result<()>,
        FirstHook: FnMut(ImmutableFileReadStage) -> Result<()>,
        InspectFirst: for<'reader> FnOnce(
            u64,
            [u8; 32],
            &'reader mut (dyn std::io::Read + 'reader),
        ) -> Result<FirstInspection>,
        RetainFirst: for<'inspection> FnOnce(
            u64,
            [u8; 32],
            &'inspection FirstInspection,
        ) -> Result<RetainedFirst>,
        BetweenReplays: FnOnce() -> Result<()>,
        ValidateReplay: FnOnce(u64) -> Result<()>,
        ReplayHook: FnMut(ImmutableFileReadStage) -> Result<()>,
        InspectReplay: for<'reader> FnOnce(
            u64,
            [u8; 32],
            &'reader mut (dyn std::io::Read + 'reader),
        ) -> Result<ReplayInspection>,
        RejectReplay: FnOnce(ReplayInspection, anyhow::Error) -> anyhow::Error,
        Deliver: FnOnce(RetainedFirst, u64, [u8; 32], ReplayInspection) -> Result<T>,
    {
        let retained_first = self
            .with_authenticated_file_stream_impl::<MAX_BYTES, _, _, _, _, _, _>(
                request,
                validate_first_length,
                first_hook,
                inspect_first,
                move |byte_length, sha256, first| retain_first(byte_length, sha256, &first),
            )?;
        between_replays()?;
        self.recheck()?;
        self.with_authenticated_file_stream_impl_with_rejection::<MAX_BYTES, _, _, _, _, _, _, _>(
            request,
            validate_replay_length,
            replay_hook,
            inspect_replay,
            reject_replay,
            move |byte_length, sha256, replay| deliver(retained_first, byte_length, sha256, replay),
        )
    }

    /// Close the only legacy proof operation which needs two retained root
    /// descriptors without exposing either descriptor or a generic callback to
    /// the executor's sibling modules.
    #[cfg(all(target_os = "linux", feature = "b4-negative-materialization-handler"))]
    #[allow(
        clippy::too_many_arguments,
        reason = "the fixed operation retains every independently authenticated semantic authority"
    )]
    pub(super) fn close_negative_materialization_authority(
        &self,
        root_plan: NegativeMaterializationDescriptorRootPlanV1,
        configured_executor_artifact: &Path,
        campaign_precommit_identity: &B4ContractArtifactIdentityV1,
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV1,
        lineage: B4TerminalSourceLineageAuthorityV1,
        ancestry: &B4NegativeAncestryWitnessCatalogAuthorityV1,
        external: &B4NegativeMaterializationSetExternalInputsV1<'_>,
    ) -> Result<B4NegativeMaterializationSetAuthorityV1> {
        let (terminal_campaign_root_index, negative_ancestry_root_index) =
            root_plan.into_root_indices();
        let terminal = self
            .with_root_descriptor(terminal_campaign_root_index, |terminal_campaign_root| {
                authenticate_b4_terminal_evidence_import_from_directory_descriptor(
                    terminal_campaign_root,
                    configured_executor_artifact,
                    campaign_precommit_identity,
                    campaign,
                    positive,
                    lineage,
                )
            })
            .context("cannot authenticate the fixed terminal-campaign descriptor root")?;
        self.with_root_descriptor(negative_ancestry_root_index, |negative_ancestry_root| {
            B4NegativeMaterializationSetAuthorityV1::from_descriptor_rooted_cryptographic_closure(
                campaign,
                positive,
                ancestry,
                negative_ancestry_root,
                &terminal,
                external,
                |request| generate_fixed_alternate_root_proof_bundle(request.statement()),
            )
        })
        .context("cannot close the fixed negative-ancestry descriptor root")
    }

    /// Close the V2 proof operation which needs the fixed terminal and
    /// negative-ancestry descriptor roots without exposing either descriptor
    /// or a generic callback to executor sibling modules.
    #[cfg(all(target_os = "linux", feature = "b4-negative-materialization-handler"))]
    #[allow(
        clippy::too_many_arguments,
        reason = "the fixed V2 operation retains every independently authenticated semantic authority"
    )]
    pub(super) fn close_negative_materialization_authority_v2(
        &self,
        root_plan: NegativeMaterializationDescriptorRootPlanV2,
        configured_executor_artifact: &Path,
        campaign_precommit_identity: &B4ContractArtifactIdentityV1,
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV2,
        lineage: B4TerminalSourceLineageAuthorityV2,
        ancestry: &B4NegativeAncestryWitnessCatalogAuthorityV2,
        external: &B4NegativeMaterializationSetExternalInputsV1<'_>,
    ) -> Result<B4NegativeMaterializationSetAuthorityV2> {
        let (terminal_campaign_root_index, negative_ancestry_root_index) =
            root_plan.into_root_indices();
        let terminal = self
            .with_root_descriptor(terminal_campaign_root_index, |terminal_campaign_root| {
                authenticate_b4_terminal_evidence_import_from_directory_descriptor_v2(
                    terminal_campaign_root,
                    configured_executor_artifact,
                    campaign_precommit_identity,
                    campaign,
                    positive,
                    lineage,
                )
            })
            .context("cannot authenticate the fixed V2 terminal-campaign descriptor root")?;
        self.with_root_descriptor(negative_ancestry_root_index, |negative_ancestry_root| {
            B4NegativeMaterializationSetAuthorityV2::from_descriptor_rooted_cryptographic_closure_v2(
                campaign,
                positive,
                ancestry,
                negative_ancestry_root,
                &terminal,
                external,
                |request| generate_fixed_alternate_root_proof_bundle(request.statement()),
            )
        })
        .context("cannot close the fixed V2 negative-ancestry descriptor root")
    }

    /// Authenticate the V2 terminal packet under the one retained terminal root.
    ///
    /// This bounded sibling deliberately stops before negative ancestry. The
    /// returned opaque V2 import authority cannot enter the legacy V1 closure,
    /// and no raw descriptor crosses the custody boundary.
    #[cfg(all(target_os = "linux", feature = "b4-negative-materialization-handler"))]
    #[allow(
        clippy::too_many_arguments,
        reason = "the V2 terminal import retains every independently authenticated semantic authority"
    )]
    pub(super) fn close_terminal_import_authority_v2(
        &self,
        terminal_campaign_root_index: usize,
        configured_executor_artifact: &Path,
        campaign_precommit_identity: &B4ContractArtifactIdentityV1,
        campaign: &B4CampaignPrecommitAuthorityV1,
        positive: &B4PositiveGenerationAuthorityV2,
        lineage: B4TerminalSourceLineageAuthorityV2,
    ) -> Result<B4TerminalEvidenceImportAuthorityV2> {
        self.with_root_descriptor(terminal_campaign_root_index, |terminal_campaign_root| {
            authenticate_b4_terminal_evidence_import_from_directory_descriptor_v2(
                terminal_campaign_root,
                configured_executor_artifact,
                campaign_precommit_identity,
                campaign,
                positive,
                lineage,
            )
        })
        .context("cannot authenticate the fixed V2 terminal-campaign descriptor root")
    }

    /// Validate one retained B4 build-evidence root and return only its opaque
    /// authoritative projection after the complete immutable-root postcheck.
    ///
    /// The caller must supply all three external anchors. No raw descriptor or
    /// unanchored validation result crosses this fixed custody boundary.
    #[cfg(all(target_os = "linux", feature = "b4-authoritative-build-custody"))]
    pub(super) fn authenticate_authoritative_b4_build_projection(
        &self,
        root_index: usize,
        expectations: &B4BuildExpectations<'_>,
    ) -> Result<AuthoritativeB4BuildProjection> {
        anyhow::ensure!(
            expectations.expected_source_commit.is_some()
                && expectations.expected_source_tree.is_some()
                && expectations.expected_evidence_root.is_some(),
            "authoritative B4 build custody requires source commit, source tree, and evidence root anchors"
        );
        self.with_root_descriptor(root_index, |root| {
            let validation =
                validate_published_b4_build_from_directory_descriptor(root, expectations).context(
                    "retained B4 build-evidence root failed descriptor-rooted validation",
                )?;
            validation.authoritative_projection().cloned().context(
                "descriptor-rooted B4 build validation produced no authoritative projection",
            )
        })
    }

    /// Borrow one retained immutable-root descriptor only for one private,
    /// fixed custody implementation, with complete tree rechecks on both exits.
    #[cfg(target_os = "linux")]
    fn with_root_descriptor<T>(
        &self,
        root_index: usize,
        effect: impl for<'descriptor> FnOnce(BorrowedFd<'descriptor>) -> Result<T>,
    ) -> Result<T> {
        let root = self
            .roots
            .get(root_index)
            .context("immutable-root index is outside the fixed root set")?;
        self.recheck()?;
        let outcome = effect(root.descriptor());
        let postcheck = self.recheck();
        match (outcome, postcheck) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(postcheck)) => Err(postcheck)
                .context("immutable-root descriptor callback completed but its postcheck failed"),
            (Err(effect), Err(postcheck)) => Err(postcheck).context(format!(
                "immutable-root descriptor callback failed ({effect:#}) and its postcheck also failed"
            )),
        }
    }
}

#[allow(
    clippy::elidable_lifetime_names,
    reason = "the named context lifetime keeps the affine custody boundary explicit for source review"
)]
impl<'context, const ROOTS: usize>
    MutationCapability<'context, ROOTS, ProjectedPrepareInputSetCampaignLayout<ROOTS>>
{
    /// Authenticate the same projected OCI archive through two independent
    /// descriptor-rooted reads. The first delivery may retain only an owned,
    /// inert value; the final delivery receives it only after the replay has
    /// independently passed the same file, digest, and complete-root checks.
    #[allow(
        clippy::too_many_arguments,
        reason = "the fixed replay API keeps both inspectors and their distinct delivery roles explicit"
    )]
    pub(super) fn with_authenticated_oci_image_layout_ustar_replay_streams<
        FirstInspection,
        RetainedFirst,
        ReplayInspection,
        T,
    >(
        &mut self,
        _permit: OciOuterUstarCustodyPermitV1,
        root_index: usize,
        relative: &str,
        expected_byte_length: u64,
        inspect_first: impl for<'reader> FnOnce(
            u64,
            [u8; 32],
            &'reader mut (dyn std::io::Read + 'reader),
        ) -> Result<FirstInspection>,
        retain_first: impl for<'inspection> FnOnce(
            u64,
            [u8; 32],
            &'inspection FirstInspection,
        ) -> Result<RetainedFirst>,
        inspect_replay: impl for<'reader> FnOnce(
            u64,
            [u8; 32],
            &'reader mut (dyn std::io::Read + 'reader),
        ) -> Result<ReplayInspection>,
        reject_replay: impl FnOnce(ReplayInspection, anyhow::Error) -> anyhow::Error,
        deliver: impl FnOnce(RetainedFirst, u64, [u8; 32], ReplayInspection) -> Result<T>,
    ) -> Result<T> {
        let limits = B4ImmutableArtifactRoleV1::OciImageLayoutUstar.limits();
        let (minimum, maximum) = limits.encoded_byte_range();
        anyhow::ensure!(
            minimum == 6_144
                && maximum == OCI_OUTER_USTAR_MAX_BYTES
                && limits.encoded_byte_multiple() == Some(512),
            "OCI image-layout stream ceiling differs from its closed role contract"
        );
        limits.validate_encoded_length(expected_byte_length, "expected OCI image-layout ustar")?;
        #[cfg(target_os = "linux")]
        {
            let immutable_roots = self.immutable_roots();
            immutable_roots.validate_retained_oci_image_layout_ustar_length(
                root_index,
                relative,
                expected_byte_length,
            )?;
            immutable_roots.with_authenticated_file_replay_streams_impl_with_rejection::<
                OCI_OUTER_USTAR_MAX_BYTES,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
            >(
                AuthenticatedFileStreamRequestV1 {
                    role: AuthenticatedStreamRoleV1::OciImageLayoutUstar,
                    root_index,
                    relative,
                },
                move |byte_length| {
                    anyhow::ensure!(
                        byte_length == expected_byte_length,
                        "OCI image-layout retained length differs from the profile footprint"
                    );
                    limits.validate_encoded_length(byte_length, "OCI image-layout ustar")
                },
                |_stage| Ok(()),
                inspect_first,
                retain_first,
                || Ok(()),
                move |byte_length| {
                    anyhow::ensure!(
                        byte_length == expected_byte_length,
                        "OCI image-layout retained length differs from the profile footprint"
                    );
                    limits.validate_encoded_length(byte_length, "OCI image-layout ustar")
                },
                |_stage| Ok(()),
                inspect_replay,
                reject_replay,
                deliver,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (
                self,
                root_index,
                relative,
                expected_byte_length,
                inspect_first,
                retain_first,
                inspect_replay,
                reject_replay,
                deliver,
            );
            anyhow::bail!("qualifying B4 immutable-root file import requires Linux")
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    #[allow(
        clippy::too_many_arguments,
        reason = "the test hook preserves every production custody input and adds one injected stage callback"
    )]
    pub(super) fn with_authenticated_oci_image_layout_ustar_stream_test_hook<Inspection, T>(
        &mut self,
        _permit: OciOuterUstarCustodyPermitV1,
        root_index: usize,
        relative: &str,
        expected_byte_length: u64,
        hook: impl FnMut(ImmutableFileReadStage) -> Result<()>,
        inspect: impl for<'reader> FnOnce(
            u64,
            [u8; 32],
            &'reader mut (dyn std::io::Read + 'reader),
        ) -> Result<Inspection>,
        deliver: impl for<'inspection> FnOnce(u64, [u8; 32], &'inspection Inspection) -> Result<T>,
    ) -> Result<T> {
        let limits = B4ImmutableArtifactRoleV1::OciImageLayoutUstar.limits();
        let (minimum, maximum) = limits.encoded_byte_range();
        anyhow::ensure!(
            minimum == 6_144
                && maximum == OCI_OUTER_USTAR_MAX_BYTES
                && limits.encoded_byte_multiple() == Some(512),
            "OCI image-layout stream ceiling differs from its closed role contract"
        );
        limits.validate_encoded_length(expected_byte_length, "expected OCI image-layout ustar")?;
        let immutable_roots = self.immutable_roots();
        immutable_roots.validate_retained_oci_image_layout_ustar_length(
            root_index,
            relative,
            expected_byte_length,
        )?;
        immutable_roots
            .with_authenticated_file_stream_impl::<OCI_OUTER_USTAR_MAX_BYTES, _, _, _, _, _, _>(
                AuthenticatedFileStreamRequestV1 {
                    role: AuthenticatedStreamRoleV1::OciImageLayoutUstar,
                    root_index,
                    relative,
                },
                move |byte_length| {
                    anyhow::ensure!(
                        byte_length == expected_byte_length,
                        "OCI image-layout retained length differs from the profile footprint"
                    );
                    limits.validate_encoded_length(byte_length, "OCI image-layout ustar")
                },
                hook,
                inspect,
                move |byte_length, sha256, inspection| deliver(byte_length, sha256, &inspection),
            )
    }

    /// Inspect one AMD64 ELF only through its closed importer, exact
    /// prepare-input-set mutation capability, and consumed private permit.
    /// Successful inspection must consume the retained body and EOF; digest,
    /// descriptor, repin, and root postchecks finish before delivery.
    pub(super) fn with_authenticated_amd64_elf_stream<Inspection, T>(
        &mut self,
        _permit: Amd64ElfCustodyPermitV1,
        policy: Amd64ElfPolicyV1,
        root_index: usize,
        relative: &str,
        inspect: impl for<'reader> FnOnce(
            u64,
            [u8; 32],
            &'reader mut (dyn std::io::Read + 'reader),
        ) -> Result<Inspection>,
        deliver: impl for<'inspection> FnOnce(u64, [u8; 32], &'inspection Inspection) -> Result<T>,
    ) -> Result<T> {
        let limits = B4ImmutableArtifactRoleV1::Amd64Elf(policy).limits();
        let (minimum, maximum) = limits.encoded_byte_range();
        anyhow::ensure!(
            minimum == 64
                && maximum == AMD64_ELF_MAX_BYTES
                && limits.encoded_byte_multiple().is_none(),
            "AMD64 ELF custody ceiling differs from its closed role contract"
        );
        #[cfg(target_os = "linux")]
        {
            self.immutable_roots()
                .with_authenticated_file_stream_impl::<AMD64_ELF_MAX_BYTES, _, _, _, _, _, _>(
                    AuthenticatedFileStreamRequestV1 {
                        role: AuthenticatedStreamRoleV1::Generic,
                        root_index,
                        relative,
                    },
                    move |byte_length| limits.validate_encoded_length(byte_length, "AMD64 ELF"),
                    |_stage| Ok(()),
                    inspect,
                    move |byte_length, sha256, inspection| {
                        deliver(byte_length, sha256, &inspection)
                    },
                )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, root_index, relative, inspect, deliver);
            anyhow::bail!("qualifying B4 immutable-root file import requires Linux")
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    #[allow(
        clippy::too_many_arguments,
        reason = "the test hook preserves every production custody input and adds one injected stage callback"
    )]
    pub(super) fn with_authenticated_amd64_elf_stream_test_hook<Inspection, T>(
        &mut self,
        _permit: Amd64ElfCustodyPermitV1,
        policy: Amd64ElfPolicyV1,
        root_index: usize,
        relative: &str,
        hook: impl FnMut(ImmutableFileReadStage) -> Result<()>,
        inspect: impl for<'reader> FnOnce(
            u64,
            [u8; 32],
            &'reader mut (dyn std::io::Read + 'reader),
        ) -> Result<Inspection>,
        deliver: impl for<'inspection> FnOnce(u64, [u8; 32], &'inspection Inspection) -> Result<T>,
    ) -> Result<T> {
        let limits = B4ImmutableArtifactRoleV1::Amd64Elf(policy).limits();
        let (minimum, maximum) = limits.encoded_byte_range();
        anyhow::ensure!(
            minimum == 64
                && maximum == AMD64_ELF_MAX_BYTES
                && limits.encoded_byte_multiple().is_none(),
            "AMD64 ELF custody ceiling differs from its closed role contract"
        );
        self.immutable_roots()
            .with_authenticated_file_stream_impl::<AMD64_ELF_MAX_BYTES, _, _, _, _, _, _>(
                AuthenticatedFileStreamRequestV1 {
                    role: AuthenticatedStreamRoleV1::Generic,
                    root_index,
                    relative,
                },
                move |byte_length| limits.validate_encoded_length(byte_length, "AMD64 ELF"),
                hook,
                inspect,
                move |byte_length, sha256, inspection| deliver(byte_length, sha256, &inspection),
            )
    }

    /// Lend one reviewed Git bundle as a forward-only stream only through the
    /// exact prepare-input-set mutation capability and the unforgeable permit
    /// consumed by the closed Git import route. A successful callback must
    /// consume exact EOF; digest, descriptor, repin, and root postchecks all
    /// complete before its result can leave this method.
    pub(super) fn with_authenticated_reviewed_git_bundle_stream<Parsed, T>(
        &mut self,
        _permit: ReviewedGitBundleCustodyPermitV1,
        root_index: usize,
        relative: &str,
        inspect: impl for<'reader> FnOnce(
            u64,
            [u8; 32],
            &'reader mut (dyn std::io::Read + 'reader),
        ) -> Result<Parsed>,
        deliver: impl for<'parsed> FnOnce(u64, [u8; 32], &'parsed Parsed) -> Result<T>,
    ) -> Result<T> {
        let limits = B4ImmutableArtifactRoleV1::ReviewedGitBundle.limits();
        let (minimum, maximum) = limits.encoded_byte_range();
        anyhow::ensure!(
            minimum == 1 && maximum == REVIEWED_GIT_BUNDLE_MAX_BYTES,
            "reviewed Git bundle custody ceiling differs from its closed role contract"
        );
        #[cfg(target_os = "linux")]
        {
            self.immutable_roots()
                .with_authenticated_file_stream_impl::<
                    REVIEWED_GIT_BUNDLE_MAX_BYTES,
                    _,
                    _,
                    _,
                    _,
                    _,
                    _,
                >(
                    AuthenticatedFileStreamRequestV1 {
                        role: AuthenticatedStreamRoleV1::Generic,
                        root_index,
                        relative,
                    },
                    move |byte_length| {
                        limits.validate_encoded_length(byte_length, "reviewed Git bundle")
                    },
                    |_stage| Ok(()),
                    inspect,
                    move |byte_length, sha256, parsed| deliver(byte_length, sha256, &parsed),
                )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, root_index, relative, inspect, deliver);
            anyhow::bail!("qualifying B4 immutable-root file import requires Linux")
        }
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn with_authenticated_reviewed_git_bundle_stream_test_hook<Parsed, T>(
        &mut self,
        _permit: ReviewedGitBundleCustodyPermitV1,
        root_index: usize,
        relative: &str,
        hook: impl FnMut(ImmutableFileReadStage) -> Result<()>,
        inspect: impl for<'reader> FnOnce(
            u64,
            [u8; 32],
            &'reader mut (dyn std::io::Read + 'reader),
        ) -> Result<Parsed>,
        deliver: impl for<'parsed> FnOnce(u64, [u8; 32], &'parsed Parsed) -> Result<T>,
    ) -> Result<T> {
        let limits = B4ImmutableArtifactRoleV1::ReviewedGitBundle.limits();
        let (minimum, maximum) = limits.encoded_byte_range();
        anyhow::ensure!(
            minimum == 1 && maximum == REVIEWED_GIT_BUNDLE_MAX_BYTES,
            "reviewed Git bundle custody ceiling differs from its closed role contract"
        );
        self.immutable_roots()
            .with_authenticated_file_stream_impl::<REVIEWED_GIT_BUNDLE_MAX_BYTES, _, _, _, _, _, _>(
                AuthenticatedFileStreamRequestV1 {
                    role: AuthenticatedStreamRoleV1::Generic,
                    root_index,
                    relative,
                },
                move |byte_length| {
                    limits.validate_encoded_length(byte_length, "reviewed Git bundle")
                },
                hook,
                inspect,
                move |byte_length, sha256, parsed| deliver(byte_length, sha256, &parsed),
            )
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        collections::{BTreeMap, BTreeSet},
        ffi::{CString, OsString},
        fmt,
        fs::File,
        io::{self, Read, Seek as _, SeekFrom},
        os::{
            fd::{AsFd as _, BorrowedFd, OwnedFd},
            unix::ffi::OsStrExt as _,
        },
        path::{Component, Path, PathBuf},
    };

    use anyhow::{Context as _, Result, ensure};
    use sha2::{Digest as _, Sha256};

    use super::{
        AuthenticatedStreamFailurePairV1, AuthenticatedStreamRoleV1, B4ImmutableArtifactRoleV1,
        ImmutableFileReadStage, MAX_BUFFERED_IMMUTABLE_FILE_BYTES,
        MAX_PROJECTED_OCI_IMAGE_LAYOUT_CAPTURE_SLOTS, OCI_OUTER_USTAR_MAX_BYTES,
        ProjectedOciImageLayoutCaptureSlotV1, combine_authenticated_stream_failures,
    };

    const DIRECTORY_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY
        .union(rustix::fs::OFlags::DIRECTORY)
        .union(rustix::fs::OFlags::NOFOLLOW)
        .union(rustix::fs::OFlags::CLOEXEC);
    const PATH_FILE_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::PATH
        .union(rustix::fs::OFlags::NOFOLLOW)
        .union(rustix::fs::OFlags::CLOEXEC);
    const FILE_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY
        .union(rustix::fs::OFlags::NOFOLLOW)
        .union(rustix::fs::OFlags::NONBLOCK)
        .union(rustix::fs::OFlags::CLOEXEC);
    const PATH_COMPONENT_RESOLVE_FLAGS: rustix::fs::ResolveFlags =
        rustix::fs::ResolveFlags::BENEATH
            .union(rustix::fs::ResolveFlags::NO_SYMLINKS)
            .union(rustix::fs::ResolveFlags::NO_MAGICLINKS);
    const TREE_ENTRY_RESOLVE_FLAGS: rustix::fs::ResolveFlags =
        PATH_COMPONENT_RESOLVE_FLAGS.union(rustix::fs::ResolveFlags::NO_XDEV);
    const MAX_IMMUTABLE_ROOTS: usize = 16;
    const MAX_IMMUTABLE_ROOT_ENTRIES: u64 = 4096;
    const MAX_IMMUTABLE_ROOT_BYTES: u64 = 1024 * 1024 * 1024;
    const MAX_IMMUTABLE_SNAPSHOT_FILE_BYTES: u64 = MAX_IMMUTABLE_ROOT_BYTES;
    const MAX_IMMUTABLE_ROOT_DEPTH: usize = 64;
    const MAX_ABSOLUTE_PATH_BYTES: usize = 4096;
    const MAX_ABSOLUTE_PATH_COMPONENTS: usize = 64;

    fn validate_buffered_file_ceiling(maximum: u64) -> Result<()> {
        ensure!(
            maximum <= u64::try_from(MAX_BUFFERED_IMMUTABLE_FILE_BYTES)?,
            "immutable-root read exceeds the compiled per-file bound"
        );
        Ok(())
    }

    fn validate_stream_file_ceiling(maximum: u64) -> Result<()> {
        ensure!(
            maximum <= MAX_IMMUTABLE_SNAPSHOT_FILE_BYTES,
            "immutable-root stream exceeds the compiled snapshot-file bound"
        );
        Ok(())
    }

    fn validate_authenticated_stream_role_ceiling(
        role: AuthenticatedStreamRoleV1,
        maximum: u64,
    ) -> Result<()> {
        match role {
            AuthenticatedStreamRoleV1::Generic => validate_stream_file_ceiling(maximum),
            AuthenticatedStreamRoleV1::OciImageLayoutUstar => {
                let limits = B4ImmutableArtifactRoleV1::OciImageLayoutUstar.limits();
                let (minimum, role_maximum) = limits.encoded_byte_range();
                ensure!(
                    minimum == 6_144
                        && role_maximum == OCI_OUTER_USTAR_MAX_BYTES
                        && maximum == role_maximum
                        && limits.encoded_byte_multiple() == Some(512),
                    "OCI image-layout stream ceiling differs from its closed role contract"
                );
                Ok(())
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
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
    enum SnapshotFileRoleV1 {
        Generic,
        OciImageLayoutUstar,
    }

    impl SnapshotFileRoleV1 {
        const fn digest_tag(self) -> &'static [u8] {
            match self {
                Self::Generic => b"G",
                Self::OciImageLayoutUstar => b"O",
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct StableFileSnapshot {
        role: SnapshotFileRoleV1,
        metadata: FileMetadata,
        sha256: [u8; 32],
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct DirectoryMetadata {
        identity: PhysicalIdentity,
        mount_id: u64,
        mode: u32,
        modified_seconds: i64,
        modified_nanoseconds: u64,
        changed_seconds: i64,
        changed_nanoseconds: u64,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ImmutableTreeSnapshot {
        entry_count: u64,
        generic_byte_length: u64,
        oci_image_layout_byte_length: u64,
        sha256: [u8; 32],
        directory_identities: Vec<PhysicalIdentity>,
        files: BTreeMap<Vec<u8>, StableFileSnapshot>,
    }

    pub(super) struct PinnedCampaignRoot {
        path: PinnedAbsoluteDirectory,
    }

    impl PinnedCampaignRoot {
        pub(super) fn capture(path: &Path) -> Result<Self> {
            let pinned = PinnedAbsoluteDirectory::open(path, "campaign root")?;
            ensure!(
                !pinned.components.is_empty(),
                "campaign root must not be the filesystem root"
            );
            pinned.reauthenticate()?;
            Ok(Self { path: pinned })
        }

        pub(super) fn recheck(&self) -> Result<()> {
            self.path.reauthenticate()
        }

        fn require_pinned_descendant(&self, descendant: &PinnedAbsoluteDirectory) -> Result<()> {
            self.path.require_prefix_of(descendant, "immutable root")
        }

        pub(super) fn require_external_descendant(
            &self,
            path: &Path,
            component_identities: &[(u64, u64, u64)],
        ) -> Result<()> {
            validate_absolute_lexical_path(path, "publication parent", true)?;
            ensure!(
                path == self.path.diagnostic_path || path.starts_with(&self.path.diagnostic_path),
                "publication parent is not derived from the retained campaign root"
            );
            ensure!(
                component_identities.len() >= self.path.components.len(),
                "publication parent chain is shorter than the retained campaign root"
            );
            for (index, ((identity, mount_id), observed)) in self
                .path
                .identities
                .iter()
                .zip(&self.path.mount_ids)
                .zip(component_identities)
                .enumerate()
            {
                ensure!(
                    (identity.device, identity.inode, *mount_id) == *observed,
                    "publication parent component {index} is outside retained campaign custody"
                );
            }
            let campaign_mount_id = self.path.final_mount_id();
            for (index, (_, _, mount_id)) in component_identities
                .iter()
                .enumerate()
                .skip(self.path.components.len())
            {
                ensure!(
                    *mount_id == campaign_mount_id,
                    "publication parent suffix component {index} crosses the retained campaign mount"
                );
            }
            Ok(())
        }
    }

    pub(super) struct PinnedImmutableRoot {
        path: PinnedAbsoluteDirectory,
        oci_image_layout_paths: BTreeSet<Vec<u8>>,
        snapshot: ImmutableTreeSnapshot,
    }

    impl PinnedImmutableRoot {
        fn capture(
            campaign_root: &PinnedCampaignRoot,
            path: &Path,
            oci_image_layout_paths: BTreeSet<Vec<u8>>,
        ) -> Result<Self> {
            let pinned = PinnedAbsoluteDirectory::open(path, "immutable root")?;
            campaign_root.require_pinned_descendant(&pinned)?;
            ensure!(
                !pinned.components.is_empty(),
                "immutable root must not be the filesystem root"
            );
            let first = snapshot_immutable_tree_with_oci_paths(
                pinned.descriptor(),
                path,
                &oci_image_layout_paths,
            )
            .with_context(|| format!("cannot snapshot immutable root {}", path.display()))?;
            let second = snapshot_immutable_tree_with_oci_paths(
                pinned.descriptor(),
                path,
                &oci_image_layout_paths,
            )
            .with_context(|| format!("cannot repeat immutable root {}", path.display()))?;
            ensure!(
                first == second,
                "immutable root changed between entry snapshots: {}",
                path.display()
            );
            pinned.reauthenticate()?;
            Ok(Self {
                path: pinned,
                oci_image_layout_paths,
                snapshot: second,
            })
        }

        pub(super) fn descriptor(&self) -> BorrowedFd<'_> {
            self.path.descriptor()
        }
    }

    pub(super) fn capture_immutable_roots<const ROOTS: usize>(
        campaign_root: &PinnedCampaignRoot,
        paths: [&Path; ROOTS],
    ) -> Result<[PinnedImmutableRoot; ROOTS]> {
        capture_immutable_roots_with_projected_oci(campaign_root, paths, Vec::new())
    }

    pub(super) fn capture_immutable_roots_with_projected_oci<const ROOTS: usize>(
        campaign_root: &PinnedCampaignRoot,
        paths: [&Path; ROOTS],
        slots: Vec<ProjectedOciImageLayoutCaptureSlotV1>,
    ) -> Result<[PinnedImmutableRoot; ROOTS]> {
        ensure!(ROOTS > 0, "immutable-root custody cannot be empty");
        ensure!(
            ROOTS <= MAX_IMMUTABLE_ROOTS,
            "immutable-root custody exceeds the compiled root-count bound"
        );
        for (index, path) in paths.iter().enumerate() {
            validate_absolute_lexical_path(path, "immutable root", false)?;
            for other in paths.iter().skip(index + 1) {
                ensure!(
                    !component_paths_conflict(path, other),
                    "immutable root paths conflict: {} and {}",
                    path.display(),
                    other.display()
                );
            }
        }

        ensure!(
            slots.len() <= MAX_PROJECTED_OCI_IMAGE_LAYOUT_CAPTURE_SLOTS,
            "projected OCI image-layout custody exceeds the closed slot-count bound"
        );
        let mut oci_paths_by_root: [BTreeSet<Vec<u8>>; ROOTS] =
            std::array::from_fn(|_| BTreeSet::new());
        for slot in slots {
            let root_index = slot.root_index();
            let relative = slot.relative_path();
            validate_projected_oci_relative_file_path(relative)?;
            let root_paths = oci_paths_by_root
                .get_mut(root_index)
                .context("projected OCI root index is outside immutable-root custody")?;
            for retained in root_paths.iter() {
                ensure!(
                    !relative_component_paths_conflict(retained, relative.as_bytes()),
                    "projected OCI image-layout paths conflict within one immutable root"
                );
            }
            let mut retained = Vec::new();
            retained
                .try_reserve_exact(relative.len())
                .context("cannot retain projected OCI image-layout path")?;
            retained.extend_from_slice(relative.as_bytes());
            ensure!(
                root_paths.insert(retained),
                "projected OCI image-layout path appeared twice"
            );
        }

        let mut captured = Vec::new();
        captured
            .try_reserve_exact(ROOTS)
            .context("cannot retain the fixed immutable-root set")?;
        for (path, oci_image_layout_paths) in paths.into_iter().zip(oci_paths_by_root) {
            captured.push(PinnedImmutableRoot::capture(
                campaign_root,
                path,
                oci_image_layout_paths,
            )?);
        }
        for (index, root) in captured.iter().enumerate() {
            for other in captured.iter().skip(index + 1) {
                ensure!(
                    !root
                        .snapshot
                        .directory_identities
                        .iter()
                        .any(|identity| { other.snapshot.directory_identities.contains(identity) }),
                    "immutable root physical identities conflict"
                );
            }
        }
        let roots = captured
            .try_into()
            .map_err(|_| anyhow::Error::msg("immutable-root cardinality changed internally"))?;
        recheck_immutable_roots(&roots)?;
        Ok(roots)
    }

    pub(super) fn recheck_immutable_roots<const ROOTS: usize>(
        roots: &[PinnedImmutableRoot; ROOTS],
    ) -> Result<()> {
        for root in roots {
            root.path.reauthenticate().with_context(|| {
                format!(
                    "immutable root no longer names retained custody: {}",
                    root.path.diagnostic_path.display()
                )
            })?;
        }
        let mut first_pass = Vec::new();
        first_pass
            .try_reserve_exact(ROOTS)
            .context("cannot retain immutable-root first-pass observations")?;
        for root in roots {
            first_pass.push(
                snapshot_immutable_tree_with_oci_paths(
                    root.path.descriptor(),
                    &root.path.diagnostic_path,
                    &root.oci_image_layout_paths,
                )
                .with_context(|| {
                    format!(
                        "cannot recheck immutable root {}",
                        root.path.diagnostic_path.display()
                    )
                })?,
            );
        }
        for (root, first) in roots.iter().zip(first_pass) {
            let second = snapshot_immutable_tree_with_oci_paths(
                root.path.descriptor(),
                &root.path.diagnostic_path,
                &root.oci_image_layout_paths,
            )
            .with_context(|| {
                format!(
                    "cannot repeat immutable root recheck {}",
                    root.path.diagnostic_path.display()
                )
            })?;
            ensure!(
                first == second && second == root.snapshot,
                "immutable root bytes or identities changed: {}",
                root.path.diagnostic_path.display()
            );
        }
        for root in roots {
            root.path.reauthenticate().with_context(|| {
                format!(
                    "immutable root no longer names retained custody: {}",
                    root.path.diagnostic_path.display()
                )
            })?;
        }
        Ok(())
    }

    pub(super) fn reject_physical_directory_aliases<const ROOTS: usize>(
        roots: &[PinnedImmutableRoot; ROOTS],
        candidates: &[(u64, u64, u64)],
    ) -> Result<()> {
        for (device, inode, _mount_id) in candidates {
            ensure!(
                !roots.iter().any(|root| {
                    root.snapshot
                        .directory_identities
                        .iter()
                        .any(|identity| identity.device == *device && identity.inode == *inode)
                }),
                "publication parent physically aliases immutable-root custody"
            );
        }
        Ok(())
    }

    pub(super) fn read_immutable_root_file<const MAX_BYTES: usize>(
        root: &PinnedImmutableRoot,
        relative: &str,
    ) -> Result<Vec<u8>> {
        read_immutable_root_file_with_hook::<MAX_BYTES, _, _>(
            root,
            relative,
            |_byte_length| Ok(()),
            |_stage| Ok(()),
        )
    }

    pub(super) fn read_immutable_root_file_with_hook<const MAX_BYTES: usize, Validate, Hook>(
        root: &PinnedImmutableRoot,
        relative: &str,
        validate_length: Validate,
        mut hook: Hook,
    ) -> Result<Vec<u8>>
    where
        Validate: FnOnce(u64) -> Result<()>,
        Hook: FnMut(ImmutableFileReadStage) -> Result<()>,
    {
        validate_buffered_file_ceiling(u64::try_from(MAX_BYTES)?)?;
        validate_portable_relative_file_path(relative)?;
        let expected = root
            .snapshot
            .files
            .get(relative.as_bytes())
            .context("immutable-root file is absent from the retained snapshot")?;
        ensure!(
            expected.role == SnapshotFileRoleV1::Generic,
            "projected OCI image-layout file requires its closed role-specific importer"
        );
        validate_length(expected.metadata.byte_length)?;
        ensure!(
            expected.metadata.byte_length <= u64::try_from(MAX_BYTES)?,
            "immutable-root file exceeds its caller-supplied bound"
        );
        let path_descriptor = rustix::fs::openat2(
            root.path.descriptor(),
            Path::new(relative),
            PATH_FILE_FLAGS,
            rustix::fs::Mode::empty(),
            TREE_ENTRY_RESOLVE_FLAGS,
        )
        .context("cannot pin immutable-root file relative to retained custody")?;
        ensure!(
            descriptor_file_metadata(path_descriptor.as_fd())? == expected.metadata,
            "immutable-root file differs from its retained identity before reading"
        );
        hook(ImmutableFileReadStage::PathPinned)?;
        let data_descriptor = rustix::fs::openat2(
            root.path.descriptor(),
            Path::new(relative),
            FILE_FLAGS,
            rustix::fs::Mode::empty(),
            TREE_ENTRY_RESOLVE_FLAGS,
        )
        .context("cannot open immutable-root file relative to retained custody")?;
        let mut file = File::from(data_descriptor);
        ensure!(
            opened_file_metadata(&file)? == expected.metadata,
            "immutable-root file changed while opening its data descriptor"
        );
        hook(ImmutableFileReadStage::DataOpened)?;
        let (observed, bytes) =
            read_open_file_bytes(&mut file, relative, u64::try_from(MAX_BYTES)?)?;
        ensure!(
            observed == *expected
                && descriptor_file_metadata(path_descriptor.as_fd())? == expected.metadata,
            "immutable-root file no longer matches its retained snapshot"
        );
        hook(ImmutableFileReadStage::BytesRead)?;
        let repinned = rustix::fs::openat2(
            root.path.descriptor(),
            Path::new(relative),
            PATH_FILE_FLAGS,
            rustix::fs::Mode::empty(),
            TREE_ENTRY_RESOLVE_FLAGS,
        )
        .context("cannot repin immutable-root file relative to retained custody")?;
        ensure!(
            descriptor_file_metadata(repinned.as_fd())? == expected.metadata,
            "named immutable-root file no longer identifies retained custody"
        );
        hook(ImmutableFileReadStage::FileRepinned)?;
        Ok(bytes)
    }

    #[derive(Clone, Debug)]
    struct StreamingReadFailure {
        kind: io::ErrorKind,
        detail: String,
    }

    impl fmt::Display for StreamingReadFailure {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(&self.detail)
        }
    }

    impl std::error::Error for StreamingReadFailure {}

    struct AuthenticatedStreamingReader<'file> {
        file: &'file mut File,
        diagnostic: String,
        expected: StableFileSnapshot,
        observed_byte_length: u64,
        hasher: Sha256,
        eof_observed: bool,
        sticky_failure: Option<StreamingReadFailure>,
    }

    impl AuthenticatedStreamingReader<'_> {
        fn sticky_error(&mut self, kind: io::ErrorKind, detail: impl Into<String>) -> io::Error {
            if self.sticky_failure.is_none() {
                self.sticky_failure = Some(StreamingReadFailure {
                    kind,
                    detail: detail.into(),
                });
            }
            let Some(failure) = self.sticky_failure.as_ref() else {
                return io::Error::new(kind, "authenticated immutable-root stream failed");
            };
            io::Error::new(failure.kind, failure.clone())
        }

        fn finish(&mut self) -> Result<()> {
            ensure!(
                self.sticky_failure.is_none(),
                "authenticated immutable-root stream {} retained a read failure: {}",
                self.diagnostic,
                self.sticky_failure
                    .as_ref()
                    .map_or("unknown failure", |failure| failure.detail.as_str())
            );
            ensure!(
                self.observed_byte_length == self.expected.metadata.byte_length,
                "authenticated immutable-root stream {} was not consumed to its retained length",
                self.diagnostic
            );
            if !self.eof_observed {
                let mut probe = [0_u8; 1];
                let count = self
                    .read(&mut probe)
                    .with_context(|| format!("cannot prove exact EOF for {}", self.diagnostic))?;
                ensure!(
                    count == 0,
                    "authenticated immutable-root EOF probe was not exact"
                );
            }
            let observed_sha256: [u8; 32] = self.hasher.clone().finalize().into();
            ensure!(
                observed_sha256 == self.expected.sha256,
                "authenticated immutable-root stream {} digest differs from retained custody",
                self.diagnostic
            );
            Ok(())
        }
    }

    impl Read for AuthenticatedStreamingReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if let Some(failure) = self.sticky_failure.clone() {
                return Err(io::Error::new(failure.kind, failure));
            }
            if buffer.is_empty() {
                return Ok(0);
            }
            let remaining = self
                .expected
                .metadata
                .byte_length
                .checked_sub(self.observed_byte_length)
                .ok_or_else(|| {
                    self.sticky_error(
                        io::ErrorKind::InvalidData,
                        "authenticated stream length underflowed",
                    )
                })?;
            if remaining == 0 {
                let mut probe = [0_u8; 1];
                return match self.file.read(&mut probe) {
                    Ok(0) => {
                        self.eof_observed = true;
                        Ok(0)
                    }
                    Ok(_) => Err(self.sticky_error(
                        io::ErrorKind::InvalidData,
                        format!(
                            "authenticated immutable-root stream {} grew beyond its retained length",
                            self.diagnostic
                        ),
                    )),
                    Err(error) => Err(self.sticky_error(
                        error.kind(),
                        format!(
                            "cannot probe authenticated immutable-root stream {} EOF: {error}",
                            self.diagnostic
                        ),
                    )),
                };
            }

            let buffer_length = u64::try_from(buffer.len()).map_err(|_| {
                self.sticky_error(
                    io::ErrorKind::InvalidData,
                    "authenticated stream buffer length does not fit u64",
                )
            })?;
            let request = usize::try_from(remaining.min(buffer_length)).map_err(|_| {
                self.sticky_error(
                    io::ErrorKind::InvalidData,
                    "authenticated stream request does not fit memory addressing",
                )
            })?;
            match self.file.read(&mut buffer[..request]) {
                Ok(0) => Err(self.sticky_error(
                    io::ErrorKind::UnexpectedEof,
                    format!(
                        "authenticated immutable-root stream {} ended before its retained length",
                        self.diagnostic
                    ),
                )),
                Ok(count) => {
                    let observed = self
                        .observed_byte_length
                        .checked_add(u64::try_from(count).map_err(|_| {
                            self.sticky_error(
                                io::ErrorKind::InvalidData,
                                "authenticated stream read count does not fit u64",
                            )
                        })?)
                        .ok_or_else(|| {
                            self.sticky_error(
                                io::ErrorKind::InvalidData,
                                "authenticated stream byte count overflowed",
                            )
                        })?;
                    if observed > self.expected.metadata.byte_length {
                        return Err(self.sticky_error(
                            io::ErrorKind::InvalidData,
                            format!(
                                "authenticated immutable-root stream {} exceeded its retained length",
                                self.diagnostic
                            ),
                        ));
                    }
                    self.observed_byte_length = observed;
                    self.hasher.update(&buffer[..count]);
                    Ok(count)
                }
                Err(error) => Err(self.sticky_error(
                    error.kind(),
                    format!(
                        "cannot read authenticated immutable-root stream {}: {error}",
                        self.diagnostic
                    ),
                )),
            }
        }
    }

    fn finish_authenticated_stream_file_inspection<T>(
        outcome: Result<T>,
        file_postcheck: Result<()>,
    ) -> Result<T> {
        match (outcome, file_postcheck) {
            (Ok(authenticated), Ok(())) => Ok(authenticated),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(postcheck)) => Err(postcheck).context(
                "immutable-root stream inspection completed but its file postcheck failed",
            ),
            (Err(inspection), Err(postcheck)) => Err(combine_authenticated_stream_failures(
                AuthenticatedStreamFailurePairV1::InspectionAndFilePostcheck,
                inspection,
                postcheck,
            )),
        }
    }

    struct OpenedAuthenticatedStreamFileV1 {
        expected: StableFileSnapshot,
        path_descriptor: OwnedFd,
        file: File,
    }

    pub(super) fn validate_retained_oci_image_layout_ustar_length(
        root: &PinnedImmutableRoot,
        relative: &str,
        expected_byte_length: u64,
    ) -> Result<()> {
        let retained = *root
            .snapshot
            .files
            .get(relative.as_bytes())
            .context("immutable-root file is absent from the retained snapshot")?;
        ensure!(
            retained.role == SnapshotFileRoleV1::OciImageLayoutUstar,
            "OCI image-layout importer role differs from its retained capture plan"
        );
        ensure!(
            retained.metadata.byte_length == expected_byte_length,
            "OCI image-layout retained length differs from the profile footprint"
        );
        Ok(())
    }

    fn open_authenticated_immutable_root_file_stream<const MAX_BYTES: u64, Validate, Hook>(
        root: &PinnedImmutableRoot,
        role: AuthenticatedStreamRoleV1,
        relative: &str,
        validate_length: Validate,
        hook: &mut Hook,
    ) -> Result<OpenedAuthenticatedStreamFileV1>
    where
        Validate: FnOnce(u64) -> Result<()>,
        Hook: FnMut(ImmutableFileReadStage) -> Result<()>,
    {
        validate_authenticated_stream_role_ceiling(role, MAX_BYTES)?;
        let expected = *root
            .snapshot
            .files
            .get(relative.as_bytes())
            .context("immutable-root file is absent from the retained snapshot")?;
        match role {
            AuthenticatedStreamRoleV1::Generic => ensure!(
                expected.role == SnapshotFileRoleV1::Generic,
                "projected OCI image-layout stream requires its closed role-specific importer"
            ),
            AuthenticatedStreamRoleV1::OciImageLayoutUstar => ensure!(
                expected.role == SnapshotFileRoleV1::OciImageLayoutUstar,
                "OCI image-layout importer role differs from its retained capture plan"
            ),
        }
        validate_length(expected.metadata.byte_length)?;
        ensure!(
            expected.metadata.byte_length <= MAX_BYTES,
            "immutable-root file exceeds its caller-supplied stream bound"
        );
        match role {
            AuthenticatedStreamRoleV1::Generic => validate_portable_relative_file_path(relative)?,
            AuthenticatedStreamRoleV1::OciImageLayoutUstar => {
                validate_projected_oci_relative_file_path(relative)?;
            }
        }
        let path_descriptor = rustix::fs::openat2(
            root.path.descriptor(),
            Path::new(relative),
            PATH_FILE_FLAGS,
            rustix::fs::Mode::empty(),
            TREE_ENTRY_RESOLVE_FLAGS,
        )
        .context("cannot pin immutable-root stream relative to retained custody")?;
        ensure!(
            descriptor_file_metadata(path_descriptor.as_fd())? == expected.metadata,
            "immutable-root stream differs from its retained identity before reading"
        );
        hook(ImmutableFileReadStage::PathPinned)?;
        let data_descriptor = rustix::fs::openat2(
            root.path.descriptor(),
            Path::new(relative),
            FILE_FLAGS,
            rustix::fs::Mode::empty(),
            TREE_ENTRY_RESOLVE_FLAGS,
        )
        .context("cannot open immutable-root stream relative to retained custody")?;
        let file = File::from(data_descriptor);
        ensure!(
            opened_file_metadata(&file)? == expected.metadata,
            "immutable-root stream changed while opening its data descriptor"
        );
        hook(ImmutableFileReadStage::DataOpened)?;
        Ok(OpenedAuthenticatedStreamFileV1 {
            expected,
            path_descriptor,
            file,
        })
    }

    pub(super) fn inspect_authenticated_immutable_root_file_stream<
        const MAX_BYTES: u64,
        Parsed,
        Validate,
        Hook,
        Inspect,
    >(
        root: &PinnedImmutableRoot,
        role: AuthenticatedStreamRoleV1,
        relative: &str,
        validate_length: Validate,
        mut hook: Hook,
        inspect: Inspect,
    ) -> Result<(u64, [u8; 32], Parsed)>
    where
        Validate: FnOnce(u64) -> Result<()>,
        Hook: FnMut(ImmutableFileReadStage) -> Result<()>,
        Inspect:
            for<'reader> FnOnce(u64, [u8; 32], &'reader mut (dyn Read + 'reader)) -> Result<Parsed>,
    {
        let OpenedAuthenticatedStreamFileV1 {
            expected,
            path_descriptor,
            mut file,
        } = open_authenticated_immutable_root_file_stream::<MAX_BYTES, _, _>(
            root,
            role,
            relative,
            validate_length,
            &mut hook,
        )?;
        file.seek(SeekFrom::Start(0))
            .with_context(|| format!("cannot seek immutable-root stream {relative}"))?;
        let mut reader = AuthenticatedStreamingReader {
            file: &mut file,
            diagnostic: relative.to_owned(),
            expected,
            observed_byte_length: 0,
            hasher: Sha256::new(),
            eof_observed: false,
            sticky_failure: None,
        };
        let byte_length = expected.metadata.byte_length;
        let sha256 = expected.sha256;
        let inspection = inspect(byte_length, sha256, &mut reader);
        let outcome = match inspection {
            Ok(parsed) => (|| {
                reader.finish()?;
                hook(ImmutableFileReadStage::BytesRead)?;
                Ok((byte_length, sha256, parsed))
            })(),
            Err(inspection) => match reader.sticky_failure.clone() {
                Some(read_failure) => Err(combine_authenticated_stream_failures(
                    AuthenticatedStreamFailurePairV1::InspectionAndRead,
                    inspection,
                    anyhow::Error::new(read_failure),
                )),
                None => Err(inspection),
            },
        };
        drop(reader);
        let file_postcheck = (|| {
            ensure!(
                opened_file_metadata(&file)? == expected.metadata
                    && descriptor_file_metadata(path_descriptor.as_fd())? == expected.metadata,
                "immutable-root stream no longer matches its retained snapshot"
            );
            let repinned = rustix::fs::openat2(
                root.path.descriptor(),
                Path::new(relative),
                PATH_FILE_FLAGS,
                rustix::fs::Mode::empty(),
                TREE_ENTRY_RESOLVE_FLAGS,
            )
            .context("cannot repin immutable-root stream relative to retained custody")?;
            ensure!(
                descriptor_file_metadata(repinned.as_fd())? == expected.metadata,
                "named immutable-root stream no longer identifies retained custody"
            );
            hook(ImmutableFileReadStage::FileRepinned)?;
            Ok(())
        })();
        finish_authenticated_stream_file_inspection(outcome, file_postcheck)
    }

    struct PinnedAbsoluteDirectory {
        anchor: OwnedFd,
        anchor_identity: PhysicalIdentity,
        anchor_mount_id: u64,
        components: Vec<OsString>,
        descriptors: Vec<OwnedFd>,
        identities: Vec<PhysicalIdentity>,
        mount_ids: Vec<u64>,
        diagnostic_path: PathBuf,
    }

    impl PinnedAbsoluteDirectory {
        fn open(path: &Path, label: &str) -> Result<Self> {
            validate_absolute_lexical_path(path, label, true)?;
            let anchor = rustix::fs::open("/", DIRECTORY_FLAGS, rustix::fs::Mode::empty())
                .with_context(|| format!("cannot pin {label} filesystem anchor"))?;
            let anchor_metadata = directory_metadata(anchor.as_fd())?;
            let anchor_identity = anchor_metadata.identity;
            let anchor_mount_id = anchor_metadata.mount_id;
            let components = path
                .components()
                .filter_map(|component| match component {
                    Component::Normal(value) => Some(value.to_os_string()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let mut descriptors = Vec::new();
            let mut identities = Vec::new();
            let mut mount_ids = Vec::new();
            descriptors
                .try_reserve_exact(components.len())
                .with_context(|| format!("cannot retain {label} descriptor chain"))?;
            identities
                .try_reserve_exact(components.len())
                .with_context(|| format!("cannot retain {label} identity chain"))?;
            mount_ids
                .try_reserve_exact(components.len())
                .with_context(|| format!("cannot retain {label} mount-identity chain"))?;
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
                let metadata = directory_metadata(descriptor.as_fd())?;
                identities.push(metadata.identity);
                mount_ids.push(metadata.mount_id);
                descriptors.push(descriptor);
            }
            Ok(Self {
                anchor,
                anchor_identity,
                anchor_mount_id,
                components,
                descriptors,
                identities,
                mount_ids,
                diagnostic_path: path.to_path_buf(),
            })
        }

        fn descriptor(&self) -> BorrowedFd<'_> {
            self.descriptors
                .last()
                .map_or_else(|| self.anchor.as_fd(), OwnedFd::as_fd)
        }

        fn final_identity(&self) -> PhysicalIdentity {
            self.identities
                .last()
                .copied()
                .unwrap_or(self.anchor_identity)
        }

        fn final_mount_id(&self) -> u64 {
            self.mount_ids
                .last()
                .copied()
                .unwrap_or(self.anchor_mount_id)
        }

        fn require_prefix_of(&self, descendant: &Self, label: &str) -> Result<()> {
            ensure!(
                descendant.components.len() > self.components.len()
                    && descendant.components.starts_with(&self.components),
                "{label} is not a strict lexical descendant of the retained campaign root"
            );
            ensure!(
                descendant.anchor_identity == self.anchor_identity
                    && descendant.anchor_mount_id == self.anchor_mount_id,
                "{label} does not share the retained campaign filesystem anchor"
            );
            for (index, ((identity, mount_id), (other_identity, other_mount_id))) in self
                .identities
                .iter()
                .zip(&self.mount_ids)
                .zip(descendant.identities.iter().zip(&descendant.mount_ids))
                .enumerate()
            {
                ensure!(
                    identity == other_identity && mount_id == other_mount_id,
                    "{label} component {index} does not share retained campaign custody"
                );
            }
            Ok(())
        }

        fn reauthenticate(&self) -> Result<()> {
            let retained_anchor = directory_metadata(self.anchor.as_fd())?;
            ensure!(
                retained_anchor.identity == self.anchor_identity
                    && retained_anchor.mount_id == self.anchor_mount_id,
                "retained directory anchor identity changed for {}",
                self.diagnostic_path.display()
            );
            for (index, ((descriptor, identity), mount_id)) in self
                .descriptors
                .iter()
                .zip(&self.identities)
                .zip(&self.mount_ids)
                .enumerate()
            {
                let metadata = directory_metadata(descriptor.as_fd())?;
                ensure!(
                    metadata.identity == *identity && metadata.mount_id == *mount_id,
                    "retained directory component {index} changed for {}",
                    self.diagnostic_path.display()
                );
            }

            let reopened_anchor = rustix::fs::openat2(
                self.anchor.as_fd(),
                ".",
                DIRECTORY_FLAGS,
                rustix::fs::Mode::empty(),
                TREE_ENTRY_RESOLVE_FLAGS,
            )
            .with_context(|| {
                format!(
                    "cannot reopen directory anchor for {}",
                    self.diagnostic_path.display()
                )
            })?;
            let reopened_anchor_metadata = directory_metadata(reopened_anchor.as_fd())?;
            ensure!(
                reopened_anchor_metadata.identity == self.anchor_identity
                    && reopened_anchor_metadata.mount_id == self.anchor_mount_id,
                "directory anchor no longer names retained identity for {}",
                self.diagnostic_path.display()
            );
            let mut reopened = Vec::new();
            reopened
                .try_reserve_exact(self.components.len())
                .context("cannot retain reauthenticated directory chain")?;
            for (index, ((component, identity), mount_id)) in self
                .components
                .iter()
                .zip(&self.identities)
                .zip(&self.mount_ids)
                .enumerate()
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
                let metadata = directory_metadata(descriptor.as_fd())?;
                ensure!(
                    metadata.identity == *identity && metadata.mount_id == *mount_id,
                    "directory path no longer names retained component {index} for {}",
                    self.diagnostic_path.display()
                );
                reopened.push(descriptor);
            }
            Ok(())
        }
    }

    fn validate_absolute_lexical_path(path: &Path, label: &str, allow_root: bool) -> Result<()> {
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
        ensure!(allow_root || bytes != b"/", "{label} path is too broad");
        Ok(())
    }

    fn component_paths_conflict(left: &Path, right: &Path) -> bool {
        left == right || left.starts_with(right) || right.starts_with(left)
    }

    const fn identity_from_stat(stat: &rustix::fs::Stat) -> PhysicalIdentity {
        PhysicalIdentity {
            device: stat.st_dev,
            inode: stat.st_ino,
        }
    }

    fn directory_metadata(descriptor: BorrowedFd<'_>) -> Result<DirectoryMetadata> {
        let stat = rustix::fs::fstat(descriptor).context("cannot inspect opened directory")?;
        ensure!(
            rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir(),
            "opened descriptor is not an ordinary directory"
        );
        Ok(DirectoryMetadata {
            identity: identity_from_stat(&stat),
            mount_id: descriptor_mount_id(descriptor)?,
            mode: stat.st_mode,
            modified_seconds: stat.st_mtime,
            modified_nanoseconds: stat.st_mtime_nsec,
            changed_seconds: stat.st_ctime,
            changed_nanoseconds: stat.st_ctime_nsec,
        })
    }

    fn descriptor_file_metadata(descriptor: BorrowedFd<'_>) -> Result<FileMetadata> {
        let metadata = rustix::fs::fstat(descriptor).context("cannot inspect opened file")?;
        ensure!(
            rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_file(),
            "opened descriptor is not an ordinary regular file"
        );
        let hard_link_count = metadata.st_nlink;
        ensure!(
            hard_link_count == 1,
            "opened ordinary file must have exactly one hard link"
        );
        Ok(FileMetadata {
            identity: identity_from_stat(&metadata),
            mount_id: descriptor_mount_id(descriptor)?,
            byte_length: u64::try_from(metadata.st_size)
                .context("opened ordinary-file byte length does not fit u64")?,
            hard_link_count,
            mode: metadata.st_mode,
            modified_seconds: metadata.st_mtime,
            modified_nanoseconds: metadata.st_mtime_nsec,
            changed_seconds: metadata.st_ctime,
            changed_nanoseconds: metadata.st_ctime_nsec,
        })
    }

    fn opened_file_metadata(file: &File) -> Result<FileMetadata> {
        descriptor_file_metadata(file.as_fd())
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

    fn measure_open_file(
        file: &mut File,
        diagnostic: &Path,
        maximum: u64,
        role: SnapshotFileRoleV1,
    ) -> Result<StableFileSnapshot> {
        file.seek(SeekFrom::Start(0))
            .with_context(|| format!("cannot seek {}", diagnostic.display()))?;
        let before = opened_file_metadata(file)?;
        validate_snapshot_file_role_length(role, before.byte_length)?;
        ensure!(
            before.byte_length <= maximum,
            "{} exceeds its compiled custody bound",
            diagnostic.display()
        );
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 16 * 1024];
        let mut observed_length = 0_u64;
        loop {
            let count = file
                .read(&mut buffer)
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
            role,
            metadata: after,
            sha256: hasher.finalize().into(),
        })
    }

    fn read_open_file_bytes(
        file: &mut File,
        diagnostic: &str,
        maximum: u64,
    ) -> Result<(StableFileSnapshot, Vec<u8>)> {
        file.seek(SeekFrom::Start(0))
            .with_context(|| format!("cannot seek immutable-root file {diagnostic}"))?;
        let before = opened_file_metadata(file)?;
        ensure!(
            before.byte_length <= maximum,
            "immutable-root file {diagnostic} exceeds its caller-supplied bound"
        );
        let capacity = usize::try_from(before.byte_length)
            .context("immutable-root file length does not fit memory addressing")?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .context("cannot reserve bounded immutable-root file bytes")?;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let count = file
                .read(&mut buffer)
                .with_context(|| format!("cannot read immutable-root file {diagnostic}"))?;
            if count == 0 {
                break;
            }
            let observed = u64::try_from(bytes.len())?
                .checked_add(u64::try_from(count)?)
                .context("immutable-root read length overflowed")?;
            ensure!(
                observed <= maximum,
                "immutable-root file {diagnostic} changed beyond its bound"
            );
            bytes.extend_from_slice(&buffer[..count]);
            hasher.update(&buffer[..count]);
        }
        let after = opened_file_metadata(file)?;
        ensure!(
            before == after && u64::try_from(bytes.len())? == before.byte_length,
            "immutable-root file {diagnostic} changed while being read"
        );
        Ok((
            StableFileSnapshot {
                role: SnapshotFileRoleV1::Generic,
                metadata: after,
                sha256: hasher.finalize().into(),
            },
            bytes,
        ))
    }

    fn validate_portable_relative_file_path(relative: &str) -> Result<()> {
        let path = Path::new(relative);
        ensure!(
            !relative.is_empty() && relative.len() <= MAX_ABSOLUTE_PATH_BYTES,
            "immutable-root relative file path is outside its byte bound"
        );
        ensure!(
            !path.is_absolute(),
            "immutable-root file path must be relative"
        );
        let mut rebuilt = PathBuf::new();
        let mut component_count = 0_usize;
        for component in path.components() {
            let Component::Normal(component) = component else {
                anyhow::bail!("immutable-root file path is not normalized relative");
            };
            rebuilt.push(component);
            component_count = component_count
                .checked_add(1)
                .context("immutable-root relative component count overflowed")?;
        }
        ensure!(
            (1..=MAX_ABSOLUTE_PATH_COMPONENTS).contains(&component_count)
                && rebuilt.as_os_str() == path.as_os_str(),
            "immutable-root file path is not normalized relative"
        );
        Ok(())
    }

    fn validate_projected_oci_relative_file_path(relative: &str) -> Result<()> {
        validate_portable_relative_file_path(relative)?;
        ensure!(
            (1..=240).contains(&relative.len()) && relative.is_ascii(),
            "projected OCI image-layout path is outside its portable byte bound"
        );
        for component in relative.split('/') {
            let bytes = component.as_bytes();
            ensure!(
                !bytes.is_empty()
                    && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
                    && bytes.iter().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'.' | b'_' | b'-')
                    })
                    && component != "."
                    && component != ".."
                    && !component.ends_with('.'),
                "projected OCI image-layout path is outside the portable component subset"
            );
        }
        Ok(())
    }

    fn relative_component_paths_conflict(left: &[u8], right: &[u8]) -> bool {
        fn is_prefix(prefix: &[u8], path: &[u8]) -> bool {
            path.starts_with(prefix) && path.get(prefix.len()) == Some(&b'/')
        }
        left == right || is_prefix(left, right) || is_prefix(right, left)
    }

    fn validate_snapshot_file_role_length(
        role: SnapshotFileRoleV1,
        byte_length: u64,
    ) -> Result<()> {
        match role {
            SnapshotFileRoleV1::Generic => ensure!(
                byte_length <= MAX_IMMUTABLE_SNAPSHOT_FILE_BYTES,
                "generic immutable-root file exceeds the compiled snapshot-file bound"
            ),
            SnapshotFileRoleV1::OciImageLayoutUstar => {
                let limits = B4ImmutableArtifactRoleV1::OciImageLayoutUstar.limits();
                let (minimum, maximum) = limits.encoded_byte_range();
                ensure!(
                    minimum == 6_144
                        && maximum == 17_179_869_184
                        && limits.encoded_byte_multiple() == Some(512),
                    "OCI image-layout custody differs from its closed role contract"
                );
                limits.validate_encoded_length(byte_length, "OCI image-layout ustar")?;
            }
        }
        Ok(())
    }

    fn projected_oci_image_layout_bounds(slot_count: usize) -> Result<(u64, u64)> {
        ensure!(
            slot_count <= MAX_PROJECTED_OCI_IMAGE_LAYOUT_CAPTURE_SLOTS,
            "projected OCI image-layout custody exceeds the closed slot-count bound"
        );
        let limits = B4ImmutableArtifactRoleV1::OciImageLayoutUstar.limits();
        let (minimum, maximum_file_bytes) = limits.encoded_byte_range();
        ensure!(
            minimum == 6_144
                && maximum_file_bytes == 17_179_869_184
                && limits.encoded_byte_multiple() == Some(512),
            "OCI image-layout custody differs from its closed role contract"
        );
        let maximum_aggregate_bytes = maximum_file_bytes
            .checked_mul(u64::try_from(slot_count)?)
            .context("projected OCI image-layout aggregate bound overflowed")?;
        Ok((maximum_file_bytes, maximum_aggregate_bytes))
    }

    struct SnapshotBudget {
        entry_count: u64,
        generic_byte_length: u64,
        oci_image_layout_byte_length: u64,
        total_byte_length: u64,
    }

    fn snapshot_immutable_tree(
        retained_root: BorrowedFd<'_>,
        diagnostic_root: &Path,
    ) -> Result<ImmutableTreeSnapshot> {
        snapshot_immutable_tree_with_oci_paths(retained_root, diagnostic_root, &BTreeSet::new())
    }

    fn snapshot_immutable_tree_with_oci_paths(
        retained_root: BorrowedFd<'_>,
        diagnostic_root: &Path,
        oci_image_layout_paths: &BTreeSet<Vec<u8>>,
    ) -> Result<ImmutableTreeSnapshot> {
        snapshot_immutable_tree_with_oci_paths_and_limits(
            retained_root,
            diagnostic_root,
            oci_image_layout_paths,
            MAX_IMMUTABLE_ROOT_BYTES,
            MAX_IMMUTABLE_SNAPSHOT_FILE_BYTES,
        )
    }

    fn snapshot_immutable_tree_with_limits(
        retained_root: BorrowedFd<'_>,
        diagnostic_root: &Path,
        maximum_root_bytes: u64,
        maximum_file_bytes: u64,
    ) -> Result<ImmutableTreeSnapshot> {
        snapshot_immutable_tree_with_oci_paths_and_limits(
            retained_root,
            diagnostic_root,
            &BTreeSet::new(),
            maximum_root_bytes,
            maximum_file_bytes,
        )
    }

    fn snapshot_immutable_tree_with_oci_paths_and_limits(
        retained_root: BorrowedFd<'_>,
        diagnostic_root: &Path,
        oci_image_layout_paths: &BTreeSet<Vec<u8>>,
        maximum_root_bytes: u64,
        maximum_file_bytes: u64,
    ) -> Result<ImmutableTreeSnapshot> {
        ensure!(
            maximum_root_bytes > 0 && maximum_root_bytes <= MAX_IMMUTABLE_ROOT_BYTES,
            "immutable-root snapshot byte ceiling is outside its compiled bound"
        );
        ensure!(
            maximum_file_bytes > 0
                && maximum_file_bytes <= MAX_IMMUTABLE_SNAPSHOT_FILE_BYTES
                && maximum_file_bytes <= maximum_root_bytes,
            "immutable-root snapshot file ceiling is outside its compiled bound"
        );
        let (maximum_oci_image_layout_file_bytes, maximum_oci_image_layout_bytes) =
            projected_oci_image_layout_bounds(oci_image_layout_paths.len())?;
        for (index, path) in oci_image_layout_paths.iter().enumerate() {
            let path_text = std::str::from_utf8(path)
                .context("projected OCI image-layout path is not portable UTF-8")?;
            validate_projected_oci_relative_file_path(path_text)?;
            for other in oci_image_layout_paths.iter().skip(index + 1) {
                ensure!(
                    !relative_component_paths_conflict(path, other),
                    "projected OCI image-layout paths conflict within one immutable root"
                );
            }
        }
        let maximum_total_bytes = maximum_root_bytes
            .checked_add(maximum_oci_image_layout_bytes)
            .context("immutable-root total role budget overflowed")?;
        let root = rustix::fs::openat2(
            retained_root,
            ".",
            DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
            TREE_ENTRY_RESOLVE_FLAGS,
        )
        .with_context(|| {
            format!(
                "cannot duplicate immutable root descriptor {}",
                diagnostic_root.display()
            )
        })?;
        let root_metadata = directory_metadata(root.as_fd())?;
        let mut hasher = Sha256::new();
        hasher.update(b"eip0045-b4-immutable-root-observation-v2\0");
        hasher.update(b"P");
        hasher.update(u64::try_from(oci_image_layout_paths.len())?.to_le_bytes());
        for path in oci_image_layout_paths {
            hasher.update(SnapshotFileRoleV1::OciImageLayoutUstar.digest_tag());
            hash_path(&mut hasher, path)?;
        }
        hasher.update(b"R");
        hash_directory_metadata(&mut hasher, root_metadata);
        let mut budget = SnapshotBudget {
            entry_count: 0,
            generic_byte_length: 0,
            oci_image_layout_byte_length: 0,
            total_byte_length: 0,
        };
        let mut directory_identities = vec![root_metadata.identity];
        let mut files = BTreeMap::new();
        let mut seen_oci_image_layout_paths = BTreeSet::new();
        snapshot_directory(
            root.as_fd(),
            diagnostic_root,
            &[],
            root_metadata.identity.device,
            root_metadata.mount_id,
            maximum_root_bytes,
            maximum_file_bytes,
            maximum_oci_image_layout_file_bytes,
            maximum_oci_image_layout_bytes,
            maximum_total_bytes,
            oci_image_layout_paths,
            0,
            &mut budget,
            &mut hasher,
            &mut directory_identities,
            &mut files,
            &mut seen_oci_image_layout_paths,
        )?;
        ensure!(
            directory_metadata(root.as_fd())? == root_metadata,
            "immutable root directory changed while being measured: {}",
            diagnostic_root.display()
        );
        ensure!(
            seen_oci_image_layout_paths == *oci_image_layout_paths,
            "every projected OCI image-layout path must resolve exactly once to an ordinary file"
        );
        Ok(ImmutableTreeSnapshot {
            entry_count: budget.entry_count,
            generic_byte_length: budget.generic_byte_length,
            oci_image_layout_byte_length: budget.oci_image_layout_byte_length,
            sha256: hasher.finalize().into(),
            directory_identities,
            files,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the recursive custody walk carries one explicit, audit-visible bounded state"
    )]
    #[allow(
        clippy::too_many_lines,
        reason = "the descriptor-open, budget, hash, and post-stat sequence is one audit unit"
    )]
    fn snapshot_directory(
        directory: BorrowedFd<'_>,
        diagnostic_root: &Path,
        relative: &[u8],
        root_device: u64,
        root_mount_id: u64,
        maximum_root_bytes: u64,
        maximum_file_bytes: u64,
        maximum_oci_image_layout_file_bytes: u64,
        maximum_oci_image_layout_bytes: u64,
        maximum_total_bytes: u64,
        oci_image_layout_paths: &BTreeSet<Vec<u8>>,
        depth: usize,
        budget: &mut SnapshotBudget,
        hasher: &mut Sha256,
        directory_identities: &mut Vec<PhysicalIdentity>,
        files: &mut BTreeMap<Vec<u8>, StableFileSnapshot>,
        seen_oci_image_layout_paths: &mut BTreeSet<Vec<u8>>,
    ) -> Result<()> {
        ensure!(
            depth <= MAX_IMMUTABLE_ROOT_DEPTH,
            "immutable root exceeds the compiled directory-depth bound"
        );
        let before = directory_metadata(directory)?;
        ensure!(
            before.identity.device == root_device && before.mount_id == root_mount_id,
            "immutable root crosses a filesystem boundary"
        );
        let mut reader = rustix::fs::Dir::read_from(directory)
            .context("cannot enumerate immutable-root directory")?;
        let mut names = Vec::<CString>::new();
        for entry in &mut reader {
            let entry = entry.context("cannot read immutable-root directory entry")?;
            let name = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            budget.entry_count = budget
                .entry_count
                .checked_add(1)
                .context("immutable-root entry count overflowed")?;
            ensure!(
                budget.entry_count <= MAX_IMMUTABLE_ROOT_ENTRIES,
                "immutable root exceeds the compiled entry bound"
            );
            names
                .try_reserve(1)
                .context("cannot retain bounded immutable-root entry name")?;
            names.push(name.to_owned());
        }
        names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

        for name in names {
            let mut child_relative = relative.to_vec();
            if !child_relative.is_empty() {
                child_relative.push(b'/');
            }
            child_relative.extend_from_slice(name.as_bytes());
            ensure!(
                child_relative.len() <= MAX_ABSOLUTE_PATH_BYTES,
                "immutable-root relative path exceeds the compiled byte bound"
            );
            let stat = rustix::fs::statat(
                directory,
                name.as_c_str(),
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .context("cannot inspect immutable-root entry")?;
            let file_type = rustix::fs::FileType::from_raw_mode(stat.st_mode);
            ensure!(
                !oci_image_layout_paths.contains(&child_relative) || file_type.is_file(),
                "projected OCI image-layout path does not name an ordinary file"
            );
            hash_path(hasher, &child_relative)?;
            if file_type.is_dir() {
                hasher.update(b"D");
                let child = rustix::fs::openat2(
                    directory,
                    name.as_c_str(),
                    DIRECTORY_FLAGS,
                    rustix::fs::Mode::empty(),
                    TREE_ENTRY_RESOLVE_FLAGS,
                )
                .context("cannot pin immutable-root child directory")?;
                let child_metadata = directory_metadata(child.as_fd())?;
                ensure!(
                    child_metadata.identity == identity_from_stat(&stat)
                        && child_metadata.mount_id == root_mount_id,
                    "immutable-root child directory changed while being opened"
                );
                ensure!(
                    !directory_identities.contains(&child_metadata.identity),
                    "immutable root contains a physical directory alias"
                );
                directory_identities
                    .try_reserve(1)
                    .context("cannot retain bounded immutable-root directory identity")?;
                directory_identities.push(child_metadata.identity);
                hash_directory_metadata(hasher, child_metadata);
                snapshot_directory(
                    child.as_fd(),
                    diagnostic_root,
                    &child_relative,
                    root_device,
                    root_mount_id,
                    maximum_root_bytes,
                    maximum_file_bytes,
                    maximum_oci_image_layout_file_bytes,
                    maximum_oci_image_layout_bytes,
                    maximum_total_bytes,
                    oci_image_layout_paths,
                    depth + 1,
                    budget,
                    hasher,
                    directory_identities,
                    files,
                    seen_oci_image_layout_paths,
                )?;
            } else if file_type.is_file() {
                hasher.update(b"F");
                let role = if oci_image_layout_paths.contains(&child_relative) {
                    SnapshotFileRoleV1::OciImageLayoutUstar
                } else {
                    SnapshotFileRoleV1::Generic
                };
                hasher.update(role.digest_tag());
                let descriptor = rustix::fs::openat2(
                    directory,
                    name.as_c_str(),
                    FILE_FLAGS,
                    rustix::fs::Mode::empty(),
                    TREE_ENTRY_RESOLVE_FLAGS,
                )
                .context("cannot open immutable-root ordinary file")?;
                let mut file = File::from(descriptor);
                let maximum = match role {
                    SnapshotFileRoleV1::Generic => {
                        let remaining_root_bytes = maximum_root_bytes
                            .checked_sub(budget.generic_byte_length)
                            .context("generic immutable-root byte budget underflowed")?;
                        maximum_file_bytes.min(remaining_root_bytes)
                    }
                    SnapshotFileRoleV1::OciImageLayoutUstar => maximum_oci_image_layout_file_bytes,
                };
                let snapshot = measure_open_file(
                    &mut file,
                    &diagnostic_root.join(std::ffi::OsStr::from_bytes(&child_relative)),
                    maximum,
                    role,
                )?;
                ensure!(
                    snapshot.metadata.identity == identity_from_stat(&stat)
                        && snapshot.metadata.mount_id == root_mount_id,
                    "immutable-root file changed while being opened"
                );
                match role {
                    SnapshotFileRoleV1::Generic => {
                        budget.generic_byte_length = budget
                            .generic_byte_length
                            .checked_add(snapshot.metadata.byte_length)
                            .context("generic immutable-root byte count overflowed")?;
                        ensure!(
                            budget.generic_byte_length <= maximum_root_bytes,
                            "immutable root exceeds the compiled generic byte bound"
                        );
                    }
                    SnapshotFileRoleV1::OciImageLayoutUstar => {
                        budget.oci_image_layout_byte_length = budget
                            .oci_image_layout_byte_length
                            .checked_add(snapshot.metadata.byte_length)
                            .context("OCI image-layout byte count overflowed")?;
                        ensure!(
                            budget.oci_image_layout_byte_length <= maximum_oci_image_layout_bytes,
                            "projected OCI image-layout files exceed their aggregate role bound"
                        );
                        ensure!(
                            seen_oci_image_layout_paths.insert(child_relative.clone()),
                            "projected OCI image-layout path appeared twice"
                        );
                    }
                }
                budget.total_byte_length = budget
                    .total_byte_length
                    .checked_add(snapshot.metadata.byte_length)
                    .context("immutable-root total byte count overflowed")?;
                ensure!(
                    budget.total_byte_length <= maximum_total_bytes,
                    "immutable root exceeds its closed aggregate role budget"
                );
                hash_file_metadata(hasher, snapshot.metadata);
                hasher.update(snapshot.sha256);
                ensure!(
                    files.insert(child_relative.clone(), snapshot).is_none(),
                    "immutable-root file path appeared twice"
                );
            } else {
                anyhow::bail!("immutable root contains a symlink or special file");
            }
            let repeated = rustix::fs::statat(
                directory,
                name.as_c_str(),
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )
            .context("cannot repeat immutable-root entry inspection")?;
            ensure!(
                named_metadata_equal(&stat, &repeated),
                "immutable-root entry changed while being measured"
            );
        }
        ensure!(
            directory_metadata(directory)? == before,
            "immutable-root directory changed while being enumerated"
        );
        Ok(())
    }

    fn hash_path(hasher: &mut Sha256, path: &[u8]) -> Result<()> {
        let length =
            u64::try_from(path.len()).context("immutable-root path length overflows u64")?;
        hasher.update(length.to_le_bytes());
        hasher.update(path);
        Ok(())
    }

    fn hash_directory_metadata(hasher: &mut Sha256, metadata: DirectoryMetadata) {
        hasher.update(metadata.identity.device.to_le_bytes());
        hasher.update(metadata.identity.inode.to_le_bytes());
        hasher.update(metadata.mount_id.to_le_bytes());
        hasher.update(metadata.mode.to_le_bytes());
        hasher.update(metadata.modified_seconds.to_le_bytes());
        hasher.update(metadata.modified_nanoseconds.to_le_bytes());
        hasher.update(metadata.changed_seconds.to_le_bytes());
        hasher.update(metadata.changed_nanoseconds.to_le_bytes());
    }

    fn hash_file_metadata(hasher: &mut Sha256, metadata: FileMetadata) {
        hasher.update(metadata.identity.device.to_le_bytes());
        hasher.update(metadata.identity.inode.to_le_bytes());
        hasher.update(metadata.mount_id.to_le_bytes());
        hasher.update(metadata.byte_length.to_le_bytes());
        hasher.update(metadata.hard_link_count.to_le_bytes());
        hasher.update(metadata.mode.to_le_bytes());
        hasher.update(metadata.modified_seconds.to_le_bytes());
        hasher.update(metadata.modified_nanoseconds.to_le_bytes());
        hasher.update(metadata.changed_seconds.to_le_bytes());
        hasher.update(metadata.changed_nanoseconds.to_le_bytes());
    }

    fn named_metadata_equal(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
        identity_from_stat(left) == identity_from_stat(right)
            && left.st_mode == right.st_mode
            && left.st_nlink == right.st_nlink
            && left.st_size == right.st_size
            && left.st_mtime == right.st_mtime
            && left.st_mtime_nsec == right.st_mtime_nsec
            && left.st_ctime == right.st_ctime
            && left.st_ctime_nsec == right.st_ctime_nsec
    }

    #[cfg(test)]
    mod ceiling_tests {
        use std::{collections::BTreeSet, fs};

        use super::{
            MAX_BUFFERED_IMMUTABLE_FILE_BYTES, MAX_IMMUTABLE_ROOT_BYTES,
            MAX_IMMUTABLE_SNAPSHOT_FILE_BYTES, PinnedAbsoluteDirectory, SnapshotFileRoleV1,
            projected_oci_image_layout_bounds, snapshot_immutable_tree_with_limits,
            snapshot_immutable_tree_with_oci_paths_and_limits, validate_buffered_file_ceiling,
            validate_snapshot_file_role_length, validate_stream_file_ceiling,
        };

        #[test]
        fn snapshot_stream_and_buffered_file_ceilings_remain_distinct() {
            assert_eq!(MAX_IMMUTABLE_SNAPSHOT_FILE_BYTES, MAX_IMMUTABLE_ROOT_BYTES);
            assert_eq!(MAX_BUFFERED_IMMUTABLE_FILE_BYTES, 536_870_912);
            validate_buffered_file_ceiling(
                u64::try_from(MAX_BUFFERED_IMMUTABLE_FILE_BYTES).unwrap(),
            )
            .unwrap();
            assert!(
                validate_buffered_file_ceiling(
                    u64::try_from(MAX_BUFFERED_IMMUTABLE_FILE_BYTES).unwrap() + 1,
                )
                .is_err()
            );
            validate_stream_file_ceiling(MAX_IMMUTABLE_SNAPSHOT_FILE_BYTES).unwrap();
            assert!(validate_stream_file_ceiling(MAX_IMMUTABLE_SNAPSHOT_FILE_BYTES + 1).is_err());
            assert!(validate_stream_file_ceiling(17_179_869_184).is_err());
        }

        #[test]
        fn snapshot_file_ceiling_is_enforced_by_the_descriptor_walk() {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            fs::create_dir(&root).unwrap();
            fs::write(root.join("payload.bin"), [0x45_u8; 33]).unwrap();
            let pinned = PinnedAbsoluteDirectory::open(&root, "test immutable root").unwrap();

            let snapshot =
                snapshot_immutable_tree_with_limits(pinned.descriptor(), &root, 33, 33).unwrap();
            assert_eq!(snapshot.generic_byte_length, 33);
            assert_eq!(snapshot.oci_image_layout_byte_length, 0);
            let error = snapshot_immutable_tree_with_limits(pinned.descriptor(), &root, 33, 32)
                .unwrap_err();
            assert!(
                format!("{error:#}").contains("compiled custody bound"),
                "{error:#}"
            );
        }

        #[test]
        fn oci_snapshot_role_uses_its_contract_without_raising_generic_ceilings() {
            assert_eq!(MAX_IMMUTABLE_ROOT_BYTES, 1_073_741_824);
            assert_eq!(MAX_IMMUTABLE_SNAPSHOT_FILE_BYTES, 1_073_741_824);
            validate_snapshot_file_role_length(
                SnapshotFileRoleV1::Generic,
                MAX_IMMUTABLE_SNAPSHOT_FILE_BYTES,
            )
            .unwrap();
            assert!(
                validate_snapshot_file_role_length(
                    SnapshotFileRoleV1::Generic,
                    MAX_IMMUTABLE_SNAPSHOT_FILE_BYTES + 1,
                )
                .is_err()
            );

            for accepted in [6_144, 17_179_869_184] {
                validate_snapshot_file_role_length(
                    SnapshotFileRoleV1::OciImageLayoutUstar,
                    accepted,
                )
                .unwrap();
            }
            for rejected in [6_143, 6_145, 17_179_869_184 + 512] {
                assert!(
                    validate_snapshot_file_role_length(
                        SnapshotFileRoleV1::OciImageLayoutUstar,
                        rejected,
                    )
                    .is_err()
                );
            }
        }

        #[test]
        fn exact_projected_oci_path_is_the_only_exception_to_generic_snapshot_budgets() {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            fs::create_dir(&root).unwrap();
            fs::write(root.join("layout.oci.tar"), [0x45_u8; 6_144]).unwrap();
            let pinned = PinnedAbsoluteDirectory::open(&root, "test immutable root").unwrap();
            let generic_paths = BTreeSet::new();
            let oci_paths = BTreeSet::from([b"layout.oci.tar".to_vec()]);

            let error = snapshot_immutable_tree_with_oci_paths_and_limits(
                pinned.descriptor(),
                &root,
                &generic_paths,
                32,
                32,
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains("compiled custody bound"));

            let generic_snapshot = snapshot_immutable_tree_with_oci_paths_and_limits(
                pinned.descriptor(),
                &root,
                &generic_paths,
                6_144,
                6_144,
            )
            .unwrap();
            let oci_snapshot = snapshot_immutable_tree_with_oci_paths_and_limits(
                pinned.descriptor(),
                &root,
                &oci_paths,
                32,
                32,
            )
            .unwrap();

            assert_eq!(generic_snapshot.generic_byte_length, 6_144);
            assert_eq!(generic_snapshot.oci_image_layout_byte_length, 0);
            assert_eq!(oci_snapshot.generic_byte_length, 0);
            assert_eq!(oci_snapshot.oci_image_layout_byte_length, 6_144);
            assert_ne!(generic_snapshot.sha256, oci_snapshot.sha256);
            assert_eq!(
                generic_snapshot.files[b"layout.oci.tar".as_slice()].role,
                SnapshotFileRoleV1::Generic
            );
            assert_eq!(
                oci_snapshot.files[b"layout.oci.tar".as_slice()].role,
                SnapshotFileRoleV1::OciImageLayoutUstar
            );

            fs::write(root.join("generic.bin"), [0x47_u8; 33]).unwrap();
            let error = snapshot_immutable_tree_with_oci_paths_and_limits(
                pinned.descriptor(),
                &root,
                &oci_paths,
                32,
                32,
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains("compiled custody bound"));

            fs::remove_file(root.join("generic.bin")).unwrap();
            fs::write(root.join("layout.oci.tar.bak"), [0x48_u8; 33]).unwrap();
            let prefix = snapshot_immutable_tree_with_oci_paths_and_limits(
                pinned.descriptor(),
                &root,
                &oci_paths,
                32,
                32,
            )
            .unwrap_err();
            assert!(format!("{prefix:#}").contains("compiled custody bound"));

            fs::remove_file(root.join("layout.oci.tar.bak")).unwrap();
            fs::create_dir(root.join("other")).unwrap();
            fs::write(root.join("other").join("layout.oci.tar"), [0x49_u8; 33]).unwrap();
            let basename = snapshot_immutable_tree_with_oci_paths_and_limits(
                pinned.descriptor(),
                &root,
                &oci_paths,
                32,
                32,
            )
            .unwrap_err();
            assert!(format!("{basename:#}").contains("compiled custody bound"));
        }

        #[test]
        fn projected_oci_path_must_resolve_once_to_an_ordinary_file() {
            use std::os::unix::fs::symlink;

            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            fs::create_dir(&root).unwrap();
            let pinned = PinnedAbsoluteDirectory::open(&root, "test immutable root").unwrap();
            let oci_paths = BTreeSet::from([b"missing.oci.tar".to_vec()]);

            let absent = snapshot_immutable_tree_with_oci_paths_and_limits(
                pinned.descriptor(),
                &root,
                &oci_paths,
                32,
                32,
            )
            .unwrap_err();
            assert!(format!("{absent:#}").contains("projected OCI"));

            fs::create_dir(root.join("missing.oci.tar")).unwrap();
            let directory = snapshot_immutable_tree_with_oci_paths_and_limits(
                pinned.descriptor(),
                &root,
                &oci_paths,
                32,
                32,
            )
            .unwrap_err();
            assert!(format!("{directory:#}").contains("projected OCI"));

            fs::remove_dir(root.join("missing.oci.tar")).unwrap();
            symlink("elsewhere.oci.tar", root.join("missing.oci.tar")).unwrap();
            let symlink = snapshot_immutable_tree_with_oci_paths_and_limits(
                pinned.descriptor(),
                &root,
                &oci_paths,
                32,
                32,
            )
            .unwrap_err();
            assert!(format!("{symlink:#}").contains("projected OCI"));

            fs::remove_file(root.join("missing.oci.tar")).unwrap();
            fs::write(root.join("missing.oci.tar"), [0x45_u8; 6_144]).unwrap();
            fs::hard_link(
                root.join("missing.oci.tar"),
                root.join("z-hard-link.oci.tar"),
            )
            .unwrap();
            let hard_link = snapshot_immutable_tree_with_oci_paths_and_limits(
                pinned.descriptor(),
                &root,
                &oci_paths,
                32,
                32,
            )
            .unwrap_err();
            assert!(format!("{hard_link:#}").contains("hard link"));
        }

        #[test]
        fn projected_oci_snapshot_rejects_invalid_lengths_and_oversized_role_plans_before_reading()
        {
            assert_eq!(
                projected_oci_image_layout_bounds(4).unwrap(),
                (17_179_869_184, 68_719_476_736)
            );
            assert!(projected_oci_image_layout_bounds(5).is_err());

            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("root");
            fs::create_dir(&root).unwrap();
            fs::write(root.join("layout.oci.tar"), [0x45_u8; 6_145]).unwrap();
            let pinned = PinnedAbsoluteDirectory::open(&root, "test immutable root").unwrap();
            let oci_paths = BTreeSet::from([b"layout.oci.tar".to_vec()]);

            let invalid_multiple = snapshot_immutable_tree_with_oci_paths_and_limits(
                pinned.descriptor(),
                &root,
                &oci_paths,
                32,
                32,
            )
            .unwrap_err();
            assert!(format!("{invalid_multiple:#}").contains("multiple"));

            let oversized_plan = BTreeSet::from([
                b"a.oci.tar".to_vec(),
                b"b.oci.tar".to_vec(),
                b"c.oci.tar".to_vec(),
                b"d.oci.tar".to_vec(),
                b"e.oci.tar".to_vec(),
            ]);
            let error = snapshot_immutable_tree_with_oci_paths_and_limits(
                pinned.descriptor(),
                &root,
                &oversized_plan,
                32,
                32,
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains("slot-count"));
        }
    }
}

#[cfg(test)]
#[allow(
    dead_code,
    reason = "this compile-only probe locks AMD64 view visibility from a true executor sibling module"
)]
fn compile_only_observe_amd64_view_from_custody_sibling(
    view: super::amd64_elf_inspection::ImportedAmd64ElfViewV1<'_>,
) {
    let _ = (
        view.policy(),
        view.byte_length(),
        view.sha256(),
        view.common(),
    );
    if let super::amd64_elf_inspection::ImportedAmd64ElfLinkageV1::Runtime(runtime) = view.linkage()
    {
        let _ = (
            runtime.interpreter_path(),
            runtime.dynamic_entry_count(),
            runtime.needed_library_count(),
        );
    }
    std::hint::black_box(view);
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    #[cfg(target_os = "linux")]
    use std::{cell::Cell, fs, io::ErrorKind, path::PathBuf};

    #[cfg(target_os = "linux")]
    use super::{
        AuthenticatedFileStreamRequestV1, AuthenticatedStreamCombinedFailureV1,
        AuthenticatedStreamFailurePairV1, AuthenticatedStreamRoleV1, B4ImmutableArtifactRoleV1,
        ImmutableFileReadStage, ImmutableRootCustody, OCI_OUTER_USTAR_MAX_BYTES,
        REVIEWED_GIT_BUNDLE_MAX_BYTES,
    };
    use super::{CampaignRootCustody, CurrentExecutableObservation};

    #[cfg(target_os = "linux")]
    fn combined_stream_failure(error: &anyhow::Error) -> &AuthenticatedStreamCombinedFailureV1 {
        error
            .chain()
            .find_map(|cause| cause.downcast_ref::<AuthenticatedStreamCombinedFailureV1>())
            .expect("authenticated stream failure pair is absent from the error chain")
    }

    #[cfg(target_os = "linux")]
    fn with_test_authenticated_stream<Parsed, T>(
        custody: &ImmutableRootCustody<1>,
        root_index: usize,
        relative: &str,
        inspect: impl for<'reader> FnOnce(
            u64,
            [u8; 32],
            &'reader mut (dyn std::io::Read + 'reader),
        ) -> anyhow::Result<Parsed>,
        deliver: impl for<'parsed> FnOnce(u64, [u8; 32], &'parsed Parsed) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let limits = B4ImmutableArtifactRoleV1::ReviewedGitBundle.limits();
        custody
            .with_authenticated_file_stream_impl::<REVIEWED_GIT_BUNDLE_MAX_BYTES, _, _, _, _, _, _>(
                AuthenticatedFileStreamRequestV1 {
                    role: AuthenticatedStreamRoleV1::Generic,
                    root_index,
                    relative,
                },
                move |byte_length| {
                    limits.validate_encoded_length(byte_length, "reviewed Git bundle")
                },
                |_stage| Ok(()),
                inspect,
                move |byte_length, sha256, parsed| deliver(byte_length, sha256, &parsed),
            )
    }

    #[cfg(target_os = "linux")]
    fn projected_oci_test_custody(
        fill: u8,
    ) -> (tempfile::TempDir, PathBuf, PathBuf, ImmutableRootCustody<1>) {
        use crate::b4_campaign_executor::preflight::{
            project_prepare_input_set_campaign_layout,
            project_prepare_input_set_oci_capture_test_only,
        };

        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let inputs = campaign.join("inputs");
        let outer_final = campaign.join("runs").join("run-001");
        let archive = inputs.join("layout.oci.tar");
        fs::create_dir_all(&inputs).unwrap();
        fs::write(&archive, vec![fill; 6_144]).unwrap();
        fs::write(inputs.join("companion.bin"), b"stable companion").unwrap();
        let layout =
            project_prepare_input_set_campaign_layout(&campaign, [&inputs], &outer_final).unwrap();
        let projected =
            project_prepare_input_set_oci_capture_test_only(layout, &[(0, "layout.oci.tar")])
                .unwrap();
        let (_layout, slots) = projected.into_parts();
        let campaign_custody = CampaignRootCustody::capture(&campaign).unwrap();
        let custody = ImmutableRootCustody::<1>::capture_with_projected_oci(
            &campaign_custody,
            [&inputs],
            slots,
        )
        .unwrap();
        (temp, campaign, archive, custody)
    }

    #[cfg(target_os = "linux")]
    #[allow(
        clippy::too_many_arguments,
        reason = "the test helper exposes both replay hooks and all three distinct callback roles"
    )]
    fn with_test_authenticated_oci_replay<FirstInspection, RetainedFirst, ReplayInspection, T>(
        custody: &ImmutableRootCustody<1>,
        first_hook: impl FnMut(ImmutableFileReadStage) -> anyhow::Result<()>,
        inspect_first: impl for<'reader> FnOnce(
            u64,
            [u8; 32],
            &'reader mut (dyn std::io::Read + 'reader),
        ) -> anyhow::Result<FirstInspection>,
        retain_first: impl for<'inspection> FnOnce(
            u64,
            [u8; 32],
            &'inspection FirstInspection,
        ) -> anyhow::Result<RetainedFirst>,
        between_replays: impl FnOnce() -> anyhow::Result<()>,
        replay_hook: impl FnMut(ImmutableFileReadStage) -> anyhow::Result<()>,
        inspect_replay: impl for<'reader> FnOnce(
            u64,
            [u8; 32],
            &'reader mut (dyn std::io::Read + 'reader),
        ) -> anyhow::Result<ReplayInspection>,
        reject_replay: impl FnOnce(ReplayInspection, anyhow::Error) -> anyhow::Error,
        deliver: impl for<'inspection> FnOnce(
            RetainedFirst,
            u64,
            [u8; 32],
            &'inspection ReplayInspection,
        ) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        custody.with_authenticated_file_replay_streams_impl_with_rejection::<
            OCI_OUTER_USTAR_MAX_BYTES,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
        >(
            AuthenticatedFileStreamRequestV1 {
                role: AuthenticatedStreamRoleV1::OciImageLayoutUstar,
                root_index: 0,
                relative: "layout.oci.tar",
            },
            |byte_length| {
                anyhow::ensure!(byte_length == 6_144, "first replay length changed");
                Ok(())
            },
            first_hook,
            inspect_first,
            retain_first,
            between_replays,
            |byte_length| {
                anyhow::ensure!(byte_length == 6_144, "second replay length changed");
                Ok(())
            },
            replay_hook,
            inspect_replay,
            reject_replay,
            move |retained, byte_length, sha256, replay| {
                deliver(retained, byte_length, sha256, &replay)
            },
        )
    }

    #[test]
    fn qualifying_custody_is_linux_only_before_path_inspection() {
        if cfg!(target_os = "linux") {
            return;
        }

        let executable_error =
            CurrentExecutableObservation::capture(Path::new("missing-relative-executable"))
                .unwrap_err();
        assert!(executable_error.to_string().contains("requires Linux"));

        let campaign_error =
            CampaignRootCustody::capture(Path::new("missing-relative-campaign")).unwrap_err();
        assert!(campaign_error.to_string().contains("requires Linux"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn projected_oci_role_never_enters_the_generic_authenticated_stream() {
        use crate::b4_campaign_executor::preflight::{
            project_prepare_input_set_campaign_layout,
            project_prepare_input_set_oci_capture_test_only,
        };

        let temp = tempfile::tempdir().unwrap();
        let campaign = temp.path().join("campaign");
        let inputs = campaign.join("inputs");
        let outer_final = campaign.join("runs").join("run-001");
        fs::create_dir_all(&inputs).unwrap();
        fs::write(inputs.join("layout.oci.tar"), [0x45_u8; 6_144]).unwrap();
        let layout =
            project_prepare_input_set_campaign_layout(&campaign, [&inputs], &outer_final).unwrap();
        let projected =
            project_prepare_input_set_oci_capture_test_only(layout, &[(0, "layout.oci.tar")])
                .unwrap();
        let (_layout, slots) = projected.into_parts();
        let campaign_custody = CampaignRootCustody::capture(&campaign).unwrap();
        let custody = ImmutableRootCustody::<1>::capture_with_projected_oci(
            &campaign_custody,
            [&inputs],
            slots,
        )
        .unwrap();
        let inspected = Cell::new(false);
        let delivered = Cell::new(false);

        let error = with_test_authenticated_stream(
            &custody,
            0,
            "layout.oci.tar",
            |_byte_length, _sha256, _reader| {
                inspected.set(true);
                Ok(())
            },
            |_byte_length, _sha256, _parsed| {
                delivered.set(true);
                Ok(())
            },
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("projected OCI image-layout stream"));
        assert!(!inspected.get());
        assert!(!delivered.get());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authenticated_oci_replay_opens_and_consumes_two_independent_streams() {
        let (_temp, _campaign, _archive, custody) = projected_oci_test_custody(0x45);
        let data_opened = Cell::new(0_u8);
        let bytes_read = Cell::new(0_u8);

        let delivered = with_test_authenticated_oci_replay(
            &custody,
            |stage| {
                if stage == ImmutableFileReadStage::DataOpened {
                    data_opened.set(data_opened.get() + 1);
                }
                if stage == ImmutableFileReadStage::BytesRead {
                    bytes_read.set(bytes_read.get() + 1);
                }
                Ok(())
            },
            |_byte_length, _sha256, reader| {
                let mut observed = Vec::new();
                reader.read_to_end(&mut observed)?;
                Ok(observed)
            },
            |_byte_length, _sha256, first| Ok(first.len()),
            || Ok(()),
            |stage| {
                if stage == ImmutableFileReadStage::DataOpened {
                    data_opened.set(data_opened.get() + 1);
                }
                if stage == ImmutableFileReadStage::BytesRead {
                    bytes_read.set(bytes_read.get() + 1);
                }
                Ok(())
            },
            |_byte_length, _sha256, reader| {
                let mut observed = Vec::new();
                reader.read_to_end(&mut observed)?;
                Ok(observed)
            },
            |_replay, error| error,
            |retained_first_length, _byte_length, _sha256, second| {
                Ok((retained_first_length, second.len()))
            },
        )
        .unwrap();

        assert_eq!(delivered, (6_144, 6_144));
        assert_eq!(data_opened.get(), 2);
        assert_eq!(bytes_read.get(), 2);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authenticated_oci_replay_rejects_same_length_inode_swap_between_streams() {
        use std::os::unix::fs::MetadataExt as _;

        let (_temp, campaign, archive, custody) = projected_oci_test_custody(0x46);
        let replay_inspected = Cell::new(false);
        let delivered = Cell::new(false);

        let error = with_test_authenticated_oci_replay(
            &custody,
            |_stage| Ok(()),
            |_byte_length, _sha256, reader| {
                let mut observed = Vec::new();
                reader.read_to_end(&mut observed)?;
                Ok(observed)
            },
            |_byte_length, _sha256, first| Ok(first.len()),
            || {
                let original_inode = fs::metadata(&archive)?.ino();
                let displaced = campaign.join("retained-layout.oci.tar");
                fs::rename(&archive, &displaced)?;
                fs::copy(&displaced, &archive)?;
                anyhow::ensure!(
                    fs::metadata(&archive)?.len() == 6_144,
                    "replacement length changed"
                );
                anyhow::ensure!(
                    fs::metadata(&archive)?.ino() != original_inode,
                    "replacement unexpectedly reused the retained inode"
                );
                Ok(())
            },
            |_stage| Ok(()),
            |_byte_length, _sha256, reader| {
                replay_inspected.set(true);
                let mut observed = Vec::new();
                reader.read_to_end(&mut observed)?;
                Ok(observed)
            },
            |_replay, error| error,
            |_retained, _byte_length, _sha256, _replay| {
                delivered.set(true);
                Ok(())
            },
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("immutable root"));
        assert!(!replay_inspected.get());
        assert!(!delivered.get());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authenticated_oci_replay_does_not_deliver_after_second_inspection_failure() {
        let (_temp, _campaign, _archive, custody) = projected_oci_test_custody(0x47);
        let retained = Cell::new(false);
        let replay_inspected = Cell::new(false);
        let delivered = Cell::new(false);

        let error = with_test_authenticated_oci_replay(
            &custody,
            |_stage| Ok(()),
            |_byte_length, _sha256, reader| {
                let mut observed = Vec::new();
                reader.read_to_end(&mut observed)?;
                Ok(observed)
            },
            |_byte_length, _sha256, first| {
                retained.set(true);
                Ok(first.len())
            },
            || Ok(()),
            |_stage| Ok(()),
            |_byte_length, _sha256, reader| -> anyhow::Result<Vec<u8>> {
                replay_inspected.set(true);
                let mut observed = Vec::new();
                reader.read_to_end(&mut observed)?;
                anyhow::bail!("injected second replay inspection failure")
            },
            |_replay, error| error,
            |_retained, _byte_length, _sha256, _replay| {
                delivered.set(true);
                Ok(())
            },
        )
        .unwrap_err();

        assert!(retained.get());
        assert!(replay_inspected.get());
        assert!(!delivered.get());
        assert!(
            format!("{error:#}").contains("injected second replay inspection failure"),
            "unexpected replay rejection: {error:#}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authenticated_oci_replay_propagates_final_delivery_failure() {
        let (_temp, _campaign, _archive, custody) = projected_oci_test_custody(0x48);
        let delivered = Cell::new(false);

        let error = with_test_authenticated_oci_replay(
            &custody,
            |_stage| Ok(()),
            |_byte_length, _sha256, reader| {
                let mut observed = Vec::new();
                reader.read_to_end(&mut observed)?;
                Ok(observed)
            },
            |_byte_length, _sha256, first| Ok(first.len()),
            || Ok(()),
            |_stage| Ok(()),
            |_byte_length, _sha256, reader| {
                let mut observed = Vec::new();
                reader.read_to_end(&mut observed)?;
                Ok(observed)
            },
            |_replay, error| error,
            |_retained, _byte_length, _sha256, _replay| -> anyhow::Result<()> {
                delivered.set(true);
                anyhow::bail!("injected final replay delivery failure")
            },
        )
        .unwrap_err();

        assert!(delivered.get());
        assert!(
            format!("{error:#}").contains("injected final replay delivery failure"),
            "unexpected delivery rejection: {error:#}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authenticated_oci_replay_rejects_owned_replay_before_delivery() {
        let (_temp, _campaign, archive, custody) = projected_oci_test_custody(0x49);
        let companion = archive.parent().unwrap().join("companion.bin");
        let rejected = Cell::new(false);
        let delivered = Cell::new(false);

        let error = with_test_authenticated_oci_replay(
            &custody,
            |_stage| Ok(()),
            |_byte_length, _sha256, reader| {
                let mut observed = Vec::new();
                reader.read_to_end(&mut observed)?;
                Ok(observed)
            },
            |_byte_length, _sha256, first| Ok(first.len()),
            || Ok(()),
            |_stage| Ok(()),
            |_byte_length, _sha256, reader| {
                let mut observed = Vec::new();
                reader.read_to_end(&mut observed)?;
                fs::write(&companion, b"changed companion")?;
                Ok(observed)
            },
            |replay, error| {
                rejected.set(true);
                assert_eq!(replay.len(), 6_144);
                error.context("owned replay rejected explicitly")
            },
            |_retained, _byte_length, _sha256, _replay| {
                delivered.set(true);
                Ok(())
            },
        )
        .unwrap_err();

        assert!(rejected.get());
        assert!(!delivered.get());
        assert!(format!("{error:#}").contains("owned replay rejected explicitly"));
        assert!(format!("{error:#}").contains("pre-delivery postcheck failed"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authenticated_stream_preserves_nested_inspection_read_file_and_root_failures() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let bundle_path = root.join("reviewed.bundle");
        fs::create_dir(&root).unwrap();
        fs::write(&bundle_path, b"stable reviewed bundle").unwrap();
        let campaign = CampaignRootCustody::capture(temp.path()).unwrap();
        let custody = ImmutableRootCustody::<1>::capture(&campaign, [root.as_path()]).unwrap();
        let delivered = Cell::new(false);

        let error = with_test_authenticated_stream(
            &custody,
            0,
            "reviewed.bundle",
            |_byte_length, _sha256, reader| -> anyhow::Result<()> {
                let mut prefix = [0_u8; 4];
                reader.read_exact(&mut prefix)?;
                fs::OpenOptions::new()
                    .write(true)
                    .open(&bundle_path)?
                    .set_len(0)?;
                let mut next = [0_u8; 1];
                let first = reader.read(&mut next).unwrap_err();
                assert_eq!(first.kind(), ErrorKind::UnexpectedEof);
                let replayed = reader.read(&mut next).unwrap_err();
                assert_eq!(replayed.kind(), ErrorKind::UnexpectedEof);
                anyhow::bail!("injected inspection failure after physical read failure")
            },
            |_byte_length, _sha256, _inspection| {
                delivered.set(true);
                Ok(())
            },
        )
        .unwrap_err();

        let root_pair = combined_stream_failure(&error);
        assert_eq!(
            root_pair.pair(),
            AuthenticatedStreamFailurePairV1::InspectionAndPreDeliveryPostcheck
        );
        let file_pair = combined_stream_failure(root_pair.earlier());
        assert_eq!(
            file_pair.pair(),
            AuthenticatedStreamFailurePairV1::InspectionAndFilePostcheck
        );
        let read_pair = combined_stream_failure(file_pair.earlier());
        assert_eq!(
            read_pair.pair(),
            AuthenticatedStreamFailurePairV1::InspectionAndRead
        );
        assert!(
            format!("{:#}", read_pair.earlier())
                .contains("injected inspection failure after physical read failure")
        );
        assert!(format!("{:#}", read_pair.later()).contains("ended before its retained length"));
        assert!(!format!("{:#}", file_pair.later()).is_empty());
        assert!(!format!("{:#}", root_pair.later()).is_empty());
        assert!(!delivered.get());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn authenticated_stream_preserves_delivery_and_root_failures() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let bundle_path = root.join("reviewed.bundle");
        fs::create_dir(&root).unwrap();
        fs::write(&bundle_path, b"stable reviewed bundle").unwrap();
        let campaign = CampaignRootCustody::capture(temp.path()).unwrap();
        let custody = ImmutableRootCustody::<1>::capture(&campaign, [root.as_path()]).unwrap();
        let delivered = Cell::new(false);

        let error = with_test_authenticated_stream(
            &custody,
            0,
            "reviewed.bundle",
            |_byte_length, _sha256, reader| {
                let mut observed = Vec::new();
                reader.read_to_end(&mut observed)?;
                Ok(observed)
            },
            |_byte_length, _sha256, _inspection| -> anyhow::Result<()> {
                delivered.set(true);
                fs::write(&bundle_path, b"changed during failed delivery")?;
                anyhow::bail!("injected delivery failure after root mutation")
            },
        )
        .unwrap_err();

        let combined = combined_stream_failure(&error);
        assert_eq!(
            combined.pair(),
            AuthenticatedStreamFailurePairV1::DeliveryAndPostcheck
        );
        assert!(
            format!("{:#}", combined.earlier())
                .contains("injected delivery failure after root mutation")
        );
        assert!(!format!("{:#}", combined.later()).is_empty());
        assert!(delivered.get());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn current_executable_is_measured_from_the_executing_image_and_rechecked() {
        let executable = fs::read_link("/proc/self/exe").unwrap();
        let observation = CurrentExecutableObservation::capture(&executable).unwrap();
        assert_eq!(
            observation.observed_byte_length(),
            fs::metadata(&executable).unwrap().len()
        );
        observation.recheck().unwrap();

        let temp = tempfile::tempdir().unwrap();
        let copied = temp.path().join("copied-test-executable");
        fs::copy(&executable, &copied).unwrap();
        let error = CurrentExecutableObservation::capture(&copied).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not name the executing image")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn current_executable_path_replacement_is_rejected() {
        use std::process::Command;

        const CHILD_MARKER: &str = "EIP0045_E1_EXECUTABLE_SWAP_CHILD";
        if std::env::var_os(CHILD_MARKER).is_some() {
            let executable = fs::read_link("/proc/self/exe").unwrap();
            let hardlink = executable.with_extension("hardlink");
            fs::hard_link(&executable, &hardlink).unwrap();
            let error = CurrentExecutableObservation::capture(&executable).unwrap_err();
            fs::remove_file(&hardlink).unwrap();
            assert!(error.to_string().contains("exactly one hard link"));

            let observation = CurrentExecutableObservation::capture(&executable).unwrap();
            let retained_name = executable.with_extension("retained-image");
            fs::rename(&executable, &retained_name).unwrap();
            fs::copy(&retained_name, &executable).unwrap();
            let error = observation.recheck().unwrap_err();
            fs::remove_file(&executable).unwrap();
            fs::rename(&retained_name, &executable).unwrap();
            let message = error.to_string();
            assert!(
                message.contains("retained executing-image observation changed")
                    || message.contains("no longer names the executing image"),
                "unexpected executable-replacement rejection: {error:#}"
            );
            return;
        }

        let temp = tempfile::tempdir().unwrap();
        let copied_runner = temp.path().join("custody-test-runner");
        fs::copy(fs::read_link("/proc/self/exe").unwrap(), &copied_runner).unwrap();
        let status = Command::new(&copied_runner)
            .env(CHILD_MARKER, "1")
            .args([
                "b4_campaign_executor::custody::tests::current_executable_path_replacement_is_rejected",
                "--exact",
                "--test-threads=1",
            ])
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn immutable_root_custody_detects_byte_and_path_identity_drift() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("payload.bin"), b"before").unwrap();

        let campaign = CampaignRootCustody::capture(temp.path()).unwrap();
        let custody = ImmutableRootCustody::<1>::capture(&campaign, [root.as_path()]).unwrap();
        custody.recheck().unwrap();

        fs::write(root.join("payload.bin"), b"after!").unwrap();
        let error = custody.recheck().unwrap_err();
        assert!(error.to_string().contains("immutable root"));

        let moved = temp.path().join("root-old");
        fs::rename(&root, &moved).unwrap();
        fs::create_dir(&root).unwrap();
        fs::write(root.join("payload.bin"), b"after!").unwrap();
        let error = custody.recheck().unwrap_err();
        assert!(error.to_string().contains("no longer names"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn immutable_roots_reject_duplicate_physical_custody() {
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let campaign = CampaignRootCustody::capture(temp.path()).unwrap();
        let error = ImmutableRootCustody::<2>::capture(&campaign, [root.as_path(), root.as_path()])
            .unwrap_err();
        assert!(error.to_string().contains("conflict"));

        let alias = temp.path().join("alias");
        symlink(&root, &alias).unwrap();
        let error = ImmutableRootCustody::<1>::capture(&campaign, [alias.as_path()]).unwrap_err();
        assert!(
            error.to_string().contains("cannot pin")
                || error.to_string().contains("not an ordinary directory")
        );

        let metadata = fs::metadata(&root).unwrap();
        let error = ImmutableRootCustody::<1>::capture(&campaign, [root.as_path()])
            .unwrap()
            .reject_physical_directory_aliases(&[(metadata.dev(), metadata.ino(), 0)])
            .unwrap_err();
        assert!(error.to_string().contains("physically aliases"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn immutable_root_reads_remain_descriptor_rooted_during_ancestor_swap() {
        let temp = tempfile::tempdir().unwrap();
        let campaign_path = temp.path().join("campaign");
        let root = campaign_path.join("inputs");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("source.bin"), b"stable").unwrap();
        let campaign = CampaignRootCustody::capture(&campaign_path).unwrap();
        let custody = ImmutableRootCustody::<1>::capture(&campaign, [root.as_path()]).unwrap();
        assert_eq!(custody.read_file::<64>(0, "source.bin").unwrap(), b"stable");

        let retained_campaign = temp.path().join("campaign-old");
        fs::rename(&campaign_path, &retained_campaign).unwrap();
        fs::create_dir_all(campaign_path.join("inputs")).unwrap();
        fs::write(campaign_path.join("inputs/source.bin"), b"evil").unwrap();

        let retained_bytes =
            super::linux::read_immutable_root_file::<64>(&custody.roots[0], "source.bin").unwrap();
        assert_eq!(retained_bytes, b"stable");
        assert!(custody.read_file::<64>(0, "source.bin").is_err());

        fs::remove_dir_all(&campaign_path).unwrap();
        fs::rename(&retained_campaign, &campaign_path).unwrap();
        custody.recheck().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn immutable_root_descriptor_is_bounded_and_postchecked_on_every_exit() {
        use std::cell::Cell;
        use std::os::unix::fs::MetadataExt as _;

        let temp = tempfile::tempdir().unwrap();
        let terminal_root = temp.path().join("terminal-root");
        let ancestry_root = temp.path().join("ancestry-root");
        fs::create_dir(&terminal_root).unwrap();
        fs::create_dir(&ancestry_root).unwrap();
        fs::write(terminal_root.join("payload.bin"), b"stable").unwrap();
        fs::write(ancestry_root.join("witness.bin"), b"distinct").unwrap();
        let campaign = CampaignRootCustody::capture(temp.path()).unwrap();
        let custody = ImmutableRootCustody::<2>::capture(
            &campaign,
            [terminal_root.as_path(), ancestry_root.as_path()],
        )
        .unwrap();

        for (root_index, expected) in [terminal_root.as_path(), ancestry_root.as_path()]
            .into_iter()
            .enumerate()
        {
            custody
                .with_root_descriptor(root_index, |descriptor| {
                    let stat = rustix::fs::fstat(descriptor)?;
                    let metadata = fs::metadata(expected)?;
                    anyhow::ensure!(
                        (stat.st_dev, stat.st_ino) == (metadata.dev(), metadata.ino()),
                        "retained immutable-root descriptor selected the wrong root"
                    );
                    Ok(())
                })
                .unwrap();
        }

        custody
            .with_root_descriptor(0, |descriptor| {
                let stat = rustix::fs::fstat(descriptor)?;
                anyhow::ensure!(
                    rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir(),
                    "retained immutable root is not a directory"
                );
                Ok(())
            })
            .unwrap();

        let entered = Cell::new(false);
        let error = custody
            .with_root_descriptor(2, |_descriptor| {
                entered.set(true);
                Ok(())
            })
            .unwrap_err();
        assert!(!entered.get());
        assert!(error.to_string().contains("outside the fixed root set"));

        let error = custody
            .with_root_descriptor(0, |_descriptor| -> anyhow::Result<()> {
                fs::write(terminal_root.join("payload.bin"), b"changed")?;
                anyhow::bail!("injected descriptor callback failure")
            })
            .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("postcheck also failed"), "{message}");
        assert!(
            message.contains("injected descriptor callback failure"),
            "{message}"
        );
        assert!(message.contains("immutable root"), "{message}");
    }

    #[cfg(all(target_os = "linux", feature = "b4-authoritative-build-custody"))]
    #[test]
    fn authoritative_build_adapter_rejects_missing_anchors_and_bad_root_index_first() {
        const SOURCE_COMMIT: &str = "1111111111111111111111111111111111111111";
        const SOURCE_TREE: &str = "2222222222222222222222222222222222222222";
        const EVIDENCE_ROOT: &str =
            "3333333333333333333333333333333333333333333333333333333333333333";

        let temp = tempfile::tempdir().unwrap();
        let immutable_root = temp.path().join("build-evidence");
        fs::create_dir(&immutable_root).unwrap();
        let campaign = CampaignRootCustody::capture(temp.path()).unwrap();
        let custody =
            ImmutableRootCustody::<1>::capture(&campaign, [immutable_root.as_path()]).unwrap();

        for missing_one in [
            eip_0045_reproduction::b4_build_check::B4BuildExpectations {
                expected_source_commit: None,
                expected_source_tree: Some(SOURCE_TREE),
                expected_evidence_root: Some(EVIDENCE_ROOT),
            },
            eip_0045_reproduction::b4_build_check::B4BuildExpectations {
                expected_source_commit: Some(SOURCE_COMMIT),
                expected_source_tree: None,
                expected_evidence_root: Some(EVIDENCE_ROOT),
            },
            eip_0045_reproduction::b4_build_check::B4BuildExpectations {
                expected_source_commit: Some(SOURCE_COMMIT),
                expected_source_tree: Some(SOURCE_TREE),
                expected_evidence_root: None,
            },
        ] {
            let missing_anchor_error = custody
                .authenticate_authoritative_b4_build_projection(0, &missing_one)
                .unwrap_err();
            assert!(
                missing_anchor_error
                    .to_string()
                    .contains("requires source commit, source tree, and evidence root anchors"),
                "{missing_anchor_error:#}"
            );
        }

        let anchored = eip_0045_reproduction::b4_build_check::B4BuildExpectations {
            expected_source_commit: Some(SOURCE_COMMIT),
            expected_source_tree: Some(SOURCE_TREE),
            expected_evidence_root: Some(EVIDENCE_ROOT),
        };
        let bad_index_error = custody
            .authenticate_authoritative_b4_build_projection(1, &anchored)
            .unwrap_err();
        assert!(
            bad_index_error
                .to_string()
                .contains("outside the fixed root set"),
            "{bad_index_error:#}"
        );
    }

    #[test]
    fn e5_fixed_descriptor_adapter_borrows_only_the_two_declared_roots() {
        let source = include_str!("custody.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let adapter = production
            .split("pub(super) fn close_negative_materialization_authority(")
            .nth(1)
            .unwrap()
            .split("/// Close the V2 proof operation")
            .next()
            .unwrap();

        assert_eq!(adapter.matches(".with_root_descriptor(").count(), 2);
        let terminal = adapter
            .find(".with_root_descriptor(terminal_campaign_root_index")
            .unwrap();
        let ancestry = adapter
            .find("self.with_root_descriptor(negative_ancestry_root_index")
            .unwrap();
        assert!(terminal < ancestry);
        assert!(
            adapter.contains("authenticate_b4_terminal_evidence_import_from_directory_descriptor(")
        );
        assert!(adapter.contains(
            "B4NegativeMaterializationSetAuthorityV1::from_descriptor_rooted_cryptographic_closure("
        ));
        assert_eq!(
            adapter
                .matches("generate_fixed_alternate_root_proof_bundle(")
                .count(),
            1
        );
        assert!(!adapter.contains("BorrowedFd"));
    }

    #[test]
    fn e5_v2_fixed_descriptor_adapter_borrows_only_the_two_declared_roots() {
        let source = include_str!("custody.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let adapter = production
            .split("pub(super) fn close_negative_materialization_authority_v2(")
            .nth(1)
            .unwrap()
            .split("/// Authenticate the V2 terminal packet")
            .next()
            .unwrap();

        assert_eq!(adapter.matches(".with_root_descriptor(").count(), 2);
        let terminal = adapter
            .find(".with_root_descriptor(terminal_campaign_root_index")
            .unwrap();
        let ancestry = adapter
            .find("self.with_root_descriptor(negative_ancestry_root_index")
            .unwrap();
        assert!(terminal < ancestry);
        assert!(
            adapter
                .contains("authenticate_b4_terminal_evidence_import_from_directory_descriptor_v2(")
        );
        assert!(adapter.contains(
            "B4NegativeMaterializationSetAuthorityV2::from_descriptor_rooted_cryptographic_closure_v2("
        ));
        assert_eq!(
            adapter
                .matches("generate_fixed_alternate_root_proof_bundle(")
                .count(),
            1
        );
        assert!(!adapter.contains("B4PositiveGenerationAuthorityV1"));
        assert!(!adapter.contains("B4TerminalSourceLineageAuthorityV1"));
        assert!(!adapter.contains("B4NegativeAncestryWitnessCatalogAuthorityV1"));
        assert!(!adapter.contains("BorrowedFd"));
    }

    #[test]
    fn e5_v2_terminal_import_adapter_borrows_only_the_terminal_root() {
        let source = include_str!("custody.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let adapter = production
            .split("pub(super) fn close_terminal_import_authority_v2(")
            .nth(1)
            .unwrap()
            .split("/// Validate one retained B4 build-evidence root")
            .next()
            .unwrap();

        assert_eq!(adapter.matches(".with_root_descriptor(").count(), 1);
        assert!(adapter.contains(".with_root_descriptor(terminal_campaign_root_index"));
        assert!(
            adapter
                .contains("authenticate_b4_terminal_evidence_import_from_directory_descriptor_v2(")
        );
        assert!(adapter.contains("Result<B4TerminalEvidenceImportAuthorityV2>"));
        assert!(!adapter.contains("negative_ancestry_root_index"));
        assert!(!adapter.contains("from_descriptor_rooted_cryptographic_closure"));
        assert!(!adapter.contains("generate_fixed_alternate_root_proof_bundle"));
        assert!(!adapter.contains("B4PositiveGenerationAuthorityV1"));
        assert!(!adapter.contains("B4TerminalSourceLineageAuthorityV1"));
        assert!(!adapter.contains("BorrowedFd"));
    }

    #[test]
    fn h3_build_projection_adapter_is_fixed_descriptor_rooted_and_feature_bound() {
        let source = include_str!("custody.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let adapter = production
            .split("pub(super) fn authenticate_authoritative_b4_build_projection(")
            .nth(1)
            .expect("missing H3 authoritative-build custody adapter")
            .split("/// Borrow one retained immutable-root descriptor")
            .next()
            .unwrap();

        assert_eq!(adapter.matches(".with_root_descriptor(").count(), 1);
        assert!(adapter.contains(".with_root_descriptor(root_index"));
        assert!(adapter.contains("validate_published_b4_build_from_directory_descriptor("));
        assert!(adapter.contains("authoritative_projection()"));
        assert!(adapter.contains("Result<AuthoritativeB4BuildProjection>"));
        assert!(!adapter.contains("BorrowedFd"));
        let anchors = adapter
            .find("expectations.expected_source_commit.is_some()")
            .unwrap();
        let descriptor = adapter.find(".with_root_descriptor(root_index").unwrap();
        assert!(anchors < descriptor);
        assert!(adapter.contains("expectations.expected_source_tree.is_some()"));
        assert!(adapter.contains("expectations.expected_evidence_root.is_some()"));

        let manifest = include_str!("../../Cargo.toml").replace("\r\n", "\n");
        let feature = manifest
            .split("b4-authoritative-build-custody = [")
            .nth(1)
            .unwrap()
            .split("\n]")
            .next()
            .unwrap();
        assert!(feature.contains("eip-0045-reproduction/b4-descriptor-build-check"));
    }
}
