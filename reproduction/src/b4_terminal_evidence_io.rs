//! Defensive reopening of measured B4 terminal-evidence packets.

#[cfg(not(any(unix, windows)))]
compile_error!("B4 terminal-evidence reopening supports only Unix and Windows");
#[cfg(all(unix, any(target_os = "espidf", target_os = "redox")))]
compile_error!(
    "B4 terminal-evidence reopening requires Unix openat and descriptor directory iteration"
);

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
use std::ffi::OsStr;
#[cfg(windows)]
use std::fs::{self, OpenOptions};
#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
use std::os::fd::AsRawFd as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read as _, Seek as _, SeekFrom},
    path::{Path, PathBuf},
};
#[cfg(unix)]
use std::{
    ffi::OsString,
    os::fd::{AsFd as _, BorrowedFd, OwnedFd},
    path::Component,
};

use anyhow::{Context as _, Result, ensure};
use sha2::{Digest as _, Sha256};

use crate::b4_campaign_contract::validate_safe_relative_path;
#[cfg(all(test, feature = "b4-terminal-evidence-publication", unix))]
use crate::b4_terminal_evidence_packet::B4MechanicalTerminalEvidencePublicationImageV1;
#[cfg(feature = "b4-terminal-evidence-publication")]
use crate::b4_terminal_evidence_packet::B4TerminalEvidencePacketPayloadsV1;
use crate::b4_terminal_evidence_packet::{
    B4_TERMINAL_EVIDENCE_COMPLETION_FILE, B4_TERMINAL_EVIDENCE_FILE_COUNT,
    B4_TERMINAL_EVIDENCE_MANIFEST_FILE, B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT,
    B4VerifiedTerminalEvidencePacketV1, COMPLETION_MAX_BYTES,
    Eip0045B4TerminalEvidenceCompletionV1, Eip0045B4TerminalEvidenceManifestV1, MANIFEST_MAX_BYTES,
    compiled_b4_terminal_evidence_role_table, mint_b4_verified_terminal_evidence_packet,
};
#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
use crate::b4_terminal_evidence_packet::{
    B4PreparedTerminalEvidencePublicationV1, prepare_b4_terminal_evidence_publication,
};

const B4_TERMINAL_EVIDENCE_PUBLICATION_STAGING_SUFFIX: &str =
    ".b4-terminal-evidence-publication-staging";
const MAX_B4_TERMINAL_EVIDENCE_PUBLICATION_FINAL_COMPONENT_BYTES: usize =
    255 - 1 - B4_TERMINAL_EVIDENCE_PUBLICATION_STAGING_SUFFIX.len();

/// Pure, non-authorizing projection of one terminal-evidence publication root.
///
/// Construction validates only the destination's portable final component.
/// It performs no filesystem access and does not reserve either path.
///
/// The projected paths are intentionally opaque and cannot be reconstructed
/// through public fields:
///
/// ```compile_fail
/// use std::path::PathBuf;
///
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     B4TerminalEvidencePublicationLayoutV1;
///
/// let _ = B4TerminalEvidencePublicationLayoutV1 {
///     final_path: PathBuf::from("packet"),
///     parent: PathBuf::from("."),
///     reserved_staging_path: PathBuf::from(".packet.staging"),
/// };
/// ```
///
/// Local publication paths are also deliberately non-serializable:
///
/// ```compile_fail
/// use std::path::Path;
///
/// use eip_0045_reproduction::b4_terminal_evidence_packet::
///     project_b4_terminal_evidence_publication_layout;
///
/// let layout =
///     project_b4_terminal_evidence_publication_layout(Path::new("packet"))?;
/// let _ = serde_json::to_vec(&layout)?;
/// # Ok::<(), anyhow::Error>(())
/// ```
pub struct B4TerminalEvidencePublicationLayoutV1 {
    final_path: PathBuf,
    parent: PathBuf,
    reserved_staging_path: PathBuf,
}

impl B4TerminalEvidencePublicationLayoutV1 {
    /// Intended final publication path.
    #[must_use]
    pub fn final_path(&self) -> &Path {
        &self.final_path
    }

    /// Ordinary parent which must physically exist for live publication.
    #[must_use]
    pub fn parent(&self) -> &Path {
        &self.parent
    }

    /// Reserved create-only staging sibling.
    #[must_use]
    pub fn reserved_staging_path(&self) -> &Path {
        &self.reserved_staging_path
    }
}

/// Project one deterministic final/parent/staging publication layout.
///
/// This helper is intentionally pure so a future outer staging hierarchy can
/// be checked before that hierarchy exists. Live preflight remains responsible
/// for every physical filesystem and no-replace capability check.
///
/// # Errors
///
/// Returns an error unless the destination has one UTF-8 portable final
/// component admitted by the campaign path grammar.
pub fn project_b4_terminal_evidence_publication_layout(
    destination: &Path,
) -> Result<B4TerminalEvidencePublicationLayoutV1> {
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .context("terminal-evidence destination must have a portable final component")?;
    validate_publication_final_component(name)?;
    let parent = usable_publication_parent(destination).to_path_buf();
    Ok(publication_layout_from_parent_and_component(
        parent,
        name,
        destination.to_path_buf(),
    ))
}

fn validate_publication_final_component(name: &str) -> Result<()> {
    validate_safe_relative_path(name)
        .context("terminal-evidence destination final component is not portable")?;
    ensure!(
        !name.contains('/'),
        "terminal-evidence destination must have exactly one final component"
    );
    ensure!(
        name.len() <= MAX_B4_TERMINAL_EVIDENCE_PUBLICATION_FINAL_COMPONENT_BYTES,
        "terminal-evidence destination final component exceeds the 213-byte derived staging bound"
    );
    Ok(())
}

fn publication_layout_from_parent_and_component(
    parent: PathBuf,
    name: &str,
    final_path: PathBuf,
) -> B4TerminalEvidencePublicationLayoutV1 {
    let reserved_staging_path = parent.join(format!(
        ".{name}{B4_TERMINAL_EVIDENCE_PUBLICATION_STAGING_SUFFIX}"
    ));
    B4TerminalEvidencePublicationLayoutV1 {
        final_path,
        parent,
        reserved_staging_path,
    }
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
fn project_descriptor_rooted_b4_terminal_evidence_publication_layout(
    final_component: &str,
) -> Result<B4TerminalEvidencePublicationLayoutV1> {
    validate_publication_final_component(final_component)?;
    let parent = PathBuf::from("<retained-publication-parent-descriptor>");
    let final_path = parent.join(final_component);
    Ok(publication_layout_from_parent_and_component(
        parent,
        final_component,
        final_path,
    ))
}

/// Reopen one exact, stable terminal-evidence packet and verify its semantics.
///
/// # Errors
///
/// Returns an error unless the path is an exact ordinary 31-file packet whose
/// files remain identity-, length-, and digest-stable through all snapshots and
/// whose payloads pass the compiled semantic verifier.
pub fn reopen_b4_terminal_evidence_packet(
    root: &Path,
) -> Result<B4VerifiedTerminalEvidencePacketV1> {
    #[cfg(unix)]
    {
        let pinned = PinnedUnixDirectoryPath::open(root, "terminal-evidence packet root")?;
        let result = reopen_b4_terminal_evidence_packet_from_descriptor(
            pinned.descriptor(),
            root,
            &mut |_event, _path| {},
        )?;
        pinned.reauthenticate()?;
        Ok(result)
    }
    #[cfg(windows)]
    {
        reopen_b4_terminal_evidence_packet_impl(root, &mut |_event, _path| {})
    }
}

/// Reopen one exact terminal-evidence packet from an already retained Unix
/// directory descriptor.
///
/// This entry does not resolve the packet root through a pathname. All
/// descendant opens and semantic verification remain rooted at `root`.
///
/// # Errors
///
/// Returns an error unless `root` names an exact ordinary 31-file packet whose
/// retained bytes pass the complete compiled semantic verifier.
#[doc(hidden)]
#[cfg(unix)]
pub fn reopen_b4_terminal_evidence_packet_from_directory_descriptor(
    root: BorrowedFd<'_>,
) -> Result<B4VerifiedTerminalEvidencePacketV1> {
    reopen_b4_terminal_evidence_packet_from_descriptor(
        root,
        Path::new("<retained-terminal-evidence-directory>"),
        &mut |_event, _path| {},
    )
}

/// Check whether a destination can support one create-only publication.
///
/// The check is non-reserving. A successful publication repeats it before
/// preparing or writing any packet bytes.
///
/// # Errors
///
/// Returns an error on non-Unix platforms, for an occupied destination or
/// reserved staging root, for an untrusted parent path, or when the parent
/// filesystem lacks atomic no-replace rename support.
#[cfg(feature = "b4-terminal-evidence-publication")]
pub fn preflight_b4_terminal_evidence_publication(destination: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let layout = project_b4_terminal_evidence_publication_layout(destination)?;
        let _pinned = preflight_b4_terminal_evidence_publication_unix(&layout, None)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = destination;
        anyhow::bail!(
            "B4 terminal-evidence publication is unsupported on this platform; Unix atomic no-replace rename semantics are required"
        )
    }
}

/// Check whether one component beneath an already retained Unix parent
/// descriptor can support one create-only publication.
///
/// The check is non-reserving and does not publish or prepare packet payloads.
/// A later publication repeats the same live preflight before preparing or
/// writing any packet bytes.
///
/// # Errors
///
/// Returns an error on unsupported Unix platforms, for an invalid or occupied
/// final component or reserved staging root, or when the retained parent
/// filesystem lacks atomic no-replace rename support.
#[doc(hidden)]
#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
pub fn preflight_b4_terminal_evidence_publication_from_directory_descriptor(
    parent: BorrowedFd<'_>,
    final_component: &str,
) -> Result<()> {
    let layout =
        project_descriptor_rooted_b4_terminal_evidence_publication_layout(final_component)?;
    let _pinned =
        preflight_b4_terminal_evidence_publication_from_descriptor(&layout, parent, None)?;
    Ok(())
}

/// Publish one consumer-verified terminal-evidence packet exactly once.
///
/// # Errors
///
/// Returns an error on unsupported platforms, on semantic preparation failure,
/// when any create-only or durability transition fails, or when the final
/// cryptographic reopen differs from the staged identity. Once created,
/// staging is retained on failure for forensic recovery and is never resumed.
#[cfg(feature = "b4-terminal-evidence-publication")]
pub fn publish_b4_terminal_evidence_packet(
    destination: &Path,
    payloads: B4TerminalEvidencePacketPayloadsV1<'_>,
) -> Result<B4VerifiedTerminalEvidencePacketV1> {
    #[cfg(unix)]
    {
        let layout = project_b4_terminal_evidence_publication_layout(destination)?;
        let parent = preflight_b4_terminal_evidence_publication_unix(&layout, None)?;
        let prepared = prepare_b4_terminal_evidence_publication(payloads)?;
        match publish_prepared_b4_terminal_evidence_transaction(
            &layout,
            &parent,
            PublicationImage::Prepared(&prepared),
            None,
            PublicationReopenMode::Full(std::marker::PhantomData),
            #[cfg(test)]
            None,
        )? {
            PublicationReopenedPacket::Full(authority) => Ok(authority),
            #[cfg(test)]
            PublicationReopenedPacket::Mechanical(_) => {
                unreachable!("public publication cannot use the test-only mechanical reopen seam")
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (destination, payloads);
        anyhow::bail!(
            "B4 terminal-evidence publication is unsupported on this platform; Unix atomic no-replace rename semantics are required"
        )
    }
}

/// Publish one consumer-verified terminal-evidence packet exactly once beneath
/// an already retained Unix parent-directory descriptor.
///
/// `final_component` is one portable component, not a relative path. The
/// parent is never resolved or reauthenticated through a pathname. The atomic
/// capability probe may use the platform's diagnostic descriptor path, while
/// staging creation, writes, commit, durability, and semantic reopening remain
/// descriptor-relative.
///
/// # Errors
///
/// Returns an error on unsupported Unix platforms, for an invalid or occupied
/// final component, on semantic preparation failure, when any create-only or
/// durability transition fails, or when the final cryptographic reopen differs
/// from the staged identity.
#[doc(hidden)]
#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
pub fn publish_b4_terminal_evidence_packet_from_directory_descriptor(
    parent: BorrowedFd<'_>,
    final_component: &str,
    payloads: B4TerminalEvidencePacketPayloadsV1<'_>,
) -> Result<B4VerifiedTerminalEvidencePacketV1> {
    let layout =
        project_descriptor_rooted_b4_terminal_evidence_publication_layout(final_component)?;
    let parent = preflight_b4_terminal_evidence_publication_from_descriptor(&layout, parent, None)?;
    let prepared = prepare_b4_terminal_evidence_publication(payloads)?;
    match publish_prepared_b4_terminal_evidence_transaction(
        &layout,
        &parent,
        PublicationImage::Prepared(&prepared),
        None,
        PublicationReopenMode::Full(std::marker::PhantomData),
        #[cfg(test)]
        None,
    )? {
        PublicationReopenedPacket::Full(authority) => Ok(authority),
        #[cfg(test)]
        PublicationReopenedPacket::Mechanical(_) => {
            unreachable!("public publication cannot use the test-only mechanical reopen seam")
        }
    }
}

#[cfg(all(test, feature = "b4-terminal-evidence-publication", unix))]
fn publish_b4_terminal_evidence_packet_with_test_preflight_fault(
    destination: &Path,
    payloads: B4TerminalEvidencePacketPayloadsV1<'_>,
    fault: PublicationTestFault<'_>,
) -> Result<()> {
    let layout = project_b4_terminal_evidence_publication_layout(destination)?;
    let _pinned = preflight_b4_terminal_evidence_publication_unix(&layout, Some(fault))?;
    let _prepared = prepare_b4_terminal_evidence_publication(payloads)?;
    anyhow::bail!("test-only publication preflight fault unexpectedly allowed preparation")
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublicationPacketIdentity {
    manifest_byte_length: u64,
    packet_id: [u8; 32],
}

#[cfg(all(test, feature = "b4-terminal-evidence-publication", unix))]
type MechanicalPacketIdentity = PublicationPacketIdentity;

#[cfg(all(test, feature = "b4-terminal-evidence-publication", unix))]
struct PublicationTestReopenSeam<'a> {
    staged: &'a mut dyn FnMut(&Path) -> Result<MechanicalPacketIdentity>,
    final_reopen: &'a mut dyn FnMut(&Path) -> Result<MechanicalPacketIdentity>,
}

#[cfg(all(test, feature = "b4-terminal-evidence-publication", unix))]
struct PublicationTestPause {
    reached: std::sync::Barrier,
    resume: std::sync::Barrier,
}

#[cfg(all(test, feature = "b4-terminal-evidence-publication", unix))]
impl PublicationTestPause {
    fn new() -> Self {
        Self {
            reached: std::sync::Barrier::new(2),
            resume: std::sync::Barrier::new(2),
        }
    }

    fn pause_publisher(&self) {
        self.reached.wait();
        self.resume.wait();
    }

    fn wait_until_reached(&self) {
        self.reached.wait();
    }

    fn resume(&self) {
        self.resume.wait();
    }
}

#[cfg(all(test, feature = "b4-terminal-evidence-publication", unix))]
#[derive(Clone, Copy)]
enum PublicationTestFault<'a> {
    AtomicUnsupported,
    Barrier(&'a std::sync::Barrier),
    AfterParentPinned(&'a PublicationTestPause),
    StagingCreate,
    BeforePayloadOpen(usize, &'a PublicationTestPause),
    PayloadWrite(usize),
    ManifestWrite,
    CompletionWrite,
    FileSync(usize),
    StagedReopen,
    BeforeStagedPhysicalClosure(&'a PublicationTestPause),
    DirectorySync(usize),
    BeforeExclusiveRename(&'a PublicationTestPause),
    FinalFileSyncAfterBeforeRename(&'a PublicationTestPause, &'a str),
    AfterExclusiveRename(&'a PublicationTestPause),
    RaceWinner(&'a B4MechanicalTerminalEvidencePublicationImageV1),
    ParentSync,
    FinalReopen,
    BeforeFinalParentReauthentication(&'a PublicationTestPause),
    FinalDirectorySync(usize),
    BeforeDurableFinalPhysicalClosure(&'a PublicationTestPause),
    AfterFinalPhysicalClosure(&'a PublicationTestPause),
}

#[cfg(all(test, feature = "b4-terminal-evidence-publication", unix))]
#[derive(Clone, Debug, Eq, PartialEq)]
enum PublicationTestTransition {
    ParentPinned,
    PayloadSynced(usize),
    ManifestSynced,
    CompletionSynced,
    StagedReopened,
    DirectorySynced(String),
    ReadyToExclusiveRename,
    ExclusiveRenamed,
    ParentSynced,
    FinalReopened,
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
enum PublicationReopenMode<'a> {
    Full(std::marker::PhantomData<&'a ()>),
    #[cfg(test)]
    Mechanical(PublicationTestReopenSeam<'a>),
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
enum PublicationImage<'a> {
    Prepared(&'a B4PreparedTerminalEvidencePublicationV1),
    #[cfg(test)]
    Mechanical(&'a B4MechanicalTerminalEvidencePublicationImageV1),
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
impl PublicationImage<'_> {
    fn visit_payloads(&self, visit: impl FnMut(&str, &[u8]) -> Result<()>) -> Result<()> {
        match self {
            Self::Prepared(prepared) => prepared.visit_payloads(visit),
            #[cfg(test)]
            Self::Mechanical(mechanical) => mechanical.visit_payloads(visit),
        }
    }

    fn manifest_bytes(&self) -> &[u8] {
        match self {
            Self::Prepared(prepared) => prepared.manifest_bytes(),
            #[cfg(test)]
            Self::Mechanical(mechanical) => mechanical.manifest_bytes(),
        }
    }

    fn completion_bytes(&self) -> &[u8] {
        match self {
            Self::Prepared(prepared) => prepared.completion_bytes(),
            #[cfg(test)]
            Self::Mechanical(mechanical) => mechanical.completion_bytes(),
        }
    }
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
enum PublicationReopenedPacket {
    Full(B4VerifiedTerminalEvidencePacketV1),
    #[cfg(test)]
    Mechanical(MechanicalPacketIdentity),
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
impl PublicationReopenedPacket {
    fn identity(&self) -> PublicationPacketIdentity {
        match self {
            Self::Full(authority) => PublicationPacketIdentity {
                manifest_byte_length: authority.manifest_byte_length(),
                packet_id: authority.packet_id(),
            },
            #[cfg(test)]
            Self::Mechanical(identity) => *identity,
        }
    }
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
fn preflight_b4_terminal_evidence_publication_unix(
    layout: &B4TerminalEvidencePublicationLayoutV1,
    #[cfg(test)] fault: Option<PublicationTestFault<'_>>,
    #[cfg(not(test))] _fault: Option<()>,
) -> Result<PinnedPublicationParent> {
    ensure_supported_publication_platform()?;
    let parent = PinnedPublicationParent::open(layout)?;
    preflight_pinned_b4_terminal_evidence_publication(
        layout,
        parent,
        #[cfg(test)]
        fault,
        #[cfg(not(test))]
        None,
    )
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
fn preflight_b4_terminal_evidence_publication_from_descriptor(
    layout: &B4TerminalEvidencePublicationLayoutV1,
    parent: BorrowedFd<'_>,
    #[cfg(test)] fault: Option<PublicationTestFault<'_>>,
    #[cfg(not(test))] _fault: Option<()>,
) -> Result<PinnedPublicationParent> {
    ensure_supported_publication_platform()?;
    let parent = PinnedPublicationParent::from_directory_descriptor(layout, parent)?;
    preflight_pinned_b4_terminal_evidence_publication(
        layout,
        parent,
        #[cfg(test)]
        fault,
        #[cfg(not(test))]
        None,
    )
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
fn preflight_pinned_b4_terminal_evidence_publication(
    layout: &B4TerminalEvidencePublicationLayoutV1,
    parent: PinnedPublicationParent,
    #[cfg(test)] fault: Option<PublicationTestFault<'_>>,
    #[cfg(not(test))] _fault: Option<()>,
) -> Result<PinnedPublicationParent> {
    let atomic = parent.with_reauthenticated_descriptor(layout, |descriptor| {
        let probe_root = publication_descriptor_path(descriptor)?;
        #[cfg(test)]
        {
            if matches!(fault, Some(PublicationTestFault::AtomicUnsupported)) {
                Ok(false)
            } else {
                renamore::rename_exclusive_is_atomic(&probe_root).with_context(|| {
                    format!(
                        "cannot establish atomic no-replace support for {}",
                        layout.parent().display()
                    )
                })
            }
        }
        #[cfg(not(test))]
        {
            renamore::rename_exclusive_is_atomic(&probe_root).with_context(|| {
                format!(
                    "cannot establish atomic no-replace support for {}",
                    layout.parent().display()
                )
            })
        }
    })?;
    ensure!(
        atomic,
        "{} does not support atomic no-replace publication",
        layout.parent().display()
    );
    parent.ensure_absent(
        layout,
        &parent.final_name,
        layout.final_path(),
        "publication destination",
    )?;
    parent.ensure_absent(
        layout,
        &parent.staging_name,
        layout.reserved_staging_path(),
        "reserved publication staging",
    )?;
    Ok(parent)
}

fn usable_publication_parent(path: &Path) -> &Path {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    }
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
fn unix_publication_platform_supported(target_os: &str, apple_vendor: bool) -> bool {
    target_os == "linux" || apple_vendor
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
fn ensure_supported_publication_platform() -> Result<()> {
    ensure!(
        unix_publication_platform_supported(std::env::consts::OS, cfg!(target_vendor = "apple")),
        "B4 terminal-evidence publication is unsupported on this Unix platform; descriptor-relative atomic no-replace rename is required"
    );
    Ok(())
}

#[cfg(unix)]
const PINNED_UNIX_DIRECTORY_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY
    .union(rustix::fs::OFlags::DIRECTORY)
    .union(rustix::fs::OFlags::NOFOLLOW)
    .union(rustix::fs::OFlags::CLOEXEC);

#[cfg(unix)]
const PINNED_UNIX_FILE_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY
    .union(rustix::fs::OFlags::NOFOLLOW)
    .union(rustix::fs::OFlags::NONBLOCK)
    .union(rustix::fs::OFlags::CLOEXEC);

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
const PUBLICATION_FILE_FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::WRONLY
    .union(rustix::fs::OFlags::CREATE)
    .union(rustix::fs::OFlags::EXCL)
    .union(rustix::fs::OFlags::NOFOLLOW)
    .union(rustix::fs::OFlags::CLOEXEC);

#[cfg(unix)]
struct PinnedUnixDirectoryPath {
    anchor: OwnedFd,
    anchor_identity: PlatformDirectoryIdentity,
    components: Vec<OsString>,
    descriptors: Vec<OwnedFd>,
    identities: Vec<PlatformDirectoryIdentity>,
    diagnostic_path: PathBuf,
}

#[cfg(unix)]
impl PinnedUnixDirectoryPath {
    fn open(path: &Path, label: &str) -> Result<Self> {
        ensure!(!path.as_os_str().is_empty(), "{label} path is empty");
        let absolute = path.is_absolute();
        let anchor_path = if absolute {
            Path::new("/")
        } else {
            Path::new(".")
        };
        let anchor = rustix::fs::open(
            anchor_path,
            PINNED_UNIX_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
        )
        .with_context(|| format!("cannot pin {label} anchor"))?;
        let anchor_identity = platform_directory_identity(&anchor)?;

        let mut components = Vec::new();
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(component) => components.push(component.to_os_string()),
                Component::ParentDir => {
                    anyhow::bail!("{label} path contains a parent traversal")
                }
                Component::Prefix(_) => {
                    anyhow::bail!("{label} path contains an unsupported prefix")
                }
            }
        }

        let mut descriptors = Vec::new();
        let mut identities = Vec::new();
        descriptors
            .try_reserve_exact(components.len())
            .with_context(|| format!("cannot retain {label} descriptors"))?;
        identities
            .try_reserve_exact(components.len())
            .with_context(|| format!("cannot retain {label} identities"))?;
        for (index, component) in components.iter().enumerate() {
            let parent = descriptors
                .last()
                .map_or_else(|| anchor.as_fd(), OwnedFd::as_fd);
            let descriptor = rustix::fs::openat(
                parent,
                component.as_os_str(),
                PINNED_UNIX_DIRECTORY_FLAGS,
                rustix::fs::Mode::empty(),
            )
            .with_context(|| {
                format!(
                    "cannot pin {label} component {index} beneath {}",
                    path.display()
                )
            })?;
            identities.push(platform_directory_identity(&descriptor)?);
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
        self.with_reauthenticated_descriptor(|_descriptor| Ok(()))
    }

    fn with_reauthenticated_descriptor<T>(
        &self,
        use_descriptor: impl FnOnce(BorrowedFd<'_>) -> Result<T>,
    ) -> Result<T> {
        ensure!(
            platform_directory_identity(&self.anchor)? == self.anchor_identity,
            "pinned directory anchor identity changed for {}",
            self.diagnostic_path.display()
        );
        for (index, (descriptor, identity)) in
            self.descriptors.iter().zip(&self.identities).enumerate()
        {
            ensure!(
                platform_directory_identity(descriptor)? == *identity,
                "retained directory component {index} changed for {}",
                self.diagnostic_path.display()
            );
        }

        let reopened_anchor = rustix::fs::openat(
            self.anchor.as_fd(),
            ".",
            PINNED_UNIX_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
        )
        .with_context(|| {
            format!(
                "cannot re-open directory anchor for {}",
                self.diagnostic_path.display()
            )
        })?;
        ensure!(
            platform_directory_identity(&reopened_anchor)? == self.anchor_identity,
            "directory anchor no longer names the pinned identity for {}",
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
            let descriptor = rustix::fs::openat(
                parent,
                component.as_os_str(),
                PINNED_UNIX_DIRECTORY_FLAGS,
                rustix::fs::Mode::empty(),
            )
            .with_context(|| {
                format!(
                    "cannot re-open directory component {index} for {}",
                    self.diagnostic_path.display()
                )
            })?;
            ensure!(
                platform_directory_identity(&descriptor)? == *identity,
                "directory component {index} no longer names the pinned identity for {}",
                self.diagnostic_path.display()
            );
            reopened.push(descriptor);
        }
        let descriptor = reopened
            .last()
            .map_or_else(|| reopened_anchor.as_fd(), OwnedFd::as_fd);
        use_descriptor(descriptor)
    }
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
enum PublicationParentAuthority {
    Path(PinnedUnixDirectoryPath),
    RetainedDescriptor {
        descriptor: OwnedFd,
        identity: PlatformDirectoryIdentity,
    },
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
struct PinnedPublicationParent {
    authority: PublicationParentAuthority,
    final_name: OsString,
    staging_name: OsString,
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
impl PinnedPublicationParent {
    fn open(layout: &B4TerminalEvidencePublicationLayoutV1) -> Result<Self> {
        let final_name = layout
            .final_path()
            .file_name()
            .context("publication destination has no final component")?
            .to_os_string();
        let staging_name = layout
            .reserved_staging_path()
            .file_name()
            .context("reserved publication staging has no final component")?
            .to_os_string();
        Ok(Self {
            authority: PublicationParentAuthority::Path(PinnedUnixDirectoryPath::open(
                layout.parent(),
                "terminal-evidence publication parent",
            )?),
            final_name,
            staging_name,
        })
    }

    fn from_directory_descriptor(
        layout: &B4TerminalEvidencePublicationLayoutV1,
        parent: BorrowedFd<'_>,
    ) -> Result<Self> {
        let identity = platform_directory_identity(parent)
            .context("cannot authenticate retained publication parent descriptor")?;
        let descriptor = rustix::fs::openat(
            parent,
            ".",
            PINNED_UNIX_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
        )
        .context("cannot retain publication parent directory descriptor")?;
        ensure!(
            platform_directory_identity(&descriptor)? == identity,
            "retained publication parent changed while acquiring its descriptor"
        );
        ensure!(
            platform_directory_identity(parent)? == identity,
            "borrowed publication parent identity changed while acquiring its descriptor"
        );
        let final_name = layout
            .final_path()
            .file_name()
            .context("publication destination has no final component")?
            .to_os_string();
        let staging_name = layout
            .reserved_staging_path()
            .file_name()
            .context("reserved publication staging has no final component")?
            .to_os_string();
        Ok(Self {
            authority: PublicationParentAuthority::RetainedDescriptor {
                descriptor,
                identity,
            },
            final_name,
            staging_name,
        })
    }

    fn descriptor(&self) -> BorrowedFd<'_> {
        match &self.authority {
            PublicationParentAuthority::Path(path) => path.descriptor(),
            PublicationParentAuthority::RetainedDescriptor { descriptor, .. } => descriptor.as_fd(),
        }
    }

    fn reauthenticate(&self, layout: &B4TerminalEvidencePublicationLayoutV1) -> Result<()> {
        let result = match &self.authority {
            PublicationParentAuthority::Path(path) => path.reauthenticate(),
            PublicationParentAuthority::RetainedDescriptor {
                descriptor,
                identity,
            } => {
                ensure!(
                    platform_directory_identity(descriptor)? == *identity,
                    "retained publication parent descriptor identity changed"
                );
                Ok(())
            }
        };
        result.with_context(|| {
            format!(
                "publication parent {} no longer names the pinned directory",
                layout.parent().display()
            )
        })
    }

    fn with_reauthenticated_descriptor<T>(
        &self,
        layout: &B4TerminalEvidencePublicationLayoutV1,
        use_descriptor: impl FnOnce(BorrowedFd<'_>) -> Result<T>,
    ) -> Result<T> {
        self.reauthenticate(layout)?;
        let transition = match &self.authority {
            PublicationParentAuthority::Path(path) => {
                path.with_reauthenticated_descriptor(use_descriptor)
            }
            PublicationParentAuthority::RetainedDescriptor { descriptor, .. } => {
                use_descriptor(descriptor.as_fd())
            }
        };
        let reauthenticated = self.reauthenticate(layout);
        match (transition, reauthenticated) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error)
                .context("publication parent failed post-transition descriptor reauthentication"),
            (Err(error), Err(reauthentication_error)) => Err(error).context(format!(
                "publication parent also failed post-transition descriptor reauthentication: {reauthentication_error:#}"
            )),
        }
    }

    fn ensure_absent(
        &self,
        layout: &B4TerminalEvidencePublicationLayoutV1,
        name: &OsStr,
        diagnostic: &Path,
        label: &str,
    ) -> Result<()> {
        self.with_reauthenticated_descriptor(layout, |descriptor| {
            Self::ensure_absent_from(descriptor, name, diagnostic, label)
        })
    }

    fn ensure_absent_from(
        descriptor: BorrowedFd<'_>,
        name: &OsStr,
        diagnostic: &Path,
        label: &str,
    ) -> Result<()> {
        match rustix::fs::statat(descriptor, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => Ok(()),
            Err(error) => Err(anyhow::Error::from(error))
                .with_context(|| format!("cannot inspect {label} {}", diagnostic.display())),
            Ok(_) => anyhow::bail!("{label} is already occupied: {}", diagnostic.display()),
        }
    }

    fn named_directory_identity(
        &self,
        name: &OsStr,
        diagnostic: &Path,
    ) -> Result<Option<PlatformDirectoryIdentity>> {
        Self::named_directory_identity_from(self.descriptor(), name, diagnostic)
    }

    fn named_directory_identity_from(
        descriptor: BorrowedFd<'_>,
        name: &OsStr,
        diagnostic: &Path,
    ) -> Result<Option<PlatformDirectoryIdentity>> {
        match rustix::fs::statat(descriptor, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => Ok(None),
            Err(error) => Err(anyhow::Error::from(error)).with_context(|| {
                format!(
                    "cannot inspect publication directory {}",
                    diagnostic.display()
                )
            }),
            Ok(stat) => {
                if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir() {
                    return Ok(None);
                }
                Ok(Some(platform_directory_identity_from_stat(&stat)?))
            }
        }
    }

    fn open_named_directory(&self, name: &OsStr, diagnostic: &Path) -> Result<OwnedFd> {
        Self::open_named_directory_from(self.descriptor(), name, diagnostic)
    }

    fn open_named_directory_from(
        descriptor: BorrowedFd<'_>,
        name: &OsStr,
        diagnostic: &Path,
    ) -> Result<OwnedFd> {
        rustix::fs::openat(
            descriptor,
            name,
            PINNED_UNIX_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
        )
        .with_context(|| {
            format!(
                "cannot open pinned publication directory {}",
                diagnostic.display()
            )
        })
    }
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
fn publication_descriptor_path(descriptor: BorrowedFd<'_>) -> Result<PathBuf> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        Ok(PathBuf::from(format!("/proc/self/fd/{}", descriptor.as_raw_fd())).join("."))
    }
    #[cfg(target_vendor = "apple")]
    {
        Ok(PathBuf::from(format!("/dev/fd/{}", descriptor.as_raw_fd())).join("."))
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
    {
        let _ = descriptor;
        anyhow::bail!("descriptor diagnostic paths are unsupported on this Unix platform")
    }
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
#[derive(Clone, Copy, Eq, PartialEq)]
struct PublicationPhysicalFileSnapshot {
    identity: PlatformFileIdentity,
    sha256: [u8; 32],
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
struct RetainedPublicationFile {
    diagnostic: PathBuf,
    file: File,
    snapshot: PublicationPhysicalFileSnapshot,
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
struct PublicationPhysicalClosure {
    directory_identities: BTreeMap<String, PlatformDirectoryIdentity>,
    file_snapshots: BTreeMap<String, PublicationPhysicalFileSnapshot>,
    paths: BTreeSet<String>,
    tree: PinnedTerminalEvidenceDirectoryTree,
    retained_files: BTreeMap<String, RetainedPublicationFile>,
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
impl PublicationPhysicalClosure {
    fn measure(
        root: BorrowedFd<'_>,
        diagnostic_root: &Path,
        expected_files: &BTreeMap<String, PublicationPhysicalFileSnapshot>,
    ) -> Result<Self> {
        let paths = expected_files.keys().cloned().collect::<BTreeSet<_>>();
        let tree = PinnedTerminalEvidenceDirectoryTree::open(root, diagnostic_root, &paths)?;
        let mut file_snapshots = BTreeMap::new();
        let mut retained_files = BTreeMap::new();
        for (relative, expected) in expected_files {
            let maximum = usize::try_from(expected.identity.byte_length)
                .context("publication file length overflows usize")?;
            let (file, snapshot, diagnostic) = tree.open_and_read_file(relative, maximum)?;
            ensure!(
                snapshot.byte_length == expected.identity.byte_length
                    && snapshot.sha256 == expected.sha256,
                "{relative} differs from the bytes written by the publisher"
            );
            let measured = PublicationPhysicalFileSnapshot {
                identity: snapshot.final_identity,
                sha256: snapshot.sha256,
            };
            ensure!(
                file_snapshots.insert(relative.clone(), measured).is_none(),
                "duplicate publication physical-closure path"
            );
            ensure!(
                retained_files
                    .insert(
                        relative.clone(),
                        RetainedPublicationFile {
                            diagnostic,
                            file,
                            snapshot: measured,
                        },
                    )
                    .is_none(),
                "duplicate retained publication physical-closure path"
            );
        }
        tree.reauthenticate(&paths)
            .context("publication physical closure changed during measurement")?;
        for (relative, measured) in &file_snapshots {
            let maximum = usize::try_from(measured.identity.byte_length)
                .context("publication physical-closure length overflows usize")?;
            let reopened = tree
                .read_one_opened_file(relative, maximum)
                .with_context(|| {
                    format!("{relative} changed after physical-closure measurement")
                })?;
            ensure!(
                reopened.final_identity == measured.identity && reopened.sha256 == measured.sha256,
                "{relative} changed after physical-closure measurement"
            );
        }
        tree.reauthenticate(&paths)
            .context("publication physical closure changed after file revalidation")?;
        let directory_identities = tree.identities.clone();
        Ok(Self {
            directory_identities,
            file_snapshots,
            paths,
            tree,
            retained_files,
        })
    }

    fn names_the_same_objects_as(&self, other: &Self) -> bool {
        self.directory_identities == other.directory_identities
            && self.file_snapshots == other.file_snapshots
    }

    fn reauthenticate(&mut self) -> Result<()> {
        ensure!(
            self.file_snapshots.keys().eq(self.paths.iter())
                && self.retained_files.keys().eq(self.paths.iter()),
            "publication physical-closure file custody is incomplete"
        );
        self.tree.reauthenticate(&self.paths)?;
        for (relative, retained) in &mut self.retained_files {
            let maximum = usize::try_from(retained.snapshot.identity.byte_length)
                .context("publication physical-closure length overflows usize")?;
            let retained_snapshot =
                read_opened_file(&retained.diagnostic, &mut retained.file, maximum).with_context(
                    || format!("{relative} retained handle changed before authority"),
                )?;
            ensure!(
                retained_snapshot.final_identity == retained.snapshot.identity
                    && retained_snapshot.sha256 == retained.snapshot.sha256,
                "{relative} retained handle changed before authority"
            );
            let named_snapshot = self
                .tree
                .read_one_opened_file(relative, maximum)
                .with_context(|| format!("{relative} named file changed before authority"))?;
            ensure!(
                named_snapshot.final_identity == retained.snapshot.identity
                    && named_snapshot.sha256 == retained.snapshot.sha256,
                "{relative} named file changed before authority"
            );
            let repeated_retained_snapshot =
                read_opened_file(&retained.diagnostic, &mut retained.file, maximum).with_context(
                    || format!("{relative} retained handle changed during named reauthentication"),
                )?;
            ensure!(
                repeated_retained_snapshot.final_identity == retained.snapshot.identity
                    && repeated_retained_snapshot.sha256 == retained.snapshot.sha256,
                "{relative} retained handle changed during named reauthentication"
            );
        }
        self.tree
            .reauthenticate(&self.paths)
            .context("publication directory tree changed during final file reauthentication")
    }
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
struct PublicationDirectoryTree {
    root: OwnedFd,
    root_identity: PlatformDirectoryIdentity,
    diagnostic_root: PathBuf,
    directories: BTreeMap<String, OwnedFd>,
    directory_identities: BTreeMap<String, PlatformDirectoryIdentity>,
    directory_order: Vec<String>,
    files: BTreeMap<String, RetainedPublicationFile>,
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
impl PublicationDirectoryTree {
    fn create(
        parent: &PinnedPublicationParent,
        name: &OsStr,
        diagnostic_root: &Path,
    ) -> Result<Self> {
        if let Err(error) = rustix::fs::mkdirat(parent.descriptor(), name, rustix::fs::Mode::RWXU) {
            let error = anyhow::Error::from(error);
            if error
                .downcast_ref::<rustix::io::Errno>()
                .is_some_and(|errno| *errno == rustix::io::Errno::EXIST)
            {
                return Err(error).context(format!(
                    "terminal-evidence publication occupation: path is occupied at {}",
                    diagnostic_root.display()
                ));
            }
            return Err(error).with_context(|| {
                format!(
                    "cannot create publication directory {}",
                    diagnostic_root.display()
                )
            });
        }
        let root = parent.open_named_directory(name, diagnostic_root)?;
        let root_identity = platform_directory_identity(&root)?;
        ensure!(
            parent.named_directory_identity(name, diagnostic_root)? == Some(root_identity),
            "created publication directory identity changed before it was pinned"
        );
        let mut directory_identities = BTreeMap::new();
        ensure!(
            directory_identities
                .insert(String::new(), root_identity)
                .is_none(),
            "duplicate publication root identity"
        );
        Ok(Self {
            root,
            root_identity,
            diagnostic_root: diagnostic_root.to_path_buf(),
            directories: BTreeMap::new(),
            directory_identities,
            directory_order: Vec::new(),
            files: BTreeMap::new(),
        })
    }

    fn descriptor(&self) -> BorrowedFd<'_> {
        self.root.as_fd()
    }

    fn directory_descriptor(&self, relative: &str) -> Result<BorrowedFd<'_>> {
        if relative.is_empty() {
            Ok(self.descriptor())
        } else {
            self.directories
                .get(relative)
                .map(OwnedFd::as_fd)
                .with_context(|| format!("publication directory descriptor is missing {relative}"))
        }
    }

    fn create_payload_parent_directories(
        &mut self,
        relative: &str,
    ) -> Result<(String, OsString, PathBuf)> {
        let relative_path = portable_path(relative)?;
        let components = relative_path.components().collect::<Vec<_>>();
        ensure!(
            !components.is_empty(),
            "compiled terminal-evidence payload path is empty"
        );
        let mut parent_key = String::new();
        for component in &components[..components.len() - 1] {
            let Component::Normal(name) = *component else {
                anyhow::bail!("compiled publication path is not component-normal");
            };
            let name_text = name
                .to_str()
                .context("compiled publication directory is not UTF-8")?;
            let next_key = if parent_key.is_empty() {
                name_text.to_owned()
            } else {
                format!("{parent_key}/{name_text}")
            };
            if !self.directories.contains_key(&next_key) {
                let parent = self.directory_descriptor(&parent_key)?;
                rustix::fs::mkdirat(parent, name, rustix::fs::Mode::RWXU).with_context(|| {
                    format!(
                        "cannot create publication directory {}",
                        self.diagnostic_root.join(&next_key).display()
                    )
                })?;
                let descriptor = rustix::fs::openat(
                    parent,
                    name,
                    PINNED_UNIX_DIRECTORY_FLAGS,
                    rustix::fs::Mode::empty(),
                )
                .with_context(|| {
                    format!(
                        "cannot pin publication directory {}",
                        self.diagnostic_root.join(&next_key).display()
                    )
                })?;
                let identity = platform_directory_identity(&descriptor)?;
                ensure!(
                    self.directory_identities
                        .insert(next_key.clone(), identity)
                        .is_none(),
                    "duplicate publication directory identity"
                );
                ensure!(
                    self.directories
                        .insert(next_key.clone(), descriptor)
                        .is_none(),
                    "duplicate publication directory descriptor"
                );
                self.directory_order.push(next_key.clone());
            }
            parent_key = next_key;
        }
        let Component::Normal(file_name) = components[components.len() - 1] else {
            anyhow::bail!("compiled publication file path is not component-normal");
        };
        Ok((
            parent_key,
            file_name.to_os_string(),
            self.diagnostic_root.join(relative_path),
        ))
    }

    fn retain_file(&mut self, relative: &str, file: RetainedPublicationFile) -> Result<()> {
        ensure!(
            self.files.insert(relative.to_owned(), file).is_none(),
            "duplicate retained publication file {relative}"
        );
        Ok(())
    }

    fn expected_file_snapshots(&self) -> BTreeMap<String, PublicationPhysicalFileSnapshot> {
        self.files
            .iter()
            .map(|(relative, retained)| (relative.clone(), retained.snapshot))
            .collect()
    }

    fn measure_physical_closure_from(
        &self,
        root: BorrowedFd<'_>,
        diagnostic_root: &Path,
    ) -> Result<PublicationPhysicalClosure> {
        PublicationPhysicalClosure::measure(root, diagnostic_root, &self.expected_file_snapshots())
    }

    fn measure_physical_closure(&self) -> Result<PublicationPhysicalClosure> {
        self.measure_physical_closure_from(self.descriptor(), &self.diagnostic_root)
    }

    fn verify_written_physical_closure(&self, measured: &PublicationPhysicalClosure) -> Result<()> {
        ensure!(
            measured.directory_identities == self.directory_identities,
            "staged publication directory physical closure differs from the created tree"
        );
        ensure!(
            measured.file_snapshots == self.expected_file_snapshots(),
            "staged publication file physical closure differs from the written files"
        );
        for (relative, retained) in &self.files {
            ensure!(
                opened_file_identity(&retained.diagnostic, &retained.file)?
                    == retained.snapshot.identity,
                "retained publication file identity changed for {relative}"
            );
        }
        Ok(())
    }

    fn sync_retained_files(&self) -> Result<()> {
        for (relative, retained) in &self.files {
            retained.file.sync_all().with_context(|| {
                format!(
                    "cannot re-sync retained publication file {relative} at {}",
                    retained.diagnostic.display()
                )
            })?;
        }
        Ok(())
    }

    fn sync_retained_files_for_final_durability(
        &self,
        #[cfg(test)] fault: Option<PublicationTestFault<'_>>,
    ) -> Result<()> {
        for (relative, retained) in &self.files {
            #[cfg(test)]
            if matches!(
                fault,
                Some(PublicationTestFault::FinalFileSyncAfterBeforeRename(_, target))
                    if target == relative
            ) {
                anyhow::bail!(
                    "injected final durability file synchronization failure at {relative}"
                );
            }
            retained.file.sync_all().with_context(|| {
                format!(
                    "cannot finalize durability of retained publication file {relative} at {}",
                    retained.diagnostic.display()
                )
            })?;
        }
        Ok(())
    }

    fn sync_directory(&self, relative: &str) -> Result<()> {
        let descriptor = self.directory_descriptor(relative)?;
        rustix::fs::fsync(descriptor).with_context(|| {
            let diagnostic = if relative.is_empty() {
                self.diagnostic_root.clone()
            } else {
                self.diagnostic_root.join(relative)
            };
            format!("cannot sync directory {}", diagnostic.display())
        })
    }
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
fn write_and_sync_publication_file(
    parent: BorrowedFd<'_>,
    name: &OsStr,
    diagnostic: &Path,
    bytes: &[u8],
    file_sync_index: &mut usize,
    #[cfg(test)] fault: Option<PublicationTestFault<'_>>,
) -> Result<RetainedPublicationFile> {
    use std::io::Write as _;

    let descriptor = rustix::fs::openat(
        parent,
        name,
        PUBLICATION_FILE_FLAGS,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .with_context(|| format!("cannot create publication file {}", diagnostic.display()))?;
    let mut file = File::from(descriptor);
    file.write_all(bytes)
        .with_context(|| format!("cannot write publication file {}", diagnostic.display()))?;
    file.flush()
        .with_context(|| format!("cannot flush publication file {}", diagnostic.display()))?;
    #[cfg(test)]
    if matches!(fault, Some(PublicationTestFault::FileSync(index)) if index == *file_sync_index) {
        anyhow::bail!(
            "injected file synchronization failure at {}",
            diagnostic.display()
        );
    }
    file.sync_all()
        .with_context(|| format!("cannot sync publication file {}", diagnostic.display()))?;
    let identity = opened_file_identity(diagnostic, &file)?;
    ensure!(
        identity.byte_length == u64::try_from(bytes.len())?,
        "publication file length changed after synchronization at {}",
        diagnostic.display()
    );
    *file_sync_index += 1;
    Ok(RetainedPublicationFile {
        diagnostic: diagnostic.to_path_buf(),
        file,
        snapshot: PublicationPhysicalFileSnapshot {
            identity,
            sha256: Sha256::digest(bytes).into(),
        },
    })
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
fn reopen_for_publication(
    root: BorrowedFd<'_>,
    diagnostic_root: &Path,
    _staged: bool,
    mode: &mut PublicationReopenMode<'_>,
    #[cfg(test)] fault: Option<PublicationTestFault<'_>>,
) -> Result<PublicationReopenedPacket> {
    #[cfg(test)]
    if (_staged && matches!(fault, Some(PublicationTestFault::StagedReopen)))
        || (!_staged && matches!(fault, Some(PublicationTestFault::FinalReopen)))
    {
        anyhow::bail!(
            "injected {} reopen failure",
            if _staged { "staged" } else { "final" }
        );
    }
    match mode {
        PublicationReopenMode::Full(_) => reopen_b4_terminal_evidence_packet_from_descriptor(
            root,
            diagnostic_root,
            &mut |_event, _path| {},
        )
        .map(PublicationReopenedPacket::Full),
        #[cfg(test)]
        PublicationReopenMode::Mechanical(seam) => {
            let root = publication_descriptor_path(root)?;
            if _staged {
                (seam.staged)(&root).map(PublicationReopenedPacket::Mechanical)
            } else {
                (seam.final_reopen)(&root).map(PublicationReopenedPacket::Mechanical)
            }
        }
    }
}

#[cfg(all(test, feature = "b4-terminal-evidence-publication", unix))]
fn write_mechanical_race_winner(
    parent: &PinnedPublicationParent,
    destination: &Path,
    prepared: &B4MechanicalTerminalEvidencePublicationImageV1,
) -> Result<()> {
    let mut tree = PublicationDirectoryTree::create(parent, &parent.final_name, destination)?;
    let mut file_sync_index = 0_usize;
    prepared.visit_payloads(|relative, bytes| {
        let (directory, name, diagnostic) = tree.create_payload_parent_directories(relative)?;
        let retained = write_and_sync_publication_file(
            tree.directory_descriptor(&directory)?,
            &name,
            &diagnostic,
            bytes,
            &mut file_sync_index,
            None,
        )?;
        tree.retain_file(relative, retained)?;
        Ok(())
    })?;
    for (name, bytes) in [
        (
            B4_TERMINAL_EVIDENCE_MANIFEST_FILE,
            prepared.manifest_bytes(),
        ),
        (
            B4_TERMINAL_EVIDENCE_COMPLETION_FILE,
            prepared.completion_bytes(),
        ),
    ] {
        let retained = write_and_sync_publication_file(
            tree.descriptor(),
            OsStr::new(name),
            &destination.join(name),
            bytes,
            &mut file_sync_index,
            None,
        )?;
        tree.retain_file(name, retained)?;
    }
    for relative in tree.directory_order.iter().rev() {
        tree.sync_directory(relative)?;
    }
    tree.sync_directory("")?;
    Ok(())
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
fn rename_publication_create_only(
    parent: BorrowedFd<'_>,
    staging_name: &OsStr,
    final_name: &OsStr,
) -> Result<()> {
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    {
        rustix::fs::renameat_with(
            parent,
            staging_name,
            parent,
            final_name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .context("descriptor-relative atomic no-replace rename failed")
    }
    #[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
    {
        let _ = (parent, staging_name, final_name);
        anyhow::bail!(
            "descriptor-relative atomic no-replace rename is unsupported on this Unix platform"
        )
    }
}

#[cfg(all(feature = "b4-terminal-evidence-publication", unix))]
fn publish_prepared_b4_terminal_evidence_transaction(
    layout: &B4TerminalEvidencePublicationLayoutV1,
    parent: &PinnedPublicationParent,
    prepared: PublicationImage<'_>,
    #[cfg(test)] fault: Option<PublicationTestFault<'_>>,
    #[cfg(not(test))] _fault: Option<()>,
    mut reopen_mode: PublicationReopenMode<'_>,
    #[cfg(test)] mut trace: Option<&mut Vec<PublicationTestTransition>>,
) -> Result<PublicationReopenedPacket> {
    #[cfg(test)]
    if let Some(trace) = trace.as_deref_mut() {
        trace.push(PublicationTestTransition::ParentPinned);
    }
    parent.reauthenticate(layout)?;
    let destination = layout.final_path();
    #[cfg(test)]
    if let Some(PublicationTestFault::Barrier(barrier)) = fault {
        barrier.wait();
    }
    #[cfg(test)]
    if matches!(fault, Some(PublicationTestFault::StagingCreate)) {
        anyhow::bail!("injected staging creation failure");
    }
    let mut staging = PublicationDirectoryTree::create(
        parent,
        &parent.staging_name,
        layout.reserved_staging_path(),
    )?;
    parent.reauthenticate(layout)?;

    let mut renamed = false;
    let transaction = (|| -> Result<PublicationReopenedPacket> {
        let mut payload_index = 0_usize;
        let mut file_sync_index = 0_usize;
        prepared.visit_payloads(|relative, bytes| {
            let (directory, name, diagnostic) =
                staging.create_payload_parent_directories(relative)?;
            #[cfg(test)]
            if let Some(PublicationTestFault::BeforePayloadOpen(index, pause)) = fault
                && index == payload_index
            {
                pause.pause_publisher();
            }
            #[cfg(test)]
            if matches!(fault, Some(PublicationTestFault::PayloadWrite(index)) if index == payload_index)
            {
                anyhow::bail!("injected payload write failure for {relative}");
            }
            let retained = write_and_sync_publication_file(
                staging.directory_descriptor(&directory)?,
                &name,
                &diagnostic,
                bytes,
                &mut file_sync_index,
                #[cfg(test)]
                fault,
            )?;
            staging.retain_file(relative, retained)?;
            #[cfg(test)]
            if let Some(trace) = trace.as_deref_mut() {
                trace.push(PublicationTestTransition::PayloadSynced(payload_index));
            }
            payload_index += 1;
            Ok(())
        })?;
        ensure!(
            payload_index == B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT,
            "prepared payload visitation count drift"
        );

        #[cfg(test)]
        if matches!(fault, Some(PublicationTestFault::ManifestWrite)) {
            anyhow::bail!("injected manifest write failure");
        }
        let retained_manifest = write_and_sync_publication_file(
            staging.descriptor(),
            OsStr::new(B4_TERMINAL_EVIDENCE_MANIFEST_FILE),
            &layout
                .reserved_staging_path()
                .join(B4_TERMINAL_EVIDENCE_MANIFEST_FILE),
            prepared.manifest_bytes(),
            &mut file_sync_index,
            #[cfg(test)]
            fault,
        )?;
        staging.retain_file(B4_TERMINAL_EVIDENCE_MANIFEST_FILE, retained_manifest)?;
        #[cfg(test)]
        if let Some(trace) = trace.as_deref_mut() {
            trace.push(PublicationTestTransition::ManifestSynced);
        }
        #[cfg(test)]
        if matches!(fault, Some(PublicationTestFault::CompletionWrite)) {
            anyhow::bail!("injected completion write failure");
        }
        let retained_completion = write_and_sync_publication_file(
            staging.descriptor(),
            OsStr::new(B4_TERMINAL_EVIDENCE_COMPLETION_FILE),
            &layout
                .reserved_staging_path()
                .join(B4_TERMINAL_EVIDENCE_COMPLETION_FILE),
            prepared.completion_bytes(),
            &mut file_sync_index,
            #[cfg(test)]
            fault,
        )?;
        staging.retain_file(B4_TERMINAL_EVIDENCE_COMPLETION_FILE, retained_completion)?;
        #[cfg(test)]
        if let Some(trace) = trace.as_deref_mut() {
            trace.push(PublicationTestTransition::CompletionSynced);
        }
        ensure!(
            file_sync_index == B4_TERMINAL_EVIDENCE_FILE_COUNT,
            "publication file synchronization count drift"
        );
        parent.reauthenticate(layout)?;

        let staged = reopen_for_publication(
            staging.descriptor(),
            layout.reserved_staging_path(),
            true,
            &mut reopen_mode,
            #[cfg(test)]
            fault,
        )?;
        let staged_identity = staged.identity();
        #[cfg(test)]
        if let Some(PublicationTestFault::BeforeStagedPhysicalClosure(pause)) = fault {
            pause.pause_publisher();
        }
        let staged_physical = staging.measure_physical_closure()?;
        staging.verify_written_physical_closure(&staged_physical)?;
        staging.sync_retained_files()?;
        #[cfg(test)]
        if let Some(trace) = trace.as_deref_mut() {
            trace.push(PublicationTestTransition::StagedReopened);
        }
        #[cfg(test)]
        let mut directory_sync_index = 0_usize;
        for relative in staging
            .directory_order
            .iter()
            .rev()
            .map(String::as_str)
            .chain([""])
        {
            #[cfg(test)]
            if matches!(fault, Some(PublicationTestFault::DirectorySync(index)) if index == directory_sync_index)
            {
                anyhow::bail!(
                    "injected directory synchronization failure at {}",
                    if relative.is_empty() {
                        layout.reserved_staging_path().display().to_string()
                    } else {
                        layout
                            .reserved_staging_path()
                            .join(relative)
                            .display()
                            .to_string()
                    }
                );
            }
            staging.sync_directory(relative)?;
            #[cfg(test)]
            if let Some(trace) = trace.as_deref_mut() {
                let relative = if relative.is_empty() {
                    ".".to_owned()
                } else {
                    relative.to_owned()
                };
                trace.push(PublicationTestTransition::DirectorySynced(relative));
            }
            #[cfg(test)]
            {
                directory_sync_index += 1;
            }
        }

        #[cfg(test)]
        if let Some(trace) = trace.as_deref_mut() {
            trace.push(PublicationTestTransition::ReadyToExclusiveRename);
        }
        #[cfg(test)]
        if let Some(
            PublicationTestFault::BeforeExclusiveRename(pause)
            | PublicationTestFault::FinalFileSyncAfterBeforeRename(pause, _),
        ) = fault
        {
            pause.pause_publisher();
        }
        parent.reauthenticate(layout)?;
        ensure!(
            parent
                .named_directory_identity(&parent.staging_name, layout.reserved_staging_path())?
                == Some(staging.root_identity),
            "reserved staging name no longer identifies the pinned staging directory"
        );
        #[cfg(test)]
        if let Some(PublicationTestFault::RaceWinner(winner)) = fault {
            write_mechanical_race_winner(parent, destination, winner)?;
        }
        if let Err(error) = rename_publication_create_only(
            parent.descriptor(),
            &parent.staging_name,
            &parent.final_name,
        ) {
            if parent
                .named_directory_identity(&parent.final_name, destination)?
                .is_some()
            {
                return Err(error).context(format!(
                    "terminal-evidence publication occupation: destination is occupied at {}",
                    destination.display()
                ));
            }
            return Err(error).context(format!(
                "cannot publish {} create-only at {}",
                layout.reserved_staging_path().display(),
                destination.display()
            ));
        }
        renamed = true;
        parent.reauthenticate(layout)?;
        #[cfg(test)]
        if let Some(trace) = trace.as_deref_mut() {
            trace.push(PublicationTestTransition::ExclusiveRenamed);
        }
        #[cfg(test)]
        if let Some(PublicationTestFault::AfterExclusiveRename(pause)) = fault {
            pause.pause_publisher();
        }

        #[cfg(test)]
        if matches!(fault, Some(PublicationTestFault::ParentSync)) {
            anyhow::bail!("injected parent directory synchronization failure");
        }
        rustix::fs::fsync(parent.descriptor()).with_context(|| {
            format!(
                "cannot sync publication parent {}",
                layout.parent().display()
            )
        })?;
        parent.reauthenticate(layout)?;
        #[cfg(test)]
        if let Some(trace) = trace.as_deref_mut() {
            trace.push(PublicationTestTransition::ParentSynced);
        }
        parent.ensure_absent(
            layout,
            &parent.staging_name,
            layout.reserved_staging_path(),
            "reserved publication staging",
        )?;
        let final_root = parent.open_named_directory(&parent.final_name, destination)?;
        ensure!(
            platform_directory_identity(&final_root)? == staging.root_identity,
            "final publication root is not the retained staged directory"
        );
        parent.reauthenticate(layout)?;
        let final_reopened = reopen_for_publication(
            final_root.as_fd(),
            destination,
            false,
            &mut reopen_mode,
            #[cfg(test)]
            fault,
        )?;
        parent.reauthenticate(layout)?;
        #[cfg(test)]
        if let Some(trace) = trace.as_deref_mut() {
            trace.push(PublicationTestTransition::FinalReopened);
        }
        ensure!(
            final_reopened.identity() == staged_identity,
            "terminal-evidence packet identity changed between staged and final reopen"
        );
        #[cfg(test)]
        if let Some(PublicationTestFault::BeforeFinalParentReauthentication(pause)) = fault {
            pause.pause_publisher();
        }
        parent.with_reauthenticated_descriptor(layout, |parent_descriptor| {
            ensure!(
                PinnedPublicationParent::named_directory_identity_from(
                    parent_descriptor,
                    &parent.final_name,
                    destination,
                )? == Some(staging.root_identity),
                "reauthenticated final publication name changed physical identity"
            );
            let reauthenticated_final_root = PinnedPublicationParent::open_named_directory_from(
                parent_descriptor,
                &parent.final_name,
                destination,
            )?;
            let final_physical = staging
                .measure_physical_closure_from(reauthenticated_final_root.as_fd(), destination)?;
            ensure!(
                final_physical.names_the_same_objects_as(&staged_physical),
                "final publication physical closure differs from the staged synced closure"
            );
            staging.sync_retained_files_for_final_durability(
                #[cfg(test)]
                fault,
            )?;
            #[cfg(test)]
            let mut final_directory_sync_index = 0_usize;
            for relative in staging
                .directory_order
                .iter()
                .rev()
                .map(String::as_str)
                .chain([""])
            {
                #[cfg(test)]
                if matches!(
                    fault,
                    Some(PublicationTestFault::FinalDirectorySync(index))
                        if index == final_directory_sync_index
                ) {
                    anyhow::bail!(
                        "injected final durability directory synchronization failure at {}",
                        if relative.is_empty() {
                            destination.display().to_string()
                        } else {
                            destination.join(relative).display().to_string()
                        }
                    );
                }
                staging.sync_directory(relative)?;
                #[cfg(test)]
                {
                    final_directory_sync_index += 1;
                }
            }
            #[cfg(test)]
            if let Some(PublicationTestFault::BeforeDurableFinalPhysicalClosure(pause)) = fault {
                pause.pause_publisher();
            }
            let mut durable_final_physical = staging
                .measure_physical_closure_from(reauthenticated_final_root.as_fd(), destination)?;
            ensure!(
                durable_final_physical.names_the_same_objects_as(&staged_physical),
                "final publication physical closure changed during durability synchronization"
            );
            #[cfg(test)]
            if let Some(PublicationTestFault::AfterFinalPhysicalClosure(pause)) = fault {
                pause.pause_publisher();
            }
            durable_final_physical
                .reauthenticate()
                .context("final publication physical closure changed before authority")?;
            ensure!(
                PinnedPublicationParent::named_directory_identity_from(
                    parent_descriptor,
                    &parent.final_name,
                    destination,
                )? == Some(staging.root_identity),
                "reauthenticated final publication name changed during physical closure"
            );
            PinnedPublicationParent::ensure_absent_from(
                parent_descriptor,
                &parent.staging_name,
                layout.reserved_staging_path(),
                "reserved publication staging",
            )
        })?;
        Ok(final_reopened)
    })();

    transaction.map_err(|error| {
        if !renamed
            && matches!(
                parent.named_directory_identity(
                    &parent.staging_name,
                    layout.reserved_staging_path()
                ),
                Ok(Some(identity)) if identity == staging.root_identity
            )
        {
            error.context(format!(
                "terminal-evidence publication retained staging at {}",
                layout.reserved_staging_path().display()
            ))
        } else {
            error
        }
    })
}

#[cfg(all(test, feature = "b4-terminal-evidence-publication", unix))]
fn publish_prepared_b4_terminal_evidence_with_test_seam(
    destination: &Path,
    prepared: &B4MechanicalTerminalEvidencePublicationImageV1,
    fault: Option<PublicationTestFault<'_>>,
    seam: PublicationTestReopenSeam<'_>,
) -> Result<MechanicalPacketIdentity> {
    let layout = project_b4_terminal_evidence_publication_layout(destination)?;
    let parent = preflight_b4_terminal_evidence_publication_unix(&layout, fault)?;
    if let Some(PublicationTestFault::AfterParentPinned(pause)) = fault {
        pause.pause_publisher();
    }
    match publish_prepared_b4_terminal_evidence_transaction(
        &layout,
        &parent,
        PublicationImage::Mechanical(prepared),
        fault,
        PublicationReopenMode::Mechanical(seam),
        None,
    )? {
        PublicationReopenedPacket::Mechanical(identity) => Ok(identity),
        PublicationReopenedPacket::Full(_) => {
            unreachable!("test-only mechanical publication returned full authority")
        }
    }
}

#[cfg(all(test, feature = "b4-terminal-evidence-publication", unix))]
fn publish_prepared_b4_terminal_evidence_from_directory_descriptor_with_test_seam(
    parent: BorrowedFd<'_>,
    final_component: &str,
    prepared: &B4MechanicalTerminalEvidencePublicationImageV1,
    seam: PublicationTestReopenSeam<'_>,
) -> Result<MechanicalPacketIdentity> {
    let layout =
        project_descriptor_rooted_b4_terminal_evidence_publication_layout(final_component)?;
    let parent = preflight_b4_terminal_evidence_publication_from_descriptor(&layout, parent, None)?;
    match publish_prepared_b4_terminal_evidence_transaction(
        &layout,
        &parent,
        PublicationImage::Mechanical(prepared),
        None,
        PublicationReopenMode::Mechanical(seam),
        None,
    )? {
        PublicationReopenedPacket::Mechanical(identity) => Ok(identity),
        PublicationReopenedPacket::Full(_) => {
            unreachable!("test-only mechanical publication returned full authority")
        }
    }
}

#[cfg(all(test, feature = "b4-terminal-evidence-publication", unix))]
fn publish_prepared_b4_terminal_evidence_with_test_seam_and_trace(
    destination: &Path,
    prepared: &B4MechanicalTerminalEvidencePublicationImageV1,
    fault: Option<PublicationTestFault<'_>>,
    seam: PublicationTestReopenSeam<'_>,
    trace: &mut Vec<PublicationTestTransition>,
) -> Result<MechanicalPacketIdentity> {
    let layout = project_b4_terminal_evidence_publication_layout(destination)?;
    let parent = preflight_b4_terminal_evidence_publication_unix(&layout, fault)?;
    if let Some(PublicationTestFault::AfterParentPinned(pause)) = fault {
        pause.pause_publisher();
    }
    match publish_prepared_b4_terminal_evidence_transaction(
        &layout,
        &parent,
        PublicationImage::Mechanical(prepared),
        fault,
        PublicationReopenMode::Mechanical(seam),
        Some(trace),
    )? {
        PublicationReopenedPacket::Mechanical(identity) => Ok(identity),
        PublicationReopenedPacket::Full(_) => {
            unreachable!("test-only mechanical publication returned full authority")
        }
    }
}

struct B4MeasuredPayloadFileV1 {
    bytes: Vec<u8>,
    byte_length: u64,
    sha256: [u8; 32],
    final_identity: PlatformFileIdentity,
}

/// Opaque stable-filesystem measurement consumed by the packet mint boundary.
///
/// Its fields are private and there is no constructor accepting caller-supplied
/// lengths or digests.
pub(super) struct B4MeasuredTerminalEvidencePacketV1 {
    manifest_bytes: Vec<u8>,
    physical_closure_identity: Option<B4PhysicalPacketClosureIdentityV1>,
    payloads: BTreeMap<String, B4MeasuredPayloadFileV1>,
}

impl B4MeasuredTerminalEvidencePacketV1 {
    pub(super) fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    pub(super) fn payload_count(&self) -> usize {
        self.payloads.len()
    }

    pub(super) fn take_physical_closure_identity(
        &mut self,
    ) -> Result<B4PhysicalPacketClosureIdentityV1> {
        self.physical_closure_identity
            .take()
            .context("physical packet-closure identity was already consumed")
    }

    pub(super) fn measured_payload(&self, path: &str) -> Result<(&[u8], u64, [u8; 32])> {
        let payload = self
            .payloads
            .get(path)
            .with_context(|| format!("measured terminal evidence payload is missing {path}"))?;
        Ok((
            payload.bytes.as_slice(),
            payload.byte_length,
            payload.sha256,
        ))
    }
}

/// Non-serializable full physical closure retained inside verified authority.
pub(super) struct B4PhysicalPacketClosureIdentityV1 {
    directories: BTreeMap<String, PlatformDirectoryIdentity>,
    files: BTreeMap<String, PlatformFileIdentity>,
    #[allow(
        dead_code,
        reason = "the opaque guard exists to keep every first-reopen filesystem object allocated until the packet is dropped"
    )]
    handle_guard: Option<B4PhysicalPacketClosureHandleGuardV1>,
}

impl B4PhysicalPacketClosureIdentityV1 {
    pub(super) fn names_same_objects_as(&self, other: &Self) -> bool {
        self.directories == other.directories && self.files == other.files
    }

    fn from_stable_reopen(
        directories: BTreeMap<String, PlatformDirectoryIdentity>,
        retained_snapshots: Vec<RetainedFinalSnapshot>,
        expected_files: &BTreeSet<String>,
        retained_directories: PinnedTerminalEvidenceDirectoryTree,
    ) -> Result<Self> {
        let expected_directories = expected_directory_entries(expected_files)?;
        ensure!(
            directories.keys().eq(expected_directories.keys()),
            "physical packet closure does not retain every compiled directory identity"
        );
        let files = retained_snapshots
            .iter()
            .map(|retained| (retained.relative.clone(), retained.snapshot.final_identity))
            .collect::<BTreeMap<_, _>>();
        ensure!(
            files.len() == expected_files.len() && files.keys().eq(expected_files),
            "physical packet closure does not retain every compiled file identity"
        );
        for retained in &retained_snapshots {
            ensure!(
                opened_file_identity(&retained.path, &retained.file)?
                    == retained.snapshot.final_identity,
                "physical packet closure file handle changed before retention"
            );
        }
        ensure!(
            retained_directories.retained_handle_count() == directories.len(),
            "physical packet closure does not retain every compiled directory handle"
        );
        retained_directories
            .verify_retained_identities()
            .context("physical packet closure directory handles changed before retention")?;
        Ok(Self {
            directories,
            files,
            handle_guard: Some(B4PhysicalPacketClosureHandleGuardV1 {
                retained_directories,
                retained_files: retained_snapshots,
            }),
        })
    }

    #[cfg(test)]
    pub(super) fn synthetic_for_test() -> Self {
        Self {
            directories: BTreeMap::from([
                (
                    String::new(),
                    PlatformDirectoryIdentity {
                        volume_or_device: 7,
                        directory: 11,
                    },
                ),
                (
                    "nested".to_owned(),
                    PlatformDirectoryIdentity {
                        volume_or_device: 7,
                        directory: 12,
                    },
                ),
            ]),
            files: BTreeMap::from([(
                "nested/payload.bin".to_owned(),
                PlatformFileIdentity {
                    volume_or_device: 7,
                    file: 21,
                    byte_length: 1,
                },
            )]),
            handle_guard: None,
        }
    }

    #[cfg(test)]
    pub(super) fn with_changed_file_identity_for_test(mut self) -> Self {
        self.files
            .get_mut("nested/payload.bin")
            .expect("synthetic physical closure has one payload")
            .file += 1;
        self
    }

    #[cfg(test)]
    pub(super) fn with_changed_directory_identity_for_test(mut self) -> Self {
        self.directories
            .get_mut("nested")
            .expect("synthetic physical closure has one nested directory")
            .directory += 1;
        self
    }

    #[cfg(test)]
    pub(super) fn from_test_tree(root: &Path, files: &[&str]) -> Result<Self> {
        let expected_files = files
            .iter()
            .map(|relative| (*relative).to_owned())
            .collect::<BTreeSet<_>>();
        ensure!(
            expected_files.len() == files.len(),
            "test physical closure contains duplicate file paths"
        );

        #[cfg(unix)]
        let retained_directories = {
            use std::os::fd::AsFd as _;

            let root_descriptor = File::open(root)
                .with_context(|| format!("cannot open test closure root {}", root.display()))?;
            PinnedTerminalEvidenceDirectoryTree::open(
                root_descriptor.as_fd(),
                root,
                &expected_files,
            )?
        };
        #[cfg(windows)]
        let retained_directories =
            PinnedTerminalEvidenceDirectoryTree::open(root, &expected_files)?;

        let directories = retained_directories.identities.clone();
        let mut retained_snapshots = Vec::new();
        retained_snapshots
            .try_reserve_exact(expected_files.len())
            .context("cannot retain test physical closure files")?;
        for relative in &expected_files {
            #[cfg(unix)]
            let (file, snapshot, path) = retained_directories.open_and_read_file(relative, 1024)?;
            #[cfg(windows)]
            let (file, snapshot) = open_and_read_file(&root.join(portable_path(relative)?), 1024)?;
            #[cfg(windows)]
            let path = root.join(portable_path(relative)?);

            retained_snapshots.push(RetainedFinalSnapshot {
                relative: relative.clone(),
                path,
                maximum: 1024,
                file,
                snapshot,
            });
        }
        Self::from_stable_reopen(
            directories,
            retained_snapshots,
            &expected_files,
            retained_directories,
        )
    }

    #[cfg(test)]
    pub(super) fn retained_handle_counts_for_test(&self) -> (usize, usize) {
        self.handle_guard.as_ref().map_or((0, 0), |guard| {
            (
                guard.retained_directories.retained_handle_count(),
                guard.retained_files.len(),
            )
        })
    }

    #[cfg(test)]
    pub(super) fn retained_handles_are_live_for_test(&self) -> Result<bool> {
        let guard = self
            .handle_guard
            .as_ref()
            .context("test physical closure lacks retained OS handles")?;
        guard.retained_directories.verify_retained_identities()?;
        for retained in &guard.retained_files {
            ensure!(
                opened_file_identity(&retained.path, &retained.file)?
                    == retained.snapshot.final_identity,
                "retained test physical-closure file handle changed identity"
            );
        }
        Ok(true)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct PlatformFileIdentity {
    volume_or_device: u64,
    file: u64,
    byte_length: u64,
}

struct StableFile {
    bytes: Vec<u8>,
    byte_length: u64,
    sha256: [u8; 32],
    final_identity: PlatformFileIdentity,
}

#[derive(Clone, Copy, Eq, PartialEq)]
#[cfg(test)]
enum ReopenTestEvent {
    AfterFirstRead,
    AfterFinalSnapshot,
}

#[cfg(test)]
fn reopen_b4_terminal_evidence_packet_with_hook(
    root: &Path,
    mut hook: impl FnMut(ReopenTestEvent, &str),
) -> Result<B4VerifiedTerminalEvidencePacketV1> {
    #[cfg(unix)]
    {
        let pinned = PinnedUnixDirectoryPath::open(root, "terminal-evidence packet root")?;
        let result = reopen_b4_terminal_evidence_packet_from_descriptor(
            pinned.descriptor(),
            root,
            &mut hook,
        )?;
        pinned.reauthenticate()?;
        Ok(result)
    }
    #[cfg(windows)]
    {
        reopen_b4_terminal_evidence_packet_impl(root, &mut hook)
    }
}

#[cfg(test)]
type ReopenEvent = ReopenTestEvent;

#[cfg(not(test))]
#[derive(Clone, Copy)]
enum ReopenEvent {
    AfterFirstRead,
    AfterFinalSnapshot,
}

struct RetainedFinalSnapshot {
    relative: String,
    path: PathBuf,
    maximum: usize,
    file: File,
    snapshot: StableFile,
}

/// Non-projectable lifetime guard for every object named by one physical
/// packet closure.
///
/// Keeping these handles live prevents an unlinked first-reopen object from
/// releasing its filesystem identity for ABA reuse before the final reopen is
/// compared.
#[allow(
    dead_code,
    reason = "owning the handles until drop is this guard's security effect"
)]
struct B4PhysicalPacketClosureHandleGuardV1 {
    retained_directories: PinnedTerminalEvidenceDirectoryTree,
    retained_files: Vec<RetainedFinalSnapshot>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct PlatformDirectoryIdentity {
    volume_or_device: u64,
    directory: u64,
}

#[cfg(unix)]
fn checked_platform_identity_component<T>(value: T, error: &'static str) -> Result<u64>
where
    u64: TryFrom<T>,
{
    u64::try_from(value).map_err(|_| anyhow::Error::msg(error))
}

#[cfg(unix)]
fn platform_directory_identity_from_stat(
    stat: &rustix::fs::Stat,
) -> Result<PlatformDirectoryIdentity> {
    ensure!(
        rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir(),
        "opened descriptor is not an ordinary directory"
    );
    Ok(PlatformDirectoryIdentity {
        volume_or_device: checked_platform_identity_component(
            stat.st_dev,
            "opened directory device identity does not fit u64",
        )?,
        directory: checked_platform_identity_component(
            stat.st_ino,
            "opened directory inode identity does not fit u64",
        )?,
    })
}

#[cfg(unix)]
fn platform_directory_identity(
    descriptor: impl std::os::fd::AsFd,
) -> Result<PlatformDirectoryIdentity> {
    let stat = rustix::fs::fstat(descriptor).context("cannot inspect opened directory")?;
    platform_directory_identity_from_stat(&stat)
}

#[cfg(unix)]
struct PinnedTerminalEvidenceDirectoryTree {
    root: OwnedFd,
    diagnostic_root: PathBuf,
    directories: BTreeMap<String, OwnedFd>,
    identities: BTreeMap<String, PlatformDirectoryIdentity>,
}

#[cfg(unix)]
impl PinnedTerminalEvidenceDirectoryTree {
    fn open(
        root: BorrowedFd<'_>,
        diagnostic_root: &Path,
        files: &BTreeSet<String>,
    ) -> Result<Self> {
        let expected = expected_directory_entries(files)?;
        let root = rustix::fs::openat(
            root,
            ".",
            PINNED_UNIX_DIRECTORY_FLAGS,
            rustix::fs::Mode::empty(),
        )
        .with_context(|| {
            format!(
                "cannot retain terminal evidence root {}",
                diagnostic_root.display()
            )
        })?;
        let mut directories = BTreeMap::new();
        let mut identities = BTreeMap::new();
        ensure!(
            identities
                .insert(String::new(), platform_directory_identity(&root)?)
                .is_none(),
            "duplicate terminal evidence root identity"
        );

        for relative in expected.keys().filter(|relative| !relative.is_empty()) {
            let (parent, name) = relative
                .rsplit_once('/')
                .map_or(("", relative.as_str()), |(parent, name)| (parent, name));
            let descriptor = {
                let parent_descriptor = if parent.is_empty() {
                    root.as_fd()
                } else {
                    directories
                        .get(parent)
                        .map(OwnedFd::as_fd)
                        .with_context(|| {
                            format!("terminal evidence directory descriptor is missing {parent}")
                        })?
                };
                rustix::fs::openat(
                    parent_descriptor,
                    name,
                    PINNED_UNIX_DIRECTORY_FLAGS,
                    rustix::fs::Mode::empty(),
                )
                .with_context(|| {
                    format!(
                        "cannot pin terminal evidence directory {}",
                        diagnostic_root.join(relative).display()
                    )
                })?
            };
            ensure!(
                identities
                    .insert(relative.clone(), platform_directory_identity(&descriptor)?)
                    .is_none(),
                "duplicate terminal evidence directory identity path"
            );
            ensure!(
                directories.insert(relative.clone(), descriptor).is_none(),
                "duplicate terminal evidence directory descriptor"
            );
        }

        let tree = Self {
            root,
            diagnostic_root: diagnostic_root.to_path_buf(),
            directories,
            identities,
        };
        tree.validate_exact_inventories(&expected)?;
        tree.verify_retained_identities()?;
        Ok(tree)
    }

    fn directory_descriptor(&self, relative: &str) -> Result<BorrowedFd<'_>> {
        if relative.is_empty() {
            Ok(self.root.as_fd())
        } else {
            self.directories
                .get(relative)
                .map(OwnedFd::as_fd)
                .with_context(|| {
                    format!("terminal evidence directory descriptor is missing {relative}")
                })
        }
    }

    fn retained_handle_count(&self) -> usize {
        1 + self.directories.len()
    }

    fn diagnostic_directory(&self, relative: &str) -> PathBuf {
        if relative.is_empty() {
            self.diagnostic_root.clone()
        } else {
            self.diagnostic_root.join(relative)
        }
    }

    fn verify_retained_identities(&self) -> Result<()> {
        for (relative, identity) in &self.identities {
            ensure!(
                platform_directory_identity(self.directory_descriptor(relative)?)? == *identity,
                "retained terminal evidence directory identity changed for {}",
                self.diagnostic_directory(relative).display()
            );
        }
        Ok(())
    }

    fn validate_exact_inventories(
        &self,
        expected: &BTreeMap<String, BTreeSet<String>>,
    ) -> Result<()> {
        for (relative, expected_entries) in expected {
            let diagnostic = self.diagnostic_directory(relative);
            let mut directory = rustix::fs::Dir::read_from(self.directory_descriptor(relative)?)
                .with_context(|| {
                    format!(
                        "cannot enumerate pinned terminal evidence directory {}",
                        diagnostic.display()
                    )
                })?;
            let mut observed = BTreeSet::new();
            for entry in &mut directory {
                let entry = entry.with_context(|| {
                    format!(
                        "cannot read pinned terminal evidence directory entry in {}",
                        diagnostic.display()
                    )
                })?;
                let name = entry.file_name().to_str().with_context(|| {
                    format!(
                        "terminal evidence entry name is not UTF-8 in {}",
                        diagnostic.display()
                    )
                })?;
                if matches!(name, "." | "..") {
                    continue;
                }
                record_expected_directory_entry(
                    &mut observed,
                    expected_entries,
                    name,
                    &diagnostic,
                )?;
            }
            ensure!(
                observed == *expected_entries,
                "{} does not have the exact compiled terminal evidence shape",
                diagnostic.display()
            );
        }
        Ok(())
    }

    fn reauthenticate(&self, files: &BTreeSet<String>) -> Result<()> {
        self.verify_retained_identities()?;
        let reopened = Self::open(self.root.as_fd(), &self.diagnostic_root, files)?;
        ensure!(
            reopened.identities == self.identities,
            "terminal evidence directory identity changed during descriptor reauthentication"
        );
        Ok(())
    }

    fn open_file(&self, relative: &str) -> Result<(File, PathBuf)> {
        let _ = portable_path(relative)?;
        let (parent, name) = relative
            .rsplit_once('/')
            .map_or(("", relative), |(parent, name)| (parent, name));
        let diagnostic = self.diagnostic_root.join(relative);
        let descriptor = rustix::fs::openat(
            self.directory_descriptor(parent)?,
            name,
            PINNED_UNIX_FILE_FLAGS,
            rustix::fs::Mode::empty(),
        )
        .with_context(|| format!("cannot open {}", diagnostic.display()))?;
        Ok((File::from(descriptor), diagnostic))
    }

    fn open_and_read_file(
        &self,
        relative: &str,
        maximum: usize,
    ) -> Result<(File, StableFile, PathBuf)> {
        let (mut file, diagnostic) = self.open_file(relative)?;
        let snapshot = read_opened_file(&diagnostic, &mut file, maximum)?;
        Ok((file, snapshot, diagnostic))
    }

    fn read_one_opened_file(&self, relative: &str, maximum: usize) -> Result<StableFile> {
        self.open_and_read_file(relative, maximum)
            .map(|(_file, snapshot, _diagnostic)| snapshot)
    }

    fn stable_read_file(
        &self,
        relative: &str,
        maximum: usize,
        hook: &mut impl FnMut(ReopenEvent, &str),
    ) -> Result<StableFile> {
        let (first_file, first, _first_diagnostic) = self.open_and_read_file(relative, maximum)?;
        hook(ReopenEvent::AfterFirstRead, relative);
        let (second_file, second, _second_diagnostic) =
            self.open_and_read_file(relative, maximum)?;
        ensure!(
            first.final_identity == second.final_identity && first.sha256 == second.sha256,
            "{relative} changed between stable-file snapshots"
        );
        drop((first_file, second_file));
        Ok(second)
    }
}

#[cfg(unix)]
#[allow(clippy::too_many_lines)] // Keep the descriptor-custody and snapshot order in one auditable sequence.
fn reopen_b4_terminal_evidence_packet_from_descriptor(
    root: BorrowedFd<'_>,
    diagnostic_root: &Path,
    hook: &mut impl FnMut(ReopenEvent, &str),
) -> Result<B4VerifiedTerminalEvidencePacketV1> {
    let roles = compiled_b4_terminal_evidence_role_table()?;
    let all_paths = roles
        .iter()
        .map(|role| role.path.clone())
        .chain([
            B4_TERMINAL_EVIDENCE_MANIFEST_FILE.to_owned(),
            B4_TERMINAL_EVIDENCE_COMPLETION_FILE.to_owned(),
        ])
        .collect::<BTreeSet<_>>();
    ensure!(
        all_paths.len() == B4_TERMINAL_EVIDENCE_FILE_COUNT,
        "compiled terminal evidence file count drift"
    );
    let tree = PinnedTerminalEvidenceDirectoryTree::open(root, diagnostic_root, &all_paths)?;

    let manifest =
        tree.stable_read_file(B4_TERMINAL_EVIDENCE_MANIFEST_FILE, MANIFEST_MAX_BYTES, hook)?;
    let parsed_manifest = Eip0045B4TerminalEvidenceManifestV1::from_canonical_jcs(&manifest.bytes)?;

    let mut payloads = BTreeMap::new();
    for (row, role) in parsed_manifest.files.iter().zip(&roles) {
        ensure!(
            row.path == role.path,
            "terminal evidence manifest and compiled role order drift"
        );
        let payload = tree.stable_read_file(&row.path, role.maximum, hook)?;
        ensure!(
            payload.byte_length == row.byte_length,
            "{} byte length differs from the manifest",
            row.path
        );
        ensure!(
            hex::encode(payload.sha256) == row.sha256,
            "{} SHA-256 differs from the manifest",
            row.path
        );
        ensure!(
            payloads
                .insert(
                    row.path.clone(),
                    B4MeasuredPayloadFileV1 {
                        bytes: payload.bytes,
                        byte_length: payload.byte_length,
                        sha256: payload.sha256,
                        final_identity: payload.final_identity,
                    },
                )
                .is_none(),
            "duplicate measured terminal evidence payload path"
        );
    }
    ensure!(
        payloads.len() == B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT,
        "measured terminal evidence payload count drift"
    );

    let completion = tree.stable_read_file(
        B4_TERMINAL_EVIDENCE_COMPLETION_FILE,
        COMPLETION_MAX_BYTES,
        hook,
    )?;
    Eip0045B4TerminalEvidenceCompletionV1::from_canonical_jcs(&completion.bytes)?
        .bind_manifest(&manifest.bytes)?;

    let mut retained_snapshots = Vec::new();
    retained_snapshots
        .try_reserve_exact(B4_TERMINAL_EVIDENCE_FILE_COUNT)
        .context("cannot retain final terminal evidence snapshots")?;
    for path in &all_paths {
        let maximum = match path.as_str() {
            B4_TERMINAL_EVIDENCE_MANIFEST_FILE => MANIFEST_MAX_BYTES,
            B4_TERMINAL_EVIDENCE_COMPLETION_FILE => COMPLETION_MAX_BYTES,
            _ => roles
                .iter()
                .find(|role| role.path == *path)
                .map(|role| role.maximum)
                .context("final snapshot encountered an unknown payload path")?,
        };
        let (file, snapshot, diagnostic) = tree.open_and_read_file(path, maximum)?;
        let (identity, digest) = if path == B4_TERMINAL_EVIDENCE_MANIFEST_FILE {
            (manifest.final_identity, manifest.sha256)
        } else if path == B4_TERMINAL_EVIDENCE_COMPLETION_FILE {
            (completion.final_identity, completion.sha256)
        } else {
            let payload = payloads
                .get(path)
                .context("final snapshot payload disappeared")?;
            (payload.final_identity, payload.sha256)
        };
        ensure!(
            snapshot.final_identity == identity && snapshot.sha256 == digest,
            "{path} changed before the packet-wide final snapshot"
        );
        retained_snapshots.push(RetainedFinalSnapshot {
            relative: path.clone(),
            path: diagnostic,
            maximum,
            file,
            snapshot,
        });
        hook(ReopenEvent::AfterFinalSnapshot, path);
    }

    tree.reauthenticate(&all_paths)
        .context("terminal evidence directory changed during the final snapshot")?;
    for retained in &mut retained_snapshots {
        let held = read_opened_file(&retained.path, &mut retained.file, retained.maximum)
            .with_context(|| {
                format!("{} changed on its retained final handle", retained.relative)
            })?;
        ensure!(
            held.final_identity == retained.snapshot.final_identity
                && held.sha256 == retained.snapshot.sha256,
            "{} changed on its retained final handle",
            retained.relative
        );
        let reopened = tree
            .read_one_opened_file(&retained.relative, retained.maximum)
            .with_context(|| format!("{} changed after its final snapshot", retained.relative))?;
        ensure!(
            reopened.final_identity == retained.snapshot.final_identity
                && reopened.sha256 == retained.snapshot.sha256,
            "{} changed after its final snapshot",
            retained.relative
        );
    }
    tree.reauthenticate(&all_paths)
        .context("terminal evidence tree changed after final descriptor revalidation")?;
    let physical_closure_identity = B4PhysicalPacketClosureIdentityV1::from_stable_reopen(
        tree.identities.clone(),
        retained_snapshots,
        &all_paths,
        tree,
    )?;

    mint_b4_verified_terminal_evidence_packet(B4MeasuredTerminalEvidencePacketV1 {
        manifest_bytes: manifest.bytes,
        physical_closure_identity: Some(physical_closure_identity),
        payloads,
    })
}

#[cfg(windows)]
struct PinnedTerminalEvidenceDirectoryTree {
    diagnostic_root: PathBuf,
    directories: BTreeMap<String, File>,
    identities: BTreeMap<String, PlatformDirectoryIdentity>,
}

#[cfg(windows)]
impl PinnedTerminalEvidenceDirectoryTree {
    fn open(root: &Path, files: &BTreeSet<String>) -> Result<Self> {
        let expected = expected_directory_entries(files)?;
        let mut directories = BTreeMap::new();
        let mut identities = BTreeMap::new();
        for relative in expected.keys() {
            let path = if relative.is_empty() {
                root.to_path_buf()
            } else {
                root.join(portable_path(relative)?)
            };
            validate_ordinary_directory(&path)?;
            let (directory, identity) = open_directory_for_identity(&path)?;
            ensure!(
                identities.insert(relative.clone(), identity).is_none(),
                "duplicate retained terminal evidence directory identity path"
            );
            ensure!(
                directories.insert(relative.clone(), directory).is_none(),
                "duplicate retained terminal evidence directory handle"
            );
        }
        let tree = Self {
            diagnostic_root: root.to_path_buf(),
            directories,
            identities,
        };
        tree.reauthenticate(files)?;
        Ok(tree)
    }

    fn retained_handle_count(&self) -> usize {
        self.directories.len()
    }

    fn verify_retained_identities(&self) -> Result<()> {
        for (relative, identity) in &self.identities {
            let path = if relative.is_empty() {
                self.diagnostic_root.clone()
            } else {
                self.diagnostic_root.join(portable_path(relative)?)
            };
            let directory = self
                .directories
                .get(relative)
                .with_context(|| format!("retained directory handle is missing {relative}"))?;
            ensure!(
                opened_directory_identity(&path, directory)? == *identity,
                "retained terminal evidence directory handle changed for {}",
                path.display()
            );
        }
        Ok(())
    }

    fn reauthenticate(&self, files: &BTreeSet<String>) -> Result<()> {
        self.verify_retained_identities()?;
        ensure!(
            validate_exact_tree(&self.diagnostic_root, files)? == self.identities,
            "terminal evidence directory identity changed during handle reauthentication"
        );
        Ok(())
    }
}

#[cfg(windows)]
fn reopen_b4_terminal_evidence_packet_impl(
    root: &Path,
    hook: &mut impl FnMut(ReopenEvent, &str),
) -> Result<B4VerifiedTerminalEvidencePacketV1> {
    let roles = compiled_b4_terminal_evidence_role_table()?;
    let all_paths = roles
        .iter()
        .map(|role| role.path.clone())
        .chain([
            B4_TERMINAL_EVIDENCE_MANIFEST_FILE.to_owned(),
            B4_TERMINAL_EVIDENCE_COMPLETION_FILE.to_owned(),
        ])
        .collect::<BTreeSet<_>>();
    ensure!(
        all_paths.len() == B4_TERMINAL_EVIDENCE_FILE_COUNT,
        "compiled terminal evidence file count drift"
    );
    let tree = PinnedTerminalEvidenceDirectoryTree::open(root, &all_paths)?;
    let directory_identities = tree.identities.clone();

    let manifest = stable_read_file(
        root,
        B4_TERMINAL_EVIDENCE_MANIFEST_FILE,
        MANIFEST_MAX_BYTES,
        hook,
    )?;
    let parsed_manifest = Eip0045B4TerminalEvidenceManifestV1::from_canonical_jcs(&manifest.bytes)?;

    let mut payloads = BTreeMap::new();
    for (row, role) in parsed_manifest.files.iter().zip(&roles) {
        ensure!(
            row.path == role.path,
            "terminal evidence manifest and compiled role order drift"
        );
        let payload = stable_read_file(root, &row.path, role.maximum, hook)?;
        ensure!(
            payload.byte_length == row.byte_length,
            "{} byte length differs from the manifest",
            row.path
        );
        ensure!(
            hex::encode(payload.sha256) == row.sha256,
            "{} SHA-256 differs from the manifest",
            row.path
        );
        ensure!(
            payloads
                .insert(
                    row.path.clone(),
                    B4MeasuredPayloadFileV1 {
                        bytes: payload.bytes,
                        byte_length: payload.byte_length,
                        sha256: payload.sha256,
                        final_identity: payload.final_identity,
                    },
                )
                .is_none(),
            "duplicate measured terminal evidence payload path"
        );
    }
    ensure!(
        payloads.len() == B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT,
        "measured terminal evidence payload count drift"
    );

    let completion = stable_read_file(
        root,
        B4_TERMINAL_EVIDENCE_COMPLETION_FILE,
        COMPLETION_MAX_BYTES,
        hook,
    )?;
    Eip0045B4TerminalEvidenceCompletionV1::from_canonical_jcs(&completion.bytes)?
        .bind_manifest(&manifest.bytes)?;

    let mut retained_snapshots = Vec::new();
    retained_snapshots
        .try_reserve_exact(B4_TERMINAL_EVIDENCE_FILE_COUNT)
        .context("cannot retain final terminal evidence snapshots")?;
    for path in &all_paths {
        let maximum = match path.as_str() {
            B4_TERMINAL_EVIDENCE_MANIFEST_FILE => MANIFEST_MAX_BYTES,
            B4_TERMINAL_EVIDENCE_COMPLETION_FILE => COMPLETION_MAX_BYTES,
            _ => roles
                .iter()
                .find(|role| role.path == *path)
                .map(|role| role.maximum)
                .context("final snapshot encountered an unknown payload path")?,
        };
        let opened_path = root.join(portable_path(path)?);
        let (file, snapshot) = open_and_read_file(&opened_path, maximum)?;
        let (identity, digest) = if path == B4_TERMINAL_EVIDENCE_MANIFEST_FILE {
            (manifest.final_identity, manifest.sha256)
        } else if path == B4_TERMINAL_EVIDENCE_COMPLETION_FILE {
            (completion.final_identity, completion.sha256)
        } else {
            let payload = payloads
                .get(path)
                .context("final snapshot payload disappeared")?;
            (payload.final_identity, payload.sha256)
        };
        ensure!(
            snapshot.final_identity == identity && snapshot.sha256 == digest,
            "{path} changed before the packet-wide final snapshot"
        );
        retained_snapshots.push(RetainedFinalSnapshot {
            relative: path.clone(),
            path: opened_path,
            maximum,
            file,
            snapshot,
        });
        hook(ReopenEvent::AfterFinalSnapshot, path);
    }

    tree.reauthenticate(&all_paths)
        .context("terminal evidence directory changed during the final snapshot")?;
    for retained in &mut retained_snapshots {
        let held = read_opened_file(&retained.path, &mut retained.file, retained.maximum)
            .with_context(|| {
                format!("{} changed on its retained final handle", retained.relative)
            })?;
        ensure!(
            held.final_identity == retained.snapshot.final_identity
                && held.sha256 == retained.snapshot.sha256,
            "{} changed on its retained final handle",
            retained.relative
        );
        let reopened = read_one_opened_file(&retained.path, retained.maximum)
            .with_context(|| format!("{} changed after its final snapshot", retained.relative))?;
        ensure!(
            reopened.final_identity == retained.snapshot.final_identity
                && reopened.sha256 == retained.snapshot.sha256,
            "{} changed after its final snapshot",
            retained.relative
        );
    }
    tree.reauthenticate(&all_paths)
        .context("terminal evidence tree changed after final path revalidation")?;
    let physical_closure_identity = B4PhysicalPacketClosureIdentityV1::from_stable_reopen(
        directory_identities,
        retained_snapshots,
        &all_paths,
        tree,
    )?;

    mint_b4_verified_terminal_evidence_packet(B4MeasuredTerminalEvidencePacketV1 {
        manifest_bytes: manifest.bytes,
        physical_closure_identity: Some(physical_closure_identity),
        payloads,
    })
}

#[cfg(windows)]
fn validate_exact_tree(
    root: &Path,
    files: &BTreeSet<String>,
) -> Result<BTreeMap<String, PlatformDirectoryIdentity>> {
    let expected = expected_directory_entries(files)?;
    let mut identities = BTreeMap::new();
    for (relative, entries) in &expected {
        let directory = if relative.is_empty() {
            root.to_path_buf()
        } else {
            root.join(portable_path(relative)?)
        };
        validate_ordinary_directory(&directory)?;
        ensure!(
            identities
                .insert(relative.clone(), directory_identity(&directory)?)
                .is_none(),
            "duplicate terminal evidence directory identity path"
        );
        let mut observed = BTreeSet::new();
        for entry in fs::read_dir(&directory)
            .with_context(|| format!("cannot read directory {}", directory.display()))?
        {
            let entry = entry.context("cannot read terminal evidence directory entry")?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .context("terminal evidence entry name is not UTF-8")?;
            record_expected_directory_entry(&mut observed, entries, name, &directory)?;
        }
        ensure!(
            observed == *entries,
            "{} does not have the exact compiled terminal evidence shape",
            directory.display()
        );
    }
    Ok(identities)
}

fn expected_directory_entries(
    files: &BTreeSet<String>,
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut directories = BTreeMap::<String, BTreeSet<String>>::new();
    directories.entry(String::new()).or_default();
    for file in files {
        let components = file.split('/').collect::<Vec<_>>();
        ensure!(
            !components.is_empty(),
            "compiled terminal evidence path is empty"
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
        directories
            .entry(parent)
            .or_default()
            .insert(components[components.len() - 1].to_owned());
    }
    Ok(directories)
}

fn record_expected_directory_entry(
    observed: &mut BTreeSet<String>,
    expected: &BTreeSet<String>,
    name: &str,
    diagnostic: &Path,
) -> Result<()> {
    ensure!(
        expected.contains(name),
        "{} does not have the exact compiled terminal evidence shape",
        diagnostic.display()
    );
    ensure!(
        observed.insert(name.to_owned()),
        "duplicate terminal evidence directory entry in {}",
        diagnostic.display()
    );
    Ok(())
}

#[cfg(windows)]
fn validate_ordinary_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect directory {}", path.display()))?;
    ensure!(
        metadata.file_type().is_dir()
            && !metadata.file_type().is_symlink()
            && !metadata_is_reparse_point(&metadata),
        "{} is not an ordinary non-reparse directory",
        path.display()
    );
    Ok(())
}

#[cfg(windows)]
fn stable_read_file(
    root: &Path,
    relative: &str,
    maximum: usize,
    hook: &mut impl FnMut(ReopenEvent, &str),
) -> Result<StableFile> {
    let path = root.join(portable_path(relative)?);
    let (first_file, first) = open_and_read_file(&path, maximum)?;
    hook(ReopenEvent::AfterFirstRead, relative);
    let (second_file, second) = open_and_read_file(&path, maximum)?;
    ensure!(
        first.final_identity == second.final_identity && first.sha256 == second.sha256,
        "{relative} changed between stable-file snapshots"
    );
    drop((first_file, second_file));
    Ok(second)
}

#[cfg(windows)]
fn read_one_opened_file(path: &Path, maximum: usize) -> Result<StableFile> {
    open_and_read_file(path, maximum).map(|(_file, snapshot)| snapshot)
}

#[cfg(windows)]
fn open_and_read_file(path: &Path, maximum: usize) -> Result<(File, StableFile)> {
    let mut file =
        open_without_following(path).with_context(|| format!("cannot open {}", path.display()))?;
    let snapshot = read_opened_file(path, &mut file, maximum)?;
    Ok((file, snapshot))
}

fn read_opened_file(path: &Path, file: &mut File, maximum: usize) -> Result<StableFile> {
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("cannot seek {}", path.display()))?;
    let identity = opened_file_identity(path, file)?;
    ensure!(
        identity.byte_length <= u64::try_from(maximum)?,
        "{} exceeds its compiled role bound",
        path.display()
    );
    let expected_length = usize::try_from(identity.byte_length)
        .context("opened terminal evidence file length overflows usize")?;
    let read_limit = u64::try_from(maximum)?
        .checked_add(1)
        .context("terminal evidence role bound overflows read limit")?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(expected_length)
        .context("cannot allocate bounded terminal evidence file")?;
    file.by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {}", path.display()))?;
    ensure!(
        bytes.len() == expected_length,
        "{} changed size while being read",
        path.display()
    );
    let sha256 = Sha256::digest(&bytes).into();
    Ok(StableFile {
        bytes,
        byte_length: identity.byte_length,
        sha256,
        final_identity: identity,
    })
}

#[cfg(windows)]
fn open_directory_for_identity(path: &Path) -> Result<(File, PlatformDirectoryIdentity)> {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("cannot open directory {}", path.display()))?;
    let identity = opened_directory_identity(path, &file)?;
    Ok((file, identity))
}

#[cfg(windows)]
fn opened_directory_identity(path: &Path, file: &File) -> Result<PlatformDirectoryIdentity> {
    const FILE_ATTRIBUTE_REPARSE_POINT: u64 = 0x0400;
    let information = winapi_util::file::information(&file)
        .with_context(|| format!("cannot inspect opened directory {}", path.display()))?;
    ensure!(
        information.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "{} is an opened reparse directory",
        path.display()
    );
    Ok(PlatformDirectoryIdentity {
        volume_or_device: information.volume_serial_number(),
        directory: information.file_index(),
    })
}

#[cfg(windows)]
fn directory_identity(path: &Path) -> Result<PlatformDirectoryIdentity> {
    open_directory_for_identity(path).map(|(_file, identity)| identity)
}

#[cfg(windows)]
fn open_without_following(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt as _;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(unix)]
fn opened_file_identity(path: &Path, file: &File) -> Result<PlatformFileIdentity> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .with_context(|| format!("cannot inspect opened file {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "{} is not an ordinary regular file",
        path.display()
    );
    ensure!(
        metadata.nlink() == 1,
        "{} must have exactly one hard link",
        path.display()
    );
    Ok(PlatformFileIdentity {
        volume_or_device: metadata.dev(),
        file: metadata.ino(),
        byte_length: metadata.len(),
    })
}

#[cfg(windows)]
fn opened_file_identity(path: &Path, file: &File) -> Result<PlatformFileIdentity> {
    const FILE_ATTRIBUTE_REPARSE_POINT: u64 = 0x0400;

    let information = winapi_util::file::information(file)
        .with_context(|| format!("cannot query opened Windows file {}", path.display()))?;
    ensure!(
        information.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "{} is a reparse point",
        path.display()
    );
    ensure!(
        winapi_util::file::typ(file)
            .with_context(|| format!("cannot query opened Windows file {}", path.display()))?
            .is_disk(),
        "{} is not an ordinary disk file",
        path.display()
    );
    ensure!(
        information.number_of_links() == 1,
        "{} must have exactly one hard link",
        path.display()
    );
    Ok(PlatformFileIdentity {
        volume_or_device: information.volume_serial_number(),
        file: information.file_index(),
        byte_length: information.file_size(),
    })
}

fn portable_path(relative: &str) -> Result<PathBuf> {
    ensure!(
        !relative.is_empty()
            && !relative.starts_with('/')
            && !relative.ends_with('/')
            && !relative.contains('\\'),
        "terminal evidence path is not portable"
    );
    let mut path = PathBuf::new();
    for component in relative.split('/') {
        ensure!(
            !component.is_empty() && component != "." && component != "..",
            "terminal evidence path is not safe"
        );
        path.push(component);
    }
    Ok(path)
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(test)]
mod tests {
    include!("b4_terminal_evidence_io_tests.rs");
}
