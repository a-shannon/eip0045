//! Bounded, non-authorizing wire values for the H0 attempt protocol.

use crate::{ReplayRoleV2, state::AttemptPhaseV1};
use core::fmt;
use sha2::{Digest as _, Sha256};

/// Fixed frame marker for this local protocol revision.
pub const FRAME_MAGIC_V1: [u8; 8] = *b"EIP45H0F";
/// Fixed frame version for this local protocol revision.
pub const FRAME_VERSION_V1: u16 = 1;
/// Maximum encoded frame length, including the body and ordered FD roles.
pub const MAX_FRAME_BYTES_V1: usize = 65_536;
/// Maximum number of transferred descriptors carried by one frame.
pub const MAX_FRAME_FDS_V1: usize = 16;
/// Maximum number of frames in one transcript chain.
pub const MAX_SESSION_FRAMES_V1: u8 = 64;
/// Encoded length before the ordered FD roles and body.
pub const FRAME_FIXED_HEADER_BYTES_V1: usize = 82;

const TRANSCRIPT_DOMAIN_V1: &[u8] = b"eip0045-b4-h0-frame-transcript-v1";

const SEALED_INGRESS_MANIFEST_DOMAIN_V1: &[u8] = b"eip0045-b4-h0-sealed-ingress-manifest-v1\0";
const PUBLICATION_TARGET_DOMAIN_V1: &[u8] = b"eip0045-b4-h0-publication-target-v1\0";
const REQUEST_COMMITMENT_DOMAIN_V1: &[u8] = b"eip0045-b4-h0-request-commitment-v1\0";
const ENDPOINT_COMMITMENT_DOMAIN_V1: &[u8] = b"eip0045-b4-h0-seqpacket-endpoint-v1\0";
const GENERATOR_CHANNEL_IDENTITY_DOMAIN_V1: &[u8] =
    b"eip0045-b4-h0-generator-channel-identity-v1\0";
const WORKER_CHANNEL_IDENTITY_DOMAIN_V1: &[u8] = b"eip0045-b4-h0-worker-channel-identity-v1\0";
const SESSION_OFFER_DOMAIN_V1: &[u8] = b"eip0045-b4-h0-session-offer-v1\0";
const NONCE_COMMITMENT_DOMAIN_V1: &[u8] = b"eip0045-b4-h0-nonce-commitment-v1\0";
const PRE_SESSION_RECORD_MAGIC_V1: [u8; 8] = *b"EIP45H0N";
const PROVIDER_SESSION_DOMAIN_V1: &[u8] = b"eip0045-b4-h0-session-id-v1\0";
const PROCESS_INVENTORY_DOMAIN_V1: &[u8] = b"eip0045-b4-h0-process-inventory-v1\0";
const GENERATOR_CHANNEL_GENESIS_DOMAIN_V1: &[u8] = b"eip0045-b4-h0-generator-channel-genesis-v1\0";
const WORKER_CHANNEL_GENESIS_DOMAIN_V1: &[u8] = b"eip0045-b4-h0-worker-channel-genesis-v1\0";
const GENERATOR_BOUND_BODY_DOMAIN_V1: &[u8] = b"eip0045-b4-h0-generator-bound-body-v1\0";
const GENERATOR_SEAL_PROFILE_DOMAIN_V1: &[u8] = b"eip0045-b4-h0-generator-seal-profile-v1\0";
const WORKER_TRANSFER_MANIFEST_DOMAIN_V1: &[u8] = b"eip0045-b4-h0-worker-transfer-manifest-v1\0";
const WORKER_BOOTSTRAP_BODY_DOMAIN_V1: &[u8] = b"eip0045-b4-h0-worker-bootstrap-body-v1\0";
const WORKER_EXEC_BOUND_BODY_DOMAIN_V1: &[u8] = b"eip0045-b4-h0-worker-exec-bound-body-v1\0";
const CLOSED_RESULT_BODY_DOMAIN_V1: &[u8] = b"eip0045-b4-h0-closed-result-body-v1\0";

const PROVIDER_ID_V1: &[u8] = b"eip0045-b4-tmpfs-metadata-provider-v1";
const POLICY_ID_V1: &[u8] = b"eip0045-b4-retained-host-rootfs-metadata-obligations-v2";
const SESSION_PROTOCOL_ID_V1: &[u8] = b"eip0045-b4-supervised-filesystem-session-v1";
const APPLIANCE_ID_V1: &[u8] = b"eip0045-b4-buildroot-appliance-v1";

/// Maximum number of campaign-input commitments in the G0 ingress projection.
pub const G0_MAX_INGRESS_COUNT_V1: usize = 15;
/// Exact canonical request preimage length.
pub const G0_REQUEST_PREIMAGE_BYTES_V1: usize = 772;
/// Exact canonical session-offer record length.
pub const G0_SESSION_OFFER_BYTES_V1: usize = 1_101;
/// Exact canonical nonce commit or reveal record length.
pub const G0_PRE_SESSION_RECORD_BYTES_V1: usize = 75;
/// Exact canonical provider-session preimage length.
pub const G0_PROVIDER_SESSION_PREIMAGE_BYTES_V1: usize = 373;
/// Exact generator-channel genesis preimage length.
pub const G0_GENERATOR_CHANNEL_GENESIS_BYTES_V1: usize = 203;
/// Exact worker-channel genesis preimage length.
pub const G0_WORKER_CHANNEL_GENESIS_BYTES_V1: usize = 232;
/// Exact `GeneratorBound` body length.
pub const G0_GENERATOR_BOUND_BODY_BYTES_V1: usize = 234;
/// Exact zero-FD `GeneratorBound` raw-frame length.
pub const G0_GENERATOR_BOUND_RAW_FRAME_BYTES_V1: usize = 316;
/// Exact `WorkerExecBound` body length.
pub const G0_WORKER_EXEC_BOUND_BODY_BYTES_V1: usize = 236;
/// Exact zero-FD `WorkerExecBound` raw-frame length.
pub const G0_WORKER_EXEC_BOUND_RAW_FRAME_BYTES_V1: usize = 318;
/// Exact closed-result body length.
pub const G0_CLOSED_RESULT_BODY_BYTES_V1: usize = 136;
/// Exact one-FD `ClosedResult` raw-frame length.
pub const G0_CLOSED_RESULT_RAW_FRAME_BYTES_V1: usize = 219;
/// Maximum accepted `FinalResult` content length.
pub const G0_FINAL_RESULT_MAX_BYTES_V1: usize = 1_048_576;
/// Maximum logical content length admitted for one worker-transfer role.
pub const G0_WORKER_TRANSFER_ROLE_MAX_BYTES_V1: u64 = 1_073_741_824;
/// Maximum checked logical content sum admitted for one worker transfer.
pub const G0_WORKER_TRANSFER_AGGREGATE_MAX_BYTES_V1: u64 = 4_294_967_296;
/// Maximum chunk accepted by the worker bootstrap streaming verifier.
pub const G0_WORKER_BOOTSTRAP_HASH_CHUNK_BYTES_V1: usize = 65_536;
/// Fixed bytes before the variable worker-transfer manifest in the bootstrap body.
pub const G0_WORKER_BOOTSTRAP_FIXED_BODY_BYTES_V1: usize = 674;

fn sha256_v1(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn push_lp16_v1(output: &mut Vec<u8>, value: &[u8]) -> Result<(), WireErrorV1> {
    let length = u16::try_from(value.len()).map_err(|_| WireErrorV1::ArithmeticOverflow)?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(value);
    Ok(())
}

/// A direction supported by the two supervised socket pairs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameDirectionV1 {
    /// Generator to supervisor.
    GeneratorToSupervisor,
    /// Supervisor to generator.
    SupervisorToGenerator,
    /// Supervisor to worker.
    SupervisorToWorker,
    /// Worker to supervisor.
    WorkerToSupervisor,
}

impl FrameDirectionV1 {
    const fn wire_code(self) -> u8 {
        match self {
            Self::GeneratorToSupervisor => 0,
            Self::SupervisorToGenerator => 1,
            Self::SupervisorToWorker => 2,
            Self::WorkerToSupervisor => 3,
        }
    }
}

/// Descriptor-rooted identity and mount tuple observed by a separate owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorIdentityV1 {
    device: u64,
    inode: u64,
    mount_id: u64,
}

impl DescriptorIdentityV1 {
    /// Constructs a non-zero descriptor identity tuple.
    ///
    /// # Errors
    ///
    /// Returns [`WireErrorV1::InvalidDescriptorIdentity`] when any component
    /// is zero.
    pub const fn try_new(device: u64, inode: u64, mount_id: u64) -> Result<Self, WireErrorV1> {
        if device == 0 || inode == 0 || mount_id == 0 {
            return Err(WireErrorV1::InvalidDescriptorIdentity);
        }
        Ok(Self {
            device,
            inode,
            mount_id,
        })
    }

    fn encode_into(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.device.to_le_bytes());
        output.extend_from_slice(&self.inode.to_le_bytes());
        output.extend_from_slice(&self.mount_id.to_le_bytes());
    }
}

/// Exact peer credentials plus the receiving user-namespace identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentialsV1 {
    process_id: u32,
    user_id: u32,
    group_id: u32,
    user_namespace: DescriptorIdentityV1,
}

impl PeerCredentialsV1 {
    /// Constructs a positive process identity and its projected credentials.
    ///
    /// # Errors
    ///
    /// Returns [`WireErrorV1::InvalidPeerProcessId`] for process ID zero.
    pub const fn try_new(
        process_id: u32,
        user_id: u32,
        group_id: u32,
        user_namespace: DescriptorIdentityV1,
    ) -> Result<Self, WireErrorV1> {
        if process_id == 0 {
            return Err(WireErrorV1::InvalidPeerProcessId);
        }
        Ok(Self {
            process_id,
            user_id,
            group_id,
            user_namespace,
        })
    }

    fn encode_into(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.process_id.to_le_bytes());
        output.extend_from_slice(&self.user_id.to_le_bytes());
        output.extend_from_slice(&self.group_id.to_le_bytes());
        self.user_namespace.encode_into(output);
    }
}

/// Closed filesystem node classification for retained descriptor identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FilesystemNodeKindV1 {
    /// Directory node.
    Directory,
    /// Regular-file node.
    RegularFile,
    /// Symbolic-link node opened without following it.
    SymbolicLink,
}

impl FilesystemNodeKindV1 {
    const fn wire_code(self) -> u8 {
        match self {
            Self::Directory => 0,
            Self::RegularFile => 1,
            Self::SymbolicLink => 2,
        }
    }
}

/// Closed namespace descriptor classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NamespaceKindV1 {
    /// User namespace.
    User,
    /// Mount namespace.
    Mount,
}

impl NamespaceKindV1 {
    const fn wire_code(self) -> u8 {
        match self {
            Self::User => 0,
            Self::Mount => 1,
        }
    }
}

/// The four memfd seal observations bound into a commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemfdSealsV1 {
    grow: SealPresenceV1,
    shrink: SealPresenceV1,
    write: SealPresenceV1,
    further_seals: SealPresenceV1,
}

/// Closed presence state for one observed memfd seal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SealPresenceV1 {
    /// The seal is absent.
    Absent,
    /// The seal is present.
    Present,
}

impl SealPresenceV1 {
    const fn is_present(self) -> bool {
        matches!(self, Self::Present)
    }

    const fn wire_code(self) -> u8 {
        match self {
            Self::Absent => 0,
            Self::Present => 1,
        }
    }
}

impl MemfdSealsV1 {
    /// Constructs the exact observed seal set.
    #[must_use]
    pub const fn new(
        grow: SealPresenceV1,
        shrink: SealPresenceV1,
        write: SealPresenceV1,
        further_seals: SealPresenceV1,
    ) -> Self {
        Self {
            grow,
            shrink,
            write,
            further_seals,
        }
    }

    const fn fixes_size(self) -> bool {
        self.grow.is_present() && self.shrink.is_present()
    }

    const fn fully_sealed(self) -> bool {
        self.fixes_size() && self.write.is_present() && self.further_seals.is_present()
    }

    fn encode_into(self, output: &mut Vec<u8>) {
        output.push(self.grow.wire_code());
        output.push(self.shrink.wire_code());
        output.push(self.write.wire_code());
        output.push(self.further_seals.wire_code());
    }
}

/// Closed access mode for a transferred descriptor role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FdAccessV1 {
    /// Metadata-only path handle.
    Path,
    /// Read-only data handle.
    ReadOnly,
    /// Write-only data handle.
    WriteOnly,
    /// Read/write data handle.
    ReadWrite,
    /// Process handle.
    Process,
    /// Connected socket endpoint.
    Socket,
}

impl FdAccessV1 {
    const fn wire_code(self) -> u8 {
        match self {
            Self::Path => 0,
            Self::ReadOnly => 1,
            Self::WriteOnly => 2,
            Self::ReadWrite => 3,
            Self::Process => 4,
            Self::Socket => 5,
        }
    }
}

/// Status and close-on-exec observations for one transferred descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FdStatusV1 {
    access: FdAccessV1,
    nonblocking: bool,
    close_on_exec: bool,
}

impl FdStatusV1 {
    /// Constructs the exact observed status tuple.
    #[must_use]
    pub const fn new(access: FdAccessV1, nonblocking: bool, close_on_exec: bool) -> Self {
        Self {
            access,
            nonblocking,
            close_on_exec,
        }
    }

    fn encode_into(self, output: &mut Vec<u8>) {
        output.push(self.access.wire_code());
        output.push(u8::from(self.nonblocking));
        output.push(u8::from(self.close_on_exec));
    }
}

/// Closed semantic role for one descriptor in a frame inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FdRoleV1 {
    /// Sealed ingress memfd at the given bounded inventory position.
    CampaignInput(u8),
    /// Descriptor-rooted create-only publication directory.
    PublicationRoot,
    /// Supervisor process handle.
    SupervisorProcess,
    /// Generator-side connected endpoint.
    GeneratorEndpoint,
    /// Worker-side connected endpoint.
    WorkerEndpoint,
    /// Attempt cgroup directory.
    AttemptCgroup,
    /// Attempt user namespace.
    UserNamespace,
    /// Attempt mount namespace.
    MountNamespace,
    /// Size-fixed observation memfd.
    Observation,
    /// Fully sealed final-result memfd.
    FinalResult,
    /// Provider-owned mounted root.
    MountedRoot,
    /// One role-specific root directory.
    RoleRoot(ReplayRoleV2),
    /// One retained OCI entry in its exact role-local position.
    RetainedEntry {
        /// Replay role owning this entry.
        role: ReplayRoleV2,
        /// Exact position within that role's canonical plan.
        index: u32,
    },
}

impl FdRoleV1 {
    const fn encoded_len(self) -> usize {
        match self {
            Self::CampaignInput(_) | Self::RoleRoot(_) => 2,
            Self::RetainedEntry { .. } => 6,
            _ => 1,
        }
    }

    fn encode_into(self, output: &mut Vec<u8>) {
        match self {
            Self::CampaignInput(index) => {
                output.push(0);
                output.push(index);
            }
            Self::PublicationRoot => output.push(1),
            Self::SupervisorProcess => output.push(2),
            Self::GeneratorEndpoint => output.push(3),
            Self::WorkerEndpoint => output.push(4),
            Self::AttemptCgroup => output.push(5),
            Self::UserNamespace => output.push(6),
            Self::MountNamespace => output.push(7),
            Self::Observation => output.push(8),
            Self::FinalResult => output.push(9),
            Self::MountedRoot => output.push(10),
            Self::RoleRoot(role) => {
                output.push(11);
                output.push(replay_role_code(role));
            }
            Self::RetainedEntry { role, index } => {
                output.push(12);
                output.push(replay_role_code(role));
                output.extend_from_slice(&index.to_le_bytes());
            }
        }
    }
}

const fn replay_role_code(role: ReplayRoleV2) -> u8 {
    match role {
        ReplayRoleV2::RustValidatorBuild => 0,
        ReplayRoleV2::JvmValidatorBuild => 1,
        ReplayRoleV2::RustVerifier => 2,
        ReplayRoleV2::JvmVerifier => 3,
    }
}

/// Closed identity union; each variant carries only fields meaningful to it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FdIdentityV1 {
    /// A retained filesystem node and its descriptor-rooted mount tuple.
    Filesystem {
        /// Descriptor-rooted identity.
        descriptor: DescriptorIdentityV1,
        /// Exact filesystem node class.
        node_kind: FilesystemNodeKindV1,
    },
    /// A namespace and its descriptor-rooted mount tuple.
    Namespace {
        /// Descriptor-rooted identity.
        descriptor: DescriptorIdentityV1,
        /// Exact namespace class.
        kind: NamespaceKindV1,
    },
    /// A memfd's bounded content and seal observations.
    Memfd {
        /// Exact byte length.
        size: u64,
        /// Digest supplied by the separate content verifier.
        content_digest: [u8; 32],
        /// Exact observed seals.
        seals: MemfdSealsV1,
    },
    /// A process handle and its start epoch.
    Pidfd {
        /// Positive process identity.
        process_id: u32,
        /// Non-zero process start epoch.
        start_epoch: u64,
    },
    /// A connected socket endpoint commitment.
    Socket {
        /// Exact endpoint commitment.
        endpoint_digest: [u8; 32],
    },
    /// A cgroup hierarchy and exact path commitment.
    Cgroup {
        /// Exact hierarchy commitment.
        hierarchy_digest: [u8; 32],
        /// Exact path commitment.
        path_digest: [u8; 32],
    },
}

impl FdIdentityV1 {
    fn validate(self) -> Result<(), WireErrorV1> {
        if let Self::Pidfd {
            process_id,
            start_epoch,
        } = self
            && (process_id == 0 || start_epoch == 0)
        {
            return Err(WireErrorV1::InvalidPidfdIdentity);
        }
        Ok(())
    }

    fn encode_into(self, output: &mut Vec<u8>) {
        match self {
            Self::Filesystem {
                descriptor,
                node_kind,
            } => {
                output.push(0);
                descriptor.encode_into(output);
                output.push(node_kind.wire_code());
            }
            Self::Namespace { descriptor, kind } => {
                output.push(1);
                descriptor.encode_into(output);
                output.push(kind.wire_code());
            }
            Self::Memfd {
                size,
                content_digest,
                seals,
            } => {
                output.push(2);
                output.extend_from_slice(&size.to_le_bytes());
                output.extend_from_slice(&content_digest);
                seals.encode_into(output);
            }
            Self::Pidfd {
                process_id,
                start_epoch,
            } => {
                output.push(3);
                output.extend_from_slice(&process_id.to_le_bytes());
                output.extend_from_slice(&start_epoch.to_le_bytes());
            }
            Self::Socket { endpoint_digest } => {
                output.push(4);
                output.extend_from_slice(&endpoint_digest);
            }
            Self::Cgroup {
                hierarchy_digest,
                path_digest,
            } => {
                output.push(5);
                output.extend_from_slice(&hierarchy_digest);
                output.extend_from_slice(&path_digest);
            }
        }
    }
}

/// One role, identity, access/status, and close-on-exec commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FdCommitmentV1 {
    role: FdRoleV1,
    identity: FdIdentityV1,
    status: FdStatusV1,
}

impl FdCommitmentV1 {
    /// Constructs a role-specific commitment and rejects category/status drift.
    ///
    /// # Errors
    ///
    /// Returns a [`WireErrorV1`] when the role index, identity category,
    /// identity values, access/status mode, or required memfd seals differ from
    /// the closed role contract.
    pub fn try_new(
        role: FdRoleV1,
        identity: FdIdentityV1,
        status: FdStatusV1,
    ) -> Result<Self, WireErrorV1> {
        let candidate = Self {
            role,
            identity,
            status,
        };
        candidate.validate()?;
        Ok(candidate)
    }

    /// Returns the semantic inventory role.
    #[must_use]
    pub const fn role(&self) -> FdRoleV1 {
        self.role
    }

    fn validate(&self) -> Result<(), WireErrorV1> {
        self.identity.validate()?;
        if let FdRoleV1::CampaignInput(index) = self.role
            && usize::from(index) >= MAX_FRAME_FDS_V1
        {
            return Err(WireErrorV1::RoleIndexOutOfRange(index));
        }

        let identity_matches = matches!(
            (self.role, self.identity),
            (
                FdRoleV1::PublicationRoot | FdRoleV1::MountedRoot | FdRoleV1::RoleRoot(_),
                FdIdentityV1::Filesystem {
                    node_kind: FilesystemNodeKindV1::Directory,
                    ..
                },
            ) | (
                FdRoleV1::RetainedEntry { .. },
                FdIdentityV1::Filesystem { .. }
            ) | (
                FdRoleV1::CampaignInput(_) | FdRoleV1::Observation | FdRoleV1::FinalResult,
                FdIdentityV1::Memfd { .. }
            ) | (FdRoleV1::SupervisorProcess, FdIdentityV1::Pidfd { .. })
                | (
                    FdRoleV1::GeneratorEndpoint | FdRoleV1::WorkerEndpoint,
                    FdIdentityV1::Socket { .. },
                )
                | (FdRoleV1::AttemptCgroup, FdIdentityV1::Cgroup { .. })
                | (
                    FdRoleV1::UserNamespace,
                    FdIdentityV1::Namespace {
                        kind: NamespaceKindV1::User,
                        ..
                    },
                )
                | (
                    FdRoleV1::MountNamespace,
                    FdIdentityV1::Namespace {
                        kind: NamespaceKindV1::Mount,
                        ..
                    },
                )
        );
        if !identity_matches {
            return Err(WireErrorV1::RoleIdentityMismatch(self.role));
        }

        let access_matches = match self.role {
            FdRoleV1::PublicationRoot
            | FdRoleV1::AttemptCgroup
            | FdRoleV1::UserNamespace
            | FdRoleV1::MountNamespace
            | FdRoleV1::MountedRoot
            | FdRoleV1::RoleRoot(_)
            | FdRoleV1::RetainedEntry { .. } => self.status.access == FdAccessV1::Path,
            FdRoleV1::CampaignInput(_) | FdRoleV1::FinalResult => {
                self.status.access == FdAccessV1::ReadOnly
            }
            FdRoleV1::Observation => self.status.access == FdAccessV1::ReadWrite,
            FdRoleV1::SupervisorProcess => self.status.access == FdAccessV1::Process,
            FdRoleV1::GeneratorEndpoint | FdRoleV1::WorkerEndpoint => {
                self.status.access == FdAccessV1::Socket
            }
        };
        let nonblocking_matches = !self.status.nonblocking
            || matches!(
                self.role,
                FdRoleV1::GeneratorEndpoint | FdRoleV1::WorkerEndpoint
            );
        if !access_matches || !nonblocking_matches {
            return Err(WireErrorV1::RoleStatusMismatch(self.role));
        }

        if let FdIdentityV1::Memfd { seals, .. } = self.identity {
            let required = match self.role {
                FdRoleV1::CampaignInput(_) | FdRoleV1::FinalResult => seals.fully_sealed(),
                FdRoleV1::Observation => seals.fixes_size(),
                _ => true,
            };
            if !required {
                return Err(WireErrorV1::RequiredMemfdSeals(self.role));
            }
        }
        Ok(())
    }

    fn encode_into(self, output: &mut Vec<u8>) {
        self.role.encode_into(output);
        self.identity.encode_into(output);
        self.status.encode_into(output);
    }
}

/// Encodes one descriptor commitment through the sole canonical V1 encoder.
///
/// The returned bytes describe a non-authorizing value. They neither retain
/// the descriptor nor prove that any live descriptor matches the observation.
///
/// # Errors
///
/// Returns a [`WireErrorV1`] when the stored role, identity, status, or seal
/// combination is outside the closed V1 contract.
pub fn encode_fd_commitment_v1(commitment: &FdCommitmentV1) -> Result<Vec<u8>, WireErrorV1> {
    commitment.validate()?;
    let mut output = Vec::with_capacity(80);
    commitment.encode_into(&mut output);
    Ok(output)
}

/// Returns the exact encoded length produced by [`encode_fd_commitment_v1`].
///
/// # Errors
///
/// Returns a [`WireErrorV1`] when the commitment is invalid or its canonical
/// encoded length cannot be represented by the V1 `u16` length field.
pub fn encoded_fd_commitment_len_v1(commitment: &FdCommitmentV1) -> Result<u16, WireErrorV1> {
    let encoded = encode_fd_commitment_v1(commitment)?;
    u16::try_from(encoded.len()).map_err(|_| WireErrorV1::ArithmeticOverflow)
}

/// Canonical, non-authorizing sealed-ingress manifest bytes.
#[derive(Debug, Eq, PartialEq)]
pub struct SealedIngressManifestV1 {
    bytes: Vec<u8>,
    count: u8,
    digest: [u8; 32],
}

impl SealedIngressManifestV1 {
    /// Encodes zero through fifteen role-ordered `CampaignInput` commitments.
    ///
    /// # Errors
    ///
    /// Returns a [`WireErrorV1`] for an excessive count or any role, ordinal,
    /// commitment, length, or checked-arithmetic drift.
    pub fn try_new(commitments: &[FdCommitmentV1]) -> Result<Self, WireErrorV1> {
        if commitments.len() > G0_MAX_INGRESS_COUNT_V1 {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::IngressCount,
            ));
        }
        let count = u8::try_from(commitments.len())
            .map_err(|_| WireErrorV1::G0ContractDrift(G0ContractFieldV1::IngressCount))?;
        let records_bytes = commitments
            .len()
            .checked_mul(53)
            .ok_or(WireErrorV1::ArithmeticOverflow)?;
        let length = 44_usize
            .checked_add(records_bytes)
            .ok_or(WireErrorV1::ArithmeticOverflow)?;
        let mut bytes = Vec::with_capacity(length);
        bytes.extend_from_slice(SEALED_INGRESS_MANIFEST_DOMAIN_V1);
        bytes.extend_from_slice(&FRAME_VERSION_V1.to_le_bytes());
        bytes.push(count);
        for (ordinal, commitment) in commitments.iter().enumerate() {
            let ordinal = u8::try_from(ordinal).map_err(|_| WireErrorV1::ArithmeticOverflow)?;
            if commitment.role != FdRoleV1::CampaignInput(ordinal) {
                return Err(WireErrorV1::G0ContractDrift(
                    G0ContractFieldV1::IngressCommitment,
                ));
            }
            let encoded = encode_fd_commitment_v1(commitment)?;
            let encoded_length = encoded_fd_commitment_len_v1(commitment)?;
            if encoded_length != 50 {
                return Err(WireErrorV1::G0ContractDrift(
                    G0ContractFieldV1::IngressCommitment,
                ));
            }
            bytes.push(ordinal);
            bytes.extend_from_slice(&encoded_length.to_le_bytes());
            bytes.extend_from_slice(&encoded);
        }
        debug_assert_eq!(bytes.len(), length);
        let digest = sha256_v1(&bytes);
        Ok(Self {
            bytes,
            count,
            digest,
        })
    }

    /// Returns the exact canonical bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the encoded campaign-input count.
    #[must_use]
    pub const fn count(&self) -> u8 {
        self.count
    }

    /// Returns SHA-256 of the complete canonical manifest bytes.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Non-authorizing publication-target commitment and its canonical preimage.
#[derive(Debug, Eq, PartialEq)]
pub struct PublicationTargetCommitmentV1 {
    preimage: [u8; 132],
    digest: [u8; 32],
}

impl PublicationTargetCommitmentV1 {
    /// Binds one `PublicationRoot` commitment to the two Task 3 destinations.
    ///
    /// # Errors
    ///
    /// Returns a [`WireErrorV1`] when the descriptor commitment is not the
    /// exact canonical `PublicationRoot` shape.
    pub fn try_new(
        publication_root: &FdCommitmentV1,
        destination_input_ai: [u8; 32],
        destination_completion_ai: [u8; 32],
    ) -> Result<Self, WireErrorV1> {
        if publication_root.role != FdRoleV1::PublicationRoot {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::PublicationRoot,
            ));
        }
        let encoded = encode_fd_commitment_v1(publication_root)?;
        let encoded_length = encoded_fd_commitment_len_v1(publication_root)?;
        if encoded_length != 30 {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::PublicationRoot,
            ));
        }
        let mut preimage = Vec::with_capacity(132);
        preimage.extend_from_slice(PUBLICATION_TARGET_DOMAIN_V1);
        preimage.extend_from_slice(&encoded_length.to_le_bytes());
        preimage.extend_from_slice(&encoded);
        preimage.extend_from_slice(&destination_input_ai);
        preimage.extend_from_slice(&destination_completion_ai);
        let preimage: [u8; 132] = preimage
            .try_into()
            .map_err(|_| WireErrorV1::ArithmeticOverflow)?;
        let digest = sha256_v1(&preimage);
        Ok(Self { preimage, digest })
    }

    /// Returns the exact 132-byte commitment preimage.
    #[must_use]
    pub const fn preimage(&self) -> &[u8; 132] {
        &self.preimage
    }

    /// Returns SHA-256 of the canonical preimage.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// One of the four role-ordered request projection blocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestRoleBlockV1 {
    role: ReplayRoleV2,
    runner_ai: [u8; 32],
    oci_layout_commitment: [u8; 32],
    rootfs_plan_commitment: [u8; 32],
}

impl RequestRoleBlockV1 {
    /// Constructs bytes-only projection data for one canonical replay role.
    #[must_use]
    pub const fn new(
        role: ReplayRoleV2,
        runner_ai: [u8; 32],
        oci_layout_commitment: [u8; 32],
        rootfs_plan_commitment: [u8; 32],
    ) -> Self {
        Self {
            role,
            runner_ai,
            oci_layout_commitment,
            rootfs_plan_commitment,
        }
    }

    fn encode_into(self, output: &mut Vec<u8>) {
        output.push(replay_role_code(self.role));
        output.extend_from_slice(&self.runner_ai);
        output.extend_from_slice(&self.oci_layout_commitment);
        output.extend_from_slice(&self.rootfs_plan_commitment);
    }
}

/// Canonical request bytes and digest; neither value carries boot authority.
#[derive(Debug, Eq, PartialEq)]
pub struct RequestCommitmentV1 {
    preimage: [u8; G0_REQUEST_PREIMAGE_BYTES_V1],
    digest: [u8; 32],
    ingress_count: u8,
}

impl RequestCommitmentV1 {
    /// Encodes the fixed 772-byte request from retained projection values.
    ///
    /// # Errors
    ///
    /// Returns a [`WireErrorV1`] for role-order drift or checked-length drift.
    pub fn try_new(
        allocation_epoch: [u8; 32],
        positive_input_set_ai: [u8; 32],
        positive_generation_set_ai: [u8; 32],
        ingress: &SealedIngressManifestV1,
        publication_target: &PublicationTargetCommitmentV1,
        role_blocks: &[RequestRoleBlockV1; 4],
    ) -> Result<Self, WireErrorV1> {
        for (index, block) in role_blocks.iter().enumerate() {
            if usize::from(replay_role_code(block.role)) != index {
                return Err(WireErrorV1::G0ContractDrift(
                    G0ContractFieldV1::RequestRoleOrder,
                ));
            }
        }
        let expected_manifest_length = 44_usize
            .checked_add(
                usize::from(ingress.count)
                    .checked_mul(53)
                    .ok_or(WireErrorV1::ArithmeticOverflow)?,
            )
            .ok_or(WireErrorV1::ArithmeticOverflow)?;
        if ingress.bytes.len() != expected_manifest_length {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::IngressManifestLength,
            ));
        }
        let ingress_length =
            u64::try_from(ingress.bytes.len()).map_err(|_| WireErrorV1::ArithmeticOverflow)?;

        let mut preimage = Vec::with_capacity(G0_REQUEST_PREIMAGE_BYTES_V1);
        preimage.extend_from_slice(REQUEST_COMMITMENT_DOMAIN_V1);
        preimage.extend_from_slice(&FRAME_VERSION_V1.to_le_bytes());
        push_lp16_v1(&mut preimage, PROVIDER_ID_V1)?;
        push_lp16_v1(&mut preimage, POLICY_ID_V1)?;
        push_lp16_v1(&mut preimage, SESSION_PROTOCOL_ID_V1)?;
        push_lp16_v1(&mut preimage, APPLIANCE_ID_V1)?;
        preimage.extend_from_slice(&allocation_epoch);
        preimage.extend_from_slice(&positive_input_set_ai);
        preimage.extend_from_slice(&positive_generation_set_ai);
        preimage.push(ingress.count);
        preimage.extend_from_slice(&ingress_length.to_le_bytes());
        preimage.extend_from_slice(&ingress.digest);
        preimage.extend_from_slice(&publication_target.digest);
        preimage.push(4);
        for block in role_blocks {
            block.encode_into(&mut preimage);
        }
        let preimage: [u8; G0_REQUEST_PREIMAGE_BYTES_V1] = preimage
            .try_into()
            .map_err(|_| WireErrorV1::ArithmeticOverflow)?;
        let digest = sha256_v1(&preimage);
        Ok(Self {
            preimage,
            digest,
            ingress_count: ingress.count,
        })
    }

    /// Returns the exact fixed-size request preimage.
    #[must_use]
    pub const fn preimage(&self) -> &[u8; G0_REQUEST_PREIMAGE_BYTES_V1] {
        &self.preimage
    }

    /// Returns SHA-256 of the complete request preimage.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the bound campaign-input count.
    #[must_use]
    pub const fn ingress_count(&self) -> u8 {
        self.ingress_count
    }
}

/// Closed role of one observed `SOCK_SEQPACKET` endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SeqpacketEndpointRoleV1 {
    /// Generator endpoint.
    Generator = 0,
    /// Supervisor endpoint on the generator channel.
    SupervisorGenerator = 1,
    /// Supervisor endpoint on the worker channel.
    SupervisorWorker = 2,
    /// Worker endpoint.
    Worker = 3,
}

/// Canonical endpoint-observation bytes and digest; not endpoint custody.
#[derive(Debug, Eq, PartialEq)]
pub struct SeqpacketEndpointCommitmentV1 {
    role: SeqpacketEndpointRoleV1,
    preimage: [u8; 83],
    digest: [u8; 32],
}

impl SeqpacketEndpointCommitmentV1 {
    /// Encodes one complete endpoint observation with the closed socket tuple.
    ///
    /// This bytes-only value cannot establish that the observation was made by
    /// D3 or that the corresponding live endpoint remains in custody.
    #[must_use]
    pub fn from_observation(
        role: SeqpacketEndpointRoleV1,
        descriptor: DescriptorIdentityV1,
        socket_cookie: u64,
    ) -> Self {
        let mut preimage = Vec::with_capacity(83);
        preimage.extend_from_slice(ENDPOINT_COMMITMENT_DOMAIN_V1);
        preimage.extend_from_slice(&FRAME_VERSION_V1.to_le_bytes());
        preimage.push(role as u8);
        descriptor.encode_into(&mut preimage);
        preimage.extend_from_slice(&socket_cookie.to_le_bytes());
        preimage.extend_from_slice(&1_u32.to_le_bytes());
        preimage.extend_from_slice(&5_u32.to_le_bytes());
        preimage.extend_from_slice(&0_u32.to_le_bytes());
        let preimage: [u8; 83] = preimage
            .try_into()
            .unwrap_or_else(|_| unreachable!("fixed endpoint preimage length"));
        let digest = sha256_v1(&preimage);
        Self {
            role,
            preimage,
            digest,
        }
    }

    /// Returns the exact endpoint-observation preimage.
    #[must_use]
    pub const fn preimage(&self) -> &[u8; 83] {
        &self.preimage
    }

    /// Returns SHA-256 of the complete observation preimage.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Closed generator or worker channel identity kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelIdentityKindV1 {
    /// Generator/supervisor channel.
    Generator,
    /// Supervisor/worker channel.
    Worker,
}

/// Bytes-only channel identity derived from two role-correct endpoint digests.
#[derive(Debug, Eq, PartialEq)]
pub struct ChannelIdentityV1 {
    kind: ChannelIdentityKindV1,
    digest: [u8; 32],
}

impl ChannelIdentityV1 {
    fn from_ordered_endpoint_digests(
        kind: ChannelIdentityKindV1,
        domain: &[u8],
        first_endpoint_digest: [u8; 32],
        second_endpoint_digest: [u8; 32],
        expected_preimage_length: usize,
    ) -> Self {
        let mut preimage = Vec::with_capacity(expected_preimage_length);
        preimage.extend_from_slice(domain);
        preimage.extend_from_slice(&first_endpoint_digest);
        preimage.extend_from_slice(&second_endpoint_digest);
        debug_assert_eq!(preimage.len(), expected_preimage_length);
        Self {
            kind,
            digest: sha256_v1(&preimage),
        }
    }

    /// Derives the generator-channel identity in fixed endpoint-role order.
    ///
    /// # Errors
    ///
    /// Returns [`WireErrorV1::G0ContractDrift`] for endpoint-role substitution.
    pub fn try_generator(
        generator: &SeqpacketEndpointCommitmentV1,
        supervisor: &SeqpacketEndpointCommitmentV1,
    ) -> Result<Self, WireErrorV1> {
        if generator.role != SeqpacketEndpointRoleV1::Generator
            || supervisor.role != SeqpacketEndpointRoleV1::SupervisorGenerator
        {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::EndpointPair,
            ));
        }
        Ok(Self::from_ordered_endpoint_digests(
            ChannelIdentityKindV1::Generator,
            GENERATOR_CHANNEL_IDENTITY_DOMAIN_V1,
            generator.digest,
            supervisor.digest,
            108,
        ))
    }

    /// Derives the worker-channel identity in fixed endpoint-role order.
    ///
    /// # Errors
    ///
    /// Returns [`WireErrorV1::G0ContractDrift`] for endpoint-role substitution.
    pub fn try_worker(
        supervisor: &SeqpacketEndpointCommitmentV1,
        worker: &SeqpacketEndpointCommitmentV1,
    ) -> Result<Self, WireErrorV1> {
        if supervisor.role != SeqpacketEndpointRoleV1::SupervisorWorker
            || worker.role != SeqpacketEndpointRoleV1::Worker
        {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::EndpointPair,
            ));
        }
        Ok(Self::from_ordered_endpoint_digests(
            ChannelIdentityKindV1::Worker,
            WORKER_CHANNEL_IDENTITY_DOMAIN_V1,
            supervisor.digest,
            worker.digest,
            105,
        ))
    }

    /// Re-derives the generator child channel from its retained local endpoint
    /// and the exact supervisor peer digest, then joins it to the typed session.
    ///
    /// # Errors
    ///
    /// Returns [`WireErrorV1::G0ContractDrift`] for local-role, peer-digest, or
    /// typed-session channel substitution.
    pub fn try_generator_child(
        local: &SeqpacketEndpointCommitmentV1,
        supervisor_generator_endpoint_digest: [u8; 32],
        session: &ProviderSessionMaterialV1,
    ) -> Result<Self, WireErrorV1> {
        if local.role != SeqpacketEndpointRoleV1::Generator {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::EndpointPair,
            ));
        }
        let channel = Self::from_ordered_endpoint_digests(
            ChannelIdentityKindV1::Generator,
            GENERATOR_CHANNEL_IDENTITY_DOMAIN_V1,
            local.digest,
            supervisor_generator_endpoint_digest,
            108,
        );
        if channel.digest != session.generator_channel {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::EndpointPair,
            ));
        }
        Ok(channel)
    }

    /// Re-derives the worker child channel from the exact supervisor peer
    /// digest and its retained local endpoint, then joins it to the typed session.
    ///
    /// # Errors
    ///
    /// Returns [`WireErrorV1::G0ContractDrift`] for local-role, peer-digest, or
    /// typed-session channel substitution.
    pub fn try_worker_child(
        local: &SeqpacketEndpointCommitmentV1,
        supervisor_worker_endpoint_digest: [u8; 32],
        session: &ProviderSessionMaterialV1,
    ) -> Result<Self, WireErrorV1> {
        if local.role != SeqpacketEndpointRoleV1::Worker {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::EndpointPair,
            ));
        }
        let channel = Self::from_ordered_endpoint_digests(
            ChannelIdentityKindV1::Worker,
            WORKER_CHANNEL_IDENTITY_DOMAIN_V1,
            supervisor_worker_endpoint_digest,
            local.digest,
            105,
        );
        if channel.digest != session.worker_channel {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::EndpointPair,
            ));
        }
        Ok(channel)
    }

    /// Returns the non-authorizing channel digest bytes.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Borrowed values encoded into the one exact session-offer record.
#[derive(Clone, Copy, Debug)]
pub struct SessionOfferInputV1<'a> {
    /// Canonical request preimage and digest.
    pub request: &'a RequestCommitmentV1,
    /// Exact appliance measurement.
    pub appliance_measurement: [u8; 32],
    /// Exact supervisor measurement.
    pub supervisor_measurement: [u8; 32],
    /// Exact generator measurement.
    pub generator_measurement: [u8; 32],
    /// Exact worker measurement.
    pub worker_measurement: [u8; 32],
    /// Positive supervisor process ID.
    pub supervisor_pid: u32,
    /// Non-zero supervisor process start epoch.
    pub supervisor_start_epoch: u64,
    /// Generator-channel identity.
    pub generator_channel: &'a ChannelIdentityV1,
    /// Worker-channel identity.
    pub worker_channel: &'a ChannelIdentityV1,
    /// Supervisor endpoint on the generator channel.
    pub supervisor_generator_endpoint: &'a SeqpacketEndpointCommitmentV1,
    /// Receiver user-namespace identity retained by the supervisor owner.
    pub supervisor_receiver_user_namespace: DescriptorIdentityV1,
}

/// Exact session-offer bytes. The bytes are not a session or authority.
#[derive(Debug, Eq, PartialEq)]
pub struct SessionOfferV1 {
    bytes: [u8; G0_SESSION_OFFER_BYTES_V1],
}

impl SessionOfferV1 {
    /// Encodes the one 1,101-byte, zero-FD session offer.
    ///
    /// # Errors
    ///
    /// Returns a [`WireErrorV1`] for process, channel-kind, endpoint-role, or
    /// fixed-length drift.
    pub fn try_new(input: SessionOfferInputV1<'_>) -> Result<Self, WireErrorV1> {
        if input.supervisor_pid == 0 || input.supervisor_start_epoch == 0 {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::SupervisorProcess,
            ));
        }
        if input.generator_channel.kind != ChannelIdentityKindV1::Generator
            || input.worker_channel.kind != ChannelIdentityKindV1::Worker
            || input.supervisor_generator_endpoint.role
                != SeqpacketEndpointRoleV1::SupervisorGenerator
        {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::SessionOfferChannel,
            ));
        }
        let mut bytes = Vec::with_capacity(G0_SESSION_OFFER_BYTES_V1);
        push_lp16_v1(&mut bytes, SESSION_OFFER_DOMAIN_V1)?;
        bytes.extend_from_slice(&FRAME_VERSION_V1.to_le_bytes());
        bytes.extend_from_slice(
            &u16::try_from(G0_REQUEST_PREIMAGE_BYTES_V1)
                .map_err(|_| WireErrorV1::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&input.request.preimage);
        bytes.extend_from_slice(&input.request.digest);
        bytes.extend_from_slice(&input.appliance_measurement);
        bytes.extend_from_slice(&input.supervisor_measurement);
        bytes.extend_from_slice(&input.generator_measurement);
        bytes.extend_from_slice(&input.worker_measurement);
        bytes.extend_from_slice(&input.supervisor_pid.to_le_bytes());
        bytes.extend_from_slice(&input.supervisor_start_epoch.to_le_bytes());
        bytes.extend_from_slice(&input.generator_channel.digest);
        bytes.extend_from_slice(&input.worker_channel.digest);
        bytes.extend_from_slice(&input.supervisor_generator_endpoint.digest);
        input
            .supervisor_receiver_user_namespace
            .encode_into(&mut bytes);
        let bytes = bytes
            .try_into()
            .map_err(|_| WireErrorV1::ArithmeticOverflow)?;
        Ok(Self { bytes })
    }

    /// Returns the complete canonical record bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; G0_SESSION_OFFER_BYTES_V1] {
        &self.bytes
    }
}

/// Generator or supervisor nonce owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NonceRoleV1 {
    /// Generator nonce.
    Generator = 0,
    /// Supervisor nonce.
    Supervisor = 1,
}

/// One of the four closed pre-session records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PreSessionRecordKindV1 {
    /// Generator commitment.
    GeneratorCommit = 0,
    /// Supervisor commitment.
    SupervisorCommit = 1,
    /// Generator reveal.
    GeneratorReveal = 2,
    /// Supervisor reveal.
    SupervisorReveal = 3,
}

/// Computes one role-bound nonce commitment from a non-zero nonce.
///
/// # Errors
///
/// Returns [`WireErrorV1::G0ContractDrift`] when the nonce is all zeroes.
pub fn nonce_commitment_v1(
    role: NonceRoleV1,
    request: &RequestCommitmentV1,
    nonce: [u8; 32],
) -> Result<[u8; 32], WireErrorV1> {
    nonce_commitment_from_digest_v1(role, request.digest, nonce)
}

fn nonce_commitment_from_digest_v1(
    role: NonceRoleV1,
    request_digest: [u8; 32],
    nonce: [u8; 32],
) -> Result<[u8; 32], WireErrorV1> {
    if nonce == [0; 32] {
        return Err(WireErrorV1::G0ContractDrift(G0ContractFieldV1::Nonce));
    }
    let mut preimage = Vec::with_capacity(99);
    preimage.extend_from_slice(NONCE_COMMITMENT_DOMAIN_V1);
    preimage.push(role as u8);
    preimage.extend_from_slice(&request_digest);
    preimage.extend_from_slice(&nonce);
    debug_assert_eq!(preimage.len(), 99);
    Ok(sha256_v1(&preimage))
}

/// Encodes one exact 75-byte nonce commit or reveal record.
///
/// The closed kind determines the role and whether the payload is the
/// internally recomputed commitment or the raw nonce.
///
/// # Errors
///
/// Returns a [`WireErrorV1`] when the nonce is all zeroes.
pub fn encode_pre_session_record_v1(
    kind: PreSessionRecordKindV1,
    request: &RequestCommitmentV1,
    nonce: [u8; 32],
) -> Result<[u8; G0_PRE_SESSION_RECORD_BYTES_V1], WireErrorV1> {
    let (role, reveal) = match kind {
        PreSessionRecordKindV1::GeneratorCommit => (NonceRoleV1::Generator, false),
        PreSessionRecordKindV1::SupervisorCommit => (NonceRoleV1::Supervisor, false),
        PreSessionRecordKindV1::GeneratorReveal => (NonceRoleV1::Generator, true),
        PreSessionRecordKindV1::SupervisorReveal => (NonceRoleV1::Supervisor, true),
    };
    let commitment = nonce_commitment_v1(role, request, nonce)?;
    let payload = if reveal { nonce } else { commitment };
    let mut bytes = Vec::with_capacity(G0_PRE_SESSION_RECORD_BYTES_V1);
    bytes.extend_from_slice(&PRE_SESSION_RECORD_MAGIC_V1);
    bytes.extend_from_slice(&FRAME_VERSION_V1.to_le_bytes());
    bytes.push(kind as u8);
    bytes.extend_from_slice(&request.digest);
    bytes.extend_from_slice(&payload);
    bytes
        .try_into()
        .map_err(|_| WireErrorV1::ArithmeticOverflow)
}

/// Borrowed inputs to the exact provider-session preimage.
#[derive(Clone, Copy, Debug)]
pub struct ProviderSessionInputV1<'a> {
    /// Request commitment.
    pub request: &'a RequestCommitmentV1,
    /// Exact appliance measurement.
    pub appliance_measurement: [u8; 32],
    /// Exact supervisor measurement.
    pub supervisor_measurement: [u8; 32],
    /// Exact generator measurement.
    pub generator_measurement: [u8; 32],
    /// Exact worker measurement.
    pub worker_measurement: [u8; 32],
    /// Generator nonce.
    pub generator_nonce: [u8; 32],
    /// Supervisor nonce.
    pub supervisor_nonce: [u8; 32],
    /// Positive supervisor process ID.
    pub supervisor_pid: u32,
    /// Non-zero supervisor process start epoch.
    pub supervisor_start_epoch: u64,
    /// Generator channel identity.
    pub generator_channel: &'a ChannelIdentityV1,
    /// Worker channel identity.
    pub worker_channel: &'a ChannelIdentityV1,
}

/// Canonical provider-session material; deliberately non-authorizing.
#[derive(Debug, Eq, PartialEq)]
pub struct ProviderSessionMaterialV1 {
    preimage: [u8; G0_PROVIDER_SESSION_PREIMAGE_BYTES_V1],
    session_id: [u8; 32],
    request_commitment: [u8; 32],
    generator_nonce_commitment: [u8; 32],
    supervisor_nonce_commitment: [u8; 32],
    generator_channel: [u8; 32],
    worker_channel: [u8; 32],
}

impl ProviderSessionMaterialV1 {
    /// Recomputes the two nonce commitments and fixed 373-byte preimage.
    ///
    /// # Errors
    ///
    /// Returns a [`WireErrorV1`] for zero nonce, process, channel-kind, or
    /// checked-length drift.
    pub fn try_new(input: ProviderSessionInputV1<'_>) -> Result<Self, WireErrorV1> {
        if input.supervisor_pid == 0 || input.supervisor_start_epoch == 0 {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::SupervisorProcess,
            ));
        }
        if input.generator_channel.kind != ChannelIdentityKindV1::Generator
            || input.worker_channel.kind != ChannelIdentityKindV1::Worker
        {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::ProviderSessionChannel,
            ));
        }
        let generator_nonce_commitment =
            nonce_commitment_v1(NonceRoleV1::Generator, input.request, input.generator_nonce)?;
        let supervisor_nonce_commitment = nonce_commitment_v1(
            NonceRoleV1::Supervisor,
            input.request,
            input.supervisor_nonce,
        )?;

        let mut preimage = Vec::with_capacity(G0_PROVIDER_SESSION_PREIMAGE_BYTES_V1);
        preimage.extend_from_slice(PROVIDER_SESSION_DOMAIN_V1);
        push_lp16_v1(&mut preimage, SESSION_PROTOCOL_ID_V1)?;
        preimage.extend_from_slice(&input.request.digest);
        preimage.extend_from_slice(&input.appliance_measurement);
        preimage.extend_from_slice(&input.supervisor_measurement);
        preimage.extend_from_slice(&input.generator_measurement);
        preimage.extend_from_slice(&input.worker_measurement);
        preimage.extend_from_slice(&input.generator_nonce);
        preimage.extend_from_slice(&input.supervisor_nonce);
        preimage.extend_from_slice(&input.supervisor_pid.to_le_bytes());
        preimage.extend_from_slice(&input.supervisor_start_epoch.to_le_bytes());
        preimage.extend_from_slice(&input.generator_channel.digest);
        preimage.extend_from_slice(&input.worker_channel.digest);
        let preimage: [u8; G0_PROVIDER_SESSION_PREIMAGE_BYTES_V1] = preimage
            .try_into()
            .map_err(|_| WireErrorV1::ArithmeticOverflow)?;
        let session_id = sha256_v1(&preimage);
        Ok(Self {
            preimage,
            session_id,
            request_commitment: input.request.digest,
            generator_nonce_commitment,
            supervisor_nonce_commitment,
            generator_channel: input.generator_channel.digest,
            worker_channel: input.worker_channel.digest,
        })
    }

    /// Returns the exact provider-session preimage.
    #[must_use]
    pub const fn preimage(&self) -> &[u8; G0_PROVIDER_SESSION_PREIMAGE_BYTES_V1] {
        &self.preimage
    }

    /// Returns SHA-256 of the exact preimage, not session authority.
    #[must_use]
    pub const fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    /// Returns the request commitment bound into this preimage.
    #[must_use]
    pub const fn request_commitment(&self) -> [u8; 32] {
        self.request_commitment
    }

    /// Returns the internally recomputed generator nonce commitment.
    #[must_use]
    pub const fn generator_nonce_commitment(&self) -> [u8; 32] {
        self.generator_nonce_commitment
    }

    /// Returns the internally recomputed supervisor nonce commitment.
    #[must_use]
    pub const fn supervisor_nonce_commitment(&self) -> [u8; 32] {
        self.supervisor_nonce_commitment
    }
}

/// Closed process-inventory kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProcessInventoryKindV1 {
    /// Generator post-exec inherited inventory.
    GeneratorPostExec = 0,
    /// Worker initial post-exec inventory.
    WorkerInitialPostExec = 1,
    /// Worker expected post-transfer inventory.
    WorkerExpectedPostTransfer = 2,
}

/// One reserved-slot descriptor record in a canonical process inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessInventoryEntryV1 {
    reserved_fd: u8,
    commitment: FdCommitmentV1,
}

impl ProcessInventoryEntryV1 {
    /// Constructs bytes-only slot and commitment data.
    #[must_use]
    pub const fn new(reserved_fd: u8, commitment: FdCommitmentV1) -> Self {
        Self {
            reserved_fd,
            commitment,
        }
    }
}

/// Exact process-inventory bytes and digest; not live descriptor custody.
#[derive(Debug, Eq, PartialEq)]
pub struct ProcessInventoryV1 {
    kind: ProcessInventoryKindV1,
    bytes: Vec<u8>,
    digest: [u8; 32],
    campaign_count: u8,
}

impl ProcessInventoryV1 {
    /// Validates a closed inventory shape and encodes its canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`WireErrorV1`] for count, slot, role, identity, status,
    /// seal, order, or checked-length drift.
    pub fn try_new(
        kind: ProcessInventoryKindV1,
        entries: &[ProcessInventoryEntryV1],
    ) -> Result<Self, WireErrorV1> {
        let campaign_count = validate_process_inventory_v1(kind, entries)?;
        let count = u16::try_from(entries.len()).map_err(|_| WireErrorV1::ArithmeticOverflow)?;
        let mut bytes = Vec::with_capacity(42 + entries.len() * 53);
        push_lp16_v1(&mut bytes, PROCESS_INVENTORY_DOMAIN_V1)?;
        bytes.extend_from_slice(&FRAME_VERSION_V1.to_le_bytes());
        bytes.push(kind as u8);
        bytes.extend_from_slice(&count.to_le_bytes());
        for entry in entries {
            let encoded = encode_fd_commitment_v1(&entry.commitment)?;
            let length = encoded_fd_commitment_len_v1(&entry.commitment)?;
            bytes.push(entry.reserved_fd);
            bytes.extend_from_slice(&length.to_le_bytes());
            bytes.extend_from_slice(&encoded);
        }
        let expected = match kind {
            ProcessInventoryKindV1::GeneratorPostExec => 135 + 53 * usize::from(campaign_count),
            ProcessInventoryKindV1::WorkerInitialPostExec => 82,
            ProcessInventoryKindV1::WorkerExpectedPostTransfer => {
                134 + 53 * usize::from(campaign_count)
            }
        };
        if bytes.len() != expected {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::InventoryLength,
            ));
        }
        let digest = sha256_v1(&bytes);
        Ok(Self {
            kind,
            bytes,
            digest,
            campaign_count,
        })
    }

    /// Returns the exact canonical inventory bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns SHA-256 of the complete canonical inventory bytes.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the exact campaign-input count in this inventory.
    #[must_use]
    pub const fn campaign_count(&self) -> u8 {
        self.campaign_count
    }
}

fn validate_process_inventory_v1(
    kind: ProcessInventoryKindV1,
    entries: &[ProcessInventoryEntryV1],
) -> Result<u8, WireErrorV1> {
    let campaign_count =
        match kind {
            ProcessInventoryKindV1::GeneratorPostExec => {
                entries
                    .len()
                    .checked_sub(3)
                    .ok_or(WireErrorV1::G0ContractDrift(
                        G0ContractFieldV1::InventoryCount,
                    ))?
            }
            ProcessInventoryKindV1::WorkerInitialPostExec => {
                if entries.len() != 1 {
                    return Err(WireErrorV1::G0ContractDrift(
                        G0ContractFieldV1::InventoryCount,
                    ));
                }
                0
            }
            ProcessInventoryKindV1::WorkerExpectedPostTransfer => entries
                .len()
                .checked_sub(2)
                .ok_or(WireErrorV1::G0ContractDrift(
                    G0ContractFieldV1::InventoryCount,
                ))?,
        };
    if campaign_count > G0_MAX_INGRESS_COUNT_V1 {
        return Err(WireErrorV1::G0ContractDrift(
            G0ContractFieldV1::InventoryCount,
        ));
    }
    for (index, entry) in entries.iter().enumerate() {
        if index > 0 && entries[index - 1].reserved_fd >= entry.reserved_fd {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::InventorySlot,
            ));
        }
        entry.commitment.validate()?;
    }

    match kind {
        ProcessInventoryKindV1::GeneratorPostExec => {
            require_inventory_entry_v1(&entries[0], 3, FdRoleV1::GeneratorEndpoint, false)?;
            require_inventory_entry_v1(&entries[1], 4, FdRoleV1::SupervisorProcess, false)?;
            require_inventory_entry_v1(&entries[2], 5, FdRoleV1::PublicationRoot, false)?;
            for (index, entry) in entries[3..].iter().enumerate() {
                require_inventory_entry_v1(
                    entry,
                    u8::try_from(6 + index).map_err(|_| WireErrorV1::ArithmeticOverflow)?,
                    FdRoleV1::CampaignInput(
                        u8::try_from(index).map_err(|_| WireErrorV1::ArithmeticOverflow)?,
                    ),
                    false,
                )?;
                require_fully_sealed_memfd_v1(&entry.commitment)?;
            }
        }
        ProcessInventoryKindV1::WorkerInitialPostExec => {
            require_inventory_entry_v1(&entries[0], 3, FdRoleV1::WorkerEndpoint, false)?;
        }
        ProcessInventoryKindV1::WorkerExpectedPostTransfer => {
            require_inventory_entry_v1(&entries[0], 3, FdRoleV1::WorkerEndpoint, true)?;
            require_inventory_entry_v1(&entries[1], 4, FdRoleV1::Observation, true)?;
            require_size_fixed_unsealed_observation_v1(&entries[1].commitment)?;
            for (index, entry) in entries[2..].iter().enumerate() {
                require_inventory_entry_v1(
                    entry,
                    u8::try_from(5 + index).map_err(|_| WireErrorV1::ArithmeticOverflow)?,
                    FdRoleV1::CampaignInput(
                        u8::try_from(index).map_err(|_| WireErrorV1::ArithmeticOverflow)?,
                    ),
                    true,
                )?;
                require_fully_sealed_memfd_v1(&entry.commitment)?;
            }
        }
    }
    u8::try_from(campaign_count).map_err(|_| WireErrorV1::ArithmeticOverflow)
}

fn require_inventory_entry_v1(
    entry: &ProcessInventoryEntryV1,
    reserved_fd: u8,
    role: FdRoleV1,
    close_on_exec: bool,
) -> Result<(), WireErrorV1> {
    if entry.reserved_fd != reserved_fd || entry.commitment.role != role {
        return Err(WireErrorV1::G0ContractDrift(
            G0ContractFieldV1::InventorySlot,
        ));
    }
    if entry.commitment.status.nonblocking || entry.commitment.status.close_on_exec != close_on_exec
    {
        return Err(WireErrorV1::G0ContractDrift(
            G0ContractFieldV1::InventoryStatus,
        ));
    }
    Ok(())
}

fn require_fully_sealed_memfd_v1(commitment: &FdCommitmentV1) -> Result<(), WireErrorV1> {
    if !matches!(
        commitment.identity,
        FdIdentityV1::Memfd { seals, .. } if seals.fully_sealed()
    ) {
        return Err(WireErrorV1::G0ContractDrift(
            G0ContractFieldV1::InventorySeals,
        ));
    }
    Ok(())
}

fn require_size_fixed_unsealed_observation_v1(
    commitment: &FdCommitmentV1,
) -> Result<(), WireErrorV1> {
    if !matches!(
        commitment.identity,
        FdIdentityV1::Memfd { seals, .. }
            if seals.grow == SealPresenceV1::Present
                && seals.shrink == SealPresenceV1::Present
                && seals.write == SealPresenceV1::Absent
                && seals.further_seals == SealPresenceV1::Absent
    ) {
        return Err(WireErrorV1::G0ContractDrift(
            G0ContractFieldV1::InventorySeals,
        ));
    }
    Ok(())
}

fn worker_transfer_memfd_size_v1(
    commitment: &FdCommitmentV1,
    field: G0ContractFieldV1,
) -> Result<u64, WireErrorV1> {
    let FdIdentityV1::Memfd { size, .. } = commitment.identity else {
        return Err(WireErrorV1::G0ContractDrift(field));
    };
    Ok(size)
}

fn require_worker_transfer_content_policy_v1(
    observation: &FdCommitmentV1,
    campaign_inputs: &[FdCommitmentV1],
) -> Result<(), WireErrorV1> {
    let observation_size =
        worker_transfer_memfd_size_v1(observation, G0ContractFieldV1::WorkerManifestObservation)?;
    let mut aggregate_size = observation_size;
    for commitment in campaign_inputs {
        aggregate_size = aggregate_size
            .checked_add(worker_transfer_memfd_size_v1(
                commitment,
                G0ContractFieldV1::WorkerManifestCampaign,
            )?)
            .ok_or(WireErrorV1::ArithmeticOverflow)?;
    }
    if observation_size > G0_WORKER_TRANSFER_ROLE_MAX_BYTES_V1 {
        return Err(WireErrorV1::G0ContractDrift(
            G0ContractFieldV1::WorkerManifestObservationContentLength,
        ));
    }
    for commitment in campaign_inputs {
        let size =
            worker_transfer_memfd_size_v1(commitment, G0ContractFieldV1::WorkerManifestCampaign)?;
        if size == 0 || size > G0_WORKER_TRANSFER_ROLE_MAX_BYTES_V1 {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::WorkerManifestCampaignContentLength,
            ));
        }
    }
    if aggregate_size > G0_WORKER_TRANSFER_AGGREGATE_MAX_BYTES_V1 {
        return Err(WireErrorV1::G0ContractDrift(
            G0ContractFieldV1::WorkerManifestAggregateContentLength,
        ));
    }
    Ok(())
}

/// One classic BPF instruction in the generator seal-profile commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SockFilterInstructionV1 {
    code: u16,
    jump_true: u8,
    jump_false: u8,
    value: u32,
}

impl SockFilterInstructionV1 {
    /// Constructs the four fields of one canonical `sock_filter` instruction.
    #[must_use]
    pub const fn new(code: u16, jump_true: u8, jump_false: u8, value: u32) -> Self {
        Self {
            code,
            jump_true,
            jump_false,
            value,
        }
    }
}

/// Canonical generator seal-profile bytes and digest; not proof of installation.
#[derive(Debug, Eq, PartialEq)]
pub struct GeneratorSealProfileV1 {
    bytes: Vec<u8>,
    digest: [u8; 32],
}

impl GeneratorSealProfileV1 {
    /// Encodes one through 4,096 BPF instructions and the closed install tuple.
    ///
    /// # Errors
    ///
    /// Returns a [`WireErrorV1`] for an out-of-range count or checked overflow.
    pub fn try_new(instructions: &[SockFilterInstructionV1]) -> Result<Self, WireErrorV1> {
        if instructions.is_empty() || instructions.len() > 4_096 {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::GeneratorSealInstructionCount,
            ));
        }
        let count = u16::try_from(instructions.len()).map_err(|_| {
            WireErrorV1::G0ContractDrift(G0ContractFieldV1::GeneratorSealInstructionCount)
        })?;
        let instruction_bytes = instructions
            .len()
            .checked_mul(8)
            .ok_or(WireErrorV1::ArithmeticOverflow)?;
        let length = 47_usize
            .checked_add(instruction_bytes)
            .ok_or(WireErrorV1::ArithmeticOverflow)?;
        let mut bytes = Vec::with_capacity(length);
        bytes.extend_from_slice(GENERATOR_SEAL_PROFILE_DOMAIN_V1);
        bytes.extend_from_slice(&count.to_le_bytes());
        for instruction in instructions {
            bytes.extend_from_slice(&instruction.code.to_le_bytes());
            bytes.push(instruction.jump_true);
            bytes.push(instruction.jump_false);
            bytes.extend_from_slice(&instruction.value.to_le_bytes());
        }
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.push(1);
        debug_assert_eq!(bytes.len(), length);
        let digest = sha256_v1(&bytes);
        Ok(Self { bytes, digest })
    }

    /// Returns the exact canonical profile bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns SHA-256 of the canonical profile bytes.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Canonical worker transfer expectation; it carries no descriptors.
#[derive(Debug, Eq, PartialEq)]
pub struct WorkerTransferManifestV1 {
    bytes: Vec<u8>,
    digest: [u8; 32],
    campaign_count: u8,
}

impl WorkerTransferManifestV1 {
    /// Encodes Observation at fd4 followed by up to fifteen `CampaignInputs`.
    ///
    /// # Errors
    ///
    /// Returns a [`WireErrorV1`] for count, role, index, status, seal, length,
    /// or checked-arithmetic drift.
    pub fn try_new(
        observation: &FdCommitmentV1,
        campaign_inputs: &[FdCommitmentV1],
    ) -> Result<Self, WireErrorV1> {
        if campaign_inputs.len() > G0_MAX_INGRESS_COUNT_V1 {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::WorkerManifestCount,
            ));
        }
        if observation.role != FdRoleV1::Observation
            || observation.status.nonblocking
            || !observation.status.close_on_exec
            || encoded_fd_commitment_len_v1(observation)? != 49
        {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::WorkerManifestObservation,
            ));
        }
        require_size_fixed_unsealed_observation_v1(observation)?;
        for (index, commitment) in campaign_inputs.iter().enumerate() {
            let index = u8::try_from(index).map_err(|_| WireErrorV1::ArithmeticOverflow)?;
            if commitment.role != FdRoleV1::CampaignInput(index)
                || commitment.status.nonblocking
                || !commitment.status.close_on_exec
                || encoded_fd_commitment_len_v1(commitment)? != 50
            {
                return Err(WireErrorV1::G0ContractDrift(
                    G0ContractFieldV1::WorkerManifestCampaign,
                ));
            }
            require_fully_sealed_memfd_v1(commitment)?;
        }
        require_worker_transfer_content_policy_v1(observation, campaign_inputs)?;
        let campaign_count =
            u8::try_from(campaign_inputs.len()).map_err(|_| WireErrorV1::ArithmeticOverflow)?;
        let total_count = campaign_count
            .checked_add(1)
            .ok_or(WireErrorV1::ArithmeticOverflow)?;
        let expected_length = 99_usize
            .checked_add(
                campaign_inputs
                    .len()
                    .checked_mul(53)
                    .ok_or(WireErrorV1::ArithmeticOverflow)?,
            )
            .ok_or(WireErrorV1::ArithmeticOverflow)?;
        let mut bytes = Vec::with_capacity(expected_length);
        push_lp16_v1(&mut bytes, WORKER_TRANSFER_MANIFEST_DOMAIN_V1)?;
        bytes.extend_from_slice(&FRAME_VERSION_V1.to_le_bytes());
        bytes.push(total_count);
        bytes.push(4);
        let observation_length = encoded_fd_commitment_len_v1(observation)?;
        bytes.extend_from_slice(&observation_length.to_le_bytes());
        bytes.extend_from_slice(&encode_fd_commitment_v1(observation)?);
        for (index, commitment) in campaign_inputs.iter().enumerate() {
            bytes.push(u8::try_from(5 + index).map_err(|_| WireErrorV1::ArithmeticOverflow)?);
            let length = encoded_fd_commitment_len_v1(commitment)?;
            bytes.extend_from_slice(&length.to_le_bytes());
            bytes.extend_from_slice(&encode_fd_commitment_v1(commitment)?);
        }
        if bytes.len() != expected_length || bytes.len() > 894 {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::WorkerManifestLength,
            ));
        }
        let digest = sha256_v1(&bytes);
        Ok(Self {
            bytes,
            digest,
            campaign_count,
        })
    }

    /// Returns the complete canonical transfer-manifest bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns SHA-256 of the complete canonical manifest bytes.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the bound campaign-input count.
    #[must_use]
    pub const fn campaign_count(&self) -> u8 {
        self.campaign_count
    }
}

/// Exact `GeneratorBound` body bytes.
#[derive(Debug, Eq, PartialEq)]
pub struct GeneratorBoundBodyV1 {
    bytes: [u8; G0_GENERATOR_BOUND_BODY_BYTES_V1],
}

impl GeneratorBoundBodyV1 {
    fn validate_session(&self, session: &ProviderSessionMaterialV1) -> Result<(), WireErrorV1> {
        if self.bytes[42..74] != session.request_commitment
            || self.bytes[74..106] != session.generator_nonce_commitment
            || self.bytes[106..138] != session.supervisor_nonce_commitment
        {
            return Err(WireErrorV1::ExpectationDrift(FrameFieldV1::Body));
        }
        Ok(())
    }

    /// Binds the provider session to the installed-seal profile and inventory.
    ///
    /// # Errors
    ///
    /// Returns a [`WireErrorV1`] for inventory kind/count or fixed-length drift.
    pub fn try_new(
        session: &ProviderSessionMaterialV1,
        seal_profile: &GeneratorSealProfileV1,
        inventory: &ProcessInventoryV1,
        ingress: &SealedIngressManifestV1,
    ) -> Result<Self, WireErrorV1> {
        if inventory.kind != ProcessInventoryKindV1::GeneratorPostExec
            || inventory.campaign_count != ingress.count
        {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::GeneratorBoundInventory,
            ));
        }
        let mut bytes = Vec::with_capacity(G0_GENERATOR_BOUND_BODY_BYTES_V1);
        push_lp16_v1(&mut bytes, GENERATOR_BOUND_BODY_DOMAIN_V1)?;
        bytes.extend_from_slice(&FRAME_VERSION_V1.to_le_bytes());
        bytes.extend_from_slice(&session.request_commitment);
        bytes.extend_from_slice(&session.generator_nonce_commitment);
        bytes.extend_from_slice(&session.supervisor_nonce_commitment);
        bytes.extend_from_slice(&seal_profile.digest);
        bytes.extend_from_slice(&inventory.digest);
        bytes.extend_from_slice(&ingress.digest);
        let bytes = bytes
            .try_into()
            .map_err(|_| WireErrorV1::ArithmeticOverflow)?;
        Ok(Self { bytes })
    }

    /// Returns the exact body bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; G0_GENERATOR_BOUND_BODY_BYTES_V1] {
        &self.bytes
    }
}

/// Borrowed fields for the variable-size worker bootstrap body.
#[derive(Clone, Copy, Debug)]
pub struct WorkerBootstrapBodyInputV1<'a> {
    /// Accepted `GeneratorBound` transcript digest.
    pub accepted_generator_bound_digest: [u8; 32],
    /// Exact provider-session material.
    pub session: &'a ProviderSessionMaterialV1,
    /// Supervisor endpoint on the worker channel.
    pub supervisor_worker_endpoint: &'a SeqpacketEndpointCommitmentV1,
    /// Supervisor receiver user-namespace identity.
    pub supervisor_receiver_user_namespace: DescriptorIdentityV1,
    /// UID in the receiver view fixed by the worker spawn identity.
    pub worker_receiver_view_uid: u32,
    /// GID in the receiver view fixed by the worker spawn identity.
    pub worker_receiver_view_gid: u32,
    /// Worker initial post-exec inventory.
    pub worker_initial_inventory: &'a ProcessInventoryV1,
    /// Worker expected post-transfer inventory.
    pub worker_transfer_inventory: &'a ProcessInventoryV1,
    /// Canonical transfer manifest.
    pub worker_manifest: &'a WorkerTransferManifestV1,
}

/// Exact variable-size worker bootstrap body bytes.
#[derive(Debug, Eq, PartialEq)]
pub struct WorkerBootstrapBodyV1 {
    bytes: Vec<u8>,
}

impl WorkerBootstrapBodyV1 {
    /// Encodes the complete bootstrap expectation.
    ///
    /// This bytes-only constructor does not advance a cursor or release a
    /// worker; the owning enqueue-before-release transition must inject the
    /// accepted `GeneratorBound` digest without exposing it as authority.
    ///
    /// # Errors
    ///
    /// Returns a [`WireErrorV1`] for endpoint, inventory, manifest, or bounded
    /// length drift.
    pub fn try_new(input: WorkerBootstrapBodyInputV1<'_>) -> Result<Self, WireErrorV1> {
        if input.supervisor_worker_endpoint.role != SeqpacketEndpointRoleV1::SupervisorWorker {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::WorkerBootstrapEndpoint,
            ));
        }
        if input.worker_initial_inventory.kind != ProcessInventoryKindV1::WorkerInitialPostExec
            || input.worker_transfer_inventory.kind
                != ProcessInventoryKindV1::WorkerExpectedPostTransfer
            || input.worker_transfer_inventory.campaign_count
                != input.worker_manifest.campaign_count
        {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::WorkerBootstrapInventory,
            ));
        }
        let manifest_length = u16::try_from(input.worker_manifest.bytes.len())
            .map_err(|_| WireErrorV1::ArithmeticOverflow)?;
        let expected_length = G0_WORKER_BOOTSTRAP_FIXED_BODY_BYTES_V1
            .checked_add(input.worker_manifest.bytes.len())
            .ok_or(WireErrorV1::ArithmeticOverflow)?;
        let mut bytes = Vec::with_capacity(expected_length);
        push_lp16_v1(&mut bytes, WORKER_BOOTSTRAP_BODY_DOMAIN_V1)?;
        bytes.extend_from_slice(&FRAME_VERSION_V1.to_le_bytes());
        bytes.extend_from_slice(&input.accepted_generator_bound_digest);
        bytes.extend_from_slice(&input.session.preimage);
        bytes.extend_from_slice(&input.session.generator_nonce_commitment);
        bytes.extend_from_slice(&input.session.supervisor_nonce_commitment);
        bytes.extend_from_slice(&input.supervisor_worker_endpoint.digest);
        input
            .supervisor_receiver_user_namespace
            .encode_into(&mut bytes);
        bytes.extend_from_slice(&input.worker_receiver_view_uid.to_le_bytes());
        bytes.extend_from_slice(&input.worker_receiver_view_gid.to_le_bytes());
        bytes.extend_from_slice(&input.worker_initial_inventory.digest);
        bytes.extend_from_slice(&input.worker_transfer_inventory.digest);
        bytes.extend_from_slice(&manifest_length.to_le_bytes());
        bytes.extend_from_slice(&input.worker_manifest.bytes);
        bytes.extend_from_slice(&input.worker_manifest.digest);
        if bytes.len() != expected_length || bytes.len() > 1_568 {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::WorkerBootstrapLength,
            ));
        }
        Ok(Self { bytes })
    }

    /// Returns the complete canonical body bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Exact `WorkerExecBound` body bytes.
#[derive(Debug, Eq, PartialEq)]
pub struct WorkerExecBoundBodyV1 {
    bytes: [u8; G0_WORKER_EXEC_BOUND_BODY_BYTES_V1],
}

impl WorkerExecBoundBodyV1 {
    fn validate_session(&self, session: &ProviderSessionMaterialV1) -> Result<(), WireErrorV1> {
        if self.bytes[44..76] != session.request_commitment
            || self.bytes[76..108] != session.generator_nonce_commitment
            || self.bytes[108..140] != session.supervisor_nonce_commitment
        {
            return Err(WireErrorV1::ExpectationDrift(FrameFieldV1::Body));
        }
        Ok(())
    }

    /// Binds the worker inventories and transfer manifest to the provider session.
    ///
    /// # Errors
    ///
    /// Returns a [`WireErrorV1`] for inventory kind/count or fixed-length drift.
    pub fn try_new(
        session: &ProviderSessionMaterialV1,
        worker_initial_inventory: &ProcessInventoryV1,
        worker_transfer_inventory: &ProcessInventoryV1,
        worker_manifest: &WorkerTransferManifestV1,
    ) -> Result<Self, WireErrorV1> {
        if worker_initial_inventory.kind != ProcessInventoryKindV1::WorkerInitialPostExec
            || worker_transfer_inventory.kind != ProcessInventoryKindV1::WorkerExpectedPostTransfer
            || worker_transfer_inventory.campaign_count != worker_manifest.campaign_count
        {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::WorkerExecBoundInventory,
            ));
        }
        let mut bytes = Vec::with_capacity(G0_WORKER_EXEC_BOUND_BODY_BYTES_V1);
        push_lp16_v1(&mut bytes, WORKER_EXEC_BOUND_BODY_DOMAIN_V1)?;
        bytes.extend_from_slice(&FRAME_VERSION_V1.to_le_bytes());
        bytes.extend_from_slice(&session.request_commitment);
        bytes.extend_from_slice(&session.generator_nonce_commitment);
        bytes.extend_from_slice(&session.supervisor_nonce_commitment);
        bytes.extend_from_slice(&worker_initial_inventory.digest);
        bytes.extend_from_slice(&worker_transfer_inventory.digest);
        bytes.extend_from_slice(&worker_manifest.digest);
        let bytes = bytes
            .try_into()
            .map_err(|_| WireErrorV1::ArithmeticOverflow)?;
        Ok(Self { bytes })
    }

    /// Returns the exact body bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; G0_WORKER_EXEC_BOUND_BODY_BYTES_V1] {
        &self.bytes
    }
}

/// Encodes the exact zero-FD `GeneratorBound` child-to-supervisor raw frame.
///
/// The previous digest is derived from the typed session; the caller cannot
/// supply credentials, ancillary state, descriptor roles, or header fields.
///
/// ```
/// use eip0045_h0_contract::wire::{
///     GeneratorBoundBodyV1, ProviderSessionMaterialV1, WireErrorV1,
///     encode_generator_bound_raw_frame_v1,
/// };
///
/// let _: fn(
///     &ProviderSessionMaterialV1,
///     &GeneratorBoundBodyV1,
/// ) -> Result<[u8; 316], WireErrorV1> = encode_generator_bound_raw_frame_v1;
/// ```
///
/// # Errors
///
/// Returns [`WireErrorV1::ExpectationDrift`] when the typed body does not bind
/// the supplied session, or another [`WireErrorV1`] for checked length drift.
pub fn encode_generator_bound_raw_frame_v1(
    session: &ProviderSessionMaterialV1,
    body: &GeneratorBoundBodyV1,
) -> Result<[u8; G0_GENERATOR_BOUND_RAW_FRAME_BYTES_V1], WireErrorV1> {
    body.validate_session(session)?;
    let binding = G0TranscriptSessionBindingV1::from_session(session);
    let raw = encode_raw_frame_parts_v1(
        FRAME_MAGIC_V1,
        FRAME_VERSION_V1,
        FrameDirectionV1::GeneratorToSupervisor,
        0,
        AttemptPhaseV1::GeneratorBound,
        u32::try_from(G0_GENERATOR_BOUND_BODY_BYTES_V1)
            .map_err(|_| WireErrorV1::ArithmeticOverflow)?,
        session.session_id,
        binding.generator_genesis(),
        0,
        &[],
        body.bytes(),
        G0_GENERATOR_BOUND_RAW_FRAME_BYTES_V1,
    );
    raw.try_into().map_err(|_| WireErrorV1::ArithmeticOverflow)
}

/// Encodes the exact zero-FD `WorkerExecBound` child-to-supervisor raw frame.
///
/// The previous digest is the explicitly named validated-bootstrap digest;
/// the caller cannot supply generic header fields, credentials, ancillary
/// state, or descriptor roles.
///
/// ```
/// use eip0045_h0_contract::wire::{
///     ProviderSessionMaterialV1, TranscriptDigestV1, WireErrorV1,
///     WorkerExecBoundBodyV1, encode_worker_exec_bound_raw_frame_v1,
/// };
///
/// let _: fn(
///     &ProviderSessionMaterialV1,
///     TranscriptDigestV1,
///     &WorkerExecBoundBodyV1,
/// ) -> Result<[u8; 318], WireErrorV1> = encode_worker_exec_bound_raw_frame_v1;
/// ```
///
/// # Errors
///
/// Returns [`WireErrorV1::ExpectationDrift`] when the typed body does not bind
/// the supplied session, or another [`WireErrorV1`] for checked length drift.
pub fn encode_worker_exec_bound_raw_frame_v1(
    session: &ProviderSessionMaterialV1,
    worker_bootstrap_digest: TranscriptDigestV1,
    body: &WorkerExecBoundBodyV1,
) -> Result<[u8; G0_WORKER_EXEC_BOUND_RAW_FRAME_BYTES_V1], WireErrorV1> {
    body.validate_session(session)?;
    let raw = encode_raw_frame_parts_v1(
        FRAME_MAGIC_V1,
        FRAME_VERSION_V1,
        FrameDirectionV1::WorkerToSupervisor,
        1,
        AttemptPhaseV1::WorkerExecBound,
        u32::try_from(G0_WORKER_EXEC_BOUND_BODY_BYTES_V1)
            .map_err(|_| WireErrorV1::ArithmeticOverflow)?,
        session.session_id,
        worker_bootstrap_digest.into_bytes(),
        0,
        &[],
        body.bytes(),
        G0_WORKER_EXEC_BOUND_RAW_FRAME_BYTES_V1,
    );
    raw.try_into().map_err(|_| WireErrorV1::ArithmeticOverflow)
}

/// Exact closed-result body bytes.
#[derive(Debug, Eq, PartialEq)]
pub struct ClosedResultBodyV1 {
    bytes: [u8; G0_CLOSED_RESULT_BODY_BYTES_V1],
}

impl ClosedResultBodyV1 {
    /// Encodes the request, terminal worker digest, and exact `FinalResult` digest.
    ///
    /// This bytes-only constructor does not queue a result or create source
    /// authority; the owning runtime transition remains separate.
    ///
    /// # Errors
    ///
    /// Returns a [`WireErrorV1`] when the `FinalResult` role, status, or seals drift.
    pub fn try_new(
        session: &ProviderSessionMaterialV1,
        terminal_worker_digest: [u8; 32],
        final_result: &FdCommitmentV1,
    ) -> Result<Self, WireErrorV1> {
        if final_result.role != FdRoleV1::FinalResult
            || final_result.status.access != FdAccessV1::ReadOnly
            || final_result.status.nonblocking
            || !final_result.status.close_on_exec
            || encoded_fd_commitment_len_v1(final_result)? != 49
        {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::ClosedResultCommitment,
            ));
        }
        require_fully_sealed_memfd_v1(final_result)?;
        let FdIdentityV1::Memfd {
            size,
            content_digest,
            ..
        } = final_result.identity
        else {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::ClosedResultCommitment,
            ));
        };
        if size == 0 || size > G0_FINAL_RESULT_MAX_BYTES_V1 as u64 {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::FinalResultContent,
            ));
        }
        let mut bytes = Vec::with_capacity(G0_CLOSED_RESULT_BODY_BYTES_V1);
        push_lp16_v1(&mut bytes, CLOSED_RESULT_BODY_DOMAIN_V1)?;
        bytes.extend_from_slice(&FRAME_VERSION_V1.to_le_bytes());
        bytes.extend_from_slice(&session.request_commitment);
        bytes.extend_from_slice(&terminal_worker_digest);
        bytes.extend_from_slice(&content_digest);
        let bytes = bytes
            .try_into()
            .map_err(|_| WireErrorV1::ArithmeticOverflow)?;
        Ok(Self { bytes })
    }

    /// Returns the exact body bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; G0_CLOSED_RESULT_BODY_BYTES_V1] {
        &self.bytes
    }
}

/// Receive-shape observations supplied by the isolated ABI owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AncillaryShapeV1 {
    /// Whether the receive ended exactly at the message boundary.
    pub message_end: bool,
    /// Whether payload truncation was reported.
    pub message_truncated: bool,
    /// Whether ancillary truncation was reported.
    pub control_truncated: bool,
    /// Number of credential records present.
    pub credential_records: u8,
    /// Number of descriptor-rights records present.
    pub rights_records: u8,
    /// Number of unknown control records present.
    pub unknown_control_records: u8,
    /// Number of malformed control records present.
    pub malformed_control_records: u8,
}

impl AncillaryShapeV1 {
    /// Returns the sole accepted shape for the given descriptor count.
    #[must_use]
    pub const fn canonical(fd_count: usize) -> Self {
        Self {
            message_end: true,
            message_truncated: false,
            control_truncated: false,
            credential_records: 1,
            rights_records: if fd_count == 0 { 0 } else { 1 },
            unknown_control_records: 0,
            malformed_control_records: 0,
        }
    }

    fn validate(self, fd_count: usize) -> Result<(), WireErrorV1> {
        if !self.message_end {
            return Err(WireErrorV1::MissingMessageEnd);
        }
        if self.message_truncated {
            return Err(WireErrorV1::MessageTruncated);
        }
        if self.control_truncated {
            return Err(WireErrorV1::ControlTruncated);
        }
        if self.credential_records != 1 {
            return Err(WireErrorV1::CredentialRecordCount(self.credential_records));
        }
        let expected_rights = u8::from(fd_count != 0);
        if self.rights_records != expected_rights {
            return Err(WireErrorV1::RightsRecordCount(
                self.rights_records,
                expected_rights,
            ));
        }
        if self.unknown_control_records != 0 {
            return Err(WireErrorV1::UnknownControlRecords(
                self.unknown_control_records,
            ));
        }
        if self.malformed_control_records != 0 {
            return Err(WireErrorV1::MalformedControlRecords(
                self.malformed_control_records,
            ));
        }
        Ok(())
    }
}

/// Borrowed inputs used to construct one bounded frame value.
#[derive(Clone, Copy, Debug)]
pub struct FrameInputV1<'a> {
    /// Declared transfer direction.
    pub direction: FrameDirectionV1,
    /// Zero-based session ordinal.
    pub ordinal: u8,
    /// Descriptive protocol phase.
    pub phase: AttemptPhaseV1,
    /// Exact 32-byte session identifier.
    pub session_id: [u8; 32],
    /// Previous transcript digest bytes.
    pub previous_hash: [u8; 32],
    /// Opaque bounded frame body.
    pub body: &'a [u8],
    /// Exact peer-credential observation.
    pub credentials: PeerCredentialsV1,
    /// Ordered descriptor commitments.
    pub fd_commitments: &'a [FdCommitmentV1],
    /// Exact ancillary receive shape.
    pub ancillary: AncillaryShapeV1,
}

/// An owned frame whose shape is validated independently of runtime authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireFrameV1 {
    magic: [u8; 8],
    version: u16,
    direction: FrameDirectionV1,
    ordinal: u8,
    phase: AttemptPhaseV1,
    declared_body_length: u32,
    session_id: [u8; 32],
    previous_hash: [u8; 32],
    declared_fd_count: u8,
    body: Vec<u8>,
    credentials: PeerCredentialsV1,
    fd_commitments: Vec<FdCommitmentV1>,
    ancillary: AncillaryShapeV1,
}

impl WireFrameV1 {
    /// Constructs one bounded frame and validates every supplied observation.
    ///
    /// # Errors
    ///
    /// Returns a [`WireErrorV1`] for a bound, declaration, ancillary, role,
    /// identity, status, seal, or duplicate-role violation.
    pub fn try_new(input: FrameInputV1<'_>) -> Result<Self, WireErrorV1> {
        if input.ordinal >= MAX_SESSION_FRAMES_V1 {
            return Err(WireErrorV1::FrameOrdinalOutOfRange(input.ordinal));
        }
        if input.fd_commitments.len() > MAX_FRAME_FDS_V1 {
            return Err(WireErrorV1::TooManyFds(input.fd_commitments.len()));
        }
        input.ancillary.validate(input.fd_commitments.len())?;
        validate_fd_inventory(input.fd_commitments)?;

        let declared_body_length = u32::try_from(input.body.len())
            .map_err(|_| WireErrorV1::BodyLengthOutOfRange(input.body.len()))?;
        let declared_fd_count = u8::try_from(input.fd_commitments.len())
            .map_err(|_| WireErrorV1::TooManyFds(input.fd_commitments.len()))?;
        let encoded_length = encoded_frame_len(input.body.len(), input.fd_commitments)?;
        if encoded_length > MAX_FRAME_BYTES_V1 {
            return Err(WireErrorV1::FrameTooLarge(encoded_length));
        }

        let frame = Self {
            magic: FRAME_MAGIC_V1,
            version: FRAME_VERSION_V1,
            direction: input.direction,
            ordinal: input.ordinal,
            phase: input.phase,
            declared_body_length,
            session_id: input.session_id,
            previous_hash: input.previous_hash,
            declared_fd_count,
            body: input.body.to_vec(),
            credentials: input.credentials,
            fd_commitments: input.fd_commitments.to_vec(),
            ancillary: input.ancillary,
        };
        frame.validate_shape()?;
        Ok(frame)
    }

    /// Revalidates all stored declarations and closed inventory invariants.
    ///
    /// # Errors
    ///
    /// Returns a [`WireErrorV1`] for any stored shape drift.
    pub fn validate_shape(&self) -> Result<(), WireErrorV1> {
        if self.magic != FRAME_MAGIC_V1 {
            return Err(WireErrorV1::MagicMismatch);
        }
        if self.version != FRAME_VERSION_V1 {
            return Err(WireErrorV1::VersionMismatch(self.version));
        }
        if self.ordinal >= MAX_SESSION_FRAMES_V1 {
            return Err(WireErrorV1::FrameOrdinalOutOfRange(self.ordinal));
        }
        let actual_body_length = self.body.len();
        if usize::try_from(self.declared_body_length).ok() != Some(actual_body_length) {
            return Err(WireErrorV1::DeclaredBodyLengthMismatch(
                self.declared_body_length,
                actual_body_length,
            ));
        }
        let actual_fd_count = self.fd_commitments.len();
        if usize::from(self.declared_fd_count) != actual_fd_count {
            return Err(WireErrorV1::DeclaredFdCountMismatch(
                self.declared_fd_count,
                actual_fd_count,
            ));
        }
        if actual_fd_count > MAX_FRAME_FDS_V1 {
            return Err(WireErrorV1::TooManyFds(actual_fd_count));
        }
        self.ancillary.validate(actual_fd_count)?;
        validate_fd_inventory(&self.fd_commitments)?;
        let encoded_length = encoded_frame_len(actual_body_length, &self.fd_commitments)?;
        if encoded_length > MAX_FRAME_BYTES_V1 {
            return Err(WireErrorV1::FrameTooLarge(encoded_length));
        }
        Ok(())
    }

    /// Returns the checked encoded frame length.
    ///
    /// # Errors
    ///
    /// Returns a [`WireErrorV1`] when stored declarations or bounds drift.
    pub fn encoded_len(&self) -> Result<usize, WireErrorV1> {
        self.validate_shape()?;
        encoded_frame_len(self.body.len(), &self.fd_commitments)
    }

    /// Encodes the fixed header, ordered roles, and opaque body.
    ///
    /// # Errors
    ///
    /// Returns a [`WireErrorV1`] when stored declarations or bounds drift.
    pub fn encode_raw_frame(&self) -> Result<Vec<u8>, WireErrorV1> {
        let encoded_length = self.encoded_len()?;
        Ok(encode_raw_frame_parts_v1(
            self.magic,
            self.version,
            self.direction,
            self.ordinal,
            self.phase,
            self.declared_body_length,
            self.session_id,
            self.previous_hash,
            self.declared_fd_count,
            &self.fd_commitments,
            &self.body,
            encoded_length,
        ))
    }

    /// Returns the ordered descriptor commitments.
    #[must_use]
    pub fn fd_commitments(&self) -> &[FdCommitmentV1] {
        &self.fd_commitments
    }

    /// Compares every semantic field with one externally compiled expectation.
    ///
    /// This comparison returns data only and does not establish authority.
    ///
    /// # Errors
    ///
    /// Returns [`WireErrorV1::ExpectationDrift`] for the first unequal field,
    /// or another [`WireErrorV1`] if the stored frame shape is invalid.
    pub fn validate_expected(&self, expected: FrameExpectationV1<'_>) -> Result<(), WireErrorV1> {
        self.validate_shape()?;
        if self.direction != expected.direction {
            return Err(WireErrorV1::ExpectationDrift(FrameFieldV1::Direction));
        }
        if self.ordinal != expected.ordinal {
            return Err(WireErrorV1::ExpectationDrift(FrameFieldV1::Ordinal));
        }
        if self.phase != expected.phase {
            return Err(WireErrorV1::ExpectationDrift(FrameFieldV1::Phase));
        }
        if self.session_id != expected.session_id {
            return Err(WireErrorV1::ExpectationDrift(FrameFieldV1::SessionId));
        }
        if self.previous_hash != expected.previous_hash {
            return Err(WireErrorV1::ExpectationDrift(FrameFieldV1::PreviousHash));
        }
        if self.body != expected.body {
            return Err(WireErrorV1::ExpectationDrift(FrameFieldV1::Body));
        }
        if self.credentials != expected.credentials {
            return Err(WireErrorV1::ExpectationDrift(FrameFieldV1::Credentials));
        }
        if self.fd_commitments != expected.fd_commitments {
            return Err(WireErrorV1::ExpectationDrift(FrameFieldV1::FdCommitments));
        }
        Ok(())
    }
}

fn validate_fd_inventory(commitments: &[FdCommitmentV1]) -> Result<(), WireErrorV1> {
    for (position, commitment) in commitments.iter().enumerate() {
        commitment.validate()?;
        if commitments[..position]
            .iter()
            .any(|prior| prior.role == commitment.role)
        {
            return Err(WireErrorV1::DuplicateFdRole(commitment.role));
        }
    }
    Ok(())
}

fn encoded_frame_len(
    body_length: usize,
    commitments: &[FdCommitmentV1],
) -> Result<usize, WireErrorV1> {
    let roles_length = commitments.iter().try_fold(0_usize, |total, commitment| {
        total
            .checked_add(commitment.role.encoded_len())
            .ok_or(WireErrorV1::ArithmeticOverflow)
    })?;
    FRAME_FIXED_HEADER_BYTES_V1
        .checked_add(roles_length)
        .and_then(|value| value.checked_add(body_length))
        .ok_or(WireErrorV1::ArithmeticOverflow)
}

#[allow(clippy::too_many_arguments)]
fn encode_raw_frame_parts_v1(
    magic: [u8; 8],
    version: u16,
    direction: FrameDirectionV1,
    ordinal: u8,
    phase: AttemptPhaseV1,
    declared_body_length: u32,
    session_id: [u8; 32],
    previous_hash: [u8; 32],
    declared_fd_count: u8,
    fd_commitments: &[FdCommitmentV1],
    body: &[u8],
    encoded_length: usize,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(encoded_length);
    output.extend_from_slice(&magic);
    output.extend_from_slice(&version.to_le_bytes());
    output.push(direction.wire_code());
    output.push(ordinal);
    output.push(phase.wire_code());
    output.extend_from_slice(&declared_body_length.to_le_bytes());
    output.extend_from_slice(&session_id);
    output.extend_from_slice(&previous_hash);
    output.push(declared_fd_count);
    for commitment in fd_commitments {
        commitment.role.encode_into(&mut output);
    }
    output.extend_from_slice(body);
    debug_assert_eq!(output.len(), encoded_length);
    output
}

/// Borrowed exact fields expected by the protocol owner for one frame.
#[derive(Clone, Copy, Debug)]
pub struct FrameExpectationV1<'a> {
    /// Expected direction.
    pub direction: FrameDirectionV1,
    /// Expected ordinal.
    pub ordinal: u8,
    /// Expected descriptive phase.
    pub phase: AttemptPhaseV1,
    /// Expected session identifier.
    pub session_id: [u8; 32],
    /// Expected previous digest bytes.
    pub previous_hash: [u8; 32],
    /// Expected opaque body.
    pub body: &'a [u8],
    /// Expected exact peer credentials.
    pub credentials: PeerCredentialsV1,
    /// Expected ordered descriptor commitments.
    pub fd_commitments: &'a [FdCommitmentV1],
}

/// A semantic frame field that differed from its exact expectation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameFieldV1 {
    /// Direction.
    Direction,
    /// Ordinal.
    Ordinal,
    /// Descriptive phase.
    Phase,
    /// Session identifier.
    SessionId,
    /// Previous transcript digest.
    PreviousHash,
    /// Opaque body.
    Body,
    /// Peer credentials.
    Credentials,
    /// Ordered descriptor commitments.
    FdCommitments,
}

/// Opaque transcript digest bytes produced by a separately pinned algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TranscriptDigestV1([u8; 32]);

impl TranscriptDigestV1 {
    /// Wraps externally produced digest bytes without validating their origin.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the wrapped digest bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Non-authorizing position in one bounded transcript chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TranscriptCursorV1 {
    session_id: [u8; 32],
    next_ordinal: u8,
    previous_hash: TranscriptDigestV1,
}

impl TranscriptCursorV1 {
    /// Starts a chain at ordinal zero with externally supplied prior bytes.
    #[must_use]
    pub const fn start(session_id: [u8; 32], initial_hash: [u8; 32]) -> Self {
        Self {
            session_id,
            next_ordinal: 0,
            previous_hash: TranscriptDigestV1::from_bytes(initial_hash),
        }
    }

    /// Returns the next required frame ordinal.
    #[must_use]
    pub const fn next_ordinal(&self) -> u8 {
        self.next_ordinal
    }

    /// Returns the exact previous digest bytes.
    #[must_use]
    pub const fn previous_hash(&self) -> TranscriptDigestV1 {
        self.previous_hash
    }

    /// Builds the canonical preimage after checking the chain join.
    ///
    /// # Errors
    ///
    /// Returns a [`WireErrorV1`] for an invalid frame, exhausted chain, or
    /// session/ordinal/previous-digest drift.
    pub fn prepare(&self, frame: &WireFrameV1) -> Result<TranscriptPreimageV1, WireErrorV1> {
        let bytes = prepare_transcript_bytes_v1(
            self.session_id,
            self.next_ordinal,
            self.previous_hash.0,
            frame,
        )?;
        Ok(TranscriptPreimageV1 {
            bytes,
            session_id: self.session_id,
            consumed_ordinal: self.next_ordinal,
        })
    }
}

fn prepare_transcript_bytes_v1(
    session_id: [u8; 32],
    next_ordinal: u8,
    previous_hash: [u8; 32],
    frame: &WireFrameV1,
) -> Result<Vec<u8>, WireErrorV1> {
    frame.validate_shape()?;
    if next_ordinal >= MAX_SESSION_FRAMES_V1 {
        return Err(WireErrorV1::SessionFrameLimit);
    }
    if frame.session_id != session_id {
        return Err(WireErrorV1::TranscriptSessionMismatch);
    }
    if frame.ordinal != next_ordinal {
        return Err(WireErrorV1::TranscriptOrdinalMismatch(
            frame.ordinal,
            next_ordinal,
        ));
    }
    if frame.previous_hash != previous_hash {
        return Err(WireErrorV1::TranscriptPreviousHashMismatch);
    }

    let raw_frame = frame.encode_raw_frame()?;
    let mut bytes = Vec::with_capacity(
        TRANSCRIPT_DOMAIN_V1.len() + raw_frame.len() + frame.fd_commitments.len() * 80 + 80,
    );
    let domain_length =
        u16::try_from(TRANSCRIPT_DOMAIN_V1.len()).map_err(|_| WireErrorV1::ArithmeticOverflow)?;
    bytes.extend_from_slice(&domain_length.to_le_bytes());
    bytes.extend_from_slice(TRANSCRIPT_DOMAIN_V1);
    bytes.extend_from_slice(&previous_hash);
    bytes.push(frame.direction.wire_code());
    bytes.push(frame.phase.wire_code());
    let raw_length = u32::try_from(raw_frame.len()).map_err(|_| WireErrorV1::ArithmeticOverflow)?;
    bytes.extend_from_slice(&raw_length.to_le_bytes());
    bytes.extend_from_slice(&raw_frame);
    frame.credentials.encode_into(&mut bytes);
    bytes.push(frame.declared_fd_count);
    for commitment in &frame.fd_commitments {
        let encoded = encode_fd_commitment_v1(commitment)?;
        let commitment_length = encoded_fd_commitment_len_v1(commitment)?;
        bytes.extend_from_slice(&commitment_length.to_le_bytes());
        bytes.extend_from_slice(&encoded);
    }
    Ok(bytes)
}

/// Canonical bytes awaiting a digest from a separately pinned algorithm.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscriptPreimageV1 {
    bytes: Vec<u8>,
    session_id: [u8; 32],
    consumed_ordinal: u8,
}

impl TranscriptPreimageV1 {
    /// Returns the complete canonical transcript preimage.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Advances with externally supplied bytes without treating them as proof.
    #[must_use]
    pub fn advance_with_external_digest(self, digest: TranscriptDigestV1) -> TranscriptCursorV1 {
        TranscriptCursorV1 {
            session_id: self.session_id,
            next_ordinal: self.consumed_ordinal + 1,
            previous_hash: digest,
        }
    }
}

#[derive(Debug)]
struct G0TranscriptSessionBindingV1 {
    session_id: [u8; 32],
    request_commitment: [u8; 32],
    generator_nonce_commitment: [u8; 32],
    supervisor_nonce_commitment: [u8; 32],
    generator_channel: [u8; 32],
    worker_channel: [u8; 32],
}

impl G0TranscriptSessionBindingV1 {
    fn from_session(session: &ProviderSessionMaterialV1) -> Self {
        Self {
            session_id: session.session_id,
            request_commitment: session.request_commitment,
            generator_nonce_commitment: session.generator_nonce_commitment,
            supervisor_nonce_commitment: session.supervisor_nonce_commitment,
            generator_channel: session.generator_channel,
            worker_channel: session.worker_channel,
        }
    }

    fn generator_genesis(&self) -> [u8; 32] {
        let mut preimage = Vec::with_capacity(G0_GENERATOR_CHANNEL_GENESIS_BYTES_V1);
        preimage.extend_from_slice(GENERATOR_CHANNEL_GENESIS_DOMAIN_V1);
        preimage.extend_from_slice(&self.session_id);
        preimage.extend_from_slice(&self.request_commitment);
        preimage.extend_from_slice(&self.generator_nonce_commitment);
        preimage.extend_from_slice(&self.supervisor_nonce_commitment);
        preimage.extend_from_slice(&self.generator_channel);
        debug_assert_eq!(preimage.len(), G0_GENERATOR_CHANNEL_GENESIS_BYTES_V1);
        sha256_v1(&preimage)
    }

    fn worker_genesis(&self, accepted_generator_bound_digest: [u8; 32]) -> [u8; 32] {
        let mut preimage = Vec::with_capacity(G0_WORKER_CHANNEL_GENESIS_BYTES_V1);
        preimage.extend_from_slice(WORKER_CHANNEL_GENESIS_DOMAIN_V1);
        preimage.extend_from_slice(&self.session_id);
        preimage.extend_from_slice(&self.request_commitment);
        preimage.extend_from_slice(&self.generator_nonce_commitment);
        preimage.extend_from_slice(&self.supervisor_nonce_commitment);
        preimage.extend_from_slice(&accepted_generator_bound_digest);
        preimage.extend_from_slice(&self.worker_channel);
        debug_assert_eq!(preimage.len(), G0_WORKER_CHANNEL_GENESIS_BYTES_V1);
        sha256_v1(&preimage)
    }
}

/// Pure, non-authorizing candidate for the sole generator-bound transcript.
///
/// This value contains only reproducible bytes and digests. It cannot record
/// receive acceptance, enqueue success, cursor advance, or aggregate state.
/// Those transitions belong to the later private G0 runtime composite.
///
/// ```compile_fail
/// use eip0045_h0_contract::wire::G0GeneratorBoundTranscriptCandidateV1;
///
/// fn cannot_promote(candidate: G0GeneratorBoundTranscriptCandidateV1) {
///     let _accepted = candidate.accept();
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct G0GeneratorBoundTranscriptCandidateV1 {
    transcript: Vec<u8>,
    digest: [u8; 32],
    generator_genesis: [u8; 32],
    worker_genesis: [u8; 32],
}

impl G0GeneratorBoundTranscriptCandidateV1 {
    /// Prepares the exact ordinal-zero generator-bound candidate and hashes it internally.
    ///
    /// # Errors
    ///
    /// Returns a [`WireErrorV1`] when the frame is not the exact generator-bound
    /// shape or does not join the session-derived generator genesis.
    pub fn prepare(
        session: &ProviderSessionMaterialV1,
        frame: &WireFrameV1,
    ) -> Result<Self, WireErrorV1> {
        if frame.direction != FrameDirectionV1::GeneratorToSupervisor
            || frame.ordinal != 0
            || frame.phase != AttemptPhaseV1::GeneratorBound
            || !frame.fd_commitments.is_empty()
            || frame.body.len() != G0_GENERATOR_BOUND_BODY_BYTES_V1
        {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::GeneratorBoundFrame,
            ));
        }
        let binding = G0TranscriptSessionBindingV1::from_session(session);
        let generator_genesis = binding.generator_genesis();
        let transcript =
            prepare_transcript_bytes_v1(binding.session_id, 0, generator_genesis, frame)?;
        let digest = sha256_v1(&transcript);
        let worker_genesis = binding.worker_genesis(digest);
        Ok(Self {
            transcript,
            digest,
            generator_genesis,
            worker_genesis,
        })
    }

    /// Returns the complete canonical transcript bytes.
    #[must_use]
    pub fn transcript_bytes(&self) -> &[u8] {
        &self.transcript
    }

    /// Returns the internally computed candidate digest bytes.
    ///
    /// These bytes are reproducible protocol data, not receive acceptance.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the exact session-derived generator genesis bytes.
    #[must_use]
    pub const fn generator_genesis(&self) -> [u8; 32] {
        self.generator_genesis
    }

    /// Returns worker-genesis candidate bytes cross-anchored to this candidate digest.
    ///
    /// Returning these bytes does not assert that the generator-bound frame was
    /// received or accepted by a runtime owner.
    #[must_use]
    pub const fn worker_genesis(&self) -> [u8; 32] {
        self.worker_genesis
    }
}

/// Pure canonical transcript candidate with internally computed SHA-256.
///
/// The caller supplies a proposed ordinal and previous digest. Successful
/// preparation proves only canonical byte agreement; it creates no cursor,
/// accepted/enqueued state, aggregate count, custody, or runtime authority.
///
/// ```compile_fail
/// use eip0045_h0_contract::wire::G0TranscriptCandidateV1;
///
/// fn cannot_promote(candidate: G0TranscriptCandidateV1) {
///     let _advanced = candidate.accept();
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct G0TranscriptCandidateV1 {
    transcript: Vec<u8>,
    digest: [u8; 32],
}

impl G0TranscriptCandidateV1 {
    /// Prepares canonical bytes for one proposed transcript position.
    ///
    /// # Errors
    ///
    /// Returns a [`WireErrorV1`] for an invalid frame, exhausted bound, or
    /// session/ordinal/previous-digest mismatch.
    pub fn prepare(
        session: &ProviderSessionMaterialV1,
        ordinal: u8,
        previous_digest: [u8; 32],
        frame: &WireFrameV1,
    ) -> Result<Self, WireErrorV1> {
        let transcript =
            prepare_transcript_bytes_v1(session.session_id, ordinal, previous_digest, frame)?;
        let digest = sha256_v1(&transcript);
        Ok(Self { transcript, digest })
    }

    /// Returns the complete canonical transcript bytes.
    #[must_use]
    pub fn transcript_bytes(&self) -> &[u8] {
        &self.transcript
    }

    /// Returns the internally computed candidate digest bytes.
    ///
    /// These bytes do not record acceptance, enqueue success, or cursor advance.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

fn g0_fixed_bytes_v1<const N: usize>(
    bytes: &[u8],
    offset: usize,
    field: G0ContractFieldV1,
) -> Result<[u8; N], WireErrorV1> {
    let end = offset
        .checked_add(N)
        .ok_or(WireErrorV1::ArithmeticOverflow)?;
    bytes
        .get(offset..end)
        .and_then(|value| value.try_into().ok())
        .ok_or(WireErrorV1::G0ContractDrift(field))
}

fn g0_u16_le_v1(bytes: &[u8], offset: usize, field: G0ContractFieldV1) -> Result<u16, WireErrorV1> {
    Ok(u16::from_le_bytes(g0_fixed_bytes_v1(bytes, offset, field)?))
}

fn g0_u32_le_v1(bytes: &[u8], offset: usize, field: G0ContractFieldV1) -> Result<u32, WireErrorV1> {
    Ok(u32::from_le_bytes(g0_fixed_bytes_v1(bytes, offset, field)?))
}

fn g0_u64_le_v1(bytes: &[u8], offset: usize, field: G0ContractFieldV1) -> Result<u64, WireErrorV1> {
    Ok(u64::from_le_bytes(g0_fixed_bytes_v1(bytes, offset, field)?))
}

fn g0_descriptor_identity_v1(
    bytes: &[u8],
    offset: usize,
    field: G0ContractFieldV1,
) -> Result<DescriptorIdentityV1, WireErrorV1> {
    DescriptorIdentityV1::try_new(
        g0_u64_le_v1(bytes, offset, field)?,
        g0_u64_le_v1(bytes, offset + 8, field)?,
        g0_u64_le_v1(bytes, offset + 16, field)?,
    )
    .map_err(|_| WireErrorV1::G0ContractDrift(field))
}

/// Generator-local request, measurements, and nonce used by the typed peer route.
pub struct G0GeneratorPeerLocalFactsV1 {
    local_request: RequestCommitmentV1,
    appliance_measurement: [u8; 32],
    supervisor_measurement: [u8; 32],
    generator_measurement: [u8; 32],
    worker_measurement: [u8; 32],
    local_generator_nonce: [u8; 32],
}

impl G0GeneratorPeerLocalFactsV1 {
    /// Owns the one local fact set used by both generator nonce records.
    ///
    /// # Errors
    ///
    /// Returns [`WireErrorV1`] when the generator nonce is zero.
    pub fn try_new(
        local_request: RequestCommitmentV1,
        appliance_measurement: [u8; 32],
        supervisor_measurement: [u8; 32],
        generator_measurement: [u8; 32],
        worker_measurement: [u8; 32],
        local_generator_nonce: [u8; 32],
    ) -> Result<Self, WireErrorV1> {
        if local_generator_nonce == [0; 32] {
            return Err(WireErrorV1::G0ContractDrift(G0ContractFieldV1::Nonce));
        }
        Ok(Self {
            local_request,
            appliance_measurement,
            supervisor_measurement,
            generator_measurement,
            worker_measurement,
            local_generator_nonce,
        })
    }

    /// Calculates the role-fixed generator commitment record.
    ///
    /// # Errors
    ///
    /// Returns [`WireErrorV1`] when the canonical record cannot be encoded.
    pub fn prepare_generator_commit_record_v1(
        &self,
    ) -> Result<G0GeneratorCommitRecordV1, WireErrorV1> {
        Ok(G0GeneratorCommitRecordV1 {
            bytes: encode_pre_session_record_v1(
                PreSessionRecordKindV1::GeneratorCommit,
                &self.local_request,
                self.local_generator_nonce,
            )?,
        })
    }

    /// Calculates the role-fixed generator reveal record.
    ///
    /// # Errors
    ///
    /// Returns [`WireErrorV1`] when the canonical record cannot be encoded.
    pub fn prepare_generator_reveal_record_v1(
        &self,
    ) -> Result<G0GeneratorRevealRecordV1, WireErrorV1> {
        Ok(G0GeneratorRevealRecordV1 {
            bytes: encode_pre_session_record_v1(
                PreSessionRecordKindV1::GeneratorReveal,
                &self.local_request,
                self.local_generator_nonce,
            )?,
        })
    }
}

/// Role-fixed generator commitment bytes.
pub struct G0GeneratorCommitRecordV1 {
    bytes: [u8; G0_PRE_SESSION_RECORD_BYTES_V1],
}

impl G0GeneratorCommitRecordV1 {
    /// Returns the exact canonical record used by the cross-crate transport.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; G0_PRE_SESSION_RECORD_BYTES_V1] {
        &self.bytes
    }
}

/// Role-fixed generator reveal bytes.
pub struct G0GeneratorRevealRecordV1 {
    bytes: [u8; G0_PRE_SESSION_RECORD_BYTES_V1],
}

impl G0GeneratorRevealRecordV1 {
    /// Returns the exact canonical record used by the cross-crate transport.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; G0_PRE_SESSION_RECORD_BYTES_V1] {
        &self.bytes
    }
}

/// Raw-only borrowed inputs for generator-side provider-session reconstruction.
#[derive(Clone, Copy)]
pub struct G0GeneratorPeerSessionInputV1<'a> {
    /// Exact received `SessionOffer` bytes.
    pub session_offer_raw: &'a [u8; G0_SESSION_OFFER_BYTES_V1],
    /// Exact successfully enqueued generator commitment bytes.
    pub generator_commit_raw: &'a [u8; G0_PRE_SESSION_RECORD_BYTES_V1],
    /// Exact received supervisor commitment bytes.
    pub supervisor_commit_raw: &'a [u8; G0_PRE_SESSION_RECORD_BYTES_V1],
    /// Exact successfully enqueued generator reveal bytes.
    pub generator_reveal_raw: &'a [u8; G0_PRE_SESSION_RECORD_BYTES_V1],
    /// Exact received supervisor reveal bytes.
    pub supervisor_reveal_raw: &'a [u8; G0_PRE_SESSION_RECORD_BYTES_V1],
    /// Retained generator-local facts.
    pub local_facts: &'a G0GeneratorPeerLocalFactsV1,
    /// Retained local generator endpoint commitment.
    pub local_generator_endpoint: &'a SeqpacketEndpointCommitmentV1,
}

/// Complete, non-authorizing generator-side provider-session candidate.
pub struct G0GeneratorPeerSessionCandidateV1 {
    session: ProviderSessionMaterialV1,
    #[cfg_attr(not(test), allow(dead_code))]
    supervisor_pid: u32,
    #[cfg_attr(not(test), allow(dead_code))]
    supervisor_start_epoch: u64,
    #[cfg_attr(not(test), allow(dead_code))]
    supervisor_generator_endpoint_digest: [u8; 32],
    #[cfg_attr(not(test), allow(dead_code))]
    supervisor_receiver_user_namespace: DescriptorIdentityV1,
}

impl G0GeneratorPeerSessionCandidateV1 {
    /// Reconstructs one provider session from the five exact transport buffers.
    ///
    /// # Errors
    ///
    /// Returns [`WireErrorV1`] when any raw input, local fact, or causal join differs.
    #[allow(clippy::too_many_lines)]
    pub fn try_new(input: G0GeneratorPeerSessionInputV1<'_>) -> Result<Self, WireErrorV1> {
        let field = G0ContractFieldV1::GeneratorPeerSession;
        let offer = input.session_offer_raw;
        let offer_domain_length = u16::try_from(SESSION_OFFER_DOMAIN_V1.len())
            .map_err(|_| WireErrorV1::ArithmeticOverflow)?;
        if g0_u16_le_v1(offer, 0, field)? != offer_domain_length
            || offer.get(2..33) != Some(SESSION_OFFER_DOMAIN_V1)
            || g0_u16_le_v1(offer, 33, field)? != FRAME_VERSION_V1
            || usize::from(g0_u16_le_v1(offer, 35, field)?) != G0_REQUEST_PREIMAGE_BYTES_V1
            || offer.get(37..809) != Some(input.local_facts.local_request.preimage.as_slice())
            || offer.get(809..841) != Some(input.local_facts.local_request.digest.as_slice())
            || offer.get(841..873) != Some(input.local_facts.appliance_measurement.as_slice())
            || offer.get(873..905) != Some(input.local_facts.supervisor_measurement.as_slice())
            || offer.get(905..937) != Some(input.local_facts.generator_measurement.as_slice())
            || offer.get(937..969) != Some(input.local_facts.worker_measurement.as_slice())
        {
            return Err(WireErrorV1::G0ContractDrift(field));
        }
        let supervisor_pid = g0_u32_le_v1(offer, 969, field)?;
        let supervisor_start_epoch = g0_u64_le_v1(offer, 973, field)?;
        if supervisor_pid == 0 || supervisor_start_epoch == 0 {
            return Err(WireErrorV1::G0ContractDrift(field));
        }
        let offered_generator_channel = g0_fixed_bytes_v1::<32>(offer, 981, field)?;
        let offered_worker_channel = g0_fixed_bytes_v1::<32>(offer, 1013, field)?;
        let supervisor_generator_endpoint_digest = g0_fixed_bytes_v1::<32>(offer, 1045, field)?;
        let supervisor_receiver_user_namespace = g0_descriptor_identity_v1(offer, 1077, field)?;

        if input.local_generator_endpoint.role != SeqpacketEndpointRoleV1::Generator {
            return Err(WireErrorV1::G0ContractDrift(field));
        }
        let generator_channel = ChannelIdentityV1::from_ordered_endpoint_digests(
            ChannelIdentityKindV1::Generator,
            GENERATOR_CHANNEL_IDENTITY_DOMAIN_V1,
            input.local_generator_endpoint.digest,
            supervisor_generator_endpoint_digest,
            108,
        );
        if generator_channel.digest != offered_generator_channel {
            return Err(WireErrorV1::G0ContractDrift(field));
        }
        let worker_channel = ChannelIdentityV1 {
            kind: ChannelIdentityKindV1::Worker,
            digest: offered_worker_channel,
        };

        let supervisor_reveal = input.supervisor_reveal_raw;
        if supervisor_reveal.get(..8) != Some(PRE_SESSION_RECORD_MAGIC_V1.as_slice())
            || g0_u16_le_v1(supervisor_reveal, 8, field)? != FRAME_VERSION_V1
            || supervisor_reveal.get(10) != Some(&(PreSessionRecordKindV1::SupervisorReveal as u8))
            || supervisor_reveal.get(11..43)
                != Some(input.local_facts.local_request.digest.as_slice())
        {
            return Err(WireErrorV1::G0ContractDrift(field));
        }
        let supervisor_nonce = g0_fixed_bytes_v1::<32>(supervisor_reveal, 43, field)?;
        if supervisor_nonce == [0; 32]
            || input.generator_commit_raw
                != &encode_pre_session_record_v1(
                    PreSessionRecordKindV1::GeneratorCommit,
                    &input.local_facts.local_request,
                    input.local_facts.local_generator_nonce,
                )?
            || input.generator_reveal_raw
                != &encode_pre_session_record_v1(
                    PreSessionRecordKindV1::GeneratorReveal,
                    &input.local_facts.local_request,
                    input.local_facts.local_generator_nonce,
                )?
            || input.supervisor_commit_raw
                != &encode_pre_session_record_v1(
                    PreSessionRecordKindV1::SupervisorCommit,
                    &input.local_facts.local_request,
                    supervisor_nonce,
                )?
            || input.supervisor_reveal_raw
                != &encode_pre_session_record_v1(
                    PreSessionRecordKindV1::SupervisorReveal,
                    &input.local_facts.local_request,
                    supervisor_nonce,
                )?
        {
            return Err(WireErrorV1::G0ContractDrift(field));
        }

        let session = ProviderSessionMaterialV1::try_new(ProviderSessionInputV1 {
            request: &input.local_facts.local_request,
            appliance_measurement: input.local_facts.appliance_measurement,
            supervisor_measurement: input.local_facts.supervisor_measurement,
            generator_measurement: input.local_facts.generator_measurement,
            worker_measurement: input.local_facts.worker_measurement,
            generator_nonce: input.local_facts.local_generator_nonce,
            supervisor_nonce,
            supervisor_pid,
            supervisor_start_epoch,
            generator_channel: &generator_channel,
            worker_channel: &worker_channel,
        })?;
        Ok(Self {
            session,
            supervisor_pid,
            supervisor_start_epoch,
            supervisor_generator_endpoint_digest,
            supervisor_receiver_user_namespace,
        })
    }

    /// Constructs the exact `GeneratorBound` body without exposing session material.
    ///
    /// # Errors
    ///
    /// Returns [`WireErrorV1`] when the body inputs violate the canonical contract.
    pub fn prepare_generator_bound_body_v1(
        &self,
        seal_profile: &GeneratorSealProfileV1,
        inventory: &ProcessInventoryV1,
        ingress: &SealedIngressManifestV1,
    ) -> Result<GeneratorBoundBodyV1, WireErrorV1> {
        GeneratorBoundBodyV1::try_new(&self.session, seal_profile, inventory, ingress)
    }

    /// Validates the raw `ClosedResult` envelope while deferring FD-bound transcript work.
    ///
    /// # Errors
    ///
    /// Returns [`WireErrorV1`] when the received envelope or ancillary shape differs.
    pub fn validate_closed_result_inbound_v1(
        &self,
        input: G0ClosedResultInboundInputV1<'_>,
    ) -> Result<G0ClosedResultInboundCandidateV1, WireErrorV1> {
        let field = G0ContractFieldV1::ClosedResultFrame;
        let raw = input.received_raw_frame;
        let closed_body_domain_length = u16::try_from(CLOSED_RESULT_BODY_DOMAIN_V1.len())
            .map_err(|_| WireErrorV1::ArithmeticOverflow)?;
        if input.actual_rights_count != 1
            || raw.get(..8) != Some(FRAME_MAGIC_V1.as_slice())
            || g0_u16_le_v1(raw, 8, field)? != FRAME_VERSION_V1
            || raw.get(10) != Some(&FrameDirectionV1::SupervisorToGenerator.wire_code())
            || raw.get(11) != Some(&1)
            || raw.get(12) != Some(&AttemptPhaseV1::Closed.wire_code())
            || usize::try_from(g0_u32_le_v1(raw, 13, field)?)
                .map_err(|_| WireErrorV1::G0ContractDrift(field))?
                != G0_CLOSED_RESULT_BODY_BYTES_V1
            || raw.get(17..49) != Some(self.session.session_id.as_slice())
            || raw.get(81) != Some(&1)
            || raw.get(82) != Some(&9)
            || g0_u16_le_v1(raw, 83, field)? != closed_body_domain_length
            || raw.get(85..121) != Some(CLOSED_RESULT_BODY_DOMAIN_V1)
            || g0_u16_le_v1(raw, 121, field)? != FRAME_VERSION_V1
            || raw.get(123..155) != Some(self.session.request_commitment.as_slice())
        {
            return Err(WireErrorV1::G0ContractDrift(field));
        }
        Ok(G0ClosedResultInboundCandidateV1 {
            raw_frame: *raw,
            observed_credentials: input.observed_credentials,
            session_id: self.session.session_id,
            claimed_generator_bound_digest: g0_fixed_bytes_v1(raw, 49, field)?,
            terminal_worker_digest: g0_fixed_bytes_v1(raw, 155, field)?,
            claimed_content_digest: g0_fixed_bytes_v1(raw, 187, field)?,
        })
    }
}

/// Raw-only `ClosedResult` receive observations supplied by linux-abi.
#[derive(Clone, Copy, Debug)]
pub struct G0ClosedResultInboundInputV1<'a> {
    /// Exact received frame bytes.
    pub received_raw_frame: &'a [u8; G0_CLOSED_RESULT_RAW_FRAME_BYTES_V1],
    /// Actual installed rights count.
    pub actual_rights_count: usize,
    /// Exact kernel-observed credentials joined by linux-abi.
    pub observed_credentials: PeerCredentialsV1,
}

/// `ClosedResult` candidate awaiting physical bytes and complete FD commitment.
pub struct G0ClosedResultInboundCandidateV1 {
    raw_frame: [u8; G0_CLOSED_RESULT_RAW_FRAME_BYTES_V1],
    observed_credentials: PeerCredentialsV1,
    session_id: [u8; 32],
    claimed_generator_bound_digest: [u8; 32],
    terminal_worker_digest: [u8; 32],
    claimed_content_digest: [u8; 32],
}

impl G0ClosedResultInboundCandidateV1 {
    /// Completes content, commitment, raw-frame, and transcript validation once.
    ///
    /// # Errors
    ///
    /// Returns [`WireErrorV1`] when the bounded bytes or reconstructed contract differ.
    pub fn verify_final_result_content_once_v1(
        self,
        bytes: &[u8],
    ) -> Result<G0VerifiedClosedResultClaimsV1, WireErrorV1> {
        if bytes.is_empty() || bytes.len() > G0_FINAL_RESULT_MAX_BYTES_V1 {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::FinalResultContent,
            ));
        }
        let size = u64::try_from(bytes.len()).map_err(|_| WireErrorV1::ArithmeticOverflow)?;
        let verified_content_digest = g0_final_result_content_digest_v1(bytes)?;
        if verified_content_digest != self.claimed_content_digest {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::FinalResultContent,
            ));
        }
        let final_result = FdCommitmentV1::try_new(
            FdRoleV1::FinalResult,
            FdIdentityV1::Memfd {
                size,
                content_digest: verified_content_digest,
                seals: MemfdSealsV1::new(
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                ),
            },
            FdStatusV1::new(FdAccessV1::ReadOnly, false, true),
        )?;
        let commitments = [final_result];
        let frame = WireFrameV1::try_new(FrameInputV1 {
            direction: FrameDirectionV1::SupervisorToGenerator,
            ordinal: 1,
            phase: AttemptPhaseV1::Closed,
            session_id: self.session_id,
            previous_hash: self.claimed_generator_bound_digest,
            body: &self.raw_frame[83..],
            credentials: self.observed_credentials,
            fd_commitments: &commitments,
            ancillary: AncillaryShapeV1::canonical(1),
        })?;
        let canonical_raw = frame.encode_raw_frame()?;
        if canonical_raw.as_slice() != self.raw_frame {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::ClosedResultFrame,
            ));
        }
        let transcript = prepare_transcript_bytes_v1(
            self.session_id,
            1,
            self.claimed_generator_bound_digest,
            &frame,
        )?;
        let transcript: [u8; 380] = transcript
            .try_into()
            .map_err(|_| WireErrorV1::G0ContractDrift(G0ContractFieldV1::ClosedResultFrame))?;
        Ok(G0VerifiedClosedResultClaimsV1 {
            claimed_generator_bound_digest: self.claimed_generator_bound_digest,
            terminal_worker_digest: self.terminal_worker_digest,
            verified_content_digest,
            transcript,
        })
    }
}

/// Bounded canonical `FinalResult` digest calculation.
///
/// # Errors
///
/// Returns [`WireErrorV1`] when `bytes` is empty or exceeds the fixed maximum.
pub fn g0_final_result_content_digest_v1(bytes: &[u8]) -> Result<[u8; 32], WireErrorV1> {
    if bytes.is_empty() || bytes.len() > G0_FINAL_RESULT_MAX_BYTES_V1 {
        return Err(WireErrorV1::G0ContractDrift(
            G0ContractFieldV1::FinalResultContent,
        ));
    }
    Ok(sha256_v1(bytes))
}

/// Verified `ClosedResult` claims awaiting the consuming expected/claimed join.
pub struct G0VerifiedClosedResultClaimsV1 {
    claimed_generator_bound_digest: [u8; 32],
    terminal_worker_digest: [u8; 32],
    verified_content_digest: [u8; 32],
    transcript: [u8; 380],
}

impl G0VerifiedClosedResultClaimsV1 {
    fn join_expected_generator_bound_v1(
        self,
        expected_generator_bound_digest: [u8; 32],
    ) -> Result<G0MatchedClosedResultClaimsV1, WireErrorV1> {
        let Self {
            claimed_generator_bound_digest,
            terminal_worker_digest,
            verified_content_digest,
            transcript: _transcript,
        } = self;
        if expected_generator_bound_digest != claimed_generator_bound_digest {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::ClosedResultFrame,
            ));
        }
        Ok(G0MatchedClosedResultClaimsV1 {
            terminal_worker_digest,
            verified_content_digest,
        })
    }

    /// Returns S's non-authorizing claimed `GeneratorBound` digest.
    #[must_use]
    pub const fn claimed_generator_bound_digest_v1(&self) -> [u8; 32] {
        self.claimed_generator_bound_digest
    }

    /// Returns the claimed terminal worker-chain digest.
    #[must_use]
    pub const fn terminal_worker_digest_v1(&self) -> [u8; 32] {
        self.terminal_worker_digest
    }

    /// Returns the content digest verified from the bounded owned bytes.
    #[must_use]
    pub const fn verified_content_digest_v1(&self) -> [u8; 32] {
        self.verified_content_digest
    }
}

/// `GeneratorBound` raw bytes plus its private credential-bound digest expectation.
pub struct G0GeneratorBoundOutboundCandidateV1 {
    session: G0GeneratorPeerSessionCandidateV1,
    raw_frame: [u8; G0_GENERATOR_BOUND_RAW_FRAME_BYTES_V1],
    expected_generator_bound_digest: [u8; 32],
}

impl G0GeneratorBoundOutboundCandidateV1 {
    /// Prepares the exact raw frame and credential-bound transcript together.
    ///
    /// # Errors
    ///
    /// Returns [`WireErrorV1`] when body, frame, or transcript reconstruction differs.
    pub fn prepare(
        session: G0GeneratorPeerSessionCandidateV1,
        body: &GeneratorBoundBodyV1,
        credentials: PeerCredentialsV1,
    ) -> Result<Self, WireErrorV1> {
        let raw_frame = encode_generator_bound_raw_frame_v1(&session.session, body)?;
        let binding = G0TranscriptSessionBindingV1::from_session(&session.session);
        let frame = WireFrameV1::try_new(FrameInputV1 {
            direction: FrameDirectionV1::GeneratorToSupervisor,
            ordinal: 0,
            phase: AttemptPhaseV1::GeneratorBound,
            session_id: session.session.session_id,
            previous_hash: binding.generator_genesis(),
            body: body.bytes(),
            credentials,
            fd_commitments: &[],
            ancillary: AncillaryShapeV1::canonical(0),
        })?;
        let transcript = G0GeneratorBoundTranscriptCandidateV1::prepare(&session.session, &frame)?;
        if frame.encode_raw_frame()?.as_slice() != raw_frame {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::GeneratorBoundFrame,
            ));
        }
        Ok(Self {
            session,
            raw_frame,
            expected_generator_bound_digest: transcript.digest(),
        })
    }

    /// Returns only the exact raw bytes required by the consuming transport send.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; G0_GENERATOR_BOUND_RAW_FRAME_BYTES_V1] {
        &self.raw_frame
    }

    /// Consumes the outbound candidate into the sole `ClosedResult` wait capability.
    ///
    /// This contract-only transition is non-authorizing and does not prove that `sendmsg`
    /// enqueued any bytes. The linux-abi runtime is the sole intended caller and must invoke
    /// it only after the exact full `GeneratorBound` frame was successfully enqueued.
    #[must_use]
    pub fn into_await_closed_result_v1(self) -> G0GeneratorBoundAwaitClosedResultV1 {
        G0GeneratorBoundAwaitClosedResultV1 {
            session: self.session,
            expected_generator_bound_digest: self.expected_generator_bound_digest,
        }
    }
}

/// Affine wait capability for the one `ClosedResult` belonging to an enqueued `GeneratorBound`.
pub struct G0GeneratorBoundAwaitClosedResultV1 {
    session: G0GeneratorPeerSessionCandidateV1,
    expected_generator_bound_digest: [u8; 32],
}

impl G0GeneratorBoundAwaitClosedResultV1 {
    /// Consumes the wait capability, observed envelope, and bounded physical content together.
    ///
    /// # Errors
    ///
    /// Returns [`WireErrorV1`] when the envelope, final-result commitment, physical content, or
    /// expected/claimed `GeneratorBound` digest differs from the retained session contract.
    pub fn verify_observed_closed_result_once_v1(
        self,
        input: G0ClosedResultInboundInputV1<'_>,
        final_result_content: &[u8],
    ) -> Result<G0ClosedResultVerifiedV1, WireErrorV1> {
        let claims = self
            .session
            .validate_closed_result_inbound_v1(input)?
            .verify_final_result_content_once_v1(final_result_content)?;
        let matched =
            claims.join_expected_generator_bound_v1(self.expected_generator_bound_digest)?;
        Ok(G0ClosedResultVerifiedV1 { _matched: matched })
    }
}

/// Opaque, non-authorizing proof that the sole terminal contract join completed.
pub struct G0ClosedResultVerifiedV1 {
    _matched: G0MatchedClosedResultClaimsV1,
}

/// Claims whose `GeneratorBound` digest has passed the sole consuming join.
pub struct G0MatchedClosedResultClaimsV1 {
    terminal_worker_digest: [u8; 32],
    verified_content_digest: [u8; 32],
}

impl G0MatchedClosedResultClaimsV1 {
    /// Returns the matched terminal worker-chain digest.
    #[must_use]
    pub const fn terminal_worker_digest_v1(&self) -> [u8; 32] {
        self.terminal_worker_digest
    }

    /// Returns the verified `FinalResult` content digest.
    #[must_use]
    pub const fn verified_content_digest_v1(&self) -> [u8; 32] {
        self.verified_content_digest
    }
}

fn g0_provider_session_from_preimage_v1(
    bytes: &[u8],
) -> Result<(ProviderSessionMaterialV1, u32), WireErrorV1> {
    let field = G0ContractFieldV1::WorkerBootstrapFrame;
    let preimage: [u8; G0_PROVIDER_SESSION_PREIMAGE_BYTES_V1] = bytes
        .try_into()
        .map_err(|_| WireErrorV1::G0ContractDrift(field))?;
    if preimage.get(..28) != Some(PROVIDER_SESSION_DOMAIN_V1)
        || usize::from(g0_u16_le_v1(&preimage, 28, field)?) != SESSION_PROTOCOL_ID_V1.len()
        || preimage.get(30..73) != Some(SESSION_PROTOCOL_ID_V1)
    {
        return Err(WireErrorV1::G0ContractDrift(field));
    }

    let request_commitment = g0_fixed_bytes_v1::<32>(&preimage, 73, field)?;
    let generator_nonce = g0_fixed_bytes_v1::<32>(&preimage, 233, field)?;
    let supervisor_nonce = g0_fixed_bytes_v1::<32>(&preimage, 265, field)?;
    let supervisor_pid = g0_u32_le_v1(&preimage, 297, field)?;
    let supervisor_start_epoch = g0_u64_le_v1(&preimage, 301, field)?;
    if supervisor_pid == 0 || supervisor_start_epoch == 0 {
        return Err(WireErrorV1::G0ContractDrift(field));
    }
    let generator_nonce_commitment = nonce_commitment_from_digest_v1(
        NonceRoleV1::Generator,
        request_commitment,
        generator_nonce,
    )
    .map_err(|_| WireErrorV1::G0ContractDrift(field))?;
    let supervisor_nonce_commitment = nonce_commitment_from_digest_v1(
        NonceRoleV1::Supervisor,
        request_commitment,
        supervisor_nonce,
    )
    .map_err(|_| WireErrorV1::G0ContractDrift(field))?;
    let session = ProviderSessionMaterialV1 {
        session_id: sha256_v1(&preimage),
        request_commitment,
        generator_nonce_commitment,
        supervisor_nonce_commitment,
        generator_channel: g0_fixed_bytes_v1(&preimage, 309, field)?,
        worker_channel: g0_fixed_bytes_v1(&preimage, 341, field)?,
        preimage,
    };
    Ok((session, supervisor_pid))
}

fn g0_worker_manifest_memfd_v1(
    bytes: &[u8],
    role: FdRoleV1,
) -> Result<FdCommitmentV1, WireErrorV1> {
    let field = G0ContractFieldV1::WorkerBootstrapFrame;
    let (encoded_length, identity_offset, seals, status) = match role {
        FdRoleV1::Observation => (
            49,
            1,
            MemfdSealsV1::new(
                SealPresenceV1::Present,
                SealPresenceV1::Present,
                SealPresenceV1::Absent,
                SealPresenceV1::Absent,
            ),
            FdStatusV1::new(FdAccessV1::ReadWrite, false, true),
        ),
        FdRoleV1::CampaignInput(_) => (
            50,
            2,
            MemfdSealsV1::new(
                SealPresenceV1::Present,
                SealPresenceV1::Present,
                SealPresenceV1::Present,
                SealPresenceV1::Present,
            ),
            FdStatusV1::new(FdAccessV1::ReadOnly, false, true),
        ),
        _ => return Err(WireErrorV1::G0ContractDrift(field)),
    };
    if bytes.len() != encoded_length || bytes.get(identity_offset) != Some(&2) {
        return Err(WireErrorV1::G0ContractDrift(field));
    }
    let size_offset = identity_offset
        .checked_add(1)
        .ok_or(WireErrorV1::ArithmeticOverflow)?;
    let digest_offset = size_offset
        .checked_add(8)
        .ok_or(WireErrorV1::ArithmeticOverflow)?;
    let commitment = FdCommitmentV1::try_new(
        role,
        FdIdentityV1::Memfd {
            size: g0_u64_le_v1(bytes, size_offset, field)?,
            content_digest: g0_fixed_bytes_v1(bytes, digest_offset, field)?,
            seals,
        },
        status,
    )
    .map_err(|_| WireErrorV1::G0ContractDrift(field))?;
    if encode_fd_commitment_v1(&commitment)?.as_slice() != bytes {
        return Err(WireErrorV1::G0ContractDrift(field));
    }
    Ok(commitment)
}

fn g0_worker_manifest_from_raw_v1(
    bytes: &[u8],
    campaign_count: usize,
) -> Result<(WorkerTransferManifestV1, Vec<FdCommitmentV1>), WireErrorV1> {
    let field = G0ContractFieldV1::WorkerBootstrapFrame;
    let expected_length = 99_usize
        .checked_add(
            campaign_count
                .checked_mul(53)
                .ok_or(WireErrorV1::ArithmeticOverflow)?,
        )
        .ok_or(WireErrorV1::ArithmeticOverflow)?;
    if bytes.len() != expected_length
        || usize::from(g0_u16_le_v1(bytes, 0, field)?) != WORKER_TRANSFER_MANIFEST_DOMAIN_V1.len()
        || bytes.get(2..44) != Some(WORKER_TRANSFER_MANIFEST_DOMAIN_V1)
        || g0_u16_le_v1(bytes, 44, field)? != FRAME_VERSION_V1
        || usize::from(*bytes.get(46).ok_or(WireErrorV1::G0ContractDrift(field))?)
            != campaign_count + 1
        || bytes.get(47) != Some(&4)
        || g0_u16_le_v1(bytes, 48, field)? != 49
    {
        return Err(WireErrorV1::G0ContractDrift(field));
    }

    let observation = g0_worker_manifest_memfd_v1(
        bytes
            .get(50..99)
            .ok_or(WireErrorV1::G0ContractDrift(field))?,
        FdRoleV1::Observation,
    )?;
    let mut campaign_inputs = Vec::with_capacity(campaign_count);
    for index in 0..campaign_count {
        let start = 99_usize
            .checked_add(
                index
                    .checked_mul(53)
                    .ok_or(WireErrorV1::ArithmeticOverflow)?,
            )
            .ok_or(WireErrorV1::ArithmeticOverflow)?;
        let end = start
            .checked_add(53)
            .ok_or(WireErrorV1::ArithmeticOverflow)?;
        let record = bytes
            .get(start..end)
            .ok_or(WireErrorV1::G0ContractDrift(field))?;
        if record.first()
            != Some(&u8::try_from(5 + index).map_err(|_| WireErrorV1::ArithmeticOverflow)?)
            || g0_u16_le_v1(record, 1, field)? != 50
        {
            return Err(WireErrorV1::G0ContractDrift(field));
        }
        campaign_inputs.push(g0_worker_manifest_memfd_v1(
            &record[3..],
            FdRoleV1::CampaignInput(
                u8::try_from(index).map_err(|_| WireErrorV1::ArithmeticOverflow)?,
            ),
        )?);
    }

    let manifest = WorkerTransferManifestV1::try_new(&observation, &campaign_inputs)?;
    if manifest.bytes.as_slice() != bytes {
        return Err(WireErrorV1::G0ContractDrift(field));
    }
    let mut commitments = Vec::with_capacity(campaign_count + 1);
    commitments.push(observation);
    commitments.extend_from_slice(&campaign_inputs);
    Ok((manifest, commitments))
}

/// Raw-only worker bootstrap receive observations supplied by linux-abi.
#[derive(Clone, Copy, Debug)]
pub struct G0WorkerBootstrapInboundInputV1<'a> {
    /// Exact received raw frame bytes.
    pub received_raw_frame: &'a [u8],
    /// Actual number of installed rights from the one kernel message.
    pub actual_rights_count: usize,
    /// Exact kernel credentials projected into W's receiver user namespace.
    pub observed_credentials: PeerCredentialsV1,
    /// W's retained local endpoint commitment.
    pub local_worker_endpoint: &'a SeqpacketEndpointCommitmentV1,
    /// Process-owned expected outer worker UID.
    pub expected_outer_uid: u32,
    /// Process-owned expected outer worker GID.
    pub expected_outer_gid: u32,
}

/// Complete non-authorizing worker bootstrap candidate retained by linux-abi.
pub struct G0WorkerBootstrapInboundCandidateV1 {
    session: ProviderSessionMaterialV1,
    bootstrap_digest: TranscriptDigestV1,
    supervisor_receiver_user_namespace: DescriptorIdentityV1,
    expected_outer_uid: u32,
    expected_outer_gid: u32,
    worker_initial_inventory: ProcessInventoryV1,
    worker_transfer_inventory: ProcessInventoryV1,
    worker_manifest: WorkerTransferManifestV1,
    transfer_commitments: Vec<FdCommitmentV1>,
}

impl G0WorkerBootstrapInboundCandidateV1 {
    /// Decodes and byte-exactly reconstructs the sole `WorkerBootstrap` shape.
    ///
    /// # Errors
    ///
    /// Returns [`WireErrorV1`] when any raw, ancillary, session, or transcript field differs.
    #[allow(clippy::too_many_lines)]
    pub fn try_new(input: G0WorkerBootstrapInboundInputV1<'_>) -> Result<Self, WireErrorV1> {
        let field = G0ContractFieldV1::WorkerBootstrapFrame;
        let raw = input.received_raw_frame;
        let declared_fd_count =
            usize::from(*raw.get(81).ok_or(WireErrorV1::G0ContractDrift(field))?);
        if declared_fd_count == 0
            || declared_fd_count > MAX_FRAME_FDS_V1
            || input.actual_rights_count != declared_fd_count
        {
            return Err(WireErrorV1::G0ContractDrift(field));
        }
        let campaign_count = declared_fd_count - 1;
        if campaign_count > G0_MAX_INGRESS_COUNT_V1 {
            return Err(WireErrorV1::G0ContractDrift(field));
        }
        let manifest_length = 99_usize
            .checked_add(
                campaign_count
                    .checked_mul(53)
                    .ok_or(WireErrorV1::ArithmeticOverflow)?,
            )
            .ok_or(WireErrorV1::ArithmeticOverflow)?;
        let body_length = G0_WORKER_BOOTSTRAP_FIXED_BODY_BYTES_V1
            .checked_add(manifest_length)
            .ok_or(WireErrorV1::ArithmeticOverflow)?;
        let roles_length = 1_usize
            .checked_add(
                campaign_count
                    .checked_mul(2)
                    .ok_or(WireErrorV1::ArithmeticOverflow)?,
            )
            .ok_or(WireErrorV1::ArithmeticOverflow)?;
        let body_start = FRAME_FIXED_HEADER_BYTES_V1
            .checked_add(roles_length)
            .ok_or(WireErrorV1::ArithmeticOverflow)?;
        let raw_length = body_start
            .checked_add(body_length)
            .ok_or(WireErrorV1::ArithmeticOverflow)?;
        if raw.len() != raw_length
            || raw.get(..8) != Some(FRAME_MAGIC_V1.as_slice())
            || g0_u16_le_v1(raw, 8, field)? != FRAME_VERSION_V1
            || raw.get(10) != Some(&FrameDirectionV1::SupervisorToWorker.wire_code())
            || raw.get(11) != Some(&0)
            || raw.get(12) != Some(&AttemptPhaseV1::UserMapsVerified.wire_code())
            || usize::try_from(g0_u32_le_v1(raw, 13, field)?)
                .map_err(|_| WireErrorV1::G0ContractDrift(field))?
                != body_length
            || raw.get(82) != Some(&8)
        {
            return Err(WireErrorV1::G0ContractDrift(field));
        }
        for index in 0..campaign_count {
            let role_offset = 83_usize
                .checked_add(
                    index
                        .checked_mul(2)
                        .ok_or(WireErrorV1::ArithmeticOverflow)?,
                )
                .ok_or(WireErrorV1::ArithmeticOverflow)?;
            if raw.get(role_offset) != Some(&0)
                || raw.get(role_offset + 1)
                    != Some(&u8::try_from(index).map_err(|_| WireErrorV1::ArithmeticOverflow)?)
            {
                return Err(WireErrorV1::G0ContractDrift(field));
            }
        }

        let body = raw
            .get(body_start..)
            .ok_or(WireErrorV1::G0ContractDrift(field))?;
        if usize::from(g0_u16_le_v1(body, 0, field)?) != WORKER_BOOTSTRAP_BODY_DOMAIN_V1.len()
            || body.get(2..41) != Some(WORKER_BOOTSTRAP_BODY_DOMAIN_V1)
            || g0_u16_le_v1(body, 41, field)? != FRAME_VERSION_V1
        {
            return Err(WireErrorV1::G0ContractDrift(field));
        }
        let accepted_generator_bound_digest = g0_fixed_bytes_v1(body, 43, field)?;
        let (session, supervisor_pid) = g0_provider_session_from_preimage_v1(
            body.get(75..448)
                .ok_or(WireErrorV1::G0ContractDrift(field))?,
        )?;
        if raw.get(17..49) != Some(session.session_id.as_slice())
            || body.get(448..480) != Some(session.generator_nonce_commitment.as_slice())
            || body.get(480..512) != Some(session.supervisor_nonce_commitment.as_slice())
            || input.observed_credentials.process_id != supervisor_pid
            || input.observed_credentials.user_id != 0
            || input.observed_credentials.group_id != 0
            || input.local_worker_endpoint.role != SeqpacketEndpointRoleV1::Worker
            || g0_u32_le_v1(body, 568, field)? != input.expected_outer_uid
            || g0_u32_le_v1(body, 572, field)? != input.expected_outer_gid
        {
            return Err(WireErrorV1::G0ContractDrift(field));
        }

        let supervisor_worker_endpoint_digest = g0_fixed_bytes_v1(body, 512, field)?;
        ChannelIdentityV1::try_worker_child(
            input.local_worker_endpoint,
            supervisor_worker_endpoint_digest,
            &session,
        )
        .map_err(|_| WireErrorV1::G0ContractDrift(field))?;
        let supervisor_receiver_user_namespace = g0_descriptor_identity_v1(body, 544, field)?;
        if usize::from(g0_u16_le_v1(body, 640, field)?) != manifest_length {
            return Err(WireErrorV1::G0ContractDrift(field));
        }
        let manifest_end = 642_usize
            .checked_add(manifest_length)
            .ok_or(WireErrorV1::ArithmeticOverflow)?;
        let manifest_bytes = body
            .get(642..manifest_end)
            .ok_or(WireErrorV1::G0ContractDrift(field))?;
        let (worker_manifest, transfer_commitments) =
            g0_worker_manifest_from_raw_v1(manifest_bytes, campaign_count)?;
        if body.get(manifest_end..manifest_end + 32) != Some(worker_manifest.digest.as_slice()) {
            return Err(WireErrorV1::G0ContractDrift(field));
        }

        let endpoint_initial = FdCommitmentV1::try_new(
            FdRoleV1::WorkerEndpoint,
            FdIdentityV1::Socket {
                endpoint_digest: input.local_worker_endpoint.digest,
            },
            FdStatusV1::new(FdAccessV1::Socket, false, false),
        )?;
        let endpoint_transfer = FdCommitmentV1::try_new(
            FdRoleV1::WorkerEndpoint,
            FdIdentityV1::Socket {
                endpoint_digest: input.local_worker_endpoint.digest,
            },
            FdStatusV1::new(FdAccessV1::Socket, false, true),
        )?;
        let worker_initial_inventory = ProcessInventoryV1::try_new(
            ProcessInventoryKindV1::WorkerInitialPostExec,
            &[ProcessInventoryEntryV1::new(3, endpoint_initial)],
        )?;
        let mut transfer_entries = Vec::with_capacity(transfer_commitments.len() + 1);
        transfer_entries.push(ProcessInventoryEntryV1::new(3, endpoint_transfer));
        for (index, commitment) in transfer_commitments.iter().copied().enumerate() {
            transfer_entries.push(ProcessInventoryEntryV1::new(
                u8::try_from(4 + index).map_err(|_| WireErrorV1::ArithmeticOverflow)?,
                commitment,
            ));
        }
        let worker_transfer_inventory = ProcessInventoryV1::try_new(
            ProcessInventoryKindV1::WorkerExpectedPostTransfer,
            &transfer_entries,
        )?;
        if body.get(576..608) != Some(worker_initial_inventory.digest.as_slice())
            || body.get(608..640) != Some(worker_transfer_inventory.digest.as_slice())
        {
            return Err(WireErrorV1::G0ContractDrift(field));
        }

        let mut canonical_body = Vec::with_capacity(body_length);
        push_lp16_v1(&mut canonical_body, WORKER_BOOTSTRAP_BODY_DOMAIN_V1)?;
        canonical_body.extend_from_slice(&FRAME_VERSION_V1.to_le_bytes());
        canonical_body.extend_from_slice(&accepted_generator_bound_digest);
        canonical_body.extend_from_slice(&session.preimage);
        canonical_body.extend_from_slice(&session.generator_nonce_commitment);
        canonical_body.extend_from_slice(&session.supervisor_nonce_commitment);
        canonical_body.extend_from_slice(&supervisor_worker_endpoint_digest);
        supervisor_receiver_user_namespace.encode_into(&mut canonical_body);
        canonical_body.extend_from_slice(&input.expected_outer_uid.to_le_bytes());
        canonical_body.extend_from_slice(&input.expected_outer_gid.to_le_bytes());
        canonical_body.extend_from_slice(&worker_initial_inventory.digest);
        canonical_body.extend_from_slice(&worker_transfer_inventory.digest);
        canonical_body.extend_from_slice(
            &u16::try_from(manifest_length)
                .map_err(|_| WireErrorV1::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        canonical_body.extend_from_slice(&worker_manifest.bytes);
        canonical_body.extend_from_slice(&worker_manifest.digest);
        if canonical_body.as_slice() != body {
            return Err(WireErrorV1::G0ContractDrift(field));
        }

        let binding = G0TranscriptSessionBindingV1::from_session(&session);
        let worker_genesis = binding.worker_genesis(accepted_generator_bound_digest);
        let frame = WireFrameV1::try_new(FrameInputV1 {
            direction: FrameDirectionV1::SupervisorToWorker,
            ordinal: 0,
            phase: AttemptPhaseV1::UserMapsVerified,
            session_id: session.session_id,
            previous_hash: worker_genesis,
            body: &canonical_body,
            credentials: input.observed_credentials,
            fd_commitments: &transfer_commitments,
            ancillary: AncillaryShapeV1::canonical(declared_fd_count),
        })?;
        if frame.encode_raw_frame()?.as_slice() != raw {
            return Err(WireErrorV1::G0ContractDrift(field));
        }
        let bootstrap = G0TranscriptCandidateV1::prepare(&session, 0, worker_genesis, &frame)?;
        Ok(Self {
            session,
            bootstrap_digest: TranscriptDigestV1::from_bytes(bootstrap.digest()),
            supervisor_receiver_user_namespace,
            expected_outer_uid: input.expected_outer_uid,
            expected_outer_gid: input.expected_outer_gid,
            worker_initial_inventory,
            worker_transfer_inventory,
            worker_manifest,
            transfer_commitments,
        })
    }

    /// Starts the exact Observation content verifier after physical comparison.
    ///
    /// # Errors
    ///
    /// Returns [`WireErrorV1`] when the physical observation differs from its commitment.
    pub fn start_observation_content_verifier_v1(
        &self,
        observed_size: u64,
        observed_status: FdStatusV1,
        observed_seals: MemfdSealsV1,
    ) -> Result<G0WorkerBootstrapContentVerifierV1, WireErrorV1> {
        let commitment = self
            .transfer_commitments
            .first()
            .ok_or(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::WorkerBootstrapContent,
            ))?;
        if commitment.role != FdRoleV1::Observation {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::WorkerBootstrapContent,
            ));
        }
        G0WorkerBootstrapContentVerifierV1::from_retained_commitment_v1(
            commitment,
            observed_size,
            observed_status,
            observed_seals,
        )
    }

    /// Starts one exact `CampaignInput` content verifier after physical comparison.
    ///
    /// # Errors
    ///
    /// Returns [`WireErrorV1`] when the index or physical observation differs.
    pub fn start_campaign_input_content_verifier_v1(
        &self,
        index: u8,
        observed_size: u64,
        observed_status: FdStatusV1,
        observed_seals: MemfdSealsV1,
    ) -> Result<G0WorkerBootstrapContentVerifierV1, WireErrorV1> {
        let position = usize::from(index)
            .checked_add(1)
            .ok_or(WireErrorV1::ArithmeticOverflow)?;
        let commitment =
            self.transfer_commitments
                .get(position)
                .ok_or(WireErrorV1::G0ContractDrift(
                    G0ContractFieldV1::WorkerBootstrapContent,
                ))?;
        if commitment.role != FdRoleV1::CampaignInput(index) {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::WorkerBootstrapContent,
            ));
        }
        G0WorkerBootstrapContentVerifierV1::from_retained_commitment_v1(
            commitment,
            observed_size,
            observed_status,
            observed_seals,
        )
    }

    /// Consumes the bootstrap candidate into the exact `WorkerExecBound` outbound candidate.
    ///
    /// The linux-abi consuming owner constructs `credentials` from its locally
    /// checked worker PID plus the retained offered namespace and outer IDs.
    /// This pure calculation boundary rechecks the namespace and both IDs; it
    /// does not claim that their future producer join has already run.
    ///
    /// # Errors
    ///
    /// Returns [`WireErrorV1`] when credentials or outbound reconstruction differ.
    pub fn prepare_worker_exec_bound_outbound_v1(
        self,
        credentials: PeerCredentialsV1,
    ) -> Result<G0WorkerExecBoundOutboundCandidateV1, WireErrorV1> {
        if credentials.user_namespace != self.supervisor_receiver_user_namespace
            || credentials.user_id != self.expected_outer_uid
            || credentials.group_id != self.expected_outer_gid
        {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::WorkerBootstrapFrame,
            ));
        }
        let body = WorkerExecBoundBodyV1::try_new(
            &self.session,
            &self.worker_initial_inventory,
            &self.worker_transfer_inventory,
            &self.worker_manifest,
        )?;
        let raw_frame =
            encode_worker_exec_bound_raw_frame_v1(&self.session, self.bootstrap_digest, &body)?;
        let frame = WireFrameV1::try_new(FrameInputV1 {
            direction: FrameDirectionV1::WorkerToSupervisor,
            ordinal: 1,
            phase: AttemptPhaseV1::WorkerExecBound,
            session_id: self.session.session_id,
            previous_hash: self.bootstrap_digest.into_bytes(),
            body: body.bytes(),
            credentials,
            fd_commitments: &[],
            ancillary: AncillaryShapeV1::canonical(0),
        })?;
        if frame.encode_raw_frame()?.as_slice() != raw_frame {
            return Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::WorkerBootstrapFrame,
            ));
        }
        let transcript = G0TranscriptCandidateV1::prepare(
            &self.session,
            1,
            self.bootstrap_digest.into_bytes(),
            &frame,
        )?;
        Ok(G0WorkerExecBoundOutboundCandidateV1 {
            raw_frame,
            _transcript_digest: transcript.digest(),
        })
    }
}

/// Candidate-owned bounded streaming SHA-256 verifier for one retained role.
pub struct G0WorkerBootstrapContentVerifierV1 {
    expected_size: u64,
    expected_digest: [u8; 32],
    next_offset: u64,
    hasher: Sha256,
}

impl G0WorkerBootstrapContentVerifierV1 {
    fn from_retained_commitment_v1(
        commitment: &FdCommitmentV1,
        observed_size: u64,
        observed_status: FdStatusV1,
        observed_seals: MemfdSealsV1,
    ) -> Result<Self, WireErrorV1> {
        let field = G0ContractFieldV1::WorkerBootstrapContent;
        let FdIdentityV1::Memfd {
            size,
            content_digest,
            seals,
        } = commitment.identity
        else {
            return Err(WireErrorV1::G0ContractDrift(field));
        };
        if observed_size != size || observed_status != commitment.status || observed_seals != seals
        {
            return Err(WireErrorV1::G0ContractDrift(field));
        }
        Ok(Self {
            expected_size: size,
            expected_digest: content_digest,
            next_offset: 0,
            hasher: Sha256::new(),
        })
    }

    /// Adds one non-empty contiguous positional chunk of at most 65,536 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`WireErrorV1`] for a gap, overlap, empty/oversized chunk, or overflow.
    pub fn update_at(&mut self, offset: u64, chunk: &[u8]) -> Result<(), WireErrorV1> {
        let field = G0ContractFieldV1::WorkerBootstrapContent;
        if offset != self.next_offset
            || chunk.is_empty()
            || chunk.len() > G0_WORKER_BOOTSTRAP_HASH_CHUNK_BYTES_V1
        {
            return Err(WireErrorV1::G0ContractDrift(field));
        }
        let chunk_length =
            u64::try_from(chunk.len()).map_err(|_| WireErrorV1::ArithmeticOverflow)?;
        let next_offset = self
            .next_offset
            .checked_add(chunk_length)
            .ok_or(WireErrorV1::ArithmeticOverflow)?;
        if next_offset > self.expected_size {
            return Err(WireErrorV1::G0ContractDrift(field));
        }
        self.hasher.update(chunk);
        self.next_offset = next_offset;
        Ok(())
    }

    /// Finishes only at the exact retained size and digest, returning no digest.
    ///
    /// # Errors
    ///
    /// Returns [`WireErrorV1`] when the final size or digest differs.
    pub fn finish(self) -> Result<(), WireErrorV1> {
        let field = G0ContractFieldV1::WorkerBootstrapContent;
        if self.next_offset != self.expected_size {
            return Err(WireErrorV1::G0ContractDrift(field));
        }
        let digest: [u8; 32] = self.hasher.finalize().into();
        if digest != self.expected_digest {
            return Err(WireErrorV1::G0ContractDrift(field));
        }
        Ok(())
    }
}

/// Exact `WorkerExecBound` raw bytes plus its private credential-bound digest.
pub struct G0WorkerExecBoundOutboundCandidateV1 {
    raw_frame: [u8; G0_WORKER_EXEC_BOUND_RAW_FRAME_BYTES_V1],
    _transcript_digest: [u8; 32],
}

impl G0WorkerExecBoundOutboundCandidateV1 {
    /// Returns only the raw bytes required by the consuming transport enqueue.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; G0_WORKER_EXEC_BOUND_RAW_FRAME_BYTES_V1] {
        &self.raw_frame
    }
}

/// First mismatched field in one exact G0 codec construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum G0ContractFieldV1 {
    /// More than fifteen ingress commitments were supplied.
    IngressCount,
    /// An ingress role, ordinal, commitment, or exact length differed.
    IngressCommitment,
    /// The ingress manifest length disagreed with its count.
    IngressManifestLength,
    /// The publication-root commitment was not the closed 30-byte shape.
    PublicationRoot,
    /// The four request role blocks were not in canonical role order.
    RequestRoleOrder,
    /// A generator or worker channel used the wrong endpoint-role pair.
    EndpointPair,
    /// `SessionOffer` used the wrong channel kind or peer endpoint role.
    SessionOfferChannel,
    /// A nonce was all zeroes.
    Nonce,
    /// Supervisor PID or start epoch was zero.
    SupervisorProcess,
    /// Provider-session input used the wrong channel kind.
    ProviderSessionChannel,
    /// A process inventory had the wrong number of entries.
    InventoryCount,
    /// A process inventory slot, role, or order differed.
    InventorySlot,
    /// A process inventory status or CLOEXEC observation differed.
    InventoryStatus,
    /// A process inventory memfd seal tuple differed.
    InventorySeals,
    /// A process inventory encoded length differed.
    InventoryLength,
    /// The generator seal instruction count was outside one through 4,096.
    GeneratorSealInstructionCount,
    /// The worker manifest had more than fifteen campaign inputs.
    WorkerManifestCount,
    /// The worker manifest Observation commitment differed.
    WorkerManifestObservation,
    /// A worker manifest `CampaignInput` commitment differed.
    WorkerManifestCampaign,
    /// The worker manifest Observation exceeded the provider role-content bound.
    WorkerManifestObservationContentLength,
    /// A worker manifest `CampaignInput` was empty or exceeded the role-content bound.
    WorkerManifestCampaignContentLength,
    /// The checked worker-transfer content sum exceeded the provider aggregate bound.
    WorkerManifestAggregateContentLength,
    /// The worker manifest length differed from its count.
    WorkerManifestLength,
    /// `GeneratorBound` used the wrong inventory kind or ingress count.
    GeneratorBoundInventory,
    /// `GeneratorBound` used the wrong direction, phase, ordinal, FD count, or body size.
    GeneratorBoundFrame,
    /// Worker bootstrap used the wrong supervisor endpoint role.
    WorkerBootstrapEndpoint,
    /// Worker bootstrap used inconsistent inventories or manifest count.
    WorkerBootstrapInventory,
    /// Worker bootstrap exceeded or disagreed with its exact length formula.
    WorkerBootstrapLength,
    /// `WorkerExecBound` used inconsistent inventories or manifest count.
    WorkerExecBoundInventory,
    /// Closed result used the wrong `FinalResult` role, status, or seals.
    ClosedResultCommitment,
    /// Generator peer-session raw inputs disagreed with the retained local facts.
    GeneratorPeerSession,
    /// A `ClosedResult` raw frame or reconstructed transcript differed.
    ClosedResultFrame,
    /// `FinalResult` content was empty, oversized, or digest-inconsistent.
    FinalResultContent,
    /// `WorkerBootstrap` raw bytes, roles, session, or transcript differed.
    WorkerBootstrapFrame,
    /// `WorkerBootstrap` content verification differed from its retained commitment.
    WorkerBootstrapContent,
}

/// A rejected wire-value, inventory, expectation, or transcript condition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireErrorV1 {
    /// A descriptor identity tuple contained zero.
    InvalidDescriptorIdentity,
    /// Peer process ID was zero.
    InvalidPeerProcessId,
    /// Process-handle identity had a zero process ID or start epoch.
    InvalidPidfdIdentity,
    /// A bounded role index was outside the frame descriptor bound.
    RoleIndexOutOfRange(u8),
    /// A role carried the wrong closed identity variant.
    RoleIdentityMismatch(FdRoleV1),
    /// A role carried an incompatible access or status tuple.
    RoleStatusMismatch(FdRoleV1),
    /// A memfd role lacked its phase-independent required seals.
    RequiredMemfdSeals(FdRoleV1),
    /// More than sixteen descriptor commitments were supplied.
    TooManyFds(usize),
    /// The frame ordinal was outside the bounded session.
    FrameOrdinalOutOfRange(u8),
    /// Body length could not be represented by the fixed field.
    BodyLengthOutOfRange(usize),
    /// The total encoded frame exceeded 65,536 bytes.
    FrameTooLarge(usize),
    /// Checked length arithmetic overflowed.
    ArithmeticOverflow,
    /// End-of-record was absent.
    MissingMessageEnd,
    /// Payload truncation was observed.
    MessageTruncated,
    /// Ancillary truncation was observed.
    ControlTruncated,
    /// The credential-record count differed from exactly one.
    CredentialRecordCount(u8),
    /// Actual and expected descriptor-rights record counts differed.
    RightsRecordCount(u8, u8),
    /// Unknown control records were present.
    UnknownControlRecords(u8),
    /// Malformed control records were present.
    MalformedControlRecords(u8),
    /// The same semantic descriptor role appeared twice.
    DuplicateFdRole(FdRoleV1),
    /// Stored magic differed from the fixed marker.
    MagicMismatch,
    /// Stored version differed from the fixed version.
    VersionMismatch(u16),
    /// Declared and actual body lengths differed.
    DeclaredBodyLengthMismatch(u32, usize),
    /// Declared and actual descriptor counts differed.
    DeclaredFdCountMismatch(u8, usize),
    /// One semantic field differed from the compiled expectation.
    ExpectationDrift(FrameFieldV1),
    /// Frame and cursor session identifiers differed.
    TranscriptSessionMismatch,
    /// Frame and expected transcript ordinals differed.
    TranscriptOrdinalMismatch(u8, u8),
    /// Frame and cursor previous digest bytes differed.
    TranscriptPreviousHashMismatch,
    /// The 64-frame transcript bound was exhausted.
    SessionFrameLimit,
    /// One exact G0 codec field differed from the closed contract.
    G0ContractDrift(G0ContractFieldV1),
}

impl fmt::Display for WireErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "H0 wire contract rejected value: {self:?}")
    }
}

impl std::error::Error for WireErrorV1 {}

#[cfg(test)]
fn production_wire_source_v1() -> &'static str {
    let source = include_str!("wire.rs");
    let production_end = source.find("#[cfg(test)]").expect("production boundary");
    assert!(production_end > 0);
    &source[..production_end]
}

#[cfg(test)]
fn rust_surface_tokens_v1(source: &str) -> Vec<String> {
    let mut chars = source.chars().peekable();
    let mut tokens = Vec::new();
    while let Some(character) = chars.next() {
        if character.is_whitespace() {
            continue;
        }
        if character == '/' && chars.peek() == Some(&'/') {
            chars.next();
            for comment_character in chars.by_ref() {
                if comment_character == '\n' {
                    break;
                }
            }
            continue;
        }
        if character == '/' && chars.peek() == Some(&'*') {
            chars.next();
            let mut depth = 1_u32;
            while let Some(comment_character) = chars.next() {
                if comment_character == '/' && chars.peek() == Some(&'*') {
                    chars.next();
                    depth += 1;
                } else if comment_character == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
            }
            continue;
        }
        if character == '"' {
            let mut escaped = false;
            for string_character in chars.by_ref() {
                if escaped {
                    escaped = false;
                } else if string_character == '\\' {
                    escaped = true;
                } else if string_character == '"' {
                    break;
                }
            }
            continue;
        }
        if character.is_ascii_alphanumeric() || character == '_' {
            let mut identifier = String::from(character);
            while let Some(next) = chars.peek().copied() {
                if !(next.is_ascii_alphanumeric() || next == '_') {
                    break;
                }
                identifier.push(next);
                chars.next();
            }
            tokens.push(identifier);
        } else {
            tokens.push(character.to_string());
        }
    }
    tokens
}

#[cfg(test)]
fn matching_surface_group_v1(tokens: &[String], open_index: usize) -> Option<usize> {
    let (open, close) = match tokens.get(open_index).map(String::as_str) {
        Some("{") => ("{", "}"),
        Some("[") => ("[", "]"),
        Some("(") => ("(", ")"),
        Some("<") => ("<", ">"),
        _ => return None,
    };
    let mut depth = 0_u32;
    for (index, token) in tokens.iter().enumerate().skip(open_index) {
        if token == open {
            depth += 1;
        } else if token == close {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

#[cfg(test)]
fn split_surface_fields_v1(tokens: &[String]) -> Vec<String> {
    let mut fields = Vec::new();
    let mut start = 0;
    let mut depth = 0_i32;
    for (index, token) in tokens.iter().enumerate() {
        match token.as_str() {
            "{" | "[" | "(" | "<" => depth += 1,
            "}" | "]" | ")" | ">" => depth -= 1,
            "," if depth == 0 => {
                if start < index {
                    fields.push(tokens[start..index].concat());
                }
                start = index + 1;
            }
            _ => {}
        }
    }
    if start < tokens.len() {
        fields.push(tokens[start..].concat());
    }
    fields
}

#[cfg(test)]
fn struct_surface_v1(tokens: &[String], owner: &str) -> (String, Vec<String>) {
    let declarations: Vec<usize> = tokens
        .windows(2)
        .enumerate()
        .filter_map(|(index, pair)| (pair[0] == "struct" && pair[1] == owner).then_some(index))
        .collect();
    assert_eq!(
        declarations.len(),
        1,
        "struct declaration drift for {owner}"
    );
    let declaration = declarations[0];
    let header_start = tokens[..declaration]
        .iter()
        .rposition(|token| token == ";" || token == "}")
        .map_or(0, |index| index + 1);
    let header = tokens[header_start..declaration].concat();
    let fields_start = (declaration + 2..tokens.len())
        .find(|index| tokens[*index] == "{")
        .expect("struct fields start");
    let fields_end = matching_surface_group_v1(tokens, fields_start).expect("struct fields end");
    (
        header,
        split_surface_fields_v1(&tokens[fields_start + 1..fields_end]),
    )
}

#[cfg(test)]
fn public_impl_surface_v1(
    tokens: &[String],
    open: usize,
    close: usize,
) -> (Vec<String>, Vec<String>, bool) {
    let mut methods = Vec::new();
    let mut non_methods = Vec::new();
    let mut associated_macro = false;
    let mut depth = 0_i32;
    let mut index = open + 1;
    while index < close {
        match tokens[index].as_str() {
            "{" => depth += 1,
            "}" => depth -= 1,
            "!" if depth == 0 => associated_macro = true,
            "pub" if depth == 0 => {
                let mut cursor = index + 1;
                if tokens.get(cursor).map(String::as_str) == Some("(") {
                    cursor =
                        matching_surface_group_v1(tokens, cursor).expect("visibility group") + 1;
                }
                let boundary = (cursor..close)
                    .find(|candidate| matches!(tokens[*candidate].as_str(), ";" | "{"))
                    .unwrap_or(close);
                let signature = &tokens[cursor..boundary];
                if let Some(function) = signature.iter().position(|token| token == "fn") {
                    methods.push(
                        signature
                            .get(function + 1)
                            .expect("public function name")
                            .clone(),
                    );
                } else {
                    let kind = signature
                        .iter()
                        .position(|token| matches!(token.as_str(), "const" | "static" | "type"))
                        .expect("public associated item kind");
                    let name = signature
                        .get(kind + 1)
                        .expect("public associated item name");
                    non_methods.push(format!("{}:{name}", signature[kind]));
                }
            }
            _ => {}
        }
        index += 1;
    }
    (methods, non_methods, associated_macro)
}

#[cfg(test)]
fn owner_impl_surface_v1(tokens: &[String], owner: &str) -> (Vec<String>, Vec<String>, bool, bool) {
    let mut methods = Vec::new();
    let mut non_methods = Vec::new();
    let mut trait_impl = false;
    let mut associated_macro = false;
    let mut depth = 0_i32;
    let mut index = 0;
    while index < tokens.len() {
        match tokens[index].as_str() {
            "{" => depth += 1,
            "}" => depth -= 1,
            "impl" if depth == 0 => {
                let open = (index + 1..tokens.len())
                    .find(|candidate| tokens[*candidate] == "{")
                    .expect("impl body start");
                let close = matching_surface_group_v1(tokens, open).expect("impl body end");
                let header = &tokens[index + 1..open];
                if let Some(for_index) = header.iter().rposition(|token| token == "for") {
                    trait_impl |= header[for_index + 1..].iter().any(|token| token == owner);
                } else if header.iter().any(|token| token == owner) {
                    let (impl_methods, impl_non_methods, impl_macro) =
                        public_impl_surface_v1(tokens, open, close);
                    methods.extend(impl_methods);
                    non_methods.extend(impl_non_methods);
                    associated_macro |= impl_macro;
                }
                index = close + 1;
                continue;
            }
            _ => {}
        }
        index += 1;
    }
    (methods, non_methods, trait_impl, associated_macro)
}

#[cfg(test)]
fn owner_alias_v1(tokens: &[String], owner: &str) -> bool {
    let mut depth = 0_i32;
    let mut index = 0;
    while index < tokens.len() {
        match tokens[index].as_str() {
            "{" => depth += 1,
            "}" => depth -= 1,
            "type" | "use" if depth == 0 => {
                let end = (index + 1..tokens.len())
                    .find(|candidate| tokens[*candidate] == ";")
                    .unwrap_or(tokens.len());
                let alias_operator = if tokens[index] == "type" { "=" } else { "as" };
                if tokens[index + 1..end]
                    .iter()
                    .any(|token| token == alias_operator)
                    && tokens[index + 1..end].iter().any(|token| token == owner)
                {
                    return true;
                }
                index = end;
            }
            _ => {}
        }
        index += 1;
    }
    false
}

#[cfg(test)]
fn public_item_end_v1(tokens: &[String], start: usize, brace_terminates: bool) -> usize {
    let mut depth = 0_i32;
    for (index, token) in tokens.iter().enumerate().skip(start) {
        match token.as_str() {
            ")" | "]" => depth -= 1,
            "{" if depth == 0 && brace_terminates => return index,
            "(" | "[" | "{" => depth += 1,
            "}" if depth > 0 => depth -= 1,
            ";" if depth == 0 => return index,
            _ => {}
        }
    }
    tokens.len()
}

#[cfg(test)]
fn public_item_kind_v1(tokens: &[String], start: usize) -> (&str, String, bool) {
    let first = tokens
        .get(start)
        .map(String::as_str)
        .expect("public item kind");
    if matches!(
        first,
        "use" | "static" | "type" | "struct" | "enum" | "union" | "trait"
    ) {
        let name = if first == "use" {
            let statement_end = (start..tokens.len())
                .find(|index| tokens[*index] == ";")
                .unwrap_or(tokens.len());
            tokens[start..statement_end]
                .iter()
                .rposition(|token| token == "as")
                .and_then(|offset| tokens.get(start + offset + 1))
                .cloned()
                .unwrap_or_else(|| "use".to_owned())
        } else {
            tokens.get(start + 1).expect("public item name").clone()
        };
        return (
            first,
            name,
            matches!(first, "struct" | "enum" | "union" | "trait"),
        );
    }
    let mut function = start;
    while tokens.get(function).is_some_and(|token| {
        matches!(
            token.as_str(),
            "const" | "async" | "unsafe" | "extern" | "default"
        )
    }) {
        function += 1;
    }
    if tokens.get(function).map(String::as_str) == Some("fn") {
        return (
            "fn",
            tokens
                .get(function + 1)
                .expect("public function name")
                .clone(),
            true,
        );
    }
    if first == "const" {
        return (
            "const",
            tokens.get(start + 1).expect("public const name").clone(),
            false,
        );
    }
    (first, "unknown".to_owned(), true)
}

#[cfg(test)]
fn owner_public_free_items_v1(tokens: &[String], owner: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut depth = 0_i32;
    let mut index = 0;
    while index < tokens.len() {
        match tokens[index].as_str() {
            "{" => depth += 1,
            "}" => depth -= 1,
            "pub" if depth == 0 => {
                let mut start = index + 1;
                if tokens.get(start).map(String::as_str) == Some("(") {
                    start = matching_surface_group_v1(tokens, start)
                        .expect("public visibility group")
                        + 1;
                }
                let (kind, name, brace_terminates) = public_item_kind_v1(tokens, start);
                let end = public_item_end_v1(tokens, start, brace_terminates);
                let mentions_owner = tokens[start..end].iter().any(|token| token == owner);
                let protected_declaration = kind == "struct" && name == owner;
                if mentions_owner && !protected_declaration {
                    items.push(format!("{kind}:{name}"));
                }
                index = end;
                continue;
            }
            _ => {}
        }
        index += 1;
    }
    items
}

#[cfg(test)]
fn owner_macro_exposure_v1(tokens: &[String], owner: &str) -> bool {
    for (index, token) in tokens.iter().enumerate() {
        if token != "!" {
            continue;
        }
        if index > 0 && tokens[index - 1] == "macro_rules" {
            return true;
        }
        let Some(open) = tokens.get(index + 1).map(String::as_str) else {
            continue;
        };
        if !matches!(open, "{" | "[" | "(") {
            continue;
        }
        let close = matching_surface_group_v1(tokens, index + 1).expect("macro invocation end");
        if tokens[index + 2..close]
            .iter()
            .any(|candidate| candidate == owner)
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
struct OwnerSurfaceV1 {
    declaration_header: String,
    fields: Vec<String>,
    methods: Vec<String>,
    non_method_items: Vec<String>,
    public_free_items: Vec<String>,
    trait_impl: bool,
    alias: bool,
    macro_exposure: bool,
}

#[cfg(test)]
fn owner_surface_v1(source: &str, owner: &str) -> OwnerSurfaceV1 {
    let tokens = rust_surface_tokens_v1(source);
    let (declaration_header, fields) = struct_surface_v1(&tokens, owner);
    let (methods, non_method_items, trait_impl, associated_macro) =
        owner_impl_surface_v1(&tokens, owner);
    OwnerSurfaceV1 {
        declaration_header,
        fields,
        methods,
        non_method_items,
        public_free_items: owner_public_free_items_v1(&tokens, owner),
        trait_impl,
        alias: owner_alias_v1(&tokens, owner),
        macro_exposure: associated_macro || owner_macro_exposure_v1(&tokens, owner),
    }
}

#[cfg(test)]
fn assert_owner_surface_v1(source: &str, owner: &str, expected_methods: &[&str]) {
    let surface = owner_surface_v1(source, owner);
    assert_eq!(
        surface.declaration_header, "pub",
        "attribute drift for {owner}"
    );
    assert!(
        !surface.fields.iter().any(|field| field
            .split(':')
            .next()
            .is_some_and(|prefix| prefix.contains("pub"))),
        "public field escaped for {owner}"
    );
    let methods: Vec<&str> = surface.methods.iter().map(String::as_str).collect();
    assert_eq!(methods, expected_methods, "public API drift for {owner}");
    assert!(
        surface.non_method_items.is_empty(),
        "public associated item escaped for {owner}"
    );
    assert!(
        surface.public_free_items.is_empty(),
        "public free item escaped for {owner}: {:?}",
        surface.public_free_items
    );
    assert!(
        !surface.trait_impl,
        "trait implementation escaped for {owner}"
    );
    assert!(!surface.alias, "type/use alias escaped for {owner}");
    assert!(!surface.macro_exposure, "macro surface escaped for {owner}");
}

#[cfg(test)]
fn assert_input_surface_v1(
    source: &str,
    owner: &str,
    expected_header: &str,
    expected_fields: &[&str],
) {
    let tokens = rust_surface_tokens_v1(source);
    let (header, fields) = struct_surface_v1(&tokens, owner);
    assert_eq!(header, expected_header, "input attribute drift for {owner}");
    let fields: Vec<&str> = fields.iter().map(String::as_str).collect();
    assert_eq!(fields, expected_fields, "input field drift for {owner}");
}

#[cfg(test)]
fn assert_production_wire_prefix_pin_v1(source: &str) {
    assert_eq!(source.len(), 165_033, "production wire prefix length drift");
    assert_eq!(
        sha256_v1(source.as_bytes()),
        [
            0x3f, 0xba, 0xa4, 0x6b, 0x86, 0x75, 0x2b, 0x15, 0xb8, 0x92, 0x81, 0xed, 0x7f, 0x6a,
            0x14, 0xf0, 0x26, 0x6f, 0x42, 0x42, 0xc9, 0x2e, 0xae, 0x44, 0x88, 0xf3, 0xfd, 0xd6,
            0x52, 0x99, 0xdc, 0x85,
        ],
        "production wire prefix digest drift"
    );
}

#[cfg(test)]
mod two_channel_transcript_v1 {
    use super::*;

    fn descriptor(seed: u64) -> DescriptorIdentityV1 {
        DescriptorIdentityV1::try_new(seed, seed + 1, seed + 2).unwrap()
    }

    fn credentials() -> PeerCredentialsV1 {
        PeerCredentialsV1::try_new(41, 1_000, 1_001, descriptor(700)).unwrap()
    }

    fn publication_root() -> FdCommitmentV1 {
        FdCommitmentV1::try_new(
            FdRoleV1::PublicationRoot,
            FdIdentityV1::Filesystem {
                descriptor: descriptor(10),
                node_kind: FilesystemNodeKindV1::Directory,
            },
            FdStatusV1::new(FdAccessV1::Path, false, true),
        )
        .unwrap()
    }

    fn session() -> ProviderSessionMaterialV1 {
        let ingress = SealedIngressManifestV1::try_new(&[]).unwrap();
        let publication =
            PublicationTargetCommitmentV1::try_new(&publication_root(), [0x61; 32], [0x62; 32])
                .unwrap();
        let role_blocks = ReplayRoleV2::ALL.map(|role| {
            let seed = replay_role_code(role) + 1;
            RequestRoleBlockV1::new(role, [seed; 32], [seed + 4; 32], [seed + 8; 32])
        });
        let request = RequestCommitmentV1::try_new(
            [0x31; 32],
            [0x32; 32],
            [0x33; 32],
            &ingress,
            &publication,
            &role_blocks,
        )
        .unwrap();
        let generator = SeqpacketEndpointCommitmentV1::from_observation(
            SeqpacketEndpointRoleV1::Generator,
            descriptor(100),
            200,
        );
        let supervisor_generator = SeqpacketEndpointCommitmentV1::from_observation(
            SeqpacketEndpointRoleV1::SupervisorGenerator,
            descriptor(110),
            210,
        );
        let supervisor_worker = SeqpacketEndpointCommitmentV1::from_observation(
            SeqpacketEndpointRoleV1::SupervisorWorker,
            descriptor(120),
            220,
        );
        let worker = SeqpacketEndpointCommitmentV1::from_observation(
            SeqpacketEndpointRoleV1::Worker,
            descriptor(130),
            230,
        );
        let generator_channel =
            ChannelIdentityV1::try_generator(&generator, &supervisor_generator).unwrap();
        let worker_channel = ChannelIdentityV1::try_worker(&supervisor_worker, &worker).unwrap();
        ProviderSessionMaterialV1::try_new(ProviderSessionInputV1 {
            request: &request,
            appliance_measurement: [0x41; 32],
            supervisor_measurement: [0x42; 32],
            generator_measurement: [0x43; 32],
            worker_measurement: [0x44; 32],
            generator_nonce: [0x51; 32],
            supervisor_nonce: [0x52; 32],
            supervisor_pid: 41,
            supervisor_start_epoch: 92,
            generator_channel: &generator_channel,
            worker_channel: &worker_channel,
        })
        .unwrap()
    }

    fn frame(
        direction: FrameDirectionV1,
        ordinal: u8,
        phase: AttemptPhaseV1,
        session_id: [u8; 32],
        previous_hash: [u8; 32],
        body_length: usize,
    ) -> WireFrameV1 {
        let body = vec![0x93; body_length];
        WireFrameV1::try_new(FrameInputV1 {
            direction,
            ordinal,
            phase,
            session_id,
            previous_hash,
            body: &body,
            credentials: credentials(),
            fd_commitments: &[],
            ancillary: AncillaryShapeV1::canonical(0),
        })
        .unwrap()
    }

    fn transcript_previous(preimage: &[u8]) -> [u8; 32] {
        let offset = 2 + TRANSCRIPT_DOMAIN_V1.len();
        preimage[offset..offset + 32].try_into().unwrap()
    }

    #[test]
    fn two_channel_transcript_v1_uses_internal_sha256_and_distinct_geneses() {
        let session = session();
        let binding = G0TranscriptSessionBindingV1::from_session(&session);
        let generator_genesis = binding.generator_genesis();
        let generator_frame = frame(
            FrameDirectionV1::GeneratorToSupervisor,
            0,
            AttemptPhaseV1::GeneratorBound,
            session.session_id(),
            generator_genesis,
            G0_GENERATOR_BOUND_BODY_BYTES_V1,
        );
        let generator_candidate =
            G0GeneratorBoundTranscriptCandidateV1::prepare(&session, &generator_frame).unwrap();
        assert_eq!(generator_candidate.transcript_bytes().len(), 426);
        assert_eq!(
            transcript_previous(generator_candidate.transcript_bytes()),
            generator_genesis
        );
        assert_eq!(generator_candidate.generator_genesis(), generator_genesis);
        assert_eq!(
            generator_candidate.digest(),
            sha256_v1(generator_candidate.transcript_bytes())
        );

        let worker_genesis = generator_candidate.worker_genesis();
        assert_eq!(
            worker_genesis,
            binding.worker_genesis(generator_candidate.digest())
        );
        assert_ne!(generator_genesis, worker_genesis);
        let worker_frame = frame(
            FrameDirectionV1::SupervisorToWorker,
            0,
            AttemptPhaseV1::UserMapsVerified,
            session.session_id(),
            worker_genesis,
            674 + 99,
        );
        let worker_candidate =
            G0TranscriptCandidateV1::prepare(&session, 0, worker_genesis, &worker_frame).unwrap();
        assert_eq!(
            transcript_previous(worker_candidate.transcript_bytes()),
            worker_genesis
        );
        assert_eq!(
            worker_candidate.digest(),
            sha256_v1(worker_candidate.transcript_bytes())
        );

        let wrong_worker_frame = frame(
            FrameDirectionV1::SupervisorToWorker,
            0,
            AttemptPhaseV1::UserMapsVerified,
            session.session_id(),
            generator_genesis,
            674 + 99,
        );
        assert!(matches!(
            G0TranscriptCandidateV1::prepare(&session, 0, worker_genesis, &wrong_worker_frame),
            Err(WireErrorV1::TranscriptPreviousHashMismatch)
        ));
    }

    #[test]
    fn two_channel_transcript_v1_candidates_are_pure_and_deterministic() {
        let session = session();
        let binding = G0TranscriptSessionBindingV1::from_session(&session);
        let generator_genesis = binding.generator_genesis();
        let generator_frame = frame(
            FrameDirectionV1::GeneratorToSupervisor,
            0,
            AttemptPhaseV1::GeneratorBound,
            session.session_id(),
            generator_genesis,
            G0_GENERATOR_BOUND_BODY_BYTES_V1,
        );
        let supervisor_candidate =
            G0GeneratorBoundTranscriptCandidateV1::prepare(&session, &generator_frame).unwrap();
        let peer_candidate =
            G0GeneratorBoundTranscriptCandidateV1::prepare(&session, &generator_frame).unwrap();
        assert_eq!(supervisor_candidate, peer_candidate);
        let generator_bound_digest = supervisor_candidate.digest();

        let worker_genesis = supervisor_candidate.worker_genesis();
        let worker_frame = frame(
            FrameDirectionV1::SupervisorToWorker,
            0,
            AttemptPhaseV1::UserMapsVerified,
            session.session_id(),
            worker_genesis,
            674 + 99,
        );
        let supervisor_worker =
            G0TranscriptCandidateV1::prepare(&session, 0, worker_genesis, &worker_frame).unwrap();
        let worker_peer =
            G0TranscriptCandidateV1::prepare(&session, 0, worker_genesis, &worker_frame).unwrap();
        assert_eq!(supervisor_worker, worker_peer);

        let generator_result = frame(
            FrameDirectionV1::SupervisorToGenerator,
            1,
            AttemptPhaseV1::Closed,
            session.session_id(),
            generator_bound_digest,
            G0_CLOSED_RESULT_BODY_BYTES_V1,
        );
        assert!(
            G0TranscriptCandidateV1::prepare(
                &session,
                1,
                generator_bound_digest,
                &generator_result
            )
            .is_ok()
        );
    }

    #[test]
    fn two_channel_transcript_v1_rejects_missing_cross_anchor_and_frame_drift() {
        let session = session();
        let binding = G0TranscriptSessionBindingV1::from_session(&session);
        let generator_genesis = binding.generator_genesis();
        let wrong_phase = frame(
            FrameDirectionV1::GeneratorToSupervisor,
            0,
            AttemptPhaseV1::UserMapsVerified,
            session.session_id(),
            generator_genesis,
            G0_GENERATOR_BOUND_BODY_BYTES_V1,
        );
        assert!(matches!(
            G0GeneratorBoundTranscriptCandidateV1::prepare(&session, &wrong_phase),
            Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::GeneratorBoundFrame
            ))
        ));

        let generator_frame = frame(
            FrameDirectionV1::GeneratorToSupervisor,
            0,
            AttemptPhaseV1::GeneratorBound,
            session.session_id(),
            generator_genesis,
            G0_GENERATOR_BOUND_BODY_BYTES_V1,
        );
        let generator_candidate =
            G0GeneratorBoundTranscriptCandidateV1::prepare(&session, &generator_frame).unwrap();
        let wrong_anchor = binding.worker_genesis([0; 32]);
        let worker_frame = frame(
            FrameDirectionV1::SupervisorToWorker,
            0,
            AttemptPhaseV1::UserMapsVerified,
            session.session_id(),
            wrong_anchor,
            674 + 99,
        );
        assert!(matches!(
            G0TranscriptCandidateV1::prepare(
                &session,
                0,
                generator_candidate.worker_genesis(),
                &worker_frame
            ),
            Err(WireErrorV1::TranscriptPreviousHashMismatch)
        ));
        assert_ne!(generator_candidate.digest(), [0; 32]);
    }

    #[test]
    fn two_channel_transcript_v1_has_no_public_acceptance_state_surface() {
        let source = production_wire_source_v1();
        let forbidden = [
            ["pub fn ac", "cept(self)"].concat(),
            ["pub fn start_", "worker("].concat(),
            ["pub struct AcceptedGenerator", "BoundJoinV1"].concat(),
            ["pub struct PendingGenerator", "BoundTranscriptV1"].concat(),
            ["pub struct SupervisorTwoChannel", "TranscriptsV1"].concat(),
            ["pub struct PendingTwoChannel", "TranscriptV1"].concat(),
            ["pub struct PeerChannel", "TranscriptV1"].concat(),
            ["pub struct PendingPeerChannel", "TranscriptV1"].concat(),
            ["G0Channel", "CursorV1"].concat(),
            ["G0AggregateFrame", "CountV1"].concat(),
        ];
        for symbol in forbidden {
            assert!(
                !source.contains(&symbol),
                "public acceptance-state surface remained: {symbol}"
            );
        }
    }
}

#[cfg(test)]
mod g0_session_contract_v1 {
    use super::*;

    fn descriptor(seed: u64) -> DescriptorIdentityV1 {
        DescriptorIdentityV1::try_new(seed, seed + 1, seed + 2).unwrap()
    }

    fn campaign_input(index: u8, close_on_exec: bool) -> FdCommitmentV1 {
        FdCommitmentV1::try_new(
            FdRoleV1::CampaignInput(index),
            FdIdentityV1::Memfd {
                size: 128 + u64::from(index),
                content_digest: [index.wrapping_add(1); 32],
                seals: MemfdSealsV1::new(
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                ),
            },
            FdStatusV1::new(FdAccessV1::ReadOnly, false, close_on_exec),
        )
        .unwrap()
    }

    fn worker_transfer_memfd(role: FdRoleV1, size: u64) -> FdCommitmentV1 {
        let (access, seals, nonempty_digest) = match role {
            FdRoleV1::Observation => (
                FdAccessV1::ReadWrite,
                MemfdSealsV1::new(
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                    SealPresenceV1::Absent,
                    SealPresenceV1::Absent,
                ),
                [0x91; 32],
            ),
            FdRoleV1::CampaignInput(_) => (
                FdAccessV1::ReadOnly,
                MemfdSealsV1::new(
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                ),
                [0x53; 32],
            ),
            _ => panic!("worker transfer helper received a non-memfd role"),
        };
        FdCommitmentV1::try_new(
            role,
            FdIdentityV1::Memfd {
                size,
                content_digest: if size == 0 {
                    sha256_v1(&[])
                } else {
                    nonempty_digest
                },
                seals,
            },
            FdStatusV1::new(access, false, true),
        )
        .unwrap()
    }

    fn publication_root(close_on_exec: bool) -> FdCommitmentV1 {
        FdCommitmentV1::try_new(
            FdRoleV1::PublicationRoot,
            FdIdentityV1::Filesystem {
                descriptor: descriptor(10),
                node_kind: FilesystemNodeKindV1::Directory,
            },
            FdStatusV1::new(FdAccessV1::Path, false, close_on_exec),
        )
        .unwrap()
    }

    fn endpoint_fd(role: FdRoleV1, digest: u8, close_on_exec: bool) -> FdCommitmentV1 {
        FdCommitmentV1::try_new(
            role,
            FdIdentityV1::Socket {
                endpoint_digest: [digest; 32],
            },
            FdStatusV1::new(FdAccessV1::Socket, false, close_on_exec),
        )
        .unwrap()
    }

    fn supervisor_pidfd(close_on_exec: bool) -> FdCommitmentV1 {
        FdCommitmentV1::try_new(
            FdRoleV1::SupervisorProcess,
            FdIdentityV1::Pidfd {
                process_id: 41,
                start_epoch: 92,
            },
            FdStatusV1::new(FdAccessV1::Process, false, close_on_exec),
        )
        .unwrap()
    }

    fn observation(close_on_exec: bool) -> FdCommitmentV1 {
        FdCommitmentV1::try_new(
            FdRoleV1::Observation,
            FdIdentityV1::Memfd {
                size: 256,
                content_digest: [0x91; 32],
                seals: MemfdSealsV1::new(
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                    SealPresenceV1::Absent,
                    SealPresenceV1::Absent,
                ),
            },
            FdStatusV1::new(FdAccessV1::ReadWrite, false, close_on_exec),
        )
        .unwrap()
    }

    fn final_result() -> FdCommitmentV1 {
        FdCommitmentV1::try_new(
            FdRoleV1::FinalResult,
            FdIdentityV1::Memfd {
                size: 512,
                content_digest: [0xa5; 32],
                seals: MemfdSealsV1::new(
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                ),
            },
            FdStatusV1::new(FdAccessV1::ReadOnly, false, true),
        )
        .unwrap()
    }

    fn role_blocks() -> [RequestRoleBlockV1; 4] {
        ReplayRoleV2::ALL.map(|role| {
            let seed = replay_role_code(role) + 1;
            RequestRoleBlockV1::new(role, [seed; 32], [seed + 4; 32], [seed + 8; 32])
        })
    }

    fn request_with_count(count: u8) -> (SealedIngressManifestV1, RequestCommitmentV1) {
        let ingress_commitments: Vec<_> = (0..count)
            .map(|index| campaign_input(index, true))
            .collect();
        let ingress = SealedIngressManifestV1::try_new(&ingress_commitments).unwrap();
        let publication =
            PublicationTargetCommitmentV1::try_new(&publication_root(true), [0x61; 32], [0x62; 32])
                .unwrap();
        let request = RequestCommitmentV1::try_new(
            [0x31; 32],
            [0x32; 32],
            [0x33; 32],
            &ingress,
            &publication,
            &role_blocks(),
        )
        .unwrap();
        (ingress, request)
    }

    fn endpoint(role: SeqpacketEndpointRoleV1, seed: u64) -> SeqpacketEndpointCommitmentV1 {
        SeqpacketEndpointCommitmentV1::from_observation(role, descriptor(seed), seed + 100)
    }

    fn session_with_endpoints(
        request: &RequestCommitmentV1,
    ) -> (
        ProviderSessionMaterialV1,
        SeqpacketEndpointCommitmentV1,
        SeqpacketEndpointCommitmentV1,
        SeqpacketEndpointCommitmentV1,
        SeqpacketEndpointCommitmentV1,
    ) {
        let generator = endpoint(SeqpacketEndpointRoleV1::Generator, 100);
        let supervisor_generator = endpoint(SeqpacketEndpointRoleV1::SupervisorGenerator, 110);
        let supervisor_worker = endpoint(SeqpacketEndpointRoleV1::SupervisorWorker, 120);
        let worker = endpoint(SeqpacketEndpointRoleV1::Worker, 130);
        let generator_channel =
            ChannelIdentityV1::try_generator(&generator, &supervisor_generator).unwrap();
        let worker_channel = ChannelIdentityV1::try_worker(&supervisor_worker, &worker).unwrap();
        let session = ProviderSessionMaterialV1::try_new(ProviderSessionInputV1 {
            request,
            appliance_measurement: [0x41; 32],
            supervisor_measurement: [0x42; 32],
            generator_measurement: [0x43; 32],
            worker_measurement: [0x44; 32],
            generator_nonce: [0x51; 32],
            supervisor_nonce: [0x52; 32],
            supervisor_pid: 41,
            supervisor_start_epoch: 92,
            generator_channel: &generator_channel,
            worker_channel: &worker_channel,
        })
        .unwrap();
        (
            session,
            generator,
            supervisor_generator,
            supervisor_worker,
            worker,
        )
    }

    fn session(request: &RequestCommitmentV1) -> ProviderSessionMaterialV1 {
        session_with_endpoints(request).0
    }

    fn generator_inventory(count: u8) -> ProcessInventoryV1 {
        let mut entries = vec![
            ProcessInventoryEntryV1::new(3, endpoint_fd(FdRoleV1::GeneratorEndpoint, 0x71, false)),
            ProcessInventoryEntryV1::new(4, supervisor_pidfd(false)),
            ProcessInventoryEntryV1::new(5, publication_root(false)),
        ];
        entries
            .extend((0..count).map(|index| {
                ProcessInventoryEntryV1::new(6 + index, campaign_input(index, false))
            }));
        ProcessInventoryV1::try_new(ProcessInventoryKindV1::GeneratorPostExec, &entries).unwrap()
    }

    fn worker_initial_inventory() -> ProcessInventoryV1 {
        ProcessInventoryV1::try_new(
            ProcessInventoryKindV1::WorkerInitialPostExec,
            &[ProcessInventoryEntryV1::new(
                3,
                endpoint_fd(FdRoleV1::WorkerEndpoint, 0x72, false),
            )],
        )
        .unwrap()
    }

    fn worker_transfer_inventory(count: u8) -> ProcessInventoryV1 {
        let mut entries = vec![
            ProcessInventoryEntryV1::new(3, endpoint_fd(FdRoleV1::WorkerEndpoint, 0x72, true)),
            ProcessInventoryEntryV1::new(4, observation(true)),
        ];
        entries.extend(
            (0..count)
                .map(|index| ProcessInventoryEntryV1::new(5 + index, campaign_input(index, true))),
        );
        ProcessInventoryV1::try_new(ProcessInventoryKindV1::WorkerExpectedPostTransfer, &entries)
            .unwrap()
    }

    fn worker_manifest(count: u8) -> WorkerTransferManifestV1 {
        let campaigns: Vec<_> = (0..count)
            .map(|index| campaign_input(index, true))
            .collect();
        WorkerTransferManifestV1::try_new(&observation(true), &campaigns).unwrap()
    }

    fn credentials() -> PeerCredentialsV1 {
        PeerCredentialsV1::try_new(41, 1_000, 1_001, descriptor(700)).unwrap()
    }

    fn zero_fd_frame(
        direction: FrameDirectionV1,
        ordinal: u8,
        phase: AttemptPhaseV1,
        session_id: [u8; 32],
        previous_hash: [u8; 32],
        body: &[u8],
    ) -> WireFrameV1 {
        WireFrameV1::try_new(FrameInputV1 {
            direction,
            ordinal,
            phase,
            session_id,
            previous_hash,
            body,
            credentials: credentials(),
            fd_commitments: &[],
            ancillary: AncillaryShapeV1::canonical(0),
        })
        .unwrap()
    }

    fn test_nonce_commitment(role: u8, request_digest: [u8; 32], nonce: [u8; 32]) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(99);
        bytes.extend_from_slice(b"eip0045-b4-h0-nonce-commitment-v1\0");
        bytes.push(role);
        bytes.extend_from_slice(&request_digest);
        bytes.extend_from_slice(&nonce);
        assert_eq!(bytes.len(), 99);
        sha256_v1(&bytes)
    }

    fn test_pre_session_record(kind: u8, request_digest: [u8; 32], nonce: [u8; 32]) -> [u8; 75] {
        let payload = match kind {
            0 => test_nonce_commitment(0, request_digest, nonce),
            1 => test_nonce_commitment(1, request_digest, nonce),
            2 | 3 => nonce,
            _ => panic!("test record kind outside the closed set"),
        };
        let mut bytes = Vec::with_capacity(75);
        bytes.extend_from_slice(b"EIP45H0N");
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.push(kind);
        bytes.extend_from_slice(&request_digest);
        bytes.extend_from_slice(&payload);
        bytes.try_into().unwrap()
    }

    struct TestPeerFixture {
        ingress: SealedIngressManifestV1,
        facts: G0GeneratorPeerLocalFactsV1,
        generator_endpoint: SeqpacketEndpointCommitmentV1,
        session_offer_raw: [u8; G0_SESSION_OFFER_BYTES_V1],
        generator_commit_raw: [u8; G0_PRE_SESSION_RECORD_BYTES_V1],
        supervisor_commit_raw: [u8; G0_PRE_SESSION_RECORD_BYTES_V1],
        generator_reveal_raw: [u8; G0_PRE_SESSION_RECORD_BYTES_V1],
        supervisor_reveal_raw: [u8; G0_PRE_SESSION_RECORD_BYTES_V1],
    }

    impl TestPeerFixture {
        fn input(&self) -> G0GeneratorPeerSessionInputV1<'_> {
            G0GeneratorPeerSessionInputV1 {
                session_offer_raw: &self.session_offer_raw,
                generator_commit_raw: &self.generator_commit_raw,
                supervisor_commit_raw: &self.supervisor_commit_raw,
                generator_reveal_raw: &self.generator_reveal_raw,
                supervisor_reveal_raw: &self.supervisor_reveal_raw,
                local_facts: &self.facts,
                local_generator_endpoint: &self.generator_endpoint,
            }
        }

        fn candidate(&self) -> G0GeneratorPeerSessionCandidateV1 {
            G0GeneratorPeerSessionCandidateV1::try_new(self.input()).unwrap()
        }
    }

    fn test_peer_fixture() -> TestPeerFixture {
        let (ingress, request) = request_with_count(2);
        let generator_endpoint = endpoint(SeqpacketEndpointRoleV1::Generator, 100);
        let supervisor_generator = endpoint(SeqpacketEndpointRoleV1::SupervisorGenerator, 110);
        let supervisor_worker = endpoint(SeqpacketEndpointRoleV1::SupervisorWorker, 120);
        let worker_endpoint = endpoint(SeqpacketEndpointRoleV1::Worker, 130);
        let generator_channel =
            ChannelIdentityV1::try_generator(&generator_endpoint, &supervisor_generator).unwrap();
        let worker_channel =
            ChannelIdentityV1::try_worker(&supervisor_worker, &worker_endpoint).unwrap();

        let mut offer = Vec::with_capacity(G0_SESSION_OFFER_BYTES_V1);
        offer.extend_from_slice(&31_u16.to_le_bytes());
        offer.extend_from_slice(b"eip0045-b4-h0-session-offer-v1\0");
        offer.extend_from_slice(&1_u16.to_le_bytes());
        offer.extend_from_slice(&772_u16.to_le_bytes());
        offer.extend_from_slice(request.preimage());
        offer.extend_from_slice(&request.digest());
        offer.extend_from_slice(&[0x41; 32]);
        offer.extend_from_slice(&[0x42; 32]);
        offer.extend_from_slice(&[0x43; 32]);
        offer.extend_from_slice(&[0x44; 32]);
        offer.extend_from_slice(&41_u32.to_le_bytes());
        offer.extend_from_slice(&92_u64.to_le_bytes());
        offer.extend_from_slice(&generator_channel.digest);
        offer.extend_from_slice(&worker_channel.digest);
        offer.extend_from_slice(&supervisor_generator.digest);
        descriptor(700).encode_into(&mut offer);
        let session_offer_raw = offer.try_into().unwrap();
        let request_digest = request.digest();
        let generator_nonce = [0x51; 32];
        let supervisor_nonce = [0x52; 32];
        let generator_commit_raw = test_pre_session_record(0, request_digest, generator_nonce);
        let supervisor_commit_raw = test_pre_session_record(1, request_digest, supervisor_nonce);
        let generator_reveal_raw = test_pre_session_record(2, request_digest, generator_nonce);
        let supervisor_reveal_raw = test_pre_session_record(3, request_digest, supervisor_nonce);
        let facts = G0GeneratorPeerLocalFactsV1::try_new(
            request,
            [0x41; 32],
            [0x42; 32],
            [0x43; 32],
            [0x44; 32],
            generator_nonce,
        )
        .unwrap();
        TestPeerFixture {
            ingress,
            facts,
            generator_endpoint,
            session_offer_raw,
            generator_commit_raw,
            supervisor_commit_raw,
            generator_reveal_raw,
            supervisor_reveal_raw,
        }
    }

    fn test_generator_seal() -> GeneratorSealProfileV1 {
        GeneratorSealProfileV1::try_new(&[SockFilterInstructionV1::new(0x06, 0, 0, 0x7fff_0000)])
            .unwrap()
    }

    fn test_generator_genesis(session: &ProviderSessionMaterialV1) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(203);
        bytes.extend_from_slice(b"eip0045-b4-h0-generator-channel-genesis-v1\0");
        bytes.extend_from_slice(&session.session_id);
        bytes.extend_from_slice(&session.request_commitment);
        bytes.extend_from_slice(&session.generator_nonce_commitment);
        bytes.extend_from_slice(&session.supervisor_nonce_commitment);
        bytes.extend_from_slice(&session.generator_channel);
        assert_eq!(bytes.len(), 203);
        sha256_v1(&bytes)
    }

    fn test_worker_genesis(
        session: &ProviderSessionMaterialV1,
        accepted_generator_bound_digest: [u8; 32],
    ) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(232);
        bytes.extend_from_slice(b"eip0045-b4-h0-worker-channel-genesis-v1\0");
        bytes.extend_from_slice(&session.session_id);
        bytes.extend_from_slice(&session.request_commitment);
        bytes.extend_from_slice(&session.generator_nonce_commitment);
        bytes.extend_from_slice(&session.supervisor_nonce_commitment);
        bytes.extend_from_slice(&accepted_generator_bound_digest);
        bytes.extend_from_slice(&session.worker_channel);
        assert_eq!(bytes.len(), 232);
        sha256_v1(&bytes)
    }

    fn test_zero_fd_raw(
        direction: u8,
        ordinal: u8,
        phase: u8,
        session_id: [u8; 32],
        previous_hash: [u8; 32],
        body: &[u8],
    ) -> Vec<u8> {
        let mut raw = Vec::with_capacity(82 + body.len());
        raw.extend_from_slice(b"EIP45H0F");
        raw.extend_from_slice(&1_u16.to_le_bytes());
        raw.push(direction);
        raw.push(ordinal);
        raw.push(phase);
        raw.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
        raw.extend_from_slice(&session_id);
        raw.extend_from_slice(&previous_hash);
        raw.push(0);
        raw.extend_from_slice(body);
        raw
    }

    fn test_transcript(
        raw: &[u8],
        previous_hash: [u8; 32],
        direction: u8,
        phase: u8,
        credentials: PeerCredentialsV1,
        commitments: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&33_u16.to_le_bytes());
        bytes.extend_from_slice(b"eip0045-b4-h0-frame-transcript-v1");
        bytes.extend_from_slice(&previous_hash);
        bytes.push(direction);
        bytes.push(phase);
        bytes.extend_from_slice(&u32::try_from(raw.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(raw);
        bytes.extend_from_slice(&credentials.process_id.to_le_bytes());
        bytes.extend_from_slice(&credentials.user_id.to_le_bytes());
        bytes.extend_from_slice(&credentials.group_id.to_le_bytes());
        credentials.user_namespace.encode_into(&mut bytes);
        bytes.push(u8::try_from(commitments.len()).unwrap());
        for commitment in commitments {
            bytes.extend_from_slice(&u16::try_from(commitment.len()).unwrap().to_le_bytes());
            bytes.extend_from_slice(commitment);
        }
        bytes
    }

    fn test_memfd_bytes(
        role: FdRoleV1,
        size: u64,
        digest: [u8; 32],
        seals: [u8; 4],
        access: u8,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        match role {
            FdRoleV1::Observation => bytes.push(8),
            FdRoleV1::FinalResult => bytes.push(9),
            FdRoleV1::CampaignInput(index) => {
                bytes.push(0);
                bytes.push(index);
            }
            _ => panic!("test helper accepts only memfd roles"),
        }
        bytes.push(2);
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(&digest);
        bytes.extend_from_slice(&seals);
        bytes.push(access);
        bytes.push(0);
        bytes.push(1);
        bytes
    }

    fn test_socket_bytes(endpoint_digest: [u8; 32], close_on_exec: bool) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(37);
        bytes.push(4);
        bytes.push(4);
        bytes.extend_from_slice(&endpoint_digest);
        bytes.push(5);
        bytes.push(0);
        bytes.push(u8::from(close_on_exec));
        bytes
    }

    fn test_inventory_digest(kind: u8, entries: &[(u8, Vec<u8>)]) -> [u8; 32] {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&35_u16.to_le_bytes());
        bytes.extend_from_slice(b"eip0045-b4-h0-process-inventory-v1\0");
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.push(kind);
        bytes.extend_from_slice(&u16::try_from(entries.len()).unwrap().to_le_bytes());
        for (fd, commitment) in entries {
            bytes.push(*fd);
            bytes.extend_from_slice(&u16::try_from(commitment.len()).unwrap().to_le_bytes());
            bytes.extend_from_slice(commitment);
        }
        sha256_v1(&bytes)
    }

    fn test_final_result_commitment(
        bytes: &[u8],
        digest_override: Option<[u8; 32]>,
    ) -> FdCommitmentV1 {
        FdCommitmentV1::try_new(
            FdRoleV1::FinalResult,
            FdIdentityV1::Memfd {
                size: u64::try_from(bytes.len()).unwrap(),
                content_digest: digest_override.unwrap_or_else(|| sha256_v1(bytes)),
                seals: MemfdSealsV1::new(
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                ),
            },
            FdStatusV1::new(FdAccessV1::ReadOnly, false, true),
        )
        .unwrap()
    }

    fn test_closed_raw(
        session: &ProviderSessionMaterialV1,
        generator_bound_digest: [u8; 32],
        terminal_worker_digest: [u8; 32],
        content_digest: [u8; 32],
    ) -> [u8; G0_CLOSED_RESULT_RAW_FRAME_BYTES_V1] {
        let mut body = Vec::with_capacity(136);
        body.extend_from_slice(&36_u16.to_le_bytes());
        body.extend_from_slice(b"eip0045-b4-h0-closed-result-body-v1\0");
        body.extend_from_slice(&1_u16.to_le_bytes());
        body.extend_from_slice(&session.request_commitment);
        body.extend_from_slice(&terminal_worker_digest);
        body.extend_from_slice(&content_digest);
        assert_eq!(body.len(), 136);
        let mut raw = Vec::with_capacity(219);
        raw.extend_from_slice(b"EIP45H0F");
        raw.extend_from_slice(&1_u16.to_le_bytes());
        raw.push(1);
        raw.push(1);
        raw.push(21);
        raw.extend_from_slice(&136_u32.to_le_bytes());
        raw.extend_from_slice(&session.session_id);
        raw.extend_from_slice(&generator_bound_digest);
        raw.push(1);
        raw.push(9);
        raw.extend_from_slice(&body);
        raw.try_into().unwrap()
    }

    struct TestWorkerFixture {
        raw: Vec<u8>,
        credentials: PeerCredentialsV1,
        worker_endpoint: SeqpacketEndpointCommitmentV1,
        campaign_contents: Vec<Vec<u8>>,
        expected_bootstrap_digest: [u8; 32],
    }

    impl TestWorkerFixture {
        fn input(&self) -> G0WorkerBootstrapInboundInputV1<'_> {
            G0WorkerBootstrapInboundInputV1 {
                received_raw_frame: &self.raw,
                actual_rights_count: self.campaign_contents.len() + 1,
                observed_credentials: self.credentials,
                local_worker_endpoint: &self.worker_endpoint,
                expected_outer_uid: 20_002,
                expected_outer_gid: 20_002,
            }
        }

        fn candidate(&self) -> G0WorkerBootstrapInboundCandidateV1 {
            G0WorkerBootstrapInboundCandidateV1::try_new(self.input()).unwrap()
        }
    }

    #[allow(clippy::too_many_lines)]
    fn test_worker_fixture(
        observation_content: &[u8],
        campaign_contents: Vec<Vec<u8>>,
        corrupt_first_campaign_digest: bool,
    ) -> TestWorkerFixture {
        let count = u8::try_from(campaign_contents.len()).unwrap();
        let (_, request) = request_with_count(count);
        let (session, _, _, supervisor_worker, worker_endpoint) = session_with_endpoints(&request);
        let observation_digest = sha256_v1(observation_content);
        let observation_bytes = test_memfd_bytes(
            FdRoleV1::Observation,
            u64::try_from(observation_content.len()).unwrap(),
            observation_digest,
            [1, 1, 0, 0],
            3,
        );
        let campaign_bytes: Vec<Vec<u8>> = campaign_contents
            .iter()
            .enumerate()
            .map(|(index, content)| {
                let digest = if corrupt_first_campaign_digest && index == 0 {
                    [0xee; 32]
                } else {
                    sha256_v1(content)
                };
                test_memfd_bytes(
                    FdRoleV1::CampaignInput(u8::try_from(index).unwrap()),
                    u64::try_from(content.len()).unwrap(),
                    digest,
                    [1, 1, 1, 1],
                    1,
                )
            })
            .collect();
        let mut manifest = Vec::new();
        manifest.extend_from_slice(&42_u16.to_le_bytes());
        manifest.extend_from_slice(b"eip0045-b4-h0-worker-transfer-manifest-v1\0");
        manifest.extend_from_slice(&1_u16.to_le_bytes());
        manifest.push(count + 1);
        manifest.push(4);
        manifest.extend_from_slice(&49_u16.to_le_bytes());
        manifest.extend_from_slice(&observation_bytes);
        for (index, commitment) in campaign_bytes.iter().enumerate() {
            manifest.push(u8::try_from(5 + index).unwrap());
            manifest.extend_from_slice(&50_u16.to_le_bytes());
            manifest.extend_from_slice(commitment);
        }
        assert_eq!(manifest.len(), 99 + 53 * usize::from(count));
        let manifest_digest = sha256_v1(&manifest);
        let endpoint_initial = test_socket_bytes(worker_endpoint.digest, false);
        let endpoint_transfer = test_socket_bytes(worker_endpoint.digest, true);
        let initial_inventory_digest = test_inventory_digest(1, &[(3, endpoint_initial)]);
        let mut transfer_entries = vec![(3, endpoint_transfer), (4, observation_bytes.clone())];
        transfer_entries.extend(
            campaign_bytes
                .iter()
                .cloned()
                .enumerate()
                .map(|(index, commitment)| (u8::try_from(5 + index).unwrap(), commitment)),
        );
        let transfer_inventory_digest = test_inventory_digest(2, &transfer_entries);
        let accepted_generator_bound_digest = [0xd1; 32];
        let mut body = Vec::new();
        body.extend_from_slice(&39_u16.to_le_bytes());
        body.extend_from_slice(b"eip0045-b4-h0-worker-bootstrap-body-v1\0");
        body.extend_from_slice(&1_u16.to_le_bytes());
        body.extend_from_slice(&accepted_generator_bound_digest);
        body.extend_from_slice(&session.preimage);
        body.extend_from_slice(&session.generator_nonce_commitment);
        body.extend_from_slice(&session.supervisor_nonce_commitment);
        body.extend_from_slice(&supervisor_worker.digest);
        descriptor(700).encode_into(&mut body);
        body.extend_from_slice(&20_002_u32.to_le_bytes());
        body.extend_from_slice(&20_002_u32.to_le_bytes());
        body.extend_from_slice(&initial_inventory_digest);
        body.extend_from_slice(&transfer_inventory_digest);
        body.extend_from_slice(&u16::try_from(manifest.len()).unwrap().to_le_bytes());
        body.extend_from_slice(&manifest);
        body.extend_from_slice(&manifest_digest);
        assert_eq!(body.len(), 773 + 53 * usize::from(count));
        let worker_genesis = test_worker_genesis(&session, accepted_generator_bound_digest);
        let mut raw = Vec::new();
        raw.extend_from_slice(b"EIP45H0F");
        raw.extend_from_slice(&1_u16.to_le_bytes());
        raw.push(2);
        raw.push(0);
        raw.push(5);
        raw.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
        raw.extend_from_slice(&session.session_id);
        raw.extend_from_slice(&worker_genesis);
        raw.push(count + 1);
        raw.push(8);
        for index in 0..count {
            raw.push(0);
            raw.push(index);
        }
        raw.extend_from_slice(&body);
        assert_eq!(raw.len(), 856 + 55 * usize::from(count));
        let credentials = PeerCredentialsV1::try_new(41, 0, 0, descriptor(701)).unwrap();
        let mut transcript_commitments = vec![observation_bytes];
        transcript_commitments.extend(campaign_bytes);
        let expected_bootstrap_digest = sha256_v1(&test_transcript(
            &raw,
            worker_genesis,
            2,
            5,
            credentials,
            &transcript_commitments,
        ));
        TestWorkerFixture {
            raw,
            credentials,
            worker_endpoint,
            campaign_contents,
            expected_bootstrap_digest,
        }
    }

    #[test]
    fn outbound_zero_fd_entry_frames_v1() {
        let (ingress, request) = request_with_count(2);
        let session = session(&request);
        let generator_inventory = generator_inventory(2);
        let worker_initial = worker_initial_inventory();
        let worker_transfer = worker_transfer_inventory(2);
        let manifest = worker_manifest(2);
        let seal = GeneratorSealProfileV1::try_new(&[SockFilterInstructionV1::new(
            0x06,
            0,
            0,
            0x7fff_0000,
        )])
        .unwrap();
        let generator_body =
            GeneratorBoundBodyV1::try_new(&session, &seal, &generator_inventory, &ingress).unwrap();
        let worker_body =
            WorkerExecBoundBodyV1::try_new(&session, &worker_initial, &worker_transfer, &manifest)
                .unwrap();

        let generator_raw = encode_generator_bound_raw_frame_v1(&session, &generator_body).unwrap();
        let worker_bootstrap_digest = TranscriptDigestV1::from_bytes([0x84; 32]);
        let worker_raw =
            encode_worker_exec_bound_raw_frame_v1(&session, worker_bootstrap_digest, &worker_body)
                .unwrap();
        assert_eq!(generator_raw.len(), G0_GENERATOR_BOUND_RAW_FRAME_BYTES_V1);
        assert_eq!(worker_raw.len(), G0_WORKER_EXEC_BOUND_RAW_FRAME_BYTES_V1);

        let generator_genesis =
            G0TranscriptSessionBindingV1::from_session(&session).generator_genesis();
        let mut expected_generator = Vec::with_capacity(316);
        expected_generator.extend_from_slice(b"EIP45H0F");
        expected_generator.extend_from_slice(&1_u16.to_le_bytes());
        expected_generator.push(0);
        expected_generator.push(0);
        expected_generator.push(AttemptPhaseV1::GeneratorBound.wire_code());
        expected_generator.extend_from_slice(&234_u32.to_le_bytes());
        expected_generator.extend_from_slice(&session.session_id());
        expected_generator.extend_from_slice(&generator_genesis);
        expected_generator.push(0);
        expected_generator.extend_from_slice(generator_body.bytes());
        assert_eq!(generator_raw.as_slice(), expected_generator);

        let mut expected_worker = Vec::with_capacity(318);
        expected_worker.extend_from_slice(b"EIP45H0F");
        expected_worker.extend_from_slice(&1_u16.to_le_bytes());
        expected_worker.push(3);
        expected_worker.push(1);
        expected_worker.push(AttemptPhaseV1::WorkerExecBound.wire_code());
        expected_worker.extend_from_slice(&236_u32.to_le_bytes());
        expected_worker.extend_from_slice(&session.session_id());
        expected_worker.extend_from_slice(&[0x84; 32]);
        expected_worker.push(0);
        expected_worker.extend_from_slice(worker_body.bytes());
        assert_eq!(worker_raw.as_slice(), expected_worker);

        assert_eq!(&generator_raw[0..8], &FRAME_MAGIC_V1);
        assert_eq!(&generator_raw[8..10], &FRAME_VERSION_V1.to_le_bytes());
        assert_eq!(generator_raw[10], 0);
        assert_eq!(generator_raw[11], 0);
        assert_eq!(
            generator_raw[12],
            AttemptPhaseV1::GeneratorBound.wire_code()
        );
        assert_eq!(&generator_raw[13..17], &234_u32.to_le_bytes());
        assert_eq!(&generator_raw[17..49], &session.session_id());
        assert_eq!(&generator_raw[49..81], &generator_genesis);
        assert_eq!(generator_raw[81], 0);
        assert_eq!(&generator_raw[82..], generator_body.bytes());
        assert_eq!(&worker_raw[0..8], &FRAME_MAGIC_V1);
        assert_eq!(&worker_raw[8..10], &FRAME_VERSION_V1.to_le_bytes());
        assert_eq!(worker_raw[10], 3);
        assert_eq!(worker_raw[11], 1);
        assert_eq!(worker_raw[12], AttemptPhaseV1::WorkerExecBound.wire_code());
        assert_eq!(&worker_raw[13..17], &236_u32.to_le_bytes());
        assert_eq!(&worker_raw[17..49], &session.session_id());
        assert_eq!(&worker_raw[49..81], &[0x84; 32]);
        assert_eq!(worker_raw[81], 0);
        assert_eq!(&worker_raw[82..], worker_body.bytes());

        let historical_generator = zero_fd_frame(
            FrameDirectionV1::GeneratorToSupervisor,
            0,
            AttemptPhaseV1::GeneratorBound,
            session.session_id(),
            generator_genesis,
            generator_body.bytes(),
        );
        let historical_worker = zero_fd_frame(
            FrameDirectionV1::WorkerToSupervisor,
            1,
            AttemptPhaseV1::WorkerExecBound,
            session.session_id(),
            [0x84; 32],
            worker_body.bytes(),
        );
        assert_eq!(
            historical_generator.encode_raw_frame().unwrap(),
            generator_raw
        );
        assert_eq!(historical_worker.encode_raw_frame().unwrap(), worker_raw);
    }

    #[test]
    fn c3c_entry_frame_header_and_fd_mutants_v1() {
        let (ingress, request) = request_with_count(2);
        let session = session(&request);
        let generator_inventory = generator_inventory(2);
        let seal = GeneratorSealProfileV1::try_new(&[SockFilterInstructionV1::new(
            0x06,
            0,
            0,
            0x7fff_0000,
        )])
        .unwrap();
        let generator_body =
            GeneratorBoundBodyV1::try_new(&session, &seal, &generator_inventory, &ingress).unwrap();
        let generator_genesis =
            G0TranscriptSessionBindingV1::from_session(&session).generator_genesis();
        let generator_raw = encode_generator_bound_raw_frame_v1(&session, &generator_body).unwrap();
        for mutated in [
            zero_fd_frame(
                FrameDirectionV1::WorkerToSupervisor,
                0,
                AttemptPhaseV1::GeneratorBound,
                session.session_id(),
                generator_genesis,
                generator_body.bytes(),
            ),
            zero_fd_frame(
                FrameDirectionV1::GeneratorToSupervisor,
                1,
                AttemptPhaseV1::GeneratorBound,
                session.session_id(),
                generator_genesis,
                generator_body.bytes(),
            ),
            zero_fd_frame(
                FrameDirectionV1::GeneratorToSupervisor,
                0,
                AttemptPhaseV1::WorkerExecBound,
                session.session_id(),
                generator_genesis,
                generator_body.bytes(),
            ),
            zero_fd_frame(
                FrameDirectionV1::GeneratorToSupervisor,
                0,
                AttemptPhaseV1::GeneratorBound,
                session.session_id(),
                [0x85; 32],
                generator_body.bytes(),
            ),
        ] {
            assert_ne!(mutated.encode_raw_frame().unwrap(), generator_raw);
            assert!(G0GeneratorBoundTranscriptCandidateV1::prepare(&session, &mutated).is_err());
        }

        let injected_fd = [endpoint_fd(FdRoleV1::GeneratorEndpoint, 0x71, false)];
        let injected_fd_frame = WireFrameV1::try_new(FrameInputV1 {
            direction: FrameDirectionV1::GeneratorToSupervisor,
            ordinal: 0,
            phase: AttemptPhaseV1::GeneratorBound,
            session_id: session.session_id(),
            previous_hash: generator_genesis,
            body: generator_body.bytes(),
            credentials: credentials(),
            fd_commitments: &injected_fd,
            ancillary: AncillaryShapeV1::canonical(1),
        })
        .unwrap();
        assert_ne!(injected_fd_frame.encode_raw_frame().unwrap(), generator_raw);
        assert_eq!(
            G0GeneratorBoundTranscriptCandidateV1::prepare(&session, &injected_fd_frame),
            Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::GeneratorBoundFrame
            ))
        );
    }

    #[test]
    fn c3c_entry_frame_body_session_join_mutants_v1() {
        let (ingress, request) = request_with_count(2);
        let (_, other_request) = request_with_count(1);
        let other_session = session(&other_request);
        let session = session(&request);
        let generator_inventory = generator_inventory(2);
        let worker_initial = worker_initial_inventory();
        let worker_transfer = worker_transfer_inventory(2);
        let manifest = worker_manifest(2);
        let seal = GeneratorSealProfileV1::try_new(&[SockFilterInstructionV1::new(
            0x06,
            0,
            0,
            0x7fff_0000,
        )])
        .unwrap();
        let generator_body =
            GeneratorBoundBodyV1::try_new(&session, &seal, &generator_inventory, &ingress).unwrap();
        let worker_body =
            WorkerExecBoundBodyV1::try_new(&session, &worker_initial, &worker_transfer, &manifest)
                .unwrap();
        let worker_bootstrap_digest = TranscriptDigestV1::from_bytes([0x84; 32]);
        assert_eq!(
            encode_generator_bound_raw_frame_v1(&other_session, &generator_body),
            Err(WireErrorV1::ExpectationDrift(FrameFieldV1::Body))
        );
        assert_eq!(
            encode_worker_exec_bound_raw_frame_v1(
                &other_session,
                worker_bootstrap_digest,
                &worker_body
            ),
            Err(WireErrorV1::ExpectationDrift(FrameFieldV1::Body))
        );

        for offset in [42, 74, 106] {
            let mut bytes = *generator_body.bytes();
            bytes[offset] ^= 1;
            let mismatched = GeneratorBoundBodyV1 { bytes };
            assert_eq!(
                encode_generator_bound_raw_frame_v1(&session, &mismatched),
                Err(WireErrorV1::ExpectationDrift(FrameFieldV1::Body))
            );
        }
        for offset in [44, 76, 108] {
            let mut bytes = *worker_body.bytes();
            bytes[offset] ^= 1;
            let mismatched = WorkerExecBoundBodyV1 { bytes };
            assert_eq!(
                encode_worker_exec_bound_raw_frame_v1(
                    &session,
                    worker_bootstrap_digest,
                    &mismatched
                ),
                Err(WireErrorV1::ExpectationDrift(FrameFieldV1::Body))
            );
        }
    }

    #[test]
    fn child_channel_identity_from_local_endpoint_v1() {
        let (_, request) = request_with_count(2);
        let (session, generator, supervisor_generator, supervisor_worker, worker) =
            session_with_endpoints(&request);

        let child_generator = ChannelIdentityV1::try_generator_child(
            &generator,
            supervisor_generator.digest(),
            &session,
        )
        .unwrap();
        let child_worker =
            ChannelIdentityV1::try_worker_child(&worker, supervisor_worker.digest(), &session)
                .unwrap();
        assert_eq!(
            child_generator.digest(),
            ChannelIdentityV1::try_generator(&generator, &supervisor_generator)
                .unwrap()
                .digest()
        );
        assert_eq!(
            child_worker.digest(),
            ChannelIdentityV1::try_worker(&supervisor_worker, &worker)
                .unwrap()
                .digest()
        );

        assert_eq!(
            ChannelIdentityV1::try_generator_child(
                &supervisor_generator,
                generator.digest(),
                &session
            ),
            Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::EndpointPair
            ))
        );
        assert_eq!(
            ChannelIdentityV1::try_worker_child(&supervisor_worker, worker.digest(), &session),
            Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::EndpointPair
            ))
        );
        assert_eq!(
            ChannelIdentityV1::try_generator_child(
                &generator,
                supervisor_worker.digest(),
                &session
            ),
            Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::EndpointPair
            ))
        );

        let alternate_generator = endpoint(SeqpacketEndpointRoleV1::Generator, 500);
        let alternate_supervisor_generator =
            endpoint(SeqpacketEndpointRoleV1::SupervisorGenerator, 510);
        let alternate_supervisor_worker = endpoint(SeqpacketEndpointRoleV1::SupervisorWorker, 520);
        let alternate_worker = endpoint(SeqpacketEndpointRoleV1::Worker, 530);
        let alternate_generator_channel =
            ChannelIdentityV1::try_generator(&alternate_generator, &alternate_supervisor_generator)
                .unwrap();
        let alternate_worker_channel =
            ChannelIdentityV1::try_worker(&alternate_supervisor_worker, &alternate_worker).unwrap();
        let alternate_session = ProviderSessionMaterialV1::try_new(ProviderSessionInputV1 {
            request: &request,
            appliance_measurement: [0x41; 32],
            supervisor_measurement: [0x42; 32],
            generator_measurement: [0x43; 32],
            worker_measurement: [0x44; 32],
            generator_nonce: [0x51; 32],
            supervisor_nonce: [0x52; 32],
            supervisor_pid: 41,
            supervisor_start_epoch: 92,
            generator_channel: &alternate_generator_channel,
            worker_channel: &alternate_worker_channel,
        })
        .unwrap();
        assert!(
            ChannelIdentityV1::try_generator_child(
                &generator,
                supervisor_generator.digest(),
                &alternate_session
            )
            .is_err()
        );
        assert!(
            ChannelIdentityV1::try_worker_child(
                &worker,
                supervisor_worker.digest(),
                &alternate_session
            )
            .is_err()
        );
    }

    #[test]
    fn outbound_entry_frame_surface_is_closed_v1() {
        let source = production_wire_source_v1();
        let raw_writer_name = ["encode_raw_frame_", "parts_v1("].concat();
        let private_raw_writer = ["fn ", raw_writer_name.as_str()].concat();
        assert_eq!(
            source
                .lines()
                .filter(|line| line.trim() == private_raw_writer)
                .count(),
            1,
            "C3c must retain exactly one private raw-parts writer"
        );
        for exposed_prefix in ["pub fn ", "pub(crate) fn ", "pub(super) fn "] {
            let exposed = [exposed_prefix, raw_writer_name.as_str()].concat();
            assert!(
                !source.contains(&exposed),
                "C3c raw-parts writer escaped through {exposed_prefix}"
            );
        }
        let restricted_public = ["pub", "(in "].concat();
        assert!(
            !source.lines().any(|line| {
                let line = line.trim_start();
                line.starts_with(&restricted_public) && line.contains(&raw_writer_name)
            }),
            "C3c raw-parts writer escaped through restricted visibility"
        );
        let signature = |name: &str| {
            let start = source.find(name).expect("public C3c function");
            let end = source[start..].find('{').expect("function body") + start;
            &source[start..end]
        };
        let generator = signature(&["pub fn encode_generator_bound_", "raw_frame_v1("].concat());
        let worker = signature(&["pub fn encode_worker_exec_bound_", "raw_frame_v1("].concat());
        for closed in [generator, worker] {
            for forbidden in [
                "PeerCredentialsV1",
                "AncillaryShapeV1",
                "FdCommitmentV1",
                "FrameInputV1",
                "WireFrameV1",
                "TranscriptCursorV1",
                "Vec<u8>",
                "authority",
            ] {
                assert!(
                    !closed.contains(forbidden),
                    "C3c surface exposed {forbidden}"
                );
            }
        }
        assert!(!generator.contains("previous_hash"));
        assert!(worker.contains("worker_bootstrap_digest: TranscriptDigestV1"));
        assert!(!worker.contains("previous_hash"));
        assert_eq!(
            source
                .matches(&["fn encode_raw_frame_", "parts_v1("].concat())
                .count(),
            1
        );
    }

    #[test]
    fn outbound_entry_previous_hash_inputs_v1() {
        let (_, request) = request_with_count(2);
        let session = session(&request);
        let worker_initial = worker_initial_inventory();
        let worker_transfer = worker_transfer_inventory(2);
        let manifest = worker_manifest(2);
        let body =
            WorkerExecBoundBodyV1::try_new(&session, &worker_initial, &worker_transfer, &manifest)
                .unwrap();
        let first = encode_worker_exec_bound_raw_frame_v1(
            &session,
            TranscriptDigestV1::from_bytes([0x84; 32]),
            &body,
        )
        .unwrap();
        let second = encode_worker_exec_bound_raw_frame_v1(
            &session,
            TranscriptDigestV1::from_bytes([0x85; 32]),
            &body,
        )
        .unwrap();
        assert_eq!(&first[49..81], &[0x84; 32]);
        assert_eq!(&second[49..81], &[0x85; 32]);
        assert_ne!(first, second);

        let source = production_wire_source_v1();
        let start = source
            .find(&["pub fn encode_worker_exec_bound_", "raw_frame_v1("].concat())
            .unwrap();
        let end = source[start..]
            .find("/// Exact closed-result body bytes.")
            .unwrap()
            + start;
        let implementation = &source[start..end];
        assert!(implementation.contains("worker_bootstrap_digest.into_bytes()"));
        assert!(!implementation.contains("TranscriptDigestV1::from_bytes"));
        assert!(!implementation.contains("worker_genesis("));
    }

    #[test]
    fn g0_session_contract_v1_freezes_every_exact_length() {
        assert_eq!(G0_REQUEST_PREIMAGE_BYTES_V1, 772);
        assert_eq!(G0_SESSION_OFFER_BYTES_V1, 1_101);
        assert_eq!(G0_PRE_SESSION_RECORD_BYTES_V1, 75);
        assert_eq!(G0_PROVIDER_SESSION_PREIMAGE_BYTES_V1, 373);
        assert_eq!(G0_GENERATOR_BOUND_BODY_BYTES_V1, 234);
        assert_eq!(G0_GENERATOR_BOUND_RAW_FRAME_BYTES_V1, 316);
        assert_eq!(G0_WORKER_EXEC_BOUND_BODY_BYTES_V1, 236);
        assert_eq!(G0_WORKER_EXEC_BOUND_RAW_FRAME_BYTES_V1, 318);
        assert_eq!(G0_CLOSED_RESULT_BODY_BYTES_V1, 136);
    }

    #[test]
    fn g0_session_contract_v1_encodes_ingress_publication_request_and_endpoints() {
        assert_eq!(SEALED_INGRESS_MANIFEST_DOMAIN_V1.len(), 41);
        assert_eq!(PUBLICATION_TARGET_DOMAIN_V1.len(), 36);
        assert_eq!(REQUEST_COMMITMENT_DOMAIN_V1.len(), 36);
        assert_eq!(ENDPOINT_COMMITMENT_DOMAIN_V1.len(), 36);
        assert_eq!(GENERATOR_CHANNEL_IDENTITY_DOMAIN_V1.len(), 44);
        assert_eq!(WORKER_CHANNEL_IDENTITY_DOMAIN_V1.len(), 41);

        let (empty, empty_request) = request_with_count(0);
        assert_eq!(empty.bytes().len(), 44);
        assert_eq!(empty.digest(), sha256_v1(empty.bytes()));
        assert_eq!(empty_request.preimage().len(), 772);
        assert_eq!(empty_request.digest(), sha256_v1(empty_request.preimage()));

        let (maximum, maximum_request) = request_with_count(15);
        assert_eq!(maximum.bytes().len(), 44 + 53 * 15);
        assert_eq!(maximum_request.ingress_count(), 15);
        let sixteen: Vec<_> = (0..16).map(|index| campaign_input(index, true)).collect();
        assert_eq!(
            SealedIngressManifestV1::try_new(&sixteen),
            Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::IngressCount
            ))
        );

        let publication =
            PublicationTargetCommitmentV1::try_new(&publication_root(true), [0x61; 32], [0x62; 32])
                .unwrap();
        assert_eq!(publication.preimage().len(), 132);
        assert_eq!(publication.digest(), sha256_v1(publication.preimage()));
        let mut reordered = role_blocks();
        reordered.swap(0, 1);
        assert_eq!(
            RequestCommitmentV1::try_new(
                [0x31; 32],
                [0x32; 32],
                [0x33; 32],
                &empty,
                &publication,
                &reordered,
            ),
            Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::RequestRoleOrder
            ))
        );

        let generator = endpoint(SeqpacketEndpointRoleV1::Generator, 100);
        let supervisor_generator = endpoint(SeqpacketEndpointRoleV1::SupervisorGenerator, 110);
        let supervisor_worker = endpoint(SeqpacketEndpointRoleV1::SupervisorWorker, 120);
        let worker = endpoint(SeqpacketEndpointRoleV1::Worker, 130);
        assert_eq!(generator.preimage().len(), 83);
        let changed_cookie = SeqpacketEndpointCommitmentV1::from_observation(
            SeqpacketEndpointRoleV1::Generator,
            descriptor(100),
            201,
        );
        assert_ne!(generator.digest(), changed_cookie.digest());
        let generator_channel =
            ChannelIdentityV1::try_generator(&generator, &supervisor_generator).unwrap();
        let worker_channel = ChannelIdentityV1::try_worker(&supervisor_worker, &worker).unwrap();
        assert_ne!(generator_channel.digest(), worker_channel.digest());
        assert_eq!(
            ChannelIdentityV1::try_generator(&worker, &supervisor_generator),
            Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::EndpointPair
            ))
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn g0_session_contract_v1_encodes_offer_nonce_exchange_and_provider_session() {
        assert_eq!(SESSION_OFFER_DOMAIN_V1.len(), 31);
        assert_eq!(NONCE_COMMITMENT_DOMAIN_V1.len(), 34);
        assert_eq!(PROVIDER_SESSION_DOMAIN_V1.len(), 28);
        let (_, request) = request_with_count(2);
        let generator = endpoint(SeqpacketEndpointRoleV1::Generator, 100);
        let supervisor_generator = endpoint(SeqpacketEndpointRoleV1::SupervisorGenerator, 110);
        let supervisor_worker = endpoint(SeqpacketEndpointRoleV1::SupervisorWorker, 120);
        let worker = endpoint(SeqpacketEndpointRoleV1::Worker, 130);
        let generator_channel =
            ChannelIdentityV1::try_generator(&generator, &supervisor_generator).unwrap();
        let worker_channel = ChannelIdentityV1::try_worker(&supervisor_worker, &worker).unwrap();
        let offer = SessionOfferV1::try_new(SessionOfferInputV1 {
            request: &request,
            appliance_measurement: [0x41; 32],
            supervisor_measurement: [0x42; 32],
            generator_measurement: [0x43; 32],
            worker_measurement: [0x44; 32],
            supervisor_pid: 41,
            supervisor_start_epoch: 92,
            generator_channel: &generator_channel,
            worker_channel: &worker_channel,
            supervisor_generator_endpoint: &supervisor_generator,
            supervisor_receiver_user_namespace: descriptor(700),
        })
        .unwrap();
        assert_eq!(offer.bytes().len(), 1_101);
        assert_eq!(&offer.bytes()[..2], &31_u16.to_le_bytes());
        assert_eq!(&offer.bytes()[2..33], SESSION_OFFER_DOMAIN_V1);
        assert_eq!(&offer.bytes()[35..37], &772_u16.to_le_bytes());
        assert_eq!(&offer.bytes()[37..809], request.preimage());
        assert_eq!(&offer.bytes()[809..841], &request.digest());

        let generator_nonce = [0x51; 32];
        let supervisor_nonce = [0x52; 32];
        let generator_commit = encode_pre_session_record_v1(
            PreSessionRecordKindV1::GeneratorCommit,
            &request,
            generator_nonce,
        )
        .unwrap();
        let supervisor_commit = encode_pre_session_record_v1(
            PreSessionRecordKindV1::SupervisorCommit,
            &request,
            supervisor_nonce,
        )
        .unwrap();
        let generator_reveal = encode_pre_session_record_v1(
            PreSessionRecordKindV1::GeneratorReveal,
            &request,
            generator_nonce,
        )
        .unwrap();
        let supervisor_reveal = encode_pre_session_record_v1(
            PreSessionRecordKindV1::SupervisorReveal,
            &request,
            supervisor_nonce,
        )
        .unwrap();
        for (kind, record) in [
            (0, generator_commit),
            (1, supervisor_commit),
            (2, generator_reveal),
            (3, supervisor_reveal),
        ] {
            assert_eq!(record.len(), 75);
            assert_eq!(&record[..8], &PRE_SESSION_RECORD_MAGIC_V1);
            assert_eq!(record[10], kind);
            assert_eq!(&record[11..43], &request.digest());
        }
        assert_eq!(&generator_reveal[43..], &generator_nonce);
        assert_eq!(&supervisor_reveal[43..], &supervisor_nonce);
        assert_ne!(&generator_commit[43..], &generator_nonce);
        assert_ne!(&generator_commit[43..], &supervisor_commit[43..]);
        assert_eq!(
            nonce_commitment_v1(NonceRoleV1::Generator, &request, [0; 32]),
            Err(WireErrorV1::G0ContractDrift(G0ContractFieldV1::Nonce))
        );

        let material = ProviderSessionMaterialV1::try_new(ProviderSessionInputV1 {
            request: &request,
            appliance_measurement: [0x41; 32],
            supervisor_measurement: [0x42; 32],
            generator_measurement: [0x43; 32],
            worker_measurement: [0x44; 32],
            generator_nonce,
            supervisor_nonce,
            supervisor_pid: 41,
            supervisor_start_epoch: 92,
            generator_channel: &generator_channel,
            worker_channel: &worker_channel,
        })
        .unwrap();
        assert_eq!(material.preimage().len(), 373);
        assert_eq!(material.session_id(), sha256_v1(material.preimage()));
        assert_eq!(&material.preimage()[297..301], &41_u32.to_le_bytes());
        assert_eq!(&material.preimage()[301..309], &92_u64.to_le_bytes());
        assert_eq!(
            material.generator_nonce_commitment(),
            nonce_commitment_v1(NonceRoleV1::Generator, &request, generator_nonce).unwrap()
        );

        let changed_measurement = ProviderSessionMaterialV1::try_new(ProviderSessionInputV1 {
            request: &request,
            appliance_measurement: [0x40; 32],
            supervisor_measurement: [0x42; 32],
            generator_measurement: [0x43; 32],
            worker_measurement: [0x44; 32],
            generator_nonce,
            supervisor_nonce,
            supervisor_pid: 41,
            supervisor_start_epoch: 92,
            generator_channel: &generator_channel,
            worker_channel: &worker_channel,
        })
        .unwrap();
        assert_ne!(material.session_id(), changed_measurement.session_id());
        let mut domain_mutant = material.preimage().to_vec();
        domain_mutant[0] ^= 1;
        assert_ne!(material.session_id(), sha256_v1(&domain_mutant));
    }

    #[test]
    fn g0_session_contract_v1_encodes_exact_inventories_manifest_and_seal_profile() {
        assert_eq!(PROCESS_INVENTORY_DOMAIN_V1.len(), 35);
        assert_eq!(WORKER_TRANSFER_MANIFEST_DOMAIN_V1.len(), 42);
        assert_eq!(GENERATOR_SEAL_PROFILE_DOMAIN_V1.len(), 40);
        let generator = generator_inventory(2);
        let worker_initial = worker_initial_inventory();
        let worker_transfer = worker_transfer_inventory(2);
        let manifest = worker_manifest(2);
        assert_eq!(generator.bytes().len(), 135 + 53 * 2);
        assert_eq!(worker_initial.bytes().len(), 82);
        assert_eq!(worker_transfer.bytes().len(), 134 + 53 * 2);
        assert_eq!(manifest.bytes().len(), 99 + 53 * 2);
        assert_eq!(generator.digest(), sha256_v1(generator.bytes()));
        assert_eq!(manifest.digest(), sha256_v1(manifest.bytes()));
        assert_eq!(worker_manifest(15).bytes().len(), 894);

        let reversed = [
            ProcessInventoryEntryV1::new(4, supervisor_pidfd(false)),
            ProcessInventoryEntryV1::new(3, endpoint_fd(FdRoleV1::GeneratorEndpoint, 0x71, false)),
            ProcessInventoryEntryV1::new(5, publication_root(false)),
        ];
        assert_eq!(
            ProcessInventoryV1::try_new(ProcessInventoryKindV1::GeneratorPostExec, &reversed),
            Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::InventorySlot
            ))
        );
        let wrong_cloexec = [ProcessInventoryEntryV1::new(
            3,
            endpoint_fd(FdRoleV1::WorkerEndpoint, 0x72, true),
        )];
        assert_eq!(
            ProcessInventoryV1::try_new(
                ProcessInventoryKindV1::WorkerInitialPostExec,
                &wrong_cloexec
            ),
            Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::InventoryStatus
            ))
        );
        let wrong_campaign = [campaign_input(1, true)];
        assert_eq!(
            WorkerTransferManifestV1::try_new(&observation(true), &wrong_campaign),
            Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::WorkerManifestCampaign
            ))
        );

        let seal = GeneratorSealProfileV1::try_new(&[
            SockFilterInstructionV1::new(0x20, 0, 1, 7),
            SockFilterInstructionV1::new(0x06, 0, 0, 0x7fff_0000),
        ])
        .unwrap();
        assert_eq!(seal.bytes().len(), 47 + 8 * 2);
        assert_eq!(seal.digest(), sha256_v1(seal.bytes()));
        assert_eq!(
            GeneratorSealProfileV1::try_new(&[]),
            Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::GeneratorSealInstructionCount
            ))
        );
    }

    #[test]
    fn worker_manifest_content_policy_v1_keeps_zero_observation_but_rejects_zero_campaign() {
        assert_eq!(G0_WORKER_TRANSFER_ROLE_MAX_BYTES_V1, 1_073_741_824);
        assert_eq!(G0_WORKER_TRANSFER_AGGREGATE_MAX_BYTES_V1, 4_294_967_296);
        let observation = worker_transfer_memfd(FdRoleV1::Observation, 0);
        assert!(WorkerTransferManifestV1::try_new(&observation, &[]).is_ok());

        let campaign = worker_transfer_memfd(FdRoleV1::CampaignInput(0), 0);
        assert_eq!(
            WorkerTransferManifestV1::try_new(&observation, &[campaign]),
            Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::WorkerManifestCampaignContentLength
            ))
        );
    }

    #[test]
    fn worker_manifest_content_policy_v1_enforces_observation_role_maximum() {
        let maximum = worker_transfer_memfd(FdRoleV1::Observation, 1_073_741_824);
        assert!(WorkerTransferManifestV1::try_new(&maximum, &[]).is_ok());

        let oversized = worker_transfer_memfd(FdRoleV1::Observation, 1_073_741_825);
        assert_eq!(
            WorkerTransferManifestV1::try_new(&oversized, &[]),
            Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::WorkerManifestObservationContentLength
            ))
        );
    }

    #[test]
    fn worker_manifest_content_policy_v1_enforces_campaign_role_maximum() {
        let observation = worker_transfer_memfd(FdRoleV1::Observation, 0);
        let maximum = worker_transfer_memfd(FdRoleV1::CampaignInput(0), 1_073_741_824);
        assert!(WorkerTransferManifestV1::try_new(&observation, &[maximum]).is_ok());

        let oversized = worker_transfer_memfd(FdRoleV1::CampaignInput(0), 1_073_741_825);
        assert_eq!(
            WorkerTransferManifestV1::try_new(&observation, &[oversized]),
            Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::WorkerManifestCampaignContentLength
            ))
        );
    }

    #[test]
    fn worker_manifest_content_policy_v1_enforces_checked_aggregate_maximum() {
        let observation = worker_transfer_memfd(FdRoleV1::Observation, 1_073_741_824);
        let exact = [
            worker_transfer_memfd(FdRoleV1::CampaignInput(0), 1_073_741_824),
            worker_transfer_memfd(FdRoleV1::CampaignInput(1), 1_073_741_824),
            worker_transfer_memfd(FdRoleV1::CampaignInput(2), 1_073_741_824),
        ];
        assert!(WorkerTransferManifestV1::try_new(&observation, &exact).is_ok());

        let over = [
            worker_transfer_memfd(FdRoleV1::CampaignInput(0), 1_073_741_824),
            worker_transfer_memfd(FdRoleV1::CampaignInput(1), 1_073_741_824),
            worker_transfer_memfd(FdRoleV1::CampaignInput(2), 1_073_741_824),
            worker_transfer_memfd(FdRoleV1::CampaignInput(3), 1),
        ];
        assert_eq!(
            WorkerTransferManifestV1::try_new(&observation, &over),
            Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::WorkerManifestAggregateContentLength
            ))
        );

        let fifteen: Vec<_> = (0..15)
            .map(|index| worker_transfer_memfd(FdRoleV1::CampaignInput(index), 1))
            .collect();
        let empty_observation = worker_transfer_memfd(FdRoleV1::Observation, 0);
        assert!(WorkerTransferManifestV1::try_new(&empty_observation, &fifteen).is_ok());
    }

    #[test]
    fn worker_manifest_content_policy_v1_rejects_u64_sum_overflow() {
        let observation = worker_transfer_memfd(FdRoleV1::Observation, u64::MAX);
        let campaign = worker_transfer_memfd(FdRoleV1::CampaignInput(0), 1);
        assert!(matches!(
            WorkerTransferManifestV1::try_new(&observation, &[campaign]),
            Err(WireErrorV1::ArithmeticOverflow)
        ));
    }

    #[test]
    fn worker_manifest_content_policy_v1_raw_decoder_reuses_the_constructor() {
        let maximum =
            worker_transfer_memfd(FdRoleV1::Observation, G0_WORKER_TRANSFER_ROLE_MAX_BYTES_V1);
        let manifest = WorkerTransferManifestV1::try_new(&maximum, &[]).unwrap();
        let mut raw = manifest.bytes().to_vec();
        assert_eq!(
            raw.get(52..60),
            Some(
                G0_WORKER_TRANSFER_ROLE_MAX_BYTES_V1
                    .to_le_bytes()
                    .as_slice()
            )
        );
        raw[52..60].copy_from_slice(&(G0_WORKER_TRANSFER_ROLE_MAX_BYTES_V1 + 1).to_le_bytes());
        assert_eq!(
            g0_worker_manifest_from_raw_v1(&raw, 0),
            Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::WorkerManifestObservationContentLength
            ))
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn g0_session_contract_v1_encodes_entry_bodies_and_exact_frame_lengths() {
        assert_eq!(GENERATOR_BOUND_BODY_DOMAIN_V1.len(), 38);
        assert_eq!(WORKER_BOOTSTRAP_BODY_DOMAIN_V1.len(), 39);
        assert_eq!(WORKER_EXEC_BOUND_BODY_DOMAIN_V1.len(), 40);
        assert_eq!(CLOSED_RESULT_BODY_DOMAIN_V1.len(), 36);
        let (ingress, request) = request_with_count(2);
        let session = session(&request);
        let generator_inventory = generator_inventory(2);
        let worker_initial = worker_initial_inventory();
        let worker_transfer = worker_transfer_inventory(2);
        let manifest = worker_manifest(2);
        let seal = GeneratorSealProfileV1::try_new(&[SockFilterInstructionV1::new(
            0x06,
            0,
            0,
            0x7fff_0000,
        )])
        .unwrap();
        let generator_body =
            GeneratorBoundBodyV1::try_new(&session, &seal, &generator_inventory, &ingress).unwrap();
        let generator_genesis = [0x81; 32];
        let generator_frame = zero_fd_frame(
            FrameDirectionV1::GeneratorToSupervisor,
            0,
            AttemptPhaseV1::GeneratorBound,
            session.session_id(),
            generator_genesis,
            generator_body.bytes(),
        );
        assert_eq!(generator_body.bytes().len(), 234);
        assert_eq!(generator_frame.encode_raw_frame().unwrap().len(), 316);
        assert_eq!(
            TranscriptCursorV1::start(session.session_id(), generator_genesis)
                .prepare(&generator_frame)
                .unwrap()
                .bytes()
                .len(),
            426
        );

        let supervisor_worker = endpoint(SeqpacketEndpointRoleV1::SupervisorWorker, 120);
        let bootstrap = WorkerBootstrapBodyV1::try_new(WorkerBootstrapBodyInputV1 {
            accepted_generator_bound_digest: [0x82; 32],
            session: &session,
            supervisor_worker_endpoint: &supervisor_worker,
            supervisor_receiver_user_namespace: descriptor(700),
            worker_receiver_view_uid: 65_532,
            worker_receiver_view_gid: 65_532,
            worker_initial_inventory: &worker_initial,
            worker_transfer_inventory: &worker_transfer,
            worker_manifest: &manifest,
        })
        .unwrap();
        assert_eq!(bootstrap.bytes().len(), 674 + manifest.bytes().len());
        let worker_genesis = [0x83; 32];
        let bootstrap_frame = zero_fd_frame(
            FrameDirectionV1::SupervisorToWorker,
            0,
            AttemptPhaseV1::UserMapsVerified,
            session.session_id(),
            worker_genesis,
            bootstrap.bytes(),
        );
        assert_eq!(
            bootstrap_frame.encode_raw_frame().unwrap().len(),
            756 + manifest.bytes().len()
        );
        assert_eq!(
            TranscriptCursorV1::start(session.session_id(), worker_genesis)
                .prepare(&bootstrap_frame)
                .unwrap()
                .bytes()
                .len(),
            866 + manifest.bytes().len()
        );

        let worker_body =
            WorkerExecBoundBodyV1::try_new(&session, &worker_initial, &worker_transfer, &manifest)
                .unwrap();
        let worker_frame = zero_fd_frame(
            FrameDirectionV1::WorkerToSupervisor,
            1,
            AttemptPhaseV1::WorkerExecBound,
            session.session_id(),
            [0x84; 32],
            worker_body.bytes(),
        );
        assert_eq!(worker_frame.encode_raw_frame().unwrap().len(), 318);
        let mut worker_cursor = TranscriptCursorV1::start(session.session_id(), [0x84; 32]);
        worker_cursor.next_ordinal = 1;
        assert_eq!(
            worker_cursor.prepare(&worker_frame).unwrap().bytes().len(),
            428
        );

        let result = final_result();
        let closed = ClosedResultBodyV1::try_new(&session, [0x85; 32], &result).unwrap();
        let result_commitments = [result];
        let closed_frame = WireFrameV1::try_new(FrameInputV1 {
            direction: FrameDirectionV1::SupervisorToGenerator,
            ordinal: 1,
            phase: AttemptPhaseV1::Closed,
            session_id: session.session_id(),
            previous_hash: [0x86; 32],
            body: closed.bytes(),
            credentials: credentials(),
            fd_commitments: &result_commitments,
            ancillary: AncillaryShapeV1::canonical(1),
        })
        .unwrap();
        assert_eq!(closed_frame.encode_raw_frame().unwrap().len(), 219);
        let mut result_cursor = TranscriptCursorV1::start(session.session_id(), [0x86; 32]);
        result_cursor.next_ordinal = 1;
        assert_eq!(
            result_cursor.prepare(&closed_frame).unwrap().bytes().len(),
            380
        );

        let maximum_manifest = worker_manifest(15);
        let maximum_transfer = worker_transfer_inventory(15);
        let maximum_bootstrap = WorkerBootstrapBodyV1::try_new(WorkerBootstrapBodyInputV1 {
            accepted_generator_bound_digest: [0x82; 32],
            session: &session,
            supervisor_worker_endpoint: &supervisor_worker,
            supervisor_receiver_user_namespace: descriptor(700),
            worker_receiver_view_uid: 65_532,
            worker_receiver_view_gid: 65_532,
            worker_initial_inventory: &worker_initial,
            worker_transfer_inventory: &maximum_transfer,
            worker_manifest: &maximum_manifest,
        })
        .unwrap();
        assert_eq!(maximum_bootstrap.bytes().len(), 1_568);
        let maximum_frame = zero_fd_frame(
            FrameDirectionV1::SupervisorToWorker,
            0,
            AttemptPhaseV1::UserMapsVerified,
            session.session_id(),
            worker_genesis,
            maximum_bootstrap.bytes(),
        );
        assert_eq!(maximum_frame.encode_raw_frame().unwrap().len(), 1_650);
        assert_eq!(
            TranscriptCursorV1::start(session.session_id(), worker_genesis)
                .prepare(&maximum_frame)
                .unwrap()
                .bytes()
                .len(),
            1_760
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn generator_peer_session_candidate_v1() {
        crate::assert_wire_source_full_pin_v1();
        let fixture = test_peer_fixture();
        let candidate = fixture.candidate();
        assert_eq!(candidate.supervisor_pid, 41);
        assert_eq!(candidate.supervisor_start_epoch, 92);
        assert_eq!(
            candidate.supervisor_generator_endpoint_digest.as_slice(),
            &fixture.session_offer_raw[1045..1077]
        );
        assert_eq!(
            candidate.supervisor_receiver_user_namespace,
            descriptor(700)
        );

        for offset in [0, 2, 33, 35, 37, 809, 841, 873, 905, 937, 981, 1045] {
            let mut bad_offer = fixture.session_offer_raw;
            bad_offer[offset] ^= 1;
            let mut bad_input = fixture.input();
            bad_input.session_offer_raw = &bad_offer;
            assert!(
                G0GeneratorPeerSessionCandidateV1::try_new(bad_input).is_err(),
                "offer offset {offset} was not causal"
            );
        }
        for range in [969..973, 973..981, 1077..1085] {
            let mut bad_offer = fixture.session_offer_raw;
            bad_offer[range.clone()].fill(0);
            let mut bad_input = fixture.input();
            bad_input.session_offer_raw = &bad_offer;
            assert!(
                G0GeneratorPeerSessionCandidateV1::try_new(bad_input).is_err(),
                "zeroed offer range {range:?} was not causal"
            );
        }
        let mut alternate_offer = fixture.session_offer_raw;
        alternate_offer[969..973].copy_from_slice(&42_u32.to_le_bytes());
        let mut alternate_input = fixture.input();
        alternate_input.session_offer_raw = &alternate_offer;
        let alternate = G0GeneratorPeerSessionCandidateV1::try_new(alternate_input).unwrap();
        assert_eq!(alternate.supervisor_pid, 42);
        assert_ne!(alternate.session.session_id, candidate.session.session_id);
        let mut alternate_offer = fixture.session_offer_raw;
        alternate_offer[973..981].copy_from_slice(&93_u64.to_le_bytes());
        let mut alternate_input = fixture.input();
        alternate_input.session_offer_raw = &alternate_offer;
        let alternate = G0GeneratorPeerSessionCandidateV1::try_new(alternate_input).unwrap();
        assert_eq!(alternate.supervisor_start_epoch, 93);
        assert_ne!(alternate.session.session_id, candidate.session.session_id);
        let mut alternate_offer = fixture.session_offer_raw;
        alternate_offer[1013] ^= 1;
        let mut alternate_input = fixture.input();
        alternate_input.session_offer_raw = &alternate_offer;
        let alternate = G0GeneratorPeerSessionCandidateV1::try_new(alternate_input).unwrap();
        assert_ne!(
            alternate.session.worker_channel,
            candidate.session.worker_channel
        );
        let mut alternate_offer = fixture.session_offer_raw;
        alternate_offer[1077] ^= 1;
        let mut alternate_input = fixture.input();
        alternate_input.session_offer_raw = &alternate_offer;
        let alternate = G0GeneratorPeerSessionCandidateV1::try_new(alternate_input).unwrap();
        assert_ne!(
            alternate.supervisor_receiver_user_namespace,
            candidate.supervisor_receiver_user_namespace
        );

        for slot in 0..4 {
            for offset in [0, 8, 10, 11, 43, 74] {
                let mut record = match slot {
                    0 => fixture.generator_commit_raw,
                    1 => fixture.supervisor_commit_raw,
                    2 => fixture.generator_reveal_raw,
                    _ => fixture.supervisor_reveal_raw,
                };
                record[offset] ^= 1;
                let mut input = fixture.input();
                match slot {
                    0 => input.generator_commit_raw = &record,
                    1 => input.supervisor_commit_raw = &record,
                    2 => input.generator_reveal_raw = &record,
                    _ => input.supervisor_reveal_raw = &record,
                }
                assert!(
                    G0GeneratorPeerSessionCandidateV1::try_new(input).is_err(),
                    "record {slot} offset {offset} was not causal"
                );
            }
        }
        let mut swapped_commits = fixture.input();
        swapped_commits.generator_commit_raw = &fixture.supervisor_commit_raw;
        swapped_commits.supervisor_commit_raw = &fixture.generator_commit_raw;
        assert!(G0GeneratorPeerSessionCandidateV1::try_new(swapped_commits).is_err());
        let mut swapped_reveals = fixture.input();
        swapped_reveals.generator_reveal_raw = &fixture.supervisor_reveal_raw;
        swapped_reveals.supervisor_reveal_raw = &fixture.generator_reveal_raw;
        assert!(G0GeneratorPeerSessionCandidateV1::try_new(swapped_reveals).is_err());

        for claim in [[0xa1; 32], [0xa2; 32]] {
            let raw = test_closed_raw(&candidate.session, claim, [0xa3; 32], [0xa4; 32]);
            assert!(
                candidate
                    .validate_closed_result_inbound_v1(G0ClosedResultInboundInputV1 {
                        received_raw_frame: &raw,
                        actual_rights_count: 1,
                        observed_credentials: credentials(),
                    })
                    .is_ok()
            );
        }
        let closed_raw = test_closed_raw(&candidate.session, [0xa1; 32], [0xa3; 32], [0xa4; 32]);
        for offset in [0, 8, 10, 11, 12, 13, 17, 81, 82, 83, 85, 121, 123] {
            let mut bad_raw = closed_raw;
            bad_raw[offset] ^= 1;
            assert!(
                candidate
                    .validate_closed_result_inbound_v1(G0ClosedResultInboundInputV1 {
                        received_raw_frame: &bad_raw,
                        actual_rights_count: 1,
                        observed_credentials: credentials(),
                    })
                    .is_err(),
                "ClosedResult offset {offset} was not causal"
            );
        }
        for actual_rights_count in [0, 2] {
            assert!(
                candidate
                    .validate_closed_result_inbound_v1(G0ClosedResultInboundInputV1 {
                        received_raw_frame: &closed_raw,
                        actual_rights_count,
                        observed_credentials: credentials(),
                    })
                    .is_err()
            );
        }

        let source = production_wire_source_v1();
        assert_production_wire_prefix_pin_v1(source);
        let start = source
            .find("pub fn validate_closed_result_inbound_v1")
            .unwrap();
        let end = source[start..]
            .find("/// Raw-only `ClosedResult` receive observations")
            .unwrap()
            + start;
        assert!(start < end && end < source.len());
        let implementation = &source[start..end];
        assert!(!implementation.contains("FdCommitmentV1::try_new"));
        assert!(!implementation.contains("prepare_transcript"));
        assert_owner_surface_v1(
            source,
            "G0GeneratorPeerSessionCandidateV1",
            &[
                "try_new",
                "prepare_generator_bound_body_v1",
                "validate_closed_result_inbound_v1",
            ],
        );
        assert_owner_surface_v1(
            source,
            "G0ClosedResultInboundCandidateV1",
            &["verify_final_result_content_once_v1"],
        );
        assert_input_surface_v1(
            source,
            "G0ClosedResultInboundInputV1",
            "#[derive(Clone,Copy,Debug)]pub",
            &[
                "pubreceived_raw_frame:&'a[u8;G0_CLOSED_RESULT_RAW_FRAME_BYTES_V1]",
                "pubactual_rights_count:usize",
                "pubobserved_credentials:PeerCredentialsV1",
            ],
        );

        let oracle_mutants = r"
#[cfg_attr(test,
derive(Clone))]
pub struct OracleOwner { secret: u8 }
impl OracleOwner {
    pub
    async
    fn leaked(&self) {}
}
impl OracleOwner { pub const LEAKED: u8 = 1; }
impl Clone
for crate::OracleOwner {
    fn clone(&self) -> Self { Self { secret: self.secret } }
}
type OracleAlias = OracleOwner;
pub use self::OracleOwner as OracleUseAlias;
pub const fn leaked_factory() -> OracleOwner { OracleOwner { secret: 0 } }
pub const CLONE_OWNER: fn(&OracleOwner) -> OracleOwner = hidden_clone;
pub static LEAK_OWNER: fn(&OracleOwner) -> u8 = hidden_leak;
macro_rules! expose { ($t:ty) => { impl $t { pub fn macro_leak(&self) {} } } }
expose!(OracleOwner);
";
        let oracle_surface = owner_surface_v1(oracle_mutants, "OracleOwner");
        assert!(oracle_surface.declaration_header.contains("cfg_attr"));
        assert!(oracle_surface.declaration_header.contains("derive"));
        assert_eq!(oracle_surface.methods, ["leaked"]);
        assert_eq!(oracle_surface.non_method_items, ["const:LEAKED"]);
        assert_eq!(
            oracle_surface.public_free_items,
            [
                "use:OracleUseAlias",
                "fn:leaked_factory",
                "const:CLONE_OWNER",
                "static:LEAK_OWNER",
            ]
        );
        assert!(oracle_surface.trait_impl);
        assert!(oracle_surface.alias);
        assert!(oracle_surface.macro_exposure);
        let use_alias_surface = owner_surface_v1(
            "pub struct UseAliasOwner { secret: u8 }\npub use self::UseAliasOwner as Alias;",
            "UseAliasOwner",
        );
        assert!(use_alias_surface.alias);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn provider_session_v1() {
        let (_, request) = request_with_count(0);
        assert!(
            G0GeneratorPeerLocalFactsV1::try_new(
                request, [1; 32], [2; 32], [3; 32], [4; 32], [0; 32],
            )
            .is_err()
        );
        let fixture = test_peer_fixture();
        assert_eq!(
            fixture
                .facts
                .prepare_generator_commit_record_v1()
                .unwrap()
                .bytes(),
            &fixture.generator_commit_raw
        );
        assert_eq!(
            fixture
                .facts
                .prepare_generator_reveal_record_v1()
                .unwrap()
                .bytes(),
            &fixture.generator_reveal_raw
        );
        let candidate = fixture.candidate();
        let seal = test_generator_seal();
        let inventory = generator_inventory(2);
        let via_candidate = candidate
            .prepare_generator_bound_body_v1(&seal, &inventory, &fixture.ingress)
            .unwrap();
        let direct =
            GeneratorBoundBodyV1::try_new(&candidate.session, &seal, &inventory, &fixture.ingress)
                .unwrap();
        assert_eq!(via_candidate.bytes(), direct.bytes());
        let mut substituted_facts = Vec::new();
        let (_, alternate_request) = request_with_count(1);
        substituted_facts.push(
            G0GeneratorPeerLocalFactsV1::try_new(
                alternate_request,
                [0x41; 32],
                [0x42; 32],
                [0x43; 32],
                [0x44; 32],
                [0x51; 32],
            )
            .unwrap(),
        );
        for measures in [
            [[0x40; 32], [0x42; 32], [0x43; 32], [0x44; 32]],
            [[0x41; 32], [0x40; 32], [0x43; 32], [0x44; 32]],
            [[0x41; 32], [0x42; 32], [0x40; 32], [0x44; 32]],
            [[0x41; 32], [0x42; 32], [0x43; 32], [0x40; 32]],
        ] {
            let (_, request) = request_with_count(2);
            substituted_facts.push(
                G0GeneratorPeerLocalFactsV1::try_new(
                    request,
                    measures[0],
                    measures[1],
                    measures[2],
                    measures[3],
                    [0x51; 32],
                )
                .unwrap(),
            );
        }
        let (_, request) = request_with_count(2);
        substituted_facts.push(
            G0GeneratorPeerLocalFactsV1::try_new(
                request, [0x41; 32], [0x42; 32], [0x43; 32], [0x44; 32], [0x53; 32],
            )
            .unwrap(),
        );
        for facts in &substituted_facts {
            let mut input = fixture.input();
            input.local_facts = facts;
            assert!(G0GeneratorPeerSessionCandidateV1::try_new(input).is_err());
        }
        assert_eq!(fixture.generator_commit_raw[10], 0);
        assert_eq!(fixture.supervisor_commit_raw[10], 1);
        assert_eq!(fixture.generator_reveal_raw[10], 2);
        assert_eq!(fixture.supervisor_reveal_raw[10], 3);
        assert_eq!(&fixture.generator_reveal_raw[43..], &[0x51; 32]);
        assert_eq!(&fixture.supervisor_reveal_raw[43..], &[0x52; 32]);
        let source = production_wire_source_v1();
        assert!(!source.contains("pub fn prepare_pre_session_record_v1"));
        assert_owner_surface_v1(
            source,
            "G0GeneratorPeerLocalFactsV1",
            &[
                "try_new",
                "prepare_generator_commit_record_v1",
                "prepare_generator_reveal_record_v1",
            ],
        );
        assert_owner_surface_v1(source, "G0GeneratorCommitRecordV1", &["bytes"]);
        assert_owner_surface_v1(source, "G0GeneratorRevealRecordV1", &["bytes"]);
        assert_input_surface_v1(
            source,
            "G0GeneratorPeerSessionInputV1",
            "#[derive(Clone,Copy)]pub",
            &[
                "pubsession_offer_raw:&'a[u8;G0_SESSION_OFFER_BYTES_V1]",
                "pubgenerator_commit_raw:&'a[u8;G0_PRE_SESSION_RECORD_BYTES_V1]",
                "pubsupervisor_commit_raw:&'a[u8;G0_PRE_SESSION_RECORD_BYTES_V1]",
                "pubgenerator_reveal_raw:&'a[u8;G0_PRE_SESSION_RECORD_BYTES_V1]",
                "pubsupervisor_reveal_raw:&'a[u8;G0_PRE_SESSION_RECORD_BYTES_V1]",
                "publocal_facts:&'aG0GeneratorPeerLocalFactsV1",
                "publocal_generator_endpoint:&'aSeqpacketEndpointCommitmentV1",
            ],
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn generator_bound_outbound_candidate_v1() {
        let fixture = test_peer_fixture();
        let session = fixture.candidate();
        let body = session
            .prepare_generator_bound_body_v1(
                &test_generator_seal(),
                &generator_inventory(2),
                &fixture.ingress,
            )
            .unwrap();
        let previous = test_generator_genesis(&session.session);
        let expected_raw =
            test_zero_fd_raw(0, 0, 2, session.session.session_id, previous, body.bytes());
        let expected_digest = sha256_v1(&test_transcript(
            &expected_raw,
            previous,
            0,
            2,
            credentials(),
            &[],
        ));
        let outbound =
            G0GeneratorBoundOutboundCandidateV1::prepare(fixture.candidate(), &body, credentials())
                .unwrap();
        assert_eq!(outbound.bytes().as_slice(), expected_raw);
        for offset in [42, 74, 106] {
            let mut wrong_body = GeneratorBoundBodyV1 {
                bytes: *body.bytes(),
            };
            wrong_body.bytes[offset] ^= 1;
            assert!(
                G0GeneratorBoundOutboundCandidateV1::prepare(
                    fixture.candidate(),
                    &wrong_body,
                    credentials(),
                )
                .is_err(),
                "GeneratorBound session field {offset} was not causal"
            );
        }
        let content = b"joined-final-result";
        let raw = test_closed_raw(
            &session.session,
            expected_digest,
            [0xb1; 32],
            sha256_v1(content),
        );
        let _verified = outbound
            .into_await_closed_result_v1()
            .verify_observed_closed_result_once_v1(
                G0ClosedResultInboundInputV1 {
                    received_raw_frame: &raw,
                    actual_rights_count: 1,
                    observed_credentials: credentials(),
                },
                content,
            )
            .unwrap();

        let alternate_credentials =
            PeerCredentialsV1::try_new(42, 1_000, 1_001, descriptor(700)).unwrap();
        let alternate_digest = sha256_v1(&test_transcript(
            &expected_raw,
            previous,
            0,
            2,
            alternate_credentials,
            &[],
        ));
        assert_ne!(alternate_digest, expected_digest);
        let alternate_outbound = G0GeneratorBoundOutboundCandidateV1::prepare(
            fixture.candidate(),
            &body,
            alternate_credentials,
        )
        .unwrap();
        assert_eq!(alternate_outbound.bytes().as_slice(), expected_raw);
        let base_raw = test_closed_raw(
            &session.session,
            expected_digest,
            [0xb1; 32],
            sha256_v1(content),
        );
        assert!(
            alternate_outbound
                .into_await_closed_result_v1()
                .verify_observed_closed_result_once_v1(
                    G0ClosedResultInboundInputV1 {
                        received_raw_frame: &base_raw,
                        actual_rights_count: 1,
                        observed_credentials: credentials(),
                    },
                    content,
                )
                .is_err()
        );

        let outbound =
            G0GeneratorBoundOutboundCandidateV1::prepare(fixture.candidate(), &body, credentials())
                .unwrap();
        let wrong_raw =
            test_closed_raw(&session.session, [0xee; 32], [0xb1; 32], sha256_v1(content));
        assert!(
            outbound
                .into_await_closed_result_v1()
                .verify_observed_closed_result_once_v1(
                    G0ClosedResultInboundInputV1 {
                        received_raw_frame: &wrong_raw,
                        actual_rights_count: 1,
                        observed_credentials: credentials(),
                    },
                    content,
                )
                .is_err()
        );
        let source = production_wire_source_v1();
        let getter = ["expected_generator_bound_", "digest_v1("].concat();
        assert!(!source.contains(&getter));
        let start = source
            .find("impl G0GeneratorBoundOutboundCandidateV1")
            .unwrap();
        let end = source[start..]
            .find("/// Claims whose `GeneratorBound` digest")
            .unwrap()
            + start;
        assert!(start < end && end < source.len());
        let implementation = &source[start..end];
        assert!(implementation.contains("encode_generator_bound_raw_frame_v1"));
        assert!(implementation.contains("G0GeneratorBoundTranscriptCandidateV1::prepare"));
        assert!(implementation.contains("frame.encode_raw_frame()?.as_slice() != raw_frame"));
        assert!(implementation.contains("credentials"));
        assert_owner_surface_v1(
            source,
            "G0VerifiedClosedResultClaimsV1",
            &[
                "claimed_generator_bound_digest_v1",
                "terminal_worker_digest_v1",
                "verified_content_digest_v1",
            ],
        );
        assert_owner_surface_v1(
            source,
            "G0GeneratorBoundOutboundCandidateV1",
            &["prepare", "bytes", "into_await_closed_result_v1"],
        );
        assert_owner_surface_v1(
            source,
            "G0GeneratorBoundAwaitClosedResultV1",
            &["verify_observed_closed_result_once_v1"],
        );
        assert_owner_surface_v1(source, "G0ClosedResultVerifiedV1", &[]);
        assert_owner_surface_v1(
            source,
            "G0MatchedClosedResultClaimsV1",
            &["terminal_worker_digest_v1", "verified_content_digest_v1"],
        );
    }

    #[test]
    fn generator_bound_closed_result_atomic_capability_v1() {
        let fixture = test_peer_fixture();
        let session = fixture.candidate();
        let body = session
            .prepare_generator_bound_body_v1(
                &test_generator_seal(),
                &generator_inventory(2),
                &fixture.ingress,
            )
            .unwrap();
        let previous = test_generator_genesis(&session.session);
        let expected_raw =
            test_zero_fd_raw(0, 0, 2, session.session.session_id, previous, body.bytes());
        let expected_digest = sha256_v1(&test_transcript(
            &expected_raw,
            previous,
            0,
            2,
            credentials(),
            &[],
        ));
        let outbound =
            G0GeneratorBoundOutboundCandidateV1::prepare(session, &body, credentials()).unwrap();
        assert_eq!(outbound.bytes().as_slice(), expected_raw);
        let awaiting = outbound.into_await_closed_result_v1();
        let content = b"atomic-closed-result";
        let raw = test_closed_raw(
            &fixture.candidate().session,
            expected_digest,
            [0xb2; 32],
            sha256_v1(content),
        );
        let _verified: G0ClosedResultVerifiedV1 = awaiting
            .verify_observed_closed_result_once_v1(
                G0ClosedResultInboundInputV1 {
                    received_raw_frame: &raw,
                    actual_rights_count: 1,
                    observed_credentials: credentials(),
                },
                content,
            )
            .unwrap();

        let source = production_wire_source_v1();
        assert_owner_surface_v1(
            source,
            "G0GeneratorBoundOutboundCandidateV1",
            &["prepare", "bytes", "into_await_closed_result_v1"],
        );
        assert_owner_surface_v1(
            source,
            "G0GeneratorBoundAwaitClosedResultV1",
            &["verify_observed_closed_result_once_v1"],
        );
        assert_owner_surface_v1(source, "G0ClosedResultVerifiedV1", &[]);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn final_result_content_bound_v1() {
        assert_eq!(G0_FINAL_RESULT_MAX_BYTES_V1, 1_048_576);
        assert!(g0_final_result_content_digest_v1(&[]).is_err());
        assert!(g0_final_result_content_digest_v1(&[1]).is_ok());
        let maximum = vec![0x5a; G0_FINAL_RESULT_MAX_BYTES_V1];
        assert!(g0_final_result_content_digest_v1(&maximum).is_ok());
        let oversized = vec![0x5a; G0_FINAL_RESULT_MAX_BYTES_V1 + 1];
        assert!(g0_final_result_content_digest_v1(&oversized).is_err());
        let fixture = test_peer_fixture();
        let session = fixture.candidate();

        for missing in 0..4 {
            let mut seals = [SealPresenceV1::Present; 4];
            seals[missing] = SealPresenceV1::Absent;
            assert!(
                FdCommitmentV1::try_new(
                    FdRoleV1::FinalResult,
                    FdIdentityV1::Memfd {
                        size: 1,
                        content_digest: sha256_v1(&[1]),
                        seals: MemfdSealsV1::new(seals[0], seals[1], seals[2], seals[3]),
                    },
                    FdStatusV1::new(FdAccessV1::ReadOnly, false, true),
                )
                .is_err()
            );
        }
        for status in [
            FdStatusV1::new(FdAccessV1::ReadWrite, false, true),
            FdStatusV1::new(FdAccessV1::ReadOnly, true, true),
        ] {
            assert!(matches!(
                FdCommitmentV1::try_new(
                    FdRoleV1::FinalResult,
                    FdIdentityV1::Memfd {
                        size: 1,
                        content_digest: sha256_v1(&[1]),
                        seals: MemfdSealsV1::new(
                            SealPresenceV1::Present,
                            SealPresenceV1::Present,
                            SealPresenceV1::Present,
                            SealPresenceV1::Present,
                        ),
                    },
                    status,
                ),
                Err(WireErrorV1::RoleStatusMismatch(FdRoleV1::FinalResult))
            ));
        }

        assert!(
            ClosedResultBodyV1::try_new(
                &session.session,
                [1; 32],
                &test_final_result_commitment(&[], None),
            )
            .is_err()
        );
        assert!(
            ClosedResultBodyV1::try_new(
                &session.session,
                [1; 32],
                &test_final_result_commitment(&maximum, None),
            )
            .is_ok()
        );
        assert!(
            ClosedResultBodyV1::try_new(
                &session.session,
                [1; 32],
                &test_final_result_commitment(&oversized, None),
            )
            .is_err()
        );

        let content = b"final-result-v1";
        let raw = test_closed_raw(&session.session, [0xd4; 32], [0xd5; 32], sha256_v1(content));
        let claims = session
            .validate_closed_result_inbound_v1(G0ClosedResultInboundInputV1 {
                received_raw_frame: &raw,
                actual_rights_count: 1,
                observed_credentials: credentials(),
            })
            .unwrap()
            .verify_final_result_content_once_v1(content)
            .unwrap();
        let expected_closed_transcript_v1: [u8; 380] = [
            33, 0, 101, 105, 112, 48, 48, 52, 53, 45, 98, 52, 45, 104, 48, 45, 102, 114, 97, 109,
            101, 45, 116, 114, 97, 110, 115, 99, 114, 105, 112, 116, 45, 118, 49, 212, 212, 212,
            212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212,
            212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 1, 21, 219, 0, 0, 0, 69,
            73, 80, 52, 53, 72, 48, 70, 1, 0, 1, 1, 21, 136, 0, 0, 0, 108, 195, 56, 214, 143, 25,
            153, 180, 165, 127, 225, 50, 238, 243, 152, 124, 158, 233, 48, 66, 9, 193, 13, 152, 62,
            74, 71, 148, 0, 163, 92, 53, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212,
            212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212, 212,
            212, 212, 212, 212, 1, 9, 36, 0, 101, 105, 112, 48, 48, 52, 53, 45, 98, 52, 45, 104,
            48, 45, 99, 108, 111, 115, 101, 100, 45, 114, 101, 115, 117, 108, 116, 45, 98, 111,
            100, 121, 45, 118, 49, 0, 1, 0, 108, 99, 149, 160, 102, 159, 110, 104, 82, 204, 163, 0,
            111, 35, 64, 64, 61, 197, 153, 189, 52, 169, 199, 183, 78, 127, 184, 31, 255, 134, 48,
            168, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213,
            213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 213, 23,
            154, 130, 177, 71, 68, 122, 92, 168, 189, 188, 160, 146, 251, 100, 135, 157, 164, 139,
            87, 14, 47, 2, 118, 206, 159, 88, 177, 87, 12, 225, 215, 41, 0, 0, 0, 232, 3, 0, 0,
            233, 3, 0, 0, 188, 2, 0, 0, 0, 0, 0, 0, 189, 2, 0, 0, 0, 0, 0, 0, 190, 2, 0, 0, 0, 0,
            0, 0, 1, 49, 0, 9, 2, 15, 0, 0, 0, 0, 0, 0, 0, 23, 154, 130, 177, 71, 68, 122, 92, 168,
            189, 188, 160, 146, 251, 100, 135, 157, 164, 139, 87, 14, 47, 2, 118, 206, 159, 88,
            177, 87, 12, 225, 215, 1, 1, 1, 1, 1, 0, 1,
        ];
        assert_eq!(claims.transcript, expected_closed_transcript_v1);

        let alternate_content = b"non-golden-final-result-v1";
        let alternate_content_digest = sha256_v1(alternate_content);
        let alternate_raw = test_closed_raw(
            &session.session,
            [0xd4; 32],
            [0xd5; 32],
            alternate_content_digest,
        );
        let alternate_claims = session
            .validate_closed_result_inbound_v1(G0ClosedResultInboundInputV1 {
                received_raw_frame: &alternate_raw,
                actual_rights_count: 1,
                observed_credentials: credentials(),
            })
            .unwrap()
            .verify_final_result_content_once_v1(alternate_content)
            .unwrap();
        let alternate_commitment = test_memfd_bytes(
            FdRoleV1::FinalResult,
            u64::try_from(alternate_content.len()).unwrap(),
            alternate_content_digest,
            [1, 1, 1, 1],
            1,
        );
        let alternate_expected_transcript = test_transcript(
            &alternate_raw,
            [0xd4; 32],
            1,
            21,
            credentials(),
            &[alternate_commitment],
        );
        assert_eq!(
            alternate_claims.transcript.as_slice(),
            alternate_expected_transcript.as_slice()
        );
        assert_ne!(alternate_claims.transcript, claims.transcript);

        for bounded in [&[0x01][..], maximum.as_slice()] {
            let bounded_raw =
                test_closed_raw(&session.session, [0xd4; 32], [0xd5; 32], sha256_v1(bounded));
            assert!(
                session
                    .validate_closed_result_inbound_v1(G0ClosedResultInboundInputV1 {
                        received_raw_frame: &bounded_raw,
                        actual_rights_count: 1,
                        observed_credentials: credentials(),
                    })
                    .unwrap()
                    .verify_final_result_content_once_v1(bounded)
                    .is_ok()
            );
        }
        let oversized_raw = test_closed_raw(
            &session.session,
            [0xd4; 32],
            [0xd5; 32],
            sha256_v1(&oversized),
        );
        assert!(
            session
                .validate_closed_result_inbound_v1(G0ClosedResultInboundInputV1 {
                    received_raw_frame: &oversized_raw,
                    actual_rights_count: 1,
                    observed_credentials: credentials(),
                })
                .unwrap()
                .verify_final_result_content_once_v1(&oversized)
                .is_err()
        );
        assert!(
            FdCommitmentV1::try_new(
                FdRoleV1::FinalResult,
                FdIdentityV1::Memfd {
                    size: 1,
                    content_digest: sha256_v1(&[1]),
                    seals: MemfdSealsV1::new(
                        SealPresenceV1::Present,
                        SealPresenceV1::Present,
                        SealPresenceV1::Absent,
                        SealPresenceV1::Present,
                    ),
                },
                FdStatusV1::new(FdAccessV1::ReadOnly, false, true),
            )
            .is_err()
        );
        let no_cloexec = FdCommitmentV1::try_new(
            FdRoleV1::FinalResult,
            FdIdentityV1::Memfd {
                size: 1,
                content_digest: sha256_v1(&[1]),
                seals: MemfdSealsV1::new(
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                ),
            },
            FdStatusV1::new(FdAccessV1::ReadOnly, false, false),
        )
        .unwrap();
        assert!(ClosedResultBodyV1::try_new(&session.session, [1; 32], &no_cloexec).is_err());

        let mut raw_equality_candidate = session
            .validate_closed_result_inbound_v1(G0ClosedResultInboundInputV1 {
                received_raw_frame: &raw,
                actual_rights_count: 1,
                observed_credentials: credentials(),
            })
            .unwrap();
        raw_equality_candidate.raw_frame[10] ^= 1;
        assert!(matches!(
            raw_equality_candidate.verify_final_result_content_once_v1(content),
            Err(WireErrorV1::G0ContractDrift(
                G0ContractFieldV1::ClosedResultFrame
            ))
        ));

        let drift_raw = test_closed_raw(&session.session, [0xd4; 32], [0xd5; 32], [0x44; 32]);
        assert!(
            session
                .validate_closed_result_inbound_v1(G0ClosedResultInboundInputV1 {
                    received_raw_frame: &drift_raw,
                    actual_rights_count: 1,
                    observed_credentials: credentials(),
                })
                .unwrap()
                .verify_final_result_content_once_v1(content)
                .is_err()
        );
        let source = production_wire_source_v1();
        let start = source
            .find("pub fn verify_final_result_content_once_v1")
            .unwrap();
        let end = source[start..]
            .find("/// Bounded canonical `FinalResult` digest calculation")
            .unwrap()
            + start;
        assert!(start < end && end < source.len());
        let normalized_implementation = source[start..end].replace("\r\n", "\n");
        let implementation = normalized_implementation.as_str();
        let expected_entry = concat!(
            "pub fn verify_final_result_content_once_v1(\n",
            "        self,\n",
            "        bytes: &[u8],\n",
            "    ) -> Result<G0VerifiedClosedResultClaimsV1, WireErrorV1> {\n",
            "        if bytes.is_empty() || bytes.len() > G0_FINAL_RESULT_MAX_BYTES_V1 {\n",
            "            return Err(WireErrorV1::G0ContractDrift(\n",
            "                G0ContractFieldV1::FinalResultContent,\n",
            "            ));\n",
            "        }\n",
            "        let size = u64::try_from(bytes.len()).map_err(|_| WireErrorV1::ArithmeticOverflow)?;\n",
            "        let verified_content_digest = g0_final_result_content_digest_v1(bytes)?;\n",
        );
        assert!(
            implementation.starts_with(expected_entry),
            "FinalResult bound moved or became decorative"
        );
        let expected_raw_equality = concat!(
            "if canonical_raw.as_slice() != self.raw_frame {\n",
            "            return Err(WireErrorV1::G0ContractDrift(\n",
            "                G0ContractFieldV1::ClosedResultFrame,\n",
            "            ));\n",
            "        }",
        );
        assert_eq!(implementation.matches(expected_raw_equality).count(), 1);
        let empty_bound = implementation.find("bytes.is_empty()").unwrap();
        let maximum_bound = implementation
            .find("bytes.len() > G0_FINAL_RESULT_MAX_BYTES_V1")
            .unwrap();
        let conversion = implementation.find("u64::try_from(bytes.len())").unwrap();
        let digest = implementation
            .find("let verified_content_digest = g0_final_result_content_digest_v1(bytes)?;")
            .unwrap();
        let claim_equality = implementation
            .find("verified_content_digest != self.claimed_content_digest")
            .unwrap();
        let commitment = implementation.find("FdCommitmentV1::try_new").unwrap();
        let commitment_end = implementation
            .find("let commitments = [final_result];")
            .unwrap();
        let commitment_source = &implementation[commitment..commitment_end];
        assert!(commitment_source.contains("size,"));
        assert!(!commitment_source.contains("size:"));
        assert!(commitment_source.contains("content_digest: verified_content_digest"));
        let raw_equality = implementation
            .find("if canonical_raw.as_slice() != self.raw_frame")
            .unwrap();
        let transcript = implementation
            .find("let transcript = prepare_transcript_bytes_v1")
            .unwrap();
        let transcript_conversion = implementation
            .find("let transcript: [u8; 380] = transcript")
            .unwrap();
        let result = implementation
            .find("Ok(G0VerifiedClosedResultClaimsV1")
            .unwrap();
        assert!(empty_bound < conversion && maximum_bound < conversion);
        assert!(conversion < digest && digest < claim_equality && claim_equality < commitment);
        assert!(commitment < commitment_end && commitment_end < raw_equality);
        assert!(raw_equality < transcript && transcript < transcript_conversion);
        assert!(transcript_conversion < result);
        let bound_branch = &implementation[empty_bound..conversion];
        assert!(
            bound_branch.contains("bytes.is_empty() || bytes.len() > G0_FINAL_RESULT_MAX_BYTES_V1")
        );
        assert!(bound_branch.contains("return Err(WireErrorV1::G0ContractDrift("));
        assert!(bound_branch.contains("G0ContractFieldV1::FinalResultContent"));
        let claim_branch = &implementation[claim_equality..commitment];
        assert!(claim_branch.contains("return Err(WireErrorV1::G0ContractDrift("));
        assert!(claim_branch.contains("G0ContractFieldV1::FinalResultContent"));
        let raw_branch = &implementation[raw_equality..transcript];
        assert!(raw_branch.contains("return Err(WireErrorV1::G0ContractDrift("));
        assert!(raw_branch.contains("G0ContractFieldV1::ClosedResultFrame"));
        let result_source = &implementation[result..];
        assert!(result_source.contains("verified_content_digest,"));
        assert!(result_source.contains("transcript,"));
        assert_eq!(
            implementation.matches("u64::try_from(bytes.len())").count(),
            1
        );
        assert_eq!(
            implementation
                .matches("g0_final_result_content_digest_v1(bytes)?")
                .count(),
            1
        );
        assert_eq!(
            implementation
                .matches("bytes.len() > G0_FINAL_RESULT_MAX_BYTES_V1")
                .count(),
            1
        );
        assert!(!implementation.contains("as u64"));
    }

    #[test]
    #[allow(clippy::too_many_lines, clippy::used_underscore_binding)]
    fn worker_bootstrap_inbound_candidate_v1() {
        for count in [0_usize, 2, 15] {
            let campaigns = (0..count)
                .map(|index| vec![u8::try_from(index + 1).unwrap(); 3 + index])
                .collect();
            let fixture = test_worker_fixture(&[0x91; 17], campaigns, false);
            let candidate = fixture.candidate();
            assert_eq!(
                candidate.bootstrap_digest.into_bytes(),
                fixture.expected_bootstrap_digest
            );
        }
        let fixture = test_worker_fixture(&[0x91; 17], vec![vec![1, 2, 3]], false);
        let baseline = fixture.candidate();
        let body_start = 85;
        let manifest_start = body_start + 642;
        let manifest_end = manifest_start + 152;
        for offset in [
            0,
            8,
            10,
            11,
            12,
            13,
            17,
            49,
            81,
            82,
            83,
            84,
            body_start,
            body_start + 2,
            body_start + 41,
            body_start + 43,
            body_start + 75,
            body_start + 75 + 28,
            body_start + 75 + 30,
            body_start + 75 + 73,
            body_start + 75 + 105,
            body_start + 75 + 137,
            body_start + 75 + 169,
            body_start + 75 + 201,
            body_start + 75 + 233,
            body_start + 75 + 265,
            body_start + 75 + 297,
            body_start + 75 + 301,
            body_start + 75 + 309,
            body_start + 75 + 341,
            body_start + 448,
            body_start + 480,
            body_start + 512,
            body_start + 568,
            body_start + 572,
            body_start + 576,
            body_start + 608,
            body_start + 640,
            manifest_start,
            manifest_start + 2,
            manifest_start + 44,
            manifest_start + 46,
            manifest_start + 47,
            manifest_start + 48,
            manifest_start + 50,
            manifest_start + 51,
            manifest_start + 59,
            manifest_start + 91,
            manifest_start + 95,
            manifest_start + 96,
            manifest_start + 97,
            manifest_start + 98,
            manifest_start + 99,
            manifest_start + 100,
            manifest_start + 102,
            manifest_start + 103,
            manifest_start + 104,
            manifest_start + 112,
            manifest_start + 144,
            manifest_start + 148,
            manifest_start + 149,
            manifest_start + 150,
            manifest_start + 151,
            manifest_end,
        ] {
            let mut bad_raw = fixture.raw.clone();
            bad_raw[offset] ^= 1;
            let mut input = fixture.input();
            input.received_raw_frame = &bad_raw;
            assert!(
                G0WorkerBootstrapInboundCandidateV1::try_new(input).is_err(),
                "WorkerBootstrap offset {offset} was not causal"
            );
        }
        let mut input = fixture.input();
        input.actual_rights_count = 1;
        assert!(G0WorkerBootstrapInboundCandidateV1::try_new(input).is_err());
        let mut input = fixture.input();
        input.expected_outer_uid = 20_003;
        assert!(G0WorkerBootstrapInboundCandidateV1::try_new(input).is_err());
        let mut input = fixture.input();
        input.expected_outer_gid = 20_003;
        assert!(G0WorkerBootstrapInboundCandidateV1::try_new(input).is_err());
        let mut bad_raw = fixture.raw.clone();
        bad_raw[body_start + 544..body_start + 552].fill(0);
        let mut input = fixture.input();
        input.received_raw_frame = &bad_raw;
        assert!(G0WorkerBootstrapInboundCandidateV1::try_new(input).is_err());
        let mut alternate_raw = fixture.raw.clone();
        alternate_raw[body_start + 544] ^= 1;
        let mut input = fixture.input();
        input.received_raw_frame = &alternate_raw;
        let alternate = G0WorkerBootstrapInboundCandidateV1::try_new(input).unwrap();
        let alternate_namespace = DescriptorIdentityV1::try_new(701, 701, 702).unwrap();
        assert_eq!(
            alternate.supervisor_receiver_user_namespace,
            alternate_namespace
        );
        assert_ne!(
            alternate.bootstrap_digest.into_bytes(),
            baseline.bootstrap_digest.into_bytes()
        );
        assert!(
            alternate
                .prepare_worker_exec_bound_outbound_v1(
                    PeerCredentialsV1::try_new(77, 20_002, 20_002, alternate_namespace).unwrap(),
                )
                .is_ok()
        );
        let mut input = fixture.input();
        input.observed_credentials = PeerCredentialsV1::try_new(42, 0, 0, descriptor(701)).unwrap();
        assert!(G0WorkerBootstrapInboundCandidateV1::try_new(input).is_err());
        let mut input = fixture.input();
        input.observed_credentials = PeerCredentialsV1::try_new(41, 1, 0, descriptor(701)).unwrap();
        assert!(G0WorkerBootstrapInboundCandidateV1::try_new(input).is_err());
        let mut input = fixture.input();
        input.observed_credentials = PeerCredentialsV1::try_new(41, 0, 1, descriptor(701)).unwrap();
        assert!(G0WorkerBootstrapInboundCandidateV1::try_new(input).is_err());
        let mut input = fixture.input();
        input.observed_credentials = PeerCredentialsV1::try_new(41, 0, 0, descriptor(702)).unwrap();
        let alternate_credentials = G0WorkerBootstrapInboundCandidateV1::try_new(input).unwrap();
        assert_ne!(
            alternate_credentials.bootstrap_digest.into_bytes(),
            baseline.bootstrap_digest.into_bytes()
        );
        let alternate_worker = endpoint(SeqpacketEndpointRoleV1::Worker, 131);
        let mut input = fixture.input();
        input.local_worker_endpoint = &alternate_worker;
        assert!(G0WorkerBootstrapInboundCandidateV1::try_new(input).is_err());
        let wrong_role_worker = endpoint(SeqpacketEndpointRoleV1::SupervisorWorker, 130);
        let mut input = fixture.input();
        input.local_worker_endpoint = &wrong_role_worker;
        assert!(G0WorkerBootstrapInboundCandidateV1::try_new(input).is_err());
        let mut short_raw = fixture.raw.clone();
        short_raw.pop();
        let mut input = fixture.input();
        input.received_raw_frame = &short_raw;
        assert!(G0WorkerBootstrapInboundCandidateV1::try_new(input).is_err());
        let mut bad_raw = fixture.raw.clone();
        *bad_raw.last_mut().unwrap() ^= 1;
        let mut input = fixture.input();
        input.received_raw_frame = &bad_raw;
        assert!(G0WorkerBootstrapInboundCandidateV1::try_new(input).is_err());

        let mut coordinated_raw = fixture.raw.clone();
        let mut accepted_generator_bound_digest: [u8; 32] = coordinated_raw
            [body_start + 43..body_start + 75]
            .try_into()
            .unwrap();
        accepted_generator_bound_digest[0] ^= 1;
        coordinated_raw[body_start + 43..body_start + 75]
            .copy_from_slice(&accepted_generator_bound_digest);
        coordinated_raw[49..81].copy_from_slice(&test_worker_genesis(
            &baseline.session,
            accepted_generator_bound_digest,
        ));
        let mut input = fixture.input();
        input.received_raw_frame = &coordinated_raw;
        let coordinated = G0WorkerBootstrapInboundCandidateV1::try_new(input).unwrap();
        assert_ne!(
            coordinated.bootstrap_digest.into_bytes(),
            baseline.bootstrap_digest.into_bytes()
        );
        let mut bad_raw = fixture.raw.clone();
        bad_raw.push(0);
        let mut input = fixture.input();
        input.received_raw_frame = &bad_raw;
        assert!(G0WorkerBootstrapInboundCandidateV1::try_new(input).is_err());

        let candidate = fixture.candidate();
        let outbound_credentials =
            PeerCredentialsV1::try_new(77, 20_002, 20_002, descriptor(700)).unwrap();
        let session_id = candidate.session.session_id;
        let previous = candidate.bootstrap_digest.into_bytes();
        let mut body = Vec::new();
        body.extend_from_slice(&40_u16.to_le_bytes());
        body.extend_from_slice(b"eip0045-b4-h0-worker-exec-bound-body-v1\0");
        body.extend_from_slice(&1_u16.to_le_bytes());
        body.extend_from_slice(&candidate.session.request_commitment);
        body.extend_from_slice(&candidate.session.generator_nonce_commitment);
        body.extend_from_slice(&candidate.session.supervisor_nonce_commitment);
        body.extend_from_slice(&candidate.worker_initial_inventory.digest);
        body.extend_from_slice(&candidate.worker_transfer_inventory.digest);
        body.extend_from_slice(&candidate.worker_manifest.digest);
        assert_eq!(body.len(), 236);
        let expected_raw = test_zero_fd_raw(3, 1, 6, session_id, previous, &body);
        for wrong_credentials in [
            PeerCredentialsV1::try_new(77, 20_003, 20_002, descriptor(700)).unwrap(),
            PeerCredentialsV1::try_new(77, 20_002, 20_003, descriptor(700)).unwrap(),
            PeerCredentialsV1::try_new(77, 20_002, 20_002, descriptor(702)).unwrap(),
        ] {
            assert!(
                fixture
                    .candidate()
                    .prepare_worker_exec_bound_outbound_v1(wrong_credentials)
                    .is_err()
            );
        }
        let outbound = candidate
            .prepare_worker_exec_bound_outbound_v1(outbound_credentials)
            .unwrap();
        assert_eq!(outbound.bytes().as_slice(), expected_raw);
        let expected_transcript_digest = sha256_v1(&test_transcript(
            &expected_raw,
            previous,
            3,
            6,
            outbound_credentials,
            &[],
        ));
        assert_eq!(outbound._transcript_digest, expected_transcript_digest);

        let alternate_pid_credentials =
            PeerCredentialsV1::try_new(78, 20_002, 20_002, descriptor(700)).unwrap();
        let alternate_pid_outbound = fixture
            .candidate()
            .prepare_worker_exec_bound_outbound_v1(alternate_pid_credentials)
            .unwrap();
        let alternate_pid_digest = sha256_v1(&test_transcript(
            &expected_raw,
            previous,
            3,
            6,
            alternate_pid_credentials,
            &[],
        ));
        assert_eq!(alternate_pid_outbound.bytes().as_slice(), expected_raw);
        assert_eq!(
            alternate_pid_outbound._transcript_digest,
            alternate_pid_digest
        );
        assert_ne!(alternate_pid_digest, expected_transcript_digest);
        let source = production_wire_source_v1();
        let start = source
            .find("pub struct G0WorkerBootstrapInboundCandidateV1")
            .unwrap();
        let end = source[start..]
            .find("/// Candidate-owned bounded streaming SHA-256 verifier")
            .unwrap()
            + start;
        assert!(start < end && end < source.len());
        let candidate_source = &source[start..end];
        assert!(!candidate_source.contains("pub fn bootstrap_digest"));
        assert!(!candidate_source.contains("pub fn worker_manifest"));
        assert!(!candidate_source.contains("pub fn decode_worker_bootstrap"));
        assert!(!candidate_source.contains("pub fn session"));
        assert!(!candidate_source.contains("pub fn inventory"));
        assert!(!candidate_source.contains("pub fn manifest"));
        assert!(!candidate_source.contains("pub fn commitment"));
        assert!(!candidate_source.contains("pub fn size"));
        assert!(!candidate_source.contains("pub fn digest"));
        assert!(candidate_source.contains("ChannelIdentityV1::try_worker_child"));
        assert!(candidate_source.contains("g0_worker_manifest_from_raw_v1"));
        assert!(candidate_source.contains("ProcessInventoryV1::try_new"));
        assert!(candidate_source.contains("canonical_body.as_slice() != body"));
        assert!(candidate_source.contains("frame.encode_raw_frame()?.as_slice() != raw"));
        assert!(candidate_source.contains("G0TranscriptCandidateV1::prepare"));
        assert!(candidate_source.contains("credentials.user_namespace"));
        assert_owner_surface_v1(
            source,
            "G0WorkerBootstrapInboundCandidateV1",
            &[
                "try_new",
                "start_observation_content_verifier_v1",
                "start_campaign_input_content_verifier_v1",
                "prepare_worker_exec_bound_outbound_v1",
            ],
        );
        assert_owner_surface_v1(source, "G0WorkerExecBoundOutboundCandidateV1", &["bytes"]);
        assert_input_surface_v1(
            source,
            "G0WorkerBootstrapInboundInputV1",
            "#[derive(Clone,Copy,Debug)]pub",
            &[
                "pubreceived_raw_frame:&'a[u8]",
                "pubactual_rights_count:usize",
                "pubobserved_credentials:PeerCredentialsV1",
                "publocal_worker_endpoint:&'aSeqpacketEndpointCommitmentV1",
                "pubexpected_outer_uid:u32",
                "pubexpected_outer_gid:u32",
            ],
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn worker_bootstrap_streaming_content_v1() {
        let observation_content = vec![0x91; G0_WORKER_BOOTSTRAP_HASH_CHUNK_BYTES_V1 + 1];
        let campaign_content = vec![0x53; G0_WORKER_BOOTSTRAP_HASH_CHUNK_BYTES_V1 + 1];
        let fixture =
            test_worker_fixture(&observation_content, vec![campaign_content.clone()], false);
        let candidate = fixture.candidate();
        let observation_status = FdStatusV1::new(FdAccessV1::ReadWrite, false, true);
        let observation_seals = MemfdSealsV1::new(
            SealPresenceV1::Present,
            SealPresenceV1::Present,
            SealPresenceV1::Absent,
            SealPresenceV1::Absent,
        );
        let campaign_status = FdStatusV1::new(FdAccessV1::ReadOnly, false, true);
        let campaign_seals = MemfdSealsV1::new(
            SealPresenceV1::Present,
            SealPresenceV1::Present,
            SealPresenceV1::Present,
            SealPresenceV1::Present,
        );
        let mut verifier = candidate
            .start_observation_content_verifier_v1(
                u64::try_from(observation_content.len()).unwrap(),
                observation_status,
                observation_seals,
            )
            .unwrap();
        verifier
            .update_at(
                0,
                &observation_content[..G0_WORKER_BOOTSTRAP_HASH_CHUNK_BYTES_V1],
            )
            .unwrap();
        verifier
            .update_at(
                u64::try_from(G0_WORKER_BOOTSTRAP_HASH_CHUNK_BYTES_V1).unwrap(),
                &observation_content[G0_WORKER_BOOTSTRAP_HASH_CHUNK_BYTES_V1..],
            )
            .unwrap();
        verifier.finish().unwrap();
        let mut verifier = candidate
            .start_campaign_input_content_verifier_v1(
                0,
                u64::try_from(campaign_content.len()).unwrap(),
                campaign_status,
                campaign_seals,
            )
            .unwrap();
        verifier
            .update_at(
                0,
                &campaign_content[..G0_WORKER_BOOTSTRAP_HASH_CHUNK_BYTES_V1],
            )
            .unwrap();
        verifier
            .update_at(
                u64::try_from(G0_WORKER_BOOTSTRAP_HASH_CHUNK_BYTES_V1).unwrap(),
                &campaign_content[G0_WORKER_BOOTSTRAP_HASH_CHUNK_BYTES_V1..],
            )
            .unwrap();
        verifier.finish().unwrap();

        assert!(
            candidate
                .start_observation_content_verifier_v1(
                    u64::try_from(observation_content.len() + 1).unwrap(),
                    observation_status,
                    observation_seals,
                )
                .is_err()
        );
        for status in [
            FdStatusV1::new(FdAccessV1::ReadWrite, true, true),
            FdStatusV1::new(FdAccessV1::ReadWrite, false, false),
        ] {
            assert!(
                candidate
                    .start_observation_content_verifier_v1(
                        u64::try_from(observation_content.len()).unwrap(),
                        status,
                        observation_seals,
                    )
                    .is_err()
            );
        }
        for seals in [
            MemfdSealsV1::new(
                SealPresenceV1::Absent,
                SealPresenceV1::Present,
                SealPresenceV1::Absent,
                SealPresenceV1::Absent,
            ),
            MemfdSealsV1::new(
                SealPresenceV1::Present,
                SealPresenceV1::Absent,
                SealPresenceV1::Absent,
                SealPresenceV1::Absent,
            ),
            MemfdSealsV1::new(
                SealPresenceV1::Present,
                SealPresenceV1::Present,
                SealPresenceV1::Present,
                SealPresenceV1::Absent,
            ),
            MemfdSealsV1::new(
                SealPresenceV1::Present,
                SealPresenceV1::Present,
                SealPresenceV1::Absent,
                SealPresenceV1::Present,
            ),
        ] {
            assert!(
                candidate
                    .start_observation_content_verifier_v1(
                        u64::try_from(observation_content.len()).unwrap(),
                        observation_status,
                        seals,
                    )
                    .is_err()
            );
        }
        for status in [
            FdStatusV1::new(FdAccessV1::ReadOnly, true, true),
            FdStatusV1::new(FdAccessV1::ReadOnly, false, false),
            FdStatusV1::new(FdAccessV1::ReadWrite, false, true),
        ] {
            assert!(
                candidate
                    .start_campaign_input_content_verifier_v1(
                        0,
                        u64::try_from(campaign_content.len()).unwrap(),
                        status,
                        campaign_seals,
                    )
                    .is_err()
            );
        }
        for missing in 0..4 {
            let mut presence = [SealPresenceV1::Present; 4];
            presence[missing] = SealPresenceV1::Absent;
            assert!(
                candidate
                    .start_campaign_input_content_verifier_v1(
                        0,
                        u64::try_from(campaign_content.len()).unwrap(),
                        campaign_status,
                        MemfdSealsV1::new(presence[0], presence[1], presence[2], presence[3],),
                    )
                    .is_err()
            );
        }
        assert!(
            candidate
                .start_observation_content_verifier_v1(
                    u64::try_from(observation_content.len()).unwrap(),
                    campaign_status,
                    observation_seals,
                )
                .is_err()
        );
        assert!(
            candidate
                .start_observation_content_verifier_v1(
                    u64::try_from(observation_content.len()).unwrap(),
                    observation_status,
                    campaign_seals,
                )
                .is_err()
        );
        assert!(
            candidate
                .start_campaign_input_content_verifier_v1(
                    1,
                    u64::try_from(campaign_content.len()).unwrap(),
                    campaign_status,
                    campaign_seals,
                )
                .is_err()
        );
        let mut verifier = candidate
            .start_campaign_input_content_verifier_v1(
                0,
                u64::try_from(campaign_content.len()).unwrap(),
                campaign_status,
                campaign_seals,
            )
            .unwrap();
        assert!(verifier.update_at(1, &[1]).is_err());
        assert!(verifier.update_at(0, &[]).is_err());
        assert!(
            verifier
                .update_at(0, &vec![0; G0_WORKER_BOOTSTRAP_HASH_CHUNK_BYTES_V1 + 1])
                .is_err()
        );
        verifier.update_at(0, &[0x53]).unwrap();
        assert!(verifier.finish().is_err());

        for next_offset in [1_u64, 3] {
            let mut verifier = candidate
                .start_campaign_input_content_verifier_v1(
                    0,
                    u64::try_from(campaign_content.len()).unwrap(),
                    campaign_status,
                    campaign_seals,
                )
                .unwrap();
            verifier.update_at(0, &[0x53, 0x53]).unwrap();
            assert!(verifier.update_at(next_offset, &[0x53]).is_err());
        }
        let mut overflow = G0WorkerBootstrapContentVerifierV1 {
            expected_size: u64::MAX,
            expected_digest: [0; 32],
            next_offset: u64::MAX,
            hasher: Sha256::new(),
        };
        assert!(matches!(
            overflow.update_at(u64::MAX, &[1]),
            Err(WireErrorV1::ArithmeticOverflow)
        ));

        let short_fixture = test_worker_fixture(&[1, 2, 3], vec![], false);
        let short_candidate = short_fixture.candidate();
        let mut verifier = short_candidate
            .start_observation_content_verifier_v1(3, observation_status, observation_seals)
            .unwrap();
        assert!(verifier.update_at(0, &[1, 2, 3, 4]).is_err());
        let empty_fixture = test_worker_fixture(&[], vec![], false);
        empty_fixture
            .candidate()
            .start_observation_content_verifier_v1(0, observation_status, observation_seals)
            .unwrap()
            .finish()
            .unwrap();
        let bad_digest_fixture = test_worker_fixture(&[1], vec![campaign_content.clone()], true);
        let bad_candidate = bad_digest_fixture.candidate();
        let mut verifier = bad_candidate
            .start_campaign_input_content_verifier_v1(
                0,
                u64::try_from(campaign_content.len()).unwrap(),
                campaign_status,
                campaign_seals,
            )
            .unwrap();
        verifier
            .update_at(
                0,
                &campaign_content[..G0_WORKER_BOOTSTRAP_HASH_CHUNK_BYTES_V1],
            )
            .unwrap();
        verifier
            .update_at(
                u64::try_from(G0_WORKER_BOOTSTRAP_HASH_CHUNK_BYTES_V1).unwrap(),
                &campaign_content[G0_WORKER_BOOTSTRAP_HASH_CHUNK_BYTES_V1..],
            )
            .unwrap();
        assert!(verifier.finish().is_err());

        let source = production_wire_source_v1();
        let start = source
            .find("pub struct G0WorkerBootstrapContentVerifierV1")
            .unwrap();
        let end = source[start..]
            .find("/// Exact `WorkerExecBound` raw bytes")
            .unwrap()
            + start;
        assert!(start < end && end < source.len());
        let verifier_source = &source[start..end];
        assert!(!verifier_source.contains("pub fn expected_digest"));
        assert!(!verifier_source.contains("pub fn digest"));
        assert!(!verifier_source.contains("pub fn from_retained_commitment_v1"));
        assert!(verifier_source.contains("offset != self.next_offset"));
        assert!(verifier_source.contains("chunk.is_empty()"));
        assert!(verifier_source.contains("chunk.len() > G0_WORKER_BOOTSTRAP_HASH_CHUNK_BYTES_V1"));
        assert!(verifier_source.contains("checked_add(chunk_length)"));
        assert!(verifier_source.contains("next_offset > self.expected_size"));
        assert!(verifier_source.contains("self.next_offset != self.expected_size"));
        assert!(verifier_source.contains("digest != self.expected_digest"));
        assert_owner_surface_v1(
            source,
            "G0WorkerBootstrapContentVerifierV1",
            &["update_at", "finish"],
        );
    }
}

#[cfg(test)]
mod canonical_fd_commitment_v1 {
    use super::*;

    fn descriptor(seed: u64) -> DescriptorIdentityV1 {
        DescriptorIdentityV1::try_new(seed, seed + 1, seed + 2).unwrap()
    }

    fn fully_sealed_memfd(role: FdRoleV1) -> FdCommitmentV1 {
        FdCommitmentV1::try_new(
            role,
            FdIdentityV1::Memfd {
                size: 123,
                content_digest: [0x5a; 32],
                seals: MemfdSealsV1::new(
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                ),
            },
            FdStatusV1::new(FdAccessV1::ReadOnly, false, true),
        )
        .unwrap()
    }

    #[test]
    fn canonical_fd_commitment_v1_has_the_six_contract_lengths() {
        let endpoint = FdCommitmentV1::try_new(
            FdRoleV1::GeneratorEndpoint,
            FdIdentityV1::Socket {
                endpoint_digest: [0x11; 32],
            },
            FdStatusV1::new(FdAccessV1::Socket, false, false),
        )
        .unwrap();
        let pidfd = FdCommitmentV1::try_new(
            FdRoleV1::SupervisorProcess,
            FdIdentityV1::Pidfd {
                process_id: 41,
                start_epoch: 92,
            },
            FdStatusV1::new(FdAccessV1::Process, false, false),
        )
        .unwrap();
        let publication = FdCommitmentV1::try_new(
            FdRoleV1::PublicationRoot,
            FdIdentityV1::Filesystem {
                descriptor: descriptor(10),
                node_kind: FilesystemNodeKindV1::Directory,
            },
            FdStatusV1::new(FdAccessV1::Path, false, false),
        )
        .unwrap();
        let campaign = fully_sealed_memfd(FdRoleV1::CampaignInput(0));
        let observation = FdCommitmentV1::try_new(
            FdRoleV1::Observation,
            FdIdentityV1::Memfd {
                size: 123,
                content_digest: [0x5a; 32],
                seals: MemfdSealsV1::new(
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                    SealPresenceV1::Absent,
                    SealPresenceV1::Absent,
                ),
            },
            FdStatusV1::new(FdAccessV1::ReadWrite, false, true),
        )
        .unwrap();
        let result = fully_sealed_memfd(FdRoleV1::FinalResult);

        for (commitment, expected) in [
            (endpoint, 37_u16),
            (pidfd, 17),
            (publication, 30),
            (campaign, 50),
            (observation, 49),
            (result, 49),
        ] {
            let bytes = encode_fd_commitment_v1(&commitment).unwrap();
            assert_eq!(encoded_fd_commitment_len_v1(&commitment), Ok(expected));
            assert_eq!(bytes.len(), usize::from(expected));
        }
    }

    #[test]
    fn canonical_fd_commitment_v1_is_shared_with_the_transcript_encoder() {
        let commitment = fully_sealed_memfd(FdRoleV1::CampaignInput(0));
        let credentials = PeerCredentialsV1::try_new(41, 1_000, 1_001, descriptor(70)).unwrap();
        let commitments = [commitment];
        let frame = WireFrameV1::try_new(FrameInputV1 {
            direction: FrameDirectionV1::GeneratorToSupervisor,
            ordinal: 0,
            phase: AttemptPhaseV1::GeneratorBound,
            session_id: [0x51; 32],
            previous_hash: [0xa7; 32],
            body: &[0x22],
            credentials,
            fd_commitments: &commitments,
            ancillary: AncillaryShapeV1::canonical(1),
        })
        .unwrap();
        let preimage = TranscriptCursorV1::start([0x51; 32], [0xa7; 32])
            .prepare(&frame)
            .unwrap();
        let encoded = encode_fd_commitment_v1(&commitment).unwrap();
        let suffix_len = 2 + encoded.len();
        let suffix = &preimage.bytes()[preimage.bytes().len() - suffix_len..];
        assert_eq!(
            &suffix[..2],
            &u16::try_from(encoded.len()).unwrap().to_le_bytes()
        );
        assert_eq!(&suffix[2..], encoded);

        let changed = fully_sealed_memfd(FdRoleV1::CampaignInput(1));
        assert_ne!(
            encode_fd_commitment_v1(&commitment).unwrap(),
            encode_fd_commitment_v1(&changed).unwrap()
        );
    }
}

#[cfg(test)]
mod wire_v1 {
    use super::*;
    use crate::state::AttemptPhaseV1;

    const SESSION_ID: [u8; 32] = [0x51; 32];
    const PREVIOUS_HASH: [u8; 32] = [0xA7; 32];

    fn descriptor(seed: u64) -> DescriptorIdentityV1 {
        DescriptorIdentityV1::try_new(seed, seed + 1, seed + 2).unwrap()
    }

    fn credentials() -> PeerCredentialsV1 {
        PeerCredentialsV1::try_new(41, 1_000, 1_001, descriptor(70)).unwrap()
    }

    fn filesystem_fd(role: FdRoleV1, seed: u64) -> FdCommitmentV1 {
        FdCommitmentV1::try_new(
            role,
            FdIdentityV1::Filesystem {
                descriptor: descriptor(seed),
                node_kind: FilesystemNodeKindV1::Directory,
            },
            FdStatusV1::new(FdAccessV1::Path, false, true),
        )
        .unwrap()
    }

    fn campaign_input(index: u8, close_on_exec: bool) -> FdCommitmentV1 {
        FdCommitmentV1::try_new(
            FdRoleV1::CampaignInput(index),
            FdIdentityV1::Memfd {
                size: 128 + u64::from(index),
                content_digest: [index.wrapping_add(1); 32],
                seals: MemfdSealsV1::new(
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                    SealPresenceV1::Present,
                ),
            },
            FdStatusV1::new(FdAccessV1::ReadOnly, false, close_on_exec),
        )
        .unwrap()
    }

    fn input<'a>(body: &'a [u8], fds: &'a [FdCommitmentV1]) -> FrameInputV1<'a> {
        FrameInputV1 {
            direction: FrameDirectionV1::GeneratorToSupervisor,
            ordinal: 0,
            phase: AttemptPhaseV1::GeneratorBound,
            session_id: SESSION_ID,
            previous_hash: PREVIOUS_HASH,
            body,
            credentials: credentials(),
            fd_commitments: fds,
            ancillary: AncillaryShapeV1::canonical(fds.len()),
        }
    }

    fn frame(body: &[u8], fds: &[FdCommitmentV1]) -> WireFrameV1 {
        WireFrameV1::try_new(input(body, fds)).unwrap()
    }

    #[test]
    fn wire_v1_accepts_the_exact_frame_bound_and_rejects_one_more_byte() {
        let exact_body = vec![0x5A; MAX_FRAME_BYTES_V1 - FRAME_FIXED_HEADER_BYTES_V1];
        let exact = frame(&exact_body, &[]);
        assert_eq!(exact.encoded_len().unwrap(), MAX_FRAME_BYTES_V1);

        let oversized_body = vec![0x5A; exact_body.len() + 1];
        assert_eq!(
            WireFrameV1::try_new(input(&oversized_body, &[])),
            Err(WireErrorV1::FrameTooLarge(MAX_FRAME_BYTES_V1 + 1))
        );
    }

    #[test]
    fn wire_v1_accepts_sixteen_fds_and_rejects_seventeen() {
        let sixteen: Vec<_> = (0..16).map(|index| campaign_input(index, true)).collect();
        assert_eq!(frame(&[], &sixteen).fd_commitments(), sixteen.as_slice());

        let seventeen = vec![campaign_input(0, true); 17];
        assert_eq!(
            WireFrameV1::try_new(input(&[], &seventeen)),
            Err(WireErrorV1::TooManyFds(17))
        );
    }

    #[test]
    fn wire_v1_rejects_each_ancillary_shape_drift() {
        let mut candidate = input(&[], &[]);
        candidate.ancillary.message_end = false;
        assert_eq!(
            WireFrameV1::try_new(candidate),
            Err(WireErrorV1::MissingMessageEnd)
        );

        let mut candidate = input(&[], &[]);
        candidate.ancillary.message_truncated = true;
        assert_eq!(
            WireFrameV1::try_new(candidate),
            Err(WireErrorV1::MessageTruncated)
        );

        let mut candidate = input(&[], &[]);
        candidate.ancillary.control_truncated = true;
        assert_eq!(
            WireFrameV1::try_new(candidate),
            Err(WireErrorV1::ControlTruncated)
        );

        for count in [0, 2] {
            let mut candidate = input(&[], &[]);
            candidate.ancillary.credential_records = count;
            assert_eq!(
                WireFrameV1::try_new(candidate),
                Err(WireErrorV1::CredentialRecordCount(count))
            );
        }

        let mut candidate = input(&[], &[]);
        candidate.ancillary.rights_records = 1;
        assert_eq!(
            WireFrameV1::try_new(candidate),
            Err(WireErrorV1::RightsRecordCount(1, 0))
        );

        let one_fd = [campaign_input(0, true)];
        let mut candidate = input(&[], &one_fd);
        candidate.ancillary.rights_records = 0;
        assert_eq!(
            WireFrameV1::try_new(candidate),
            Err(WireErrorV1::RightsRecordCount(0, 1))
        );

        let mut candidate = input(&[], &[]);
        candidate.ancillary.unknown_control_records = 1;
        assert_eq!(
            WireFrameV1::try_new(candidate),
            Err(WireErrorV1::UnknownControlRecords(1))
        );

        let mut candidate = input(&[], &[]);
        candidate.ancillary.malformed_control_records = 1;
        assert_eq!(
            WireFrameV1::try_new(candidate),
            Err(WireErrorV1::MalformedControlRecords(1))
        );
    }

    #[test]
    fn wire_v1_rejects_role_category_status_duplicate_and_order_drift() {
        let publication = filesystem_fd(FdRoleV1::PublicationRoot, 10);
        let supervisor = FdCommitmentV1::try_new(
            FdRoleV1::SupervisorProcess,
            FdIdentityV1::Pidfd {
                process_id: 41,
                start_epoch: 92,
            },
            FdStatusV1::new(FdAccessV1::Process, false, true),
        )
        .unwrap();
        let fds = [publication, supervisor];
        let exact = frame(&[7], &fds);

        let wrong_category = FdCommitmentV1::try_new(
            FdRoleV1::PublicationRoot,
            FdIdentityV1::Pidfd {
                process_id: 41,
                start_epoch: 92,
            },
            FdStatusV1::new(FdAccessV1::Process, false, true),
        );
        assert_eq!(
            wrong_category,
            Err(WireErrorV1::RoleIdentityMismatch(FdRoleV1::PublicationRoot))
        );

        let wrong_status = FdCommitmentV1::try_new(
            FdRoleV1::PublicationRoot,
            FdIdentityV1::Filesystem {
                descriptor: descriptor(10),
                node_kind: FilesystemNodeKindV1::Directory,
            },
            FdStatusV1::new(FdAccessV1::ReadOnly, false, true),
        );
        assert_eq!(
            wrong_status,
            Err(WireErrorV1::RoleStatusMismatch(FdRoleV1::PublicationRoot))
        );

        let duplicate = [publication, filesystem_fd(FdRoleV1::PublicationRoot, 20)];
        assert_eq!(
            WireFrameV1::try_new(input(&[], &duplicate)),
            Err(WireErrorV1::DuplicateFdRole(FdRoleV1::PublicationRoot))
        );

        let reversed = [supervisor, publication];
        assert_eq!(
            exact.validate_expected(FrameExpectationV1 {
                direction: FrameDirectionV1::GeneratorToSupervisor,
                ordinal: 0,
                phase: AttemptPhaseV1::GeneratorBound,
                session_id: SESSION_ID,
                previous_hash: PREVIOUS_HASH,
                body: &[7],
                credentials: credentials(),
                fd_commitments: &reversed,
            }),
            Err(WireErrorV1::ExpectationDrift(FrameFieldV1::FdCommitments))
        );

        assert_eq!(
            FdCommitmentV1::try_new(
                FdRoleV1::CampaignInput(16),
                FdIdentityV1::Memfd {
                    size: 1,
                    content_digest: [3; 32],
                    seals: MemfdSealsV1::new(
                        SealPresenceV1::Present,
                        SealPresenceV1::Present,
                        SealPresenceV1::Present,
                        SealPresenceV1::Present,
                    ),
                },
                FdStatusV1::new(FdAccessV1::ReadOnly, false, true),
            ),
            Err(WireErrorV1::RoleIndexOutOfRange(16))
        );
    }

    #[test]
    fn wire_v1_rejects_header_declaration_and_expected_field_drift() {
        let exact = frame(&[1, 2, 3], &[]);
        let raw = exact.encode_raw_frame().unwrap();
        assert_eq!(&raw[..FRAME_MAGIC_V1.len()], &FRAME_MAGIC_V1);
        assert_eq!(raw.len(), exact.encoded_len().unwrap());

        let mut malformed = frame(&[1, 2, 3], &[]);
        malformed.magic = [0; 8];
        assert_eq!(malformed.validate_shape(), Err(WireErrorV1::MagicMismatch));

        let mut malformed = frame(&[1, 2, 3], &[]);
        malformed.version += 1;
        assert_eq!(
            malformed.validate_shape(),
            Err(WireErrorV1::VersionMismatch(FRAME_VERSION_V1 + 1))
        );

        let mut malformed = frame(&[1, 2, 3], &[]);
        malformed.declared_body_length += 1;
        assert_eq!(
            malformed.validate_shape(),
            Err(WireErrorV1::DeclaredBodyLengthMismatch(4, 3))
        );

        let mut malformed = frame(&[1, 2, 3], &[]);
        malformed.declared_fd_count = 1;
        assert_eq!(
            malformed.validate_shape(),
            Err(WireErrorV1::DeclaredFdCountMismatch(1, 0))
        );

        assert_eq!(
            exact.validate_expected(FrameExpectationV1 {
                direction: FrameDirectionV1::WorkerToSupervisor,
                ordinal: 0,
                phase: AttemptPhaseV1::GeneratorBound,
                session_id: SESSION_ID,
                previous_hash: PREVIOUS_HASH,
                body: &[1, 2, 3],
                credentials: credentials(),
                fd_commitments: &[],
            }),
            Err(WireErrorV1::ExpectationDrift(FrameFieldV1::Direction))
        );
    }

    #[test]
    fn wire_v1_transcript_binds_raw_frame_credentials_and_fd_commitments() {
        let base_fd = [campaign_input(0, true)];
        let base = frame(&[0x22], &base_fd);
        let cursor = TranscriptCursorV1::start(SESSION_ID, PREVIOUS_HASH);
        let base_preimage = cursor.prepare(&base).unwrap();

        let changed_body = frame(&[0x23], &base_fd);
        assert_ne!(
            base_preimage.bytes(),
            cursor.prepare(&changed_body).unwrap().bytes()
        );

        let mut changed_credentials_input = input(&[0x22], &base_fd);
        changed_credentials_input.credentials =
            PeerCredentialsV1::try_new(41, 1_001, 1_001, descriptor(70)).unwrap();
        let changed_credentials = WireFrameV1::try_new(changed_credentials_input).unwrap();
        assert_ne!(
            base_preimage.bytes(),
            cursor.prepare(&changed_credentials).unwrap().bytes()
        );

        let changed_fd = [campaign_input(0, false)];
        let same_raw_different_fd_state = frame(&[0x22], &changed_fd);
        assert_eq!(
            base.encode_raw_frame().unwrap(),
            same_raw_different_fd_state.encode_raw_frame().unwrap()
        );
        assert_ne!(
            base_preimage.bytes(),
            cursor
                .prepare(&same_raw_different_fd_state)
                .unwrap()
                .bytes()
        );

        let next_hash = TranscriptDigestV1::from_bytes([0x33; 32]);
        let next = base_preimage.advance_with_external_digest(next_hash);
        assert_eq!(next.next_ordinal(), 1);
        assert_eq!(next.previous_hash(), next_hash);
    }

    #[test]
    fn wire_v1_transcript_rejects_chain_drift_and_frame_limit() {
        let cursor = TranscriptCursorV1::start(SESSION_ID, PREVIOUS_HASH);

        let mut wrong_session = input(&[], &[]);
        wrong_session.session_id = [0x52; 32];
        assert_eq!(
            cursor.prepare(&WireFrameV1::try_new(wrong_session).unwrap()),
            Err(WireErrorV1::TranscriptSessionMismatch)
        );

        let mut wrong_ordinal = input(&[], &[]);
        wrong_ordinal.ordinal = 1;
        assert_eq!(
            cursor.prepare(&WireFrameV1::try_new(wrong_ordinal).unwrap()),
            Err(WireErrorV1::TranscriptOrdinalMismatch(1, 0))
        );

        let mut wrong_previous = input(&[], &[]);
        wrong_previous.previous_hash = [0xA8; 32];
        assert_eq!(
            cursor.prepare(&WireFrameV1::try_new(wrong_previous).unwrap()),
            Err(WireErrorV1::TranscriptPreviousHashMismatch)
        );

        let exhausted = TranscriptCursorV1 {
            session_id: SESSION_ID,
            next_ordinal: MAX_SESSION_FRAMES_V1,
            previous_hash: TranscriptDigestV1::from_bytes(PREVIOUS_HASH),
        };
        assert_eq!(
            exhausted.prepare(&frame(&[], &[])),
            Err(WireErrorV1::SessionFrameLimit)
        );
    }
}
