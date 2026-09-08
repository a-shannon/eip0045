//! Exhaustive, bounded ancillary receive contract.

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
use eip0045_h0_contract::wire::{DescriptorIdentityV1, SeqpacketEndpointRoleV1};
use eip0045_h0_contract::wire::{
    FdRoleV1 as ContractFdRoleV1, MAX_FRAME_BYTES_V1 as CONTRACT_MAX_FRAME_BYTES_V1,
    MAX_FRAME_FDS_V1 as CONTRACT_MAX_FRAME_FDS_V1,
};
use std::fmt;

/// Exact peer credentials required from one `SCM_CREDENTIALS` record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExpectedPeerCredentialsV1 {
    process: u32,
    user: u32,
    group: u32,
}

impl ExpectedPeerCredentialsV1 {
    /// Constructs an exact peer identity. Linux process identifiers must be
    /// positive and representable by the signed `pid_t` field in `ucred`.
    ///
    /// # Errors
    ///
    /// Returns [`AncillaryReceiveErrorV1::InvalidPeerProcessId`] when the
    /// process identifier is zero or outside the signed `pid_t` range.
    pub(crate) fn try_new(
        process_id: u32,
        user_id: u32,
        group_id: u32,
    ) -> Result<Self, AncillaryReceiveErrorV1> {
        if process_id == 0 || process_id > i32::MAX.unsigned_abs() {
            return Err(AncillaryReceiveErrorV1::InvalidPeerProcessId(process_id));
        }
        Ok(Self {
            process: process_id,
            user: user_id,
            group: group_id,
        })
    }

    /// Returns the exact expected process identifier.
    #[must_use]
    pub(crate) const fn process_id(self) -> u32 {
        self.process
    }

    /// Returns the exact expected user identifier.
    #[must_use]
    pub(crate) const fn user_id(self) -> u32 {
        self.user
    }

    /// Returns the exact expected group identifier.
    #[must_use]
    pub(crate) const fn group_id(self) -> u32 {
        self.group
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedPeerRoleV1 {
    #[allow(dead_code)] // D5-private until the same-crate G0 receive owner lands.
    Generator,
    #[allow(dead_code)] // D5-private until the same-crate G0 receive owner lands.
    Worker,
    SupervisorForGenerator,
    SupervisorForWorker,
}

/// Fixed receive expectation for one peer-specific frame boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StrictReceiveExpectationV1 {
    peer: ExpectedPeerRoleV1,
    frame_length: usize,
    credentials: ExpectedPeerCredentialsV1,
    ordered_roles: Vec<ContractFdRoleV1>,
}

impl StrictReceiveExpectationV1 {
    /// Constructs an exact generator-frame expectation.
    ///
    /// # Errors
    ///
    /// Returns [`AncillaryReceiveErrorV1`] when the frame length, descriptor
    /// count, or uniqueness of the ordered role inventory is invalid.
    #[allow(dead_code)] // D5-private until the same-crate G0 receive owner lands.
    pub(crate) fn try_for_generator(
        frame_length: usize,
        credentials: ExpectedPeerCredentialsV1,
        ordered_roles: &[ContractFdRoleV1],
    ) -> Result<Self, AncillaryReceiveErrorV1> {
        Self::try_new(
            ExpectedPeerRoleV1::Generator,
            frame_length,
            credentials,
            ordered_roles,
        )
    }

    /// Constructs an exact worker-frame expectation.
    ///
    /// # Errors
    ///
    /// Returns [`AncillaryReceiveErrorV1`] when the frame length, descriptor
    /// count, or uniqueness of the ordered role inventory is invalid.
    #[allow(dead_code)] // D5-private until the same-crate G0 receive owner lands.
    pub(crate) fn try_for_worker(
        frame_length: usize,
        credentials: ExpectedPeerCredentialsV1,
        ordered_roles: &[ContractFdRoleV1],
    ) -> Result<Self, AncillaryReceiveErrorV1> {
        Self::try_new(
            ExpectedPeerRoleV1::Worker,
            frame_length,
            credentials,
            ordered_roles,
        )
    }

    /// Constructs the exact child-side expectation for a supervisor frame on
    /// the generator channel.
    ///
    /// # Errors
    ///
    /// Returns [`AncillaryReceiveErrorV1`] when the frame length, descriptor
    /// count, or uniqueness of the ordered role inventory is invalid.
    pub(crate) fn try_for_supervisor_to_generator(
        frame_length: usize,
        credentials: ExpectedPeerCredentialsV1,
        ordered_roles: &[ContractFdRoleV1],
    ) -> Result<Self, AncillaryReceiveErrorV1> {
        Self::try_new(
            ExpectedPeerRoleV1::SupervisorForGenerator,
            frame_length,
            credentials,
            ordered_roles,
        )
    }

    /// Constructs the exact child-side expectation for a supervisor frame on
    /// the worker channel.
    ///
    /// # Errors
    ///
    /// Returns [`AncillaryReceiveErrorV1`] when the frame length, descriptor
    /// count, or uniqueness of the ordered role inventory is invalid.
    pub(crate) fn try_for_supervisor_to_worker(
        frame_length: usize,
        credentials: ExpectedPeerCredentialsV1,
        ordered_roles: &[ContractFdRoleV1],
    ) -> Result<Self, AncillaryReceiveErrorV1> {
        Self::try_new(
            ExpectedPeerRoleV1::SupervisorForWorker,
            frame_length,
            credentials,
            ordered_roles,
        )
    }

    fn try_new(
        peer: ExpectedPeerRoleV1,
        frame_length: usize,
        credentials: ExpectedPeerCredentialsV1,
        ordered_roles: &[ContractFdRoleV1],
    ) -> Result<Self, AncillaryReceiveErrorV1> {
        if !(1..=CONTRACT_MAX_FRAME_BYTES_V1).contains(&frame_length) {
            return Err(AncillaryReceiveErrorV1::FrameLengthOutOfRange(frame_length));
        }
        if ordered_roles.len() > CONTRACT_MAX_FRAME_FDS_V1 {
            return Err(AncillaryReceiveErrorV1::TooManyFds(ordered_roles.len()));
        }
        for (index, role) in ordered_roles.iter().copied().enumerate() {
            if ordered_roles[..index].contains(&role) {
                return Err(AncillaryReceiveErrorV1::DuplicateFdRole(role));
            }
        }
        Ok(Self {
            peer,
            frame_length,
            credentials,
            ordered_roles: ordered_roles.to_vec(),
        })
    }

    /// Returns the exact frame length accepted by the receive operation.
    #[must_use]
    pub(crate) const fn frame_length(&self) -> usize {
        self.frame_length
    }

    /// Returns the exact ordered semantic descriptor inventory.
    #[must_use]
    pub(crate) fn ordered_roles(&self) -> &[ContractFdRoleV1] {
        &self.ordered_roles
    }

    /// Returns the numeric peer projection only to the same-crate D4 process
    /// join, which binds it to retained child and namespace custody.
    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
    pub(crate) const fn expected_credentials_for_d4(&self) -> ExpectedPeerCredentialsV1 {
        self.credentials
    }
}

/// Failure from the role-specific strict ancillary receive boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AncillaryReceiveErrorV1 {
    /// Expected frame length was zero or above the protocol maximum.
    FrameLengthOutOfRange(usize),
    /// Expected descriptor count exceeded the protocol maximum.
    TooManyFds(usize),
    /// Expected descriptor inventory repeated one semantic role.
    DuplicateFdRole(ContractFdRoleV1),
    /// Expected Linux process identifier was zero or out of `pid_t` range.
    InvalidPeerProcessId(u32),
    /// A peer-specific receive function received an expectation for the other peer.
    PeerRoleDrift,
    /// Legacy missing-end classification retained for error-surface stability.
    /// Linux AF_UNIX `SOCK_SEQPACKET` may omit the optional `MSG_EOR` bit.
    MissingMessageEnd,
    /// The selected receive omitted proof that received descriptors were
    /// installed atomically with close-on-exec.
    MissingControlCloseOnExec,
    /// The data payload was truncated.
    MessageTruncated,
    /// The control payload was truncated.
    ControlTruncated,
    /// The kernel returned an unreviewed message flag combination.
    UnexpectedMessageFlags(u32),
    /// Actual and expected frame lengths differed, in that order.
    FrameLengthDrift(usize, usize),
    /// Control length exceeded the single fixed ancillary buffer.
    ControlLengthOutOfRange(usize),
    /// A control record used an unreviewed level and type.
    UnknownControlRecord(i32, i32),
    /// A control record header, length, padding, or payload was malformed.
    MalformedControlRecord,
    /// Credential and rights records did not occur in the sole accepted order.
    ControlRecordOrderDrift,
    /// The number of credential records differed from exactly one.
    CredentialRecordCount(usize),
    /// The received credential tuple differed from the exact peer identity.
    CredentialDrift,
    /// The number of rights records differed from the expected zero or one.
    RightsRecordCount(usize),
    /// Actual and expected descriptor counts differed, in that order.
    FdCountDrift(usize, usize),
    /// A received descriptor number was negative.
    InvalidReceivedFd(i32),
    /// The kernel returned the same installed descriptor number more than once.
    DuplicateReceivedFd(i32),
    /// Checked control-message arithmetic overflowed.
    ArithmeticOverflow,
    /// The fixed `recvmsg` operation failed with this operating-system code.
    ReceiveFailed(i32),
    /// `SO_PASSCRED` could not be reread or was not enabled on the receiver.
    PasscredNotEnabled,
    /// The retained receiver user-namespace identity changed before receive.
    ReceiverNamespaceDrift,
}

impl fmt::Display for AncillaryReceiveErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrameLengthOutOfRange(length) => {
                write!(formatter, "frame length outside fixed bounds: {length}")
            }
            Self::TooManyFds(count) => write!(formatter, "too many frame descriptors: {count}"),
            Self::DuplicateFdRole(role) => {
                write!(formatter, "duplicate descriptor role: {role:?}")
            }
            Self::InvalidPeerProcessId(process_id) => {
                write!(formatter, "invalid peer process identifier: {process_id}")
            }
            Self::PeerRoleDrift => formatter.write_str("peer-specific receive role drift"),
            Self::MissingMessageEnd => formatter.write_str("message end flag missing"),
            Self::MissingControlCloseOnExec => {
                formatter.write_str("control close-on-exec return flag missing")
            }
            Self::MessageTruncated => formatter.write_str("message payload truncated"),
            Self::ControlTruncated => formatter.write_str("message control data truncated"),
            Self::UnexpectedMessageFlags(flags) => {
                write!(formatter, "unexpected returned message flags: {flags:#x}")
            }
            Self::FrameLengthDrift(actual, expected) => {
                write!(formatter, "frame length drift: {actual} != {expected}")
            }
            Self::ControlLengthOutOfRange(length) => {
                write!(formatter, "control length outside fixed bounds: {length}")
            }
            Self::UnknownControlRecord(level, kind) => {
                write!(
                    formatter,
                    "unknown control record: level={level}, type={kind}"
                )
            }
            Self::MalformedControlRecord => formatter.write_str("malformed control record"),
            Self::ControlRecordOrderDrift => formatter.write_str("control record order drift"),
            Self::CredentialRecordCount(count) => {
                write!(formatter, "credential record count drift: {count}")
            }
            Self::CredentialDrift => formatter.write_str("peer credential drift"),
            Self::RightsRecordCount(count) => {
                write!(formatter, "rights record count drift: {count}")
            }
            Self::FdCountDrift(actual, expected) => {
                write!(formatter, "descriptor count drift: {actual} != {expected}")
            }
            Self::InvalidReceivedFd(descriptor) => {
                write!(formatter, "invalid received descriptor: {descriptor}")
            }
            Self::DuplicateReceivedFd(descriptor) => {
                write!(formatter, "duplicate installed descriptor: {descriptor}")
            }
            Self::ArithmeticOverflow => formatter.write_str("control-message arithmetic overflow"),
            Self::ReceiveFailed(code) => write!(formatter, "fixed recvmsg failed: {code}"),
            Self::PasscredNotEnabled => {
                formatter.write_str("SO_PASSCRED is not enabled on the receiving endpoint")
            }
            Self::ReceiverNamespaceDrift => {
                formatter.write_str("retained receiver user namespace drifted")
            }
        }
    }
}

impl std::error::Error for AncillaryReceiveErrorV1 {}

/// Failure while creating or rereading one closed seqpacket channel ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeqpacketEndpointErrorV1 {
    /// A selected-target socket or descriptor observation failed.
    KernelObservation,
    /// The socket domain, type, or protocol differed from the fixed tuple.
    SocketTupleDrift,
    /// The descriptor identity or socket cookie used a reserved zero value.
    InvalidIdentity,
    /// The two socketpair endpoint cookies were not distinct.
    CookieAlias,
    /// A role-specific pair used the wrong endpoint order.
    EndpointRoleDrift,
    /// `SO_PASSCRED` could not be enabled and reread on both receivers.
    PasscredNotEnabled,
    /// A complete second kernel observation differed from the first.
    ObservationDrift,
    /// The safe canonical commitment encoder rejected a fixed observation.
    CommitmentDrift,
}

impl fmt::Display for SeqpacketEndpointErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "H0 seqpacket endpoint ledger rejected: {self:?}")
    }
}

impl std::error::Error for SeqpacketEndpointErrorV1 {}

/// Consuming one-shot send failure. Every input and the sending endpoint have
/// already been dropped; the error carries no retry or resend authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AncillarySendErrorV1 {
    /// The packet was empty or exceeded the fixed frame bound.
    FrameLength,
    /// The ordered descriptor inventory exceeded the fixed bound.
    DescriptorCount,
    /// The fixed ancillary encoder could not hold the complete inventory.
    ControlEncoding,
    /// The sole kernel send operation failed; it is never retried.
    SendFailed,
    /// The kernel did not report the exact complete packet length.
    IncompleteEnqueue,
}

impl fmt::Display for AncillarySendErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "H0 one-shot ancillary send rejected: {self:?}")
    }
}

impl std::error::Error for AncillarySendErrorV1 {}

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
mod strict_model {
    use super::*;
    use core::ffi::c_void;

    const CMSG_HEADER_BYTES_V1: usize = 16;
    const UCRED_BYTES_V1: usize = 12;
    const CMSG_ALIGNMENT_V1: usize = 8;
    const MAX_CONTROL_BYTES_V1: usize = 112;
    const SOL_SOCKET_V1: i32 = 1;
    const SCM_RIGHTS_V1: i32 = 1;
    const SCM_CREDENTIALS_V1: i32 = 2;
    const MSG_CTRUNC_V1: u32 = 0x0008;
    const MSG_TRUNC_V1: u32 = 0x0020;
    const MSG_EOR_V1: u32 = 0x0080;
    const MSG_CMSG_CLOEXEC_V1: i32 = 0x4000_0000;
    const MSG_CMSG_CLOEXEC_RETURNED_V1: u32 = MSG_CMSG_CLOEXEC_V1 as u32;

    const AF_UNIX_V1: u32 = 1;
    const SOCK_SEQPACKET_V1: u32 = 5;
    const SOCKET_PROTOCOL_DEFAULT_V1: u32 = 0;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct EndpointObservationSnapshotV1 {
        role: SeqpacketEndpointRoleV1,
        descriptor_identity: DescriptorIdentityV1,
        socket_cookie: u64,
        socket_domain: u32,
        socket_type: u32,
        socket_protocol: u32,
        passcred: bool,
        nonblocking: bool,
        close_on_exec: bool,
    }

    fn validate_endpoint_observation_v1(
        snapshot: EndpointObservationSnapshotV1,
    ) -> Result<(), SeqpacketEndpointErrorV1> {
        if snapshot.socket_cookie == 0 {
            return Err(SeqpacketEndpointErrorV1::InvalidIdentity);
        }
        if snapshot.socket_domain != AF_UNIX_V1
            || snapshot.socket_type != SOCK_SEQPACKET_V1
            || snapshot.socket_protocol != SOCKET_PROTOCOL_DEFAULT_V1
        {
            return Err(SeqpacketEndpointErrorV1::SocketTupleDrift);
        }
        if !snapshot.passcred {
            return Err(SeqpacketEndpointErrorV1::PasscredNotEnabled);
        }
        Ok(())
    }

    fn validate_endpoint_pair_v1(
        first: EndpointObservationSnapshotV1,
        second: EndpointObservationSnapshotV1,
        expected_first: SeqpacketEndpointRoleV1,
        expected_second: SeqpacketEndpointRoleV1,
    ) -> Result<(), SeqpacketEndpointErrorV1> {
        validate_endpoint_observation_v1(first)?;
        validate_endpoint_observation_v1(second)?;
        if first.role != expected_first || second.role != expected_second {
            return Err(SeqpacketEndpointErrorV1::EndpointRoleDrift);
        }
        if first.socket_cookie == second.socket_cookie {
            return Err(SeqpacketEndpointErrorV1::CookieAlias);
        }
        Ok(())
    }

    fn validate_endpoint_reread_v1(
        first: EndpointObservationSnapshotV1,
        second: EndpointObservationSnapshotV1,
    ) -> Result<(), SeqpacketEndpointErrorV1> {
        validate_endpoint_observation_v1(second)?;
        if first == second {
            Ok(())
        } else {
            Err(SeqpacketEndpointErrorV1::ObservationDrift)
        }
    }

    #[cfg(test)]
    fn invoke_send_once_for_test<F>(
        frame_length: usize,
        descriptor_count: usize,
        operation: F,
    ) -> Result<(), AncillarySendErrorV1>
    where
        F: FnOnce() -> Result<usize, ()>,
    {
        if !(1..=CONTRACT_MAX_FRAME_BYTES_V1).contains(&frame_length) {
            return Err(AncillarySendErrorV1::FrameLength);
        }
        if descriptor_count > CONTRACT_MAX_FRAME_FDS_V1 {
            return Err(AncillarySendErrorV1::DescriptorCount);
        }
        match operation() {
            Ok(length) if length == frame_length => Ok(()),
            Ok(_) => Err(AncillarySendErrorV1::IncompleteEnqueue),
            Err(()) => Err(AncillarySendErrorV1::SendFailed),
        }
    }

    #[repr(C, align(8))]
    struct ControlBufferV1([u8; MAX_CONTROL_BYTES_V1]);

    #[repr(C)]
    struct IoVectorV1 {
        base: *mut c_void,
        length: usize,
    }

    #[repr(C)]
    struct MessageHeaderV1 {
        name: *mut c_void,
        name_length: u32,
        io_vectors: *mut IoVectorV1,
        io_vector_count: i32,
        io_vector_padding: i32,
        control: *mut c_void,
        control_length: u32,
        control_padding: i32,
        returned_flags: i32,
    }

    #[repr(C)]
    struct ControlMessageHeaderV1 {
        length: u32,
        padding: u32,
        level: i32,
        kind: i32,
    }

    const _: [(); MAX_CONTROL_BYTES_V1] = [(); core::mem::size_of::<ControlBufferV1>()];
    const _: [(); 8] = [(); core::mem::align_of::<ControlBufferV1>()];
    #[cfg(target_pointer_width = "64")]
    const _: [(); 16] = [(); core::mem::size_of::<IoVectorV1>()];
    #[cfg(target_pointer_width = "64")]
    const _: [(); 8] = [(); core::mem::align_of::<IoVectorV1>()];
    const _: [(); 0] = [(); core::mem::offset_of!(IoVectorV1, base)];
    #[cfg(target_pointer_width = "64")]
    const _: [(); 8] = [(); core::mem::offset_of!(IoVectorV1, length)];
    #[cfg(target_pointer_width = "64")]
    const _: [(); 56] = [(); core::mem::size_of::<MessageHeaderV1>()];
    #[cfg(target_pointer_width = "64")]
    const _: [(); 8] = [(); core::mem::align_of::<MessageHeaderV1>()];
    const _: [(); 0] = [(); core::mem::offset_of!(MessageHeaderV1, name)];
    const _: [(); 8] = [(); core::mem::offset_of!(MessageHeaderV1, name_length)];
    #[cfg(target_pointer_width = "64")]
    const _: [(); 16] = [(); core::mem::offset_of!(MessageHeaderV1, io_vectors)];
    #[cfg(target_pointer_width = "64")]
    const _: [(); 24] = [(); core::mem::offset_of!(MessageHeaderV1, io_vector_count)];
    #[cfg(target_pointer_width = "64")]
    const _: [(); 28] = [(); core::mem::offset_of!(MessageHeaderV1, io_vector_padding)];
    #[cfg(target_pointer_width = "64")]
    const _: [(); 32] = [(); core::mem::offset_of!(MessageHeaderV1, control)];
    #[cfg(target_pointer_width = "64")]
    const _: [(); 40] = [(); core::mem::offset_of!(MessageHeaderV1, control_length)];
    #[cfg(target_pointer_width = "64")]
    const _: [(); 44] = [(); core::mem::offset_of!(MessageHeaderV1, control_padding)];
    #[cfg(target_pointer_width = "64")]
    const _: [(); 48] = [(); core::mem::offset_of!(MessageHeaderV1, returned_flags)];
    const _: [(); 16] = [(); core::mem::size_of::<ControlMessageHeaderV1>()];
    const _: [(); 4] = [(); core::mem::align_of::<ControlMessageHeaderV1>()];
    const _: [(); 0] = [(); core::mem::offset_of!(ControlMessageHeaderV1, length)];
    const _: [(); 4] = [(); core::mem::offset_of!(ControlMessageHeaderV1, padding)];
    const _: [(); 8] = [(); core::mem::offset_of!(ControlMessageHeaderV1, level)];
    const _: [(); 12] = [(); core::mem::offset_of!(ControlMessageHeaderV1, kind)];

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct MessageEnvelopeV1 {
        received_length: usize,
        returned_flags: u32,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ControlRecordKindV1 {
        Credentials,
        Rights,
    }

    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    struct ParsedControlV1 {
        credentials: Vec<ExpectedPeerCredentialsV1>,
        rights_record_count: usize,
        raw_fds: Vec<i32>,
        order: Vec<ControlRecordKindV1>,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ControlParseOutcomeV1 {
        parsed: ParsedControlV1,
        error: Option<AncillaryReceiveErrorV1>,
    }

    impl ControlParseOutcomeV1 {
        fn record_error(&mut self, error: AncillaryReceiveErrorV1) {
            if self.error.is_none() {
                self.error = Some(error);
            }
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ValidatedAncillaryV1 {
        credentials: ExpectedPeerCredentialsV1,
        raw_fds: Vec<i32>,
        ordered_roles: Vec<ContractFdRoleV1>,
    }

    impl ValidatedAncillaryV1 {
        #[cfg(test)]
        #[must_use]
        const fn credentials(&self) -> ExpectedPeerCredentialsV1 {
            self.credentials
        }

        #[must_use]
        fn raw_fds(&self) -> &[i32] {
            &self.raw_fds
        }

        #[must_use]
        fn ordered_roles(&self) -> &[ContractFdRoleV1] {
            &self.ordered_roles
        }
    }

    fn cmsg_align_v1(value: usize) -> Result<usize, AncillaryReceiveErrorV1> {
        value
            .checked_add(CMSG_ALIGNMENT_V1 - 1)
            .map(|candidate| candidate & !(CMSG_ALIGNMENT_V1 - 1))
            .ok_or(AncillaryReceiveErrorV1::ArithmeticOverflow)
    }

    fn read_u32_v1(bytes: &[u8]) -> Result<u32, AncillaryReceiveErrorV1> {
        let array = <[u8; 4]>::try_from(bytes)
            .map_err(|_| AncillaryReceiveErrorV1::MalformedControlRecord)?;
        Ok(u32::from_le_bytes(array))
    }

    fn read_i32_v1(bytes: &[u8]) -> Result<i32, AncillaryReceiveErrorV1> {
        let array = <[u8; 4]>::try_from(bytes)
            .map_err(|_| AncillaryReceiveErrorV1::MalformedControlRecord)?;
        Ok(i32::from_le_bytes(array))
    }

    fn parse_record_payload_v1(
        outcome: &mut ControlParseOutcomeV1,
        level: i32,
        kind: i32,
        payload: &[u8],
    ) {
        match (level, kind) {
            (SOL_SOCKET_V1, SCM_CREDENTIALS_V1) => {
                outcome.parsed.order.push(ControlRecordKindV1::Credentials);
                if payload.len() != UCRED_BYTES_V1 {
                    outcome.record_error(AncillaryReceiveErrorV1::MalformedControlRecord);
                    return;
                }
                let process_id = read_u32_v1(&payload[..4]);
                let user_id = read_u32_v1(&payload[4..8]);
                let group_id = read_u32_v1(&payload[8..12]);
                match (process_id, user_id, group_id) {
                    (Ok(process_id), Ok(user_id), Ok(group_id)) => {
                        match ExpectedPeerCredentialsV1::try_new(process_id, user_id, group_id) {
                            Ok(credentials) => outcome.parsed.credentials.push(credentials),
                            Err(error) => outcome.record_error(error),
                        }
                    }
                    _ => outcome.record_error(AncillaryReceiveErrorV1::MalformedControlRecord),
                }
            }
            (SOL_SOCKET_V1, SCM_RIGHTS_V1) => {
                outcome.parsed.order.push(ControlRecordKindV1::Rights);
                outcome.parsed.rights_record_count += 1;
                if payload.is_empty() || !payload.len().is_multiple_of(size_of::<i32>()) {
                    outcome.record_error(AncillaryReceiveErrorV1::MalformedControlRecord);
                    return;
                }
                for encoded in payload.chunks_exact(size_of::<i32>()) {
                    match read_i32_v1(encoded) {
                        Ok(descriptor) if descriptor >= 0 => {
                            outcome.parsed.raw_fds.push(descriptor);
                        }
                        Ok(descriptor) => outcome
                            .record_error(AncillaryReceiveErrorV1::InvalidReceivedFd(descriptor)),
                        Err(error) => outcome.record_error(error),
                    }
                }
            }
            _ => outcome.record_error(AncillaryReceiveErrorV1::UnknownControlRecord(level, kind)),
        }
    }

    fn parse_control_v1(control: &[u8]) -> ControlParseOutcomeV1 {
        let mut outcome = ControlParseOutcomeV1 {
            parsed: ParsedControlV1::default(),
            error: None,
        };
        if control.len() > MAX_CONTROL_BYTES_V1 {
            outcome.record_error(AncillaryReceiveErrorV1::ControlLengthOutOfRange(
                control.len(),
            ));
            return outcome;
        }

        let mut offset = 0_usize;
        while offset < control.len() {
            let Some(header_end) = offset.checked_add(CMSG_HEADER_BYTES_V1) else {
                outcome.record_error(AncillaryReceiveErrorV1::ArithmeticOverflow);
                break;
            };
            let Some(header) = control.get(offset..header_end) else {
                outcome.record_error(AncillaryReceiveErrorV1::MalformedControlRecord);
                break;
            };
            let Ok(record_length_u32) = read_u32_v1(&header[..4]) else {
                outcome.record_error(AncillaryReceiveErrorV1::MalformedControlRecord);
                break;
            };
            let Ok(record_length) = usize::try_from(record_length_u32) else {
                outcome.record_error(AncillaryReceiveErrorV1::ArithmeticOverflow);
                break;
            };
            if record_length < CMSG_HEADER_BYTES_V1 {
                outcome.record_error(AncillaryReceiveErrorV1::MalformedControlRecord);
                break;
            }
            let Some(record_end) = offset.checked_add(record_length) else {
                outcome.record_error(AncillaryReceiveErrorV1::ArithmeticOverflow);
                break;
            };
            let Ok(aligned_length) = cmsg_align_v1(record_length) else {
                outcome.record_error(AncillaryReceiveErrorV1::ArithmeticOverflow);
                break;
            };
            let Some(aligned_end) = offset.checked_add(aligned_length) else {
                outcome.record_error(AncillaryReceiveErrorV1::ArithmeticOverflow);
                break;
            };
            if record_end > control.len() || aligned_end > control.len() {
                outcome.record_error(AncillaryReceiveErrorV1::MalformedControlRecord);
                break;
            }
            if header[4..8].iter().any(|byte| *byte != 0)
                || control[record_end..aligned_end]
                    .iter()
                    .any(|byte| *byte != 0)
            {
                outcome.record_error(AncillaryReceiveErrorV1::MalformedControlRecord);
            }
            let Ok(level) = read_i32_v1(&header[8..12]) else {
                outcome.record_error(AncillaryReceiveErrorV1::MalformedControlRecord);
                break;
            };
            let Ok(kind) = read_i32_v1(&header[12..16]) else {
                outcome.record_error(AncillaryReceiveErrorV1::MalformedControlRecord);
                break;
            };
            let payload = &control[header_end..record_end];
            parse_record_payload_v1(&mut outcome, level, kind, payload);
            offset = aligned_end;
        }
        outcome
    }

    fn validate_envelope_v1(
        expectation: &StrictReceiveExpectationV1,
        envelope: MessageEnvelopeV1,
    ) -> Result<(), AncillaryReceiveErrorV1> {
        if envelope.returned_flags & MSG_TRUNC_V1 != 0 {
            return Err(AncillaryReceiveErrorV1::MessageTruncated);
        }
        if envelope.returned_flags & MSG_CTRUNC_V1 != 0 {
            return Err(AncillaryReceiveErrorV1::ControlTruncated);
        }
        if envelope.returned_flags & MSG_CMSG_CLOEXEC_RETURNED_V1 == 0 {
            return Err(AncillaryReceiveErrorV1::MissingControlCloseOnExec);
        }
        // Linux AF_UNIX `SOCK_SEQPACKET` preserves one-record-per-receive
        // boundaries but may omit `MSG_EOR` even when the sender supplied it.
        // Exact length plus the truncation checks above close that boundary;
        // the mandatory CMSG_CLOEXEC reflection and optional EOR bit are the
        // only reviewed return states.
        let reviewed_flags = MSG_CMSG_CLOEXEC_RETURNED_V1 | MSG_EOR_V1;
        if envelope.returned_flags & !reviewed_flags != 0 {
            return Err(AncillaryReceiveErrorV1::UnexpectedMessageFlags(
                envelope.returned_flags,
            ));
        }
        if envelope.received_length != expectation.frame_length {
            return Err(AncillaryReceiveErrorV1::FrameLengthDrift(
                envelope.received_length,
                expectation.frame_length,
            ));
        }
        Ok(())
    }

    fn validate_parsed_v1(
        expectation: &StrictReceiveExpectationV1,
        envelope: MessageEnvelopeV1,
        outcome: &ControlParseOutcomeV1,
    ) -> Result<ValidatedAncillaryV1, AncillaryReceiveErrorV1> {
        validate_envelope_v1(expectation, envelope)?;
        if let Some(error) = outcome.error {
            return Err(error);
        }
        let parsed = &outcome.parsed;
        if parsed.credentials.len() != 1 {
            return Err(AncillaryReceiveErrorV1::CredentialRecordCount(
                parsed.credentials.len(),
            ));
        }
        let expected_rights_count = usize::from(!expectation.ordered_roles.is_empty());
        if parsed.rights_record_count != expected_rights_count {
            return Err(AncillaryReceiveErrorV1::RightsRecordCount(
                parsed.rights_record_count,
            ));
        }
        let order_matches = if expected_rights_count == 0 {
            parsed.order.as_slice() == [ControlRecordKindV1::Credentials]
        } else {
            parsed.order.as_slice()
                == [
                    ControlRecordKindV1::Credentials,
                    ControlRecordKindV1::Rights,
                ]
        };
        if !order_matches {
            return Err(AncillaryReceiveErrorV1::ControlRecordOrderDrift);
        }
        if parsed.credentials[0] != expectation.credentials {
            return Err(AncillaryReceiveErrorV1::CredentialDrift);
        }
        if parsed.raw_fds.len() != expectation.ordered_roles.len() {
            return Err(AncillaryReceiveErrorV1::FdCountDrift(
                parsed.raw_fds.len(),
                expectation.ordered_roles.len(),
            ));
        }
        Ok(ValidatedAncillaryV1 {
            credentials: parsed.credentials[0],
            raw_fds: parsed.raw_fds.clone(),
            ordered_roles: expectation.ordered_roles.clone(),
        })
    }

    #[cfg(test)]
    fn validate_strict_observation_v1(
        expectation: &StrictReceiveExpectationV1,
        envelope: MessageEnvelopeV1,
        control: &[u8],
    ) -> Result<ValidatedAncillaryV1, AncillaryReceiveErrorV1> {
        let outcome = parse_control_v1(control);
        validate_parsed_v1(expectation, envelope, &outcome)
    }

    fn validate_expected_peer_role_v1(
        expectation: &StrictReceiveExpectationV1,
        actual: ExpectedPeerRoleV1,
    ) -> Result<(), AncillaryReceiveErrorV1> {
        if expectation.peer == actual {
            Ok(())
        } else {
            Err(AncillaryReceiveErrorV1::PeerRoleDrift)
        }
    }

    #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
    pub(super) mod selected_target {
        use super::*;
        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        use crate::process::{WORKER_OUTER_GID_V1, WORKER_OUTER_UID_V1};
        use eip0045_h0_contract::wire::{
            ChannelIdentityV1, ProviderSessionMaterialV1, SeqpacketEndpointCommitmentV1,
        };
        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        use eip0045_h0_contract::wire::{
            FdAccessV1, FdStatusV1, G0_CLOSED_RESULT_RAW_FRAME_BYTES_V1,
            G0_FINAL_RESULT_MAX_BYTES_V1, G0_PRE_SESSION_RECORD_BYTES_V1,
            G0_SESSION_OFFER_BYTES_V1, G0ClosedResultInboundInputV1, G0ClosedResultVerifiedV1,
            G0GeneratorBoundAwaitClosedResultV1, G0GeneratorBoundOutboundCandidateV1,
            G0GeneratorBoundTranscriptCandidateV1, G0GeneratorCommitRecordV1,
            G0GeneratorPeerLocalFactsV1, G0GeneratorPeerSessionCandidateV1,
            G0GeneratorPeerSessionInputV1, G0GeneratorRevealRecordV1, G0TranscriptCandidateV1,
            G0WorkerBootstrapContentVerifierV1, G0WorkerBootstrapInboundCandidateV1,
            G0WorkerBootstrapInboundInputV1, GeneratorSealProfileV1, MemfdSealsV1,
            PeerCredentialsV1, ProcessInventoryV1, SealPresenceV1, SealedIngressManifestV1,
            WireErrorV1, WireFrameV1,
        };
        use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
        use rustix::fs::{
            CWD, Dir, Mode, OFlags, PROC_SUPER_MAGIC, SealFlags, fcntl_get_seals, fcntl_getfl,
            fstat, fstatfs, openat,
        };
        use rustix::io::{FdFlags, fcntl_dupfd_cloexec, fcntl_getfd, fcntl_setfd, pread};
        use rustix::net::sockopt::{
            set_socket_passcred, socket_cookie, socket_domain, socket_passcred, socket_protocol,
            socket_type,
        };
        use rustix::net::{
            AddressFamily, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags,
            SocketType, UCred, socketpair,
        };
        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        use rustix::process::{Resource, getgid, getpid, getppid, getrlimit, getuid};
        use std::fs::{File, read_link};
        use std::io::IoSlice;
        use std::mem::MaybeUninit;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::ptr::null_mut;
        #[cfg(test)]
        use std::sync::atomic::AtomicUsize;
        use std::sync::atomic::{AtomicBool, Ordering};

        unsafe extern "C" {
            #[link_name = "recvmsg"]
            fn c_recvmsg(socket: i32, message: *mut MessageHeaderV1, flags: i32) -> isize;
        }

        /// Terminal failure while adopting the sole inherited child endpoint.
        pub struct InheritedEndpointAdoptionErrorV1 {
            _private: (),
        }

        impl InheritedEndpointAdoptionErrorV1 {
            const fn terminal() -> Self {
                Self { _private: () }
            }
        }

        impl fmt::Debug for InheritedEndpointAdoptionErrorV1 {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("InheritedEndpointAdoptionErrorV1")
            }
        }

        impl fmt::Display for InheritedEndpointAdoptionErrorV1 {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("inherited endpoint adoption rejected")
            }
        }

        impl std::error::Error for InheritedEndpointAdoptionErrorV1 {}

        /// Terminal failure after a typed child send consumes its endpoint.
        pub struct ChildTypedSendErrorV1 {
            _private: (),
        }

        impl ChildTypedSendErrorV1 {
            const fn terminal() -> Self {
                Self { _private: () }
            }
        }

        impl fmt::Debug for ChildTypedSendErrorV1 {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("ChildTypedSendErrorV1")
            }
        }

        impl fmt::Display for ChildTypedSendErrorV1 {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("typed child send rejected")
            }
        }

        impl std::error::Error for ChildTypedSendErrorV1 {}

        /// Terminal failure after a typed child receive consumes its endpoint.
        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub struct ChildTypedReceiveErrorV1 {
            _private: (),
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        impl ChildTypedReceiveErrorV1 {
            const fn terminal() -> Self {
                Self { _private: () }
            }
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        impl fmt::Debug for ChildTypedReceiveErrorV1 {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("ChildTypedReceiveErrorV1")
            }
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        impl fmt::Display for ChildTypedReceiveErrorV1 {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("typed child receive rejected")
            }
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        impl std::error::Error for ChildTypedReceiveErrorV1 {}

        static INHERITED_ENDPOINT_ADOPTION_ATTEMPTED_V1: AtomicBool = AtomicBool::new(false);
        #[cfg(test)]
        static ENDPOINT_OBSERVATION_CALLS_V1: AtomicUsize = AtomicUsize::new(0);

        struct SeqpacketEndpointV1 {
            descriptor: OwnedFd,
            commitment: SeqpacketEndpointCommitmentV1,
        }

        enum SendCredentialSourceV1 {
            AutomaticChild,
            ExplicitSupervisor(UCred),
        }

        struct PreparedSupervisorSendV1 {
            frame: Box<[u8]>,
            descriptors: Vec<OwnedFd>,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        struct PreparedSupervisorReceiveV1 {
            frame: Box<[u8]>,
            expectation: StrictReceiveExpectationV1,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub(crate) struct SessionOfferSendInputV1 {
            prepared: PreparedSupervisorSendV1,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub(crate) struct GeneratorCommitReceiveInputV1 {
            prepared: PreparedSupervisorReceiveV1,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub(crate) struct SupervisorCommitSendInputV1 {
            prepared: PreparedSupervisorSendV1,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub(crate) struct GeneratorRevealReceiveInputV1 {
            prepared: PreparedSupervisorReceiveV1,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub(crate) struct SupervisorRevealSendInputV1 {
            prepared: PreparedSupervisorSendV1,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        enum UninhabitedSupervisorSemanticJoinV1 {}

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub(crate) struct GeneratorBoundReceiveInputV1 {
            prepared: PreparedSupervisorReceiveV1,
            session: ProviderSessionMaterialV1,
            frame: WireFrameV1,
            _seal: UninhabitedSupervisorSemanticJoinV1,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub(crate) struct WorkerBootstrapSendInputV1 {
            prepared: PreparedSupervisorSendV1,
            session: ProviderSessionMaterialV1,
            frame: WireFrameV1,
            _seal: UninhabitedSupervisorSemanticJoinV1,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub(crate) struct WorkerExecBoundReceiveInputV1 {
            prepared: PreparedSupervisorReceiveV1,
            session: ProviderSessionMaterialV1,
            frame: WireFrameV1,
            _seal: UninhabitedSupervisorSemanticJoinV1,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub(crate) struct ClosedResultSendInputV1 {
            prepared: PreparedSupervisorSendV1,
            session: ProviderSessionMaterialV1,
            frame: WireFrameV1,
            _seal: UninhabitedSupervisorSemanticJoinV1,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub(crate) struct SupervisorTypedTransitionErrorV1 {
            _private: (),
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        impl SupervisorTypedTransitionErrorV1 {
            fn terminal() -> Self {
                Self { _private: () }
            }
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        impl From<AncillaryReceiveErrorV1> for SupervisorTypedTransitionErrorV1 {
            fn from(_: AncillaryReceiveErrorV1) -> Self {
                Self::terminal()
            }
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        impl From<WireErrorV1> for SupervisorTypedTransitionErrorV1 {
            fn from(_: WireErrorV1) -> Self {
                Self::terminal()
            }
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        enum SupervisorGeneratorSendPhaseV1 {
            AwaitGeneratorCommit,
            AwaitGeneratorReveal,
            AwaitGeneratorBound,
            ClosedResult,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub(crate) struct GeneratorCommitReceivedEndpointV1 {
            endpoint: SeqpacketEndpointV1,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub(crate) struct GeneratorRevealReceivedEndpointV1 {
            endpoint: SeqpacketEndpointV1,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub(crate) struct GeneratorBoundReceivedEndpointV1 {
            endpoint: SeqpacketEndpointV1,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub(crate) struct WorkerExecBoundReceivedEndpointV1 {
            endpoint: SeqpacketEndpointV1,
        }

        /// Consuming generator state awaiting the exact supervisor offer.
        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub struct GeneratorPeerSessionOfferEndpointV1 {
            endpoint: GeneratorEndpointV1,
            local_facts: G0GeneratorPeerLocalFactsV1,
        }

        /// Consuming generator state allowed to calculate and enqueue GCommit.
        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub struct GeneratorPeerGCommitSendEndpointV1 {
            endpoint: GeneratorEndpointV1,
            local_facts: G0GeneratorPeerLocalFactsV1,
            session_offer_raw: [u8; G0_SESSION_OFFER_BYTES_V1],
            supervisor_pid: u32,
            supervisor_receiver_user_namespace: DescriptorIdentityV1,
        }

        /// Consuming generator state awaiting the exact supervisor commitment.
        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub struct GeneratorPeerSCommitReceiveEndpointV1 {
            endpoint: GeneratorEndpointV1,
            local_facts: G0GeneratorPeerLocalFactsV1,
            session_offer_raw: [u8; G0_SESSION_OFFER_BYTES_V1],
            generator_commit: G0GeneratorCommitRecordV1,
            supervisor_pid: u32,
            supervisor_receiver_user_namespace: DescriptorIdentityV1,
        }

        /// Consuming generator state allowed to calculate and enqueue GReveal.
        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub struct GeneratorPeerGRevealSendEndpointV1 {
            endpoint: GeneratorEndpointV1,
            local_facts: G0GeneratorPeerLocalFactsV1,
            session_offer_raw: [u8; G0_SESSION_OFFER_BYTES_V1],
            generator_commit: G0GeneratorCommitRecordV1,
            supervisor_commit_raw: [u8; G0_PRE_SESSION_RECORD_BYTES_V1],
            supervisor_pid: u32,
            supervisor_receiver_user_namespace: DescriptorIdentityV1,
        }

        /// Consuming generator state awaiting the exact supervisor reveal.
        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub struct GeneratorPeerSRevealReceiveEndpointV1 {
            endpoint: GeneratorEndpointV1,
            local_facts: G0GeneratorPeerLocalFactsV1,
            session_offer_raw: [u8; G0_SESSION_OFFER_BYTES_V1],
            generator_commit: G0GeneratorCommitRecordV1,
            supervisor_commit_raw: [u8; G0_PRE_SESSION_RECORD_BYTES_V1],
            generator_reveal: G0GeneratorRevealRecordV1,
            supervisor_pid: u32,
            supervisor_receiver_user_namespace: DescriptorIdentityV1,
        }

        /// Opaque endpoint plus complete provider-session candidate after SReveal.
        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub struct GeneratorProviderSessionEndpointV1 {
            endpoint: GeneratorEndpointV1,
            candidate: G0GeneratorPeerSessionCandidateV1,
            supervisor_pid: u32,
            supervisor_receiver_user_namespace: DescriptorIdentityV1,
        }

        /// Borrowed semantic inputs for the sole consuming `GeneratorBound` send.
        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub struct GeneratorBoundSendInputV1<'a> {
            seal_profile: &'a GeneratorSealProfileV1,
            inventory: &'a ProcessInventoryV1,
            ingress: &'a SealedIngressManifestV1,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        impl<'a> GeneratorBoundSendInputV1<'a> {
            /// Binds the exact post-exec generator observations to the one send.
            #[must_use]
            pub const fn new(
                seal_profile: &'a GeneratorSealProfileV1,
                inventory: &'a ProcessInventoryV1,
                ingress: &'a SealedIngressManifestV1,
            ) -> Self {
                Self {
                    seal_profile,
                    inventory,
                    ingress,
                }
            }
        }

        /// Opaque same-endpoint custody awaiting one terminal `ClosedResult`.
        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub struct GeneratorBoundAwaitClosedResultEndpointV1 {
            endpoint: SeqpacketEndpointV1,
            await_closed_result: G0GeneratorBoundAwaitClosedResultV1,
            supervisor_pid: u32,
            supervisor_receiver_user_namespace: DescriptorIdentityV1,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        fn generator_outbound_credentials_v1() -> Result<PeerCredentialsV1, ChildTypedSendErrorV1> {
            let process_id = u32::try_from(getpid().as_raw_nonzero().get())
                .map_err(|_| ChildTypedSendErrorV1::terminal())?;
            let namespace =
                File::open("/proc/self/ns/user").map_err(|_| ChildTypedSendErrorV1::terminal())?;
            let user_namespace = descriptor_identity_v1(namespace.as_fd())
                .map_err(|_| ChildTypedSendErrorV1::terminal())?;
            PeerCredentialsV1::try_new(
                process_id,
                getuid().as_raw(),
                getgid().as_raw(),
                user_namespace,
            )
            .map_err(|_| ChildTypedSendErrorV1::terminal())
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        fn observed_supervisor_credentials_v1(
            observed: ExpectedPeerCredentialsV1,
            user_namespace: DescriptorIdentityV1,
        ) -> Result<PeerCredentialsV1, ChildTypedReceiveErrorV1> {
            PeerCredentialsV1::try_new(
                observed.process_id(),
                observed.user_id(),
                observed.group_id(),
                user_namespace,
            )
            .map_err(|_| ChildTypedReceiveErrorV1::terminal())
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        const WORKER_BOOTSTRAP_FINAL_FIRST_FD_V1: i32 = 4;
        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        const WORKER_BOOTSTRAP_TEMP_FIRST_FD_V1: i32 = 22;
        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        const WORKER_BOOTSTRAP_RLIMIT_NOFILE_MIN_V1: u64 = 38;

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        struct WorkerBootstrapPreflightErrorV1 {
            _private: (),
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        impl WorkerBootstrapPreflightErrorV1 {
            const fn terminal() -> Self {
                Self { _private: () }
            }
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        struct WorkerBootstrapNormalizedFdCustodyV1 {
            descriptors: Vec<OwnedFd>,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        const fn worker_bootstrap_rlimit_nofile_accepts_v1(current: Option<u64>) -> bool {
            match current {
                None => true,
                Some(limit) => limit >= WORKER_BOOTSTRAP_RLIMIT_NOFILE_MIN_V1,
            }
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        fn require_worker_bootstrap_rlimit_nofile_v1() -> Result<(), WorkerBootstrapPreflightErrorV1>
        {
            if worker_bootstrap_rlimit_nofile_accepts_v1(getrlimit(Resource::Nofile).current) {
                Ok(())
            } else {
                Err(WorkerBootstrapPreflightErrorV1::terminal())
            }
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        fn normalize_worker_bootstrap_descriptors_v1(
            originals: Vec<OwnedFd>,
        ) -> Result<WorkerBootstrapNormalizedFdCustodyV1, WorkerBootstrapPreflightErrorV1> {
            if originals.is_empty() || originals.len() > CONTRACT_MAX_FRAME_FDS_V1 {
                return Err(WorkerBootstrapPreflightErrorV1::terminal());
            }

            let mut temporaries = Vec::new();
            temporaries
                .try_reserve_exact(originals.len())
                .map_err(|_| WorkerBootstrapPreflightErrorV1::terminal())?;
            for (index, original) in originals.iter().enumerate() {
                let expected = WORKER_BOOTSTRAP_TEMP_FIRST_FD_V1
                    .checked_add(
                        i32::try_from(index)
                            .map_err(|_| WorkerBootstrapPreflightErrorV1::terminal())?,
                    )
                    .ok_or_else(WorkerBootstrapPreflightErrorV1::terminal)?;
                let temporary = fcntl_dupfd_cloexec(original.as_fd(), expected)
                    .map_err(|_| WorkerBootstrapPreflightErrorV1::terminal())?;
                if temporary.as_raw_fd() != expected {
                    return Err(WorkerBootstrapPreflightErrorV1::terminal());
                }
                temporaries.push(temporary);
            }

            drop(originals);

            let mut finals = Vec::new();
            finals
                .try_reserve_exact(temporaries.len())
                .map_err(|_| WorkerBootstrapPreflightErrorV1::terminal())?;
            for (index, temporary) in temporaries.iter().enumerate() {
                let expected = WORKER_BOOTSTRAP_FINAL_FIRST_FD_V1
                    .checked_add(
                        i32::try_from(index)
                            .map_err(|_| WorkerBootstrapPreflightErrorV1::terminal())?,
                    )
                    .ok_or_else(WorkerBootstrapPreflightErrorV1::terminal)?;
                let final_descriptor = fcntl_dupfd_cloexec(temporary.as_fd(), expected)
                    .map_err(|_| WorkerBootstrapPreflightErrorV1::terminal())?;
                if final_descriptor.as_raw_fd() != expected {
                    return Err(WorkerBootstrapPreflightErrorV1::terminal());
                }
                finals.push(final_descriptor);
            }

            drop(temporaries);
            Ok(WorkerBootstrapNormalizedFdCustodyV1 {
                descriptors: finals,
            })
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        #[derive(Debug, Eq, PartialEq)]
        enum WorkerBootstrapPreflightRoleV1 {
            Observation,
            CampaignInput(u8),
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        #[derive(Debug, Eq, PartialEq)]
        struct WorkerBootstrapPhysicalPreflightV1 {
            device: u64,
            inode: u64,
            mode: u32,
            byte_length: u64,
            descriptor_flags: FdFlags,
            status_flags: OFlags,
            seals: SealFlags,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        struct WorkerBootstrapRolePreflightCustodyV1 {
            role: WorkerBootstrapPreflightRoleV1,
            descriptor: OwnedFd,
            physical: WorkerBootstrapPhysicalPreflightV1,
            _content_verifier: G0WorkerBootstrapContentVerifierV1,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        struct WorkerBootstrapPreflightCandidateCustodyV1 {
            candidate: G0WorkerBootstrapInboundCandidateV1,
            descriptor_count: usize,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        struct WorkerBootstrapNormalizedCustodyV1 {
            candidate: G0WorkerBootstrapInboundCandidateV1,
            roles: Vec<WorkerBootstrapRolePreflightCustodyV1>,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        fn checked_worker_bootstrap_size_v1(
            size: i64,
        ) -> Result<u64, WorkerBootstrapPreflightErrorV1> {
            u64::try_from(size).map_err(|_| WorkerBootstrapPreflightErrorV1::terminal())
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        const fn worker_bootstrap_seal_presence_v1(present: bool) -> SealPresenceV1 {
            if present {
                SealPresenceV1::Present
            } else {
                SealPresenceV1::Absent
            }
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        fn worker_bootstrap_memfd_seals_v1(
            seals: SealFlags,
        ) -> Result<MemfdSealsV1, WorkerBootstrapPreflightErrorV1> {
            let known = SealFlags::GROW | SealFlags::SHRINK | SealFlags::WRITE | SealFlags::SEAL;
            if seals.bits() & !known.bits() != 0 {
                return Err(WorkerBootstrapPreflightErrorV1::terminal());
            }
            Ok(MemfdSealsV1::new(
                worker_bootstrap_seal_presence_v1(seals.contains(SealFlags::GROW)),
                worker_bootstrap_seal_presence_v1(seals.contains(SealFlags::SHRINK)),
                worker_bootstrap_seal_presence_v1(seals.contains(SealFlags::WRITE)),
                worker_bootstrap_seal_presence_v1(seals.contains(SealFlags::SEAL)),
            ))
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        fn worker_bootstrap_fd_status_v1(
            descriptor_flags: FdFlags,
            status_flags: OFlags,
        ) -> Result<FdStatusV1, WorkerBootstrapPreflightErrorV1> {
            let access = match status_flags & OFlags::ACCMODE {
                OFlags::RDONLY => FdAccessV1::ReadOnly,
                OFlags::WRONLY => FdAccessV1::WriteOnly,
                OFlags::RDWR => FdAccessV1::ReadWrite,
                _ => return Err(WorkerBootstrapPreflightErrorV1::terminal()),
            };
            Ok(FdStatusV1::new(
                access,
                status_flags.contains(OFlags::NONBLOCK),
                descriptor_flags.contains(FdFlags::CLOEXEC),
            ))
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        fn observe_worker_bootstrap_physical_preflight_v1(
            candidate: &G0WorkerBootstrapInboundCandidateV1,
            role: WorkerBootstrapPreflightRoleV1,
            descriptor: OwnedFd,
        ) -> Result<WorkerBootstrapRolePreflightCustodyV1, WorkerBootstrapPreflightErrorV1>
        {
            let descriptor_flags = fcntl_getfd(descriptor.as_fd())
                .map_err(|_| WorkerBootstrapPreflightErrorV1::terminal())?;
            let status_flags = fcntl_getfl(descriptor.as_fd())
                .map_err(|_| WorkerBootstrapPreflightErrorV1::terminal())?;
            let metadata = fstat(descriptor.as_fd())
                .map_err(|_| WorkerBootstrapPreflightErrorV1::terminal())?;
            if !rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_file() {
                return Err(WorkerBootstrapPreflightErrorV1::terminal());
            }
            let byte_length = checked_worker_bootstrap_size_v1(metadata.st_size)?;
            let seals = fcntl_get_seals(descriptor.as_fd())
                .map_err(|_| WorkerBootstrapPreflightErrorV1::terminal())?;
            let observed_status = worker_bootstrap_fd_status_v1(descriptor_flags, status_flags)?;
            let observed_seals = worker_bootstrap_memfd_seals_v1(seals)?;
            let content_verifier = match &role {
                WorkerBootstrapPreflightRoleV1::Observation => candidate
                    .start_observation_content_verifier_v1(
                        byte_length,
                        observed_status,
                        observed_seals,
                    ),
                WorkerBootstrapPreflightRoleV1::CampaignInput(index) => candidate
                    .start_campaign_input_content_verifier_v1(
                        *index,
                        byte_length,
                        observed_status,
                        observed_seals,
                    ),
            }
            .map_err(|_| WorkerBootstrapPreflightErrorV1::terminal())?;
            Ok(WorkerBootstrapRolePreflightCustodyV1 {
                role,
                descriptor,
                physical: WorkerBootstrapPhysicalPreflightV1 {
                    device: metadata.st_dev,
                    inode: metadata.st_ino,
                    mode: metadata.st_mode,
                    byte_length,
                    descriptor_flags,
                    status_flags,
                    seals,
                },
                _content_verifier: content_verifier,
            })
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        fn bind_worker_bootstrap_normalized_custody_v1(
            candidate_custody: WorkerBootstrapPreflightCandidateCustodyV1,
            normalized: WorkerBootstrapNormalizedFdCustodyV1,
        ) -> Result<WorkerBootstrapNormalizedCustodyV1, WorkerBootstrapPreflightErrorV1> {
            let WorkerBootstrapPreflightCandidateCustodyV1 {
                candidate,
                descriptor_count,
            } = candidate_custody;
            if descriptor_count == 0
                || descriptor_count > CONTRACT_MAX_FRAME_FDS_V1
                || normalized.descriptors.len() != descriptor_count
            {
                return Err(WorkerBootstrapPreflightErrorV1::terminal());
            }
            let mut roles = Vec::new();
            roles
                .try_reserve_exact(normalized.descriptors.len())
                .map_err(|_| WorkerBootstrapPreflightErrorV1::terminal())?;
            for (index, descriptor) in normalized.descriptors.into_iter().enumerate() {
                let role = if index == 0 {
                    WorkerBootstrapPreflightRoleV1::Observation
                } else {
                    WorkerBootstrapPreflightRoleV1::CampaignInput(
                        u8::try_from(index - 1)
                            .map_err(|_| WorkerBootstrapPreflightErrorV1::terminal())?,
                    )
                };
                roles.push(observe_worker_bootstrap_physical_preflight_v1(
                    &candidate, role, descriptor,
                )?);
            }
            Ok(WorkerBootstrapNormalizedCustodyV1 { candidate, roles })
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        fn join_worker_bootstrap_post_receive_v1(
            input: G0WorkerBootstrapInboundInputV1<'_>,
            received_rights: Vec<OwnedFd>,
        ) -> Result<WorkerBootstrapNormalizedCustodyV1, WorkerBootstrapPreflightErrorV1> {
            require_worker_bootstrap_rlimit_nofile_v1()?;
            let descriptor_count = input.actual_rights_count;
            if descriptor_count == 0
                || descriptor_count > CONTRACT_MAX_FRAME_FDS_V1
                || received_rights.len() != descriptor_count
            {
                return Err(WorkerBootstrapPreflightErrorV1::terminal());
            }
            let candidate = G0WorkerBootstrapInboundCandidateV1::try_new(input)
                .map_err(|_| WorkerBootstrapPreflightErrorV1::terminal())?;
            let normalized = normalize_worker_bootstrap_descriptors_v1(received_rights)?;
            bind_worker_bootstrap_normalized_custody_v1(
                WorkerBootstrapPreflightCandidateCustodyV1 {
                    candidate,
                    descriptor_count,
                },
                normalized,
            )
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        #[derive(Eq, PartialEq)]
        struct FinalResultPhysicalObservationV1 {
            device: u64,
            inode: u64,
            mode: u32,
            byte_length: usize,
            descriptor_flags: FdFlags,
            status_flags: OFlags,
            seals: SealFlags,
            descriptor_link: std::path::PathBuf,
            bytes: Box<[u8]>,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        fn observe_final_result_physical_pass_v1(
            descriptor: &OwnedFd,
        ) -> Result<FinalResultPhysicalObservationV1, ChildTypedReceiveErrorV1> {
            let descriptor_flags = fcntl_getfd(descriptor.as_fd())
                .map_err(|_| ChildTypedReceiveErrorV1::terminal())?;
            if !descriptor_flags.contains(FdFlags::CLOEXEC) {
                return Err(ChildTypedReceiveErrorV1::terminal());
            }
            let status_flags = fcntl_getfl(descriptor.as_fd())
                .map_err(|_| ChildTypedReceiveErrorV1::terminal())?;
            if status_flags & OFlags::ACCMODE != OFlags::RDONLY
                || status_flags.contains(OFlags::NONBLOCK)
            {
                return Err(ChildTypedReceiveErrorV1::terminal());
            }
            let metadata =
                fstat(descriptor.as_fd()).map_err(|_| ChildTypedReceiveErrorV1::terminal())?;
            if !rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_file() {
                return Err(ChildTypedReceiveErrorV1::terminal());
            }
            let byte_length_u64 = u64::try_from(metadata.st_size)
                .map_err(|_| ChildTypedReceiveErrorV1::terminal())?;
            let byte_length = usize::try_from(byte_length_u64)
                .map_err(|_| ChildTypedReceiveErrorV1::terminal())?;
            if !(1..=G0_FINAL_RESULT_MAX_BYTES_V1).contains(&byte_length) {
                return Err(ChildTypedReceiveErrorV1::terminal());
            }
            let raw_descriptor = descriptor.as_raw_fd();
            let descriptor_link = read_link(format!("/proc/self/fd/{raw_descriptor}"))
                .map_err(|_| ChildTypedReceiveErrorV1::terminal())?;
            if !descriptor_link.to_string_lossy().starts_with("/memfd:") {
                return Err(ChildTypedReceiveErrorV1::terminal());
            }
            let seals = fcntl_get_seals(descriptor.as_fd())
                .map_err(|_| ChildTypedReceiveErrorV1::terminal())?;
            let required_seals =
                SealFlags::GROW | SealFlags::SHRINK | SealFlags::WRITE | SealFlags::SEAL;
            if seals != required_seals {
                return Err(ChildTypedReceiveErrorV1::terminal());
            }
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(byte_length)
                .map_err(|_| ChildTypedReceiveErrorV1::terminal())?;
            bytes.resize(byte_length, 0);
            let mut observed = 0_usize;
            while observed < bytes.len() {
                let offset =
                    u64::try_from(observed).map_err(|_| ChildTypedReceiveErrorV1::terminal())?;
                let count = pread(descriptor.as_fd(), &mut bytes[observed..], offset)
                    .map_err(|_| ChildTypedReceiveErrorV1::terminal())?;
                if count == 0 {
                    return Err(ChildTypedReceiveErrorV1::terminal());
                }
                observed = observed
                    .checked_add(count)
                    .ok_or_else(ChildTypedReceiveErrorV1::terminal)?;
            }
            let mut eof_probe = [0_u8; 1];
            if pread(descriptor.as_fd(), &mut eof_probe, byte_length_u64)
                .map_err(|_| ChildTypedReceiveErrorV1::terminal())?
                != 0
            {
                return Err(ChildTypedReceiveErrorV1::terminal());
            }
            Ok(FinalResultPhysicalObservationV1 {
                device: metadata.st_dev,
                inode: metadata.st_ino,
                mode: metadata.st_mode,
                byte_length,
                descriptor_flags,
                status_flags,
                seals,
                descriptor_link,
                bytes: bytes.into_boxed_slice(),
            })
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        fn require_matching_final_result_observations_v1(
            first: FinalResultPhysicalObservationV1,
            second: FinalResultPhysicalObservationV1,
        ) -> Result<Box<[u8]>, ChildTypedReceiveErrorV1> {
            if first != second {
                return Err(ChildTypedReceiveErrorV1::terminal());
            }
            Ok(first.bytes)
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        fn validate_received_final_result_once_v1(
            received: ReceivedFdV1,
        ) -> Result<Box<[u8]>, ChildTypedReceiveErrorV1> {
            if received.role != ContractFdRoleV1::FinalResult {
                return Err(ChildTypedReceiveErrorV1::terminal());
            }
            let descriptor = received.descriptor;
            let first = observe_final_result_physical_pass_v1(&descriptor)?;
            let second = observe_final_result_physical_pass_v1(&descriptor)?;
            require_matching_final_result_observations_v1(first, second)
        }

        #[cfg(test)]
        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        fn validate_received_final_result_with_test_observer_v1<F>(
            received: ReceivedFdV1,
            mut observe: F,
        ) -> Result<Box<[u8]>, ChildTypedReceiveErrorV1>
        where
            F: FnMut(
                &OwnedFd,
            )
                -> Result<FinalResultPhysicalObservationV1, ChildTypedReceiveErrorV1>,
        {
            if received.role != ContractFdRoleV1::FinalResult {
                return Err(ChildTypedReceiveErrorV1::terminal());
            }
            let descriptor = received.descriptor;
            let first = observe(&descriptor)?;
            let second = observe(&descriptor)?;
            require_matching_final_result_observations_v1(first, second)
        }

        /// Opaque generator-side endpoint created by the D4 ledger.
        pub struct GeneratorEndpointV1(SeqpacketEndpointV1);

        impl GeneratorEndpointV1 {
            pub(crate) fn descriptor(&self) -> BorrowedFd<'_> {
                self.0.descriptor.as_fd()
            }

            fn commitment(&self) -> &SeqpacketEndpointCommitmentV1 {
                &self.0.commitment
            }

            /// Consumes the adopted endpoint and the sole generator-local fact owner.
            #[must_use]
            #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
            pub fn begin_peer_session_v1(
                self,
                local_facts: G0GeneratorPeerLocalFactsV1,
            ) -> GeneratorPeerSessionOfferEndpointV1 {
                GeneratorPeerSessionOfferEndpointV1 {
                    endpoint: self,
                    local_facts,
                }
            }
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        struct ParentSupervisorIdentityV1 {
            process_id: u32,
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        fn expected_supervisor_credentials_v1(
            supervisor_pid: u32,
        ) -> Result<ExpectedPeerCredentialsV1, ChildTypedReceiveErrorV1> {
            ExpectedPeerCredentialsV1::try_new(
                supervisor_pid,
                WORKER_OUTER_UID_V1,
                WORKER_OUTER_GID_V1,
            )
            .map_err(|_| ChildTypedReceiveErrorV1::terminal())
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        fn receive_current_parent_zero_fd_once_v1<const FRAME_BYTES: usize>(
            endpoint: &GeneratorEndpointV1,
        ) -> Result<(rustix::process::Pid, u32, [u8; FRAME_BYTES]), ChildTypedReceiveErrorV1>
        {
            let mut frame_buffer = Box::new([0_u8; CONTRACT_MAX_FRAME_BYTES_V1]);
            let parent_before = getppid().ok_or_else(ChildTypedReceiveErrorV1::terminal)?;
            let identity = ParentSupervisorIdentityV1 {
                process_id: u32::try_from(parent_before.as_raw_nonzero().get())
                    .map_err(|_| ChildTypedReceiveErrorV1::terminal())?,
            };
            let credentials = expected_supervisor_credentials_v1(identity.process_id)?;
            let expectation = StrictReceiveExpectationV1::try_for_supervisor_to_generator(
                FRAME_BYTES,
                credentials,
                &[],
            )
            .map_err(|_| ChildTypedReceiveErrorV1::terminal())?;
            let received = receive_supervisor_for_generator_frame_v1(
                endpoint.0.descriptor.as_fd(),
                frame_buffer.as_mut(),
                &expectation,
            )
            .map_err(|_| ChildTypedReceiveErrorV1::terminal())?;
            if received.received_length != FRAME_BYTES || !received.descriptors.is_empty() {
                return Err(ChildTypedReceiveErrorV1::terminal());
            }
            let frame = <[u8; FRAME_BYTES]>::try_from(&frame_buffer[..FRAME_BYTES])
                .map_err(|_| ChildTypedReceiveErrorV1::terminal())?;
            Ok((parent_before, credentials.process_id(), frame))
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        fn require_parent_unchanged_v1(
            parent_before: rustix::process::Pid,
        ) -> Result<(), ChildTypedReceiveErrorV1> {
            let parent_after = getppid().ok_or_else(ChildTypedReceiveErrorV1::terminal)?;
            if parent_after != parent_before {
                return Err(ChildTypedReceiveErrorV1::terminal());
            }
            Ok(())
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        fn send_generator_pre_session_record_once_v1(
            endpoint: GeneratorEndpointV1,
            record: &[u8; G0_PRE_SESSION_RECORD_BYTES_V1],
        ) -> Result<GeneratorEndpointV1, ChildTypedSendErrorV1> {
            let GeneratorEndpointV1(endpoint) = endpoint;
            let endpoint = send_seqpacket_once_v1(
                endpoint,
                record,
                &[],
                SendCredentialSourceV1::AutomaticChild,
            )
            .map_err(|_| ChildTypedSendErrorV1::terminal())?;
            Ok(GeneratorEndpointV1(endpoint))
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        impl GeneratorPeerSessionOfferEndpointV1 {
            /// Receives the sole exact zero-FD offer and consumes retry authority.
            pub fn receive_session_offer_once_v1(
                self,
            ) -> Result<GeneratorPeerGCommitSendEndpointV1, ChildTypedReceiveErrorV1> {
                let (parent_before, supervisor_pid, session_offer_raw) =
                    receive_current_parent_zero_fd_once_v1::<G0_SESSION_OFFER_BYTES_V1>(
                        &self.endpoint,
                    )?;
                let offered_pid = u32::from_le_bytes(
                    session_offer_raw[969..973]
                        .try_into()
                        .map_err(|_| ChildTypedReceiveErrorV1::terminal())?,
                );
                let supervisor_start_epoch = u64::from_le_bytes(
                    session_offer_raw[973..981]
                        .try_into()
                        .map_err(|_| ChildTypedReceiveErrorV1::terminal())?,
                );
                let supervisor_receiver_user_namespace = DescriptorIdentityV1::try_new(
                    u64::from_le_bytes(
                        session_offer_raw[1077..1085]
                            .try_into()
                            .map_err(|_| ChildTypedReceiveErrorV1::terminal())?,
                    ),
                    u64::from_le_bytes(
                        session_offer_raw[1085..1093]
                            .try_into()
                            .map_err(|_| ChildTypedReceiveErrorV1::terminal())?,
                    ),
                    u64::from_le_bytes(
                        session_offer_raw[1093..1101]
                            .try_into()
                            .map_err(|_| ChildTypedReceiveErrorV1::terminal())?,
                    ),
                )
                .map_err(|_| ChildTypedReceiveErrorV1::terminal())?;
                if offered_pid != supervisor_pid || supervisor_start_epoch == 0 {
                    return Err(ChildTypedReceiveErrorV1::terminal());
                }
                require_parent_unchanged_v1(parent_before)?;
                Ok(GeneratorPeerGCommitSendEndpointV1 {
                    endpoint: self.endpoint,
                    local_facts: self.local_facts,
                    session_offer_raw,
                    supervisor_pid,
                    supervisor_receiver_user_namespace,
                })
            }
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        impl GeneratorPeerGCommitSendEndpointV1 {
            /// Calculates and enqueues the sole role-fixed GCommit record.
            pub fn send_generator_commit_once_v1(
                self,
            ) -> Result<GeneratorPeerSCommitReceiveEndpointV1, ChildTypedSendErrorV1> {
                let generator_commit = self
                    .local_facts
                    .prepare_generator_commit_record_v1()
                    .map_err(|_| ChildTypedSendErrorV1::terminal())?;
                let endpoint = send_generator_pre_session_record_once_v1(
                    self.endpoint,
                    generator_commit.bytes(),
                )?;
                Ok(GeneratorPeerSCommitReceiveEndpointV1 {
                    endpoint,
                    local_facts: self.local_facts,
                    session_offer_raw: self.session_offer_raw,
                    generator_commit,
                    supervisor_pid: self.supervisor_pid,
                    supervisor_receiver_user_namespace: self.supervisor_receiver_user_namespace,
                })
            }
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        impl GeneratorPeerSCommitReceiveEndpointV1 {
            /// Receives the sole exact zero-FD SCommit record.
            pub fn receive_supervisor_commit_once_v1(
                self,
            ) -> Result<GeneratorPeerGRevealSendEndpointV1, ChildTypedReceiveErrorV1> {
                let (parent_before, supervisor_pid, supervisor_commit_raw) =
                    receive_current_parent_zero_fd_once_v1::<G0_PRE_SESSION_RECORD_BYTES_V1>(
                        &self.endpoint,
                    )?;
                if supervisor_pid != self.supervisor_pid {
                    return Err(ChildTypedReceiveErrorV1::terminal());
                }
                require_parent_unchanged_v1(parent_before)?;
                Ok(GeneratorPeerGRevealSendEndpointV1 {
                    endpoint: self.endpoint,
                    local_facts: self.local_facts,
                    session_offer_raw: self.session_offer_raw,
                    generator_commit: self.generator_commit,
                    supervisor_commit_raw,
                    supervisor_pid,
                    supervisor_receiver_user_namespace: self.supervisor_receiver_user_namespace,
                })
            }
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        impl GeneratorPeerGRevealSendEndpointV1 {
            /// Calculates and enqueues the sole role-fixed GReveal record.
            pub fn send_generator_reveal_once_v1(
                self,
            ) -> Result<GeneratorPeerSRevealReceiveEndpointV1, ChildTypedSendErrorV1> {
                let generator_reveal = self
                    .local_facts
                    .prepare_generator_reveal_record_v1()
                    .map_err(|_| ChildTypedSendErrorV1::terminal())?;
                let endpoint = send_generator_pre_session_record_once_v1(
                    self.endpoint,
                    generator_reveal.bytes(),
                )?;
                Ok(GeneratorPeerSRevealReceiveEndpointV1 {
                    endpoint,
                    local_facts: self.local_facts,
                    session_offer_raw: self.session_offer_raw,
                    generator_commit: self.generator_commit,
                    supervisor_commit_raw: self.supervisor_commit_raw,
                    generator_reveal,
                    supervisor_pid: self.supervisor_pid,
                    supervisor_receiver_user_namespace: self.supervisor_receiver_user_namespace,
                })
            }
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        impl GeneratorPeerSRevealReceiveEndpointV1 {
            /// Receives SReveal and creates the sole complete provider-session owner.
            pub fn receive_supervisor_reveal_once_v1(
                self,
            ) -> Result<GeneratorProviderSessionEndpointV1, ChildTypedReceiveErrorV1> {
                let (parent_before, supervisor_pid, supervisor_reveal_raw) =
                    receive_current_parent_zero_fd_once_v1::<G0_PRE_SESSION_RECORD_BYTES_V1>(
                        &self.endpoint,
                    )?;
                if supervisor_pid != self.supervisor_pid {
                    return Err(ChildTypedReceiveErrorV1::terminal());
                }
                let candidate =
                    G0GeneratorPeerSessionCandidateV1::try_new(G0GeneratorPeerSessionInputV1 {
                        session_offer_raw: &self.session_offer_raw,
                        generator_commit_raw: self.generator_commit.bytes(),
                        supervisor_commit_raw: &self.supervisor_commit_raw,
                        generator_reveal_raw: self.generator_reveal.bytes(),
                        supervisor_reveal_raw: &supervisor_reveal_raw,
                        local_facts: &self.local_facts,
                        local_generator_endpoint: self.endpoint.commitment(),
                    })
                    .map_err(|_| ChildTypedReceiveErrorV1::terminal())?;
                require_parent_unchanged_v1(parent_before)?;
                Ok(GeneratorProviderSessionEndpointV1 {
                    endpoint: self.endpoint,
                    candidate,
                    supervisor_pid,
                    supervisor_receiver_user_namespace: self.supervisor_receiver_user_namespace,
                })
            }
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        impl GeneratorProviderSessionEndpointV1 {
            /// Consumes the complete peer session and enqueues `GeneratorBound` once.
            ///
            /// The wait capability is constructed only after the kernel confirms a
            /// full packet enqueue. Any preparation, identity, or send failure
            /// consumes the endpoint and session without retry authority.
            pub fn send_generator_bound_once_v1(
                self,
                input: &GeneratorBoundSendInputV1<'_>,
            ) -> Result<GeneratorBoundAwaitClosedResultEndpointV1, ChildTypedSendErrorV1>
            {
                let GeneratorProviderSessionEndpointV1 {
                    endpoint,
                    candidate,
                    supervisor_pid,
                    supervisor_receiver_user_namespace,
                } = self;
                let body = candidate
                    .prepare_generator_bound_body_v1(
                        input.seal_profile,
                        input.inventory,
                        input.ingress,
                    )
                    .map_err(|_| ChildTypedSendErrorV1::terminal())?;
                let credentials = generator_outbound_credentials_v1()?;
                let outbound =
                    G0GeneratorBoundOutboundCandidateV1::prepare(candidate, &body, credentials)
                        .map_err(|_| ChildTypedSendErrorV1::terminal())?;
                let GeneratorEndpointV1(endpoint) = endpoint;
                let endpoint = send_seqpacket_once_v1(
                    endpoint,
                    outbound.bytes(),
                    &[],
                    SendCredentialSourceV1::AutomaticChild,
                )
                .map_err(|_| ChildTypedSendErrorV1::terminal())?;
                Ok(GeneratorBoundAwaitClosedResultEndpointV1 {
                    endpoint,
                    await_closed_result: outbound.into_await_closed_result_v1(),
                    supervisor_pid,
                    supervisor_receiver_user_namespace,
                })
            }
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        impl GeneratorBoundAwaitClosedResultEndpointV1 {
            /// Consumes the one terminal receive and returns only an opaque
            /// non-authorizing completion token after every physical and contract
            /// join succeeds.
            pub fn receive_and_verify_closed_result_once_v1(
                self,
            ) -> Result<G0ClosedResultVerifiedV1, ChildTypedReceiveErrorV1> {
                let GeneratorBoundAwaitClosedResultEndpointV1 {
                    endpoint,
                    await_closed_result,
                    supervisor_pid,
                    supervisor_receiver_user_namespace,
                } = self;
                let expected = expected_supervisor_credentials_v1(supervisor_pid)?;
                let expectation = StrictReceiveExpectationV1::try_for_supervisor_to_generator(
                    G0_CLOSED_RESULT_RAW_FRAME_BYTES_V1,
                    expected,
                    &[ContractFdRoleV1::FinalResult],
                )
                .map_err(|_| ChildTypedReceiveErrorV1::terminal())?;
                let mut frame_buffer = Box::new([0_u8; CONTRACT_MAX_FRAME_BYTES_V1]);
                let ReceivedFrameV1 {
                    received_length,
                    observed_credentials,
                    mut descriptors,
                } = receive_supervisor_for_generator_frame_v1(
                    endpoint.descriptor.as_fd(),
                    frame_buffer.as_mut(),
                    &expectation,
                )
                .map_err(|_| ChildTypedReceiveErrorV1::terminal())?;
                if received_length != G0_CLOSED_RESULT_RAW_FRAME_BYTES_V1 {
                    return Err(ChildTypedReceiveErrorV1::terminal());
                }
                let raw_frame = <[u8; G0_CLOSED_RESULT_RAW_FRAME_BYTES_V1]>::try_from(
                    &frame_buffer[..G0_CLOSED_RESULT_RAW_FRAME_BYTES_V1],
                )
                .map_err(|_| ChildTypedReceiveErrorV1::terminal())?;
                let final_result = descriptors
                    .pop()
                    .ok_or_else(ChildTypedReceiveErrorV1::terminal)?;
                if !descriptors.is_empty() {
                    return Err(ChildTypedReceiveErrorV1::terminal());
                }
                let final_result_content = validate_received_final_result_once_v1(final_result)?;
                let observed_credentials = observed_supervisor_credentials_v1(
                    observed_credentials,
                    supervisor_receiver_user_namespace,
                )?;
                await_closed_result
                    .verify_observed_closed_result_once_v1(
                        G0ClosedResultInboundInputV1 {
                            received_raw_frame: &raw_frame,
                            actual_rights_count: 1,
                            observed_credentials,
                        },
                        &final_result_content,
                    )
                    .map_err(|_| ChildTypedReceiveErrorV1::terminal())
            }
        }

        /// Opaque supervisor endpoint on the generator channel.
        pub(crate) struct SupervisorGeneratorEndpointV1(SeqpacketEndpointV1);

        /// Sealed supervisor-to-generator packet and endpoint operation.
        ///
        /// No constructor exists before G0. The future typed session join may
        /// construct this value only inside this module from one exact
        /// role-specific encoding.
        pub(crate) struct SupervisorGeneratorSendOpV1 {
            endpoint: SupervisorGeneratorEndpointV1,
            prepared: PreparedSupervisorSendV1,
            #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
            phase: SupervisorGeneratorSendPhaseV1,
        }

        /// Opaque same-endpoint custody after one supervisor-to-generator
        /// packet is completely enqueued.
        pub(crate) struct SupervisorGeneratorSentEndpointV1 {
            endpoint: SeqpacketEndpointV1,
            #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
            phase: SupervisorGeneratorSendPhaseV1,
        }

        #[cfg(test)]
        #[cfg(not(feature = "h0-tmpfs-provider-v2-g0"))]
        fn feature_off_generator_transport_shape_v1(
            operation: SupervisorGeneratorSendOpV1,
            sent: SupervisorGeneratorSentEndpointV1,
        ) {
            let SupervisorGeneratorSendOpV1 { endpoint, prepared } = operation;
            let SupervisorGeneratorSentEndpointV1 {
                endpoint: sent_endpoint,
            } = sent;
            drop((endpoint, prepared, sent_endpoint));
        }

        impl SupervisorGeneratorSendOpV1 {
            pub(crate) fn enqueue_once_v1(
                self,
                credentials: UCred,
            ) -> Result<SupervisorGeneratorSentEndpointV1, AncillarySendErrorV1> {
                let SupervisorGeneratorEndpointV1(endpoint) = self.endpoint;
                let endpoint = send_seqpacket_once_v1(
                    endpoint,
                    &self.prepared.frame,
                    &self.prepared.descriptors,
                    SendCredentialSourceV1::ExplicitSupervisor(credentials),
                )?;
                Ok(SupervisorGeneratorSentEndpointV1 {
                    endpoint,
                    #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
                    phase: self.phase,
                })
            }
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        impl SupervisorGeneratorSentEndpointV1 {
            pub(crate) fn receive_generator_nonce_commit_once_v1(
                self,
                input: GeneratorCommitReceiveInputV1,
            ) -> Result<GeneratorCommitReceivedEndpointV1, SupervisorTypedTransitionErrorV1>
            {
                let SupervisorGeneratorSentEndpointV1 { endpoint, phase } = self;
                if phase as u8 != SupervisorGeneratorSendPhaseV1::AwaitGeneratorCommit as u8 {
                    return Err(SupervisorTypedTransitionErrorV1::terminal());
                }
                let prepared = prepare_supervisor_typed_receive_v1(input.prepared, &[])?;
                let endpoint = receive_exact_generator_once_v1(endpoint, prepared)?;
                Ok(GeneratorCommitReceivedEndpointV1 { endpoint })
            }

            pub(crate) fn receive_generator_nonce_reveal_once_v1(
                self,
                input: GeneratorRevealReceiveInputV1,
            ) -> Result<GeneratorRevealReceivedEndpointV1, SupervisorTypedTransitionErrorV1>
            {
                let SupervisorGeneratorSentEndpointV1 { endpoint, phase } = self;
                if phase as u8 != SupervisorGeneratorSendPhaseV1::AwaitGeneratorReveal as u8 {
                    return Err(SupervisorTypedTransitionErrorV1::terminal());
                }
                let prepared = prepare_supervisor_typed_receive_v1(input.prepared, &[])?;
                let endpoint = receive_exact_generator_once_v1(endpoint, prepared)?;
                Ok(GeneratorRevealReceivedEndpointV1 { endpoint })
            }

            pub(crate) fn receive_generator_bound_once_v1(
                self,
                input: GeneratorBoundReceiveInputV1,
            ) -> Result<
                (
                    GeneratorBoundReceivedEndpointV1,
                    G0GeneratorBoundTranscriptCandidateV1,
                ),
                SupervisorTypedTransitionErrorV1,
            > {
                let SupervisorGeneratorSentEndpointV1 { endpoint, phase } = self;
                if phase as u8 != SupervisorGeneratorSendPhaseV1::AwaitGeneratorBound as u8 {
                    return Err(SupervisorTypedTransitionErrorV1::terminal());
                }
                let raw = input.frame.encode_raw_frame()?;
                if input.prepared.frame.as_ref() != raw.as_slice()
                    || input.prepared.expectation.ordered_roles.len()
                        != input.frame.fd_commitments().len()
                {
                    return Err(SupervisorTypedTransitionErrorV1::terminal());
                }
                let endpoint = receive_exact_generator_once_v1(endpoint, input.prepared)?;
                let candidate =
                    G0GeneratorBoundTranscriptCandidateV1::prepare(&input.session, &input.frame)?;
                let received_endpoint = GeneratorBoundReceivedEndpointV1 { endpoint };
                Ok((received_endpoint, candidate))
            }
        }

        impl SupervisorGeneratorEndpointV1 {
            #[allow(dead_code)] // D6a-private projection consumed by G0a.
            pub(crate) fn commitment(&self) -> &SeqpacketEndpointCommitmentV1 {
                &self.0.commitment
            }

            /// Receives one exact generator frame without exposing the
            /// supervisor endpoint descriptor.
            ///
            /// # Errors
            ///
            /// Returns [`AncillaryReceiveErrorV1`] for disabled `SO_PASSCRED`
            /// or any peer, frame, credential, CMSG, or descriptor drift.
            pub(crate) fn receive_generator_frame_v1(
                &self,
                frame_buffer: &mut [u8; CONTRACT_MAX_FRAME_BYTES_V1],
                expectation: &StrictReceiveExpectationV1,
            ) -> Result<ReceivedFrameV1, AncillaryReceiveErrorV1> {
                receive_generator_frame_v1(self.0.descriptor.as_fd(), frame_buffer, expectation)
            }
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub(crate) fn prepare_session_offer_send_v1(
            endpoint: SupervisorGeneratorEndpointV1,
            input: SessionOfferSendInputV1,
        ) -> Result<SupervisorGeneratorSendOpV1, SupervisorTypedTransitionErrorV1> {
            let prepared = prepare_supervisor_typed_send_v1(input.prepared, &[])?;
            let operation = SupervisorGeneratorSendOpV1 {
                endpoint,
                prepared,
                phase: SupervisorGeneratorSendPhaseV1::AwaitGeneratorCommit,
            };
            Ok(operation)
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub(crate) fn prepare_supervisor_commit_send_v1(
            endpoint: GeneratorCommitReceivedEndpointV1,
            input: SupervisorCommitSendInputV1,
        ) -> Result<SupervisorGeneratorSendOpV1, SupervisorTypedTransitionErrorV1> {
            let prepared = prepare_supervisor_typed_send_v1(input.prepared, &[])?;
            let GeneratorCommitReceivedEndpointV1 { endpoint } = endpoint;
            let operation = SupervisorGeneratorSendOpV1 {
                endpoint: SupervisorGeneratorEndpointV1(endpoint),
                prepared,
                phase: SupervisorGeneratorSendPhaseV1::AwaitGeneratorReveal,
            };
            Ok(operation)
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub(crate) fn prepare_supervisor_reveal_send_v1(
            endpoint: GeneratorRevealReceivedEndpointV1,
            input: SupervisorRevealSendInputV1,
        ) -> Result<SupervisorGeneratorSendOpV1, SupervisorTypedTransitionErrorV1> {
            let prepared = prepare_supervisor_typed_send_v1(input.prepared, &[])?;
            let GeneratorRevealReceivedEndpointV1 { endpoint } = endpoint;
            let operation = SupervisorGeneratorSendOpV1 {
                endpoint: SupervisorGeneratorEndpointV1(endpoint),
                prepared,
                phase: SupervisorGeneratorSendPhaseV1::AwaitGeneratorBound,
            };
            Ok(operation)
        }

        /// Opaque supervisor endpoint on the worker channel.
        pub(crate) struct SupervisorWorkerEndpointV1(SeqpacketEndpointV1);

        /// Sealed supervisor-to-worker bootstrap packet and endpoint
        /// operation. No constructor exists before G0.
        pub(crate) struct SupervisorWorkerBootstrapSendOpV1 {
            endpoint: SupervisorWorkerEndpointV1,
            prepared: PreparedSupervisorSendV1,
        }

        impl SupervisorWorkerBootstrapSendOpV1 {
            pub(crate) fn enqueue_once_v1(
                self,
                credentials: UCred,
            ) -> Result<WorkerBootstrapEnqueuedEndpointV1, AncillarySendErrorV1> {
                let SupervisorWorkerEndpointV1(endpoint) = self.endpoint;
                let endpoint = send_seqpacket_once_v1(
                    endpoint,
                    &self.prepared.frame,
                    &self.prepared.descriptors,
                    SendCredentialSourceV1::ExplicitSupervisor(credentials),
                )?;
                Ok(WorkerBootstrapEnqueuedEndpointV1 { endpoint })
            }
        }

        impl SupervisorWorkerEndpointV1 {
            #[allow(dead_code)] // D6a-private projection consumed by G0a.
            pub(crate) fn commitment(&self) -> &SeqpacketEndpointCommitmentV1 {
                &self.0.commitment
            }

            /// Receives one exact worker frame without exposing the supervisor
            /// endpoint descriptor.
            ///
            /// # Errors
            ///
            /// Returns [`AncillaryReceiveErrorV1`] for disabled `SO_PASSCRED`
            /// or any peer, frame, credential, CMSG, or descriptor drift.
            pub(crate) fn receive_worker_frame_v1(
                &self,
                frame_buffer: &mut [u8; CONTRACT_MAX_FRAME_BYTES_V1],
                expectation: &StrictReceiveExpectationV1,
            ) -> Result<ReceivedFrameV1, AncillaryReceiveErrorV1> {
                receive_worker_frame_v1(self.0.descriptor.as_fd(), frame_buffer, expectation)
            }

            #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
            pub(crate) fn prepare_worker_bootstrap_send_v1(
                self,
                input: WorkerBootstrapSendInputV1,
                previous_digest: [u8; 32],
            ) -> Result<
                (SupervisorWorkerBootstrapSendOpV1, G0TranscriptCandidateV1),
                SupervisorTypedTransitionErrorV1,
            > {
                let raw = input.frame.encode_raw_frame()?;
                if input.prepared.frame.as_ref() != raw.as_slice()
                    || input.prepared.descriptors.len() != input.frame.fd_commitments().len()
                {
                    return Err(SupervisorTypedTransitionErrorV1::terminal());
                }
                let candidate = G0TranscriptCandidateV1::prepare(
                    &input.session,
                    0,
                    previous_digest,
                    &input.frame,
                )?;
                let operation = SupervisorWorkerBootstrapSendOpV1 {
                    endpoint: self,
                    prepared: input.prepared,
                };
                Ok((operation, candidate))
            }
        }

        /// Opaque worker-side endpoint created by the D4 ledger.
        pub struct WorkerEndpointV1(SeqpacketEndpointV1);

        impl WorkerEndpointV1 {
            pub(crate) fn descriptor(&self) -> BorrowedFd<'_> {
                self.0.descriptor.as_fd()
            }
        }

        /// Generator-channel endpoint custody and its role-ordered identity.
        pub(crate) struct GeneratorChannelV1 {
            generator: GeneratorEndpointV1,
            supervisor: SupervisorGeneratorEndpointV1,
            identity: ChannelIdentityV1,
        }

        impl GeneratorChannelV1 {
            /// Returns the non-authorizing channel identity while both exact
            /// endpoint custodies remain joined to this ledger.
            #[must_use]
            pub(crate) const fn channel_identity(&self) -> &ChannelIdentityV1 {
                &self.identity
            }

            /// Moves the two opaque endpoints and their safe channel identity
            /// into the role-specific launch owner.
            #[must_use]
            pub(crate) fn into_endpoints(
                self,
            ) -> (
                GeneratorEndpointV1,
                SupervisorGeneratorEndpointV1,
                ChannelIdentityV1,
            ) {
                (self.generator, self.supervisor, self.identity)
            }
        }

        /// Worker-channel endpoint custody and its role-ordered identity.
        pub(crate) struct WorkerChannelV1 {
            supervisor: SupervisorWorkerEndpointV1,
            worker: WorkerEndpointV1,
            identity: ChannelIdentityV1,
        }

        impl WorkerChannelV1 {
            /// Returns the non-authorizing channel identity while both exact
            /// endpoint custodies remain joined to this ledger.
            #[must_use]
            pub(crate) const fn channel_identity(&self) -> &ChannelIdentityV1 {
                &self.identity
            }

            /// Moves the two opaque endpoints and their safe channel identity
            /// into the role-specific launch owner.
            #[must_use]
            pub(crate) fn into_endpoints(
                self,
            ) -> (
                SupervisorWorkerEndpointV1,
                WorkerEndpointV1,
                ChannelIdentityV1,
            ) {
                (self.supervisor, self.worker, self.identity)
            }
        }

        /// Opaque kernel-success state for the exact worker-bootstrap packet.
        ///
        /// The endpoint remains owned, but no raw descriptor, packet, FD,
        /// digest, transcript state, retry, or resend operation is exposed.
        pub(crate) struct WorkerBootstrapEnqueuedEndpointV1 {
            endpoint: SeqpacketEndpointV1,
        }

        impl WorkerBootstrapEnqueuedEndpointV1 {
            #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
            pub(crate) fn receive_worker_exec_bound_once_v1(
                self,
                input: WorkerExecBoundReceiveInputV1,
                previous_digest: [u8; 32],
            ) -> Result<
                (WorkerExecBoundReceivedEndpointV1, G0TranscriptCandidateV1),
                SupervisorTypedTransitionErrorV1,
            > {
                let WorkerBootstrapEnqueuedEndpointV1 { endpoint } = self;
                let raw = input.frame.encode_raw_frame()?;
                if input.prepared.frame.as_ref() != raw.as_slice()
                    || input.prepared.expectation.ordered_roles.len()
                        != input.frame.fd_commitments().len()
                {
                    return Err(SupervisorTypedTransitionErrorV1::terminal());
                }
                let endpoint = receive_exact_worker_once_v1(endpoint, input.prepared)?;
                let candidate = G0TranscriptCandidateV1::prepare(
                    &input.session,
                    1,
                    previous_digest,
                    &input.frame,
                )?;
                let received_endpoint = WorkerExecBoundReceivedEndpointV1 { endpoint };
                Ok((received_endpoint, candidate))
            }

            /// Receives one exact worker frame after the one-shot bootstrap
            /// enqueue while retaining the endpoint as opaque custody.
            ///
            /// # Errors
            ///
            /// Returns [`AncillaryReceiveErrorV1`] for disabled `SO_PASSCRED`
            /// or any peer, frame, credential, CMSG, or descriptor drift.
            pub(crate) fn receive_worker_frame_v1(
                &self,
                frame_buffer: &mut [u8; CONTRACT_MAX_FRAME_BYTES_V1],
                expectation: &StrictReceiveExpectationV1,
            ) -> Result<ReceivedFrameV1, AncillaryReceiveErrorV1> {
                receive_worker_frame_v1(self.endpoint.descriptor.as_fd(), frame_buffer, expectation)
            }
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        pub(crate) fn prepare_closed_result_send_v1(
            endpoint: GeneratorBoundReceivedEndpointV1,
            input: ClosedResultSendInputV1,
            previous_digest: [u8; 32],
        ) -> Result<
            (SupervisorGeneratorSendOpV1, G0TranscriptCandidateV1),
            SupervisorTypedTransitionErrorV1,
        > {
            let raw = input.frame.encode_raw_frame()?;
            if input.prepared.frame.as_ref() != raw.as_slice()
                || input.prepared.descriptors.len() != input.frame.fd_commitments().len()
            {
                return Err(SupervisorTypedTransitionErrorV1::terminal());
            }
            let candidate =
                G0TranscriptCandidateV1::prepare(&input.session, 1, previous_digest, &input.frame)?;
            let GeneratorBoundReceivedEndpointV1 { endpoint } = endpoint;
            let operation = SupervisorGeneratorSendOpV1 {
                endpoint: SupervisorGeneratorEndpointV1(endpoint),
                prepared: input.prepared,
                phase: SupervisorGeneratorSendPhaseV1::ClosedResult,
            };
            Ok((operation, candidate))
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        fn prepare_supervisor_typed_send_v1(
            prepared: PreparedSupervisorSendV1,
            expected_roles: &[ContractFdRoleV1],
        ) -> Result<PreparedSupervisorSendV1, SupervisorTypedTransitionErrorV1> {
            if prepared.descriptors.len() != expected_roles.len() {
                return Err(SupervisorTypedTransitionErrorV1::terminal());
            }
            Ok(prepared)
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        fn prepare_supervisor_typed_receive_v1(
            prepared: PreparedSupervisorReceiveV1,
            expected_roles: &[ContractFdRoleV1],
        ) -> Result<PreparedSupervisorReceiveV1, SupervisorTypedTransitionErrorV1> {
            if prepared.expectation.ordered_roles.as_slice() != expected_roles {
                return Err(SupervisorTypedTransitionErrorV1::terminal());
            }
            Ok(prepared)
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        fn receive_exact_generator_once_v1(
            endpoint: SeqpacketEndpointV1,
            prepared: PreparedSupervisorReceiveV1,
        ) -> Result<SeqpacketEndpointV1, SupervisorTypedTransitionErrorV1> {
            let PreparedSupervisorReceiveV1 { frame, expectation } = prepared;
            if frame.len() != expectation.frame_length {
                return Err(SupervisorTypedTransitionErrorV1::terminal());
            }
            let mut buffer = [0_u8; CONTRACT_MAX_FRAME_BYTES_V1];
            let received =
                receive_generator_frame_v1(endpoint.descriptor.as_fd(), &mut buffer, &expectation)?;
            if !received.descriptors.is_empty()
                || received.received_length != frame.len()
                || buffer[..received.received_length] != frame[..]
            {
                return Err(SupervisorTypedTransitionErrorV1::terminal());
            }
            Ok(endpoint)
        }

        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        fn receive_exact_worker_once_v1(
            endpoint: SeqpacketEndpointV1,
            prepared: PreparedSupervisorReceiveV1,
        ) -> Result<SeqpacketEndpointV1, SupervisorTypedTransitionErrorV1> {
            let PreparedSupervisorReceiveV1 { frame, expectation } = prepared;
            if frame.len() != expectation.frame_length {
                return Err(SupervisorTypedTransitionErrorV1::terminal());
            }
            let mut buffer = [0_u8; CONTRACT_MAX_FRAME_BYTES_V1];
            let received =
                receive_worker_frame_v1(endpoint.descriptor.as_fd(), &mut buffer, &expectation)?;
            if !received.descriptors.is_empty()
                || received.received_length != frame.len()
                || buffer[..received.received_length] != frame[..]
            {
                return Err(SupervisorTypedTransitionErrorV1::terminal());
            }
            Ok(endpoint)
        }

        fn descriptor_identity_v1(
            descriptor: BorrowedFd<'_>,
        ) -> Result<DescriptorIdentityV1, SeqpacketEndpointErrorV1> {
            const STATX_MNT_ID_UNIQUE_V1: u32 = 0x4000;
            let flags = rustix::fs::AtFlags::EMPTY_PATH
                | rustix::fs::AtFlags::SYMLINK_NOFOLLOW
                | rustix::fs::AtFlags::NO_AUTOMOUNT;
            let requested = rustix::fs::StatxFlags::BASIC_STATS
                | rustix::fs::StatxFlags::from_bits_retain(STATX_MNT_ID_UNIQUE_V1);
            let observed = rustix::fs::statx(descriptor, c"", flags, requested)
                .map_err(|_| SeqpacketEndpointErrorV1::KernelObservation)?;
            if observed.stx_mask & requested.bits() != requested.bits() {
                return Err(SeqpacketEndpointErrorV1::InvalidIdentity);
            }
            let device =
                (u64::from(observed.stx_dev_major) << 32) | u64::from(observed.stx_dev_minor);
            DescriptorIdentityV1::try_new(device, observed.stx_ino, observed.stx_mnt_id)
                .map_err(|_| SeqpacketEndpointErrorV1::InvalidIdentity)
        }

        fn observe_endpoint_v1(
            descriptor: BorrowedFd<'_>,
            role: SeqpacketEndpointRoleV1,
        ) -> Result<EndpointObservationSnapshotV1, SeqpacketEndpointErrorV1> {
            #[cfg(test)]
            ENDPOINT_OBSERVATION_CALLS_V1.fetch_add(1, Ordering::Relaxed);
            let domain = socket_domain(descriptor)
                .map_err(|_| SeqpacketEndpointErrorV1::KernelObservation)?;
            let kind =
                socket_type(descriptor).map_err(|_| SeqpacketEndpointErrorV1::KernelObservation)?;
            let protocol = socket_protocol(descriptor)
                .map_err(|_| SeqpacketEndpointErrorV1::KernelObservation)?;
            let passcred = socket_passcred(descriptor)
                .map_err(|_| SeqpacketEndpointErrorV1::KernelObservation)?;
            let status_flags =
                fcntl_getfl(descriptor).map_err(|_| SeqpacketEndpointErrorV1::KernelObservation)?;
            let descriptor_flags =
                fcntl_getfd(descriptor).map_err(|_| SeqpacketEndpointErrorV1::KernelObservation)?;
            let snapshot = EndpointObservationSnapshotV1 {
                role,
                descriptor_identity: descriptor_identity_v1(descriptor)?,
                socket_cookie: socket_cookie(descriptor)
                    .map_err(|_| SeqpacketEndpointErrorV1::KernelObservation)?,
                socket_domain: if domain == AddressFamily::UNIX {
                    AF_UNIX_V1
                } else {
                    u32::MAX
                },
                socket_type: if kind == SocketType::SEQPACKET {
                    SOCK_SEQPACKET_V1
                } else {
                    u32::MAX
                },
                socket_protocol: if protocol.is_none() {
                    SOCKET_PROTOCOL_DEFAULT_V1
                } else {
                    u32::MAX
                },
                passcred,
                nonblocking: status_flags.contains(OFlags::NONBLOCK),
                close_on_exec: descriptor_flags.contains(FdFlags::CLOEXEC),
            };
            validate_endpoint_observation_v1(snapshot)?;
            Ok(snapshot)
        }

        fn reread_endpoint_observation_v1(
            descriptor: BorrowedFd<'_>,
            initial: EndpointObservationSnapshotV1,
        ) -> Result<EndpointObservationSnapshotV1, SeqpacketEndpointErrorV1> {
            let reread = observe_endpoint_v1(descriptor, initial.role)?;
            validate_endpoint_reread_v1(initial, reread)?;
            Ok(reread)
        }

        fn create_seqpacket_pair_v1(
            first_role: SeqpacketEndpointRoleV1,
            second_role: SeqpacketEndpointRoleV1,
        ) -> Result<(SeqpacketEndpointV1, SeqpacketEndpointV1), SeqpacketEndpointErrorV1> {
            let (first, second) = socketpair(
                AddressFamily::UNIX,
                SocketType::SEQPACKET,
                SocketFlags::CLOEXEC,
                None,
            )
            .map_err(|_| SeqpacketEndpointErrorV1::KernelObservation)?;

            set_socket_passcred(&first, true)
                .map_err(|_| SeqpacketEndpointErrorV1::PasscredNotEnabled)?;
            set_socket_passcred(&second, true)
                .map_err(|_| SeqpacketEndpointErrorV1::PasscredNotEnabled)?;
            if !socket_passcred(&first).map_err(|_| SeqpacketEndpointErrorV1::PasscredNotEnabled)?
                || !socket_passcred(&second)
                    .map_err(|_| SeqpacketEndpointErrorV1::PasscredNotEnabled)?
            {
                return Err(SeqpacketEndpointErrorV1::PasscredNotEnabled);
            }

            let first_observation = observe_endpoint_v1(first.as_fd(), first_role)?;
            let second_observation = observe_endpoint_v1(second.as_fd(), second_role)?;
            validate_endpoint_pair_v1(
                first_observation,
                second_observation,
                first_role,
                second_role,
            )?;
            let first_observation =
                reread_endpoint_observation_v1(first.as_fd(), first_observation)?;
            let second_observation =
                reread_endpoint_observation_v1(second.as_fd(), second_observation)?;
            validate_endpoint_pair_v1(
                first_observation,
                second_observation,
                first_role,
                second_role,
            )?;

            let first_commitment = SeqpacketEndpointCommitmentV1::from_observation(
                first_role,
                first_observation.descriptor_identity,
                first_observation.socket_cookie,
            );
            let second_commitment = SeqpacketEndpointCommitmentV1::from_observation(
                second_role,
                second_observation.descriptor_identity,
                second_observation.socket_cookie,
            );
            Ok((
                SeqpacketEndpointV1 {
                    descriptor: first,
                    commitment: first_commitment,
                },
                SeqpacketEndpointV1 {
                    descriptor: second,
                    commitment: second_commitment,
                },
            ))
        }

        struct WorkerPostExecFdInventoryV1 {
            observed_numeric_entries: u8,
            endpoint_fd3_seen: bool,
            enumeration_fd_seen: bool,
        }

        impl WorkerPostExecFdInventoryV1 {
            const fn new() -> Self {
                Self {
                    observed_numeric_entries: 0,
                    endpoint_fd3_seen: false,
                    enumeration_fd_seen: false,
                }
            }

            fn observe_entry_v1(
                &mut self,
                name: &[u8],
                enumeration_descriptor: i32,
            ) -> Result<(), InheritedEndpointAdoptionErrorV1> {
                if name == b"." || name == b".." {
                    return Ok(());
                }
                let descriptor = parse_canonical_worker_fd_name_v1(name)?;
                if self.observed_numeric_entries >= 2 {
                    return Err(InheritedEndpointAdoptionErrorV1::terminal());
                }
                self.observed_numeric_entries += 1;
                if descriptor == 3 {
                    if self.endpoint_fd3_seen {
                        return Err(InheritedEndpointAdoptionErrorV1::terminal());
                    }
                    self.endpoint_fd3_seen = true;
                } else if descriptor == enumeration_descriptor {
                    if self.enumeration_fd_seen {
                        return Err(InheritedEndpointAdoptionErrorV1::terminal());
                    }
                    self.enumeration_fd_seen = true;
                } else {
                    return Err(InheritedEndpointAdoptionErrorV1::terminal());
                }
                Ok(())
            }

            fn finish_v1(self) -> Result<(), InheritedEndpointAdoptionErrorV1> {
                if self.observed_numeric_entries == 2
                    && self.endpoint_fd3_seen
                    && self.enumeration_fd_seen
                {
                    Ok(())
                } else {
                    Err(InheritedEndpointAdoptionErrorV1::terminal())
                }
            }
        }

        fn parse_canonical_worker_fd_name_v1(
            name: &[u8],
        ) -> Result<i32, InheritedEndpointAdoptionErrorV1> {
            if name.is_empty() || (name.len() > 1 && name[0] == b'0') {
                return Err(InheritedEndpointAdoptionErrorV1::terminal());
            }
            let mut descriptor = 0_i32;
            for byte in name {
                if !byte.is_ascii_digit() {
                    return Err(InheritedEndpointAdoptionErrorV1::terminal());
                }
                descriptor = descriptor
                    .checked_mul(10)
                    .and_then(|value| value.checked_add(i32::from(*byte - b'0')))
                    .ok_or_else(InheritedEndpointAdoptionErrorV1::terminal)?;
            }
            Ok(descriptor)
        }

        fn require_exact_worker_post_exec_fd3_inventory_v1()
        -> Result<(), InheritedEndpointAdoptionErrorV1> {
            let descriptor = openat(
                CWD,
                c"/proc/self/fd",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|_| InheritedEndpointAdoptionErrorV1::terminal())?;
            let filesystem = fstatfs(descriptor.as_fd())
                .map_err(|_| InheritedEndpointAdoptionErrorV1::terminal())?;
            if filesystem.f_type != PROC_SUPER_MAGIC {
                return Err(InheritedEndpointAdoptionErrorV1::terminal());
            }
            let mut directory =
                Dir::new(descriptor).map_err(|_| InheritedEndpointAdoptionErrorV1::terminal())?;
            let enumeration_descriptor = directory
                .fd()
                .map_err(|_| InheritedEndpointAdoptionErrorV1::terminal())?
                .as_raw_fd();
            if enumeration_descriptor == 3 {
                return Err(InheritedEndpointAdoptionErrorV1::terminal());
            }

            let mut inventory = WorkerPostExecFdInventoryV1::new();
            while let Some(entry) = directory.read() {
                let entry = entry.map_err(|_| InheritedEndpointAdoptionErrorV1::terminal())?;
                inventory.observe_entry_v1(entry.file_name().to_bytes(), enumeration_descriptor)?;
            }
            let result = inventory.finish_v1();
            drop(directory);
            result
        }

        fn adopt_inherited_endpoint_v1(
            descriptor: OwnedFd,
            role: SeqpacketEndpointRoleV1,
        ) -> Result<SeqpacketEndpointV1, InheritedEndpointAdoptionErrorV1> {
            if INHERITED_ENDPOINT_ADOPTION_ATTEMPTED_V1
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Err(InheritedEndpointAdoptionErrorV1::terminal());
            }
            if descriptor.as_raw_fd() != 3 {
                return Err(InheritedEndpointAdoptionErrorV1::terminal());
            }
            if role == SeqpacketEndpointRoleV1::Worker {
                require_exact_worker_post_exec_fd3_inventory_v1()?;
            }

            let first = observe_endpoint_v1(descriptor.as_fd(), role)
                .map_err(|_| InheritedEndpointAdoptionErrorV1::terminal())?;
            let first_flags_valid = !first.nonblocking && !first.close_on_exec;
            if !first_flags_valid {
                return Err(InheritedEndpointAdoptionErrorV1::terminal());
            }
            let second = observe_endpoint_v1(descriptor.as_fd(), role)
                .map_err(|_| InheritedEndpointAdoptionErrorV1::terminal())?;
            validate_endpoint_reread_v1(first, second)
                .map_err(|_| InheritedEndpointAdoptionErrorV1::terminal())?;
            if second.nonblocking || second.close_on_exec {
                return Err(InheritedEndpointAdoptionErrorV1::terminal());
            }
            let commitment = SeqpacketEndpointCommitmentV1::from_observation(
                role,
                second.descriptor_identity,
                second.socket_cookie,
            );
            Ok(SeqpacketEndpointV1 {
                descriptor,
                commitment,
            })
        }

        /// Adopts the owning inherited fd3 generator endpoint exactly once.
        ///
        /// The caller must obtain `descriptor` from the reviewed post-exec
        /// entry boundary. This function consumes and closes it on every
        /// rejection and never permits another adoption attempt.
        ///
        /// # Errors
        ///
        /// Returns [`InheritedEndpointAdoptionErrorV1`] for a repeated attempt,
        /// a descriptor other than fd3, or any endpoint/flag/reread drift.
        pub fn try_adopt_generator_exec_inherited_fd3_once_v1(
            descriptor: OwnedFd,
        ) -> Result<GeneratorEndpointV1, InheritedEndpointAdoptionErrorV1> {
            adopt_inherited_endpoint_v1(descriptor, SeqpacketEndpointRoleV1::Generator)
                .map(GeneratorEndpointV1)
        }

        /// Adopts the owning inherited fd3 worker endpoint exactly once.
        ///
        /// The caller must obtain `descriptor` from the reviewed post-exec
        /// entry boundary. This function consumes and closes it on every
        /// rejection and never permits another adoption attempt.
        ///
        /// # Errors
        ///
        /// Returns [`InheritedEndpointAdoptionErrorV1`] for a repeated attempt,
        /// a descriptor other than fd3, or any endpoint/flag/reread drift.
        pub fn try_adopt_worker_exec_inherited_fd3_once_v1(
            descriptor: OwnedFd,
        ) -> Result<WorkerEndpointV1, InheritedEndpointAdoptionErrorV1> {
            adopt_inherited_endpoint_v1(descriptor, SeqpacketEndpointRoleV1::Worker)
                .map(WorkerEndpointV1)
        }

        /// Creates the sole non-reconnectable generator/supervisor channel.
        ///
        /// # Errors
        ///
        /// Rejects any socketpair, passcred, descriptor, cookie, tuple, role,
        /// reread, or canonical-commitment drift.
        pub(crate) fn create_generator_channel_v1()
        -> Result<GeneratorChannelV1, SeqpacketEndpointErrorV1> {
            let (generator, supervisor) = create_seqpacket_pair_v1(
                SeqpacketEndpointRoleV1::Generator,
                SeqpacketEndpointRoleV1::SupervisorGenerator,
            )?;
            let identity =
                ChannelIdentityV1::try_generator(&generator.commitment, &supervisor.commitment)
                    .map_err(|_| SeqpacketEndpointErrorV1::CommitmentDrift)?;
            Ok(GeneratorChannelV1 {
                generator: GeneratorEndpointV1(generator),
                supervisor: SupervisorGeneratorEndpointV1(supervisor),
                identity,
            })
        }

        /// Creates the sole attempt-local supervisor/worker channel.
        ///
        /// # Errors
        ///
        /// Rejects any socketpair, passcred, descriptor, cookie, tuple, role,
        /// reread, or canonical-commitment drift.
        pub(crate) fn create_worker_channel_v1() -> Result<WorkerChannelV1, SeqpacketEndpointErrorV1>
        {
            let (supervisor, worker) = create_seqpacket_pair_v1(
                SeqpacketEndpointRoleV1::SupervisorWorker,
                SeqpacketEndpointRoleV1::Worker,
            )?;
            let identity =
                ChannelIdentityV1::try_worker(&supervisor.commitment, &worker.commitment)
                    .map_err(|_| SeqpacketEndpointErrorV1::CommitmentDrift)?;
            Ok(WorkerChannelV1 {
                supervisor: SupervisorWorkerEndpointV1(supervisor),
                worker: WorkerEndpointV1(worker),
                identity,
            })
        }

        /// One received descriptor paired only with its validated wire role.
        ///
        /// The role is not filesystem or mount identity. Callers must pass this
        /// owned descriptor through the appropriate exact-descriptor validator.
        #[derive(Debug)]
        pub(crate) struct ReceivedFdV1 {
            role: ContractFdRoleV1,
            descriptor: OwnedFd,
        }

        impl ReceivedFdV1 {
            /// Returns the validated position-preserving semantic role.
            #[must_use]
            pub(crate) const fn role(&self) -> ContractFdRoleV1 {
                self.role
            }

            /// Borrows the received descriptor without exposing a raw integer.
            #[must_use]
            pub(crate) fn descriptor(&self) -> BorrowedFd<'_> {
                self.descriptor.as_fd()
            }
        }

        /// Successful exact-length frame receive and owned descriptor inventory.
        #[derive(Debug)]
        pub(crate) struct ReceivedFrameV1 {
            received_length: usize,
            observed_credentials: ExpectedPeerCredentialsV1,
            descriptors: Vec<ReceivedFdV1>,
        }

        impl ReceivedFrameV1 {
            /// Returns the exact received frame length.
            #[must_use]
            pub(crate) const fn received_length(&self) -> usize {
                self.received_length
            }

            /// Returns the one kernel-observed credential record after its exact
            /// peer comparison; only same-crate typed joins may project it.
            #[must_use]
            pub(crate) const fn observed_credentials(&self) -> ExpectedPeerCredentialsV1 {
                self.observed_credentials
            }

            /// Returns descriptors in their validated wire order.
            #[must_use]
            pub(crate) fn descriptors(&self) -> &[ReceivedFdV1] {
                &self.descriptors
            }
        }

        /// Receives one exact generator frame with fixed ancillary flags and
        /// exhaustive credential and descriptor validation.
        ///
        /// # Errors
        ///
        /// Returns [`AncillaryReceiveErrorV1`] for any receive failure or drift in
        /// peer role, frame envelope, credentials, CMSG structure, or FD inventory.
        fn receive_generator_frame_v1(
            socket: BorrowedFd<'_>,
            frame_buffer: &mut [u8; CONTRACT_MAX_FRAME_BYTES_V1],
            expectation: &StrictReceiveExpectationV1,
        ) -> Result<ReceivedFrameV1, AncillaryReceiveErrorV1> {
            receive_for_peer_v1(
                ExpectedPeerRoleV1::Generator,
                socket,
                frame_buffer,
                expectation,
            )
        }

        /// Receives one exact worker frame with fixed ancillary flags and
        /// exhaustive credential and descriptor validation.
        ///
        /// # Errors
        ///
        /// Returns [`AncillaryReceiveErrorV1`] for any receive failure or drift in
        /// peer role, frame envelope, credentials, CMSG structure, or FD inventory.
        fn receive_worker_frame_v1(
            socket: BorrowedFd<'_>,
            frame_buffer: &mut [u8; CONTRACT_MAX_FRAME_BYTES_V1],
            expectation: &StrictReceiveExpectationV1,
        ) -> Result<ReceivedFrameV1, AncillaryReceiveErrorV1> {
            receive_for_peer_v1(
                ExpectedPeerRoleV1::Worker,
                socket,
                frame_buffer,
                expectation,
            )
        }

        /// Receives one exact supervisor frame on the generator child's
        /// inherited endpoint.
        ///
        /// # Errors
        ///
        /// Returns [`AncillaryReceiveErrorV1`] for disabled `SO_PASSCRED`, a
        /// receive failure, or any envelope, credential, CMSG, or FD drift.
        fn receive_supervisor_for_generator_frame_v1(
            socket: BorrowedFd<'_>,
            frame_buffer: &mut [u8; CONTRACT_MAX_FRAME_BYTES_V1],
            expectation: &StrictReceiveExpectationV1,
        ) -> Result<ReceivedFrameV1, AncillaryReceiveErrorV1> {
            receive_for_peer_v1(
                ExpectedPeerRoleV1::SupervisorForGenerator,
                socket,
                frame_buffer,
                expectation,
            )
        }

        /// Receives one exact supervisor frame on the worker child's inherited
        /// endpoint.
        ///
        /// # Errors
        ///
        /// Returns [`AncillaryReceiveErrorV1`] for disabled `SO_PASSCRED`, a
        /// receive failure, or any envelope, credential, CMSG, or FD drift.
        fn receive_supervisor_for_worker_frame_v1(
            socket: BorrowedFd<'_>,
            frame_buffer: &mut [u8; CONTRACT_MAX_FRAME_BYTES_V1],
            expectation: &StrictReceiveExpectationV1,
        ) -> Result<ReceivedFrameV1, AncillaryReceiveErrorV1> {
            receive_for_peer_v1(
                ExpectedPeerRoleV1::SupervisorForWorker,
                socket,
                frame_buffer,
                expectation,
            )
        }

        fn take_received_rights_ownership_v1(
            raw_fds: &[i32],
        ) -> (Vec<OwnedFd>, Option<AncillaryReceiveErrorV1>) {
            let mut raw_seen = Vec::with_capacity(raw_fds.len());
            let mut owned = Vec::with_capacity(raw_fds.len());
            let mut first_error = None;
            for raw_descriptor in raw_fds.iter().copied() {
                if raw_descriptor < 0 {
                    first_error
                        .get_or_insert(AncillaryReceiveErrorV1::InvalidReceivedFd(raw_descriptor));
                    continue;
                }
                if raw_seen.contains(&raw_descriptor) {
                    first_error.get_or_insert(AncillaryReceiveErrorV1::DuplicateReceivedFd(
                        raw_descriptor,
                    ));
                    continue;
                }
                raw_seen.push(raw_descriptor);
                // SAFETY: a successful `recvmsg` with `SCM_RIGHTS` installs each
                // parsed nonnegative descriptor into this process. This is the
                // first owner created for every unique result. All unique results
                // are acquired before a duplicate error is returned, so every
                // installed descriptor is closed on every later failure path.
                owned.push(unsafe { OwnedFd::from_raw_fd(raw_descriptor) });
            }
            (owned, first_error)
        }

        fn receive_for_peer_v1(
            peer: ExpectedPeerRoleV1,
            socket: BorrowedFd<'_>,
            frame_buffer: &mut [u8; CONTRACT_MAX_FRAME_BYTES_V1],
            expectation: &StrictReceiveExpectationV1,
        ) -> Result<ReceivedFrameV1, AncillaryReceiveErrorV1> {
            validate_expected_peer_role_v1(expectation, peer)?;
            if !socket_passcred(socket).map_err(|_| AncillaryReceiveErrorV1::PasscredNotEnabled)? {
                return Err(AncillaryReceiveErrorV1::PasscredNotEnabled);
            }
            let mut control = ControlBufferV1([0; MAX_CONTROL_BYTES_V1]);
            let mut io_vector = IoVectorV1 {
                base: frame_buffer.as_mut_ptr().cast(),
                length: expectation.frame_length,
            };
            let mut message = MessageHeaderV1 {
                name: null_mut(),
                name_length: 0,
                io_vectors: &mut io_vector,
                io_vector_count: 1,
                io_vector_padding: 0,
                control: control.0.as_mut_ptr().cast(),
                control_length: 112,
                control_padding: 0,
                returned_flags: 0,
            };
            // SAFETY: the selected target's pinned musl `msghdr` and `iovec`
            // layouts are represented above; every pointer is writable for its
            // declared length for the duration of this single fixed-flag call.
            let received =
                unsafe { c_recvmsg(socket.as_raw_fd(), &mut message, MSG_CMSG_CLOEXEC_V1) };
            if received < 0 {
                let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
                return Err(AncillaryReceiveErrorV1::ReceiveFailed(code));
            }
            let received_length = usize::try_from(received)
                .map_err(|_| AncillaryReceiveErrorV1::ArithmeticOverflow)?;
            let control_length = usize::try_from(message.control_length)
                .map_err(|_| AncillaryReceiveErrorV1::ArithmeticOverflow)?;
            if control_length > MAX_CONTROL_BYTES_V1 {
                return Err(AncillaryReceiveErrorV1::ControlLengthOutOfRange(
                    control_length,
                ));
            }
            let mut outcome = parse_control_v1(&control.0[..control_length]);
            let envelope = MessageEnvelopeV1 {
                received_length,
                returned_flags: u32::from_ne_bytes(message.returned_flags.to_ne_bytes()),
            };

            let (owned, ownership_error) =
                take_received_rights_ownership_v1(&outcome.parsed.raw_fds);
            if let Some(error) = ownership_error {
                outcome.record_error(error);
            }
            let validated = validate_parsed_v1(expectation, envelope, &outcome)?;
            let observed_credentials = validated.credentials;
            ::core::debug_assert_eq!(validated.raw_fds().len(), owned.len());
            let descriptors = validated
                .ordered_roles()
                .iter()
                .copied()
                .zip(owned)
                .map(|(role, descriptor)| ReceivedFdV1 { role, descriptor })
                .collect();
            Ok(ReceivedFrameV1 {
                received_length,
                observed_credentials,
                descriptors,
            })
        }

        fn send_seqpacket_once_v1(
            endpoint: SeqpacketEndpointV1,
            frame: &[u8],
            descriptors: &[OwnedFd],
            credential_source: SendCredentialSourceV1,
        ) -> Result<SeqpacketEndpointV1, AncillarySendErrorV1> {
            if !(1..=CONTRACT_MAX_FRAME_BYTES_V1).contains(&frame.len()) {
                return Err(AncillarySendErrorV1::FrameLength);
            }
            if descriptors.len() > CONTRACT_MAX_FRAME_FDS_V1 {
                return Err(AncillarySendErrorV1::DescriptorCount);
            }

            let borrowed_descriptors = descriptors
                .iter()
                .map(AsFd::as_fd)
                .collect::<Vec<BorrowedFd<'_>>>();
            let mut control_space = [MaybeUninit::uninit();
                rustix::cmsg_space!(ScmCredentials(1), ScmRights(CONTRACT_MAX_FRAME_FDS_V1))];
            let mut control = SendAncillaryBuffer::new(&mut control_space);
            match credential_source {
                SendCredentialSourceV1::AutomaticChild => {}
                SendCredentialSourceV1::ExplicitSupervisor(credentials) => {
                    if !control.push(SendAncillaryMessage::ScmCredentials(credentials)) {
                        return Err(AncillarySendErrorV1::ControlEncoding);
                    }
                }
            }
            if !borrowed_descriptors.is_empty() {
                if !control.push(SendAncillaryMessage::ScmRights(&borrowed_descriptors)) {
                    return Err(AncillarySendErrorV1::ControlEncoding);
                }
            }
            let vectors = [IoSlice::new(frame)];
            let sent = rustix::net::sendmsg(
                endpoint.descriptor.as_fd(),
                &vectors,
                &mut control,
                SendFlags::EOR | SendFlags::NOSIGNAL,
            )
            .map_err(|_| AncillarySendErrorV1::SendFailed)?;
            if sent != frame.len() {
                return Err(AncillarySendErrorV1::IncompleteEnqueue);
            }
            Ok(endpoint)
        }

        fn verify_worker_post_enqueue_cloexec_v1(
            initial: FdFlags,
            restored: FdFlags,
        ) -> Result<(), ()> {
            if restored == initial | FdFlags::CLOEXEC {
                Ok(())
            } else {
                Err(())
            }
        }

        #[cfg(test)]
        mod inherited_fd3_subprocess_tests {
            use super::*;
            use std::fs::{File, read_link};
            use std::process::Command;

            const SCENARIO_ENV_V1: &str = "EIP0045_D6A_ADOPTION_SCENARIO_V1";
            const SCENARIOS_V1: [&str; 9] = [
                "generator-success",
                "worker-stdio-surplus",
                "repeated-after-success",
                "first-failure-cross-role",
                "wrong-fd",
                "wrong-shape",
                "passcred-disabled",
                "nonblocking",
                "cloexec",
            ];

            fn endpoint_descriptor_v1(
                role: SeqpacketEndpointRoleV1,
                clear_cloexec: bool,
            ) -> OwnedFd {
                let peer_role = match role {
                    SeqpacketEndpointRoleV1::Generator => {
                        SeqpacketEndpointRoleV1::SupervisorGenerator
                    }
                    SeqpacketEndpointRoleV1::Worker => SeqpacketEndpointRoleV1::SupervisorWorker,
                    _ => panic!("fixture role must be a child endpoint"),
                };
                let (local, peer) = create_seqpacket_pair_v1(role, peer_role).unwrap();
                drop(peer);
                let SeqpacketEndpointV1 { descriptor, .. } = local;
                if clear_cloexec {
                    let mut flags = fcntl_getfd(descriptor.as_fd()).unwrap();
                    flags.remove(FdFlags::CLOEXEC);
                    fcntl_setfd(descriptor.as_fd(), flags).unwrap();
                }
                descriptor
            }

            fn assert_closed_v1(raw_descriptor: i32) {
                assert!(
                    read_link(format!("/proc/self/fd/{raw_descriptor}")).is_err(),
                    "consumed descriptor {raw_descriptor} remained open"
                );
            }

            fn observation_count_v1() -> usize {
                ENDPOINT_OBSERVATION_CALLS_V1.load(Ordering::Relaxed)
            }

            fn assert_observation_delta_v1(before: usize, expected: usize) {
                assert_eq!(observation_count_v1() - before, expected);
            }

            fn observe_inventory_names_v1(
                names: &[&[u8]],
                enumeration_descriptor: i32,
            ) -> Result<(), InheritedEndpointAdoptionErrorV1> {
                let mut inventory = WorkerPostExecFdInventoryV1::new();
                for name in names {
                    inventory.observe_entry_v1(name, enumeration_descriptor)?;
                }
                inventory.finish_v1()
            }

            #[test]
            fn worker_post_exec_fd_inventory_accumulator_is_exact_and_bounded_v1() {
                assert!(observe_inventory_names_v1(&[b".", b"3", b"..", b"7"], 7).is_ok());
                for rejected in [
                    &[b"3".as_slice()][..],
                    &[b"7".as_slice()][..],
                    &[b"3".as_slice(), b"8".as_slice()][..],
                    &[b"3".as_slice(), b"3".as_slice()][..],
                    &[b"7".as_slice(), b"7".as_slice()][..],
                    &[b"3".as_slice(), b"7".as_slice(), b"8".as_slice()][..],
                    &[b"03".as_slice(), b"7".as_slice()][..],
                    &[b"+3".as_slice(), b"7".as_slice()][..],
                    &[b"fd3".as_slice(), b"7".as_slice()][..],
                    &[b"2147483648".as_slice(), b"7".as_slice()][..],
                    &[b"".as_slice(), b"7".as_slice()][..],
                ] {
                    assert!(observe_inventory_names_v1(rejected, 7).is_err());
                }
            }

            fn generator_success_v1() {
                let descriptor = endpoint_descriptor_v1(SeqpacketEndpointRoleV1::Generator, true);
                assert_eq!(descriptor.as_raw_fd(), 3);
                let before = observation_count_v1();
                let GeneratorEndpointV1(endpoint) =
                    try_adopt_generator_exec_inherited_fd3_once_v1(descriptor).unwrap();
                assert_observation_delta_v1(before, 2);
                assert_eq!(endpoint.descriptor.as_raw_fd(), 3);
                let observed = observe_endpoint_v1(
                    endpoint.descriptor.as_fd(),
                    SeqpacketEndpointRoleV1::Generator,
                )
                .unwrap();
                assert!(!observed.nonblocking);
                assert!(!observed.close_on_exec);
                assert_eq!(
                    endpoint.commitment,
                    SeqpacketEndpointCommitmentV1::from_observation(
                        SeqpacketEndpointRoleV1::Generator,
                        observed.descriptor_identity,
                        observed.socket_cookie,
                    )
                );
            }

            fn worker_stdio_surplus_v1() {
                let descriptor = endpoint_descriptor_v1(SeqpacketEndpointRoleV1::Worker, true);
                let raw_descriptor = descriptor.as_raw_fd();
                assert_eq!(raw_descriptor, 3);
                let before = observation_count_v1();
                assert!(
                    try_adopt_worker_exec_inherited_fd3_once_v1(descriptor).is_err(),
                    "post-exec Worker adoption must reject inherited stdio"
                );
                assert_observation_delta_v1(before, 0);
                assert_closed_v1(raw_descriptor);
            }

            fn repeated_after_success_v1() {
                let descriptor = endpoint_descriptor_v1(SeqpacketEndpointRoleV1::Generator, true);
                let before = observation_count_v1();
                let generator = try_adopt_generator_exec_inherited_fd3_once_v1(descriptor).unwrap();
                assert_observation_delta_v1(before, 2);
                drop(generator);

                let repeated = endpoint_descriptor_v1(SeqpacketEndpointRoleV1::Worker, true);
                let repeated_raw = repeated.as_raw_fd();
                assert_eq!(repeated_raw, 3);
                let before = observation_count_v1();
                assert!(
                    try_adopt_worker_exec_inherited_fd3_once_v1(repeated).is_err(),
                    "the shared gate must reject a cross-role second attempt"
                );
                assert_observation_delta_v1(before, 0);
                assert_closed_v1(repeated_raw);
            }

            fn first_failure_cross_role_v1() {
                let invalid: OwnedFd = File::open("/dev/null").unwrap().into();
                let invalid_raw = invalid.as_raw_fd();
                assert_eq!(invalid_raw, 3);
                let before = observation_count_v1();
                assert!(try_adopt_generator_exec_inherited_fd3_once_v1(invalid).is_err());
                assert_observation_delta_v1(before, 1);
                assert_closed_v1(invalid_raw);

                let valid = endpoint_descriptor_v1(SeqpacketEndpointRoleV1::Worker, true);
                let valid_raw = valid.as_raw_fd();
                assert_eq!(valid_raw, 3);
                let before = observation_count_v1();
                assert!(try_adopt_worker_exec_inherited_fd3_once_v1(valid).is_err());
                assert_observation_delta_v1(before, 0);
                assert_closed_v1(valid_raw);
            }

            fn wrong_fd_v1() {
                let (kept, rejected) = create_seqpacket_pair_v1(
                    SeqpacketEndpointRoleV1::Generator,
                    SeqpacketEndpointRoleV1::SupervisorGenerator,
                )
                .unwrap();
                let rejected_raw = rejected.descriptor.as_raw_fd();
                assert_eq!(kept.descriptor.as_raw_fd(), 3);
                assert_ne!(rejected_raw, 3);
                let before = observation_count_v1();
                assert!(
                    try_adopt_generator_exec_inherited_fd3_once_v1(rejected.descriptor).is_err()
                );
                assert_observation_delta_v1(before, 0);
                assert_closed_v1(rejected_raw);
                fcntl_getfd(kept.descriptor.as_fd()).unwrap();
            }

            fn wrong_shape_v1() {
                let descriptor: OwnedFd = File::open("/dev/null").unwrap().into();
                let raw_descriptor = descriptor.as_raw_fd();
                assert_eq!(raw_descriptor, 3);
                let before = observation_count_v1();
                assert!(try_adopt_generator_exec_inherited_fd3_once_v1(descriptor).is_err());
                assert_observation_delta_v1(before, 1);
                assert_closed_v1(raw_descriptor);
            }

            fn passcred_disabled_v1() {
                let descriptor = endpoint_descriptor_v1(SeqpacketEndpointRoleV1::Generator, true);
                let raw_descriptor = descriptor.as_raw_fd();
                assert_eq!(raw_descriptor, 3);
                set_socket_passcred(descriptor.as_fd(), false).unwrap();
                let before = observation_count_v1();
                assert!(try_adopt_generator_exec_inherited_fd3_once_v1(descriptor).is_err());
                assert_observation_delta_v1(before, 1);
                assert_closed_v1(raw_descriptor);
            }

            fn nonblocking_v1() {
                let descriptor = endpoint_descriptor_v1(SeqpacketEndpointRoleV1::Generator, true);
                let raw_descriptor = descriptor.as_raw_fd();
                assert_eq!(raw_descriptor, 3);
                let status = fcntl_getfl(descriptor.as_fd()).unwrap();
                rustix::fs::fcntl_setfl(descriptor.as_fd(), status | OFlags::NONBLOCK).unwrap();
                let before = observation_count_v1();
                assert!(try_adopt_generator_exec_inherited_fd3_once_v1(descriptor).is_err());
                assert_observation_delta_v1(before, 1);
                assert_closed_v1(raw_descriptor);
            }

            fn cloexec_v1() {
                let descriptor = endpoint_descriptor_v1(SeqpacketEndpointRoleV1::Generator, false);
                let raw_descriptor = descriptor.as_raw_fd();
                assert_eq!(raw_descriptor, 3);
                let before = observation_count_v1();
                assert!(try_adopt_generator_exec_inherited_fd3_once_v1(descriptor).is_err());
                assert_observation_delta_v1(before, 1);
                assert_closed_v1(raw_descriptor);
            }

            fn run_scenario_v1(scenario: &str) {
                match scenario {
                    "generator-success" => generator_success_v1(),
                    "worker-stdio-surplus" => worker_stdio_surplus_v1(),
                    "repeated-after-success" => repeated_after_success_v1(),
                    "first-failure-cross-role" => first_failure_cross_role_v1(),
                    "wrong-fd" => wrong_fd_v1(),
                    "wrong-shape" => wrong_shape_v1(),
                    "passcred-disabled" => passcred_disabled_v1(),
                    "nonblocking" => nonblocking_v1(),
                    "cloexec" => cloexec_v1(),
                    _ => panic!("unknown selected-target adoption scenario"),
                }
            }

            #[test]
            fn inherited_fd3_adoption_selected_target_subprocess_v1() {
                if let Ok(scenario) = std::env::var(SCENARIO_ENV_V1) {
                    run_scenario_v1(&scenario);
                    eprintln!("D6A_SELECTED_TARGET_SCENARIO_OK={scenario}");
                    return;
                }

                let scenario_count = SCENARIOS_V1
                    .iter()
                    .filter(|scenario| !scenario.is_empty())
                    .count();
                assert_eq!(scenario_count, 9);
                let executable = std::env::current_exe().unwrap();
                for scenario in SCENARIOS_V1 {
                    let output = Command::new("/bin/bash")
                        .arg("-c")
                        .arg("for fd in {3..37}; do eval \"exec ${fd}>&-\"; done; exec \"$@\"")
                        .arg("eip0045-g0b31-adoption-fixture")
                        .arg(&executable)
                        .arg("inherited_fd3_adoption_selected_target_subprocess_v1")
                        .arg("--nocapture")
                        .env(SCENARIO_ENV_V1, scenario)
                        .output()
                        .unwrap();
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    assert!(
                        output.status.success()
                            && stdout.contains("1 passed")
                            && stderr
                                .contains(&format!("D6A_SELECTED_TARGET_SCENARIO_OK={scenario}")),
                        "selected-target scenario {scenario} failed:\nstdout={stdout}\nstderr={stderr}"
                    );
                }
            }
        }

        #[cfg(test)]
        mod received_rights_ownership_tests {
            use super::*;
            use std::os::fd::IntoRawFd;
            use std::process::Command;

            const ISOLATED_STAGE_ENV_V1: &str = "EIP0045_G0B2_RIGHTS_OWNERSHIP_ISOLATED_STAGE_V1";
            const CHILD_OK_PREFIX_V1: &str = "G0B2_RIGHTS_OWNERSHIP_CHILD_OK=";
            const DUPLICATE_TEST_FILTER_V1: &str = concat!(
                "ancillary::strict_model::selected_target::received_rights_ownership_tests::",
                "received_rights_ownership_rejects_duplicate_and_negative_without_leaks_v1"
            );
            const SUCCESS_TEST_FILTER_V1: &str = concat!(
                "ancillary::strict_model::selected_target::received_rights_ownership_tests::",
                "received_rights_ownership_success_lives_until_drop_v1"
            );

            fn enter_isolated_process_v1(test_filter: &str) -> bool {
                match std::env::var(ISOLATED_STAGE_ENV_V1) {
                    Ok(stage) => {
                        assert_eq!(stage, test_filter, "ownership-test stage drift");
                        false
                    }
                    Err(std::env::VarError::NotPresent) => {
                        let output = Command::new("/usr/bin/timeout")
                            .arg("--signal=KILL")
                            .arg("20s")
                            .arg(std::env::current_exe().unwrap())
                            .env(ISOLATED_STAGE_ENV_V1, test_filter)
                            .arg(test_filter)
                            .arg("--exact")
                            .arg("--nocapture")
                            .arg("--test-threads=1")
                            .output()
                            .unwrap();
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        let expected_marker = format!("{CHILD_OK_PREFIX_V1}{test_filter}");
                        assert!(
                            output.status.success()
                                && (stdout.contains(&expected_marker)
                                    || stderr.contains(&expected_marker)),
                            "isolated ownership test {test_filter} failed:\nstdout={}\nstderr={}",
                            stdout,
                            stderr
                        );
                        true
                    }
                    Err(error) => panic!("ownership-test stage is not Unicode: {error}"),
                }
            }

            fn transferred_dev_null_v1() -> i32 {
                let descriptor: OwnedFd = File::open("/dev/null").unwrap().into();
                descriptor.into_raw_fd()
            }

            fn assert_closed_v1(raw_descriptor: i32) {
                assert!(
                    read_link(format!("/proc/self/fd/{raw_descriptor}")).is_err(),
                    "received descriptor {raw_descriptor} remained open"
                );
            }

            #[test]
            fn received_rights_ownership_rejects_duplicate_and_negative_without_leaks_v1() {
                if enter_isolated_process_v1(DUPLICATE_TEST_FILTER_V1) {
                    return;
                }
                let duplicate = transferred_dev_null_v1();
                let later = transferred_dev_null_v1();
                let (owned, error) =
                    take_received_rights_ownership_v1(&[duplicate, duplicate, later]);
                assert!(matches!(
                    error,
                    Some(AncillaryReceiveErrorV1::DuplicateReceivedFd(raw)) if raw == duplicate
                ));
                drop(owned);
                assert_closed_v1(duplicate);
                assert_closed_v1(later);

                let before_negative = transferred_dev_null_v1();
                let after_negative = transferred_dev_null_v1();
                let (owned, error) =
                    take_received_rights_ownership_v1(&[before_negative, -1, after_negative]);
                assert_eq!(error, Some(AncillaryReceiveErrorV1::InvalidReceivedFd(-1)));
                drop(owned);
                assert_closed_v1(before_negative);
                assert_closed_v1(after_negative);
                eprintln!("{CHILD_OK_PREFIX_V1}{DUPLICATE_TEST_FILTER_V1}");
            }

            #[test]
            fn received_rights_ownership_success_lives_until_drop_v1() {
                if enter_isolated_process_v1(SUCCESS_TEST_FILTER_V1) {
                    return;
                }
                let first = transferred_dev_null_v1();
                let second = transferred_dev_null_v1();
                let (owned, error) = take_received_rights_ownership_v1(&[first, second]);
                assert_eq!(error, None);
                for raw_descriptor in [first, second] {
                    assert!(read_link(format!("/proc/self/fd/{raw_descriptor}")).is_ok());
                }
                drop(owned);
                assert_closed_v1(first);
                assert_closed_v1(second);
                eprintln!("{CHILD_OK_PREFIX_V1}{SUCCESS_TEST_FILTER_V1}");
            }
        }

        #[cfg(test)]
        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        mod generator_peer_session_runtime_tests {
            use super::*;
            use eip0045_h0_contract::ReplayRoleV2;
            use eip0045_h0_contract::state::AttemptPhaseV1;
            use eip0045_h0_contract::wire::{
                AncillaryShapeV1, ClosedResultBodyV1, FdAccessV1, FdCommitmentV1, FdIdentityV1,
                FdRoleV1, FdStatusV1, FilesystemNodeKindV1, FrameDirectionV1, FrameInputV1,
                G0_GENERATOR_BOUND_RAW_FRAME_BYTES_V1, G0WorkerBootstrapInboundInputV1,
                GeneratorBoundBodyV1, MemfdSealsV1, PeerCredentialsV1, PreSessionRecordKindV1,
                ProcessInventoryEntryV1, ProcessInventoryKindV1, ProviderSessionInputV1,
                ProviderSessionMaterialV1, PublicationTargetCommitmentV1, RequestCommitmentV1,
                RequestRoleBlockV1, SealPresenceV1, SealedIngressManifestV1, SessionOfferInputV1,
                SessionOfferV1, SockFilterInstructionV1, WireFrameV1, WorkerBootstrapBodyInputV1,
                WorkerBootstrapBodyV1, WorkerTransferManifestV1,
                encode_generator_bound_raw_frame_v1, encode_pre_session_record_v1,
                g0_final_result_content_digest_v1,
            };
            use rustix::fs::{MemfdFlags, Mode, fcntl_add_seals, fcntl_setfl, memfd_create, open};
            use rustix::io::write;
            use rustix::process::{getgid, getpid, getuid};
            use std::process::Command;

            const STAGE_ENV_V1: &str = "EIP0045_G0B1_RUNTIME_STAGE_V1";
            const SCENARIO_ENV_V1: &str = "EIP0045_G0B1_RUNTIME_SCENARIO_V1";
            const SUPERVISOR_STAGE_V1: &str = "supervisor";
            const GENERATOR_STAGE_V1: &str = "generator";
            const TEST_FILTER_V1: &str = concat!(
                "ancillary::strict_model::selected_target::generator_peer_session_runtime_tests::",
                "generator_peer_session_selected_target_runtime_v1"
            );
            const INHERITED_GENERATOR_ENDPOINT_FD_V1: i32 = 3;
            const POSITIVE_SCENARIO_V1: &str = "positive-full-session";
            const NEGATIVE_SCENARIO_V1: &str = "negative-offer-byte-969";
            const SCENARIOS_V1: [&str; 2] = [POSITIVE_SCENARIO_V1, NEGATIVE_SCENARIO_V1];
            const G0B2_STAGE_ENV_V1: &str = "EIP0045_G0B2_REAL_RUNTIME_STAGE_V1";
            const G0B2_SCENARIO_ENV_V1: &str = "EIP0045_G0B2_REAL_RUNTIME_SCENARIO_V1";
            const G0B2_TEST_FILTER_V1: &str = concat!(
                "ancillary::strict_model::selected_target::generator_peer_session_runtime_tests::",
                "generator_bound_closed_result_selected_target_real_runtime_v1"
            );
            const G0B2_POSITIVE_SCENARIO_V1: &str = "positive-real-closed-result";
            const G0B2_NEGATIVE_TRUNCATED_SCENARIO_V1: &str = "negative-message-truncated";
            const G0B2_NEGATIVE_RIGHTS_SCENARIO_V1: &str = "negative-extra-right";
            const G0B2_NEGATIVE_PHYSICAL_SCENARIO_V1: &str = "negative-extra-seal";
            const G0B2_SCENARIOS_V1: [&str; 4] = [
                G0B2_POSITIVE_SCENARIO_V1,
                G0B2_NEGATIVE_TRUNCATED_SCENARIO_V1,
                G0B2_NEGATIVE_RIGHTS_SCENARIO_V1,
                G0B2_NEGATIVE_PHYSICAL_SCENARIO_V1,
            ];
            const G0B2_FINAL_RESULT_CONTENT_V1: &[u8] = b"eip0045-g0b2-real-final-result-v1\n";

            fn descriptor_v1(seed: u64) -> DescriptorIdentityV1 {
                DescriptorIdentityV1::try_new(seed, seed + 1, seed + 2).unwrap()
            }

            fn request_v1() -> RequestCommitmentV1 {
                let ingress = SealedIngressManifestV1::try_new(&[]).unwrap();
                let publication_root = FdCommitmentV1::try_new(
                    FdRoleV1::PublicationRoot,
                    FdIdentityV1::Filesystem {
                        descriptor: descriptor_v1(10),
                        node_kind: FilesystemNodeKindV1::Directory,
                    },
                    FdStatusV1::new(FdAccessV1::Path, false, true),
                )
                .unwrap();
                let publication = PublicationTargetCommitmentV1::try_new(
                    &publication_root,
                    [0x61; 32],
                    [0x62; 32],
                )
                .unwrap();
                let mut seed = 0_u8;
                let role_blocks = ReplayRoleV2::ALL.map(|role| {
                    seed += 1;
                    RequestRoleBlockV1::new(role, [seed; 32], [seed + 4; 32], [seed + 8; 32])
                });
                RequestCommitmentV1::try_new(
                    [0x31; 32],
                    [0x32; 32],
                    [0x33; 32],
                    &ingress,
                    &publication,
                    &role_blocks,
                )
                .unwrap()
            }

            fn local_facts_v1() -> G0GeneratorPeerLocalFactsV1 {
                G0GeneratorPeerLocalFactsV1::try_new(
                    request_v1(),
                    [0x41; 32],
                    [0x42; 32],
                    [0x43; 32],
                    [0x44; 32],
                    [0x51; 32],
                )
                .unwrap()
            }

            fn adopt_inherited_generator_endpoint_v1() -> GeneratorEndpointV1 {
                // SAFETY: each supervisor stage creates the generator socket
                // first, verifies it is fd3, and clears CLOEXEC only there.
                let inherited = unsafe { OwnedFd::from_raw_fd(INHERITED_GENERATOR_ENDPOINT_FD_V1) };
                try_adopt_generator_exec_inherited_fd3_once_v1(inherited).unwrap()
            }

            fn send_input_v1(frame: &[u8]) -> PreparedSupervisorSendV1 {
                PreparedSupervisorSendV1 {
                    frame: frame.to_vec().into_boxed_slice(),
                    descriptors: Vec::new(),
                }
            }

            fn receive_input_v1(frame: &[u8], child_pid: u32) -> PreparedSupervisorReceiveV1 {
                let credentials = ExpectedPeerCredentialsV1::try_new(
                    child_pid,
                    getuid().as_raw(),
                    getgid().as_raw(),
                )
                .unwrap();
                PreparedSupervisorReceiveV1 {
                    frame: frame.to_vec().into_boxed_slice(),
                    expectation: StrictReceiveExpectationV1::try_for_generator(
                        frame.len(),
                        credentials,
                        &[],
                    )
                    .unwrap(),
                }
            }

            fn supervisor_credentials_v1() -> UCred {
                UCred {
                    pid: getpid(),
                    uid: getuid(),
                    gid: getgid(),
                }
            }

            fn typed_ok_v1<T>(
                result: Result<T, SupervisorTypedTransitionErrorV1>,
                transition: &str,
            ) -> T {
                match result {
                    Ok(value) => value,
                    Err(_) => panic!("G0b-1 typed supervisor transition failed: {transition}"),
                }
            }

            fn generator_seal_profile_v1() -> GeneratorSealProfileV1 {
                GeneratorSealProfileV1::try_new(&[SockFilterInstructionV1::new(
                    0x06,
                    0,
                    0,
                    0x7fff_0000,
                )])
                .unwrap()
            }

            fn generator_inventory_v1() -> ProcessInventoryV1 {
                let endpoint = FdCommitmentV1::try_new(
                    FdRoleV1::GeneratorEndpoint,
                    FdIdentityV1::Socket {
                        endpoint_digest: [0x71; 32],
                    },
                    FdStatusV1::new(FdAccessV1::Socket, false, false),
                )
                .unwrap();
                let supervisor = FdCommitmentV1::try_new(
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
                        descriptor: descriptor_v1(10),
                        node_kind: FilesystemNodeKindV1::Directory,
                    },
                    FdStatusV1::new(FdAccessV1::Path, false, false),
                )
                .unwrap();
                ProcessInventoryV1::try_new(
                    ProcessInventoryKindV1::GeneratorPostExec,
                    &[
                        ProcessInventoryEntryV1::new(3, endpoint),
                        ProcessInventoryEntryV1::new(4, supervisor),
                        ProcessInventoryEntryV1::new(5, publication),
                    ],
                )
                .unwrap()
            }

            fn generator_bound_contracts_v1() -> (
                GeneratorSealProfileV1,
                ProcessInventoryV1,
                SealedIngressManifestV1,
            ) {
                (
                    generator_seal_profile_v1(),
                    generator_inventory_v1(),
                    SealedIngressManifestV1::try_new(&[]).unwrap(),
                )
            }

            fn final_result_commitment_v1(content: &[u8]) -> FdCommitmentV1 {
                FdCommitmentV1::try_new(
                    FdRoleV1::FinalResult,
                    FdIdentityV1::Memfd {
                        size: u64::try_from(content.len()).unwrap(),
                        content_digest: g0_final_result_content_digest_v1(content).unwrap(),
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

            fn write_all_v1(descriptor: BorrowedFd<'_>, content: &[u8]) {
                let mut written = 0_usize;
                while written < content.len() {
                    let count = write(descriptor, &content[written..]).unwrap();
                    assert_ne!(count, 0);
                    written += count;
                }
            }

            fn final_result_memfd_v1(content: &[u8], extra_seal: bool) -> OwnedFd {
                let writable = memfd_create(
                    c"eip0045-g0b2-final-result-v1",
                    MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
                )
                .unwrap();
                write_all_v1(writable.as_fd(), content);
                let mut seals =
                    SealFlags::GROW | SealFlags::SHRINK | SealFlags::WRITE | SealFlags::SEAL;
                if extra_seal {
                    seals |= SealFlags::FUTURE_WRITE;
                }
                fcntl_add_seals(writable.as_fd(), seals).unwrap();
                let reopened = open(
                    format!("/proc/self/fd/{}", writable.as_raw_fd()),
                    OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .unwrap();
                drop(writable);
                reopened
            }

            fn provider_session_v1(
                request: &RequestCommitmentV1,
                generator_channel: &ChannelIdentityV1,
                worker_channel: &ChannelIdentityV1,
            ) -> ProviderSessionMaterialV1 {
                ProviderSessionMaterialV1::try_new(ProviderSessionInputV1 {
                    request,
                    appliance_measurement: [0x41; 32],
                    supervisor_measurement: [0x42; 32],
                    generator_measurement: [0x43; 32],
                    worker_measurement: [0x44; 32],
                    generator_nonce: [0x51; 32],
                    supervisor_nonce: [0x52; 32],
                    supervisor_pid: getpid().as_raw_nonzero().get().unsigned_abs(),
                    supervisor_start_epoch: 92,
                    generator_channel,
                    worker_channel,
                })
                .unwrap()
            }

            fn run_generator_stage_v1(scenario: &str) {
                let endpoint = adopt_inherited_generator_endpoint_v1();
                let awaiting_offer = endpoint.begin_peer_session_v1(local_facts_v1());
                match scenario {
                    POSITIVE_SCENARIO_V1 => {
                        let commit = awaiting_offer.receive_session_offer_once_v1().unwrap();
                        let supervisor_commit = commit.send_generator_commit_once_v1().unwrap();
                        let reveal = supervisor_commit
                            .receive_supervisor_commit_once_v1()
                            .unwrap();
                        let supervisor_reveal = reveal.send_generator_reveal_once_v1().unwrap();
                        let provider: GeneratorProviderSessionEndpointV1 = supervisor_reveal
                            .receive_supervisor_reveal_once_v1()
                            .unwrap();
                        eprintln!("G0B1_GENERATOR_PROVIDER_SESSION_OK={scenario}");
                        drop(provider);
                    }
                    NEGATIVE_SCENARIO_V1 => {
                        assert!(awaiting_offer.receive_session_offer_once_v1().is_err());
                        eprintln!("G0B1_GENERATOR_OFFER_REJECTED_NO_AUTHORITY={scenario}");
                    }
                    _ => panic!("unknown G0b-1 generator runtime scenario"),
                }
            }

            #[allow(clippy::too_many_lines)]
            fn run_supervisor_stage_v1(scenario: &str) {
                let channel = create_generator_channel_v1().unwrap();
                let (generator, supervisor, generator_channel) = channel.into_endpoints();
                let worker_channel = create_worker_channel_v1().unwrap();
                let supervisor_user_namespace = std::fs::File::open("/proc/self/ns/user").unwrap();
                let supervisor_receiver_user_namespace =
                    descriptor_identity_v1(supervisor_user_namespace.as_fd()).unwrap();
                assert_eq!(
                    generator.descriptor().as_raw_fd(),
                    INHERITED_GENERATOR_ENDPOINT_FD_V1
                );
                assert!(
                    fcntl_getfd(generator.descriptor())
                        .unwrap()
                        .contains(FdFlags::CLOEXEC)
                );
                let mut child_flags = fcntl_getfd(generator.descriptor()).unwrap();
                child_flags.remove(FdFlags::CLOEXEC);
                fcntl_setfd(generator.descriptor(), child_flags).unwrap();
                assert!(
                    !fcntl_getfd(generator.descriptor())
                        .unwrap()
                        .contains(FdFlags::CLOEXEC)
                );
                assert!(
                    fcntl_getfd(supervisor.0.descriptor.as_fd())
                        .unwrap()
                        .contains(FdFlags::CLOEXEC)
                );
                assert!(
                    fcntl_getfd(worker_channel.supervisor.0.descriptor.as_fd())
                        .unwrap()
                        .contains(FdFlags::CLOEXEC)
                );
                assert!(
                    fcntl_getfd(worker_channel.worker.descriptor())
                        .unwrap()
                        .contains(FdFlags::CLOEXEC)
                );
                assert!(
                    fcntl_getfd(supervisor_user_namespace.as_fd())
                        .unwrap()
                        .contains(FdFlags::CLOEXEC)
                );
                assert_eq!(getuid().as_raw(), WORKER_OUTER_UID_V1);
                assert_eq!(getgid().as_raw(), WORKER_OUTER_GID_V1);

                let executable = std::env::current_exe().unwrap();
                let mut child = Command::new(&executable)
                    .arg(TEST_FILTER_V1)
                    .arg("--exact")
                    .arg("--nocapture")
                    .arg("--test-threads=1")
                    .env(STAGE_ENV_V1, GENERATOR_STAGE_V1)
                    .env(SCENARIO_ENV_V1, scenario)
                    .spawn()
                    .unwrap();
                let child_pid = child.id();
                drop(generator);

                let request = request_v1();
                let supervisor_nonce = [0x52; 32];
                let generator_commit = encode_pre_session_record_v1(
                    PreSessionRecordKindV1::GeneratorCommit,
                    &request,
                    [0x51; 32],
                )
                .unwrap();
                let generator_reveal = encode_pre_session_record_v1(
                    PreSessionRecordKindV1::GeneratorReveal,
                    &request,
                    [0x51; 32],
                )
                .unwrap();
                let supervisor_commit = encode_pre_session_record_v1(
                    PreSessionRecordKindV1::SupervisorCommit,
                    &request,
                    supervisor_nonce,
                )
                .unwrap();
                let supervisor_reveal = encode_pre_session_record_v1(
                    PreSessionRecordKindV1::SupervisorReveal,
                    &request,
                    supervisor_nonce,
                )
                .unwrap();
                let offer = SessionOfferV1::try_new(SessionOfferInputV1 {
                    request: &request,
                    appliance_measurement: [0x41; 32],
                    supervisor_measurement: [0x42; 32],
                    generator_measurement: [0x43; 32],
                    worker_measurement: [0x44; 32],
                    supervisor_pid: getpid().as_raw_nonzero().get().unsigned_abs(),
                    supervisor_start_epoch: 92,
                    generator_channel: &generator_channel,
                    worker_channel: worker_channel.channel_identity(),
                    supervisor_generator_endpoint: supervisor.commitment(),
                    supervisor_receiver_user_namespace,
                })
                .unwrap();
                let exact_offer = *offer.bytes();
                let mut transmitted_offer = exact_offer;
                if scenario == NEGATIVE_SCENARIO_V1 {
                    transmitted_offer[969] ^= 1;
                    let changed: Vec<_> = exact_offer
                        .iter()
                        .zip(transmitted_offer.iter())
                        .enumerate()
                        .filter_map(|(index, (before, after))| (before != after).then_some(index))
                        .collect();
                    assert_eq!(changed, [969]);
                }
                let operation = typed_ok_v1(
                    prepare_session_offer_send_v1(
                        supervisor,
                        SessionOfferSendInputV1 {
                            prepared: send_input_v1(&transmitted_offer),
                        },
                    ),
                    "prepare SessionOffer",
                );
                let sent = operation
                    .enqueue_once_v1(supervisor_credentials_v1())
                    .unwrap();

                match scenario {
                    POSITIVE_SCENARIO_V1 => {
                        let commit_received = typed_ok_v1(
                            sent.receive_generator_nonce_commit_once_v1(
                                GeneratorCommitReceiveInputV1 {
                                    prepared: receive_input_v1(&generator_commit, child_pid),
                                },
                            ),
                            "receive GCommit",
                        );
                        let operation = typed_ok_v1(
                            prepare_supervisor_commit_send_v1(
                                commit_received,
                                SupervisorCommitSendInputV1 {
                                    prepared: send_input_v1(&supervisor_commit),
                                },
                            ),
                            "prepare SCommit",
                        );
                        let sent = operation
                            .enqueue_once_v1(supervisor_credentials_v1())
                            .unwrap();
                        let reveal_received = typed_ok_v1(
                            sent.receive_generator_nonce_reveal_once_v1(
                                GeneratorRevealReceiveInputV1 {
                                    prepared: receive_input_v1(&generator_reveal, child_pid),
                                },
                            ),
                            "receive GReveal",
                        );
                        let operation = typed_ok_v1(
                            prepare_supervisor_reveal_send_v1(
                                reveal_received,
                                SupervisorRevealSendInputV1 {
                                    prepared: send_input_v1(&supervisor_reveal),
                                },
                            ),
                            "prepare SReveal",
                        );
                        drop(
                            operation
                                .enqueue_once_v1(supervisor_credentials_v1())
                                .unwrap(),
                        );
                        assert!(child.wait().unwrap().success());
                        eprintln!("G0B1_SUPERVISOR_FULL_SESSION_OK={scenario}");
                    }
                    NEGATIVE_SCENARIO_V1 => {
                        assert!(child.wait().unwrap().success());
                        assert!(
                            sent.receive_generator_nonce_commit_once_v1(
                                GeneratorCommitReceiveInputV1 {
                                    prepared: receive_input_v1(&generator_commit, child_pid),
                                },
                            )
                            .is_err()
                        );
                        eprintln!("G0B1_SUPERVISOR_TERMINAL_NO_GCOMMIT={scenario}");
                    }
                    _ => panic!("unknown G0b-1 supervisor runtime scenario"),
                }
            }

            #[test]
            fn generator_peer_session_selected_target_runtime_v1() {
                let scenario = std::env::var(SCENARIO_ENV_V1).ok();
                match std::env::var(STAGE_ENV_V1).as_deref() {
                    Ok(SUPERVISOR_STAGE_V1) => {
                        let scenario = scenario.as_deref().expect("supervisor scenario");
                        run_supervisor_stage_v1(scenario);
                        eprintln!("G0B1_SUPERVISOR_SCENARIO_OK={scenario}");
                    }
                    Ok(GENERATOR_STAGE_V1) => {
                        let scenario = scenario.as_deref().expect("generator scenario");
                        run_generator_stage_v1(scenario);
                    }
                    Ok(_) => panic!("unknown G0b-1 runtime stage"),
                    Err(_) => {
                        assert_eq!(SCENARIOS_V1.len(), 2);
                        let executable = std::env::current_exe().unwrap();
                        for scenario in SCENARIOS_V1 {
                            let output = Command::new("/bin/bash")
                                .arg("-c")
                                .arg(
                                    "for fd in {3..37}; do eval \"exec ${fd}>&-\"; done; exec \"$@\"",
                                )
                                .arg("eip0045-g0b1-runtime-fixture")
                                .arg("/usr/bin/timeout")
                                .arg("--signal=KILL")
                                .arg("20s")
                                .arg("/usr/bin/unshare")
                                .arg("--user")
                                .arg("--map-user=20002")
                                .arg("--map-group=20002")
                                .arg(&executable)
                                .arg(TEST_FILTER_V1)
                                .arg("--exact")
                                .arg("--nocapture")
                                .arg("--test-threads=1")
                                .env(STAGE_ENV_V1, SUPERVISOR_STAGE_V1)
                                .env(SCENARIO_ENV_V1, scenario)
                                .output()
                                .unwrap();
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            let deciding_marker = if scenario == POSITIVE_SCENARIO_V1 {
                                "G0B1_SUPERVISOR_FULL_SESSION_OK=positive-full-session"
                            } else {
                                "G0B1_SUPERVISOR_TERMINAL_NO_GCOMMIT=negative-offer-byte-969"
                            };
                            assert!(
                                output.status.success()
                                    && stdout.contains("1 passed")
                                    && stderr.contains(&format!(
                                        "G0B1_SUPERVISOR_SCENARIO_OK={scenario}"
                                    ))
                                    && stderr.contains(deciding_marker),
                                "G0b-1 runtime scenario {scenario} failed:\nstdout={stdout}\nstderr={stderr}"
                            );
                        }
                    }
                }
            }

            fn canonical_closed_result_raw_v1(
                session: &ProviderSessionMaterialV1,
                generator_bound_digest: [u8; 32],
                supervisor_receiver_user_namespace: DescriptorIdentityV1,
            ) -> Vec<u8> {
                let commitment = final_result_commitment_v1(G0B2_FINAL_RESULT_CONTENT_V1);
                let body = ClosedResultBodyV1::try_new(session, [0xb2; 32], &commitment).unwrap();
                let credentials = PeerCredentialsV1::try_new(
                    getpid().as_raw_nonzero().get().unsigned_abs(),
                    getuid().as_raw(),
                    getgid().as_raw(),
                    supervisor_receiver_user_namespace,
                )
                .unwrap();
                WireFrameV1::try_new(FrameInputV1 {
                    direction: FrameDirectionV1::SupervisorToGenerator,
                    ordinal: 1,
                    phase: AttemptPhaseV1::Closed,
                    session_id: session.session_id(),
                    previous_hash: generator_bound_digest,
                    body: body.bytes(),
                    credentials,
                    fd_commitments: &[commitment],
                    ancillary: AncillaryShapeV1::canonical(1),
                })
                .unwrap()
                .encode_raw_frame()
                .unwrap()
            }

            fn assert_g0b2_receive_slots_before_v1() {
                assert!(
                    std::fs::read_link(format!(
                        "/proc/self/fd/{INHERITED_GENERATOR_ENDPOINT_FD_V1}"
                    ))
                    .is_ok(),
                    "the consumed generator endpoint must still own fd3 before ClosedResult"
                );
                for raw_descriptor in 4..=5 {
                    assert!(
                        std::fs::read_link(format!("/proc/self/fd/{raw_descriptor}")).is_err(),
                        "fixture slot fd{raw_descriptor} was unexpectedly occupied before recvmsg"
                    );
                }
            }

            fn assert_g0b2_receive_slots_closed_v1() {
                for raw_descriptor in 3..=5 {
                    assert!(
                        std::fs::read_link(format!("/proc/self/fd/{raw_descriptor}")).is_err(),
                        "terminal ClosedResult left received slot fd{raw_descriptor} open"
                    );
                }
            }

            fn run_g0b2_generator_stage_v1(scenario: &str) {
                let endpoint = adopt_inherited_generator_endpoint_v1();
                let provider = endpoint
                    .begin_peer_session_v1(local_facts_v1())
                    .receive_session_offer_once_v1()
                    .unwrap()
                    .send_generator_commit_once_v1()
                    .unwrap()
                    .receive_supervisor_commit_once_v1()
                    .unwrap()
                    .send_generator_reveal_once_v1()
                    .unwrap()
                    .receive_supervisor_reveal_once_v1()
                    .unwrap();
                let (seal_profile, inventory, ingress) = generator_bound_contracts_v1();
                let awaiting_closed_result = provider
                    .send_generator_bound_once_v1(&GeneratorBoundSendInputV1::new(
                        &seal_profile,
                        &inventory,
                        &ingress,
                    ))
                    .unwrap();
                assert_g0b2_receive_slots_before_v1();
                match scenario {
                    G0B2_POSITIVE_SCENARIO_V1 => {
                        let _verified: G0ClosedResultVerifiedV1 = awaiting_closed_result
                            .receive_and_verify_closed_result_once_v1()
                            .unwrap();
                        assert_g0b2_receive_slots_closed_v1();
                        eprintln!("G0B2_GENERATOR_VALIDATED_RESULT={scenario}");
                    }
                    G0B2_NEGATIVE_TRUNCATED_SCENARIO_V1
                    | G0B2_NEGATIVE_RIGHTS_SCENARIO_V1
                    | G0B2_NEGATIVE_PHYSICAL_SCENARIO_V1 => {
                        assert!(
                            awaiting_closed_result
                                .receive_and_verify_closed_result_once_v1()
                                .is_err()
                        );
                        assert_g0b2_receive_slots_closed_v1();
                        eprintln!("G0B2_GENERATOR_TERMINAL_REJECTION_OK={scenario}");
                    }
                    _ => panic!("unknown G0b-2 generator runtime scenario"),
                }
            }

            #[allow(clippy::too_many_lines)]
            fn run_g0b2_supervisor_stage_v1(scenario: &str) {
                let channel = create_generator_channel_v1().unwrap();
                let (generator, supervisor, generator_channel) = channel.into_endpoints();
                let worker_channel = create_worker_channel_v1().unwrap();
                let supervisor_user_namespace = std::fs::File::open("/proc/self/ns/user").unwrap();
                let supervisor_receiver_user_namespace =
                    descriptor_identity_v1(supervisor_user_namespace.as_fd()).unwrap();
                assert_eq!(
                    generator.descriptor().as_raw_fd(),
                    INHERITED_GENERATOR_ENDPOINT_FD_V1
                );
                let mut child_flags = fcntl_getfd(generator.descriptor()).unwrap();
                assert!(child_flags.contains(FdFlags::CLOEXEC));
                child_flags.remove(FdFlags::CLOEXEC);
                fcntl_setfd(generator.descriptor(), child_flags).unwrap();
                assert!(
                    !fcntl_getfd(generator.descriptor())
                        .unwrap()
                        .contains(FdFlags::CLOEXEC)
                );
                assert!(
                    fcntl_getfd(supervisor.0.descriptor.as_fd())
                        .unwrap()
                        .contains(FdFlags::CLOEXEC)
                );
                assert_eq!(getuid().as_raw(), WORKER_OUTER_UID_V1);
                assert_eq!(getgid().as_raw(), WORKER_OUTER_GID_V1);

                let executable = std::env::current_exe().unwrap();
                let mut child = Command::new(&executable)
                    .arg(G0B2_TEST_FILTER_V1)
                    .arg("--exact")
                    .arg("--nocapture")
                    .arg("--test-threads=1")
                    .env(G0B2_STAGE_ENV_V1, GENERATOR_STAGE_V1)
                    .env(G0B2_SCENARIO_ENV_V1, scenario)
                    .spawn()
                    .unwrap();
                let child_pid = child.id();
                drop(generator);

                let request = request_v1();
                let supervisor_nonce = [0x52; 32];
                let generator_commit = encode_pre_session_record_v1(
                    PreSessionRecordKindV1::GeneratorCommit,
                    &request,
                    [0x51; 32],
                )
                .unwrap();
                let generator_reveal = encode_pre_session_record_v1(
                    PreSessionRecordKindV1::GeneratorReveal,
                    &request,
                    [0x51; 32],
                )
                .unwrap();
                let supervisor_commit = encode_pre_session_record_v1(
                    PreSessionRecordKindV1::SupervisorCommit,
                    &request,
                    supervisor_nonce,
                )
                .unwrap();
                let supervisor_reveal = encode_pre_session_record_v1(
                    PreSessionRecordKindV1::SupervisorReveal,
                    &request,
                    supervisor_nonce,
                )
                .unwrap();
                let offer = SessionOfferV1::try_new(SessionOfferInputV1 {
                    request: &request,
                    appliance_measurement: [0x41; 32],
                    supervisor_measurement: [0x42; 32],
                    generator_measurement: [0x43; 32],
                    worker_measurement: [0x44; 32],
                    supervisor_pid: getpid().as_raw_nonzero().get().unsigned_abs(),
                    supervisor_start_epoch: 92,
                    generator_channel: &generator_channel,
                    worker_channel: worker_channel.channel_identity(),
                    supervisor_generator_endpoint: supervisor.commitment(),
                    supervisor_receiver_user_namespace,
                })
                .unwrap();
                let session = provider_session_v1(
                    &request,
                    &generator_channel,
                    worker_channel.channel_identity(),
                );
                let operation = typed_ok_v1(
                    prepare_session_offer_send_v1(
                        supervisor,
                        SessionOfferSendInputV1 {
                            prepared: send_input_v1(offer.bytes()),
                        },
                    ),
                    "prepare SessionOffer for G0b-2",
                );
                let sent = operation
                    .enqueue_once_v1(supervisor_credentials_v1())
                    .unwrap();
                let commit_received = typed_ok_v1(
                    sent.receive_generator_nonce_commit_once_v1(GeneratorCommitReceiveInputV1 {
                        prepared: receive_input_v1(&generator_commit, child_pid),
                    }),
                    "receive GCommit for G0b-2",
                );
                let operation = typed_ok_v1(
                    prepare_supervisor_commit_send_v1(
                        commit_received,
                        SupervisorCommitSendInputV1 {
                            prepared: send_input_v1(&supervisor_commit),
                        },
                    ),
                    "prepare SCommit for G0b-2",
                );
                let sent = operation
                    .enqueue_once_v1(supervisor_credentials_v1())
                    .unwrap();
                let reveal_received = typed_ok_v1(
                    sent.receive_generator_nonce_reveal_once_v1(GeneratorRevealReceiveInputV1 {
                        prepared: receive_input_v1(&generator_reveal, child_pid),
                    }),
                    "receive GReveal for G0b-2",
                );
                let operation = typed_ok_v1(
                    prepare_supervisor_reveal_send_v1(
                        reveal_received,
                        SupervisorRevealSendInputV1 {
                            prepared: send_input_v1(&supervisor_reveal),
                        },
                    ),
                    "prepare SReveal for G0b-2",
                );
                let sent = operation
                    .enqueue_once_v1(supervisor_credentials_v1())
                    .unwrap();
                let endpoint = match sent {
                    SupervisorGeneratorSentEndpointV1 {
                        endpoint,
                        phase: SupervisorGeneratorSendPhaseV1::AwaitGeneratorBound,
                    } => endpoint,
                    _ => panic!("G0b-2 supervisor phase drift after SReveal"),
                };

                let child_credentials = ExpectedPeerCredentialsV1::try_new(
                    child_pid,
                    getuid().as_raw(),
                    getgid().as_raw(),
                )
                .unwrap();
                let expectation = StrictReceiveExpectationV1::try_for_generator(
                    G0_GENERATOR_BOUND_RAW_FRAME_BYTES_V1,
                    child_credentials,
                    &[],
                )
                .unwrap();
                let mut frame_buffer = [0_u8; CONTRACT_MAX_FRAME_BYTES_V1];
                let received = receive_generator_frame_v1(
                    endpoint.descriptor.as_fd(),
                    &mut frame_buffer,
                    &expectation,
                )
                .unwrap();
                assert_eq!(
                    received.received_length(),
                    G0_GENERATOR_BOUND_RAW_FRAME_BYTES_V1
                );
                assert_eq!(received.observed_credentials(), child_credentials);
                assert!(received.descriptors().is_empty());

                let (seal_profile, inventory, ingress) = generator_bound_contracts_v1();
                let body =
                    GeneratorBoundBodyV1::try_new(&session, &seal_profile, &inventory, &ingress)
                        .unwrap();
                let expected_generator_bound =
                    encode_generator_bound_raw_frame_v1(&session, &body).unwrap();
                assert_eq!(
                    &frame_buffer[..G0_GENERATOR_BOUND_RAW_FRAME_BYTES_V1],
                    expected_generator_bound.as_slice()
                );
                let generator_credentials = PeerCredentialsV1::try_new(
                    child_pid,
                    getuid().as_raw(),
                    getgid().as_raw(),
                    supervisor_receiver_user_namespace,
                )
                .unwrap();
                let generator_frame = WireFrameV1::try_new(FrameInputV1 {
                    direction: FrameDirectionV1::GeneratorToSupervisor,
                    ordinal: 0,
                    phase: AttemptPhaseV1::GeneratorBound,
                    session_id: session.session_id(),
                    previous_hash: expected_generator_bound[49..81].try_into().unwrap(),
                    body: body.bytes(),
                    credentials: generator_credentials,
                    fd_commitments: &[],
                    ancillary: AncillaryShapeV1::canonical(0),
                })
                .unwrap();
                assert_eq!(
                    generator_frame.encode_raw_frame().unwrap().as_slice(),
                    expected_generator_bound
                );
                let generator_bound_digest =
                    G0GeneratorBoundTranscriptCandidateV1::prepare(&session, &generator_frame)
                        .unwrap()
                        .digest();
                let mut closed_result = canonical_closed_result_raw_v1(
                    &session,
                    generator_bound_digest,
                    supervisor_receiver_user_namespace,
                );
                assert_eq!(closed_result.len(), G0_CLOSED_RESULT_RAW_FRAME_BYTES_V1);
                if scenario == G0B2_NEGATIVE_TRUNCATED_SCENARIO_V1 {
                    closed_result.push(0);
                }
                let descriptors = match scenario {
                    G0B2_POSITIVE_SCENARIO_V1 | G0B2_NEGATIVE_TRUNCATED_SCENARIO_V1 => {
                        vec![final_result_memfd_v1(G0B2_FINAL_RESULT_CONTENT_V1, false)]
                    }
                    G0B2_NEGATIVE_RIGHTS_SCENARIO_V1 => vec![
                        final_result_memfd_v1(G0B2_FINAL_RESULT_CONTENT_V1, false),
                        final_result_memfd_v1(G0B2_FINAL_RESULT_CONTENT_V1, false),
                    ],
                    G0B2_NEGATIVE_PHYSICAL_SCENARIO_V1 => {
                        vec![final_result_memfd_v1(G0B2_FINAL_RESULT_CONTENT_V1, true)]
                    }
                    _ => panic!("unknown G0b-2 supervisor runtime scenario"),
                };
                let endpoint = send_seqpacket_once_v1(
                    endpoint,
                    &closed_result,
                    &descriptors,
                    SendCredentialSourceV1::ExplicitSupervisor(supervisor_credentials_v1()),
                )
                .unwrap();
                drop(endpoint);
                assert!(child.wait().unwrap().success());
                eprintln!("G0B2_SUPERVISOR_REAL_PACKET_OK={scenario}");
            }

            #[test]
            fn generator_bound_closed_result_selected_target_real_runtime_v1() {
                let scenario = std::env::var(G0B2_SCENARIO_ENV_V1).ok();
                match std::env::var(G0B2_STAGE_ENV_V1).as_deref() {
                    Ok(SUPERVISOR_STAGE_V1) => {
                        let scenario = scenario.as_deref().expect("G0b-2 supervisor scenario");
                        run_g0b2_supervisor_stage_v1(scenario);
                        eprintln!("G0B2_SUPERVISOR_SCENARIO_OK={scenario}");
                    }
                    Ok(GENERATOR_STAGE_V1) => {
                        let scenario = scenario.as_deref().expect("G0b-2 generator scenario");
                        run_g0b2_generator_stage_v1(scenario);
                    }
                    Ok(_) => panic!("unknown G0b-2 runtime stage"),
                    Err(_) => {
                        assert_eq!(G0B2_SCENARIOS_V1.len(), 4);
                        let executable = std::env::current_exe().unwrap();
                        for scenario in G0B2_SCENARIOS_V1 {
                            let output = Command::new("/bin/bash")
                                .arg("-c")
                                .arg(
                                    "for fd in {3..37}; do eval \"exec ${fd}>&-\"; done; exec \"$@\"",
                                )
                                .arg("eip0045-g0b2-runtime-fixture")
                                .arg("/usr/bin/timeout")
                                .arg("--signal=KILL")
                                .arg("20s")
                                .arg("/usr/bin/unshare")
                                .arg("--user")
                                .arg("--map-user=20002")
                                .arg("--map-group=20002")
                                .arg(&executable)
                                .arg(G0B2_TEST_FILTER_V1)
                                .arg("--exact")
                                .arg("--nocapture")
                                .arg("--test-threads=1")
                                .env(G0B2_STAGE_ENV_V1, SUPERVISOR_STAGE_V1)
                                .env(G0B2_SCENARIO_ENV_V1, scenario)
                                .output()
                                .unwrap();
                            let stdout = String::from_utf8_lossy(&output.stdout);
                            let stderr = String::from_utf8_lossy(&output.stderr);
                            let generator_marker = if scenario == G0B2_POSITIVE_SCENARIO_V1 {
                                "G0B2_GENERATOR_VALIDATED_RESULT=positive-real-closed-result"
                            } else {
                                &format!("G0B2_GENERATOR_TERMINAL_REJECTION_OK={scenario}")
                            };
                            assert!(
                                output.status.success()
                                    && stdout.contains("1 passed")
                                    && stderr.contains(&format!(
                                        "G0B2_SUPERVISOR_SCENARIO_OK={scenario}"
                                    ))
                                    && stderr.contains(&format!(
                                        "G0B2_SUPERVISOR_REAL_PACKET_OK={scenario}"
                                    ))
                                    && stderr.contains(generator_marker),
                                "G0b-2 real runtime scenario {scenario} failed:\nstdout={stdout}\nstderr={stderr}"
                            );
                        }
                    }
                }
            }

            fn worker_transfer_commitment_v1(role: FdRoleV1, byte_length: u64) -> FdCommitmentV1 {
                let (access, seals, digest) = match role {
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
                    _ => panic!("worker preflight fixture received the wrong role"),
                };
                FdCommitmentV1::try_new(
                    role,
                    FdIdentityV1::Memfd {
                        size: byte_length,
                        content_digest: digest,
                        seals,
                    },
                    FdStatusV1::new(access, false, true),
                )
                .unwrap()
            }

            struct WorkerBootstrapInboundFixtureV1 {
                raw: Box<[u8]>,
                actual_rights_count: usize,
                observed_credentials: PeerCredentialsV1,
                local_worker_endpoint: SeqpacketEndpointCommitmentV1,
            }

            impl WorkerBootstrapInboundFixtureV1 {
                fn input_v1(&self) -> G0WorkerBootstrapInboundInputV1<'_> {
                    self.input_with_actual_rights_count_v1(self.actual_rights_count)
                }

                fn input_with_actual_rights_count_v1(
                    &self,
                    actual_rights_count: usize,
                ) -> G0WorkerBootstrapInboundInputV1<'_> {
                    G0WorkerBootstrapInboundInputV1 {
                        received_raw_frame: &self.raw,
                        actual_rights_count,
                        observed_credentials: self.observed_credentials,
                        local_worker_endpoint: &self.local_worker_endpoint,
                        expected_outer_uid: WORKER_OUTER_UID_V1,
                        expected_outer_gid: WORKER_OUTER_GID_V1,
                    }
                }
            }

            fn worker_bootstrap_inbound_fixture_v1(
                observation_length: u64,
                campaign_lengths: &[u64],
            ) -> WorkerBootstrapInboundFixtureV1 {
                let request = request_v1();
                let generator_endpoint = SeqpacketEndpointCommitmentV1::from_observation(
                    SeqpacketEndpointRoleV1::Generator,
                    descriptor_v1(100),
                    200,
                );
                let supervisor_generator_endpoint = SeqpacketEndpointCommitmentV1::from_observation(
                    SeqpacketEndpointRoleV1::SupervisorGenerator,
                    descriptor_v1(110),
                    210,
                );
                let supervisor_worker_endpoint = SeqpacketEndpointCommitmentV1::from_observation(
                    SeqpacketEndpointRoleV1::SupervisorWorker,
                    descriptor_v1(120),
                    220,
                );
                let worker_endpoint = SeqpacketEndpointCommitmentV1::from_observation(
                    SeqpacketEndpointRoleV1::Worker,
                    descriptor_v1(130),
                    230,
                );
                let generator_channel = ChannelIdentityV1::try_generator(
                    &generator_endpoint,
                    &supervisor_generator_endpoint,
                )
                .unwrap();
                let worker_channel =
                    ChannelIdentityV1::try_worker(&supervisor_worker_endpoint, &worker_endpoint)
                        .unwrap();
                let session = provider_session_v1(&request, &generator_channel, &worker_channel);
                let (seal_profile, generator_inventory, ingress) = generator_bound_contracts_v1();
                let generator_body = GeneratorBoundBodyV1::try_new(
                    &session,
                    &seal_profile,
                    &generator_inventory,
                    &ingress,
                )
                .unwrap();
                let generator_raw =
                    encode_generator_bound_raw_frame_v1(&session, &generator_body).unwrap();
                let generator_credentials = PeerCredentialsV1::try_new(
                    getpid().as_raw_nonzero().get().unsigned_abs(),
                    getuid().as_raw(),
                    getgid().as_raw(),
                    descriptor_v1(700),
                )
                .unwrap();
                let generator_frame = WireFrameV1::try_new(FrameInputV1 {
                    direction: FrameDirectionV1::GeneratorToSupervisor,
                    ordinal: 0,
                    phase: AttemptPhaseV1::GeneratorBound,
                    session_id: session.session_id(),
                    previous_hash: generator_raw[49..81].try_into().unwrap(),
                    body: generator_body.bytes(),
                    credentials: generator_credentials,
                    fd_commitments: &[],
                    ancillary: AncillaryShapeV1::canonical(0),
                })
                .unwrap();
                let generator_candidate =
                    G0GeneratorBoundTranscriptCandidateV1::prepare(&session, &generator_frame)
                        .unwrap();

                let observation =
                    worker_transfer_commitment_v1(FdRoleV1::Observation, observation_length);
                let campaigns = campaign_lengths
                    .iter()
                    .copied()
                    .enumerate()
                    .map(|(index, byte_length)| {
                        worker_transfer_commitment_v1(
                            FdRoleV1::CampaignInput(u8::try_from(index).unwrap()),
                            byte_length,
                        )
                    })
                    .collect::<Vec<_>>();
                let manifest = WorkerTransferManifestV1::try_new(&observation, &campaigns).unwrap();
                let endpoint_initial = FdCommitmentV1::try_new(
                    FdRoleV1::WorkerEndpoint,
                    FdIdentityV1::Socket {
                        endpoint_digest: worker_endpoint.digest(),
                    },
                    FdStatusV1::new(FdAccessV1::Socket, false, false),
                )
                .unwrap();
                let endpoint_transfer = FdCommitmentV1::try_new(
                    FdRoleV1::WorkerEndpoint,
                    FdIdentityV1::Socket {
                        endpoint_digest: worker_endpoint.digest(),
                    },
                    FdStatusV1::new(FdAccessV1::Socket, false, true),
                )
                .unwrap();
                let initial_inventory = ProcessInventoryV1::try_new(
                    ProcessInventoryKindV1::WorkerInitialPostExec,
                    &[ProcessInventoryEntryV1::new(3, endpoint_initial)],
                )
                .unwrap();
                let mut transfer_entries = Vec::with_capacity(campaigns.len() + 2);
                transfer_entries.push(ProcessInventoryEntryV1::new(3, endpoint_transfer));
                transfer_entries.push(ProcessInventoryEntryV1::new(4, observation));
                transfer_entries.extend(campaigns.iter().copied().enumerate().map(
                    |(index, campaign)| {
                        ProcessInventoryEntryV1::new(u8::try_from(index + 5).unwrap(), campaign)
                    },
                ));
                let transfer_inventory = ProcessInventoryV1::try_new(
                    ProcessInventoryKindV1::WorkerExpectedPostTransfer,
                    &transfer_entries,
                )
                .unwrap();
                let body = WorkerBootstrapBodyV1::try_new(WorkerBootstrapBodyInputV1 {
                    accepted_generator_bound_digest: generator_candidate.digest(),
                    session: &session,
                    supervisor_worker_endpoint: &supervisor_worker_endpoint,
                    supervisor_receiver_user_namespace: descriptor_v1(701),
                    worker_receiver_view_uid: WORKER_OUTER_UID_V1,
                    worker_receiver_view_gid: WORKER_OUTER_GID_V1,
                    worker_initial_inventory: &initial_inventory,
                    worker_transfer_inventory: &transfer_inventory,
                    worker_manifest: &manifest,
                })
                .unwrap();
                let observed_credentials = PeerCredentialsV1::try_new(
                    getpid().as_raw_nonzero().get().unsigned_abs(),
                    0,
                    0,
                    descriptor_v1(702),
                )
                .unwrap();
                let mut commitments = Vec::with_capacity(campaigns.len() + 1);
                commitments.push(observation);
                commitments.extend_from_slice(&campaigns);
                let frame = WireFrameV1::try_new(FrameInputV1 {
                    direction: FrameDirectionV1::SupervisorToWorker,
                    ordinal: 0,
                    phase: AttemptPhaseV1::UserMapsVerified,
                    session_id: session.session_id(),
                    previous_hash: generator_candidate.worker_genesis(),
                    body: body.bytes(),
                    credentials: observed_credentials,
                    fd_commitments: &commitments,
                    ancillary: AncillaryShapeV1::canonical(commitments.len()),
                })
                .unwrap();
                WorkerBootstrapInboundFixtureV1 {
                    raw: frame.encode_raw_frame().unwrap().into_boxed_slice(),
                    actual_rights_count: commitments.len(),
                    observed_credentials,
                    local_worker_endpoint: worker_endpoint,
                }
            }

            fn worker_bootstrap_candidate_v1(
                observation_length: u64,
                campaign_length: u64,
            ) -> G0WorkerBootstrapInboundCandidateV1 {
                let fixture =
                    worker_bootstrap_inbound_fixture_v1(observation_length, &[campaign_length]);
                G0WorkerBootstrapInboundCandidateV1::try_new(fixture.input_v1()).unwrap()
            }

            fn worker_preflight_memfd_v1(
                content: &[u8],
                seals: SealFlags,
                reopen_read_only: bool,
            ) -> OwnedFd {
                let writable = memfd_create(
                    c"eip0045-g0b32-worker-preflight-v1",
                    MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
                )
                .unwrap();
                write_all_v1(writable.as_fd(), content);
                if !seals.is_empty() {
                    fcntl_add_seals(writable.as_fd(), seals).unwrap();
                }
                if !reopen_read_only {
                    return writable;
                }
                let reopened = open(
                    format!("/proc/self/fd/{}", writable.as_raw_fd()),
                    OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .unwrap();
                drop(writable);
                reopened
            }

            fn assert_worker_preflight_rejected_and_closed_v1(
                candidate: &G0WorkerBootstrapInboundCandidateV1,
                role: WorkerBootstrapPreflightRoleV1,
                descriptor: OwnedFd,
            ) {
                let raw_descriptor = descriptor.as_raw_fd();
                assert!(
                    observe_worker_bootstrap_physical_preflight_v1(candidate, role, descriptor,)
                        .is_err()
                );
                assert!(read_link(format!("/proc/self/fd/{raw_descriptor}")).is_err());
            }

            fn assert_worker_preflight_fd_closed_v1(raw_descriptor: i32) {
                assert!(
                    read_link(format!("/proc/self/fd/{raw_descriptor}")).is_err(),
                    "WorkerBootstrap preflight retained fd{raw_descriptor}"
                );
            }

            fn exact_worker_bootstrap_post_receive_join_v1() -> &'static str {
                concat!(
                    "fnjoin_worker_bootstrap_post_receive_v1(",
                    "input:G0WorkerBootstrapInboundInputV1<'_>,",
                    "received_rights:Vec<OwnedFd>,",
                    ")->Result<WorkerBootstrapNormalizedCustodyV1,",
                    "WorkerBootstrapPreflightErrorV1>{",
                    "require_worker_bootstrap_rlimit_nofile_v1()?;",
                    "letdescriptor_count=input.actual_rights_count;",
                    "ifdescriptor_count==0",
                    "||descriptor_count>CONTRACT_MAX_FRAME_FDS_V1",
                    "||received_rights.len()!=descriptor_count",
                    "{returnErr(WorkerBootstrapPreflightErrorV1::terminal());}",
                    "letcandidate=G0WorkerBootstrapInboundCandidateV1::try_new(input)",
                    ".map_err(|_|WorkerBootstrapPreflightErrorV1::terminal())?;",
                    "letnormalized=normalize_worker_bootstrap_descriptors_v1(received_rights)?;",
                    "bind_worker_bootstrap_normalized_custody_v1(",
                    "WorkerBootstrapPreflightCandidateCustodyV1{",
                    "candidate,descriptor_count,},normalized,)}"
                )
            }

            fn worker_bootstrap_post_receive_kernel_is_exact_v1(source: &str) -> bool {
                let Some(start) = source.find("enum WorkerBootstrapPreflightRoleV1") else {
                    return false;
                };
                let Some(end) = source[start..]
                    .find("struct FinalResultPhysicalObservationV1")
                    .map(|offset| start + offset)
                else {
                    return false;
                };
                let masked_source = crate::d6b_rust_code_mask_v1(source);
                let masked_body = &masked_source[start..end];
                let join_declaration = "fn join_worker_bootstrap_post_receive_v1(";
                let mut join_starts = masked_body.match_indices(join_declaration);
                let Some((join_start, _)) = join_starts.next() else {
                    return false;
                };
                if join_starts.next().is_some() {
                    return false;
                }
                let Some(join_opening) = masked_body[join_start..]
                    .find('{')
                    .map(|offset| join_start + offset)
                else {
                    return false;
                };
                let join_closing =
                    crate::d6b_closing_brace_v1(masked_body.as_bytes(), join_opening);
                let compact_join = masked_body[join_start..=join_closing]
                    .split_whitespace()
                    .collect::<String>();
                compact_join == exact_worker_bootstrap_post_receive_join_v1()
                    && source[start..end]
                        .lines()
                        .map(str::trim)
                        .filter(|line| *line == join_declaration)
                        .count()
                        == 1
            }

            #[test]
            fn worker_bootstrap_physical_custody_v1() {
                let isolated_stage = "EIP0045_G0B32_PHYSICAL_ISOLATED_STAGE_V1";
                let test_filter = concat!(
                    "ancillary::strict_model::selected_target::generator_peer_session_runtime_tests::",
                    "worker_bootstrap_physical_custody_v1"
                );
                match std::env::var(isolated_stage) {
                    Ok(stage) => assert_eq!(stage, test_filter),
                    Err(std::env::VarError::NotPresent) => {
                        let status = Command::new("/bin/bash")
                            .arg("-c")
                            .arg("for fd in {3..37}; do eval \"exec ${fd}>&-\"; done; exec \"$@\"")
                            .arg("eip0045-g0b32-physical-fixture")
                            .arg("/usr/bin/timeout")
                            .arg("--signal=KILL")
                            .arg("20s")
                            .arg(std::env::current_exe().unwrap())
                            .arg(test_filter)
                            .arg("--exact")
                            .arg("--nocapture")
                            .arg("--test-threads=1")
                            .env(isolated_stage, test_filter)
                            .status()
                            .unwrap();
                        assert!(
                            status.success(),
                            "isolated physical preflight fixture failed"
                        );
                        return;
                    }
                    Err(error) => panic!("physical preflight stage is not Unicode: {error}"),
                }

                const OBSERVATION: &[u8] = b"";
                const CAMPAIGN: &[u8] = b"g0b32-campaign";
                let observation_seals = SealFlags::GROW | SealFlags::SHRINK;
                let campaign_seals = observation_seals | SealFlags::WRITE | SealFlags::SEAL;
                let endpoint: OwnedFd = File::open("/dev/null").unwrap().into();
                assert_eq!(
                    endpoint.as_raw_fd(),
                    3,
                    "isolated fixture did not reserve fd3"
                );
                let candidate = worker_bootstrap_candidate_v1(
                    u64::try_from(OBSERVATION.len()).unwrap(),
                    u64::try_from(CAMPAIGN.len()).unwrap(),
                );
                let observation = worker_preflight_memfd_v1(OBSERVATION, observation_seals, false);
                let campaign = worker_preflight_memfd_v1(CAMPAIGN, campaign_seals, true);
                let expected_observation = fstat(observation.as_fd()).unwrap();
                let expected_campaign = fstat(campaign.as_fd()).unwrap();
                let custody = bind_worker_bootstrap_normalized_custody_v1(
                    WorkerBootstrapPreflightCandidateCustodyV1 {
                        candidate,
                        descriptor_count: 2,
                    },
                    WorkerBootstrapNormalizedFdCustodyV1 {
                        descriptors: vec![observation, campaign],
                    },
                )
                .unwrap_or_else(|_| panic!("exact physical preflight rejected"));
                let _paired_candidate = &custody.candidate;
                assert_eq!(custody.roles.len(), 2);
                assert_eq!(
                    custody.roles[0].role,
                    WorkerBootstrapPreflightRoleV1::Observation
                );
                assert_eq!(
                    custody.roles[1].role,
                    WorkerBootstrapPreflightRoleV1::CampaignInput(0)
                );
                for (role, expected, expected_length, expected_seals) in [
                    (
                        &custody.roles[0],
                        expected_observation,
                        u64::try_from(OBSERVATION.len()).unwrap(),
                        observation_seals,
                    ),
                    (
                        &custody.roles[1],
                        expected_campaign,
                        u64::try_from(CAMPAIGN.len()).unwrap(),
                        campaign_seals,
                    ),
                ] {
                    assert_eq!(role.physical.device, expected.st_dev);
                    assert_eq!(role.physical.inode, expected.st_ino);
                    assert_eq!(role.physical.mode, expected.st_mode);
                    assert_eq!(role.physical.byte_length, expected_length);
                    assert_eq!(role.physical.seals, expected_seals);
                    assert!(role.physical.descriptor_flags.contains(FdFlags::CLOEXEC));
                    assert!(!role.physical.status_flags.contains(OFlags::NONBLOCK));
                    assert_eq!(
                        fstat(role.descriptor.as_fd()).unwrap().st_ino,
                        role.physical.inode
                    );
                }
                drop(custody);

                let missing_candidate = worker_bootstrap_candidate_v1(
                    u64::try_from(OBSERVATION.len()).unwrap(),
                    u64::try_from(CAMPAIGN.len()).unwrap(),
                );
                let missing_campaign =
                    worker_preflight_memfd_v1(OBSERVATION, observation_seals, false);
                let missing_campaign_raw = missing_campaign.as_raw_fd();
                assert!(
                    bind_worker_bootstrap_normalized_custody_v1(
                        WorkerBootstrapPreflightCandidateCustodyV1 {
                            candidate: missing_candidate,
                            descriptor_count: 2,
                        },
                        WorkerBootstrapNormalizedFdCustodyV1 {
                            descriptors: vec![missing_campaign],
                        },
                    )
                    .is_err()
                );
                assert!(
                    read_link(format!("/proc/self/fd/{missing_campaign_raw}")).is_err(),
                    "missing-descriptor rejection retained the partial custody"
                );

                let partial_candidate = worker_bootstrap_candidate_v1(
                    u64::try_from(OBSERVATION.len()).unwrap(),
                    u64::try_from(CAMPAIGN.len()).unwrap(),
                );
                let valid_observation =
                    worker_preflight_memfd_v1(OBSERVATION, observation_seals, false);
                let invalid_campaign = worker_preflight_memfd_v1(CAMPAIGN, campaign_seals, false);
                let valid_observation_raw = valid_observation.as_raw_fd();
                let invalid_campaign_raw = invalid_campaign.as_raw_fd();
                assert!(
                    bind_worker_bootstrap_normalized_custody_v1(
                        WorkerBootstrapPreflightCandidateCustodyV1 {
                            candidate: partial_candidate,
                            descriptor_count: 2,
                        },
                        WorkerBootstrapNormalizedFdCustodyV1 {
                            descriptors: vec![valid_observation, invalid_campaign],
                        },
                    )
                    .is_err()
                );
                for raw_descriptor in [valid_observation_raw, invalid_campaign_raw] {
                    assert!(
                        read_link(format!("/proc/self/fd/{raw_descriptor}")).is_err(),
                        "partial physical bind retained fd{raw_descriptor}"
                    );
                }

                assert!(checked_worker_bootstrap_size_v1(-1).is_err());
                let candidate = worker_bootstrap_candidate_v1(
                    u64::try_from(OBSERVATION.len()).unwrap(),
                    u64::try_from(CAMPAIGN.len()).unwrap(),
                );
                assert_worker_preflight_rejected_and_closed_v1(
                    &candidate,
                    WorkerBootstrapPreflightRoleV1::Observation,
                    File::open("/dev/null").unwrap().into(),
                );
                assert_worker_preflight_rejected_and_closed_v1(
                    &candidate,
                    WorkerBootstrapPreflightRoleV1::Observation,
                    worker_preflight_memfd_v1(b"wrong-size", observation_seals, false),
                );
                assert_worker_preflight_rejected_and_closed_v1(
                    &candidate,
                    WorkerBootstrapPreflightRoleV1::Observation,
                    worker_preflight_memfd_v1(OBSERVATION, observation_seals, true),
                );
                let write_only_source =
                    worker_preflight_memfd_v1(OBSERVATION, observation_seals, false);
                let write_only = open(
                    format!("/proc/self/fd/{}", write_only_source.as_raw_fd()),
                    OFlags::WRONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .unwrap();
                drop(write_only_source);
                assert_eq!(
                    fcntl_getfl(write_only.as_fd()).unwrap() & OFlags::ACCMODE,
                    OFlags::WRONLY
                );
                assert_worker_preflight_rejected_and_closed_v1(
                    &candidate,
                    WorkerBootstrapPreflightRoleV1::Observation,
                    write_only,
                );
                assert_worker_preflight_rejected_and_closed_v1(
                    &candidate,
                    WorkerBootstrapPreflightRoleV1::CampaignInput(0),
                    worker_preflight_memfd_v1(CAMPAIGN, campaign_seals, false),
                );

                let nonblocking = worker_preflight_memfd_v1(OBSERVATION, observation_seals, false);
                fcntl_setfl(nonblocking.as_fd(), OFlags::NONBLOCK).unwrap();
                assert_worker_preflight_rejected_and_closed_v1(
                    &candidate,
                    WorkerBootstrapPreflightRoleV1::Observation,
                    nonblocking,
                );
                let no_cloexec = worker_preflight_memfd_v1(OBSERVATION, observation_seals, false);
                let mut flags = fcntl_getfd(no_cloexec.as_fd()).unwrap();
                flags.remove(FdFlags::CLOEXEC);
                fcntl_setfd(no_cloexec.as_fd(), flags).unwrap();
                assert_worker_preflight_rejected_and_closed_v1(
                    &candidate,
                    WorkerBootstrapPreflightRoleV1::Observation,
                    no_cloexec,
                );
                for seals in [
                    SealFlags::SHRINK,
                    SealFlags::GROW,
                    observation_seals | SealFlags::WRITE,
                    observation_seals | SealFlags::FUTURE_WRITE,
                ] {
                    assert_worker_preflight_rejected_and_closed_v1(
                        &candidate,
                        WorkerBootstrapPreflightRoleV1::Observation,
                        worker_preflight_memfd_v1(OBSERVATION, seals, false),
                    );
                }
                for missing in [
                    SealFlags::GROW,
                    SealFlags::SHRINK,
                    SealFlags::WRITE,
                    SealFlags::SEAL,
                ] {
                    assert_worker_preflight_rejected_and_closed_v1(
                        &candidate,
                        WorkerBootstrapPreflightRoleV1::CampaignInput(0),
                        worker_preflight_memfd_v1(CAMPAIGN, campaign_seals & !missing, true),
                    );
                }
                assert_worker_preflight_rejected_and_closed_v1(
                    &candidate,
                    WorkerBootstrapPreflightRoleV1::CampaignInput(0),
                    worker_preflight_memfd_v1(
                        CAMPAIGN,
                        campaign_seals | SealFlags::FUTURE_WRITE,
                        true,
                    ),
                );
                assert_worker_preflight_rejected_and_closed_v1(
                    &candidate,
                    WorkerBootstrapPreflightRoleV1::CampaignInput(1),
                    worker_preflight_memfd_v1(CAMPAIGN, campaign_seals, true),
                );

                let fixture = worker_bootstrap_inbound_fixture_v1(
                    u64::try_from(OBSERVATION.len()).unwrap(),
                    &[u64::try_from(CAMPAIGN.len()).unwrap()],
                );
                let campaign = worker_preflight_memfd_v1(CAMPAIGN, campaign_seals, true);
                let observation = worker_preflight_memfd_v1(OBSERVATION, observation_seals, false);
                assert_eq!((observation.as_raw_fd(), campaign.as_raw_fd()), (4, 5));
                let custody = join_worker_bootstrap_post_receive_v1(
                    fixture.input_v1(),
                    vec![observation, campaign],
                )
                .unwrap_or_else(|_| panic!("exact K=2 post-receive join rejected"));
                assert_eq!(custody.roles.len(), 2);
                assert_eq!(
                    custody.roles[0].role,
                    WorkerBootstrapPreflightRoleV1::Observation
                );
                assert_eq!(
                    custody.roles[1].role,
                    WorkerBootstrapPreflightRoleV1::CampaignInput(0)
                );
                assert_eq!(
                    custody
                        .roles
                        .iter()
                        .map(|role| role.descriptor.as_raw_fd())
                        .collect::<Vec<_>>(),
                    vec![4, 5]
                );
                for raw_descriptor in [22, 23] {
                    assert_worker_preflight_fd_closed_v1(raw_descriptor);
                }
                drop(custody);
                for raw_descriptor in [4, 5] {
                    assert_worker_preflight_fd_closed_v1(raw_descriptor);
                }

                let mismatch_fixture = worker_bootstrap_inbound_fixture_v1(
                    u64::try_from(OBSERVATION.len()).unwrap(),
                    &[u64::try_from(CAMPAIGN.len()).unwrap()],
                );
                let mismatch_campaign = worker_preflight_memfd_v1(CAMPAIGN, campaign_seals, true);
                let extra_owner = worker_preflight_memfd_v1(CAMPAIGN, campaign_seals, true);
                let mismatch_observation =
                    worker_preflight_memfd_v1(OBSERVATION, observation_seals, false);
                assert_eq!(
                    (
                        mismatch_observation.as_raw_fd(),
                        mismatch_campaign.as_raw_fd(),
                        extra_owner.as_raw_fd()
                    ),
                    (4, 5, 6)
                );
                assert!(
                    join_worker_bootstrap_post_receive_v1(
                        mismatch_fixture.input_v1(),
                        vec![mismatch_observation, mismatch_campaign, extra_owner],
                    )
                    .is_err()
                );
                for raw_descriptor in [4, 5, 6, 22, 23, 24] {
                    assert_worker_preflight_fd_closed_v1(raw_descriptor);
                }

                let raw_count_fixture = worker_bootstrap_inbound_fixture_v1(
                    u64::try_from(OBSERVATION.len()).unwrap(),
                    &[u64::try_from(CAMPAIGN.len()).unwrap()],
                );
                let raw_count_observation =
                    worker_preflight_memfd_v1(OBSERVATION, observation_seals, false);
                assert_eq!(raw_count_observation.as_raw_fd(), 4);
                assert!(
                    join_worker_bootstrap_post_receive_v1(
                        raw_count_fixture.input_with_actual_rights_count_v1(1),
                        vec![raw_count_observation],
                    )
                    .is_err()
                );
                for raw_descriptor in [4, 22] {
                    assert_worker_preflight_fd_closed_v1(raw_descriptor);
                }

                let partial_fixture = worker_bootstrap_inbound_fixture_v1(
                    u64::try_from(OBSERVATION.len()).unwrap(),
                    &[u64::try_from(CAMPAIGN.len()).unwrap()],
                );
                let valid_observation =
                    worker_preflight_memfd_v1(OBSERVATION, observation_seals, false);
                let invalid_campaign = worker_preflight_memfd_v1(CAMPAIGN, campaign_seals, false);
                assert_eq!(
                    (valid_observation.as_raw_fd(), invalid_campaign.as_raw_fd()),
                    (4, 5)
                );
                assert!(
                    join_worker_bootstrap_post_receive_v1(
                        partial_fixture.input_v1(),
                        vec![valid_observation, invalid_campaign],
                    )
                    .is_err()
                );
                for raw_descriptor in [4, 5, 22, 23] {
                    assert_worker_preflight_fd_closed_v1(raw_descriptor);
                }

                let campaign_lengths = [1_u64; 15];
                let maximal_fixture = worker_bootstrap_inbound_fixture_v1(
                    u64::try_from(OBSERVATION.len()).unwrap(),
                    &campaign_lengths,
                );
                let mut maximal_descriptors = Vec::with_capacity(16);
                maximal_descriptors
                    .extend((0..15).map(|_| worker_preflight_memfd_v1(b"x", campaign_seals, true)));
                maximal_descriptors.insert(
                    0,
                    worker_preflight_memfd_v1(OBSERVATION, observation_seals, false),
                );
                assert_eq!(
                    maximal_descriptors
                        .iter()
                        .map(AsRawFd::as_raw_fd)
                        .collect::<Vec<_>>(),
                    (4..=19).collect::<Vec<_>>()
                );
                let maximal_custody = join_worker_bootstrap_post_receive_v1(
                    maximal_fixture.input_v1(),
                    maximal_descriptors,
                )
                .unwrap_or_else(|_| panic!("exact K=16 post-receive join rejected"));
                assert_eq!(maximal_custody.roles.len(), 16);
                assert_eq!(
                    maximal_custody.roles[0].role,
                    WorkerBootstrapPreflightRoleV1::Observation
                );
                for (index, role) in maximal_custody.roles[1..].iter().enumerate() {
                    assert_eq!(
                        role.role,
                        WorkerBootstrapPreflightRoleV1::CampaignInput(u8::try_from(index).unwrap())
                    );
                }
                assert_eq!(
                    maximal_custody
                        .roles
                        .iter()
                        .map(|role| role.descriptor.as_raw_fd())
                        .collect::<Vec<_>>(),
                    (4..=19).collect::<Vec<_>>()
                );
                for role in &maximal_custody.roles {
                    assert!(role.physical.descriptor_flags.contains(FdFlags::CLOEXEC));
                    assert!(!role.physical.status_flags.contains(OFlags::NONBLOCK));
                }
                for raw_descriptor in 22..=37 {
                    assert_worker_preflight_fd_closed_v1(raw_descriptor);
                }
                drop(maximal_custody);
                for raw_descriptor in 4..=19 {
                    assert_worker_preflight_fd_closed_v1(raw_descriptor);
                }

                let source = include_str!("ancillary.rs");
                let start = source.find("enum WorkerBootstrapPreflightRoleV1").unwrap();
                let end = source[start..]
                    .find("struct FinalResultPhysicalObservationV1")
                    .map(|offset| start + offset)
                    .unwrap();
                let body = &source[start..end];
                for required in [
                    "G0WorkerBootstrapInboundCandidateV1",
                    "start_observation_content_verifier_v1",
                    "start_campaign_input_content_verifier_v1",
                    "fcntl_getfd",
                    "fcntl_getfl",
                    "fstat",
                    "fcntl_get_seals",
                    "candidate: G0WorkerBootstrapInboundCandidateV1",
                    "descriptor: OwnedFd",
                ] {
                    assert!(
                        body.contains(required),
                        "physical custody omitted {required}"
                    );
                }
                let compact_body = body.split_whitespace().collect::<String>();
                assert_eq!(
                    compact_body
                        .matches(
                            "if!rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_file(){returnErr(WorkerBootstrapPreflightErrorV1::terminal());}"
                        )
                        .count(),
                    1,
                    "physical custody regular-file branch drifted"
                );
                assert!(
                    worker_bootstrap_post_receive_kernel_is_exact_v1(source),
                    "private WorkerBootstrap join drifted from the exact post-receive kernel"
                );
                let private_start = source
                    .find("const WORKER_BOOTSTRAP_FINAL_FIRST_FD_V1")
                    .unwrap();
                let private_source = &source[private_start..end];
                for private_declaration in [
                    "struct WorkerBootstrapPreflightErrorV1 {",
                    "struct WorkerBootstrapNormalizedFdCustodyV1 {",
                    "enum WorkerBootstrapPreflightRoleV1 {",
                    "struct WorkerBootstrapPhysicalPreflightV1 {",
                    "struct WorkerBootstrapRolePreflightCustodyV1 {",
                    "struct WorkerBootstrapPreflightCandidateCustodyV1 {",
                    "struct WorkerBootstrapNormalizedCustodyV1 {",
                    "fn join_worker_bootstrap_post_receive_v1(",
                ] {
                    assert_eq!(
                        private_source
                            .lines()
                            .map(str::trim)
                            .filter(|line| *line == private_declaration)
                            .count(),
                        1,
                        "physical custody strictly-private declaration drifted: {private_declaration}"
                    );
                }
                for forbidden in [
                    "pub ",
                    "unsafe",
                    "recvmsg",
                    "read(",
                    "WorkerBootstrapAcceptedEndpointV1",
                    "WorkerExecBound",
                    "BorrowedFd",
                    "FromRawFd",
                    "AsRawFd",
                    "parts",
                    "split",
                    "callback",
                    "Clone",
                    "serde",
                ] {
                    assert!(
                        !body.contains(forbidden),
                        "physical custody exposed {forbidden}"
                    );
                }
            }

            #[test]
            fn worker_bootstrap_post_receive_source_mutants_v1() {
                let source = include_str!("ancillary.rs");
                assert!(worker_bootstrap_post_receive_kernel_is_exact_v1(source));
                let mutants = [
                    (
                        "visibility",
                        source.replacen(
                            "        fn join_worker_bootstrap_post_receive_v1(",
                            "        pub(crate) fn join_worker_bootstrap_post_receive_v1(",
                            1,
                        ),
                    ),
                    (
                        "moved fresh RLIMIT check",
                        source.replacen(
                            concat!(
                                "            require_worker_bootstrap_rlimit_nofile_v1()?;\n",
                                "            let descriptor_count = input.actual_rights_count;"
                            ),
                            concat!(
                                "            let descriptor_count = input.actual_rights_count;\n",
                                "            require_worker_bootstrap_rlimit_nofile_v1()?;"
                            ),
                            1,
                        ),
                    ),
                    (
                        "omitted fresh RLIMIT check",
                        source.replacen(
                            "            require_worker_bootstrap_rlimit_nofile_v1()?;\n",
                            "",
                            1,
                        ),
                    ),
                    (
                        "vector-derived count authority",
                        source.replacen(
                            "let descriptor_count = input.actual_rights_count;",
                            "let descriptor_count = received_rights.len();",
                            1,
                        ),
                    ),
                    (
                        "relaxed owner-count equality",
                        source.replacen(
                            "received_rights.len() != descriptor_count",
                            "received_rights.len() < descriptor_count",
                            1,
                        ),
                    ),
                    (
                        "bypassed normalizer",
                        source.replacen(
                            concat!(
                                "let normalized = ",
                                "normalize_worker_bootstrap_descriptors_v1(received_rights)?;"
                            ),
                            concat!(
                                "let normalized = WorkerBootstrapNormalizedFdCustodyV1 { ",
                                "descriptors: received_rights };"
                            ),
                            1,
                        ),
                    ),
                    (
                        "bypassed physical bind",
                        source.replacen(
                            concat!(
                                "            bind_worker_bootstrap_normalized_custody_v1(\n",
                                "                WorkerBootstrapPreflightCandidateCustodyV1 {\n",
                                "                    candidate,\n",
                                "                    descriptor_count,\n",
                                "                },\n",
                                "                normalized,\n",
                                "            )"
                            ),
                            concat!(
                                "            let _ = (descriptor_count, normalized);\n",
                                "            Ok(WorkerBootstrapNormalizedCustodyV1 { ",
                                "candidate, roles: Vec::new() })"
                            ),
                            1,
                        ),
                    ),
                    (
                        "non-terminal physical bind",
                        source.replacen(
                            concat!(
                                "                normalized,\n",
                                "            )\n",
                                "        }\n\n",
                                "        #[cfg(feature = \"h0-tmpfs-provider-v2-g0\")]\n",
                                "        #[derive(Eq, PartialEq)]"
                            ),
                            concat!(
                                "                normalized,\n",
                                "            )\n",
                                "            .map(|custody| custody)\n",
                                "        }\n\n",
                                "        #[cfg(feature = \"h0-tmpfs-provider-v2-g0\")]\n",
                                "        #[derive(Eq, PartialEq)]"
                            ),
                            1,
                        ),
                    ),
                ];
                for (label, mutant) in mutants {
                    assert_ne!(mutant, source, "{label} mutant did not alter production");
                    assert!(
                        !worker_bootstrap_post_receive_kernel_is_exact_v1(&mutant),
                        "{label} mutant survived the exact kernel oracle"
                    );
                }
            }
        }

        #[cfg(test)]
        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        mod worker_bootstrap_preflight_tests {
            use super::*;
            use std::process::Command;

            const NORMALIZATION_STAGE_ENV_V1: &str =
                "EIP0045_G0B32_NORMALIZATION_ISOLATED_STAGE_V1";
            const NORMALIZATION_TEST_FILTER_V1: &str = concat!(
                "ancillary::strict_model::selected_target::worker_bootstrap_preflight_tests::",
                "worker_bootstrap_fd_normalization_v1"
            );
            const RLIMIT_STAGE_ENV_V1: &str = "EIP0045_G0B32_RLIMIT_ISOLATED_STAGE_V1";
            const RLIMIT_TEST_FILTER_V1: &str = concat!(
                "ancillary::strict_model::selected_target::worker_bootstrap_preflight_tests::",
                "worker_bootstrap_rlimit_nofile_v1"
            );

            fn enter_normalization_fixture_v1() -> bool {
                match std::env::var(NORMALIZATION_STAGE_ENV_V1) {
                    Ok(stage) => {
                        assert_eq!(stage, NORMALIZATION_TEST_FILTER_V1);
                        false
                    }
                    Err(std::env::VarError::NotPresent) => {
                        let inherited_noise: OwnedFd = File::open("/dev/null").unwrap().into();
                        let mut inherited_noise_flags =
                            fcntl_getfd(inherited_noise.as_fd()).unwrap();
                        inherited_noise_flags.remove(FdFlags::CLOEXEC);
                        fcntl_setfd(inherited_noise.as_fd(), inherited_noise_flags).unwrap();
                        let output = Command::new("/bin/bash")
                            .arg("-c")
                            .arg("for fd in {3..37}; do eval \"exec ${fd}>&-\"; done; exec \"$@\"")
                            .arg("eip0045-g0b32-normalization-fixture")
                            .arg("/usr/bin/timeout")
                            .arg("--signal=KILL")
                            .arg("20s")
                            .arg(std::env::current_exe().unwrap())
                            .arg(NORMALIZATION_TEST_FILTER_V1)
                            .arg("--exact")
                            .arg("--nocapture")
                            .arg("--test-threads=1")
                            .env(NORMALIZATION_STAGE_ENV_V1, NORMALIZATION_TEST_FILTER_V1)
                            .output()
                            .unwrap();
                        drop(inherited_noise);
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        assert!(
                            output.status.success()
                                && stdout.contains("1 passed")
                                && stderr.contains("G0B32_NORMALIZATION_CHILD_OK"),
                            "isolated normalization fixture failed:\nstdout={stdout}\nstderr={stderr}"
                        );
                        true
                    }
                    Err(error) => panic!("normalization stage is not Unicode: {error}"),
                }
            }

            fn open_dev_null_v1() -> OwnedFd {
                File::open("/dev/null").unwrap().into()
            }

            fn require_low_rlimit_rejection_v1() {
                match std::env::var(RLIMIT_STAGE_ENV_V1) {
                    Ok(stage) => {
                        assert_eq!(stage, RLIMIT_TEST_FILTER_V1);
                        let current = getrlimit(Resource::Nofile);
                        rustix::process::setrlimit(
                            Resource::Nofile,
                            rustix::process::Rlimit {
                                current: Some(37),
                                maximum: current.maximum,
                            },
                        )
                        .unwrap();
                        assert!(require_worker_bootstrap_rlimit_nofile_v1().is_err());
                        eprintln!("G0B32_RLIMIT_CHILD_OK");
                    }
                    Err(std::env::VarError::NotPresent) => {
                        let output = Command::new("/usr/bin/timeout")
                            .arg("--signal=KILL")
                            .arg("20s")
                            .arg(std::env::current_exe().unwrap())
                            .arg(RLIMIT_TEST_FILTER_V1)
                            .arg("--exact")
                            .arg("--nocapture")
                            .arg("--test-threads=1")
                            .env(RLIMIT_STAGE_ENV_V1, RLIMIT_TEST_FILTER_V1)
                            .output()
                            .unwrap();
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        assert!(
                            output.status.success()
                                && stdout.contains("1 passed")
                                && stderr.contains("G0B32_RLIMIT_CHILD_OK"),
                            "isolated RLIMIT fixture failed:\nstdout={stdout}\nstderr={stderr}"
                        );
                    }
                    Err(error) => panic!("RLIMIT stage is not Unicode: {error}"),
                }
            }

            fn assert_closed_v1(raw_descriptor: i32) {
                assert!(
                    read_link(format!("/proc/self/fd/{raw_descriptor}")).is_err(),
                    "descriptor fd{raw_descriptor} remained open"
                );
            }

            #[test]
            fn worker_bootstrap_fd_normalization_v1() {
                if enter_normalization_fixture_v1() {
                    return;
                }

                let endpoint = open_dev_null_v1();
                assert_eq!(
                    endpoint.as_raw_fd(),
                    3,
                    "isolated fixture did not reserve fd3"
                );
                let originals: Vec<_> = (0..CONTRACT_MAX_FRAME_FDS_V1)
                    .map(|_| open_dev_null_v1())
                    .collect();
                assert_eq!(
                    originals.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>(),
                    (4..=19).collect::<Vec<_>>()
                );
                let normalized = normalize_worker_bootstrap_descriptors_v1(originals)
                    .unwrap_or_else(|_| panic!("exact K=16 normalization rejected"));
                assert_eq!(
                    normalized
                        .descriptors
                        .iter()
                        .map(AsRawFd::as_raw_fd)
                        .collect::<Vec<_>>(),
                    (4..=19).collect::<Vec<_>>()
                );
                for descriptor in &normalized.descriptors {
                    assert!(
                        fcntl_getfd(descriptor.as_fd())
                            .unwrap()
                            .contains(FdFlags::CLOEXEC)
                    );
                }
                for raw_descriptor in 22..=37 {
                    assert_closed_v1(raw_descriptor);
                }
                drop(normalized);
                for raw_descriptor in 4..=19 {
                    assert_closed_v1(raw_descriptor);
                }

                let original = open_dev_null_v1();
                assert_eq!(original.as_raw_fd(), 4);
                let occupied_temp = fcntl_dupfd_cloexec(endpoint.as_fd(), 22).unwrap();
                assert_eq!(occupied_temp.as_raw_fd(), 22);
                assert!(normalize_worker_bootstrap_descriptors_v1(vec![original]).is_err());
                assert_closed_v1(4);
                assert_closed_v1(23);
                drop(occupied_temp);

                let first = open_dev_null_v1();
                let second = open_dev_null_v1();
                assert_eq!((first.as_raw_fd(), second.as_raw_fd()), (4, 5));
                let occupied_second_temp = fcntl_dupfd_cloexec(endpoint.as_fd(), 23).unwrap();
                assert_eq!(occupied_second_temp.as_raw_fd(), 23);
                assert!(normalize_worker_bootstrap_descriptors_v1(vec![first, second]).is_err());
                for raw_descriptor in [4, 5, 22, 24] {
                    assert_closed_v1(raw_descriptor);
                }
                drop(occupied_second_temp);

                let occupied_final = open_dev_null_v1();
                let original = open_dev_null_v1();
                assert_eq!((occupied_final.as_raw_fd(), original.as_raw_fd()), (4, 5));
                assert!(normalize_worker_bootstrap_descriptors_v1(vec![original]).is_err());
                assert_closed_v1(5);
                assert_closed_v1(22);
                drop(occupied_final);

                assert!(normalize_worker_bootstrap_descriptors_v1(Vec::new()).is_err());
                let too_many: Vec<_> = (0..=CONTRACT_MAX_FRAME_FDS_V1)
                    .map(|_| open_dev_null_v1())
                    .collect();
                assert!(normalize_worker_bootstrap_descriptors_v1(too_many).is_err());

                let source = include_str!("ancillary.rs");
                let start = source
                    .find("fn normalize_worker_bootstrap_descriptors_v1(")
                    .unwrap();
                let end = source[start..]
                    .find("enum WorkerBootstrapPreflightRoleV1")
                    .map(|offset| start + offset)
                    .unwrap();
                let body = &source[start..end];
                let temporary_stage = body.find("for (index, original)").unwrap();
                let drop_originals = body.find("drop(originals);").unwrap();
                let final_stage = body.find("for (index, temporary)").unwrap();
                let drop_temporaries = body.find("drop(temporaries);").unwrap();
                assert!(temporary_stage < drop_originals);
                assert!(drop_originals < final_stage);
                assert!(final_stage < drop_temporaries);
                assert_eq!(body.matches("fcntl_dupfd_cloexec").count(), 2);
                for forbidden in [
                    "unsafe",
                    "dup3",
                    "from_raw_fd",
                    "pub ",
                    "BorrowedFd",
                    "AsFd",
                    "AsRawFd",
                    "parts",
                    "split",
                    "callback",
                    "Clone",
                    "serde",
                ] {
                    assert!(!body.contains(forbidden), "normalizer exposed {forbidden}");
                }
                eprintln!("G0B32_NORMALIZATION_CHILD_OK");
            }

            #[test]
            fn worker_bootstrap_rlimit_nofile_v1() {
                assert!(worker_bootstrap_rlimit_nofile_accepts_v1(None));
                assert!(worker_bootstrap_rlimit_nofile_accepts_v1(Some(38)));
                assert!(!worker_bootstrap_rlimit_nofile_accepts_v1(Some(37)));
                require_worker_bootstrap_rlimit_nofile_v1()
                    .unwrap_or_else(|_| panic!("live RLIMIT_NOFILE did not satisfy the preflight"));
                require_low_rlimit_rejection_v1();
            }
        }

        #[cfg(test)]
        #[cfg(feature = "h0-tmpfs-provider-v2-g0")]
        mod final_result_physical_tests {
            use super::*;
            use rustix::fs::{
                MemfdFlags, Mode, fcntl_add_seals, fcntl_setfl, ftruncate, memfd_create, open,
            };
            use rustix::io::write;

            fn required_seals_v1() -> SealFlags {
                SealFlags::GROW | SealFlags::SHRINK | SealFlags::WRITE | SealFlags::SEAL
            }

            fn write_all_v1(descriptor: BorrowedFd<'_>, content: &[u8]) {
                let mut written = 0_usize;
                while written < content.len() {
                    let count = write(descriptor, &content[written..]).unwrap();
                    assert_ne!(count, 0);
                    written += count;
                }
            }

            fn memfd_v1(content: &[u8], seals: SealFlags, reopen_read_only: bool) -> OwnedFd {
                let descriptor = memfd_create(
                    "eip0045-g0b2-final-result",
                    MemfdFlags::ALLOW_SEALING | MemfdFlags::CLOEXEC,
                )
                .unwrap();
                ftruncate(descriptor.as_fd(), u64::try_from(content.len()).unwrap()).unwrap();
                write_all_v1(descriptor.as_fd(), content);
                if !seals.is_empty() {
                    fcntl_add_seals(descriptor.as_fd(), seals).unwrap();
                }
                if !reopen_read_only {
                    return descriptor;
                }
                let reopened = open(
                    format!("/proc/self/fd/{}", descriptor.as_raw_fd()),
                    OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .unwrap();
                drop(descriptor);
                reopened
            }

            fn received_v1(descriptor: OwnedFd) -> ReceivedFdV1 {
                ReceivedFdV1 {
                    role: ContractFdRoleV1::FinalResult,
                    descriptor,
                }
            }

            #[test]
            fn final_result_physical_validator_accepts_exact_fully_sealed_memfd() {
                let content = b"g0b2-final-result";
                assert_eq!(
                    validate_received_final_result_once_v1(received_v1(memfd_v1(
                        content,
                        required_seals_v1(),
                        true,
                    )))
                    .unwrap()
                    .as_ref(),
                    content,
                );
            }

            #[test]
            fn final_result_physical_validator_rejects_length_status_and_kind_drift() {
                assert!(
                    validate_received_final_result_once_v1(received_v1(memfd_v1(
                        &[],
                        required_seals_v1(),
                        true,
                    )))
                    .is_err()
                );
                assert!(
                    validate_received_final_result_once_v1(received_v1(memfd_v1(
                        &vec![0_u8; G0_FINAL_RESULT_MAX_BYTES_V1 + 1],
                        required_seals_v1(),
                        true,
                    )))
                    .is_err()
                );
                assert!(
                    validate_received_final_result_once_v1(received_v1(memfd_v1(
                        b"rw",
                        required_seals_v1(),
                        false,
                    )))
                    .is_err()
                );

                let nonregular: OwnedFd = File::open("/dev/null").unwrap().into();
                assert!(validate_received_final_result_once_v1(received_v1(nonregular)).is_err());
            }

            #[test]
            fn final_result_physical_validator_rejects_descriptor_flags_and_every_missing_seal() {
                let descriptor = memfd_v1(b"cloexec", required_seals_v1(), true);
                let mut flags = fcntl_getfd(descriptor.as_fd()).unwrap();
                flags.remove(FdFlags::CLOEXEC);
                fcntl_setfd(descriptor.as_fd(), flags).unwrap();
                assert!(validate_received_final_result_once_v1(received_v1(descriptor)).is_err());

                let descriptor = memfd_v1(b"nonblock", required_seals_v1(), true);
                fcntl_setfl(descriptor.as_fd(), OFlags::NONBLOCK).unwrap();
                assert!(validate_received_final_result_once_v1(received_v1(descriptor)).is_err());

                for missing in [
                    SealFlags::GROW,
                    SealFlags::SHRINK,
                    SealFlags::WRITE,
                    SealFlags::SEAL,
                ] {
                    let seals = required_seals_v1() & !missing;
                    assert!(
                        validate_received_final_result_once_v1(received_v1(memfd_v1(
                            b"missing-seal",
                            seals,
                            true,
                        )))
                        .is_err()
                    );
                }
            }

            #[test]
            fn final_result_physical_validator_rejects_an_extra_seal() {
                let descriptor = memfd_v1(
                    b"extra-seal",
                    required_seals_v1() | SealFlags::FUTURE_WRITE,
                    true,
                );
                assert_eq!(
                    fcntl_get_seals(descriptor.as_fd()).unwrap(),
                    required_seals_v1() | SealFlags::FUTURE_WRITE,
                );
                assert!(validate_received_final_result_once_v1(received_v1(descriptor)).is_err());
            }

            #[test]
            fn final_result_physical_validator_rejects_a_regular_non_memfd() {
                let descriptor = open(
                    "/etc/hostname",
                    OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .unwrap();
                let metadata = fstat(descriptor.as_fd()).unwrap();
                assert!(rustix::fs::FileType::from_raw_mode(metadata.st_mode).is_file());
                assert!(
                    (1..=G0_FINAL_RESULT_MAX_BYTES_V1).contains(
                        &usize::try_from(u64::try_from(metadata.st_size).unwrap()).unwrap()
                    )
                );
                assert!(
                    !read_link(format!("/proc/self/fd/{}", descriptor.as_raw_fd()))
                        .unwrap()
                        .to_string_lossy()
                        .starts_with("/memfd:")
                );
                assert!(validate_received_final_result_once_v1(received_v1(descriptor)).is_err());
            }

            #[test]
            fn final_result_physical_validator_rejects_second_pass_descriptor_drift() {
                let mut passes = 0_u8;
                let result = validate_received_final_result_with_test_observer_v1(
                    received_v1(memfd_v1(b"second-pass-flags", required_seals_v1(), true)),
                    |descriptor| {
                        passes += 1;
                        if passes == 2 {
                            let mut flags = fcntl_getfd(descriptor.as_fd()).unwrap();
                            flags.remove(FdFlags::CLOEXEC);
                            fcntl_setfd(descriptor.as_fd(), flags).unwrap();
                        }
                        observe_final_result_physical_pass_v1(descriptor)
                    },
                );
                assert!(result.is_err());
                assert_eq!(passes, 2);
            }

            #[test]
            fn final_result_physical_validator_rejects_every_second_observation_field_drift() {
                type MutateObservationV1 = fn(&mut FinalResultPhysicalObservationV1);

                fn device(observation: &mut FinalResultPhysicalObservationV1) {
                    observation.device ^= 1;
                }
                fn inode(observation: &mut FinalResultPhysicalObservationV1) {
                    observation.inode ^= 1;
                }
                fn mode(observation: &mut FinalResultPhysicalObservationV1) {
                    observation.mode ^= 0o100;
                }
                fn byte_length(observation: &mut FinalResultPhysicalObservationV1) {
                    observation.byte_length += 1;
                }
                fn descriptor_flags(observation: &mut FinalResultPhysicalObservationV1) {
                    observation.descriptor_flags.remove(FdFlags::CLOEXEC);
                }
                fn status_flags(observation: &mut FinalResultPhysicalObservationV1) {
                    observation.status_flags.insert(OFlags::NONBLOCK);
                }
                fn seals(observation: &mut FinalResultPhysicalObservationV1) {
                    observation.seals.insert(SealFlags::FUTURE_WRITE);
                }
                fn descriptor_link(observation: &mut FinalResultPhysicalObservationV1) {
                    observation.descriptor_link.push("drift");
                }
                fn bytes(observation: &mut FinalResultPhysicalObservationV1) {
                    observation.bytes[0] ^= 1;
                }

                let cases: [(&str, MutateObservationV1); 9] = [
                    ("device", device),
                    ("inode", inode),
                    ("mode", mode),
                    ("byte_length", byte_length),
                    ("descriptor_flags", descriptor_flags),
                    ("status_flags", status_flags),
                    ("seals", seals),
                    ("descriptor_link", descriptor_link),
                    ("bytes", bytes),
                ];
                for (case, mutate) in cases {
                    let mut passes = 0_u8;
                    let result = validate_received_final_result_with_test_observer_v1(
                        received_v1(memfd_v1(b"observation-drift", required_seals_v1(), true)),
                        |descriptor| {
                            passes += 1;
                            let mut observation =
                                observe_final_result_physical_pass_v1(descriptor)?;
                            if passes == 2 {
                                mutate(&mut observation);
                            }
                            Ok(observation)
                        },
                    );
                    assert!(result.is_err(), "accepted second-pass {case} drift");
                    assert_eq!(passes, 2, "did not execute two passes for {case}");
                }
            }
        }
    }

    #[cfg(test)]
    mod strict_ancillary {
        use super::*;
        use eip0045_h0_contract::wire::{FdRoleV1, MAX_FRAME_BYTES_V1, MAX_FRAME_FDS_V1};
        use std::cell::Cell;

        fn credentials() -> ExpectedPeerCredentialsV1 {
            ExpectedPeerCredentialsV1::try_new(41, 1_000, 1_001).unwrap()
        }

        #[test]
        fn expected_peer_credentials_preserves_distinct_tuple_and_rejects_process_id_bounds_v1() {
            let exact = ExpectedPeerCredentialsV1::try_new(41, 1_000, 1_001).unwrap();
            assert_eq!(
                (exact.process_id(), exact.user_id(), exact.group_id()),
                (41, 1_000, 1_001)
            );

            let maximum_process_id = i32::MAX.unsigned_abs();
            let maximum =
                ExpectedPeerCredentialsV1::try_new(maximum_process_id, 2_000, 2_001).unwrap();
            assert_eq!(
                (maximum.process_id(), maximum.user_id(), maximum.group_id()),
                (maximum_process_id, 2_000, 2_001)
            );

            for invalid_process_id in [0, maximum_process_id.checked_add(1).unwrap()] {
                assert_eq!(
                    ExpectedPeerCredentialsV1::try_new(invalid_process_id, 3_000, 3_001),
                    Err(AncillaryReceiveErrorV1::InvalidPeerProcessId(
                        invalid_process_id
                    ))
                );
            }
        }

        fn roles() -> [FdRoleV1; 2] {
            [FdRoleV1::CampaignInput(0), FdRoleV1::PublicationRoot]
        }

        fn endpoint_snapshot(role: SeqpacketEndpointRoleV1) -> EndpointObservationSnapshotV1 {
            EndpointObservationSnapshotV1 {
                role,
                descriptor_identity: DescriptorIdentityV1::try_new(7, 11, 13).unwrap(),
                socket_cookie: match role {
                    SeqpacketEndpointRoleV1::Generator
                    | SeqpacketEndpointRoleV1::SupervisorWorker => 17,
                    SeqpacketEndpointRoleV1::SupervisorGenerator
                    | SeqpacketEndpointRoleV1::Worker => 19,
                },
                socket_domain: AF_UNIX_V1,
                socket_type: SOCK_SEQPACKET_V1,
                socket_protocol: SOCKET_PROTOCOL_DEFAULT_V1,
                passcred: true,
                nonblocking: false,
                close_on_exec: true,
            }
        }

        fn expectation() -> StrictReceiveExpectationV1 {
            StrictReceiveExpectationV1::try_for_generator(128, credentials(), &roles()).unwrap()
        }

        fn push_record(output: &mut Vec<u8>, level: i32, kind: i32, payload: &[u8]) {
            let record_length = CMSG_HEADER_BYTES_V1 + payload.len();
            output.extend_from_slice(&u32::try_from(record_length).unwrap().to_le_bytes());
            output.extend_from_slice(&[0; 4]);
            output.extend_from_slice(&level.to_le_bytes());
            output.extend_from_slice(&kind.to_le_bytes());
            output.extend_from_slice(payload);
            output.resize(cmsg_align_v1(output.len()).unwrap(), 0);
        }

        fn exact_control() -> Vec<u8> {
            let mut output = Vec::new();
            let expected = credentials();
            let mut credential_payload = Vec::new();
            credential_payload.extend_from_slice(&expected.process_id().to_le_bytes());
            credential_payload.extend_from_slice(&expected.user_id().to_le_bytes());
            credential_payload.extend_from_slice(&expected.group_id().to_le_bytes());
            push_record(
                &mut output,
                SOL_SOCKET_V1,
                SCM_CREDENTIALS_V1,
                &credential_payload,
            );
            let mut rights_payload = Vec::new();
            rights_payload.extend_from_slice(&7_i32.to_le_bytes());
            rights_payload.extend_from_slice(&9_i32.to_le_bytes());
            push_record(&mut output, SOL_SOCKET_V1, SCM_RIGHTS_V1, &rights_payload);
            output
        }

        fn exact_envelope() -> MessageEnvelopeV1 {
            MessageEnvelopeV1 {
                received_length: 128,
                returned_flags: MSG_CMSG_CLOEXEC_RETURNED_V1,
            }
        }

        #[test]
        fn strict_ancillary_accepts_exact_credentials_and_ordered_inventory() {
            let validated =
                validate_strict_observation_v1(&expectation(), exact_envelope(), &exact_control())
                    .unwrap();
            assert_eq!(validated.credentials(), credentials());
            assert_eq!(validated.raw_fds(), &[7, 9]);
            assert_eq!(validated.ordered_roles(), &roles());
        }

        #[test]
        fn strict_ancillary_accepts_linux_optional_message_end_with_cloexec() {
            for returned_flags in [
                MSG_CMSG_CLOEXEC_RETURNED_V1,
                MSG_CMSG_CLOEXEC_RETURNED_V1 | MSG_EOR_V1,
            ] {
                let envelope = MessageEnvelopeV1 {
                    returned_flags,
                    ..exact_envelope()
                };
                assert!(
                    validate_strict_observation_v1(&expectation(), envelope, &exact_control())
                        .is_ok()
                );
            }
        }

        #[test]
        fn strict_ancillary_rejects_frame_and_inventory_bounds() {
            assert_eq!(
                StrictReceiveExpectationV1::try_for_generator(0, credentials(), &[]),
                Err(AncillaryReceiveErrorV1::FrameLengthOutOfRange(0))
            );
            assert_eq!(
                StrictReceiveExpectationV1::try_for_generator(
                    MAX_FRAME_BYTES_V1 + 1,
                    credentials(),
                    &[]
                ),
                Err(AncillaryReceiveErrorV1::FrameLengthOutOfRange(
                    MAX_FRAME_BYTES_V1 + 1
                ))
            );
            let too_many = vec![FdRoleV1::CampaignInput(0); MAX_FRAME_FDS_V1 + 1];
            assert_eq!(
                StrictReceiveExpectationV1::try_for_generator(128, credentials(), &too_many),
                Err(AncillaryReceiveErrorV1::TooManyFds(MAX_FRAME_FDS_V1 + 1))
            );
            let duplicate = [FdRoleV1::CampaignInput(0), FdRoleV1::CampaignInput(0)];
            assert_eq!(
                StrictReceiveExpectationV1::try_for_generator(128, credentials(), &duplicate),
                Err(AncillaryReceiveErrorV1::DuplicateFdRole(
                    FdRoleV1::CampaignInput(0)
                ))
            );
        }

        #[test]
        fn strict_ancillary_rejects_each_message_envelope_drift() {
            let cases = [
                (
                    MessageEnvelopeV1 {
                        returned_flags: 0,
                        ..exact_envelope()
                    },
                    AncillaryReceiveErrorV1::MissingControlCloseOnExec,
                ),
                (
                    MessageEnvelopeV1 {
                        returned_flags: MSG_CMSG_CLOEXEC_RETURNED_V1 | MSG_TRUNC_V1,
                        ..exact_envelope()
                    },
                    AncillaryReceiveErrorV1::MessageTruncated,
                ),
                (
                    MessageEnvelopeV1 {
                        returned_flags: MSG_CMSG_CLOEXEC_RETURNED_V1 | MSG_CTRUNC_V1,
                        ..exact_envelope()
                    },
                    AncillaryReceiveErrorV1::ControlTruncated,
                ),
                (
                    MessageEnvelopeV1 {
                        returned_flags: MSG_CMSG_CLOEXEC_RETURNED_V1 | 0x1,
                        ..exact_envelope()
                    },
                    AncillaryReceiveErrorV1::UnexpectedMessageFlags(
                        MSG_CMSG_CLOEXEC_RETURNED_V1 | 0x1,
                    ),
                ),
                (
                    MessageEnvelopeV1 {
                        received_length: 127,
                        ..exact_envelope()
                    },
                    AncillaryReceiveErrorV1::FrameLengthDrift(127, 128),
                ),
            ];
            for (envelope, expected) in cases {
                assert_eq!(
                    validate_strict_observation_v1(&expectation(), envelope, &exact_control()),
                    Err(expected)
                );
            }
        }

        #[test]
        fn strict_ancillary_rejects_unknown_malformed_and_reordered_records() {
            let mut unknown = Vec::new();
            push_record(&mut unknown, SOL_SOCKET_V1, 99, &[]);
            assert_eq!(
                validate_strict_observation_v1(&expectation(), exact_envelope(), &unknown),
                Err(AncillaryReceiveErrorV1::UnknownControlRecord(1, 99))
            );

            let mut malformed = exact_control();
            malformed[..4].copy_from_slice(&8_u32.to_le_bytes());
            assert_eq!(
                validate_strict_observation_v1(&expectation(), exact_envelope(), &malformed),
                Err(AncillaryReceiveErrorV1::MalformedControlRecord)
            );

            let mut nonzero_header_padding = exact_control();
            nonzero_header_padding[4] = 1;
            assert_eq!(
                validate_strict_observation_v1(
                    &expectation(),
                    exact_envelope(),
                    &nonzero_header_padding,
                ),
                Err(AncillaryReceiveErrorV1::MalformedControlRecord)
            );

            let exact = exact_control();
            let first_length = cmsg_align_v1(CMSG_HEADER_BYTES_V1 + UCRED_BYTES_V1).unwrap();
            let mut reordered = exact[first_length..].to_vec();
            reordered.extend_from_slice(&exact[..first_length]);
            assert_eq!(
                validate_strict_observation_v1(&expectation(), exact_envelope(), &reordered),
                Err(AncillaryReceiveErrorV1::ControlRecordOrderDrift)
            );
        }

        #[test]
        fn strict_ancillary_rejects_credentials_missing_duplicate_and_drift() {
            let exact = exact_control();
            let credential_length = cmsg_align_v1(CMSG_HEADER_BYTES_V1 + UCRED_BYTES_V1).unwrap();
            assert_eq!(
                validate_strict_observation_v1(
                    &expectation(),
                    exact_envelope(),
                    &exact[credential_length..]
                ),
                Err(AncillaryReceiveErrorV1::CredentialRecordCount(0))
            );

            let mut duplicate = exact[..credential_length].to_vec();
            duplicate.extend_from_slice(&exact);
            assert_eq!(
                validate_strict_observation_v1(&expectation(), exact_envelope(), &duplicate),
                Err(AncillaryReceiveErrorV1::CredentialRecordCount(2))
            );

            let mut drift = exact;
            let uid_offset = CMSG_HEADER_BYTES_V1 + 4;
            drift[uid_offset..uid_offset + 4].copy_from_slice(&1_002_u32.to_le_bytes());
            assert_eq!(
                validate_strict_observation_v1(&expectation(), exact_envelope(), &drift),
                Err(AncillaryReceiveErrorV1::CredentialDrift)
            );
        }

        #[test]
        fn seqpacket_endpoint_ledger_v1_rejects_each_independent_drift() {
            let generator = endpoint_snapshot(SeqpacketEndpointRoleV1::Generator);
            let supervisor = endpoint_snapshot(SeqpacketEndpointRoleV1::SupervisorGenerator);
            assert!(
                validate_endpoint_pair_v1(
                    generator,
                    supervisor,
                    SeqpacketEndpointRoleV1::Generator,
                    SeqpacketEndpointRoleV1::SupervisorGenerator,
                )
                .is_ok()
            );

            let mutations = [
                EndpointObservationSnapshotV1 {
                    socket_cookie: 0,
                    ..generator
                },
                EndpointObservationSnapshotV1 {
                    socket_domain: 2,
                    ..generator
                },
                EndpointObservationSnapshotV1 {
                    socket_type: 1,
                    ..generator
                },
                EndpointObservationSnapshotV1 {
                    socket_protocol: 1,
                    ..generator
                },
                EndpointObservationSnapshotV1 {
                    passcred: false,
                    ..generator
                },
            ];
            for mutation in mutations {
                assert!(validate_endpoint_observation_v1(mutation).is_err());
            }

            let alias = EndpointObservationSnapshotV1 {
                socket_cookie: generator.socket_cookie,
                ..supervisor
            };
            assert_eq!(
                validate_endpoint_pair_v1(
                    generator,
                    alias,
                    SeqpacketEndpointRoleV1::Generator,
                    SeqpacketEndpointRoleV1::SupervisorGenerator,
                ),
                Err(SeqpacketEndpointErrorV1::CookieAlias)
            );
            assert_eq!(
                validate_endpoint_pair_v1(
                    generator,
                    supervisor,
                    SeqpacketEndpointRoleV1::Worker,
                    SeqpacketEndpointRoleV1::SupervisorGenerator,
                ),
                Err(SeqpacketEndpointErrorV1::EndpointRoleDrift)
            );
            let reread_drift = EndpointObservationSnapshotV1 {
                descriptor_identity: DescriptorIdentityV1::try_new(7, 12, 13).unwrap(),
                ..generator
            };
            assert_eq!(
                validate_endpoint_reread_v1(generator, reread_drift),
                Err(SeqpacketEndpointErrorV1::ObservationDrift)
            );
            for flag_drift in [
                EndpointObservationSnapshotV1 {
                    nonblocking: true,
                    ..generator
                },
                EndpointObservationSnapshotV1 {
                    close_on_exec: false,
                    ..generator
                },
            ] {
                assert_eq!(
                    validate_endpoint_reread_v1(generator, flag_drift),
                    Err(SeqpacketEndpointErrorV1::ObservationDrift)
                );
            }
        }

        #[test]
        fn strict_child_receive_v1_keeps_all_four_directions_distinct() {
            let expectations = [
                StrictReceiveExpectationV1::try_for_generator(128, credentials(), &roles())
                    .unwrap(),
                StrictReceiveExpectationV1::try_for_worker(128, credentials(), &roles()).unwrap(),
                StrictReceiveExpectationV1::try_for_supervisor_to_generator(
                    128,
                    credentials(),
                    &roles(),
                )
                .unwrap(),
                StrictReceiveExpectationV1::try_for_supervisor_to_worker(
                    128,
                    credentials(),
                    &roles(),
                )
                .unwrap(),
            ];
            let roles = [
                ExpectedPeerRoleV1::Generator,
                ExpectedPeerRoleV1::Worker,
                ExpectedPeerRoleV1::SupervisorForGenerator,
                ExpectedPeerRoleV1::SupervisorForWorker,
            ];
            for (index, expectation) in expectations.iter().enumerate() {
                assert!(validate_expected_peer_role_v1(expectation, roles[index]).is_ok());
                for (other_index, role) in roles.iter().copied().enumerate() {
                    if index != other_index {
                        assert_eq!(
                            validate_expected_peer_role_v1(expectation, role),
                            Err(AncillaryReceiveErrorV1::PeerRoleDrift)
                        );
                    }
                }
            }
        }

        #[test]
        fn send_once_v1_never_retries_error_or_short_enqueue() {
            for outcome in [Err(()), Ok(127)] {
                let calls = Cell::new(0_usize);
                let result = invoke_send_once_for_test(128, 2, || {
                    calls.set(calls.get() + 1);
                    outcome
                });
                assert!(result.is_err());
                assert_eq!(calls.get(), 1);
            }

            let calls = Cell::new(0_usize);
            assert!(
                invoke_send_once_for_test(128, 2, || {
                    calls.set(calls.get() + 1);
                    Ok(128)
                })
                .is_ok()
            );
            assert_eq!(calls.get(), 1);

            let calls = Cell::new(0_usize);
            assert_eq!(
                invoke_send_once_for_test(0, 0, || {
                    calls.set(calls.get() + 1);
                    Ok(0)
                }),
                Err(AncillarySendErrorV1::FrameLength)
            );
            assert_eq!(calls.get(), 0);
        }

        #[test]
        fn strict_ancillary_rejects_rights_missing_duplicate_malformed_and_surplus() {
            let exact = exact_control();
            let credential_length = cmsg_align_v1(CMSG_HEADER_BYTES_V1 + UCRED_BYTES_V1).unwrap();
            assert_eq!(
                validate_strict_observation_v1(
                    &expectation(),
                    exact_envelope(),
                    &exact[..credential_length]
                ),
                Err(AncillaryReceiveErrorV1::RightsRecordCount(0))
            );

            let mut duplicate = exact.clone();
            duplicate.extend_from_slice(&exact[credential_length..]);
            assert_eq!(
                validate_strict_observation_v1(&expectation(), exact_envelope(), &duplicate),
                Err(AncillaryReceiveErrorV1::RightsRecordCount(2))
            );

            let mut malformed_payload = exact.clone();
            malformed_payload.push(0);
            assert_eq!(
                validate_strict_observation_v1(
                    &expectation(),
                    exact_envelope(),
                    &malformed_payload
                ),
                Err(AncillaryReceiveErrorV1::MalformedControlRecord)
            );

            let one_role = [FdRoleV1::CampaignInput(0)];
            let expected_one =
                StrictReceiveExpectationV1::try_for_generator(128, credentials(), &one_role)
                    .unwrap();
            assert_eq!(
                validate_strict_observation_v1(&expected_one, exact_envelope(), &exact),
                Err(AncillaryReceiveErrorV1::FdCountDrift(2, 1))
            );
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
pub use strict_model::selected_target::{
    ChildTypedSendErrorV1, GeneratorEndpointV1, InheritedEndpointAdoptionErrorV1, WorkerEndpointV1,
    try_adopt_generator_exec_inherited_fd3_once_v1, try_adopt_worker_exec_inherited_fd3_once_v1,
};

#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
#[cfg(feature = "h0-tmpfs-provider-v2-g0")]
pub use strict_model::selected_target::{
    ChildTypedReceiveErrorV1, GeneratorBoundAwaitClosedResultEndpointV1, GeneratorBoundSendInputV1,
    GeneratorPeerGCommitSendEndpointV1, GeneratorPeerGRevealSendEndpointV1,
    GeneratorPeerSCommitReceiveEndpointV1, GeneratorPeerSRevealReceiveEndpointV1,
    GeneratorPeerSessionOfferEndpointV1, GeneratorProviderSessionEndpointV1,
};

#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
pub(crate) use strict_model::selected_target::{
    GeneratorChannelV1, SupervisorGeneratorEndpointV1, SupervisorGeneratorSendOpV1,
    SupervisorGeneratorSentEndpointV1, SupervisorWorkerBootstrapSendOpV1,
    SupervisorWorkerEndpointV1, WorkerBootstrapEnqueuedEndpointV1, WorkerChannelV1,
    create_generator_channel_v1, create_worker_channel_v1,
};

#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
#[cfg(feature = "h0-tmpfs-provider-v2-g0")]
pub(crate) use strict_model::selected_target::{
    ClosedResultSendInputV1, GeneratorBoundReceiveInputV1, GeneratorBoundReceivedEndpointV1,
    GeneratorCommitReceiveInputV1, GeneratorCommitReceivedEndpointV1,
    GeneratorRevealReceiveInputV1, GeneratorRevealReceivedEndpointV1, SessionOfferSendInputV1,
    SupervisorCommitSendInputV1, SupervisorRevealSendInputV1, SupervisorTypedTransitionErrorV1,
    WorkerBootstrapSendInputV1, WorkerExecBoundReceiveInputV1, WorkerExecBoundReceivedEndpointV1,
    prepare_closed_result_send_v1, prepare_session_offer_send_v1,
    prepare_supervisor_commit_send_v1, prepare_supervisor_reveal_send_v1,
};
