//! Exact-descriptor statx observation contract.

use eip0045_h0_contract::ReplayRoleV2;
use std::fmt;

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const FIXED_STATX_AT_FLAGS_V1: u32 = 0x1900;
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const STATX_MNT_ID_UNIQUE_V1: u32 = 0x4000;
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const FIXED_STATX_REQUEST_MASK_V1: u32 = 0x07ff | STATX_MNT_ID_UNIQUE_V1;
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const STATX_ATTR_IMMUTABLE_V1: u64 = 0x0010;
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const STATX_ATTR_APPEND_V1: u64 = 0x0020;
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const STATX_ATTR_MOUNT_ROOT_V1: u64 = 0x2000;
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const STATX_ATTR_DAX_V1: u64 = 0x20_0000;
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const REQUIRED_ATTRIBUTE_MASK_V1: u64 = STATX_ATTR_IMMUTABLE_V1 | STATX_ATTR_APPEND_V1;
#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
const KNOWN_ATTRIBUTE_MASK_V1: u64 = 0x50_1874 | STATX_ATTR_MOUNT_ROOT_V1 | STATX_ATTR_DAX_V1;

/// Closed semantic subject for one exact-descriptor observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorSubjectV1 {
    /// Provider-owned mount root.
    MountRoot,
    /// Retained measured generator executable.
    GeneratorExecutable,
    /// Retained measured worker executable.
    WorkerExecutable,
    /// Root directory for one replay role.
    RoleRoot(ReplayRoleV2),
    /// Retained directory at its authenticated role-local position.
    RetainedDirectory {
        /// Replay role owning the entry.
        role: ReplayRoleV2,
        /// Exact position in the authenticated inventory.
        index: u32,
    },
    /// Retained regular file at its authenticated role-local position.
    RetainedRegularFile {
        /// Replay role owning the entry.
        role: ReplayRoleV2,
        /// Exact position in the authenticated inventory.
        index: u32,
    },
    /// Retained symbolic link at its authenticated role-local position.
    RetainedSymlink {
        /// Replay role owning the entry.
        role: ReplayRoleV2,
        /// Exact position in the authenticated inventory.
        index: u32,
    },
}

/// Exact identity tuple expected from a descriptor-rooted observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorExpectationV1 {
    subject: DescriptorSubjectV1,
    device_major: u32,
    device_minor: u32,
    inode: u64,
    unique_mount_id: u64,
}

impl DescriptorExpectationV1 {
    /// Constructs an expectation after rejecting identity values that cannot
    /// identify a retained object or mount.
    ///
    /// # Errors
    ///
    /// Returns [`DescriptorObservationErrorV1::InvalidExpectedIdentity`] when
    /// the inode or unique mount identifier is zero.
    pub fn try_new(
        subject: DescriptorSubjectV1,
        device_major: u32,
        device_minor: u32,
        inode: u64,
        unique_mount_id: u64,
    ) -> Result<Self, DescriptorObservationErrorV1> {
        if inode == 0 {
            return Err(DescriptorObservationErrorV1::InvalidExpectedIdentity(
                DescriptorIdentityFieldV1::Inode,
            ));
        }
        if unique_mount_id == 0 {
            return Err(DescriptorObservationErrorV1::InvalidExpectedIdentity(
                DescriptorIdentityFieldV1::UniqueMountId,
            ));
        }
        Ok(Self {
            subject,
            device_major,
            device_minor,
            inode,
            unique_mount_id,
        })
    }
}

/// Attribute whose support or zero value is mandatory for every observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatxAttributeV1 {
    /// Immutable attribute.
    Immutable,
    /// Append-only attribute.
    AppendOnly,
}

/// One independently checked member of the descriptor identity tuple.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorIdentityFieldV1 {
    /// Inode number.
    Inode,
    /// Device major number.
    DeviceMajor,
    /// Device minor number.
    DeviceMinor,
    /// Non-recycled mount identifier requested with `STATX_MNT_ID_UNIQUE`.
    UniqueMountId,
}

/// Failure from the fixed statx observation boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorObservationErrorV1 {
    /// Kernel result mask differed from the exact requested mask.
    ReturnedMaskDrift(u32),
    /// Attribute-support mask contained a bit absent from the pinned UAPI.
    UnknownAttributeMask(u64),
    /// The filesystem did not report support for a mandatory attribute.
    RequiredAttributeMissing(StatxAttributeV1),
    /// A mandatory-prohibited attribute was set.
    ProhibitedAttributeSet(StatxAttributeV1),
    /// An attribute value was set outside the reported support mask.
    AttributeOutsideMask(u64),
    /// One exact descriptor identity member differed.
    IdentityDrift(DescriptorIdentityFieldV1),
    /// An expected identity used a reserved zero value.
    InvalidExpectedIdentity(DescriptorIdentityFieldV1),
    /// The fixed safe statx operation failed before an observation existed.
    OperationFailed,
}

impl fmt::Display for DescriptorObservationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReturnedMaskDrift(mask) => {
                write!(formatter, "statx result-mask drift: {mask:#x}")
            }
            Self::UnknownAttributeMask(mask) => {
                write!(formatter, "statx unknown attribute-mask bits: {mask:#x}")
            }
            Self::RequiredAttributeMissing(attribute) => {
                write!(
                    formatter,
                    "statx required attribute support missing: {attribute:?}"
                )
            }
            Self::ProhibitedAttributeSet(attribute) => {
                write!(formatter, "statx prohibited attribute set: {attribute:?}")
            }
            Self::AttributeOutsideMask(bits) => {
                write!(formatter, "statx attribute outside support mask: {bits:#x}")
            }
            Self::IdentityDrift(field) => write!(formatter, "statx identity drift: {field:?}"),
            Self::InvalidExpectedIdentity(field) => {
                write!(formatter, "invalid expected statx identity: {field:?}")
            }
            Self::OperationFailed => formatter.write_str("fixed statx operation failed"),
        }
    }
}

impl std::error::Error for DescriptorObservationErrorV1 {}

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RawStatxSnapshotV1 {
    returned_mask: u32,
    attributes_mask: u64,
    attributes: u64,
    inode: u64,
    device_major: u32,
    device_minor: u32,
    unique_mount_id: u64,
}

/// Fully validated result of one exact-descriptor observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DescriptorObservationV1 {
    subject: DescriptorSubjectV1,
    inode: u64,
    device_major: u32,
    device_minor: u32,
    unique_mount_id: u64,
    attributes_mask: u64,
    attributes: u64,
}

impl DescriptorObservationV1 {
    /// Returns the semantic subject bound to the expectation.
    #[must_use]
    pub const fn subject(self) -> DescriptorSubjectV1 {
        self.subject
    }

    /// Returns the exact observed inode number.
    #[must_use]
    pub const fn inode(self) -> u64 {
        self.inode
    }

    /// Returns the exact observed device major number.
    #[must_use]
    pub const fn device_major(self) -> u32 {
        self.device_major
    }

    /// Returns the exact observed device minor number.
    #[must_use]
    pub const fn device_minor(self) -> u32 {
        self.device_minor
    }

    /// Returns the exact observed non-recycled mount identifier.
    #[must_use]
    pub const fn unique_mount_id(self) -> u64 {
        self.unique_mount_id
    }

    /// Returns the complete known attribute-support mask.
    #[must_use]
    pub const fn attributes_mask(self) -> u64 {
        self.attributes_mask
    }

    /// Returns the complete observed attribute value mask.
    #[must_use]
    pub const fn attributes(self) -> u64 {
        self.attributes
    }
}

#[cfg(any(
    test,
    all(target_arch = "x86_64", target_os = "linux", target_env = "musl")
))]
fn validate_snapshot_v1(
    expectation: DescriptorExpectationV1,
    snapshot: RawStatxSnapshotV1,
) -> Result<DescriptorObservationV1, DescriptorObservationErrorV1> {
    if snapshot.returned_mask != FIXED_STATX_REQUEST_MASK_V1 {
        return Err(DescriptorObservationErrorV1::ReturnedMaskDrift(
            snapshot.returned_mask,
        ));
    }
    if snapshot.attributes_mask & !KNOWN_ATTRIBUTE_MASK_V1 != 0 {
        return Err(DescriptorObservationErrorV1::UnknownAttributeMask(
            snapshot.attributes_mask,
        ));
    }
    for (bit, attribute) in [
        (STATX_ATTR_IMMUTABLE_V1, StatxAttributeV1::Immutable),
        (STATX_ATTR_APPEND_V1, StatxAttributeV1::AppendOnly),
    ] {
        if snapshot.attributes_mask & bit == 0 {
            return Err(DescriptorObservationErrorV1::RequiredAttributeMissing(
                attribute,
            ));
        }
    }
    let outside_mask = snapshot.attributes & !snapshot.attributes_mask;
    if outside_mask != 0 {
        return Err(DescriptorObservationErrorV1::AttributeOutsideMask(
            outside_mask,
        ));
    }
    for (bit, attribute) in [
        (STATX_ATTR_IMMUTABLE_V1, StatxAttributeV1::Immutable),
        (STATX_ATTR_APPEND_V1, StatxAttributeV1::AppendOnly),
    ] {
        if snapshot.attributes & bit != 0 {
            return Err(DescriptorObservationErrorV1::ProhibitedAttributeSet(
                attribute,
            ));
        }
    }
    for (matches, field) in [
        (
            snapshot.inode == expectation.inode,
            DescriptorIdentityFieldV1::Inode,
        ),
        (
            snapshot.device_major == expectation.device_major,
            DescriptorIdentityFieldV1::DeviceMajor,
        ),
        (
            snapshot.device_minor == expectation.device_minor,
            DescriptorIdentityFieldV1::DeviceMinor,
        ),
        (
            snapshot.unique_mount_id == expectation.unique_mount_id,
            DescriptorIdentityFieldV1::UniqueMountId,
        ),
    ] {
        if !matches {
            return Err(DescriptorObservationErrorV1::IdentityDrift(field));
        }
    }
    Ok(DescriptorObservationV1 {
        subject: expectation.subject,
        inode: snapshot.inode,
        device_major: snapshot.device_major,
        device_minor: snapshot.device_minor,
        unique_mount_id: snapshot.unique_mount_id,
        attributes_mask: snapshot.attributes_mask,
        attributes: snapshot.attributes,
    })
}

/// Observes one already-retained descriptor with provider-fixed statx flags
/// and mask, then checks every identity and attribute invariant.
///
/// This target-only wrapper accepts neither a path, raw descriptor number,
/// caller-selected flag, nor caller-selected mask.
///
/// # Errors
///
/// Returns [`DescriptorObservationErrorV1`] when the fixed operation fails or
/// any returned mask, attribute, or exact identity member drifts.
#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "musl"))]
pub fn observe_exact_descriptor_v1(
    descriptor: rustix::fd::BorrowedFd<'_>,
    expectation: DescriptorExpectationV1,
) -> Result<DescriptorObservationV1, DescriptorObservationErrorV1> {
    use rustix::fs::{AtFlags, StatxFlags};

    let flags = AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW | AtFlags::NO_AUTOMOUNT;
    debug_assert_eq!(flags.bits(), FIXED_STATX_AT_FLAGS_V1);
    let mask = StatxFlags::BASIC_STATS | StatxFlags::from_bits_retain(STATX_MNT_ID_UNIQUE_V1);
    debug_assert_eq!(mask.bits(), FIXED_STATX_REQUEST_MASK_V1);
    let observed = rustix::fs::statx(descriptor, c"", flags, mask)
        .map_err(|_| DescriptorObservationErrorV1::OperationFailed)?;
    validate_snapshot_v1(
        expectation,
        RawStatxSnapshotV1 {
            returned_mask: observed.stx_mask,
            attributes_mask: observed.stx_attributes_mask.bits(),
            attributes: observed.stx_attributes.bits(),
            inode: observed.stx_ino,
            device_major: observed.stx_dev_major,
            device_minor: observed.stx_dev_minor,
            unique_mount_id: observed.stx_mnt_id,
        },
    )
}

#[cfg(test)]
mod descriptor_observation {
    use super::*;
    use eip0045_h0_contract::ReplayRoleV2;

    fn expectation() -> DescriptorExpectationV1 {
        DescriptorExpectationV1::try_new(
            DescriptorSubjectV1::RoleRoot(ReplayRoleV2::RustValidatorBuild),
            7,
            9,
            41,
            73,
        )
        .unwrap()
    }

    fn snapshot() -> RawStatxSnapshotV1 {
        RawStatxSnapshotV1 {
            returned_mask: FIXED_STATX_REQUEST_MASK_V1,
            attributes_mask: REQUIRED_ATTRIBUTE_MASK_V1 | STATX_ATTR_MOUNT_ROOT_V1,
            attributes: STATX_ATTR_MOUNT_ROOT_V1,
            inode: 41,
            device_major: 7,
            device_minor: 9,
            unique_mount_id: 73,
        }
    }

    #[test]
    fn descriptor_observation_pins_flags_mask_and_known_attributes() {
        assert_eq!(FIXED_STATX_AT_FLAGS_V1, 0x1900);
        assert_eq!(FIXED_STATX_REQUEST_MASK_V1, 0x47ff);
        assert_eq!(REQUIRED_ATTRIBUTE_MASK_V1, 0x30);
        assert_eq!(KNOWN_ATTRIBUTE_MASK_V1, 0x70_3874);
    }

    #[test]
    fn descriptor_observation_accepts_only_the_exact_snapshot() {
        let observed = validate_snapshot_v1(expectation(), snapshot()).unwrap();
        assert_eq!(
            observed.subject(),
            DescriptorSubjectV1::RoleRoot(ReplayRoleV2::RustValidatorBuild)
        );
        assert_eq!(observed.inode(), 41);
        assert_eq!(observed.device_major(), 7);
        assert_eq!(observed.device_minor(), 9);
        assert_eq!(observed.unique_mount_id(), 73);
        assert_eq!(
            observed.attributes_mask(),
            REQUIRED_ATTRIBUTE_MASK_V1 | STATX_ATTR_MOUNT_ROOT_V1
        );
        assert_eq!(observed.attributes(), STATX_ATTR_MOUNT_ROOT_V1);
    }

    #[test]
    fn descriptor_observation_keeps_executable_roles_distinct() {
        for subject in [
            DescriptorSubjectV1::GeneratorExecutable,
            DescriptorSubjectV1::WorkerExecutable,
        ] {
            let expectation = DescriptorExpectationV1::try_new(subject, 7, 9, 41, 73).unwrap();
            let observed = validate_snapshot_v1(expectation, snapshot()).unwrap();
            assert_eq!(observed.subject(), subject);
        }
        assert_ne!(
            DescriptorSubjectV1::GeneratorExecutable,
            DescriptorSubjectV1::WorkerExecutable
        );
    }

    #[test]
    fn descriptor_observation_rejects_mask_and_attribute_drift_independently() {
        let mut candidate = snapshot();
        candidate.returned_mask ^= STATX_MNT_ID_UNIQUE_V1;
        assert_eq!(
            validate_snapshot_v1(expectation(), candidate),
            Err(DescriptorObservationErrorV1::ReturnedMaskDrift(
                candidate.returned_mask
            ))
        );

        let mut candidate = snapshot();
        candidate.attributes_mask |= 1_u64 << 63;
        assert_eq!(
            validate_snapshot_v1(expectation(), candidate),
            Err(DescriptorObservationErrorV1::UnknownAttributeMask(
                candidate.attributes_mask
            ))
        );

        for (bit, attribute) in [
            (STATX_ATTR_IMMUTABLE_V1, StatxAttributeV1::Immutable),
            (STATX_ATTR_APPEND_V1, StatxAttributeV1::AppendOnly),
        ] {
            let mut candidate = snapshot();
            candidate.attributes_mask &= !bit;
            assert_eq!(
                validate_snapshot_v1(expectation(), candidate),
                Err(DescriptorObservationErrorV1::RequiredAttributeMissing(
                    attribute
                ))
            );

            let mut candidate = snapshot();
            candidate.attributes |= bit;
            assert_eq!(
                validate_snapshot_v1(expectation(), candidate),
                Err(DescriptorObservationErrorV1::ProhibitedAttributeSet(
                    attribute
                ))
            );
        }

        let mut candidate = snapshot();
        candidate.attributes = STATX_ATTR_DAX_V1;
        assert_eq!(
            validate_snapshot_v1(expectation(), candidate),
            Err(DescriptorObservationErrorV1::AttributeOutsideMask(
                STATX_ATTR_DAX_V1
            ))
        );
    }

    #[test]
    fn descriptor_observation_rejects_each_identity_field_drift() {
        let cases = [
            (
                RawStatxSnapshotV1 {
                    inode: 42,
                    ..snapshot()
                },
                DescriptorIdentityFieldV1::Inode,
            ),
            (
                RawStatxSnapshotV1 {
                    device_major: 8,
                    ..snapshot()
                },
                DescriptorIdentityFieldV1::DeviceMajor,
            ),
            (
                RawStatxSnapshotV1 {
                    device_minor: 10,
                    ..snapshot()
                },
                DescriptorIdentityFieldV1::DeviceMinor,
            ),
            (
                RawStatxSnapshotV1 {
                    unique_mount_id: 74,
                    ..snapshot()
                },
                DescriptorIdentityFieldV1::UniqueMountId,
            ),
        ];
        for (candidate, field) in cases {
            assert_eq!(
                validate_snapshot_v1(expectation(), candidate),
                Err(DescriptorObservationErrorV1::IdentityDrift(field))
            );
        }
    }

    #[test]
    fn descriptor_observation_rejects_invalid_expected_identity() {
        assert_eq!(
            DescriptorExpectationV1::try_new(DescriptorSubjectV1::MountRoot, 0, 0, 0, 1),
            Err(DescriptorObservationErrorV1::InvalidExpectedIdentity(
                DescriptorIdentityFieldV1::Inode
            ))
        );
        assert_eq!(
            DescriptorExpectationV1::try_new(DescriptorSubjectV1::MountRoot, 0, 0, 1, 0),
            Err(DescriptorObservationErrorV1::InvalidExpectedIdentity(
                DescriptorIdentityFieldV1::UniqueMountId
            ))
        );
    }
}
