// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Pure, non-authorizing trusted-host F0 metadata policy declaration.
//!
//! This module has no filesystem access, provider, packet constructor, or
//! conversion from the H0/V2 metadata theorem. Matching this declaration
//! cannot establish that a particular kernel, mount, inode, or observer ran.

use sha2::{Digest, Sha256};

/// New policy identity. The V1 and H0/V2 identities remain separate.
pub const POLICY_ID_TH_F0_V1: &str =
    "eip0045-b4-retained-host-rootfs-metadata-obligations-th-f0-v1";
/// Explicit trust premise for the selected WSL-host realization.
pub const HOST_PREMISE_ID_TH_F0_V1: &str = "eip0045-b4-trusted-host-wsl-f0-v1";
/// Observed release name; it does not attest the bytes of the booted kernel.
pub const OBSERVED_KERNEL_RELEASE: &str = "6.18.33.2-microsoft-standard-WSL2";
/// Candidate Microsoft source commit, not a binary build attestation.
pub const CANDIDATE_SOURCE_COMMIT: &str = "c21a03b2943d147c280bdf32530d4fe6badfd6bd";
/// Captured `/proc/config.gz` bytes under the F0 premise.
pub const CONFIG_GZIP_SHA256_HEX: &str =
    "30e49f5d4d0a53d46f4f8056ecca9ab0be08e7949cf058f961d779e023f752b5";
/// Installed WSL image bytes; no boot-image equality is inferred.
pub const INSTALLED_KERNEL_SHA256_HEX: &str =
    "d540850bfbf1beba3ded6b2965b9d0249b23fbcb3e90e7dc0845ac7ad86bc861";
/// Selected diagnostic securityfs stack; it does not prove label visibility.
pub const DIAGNOSTIC_LSM_STACK_TH: &str = "capability,landlock,yama,safesetid,selinux,ima";

const MODE_TABLE_DOMAIN: &[u8] = b"eip0045.b4.trusted-host.metadata-mode-table.f0.v1\0";
/// Frozen SHA-256 of `MODE_TABLE_DOMAIN` followed by the 55 class/kind/mode triples.
pub const MODE_TABLE_SHA256_HEX: &str =
    "e8ad5b5e41a6d3d3fab57e5055f85bc01ef736581b3e6f3935b9390bddd8c218";

/// The closed prohibited-class order, distinct from any H0 theorem authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MetadataClassTh {
    /// Any extended-attribute name.
    XattrNameSet = 0,
    /// POSIX access ACL.
    PosixAccessAcl = 1,
    /// POSIX default ACL.
    PosixDefaultAcl = 2,
    /// Linux file capability.
    LinuxFileCapability = 3,
    /// Immutable inode attribute.
    Immutable = 4,
    /// Append-only inode attribute.
    AppendOnly = 5,
    /// Filesystem encryption.
    Encrypted = 6,
    /// Filesystem verity.
    Verity = 7,
    /// Case-folding.
    Casefold = 8,
    /// Nonzero project identifier.
    NonzeroProjectId = 9,
    /// Project-inherit attribute.
    ProjectInherit = 10,
}

/// The five physical subject kinds in each retained rootfs inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MetadataSubjectKindTh {
    /// The fresh tmpfs superblock root.
    MountRoot = 0,
    /// A role-bound retained root.
    RoleRoot = 1,
    /// A retained directory.
    RetainedDirectory = 2,
    /// A retained regular file.
    RetainedRegularFile = 3,
    /// A retained symbolic link.
    RetainedSymbolicLink = 4,
}

/// Conditional proof mode required for one class and subject kind.
///
/// A mode describes what a future physical provider must establish; it is not
/// itself an observation or a claim that the condition has been met.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ExpectedModeTh {
    /// Empty name enumeration plus direct absence of labels hidden by the LSM.
    ObservedXattrNamesAndHiddenLabelsAbsentComplete = 4,
    /// The requested `statx` attribute bit is returned in the mask and clear.
    ObservedStatxBitClearComplete = 2,
    /// Absence follows only under the exact F0 source/config/mount premise.
    StructurallyExcludedUnderF0 = 3,
}

/// One cell in class-major, subject-kind-minor order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedModeCellTh {
    /// Prohibited class.
    pub class: MetadataClassTh,
    /// Physical subject kind.
    pub kind: MetadataSubjectKindTh,
    /// Required conditional proof mode.
    pub mode: ExpectedModeTh,
}

/// Closed prohibited-class order.
pub const METADATA_CLASSES_TH: [MetadataClassTh; 11] = [
    MetadataClassTh::XattrNameSet,
    MetadataClassTh::PosixAccessAcl,
    MetadataClassTh::PosixDefaultAcl,
    MetadataClassTh::LinuxFileCapability,
    MetadataClassTh::Immutable,
    MetadataClassTh::AppendOnly,
    MetadataClassTh::Encrypted,
    MetadataClassTh::Verity,
    MetadataClassTh::Casefold,
    MetadataClassTh::NonzeroProjectId,
    MetadataClassTh::ProjectInherit,
];

/// Closed physical subject-kind order.
pub const SUBJECT_KINDS_TH: [MetadataSubjectKindTh; 5] = [
    MetadataSubjectKindTh::MountRoot,
    MetadataSubjectKindTh::RoleRoot,
    MetadataSubjectKindTh::RetainedDirectory,
    MetadataSubjectKindTh::RetainedRegularFile,
    MetadataSubjectKindTh::RetainedSymbolicLink,
];

/// The `statx` attribute bit for immutable inodes.
pub const STATX_ATTR_IMMUTABLE_TH: u64 = 0x10;
/// The `statx` attribute bit for append-only inodes.
pub const STATX_ATTR_APPEND_TH: u64 = 0x20;

/// Required condition names. A future provider must prove these facts from its
/// own retained session; merely copying this list does not satisfy them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrerequisiteTh {
    /// F0 explicitly accepts the trusted host premise.
    ExplicitTrustedHostF0Premise,
    /// Source and configuration premise matches the declared bytes.
    ExactKernelSourceAndConfigPremise,
    /// One fresh private tmpfs mount is retained.
    FreshPrivateTmpfsMount,
    /// Mutations are excluded through observation and transfer.
    ExclusiveMutationClosure,
    /// Mount and subject descriptors retain identity.
    RetainedMountAndSubjectDescriptors,
    /// Every retained subject is inventoried exactly once.
    CompleteSubjectInventory,
    /// No-follow leaf lookup cannot undergo an ABA replacement.
    NoFollowLeafLookupAndAbaExclusion,
    /// The observer has CAP_SYS_ADMIN in the initial user namespace.
    InitialUserNamespaceCapSysAdmin,
    /// The active LSM stack is observed in the same session.
    ActiveLsmStackObserved,
    /// Label-listing gaps are reviewed and hidden names checked directly.
    LsmHiddenLabelCoverageReviewedComplete,
    /// Name enumeration is complete and empty on every subject.
    CompleteXattrNameEnumeration,
    /// Supported statx bits are returned and clear on every subject.
    CompleteStatxAttributeMask,
    /// Read-only transfer retains and revalidates the same inventory.
    ReadOnlyTransferAndRevalidation,
}

/// Closed prerequisite order for the later provider.
pub const REQUIRED_PREREQUISITES_TH: [PrerequisiteTh; 13] = [
    PrerequisiteTh::ExplicitTrustedHostF0Premise,
    PrerequisiteTh::ExactKernelSourceAndConfigPremise,
    PrerequisiteTh::FreshPrivateTmpfsMount,
    PrerequisiteTh::ExclusiveMutationClosure,
    PrerequisiteTh::RetainedMountAndSubjectDescriptors,
    PrerequisiteTh::CompleteSubjectInventory,
    PrerequisiteTh::NoFollowLeafLookupAndAbaExclusion,
    PrerequisiteTh::InitialUserNamespaceCapSysAdmin,
    PrerequisiteTh::ActiveLsmStackObserved,
    PrerequisiteTh::LsmHiddenLabelCoverageReviewedComplete,
    PrerequisiteTh::CompleteXattrNameEnumeration,
    PrerequisiteTh::CompleteStatxAttributeMask,
    PrerequisiteTh::ReadOnlyTransferAndRevalidation,
];

/// Select the required proof mode for one prohibited metadata class.
#[must_use]
pub const fn expected_mode_th(class: MetadataClassTh) -> ExpectedModeTh {
    match class {
        MetadataClassTh::XattrNameSet
        | MetadataClassTh::PosixAccessAcl
        | MetadataClassTh::PosixDefaultAcl
        | MetadataClassTh::LinuxFileCapability => {
            ExpectedModeTh::ObservedXattrNamesAndHiddenLabelsAbsentComplete
        }
        MetadataClassTh::Immutable | MetadataClassTh::AppendOnly => {
            ExpectedModeTh::ObservedStatxBitClearComplete
        }
        MetadataClassTh::Encrypted
        | MetadataClassTh::Verity
        | MetadataClassTh::Casefold
        | MetadataClassTh::NonzeroProjectId
        | MetadataClassTh::ProjectInherit => ExpectedModeTh::StructurallyExcludedUnderF0,
    }
}

const fn compile_mode_table() -> [ExpectedModeCellTh; 55] {
    let mut table = [ExpectedModeCellTh {
        class: MetadataClassTh::XattrNameSet,
        kind: MetadataSubjectKindTh::MountRoot,
        mode: ExpectedModeTh::ObservedXattrNamesAndHiddenLabelsAbsentComplete,
    }; 55];
    let mut class_index = 0;
    while class_index < METADATA_CLASSES_TH.len() {
        let mut kind_index = 0;
        while kind_index < SUBJECT_KINDS_TH.len() {
            table[class_index * SUBJECT_KINDS_TH.len() + kind_index] = ExpectedModeCellTh {
                class: METADATA_CLASSES_TH[class_index],
                kind: SUBJECT_KINDS_TH[kind_index],
                mode: expected_mode_th(METADATA_CLASSES_TH[class_index]),
            };
            kind_index += 1;
        }
        class_index += 1;
    }
    table
}

/// Closed class-major, subject-kind-minor 55-cell expectation table.
pub const EXPECTED_MODE_TABLE_TH: [ExpectedModeCellTh; 55] = compile_mode_table();

/// Hash the complete ordered table with the TH-specific domain separator.
#[must_use]
pub fn expected_mode_table_sha256_th() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MODE_TABLE_DOMAIN);
    for cell in EXPECTED_MODE_TABLE_TH {
        hasher.update([cell.class as u8, cell.kind as u8, cell.mode as u8]);
    }
    hasher.finalize().into()
}

/// A declaration offered for pure consistency checking, never physical proof.
pub struct PolicyDeclarationTh<'a> {
    /// Policy identity.
    pub policy_id: &'a str,
    /// Explicit trusted-host premise identity.
    pub host_premise_id: &'a str,
    /// Observed, unauthenticated kernel release string.
    pub observed_kernel_release: &'a str,
    /// Candidate source commit.
    pub candidate_source_commit: &'a str,
    /// Captured compressed-config SHA-256.
    pub config_gzip_sha256_hex: &'a str,
    /// Installed-image SHA-256, without a boot equality claim.
    pub installed_kernel_sha256_hex: &'a str,
    /// Required prerequisite names in closed order.
    pub prerequisites: &'a [PrerequisiteTh],
    /// Required expectation cells in closed order.
    pub mode_table: &'a [ExpectedModeCellTh],
}

/// Check declaration identity and completeness without minting an authority.
pub fn require_exact_policy_declaration_th(
    candidate: &PolicyDeclarationTh<'_>,
) -> Result<(), &'static str> {
    if candidate.policy_id != POLICY_ID_TH_F0_V1 {
        return Err("trusted-host metadata policy ID differs");
    }
    if candidate.host_premise_id != HOST_PREMISE_ID_TH_F0_V1 {
        return Err("trusted-host F0 premise ID differs");
    }
    if candidate.observed_kernel_release != OBSERVED_KERNEL_RELEASE
        || candidate.candidate_source_commit != CANDIDATE_SOURCE_COMMIT
        || candidate.config_gzip_sha256_hex != CONFIG_GZIP_SHA256_HEX
        || candidate.installed_kernel_sha256_hex != INSTALLED_KERNEL_SHA256_HEX
    {
        return Err("trusted-host kernel-basis declaration differs");
    }
    if candidate.prerequisites != REQUIRED_PREREQUISITES_TH {
        return Err("trusted-host metadata prerequisites differ");
    }
    if candidate.mode_table != EXPECTED_MODE_TABLE_TH {
        return Err("trusted-host metadata mode table differs");
    }
    Ok(())
}

/// Pure shape check for a future xattr observer's LSM declaration. The caller
/// remains responsible for proving the declared stack and coverage physically.
pub struct LsmCoverageDeclarationTh<'a> {
    /// Observed active stack, requiring separate physical provenance.
    pub observed_stack: &'a str,
    /// Claimed review of all names hidden from the listing by that stack.
    pub hidden_label_coverage_reviewed_complete: bool,
    /// Claimed initial-user-namespace listing privilege.
    pub init_user_namespace_cap_sys_admin: bool,
}

/// Reject unknown coverage, absent stack, or missing listing privilege.
/// This does not authenticate the caller's assertions.
pub fn require_complete_lsm_coverage_declaration_th(
    declaration: &LsmCoverageDeclarationTh<'_>,
) -> Result<(), &'static str> {
    if declaration.observed_stack.is_empty() {
        return Err("active LSM stack is unobserved");
    }
    if declaration.observed_stack != DIAGNOSTIC_LSM_STACK_TH {
        return Err("active LSM stack differs from the selected diagnostic");
    }
    if !declaration.hidden_label_coverage_reviewed_complete {
        return Err("LSM hidden-label coverage is unknown");
    }
    if !declaration.init_user_namespace_cap_sys_admin {
        return Err("initial-user-namespace CAP_SYS_ADMIN is absent");
    }
    Ok(())
}

/// Claimed output of one no-follow xattr-name observation. The fields must be
/// filled by a later descriptor-retaining provider, not by a caller packet.
pub struct XattrAbsenceDeclarationTh<'a> {
    /// Whether the name-enumeration syscall completed without truncation.
    pub complete_no_follow_listing: bool,
    /// Whether the observed leaf remained the exact retained subject.
    pub same_retained_leaf: bool,
    /// Number of bytes in the complete name set; only zero is admitted.
    pub name_byte_count: usize,
    /// Direct `getxattrat` on the same no-follow retained leaf returned ENODATA
    /// for `security.selinux`; this name can be hidden when SELinux is present
    /// but uninitialized on the selected WSL boot.
    pub security_selinux_direct_absence_on_same_retained_leaf: bool,
    /// Active-stack, hidden-label coverage, and listing privilege declarations.
    pub lsm: LsmCoverageDeclarationTh<'a>,
}

/// Reject an incomplete or nonempty claimed xattr observation. This check
/// does not authenticate the provenance or truth of the supplied fields.
pub fn require_empty_xattr_observation_declaration_th(
    declaration: &XattrAbsenceDeclarationTh<'_>,
) -> Result<(), &'static str> {
    if !declaration.complete_no_follow_listing {
        return Err("xattr-name listing is incomplete or followed a symlink");
    }
    if !declaration.same_retained_leaf {
        return Err("xattr-name listing is detached from the retained leaf");
    }
    require_complete_lsm_coverage_declaration_th(&declaration.lsm)?;
    if declaration.name_byte_count != 0 {
        return Err("xattr-name set is nonempty");
    }
    if !declaration.security_selinux_direct_absence_on_same_retained_leaf {
        return Err("hidden security.selinux absence is unproved");
    }
    Ok(())
}

/// Claimed output of one retained-subject `statx` observation.
pub struct StatxAbsenceDeclarationTh {
    /// Requested result returned completely on the retained subject.
    pub complete_retained_subject_observation: bool,
    /// `stx_attributes_mask`, not the general `stx_mask` result field.
    pub attribute_support_mask: u64,
    /// `stx_attributes` returned by the same syscall.
    pub attributes: u64,
}

/// Reject an unsupported, set, or detached immutable/append-only claim.
/// This does not authenticate the syscall or the retained descriptor.
pub fn require_clear_statx_attribute_declaration_th(
    class: MetadataClassTh,
    declaration: &StatxAbsenceDeclarationTh,
) -> Result<(), &'static str> {
    let bit = match class {
        MetadataClassTh::Immutable => STATX_ATTR_IMMUTABLE_TH,
        MetadataClassTh::AppendOnly => STATX_ATTR_APPEND_TH,
        _ => return Err("metadata class does not use statx attribute observation"),
    };
    if !declaration.complete_retained_subject_observation {
        return Err("statx observation is incomplete or detached");
    }
    if declaration.attribute_support_mask & bit == 0 {
        return Err("statx attribute support bit is absent");
    }
    if declaration.attributes & bit != 0 {
        return Err("statx prohibited attribute is set");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declaration<'a>(
        prerequisites: &'a [PrerequisiteTh],
        mode_table: &'a [ExpectedModeCellTh],
    ) -> PolicyDeclarationTh<'a> {
        PolicyDeclarationTh {
            policy_id: POLICY_ID_TH_F0_V1,
            host_premise_id: HOST_PREMISE_ID_TH_F0_V1,
            observed_kernel_release: OBSERVED_KERNEL_RELEASE,
            candidate_source_commit: CANDIDATE_SOURCE_COMMIT,
            config_gzip_sha256_hex: CONFIG_GZIP_SHA256_HEX,
            installed_kernel_sha256_hex: INSTALLED_KERNEL_SHA256_HEX,
            prerequisites,
            mode_table,
        }
    }

    #[test]
    fn th_table_has_55_ordered_cells_and_frozen_digest() {
        assert_eq!(EXPECTED_MODE_TABLE_TH.len(), 55);
        for (index, cell) in EXPECTED_MODE_TABLE_TH.iter().enumerate() {
            assert_eq!(cell.class, METADATA_CLASSES_TH[index / 5]);
            assert_eq!(cell.kind, SUBJECT_KINDS_TH[index % 5]);
            assert_eq!(cell.mode, expected_mode_th(cell.class));
        }
        assert_eq!(
            hex::encode(expected_mode_table_sha256_th()),
            MODE_TABLE_SHA256_HEX
        );
        require_exact_policy_declaration_th(&declaration(
            &REQUIRED_PREREQUISITES_TH,
            &EXPECTED_MODE_TABLE_TH,
        ))
        .unwrap();
    }

    #[test]
    fn th_rejects_h0_and_v1_policy_ids_without_conversion() {
        for policy_id in [
            "eip0045-b4-retained-host-rootfs-metadata-obligations-v1",
            "eip0045-b4-retained-host-rootfs-metadata-obligations-v2",
        ] {
            let mut candidate = declaration(&REQUIRED_PREREQUISITES_TH, &EXPECTED_MODE_TABLE_TH);
            candidate.policy_id = policy_id;
            assert_eq!(
                require_exact_policy_declaration_th(&candidate),
                Err("trusted-host metadata policy ID differs")
            );
        }
    }

    #[test]
    fn th_rejects_each_substituted_kernel_basis_and_host_premise() {
        let mut candidate = declaration(&REQUIRED_PREREQUISITES_TH, &EXPECTED_MODE_TABLE_TH);
        candidate.host_premise_id = "eip0045-b4-trusted-host-wsl-f0-v0";
        assert_eq!(
            require_exact_policy_declaration_th(&candidate),
            Err("trusted-host F0 premise ID differs")
        );
        for substitute in 0..4 {
            let mut candidate = declaration(&REQUIRED_PREREQUISITES_TH, &EXPECTED_MODE_TABLE_TH);
            match substitute {
                0 => candidate.observed_kernel_release = "6.18.33.1-microsoft-standard-WSL2",
                1 => candidate.candidate_source_commit = "0000000000000000000000000000000000000000",
                2 => candidate.config_gzip_sha256_hex = "0",
                3 => candidate.installed_kernel_sha256_hex = "0",
                _ => unreachable!(),
            }
            assert_eq!(
                require_exact_policy_declaration_th(&candidate),
                Err("trusted-host kernel-basis declaration differs")
            );
        }
    }

    #[test]
    fn th_rejects_each_omitted_prerequisite() {
        for omitted in 0..REQUIRED_PREREQUISITES_TH.len() {
            let mut prerequisites = REQUIRED_PREREQUISITES_TH.to_vec();
            prerequisites.remove(omitted);
            assert_eq!(
                require_exact_policy_declaration_th(&declaration(
                    &prerequisites,
                    &EXPECTED_MODE_TABLE_TH,
                )),
                Err("trusted-host metadata prerequisites differ")
            );
        }
    }

    #[test]
    fn th_rejects_every_cell_mode_and_order_mutation_and_one_omission() {
        for cell_index in 0..EXPECTED_MODE_TABLE_TH.len() {
            let mut table = EXPECTED_MODE_TABLE_TH;
            let cell = &mut table[cell_index];
            cell.mode = match cell.mode {
                ExpectedModeTh::ObservedXattrNamesAndHiddenLabelsAbsentComplete => {
                    ExpectedModeTh::ObservedStatxBitClearComplete
                }
                ExpectedModeTh::ObservedStatxBitClearComplete
                | ExpectedModeTh::StructurallyExcludedUnderF0 => {
                    ExpectedModeTh::ObservedXattrNamesAndHiddenLabelsAbsentComplete
                }
            };
            assert_eq!(
                require_exact_policy_declaration_th(&declaration(
                    &REQUIRED_PREREQUISITES_TH,
                    &table
                )),
                Err("trusted-host metadata mode table differs")
            );

            let mut table = EXPECTED_MODE_TABLE_TH;
            let next_class = (cell_index / SUBJECT_KINDS_TH.len() + 1) % METADATA_CLASSES_TH.len();
            table[cell_index].class = METADATA_CLASSES_TH[next_class];
            assert_eq!(
                require_exact_policy_declaration_th(&declaration(
                    &REQUIRED_PREREQUISITES_TH,
                    &table
                )),
                Err("trusted-host metadata mode table differs")
            );

            let mut table = EXPECTED_MODE_TABLE_TH;
            let next_kind = (cell_index % SUBJECT_KINDS_TH.len() + 1) % SUBJECT_KINDS_TH.len();
            table[cell_index].kind = SUBJECT_KINDS_TH[next_kind];
            assert_eq!(
                require_exact_policy_declaration_th(&declaration(
                    &REQUIRED_PREREQUISITES_TH,
                    &table
                )),
                Err("trusted-host metadata mode table differs")
            );
        }
        let shortened = &EXPECTED_MODE_TABLE_TH[..54];
        assert_eq!(
            require_exact_policy_declaration_th(&declaration(
                &REQUIRED_PREREQUISITES_TH,
                shortened
            )),
            Err("trusted-host metadata mode table differs")
        );
    }

    #[test]
    fn th_rejects_unknown_lsm_coverage_and_missing_listing_privilege() {
        let mut lsm = LsmCoverageDeclarationTh {
            observed_stack: DIAGNOSTIC_LSM_STACK_TH,
            hidden_label_coverage_reviewed_complete: true,
            init_user_namespace_cap_sys_admin: true,
        };
        require_complete_lsm_coverage_declaration_th(&lsm).unwrap();
        lsm.observed_stack = "";
        assert_eq!(
            require_complete_lsm_coverage_declaration_th(&lsm),
            Err("active LSM stack is unobserved")
        );
        lsm.observed_stack = "capability,landlock,yama,safesetid";
        assert_eq!(
            require_complete_lsm_coverage_declaration_th(&lsm),
            Err("active LSM stack differs from the selected diagnostic")
        );
        lsm.observed_stack = DIAGNOSTIC_LSM_STACK_TH;
        lsm.hidden_label_coverage_reviewed_complete = false;
        assert_eq!(
            require_complete_lsm_coverage_declaration_th(&lsm),
            Err("LSM hidden-label coverage is unknown")
        );
        lsm.hidden_label_coverage_reviewed_complete = true;
        lsm.init_user_namespace_cap_sys_admin = false;
        assert_eq!(
            require_complete_lsm_coverage_declaration_th(&lsm),
            Err("initial-user-namespace CAP_SYS_ADMIN is absent")
        );
    }

    #[test]
    fn th_xattr_rule_rejects_isolated_nonempty_and_incomplete_claims() {
        let mut observation = XattrAbsenceDeclarationTh {
            complete_no_follow_listing: true,
            same_retained_leaf: true,
            name_byte_count: 0,
            security_selinux_direct_absence_on_same_retained_leaf: true,
            lsm: LsmCoverageDeclarationTh {
                observed_stack: DIAGNOSTIC_LSM_STACK_TH,
                hidden_label_coverage_reviewed_complete: true,
                init_user_namespace_cap_sys_admin: true,
            },
        };
        require_empty_xattr_observation_declaration_th(&observation).unwrap();
        observation.name_byte_count =
            b"user.b4probe\0trusted.b4probe\0system.posix_acl_access\0".len();
        assert_eq!(
            require_empty_xattr_observation_declaration_th(&observation),
            Err("xattr-name set is nonempty")
        );
        observation.name_byte_count = 0;
        observation.complete_no_follow_listing = false;
        assert_eq!(
            require_empty_xattr_observation_declaration_th(&observation),
            Err("xattr-name listing is incomplete or followed a symlink")
        );
        observation.complete_no_follow_listing = true;
        observation.same_retained_leaf = false;
        assert_eq!(
            require_empty_xattr_observation_declaration_th(&observation),
            Err("xattr-name listing is detached from the retained leaf")
        );
        observation.same_retained_leaf = true;
        observation.security_selinux_direct_absence_on_same_retained_leaf = false;
        assert_eq!(
            require_empty_xattr_observation_declaration_th(&observation),
            Err("hidden security.selinux absence is unproved")
        );
        observation.security_selinux_direct_absence_on_same_retained_leaf = true;
        observation.lsm.hidden_label_coverage_reviewed_complete = false;
        assert_eq!(
            require_empty_xattr_observation_declaration_th(&observation),
            Err("LSM hidden-label coverage is unknown")
        );
    }

    #[test]
    fn th_statx_rule_rejects_unsupported_set_and_detached_attributes() {
        for (class, bit) in [
            (MetadataClassTh::Immutable, STATX_ATTR_IMMUTABLE_TH),
            (MetadataClassTh::AppendOnly, STATX_ATTR_APPEND_TH),
        ] {
            let mut observation = StatxAbsenceDeclarationTh {
                complete_retained_subject_observation: true,
                attribute_support_mask: bit,
                attributes: 0,
            };
            require_clear_statx_attribute_declaration_th(class, &observation).unwrap();
            observation.attribute_support_mask = 0;
            assert_eq!(
                require_clear_statx_attribute_declaration_th(class, &observation),
                Err("statx attribute support bit is absent")
            );
            observation.attribute_support_mask = bit;
            observation.attributes = bit;
            assert_eq!(
                require_clear_statx_attribute_declaration_th(class, &observation),
                Err("statx prohibited attribute is set")
            );
            observation.attributes = 0;
            observation.complete_retained_subject_observation = false;
            assert_eq!(
                require_clear_statx_attribute_declaration_th(class, &observation),
                Err("statx observation is incomplete or detached")
            );
        }
        assert_eq!(
            require_clear_statx_attribute_declaration_th(
                MetadataClassTh::Verity,
                &StatxAbsenceDeclarationTh {
                    complete_retained_subject_observation: true,
                    attribute_support_mask: u64::MAX,
                    attributes: 0,
                },
            ),
            Err("metadata class does not use statx attribute observation")
        );
    }
}
