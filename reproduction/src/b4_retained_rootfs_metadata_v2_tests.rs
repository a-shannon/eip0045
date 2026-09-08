use super::b4_positive_gate::PositiveRunnerRole;
use super::b4_retained_rootfs_metadata_v2::*;

const MOUNT_EPOCH: [u8; 32] = [0xa5; 32];

fn role(index: usize) -> PositiveRunnerRole {
    CANONICAL_ROLES[index]
}

fn profile_identity() -> MetadataProfileIdentityV2 {
    bind_metadata_profile_v2(&MetadataProfileBindingV2 {
        theorem: canonical_metadata_theorem_candidate_v2(),
        resolved_config_sha256: [0x11; 32],
        boot_image_sha256: [0x22; 32],
        dynamic_extension_state_sha256: [0x33; 32],
    })
    .expect("canonical test profile binding")
}

fn descriptor(inode: u64) -> DescriptorIdentityV2 {
    DescriptorIdentityV2 {
        mount_id_unique: 41,
        device_major: 0,
        device_minor: 77,
        inode,
    }
}

fn subject(
    kind: MetadataSubjectKindV2,
    role: Option<PositiveRunnerRole>,
    entry_index: Option<u64>,
    inode: u64,
) -> MetadataSubjectIdentityV2 {
    MetadataSubjectIdentityV2 {
        kind,
        role,
        entry_index,
        descriptor: descriptor(inode),
        mount_epoch: MOUNT_EPOCH,
    }
}

fn nominal_subjects() -> Vec<MetadataSubjectIdentityV2> {
    let mut subjects = vec![subject(MetadataSubjectKindV2::MountRoot, None, None, 1)];
    let mut inode = 2_u64;
    for role in CANONICAL_ROLES {
        subjects.push(subject(
            MetadataSubjectKindV2::RoleRoot,
            Some(role),
            None,
            inode,
        ));
        inode += 1;
        for kind in [
            MetadataSubjectKindV2::RetainedDirectory,
            MetadataSubjectKindV2::RetainedRegularFile,
            MetadataSubjectKindV2::RetainedSymbolicLink,
        ] {
            subjects.push(subject(kind, Some(role), Some(0), inode));
            inode += 1;
        }
    }
    subjects
}

fn nominal_packet() -> RetainedRootfsMetadataPacketV2 {
    let profile = profile_identity();
    let subjects = nominal_subjects();
    let mut cells = Vec::new();
    for subject in &subjects {
        for class in PROHIBITED_METADATA_CLASSES_V2 {
            let mode = expected_metadata_mode_v2(class, subject.kind);
            let (attribute_mask, attributes) = match mode {
                ExpectedMetadataModeV2::ObservedAbsentComplete => {
                    (Some(STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND), Some(0))
                }
                ExpectedMetadataModeV2::StructurallyUnrepresentable => (None, None),
            };
            cells.push(MetadataCellRecordV2 {
                profile_identity_sha256: profile.profile_identity_sha256(),
                expected_mode_table_sha256: profile.expected_mode_table_sha256(),
                subject: subject.clone(),
                class,
                mode,
                attribute_mask,
                attributes,
            });
        }
    }
    RetainedRootfsMetadataPacketV2 {
        profile,
        root_seed: Some(MountRootSeedV2 {
            inode_flags: 0,
            shmem_fsflags: 0,
        }),
        claimed_counts: DynamicSubjectCountsV2 {
            retained_directories: 4,
            retained_regular_files: 4,
            retained_symbolic_links: 4,
        },
        subjects,
        cells,
    }
}

fn flip_mode(mode: ExpectedMetadataModeV2) -> ExpectedMetadataModeV2 {
    match mode {
        ExpectedMetadataModeV2::ObservedAbsentComplete => {
            ExpectedMetadataModeV2::StructurallyUnrepresentable
        }
        ExpectedMetadataModeV2::StructurallyUnrepresentable => {
            ExpectedMetadataModeV2::ObservedAbsentComplete
        }
    }
}

#[test]
fn b4_retained_rootfs_metadata_v2_table_is_exact_closed_and_profile_bound() {
    assert_eq!(PROHIBITED_METADATA_CLASSES_V2.len(), 11);
    assert_eq!(METADATA_SUBJECT_KINDS_V2.len(), 5);
    assert_eq!(EXPECTED_MODE_ENTRY_COUNT_V2, 55);
    assert_eq!(EXPECTED_MODE_TABLE_V2.len(), 55);

    let mut observed = 0;
    let mut structural = 0;
    for (ordinal, cell) in EXPECTED_MODE_TABLE_V2.into_iter().enumerate() {
        assert_eq!(
            cell.class,
            PROHIBITED_METADATA_CLASSES_V2[ordinal / METADATA_SUBJECT_KIND_COUNT_V2]
        );
        assert_eq!(
            cell.kind,
            METADATA_SUBJECT_KINDS_V2[ordinal % METADATA_SUBJECT_KIND_COUNT_V2]
        );
        assert_eq!(cell.mode, expected_metadata_mode_v2(cell.class, cell.kind));
        match cell.mode {
            ExpectedMetadataModeV2::ObservedAbsentComplete => observed += 1,
            ExpectedMetadataModeV2::StructurallyUnrepresentable => structural += 1,
        }
    }
    assert_eq!((structural, observed), (45, 10));

    for kind in METADATA_SUBJECT_KINDS_V2 {
        assert_eq!(
            expected_metadata_mode_v2(ProhibitedMetadataClassV2::Immutable, kind),
            ExpectedMetadataModeV2::ObservedAbsentComplete
        );
        assert_eq!(
            expected_metadata_mode_v2(ProhibitedMetadataClassV2::AppendOnly, kind),
            ExpectedMetadataModeV2::ObservedAbsentComplete
        );
    }

    let theorem =
        validate_metadata_theorem_candidate_v2(&canonical_metadata_theorem_candidate_v2())
            .expect("compiled theorem");
    assert_ne!(theorem.theorem_basis_sha256(), [0; 32]);
    assert_ne!(theorem.expected_mode_table_sha256(), [0; 32]);
    assert_ne!(
        theorem.theorem_basis_sha256(),
        theorem.expected_mode_table_sha256()
    );
    assert_eq!(
        hex::encode(theorem.theorem_basis_sha256()),
        THEOREM_BASIS_SHA256_HEX_V2
    );
    assert_eq!(
        hex::encode(theorem.expected_mode_table_sha256()),
        EXPECTED_MODE_TABLE_SHA256_HEX_V2
    );
    assert_eq!(
        hex::encode(profile_identity().profile_identity_sha256()),
        "5321d6a7614ff54d60c806b3a64210f7fe5767dca2138afda581f6b62dab7f47"
    );
    assert_eq!(REQUIRED_KERNEL_CONFIG_V2.len(), 27);
    assert_eq!(LINUX_SOURCE_PINS_V2.len(), 8);
    assert_eq!(LINUX_COMMIT_V2.len(), 40);
}

#[test]
fn b4_retained_rootfs_metadata_v2_every_configuration_and_source_pin_is_exact() {
    let canonical = canonical_metadata_theorem_candidate_v2();
    for index in 0..canonical.required_config.len() {
        let mut candidate = canonical.clone();
        candidate.required_config[index].state = candidate.required_config[index].state.flipped();
        assert_eq!(
            validate_metadata_theorem_candidate_v2(&candidate),
            Err(MetadataModelErrorV2::ConfigurationBinding { index })
        );
    }

    let mut missing = canonical.clone();
    missing.required_config.pop();
    assert_eq!(
        validate_metadata_theorem_candidate_v2(&missing),
        Err(MetadataModelErrorV2::ConfigurationCardinality)
    );

    let mut reordered = canonical.clone();
    reordered.required_config.swap(0, 1);
    assert_eq!(
        validate_metadata_theorem_candidate_v2(&reordered),
        Err(MetadataModelErrorV2::ConfigurationBinding { index: 0 })
    );

    for index in 0..canonical.source_pins.len() {
        let mut candidate = canonical.clone();
        candidate.source_pins[index]
            .sha256_hex
            .replace_range(0..1, "0");
        if candidate.source_pins[index] == canonical.source_pins[index] {
            candidate.source_pins[index]
                .sha256_hex
                .replace_range(0..1, "1");
        }
        assert_eq!(
            validate_metadata_theorem_candidate_v2(&candidate),
            Err(MetadataModelErrorV2::SourceBinding { index })
        );
    }

    let mut wrong_commit = canonical;
    wrong_commit.linux_commit.replace_range(0..1, "0");
    assert_eq!(
        validate_metadata_theorem_candidate_v2(&wrong_commit),
        Err(MetadataModelErrorV2::LinuxCommitBinding)
    );
}

#[test]
fn b4_retained_rootfs_metadata_v2_nominal_dynamic_packet_is_complete() {
    let packet = nominal_packet();
    assert_eq!(packet.subjects.len(), 17);
    assert_eq!(packet.cells.len(), 187);
    assert_eq!(
        expected_physical_cell_count_v2(packet.claimed_counts),
        Ok(187)
    );
    assert_eq!(validate_retained_rootfs_metadata_packet_v2(&packet), Ok(()));
}

#[test]
fn b4_retained_rootfs_metadata_v2_kind_mode_and_binding_mutants_fail_independently() {
    let nominal = nominal_packet();

    let mut wrong_kind = nominal.clone();
    wrong_kind.subjects[2].kind = MetadataSubjectKindV2::RetainedRegularFile;
    assert!(matches!(
        validate_retained_rootfs_metadata_packet_v2(&wrong_kind),
        Err(MetadataModelErrorV2::SubjectOrder { ordinal: 3 })
    ));

    for index in 0..nominal.cells.len() {
        let mut wrong_mode = nominal.clone();
        wrong_mode.cells[index].mode = flip_mode(wrong_mode.cells[index].mode);
        assert_eq!(
            validate_retained_rootfs_metadata_packet_v2(&wrong_mode),
            Err(MetadataModelErrorV2::CellMode { ordinal: index })
        );
    }

    let mut wrong_table = nominal.clone();
    wrong_table.cells[0].expected_mode_table_sha256[0] ^= 1;
    assert_eq!(
        validate_retained_rootfs_metadata_packet_v2(&wrong_table),
        Err(MetadataModelErrorV2::CellTableBinding { ordinal: 0 })
    );

    let mut wrong_profile = nominal;
    wrong_profile.cells[0].profile_identity_sha256[0] ^= 1;
    assert_eq!(
        validate_retained_rootfs_metadata_packet_v2(&wrong_profile),
        Err(MetadataModelErrorV2::CellProfileBinding { ordinal: 0 })
    );
}

#[test]
fn b4_retained_rootfs_metadata_v2_every_observed_mask_and_attribute_branch_is_isolated() {
    let nominal = nominal_packet();
    let observed_cells = nominal
        .cells
        .iter()
        .enumerate()
        .filter(|(_, cell)| cell.mode == ExpectedMetadataModeV2::ObservedAbsentComplete)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    assert_eq!(observed_cells.len(), nominal.subjects.len() * 2);

    for index in observed_cells {
        let bit = nominal.cells[index].class.observed_statx_bit().unwrap();

        let mut missing_mask = nominal.clone();
        missing_mask.cells[index].attribute_mask = None;
        assert_eq!(
            validate_retained_rootfs_metadata_packet_v2(&missing_mask),
            Err(MetadataModelErrorV2::ObservedMaskMissing { ordinal: index })
        );

        let mut unknown_mask = nominal.clone();
        unknown_mask.cells[index].attribute_mask = Some(0);
        assert_eq!(
            validate_retained_rootfs_metadata_packet_v2(&unknown_mask),
            Err(MetadataModelErrorV2::ObservedMaskUnknown { ordinal: index })
        );

        let mut present = nominal.clone();
        present.cells[index].attributes = Some(bit);
        assert_eq!(
            validate_retained_rootfs_metadata_packet_v2(&present),
            Err(MetadataModelErrorV2::ObservedAttributePresent { ordinal: index })
        );
    }

    let structural_index = nominal
        .cells
        .iter()
        .position(|cell| cell.mode == ExpectedMetadataModeV2::StructurallyUnrepresentable)
        .unwrap();
    let mut invented_observation = nominal;
    invented_observation.cells[structural_index].attribute_mask = Some(0);
    invented_observation.cells[structural_index].attributes = Some(0);
    assert_eq!(
        validate_retained_rootfs_metadata_packet_v2(&invented_observation),
        Err(MetadataModelErrorV2::StructuralObservationPresent {
            ordinal: structural_index
        })
    );
}

#[test]
fn b4_retained_rootfs_metadata_v2_root_seed_role_order_and_aliases_fail_closed() {
    let nominal = nominal_packet();

    let mut missing_seed = nominal.clone();
    missing_seed.root_seed = None;
    assert_eq!(
        validate_retained_rootfs_metadata_packet_v2(&missing_seed),
        Err(MetadataModelErrorV2::MountRootSeedMissing)
    );

    for seed in [
        MountRootSeedV2 {
            inode_flags: 1,
            shmem_fsflags: 0,
        },
        MountRootSeedV2 {
            inode_flags: 0,
            shmem_fsflags: 1,
        },
    ] {
        let mut nonzero_seed = nominal.clone();
        nonzero_seed.root_seed = Some(seed);
        assert_eq!(
            validate_retained_rootfs_metadata_packet_v2(&nonzero_seed),
            Err(MetadataModelErrorV2::MountRootSeedNonzero)
        );
    }

    let mut wrong_role = nominal.clone();
    wrong_role.subjects[1].role = Some(role(1));
    assert_eq!(
        validate_retained_rootfs_metadata_packet_v2(&wrong_role),
        Err(MetadataModelErrorV2::SubjectOrder { ordinal: 1 })
    );

    let mut reordered = nominal.clone();
    reordered.subjects.swap(2, 3);
    assert_eq!(
        validate_retained_rootfs_metadata_packet_v2(&reordered),
        Err(MetadataModelErrorV2::SubjectOrder { ordinal: 3 })
    );

    let mut duplicated = nominal.clone();
    duplicated
        .subjects
        .insert(2, duplicated.subjects[2].clone());
    assert_eq!(
        validate_retained_rootfs_metadata_packet_v2(&duplicated),
        Err(MetadataModelErrorV2::SubjectAlias { ordinal: 3 })
    );

    let mut extra = nominal.clone();
    extra.subjects.push(subject(
        MetadataSubjectKindV2::RoleRoot,
        Some(role(0)),
        None,
        99,
    ));
    assert_eq!(
        validate_retained_rootfs_metadata_packet_v2(&extra),
        Err(MetadataModelErrorV2::SubjectOrder { ordinal: 17 })
    );

    let mut aliased = nominal.clone();
    aliased.subjects[1].descriptor = aliased.subjects[0].descriptor;
    assert_eq!(
        validate_retained_rootfs_metadata_packet_v2(&aliased),
        Err(MetadataModelErrorV2::SubjectAlias { ordinal: 1 })
    );

    let mut foreign_mount = nominal;
    foreign_mount.subjects[1].descriptor.mount_id_unique += 1;
    assert_eq!(
        validate_retained_rootfs_metadata_packet_v2(&foreign_mount),
        Err(MetadataModelErrorV2::SubjectMountBinding { ordinal: 1 })
    );
}

#[test]
fn b4_retained_rootfs_metadata_v2_cardinality_and_omission_are_exact() {
    assert_eq!(
        expected_physical_cell_count_v2(DynamicSubjectCountsV2 {
            retained_directories: usize::MAX,
            retained_regular_files: 0,
            retained_symbolic_links: 0,
        }),
        Err(MetadataModelErrorV2::CardinalityOverflow)
    );

    let nominal = nominal_packet();
    let mut wrong_counts = nominal.clone();
    wrong_counts.claimed_counts.retained_directories -= 1;
    assert_eq!(
        validate_retained_rootfs_metadata_packet_v2(&wrong_counts),
        Err(MetadataModelErrorV2::DynamicSubjectCount)
    );

    let mut missing_mount_root = nominal.clone();
    missing_mount_root.subjects.remove(0);
    assert_eq!(
        validate_retained_rootfs_metadata_packet_v2(&missing_mount_root),
        Err(MetadataModelErrorV2::MountRootSubjectMissing)
    );

    let mut omitted_subject = nominal.clone();
    omitted_subject.subjects.remove(2);
    assert_eq!(
        validate_retained_rootfs_metadata_packet_v2(&omitted_subject),
        Err(MetadataModelErrorV2::DynamicSubjectCount)
    );

    let mut omitted_cell = nominal.clone();
    omitted_cell.cells.remove(0);
    assert_eq!(
        validate_retained_rootfs_metadata_packet_v2(&omitted_cell),
        Err(MetadataModelErrorV2::CellCardinality)
    );

    let mut reordered_cells = nominal;
    reordered_cells.cells.swap(0, 1);
    assert_eq!(
        validate_retained_rootfs_metadata_packet_v2(&reordered_cells),
        Err(MetadataModelErrorV2::CellClassOrder { ordinal: 0 })
    );
}

#[test]
fn b4_retained_rootfs_metadata_v2_surface_remains_pure_and_non_authorizing() {
    let source = include_str!("b4_retained_rootfs_metadata_v2.rs");
    for forbidden in [
        "std::fs::",
        "std::os::fd",
        "rustix::",
        "libc::",
        "Errno",
        "errno",
        "Deserialize",
        "Serialize",
        "unsafe {",
        "VerifiedBootAuthority",
        "AuthenticatedPrepareInputSetSourceV2",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden surface: {forbidden}"
        );
    }

    let cargo = include_str!("../Cargo.toml");
    assert!(cargo.contains("h0-tmpfs-provider-v2 = [\"positive-gate\"]"));
    let default_line = cargo
        .lines()
        .find(|line| line.starts_with("default ="))
        .unwrap();
    assert!(!default_line.contains("h0-tmpfs-provider-v2"));
}
