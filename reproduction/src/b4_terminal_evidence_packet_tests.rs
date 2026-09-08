use super::*;

const PROFILE_MANIFEST: &[u8] =
    include_bytes!("../../profiles/risc0-v3-succinct/manifest.bin");
const PROFILE_ALGORITHM: &[u8] =
    include_bytes!("../../profiles/risc0-v3-succinct/algorithm.txt");
const PROFILE_CONSTANTS: &[u8] =
    include_bytes!("../../profiles/risc0-v3-succinct/constants.bin");

#[test]
fn payload_constructors_are_bytes_only_and_fixed_shape() {
    let raw_seal = vec![0_u8; PROOF_BYTES];
    let profile = B4TerminalEvidenceProfilePayloadsV1::new(
        PROFILE_MANIFEST,
        PROFILE_ALGORITHM,
        PROFILE_CONSTANTS,
    )
    .unwrap();
    let sources =
        B4TerminalEvidenceProducerSourcesV1::new(b"g", b"s", b"0", b"8", b"9").unwrap();
    let fixtures = std::array::from_fn(|_| {
        B4TerminalEvidenceFixturePairPayloadV1::new(&raw_seal, b"o").unwrap()
    });
    let direct = B4TerminalEvidenceDirectPairPayloadV1::new(&raw_seal, b"d").unwrap();
    let _packet =
        B4TerminalEvidencePacketPayloadsV1::new(profile, sources, fixtures, b"c", direct)
            .unwrap();
}

#[test]
fn owned_packet_conversion_retains_all_twenty_nine_semantic_payload_roles() {
    let sentinel = |role: u8| vec![role];
    let owned = B4OwnedTerminalEvidencePacketPayloadsV1 {
        profile: B4OwnedTerminalEvidenceProfilePayloadsV1 {
            manifest: sentinel(1),
            algorithm: sentinel(2),
            constants: sentinel(3),
        },
        sources: B4OwnedTerminalEvidenceProducerSourcesV1 {
            guest_elf: sentinel(4),
            statement: sentinel(5),
            case0_lift15_receipt_oracle: sentinel(6),
            case8_terminal_join_recursive_oracle: sentinel(7),
            case9_terminal_resolve_recursive_oracle: sentinel(8),
        },
        fixtures: std::array::from_fn(|index| B4OwnedTerminalEvidencePairPayloadV1 {
            raw_seal: sentinel(u8::try_from(9 + index * 2).unwrap()),
            receipt_oracle: sentinel(u8::try_from(10 + index * 2).unwrap()),
        }),
        catalogue: sentinel(27),
        case8_direct: B4OwnedTerminalEvidencePairPayloadV1 {
            raw_seal: sentinel(28),
            receipt_oracle: sentinel(29),
        },
    };
    let semantic = owned.into_semantic_state(B4AuthenticatedPacketProfileV1 {
        profile_id: [0x30; DIGEST_BYTES],
        program_id: [0x31; DIGEST_BYTES],
        statement_sha256: [0x32; DIGEST_BYTES],
    });

    assert_eq!(semantic.profile_id, [0x30; DIGEST_BYTES]);
    assert_eq!(semantic.program_id, [0x31; DIGEST_BYTES]);
    assert_eq!(semantic.statement_sha256, [0x32; DIGEST_BYTES]);
    assert_eq!(semantic.profile.manifest, sentinel(1));
    assert_eq!(semantic.profile.algorithm, sentinel(2));
    assert_eq!(semantic.profile.constants, sentinel(3));
    assert_eq!(semantic.sources.guest_elf, sentinel(4));
    assert_eq!(semantic.sources.statement, sentinel(5));
    assert_eq!(
        semantic.sources.case0_lift15_receipt_oracle,
        sentinel(6)
    );
    assert_eq!(
        semantic.sources.case8_terminal_join_recursive_oracle,
        sentinel(7)
    );
    assert_eq!(
        semantic.sources.case9_terminal_resolve_recursive_oracle,
        sentinel(8)
    );
    assert_eq!(semantic.fixtures.len(), B4_TERMINAL_FIXTURE_COUNT);
    for (index, (pair, layout)) in semantic
        .fixtures
        .iter()
        .zip(B4_TERMINAL_FIXTURE_LAYOUT)
        .enumerate()
    {
        assert_eq!(
            pair.raw_seal,
            sentinel(u8::try_from(9 + index * 2).unwrap()),
            "raw-seal role drift for {}",
            layout.fixture_id
        );
        assert_eq!(
            pair.receipt_oracle,
            sentinel(u8::try_from(10 + index * 2).unwrap()),
            "receipt-oracle role drift for {}",
            layout.fixture_id
        );
    }
    assert_eq!(semantic.catalogue, sentinel(27));
    assert_eq!(semantic.case8_direct.raw_seal, sentinel(28));
    assert_eq!(semantic.case8_direct.receipt_oracle, sentinel(29));
}

#[test]
fn payload_role_bounds_are_enforced_before_semantic_decode() {
    assert!(
        B4TerminalEvidenceProfilePayloadsV1::new(
            &PROFILE_MANIFEST[..PROFILE_MANIFEST.len() - 1],
            PROFILE_ALGORITHM,
            PROFILE_CONSTANTS,
        )
        .is_err()
    );
    assert!(
        B4TerminalEvidenceProfilePayloadsV1::new(
            PROFILE_MANIFEST,
            &PROFILE_ALGORITHM[..PROFILE_ALGORITHM.len() - 1],
            PROFILE_CONSTANTS,
        )
        .is_err()
    );
    assert!(
        B4TerminalEvidenceProfilePayloadsV1::new(
            PROFILE_MANIFEST,
            PROFILE_ALGORITHM,
            &PROFILE_CONSTANTS[..PROFILE_CONSTANTS.len() - 1],
        )
        .is_err()
    );

    let oversized_guest = vec![0_u8; GUEST_ELF_MAX_BYTES + 1];
    let oversized_statement = vec![0_u8; MAX_STATEMENT_BYTES + 1];
    let oversized_oracle = vec![0_u8; RECEIPT_ORACLE_MAX_BYTES + 1];
    let oversized_recursive =
        vec![0_u8; B4_TERMINAL_EVIDENCE_RECURSIVE_SOURCE_MAX_BYTES + 1];
    assert!(
        B4TerminalEvidenceProducerSourcesV1::new(
            &oversized_guest,
            b"s",
            b"0",
            b"8",
            b"9"
        )
        .is_err()
    );
    assert!(
        B4TerminalEvidenceProducerSourcesV1::new(
            b"g",
            &oversized_statement,
            b"0",
            b"8",
            b"9"
        )
        .is_err()
    );
    assert!(
        B4TerminalEvidenceProducerSourcesV1::new(
            b"g",
            b"s",
            &oversized_oracle,
            b"8",
            b"9"
        )
        .is_err()
    );
    assert!(
        B4TerminalEvidenceProducerSourcesV1::new(
            b"g",
            b"s",
            b"0",
            &oversized_recursive,
            b"9"
        )
        .is_err()
    );
    assert!(
        B4TerminalEvidenceProducerSourcesV1::new(
            b"g",
            b"s",
            b"0",
            b"8",
            &oversized_recursive
        )
        .is_err()
    );

    let oversized_seal = vec![0_u8; PROOF_BYTES + 1];
    assert!(
        B4TerminalEvidenceFixturePairPayloadV1::new(&oversized_seal, b"o").is_err()
    );
    assert!(
        B4TerminalEvidenceFixturePairPayloadV1::new(&vec![0_u8; PROOF_BYTES], &oversized_oracle)
            .is_err()
    );
    assert!(B4TerminalEvidenceFixturePairPayloadV1::new(&[], b"o").is_err());
    assert!(
        B4TerminalEvidenceDirectPairPayloadV1::new(&oversized_seal, b"o").is_err()
    );
    assert!(
        B4TerminalEvidenceDirectPairPayloadV1::new(&vec![0_u8; PROOF_BYTES], &oversized_oracle)
            .is_err()
    );

    let raw_seal = vec![0_u8; PROOF_BYTES];
    let fixtures = std::array::from_fn(|_| {
        B4TerminalEvidenceFixturePairPayloadV1::new(&raw_seal, b"o").unwrap()
    });
    let profile = B4TerminalEvidenceProfilePayloadsV1::new(
        PROFILE_MANIFEST,
        PROFILE_ALGORITHM,
        PROFILE_CONSTANTS,
    )
    .unwrap();
    let sources =
        B4TerminalEvidenceProducerSourcesV1::new(b"g", b"s", b"0", b"8", b"9").unwrap();
    let direct = B4TerminalEvidenceDirectPairPayloadV1::new(&raw_seal, b"d").unwrap();
    let oversized_catalogue = vec![0_u8; B4_TERMINAL_FIXTURE_CATALOG_MAX_BYTES + 1];
    assert!(
        B4TerminalEvidencePacketPayloadsV1::new(
            profile,
            sources,
            fixtures,
            &oversized_catalogue,
            direct,
        )
        .is_err()
    );
}

#[test]
fn payload_authority_types_exist_with_opaque_surface() {
    let _: fn(
        B4TerminalEvidencePacketIdentityV1,
    ) -> u64 = B4TerminalEvidencePacketIdentityV1::manifest_byte_length;
    let _: fn(
        B4TerminalEvidencePacketIdentityV1,
    ) -> [u8; 32] = B4TerminalEvidencePacketIdentityV1::packet_id;
    let _: fn(
        &B4VerifiedTerminalEvidencePacketV1,
    ) -> B4TerminalEvidencePacketIdentityV1 = B4VerifiedTerminalEvidencePacketV1::identity;
    let _: fn(&B4VerifiedTerminalEvidencePacketV1) -> u64 =
        B4VerifiedTerminalEvidencePacketV1::manifest_byte_length;
    let _: fn(&B4VerifiedTerminalEvidencePacketV1) -> [u8; 32] =
        B4VerifiedTerminalEvidencePacketV1::packet_id;
    let _: for<'a> fn(
        &'a B4VerifiedTerminalEvidencePacketV1,
    ) -> B4TerminalEvidenceSourceReplayViewV1<'a> =
        B4VerifiedTerminalEvidencePacketV1::source_replay_view;
    let _ = B4TerminalEvidenceSourceReplayViewV1::guest_elf;
    let _ = B4TerminalEvidenceSourceReplayViewV1::statement;
    let _ = B4TerminalEvidenceSourceReplayViewV1::case0_lift15_receipt_oracle;
    let _ = B4TerminalEvidenceSourceReplayViewV1::case8_terminal_join_recursive_oracle;
    let _ = B4TerminalEvidenceSourceReplayViewV1::case9_terminal_resolve_recursive_oracle;
    let _ = B4TerminalEvidenceSourceReplayViewV1::case8_direct_pair;
    let _ = B4TerminalEvidenceFixturePairPayloadV1::raw_seal;
    let _ = B4TerminalEvidenceFixturePairPayloadV1::receipt_oracle;
    let _ = B4TerminalEvidenceDirectPairPayloadV1::raw_seal;
    let _ = B4TerminalEvidenceDirectPairPayloadV1::receipt_oracle;
}

fn fixed_statement(guest: &[u8]) -> Vec<u8> {
    let manifest = crate::b4_validator::authenticate_initial_profile_package(
        PROFILE_MANIFEST,
        PROFILE_ALGORITHM,
        PROFILE_CONSTANTS,
    )
    .unwrap();
    let program_id: [u8; 32] = risc0_binfmt::compute_image_id(guest).unwrap().into();
    crate::ergo_statement::ErgoStatementV1::new(
        [0x11; 32],
        manifest.profile_id().unwrap(),
        program_id,
        [0x22; 32],
        b"packet consumer boundary",
    )
    .unwrap()
    .encode()
    .unwrap()
}

#[test]
fn consumer_profile_guest_and_statement_reach_native_boundaries() {
    let (guest, _) = crate::test_support::valid_program_fixture();
    let statement = fixed_statement(&guest);

    let profile_error = match authenticate_packet_profile_program_statement(
        &vec![0_u8; PROFILE_MANIFEST_BYTES],
        PROFILE_ALGORITHM,
        PROFILE_CONSTANTS,
        &guest,
        &statement,
    ) {
        Ok(_) => panic!("malformed profile unexpectedly authenticated"),
        Err(error) => error,
    };
    assert!(
        format!("{profile_error:#}")
            .contains("cannot decode the authenticated initial profile manifest")
    );

    let guest_error = match authenticate_packet_profile_program_statement(
        PROFILE_MANIFEST,
        PROFILE_ALGORITHM,
        PROFILE_CONSTANTS,
        b"not-an-encoded-program",
        &statement,
    ) {
        Ok(_) => panic!("malformed guest unexpectedly authenticated"),
        Err(error) => error,
    };
    assert!(
        format!("{guest_error:#}")
            .contains("packet guest.elf is not a valid encoded RISC Zero program")
    );

    let statement_error = match authenticate_packet_profile_program_statement(
        PROFILE_MANIFEST,
        PROFILE_ALGORITHM,
        PROFILE_CONSTANTS,
        &guest,
        b"not-an-ergo-statement",
    ) {
        Ok(_) => panic!("malformed statement unexpectedly authenticated"),
        Err(error) => error,
    };
    assert!(
        format!("{statement_error:#}").contains("cannot decode packet ErgoStatementV1")
    );
}

#[test]
fn consumer_fixture_adapter_uses_all_nine_compiled_positions() {
    let raw_seals: [Vec<u8>; 9] =
        std::array::from_fn(|index| vec![u8::try_from(index).unwrap(); PROOF_BYTES]);
    let receipt_oracles: [Vec<u8>; 9] =
        std::array::from_fn(|index| vec![u8::try_from(index + 1).unwrap()]);
    let fixtures = std::array::from_fn(|index| {
        B4TerminalEvidenceFixturePairPayloadV1::new(
            &raw_seals[index],
            &receipt_oracles[index],
        )
        .unwrap()
    });

    let (raw_map, oracle_map) = packet_fixture_maps(&fixtures).unwrap();
    assert_eq!(raw_map.len(), 9);
    assert_eq!(oracle_map.len(), 9);
    for (index, layout) in B4_TERMINAL_FIXTURE_LAYOUT.iter().enumerate() {
        let raw_path = terminal_fixture_raw_seal_path(layout.fixture_id).unwrap();
        let oracle_path = terminal_fixture_receipt_oracle_path(layout.fixture_id).unwrap();
        assert_eq!(raw_map.get(&raw_path).unwrap(), &raw_seals[index]);
        assert_eq!(
            oracle_map.get(&oracle_path).unwrap(),
            &receipt_oracles[index]
        );
    }
}

#[test]
fn consumer_invalid_first_fixture_reaches_exact_typed_native_boundary() {
    let raw_seals: [Vec<u8>; 9] = std::array::from_fn(|_| vec![0_u8; PROOF_BYTES]);
    let receipt_oracles: [Vec<u8>; 9] = std::array::from_fn(|_| vec![0_u8]);
    let fixtures = std::array::from_fn(|index| {
        B4TerminalEvidenceFixturePairPayloadV1::new(
            &raw_seals[index],
            &receipt_oracles[index],
        )
        .unwrap()
    });

    let error = match replay_packet_fixture_pairs(&fixtures) {
        Ok(_) => panic!("malformed first fixture unexpectedly replayed"),
        Err(error) => error,
    };
    let error = error
        .downcast_ref::<crate::b4_terminal_oracle::B4TerminalOracleReplayError>()
        .unwrap();
    assert_eq!(
        error.kind(),
        crate::b4_terminal_oracle::B4TerminalOracleReplayErrorKind::ReceiptDecode
    );
    assert_eq!(
        error.slot(),
        Some(crate::b4_terminal_oracle::B4TerminalOracleSlot::LiftPo214)
    );
}

#[test]
fn consumer_catalogue_and_direct_receipt_use_exact_native_decoders() {
    let catalogue_error = decode_packet_fixture_catalogue(b"{").unwrap_err();
    assert!(
        format!("{catalogue_error:#}")
            .contains("terminal-fixture catalogue is not exact RFC 8785 JCS")
    );

    let replay =
        crate::receipt_oracle_replay::CompiledStockSuccinctReplayV1::from_compiled_profile()
            .unwrap();
    let direct_error = match decode_packet_direct_receipt(&replay, b"\0") {
        Ok(_) => panic!("malformed direct receipt unexpectedly decoded"),
        Err(error) => error,
    };
    assert_eq!(
        direct_error.kind(),
        crate::receipt_oracle_replay::StockReceiptReplayErrorKind::ReceiptDecode
    );
}

#[test]
fn consumer_adapters_are_derive_first_and_native_only() {
    let _: fn(
        &crate::b4_terminal_oracle::VerifiedB4TerminalOracleReplay,
        &[u8],
    ) -> std::result::Result<
        (),
        crate::b4_terminal_oracle::B4TerminalOracleReplayError,
    > = bind_packet_fixture_catalogue;
    let _: for<'a> fn(
        B4TerminalEvidenceDirectPairPayloadV1<'a>,
    ) -> std::result::Result<
        crate::receipt_oracle_replay::VerifiedStockSuccinctReceiptV1<
            risc0_zkvm::ReceiptClaim,
        >,
        crate::receipt_oracle_replay::StockReceiptReplayError,
    > = replay_packet_direct_pair;
    let _: fn(
        &B4OwnedTerminalEvidencePacketPayloadsV1,
    ) -> Result<crate::b4_case8_terminal_join_root::B4VerifiedCase8TerminalJoinReplayV1> =
        replay_packet_case8;
    let _: fn(
        B4TerminalEvidencePacketPayloadsV1<'_>,
    ) -> Result<B4TerminalEvidenceSemanticStateV1> = verify_packet_semantics;

    let receipt_oracle =
        crate::receipt_oracle_replay::test_support::alternate_direct_receipt_bytes();
    let direct = B4TerminalEvidenceDirectPairPayloadV1::new(
        crate::receipt_oracle_replay::test_support::alternate_raw_seal_bytes(),
        &receipt_oracle,
    )
    .unwrap();
    let error = match replay_packet_direct_pair(direct) {
        Ok(_) => panic!("alternate direct receipt unexpectedly replayed"),
        Err(error) => error,
    };
    assert_eq!(
        error.kind(),
        crate::receipt_oracle_replay::StockReceiptReplayErrorKind::ReceiptProfileShape
    );
}

#[test]
fn consumer_owned_and_verified_authorities_have_no_debug_or_mint_escape_hatch() {
    let source = include_str!("b4_terminal_evidence_packet.rs");
    for name in [
        "B4OwnedTerminalEvidenceProfilePayloadsV1",
        "B4OwnedTerminalEvidenceProducerSourcesV1",
        "B4OwnedTerminalEvidencePairPayloadV1",
        "B4OwnedTerminalEvidencePacketPayloadsV1",
        "B4AuthenticatedPacketProfileV1",
        "B4TerminalEvidenceSemanticStateV1",
        "B4TerminalEvidencePacketIdentityV1",
        "B4VerifiedTerminalEvidencePacketV1",
    ] {
        let declaration = format!("struct {name}");
        let offset = source.find(&declaration).unwrap();
        let prefix = &source[offset.saturating_sub(160)..offset];
        assert!(
            !prefix.contains("derive(Debug") && !prefix.contains(", Debug"),
            "{name} unexpectedly derives Debug"
        );
        assert!(
            !source.contains(&format!("impl core::fmt::Debug for {name}"))
                && !source.contains(&format!("impl std::fmt::Debug for {name}"))
                && !source.contains(&format!("impl fmt::Debug for {name}")),
            "{name} unexpectedly implements Debug"
        );
    }
    assert!(!source.contains("from_unchecked"));
    assert!(!source.contains("impl Serialize for B4VerifiedTerminalEvidencePacketV1"));
    assert!(!source.contains("impl Deserialize for B4VerifiedTerminalEvidencePacketV1"));
    assert!(!source.contains("impl Default for B4VerifiedTerminalEvidencePacketV1"));
}

#[test]
fn packet_inventory_is_exactly_twenty_nine_safe_unique_payloads() {
    let paths = compiled_b4_terminal_evidence_payload_paths().unwrap();
    assert_eq!(paths.len(), B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT);
    assert_eq!(B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT, 29);
    assert_eq!(B4_TERMINAL_EVIDENCE_FILE_COUNT, 31);

    let unique = paths.iter().collect::<std::collections::BTreeSet<_>>();
    assert_eq!(unique.len(), paths.len());
    for path in &paths {
        crate::b4_campaign_contract::validate_safe_relative_path(path).unwrap();
    }
    for (index, left) in paths.iter().enumerate() {
        for right in &paths[index + 1..] {
            assert!(!crate::b4_campaign_contract::b4_paths_conflict(left, right));
        }
    }

    assert_eq!(
        paths.as_slice(),
        [
            "derived/case-8-terminal-join-final.raw-seal.bin",
            "derived/case-8-terminal-join-final.receipt-oracle.bincode",
            "profiles/risc0-v3-succinct/algorithm.txt",
            "profiles/risc0-v3-succinct/constants.bin",
            "profiles/risc0-v3-succinct/manifest.bin",
            "reproduction/schema/b4-corpus-v1.candidate/bindings/terminal-fixture-catalog.json",
            "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/allowed-terminal-non-ok.raw-seal.bin",
            "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/allowed-terminal-non-ok.receipt-oracle.bincode",
            "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/join-povw.raw-seal.bin",
            "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/join-povw.receipt-oracle.bincode",
            "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/join-unwrap-povw.raw-seal.bin",
            "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/join-unwrap-povw.receipt-oracle.bincode",
            "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/lift-po2-14.raw-seal.bin",
            "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/lift-po2-14.receipt-oracle.bincode",
            "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/lift-povw-po2-18.raw-seal.bin",
            "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/lift-povw-po2-18.receipt-oracle.bincode",
            "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/resolve-povw.raw-seal.bin",
            "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/resolve-povw.receipt-oracle.bincode",
            "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/resolve-unwrap-povw.raw-seal.bin",
            "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/resolve-unwrap-povw.receipt-oracle.bincode",
            "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/union.raw-seal.bin",
            "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/union.receipt-oracle.bincode",
            "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/unwrap-povw.raw-seal.bin",
            "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/unwrap-povw.receipt-oracle.bincode",
            "sources/case-0-lift-15.receipt-oracle.bincode",
            "sources/case-8-terminal-join.recursive-oracle.borsh",
            "sources/case-9-terminal-resolve.recursive-oracle.borsh",
            "sources/guest.elf",
            "sources/statement.bin",
        ]
    );
}

#[test]
fn packet_documents_are_closed_canonical_and_manifest_ordered() {
    let manifest = synthetic_manifest().to_canonical_jcs().unwrap();
    let parsed = Eip0045B4TerminalEvidenceManifestV1::from_canonical_jcs(&manifest).unwrap();
    assert_eq!(parsed.files.len(), B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT);
    assert!(parsed.files.windows(2).all(|pair| pair[0].path < pair[1].path));

    let completion = Eip0045B4TerminalEvidenceCompletionV1::for_manifest(&manifest)
        .unwrap()
        .to_canonical_jcs()
        .unwrap();
    Eip0045B4TerminalEvidenceCompletionV1::from_canonical_jcs(&completion)
        .unwrap()
        .bind_manifest(&manifest)
        .unwrap();

    let mut unknown_value = crate::canonical::validate_canonical_json_source(&manifest).unwrap();
    unknown_value["unknown"] = serde_json::Value::from(0);
    let unknown = crate::canonical::canonical_json_bytes(&unknown_value).unwrap();
    let error = Eip0045B4TerminalEvidenceManifestV1::from_canonical_jcs(&unknown).unwrap_err();
    assert!(format!("{error:#}").contains("unknown field `unknown`"));

    let reordered = canonical_synthetic_manifest_value_with_first_two_files_swapped();
    assert!(Eip0045B4TerminalEvidenceManifestV1::from_canonical_jcs(&reordered).is_err());
}

#[test]
fn packet_bounds_are_compiled_checked_and_directory_closed() {
    assert_eq!(
        MANIFEST_MAX_BYTES,
        crate::b4_terminal::B4_TERMINAL_EVIDENCE_MANIFEST_MAX_BYTES
    );
    assert_eq!(COMPLETION_MAX_BYTES, 4_096);
    let roles = compiled_b4_terminal_evidence_role_table().unwrap();
    assert_eq!(roles.len(), B4_TERMINAL_EVIDENCE_PAYLOAD_COUNT);
    assert!(roles.iter().all(|role| role.minimum > 0 && role.minimum <= role.maximum));
    assert_eq!(
        roles
            .iter()
            .map(|role| (role.path.as_str(), role.minimum, role.maximum))
            .collect::<Vec<_>>(),
        vec![
            ("derived/case-8-terminal-join-final.raw-seal.bin", 222_668, 222_668),
            ("derived/case-8-terminal-join-final.receipt-oracle.bincode", 1, 1_048_576),
            ("profiles/risc0-v3-succinct/algorithm.txt", 29_773, 29_773),
            ("profiles/risc0-v3-succinct/constants.bin", 65_119, 65_119),
            ("profiles/risc0-v3-succinct/manifest.bin", 458, 458),
            ("reproduction/schema/b4-corpus-v1.candidate/bindings/terminal-fixture-catalog.json", 1, 262_144),
            ("reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/allowed-terminal-non-ok.raw-seal.bin", 222_668, 222_668),
            ("reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/allowed-terminal-non-ok.receipt-oracle.bincode", 1, 1_048_576),
            ("reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/join-povw.raw-seal.bin", 222_668, 222_668),
            ("reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/join-povw.receipt-oracle.bincode", 1, 1_048_576),
            ("reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/join-unwrap-povw.raw-seal.bin", 222_668, 222_668),
            ("reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/join-unwrap-povw.receipt-oracle.bincode", 1, 1_048_576),
            ("reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/lift-po2-14.raw-seal.bin", 222_668, 222_668),
            ("reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/lift-po2-14.receipt-oracle.bincode", 1, 1_048_576),
            ("reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/lift-povw-po2-18.raw-seal.bin", 222_668, 222_668),
            ("reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/lift-povw-po2-18.receipt-oracle.bincode", 1, 1_048_576),
            ("reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/resolve-povw.raw-seal.bin", 222_668, 222_668),
            ("reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/resolve-povw.receipt-oracle.bincode", 1, 1_048_576),
            ("reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/resolve-unwrap-povw.raw-seal.bin", 222_668, 222_668),
            ("reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/resolve-unwrap-povw.receipt-oracle.bincode", 1, 1_048_576),
            ("reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/union.raw-seal.bin", 222_668, 222_668),
            ("reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/union.receipt-oracle.bincode", 1, 1_048_576),
            ("reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/unwrap-povw.raw-seal.bin", 222_668, 222_668),
            ("reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/unwrap-povw.receipt-oracle.bincode", 1, 1_048_576),
            ("sources/case-0-lift-15.receipt-oracle.bincode", 1, 1_048_576),
            ("sources/case-8-terminal-join.recursive-oracle.borsh", 1, 33_554_432),
            ("sources/case-9-terminal-resolve.recursive-oracle.borsh", 1, 33_554_432),
            ("sources/guest.elf", 1, 4_194_304),
            ("sources/statement.bin", 1, 16_543),
        ]
    );
    let aggregate = checked_role_maximum(&roles).unwrap();
    assert_eq!(aggregate, 85_438_221);
    assert_eq!(complete_packet_maximum(&roles).unwrap(), 85_507_853);
    assert!(checked_sum([usize::MAX, 1]).is_err());
    let directories = compiled_b4_terminal_evidence_directories().unwrap();
    assert_eq!(directories.len(), 9);
    assert_eq!(directories.len() + 1, 10);
}
