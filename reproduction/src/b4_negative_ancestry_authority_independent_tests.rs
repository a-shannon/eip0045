// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

// Independent upstream-type KATs for the negative-ancestry claim authority.
//
// Expected claims in this module are constructed directly from RISC Zero's
// `ReceiptClaim`, `Output`, `Assumptions`, and `Assumption` types. They never
// call the authority's claim derivation or the shared recursive-inventory
// derivation helper.

use risc0_zkvm::{
    Assumption, Assumptions, Digest as Risc0Digest, MaybePruned, Output, ReceiptClaim,
    sha::Digestible as _,
};
use sha2::{Digest as _, Sha256};

use super::*;
use crate::{
    b4_negative_ancestry_witness::B4NegativeAncestryWitnessIdV1,
    constants::{
        DIGEST_BYTES, RISC0_INNER_CONTROL_ROOT_HEX, RISC0_NORMAL_LIFT_CONTROL_IDS_HEX,
        RISC0_RESOLVE_CONTROL_ID_HEX,
    },
    ergo_statement::{ErgoStatementFieldV1, ErgoStatementV1, parse_ergo_statement_v1},
    recursive_ancestry::{
        RECURSIVE_ANCESTRY_FORMAT, RECURSIVE_ANCESTRY_FORMAT_VERSION,
        RecursiveAncestryArtifactReference, RecursiveAncestryAssumption,
        RecursiveAncestryInventoryEntry, RecursiveAncestryOperation, RecursiveAncestryProjection,
        RecursiveAncestrySourceInventory, RecursiveAncestryStep, RecursiveAncestryTerminal,
    },
};

const CONSUMER_PROGRAM_ID: [u8; DIGEST_BYTES] = [0x44; DIGEST_BYTES];
const ALTERNATE_PROGRAM_ID: [u8; DIGEST_BYTES] = [0x55; DIGEST_BYTES];
const PROFILE_ID: [u8; DIGEST_BYTES] = [0x22; DIGEST_BYTES];

#[derive(Clone)]
struct IndependentClaimFixture {
    profile: AuthenticatedProfileV1,
    case9: AuthenticatedCase9V1,
    canonical: RecursiveAncestryClaim,
    alternate_statement: RecursiveAncestryClaim,
    alternate_program: RecursiveAncestryClaim,
    duplicate: RecursiveAncestryClaim,
    source_head: Assumption,
}

fn sha256_array(bytes: &[u8]) -> [u8; DIGEST_BYTES] {
    Sha256::digest(bytes).into()
}

fn decode_hex_digest(value: &str) -> [u8; DIGEST_BYTES] {
    hex::decode(value).unwrap().try_into().unwrap()
}

fn independent_projection(claim: &ReceiptClaim) -> RecursiveAncestryClaim {
    let (system_exit, user_exit) = claim.exit_code.into_pair();
    RecursiveAncestryClaim {
        input_digest: hex::encode(claim.input.digest().as_bytes()),
        pre_state_digest: hex::encode(claim.pre.digest().as_bytes()),
        post_state_digest: hex::encode(claim.post.digest().as_bytes()),
        system_exit,
        user_exit,
        output_digest: hex::encode(claim.output.digest().as_bytes()),
    }
}

fn independent_ok_claim(program_id: [u8; DIGEST_BYTES], journal: &[u8]) -> ReceiptClaim {
    ReceiptClaim::ok(Risc0Digest::from(program_id), journal.to_vec())
}

fn independent_inventory_claim(
    base: &ReceiptClaim,
    journal: &[u8],
    entries: Vec<MaybePruned<Assumption>>,
) -> ReceiptClaim {
    ReceiptClaim {
        input: base.input.clone(),
        pre: base.pre.clone(),
        post: base.post.clone(),
        exit_code: base.exit_code,
        output: MaybePruned::Value(Some(Output {
            journal: MaybePruned::Pruned(Risc0Digest::from(sha256_array(journal))),
            assumptions: MaybePruned::Value(Assumptions(entries)),
        })),
    }
}

fn independent_statement(
    chain_domain_id: [u8; DIGEST_BYTES],
    program_id: [u8; DIGEST_BYTES],
    contract_id: [u8; DIGEST_BYTES],
    payload: &[u8],
) -> Vec<u8> {
    ErgoStatementV1::new(
        chain_domain_id,
        PROFILE_ID,
        program_id,
        contract_id,
        payload,
    )
    .unwrap()
    .encode()
    .unwrap()
}

fn independent_reference(label: &str) -> RecursiveAncestryArtifactReference {
    RecursiveAncestryArtifactReference {
        path: format!("independent/{label}.bin"),
        byte_length: 1,
        sha256: "11".repeat(DIGEST_BYTES),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the fixture keeps every independently constructed upstream claim visible"
)]
fn independent_claim_fixture() -> IndependentClaimFixture {
    let canonical_statement = independent_statement(
        [0x11; DIGEST_BYTES],
        CONSUMER_PROGRAM_ID,
        [0x33; DIGEST_BYTES],
        b"independent authority KAT",
    );
    let canonical_upstream = independent_ok_claim(CONSUMER_PROGRAM_ID, &canonical_statement);
    let canonical = independent_projection(&canonical_upstream);

    let requested_root = decode_hex_digest(RISC0_INNER_CONTROL_ROOT_HEX);
    let source_head = Assumption {
        claim: canonical_upstream.digest(),
        control_root: Risc0Digest::from(requested_root),
    };
    let one_head_upstream = independent_inventory_claim(
        &canonical_upstream,
        &canonical_statement,
        vec![MaybePruned::Value(source_head.clone())],
    );
    let duplicate_upstream = independent_inventory_claim(
        &canonical_upstream,
        &canonical_statement,
        vec![
            MaybePruned::Value(source_head.clone()),
            MaybePruned::Value(source_head.clone()),
        ],
    );
    let duplicate = independent_projection(&duplicate_upstream);

    let mut alternate_chain_domain = [0x11; DIGEST_BYTES];
    alternate_chain_domain[0] ^= 0x01;
    let alternate_statement_bytes = independent_statement(
        alternate_chain_domain,
        CONSUMER_PROGRAM_ID,
        [0x33; DIGEST_BYTES],
        b"independent authority KAT",
    );
    let alternate_statement = independent_projection(&independent_ok_claim(
        CONSUMER_PROGRAM_ID,
        &alternate_statement_bytes,
    ));

    let alternate_program_statement = independent_statement(
        [0x11; DIGEST_BYTES],
        ALTERNATE_PROGRAM_ID,
        [0x33; DIGEST_BYTES],
        b"independent authority KAT",
    );
    let alternate_program = independent_projection(&independent_ok_claim(
        ALTERNATE_PROGRAM_ID,
        &alternate_program_statement,
    ));

    let inventory = RecursiveAncestrySourceInventory {
        entries: vec![RecursiveAncestryInventoryEntry::Revealed {
            claim_digest: hex::encode(source_head.claim.as_bytes()),
            control_root: hex::encode(source_head.control_root.as_bytes()),
        }],
    };
    let lift_terminal = RecursiveAncestryTerminal::Lift {
        segment_po2: 15,
        control_id: RISC0_NORMAL_LIFT_CONTROL_IDS_HEX[0].to_owned(),
    };
    let family = RecursiveAncestryFamily::TerminalResolve;
    let projection = RecursiveAncestryProjection {
        format: RECURSIVE_ANCESTRY_FORMAT.to_owned(),
        format_version: RECURSIVE_ANCESTRY_FORMAT_VERSION,
        case_id: family.case_id().to_owned(),
        profile_id: hex::encode(PROFILE_ID),
        program_id: hex::encode(CONSUMER_PROGRAM_ID),
        statement: independent_reference("statement"),
        family,
        assumption_receipt: Some(RecursiveAncestryAssumption {
            claim: canonical.clone(),
            requested_control_root: hex::encode(requested_root),
            source_inventory: inventory,
            raw_seal: independent_reference("assumption"),
            terminal: lift_terminal.clone(),
        }),
        steps: vec![
            RecursiveAncestryStep {
                ordinal: 0,
                operation: RecursiveAncestryOperation::Lift { segment_index: 0 },
                claim: independent_projection(&one_head_upstream),
                raw_seal: independent_reference("conditional"),
                terminal: lift_terminal,
            },
            RecursiveAncestryStep {
                ordinal: 1,
                operation: RecursiveAncestryOperation::Resolve {
                    conditional_step: 0,
                },
                claim: canonical.clone(),
                raw_seal: independent_reference("final"),
                terminal: RecursiveAncestryTerminal::Resolve {
                    control_id: RISC0_RESOLVE_CONTROL_ID_HEX.to_owned(),
                },
            },
        ],
    };
    let identity = |path: &str, bytes: &[u8]| {
        B4ContractArtifactIdentityV1::from_bytes(
            path,
            B4ContractArtifactEncodingV1::RawBytes,
            bytes,
        )
        .unwrap()
    };
    let profile = AuthenticatedProfileV1 {
        profile_manifest: identity("independent/profile.bin", b"profile"),
        consumer_program_id: CONSUMER_PROGRAM_ID,
        alternate_guest_elf: identity("independent/alternate.elf", b"alternate"),
        alternate_program_id: ALTERNATE_PROGRAM_ID,
        profile_id: PROFILE_ID,
    };
    let case9 = AuthenticatedCase9V1 {
        projection,
        statement: canonical_statement,
        final_raw_seal: b"final".to_vec(),
        assumption_raw_seal: b"assumption".to_vec(),
    };

    IndependentClaimFixture {
        profile,
        case9,
        canonical,
        alternate_statement,
        alternate_program,
        duplicate,
        source_head,
    }
}

fn expected_independent_dispatch(
    fixture: &IndependentClaimFixture,
) -> BTreeMap<B4NegativeAncestryWitnessIdV1, RecursiveAncestryClaim> {
    BTreeMap::from([
        (
            B4NegativeAncestryWitnessIdV1::Case9AssumptionLift,
            fixture.canonical.clone(),
        ),
        (
            B4NegativeAncestryWitnessIdV1::Case9FinalResolve,
            fixture.canonical.clone(),
        ),
        (
            B4NegativeAncestryWitnessIdV1::AlternateStatementAssumptionLift,
            fixture.alternate_statement.clone(),
        ),
        (
            B4NegativeAncestryWitnessIdV1::AlternateStatementFinalResolve,
            fixture.alternate_statement.clone(),
        ),
        (
            B4NegativeAncestryWitnessIdV1::AlternateStatementFinalJoin,
            fixture.alternate_statement.clone(),
        ),
        (
            B4NegativeAncestryWitnessIdV1::AlternateProgramLift,
            fixture.alternate_program.clone(),
        ),
        (
            B4NegativeAncestryWitnessIdV1::DuplicateAssumptionLift,
            fixture.duplicate.clone(),
        ),
    ])
}

fn independent_claim_digest_hex(claim: &RecursiveAncestryClaim) -> String {
    hex::encode(recursive_ancestry_claim_digest(claim).unwrap())
}

#[test]
fn exact_four_class_dispatch_matches_independent_risc0_claim_kat() {
    let fixture = independent_claim_fixture();
    let derived = derive_expected_claims(&fixture.profile, &fixture.case9).unwrap();
    let expected = expected_independent_dispatch(&fixture);

    assert_eq!(derived, expected);
    assert_eq!(derived.len(), 7);
    assert_eq!(
        derived
            .values()
            .map(independent_claim_digest_hex)
            .collect::<BTreeSet<_>>()
            .len(),
        4
    );
    assert_eq!(
        derived[&B4NegativeAncestryWitnessIdV1::Case9AssumptionLift],
        derived[&B4NegativeAncestryWitnessIdV1::Case9FinalResolve]
    );
    assert_eq!(
        derived[&B4NegativeAncestryWitnessIdV1::AlternateStatementAssumptionLift],
        derived[&B4NegativeAncestryWitnessIdV1::AlternateStatementFinalResolve]
    );
    assert_eq!(
        derived[&B4NegativeAncestryWitnessIdV1::AlternateStatementAssumptionLift],
        derived[&B4NegativeAncestryWitnessIdV1::AlternateStatementFinalJoin]
    );
}

#[test]
fn statement_and_program_kats_reject_every_recipe_foreign_binding() {
    let fixture = independent_claim_fixture();
    let canonical_statement = &fixture.case9.statement;
    let canonical_parsed = parse_ergo_statement_v1(canonical_statement).unwrap();

    let arbitrary_journal = independent_projection(&independent_ok_claim(
        CONSUMER_PROGRAM_ID,
        b"arbitrary journal",
    ));
    assert_ne!(arbitrary_journal, fixture.canonical);

    let wrong_contract_statement = independent_statement(
        canonical_parsed.chain_domain_id(),
        CONSUMER_PROGRAM_ID,
        [0x34; DIGEST_BYTES],
        canonical_parsed.application_payload(),
    );
    let wrong_contract = independent_projection(&independent_ok_claim(
        CONSUMER_PROGRAM_ID,
        &wrong_contract_statement,
    ));
    assert_ne!(wrong_contract, fixture.canonical);
    assert_ne!(wrong_contract, fixture.alternate_statement);

    let wrong_image = independent_projection(&independent_ok_claim(
        [0x66; DIGEST_BYTES],
        canonical_statement,
    ));
    assert_ne!(wrong_image, fixture.canonical);

    let alternate_image_over_unchanged_statement = independent_projection(&independent_ok_claim(
        ALTERNATE_PROGRAM_ID,
        canonical_statement,
    ));
    assert_ne!(
        alternate_image_over_unchanged_statement, fixture.alternate_program,
        "the alternate image must also be bound into the statement program field"
    );

    let intended_chain_statement = parse_ergo_statement_v1(&fixture.case9.statement).unwrap();
    let mut chain_domain = intended_chain_statement.chain_domain_id();
    chain_domain[0] ^= 0x01;
    let alternate_statement = independent_statement(
        chain_domain,
        CONSUMER_PROGRAM_ID,
        intended_chain_statement.contract_id(),
        intended_chain_statement.application_payload(),
    );
    let layout = intended_chain_statement.layout().unwrap();
    let chain_span = layout.span(ErgoStatementFieldV1::ChainDomainId);
    assert_eq!(canonical_statement.len(), alternate_statement.len());
    assert_eq!(
        &canonical_statement[..chain_span.start()],
        &alternate_statement[..chain_span.start()]
    );
    assert_eq!(
        &canonical_statement[chain_span.end()..],
        &alternate_statement[chain_span.end()..]
    );
    assert_eq!(
        canonical_statement
            .iter()
            .zip(&alternate_statement)
            .filter(|(left, right)| left != right)
            .count(),
        1
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "each independently built assumption-list defect is isolated in one matrix"
)]
fn duplicate_assumption_kat_is_count_value_root_digest_and_order_exact() {
    let fixture = independent_claim_fixture();
    let canonical_upstream = independent_ok_claim(CONSUMER_PROGRAM_ID, &fixture.case9.statement);
    let head = fixture.source_head.clone();
    let exact = |entries| {
        independent_projection(&independent_inventory_claim(
            &canonical_upstream,
            &fixture.case9.statement,
            entries,
        ))
    };

    let one = exact(vec![MaybePruned::Value(head.clone())]);
    let three = exact(vec![
        MaybePruned::Value(head.clone()),
        MaybePruned::Value(head.clone()),
        MaybePruned::Value(head.clone()),
    ]);
    assert_ne!(one, fixture.duplicate, "one head is the conditional source");
    assert_ne!(
        three, fixture.duplicate,
        "three heads are not the closed recipe"
    );

    let unequal_claim = Assumption {
        claim: Risc0Digest::from([0x71; DIGEST_BYTES]),
        control_root: head.control_root,
    };
    let unequal = exact(vec![
        MaybePruned::Value(head.clone()),
        MaybePruned::Value(unequal_claim.clone()),
    ]);
    assert_ne!(unequal, fixture.duplicate);

    let wrong_root = Assumption {
        claim: head.claim,
        control_root: Risc0Digest::from([0x72; DIGEST_BYTES]),
    };
    let wrong_root_claim = exact(vec![
        MaybePruned::Value(wrong_root.clone()),
        MaybePruned::Value(wrong_root),
    ]);
    assert_ne!(wrong_root_claim, fixture.duplicate);

    let wrong_digest = Assumption {
        claim: Risc0Digest::from([0x73; DIGEST_BYTES]),
        control_root: head.control_root,
    };
    let wrong_digest_claim = exact(vec![
        MaybePruned::Value(wrong_digest.clone()),
        MaybePruned::Value(wrong_digest),
    ]);
    assert_ne!(wrong_digest_claim, fixture.duplicate);

    let ordered = exact(vec![
        MaybePruned::Value(head.clone()),
        MaybePruned::Value(unequal_claim.clone()),
    ]);
    let reversed = exact(vec![
        MaybePruned::Value(unequal_claim),
        MaybePruned::Value(head.clone()),
    ]);
    assert_ne!(ordered, reversed, "the upstream assumption list is ordered");

    let exact_pruned = exact(vec![
        MaybePruned::Pruned(head.digest()),
        MaybePruned::Pruned(head.digest()),
    ]);
    assert_eq!(
        exact_pruned, fixture.duplicate,
        "pruning is digest-preserving and must be rejected by source-shape authentication"
    );
}

#[test]
fn case9_head_source_rejects_count_unequal_root_digest_and_pruning_defects() {
    let fixture = independent_claim_fixture();
    assert!(derive_expected_claims(&fixture.profile, &fixture.case9).is_ok());
    let valid = fixture
        .case9
        .projection
        .assumption_receipt
        .as_ref()
        .unwrap()
        .source_inventory
        .entries[0]
        .clone();

    for mutation in 0..6 {
        let mut mutated = fixture.case9.clone();
        let assumption = mutated.projection.assumption_receipt.as_mut().unwrap();
        assumption.source_inventory.entries = match mutation {
            0 => vec![],
            1 => vec![valid.clone(), valid.clone(), valid.clone()],
            2 => vec![
                valid.clone(),
                RecursiveAncestryInventoryEntry::Revealed {
                    claim_digest: "71".repeat(DIGEST_BYTES),
                    control_root: RISC0_INNER_CONTROL_ROOT_HEX.to_owned(),
                },
            ],
            3 => vec![RecursiveAncestryInventoryEntry::Revealed {
                claim_digest: fixture.canonical.input_digest.clone(),
                control_root: RISC0_INNER_CONTROL_ROOT_HEX.to_owned(),
            }],
            4 => vec![RecursiveAncestryInventoryEntry::Revealed {
                claim_digest: independent_claim_digest_hex(&fixture.canonical),
                control_root: "72".repeat(DIGEST_BYTES),
            }],
            5 => vec![RecursiveAncestryInventoryEntry::Pruned {
                digest: hex::encode(fixture.source_head.digest().as_bytes()),
            }],
            _ => unreachable!(),
        };
        let error = derive_expected_claims(&fixture.profile, &mutated).unwrap_err();
        let expected_boundary = match mutation {
            0 | 1 | 2 | 5 => "assumption source inventory is not exactly one revealed head",
            3 => "revealed assumption claim differs from its authenticated receipt claim",
            4 => "revealed assumption root differs from the requested control root",
            _ => unreachable!(),
        };
        assert_eq!(
            error.to_string(),
            expected_boundary,
            "case-9 source mutation {mutation} reached an incidental boundary"
        );
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the table independently constructs every recipe-foreign claim before exercising the one authority boundary"
)]
fn independently_valid_recipe_foreign_claim_matrix_is_rejected_by_authority() {
    for mutation in 0..11 {
        let mut fixture = derivation_fixture();
        let statement = fixture.authenticated.case9.statement.clone();
        let parsed = parse_ergo_statement_v1(&statement).unwrap();
        let consumer_program_id = fixture.authenticated.profile.consumer_program_id;
        let alternate_program_id = fixture.authenticated.profile.alternate_program_id;
        let canonical = independent_ok_claim(consumer_program_id, &statement);
        let root = Risc0Digest::from(decode_hex_digest(RISC0_INNER_CONTROL_ROOT_HEX));
        let head = Assumption {
            claim: canonical.digest(),
            control_root: root,
        };
        let inventory_claim = |entries| {
            independent_projection(&independent_inventory_claim(
                &canonical, &statement, entries,
            ))
        };
        let other = Assumption {
            claim: Risc0Digest::from([0x71; DIGEST_BYTES]),
            control_root: root,
        };

        let (label, representative_token, foreign_claim) = match mutation {
            0 => (
                "arbitrary journal",
                0x11,
                independent_projection(&independent_ok_claim(
                    consumer_program_id,
                    b"arbitrary journal",
                )),
            ),
            1 => {
                let mut chain_domain = parsed.chain_domain_id();
                chain_domain[0] ^= 0x01;
                let wrong_statement = ErgoStatementV1::new(
                    chain_domain,
                    parsed.profile_id(),
                    consumer_program_id,
                    [0x34; DIGEST_BYTES],
                    parsed.application_payload(),
                )
                .unwrap()
                .encode()
                .unwrap();
                (
                    "wrong alternate-statement field",
                    0x45,
                    independent_projection(&independent_ok_claim(
                        consumer_program_id,
                        &wrong_statement,
                    )),
                )
            }
            2 => (
                "wrong image",
                0x11,
                independent_projection(&independent_ok_claim([0x66; DIGEST_BYTES], &statement)),
            ),
            3 => (
                "alternate image over unchanged statement",
                0x47,
                independent_projection(&independent_ok_claim(alternate_program_id, &statement)),
            ),
            4 => (
                "one assumption",
                0x54,
                inventory_claim(vec![MaybePruned::Value(head.clone())]),
            ),
            5 => (
                "three assumptions",
                0x54,
                inventory_claim(vec![
                    MaybePruned::Value(head.clone()),
                    MaybePruned::Value(head.clone()),
                    MaybePruned::Value(head.clone()),
                ]),
            ),
            6 => (
                "unequal assumptions",
                0x54,
                inventory_claim(vec![
                    MaybePruned::Value(head.clone()),
                    MaybePruned::Value(other.clone()),
                ]),
            ),
            7 => {
                let wrong_root = Assumption {
                    claim: head.claim,
                    control_root: Risc0Digest::from([0x72; DIGEST_BYTES]),
                };
                (
                    "wrong requested root",
                    0x54,
                    inventory_claim(vec![
                        MaybePruned::Value(wrong_root.clone()),
                        MaybePruned::Value(wrong_root),
                    ]),
                )
            }
            8 => {
                let wrong_digest = Assumption {
                    claim: Risc0Digest::from([0x73; DIGEST_BYTES]),
                    control_root: root,
                };
                (
                    "wrong claim digest",
                    0x54,
                    inventory_claim(vec![
                        MaybePruned::Value(wrong_digest.clone()),
                        MaybePruned::Value(wrong_digest),
                    ]),
                )
            }
            9 => (
                "ordered unequal heads",
                0x54,
                inventory_claim(vec![
                    MaybePruned::Value(head.clone()),
                    MaybePruned::Value(other.clone()),
                ]),
            ),
            10 => (
                "reversed unequal heads",
                0x54,
                inventory_claim(vec![MaybePruned::Value(other), MaybePruned::Value(head)]),
            ),
            _ => unreachable!(),
        };
        let replayed = fixture
            .replay
            .expected
            .iter_mut()
            .find(|((raw_seal, _), _)| raw_seal.first() == Some(&representative_token))
            .unwrap()
            .1;
        replayed.claim = foreign_claim;

        let entries = fixture.external_entries();
        let external = dummy_external_closure(&entries, &fixture.alternate_elf);
        let error = build_catalog_authority(
            &fixture.prior,
            &external,
            &fixture.authenticated,
            &fixture.replay,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("claim foreign to its compiled producer recipe"),
            "{label} reached an incidental rejection boundary: {error:#}"
        );
    }
}

#[test]
fn coordinated_program_claim_and_terminal_candidate_rewrites_never_replace_authority() {
    let fixture = derivation_fixture();
    let entries = fixture.external_entries();
    let external = dummy_external_closure(&entries, &fixture.alternate_elf);
    let authority = build_catalog_authority(
        &fixture.prior,
        &external,
        &fixture.authenticated,
        &fixture.replay,
    )
    .unwrap();

    let mut consumer_rewrite = authority.catalog().clone();
    consumer_rewrite.consumer_program_id = "66".repeat(DIGEST_BYTES);
    for entry in consumer_rewrite
        .entries
        .iter_mut()
        .filter(|entry| !matches!(entry.expanded_row, 147 | 151))
    {
        entry.producer_program_id = consumer_rewrite.consumer_program_id.clone();
        entry.claim.pre_state_digest = consumer_rewrite.consumer_program_id.clone();
        entry.claim_digest = independent_claim_digest_hex(&entry.claim);
    }
    consumer_rewrite.validate().unwrap();
    assert!(
        authority
            .verify_candidate_jcs(&consumer_rewrite.to_canonical_jcs().unwrap())
            .is_err()
    );

    let mut alternate_rewrite = authority.catalog().clone();
    alternate_rewrite.alternate_program_id = "77".repeat(DIGEST_BYTES);
    for entry in alternate_rewrite
        .entries
        .iter_mut()
        .filter(|entry| matches!(entry.expanded_row, 147 | 151))
    {
        entry.producer_program_id = alternate_rewrite.alternate_program_id.clone();
        entry.claim.pre_state_digest = alternate_rewrite.alternate_program_id.clone();
        entry.claim_digest = independent_claim_digest_hex(&entry.claim);
    }
    alternate_rewrite.validate().unwrap();
    assert!(
        authority
            .verify_candidate_jcs(&alternate_rewrite.to_canonical_jcs().unwrap())
            .is_err()
    );

    let mut claim_rewrite = authority.catalog().clone();
    for entry in claim_rewrite
        .entries
        .iter_mut()
        .filter(|entry| matches!(entry.expanded_row, 141 | 142 | 143 | 153))
    {
        entry.claim.output_digest = "78".repeat(DIGEST_BYTES);
        entry.claim_digest = independent_claim_digest_hex(&entry.claim);
    }
    claim_rewrite.validate().unwrap();
    assert!(
        authority
            .verify_candidate_jcs(&claim_rewrite.to_canonical_jcs().unwrap())
            .is_err()
    );

    let mut terminal_rewrite = authority.catalog().clone();
    terminal_rewrite.entries[0].terminal = RecursiveAncestryTerminal::Resolve {
        control_id: RISC0_RESOLVE_CONTROL_ID_HEX.to_owned(),
    };
    assert!(
        terminal_rewrite.validate().is_err(),
        "typed terminals are frozen by the compiled slot before authority comparison"
    );
    let terminal_rewrite_jcs =
        canonical_json_bytes(&serde_json::to_value(&terminal_rewrite).unwrap()).unwrap();
    assert!(
        authority
            .verify_candidate_jcs(&terminal_rewrite_jcs)
            .is_err()
    );
}
