#![cfg(feature = "positive-gate")]

//! Draft 2020-12 interoperability-schema parity tests for the B4 campaign.
//!
//! The schemas close JSON object shape, Serde field names, tagged-union
//! alternatives, lexical forms, enums, and local numeric/cardinality bounds.
//! They intentionally do not claim authority over semantic ordering, digest
//! recomputation, no-op exclusion, plan/registry bijections, cross-document
//! mappings, physical artifacts, or validator observations. The strict parsers,
//! replay adapters, and campaign gates continue to own those invariants.

use jsonschema::Validator;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::{
    b4::{
        B4_MAX_JCS_SAFE_INTEGER, B4AncestryInventoryOperation, B4AncestryInventoryTarget,
        B4ArtifactBinding, B4ArtifactEncoding, B4BindingState, B4BoundaryShiftDirection,
        B4ByteOperation, B4ByteTarget, B4CandidateCorpus, B4GuestBinding, B4NegativeCase,
        B4NegativeMaterialization, B4NegativeMutation, B4PositiveArtifact, B4PositiveArtifactRole,
        B4PositiveCase, B4PositiveFamily, B4RegistryStage, B4SequenceOperation, B4SequenceTarget,
        B4StatementBinding, negative_ancestry_witness_recipe,
    },
    b4_catalog::{
        B4_SUBJECT_CATALOG_FORMAT, B4_SUBJECT_CATALOG_FORMAT_VERSION, B4SubjectArtifactIdentityV1,
        B4SubjectCatalogEntryV1, B4SubjectProvenanceV1, Eip0045B4SubjectCatalogV1,
    },
    b4_mutation::{
        B4_MATERIALIZATION_IDENTITY_FORMAT, B4_MATERIALIZATION_IDENTITY_FORMAT_VERSION,
        B4ByteEditReplayAdapterV1, Eip0045B4MaterializationIdentityV1,
        create_materialization_identity_with_adapter, reconstruct_mutation,
        verify_materialization_identity_with_adapter,
    },
    b4_plan::{Eip0045B4NegativePlanV1, negative_group_requires_fixture_selection},
    b4_registry_probe::Eip0045B4NegativeBindingIndexV1,
    b4_result::{
        B4_VALIDATION_RESULT_FORMAT, B4_VALIDATION_RESULT_FORMAT_VERSION, B4ObservedRejectionV1,
        B4ValidationReplayContextV1, B4ValidationResultExpectationV1, B4ValidationVerdict,
        B4ValidatorArtifactIdentityV1, B4ValidatorImplementation, Eip0045B4ValidationResultV1,
        create_b4_validation_result, verify_b4_validation_result,
    },
    b4_subject::{B4SequenceSubjectElement, Eip0045B4SequenceSubjectV1},
    b4_terminal::{
        B4_STOCK_CONTROL_LAYOUT, B4_TERMINAL_FIXTURE_CATALOG_FORMAT,
        B4_TERMINAL_FIXTURE_CATALOG_FORMAT_VERSION, B4_TERMINAL_FIXTURE_CATALOG_STAGE,
        B4_TERMINAL_FIXTURE_LAYOUT, B4_TERMINAL_FIXTURE_RECEIPT_CODEC,
        B4_TERMINAL_FIXTURE_RISC0_VERSION, B4ApplicationBindingV1, B4AssumptionsBindingV1,
        B4DirectApplicationBindingV1, B4ExitStatusV1, B4StockControlV1, B4TerminalArtifactV1,
        B4TerminalBindingV1, B4TerminalFixtureV1, B4TerminalUpstreamV1, B4UnionAssumptionBindingV1,
        Eip0045B4TerminalFixtureCatalogV1, terminal_fixture_raw_seal_path,
        terminal_fixture_receipt_oracle_path,
    },
    b4_tree_probe::Eip0045B4AbstractTreeV1,
    canonical::canonical_json_bytes,
    constants::{PROOF_BYTES, RISC0_COMMIT, RISC0_INNER_CONTROL_ROOT_HEX, RISC0_REPOSITORY},
};

type SchemaSource = (&'static str, &'static str, &'static str);

const SCHEMAS: [SchemaSource; 9] = [
    (
        "negative-plan",
        "urn:ergo:eip-0045:b4-negative-plan-v1",
        include_str!("../finalizer-schema/b4-negative-plan-v1.schema.json"),
    ),
    (
        "expanded-corpus-registry",
        "urn:ergo:eip-0045:b4-expanded-corpus-registry-v1",
        include_str!("../finalizer-schema/b4-expanded-corpus-registry-v1.schema.json"),
    ),
    (
        "sequence-subject",
        "urn:ergo:eip-0045:b4-sequence-subject-v1",
        include_str!("../finalizer-schema/b4-sequence-subject-v1.schema.json"),
    ),
    (
        "subject-catalog",
        "urn:ergo:eip-0045:b4-subject-catalog-v1",
        include_str!("../finalizer-schema/b4-subject-catalog-v1.schema.json"),
    ),
    (
        "terminal-fixture-catalog",
        "urn:ergo:eip-0045:b4-terminal-fixture-catalog-v1",
        include_str!("../finalizer-schema/b4-terminal-fixture-catalog-v1.schema.json"),
    ),
    (
        "negative-binding-index",
        "urn:ergo:eip-0045:b4-negative-binding-index-v1",
        include_str!("../finalizer-schema/b4-negative-binding-index-v1.schema.json"),
    ),
    (
        "abstract-tree",
        "urn:ergo:eip-0045:b4-abstract-tree-v1",
        include_str!("../finalizer-schema/b4-abstract-tree-v1.schema.json"),
    ),
    (
        "materialization-identity",
        "urn:ergo:eip-0045:b4-materialization-identity-v1",
        include_str!("../finalizer-schema/b4-materialization-identity-v1.schema.json"),
    ),
    (
        "validation-result",
        "urn:ergo:eip-0045:b4-validation-result-v1",
        include_str!("../finalizer-schema/b4-validation-result-v1.schema.json"),
    ),
];

fn compile_schema(source: &str) -> Validator {
    let schema = crate::canonical::parse_json_strict(source.as_bytes()).unwrap();
    jsonschema::draft202012::options().build(&schema).unwrap()
}

fn assert_valid(source: &str, instance: &Value, label: &str) {
    compile_schema(source)
        .validate(instance)
        .unwrap_or_else(|error| panic!("{label} fixture fails its schema: {error}"));
}

fn assert_invalid(source: &str, instance: &Value, label: &str) {
    assert!(
        compile_schema(source).validate(instance).is_err(),
        "{label} unexpectedly satisfies its schema"
    );
}

fn schema_source(name: &str) -> &'static str {
    SCHEMAS
        .iter()
        .find_map(|(candidate, _, source)| (*candidate == name).then_some(*source))
        .unwrap()
}

fn assert_internal_refs(value: &Value) {
    match value {
        Value::Object(object) => {
            if object.get("type") == Some(&Value::String("object".to_owned())) {
                assert_eq!(
                    object.get("additionalProperties"),
                    Some(&Value::Bool(false)),
                    "object schema is not closed with additionalProperties:false"
                );
            }
            for (key, nested) in object {
                if key == "$ref" {
                    let reference = nested.as_str().unwrap();
                    assert!(
                        reference.starts_with("#/"),
                        "schema contains a non-internal reference: {reference}"
                    );
                }
                assert_internal_refs(nested);
            }
        }
        Value::Array(items) => {
            for item in items {
                assert_internal_refs(item);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

fn digest(value: usize) -> String {
    format!("{value:064x}")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn canonical_plan() -> (Eip0045B4NegativePlanV1, Vec<u8>) {
    let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
    let source = plan.to_canonical_jcs().unwrap();
    (plan, source)
}

fn sequence_subject() -> Eip0045B4SequenceSubjectV1 {
    Eip0045B4SequenceSubjectV1::new(
        B4SequenceTarget::ProofChunks,
        vec![
            B4SequenceSubjectElement::from_bytes("chunk-a", b"abc").unwrap(),
            B4SequenceSubjectElement::from_bytes("chunk-b", b"def").unwrap(),
        ],
    )
    .unwrap()
}

fn subject_entry(
    subject_id: &str,
    target: B4SequenceTarget,
    provenance: B4SubjectProvenanceV1,
    seed: usize,
) -> B4SubjectCatalogEntryV1 {
    B4SubjectCatalogEntryV1 {
        artifact: B4SubjectArtifactIdentityV1 {
            byte_length: 1,
            path: format!(
                "reproduction/schema/b4-corpus-v1.candidate/subjects/{subject_id}.subject.json"
            ),
            sha256: digest(seed),
        },
        provenance,
        subject_id: subject_id.to_owned(),
        target,
    }
}

fn subject_catalog(plan_source: &[u8]) -> Eip0045B4SubjectCatalogV1 {
    let plan_sha256 = sha256_hex(plan_source);
    let profile_id = "23c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383";
    let proof_cases = [
        ("proof-chunks-lift-po2-15", "lift-po2-15"),
        ("proof-chunks-lift-po2-16", "lift-po2-16"),
        ("proof-chunks-lift-po2-17", "lift-po2-17"),
        ("proof-chunks-lift-po2-18", "lift-po2-18"),
        ("proof-chunks-lift-po2-19", "lift-po2-19"),
        ("proof-chunks-lift-po2-20", "lift-po2-20"),
        ("proof-chunks-lift-po2-21", "lift-po2-21"),
        ("proof-chunks-lift-po2-22", "lift-po2-22"),
        ("proof-chunks-terminal-join", "terminal-join"),
        (
            "proof-chunks-terminal-resolve-explicit-root",
            "terminal-resolve-explicit-root",
        ),
        (
            "proof-chunks-resolve-zero-root-then-join",
            "resolve-zero-root-then-join",
        ),
    ];
    let mut subjects = vec![
        subject_entry(
            "registry-positive-cases",
            B4SequenceTarget::RegistryPositiveCases,
            B4SubjectProvenanceV1::PositiveProjection {
                positive_case_count: 11,
            },
            1,
        ),
        subject_entry(
            "registry-negative-cases",
            B4SequenceTarget::RegistryNegativeCases,
            B4SubjectProvenanceV1::NegativePlan {
                plan_sha256: plan_sha256.clone(),
            },
            2,
        ),
        subject_entry(
            "registry-negative-classes",
            B4SequenceTarget::RegistryNegativeClasses,
            B4SubjectProvenanceV1::NegativeClasses {
                plan_sha256: plan_sha256.clone(),
            },
            3,
        ),
        subject_entry(
            "profile-package-files",
            B4SequenceTarget::ProfilePackageFiles,
            B4SubjectProvenanceV1::ProfilePackage {
                profile_id: profile_id.to_owned(),
            },
            4,
        ),
    ];
    subjects.extend(
        proof_cases
            .into_iter()
            .enumerate()
            .map(|(index, (subject_id, case_id))| {
                subject_entry(
                    subject_id,
                    B4SequenceTarget::ProofChunks,
                    B4SubjectProvenanceV1::ProofChunks {
                        case_id: case_id.to_owned(),
                        raw_seal_sha256: digest(20 + index),
                    },
                    40 + index,
                )
            }),
    );
    let catalog = Eip0045B4SubjectCatalogV1 {
        format: B4_SUBJECT_CATALOG_FORMAT.to_owned(),
        format_version: B4_SUBJECT_CATALOG_FORMAT_VERSION,
        subjects,
    };
    catalog.validate().unwrap();
    catalog
}

#[allow(clippy::too_many_lines)]
fn terminal_catalog() -> Eip0045B4TerminalFixtureCatalogV1 {
    let stock_controls = B4_STOCK_CONTROL_LAYOUT
        .iter()
        .map(|row| B4StockControlV1 {
            stock_index: row.stock_index,
            family: row.family.to_owned(),
            upstream_program: row.upstream_program.to_owned(),
            control_id: row.control_id.to_owned(),
            eip_allowed: row.eip_allowed,
        })
        .collect::<Vec<_>>();
    let fixtures = B4_TERMINAL_FIXTURE_LAYOUT
        .iter()
        .enumerate()
        .map(|(index, layout)| {
            let stock = match layout.expected_family {
                Some(family) => B4_STOCK_CONTROL_LAYOUT
                    .iter()
                    .find(|row| row.family == family)
                    .unwrap(),
                None => &B4_STOCK_CONTROL_LAYOUT[1],
            };
            let status = if layout.direct_ok == Some(false) {
                B4ExitStatusV1 {
                    system: 2,
                    user: 0,
                    ok: false,
                }
            } else {
                B4ExitStatusV1 {
                    system: 0,
                    user: 0,
                    ok: true,
                }
            };
            let application = if layout.fixture_id == "union" {
                B4ApplicationBindingV1::Union {
                    left: B4UnionAssumptionBindingV1 {
                        assumption_digest: digest(90),
                        source_claim_digest: digest(1),
                        witness_fixture_ids: vec!["lift-po2-14".to_owned()],
                    },
                    right: B4UnionAssumptionBindingV1 {
                        assumption_digest: digest(91),
                        source_claim_digest: digest(2),
                        witness_fixture_ids: vec!["lift-povw-po2-18".to_owned()],
                    },
                }
            } else {
                B4ApplicationBindingV1::Direct {
                    binding: B4DirectApplicationBindingV1 {
                        application_claim_digest: digest(100 + index),
                        status,
                        assumptions: if layout.direct_ok == Some(false) {
                            B4AssumptionsBindingV1::NoOutput
                        } else {
                            B4AssumptionsBindingV1::Commitment {
                                digest: digest(0),
                                empty: true,
                            }
                        },
                    },
                }
            };
            B4TerminalFixtureV1 {
                fixture_id: layout.fixture_id.to_owned(),
                family: stock.family.to_owned(),
                claim_kind: layout.claim_kind,
                claim_digest: digest(index + 1),
                terminal: B4TerminalBindingV1 {
                    stock_index: stock.stock_index,
                    control_id: stock.control_id.to_owned(),
                    control_root: RISC0_INNER_CONTROL_ROOT_HEX.to_owned(),
                    eip_allowed: stock.eip_allowed,
                },
                application,
                raw_seal: B4TerminalArtifactV1 {
                    path: terminal_fixture_raw_seal_path(layout.fixture_id).unwrap(),
                    byte_length: PROOF_BYTES as u64,
                    sha256: digest(140 + index),
                },
                receipt_oracle: B4TerminalArtifactV1 {
                    path: terminal_fixture_receipt_oracle_path(layout.fixture_id).unwrap(),
                    byte_length: 1,
                    sha256: digest(160 + index),
                },
            }
        })
        .collect();
    let catalog = Eip0045B4TerminalFixtureCatalogV1 {
        format: B4_TERMINAL_FIXTURE_CATALOG_FORMAT.to_owned(),
        format_version: B4_TERMINAL_FIXTURE_CATALOG_FORMAT_VERSION,
        stage: B4_TERMINAL_FIXTURE_CATALOG_STAGE.to_owned(),
        upstream: B4TerminalUpstreamV1 {
            repository: RISC0_REPOSITORY.to_owned(),
            commit: RISC0_COMMIT.to_owned(),
            risc0_zkvm_version: B4_TERMINAL_FIXTURE_RISC0_VERSION.to_owned(),
            receipt_oracle_codec: B4_TERMINAL_FIXTURE_RECEIPT_CODEC.to_owned(),
        },
        program_id: digest(200),
        inner_control_root: RISC0_INNER_CONTROL_ROOT_HEX.to_owned(),
        stock_controls,
        fixtures,
    };
    catalog.validate().unwrap();
    catalog
}

fn bound(path: String, encoding: B4ArtifactEncoding) -> B4ArtifactBinding {
    B4ArtifactBinding {
        byte_length: 1,
        encoding,
        path,
        sha256: digest(0),
        state: B4BindingState::Bound,
    }
}

fn positive_artifacts(case: &B4PositiveCase) -> Vec<B4PositiveArtifact> {
    let roles: &[B4PositiveArtifactRole] = if case.family == B4PositiveFamily::Lift {
        &[
            B4PositiveArtifactRole::ClaimDigest,
            B4PositiveArtifactRole::ControlId,
            B4PositiveArtifactRole::ImageId,
            B4PositiveArtifactRole::Journal,
            B4PositiveArtifactRole::Metadata,
            B4PositiveArtifactRole::RawSeal,
            B4PositiveArtifactRole::ReceiptOracle,
        ]
    } else {
        &[
            B4PositiveArtifactRole::Ancestry,
            B4PositiveArtifactRole::Calibration,
            B4PositiveArtifactRole::ClaimDigest,
            B4PositiveArtifactRole::ControlId,
            B4PositiveArtifactRole::ImageId,
            B4PositiveArtifactRole::Journal,
            B4PositiveArtifactRole::RawSeal,
            B4PositiveArtifactRole::ReceiptOracle,
        ]
    };
    roles
        .iter()
        .copied()
        .enumerate()
        .map(|(index, role)| B4PositiveArtifact {
            byte_length: 1,
            encoding: match role {
                B4PositiveArtifactRole::Ancestry
                | B4PositiveArtifactRole::Calibration
                | B4PositiveArtifactRole::Metadata => B4ArtifactEncoding::Rfc8785Jcs,
                B4PositiveArtifactRole::ClaimDigest
                | B4PositiveArtifactRole::ControlId
                | B4PositiveArtifactRole::ImageId
                | B4PositiveArtifactRole::Journal
                | B4PositiveArtifactRole::RawSeal
                | B4PositiveArtifactRole::ReceiptOracle => B4ArtifactEncoding::RawBytes,
            },
            path: format!(
                "reproduction/schema/b4-corpus-v1.candidate/positive/{}/{index:02}-artifact",
                case.case_id
            ),
            role,
            sha256: digest(index + 1),
        })
        .collect()
}

fn synthetic_mutation(index: usize, execution_id: &str) -> B4NegativeMutation {
    if execution_id == "resolve-explicit-field-sweep--assumption-receipt-root" {
        B4NegativeMutation::AlternateRootAssumptionSubstitution {}
    } else if let Some(recipe) = negative_ancestry_witness_recipe(execution_id) {
        B4NegativeMutation::AncestryWitnessSubstitution { recipe }
    } else if execution_id == "resolve-assumption-inventory-sweep--pruned-assumption" {
        B4NegativeMutation::AncestryInventoryEdit {
            edit: B4AncestryInventoryOperation::PruneRevealedHead {
                before_claim_digest: digest(0x11),
                before_control_root: digest(0x22),
                exact_digest: digest(0x33),
            },
            target: B4AncestryInventoryTarget::AssumptionSourceInventoryHead,
        }
    } else if index.is_multiple_of(2) {
        B4NegativeMutation::ByteEdit {
            edit: B4ByteOperation::Replace {
                before_hex: "00".to_owned(),
                replacement_hex: "01".to_owned(),
                offset: 0,
            },
            target: B4ByteTarget::Statement,
        }
    } else {
        B4NegativeMutation::SequenceEdit {
            edit: B4SequenceOperation::Omit {
                before_element_id: "proof-chunk-00".to_owned(),
                before_element_sha256: digest(2),
                index: 0,
            },
            target: B4SequenceTarget::ProofChunks,
        }
    }
}

#[allow(clippy::too_many_lines)]
fn expanded_registry(plan: &Eip0045B4NegativePlanV1, plan_source: &[u8]) -> B4CandidateCorpus {
    let root = "reproduction/schema/b4-corpus-v1.candidate";
    let mut corpus = B4CandidateCorpus::from_canonical_jcs(include_bytes!(
        "../schema/b4-corpus-v1.candidate.json"
    ))
    .unwrap();
    corpus.stage = B4RegistryStage::Expanded;
    corpus.bindings.reference_statement_bundle = B4StatementBinding {
        contract_id: digest(8),
        manifest: bound(
            format!("{root}/bindings/statement-manifest.json"),
            B4ArtifactEncoding::Rfc8785Jcs,
        ),
        statement_sha256: digest(9),
        state: B4BindingState::Bound,
    };
    corpus.bindings.guest = B4GuestBinding {
        elf: bound(
            format!("{root}/bindings/guest.elf"),
            B4ArtifactEncoding::RawBytes,
        ),
        image_id: digest(10),
        state: B4BindingState::Bound,
    };
    corpus.bindings.source_lock = bound(
        format!("{root}/bindings/source-lock.json"),
        B4ArtifactEncoding::Rfc8785Jcs,
    );
    corpus.bindings.generator = bound(
        format!("{root}/bindings/generator.bin"),
        B4ArtifactEncoding::RawBytes,
    );
    corpus.bindings.rust_verifier = bound(
        format!("{root}/bindings/rust-verifier.bin"),
        B4ArtifactEncoding::RawBytes,
    );
    corpus.bindings.jvm_verifier = bound(
        format!("{root}/bindings/jvm-verifier.bin"),
        B4ArtifactEncoding::RawBytes,
    );
    corpus
        .bind_canonical_negative_plan_source(
            format!("{root}/bindings/negative-plan.json"),
            plan_source,
        )
        .unwrap();
    corpus.bindings.subject_catalog = bound(
        format!("{root}/bindings/subject-catalog.json"),
        B4ArtifactEncoding::Rfc8785Jcs,
    );
    corpus.bindings.terminal_fixture_catalog = bound(
        format!("{root}/bindings/terminal-fixture-catalog.json"),
        B4ArtifactEncoding::Rfc8785Jcs,
    );
    for case in &mut corpus.positive_cases {
        case.artifacts = positive_artifacts(case);
    }
    corpus.negative_cases = plan
        .groups
        .iter()
        .flat_map(|group| {
            group
                .executions
                .iter()
                .map(move |execution| (group, execution))
        })
        .enumerate()
        .map(|(index, (group, execution))| B4NegativeCase {
            execution_id: execution.execution_id.clone(),
            base_selector_id: execution.base_selector_id.clone(),
            materialization_domain: execution.materialization_domain,
            materialization: if negative_group_requires_fixture_selection(&group.case_id) {
                B4NegativeMaterialization::FixtureSelection {
                    fixture_id: execution.base_selector_id.clone(),
                }
            } else {
                B4NegativeMaterialization::Mutation {
                    mutation: synthetic_mutation(index, &execution.execution_id),
                }
            },
        })
        .collect();
    corpus
        .validate_expanded_against_canonical_plan_source(plan_source)
        .unwrap();
    corpus
}

fn materialization_identity(
    plan: &Eip0045B4NegativePlanV1,
    plan_source: &[u8],
) -> Eip0045B4MaterializationIdentityV1 {
    let execution = &plan.groups[0].executions[0];
    let identity = Eip0045B4MaterializationIdentityV1 {
        format: B4_MATERIALIZATION_IDENTITY_FORMAT.to_owned(),
        format_version: B4_MATERIALIZATION_IDENTITY_FORMAT_VERSION,
        base_selector_id: execution.base_selector_id.clone(),
        base_byte_length: 1,
        base_sha256: digest(1),
        execution_id: execution.execution_id.clone(),
        materialization_domain: execution.materialization_domain,
        materialization_recipe_byte_length: 1,
        materialization_recipe_sha256: digest(2),
        negative_plan_byte_length: plan_source.len() as u64,
        negative_plan_sha256: sha256_hex(plan_source),
        output_byte_length: 1,
        output_sha256: digest(3),
    };
    identity.validate().unwrap();
    identity
}

fn validation_result(
    plan: &Eip0045B4NegativePlanV1,
    plan_source: &[u8],
    identity: &Eip0045B4MaterializationIdentityV1,
) -> Eip0045B4ValidationResultV1 {
    let execution = &plan.groups[0].executions[0];
    let identity_source = identity.to_canonical_jcs().unwrap();
    let result = Eip0045B4ValidationResultV1 {
        format: B4_VALIDATION_RESULT_FORMAT.to_owned(),
        format_version: B4_VALIDATION_RESULT_FORMAT_VERSION,
        execution_id: execution.execution_id.clone(),
        implementation: B4ValidatorImplementation::RustReference,
        materialization_identity_byte_length: identity_source.len() as u64,
        materialization_identity_sha256: sha256_hex(&identity_source),
        materialization_domain: execution.materialization_domain,
        negative_plan_byte_length: plan_source.len() as u64,
        negative_plan_sha256: sha256_hex(plan_source),
        qa_result_code: execution.qa_result_code,
        rejection: B4ObservedRejectionV1 {
            class: "receipt-claim-mismatch".to_owned(),
            stage: "expected-claim-binding".to_owned(),
            verdict: B4ValidationVerdict::Reject,
        },
        validator_artifact: B4ValidatorArtifactIdentityV1::from_bytes(b"validator").unwrap(),
        validation_surface: execution.execution_surface,
    };
    result.validate().unwrap();
    result
}

const REAL_REPLAY_EXECUTION_ID: &str = "statement-field-byte-sweep--profile-id";

#[derive(Debug)]
struct RealReplayFixture {
    base: Vec<u8>,
    identity_source: Vec<u8>,
    output: Vec<u8>,
    plan_source: Vec<u8>,
    registry_row: B4NegativeCase,
    rejection: B4ObservedRejectionV1,
    validator_artifact: B4ValidatorArtifactIdentityV1,
}

impl RealReplayFixture {
    fn adapter(&self) -> B4ByteEditReplayAdapterV1<'_> {
        B4ByteEditReplayAdapterV1 {
            materialization_domain: self.registry_row.materialization_domain,
            base: &self.base,
            output: &self.output,
        }
    }

    fn result(&self) -> Eip0045B4ValidationResultV1 {
        let adapter = self.adapter();
        let replay = B4ValidationReplayContextV1 {
            materialization_identity_source: &self.identity_source,
            registry_row: &self.registry_row,
            adapter: &adapter,
        };
        create_b4_validation_result(
            &self.plan_source,
            &replay,
            B4ValidatorImplementation::RustReference,
            self.validator_artifact.clone(),
            self.rejection.clone(),
        )
        .unwrap()
    }
}

fn real_replay_fixture() -> RealReplayFixture {
    let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
    let execution = plan
        .groups
        .iter()
        .flat_map(|group| &group.executions)
        .find(|execution| execution.execution_id == REAL_REPLAY_EXECUTION_ID)
        .unwrap()
        .clone();
    let plan_source = plan.to_canonical_jcs().unwrap();
    let base = b"abcdef".to_vec();
    let mutation = B4NegativeMutation::ByteEdit {
        edit: B4ByteOperation::Replace {
            before_hex: "63".to_owned(),
            replacement_hex: "ff".to_owned(),
            offset: 2,
        },
        target: B4ByteTarget::Statement,
    };
    let output = reconstruct_mutation(&base, &mutation).unwrap();
    let registry_row = B4NegativeCase {
        execution_id: execution.execution_id,
        base_selector_id: execution.base_selector_id,
        materialization_domain: execution.materialization_domain,
        materialization: B4NegativeMaterialization::Mutation { mutation },
    };
    let adapter = B4ByteEditReplayAdapterV1 {
        materialization_domain: registry_row.materialization_domain,
        base: &base,
        output: &output,
    };
    let identity_source =
        create_materialization_identity_with_adapter(&plan_source, &registry_row, &adapter)
            .unwrap()
            .to_canonical_jcs()
            .unwrap();
    RealReplayFixture {
        base,
        identity_source,
        output,
        plan_source,
        registry_row,
        rejection: B4ObservedRejectionV1 {
            class: "receipt-claim-mismatch".to_owned(),
            stage: "expected-claim-binding".to_owned(),
            verdict: B4ValidationVerdict::Reject,
        },
        validator_artifact: B4ValidatorArtifactIdentityV1::from_bytes(b"pinned-validator").unwrap(),
    }
}

#[allow(clippy::too_many_lines)]
fn fixture_values() -> Vec<(&'static str, Value)> {
    let (plan, plan_source) = canonical_plan();
    let identity = materialization_identity(&plan, &plan_source);
    let result = validation_result(&plan, &plan_source, &identity);
    let negative_index = Eip0045B4NegativeBindingIndexV1::from_plan(&plan).unwrap();
    let expanded = expanded_registry(&plan, &plan_source);
    vec![
        ("negative-plan", serde_json::to_value(&plan).unwrap()),
        (
            "expanded-corpus-registry",
            serde_json::to_value(expanded).unwrap(),
        ),
        (
            "sequence-subject",
            serde_json::to_value(sequence_subject()).unwrap(),
        ),
        (
            "subject-catalog",
            serde_json::to_value(subject_catalog(&plan_source)).unwrap(),
        ),
        (
            "terminal-fixture-catalog",
            serde_json::to_value(terminal_catalog()).unwrap(),
        ),
        (
            "negative-binding-index",
            serde_json::to_value(negative_index).unwrap(),
        ),
        (
            "abstract-tree",
            serde_json::to_value(Eip0045B4AbstractTreeV1::canonical_baseline().unwrap()).unwrap(),
        ),
        (
            "materialization-identity",
            serde_json::to_value(identity).unwrap(),
        ),
        ("validation-result", serde_json::to_value(result).unwrap()),
    ]
}

fn fixture_value(name: &str) -> Value {
    fixture_values()
        .into_iter()
        .find_map(|(candidate, value)| (candidate == name).then_some(value))
        .unwrap()
}

#[test]
fn all_nine_schemas_compile_are_closed_and_use_only_internal_refs() {
    for (name, expected_id, source) in SCHEMAS {
        let schema = crate::canonical::parse_json_strict(source.as_bytes()).unwrap();
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(schema["$id"], expected_id, "{name} schema ID drift");
        assert_eq!(schema["type"], "object", "{name} root type drift");
        assert_eq!(
            schema["additionalProperties"],
            Value::Bool(false),
            "{name} root is not closed"
        );
        assert_internal_refs(&schema);
        compile_schema(source);
    }
}

#[test]
fn observation_and_result_schemas_share_the_exact_dispatch_boundary() {
    let observation = crate::canonical::parse_json_strict(
        include_str!("../finalizer-schema/b4-negative-observation-v1.schema.json").as_bytes(),
    )
    .unwrap();
    let result = crate::canonical::parse_json_strict(
        include_str!("../finalizer-schema/b4-validation-result-v1.schema.json").as_bytes(),
    )
    .unwrap();
    assert_eq!(
        observation["$defs"]["DispatchBoundary"], result["$defs"]["DispatchBoundary"],
        "observation/result rejection dispatch vocabularies drift"
    );
}

#[test]
fn current_rust_fixtures_validate_against_all_nine_schemas() {
    let values = fixture_values();
    assert_eq!(values.len(), SCHEMAS.len());
    for ((schema_name, _, source), (fixture_name, value)) in SCHEMAS.iter().zip(values) {
        assert_eq!(*schema_name, fixture_name);
        assert_valid(source, &value, fixture_name);
    }
}

#[test]
fn schemas_reject_unknown_fields_enums_bounds_and_forbidden_sum_shapes() {
    let mut unknown = fixture_value("negative-plan");
    unknown["unexpected"] = json!(true);
    assert_invalid(
        schema_source("negative-plan"),
        &unknown,
        "unknown root field",
    );

    let mut nested_unknown = fixture_value("terminal-fixture-catalog");
    nested_unknown["fixtures"][0]["terminal"]["unexpected"] = json!(true);
    assert_invalid(
        schema_source("terminal-fixture-catalog"),
        &nested_unknown,
        "unknown nested field",
    );

    let mut unknown_enum = fixture_value("abstract-tree");
    unknown_enum["roles"][0] = json!("other-role");
    assert_invalid(
        schema_source("abstract-tree"),
        &unknown_enum,
        "unknown abstract role",
    );

    let mut underflow = fixture_value("materialization-identity");
    underflow["materializationRecipeByteLength"] = json!(0);
    assert_invalid(
        schema_source("materialization-identity"),
        &underflow,
        "materialization recipe lower bound",
    );

    let mut forbidden_sum_shape = fixture_value("negative-binding-index");
    forbidden_sum_shape["rows"][0]["materialization"]["fixtureId"] = json!("lift-po2-14");
    assert_invalid(
        schema_source("negative-binding-index"),
        &forbidden_sum_shape,
        "mixed materialization union shape",
    );

    let mut odd_hex = fixture_value("sequence-subject");
    odd_hex["elements"][0]["bytesHex"] = json!("0");
    assert_invalid(
        schema_source("sequence-subject"),
        &odd_hex,
        "odd-length sequence bytes",
    );

    let mut placeholder = fixture_value("validation-result");
    placeholder["rejection"]["stage"] = json!("unknown");
    assert_invalid(
        schema_source("validation-result"),
        &placeholder,
        "placeholder rejection stage",
    );
}

#[test]
fn semantic_counterexamples_remain_schema_valid_but_fail_their_parser_or_gate() {
    let (plan, plan_source) = canonical_plan();

    let mut wrong_digest = serde_json::to_value(sequence_subject()).unwrap();
    wrong_digest["elements"][0]["sha256"] = json!(digest(0));
    assert_valid(
        schema_source("sequence-subject"),
        &wrong_digest,
        "digest-shaped sequence subject",
    );
    let wrong_digest_source = canonical_json_bytes(&wrong_digest).unwrap();
    assert!(Eip0045B4SequenceSubjectV1::from_canonical_jcs(&wrong_digest_source).is_err());

    let mut reordered_tree =
        serde_json::to_value(Eip0045B4AbstractTreeV1::canonical_baseline().unwrap()).unwrap();
    reordered_tree["roles"].as_array_mut().unwrap().swap(0, 1);
    assert_valid(
        schema_source("abstract-tree"),
        &reordered_tree,
        "lexically valid reordered abstract tree",
    );
    let reordered_tree_source = canonical_json_bytes(&reordered_tree).unwrap();
    assert!(Eip0045B4AbstractTreeV1::from_canonical_jcs(&reordered_tree_source).is_err());

    let mut reordered_plan = serde_json::to_value(&plan).unwrap();
    reordered_plan["groups"].as_array_mut().unwrap().swap(0, 1);
    assert_valid(
        schema_source("negative-plan"),
        &reordered_plan,
        "shape-valid reordered plan",
    );
    let reordered_plan_source = canonical_json_bytes(&reordered_plan).unwrap();
    assert!(Eip0045B4NegativePlanV1::from_canonical_jcs(&reordered_plan_source).is_err());

    let mut reordered_index = Eip0045B4NegativeBindingIndexV1::from_plan(&plan).unwrap();
    reordered_index.rows.swap(0, 1);
    let reordered_index_value = serde_json::to_value(&reordered_index).unwrap();
    assert_valid(
        schema_source("negative-binding-index"),
        &reordered_index_value,
        "shape-valid reordered negative index",
    );
    let reordered_index_source = canonical_json_bytes(&reordered_index_value).unwrap();
    let parsed =
        Eip0045B4NegativeBindingIndexV1::from_canonical_jcs(&reordered_index_source).unwrap();
    assert!(parsed.validate_against_plan(&plan).is_err());

    let mut reordered_registry = expanded_registry(&plan, &plan_source);
    reordered_registry.negative_cases.swap(0, 1);
    let reordered_registry_value = serde_json::to_value(&reordered_registry).unwrap();
    assert_valid(
        schema_source("expanded-corpus-registry"),
        &reordered_registry_value,
        "shape-valid reordered expanded registry",
    );
    let reordered_registry_source = canonical_json_bytes(&reordered_registry_value).unwrap();
    let parsed_registry =
        B4CandidateCorpus::from_canonical_jcs(&reordered_registry_source).unwrap_err();
    assert!(
        format!("{parsed_registry:#}").contains("negative execution ID/order drift"),
        "unexpected expanded-registry failure: {parsed_registry:#}"
    );
}

#[test]
fn subject_and_terminal_catalog_semantics_remain_parser_owned() {
    let (_, plan_source) = canonical_plan();

    let mut reordered_subjects = serde_json::to_value(subject_catalog(&plan_source)).unwrap();
    reordered_subjects["subjects"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    assert_valid(
        schema_source("subject-catalog"),
        &reordered_subjects,
        "shape-valid reordered subject catalog",
    );
    let source = canonical_json_bytes(&reordered_subjects).unwrap();
    let error = Eip0045B4SubjectCatalogV1::from_canonical_jcs(&source).unwrap_err();
    assert!(
        format!("{error:#}").contains("subject ID/order drift"),
        "subject ordering rejected at the wrong boundary: {error:#}"
    );

    let mut provenance_drift = serde_json::to_value(subject_catalog(&plan_source)).unwrap();
    provenance_drift["subjects"][1]["provenance"]["planSha256"] = json!(digest(999));
    assert_valid(
        schema_source("subject-catalog"),
        &provenance_drift,
        "shape-valid subject provenance drift",
    );
    let source = canonical_json_bytes(&provenance_drift).unwrap();
    let error = Eip0045B4SubjectCatalogV1::from_canonical_jcs(&source).unwrap_err();
    assert!(
        format!("{error:#}").contains("bind different plans"),
        "subject provenance rejected at the wrong boundary: {error:#}"
    );

    let mut fixed_root_drift = serde_json::to_value(terminal_catalog()).unwrap();
    let replacement_root = digest(777);
    fixed_root_drift["innerControlRoot"] = json!(replacement_root);
    for fixture in fixed_root_drift["fixtures"].as_array_mut().unwrap() {
        fixture["terminal"]["controlRoot"] = json!(replacement_root);
    }
    assert_invalid(
        schema_source("terminal-fixture-catalog"),
        &fixed_root_drift,
        "fixed terminal root drift",
    );
    let source = canonical_json_bytes(&fixed_root_drift).unwrap();
    let error = Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(&source).unwrap_err();
    assert!(
        format!("{error:#}").contains("inner control root drift"),
        "fixed terminal root rejected at the wrong boundary: {error:#}"
    );

    let mut terminal_link_drift = serde_json::to_value(terminal_catalog()).unwrap();
    terminal_link_drift["fixtures"][0]["terminal"]["controlId"] = json!(digest(778));
    assert_valid(
        schema_source("terminal-fixture-catalog"),
        &terminal_link_drift,
        "shape-valid terminal stock/root-link drift",
    );
    let source = canonical_json_bytes(&terminal_link_drift).unwrap();
    let error = Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(&source).unwrap_err();
    assert!(
        format!("{error:#}").contains("does not match its exact stock row/root"),
        "terminal stock/root link rejected at the wrong boundary: {error:#}"
    );

    let mut union_link_drift = serde_json::to_value(terminal_catalog()).unwrap();
    let union = union_link_drift["fixtures"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|fixture| fixture["fixtureId"] == "union")
        .unwrap();
    union["application"]["left"]["witnessFixtureIds"] = json!(["allowed-terminal-non-ok"]);
    assert_valid(
        schema_source("terminal-fixture-catalog"),
        &union_link_drift,
        "shape-valid terminal union-link drift",
    );
    let source = canonical_json_bytes(&union_link_drift).unwrap();
    let error = Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(&source).unwrap_err();
    assert!(
        format!("{error:#}").contains("union witness fixture IDs"),
        "terminal union link rejected at the wrong boundary: {error:#}"
    );
}

#[test]
fn materialization_and_result_drift_remain_real_replay_gate_obligations() {
    let fixture = real_replay_fixture();
    let identity =
        Eip0045B4MaterializationIdentityV1::from_canonical_jcs(&fixture.identity_source).unwrap();
    let mut coordinated_identity_drift = serde_json::to_value(identity).unwrap();
    coordinated_identity_drift["baseByteLength"] = json!(fixture.base.len() + 1);
    coordinated_identity_drift["baseSha256"] = json!(sha256_hex(b"coordinated-base-drift"));
    coordinated_identity_drift["outputByteLength"] = json!(fixture.output.len() + 1);
    coordinated_identity_drift["outputSha256"] = json!(sha256_hex(b"coordinated-output-drift"));
    assert_valid(
        schema_source("materialization-identity"),
        &coordinated_identity_drift,
        "shape-valid coordinated materialization drift",
    );
    let identity_source = canonical_json_bytes(&coordinated_identity_drift).unwrap();
    let identity =
        Eip0045B4MaterializationIdentityV1::from_canonical_jcs(&identity_source).unwrap();
    let adapter = fixture.adapter();
    let error = verify_materialization_identity_with_adapter(
        &identity,
        &fixture.plan_source,
        &fixture.registry_row,
        &adapter,
    )
    .unwrap_err();
    assert!(
        format!("{error:#}").contains("differs from independently replayed bindings"),
        "coordinated materialization drift rejected at the wrong boundary: {error:#}"
    );

    let result = fixture.result();
    let baseline_source = result.to_canonical_jcs().unwrap();
    let adapter = fixture.adapter();
    let replay = B4ValidationReplayContextV1 {
        materialization_identity_source: &fixture.identity_source,
        registry_row: &fixture.registry_row,
        adapter: &adapter,
    };
    let expectation = B4ValidationResultExpectationV1 {
        execution_id: REAL_REPLAY_EXECUTION_ID,
        implementation: B4ValidatorImplementation::RustReference,
        validator_artifact: &fixture.validator_artifact,
        rejection: &fixture.rejection,
    };
    verify_b4_validation_result(
        &baseline_source,
        &fixture.plan_source,
        &replay,
        &expectation,
    )
    .unwrap();

    let mut plan_drift = serde_json::to_value(&result).unwrap();
    plan_drift["negativePlanByteLength"] = json!(fixture.plan_source.len() + 1);
    plan_drift["negativePlanSha256"] = json!(sha256_hex(b"coordinated-plan-drift"));
    let mut identity_drift = serde_json::to_value(&result).unwrap();
    identity_drift["materializationIdentityByteLength"] = json!(fixture.identity_source.len() + 1);
    identity_drift["materializationIdentitySha256"] =
        json!(sha256_hex(b"coordinated-identity-drift"));
    let mut observation_drift = serde_json::to_value(result).unwrap();
    observation_drift["rejection"]["class"] = json!("alternate-claim-digest-mismatch");
    assert_invalid(
        schema_source("validation-result"),
        &observation_drift,
        "result observation outside the handler vocabulary",
    );

    for (label, value, expected_error) in [
        (
            "shape-valid result plan drift",
            plan_drift,
            "differs from exact independently rebuilt bindings",
        ),
        (
            "shape-valid result identity drift",
            identity_drift,
            "differs from exact independently rebuilt bindings",
        ),
    ] {
        assert_valid(schema_source("validation-result"), &value, label);
        let source = canonical_json_bytes(&value).unwrap();
        Eip0045B4ValidationResultV1::from_canonical_jcs(&source).unwrap();
        let error =
            verify_b4_validation_result(&source, &fixture.plan_source, &replay, &expectation)
                .unwrap_err();
        assert!(
            format!("{error:#}").contains(expected_error),
            "{label} rejected at the wrong boundary: {error:#}"
        );
    }
}

fn mutation_schema_instance(schema_name: &str, mutation: &Value) -> Value {
    let mut value = fixture_value(schema_name);
    let materialization = json!({
        "materializationKind": "mutation",
        "mutation": mutation,
    });
    match schema_name {
        "expanded-corpus-registry" => {
            value["negativeCases"][0]["materialization"] = materialization;
        }
        "negative-binding-index" => {
            value["rows"][0]["materialization"] = materialization;
        }
        _ => unreachable!("mutation fixture requested for an unrelated schema"),
    }
    value
}

#[test]
fn byte_target_schemas_and_rust_parser_share_the_exhaustive_closed_vocabulary() {
    let unit_target_kinds = [
        "application-payload",
        "ancestry",
        "candidate-registry-source",
        "positive-calibration",
        "positive-metadata",
        "profile-manifest",
        "profile-id",
        "program-id",
        "receipt-oracle",
        "raw-seal",
        "statement",
        "subject-catalog-entry",
        "terminal-fixture-catalog-entry",
        "terminal-metadata-record",
        "terminal-policy-probe",
    ];
    let mut targets = unit_target_kinds
        .into_iter()
        .map(|target_kind| json!({"targetKind": target_kind}))
        .collect::<Vec<_>>();
    targets.extend(
        [
            "algorithm",
            "algorithm-artifact-preimage",
            "constants",
            "binary-data-artifact-preimage",
            "profile-id",
            "profile-id-preimage",
        ]
        .into_iter()
        .map(|artifact| json!({"artifact": artifact, "targetKind": "profile-artifact"})),
    );

    for target in targets {
        let mutation = json!({
            "edit": {
                "insertedHex": "00",
                "offset": 0,
                "operation": "insert"
            },
            "family": "byte-edit",
            "target": target
        });
        for schema_name in ["expanded-corpus-registry", "negative-binding-index"] {
            let instance = mutation_schema_instance(schema_name, &mutation);
            assert_valid(
                schema_source(schema_name),
                &instance,
                &format!(
                    "{schema_name} byte target {}",
                    mutation["target"]["targetKind"]
                ),
            );
        }
        let parsed = serde_json::from_value::<B4NegativeMutation>(mutation.clone())
            .expect("schema-approved byte target must parse in Rust");
        assert_eq!(serde_json::to_value(parsed).unwrap(), mutation);
    }

    for invalid_target in [
        json!({"targetKind": "unknown-terminal-target"}),
        json!({"targetKind": "terminal-metadata-record", "unexpected": true}),
    ] {
        let mutation = json!({
            "edit": {
                "insertedHex": "00",
                "offset": 0,
                "operation": "insert"
            },
            "family": "byte-edit",
            "target": invalid_target
        });
        for schema_name in ["expanded-corpus-registry", "negative-binding-index"] {
            let instance = mutation_schema_instance(schema_name, &mutation);
            assert_invalid(
                schema_source(schema_name),
                &instance,
                &format!("{schema_name} unknown byte target"),
            );
        }
        assert!(serde_json::from_value::<B4NegativeMutation>(mutation).is_err());
    }
}

#[test]
fn ancestry_inventory_mutation_schema_and_serde_share_one_closed_shape() {
    let mutation = json!({
        "edit": {
            "beforeClaimDigest": digest(0x11),
            "beforeControlRoot": digest(0x22),
            "exactDigest": digest(0x33),
            "operation": "prune-revealed-head"
        },
        "family": "ancestry-inventory-edit",
        "target": {
            "targetKind": "assumption-source-inventory-head"
        }
    });
    for schema_name in ["expanded-corpus-registry", "negative-binding-index"] {
        assert_valid(
            schema_source(schema_name),
            &mutation_schema_instance(schema_name, &mutation),
            &format!("{schema_name} ancestry-inventory edit"),
        );

        for pointer in ["/edit", "/target"] {
            let mut invalid = mutation.clone();
            invalid
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("unexpected".to_owned(), json!(true));
            assert_invalid(
                schema_source(schema_name),
                &mutation_schema_instance(schema_name, &invalid),
                &format!("{schema_name} closed ancestry-inventory {pointer}"),
            );
        }
    }

    let parsed = serde_json::from_value::<B4NegativeMutation>(mutation.clone()).unwrap();
    parsed.validate().unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), mutation);
}

#[test]
fn alternate_root_assumption_substitution_schema_and_serde_share_one_closed_unit_shape() {
    let mutation = json!({
        "family": "alternate-root-assumption-substitution"
    });
    for schema_name in ["expanded-corpus-registry", "negative-binding-index"] {
        assert_valid(
            schema_source(schema_name),
            &mutation_schema_instance(schema_name, &mutation),
            &format!("{schema_name} alternate-root assumption substitution"),
        );

        for unexpected_field in [
            "alternateRoot",
            "controlId",
            "fixtureId",
            "mode",
            "po2",
            "workload",
        ] {
            let mut invalid = mutation.clone();
            invalid[unexpected_field] = json!("caller-selected");
            assert_invalid(
                schema_source(schema_name),
                &mutation_schema_instance(schema_name, &invalid),
                &format!(
                    "{schema_name} closed alternate-root assumption substitution {unexpected_field}"
                ),
            );
        }
    }

    let parsed = serde_json::from_value::<B4NegativeMutation>(mutation.clone())
        .expect("schema-approved alternate-root assumption substitution must parse in Rust");
    parsed.validate().unwrap();
    assert!(matches!(
        parsed,
        B4NegativeMutation::AlternateRootAssumptionSubstitution {}
    ));
    assert_eq!(
        serde_json::to_value(B4NegativeMutation::AlternateRootAssumptionSubstitution {}).unwrap(),
        mutation
    );

    for unexpected_field in [
        "alternateRoot",
        "controlId",
        "fixtureId",
        "mode",
        "po2",
        "workload",
    ] {
        let mut invalid = mutation.clone();
        invalid[unexpected_field] = json!("caller-selected");
        assert!(
            serde_json::from_value::<B4NegativeMutation>(invalid).is_err(),
            "Rust parser accepted alternate-root selector field {unexpected_field}"
        );
    }
}

#[test]
fn ancestry_witness_substitution_schema_and_serde_share_one_closed_shape() {
    let recipes = [
        "reuse-case9-assumption-at-terminal-join-step0",
        "reuse-case9-assumption-at-terminal-resolve-step0",
        "reuse-case9-final-resolve-at-resolve-then-join-step2",
        "alternate-statement-assumption-lift-for-terminal-resolve",
        "alternate-guest-lift-for-terminal-resolve",
        "alternate-statement-final-resolve-for-terminal-resolve",
        "alternate-statement-assumption-lift-for-resolve-then-join",
        "alternate-guest-lift-for-resolve-then-join",
        "alternate-statement-final-join-for-resolve-then-join",
        "reuse-case9-assumption-with-empty-inventory",
        "duplicate-assumption-lift-with-duplicated-inventory",
    ];
    for recipe in recipes {
        let mutation = json!({
            "family": "ancestry-witness-substitution",
            "recipe": recipe
        });
        for schema_name in ["expanded-corpus-registry", "negative-binding-index"] {
            assert_valid(
                schema_source(schema_name),
                &mutation_schema_instance(schema_name, &mutation),
                &format!("{schema_name} ancestry-witness substitution {recipe}"),
            );
        }
        let parsed = serde_json::from_value::<B4NegativeMutation>(mutation.clone())
            .expect("schema-approved ancestry substitution must parse in Rust");
        assert_eq!(serde_json::to_value(parsed).unwrap(), mutation);
    }

    for invalid in [
        json!({
            "family": "ancestry-witness-substitution",
            "recipe": "unknown-recipe"
        }),
        json!({
            "family": "ancestry-witness-substitution",
            "recipe": recipes[0],
            "witnessId": "case9-assumption-lift"
        }),
    ] {
        for schema_name in ["expanded-corpus-registry", "negative-binding-index"] {
            assert_invalid(
                schema_source(schema_name),
                &mutation_schema_instance(schema_name, &invalid),
                &format!("{schema_name} rejects non-closed ancestry substitution"),
            );
        }
        assert!(serde_json::from_value::<B4NegativeMutation>(invalid).is_err());
    }
}

#[allow(clippy::too_many_lines)]
#[test]
fn mutation_integer_shapes_share_the_rfc8785_safe_boundary() {
    let replacement_element =
        B4SequenceSubjectElement::from_bytes("replacement", b"replacement").unwrap();
    let seeds = vec![
        (
            "delete offset",
            B4NegativeMutation::ByteEdit {
                edit: B4ByteOperation::Delete {
                    before_hex: "00".to_owned(),
                    offset: 0,
                },
                target: B4ByteTarget::Statement,
            },
            "/edit/offset",
            Some("byte deletion range end exceeds the RFC 8785 exact-integer bound"),
        ),
        (
            "insert offset",
            B4NegativeMutation::ByteEdit {
                edit: B4ByteOperation::Insert {
                    inserted_hex: "00".to_owned(),
                    offset: 0,
                },
                target: B4ByteTarget::Statement,
            },
            "/edit/offset",
            Some("byte insertion range end exceeds the RFC 8785 exact-integer bound"),
        ),
        (
            "replace offset",
            B4NegativeMutation::ByteEdit {
                edit: B4ByteOperation::Replace {
                    before_hex: "00".to_owned(),
                    replacement_hex: "01".to_owned(),
                    offset: 0,
                },
                target: B4ByteTarget::Statement,
            },
            "/edit/offset",
            Some("byte replacement range end exceeds the RFC 8785 exact-integer bound"),
        ),
        (
            "truncate new length",
            B4NegativeMutation::ByteEdit {
                edit: B4ByteOperation::Truncate {
                    before_hex: "00".to_owned(),
                    new_length: 0,
                    original_length: 1,
                },
                target: B4ByteTarget::Statement,
            },
            "/edit/newLength",
            Some("truncation does not shorten the target"),
        ),
        (
            "truncate original length",
            B4NegativeMutation::ByteEdit {
                edit: B4ByteOperation::Truncate {
                    before_hex: "00".to_owned(),
                    new_length: 0,
                    original_length: 1,
                },
                target: B4ByteTarget::Statement,
            },
            "/edit/originalLength",
            None,
        ),
        (
            "sequence insertion index",
            B4NegativeMutation::SequenceEdit {
                edit: B4SequenceOperation::Insert {
                    inserted_element: replacement_element.clone(),
                    index: 0,
                },
                target: B4SequenceTarget::ProofChunks,
            },
            "/edit/index",
            None,
        ),
        (
            "sequence move source index",
            B4NegativeMutation::SequenceEdit {
                edit: B4SequenceOperation::Move {
                    before_element_id: "proof-chunk-00".to_owned(),
                    before_element_sha256: digest(51),
                    from_index: 0,
                    to_index: 1,
                },
                target: B4SequenceTarget::ProofChunks,
            },
            "/edit/fromIndex",
            None,
        ),
        (
            "sequence move destination index",
            B4NegativeMutation::SequenceEdit {
                edit: B4SequenceOperation::Move {
                    before_element_id: "proof-chunk-00".to_owned(),
                    before_element_sha256: digest(52),
                    from_index: 0,
                    to_index: 1,
                },
                target: B4SequenceTarget::ProofChunks,
            },
            "/edit/toIndex",
            None,
        ),
        (
            "sequence omission index",
            B4NegativeMutation::SequenceEdit {
                edit: B4SequenceOperation::Omit {
                    before_element_id: "proof-chunk-00".to_owned(),
                    before_element_sha256: digest(53),
                    index: 0,
                },
                target: B4SequenceTarget::ProofChunks,
            },
            "/edit/index",
            None,
        ),
        (
            "sequence replacement index",
            B4NegativeMutation::SequenceEdit {
                edit: B4SequenceOperation::Replace {
                    before_element_id: "proof-chunk-00".to_owned(),
                    before_element_sha256: digest(54),
                    index: 0,
                    replacement_element,
                },
                target: B4SequenceTarget::ProofChunks,
            },
            "/edit/index",
            None,
        ),
        (
            "boundary-shift byte count",
            B4NegativeMutation::SequenceEdit {
                edit: B4SequenceOperation::ShiftBoundary {
                    byte_count: 1,
                    direction: B4BoundaryShiftDirection::LeftToRight,
                    left_chunk_index: 0,
                },
                target: B4SequenceTarget::ProofChunks,
            },
            "/edit/byteCount",
            None,
        ),
        (
            "boundary-shift left index",
            B4NegativeMutation::SequenceEdit {
                edit: B4SequenceOperation::ShiftBoundary {
                    byte_count: 1,
                    direction: B4BoundaryShiftDirection::RightToLeft,
                    left_chunk_index: 0,
                },
                target: B4SequenceTarget::ProofChunks,
            },
            "/edit/leftChunkIndex",
            Some("proof-chunk right-neighbor index exceeds the RFC 8785 exact-integer bound"),
        ),
    ];
    let validators = [
        (
            "expanded-corpus-registry",
            compile_schema(schema_source("expanded-corpus-registry")),
        ),
        (
            "negative-binding-index",
            compile_schema(schema_source("negative-binding-index")),
        ),
    ];

    for (label, seed, pointer, semantic_boundary_error) in seeds {
        let mut at_boundary = serde_json::to_value(seed).unwrap();
        *at_boundary.pointer_mut(pointer).unwrap() = json!(B4_MAX_JCS_SAFE_INTEGER);
        let mut above_boundary = at_boundary.clone();
        *above_boundary.pointer_mut(pointer).unwrap() = json!(B4_MAX_JCS_SAFE_INTEGER + 1);

        for (schema_name, validator) in &validators {
            let at_boundary_instance = mutation_schema_instance(schema_name, &at_boundary);
            validator
                .validate(&at_boundary_instance)
                .unwrap_or_else(|error| {
                    panic!("{schema_name} rejects {label} at the RFC 8785 boundary: {error}")
                });
            let above_boundary_instance = mutation_schema_instance(schema_name, &above_boundary);
            assert!(
                validator.validate(&above_boundary_instance).is_err(),
                "{schema_name} accepts {label} above the RFC 8785 boundary"
            );
        }

        let at_boundary_mutation: B4NegativeMutation = serde_json::from_value(at_boundary).unwrap();
        match semantic_boundary_error {
            Some(expected_error) => {
                let error = at_boundary_mutation.validate().unwrap_err();
                assert!(
                    format!("{error:#}").contains(expected_error),
                    "{label} reached the wrong Rust semantic boundary: {error:#}"
                );
            }
            None => at_boundary_mutation.validate().unwrap(),
        }
        let above_boundary_mutation: B4NegativeMutation =
            serde_json::from_value(above_boundary).unwrap();
        let error = above_boundary_mutation.validate().unwrap_err();
        assert!(
            format!("{error:#}").contains("exceeds the RFC 8785 exact-integer bound"),
            "{label} above the safe boundary was rejected for the wrong reason: {error:#}"
        );
    }
}

#[test]
fn candidate_paths_share_the_schema_and_rust_portability_boundary() {
    const CANDIDATE_PREFIX: &str = "reproduction/schema/b4-corpus-v1.candidate/";

    let portable_240 = format!(
        "{CANDIDATE_PREFIX}{}",
        "a".repeat(240 - CANDIDATE_PREFIX.len())
    );
    assert_eq!(portable_240.len(), 240);
    let mut portable = fixture_value("expanded-corpus-registry");
    portable["bindings"]["generator"]["path"] = json!(portable_240);
    assert_valid(
        schema_source("expanded-corpus-registry"),
        &portable,
        "portable 240-byte candidate path",
    );
    let source = canonical_json_bytes(&portable).unwrap();
    B4CandidateCorpus::from_canonical_jcs(&source).unwrap();

    let overlong = format!(
        "{CANDIDATE_PREFIX}{}",
        "a".repeat(241 - CANDIDATE_PREFIX.len())
    );
    let invalid = [
        (
            "Reproduction/schema/b4-corpus-v1.candidate/input.bin".to_owned(),
            "portable lowercase ASCII subset",
        ),
        (
            format!("{CANDIDATE_PREFIX}con.txt"),
            "unsafe or non-portable",
        ),
        (
            format!("{CANDIDATE_PREFIX}prn.bin"),
            "unsafe or non-portable",
        ),
        (
            format!("{CANDIDATE_PREFIX}aux.json"),
            "unsafe or non-portable",
        ),
        (
            format!("{CANDIDATE_PREFIX}nul.dat"),
            "unsafe or non-portable",
        ),
        (
            format!("{CANDIDATE_PREFIX}com1.bin"),
            "unsafe or non-portable",
        ),
        (
            format!("{CANDIDATE_PREFIX}lpt9.log"),
            "unsafe or non-portable",
        ),
        (overlong, "portable bound"),
        (
            format!("{CANDIDATE_PREFIX}lock.json.bak"),
            "candidate registry references a final",
        ),
        (
            format!("{CANDIDATE_PREFIX}lock.json/child"),
            "candidate registry references a final",
        ),
    ];
    for (path, expected_error) in invalid {
        let mut value = fixture_value("expanded-corpus-registry");
        value["bindings"]["generator"]["path"] = json!(path);
        assert_invalid(
            schema_source("expanded-corpus-registry"),
            &value,
            "non-portable candidate path",
        );
        let source = canonical_json_bytes(&value).unwrap();
        let error = B4CandidateCorpus::from_canonical_jcs(&source).unwrap_err();
        assert!(
            format!("{error:#}").contains(expected_error),
            "candidate path rejected at the wrong Rust boundary: {error:#}"
        );
    }
}
