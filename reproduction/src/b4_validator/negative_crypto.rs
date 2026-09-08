// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Fail-closed contract for the pinned RISC Zero checkpoint patch.
//!
//! The reviewed patch is mechanically bounded to two upstream verifier files.
//! The executable dependency is bound to the reviewed fork commit 227229d.
//! This adapter requires stock/instrumented agreement on an authenticated
//! receipt mutation before projecting a checkpoint. Local test evidence does
//! not establish campaign authority or close the remaining handlers.

use core::fmt;

use risc0_zkp::verify::VerificationCheckpoint;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::{
    canonical::validate_canonical_json_source,
    constants::PROOF_BYTES,
    receipt_oracle_replay::{CompiledStockSuccinctReplayV1, compare_direct_seal_mutation},
};

const FROZEN_MANIFEST: &[u8] = include_bytes!("../../../profiles/risc0-v3-succinct/manifest.bin");
const CONTRACT_FILE: &[u8] =
    include_bytes!("../../instrumentation/risc0-zkp-8eb06ab/contract.json");
const MOD_PATCH: &[u8] = include_bytes!("../../instrumentation/risc0-zkp-8eb06ab/verify-mod.patch");
const FRI_PATCH: &[u8] = include_bytes!("../../instrumentation/risc0-zkp-8eb06ab/verify-fri.patch");

const CONTRACT_FORMAT: &str = "Eip0045Risc0CheckpointPatchContractV1";
const UPSTREAM_REPOSITORY: &str = "https://github.com/risc0/risc0";
const UPSTREAM_COMMIT: &str = "8eb06ab020a92dc5b63ba6dd0836d432aba6d890";
const UPSTREAM_PACKAGE: &str = "risc0-zkp";
const UPSTREAM_VERSION: &str = "3.0.4";
const REQUIRED_BUILD_AUTHORITY: &str = "reviewed published RISC Zero fork commit or accepted upstream equivalent pinned by Cargo.lock, followed by stock/instrumented agreement on the four exact mutated real seals";
const BUILD_REPOSITORY: &str = "https://github.com/a-shannon/risc0";
const BUILD_COMMIT: &str = "227229dc793c215c533cbc0e07911601974a4629";
const BUILD_PARENT: &str = "8eb06ab020a92dc5b63ba6dd0836d432aba6d890";
const BUILD_TREE: &str = "a4e8abc0fffa0eab25f66266150f998f581f1cac";
const BUILD_RAW_DIFF_SHA256: &str =
    "ab3208e886ed1a7d3c45248170c8eec1393986ab9ec8abb14a98711ae008423a";
const MOD_SOURCE_PATH: &str = "risc0/zkp/src/verify/mod.rs";
const FRI_SOURCE_PATH: &str = "risc0/zkp/src/verify/fri.rs";
const MOD_SOURCE_SHA256: &str = "003a67af89a7cfaeac9ff23808225cdc4d81c41d64956f20243574531b166c4f";
const FRI_SOURCE_SHA256: &str = "a601cfad5d01b294f934d697d6d832c57662e4778eac20ac549b1da53d11e377";
const MOD_PATCH_SHA256: &str = "832564d4f1ff9b8271638958f8cf424a3aca7b23c6e6739734983699c2b7c7d2";
const FRI_PATCH_SHA256: &str = "d9f6433623dbe6bf1423218e76dece0f2f6c83c0a24a73c17c464af93a6ee117";
const MOD_PATCHED_SHA256: &str = "66c01f904ea267e481d78a1d6fcdb1a3f8963d88f28b0ad75e9264e848d82f9c";
const FRI_PATCHED_SHA256: &str = "d191f76c984a005ab30d306ba8174a9b615e6b36fc53638282f26ace1b93534b";

const CHECKPOINTS: [(&str, &str, &str); 4] = [
    ("validity-check", MOD_SOURCE_PATH, "check != result"),
    (
        "fri-inner-query",
        FRI_SOURCE_PATH,
        "inner(pos) returns InvalidProof",
    ),
    ("fri-round-goal", FRI_SOURCE_PATH, "data_ext[quot] != goal"),
    ("fri-final-polynomial", FRI_SOURCE_PATH, "fx != goal"),
];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PatchContract {
    build_authority: BuildAuthority,
    checkpoints: Vec<CheckpointContract>,
    files: Vec<FileContract>,
    format: String,
    format_version: u8,
    upstream: UpstreamContract,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BuildAuthority {
    commit: String,
    parent: String,
    raw_diff_sha256: String,
    repository: String,
    required: String,
    review: ReviewContract,
    state: String,
    tree: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReviewContract {
    critical: u8,
    important: u8,
    minor: u8,
    state: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckpointContract {
    guard: String,
    kind: String,
    order: u8,
    source: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileContract {
    patch: String,
    patch_sha256: String,
    patched_sha256: String,
    source: String,
    source_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpstreamContract {
    commit: String,
    package: String,
    repository: String,
    version: String,
}

/// Stable site boundary admitted for one of the four depth probes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct B4CryptoBoundary {
    class: &'static str,
    stage: &'static str,
}

impl B4CryptoBoundary {
    pub(super) const fn class(self) -> &'static str {
        self.class
    }

    pub(super) const fn stage(self) -> &'static str {
        self.stage
    }
}

/// Private checkpoint-adapter failures which cannot become observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum B4CryptoAdapterError {
    ContextCardinality,
    ProfileContext,
    SubjectLength,
    ContractDrift,
    ReceiptOracleReplay,
    SealMutationComparison,
    MissingCheckpoint,
    MultipleCheckpoints,
    NonTargetCheckpoint,
}

impl fmt::Display for B4CryptoAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for B4CryptoAdapterError {}

/// Verify the authenticated original receipt, compare stock and instrumented
/// rejection of the exact mutated seal, and project one typed target site.
pub(super) fn reject_crypto_depth(
    subject: &[u8],
    contexts: &[&[u8]],
) -> Result<B4CryptoBoundary, B4CryptoAdapterError> {
    if contexts.len() != 2 {
        return Err(B4CryptoAdapterError::ContextCardinality);
    }
    if contexts[0] != FROZEN_MANIFEST {
        return Err(B4CryptoAdapterError::ProfileContext);
    }
    if subject.len() != PROOF_BYTES {
        return Err(B4CryptoAdapterError::SubjectLength);
    }
    validate_patch_contract()?;
    let replay = CompiledStockSuccinctReplayV1::from_compiled_profile()
        .map_err(|_| B4CryptoAdapterError::ReceiptOracleReplay)?;
    let verified = replay
        .verify_direct_oracle(contexts[1])
        .map_err(|_| B4CryptoAdapterError::ReceiptOracleReplay)?;
    let trace = compare_direct_seal_mutation(&verified, subject)
        .map_err(|_| B4CryptoAdapterError::SealMutationComparison)?;
    project_checkpoint_trace(trace.checkpoints())
}

fn project_checkpoint_trace(
    checkpoints: &[VerificationCheckpoint],
) -> Result<B4CryptoBoundary, B4CryptoAdapterError> {
    let [checkpoint] = checkpoints else {
        return Err(if checkpoints.is_empty() {
            B4CryptoAdapterError::MissingCheckpoint
        } else {
            B4CryptoAdapterError::MultipleCheckpoints
        });
    };
    let stage = match checkpoint {
        VerificationCheckpoint::ValidityCheck => "risc0-validity-check",
        VerificationCheckpoint::FriRoundGoal { query: 0, round: 1 } => {
            "risc0-fri-round-two-query-zero"
        }
        VerificationCheckpoint::FriFinalPolynomial { query: 0 } => {
            "risc0-fri-final-polynomial-query-zero"
        }
        VerificationCheckpoint::FriInnerQuery { query: 49 } => "risc0-fri-inner-query-forty-nine",
        _ => return Err(B4CryptoAdapterError::NonTargetCheckpoint),
    };
    Ok(B4CryptoBoundary {
        class: "risc0-proof-invalid",
        stage,
    })
}

fn validate_patch_contract() -> Result<(), B4CryptoAdapterError> {
    let contract_source = CONTRACT_FILE
        .strip_suffix(b"\n")
        .ok_or(B4CryptoAdapterError::ContractDrift)?;
    let value = validate_canonical_json_source(contract_source)
        .map_err(|_| B4CryptoAdapterError::ContractDrift)?;
    let contract: PatchContract =
        serde_json::from_value(value).map_err(|_| B4CryptoAdapterError::ContractDrift)?;

    if contract.format != CONTRACT_FORMAT
        || contract.format_version != 1
        || contract.upstream.repository != UPSTREAM_REPOSITORY
        || contract.upstream.commit != UPSTREAM_COMMIT
        || contract.upstream.package != UPSTREAM_PACKAGE
        || contract.upstream.version != UPSTREAM_VERSION
        || contract.build_authority.commit != BUILD_COMMIT
        || contract.build_authority.parent != BUILD_PARENT
        || contract.build_authority.raw_diff_sha256 != BUILD_RAW_DIFF_SHA256
        || contract.build_authority.repository != BUILD_REPOSITORY
        || contract.build_authority.state != "published-reviewed-pinned"
        || contract.build_authority.tree != BUILD_TREE
        || contract.build_authority.required != REQUIRED_BUILD_AUTHORITY
        || contract.build_authority.review.state != "pass"
        || contract.build_authority.review.critical != 0
        || contract.build_authority.review.important != 0
        || contract.build_authority.review.minor != 0
        || contract.files.len() != 2
        || contract.checkpoints.len() != CHECKPOINTS.len()
    {
        return Err(B4CryptoAdapterError::ContractDrift);
    }

    let expected_files = [
        (
            "verify-mod.patch",
            MOD_PATCH_SHA256,
            MOD_PATCHED_SHA256,
            MOD_SOURCE_PATH,
            MOD_SOURCE_SHA256,
            MOD_PATCH,
        ),
        (
            "verify-fri.patch",
            FRI_PATCH_SHA256,
            FRI_PATCHED_SHA256,
            FRI_SOURCE_PATH,
            FRI_SOURCE_SHA256,
            FRI_PATCH,
        ),
    ];
    for (observed, expected) in contract.files.iter().zip(expected_files) {
        let (patch, patch_sha256, patched_sha256, source, source_sha256, patch_bytes) = expected;
        if observed.patch != patch
            || observed.patch_sha256 != patch_sha256
            || observed.patched_sha256 != patched_sha256
            || observed.source != source
            || observed.source_sha256 != source_sha256
            || sha256_hex(patch_bytes) != patch_sha256
        {
            return Err(B4CryptoAdapterError::ContractDrift);
        }
    }

    for (index, (observed, expected)) in contract.checkpoints.iter().zip(CHECKPOINTS).enumerate() {
        let (kind, source, guard) = expected;
        if usize::from(observed.order) != index
            || observed.kind != kind
            || observed.source != source
            || observed.guard != guard
        {
            return Err(B4CryptoAdapterError::ContractDrift);
        }
    }
    Ok(())
}

fn sha256_hex(source: &[u8]) -> String {
    hex::encode(Sha256::digest(source))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_contract_is_canonical_exact_and_published_reviewed_pinned() {
        validate_patch_contract().unwrap();
        let source = String::from_utf8(CONTRACT_FILE.to_vec()).unwrap();
        assert_eq!(source.matches('\n').count(), 1);
        assert!(source.ends_with('\n'));
        assert!(!source.contains(":\\"));
        assert!(!source.contains("file://"));
        assert!(source.contains("\"state\":\"published-reviewed-pinned\""));
        assert!(source.contains("227229dc793c215c533cbc0e07911601974a4629"));
        assert!(
            source.contains("ab3208e886ed1a7d3c45248170c8eec1393986ab9ec8abb14a98711ae008423a")
        );
    }

    #[test]
    fn four_target_sites_project_without_case_or_error_text_authority() {
        let expected = [
            (
                VerificationCheckpoint::ValidityCheck,
                "risc0-validity-check",
            ),
            (
                VerificationCheckpoint::FriRoundGoal { query: 0, round: 1 },
                "risc0-fri-round-two-query-zero",
            ),
            (
                VerificationCheckpoint::FriFinalPolynomial { query: 0 },
                "risc0-fri-final-polynomial-query-zero",
            ),
            (
                VerificationCheckpoint::FriInnerQuery { query: 49 },
                "risc0-fri-inner-query-forty-nine",
            ),
        ];
        for (checkpoint, stage) in expected {
            let boundary = project_checkpoint_trace(&[checkpoint]).unwrap();
            assert_eq!(boundary.class(), "risc0-proof-invalid");
            assert_eq!(boundary.stage(), stage);
        }
    }

    #[test]
    fn neighboring_generic_sites_and_non_singleton_traces_never_project() {
        for checkpoint in [
            VerificationCheckpoint::FriRoundGoal { query: 1, round: 1 },
            VerificationCheckpoint::FriRoundGoal { query: 0, round: 0 },
            VerificationCheckpoint::FriFinalPolynomial { query: 49 },
            VerificationCheckpoint::FriInnerQuery { query: 48 },
        ] {
            assert_eq!(
                project_checkpoint_trace(&[checkpoint]),
                Err(B4CryptoAdapterError::NonTargetCheckpoint)
            );
        }
        assert_eq!(
            project_checkpoint_trace(&[]),
            Err(B4CryptoAdapterError::MissingCheckpoint)
        );
        assert_eq!(
            project_checkpoint_trace(&[
                VerificationCheckpoint::ValidityCheck,
                VerificationCheckpoint::FriInnerQuery { query: 49 },
            ]),
            Err(B4CryptoAdapterError::MultipleCheckpoints)
        );
    }

    #[test]
    fn malformed_receipt_oracle_never_projects_a_crypto_boundary() {
        let subject = vec![0_u8; PROOF_BYTES];
        assert_eq!(
            reject_crypto_depth(&subject, &[FROZEN_MANIFEST, b"not-a-receipt-oracle"]),
            Err(B4CryptoAdapterError::ReceiptOracleReplay)
        );
    }

    #[test]
    fn patches_preserve_stock_wrapper_and_return_sites_without_text_matching() {
        let mod_patch = String::from_utf8(MOD_PATCH.to_vec()).unwrap();
        let fri_patch = String::from_utf8(FRI_PATCH.to_vec()).unwrap();
        assert!(
            mod_patch.contains("verify_with_checkpoints(circuit, suite, seal, check_code, |_| {})")
        );
        assert!(mod_patch.contains("return Err(VerificationError::InvalidProof);"));
        assert!(fri_patch.contains("return Err(VerificationError::InvalidProof);"));
        assert!(!mod_patch.contains("to_string()"));
        assert!(!fri_patch.contains("to_string()"));
        assert!(!mod_patch.contains("verification indicates proof is invalid"));
        assert!(!fri_patch.contains("verification indicates proof is invalid"));
    }
}

#[cfg(all(test, feature = "negative-materialization-set"))]
mod genuine_crypto_tests {
    use super::*;
    use crate::b4_c2_crypto::genuine_crypto_join::{assert_loader_single_fault_negatives, load_fixture};

    type Outcome = Result<B4CryptoBoundary, B4CryptoAdapterError>;
    const ROWS: [(usize, &str, &str); 4] = [
        (156, "crypto-early-check-value-mismatch--check-value", "risc0-validity-check"),
        (157, "crypto-middle-fri-round-two-mismatch--fri-query-00", "risc0-fri-round-two-query-zero"),
        (158, "crypto-late-final-opening-mismatch--fri-query-00", "risc0-fri-final-polynomial-query-zero"),
        (159, "crypto-final-expected-claim-mismatch--claim-query-49", "risc0-fri-inner-query-forty-nine"),
    ];

    fn exact_matrix(stock_positive: bool, positive: Outcome, rows: &[(usize, Outcome)]) -> bool {
        stock_positive
            && positive == Err(B4CryptoAdapterError::SealMutationComparison)
            && rows.len() == ROWS.len()
            && rows.iter().zip(ROWS).all(|((index, outcome), expected)| {
                *index == expected.0 && *outcome == Ok(B4CryptoBoundary {
                    class: "risc0-proof-invalid", stage: expected.2,
                })
            })
    }

    #[test]
    fn crypto_matrix_oracle_rejects_canned_missing_duplicate_and_wrong_boundaries() {
        let positive = Err(B4CryptoAdapterError::SealMutationComparison);
        let rows = ROWS.map(|(index, _, stage)| (index,
            Ok(B4CryptoBoundary { class: "risc0-proof-invalid", stage })));
        assert!(exact_matrix(true, positive, &rows)); // oracle truth table, not real proof evidence
        assert!(!exact_matrix(false, positive, &rows));
        assert!(!exact_matrix(true, rows[0].1, &rows));
        assert!(!exact_matrix(true, Err(B4CryptoAdapterError::MissingCheckpoint), &rows));
        assert!(!exact_matrix(true, positive, &rows[..3]));
        let mut duplicate = rows;
        duplicate[3] = duplicate[2];
        assert!(!exact_matrix(true, positive, &duplicate));
        for index in 0..4 {
            for wrong in [positive, Err(B4CryptoAdapterError::ReceiptOracleReplay),
                Ok(B4CryptoBoundary { class: "wrong", stage: ROWS[index].2 }),
                Ok(B4CryptoBoundary { class: "risc0-proof-invalid", stage: "wrong" })] {
                let mut mutated = rows;
                mutated[index].1 = wrong;
                assert!(!exact_matrix(true, positive, &mutated));
            }
        }
    }

    #[test]
    #[ignore = "requires EIP0045_B4_REAL_VECTOR_ROOT; reconstructs four genuine rows including two bounded FRI grinds"]
    fn genuine_crypto_c2_producer_consumer_matrix() {
        let root = std::path::PathBuf::from(std::env::var_os("EIP0045_B4_REAL_VECTOR_ROOT")
            .expect("explicit authenticated case-zero vector root"));
        let fixture = load_fixture(&root).unwrap();
        assert_eq!(fixture.manifest, FROZEN_MANIFEST);
        let replay = CompiledStockSuccinctReplayV1::from_compiled_profile().unwrap();
        let verified = replay.verify_direct_oracle(&fixture.oracle).unwrap();
        assert_eq!(verified.raw_seal_bytes(), fixture.raw);
        let contexts = [fixture.manifest.as_slice(), fixture.oracle.as_slice()];
        // An unchanged valid seal cannot yield InvalidProof agreement, so the
        // positive adapter control is precisely SealMutationComparison.
        let positive = reject_crypto_depth(&fixture.raw, &contexts);
        assert_eq!(positive, Err(B4CryptoAdapterError::SealMutationComparison));
        assert_eq!(reject_crypto_depth(&fixture.raw, &contexts[..1]),
            Err(B4CryptoAdapterError::ContextCardinality));
        assert_eq!(reject_crypto_depth(&fixture.raw, &[contexts[1], contexts[0]]),
            Err(B4CryptoAdapterError::ProfileContext));
        let mut manifest = fixture.manifest.clone();
        manifest[0] ^= 1;
        assert_eq!(reject_crypto_depth(&fixture.raw, &[&manifest, contexts[1]]),
            Err(B4CryptoAdapterError::ProfileContext));
        assert_eq!(reject_crypto_depth(&fixture.raw[..fixture.raw.len() - 1], &contexts),
            Err(B4CryptoAdapterError::SubjectLength));
        assert_eq!(reject_crypto_depth(&fixture.raw, &[contexts[0], b"invalid-oracle"]),
            Err(B4CryptoAdapterError::ReceiptOracleReplay));

        assert_loader_single_fault_negatives(&root).unwrap(); // copies only; no mutation authority or grind
        let reconstructed = fixture.reconstruct().unwrap(); // exactly one authority/grind invocation
        assert_eq!(reconstructed.len(), 4);
        let outcomes = reconstructed.iter().zip(ROWS).map(|(row, expected)| {
            assert_eq!(row.derived_registry_row.execution_id, expected.1);
            assert_eq!(row.base, fixture.raw);
            assert_eq!(row.subject.len(), fixture.raw.len());
            assert_eq!(row.subject.len() % 4, 0);
            assert_eq!(row.subject.chunks_exact(4).zip(fixture.raw.chunks_exact(4))
                .filter(|(left, right)| left != right).count(), 1);
            assert_eq!(row.contexts, vec![fixture.manifest.clone(), fixture.oracle.clone()]);
            let actual_contexts = row.contexts.iter().map(Vec::as_slice).collect::<Vec<_>>();
            (expected.0, reject_crypto_depth(&row.subject, &actual_contexts))
        }).collect::<Vec<_>>();
        assert!(exact_matrix(true, positive, &outcomes));
        // Counterfactual observations reuse the completed results, never grind again.
        let mut restored = outcomes.clone();
        restored[0].1 = positive;
        assert!(!exact_matrix(true, positive, &restored));
        let canned = outcomes.iter().map(|(index, _)| (*index, outcomes[0].1)).collect::<Vec<_>>();
        assert!(!exact_matrix(true, positive, &canned));
    }

    /// Local production-dispatch evidence, not a deserializable authority.
    /// The two FRI searches happen once in the genuine test. Retained bytes
    /// preserve that execution; replaying their hashes cannot prove minimality.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    mod production_dispatch {
        use super::*;
        use std::{collections::BTreeSet, fs, io::Write as _, path::{Path, PathBuf}};
        use anyhow::{Result, ensure};
        use crate::{
            b4::{B4ByteOperation, B4ByteTarget, B4NegativeMaterialization, B4NegativeMutation},
            b4_c2_crypto::genuine_crypto_join::Fixture,
            b4_materialization_set::B4ClosedReconstructedExecutionV1,
            b4_mutation::{canonical_materialization_recipe_jcs, reconstruct_byte_edit,
                Eip0045B4MaterializationIdentityV1},
            b4_negative_io::{B4NegativeFileEncoding, B4NegativeNamedIdentityV1,
                B4NegativeObservationRejectionV1, B4NegativeObservationVerdict,
                Eip0045B4NegativeObservationV1, Eip0045B4NegativeVerifierInputV1},
            b4_plan::{B4MaterializationDomain as D, B4NegativeExecutionSurface as S,
                Eip0045B4NegativePlanV1},
        };

        const PRIVATE_FAILURE: &str = "selected negative adapter VerifierRisc0CryptographicVerifier failed privately; no observation was produced";
        const EXPORT_ROOT: &str = "/output/crypto-dispatch-materializations-20260905-01";

        fn identity(role: &str, path: &str, bytes: &[u8]) -> B4NegativeNamedIdentityV1 {
            B4NegativeNamedIdentityV1 { role: role.into(), path: path.into(),
                byte_length: bytes.len() as u64, sha256: sha256_hex(bytes),
                encoding: B4NegativeFileEncoding::RawBytes }
        }

        fn neutral(subject: &[u8], contexts: &[Vec<u8>]) -> Result<Vec<u8>> {
            Eip0045B4NegativeVerifierInputV1 {
                format: "Eip0045B4NegativeVerifierInputV1".into(), format_version: 1,
                materialization_domain: D::VerifierInput, validation_surface: S::Risc0CryptographicVerifier,
                subject: identity("subject", "subject.bin", subject),
                context: contexts.iter().enumerate().map(|(index, bytes)|
                    identity(&format!("context-{index:02}"), &format!("context/{index:02}.bin"), bytes)).collect(),
            }.to_canonical_jcs()
        }

        fn expected(input: &[u8], subject: &[u8], stage: &str) -> Eip0045B4NegativeObservationV1 {
            Eip0045B4NegativeObservationV1 {
                format: "Eip0045B4NegativeObservationV1".into(), format_version: 1,
                materialization_domain: D::VerifierInput, validation_surface: S::Risc0CryptographicVerifier,
                negative_input_sha256: sha256_hex(input), subject_byte_length: subject.len() as u64,
                subject_sha256: sha256_hex(subject), verdict: B4NegativeObservationVerdict::Reject,
                rejection: B4NegativeObservationRejectionV1 {
                    class: "risc0-proof-invalid".into(), stage: stage.into(),
                },
            }
        }

        fn observation(actual: &Eip0045B4NegativeObservationV1, input: &[u8], subject: &[u8], stage: &str) -> Result<()> {
            ensure!(*actual == expected(input, subject, stage), "crypto observation identity/boundary mismatch");
            let jcs = actual.to_canonical_jcs()?;
            let literal = format!(concat!(
                "{{\"format\":\"Eip0045B4NegativeObservationV1\",\"formatVersion\":1,",
                "\"materializationDomain\":\"verifier-input\",\"negativeInputSha256\":\"{}\",",
                "\"rejection\":{{\"class\":\"risc0-proof-invalid\",\"stage\":\"{}\"}},",
                "\"subjectByteLength\":{},\"subjectSha256\":\"{}\",",
                "\"validationSurface\":\"risc0-cryptographic-verifier\",\"verdict\":\"reject\"}}"
            ), sha256_hex(input), stage, subject.len(), sha256_hex(subject));
            ensure!(jcs == literal.as_bytes(), "crypto observation exact JCS mismatch");
            ensure!(Eip0045B4NegativeObservationV1::from_canonical_jcs(&jcs)? == *actual,
                "crypto observation round-trip mismatch");
            Ok(())
        }

        fn validate_row(fixture: &Fixture, index: usize, row: &B4ClosedReconstructedExecutionV1) -> Result<()> {
            let (_, id, _) = ROWS.iter().find(|entry| entry.0 == index)
                .ok_or_else(|| anyhow::anyhow!("closed crypto row index"))?;
            ensure!(row.derived_registry_row.execution_id == *id
                && row.derived_registry_row.base_selector_id == "lift-po2-15"
                && row.derived_registry_row.materialization_domain == D::VerifierInput,
                "crypto registry identity mismatch");
            ensure!(row.base == fixture.raw && row.subject.len() == PROOF_BYTES,
                "crypto base/output mismatch");
            ensure!(row.contexts == [fixture.manifest.clone(), fixture.oracle.clone()],
                "crypto positional context mismatch");
            ensure!(row.negative_input_jcs == neutral(&row.subject, &row.contexts)?,
                "C2 neutral input differs from the physical crypto package");
            let B4NegativeMaterialization::Mutation { mutation: B4NegativeMutation::ByteEdit {
                target: B4ByteTarget::RawSeal, edit: edit @ B4ByteOperation::Replace { .. },
            }} = &row.derived_registry_row.materialization else { anyhow::bail!("crypto single-word recipe"); };
            let B4ByteOperation::Replace { before_hex, replacement_hex, offset } = edit else { unreachable!() };
            ensure!(*offset % 4 == 0 && before_hex.len() == 8 && replacement_hex.len() == 8
                && row.subject.chunks_exact(4).zip(row.base.chunks_exact(4)).filter(|(a,b)| a != b).count() == 1,
                "crypto single-word recipe");
            ensure!(reconstruct_byte_edit(&row.base, edit)? == row.subject, "crypto recipe/output mismatch");
            let recipe = canonical_materialization_recipe_jcs(&row.derived_registry_row.materialization)?;
            let plan = Eip0045B4NegativePlanV1::canonical()?;
            let planned = plan.groups.iter().flat_map(|group| &group.executions).nth(index).unwrap();
            ensure!(planned.execution_id == *id && planned.execution_surface == S::Risc0CryptographicVerifier
                && planned.materialization_domain == D::VerifierInput, "crypto canonical plan mismatch");
            let plan_jcs = plan.to_canonical_jcs()?;
            let identity = Eip0045B4MaterializationIdentityV1::from_canonical_jcs(&row.materialization_identity_jcs)?;
            ensure!(identity.execution_id == *id && identity.base_selector_id == "lift-po2-15"
                && identity.materialization_domain == D::VerifierInput
                && identity.base_byte_length == row.base.len() as u64 && identity.base_sha256 == sha256_hex(&row.base)
                && identity.output_byte_length == row.subject.len() as u64 && identity.output_sha256 == sha256_hex(&row.subject)
                && identity.materialization_recipe_byte_length == recipe.len() as u64
                && identity.materialization_recipe_sha256 == sha256_hex(&recipe)
                && identity.negative_plan_byte_length == plan_jcs.len() as u64
                && identity.negative_plan_sha256 == sha256_hex(&plan_jcs), "crypto materialization identity mismatch");
            Ok(())
        }

        fn validate_rows(fixture: &Fixture, rows: &[B4ClosedReconstructedExecutionV1]) -> Result<()> {
            ensure!(rows.len() == 4, "ordered four-row crypto coverage");
            for (row, (index, id, _)) in rows.iter().zip(ROWS) {
                ensure!(row.derived_registry_row.execution_id == id, "ordered four-row crypto coverage");
                validate_row(fixture, index, row)?;
            }
            Ok(())
        }

        // This test owns its private output namespace. These repeated physical
        // checks do not claim custody against a hostile concurrent writer.
        fn physical_directory(path: &Path) -> Result<()> {
            ensure!(path.is_absolute(), "crypto export path must be absolute");
            for parent in path.ancestors() {
                let metadata = fs::symlink_metadata(parent)?;
                ensure!(metadata.is_dir() && !metadata.file_type().is_symlink(), "redirected crypto export parent");
            }
            ensure!(fs::canonicalize(path)? == path, "redirected crypto export parent");
            Ok(())
        }

        fn new_export_root(path: &Path) -> Result<()> {
            physical_directory(path.parent().ok_or_else(|| anyhow::anyhow!("crypto export parent"))?)?;
            match fs::symlink_metadata(path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                _ => anyhow::bail!("crypto export destination already exists"),
            }
        }

        fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
            physical_directory(path.parent().unwrap())?;
            let mut file = fs::OpenOptions::new().write(true).create_new(true).open(path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            ensure!(fs::read(path)? == bytes, "crypto export readback mismatch");
            Ok(())
        }

        fn package(root: &Path, subject: &[u8], contexts: &[Vec<u8>], input: &[u8]) -> Result<()> {
            new_export_root(root)?;
            fs::create_dir(root)?;
            fs::create_dir(root.join("context"))?;
            write_new(&root.join("subject.bin"), subject)?;
            for (index, bytes) in contexts.iter().enumerate() {
                write_new(&root.join(format!("context/{index:02}.bin")), bytes)?;
            }
            write_new(&root.join("negative-input.json"), input)?;
            fs::File::open(root.join("context"))?.sync_all()?;
            fs::File::open(root)?.sync_all()?;
            Ok(())
        }

        fn dispatch(root: &Path, row: &B4ClosedReconstructedExecutionV1, stage: &str) -> Result<()> {
            ensure!(fs::read(root.join("negative-input.json"))? == row.negative_input_jcs
                && fs::read(root.join("subject.bin"))? == row.subject, "crypto physical C2 bytes mismatch");
            for (index, context) in row.contexts.iter().enumerate() {
                ensure!(fs::read(root.join(format!("context/{index:02}.bin")))? == *context,
                    "crypto physical C2 context mismatch");
            }
            // This public Frozen entry receives only the physical root.
            observation(&crate::b4_validator::verify_negative_root(root)?,
                &row.negative_input_jcs, &row.subject, stage)
        }

        fn export_names() -> BTreeSet<String> {
            let mut names = BTreeSet::from(["base.bin".to_owned()]);
            for (index, _, _) in ROWS {
                for leaf in ["materialization-identity.json", "materialization-recipe.json",
                    "input/negative-input.json", "input/subject.bin", "input/context/00.bin", "input/context/01.bin"] {
                    names.insert(format!("{index}/{leaf}"));
                }
            }
            names
        }

        fn inventory(root: &Path) -> Result<BTreeSet<String>> {
            use std::os::unix::fs::MetadataExt as _;
            let mut names = BTreeSet::new();
            let mut pending = vec![root.to_path_buf()];
            let mut directories = BTreeSet::new();
            while let Some(directory) = pending.pop() {
                physical_directory(&directory)?;
                for entry in fs::read_dir(&directory)? {
                    let entry = entry?;
                    let path = entry.path();
                    let metadata = fs::symlink_metadata(&path)?;
                    ensure!(!metadata.file_type().is_symlink(), "redirected crypto export file");
                    let name = path.strip_prefix(root)?.to_str().unwrap().to_owned();
                    if metadata.is_dir() { directories.insert(name); pending.push(path); }
                    else {
                        ensure!(metadata.is_file() && metadata.nlink() == 1, "non-private crypto export file");
                        names.insert(name);
                    }
                }
            }
            let expected_directories: BTreeSet<String> = ROWS.iter().flat_map(|(index, _, _)|
                [format!("{index}"), format!("{index}/input"), format!("{index}/input/context")]).collect();
            ensure!(directories == expected_directories, "crypto export directory inventory mismatch");
            ensure!(names == export_names(), "crypto export file inventory mismatch");
            Ok(names)
        }

        fn export(root: &Path, fixture: &Fixture, rows: &[B4ClosedReconstructedExecutionV1]) -> Result<()> {
            validate_rows(fixture, rows)?;
            new_export_root(root)?;
            fs::create_dir(root)?; // create-only; failed attempts are retained, never cleaned up
            write_new(&root.join("base.bin"), &fixture.raw)?;
            for (row, (index, _, stage)) in rows.iter().zip(ROWS) {
                let directory = root.join(index.to_string());
                fs::create_dir(&directory)?;
                write_new(&directory.join("materialization-identity.json"), &row.materialization_identity_jcs)?;
                write_new(&directory.join("materialization-recipe.json"),
                    &canonical_materialization_recipe_jcs(&row.derived_registry_row.materialization)?)?;
                package(&directory.join("input"), &row.subject, &row.contexts, &row.negative_input_jcs)?;
                dispatch(&directory.join("input"), row, stage)?;
                fs::File::open(&directory)?.sync_all()?;
            }
            inventory(root)?;
            fs::File::open(root)?.sync_all()?;
            fs::File::open(root.parent().unwrap())?.sync_all()?;
            Ok(())
        }

        fn fault_package(row: &B4ClosedReconstructedExecutionV1) -> (tempfile::TempDir, PathBuf) {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().join("input");
            package(&root, &row.subject, &row.contexts, &row.negative_input_jcs).unwrap();
            (temporary, root)
        }

        fn deny(root: &Path, message: &str) {
            assert_eq!(crate::b4_validator::verify_negative_root(root)
                .expect_err("crypto private/custody fault produced an observation").to_string(), message);
        }

        #[test]
        fn production_crypto_observation_and_export_contract_are_exact() {
            // Observation/schema truth table only: no synthetic mutation authority.
            let subject = vec![0_u8; PROOF_BYTES];
            let value = expected(b"input", &subject, ROWS[0].2);
            observation(&value, b"input", &subject, ROWS[0].2).unwrap();
            for fault in 0..7 {
                let mut changed = value.clone();
                match fault {
                    0 => changed.negative_input_sha256 = "00".repeat(32),
                    1 => changed.subject_sha256 = "00".repeat(32),
                    2 => changed.subject_byte_length += 1,
                    3 => changed.rejection.class = "wrong".into(),
                    4 => changed.rejection.stage = ROWS[1].2.into(),
                    5 => changed.materialization_domain = D::ArtifactValidator,
                    _ => changed.validation_surface = S::RawSealShape,
                }
                assert_eq!(observation(&changed, b"input", &subject, ROWS[0].2).unwrap_err().to_string(),
                    "crypto observation identity/boundary mismatch");
            }
            assert_eq!(export_names().len(), 25);
            assert!(export_names().contains("159/input/context/01.bin"));
            assert!(!export_names().contains("156/input/materialization-identity.json"));
            let temp = tempfile::tempdir().unwrap();
            let destination = temp.path().join("export");
            new_export_root(&destination).unwrap();
            fs::create_dir(&destination).unwrap();
            assert_eq!(new_export_root(&destination).unwrap_err().to_string(), "crypto export destination already exists");
            write_new(&destination.join("retained"), b"original").unwrap();
            assert!(write_new(&destination.join("retained"), b"changed").is_err());
            assert_eq!(fs::read(destination.join("retained")).unwrap(), b"original");
            let link = temp.path().join("link");
            std::os::unix::fs::symlink(&destination, &link).unwrap();
            assert_eq!(new_export_root(&link.join("new")).unwrap_err().to_string(), "redirected crypto export parent");

            for fault in 0..4 {
                // Synthetic bytes exercise only the closed physical inventory,
                // never a receipt, C2 reconstruction, or mutation authority.
                let temporary = tempfile::tempdir().unwrap();
                let root = temporary.path().join("export");
                fs::create_dir(&root).unwrap();
                for name in export_names() {
                    let path = root.join(name);
                    fs::create_dir_all(path.parent().unwrap()).unwrap();
                    write_new(&path, b"inventory-only").unwrap();
                }
                assert_eq!(inventory(&root).unwrap(), export_names());
                let message = match fault {
                    0 => {
                        write_new(&root.join("extra.bin"), b"extra").unwrap();
                        "crypto export file inventory mismatch"
                    },
                    1 => {
                        fs::create_dir(root.join("extra-directory")).unwrap();
                        "crypto export directory inventory mismatch"
                    },
                    2 | 3 => {
                        let target = root.join("156/input/subject.bin");
                        let backing = temporary.path().join("backing.bin");
                        fs::rename(&target, &backing).unwrap();
                        if fault == 2 {
                            std::os::unix::fs::symlink(&backing, &target).unwrap();
                            assert!(fs::symlink_metadata(&target).unwrap().file_type().is_symlink());
                            "redirected crypto export file"
                        } else {
                            fs::hard_link(&backing, &target).unwrap();
                            "non-private crypto export file"
                        }
                    },
                    _ => unreachable!(),
                };
                assert_eq!(inventory(&root).unwrap_err().to_string(), message);
            }
        }

        #[test]
        #[ignore = "requires authenticated case0 vector and fresh fixed export root; one four-row reconstruction including two bounded FRI grinds"]
        fn production_crypto_frozen_dispatch_and_export() {
            let output = PathBuf::from(std::env::var_os("EIP0045_B4_CRYPTO_DISPATCH_EXPORT_ROOT").unwrap());
            assert_eq!(output, Path::new(EXPORT_ROOT));
            new_export_root(&output).unwrap(); // fail before any search
            let vector = PathBuf::from(std::env::var_os("EIP0045_B4_REAL_VECTOR_ROOT").unwrap());
            let fixture = load_fixture(&vector).unwrap();
            let replay = CompiledStockSuccinctReplayV1::from_compiled_profile().unwrap();
            let verified = replay.verify_direct_oracle(&fixture.oracle).unwrap();
            assert_eq!(verified.raw_seal_bytes(), fixture.raw);
            let contexts = [fixture.manifest.as_slice(), fixture.oracle.as_slice()];
            assert_eq!(reject_crypto_depth(&fixture.raw, &contexts), Err(B4CryptoAdapterError::SealMutationComparison));

            let rows = fixture.reconstruct().unwrap(); // sole authority/search call in this grouped test
            validate_rows(&fixture, &rows).unwrap();
            let outcomes = rows.iter().zip(ROWS).map(|(row, (index, _, _))| {
                (index, reject_crypto_depth(&row.subject, &contexts))
            }).collect::<Vec<_>>();
            assert!(exact_matrix(true, Err(B4CryptoAdapterError::SealMutationComparison), &outcomes));
            export(&output, &fixture, &rows).unwrap(); // four actual public Frozen observations

            assert_eq!(validate_rows(&fixture, &rows[..3]).unwrap_err().to_string(), "ordered four-row crypto coverage");
            let mut duplicated = rows.clone();
            duplicated[3] = duplicated[2].clone();
            assert_eq!(validate_rows(&fixture, &duplicated).unwrap_err().to_string(), "ordered four-row crypto coverage");
            for fault in 0..6 {
                let mut changed = rows[0].clone();
                let message = match fault {
                    0 => { changed.negative_input_jcs.push(b'\n'); "C2 neutral input differs from the physical crypto package" },
                    1 => { changed.contexts.swap(0, 1); "crypto positional context mismatch" },
                    2 => { changed.derived_registry_row.execution_id = ROWS[1].1.into(); "crypto registry identity mismatch" },
                    3 => { changed.base[0] ^= 1; "crypto base/output mismatch" },
                    4 => { changed.materialization_identity_jcs = rows[1].materialization_identity_jcs.clone(); "crypto materialization identity mismatch" },
                    _ => { changed.derived_registry_row.materialization = rows[1].derived_registry_row.materialization.clone(); "crypto recipe/output mismatch" },
                };
                assert_eq!(validate_row(&fixture, 156, &changed).unwrap_err().to_string(), message);
            }

            for fault in 0..12 {
                let (temporary, root) = fault_package(&rows[0]);
                dispatch(&root, &rows[0], ROWS[0].2).unwrap(); // same physical positive before each isolated fault
                let message = match fault {
                    0 => {
                        let mut input = Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(&rows[0].negative_input_jcs).unwrap();
                        input.subject.sha256 = "00".repeat(32);
                        fs::write(root.join("negative-input.json"), input.to_canonical_jcs().unwrap()).unwrap();
                        "negative verifier file subject.bin SHA-256 differs from its descriptor"
                    },
                    1 => {
                        let mut subject = rows[0].subject.clone(); subject[0] ^= 1;
                        fs::write(root.join("subject.bin"), subject).unwrap();
                        "negative verifier file subject.bin SHA-256 differs from its descriptor"
                    },
                    2 => {
                        let mut context = rows[0].contexts[1].clone(); context[0] ^= 1;
                        fs::write(root.join("context/01.bin"), context).unwrap();
                        "negative verifier file context/01.bin SHA-256 differs from its descriptor"
                    },
                    3 => {
                        let mut input = rows[0].negative_input_jcs.clone(); input.push(b'\n');
                        fs::write(root.join("negative-input.json"), input).unwrap();
                        "B4 negative verifier input is not exact RFC 8785 JCS"
                    },
                    4 => {
                        fs::remove_file(root.join("context/01.bin")).unwrap();
                        "negative context directory is not the exact NN.bin positional prefix"
                    },
                    5 => {
                        fs::write(root.join("extra"), b"unexpected").unwrap();
                        "negative verifier root contains an unexpected or duplicate entry"
                    },
                    6 => {
                        fs::remove_file(root.join("subject.bin")).unwrap();
                        "negative verifier root does not contain the exact V1 inventory"
                    },
                    7 | 8 => {
                        let subject = root.join("subject.bin");
                        let backing = temporary.path().join("backing.bin");
                        fs::rename(&subject, &backing).unwrap(); // backing is outside the watched input tree
                        if fault == 7 {
                            std::os::unix::fs::symlink(&backing, &subject).unwrap();
                            assert!(fs::symlink_metadata(&subject).unwrap().file_type().is_symlink());
                            "negative verifier path is not a regular file: subject.bin"
                        } else {
                            fs::hard_link(&backing, &subject).unwrap();
                            "hard-linked negative verifier file is forbidden: subject.bin"
                        }
                    },
                    9 => {
                        let mut input = Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(&rows[0].negative_input_jcs).unwrap();
                        input.context.pop();
                        fs::write(root.join("negative-input.json"), input.to_canonical_jcs().unwrap()).unwrap();
                        "negative input context cardinality differs from the frozen handler contract"
                    },
                    10 => {
                        let mut input = Eip0045B4NegativeVerifierInputV1::from_canonical_jcs(&rows[0].negative_input_jcs).unwrap();
                        input.context[1].sha256 = "00".repeat(32);
                        fs::write(root.join("negative-input.json"), input.to_canonical_jcs().unwrap()).unwrap();
                        "negative verifier file context/01.bin SHA-256 differs from its descriptor"
                    },
                    _ => {
                        let swapped = vec![rows[0].contexts[1].clone(), rows[0].contexts[0].clone()];
                        fs::write(root.join("context/00.bin"), &swapped[0]).unwrap();
                        fs::write(root.join("context/01.bin"), &swapped[1]).unwrap();
                        fs::write(root.join("negative-input.json"), neutral(&rows[0].subject, &swapped).unwrap()).unwrap();
                        "negative context 00 declared length is outside its handler custody bound"
                    },
                };
                deny(&root, message);
            }

            // Fresh descriptors isolate genuine adapter failures from custody.
            for fault in 0..4 {
                let mut row = rows[0].clone();
                let private = match fault {
                    0 => { row.subject.clone_from(&fixture.raw); B4CryptoAdapterError::SealMutationComparison },
                    1 => { row.contexts[0][0] ^= 1; B4CryptoAdapterError::ProfileContext },
                    2 => { row.contexts[1][0] ^= 1; B4CryptoAdapterError::ReceiptOracleReplay },
                    _ => { row.subject[0..4].copy_from_slice(&u32::MAX.to_le_bytes()); B4CryptoAdapterError::SealMutationComparison },
                };
                let refs = row.contexts.iter().map(Vec::as_slice).collect::<Vec<_>>();
                assert_eq!(reject_crypto_depth(&row.subject, &refs), Err(private));
                row.negative_input_jcs = neutral(&row.subject, &row.contexts).unwrap();
                let (_temporary, root) = fault_package(&row);
                deny(&root, PRIVATE_FAILURE);
            }
            // Reopen the unchanged export after every fault; metadata stays
            // outside custody roots and cannot influence consumer dispatch.
            assert_eq!(fs::read(output.join("base.bin")).unwrap(), fixture.raw);
            for (row, (index, _, stage)) in rows.iter().zip(ROWS) {
                let directory = output.join(index.to_string());
                assert_eq!(fs::read(directory.join("materialization-identity.json")).unwrap(), row.materialization_identity_jcs);
                assert_eq!(fs::read(directory.join("materialization-recipe.json")).unwrap(),
                    canonical_materialization_recipe_jcs(&row.derived_registry_row.materialization).unwrap());
                dispatch(&directory.join("input"), row, stage).unwrap();
            }
            assert_eq!(inventory(&output).unwrap(), export_names());
            assert_eq!(reject_crypto_depth(&fixture.raw, &contexts), Err(B4CryptoAdapterError::SealMutationComparison));
        }
    }
}
