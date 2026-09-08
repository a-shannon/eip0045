//! Validation primitives for the EIP-0045 reproduction package.

/// Closed candidate grammar for the eleven-case B4 corpus.
pub mod b4;
/// Fixed owned request and generated bundle for the B4 alternate-root witness.
pub mod b4_alternate_root_authority;
/// Strict validation of atomically published B4 build evidence.
#[cfg(feature = "profile")]
pub mod b4_build_check;
#[cfg(all(
    feature = "negative-materialization-set",
    any(target_os = "linux", test)
))]
pub(crate) mod b4_c2_alternate_root;
/// Closed semantic materializers for recursive ancestry rows.
#[cfg(all(feature = "positive-gate", feature = "recursive-ancestry"))]
pub(crate) mod b4_c2_ancestry;
/// Descriptor-rooted typed-checkpoint producers for the four E7 rows.
#[cfg(all(
    feature = "negative-materialization-set",
    any(target_os = "linux", test)
))]
pub(crate) mod b4_c2_crypto;
/// Descriptor-rooted strong-inference producers for authenticated ancestry witnesses.
#[cfg(all(
    feature = "negative-materialization-set",
    any(target_os = "linux", test)
))]
pub(crate) mod b4_c2_negative_ancestry_witness;
/// Deterministic C2 opcode-input and detached-sequence materializers.
#[cfg(feature = "positive-gate")]
pub(crate) mod b4_c2_opcode_sequence;
/// Deterministic C2 internal-parser prefix materializers.
#[cfg(feature = "positive-gate")]
pub(crate) mod b4_c2_parser;
/// Deterministic C2 profile-package materializers.
#[cfg(feature = "positive-gate")]
pub(crate) mod b4_c2_profile;
/// Deterministic C2 raw statement, proof-order, and raw-seal materializers.
#[cfg(feature = "positive-gate")]
pub(crate) mod b4_c2_raw;
/// Closed case-9 conditional receipt-claim materializer.
#[cfg(all(feature = "positive-gate", feature = "recursive-ancestry"))]
pub(crate) mod b4_c2_receipt_claim;
/// Deterministic C2 terminal-policy materializers.
#[cfg(feature = "positive-gate")]
pub(crate) mod b4_c2_terminal;
/// Staged terminal-catalogue recipes for rows 11 through 13.
#[cfg(feature = "materializer-replay")]
pub(crate) mod b4_c2_terminal_catalog;
/// Staged fixed terminal-fixture recipes for rows 131 through 139.
#[cfg(feature = "materializer-replay")]
pub(crate) mod b4_c2_terminal_fixture;
/// Staged terminal-metadata materializer over the verified case-8 replay.
#[cfg(feature = "materializer-replay")]
pub(crate) mod b4_c2_terminal_metadata;
/// Pre-proof verifier, executor, and campaign-precommit contracts.
pub mod b4_campaign_contract;
/// Fixed owned root and verified replay state for positive case 8.
#[cfg(any(
    feature = "materializer-replay",
    feature = "b4-terminal-evidence-packet"
))]
pub(crate) mod b4_case8_terminal_join_root;
/// Live-derived detached sequence-subject catalogue for B4 mutations.
pub mod b4_catalog;
/// Retained executing-image custody for descriptor-rooted B4 campaign imports.
#[cfg(feature = "b4-terminal-evidence-packet")]
#[doc(hidden)]
pub mod b4_executor_custody;
/// Reviewed implementation-specific rejection expectations for B4 negatives.
pub mod b4_expectation;
/// Typed, authenticated source views for B4 fixture-backed producers.
#[cfg(feature = "positive-gate")]
pub(crate) mod b4_fixture_sources;
#[cfg(test)]
mod b4_interop_schemas;
/// Canonical structural commitments for all B4 negative materializations.
pub mod b4_materialization_set;
/// Authenticated B4 reconstruction and domain-generic materialization identities.
pub mod b4_mutation;
/// Opaque derive-first authority for the negative ancestry witness catalogue.
#[cfg(all(
    feature = "positive-gate",
    feature = "recursive-ancestry",
    feature = "receipt-oracle"
))]
pub mod b4_negative_ancestry_authority;
/// Feature-independent layout constants shared by B4 ancestry handoff formats.
pub(crate) mod b4_negative_ancestry_layout;
/// Create-only custody and exact validation of the authenticated catalogue.
#[cfg(all(
    feature = "negative-ancestry-publication",
    feature = "positive-gate",
    feature = "recursive-ancestry",
    feature = "receipt-oracle",
))]
pub mod b4_negative_ancestry_publication;
/// Opaque authenticated sources consumed by negative-ancestry producers.
pub mod b4_negative_ancestry_source;
/// Post-generation structural catalogue for negative ancestry witnesses.
#[cfg(feature = "recursive-ancestry")]
pub mod b4_negative_ancestry_witness;
/// Single compile-time authority for B4 negative handler contracts.
pub(crate) mod b4_negative_handler_contract;
/// Canonical verifier inputs and observations for B4 negative executions.
pub mod b4_negative_io;
/// Closed, typed inventory of every B4 negative QA execution.
pub mod b4_plan;
/// Trusted-finalizer semantic bindings for B4 positive verification.
#[cfg(feature = "positive-gate")]
pub mod b4_positive_gate;
/// Closed H0 publication layout and completion witness for the positive input set.
pub mod b4_positive_input_set;
#[cfg(feature = "positive-gate")]
pub(crate) mod b4_positive_source_auth;
/// Exact shared wire codec for recursive positive auxiliary raw seals.
#[cfg(feature = "recursive-ancestry")]
pub(crate) mod b4_recursive_auxiliary_map;
/// Single compiled path authority for recursive positive auxiliary seals.
#[cfg(any(feature = "positive-gate", feature = "recursive-ancestry", test))]
pub(crate) mod b4_recursive_auxiliary_paths;
/// Honest synthetic inputs for the registry-owned B4 validation probes.
pub mod b4_registry_probe;
/// Canonical implementation-specific B4 validation results.
pub mod b4_result;
/// Pure, non-authorizing Linux/tmpfs metadata theorem and packet validator.
#[cfg(feature = "h0-tmpfs-provider-v2")]
pub mod b4_retained_rootfs_metadata_v2;
#[cfg(all(test, feature = "h0-tmpfs-provider-v2"))]
#[path = "b4_retained_rootfs_metadata_v2_tests.rs"]
mod b4_retained_rootfs_metadata_v2_tests;
/// Structural semantic-report format for all B4 negative result commitments.
pub mod b4_semantic_report;
/// Strict decode-only codec for authenticated statement-bundle manifests.
#[cfg(feature = "positive-gate")]
pub(crate) mod b4_statement_bundle_manifest;
/// Canonical detached sequence subjects for B4 mutations.
pub mod b4_subject;
/// Closed crate-private canonical codec for composite B4 subjects.
pub(crate) mod b4_subject_envelope;
/// Portable catalogue of shipping terminal-policy fixtures.
pub mod b4_terminal;
/// Shared exact wire codec for terminal raw-seal and receipt-oracle byte maps.
#[cfg(any(
    feature = "materializer-replay",
    feature = "recursive-ancestry",
    feature = "validator",
    test
))]
pub(crate) mod b4_terminal_byte_map;
/// Defensive reopening and feature-gated create-only publication for B4 terminal evidence packets.
#[cfg(feature = "b4-terminal-evidence-packet")]
pub(crate) mod b4_terminal_evidence_io;
/// Closed layout and canonical documents for B4 terminal evidence packets.
#[cfg(feature = "b4-terminal-evidence-packet")]
pub mod b4_terminal_evidence_packet;
/// Shared exact 34-byte projection for verified Join terminal metadata.
#[cfg(any(feature = "materializer-replay", feature = "validator"))]
pub(crate) mod b4_terminal_metadata_record;
/// Typed, derive-first replay of the nine fixed terminal receipt oracles.
#[cfg(feature = "receipt-oracle")]
pub mod b4_terminal_oracle;
/// Fixed official-lineage custody for the five B4 terminal-producer sources.
#[cfg(feature = "positive-gate")]
pub mod b4_terminal_source_lineage;
/// Complete B4 corpus-tree manifest and structural terminal-lock document.
pub mod b4_tree;
/// Abstract, role-only B4 closed-tree negative probes.
pub mod b4_tree_probe;
/// Pinned-circuit STARK core for the B4 Rust reference validator.
#[cfg(feature = "validator")]
pub mod b4_validator;
#[cfg(all(feature = "materializer-replay", not(feature = "validator")))]
pub(crate) mod b4_validator;
/// Candidate-artifact quarantine and completeness checks.
pub mod candidate;
/// Closed producer/consumer wire model for candidate proof metadata.
pub mod candidate_metadata;
pub mod canonical;
/// Cargo dependency-source, feature, and configuration closure checks.
pub mod cargo_closure;
/// Independent SHA-256 receipt-claim digest construction.
pub mod claim;
pub mod constants;
/// Strict pure codec for the frozen B2 constants artifact.
#[cfg(any(feature = "positive-gate", feature = "validator"))]
pub(crate) mod constants_artifact;
/// Strict codec for the shared `ErgoStatementV1` byte format.
#[cfg(any(
    feature = "positive-gate",
    feature = "recursive-ancestry",
    feature = "validator"
))]
pub(crate) mod ergo_statement;
/// Strict shared `ErgoStatementV1` value and decoder used by external candidate tooling.
#[cfg(any(
    feature = "positive-gate",
    feature = "recursive-ancestry",
    feature = "validator"
))]
pub use ergo_statement::{ErgoStatementV1, parse_ergo_statement_v1};
#[cfg(feature = "evidence")]
pub mod evidence;
/// Byte-exact proof-output manifest construction and validation.
pub mod manifest;
/// Exact statement and profile-identifier byte constructions.
#[cfg(feature = "profile")]
pub mod profile;
/// Exact B1 algorithm-artifact authentication against Manifest V1.
#[cfg(any(feature = "positive-gate", feature = "validator"))]
pub(crate) mod profile_algorithm;
/// Strict binary Manifest V1 codec and artifact-package validation.
#[cfg(feature = "profile")]
pub mod profile_manifest;
/// Shared bound and optional exact bincode configuration for receipt oracles.
pub mod receipt_oracle_codec;
/// Single compiled stock replay authority for direct, work, and union receipts.
#[cfg(feature = "receipt-oracle")]
pub(crate) mod receipt_oracle_replay;
#[cfg(feature = "recursive-ancestry")]
pub mod recursive_ancestry;
/// Exact raw-seal byte/word grammar shared with candidate generation.
pub mod seal;
/// Materialized source-tree, Git LFS, OCI, and toolchain lock checks.
pub mod source_lock;
#[cfg(test)]
mod test_support;
