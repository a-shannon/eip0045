//! Closed QA inventory for the EIP-0045 B4 negative conformance plan.

use std::{collections::BTreeSet, sync::LazyLock};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::canonical::{canonical_json_bytes, validate_canonical_json_source};

/// Exact format label for the B4 negative-plan inventory.
pub const B4_NEGATIVE_PLAN_FORMAT: &str = "Eip0045B4NegativePlanV1";
/// Exact format version for the B4 negative-plan inventory.
pub const B4_NEGATIVE_PLAN_FORMAT_VERSION: u8 = 1;
/// Exact number of closed QA groups.
pub const B4_NEGATIVE_PLAN_GROUP_COUNT: usize = 63;
/// Exact number of concrete executions represented by the closed QA groups.
pub const B4_NEGATIVE_PLAN_VARIANT_COUNT: u16 = 254;
/// Exact number of groups materialized as verifier inputs.
pub const B4_VERIFIER_INPUT_GROUP_COUNT: usize = 32;
/// Exact number of verifier-input executions.
pub const B4_VERIFIER_INPUT_EXECUTION_COUNT: u16 = 131;
/// Exact number of groups materialized for an artifact validator.
pub const B4_ARTIFACT_VALIDATOR_GROUP_COUNT: usize = 29;
/// Exact number of artifact-validator executions.
pub const B4_ARTIFACT_VALIDATOR_EXECUTION_COUNT: u16 = 102;
/// Exact number of groups materialized for the closed-tree validator.
pub const B4_TREE_VALIDATOR_GROUP_COUNT: usize = 2;
/// Exact number of tree-validator executions.
pub const B4_TREE_VALIDATOR_EXECUTION_COUNT: u16 = 21;

const MAX_CANONICAL_PLAN_BYTES: usize = 128 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 128;

/// Closed B4 negative acceptance-boundary class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4NegativePlanClass {
    /// Serialized statement and identity binding.
    StatementBinding,
    /// Proof chunking and transport grammar.
    ProofTransport,
    /// Canonical outer word encoding.
    CanonicalOuterWords,
    /// Frozen parser read phases.
    ParserPhases,
    /// Terminal allowlist and typed controls.
    TerminalPolicy,
    /// Final and recursive claim semantics.
    ClaimSemantics,
    /// Explicit- and zero-root resolution semantics.
    ResolveSemantics,
    /// Early, middle, late, and final rejection depth.
    CryptographicRejectionDepth,
    /// Profile-package and corpus-registry closure.
    ProfilePackageAndRegistry,
}

/// Closed reference fixture used by one QA group.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4NegativePlanFixture {
    /// The `lift-po2-15` positive receipt.
    #[serde(rename = "lift-po2-15")]
    LiftPo215,
    /// The fixed valid `po2=15` lift under the alternate recursion control root.
    #[serde(rename = "alternate-root-lift-po2-15-v1")]
    AlternateRootLiftPo215V1,
    /// The `lift-po2-15` receipt and canonical reference statement.
    #[serde(rename = "lift-po2-15-reference-statement-v1")]
    LiftPo215ReferenceStatementV1,
    /// The exact opcode children and trusted-host inputs used by `lift-po2-15`.
    #[serde(rename = "lift-po2-15-opcode-inputs-v1")]
    LiftPo215OpcodeInputsV1,
    /// The bounded parser oracle derived from `lift-po2-15`.
    #[serde(rename = "lift-po2-15-parser-oracle")]
    LiftPo215ParserOracle,
    /// The positive terminal-join receipt.
    #[serde(rename = "terminal-join")]
    TerminalJoin,
    /// The complete pinned stock-control table.
    #[serde(rename = "stock-control-table-v1")]
    StockControlTableV1,
    /// The exact stock controls outside the EIP allowlist.
    #[serde(rename = "stock-excluded-control-table-v1")]
    StockExcludedControlTableV1,
    /// The eight independently verified excluded shipping-family receipts.
    #[serde(rename = "excluded-family-receipts-v1")]
    ExcludedFamilyReceiptsV1,
    /// One independently verified allowed-terminal non-OK receipt.
    #[serde(rename = "allowed-terminal-non-ok-v1")]
    AllowedTerminalNonOkV1,
    /// The retained conditional receipt from positive case 9.
    #[serde(rename = "case9-conditional-receipt-v1")]
    Case9ConditionalReceiptV1,
    /// The three positive recursive claim-edge families.
    #[serde(rename = "join-resolve-edge-set-v1")]
    JoinResolveEdgeSetV1,
    /// The typed ancestry envelope for positive case 9.
    #[serde(rename = "case9-typed-ancestry-v1")]
    Case9TypedAncestryV1,
    /// The typed ancestry envelope for positive case 10.
    #[serde(rename = "case10-typed-ancestry-v1")]
    Case10TypedAncestryV1,
    /// The descriptor-bound catalogue of excluded and non-OK terminal fixtures.
    #[serde(rename = "terminal-fixture-catalog-v1")]
    TerminalFixtureCatalogV1,
    /// The live-derived catalogue for all fifteen detached sequence subjects.
    #[serde(rename = "sequence-subject-catalog-v1")]
    SequenceSubjectCatalogV1,
    /// The closed `risc0-v3-succinct` profile package.
    #[serde(rename = "risc0-v3-succinct-package-v1")]
    Risc0V3SuccinctPackageV1,
    /// The closed B4 candidate corpus and registry.
    #[serde(rename = "b4-candidate-corpus-v1")]
    B4CandidateCorpusV1,
}

/// Closed owner of base selection, mutation, and validation for one execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4MaterializationDomain {
    /// A concrete receipt, statement, proof transport, seal, or ancestry input.
    VerifierInput,
    /// A catalogue, table, manifest, package, registry, or result artifact.
    ArtifactValidator,
    /// The abstract closed-corpus tree, before concrete manifest closure.
    TreeValidator,
}

/// Exact validation entry point exercised by one concrete negative execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4NegativeExecutionSurface {
    /// Normal opcode evaluation before statement construction or proof parsing.
    OpcodePreflight,
    /// Claim binding against an exact already-constructed statement.
    RawStatementClaimBinding,
    /// Canonical raw-seal shape and output decoding.
    RawSealShape,
    /// Internal bounded parser after canonical transport has been isolated.
    Risc0ParserInternal,
    /// Instrumented upstream cryptographic verification.
    Risc0CryptographicVerifier,
    /// Typed terminal allowlist and metadata policy.
    TerminalPolicy,
    /// Final receipt-claim policy.
    ReceiptClaimPolicy,
    /// Typed recursive ancestry and resolve semantics.
    AncestryReplay,
    /// Reusable binary Manifest V1 grammar.
    ProfileManifestCodec,
    /// Initial-profile construction target selected before activation.
    InitialProfileTarget,
    /// Manifest-owned artifact envelopes against exact artifact bytes.
    ProfileArtifactEnvelope,
    /// Transition-authorized profile package identity.
    ActivatedProfilePackage,
    /// Descriptor-bound terminal-fixture catalogue validation.
    TerminalFixtureCatalog,
    /// Live-derived detached sequence-subject catalogue validation.
    SequenceSubjectCatalog,
    /// Typed terminal metadata validation.
    TerminalMetadata,
    /// Profile-ID preimage validation.
    ProfileIdPreimage,
    /// Candidate registry validation.
    CandidateRegistry,
    /// Negative-plan binding-index validation.
    NegativeBindingIndex,
    /// Closed abstract-tree corpus validation.
    CorpusClosure,
}

/// Closed normalized QA expectation for one B4 execution surface.
///
/// These codes describe the result that materialization is required to prove;
/// they are not claims that either verifier has already emitted a particular
/// internal error. The independently observed Rust and JVM first stage, class,
/// and implementation detail are archived separately from this plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum B4NegativeQaResultCode {
    /// The raw seal does not bind the exact expected receipt claim.
    RawSealClaimMismatch,
    /// Opcode preflight rejects a profile ID whose byte length is not 32.
    OpcodeProfileIdLengthInvalid,
    /// Opcode preflight rejects a program ID whose byte length is not 32.
    OpcodeProgramIdLengthInvalid,
    /// Opcode preflight rejects an application payload above the profile maximum.
    OpcodeApplicationPayloadTooLarge,
    /// Opcode preflight rejects a proof chunk count outside the exact profile shape.
    OpcodeProofChunkCountInvalid,
    /// Opcode preflight rejects a proof chunk with a noncanonical byte length.
    OpcodeProofChunkLengthInvalid,
    /// Canonical raw-seal decoding rejects a field word at or above the modulus.
    RawSealWordNotReduced,
    /// Canonical raw-seal decoding rejects nonzero digest padding.
    RawSealNonzeroRootPadding,
    /// Canonical raw-seal decoding rejects an overflowing claim halfword.
    RawSealClaimHalfwordOutOfRange,
    /// The selected byte-order mutation is rejected at its bound checkpoint.
    B4ByteOrderRejectedAtBoundCheckpoint,
    /// Raw-seal policy rejects an outer recursion exponent outside the profile.
    RawSealWrongOuterPo2,
    /// The bounded parser reaches EOF at the named phase and exact word cut.
    B4ParserUnexpectedEofAtPhase,
    /// Raw-seal policy rejects an inner control root outside the profile identity.
    RawSealInnerControlRootMismatch,
    /// Corpus closure rejects terminal metadata that differs from the bound fixture.
    B4TerminalMetadataMismatch,
    /// Terminal policy rejects a control ID outside the activated allowlist.
    RawSealControlIdNotAllowed,
    /// Ancestry replay rejects a recursive claim edge that does not bind exactly.
    B4AncestryClaimEdgeMismatch,
    /// Ancestry replay rejects altered explicit-root resolve semantics.
    B4ResolveExplicitSemanticsMismatch,
    /// Ancestry replay rejects altered zero-root resolve semantics.
    B4ResolveZeroRootSemanticsMismatch,
    /// Ancestry replay rejects a missing, extra, or pruned assumption.
    B4ResolveAssumptionInventoryInvalid,
    /// Normalized expectation for rejection at the selected early crypto checkpoint.
    B4CryptoEarlyCheckpointRejected,
    /// Normalized expectation for rejection at the selected middle crypto checkpoint.
    B4CryptoMiddleCheckpointRejected,
    /// Normalized expectation for rejection at the selected late crypto checkpoint.
    B4CryptoLateCheckpointRejected,
    /// Normalized expectation for rejection at the selected final crypto checkpoint.
    B4CryptoFinalCheckpointRejected,
    /// Manifest decoding rejects an exact-length violation.
    B4ProfileManifestLengthInvalid,
    /// Manifest decoding rejects an unsupported format version.
    B4ProfileManifestVersionUnsupported,
    /// Initial-profile construction rejects a changed exact proof-byte count.
    B4ProfileExactProofBytesInvalid,
    /// Initial-profile construction rejects a changed maximum payload.
    B4ProfileMaximumPayloadInvalid,
    /// Initial-profile construction rejects a changed outer recursion exponent.
    B4ProfileOuterPo2Invalid,
    /// Initial-profile construction rejects a field that changes profile identity.
    B4ProfileIdentityMismatch,
    /// Initial-profile construction rejects altered typed terminal metadata.
    B4ProfileTerminalFieldInvalid,
    /// Manifest decoding rejects a duplicate terminal control ID.
    B4ProfileTerminalControlIdDuplicate,
    /// Manifest decoding rejects noncanonical terminal-control ordering.
    B4ProfileTerminalOrderInvalid,
    /// Artifact-envelope validation rejects an altered manifest reference field.
    B4ProfileArtifactReferenceInvalid,
    /// Manifest decoding rejects artifact references in the wrong typed position.
    B4ProfileArtifactKindPositionInvalid,
    /// Artifact-envelope validation rejects bytes outside their bound digest.
    B4ProfileArtifactDigestMismatch,
    /// Activated-package validation rejects a supplied profile ID mismatch.
    B4ProfileIdMismatch,
    /// Corpus closure rejects a profile-ID preimage mismatch.
    B4ProfileIdPreimageMismatch,
    /// Corpus closure rejects a terminal fixture outside its catalog binding.
    B4TerminalFixtureCatalogBindingMismatch,
    /// Corpus closure rejects detached sequence-subject provenance drift.
    B4SequenceSubjectProvenanceMismatch,
    /// Corpus closure rejects omission of one representative structural stratum.
    /// Exact per-path completeness is derived separately from the final manifest.
    B4CorpusRepresentativeStratumMissing,
    /// Corpus closure rejects a path outside the final closed manifest.
    B4CorpusExtraFile,
    /// Registry validation rejects omission of one mandatory positive case.
    B4RegistryMandatoryPositiveMissing,
    /// Registry validation rejects a duplicate positive or negative case ID.
    B4RegistryCaseIdDuplicate,
    /// Registry validation rejects noncanonical positive-case ordering.
    B4RegistryPositiveOrderInvalid,
    /// Registry validation rejects a relabeled mandatory positive case.
    B4RegistryPositiveLabelInvalid,
    /// Registry validation rejects a negative row outside the closed class enum.
    B4RegistryNegativeClassUnknown,
    /// Registry decoding rejects an unknown field.
    B4RegistryUnknownField,
    /// Registry source validation rejects bytes outside exact RFC 8785 JCS.
    B4RegistryNoncanonicalJcs,
    /// Registry closure rejects a non-bijective negative-plan projection.
    B4NegativePlanRegistryBijectionMismatch,
}

/// One fully enumerated negative execution. This is a plan row, not yet a
/// materialized mutation or verifier result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4NegativePlanExecutionV1 {
    /// Exact canonical selector for the unmutated base within its typed fixture.
    pub base_selector_id: String,
    /// Globally unique `group-id--variant-id` identity.
    pub execution_id: String,
    /// Exact validation entry point.
    pub execution_surface: B4NegativeExecutionSurface,
    /// Exact typed base fixture selector.
    pub fixture: B4NegativePlanFixture,
    /// Closed materializer and validator family which owns this execution.
    pub materialization_domain: B4MaterializationDomain,
    /// Expected normalized result which materialization must prove.
    pub qa_result_code: B4NegativeQaResultCode,
    /// Resulting raw-seal word length for an internal parser cut, absent for
    /// every other surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parser_truncation_words: Option<u32>,
    /// Stable lower-kebab variant identifier.
    pub variant_id: String,
}

/// One closed QA group in the B4 negative-plan inventory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4NegativePlanGroupV1 {
    /// Stable lower-kebab group identifier.
    pub case_id: String,
    /// Closed acceptance-boundary class.
    pub class: B4NegativePlanClass,
    /// Exact ordered finite concrete executions represented by this group.
    pub executions: Vec<B4NegativePlanExecutionV1>,
    /// Exact number of concrete executions represented by this group.
    pub variant_count: u16,
}

/// Exact canonical B4 negative conformance-plan inventory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Eip0045B4NegativePlanV1 {
    /// Exact format label.
    pub format: String,
    /// Exact format version.
    pub format_version: u8,
    /// Canonically ordered closed QA groups.
    pub groups: Vec<B4NegativePlanGroupV1>,
    /// Exact sum of every group variant count.
    pub total_variant_count: u16,
}

impl Eip0045B4NegativePlanV1 {
    /// Construct the one canonical 63-group, 254-execution inventory.
    ///
    /// # Errors
    ///
    /// Returns an error if the compiled inventory is internally inconsistent.
    pub fn canonical() -> Result<Self> {
        let plan = Self {
            format: B4_NEGATIVE_PLAN_FORMAT.to_owned(),
            format_version: B4_NEGATIVE_PLAN_FORMAT_VERSION,
            groups: EXPECTED_GROUPS
                .iter()
                .map(ExpectedGroup::materialize)
                .collect(),
            total_variant_count: B4_NEGATIVE_PLAN_VARIANT_COUNT,
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Parse an exact RFC 8785 JCS plan and validate its closed inventory.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized, malformed, duplicate-key,
    /// non-canonical, unknown-field, incorrectly ordered, or otherwise
    /// non-conforming input.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            source.len() <= MAX_CANONICAL_PLAN_BYTES,
            "B4 negative plan exceeds the canonical-byte bound"
        );
        let value = validate_canonical_json_source(source)
            .context("B4 negative plan is not exact RFC 8785 JCS")?;
        let plan: Self = serde_json::from_value(value).context("invalid B4 negative-plan shape")?;
        plan.validate()?;
        ensure!(
            plan.to_canonical_jcs()? == source,
            "B4 negative plan does not round-trip byte-exactly"
        );
        Ok(plan)
    }

    /// Serialize this inventory to exact RFC 8785 JCS bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the in-memory inventory is not the closed V1 plan
    /// or if canonical serialization exceeds the V1 byte bound.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value = serde_json::to_value(self).context("cannot serialize B4 negative plan")?;
        let bytes = canonical_json_bytes(&value)?;
        ensure!(
            bytes.len() <= MAX_CANONICAL_PLAN_BYTES,
            "B4 negative plan exceeds the canonical-byte bound"
        );
        Ok(bytes)
    }

    /// Validate the exact V1 format, ordering, inventory, namespaces, and totals.
    ///
    /// # Errors
    ///
    /// Returns an error for any deviation from the closed 63-group,
    /// 254-execution inventory.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == B4_NEGATIVE_PLAN_FORMAT,
            "wrong B4 negative-plan format label"
        );
        ensure!(
            self.format_version == B4_NEGATIVE_PLAN_FORMAT_VERSION,
            "wrong B4 negative-plan format version"
        );
        ensure!(
            self.groups.len() == B4_NEGATIVE_PLAN_GROUP_COUNT,
            "B4 negative plan must contain exactly {B4_NEGATIVE_PLAN_GROUP_COUNT} groups"
        );

        let mut case_ids = BTreeSet::new();
        let mut execution_ids = BTreeSet::new();
        let mut parser_offsets = BTreeSet::new();
        let mut total = 0_u16;
        for (index, group) in self.groups.iter().enumerate() {
            validate_lower_kebab(&group.case_id, "B4 negative-plan case ID")?;
            ensure!(
                case_ids.insert(group.case_id.as_str()),
                "duplicate B4 negative-plan case ID at index {index}"
            );
            ensure!(
                usize::from(group.variant_count) == group.executions.len(),
                "B4 negative-plan variant ID count does not match variantCount at index {index}"
            );
            let mut local_variant_ids = BTreeSet::new();
            for (variant_index, execution) in group.executions.iter().enumerate() {
                validate_lower_kebab(&execution.variant_id, "B4 negative-plan variant ID")?;
                validate_non_wildcard_variant_id(&execution.variant_id)?;
                ensure!(
                    local_variant_ids.insert(execution.variant_id.as_str()),
                    "duplicate B4 variant ID at group index {index}, variant index {variant_index}"
                );
                let expected_execution_id = format!("{}--{}", group.case_id, execution.variant_id);
                ensure!(
                    execution.execution_id == expected_execution_id,
                    "wrong B4 execution ID at group index {index}, variant index {variant_index}"
                );
                ensure!(
                    execution_ids.insert(execution.execution_id.as_str()),
                    "duplicate B4 execution ID at group index {index}, variant index {variant_index}"
                );
                validate_execution_contract(&group.case_id, group.class, execution)?;
                if let Some(offset) = execution.parser_truncation_words {
                    ensure!(
                        parser_offsets.insert(offset),
                        "duplicate B4 parser truncation offset {offset}"
                    );
                }
            }
            total = total
                .checked_add(group.variant_count)
                .context("B4 negative-plan variant sum overflows u16")?;
            let expected = &EXPECTED_GROUPS[index];
            ensure!(
                group.case_id == expected.case_id,
                "wrong B4 negative-plan group ID or order at index {index}"
            );
            ensure!(
                group.class == expected.class,
                "wrong B4 negative-plan class at index {index}"
            );
            ensure!(
                group.variant_count == expected.variant_count,
                "wrong B4 negative-plan variant count at index {index}"
            );
            ensure!(
                group == &expected.materialize(),
                "wrong B4 negative-plan execution material or order at index {index}"
            );
        }

        ensure!(
            total == B4_NEGATIVE_PLAN_VARIANT_COUNT,
            "B4 negative-plan group variants must sum to {B4_NEGATIVE_PLAN_VARIANT_COUNT}"
        );
        ensure!(
            self.total_variant_count == B4_NEGATIVE_PLAN_VARIANT_COUNT,
            "wrong B4 negative-plan declared variant total"
        );
        ensure!(
            self.total_variant_count == total,
            "B4 negative-plan declared variant total does not match its groups"
        );
        validate_domain_totals(&self.groups)?;
        Ok(())
    }
}

fn validate_domain_totals(groups: &[B4NegativePlanGroupV1]) -> Result<()> {
    let mut totals = [(0_usize, 0_u16); 3];
    for group in groups {
        let index = match materialization_domain_for(&group.case_id)
            .context("B4 negative-plan group has no materialization domain")?
        {
            B4MaterializationDomain::VerifierInput => 0,
            B4MaterializationDomain::ArtifactValidator => 1,
            B4MaterializationDomain::TreeValidator => 2,
        };
        totals[index].0 += 1;
        totals[index].1 = totals[index]
            .1
            .checked_add(group.variant_count)
            .context("B4 materialization-domain variant sum overflows u16")?;
    }
    ensure!(
        totals
            == [
                (
                    B4_VERIFIER_INPUT_GROUP_COUNT,
                    B4_VERIFIER_INPUT_EXECUTION_COUNT,
                ),
                (
                    B4_ARTIFACT_VALIDATOR_GROUP_COUNT,
                    B4_ARTIFACT_VALIDATOR_EXECUTION_COUNT,
                ),
                (
                    B4_TREE_VALIDATOR_GROUP_COUNT,
                    B4_TREE_VALIDATOR_EXECUTION_COUNT,
                ),
            ],
        "wrong B4 materialization-domain group or execution totals"
    );
    Ok(())
}

#[derive(Clone, Copy)]
struct ExpectedGroup {
    case_id: &'static str,
    class: B4NegativePlanClass,
    fixture: B4NegativePlanFixture,
    qa_result_code: B4NegativeQaResultCode,
    variant_count: u16,
}

impl ExpectedGroup {
    fn materialize(&self) -> B4NegativePlanGroupV1 {
        B4NegativePlanGroupV1 {
            case_id: self.case_id.to_owned(),
            class: self.class,
            executions: variant_ids_for(self.case_id)
                .iter()
                .map(|variant_id| B4NegativePlanExecutionV1 {
                    base_selector_id: base_selector_id_for(self.case_id, variant_id)
                        .expect("closed B4 case/variant has a base selector"),
                    execution_id: format!("{}--{variant_id}", self.case_id),
                    execution_surface: execution_surface_for(self.case_id, variant_id),
                    fixture: self.fixture,
                    materialization_domain: materialization_domain_for(self.case_id)
                        .expect("closed B4 case has a materialization domain"),
                    qa_result_code: self.qa_result_code,
                    parser_truncation_words: parser_truncation_words(self.case_id, variant_id),
                    variant_id: (*variant_id).to_owned(),
                })
                .collect(),
            variant_count: self.variant_count,
        }
    }
}

fn group(
    case_id: &'static str,
    class: B4NegativePlanClass,
    fixture: B4NegativePlanFixture,
    qa_result_code: B4NegativeQaResultCode,
    variant_count: u16,
) -> ExpectedGroup {
    ExpectedGroup {
        case_id,
        class,
        fixture,
        qa_result_code,
        variant_count,
    }
}

fn execution_surface_for(case_id: &str, variant_id: &str) -> B4NegativeExecutionSurface {
    match case_id {
        "statement-field-byte-sweep"
        | "statement-profile-id-byte-order"
        | "statement-program-id-byte-order" => B4NegativeExecutionSurface::RawStatementClaimBinding,
        "opcode-profile-id-length-sweep"
        | "opcode-program-id-length-sweep"
        | "statement-payload-over-maximum"
        | "proof-chunk-count-sweep"
        | "proof-empty-chunk"
        | "proof-boundary-shift-sweep"
        | "proof-seal-truncated-byte"
        | "proof-seal-trailing-byte"
        | "proof-seal-trailing-word" => B4NegativeExecutionSurface::OpcodePreflight,
        "proof-chunks-reordered"
        | "outer-root-padding-sweep"
        | "outer-claim-halfword-overflow-sweep"
        | "outer-field-modulus-role-sweep"
        | "outer-field-byte-order-role-sweep"
        | "outer-po2-montgomery-encoding"
        | "terminal-inner-root-mismatch"
        | "terminal-outer-po2-mismatch" => B4NegativeExecutionSurface::RawSealShape,
        "parser-phase-truncation-sweep" => B4NegativeExecutionSurface::Risc0ParserInternal,
        "terminal-control-id-unknown"
        | "terminal-excluded-control-id-sweep"
        | "terminal-excluded-shipping-family-sweep" => B4NegativeExecutionSurface::TerminalPolicy,
        "terminal-metadata-field-sweep" => B4NegativeExecutionSurface::TerminalMetadata,
        "terminal-fixture-catalog-binding-sweep" => {
            B4NegativeExecutionSurface::TerminalFixtureCatalog
        }
        "sequence-subject-provenance-target-sweep" => {
            B4NegativeExecutionSurface::SequenceSubjectCatalog
        }
        "profile-id-preimage-mismatch" => B4NegativeExecutionSurface::ProfileIdPreimage,
        "corpus-representative-stratum-omit-sweep" | "corpus-extra-file" => {
            B4NegativeExecutionSurface::CorpusClosure
        }
        "registry-positive-case-omit-sweep"
        | "registry-positive-case-id-duplicate"
        | "registry-positive-cases-reordered"
        | "registry-positive-case-relabel"
        | "registry-negative-class-unknown"
        | "registry-unknown-field"
        | "registry-noncanonical-jcs" => B4NegativeExecutionSurface::CandidateRegistry,
        "registry-negative-case-id-duplicate" | "negative-plan-registry-bijection-sweep" => {
            B4NegativeExecutionSurface::NegativeBindingIndex
        }
        "claim-final-status-non-ok" | "claim-final-assumptions-nonempty" => {
            B4NegativeExecutionSurface::ReceiptClaimPolicy
        }
        "claim-edge-family-sweep"
        | "resolve-explicit-field-sweep"
        | "resolve-zero-root-field-sweep"
        | "resolve-assumption-inventory-sweep" => B4NegativeExecutionSurface::AncestryReplay,
        "crypto-early-check-value-mismatch"
        | "crypto-middle-fri-round-two-mismatch"
        | "crypto-late-final-opening-mismatch"
        | "crypto-final-expected-claim-mismatch" => {
            B4NegativeExecutionSurface::Risc0CryptographicVerifier
        }
        "profile-manifest-short"
        | "profile-manifest-trailing-byte"
        | "profile-manifest-version"
        | "profile-terminal-control-id-duplicate"
        | "profile-terminal-controls-reordered"
        | "profile-artifact-refs-reordered" => B4NegativeExecutionSurface::ProfileManifestCodec,
        "profile-manifest-exact-proof-bytes"
        | "profile-manifest-maximum-payload"
        | "profile-manifest-outer-po2"
        | "profile-manifest-inner-control-root" => B4NegativeExecutionSurface::InitialProfileTarget,
        "profile-terminal-field-sweep" => match variant_id.rsplit_once('-') {
            Some((_, "kind" | "parameter")) => B4NegativeExecutionSurface::ProfileManifestCodec,
            Some((_, "id")) if variant_id.ends_with("-control-id") => {
                B4NegativeExecutionSurface::InitialProfileTarget
            }
            _ => panic!("closed B4 profile-terminal variant has no execution surface"),
        },
        "profile-artifact-ref-field-sweep" => match variant_id {
            "algorithm-kind" | "binary-data-kind" => {
                B4NegativeExecutionSurface::ProfileManifestCodec
            }
            "algorithm-length" | "algorithm-digest" | "binary-data-length"
            | "binary-data-digest" => B4NegativeExecutionSurface::ProfileArtifactEnvelope,
            _ => panic!("closed B4 profile-artifact-reference variant has no execution surface"),
        },
        "profile-artifact-bytes-sweep" => B4NegativeExecutionSurface::ProfileArtifactEnvelope,
        "profile-id-mismatch" => B4NegativeExecutionSurface::ActivatedProfilePackage,
        _ => panic!("closed B4 group has no execution surface"),
    }
}

fn materialization_domain_for(case_id: &str) -> Option<B4MaterializationDomain> {
    use B4MaterializationDomain as D;

    Some(match case_id {
        "statement-field-byte-sweep"
        | "statement-profile-id-byte-order"
        | "statement-program-id-byte-order"
        | "opcode-profile-id-length-sweep"
        | "opcode-program-id-length-sweep"
        | "statement-payload-over-maximum"
        | "proof-chunk-count-sweep"
        | "proof-empty-chunk"
        | "proof-boundary-shift-sweep"
        | "proof-chunks-reordered"
        | "proof-seal-truncated-byte"
        | "proof-seal-trailing-byte"
        | "proof-seal-trailing-word"
        | "outer-root-padding-sweep"
        | "outer-claim-halfword-overflow-sweep"
        | "outer-field-modulus-role-sweep"
        | "outer-field-byte-order-role-sweep"
        | "outer-po2-montgomery-encoding"
        | "parser-phase-truncation-sweep"
        | "terminal-inner-root-mismatch"
        | "terminal-outer-po2-mismatch"
        | "terminal-excluded-shipping-family-sweep"
        | "claim-final-status-non-ok"
        | "claim-final-assumptions-nonempty"
        | "claim-edge-family-sweep"
        | "resolve-explicit-field-sweep"
        | "resolve-zero-root-field-sweep"
        | "resolve-assumption-inventory-sweep"
        | "crypto-early-check-value-mismatch"
        | "crypto-middle-fri-round-two-mismatch"
        | "crypto-late-final-opening-mismatch"
        | "crypto-final-expected-claim-mismatch" => D::VerifierInput,
        "terminal-fixture-catalog-binding-sweep"
        | "sequence-subject-provenance-target-sweep"
        | "terminal-metadata-field-sweep"
        | "terminal-control-id-unknown"
        | "terminal-excluded-control-id-sweep"
        | "profile-manifest-short"
        | "profile-manifest-trailing-byte"
        | "profile-manifest-version"
        | "profile-manifest-exact-proof-bytes"
        | "profile-manifest-maximum-payload"
        | "profile-manifest-outer-po2"
        | "profile-manifest-inner-control-root"
        | "profile-terminal-field-sweep"
        | "profile-terminal-control-id-duplicate"
        | "profile-terminal-controls-reordered"
        | "profile-artifact-ref-field-sweep"
        | "profile-artifact-refs-reordered"
        | "profile-artifact-bytes-sweep"
        | "profile-id-mismatch"
        | "profile-id-preimage-mismatch"
        | "registry-positive-case-omit-sweep"
        | "registry-positive-case-id-duplicate"
        | "registry-negative-case-id-duplicate"
        | "registry-positive-cases-reordered"
        | "registry-positive-case-relabel"
        | "registry-negative-class-unknown"
        | "registry-unknown-field"
        | "registry-noncanonical-jcs"
        | "negative-plan-registry-bijection-sweep" => D::ArtifactValidator,
        "corpus-representative-stratum-omit-sweep" | "corpus-extra-file" => D::TreeValidator,
        _ => return None,
    })
}

/// Whether a canonical group selects an independently produced fixture rather
/// than applying a mutation recipe to another base.
///
/// This is the sole fixture-selection classification used by registry,
/// materialization, interoperability, and report fixtures.
pub(crate) fn negative_group_requires_fixture_selection(case_id: &str) -> bool {
    matches!(
        case_id,
        "terminal-inner-root-mismatch"
            | "terminal-excluded-shipping-family-sweep"
            | "claim-final-status-non-ok"
            | "claim-final-assumptions-nonempty"
    )
}

fn base_selector_id_for(case_id: &str, variant_id: &str) -> Option<String> {
    let selector = match case_id {
        "statement-field-byte-sweep" => "lift-po2-15-reference-statement-v1",
        "statement-profile-id-byte-order"
        | "statement-program-id-byte-order"
        | "proof-chunk-count-sweep"
        | "proof-empty-chunk"
        | "proof-boundary-shift-sweep"
        | "proof-chunks-reordered"
        | "proof-seal-truncated-byte"
        | "proof-seal-trailing-byte"
        | "proof-seal-trailing-word"
        | "outer-root-padding-sweep"
        | "outer-claim-halfword-overflow-sweep"
        | "outer-field-modulus-role-sweep"
        | "outer-field-byte-order-role-sweep"
        | "outer-po2-montgomery-encoding"
        | "terminal-outer-po2-mismatch"
        | "crypto-early-check-value-mismatch"
        | "crypto-middle-fri-round-two-mismatch"
        | "crypto-late-final-opening-mismatch"
        | "crypto-final-expected-claim-mismatch" => "lift-po2-15",
        "terminal-inner-root-mismatch" => "alternate-root-lift-po2-15-v1",
        "opcode-profile-id-length-sweep"
        | "opcode-program-id-length-sweep"
        | "statement-payload-over-maximum" => "lift-po2-15-opcode-inputs-v1",
        "terminal-fixture-catalog-binding-sweep" => "terminal-fixture-catalog-v1",
        "sequence-subject-provenance-target-sweep" => "sequence-subject-catalog-v1",
        "parser-phase-truncation-sweep" => "lift-po2-15-parser-oracle",
        "terminal-metadata-field-sweep" => "terminal-join",
        "terminal-control-id-unknown" => "stock-control-table-v1",
        "terminal-excluded-control-id-sweep" => "stock-excluded-control-table-v1",
        "terminal-excluded-shipping-family-sweep" => match variant_id {
            "lift-po2-14"
            | "lift-povw-po2-18"
            | "join-povw"
            | "join-unwrap-povw"
            | "resolve-povw"
            | "resolve-unwrap-povw"
            | "union"
            | "unwrap-povw" => variant_id,
            _ => return None,
        },
        "claim-final-status-non-ok" => "allowed-terminal-non-ok-v1",
        "claim-final-assumptions-nonempty" => "case9-conditional-receipt-v1",
        "claim-edge-family-sweep" => match variant_id {
            "terminal-join" | "terminal-resolve-explicit-root" | "resolve-zero-root-then-join" => {
                variant_id
            }
            _ => return None,
        },
        "resolve-explicit-field-sweep" | "resolve-assumption-inventory-sweep" => {
            "case9-typed-ancestry-v1"
        }
        "resolve-zero-root-field-sweep" => "case10-typed-ancestry-v1",
        "profile-manifest-short"
        | "profile-manifest-trailing-byte"
        | "profile-manifest-version"
        | "profile-manifest-exact-proof-bytes"
        | "profile-manifest-maximum-payload"
        | "profile-manifest-outer-po2"
        | "profile-manifest-inner-control-root"
        | "profile-terminal-field-sweep"
        | "profile-terminal-control-id-duplicate"
        | "profile-terminal-controls-reordered"
        | "profile-artifact-ref-field-sweep"
        | "profile-artifact-refs-reordered" => "risc0-v3-succinct-profile-manifest-v1",
        "profile-artifact-bytes-sweep" => match variant_id {
            "algorithm" => "risc0-v3-succinct-algorithm-artifact-v1",
            "constants" => "risc0-v3-succinct-constants-artifact-v1",
            _ => return None,
        },
        "profile-id-mismatch" => "risc0-v3-succinct-package-v1",
        "profile-id-preimage-mismatch" => "risc0-v3-succinct-profile-id-preimage-v1",
        "corpus-representative-stratum-omit-sweep" | "corpus-extra-file" => {
            "abstract-corpus-strata-v1"
        }
        "registry-positive-case-omit-sweep"
        | "registry-positive-case-id-duplicate"
        | "registry-positive-cases-reordered"
        | "registry-positive-case-relabel"
        | "registry-negative-class-unknown"
        | "registry-unknown-field"
        | "registry-noncanonical-jcs" => "synthetic-registry-skeleton-v1",
        "registry-negative-case-id-duplicate" => "synthetic-negative-binding-index-v1",
        "negative-plan-registry-bijection-sweep" => match variant_id {
            "missing-execution"
            | "unexpected-execution"
            | "wrong-base-selector-binding"
            | "wrong-materialization-domain"
            | "wrong-materialization-binding" => "synthetic-negative-binding-index-v1",
            _ => return None,
        },
        _ => return None,
    };
    Some(selector.to_owned())
}

/// Return the raw-seal word length retained by one parser truncation.
///
/// The closed inventory contains 36 distinct cuts rather than 38 labels
/// because two pairs are the same physical offset: the one-word `outerPo2`
/// phase has both its before-read and last-required-word cut at word 32, and
/// the top-level `queries` before-read cut is also query zero's `accumOpening`
/// before-read cut at word 4,717.
fn parser_truncation_words(case_id: &str, variant_id: &str) -> Option<u32> {
    if case_id != "parser-phase-truncation-sweep" {
        return None;
    }
    Some(match variant_id {
        "output-before-read" => 0,
        "output-at-last-required-word" => 31,
        "outer-po2-before-read" => 32,
        "code-top-before-read" => 33,
        "code-top-at-last-required-word" => 288,
        "data-top-before-read" => 289,
        "data-top-at-last-required-word" => 544,
        "accum-top-before-read" => 545,
        "accum-top-at-last-required-word" => 800,
        "check-top-before-read" => 801,
        "check-top-at-last-required-word" => 1_056,
        "coeff-u-before-read" => 1_057,
        "coeff-u-at-last-required-word" => 3_692,
        "fri-round-one-top-before-read" => 3_693,
        "fri-round-one-top-at-last-required-word" => 3_948,
        "fri-round-two-top-before-read" => 3_949,
        "fri-round-two-top-at-last-required-word" => 4_204,
        "fri-round-three-top-before-read" => 4_205,
        "fri-round-three-top-at-last-required-word" => 4_460,
        "final-coefficients-before-read" => 4_461,
        "final-coefficients-at-last-required-word" => 4_716,
        "queries-before-read" => 4_717,
        "queries-at-last-required-word" => 55_666,
        "query-zero-accum-opening-at-last-required-word" => 4_848,
        "query-zero-code-opening-before-read" => 4_849,
        "query-zero-code-opening-at-last-required-word" => 4_991,
        "query-zero-data-opening-before-read" => 4_992,
        "query-zero-data-opening-at-last-required-word" => 5_239,
        "query-zero-check-opening-before-read" => 5_240,
        "query-zero-check-opening-at-last-required-word" => 5_375,
        "query-zero-fri-round-one-opening-before-read" => 5_376,
        "query-zero-fri-round-one-opening-at-last-required-word" => 5_527,
        "query-zero-fri-round-two-opening-before-read" => 5_528,
        "query-zero-fri-round-two-opening-at-last-required-word" => 5_647,
        "query-zero-fri-round-three-opening-before-read" => 5_648,
        "query-zero-fri-round-three-opening-at-last-required-word" => 5_735,
        _ => panic!("closed parser variant has no exact truncation offset"),
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the exhaustive contract table stays grouped and explicit for audit; splitting it would add risky indirection"
)]
fn validate_execution_contract(
    case_id: &str,
    class: B4NegativePlanClass,
    execution: &B4NegativePlanExecutionV1,
) -> Result<()> {
    use B4NegativeExecutionSurface as S;
    use B4NegativeQaResultCode as Q;

    validate_materialization_contract(case_id, execution)?;
    let parser_execution = execution.execution_surface == S::Risc0ParserInternal;
    ensure!(
        parser_execution == execution.parser_truncation_words.is_some(),
        "parser truncation offsets exist exactly on internal parser executions"
    );
    if let Some(offset) = execution.parser_truncation_words {
        ensure!(
            offset < 55_667,
            "parser truncation offset must be strictly before canonical proof EOF"
        );
    }

    let class_surface_allowed = match class {
        B4NegativePlanClass::StatementBinding => matches!(
            execution.execution_surface,
            S::OpcodePreflight | S::RawStatementClaimBinding
        ),
        B4NegativePlanClass::ProofTransport => matches!(
            execution.execution_surface,
            S::OpcodePreflight | S::RawSealShape
        ),
        B4NegativePlanClass::CanonicalOuterWords => execution.execution_surface == S::RawSealShape,
        B4NegativePlanClass::ParserPhases => execution.execution_surface == S::Risc0ParserInternal,
        B4NegativePlanClass::TerminalPolicy => matches!(
            execution.execution_surface,
            S::RawSealShape | S::TerminalPolicy | S::TerminalMetadata
        ),
        B4NegativePlanClass::ClaimSemantics => matches!(
            execution.execution_surface,
            S::ReceiptClaimPolicy | S::AncestryReplay
        ),
        B4NegativePlanClass::ResolveSemantics => execution.execution_surface == S::AncestryReplay,
        B4NegativePlanClass::CryptographicRejectionDepth => {
            execution.execution_surface == S::Risc0CryptographicVerifier
        }
        B4NegativePlanClass::ProfilePackageAndRegistry => matches!(
            execution.execution_surface,
            S::ProfileManifestCodec
                | S::InitialProfileTarget
                | S::ProfileArtifactEnvelope
                | S::ActivatedProfilePackage
                | S::TerminalFixtureCatalog
                | S::SequenceSubjectCatalog
                | S::ProfileIdPreimage
                | S::CandidateRegistry
                | S::NegativeBindingIndex
                | S::CorpusClosure
        ),
    };
    ensure!(
        class_surface_allowed,
        "B4 execution surface contradicts its acceptance-boundary class"
    );

    let result_surface_allowed = match execution.execution_surface {
        S::OpcodePreflight => matches!(
            execution.qa_result_code,
            Q::OpcodeProfileIdLengthInvalid
                | Q::OpcodeProgramIdLengthInvalid
                | Q::OpcodeApplicationPayloadTooLarge
                | Q::OpcodeProofChunkCountInvalid
                | Q::OpcodeProofChunkLengthInvalid
        ),
        S::RawStatementClaimBinding | S::ReceiptClaimPolicy => {
            execution.qa_result_code == Q::RawSealClaimMismatch
        }
        S::RawSealShape => matches!(
            execution.qa_result_code,
            Q::RawSealWordNotReduced
                | Q::RawSealNonzeroRootPadding
                | Q::RawSealClaimHalfwordOutOfRange
                | Q::B4ByteOrderRejectedAtBoundCheckpoint
                | Q::RawSealWrongOuterPo2
                | Q::RawSealInnerControlRootMismatch
        ),
        S::Risc0ParserInternal => execution.qa_result_code == Q::B4ParserUnexpectedEofAtPhase,
        S::Risc0CryptographicVerifier => matches!(
            execution.qa_result_code,
            Q::B4CryptoEarlyCheckpointRejected
                | Q::B4CryptoMiddleCheckpointRejected
                | Q::B4CryptoLateCheckpointRejected
                | Q::B4CryptoFinalCheckpointRejected
        ),
        S::TerminalPolicy => execution.qa_result_code == Q::RawSealControlIdNotAllowed,
        S::AncestryReplay => matches!(
            execution.qa_result_code,
            Q::B4AncestryClaimEdgeMismatch
                | Q::B4ResolveExplicitSemanticsMismatch
                | Q::B4ResolveZeroRootSemanticsMismatch
                | Q::B4ResolveAssumptionInventoryInvalid
        ),
        S::ProfileManifestCodec => matches!(
            execution.qa_result_code,
            Q::B4ProfileManifestLengthInvalid
                | Q::B4ProfileManifestVersionUnsupported
                | Q::B4ProfileTerminalFieldInvalid
                | Q::B4ProfileTerminalControlIdDuplicate
                | Q::B4ProfileTerminalOrderInvalid
                | Q::B4ProfileArtifactReferenceInvalid
                | Q::B4ProfileArtifactKindPositionInvalid
        ),
        S::InitialProfileTarget => matches!(
            execution.qa_result_code,
            Q::B4ProfileExactProofBytesInvalid
                | Q::B4ProfileMaximumPayloadInvalid
                | Q::B4ProfileOuterPo2Invalid
                | Q::B4ProfileIdentityMismatch
                | Q::B4ProfileTerminalFieldInvalid
        ),
        S::ProfileArtifactEnvelope => matches!(
            execution.qa_result_code,
            Q::B4ProfileArtifactReferenceInvalid | Q::B4ProfileArtifactDigestMismatch
        ),
        S::ActivatedProfilePackage => execution.qa_result_code == Q::B4ProfileIdMismatch,
        S::TerminalFixtureCatalog => {
            execution.qa_result_code == Q::B4TerminalFixtureCatalogBindingMismatch
        }
        S::SequenceSubjectCatalog => {
            execution.qa_result_code == Q::B4SequenceSubjectProvenanceMismatch
        }
        S::TerminalMetadata => execution.qa_result_code == Q::B4TerminalMetadataMismatch,
        S::ProfileIdPreimage => execution.qa_result_code == Q::B4ProfileIdPreimageMismatch,
        S::CandidateRegistry => matches!(
            execution.qa_result_code,
            Q::B4RegistryMandatoryPositiveMissing
                | Q::B4RegistryCaseIdDuplicate
                | Q::B4RegistryPositiveOrderInvalid
                | Q::B4RegistryPositiveLabelInvalid
                | Q::B4RegistryNegativeClassUnknown
                | Q::B4RegistryUnknownField
                | Q::B4RegistryNoncanonicalJcs
        ),
        S::NegativeBindingIndex => matches!(
            execution.qa_result_code,
            Q::B4RegistryCaseIdDuplicate | Q::B4NegativePlanRegistryBijectionMismatch
        ),
        S::CorpusClosure => matches!(
            execution.qa_result_code,
            Q::B4CorpusRepresentativeStratumMissing | Q::B4CorpusExtraFile
        ),
    };
    ensure!(
        result_surface_allowed,
        "B4 QA result code contradicts its execution surface"
    );
    Ok(())
}

fn validate_materialization_contract(
    case_id: &str,
    execution: &B4NegativePlanExecutionV1,
) -> Result<()> {
    use B4MaterializationDomain as D;
    use B4NegativeExecutionSurface as S;
    use B4NegativePlanFixture as F;

    validate_lower_kebab(&execution.base_selector_id, "B4 base selector ID")?;
    let expected_domain = materialization_domain_for(case_id)
        .context("B4 execution case has no materialization domain")?;
    ensure!(
        execution.materialization_domain == expected_domain,
        "B4 execution uses the wrong materialization domain"
    );
    let expected_selector = base_selector_id_for(case_id, &execution.variant_id)
        .context("B4 execution case/variant has no base selector")?;
    ensure!(
        execution.base_selector_id == expected_selector,
        "B4 execution uses the wrong base selector"
    );

    let domain_surface_allowed = match execution.materialization_domain {
        D::VerifierInput => matches!(
            execution.execution_surface,
            S::OpcodePreflight
                | S::RawStatementClaimBinding
                | S::RawSealShape
                | S::Risc0ParserInternal
                | S::Risc0CryptographicVerifier
                | S::TerminalPolicy
                | S::ReceiptClaimPolicy
                | S::AncestryReplay
        ),
        D::ArtifactValidator => matches!(
            execution.execution_surface,
            S::TerminalPolicy
                | S::ProfileManifestCodec
                | S::InitialProfileTarget
                | S::ProfileArtifactEnvelope
                | S::ActivatedProfilePackage
                | S::TerminalFixtureCatalog
                | S::SequenceSubjectCatalog
                | S::TerminalMetadata
                | S::ProfileIdPreimage
                | S::CandidateRegistry
                | S::NegativeBindingIndex
        ),
        D::TreeValidator => execution.execution_surface == S::CorpusClosure,
    };
    ensure!(
        domain_surface_allowed,
        "B4 materialization domain contradicts its execution surface"
    );
    let domain_fixture_allowed = match execution.materialization_domain {
        D::VerifierInput => !matches!(
            execution.fixture,
            F::TerminalFixtureCatalogV1
                | F::SequenceSubjectCatalogV1
                | F::StockControlTableV1
                | F::StockExcludedControlTableV1
                | F::Risc0V3SuccinctPackageV1
                | F::B4CandidateCorpusV1
        ),
        D::ArtifactValidator => matches!(
            execution.fixture,
            F::TerminalFixtureCatalogV1
                | F::SequenceSubjectCatalogV1
                | F::TerminalJoin
                | F::StockControlTableV1
                | F::StockExcludedControlTableV1
                | F::Risc0V3SuccinctPackageV1
                | F::B4CandidateCorpusV1
        ),
        D::TreeValidator => execution.fixture == F::B4CandidateCorpusV1,
    };
    ensure!(
        domain_fixture_allowed,
        "B4 materialization domain contradicts its base fixture"
    );
    Ok(())
}

static EXPECTED_GROUPS: LazyLock<[ExpectedGroup; B4_NEGATIVE_PLAN_GROUP_COUNT]> =
    LazyLock::new(|| {
        [
            group(
                "statement-field-byte-sweep",
                B4NegativePlanClass::StatementBinding,
                B4NegativePlanFixture::LiftPo215ReferenceStatementV1,
                B4NegativeQaResultCode::RawSealClaimMismatch,
                5,
            ),
            group(
                "statement-profile-id-byte-order",
                B4NegativePlanClass::StatementBinding,
                B4NegativePlanFixture::LiftPo215,
                B4NegativeQaResultCode::RawSealClaimMismatch,
                1,
            ),
            group(
                "statement-program-id-byte-order",
                B4NegativePlanClass::StatementBinding,
                B4NegativePlanFixture::LiftPo215,
                B4NegativeQaResultCode::RawSealClaimMismatch,
                1,
            ),
            group(
                "opcode-profile-id-length-sweep",
                B4NegativePlanClass::StatementBinding,
                B4NegativePlanFixture::LiftPo215OpcodeInputsV1,
                B4NegativeQaResultCode::OpcodeProfileIdLengthInvalid,
                2,
            ),
            group(
                "opcode-program-id-length-sweep",
                B4NegativePlanClass::StatementBinding,
                B4NegativePlanFixture::LiftPo215OpcodeInputsV1,
                B4NegativeQaResultCode::OpcodeProgramIdLengthInvalid,
                2,
            ),
            group(
                "terminal-fixture-catalog-binding-sweep",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::TerminalFixtureCatalogV1,
                B4NegativeQaResultCode::B4TerminalFixtureCatalogBindingMismatch,
                3,
            ),
            group(
                "sequence-subject-provenance-target-sweep",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::SequenceSubjectCatalogV1,
                B4NegativeQaResultCode::B4SequenceSubjectProvenanceMismatch,
                5,
            ),
            group(
                "statement-payload-over-maximum",
                B4NegativePlanClass::StatementBinding,
                B4NegativePlanFixture::LiftPo215OpcodeInputsV1,
                B4NegativeQaResultCode::OpcodeApplicationPayloadTooLarge,
                1,
            ),
            group(
                "proof-chunk-count-sweep",
                B4NegativePlanClass::ProofTransport,
                B4NegativePlanFixture::LiftPo215,
                B4NegativeQaResultCode::OpcodeProofChunkCountInvalid,
                2,
            ),
            group(
                "proof-empty-chunk",
                B4NegativePlanClass::ProofTransport,
                B4NegativePlanFixture::LiftPo215,
                B4NegativeQaResultCode::OpcodeProofChunkLengthInvalid,
                1,
            ),
            group(
                "proof-boundary-shift-sweep",
                B4NegativePlanClass::ProofTransport,
                B4NegativePlanFixture::LiftPo215,
                B4NegativeQaResultCode::OpcodeProofChunkLengthInvalid,
                6,
            ),
            group(
                "proof-chunks-reordered",
                B4NegativePlanClass::ProofTransport,
                B4NegativePlanFixture::LiftPo215,
                B4NegativeQaResultCode::RawSealWordNotReduced,
                1,
            ),
            group(
                "proof-seal-truncated-byte",
                B4NegativePlanClass::ProofTransport,
                B4NegativePlanFixture::LiftPo215,
                B4NegativeQaResultCode::OpcodeProofChunkLengthInvalid,
                1,
            ),
            group(
                "proof-seal-trailing-byte",
                B4NegativePlanClass::ProofTransport,
                B4NegativePlanFixture::LiftPo215,
                B4NegativeQaResultCode::OpcodeProofChunkLengthInvalid,
                1,
            ),
            group(
                "proof-seal-trailing-word",
                B4NegativePlanClass::ProofTransport,
                B4NegativePlanFixture::LiftPo215,
                B4NegativeQaResultCode::OpcodeProofChunkLengthInvalid,
                1,
            ),
            group(
                "outer-root-padding-sweep",
                B4NegativePlanClass::CanonicalOuterWords,
                B4NegativePlanFixture::LiftPo215,
                B4NegativeQaResultCode::RawSealNonzeroRootPadding,
                8,
            ),
            group(
                "outer-claim-halfword-overflow-sweep",
                B4NegativePlanClass::CanonicalOuterWords,
                B4NegativePlanFixture::LiftPo215,
                B4NegativeQaResultCode::RawSealClaimHalfwordOutOfRange,
                16,
            ),
            group(
                "outer-field-modulus-role-sweep",
                B4NegativePlanClass::CanonicalOuterWords,
                B4NegativePlanFixture::LiftPo215,
                B4NegativeQaResultCode::RawSealWordNotReduced,
                7,
            ),
            group(
                "outer-field-byte-order-role-sweep",
                B4NegativePlanClass::CanonicalOuterWords,
                B4NegativePlanFixture::LiftPo215,
                B4NegativeQaResultCode::B4ByteOrderRejectedAtBoundCheckpoint,
                7,
            ),
            group(
                "outer-po2-montgomery-encoding",
                B4NegativePlanClass::CanonicalOuterWords,
                B4NegativePlanFixture::LiftPo215,
                B4NegativeQaResultCode::RawSealWrongOuterPo2,
                1,
            ),
            group(
                "parser-phase-truncation-sweep",
                B4NegativePlanClass::ParserPhases,
                B4NegativePlanFixture::LiftPo215ParserOracle,
                B4NegativeQaResultCode::B4ParserUnexpectedEofAtPhase,
                36,
            ),
            group(
                "terminal-inner-root-mismatch",
                B4NegativePlanClass::TerminalPolicy,
                B4NegativePlanFixture::AlternateRootLiftPo215V1,
                B4NegativeQaResultCode::RawSealInnerControlRootMismatch,
                1,
            ),
            group(
                "terminal-outer-po2-mismatch",
                B4NegativePlanClass::TerminalPolicy,
                B4NegativePlanFixture::LiftPo215,
                B4NegativeQaResultCode::RawSealWrongOuterPo2,
                1,
            ),
            group(
                "terminal-metadata-field-sweep",
                B4NegativePlanClass::TerminalPolicy,
                B4NegativePlanFixture::TerminalJoin,
                B4NegativeQaResultCode::B4TerminalMetadataMismatch,
                3,
            ),
            group(
                "terminal-control-id-unknown",
                B4NegativePlanClass::TerminalPolicy,
                B4NegativePlanFixture::StockControlTableV1,
                B4NegativeQaResultCode::RawSealControlIdNotAllowed,
                1,
            ),
            group(
                "terminal-excluded-control-id-sweep",
                B4NegativePlanClass::TerminalPolicy,
                B4NegativePlanFixture::StockExcludedControlTableV1,
                B4NegativeQaResultCode::RawSealControlIdNotAllowed,
                17,
            ),
            group(
                "terminal-excluded-shipping-family-sweep",
                B4NegativePlanClass::TerminalPolicy,
                B4NegativePlanFixture::ExcludedFamilyReceiptsV1,
                B4NegativeQaResultCode::RawSealControlIdNotAllowed,
                8,
            ),
            group(
                "claim-final-status-non-ok",
                B4NegativePlanClass::ClaimSemantics,
                B4NegativePlanFixture::AllowedTerminalNonOkV1,
                B4NegativeQaResultCode::RawSealClaimMismatch,
                1,
            ),
            group(
                "claim-final-assumptions-nonempty",
                B4NegativePlanClass::ClaimSemantics,
                B4NegativePlanFixture::Case9ConditionalReceiptV1,
                B4NegativeQaResultCode::RawSealClaimMismatch,
                1,
            ),
            group(
                "claim-edge-family-sweep",
                B4NegativePlanClass::ClaimSemantics,
                B4NegativePlanFixture::JoinResolveEdgeSetV1,
                B4NegativeQaResultCode::B4AncestryClaimEdgeMismatch,
                3,
            ),
            group(
                "resolve-explicit-field-sweep",
                B4NegativePlanClass::ResolveSemantics,
                B4NegativePlanFixture::Case9TypedAncestryV1,
                B4NegativeQaResultCode::B4ResolveExplicitSemanticsMismatch,
                5,
            ),
            group(
                "resolve-zero-root-field-sweep",
                B4NegativePlanClass::ResolveSemantics,
                B4NegativePlanFixture::Case10TypedAncestryV1,
                B4NegativeQaResultCode::B4ResolveZeroRootSemanticsMismatch,
                4,
            ),
            group(
                "resolve-assumption-inventory-sweep",
                B4NegativePlanClass::ResolveSemantics,
                B4NegativePlanFixture::Case9TypedAncestryV1,
                B4NegativeQaResultCode::B4ResolveAssumptionInventoryInvalid,
                3,
            ),
            group(
                "crypto-early-check-value-mismatch",
                B4NegativePlanClass::CryptographicRejectionDepth,
                B4NegativePlanFixture::LiftPo215,
                B4NegativeQaResultCode::B4CryptoEarlyCheckpointRejected,
                1,
            ),
            group(
                "crypto-middle-fri-round-two-mismatch",
                B4NegativePlanClass::CryptographicRejectionDepth,
                B4NegativePlanFixture::LiftPo215,
                B4NegativeQaResultCode::B4CryptoMiddleCheckpointRejected,
                1,
            ),
            group(
                "crypto-late-final-opening-mismatch",
                B4NegativePlanClass::CryptographicRejectionDepth,
                B4NegativePlanFixture::LiftPo215,
                B4NegativeQaResultCode::B4CryptoLateCheckpointRejected,
                1,
            ),
            group(
                "crypto-final-expected-claim-mismatch",
                B4NegativePlanClass::CryptographicRejectionDepth,
                B4NegativePlanFixture::LiftPo215,
                B4NegativeQaResultCode::B4CryptoFinalCheckpointRejected,
                1,
            ),
            group(
                "profile-manifest-short",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::Risc0V3SuccinctPackageV1,
                B4NegativeQaResultCode::B4ProfileManifestLengthInvalid,
                1,
            ),
            group(
                "profile-manifest-trailing-byte",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::Risc0V3SuccinctPackageV1,
                B4NegativeQaResultCode::B4ProfileManifestLengthInvalid,
                1,
            ),
            group(
                "profile-manifest-version",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::Risc0V3SuccinctPackageV1,
                B4NegativeQaResultCode::B4ProfileManifestVersionUnsupported,
                1,
            ),
            group(
                "profile-manifest-exact-proof-bytes",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::Risc0V3SuccinctPackageV1,
                B4NegativeQaResultCode::B4ProfileExactProofBytesInvalid,
                1,
            ),
            group(
                "profile-manifest-maximum-payload",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::Risc0V3SuccinctPackageV1,
                B4NegativeQaResultCode::B4ProfileMaximumPayloadInvalid,
                1,
            ),
            group(
                "profile-manifest-outer-po2",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::Risc0V3SuccinctPackageV1,
                B4NegativeQaResultCode::B4ProfileOuterPo2Invalid,
                1,
            ),
            group(
                "profile-manifest-inner-control-root",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::Risc0V3SuccinctPackageV1,
                B4NegativeQaResultCode::B4ProfileIdentityMismatch,
                1,
            ),
            group(
                "profile-terminal-field-sweep",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::Risc0V3SuccinctPackageV1,
                B4NegativeQaResultCode::B4ProfileTerminalFieldInvalid,
                30,
            ),
            group(
                "profile-terminal-control-id-duplicate",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::Risc0V3SuccinctPackageV1,
                B4NegativeQaResultCode::B4ProfileTerminalControlIdDuplicate,
                1,
            ),
            group(
                "profile-terminal-controls-reordered",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::Risc0V3SuccinctPackageV1,
                B4NegativeQaResultCode::B4ProfileTerminalOrderInvalid,
                1,
            ),
            group(
                "profile-artifact-ref-field-sweep",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::Risc0V3SuccinctPackageV1,
                B4NegativeQaResultCode::B4ProfileArtifactReferenceInvalid,
                6,
            ),
            group(
                "profile-artifact-refs-reordered",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::Risc0V3SuccinctPackageV1,
                B4NegativeQaResultCode::B4ProfileArtifactKindPositionInvalid,
                1,
            ),
            group(
                "profile-artifact-bytes-sweep",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::Risc0V3SuccinctPackageV1,
                B4NegativeQaResultCode::B4ProfileArtifactDigestMismatch,
                2,
            ),
            group(
                "profile-id-mismatch",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::Risc0V3SuccinctPackageV1,
                B4NegativeQaResultCode::B4ProfileIdMismatch,
                1,
            ),
            group(
                "profile-id-preimage-mismatch",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::Risc0V3SuccinctPackageV1,
                B4NegativeQaResultCode::B4ProfileIdPreimageMismatch,
                1,
            ),
            group(
                "corpus-representative-stratum-omit-sweep",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::B4CandidateCorpusV1,
                B4NegativeQaResultCode::B4CorpusRepresentativeStratumMissing,
                20,
            ),
            group(
                "corpus-extra-file",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::B4CandidateCorpusV1,
                B4NegativeQaResultCode::B4CorpusExtraFile,
                1,
            ),
            group(
                "registry-positive-case-omit-sweep",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::B4CandidateCorpusV1,
                B4NegativeQaResultCode::B4RegistryMandatoryPositiveMissing,
                11,
            ),
            group(
                "registry-positive-case-id-duplicate",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::B4CandidateCorpusV1,
                B4NegativeQaResultCode::B4RegistryCaseIdDuplicate,
                1,
            ),
            group(
                "registry-negative-case-id-duplicate",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::B4CandidateCorpusV1,
                B4NegativeQaResultCode::B4RegistryCaseIdDuplicate,
                1,
            ),
            group(
                "registry-positive-cases-reordered",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::B4CandidateCorpusV1,
                B4NegativeQaResultCode::B4RegistryPositiveOrderInvalid,
                1,
            ),
            group(
                "registry-positive-case-relabel",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::B4CandidateCorpusV1,
                B4NegativeQaResultCode::B4RegistryPositiveLabelInvalid,
                1,
            ),
            group(
                "registry-negative-class-unknown",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::B4CandidateCorpusV1,
                B4NegativeQaResultCode::B4RegistryNegativeClassUnknown,
                1,
            ),
            group(
                "registry-unknown-field",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::B4CandidateCorpusV1,
                B4NegativeQaResultCode::B4RegistryUnknownField,
                1,
            ),
            group(
                "registry-noncanonical-jcs",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::B4CandidateCorpusV1,
                B4NegativeQaResultCode::B4RegistryNoncanonicalJcs,
                1,
            ),
            group(
                "negative-plan-registry-bijection-sweep",
                B4NegativePlanClass::ProfilePackageAndRegistry,
                B4NegativePlanFixture::B4CandidateCorpusV1,
                B4NegativeQaResultCode::B4NegativePlanRegistryBijectionMismatch,
                5,
            ),
        ]
    });

#[allow(
    clippy::match_same_arms,
    clippy::too_many_lines,
    reason = "the exhaustive variant table stays grouped and explicit for audit; merging arms would obscure the closed mapping"
)]
fn variant_ids_for(case_id: &str) -> &'static [&'static str] {
    match case_id {
        "statement-field-byte-sweep" => &[
            "chain-domain-byte-order-reversed",
            "profile-id",
            "program-id",
            "contract-id-byte-order-reversed",
            "application-payload",
        ],
        "statement-profile-id-byte-order" => &["profile-id"],
        "statement-program-id-byte-order" => &["program-id"],
        "opcode-profile-id-length-sweep" => &["thirty-one-bytes", "thirty-three-bytes"],
        "opcode-program-id-length-sweep" => &["thirty-one-bytes", "thirty-three-bytes"],
        "terminal-fixture-catalog-binding-sweep" => &["program-id", "claim-digest", "control-id"],
        "sequence-subject-provenance-target-sweep" => &[
            "registry-positive-cases",
            "registry-negative-cases",
            "registry-negative-classes",
            "profile-package-files",
            "proof-chunks",
        ],
        "statement-payload-over-maximum" => &["maximum-plus-one"],
        "proof-chunk-count-sweep" => &["three-chunks", "five-chunks"],
        "proof-empty-chunk" => &["fourth-chunk-empty"],
        "proof-boundary-shift-sweep" => &[
            "boundary-zero-left-short-right-long",
            "boundary-zero-left-long-right-short",
            "boundary-one-left-short-right-long",
            "boundary-one-left-long-right-short",
            "boundary-two-left-short-right-long",
            "boundary-two-left-long-right-short",
        ],
        "proof-chunks-reordered" => &["first-two-chunks-swapped"],
        "proof-seal-truncated-byte" => &["last-chunk-short-one-byte"],
        "proof-seal-trailing-byte" => &["last-chunk-long-one-byte"],
        "proof-seal-trailing-word" => &["last-chunk-long-one-word"],
        "outer-root-padding-sweep" => &[
            "padding-word-01",
            "padding-word-03",
            "padding-word-05",
            "padding-word-07",
            "padding-word-09",
            "padding-word-11",
            "padding-word-13",
            "padding-word-15",
        ],
        "outer-claim-halfword-overflow-sweep" => &[
            "claim-word-16",
            "claim-word-17",
            "claim-word-18",
            "claim-word-19",
            "claim-word-20",
            "claim-word-21",
            "claim-word-22",
            "claim-word-23",
            "claim-word-24",
            "claim-word-25",
            "claim-word-26",
            "claim-word-27",
            "claim-word-28",
            "claim-word-29",
            "claim-word-30",
            "claim-word-31",
        ],
        "outer-field-modulus-role-sweep" | "outer-field-byte-order-role-sweep" => &[
            "output-root",
            "output-claim",
            "merkle-top",
            "coefficient",
            "final-coefficient",
            "merkle-opening-leaf",
            "merkle-opening-sibling",
        ],
        "outer-po2-montgomery-encoding" => &["outer-po2-literal"],
        "parser-phase-truncation-sweep" => &[
            "output-before-read",
            "output-at-last-required-word",
            "outer-po2-before-read",
            "code-top-before-read",
            "code-top-at-last-required-word",
            "data-top-before-read",
            "data-top-at-last-required-word",
            "accum-top-before-read",
            "accum-top-at-last-required-word",
            "check-top-before-read",
            "check-top-at-last-required-word",
            "coeff-u-before-read",
            "coeff-u-at-last-required-word",
            "fri-round-one-top-before-read",
            "fri-round-one-top-at-last-required-word",
            "fri-round-two-top-before-read",
            "fri-round-two-top-at-last-required-word",
            "fri-round-three-top-before-read",
            "fri-round-three-top-at-last-required-word",
            "final-coefficients-before-read",
            "final-coefficients-at-last-required-word",
            "queries-before-read",
            "queries-at-last-required-word",
            "query-zero-accum-opening-at-last-required-word",
            "query-zero-code-opening-before-read",
            "query-zero-code-opening-at-last-required-word",
            "query-zero-data-opening-before-read",
            "query-zero-data-opening-at-last-required-word",
            "query-zero-check-opening-before-read",
            "query-zero-check-opening-at-last-required-word",
            "query-zero-fri-round-one-opening-before-read",
            "query-zero-fri-round-one-opening-at-last-required-word",
            "query-zero-fri-round-two-opening-before-read",
            "query-zero-fri-round-two-opening-at-last-required-word",
            "query-zero-fri-round-three-opening-before-read",
            "query-zero-fri-round-three-opening-at-last-required-word",
        ],
        "terminal-inner-root-mismatch" => &["inner-control-root"],
        "terminal-outer-po2-mismatch" => &["outer-po2"],
        "terminal-metadata-field-sweep" => &["kind", "parameter", "control-id"],
        "terminal-control-id-unknown" => &["unknown-control-id"],
        "terminal-excluded-control-id-sweep" => &[
            "identity",
            "join-povw",
            "join-unwrap-povw",
            "lift-po2-14",
            "lift-povw-po2-14",
            "lift-povw-po2-15",
            "lift-povw-po2-16",
            "lift-povw-po2-17",
            "lift-povw-po2-18",
            "lift-povw-po2-19",
            "lift-povw-po2-20",
            "lift-povw-po2-21",
            "lift-povw-po2-22",
            "resolve-povw",
            "resolve-unwrap-povw",
            "union",
            "unwrap-povw",
        ],
        "terminal-excluded-shipping-family-sweep" => &[
            "lift-po2-14",
            "lift-povw-po2-18",
            "join-povw",
            "join-unwrap-povw",
            "resolve-povw",
            "resolve-unwrap-povw",
            "union",
            "unwrap-povw",
        ],
        "claim-final-status-non-ok" => &["non-ok-status"],
        "claim-final-assumptions-nonempty" => &["nonempty-assumptions"],
        "claim-edge-family-sweep" => &[
            "terminal-join",
            "terminal-resolve-explicit-root",
            "resolve-zero-root-then-join",
        ],
        "resolve-explicit-field-sweep" => &[
            "declared-explicit-root",
            "assumption-claim",
            "assumption-receipt-root",
            "program-id",
            "final-claim",
        ],
        "resolve-zero-root-field-sweep" => &[
            "substituted-nonzero-root",
            "assumption-claim",
            "program-id",
            "final-claim",
        ],
        "resolve-assumption-inventory-sweep" => &[
            "missing-assumption",
            "extra-assumption",
            "pruned-assumption",
        ],
        "crypto-early-check-value-mismatch" => &["check-value"],
        "crypto-middle-fri-round-two-mismatch" => &["fri-query-00"],
        "crypto-late-final-opening-mismatch" => &["fri-query-00"],
        "crypto-final-expected-claim-mismatch" => &["claim-query-49"],
        "profile-manifest-short" => &["manifest-unexpected-eof"],
        "profile-manifest-trailing-byte" => &["manifest-trailing-byte"],
        "profile-manifest-version" => &["format-version"],
        "profile-manifest-exact-proof-bytes" => &["exact-proof-bytes"],
        "profile-manifest-maximum-payload" => &["maximum-payload"],
        "profile-manifest-outer-po2" => &["outer-po2"],
        "profile-manifest-inner-control-root" => &["inner-control-root"],
        "profile-terminal-field-sweep" => &[
            "lift-po2-15-kind",
            "lift-po2-15-parameter",
            "lift-po2-15-control-id",
            "lift-po2-16-kind",
            "lift-po2-16-parameter",
            "lift-po2-16-control-id",
            "lift-po2-17-kind",
            "lift-po2-17-parameter",
            "lift-po2-17-control-id",
            "lift-po2-18-kind",
            "lift-po2-18-parameter",
            "lift-po2-18-control-id",
            "lift-po2-19-kind",
            "lift-po2-19-parameter",
            "lift-po2-19-control-id",
            "lift-po2-20-kind",
            "lift-po2-20-parameter",
            "lift-po2-20-control-id",
            "lift-po2-21-kind",
            "lift-po2-21-parameter",
            "lift-po2-21-control-id",
            "lift-po2-22-kind",
            "lift-po2-22-parameter",
            "lift-po2-22-control-id",
            "terminal-join-kind",
            "terminal-join-parameter",
            "terminal-join-control-id",
            "terminal-resolve-kind",
            "terminal-resolve-parameter",
            "terminal-resolve-control-id",
        ],
        "profile-terminal-control-id-duplicate" => &["first-two-control-ids"],
        "profile-terminal-controls-reordered" => &["first-two-controls"],
        "profile-artifact-ref-field-sweep" => &[
            "algorithm-kind",
            "algorithm-length",
            "algorithm-digest",
            "binary-data-kind",
            "binary-data-length",
            "binary-data-digest",
        ],
        "profile-artifact-refs-reordered" => &["algorithm-and-binary-data"],
        "profile-artifact-bytes-sweep" => &["algorithm", "constants"],
        "profile-id-mismatch" => &["profile-id"],
        "profile-id-preimage-mismatch" => &["profile-id-preimage"],
        // These are representative structural strata, not a substitute for
        // enumerating every exact required path. Final closure derives the
        // exhaustive per-path omission sweep from the frozen tree manifest.
        "corpus-representative-stratum-omit-sweep" => &[
            "profile-manifest",
            "statement-bundle-manifest",
            "guest-elf",
            "source-lock",
            "proof-generator",
            "rust-verifier",
            "jvm-verifier",
            "positive-raw-seal",
            "recursive-ancestry",
            "negative-plan",
            "subject-catalog",
            "terminal-fixture-catalog",
            "positive-registry",
            "expanded-negative-registry",
            "mutation-identities",
            "rust-negative-results",
            "jvm-negative-results",
            "semantic-report",
            "tree-manifest",
            "lock",
        ],
        "corpus-extra-file" => &["unregistered-file"],
        "registry-positive-case-omit-sweep" => &[
            "lift-po2-15",
            "lift-po2-16",
            "lift-po2-17",
            "lift-po2-18",
            "lift-po2-19",
            "lift-po2-20",
            "lift-po2-21",
            "lift-po2-22",
            "terminal-join",
            "terminal-resolve-explicit-root",
            "resolve-zero-root-then-join",
        ],
        "registry-positive-case-id-duplicate" => &["positive-case-id"],
        "registry-negative-case-id-duplicate" => &["negative-case-id"],
        "registry-positive-cases-reordered" => &["first-two-positive-cases"],
        "registry-positive-case-relabel" => &["terminal-resolve-explicit-root"],
        "registry-negative-class-unknown" => &["unknown-negative-class"],
        "registry-unknown-field" => &["unknown-registry-field"],
        "registry-noncanonical-jcs" => &["noncanonical-registry-source"],
        "negative-plan-registry-bijection-sweep" => &[
            "missing-execution",
            "unexpected-execution",
            "wrong-base-selector-binding",
            "wrong-materialization-domain",
            "wrong-materialization-binding",
        ],
        _ => unreachable!("closed B4 negative-plan group ID"),
    }
}

fn validate_lower_kebab(value: &str, label: &str) -> Result<()> {
    let bytes = value.as_bytes();
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_IDENTIFIER_BYTES,
        "{label} is empty or too long"
    );
    ensure!(
        bytes[0].is_ascii_lowercase() && bytes[bytes.len() - 1].is_ascii_alphanumeric(),
        "{label} must start with a lowercase letter and end with a lowercase letter or digit"
    );
    ensure!(
        bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-'),
        "{label} is not lower-kebab ASCII"
    );
    ensure!(!value.contains("--"), "{label} contains an empty component");
    Ok(())
}

fn validate_non_wildcard_variant_id(value: &str) -> Result<()> {
    const FORBIDDEN_COMPONENTS: [&str; 6] = ["all", "any", "every", "wildcard", "todo", "tbd"];
    ensure!(
        !value
            .split('-')
            .any(|component| FORBIDDEN_COMPONENTS.contains(&component)),
        "B4 negative-plan variant ID contains a wildcard or placeholder component"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn canonical_plan() -> Eip0045B4NegativePlanV1 {
        Eip0045B4NegativePlanV1::canonical().unwrap()
    }

    fn canonical_value() -> Value {
        serde_json::to_value(canonical_plan()).unwrap()
    }

    #[test]
    fn exact_inventory_contains_all_63_groups_and_254_executions() {
        let plan = canonical_plan();
        plan.validate().unwrap();
        assert_eq!(plan.groups.len(), B4_NEGATIVE_PLAN_GROUP_COUNT);
        assert_eq!(plan.total_variant_count, B4_NEGATIVE_PLAN_VARIANT_COUNT);

        for (index, (actual, expected)) in
            plan.groups.iter().zip(EXPECTED_GROUPS.iter()).enumerate()
        {
            assert_eq!(actual, &expected.materialize(), "group index {index}");
            assert_eq!(
                actual.executions.len(),
                usize::from(actual.variant_count),
                "variant domain at group index {index}"
            );
        }

        let execution_ids: BTreeSet<_> = plan
            .groups
            .iter()
            .flat_map(|group| {
                group
                    .executions
                    .iter()
                    .map(|execution| &execution.execution_id)
            })
            .collect();
        assert_eq!(
            execution_ids.len(),
            usize::from(B4_NEGATIVE_PLAN_VARIANT_COUNT)
        );

        let class_totals = [
            (B4NegativePlanClass::StatementBinding, 6_usize, 12_u16),
            (B4NegativePlanClass::ProofTransport, 7, 13),
            (B4NegativePlanClass::CanonicalOuterWords, 5, 39),
            (B4NegativePlanClass::ParserPhases, 1, 36),
            (B4NegativePlanClass::TerminalPolicy, 6, 31),
            (B4NegativePlanClass::ClaimSemantics, 3, 5),
            (B4NegativePlanClass::ResolveSemantics, 3, 12),
            (B4NegativePlanClass::CryptographicRejectionDepth, 4, 4),
            (B4NegativePlanClass::ProfilePackageAndRegistry, 28, 102),
        ];
        for (class, expected_groups, expected_variants) in class_totals {
            let matching: Vec<_> = plan
                .groups
                .iter()
                .filter(|group| group.class == class)
                .collect();
            assert_eq!(matching.len(), expected_groups);
            assert_eq!(
                matching
                    .iter()
                    .map(|group| group.variant_count)
                    .sum::<u16>(),
                expected_variants
            );
        }
    }

    #[test]
    fn inner_root_mismatch_selects_only_the_fixed_valid_alternate_root_fixture() {
        let plan = canonical_plan();
        let group = plan
            .groups
            .iter()
            .find(|group| group.case_id == "terminal-inner-root-mismatch")
            .unwrap();
        assert_eq!(
            group.executions.as_slice(),
            [B4NegativePlanExecutionV1 {
                base_selector_id: "alternate-root-lift-po2-15-v1".to_owned(),
                execution_id: "terminal-inner-root-mismatch--inner-control-root".to_owned(),
                execution_surface: B4NegativeExecutionSurface::RawSealShape,
                fixture: B4NegativePlanFixture::AlternateRootLiftPo215V1,
                materialization_domain: B4MaterializationDomain::VerifierInput,
                qa_result_code: B4NegativeQaResultCode::RawSealInnerControlRootMismatch,
                parser_truncation_words: None,
                variant_id: "inner-control-root".to_owned(),
            }]
        );
    }

    #[test]
    fn materialization_domains_have_closed_group_and_execution_totals() {
        let plan = canonical_plan();
        let expected = [
            (
                B4MaterializationDomain::VerifierInput,
                B4_VERIFIER_INPUT_GROUP_COUNT,
                B4_VERIFIER_INPUT_EXECUTION_COUNT,
            ),
            (
                B4MaterializationDomain::ArtifactValidator,
                B4_ARTIFACT_VALIDATOR_GROUP_COUNT,
                B4_ARTIFACT_VALIDATOR_EXECUTION_COUNT,
            ),
            (
                B4MaterializationDomain::TreeValidator,
                B4_TREE_VALIDATOR_GROUP_COUNT,
                B4_TREE_VALIDATOR_EXECUTION_COUNT,
            ),
        ];

        for (domain, expected_groups, expected_executions) in expected {
            let groups = plan
                .groups
                .iter()
                .filter(|group| {
                    group
                        .executions
                        .iter()
                        .all(|execution| execution.materialization_domain == domain)
                })
                .collect::<Vec<_>>();
            assert_eq!(groups.len(), expected_groups);
            assert_eq!(
                groups.iter().map(|group| group.variant_count).sum::<u16>(),
                expected_executions
            );
        }
    }

    #[test]
    fn profile_field_sweeps_bind_each_variant_to_its_first_typed_consumer() {
        use B4NegativeExecutionSurface as S;

        let plan = canonical_plan();
        let terminal = plan
            .groups
            .iter()
            .find(|group| group.case_id == "profile-terminal-field-sweep")
            .unwrap();
        assert_eq!(terminal.executions.len(), 30);
        for execution in &terminal.executions {
            let expected = if execution.variant_id.ends_with("-control-id") {
                S::InitialProfileTarget
            } else {
                assert!(
                    execution.variant_id.ends_with("-kind")
                        || execution.variant_id.ends_with("-parameter")
                );
                S::ProfileManifestCodec
            };
            assert_eq!(execution.execution_surface, expected);
        }
        assert_eq!(
            terminal
                .executions
                .iter()
                .filter(|execution| execution.execution_surface == S::ProfileManifestCodec)
                .count(),
            20
        );
        assert_eq!(
            terminal
                .executions
                .iter()
                .filter(|execution| execution.execution_surface == S::InitialProfileTarget)
                .count(),
            10
        );

        let artifact = plan
            .groups
            .iter()
            .find(|group| group.case_id == "profile-artifact-ref-field-sweep")
            .unwrap();
        assert_eq!(artifact.executions.len(), 6);
        for execution in &artifact.executions {
            let expected = if execution.variant_id.ends_with("-kind") {
                S::ProfileManifestCodec
            } else {
                assert!(
                    execution.variant_id.ends_with("-length")
                        || execution.variant_id.ends_with("-digest")
                );
                S::ProfileArtifactEnvelope
            };
            assert_eq!(execution.execution_surface, expected);
        }
    }

    #[test]
    fn first_two_chunk_swap_tracks_the_observed_field_reduction_boundary() {
        let plan = canonical_plan();
        let group = plan
            .groups
            .iter()
            .find(|group| group.case_id == "proof-chunks-reordered")
            .unwrap();
        let [execution] = group.executions.as_slice() else {
            panic!("chunk-swap group must retain exactly one execution");
        };

        assert_eq!(execution.variant_id, "first-two-chunks-swapped");
        assert_eq!(
            execution.execution_id,
            "proof-chunks-reordered--first-two-chunks-swapped"
        );
        assert_eq!(
            execution.execution_surface,
            B4NegativeExecutionSurface::RawSealShape
        );
        assert_eq!(
            execution.qa_result_code,
            B4NegativeQaResultCode::RawSealWordNotReduced
        );
    }

    #[test]
    fn artifact_corpus_grammars_have_six_explicit_surfaces_and_no_hidden_subdispatch() {
        use B4NegativeExecutionSurface as S;

        let plan = canonical_plan();
        let expected = [
            (
                "terminal-fixture-catalog-binding-sweep",
                S::TerminalFixtureCatalog,
            ),
            (
                "sequence-subject-provenance-target-sweep",
                S::SequenceSubjectCatalog,
            ),
            ("terminal-metadata-field-sweep", S::TerminalMetadata),
            ("profile-id-preimage-mismatch", S::ProfileIdPreimage),
            ("registry-positive-case-id-duplicate", S::CandidateRegistry),
            (
                "registry-negative-case-id-duplicate",
                S::NegativeBindingIndex,
            ),
            (
                "negative-plan-registry-bijection-sweep",
                S::NegativeBindingIndex,
            ),
        ];
        for (case_id, surface) in expected {
            let group = plan
                .groups
                .iter()
                .find(|group| group.case_id == case_id)
                .unwrap();
            assert!(group.executions.iter().all(|execution| {
                execution.materialization_domain == B4MaterializationDomain::ArtifactValidator
                    && execution.execution_surface == surface
            }));
        }
        assert!(
            plan.groups
                .iter()
                .flat_map(|group| &group.executions)
                .all(|execution| {
                    execution.materialization_domain != B4MaterializationDomain::ArtifactValidator
                        || execution.execution_surface != S::CorpusClosure
                })
        );
    }

    #[test]
    fn base_selectors_distinguish_tree_registry_result_and_shipping_authorities() {
        let plan = canonical_plan();

        for case_id in [
            "corpus-representative-stratum-omit-sweep",
            "corpus-extra-file",
        ] {
            let group = plan
                .groups
                .iter()
                .find(|group| group.case_id == case_id)
                .unwrap();
            assert!(group.executions.iter().all(|execution| {
                execution.materialization_domain == B4MaterializationDomain::TreeValidator
                    && execution.base_selector_id == "abstract-corpus-strata-v1"
            }));
        }

        for case_id in [
            "registry-positive-case-omit-sweep",
            "registry-positive-cases-reordered",
            "registry-positive-case-relabel",
            "registry-negative-class-unknown",
            "registry-unknown-field",
            "registry-noncanonical-jcs",
        ] {
            let group = plan
                .groups
                .iter()
                .find(|group| group.case_id == case_id)
                .unwrap();
            assert!(group.executions.iter().all(|execution| {
                execution.materialization_domain == B4MaterializationDomain::ArtifactValidator
                    && execution.base_selector_id == "synthetic-registry-skeleton-v1"
            }));
        }

        let positive_duplicate_id = plan
            .groups
            .iter()
            .find(|group| group.case_id == "registry-positive-case-id-duplicate")
            .unwrap();
        assert_eq!(
            positive_duplicate_id.executions[0].base_selector_id,
            "synthetic-registry-skeleton-v1"
        );
        let negative_duplicate_id = plan
            .groups
            .iter()
            .find(|group| group.case_id == "registry-negative-case-id-duplicate")
            .unwrap();
        assert_eq!(
            negative_duplicate_id.executions[0].base_selector_id,
            "synthetic-negative-binding-index-v1"
        );

        let bijection = plan
            .groups
            .iter()
            .find(|group| group.case_id == "negative-plan-registry-bijection-sweep")
            .unwrap();
        assert!(bijection.executions.iter().all(|execution| {
            execution.base_selector_id == "synthetic-negative-binding-index-v1"
        }));

        let shipping = plan
            .groups
            .iter()
            .find(|group| group.case_id == "terminal-excluded-shipping-family-sweep")
            .unwrap();
        assert_eq!(shipping.executions.len(), 8);
        assert!(shipping.executions.iter().all(|execution| {
            execution.materialization_domain == B4MaterializationDomain::VerifierInput
                && execution.base_selector_id == execution.variant_id
        }));
    }

    #[test]
    fn rejects_materialization_domain_and_base_selector_drift() {
        let mut wrong_domain = canonical_plan();
        wrong_domain.groups[0].executions[0].materialization_domain =
            B4MaterializationDomain::ArtifactValidator;
        assert!(wrong_domain.validate().is_err());

        let mut wrong_selector = canonical_plan();
        wrong_selector.groups[0].executions[0].base_selector_id = "lift-po2-15".to_owned();
        assert!(wrong_selector.validate().is_err());

        let mut table_as_verifier_input = canonical_plan();
        let table = table_as_verifier_input
            .groups
            .iter_mut()
            .find(|group| group.case_id == "terminal-excluded-control-id-sweep")
            .unwrap();
        table.executions[0].materialization_domain = B4MaterializationDomain::VerifierInput;
        assert!(table_as_verifier_input.validate().is_err());
    }

    #[test]
    fn canonical_jcs_round_trip_is_byte_exact() {
        let plan = canonical_plan();
        let bytes = plan.to_canonical_jcs().unwrap();
        assert_eq!(
            Eip0045B4NegativePlanV1::from_canonical_jcs(&bytes).unwrap(),
            plan
        );
    }

    #[test]
    fn rejects_wrong_format_and_version() {
        let mut wrong_format = canonical_plan();
        wrong_format.format.push_str("Other");
        assert!(wrong_format.validate().is_err());

        let mut wrong_version = canonical_plan();
        wrong_version.format_version += 1;
        assert!(wrong_version.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_group_and_execution_ids() {
        let mut plan = canonical_plan();
        let duplicate_case_id = plan.groups[0].case_id.clone();
        plan.groups[1].case_id = duplicate_case_id;
        plan.groups[1].executions[0].execution_id =
            plan.groups[0].executions[0].execution_id.clone();
        assert!(plan.validate().is_err());
    }

    #[test]
    fn rejects_noncanonical_group_order() {
        let mut plan = canonical_plan();
        plan.groups.swap(0, 1);
        assert!(plan.validate().is_err());
    }

    #[test]
    fn rejects_unknown_top_level_and_nested_fields() {
        let mut top = canonical_value();
        top.as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), Value::Bool(true));
        let top = canonical_json_bytes(&top).unwrap();
        assert!(Eip0045B4NegativePlanV1::from_canonical_jcs(&top).is_err());

        let mut nested = canonical_value();
        nested["groups"][0]
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), Value::Bool(true));
        let nested = canonical_json_bytes(&nested).unwrap();
        assert!(Eip0045B4NegativePlanV1::from_canonical_jcs(&nested).is_err());

        let mut execution = canonical_value();
        execution["groups"][0]["executions"][0]
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), Value::Bool(true));
        let execution = canonical_json_bytes(&execution).unwrap();
        assert!(Eip0045B4NegativePlanV1::from_canonical_jcs(&execution).is_err());
    }

    #[test]
    fn rejects_noncanonical_json() {
        let pretty = serde_json::to_vec_pretty(&canonical_plan()).unwrap();
        assert!(Eip0045B4NegativePlanV1::from_canonical_jcs(&pretty).is_err());
    }

    #[test]
    fn rejects_wrong_declared_sum_and_wrong_group_count() {
        let mut wrong_sum = canonical_plan();
        wrong_sum.total_variant_count -= 1;
        assert!(wrong_sum.validate().is_err());

        let mut wrong_group_count = canonical_plan();
        wrong_group_count.groups[0].variant_count += 1;
        wrong_group_count.total_variant_count += 1;
        assert!(wrong_group_count.validate().is_err());
    }

    #[test]
    fn rejects_missing_duplicate_reordered_and_wildcard_variant_ids() {
        let mut missing = canonical_plan();
        missing.groups[0].executions.pop();
        assert!(missing.validate().is_err());

        let mut duplicate = canonical_plan();
        let duplicate_variant_id = duplicate.groups[0].executions[0].variant_id.clone();
        duplicate.groups[0].executions[1].variant_id = duplicate_variant_id;
        assert!(duplicate.validate().is_err());

        let mut reordered = canonical_plan();
        reordered.groups[0].executions.swap(0, 1);
        assert!(reordered.validate().is_err());

        let mut wildcard = canonical_plan();
        wildcard.groups[0].executions[0].variant_id = "every-field".to_owned();
        assert!(wildcard.validate().is_err());
    }

    #[test]
    fn rejects_wrong_qa_result_code() {
        let mut plan = canonical_plan();
        plan.groups[0].executions[0].qa_result_code =
            B4NegativeQaResultCode::OpcodeProofChunkCountInvalid;
        assert!(plan.validate().is_err());
    }

    #[test]
    fn execution_ids_fixtures_surfaces_and_parser_offsets_are_exact_and_unique() {
        let plan = canonical_plan();
        let executions = plan
            .groups
            .iter()
            .flat_map(|group| {
                group
                    .executions
                    .iter()
                    .map(move |execution| (group, execution))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            executions.len(),
            usize::from(B4_NEGATIVE_PLAN_VARIANT_COUNT)
        );
        let ids = executions
            .iter()
            .map(|(_, execution)| execution.execution_id.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), executions.len());
        assert!(executions.iter().all(|(group, execution)| {
            execution.execution_id == format!("{}--{}", group.case_id, execution.variant_id)
                && validate_execution_contract(&group.case_id, group.class, execution).is_ok()
        }));

        let parser_offsets = executions
            .iter()
            .filter_map(|(_, execution)| execution.parser_truncation_words)
            .collect::<Vec<_>>();
        assert_eq!(parser_offsets.len(), 36);
        assert_eq!(
            parser_offsets
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len(),
            parser_offsets.len()
        );
    }

    #[test]
    fn parser_offsets_equal_the_frozen_seal_layout_with_two_collapsed_aliases() {
        use crate::seal::{QUERY_WORD_SPANS, TOP_LEVEL_WORD_SPANS};

        let mut derived = BTreeSet::new();
        for span in TOP_LEVEL_WORD_SPANS {
            assert!(!span.is_empty());
            derived.insert(u32::try_from(span.start).unwrap());
            derived.insert(u32::try_from(span.end - 1).unwrap());
        }

        let queries = TOP_LEVEL_WORD_SPANS
            .iter()
            .find(|span| span.name == "queries")
            .unwrap();
        for span in QUERY_WORD_SPANS {
            assert!(!span.is_empty());
            derived.insert(u32::try_from(queries.start + span.start).unwrap());
            derived.insert(u32::try_from(queries.start + span.end - 1).unwrap());
        }

        let outer_po2 = TOP_LEVEL_WORD_SPANS
            .iter()
            .find(|span| span.name == "outerPo2")
            .unwrap();
        assert_eq!(outer_po2.start, outer_po2.end - 1);
        assert_eq!(queries.start, queries.start + QUERY_WORD_SPANS[0].start);
        assert_eq!(derived.len(), 36);

        let plan = canonical_plan();
        let actual = plan
            .groups
            .iter()
            .flat_map(|group| &group.executions)
            .filter_map(|execution| execution.parser_truncation_words)
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, derived);
    }

    #[test]
    fn rejects_wrong_fixture_surface_and_parser_offset() {
        let mut wrong_fixture = canonical_plan();
        wrong_fixture.groups[0].executions[0].fixture = B4NegativePlanFixture::LiftPo215;
        assert!(wrong_fixture.validate().is_err());

        let mut wrong_surface = canonical_plan();
        wrong_surface.groups[0].executions[0].execution_surface =
            B4NegativeExecutionSurface::OpcodePreflight;
        assert!(wrong_surface.validate().is_err());

        let mut wrong_parser_offset = canonical_plan();
        let parser = wrong_parser_offset
            .groups
            .iter_mut()
            .find(|group| group.case_id == "parser-phase-truncation-sweep")
            .unwrap();
        parser.executions[0].parser_truncation_words = Some(1);
        assert!(wrong_parser_offset.validate().is_err());
    }

    #[test]
    fn byte_order_and_corpus_closure_obligations_are_explicit() {
        let plan = canonical_plan();
        let statement = plan
            .groups
            .iter()
            .find(|group| group.case_id == "statement-field-byte-sweep")
            .unwrap();
        let statement_variants = statement
            .executions
            .iter()
            .map(|execution| execution.variant_id.as_str())
            .collect::<BTreeSet<_>>();
        assert!(statement_variants.contains("chain-domain-byte-order-reversed"));
        assert!(statement_variants.contains("contract-id-byte-order-reversed"));

        let corpus = plan
            .groups
            .iter()
            .find(|group| group.case_id == "corpus-representative-stratum-omit-sweep")
            .unwrap();
        let corpus_variants = corpus
            .executions
            .iter()
            .map(|execution| execution.variant_id.as_str())
            .collect::<BTreeSet<_>>();
        for required in [
            "negative-plan",
            "subject-catalog",
            "terminal-fixture-catalog",
            "positive-registry",
            "expanded-negative-registry",
            "mutation-identities",
            "rust-negative-results",
            "jvm-negative-results",
            "semantic-report",
            "tree-manifest",
            "lock",
        ] {
            assert!(corpus_variants.contains(required), "missing {required}");
        }

        let bijection = plan
            .groups
            .iter()
            .find(|group| group.case_id == "negative-plan-registry-bijection-sweep")
            .unwrap();
        let bijection_variants = bijection
            .executions
            .iter()
            .map(|execution| execution.variant_id.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(bijection_variants.len(), 5);
        assert!(bijection_variants.contains("wrong-base-selector-binding"));
        assert!(bijection_variants.contains("wrong-materialization-domain"));
        assert!(bijection_variants.contains("wrong-materialization-binding"));
    }

    #[test]
    fn serialized_vocabulary_is_closed_and_has_no_stale_placeholders() {
        assert_eq!(
            serde_json::to_string(&B4NegativeExecutionSurface::Risc0ParserInternal).unwrap(),
            "\"risc0-parser-internal\""
        );
        assert_eq!(
            serde_json::to_string(&B4NegativePlanFixture::TerminalFixtureCatalogV1).unwrap(),
            "\"terminal-fixture-catalog-v1\""
        );
        assert_eq!(
            serde_json::to_string(&B4NegativeQaResultCode::RawSealWordNotReduced).unwrap(),
            "\"raw-seal-word-not-reduced\""
        );

        let bytes = canonical_plan().to_canonical_jcs().unwrap();
        let source = std::str::from_utf8(&bytes).unwrap();
        for stale in [
            "executionIdPrefix",
            "negative-mutated-input",
            "statement-truncated",
            "statement-digest-length",
            "corpus-required-file-omit-sweep",
            "wrong-binding-or-result",
        ] {
            assert!(!source.contains(stale), "stale vocabulary: {stale}");
        }
    }
}
