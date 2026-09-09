// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Shared bounded wire and stock replay authority for recursive B4 ancestry.
//!
//! Candidate generation and negative validation consume this module rather
//! than maintaining separate JSON, graph, claim, and resolve implementations.
//! The wire is producer-derived from the retained recursive oracle, but it is
//! not consensus provenance. A negative observation additionally requires the
//! validator to authenticate every referenced raw seal.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail, ensure};
use risc0_zkvm::{
    Assumption, Assumptions, Digest as Risc0Digest, ExitCode, MaybePruned, Output, ReceiptClaim,
    sha::Digestible as _,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    b4_recursive_auxiliary_paths::compiled_positive_auxiliary_artifact_paths,
    canonical::{canonical_json_bytes, validate_canonical_json_source, validate_lower_hex_exact},
    claim::ok_receipt_claim_digests,
    constants::{
        DIGEST_BYTES, PROOF_BYTES, RISC0_INNER_CONTROL_ROOT_HEX, RISC0_JOIN_CONTROL_ID_HEX,
        RISC0_NORMAL_LIFT_CONTROL_IDS_HEX, RISC0_RESOLVE_CONTROL_ID_HEX, SUPPORTED_SEGMENT_PO2,
    },
    ergo_statement::{ErgoStatementV1, parse_ergo_statement_v1},
};

/// Exact format discriminator of the provisional inventory-aware wire.
pub const RECURSIVE_ANCESTRY_FORMAT: &str = "Eip0045B4RecursiveAncestryV2";
/// Exact schema version of the provisional inventory-aware wire.
pub const RECURSIVE_ANCESTRY_FORMAT_VERSION: u8 = 2;
/// Maximum accepted canonical projection byte length.
pub const RECURSIVE_ANCESTRY_MAX_BYTES: usize = 64 * 1024;
/// Maximum number of retained ancestry steps.
pub const RECURSIVE_ANCESTRY_MAX_STEPS: usize = 4;
/// Maximum repository-relative artifact path length.
pub const RECURSIVE_ANCESTRY_MAX_PATH_BYTES: usize = 512;
/// Positive-corpus root used by deterministic ancestry references.
pub const RECURSIVE_ANCESTRY_POSITIVE_ROOT: &str =
    "reproduction/schema/b4-corpus-v1.candidate/positive";
/// Existing statement filename.
pub const RECURSIVE_ANCESTRY_STATEMENT_FILE: &str = "candidate-journal.bin";
/// Existing final raw-seal filename.
pub const RECURSIVE_ANCESTRY_FINAL_SEAL_FILE: &str = "candidate-raw-seal.bin";
/// Derived assumption raw-seal filename.
pub const RECURSIVE_ANCESTRY_ASSUMPTION_SEAL_FILE: &str =
    "candidate-ancestry-assumption-raw-seal.bin";

/// The three closed recursive ancestry families.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecursiveAncestryFamily {
    /// Two lifted continuation segments followed by stock join.
    TerminalJoin,
    /// One conditional lift followed by explicit-root resolve.
    TerminalResolve,
    /// Two lifts, zero-root resolve, then stock join.
    ResolveThenJoin,
}

impl RecursiveAncestryFamily {
    /// Deterministic positive-case identifier.
    #[must_use]
    pub const fn case_id(self) -> &'static str {
        match self {
            Self::TerminalJoin => "terminal-join",
            Self::TerminalResolve => "terminal-resolve-explicit-root",
            Self::ResolveThenJoin => "resolve-zero-root-then-join",
        }
    }

    /// Exact positive-corpus ordinal for this recursive family.
    #[must_use]
    pub const fn positive_case_index(self) -> usize {
        match self {
            Self::TerminalJoin => 8,
            Self::TerminalResolve => 9,
            Self::ResolveThenJoin => 10,
        }
    }

    /// Exact step count in the canonical family graph.
    #[must_use]
    pub const fn step_count(self) -> usize {
        match self {
            Self::TerminalJoin => 3,
            Self::TerminalResolve => 2,
            Self::ResolveThenJoin => 4,
        }
    }

    /// Exact source-lift count in the canonical family graph.
    #[must_use]
    pub const fn source_count(self) -> usize {
        match self {
            Self::TerminalResolve => 1,
            Self::TerminalJoin | Self::ResolveThenJoin => 2,
        }
    }

    /// Exact auxiliary raw-seal count.
    #[must_use]
    pub const fn auxiliary_count(self) -> usize {
        match self {
            Self::TerminalJoin | Self::TerminalResolve => 2,
            Self::ResolveThenJoin => 4,
        }
    }

    /// Whether the family has one assumption receipt and source inventory.
    #[must_use]
    pub const fn uses_assumption(self) -> bool {
        !matches!(self, Self::TerminalJoin)
    }
}

/// Exact reference to one retained ancestry artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecursiveAncestryArtifactReference {
    /// Canonical repository-relative POSIX path.
    pub path: String,
    /// Exact byte length.
    pub byte_length: u64,
    /// Lowercase SHA-256 of the exact bytes.
    pub sha256: String,
}

/// One revealed or digest-only source assumption entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum RecursiveAncestryInventoryEntry {
    /// Fully revealed upstream `Assumption`.
    Revealed {
        /// Digest of the claim requested by the guest.
        claim_digest: String,
        /// Control root requested for that claim.
        control_root: String,
    },
    /// Digest-only upstream `MaybePruned::Pruned` entry.
    Pruned {
        /// Digest of the hidden `Assumption`.
        digest: String,
    },
}

/// Bounded revealed source assumption-list representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecursiveAncestrySourceInventory {
    /// Zero, one, or two exact upstream `MaybePruned<Assumption>` entries.
    pub entries: Vec<RecursiveAncestryInventoryEntry>,
}

/// Assumption receipt plus the source list consumed by stock resolve.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecursiveAncestryAssumption {
    /// Full projected same-program receipt claim.
    pub claim: RecursiveAncestryClaim,
    /// Family-selected requested control root.
    pub requested_control_root: String,
    /// Producer-derived source assumption inventory.
    pub source_inventory: RecursiveAncestrySourceInventory,
    /// Exact auxiliary raw-seal reference.
    pub raw_seal: RecursiveAncestryArtifactReference,
    /// Exact normal-lift terminal tuple.
    pub terminal: RecursiveAncestryTerminal,
}

/// One projected ancestry step.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecursiveAncestryStep {
    /// Zero-based append-only ordinal.
    pub ordinal: u32,
    /// Closed stock recursion operation and its earlier inputs.
    pub operation: RecursiveAncestryOperation,
    /// Full projected output claim.
    pub claim: RecursiveAncestryClaim,
    /// Exact raw-seal reference.
    pub raw_seal: RecursiveAncestryArtifactReference,
    /// Exact terminal tuple.
    pub terminal: RecursiveAncestryTerminal,
}

/// The six inputs to the upstream `ReceiptClaim` digest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecursiveAncestryClaim {
    /// Input digest.
    pub input_digest: String,
    /// Pre-state digest.
    pub pre_state_digest: String,
    /// Post-state digest.
    pub post_state_digest: String,
    /// System exit code.
    pub system_exit: u32,
    /// User exit code.
    pub user_exit: u32,
    /// Output digest.
    pub output_digest: String,
}

/// Closed stock recursion operation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum RecursiveAncestryOperation {
    /// Lift one source segment.
    Lift {
        /// Zero-based source segment index.
        segment_index: u32,
    },
    /// Join two earlier continuation-adjacent steps.
    Join {
        /// Earlier left step.
        left_step: u32,
        /// Earlier right step.
        right_step: u32,
    },
    /// Resolve the source assumption from one earlier conditional step.
    Resolve {
        /// Earlier conditional step.
        conditional_step: u32,
    },
}

/// Closed terminal tuple projected from one producer receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum RecursiveAncestryTerminal {
    /// Normal RV32IM lift.
    Lift {
        /// Supported source segment exponent.
        segment_po2: u32,
        /// Exact corresponding normal-lift control ID.
        control_id: String,
    },
    /// Stock join terminal.
    Join {
        /// Exact stock join control ID.
        control_id: String,
    },
    /// Stock resolve terminal.
    Resolve {
        /// Exact stock resolve control ID.
        control_id: String,
    },
}

/// Complete canonical recursive ancestry projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecursiveAncestryProjection {
    /// Exact format discriminator.
    pub format: String,
    /// Exact format version.
    pub format_version: u8,
    /// Deterministic positive-case identifier.
    pub case_id: String,
    /// Initial profile identifier.
    pub profile_id: String,
    /// Guest program/image identifier.
    pub program_id: String,
    /// Existing statement reference.
    pub statement: RecursiveAncestryArtifactReference,
    /// Parsed family authority.
    pub family: RecursiveAncestryFamily,
    /// Assumption producer and source inventory, absent only for terminal join.
    pub assumption_receipt: Option<RecursiveAncestryAssumption>,
    /// Exact canonical step graph.
    pub steps: Vec<RecursiveAncestryStep>,
}

/// Canonical projection plus only derived auxiliary seal bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecursiveAncestryProjectionBundle {
    /// Exact RFC 8785 JCS projection bytes.
    pub jcs: Vec<u8>,
    /// Assumption and non-final step seals by deterministic path.
    pub auxiliary_seals: BTreeMap<String, Vec<u8>>,
}

/// Exact planned source-inventory defect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecursiveAncestryInventoryDefect {
    /// Revealed source list is empty.
    Missing,
    /// Revealed source list contains one exact duplicate head.
    Extra,
    /// The exact source head is present only by its digest.
    Pruned,
}

/// Exact authenticated revealed-head tuple used by the closed pruning mutation.
#[cfg(any(feature = "positive-gate", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecursiveAncestryRevealedHeadWitness {
    pub(crate) claim_digest: [u8; DIGEST_BYTES],
    pub(crate) control_root: [u8; DIGEST_BYTES],
    pub(crate) exact_digest: [u8; DIGEST_BYTES],
}

/// Shared semantic classification after structural validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecursiveAncestrySemanticOutcome {
    /// Exact canonical producer projection.
    Canonical,
    /// Continuation or stock join algebra mismatch.
    ClaimEdge,
    /// Explicit-root resolve semantic mismatch.
    ResolveExplicit,
    /// Zero-root resolve semantic mismatch.
    ResolveZeroRoot,
    /// One exact source assumption-inventory defect.
    AssumptionInventory(RecursiveAncestryInventoryDefect),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedClaim {
    input: [u8; DIGEST_BYTES],
    pre: [u8; DIGEST_BYTES],
    post: [u8; DIGEST_BYTES],
    system_exit: u32,
    user_exit: u32,
    output: [u8; DIGEST_BYTES],
}

/// Parse exact bounded RFC 8785 JCS into the closed V2 wire.
///
/// # Errors
///
/// Returns an error for oversized, noncanonical, duplicate, unknown, or
/// otherwise malformed JSON.
pub fn parse_recursive_ancestry_jcs(source: &[u8]) -> Result<RecursiveAncestryProjection> {
    ensure!(
        source.len() <= RECURSIVE_ANCESTRY_MAX_BYTES,
        "ancestry projection exceeds its byte limit"
    );
    let value = validate_canonical_json_source(source)
        .context("ancestry projection is not exact RFC 8785 JCS")?;
    serde_json::from_value(value).context("ancestry projection has the wrong closed shape")
}

/// Serialize one projection as bounded exact RFC 8785 JCS.
///
/// # Errors
///
/// Returns an error when serialization fails or exceeds the byte limit.
pub fn recursive_ancestry_to_jcs(projection: &RecursiveAncestryProjection) -> Result<Vec<u8>> {
    let value = serde_json::to_value(projection).context("cannot serialize ancestry projection")?;
    let bytes = canonical_json_bytes(&value).context("cannot canonicalize ancestry projection")?;
    ensure!(
        bytes.len() <= RECURSIVE_ANCESTRY_MAX_BYTES,
        "canonical ancestry projection exceeds its byte limit"
    );
    Ok(bytes)
}

/// Validate the closed wire, family graph, identities, paths, and terminals.
///
/// Semantic claim and resolve classification is performed separately.
///
/// # Errors
///
/// Returns an error for any structural, identity, graph, path, reference, or
/// terminal mismatch.
#[allow(
    clippy::too_many_lines,
    reason = "the closed wire and family graph are checked in one fail-closed order"
)]
pub fn validate_recursive_ancestry_structure(
    projection: &RecursiveAncestryProjection,
    statement: &[u8],
    expected_profile_id: [u8; DIGEST_BYTES],
) -> Result<()> {
    ensure!(
        projection.format == RECURSIVE_ANCESTRY_FORMAT
            && projection.format_version == RECURSIVE_ANCESTRY_FORMAT_VERSION,
        "ancestry projection format/version differs"
    );
    ensure!(
        projection.case_id == projection.family.case_id(),
        "ancestry case ID differs from its parsed family"
    );
    ensure!(
        projection.steps.len() == projection.family.step_count()
            && (1..=RECURSIVE_ANCESTRY_MAX_STEPS).contains(&projection.steps.len()),
        "ancestry step count differs from its parsed family"
    );
    let statement_value =
        parse_ergo_statement_v1(statement).context("cannot decode ancestry statement")?;
    ensure!(
        statement_value.encode()?.as_slice() == statement,
        "ancestry statement decode/re-encode changed bytes"
    );
    ensure!(
        statement_value.profile_id() == expected_profile_id,
        "ancestry statement profile ID differs from expected profile"
    );
    ensure!(
        projection.profile_id == hex::encode(expected_profile_id),
        "ancestry projection profile ID differs"
    );
    ensure!(
        projection.program_id == hex::encode(statement_value.program_id()),
        "ancestry projection program ID differs from the statement"
    );
    validate_recursive_ancestry_reference(
        &projection.statement,
        &recursive_ancestry_case_path(projection.family, RECURSIVE_ANCESTRY_STATEMENT_FILE),
        statement.len(),
    )?;
    ensure!(
        projection.statement.sha256 == sha256_hex(statement),
        "ancestry statement SHA-256 differs"
    );

    match (
        projection.family.uses_assumption(),
        &projection.assumption_receipt,
    ) {
        (false, None) => {}
        (false, Some(_)) => bail!("plain ancestry unexpectedly carries an assumption receipt"),
        (true, None) => bail!("assumption-bearing ancestry has no assumption receipt"),
        (true, Some(assumption)) => {
            ensure!(
                assumption.source_inventory.entries.len() <= 2,
                "source assumption inventory exceeds its two-entry bound"
            );
            for entry in &assumption.source_inventory.entries {
                validate_inventory_entry_shape(entry)?;
            }
            validate_lift_terminal(&assumption.terminal)?;
            validate_recursive_ancestry_reference(
                &assumption.raw_seal,
                &recursive_ancestry_case_path(
                    projection.family,
                    RECURSIVE_ANCESTRY_ASSUMPTION_SEAL_FILE,
                ),
                PROOF_BYTES,
            )?;
        }
    }

    let expected_operations = recursive_ancestry_expected_operations(projection.family);
    let mut paths = BTreeSet::new();
    ensure!(
        paths.insert(projection.statement.path.clone()),
        "duplicate ancestry statement path"
    );
    if let Some(assumption) = &projection.assumption_receipt {
        ensure!(
            paths.insert(assumption.raw_seal.path.clone()),
            "duplicate ancestry assumption path"
        );
    }
    for (index, (step, expected_operation)) in projection
        .steps
        .iter()
        .zip(expected_operations.iter())
        .enumerate()
    {
        ensure!(
            usize::try_from(step.ordinal).ok() == Some(index),
            "ancestry step ordinal is not canonical"
        );
        ensure!(
            &step.operation == expected_operation,
            "ancestry operation differs from its parsed-family graph"
        );
        validate_operation_terminal(&step.operation, &step.terminal)?;
        validate_claim_projection(&step.claim)?;
        let file = if index + 1 == projection.steps.len() {
            RECURSIVE_ANCESTRY_FINAL_SEAL_FILE.to_owned()
        } else {
            format!("candidate-ancestry-step-{index:02}-raw-seal.bin")
        };
        validate_recursive_ancestry_reference(
            &step.raw_seal,
            &recursive_ancestry_case_path(projection.family, &file),
            PROOF_BYTES,
        )?;
        ensure!(
            paths.insert(step.raw_seal.path.clone()),
            "duplicate ancestry step path"
        );
    }
    if let Some(assumption) = &projection.assumption_receipt {
        validate_claim_projection(&assumption.claim)?;
        parse_digest(
            &assumption.requested_control_root,
            "assumption requested control root",
        )?;
    }
    Ok(())
}

/// Classify one structurally valid projection through shared stock semantics.
///
/// Inventory classification reconstructs the exact upstream
/// `ReceiptClaim`, `Output`, `Assumptions`, and `MaybePruned<Assumption>`
/// representation and invokes [`ReceiptClaim::resolve`]. Missing and extra
/// inventories necessarily change the conditional claim digest; a validator
/// can publish them only when a real seal authenticates that changed claim.
/// The exact pruned head preserves the producer digest but makes stock resolve
/// unable to open the head.
///
/// # Errors
///
/// Returns an error for malformed or coordinated drift, any unplanned
/// inventory form, or disagreement with the pinned upstream stock semantics.
#[allow(
    clippy::too_many_lines,
    reason = "the shared classifier keeps one visible fail-closed stock replay order"
)]
pub fn classify_recursive_ancestry_semantics(
    projection: &RecursiveAncestryProjection,
    statement: &[u8],
    expected_profile_id: [u8; DIGEST_BYTES],
) -> Result<RecursiveAncestrySemanticOutcome> {
    validate_recursive_ancestry_structure(projection, statement, expected_profile_id)?;
    let statement_value = parse_ergo_statement_v1(statement)?;
    let ok = ok_receipt_claim_digests(&statement_value.program_id(), statement)
        .context("cannot derive ancestry same-program OK claim")?;
    let expected_ok = ParsedClaim {
        input: [0; DIGEST_BYTES],
        pre: statement_value.program_id(),
        post: ok.post,
        system_exit: 0,
        user_exit: 0,
        output: ok.output,
    };
    let expected_root = recursive_ancestry_expected_assumption_root(projection.family)?;

    let inventory_defect = match (
        projection.family,
        projection.assumption_receipt.as_ref(),
        expected_root,
    ) {
        (RecursiveAncestryFamily::TerminalJoin, None, None) => None,
        (family, Some(assumption), Some(root)) => {
            if parse_claim(&assumption.claim)? != expected_ok {
                return Ok(family.resolve_outcome());
            }
            if parse_digest(
                &assumption.requested_control_root,
                "assumption requested control root",
            )? != root
            {
                return Ok(family.resolve_outcome());
            }
            let canonical_entry = RecursiveAncestryInventoryEntry::Revealed {
                claim_digest: hex::encode(ok.expected_claim),
                control_root: hex::encode(root),
            };
            if family == RecursiveAncestryFamily::TerminalResolve
                && assumption.source_inventory.entries.as_slice() == [canonical_entry]
                && parse_claim(&projection.steps[0].claim)? == expected_ok
            {
                // B4 row 142 substitutes the already authenticated assumption
                // Lift into the conditional source slot. Its full OK output is
                // therefore a real non-final claim-edge witness, not an
                // inventory reconstruction error. Keep this guard exact; other
                // source-output/inventory coordination remains private.
                return Ok(RecursiveAncestrySemanticOutcome::ClaimEdge);
            }
            if matches_exact_alternate_program_step_zero(projection, statement)? {
                return Ok(RecursiveAncestrySemanticOutcome::ResolveExplicit);
            }
            classify_stock_inventory(
                family,
                projection,
                assumption,
                statement,
                ok.expected_claim,
                expected_ok,
                root,
            )?
        }
        _ => bail!("ancestry assumption presence differs from parsed family"),
    };

    let claims = projection
        .steps
        .iter()
        .map(|step| parse_claim(&step.claim))
        .collect::<Result<Vec<_>>>()?;
    let expected_conditional_output =
        expected_root.map(|root| conditional_output_digest(statement, ok.expected_claim, root));
    if let Some(defect) = inventory_defect {
        ensure!(
            projection.family == RecursiveAncestryFamily::TerminalResolve,
            "source inventory defects are planned only for terminal resolve"
        );
        let expected_source_output = reconstructed_inventory_output_digest(
            statement,
            &projection
                .assumption_receipt
                .as_ref()
                .context("inventory defect lost its assumption")?
                .source_inventory,
        )?;
        ensure!(
            claims.len() == 2
                && canonical_source_fields(claims[0], statement_value.program_id(), ok.post)
                && claims[0].output == expected_source_output
                && claims[1] == expected_ok,
            "inventory defect is coordinated with another ancestry claim drift"
        );
        return Ok(RecursiveAncestrySemanticOutcome::AssumptionInventory(
            defect,
        ));
    }

    let source_count = projection.family.source_count();
    if claims[0].pre != statement_value.program_id() {
        return Ok(projection.family.resolve_outcome());
    }
    for index in 0..source_count {
        let claim = claims[index];
        if index + 1 < source_count {
            if claim.post != claims[index + 1].pre
                || (claim.system_exit, claim.user_exit) != (2, 0)
                || claim.output != [0; DIGEST_BYTES]
            {
                return Ok(RecursiveAncestrySemanticOutcome::ClaimEdge);
            }
        } else {
            if claim.post != ok.post || (claim.system_exit, claim.user_exit) != (0, 0) {
                return Ok(RecursiveAncestrySemanticOutcome::ClaimEdge);
            }
            if claim.output != expected_conditional_output.unwrap_or(ok.output) {
                bail!("canonical inventory is coordinated with a noncanonical source output");
            }
        }
    }

    for (index, step) in projection.steps.iter().enumerate() {
        // Replay every non-final operation before giving a noncanonical family
        // terminal its policy-specific precedence. This prevents a final
        // Resolve/Join fault from masking an earlier claim-edge defect while
        // still keeping a final-only witness out of the generic class.
        if index + 1 == projection.steps.len() && claims.last() != Some(&expected_ok) {
            return Ok(projection.family.resolve_outcome());
        }
        match step.operation {
            RecursiveAncestryOperation::Lift { .. } => {}
            RecursiveAncestryOperation::Join {
                left_step,
                right_step,
            } => {
                let left = earlier_claim(&claims, left_step, index)?;
                let right = earlier_claim(&claims, right_step, index)?;
                let left_projection = &projection.steps[usize::try_from(left_step)
                    .context("left ancestry ordinal does not fit usize")?]
                .claim;
                let right_projection = &projection.steps[usize::try_from(right_step)
                    .context("right ancestry ordinal does not fit usize")?]
                .claim;
                let joined = receipt_claim_from_projection(left_projection)?
                    .join(&receipt_claim_from_projection(right_projection)?);
                if left.post != right.pre
                    || (left.system_exit, left.user_exit) != (2, 0)
                    || left.output != [0; DIGEST_BYTES]
                    || !receipt_claim_matches_projection(&joined, &step.claim)?
                {
                    return Ok(RecursiveAncestrySemanticOutcome::ClaimEdge);
                }
            }
            RecursiveAncestryOperation::Resolve { conditional_step } => {
                let conditional = earlier_claim(&claims, conditional_step, index)?;
                let expected_output = expected_conditional_output
                    .context("resolve operation has no parsed-family conditional output")?;
                if conditional.output != expected_output {
                    bail!("canonical inventory resolve input has a noncanonical output");
                }
                let assumption = projection
                    .assumption_receipt
                    .as_ref()
                    .context("resolve operation has no assumption receipt")?;
                let conditional_projection =
                    &projection.steps[usize::try_from(conditional_step)
                        .context("conditional ancestry ordinal does not fit usize")?]
                    .claim;
                let conditional_claim = receipt_claim_with_inventory(
                    conditional_projection,
                    statement,
                    &assumption.source_inventory,
                )?;
                let assumption_claim = receipt_claim_from_projection(&assumption.claim)?;
                let resolved = conditional_claim
                    .resolve(&assumption_claim)
                    .context("canonical stock resolve replay failed")?;
                if !receipt_claim_matches_projection(&resolved, &step.claim)? {
                    return Ok(RecursiveAncestrySemanticOutcome::ClaimEdge);
                }
            }
        }
    }
    Ok(RecursiveAncestrySemanticOutcome::Canonical)
}

/// Recognize only the alternate-program OK replacement of the explicit family's
/// conditional Lift. Its independently authenticated output belongs to the
/// alternate journal with no assumptions, so the original conditional inventory
/// cannot reconstruct it. Other inventory/output coordination stays private.
fn matches_exact_alternate_program_step_zero(
    projection: &RecursiveAncestryProjection,
    statement: &[u8],
) -> Result<bool> {
    if projection.family != RecursiveAncestryFamily::TerminalResolve {
        return Ok(false);
    }
    let [source, final_step] = projection.steps.as_slice() else { return Ok(false) };
    let Some(assumption) = projection.assumption_receipt.as_ref() else { return Ok(false) };
    let parsed = parse_ergo_statement_v1(statement)?;
    let expected = derive_empty_assumption_ok_recursive_ancestry_claim(&parsed.program_id(), statement)?;
    let expected_head = RecursiveAncestryInventoryEntry::Revealed {
        claim_digest: hex::encode(recursive_ancestry_claim_digest(&expected)?),
        control_root: RISC0_INNER_CONTROL_ROOT_HEX.to_owned(),
    };
    let expected_lift = RecursiveAncestryTerminal::Lift {
        segment_po2: 15, control_id: RISC0_NORMAL_LIFT_CONTROL_IDS_HEX[0].to_owned(),
    };
    if assumption.claim != expected
        || assumption.requested_control_root != RISC0_INNER_CONTROL_ROOT_HEX
        || assumption.source_inventory.entries.as_slice() != [expected_head]
        || assumption.terminal != expected_lift
        || final_step.claim != expected
        || source.ordinal != 0 || final_step.ordinal != 1
        || source.operation != (RecursiveAncestryOperation::Lift { segment_index: 0 })
        || final_step.operation != (RecursiveAncestryOperation::Resolve { conditional_step: 0 })
        || source.terminal != expected_lift
        || final_step.terminal != (RecursiveAncestryTerminal::Resolve {
            control_id: RISC0_RESOLVE_CONTROL_ID_HEX.to_owned(),
        })
    {
        return Ok(false);
    }
    let alternate_program = parse_digest(&source.claim.pre_state_digest, "alternate source program")?;
    if alternate_program == parsed.program_id() { return Ok(false); }
    let alternate_statement = ErgoStatementV1::new(parsed.chain_domain_id(), parsed.profile_id(),
        alternate_program, parsed.contract_id(), parsed.application_payload())?.encode()?;
    let alternate_claim = derive_empty_assumption_ok_recursive_ancestry_claim(
        &alternate_program, &alternate_statement)?;
    Ok(source.claim == alternate_claim)
}

/// Require exact canonical semantics with no negative classification.
///
/// # Errors
///
/// Returns an error unless the shared classifier returns `Canonical`.
pub fn validate_canonical_recursive_ancestry(
    projection: &RecursiveAncestryProjection,
    statement: &[u8],
    expected_profile_id: [u8; DIGEST_BYTES],
) -> Result<()> {
    ensure!(
        classify_recursive_ancestry_semantics(projection, statement, expected_profile_id)?
            == RecursiveAncestrySemanticOutcome::Canonical,
        "recursive ancestry projection is not canonical producer evidence"
    );
    Ok(())
}

/// Derive the exact revealed assumption head and its pinned RISC0 digest.
///
/// The function is intentionally crate-private: it supplies the closed B4
/// row-155 mutation recipe and is not a general ancestry editing API.
#[cfg(any(feature = "positive-gate", test))]
pub(crate) fn recursive_ancestry_revealed_head_witness(
    projection: &RecursiveAncestryProjection,
) -> Result<RecursiveAncestryRevealedHeadWitness> {
    ensure!(
        projection.family == RecursiveAncestryFamily::TerminalResolve,
        "revealed-head pruning is planned only for terminal resolve"
    );
    let assumption = projection
        .assumption_receipt
        .as_ref()
        .context("terminal resolve has no assumption receipt")?;
    let [
        RecursiveAncestryInventoryEntry::Revealed {
            claim_digest,
            control_root,
        },
    ] = assumption.source_inventory.entries.as_slice()
    else {
        bail!("assumption source inventory is not exactly one revealed head");
    };
    let claim_digest = parse_digest(claim_digest, "revealed assumption claim digest")?;
    let control_root = parse_digest(control_root, "revealed assumption control root")?;
    ensure!(
        recursive_ancestry_claim_digest(&assumption.claim)? == claim_digest,
        "revealed assumption claim differs from its authenticated receipt claim"
    );
    ensure!(
        parse_digest(
            &assumption.requested_control_root,
            "assumption requested control root",
        )? == control_root,
        "revealed assumption root differs from the requested control root"
    );
    let exact_digest = digest_bytes(
        &Assumption {
            claim: Risc0Digest::from(claim_digest),
            control_root: Risc0Digest::from(control_root),
        }
        .digest(),
    );
    Ok(RecursiveAncestryRevealedHeadWitness {
        claim_digest,
        control_root,
        exact_digest,
    })
}

/// Apply the sole closed semantic inventory transition used by B4 row 155.
///
/// The positive base must be canonical terminal-resolve ancestry. The supplied
/// tuple is checked against its exact revealed head and the pinned RISC0
/// `Assumption` digest before only that head becomes digest-only.
#[cfg(any(feature = "positive-gate", test))]
pub(crate) fn prune_recursive_ancestry_revealed_head(
    projection: &RecursiveAncestryProjection,
    statement: &[u8],
    expected_profile_id: [u8; DIGEST_BYTES],
    witness: RecursiveAncestryRevealedHeadWitness,
) -> Result<RecursiveAncestryProjection> {
    ensure!(
        classify_recursive_ancestry_semantics(projection, statement, expected_profile_id)?
            == RecursiveAncestrySemanticOutcome::Canonical,
        "pruned-head mutation base is not canonical positive ancestry"
    );
    ensure!(
        recursive_ancestry_revealed_head_witness(projection)? == witness,
        "pruned-head mutation witness differs from the exact revealed assumption"
    );
    let source_claim = recursive_ancestry_claim_digest(
        &projection
            .steps
            .first()
            .context("terminal-resolve ancestry has no conditional source step")?
            .claim,
    )?;
    let mut pruned = projection.clone();
    pruned
        .assumption_receipt
        .as_mut()
        .context("terminal-resolve ancestry lost its assumption receipt")?
        .source_inventory
        .entries = vec![RecursiveAncestryInventoryEntry::Pruned {
        digest: hex::encode(witness.exact_digest),
    }];
    ensure!(
        recursive_ancestry_claim_digest(
            &pruned
                .steps
                .first()
                .context("pruned ancestry lost its conditional source step")?
                .claim,
        )? == source_claim,
        "pruned assumption head changed the authenticated source claim digest"
    );
    ensure!(
        classify_recursive_ancestry_semantics(&pruned, statement, expected_profile_id)?
            == RecursiveAncestrySemanticOutcome::AssumptionInventory(
                RecursiveAncestryInventoryDefect::Pruned,
            ),
        "pruned assumption head did not isolate the planned inventory rejection"
    );
    Ok(pruned)
}

/// Bind statement, final seal, and the exact auxiliary seal map to references.
///
/// # Errors
///
/// Returns an error for any missing, extra, duplicate, length, hash, or
/// existing-artifact alias.
pub fn validate_recursive_ancestry_artifacts<T: AsRef<[u8]>>(
    projection: &RecursiveAncestryProjection,
    statement: &[u8],
    final_raw_seal: &[u8],
    auxiliary_seals: &BTreeMap<String, T>,
) -> Result<()> {
    validate_bound_bytes(&projection.statement, statement, "statement")?;
    ensure!(
        final_raw_seal.len() == PROOF_BYTES,
        "existing final raw seal has the wrong byte length"
    );
    let final_step = projection
        .steps
        .last()
        .context("ancestry projection has no final step")?;
    validate_bound_bytes(&final_step.raw_seal, final_raw_seal, "final raw seal")?;
    ensure!(
        !auxiliary_seals.contains_key(&projection.statement.path)
            && !auxiliary_seals.contains_key(&final_step.raw_seal.path),
        "auxiliary map duplicates an existing statement or final seal"
    );

    let expected = recursive_ancestry_expected_auxiliary_paths(projection.family);
    ensure!(
        auxiliary_seals.keys().eq(expected.iter()),
        "auxiliary seal map differs from the exact parsed-family path sequence"
    );
    if let Some(assumption) = &projection.assumption_receipt {
        let bytes = auxiliary_seals
            .get(&assumption.raw_seal.path)
            .context("missing assumption raw seal")?;
        validate_bound_bytes(&assumption.raw_seal, bytes.as_ref(), "assumption raw seal")?;
    }
    for step in projection.steps.iter().take(projection.steps.len() - 1) {
        let bytes = auxiliary_seals
            .get(&step.raw_seal.path)
            .context("missing intermediate raw seal")?;
        validate_bound_bytes(&step.raw_seal, bytes.as_ref(), "intermediate raw seal")?;
    }
    Ok(())
}

/// Construct and validate an exact artifact reference.
///
/// # Errors
///
/// Returns an error when the path or byte length is outside the wire bounds.
pub fn recursive_ancestry_artifact_reference(
    path: String,
    bytes: &[u8],
) -> Result<RecursiveAncestryArtifactReference> {
    validate_recursive_ancestry_path(&path)?;
    Ok(RecursiveAncestryArtifactReference {
        path,
        byte_length: u64::try_from(bytes.len()).context("artifact length does not fit u64")?,
        sha256: sha256_hex(bytes),
    })
}

/// Deterministic repository path for one family artifact.
#[must_use]
pub fn recursive_ancestry_case_path(family: RecursiveAncestryFamily, file_name: &str) -> String {
    format!(
        "{RECURSIVE_ANCESTRY_POSITIVE_ROOT}/{}/{file_name}",
        family.case_id()
    )
}

/// Exact sorted auxiliary raw-seal paths for one family.
#[must_use]
///
/// # Panics
///
/// Panics only if the closed family-to-positive-case mapping and the compiled
/// eleven-case path authority are changed inconsistently.
pub fn recursive_ancestry_expected_auxiliary_paths(family: RecursiveAncestryFamily) -> Vec<String> {
    compiled_positive_auxiliary_artifact_paths(family.positive_case_index())
        .expect("closed recursive family must have one compiled auxiliary path sequence")
        .iter()
        .map(|path| (*path).to_owned())
        .collect()
}

/// One canonical graph operation sequence.
#[must_use]
pub fn recursive_ancestry_expected_operations(
    family: RecursiveAncestryFamily,
) -> Vec<RecursiveAncestryOperation> {
    match family {
        RecursiveAncestryFamily::TerminalJoin => vec![
            RecursiveAncestryOperation::Lift { segment_index: 0 },
            RecursiveAncestryOperation::Lift { segment_index: 1 },
            RecursiveAncestryOperation::Join {
                left_step: 0,
                right_step: 1,
            },
        ],
        RecursiveAncestryFamily::TerminalResolve => vec![
            RecursiveAncestryOperation::Lift { segment_index: 0 },
            RecursiveAncestryOperation::Resolve {
                conditional_step: 0,
            },
        ],
        RecursiveAncestryFamily::ResolveThenJoin => vec![
            RecursiveAncestryOperation::Lift { segment_index: 0 },
            RecursiveAncestryOperation::Lift { segment_index: 1 },
            RecursiveAncestryOperation::Resolve {
                conditional_step: 1,
            },
            RecursiveAncestryOperation::Join {
                left_step: 0,
                right_step: 2,
            },
        ],
    }
}

/// Parse and hash one projected claim through upstream `ReceiptClaim`.
///
/// # Errors
///
/// Returns an error for malformed digests or exit codes.
pub fn recursive_ancestry_claim_digest(
    claim: &RecursiveAncestryClaim,
) -> Result<[u8; DIGEST_BYTES]> {
    Ok(digest_bytes(
        &receipt_claim_from_projection(claim)?.digest(),
    ))
}

/// Project one already authenticated upstream claim into the closed ancestry wire.
///
/// Authentication remains the caller's responsibility. This helper only
/// projects the six digest inputs and refuses to return a projection unless
/// reconstructing it produces the exact upstream claim digest.
pub(crate) fn project_verified_receipt_claim(
    verified_claim: &ReceiptClaim,
) -> Result<RecursiveAncestryClaim> {
    let parsed = parsed_from_receipt_claim(verified_claim);
    let projected = RecursiveAncestryClaim {
        input_digest: hex::encode(parsed.input),
        pre_state_digest: hex::encode(parsed.pre),
        post_state_digest: hex::encode(parsed.post),
        system_exit: parsed.system_exit,
        user_exit: parsed.user_exit,
        output_digest: hex::encode(parsed.output),
    };
    ensure!(
        recursive_ancestry_claim_digest(&projected)? == digest_bytes(&verified_claim.digest()),
        "verified receipt claim digest changed during ancestry projection"
    );
    Ok(projected)
}

/// Independently derive the exact empty-assumption OK ancestry claim.
///
/// The derivation uses the local byte-level claim oracle rather than
/// `ReceiptClaim::ok`, then checks that the closed ancestry projection hashes
/// to the independently derived expected claim digest.
pub(crate) fn derive_empty_assumption_ok_recursive_ancestry_claim(
    image_id: &[u8],
    journal: &[u8],
) -> Result<RecursiveAncestryClaim> {
    let digests = ok_receipt_claim_digests(image_id, journal)
        .context("cannot independently derive empty-assumption OK claim")?;
    let derived = RecursiveAncestryClaim {
        input_digest: "00".repeat(DIGEST_BYTES),
        pre_state_digest: hex::encode(image_id),
        post_state_digest: hex::encode(digests.post),
        system_exit: 0,
        user_exit: 0,
        output_digest: hex::encode(digests.output),
    };
    ensure!(
        recursive_ancestry_claim_digest(&derived)? == digests.expected_claim,
        "independent OK claim digest differs from its ancestry projection"
    );
    Ok(derived)
}

/// Derive the same claim fields with one explicit source inventory.
///
/// Input, pre-state, post-state, and exit codes are retained exactly. Only the
/// output is rebuilt from the supplied journal and the existing closed
/// inventory representation, after which the complete claim digest is
/// reconstructed and checked against the corresponding upstream claim.
pub(crate) fn derive_recursive_ancestry_claim_with_inventory(
    base: &RecursiveAncestryClaim,
    journal: &[u8],
    inventory: &RecursiveAncestrySourceInventory,
) -> Result<RecursiveAncestryClaim> {
    ensure!(
        inventory.entries.len() <= 2,
        "derived source inventory exceeds the closed ancestry bound"
    );
    for entry in &inventory.entries {
        validate_inventory_entry_shape(entry)?;
    }

    let mut derived = base.clone();
    derived.output_digest = hex::encode(reconstructed_inventory_output_digest(journal, inventory)?);
    let reconstructed = receipt_claim_with_inventory(&derived, journal, inventory)?;
    ensure!(
        recursive_ancestry_claim_digest(&derived)? == digest_bytes(&reconstructed.digest()),
        "inventory-derived ancestry claim differs from its upstream reconstruction"
    );
    Ok(derived)
}

/// Exact expected assumption root for one family.
///
/// # Errors
///
/// Returns an error only if the frozen root constant is malformed.
pub fn recursive_ancestry_expected_assumption_root(
    family: RecursiveAncestryFamily,
) -> Result<Option<[u8; DIGEST_BYTES]>> {
    match family {
        RecursiveAncestryFamily::TerminalJoin => Ok(None),
        RecursiveAncestryFamily::TerminalResolve => Ok(Some(parse_digest(
            RISC0_INNER_CONTROL_ROOT_HEX,
            "initial inner control root",
        )?)),
        RecursiveAncestryFamily::ResolveThenJoin => Ok(Some([0; DIGEST_BYTES])),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "all four exact stock-resolve outcomes remain visible in one differential"
)]
fn classify_stock_inventory(
    family: RecursiveAncestryFamily,
    projection: &RecursiveAncestryProjection,
    assumption: &RecursiveAncestryAssumption,
    statement: &[u8],
    expected_claim: [u8; DIGEST_BYTES],
    expected_ok: ParsedClaim,
    expected_root: [u8; DIGEST_BYTES],
) -> Result<Option<RecursiveAncestryInventoryDefect>> {
    let expected_entry = RecursiveAncestryInventoryEntry::Revealed {
        claim_digest: hex::encode(expected_claim),
        control_root: hex::encode(expected_root),
    };
    let expected_head_digest = digest_bytes(
        &Assumption {
            claim: Risc0Digest::from(expected_claim),
            control_root: Risc0Digest::from(expected_root),
        }
        .digest(),
    );
    let defect = match assumption.source_inventory.entries.as_slice() {
        [entry] if entry == &expected_entry => None,
        [] => Some(RecursiveAncestryInventoryDefect::Missing),
        [first, second] if first == &expected_entry && second == &expected_entry => {
            Some(RecursiveAncestryInventoryDefect::Extra)
        }
        [RecursiveAncestryInventoryEntry::Pruned { digest }]
            if parse_digest(digest, "pruned assumption digest")? == expected_head_digest =>
        {
            Some(RecursiveAncestryInventoryDefect::Pruned)
        }
        _ => bail!("source assumption inventory is not canonical or one exact planned defect"),
    };
    if defect.is_some() {
        ensure!(
            family == RecursiveAncestryFamily::TerminalResolve,
            "source assumption inventory defect is outside the planned explicit-root family"
        );
    }

    let conditional_index = match family {
        RecursiveAncestryFamily::TerminalResolve => 0,
        RecursiveAncestryFamily::ResolveThenJoin => 1,
        RecursiveAncestryFamily::TerminalJoin => {
            bail!("plain family cannot classify an assumption inventory")
        }
    };
    let conditional_projection = &projection.steps[conditional_index].claim;
    let conditional = receipt_claim_with_inventory(
        conditional_projection,
        statement,
        &assumption.source_inventory,
    )?;
    ensure!(
        digest_bytes(&conditional.digest())
            == recursive_ancestry_claim_digest(conditional_projection)?,
        "source inventory reconstruction is not bound to the projected claim digest"
    );
    let assumption_claim = receipt_claim_from_projection(&assumption.claim)?;
    ensure!(
        digest_bytes(&assumption_claim.digest()) == expected_claim,
        "assumption claim reconstruction differs from exact same-program OK"
    );
    let expected_resolved = ParsedClaim {
        output: expected_ok.output,
        ..parse_claim(conditional_projection)?
    };
    let resolved = conditional.resolve(&assumption_claim);
    match defect {
        None => {
            let resolved = resolved.context("canonical one-head stock resolve failed")?;
            ensure!(
                parsed_from_receipt_claim(&resolved) == expected_resolved,
                "canonical stock resolve output differs from the family-local resolved claim"
            );
        }
        Some(RecursiveAncestryInventoryDefect::Missing) => {
            ensure!(
                resolved.is_err(),
                "stock resolve unexpectedly accepted an empty assumption inventory"
            );
        }
        Some(RecursiveAncestryInventoryDefect::Extra) => {
            let resolved =
                resolved.context("stock resolve rejected the exact duplicate-head case")?;
            ensure!(
                parsed_from_receipt_claim(&resolved) != expected_resolved,
                "stock resolve unexpectedly removed more than one assumption"
            );
            let canonical_inventory = RecursiveAncestrySourceInventory {
                entries: vec![expected_entry],
            };
            let mut canonical_projection = conditional_projection.clone();
            canonical_projection.output_digest = hex::encode(
                reconstructed_inventory_output_digest(statement, &canonical_inventory)?,
            );
            let canonical_conditional = receipt_claim_with_inventory(
                &canonical_projection,
                statement,
                &canonical_inventory,
            )?;
            ensure!(
                resolved.digest() == canonical_conditional.digest()
                    && parsed_from_receipt_claim(&resolved)
                        == parsed_from_receipt_claim(&canonical_conditional),
                "stock resolve duplicate-head residual differs from the exact one-head claim"
            );
        }
        Some(RecursiveAncestryInventoryDefect::Pruned) => {
            ensure!(
                resolved.is_err(),
                "stock resolve unexpectedly opened a pruned assumption head"
            );
        }
    }
    Ok(defect)
}

fn receipt_claim_with_inventory(
    claim: &RecursiveAncestryClaim,
    statement: &[u8],
    inventory: &RecursiveAncestrySourceInventory,
) -> Result<ReceiptClaim> {
    let entries = inventory
        .entries
        .iter()
        .map(|entry| match entry {
            RecursiveAncestryInventoryEntry::Revealed {
                claim_digest,
                control_root,
            } => Ok(MaybePruned::Value(Assumption {
                claim: Risc0Digest::from(parse_digest(
                    claim_digest,
                    "source assumption claim digest",
                )?),
                control_root: Risc0Digest::from(parse_digest(
                    control_root,
                    "source assumption control root",
                )?),
            })),
            RecursiveAncestryInventoryEntry::Pruned { digest } => Ok(MaybePruned::Pruned(
                Risc0Digest::from(parse_digest(digest, "pruned source assumption digest")?),
            )),
        })
        .collect::<Result<Vec<_>>>()?;
    let mut reconstructed = receipt_claim_from_projection(claim)?;
    reconstructed.output = MaybePruned::Value(Some(Output {
        journal: MaybePruned::Pruned(Risc0Digest::from(sha256(statement))),
        assumptions: MaybePruned::Value(Assumptions(entries)),
    }));
    ensure!(
        digest_bytes(&reconstructed.output.digest())
            == parse_digest(&claim.output_digest, "claim output digest")?,
        "projected output digest differs from reconstructed source inventory"
    );
    Ok(reconstructed)
}

fn reconstructed_inventory_output_digest(
    statement: &[u8],
    inventory: &RecursiveAncestrySourceInventory,
) -> Result<[u8; DIGEST_BYTES]> {
    let entries = inventory
        .entries
        .iter()
        .map(|entry| match entry {
            RecursiveAncestryInventoryEntry::Revealed {
                claim_digest,
                control_root,
            } => Ok(MaybePruned::Value(Assumption {
                claim: Risc0Digest::from(parse_digest(
                    claim_digest,
                    "source assumption claim digest",
                )?),
                control_root: Risc0Digest::from(parse_digest(
                    control_root,
                    "source assumption control root",
                )?),
            })),
            RecursiveAncestryInventoryEntry::Pruned { digest } => Ok(MaybePruned::Pruned(
                Risc0Digest::from(parse_digest(digest, "pruned source assumption digest")?),
            )),
        })
        .collect::<Result<Vec<_>>>()?;
    let output = MaybePruned::Value(Some(Output {
        journal: MaybePruned::Pruned(Risc0Digest::from(sha256(statement))),
        assumptions: MaybePruned::Value(Assumptions(entries)),
    }));
    Ok(digest_bytes(&output.digest()))
}

fn receipt_claim_from_projection(claim: &RecursiveAncestryClaim) -> Result<ReceiptClaim> {
    Ok(ReceiptClaim {
        input: MaybePruned::Pruned(Risc0Digest::from(parse_digest(
            &claim.input_digest,
            "claim input digest",
        )?)),
        pre: MaybePruned::Pruned(Risc0Digest::from(parse_digest(
            &claim.pre_state_digest,
            "claim pre-state digest",
        )?)),
        post: MaybePruned::Pruned(Risc0Digest::from(parse_digest(
            &claim.post_state_digest,
            "claim post-state digest",
        )?)),
        exit_code: ExitCode::from_pair(claim.system_exit, claim.user_exit)
            .context("claim exit-code pair is invalid")?,
        output: MaybePruned::Pruned(Risc0Digest::from(parse_digest(
            &claim.output_digest,
            "claim output digest",
        )?)),
    })
}

fn parsed_from_receipt_claim(claim: &ReceiptClaim) -> ParsedClaim {
    let (system_exit, user_exit) = claim.exit_code.into_pair();
    ParsedClaim {
        input: digest_bytes(&claim.input.digest()),
        pre: digest_bytes(&claim.pre.digest()),
        post: digest_bytes(&claim.post.digest()),
        system_exit,
        user_exit,
        output: digest_bytes(&claim.output.digest()),
    }
}

fn receipt_claim_matches_projection(
    claim: &ReceiptClaim,
    projection: &RecursiveAncestryClaim,
) -> Result<bool> {
    let projected = receipt_claim_from_projection(projection)?;
    Ok(claim.digest() == projected.digest()
        && parsed_from_receipt_claim(claim) == parse_claim(projection)?)
}

fn parse_claim(claim: &RecursiveAncestryClaim) -> Result<ParsedClaim> {
    Ok(ParsedClaim {
        input: parse_digest(&claim.input_digest, "claim input digest")?,
        pre: parse_digest(&claim.pre_state_digest, "claim pre-state digest")?,
        post: parse_digest(&claim.post_state_digest, "claim post-state digest")?,
        system_exit: claim.system_exit,
        user_exit: claim.user_exit,
        output: parse_digest(&claim.output_digest, "claim output digest")?,
    })
}

fn validate_claim_projection(claim: &RecursiveAncestryClaim) -> Result<()> {
    let parsed = parse_claim(claim)?;
    let exit = ExitCode::from_pair(parsed.system_exit, parsed.user_exit)
        .context("claim exit-code pair is invalid")?;
    ensure!(
        exit.into_pair() == (parsed.system_exit, parsed.user_exit),
        "claim exit-code pair is not canonical"
    );
    let _ = recursive_ancestry_claim_digest(claim)?;
    Ok(())
}

fn validate_inventory_entry_shape(entry: &RecursiveAncestryInventoryEntry) -> Result<()> {
    match entry {
        RecursiveAncestryInventoryEntry::Revealed {
            claim_digest,
            control_root,
        } => {
            parse_digest(claim_digest, "source assumption claim digest")?;
            parse_digest(control_root, "source assumption control root")?;
        }
        RecursiveAncestryInventoryEntry::Pruned { digest } => {
            parse_digest(digest, "pruned source assumption digest")?;
        }
    }
    Ok(())
}

fn validate_operation_terminal(
    operation: &RecursiveAncestryOperation,
    terminal: &RecursiveAncestryTerminal,
) -> Result<()> {
    match (operation, terminal) {
        (
            RecursiveAncestryOperation::Lift { .. },
            RecursiveAncestryTerminal::Lift {
                segment_po2,
                control_id,
            },
        ) => {
            validate_lift_terminal_fields(*segment_po2, control_id)?;
        }
        (
            RecursiveAncestryOperation::Join { .. },
            RecursiveAncestryTerminal::Join { control_id },
        ) => {
            ensure!(
                control_id == RISC0_JOIN_CONTROL_ID_HEX,
                "join terminal control ID differs from the frozen stock control"
            );
        }
        (
            RecursiveAncestryOperation::Resolve { .. },
            RecursiveAncestryTerminal::Resolve { control_id },
        ) => {
            ensure!(
                control_id == RISC0_RESOLVE_CONTROL_ID_HEX,
                "resolve terminal control ID differs from the frozen stock control"
            );
        }
        _ => bail!("ancestry operation and terminal kinds differ"),
    }
    Ok(())
}

fn validate_lift_terminal(terminal: &RecursiveAncestryTerminal) -> Result<()> {
    let RecursiveAncestryTerminal::Lift {
        segment_po2,
        control_id,
    } = terminal
    else {
        bail!("assumption receipt terminal is not a normal lift");
    };
    validate_lift_terminal_fields(*segment_po2, control_id)
}

fn validate_lift_terminal_fields(segment_po2: u32, control_id: &str) -> Result<()> {
    let po2 = u8::try_from(segment_po2).context("lift segment exponent does not fit u8")?;
    let index = SUPPORTED_SEGMENT_PO2
        .iter()
        .position(|candidate| *candidate == po2)
        .context("normal-lift segment exponent is outside the supported range")?;
    ensure!(
        control_id == RISC0_NORMAL_LIFT_CONTROL_IDS_HEX[index],
        "normal-lift control ID differs from its segment exponent"
    );
    Ok(())
}

fn validate_recursive_ancestry_reference(
    reference: &RecursiveAncestryArtifactReference,
    expected_path: &str,
    expected_length: usize,
) -> Result<()> {
    validate_recursive_ancestry_path(&reference.path)?;
    ensure!(
        reference.path == expected_path,
        "ancestry artifact path differs from its parsed family"
    );
    ensure!(
        reference.byte_length
            == u64::try_from(expected_length).context("artifact length does not fit u64")?,
        "ancestry artifact length differs from its exact bound"
    );
    validate_lower_hex_exact(&reference.sha256, DIGEST_BYTES)
        .context("ancestry artifact SHA-256 is not exact lowercase hex")
}

fn validate_recursive_ancestry_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty() && path.len() <= RECURSIVE_ANCESTRY_MAX_PATH_BYTES,
        "ancestry artifact path is empty or too long"
    );
    ensure!(
        path.bytes().all(|byte| (0x21..=0x7e).contains(&byte)),
        "ancestry artifact path is not printable space-free ASCII"
    );
    ensure!(
        !path.starts_with('/')
            && !path.ends_with('/')
            && !path.contains('\\')
            && !path.contains(':')
            && path.split('/').all(|component| {
                !component.is_empty()
                    && component != "."
                    && component != ".."
                    && !component.ends_with('.')
                    && !component.ends_with(' ')
            }),
        "ancestry artifact path is not canonical repository-relative POSIX"
    );
    Ok(())
}

fn validate_bound_bytes(
    reference: &RecursiveAncestryArtifactReference,
    bytes: &[u8],
    label: &str,
) -> Result<()> {
    ensure!(
        reference.byte_length == u64::try_from(bytes.len())?,
        "{label} byte length differs from its binding"
    );
    ensure!(
        reference.sha256 == sha256_hex(bytes),
        "{label} SHA-256 differs from its binding"
    );
    Ok(())
}

fn earlier_claim(claims: &[ParsedClaim], ordinal: u32, current: usize) -> Result<ParsedClaim> {
    let index = usize::try_from(ordinal).context("ancestry ordinal does not fit usize")?;
    ensure!(index < current, "ancestry edge does not point backward");
    claims
        .get(index)
        .copied()
        .context("ancestry edge points outside the parsed graph")
}

fn canonical_source_fields(
    claim: ParsedClaim,
    program_id: [u8; DIGEST_BYTES],
    post: [u8; DIGEST_BYTES],
) -> bool {
    claim.input == [0; DIGEST_BYTES]
        && claim.pre == program_id
        && claim.post == post
        && claim.system_exit == 0
        && claim.user_exit == 0
}

fn conditional_output_digest(
    statement: &[u8],
    claim: [u8; DIGEST_BYTES],
    root: [u8; DIGEST_BYTES],
) -> [u8; DIGEST_BYTES] {
    let output = Output {
        journal: MaybePruned::Pruned(Risc0Digest::from(sha256(statement))),
        assumptions: MaybePruned::Value(Assumptions(vec![MaybePruned::Value(Assumption {
            claim: Risc0Digest::from(claim),
            control_root: Risc0Digest::from(root),
        })])),
    };
    digest_bytes(&output.digest())
}

fn parse_digest(value: &str, label: &str) -> Result<[u8; DIGEST_BYTES]> {
    validate_lower_hex_exact(value, DIGEST_BYTES)
        .with_context(|| format!("{label} is not exact lowercase hex"))?;
    let mut bytes = [0u8; DIGEST_BYTES];
    hex::decode_to_slice(value, &mut bytes).with_context(|| format!("cannot decode {label}"))?;
    Ok(bytes)
}

fn digest_bytes(digest: &Risc0Digest) -> [u8; DIGEST_BYTES] {
    let mut bytes = [0u8; DIGEST_BYTES];
    bytes.copy_from_slice(digest.as_bytes());
    bytes
}

fn sha256(bytes: &[u8]) -> [u8; DIGEST_BYTES] {
    Sha256::digest(bytes).into()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

impl RecursiveAncestryFamily {
    const fn resolve_outcome(self) -> RecursiveAncestrySemanticOutcome {
        match self {
            Self::TerminalResolve => RecursiveAncestrySemanticOutcome::ResolveExplicit,
            Self::ResolveThenJoin => RecursiveAncestrySemanticOutcome::ResolveZeroRoot,
            Self::TerminalJoin => RecursiveAncestrySemanticOutcome::ClaimEdge,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_json::json;

    use super::*;
    use crate::{constants::STATEMENT_PREFIX_BYTES, ergo_statement::ErgoStatementV1};

    fn fixture_statement() -> Vec<u8> {
        ErgoStatementV1::new(
            [0x11; DIGEST_BYTES],
            [0x22; DIGEST_BYTES],
            [0x42; DIGEST_BYTES],
            [0x44; DIGEST_BYTES],
            b"",
        )
        .unwrap()
        .encode()
        .unwrap()
    }

    #[test]
    fn empty_assumption_ok_derivation_matches_upstream_receipt_claim() {
        let image_id = [0x31; DIGEST_BYTES];
        let journal = b"independent empty-assumption ancestry claim";

        let derived =
            derive_empty_assumption_ok_recursive_ancestry_claim(&image_id, journal).unwrap();
        let upstream = ReceiptClaim::ok(Risc0Digest::from(image_id), journal.to_vec());
        let projected_upstream = project_verified_receipt_claim(&upstream).unwrap();

        assert_eq!(derived, projected_upstream);
        assert_eq!(
            recursive_ancestry_claim_digest(&derived).unwrap(),
            digest_bytes(&upstream.digest())
        );
        assert_eq!(derived.input_digest, "00".repeat(DIGEST_BYTES));
        assert_eq!(derived.pre_state_digest, hex::encode(image_id));
        assert_eq!((derived.system_exit, derived.user_exit), (0, 0));
    }

    #[test]
    fn verified_receipt_projection_preserves_every_claim_field_and_digest() {
        let upstream = ReceiptClaim {
            input: MaybePruned::Pruned(Risc0Digest::from([0x01; DIGEST_BYTES])),
            pre: MaybePruned::Pruned(Risc0Digest::from([0x02; DIGEST_BYTES])),
            post: MaybePruned::Pruned(Risc0Digest::from([0x03; DIGEST_BYTES])),
            exit_code: ExitCode::from_pair(0, 7).unwrap(),
            output: MaybePruned::Pruned(Risc0Digest::from([0x04; DIGEST_BYTES])),
        };

        let projected = project_verified_receipt_claim(&upstream).unwrap();

        assert_eq!(projected.input_digest, "01".repeat(DIGEST_BYTES));
        assert_eq!(projected.pre_state_digest, "02".repeat(DIGEST_BYTES));
        assert_eq!(projected.post_state_digest, "03".repeat(DIGEST_BYTES));
        assert_eq!((projected.system_exit, projected.user_exit), (0, 7));
        assert_eq!(projected.output_digest, "04".repeat(DIGEST_BYTES));
        assert_eq!(
            recursive_ancestry_claim_digest(&projected).unwrap(),
            digest_bytes(&upstream.digest())
        );
    }

    #[test]
    fn explicit_duplicate_inventory_derives_two_identical_revealed_heads_exactly() {
        let image_id = [0x41; DIGEST_BYTES];
        let journal = b"two-head conditional ancestry claim";
        let base = derive_empty_assumption_ok_recursive_ancestry_claim(&image_id, journal).unwrap();
        let head_claim = recursive_ancestry_claim_digest(&base).unwrap();
        let requested_root = [0x52; DIGEST_BYTES];
        let head = RecursiveAncestryInventoryEntry::Revealed {
            claim_digest: hex::encode(head_claim),
            control_root: hex::encode(requested_root),
        };
        let inventory = RecursiveAncestrySourceInventory {
            entries: vec![head.clone(), head],
        };
        let upstream_head = MaybePruned::Value(Assumption {
            claim: Risc0Digest::from(head_claim),
            control_root: Risc0Digest::from(requested_root),
        });
        let upstream_output = MaybePruned::Value(Some(Output {
            journal: MaybePruned::Pruned(Risc0Digest::from(sha256(journal))),
            assumptions: MaybePruned::Value(Assumptions(vec![
                upstream_head.clone(),
                upstream_head,
            ])),
        }));

        let conditional =
            derive_recursive_ancestry_claim_with_inventory(&base, journal, &inventory).unwrap();

        assert_eq!(conditional.input_digest, base.input_digest);
        assert_eq!(conditional.pre_state_digest, base.pre_state_digest);
        assert_eq!(conditional.post_state_digest, base.post_state_digest);
        assert_eq!(conditional.system_exit, base.system_exit);
        assert_eq!(conditional.user_exit, base.user_exit);
        assert_eq!(
            parse_digest(&conditional.output_digest, "derived conditional output").unwrap(),
            digest_bytes(&upstream_output.digest())
        );
        let mut upstream_claim = receipt_claim_from_projection(&base).unwrap();
        upstream_claim.output = upstream_output;
        assert_eq!(
            recursive_ancestry_claim_digest(&conditional).unwrap(),
            digest_bytes(&upstream_claim.digest())
        );
        assert_ne!(
            recursive_ancestry_claim_digest(&conditional).unwrap(),
            recursive_ancestry_claim_digest(&base).unwrap()
        );
    }

    #[test]
    fn explicit_inventory_claim_is_count_order_and_root_sensitive() {
        let image_id = [0x61; DIGEST_BYTES];
        let journal = b"inventory sensitivity";
        let base = derive_empty_assumption_ok_recursive_ancestry_claim(&image_id, journal).unwrap();
        let first = RecursiveAncestryInventoryEntry::Revealed {
            claim_digest: "71".repeat(DIGEST_BYTES),
            control_root: "72".repeat(DIGEST_BYTES),
        };
        let second = RecursiveAncestryInventoryEntry::Revealed {
            claim_digest: "73".repeat(DIGEST_BYTES),
            control_root: "74".repeat(DIGEST_BYTES),
        };
        let one = RecursiveAncestrySourceInventory {
            entries: vec![first.clone()],
        };
        let two = RecursiveAncestrySourceInventory {
            entries: vec![first.clone(), second.clone()],
        };
        let reversed = RecursiveAncestrySourceInventory {
            entries: vec![second, first.clone()],
        };
        let changed_root = RecursiveAncestrySourceInventory {
            entries: vec![
                first,
                RecursiveAncestryInventoryEntry::Revealed {
                    claim_digest: "73".repeat(DIGEST_BYTES),
                    control_root: "75".repeat(DIGEST_BYTES),
                },
            ],
        };

        let digest = |inventory: &RecursiveAncestrySourceInventory| {
            let claim =
                derive_recursive_ancestry_claim_with_inventory(&base, journal, inventory).unwrap();
            recursive_ancestry_claim_digest(&claim).unwrap()
        };

        let one_digest = digest(&one);
        let two_digest = digest(&two);
        assert_ne!(one_digest, two_digest, "head count must affect the claim");
        assert_ne!(
            two_digest,
            digest(&reversed),
            "head order must affect the claim"
        );
        assert_ne!(
            two_digest,
            digest(&changed_root),
            "requested control root must affect the claim"
        );
    }

    #[test]
    fn stock_resolve_distinguishes_the_three_exact_inventory_forms() {
        let statement = fixture_statement();
        assert_eq!(statement.len(), STATEMENT_PREFIX_BYTES);
        let mut projection = synthetic_terminal_resolve(&statement);
        assert_eq!(
            classify_recursive_ancestry_semantics(&projection, &statement, [0x22; DIGEST_BYTES])
                .unwrap(),
            RecursiveAncestrySemanticOutcome::Canonical
        );
        let canonical_source_claim =
            recursive_ancestry_claim_digest(&projection.steps[0].claim).unwrap();

        set_inventory(
            &mut projection,
            RecursiveAncestryInventoryDefect::Pruned,
            &statement,
        );
        assert_eq!(
            recursive_ancestry_claim_digest(&projection.steps[0].claim).unwrap(),
            canonical_source_claim,
            "the exact pruned head must preserve the upstream source claim digest"
        );
        assert_eq!(
            classify_recursive_ancestry_semantics(&projection, &statement, [0x22; DIGEST_BYTES])
                .unwrap(),
            RecursiveAncestrySemanticOutcome::AssumptionInventory(
                RecursiveAncestryInventoryDefect::Pruned
            )
        );

        projection = synthetic_terminal_resolve(&statement);
        set_inventory(
            &mut projection,
            RecursiveAncestryInventoryDefect::Missing,
            &statement,
        );
        assert_ne!(
            recursive_ancestry_claim_digest(&projection.steps[0].claim).unwrap(),
            canonical_source_claim,
            "an empty inventory must require a genuinely changed source-claim seal"
        );
        assert_eq!(
            classify_recursive_ancestry_semantics(&projection, &statement, [0x22; DIGEST_BYTES])
                .unwrap(),
            RecursiveAncestrySemanticOutcome::AssumptionInventory(
                RecursiveAncestryInventoryDefect::Missing
            )
        );

        projection = synthetic_terminal_resolve(&statement);
        set_inventory(
            &mut projection,
            RecursiveAncestryInventoryDefect::Extra,
            &statement,
        );
        assert_ne!(
            recursive_ancestry_claim_digest(&projection.steps[0].claim).unwrap(),
            canonical_source_claim,
            "a duplicate head must require a genuinely changed source-claim seal"
        );
        assert_eq!(
            classify_recursive_ancestry_semantics(&projection, &statement, [0x22; DIGEST_BYTES])
                .unwrap(),
            RecursiveAncestrySemanticOutcome::AssumptionInventory(
                RecursiveAncestryInventoryDefect::Extra
            )
        );
    }

    #[test]
    fn typed_pruned_head_transition_preserves_the_authenticated_source_claim() {
        let statement = fixture_statement();
        let projection = synthetic_terminal_resolve(&statement);
        let witness = recursive_ancestry_revealed_head_witness(&projection).unwrap();
        let source_claim = recursive_ancestry_claim_digest(&projection.steps[0].claim).unwrap();

        let pruned = prune_recursive_ancestry_revealed_head(
            &projection,
            &statement,
            [0x22; DIGEST_BYTES],
            witness,
        )
        .unwrap();

        assert_eq!(
            recursive_ancestry_claim_digest(&pruned.steps[0].claim).unwrap(),
            source_claim
        );
        let mut expected = projection.clone();
        expected
            .assumption_receipt
            .as_mut()
            .unwrap()
            .source_inventory
            .entries = vec![RecursiveAncestryInventoryEntry::Pruned {
            digest: hex::encode(witness.exact_digest),
        }];
        assert_eq!(pruned, expected);
        assert_eq!(
            classify_recursive_ancestry_semantics(&pruned, &statement, [0x22; DIGEST_BYTES],)
                .unwrap(),
            RecursiveAncestrySemanticOutcome::AssumptionInventory(
                RecursiveAncestryInventoryDefect::Pruned
            )
        );
    }

    #[test]
    fn typed_pruned_head_transition_rejects_wrong_witness_or_noncanonical_base() {
        let statement = fixture_statement();
        let projection = synthetic_terminal_resolve(&statement);
        let witness = recursive_ancestry_revealed_head_witness(&projection).unwrap();

        for wrong in [
            RecursiveAncestryRevealedHeadWitness {
                claim_digest: [0x91; DIGEST_BYTES],
                ..witness
            },
            RecursiveAncestryRevealedHeadWitness {
                control_root: [0x92; DIGEST_BYTES],
                ..witness
            },
            RecursiveAncestryRevealedHeadWitness {
                exact_digest: [0x93; DIGEST_BYTES],
                ..witness
            },
        ] {
            assert!(
                prune_recursive_ancestry_revealed_head(
                    &projection,
                    &statement,
                    [0x22; DIGEST_BYTES],
                    wrong,
                )
                .is_err()
            );
        }

        let mut already_pruned = projection.clone();
        set_inventory(
            &mut already_pruned,
            RecursiveAncestryInventoryDefect::Pruned,
            &statement,
        );
        assert!(recursive_ancestry_revealed_head_witness(&already_pruned).is_err());
        assert!(
            prune_recursive_ancestry_revealed_head(
                &already_pruned,
                &statement,
                [0x22; DIGEST_BYTES],
                witness,
            )
            .is_err()
        );

        let terminal_join = synthetic_terminal_join(&statement);
        assert!(recursive_ancestry_revealed_head_witness(&terminal_join).is_err());
    }

    #[test]
    fn inventory_drift_outside_the_three_exact_forms_is_private() {
        let statement = fixture_statement();
        let mut projection = synthetic_terminal_resolve(&statement);
        projection
            .assumption_receipt
            .as_mut()
            .unwrap()
            .source_inventory
            .entries = vec![RecursiveAncestryInventoryEntry::Pruned {
            digest: "99".repeat(DIGEST_BYTES),
        }];
        assert!(
            classify_recursive_ancestry_semantics(&projection, &statement, [0x22; DIGEST_BYTES])
                .is_err()
        );

        let mut coordinated = synthetic_terminal_resolve(&statement);
        set_inventory(
            &mut coordinated,
            RecursiveAncestryInventoryDefect::Pruned,
            &statement,
        );
        coordinated.steps[1].claim.post_state_digest = "77".repeat(DIGEST_BYTES);
        assert!(
            classify_recursive_ancestry_semantics(&coordinated, &statement, [0x22; DIGEST_BYTES])
                .is_err()
        );
    }

    #[test]
    fn v1_wire_and_unknown_inventory_fields_reject() {
        let statement = fixture_statement();
        let projection = synthetic_terminal_resolve(&statement);
        let mut value = serde_json::to_value(&projection).unwrap();
        value["format"] = json!("Eip0045B4RecursiveAncestryV1");
        value["formatVersion"] = json!(1);
        let bytes = canonical_json_bytes(&value).unwrap();
        let parsed = parse_recursive_ancestry_jcs(&bytes).unwrap();
        assert!(
            validate_recursive_ancestry_structure(&parsed, &statement, [0x22; DIGEST_BYTES])
                .is_err()
        );

        let mut value = serde_json::to_value(&projection).unwrap();
        value["assumptionReceipt"]["sourceInventory"]["unknown"] = json!(true);
        assert!(parse_recursive_ancestry_jcs(&canonical_json_bytes(&value).unwrap()).is_err());
    }

    #[test]
    fn stock_join_replay_accepts_the_other_two_canonical_families() {
        let statement = fixture_statement();
        for projection in [
            synthetic_terminal_join(&statement),
            synthetic_resolve_then_join(&statement),
        ] {
            assert_eq!(
                classify_recursive_ancestry_semantics(
                    &projection,
                    &statement,
                    [0x22; DIGEST_BYTES],
                )
                .unwrap(),
                RecursiveAncestrySemanticOutcome::Canonical
            );
        }
    }

    #[test]
    fn stock_join_replay_classifies_one_join_edge_mutation() {
        let statement = fixture_statement();
        let mut projection = synthetic_terminal_join(&statement);
        projection.steps[2].claim.output_digest = "99".repeat(DIGEST_BYTES);
        assert_eq!(
            classify_recursive_ancestry_semantics(&projection, &statement, [0x22; DIGEST_BYTES],)
                .unwrap(),
            RecursiveAncestrySemanticOutcome::ClaimEdge
        );
    }

    #[test]
    fn final_resolve_and_join_claims_take_family_specific_precedence() {
        let statement = fixture_statement();
        for (mut projection, expected) in [
            (
                synthetic_terminal_resolve(&statement),
                RecursiveAncestrySemanticOutcome::ResolveExplicit,
            ),
            (
                synthetic_resolve_then_join(&statement),
                RecursiveAncestrySemanticOutcome::ResolveZeroRoot,
            ),
        ] {
            projection.steps.last_mut().unwrap().claim.output_digest = "99".repeat(DIGEST_BYTES);
            assert_eq!(
                classify_recursive_ancestry_semantics(
                    &projection,
                    &statement,
                    [0x22; DIGEST_BYTES],
                )
                .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn nonfinal_resolve_and_join_edges_remain_claim_edge_defects() {
        let statement = fixture_statement();

        let mut terminal_join = synthetic_terminal_join(&statement);
        terminal_join.steps[0].claim.post_state_digest = "99".repeat(DIGEST_BYTES);
        assert_eq!(
            classify_recursive_ancestry_semantics(
                &terminal_join,
                &statement,
                [0x22; DIGEST_BYTES],
            )
            .unwrap(),
            RecursiveAncestrySemanticOutcome::ClaimEdge
        );

        let mut explicit = synthetic_terminal_resolve(&statement);
        explicit.steps[0].claim.post_state_digest = "99".repeat(DIGEST_BYTES);
        assert_eq!(
            classify_recursive_ancestry_semantics(&explicit, &statement, [0x22; DIGEST_BYTES],)
                .unwrap(),
            RecursiveAncestrySemanticOutcome::ClaimEdge
        );

        let mut zero_root = synthetic_resolve_then_join(&statement);
        zero_root.steps[2].claim.post_state_digest = "99".repeat(DIGEST_BYTES);
        assert_eq!(
            classify_recursive_ancestry_semantics(&zero_root, &statement, [0x22; DIGEST_BYTES],)
                .unwrap(),
            RecursiveAncestrySemanticOutcome::ClaimEdge
        );
    }

    #[test]
    fn authenticated_ok_lift_in_the_conditional_slot_is_a_public_claim_edge() {
        let statement = fixture_statement();
        let mut projection = synthetic_terminal_resolve(&statement);
        let assumption = projection.assumption_receipt.as_ref().unwrap().clone();
        projection.steps[0].claim = assumption.claim;
        projection.steps[0].terminal = assumption.terminal;
        projection.steps[0].raw_seal.byte_length = assumption.raw_seal.byte_length;
        projection.steps[0].raw_seal.sha256 = assumption.raw_seal.sha256;

        assert_eq!(
            classify_recursive_ancestry_semantics(&projection, &statement, [0x22; DIGEST_BYTES],)
                .unwrap(),
            RecursiveAncestrySemanticOutcome::ClaimEdge
        );
    }

    #[test]
    fn arbitrary_canonical_inventory_output_drift_remains_private() {
        let statement = fixture_statement();
        let mut projection = synthetic_terminal_resolve(&statement);
        projection.steps[0].claim.output_digest = "99".repeat(DIGEST_BYTES);

        assert!(
            classify_recursive_ancestry_semantics(&projection, &statement, [0x22; DIGEST_BYTES],)
                .is_err()
        );
    }

    #[test]
    fn exact_ok_lift_guard_does_not_mask_resolve_specific_faults() {
        let statement = fixture_statement();

        let mut assumption_claim = synthetic_terminal_resolve(&statement);
        assumption_claim
            .assumption_receipt
            .as_mut()
            .unwrap()
            .claim
            .output_digest = "98".repeat(DIGEST_BYTES);
        assert_eq!(
            classify_recursive_ancestry_semantics(
                &assumption_claim,
                &statement,
                [0x22; DIGEST_BYTES],
            )
            .unwrap(),
            RecursiveAncestrySemanticOutcome::ResolveExplicit
        );

        let mut producer_program = synthetic_terminal_resolve(&statement);
        producer_program.steps[0].claim.pre_state_digest = "99".repeat(DIGEST_BYTES);
        assert_eq!(
            classify_recursive_ancestry_semantics(
                &producer_program,
                &statement,
                [0x22; DIGEST_BYTES],
            )
            .unwrap(),
            RecursiveAncestrySemanticOutcome::ResolveExplicit
        );
    }

    #[test]
    fn nonfinal_claim_edge_cannot_be_masked_by_a_final_family_claim_fault() {
        let statement = fixture_statement();
        let mut projection = synthetic_resolve_then_join(&statement);
        projection.steps[2].claim.post_state_digest = "98".repeat(DIGEST_BYTES);
        projection.steps.last_mut().unwrap().claim.output_digest = "99".repeat(DIGEST_BYTES);

        assert_eq!(
            classify_recursive_ancestry_semantics(&projection, &statement, [0x22; DIGEST_BYTES],)
                .unwrap(),
            RecursiveAncestrySemanticOutcome::ClaimEdge
        );
    }

    fn alternate_program_step_zero_fixture(statement: &[u8]) -> RecursiveAncestryProjection {
        let mut projection = synthetic_terminal_resolve(statement);
        let parsed = parse_ergo_statement_v1(statement).unwrap();
        let alternate = ErgoStatementV1::new(parsed.chain_domain_id(), parsed.profile_id(),
            [0x99; DIGEST_BYTES], parsed.contract_id(), parsed.application_payload()).unwrap().encode().unwrap();
        projection.steps[0].claim = derive_empty_assumption_ok_recursive_ancestry_claim(
            &[0x99; DIGEST_BYTES], &alternate).unwrap();
        projection
    }

    #[test]
    fn exact_alternate_program_step_zero_reaches_shared_resolve_explicit() {
        let statement = fixture_statement();
        let positive = synthetic_terminal_resolve(&statement);
        assert_eq!(classify_recursive_ancestry_semantics(&positive, &statement, [0x22; DIGEST_BYTES]).unwrap(),
            RecursiveAncestrySemanticOutcome::Canonical);
        let alternate = alternate_program_step_zero_fixture(&statement);
        assert_eq!(alternate.assumption_receipt, positive.assumption_receipt);
        assert_eq!(alternate.steps[1], positive.steps[1]);
        assert_eq!(classify_recursive_ancestry_semantics(&alternate, &statement, [0x22; DIGEST_BYTES]).unwrap(),
            RecursiveAncestrySemanticOutcome::ResolveExplicit);
    }

    fn mutate_one_claim_field(claim: &mut RecursiveAncestryClaim, field: usize) {
        match field {
            0 => claim.input_digest = "88".repeat(DIGEST_BYTES),
            1 => claim.pre_state_digest = "88".repeat(DIGEST_BYTES),
            2 => claim.post_state_digest = "88".repeat(DIGEST_BYTES),
            3 => claim.system_exit = 1,
            4 => claim.user_exit = 1,
            5 => claim.output_digest = "88".repeat(DIGEST_BYTES),
            _ => unreachable!(),
        }
    }

    #[test]
    fn alternate_program_route_requires_every_source_and_final_claim_field() {
        let statement = fixture_statement();
        let exact = alternate_program_step_zero_fixture(&statement);
        assert!(matches_exact_alternate_program_step_zero(&exact, &statement).unwrap());
        for selected in 0..2 {
            for field in 0..6 {
                let mut changed = exact.clone();
                mutate_one_claim_field(&mut changed.steps[selected].claim, field);
                validate_recursive_ancestry_structure(&changed, &statement, [0x22; DIGEST_BYTES]).unwrap();
                assert!(!matches_exact_alternate_program_step_zero(&changed, &statement).unwrap(),
                    "step {selected} field {field}");
                assert!(classify_recursive_ancestry_semantics(&changed, &statement, [0x22; DIGEST_BYTES]).is_err(),
                    "step {selected} field {field} became a typed observation");
            }
        }
        // The older conditional-output/program mismatch path is not this new route.
        let mut old_case = synthetic_terminal_resolve(&statement);
        old_case.steps[0].claim.pre_state_digest = "88".repeat(DIGEST_BYTES);
        assert!(!matches_exact_alternate_program_step_zero(&old_case, &statement).unwrap());
        assert_eq!(classify_recursive_ancestry_semantics(&old_case, &statement, [0x22; DIGEST_BYTES]).unwrap(),
            RecursiveAncestrySemanticOutcome::ResolveExplicit);
    }

    #[test]
    fn alternate_program_route_requires_original_assumption_root_and_inventory() {
        let statement = fixture_statement();
        let exact = alternate_program_step_zero_fixture(&statement);
        assert!(matches_exact_alternate_program_step_zero(&exact, &statement).unwrap());
        for field in 0..6 {
            let mut changed = exact.clone();
            mutate_one_claim_field(&mut changed.assumption_receipt.as_mut().unwrap().claim, field);
            assert!(!matches_exact_alternate_program_step_zero(&changed, &statement).unwrap());
            // Existing assumption-claim precedence remains a distinct semantic route.
            assert_eq!(classify_recursive_ancestry_semantics(&changed, &statement, [0x22; DIGEST_BYTES]).unwrap(),
                RecursiveAncestrySemanticOutcome::ResolveExplicit);
        }
        let mut changed = exact.clone();
        changed.assumption_receipt.as_mut().unwrap().requested_control_root = "00".repeat(DIGEST_BYTES);
        assert!(!matches_exact_alternate_program_step_zero(&changed, &statement).unwrap());
        let original = exact.assumption_receipt.as_ref().unwrap().source_inventory.entries[0].clone();
        let head = recursive_ancestry_revealed_head_witness(&exact).unwrap();
        for entries in [vec![], vec![original.clone(), original],
            vec![RecursiveAncestryInventoryEntry::Pruned { digest: hex::encode(head.exact_digest) }],
            vec![RecursiveAncestryInventoryEntry::Revealed {
                claim_digest: "88".repeat(DIGEST_BYTES), control_root: RISC0_INNER_CONTROL_ROOT_HEX.to_owned() }],
            vec![RecursiveAncestryInventoryEntry::Revealed {
                claim_digest: hex::encode(head.claim_digest), control_root: "88".repeat(DIGEST_BYTES) }],
        ] {
            let mut changed = exact.clone();
            changed.assumption_receipt.as_mut().unwrap().source_inventory.entries = entries;
            validate_recursive_ancestry_structure(&changed, &statement, [0x22; DIGEST_BYTES]).unwrap();
            assert!(!matches_exact_alternate_program_step_zero(&changed, &statement).unwrap());
            assert!(classify_recursive_ancestry_semantics(&changed, &statement, [0x22; DIGEST_BYTES]).is_err());
        }
    }

    #[test]
    fn alternate_program_route_derives_only_the_program_field_journal_change() {
        let statement = fixture_statement();
        let parsed = parse_ergo_statement_v1(&statement).unwrap();
        let exact = alternate_program_step_zero_fixture(&statement);
        assert!(matches_exact_alternate_program_step_zero(&exact, &statement).unwrap());
        for field in 0..4 {
            let mut chain = parsed.chain_domain_id();
            let mut profile = parsed.profile_id();
            let mut contract = parsed.contract_id();
            let mut payload = parsed.application_payload().to_vec();
            match field { 0 => chain[0] ^= 1, 1 => profile[0] ^= 1,
                2 => contract[0] ^= 1, 3 => payload.push(1), _ => unreachable!() }
            let journal = ErgoStatementV1::new(chain, profile, [0x99; DIGEST_BYTES], contract, &payload)
                .unwrap().encode().unwrap();
            let mut changed = exact.clone();
            changed.steps[0].claim = derive_empty_assumption_ok_recursive_ancestry_claim(
                &[0x99; DIGEST_BYTES], &journal).unwrap();
            validate_recursive_ancestry_structure(&changed, &statement, [0x22; DIGEST_BYTES]).unwrap();
            assert!(!matches_exact_alternate_program_step_zero(&changed, &statement).unwrap());
            assert!(classify_recursive_ancestry_semantics(&changed, &statement, [0x22; DIGEST_BYTES]).is_err());
        }
    }

    #[test]
    fn alternate_program_route_is_explicit_family_graph_and_lift15_only() {
        let statement = fixture_statement();
        let exact = alternate_program_step_zero_fixture(&statement);
        assert!(matches_exact_alternate_program_step_zero(&exact, &statement).unwrap());
        assert!(!matches_exact_alternate_program_step_zero(&synthetic_resolve_then_join(&statement), &statement).unwrap());
        for target in 0..2 {
            let mut changed = exact.clone();
            let terminal = if target == 0 { &mut changed.steps[0].terminal }
                else { &mut changed.assumption_receipt.as_mut().unwrap().terminal };
            *terminal = RecursiveAncestryTerminal::Lift { segment_po2: 16,
                control_id: RISC0_NORMAL_LIFT_CONTROL_IDS_HEX[1].to_owned() };
            validate_recursive_ancestry_structure(&changed, &statement, [0x22; DIGEST_BYTES]).unwrap();
            assert!(!matches_exact_alternate_program_step_zero(&changed, &statement).unwrap());
            assert!(classify_recursive_ancestry_semantics(&changed, &statement, [0x22; DIGEST_BYTES]).is_err());
        }
        for step in 0..2 {
            let mut changed = exact.clone(); changed.steps[step].ordinal += 1;
            assert!(!matches_exact_alternate_program_step_zero(&changed, &statement).unwrap());
            assert!(validate_recursive_ancestry_structure(&changed, &statement, [0x22; DIGEST_BYTES]).is_err());
        }
        let mut changed = exact.clone(); changed.steps[1].operation = RecursiveAncestryOperation::Resolve { conditional_step: 1 };
        assert!(!matches_exact_alternate_program_step_zero(&changed, &statement).unwrap());
        assert!(validate_recursive_ancestry_structure(&changed, &statement, [0x22; DIGEST_BYTES]).is_err());
    }

    pub(crate) fn synthetic_terminal_resolve(statement: &[u8]) -> RecursiveAncestryProjection {
        let statement_value = parse_ergo_statement_v1(statement).unwrap();
        let program_id = statement_value.program_id();
        let profile_id = statement_value.profile_id();
        let ok = ok_receipt_claim_digests(&program_id, statement).unwrap();
        let root =
            recursive_ancestry_expected_assumption_root(RecursiveAncestryFamily::TerminalResolve)
                .unwrap()
                .unwrap();
        let inventory = canonical_inventory(ok.expected_claim, root);
        let conditional_output =
            reconstructed_inventory_output_digest(statement, &inventory).unwrap();
        let source_claim = RecursiveAncestryClaim {
            input_digest: "00".repeat(DIGEST_BYTES),
            pre_state_digest: hex::encode(program_id),
            post_state_digest: hex::encode(ok.post),
            system_exit: 0,
            user_exit: 0,
            output_digest: hex::encode(conditional_output),
        };
        let final_claim = RecursiveAncestryClaim {
            input_digest: "00".repeat(DIGEST_BYTES),
            pre_state_digest: hex::encode(program_id),
            post_state_digest: hex::encode(ok.post),
            system_exit: 0,
            user_exit: 0,
            output_digest: hex::encode(ok.output),
        };
        let family = RecursiveAncestryFamily::TerminalResolve;
        let terminal_lift = RecursiveAncestryTerminal::Lift {
            segment_po2: 15,
            control_id: RISC0_NORMAL_LIFT_CONTROL_IDS_HEX[0].to_owned(),
        };
        RecursiveAncestryProjection {
            format: RECURSIVE_ANCESTRY_FORMAT.to_owned(),
            format_version: RECURSIVE_ANCESTRY_FORMAT_VERSION,
            case_id: family.case_id().to_owned(),
            profile_id: hex::encode(profile_id),
            program_id: hex::encode(program_id),
            statement: recursive_ancestry_artifact_reference(
                recursive_ancestry_case_path(family, RECURSIVE_ANCESTRY_STATEMENT_FILE),
                statement,
            )
            .unwrap(),
            family,
            assumption_receipt: Some(RecursiveAncestryAssumption {
                claim: final_claim.clone(),
                requested_control_root: hex::encode(root),
                source_inventory: inventory,
                raw_seal: RecursiveAncestryArtifactReference {
                    path: recursive_ancestry_case_path(
                        family,
                        RECURSIVE_ANCESTRY_ASSUMPTION_SEAL_FILE,
                    ),
                    byte_length: PROOF_BYTES as u64,
                    sha256: "11".repeat(DIGEST_BYTES),
                },
                terminal: terminal_lift.clone(),
            }),
            steps: vec![
                RecursiveAncestryStep {
                    ordinal: 0,
                    operation: RecursiveAncestryOperation::Lift { segment_index: 0 },
                    claim: source_claim,
                    raw_seal: RecursiveAncestryArtifactReference {
                        path: recursive_ancestry_case_path(
                            family,
                            "candidate-ancestry-step-00-raw-seal.bin",
                        ),
                        byte_length: PROOF_BYTES as u64,
                        sha256: "22".repeat(DIGEST_BYTES),
                    },
                    terminal: terminal_lift,
                },
                RecursiveAncestryStep {
                    ordinal: 1,
                    operation: RecursiveAncestryOperation::Resolve {
                        conditional_step: 0,
                    },
                    claim: final_claim,
                    raw_seal: RecursiveAncestryArtifactReference {
                        path: recursive_ancestry_case_path(
                            family,
                            RECURSIVE_ANCESTRY_FINAL_SEAL_FILE,
                        ),
                        byte_length: PROOF_BYTES as u64,
                        sha256: "33".repeat(DIGEST_BYTES),
                    },
                    terminal: RecursiveAncestryTerminal::Resolve {
                        control_id: RISC0_RESOLVE_CONTROL_ID_HEX.to_owned(),
                    },
                },
            ],
        }
    }

    pub(crate) fn synthetic_terminal_join(statement: &[u8]) -> RecursiveAncestryProjection {
        let family = RecursiveAncestryFamily::TerminalJoin;
        let statement_value = parse_ergo_statement_v1(statement).unwrap();
        let program_id = statement_value.program_id();
        let profile_id = statement_value.profile_id();
        let midpoint = [0x77; DIGEST_BYTES];
        let ok = ok_receipt_claim_digests(&program_id, statement).unwrap();
        let first = projected_claim(program_id, midpoint, 2, [0; DIGEST_BYTES]);
        let second = projected_claim(midpoint, ok.post, 0, ok.output);
        let final_claim = projected_claim(program_id, ok.post, 0, ok.output);
        RecursiveAncestryProjection {
            format: RECURSIVE_ANCESTRY_FORMAT.to_owned(),
            format_version: RECURSIVE_ANCESTRY_FORMAT_VERSION,
            case_id: family.case_id().to_owned(),
            profile_id: hex::encode(profile_id),
            program_id: hex::encode(program_id),
            statement: recursive_ancestry_artifact_reference(
                recursive_ancestry_case_path(family, RECURSIVE_ANCESTRY_STATEMENT_FILE),
                statement,
            )
            .unwrap(),
            family,
            assumption_receipt: None,
            steps: vec![
                synthetic_step(
                    family,
                    0,
                    RecursiveAncestryOperation::Lift { segment_index: 0 },
                    first,
                    lift_terminal(0),
                ),
                synthetic_step(
                    family,
                    1,
                    RecursiveAncestryOperation::Lift { segment_index: 1 },
                    second,
                    lift_terminal(1),
                ),
                synthetic_step(
                    family,
                    2,
                    RecursiveAncestryOperation::Join {
                        left_step: 0,
                        right_step: 1,
                    },
                    final_claim,
                    RecursiveAncestryTerminal::Join {
                        control_id: RISC0_JOIN_CONTROL_ID_HEX.to_owned(),
                    },
                ),
            ],
        }
    }

    pub(crate) fn synthetic_resolve_then_join(statement: &[u8]) -> RecursiveAncestryProjection {
        let family = RecursiveAncestryFamily::ResolveThenJoin;
        let statement_value = parse_ergo_statement_v1(statement).unwrap();
        let program_id = statement_value.program_id();
        let profile_id = statement_value.profile_id();
        let midpoint = [0x77; DIGEST_BYTES];
        let ok = ok_receipt_claim_digests(&program_id, statement).unwrap();
        let root = [0; DIGEST_BYTES];
        let inventory = canonical_inventory(ok.expected_claim, root);
        let conditional_output =
            reconstructed_inventory_output_digest(statement, &inventory).unwrap();
        let first = projected_claim(program_id, midpoint, 2, [0; DIGEST_BYTES]);
        let conditional = projected_claim(midpoint, ok.post, 0, conditional_output);
        let resolved = projected_claim(midpoint, ok.post, 0, ok.output);
        let final_claim = projected_claim(program_id, ok.post, 0, ok.output);
        RecursiveAncestryProjection {
            format: RECURSIVE_ANCESTRY_FORMAT.to_owned(),
            format_version: RECURSIVE_ANCESTRY_FORMAT_VERSION,
            case_id: family.case_id().to_owned(),
            profile_id: hex::encode(profile_id),
            program_id: hex::encode(program_id),
            statement: recursive_ancestry_artifact_reference(
                recursive_ancestry_case_path(family, RECURSIVE_ANCESTRY_STATEMENT_FILE),
                statement,
            )
            .unwrap(),
            family,
            assumption_receipt: Some(RecursiveAncestryAssumption {
                claim: final_claim.clone(),
                requested_control_root: hex::encode(root),
                source_inventory: inventory,
                raw_seal: synthetic_reference(
                    family,
                    RECURSIVE_ANCESTRY_ASSUMPTION_SEAL_FILE,
                    0x11,
                ),
                terminal: lift_terminal(0),
            }),
            steps: vec![
                synthetic_step(
                    family,
                    0,
                    RecursiveAncestryOperation::Lift { segment_index: 0 },
                    first,
                    lift_terminal(0),
                ),
                synthetic_step(
                    family,
                    1,
                    RecursiveAncestryOperation::Lift { segment_index: 1 },
                    conditional,
                    lift_terminal(1),
                ),
                synthetic_step(
                    family,
                    2,
                    RecursiveAncestryOperation::Resolve {
                        conditional_step: 1,
                    },
                    resolved,
                    RecursiveAncestryTerminal::Resolve {
                        control_id: RISC0_RESOLVE_CONTROL_ID_HEX.to_owned(),
                    },
                ),
                synthetic_step(
                    family,
                    3,
                    RecursiveAncestryOperation::Join {
                        left_step: 0,
                        right_step: 2,
                    },
                    final_claim,
                    RecursiveAncestryTerminal::Join {
                        control_id: RISC0_JOIN_CONTROL_ID_HEX.to_owned(),
                    },
                ),
            ],
        }
    }

    fn projected_claim(
        pre: [u8; DIGEST_BYTES],
        post: [u8; DIGEST_BYTES],
        system_exit: u32,
        output: [u8; DIGEST_BYTES],
    ) -> RecursiveAncestryClaim {
        RecursiveAncestryClaim {
            input_digest: "00".repeat(DIGEST_BYTES),
            pre_state_digest: hex::encode(pre),
            post_state_digest: hex::encode(post),
            system_exit,
            user_exit: 0,
            output_digest: hex::encode(output),
        }
    }

    fn synthetic_step(
        family: RecursiveAncestryFamily,
        ordinal: u32,
        operation: RecursiveAncestryOperation,
        claim: RecursiveAncestryClaim,
        terminal: RecursiveAncestryTerminal,
    ) -> RecursiveAncestryStep {
        let file = if usize::try_from(ordinal).unwrap() + 1 == family.step_count() {
            RECURSIVE_ANCESTRY_FINAL_SEAL_FILE.to_owned()
        } else {
            format!("candidate-ancestry-step-{ordinal:02}-raw-seal.bin")
        };
        RecursiveAncestryStep {
            ordinal,
            operation,
            claim,
            raw_seal: synthetic_reference(family, &file, u8::try_from(ordinal).unwrap() + 0x20),
            terminal,
        }
    }

    fn synthetic_reference(
        family: RecursiveAncestryFamily,
        file: &str,
        octet: u8,
    ) -> RecursiveAncestryArtifactReference {
        RecursiveAncestryArtifactReference {
            path: recursive_ancestry_case_path(family, file),
            byte_length: PROOF_BYTES as u64,
            sha256: format!("{octet:02x}").repeat(DIGEST_BYTES),
        }
    }

    fn lift_terminal(index: usize) -> RecursiveAncestryTerminal {
        RecursiveAncestryTerminal::Lift {
            segment_po2: u32::from(SUPPORTED_SEGMENT_PO2[index]),
            control_id: RISC0_NORMAL_LIFT_CONTROL_IDS_HEX[index].to_owned(),
        }
    }

    fn canonical_inventory(
        claim: [u8; DIGEST_BYTES],
        root: [u8; DIGEST_BYTES],
    ) -> RecursiveAncestrySourceInventory {
        RecursiveAncestrySourceInventory {
            entries: vec![RecursiveAncestryInventoryEntry::Revealed {
                claim_digest: hex::encode(claim),
                control_root: hex::encode(root),
            }],
        }
    }

    fn set_inventory(
        projection: &mut RecursiveAncestryProjection,
        defect: RecursiveAncestryInventoryDefect,
        statement: &[u8],
    ) {
        let assumption = projection.assumption_receipt.as_mut().unwrap();
        let canonical = RecursiveAncestryInventoryEntry::Revealed {
            claim_digest: hex::encode(recursive_ancestry_claim_digest(&assumption.claim).unwrap()),
            control_root: assumption.requested_control_root.clone(),
        };
        assumption.source_inventory.entries = match defect {
            RecursiveAncestryInventoryDefect::Missing => vec![],
            RecursiveAncestryInventoryDefect::Extra => vec![canonical.clone(), canonical],
            RecursiveAncestryInventoryDefect::Pruned => {
                let RecursiveAncestryInventoryEntry::Revealed {
                    claim_digest,
                    control_root,
                } = canonical
                else {
                    unreachable!()
                };
                let head = Assumption {
                    claim: Risc0Digest::from(
                        parse_digest(&claim_digest, "fixture claim digest").unwrap(),
                    ),
                    control_root: Risc0Digest::from(
                        parse_digest(&control_root, "fixture root").unwrap(),
                    ),
                };
                vec![RecursiveAncestryInventoryEntry::Pruned {
                    digest: hex::encode(head.digest().as_bytes()),
                }]
            }
        };
        projection.steps[0].claim.output_digest = hex::encode(
            reconstructed_inventory_output_digest(statement, &assumption.source_inventory).unwrap(),
        );
    }
}
