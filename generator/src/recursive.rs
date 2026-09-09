//! Candidate-only construction and replay of stock RISC Zero recursion paths.
//!
//! This module deliberately stops below B7. It retains the source composite
//! receipt and every intermediate succinct receipt so a fresh checker can
//! replay the claimed `lift`, `join`, and `resolve` graph. The ancestry archive
//! is evidence from this generator run; it is not committed by the final
//! receipt and is never described as consensus provenance.

use std::{fmt, str::FromStr};

use anyhow::{Context, Result, bail, ensure};
#[cfg(feature = "embedded-method")]
use borsh::BorshDeserialize;
pub use crate::recursive_oracle::{
    RECURSIVE_ORACLE_MAX_BYTES, RecursiveFamily, RecursiveInputs, RecursiveOperation,
    RecursiveOracle, RecursiveStep, decode_recursive_oracle, encode_recursive_oracle,
};
use eip_0045_methods::{GuestInputHeader, GuestMode};
#[cfg(feature = "b4-negative-ancestry-finalization")]
use eip_0045_reproduction::b4_negative_ancestry_authority::{
    B4NegativeAncestrySourceAuthorityV1, B4NegativeAncestrySourceAuthorityV2,
    B4NegativeAncestryWitnessCatalogAuthorityV1, B4NegativeAncestryWitnessCatalogAuthorityV2,
};
use eip_0045_reproduction::b4_negative_ancestry_source::{
    B4AuthenticatedNegativeAncestryProducerSourceV1,
    B4AuthenticatedNegativeAncestryProducerSourceV2,
};
use risc0_zkvm::{
    ALLOWED_CONTROL_ROOT, Assumption, AssumptionReceipt, Assumptions, Digest, Executor,
    ExecutorEnv, ExitCode, InnerAssumptionReceipt, InnerReceipt, LocalProver, MaybePruned, Prover,
    ProverOpts, Receipt, ReceiptClaim, SegmentReceipt, SuccinctReceipt, VerifierContext,
    compute_image_id, get_prover_server, sha::Digestible,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::b4_negative_ancestry_witness_set::{
    B4AlternateProgramLiftEvidenceV1, B4AlternateStatementAssumptionLiftEvidenceV1,
    B4AlternateStatementFinalJoinEvidenceV1, B4AlternateStatementFinalResolveEvidenceV1,
    B4Case9AssumptionLiftEvidenceV1, B4Case9FinalResolveEvidenceV1,
    B4DuplicateAssumptionLiftEvidenceV1, B4ProducedNegativeAncestryWitnessSetV1,
};
use crate::recursive_calibration::{
    RECURSIVE_CALIBRATION_SEGMENT_LIMIT_PO2, RecursiveCalibrationReport,
    derive_recursive_calibration, verify_recursive_calibration_with_recipe, RecursiveCalibrationRecipe,
};
use crate::{
    CandidateTerminal, SegmentObservation, WORKLOAD_SEED,
    derive_b4_alternate_chain_domain_statement, derive_b4_alternate_program_statement,
    normal_lift_segment_po2, select_canonical_iterations, validate_candidate_terminal_shape,
    validate_ergo_statement_v1,
};

const PLAIN_PO2_18_TARGET_PO2: u32 = 18;


/// Execute-only evidence that the explicit-root guest accepts only the exact
/// pinned assumption-cache root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplicitRootCacheGateObservation {
    /// Image ID whose same-program claim was requested by the guest.
    pub image_id: Digest,
    /// Exact same-program OK claim requested by the explicit-root guest.
    pub requested_claim: Digest,
    /// Exact non-zero root requested by the explicit-root guest mode.
    pub requested_root: Digest,
    /// Deterministic one-bit claim mutation rejected by the upstream matcher.
    pub mutated_claim: Digest,
    /// Deterministic one-bit mutation rejected by the upstream matcher.
    pub mutated_root: Digest,
    /// Segment exponents emitted by the accepted control execution.
    pub accepted_segment_po2: Vec<u32>,
}

/// Fully checked internal result for the row-154 duplicate-assumption Lift.
struct DuplicateAssumptionLiftWitness {
    // The local embedded checkpoint must retain the original construction,
    // not merely the final Lift. Campaign byte artifacts remain unchanged.
    #[cfg(feature = "embedded-method")]
    source_receipt: Receipt,
    #[cfg(feature = "embedded-method")]
    lifted_receipt: SuccinctReceipt<ReceiptClaim>,
    raw_seal: Vec<u8>,
    receipt_oracle: Vec<u8>,
}

/// Opaque exact case-9 assumption receipt accepted by the row-154 producer.
///
/// The private constructor boundary prevents callers from substituting a
/// freshly proved receipt with the same public claim. Production construction
/// is reserved for authentication of the exact case-9 recursive-oracle bytes.
struct AuthenticatedCase9AssumptionReceipt {
    receipt: Receipt,
}

struct AuthenticatedCase9WitnessBundle {
    assumption_receipt: AuthenticatedCase9AssumptionReceipt,
    assumption_lift: B4Case9AssumptionLiftEvidenceV1,
    final_resolve: B4Case9FinalResolveEvidenceV1,
}

struct ProvedPlainLift15 {
    receipt: Receipt,
    raw_seal: Vec<u8>,
    receipt_oracle: Vec<u8>,
}

/// Local replay admission only; never a campaign producer-source token.
#[cfg(feature = "embedded-method")]
pub(crate) struct LocalSharedAssumptionInput {
    elf: &'static [u8],
    image_id: Digest,
    statement: Vec<u8>,
}

#[cfg(feature = "embedded-method")]
impl LocalSharedAssumptionInput {
    pub(crate) fn statement(&self) -> &[u8] { &self.statement }

    pub(crate) fn prove(&self, prover: &LocalProver) -> Result<Receipt> {
        prove_same_program_lift_15_assumption(prover, self.elf, self.image_id, &self.statement)
    }

    pub(crate) fn replay(&self, oracle: &[u8], raw_seal: &[u8]) -> Result<Receipt> {
        let succinct = crate::receipt_oracle_wire::decode_succinct_receipt_oracle::<ReceiptClaim>(oracle)?;
        ensure!(succinct.get_seal_bytes() == raw_seal, "local shared assumption raw seal mismatch");
        let receipt = Receipt::new(InnerReceipt::Succinct(succinct), self.statement.clone());
        validate_supplied_lift_15_assumption(&receipt, self.image_id, &self.statement,
            &VerifierContext::default().with_dev_mode(false))?;
        Ok(receipt)
    }

    pub(crate) fn checkpoint_parts(&self, original: &Receipt) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        validate_supplied_lift_15_assumption(original, self.image_id, &self.statement,
            &VerifierContext::default().with_dev_mode(false))?;
        let InnerReceipt::Succinct(inner) = &original.inner else {
            bail!("local shared assumption is not succinct");
        };
        let oracle = encode_direct_receipt_oracle(inner)?;
        let raw = inner.get_seal_bytes();
        let reconstructed = self.replay(&oracle, &raw)?;
        let bytes = require_local_receipt_byte_identity(original, &reconstructed)?;
        Ok((oracle, raw, bytes))
    }
}

/// Local-only locked alternate-program admission; not a campaign source token.
#[cfg(feature = "embedded-method")]
pub(crate) struct LocalAlternateProgramInput {
    elf: &'static [u8],
    image_id: Digest,
    statement: Vec<u8>,
}

#[cfg(feature = "embedded-method")]
impl LocalAlternateProgramInput {
    fn require_locked_context(&self, locked: &crate::locked_negative_ancestry_guest::LockedGuestPairV1,
                              canonical: &[u8]) -> Result<()> {
        let (consumer_elf, consumer_id) = locked.consumer();
        let (alternate_elf, alternate_id) = locked.alternate();
        validate_method_identity(consumer_elf, consumer_id)?;
        validate_method_identity(alternate_elf, alternate_id)?;
        ensure!(self.elf == alternate_elf && self.image_id == alternate_id && alternate_id != consumer_id,
            "local alternate producer differs from locked alternate guest");
        ensure!(self.statement == derive_b4_alternate_program_statement(canonical, &consumer_id, &alternate_id)?,
            "local alternate statement differs from program-ID-only derivation");
        Ok(())
    }

    pub(crate) fn statement(&self) -> &[u8] { &self.statement }

    pub(crate) fn prove(&self, prover: &LocalProver) -> Result<Receipt> {
        prove_same_program_lift_15_assumption(prover, self.elf, self.image_id, &self.statement)
    }

    pub(crate) fn replay(&self, oracle: &[u8], raw_seal: &[u8]) -> Result<Receipt> {
        let inner = crate::receipt_oracle_wire::decode_succinct_receipt_oracle::<ReceiptClaim>(oracle)?;
        ensure!(inner.get_seal_bytes() == raw_seal, "local alternate raw seal mismatch");
        let receipt = Receipt::new(InnerReceipt::Succinct(inner), self.statement.clone());
        validate_supplied_lift_15_assumption(&receipt, self.image_id, &self.statement,
            &VerifierContext::default().with_dev_mode(false))?;
        Ok(receipt)
    }

    pub(crate) fn checkpoint_parts(&self, original: &Receipt) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        validate_supplied_lift_15_assumption(original, self.image_id, &self.statement,
            &VerifierContext::default().with_dev_mode(false))?;
        let InnerReceipt::Succinct(inner) = &original.inner else {
            bail!("local alternate receipt is not succinct");
        };
        let oracle = encode_direct_receipt_oracle(inner)?;
        let raw = inner.get_seal_bytes();
        let reconstructed = self.replay(&oracle, &raw)?;
        let outer = require_local_receipt_byte_identity(original, &reconstructed)?;
        Ok((oracle, raw, outer))
    }
}

/// Admit the exact retained Case9 closure, then derive only the alternate program field.
#[cfg(feature = "embedded-method")]
pub(crate) fn admit_local_alternate_program(
    locked: &crate::locked_negative_ancestry_guest::LockedGuestPairV1,
    canonical_statement: &[u8], case9_oracle: &[u8], assumption_raw: &[u8], final_raw: &[u8],
) -> Result<LocalAlternateProgramInput> {
    let (_, consumer_id) = locked.consumer();
    validate_ergo_statement_v1(canonical_statement, &consumer_id)?;
    let oracle = authenticate_case9_recursive_oracle_parts(case9_oracle, canonical_statement, consumer_id)?;
    authenticate_case9_assumption_receipt_from_oracle(&oracle, assumption_raw, canonical_statement, consumer_id)?;
    let final_receipt = step_receipt(&oracle.steps, oracle.final_step)?;
    let expected = ReceiptClaim::ok(consumer_id, canonical_statement.to_vec()).digest();
    ensure!(validate_candidate_terminal_shape(final_receipt, CandidateTerminal::Resolve, &expected)? == final_raw,
        "local alternate Case9 final Resolve raw seal mismatch");
    let (elf, image_id) = locked.alternate();
    let admitted = LocalAlternateProgramInput { elf, image_id,
        statement: derive_b4_alternate_program_statement(canonical_statement, &consumer_id, &image_id)? };
    admitted.require_locked_context(locked, canonical_statement)?;
    Ok(admitted)
}

/// Exact original Case9 admission for the fixed local duplicate construction.
#[cfg(feature = "embedded-method")]
pub(crate) struct LocalDuplicateAssumptionInput {
    elf: &'static [u8],
    image_id: Digest,
    statement: Vec<u8>,
    assumption: AuthenticatedCase9AssumptionReceipt,
}

#[cfg(feature = "embedded-method")]
pub(crate) fn admit_local_duplicate_assumption(
    locked: &crate::locked_negative_ancestry_guest::LockedGuestPairV1,
    canonical_statement: &[u8], case9_oracle: &[u8], assumption_raw: &[u8], final_raw: &[u8],
) -> Result<LocalDuplicateAssumptionInput> {
    let (elf, image_id) = locked.consumer();
    let (alternate_elf, alternate_id) = locked.alternate();
    validate_method_identity(elf, image_id)?;
    validate_method_identity(alternate_elf, alternate_id)?;
    ensure!(image_id != alternate_id, "local duplicate locked guests are not distinct");
    validate_ergo_statement_v1(canonical_statement, &image_id)?;
    let oracle = authenticate_case9_recursive_oracle_parts(case9_oracle, canonical_statement, image_id)?;
    let assumption = authenticate_case9_assumption_receipt_from_oracle(
        &oracle, assumption_raw, canonical_statement, image_id)?;
    let final_receipt = step_receipt(&oracle.steps, oracle.final_step)?;
    let expected = ReceiptClaim::ok(image_id, canonical_statement.to_vec()).digest();
    ensure!(validate_candidate_terminal_shape(final_receipt, CandidateTerminal::Resolve, &expected)? == final_raw,
        "local duplicate Case9 final Resolve raw seal mismatch");
    Ok(LocalDuplicateAssumptionInput { elf, image_id, statement: canonical_statement.to_vec(), assumption })
}

#[cfg(feature = "embedded-method")]
fn require_duplicate_cached_receipts(actual: &[InnerAssumptionReceipt], expected: &InnerAssumptionReceipt) -> Result<()> {
    ensure!(actual.len() == 2, "local duplicate attachment count must be exactly two");
    let bytes = borsh::to_vec(expected)?;
    for (index, receipt) in actual.iter().enumerate() {
        ensure!(borsh::to_vec(receipt)? == bytes,
            "local duplicate attachment {index} differs from original Case9 receipt");
    }
    Ok(())
}

#[cfg(feature = "embedded-method")]
impl LocalDuplicateAssumptionInput {
    pub(crate) fn statement(&self) -> &[u8] { &self.statement }

    pub(crate) fn prove(&self, prover: &LocalProver) -> Result<(Receipt, Receipt)> {
        let witness = prove_duplicate_assumption_lift_witness(prover, self.elf, self.image_id,
            &self.statement, &self.assumption)?;
        let lifted = Receipt::new(InnerReceipt::Succinct(witness.lifted_receipt), self.statement.clone());
        Ok((witness.source_receipt, lifted))
    }

    fn validate_receipts(&self, source_receipt: &Receipt, lifted_receipt: &Receipt) -> Result<Vec<u8>> {
        ensure!(source_receipt.journal.bytes == self.statement && lifted_receipt.journal.bytes == self.statement,
            "local duplicate receipt journal mismatch");
        // Explicit full outer identity prevents reconstruction from silently
        // discarding metadata, even for a same-claim replacement.
        require_local_receipt_byte_identity(source_receipt,
            &Receipt::new(source_receipt.inner.clone(), self.statement.clone()))?;
        require_local_receipt_byte_identity(lifted_receipt,
            &Receipt::new(lifted_receipt.inner.clone(), self.statement.clone()))?;
        let InnerReceipt::Composite(source) = &source_receipt.inner else {
            bail!("local duplicate original source is not composite");
        };
        ensure!(source.segments.len() == 1 && source.segments[0].index == 0,
            "local duplicate source must contain only segment zero");
        let cached: AssumptionReceipt = self.assumption.receipt.clone().into();
        let AssumptionReceipt::Proven(expected) = cached else {
            bail!("local duplicate original assumption is not proven");
        };
        require_duplicate_cached_receipts(&source.assumption_receipts, &expected)?;
        let mode = GuestMode::VerifyAssumptionExplicitRootTwice;
        let source_output = source.segments[0].claim.output.as_value()
            .context("local duplicate source output is pruned")?.as_ref()
            .context("local duplicate source output is absent")?;
        validate_assumption_inventory(&source_output.assumptions, self.image_id, &self.statement, mode)?;
        let InnerReceipt::Succinct(lifted) = &lifted_receipt.inner else {
            bail!("local duplicate final receipt is not succinct");
        };
        let lifted_output = lifted.claim.as_value().context("local duplicate Lift claim is pruned")?
            .output.as_value().context("local duplicate Lift output is pruned")?.as_ref()
            .context("local duplicate Lift output is absent")?;
        validate_assumption_inventory(&lifted_output.assumptions, self.image_id, &self.statement, mode)?;
        let conditional_claim = source.segments[0].claim.digest();
        ensure!(lifted.claim.digest() == conditional_claim,
            "local duplicate Lift does not match original source conditional claim");
        let raw = validate_candidate_terminal_shape(lifted, CandidateTerminal::Lift(16), &conditional_claim)
            .context("local duplicate Lift16 terminal shape")?;
        let ctx = VerifierContext::default().with_dev_mode(false);
        source_receipt.verify_with_context(&ctx, self.image_id)
            .context("local duplicate original composite replay failed")?;
        ensure!(source_receipt.claim()?.digest() == ReceiptClaim::ok(self.image_id, self.statement.clone()).digest(),
            "local duplicate resolved source claim mismatch");
        lifted.verify_integrity_with_context(&ctx).context("local duplicate Lift16 replay failed")?;
        Ok(raw)
    }

    pub(crate) fn replay(&self, source_bytes: &[u8], oracle: &[u8], raw: &[u8]) -> Result<(Receipt, Receipt)> {
        ensure!(!source_bytes.is_empty() && source_bytes.len() <= RECURSIVE_ORACLE_MAX_BYTES,
            "local duplicate source Receipt byte bound");
        let source = Receipt::try_from_slice(source_bytes).context("local duplicate source Receipt Borsh")?;
        ensure!(borsh::to_vec(&source)? == source_bytes, "local duplicate source Receipt encoding changed");
        let inner = crate::receipt_oracle_wire::decode_succinct_receipt_oracle::<ReceiptClaim>(oracle)?;
        ensure!(inner.get_seal_bytes() == raw, "local duplicate raw seal mismatch");
        let lifted = Receipt::new(InnerReceipt::Succinct(inner), self.statement.clone());
        ensure!(self.validate_receipts(&source, &lifted)? == raw, "local duplicate validated seal mismatch");
        Ok((source, lifted))
    }

    pub(crate) fn checkpoint_parts(&self, source: &Receipt, lifted: &Receipt) -> Result<([Vec<u8>; 4], Vec<u8>)> {
        let raw = self.validate_receipts(source, lifted)?;
        let InnerReceipt::Succinct(inner) = &lifted.inner else { bail!("local duplicate final receipt is not succinct"); };
        let source_bytes = borsh::to_vec(source)?;
        let oracle = encode_direct_receipt_oracle(inner)?;
        let (reopened_source, reopened_lifted) = self.replay(&source_bytes, &oracle, &raw)?;
        require_local_receipt_byte_identity(source, &reopened_source)?;
        let outer = require_local_receipt_byte_identity(lifted, &reopened_lifted)?;
        Ok(([source_bytes, oracle, raw, self.statement.clone()], outer))
    }
}

#[cfg(feature = "embedded-method")]
fn require_local_receipt_byte_identity(original: &Receipt, reconstructed: &Receipt) -> Result<Vec<u8>> {
    let expected = borsh::to_vec(original)?;
    ensure!(expected == borsh::to_vec(reconstructed)?, "local shared assumption full Receipt bytes changed");
    Ok(expected)
}

#[cfg(feature = "embedded-method")]
pub(crate) fn admit_local_shared_assumption(
    locked: &crate::locked_negative_ancestry_guest::LockedGuestPairV1,
    canonical_statement: &[u8], case9_oracle: &[u8], assumption_raw: &[u8], final_raw: &[u8],
) -> Result<LocalSharedAssumptionInput> {
    let (elf, image_id) = locked.consumer();
    validate_ergo_statement_v1(canonical_statement, &image_id)?;
    let oracle = authenticate_case9_recursive_oracle_parts(case9_oracle, canonical_statement, image_id)?;
    authenticate_case9_assumption_receipt_from_oracle(&oracle, assumption_raw, canonical_statement, image_id)?;
    let final_receipt = step_receipt(&oracle.steps, oracle.final_step)?;
    let expected = ReceiptClaim::ok(image_id, canonical_statement.to_vec()).digest();
    let raw = validate_candidate_terminal_shape(final_receipt, CandidateTerminal::Resolve, &expected)?;
    ensure!(raw == final_raw, "local Case9 final Resolve raw seal mismatch");
    Ok(LocalSharedAssumptionInput { elf, image_id,
        statement: derive_b4_alternate_chain_domain_statement(canonical_statement, &image_id)? })
}

#[cfg(all(test, feature = "embedded-method"))]
impl DuplicateAssumptionLiftWitness {
    /// Transient authenticated composite proving the one-cache/two-attachment
    /// construction.
    #[must_use]
    const fn source_receipt(&self) -> &Receipt {
        &self.source_receipt
    }

    /// Stock Lift-16 receipt whose claim contains exactly two revealed heads.
    #[must_use]
    const fn lifted_receipt(&self) -> &SuccinctReceipt<ReceiptClaim> {
        &self.lifted_receipt
    }

    /// Exact little-endian succinct seal consumed by the B4 verifier.
    #[must_use]
    fn raw_seal(&self) -> &[u8] {
        &self.raw_seal
    }

    /// Exact direct `SuccinctReceipt<ReceiptClaim>` bincode oracle.
    #[must_use]
    fn receipt_oracle(&self) -> &[u8] {
        &self.receipt_oracle
    }
}

impl RecursiveFamily {
    /// Stable command-line spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TerminalJoin => "terminal-join",
            Self::TerminalResolve => "terminal-resolve",
            Self::ResolveThenJoin => "resolve-then-join",
        }
    }

    /// Whether the guest must make exactly one receipt assumption.
    #[must_use]
    pub const fn uses_assumption(self) -> bool {
        self.guest_mode().verifies_assumption()
    }

    /// Exact private guest mode used to construct this family.
    #[must_use]
    pub const fn guest_mode(self) -> GuestMode {
        match self {
            Self::TerminalJoin => GuestMode::Plain,
            Self::TerminalResolve => GuestMode::VerifyAssumptionExplicitRoot,
            Self::ResolveThenJoin => GuestMode::VerifyAssumptionZeroRoot,
        }
    }

    /// Stable label for the assumption-root semantics exercised by this family.
    #[must_use]
    pub const fn assumption_root_semantics(self) -> &'static str {
        match self {
            Self::TerminalJoin => "none",
            Self::TerminalResolve => "explicit-allowed-control-root",
            Self::ResolveThenJoin => "zero-root-self-composition",
        }
    }

    /// Exact required outer terminal.
    #[must_use]
    pub const fn terminal(self) -> CandidateTerminal {
        match self {
            Self::TerminalResolve => CandidateTerminal::Resolve,
            Self::TerminalJoin | Self::ResolveThenJoin => CandidateTerminal::Join,
        }
    }
}

impl fmt::Display for RecursiveFamily {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for RecursiveFamily {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "terminal-join" => Ok(Self::TerminalJoin),
            "terminal-resolve" => Ok(Self::TerminalResolve),
            "resolve-then-join" => Ok(Self::ResolveThenJoin),
            _ => bail!(
                "unknown recursive family {value:?}; expected terminal-join, terminal-resolve, or resolve-then-join"
            ),
        }
    }
}


/// Deterministic graph node used before any proving is attempted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedStep {
    /// Stock recursion operation.
    pub operation: RecursiveOperation,
    /// Exact source references.
    pub inputs: RecursiveInputs,
}

/// Return the one canonical operation graph for `family` and `segment_count`.
///
/// # Errors
///
/// Returns an error unless join families have exactly two segments and the
/// terminal-resolve family has exactly one. These are the smallest genuine
/// witnesses for the three B4 paths and keep the candidate graph closed.
pub fn planned_steps(family: RecursiveFamily, segment_count: usize) -> Result<Vec<PlannedStep>> {
    match family {
        RecursiveFamily::TerminalResolve => ensure!(
            segment_count == 1,
            "terminal-resolve requires exactly one source segment"
        ),
        RecursiveFamily::TerminalJoin | RecursiveFamily::ResolveThenJoin => ensure!(
            segment_count == 2,
            "{} requires exactly two source segments",
            family.as_str()
        ),
    }
    let segment_count_u32 =
        u32::try_from(segment_count).context("source segment count does not fit u32")?;

    let mut plan = Vec::new();
    for segment_index in 0..segment_count {
        let segment_index =
            u32::try_from(segment_index).context("source segment index does not fit u32")?;
        plan.push(PlannedStep {
            operation: RecursiveOperation::Lift,
            inputs: RecursiveInputs::Lift { segment_index },
        });
    }

    match family {
        RecursiveFamily::TerminalJoin => {
            let mut left_step = 0_u32;
            for right_step in 1..segment_count_u32 {
                let ordinal =
                    u32::try_from(plan.len()).context("join step ordinal does not fit u32")?;
                plan.push(PlannedStep {
                    operation: RecursiveOperation::Join,
                    inputs: RecursiveInputs::Join {
                        left_step,
                        right_step,
                    },
                });
                left_step = ordinal;
            }
        }
        RecursiveFamily::TerminalResolve => {
            plan.push(PlannedStep {
                operation: RecursiveOperation::Resolve,
                inputs: RecursiveInputs::Resolve {
                    conditional_step: 0,
                },
            });
        }
        RecursiveFamily::ResolveThenJoin => {
            let final_lift = 1_u32;
            let resolved_step =
                u32::try_from(plan.len()).context("resolve step ordinal does not fit u32")?;
            plan.push(PlannedStep {
                operation: RecursiveOperation::Resolve,
                inputs: RecursiveInputs::Resolve {
                    conditional_step: final_lift,
                },
            });
            plan.push(PlannedStep {
                operation: RecursiveOperation::Join,
                inputs: RecursiveInputs::Join {
                    left_step: 0,
                    right_step: resolved_step,
                },
            });
        }
    }
    Ok(plan)
}


fn authenticate_case9_recursive_oracle_parts(
    recursive_oracle_borsh: &[u8],
    statement: &[u8],
    image_id: Digest,
) -> Result<RecursiveOracle> {
    let oracle = authenticate_recursive_oracle_bytes(
        recursive_oracle_borsh,
        image_id,
        statement,
        RecursiveFamily::TerminalResolve,
    )
    .context("authenticated case-9 recursive oracle is invalid")?;
    ensure!(
        oracle.format_version == 2
            && oracle.final_step == 1
            && oracle.steps.len() == 2
            && oracle.steps[0].ordinal == 0
            && oracle.steps[0].operation == RecursiveOperation::Lift
            && oracle.steps[0].inputs == (RecursiveInputs::Lift { segment_index: 0 })
            && oracle.steps[1].ordinal == 1
            && oracle.steps[1].operation == RecursiveOperation::Resolve
            && oracle.steps[1].inputs
                == (RecursiveInputs::Resolve {
                    conditional_step: 0,
                }),
        "authenticated case-9 recursive oracle is not the exact terminal-resolve graph"
    );
    Ok(oracle)
}

/// Authenticate one exact recursive-oracle byte source for a caller-selected family.
///
/// # Errors
///
/// Returns an error if the source is not bounded exact Borsh, changes across
/// re-encoding, names another family, or fails complete disabled-dev replay.
pub(crate) fn authenticate_recursive_oracle_bytes(
    source: &[u8],
    image_id: Digest,
    statement: &[u8],
    expected_family: RecursiveFamily,
) -> Result<RecursiveOracle> {
    let oracle = decode_recursive_oracle(source)
        .context("recursive oracle source is not bounded exact Borsh")?;
    ensure!(
        encode_recursive_oracle(&oracle)? == source,
        "recursive oracle changed across its typed Borsh round trip"
    );
    ensure!(
        oracle.family == expected_family,
        "recursive oracle family is {}, expected {}",
        oracle.family,
        expected_family
    );
    validate_recursive_oracle(&oracle, image_id, statement)
        .context("recursive oracle failed complete replay")?;
    Ok(oracle)
}

fn authenticate_case9_assumption_receipt_from_oracle(
    oracle: &RecursiveOracle,
    assumption_raw_seal: &[u8],
    statement: &[u8],
    image_id: Digest,
) -> Result<AuthenticatedCase9AssumptionReceipt> {
    let receipt = oracle
        .assumption_receipt
        .as_ref()
        .context("authenticated case-9 recursive oracle has no assumption receipt")?;
    let InnerReceipt::Succinct(inner) = &receipt.inner else {
        bail!("authenticated case-9 assumption receipt is not succinct");
    };
    ensure!(
        normal_lift_segment_po2(&inner.control_id)? == 15,
        "authenticated case-9 assumption receipt is not Lift-15"
    );
    ensure!(
        inner.get_seal_bytes() == assumption_raw_seal,
        "case-9 assumption receipt seal differs from the authenticated auxiliary artifact"
    );
    let ctx = VerifierContext::default().with_dev_mode(false);
    validate_top_level_receipt(
        receipt,
        image_id,
        statement,
        CandidateTerminal::Lift(15),
        &ctx,
    )
    .context("authenticated case-9 assumption receipt failed exact replay")?;
    Ok(AuthenticatedCase9AssumptionReceipt {
        receipt: receipt.clone(),
    })
}

#[cfg(test)]
fn authenticate_case9_assumption_receipt_parts(
    recursive_oracle_borsh: &[u8],
    assumption_raw_seal: &[u8],
    statement: &[u8],
    image_id: Digest,
) -> Result<AuthenticatedCase9AssumptionReceipt> {
    let oracle =
        authenticate_case9_recursive_oracle_parts(recursive_oracle_borsh, statement, image_id)?;
    authenticate_case9_assumption_receipt_from_oracle(
        &oracle,
        assumption_raw_seal,
        statement,
        image_id,
    )
}

/// Private byte view constructed through version-specific authenticated tokens.
///
/// This is cryptographic implementation detail, not an authority adapter: it
/// cannot be constructed outside this module and carries no authority token,
/// selector, proof parameter, conversion, or publication input.
struct AuthenticatedNegativeAncestryProducerView<'source> {
    case9_recursive_oracle_borsh: &'source [u8],
    case9_assumption_raw_seal: &'source [u8],
    case9_final_raw_seal: &'source [u8],
    canonical_statement: &'source [u8],
    consumer_guest_elf: &'source [u8],
    consumer_program_id: [u8; 32],
    alternate_guest_elf: &'source [u8],
    alternate_program_id: [u8; 32],
}

impl<'source> AuthenticatedNegativeAncestryProducerView<'source> {
    fn from_v1(source: &'source B4AuthenticatedNegativeAncestryProducerSourceV1<'_>) -> Self {
        Self {
            case9_recursive_oracle_borsh: source.case9_recursive_oracle_borsh(),
            case9_assumption_raw_seal: source.case9_assumption_raw_seal(),
            case9_final_raw_seal: source.case9_final_raw_seal(),
            canonical_statement: source.canonical_statement(),
            consumer_guest_elf: source.consumer_guest_elf(),
            consumer_program_id: source.consumer_program_id(),
            alternate_guest_elf: source.alternate_guest_elf(),
            alternate_program_id: source.alternate_program_id(),
        }
    }

    fn from_v2(source: &'source B4AuthenticatedNegativeAncestryProducerSourceV2<'_>) -> Self {
        Self {
            case9_recursive_oracle_borsh: source.case9_recursive_oracle_borsh(),
            case9_assumption_raw_seal: source.case9_assumption_raw_seal(),
            case9_final_raw_seal: source.case9_final_raw_seal(),
            canonical_statement: source.canonical_statement(),
            consumer_guest_elf: source.consumer_guest_elf(),
            consumer_program_id: source.consumer_program_id(),
            alternate_guest_elf: source.alternate_guest_elf(),
            alternate_program_id: source.alternate_program_id(),
        }
    }

    const fn case9_recursive_oracle_borsh(&self) -> &[u8] {
        self.case9_recursive_oracle_borsh
    }

    const fn case9_assumption_raw_seal(&self) -> &[u8] {
        self.case9_assumption_raw_seal
    }

    const fn case9_final_raw_seal(&self) -> &[u8] {
        self.case9_final_raw_seal
    }

    const fn canonical_statement(&self) -> &[u8] {
        self.canonical_statement
    }

    const fn consumer_guest_elf(&self) -> &[u8] {
        self.consumer_guest_elf
    }

    const fn consumer_program_id(&self) -> [u8; 32] {
        self.consumer_program_id
    }

    const fn alternate_guest_elf(&self) -> &[u8] {
        self.alternate_guest_elf
    }

    const fn alternate_program_id(&self) -> [u8; 32] {
        self.alternate_program_id
    }
}

fn authenticate_negative_ancestry_source_identities(
    source: &AuthenticatedNegativeAncestryProducerView<'_>,
) -> Result<(Digest, Digest)> {
    let consumer_image_id = compute_image_id(source.consumer_guest_elf())
        .context("cannot compute authenticated consumer guest image ID")?;
    ensure!(
        digest_bytes(consumer_image_id) == source.consumer_program_id(),
        "authenticated consumer guest ELF differs from its source-authority program ID"
    );
    let alternate_image_id = compute_image_id(source.alternate_guest_elf())
        .context("cannot compute authenticated alternate guest image ID")?;
    ensure!(
        digest_bytes(alternate_image_id) == source.alternate_program_id(),
        "authenticated alternate guest ELF differs from its source-authority program ID"
    );
    ensure!(
        consumer_image_id != alternate_image_id,
        "authenticated alternate guest image ID equals the consumer image ID"
    );
    validate_ergo_statement_v1(source.canonical_statement(), &consumer_image_id)
        .context("authenticated canonical producer statement is invalid")?;
    Ok((consumer_image_id, alternate_image_id))
}

fn authenticate_case9_witness_bundle(
    source: &AuthenticatedNegativeAncestryProducerView<'_>,
    consumer_image_id: Digest,
) -> Result<AuthenticatedCase9WitnessBundle> {
    let oracle = authenticate_case9_recursive_oracle_parts(
        source.case9_recursive_oracle_borsh(),
        source.canonical_statement(),
        consumer_image_id,
    )?;
    let assumption_receipt = authenticate_case9_assumption_receipt_from_oracle(
        &oracle,
        source.case9_assumption_raw_seal(),
        source.canonical_statement(),
        consumer_image_id,
    )?;
    let InnerReceipt::Succinct(assumption_succinct) = &assumption_receipt.receipt.inner else {
        bail!("authenticated case-9 assumption receipt is not succinct");
    };
    let assumption_raw_seal = assumption_succinct.get_seal_bytes();
    ensure!(
        assumption_raw_seal == source.case9_assumption_raw_seal(),
        "case-9 assumption receipt seal differs from its authenticated source artifact"
    );
    let assumption_oracle = encode_direct_receipt_oracle(assumption_succinct)
        .context("cannot encode the authenticated case-9 assumption receipt")?;
    let assumption_lift = B4Case9AssumptionLiftEvidenceV1::from_verified_parts(
        assumption_raw_seal,
        assumption_oracle,
    )?;

    let final_receipt = step_receipt(&oracle.steps, oracle.final_step)
        .context("authenticated case-9 oracle has no final receipt")?;
    let expected_claim =
        ReceiptClaim::ok(consumer_image_id, source.canonical_statement().to_vec()).digest();
    let final_raw_seal = validate_candidate_terminal_shape(
        final_receipt,
        CandidateTerminal::Resolve,
        &expected_claim,
    )
    .context("authenticated case-9 final receipt is not the exact stock Resolve")?;
    ensure!(
        final_raw_seal == source.case9_final_raw_seal(),
        "case-9 final Resolve seal differs from its authenticated source artifact"
    );
    let final_oracle = encode_direct_receipt_oracle(final_receipt)
        .context("cannot encode the authenticated case-9 final Resolve receipt")?;
    let final_resolve =
        B4Case9FinalResolveEvidenceV1::from_verified_parts(final_raw_seal, final_oracle)?;

    Ok(AuthenticatedCase9WitnessBundle {
        assumption_receipt,
        assumption_lift,
        final_resolve,
    })
}

/// Execute only, returning the exact segment exponents and assumption count.
///
/// This is the cheap shape preflight used before base or recursion proving.
///
/// # Errors
///
/// Returns an error for a malformed statement, guest failure, unsupported
/// segment exponent, or a mode/assumption mismatch.
pub fn inspect_recursive_shape(
    prover: &LocalProver,
    elf: &[u8],
    image_id: Digest,
    statement: &[u8],
    family: RecursiveFamily,
    segment_limit_po2: u32,
    workload_iterations: u32,
) -> Result<Vec<u32>> {
    let po2 = execute_recursive_shape(
        prover,
        elf,
        image_id,
        statement,
        family,
        segment_limit_po2,
        workload_iterations,
    )?;
    validate_profile_segment_sequence(&po2)?;
    validate_family_shape(family, &po2)?;
    Ok(po2)
}

/// Execute once for deterministic family calibration without requiring the
/// final family cardinality yet.
///
/// This returns the raw source-segment exponents so the calibration layer can
/// rank an undersized final segment below the first profile-valid sequence.
/// That layer rejects empty executions, overlarge or undersized non-final
/// segments, jumps beyond the family's exact count, and nondeterministic
/// replay. The strict [`inspect_recursive_shape`] gate is still repeated before
/// proving.
///
/// # Errors
///
/// Returns an error for a malformed statement, guest failure, or
/// mode/assumption mismatch.
pub fn observe_recursive_calibration_shape(
    prover: &LocalProver,
    elf: &[u8],
    image_id: Digest,
    statement: &[u8],
    family: RecursiveFamily,
    segment_limit_po2: u32,
    workload_iterations: u32,
) -> Result<Vec<u32>> {
    execute_recursive_shape(
        prover,
        elf,
        image_id,
        statement,
        family,
        segment_limit_po2,
        workload_iterations,
    )
}

fn execute_recursive_shape(
    prover: &LocalProver,
    elf: &[u8],
    image_id: Digest,
    statement: &[u8],
    family: RecursiveFamily,
    segment_limit_po2: u32,
    workload_iterations: u32,
) -> Result<Vec<u32>> {
    validate_method_identity(elf, image_id)?;
    validate_ergo_statement_v1(statement, &image_id)?;
    let mode = family.guest_mode();
    let assumption = unresolved_assumption_for_mode(image_id, statement, mode)?;
    let session = prover
        .execute(
            build_recursive_source_env(
                statement,
                image_id,
                family,
                segment_limit_po2,
                workload_iterations,
                assumption,
            )?,
            elf,
        )
        .context("recursive candidate shape execution failed")?;
    validate_session_semantics(&session, image_id, statement, mode)?;
    Ok(session
        .segments
        .iter()
        .map(|segment| segment.po2)
        .collect::<Vec<_>>())
}

/// Execute the explicit-root guest against one correct and three independently
/// malformed assumption caches without generating a STARK proof.
///
/// The positive execution is validated as an exact same-program statement
/// claim. The zero-root, one-bit-mutated-root, and one-bit-mutated-claim
/// executions must fail in the pinned upstream assumption matcher with the
/// exact requested claim and root in its stable missing-receipt diagnostic.
///
/// # Errors
///
/// Returns an error if the ELF differs from the image ID, the statement is
/// malformed, the pinned explicit root drifts from the profile, the correct
/// cache is rejected, a malformed cache is accepted, or a rejection does not
/// originate from the exact requested tuple in the assumption matcher.
pub fn inspect_explicit_root_cache_gate(
    prover: &LocalProver,
    elf: &[u8],
    image_id: Digest,
    statement: &[u8],
    segment_limit_po2: u32,
    workload_iterations: u32,
) -> Result<ExplicitRootCacheGateObservation> {
    validate_method_identity(elf, image_id)?;
    validate_ergo_statement_v1(statement, &image_id)?;
    let mode = GuestMode::VerifyAssumptionExplicitRoot;
    let requested_root = expected_assumption_control_root(mode)?
        .context("explicit-root guest mode did not yield an assumption root")?;
    ensure!(
        requested_root != Digest::ZERO,
        "explicit-root guest mode unexpectedly selected the zero root"
    );
    let claim_digest = ReceiptClaim::ok(image_id, statement.to_vec()).digest();
    let execute_with_cache = |cached_claim: Digest, cached_root: Digest| -> Result<_> {
        prover.execute(
            build_env(
                statement,
                image_id,
                mode,
                segment_limit_po2,
                workload_iterations,
                Some(
                    Assumption {
                        claim: cached_claim,
                        control_root: cached_root,
                    }
                    .into(),
                ),
            )?,
            elf,
        )
    };

    let accepted = execute_with_cache(claim_digest, requested_root)
        .context("explicit-root control execution rejected the correct assumption cache")?;
    validate_session(&accepted, image_id, statement, mode)?;
    let accepted_segment_po2 = accepted
        .segments
        .iter()
        .map(|segment| segment.po2)
        .collect::<Vec<_>>();

    let zero_root_error = execute_with_cache(claim_digest, Digest::ZERO)
        .err()
        .context("explicit-root guest accepted a zero-root assumption cache")?;
    validate_missing_assumption_diagnostic(
        &zero_root_error,
        claim_digest,
        requested_root,
        "zero-root cache",
    )?;

    let mutated_root = flip_first_digest_bit(requested_root);
    ensure!(
        mutated_root != requested_root && mutated_root != Digest::ZERO,
        "explicit-root mutation did not produce a distinct non-zero root"
    );
    let mutated_root_error = execute_with_cache(claim_digest, mutated_root)
        .err()
        .context("explicit-root guest accepted a one-bit-mutated assumption root")?;
    validate_missing_assumption_diagnostic(
        &mutated_root_error,
        claim_digest,
        requested_root,
        "mutated-root cache",
    )?;

    let mutated_claim = flip_first_digest_bit(claim_digest);
    ensure!(
        mutated_claim != claim_digest,
        "claim mutation did not produce a distinct digest"
    );
    let mutated_claim_error = execute_with_cache(mutated_claim, requested_root)
        .err()
        .context("explicit-root guest accepted a one-bit-mutated assumption claim")?;
    validate_missing_assumption_diagnostic(
        &mutated_claim_error,
        claim_digest,
        requested_root,
        "mutated-claim cache",
    )?;

    Ok(ExplicitRootCacheGateObservation {
        image_id,
        requested_claim: claim_digest,
        requested_root,
        mutated_claim,
        mutated_root,
        accepted_segment_po2,
    })
}

fn validate_method_identity(elf: &[u8], image_id: Digest) -> Result<()> {
    let computed = compute_image_id(elf).context("cannot compute guest ELF image ID")?;
    ensure!(
        computed == image_id,
        "guest ELF differs from expected image ID"
    );
    Ok(())
}

fn flip_first_digest_bit(digest: Digest) -> Digest {
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(digest.as_bytes());
    bytes[0] ^= 1;
    Digest::from_bytes(bytes)
}

fn validate_missing_assumption_diagnostic(
    error: &anyhow::Error,
    requested_claim: Digest,
    requested_root: Digest,
    label: &str,
) -> Result<()> {
    const EXPECTED_REJECTION: &str = "no receipt found to resolve assumption";

    let diagnostic = format!("{error:#}");
    ensure!(
        diagnostic.contains(EXPECTED_REJECTION),
        "{label} rejection did not originate in the assumption matcher: {diagnostic}"
    );
    ensure!(
        diagnostic.contains(&requested_claim.to_string()),
        "{label} rejection does not name the exact requested claim: {diagnostic}"
    );
    ensure!(
        diagnostic.contains(&requested_root.to_string()),
        "{label} rejection does not name the exact requested root: {diagnostic}"
    );
    Ok(())
}

/// Encode one direct succinct receipt through the frozen evidence-only codec.
///
/// This is deliberately not the outer `Receipt` encoding used by ordinary
/// candidate exports. The negative-ancestry replay boundary decodes the direct
/// `SuccinctReceipt<ReceiptClaim>` type.
///
/// # Errors
///
/// Returns an error if the receipt exceeds the one-MiB cap, cannot be decoded
/// as the exact direct type, changes under re-encoding, or changes any
/// cryptographically relevant public field across the typed round trip.
fn encode_direct_receipt_oracle(receipt: &SuccinctReceipt<ReceiptClaim>) -> Result<Vec<u8>> {
    crate::receipt_oracle_wire::encode_succinct_receipt_oracle(receipt)
}

fn validate_supplied_assumption_family(family: RecursiveFamily) -> Result<()> {
    ensure!(
        family.uses_assumption(),
        "a supplied assumption receipt is inadmissible for {}",
        family.as_str()
    );
    Ok(())
}

fn prove_same_program_assumption_receipt(
    prover: &LocalProver,
    elf: &[u8],
    image_id: Digest,
    statement: &[u8],
    workload_iterations: u32,
    ctx: &VerifierContext,
    succinct_opts: &ProverOpts,
) -> Result<Receipt> {
    let assumption_session = prover
        .execute(
            build_env(
                statement,
                image_id,
                GuestMode::Plain,
                crate::EXECUTOR_SEGMENT_LIMIT_PO2,
                workload_iterations,
                None,
            )?,
            elf,
        )
        .context("assumption receipt preflight execution failed")?;
    validate_session(&assumption_session, image_id, statement, GuestMode::Plain)?;
    ensure!(
        assumption_session.segments.len() == 1,
        "assumption receipt source must contain exactly one segment"
    );
    let assumption_po2 = assumption_session.segments[0].po2;
    validate_lift_po2(assumption_po2)?;

    let prove_info = prover
        .prove_with_ctx(
            build_env(
                statement,
                image_id,
                GuestMode::Plain,
                crate::EXECUTOR_SEGMENT_LIMIT_PO2,
                workload_iterations,
                None,
            )?,
            ctx,
            elf,
            succinct_opts,
        )
        .context("same-program assumption receipt proving failed")?;
    ensure!(
        prove_info.stats.segments == 1 && prove_info.work_receipt.is_none(),
        "assumption receipt proving returned an unexpected segment/work shape"
    );
    validate_top_level_receipt(
        &prove_info.receipt,
        image_id,
        statement,
        CandidateTerminal::Lift(assumption_po2),
        ctx,
    )?;
    Ok(prove_info.receipt)
}

fn validate_supplied_lift_15_assumption(
    receipt: &Receipt,
    image_id: Digest,
    statement: &[u8],
    ctx: &VerifierContext,
) -> Result<()> {
    validate_top_level_receipt(
        receipt,
        image_id,
        statement,
        CandidateTerminal::Lift(15),
        ctx,
    )
    .context("supplied assumption receipt failed exact Lift-15 validation")
}

/// Prove the fixed plain Lift-15 receipt used by B4 negative ancestry.
///
/// This crate-private boundary exposes no workload, segment, mode, root, or
/// terminal selector. It always executes the exact plain same-program guest at
/// the frozen zero assumption workload and rejects any result other than a
/// stock Lift-15 with an empty assumption inventory.
pub(crate) fn prove_same_program_lift_15_assumption(
    prover: &LocalProver,
    elf: &[u8],
    image_id: Digest,
    statement: &[u8],
) -> Result<Receipt> {
    validate_method_identity(elf, image_id)?;
    validate_ergo_statement_v1(statement, &image_id)?;
    let ctx = VerifierContext::default().with_dev_mode(false);
    let succinct_opts = ProverOpts::succinct()
        .with_dev_mode(false)
        .with_prove_guest_errors(false);
    validate_options(&succinct_opts)?;
    let receipt = prove_same_program_assumption_receipt(
        prover,
        elf,
        image_id,
        statement,
        crate::recursive_calibration::RECURSIVE_ASSUMPTION_WORKLOAD_ITERATIONS,
        &ctx,
        &succinct_opts,
    )?;
    let InnerReceipt::Succinct(inner) = &receipt.inner else {
        bail!("fixed plain assumption receipt is not succinct");
    };
    ensure!(
        normal_lift_segment_po2(&inner.control_id)? == 15,
        "fixed plain assumption receipt is not Lift-15"
    );
    Ok(receipt)
}

/// Prove the fixed plain source segment used by terminal `lift-povw-po2-18`.
pub(crate) fn prove_plain_po2_18_segment(
    prover: &LocalProver,
    elf: &[u8],
    image_id: Digest,
    statement: &[u8],
) -> Result<SegmentReceipt> {
    validate_method_identity(elf, image_id)?;
    validate_ergo_statement_v1(statement, &image_id)?;
    let observe = |iterations| {
        let session = prover.execute(
            build_env(
                statement,
                image_id,
                GuestMode::Plain,
                crate::EXECUTOR_SEGMENT_LIMIT_PO2,
                iterations,
                None,
            )?,
            elf,
        )?;
        validate_session(&session, image_id, statement, GuestMode::Plain)?;
        SegmentObservation::new(
            session.segments.len(),
            (session.segments.len() == 1).then(|| session.segments[0].po2),
        )
    };
    let selected = select_canonical_iterations(PLAIN_PO2_18_TARGET_PO2, observe)?;
    let repeated = prover.execute(
        build_env(
            statement,
            image_id,
            GuestMode::Plain,
            crate::EXECUTOR_SEGMENT_LIMIT_PO2,
            selected.workload_iterations,
            None,
        )?,
        elf,
    )?;
    validate_session(&repeated, image_id, statement, GuestMode::Plain)?;
    let repeated_shape = SegmentObservation::new(
        repeated.segments.len(),
        (repeated.segments.len() == 1).then(|| repeated.segments[0].po2),
    )?;
    ensure!(
        repeated_shape == selected.observation
            && repeated_shape == SegmentObservation::new(1, Some(PLAIN_PO2_18_TARGET_PO2))?,
        "selected plain po2-18 execution did not repeat exactly"
    );

    let ctx = VerifierContext::default().with_dev_mode(false);
    let options = ProverOpts::composite()
        .with_dev_mode(false)
        .with_prove_guest_errors(false);
    validate_options(&options)?;
    let proof = prover.prove_with_ctx(
        build_env(
            statement,
            image_id,
            GuestMode::Plain,
            crate::EXECUTOR_SEGMENT_LIMIT_PO2,
            selected.workload_iterations,
            None,
        )?,
        &ctx,
        elf,
        &options,
    )?;
    ensure!(
        proof.stats.segments == 1 && proof.work_receipt.is_none(),
        "plain po2-18 proof returned an unexpected segment/work shape"
    );
    ensure!(
        proof.receipt.journal.bytes == statement,
        "plain po2-18 proof journal differs from the canonical statement"
    );
    proof.receipt.verify_with_context(&ctx, image_id)?;
    let InnerReceipt::Composite(composite) = proof.receipt.inner else {
        bail!("plain po2-18 proof is not composite");
    };
    ensure!(
        composite.segments.len() == 1 && composite.assumption_receipts.is_empty(),
        "plain po2-18 proof is not one assumption-free segment"
    );
    let segment = composite
        .segments
        .into_iter()
        .next()
        .context("plain po2-18 segment is absent")?;
    ensure!(segment.index == 0, "plain po2-18 segment index is not zero");
    let expected_claim = ReceiptClaim::ok(image_id, statement.to_vec()).digest();
    ensure!(
        segment.claim.digest() == expected_claim,
        "plain po2-18 segment claim differs from the canonical success claim"
    );
    ensure_claim_has_empty_assumptions(&segment.claim)?;
    segment.verify_integrity_with_context(&ctx)?;
    Ok(segment)
}

fn prove_b4_plain_lift_15(
    prover: &LocalProver,
    elf: &[u8],
    image_id: Digest,
    statement: &[u8],
) -> Result<ProvedPlainLift15> {
    let receipt = prove_same_program_lift_15_assumption(prover, elf, image_id, statement)?;
    let InnerReceipt::Succinct(succinct) = &receipt.inner else {
        bail!("fixed plain Lift-15 receipt is not succinct");
    };
    let expected_claim = ReceiptClaim::ok(image_id, statement.to_vec()).digest();
    let raw_seal =
        validate_candidate_terminal_shape(succinct, CandidateTerminal::Lift(15), &expected_claim)
            .context("fixed plain receipt is not the exact stock Lift-15")?;
    let receipt_oracle = encode_direct_receipt_oracle(succinct)
        .context("cannot encode the fixed plain Lift-15 receipt")?;
    Ok(ProvedPlainLift15 {
        receipt,
        raw_seal,
        receipt_oracle,
    })
}

/// Prove the fixed row-154 duplicate-assumption conditional Lift.
///
/// The caller supplies the already-authenticated case-9 assumption receipt.
/// This function exposes no mode, count, root, workload, or segment controls:
/// it validates that receipt as the exact same-program empty-assumption
/// Lift-15, inserts it once into the host cache, proves the private exact-twice
/// guest mode, requires two byte-identical attached receipts and two identical
/// revealed heads, and lifts the sole conditional segment with the stock
/// Lift-16 circuit.
///
/// # Errors
///
/// Returns an error for any method, statement, case-9 receipt, cache,
/// execution, source, assumption inventory, Lift, stock-profile, seal, or
/// direct-oracle mismatch.
#[allow(clippy::too_many_lines)]
fn prove_duplicate_assumption_lift_witness(
    prover: &LocalProver,
    elf: &[u8],
    image_id: Digest,
    statement: &[u8],
    authenticated_case9_assumption: &AuthenticatedCase9AssumptionReceipt,
) -> Result<DuplicateAssumptionLiftWitness> {
    const CASE9_ASSUMPTION_LIFT_PO2: u32 = 15;
    const DUPLICATE_SOURCE_LIFT_PO2: u32 = 16;

    let authenticated_case9_assumption = &authenticated_case9_assumption.receipt;
    validate_method_identity(elf, image_id)?;
    validate_ergo_statement_v1(statement, &image_id)?;
    let ctx = VerifierContext::default().with_dev_mode(false);
    let succinct_opts = ProverOpts::succinct()
        .with_dev_mode(false)
        .with_prove_guest_errors(false);
    let composite_opts = ProverOpts::composite()
        .with_dev_mode(false)
        .with_prove_guest_errors(false);
    validate_options(&succinct_opts)?;
    validate_options(&composite_opts)?;

    let InnerReceipt::Succinct(assumption_inner) = &authenticated_case9_assumption.inner else {
        bail!("authenticated case-9 assumption receipt is not succinct");
    };
    ensure!(
        normal_lift_segment_po2(&assumption_inner.control_id)? == CASE9_ASSUMPTION_LIFT_PO2,
        "authenticated case-9 assumption receipt is not Lift-15"
    );
    validate_top_level_receipt(
        authenticated_case9_assumption,
        image_id,
        statement,
        CandidateTerminal::Lift(CASE9_ASSUMPTION_LIFT_PO2),
        &ctx,
    )
    .context("authenticated case-9 assumption receipt is invalid")?;

    let mode = GuestMode::VerifyAssumptionExplicitRootTwice;
    let preflight = prover
        .execute(
            build_env(
                statement,
                image_id,
                mode,
                crate::EXECUTOR_SEGMENT_LIMIT_PO2,
                0,
                unresolved_assumption_for_mode(image_id, statement, mode)?,
            )?,
            elf,
        )
        .context("duplicate-assumption execute-only preflight failed")?;
    validate_session(&preflight, image_id, statement, mode)?;
    let preflight_po2 = preflight
        .segments
        .iter()
        .map(|segment| segment.po2)
        .collect::<Vec<_>>();
    ensure!(
        preflight_po2 == [DUPLICATE_SOURCE_LIFT_PO2],
        "duplicate-assumption preflight segment sequence is {preflight_po2:?}, expected [16]"
    );

    // One conversion and one builder insertion are intentional. The pinned
    // matcher is non-consuming, so both guest calls resolve through this one
    // cache entry while authenticating two separate output heads.
    let cached: AssumptionReceipt = authenticated_case9_assumption.clone().into();
    let AssumptionReceipt::Proven(expected_cached_inner) = &cached else {
        bail!("authenticated case-9 receipt converted to an unresolved cache entry");
    };
    let expected_cached_bytes =
        borsh::to_vec(expected_cached_inner).context("cannot encode the exact cached receipt")?;

    let source_info = prover
        .prove_with_ctx(
            build_env(
                statement,
                image_id,
                mode,
                crate::EXECUTOR_SEGMENT_LIMIT_PO2,
                0,
                Some(cached),
            )?,
            &ctx,
            elf,
            &composite_opts,
        )
        .context("duplicate-assumption source proving failed")?;
    ensure!(
        source_info.work_receipt.is_none() && source_info.stats.segments == 1,
        "duplicate-assumption source returned work or a non-single-segment shape"
    );
    let source_receipt = source_info.receipt;
    ensure!(
        source_receipt.journal.bytes == statement,
        "duplicate-assumption source journal differs from the exact statement"
    );
    source_receipt
        .verify_with_context(&ctx, image_id)
        .context("duplicate-assumption source receipt verification failed")?;
    ensure!(
        source_receipt.claim()?.digest() == ReceiptClaim::ok(image_id, statement.to_vec()).digest(),
        "resolved duplicate-assumption source is not the exact OK claim"
    );
    let InnerReceipt::Composite(source) = &source_receipt.inner else {
        bail!("duplicate-assumption source proof is not composite");
    };
    source
        .verify_integrity_with_context(&ctx)
        .context("duplicate-assumption source integrity verification failed")?;
    ensure!(
        source.segments.len() == 1 && source.segments[0].index == 0,
        "duplicate-assumption source is not the sole segment zero"
    );

    // CompositeReceipt::claim() resolves attached receipts. The raw segment
    // claim is the authenticated conditional claim required by row 154.
    let source_output = source.segments[0]
        .claim
        .output
        .as_value()
        .context("duplicate-assumption source output is pruned")?
        .as_ref()
        .context("duplicate-assumption source has no output")?;
    validate_assumption_inventory(&source_output.assumptions, image_id, statement, mode)?;
    ensure!(
        source.assumption_receipts.len() == 2,
        "duplicate-assumption source has {} attached receipts, expected 2",
        source.assumption_receipts.len()
    );
    for (index, actual) in source.assumption_receipts.iter().enumerate() {
        ensure!(
            borsh::to_vec(actual)? == expected_cached_bytes,
            "attached assumption receipt {index} differs from the single cached receipt"
        );
    }

    let server = get_prover_server(&succinct_opts)
        .context("cannot construct the pinned stock recursion prover")?;
    let lifted_receipt = server
        .lift(&source.segments[0])
        .context("duplicate-assumption Lift-16 proving failed")?;
    lifted_receipt
        .verify_integrity_with_context(&ctx)
        .context("duplicate-assumption Lift-16 integrity verification failed")?;
    let conditional_claim = source.segments[0].claim.digest();
    ensure!(
        lifted_receipt.claim.digest() == conditional_claim,
        "duplicate-assumption Lift does not authenticate the source segment claim"
    );
    let raw_seal = validate_candidate_terminal_shape(
        &lifted_receipt,
        CandidateTerminal::Lift(DUPLICATE_SOURCE_LIFT_PO2),
        &conditional_claim,
    )?;
    let lifted_output = lifted_receipt
        .claim
        .as_value()
        .context("duplicate-assumption Lift claim is pruned")?
        .output
        .as_value()
        .context("duplicate-assumption Lift output is pruned")?
        .as_ref()
        .context("duplicate-assumption Lift has no output")?;
    validate_assumption_inventory(&lifted_output.assumptions, image_id, statement, mode)?;
    let receipt_oracle = encode_direct_receipt_oracle(&lifted_receipt)?;

    Ok(DuplicateAssumptionLiftWitness {
        #[cfg(feature = "embedded-method")]
        source_receipt,
        #[cfg(feature = "embedded-method")]
        lifted_receipt,
        raw_seal,
        receipt_oracle,
    })
}

fn derive_b4_recursive_calibration_report(
    prover: &LocalProver,
    elf: &[u8],
    image_id: Digest,
    statement: &[u8],
    family: RecursiveFamily,
) -> Result<RecursiveCalibrationReport> {
    let image_id_bytes = digest_bytes(image_id);
    derive_recursive_calibration(
        elf,
        &image_id_bytes,
        statement,
        family.as_str(),
        |workload_iterations| {
            observe_recursive_calibration_shape(
                prover,
                elf,
                image_id,
                statement,
                family,
                RECURSIVE_CALIBRATION_SEGMENT_LIMIT_PO2,
                workload_iterations,
            )
        },
    )
    .with_context(|| format!("cannot derive the fixed {} calibration", family.as_str()))
}

fn final_b4_direct_evidence(
    oracle: &RecursiveOracle,
    image_id: Digest,
    statement: &[u8],
    expected_family: RecursiveFamily,
) -> Result<(Vec<u8>, Vec<u8>)> {
    ensure!(
        oracle.family == expected_family,
        "recursive oracle family differs from its fixed B4 producer recipe"
    );
    validate_recursive_oracle(oracle, image_id, statement)
        .context("fixed B4 recursive oracle failed complete replay")?;
    let final_receipt = step_receipt(&oracle.steps, oracle.final_step)
        .context("fixed B4 recursive oracle has no final receipt")?;
    let expected_claim = ReceiptClaim::ok(image_id, statement.to_vec()).digest();
    let raw_seal = validate_candidate_terminal_shape(
        final_receipt,
        expected_family.terminal(),
        &expected_claim,
    )
    .context("fixed B4 recursive oracle has the wrong final terminal")?;
    let receipt_oracle = encode_direct_receipt_oracle(final_receipt)
        .context("cannot encode the fixed B4 final receipt")?;
    Ok((raw_seal, receipt_oracle))
}

pub(crate) fn final_b4_terminal_join_direct_evidence(
    oracle: &RecursiveOracle,
    image_id: Digest,
    statement: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    final_b4_direct_evidence(oracle, image_id, statement, RecursiveFamily::TerminalJoin)
}

fn require_exact_assumption_receipt(
    oracle: &RecursiveOracle,
    expected: &[u8],
    family: RecursiveFamily,
) -> Result<()> {
    let receipt = oracle
        .assumption_receipt
        .as_ref()
        .with_context(|| format!("{} oracle has no assumption receipt", family.as_str()))?;
    ensure!(
        borsh::to_vec(receipt)? == expected,
        "{} oracle did not retain the one shared assumption receipt",
        family.as_str()
    );
    Ok(())
}

/// Prove all seven cryptographically distinct B4 negative-ancestry witnesses.
///
/// The opaque source token is created only after the reproduction authority
/// authenticates the complete positive case-9 and guest-program closure. This
/// producer accepts no caller-selected statement, ELF, image ID, family,
/// workload, segment exponent, root, terminal, row, path, or count. It derives
/// every such value internally, proves one alternate-statement assumption
/// exactly once for both recursive families, and returns evidence only after
/// all seven witnesses have succeeded and proved pairwise distinct.
///
/// This function does not publish or materialize witness artifacts; it returns
/// the complete in-memory set.
///
/// # Errors
///
/// Returns an error for any source identity, statement derivation, case-9
/// replay, calibration, execution, proof, assumption reuse, terminal, direct
/// receipt encoding, or seven-witness atomicity mismatch.
// Taking ownership preserves the opaque source token's single-use boundary.
#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
pub fn prove_b4_negative_ancestry_witness_set(
    prover: &LocalProver,
    source: B4AuthenticatedNegativeAncestryProducerSourceV1<'_>,
) -> Result<B4ProducedNegativeAncestryWitnessSetV1> {
    let source = AuthenticatedNegativeAncestryProducerView::from_v1(&source);
    prove_b4_negative_ancestry_witness_set_from_authenticated_view(prover, &source)
}

/// Prove all seven cryptographically distinct witnesses from a V2-authenticated source.
///
/// The V2 token is consumed directly and never converted to a V1 source. The
/// caller supplies no proof parameters, statement, guest, row, path, terminal,
/// or packet-derived lineage input.
///
/// # Errors
///
/// Returns the first authenticated-source, execution, proof, replay, terminal,
/// or seven-witness atomicity failure.
#[allow(clippy::needless_pass_by_value)]
pub fn prove_b4_negative_ancestry_witness_set_v2(
    prover: &LocalProver,
    source: B4AuthenticatedNegativeAncestryProducerSourceV2<'_>,
) -> Result<B4ProducedNegativeAncestryWitnessSetV1> {
    let source = AuthenticatedNegativeAncestryProducerView::from_v2(&source);
    prove_b4_negative_ancestry_witness_set_from_authenticated_view(prover, &source)
}

#[allow(clippy::too_many_lines)]
fn prove_b4_negative_ancestry_witness_set_from_authenticated_view(
    prover: &LocalProver,
    source: &AuthenticatedNegativeAncestryProducerView<'_>,
) -> Result<B4ProducedNegativeAncestryWitnessSetV1> {
    let (consumer_image_id, alternate_image_id) =
        authenticate_negative_ancestry_source_identities(&source)?;
    let alternate_statement = derive_b4_alternate_chain_domain_statement(
        source.canonical_statement(),
        &consumer_image_id,
    )?;
    let alternate_program_statement = derive_b4_alternate_program_statement(
        source.canonical_statement(),
        &consumer_image_id,
        &alternate_image_id,
    )?;
    let case9 = authenticate_case9_witness_bundle(&source, consumer_image_id)?;

    // Calibration remains execution-only. Both reports are derived in memory
    // from the exact authenticated guest and statement, then the proof core
    // repeats the selected source shape before doing any recursive proving.
    let resolve_calibration = derive_b4_recursive_calibration_report(
        prover,
        source.consumer_guest_elf(),
        consumer_image_id,
        &alternate_statement,
        RecursiveFamily::TerminalResolve,
    )?;
    let join_calibration = derive_b4_recursive_calibration_report(
        prover,
        source.consumer_guest_elf(),
        consumer_image_id,
        &alternate_statement,
        RecursiveFamily::ResolveThenJoin,
    )?;

    // This is the sole alternate-statement assumption proof. Exact clones of
    // this receipt are injected into both source composites.
    let shared_assumption = prove_b4_plain_lift_15(
        prover,
        source.consumer_guest_elf(),
        consumer_image_id,
        &alternate_statement,
    )?;
    let shared_assumption_bytes = borsh::to_vec(&shared_assumption.receipt)
        .context("cannot encode the shared alternate-statement assumption receipt")?;

    let resolve_oracle = generate_recursive_oracle_with_assumption_unreplayed(
        prover,
        source.consumer_guest_elf(),
        consumer_image_id,
        &alternate_statement,
        RecursiveFamily::TerminalResolve,
        &resolve_calibration,
        shared_assumption.receipt.clone(),
    )?;
    let (resolve_raw_seal, resolve_receipt_oracle) = final_b4_direct_evidence(
        &resolve_oracle,
        consumer_image_id,
        &alternate_statement,
        RecursiveFamily::TerminalResolve,
    )?;
    validate_recursive_oracle_calibration(&resolve_oracle, &resolve_calibration)?;
    require_exact_assumption_receipt(
        &resolve_oracle,
        &shared_assumption_bytes,
        RecursiveFamily::TerminalResolve,
    )?;

    let join_oracle = generate_recursive_oracle_with_assumption_unreplayed(
        prover,
        source.consumer_guest_elf(),
        consumer_image_id,
        &alternate_statement,
        RecursiveFamily::ResolveThenJoin,
        &join_calibration,
        shared_assumption.receipt.clone(),
    )?;
    let (join_raw_seal, join_receipt_oracle) = final_b4_direct_evidence(
        &join_oracle,
        consumer_image_id,
        &alternate_statement,
        RecursiveFamily::ResolveThenJoin,
    )?;
    validate_recursive_oracle_calibration(&join_oracle, &join_calibration)?;
    require_exact_assumption_receipt(
        &join_oracle,
        &shared_assumption_bytes,
        RecursiveFamily::ResolveThenJoin,
    )?;

    let alternate_program_lift = prove_b4_plain_lift_15(
        prover,
        source.alternate_guest_elf(),
        alternate_image_id,
        &alternate_program_statement,
    )?;
    let duplicate_assumption = prove_duplicate_assumption_lift_witness(
        prover,
        source.consumer_guest_elf(),
        consumer_image_id,
        source.canonical_statement(),
        &case9.assumption_receipt,
    )?;

    let ProvedPlainLift15 {
        receipt: _,
        raw_seal: shared_raw_seal,
        receipt_oracle: shared_receipt_oracle,
    } = shared_assumption;
    let ProvedPlainLift15 {
        receipt: _,
        raw_seal: alternate_program_raw_seal,
        receipt_oracle: alternate_program_receipt_oracle,
    } = alternate_program_lift;
    let DuplicateAssumptionLiftWitness {
        raw_seal: duplicate_raw_seal,
        receipt_oracle: duplicate_receipt_oracle,
        ..
    } = duplicate_assumption;

    B4ProducedNegativeAncestryWitnessSetV1::from_verified_distinct(
        case9.assumption_lift,
        case9.final_resolve,
        B4AlternateStatementAssumptionLiftEvidenceV1::from_verified_parts(
            shared_raw_seal,
            shared_receipt_oracle,
        )?,
        B4AlternateProgramLiftEvidenceV1::from_verified_parts(
            alternate_program_raw_seal,
            alternate_program_receipt_oracle,
        )?,
        B4AlternateStatementFinalResolveEvidenceV1::from_verified_parts(
            resolve_raw_seal,
            resolve_receipt_oracle,
        )?,
        B4AlternateStatementFinalJoinEvidenceV1::from_verified_parts(
            join_raw_seal,
            join_receipt_oracle,
        )?,
        B4DuplicateAssumptionLiftEvidenceV1::from_verified_parts(
            duplicate_raw_seal,
            duplicate_receipt_oracle,
        )?,
    )
}

/// Prove the fixed seven-witness set and derive its authenticated catalogue as
/// one in-memory semantic transaction.
///
/// The caller supplies only the opaque source authority. It selects neither
/// rows nor evidence paths, and this bridge performs no filesystem writes.
///
/// # Errors
///
/// Returns the first source-authentication, proof-production, row-expansion,
/// stock-replay, claim, or derived-catalogue invariant failure.
#[cfg(feature = "b4-negative-ancestry-finalization")]
pub fn prove_and_finalize_b4_negative_ancestry_witness_catalog(
    prover: &LocalProver,
    authority: &B4NegativeAncestrySourceAuthorityV1,
) -> Result<B4NegativeAncestryWitnessCatalogAuthorityV1> {
    prove_b4_negative_ancestry_witness_set(prover, authority.producer_source())?
        .finalize_catalog(authority)
}

/// Prove the fixed seven-witness set and derive its V2-authenticated catalogue.
///
/// # Errors
///
/// Returns the first V2 source-authentication, proof-production, row-expansion,
/// stock-replay, claim, or derived-catalogue invariant failure.
#[cfg(feature = "b4-negative-ancestry-finalization")]
pub fn prove_and_finalize_b4_negative_ancestry_witness_catalog_v2(
    prover: &LocalProver,
    authority: &B4NegativeAncestrySourceAuthorityV2,
) -> Result<B4NegativeAncestryWitnessCatalogAuthorityV2> {
    prove_b4_negative_ancestry_witness_set_v2(prover, authority.producer_source())?
        .finalize_catalog_v2(authority)
}

/// Prove, authenticate, and create-only publish the fixed B4 negative-ancestry
/// witness catalogue.
///
/// # Errors
///
/// Returns the first proving, authentication, publication, durability, or
/// post-publication validation failure. An error after the no-replace rename
/// may still leave the authenticated destination committed.
#[cfg(feature = "b4-negative-ancestry-publication")]
pub fn prove_finalize_and_publish_b4_negative_ancestry_witness_catalog(
    prover: &LocalProver,
    authority: &B4NegativeAncestrySourceAuthorityV1,
    output_root: &std::path::Path,
) -> Result<B4NegativeAncestryWitnessCatalogAuthorityV1> {
    let catalog = prove_and_finalize_b4_negative_ancestry_witness_catalog(prover, authority)?;
    eip_0045_reproduction::b4_negative_ancestry_publication::publish_b4_negative_ancestry_witness_catalog(
        output_root,
        &catalog,
    )?;
    Ok(catalog)
}

/// Generate one complete recursive candidate oracle without publishing files.
///
/// The caller must run the execute-only shape inspection first. This function
/// repeats that inspection, proves a single-lift assumption receipt when
/// required, proves the source composite, then applies only stock normal lift,
/// join, and resolve programs in the canonical graph order.
///
/// # Errors
///
/// Returns an error for any guest, receipt, claim, graph, terminal, assumption,
/// or upstream verification mismatch.
// Keeping the generation transaction in one function makes its preflight,
// proving, replay, and final verification order explicit and auditable.
#[allow(clippy::too_many_lines)]
pub fn generate_recursive_oracle(
    prover: &LocalProver,
    elf: &[u8],
    image_id: Digest,
    statement: &[u8],
    family: RecursiveFamily,
    calibration: &RecursiveCalibrationReport,
) -> Result<RecursiveOracle> {

    generate_recursive_oracle_with_recipe(prover, elf, image_id, statement, family, calibration, RecursiveCalibrationRecipe::Fixed22)
}

/// Explicit-recipe counterpart; the historical entry remains Fixed22.
pub fn generate_recursive_oracle_with_recipe(
    prover: &LocalProver,
    elf: &[u8],
    image_id: Digest,
    statement: &[u8],
    family: RecursiveFamily,
    calibration: &RecursiveCalibrationReport,
    recipe: RecursiveCalibrationRecipe,
) -> Result<RecursiveOracle> {

    recipe.validate_family(family.as_str())?;
    let image_id_bytes = digest_bytes(image_id);
    verify_recursive_calibration_with_recipe(
        calibration,
        elf,
        &image_id_bytes,
        statement,
        family.as_str(),
        recipe,
        |workload_iterations| {
            observe_recursive_calibration_shape(
                prover,
                elf,
                image_id,
                statement,
                family,
                recipe.segment_limit_po2(),
                workload_iterations,
            )
        },
    )?;
    let oracle = generate_recursive_oracle_unreplayed(
        prover,
        elf,
        image_id,
        statement,
        family,
        &calibration.segment_po2,
        calibration.segment_limit_po2,
        calibration.workload_iterations,
        calibration.assumption_workload_iterations,
    )?;
    validate_recursive_oracle(&oracle, image_id, statement)?;
    validate_recursive_oracle_calibration_with_recipe(&oracle, calibration, recipe)?;
    Ok(oracle)
}

/// Generate an assumption-bearing oracle through final receipt verification
/// without replaying its complete ancestry archive.
///
/// The calibration must already have been authenticated or freshly derived by
/// the caller. The core still repeats the exact source-shape preflight before
/// proving and preserves the supplied Lift-15 receipt byte-for-byte.
#[allow(clippy::too_many_arguments)]
pub(crate) fn generate_recursive_oracle_with_assumption_unreplayed(
    prover: &LocalProver,
    elf: &[u8],
    image_id: Digest,
    statement: &[u8],
    family: RecursiveFamily,
    calibration: &RecursiveCalibrationReport,
    assumption_receipt: Receipt,
) -> Result<RecursiveOracle> {
    validate_supplied_assumption_family(family)?;
    let expected_assumption_bytes = borsh::to_vec(&assumption_receipt)
        .context("cannot encode the supplied assumption receipt")?;
    let oracle = generate_recursive_oracle_unreplayed_with_assumption_source(
        prover,
        elf,
        image_id,
        statement,
        family,
        &calibration.segment_po2,
        calibration.segment_limit_po2,
        calibration.workload_iterations,
        RecursiveAssumptionSource::Supplied(assumption_receipt),
    )?;
    let retained = oracle
        .assumption_receipt
        .as_ref()
        .context("assumption-bearing oracle did not retain its supplied receipt")?;
    ensure!(
        borsh::to_vec(retained)? == expected_assumption_bytes,
        "assumption-bearing oracle changed the supplied receipt bytes"
    );
    Ok(oracle)
}

/// Only the two local alternate-statement final recipes; no ambient selector.
#[cfg(feature = "embedded-method")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalAlternateStatementBranch { ResolveFixed22, ResolveThenJoinJoin21 }

#[cfg(feature = "embedded-method")]
impl LocalAlternateStatementBranch {
    pub(crate) fn family(self) -> RecursiveFamily {
        match self { Self::ResolveFixed22 => RecursiveFamily::TerminalResolve,
            Self::ResolveThenJoinJoin21 => RecursiveFamily::ResolveThenJoin }
    }
    pub(crate) fn recipe(self) -> RecursiveCalibrationRecipe {
        match self { Self::ResolveFixed22 => RecursiveCalibrationRecipe::Fixed22,
            Self::ResolveThenJoinJoin21 => RecursiveCalibrationRecipe::Join21 }
    }
    pub(crate) fn label(self) -> &'static str {
        match self { Self::ResolveFixed22 => "alternate-statement-resolve-fixed22",
            Self::ResolveThenJoinJoin21 => "alternate-statement-resolve-then-join-join21" }
    }
}

#[cfg(feature = "embedded-method")]
fn verify_local_final_calibration(report: &RecursiveCalibrationReport, elf: &[u8], image_id: Digest,
    statement: &[u8], branch: LocalAlternateStatementBranch,
    observe: impl FnMut(u32) -> Result<Vec<u32>>) -> Result<()> {
    verify_recursive_calibration_with_recipe(report, elf, &digest_bytes(image_id), statement,
        branch.family().as_str(), branch.recipe(), observe)
}

/// Borrows the admitted checkpoint and the one authenticated calibration report.
#[cfg(feature = "embedded-method")]
pub(crate) struct LocalAlternateStatementFinalInput<'a> {
    shared: &'a crate::local_ancestry_shared_assumption::AuthenticatedSharedCheckpoint,
    calibration: &'a RecursiveCalibrationReport,
    branch: LocalAlternateStatementBranch,
}

#[cfg(feature = "embedded-method")]
impl<'a> LocalAlternateStatementFinalInput<'a> {
    pub(crate) fn admit(
        shared: &'a crate::local_ancestry_shared_assumption::AuthenticatedSharedCheckpoint,
        calibration: &'a RecursiveCalibrationReport, branch: LocalAlternateStatementBranch,
        prover: &LocalProver,
    ) -> Result<Self> {
        shared.verify()?;
        let (elf, image_id) = shared.consumer();
        let result = verify_local_final_calibration(calibration, elf, image_id,
            shared.statement(), branch, |iterations| {
                observe_recursive_calibration_shape(prover, elf, image_id, shared.statement(),
                    branch.family(), branch.recipe().segment_limit_po2(), iterations)
            });
        shared.verify()?;
        result?;
        Ok(Self { shared, calibration, branch })
    }

    pub(crate) fn prove(&self, prover: &LocalProver) -> Result<RecursiveOracle> {
        self.shared.verify()?;
        let result = (|| {
            let (elf, image_id) = self.shared.consumer();
            let oracle = generate_recursive_oracle_with_assumption_unreplayed(prover, elf,
                image_id, self.shared.statement(), self.branch.family(), self.calibration,
                self.shared.receipt_clone()?)?;
            self.evidence(&oracle)?;
            Ok(oracle)
        })();
        self.shared.verify()?;
        result
    }

    /// Full archive replay, exact supplied outer Receipt, calibrated graph and terminal.
    pub(crate) fn evidence(&self, oracle: &RecursiveOracle) -> Result<(Vec<u8>, Vec<u8>)> {
        self.shared.verify()?;
        let result = (|| {
            ensure!(oracle.family == self.branch.family(), "local final family mismatch");
            require_exact_assumption_receipt(oracle, self.shared.outer_bytes(), self.branch.family())?;
            let (_, image_id) = self.shared.consumer();
            let evidence = final_b4_direct_evidence(oracle, image_id, self.shared.statement(), self.branch.family())?;
            validate_recursive_oracle_calibration_with_recipe(oracle, self.calibration, self.branch.recipe())?;
            require_exact_assumption_receipt(oracle, self.shared.outer_bytes(), self.branch.family())?;
            Ok(evidence)
        })();
        self.shared.verify()?;
        result
    }
}

/// Generate an oracle through final receipt verification, before full replay.
///
/// This internal boundary lets the export layer durably checkpoint the costly
/// final receipt before performing redundant archive replay and serialization
/// checks. Callers outside the export transaction must use
/// [`generate_recursive_oracle`], which always replays the complete oracle.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn generate_recursive_oracle_unreplayed(
    prover: &LocalProver,
    elf: &[u8],
    image_id: Digest,
    statement: &[u8],
    family: RecursiveFamily,
    expected_source_segment_po2: &[u32],
    segment_limit_po2: u32,
    workload_iterations: u32,
    assumption_workload_iterations: u32,
) -> Result<RecursiveOracle> {
    let assumption_source = if family.uses_assumption() {
        RecursiveAssumptionSource::Prove {
            workload_iterations: assumption_workload_iterations,
        }
    } else {
        RecursiveAssumptionSource::None
    };
    generate_recursive_oracle_unreplayed_with_assumption_source(
        prover,
        elf,
        image_id,
        statement,
        family,
        expected_source_segment_po2,
        segment_limit_po2,
        workload_iterations,
        assumption_source,
    )
}

// The supplied receipt is intentionally retained by value for byte-exact replay.
#[allow(clippy::large_enum_variant)]
enum RecursiveAssumptionSource {
    None,
    Prove { workload_iterations: u32 },
    Supplied(Receipt),
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn generate_recursive_oracle_unreplayed_with_assumption_source(
    prover: &LocalProver,
    elf: &[u8],
    image_id: Digest,
    statement: &[u8],
    family: RecursiveFamily,
    expected_source_segment_po2: &[u32],
    segment_limit_po2: u32,
    workload_iterations: u32,
    assumption_source: RecursiveAssumptionSource,
) -> Result<RecursiveOracle> {
    let preflight_po2 = inspect_recursive_shape(
        prover,
        elf,
        image_id,
        statement,
        family,
        segment_limit_po2,
        workload_iterations,
    )?;
    validate_calibrated_source_shape(family, expected_source_segment_po2, &preflight_po2)?;

    let ctx = VerifierContext::default().with_dev_mode(false);
    let succinct_opts = ProverOpts::succinct()
        .with_dev_mode(false)
        .with_prove_guest_errors(false);
    validate_options(&succinct_opts)?;

    let assumption_receipt = match (family.uses_assumption(), assumption_source) {
        (false, RecursiveAssumptionSource::None) => None,
        (
            true,
            RecursiveAssumptionSource::Prove {
                workload_iterations,
            },
        ) => Some(prove_same_program_assumption_receipt(
            prover,
            elf,
            image_id,
            statement,
            workload_iterations,
            &ctx,
            &succinct_opts,
        )?),
        (true, RecursiveAssumptionSource::Supplied(receipt)) => {
            validate_supplied_lift_15_assumption(&receipt, image_id, statement, &ctx)?;
            Some(receipt)
        }
        (false, _) => bail!(
            "a recursive assumption source is inadmissible for {}",
            family.as_str()
        ),
        (true, RecursiveAssumptionSource::None) => {
            bail!("{} requires one assumption receipt", family.as_str())
        }
    };

    let source_assumption = assumption_receipt.clone().map(Into::into);
    let composite_opts = ProverOpts::composite()
        .with_dev_mode(false)
        .with_prove_guest_errors(false);
    validate_options(&composite_opts)?;
    let source_info = prover
        .prove_with_ctx(
            build_recursive_source_env(
                statement,
                image_id,
                family,
                segment_limit_po2,
                workload_iterations,
                source_assumption,
            )?,
            &ctx,
            elf,
            &composite_opts,
        )
        .context("recursive source composite proving failed")?;
    ensure!(
        source_info.stats.segments == preflight_po2.len(),
        "source proof segment count differs from execute-only preflight"
    );
    ensure!(
        source_info.work_receipt.is_none(),
        "source composite unexpectedly returned a work receipt"
    );
    ensure!(
        source_info.receipt.journal.bytes == statement,
        "source composite journal differs from ErgoStatementV1"
    );
    source_info
        .receipt
        .verify_with_context(&ctx, image_id)
        .context("source composite verification failed")?;
    let InnerReceipt::Composite(source_composite) = &source_info.receipt.inner else {
        bail!("source prover did not return a composite receipt");
    };
    ensure!(
        source_composite.segments.len() == preflight_po2.len(),
        "source composite segment count differs from execute-only preflight"
    );
    ensure!(
        source_composite.assumption_receipts.len() == usize::from(family.uses_assumption()),
        "source composite assumption receipt count differs from requested family"
    );

    let plan = planned_steps(family, source_composite.segments.len())?;
    let server = get_prover_server(&succinct_opts)
        .context("cannot construct pinned stock recursion prover")?;
    let assumption_succinct = assumption_receipt
        .as_ref()
        .map(|receipt| match &receipt.inner {
            InnerReceipt::Succinct(inner) => Ok(inner.clone()),
            _ => bail!("assumption receipt is not succinct"),
        })
        .transpose()?;
    validate_source_assumption_claim(source_composite, family, assumption_succinct.as_ref())?;

    let mut steps = Vec::<RecursiveStep>::with_capacity(plan.len());
    for planned in plan {
        let receipt = match planned.inputs {
            RecursiveInputs::Lift { segment_index } => {
                let segment = source_composite
                    .segments
                    .get(segment_index as usize)
                    .context("planned lift segment index is out of range")?;
                let receipt = server.lift(segment).context("stock lift proving failed")?;
                validate_lift_control_id(
                    expected_source_segment_po2,
                    segment_index,
                    &receipt.control_id,
                )?;
                receipt
            }
            RecursiveInputs::Join {
                left_step,
                right_step,
            } => {
                let left = step_receipt(&steps, left_step)?;
                let right = step_receipt(&steps, right_step)?;
                server
                    .join(left, right)
                    .context("stock join proving failed")?
            }
            RecursiveInputs::Resolve { conditional_step } => {
                let conditional = step_receipt(&steps, conditional_step)?;
                let assumption = assumption_succinct
                    .as_ref()
                    .context("resolve plan has no assumption receipt")?
                    .clone()
                    .into_unknown();
                server
                    .resolve(conditional, &assumption)
                    .context("stock resolve proving failed")?
            }
        };
        let ordinal = u32::try_from(steps.len()).context("ancestry ordinal does not fit u32")?;
        let step = RecursiveStep {
            ordinal,
            operation: planned.operation,
            inputs: planned.inputs,
            receipt,
        };
        validate_step(
            &step,
            source_composite,
            assumption_succinct.as_ref(),
            &steps,
            &ctx,
        )?;
        steps.push(step);
    }

    let final_step = u32::try_from(steps.len() - 1).context("final step does not fit u32")?;
    let final_receipt = step_receipt(&steps, final_step)?;
    let expected_claim = ReceiptClaim::ok(image_id, statement.to_vec()).digest();
    ensure!(
        final_receipt.claim.digest() == expected_claim,
        "recursive final receipt is not the exact successful ErgoStatementV1 claim"
    );
    validate_candidate_terminal_shape(final_receipt, family.terminal(), &expected_claim)?;
    ensure_claim_has_empty_assumptions(final_receipt.claim.as_value()?)?;
    Receipt::new(
        InnerReceipt::Succinct(final_receipt.clone()),
        statement.to_vec(),
    )
    .verify_with_context(&ctx, image_id)
    .context("recursive final receipt failed upstream verification")?;

    Ok(RecursiveOracle {
        format_version: 2,
        family,
        source_receipt: source_info.receipt,
        assumption_receipt,
        steps,
        final_step,
    })
}

/// Verify every source proof, ancestry edge, final terminal, and OK claim.
///
/// # Errors
///
/// Returns an error for any schema, family graph, receipt, operation semantic,
/// assumption, final-claim, or terminal mismatch.
// This is deliberately one fail-closed replay pipeline: the source,
// assumption, ancestry, and final gates stay in their visible validation order.
#[allow(clippy::too_many_lines)]
pub fn validate_recursive_oracle(
    oracle: &RecursiveOracle,
    image_id: Digest,
    statement: &[u8],
) -> Result<()> {
    ensure!(
        oracle.format_version == 2,
        "recursive oracle format version is not 2"
    );
    validate_ergo_statement_v1(statement, &image_id)?;
    let ctx = VerifierContext::default().with_dev_mode(false);
    ensure!(
        oracle.source_receipt.journal.bytes == statement,
        "source oracle journal differs from expected statement"
    );
    oracle
        .source_receipt
        .verify_with_context(&ctx, image_id)
        .context("source oracle receipt verification failed")?;
    let InnerReceipt::Composite(source) = &oracle.source_receipt.inner else {
        bail!("source oracle receipt is not composite");
    };
    if oracle.family == RecursiveFamily::TerminalJoin {
        validate_terminal_join_source_povw_segments(&source.segments, image_id, statement)?;
    }
    let plan = planned_steps(oracle.family, source.segments.len())?;
    ensure!(
        oracle.steps.len() == plan.len(),
        "ancestry step count differs from canonical family graph"
    );
    ensure!(
        oracle.final_step as usize + 1 == oracle.steps.len(),
        "final-step index does not identify the last ancestry receipt"
    );

    let assumption_succinct = match (
        oracle.family.uses_assumption(),
        oracle.assumption_receipt.as_ref(),
    ) {
        (false, None) => None,
        (false, Some(_)) => bail!("terminal-join oracle unexpectedly carries an assumption"),
        (true, None) => bail!("assumption-bearing oracle has no assumption receipt"),
        (true, Some(receipt)) => {
            ensure!(
                receipt.journal.bytes == statement,
                "assumption receipt journal differs from expected statement"
            );
            receipt
                .verify_with_context(&ctx, image_id)
                .context("assumption oracle receipt verification failed")?;
            ensure!(
                receipt.claim()?.digest()
                    == ReceiptClaim::ok(image_id, statement.to_vec()).digest(),
                "assumption receipt is not the exact successful same-program claim"
            );
            let InnerReceipt::Succinct(inner) = &receipt.inner else {
                bail!("assumption oracle receipt is not succinct");
            };
            let po2 = normal_lift_segment_po2(&inner.control_id)?;
            validate_candidate_terminal_shape(
                inner,
                CandidateTerminal::Lift(po2),
                &inner.claim.digest(),
            )?;
            ensure_claim_has_empty_assumptions(inner.claim.as_value()?)?;
            Some(inner.clone())
        }
    };
    ensure!(
        source.assumption_receipts.len() == usize::from(oracle.family.uses_assumption()),
        "source oracle assumption count differs from family"
    );
    validate_source_assumption_claim(source, oracle.family, assumption_succinct.as_ref())?;
    if let Some(assumption) = &assumption_succinct {
        let InnerAssumptionReceipt::Succinct(source_assumption) = &source.assumption_receipts[0]
        else {
            bail!("source composite assumption is not succinct");
        };
        ensure!(
            source_assumption.claim.digest() == assumption.claim.digest()
                && source_assumption.control_id == assumption.control_id
                && source_assumption.get_seal_bytes() == assumption.get_seal_bytes()
                && source_assumption.hashfn == assumption.hashfn
                && source_assumption.verifier_parameters == assumption.verifier_parameters
                && source_assumption.control_inclusion_proof.index
                    == assumption.control_inclusion_proof.index
                && source_assumption.control_inclusion_proof.digests
                    == assumption.control_inclusion_proof.digests,
            "source composite assumption differs from exported assumption receipt"
        );
    }

    let mut verified = Vec::with_capacity(oracle.steps.len());
    for (ordinal, (step, expected)) in oracle.steps.iter().zip(plan).enumerate() {
        ensure!(
            step.ordinal as usize == ordinal,
            "ancestry ordinal is not canonical at index {ordinal}"
        );
        ensure!(
            step.operation == expected.operation && step.inputs == expected.inputs,
            "ancestry graph differs from canonical plan at step {ordinal}"
        );
        validate_step(step, source, assumption_succinct.as_ref(), &verified, &ctx)?;
        verified.push(step.clone());
    }

    let final_receipt = step_receipt(&verified, oracle.final_step)?;
    let expected_claim = ReceiptClaim::ok(image_id, statement.to_vec()).digest();
    ensure!(
        final_receipt.claim.digest() == expected_claim,
        "final ancestry claim is not exact ErgoStatementV1 OK"
    );
    ensure_claim_has_empty_assumptions(final_receipt.claim.as_value()?)?;
    validate_candidate_terminal_shape(final_receipt, oracle.family.terminal(), &expected_claim)?;
    Receipt::new(
        InnerReceipt::Succinct(final_receipt.clone()),
        statement.to_vec(),
    )
    .verify_with_context(&ctx, image_id)
    .context("reconstructed final receipt verification failed")?;
    Ok(())
}

/// Bind an already cryptographically replayed oracle to one authenticated
/// deterministic calibration report.
///
/// This proves agreement between the retained source/lift shape and the fresh
/// calibration replay. It does not make the historical ancestry receipt-bound
/// or consensus provenance.
///
/// # Errors
///
/// Returns an error if the family, source cardinality, or any retained lift
/// exponent differs from the exact calibrated sequence.
pub fn validate_recursive_oracle_calibration(
    oracle: &RecursiveOracle,
    calibration: &RecursiveCalibrationReport,
) -> Result<()> {

    validate_recursive_oracle_calibration_with_recipe(oracle, calibration, RecursiveCalibrationRecipe::Fixed22)
}

/// Check the oracle against the explicitly selected calibration recipe.
pub fn validate_recursive_oracle_calibration_with_recipe(
    oracle: &RecursiveOracle,
    calibration: &RecursiveCalibrationReport,
    recipe: RecursiveCalibrationRecipe,
) -> Result<()> {
    let canonical = calibration.to_canonical_jcs_with_recipe(recipe)?;
    let parsed = RecursiveCalibrationReport::from_canonical_jcs_with_recipe(&canonical, recipe)?;
    ensure!(
        parsed == *calibration,
        "recursive calibration changed during canonical round-trip"
    );
    ensure!(
        calibration.family == oracle.family.as_str(),
        "recursive calibration family differs from retained oracle"
    );
    ensure!(
        calibration.segment_limit_po2 == recipe.segment_limit_po2(),
        "recursive calibration segment limit differs from the fixed B4 value"
    );
    let InnerReceipt::Composite(source) = &oracle.source_receipt.inner else {
        bail!("recursive source receipt is not composite");
    };
    ensure!(
        source.segments.len() == calibration.segment_po2.len(),
        "retained source segment count differs from calibration"
    );
    for (segment_index, expected_po2) in calibration.segment_po2.iter().enumerate() {
        let step = oracle
            .steps
            .get(segment_index)
            .context("retained oracle omits a calibrated source lift")?;
        let RecursiveInputs::Lift {
            segment_index: lifted_index,
        } = &step.inputs
        else {
            bail!("retained calibrated source step is not a lift");
        };
        ensure!(
            *lifted_index as usize == segment_index,
            "retained calibrated lift index differs"
        );
        let actual_po2 = normal_lift_segment_po2(&step.receipt.control_id)?;
        ensure!(
            actual_po2 == *expected_po2,
            "retained source lift exponent differs from calibration"
        );
    }
    Ok(())
}

fn digest_bytes(digest: Digest) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(digest.as_bytes());
    bytes
}

const TERMINAL_JOIN_SOURCE_POVW_JOB_DOMAIN: &[u8] =
    b"eip0045/b4/terminal-join/source-povw-job/v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TerminalJoinSourceNonceFields {
    receipt_index: u32,
    log_is_zero: bool,
    job: u64,
    segment: u32,
}

const fn normalize_terminal_join_source_job_number(candidate: u64) -> u64 {
    if candidate == 0 { 1 } else { candidate }
}

fn derive_terminal_join_source_povw_job_digest(image_id: Digest, statement: &[u8]) -> [u8; 32] {
    let statement_digest = Sha256::digest(statement);
    let mut hasher = Sha256::new();
    hasher.update(TERMINAL_JOIN_SOURCE_POVW_JOB_DOMAIN);
    hasher.update(image_id.as_bytes());
    hasher.update(statement_digest);
    hasher.finalize().into()
}

fn derive_terminal_join_source_povw_job_number(image_id: Digest, statement: &[u8]) -> u64 {
    let digest = derive_terminal_join_source_povw_job_digest(image_id, statement);
    let candidate = u64::from_le_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 prefix is exactly eight bytes"),
    );
    normalize_terminal_join_source_job_number(candidate)
}

fn recursive_source_povw_job_number(
    family: RecursiveFamily,
    image_id: Digest,
    statement: &[u8],
) -> Option<u64> {
    (family == RecursiveFamily::TerminalJoin)
        .then(|| derive_terminal_join_source_povw_job_number(image_id, statement))
}

fn validate_terminal_join_source_nonce_fields(
    job_number: u64,
    fields: &[TerminalJoinSourceNonceFields],
) -> Result<()> {
    ensure!(
        fields.len() == 2,
        "terminal-join source must contain exactly two PoVW nonces"
    );
    for (expected, field) in fields.iter().enumerate() {
        let expected = u32::try_from(expected).expect("two nonce positions fit u32");
        ensure!(
            field.receipt_index == expected,
            "terminal-join source receipt index differs at position {expected}"
        );
        ensure!(
            field.log_is_zero && field.job == job_number && field.segment == expected,
            "terminal-join source PoVW nonce differs at segment {expected}"
        );
    }
    Ok(())
}

fn validate_terminal_join_source_povw_segments(
    segments: &[SegmentReceipt],
    image_id: Digest,
    statement: &[u8],
) -> Result<()> {
    let fields = segments
        .iter()
        .map(|receipt| {
            let nonce = receipt.povw_nonce().with_context(|| {
                format!(
                    "cannot decode terminal-join source PoVW nonce at receipt index {}",
                    receipt.index
                )
            })?;
            Ok(TerminalJoinSourceNonceFields {
                receipt_index: receipt.index,
                log_is_zero: nonce.log == 0_u64,
                job: nonce.job,
                segment: nonce.segment,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    validate_terminal_join_source_nonce_fields(
        derive_terminal_join_source_povw_job_number(image_id, statement),
        &fields,
    )
}

pub(crate) fn validate_terminal_join_source_povw(
    oracle: &RecursiveOracle,
    image_id: Digest,
    statement: &[u8],
) -> Result<()> {
    ensure!(
        oracle.family == RecursiveFamily::TerminalJoin,
        "terminal-join PoVW source validator received another family"
    );
    let InnerReceipt::Composite(source) = &oracle.source_receipt.inner else {
        bail!("terminal-join source receipt is not composite");
    };
    validate_terminal_join_source_povw_segments(&source.segments, image_id, statement)
}

fn build_recursive_source_env(
    statement: &[u8],
    image_id: Digest,
    family: RecursiveFamily,
    segment_limit_po2: u32,
    workload_iterations: u32,
    assumption: Option<AssumptionReceipt>,
) -> Result<ExecutorEnv<'static>> {
    build_env_with_povw_job(
        statement,
        image_id,
        family.guest_mode(),
        segment_limit_po2,
        workload_iterations,
        assumption,
        recursive_source_povw_job_number(family, image_id, statement),
    )
}

fn build_env(
    statement: &[u8],
    image_id: Digest,
    mode: GuestMode,
    segment_limit_po2: u32,
    workload_iterations: u32,
    assumption: Option<AssumptionReceipt>,
) -> Result<ExecutorEnv<'static>> {
    build_env_with_povw_job(
        statement,
        image_id,
        mode,
        segment_limit_po2,
        workload_iterations,
        assumption,
        None,
    )
}

// The pinned tuple target is intentionally inferred to avoid a direct
// `risc0-binfmt` dependency merely to name the default work-log type.
#[allow(clippy::default_trait_access)]
fn build_env_with_povw_job(
    statement: &[u8],
    image_id: Digest,
    mode: GuestMode,
    segment_limit_po2: u32,
    workload_iterations: u32,
    assumption: Option<AssumptionReceipt>,
    povw_job_number: Option<u64>,
) -> Result<ExecutorEnv<'static>> {
    ensure!(
        (15..=crate::EXECUTOR_SEGMENT_LIMIT_PO2).contains(&segment_limit_po2),
        "executor segment limit po2 is outside 15..={}",
        crate::EXECUTOR_SEGMENT_LIMIT_PO2
    );
    ensure!(
        mode.verifies_assumption() == assumption.is_some(),
        "guest assumption mode and host assumption cache differ"
    );
    expected_assumption_control_root(mode)?;
    let image_id_bytes: [u8; 32] = image_id
        .as_bytes()
        .try_into()
        .context("guest image ID is not exactly 32 bytes")?;
    let header = match mode {
        GuestMode::Plain => {
            GuestInputHeader::new(statement.len(), workload_iterations, WORKLOAD_SEED)
        }
        GuestMode::VerifyAssumptionZeroRoot => GuestInputHeader::new_verifying_zero_root(
            statement.len(),
            workload_iterations,
            WORKLOAD_SEED,
            image_id_bytes,
        ),
        GuestMode::VerifyAssumptionExplicitRoot => GuestInputHeader::new_verifying_explicit_root(
            statement.len(),
            workload_iterations,
            WORKLOAD_SEED,
            image_id_bytes,
        ),
        GuestMode::VerifyAssumptionExplicitRootTwice => {
            GuestInputHeader::new_verifying_explicit_root_twice(
                statement.len(),
                workload_iterations,
                WORKLOAD_SEED,
                image_id_bytes,
            )
        }
    }
    .map_err(|error| anyhow::anyhow!("cannot construct recursive guest header: {error}"))?;
    ensure!(
        header.mode() == mode,
        "constructed guest header mode drifted"
    );
    let mut input = Vec::with_capacity(header.encoded_input_length());
    input.extend_from_slice(&header.encode());
    input.extend_from_slice(statement);
    ensure!(
        input.len() == header.encoded_input_length(),
        "guest input length drifted"
    );

    let mut builder = ExecutorEnv::builder();
    builder
        .segment_limit_po2(segment_limit_po2)
        .write_slice(&input);
    if let Some(job_number) = povw_job_number {
        builder.povw((Default::default(), job_number));
    }
    if let Some(assumption) = assumption {
        // One cache entry is intentional even for the exact-twice mode. The
        // pinned matcher does not consume the cache, while each successful
        // guest call records one separate head in the authenticated output.
        builder.add_assumption(assumption);
    }
    builder
        .build()
        .context("cannot build recursive executor environment")
}

fn validate_session(
    session: &risc0_zkvm::SessionInfo,
    image_id: Digest,
    statement: &[u8],
    expected_mode: GuestMode,
) -> Result<()> {
    validate_session_semantics(session, image_id, statement, expected_mode)?;
    let segment_po2 = session
        .segments
        .iter()
        .map(|segment| segment.po2)
        .collect::<Vec<_>>();
    validate_profile_segment_sequence(&segment_po2)
}

fn validate_session_semantics(
    session: &risc0_zkvm::SessionInfo,
    image_id: Digest,
    statement: &[u8],
    expected_mode: GuestMode,
) -> Result<()> {
    ensure!(
        session.exit_code == ExitCode::Halted(0),
        "guest did not halt successfully"
    );
    ensure!(
        session.journal.bytes == statement,
        "guest journal differs from statement"
    );
    ensure!(
        !session.segments.is_empty(),
        "guest execution emitted no segments"
    );
    let claim = session
        .receipt_claim
        .as_ref()
        .context("guest execution did not return a receipt claim")?;
    let output = claim
        .output
        .as_value()
        .context("guest execution output is pruned")?
        .as_ref()
        .context("guest execution has no output")?;
    validate_assumption_inventory(&output.assumptions, image_id, statement, expected_mode)?;
    Ok(())
}

fn validate_assumption_inventory(
    assumptions: &MaybePruned<Assumptions>,
    image_id: Digest,
    statement: &[u8],
    expected_mode: GuestMode,
) -> Result<()> {
    let expected_count = expected_mode.assumption_count();
    if expected_count == 0 {
        ensure!(
            assumptions.is_empty(),
            "guest emitted one or more assumptions, expected 0"
        );
        return Ok(());
    }

    let assumptions = assumptions
        .as_value()
        .context("guest execution assumption list is pruned")?;
    ensure!(
        assumptions.len() == expected_count,
        "guest emitted {} assumptions, expected {expected_count}",
        assumptions.len()
    );
    let expected_root = expected_assumption_control_root(expected_mode)?
        .context("assumption-bearing guest mode has no expected control root")?;
    let expected_claim = ReceiptClaim::ok(image_id, statement.to_vec()).digest();

    for (index, assumption) in assumptions.iter().enumerate() {
        let recorded = assumption
            .as_value()
            .with_context(|| format!("guest assumption {index} is pruned"))?;
        ensure!(
            recorded.control_root == expected_root,
            "guest assumption {index} control root differs from its private mode"
        );
        ensure!(
            recorded.claim == expected_claim,
            "guest assumption {index} claim is not the exact same-program statement claim"
        );
    }
    Ok(())
}

fn validate_profile_segment_sequence(segment_po2: &[u32]) -> Result<()> {
    ensure!(
        segment_po2.iter().all(|po2| (15..=22).contains(po2)),
        "source segment po2 sequence {segment_po2:?} is outside profile range 15..=22"
    );
    Ok(())
}

fn expected_assumption_control_root(mode: GuestMode) -> Result<Option<Digest>> {
    match mode {
        GuestMode::Plain => Ok(None),
        GuestMode::VerifyAssumptionZeroRoot => Ok(Some(Digest::ZERO)),
        GuestMode::VerifyAssumptionExplicitRoot | GuestMode::VerifyAssumptionExplicitRootTwice => {
            let profile_root = crate::expected_inner_control_root()?;
            ensure!(
                ALLOWED_CONTROL_ROOT == profile_root,
                "pinned upstream assumption root differs from the B3 profile inner root"
            );
            Ok(Some(ALLOWED_CONTROL_ROOT))
        }
    }
}

fn unresolved_assumption_for_mode(
    image_id: Digest,
    statement: &[u8],
    mode: GuestMode,
) -> Result<Option<AssumptionReceipt>> {
    let Some(control_root) = expected_assumption_control_root(mode)? else {
        return Ok(None);
    };
    Ok(Some(
        Assumption {
            claim: ReceiptClaim::ok(image_id, statement.to_vec()).digest(),
            control_root,
        }
        .into(),
    ))
}

fn validate_family_shape(family: RecursiveFamily, segment_po2: &[u32]) -> Result<()> {
    planned_steps(family, segment_po2.len())?;
    for po2 in segment_po2 {
        validate_lift_po2(*po2)?;
    }
    Ok(())
}

fn validate_calibrated_source_shape(
    family: RecursiveFamily,
    expected_segment_po2: &[u32],
    observed_segment_po2: &[u32],
) -> Result<()> {
    validate_family_shape(family, expected_segment_po2)?;
    ensure!(
        observed_segment_po2 == expected_segment_po2,
        "recursive source preflight segment sequence differs from calibration"
    );
    Ok(())
}

fn validate_lift_control_id(
    expected_segment_po2: &[u32],
    segment_index: u32,
    control_id: &Digest,
) -> Result<()> {
    let expected_po2 = expected_segment_po2
        .get(segment_index as usize)
        .context("calibrated source segment index is out of range")?;
    let actual_po2 = normal_lift_segment_po2(control_id)?;
    ensure!(
        actual_po2 == *expected_po2,
        "source lift po2 {actual_po2} differs from calibrated po2 {expected_po2} at segment {segment_index}"
    );
    Ok(())
}

fn validate_lift_po2(po2: u32) -> Result<()> {
    ensure!(
        (15..=22).contains(&po2),
        "source segment po2 {po2} is outside profile range 15..=22"
    );
    Ok(())
}

fn validate_options(options: &ProverOpts) -> Result<()> {
    ensure!(
        options.hashfn == "poseidon2",
        "prover hash suite is not poseidon2"
    );
    ensure!(
        !options.dev_mode(),
        "prover options enabled development mode"
    );
    ensure!(
        !options.prove_guest_errors,
        "prover options enabled guest-error proving"
    );
    Ok(())
}

fn validate_top_level_receipt(
    receipt: &Receipt,
    image_id: Digest,
    statement: &[u8],
    terminal: CandidateTerminal,
    ctx: &VerifierContext,
) -> Result<()> {
    ensure!(
        receipt.journal.bytes == statement,
        "receipt journal differs from statement"
    );
    let expected_claim = ReceiptClaim::ok(image_id, statement.to_vec()).digest();
    ensure!(
        receipt.claim()?.digest() == expected_claim,
        "receipt claim is not exact OK"
    );
    let InnerReceipt::Succinct(inner) = &receipt.inner else {
        bail!("receipt is not succinct");
    };
    validate_candidate_terminal_shape(inner, terminal, &expected_claim)?;
    ensure_claim_has_empty_assumptions(inner.claim.as_value()?)?;
    receipt.verify_with_context(ctx, image_id)?;
    Ok(())
}

fn validate_step(
    step: &RecursiveStep,
    source: &risc0_zkvm::CompositeReceipt,
    assumption: Option<&SuccinctReceipt<ReceiptClaim>>,
    previous: &[RecursiveStep],
    ctx: &VerifierContext,
) -> Result<()> {
    ensure!(
        step.ordinal as usize == previous.len(),
        "step ordinal is not append-only"
    );
    step.receipt
        .verify_integrity_with_context(ctx)
        .context("intermediate succinct receipt verification failed")?;

    let expected_claim = match step.inputs {
        RecursiveInputs::Lift { segment_index } => {
            ensure!(
                step.operation == RecursiveOperation::Lift,
                "lift inputs use wrong operation"
            );
            let segment = source
                .segments
                .get(segment_index as usize)
                .context("lift source segment index is out of range")?;
            let po2 = normal_lift_segment_po2(&step.receipt.control_id)?;
            validate_candidate_terminal_shape(
                &step.receipt,
                CandidateTerminal::Lift(po2),
                &step.receipt.claim.digest(),
            )?;
            segment.claim.digest()
        }
        RecursiveInputs::Join {
            left_step,
            right_step,
        } => {
            ensure!(
                step.operation == RecursiveOperation::Join,
                "join inputs use wrong operation"
            );
            let left = step_receipt(previous, left_step)?;
            let right = step_receipt(previous, right_step)?;
            validate_candidate_terminal_shape(
                &step.receipt,
                CandidateTerminal::Join,
                &step.receipt.claim.digest(),
            )?;
            left.claim.join(&right.claim)?.digest()
        }
        RecursiveInputs::Resolve { conditional_step } => {
            ensure!(
                step.operation == RecursiveOperation::Resolve,
                "resolve inputs use wrong operation"
            );
            let conditional = step_receipt(previous, conditional_step)?;
            let assumption = assumption.context("resolve step has no assumption receipt")?;
            validate_candidate_terminal_shape(
                &step.receipt,
                CandidateTerminal::Resolve,
                &step.receipt.claim.digest(),
            )?;
            conditional
                .claim
                .as_value()?
                .resolve(&assumption.claim)?
                .digest()
        }
    };
    ensure!(
        step.receipt.claim.digest() == expected_claim,
        "step output claim does not match operation semantics"
    );
    Ok(())
}

fn validate_source_assumption_claim(
    source: &risc0_zkvm::CompositeReceipt,
    family: RecursiveFamily,
    assumption: Option<&SuccinctReceipt<ReceiptClaim>>,
) -> Result<()> {
    let final_segment = source
        .segments
        .last()
        .context("source composite has no final segment")?;
    let output = final_segment
        .claim
        .output
        .as_value()
        .context("source final-segment output is pruned")?
        .as_ref()
        .context("source final-segment claim has no output")?;

    match (family.uses_assumption(), assumption) {
        (false, None) => ensure!(
            output.assumptions.is_empty(),
            "unconditional source final segment unexpectedly has assumptions"
        ),
        (false, Some(_)) => bail!("unconditional source unexpectedly has an assumption receipt"),
        (true, None) => bail!("conditional source has no assumption receipt"),
        (true, Some(assumption)) => {
            let assumptions = output
                .assumptions
                .as_value()
                .context("source final-segment assumption list is pruned")?;
            ensure!(
                assumptions.len() == 1,
                "conditional source final segment has {} assumptions, expected one",
                assumptions.len()
            );
            let recorded = assumptions[0]
                .as_value()
                .context("source final-segment assumption is pruned")?;
            let expected_root = expected_assumption_control_root(family.guest_mode())?
                .context("assumption-bearing family has no expected control root")?;
            ensure!(
                recorded.control_root == expected_root,
                "source assumption control root differs from family semantics"
            );
            ensure!(
                recorded.claim == assumption.claim.digest(),
                "source assumption claim differs from the proved assumption receipt"
            );
        }
    }
    Ok(())
}

fn ensure_claim_has_empty_assumptions(claim: &ReceiptClaim) -> Result<()> {
    let output = claim
        .output
        .as_value()
        .context("final claim output is pruned")?
        .as_ref()
        .context("final claim has no output")?;
    ensure!(
        output.assumptions.is_empty(),
        "final claim still has assumptions"
    );
    Ok(())
}

fn step_receipt(steps: &[RecursiveStep], index: u32) -> Result<&SuccinctReceipt<ReceiptClaim>> {
    steps
        .get(index as usize)
        .map(|step| &step.receipt)
        .with_context(|| format!("ancestry step index {index} is out of range"))
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "embedded-method")]
    use bincode::Options as _;

    use super::*;

    #[cfg(feature = "embedded-method")]
    #[test]
    fn local_alternate_statement_final_branches_and_supplied_api_are_closed() {
        use LocalAlternateStatementBranch as B;
        assert_eq!(B::ResolveFixed22.family(), RecursiveFamily::TerminalResolve);
        assert_eq!(B::ResolveFixed22.recipe(), RecursiveCalibrationRecipe::Fixed22);
        assert_eq!(B::ResolveThenJoinJoin21.family(), RecursiveFamily::ResolveThenJoin);
        assert_eq!(B::ResolveThenJoinJoin21.recipe(), RecursiveCalibrationRecipe::Join21);
        for branch in [B::ResolveFixed22, B::ResolveThenJoinJoin21] {
            validate_supplied_assumption_family(branch.family()).unwrap();
            branch.recipe().validate_family(branch.family().as_str()).unwrap();
        }
        let _: fn(&LocalProver, &[u8], Digest, &[u8], RecursiveFamily, &RecursiveCalibrationReport, Receipt)
            -> Result<RecursiveOracle> = generate_recursive_oracle_with_assumption_unreplayed;
    }

    #[cfg(feature = "embedded-method")]
    #[test]
    fn local_alternate_statement_final_calibration_binds_before_observation() {
        use crate::recursive_calibration::derive_recursive_calibration_with_recipe;
        use LocalAlternateStatementBranch as B;
        let locked = crate::locked_negative_ancestry_guest::embedded_negative_ancestry_guest_pair().unwrap();
        let (elf, id) = locked.consumer();
        let canonical = canonical_test_statement(id, b"alternate-statement calibration seam");
        let statement = derive_b4_alternate_chain_domain_statement(&canonical, &id).unwrap();
        for branch in [B::ResolveFixed22, B::ResolveThenJoinJoin21] {
            // Only the execution observer is synthetic. The same production admission
            // helper and exact guest identity/report rederivation gates are exercised.
            let observe = |work| Ok(match branch {
                B::ResolveFixed22 => vec![19],
                B::ResolveThenJoinJoin21 => if work < 5 { vec![20] } else { vec![21, 19] },
            });
            let report = derive_recursive_calibration_with_recipe(elf, &digest_bytes(id), &statement,
                branch.family().as_str(), branch.recipe(), observe).unwrap();
            verify_local_final_calibration(&report, elf, id, &statement, branch, observe).unwrap();
            for (field, message) in [("elf", "recursive calibration ELF SHA-256 differs"),
                ("id", "recursive calibration image ID differs"),
                ("statement", "recursive calibration statement SHA-256 differs")] {
                let mut changed = report.clone();
                match field {
                    "elf" => changed.elf_sha256 = "00".repeat(32),
                    "id" => changed.image_id = "00".repeat(32),
                    "statement" => changed.statement_sha256 = hex::encode(Sha256::digest(&canonical)),
                    _ => unreachable!(),
                }
                let calls = std::cell::Cell::new(0);
                let error = verify_local_final_calibration(&changed, elf, id, &statement, branch, |_| {
                    calls.set(calls.get() + 1); anyhow::bail!("observer must not run")
                }).unwrap_err();
                assert_eq!(error.to_string(), message); assert_eq!(calls.get(), 0);
                verify_local_final_calibration(&report, elf, id, &statement, branch, observe).unwrap();
            }
            let mut changed = report.clone(); changed.workload_iterations += 1;
            let calls = std::cell::Cell::new(0);
            assert_eq!(verify_local_final_calibration(&changed, elf, id, &statement, branch, |work| {
                calls.set(calls.get() + 1); observe(work)
            }).unwrap_err().to_string(), "recursive calibration report differs from deterministic rederivation");
            assert!(calls.get() > 0);
            verify_local_final_calibration(&report, elf, id, &statement, branch, observe).unwrap();
            let mut wrong_recipe = report.clone();
            wrong_recipe.segment_limit_po2 = if branch == B::ResolveFixed22 { 21 } else { 22 };
            let calls = std::cell::Cell::new(0);
            assert_eq!(verify_local_final_calibration(&wrong_recipe, elf, id, &statement, branch, |_| {
                calls.set(calls.get() + 1); anyhow::bail!("observer must not run")
            }).unwrap_err().to_string(), "recursive calibration segment ceiling is not the fixed B4 value");
            assert_eq!(calls.get(), 0);
            if branch == B::ResolveThenJoinJoin21 {
                let mut wrong_family = report.clone(); wrong_family.family = "terminal-join".to_owned();
                // Same recipe/cardinality: only the expected family guard decides.
                wrong_family.to_canonical_jcs_with_recipe(branch.recipe()).unwrap();
                assert_eq!(verify_local_final_calibration(&wrong_family, elf, id, &statement, branch, |_| {
                    calls.set(calls.get() + 1); anyhow::bail!("observer must not run")
                }).unwrap_err().to_string(), "recursive calibration family differs from the requested proof family");
                assert_eq!(calls.get(), 0);
            }
            verify_local_final_calibration(&report, elf, id, &statement, branch, observe).unwrap();
        }
    }

    #[cfg(feature = "embedded-method")]
    #[test]
    fn local_duplicate_admission_is_fixed_before_any_prover() {
        let locked = crate::locked_negative_ancestry_guest::embedded_negative_ancestry_guest_pair().unwrap();
        let canonical = canonical_test_statement(locked.consumer().1, b"local duplicate admission");
        assert!(admit_local_duplicate_assumption(&locked, b"bad", &[], &[], &[]).is_err());
        assert_eq!(admit_local_duplicate_assumption(&locked, &canonical, &[], &[], &[]).err().unwrap().to_string(),
            "authenticated case-9 recursive oracle is invalid");
        let _: fn(&crate::locked_negative_ancestry_guest::LockedGuestPairV1, &[u8], &[u8], &[u8], &[u8])
            -> Result<LocalDuplicateAssumptionInput> = admit_local_duplicate_assumption;
        let _: fn(&LocalDuplicateAssumptionInput, &LocalProver) -> Result<(Receipt, Receipt)> = LocalDuplicateAssumptionInput::prove;
        let _: fn(&LocalDuplicateAssumptionInput, &[u8], &[u8], &[u8])
            -> Result<(Receipt, Receipt)> = LocalDuplicateAssumptionInput::replay;
    }

    #[cfg(feature = "embedded-method")]
    #[test]
    fn local_duplicate_cached_attachments_require_count_and_full_bytes() {
        // Pure attachment comparison: the fixture seal is not a valid proof.
        let control = crate::expected_normal_lift_control_id(15).unwrap();
        let group = risc0_zkvm::recursion::MerkleGroup::new(vec![control]).unwrap();
        let suites = VerifierContext::default_hash_suites(); let suite = suites.get("poseidon2").unwrap();
        let inner = crate::receipt_oracle_wire::assemble_succinct_receipt(
            vec![0; eip_0045_reproduction::constants::PROOF_WORDS], control,
            MaybePruned::Value(ReceiptClaim::ok(Digest::ZERO, b"fixture".to_vec())),
            "poseidon2".to_owned(), Digest::ZERO,
            group.get_proof_by_index(0, suite.hashfn.as_ref())).unwrap();
        let original = Receipt::new(InnerReceipt::Succinct(inner), b"fixture".to_vec());
        let AssumptionReceipt::Proven(expected) = AssumptionReceipt::from(original.clone()) else { unreachable!() };
        let positive = || vec![expected.clone(), expected.clone()];
        require_duplicate_cached_receipts(&positive(), &expected).unwrap();
        for count in [0, 1, 3] {
            assert_eq!(require_duplicate_cached_receipts(&vec![expected.clone(); count], &expected).unwrap_err().to_string(),
                "local duplicate attachment count must be exactly two");
            require_duplicate_cached_receipts(&positive(), &expected).unwrap();
        }
        let mut changed = original.clone();
        let InnerReceipt::Succinct(inner) = &mut changed.inner else { unreachable!() };
        inner.seal[0] ^= 1;
        assert_eq!(original.claim().unwrap().digest(), changed.claim().unwrap().digest());
        let AssumptionReceipt::Proven(other) = AssumptionReceipt::from(changed) else { unreachable!() };
        for index in 0..2 {
            let mut actual = positive(); actual[index] = other.clone();
            assert_eq!(require_duplicate_cached_receipts(&actual, &expected).unwrap_err().to_string(),
                format!("local duplicate attachment {index} differs from original Case9 receipt"));
            require_duplicate_cached_receipts(&positive(), &expected).unwrap();
        }
    }

    #[cfg(feature = "embedded-method")]
    #[test]
    fn local_alternate_context_uses_only_locked_guest_and_program_field() {
        let locked = crate::locked_negative_ancestry_guest::embedded_negative_ancestry_guest_pair().unwrap();
        let (consumer_elf, consumer_id) = locked.consumer();
        let (elf, image_id) = locked.alternate();
        let canonical = canonical_test_statement(consumer_id, b"local alternate context");
        let statement = derive_b4_alternate_program_statement(&canonical, &consumer_id, &image_id).unwrap();
        let positive = || LocalAlternateProgramInput { elf, image_id, statement: statement.clone() };
        positive().require_locked_context(&locked, &canonical).unwrap();
        for fault in ["elf", "id", "coordinated-pair", "empty-elf", "other-field"] {
            let mut changed = positive();
            match fault {
                "elf" => changed.elf = consumer_elf,
                "id" => changed.image_id = consumer_id,
                "coordinated-pair" => { changed.elf = consumer_elf; changed.image_id = consumer_id; },
                "empty-elf" => changed.elf = &[],
                "other-field" => changed.statement[0] ^= 1,
                _ => unreachable!(),
            }
            if fault == "coordinated-pair" {
                assert_eq!(compute_image_id(changed.elf).unwrap(), changed.image_id);
            }
            assert_eq!(changed.require_locked_context(&locked, &canonical).unwrap_err().to_string(),
                if fault == "other-field" { "local alternate statement differs from program-ID-only derivation" }
                else { "local alternate producer differs from locked alternate guest" });
            positive().require_locked_context(&locked, &canonical).unwrap();
        }
        assert!(positive().require_locked_context(&locked, &statement).is_err());
    }

    #[cfg(feature = "embedded-method")]
    #[test]
    fn local_alternate_admission_rejects_unproved_inputs_before_prover() {
        let locked = crate::locked_negative_ancestry_guest::embedded_negative_ancestry_guest_pair().unwrap();
        let canonical = canonical_test_statement(locked.consumer().1, b"local alternate admission");
        assert!(admit_local_alternate_program(&locked, b"bad", &[], &[], &[]).is_err());
        assert_eq!(admit_local_alternate_program(&locked, &canonical, &[], &[], &[]).err().unwrap().to_string(),
            "authenticated case-9 recursive oracle is invalid");
        let _: fn(&crate::locked_negative_ancestry_guest::LockedGuestPairV1, &[u8], &[u8], &[u8], &[u8])
            -> Result<LocalAlternateProgramInput> = admit_local_alternate_program;
        let _: fn(&LocalAlternateProgramInput, &LocalProver) -> Result<Receipt> = LocalAlternateProgramInput::prove;
        let statement = derive_b4_alternate_program_statement(&canonical, &locked.consumer().1, &locked.alternate().1).unwrap();
        let admitted = LocalAlternateProgramInput { elf: locked.alternate().0, image_id: locked.alternate().1, statement };
        assert!(admitted.replay(&[], &[]).is_err());
    }

    #[cfg(feature = "embedded-method")]
    #[test]
    fn local_ancestry_shared_admission_is_closed_before_proving() {
        let locked = crate::locked_negative_ancestry_guest::embedded_negative_ancestry_guest_pair().unwrap();
        let (_, image_id) = locked.consumer();
        let statement = canonical_test_statement(image_id, b"local admission fixture");
        assert!(admit_local_shared_assumption(&locked, b"bad statement", &[], &[], &[]).is_err());
        let error = admit_local_shared_assumption(&locked, &statement, &[], &[], &[]).err().unwrap();
        assert_eq!(error.to_string(), "authenticated case-9 recursive oracle is invalid");
        let direct = LocalSharedAssumptionInput { elf: locked.consumer().0, image_id, statement };
        assert!(direct.replay(&[], &[]).is_err());
        // This local type cannot carry a campaign token, selector or supplied proof recipe.
        let _: fn(&crate::locked_negative_ancestry_guest::LockedGuestPairV1, &[u8], &[u8], &[u8], &[u8])
            -> Result<LocalSharedAssumptionInput> = admit_local_shared_assumption;
        let _: fn(&LocalSharedAssumptionInput, &LocalProver) -> Result<Receipt> = LocalSharedAssumptionInput::prove;
    }

    #[cfg(feature = "embedded-method")]
    #[test]
    fn local_ancestry_shared_full_receipt_bytes_include_outer_metadata() {
        // Codec-only fixture: no cryptographic validity is asserted.
        let control_id = crate::expected_normal_lift_control_id(15).unwrap();
        let group = risc0_zkvm::recursion::MerkleGroup::new(vec![control_id]).unwrap();
        let suites = VerifierContext::default_hash_suites();
        let suite = suites.get("poseidon2").unwrap();
        let inner = crate::receipt_oracle_wire::assemble_succinct_receipt(
            vec![0; eip_0045_reproduction::constants::PROOF_WORDS],
            control_id,
            MaybePruned::Value(ReceiptClaim::ok(Digest::ZERO, b"fixture".to_vec())),
            "poseidon2".to_owned(), Digest::ZERO,
            group.get_proof_by_index(0, suite.hashfn.as_ref()),
        ).unwrap();
        let original = Receipt::new(InnerReceipt::Succinct(inner), b"fixture".to_vec());
        let bytes = require_local_receipt_byte_identity(&original, &original.clone()).unwrap();
        assert_eq!(bytes, borsh::to_vec(&original).unwrap());
        let mut changed = original.clone();
        changed.metadata.verifier_parameters = flip_first_digest_bit(original.metadata.verifier_parameters);
        assert_eq!(original.claim().unwrap().digest(), changed.claim().unwrap().digest());
        assert_eq!(borsh::to_vec(&original.inner).unwrap(), borsh::to_vec(&changed.inner).unwrap());
        assert_eq!(require_local_receipt_byte_identity(&original, &changed).unwrap_err().to_string(),
            "local shared assumption full Receipt bytes changed");
    }

    #[test]
    fn explicit_recipe_oracle_rejects_wrong_family_before_execution() {
        let report = RecursiveCalibrationReport {
            schema: crate::recursive_calibration::RECURSIVE_CALIBRATION_SCHEMA.to_owned(),
            lifecycle: crate::recursive_calibration::RECURSIVE_CALIBRATION_LIFECYCLE.to_owned(),
            elf_sha256: "00".repeat(32), image_id: "00".repeat(32), statement_sha256: "00".repeat(32),
            family: "terminal-resolve".to_owned(), segment_limit_po2: 21,
            workload_iterations: 0, assumption_workload_iterations: 0, segment_po2: vec![21],
        };
        let prover = LocalProver::new("recipe-family-preflight");
        let error = generate_recursive_oracle_with_recipe(&prover, b"not-elf", Digest::ZERO,
            b"not-statement", RecursiveFamily::TerminalResolve, &report,
            RecursiveCalibrationRecipe::Join21).err().expect("wrong family must fail before execution");
        assert_eq!(error.to_string(), "Join21 permits only terminal-join and resolve-then-join");
        let _: fn(&LocalProver, &[u8], Digest, &[u8], RecursiveFamily, &RecursiveCalibrationReport) -> Result<RecursiveOracle> = generate_recursive_oracle;
        let _: fn(&RecursiveOracle, &RecursiveCalibrationReport) -> Result<()> = validate_recursive_oracle_calibration;
    }

    #[test]
    #[allow(clippy::type_complexity)]
    fn fixed_b4_producer_and_assumption_api_signatures_are_closed() {
        let _: for<'a> fn(
            &LocalProver,
            B4AuthenticatedNegativeAncestryProducerSourceV1<'a>,
        ) -> Result<B4ProducedNegativeAncestryWitnessSetV1> =
            prove_b4_negative_ancestry_witness_set;
        let _: for<'a> fn(
            &LocalProver,
            B4AuthenticatedNegativeAncestryProducerSourceV2<'a>,
        ) -> Result<B4ProducedNegativeAncestryWitnessSetV1> =
            prove_b4_negative_ancestry_witness_set_v2;
        let _: fn(&LocalProver, &[u8], Digest, &[u8]) -> Result<Receipt> =
            prove_same_program_lift_15_assumption;
        let _: fn(
            &LocalProver,
            &[u8],
            Digest,
            &[u8],
            RecursiveFamily,
            &RecursiveCalibrationReport,
            Receipt,
        ) -> Result<RecursiveOracle> = generate_recursive_oracle_with_assumption_unreplayed;
    }

    #[test]
    fn plain_po2_18_terminal_source_api_and_target_are_closed() {
        let _: fn(&LocalProver, &[u8], Digest, &[u8]) -> Result<SegmentReceipt> =
            prove_plain_po2_18_segment;
        assert_eq!(PLAIN_PO2_18_TARGET_PO2, 18);
        assert_eq!(crate::EXECUTOR_SEGMENT_LIMIT_PO2, 23);
    }

    #[test]
    fn terminal_join_source_job_derivation_matches_pinned_little_endian_kat() {
        let image_id = Digest::from([0x11_u8; 32]);
        let statement = b"statement-v1";
        let statement_digest: [u8; 32] = Sha256::digest(statement).into();
        let outer_digest = derive_terminal_join_source_povw_job_digest(image_id, statement);

        let first = derive_terminal_join_source_povw_job_number(image_id, statement);
        let second = derive_terminal_join_source_povw_job_number(image_id, statement);

        assert_eq!(
            hex::encode(statement_digest),
            "1526411b353705d21dae17d63d80acc81525a6dcf0ce815a7526a9ae3d2414e7"
        );
        assert_eq!(
            hex::encode(outer_digest),
            "e2bfe230bbdd71d42f331f40205901d4fb79a5c77336303e713b07881a1f1e01"
        );
        assert_eq!(first, 0xd471_ddbb_30e2_bfe2);
        assert_eq!(second, first);
        assert_ne!(first, 0);
    }

    #[test]
    fn terminal_join_source_job_normalization_maps_only_zero_to_one() {
        assert_eq!(normalize_terminal_join_source_job_number(0), 1);
        assert_eq!(
            normalize_terminal_join_source_job_number(0x0123_4567_89ab_cdef),
            0x0123_4567_89ab_cdef
        );
    }

    #[test]
    fn terminal_join_source_job_binds_image_id_and_statement() {
        let image_id = Digest::from([0x11_u8; 32]);
        let statement = b"statement-v1";
        let expected = derive_terminal_join_source_povw_job_number(image_id, statement);

        assert_ne!(
            derive_terminal_join_source_povw_job_number(Digest::from([0x12_u8; 32]), statement),
            expected
        );
        assert_ne!(
            derive_terminal_join_source_povw_job_number(image_id, b"statement-v2"),
            expected
        );
    }

    #[test]
    fn only_terminal_join_receives_a_recursive_source_povw_job() {
        let image_id = Digest::from([0x11_u8; 32]);
        let statement = b"statement-v1";
        let expected = derive_terminal_join_source_povw_job_number(image_id, statement);

        assert_eq!(
            recursive_source_povw_job_number(RecursiveFamily::TerminalJoin, image_id, statement),
            Some(expected)
        );
        assert_eq!(
            recursive_source_povw_job_number(RecursiveFamily::TerminalResolve, image_id, statement),
            None
        );
        assert_eq!(
            recursive_source_povw_job_number(RecursiveFamily::ResolveThenJoin, image_id, statement),
            None
        );
    }

    fn terminal_join_nonce_fields(
        receipt_index: u32,
        log_is_zero: bool,
        job: u64,
        segment: u32,
    ) -> TerminalJoinSourceNonceFields {
        TerminalJoinSourceNonceFields {
            receipt_index,
            log_is_zero,
            job,
            segment,
        }
    }

    #[test]
    fn terminal_join_source_nonce_pair_accepts_exact_indices_and_fields() {
        let job = 0xd471_ddbb_30e2_bfe2;
        let fields = [
            terminal_join_nonce_fields(0, true, job, 0),
            terminal_join_nonce_fields(1, true, job, 1),
        ];

        validate_terminal_join_source_nonce_fields(job, &fields).unwrap();
    }

    #[test]
    fn terminal_join_source_nonce_pair_rejects_wrong_receipt_index() {
        let job = 0xd471_ddbb_30e2_bfe2;
        let fields = [
            terminal_join_nonce_fields(0, true, job, 0),
            terminal_join_nonce_fields(2, true, job, 1),
        ];

        assert!(validate_terminal_join_source_nonce_fields(job, &fields).is_err());
    }

    #[test]
    fn terminal_join_source_nonce_pair_rejects_nonzero_work_log() {
        let job = 0xd471_ddbb_30e2_bfe2;
        let fields = [
            terminal_join_nonce_fields(0, true, job, 0),
            terminal_join_nonce_fields(1, false, job, 1),
        ];

        assert!(validate_terminal_join_source_nonce_fields(job, &fields).is_err());
    }

    #[test]
    fn terminal_join_source_nonce_pair_rejects_duplicate_default_and_swapped_fields() {
        let job = 0xd471_ddbb_30e2_bfe2;
        let duplicate_default = [
            terminal_join_nonce_fields(0, true, 0, 0),
            terminal_join_nonce_fields(1, true, 0, 0),
        ];
        let swapped = [
            terminal_join_nonce_fields(0, true, job, 1),
            terminal_join_nonce_fields(1, true, job, 0),
        ];

        assert!(validate_terminal_join_source_nonce_fields(job, &duplicate_default).is_err());
        assert!(validate_terminal_join_source_nonce_fields(job, &swapped).is_err());
    }

    #[test]
    fn terminal_join_source_nonce_pair_rejects_other_job_and_gap() {
        let job = 0xd471_ddbb_30e2_bfe2;
        let other_job = [
            terminal_join_nonce_fields(0, true, job, 0),
            terminal_join_nonce_fields(1, true, job + 1, 1),
        ];
        let gap = [
            terminal_join_nonce_fields(0, true, job, 0),
            terminal_join_nonce_fields(1, true, job, 2),
        ];

        assert!(validate_terminal_join_source_nonce_fields(job, &other_job).is_err());
        assert!(validate_terminal_join_source_nonce_fields(job, &gap).is_err());
    }

    #[test]
    fn terminal_join_source_nonce_pair_rejects_wrong_cardinality() {
        let job = 0xd471_ddbb_30e2_bfe2;
        let one = [terminal_join_nonce_fields(0, true, job, 0)];
        let three = [
            terminal_join_nonce_fields(0, true, job, 0),
            terminal_join_nonce_fields(1, true, job, 1),
            terminal_join_nonce_fields(2, true, job, 2),
        ];

        assert!(validate_terminal_join_source_nonce_fields(job, &one).is_err());
        assert!(validate_terminal_join_source_nonce_fields(job, &three).is_err());
    }

    #[cfg(feature = "b4-negative-ancestry-finalization")]
    #[test]
    fn fixed_b4_finalization_bridge_signature_is_closed() {
        let _: fn(
            &LocalProver,
            &eip_0045_reproduction::b4_negative_ancestry_authority::B4NegativeAncestrySourceAuthorityV1,
        ) -> Result<
            eip_0045_reproduction::b4_negative_ancestry_authority::B4NegativeAncestryWitnessCatalogAuthorityV1,
        > = prove_and_finalize_b4_negative_ancestry_witness_catalog;
        let _: fn(
            &LocalProver,
            &eip_0045_reproduction::b4_negative_ancestry_authority::B4NegativeAncestrySourceAuthorityV2,
        ) -> Result<
            eip_0045_reproduction::b4_negative_ancestry_authority::B4NegativeAncestryWitnessCatalogAuthorityV2,
        > = prove_and_finalize_b4_negative_ancestry_witness_catalog_v2;
    }

    #[test]
    fn v2_producer_has_no_v1_authority_conversion_or_external_selectors() {
        let production = include_str!("recursive.rs")
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .unwrap();
        for forbidden in [
            ["From<B4NegativeAncestrySourceAuthorityV2", ">"].concat(),
            ["Into<B4NegativeAncestrySourceAuthorityV1", ">"].concat(),
            [
                "B4AuthenticatedNegativeAncestryProducerSourceV2",
                "::into_v1",
            ]
            .concat(),
            ["prove_b4_negative_ancestry_witness_set_v2", "("].concat() + "prover, source.into",
        ] {
            assert!(
                !production.contains(&forbidden),
                "V2 producer contains forbidden authority conversion {forbidden}"
            );
        }
        let v2_boundary = production
            .split("pub fn prove_b4_negative_ancestry_witness_set_v2")
            .nth(1)
            .unwrap()
            .split("fn prove_b4_negative_ancestry_witness_set_from_authenticated_view")
            .next()
            .unwrap();
        for forbidden in [
            "statement:",
            "elf:",
            "image_id:",
            "family:",
            "segment",
            "terminal",
            "Path",
            "receipt",
            "packet",
        ] {
            assert!(
                !v2_boundary.contains(forbidden),
                "V2 producer boundary accepts forbidden selector {forbidden}"
            );
        }
    }

    #[cfg(feature = "b4-negative-ancestry-publication")]
    #[test]
    fn fixed_b4_publication_bridge_signature_is_closed() {
        let _: fn(
            &LocalProver,
            &eip_0045_reproduction::b4_negative_ancestry_authority::B4NegativeAncestrySourceAuthorityV1,
            &std::path::Path,
        ) -> Result<
            eip_0045_reproduction::b4_negative_ancestry_authority::B4NegativeAncestryWitnessCatalogAuthorityV1,
        > = prove_finalize_and_publish_b4_negative_ancestry_witness_catalog;
    }

    #[test]
    fn supplied_assumption_family_rejects_terminal_join() {
        assert!(validate_supplied_assumption_family(RecursiveFamily::TerminalJoin).is_err());
        assert!(validate_supplied_assumption_family(RecursiveFamily::TerminalResolve).is_ok());
        assert!(validate_supplied_assumption_family(RecursiveFamily::ResolveThenJoin).is_ok());
    }

    #[cfg(feature = "embedded-method")]
    fn canonical_test_statement(image_id: Digest, payload: &[u8]) -> Vec<u8> {
        let mut statement = Vec::with_capacity(
            eip_0045_reproduction::constants::STATEMENT_PREFIX_BYTES + payload.len(),
        );
        statement.extend_from_slice(eip_0045_reproduction::constants::ERGO_STATEMENT_DOMAIN);
        statement.push(0x01);
        statement.extend_from_slice(&[0x11; 32]);
        statement.extend_from_slice(&[0x22; 32]);
        statement.extend_from_slice(image_id.as_bytes());
        statement.extend_from_slice(&[0x33; 32]);
        statement.extend_from_slice(
            &u32::try_from(payload.len())
                .expect("test payload length must fit u32")
                .to_le_bytes(),
        );
        statement.extend_from_slice(payload);
        validate_ergo_statement_v1(&statement, &image_id)
            .expect("test statement must be canonical");
        statement
    }

    #[test]
    fn canonical_terminal_join_plan_is_exact() {
        assert_eq!(
            planned_steps(RecursiveFamily::TerminalJoin, 2).unwrap(),
            vec![
                PlannedStep {
                    operation: RecursiveOperation::Lift,
                    inputs: RecursiveInputs::Lift { segment_index: 0 },
                },
                PlannedStep {
                    operation: RecursiveOperation::Lift,
                    inputs: RecursiveInputs::Lift { segment_index: 1 },
                },
                PlannedStep {
                    operation: RecursiveOperation::Join,
                    inputs: RecursiveInputs::Join {
                        left_step: 0,
                        right_step: 1,
                    },
                },
            ]
        );
    }

    #[test]
    fn terminal_resolve_plan_is_exact() {
        assert_eq!(
            planned_steps(RecursiveFamily::TerminalResolve, 1).unwrap(),
            vec![
                PlannedStep {
                    operation: RecursiveOperation::Lift,
                    inputs: RecursiveInputs::Lift { segment_index: 0 },
                },
                PlannedStep {
                    operation: RecursiveOperation::Resolve,
                    inputs: RecursiveInputs::Resolve {
                        conditional_step: 0,
                    },
                },
            ]
        );
    }

    #[test]
    fn resolve_then_join_plan_has_real_resolve_ancestry_and_join_terminal() {
        let plan = planned_steps(RecursiveFamily::ResolveThenJoin, 2).unwrap();
        assert_eq!(plan.last().unwrap().operation, RecursiveOperation::Join);
        assert_eq!(
            plan[2],
            PlannedStep {
                operation: RecursiveOperation::Resolve,
                inputs: RecursiveInputs::Resolve {
                    conditional_step: 1,
                },
            }
        );
        assert_eq!(
            plan[3],
            PlannedStep {
                operation: RecursiveOperation::Join,
                inputs: RecursiveInputs::Join {
                    left_step: 0,
                    right_step: 2,
                },
            }
        );
    }

    #[test]
    fn family_segment_cardinality_is_closed() {
        assert!(planned_steps(RecursiveFamily::TerminalJoin, 1).is_err());
        assert!(planned_steps(RecursiveFamily::TerminalJoin, 3).is_err());
        assert!(planned_steps(RecursiveFamily::TerminalResolve, 2).is_err());
        assert!(planned_steps(RecursiveFamily::ResolveThenJoin, 1).is_err());
        assert!(planned_steps(RecursiveFamily::ResolveThenJoin, 3).is_err());
    }

    #[test]
    fn calibrated_source_sequence_is_byte_exact_not_count_only() {
        assert!(
            validate_calibrated_source_shape(RecursiveFamily::TerminalJoin, &[22, 19], &[22, 19])
                .is_ok()
        );
        assert!(
            validate_calibrated_source_shape(RecursiveFamily::TerminalJoin, &[22, 19], &[21, 20])
                .is_err()
        );
        assert!(
            validate_calibrated_source_shape(RecursiveFamily::TerminalResolve, &[18], &[18, 18])
                .is_err()
        );
    }

    #[test]
    fn strict_shape_gate_rejects_the_calibrators_undersized_final_observation() {
        assert!(validate_profile_segment_sequence(&[22, 15]).is_ok());
        assert!(validate_profile_segment_sequence(&[22, 14]).is_err());
        assert!(validate_profile_segment_sequence(&[14, 22]).is_err());
        assert!(validate_profile_segment_sequence(&[22, 23]).is_err());
    }

    #[cfg(feature = "embedded-method")]
    #[test]
    #[ignore = "runs the pinned zkVM executor at the real terminal-join calibration boundary"]
    fn pinned_guest_calibration_observer_returns_the_raw_undersized_final_segment() {
        let elf = eip_0045_methods::EIP_0045_GUEST_ELF;
        let image_id = compute_image_id(elf).unwrap();
        let mut statement =
            Vec::with_capacity(eip_0045_reproduction::constants::STATEMENT_PREFIX_BYTES);
        statement.extend_from_slice(eip_0045_reproduction::constants::ERGO_STATEMENT_DOMAIN);
        statement.push(0x01);
        statement.extend_from_slice(&[0x11; 32]);
        statement.extend_from_slice(&[0x22; 32]);
        statement.extend_from_slice(image_id.as_bytes());
        statement.extend_from_slice(&[0x33; 32]);
        statement.extend_from_slice(&0_u32.to_le_bytes());
        assert_eq!(
            statement.len(),
            eip_0045_reproduction::constants::STATEMENT_PREFIX_BYTES
        );

        let segment_po2 = observe_recursive_calibration_shape(
            &LocalProver::new("eip-0045-recursive-calibration-regression"),
            elf,
            image_id,
            &statement,
            RecursiveFamily::TerminalJoin,
            RECURSIVE_CALIBRATION_SEGMENT_LIMIT_PO2,
            109_184,
        )
        .unwrap();
        assert_eq!(segment_po2, vec![22, 14]);
    }

    #[cfg(feature = "embedded-method")]
    #[test]
    #[ignore = "runs the pinned zkVM executor against the duplicate-assumption guest mode"]
    fn pinned_guest_explicit_root_twice_uses_one_cache_and_emits_two_heads() {
        let elf = eip_0045_methods::EIP_0045_GUEST_ELF;
        let image_id = compute_image_id(elf).unwrap();
        let statement = canonical_test_statement(image_id, b"row-154");
        let mode = GuestMode::VerifyAssumptionExplicitRootTwice;
        let prover = LocalProver::new("eip-0045-explicit-root-twice-regression");
        let assumption = unresolved_assumption_for_mode(image_id, &statement, mode).unwrap();
        let session = prover
            .execute(
                build_env(
                    &statement,
                    image_id,
                    mode,
                    crate::EXECUTOR_SEGMENT_LIMIT_PO2,
                    0,
                    assumption,
                )
                .unwrap(),
                elf,
            )
            .unwrap();

        validate_session_semantics(&session, image_id, &statement, mode).unwrap();
        let twice_po2 = session
            .segments
            .iter()
            .map(|segment| segment.po2)
            .collect::<Vec<_>>();
        let once_mode = GuestMode::VerifyAssumptionExplicitRoot;
        let once_session = prover
            .execute(
                build_env(
                    &statement,
                    image_id,
                    once_mode,
                    crate::EXECUTOR_SEGMENT_LIMIT_PO2,
                    0,
                    unresolved_assumption_for_mode(image_id, &statement, once_mode).unwrap(),
                )
                .unwrap(),
                elf,
            )
            .unwrap();
        validate_session_semantics(&once_session, image_id, &statement, once_mode).unwrap();
        let once_po2 = once_session
            .segments
            .iter()
            .map(|segment| segment.po2)
            .collect::<Vec<_>>();
        assert_eq!(twice_po2, once_po2);
        assert_eq!(
            twice_po2,
            vec![16],
            "diagnostic expectation for the row-154 source shape"
        );

        let output = session
            .receipt_claim
            .as_ref()
            .unwrap()
            .output
            .as_value()
            .unwrap()
            .as_ref()
            .unwrap();
        let assumptions = output.assumptions.as_value().unwrap();
        assert_eq!(assumptions.len(), 2);
        let expected_claim = ReceiptClaim::ok(image_id, statement).digest();
        for assumption in assumptions.iter() {
            let recorded = assumption.as_value().unwrap();
            assert_eq!(recorded.claim, expected_claim);
            assert_eq!(recorded.control_root, ALLOWED_CONTROL_ROOT);
        }
    }

    #[cfg(feature = "embedded-method")]
    #[test]
    #[ignore = "proves the pinned duplicate-assumption composite and lift"]
    fn pinned_guest_explicit_root_twice_proves_duplicate_heads_and_lift() -> Result<()> {
        let prover = LocalProver::new("eip-0045-explicit-root-twice-proof-regression");
        let elf = eip_0045_methods::EIP_0045_GUEST_ELF;
        let image_id = compute_image_id(elf)?;
        let statement = canonical_test_statement(image_id, b"row-154");
        let ctx = VerifierContext::default().with_dev_mode(false);
        let succinct_opts = ProverOpts::succinct()
            .with_dev_mode(false)
            .with_prove_guest_errors(false);
        validate_options(&succinct_opts)?;

        // Prove exactly one unconditional same-program receipt for the host cache.
        let assumption_info = prover.prove_with_ctx(
            build_env(
                &statement,
                image_id,
                GuestMode::Plain,
                crate::EXECUTOR_SEGMENT_LIMIT_PO2,
                0,
                None,
            )?,
            &ctx,
            elf,
            &succinct_opts,
        )?;
        ensure!(
            assumption_info.work_receipt.is_none(),
            "assumption proof returned work"
        );
        assumption_info
            .receipt
            .verify_with_context(&ctx, image_id)?;
        let InnerReceipt::Succinct(assumption_inner) = &assumption_info.receipt.inner else {
            bail!("assumption proof is not succinct");
        };
        let assumption_po2 = normal_lift_segment_po2(&assumption_inner.control_id)?;
        validate_top_level_receipt(
            &assumption_info.receipt,
            image_id,
            &statement,
            CandidateTerminal::Lift(assumption_po2),
            &ctx,
        )?;

        let authenticated_case9_assumption = AuthenticatedCase9AssumptionReceipt {
            receipt: assumption_info.receipt.clone(),
        };
        let witness = prove_duplicate_assumption_lift_witness(
            &prover,
            elf,
            image_id,
            &statement,
            &authenticated_case9_assumption,
        )?;

        // The typed witness retains the transient source so the one-cache/two-
        // attachment invariant remains directly auditable.
        let cached: AssumptionReceipt = assumption_info.receipt.clone().into();
        let AssumptionReceipt::Proven(expected_cached_inner) = &cached else {
            bail!("proved assumption converted to an unresolved cache entry");
        };
        let expected_cached_bytes = borsh::to_vec(expected_cached_inner)?;
        let InnerReceipt::Composite(source) = &witness.source_receipt().inner else {
            bail!("duplicate source proof is not composite");
        };
        assert_eq!(source.segments.len(), 1);
        assert_eq!(source.assumption_receipts.len(), 2);
        for actual in &source.assumption_receipts {
            assert_eq!(borsh::to_vec(actual)?, expected_cached_bytes);
        }

        // CompositeReceipt::claim() removes assumptions resolved by attached
        // receipts. Inspect the authenticated raw segment claim instead.
        let output = source.segments[0]
            .claim
            .output
            .as_value()
            .context("duplicate source output is pruned")?
            .as_ref()
            .context("duplicate source has no output")?;
        validate_assumption_inventory(
            &output.assumptions,
            image_id,
            &statement,
            GuestMode::VerifyAssumptionExplicitRootTwice,
        )?;

        let lifted = witness.lifted_receipt();
        lifted.verify_integrity_with_context(&ctx)?;
        let conditional_claim = source.segments[0].claim.digest();
        assert_eq!(lifted.claim.digest(), conditional_claim);
        assert_eq!(normal_lift_segment_po2(&lifted.control_id)?, 16);
        let checked_raw_seal = validate_candidate_terminal_shape(
            &lifted,
            CandidateTerminal::Lift(16),
            &conditional_claim,
        )?;
        assert_eq!(witness.raw_seal(), checked_raw_seal);
        assert_eq!(
            witness.raw_seal().len(),
            eip_0045_reproduction::constants::PROOF_BYTES
        );

        let decoded: SuccinctReceipt<ReceiptClaim> =
            crate::receipt_oracle_bincode_options().deserialize(witness.receipt_oracle())?;
        assert_eq!(decoded.claim.digest(), conditional_claim);
        assert_eq!(decoded.get_seal_bytes(), witness.raw_seal());
        decoded.verify_integrity_with_context(&ctx)?;
        assert_eq!(
            crate::receipt_oracle_bincode_options().serialize(&decoded)?,
            witness.receipt_oracle()
        );
        assert!(witness.receipt_oracle().len() <= crate::CANDIDATE_RECEIPT_ORACLE_MAX_BYTES);
        Ok(())
    }

    #[test]
    fn every_lift_control_id_is_checked_against_its_calibrated_position() {
        let po2_19 = crate::expected_normal_lift_control_id(19).unwrap();
        let po2_22 = crate::expected_normal_lift_control_id(22).unwrap();

        assert!(validate_lift_control_id(&[22, 19], 0, &po2_22).is_ok());
        assert!(validate_lift_control_id(&[22, 19], 1, &po2_19).is_ok());
        assert!(validate_lift_control_id(&[22, 19], 0, &po2_19).is_err());
        assert!(validate_lift_control_id(&[22, 19], 2, &po2_19).is_err());
        assert!(validate_lift_control_id(&[22, 19], 1, &Digest::ZERO).is_err());
    }

    #[test]
    fn family_names_round_trip_and_terminal_mapping_is_exact() {
        for family in [
            RecursiveFamily::TerminalJoin,
            RecursiveFamily::TerminalResolve,
            RecursiveFamily::ResolveThenJoin,
        ] {
            assert_eq!(family.as_str().parse::<RecursiveFamily>().unwrap(), family);
        }
        assert_eq!(
            RecursiveFamily::TerminalJoin.terminal(),
            CandidateTerminal::Join
        );
        assert_eq!(
            RecursiveFamily::TerminalResolve.terminal(),
            CandidateTerminal::Resolve
        );
        assert_eq!(
            RecursiveFamily::ResolveThenJoin.terminal(),
            CandidateTerminal::Join
        );
        assert_eq!(RecursiveFamily::TerminalJoin.guest_mode(), GuestMode::Plain);
        assert_eq!(
            RecursiveFamily::TerminalResolve.guest_mode(),
            GuestMode::VerifyAssumptionExplicitRoot
        );
        assert_eq!(
            RecursiveFamily::ResolveThenJoin.guest_mode(),
            GuestMode::VerifyAssumptionZeroRoot
        );
        assert_eq!(
            RecursiveFamily::TerminalJoin.assumption_root_semantics(),
            "none"
        );
        assert_eq!(
            RecursiveFamily::TerminalResolve.assumption_root_semantics(),
            "explicit-allowed-control-root"
        );
        assert_eq!(
            RecursiveFamily::ResolveThenJoin.assumption_root_semantics(),
            "zero-root-self-composition"
        );
    }

    #[test]
    fn assumption_root_mapping_is_exact_and_bound_to_b3() {
        assert_eq!(
            expected_assumption_control_root(GuestMode::Plain).unwrap(),
            None
        );
        assert_eq!(
            expected_assumption_control_root(GuestMode::VerifyAssumptionZeroRoot).unwrap(),
            Some(Digest::ZERO)
        );
        assert_eq!(
            expected_assumption_control_root(GuestMode::VerifyAssumptionExplicitRoot).unwrap(),
            Some(ALLOWED_CONTROL_ROOT)
        );
        assert_eq!(
            expected_assumption_control_root(GuestMode::VerifyAssumptionExplicitRootTwice).unwrap(),
            Some(ALLOWED_CONTROL_ROOT)
        );
        assert_eq!(
            ALLOWED_CONTROL_ROOT,
            crate::expected_inner_control_root().unwrap()
        );
    }

    #[test]
    fn execute_only_assumption_cache_uses_the_guest_mode_root() {
        let image_id = Digest::from([7_u8; 32]);
        let statement = b"same-program-statement";
        let expected_claim = ReceiptClaim::ok(image_id, statement.to_vec()).digest();

        assert!(
            unresolved_assumption_for_mode(image_id, statement, GuestMode::Plain)
                .unwrap()
                .is_none()
        );
        for (mode, expected_root) in [
            (GuestMode::VerifyAssumptionZeroRoot, Digest::ZERO),
            (
                GuestMode::VerifyAssumptionExplicitRoot,
                ALLOWED_CONTROL_ROOT,
            ),
            (
                GuestMode::VerifyAssumptionExplicitRootTwice,
                ALLOWED_CONTROL_ROOT,
            ),
        ] {
            let Some(AssumptionReceipt::Unresolved(assumption)) =
                unresolved_assumption_for_mode(image_id, statement, mode).unwrap()
            else {
                panic!("execute-only cache did not contain one unresolved assumption");
            };
            assert_eq!(assumption.claim, expected_claim);
            assert_eq!(assumption.control_root, expected_root);
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn explicit_root_twice_inventory_is_ordered_revealed_and_exact() {
        use risc0_zkvm::{Assumptions, MaybePruned};

        fn inventory(heads: Vec<MaybePruned<Assumption>>) -> MaybePruned<Assumptions> {
            Assumptions(heads).into()
        }

        let image_id = Digest::from([7_u8; 32]);
        let statement = b"same-program-statement";
        let expected = Assumption {
            claim: ReceiptClaim::ok(image_id, statement.to_vec()).digest(),
            control_root: ALLOWED_CONTROL_ROOT,
        };
        let validate = |assumptions: &MaybePruned<Assumptions>| {
            validate_assumption_inventory(
                assumptions,
                image_id,
                statement,
                GuestMode::VerifyAssumptionExplicitRootTwice,
            )
        };

        assert!(
            validate_assumption_inventory(
                &inventory(Vec::new()),
                image_id,
                statement,
                GuestMode::Plain,
            )
            .is_ok()
        );
        assert!(
            validate_assumption_inventory(
                &inventory(vec![expected.clone().into()]),
                image_id,
                statement,
                GuestMode::VerifyAssumptionExplicitRoot,
            )
            .is_ok()
        );
        assert!(
            validate_assumption_inventory(
                &inventory(vec![expected.clone().into(), expected.clone().into()]),
                image_id,
                statement,
                GuestMode::VerifyAssumptionExplicitRoot,
            )
            .is_err()
        );
        assert!(
            validate_assumption_inventory(
                &inventory(vec![expected.clone().into()]),
                image_id,
                statement,
                GuestMode::Plain,
            )
            .is_err()
        );

        assert!(
            validate(&inventory(vec![
                expected.clone().into(),
                expected.clone().into(),
            ]))
            .is_ok()
        );
        assert!(
            validate(&inventory(Vec::new()))
                .unwrap_err()
                .to_string()
                .contains("guest emitted 0 assumptions, expected 2")
        );
        assert!(
            validate(&inventory(vec![expected.clone().into()]))
                .unwrap_err()
                .to_string()
                .contains("guest emitted 1 assumptions, expected 2")
        );
        assert!(
            validate(&inventory(vec![
                expected.clone().into(),
                expected.clone().into(),
                expected.clone().into(),
            ]))
            .unwrap_err()
            .to_string()
            .contains("guest emitted 3 assumptions, expected 2")
        );

        for index in 0..2 {
            let mut heads = vec![expected.clone(), expected.clone()];
            heads[index].claim = flip_first_digest_bit(expected.claim);
            let error = validate(&inventory(
                heads.into_iter().map(MaybePruned::Value).collect(),
            ))
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("guest assumption {index} claim"))
            );

            let mut heads = vec![expected.clone(), expected.clone()];
            heads[index].control_root = flip_first_digest_bit(expected.control_root);
            let error = validate(&inventory(
                heads.into_iter().map(MaybePruned::Value).collect(),
            ))
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("guest assumption {index} control root"))
            );

            let mut heads = vec![
                MaybePruned::Value(expected.clone()),
                MaybePruned::Value(expected.clone()),
            ];
            heads[index] = MaybePruned::Pruned(expected.digest());
            let error = validate(&inventory(heads)).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("guest assumption {index} is pruned"))
            );
        }

        let wrong_claim = Assumption {
            claim: flip_first_digest_bit(expected.claim),
            ..expected.clone()
        };
        assert!(
            validate(&inventory(vec![
                wrong_claim.clone().into(),
                wrong_claim.into(),
            ]))
            .is_err()
        );
        let wrong_root = Assumption {
            control_root: flip_first_digest_bit(expected.control_root),
            ..expected.clone()
        };
        assert!(
            validate(&inventory(vec![
                wrong_root.clone().into(),
                wrong_root.into(),
            ]))
            .is_err()
        );
        assert!(
            validate(&MaybePruned::Pruned(Digest::from([9_u8; 32])))
                .unwrap_err()
                .to_string()
                .contains("guest execution assumption list is pruned")
        );
    }

    #[test]
    fn case9_assumption_source_authentication_is_bounded_and_exactly_typed() {
        let image_id = Digest::from([0x44; 32]);
        let malformed =
            authenticate_case9_assumption_receipt_parts(&[], &[], b"statement", image_id)
                .err()
                .expect("malformed case-9 source must fail");
        assert!(
            malformed
                .to_string()
                .contains("authenticated case-9 recursive oracle is invalid")
        );

        let oversized = vec![0_u8; RECURSIVE_ORACLE_MAX_BYTES + 1];
        let error =
            authenticate_case9_assumption_receipt_parts(&oversized, &[], b"statement", image_id)
                .err()
                .expect("oversized case-9 source must fail");
        assert!(
            error
                .to_string()
                .contains("authenticated case-9 recursive oracle is invalid")
        );
        assert!(format!("{error:#}").contains("recursive ancestry oracle exceeds its byte limit"));
    }

    #[test]
    fn full_and_pruned_journal_forms_have_the_same_ok_claim_digest() {
        let image_id = Digest::from([11_u8; 32]);
        let statement = b"exact-journal-bytes";
        let full = ReceiptClaim::ok(image_id, statement.to_vec()).digest();
        let pruned = ReceiptClaim::ok(
            image_id,
            risc0_zkvm::MaybePruned::Pruned(statement.as_slice().digest()),
        )
        .digest();
        assert_eq!(full, pruned);
    }

    #[test]
    fn recursive_input_codec_round_trips_every_variant() {
        for inputs in [
            RecursiveInputs::Lift { segment_index: 7 },
            RecursiveInputs::Join {
                left_step: 1,
                right_step: 2,
            },
            RecursiveInputs::Resolve {
                conditional_step: 3,
            },
        ] {
            let encoded = borsh::to_vec(&inputs).unwrap();
            let decoded: RecursiveInputs = borsh::from_slice(&encoded).unwrap();
            assert_eq!(decoded, inputs);

            let mut trailing = encoded;
            trailing.push(0);
            assert!(borsh::from_slice::<RecursiveInputs>(&trailing).is_err());
        }
    }
}
