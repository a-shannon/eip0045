//! Validation and calibration primitives for the non-final candidate generator.

#[cfg(feature = "embedded-method")]
pub mod alternate_root_candidate;
#[cfg(feature = "b4-campaign-executor")]
pub(crate) mod b4_campaign_executor;
/// Fixed owned evidence and compiled fan-out for B4 negative ancestry.
pub mod b4_negative_ancestry_witness_set;
#[allow(dead_code, missing_docs)]
mod constants_artifact;
/// Bounded verifier for one complete non-final candidate export.
pub mod export;
#[cfg(feature = "embedded-method")]
mod locked_negative_ancestry_guest;
/// Local fixed Lift15 checkpoint acquisition, without campaign authority.
#[cfg(feature = "embedded-method")]
pub mod local_ancestry_shared_assumption;
/// Fixed locked-alternate-program Lift15 checkpoint, without campaign authority.
#[cfg(feature = "embedded-method")]
pub mod local_ancestry_alternate_program;
/// Local fixed duplicate-assumption checkpoint; not campaign authority.
#[cfg(feature = "embedded-method")]
pub mod local_ancestry_duplicate_assumption;
/// Local alternate-statement final branches reusing one retained shared Receipt.
#[cfg(feature = "embedded-method")]
pub mod local_ancestry_alternate_statement_final;
/// Deterministic construction and verification of the B3 profile package.
pub mod profile_freeze;
mod receipt_oracle_wire;
/// Candidate-only construction and replay of join/resolve receipt ancestries.
#[cfg(feature = "proof-generation")]
pub mod recursive;
/// Bounded ancestry wire codec and retained-byte comparison, without proving.
pub mod recursive_oracle;
/// Pure extraction of retained Case-9 direct receipt encodings, without proving.
pub mod local_case9_oracle_extraction;
/// Minimal canonical claim-algebra projection for recursive B4 ancestry.
#[cfg(feature = "proof-generation")]
pub mod recursive_ancestry;
/// Deterministic, create-only calibration records for recursive B4 families.
pub mod recursive_calibration;
/// Closed candidate export and strict replay for recursive receipt families.
#[cfg(feature = "proof-generation")]
pub mod recursive_export;
/// Create-only statement-bundle construction and strict verification.
pub mod statement_bundle;
#[cfg(feature = "b4-terminal-evidence-export")]
pub mod terminal_evidence_export;
#[cfg(feature = "b4-terminal-evidence-export")]
mod terminal_evidence_profile;
/// Semantic authentication of the fixed B4 terminal-fixture source shapes.
#[cfg(feature = "b4-terminal-fixture-generation")]
pub mod terminal_fixtures;
/// Create-only local terminal fixtures, without campaign or custody authority.
#[cfg(feature = "b4-terminal-fixture-generation")]
pub mod terminal_fixture_export;
/// Official-lineage composition for the fixed B4 terminal producer.
#[cfg(feature = "b4-terminal-source-lineage")]
pub mod terminal_lineage;

use anyhow::{Context, Result, bail, ensure};
use eip_0045_methods::{
    MAX_CALIBRATION_PO2 as METHODS_MAX_CALIBRATION_PO2,
    MAX_STATEMENT_BYTES as METHODS_MAX_STATEMENT_BYTES,
    MIN_CALIBRATION_PO2 as METHODS_MIN_CALIBRATION_PO2,
};
use risc0_core::field::baby_bear::{BabyBearElem, P as BABY_BEAR_MODULUS};
#[cfg(feature = "proof-generation")]
use risc0_zkvm::{ALLOWED_CONTROL_IDS, VerifierContext, recursion::MerkleGroup};
use risc0_zkvm::{
    ALLOWED_CONTROL_ROOT, Digest, ReceiptClaim, SuccinctReceipt, SuccinctReceiptVerifierParameters,
    sha::Digestible,
};

pub use eip_0045_reproduction::constants::{
    B4_ALTERNATE_CONTROL_ROOT_HEX as EXPECTED_ALTERNATE_CONTROL_ROOT_HEX,
    B4_ALTERNATE_OMITTED_CONTROL_ID_HEX as ALTERNATE_ROOT_OMITTED_CONTROL_ID_HEX,
    B4_ALTERNATE_VERIFIER_PARAMETERS_HEX as EXPECTED_ALTERNATE_VERIFIER_PARAMETERS_HEX,
};
use eip_0045_reproduction::constants::{
    DIGEST_BYTES, ERGO_STATEMENT_DOMAIN, MAX_APPLICATION_PAYLOAD_BYTES, MAX_SEGMENT_PO2,
    MAX_STATEMENT_BYTES, MIN_SEGMENT_PO2, PAYLOAD_LENGTH_PREFIX_BYTES, PROOF_BYTES, PROOF_WORDS,
    RISC0_INNER_CONTROL_ROOT_HEX, RISC0_JOIN_CONTROL_ID_HEX, RISC0_NORMAL_LIFT_CONTROL_IDS_HEX,
    RISC0_OUTER_PO2, RISC0_RESOLVE_CONTROL_ID_HEX, STATEMENT_PREFIX_BYTES,
};
pub use eip_0045_reproduction::receipt_oracle_codec::{
    RECEIPT_ORACLE_MAX_BYTES as CANDIDATE_RECEIPT_ORACLE_MAX_BYTES,
    RECEIPT_ORACLE_MAX_BYTES_U64 as CANDIDATE_RECEIPT_ORACLE_MAX_BYTES_U64,
    receipt_oracle_bincode_options,
};
pub use eip_0045_reproduction::seal::decode_seal_words;

/// Host-only executor ceiling used to prevent premature multi-segment splits.
///
/// This is deliberately one exponent above the profile's largest accepted
/// final segment. It is not written to the journal, receipt claim, or raw seal.
pub const EXECUTOR_SEGMENT_LIMIT_PO2: u32 = 23;

const _: () = {
    assert!(METHODS_MAX_STATEMENT_BYTES == MAX_STATEMENT_BYTES);
    assert!(METHODS_MIN_CALIBRATION_PO2 == MIN_SEGMENT_PO2 as u32);
    assert!(METHODS_MAX_CALIBRATION_PO2 == MAX_SEGMENT_PO2 as u32);
    assert!(EXECUTOR_SEGMENT_LIMIT_PO2 == METHODS_MAX_CALIBRATION_PO2 + 1);
    assert!(
        recursive_calibration::RECURSIVE_CALIBRATION_SEGMENT_LIMIT_PO2
            == METHODS_MAX_CALIBRATION_PO2
    );
    assert!(EXECUTOR_SEGMENT_LIMIT_PO2 <= 24);
};

/// Fixed recursion-circuit trace exponent carried by the raw succinct seal.
pub const EXPECTED_OUTER_PO2: u32 = RISC0_OUTER_PO2 as u32;
/// Candidate generator's deterministic workload seed.
pub const WORKLOAD_SEED: u64 = 0x4549_5030_3034_3501;
/// Exact upstream verifier-parameters digest for the pinned default context.
pub const EXPECTED_VERIFIER_PARAMETERS_HEX: &str =
    "ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013";
/// Exact upstream Poseidon2 allowed-control root bound by Manifest V1.
pub const EXPECTED_INNER_CONTROL_ROOT_HEX: &str = RISC0_INNER_CONTROL_ROOT_HEX;
/// Segment exponent used by the fixed alternate-root negative witness.
pub const ALTERNATE_ROOT_SEGMENT_PO2: u32 = 15;

const CONTROL_INCLUSION_PROOF_DEPTH: usize = 8;
const MIN_SEGMENT_CONTROL_INDEX: u32 = 5;
const JOIN_CONTROL_INDEX: u32 = 1;
const RESOLVE_CONTROL_INDEX: u32 = 22;
#[cfg(feature = "proof-generation")]
const STOCK_ALLOWED_CONTROL_COUNT: usize = 27;

/// Exact outer recursion-program family required from a candidate receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateTerminal {
    /// Normal RV32IM lift for one supported segment exponent.
    Lift(u32),
    /// Stock Poseidon2 `join.zkr` terminal.
    Join,
    /// Stock Poseidon2 `resolve.zkr` terminal.
    Resolve,
}

impl CandidateTerminal {
    fn expected_control(self) -> Result<(Digest, u32)> {
        match self {
            Self::Lift(segment_po2) => {
                validate_segment_po2(segment_po2)?;
                let index = MIN_SEGMENT_CONTROL_INDEX
                    .checked_add(segment_po2 - u32::from(MIN_SEGMENT_PO2))
                    .context("expected lift control-inclusion index overflowed")?;
                Ok((expected_normal_lift_control_id(segment_po2)?, index))
            }
            Self::Join => Ok((expected_join_control_id()?, JOIN_CONTROL_INDEX)),
            Self::Resolve => Ok((expected_resolve_control_id()?, RESOLVE_CONTROL_INDEX)),
        }
    }

    fn label(self) -> String {
        match self {
            Self::Lift(segment_po2) => format!("normal lift for segment po2 {segment_po2}"),
            Self::Join => "terminal join".to_owned(),
            Self::Resolve => "terminal resolve".to_owned(),
        }
    }
}

/// Fixed verifier contract for the valid alternate-root negative witness.
///
/// This contract is derived only from the pinned stock control-ID list. The
/// caller cannot choose, reorder, add, or remove IDs.
#[cfg(feature = "proof-generation")]
#[derive(Clone, Debug)]
pub struct AlternateControlRootProfile {
    control_ids: Vec<Digest>,
    control_root: Digest,
    verifier_parameters: SuccinctReceiptVerifierParameters,
    verifier_parameters_digest: Digest,
    terminal_control_id: Digest,
    terminal_control_index: u32,
}

#[cfg(feature = "proof-generation")]
impl AlternateControlRootProfile {
    /// Exact ordered control-ID set used by the alternate-root prover.
    #[must_use]
    pub fn control_ids(&self) -> &[Digest] {
        &self.control_ids
    }

    /// Poseidon2 Merkle root of the exact alternate control-ID set.
    #[must_use]
    pub const fn control_root(&self) -> Digest {
        self.control_root
    }

    /// Full trusted verifier parameters corresponding to `control_root`.
    #[must_use]
    pub const fn verifier_parameters(&self) -> &SuccinctReceiptVerifierParameters {
        &self.verifier_parameters
    }

    /// Digest carried by the alternate succinct receipt.
    #[must_use]
    pub const fn verifier_parameters_digest(&self) -> Digest {
        self.verifier_parameters_digest
    }

    /// Retained normal-lift po2-15 control ID.
    #[must_use]
    pub const fn terminal_control_id(&self) -> Digest {
        self.terminal_control_id
    }

    /// Unchanged stock leaf index of the retained terminal.
    #[must_use]
    pub const fn terminal_control_index(&self) -> u32 {
        self.terminal_control_index
    }
}

/// Derive the sole alternate-root profile used by B4.
///
/// The fixed construction removes only the final stock
/// `unwrap_povw.zkr` leaf. It proves that the normal lift at po2 15 remains at
/// the stock index and that both the root and verifier-parameter digest differ
/// from the initial profile.
///
/// # Errors
///
/// Returns an error if the pinned upstream list, omitted ID, terminal index,
/// Poseidon2 suite, Merkle root, or verifier parameters differ from the closed
/// construction.
#[cfg(feature = "proof-generation")]
pub fn alternate_control_root_profile() -> Result<AlternateControlRootProfile> {
    ensure!(
        ALLOWED_CONTROL_IDS.len() == STOCK_ALLOWED_CONTROL_COUNT,
        "pinned stock control-ID count changed"
    );
    let omitted = digest_from_hex(ALTERNATE_ROOT_OMITTED_CONTROL_ID_HEX)?;
    ensure!(
        ALLOWED_CONTROL_IDS.last() == Some(&omitted),
        "fixed alternate-root omitted ID is not the final stock control ID"
    );

    let control_ids = ALLOWED_CONTROL_IDS[..ALLOWED_CONTROL_IDS.len() - 1].to_vec();
    let terminal_control_id = expected_normal_lift_control_id(ALTERNATE_ROOT_SEGMENT_PO2)?;
    let terminal_index = control_ids
        .iter()
        .position(|control_id| *control_id == terminal_control_id)
        .context("alternate-root set does not retain the po2-15 lift")?;
    let terminal_control_index =
        u32::try_from(terminal_index).context("alternate terminal index does not fit u32")?;
    ensure!(
        terminal_control_index == MIN_SEGMENT_CONTROL_INDEX,
        "alternate-root construction changed the po2-15 terminal index"
    );

    let suites = VerifierContext::default_hash_suites();
    let suite = suites
        .get("poseidon2")
        .context("default verifier context has no Poseidon2 suite")?;
    let control_root = MerkleGroup::new(control_ids.clone())?.calc_root(suite.hashfn.as_ref());
    ensure!(
        control_root != ALLOWED_CONTROL_ROOT,
        "alternate-root construction reproduced the stock control root"
    );
    ensure!(
        control_root == digest_from_hex(EXPECTED_ALTERNATE_CONTROL_ROOT_HEX)?,
        "fixed alternate control root drifted"
    );

    let verifier_parameters = SuccinctReceiptVerifierParameters {
        control_root,
        inner_control_root: None,
        ..Default::default()
    };
    let verifier_parameters_digest = verifier_parameters.digest();
    ensure!(
        verifier_parameters_digest != digest_from_hex(EXPECTED_VERIFIER_PARAMETERS_HEX)?,
        "alternate-root verifier parameters reproduced the stock digest"
    );
    ensure!(
        verifier_parameters_digest == digest_from_hex(EXPECTED_ALTERNATE_VERIFIER_PARAMETERS_HEX)?,
        "fixed alternate verifier-parameter digest drifted"
    );

    Ok(AlternateControlRootProfile {
        control_ids,
        control_root,
        verifier_parameters,
        verifier_parameters_digest,
        terminal_control_id,
        terminal_control_index,
    })
}

const STATEMENT_VERSION_OFFSET: usize = ERGO_STATEMENT_DOMAIN.len();
const STATEMENT_CHAIN_DOMAIN_OFFSET: usize = STATEMENT_VERSION_OFFSET + 1;
const STATEMENT_PROFILE_ID_OFFSET: usize = STATEMENT_CHAIN_DOMAIN_OFFSET + DIGEST_BYTES;
const STATEMENT_PROGRAM_ID_OFFSET: usize = STATEMENT_PROFILE_ID_OFFSET + DIGEST_BYTES;
const STATEMENT_CONTRACT_ID_OFFSET: usize = STATEMENT_PROGRAM_ID_OFFSET + DIGEST_BYTES;
const STATEMENT_PAYLOAD_LENGTH_OFFSET: usize = STATEMENT_CONTRACT_ID_OFFSET + DIGEST_BYTES;
const STATEMENT_PAYLOAD_OFFSET: usize =
    STATEMENT_PAYLOAD_LENGTH_OFFSET + PAYLOAD_LENGTH_PREFIX_BYTES;

/// Validate the exact `ErgoStatementV1` byte grammar accepted by this
/// candidate generator.
///
/// The chain-domain, profile, and contract identifiers are opaque 32-byte
/// fields. The program identifier is profile-owned and must equal
/// `expected_program_id`. The payload length is little-endian and must describe
/// the complete remaining input without trailing bytes.
///
/// # Errors
///
/// Returns an error for a non-exact domain or version, a statement outside the
/// frozen length bounds, a program ID other than `expected_program_id`, an
/// oversized payload declaration, or any mismatch between the declared payload
/// length and exact end of input.
pub fn validate_ergo_statement_v1(statement: &[u8], expected_program_id: &Digest) -> Result<()> {
    ensure!(
        (STATEMENT_PREFIX_BYTES..=MAX_STATEMENT_BYTES).contains(&statement.len()),
        "ErgoStatementV1 has {} bytes, expected {STATEMENT_PREFIX_BYTES}..={MAX_STATEMENT_BYTES}",
        statement.len()
    );
    ensure!(
        STATEMENT_PAYLOAD_OFFSET == STATEMENT_PREFIX_BYTES,
        "compiled ErgoStatementV1 offsets disagree with the frozen prefix length"
    );
    ensure!(
        statement.starts_with(ERGO_STATEMENT_DOMAIN),
        "ErgoStatementV1 domain is not exact"
    );
    ensure!(
        statement[STATEMENT_VERSION_OFFSET] == 0x01,
        "ErgoStatementV1 version is not 0x01"
    );

    ensure!(
        &statement[STATEMENT_PROGRAM_ID_OFFSET..STATEMENT_CONTRACT_ID_OFFSET]
            == expected_program_id.as_bytes(),
        "ErgoStatementV1 program ID differs from the expected guest image ID"
    );

    let payload_length_bytes: [u8; PAYLOAD_LENGTH_PREFIX_BYTES] = statement
        [STATEMENT_PAYLOAD_LENGTH_OFFSET..STATEMENT_PAYLOAD_OFFSET]
        .try_into()
        .context("ErgoStatementV1 payload-length field is not exactly four bytes")?;
    let payload_length = usize::try_from(u32::from_le_bytes(payload_length_bytes))
        .context("ErgoStatementV1 payload length does not fit usize")?;
    ensure!(
        payload_length <= MAX_APPLICATION_PAYLOAD_BYTES,
        "ErgoStatementV1 payload declares {payload_length} bytes, maximum is {MAX_APPLICATION_PAYLOAD_BYTES}"
    );
    let expected_statement_length = STATEMENT_PREFIX_BYTES
        .checked_add(payload_length)
        .context("ErgoStatementV1 length arithmetic overflow")?;
    ensure!(
        statement.len() == expected_statement_length,
        "ErgoStatementV1 payload declares {payload_length} bytes but exact input length is {}",
        statement.len() - STATEMENT_PREFIX_BYTES
    );

    Ok(())
}

/// Derive the fixed B4 alternate-chain-domain statement.
///
/// The source must be an exact `ErgoStatementV1` for `expected_program_id`.
/// The result differs only at byte zero of the chain-domain identifier, where
/// the source byte is `XORed` with `0x01`.
///
/// # Errors
///
/// Returns an error if the source or result is not an exact statement for the
/// expected program, if the fixed mutation offset is unavailable, or if any
/// byte outside the one authorized byte changes.
pub fn derive_b4_alternate_chain_domain_statement(
    source: &[u8],
    expected_program_id: &Digest,
) -> Result<Vec<u8>> {
    validate_ergo_statement_v1(source, expected_program_id)
        .context("source alternate-chain-domain statement is invalid")?;
    let mut changed = source.to_vec();
    let changed_byte = changed
        .get_mut(STATEMENT_CHAIN_DOMAIN_OFFSET)
        .context("alternate-chain-domain byte zero is outside the statement")?;
    *changed_byte ^= 0x01;
    validate_ergo_statement_v1(&changed, expected_program_id)
        .context("derived alternate-chain-domain statement is invalid")?;
    require_only_statement_span_changed(
        source,
        &changed,
        STATEMENT_CHAIN_DOMAIN_OFFSET,
        STATEMENT_CHAIN_DOMAIN_OFFSET + 1,
        "alternate-chain-domain statement",
    )?;
    Ok(changed)
}

/// Derive the fixed B4 alternate-program statement.
///
/// The source must be an exact `ErgoStatementV1` for `source_program_id`.
/// The result replaces exactly the 32-byte program-ID field with
/// `alternate_program_id` and preserves every other byte.
///
/// # Errors
///
/// Returns an error if the source or result is not an exact statement for its
/// respective program, if the two program identities are equal, if the fixed
/// program span is unavailable, or if any byte outside that span changes.
pub fn derive_b4_alternate_program_statement(
    source: &[u8],
    source_program_id: &Digest,
    alternate_program_id: &Digest,
) -> Result<Vec<u8>> {
    validate_ergo_statement_v1(source, source_program_id)
        .context("source alternate-program statement is invalid")?;
    ensure!(
        source_program_id != alternate_program_id,
        "alternate program ID equals the source program ID"
    );
    let mut changed = source.to_vec();
    changed
        .get_mut(STATEMENT_PROGRAM_ID_OFFSET..STATEMENT_CONTRACT_ID_OFFSET)
        .context("alternate-program field is outside the statement")?
        .copy_from_slice(alternate_program_id.as_bytes());
    validate_ergo_statement_v1(&changed, alternate_program_id)
        .context("derived alternate-program statement is invalid")?;
    require_only_statement_span_changed(
        source,
        &changed,
        STATEMENT_PROGRAM_ID_OFFSET,
        STATEMENT_CONTRACT_ID_OFFSET,
        "alternate-program statement",
    )?;
    Ok(changed)
}

fn require_only_statement_span_changed(
    original: &[u8],
    changed: &[u8],
    start: usize,
    end: usize,
    label: &str,
) -> Result<()> {
    ensure!(
        original.len() == changed.len(),
        "{label} length differs from its source"
    );
    ensure!(
        start < end && end <= original.len(),
        "{label} authorized span is outside its source"
    );
    ensure!(
        original[..start] == changed[..start]
            && original[end..] == changed[end..]
            && original[start..end] != changed[start..end],
        "{label} did not change exactly its one authorized span"
    );
    Ok(())
}

/// Result of one execution observed during workload calibration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentObservation {
    /// Number of segments emitted by execution.
    pub segment_count: usize,
    /// Trace exponent when and only when exactly one segment was emitted.
    pub single_segment_po2: Option<u32>,
}

impl SegmentObservation {
    /// Construct an observation while enforcing the option/count relationship.
    ///
    /// # Errors
    ///
    /// Returns an error if `single_segment_po2` is present for a count other
    /// than one, or absent when the count is one.
    pub fn new(segment_count: usize, single_segment_po2: Option<u32>) -> Result<Self> {
        ensure!(
            (segment_count == 1) == single_segment_po2.is_some(),
            "single-segment po2 presence does not match segment count"
        );
        Ok(Self {
            segment_count,
            single_segment_po2,
        })
    }
}

/// Result of deterministic canonical calibration selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalCalibrationSelection {
    /// Iteration count selected by the prescribed ranking procedure.
    ///
    /// This is not a claim that no lower iteration count can yield the target
    /// shape. The procedure uses a monotone ranking as a selection convention;
    /// it does not establish that executions are globally monotone.
    pub workload_iterations: u32,
    /// Exact observation at `workload_iterations`.
    pub observation: SegmentObservation,
}

/// Select one exact iteration count for `target_po2` using the prescribed
/// monotone-ranking procedure.
///
/// The procedure first brackets with exponential growth, then binary-searches
/// under a *selection convention* that treats a lower observation as below and
/// a multi-segment or higher observation as above. It always requires the
/// selected observation to be exact. It neither proves nor claims that the
/// observed executions are globally monotone, so it must not be described as
/// finding a global minimum.
///
/// # Errors
///
/// Returns an error for an unsupported target, a malformed observation, an
/// above-target bracket endpoint, exhaustion of the `u32` search space, or any
/// error returned by `observe`.
pub fn select_canonical_iterations<F>(
    target_po2: u32,
    mut observe: F,
) -> Result<CanonicalCalibrationSelection>
where
    F: FnMut(u32) -> Result<SegmentObservation>,
{
    validate_segment_po2(target_po2)?;

    let zero = observe(0).context("failed to observe zero-workload execution")?;
    match classify(zero, target_po2)? {
        OrderingClass::Exact => {
            return Ok(CanonicalCalibrationSelection {
                workload_iterations: 0,
                observation: zero,
            });
        }
        OrderingClass::Above => bail!(
            "zero-workload execution already exceeds target po2 {target_po2}; target is unreachable"
        ),
        OrderingClass::Below => {}
    }

    let mut below = 0_u32;
    let mut high = 1_u32;
    let high_observation = loop {
        let observation = observe(high)
            .with_context(|| format!("failed to observe workload iteration count {high}"))?;
        match classify(observation, target_po2)? {
            OrderingClass::Below => {
                below = high;
                if high == u32::MAX {
                    bail!("u32 workload range exhausted below target po2 {target_po2}");
                }
                high = high.saturating_mul(2).max(high + 1);
            }
            OrderingClass::Exact | OrderingClass::Above => break observation,
        }
    };

    let mut upper_observation = high_observation;
    while below + 1 < high {
        let middle = below + (high - below) / 2;
        let observation = observe(middle)
            .with_context(|| format!("failed to observe workload iteration count {middle}"))?;
        match classify(observation, target_po2)? {
            OrderingClass::Below => below = middle,
            OrderingClass::Exact | OrderingClass::Above => {
                high = middle;
                upper_observation = observation;
            }
        }
    }

    ensure!(
        classify(upper_observation, target_po2)? == OrderingClass::Exact,
        "calibration crossed from below target po2 {target_po2} to a non-single-segment or higher-po2 execution"
    );
    Ok(CanonicalCalibrationSelection {
        workload_iterations: high,
        observation: upper_observation,
    })
}

/// Validate the profile-owned raw-seal and succinct-receipt shape.
///
/// This is an additional exact-shape gate before the upstream cryptographic
/// verifier is invoked by the command. It does not replace that verifier.
///
/// # Errors
///
/// Returns an error for any wrong proof length, field canonicality, padding,
/// SHA-halfword, outer exponent, hash suite, normal-lift control ID, bounded
/// control-inclusion proof, root, claim, or verifier parameter.
pub fn validate_candidate_succinct_shape(
    receipt: &SuccinctReceipt<ReceiptClaim>,
    segment_po2: u32,
    claim_digest: &Digest,
) -> Result<Vec<u8>> {
    validate_candidate_terminal_shape(receipt, CandidateTerminal::Lift(segment_po2), claim_digest)
}

/// Validate the profile-owned raw seal and exact lift/join/resolve terminal.
///
/// This is the shared structural gate used by the eleven-family candidate
/// corpus. It checks the exact frozen control ID and its upstream Merkle index,
/// in addition to the full raw-seal, root, claim, and verifier-parameter shape.
/// It does not infer or authenticate ancestry hidden below the final recursive
/// proof; the recursive candidate exporter records and verifies those
/// intermediate receipts separately.
///
/// # Errors
///
/// Returns an error for any terminal mismatch or malformed profile-owned
/// succinct-receipt field.
pub fn validate_candidate_terminal_shape(
    receipt: &SuccinctReceipt<ReceiptClaim>,
    terminal: CandidateTerminal,
    claim_digest: &Digest,
) -> Result<Vec<u8>> {
    let (expected_control_id, expected_control_index) = terminal.expected_control()?;
    let expected_root = expected_inner_control_root()?;
    ensure!(
        ALLOWED_CONTROL_ROOT == expected_root,
        "compiled upstream allowed-control root differs from the frozen root"
    );
    let parameters = SuccinctReceiptVerifierParameters::default();
    ensure!(
        parameters.control_root == expected_root && parameters.inner_control_root.is_none(),
        "compiled succinct verifier parameters do not bind the expected inner root"
    );

    let expected_parameters_digest = digest_from_hex(EXPECTED_VERIFIER_PARAMETERS_HEX)?;
    ensure!(
        parameters.digest() == expected_parameters_digest,
        "compiled succinct verifier-parameters digest differs from the frozen digest"
    );
    validate_terminal_shape_against_root(
        receipt,
        terminal,
        expected_control_id,
        expected_control_index,
        expected_root,
        expected_parameters_digest,
        claim_digest,
    )
}

/// Validate the valid alternate-root lift witness before it is exported.
///
/// The proof must retain the stock normal-lift po2-15 terminal, claim, proof
/// dimensions, and field encoding while binding the one fixed alternate
/// control root and its corresponding verifier-parameter digest.
///
/// # Errors
///
/// Returns an error for any deviation from the closed alternate-root profile
/// or the common succinct proof shape.
#[cfg(feature = "proof-generation")]
pub fn validate_alternate_root_succinct_shape(
    receipt: &SuccinctReceipt<ReceiptClaim>,
    claim_digest: &Digest,
    profile: &AlternateControlRootProfile,
) -> Result<Vec<u8>> {
    ensure!(
        profile.control_root != expected_inner_control_root()?,
        "alternate-root profile equals the initial profile root"
    );
    ensure!(
        profile.verifier_parameters_digest != digest_from_hex(EXPECTED_VERIFIER_PARAMETERS_HEX)?,
        "alternate-root profile equals the initial verifier parameters"
    );
    validate_terminal_shape_against_root(
        receipt,
        CandidateTerminal::Lift(ALTERNATE_ROOT_SEGMENT_PO2),
        profile.terminal_control_id,
        profile.terminal_control_index,
        profile.control_root,
        profile.verifier_parameters_digest,
        claim_digest,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_terminal_shape_against_root(
    receipt: &SuccinctReceipt<ReceiptClaim>,
    terminal: CandidateTerminal,
    expected_control_id: Digest,
    expected_control_index: u32,
    expected_root: Digest,
    expected_parameters_digest: Digest,
    claim_digest: &Digest,
) -> Result<Vec<u8>> {
    let terminal_label = terminal.label();
    ensure!(
        receipt.hashfn == "poseidon2",
        "receipt hash suite is not poseidon2"
    );
    ensure!(
        receipt.control_id == expected_control_id,
        "receipt control ID is not the expected {terminal_label}"
    );
    validate_reduced_digest(&receipt.control_id, "receipt control ID")?;

    ensure!(
        receipt.control_inclusion_proof.index == expected_control_index,
        "control-inclusion proof index is {}, expected {expected_control_index} for {terminal_label}",
        receipt.control_inclusion_proof.index
    );
    ensure!(
        receipt.control_inclusion_proof.digests.len() == CONTROL_INCLUSION_PROOF_DEPTH,
        "control-inclusion proof has {} sibling digests, expected {CONTROL_INCLUSION_PROOF_DEPTH}",
        receipt.control_inclusion_proof.digests.len()
    );
    for (sibling_index, sibling) in receipt.control_inclusion_proof.digests.iter().enumerate() {
        validate_reduced_digest(
            sibling,
            &format!("control-inclusion sibling digest {sibling_index}"),
        )?;
    }
    ensure!(
        receipt.verifier_parameters == expected_parameters_digest,
        "receipt verifier-parameters digest differs from the expected root contract"
    );

    let raw_seal = receipt.get_seal_bytes();
    ensure!(
        receipt.seal.len() == PROOF_WORDS,
        "raw seal has {} words, expected {PROOF_WORDS}",
        receipt.seal.len()
    );
    for (word_index, word) in receipt.seal.iter().copied().enumerate() {
        if word_index != 32 {
            ensure!(
                word < BABY_BEAR_MODULUS,
                "raw seal field/digest word at index {word_index} is not reduced"
            );
        }
    }
    ensure!(
        raw_seal.len() == PROOF_BYTES,
        "raw seal has {} bytes, expected {PROOF_BYTES}",
        raw_seal.len()
    );
    ensure!(
        decode_seal_words(&raw_seal)? == receipt.seal,
        "get_seal_bytes is not the exact little-endian encoding of receipt seal words"
    );

    let decoded_root = decode_inner_control_root(&receipt.seal[..16])?;
    ensure!(
        decoded_root == expected_root,
        "raw-seal inner control root differs from the expected root contract"
    );

    let decoded_claim = decode_claim_digest(&receipt.seal[16..32])?;
    ensure!(
        decoded_claim.as_slice() == claim_digest.as_bytes(),
        "raw-seal SHA halfwords do not encode the expected claim digest"
    );
    ensure!(
        receipt.claim.digest() == *claim_digest,
        "succinct receipt claim differs from the expected claim digest"
    );
    ensure!(
        receipt.seal[32] == EXPECTED_OUTER_PO2,
        "raw-seal outer po2 is {}, expected {EXPECTED_OUTER_PO2}",
        receipt.seal[32]
    );

    Ok(raw_seal)
}

fn validate_reduced_digest(digest: &Digest, label: &str) -> Result<()> {
    for (word_index, word) in digest.as_words().iter().copied().enumerate() {
        ensure!(
            word < BABY_BEAR_MODULUS,
            "{label} word {word_index} is not a reduced BabyBear element"
        );
    }
    Ok(())
}

fn decode_inner_control_root(raw_slot: &[u32]) -> Result<Digest> {
    ensure!(
        raw_slot.len() == 16,
        "inner-root slot does not contain exactly 16 words"
    );
    for index in (1..16).step_by(2) {
        ensure!(
            raw_slot[index] == 0,
            "nonzero Poseidon2 root padding at seal word {index}"
        );
    }
    let root_words = (0..16)
        .step_by(2)
        .map(|index| decode_recursion_output_word(raw_slot[index], index))
        .collect::<Result<Vec<_>>>()?;
    Digest::try_from(root_words)
        .map_err(|_| anyhow::anyhow!("inner-root slot does not contain exactly eight words"))
}

fn decode_claim_digest(raw_slot: &[u32]) -> Result<[u8; 32]> {
    let mut decoded_claim = [0_u8; 32];
    ensure!(
        raw_slot.len() == 16,
        "claim slot does not contain exactly 16 words"
    );
    for (index, raw_word) in raw_slot.iter().copied().enumerate() {
        let word = decode_recursion_output_word(raw_word, index + 16)?;
        let halfword = u16::try_from(word).map_err(|_| {
            anyhow::anyhow!(
                "claim SHA halfword at seal word {} exceeds 0xffff",
                index + 16
            )
        })?;
        decoded_claim[index * 2..index * 2 + 2].copy_from_slice(&halfword.to_le_bytes());
    }
    Ok(decoded_claim)
}

fn decode_recursion_output_word(raw_word: u32, seal_word_index: usize) -> Result<u32> {
    ensure!(
        raw_word < BABY_BEAR_MODULUS,
        "raw recursion-output field element at seal word {seal_word_index} is not reduced"
    );
    Ok(BabyBearElem::new_raw(raw_word).as_u32())
}

/// Return the frozen normal-lift control ID for one supported segment exponent.
///
/// # Errors
///
/// Returns an error unless `segment_po2` is in the exact inclusive range
/// `15..=22`, or if the embedded digest is malformed.
pub fn expected_normal_lift_control_id(segment_po2: u32) -> Result<Digest> {
    validate_segment_po2(segment_po2)?;
    let index = usize::try_from(segment_po2 - u32::from(MIN_SEGMENT_PO2))
        .context("segment po2 index does not fit usize")?;
    digest_from_hex(RISC0_NORMAL_LIFT_CONTROL_IDS_HEX[index])
}

/// Resolve one frozen normal-lift control ID to its unique segment exponent.
///
/// # Errors
///
/// Returns an error when the control ID is not one of the eight profile-owned
/// normal lifts for exponents 15 through 22.
pub fn normal_lift_segment_po2(control_id: &Digest) -> Result<u32> {
    for segment_po2 in u32::from(MIN_SEGMENT_PO2)..=u32::from(MAX_SEGMENT_PO2) {
        if expected_normal_lift_control_id(segment_po2)? == *control_id {
            return Ok(segment_po2);
        }
    }
    bail!("control ID is not one of the frozen normal lifts")
}

/// Return the frozen stock Poseidon2 `join.zkr` control ID.
///
/// # Errors
///
/// Returns an error only if the embedded digest is malformed.
pub fn expected_join_control_id() -> Result<Digest> {
    digest_from_hex(RISC0_JOIN_CONTROL_ID_HEX)
}

/// Return the frozen stock Poseidon2 `resolve.zkr` control ID.
///
/// # Errors
///
/// Returns an error only if the embedded digest is malformed.
pub fn expected_resolve_control_id() -> Result<Digest> {
    digest_from_hex(RISC0_RESOLVE_CONTROL_ID_HEX)
}

/// Return the frozen upstream Poseidon2 allowed-control root.
///
/// # Errors
///
/// Returns an error only if the embedded digest is malformed.
pub fn expected_inner_control_root() -> Result<Digest> {
    digest_from_hex(EXPECTED_INNER_CONTROL_ROOT_HEX)
}

fn validate_segment_po2(segment_po2: u32) -> Result<()> {
    ensure!(
        (u32::from(MIN_SEGMENT_PO2)..=u32::from(MAX_SEGMENT_PO2)).contains(&segment_po2),
        "segment po2 {segment_po2} is outside the frozen range {MIN_SEGMENT_PO2}..={MAX_SEGMENT_PO2}"
    );
    Ok(())
}

fn digest_from_hex(value: &str) -> Result<Digest> {
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(value, &mut bytes).context("embedded digest is not exact 32-byte hex")?;
    Ok(Digest::from(bytes))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OrderingClass {
    Below,
    Exact,
    Above,
}

fn classify(observation: SegmentObservation, target_po2: u32) -> Result<OrderingClass> {
    ensure!(
        (observation.segment_count == 1) == observation.single_segment_po2.is_some(),
        "malformed segment observation"
    );
    if observation.segment_count != 1 {
        return Ok(OrderingClass::Above);
    }
    let po2 = observation
        .single_segment_po2
        .expect("presence checked above");
    Ok(match po2.cmp(&target_po2) {
        core::cmp::Ordering::Less => OrderingClass::Below,
        core::cmp::Ordering::Equal => OrderingClass::Exact,
        core::cmp::Ordering::Greater => OrderingClass::Above,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_program_id() -> Digest {
        Digest::from([0x4242_4242_u32; 8])
    }

    fn statement_fixture(payload: &[u8]) -> Vec<u8> {
        let payload_length = u32::try_from(payload.len()).unwrap();
        let expected_program_id = fixture_program_id();
        let mut statement = Vec::with_capacity(STATEMENT_PREFIX_BYTES + payload.len());
        statement.extend_from_slice(ERGO_STATEMENT_DOMAIN);
        statement.push(0x01);
        statement.extend_from_slice(&[0x11; DIGEST_BYTES]);
        statement.extend_from_slice(&[0x22; DIGEST_BYTES]);
        statement.extend_from_slice(expected_program_id.as_bytes());
        statement.extend_from_slice(&[0x44; DIGEST_BYTES]);
        statement.extend_from_slice(&payload_length.to_le_bytes());
        statement.extend_from_slice(payload);
        statement
    }

    fn validate_statement(statement: &[u8]) -> Result<()> {
        validate_ergo_statement_v1(statement, &fixture_program_id())
    }

    #[derive(serde::Serialize)]
    struct MerkleProofWireFixture {
        index: u32,
        digests: Vec<Digest>,
    }

    #[derive(serde::Serialize)]
    struct SuccinctReceiptWireFixture {
        seal: Vec<u32>,
        control_id: Digest,
        claim: risc0_zkvm::MaybePruned<ReceiptClaim>,
        hashfn: String,
        verifier_parameters: Digest,
        control_inclusion_proof: MerkleProofWireFixture,
    }

    fn candidate_shape_fixture() -> (SuccinctReceipt<ReceiptClaim>, Digest) {
        candidate_terminal_shape_fixture(CandidateTerminal::Lift(15))
    }

    fn candidate_terminal_shape_fixture(
        terminal: CandidateTerminal,
    ) -> (SuccinctReceipt<ReceiptClaim>, Digest) {
        let image_id = fixture_program_id();
        let claim = ReceiptClaim::ok(image_id, b"shape-validator-fixture".to_vec());
        let claim_digest = claim.digest();
        let root = expected_inner_control_root().unwrap();
        let mut seal = vec![0_u32; PROOF_WORDS];

        for (index, word) in root.as_words().iter().copied().enumerate() {
            seal[index * 2] = BabyBearElem::new(word).as_u32_montgomery();
        }
        for (index, pair) in claim_digest.as_bytes().chunks_exact(2).enumerate() {
            let halfword = u32::from(u16::from_le_bytes([pair[0], pair[1]]));
            seal[16 + index] = BabyBearElem::new(halfword).as_u32_montgomery();
        }
        seal[32] = EXPECTED_OUTER_PO2;

        // Both upstream types are non-exhaustive. Bincode's positional serde
        // encoding lets this test construct their exact public wire shape
        // without adding a test-only constructor to production code.
        let (control_id, control_index) = terminal.expected_control().unwrap();
        let encoded = bincode::serialize(&SuccinctReceiptWireFixture {
            seal,
            control_id,
            claim: risc0_zkvm::MaybePruned::Value(claim),
            hashfn: "poseidon2".to_owned(),
            verifier_parameters: digest_from_hex(EXPECTED_VERIFIER_PARAMETERS_HEX).unwrap(),
            control_inclusion_proof: MerkleProofWireFixture {
                index: control_index,
                digests: vec![Digest::ZERO; CONTROL_INCLUSION_PROOF_DEPTH],
            },
        })
        .unwrap();
        let receipt = bincode::deserialize(&encoded).unwrap();
        (receipt, claim_digest)
    }

    #[test]
    fn statement_length_bounds_are_exact() {
        assert!(validate_statement(&statement_fixture(&[])).is_ok());
        assert!(
            validate_statement(&statement_fixture(&[0x5a; MAX_APPLICATION_PAYLOAD_BYTES])).is_ok()
        );

        let too_short = statement_fixture(&[])[..STATEMENT_PREFIX_BYTES - 1].to_vec();
        assert!(
            validate_statement(&too_short)
                .unwrap_err()
                .to_string()
                .contains("expected 159..=16543")
        );
    }

    #[test]
    fn statement_domain_must_be_byte_exact() {
        let mut statement = statement_fixture(&[]);
        statement[0] ^= 1;
        assert!(
            validate_statement(&statement)
                .unwrap_err()
                .to_string()
                .contains("domain is not exact")
        );
    }

    #[test]
    fn statement_version_must_be_one() {
        let mut statement = statement_fixture(&[]);
        statement[STATEMENT_VERSION_OFFSET] = 0x02;
        assert!(
            validate_statement(&statement)
                .unwrap_err()
                .to_string()
                .contains("version is not 0x01")
        );
    }

    #[test]
    fn statement_program_id_must_equal_the_guest_image_id() {
        let mut statement = statement_fixture(&[]);
        statement[STATEMENT_PROGRAM_ID_OFFSET] ^= 1;
        assert!(
            validate_statement(&statement)
                .unwrap_err()
                .to_string()
                .contains("expected guest image ID")
        );
    }

    #[test]
    fn statement_payload_length_is_little_endian_and_bounded() {
        let mut statement = statement_fixture(&[]);
        statement[STATEMENT_PAYLOAD_LENGTH_OFFSET..STATEMENT_PAYLOAD_OFFSET]
            .copy_from_slice(&16_385_u32.to_le_bytes());
        assert!(
            validate_statement(&statement)
                .unwrap_err()
                .to_string()
                .contains("maximum is 16384")
        );
    }

    #[test]
    fn statement_declared_payload_length_must_reach_exact_eof() {
        let mut statement = statement_fixture(&[]);
        statement[STATEMENT_PAYLOAD_LENGTH_OFFSET..STATEMENT_PAYLOAD_OFFSET]
            .copy_from_slice(&1_u32.to_le_bytes());
        assert!(
            validate_statement(&statement)
                .unwrap_err()
                .to_string()
                .contains("exact input length is 0")
        );
    }

    #[test]
    fn statement_rejects_trailing_bytes() {
        let mut statement = statement_fixture(&[]);
        statement.push(0xaa);
        assert!(
            validate_statement(&statement)
                .unwrap_err()
                .to_string()
                .contains("exact input length is 1")
        );
    }

    #[test]
    fn statement_chain_profile_and_contract_fields_are_opaque() {
        let mut statement = statement_fixture(&[]);
        statement[STATEMENT_CHAIN_DOMAIN_OFFSET..STATEMENT_PROFILE_ID_OFFSET].fill(0xa1);
        statement[STATEMENT_PROFILE_ID_OFFSET..STATEMENT_PROGRAM_ID_OFFSET].fill(0xb2);
        statement[STATEMENT_CONTRACT_ID_OFFSET..STATEMENT_PAYLOAD_LENGTH_OFFSET].fill(0xc3);
        validate_statement(&statement).unwrap();
    }

    #[test]
    fn statement_derivation_chain_domain_flips_only_byte_zero_at_both_length_bounds() {
        for payload_length in [0, MAX_APPLICATION_PAYLOAD_BYTES] {
            let payload = vec![0x5a; payload_length];
            let source = statement_fixture(&payload);
            let changed =
                derive_b4_alternate_chain_domain_statement(&source, &fixture_program_id()).unwrap();

            assert_eq!(changed.len(), source.len());
            assert_eq!(
                changed[STATEMENT_CHAIN_DOMAIN_OFFSET],
                source[STATEMENT_CHAIN_DOMAIN_OFFSET] ^ 0x01
            );
            assert_eq!(
                &changed[..STATEMENT_CHAIN_DOMAIN_OFFSET],
                &source[..STATEMENT_CHAIN_DOMAIN_OFFSET]
            );
            assert_eq!(
                &changed[STATEMENT_CHAIN_DOMAIN_OFFSET + 1..],
                &source[STATEMENT_CHAIN_DOMAIN_OFFSET + 1..]
            );
            assert_eq!(
                source
                    .iter()
                    .zip(&changed)
                    .filter(|(left, right)| left != right)
                    .count(),
                1
            );
            validate_ergo_statement_v1(&changed, &fixture_program_id()).unwrap();
        }
    }

    #[test]
    fn statement_derivation_program_replaces_only_exact_span_at_both_length_bounds() {
        let alternate_program_id = Digest::from([0x7777_7777_u32; 8]);
        for payload_length in [0, MAX_APPLICATION_PAYLOAD_BYTES] {
            let payload = vec![0x5a; payload_length];
            let source = statement_fixture(&payload);
            let changed = derive_b4_alternate_program_statement(
                &source,
                &fixture_program_id(),
                &alternate_program_id,
            )
            .unwrap();

            assert_eq!(changed.len(), source.len());
            assert_eq!(
                &changed[STATEMENT_PROGRAM_ID_OFFSET..STATEMENT_CONTRACT_ID_OFFSET],
                alternate_program_id.as_bytes()
            );
            assert_eq!(
                &changed[..STATEMENT_PROGRAM_ID_OFFSET],
                &source[..STATEMENT_PROGRAM_ID_OFFSET]
            );
            assert_eq!(
                &changed[STATEMENT_CONTRACT_ID_OFFSET..],
                &source[STATEMENT_CONTRACT_ID_OFFSET..]
            );
            assert_eq!(
                &changed[STATEMENT_PAYLOAD_OFFSET..],
                &source[STATEMENT_PAYLOAD_OFFSET..]
            );
            validate_ergo_statement_v1(&changed, &alternate_program_id).unwrap();
            assert!(validate_ergo_statement_v1(&changed, &fixture_program_id()).is_err());
        }
    }

    #[test]
    fn statement_derivation_rejects_invalid_source_bounds_before_mutation() {
        let alternate_program_id = Digest::from([0x7777_7777_u32; 8]);
        let too_short = statement_fixture(&[])[..STATEMENT_PREFIX_BYTES - 1].to_vec();
        let mut too_long = statement_fixture(&[0x5a; MAX_APPLICATION_PAYLOAD_BYTES]);
        too_long.push(0xaa);
        let mut malformed_payload_length = statement_fixture(&[0x5a]);
        malformed_payload_length[STATEMENT_PAYLOAD_LENGTH_OFFSET..STATEMENT_PAYLOAD_OFFSET]
            .copy_from_slice(&2_u32.to_le_bytes());

        for source in [&too_short, &too_long, &malformed_payload_length] {
            assert!(
                derive_b4_alternate_chain_domain_statement(source, &fixture_program_id()).is_err()
            );
            assert!(
                derive_b4_alternate_program_statement(
                    source,
                    &fixture_program_id(),
                    &alternate_program_id,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn statement_derivation_rejects_wrong_source_program_binding() {
        let source = statement_fixture(&[]);
        let wrong_source_program_id = Digest::from([0x9999_9999_u32; 8]);
        let alternate_program_id = Digest::from([0x7777_7777_u32; 8]);

        assert!(
            derive_b4_alternate_chain_domain_statement(&source, &wrong_source_program_id).is_err()
        );
        assert!(
            derive_b4_alternate_program_statement(
                &source,
                &wrong_source_program_id,
                &alternate_program_id,
            )
            .is_err()
        );
    }

    #[test]
    fn statement_derivation_rejects_an_unchanged_program_identity() {
        let source = statement_fixture(&[]);
        assert!(
            derive_b4_alternate_program_statement(
                &source,
                &fixture_program_id(),
                &fixture_program_id(),
            )
            .is_err()
        );
    }

    #[test]
    fn statement_derivation_span_guard_rejects_every_out_of_span_change() {
        let source = statement_fixture(&[]);
        let alternate_program_id = Digest::from([0x7777_7777_u32; 8]);
        let alternate_chain =
            derive_b4_alternate_chain_domain_statement(&source, &fixture_program_id()).unwrap();
        let alternate_program = derive_b4_alternate_program_statement(
            &source,
            &fixture_program_id(),
            &alternate_program_id,
        )
        .unwrap();

        for (changed, start, end, label) in [
            (
                alternate_chain,
                STATEMENT_CHAIN_DOMAIN_OFFSET,
                STATEMENT_CHAIN_DOMAIN_OFFSET + 1,
                "alternate chain-domain statement",
            ),
            (
                alternate_program,
                STATEMENT_PROGRAM_ID_OFFSET,
                STATEMENT_CONTRACT_ID_OFFSET,
                "alternate-program statement",
            ),
        ] {
            require_only_statement_span_changed(&source, &changed, start, end, label).unwrap();
            assert!(
                require_only_statement_span_changed(&source, &source, start, end, label).is_err()
            );

            let mut changed_before = changed.clone();
            changed_before[start - 1] ^= 0x01;
            assert!(
                require_only_statement_span_changed(&source, &changed_before, start, end, label,)
                    .is_err()
            );

            let mut changed_after = changed;
            changed_after[end] ^= 0x01;
            assert!(
                require_only_statement_span_changed(&source, &changed_after, start, end, label,)
                    .is_err()
            );
        }
    }

    #[test]
    fn frozen_control_table_has_exact_endpoints_and_distinct_entries() {
        let mut ids = (15..=22)
            .map(|po2| expected_normal_lift_control_id(po2).unwrap())
            .collect::<Vec<_>>();
        ids.push(expected_join_control_id().unwrap());
        ids.push(expected_resolve_control_id().unwrap());
        assert_eq!(ids.len(), 10);
        for (index, left) in ids.iter().enumerate() {
            assert!(!ids[index + 1..].contains(left));
        }
        assert_eq!(
            hex::encode(ids[0].as_bytes()),
            "1ca3ca03030719064ba61b3125bdd326fc57f74e799ef860bdea6f3227381e16"
        );
        assert_eq!(
            hex::encode(ids[7].as_bytes()),
            "9d9dbf33535ab11f52a93839dfd23b352b7626009e81d9459fd04e488898ec6a"
        );
        assert_eq!(
            hex::encode(ids[8].as_bytes()),
            "7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e"
        );
        assert_eq!(
            hex::encode(ids[9].as_bytes()),
            "53a7b23d07f99e5d5685e85874f5181e8486aa267a0ae607ffe9ba47c8bdda4a"
        );
    }

    #[test]
    fn generic_terminal_shape_gate_accepts_only_exact_join_and_resolve_controls() {
        for terminal in [CandidateTerminal::Join, CandidateTerminal::Resolve] {
            let (receipt, claim_digest) = candidate_terminal_shape_fixture(terminal);
            validate_candidate_terminal_shape(&receipt, terminal, &claim_digest).unwrap();

            let other = match terminal {
                CandidateTerminal::Join => CandidateTerminal::Resolve,
                CandidateTerminal::Resolve => CandidateTerminal::Join,
                CandidateTerminal::Lift(_) => unreachable!(),
            };
            assert!(
                validate_candidate_terminal_shape(&receipt, other, &claim_digest)
                    .unwrap_err()
                    .to_string()
                    .contains("control ID is not the expected")
            );

            let mut wrong_index = receipt.clone();
            wrong_index.control_inclusion_proof.index ^= 1;
            assert!(
                validate_candidate_terminal_shape(&wrong_index, terminal, &claim_digest)
                    .unwrap_err()
                    .to_string()
                    .contains("control-inclusion proof index")
            );
        }
    }

    #[test]
    fn canonical_selection_returns_zero_when_base_execution_is_exact() {
        let result =
            select_canonical_iterations(15, |_| SegmentObservation::new(1, Some(15))).unwrap();
        assert_eq!(result.workload_iterations, 0);
    }

    #[test]
    fn removed_po2_14_branch_is_rejected() {
        assert!(expected_normal_lift_control_id(14).is_err());
        assert!(select_canonical_iterations(14, |_| SegmentObservation::new(1, Some(14))).is_err());
    }

    #[test]
    fn canonical_selection_uses_the_prescribed_monotone_ranking() {
        let result = select_canonical_iterations(18, |iterations| {
            let po2 = if iterations < 37 { 17 } else { 18 };
            SegmentObservation::new(1, Some(po2))
        })
        .unwrap();
        assert_eq!(result.workload_iterations, 37);
        assert_eq!(result.observation.single_segment_po2, Some(18));
    }

    #[test]
    fn canonical_selection_rejects_an_above_target_bracket_endpoint() {
        let error = select_canonical_iterations(18, |iterations| {
            if iterations < 9 {
                SegmentObservation::new(1, Some(17))
            } else {
                SegmentObservation::new(2, None)
            }
        })
        .unwrap_err();
        assert!(error.to_string().contains("crossed from below"));
    }

    #[test]
    fn canonical_selection_does_not_claim_a_global_minimum_for_non_monotone_observations() {
        let selection = select_canonical_iterations(18, |iterations| {
            let po2 = match iterations {
                3 | 8 => 18,
                _ => 17,
            };
            SegmentObservation::new(1, Some(po2))
        })
        .unwrap();

        // The canonical ranking probes 1, 2, 4, 6, 7, then 8. An earlier
        // exact value at 3 is deliberately not represented as a minimum.
        assert_eq!(selection.workload_iterations, 8);
        assert_eq!(selection.observation.single_segment_po2, Some(18));
    }

    #[test]
    fn seal_decoder_is_exact_little_endian_and_length_gated() {
        let mut raw = vec![0_u8; PROOF_BYTES];
        raw[..8].copy_from_slice(&[1, 2, 3, 4, 0xfc, 0xfd, 0xfe, 0xff]);
        let words = decode_seal_words(&raw).unwrap();
        assert_eq!(words.len(), PROOF_WORDS);
        assert_eq!(words[0], 0x0403_0201);
        assert_eq!(words[1], 0xfffe_fdfc);
        assert!(decode_seal_words(&raw[..raw.len() - 1]).is_err());
    }

    #[test]
    fn seal_decoder_rejects_an_appended_grinding_nonce_word() {
        let mut raw = vec![0_u8; PROOF_BYTES];
        raw.extend_from_slice(&0x4433_2211_u32.to_le_bytes());
        let error = decode_seal_words(&raw).unwrap_err();
        assert!(error.to_string().contains(&format!(
            "raw seal has {} bytes, expected {PROOF_BYTES}",
            PROOF_BYTES + 4
        )));
    }

    #[test]
    fn complete_shape_validator_isolates_identity_and_length_gates() {
        let (receipt, claim_digest) = candidate_shape_fixture();
        let raw = validate_candidate_succinct_shape(&receipt, 15, &claim_digest).unwrap();
        assert_eq!(receipt.seal.len(), PROOF_WORDS);
        assert_eq!(raw.len(), PROOF_BYTES);

        let mut changed = receipt.clone();
        changed.hashfn = "sha-256".to_owned();
        assert!(
            validate_candidate_succinct_shape(&changed, 15, &claim_digest)
                .unwrap_err()
                .to_string()
                .contains("hash suite is not poseidon2")
        );

        let mut changed = receipt.clone();
        changed.control_id = Digest::ZERO;
        assert!(
            validate_candidate_succinct_shape(&changed, 15, &claim_digest)
                .unwrap_err()
                .to_string()
                .contains("control ID is not the expected normal lift")
        );

        let mut changed = receipt.clone();
        changed.verifier_parameters = Digest::ZERO;
        assert!(
            validate_candidate_succinct_shape(&changed, 15, &claim_digest)
                .unwrap_err()
                .to_string()
                .contains("verifier-parameters digest differs")
        );

        let mut changed = receipt.clone();
        changed.seal.pop();
        assert!(
            validate_candidate_succinct_shape(&changed, 15, &claim_digest)
                .unwrap_err()
                .to_string()
                .contains("raw seal has 55666 words")
        );
    }

    #[test]
    fn complete_shape_validator_bounds_control_inclusion_before_upstream_hashing() {
        let (receipt, claim_digest) = candidate_shape_fixture();

        let mut changed = receipt.clone();
        changed.control_inclusion_proof.index = MIN_SEGMENT_CONTROL_INDEX - 1;
        assert!(
            validate_candidate_succinct_shape(&changed, 15, &claim_digest)
                .unwrap_err()
                .to_string()
                .contains("control-inclusion proof index is 4, expected 5")
        );

        let mut changed = receipt.clone();
        changed.control_inclusion_proof.digests.pop();
        assert!(
            validate_candidate_succinct_shape(&changed, 15, &claim_digest)
                .unwrap_err()
                .to_string()
                .contains("has 7 sibling digests, expected 8")
        );

        let mut changed = receipt.clone();
        changed.control_inclusion_proof.digests.push(Digest::ZERO);
        assert!(
            validate_candidate_succinct_shape(&changed, 15, &claim_digest)
                .unwrap_err()
                .to_string()
                .contains("has 9 sibling digests, expected 8")
        );

        let mut changed = receipt.clone();
        changed.control_inclusion_proof.digests[7] =
            Digest::new([BABY_BEAR_MODULUS, 0, 0, 0, 0, 0, 0, 0]);
        assert!(
            validate_candidate_succinct_shape(&changed, 15, &claim_digest)
                .unwrap_err()
                .to_string()
                .contains("control-inclusion sibling digest 7 word 0 is not a reduced")
        );
    }

    #[test]
    fn complete_shape_validator_range_checks_the_entire_raw_seal() {
        let (receipt, claim_digest) = candidate_shape_fixture();

        for word_index in [33, PROOF_WORDS - 1] {
            let mut changed = receipt.clone();
            changed.seal[word_index] = BABY_BEAR_MODULUS;
            let error = validate_candidate_succinct_shape(&changed, 15, &claim_digest).unwrap_err();
            assert!(error.to_string().contains(&format!(
                "raw seal field/digest word at index {word_index} is not reduced"
            )));
        }
    }

    #[test]
    fn complete_shape_validator_isolates_root_claim_and_outer_gates() {
        let (receipt, claim_digest) = candidate_shape_fixture();

        let mut changed = receipt.clone();
        changed.seal[1] = 1;
        assert!(
            validate_candidate_succinct_shape(&changed, 15, &claim_digest)
                .unwrap_err()
                .to_string()
                .contains("nonzero Poseidon2 root padding at seal word 1")
        );

        let mut changed = receipt.clone();
        let root_word = BabyBearElem::new_raw(changed.seal[0]).as_u32();
        let alternate_root_word = if root_word + 1 < BABY_BEAR_MODULUS {
            root_word + 1
        } else {
            root_word - 1
        };
        changed.seal[0] = BabyBearElem::new(alternate_root_word).as_u32_montgomery();
        assert!(
            validate_candidate_succinct_shape(&changed, 15, &claim_digest)
                .unwrap_err()
                .to_string()
                .contains("inner control root differs")
        );

        let mut changed = receipt.clone();
        let claim_halfword = BabyBearElem::new_raw(changed.seal[16]).as_u32();
        let alternate_halfword = if claim_halfword == 0 {
            1
        } else {
            claim_halfword - 1
        };
        changed.seal[16] = BabyBearElem::new(alternate_halfword).as_u32_montgomery();
        assert!(
            validate_candidate_succinct_shape(&changed, 15, &claim_digest)
                .unwrap_err()
                .to_string()
                .contains("SHA halfwords do not encode")
        );

        let mut changed = receipt.clone();
        changed.claim = risc0_zkvm::MaybePruned::Value(ReceiptClaim::ok(
            fixture_program_id(),
            b"different-claim".to_vec(),
        ));
        assert!(
            validate_candidate_succinct_shape(&changed, 15, &claim_digest)
                .unwrap_err()
                .to_string()
                .contains("succinct receipt claim differs")
        );

        let mut changed = receipt.clone();
        changed.seal[32] = EXPECTED_OUTER_PO2 + 1;
        assert!(
            validate_candidate_succinct_shape(&changed, 15, &claim_digest)
                .unwrap_err()
                .to_string()
                .contains("raw-seal outer po2 is 19")
        );

        assert!(
            validate_candidate_succinct_shape(&receipt, 15, &Digest::ZERO)
                .unwrap_err()
                .to_string()
                .contains("SHA halfwords do not encode")
        );
        assert!(
            validate_candidate_succinct_shape(&receipt, 14, &claim_digest)
                .unwrap_err()
                .to_string()
                .contains("outside the frozen range 15..=22")
        );
    }

    #[test]
    fn compiled_root_and_parameters_match_frozen_values() {
        let root = expected_inner_control_root().unwrap();
        assert_eq!(root, ALLOWED_CONTROL_ROOT);
        assert_eq!(
            SuccinctReceiptVerifierParameters::default().control_root,
            root
        );
        assert_eq!(
            hex::encode(
                SuccinctReceiptVerifierParameters::default()
                    .digest()
                    .as_bytes()
            ),
            EXPECTED_VERIFIER_PARAMETERS_HEX
        );
    }

    #[cfg(feature = "proof-generation")]
    #[test]
    fn alternate_root_profile_is_fixed_distinct_and_retains_lift_fifteen() {
        let profile = alternate_control_root_profile().unwrap();
        assert_eq!(profile.control_ids().len(), STOCK_ALLOWED_CONTROL_COUNT - 1);
        assert_eq!(
            profile.terminal_control_id(),
            expected_normal_lift_control_id(ALTERNATE_ROOT_SEGMENT_PO2).unwrap()
        );
        assert_eq!(profile.terminal_control_index(), MIN_SEGMENT_CONTROL_INDEX);
        assert_eq!(
            profile.control_ids().last(),
            ALLOWED_CONTROL_IDS.get(STOCK_ALLOWED_CONTROL_COUNT - 2)
        );
        assert!(
            !profile
                .control_ids()
                .contains(&digest_from_hex(ALTERNATE_ROOT_OMITTED_CONTROL_ID_HEX).unwrap())
        );
        assert_ne!(profile.control_root(), ALLOWED_CONTROL_ROOT);
        assert_eq!(
            hex::encode(profile.control_root().as_bytes()),
            EXPECTED_ALTERNATE_CONTROL_ROOT_HEX
        );
        assert_eq!(
            profile.verifier_parameters().control_root,
            profile.control_root()
        );
        assert_eq!(profile.verifier_parameters().inner_control_root, None);
        assert_eq!(
            profile.verifier_parameters_digest(),
            profile.verifier_parameters().digest()
        );
        assert_eq!(
            hex::encode(profile.verifier_parameters_digest().as_bytes()),
            EXPECTED_ALTERNATE_VERIFIER_PARAMETERS_HEX
        );
        assert_ne!(
            profile.verifier_parameters_digest(),
            digest_from_hex(EXPECTED_VERIFIER_PARAMETERS_HEX).unwrap()
        );
    }

    #[test]
    fn recursion_output_root_words_are_montgomery_decoded() {
        let expected = expected_inner_control_root().unwrap();
        let raw_slot = [
            0x2654_afb3,
            0,
            0x7327_33aa,
            0,
            0x3dc8_decb,
            0,
            0x2bdf_cbd9,
            0,
            0x390f_2272,
            0,
            0x50f5_9b17,
            0,
            0x1dd8_f361,
            0,
            0x1045_3a77,
            0,
        ];

        assert_eq!(decode_inner_control_root(&raw_slot).unwrap(), expected);
    }

    #[test]
    fn recursion_output_claim_halfwords_are_montgomery_decoded() {
        let expected = [
            0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10,
            0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb,
        ];
        let raw_slot = [
            0x0fff_fdde,
            0x77fe_ede1,
            0x67fd_dde3,
            0x67ff_6c83,
            0x77fe_dae1,
            0x0ffe_493e,
            0x77ff_dbe1,
            0x67ff_4c63,
            0x77fe_bac1,
            0x0ffe_291e,
            0x0fff_d99e,
            0x27ff_92eb,
            0x2fff_4a1a,
            0x37ff_0149,
            0x3ffe_b878,
            0x47fe_6fa7,
        ];

        assert_eq!(decode_claim_digest(&raw_slot).unwrap(), expected);
    }

    #[test]
    fn recursion_output_rejects_non_reduced_raw_field_words() {
        let mut root_slot = [0_u32; 16];
        root_slot[0] = BABY_BEAR_MODULUS;
        assert!(
            decode_inner_control_root(&root_slot)
                .unwrap_err()
                .to_string()
                .contains("seal word 0 is not reduced")
        );

        let mut claim_slot = [0_u32; 16];
        claim_slot[7] = BABY_BEAR_MODULUS;
        assert!(
            decode_claim_digest(&claim_slot)
                .unwrap_err()
                .to_string()
                .contains("seal word 23 is not reduced")
        );
    }

    #[test]
    fn recursion_output_root_decoder_rejects_nonzero_raw_padding() {
        for index in (1..16).step_by(2) {
            let mut root_slot = [0_u32; 16];
            root_slot[index] = 1;
            assert_eq!(root_slot.iter().filter(|word| **word != 0).count(), 1);
            let error = decode_inner_control_root(&root_slot).unwrap_err();
            assert!(error.to_string().contains(&format!(
                "nonzero Poseidon2 root padding at seal word {index}"
            )));
        }
    }

    #[test]
    fn recursion_output_claim_rejects_halfword_overflow_after_montgomery_decode() {
        // Independent fixed vector: canonical 0x1_0000 is encoded as this
        // reduced BabyBear Montgomery residue by the pinned upstream field.
        const OVERFLOW_RESIDUE: u32 = 0x0ffd_ddde;
        assert_eq!(BabyBearElem::new_raw(OVERFLOW_RESIDUE).as_u32(), 0x1_0000);

        for index in 0..16 {
            let mut claim_slot = [0_u32; 16];
            claim_slot[index] = OVERFLOW_RESIDUE;
            assert_eq!(claim_slot.iter().filter(|word| **word != 0).count(), 1);
            let error = decode_claim_digest(&claim_slot).unwrap_err();
            assert!(error.to_string().contains(&format!(
                "claim SHA halfword at seal word {} exceeds 0xffff",
                index + 16
            )));
        }
    }

    #[test]
    fn outer_po2_wire_word_remains_the_literal_raw_value() {
        assert_eq!(EXPECTED_OUTER_PO2, 18);
        assert_ne!(
            BabyBearElem::new_raw(EXPECTED_OUTER_PO2).as_u32(),
            EXPECTED_OUTER_PO2
        );
    }

    #[test]
    fn executor_ceiling_is_distinct_from_every_profile_target() {
        assert_eq!(EXECUTOR_SEGMENT_LIMIT_PO2, 23);
        assert!(EXECUTOR_SEGMENT_LIMIT_PO2 > u32::from(MAX_SEGMENT_PO2));
    }
}
