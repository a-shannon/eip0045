//! Closed semantic and cryptographic authentication for B4 terminal sources.
//!
//! This boundary proves only that caller-owned bytes have the required stock
//! receipt shapes. It does not establish membership in an official generation
//! campaign or authorize later materialization.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail, ensure};
use eip_0045_reproduction::{
    b4_terminal::{
        B4_TERMINAL_FIXTURE_LAYOUT, terminal_fixture_raw_seal_path,
        terminal_fixture_receipt_oracle_path,
    },
    b4_terminal_oracle::replay_fixed_terminal_oracles,
    constants::PROOF_BYTES,
};
use risc0_zkvm::{
    ALLOWED_CONTROL_IDS, ALLOWED_CONTROL_ROOT, Digest, ExitCode, InnerReceipt, LocalProver,
    MaybePruned, ProverOpts, ReceiptClaim, ReceiptKind, SegmentReceipt, SuccinctReceipt,
    SuccinctReceiptVerifierParameters, VerifierContext, WorkClaim, compute_image_id,
    get_prover_server, recursion::Prover as RecursionProver, sha::Digestible,
};
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    CandidateTerminal,
    receipt_oracle_wire::{
        assemble_succinct_receipt, decode_outer_receipt_oracle, encode_succinct_receipt_oracle,
    },
    recursive::{
        RecursiveFamily, RecursiveInputs, RecursiveOperation, RecursiveOracle, RecursiveStep,
        authenticate_recursive_oracle_bytes, final_b4_terminal_join_direct_evidence,
        prove_plain_po2_18_segment, validate_terminal_join_source_povw,
    },
    validate_candidate_terminal_shape, validate_ergo_statement_v1,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminalFixtureRecipe {
    IdentityFromCase0Lift15,
    LiftPovwPo218,
    JoinPovwFromCase8,
    JoinUnwrapPovwFromCase8,
    ResolvePovwFromCase9,
    ResolveUnwrapPovwFromCase9,
    UnionOfIdentityAndJoinUnwrap,
    UnwrapJoinPovw,
    AllowedSystemSplitFromCase8Step0,
}

const TERMINAL_FIXTURE_RECIPES: [TerminalFixtureRecipe; 9] = [
    TerminalFixtureRecipe::IdentityFromCase0Lift15,
    TerminalFixtureRecipe::LiftPovwPo218,
    TerminalFixtureRecipe::JoinPovwFromCase8,
    TerminalFixtureRecipe::JoinUnwrapPovwFromCase8,
    TerminalFixtureRecipe::ResolvePovwFromCase9,
    TerminalFixtureRecipe::ResolveUnwrapPovwFromCase9,
    TerminalFixtureRecipe::UnionOfIdentityAndJoinUnwrap,
    TerminalFixtureRecipe::UnwrapJoinPovw,
    TerminalFixtureRecipe::AllowedSystemSplitFromCase8Step0,
];

impl TerminalFixtureRecipe {
    const fn fixture_id(self) -> &'static str {
        match self {
            Self::IdentityFromCase0Lift15 => "lift-po2-14",
            Self::LiftPovwPo218 => "lift-povw-po2-18",
            Self::JoinPovwFromCase8 => "join-povw",
            Self::JoinUnwrapPovwFromCase8 => "join-unwrap-povw",
            Self::ResolvePovwFromCase9 => "resolve-povw",
            Self::ResolveUnwrapPovwFromCase9 => "resolve-unwrap-povw",
            Self::UnionOfIdentityAndJoinUnwrap => "union",
            Self::UnwrapJoinPovw => "unwrap-povw",
            Self::AllowedSystemSplitFromCase8Step0 => "allowed-terminal-non-ok",
        }
    }
}

/// Complete in-memory output of the fixed B4 terminal-fixture producer.
pub struct B4GeneratedTerminalFixtureSetV1 {
    catalogue_jcs: Vec<u8>,
    raw_seals: BTreeMap<String, Vec<u8>>,
    receipt_oracles: BTreeMap<String, Vec<u8>>,
}

impl B4GeneratedTerminalFixtureSetV1 {
    /// Canonical catalogue derived only from cryptographically replayed fixtures.
    #[must_use]
    pub fn catalogue_jcs(&self) -> &[u8] {
        &self.catalogue_jcs
    }

    /// Exact repository-relative raw-seal paths and bytes.
    #[must_use]
    pub const fn raw_seals(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.raw_seals
    }

    /// Exact repository-relative typed receipt-oracle paths and bytes.
    #[must_use]
    pub const fn receipt_oracles(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.receipt_oracles
    }
}

/// Owned, opaque sources authenticated for later B4 terminal-fixture materialization.
///
/// This type has no public source-byte projection. Its only source-byte views
/// are five bounded crate-private borrows: the guest ELF, statement, case-0
/// receipt oracle, case-8 recursive oracle, and case-9 recursive oracle. It
/// exposes no receipt selectors, proving options, serializer, or unchecked
/// constructor.
#[allow(dead_code)]
pub struct B4AuthenticatedTerminalFixtureSourcesV1 {
    guest_elf: Vec<u8>,
    statement: Vec<u8>,
    image_id: Digest,
    lift15_receipt_oracle: Vec<u8>,
    lift15_receipt: SuccinctReceipt<ReceiptClaim>,
    terminal_join_recursive_oracle: Vec<u8>,
    terminal_join: RecursiveOracle,
    terminal_resolve_recursive_oracle: Vec<u8>,
    terminal_resolve: RecursiveOracle,
}

impl B4AuthenticatedTerminalFixtureSourcesV1 {
    pub(crate) fn guest_elf(&self) -> &[u8] {
        &self.guest_elf
    }

    pub(crate) fn statement(&self) -> &[u8] {
        &self.statement
    }

    pub(crate) fn lift15_receipt_oracle(&self) -> &[u8] {
        &self.lift15_receipt_oracle
    }

    pub(crate) fn terminal_join_recursive_oracle(&self) -> &[u8] {
        &self.terminal_join_recursive_oracle
    }

    pub(crate) fn terminal_resolve_recursive_oracle(&self) -> &[u8] {
        &self.terminal_resolve_recursive_oracle
    }
}

pub(crate) struct B4Case8FinalJoinDirectEvidenceV1 {
    raw_seal: Vec<u8>,
    receipt_oracle: Vec<u8>,
}

impl B4Case8FinalJoinDirectEvidenceV1 {
    pub(crate) fn raw_seal(&self) -> &[u8] {
        &self.raw_seal
    }

    pub(crate) fn receipt_oracle(&self) -> &[u8] {
        &self.receipt_oracle
    }
}

pub(crate) struct B4TerminalFixtureCompositionV1 {
    authenticated: B4AuthenticatedTerminalFixtureSourcesV1,
    generated: B4GeneratedTerminalFixtureSetV1,
    case8_direct: B4Case8FinalJoinDirectEvidenceV1,
}

impl B4TerminalFixtureCompositionV1 {
    pub(crate) fn into_parts(
        self,
    ) -> (
        B4AuthenticatedTerminalFixtureSourcesV1,
        B4GeneratedTerminalFixtureSetV1,
        B4Case8FinalJoinDirectEvidenceV1,
    ) {
        (self.authenticated, self.generated, self.case8_direct)
    }
}

/// Authenticate the exact owned source shapes used by the B4 terminal producer.
///
/// This validates bytewise canonical stock receipts and recursive oracles. It
/// does not establish official positive-campaign lineage.
///
/// # Errors
///
/// Returns an error when the guest identity, statement, outer Lift-15 receipt,
/// terminal-join oracle, terminal-resolve oracle, cross-source claim, or
/// case-8 step-zero `SystemSplit` gate differs from the closed source contract.
pub fn authenticate_b4_terminal_fixture_sources(
    guest_elf: &[u8],
    statement: &[u8],
    lift15_receipt_oracle: &[u8],
    terminal_join_recursive_oracle: &[u8],
    terminal_resolve_recursive_oracle: &[u8],
) -> Result<B4AuthenticatedTerminalFixtureSourcesV1> {
    let image_id =
        compute_image_id(guest_elf).context("cannot compute terminal-fixture guest image ID")?;
    validate_ergo_statement_v1(statement, &image_id)
        .context("terminal-fixture statement is invalid")?;
    let expected_claim = ReceiptClaim::ok(image_id, statement.to_vec()).digest();
    let ctx = VerifierContext::default().with_dev_mode(false);

    let lift15_outer = decode_outer_receipt_oracle(lift15_receipt_oracle)
        .context("case-0 Lift-15 source is not an exact outer receipt oracle")?;
    ensure!(
        lift15_outer.journal.bytes == statement,
        "case-0 Lift-15 journal differs from the canonical statement"
    );
    lift15_outer
        .verify_with_context(&ctx, image_id)
        .context("case-0 Lift-15 failed stock disabled-dev verification")?;
    ensure!(
        lift15_outer.claim()?.digest() == expected_claim,
        "case-0 Lift-15 is not the exact successful statement claim"
    );
    let InnerReceipt::Succinct(lift15_receipt) = &lift15_outer.inner else {
        bail!("case-0 Lift-15 source is not a direct succinct receipt");
    };
    validate_candidate_terminal_shape(lift15_receipt, CandidateTerminal::Lift(15), &expected_claim)
        .context("case-0 source is not the stock direct Lift-15 shape")?;
    require_successful_empty_assumption_claim(lift15_receipt.claim.as_value()?, expected_claim)
        .context("case-0 Lift-15 claim is not exact and assumption-free")?;

    let terminal_join = authenticate_recursive_oracle_bytes(
        terminal_join_recursive_oracle,
        image_id,
        statement,
        RecursiveFamily::TerminalJoin,
    )
    .context("case-8 terminal-join source authentication failed")?;
    require_terminal_join_source_shape(&terminal_join, image_id, statement)
        .context("case-8 source is not the exact terminal-join graph")?;

    let terminal_resolve = authenticate_recursive_oracle_bytes(
        terminal_resolve_recursive_oracle,
        image_id,
        statement,
        RecursiveFamily::TerminalResolve,
    )
    .context("case-9 terminal-resolve source authentication failed")?;
    require_terminal_resolve_source_shape(&terminal_resolve)
        .context("case-9 source is not the exact terminal-resolve graph")?;

    require_recursive_common_claim(&terminal_join, expected_claim, statement, "case-8")?;
    require_recursive_common_claim(&terminal_resolve, expected_claim, statement, "case-9")?;

    let source = B4AuthenticatedTerminalFixtureSourcesV1 {
        guest_elf: guest_elf.to_vec(),
        statement: statement.to_vec(),
        image_id,
        lift15_receipt_oracle: lift15_receipt_oracle.to_vec(),
        lift15_receipt: lift15_receipt.clone(),
        terminal_join_recursive_oracle: terminal_join_recursive_oracle.to_vec(),
        terminal_join,
        terminal_resolve_recursive_oracle: terminal_resolve_recursive_oracle.to_vec(),
        terminal_resolve,
    };
    case8_allowed_non_ok_receipt(&source)
        .context("case-8 step zero is not the allowed non-OK source")?;
    Ok(source)
}

pub(crate) fn derive_case8_final_join_direct_evidence(
    source: &B4AuthenticatedTerminalFixtureSourcesV1,
) -> Result<B4Case8FinalJoinDirectEvidenceV1> {
    let oracle = authenticate_recursive_oracle_bytes(
        source.terminal_join_recursive_oracle(),
        source.image_id,
        source.statement(),
        RecursiveFamily::TerminalJoin,
    )
    .context("retained case-8 terminal-join source reauthentication failed")?;
    require_terminal_join_source_shape(&oracle, source.image_id, source.statement())
        .context("retained case-8 source is not the exact terminal-join graph")?;
    let expected_claim = ReceiptClaim::ok(source.image_id, source.statement().to_vec()).digest();
    require_recursive_common_claim(
        &oracle,
        expected_claim,
        source.statement(),
        "retained case-8",
    )?;
    let (raw_seal, receipt_oracle) =
        final_b4_terminal_join_direct_evidence(&oracle, source.image_id, source.statement())
            .context("cannot retain the exact case-8 final Join direct evidence")?;
    Ok(B4Case8FinalJoinDirectEvidenceV1 {
        raw_seal,
        receipt_oracle,
    })
}

pub(crate) fn compose_authenticated_b4_terminal_fixture_set(
    prover: &LocalProver,
    authenticated: B4AuthenticatedTerminalFixtureSourcesV1,
) -> Result<B4TerminalFixtureCompositionV1> {
    let case8_direct = derive_case8_final_join_direct_evidence(&authenticated)?;
    let generated = generate_b4_terminal_fixture_set(prover, &authenticated)?;
    Ok(B4TerminalFixtureCompositionV1 {
        authenticated,
        generated,
        case8_direct,
    })
}

/// Generate the exact nine stock B4 terminal fixtures in memory.
///
/// # Errors
///
/// Returns an error until every fixed proof operation and derive-first replay
/// step succeeds.
#[allow(
    clippy::too_many_lines,
    reason = "the fixed nine-node terminal DAG is kept linear for auditability"
)]
pub fn generate_b4_terminal_fixture_set(
    prover: &LocalProver,
    source: &B4AuthenticatedTerminalFixtureSourcesV1,
) -> Result<B4GeneratedTerminalFixtureSetV1> {
    let dev_mode = std::env::var_os("RISC0_DEV_MODE");
    require_terminal_dev_mode_absent(dev_mode.as_deref())?;
    let stock_opts = stock_terminal_prover_opts()?;
    let server = get_prover_server(&stock_opts)
        .context("cannot construct the pinned stock terminal prover")?;
    let ctx = VerifierContext::default().with_dev_mode(false);
    let expected = ReceiptClaim::ok(source.image_id, source.statement.clone()).digest();

    let identity = prove_stock_identity(source, stock_opts.clone(), &ctx)?;
    require_direct_success(&identity, expected, "Identity")?;

    let po2_segment = prove_plain_po2_18_segment(
        prover,
        &source.guest_elf,
        source.image_id,
        &source.statement,
    )?;
    po2_segment.verify_integrity_with_context(&ctx)?;
    let lift_povw_18 = server.lift_povw(&po2_segment)?;
    require_work_receipt(
        &lift_povw_18,
        po2_segment.claim.digest(),
        &ctx,
        "po2-18 Lift-PoVW",
    )?;
    require_single_work_range(&lift_povw_18, &po2_segment, "po2-18 Lift-PoVW")?;

    validate_terminal_join_source_povw(&source.terminal_join, source.image_id, &source.statement)?;
    let InnerReceipt::Composite(join_source) = &source.terminal_join.source_receipt.inner else {
        bail!("case-8 source is not composite");
    };
    ensure!(
        join_source.segments.len() == 2
            && join_source.segments[0].index == 0
            && join_source.segments[1].index == 1,
        "case-8 source indexes changed"
    );
    let work0 = server.lift_povw(&join_source.segments[0])?;
    let work1 = server.lift_povw(&join_source.segments[1])?;
    require_work_receipt(
        &work0,
        join_source.segments[0].claim.digest(),
        &ctx,
        "case-8 work zero",
    )?;
    require_work_receipt(
        &work1,
        join_source.segments[1].claim.digest(),
        &ctx,
        "case-8 work one",
    )?;
    require_single_work_range(&work0, &join_source.segments[0], "case-8 work zero")?;
    require_single_work_range(&work1, &join_source.segments[1], "case-8 work one")?;
    work_value(&work0, "case-8 work zero")?
        .join(work_value(&work1, "case-8 work one")?)
        .context("case-8 work ranges are not contiguous")?;

    let join_povw = server.join_povw(&work0, &work1)?;
    require_work_receipt(&join_povw, expected, &ctx, "Join-PoVW")?;
    require_successful_work(&join_povw, expected, "Join-PoVW")?;
    let join_unwrap = server.join_unwrap_povw(&work0, &work1)?;
    join_unwrap.verify_integrity_with_context(&ctx)?;
    require_direct_success(&join_unwrap, expected, "Join-Unwrap-PoVW")?;

    let InnerReceipt::Composite(resolve_source) = &source.terminal_resolve.source_receipt.inner
    else {
        bail!("case-9 source is not composite");
    };
    ensure!(
        resolve_source.segments.len() == 1 && resolve_source.segments[0].index == 0,
        "case-9 source index changed"
    );
    let conditional = server.lift_povw(&resolve_source.segments[0])?;
    require_work_receipt(
        &conditional,
        resolve_source.segments[0].claim.digest(),
        &ctx,
        "case-9 conditional work",
    )?;
    require_single_work_range(
        &conditional,
        &resolve_source.segments[0],
        "case-9 conditional work",
    )?;
    let assumption = source
        .terminal_resolve
        .assumption_receipt
        .as_ref()
        .context("case-9 assumption is absent")?;
    let InnerReceipt::Succinct(assumption) = &assumption.inner else {
        bail!("case-9 assumption is not succinct");
    };
    assumption.verify_integrity_with_context(&ctx)?;
    ensure!(
        assumption.claim.digest() == expected,
        "case-9 assumption claim changed"
    );
    let unknown_assumption = assumption.clone().into_unknown();
    let resolve_povw = server.resolve_povw(&conditional, &unknown_assumption)?;
    require_work_receipt(&resolve_povw, expected, &ctx, "Resolve-PoVW")?;
    require_successful_work(&resolve_povw, expected, "Resolve-PoVW")?;
    let resolve_unwrap = server.resolve_unwrap_povw(&conditional, &unknown_assumption)?;
    resolve_unwrap.verify_integrity_with_context(&ctx)?;
    require_direct_success(&resolve_unwrap, expected, "Resolve-Unwrap-PoVW")?;

    require_equal_union_source_claims(identity.claim.digest(), join_unwrap.claim.digest())?;
    let union = server.union(
        &identity.clone().into_unknown(),
        &join_unwrap.clone().into_unknown(),
    )?;
    union.verify_integrity_with_context(&ctx)?;
    let unwrap = server.unwrap_povw(&join_povw)?;
    unwrap.verify_integrity_with_context(&ctx)?;
    require_direct_success(&unwrap, expected, "Unwrap-PoVW")?;
    let allowed = case8_allowed_non_ok_receipt(source)?;
    allowed.verify_integrity_with_context(&ctx)?;

    let mut raw_seals = BTreeMap::new();
    let mut receipt_oracles = BTreeMap::new();
    insert_fixture(
        &mut raw_seals,
        &mut receipt_oracles,
        TERMINAL_FIXTURE_RECIPES[0],
        &identity,
    )?;
    insert_fixture(
        &mut raw_seals,
        &mut receipt_oracles,
        TERMINAL_FIXTURE_RECIPES[1],
        &lift_povw_18,
    )?;
    insert_fixture(
        &mut raw_seals,
        &mut receipt_oracles,
        TERMINAL_FIXTURE_RECIPES[2],
        &join_povw,
    )?;
    insert_fixture(
        &mut raw_seals,
        &mut receipt_oracles,
        TERMINAL_FIXTURE_RECIPES[3],
        &join_unwrap,
    )?;
    insert_fixture(
        &mut raw_seals,
        &mut receipt_oracles,
        TERMINAL_FIXTURE_RECIPES[4],
        &resolve_povw,
    )?;
    insert_fixture(
        &mut raw_seals,
        &mut receipt_oracles,
        TERMINAL_FIXTURE_RECIPES[5],
        &resolve_unwrap,
    )?;
    insert_fixture(
        &mut raw_seals,
        &mut receipt_oracles,
        TERMINAL_FIXTURE_RECIPES[6],
        &union,
    )?;
    insert_fixture(
        &mut raw_seals,
        &mut receipt_oracles,
        TERMINAL_FIXTURE_RECIPES[7],
        &unwrap,
    )?;
    insert_fixture(
        &mut raw_seals,
        &mut receipt_oracles,
        TERMINAL_FIXTURE_RECIPES[8],
        allowed,
    )?;
    finalize_generated_terminal_fixture_set(raw_seals, receipt_oracles)
}

fn require_terminal_dev_mode_absent(value: Option<&std::ffi::OsStr>) -> Result<()> {
    ensure!(
        value.is_none(),
        "RISC0_DEV_MODE must be absent for terminal-fixture generation"
    );
    Ok(())
}

fn stock_terminal_prover_opts() -> Result<ProverOpts> {
    let options = ProverOpts::succinct()
        .with_hashfn("poseidon2".to_owned())
        .with_control_ids(ALLOWED_CONTROL_IDS.to_vec())
        .with_dev_mode(false)
        .with_prove_guest_errors(false);
    ensure!(
        options.receipt_kind == ReceiptKind::Succinct
            && options.hashfn == "poseidon2"
            && options.control_ids.as_slice() == ALLOWED_CONTROL_IDS
            && !options.dev_mode()
            && !options.prove_guest_errors,
        "stock terminal prover options drifted"
    );
    Ok(options)
}

fn require_equal_union_source_claims(left: Digest, right: Digest) -> Result<()> {
    ensure!(
        left == right,
        "Identity and Join-Unwrap source claims differ"
    );
    Ok(())
}

fn prove_stock_identity(
    source: &B4AuthenticatedTerminalFixtureSourcesV1,
    options: ProverOpts,
    ctx: &VerifierContext,
) -> Result<SuccinctReceipt<ReceiptClaim>> {
    let mut prover = RecursionProver::new_identity(&source.lift15_receipt, options)?;
    let control_id = *prover.control_id();
    let proof = prover.control_inclusion_proof()?;
    let recursion_receipt = prover.run()?;
    let decoded = ReceiptClaim::decode(&mut recursion_receipt.out_stream())?;
    ensure!(
        decoded.digest() == source.lift15_receipt.claim.digest(),
        "Identity output claim changed"
    );
    ensure!(
        control_id == ALLOWED_CONTROL_IDS[0] && proof.index == 0,
        "Identity control/index changed"
    );
    let suites = VerifierContext::default_hash_suites();
    let suite = suites
        .get("poseidon2")
        .context("Poseidon2 suite is absent")?;
    ensure!(
        proof.root(&control_id, suite.hashfn.as_ref()) == ALLOWED_CONTROL_ROOT,
        "Identity inclusion proof has wrong root"
    );
    let parameters = SuccinctReceiptVerifierParameters::default().digest();
    let receipt = assemble_succinct_receipt(
        recursion_receipt.seal,
        control_id,
        source.lift15_receipt.claim.clone(),
        "poseidon2".to_owned(),
        parameters,
        proof,
    )?;
    ensure!(
        receipt.verifier_parameters == parameters
            && receipt.claim.digest() == source.lift15_receipt.claim.digest(),
        "assembled Identity changed claim or parameters"
    );
    receipt.verify_integrity_with_context(ctx)?;
    Ok(receipt)
}

fn require_direct_success(
    receipt: &SuccinctReceipt<ReceiptClaim>,
    expected: Digest,
    label: &str,
) -> Result<()> {
    require_successful_empty_assumption_claim(receipt.claim.as_value()?, expected)
        .with_context(|| format!("{label} is not the common success"))
}

fn work_value<'a>(
    receipt: &'a SuccinctReceipt<WorkClaim<ReceiptClaim>>,
    label: &str,
) -> Result<&'a risc0_zkvm::Work> {
    receipt
        .claim
        .as_value()
        .with_context(|| format!("{label} claim is pruned"))?
        .work
        .as_value()
        .with_context(|| format!("{label} work is pruned"))
}

fn require_work_receipt(
    receipt: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
    expected: Digest,
    ctx: &VerifierContext,
    label: &str,
) -> Result<()> {
    receipt.verify_integrity_with_context(ctx)?;
    let claim = receipt
        .claim
        .as_value()
        .with_context(|| format!("{label} claim is pruned"))?;
    ensure!(
        claim.claim.digest() == expected && claim.work.as_value().is_ok(),
        "{label} source claim/work changed"
    );
    Ok(())
}

fn require_successful_work(
    receipt: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
    expected: Digest,
    label: &str,
) -> Result<()> {
    let application = receipt
        .claim
        .as_value()?
        .claim
        .as_value()
        .with_context(|| format!("{label} application is pruned"))?;
    require_successful_empty_assumption_claim(application, expected)
}

fn require_single_work_range(
    receipt: &SuccinctReceipt<WorkClaim<ReceiptClaim>>,
    segment: &SegmentReceipt,
    label: &str,
) -> Result<()> {
    let nonce = segment.povw_nonce()?;
    let work = work_value(receipt, label)?;
    ensure!(
        work.nonce_min == nonce && work.nonce_max == nonce,
        "{label} is not one exact source nonce"
    );
    Ok(())
}

fn insert_fixture<Claim>(
    raw: &mut BTreeMap<String, Vec<u8>>,
    oracles: &mut BTreeMap<String, Vec<u8>>,
    recipe: TerminalFixtureRecipe,
    receipt: &SuccinctReceipt<Claim>,
) -> Result<()>
where
    Claim: Digestible,
    SuccinctReceipt<Claim>: Serialize + DeserializeOwned,
{
    let id = recipe.fixture_id();
    let seal = receipt.get_seal_bytes();
    let oracle = encode_succinct_receipt_oracle(receipt)?;
    ensure!(
        seal.len() == PROOF_BYTES && !oracle.is_empty(),
        "{id} has invalid artifact lengths"
    );
    ensure!(
        raw.insert(terminal_fixture_raw_seal_path(id)?, seal)
            .is_none(),
        "{id} duplicates a raw path"
    );
    ensure!(
        oracles
            .insert(terminal_fixture_receipt_oracle_path(id)?, oracle)
            .is_none(),
        "{id} duplicates an oracle path"
    );
    Ok(())
}

fn finalize_generated_terminal_fixture_set(
    raw_seals: BTreeMap<String, Vec<u8>>,
    receipt_oracles: BTreeMap<String, Vec<u8>>,
) -> Result<B4GeneratedTerminalFixtureSetV1> {
    ensure!(
        raw_seals.len() == TERMINAL_FIXTURE_RECIPES.len()
            && receipt_oracles.len() == TERMINAL_FIXTURE_RECIPES.len(),
        "generated terminal fixture maps do not each contain exactly nine entries"
    );
    ensure!(
        TERMINAL_FIXTURE_RECIPES
            .iter()
            .zip(B4_TERMINAL_FIXTURE_LAYOUT)
            .all(|(recipe, layout)| recipe.fixture_id() == layout.fixture_id),
        "fixed terminal recipe order differs from the compiled layout"
    );
    for layout in B4_TERMINAL_FIXTURE_LAYOUT {
        let raw_path = terminal_fixture_raw_seal_path(layout.fixture_id)?;
        let oracle_path = terminal_fixture_receipt_oracle_path(layout.fixture_id)?;
        ensure!(
            raw_seals
                .get(&raw_path)
                .is_some_and(|bytes| bytes.len() == PROOF_BYTES),
            "{} raw seal is absent or has wrong length",
            layout.fixture_id
        );
        ensure!(
            receipt_oracles
                .get(&oracle_path)
                .is_some_and(|bytes| !bytes.is_empty()),
            "{} receipt oracle is absent or empty",
            layout.fixture_id
        );
    }
    let replay = replay_fixed_terminal_oracles(&raw_seals, &receipt_oracles)?;
    let catalogue_jcs = replay.derived_catalogue_jcs()?;
    replay.bind_candidate_catalogue_jcs(&catalogue_jcs)?;
    Ok(B4GeneratedTerminalFixtureSetV1 {
        catalogue_jcs,
        raw_seals,
        receipt_oracles,
    })
}

fn require_successful_empty_assumption_claim(
    claim: &ReceiptClaim,
    expected_claim: Digest,
) -> Result<()> {
    ensure!(
        claim.digest() == expected_claim && claim.exit_code == ExitCode::Halted(0),
        "claim is not exact successful execution"
    );
    let output = claim
        .output
        .as_value()
        .context("successful claim output is pruned")?
        .as_ref()
        .context("successful claim has no output")?;
    ensure!(
        output.assumptions.is_empty(),
        "successful claim has nonempty assumptions"
    );
    Ok(())
}

fn require_terminal_join_source_shape(
    oracle: &RecursiveOracle,
    image_id: Digest,
    statement: &[u8],
) -> Result<()> {
    let InnerReceipt::Composite(source) = &oracle.source_receipt.inner else {
        bail!("terminal-join source receipt is not composite");
    };
    ensure!(
        source.segments.len() == 2
            && source.assumption_receipts.is_empty()
            && oracle.assumption_receipt.is_none()
            && oracle.final_step == 2
            && oracle.steps.len() == 3
            && is_lift_step(&oracle.steps[0], 0, 0)
            && is_lift_step(&oracle.steps[1], 1, 1)
            && oracle.steps[2].ordinal == 2
            && oracle.steps[2].operation == RecursiveOperation::Join
            && oracle.steps[2].inputs
                == (RecursiveInputs::Join {
                    left_step: 0,
                    right_step: 1,
                }),
        "terminal-join source is not [Lift(0), Lift(1), Join(0,1)]"
    );
    validate_terminal_join_source_povw(oracle, image_id, statement)
        .context("terminal-join source PoVW nonces are not canonical")?;
    Ok(())
}

fn require_terminal_resolve_source_shape(oracle: &RecursiveOracle) -> Result<()> {
    let InnerReceipt::Composite(source) = &oracle.source_receipt.inner else {
        bail!("terminal-resolve source receipt is not composite");
    };
    ensure!(
        source.segments.len() == 1
            && source.assumption_receipts.len() == 1
            && oracle.assumption_receipt.is_some()
            && oracle.final_step == 1
            && oracle.steps.len() == 2
            && is_lift_step(&oracle.steps[0], 0, 0)
            && oracle.steps[1].ordinal == 1
            && oracle.steps[1].operation == RecursiveOperation::Resolve
            && oracle.steps[1].inputs
                == (RecursiveInputs::Resolve {
                    conditional_step: 0,
                }),
        "terminal-resolve source is not [Lift(0), Resolve(0)]"
    );
    Ok(())
}

fn is_lift_step(step: &RecursiveStep, ordinal: u32, segment_index: u32) -> bool {
    step.ordinal == ordinal
        && step.operation == RecursiveOperation::Lift
        && step.inputs == (RecursiveInputs::Lift { segment_index })
}

fn require_recursive_common_claim(
    oracle: &RecursiveOracle,
    expected_claim: Digest,
    statement: &[u8],
    label: &str,
) -> Result<()> {
    ensure!(
        oracle.source_receipt.journal.bytes == statement,
        "{label} source journal differs from the canonical statement"
    );
    let final_step = oracle
        .steps
        .get(
            usize::try_from(oracle.final_step)
                .with_context(|| format!("{label} final-step index does not fit usize"))?,
        )
        .with_context(|| format!("{label} final step is absent"))?;
    ensure!(
        final_step.receipt.claim.digest() == expected_claim,
        "{label} final claim differs from the common successful statement claim"
    );
    require_successful_empty_assumption_claim(final_step.receipt.claim.as_value()?, expected_claim)
        .with_context(|| format!("{label} final claim is not exact and assumption-free"))
}

fn case8_allowed_non_ok_receipt(
    source: &B4AuthenticatedTerminalFixtureSourcesV1,
) -> Result<&SuccinctReceipt<ReceiptClaim>> {
    let InnerReceipt::Composite(composite) = &source.terminal_join.source_receipt.inner else {
        bail!("case-8 source receipt is not composite");
    };
    ensure!(
        composite.segments.len() == 2,
        "case-8 source does not have exactly two segments"
    );
    let segment = &composite.segments[0];
    ensure!(
        segment.index == 0,
        "case-8 source segment zero has wrong index"
    );
    let step = &source.terminal_join.steps[0];
    ensure!(
        is_lift_step(step, 0, 0),
        "case-8 allowed source is not ancestry step zero Lift(0)"
    );
    let segment_claim = &segment.claim;
    let step_claim = step
        .receipt
        .claim
        .as_value()
        .context("case-8 step-zero claim is pruned")?;
    ensure!(
        segment_claim.digest() == step_claim.digest()
            && step.receipt.claim.digest() == segment.claim.digest(),
        "case-8 step zero is not linked to source segment zero"
    );
    require_case8_system_split_claim(step_claim, source.image_id)?;
    let po2 = crate::normal_lift_segment_po2(&step.receipt.control_id)?;
    ensure!(
        (15..=22).contains(&po2),
        "case-8 step-zero Lift exponent is outside 15..=22"
    );
    validate_candidate_terminal_shape(
        &step.receipt,
        CandidateTerminal::Lift(po2),
        &step_claim.digest(),
    )
    .context("case-8 step zero is not the expected stock normal Lift")?;
    step.receipt
        .verify_integrity_with_context(&VerifierContext::default().with_dev_mode(false))
        .context("case-8 step-zero receipt failed disabled-dev integrity verification")?;
    Ok(&step.receipt)
}

fn require_case8_system_split_claim(claim: &ReceiptClaim, image_id: Digest) -> Result<()> {
    ensure!(
        claim.exit_code == ExitCode::SystemSplit,
        "case-8 allowed claim is not SystemSplit"
    );
    ensure!(
        matches!(&claim.output, MaybePruned::Value(None)),
        "case-8 allowed claim output is not exactly opened None"
    );
    ensure!(
        claim.pre.digest() == image_id,
        "case-8 allowed claim does not begin at the guest image ID"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use eip_0045_reproduction::{
        b4_terminal::{
            B4_TERMINAL_FIXTURE_LAYOUT, terminal_fixture_raw_seal_path,
            terminal_fixture_receipt_oracle_path,
        },
        constants::PROOF_BYTES,
    };
    use risc0_zkvm::{
        ALLOWED_CONTROL_IDS, Digest, ExitCode, LocalProver, MaybePruned, ReceiptClaim, ReceiptKind,
    };

    use super::{
        B4AuthenticatedTerminalFixtureSourcesV1, B4Case8FinalJoinDirectEvidenceV1,
        B4GeneratedTerminalFixtureSetV1, B4TerminalFixtureCompositionV1, TERMINAL_FIXTURE_RECIPES,
        TerminalFixtureRecipe, authenticate_b4_terminal_fixture_sources,
        compose_authenticated_b4_terminal_fixture_set, derive_case8_final_join_direct_evidence,
        finalize_generated_terminal_fixture_set, generate_b4_terminal_fixture_set,
        require_case8_system_split_claim, require_equal_union_source_claims,
        require_terminal_dev_mode_absent, stock_terminal_prover_opts,
    };

    #[test]
    #[allow(clippy::type_complexity)]
    fn authenticated_terminal_fixture_source_api_is_closed() {
        let _: fn(
            &[u8],
            &[u8],
            &[u8],
            &[u8],
            &[u8],
        ) -> anyhow::Result<B4AuthenticatedTerminalFixtureSourcesV1> =
            authenticate_b4_terminal_fixture_sources;
    }

    #[test]
    fn case8_final_join_direct_evidence_api_is_selector_free() {
        let _: fn(&B4AuthenticatedTerminalFixtureSourcesV1) -> &[u8] =
            B4AuthenticatedTerminalFixtureSourcesV1::guest_elf;
        let _: fn(&B4AuthenticatedTerminalFixtureSourcesV1) -> &[u8] =
            B4AuthenticatedTerminalFixtureSourcesV1::statement;
        let _: fn(&B4AuthenticatedTerminalFixtureSourcesV1) -> &[u8] =
            B4AuthenticatedTerminalFixtureSourcesV1::lift15_receipt_oracle;
        let _: fn(&B4AuthenticatedTerminalFixtureSourcesV1) -> &[u8] =
            B4AuthenticatedTerminalFixtureSourcesV1::terminal_join_recursive_oracle;
        let _: fn(&B4AuthenticatedTerminalFixtureSourcesV1) -> &[u8] =
            B4AuthenticatedTerminalFixtureSourcesV1::terminal_resolve_recursive_oracle;
        let _: fn(
            &B4AuthenticatedTerminalFixtureSourcesV1,
        ) -> anyhow::Result<B4Case8FinalJoinDirectEvidenceV1> =
            derive_case8_final_join_direct_evidence;
        let _: fn(&B4Case8FinalJoinDirectEvidenceV1) -> &[u8] =
            B4Case8FinalJoinDirectEvidenceV1::raw_seal;
        let _: fn(&B4Case8FinalJoinDirectEvidenceV1) -> &[u8] =
            B4Case8FinalJoinDirectEvidenceV1::receipt_oracle;
        let _: fn(
            &LocalProver,
            B4AuthenticatedTerminalFixtureSourcesV1,
        ) -> anyhow::Result<B4TerminalFixtureCompositionV1> =
            compose_authenticated_b4_terminal_fixture_set;
        let _: fn(
            B4TerminalFixtureCompositionV1,
        ) -> (
            B4AuthenticatedTerminalFixtureSourcesV1,
            B4GeneratedTerminalFixtureSetV1,
            B4Case8FinalJoinDirectEvidenceV1,
        ) = B4TerminalFixtureCompositionV1::into_parts;
    }

    #[test]
    fn generated_terminal_fixture_api_is_selector_free_and_read_only() {
        let _: fn(
            &LocalProver,
            &B4AuthenticatedTerminalFixtureSourcesV1,
        ) -> anyhow::Result<B4GeneratedTerminalFixtureSetV1> = generate_b4_terminal_fixture_set;
        let _: fn(&B4GeneratedTerminalFixtureSetV1) -> &[u8] =
            B4GeneratedTerminalFixtureSetV1::catalogue_jcs;
        let _: fn(&B4GeneratedTerminalFixtureSetV1) -> &BTreeMap<String, Vec<u8>> =
            B4GeneratedTerminalFixtureSetV1::raw_seals;
        let _: fn(&B4GeneratedTerminalFixtureSetV1) -> &BTreeMap<String, Vec<u8>> =
            B4GeneratedTerminalFixtureSetV1::receipt_oracles;
    }

    #[test]
    fn terminal_fixture_recipes_match_the_closed_layout_in_exact_order() {
        let actual = TERMINAL_FIXTURE_RECIPES.map(TerminalFixtureRecipe::fixture_id);
        let expected = B4_TERMINAL_FIXTURE_LAYOUT.map(|layout| layout.fixture_id);
        assert_eq!(actual, expected);
        assert_eq!(
            TerminalFixtureRecipe::IdentityFromCase0Lift15.fixture_id(),
            "lift-po2-14"
        );
        assert_eq!(
            B4_TERMINAL_FIXTURE_LAYOUT[0].expected_family,
            Some("identity")
        );
    }

    #[test]
    fn path_shaped_synthetic_fixture_pairs_cannot_finalize_a_generated_set() {
        let mut raw_seals = BTreeMap::new();
        let mut receipt_oracles = BTreeMap::new();
        for layout in B4_TERMINAL_FIXTURE_LAYOUT {
            raw_seals.insert(
                terminal_fixture_raw_seal_path(layout.fixture_id).unwrap(),
                vec![0_u8; PROOF_BYTES],
            );
            receipt_oracles.insert(
                terminal_fixture_receipt_oracle_path(layout.fixture_id).unwrap(),
                vec![0_u8],
            );
        }

        assert!(
            finalize_generated_terminal_fixture_set(raw_seals, receipt_oracles).is_err(),
            "only cryptographic derive-first replay may construct success"
        );
    }

    #[test]
    fn terminal_prover_options_and_environment_policy_are_closed() {
        let options = stock_terminal_prover_opts().unwrap();
        assert_eq!(options.receipt_kind, ReceiptKind::Succinct);
        assert_eq!(options.hashfn, "poseidon2");
        assert_eq!(options.control_ids.as_slice(), ALLOWED_CONTROL_IDS);
        assert!(!options.dev_mode());
        assert!(!options.prove_guest_errors);

        require_terminal_dev_mode_absent(None).unwrap();
        assert!(
            require_terminal_dev_mode_absent(Some(std::ffi::OsStr::new("non-unicode-safe")))
                .is_err()
        );
    }

    #[test]
    fn equal_union_source_claims_are_the_required_dag_shape() {
        let common = Digest::from([13_u32; 8]);
        require_equal_union_source_claims(common, common).unwrap();
        assert!(require_equal_union_source_claims(common, Digest::from([14_u32; 8])).is_err());
    }

    #[test]
    fn allowed_non_ok_claim_is_exact_system_split_at_the_guest_pre_state() {
        let image_id = Digest::from([7_u32; 8]);
        let mut claim = ReceiptClaim::ok(image_id, Vec::<u8>::new());
        claim.exit_code = ExitCode::SystemSplit;
        claim.output = MaybePruned::Value(None);
        require_case8_system_split_claim(&claim, image_id).unwrap();

        let mut halted = claim.clone();
        halted.exit_code = ExitCode::Halted(1);
        assert!(require_case8_system_split_claim(&halted, image_id).is_err());

        let mut wrong_pre = claim;
        wrong_pre.pre = MaybePruned::Pruned(Digest::ZERO);
        assert!(require_case8_system_split_claim(&wrong_pre, image_id).is_err());
    }

    #[test]
    fn case8_step_one_claim_is_rejected_by_the_same_non_ok_validator() {
        let image_id = Digest::from([7_u32; 8]);
        let step_one_claim = ReceiptClaim::ok(image_id, b"step-one".to_vec());
        let error = require_case8_system_split_claim(&step_one_claim, image_id).unwrap_err();
        assert!(error.to_string().contains("not SystemSplit"));
    }
}
