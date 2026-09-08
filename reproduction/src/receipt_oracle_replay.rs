//! Single compiled replay authority for stock RISC Zero succinct receipts.
//!
//! Receipt decoding and cryptographic verification are separated by an opaque
//! typestate boundary. No receipt claim is exposed until the stock verifier
//! has accepted the seal.

use std::{
    collections::BTreeMap,
    fmt,
    io::Cursor,
    rc::Rc,
    sync::atomic::{AtomicU32, Ordering},
    thread,
};

use bincode::Options as _;
use risc0_circuit_recursion::{CIRCUIT, control_id::POSEIDON2_CONTROL_IDS};
use risc0_zkp::{
    adapter::{CircuitInfo, PROOF_SYSTEM_INFO},
    core::hash::{
        HashFn, HashSuite, Rng,
        poseidon2::{Poseidon2HashSuite, Poseidon2Rng},
    },
    field::{
        ExtElem as _,
        baby_bear::{BabyBear, BabyBearElem, BabyBearExtElem},
    },
    verify::{VerificationCheckpoint, VerificationError},
};
use risc0_zkvm::{
    ALLOWED_CONTROL_IDS, ALLOWED_CONTROL_ROOT, Digest, MaybePruned, ReceiptClaim, SuccinctReceipt,
    SuccinctReceiptVerifierParameters, UnionClaim, VerifierContext, WorkClaim,
    sha::Digestible as _,
};
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    b4_terminal::{
        B4_STOCK_CONTROL_COUNT, B4_STOCK_CONTROL_LAYOUT, B4_TERMINAL_FIXTURE_RISC0_VERSION,
        B4StockControlLayoutV1,
    },
    constants::{PROOF_WORDS, RISC0_INNER_CONTROL_ROOT_HEX, RISC0_OUTER_PO2},
    receipt_oracle_codec::{RECEIPT_ORACLE_MAX_BYTES, receipt_oracle_bincode_options},
    seal::decode_seal_words,
};

const CONTROL_INCLUSION_PROOF_DEPTH: usize = 8;
const BABY_BEAR_MODULUS: u32 = 15 * (1 << 27) + 1;
const EXPECTED_VERIFIER_PARAMETERS_HEX: &str =
    "ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013";

const DIRECT_SEAL_WORDS: usize = 55_667;
const DIGEST_WORDS: usize = 8;
const MERKLE_TOP_DIGESTS: usize = 32;
const MERKLE_TOP_WORDS: usize = DIGEST_WORDS * MERKLE_TOP_DIGESTS;
const OUTPUT_WITH_PO2_END: usize = 33;
const CODE_TOP_START: usize = 33;
const DATA_TOP_START: usize = 289;
const ACCUM_TOP_START: usize = 545;
const CHECK_TOP_START: usize = 801;
const COEFF_U_START: usize = 1_057;
const FRI_ROUND_ONE_TOP_START: usize = 3_693;
const FRI_ROUND_TWO_TOP_START: usize = 3_949;
const FRI_ROUND_THREE_TOP_START: usize = 4_205;
const FINAL_COEFFICIENTS_START: usize = 4_461;
const QUERIES_START: usize = 4_717;
const QUERY_WORDS: usize = 1_019;
const QUERY_ZERO_FRI_ROUND_ONE_START: usize = 5_376;
const QUERY_ZERO_FRI_ROUND_THREE_START: usize = 5_648;
const FRI_LEAF_WORDS: usize = 64;
const FRI_ORIGINAL_DOMAIN: usize = 1 << 20;
const FRI_ROUND_ONE_DOMAIN: usize = 1 << 16;
const FRI_ROUND_THREE_DOMAIN: usize = 1 << 8;
const MAX_Q0_GRIND_ATTEMPTS: u32 = 1 << 24;

const _: () = assert!(PROOF_WORDS == DIRECT_SEAL_WORDS);
const _: () = assert!(QUERIES_START + 50 * QUERY_WORDS == DIRECT_SEAL_WORDS);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StockReceiptReplayErrorKind {
    ArtifactLength,
    ReceiptDecode,
    ReceiptReencode,
    /// Defense in depth for future custom serde behavior. Standard tracked
    /// RISC Zero receipt types currently round-trip byte-exactly after decode.
    ReceiptEncodingNotExact,
    CompiledAuthorityDrift,
    ReceiptProfileShape,
    ReceiptCryptographicVerification,
}

#[derive(Debug)]
pub(crate) struct StockReceiptReplayError {
    kind: StockReceiptReplayErrorKind,
    detail: String,
}

impl StockReceiptReplayError {
    fn new(kind: StockReceiptReplayErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    pub(crate) const fn kind(&self) -> StockReceiptReplayErrorKind {
        self.kind
    }

    pub(crate) fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for StockReceiptReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for StockReceiptReplayError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectSealMutationErrorKind {
    Shape,
    Derivation,
    Agreement,
    CompiledAuthorityDrift,
}

/// Closed mutation sites derivable from an authenticated direct succinct seal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectSealCheckpointMutationV1 {
    ValidityCheck,
    FriRoundTwoQueryZero,
    FriFinalPolynomialQueryZero,
    FriInnerQueryFortyNine,
}

impl DirectSealCheckpointMutationV1 {
    const fn checkpoint(self) -> VerificationCheckpoint {
        match self {
            Self::ValidityCheck => VerificationCheckpoint::ValidityCheck,
            Self::FriRoundTwoQueryZero => {
                VerificationCheckpoint::FriRoundGoal { query: 0, round: 1 }
            }
            Self::FriFinalPolynomialQueryZero => {
                VerificationCheckpoint::FriFinalPolynomial { query: 0 }
            }
            Self::FriInnerQueryFortyNine => VerificationCheckpoint::FriInnerQuery { query: 49 },
        }
    }
}

#[derive(Debug)]
pub(crate) struct DirectSealMutationError {
    kind: DirectSealMutationErrorKind,
    detail: String,
}

impl DirectSealMutationError {
    fn new(kind: DirectSealMutationErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    pub(crate) const fn kind(&self) -> DirectSealMutationErrorKind {
        self.kind
    }

    pub(crate) fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for DirectSealMutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for DirectSealMutationError {}

pub(crate) struct CompiledStockSuccinctReplayV1 {
    context: Rc<VerifierContext>,
    parameters_digest: Digest,
    control_root: Digest,
}

pub(crate) struct DecodedStockSuccinctReceiptV1<Claim> {
    receipt: SuccinctReceipt<Claim>,
    stock: &'static B4StockControlLayoutV1,
}

impl<Claim> DecodedStockSuccinctReceiptV1<Claim> {
    pub(crate) const fn stock(&self) -> &'static B4StockControlLayoutV1 {
        self.stock
    }
}

pub(crate) struct VerifiedStockSuccinctReceiptV1<Claim> {
    receipt: SuccinctReceipt<Claim>,
    stock: &'static B4StockControlLayoutV1,
    control_root: Digest,
    context: Rc<VerifierContext>,
}

impl<Claim> fmt::Debug for VerifiedStockSuccinctReceiptV1<Claim> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedStockSuccinctReceiptV1")
            .field("stock_index", &self.stock.stock_index)
            .field("control_root", &self.control_root)
            .finish_non_exhaustive()
    }
}

impl<Claim> VerifiedStockSuccinctReceiptV1<Claim> {
    pub(crate) const fn stock(&self) -> &'static B4StockControlLayoutV1 {
        self.stock
    }

    pub(crate) const fn claim(&self) -> &MaybePruned<Claim> {
        &self.receipt.claim
    }

    pub(crate) fn claim_digest(&self) -> Digest
    where
        Claim: StockClaimV1,
    {
        Claim::claim_digest(&self.receipt.claim)
    }

    pub(crate) const fn control_id(&self) -> Digest {
        self.receipt.control_id
    }

    pub(crate) const fn control_root(&self) -> Digest {
        self.control_root
    }

    /// Exact little-endian raw seal accepted by the full stock receipt verifier.
    pub(crate) fn raw_seal_bytes(&self) -> Vec<u8> {
        self.receipt.get_seal_bytes()
    }
}

/// Opaque typed trace from one stock/instrumented direct-seal comparison.
pub(crate) struct DirectSealMutationTraceV1 {
    checkpoints: Vec<VerificationCheckpoint>,
}

impl fmt::Debug for DirectSealMutationTraceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectSealMutationTraceV1")
            .field("checkpoint_count", &self.checkpoints.len())
            .finish_non_exhaustive()
    }
}

impl DirectSealMutationTraceV1 {
    /// Return the exact typed checkpoints emitted by the pinned verifier.
    pub(crate) fn checkpoints(&self) -> &[VerificationCheckpoint] {
        &self.checkpoints
    }
}

pub(crate) trait StockClaimV1: Sized {
    fn verify_integrity(
        receipt: &SuccinctReceipt<Self>,
        context: &VerifierContext,
    ) -> Result<(), String>;

    fn claim_digest(claim: &MaybePruned<Self>) -> Digest;
}

macro_rules! impl_stock_claim {
    ($($claim:ty),+ $(,)?) => {
        $(
            impl StockClaimV1 for $claim {
                fn verify_integrity(
                    receipt: &SuccinctReceipt<Self>,
                    context: &VerifierContext,
                ) -> Result<(), String> {
                    receipt
                        .verify_integrity_with_context(context)
                        .map_err(|error| error.to_string())
                }

                fn claim_digest(claim: &MaybePruned<Self>) -> Digest {
                    claim.digest()
                }
            }
        )+
    };
}

impl_stock_claim!(ReceiptClaim, WorkClaim<ReceiptClaim>, UnionClaim,);

impl CompiledStockSuccinctReplayV1 {
    pub(crate) fn from_compiled_profile() -> Result<Self, StockReceiptReplayError> {
        if risc0_zkvm::VERSION != B4_TERMINAL_FIXTURE_RISC0_VERSION {
            return authority_drift("compiled risc0-zkvm version differs from 3.0.5");
        }
        if ALLOWED_CONTROL_IDS.len() != B4_STOCK_CONTROL_COUNT {
            return authority_drift(
                "compiled ALLOWED_CONTROL_IDS does not contain exactly 27 rows",
            );
        }
        validate_compiled_control_words(ALLOWED_CONTROL_IDS)?;
        for (index, (compiled, frozen)) in ALLOWED_CONTROL_IDS
            .iter()
            .zip(B4_STOCK_CONTROL_LAYOUT)
            .enumerate()
        {
            let mut upstream_rows = POSEIDON2_CONTROL_IDS
                .iter()
                .filter(|(_, control_id)| control_id == compiled);
            let upstream_row = upstream_rows.next();
            if frozen.stock_index as usize != index
                || digest_hex(compiled) != frozen.control_id
                || upstream_rows.next().is_some()
                || !matches!(
                    upstream_row,
                    Some((program, control_id))
                        if *program == frozen.upstream_program && control_id == compiled
                )
            {
                return authority_drift(
                    "compiled control ID or upstream program differs from the frozen table",
                );
            }
        }
        if digest_hex(&ALLOWED_CONTROL_ROOT) != RISC0_INNER_CONTROL_ROOT_HEX {
            return authority_drift("compiled Poseidon2 control root differs from the frozen root");
        }

        let parameters = SuccinctReceiptVerifierParameters::default();
        if parameters.control_root != ALLOWED_CONTROL_ROOT
            || parameters.inner_control_root.is_some()
        {
            return authority_drift(
                "compiled succinct verifier parameters do not bind exactly the stock root",
            );
        }
        let parameters_digest = parameters.digest();
        if digest_hex(&parameters_digest) != EXPECTED_VERIFIER_PARAMETERS_HEX {
            return authority_drift("compiled succinct verifier-parameter digest drifted");
        }

        let mut default_suites = VerifierContext::default_hash_suites();
        let poseidon2 = default_suites.remove("poseidon2").ok_or_else(|| {
            StockReceiptReplayError::new(
                StockReceiptReplayErrorKind::CompiledAuthorityDrift,
                "compiled verifier has no Poseidon2 hash suite",
            )
        })?;
        let context = VerifierContext::empty()
            .with_suites(BTreeMap::from([("poseidon2".to_owned(), poseidon2)]))
            .with_succinct_verifier_parameters(parameters)
            .with_dev_mode(false);

        Ok(Self {
            context: Rc::new(context),
            parameters_digest,
            control_root: ALLOWED_CONTROL_ROOT,
        })
    }

    #[cfg(feature = "negative-materialization-set")]
    #[cfg_attr(
        not(any(test, target_os = "linux")),
        allow(
            dead_code,
            reason = "the sole production caller is the Linux descriptor-rooted E6 closure"
        )
    )]
    pub(crate) fn context(&self) -> &VerifierContext {
        &self.context
    }

    #[cfg(feature = "negative-materialization-set")]
    #[cfg_attr(
        not(any(test, target_os = "linux")),
        allow(
            dead_code,
            reason = "the sole production caller is the Linux descriptor-rooted E6 closure"
        )
    )]
    pub(crate) const fn parameters_digest(&self) -> Digest {
        self.parameters_digest
    }

    pub(crate) fn decode_direct(
        &self,
        bytes: &[u8],
    ) -> Result<DecodedStockSuccinctReceiptV1<ReceiptClaim>, StockReceiptReplayError> {
        self.decode(bytes)
    }

    /// Decode and verify one direct receipt oracle using the raw seal encoded
    /// by that exact oracle.
    pub(crate) fn verify_direct_oracle(
        &self,
        receipt_oracle: &[u8],
    ) -> Result<VerifiedStockSuccinctReceiptV1<ReceiptClaim>, StockReceiptReplayError> {
        let decoded = self.decode_direct(receipt_oracle)?;
        let original_raw_seal = decoded.receipt.get_seal_bytes();
        self.verify(decoded, &original_raw_seal)
    }

    pub(crate) fn decode_work(
        &self,
        bytes: &[u8],
    ) -> Result<DecodedStockSuccinctReceiptV1<WorkClaim<ReceiptClaim>>, StockReceiptReplayError>
    {
        self.decode(bytes)
    }

    pub(crate) fn decode_union(
        &self,
        bytes: &[u8],
    ) -> Result<DecodedStockSuccinctReceiptV1<UnionClaim>, StockReceiptReplayError> {
        self.decode(bytes)
    }

    fn decode<Claim>(
        &self,
        bytes: &[u8],
    ) -> Result<DecodedStockSuccinctReceiptV1<Claim>, StockReceiptReplayError>
    where
        Claim: DeserializeOwned + Serialize,
    {
        let receipt = decode_exact::<SuccinctReceipt<Claim>>(bytes)?;
        let stock = self.select_stock_control(receipt.control_id)?;
        Ok(DecodedStockSuccinctReceiptV1 { receipt, stock })
    }

    fn select_stock_control(
        &self,
        actual_control_id: Digest,
    ) -> Result<&'static B4StockControlLayoutV1, StockReceiptReplayError> {
        if self.control_root != ALLOWED_CONTROL_ROOT {
            return authority_drift("stock replay control root drifted after construction");
        }
        let actual_hex = digest_hex(&actual_control_id);
        B4_STOCK_CONTROL_LAYOUT
            .iter()
            .find(|row| row.control_id == actual_hex)
            .ok_or_else(|| {
                StockReceiptReplayError::new(
                    StockReceiptReplayErrorKind::ReceiptProfileShape,
                    "receipt control ID is outside the compiled 27-row stock table",
                )
            })
    }

    pub(crate) fn verify<Claim>(
        &self,
        decoded: DecodedStockSuccinctReceiptV1<Claim>,
        raw_seal: &[u8],
    ) -> Result<VerifiedStockSuccinctReceiptV1<Claim>, StockReceiptReplayError>
    where
        Claim: StockClaimV1,
    {
        verify_typed_receipt_shape(
            &decoded.receipt,
            raw_seal,
            decoded.stock,
            self.parameters_digest,
        )?;
        Claim::verify_integrity(&decoded.receipt, &self.context).map_err(|error| {
            StockReceiptReplayError::new(
                StockReceiptReplayErrorKind::ReceiptCryptographicVerification,
                error.to_string(),
            )
        })?;
        Ok(VerifiedStockSuccinctReceiptV1 {
            receipt: decoded.receipt,
            stock: decoded.stock,
            control_root: self.control_root,
            context: Rc::clone(&self.context),
        })
    }
}

/// Compare stock and checkpoint-instrumented verification on one mutation of
/// an already verified direct receipt.
pub(crate) fn compare_direct_seal_mutation(
    verified: &VerifiedStockSuccinctReceiptV1<ReceiptClaim>,
    mutated_raw_seal: &[u8],
) -> Result<DirectSealMutationTraceV1, DirectSealMutationError> {
    let mutated_words = decode_seal_words(mutated_raw_seal).map_err(|error| {
        DirectSealMutationError::new(
            DirectSealMutationErrorKind::Shape,
            format!("mutated raw-seal grammar rejected: {error}"),
        )
    })?;
    let mut mutated = verified.receipt.clone();
    mutated.seal = mutated_words;

    let parameters = verified
        .context
        .succinct_verifier_parameters
        .as_ref()
        .ok_or_else(|| {
            DirectSealMutationError::new(
                DirectSealMutationErrorKind::CompiledAuthorityDrift,
                "verified direct receipt context has no succinct verifier parameters",
            )
        })?;
    let parameters_digest = parameters.digest();
    if verified.context.dev_mode()
        || parameters.control_root != verified.control_root
        || parameters_digest != mutated.verifier_parameters
    {
        return Err(DirectSealMutationError::new(
            DirectSealMutationErrorKind::CompiledAuthorityDrift,
            "verified direct receipt context drifted from its cryptographic typestate",
        ));
    }
    let suite = verified
        .context
        .suites
        .get(&mutated.hashfn)
        .ok_or_else(|| {
            DirectSealMutationError::new(
                DirectSealMutationErrorKind::CompiledAuthorityDrift,
                "verified direct receipt context lost its exact hash suite",
            )
        })?;
    verify_typed_receipt_shape(
        &mutated,
        mutated_raw_seal,
        verified.stock,
        parameters_digest,
    )
    .map_err(|error| {
        DirectSealMutationError::new(DirectSealMutationErrorKind::Shape, error.detail)
    })?;

    let stock_receipt = mutated.verify_integrity_with_context(&verified.context);
    let stock_core = risc0_zkp::verify::verify(&CIRCUIT, suite, &mutated.seal, |_, control_id| {
        verify_direct_control_id(&mutated, parameters, suite, control_id)
    });
    let mut checkpoints = Vec::new();
    let instrumented = risc0_zkp::verify::verify_with_checkpoints(
        &CIRCUIT,
        suite,
        &mutated.seal,
        |_, control_id| verify_direct_control_id(&mutated, parameters, suite, control_id),
        |checkpoint| checkpoints.push(checkpoint),
    );
    reconcile_direct_seal_mutation_results(stock_receipt, stock_core, instrumented, checkpoints)
}

fn reconcile_direct_seal_mutation_results(
    stock_receipt: Result<(), VerificationError>,
    stock_core: Result<(), VerificationError>,
    instrumented: Result<(), VerificationError>,
    checkpoints: Vec<VerificationCheckpoint>,
) -> Result<DirectSealMutationTraceV1, DirectSealMutationError> {
    if stock_receipt != stock_core || stock_core != instrumented {
        return Err(DirectSealMutationError::new(
            DirectSealMutationErrorKind::Agreement,
            "full stock receipt, stock core, and checkpoint-instrumented verdicts differ",
        ));
    }
    if stock_receipt != Err(VerificationError::InvalidProof) {
        return Err(DirectSealMutationError::new(
            DirectSealMutationErrorKind::Agreement,
            "matching full stock receipt, stock core, and instrumented verdict is not InvalidProof",
        ));
    }
    if checkpoints.is_empty() {
        return Err(DirectSealMutationError::new(
            DirectSealMutationErrorKind::Agreement,
            "instrumented InvalidProof emitted no typed checkpoint",
        ));
    }
    Ok(DirectSealMutationTraceV1 { checkpoints })
}

/// Derive one same-length raw-seal mutation and prove that the full stock
/// receipt verifier and the checkpoint-instrumented core reject it at the
/// exact requested typed boundary.
pub(crate) fn derive_direct_seal_checkpoint_mutation(
    verified: &VerifiedStockSuccinctReceiptV1<ReceiptClaim>,
    target: DirectSealCheckpointMutationV1,
) -> Result<Vec<u8>, DirectSealMutationError> {
    let mut words = verified.receipt.seal.clone();
    if words.len() != DIRECT_SEAL_WORDS {
        return Err(direct_seal_derivation_error(format!(
            "verified direct seal has {} words instead of {DIRECT_SEAL_WORDS}",
            words.len()
        )));
    }

    match target {
        DirectSealCheckpointMutationV1::ValidityCheck => {
            replace_with_next_reduced_word(&mut words, COEFF_U_START)?;
        }
        DirectSealCheckpointMutationV1::FriRoundTwoQueryZero => {
            derive_fri_top_transcript_mutation(&mut words, FriTranscriptRoundV1::One)?;
        }
        DirectSealCheckpointMutationV1::FriFinalPolynomialQueryZero => {
            derive_fri_top_transcript_mutation(&mut words, FriTranscriptRoundV1::Three)?;
        }
        DirectSealCheckpointMutationV1::FriInnerQueryFortyNine => {
            let query_49_first_word = QUERIES_START + 49 * QUERY_WORDS;
            replace_with_next_reduced_word(&mut words, query_49_first_word)?;
        }
    }

    let mutated_raw_seal = encode_seal_words(&words);
    let trace = compare_direct_seal_mutation(verified, &mutated_raw_seal)?;
    let expected = target.checkpoint();
    if trace.checkpoints() != [expected] {
        return Err(direct_seal_derivation_error(format!(
            "derived mutation emitted {:?} instead of the sole target {expected:?}",
            trace.checkpoints()
        )));
    }
    Ok(mutated_raw_seal)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FriTranscriptRoundV1 {
    One,
    Three,
}

impl FriTranscriptRoundV1 {
    const fn index(self) -> usize {
        match self {
            Self::One => 0,
            Self::Three => 2,
        }
    }

    const fn top_start(self) -> usize {
        match self {
            Self::One => FRI_ROUND_ONE_TOP_START,
            Self::Three => FRI_ROUND_THREE_TOP_START,
        }
    }

    const fn domain(self) -> usize {
        match self {
            Self::One => FRI_ROUND_ONE_DOMAIN,
            Self::Three => FRI_ROUND_THREE_DOMAIN,
        }
    }

    const fn query_zero_opening_start(self) -> usize {
        match self {
            Self::One => QUERY_ZERO_FRI_ROUND_ONE_START,
            Self::Three => QUERY_ZERO_FRI_ROUND_THREE_START,
        }
    }
}

#[derive(Clone)]
struct DirectSealFriTranscriptV1 {
    before_fri: Poseidon2Rng,
    roots: [Digest; 3],
    final_coefficients_digest: Digest,
}

impl DirectSealFriTranscriptV1 {
    fn from_words(words: &[u32]) -> Result<Self, DirectSealMutationError> {
        if words.len() != DIRECT_SEAL_WORDS || words.iter().any(|word| *word >= BABY_BEAR_MODULUS) {
            return Err(direct_seal_derivation_error(
                "direct seal is not the exact reduced fixed-length transcript",
            ));
        }
        let suite = Poseidon2HashSuite::new_suite();
        let hashfn = suite.hashfn.as_ref();
        let mut rng = Poseidon2Rng::new();

        rng.mix(
            hashfn
                .hash_elem_slice(&PROOF_SYSTEM_INFO.encode::<BabyBearElem>())
                .as_ref(),
        );
        rng.mix(
            hashfn
                .hash_elem_slice(
                    &<risc0_circuit_recursion::CircuitImpl as CircuitInfo>::CIRCUIT_INFO
                        .encode::<BabyBearElem>(),
                )
                .as_ref(),
        );
        rng.mix(hash_field_words(hashfn, &words[..OUTPUT_WITH_PO2_END]).as_ref());
        rng.mix(merkle_top_root(hashfn, words, CODE_TOP_START)?.as_ref());
        rng.mix(merkle_top_root(hashfn, words, DATA_TOP_START)?.as_ref());
        for _ in 0..<risc0_circuit_recursion::CircuitImpl as CircuitInfo>::MIX_SIZE {
            let _ = rng.random_elem();
        }
        rng.mix(merkle_top_root(hashfn, words, ACCUM_TOP_START)?.as_ref());
        let _ = rng.random_ext_elem();
        rng.mix(merkle_top_root(hashfn, words, CHECK_TOP_START)?.as_ref());
        let _ = rng.random_ext_elem();

        let coeff_u_words = &words[COEFF_U_START..FRI_ROUND_ONE_TOP_START];
        if !coeff_u_words.len().is_multiple_of(4) {
            return Err(direct_seal_derivation_error(
                "coeff-U transcript shape is not exact",
            ));
        }
        let coeff_u = coeff_u_words
            .chunks_exact(4)
            .map(|chunk| {
                BabyBearExtElem::from_subelems(
                    chunk.iter().map(|word| BabyBearElem::new_raw(*word)),
                )
            })
            .collect::<Vec<_>>();
        rng.mix(hashfn.hash_ext_elem_slice(&coeff_u).as_ref());
        let _ = rng.random_ext_elem();

        let roots = [
            *merkle_top_root(hashfn, words, FRI_ROUND_ONE_TOP_START)?,
            *merkle_top_root(hashfn, words, FRI_ROUND_TWO_TOP_START)?,
            *merkle_top_root(hashfn, words, FRI_ROUND_THREE_TOP_START)?,
        ];
        let final_coefficients_digest =
            *hash_field_words(hashfn, &words[FINAL_COEFFICIENTS_START..QUERIES_START]);
        Ok(Self {
            before_fri: rng,
            roots,
            final_coefficients_digest,
        })
    }

    fn q0_position(&self) -> usize {
        let search = self.search_for_round(FriTranscriptRoundV1::One);
        search.position_for_root(self.roots[0])
    }

    fn search_for_round(&self, round: FriTranscriptRoundV1) -> FriQ0SearchV1 {
        let round_index = round.index();
        let mut before_round = self.before_fri.clone();
        for root in &self.roots[..round_index] {
            before_round.mix(root);
            let _ = before_round.random_ext_elem();
        }
        FriQ0SearchV1 {
            before_round,
            suffix_roots: self.roots[round_index + 1..].to_vec(),
            final_coefficients_digest: self.final_coefficients_digest,
        }
    }
}

#[derive(Clone)]
struct FriQ0SearchV1 {
    before_round: Poseidon2Rng,
    suffix_roots: Vec<Digest>,
    final_coefficients_digest: Digest,
}

impl FriQ0SearchV1 {
    fn position_for_root(&self, root: Digest) -> usize {
        let mut rng = self.before_round.clone();
        rng.mix(&root);
        let _ = rng.random_ext_elem();
        for suffix_root in &self.suffix_roots {
            rng.mix(suffix_root);
            let _ = rng.random_ext_elem();
        }
        rng.mix(&self.final_coefficients_digest);
        rng.random_bits(FRI_ORIGINAL_DOMAIN.trailing_zeros() as usize) as usize
    }
}

fn derive_fri_top_transcript_mutation(
    words: &mut [u32],
    round: FriTranscriptRoundV1,
) -> Result<(), DirectSealMutationError> {
    let transcript = DirectSealFriTranscriptV1::from_words(words)?;
    let q0_position = transcript.q0_position();
    let suite = Poseidon2HashSuite::new_suite();
    let hashfn = suite.hashfn.as_ref();
    authenticate_query_zero_fri_opening(hashfn, words, round, q0_position)?;

    let domain = round.domain();
    let q0_group = q0_position % domain;
    let q0_top_index = q0_group / (domain / MERKLE_TOP_DIGESTS);
    let mutation_top_index = (q0_top_index + 1) % MERKLE_TOP_DIGESTS;
    let top = merkle_top_digests(words, round.top_start())?;
    let branch = merkle_top_branch(hashfn, &top, mutation_top_index);
    let original_root = fold_merkle_top_branch(hashfn, top[mutation_top_index], &branch);
    if original_root != transcript.roots[round.index()] {
        return Err(direct_seal_derivation_error(
            "FRI top branch does not reconstruct the committed root",
        ));
    }

    let mutation_word_index = round.top_start() + mutation_top_index * DIGEST_WORDS;
    let original_word = words[mutation_word_index];
    let search = transcript.search_for_round(round);
    let attempt = find_q0_preserving_top_word_attempt(
        &search,
        top[mutation_top_index],
        &branch,
        original_word,
        q0_position,
    )?;
    words[mutation_word_index] = reduced_word_for_attempt(original_word, attempt);
    Ok(())
}

fn find_q0_preserving_top_word_attempt(
    search: &FriQ0SearchV1,
    original_top_digest: Digest,
    branch: &[(bool, Digest)],
    original_word: u32,
    target_q0_position: usize,
) -> Result<u32, DirectSealMutationError> {
    let worker_count = thread::available_parallelism()
        .map_or(1, usize::from)
        .min(16);
    let no_match = MAX_Q0_GRIND_ATTEMPTS + 1;
    let best = AtomicU32::new(no_match);
    thread::scope(|scope| {
        for lane in 0..worker_count {
            let best = &best;
            scope.spawn(move || {
                let suite = Poseidon2HashSuite::new_suite();
                let hashfn = suite.hashfn.as_ref();
                let mut attempt = u32::try_from(lane).unwrap() + 1;
                let stride = u32::try_from(worker_count).unwrap();
                while attempt <= MAX_Q0_GRIND_ATTEMPTS && attempt < best.load(Ordering::Relaxed) {
                    let mut candidate_top_digest = original_top_digest;
                    candidate_top_digest.as_mut_words()[0] =
                        reduced_word_for_attempt(original_word, attempt);
                    let candidate_root =
                        fold_merkle_top_branch(hashfn, candidate_top_digest, branch);
                    if search.position_for_root(candidate_root) == target_q0_position {
                        best.fetch_min(attempt, Ordering::Relaxed);
                        break;
                    }
                    attempt += stride;
                }
            });
        }
    });
    let attempt = best.load(Ordering::Relaxed);
    if attempt == no_match {
        return Err(direct_seal_derivation_error(format!(
            "no query-zero-preserving FRI top mutation in {MAX_Q0_GRIND_ATTEMPTS} attempts"
        )));
    }
    Ok(attempt)
}

fn authenticate_query_zero_fri_opening(
    hashfn: &dyn HashFn<BabyBear>,
    words: &[u32],
    round: FriTranscriptRoundV1,
    q0_position: usize,
) -> Result<(), DirectSealMutationError> {
    let domain = round.domain();
    let group = q0_position % domain;
    let opening_start = round.query_zero_opening_start();
    let leaf_end = opening_start + FRI_LEAF_WORDS;
    let mut current = *hash_field_words(hashfn, &words[opening_start..leaf_end]);
    let mut merkle_index = domain + group;
    let mut sibling_start = leaf_end;
    while merkle_index >= 2 * MERKLE_TOP_DIGESTS {
        let sibling = digest_from_words(words, sibling_start)?;
        sibling_start += DIGEST_WORDS;
        current = if merkle_index % 2 == 1 {
            *hashfn.hash_pair(&sibling, &current)
        } else {
            *hashfn.hash_pair(&current, &sibling)
        };
        merkle_index /= 2;
    }
    let expected_sibling_end = opening_start
        + FRI_LEAF_WORDS
        + usize::try_from(domain.trailing_zeros() - 5).unwrap() * DIGEST_WORDS;
    if sibling_start != expected_sibling_end {
        return Err(direct_seal_derivation_error(
            "query-zero FRI branch length differs from the fixed layout",
        ));
    }
    let top_index = merkle_index - MERKLE_TOP_DIGESTS;
    let top = merkle_top_digests(words, round.top_start())?;
    if current != top[top_index] {
        return Err(direct_seal_derivation_error(
            "reconstructed Fiat-Shamir query zero does not authenticate its FRI opening",
        ));
    }
    Ok(())
}

fn merkle_top_root(
    hashfn: &dyn HashFn<BabyBear>,
    words: &[u32],
    start: usize,
) -> Result<Box<Digest>, DirectSealMutationError> {
    let top = merkle_top_digests(words, start)?;
    let mut level = top.to_vec();
    while level.len() > 1 {
        level = level
            .chunks_exact(2)
            .map(|pair| *hashfn.hash_pair(&pair[0], &pair[1]))
            .collect();
    }
    Ok(Box::new(level[0]))
}

fn merkle_top_digests(
    words: &[u32],
    start: usize,
) -> Result<[Digest; MERKLE_TOP_DIGESTS], DirectSealMutationError> {
    let end = start
        .checked_add(MERKLE_TOP_WORDS)
        .ok_or_else(|| direct_seal_derivation_error("FRI top offset overflow"))?;
    if end > words.len() {
        return Err(direct_seal_derivation_error(
            "FRI top extends beyond the direct seal",
        ));
    }
    let mut top = [Digest::ZERO; MERKLE_TOP_DIGESTS];
    for (index, digest) in top.iter_mut().enumerate() {
        *digest = digest_from_words(words, start + index * DIGEST_WORDS)?;
    }
    Ok(top)
}

fn merkle_top_branch(
    hashfn: &dyn HashFn<BabyBear>,
    top: &[Digest; MERKLE_TOP_DIGESTS],
    mut index: usize,
) -> Vec<(bool, Digest)> {
    let mut branch = Vec::with_capacity(MERKLE_TOP_DIGESTS.trailing_zeros() as usize);
    let mut level = top.to_vec();
    while level.len() > 1 {
        branch.push((index % 2 == 1, level[index ^ 1]));
        level = level
            .chunks_exact(2)
            .map(|pair| *hashfn.hash_pair(&pair[0], &pair[1]))
            .collect();
        index /= 2;
    }
    branch
}

fn fold_merkle_top_branch(
    hashfn: &dyn HashFn<BabyBear>,
    mut current: Digest,
    branch: &[(bool, Digest)],
) -> Digest {
    for (current_is_right, sibling) in branch {
        current = if *current_is_right {
            *hashfn.hash_pair(sibling, &current)
        } else {
            *hashfn.hash_pair(&current, sibling)
        };
    }
    current
}

fn digest_from_words(words: &[u32], start: usize) -> Result<Digest, DirectSealMutationError> {
    let end = start
        .checked_add(DIGEST_WORDS)
        .ok_or_else(|| direct_seal_derivation_error("digest offset overflow"))?;
    let source = words
        .get(start..end)
        .ok_or_else(|| direct_seal_derivation_error("digest extends beyond the direct seal"))?;
    Ok(Digest::new(source.try_into().unwrap()))
}

fn hash_field_words(hashfn: &dyn HashFn<BabyBear>, words: &[u32]) -> Box<Digest> {
    let elements = words
        .iter()
        .map(|word| BabyBearElem::new_raw(*word))
        .collect::<Vec<_>>();
    hashfn.hash_elem_slice(&elements)
}

fn replace_with_next_reduced_word(
    words: &mut [u32],
    index: usize,
) -> Result<(), DirectSealMutationError> {
    let word = words
        .get_mut(index)
        .ok_or_else(|| direct_seal_derivation_error("mutation word is outside the direct seal"))?;
    *word = if *word + 1 < BABY_BEAR_MODULUS {
        *word + 1
    } else {
        *word - 1
    };
    Ok(())
}

fn reduced_word_for_attempt(original: u32, attempt: u32) -> u32 {
    u32::try_from((u64::from(original) + u64::from(attempt)) % u64::from(BABY_BEAR_MODULUS))
        .unwrap()
}

fn encode_seal_words(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn direct_seal_derivation_error(detail: impl Into<String>) -> DirectSealMutationError {
    DirectSealMutationError::new(DirectSealMutationErrorKind::Derivation, detail)
}

fn verify_direct_control_id(
    receipt: &SuccinctReceipt<ReceiptClaim>,
    parameters: &SuccinctReceiptVerifierParameters,
    suite: &HashSuite<BabyBear>,
    control_id: &Digest,
) -> Result<(), VerificationError> {
    if *control_id != receipt.control_id {
        return Err(VerificationError::ControlVerificationError {
            control_id: *control_id,
        });
    }
    receipt
        .control_inclusion_proof
        .verify(control_id, &parameters.control_root, suite.hashfn.as_ref())
        .map_err(|_| VerificationError::ControlVerificationError {
            control_id: *control_id,
        })
}

fn authority_drift<T>(detail: &'static str) -> Result<T, StockReceiptReplayError> {
    Err(StockReceiptReplayError::new(
        StockReceiptReplayErrorKind::CompiledAuthorityDrift,
        detail,
    ))
}

fn validate_compiled_control_words(controls: &[Digest]) -> Result<(), StockReceiptReplayError> {
    if controls
        .iter()
        .flat_map(Digest::as_words)
        .any(|word| *word >= BABY_BEAR_MODULUS)
    {
        return authority_drift("compiled control ID contains a non-reduced BabyBear word");
    }
    Ok(())
}

pub(crate) fn decode_exact<T>(bytes: &[u8]) -> Result<T, StockReceiptReplayError>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.is_empty() || bytes.len() > RECEIPT_ORACLE_MAX_BYTES {
        return Err(StockReceiptReplayError::new(
            StockReceiptReplayErrorKind::ArtifactLength,
            "receipt oracle is outside the closed 1..=1048576-byte bound",
        ));
    }
    let mut cursor = Cursor::new(bytes);
    let decoded = receipt_oracle_bincode_options()
        .deserialize_from(&mut cursor)
        .map_err(|error| {
            StockReceiptReplayError::new(
                StockReceiptReplayErrorKind::ReceiptDecode,
                error.to_string(),
            )
        })?;
    if cursor.position() != bytes.len() as u64 {
        return Err(StockReceiptReplayError::new(
            StockReceiptReplayErrorKind::ReceiptDecode,
            "typed receipt did not consume its exact source bytes",
        ));
    }
    let reencoded = receipt_oracle_bincode_options()
        .serialize(&decoded)
        .map_err(|error| {
            StockReceiptReplayError::new(
                StockReceiptReplayErrorKind::ReceiptReencode,
                error.to_string(),
            )
        })?;
    if reencoded != bytes {
        return Err(StockReceiptReplayError::new(
            StockReceiptReplayErrorKind::ReceiptEncodingNotExact,
            "decoded receipt does not round-trip to the exact source bytes",
        ));
    }
    Ok(decoded)
}

fn verify_typed_receipt_shape<Claim>(
    receipt: &SuccinctReceipt<Claim>,
    raw_seal: &[u8],
    stock: &B4StockControlLayoutV1,
    parameters_digest: Digest,
) -> Result<(), StockReceiptReplayError> {
    if receipt.hashfn != "poseidon2" {
        return Err(profile_shape_error(
            "receipt hash suite is not exactly poseidon2",
        ));
    }
    if receipt.verifier_parameters != parameters_digest {
        return Err(profile_shape_error(
            "receipt verifier-parameter digest differs from the pinned default",
        ));
    }
    if receipt.control_id != ALLOWED_CONTROL_IDS[stock.stock_index as usize] {
        return Err(profile_shape_error(
            "receipt control ID differs from its compiled stock-table row",
        ));
    }
    if receipt.control_inclusion_proof.index != stock.stock_index {
        return Err(profile_shape_error(
            "control-inclusion index differs from the fixed stock-table index",
        ));
    }
    if receipt.control_inclusion_proof.digests.len() != CONTROL_INCLUSION_PROOF_DEPTH {
        return Err(profile_shape_error(
            "control-inclusion path does not contain exactly eight siblings",
        ));
    }
    if receipt
        .control_inclusion_proof
        .digests
        .iter()
        .flat_map(Digest::as_words)
        .any(|word| *word >= BABY_BEAR_MODULUS)
    {
        return Err(profile_shape_error(
            "control-inclusion sibling is not a reduced BabyBear digest",
        ));
    }
    if receipt.seal.len() != PROOF_WORDS {
        return Err(profile_shape_error(
            "receipt seal does not contain the exact profile word count",
        ));
    }
    if receipt
        .seal
        .iter()
        .enumerate()
        .any(|(index, word)| index != 32 && *word >= BABY_BEAR_MODULUS)
    {
        return Err(profile_shape_error(
            "raw seal contains a non-reduced BabyBear field element",
        ));
    }
    if (1..16).step_by(2).any(|index| receipt.seal[index] != 0) {
        return Err(profile_shape_error(
            "raw-seal inner-root slot contains nonzero Poseidon2 padding",
        ));
    }
    let decoded_words = decode_seal_words(raw_seal)
        .map_err(|error| profile_shape_error(format!("raw-seal grammar rejected: {error}")))?;
    if decoded_words != receipt.seal || receipt.get_seal_bytes() != raw_seal {
        return Err(profile_shape_error(
            "raw-seal artifact is not the exact little-endian receipt seal",
        ));
    }
    if receipt.seal.get(32).copied() != Some(u32::from(RISC0_OUTER_PO2)) {
        return Err(profile_shape_error(
            "raw seal does not carry the frozen outer recursion exponent",
        ));
    }
    Ok(())
}

fn profile_shape_error(detail: impl Into<String>) -> StockReceiptReplayError {
    StockReceiptReplayError::new(StockReceiptReplayErrorKind::ReceiptProfileShape, detail)
}

fn digest_hex(digest: &Digest) -> String {
    hex::encode(digest.as_bytes())
}

#[cfg(test)]
pub(crate) mod test_support {
    use bincode::Options as _;

    use crate::receipt_oracle_codec::receipt_oracle_bincode_options;

    pub(crate) fn alternate_direct_receipt_bytes() -> Vec<u8> {
        let outer_bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../generator/testdata/alternate-root-lift-po2-15-v1/",
            "candidate-proof-export/proof-output/candidate-receipt-oracle.bincode"
        ));
        let outer: risc0_zkvm::Receipt = receipt_oracle_bincode_options()
            .deserialize(outer_bytes)
            .unwrap();
        let risc0_zkvm::InnerReceipt::Succinct(receipt) = outer.inner else {
            panic!("tracked alternate-root receipt is not succinct");
        };
        receipt_oracle_bincode_options()
            .serialize(&receipt)
            .unwrap()
    }

    pub(crate) fn alternate_raw_seal_bytes() -> &'static [u8] {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../generator/testdata/alternate-root-lift-po2-15-v1/",
            "candidate-proof-export/proof-output/candidate-raw-seal.bin"
        ))
    }
}

#[cfg(test)]
mod tests {
    use bincode::Options as _;

    use crate::{
        constants::{B4_ALTERNATE_CONTROL_ROOT, B4_ALTERNATE_VERIFIER_PARAMETERS_HEX},
        receipt_oracle_codec::{RECEIPT_ORACLE_MAX_BYTES, receipt_oracle_bincode_options},
    };

    use super::{
        test_support::{alternate_direct_receipt_bytes, alternate_raw_seal_bytes},
        *,
    };

    #[test]
    fn compiled_stock_replay_is_poseidon2_only_dev_mode_closed_and_parameter_pinned() {
        let replay = CompiledStockSuccinctReplayV1::from_compiled_profile().unwrap();

        assert_eq!(replay.context.suites.len(), 1);
        assert!(replay.context.suites.contains_key("poseidon2"));
        assert!(!replay.context.dev_mode());
        assert_eq!(
            digest_hex(&replay.parameters_digest),
            EXPECTED_VERIFIER_PARAMETERS_HEX
        );
        assert_eq!(replay.control_root, risc0_zkvm::ALLOWED_CONTROL_ROOT);
    }

    #[test]
    fn compiled_authority_rejects_an_unreduced_control_word() {
        let mut controls = ALLOWED_CONTROL_IDS.to_vec();
        controls[0] = Digest::new([BABY_BEAR_MODULUS, 0, 0, 0, 0, 0, 0, 0]);

        let error = validate_compiled_control_words(&controls).unwrap_err();
        assert_eq!(
            error.kind(),
            StockReceiptReplayErrorKind::CompiledAuthorityDrift
        );
        assert!(
            error
                .detail()
                .contains("compiled control ID contains a non-reduced BabyBear word")
        );
    }

    #[test]
    fn mutation_comparison_requires_matching_invalid_proof_and_a_typed_trace() {
        let checkpoint = VerificationCheckpoint::ValidityCheck;
        let trace = reconcile_direct_seal_mutation_results(
            Err(VerificationError::InvalidProof),
            Err(VerificationError::InvalidProof),
            Err(VerificationError::InvalidProof),
            vec![checkpoint],
        )
        .unwrap();
        assert_eq!(trace.checkpoints(), &[checkpoint]);

        for (stock_receipt, stock_core, instrumented, checkpoints) in [
            (Ok(()), Ok(()), Ok(()), vec![checkpoint]),
            (
                Err(VerificationError::ReceiptFormatError),
                Err(VerificationError::ReceiptFormatError),
                Err(VerificationError::ReceiptFormatError),
                vec![checkpoint],
            ),
            (
                Err(VerificationError::InvalidProof),
                Err(VerificationError::ReceiptFormatError),
                Err(VerificationError::ReceiptFormatError),
                vec![checkpoint],
            ),
            (
                Err(VerificationError::InvalidProof),
                Err(VerificationError::InvalidProof),
                Err(VerificationError::ReceiptFormatError),
                vec![checkpoint],
            ),
            (
                Err(VerificationError::InvalidProof),
                Err(VerificationError::InvalidProof),
                Err(VerificationError::InvalidProof),
                Vec::new(),
            ),
        ] {
            let error = reconcile_direct_seal_mutation_results(
                stock_receipt,
                stock_core,
                instrumented,
                checkpoints,
            )
            .unwrap_err();
            assert_eq!(error.kind(), DirectSealMutationErrorKind::Agreement);
        }
    }

    #[test]
    fn real_direct_kat_rejects_intact_length_and_shape_drift_at_named_boundaries() {
        let verified = verified_alternate_direct_kat();
        let intact = verified.receipt.get_seal_bytes();

        let intact_error = compare_direct_seal_mutation(&verified, &intact).unwrap_err();
        assert_eq!(intact_error.kind(), DirectSealMutationErrorKind::Agreement);
        assert!(
            intact_error
                .detail()
                .contains("verdict is not InvalidProof")
        );

        let length_error =
            compare_direct_seal_mutation(&verified, &intact[..intact.len() - 1]).unwrap_err();
        assert_eq!(length_error.kind(), DirectSealMutationErrorKind::Shape);
        assert!(length_error.detail().contains("raw seal has"));

        let mut padding_drift = intact.clone();
        padding_drift[4..8].copy_from_slice(&1_u32.to_le_bytes());
        let shape_error = compare_direct_seal_mutation(&verified, &padding_drift).unwrap_err();
        assert_eq!(shape_error.kind(), DirectSealMutationErrorKind::Shape);
        assert!(
            shape_error
                .detail()
                .contains("inner-root slot contains nonzero")
        );

        assert_eq!(verified.receipt.get_seal_bytes(), intact);
    }

    #[test]
    fn real_direct_kat_returns_the_pinned_typed_checkpoint_without_text_matching() {
        let verified = verified_alternate_direct_kat();
        let mut mutated = verified.receipt.get_seal_bytes();
        let query_49_first_word = 54_648;
        let offset = query_49_first_word * 4;
        let original = u32::from_le_bytes(mutated[offset..offset + 4].try_into().unwrap());
        let replacement = if original + 1 < BABY_BEAR_MODULUS {
            original + 1
        } else {
            original - 1
        };
        mutated[offset..offset + 4].copy_from_slice(&replacement.to_le_bytes());

        let trace = compare_direct_seal_mutation(&verified, &mutated).unwrap();
        assert_eq!(
            trace.checkpoints(),
            &[VerificationCheckpoint::FriInnerQuery { query: 49 }]
        );
    }

    #[test]
    fn real_direct_kat_reaches_the_validity_checkpoint_from_one_reduced_coeff_u_word() {
        let verified = verified_alternate_direct_kat();
        let mut mutated = verified.receipt.get_seal_bytes();
        let first_coeff_u_word = 1_057;
        let offset = first_coeff_u_word * 4;
        let original = u32::from_le_bytes(mutated[offset..offset + 4].try_into().unwrap());
        let replacement = if original + 1 < BABY_BEAR_MODULUS {
            original + 1
        } else {
            original - 1
        };
        mutated[offset..offset + 4].copy_from_slice(&replacement.to_le_bytes());

        let trace = compare_direct_seal_mutation(&verified, &mutated).unwrap();
        assert_eq!(
            trace.checkpoints(),
            &[VerificationCheckpoint::ValidityCheck]
        );
    }

    #[test]
    fn real_direct_kat_reconstructs_and_authenticates_fiat_shamir_query_zero() {
        let verified = verified_alternate_direct_kat();
        let transcript = DirectSealFriTranscriptV1::from_words(&verified.receipt.seal).unwrap();
        let q0_position = transcript.q0_position();
        assert!(q0_position < FRI_ORIGINAL_DOMAIN);

        let suite = Poseidon2HashSuite::new_suite();
        authenticate_query_zero_fri_opening(
            suite.hashfn.as_ref(),
            &verified.receipt.seal,
            FriTranscriptRoundV1::One,
            q0_position,
        )
        .unwrap();
        authenticate_query_zero_fri_opening(
            suite.hashfn.as_ref(),
            &verified.receipt.seal,
            FriTranscriptRoundV1::Three,
            q0_position,
        )
        .unwrap();
    }

    #[test]
    fn real_direct_kat_derives_four_single_word_typed_checkpoint_mutations() {
        let verified = verified_alternate_direct_kat();
        let original = verified.receipt.seal.clone();
        let targets = [
            DirectSealCheckpointMutationV1::ValidityCheck,
            DirectSealCheckpointMutationV1::FriRoundTwoQueryZero,
            DirectSealCheckpointMutationV1::FriFinalPolynomialQueryZero,
            DirectSealCheckpointMutationV1::FriInnerQueryFortyNine,
        ];

        for target in targets {
            let mutated = derive_direct_seal_checkpoint_mutation(&verified, target).unwrap();
            let mutated_words = decode_seal_words(&mutated).unwrap();
            assert_eq!(mutated_words.len(), original.len());
            assert_eq!(
                mutated_words
                    .iter()
                    .zip(&original)
                    .filter(|(observed, expected)| observed != expected)
                    .count(),
                1,
                "{target:?} must replace exactly one raw-seal word"
            );
        }
    }

    #[test]
    fn direct_codec_rejects_empty_trailing_oversize_and_wrong_typed_shape() {
        let canonical = receipt_oracle_bincode_options().serialize(&42_u32).unwrap();
        assert_eq!(decode_exact::<u32>(&canonical).unwrap(), 42);

        assert_eq!(
            decode_exact::<u32>(&[]).unwrap_err().kind(),
            StockReceiptReplayErrorKind::ArtifactLength
        );

        let mut trailing = canonical.clone();
        trailing.push(0);
        assert_eq!(
            decode_exact::<u32>(&trailing).unwrap_err().kind(),
            StockReceiptReplayErrorKind::ReceiptDecode
        );

        let oversized = vec![0_u8; RECEIPT_ORACLE_MAX_BYTES + 1];
        assert_eq!(
            decode_exact::<u32>(&oversized).unwrap_err().kind(),
            StockReceiptReplayErrorKind::ArtifactLength
        );

        let wrong_typed_shape = receipt_oracle_bincode_options()
            .serialize(&(42_u32, 0_u8))
            .unwrap();
        assert_eq!(
            decode_exact::<u32>(&wrong_typed_shape).unwrap_err().kind(),
            StockReceiptReplayErrorKind::ReceiptDecode
        );
    }

    #[test]
    fn standard_receipt_round_trip_is_exact_not_a_noncanonical_fixture_case() {
        let source = alternate_direct_receipt_bytes();
        let receipt: SuccinctReceipt<ReceiptClaim> = decode_exact(&source).unwrap();
        let round_trip = receipt_oracle_bincode_options()
            .serialize(&receipt)
            .unwrap();

        assert_eq!(round_trip, source);
        // `ReceiptEncodingNotExact` remains defense in depth for a future
        // custom serde implementation. No standard RISC Zero receipt vector
        // is claimed to reach that class.
    }

    #[test]
    fn wrong_hash_suite_is_isolated_before_other_profile_checks() {
        let (replay, mut decoded, raw_seal) = stock_shape_fixture();
        decoded.receipt.hashfn = "sha-256".to_owned();

        assert_profile_shape_rejection(
            &replay,
            decoded,
            &raw_seal,
            "receipt hash suite is not exactly poseidon2",
        );
    }

    #[test]
    fn foreign_control_id_is_rejected_by_stock_lookup() {
        let (replay, mut decoded, _) = stock_shape_fixture();
        decoded.receipt.control_id = Digest::new([0; 8]);
        let source = receipt_oracle_bincode_options()
            .serialize(&decoded.receipt)
            .unwrap();

        let Err(error) = replay.decode_direct(&source) else {
            panic!("foreign control ID unexpectedly entered decoded typestate");
        };
        assert_eq!(
            error.kind(),
            StockReceiptReplayErrorKind::ReceiptProfileShape
        );
        assert!(
            error
                .detail()
                .contains("receipt control ID is outside the compiled 27-row stock table")
        );
    }

    #[test]
    fn wrong_inclusion_index_is_isolated() {
        let (replay, mut decoded, raw_seal) = stock_shape_fixture();
        decoded.receipt.control_inclusion_proof.index += 1;

        assert_profile_shape_rejection(
            &replay,
            decoded,
            &raw_seal,
            "control-inclusion index differs from the fixed stock-table index",
        );
    }

    #[test]
    fn wrong_inclusion_depth_is_isolated() {
        let (replay, mut decoded, raw_seal) = stock_shape_fixture();
        decoded.receipt.control_inclusion_proof.digests.pop();

        assert_profile_shape_rejection(
            &replay,
            decoded,
            &raw_seal,
            "control-inclusion path does not contain exactly eight siblings",
        );
    }

    #[test]
    fn unreduced_inclusion_sibling_is_isolated() {
        let (replay, mut decoded, raw_seal) = stock_shape_fixture();
        decoded.receipt.control_inclusion_proof.digests[0] =
            Digest::new([BABY_BEAR_MODULUS, 0, 0, 0, 0, 0, 0, 0]);

        assert_profile_shape_rejection(
            &replay,
            decoded,
            &raw_seal,
            "control-inclusion sibling is not a reduced BabyBear digest",
        );
    }

    #[test]
    fn unreduced_seal_word_is_isolated() {
        let (replay, mut decoded, raw_seal) = stock_shape_fixture();
        decoded.receipt.seal[33] = BABY_BEAR_MODULUS;

        assert_profile_shape_rejection(
            &replay,
            decoded,
            &raw_seal,
            "raw seal contains a non-reduced BabyBear field element",
        );
    }

    #[test]
    fn nonzero_poseidon2_padding_is_isolated() {
        let (replay, mut decoded, raw_seal) = stock_shape_fixture();
        decoded.receipt.seal[1] = 1;

        assert_profile_shape_rejection(
            &replay,
            decoded,
            &raw_seal,
            "raw-seal inner-root slot contains nonzero Poseidon2 padding",
        );
    }

    #[test]
    fn wrong_outer_po2_is_isolated_after_exact_raw_seal_binding() {
        let (replay, mut decoded, _) = stock_shape_fixture();
        decoded.receipt.seal[32] = u32::from(RISC0_OUTER_PO2) + 1;
        let matching_raw_seal = decoded.receipt.get_seal_bytes();

        assert_profile_shape_rejection(
            &replay,
            decoded,
            &matching_raw_seal,
            "raw seal does not carry the frozen outer recursion exponent",
        );
    }

    #[test]
    fn cryptographic_verification_failure_is_isolated_after_shape_acceptance() {
        let (replay, decoded, raw_seal) = stock_shape_fixture();

        let error = replay.verify(decoded, &raw_seal).unwrap_err();
        assert_eq!(
            error.kind(),
            StockReceiptReplayErrorKind::ReceiptCryptographicVerification
        );
    }

    #[test]
    fn decoded_claim_is_not_exposed_before_cryptographic_verification() {
        let replay = CompiledStockSuccinctReplayV1::from_compiled_profile().unwrap();
        let receipt_bytes = alternate_direct_receipt_bytes();
        let decoded = replay.decode_direct(&receipt_bytes).unwrap();

        // Decoded state exposes only authenticated-profile routing metadata.
        // The claim accessor exists exclusively on the verified typestate.
        assert!(usize::try_from(decoded.stock().stock_index).unwrap() < B4_STOCK_CONTROL_COUNT);
        let error = replay
            .verify(decoded, alternate_raw_seal_bytes())
            .unwrap_err();
        assert_eq!(
            error.kind(),
            StockReceiptReplayErrorKind::ReceiptProfileShape
        );
    }

    #[test]
    fn alternate_root_receipt_cannot_select_an_alternate_verifier() {
        let replay = CompiledStockSuccinctReplayV1::from_compiled_profile().unwrap();
        let receipt_bytes = alternate_direct_receipt_bytes();
        let error = replay.verify_direct_oracle(&receipt_bytes).unwrap_err();
        assert_eq!(
            error.kind(),
            StockReceiptReplayErrorKind::ReceiptProfileShape
        );
        assert!(
            error
                .detail()
                .contains("verifier-parameter digest differs from the pinned default")
        );
    }

    #[test]
    fn raw_seal_must_equal_the_verified_receipt_seal() {
        let replay = CompiledStockSuccinctReplayV1::from_compiled_profile().unwrap();
        let receipt_bytes = alternate_direct_receipt_bytes();
        let mut decoded = replay.decode_direct(&receipt_bytes).unwrap();
        decoded.receipt.verifier_parameters = replay.parameters_digest;
        let mut wrong_raw_seal = alternate_raw_seal_bytes().to_vec();
        wrong_raw_seal[0] ^= 1;

        let error = replay.verify(decoded, &wrong_raw_seal).unwrap_err();
        assert_eq!(
            error.kind(),
            StockReceiptReplayErrorKind::ReceiptProfileShape
        );
        assert!(
            error
                .detail()
                .contains("raw-seal artifact is not the exact little-endian receipt seal")
        );
    }

    fn stock_shape_fixture() -> (
        CompiledStockSuccinctReplayV1,
        DecodedStockSuccinctReceiptV1<ReceiptClaim>,
        Vec<u8>,
    ) {
        let replay = CompiledStockSuccinctReplayV1::from_compiled_profile().unwrap();
        let receipt_bytes = alternate_direct_receipt_bytes();
        let mut decoded = replay.decode_direct(&receipt_bytes).unwrap();
        decoded.receipt.verifier_parameters = replay.parameters_digest;
        let raw_seal = decoded.receipt.get_seal_bytes();
        assert_eq!(raw_seal, alternate_raw_seal_bytes());
        (replay, decoded, raw_seal)
    }

    fn verified_alternate_direct_kat() -> VerifiedStockSuccinctReceiptV1<ReceiptClaim> {
        // Production intentionally rejects this alternate authority. The
        // test-only context lets the comparator exercise the sole tracked
        // cryptographically valid real succinct receipt.
        let source = alternate_direct_receipt_bytes();
        let receipt: SuccinctReceipt<ReceiptClaim> = decode_exact(&source).unwrap();
        let stock = B4_STOCK_CONTROL_LAYOUT
            .iter()
            .find(|row| row.control_id == digest_hex(&receipt.control_id))
            .unwrap();

        let mut suites = VerifierContext::default_hash_suites();
        let poseidon2 = suites.remove("poseidon2").unwrap();
        let parameters = SuccinctReceiptVerifierParameters {
            control_root: Digest::from(B4_ALTERNATE_CONTROL_ROOT),
            inner_control_root: None,
            ..Default::default()
        };
        let parameters_digest = parameters.digest();
        assert_eq!(
            digest_hex(&parameters_digest),
            B4_ALTERNATE_VERIFIER_PARAMETERS_HEX
        );
        let context = Rc::new(
            VerifierContext::empty()
                .with_suites(BTreeMap::from([("poseidon2".to_owned(), poseidon2)]))
                .with_succinct_verifier_parameters(parameters)
                .with_dev_mode(false),
        );
        let raw_seal = receipt.get_seal_bytes();
        verify_typed_receipt_shape(&receipt, &raw_seal, stock, parameters_digest).unwrap();
        receipt.verify_integrity_with_context(&context).unwrap();

        VerifiedStockSuccinctReceiptV1 {
            receipt,
            stock,
            control_root: Digest::from(B4_ALTERNATE_CONTROL_ROOT),
            context,
        }
    }

    fn assert_profile_shape_rejection(
        replay: &CompiledStockSuccinctReplayV1,
        decoded: DecodedStockSuccinctReceiptV1<ReceiptClaim>,
        raw_seal: &[u8],
        expected_detail: &str,
    ) {
        let error = replay.verify(decoded, raw_seal).unwrap_err();
        assert_eq!(
            error.kind(),
            StockReceiptReplayErrorKind::ReceiptProfileShape
        );
        assert_eq!(error.detail(), expected_detail);
    }
}
