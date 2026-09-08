//! Derive-first upstream replay for the closed B4 terminal-oracle corpus.
//!
//! The candidate catalogue is deliberately absent from the replay entry point.
//! Fixture paths, claim types, ordering, and terminal controls are selected only
//! by the compiled V1 layout below.  Catalogue bytes can be checked only after
//! all nine typed receipts have been decoded canonically, cryptographically
//! verified, and projected into a derived catalogue.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use risc0_zkvm::{
    ALLOWED_CONTROL_ROOT, Assumption, Digest, MaybePruned, ReceiptClaim, UnionClaim, WorkClaim,
    sha::Digestible as _,
};
use sha2::{Digest as _, Sha256};

use crate::{
    b4_terminal::{
        B4_STOCK_CONTROL_LAYOUT, B4_TERMINAL_FIXTURE_CATALOG_FORMAT,
        B4_TERMINAL_FIXTURE_CATALOG_FORMAT_VERSION, B4_TERMINAL_FIXTURE_CATALOG_MAX_BYTES,
        B4_TERMINAL_FIXTURE_CATALOG_STAGE, B4_TERMINAL_FIXTURE_COUNT,
        B4_TERMINAL_FIXTURE_DIRECTORY, B4_TERMINAL_FIXTURE_RECEIPT_CODEC,
        B4_TERMINAL_FIXTURE_RISC0_VERSION, B4ApplicationBindingV1, B4AssumptionsBindingV1,
        B4DirectApplicationBindingV1, B4ExitStatusV1, B4StockControlV1, B4TerminalArtifactV1,
        B4TerminalBindingV1, B4TerminalClaimKindV1, B4TerminalFixtureV1, B4TerminalUpstreamV1,
        B4UnionAssumptionBindingV1, Eip0045B4TerminalFixtureCatalogV1,
    },
    canonical::{canonical_json_bytes, validate_canonical_json_source, validate_lower_hex_exact},
    constants::{PROOF_BYTES, RISC0_COMMIT, RISC0_INNER_CONTROL_ROOT_HEX, RISC0_REPOSITORY},
    receipt_oracle_codec::RECEIPT_ORACLE_MAX_BYTES,
    receipt_oracle_replay::{
        CompiledStockSuccinctReplayV1, DecodedStockSuccinctReceiptV1, StockReceiptReplayError,
        StockReceiptReplayErrorKind, VerifiedStockSuccinctReceiptV1,
    },
};

/// One immutable position in the nine-fixture terminal-oracle corpus.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum B4TerminalOracleSlot {
    /// Stable Lift14-named slot backed by the stock Identity receipt.
    LiftPo214,
    /// Excluded `PoVW` lift at po2 18.
    LiftPovwPo218,
    /// Excluded `PoVW` join.
    JoinPovw,
    /// Excluded join followed by `PoVW` unwrap.
    JoinUnwrapPovw,
    /// Excluded `PoVW` resolve.
    ResolvePovw,
    /// Excluded resolve followed by `PoVW` unwrap.
    ResolveUnwrapPovw,
    /// Excluded union receipt.
    Union,
    /// Excluded `PoVW` unwrap.
    UnwrapPovw,
    /// Profile-allowed terminal with a non-OK application status.
    AllowedTerminalNonOk,
}

const FIXTURE_SLOTS: [B4TerminalOracleSlot; B4_TERMINAL_FIXTURE_COUNT] = [
    B4TerminalOracleSlot::LiftPo214,
    B4TerminalOracleSlot::LiftPovwPo218,
    B4TerminalOracleSlot::JoinPovw,
    B4TerminalOracleSlot::JoinUnwrapPovw,
    B4TerminalOracleSlot::ResolvePovw,
    B4TerminalOracleSlot::ResolveUnwrapPovw,
    B4TerminalOracleSlot::Union,
    B4TerminalOracleSlot::UnwrapPovw,
    B4TerminalOracleSlot::AllowedTerminalNonOk,
];

impl B4TerminalOracleSlot {
    const fn fixture_id(self) -> &'static str {
        match self {
            Self::LiftPo214 => "lift-po2-14",
            Self::LiftPovwPo218 => "lift-povw-po2-18",
            Self::JoinPovw => "join-povw",
            Self::JoinUnwrapPovw => "join-unwrap-povw",
            Self::ResolvePovw => "resolve-povw",
            Self::ResolveUnwrapPovw => "resolve-unwrap-povw",
            Self::Union => "union",
            Self::UnwrapPovw => "unwrap-povw",
            Self::AllowedTerminalNonOk => "allowed-terminal-non-ok",
        }
    }

    const fn claim_kind(self) -> B4TerminalClaimKindV1 {
        match self {
            Self::LiftPovwPo218 | Self::JoinPovw | Self::ResolvePovw => {
                B4TerminalClaimKindV1::WorkReceiptClaim
            }
            Self::Union => B4TerminalClaimKindV1::UnionClaim,
            Self::LiftPo214
            | Self::JoinUnwrapPovw
            | Self::ResolveUnwrapPovw
            | Self::UnwrapPovw
            | Self::AllowedTerminalNonOk => B4TerminalClaimKindV1::ReceiptClaim,
        }
    }

    const fn fixed_family(self) -> Option<&'static str> {
        match self {
            Self::LiftPo214 => Some("identity"),
            Self::LiftPovwPo218 => Some("lift-povw-po2-18"),
            Self::JoinPovw => Some("join-povw"),
            Self::JoinUnwrapPovw => Some("join-unwrap-povw"),
            Self::ResolvePovw => Some("resolve-povw"),
            Self::ResolveUnwrapPovw => Some("resolve-unwrap-povw"),
            Self::Union => Some("union"),
            Self::UnwrapPovw => Some("unwrap-povw"),
            Self::AllowedTerminalNonOk => None,
        }
    }

    const fn required_direct_ok(self) -> Option<bool> {
        match self {
            Self::Union => None,
            Self::AllowedTerminalNonOk => Some(false),
            _ => Some(true),
        }
    }

    fn raw_seal_path(self) -> String {
        format!(
            "{B4_TERMINAL_FIXTURE_DIRECTORY}/{}.raw-seal.bin",
            self.fixture_id()
        )
    }

    fn receipt_oracle_path(self) -> String {
        format!(
            "{B4_TERMINAL_FIXTURE_DIRECTORY}/{}.receipt-oracle.bincode",
            self.fixture_id()
        )
    }
}

/// Closed failure classes emitted by terminal-oracle replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum B4TerminalOracleReplayErrorKind {
    /// A fixed artifact map is missing a path or contains an extra path.
    ArtifactMapShape,
    /// A fixed artifact length is outside its exact bound.
    ArtifactLength,
    /// Allocation for a bounded artifact failed.
    Allocation,
    /// A typed receipt did not decode with the frozen bincode options.
    ReceiptDecode,
    /// A decoded typed receipt could not be re-encoded.
    ReceiptReencode,
    /// Receipt bytes failed the defensive byte-exact round trip. No standard
    /// tracked RISC Zero receipt currently reaches this class.
    ReceiptEncodingNotExact,
    /// Compiled RISC Zero version, control rows, root, or parameters drifted.
    CompiledAuthorityDrift,
    /// Receipt seal, hash suite, inclusion path, or profile shape drifted.
    ReceiptProfileShape,
    /// Upstream cryptographic verification rejected the typed receipt.
    ReceiptCryptographicVerification,
    /// A claim field required for derive-first replay was pruned.
    RequiredClaimPruned,
    /// Direct application program, status, or assumptions semantics drifted.
    DirectApplicationSemantics,
    /// The union claim could not be linked exhaustively to verified direct fixtures.
    UnionWitnessDerivation,
    /// The nine derived fixtures do not satisfy the closed portable catalogue.
    DerivedCatalogueInvalid,
    /// Candidate bytes are malformed, noncanonical, or drift outside one
    /// exactly isolated planned binding field.
    CandidateCatalogueInvalid,
    /// Candidate catalogue bytes describe data other than the derived replay.
    CandidateCatalogueBindingMismatch,
}

/// Typed replay failure with an optional immutable fixture position.
#[derive(Debug)]
pub struct B4TerminalOracleReplayError {
    kind: B4TerminalOracleReplayErrorKind,
    slot: Option<B4TerminalOracleSlot>,
    detail: String,
}

impl B4TerminalOracleReplayError {
    fn new(
        kind: B4TerminalOracleReplayErrorKind,
        slot: Option<B4TerminalOracleSlot>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            slot,
            detail: detail.into(),
        }
    }

    /// Return the closed error class.
    #[must_use]
    pub const fn kind(&self) -> B4TerminalOracleReplayErrorKind {
        self.kind
    }

    /// Return the fixed fixture position, when the failure is fixture-local.
    #[must_use]
    pub const fn slot(&self) -> Option<B4TerminalOracleSlot> {
        self.slot
    }
}

impl fmt::Display for B4TerminalOracleReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.slot {
            Some(slot) => write!(
                formatter,
                "{:?} for {}: {}",
                self.kind,
                slot.fixture_id(),
                self.detail
            ),
            None => write!(formatter, "{:?}: {}", self.kind, self.detail),
        }
    }
}

impl std::error::Error for B4TerminalOracleReplayError {}

/// Cryptographically verified derive-first state.
///
/// All fields are private and this type has no public data constructor,
/// deserializer, or synthetic-success path.  The only producer is
/// [`replay_fixed_terminal_oracles`].
pub struct VerifiedB4TerminalOracleReplay {
    derived_catalogue: Eip0045B4TerminalFixtureCatalogV1,
}

impl VerifiedB4TerminalOracleReplay {
    /// Parse and bind canonical candidate-catalogue bytes to the derive-first replay.
    ///
    /// Candidate fields are never consulted by replay and cannot select an
    /// artifact path, decoder, fixture family, control, or verifier context.
    ///
    /// # Errors
    ///
    /// Exact semantic equality accepts. A lexically valid, exactly isolated
    /// mutation of `programId`, one fixture `claimDigest`, or one terminal
    /// `controlId` is a binding mismatch even when it also breaks a
    /// candidate-internal link. Every other drift, whether structurally valid
    /// or invalid, and every malformed or noncanonical source remains private.
    pub fn bind_candidate_catalogue_jcs(
        &self,
        source: &[u8],
    ) -> Result<(), B4TerminalOracleReplayError> {
        let candidate = parse_candidate_catalogue_shape(source)?;
        self.bind_candidate_catalogue(&candidate)
    }

    fn bind_candidate_catalogue(
        &self,
        candidate: &Eip0045B4TerminalFixtureCatalogV1,
    ) -> Result<(), B4TerminalOracleReplayError> {
        if candidate == &self.derived_catalogue {
            return Ok(());
        }
        if is_isolated_planned_binding_mutation(candidate, &self.derived_catalogue) {
            return Err(B4TerminalOracleReplayError::new(
                B4TerminalOracleReplayErrorKind::CandidateCatalogueBindingMismatch,
                None,
                "candidate catalogue carries one isolated planned binding mutation",
            ));
        }
        Err(B4TerminalOracleReplayError::new(
            B4TerminalOracleReplayErrorKind::CandidateCatalogueInvalid,
            None,
            "candidate catalogue drift is outside the three planned binding mutations",
        ))
    }

    /// Return canonical catalogue bytes derived only from verified fixture data.
    ///
    /// # Errors
    ///
    /// Returns an error if the private derived catalogue cannot pass its closed
    /// invariants or serialize as canonical JCS.
    pub fn derived_catalogue_jcs(&self) -> Result<Vec<u8>, B4TerminalOracleReplayError> {
        self.derived_catalogue.to_canonical_jcs().map_err(|error| {
            B4TerminalOracleReplayError::new(
                B4TerminalOracleReplayErrorKind::DerivedCatalogueInvalid,
                None,
                error.to_string(),
            )
        })
    }
}

fn parse_candidate_catalogue_shape(
    source: &[u8],
) -> Result<Eip0045B4TerminalFixtureCatalogV1, B4TerminalOracleReplayError> {
    if source.len() > B4_TERMINAL_FIXTURE_CATALOG_MAX_BYTES {
        return Err(B4TerminalOracleReplayError::new(
            B4TerminalOracleReplayErrorKind::CandidateCatalogueInvalid,
            None,
            "candidate terminal catalogue exceeds its canonical-byte bound",
        ));
    }
    let value = validate_canonical_json_source(source).map_err(|error| {
        B4TerminalOracleReplayError::new(
            B4TerminalOracleReplayErrorKind::CandidateCatalogueInvalid,
            None,
            error.to_string(),
        )
    })?;
    let candidate: Eip0045B4TerminalFixtureCatalogV1 =
        serde_json::from_value(value).map_err(|error| {
            B4TerminalOracleReplayError::new(
                B4TerminalOracleReplayErrorKind::CandidateCatalogueInvalid,
                None,
                error.to_string(),
            )
        })?;
    let round_trip = serde_json::to_value(&candidate)
        .map_err(|error| {
            B4TerminalOracleReplayError::new(
                B4TerminalOracleReplayErrorKind::CandidateCatalogueInvalid,
                None,
                error.to_string(),
            )
        })
        .and_then(|value| {
            canonical_json_bytes(&value).map_err(|error| {
                B4TerminalOracleReplayError::new(
                    B4TerminalOracleReplayErrorKind::CandidateCatalogueInvalid,
                    None,
                    error.to_string(),
                )
            })
        })?;
    if round_trip != source {
        return Err(B4TerminalOracleReplayError::new(
            B4TerminalOracleReplayErrorKind::CandidateCatalogueInvalid,
            None,
            "candidate terminal catalogue does not round-trip byte-exactly",
        ));
    }
    Ok(candidate)
}

fn is_isolated_planned_binding_mutation(
    candidate: &Eip0045B4TerminalFixtureCatalogV1,
    derived: &Eip0045B4TerminalFixtureCatalogV1,
) -> bool {
    let mut normalized = candidate.clone();
    let mut mutation_count = 0_u8;

    if normalized.program_id != derived.program_id {
        if validate_lower_hex_exact(&normalized.program_id, 32).is_err() {
            return false;
        }
        normalized.program_id.clone_from(&derived.program_id);
        mutation_count += 1;
    }
    if normalized.fixtures.len() != derived.fixtures.len() {
        return false;
    }
    for (actual, expected) in normalized.fixtures.iter_mut().zip(&derived.fixtures) {
        if actual.claim_digest != expected.claim_digest {
            if validate_lower_hex_exact(&actual.claim_digest, 32).is_err() {
                return false;
            }
            actual.claim_digest.clone_from(&expected.claim_digest);
            mutation_count += 1;
        }
        if actual.terminal.control_id != expected.terminal.control_id {
            if validate_lower_hex_exact(&actual.terminal.control_id, 32).is_err() {
                return false;
            }
            actual
                .terminal
                .control_id
                .clone_from(&expected.terminal.control_id);
            mutation_count += 1;
        }
    }

    mutation_count == 1 && normalized == *derived
}

/// Replay all nine fixed receipt oracles and derive their complete catalogue.
///
/// Both maps must contain exactly the nine compiled repository-relative paths.
/// Every lookup path, decoder, and expected fixed-family control is selected
/// locally; neither map nor any candidate-catalogue field can change dispatch.
///
/// # Errors
///
/// Returns a closed typed error for artifact custody, codec, compiled-authority,
/// profile-shape, cryptographic, derivation, or catalogue-invariant failure.
pub fn replay_fixed_terminal_oracles(
    raw_seals: &BTreeMap<String, Vec<u8>>,
    receipt_oracles: &BTreeMap<String, Vec<u8>>,
) -> Result<VerifiedB4TerminalOracleReplay, B4TerminalOracleReplayError> {
    let authority = compiled_replay()?;
    validate_artifact_maps(raw_seals, receipt_oracles)?;
    let mut verified_fixtures = Vec::new();
    verified_fixtures
        .try_reserve_exact(B4_TERMINAL_FIXTURE_COUNT)
        .map_err(|error| {
            B4TerminalOracleReplayError::new(
                B4TerminalOracleReplayErrorKind::Allocation,
                None,
                error.to_string(),
            )
        })?;

    for slot in FIXTURE_SLOTS {
        let raw_path = slot.raw_seal_path();
        let oracle_path = slot.receipt_oracle_path();
        let raw_seal = raw_seals.get(&raw_path).ok_or_else(|| {
            B4TerminalOracleReplayError::new(
                B4TerminalOracleReplayErrorKind::ArtifactMapShape,
                Some(slot),
                "raw-seal map is missing its fixed path",
            )
        })?;
        if raw_seal.len() != PROOF_BYTES {
            return Err(B4TerminalOracleReplayError::new(
                B4TerminalOracleReplayErrorKind::ArtifactLength,
                Some(slot),
                format!(
                    "raw seal has {} bytes, expected {PROOF_BYTES}",
                    raw_seal.len()
                ),
            ));
        }
        let oracle_bytes = receipt_oracles.get(&oracle_path).ok_or_else(|| {
            B4TerminalOracleReplayError::new(
                B4TerminalOracleReplayErrorKind::ArtifactMapShape,
                Some(slot),
                "receipt-oracle map is missing its fixed path",
            )
        })?;
        if oracle_bytes.is_empty() || oracle_bytes.len() > RECEIPT_ORACLE_MAX_BYTES {
            return Err(B4TerminalOracleReplayError::new(
                B4TerminalOracleReplayErrorKind::ArtifactLength,
                Some(slot),
                "receipt oracle is outside the closed 1..=1048576-byte bound",
            ));
        }
        let decoded = decode_fixed_receipt(slot, oracle_bytes, &authority)?;
        require_terminal_control_policy(slot, decoded.stock())?;
        let verified_receipt = verify_decoded_receipt(slot, decoded, raw_seal, &authority)?;
        let claim_digest = verified_receipt.claim_digest();
        let application = derive_application(slot, &verified_receipt)?;
        verified_fixtures.push(VerifiedFixture {
            slot,
            stock_index: verified_receipt.stock().stock_index,
            family: verified_receipt.stock().family,
            control_id: verified_receipt.control_id(),
            control_root: verified_receipt.control_root(),
            claim_digest,
            application,
            raw_seal: artifact_binding(raw_path, raw_seal),
            receipt_oracle: artifact_binding(oracle_path, oracle_bytes),
        });
    }

    require_unique_terminal_controls(&verified_fixtures)?;
    let program_id = require_common_program_id(&verified_fixtures)?;
    let fixtures = finish_fixtures(&verified_fixtures)?;
    let derived_catalogue = Eip0045B4TerminalFixtureCatalogV1 {
        format: B4_TERMINAL_FIXTURE_CATALOG_FORMAT.to_owned(),
        format_version: B4_TERMINAL_FIXTURE_CATALOG_FORMAT_VERSION,
        stage: B4_TERMINAL_FIXTURE_CATALOG_STAGE.to_owned(),
        upstream: B4TerminalUpstreamV1 {
            repository: RISC0_REPOSITORY.to_owned(),
            commit: RISC0_COMMIT.to_owned(),
            risc0_zkvm_version: B4_TERMINAL_FIXTURE_RISC0_VERSION.to_owned(),
            receipt_oracle_codec: B4_TERMINAL_FIXTURE_RECEIPT_CODEC.to_owned(),
        },
        program_id: digest_hex(&program_id),
        inner_control_root: RISC0_INNER_CONTROL_ROOT_HEX.to_owned(),
        stock_controls: derived_stock_controls(),
        fixtures,
    };
    derived_catalogue.validate().map_err(|error| {
        B4TerminalOracleReplayError::new(
            B4TerminalOracleReplayErrorKind::DerivedCatalogueInvalid,
            None,
            error.to_string(),
        )
    })?;

    Ok(VerifiedB4TerminalOracleReplay { derived_catalogue })
}

fn validate_artifact_maps(
    raw_seals: &BTreeMap<String, Vec<u8>>,
    receipt_oracles: &BTreeMap<String, Vec<u8>>,
) -> Result<(), B4TerminalOracleReplayError> {
    if raw_seals.len() != B4_TERMINAL_FIXTURE_COUNT
        || receipt_oracles.len() != B4_TERMINAL_FIXTURE_COUNT
    {
        return Err(B4TerminalOracleReplayError::new(
            B4TerminalOracleReplayErrorKind::ArtifactMapShape,
            None,
            "terminal artifact maps must each contain exactly nine paths",
        ));
    }
    for slot in FIXTURE_SLOTS {
        if !raw_seals.contains_key(&slot.raw_seal_path())
            || !receipt_oracles.contains_key(&slot.receipt_oracle_path())
        {
            return Err(B4TerminalOracleReplayError::new(
                B4TerminalOracleReplayErrorKind::ArtifactMapShape,
                Some(slot),
                "terminal artifact maps differ from the fixed path layout",
            ));
        }
    }
    Ok(())
}

fn compiled_replay() -> Result<CompiledStockSuccinctReplayV1, B4TerminalOracleReplayError> {
    for (slot, layout) in FIXTURE_SLOTS
        .iter()
        .copied()
        .zip(crate::b4_terminal::B4_TERMINAL_FIXTURE_LAYOUT)
    {
        if slot.fixture_id() != layout.fixture_id
            || slot.claim_kind() != layout.claim_kind
            || slot.fixed_family() != layout.expected_family
            || slot.required_direct_ok() != layout.direct_ok
        {
            return authority_drift(
                "compiled typed-decoder dispatch differs from the portable fixture layout",
            );
        }
    }
    CompiledStockSuccinctReplayV1::from_compiled_profile()
        .map_err(|error| map_global_stock_replay_error(&error))
}

fn authority_drift<T>(detail: &'static str) -> Result<T, B4TerminalOracleReplayError> {
    Err(B4TerminalOracleReplayError::new(
        B4TerminalOracleReplayErrorKind::CompiledAuthorityDrift,
        None,
        detail,
    ))
}

enum DecodedReceipt {
    Direct(DecodedStockSuccinctReceiptV1<ReceiptClaim>),
    Work(DecodedStockSuccinctReceiptV1<WorkClaim<ReceiptClaim>>),
    Union(DecodedStockSuccinctReceiptV1<UnionClaim>),
}

impl DecodedReceipt {
    fn stock(&self) -> &'static crate::b4_terminal::B4StockControlLayoutV1 {
        match self {
            Self::Direct(receipt) => receipt.stock(),
            Self::Work(receipt) => receipt.stock(),
            Self::Union(receipt) => receipt.stock(),
        }
    }
}

fn decode_fixed_receipt(
    slot: B4TerminalOracleSlot,
    bytes: &[u8],
    replay: &CompiledStockSuccinctReplayV1,
) -> Result<DecodedReceipt, B4TerminalOracleReplayError> {
    let decoded = match slot.claim_kind() {
        B4TerminalClaimKindV1::ReceiptClaim => {
            replay.decode_direct(bytes).map(DecodedReceipt::Direct)
        }
        B4TerminalClaimKindV1::WorkReceiptClaim => {
            replay.decode_work(bytes).map(DecodedReceipt::Work)
        }
        B4TerminalClaimKindV1::UnionClaim => replay.decode_union(bytes).map(DecodedReceipt::Union),
    };
    decoded.map_err(|error| map_stock_replay_error(slot, &error))
}

fn require_terminal_control_policy(
    slot: B4TerminalOracleSlot,
    stock: &'static crate::b4_terminal::B4StockControlLayoutV1,
) -> Result<(), B4TerminalOracleReplayError> {
    match slot.fixed_family() {
        Some(expected) if stock.family != expected => {
            return Err(B4TerminalOracleReplayError::new(
                B4TerminalOracleReplayErrorKind::ReceiptProfileShape,
                Some(slot),
                "receipt control does not match the fixed fixture family",
            ));
        }
        None if !stock.eip_allowed => {
            return Err(B4TerminalOracleReplayError::new(
                B4TerminalOracleReplayErrorKind::ReceiptProfileShape,
                Some(slot),
                "allowed-terminal-non-ok does not use a profile-allowed control",
            ));
        }
        _ => {}
    }
    Ok(())
}

enum VerifiedReceipt {
    Direct(VerifiedStockSuccinctReceiptV1<ReceiptClaim>),
    Work(VerifiedStockSuccinctReceiptV1<WorkClaim<ReceiptClaim>>),
    Union(VerifiedStockSuccinctReceiptV1<UnionClaim>),
}

impl VerifiedReceipt {
    fn stock(&self) -> &'static crate::b4_terminal::B4StockControlLayoutV1 {
        match self {
            Self::Direct(receipt) => receipt.stock(),
            Self::Work(receipt) => receipt.stock(),
            Self::Union(receipt) => receipt.stock(),
        }
    }

    fn control_id(&self) -> Digest {
        match self {
            Self::Direct(receipt) => receipt.control_id(),
            Self::Work(receipt) => receipt.control_id(),
            Self::Union(receipt) => receipt.control_id(),
        }
    }

    fn claim_digest(&self) -> Digest {
        match self {
            Self::Direct(receipt) => receipt.claim_digest(),
            Self::Work(receipt) => receipt.claim_digest(),
            Self::Union(receipt) => receipt.claim_digest(),
        }
    }

    fn control_root(&self) -> Digest {
        match self {
            Self::Direct(receipt) => receipt.control_root(),
            Self::Work(receipt) => receipt.control_root(),
            Self::Union(receipt) => receipt.control_root(),
        }
    }
}

fn verify_decoded_receipt(
    slot: B4TerminalOracleSlot,
    decoded: DecodedReceipt,
    raw_seal: &[u8],
    replay: &CompiledStockSuccinctReplayV1,
) -> Result<VerifiedReceipt, B4TerminalOracleReplayError> {
    match decoded {
        DecodedReceipt::Direct(receipt) => replay
            .verify(receipt, raw_seal)
            .map(VerifiedReceipt::Direct),
        DecodedReceipt::Work(receipt) => {
            replay.verify(receipt, raw_seal).map(VerifiedReceipt::Work)
        }
        DecodedReceipt::Union(receipt) => {
            replay.verify(receipt, raw_seal).map(VerifiedReceipt::Union)
        }
    }
    .map_err(|error| map_stock_replay_error(slot, &error))
}

fn map_stock_replay_error(
    slot: B4TerminalOracleSlot,
    error: &StockReceiptReplayError,
) -> B4TerminalOracleReplayError {
    B4TerminalOracleReplayError::new(
        map_stock_replay_error_kind(error.kind()),
        Some(slot),
        error.detail(),
    )
}

fn map_global_stock_replay_error(error: &StockReceiptReplayError) -> B4TerminalOracleReplayError {
    B4TerminalOracleReplayError::new(
        map_stock_replay_error_kind(error.kind()),
        None,
        error.detail(),
    )
}

const fn map_stock_replay_error_kind(
    kind: StockReceiptReplayErrorKind,
) -> B4TerminalOracleReplayErrorKind {
    match kind {
        StockReceiptReplayErrorKind::ArtifactLength => {
            B4TerminalOracleReplayErrorKind::ArtifactLength
        }
        StockReceiptReplayErrorKind::ReceiptDecode => {
            B4TerminalOracleReplayErrorKind::ReceiptDecode
        }
        StockReceiptReplayErrorKind::ReceiptReencode => {
            B4TerminalOracleReplayErrorKind::ReceiptReencode
        }
        StockReceiptReplayErrorKind::ReceiptEncodingNotExact => {
            B4TerminalOracleReplayErrorKind::ReceiptEncodingNotExact
        }
        StockReceiptReplayErrorKind::CompiledAuthorityDrift => {
            B4TerminalOracleReplayErrorKind::CompiledAuthorityDrift
        }
        StockReceiptReplayErrorKind::ReceiptProfileShape => {
            B4TerminalOracleReplayErrorKind::ReceiptProfileShape
        }
        StockReceiptReplayErrorKind::ReceiptCryptographicVerification => {
            B4TerminalOracleReplayErrorKind::ReceiptCryptographicVerification
        }
    }
}

enum DerivedApplication {
    Direct {
        program_id: Digest,
        binding: B4DirectApplicationBindingV1,
    },
    Union {
        left: Digest,
        right: Digest,
    },
}

fn derive_application(
    slot: B4TerminalOracleSlot,
    verified: &VerifiedReceipt,
) -> Result<DerivedApplication, B4TerminalOracleReplayError> {
    match verified {
        VerifiedReceipt::Direct(receipt) => {
            let claim = require_open(receipt.claim(), slot, "outer ReceiptClaim")?;
            derive_direct_application(slot, claim)
        }
        VerifiedReceipt::Work(receipt) => {
            let work = require_open(receipt.claim(), slot, "outer WorkClaim")?;
            let claim = require_open(&work.claim, slot, "ReceiptClaim below WorkClaim")?;
            derive_direct_application(slot, claim)
        }
        VerifiedReceipt::Union(receipt) => {
            let union = require_open(receipt.claim(), slot, "outer UnionClaim")?;
            Ok(DerivedApplication::Union {
                left: union.left,
                right: union.right,
            })
        }
    }
}

fn require_open<'a, T>(
    value: &'a MaybePruned<T>,
    slot: B4TerminalOracleSlot,
    field: &'static str,
) -> Result<&'a T, B4TerminalOracleReplayError> {
    value.as_value().map_err(|_| {
        B4TerminalOracleReplayError::new(
            B4TerminalOracleReplayErrorKind::RequiredClaimPruned,
            Some(slot),
            format!("{field} is pruned"),
        )
    })
}

fn derive_direct_application(
    slot: B4TerminalOracleSlot,
    claim: &ReceiptClaim,
) -> Result<DerivedApplication, B4TerminalOracleReplayError> {
    let (system, user) = claim.exit_code.into_pair();
    let status = B4ExitStatusV1 {
        system,
        user,
        ok: claim.exit_code.is_ok(),
    };
    if slot.required_direct_ok() != Some(status.ok) {
        return Err(B4TerminalOracleReplayError::new(
            B4TerminalOracleReplayErrorKind::DirectApplicationSemantics,
            Some(slot),
            "derived application status does not isolate the fixed policy case",
        ));
    }

    let output = claim.output.as_value().map_err(|_| {
        B4TerminalOracleReplayError::new(
            B4TerminalOracleReplayErrorKind::RequiredClaimPruned,
            Some(slot),
            "ReceiptClaim output option is pruned",
        )
    })?;
    let assumptions = match (claim.exit_code.expects_output(), output) {
        (false, None) => B4AssumptionsBindingV1::NoOutput,
        (true, Some(output)) => B4AssumptionsBindingV1::Commitment {
            digest: digest_hex(&output.assumptions.digest()),
            empty: output.assumptions.is_empty(),
        },
        (expects_output, actual) => {
            return Err(B4TerminalOracleReplayError::new(
                B4TerminalOracleReplayErrorKind::DirectApplicationSemantics,
                Some(slot),
                format!(
                    "exit/output shape mismatch: expectsOutput={expects_output}, outputPresent={}",
                    actual.is_some()
                ),
            ));
        }
    };
    if !matches!(
        assumptions,
        B4AssumptionsBindingV1::NoOutput | B4AssumptionsBindingV1::Commitment { empty: true, .. }
    ) {
        return Err(B4TerminalOracleReplayError::new(
            B4TerminalOracleReplayErrorKind::DirectApplicationSemantics,
            Some(slot),
            "direct application carries a non-empty assumptions list",
        ));
    }

    Ok(DerivedApplication::Direct {
        program_id: claim.pre.digest(),
        binding: B4DirectApplicationBindingV1 {
            application_claim_digest: digest_hex(&claim.digest()),
            status,
            assumptions,
        },
    })
}

struct VerifiedFixture {
    slot: B4TerminalOracleSlot,
    stock_index: u32,
    family: &'static str,
    control_id: Digest,
    control_root: Digest,
    claim_digest: Digest,
    application: DerivedApplication,
    raw_seal: B4TerminalArtifactV1,
    receipt_oracle: B4TerminalArtifactV1,
}

fn require_unique_terminal_controls(
    fixtures: &[VerifiedFixture],
) -> Result<(), B4TerminalOracleReplayError> {
    let mut controls = BTreeSet::new();
    if fixtures
        .iter()
        .any(|fixture| !controls.insert(fixture.control_id))
    {
        return Err(B4TerminalOracleReplayError::new(
            B4TerminalOracleReplayErrorKind::DerivedCatalogueInvalid,
            None,
            "two terminal fixtures use the same control ID",
        ));
    }
    Ok(())
}

fn require_common_program_id(
    fixtures: &[VerifiedFixture],
) -> Result<Digest, B4TerminalOracleReplayError> {
    let mut direct = fixtures.iter().filter_map(|fixture| {
        if let DerivedApplication::Direct { program_id, .. } = &fixture.application {
            Some(*program_id)
        } else {
            None
        }
    });
    let first = direct.next().ok_or_else(|| {
        B4TerminalOracleReplayError::new(
            B4TerminalOracleReplayErrorKind::DirectApplicationSemantics,
            None,
            "terminal corpus contains no direct application fixture",
        )
    })?;
    if direct.any(|program_id| program_id != first) {
        return Err(B4TerminalOracleReplayError::new(
            B4TerminalOracleReplayErrorKind::DirectApplicationSemantics,
            None,
            "verified direct fixtures do not derive one common program ID",
        ));
    }
    Ok(first)
}

fn finish_fixtures(
    verified: &[VerifiedFixture],
) -> Result<Vec<B4TerminalFixtureV1>, B4TerminalOracleReplayError> {
    let mut fixtures = Vec::new();
    fixtures
        .try_reserve_exact(B4_TERMINAL_FIXTURE_COUNT)
        .map_err(|error| {
            B4TerminalOracleReplayError::new(
                B4TerminalOracleReplayErrorKind::Allocation,
                None,
                error.to_string(),
            )
        })?;
    for fixture in verified {
        let application = match &fixture.application {
            DerivedApplication::Direct { binding, .. } => B4ApplicationBindingV1::Direct {
                binding: binding.clone(),
            },
            DerivedApplication::Union { left, right } => B4ApplicationBindingV1::Union {
                left: derive_union_side(*left, verified)?,
                right: derive_union_side(*right, verified)?,
            },
        };
        let stock = &B4_STOCK_CONTROL_LAYOUT[fixture.stock_index as usize];
        fixtures.push(B4TerminalFixtureV1 {
            fixture_id: fixture.slot.fixture_id().to_owned(),
            family: fixture.family.to_owned(),
            claim_kind: fixture.slot.claim_kind(),
            claim_digest: digest_hex(&fixture.claim_digest),
            terminal: B4TerminalBindingV1 {
                stock_index: fixture.stock_index,
                control_id: digest_hex(&fixture.control_id),
                control_root: digest_hex(&fixture.control_root),
                eip_allowed: stock.eip_allowed,
            },
            application,
            raw_seal: fixture.raw_seal.clone(),
            receipt_oracle: fixture.receipt_oracle.clone(),
        });
    }
    Ok(fixtures)
}

fn derive_union_side(
    assumption_digest: Digest,
    verified: &[VerifiedFixture],
) -> Result<B4UnionAssumptionBindingV1, B4TerminalOracleReplayError> {
    let mut source_claim: Option<Digest> = None;
    let mut witnesses = Vec::new();
    witnesses
        .try_reserve_exact(B4_TERMINAL_FIXTURE_COUNT)
        .map_err(|error| {
            B4TerminalOracleReplayError::new(
                B4TerminalOracleReplayErrorKind::Allocation,
                Some(B4TerminalOracleSlot::Union),
                error.to_string(),
            )
        })?;

    for fixture in verified {
        let DerivedApplication::Direct { binding, .. } = &fixture.application else {
            continue;
        };
        if fixture.slot.fixed_family().is_none()
            || !binding.status.ok
            || !assumptions_empty_or_absent(&binding.assumptions)
        {
            continue;
        }
        let candidate = Assumption {
            claim: fixture.claim_digest,
            control_root: ALLOWED_CONTROL_ROOT,
        }
        .digest();
        if candidate == assumption_digest {
            if let Some(expected) = source_claim {
                if expected != fixture.claim_digest {
                    return Err(B4TerminalOracleReplayError::new(
                        B4TerminalOracleReplayErrorKind::UnionWitnessDerivation,
                        Some(B4TerminalOracleSlot::Union),
                        "one union assumption digest maps to two source claims",
                    ));
                }
            } else {
                source_claim = Some(fixture.claim_digest);
            }
            witnesses.push(fixture.slot.fixture_id().to_owned());
        }
    }

    let source_claim = source_claim.ok_or_else(|| {
        B4TerminalOracleReplayError::new(
            B4TerminalOracleReplayErrorKind::UnionWitnessDerivation,
            Some(B4TerminalOracleSlot::Union),
            "union assumption has no verified eligible direct fixture",
        )
    })?;
    Ok(B4UnionAssumptionBindingV1 {
        assumption_digest: digest_hex(&assumption_digest),
        source_claim_digest: digest_hex(&source_claim),
        witness_fixture_ids: witnesses,
    })
}

fn assumptions_empty_or_absent(binding: &B4AssumptionsBindingV1) -> bool {
    matches!(
        binding,
        B4AssumptionsBindingV1::NoOutput | B4AssumptionsBindingV1::Commitment { empty: true, .. }
    )
}

fn derived_stock_controls() -> Vec<B4StockControlV1> {
    B4_STOCK_CONTROL_LAYOUT
        .iter()
        .map(|row| B4StockControlV1 {
            stock_index: row.stock_index,
            family: row.family.to_owned(),
            upstream_program: row.upstream_program.to_owned(),
            control_id: row.control_id.to_owned(),
            eip_allowed: row.eip_allowed,
        })
        .collect()
}

fn artifact_binding(path: String, bytes: &[u8]) -> B4TerminalArtifactV1 {
    B4TerminalArtifactV1 {
        path,
        byte_length: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(bytes)),
    }
}

fn digest_hex(digest: &Digest) -> String {
    hex::encode(digest.as_bytes())
}

#[cfg(test)]
mod tests {
    use std::{env, fs, path::PathBuf};

    use super::*;
    use crate::b4_terminal::{
        B4_TERMINAL_FIXTURE_LAYOUT, terminal_fixture_raw_seal_path,
        terminal_fixture_receipt_oracle_path,
    };

    // Portable grammar fixture only. This is not receipt-oracle or producer
    // evidence and cannot make the pending handler row eligible for freezing.
    #[allow(clippy::too_many_lines)]
    fn synthetic_derived_catalogue() -> Eip0045B4TerminalFixtureCatalogV1 {
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
        let mut fixtures = Vec::new();
        for (index, layout) in B4_TERMINAL_FIXTURE_LAYOUT.iter().enumerate() {
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
            let application = if layout.claim_kind == B4TerminalClaimKindV1::UnionClaim {
                B4ApplicationBindingV1::Union {
                    left: B4UnionAssumptionBindingV1 {
                        assumption_digest: test_digest(90),
                        source_claim_digest: test_digest(1),
                        witness_fixture_ids: vec!["lift-po2-14".to_owned()],
                    },
                    right: B4UnionAssumptionBindingV1 {
                        assumption_digest: test_digest(91),
                        source_claim_digest: test_digest(2),
                        witness_fixture_ids: vec!["lift-povw-po2-18".to_owned()],
                    },
                }
            } else {
                B4ApplicationBindingV1::Direct {
                    binding: B4DirectApplicationBindingV1 {
                        application_claim_digest: test_digest(40 + index),
                        status,
                        assumptions: if layout.direct_ok == Some(false) {
                            B4AssumptionsBindingV1::NoOutput
                        } else {
                            B4AssumptionsBindingV1::Commitment {
                                digest: test_digest(0),
                                empty: true,
                            }
                        },
                    },
                }
            };
            let raw = vec![u8::try_from(index + 1).unwrap(); PROOF_BYTES];
            fixtures.push(B4TerminalFixtureV1 {
                fixture_id: layout.fixture_id.to_owned(),
                family: stock.family.to_owned(),
                claim_kind: layout.claim_kind,
                claim_digest: test_digest(index + 1),
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
                    sha256: hex::encode(Sha256::digest(&raw)),
                },
                receipt_oracle: B4TerminalArtifactV1 {
                    path: terminal_fixture_receipt_oracle_path(layout.fixture_id).unwrap(),
                    byte_length: 1,
                    sha256: hex::encode(Sha256::digest([u8::try_from(index).unwrap()])),
                },
            });
        }
        let catalogue = Eip0045B4TerminalFixtureCatalogV1 {
            format: B4_TERMINAL_FIXTURE_CATALOG_FORMAT.to_owned(),
            format_version: B4_TERMINAL_FIXTURE_CATALOG_FORMAT_VERSION,
            stage: B4_TERMINAL_FIXTURE_CATALOG_STAGE.to_owned(),
            upstream: B4TerminalUpstreamV1 {
                repository: RISC0_REPOSITORY.to_owned(),
                commit: RISC0_COMMIT.to_owned(),
                risc0_zkvm_version: B4_TERMINAL_FIXTURE_RISC0_VERSION.to_owned(),
                receipt_oracle_codec: B4_TERMINAL_FIXTURE_RECEIPT_CODEC.to_owned(),
            },
            program_id: test_digest(200),
            inner_control_root: RISC0_INNER_CONTROL_ROOT_HEX.to_owned(),
            stock_controls,
            fixtures,
        };
        catalogue.validate().unwrap();
        catalogue
    }

    fn test_digest(value: usize) -> String {
        format!("{value:064x}")
    }

    fn candidate_bytes(candidate: &Eip0045B4TerminalFixtureCatalogV1) -> Vec<u8> {
        canonical_json_bytes(&serde_json::to_value(candidate).unwrap()).unwrap()
    }

    fn changed_digest(source: &str) -> String {
        let mut changed = source.as_bytes().to_vec();
        changed[0] = if changed[0] == b'0' { b'1' } else { b'0' };
        String::from_utf8(changed).unwrap()
    }

    #[test]
    fn fixed_decoder_matrix_is_exactly_five_three_one() {
        assert_eq!(FIXTURE_SLOTS.len(), B4_TERMINAL_FIXTURE_COUNT);
        assert_eq!(
            FIXTURE_SLOTS
                .iter()
                .filter(|slot| slot.claim_kind() == B4TerminalClaimKindV1::ReceiptClaim)
                .count(),
            5
        );
        assert_eq!(
            FIXTURE_SLOTS
                .iter()
                .filter(|slot| slot.claim_kind() == B4TerminalClaimKindV1::WorkReceiptClaim)
                .count(),
            3
        );
        assert_eq!(
            FIXTURE_SLOTS
                .iter()
                .filter(|slot| slot.claim_kind() == B4TerminalClaimKindV1::UnionClaim)
                .count(),
            1
        );
        for (slot, layout) in FIXTURE_SLOTS
            .iter()
            .copied()
            .zip(crate::b4_terminal::B4_TERMINAL_FIXTURE_LAYOUT)
        {
            assert_eq!(slot.fixture_id(), layout.fixture_id);
            assert_eq!(slot.claim_kind(), layout.claim_kind);
            assert_eq!(slot.fixed_family(), layout.expected_family);
            assert_eq!(slot.required_direct_ok(), layout.direct_ok);
        }
    }

    #[test]
    fn fixed_paths_are_exhaustive_and_non_overlapping() {
        let raw = FIXTURE_SLOTS
            .iter()
            .copied()
            .map(B4TerminalOracleSlot::raw_seal_path)
            .collect::<BTreeSet<_>>();
        let receipts = FIXTURE_SLOTS
            .iter()
            .copied()
            .map(B4TerminalOracleSlot::receipt_oracle_path)
            .collect::<BTreeSet<_>>();
        assert_eq!(raw.len(), B4_TERMINAL_FIXTURE_COUNT);
        assert_eq!(receipts.len(), B4_TERMINAL_FIXTURE_COUNT);
        assert!(raw.is_disjoint(&receipts));
    }

    #[test]
    fn artifact_maps_require_the_exact_fixed_paths() {
        let mut raw = FIXTURE_SLOTS
            .iter()
            .copied()
            .map(|slot| (slot.raw_seal_path(), Vec::new()))
            .collect::<BTreeMap<_, _>>();
        let receipts = FIXTURE_SLOTS
            .iter()
            .copied()
            .map(|slot| (slot.receipt_oracle_path(), Vec::new()))
            .collect::<BTreeMap<_, _>>();
        validate_artifact_maps(&raw, &receipts).unwrap();

        raw.remove(&B4TerminalOracleSlot::LiftPo214.raw_seal_path());
        raw.insert("not-a-fixed-path".to_owned(), Vec::new());
        let error = validate_artifact_maps(&raw, &receipts).unwrap_err();
        assert_eq!(
            error.kind(),
            B4TerminalOracleReplayErrorKind::ArtifactMapShape
        );
    }

    #[test]
    fn shared_replay_errors_map_one_to_one_without_losing_the_terminal_slot() {
        let replay = CompiledStockSuccinctReplayV1::from_compiled_profile().unwrap();
        let Err(shared) = replay.decode_direct(&[]) else {
            panic!("empty receipt oracle unexpectedly decoded");
        };

        let mapped = map_stock_replay_error(B4TerminalOracleSlot::LiftPo214, &shared);
        assert_eq!(
            mapped.kind(),
            B4TerminalOracleReplayErrorKind::ArtifactLength
        );
        assert_eq!(mapped.slot(), Some(B4TerminalOracleSlot::LiftPo214));
    }

    #[test]
    fn shared_replay_error_kind_mapping_is_exhaustive() {
        let cases = [
            (
                StockReceiptReplayErrorKind::ArtifactLength,
                B4TerminalOracleReplayErrorKind::ArtifactLength,
            ),
            (
                StockReceiptReplayErrorKind::ReceiptDecode,
                B4TerminalOracleReplayErrorKind::ReceiptDecode,
            ),
            (
                StockReceiptReplayErrorKind::ReceiptReencode,
                B4TerminalOracleReplayErrorKind::ReceiptReencode,
            ),
            (
                StockReceiptReplayErrorKind::ReceiptEncodingNotExact,
                B4TerminalOracleReplayErrorKind::ReceiptEncodingNotExact,
            ),
            (
                StockReceiptReplayErrorKind::CompiledAuthorityDrift,
                B4TerminalOracleReplayErrorKind::CompiledAuthorityDrift,
            ),
            (
                StockReceiptReplayErrorKind::ReceiptProfileShape,
                B4TerminalOracleReplayErrorKind::ReceiptProfileShape,
            ),
            (
                StockReceiptReplayErrorKind::ReceiptCryptographicVerification,
                B4TerminalOracleReplayErrorKind::ReceiptCryptographicVerification,
            ),
        ];

        for (shared, terminal) in cases {
            assert_eq!(map_stock_replay_error_kind(shared), terminal);
        }
    }

    #[test]
    fn compiled_terminal_dispatch_accepts_the_shared_stock_replay() {
        compiled_replay().unwrap();
    }

    #[test]
    fn compiled_terminal_policy_is_applied_to_shared_stock_rows() {
        for slot in FIXTURE_SLOTS {
            let Some(family) = slot.fixed_family() else {
                continue;
            };
            let stock = B4_STOCK_CONTROL_LAYOUT
                .iter()
                .find(|row| row.family == family)
                .unwrap();
            require_terminal_control_policy(slot, stock).unwrap();
        }

        let wrong_slot = B4TerminalOracleSlot::JoinPovw;
        let lift_po2_14 = B4_STOCK_CONTROL_LAYOUT
            .iter()
            .find(|row| row.family == "lift-po2-14")
            .unwrap();
        let error = require_terminal_control_policy(wrong_slot, lift_po2_14).unwrap_err();
        assert_eq!(
            error.kind(),
            B4TerminalOracleReplayErrorKind::ReceiptProfileShape
        );
    }

    #[test]
    fn stable_slot_accepts_identity_and_rejects_lift14() {
        let slot = B4TerminalOracleSlot::LiftPo214;
        assert_eq!(slot.fixture_id(), "lift-po2-14");
        assert_eq!(slot.fixed_family(), Some("identity"));

        let identity = B4_STOCK_CONTROL_LAYOUT
            .iter()
            .find(|row| row.family == "identity")
            .unwrap();
        assert!(require_terminal_control_policy(slot, identity).is_ok());

        let lift_po2_14 = B4_STOCK_CONTROL_LAYOUT
            .iter()
            .find(|row| row.family == "lift-po2-14")
            .unwrap();
        let error = require_terminal_control_policy(slot, lift_po2_14).unwrap_err();
        assert_eq!(
            error.kind(),
            B4TerminalOracleReplayErrorKind::ReceiptProfileShape
        );
    }

    #[test]
    fn planned_catalogue_field_mutations_reach_the_typed_binding_boundary() {
        let derived = synthetic_derived_catalogue();
        let replay = VerifiedB4TerminalOracleReplay {
            derived_catalogue: derived.clone(),
        };

        let mut program_id = derived.clone();
        program_id.program_id = test_digest(201);
        let mut claim_digest = derived.clone();
        claim_digest.fixtures[0].claim_digest = test_digest(202);
        let mut control_id = derived;
        control_id.fixtures[0].terminal.control_id = test_digest(203);

        for candidate in [program_id, claim_digest, control_id] {
            let error = replay
                .bind_candidate_catalogue_jcs(&candidate_bytes(&candidate))
                .unwrap_err();
            assert_eq!(
                error.kind(),
                B4TerminalOracleReplayErrorKind::CandidateCatalogueBindingMismatch
            );
        }
    }

    #[test]
    fn unrelated_invalid_or_noncanonical_catalogues_remain_private() {
        let derived = synthetic_derived_catalogue();
        let replay = VerifiedB4TerminalOracleReplay {
            derived_catalogue: derived.clone(),
        };

        let mut unrelated = derived;
        unrelated.stage = "other".to_owned();
        let error = replay
            .bind_candidate_catalogue_jcs(&candidate_bytes(&unrelated))
            .unwrap_err();
        assert_eq!(
            error.kind(),
            B4TerminalOracleReplayErrorKind::CandidateCatalogueInvalid
        );

        let mut malformed_planned_field = synthetic_derived_catalogue();
        malformed_planned_field.program_id = "not-a-digest".to_owned();
        let error = replay
            .bind_candidate_catalogue_jcs(&candidate_bytes(&malformed_planned_field))
            .unwrap_err();
        assert_eq!(
            error.kind(),
            B4TerminalOracleReplayErrorKind::CandidateCatalogueInvalid
        );

        let mut coordinated = synthetic_derived_catalogue();
        coordinated.program_id = test_digest(204);
        coordinated.fixtures[0].claim_digest = test_digest(205);
        let error = replay
            .bind_candidate_catalogue_jcs(&candidate_bytes(&coordinated))
            .unwrap_err();
        assert_eq!(
            error.kind(),
            B4TerminalOracleReplayErrorKind::CandidateCatalogueInvalid
        );

        let pretty = serde_json::to_vec_pretty(&serde_json::to_value(unrelated).unwrap()).unwrap();
        let error = replay.bind_candidate_catalogue_jcs(&pretty).unwrap_err();
        assert_eq!(
            error.kind(),
            B4TerminalOracleReplayErrorKind::CandidateCatalogueInvalid
        );
    }

    #[test]
    fn structurally_valid_unplanned_drift_remains_private() {
        let derived = synthetic_derived_catalogue();
        let replay = VerifiedB4TerminalOracleReplay {
            derived_catalogue: derived.clone(),
        };
        let mut unplanned = derived;
        unplanned.fixtures[0].receipt_oracle.byte_length += 1;
        unplanned.validate().unwrap();

        let error = replay
            .bind_candidate_catalogue_jcs(&candidate_bytes(&unplanned))
            .unwrap_err();
        assert_eq!(
            error.kind(),
            B4TerminalOracleReplayErrorKind::CandidateCatalogueInvalid
        );
    }

    #[test]
    #[ignore = "requires EIP0045_B4_TERMINAL_FIXTURE_REPOSITORY_ROOT"]
    fn real_producer_replay_precedes_all_three_planned_binding_mutations() {
        let root =
            PathBuf::from(env::var_os("EIP0045_B4_TERMINAL_FIXTURE_REPOSITORY_ROOT").unwrap());
        let mut raw_seals = BTreeMap::new();
        let mut receipt_oracles = BTreeMap::new();
        for slot in FIXTURE_SLOTS {
            let raw_path = slot.raw_seal_path();
            let receipt_path = slot.receipt_oracle_path();
            raw_seals.insert(raw_path.clone(), fs::read(root.join(&raw_path)).unwrap());
            receipt_oracles.insert(
                receipt_path.clone(),
                fs::read(root.join(&receipt_path)).unwrap(),
            );
        }

        let replay = replay_fixed_terminal_oracles(&raw_seals, &receipt_oracles).unwrap();
        let derived = Eip0045B4TerminalFixtureCatalogV1::from_canonical_jcs(
            &replay.derived_catalogue_jcs().unwrap(),
        )
        .unwrap();
        let mut program_id = derived.clone();
        program_id.program_id = changed_digest(&program_id.program_id);
        let mut claim_digest = derived.clone();
        claim_digest.fixtures[0].claim_digest =
            changed_digest(&claim_digest.fixtures[0].claim_digest);
        let mut control_id = derived;
        control_id.fixtures[0].terminal.control_id =
            changed_digest(&control_id.fixtures[0].terminal.control_id);

        for candidate in [program_id, claim_digest, control_id] {
            let error = replay
                .bind_candidate_catalogue_jcs(&candidate_bytes(&candidate))
                .unwrap_err();
            assert_eq!(
                error.kind(),
                B4TerminalOracleReplayErrorKind::CandidateCatalogueBindingMismatch
            );
        }
    }
}
