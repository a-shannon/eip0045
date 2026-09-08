//! Single compile-time authority for B4 negative handler contracts.
//!
//! The twenty rows below own pair selection, physical custody bounds, the
//! future production adapter selector, and freeze state. Structural input
//! parsing, Linux custody, dispatch, and campaign precommit must derive from
//! this table rather than maintain parallel pair or cardinality inventories.

use std::{collections::BTreeSet, sync::OnceLock};

use anyhow::{Context, Result, bail, ensure};

use crate::{
    b4_plan::{
        B4_NEGATIVE_PLAN_GROUP_COUNT, B4_NEGATIVE_PLAN_VARIANT_COUNT, B4MaterializationDomain,
        B4NegativeExecutionSurface, B4NegativePlanExecutionV1, B4NegativeQaResultCode,
        Eip0045B4NegativePlanV1,
    },
    receipt_oracle_codec::RECEIPT_ORACLE_MAX_BYTES_U64,
};

/// Exact number of canonical negative-handler dispatch pairs.
pub(crate) const B4_NEGATIVE_HANDLER_CONTRACT_COUNT: usize = 20;
/// Maximum canonical neutral-input byte length.
pub(crate) const NEGATIVE_INPUT_MAX_BYTES: u64 = 65_536;
/// Maximum positional external-context cardinality.
pub(crate) const MAX_NEGATIVE_CONTEXT_FILES: usize = 64;
/// Maximum byte length of one negative subject or context file.
pub(crate) const MAX_NEGATIVE_DATA_FILE_BYTES: u64 = 536_870_912;
/// Maximum aggregate measured-file bytes admitted by one negative root.
pub(crate) const MAX_NEGATIVE_ROOT_ALLOCATION_BYTES: u64 =
    NEGATIVE_INPUT_MAX_BYTES + MAX_NEGATIVE_DATA_FILE_BYTES;

static CANONICAL_NEGATIVE_PLAN: OnceLock<Eip0045B4NegativePlanV1> = OnceLock::new();

const MANIFEST_BYTES: u64 = 458;
const ALGORITHM_BYTES: u64 = 29_773;
const CONSTANTS_BYTES: u64 = 65_119;
const RAW_SEAL_BYTES: u64 = 222_668;
const STATEMENT_MIN_BYTES: u64 = 159;
const STATEMENT_MAX_BYTES: u64 = 16_543;
const PROFILE_ID_BYTES: u64 = 32;
const POSITIVE_INPUT_BYTES_MAX: u64 = 65_536;
const GUEST_ELF_BYTES_MAX: u64 = 4_194_304;
const PROFILE_ID_PREIMAGE_BUNDLE_BYTES: u64 = 963;
const TERMINAL_RECORD_BUNDLE_BYTES: u64 = 512;
const ABSTRACT_TREE_MAX_BYTES: u64 = 16 * 1024;
const MANIFEST_CANDIDATE_MAX_BYTES: u64 = 64 * 1024;
const PROFILE_PACKAGE_MAX_BYTES: u64 = 128 * 1024;
const SEQUENCE_CATALOG_BUNDLE_MAX_BYTES: u64 = 128 * 1024 + 16;
const CANDIDATE_REGISTRY_BUNDLE_MAX_BYTES: u64 = 8 * 1024 * 1024 + 16;
const NEGATIVE_BINDING_INDEX_BUNDLE_MAX_BYTES: u64 = 128 * 1024 + 8 * 1024 * 1024 + 20;
const TERMINAL_CATALOG_BUNDLE_MAX_BYTES: u64 = 16 * 1024 * 1024;
const ANCESTRY_BUNDLE_MAX_BYTES: u64 = 2 * 1024 * 1024;
const OPCODE_INPUTS_MAX_BYTES: u64 = 262_144;

/// Inclusive physical byte bounds owned by one negative handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct B4NegativeByteBounds {
    minimum: u64,
    maximum: u64,
}

impl B4NegativeByteBounds {
    /// Construct inclusive physical byte bounds.
    #[must_use]
    pub(crate) const fn new(minimum: u64, maximum: u64) -> Self {
        Self { minimum, maximum }
    }

    /// Inclusive lower byte bound.
    #[must_use]
    pub(crate) const fn minimum(self) -> u64 {
        self.minimum
    }

    /// Inclusive upper byte bound.
    #[must_use]
    pub(crate) const fn maximum(self) -> u64 {
        self.maximum
    }

    /// Whether `length` lies inside this contract.
    #[must_use]
    #[cfg(feature = "validator")]
    pub(crate) const fn contains(self, length: u64) -> bool {
        length >= self.minimum && length <= self.maximum
    }

    fn validate(self, label: &str) -> Result<()> {
        ensure!(
            self.minimum <= self.maximum,
            "{label} custody bounds are internally inconsistent"
        );
        ensure!(
            self.maximum <= MAX_NEGATIVE_DATA_FILE_BYTES,
            "{label} custody bound exceeds the V1 physical-file limit"
        );
        Ok(())
    }
}

/// Physical-custody projection owned by one handler-table row.
///
/// `contexts` is positional: entry zero bounds `context/00.bin`, entry one
/// bounds `context/01.bin`, and so on.
#[derive(Clone, Copy, Debug)]
pub(crate) struct B4NegativeCustodyContract {
    materialization_domain: B4MaterializationDomain,
    validation_surface: B4NegativeExecutionSurface,
    subject: B4NegativeByteBounds,
    contexts: &'static [B4NegativeByteBounds],
    total_allocation_cap: u64,
}

impl B4NegativeCustodyContract {
    /// Construct one physical-custody projection.
    #[must_use]
    pub(crate) const fn new(
        materialization_domain: B4MaterializationDomain,
        validation_surface: B4NegativeExecutionSurface,
        subject: B4NegativeByteBounds,
        contexts: &'static [B4NegativeByteBounds],
        total_allocation_cap: u64,
    ) -> Self {
        Self {
            materialization_domain,
            validation_surface,
            subject,
            contexts,
            total_allocation_cap,
        }
    }

    /// Materialization owner selected by the canonical plan.
    #[must_use]
    pub(crate) const fn materialization_domain(self) -> B4MaterializationDomain {
        self.materialization_domain
    }

    /// Validation entry point selected by the canonical plan.
    #[must_use]
    pub(crate) const fn validation_surface(self) -> B4NegativeExecutionSurface {
        self.validation_surface
    }

    /// Subject physical bounds.
    #[must_use]
    pub(crate) const fn subject(self) -> B4NegativeByteBounds {
        self.subject
    }

    /// Exact positional context bounds.
    #[must_use]
    pub(crate) const fn contexts(self) -> &'static [B4NegativeByteBounds] {
        self.contexts
    }

    /// Aggregate measured-file byte cap.
    #[must_use]
    #[cfg(feature = "validator")]
    #[cfg_attr(
        not(all(target_os = "linux", target_arch = "x86_64")),
        allow(
            dead_code,
            reason = "the production custody consumer exists only on Linux/x86_64"
        )
    )]
    pub(crate) const fn total_allocation_cap(self) -> u64 {
        self.total_allocation_cap
    }

    /// Validate internal physical-bound consistency.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid per-file bounds, excessive context
    /// cardinality, arithmetic overflow, or a cap that differs from the exact
    /// sum of all row-owned maxima plus the neutral-input maximum.
    pub(crate) fn validate(self) -> Result<()> {
        self.subject.validate("negative subject")?;
        ensure!(
            self.contexts.len() <= MAX_NEGATIVE_CONTEXT_FILES,
            "negative custody contract exceeds the positional context limit"
        );
        for (index, bounds) in self.contexts.iter().copied().enumerate() {
            bounds.validate(&format!("negative context {index:02}"))?;
            ensure!(
                bounds.minimum() >= 1,
                "negative context custody bounds admit an empty file"
            );
        }
        ensure!(
            self.subject.minimum() >= 1
                || (self.materialization_domain == B4MaterializationDomain::VerifierInput
                    && self.validation_surface == B4NegativeExecutionSurface::Risc0ParserInternal),
            "only the internal parser handler may admit an empty subject"
        );
        let expected_cap = maximum_allocation(self.subject, self.contexts)?;
        ensure!(
            self.total_allocation_cap == expected_cap,
            "negative custody allocation cap differs from its exact physical maxima"
        );
        ensure!(
            (1..=MAX_NEGATIVE_ROOT_ALLOCATION_BYTES).contains(&self.total_allocation_cap),
            "negative custody allocation cap is outside the V1 root limit"
        );
        Ok(())
    }
}

/// Closed adapter selected by one handler-table row.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub(crate) enum B4NegativeHandlerSelector {
    VerifierOpcodePreflight,
    VerifierRawStatementClaimBinding,
    VerifierRawSealShape,
    VerifierRisc0ParserInternal,
    VerifierRisc0CryptographicVerifier,
    VerifierTerminalPolicy,
    VerifierReceiptClaimPolicy,
    VerifierAncestryReplay,
    ArtifactTerminalPolicy,
    ArtifactProfileManifestCodec,
    ArtifactInitialProfileTarget,
    ArtifactProfileArtifactEnvelope,
    ArtifactActivatedProfilePackage,
    ArtifactTerminalFixtureCatalog,
    ArtifactSequenceSubjectCatalog,
    ArtifactTerminalMetadata,
    ArtifactProfileIdPreimage,
    ArtifactCandidateRegistry,
    ArtifactNegativeBindingIndex,
    TreeCorpusClosure,
}

/// One exact implementation-neutral rejection boundary admitted by a handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub(crate) struct B4NegativeRejectionBoundary {
    class: &'static str,
    stage: &'static str,
}

impl B4NegativeRejectionBoundary {
    const fn new(class: &'static str, stage: &'static str) -> Self {
        Self { class, stage }
    }

    #[must_use]
    pub(crate) const fn class(self) -> &'static str {
        self.class
    }

    #[must_use]
    pub(crate) const fn stage(self) -> &'static str {
        self.stage
    }
}

/// Closed parser-EOF stage vocabulary.
///
/// These stages are named after the canonical physical cuts, but the validator
/// must derive them only from its typed
/// `(phase, cursor_words, required_words, available_words)` boundary.  Case
/// IDs, variant IDs, QA codes, and expected offsets are not validator input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub(crate) enum B4ParserRejectionStage {
    OutputBeforeRead,
    OutputAtLastRequiredWord,
    OuterPo2BeforeRead,
    CodeTopBeforeRead,
    CodeTopAtLastRequiredWord,
    DataTopBeforeRead,
    DataTopAtLastRequiredWord,
    AccumTopBeforeRead,
    AccumTopAtLastRequiredWord,
    CheckTopBeforeRead,
    CheckTopAtLastRequiredWord,
    CoeffUBeforeRead,
    CoeffUAtLastRequiredWord,
    FriRoundOneTopBeforeRead,
    FriRoundOneTopAtLastRequiredWord,
    FriRoundTwoTopBeforeRead,
    FriRoundTwoTopAtLastRequiredWord,
    FriRoundThreeTopBeforeRead,
    FriRoundThreeTopAtLastRequiredWord,
    FinalCoefficientsBeforeRead,
    FinalCoefficientsAtLastRequiredWord,
    QueriesBeforeRead,
    QueriesAtLastRequiredWord,
    QueryZeroAccumOpeningAtLastRequiredWord,
    QueryZeroCodeOpeningBeforeRead,
    QueryZeroCodeOpeningAtLastRequiredWord,
    QueryZeroDataOpeningBeforeRead,
    QueryZeroDataOpeningAtLastRequiredWord,
    QueryZeroCheckOpeningBeforeRead,
    QueryZeroCheckOpeningAtLastRequiredWord,
    QueryZeroFriRoundOneOpeningBeforeRead,
    QueryZeroFriRoundOneOpeningAtLastRequiredWord,
    QueryZeroFriRoundTwoOpeningBeforeRead,
    QueryZeroFriRoundTwoOpeningAtLastRequiredWord,
    QueryZeroFriRoundThreeOpeningBeforeRead,
    QueryZeroFriRoundThreeOpeningAtLastRequiredWord,
}

impl B4ParserRejectionStage {
    fn from_plan_variant(value: &str) -> Option<Self> {
        Some(match value {
            "output-before-read" => Self::OutputBeforeRead,
            "output-at-last-required-word" => Self::OutputAtLastRequiredWord,
            "outer-po2-before-read" => Self::OuterPo2BeforeRead,
            "code-top-before-read" => Self::CodeTopBeforeRead,
            "code-top-at-last-required-word" => Self::CodeTopAtLastRequiredWord,
            "data-top-before-read" => Self::DataTopBeforeRead,
            "data-top-at-last-required-word" => Self::DataTopAtLastRequiredWord,
            "accum-top-before-read" => Self::AccumTopBeforeRead,
            "accum-top-at-last-required-word" => Self::AccumTopAtLastRequiredWord,
            "check-top-before-read" => Self::CheckTopBeforeRead,
            "check-top-at-last-required-word" => Self::CheckTopAtLastRequiredWord,
            "coeff-u-before-read" => Self::CoeffUBeforeRead,
            "coeff-u-at-last-required-word" => Self::CoeffUAtLastRequiredWord,
            "fri-round-one-top-before-read" => Self::FriRoundOneTopBeforeRead,
            "fri-round-one-top-at-last-required-word" => Self::FriRoundOneTopAtLastRequiredWord,
            "fri-round-two-top-before-read" => Self::FriRoundTwoTopBeforeRead,
            "fri-round-two-top-at-last-required-word" => Self::FriRoundTwoTopAtLastRequiredWord,
            "fri-round-three-top-before-read" => Self::FriRoundThreeTopBeforeRead,
            "fri-round-three-top-at-last-required-word" => Self::FriRoundThreeTopAtLastRequiredWord,
            "final-coefficients-before-read" => Self::FinalCoefficientsBeforeRead,
            "final-coefficients-at-last-required-word" => Self::FinalCoefficientsAtLastRequiredWord,
            "queries-before-read" => Self::QueriesBeforeRead,
            "queries-at-last-required-word" => Self::QueriesAtLastRequiredWord,
            "query-zero-accum-opening-at-last-required-word" => {
                Self::QueryZeroAccumOpeningAtLastRequiredWord
            }
            "query-zero-code-opening-before-read" => Self::QueryZeroCodeOpeningBeforeRead,
            "query-zero-code-opening-at-last-required-word" => {
                Self::QueryZeroCodeOpeningAtLastRequiredWord
            }
            "query-zero-data-opening-before-read" => Self::QueryZeroDataOpeningBeforeRead,
            "query-zero-data-opening-at-last-required-word" => {
                Self::QueryZeroDataOpeningAtLastRequiredWord
            }
            "query-zero-check-opening-before-read" => Self::QueryZeroCheckOpeningBeforeRead,
            "query-zero-check-opening-at-last-required-word" => {
                Self::QueryZeroCheckOpeningAtLastRequiredWord
            }
            "query-zero-fri-round-one-opening-before-read" => {
                Self::QueryZeroFriRoundOneOpeningBeforeRead
            }
            "query-zero-fri-round-one-opening-at-last-required-word" => {
                Self::QueryZeroFriRoundOneOpeningAtLastRequiredWord
            }
            "query-zero-fri-round-two-opening-before-read" => {
                Self::QueryZeroFriRoundTwoOpeningBeforeRead
            }
            "query-zero-fri-round-two-opening-at-last-required-word" => {
                Self::QueryZeroFriRoundTwoOpeningAtLastRequiredWord
            }
            "query-zero-fri-round-three-opening-before-read" => {
                Self::QueryZeroFriRoundThreeOpeningBeforeRead
            }
            "query-zero-fri-round-three-opening-at-last-required-word" => {
                Self::QueryZeroFriRoundThreeOpeningAtLastRequiredWord
            }
            _ => return None,
        })
    }

    /// Stable implementation-neutral stage identifier.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::OutputBeforeRead => "risc0-read-iop-output-before-read",
            Self::OutputAtLastRequiredWord => "risc0-read-iop-output-at-last-required-word",
            Self::OuterPo2BeforeRead => "risc0-read-iop-outer-po2-before-read",
            Self::CodeTopBeforeRead => "risc0-read-iop-code-top-before-read",
            Self::CodeTopAtLastRequiredWord => "risc0-read-iop-code-top-at-last-required-word",
            Self::DataTopBeforeRead => "risc0-read-iop-data-top-before-read",
            Self::DataTopAtLastRequiredWord => "risc0-read-iop-data-top-at-last-required-word",
            Self::AccumTopBeforeRead => "risc0-read-iop-accum-top-before-read",
            Self::AccumTopAtLastRequiredWord => "risc0-read-iop-accum-top-at-last-required-word",
            Self::CheckTopBeforeRead => "risc0-read-iop-check-top-before-read",
            Self::CheckTopAtLastRequiredWord => "risc0-read-iop-check-top-at-last-required-word",
            Self::CoeffUBeforeRead => "risc0-read-iop-coeff-u-before-read",
            Self::CoeffUAtLastRequiredWord => "risc0-read-iop-coeff-u-at-last-required-word",
            Self::FriRoundOneTopBeforeRead => "risc0-read-iop-fri-round-one-top-before-read",
            Self::FriRoundOneTopAtLastRequiredWord => {
                "risc0-read-iop-fri-round-one-top-at-last-required-word"
            }
            Self::FriRoundTwoTopBeforeRead => "risc0-read-iop-fri-round-two-top-before-read",
            Self::FriRoundTwoTopAtLastRequiredWord => {
                "risc0-read-iop-fri-round-two-top-at-last-required-word"
            }
            Self::FriRoundThreeTopBeforeRead => "risc0-read-iop-fri-round-three-top-before-read",
            Self::FriRoundThreeTopAtLastRequiredWord => {
                "risc0-read-iop-fri-round-three-top-at-last-required-word"
            }
            Self::FinalCoefficientsBeforeRead => "risc0-read-iop-final-coefficients-before-read",
            Self::FinalCoefficientsAtLastRequiredWord => {
                "risc0-read-iop-final-coefficients-at-last-required-word"
            }
            Self::QueriesBeforeRead => "risc0-read-iop-queries-before-read",
            Self::QueriesAtLastRequiredWord => "risc0-read-iop-queries-at-last-required-word",
            Self::QueryZeroAccumOpeningAtLastRequiredWord => {
                "risc0-read-iop-query-zero-accum-opening-at-last-required-word"
            }
            Self::QueryZeroCodeOpeningBeforeRead => {
                "risc0-read-iop-query-zero-code-opening-before-read"
            }
            Self::QueryZeroCodeOpeningAtLastRequiredWord => {
                "risc0-read-iop-query-zero-code-opening-at-last-required-word"
            }
            Self::QueryZeroDataOpeningBeforeRead => {
                "risc0-read-iop-query-zero-data-opening-before-read"
            }
            Self::QueryZeroDataOpeningAtLastRequiredWord => {
                "risc0-read-iop-query-zero-data-opening-at-last-required-word"
            }
            Self::QueryZeroCheckOpeningBeforeRead => {
                "risc0-read-iop-query-zero-check-opening-before-read"
            }
            Self::QueryZeroCheckOpeningAtLastRequiredWord => {
                "risc0-read-iop-query-zero-check-opening-at-last-required-word"
            }
            Self::QueryZeroFriRoundOneOpeningBeforeRead => {
                "risc0-read-iop-query-zero-fri-round-one-opening-before-read"
            }
            Self::QueryZeroFriRoundOneOpeningAtLastRequiredWord => {
                "risc0-read-iop-query-zero-fri-round-one-opening-at-last-required-word"
            }
            Self::QueryZeroFriRoundTwoOpeningBeforeRead => {
                "risc0-read-iop-query-zero-fri-round-two-opening-before-read"
            }
            Self::QueryZeroFriRoundTwoOpeningAtLastRequiredWord => {
                "risc0-read-iop-query-zero-fri-round-two-opening-at-last-required-word"
            }
            Self::QueryZeroFriRoundThreeOpeningBeforeRead => {
                "risc0-read-iop-query-zero-fri-round-three-opening-before-read"
            }
            Self::QueryZeroFriRoundThreeOpeningAtLastRequiredWord => {
                "risc0-read-iop-query-zero-fri-round-three-opening-at-last-required-word"
            }
        }
    }
}

/// One row in the sole canonical negative-handler authority.
#[derive(Clone, Copy, Debug)]
pub(crate) struct B4NegativeHandlerContract {
    custody: B4NegativeCustodyContract,
    selector: B4NegativeHandlerSelector,
    rejection_boundaries: &'static [B4NegativeRejectionBoundary],
    frozen: bool,
}

impl B4NegativeHandlerContract {
    const fn frozen(
        custody: B4NegativeCustodyContract,
        selector: B4NegativeHandlerSelector,
        rejection_boundaries: &'static [B4NegativeRejectionBoundary],
    ) -> Self {
        Self {
            custody,
            selector,
            rejection_boundaries,
            frozen: true,
        }
    }

    const fn pending(
        custody: B4NegativeCustodyContract,
        selector: B4NegativeHandlerSelector,
        rejection_boundaries: &'static [B4NegativeRejectionBoundary],
    ) -> Self {
        Self {
            custody,
            selector,
            rejection_boundaries,
            frozen: false,
        }
    }

    /// Physical custody contract for this row.
    #[must_use]
    pub(crate) const fn custody(self) -> B4NegativeCustodyContract {
        self.custody
    }

    /// Production adapter selected by this row.
    #[must_use]
    pub(crate) const fn selector(self) -> B4NegativeHandlerSelector {
        self.selector
    }

    /// Exact finite rejection vocabulary admitted by this row.
    #[must_use]
    pub(crate) const fn rejection_boundaries(self) -> &'static [B4NegativeRejectionBoundary] {
        self.rejection_boundaries
    }

    /// Whether this row admits the exact supplied rejection pair.
    #[must_use]
    pub(crate) fn admits_rejection(self, class: &str, stage: &str) -> bool {
        self.rejection_boundaries
            .iter()
            .any(|boundary| boundary.class == class && boundary.stage == stage)
    }

    /// Whether implementation and focused fixtures have frozen this row.
    #[must_use]
    pub(crate) const fn is_frozen(self) -> bool {
        self.frozen
    }
}

const NO_CONTEXT: [B4NegativeByteBounds; 0] = [];
const MANIFEST_CONTEXT: [B4NegativeByteBounds; 1] =
    [B4NegativeByteBounds::new(MANIFEST_BYTES, MANIFEST_BYTES)];
const MANIFEST_AND_SEAL_CONTEXT: [B4NegativeByteBounds; 2] = [
    B4NegativeByteBounds::new(MANIFEST_BYTES, MANIFEST_BYTES),
    B4NegativeByteBounds::new(RAW_SEAL_BYTES, RAW_SEAL_BYTES),
];
const MANIFEST_AND_RECEIPT_ORACLE_CONTEXT: [B4NegativeByteBounds; 2] = [
    B4NegativeByteBounds::new(MANIFEST_BYTES, MANIFEST_BYTES),
    B4NegativeByteBounds::new(1, RECEIPT_ORACLE_MAX_BYTES_U64),
];
const MANIFEST_AND_STATEMENT_CONTEXT: [B4NegativeByteBounds; 2] = [
    B4NegativeByteBounds::new(MANIFEST_BYTES, MANIFEST_BYTES),
    B4NegativeByteBounds::new(STATEMENT_MIN_BYTES, STATEMENT_MAX_BYTES),
];
const ACTIVATED_PACKAGE_CONTEXT: [B4NegativeByteBounds; 3] = [
    B4NegativeByteBounds::new(MANIFEST_BYTES, MANIFEST_BYTES),
    B4NegativeByteBounds::new(ALGORITHM_BYTES, ALGORITHM_BYTES),
    B4NegativeByteBounds::new(CONSTANTS_BYTES, CONSTANTS_BYTES),
];
const TERMINAL_METADATA_POSITIVE_CONTEXT: [B4NegativeByteBounds; 7] = [
    B4NegativeByteBounds::new(1, POSITIVE_INPUT_BYTES_MAX),
    B4NegativeByteBounds::new(MANIFEST_BYTES, MANIFEST_BYTES),
    B4NegativeByteBounds::new(ALGORITHM_BYTES, ALGORITHM_BYTES),
    B4NegativeByteBounds::new(CONSTANTS_BYTES, CONSTANTS_BYTES),
    B4NegativeByteBounds::new(1, GUEST_ELF_BYTES_MAX),
    B4NegativeByteBounds::new(STATEMENT_MIN_BYTES, STATEMENT_MAX_BYTES),
    B4NegativeByteBounds::new(RAW_SEAL_BYTES, RAW_SEAL_BYTES),
];

const fn rejection(class: &'static str, stage: &'static str) -> B4NegativeRejectionBoundary {
    B4NegativeRejectionBoundary::new(class, stage)
}

const OPCODE_PREFLIGHT_REJECTIONS: &[B4NegativeRejectionBoundary] = &[
    rejection(
        "opcode-input-shape-invalid",
        "opcode-profile-id-byte-length",
    ),
    rejection(
        "opcode-input-shape-invalid",
        "opcode-program-id-byte-length",
    ),
    rejection(
        "opcode-input-shape-invalid",
        "opcode-application-payload-byte-length",
    ),
    rejection("opcode-input-shape-invalid", "opcode-proof-chunk-count"),
    rejection(
        "opcode-input-shape-invalid",
        "opcode-proof-chunk-byte-length",
    ),
];
const RECEIPT_CLAIM_REJECTIONS: &[B4NegativeRejectionBoundary] = &[rejection(
    "receipt-claim-mismatch",
    "expected-claim-binding",
)];
const RAW_SEAL_REJECTIONS: &[B4NegativeRejectionBoundary] = &[
    rejection("raw-seal-shape-invalid", "babybear-word-reduction"),
    rejection("raw-seal-shape-invalid", "inner-root-padding"),
    rejection("raw-seal-shape-invalid", "claim-halfword-decoding"),
    rejection("raw-seal-shape-invalid", "outer-po2-preflight"),
    rejection("inner-control-root-mismatch", "inner-control-root-binding"),
];
const fn parser_rejection(stage: B4ParserRejectionStage) -> B4NegativeRejectionBoundary {
    rejection("risc0-parser-invalid", stage.as_str())
}

const PARSER_REJECTIONS: &[B4NegativeRejectionBoundary] = &[
    parser_rejection(B4ParserRejectionStage::OutputBeforeRead),
    parser_rejection(B4ParserRejectionStage::OutputAtLastRequiredWord),
    parser_rejection(B4ParserRejectionStage::OuterPo2BeforeRead),
    parser_rejection(B4ParserRejectionStage::CodeTopBeforeRead),
    parser_rejection(B4ParserRejectionStage::CodeTopAtLastRequiredWord),
    parser_rejection(B4ParserRejectionStage::DataTopBeforeRead),
    parser_rejection(B4ParserRejectionStage::DataTopAtLastRequiredWord),
    parser_rejection(B4ParserRejectionStage::AccumTopBeforeRead),
    parser_rejection(B4ParserRejectionStage::AccumTopAtLastRequiredWord),
    parser_rejection(B4ParserRejectionStage::CheckTopBeforeRead),
    parser_rejection(B4ParserRejectionStage::CheckTopAtLastRequiredWord),
    parser_rejection(B4ParserRejectionStage::CoeffUBeforeRead),
    parser_rejection(B4ParserRejectionStage::CoeffUAtLastRequiredWord),
    parser_rejection(B4ParserRejectionStage::FriRoundOneTopBeforeRead),
    parser_rejection(B4ParserRejectionStage::FriRoundOneTopAtLastRequiredWord),
    parser_rejection(B4ParserRejectionStage::FriRoundTwoTopBeforeRead),
    parser_rejection(B4ParserRejectionStage::FriRoundTwoTopAtLastRequiredWord),
    parser_rejection(B4ParserRejectionStage::FriRoundThreeTopBeforeRead),
    parser_rejection(B4ParserRejectionStage::FriRoundThreeTopAtLastRequiredWord),
    parser_rejection(B4ParserRejectionStage::FinalCoefficientsBeforeRead),
    parser_rejection(B4ParserRejectionStage::FinalCoefficientsAtLastRequiredWord),
    parser_rejection(B4ParserRejectionStage::QueriesBeforeRead),
    parser_rejection(B4ParserRejectionStage::QueriesAtLastRequiredWord),
    parser_rejection(B4ParserRejectionStage::QueryZeroAccumOpeningAtLastRequiredWord),
    parser_rejection(B4ParserRejectionStage::QueryZeroCodeOpeningBeforeRead),
    parser_rejection(B4ParserRejectionStage::QueryZeroCodeOpeningAtLastRequiredWord),
    parser_rejection(B4ParserRejectionStage::QueryZeroDataOpeningBeforeRead),
    parser_rejection(B4ParserRejectionStage::QueryZeroDataOpeningAtLastRequiredWord),
    parser_rejection(B4ParserRejectionStage::QueryZeroCheckOpeningBeforeRead),
    parser_rejection(B4ParserRejectionStage::QueryZeroCheckOpeningAtLastRequiredWord),
    parser_rejection(B4ParserRejectionStage::QueryZeroFriRoundOneOpeningBeforeRead),
    parser_rejection(B4ParserRejectionStage::QueryZeroFriRoundOneOpeningAtLastRequiredWord),
    parser_rejection(B4ParserRejectionStage::QueryZeroFriRoundTwoOpeningBeforeRead),
    parser_rejection(B4ParserRejectionStage::QueryZeroFriRoundTwoOpeningAtLastRequiredWord),
    parser_rejection(B4ParserRejectionStage::QueryZeroFriRoundThreeOpeningBeforeRead),
    parser_rejection(B4ParserRejectionStage::QueryZeroFriRoundThreeOpeningAtLastRequiredWord),
];
const CRYPTO_REJECTIONS: &[B4NegativeRejectionBoundary] = &[
    rejection("risc0-proof-invalid", "risc0-validity-check"),
    rejection("risc0-proof-invalid", "risc0-fri-round-two-query-zero"),
    rejection(
        "risc0-proof-invalid",
        "risc0-fri-final-polynomial-query-zero",
    ),
    rejection("risc0-proof-invalid", "risc0-fri-inner-query-forty-nine"),
];
const TERMINAL_POLICY_REJECTIONS: &[B4NegativeRejectionBoundary] =
    &[rejection("terminal-policy-mismatch", "terminal-control-id")];
const ANCESTRY_REJECTIONS: &[B4NegativeRejectionBoundary] = &[
    rejection("ancestry-replay-mismatch", "claim-edge"),
    rejection("ancestry-replay-mismatch", "resolve-explicit-semantics"),
    rejection("ancestry-replay-mismatch", "resolve-zero-root-semantics"),
    rejection("ancestry-replay-mismatch", "resolve-assumption-inventory"),
];
const PROFILE_MANIFEST_REJECTIONS: &[B4NegativeRejectionBoundary] = &[
    rejection("profile-manifest-invalid", "profile-manifest-byte-length"),
    rejection(
        "profile-manifest-invalid",
        "profile-manifest-format-version",
    ),
    rejection("profile-manifest-invalid", "profile-manifest-terminal-kind"),
    rejection(
        "profile-manifest-invalid",
        "profile-manifest-terminal-parameter",
    ),
    rejection(
        "profile-manifest-invalid",
        "profile-manifest-terminal-order",
    ),
    rejection(
        "profile-manifest-invalid",
        "profile-manifest-terminal-control-id-uniqueness",
    ),
    rejection("profile-manifest-invalid", "profile-manifest-artifact-kind"),
];
const INITIAL_PROFILE_REJECTIONS: &[B4NegativeRejectionBoundary] = &[
    rejection("initial-profile-target-mismatch", "exact-proof-bytes"),
    rejection(
        "initial-profile-target-mismatch",
        "maximum-application-payload-bytes",
    ),
    rejection("initial-profile-target-mismatch", "outer-po2"),
    rejection("initial-profile-target-mismatch", "inner-control-root"),
    rejection("initial-profile-target-mismatch", "terminal-control-id"),
];
const PROFILE_ARTIFACT_REJECTIONS: &[B4NegativeRejectionBoundary] = &[
    rejection(
        "profile-artifact-package-mismatch",
        "profile-artifact-byte-length",
    ),
    rejection(
        "profile-artifact-package-mismatch",
        "profile-artifact-digest",
    ),
];
const ACTIVATED_PROFILE_REJECTIONS: &[B4NegativeRejectionBoundary] = &[rejection(
    "activated-profile-package-mismatch",
    "activated-profile-id",
)];
const TERMINAL_FIXTURE_REJECTIONS: &[B4NegativeRejectionBoundary] = &[rejection(
    "terminal-fixture-catalog-mismatch",
    "terminal-fixture-catalog-binding",
)];
const SEQUENCE_SUBJECT_REJECTIONS: &[B4NegativeRejectionBoundary] = &[rejection(
    "sequence-subject-catalog-invalid",
    "sequence-subject-catalog-validation",
)];
const TERMINAL_METADATA_REJECTIONS: &[B4NegativeRejectionBoundary] = &[rejection(
    "terminal-metadata-mismatch",
    "terminal-metadata-binding",
)];
const PROFILE_ID_PREIMAGE_REJECTIONS: &[B4NegativeRejectionBoundary] = &[rejection(
    "profile-id-preimage-mismatch",
    "profile-id-preimage-binding",
)];
const CANDIDATE_REGISTRY_REJECTIONS: &[B4NegativeRejectionBoundary] = &[rejection(
    "candidate-registry-invalid",
    "candidate-registry-validation",
)];
const NEGATIVE_BINDING_REJECTIONS: &[B4NegativeRejectionBoundary] = &[
    rejection(
        "negative-binding-index-invalid",
        "negative-binding-index-codec",
    ),
    rejection(
        "negative-binding-index-invalid",
        "negative-binding-index-plan-binding",
    ),
];
const CORPUS_CLOSURE_REJECTIONS: &[B4NegativeRejectionBoundary] = &[
    rejection("corpus-closure-mismatch", "corpus-required-role"),
    rejection("corpus-closure-mismatch", "corpus-unexpected-role"),
];

const fn unchecked_maximum_allocation(
    subject: B4NegativeByteBounds,
    contexts: &[B4NegativeByteBounds],
) -> u64 {
    let mut total = NEGATIVE_INPUT_MAX_BYTES + subject.maximum;
    let mut index = 0;
    while index < contexts.len() {
        total += contexts[index].maximum;
        index += 1;
    }
    total
}

const fn custody(
    domain: B4MaterializationDomain,
    surface: B4NegativeExecutionSurface,
    subject: B4NegativeByteBounds,
    contexts: &'static [B4NegativeByteBounds],
) -> B4NegativeCustodyContract {
    B4NegativeCustodyContract::new(
        domain,
        surface,
        subject,
        contexts,
        unchecked_maximum_allocation(subject, contexts),
    )
}

use B4MaterializationDomain as D;
use B4NegativeExecutionSurface as S;
use B4NegativeHandlerSelector as H;

/// Sole twenty-row negative-handler contract inventory.
///
/// Rows remain pending until their production adapters and focused fixtures
/// close. A pending row cannot be selected by production custody, and the
/// global campaign-precommit gate requires every row to be frozen.
const B4_NEGATIVE_HANDLER_CONTRACTS: &[B4NegativeHandlerContract] = &[
    B4NegativeHandlerContract::frozen(
        custody(
            D::VerifierInput,
            S::OpcodePreflight,
            B4NegativeByteBounds::new(1, OPCODE_INPUTS_MAX_BYTES),
            &MANIFEST_CONTEXT,
        ),
        H::VerifierOpcodePreflight,
        OPCODE_PREFLIGHT_REJECTIONS,
    ),
    B4NegativeHandlerContract::frozen(
        custody(
            D::VerifierInput,
            S::RawStatementClaimBinding,
            B4NegativeByteBounds::new(STATEMENT_MIN_BYTES, STATEMENT_MAX_BYTES),
            &MANIFEST_AND_SEAL_CONTEXT,
        ),
        H::VerifierRawStatementClaimBinding,
        RECEIPT_CLAIM_REJECTIONS,
    ),
    B4NegativeHandlerContract::frozen(
        custody(
            D::VerifierInput,
            S::RawSealShape,
            B4NegativeByteBounds::new(1, OPCODE_INPUTS_MAX_BYTES),
            &MANIFEST_CONTEXT,
        ),
        H::VerifierRawSealShape,
        RAW_SEAL_REJECTIONS,
    ),
    B4NegativeHandlerContract::frozen(
        custody(
            D::VerifierInput,
            S::Risc0ParserInternal,
            B4NegativeByteBounds::new(0, RAW_SEAL_BYTES),
            &MANIFEST_CONTEXT,
        ),
        H::VerifierRisc0ParserInternal,
        PARSER_REJECTIONS,
    ),
    B4NegativeHandlerContract::frozen(
        custody(
            D::VerifierInput,
            S::Risc0CryptographicVerifier,
            B4NegativeByteBounds::new(RAW_SEAL_BYTES, RAW_SEAL_BYTES),
            &MANIFEST_AND_RECEIPT_ORACLE_CONTEXT,
        ),
        H::VerifierRisc0CryptographicVerifier,
        CRYPTO_REJECTIONS,
    ),
    B4NegativeHandlerContract::frozen(
        custody(
            D::VerifierInput,
            S::TerminalPolicy,
            B4NegativeByteBounds::new(RAW_SEAL_BYTES, RAW_SEAL_BYTES),
            &MANIFEST_CONTEXT,
        ),
        H::VerifierTerminalPolicy,
        TERMINAL_POLICY_REJECTIONS,
    ),
    B4NegativeHandlerContract::frozen(
        custody(
            D::VerifierInput,
            S::ReceiptClaimPolicy,
            B4NegativeByteBounds::new(RAW_SEAL_BYTES, RAW_SEAL_BYTES),
            &MANIFEST_AND_STATEMENT_CONTEXT,
        ),
        H::VerifierReceiptClaimPolicy,
        RECEIPT_CLAIM_REJECTIONS,
    ),
    B4NegativeHandlerContract::pending(
        custody(
            D::VerifierInput,
            S::AncestryReplay,
            B4NegativeByteBounds::new(1, ANCESTRY_BUNDLE_MAX_BYTES),
            &MANIFEST_CONTEXT,
        ),
        H::VerifierAncestryReplay,
        ANCESTRY_REJECTIONS,
    ),
    B4NegativeHandlerContract::frozen(
        custody(
            D::ArtifactValidator,
            S::TerminalPolicy,
            B4NegativeByteBounds::new(36, 36),
            &MANIFEST_CONTEXT,
        ),
        H::ArtifactTerminalPolicy,
        TERMINAL_POLICY_REJECTIONS,
    ),
    B4NegativeHandlerContract::frozen(
        custody(
            D::ArtifactValidator,
            S::ProfileManifestCodec,
            B4NegativeByteBounds::new(1, MANIFEST_CANDIDATE_MAX_BYTES),
            &NO_CONTEXT,
        ),
        H::ArtifactProfileManifestCodec,
        PROFILE_MANIFEST_REJECTIONS,
    ),
    B4NegativeHandlerContract::frozen(
        custody(
            D::ArtifactValidator,
            S::InitialProfileTarget,
            B4NegativeByteBounds::new(MANIFEST_BYTES, MANIFEST_BYTES),
            &NO_CONTEXT,
        ),
        H::ArtifactInitialProfileTarget,
        INITIAL_PROFILE_REJECTIONS,
    ),
    B4NegativeHandlerContract::frozen(
        custody(
            D::ArtifactValidator,
            S::ProfileArtifactEnvelope,
            B4NegativeByteBounds::new(1, PROFILE_PACKAGE_MAX_BYTES),
            &NO_CONTEXT,
        ),
        H::ArtifactProfileArtifactEnvelope,
        PROFILE_ARTIFACT_REJECTIONS,
    ),
    B4NegativeHandlerContract::frozen(
        custody(
            D::ArtifactValidator,
            S::ActivatedProfilePackage,
            B4NegativeByteBounds::new(PROFILE_ID_BYTES, PROFILE_ID_BYTES),
            &ACTIVATED_PACKAGE_CONTEXT,
        ),
        H::ArtifactActivatedProfilePackage,
        ACTIVATED_PROFILE_REJECTIONS,
    ),
    B4NegativeHandlerContract::frozen(
        custody(
            D::ArtifactValidator,
            S::TerminalFixtureCatalog,
            B4NegativeByteBounds::new(1, TERMINAL_CATALOG_BUNDLE_MAX_BYTES),
            &NO_CONTEXT,
        ),
        H::ArtifactTerminalFixtureCatalog,
        TERMINAL_FIXTURE_REJECTIONS,
    ),
    B4NegativeHandlerContract::frozen(
        custody(
            D::ArtifactValidator,
            S::SequenceSubjectCatalog,
            B4NegativeByteBounds::new(1, SEQUENCE_CATALOG_BUNDLE_MAX_BYTES),
            &NO_CONTEXT,
        ),
        H::ArtifactSequenceSubjectCatalog,
        SEQUENCE_SUBJECT_REJECTIONS,
    ),
    B4NegativeHandlerContract::frozen(
        custody(
            D::ArtifactValidator,
            S::TerminalMetadata,
            B4NegativeByteBounds::new(TERMINAL_RECORD_BUNDLE_BYTES, TERMINAL_RECORD_BUNDLE_BYTES),
            &TERMINAL_METADATA_POSITIVE_CONTEXT,
        ),
        H::ArtifactTerminalMetadata,
        TERMINAL_METADATA_REJECTIONS,
    ),
    B4NegativeHandlerContract::frozen(
        custody(
            D::ArtifactValidator,
            S::ProfileIdPreimage,
            B4NegativeByteBounds::new(
                PROFILE_ID_PREIMAGE_BUNDLE_BYTES,
                PROFILE_ID_PREIMAGE_BUNDLE_BYTES,
            ),
            &NO_CONTEXT,
        ),
        H::ArtifactProfileIdPreimage,
        PROFILE_ID_PREIMAGE_REJECTIONS,
    ),
    B4NegativeHandlerContract::frozen(
        custody(
            D::ArtifactValidator,
            S::CandidateRegistry,
            B4NegativeByteBounds::new(1, CANDIDATE_REGISTRY_BUNDLE_MAX_BYTES),
            &NO_CONTEXT,
        ),
        H::ArtifactCandidateRegistry,
        CANDIDATE_REGISTRY_REJECTIONS,
    ),
    B4NegativeHandlerContract::frozen(
        custody(
            D::ArtifactValidator,
            S::NegativeBindingIndex,
            B4NegativeByteBounds::new(1, NEGATIVE_BINDING_INDEX_BUNDLE_MAX_BYTES),
            &NO_CONTEXT,
        ),
        H::ArtifactNegativeBindingIndex,
        NEGATIVE_BINDING_REJECTIONS,
    ),
    B4NegativeHandlerContract::frozen(
        custody(
            D::TreeValidator,
            S::CorpusClosure,
            B4NegativeByteBounds::new(1, ABSTRACT_TREE_MAX_BYTES),
            &NO_CONTEXT,
        ),
        H::TreeCorpusClosure,
        CORPUS_CLOSURE_REJECTIONS,
    ),
];

fn maximum_allocation(
    subject: B4NegativeByteBounds,
    contexts: &[B4NegativeByteBounds],
) -> Result<u64> {
    let mut total = NEGATIVE_INPUT_MAX_BYTES
        .checked_add(subject.maximum())
        .ok_or_else(|| anyhow::anyhow!("negative custody maximum overflows u64"))?;
    for bounds in contexts {
        total = total
            .checked_add(bounds.maximum())
            .ok_or_else(|| anyhow::anyhow!("negative custody maximum overflows u64"))?;
    }
    Ok(total)
}

fn canonical_negative_plan() -> Result<&'static Eip0045B4NegativePlanV1> {
    if let Some(plan) = CANONICAL_NEGATIVE_PLAN.get() {
        return Ok(plan);
    }
    let plan = Eip0045B4NegativePlanV1::canonical()?;
    let _ = CANONICAL_NEGATIVE_PLAN.set(plan);
    CANONICAL_NEGATIVE_PLAN
        .get()
        .context("canonical B4 negative plan was not retained after successful construction")
}

/// Validate the sole handler table against the canonical 63/254 plan.
///
/// # Errors
///
/// Returns an error for wrong cardinality or ordering, duplicate pairs or
/// selectors, invalid custody bounds, or a pair set differing from the
/// canonical plan.
pub(crate) fn validate_negative_handler_contract_inventory() -> Result<()> {
    ensure!(
        B4_NEGATIVE_PLAN_GROUP_COUNT == 63 && B4_NEGATIVE_PLAN_VARIANT_COUNT == 254,
        "B4 negative plan totals differ from the handler-contract lineage"
    );
    ensure!(
        B4_NEGATIVE_HANDLER_CONTRACTS.len() == B4_NEGATIVE_HANDLER_CONTRACT_COUNT,
        "B4 negative handler-contract table has the wrong row count"
    );

    let plan = canonical_negative_plan()?;
    let planned_pairs: BTreeSet<_> = plan
        .groups
        .iter()
        .flat_map(|group| &group.executions)
        .map(|execution| {
            (
                execution.materialization_domain,
                execution.execution_surface,
            )
        })
        .collect();
    ensure!(
        planned_pairs.len() == B4_NEGATIVE_HANDLER_CONTRACT_COUNT,
        "canonical B4 plan has the wrong negative-handler pair count"
    );

    let mut observed_pairs = BTreeSet::new();
    let mut observed_selectors = BTreeSet::new();
    let mut previous_pair = None;
    for row in B4_NEGATIVE_HANDLER_CONTRACTS {
        row.custody().validate()?;
        ensure!(
            !row.rejection_boundaries().is_empty(),
            "B4 negative handler has an empty rejection vocabulary"
        );
        let mut row_boundaries = BTreeSet::new();
        for boundary in row.rejection_boundaries() {
            ensure!(
                valid_rejection_id(boundary.class()) && valid_rejection_id(boundary.stage()),
                "B4 negative handler contains an invalid rejection identifier"
            );
            ensure!(
                row_boundaries.insert((boundary.class(), boundary.stage())),
                "B4 negative handler contains a duplicate rejection boundary"
            );
        }
        let pair = (
            row.custody().materialization_domain(),
            row.custody().validation_surface(),
        );
        if let Some(previous) = previous_pair {
            ensure!(
                previous < pair,
                "B4 negative handler-contract rows are not in strict pair order"
            );
        }
        previous_pair = Some(pair);
        ensure!(
            observed_pairs.insert(pair),
            "B4 negative handler-contract table contains a duplicate pair"
        );
        ensure!(
            observed_selectors.insert(row.selector()),
            "B4 negative handler-contract table contains a duplicate selector"
        );
    }
    ensure!(
        observed_pairs == planned_pairs,
        "B4 negative handler-contract pairs differ from the canonical plan"
    );
    Ok(())
}

fn valid_rejection_id(value: &str) -> bool {
    const FORBIDDEN: &[&str] = &[
        "error",
        "failure",
        "fixme",
        "generic",
        "pending",
        "placeholder",
        "reject",
        "tbd",
        "todo",
        "unclassified",
        "unknown",
        "unspecified",
    ];
    !value.is_empty()
        && value.len() <= 192
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (byte == b'-'
                    && index != 0
                    && index + 1 != value.len()
                    && value.as_bytes()[index - 1] != b'-')
        })
        && value
            .split('-')
            .all(|component| !FORBIDDEN.contains(&component))
}

/// Return one planned row after validating the complete table.
///
/// # Errors
///
/// Returns an error if the sole handler table is internally inconsistent.
pub(crate) fn planned_negative_handler_contract(
    domain: B4MaterializationDomain,
    surface: B4NegativeExecutionSurface,
) -> Result<Option<B4NegativeHandlerContract>> {
    validate_negative_handler_contract_inventory()?;
    Ok(B4_NEGATIVE_HANDLER_CONTRACTS.iter().copied().find(|row| {
        row.custody().materialization_domain() == domain
            && row.custody().validation_surface() == surface
    }))
}

/// Project one canonical plan execution to its sole expected first rejection.
///
/// Handler rows own finite vocabularies, not execution-level choice. This
/// projection is the only authority allowed to choose one boundary inside that
/// vocabulary. It first requires byte-for-byte equality with the compiled
/// canonical execution and then maps the typed QA code, surface, and, where
/// needed, exact variant to one admitted boundary.
///
/// # Errors
///
/// Returns an error for an unknown or rewritten execution, an impossible
/// QA/surface/variant combination, or a projection outside the selected
/// handler's finite rejection vocabulary.
pub(crate) fn exact_negative_rejection_boundary(
    execution: &B4NegativePlanExecutionV1,
) -> Result<B4NegativeRejectionBoundary> {
    let plan = canonical_negative_plan()?;
    let mut canonical_matches = plan
        .groups
        .iter()
        .flat_map(|group| &group.executions)
        .filter(|candidate| candidate.execution_id == execution.execution_id);
    let canonical = canonical_matches
        .next()
        .with_context(|| format!("unknown B4 negative execution {}", execution.execution_id))?;
    ensure!(
        canonical_matches.next().is_none(),
        "canonical B4 negative plan contains a duplicate execution ID"
    );
    ensure!(
        canonical == execution,
        "B4 negative execution differs from its compiled canonical row"
    );

    let (class, stage) = exact_negative_rejection_pair(execution)?;
    let contract = planned_negative_handler_contract(
        execution.materialization_domain,
        execution.execution_surface,
    )?
    .context("canonical B4 negative execution has no handler contract")?;
    contract
        .rejection_boundaries()
        .iter()
        .copied()
        .find(|boundary| boundary.class() == class && boundary.stage() == stage)
        .context("exact B4 negative rejection is outside its handler vocabulary")
}

#[allow(
    clippy::too_many_lines,
    reason = "the exhaustive QA-to-boundary projection is intentionally centralized"
)]
fn exact_negative_rejection_pair(
    execution: &B4NegativePlanExecutionV1,
) -> Result<(&'static str, &'static str)> {
    use B4NegativeExecutionSurface as S;
    use B4NegativeQaResultCode as Q;

    let pair = match execution.qa_result_code {
        Q::RawSealClaimMismatch => require_surface_pair(
            execution,
            &[S::RawStatementClaimBinding, S::ReceiptClaimPolicy],
            "receipt-claim-mismatch",
            "expected-claim-binding",
        )?,
        Q::OpcodeProfileIdLengthInvalid => require_surface_pair(
            execution,
            &[S::OpcodePreflight],
            "opcode-input-shape-invalid",
            "opcode-profile-id-byte-length",
        )?,
        Q::OpcodeProgramIdLengthInvalid => require_surface_pair(
            execution,
            &[S::OpcodePreflight],
            "opcode-input-shape-invalid",
            "opcode-program-id-byte-length",
        )?,
        Q::OpcodeApplicationPayloadTooLarge => require_surface_pair(
            execution,
            &[S::OpcodePreflight],
            "opcode-input-shape-invalid",
            "opcode-application-payload-byte-length",
        )?,
        Q::OpcodeProofChunkCountInvalid => require_surface_pair(
            execution,
            &[S::OpcodePreflight],
            "opcode-input-shape-invalid",
            "opcode-proof-chunk-count",
        )?,
        Q::OpcodeProofChunkLengthInvalid => require_surface_pair(
            execution,
            &[S::OpcodePreflight],
            "opcode-input-shape-invalid",
            "opcode-proof-chunk-byte-length",
        )?,
        Q::RawSealWordNotReduced | Q::B4ByteOrderRejectedAtBoundCheckpoint => require_surface_pair(
            execution,
            &[S::RawSealShape],
            "raw-seal-shape-invalid",
            "babybear-word-reduction",
        )?,
        Q::RawSealNonzeroRootPadding => require_surface_pair(
            execution,
            &[S::RawSealShape],
            "raw-seal-shape-invalid",
            "inner-root-padding",
        )?,
        Q::RawSealClaimHalfwordOutOfRange => require_surface_pair(
            execution,
            &[S::RawSealShape],
            "raw-seal-shape-invalid",
            "claim-halfword-decoding",
        )?,
        Q::RawSealWrongOuterPo2 => require_surface_pair(
            execution,
            &[S::RawSealShape],
            "raw-seal-shape-invalid",
            "outer-po2-preflight",
        )?,
        Q::B4ParserUnexpectedEofAtPhase => {
            ensure!(
                execution.execution_surface == S::Risc0ParserInternal,
                "parser QA code is bound to the wrong execution surface"
            );
            let stage = B4ParserRejectionStage::from_plan_variant(&execution.variant_id)
                .context("parser execution has no exact typed rejection stage")?;
            ("risc0-parser-invalid", stage.as_str())
        }
        Q::RawSealInnerControlRootMismatch => require_surface_pair(
            execution,
            &[S::RawSealShape],
            "inner-control-root-mismatch",
            "inner-control-root-binding",
        )?,
        Q::B4TerminalMetadataMismatch => require_surface_pair(
            execution,
            &[S::TerminalMetadata],
            "terminal-metadata-mismatch",
            "terminal-metadata-binding",
        )?,
        Q::RawSealControlIdNotAllowed => require_surface_pair(
            execution,
            &[S::TerminalPolicy],
            "terminal-policy-mismatch",
            "terminal-control-id",
        )?,
        Q::B4AncestryClaimEdgeMismatch => require_surface_pair(
            execution,
            &[S::AncestryReplay],
            "ancestry-replay-mismatch",
            "claim-edge",
        )?,
        Q::B4ResolveExplicitSemanticsMismatch => require_surface_pair(
            execution,
            &[S::AncestryReplay],
            "ancestry-replay-mismatch",
            "resolve-explicit-semantics",
        )?,
        Q::B4ResolveZeroRootSemanticsMismatch => require_surface_pair(
            execution,
            &[S::AncestryReplay],
            "ancestry-replay-mismatch",
            "resolve-zero-root-semantics",
        )?,
        Q::B4ResolveAssumptionInventoryInvalid => require_surface_pair(
            execution,
            &[S::AncestryReplay],
            "ancestry-replay-mismatch",
            "resolve-assumption-inventory",
        )?,
        Q::B4CryptoEarlyCheckpointRejected => require_surface_pair(
            execution,
            &[S::Risc0CryptographicVerifier],
            "risc0-proof-invalid",
            "risc0-validity-check",
        )?,
        Q::B4CryptoMiddleCheckpointRejected => require_surface_pair(
            execution,
            &[S::Risc0CryptographicVerifier],
            "risc0-proof-invalid",
            "risc0-fri-round-two-query-zero",
        )?,
        Q::B4CryptoLateCheckpointRejected => require_surface_pair(
            execution,
            &[S::Risc0CryptographicVerifier],
            "risc0-proof-invalid",
            "risc0-fri-final-polynomial-query-zero",
        )?,
        Q::B4CryptoFinalCheckpointRejected => require_surface_pair(
            execution,
            &[S::Risc0CryptographicVerifier],
            "risc0-proof-invalid",
            "risc0-fri-inner-query-forty-nine",
        )?,
        Q::B4ProfileManifestLengthInvalid => require_surface_pair(
            execution,
            &[S::ProfileManifestCodec],
            "profile-manifest-invalid",
            "profile-manifest-byte-length",
        )?,
        Q::B4ProfileManifestVersionUnsupported => require_surface_pair(
            execution,
            &[S::ProfileManifestCodec],
            "profile-manifest-invalid",
            "profile-manifest-format-version",
        )?,
        Q::B4ProfileExactProofBytesInvalid => require_surface_pair(
            execution,
            &[S::InitialProfileTarget],
            "initial-profile-target-mismatch",
            "exact-proof-bytes",
        )?,
        Q::B4ProfileMaximumPayloadInvalid => require_surface_pair(
            execution,
            &[S::InitialProfileTarget],
            "initial-profile-target-mismatch",
            "maximum-application-payload-bytes",
        )?,
        Q::B4ProfileOuterPo2Invalid => require_surface_pair(
            execution,
            &[S::InitialProfileTarget],
            "initial-profile-target-mismatch",
            "outer-po2",
        )?,
        Q::B4ProfileIdentityMismatch => require_surface_pair(
            execution,
            &[S::InitialProfileTarget],
            "initial-profile-target-mismatch",
            "inner-control-root",
        )?,
        Q::B4ProfileTerminalFieldInvalid => exact_profile_terminal_pair(execution)?,
        Q::B4ProfileTerminalControlIdDuplicate => require_surface_pair(
            execution,
            &[S::ProfileManifestCodec],
            "profile-manifest-invalid",
            "profile-manifest-terminal-control-id-uniqueness",
        )?,
        Q::B4ProfileTerminalOrderInvalid => require_surface_pair(
            execution,
            &[S::ProfileManifestCodec],
            "profile-manifest-invalid",
            "profile-manifest-terminal-order",
        )?,
        Q::B4ProfileArtifactReferenceInvalid => exact_profile_artifact_reference_pair(execution)?,
        Q::B4ProfileArtifactKindPositionInvalid => require_surface_pair(
            execution,
            &[S::ProfileManifestCodec],
            "profile-manifest-invalid",
            "profile-manifest-artifact-kind",
        )?,
        Q::B4ProfileArtifactDigestMismatch => require_surface_pair(
            execution,
            &[S::ProfileArtifactEnvelope],
            "profile-artifact-package-mismatch",
            "profile-artifact-digest",
        )?,
        Q::B4ProfileIdMismatch => require_surface_pair(
            execution,
            &[S::ActivatedProfilePackage],
            "activated-profile-package-mismatch",
            "activated-profile-id",
        )?,
        Q::B4ProfileIdPreimageMismatch => require_surface_pair(
            execution,
            &[S::ProfileIdPreimage],
            "profile-id-preimage-mismatch",
            "profile-id-preimage-binding",
        )?,
        Q::B4TerminalFixtureCatalogBindingMismatch => require_surface_pair(
            execution,
            &[S::TerminalFixtureCatalog],
            "terminal-fixture-catalog-mismatch",
            "terminal-fixture-catalog-binding",
        )?,
        Q::B4SequenceSubjectProvenanceMismatch => require_surface_pair(
            execution,
            &[S::SequenceSubjectCatalog],
            "sequence-subject-catalog-invalid",
            "sequence-subject-catalog-validation",
        )?,
        Q::B4CorpusRepresentativeStratumMissing => require_surface_pair(
            execution,
            &[S::CorpusClosure],
            "corpus-closure-mismatch",
            "corpus-required-role",
        )?,
        Q::B4CorpusExtraFile => require_surface_pair(
            execution,
            &[S::CorpusClosure],
            "corpus-closure-mismatch",
            "corpus-unexpected-role",
        )?,
        Q::B4RegistryMandatoryPositiveMissing
        | Q::B4RegistryPositiveOrderInvalid
        | Q::B4RegistryPositiveLabelInvalid
        | Q::B4RegistryNegativeClassUnknown
        | Q::B4RegistryUnknownField
        | Q::B4RegistryNoncanonicalJcs => require_surface_pair(
            execution,
            &[S::CandidateRegistry],
            "candidate-registry-invalid",
            "candidate-registry-validation",
        )?,
        Q::B4RegistryCaseIdDuplicate => match execution.execution_surface {
            S::CandidateRegistry => (
                "candidate-registry-invalid",
                "candidate-registry-validation",
            ),
            S::NegativeBindingIndex => (
                "negative-binding-index-invalid",
                "negative-binding-index-codec",
            ),
            _ => bail!("case-ID duplicate QA code is bound to the wrong execution surface"),
        },
        Q::B4NegativePlanRegistryBijectionMismatch => require_surface_pair(
            execution,
            &[S::NegativeBindingIndex],
            "negative-binding-index-invalid",
            "negative-binding-index-plan-binding",
        )?,
    };
    Ok(pair)
}

fn require_surface_pair(
    execution: &B4NegativePlanExecutionV1,
    allowed: &[B4NegativeExecutionSurface],
    class: &'static str,
    stage: &'static str,
) -> Result<(&'static str, &'static str)> {
    ensure!(
        allowed.contains(&execution.execution_surface),
        "B4 negative QA code is bound to the wrong execution surface"
    );
    Ok((class, stage))
}

fn exact_profile_terminal_pair(
    execution: &B4NegativePlanExecutionV1,
) -> Result<(&'static str, &'static str)> {
    use B4NegativeExecutionSurface as S;

    match execution.execution_surface {
        S::ProfileManifestCodec if execution.variant_id.ends_with("-kind") => {
            Ok(("profile-manifest-invalid", "profile-manifest-terminal-kind"))
        }
        S::ProfileManifestCodec
            if matches!(
                execution.variant_id.as_str(),
                "terminal-join-parameter" | "terminal-resolve-parameter"
            ) =>
        {
            Ok((
                "profile-manifest-invalid",
                "profile-manifest-terminal-parameter",
            ))
        }
        S::ProfileManifestCodec if execution.variant_id.ends_with("-parameter") => Ok((
            "profile-manifest-invalid",
            "profile-manifest-terminal-order",
        )),
        S::InitialProfileTarget if execution.variant_id.ends_with("-control-id") => {
            Ok(("initial-profile-target-mismatch", "terminal-control-id"))
        }
        _ => bail!("profile-terminal execution has no exact rejection projection"),
    }
}

fn exact_profile_artifact_reference_pair(
    execution: &B4NegativePlanExecutionV1,
) -> Result<(&'static str, &'static str)> {
    use B4NegativeExecutionSurface as S;

    match execution.execution_surface {
        S::ProfileManifestCodec
            if matches!(
                execution.variant_id.as_str(),
                "algorithm-kind" | "binary-data-kind"
            ) =>
        {
            Ok(("profile-manifest-invalid", "profile-manifest-artifact-kind"))
        }
        S::ProfileArtifactEnvelope if execution.variant_id.ends_with("-length") => Ok((
            "profile-artifact-package-mismatch",
            "profile-artifact-byte-length",
        )),
        S::ProfileArtifactEnvelope if execution.variant_id.ends_with("-digest") => Ok((
            "profile-artifact-package-mismatch",
            "profile-artifact-digest",
        )),
        _ => bail!("profile-artifact reference execution has no exact rejection projection"),
    }
}

/// Validate one exact rejection pair against its selected domain/surface row.
///
/// # Errors
///
/// Returns an error if the pair is outside the canonical twenty-row plan or is
/// not a member of the selected handler's finite rejection vocabulary.
pub(crate) fn validate_negative_rejection_boundary(
    domain: B4MaterializationDomain,
    surface: B4NegativeExecutionSurface,
    class: &str,
    stage: &str,
) -> Result<()> {
    let contract = planned_negative_handler_contract(domain, surface)?
        .ok_or_else(|| anyhow::anyhow!("negative rejection uses an unplanned handler pair"))?;
    ensure!(
        contract.admits_rejection(class, stage),
        "negative rejection boundary is not admitted by the selected handler"
    );
    Ok(())
}

/// Return one production-frozen custody row after validating the complete table.
///
/// # Errors
///
/// Returns an error if the sole handler table is internally inconsistent.
#[cfg(feature = "validator")]
#[cfg_attr(
    not(all(target_os = "linux", target_arch = "x86_64")),
    allow(
        dead_code,
        reason = "the production custody consumer exists only on Linux/x86_64"
    )
)]
pub(crate) fn frozen_negative_custody_contract(
    domain: B4MaterializationDomain,
    surface: B4NegativeExecutionSurface,
) -> Result<Option<B4NegativeCustodyContract>> {
    Ok(planned_negative_handler_contract(domain, surface)?
        .filter(|row| row.is_frozen())
        .map(B4NegativeHandlerContract::custody))
}

/// Require a complete and fully frozen twenty-row handler authority.
///
/// # Errors
///
/// Returns an error for an invalid table or while any production adapter row
/// remains pending.
pub(crate) fn require_negative_handler_contracts_frozen() -> Result<()> {
    validate_negative_handler_contract_inventory()?;
    ensure!(
        B4_NEGATIVE_HANDLER_CONTRACTS
            .iter()
            .all(|contract| contract.is_frozen()),
        "B4 negative handler-contract table is not fully frozen; campaign precommit is forbidden"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    const NEGATIVE_REJECTION_PROJECTION_GOLDEN_V1: &str =
        include_str!("../tests/fixtures/b4-negative-rejection-projection-v1.tsv");
    /// SHA-256 of the exact UTF-8, LF-terminated golden-oracle bytes.
    const NEGATIVE_REJECTION_PROJECTION_GOLDEN_V1_SHA256: &str =
        "e0e7aee8ea29155287e08b10cc0b8ad2c6e09c56689e131763e1fd1418f0a5e9";

    fn validate_negative_rejection_projection_golden(
        golden: &str,
        enforce_frozen_digest: bool,
    ) -> Result<()> {
        if enforce_frozen_digest {
            let actual_digest = hex::encode(Sha256::digest(golden.as_bytes()));
            ensure!(
                actual_digest == NEGATIVE_REJECTION_PROJECTION_GOLDEN_V1_SHA256,
                "golden rejection projection digest differs from its frozen SHA-256"
            );
        }

        ensure!(
            golden.ends_with('\n'),
            "golden rejection projection is not LF-terminated"
        );
        ensure!(
            !golden.as_bytes().contains(&b'\r'),
            "golden rejection projection is not canonical LF text"
        );

        let mut rows = Vec::new();
        for (line_index, line) in golden.lines().enumerate() {
            if line.starts_with('#') {
                continue;
            }
            ensure!(
                !line.is_empty(),
                "golden rejection projection contains an empty data line"
            );
            let mut fields = line.split('\t');
            let execution_id = fields.next().context("golden row has no execution ID")?;
            let class = fields.next().context("golden row has no rejection class")?;
            let stage = fields.next().context("golden row has no rejection stage")?;
            ensure!(
                fields.next().is_none(),
                "golden rejection row {} has extra columns",
                line_index + 1
            );
            ensure!(
                !execution_id.is_empty() && !class.is_empty() && !stage.is_empty(),
                "golden rejection row {} contains an empty field",
                line_index + 1
            );
            rows.push((execution_id, class, stage));
        }
        ensure!(
            rows.len() == usize::from(B4_NEGATIVE_PLAN_VARIANT_COUNT),
            "golden rejection projection must contain exactly 254 rows"
        );
        let unique_ids = rows
            .iter()
            .map(|(execution_id, _, _)| *execution_id)
            .collect::<BTreeSet<_>>();
        ensure!(
            unique_ids.len() == rows.len(),
            "golden rejection projection contains duplicate execution IDs"
        );

        let plan = Eip0045B4NegativePlanV1::canonical()?;
        let executions = plan
            .groups
            .iter()
            .flat_map(|group| &group.executions)
            .collect::<Vec<_>>();
        ensure!(
            executions.len() == rows.len(),
            "canonical plan and golden rejection projection cardinalities differ"
        );
        for (row_index, (execution, (execution_id, class, stage))) in
            executions.iter().zip(rows).enumerate()
        {
            ensure!(
                execution.execution_id == execution_id,
                "golden rejection row {row_index} execution ID/order differs from the canonical plan"
            );
            let boundary = exact_negative_rejection_boundary(execution)?;
            ensure!(
                boundary.class() == class && boundary.stage() == stage,
                "golden rejection row {row_index} class/stage differs for {execution_id}"
            );
        }
        Ok(())
    }

    #[test]
    fn exact_rejection_projection_matches_independent_golden_oracle() {
        validate_negative_rejection_projection_golden(
            NEGATIVE_REJECTION_PROJECTION_GOLDEN_V1,
            true,
        )
        .unwrap();
    }

    #[test]
    fn golden_rejection_projection_fails_closed_on_id_order_or_pair_drift() {
        let id_drift = NEGATIVE_REJECTION_PROJECTION_GOLDEN_V1.replacen(
            "statement-field-byte-sweep--chain-domain-byte-order-reversed\t",
            "statement-field-byte-sweep--chain-domain-byte-order-mutated\t",
            1,
        );

        let mut ordered_lines = NEGATIVE_REJECTION_PROJECTION_GOLDEN_V1
            .split_inclusive('\n')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        ordered_lines.swap(3, 4);
        let order_drift = ordered_lines.concat();

        let pair_drift = NEGATIVE_REJECTION_PROJECTION_GOLDEN_V1.replacen(
            "\treceipt-claim-mismatch\texpected-claim-binding\n",
            "\traw-seal-shape-invalid\tbabybear-word-reduction\n",
            1,
        );

        for (label, mutated, expected_error) in [
            ("execution ID", id_drift, "execution ID/order differs"),
            ("row order", order_drift, "execution ID/order differs"),
            ("class/stage pair", pair_drift, "class/stage differs"),
        ] {
            let error = validate_negative_rejection_projection_golden(&mutated, false)
                .expect_err(label)
                .to_string();
            assert!(
                error.contains(expected_error),
                "{label} drift failed for the wrong reason: {error}"
            );
            assert!(
                validate_negative_rejection_projection_golden(&mutated, true).is_err(),
                "{label} drift retained the frozen SHA-256"
            );
        }
    }

    #[test]
    fn sole_table_is_complete_unique_ordered_and_plan_exact() {
        validate_negative_handler_contract_inventory().unwrap();
        assert_eq!(
            B4_NEGATIVE_HANDLER_CONTRACTS.len(),
            B4_NEGATIVE_HANDLER_CONTRACT_COUNT
        );
        assert_eq!(B4_NEGATIVE_PLAN_GROUP_COUNT, 63);
        assert_eq!(B4_NEGATIVE_PLAN_VARIANT_COUNT, 254);
        assert_eq!(
            B4_NEGATIVE_HANDLER_CONTRACTS
                .iter()
                .map(|row| row.rejection_boundaries().len())
                .sum::<usize>(),
            82
        );
    }

    #[test]
    fn exact_rejection_projection_is_total_unique_and_handler_admitted() {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let mut execution_ids = BTreeSet::new();
        let mut projection = BTreeSet::new();
        for execution in plan.groups.iter().flat_map(|group| &group.executions) {
            let boundary = exact_negative_rejection_boundary(execution).unwrap();
            assert!(execution_ids.insert(execution.execution_id.as_str()));
            assert!(projection.insert((
                execution.execution_id.as_str(),
                boundary.class(),
                boundary.stage(),
            )));
            let handler = planned_negative_handler_contract(
                execution.materialization_domain,
                execution.execution_surface,
            )
            .unwrap()
            .unwrap();
            assert!(
                handler.admits_rejection(boundary.class(), boundary.stage()),
                "{} projected outside its handler vocabulary",
                execution.execution_id
            );
        }
        assert_eq!(
            execution_ids.len(),
            usize::from(B4_NEGATIVE_PLAN_VARIANT_COUNT)
        );
        assert_eq!(
            projection.len(),
            usize::from(B4_NEGATIVE_PLAN_VARIANT_COUNT)
        );
    }

    #[test]
    fn rejection_vocabulary_is_handler_specific_and_fail_closed() {
        validate_negative_rejection_boundary(
            D::VerifierInput,
            S::RawSealShape,
            "raw-seal-shape-invalid",
            "babybear-word-reduction",
        )
        .unwrap();
        validate_negative_rejection_boundary(
            D::VerifierInput,
            S::RawSealShape,
            "inner-control-root-mismatch",
            "inner-control-root-binding",
        )
        .unwrap();

        for (class, stage) in [
            ("profile-manifest-invalid", "profile-manifest-byte-length"),
            ("raw-seal-shape-invalid", "raw-seal-byte-length"),
            ("raw-seal-shape-invalid", "canonical-word-decoding"),
            ("terminal-policy-mismatch", "terminal-outer-po2"),
            ("risc0-proof-invalid", "risc0-proof-verification"),
            ("raw-seal-shape-invalid", "inner-control-root-binding"),
            ("unknown-boundary", "unknown-stage"),
        ] {
            assert!(
                validate_negative_rejection_boundary(
                    D::VerifierInput,
                    S::RawSealShape,
                    class,
                    stage,
                )
                .is_err(),
                "raw-seal handler admitted {class}/{stage}"
            );
        }
    }

    #[test]
    fn target_context_cardinalities_are_derived_from_the_sole_table() {
        let expected = [
            (D::VerifierInput, S::OpcodePreflight, 1),
            (D::VerifierInput, S::RawStatementClaimBinding, 2),
            (D::VerifierInput, S::RawSealShape, 1),
            (D::VerifierInput, S::Risc0ParserInternal, 1),
            (D::VerifierInput, S::Risc0CryptographicVerifier, 2),
            (D::VerifierInput, S::TerminalPolicy, 1),
            (D::VerifierInput, S::ReceiptClaimPolicy, 2),
            (D::VerifierInput, S::AncestryReplay, 1),
            (D::ArtifactValidator, S::TerminalPolicy, 1),
            (D::ArtifactValidator, S::ProfileManifestCodec, 0),
            (D::ArtifactValidator, S::InitialProfileTarget, 0),
            (D::ArtifactValidator, S::ProfileArtifactEnvelope, 0),
            (D::ArtifactValidator, S::ActivatedProfilePackage, 3),
            (D::ArtifactValidator, S::TerminalFixtureCatalog, 0),
            (D::ArtifactValidator, S::SequenceSubjectCatalog, 0),
            (D::ArtifactValidator, S::TerminalMetadata, 7),
            (D::ArtifactValidator, S::ProfileIdPreimage, 0),
            (D::ArtifactValidator, S::CandidateRegistry, 0),
            (D::ArtifactValidator, S::NegativeBindingIndex, 0),
            (D::TreeValidator, S::CorpusClosure, 0),
        ];
        assert_eq!(expected.len(), B4_NEGATIVE_HANDLER_CONTRACT_COUNT);
        for (domain, surface, cardinality) in expected {
            let row = planned_negative_handler_contract(domain, surface)
                .unwrap()
                .unwrap();
            assert_eq!(row.custody().contexts().len(), cardinality);
        }
    }

    #[test]
    fn parser_freeze_covers_exactly_rows_72_through_107() {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let parser_rows = plan
            .groups
            .iter()
            .flat_map(|group| &group.executions)
            .enumerate()
            .filter(|(_, execution)| {
                execution.materialization_domain == D::VerifierInput
                    && execution.execution_surface == S::Risc0ParserInternal
            })
            .collect::<Vec<_>>();
        assert_eq!(
            parser_rows
                .iter()
                .map(|(index, _)| *index)
                .collect::<Vec<_>>(),
            (72..=107).collect::<Vec<_>>()
        );
        assert_eq!(parser_rows.len(), PARSER_REJECTIONS.len());

        let row = planned_negative_handler_contract(D::VerifierInput, S::Risc0ParserInternal)
            .unwrap()
            .unwrap();
        assert!(row.is_frozen());
        assert_eq!(row.selector(), H::VerifierRisc0ParserInternal);
        for (_, execution) in parser_rows {
            let boundary = exact_negative_rejection_boundary(execution).unwrap();
            assert_eq!(boundary.class(), "risc0-parser-invalid");
            assert!(row.admits_rejection(boundary.class(), boundary.stage()));
        }
        assert!(require_negative_handler_contracts_frozen().is_err());
    }

    #[test]
    fn only_rows_with_closed_adapters_and_focused_fixtures_are_frozen() {
        assert!(require_negative_handler_contracts_frozen().is_err());
        let frozen_selectors = [
            H::VerifierOpcodePreflight,
            H::VerifierRawStatementClaimBinding,
            H::VerifierRawSealShape,
            H::VerifierRisc0ParserInternal,
            H::VerifierRisc0CryptographicVerifier,
            H::VerifierTerminalPolicy,
            H::VerifierReceiptClaimPolicy,
            H::ArtifactTerminalPolicy,
            H::ArtifactProfileManifestCodec,
            H::ArtifactInitialProfileTarget,
            H::ArtifactProfileArtifactEnvelope,
            H::ArtifactActivatedProfilePackage,
            H::ArtifactTerminalFixtureCatalog,
            H::ArtifactSequenceSubjectCatalog,
            H::ArtifactTerminalMetadata,
            H::ArtifactProfileIdPreimage,
            H::ArtifactCandidateRegistry,
            H::ArtifactNegativeBindingIndex,
            H::TreeCorpusClosure,
        ];
        for row in B4_NEGATIVE_HANDLER_CONTRACTS {
            let expected_frozen = frozen_selectors.contains(&row.selector());
            assert_eq!(row.is_frozen(), expected_frozen);
            #[cfg(feature = "validator")]
            {
                let custody = row.custody();
                assert_eq!(
                    frozen_negative_custody_contract(
                        custody.materialization_domain(),
                        custody.validation_surface()
                    )
                    .unwrap()
                    .is_some(),
                    expected_frozen
                );
            }
        }
    }

    #[test]
    fn statement_claim_freeze_is_individual_and_campaign_gate_stays_closed() {
        let statement = planned_negative_handler_contract(
            D::VerifierInput,
            S::RawStatementClaimBinding,
        )
        .unwrap()
        .unwrap();
        assert!(statement.is_frozen());
        assert_eq!(statement.selector(), H::VerifierRawStatementClaimBinding);
        assert_eq!(statement.custody().subject(), B4NegativeByteBounds::new(159, 16_543));
        assert_eq!(statement.custody().contexts(), &MANIFEST_AND_SEAL_CONTEXT);

        // This literal list is a scope guard: freezing any unrelated row must
        // fail even if a caller updates the total frozen count elsewhere.
        let pending = B4_NEGATIVE_HANDLER_CONTRACTS.iter()
            .filter(|row| !row.is_frozen())
            .map(|row| row.selector())
            .collect::<Vec<_>>();
        assert_eq!(pending, [
            H::VerifierAncestryReplay,
        ]);
        assert_eq!(B4_NEGATIVE_HANDLER_CONTRACTS.iter().filter(|row| row.is_frozen()).count(), 19);
        #[cfg(feature = "validator")]
        for row in B4_NEGATIVE_HANDLER_CONTRACTS.iter().filter(|row| !row.is_frozen()) {
            let custody = row.custody();
            assert!(frozen_negative_custody_contract(
                custody.materialization_domain(), custody.validation_surface(),
            ).unwrap().is_none());
        }
        assert_eq!(require_negative_handler_contracts_frozen().unwrap_err().to_string(),
            "B4 negative handler-contract table is not fully frozen; campaign precommit is forbidden");
    }

    #[test]
    fn raw_shape_freeze_covers_exactly_42_rows_and_keeps_one_pending() {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let rows = plan.groups.iter().flat_map(|group| &group.executions).enumerate()
            .filter(|(_, execution)| execution.materialization_domain == D::VerifierInput
                && execution.execution_surface == S::RawSealShape).collect::<Vec<_>>();
        assert_eq!(rows.iter().map(|(index, _)| *index).collect::<Vec<_>>(), [
            29, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
            47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61,
            62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 108, 109,
        ]);
        let contract = planned_negative_handler_contract(D::VerifierInput, S::RawSealShape)
            .unwrap().unwrap();
        assert!(contract.is_frozen());
        assert_eq!(contract.selector(), H::VerifierRawSealShape);
        assert_eq!(contract.custody().subject(), B4NegativeByteBounds::new(1, 262_144));
        assert_eq!(contract.custody().contexts(), &[B4NegativeByteBounds::new(458, 458)]);
        for (index, execution) in rows {
            let boundary = exact_negative_rejection_boundary(execution).unwrap();
            let expected = match index {
                29 | 57..=70 => ("raw-seal-shape-invalid", "babybear-word-reduction"),
                33..=40 => ("raw-seal-shape-invalid", "inner-root-padding"),
                41..=56 => ("raw-seal-shape-invalid", "claim-halfword-decoding"),
                71 | 109 => ("raw-seal-shape-invalid", "outer-po2-preflight"),
                108 => ("inner-control-root-mismatch", "inner-control-root-binding"),
                _ => unreachable!(),
            };
            assert_eq!((boundary.class(), boundary.stage()), expected);
            assert!(contract.admits_rejection(expected.0, expected.1));
        }
        // Literal scope guard, independent of any updated frozen-row count.
        assert_eq!(B4_NEGATIVE_HANDLER_CONTRACTS.iter().filter(|row| !row.is_frozen())
            .map(|row| row.selector()).collect::<Vec<_>>(), [
                H::VerifierAncestryReplay,
            ]);
        assert_eq!(require_negative_handler_contracts_frozen().unwrap_err().to_string(),
            "B4 negative handler-contract table is not fully frozen; campaign precommit is forbidden");
    }

    #[test]
    fn crypto_freeze_covers_exactly_four_rows_and_keeps_one_pending() {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let rows = plan.groups.iter().flat_map(|group| &group.executions).enumerate()
            .filter(|(_, row)| row.materialization_domain == D::VerifierInput
                && row.execution_surface == S::Risc0CryptographicVerifier).collect::<Vec<_>>();
        assert_eq!(rows.iter().map(|(index, _)| *index).collect::<Vec<_>>(), [156, 157, 158, 159]);
        let contract = planned_negative_handler_contract(D::VerifierInput, S::Risc0CryptographicVerifier)
            .unwrap().unwrap();
        assert!(contract.is_frozen());
        assert_eq!(contract.selector(), H::VerifierRisc0CryptographicVerifier);
        assert_eq!(contract.custody().subject(), B4NegativeByteBounds::new(222_668, 222_668));
        assert_eq!(contract.custody().contexts(), &MANIFEST_AND_RECEIPT_ORACLE_CONTEXT);
        for ((_, row), stage) in rows.into_iter().zip([
            "risc0-validity-check", "risc0-fri-round-two-query-zero",
            "risc0-fri-final-polynomial-query-zero", "risc0-fri-inner-query-forty-nine",
        ]) {
            let boundary = exact_negative_rejection_boundary(row).unwrap();
            assert_eq!((boundary.class(), boundary.stage()), ("risc0-proof-invalid", stage));
            assert!(contract.admits_rejection(boundary.class(), boundary.stage()));
        }
        assert_eq!(B4_NEGATIVE_HANDLER_CONTRACTS.iter().filter(|row| !row.is_frozen())
            .map(|row| row.selector()).collect::<Vec<_>>(), [
                H::VerifierAncestryReplay,
            ]);
        assert_eq!(B4_NEGATIVE_HANDLER_CONTRACTS.iter().filter(|row| row.is_frozen()).count(), 19);
        assert_eq!(require_negative_handler_contracts_frozen().unwrap_err().to_string(),
            "B4 negative handler-contract table is not fully frozen; campaign precommit is forbidden");
    }

    #[test]
    fn terminal_catalog_freeze_covers_exactly_three_rows_and_keeps_campaign_closed() {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let rows = plan.groups.iter().flat_map(|group| &group.executions).enumerate()
            .filter(|(_, row)| row.materialization_domain == D::ArtifactValidator
                && row.execution_surface == S::TerminalFixtureCatalog).collect::<Vec<_>>();
        assert_eq!(rows.iter().map(|(index, _)| *index).collect::<Vec<_>>(), [11, 12, 13]);
        let contract = planned_negative_handler_contract(D::ArtifactValidator, S::TerminalFixtureCatalog)
            .unwrap().unwrap();
        assert!(contract.is_frozen());
        assert_eq!(contract.selector(), H::ArtifactTerminalFixtureCatalog);
        assert_eq!(contract.custody().subject(), B4NegativeByteBounds::new(1, 16 * 1024 * 1024));
        assert!(contract.custody().contexts().is_empty());
        for (_, row) in rows {
            let boundary = exact_negative_rejection_boundary(row).unwrap();
            assert_eq!((boundary.class(), boundary.stage()),
                ("terminal-fixture-catalog-mismatch", "terminal-fixture-catalog-binding"));
            assert!(contract.admits_rejection(boundary.class(), boundary.stage()));
        }
        #[cfg(feature = "validator")]
        assert!(frozen_negative_custody_contract(D::ArtifactValidator, S::TerminalFixtureCatalog)
            .unwrap().is_some());
        assert_eq!(B4_NEGATIVE_HANDLER_CONTRACTS.iter().filter(|row| !row.is_frozen())
            .map(|row| row.selector()).collect::<Vec<_>>(), [
                    H::VerifierAncestryReplay,
            ]);
        assert_eq!(require_negative_handler_contracts_frozen().unwrap_err().to_string(),
            "B4 negative handler-contract table is not fully frozen; campaign precommit is forbidden");
    }

    #[test]
    fn terminal_metadata_freeze_covers_exactly_three_rows_and_keeps_campaign_closed() {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let rows = plan.groups.iter().flat_map(|group| &group.executions).enumerate()
            .filter(|(_, row)| row.materialization_domain == D::ArtifactValidator
                && row.execution_surface == S::TerminalMetadata).collect::<Vec<_>>();
        assert_eq!(rows.iter().map(|(index, _)| *index).collect::<Vec<_>>(), [110, 111, 112]);
        assert_eq!(rows.iter().map(|(_, row)| row.execution_id.as_str()).collect::<Vec<_>>(), [
            "terminal-metadata-field-sweep--kind",
            "terminal-metadata-field-sweep--parameter",
            "terminal-metadata-field-sweep--control-id",
        ]);
        let contract = planned_negative_handler_contract(D::ArtifactValidator, S::TerminalMetadata)
            .unwrap().unwrap();
        assert!(contract.is_frozen());
        assert_eq!(contract.selector(), H::ArtifactTerminalMetadata);
        assert_eq!(contract.custody().subject(), B4NegativeByteBounds::new(512, 512));
        assert_eq!(contract.custody().contexts(), &TERMINAL_METADATA_POSITIVE_CONTEXT);
        assert_eq!(contract.custody().contexts().len(), 7);
        for (_, row) in rows {
            let boundary = exact_negative_rejection_boundary(row).unwrap();
            assert_eq!((boundary.class(), boundary.stage()),
                ("terminal-metadata-mismatch", "terminal-metadata-binding"));
            assert!(contract.admits_rejection(boundary.class(), boundary.stage()));
        }
        #[cfg(feature = "validator")]
        assert!(frozen_negative_custody_contract(D::ArtifactValidator, S::TerminalMetadata)
            .unwrap().is_some());
        assert_eq!(B4_NEGATIVE_HANDLER_CONTRACTS.iter().filter(|row| !row.is_frozen())
            .map(|row| row.selector()).collect::<Vec<_>>(), [
                H::VerifierAncestryReplay,
            ]);
        assert_eq!(B4_NEGATIVE_HANDLER_CONTRACTS.iter().filter(|row| row.is_frozen()).count(), 19);
        assert_eq!(require_negative_handler_contracts_frozen().unwrap_err().to_string(),
            "B4 negative handler-contract table is not fully frozen; campaign precommit is forbidden");
    }

    #[test]
    fn terminal_policy_freeze_covers_exactly_eight_verifier_rows_and_keeps_campaign_closed() {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let rows = plan.groups.iter().flat_map(|group| &group.executions).enumerate()
            .filter(|(_, row)| row.materialization_domain == D::VerifierInput
                && row.execution_surface == S::TerminalPolicy).collect::<Vec<_>>();
        assert_eq!(rows.iter().map(|(index, _)| *index).collect::<Vec<_>>(), [131,132,133,134,135,136,137,138]);
        let contract = planned_negative_handler_contract(D::VerifierInput, S::TerminalPolicy).unwrap().unwrap();
        assert!(contract.is_frozen());
        assert_eq!(contract.selector(), H::VerifierTerminalPolicy);
        assert_eq!(contract.custody().subject(), B4NegativeByteBounds::new(222_668,222_668));
        assert_eq!(contract.custody().contexts(), &MANIFEST_CONTEXT);
        for (_, row) in rows {
            let boundary = exact_negative_rejection_boundary(row).unwrap();
            assert_eq!((boundary.class(),boundary.stage()), ("terminal-policy-mismatch","terminal-control-id"));
            assert!(contract.admits_rejection(boundary.class(),boundary.stage()));
        }
        assert_eq!(B4_NEGATIVE_HANDLER_CONTRACTS.iter().filter(|row| !row.is_frozen())
            .map(|row| row.selector()).collect::<Vec<_>>(), [H::VerifierAncestryReplay]);
        assert_eq!(require_negative_handler_contracts_frozen().unwrap_err().to_string(),
            "B4 negative handler-contract table is not fully frozen; campaign precommit is forbidden");
    }
    #[test]
    fn receipt_claim_freeze_covers_exactly_two_rows_and_keeps_campaign_closed() {
        let plan = Eip0045B4NegativePlanV1::canonical().unwrap();
        let rows = plan.groups.iter().flat_map(|group| &group.executions).enumerate()
            .filter(|(_, row)| row.materialization_domain == D::VerifierInput
                && row.execution_surface == S::ReceiptClaimPolicy).collect::<Vec<_>>();
        assert_eq!(rows.iter().map(|(index, _)| *index).collect::<Vec<_>>(), [139,140]);
        let contract = planned_negative_handler_contract(D::VerifierInput, S::ReceiptClaimPolicy).unwrap().unwrap();
        assert!(contract.is_frozen());
        assert_eq!(contract.selector(), H::VerifierReceiptClaimPolicy);
        assert_eq!(contract.custody().subject(), B4NegativeByteBounds::new(222_668,222_668));
        assert_eq!(contract.custody().contexts(), &MANIFEST_AND_STATEMENT_CONTEXT);
        for (_, row) in rows {
            let boundary = exact_negative_rejection_boundary(row).unwrap();
            assert_eq!((boundary.class(),boundary.stage()), ("receipt-claim-mismatch","expected-claim-binding"));
            assert!(contract.admits_rejection(boundary.class(),boundary.stage()));
        }
        assert_eq!(B4_NEGATIVE_HANDLER_CONTRACTS.iter().filter(|row| !row.is_frozen())
            .map(|row| row.selector()).collect::<Vec<_>>(), [H::VerifierAncestryReplay]);
        assert_eq!(B4_NEGATIVE_HANDLER_CONTRACTS.iter().filter(|row| row.is_frozen()).count(), 19);
        assert_eq!(require_negative_handler_contracts_frozen().unwrap_err().to_string(),
            "B4 negative handler-contract table is not fully frozen; campaign precommit is forbidden");
    }
}
