//! Stable failures emitted by the bounded B4 STARK core.

use core::fmt;

use risc0_zkp::verify::VerificationError;

/// Closed implementation-facing rejection classes for the STARK core.
///
/// These identifiers are deliberately more stable than upstream error text.
/// They are suitable inputs to the B4 expectation freeze, but do not by
/// themselves construct a campaign observation or result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum B4StarkErrorClass {
    /// The authenticated initial-profile manifest is not the frozen target.
    InitialProfileTarget,
    /// The raw seal violates the fixed byte/word grammar.
    RawSealShape,
    /// The verifier callback did not identify exactly one allowed terminal.
    TerminalPolicy,
    /// The upstream verifier rejected proof framing or IOP consumption.
    Risc0Parser,
    /// The upstream verifier rejected a cryptographic proof relation.
    Risc0CryptographicVerifier,
    /// The verified output does not bind the profile's inner control root.
    InnerControlRoot,
    /// The verified output does not bind the independently derived claim.
    ReceiptClaim,
}

impl B4StarkErrorClass {
    /// Stable lower-kebab identifier used by B4 rejection records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InitialProfileTarget => "initial-profile-target-mismatch",
            Self::RawSealShape => "raw-seal-shape-invalid",
            Self::TerminalPolicy => "terminal-policy-mismatch",
            Self::Risc0Parser => "risc0-parser-invalid",
            Self::Risc0CryptographicVerifier => "risc0-proof-invalid",
            Self::InnerControlRoot => "inner-control-root-mismatch",
            Self::ReceiptClaim => "receipt-claim-mismatch",
        }
    }
}

/// Closed first-failure stages for the STARK core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum B4StarkErrorStage {
    /// Initial-profile target validation.
    InitialProfileTarget,
    /// Exact raw-seal byte-length check.
    RawSealByteLength,
    /// Existing raw-seal codec/layout check.
    CanonicalWordDecoding,
    /// `BabyBear` canonical word check.
    BabyBearWordReduction,
    /// Zero padding in the inner-root output slot.
    InnerRootPadding,
    /// Montgomery decoding and range check of one claim halfword.
    ClaimHalfwordDecoding,
    /// Raw outer-recursion exponent preflight.
    OuterPo2Preflight,
    /// Exactly-one terminal-callback check.
    TerminalCallbackCardinality,
    /// Callback exponent check against the authenticated manifest.
    TerminalOuterPo2,
    /// Callback code-root check against the authenticated allowlist.
    TerminalControlId,
    /// Upstream bounded proof framing or EOF check.
    Risc0ReadIop,
    /// Upstream Merkle query range check.
    Risc0MerkleOpening,
    /// Phase-aware constraint checkpoint, used only by explicit instrumentation.
    Risc0ConstraintVerification,
    /// Upstream verification boundary not otherwise distinguished.
    Risc0ProofVerification,
    /// Post-STARK inner-root comparison.
    InnerControlRootBinding,
    /// Post-root expected-claim comparison.
    ExpectedClaimBinding,
}

impl B4StarkErrorStage {
    /// Stable lower-kebab identifier used by B4 rejection records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InitialProfileTarget => "initial-profile-target",
            Self::RawSealByteLength => "raw-seal-byte-length",
            Self::CanonicalWordDecoding => "canonical-word-decoding",
            Self::BabyBearWordReduction => "babybear-word-reduction",
            Self::InnerRootPadding => "inner-root-padding",
            Self::ClaimHalfwordDecoding => "claim-halfword-decoding",
            Self::OuterPo2Preflight => "outer-po2-preflight",
            Self::TerminalCallbackCardinality => "terminal-callback-cardinality",
            Self::TerminalOuterPo2 => "terminal-outer-po2",
            Self::TerminalControlId => "terminal-control-id",
            Self::Risc0ReadIop => "risc0-read-iop",
            Self::Risc0MerkleOpening => "risc0-merkle-opening",
            Self::Risc0ConstraintVerification => "risc0-constraint-verification",
            Self::Risc0ProofVerification => "risc0-proof-verification",
            Self::InnerControlRootBinding => "inner-control-root-binding",
            Self::ExpectedClaimBinding => "expected-claim-binding",
        }
    }
}

/// Stable class/stage projection for one typed STARK-core failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct B4StarkRejectionBoundary {
    /// Stable rejection class.
    pub class: B4StarkErrorClass,
    /// Stable first rejection stage.
    pub stage: B4StarkErrorStage,
}

/// Coarse, closed projection of the pinned upstream verifier's non-exhaustive
/// error enum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum B4Risc0Failure {
    /// The proof was truncated, trailing, or otherwise malformed.
    ReceiptFormat,
    /// A Merkle query addressed a row outside the committed domain.
    MerkleQueryOutOfRange,
    /// An undifferentiated Merkle, algebraic, or FRI proof relation was false.
    InvalidProof,
    /// Another pinned upstream verification boundary rejected.
    Verification,
}

/// Typed failure from the bounded B4 STARK core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum B4StarkError {
    /// The supplied manifest is not the frozen initial-profile target.
    InitialProfileTarget,
    /// The raw seal length differs from the fixed profile length.
    RawSealLength {
        /// Supplied byte length.
        actual: usize,
        /// Required byte length.
        expected: usize,
    },
    /// The existing raw-seal codec rejected an otherwise length-bounded input.
    RawSealDecode,
    /// A raw field/digest word is not a reduced `BabyBear` element.
    RawSealWordNotReduced {
        /// Absolute word index.
        index: usize,
        /// Supplied word.
        word: u32,
    },
    /// One odd inner-root slot word is nonzero.
    NonzeroInnerRootPadding {
        /// Absolute word index.
        index: usize,
    },
    /// A Montgomery-decoded claim word does not fit one unsigned halfword.
    ClaimHalfwordOutOfRange {
        /// Absolute word index.
        index: usize,
        /// Decoded field value.
        value: u32,
    },
    /// The raw header exponent differs from the authenticated manifest.
    OuterPo2Mismatch {
        /// Supplied exponent.
        actual: u32,
        /// Manifest exponent.
        expected: u32,
    },
    /// The upstream callback exponent differs from the authenticated manifest.
    TerminalOuterPo2Mismatch {
        /// Callback exponent.
        actual: u32,
        /// Manifest exponent.
        expected: u32,
    },
    /// Upstream verification returned without invoking the code-root callback.
    TerminalCallbackMissing,
    /// The code-root callback was invoked more than once.
    TerminalCallbackRepeated,
    /// A manifest terminal kind could not be projected to the closed V1 enum.
    TerminalKindUnsupported {
        /// Manifest kind byte.
        kind: u8,
    },
    /// The callback's code root is not exactly one manifest allowlist entry.
    TerminalControlIdNotAllowed {
        /// Explicit little-endian digest bytes observed from the callback.
        actual: [u8; 32],
    },
    /// The pinned upstream verifier rejected.
    Risc0Verifier(B4Risc0Failure),
    /// The cryptographically verified output root differs from the manifest.
    InnerControlRootMismatch {
        /// Manifest root bytes.
        expected: [u8; 32],
        /// Root decoded from the verified output globals.
        actual: [u8; 32],
    },
    /// The cryptographically verified output claim differs from the expected claim.
    ClaimDigestMismatch {
        /// Independently derived claim bytes.
        expected: [u8; 32],
        /// Claim decoded from the verified output globals.
        actual: [u8; 32],
    },
}

impl B4StarkError {
    /// Return the stable B4 class/stage projection for this failure.
    #[must_use]
    pub const fn rejection_boundary(&self) -> B4StarkRejectionBoundary {
        match self {
            Self::InitialProfileTarget => boundary(
                B4StarkErrorClass::InitialProfileTarget,
                B4StarkErrorStage::InitialProfileTarget,
            ),
            Self::RawSealLength { .. } => boundary(
                B4StarkErrorClass::RawSealShape,
                B4StarkErrorStage::RawSealByteLength,
            ),
            Self::RawSealDecode => boundary(
                B4StarkErrorClass::RawSealShape,
                B4StarkErrorStage::CanonicalWordDecoding,
            ),
            Self::RawSealWordNotReduced { .. } => boundary(
                B4StarkErrorClass::RawSealShape,
                B4StarkErrorStage::BabyBearWordReduction,
            ),
            Self::NonzeroInnerRootPadding { .. } => boundary(
                B4StarkErrorClass::RawSealShape,
                B4StarkErrorStage::InnerRootPadding,
            ),
            Self::ClaimHalfwordOutOfRange { .. } => boundary(
                B4StarkErrorClass::RawSealShape,
                B4StarkErrorStage::ClaimHalfwordDecoding,
            ),
            Self::OuterPo2Mismatch { .. } => boundary(
                B4StarkErrorClass::RawSealShape,
                B4StarkErrorStage::OuterPo2Preflight,
            ),
            Self::TerminalOuterPo2Mismatch { .. } => boundary(
                B4StarkErrorClass::TerminalPolicy,
                B4StarkErrorStage::TerminalOuterPo2,
            ),
            Self::TerminalCallbackMissing | Self::TerminalCallbackRepeated => boundary(
                B4StarkErrorClass::TerminalPolicy,
                B4StarkErrorStage::TerminalCallbackCardinality,
            ),
            Self::TerminalKindUnsupported { .. } | Self::TerminalControlIdNotAllowed { .. } => {
                boundary(
                    B4StarkErrorClass::TerminalPolicy,
                    B4StarkErrorStage::TerminalControlId,
                )
            }
            Self::Risc0Verifier(B4Risc0Failure::ReceiptFormat) => boundary(
                B4StarkErrorClass::Risc0Parser,
                B4StarkErrorStage::Risc0ReadIop,
            ),
            Self::Risc0Verifier(B4Risc0Failure::MerkleQueryOutOfRange) => boundary(
                B4StarkErrorClass::Risc0Parser,
                B4StarkErrorStage::Risc0MerkleOpening,
            ),
            Self::Risc0Verifier(B4Risc0Failure::InvalidProof | B4Risc0Failure::Verification) => {
                boundary(
                    B4StarkErrorClass::Risc0CryptographicVerifier,
                    B4StarkErrorStage::Risc0ProofVerification,
                )
            }
            Self::InnerControlRootMismatch { .. } => boundary(
                B4StarkErrorClass::InnerControlRoot,
                B4StarkErrorStage::InnerControlRootBinding,
            ),
            Self::ClaimDigestMismatch { .. } => boundary(
                B4StarkErrorClass::ReceiptClaim,
                B4StarkErrorStage::ExpectedClaimBinding,
            ),
        }
    }
}

const fn boundary(class: B4StarkErrorClass, stage: B4StarkErrorStage) -> B4StarkRejectionBoundary {
    B4StarkRejectionBoundary { class, stage }
}

impl From<VerificationError> for B4StarkError {
    fn from(error: VerificationError) -> Self {
        let failure = match error {
            VerificationError::ReceiptFormatError => B4Risc0Failure::ReceiptFormat,
            VerificationError::MerkleQueryOutOfRange { .. } => {
                B4Risc0Failure::MerkleQueryOutOfRange
            }
            VerificationError::InvalidProof => B4Risc0Failure::InvalidProof,
            _ => B4Risc0Failure::Verification,
        };
        Self::Risc0Verifier(failure)
    }
}

impl fmt::Display for B4StarkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InitialProfileTarget => {
                formatter.write_str("manifest is not the frozen initial-profile target")
            }
            Self::RawSealLength { actual, expected } => {
                write!(
                    formatter,
                    "raw seal has {actual} bytes, expected {expected}"
                )
            }
            Self::RawSealDecode => formatter.write_str("raw seal word decoding failed"),
            Self::RawSealWordNotReduced { index, word } => write!(
                formatter,
                "raw seal word {index} ({word:#010x}) is not a reduced BabyBear element"
            ),
            Self::NonzeroInnerRootPadding { index } => {
                write!(
                    formatter,
                    "raw seal inner-root padding word {index} is nonzero"
                )
            }
            Self::ClaimHalfwordOutOfRange { index, value } => write!(
                formatter,
                "raw seal claim word {index} decodes to {value}, above 65535"
            ),
            Self::OuterPo2Mismatch { actual, expected } => {
                write!(
                    formatter,
                    "raw seal outer po2 is {actual}, expected {expected}"
                )
            }
            Self::TerminalOuterPo2Mismatch { actual, expected } => write!(
                formatter,
                "RISC Zero callback outer po2 is {actual}, expected {expected}"
            ),
            Self::TerminalCallbackMissing => {
                formatter.write_str("RISC Zero terminal callback was not invoked")
            }
            Self::TerminalCallbackRepeated => {
                formatter.write_str("RISC Zero terminal callback was invoked more than once")
            }
            Self::TerminalKindUnsupported { kind } => {
                write!(formatter, "manifest terminal kind {kind} is unsupported")
            }
            Self::TerminalControlIdNotAllowed { actual } => write!(
                formatter,
                "RISC Zero terminal control ID {} is not exactly one manifest allowlist entry",
                hex::encode(actual)
            ),
            Self::Risc0Verifier(failure) => {
                write!(formatter, "pinned RISC Zero verifier rejected: {failure:?}")
            }
            Self::InnerControlRootMismatch { expected, actual } => write!(
                formatter,
                "verified inner control root {} differs from manifest {}",
                hex::encode(actual),
                hex::encode(expected)
            ),
            Self::ClaimDigestMismatch { expected, actual } => write!(
                formatter,
                "verified claim digest {} differs from expected {}",
                hex::encode(actual),
                hex::encode(expected)
            ),
        }
    }
}

impl std::error::Error for B4StarkError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_typed_error_has_closed_nonplaceholder_identifiers() {
        let errors = [
            B4StarkError::InitialProfileTarget,
            B4StarkError::RawSealLength {
                actual: 0,
                expected: 1,
            },
            B4StarkError::RawSealDecode,
            B4StarkError::RawSealWordNotReduced { index: 0, word: 0 },
            B4StarkError::NonzeroInnerRootPadding { index: 1 },
            B4StarkError::ClaimHalfwordOutOfRange {
                index: 16,
                value: 65_536,
            },
            B4StarkError::OuterPo2Mismatch {
                actual: 17,
                expected: 18,
            },
            B4StarkError::TerminalOuterPo2Mismatch {
                actual: 17,
                expected: 18,
            },
            B4StarkError::TerminalCallbackMissing,
            B4StarkError::TerminalCallbackRepeated,
            B4StarkError::TerminalKindUnsupported { kind: 0xff },
            B4StarkError::TerminalControlIdNotAllowed { actual: [0; 32] },
            B4StarkError::Risc0Verifier(B4Risc0Failure::ReceiptFormat),
            B4StarkError::Risc0Verifier(B4Risc0Failure::MerkleQueryOutOfRange),
            B4StarkError::Risc0Verifier(B4Risc0Failure::InvalidProof),
            B4StarkError::Risc0Verifier(B4Risc0Failure::Verification),
            B4StarkError::InnerControlRootMismatch {
                expected: [0; 32],
                actual: [1; 32],
            },
            B4StarkError::ClaimDigestMismatch {
                expected: [0; 32],
                actual: [1; 32],
            },
        ];
        let forbidden = [
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

        for error in errors {
            let boundary = error.rejection_boundary();
            for value in [boundary.class.as_str(), boundary.stage.as_str()] {
                assert!(value.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                }));
                assert!(
                    !forbidden
                        .iter()
                        .any(|part| value.split('-').any(|v| v == *part))
                );
            }
        }
    }
}
