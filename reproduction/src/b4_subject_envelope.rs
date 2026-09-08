// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Closed canonical codec for composite B4 negative subjects.
//!
//! The external negative input selects the handler. This envelope carries only
//! the ordered byte parts required by that handler's fixed consumer grammar;
//! its kind is checked against a compile-time contract and never acts as a
//! second dispatch channel.

#![allow(
    dead_code,
    reason = "the shared codec is staged for the closed materialization finalizer and feature-gated validator"
)]

use core::fmt;

#[cfg(any(feature = "materializer-replay", feature = "validator"))]
use crate::{
    b4_terminal::B4_TERMINAL_FIXTURE_CATALOG_MAX_BYTES,
    b4_terminal_byte_map::{B4TerminalByteMapKind, terminal_byte_map_maximum_encoded_bytes},
    constants::{MANIFEST_BYTES, MANIFEST_CONTROL_ENTRY_BYTES},
};

#[cfg(feature = "recursive-ancestry")]
use crate::{
    b4_recursive_auxiliary_map::B4_RECURSIVE_AUXILIARY_MAP_MAX_BYTES, constants::PROOF_BYTES,
    recursive_ancestry::RECURSIVE_ANCESTRY_MAX_BYTES,
};

const MAGIC: [u8; 8] = *b"EIP45B4S";
const VERSION: u8 = 1;
const HEADER_BYTES: usize = MAGIC.len() + 1 + 1 + 2;
const PART_LENGTH_BYTES: usize = 4;
const MAX_PARTS: usize = 64;
const MAX_ENCODED_BYTES: usize = 536_870_912;
#[cfg(feature = "recursive-ancestry")]
const ANCESTRY_STATEMENT_MIN_BYTES: usize = 159;
#[cfg(feature = "recursive-ancestry")]
const ANCESTRY_STATEMENT_MAX_BYTES: usize = 16_543;

/// Closed V1 composite-subject grammar identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum B4SubjectEnvelopeKind {
    OpcodeInputs = 0x01,
    ProfilePackage = 0x02,
    AncestryBundle = 0x03,
    TerminalCatalogBundle = 0x10,
    SequenceCatalogBundle = 0x11,
    TerminalMetadataBundle = 0x12,
    ProfileIdPreimageBundle = 0x13,
    CandidateRegistryBundle = 0x14,
    NegativeBindingIndexBundle = 0x15,
}

impl B4SubjectEnvelopeKind {
    #[cfg(test)]
    const ALL: [Self; 9] = [
        Self::OpcodeInputs,
        Self::ProfilePackage,
        Self::AncestryBundle,
        Self::TerminalCatalogBundle,
        Self::SequenceCatalogBundle,
        Self::TerminalMetadataBundle,
        Self::ProfileIdPreimageBundle,
        Self::CandidateRegistryBundle,
        Self::NegativeBindingIndexBundle,
    ];

    const fn from_byte(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::OpcodeInputs),
            0x02 => Some(Self::ProfilePackage),
            0x03 => Some(Self::AncestryBundle),
            0x10 => Some(Self::TerminalCatalogBundle),
            0x11 => Some(Self::SequenceCatalogBundle),
            0x12 => Some(Self::TerminalMetadataBundle),
            0x13 => Some(Self::ProfileIdPreimageBundle),
            0x14 => Some(Self::CandidateRegistryBundle),
            0x15 => Some(Self::NegativeBindingIndexBundle),
            _ => None,
        }
    }
}

/// Consumer-owned byte bounds for one positional envelope part.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct B4SubjectPartBounds {
    minimum: usize,
    maximum: usize,
}

impl B4SubjectPartBounds {
    pub(crate) const fn new(minimum: usize, maximum: usize) -> Self {
        Self { minimum, maximum }
    }
}

/// Exact envelope grammar required by one closed negative handler.
#[derive(Clone, Copy, Debug)]
pub(crate) struct B4SubjectEnvelopeContract<'a> {
    kind: B4SubjectEnvelopeKind,
    part_bounds: &'a [B4SubjectPartBounds],
}

impl<'a> B4SubjectEnvelopeContract<'a> {
    pub(crate) const fn new(
        kind: B4SubjectEnvelopeKind,
        part_bounds: &'a [B4SubjectPartBounds],
    ) -> Self {
        Self { kind, part_bounds }
    }
}

#[cfg(feature = "recursive-ancestry")]
const ANCESTRY_PARTS: [B4SubjectPartBounds; 4] = [
    B4SubjectPartBounds::new(1, RECURSIVE_ANCESTRY_MAX_BYTES),
    B4SubjectPartBounds::new(ANCESTRY_STATEMENT_MIN_BYTES, ANCESTRY_STATEMENT_MAX_BYTES),
    B4SubjectPartBounds::new(PROOF_BYTES, PROOF_BYTES),
    B4SubjectPartBounds::new(1, B4_RECURSIVE_AUXILIARY_MAP_MAX_BYTES),
];

/// Sole four-part contract for recursive ancestry producer and consumer framing.
#[cfg(feature = "recursive-ancestry")]
pub(crate) const fn ancestry_subject_envelope_contract() -> B4SubjectEnvelopeContract<'static> {
    B4SubjectEnvelopeContract::new(B4SubjectEnvelopeKind::AncestryBundle, &ANCESTRY_PARTS)
}

#[cfg(any(feature = "materializer-replay", feature = "validator"))]
const TERMINAL_METADATA_PARTS: [B4SubjectPartBounds; 2] = [
    B4SubjectPartBounds::new(MANIFEST_BYTES, MANIFEST_BYTES),
    B4SubjectPartBounds::new(MANIFEST_CONTROL_ENTRY_BYTES, MANIFEST_CONTROL_ENTRY_BYTES),
];

/// Sole two-part contract for terminal-metadata producer and consumer framing.
#[cfg(any(feature = "materializer-replay", feature = "validator"))]
pub(crate) const fn terminal_metadata_subject_envelope_contract()
-> B4SubjectEnvelopeContract<'static> {
    B4SubjectEnvelopeContract::new(
        B4SubjectEnvelopeKind::TerminalMetadataBundle,
        &TERMINAL_METADATA_PARTS,
    )
}

#[cfg(any(feature = "materializer-replay", feature = "validator"))]
const TERMINAL_CATALOG_PARTS: [B4SubjectPartBounds; 3] = [
    B4SubjectPartBounds::new(1, B4_TERMINAL_FIXTURE_CATALOG_MAX_BYTES),
    B4SubjectPartBounds::new(
        1,
        terminal_byte_map_maximum_encoded_bytes(B4TerminalByteMapKind::RawSeal),
    ),
    B4SubjectPartBounds::new(
        1,
        terminal_byte_map_maximum_encoded_bytes(B4TerminalByteMapKind::ReceiptOracle),
    ),
];

/// Sole three-part contract for terminal-catalogue producer and consumer framing.
#[cfg(any(feature = "materializer-replay", feature = "validator"))]
pub(crate) const fn terminal_catalog_subject_envelope_contract()
-> B4SubjectEnvelopeContract<'static> {
    B4SubjectEnvelopeContract::new(
        B4SubjectEnvelopeKind::TerminalCatalogBundle,
        &TERMINAL_CATALOG_PARTS,
    )
}

/// Borrowed canonical parts from one authenticated subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct B4DecodedSubjectEnvelope<'a> {
    parts: Vec<&'a [u8]>,
}

impl<'a> B4DecodedSubjectEnvelope<'a> {
    pub(crate) fn parts(&self) -> &[&'a [u8]] {
        &self.parts
    }
}

/// Private framing failures. None is a campaign rejection observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum B4SubjectEnvelopeError {
    InvalidContract,
    SubjectTooLarge,
    TruncatedHeader,
    MagicMismatch,
    UnsupportedVersion(u8),
    UnsupportedKind(u8),
    UnexpectedKind {
        actual: B4SubjectEnvelopeKind,
        expected: B4SubjectEnvelopeKind,
    },
    PartCountMismatch {
        actual: usize,
        expected: usize,
    },
    TruncatedPartLength {
        index: usize,
    },
    PartLengthOutOfBounds {
        index: usize,
        actual: usize,
        minimum: usize,
        maximum: usize,
    },
    LengthArithmeticOverflow {
        index: usize,
    },
    TruncatedPart {
        index: usize,
    },
    TrailingBytes,
}

impl fmt::Display for B4SubjectEnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContract => formatter.write_str("invalid subject-envelope contract"),
            Self::SubjectTooLarge => {
                formatter.write_str("subject envelope exceeds its handler-owned byte bound")
            }
            Self::TruncatedHeader => formatter.write_str("truncated subject-envelope header"),
            Self::MagicMismatch => formatter.write_str("wrong subject-envelope magic"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported subject-envelope version {version}")
            }
            Self::UnsupportedKind(kind) => {
                write!(formatter, "unsupported subject-envelope kind {kind:#04x}")
            }
            Self::UnexpectedKind { actual, expected } => write!(
                formatter,
                "subject-envelope kind {actual:?} differs from handler contract {expected:?}"
            ),
            Self::PartCountMismatch { actual, expected } => write!(
                formatter,
                "subject-envelope part count {actual} differs from handler contract {expected}"
            ),
            Self::TruncatedPartLength { index } => {
                write!(formatter, "truncated subject-envelope part-{index} length")
            }
            Self::PartLengthOutOfBounds {
                index,
                actual,
                minimum,
                maximum,
            } => write!(
                formatter,
                "subject-envelope part-{index} length {actual} is outside {minimum}..={maximum}"
            ),
            Self::LengthArithmeticOverflow { index } => {
                write!(formatter, "subject-envelope part-{index} length overflows")
            }
            Self::TruncatedPart { index } => {
                write!(formatter, "truncated subject-envelope part-{index}")
            }
            Self::TrailingBytes => formatter.write_str("trailing subject-envelope bytes"),
        }
    }
}

impl std::error::Error for B4SubjectEnvelopeError {}

/// Decode one envelope against the already selected handler contract.
///
/// Payloads are borrowed from `source`; the decoder allocates only the bounded
/// vector of at most 64 slice descriptors.
pub(crate) fn decode_subject_envelope<'a>(
    source: &'a [u8],
    contract: B4SubjectEnvelopeContract<'_>,
) -> Result<B4DecodedSubjectEnvelope<'a>, B4SubjectEnvelopeError> {
    let maximum_encoded_bytes = validate_contract(contract)?;
    if source.len() > maximum_encoded_bytes {
        return Err(B4SubjectEnvelopeError::SubjectTooLarge);
    }
    if source.len() < HEADER_BYTES {
        return Err(B4SubjectEnvelopeError::TruncatedHeader);
    }
    if source[..MAGIC.len()] != MAGIC {
        return Err(B4SubjectEnvelopeError::MagicMismatch);
    }
    let version = source[MAGIC.len()];
    if version != VERSION {
        return Err(B4SubjectEnvelopeError::UnsupportedVersion(version));
    }
    let kind_byte = source[MAGIC.len() + 1];
    let actual_kind = B4SubjectEnvelopeKind::from_byte(kind_byte)
        .ok_or(B4SubjectEnvelopeError::UnsupportedKind(kind_byte))?;
    if actual_kind != contract.kind {
        return Err(B4SubjectEnvelopeError::UnexpectedKind {
            actual: actual_kind,
            expected: contract.kind,
        });
    }
    let part_count_offset = MAGIC.len() + 2;
    let part_count = usize::from(u16::from_le_bytes([
        source[part_count_offset],
        source[part_count_offset + 1],
    ]));
    if part_count != contract.part_bounds.len() {
        return Err(B4SubjectEnvelopeError::PartCountMismatch {
            actual: part_count,
            expected: contract.part_bounds.len(),
        });
    }

    let mut cursor = HEADER_BYTES;
    let mut parts = Vec::with_capacity(part_count);
    for (index, bounds) in contract.part_bounds.iter().enumerate() {
        let length_end = cursor
            .checked_add(PART_LENGTH_BYTES)
            .ok_or(B4SubjectEnvelopeError::LengthArithmeticOverflow { index })?;
        let length_bytes = source
            .get(cursor..length_end)
            .ok_or(B4SubjectEnvelopeError::TruncatedPartLength { index })?;
        let length = usize::try_from(u32::from_le_bytes(
            length_bytes
                .try_into()
                .map_err(|_| B4SubjectEnvelopeError::TruncatedPartLength { index })?,
        ))
        .map_err(|_| B4SubjectEnvelopeError::LengthArithmeticOverflow { index })?;
        if !(bounds.minimum..=bounds.maximum).contains(&length) {
            return Err(B4SubjectEnvelopeError::PartLengthOutOfBounds {
                index,
                actual: length,
                minimum: bounds.minimum,
                maximum: bounds.maximum,
            });
        }
        cursor = length_end;
        let part_end = cursor
            .checked_add(length)
            .ok_or(B4SubjectEnvelopeError::LengthArithmeticOverflow { index })?;
        let part = source
            .get(cursor..part_end)
            .ok_or(B4SubjectEnvelopeError::TruncatedPart { index })?;
        parts.push(part);
        cursor = part_end;
    }
    if cursor != source.len() {
        return Err(B4SubjectEnvelopeError::TrailingBytes);
    }
    Ok(B4DecodedSubjectEnvelope { parts })
}

/// Encode one envelope under the same closed contract used by the decoder.
///
/// The caller selects a compile-time contract; arbitrary kind bytes, part
/// counts, and unbounded part lengths are not accepted. The returned bytes use
/// the single V1 layout: magic, version, kind, little-endian `u16` part count,
/// then one little-endian `u32` length and payload per ordered part.
pub(crate) fn encode_subject_envelope(
    parts: &[&[u8]],
    contract: B4SubjectEnvelopeContract<'_>,
) -> Result<Vec<u8>, B4SubjectEnvelopeError> {
    validate_contract(contract)?;
    if parts.len() != contract.part_bounds.len() {
        return Err(B4SubjectEnvelopeError::PartCountMismatch {
            actual: parts.len(),
            expected: contract.part_bounds.len(),
        });
    }

    let mut encoded_bytes = HEADER_BYTES;
    for (index, (part, bounds)) in parts.iter().zip(contract.part_bounds).enumerate() {
        if !(bounds.minimum..=bounds.maximum).contains(&part.len()) {
            return Err(B4SubjectEnvelopeError::PartLengthOutOfBounds {
                index,
                actual: part.len(),
                minimum: bounds.minimum,
                maximum: bounds.maximum,
            });
        }
        encoded_bytes = encoded_bytes
            .checked_add(PART_LENGTH_BYTES)
            .and_then(|length| length.checked_add(part.len()))
            .ok_or(B4SubjectEnvelopeError::LengthArithmeticOverflow { index })?;
    }
    if encoded_bytes > MAX_ENCODED_BYTES {
        return Err(B4SubjectEnvelopeError::SubjectTooLarge);
    }

    let part_count =
        u16::try_from(parts.len()).map_err(|_| B4SubjectEnvelopeError::InvalidContract)?;
    let mut encoded = Vec::with_capacity(encoded_bytes);
    encoded.extend_from_slice(&MAGIC);
    encoded.push(VERSION);
    encoded.push(contract.kind as u8);
    encoded.extend_from_slice(&part_count.to_le_bytes());
    for (index, part) in parts.iter().enumerate() {
        let part_length = u32::try_from(part.len())
            .map_err(|_| B4SubjectEnvelopeError::LengthArithmeticOverflow { index })?;
        encoded.extend_from_slice(&part_length.to_le_bytes());
        encoded.extend_from_slice(part);
    }
    debug_assert_eq!(encoded.len(), encoded_bytes);
    Ok(encoded)
}

fn validate_contract(
    contract: B4SubjectEnvelopeContract<'_>,
) -> Result<usize, B4SubjectEnvelopeError> {
    if contract.part_bounds.len() > MAX_PARTS {
        return Err(B4SubjectEnvelopeError::InvalidContract);
    }
    let mut maximum_encoded_bytes = HEADER_BYTES;
    for bounds in contract.part_bounds {
        if bounds.minimum > bounds.maximum || bounds.maximum > u32::MAX as usize {
            return Err(B4SubjectEnvelopeError::InvalidContract);
        }
        maximum_encoded_bytes = maximum_encoded_bytes
            .checked_add(PART_LENGTH_BYTES)
            .and_then(|length| length.checked_add(bounds.maximum))
            .ok_or(B4SubjectEnvelopeError::InvalidContract)?;
    }
    if maximum_encoded_bytes > MAX_ENCODED_BYTES {
        return Err(B4SubjectEnvelopeError::InvalidContract);
    }
    Ok(maximum_encoded_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_TO_THREE: B4SubjectPartBounds = B4SubjectPartBounds::new(0, 3);
    const ONE_TO_FOUR: B4SubjectPartBounds = B4SubjectPartBounds::new(1, 4);
    const TWO_PARTS: [B4SubjectPartBounds; 2] = [ZERO_TO_THREE, ONE_TO_FOUR];

    fn contract(
        kind: B4SubjectEnvelopeKind,
        bounds: &'static [B4SubjectPartBounds],
    ) -> B4SubjectEnvelopeContract<'static> {
        B4SubjectEnvelopeContract::new(kind, bounds)
    }

    fn encode_raw(kind: B4SubjectEnvelopeKind, parts: &[&[u8]]) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&MAGIC);
        encoded.push(VERSION);
        encoded.push(kind as u8);
        encoded.extend_from_slice(&u16::try_from(parts.len()).unwrap().to_le_bytes());
        for part in parts {
            encoded.extend_from_slice(&u32::try_from(part.len()).unwrap().to_le_bytes());
            encoded.extend_from_slice(part);
        }
        encoded
    }

    #[test]
    fn canonical_layout_and_borrowed_parts_are_exact() {
        let source = encode_subject_envelope(
            &[b"", b"abc"],
            contract(B4SubjectEnvelopeKind::OpcodeInputs, &TWO_PARTS),
        )
        .unwrap();
        let mut expected = b"EIP45B4S\x01\x01\x02\x00".to_vec();
        expected.extend_from_slice(&[0, 0, 0, 0]);
        expected.extend_from_slice(&[3, 0, 0, 0]);
        expected.extend_from_slice(b"abc");
        assert_eq!(source, expected);

        let decoded = decode_subject_envelope(
            &source,
            contract(B4SubjectEnvelopeKind::OpcodeInputs, &TWO_PARTS),
        )
        .unwrap();
        assert_eq!(decoded.parts(), &[&b""[..], &b"abc"[..]]);
        assert_eq!(decoded.parts()[1].as_ptr(), source[20..].as_ptr());
    }

    #[test]
    fn every_v1_kind_round_trips_under_its_selected_contract() {
        const ONE_PART: [B4SubjectPartBounds; 1] = [B4SubjectPartBounds::new(1, 8)];
        for kind in B4SubjectEnvelopeKind::ALL {
            let source = encode_subject_envelope(&[b"part"], contract(kind, &ONE_PART)).unwrap();
            let decoded = decode_subject_envelope(&source, contract(kind, &ONE_PART)).unwrap();
            assert_eq!(decoded.parts(), &[&b"part"[..]]);

            let mut exact = b"EIP45B4S\x01".to_vec();
            exact.push(kind as u8);
            exact.extend_from_slice(&1_u16.to_le_bytes());
            exact.extend_from_slice(&4_u32.to_le_bytes());
            exact.extend_from_slice(b"part");
            assert_eq!(source, exact, "canonical bytes drifted for {kind:?}");
        }
    }

    #[test]
    fn encoder_rejects_part_count_and_length_mismatches() {
        assert_eq!(
            encode_subject_envelope(
                &[b"abc"],
                contract(B4SubjectEnvelopeKind::OpcodeInputs, &TWO_PARTS),
            ),
            Err(B4SubjectEnvelopeError::PartCountMismatch {
                actual: 1,
                expected: 2,
            })
        );
        assert_eq!(
            encode_subject_envelope(
                &[b"abcde"],
                contract(B4SubjectEnvelopeKind::OpcodeInputs, &[ONE_TO_FOUR]),
            ),
            Err(B4SubjectEnvelopeError::PartLengthOutOfBounds {
                index: 0,
                actual: 5,
                minimum: 1,
                maximum: 4,
            })
        );
    }

    #[test]
    fn encoder_rejects_global_part_and_byte_bounds_before_allocation() {
        const EMPTY: B4SubjectPartBounds = B4SubjectPartBounds::new(0, 0);
        const TOO_MANY: [B4SubjectPartBounds; MAX_PARTS + 1] = [EMPTY; MAX_PARTS + 1];
        const TOO_LARGE: [B4SubjectPartBounds; 1] =
            [B4SubjectPartBounds::new(0, MAX_ENCODED_BYTES)];
        const EMPTY_PARTS: [&[u8]; MAX_PARTS + 1] = [&[]; MAX_PARTS + 1];

        assert_eq!(
            encode_subject_envelope(
                &EMPTY_PARTS,
                contract(B4SubjectEnvelopeKind::OpcodeInputs, &TOO_MANY),
            ),
            Err(B4SubjectEnvelopeError::InvalidContract)
        );
        assert_eq!(
            encode_subject_envelope(
                &[b""],
                contract(B4SubjectEnvelopeKind::OpcodeInputs, &TOO_LARGE),
            ),
            Err(B4SubjectEnvelopeError::InvalidContract)
        );
    }

    #[test]
    fn every_strict_prefix_is_rejected() {
        let source = encode_raw(B4SubjectEnvelopeKind::OpcodeInputs, &[b"ab", b"cdef"]);
        for cut in 0..source.len() {
            assert!(
                decode_subject_envelope(
                    &source[..cut],
                    contract(B4SubjectEnvelopeKind::OpcodeInputs, &TWO_PARTS),
                )
                .is_err(),
                "prefix ending at byte {cut} was accepted"
            );
        }
    }

    #[test]
    fn every_magic_byte_and_each_other_header_field_is_authenticated() {
        let source = encode_raw(B4SubjectEnvelopeKind::OpcodeInputs, &[b"ab", b"c"]);
        for index in 0..MAGIC.len() {
            let mut changed = source.clone();
            changed[index] ^= 1;
            assert_eq!(
                decode_subject_envelope(
                    &changed,
                    contract(B4SubjectEnvelopeKind::OpcodeInputs, &TWO_PARTS)
                ),
                Err(B4SubjectEnvelopeError::MagicMismatch)
            );
        }

        let mut version = source.clone();
        version[MAGIC.len()] = 2;
        assert_eq!(
            decode_subject_envelope(
                &version,
                contract(B4SubjectEnvelopeKind::OpcodeInputs, &TWO_PARTS)
            ),
            Err(B4SubjectEnvelopeError::UnsupportedVersion(2))
        );

        let mut unknown_kind = source.clone();
        unknown_kind[MAGIC.len() + 1] = 0xff;
        assert_eq!(
            decode_subject_envelope(
                &unknown_kind,
                contract(B4SubjectEnvelopeKind::OpcodeInputs, &TWO_PARTS)
            ),
            Err(B4SubjectEnvelopeError::UnsupportedKind(0xff))
        );

        let mut count_low = source.clone();
        count_low[MAGIC.len() + 2] = 1;
        assert_eq!(
            decode_subject_envelope(
                &count_low,
                contract(B4SubjectEnvelopeKind::OpcodeInputs, &TWO_PARTS)
            ),
            Err(B4SubjectEnvelopeError::PartCountMismatch {
                actual: 1,
                expected: 2
            })
        );

        let mut count_high = source;
        count_high[MAGIC.len() + 3] = 1;
        assert_eq!(
            decode_subject_envelope(
                &count_high,
                contract(B4SubjectEnvelopeKind::OpcodeInputs, &TWO_PARTS)
            ),
            Err(B4SubjectEnvelopeError::PartCountMismatch {
                actual: 258,
                expected: 2
            })
        );
    }

    #[test]
    fn a_known_but_wrong_kind_cannot_select_another_handler() {
        const ONE_PART: [B4SubjectPartBounds; 1] = [B4SubjectPartBounds::new(1, 8)];
        let source = encode_raw(B4SubjectEnvelopeKind::ProfilePackage, &[b"x"]);
        assert_eq!(
            decode_subject_envelope(
                &source,
                contract(B4SubjectEnvelopeKind::OpcodeInputs, &ONE_PART)
            ),
            Err(B4SubjectEnvelopeError::UnexpectedKind {
                actual: B4SubjectEnvelopeKind::ProfilePackage,
                expected: B4SubjectEnvelopeKind::OpcodeInputs
            })
        );
    }

    #[test]
    fn understated_overstated_and_out_of_bound_lengths_fail_closed() {
        const ONE_PART: [B4SubjectPartBounds; 1] = [B4SubjectPartBounds::new(1, 4)];
        let selected = contract(B4SubjectEnvelopeKind::OpcodeInputs, &ONE_PART);

        let mut understated = encode_raw(B4SubjectEnvelopeKind::OpcodeInputs, &[b"abc"]);
        understated[HEADER_BYTES..HEADER_BYTES + 4].copy_from_slice(&2_u32.to_le_bytes());
        assert_eq!(
            decode_subject_envelope(&understated, selected),
            Err(B4SubjectEnvelopeError::TrailingBytes)
        );

        let mut overstated = encode_raw(B4SubjectEnvelopeKind::OpcodeInputs, &[b"abc"]);
        overstated[HEADER_BYTES..HEADER_BYTES + 4].copy_from_slice(&4_u32.to_le_bytes());
        assert_eq!(
            decode_subject_envelope(&overstated, selected),
            Err(B4SubjectEnvelopeError::TruncatedPart { index: 0 })
        );

        let too_long = encode_raw(B4SubjectEnvelopeKind::OpcodeInputs, &[b"abcde"]);
        assert_eq!(
            decode_subject_envelope(&too_long, selected),
            Err(B4SubjectEnvelopeError::SubjectTooLarge)
        );

        let empty = encode_raw(B4SubjectEnvelopeKind::OpcodeInputs, &[b""]);
        assert_eq!(
            decode_subject_envelope(&empty, selected),
            Err(B4SubjectEnvelopeError::PartLengthOutOfBounds {
                index: 0,
                actual: 0,
                minimum: 1,
                maximum: 4
            })
        );
    }

    #[test]
    fn zero_length_is_a_consumer_contract_choice() {
        const OPTIONAL: [B4SubjectPartBounds; 1] = [B4SubjectPartBounds::new(0, 0)];
        let source = encode_subject_envelope(
            &[b""],
            contract(B4SubjectEnvelopeKind::OpcodeInputs, &OPTIONAL),
        )
        .unwrap();
        let decoded = decode_subject_envelope(
            &source,
            contract(B4SubjectEnvelopeKind::OpcodeInputs, &OPTIONAL),
        )
        .unwrap();
        assert_eq!(decoded.parts(), &[&b""[..]]);
    }

    #[test]
    fn invalid_or_oversized_contracts_are_rejected_before_subject_use() {
        const REVERSED: [B4SubjectPartBounds; 1] = [B4SubjectPartBounds::new(2, 1)];
        const TOO_LARGE: [B4SubjectPartBounds; 1] =
            [B4SubjectPartBounds::new(0, MAX_ENCODED_BYTES)];
        const ONE_BYTE: B4SubjectPartBounds = B4SubjectPartBounds::new(0, 0);
        const TOO_MANY: [B4SubjectPartBounds; MAX_PARTS + 1] = [ONE_BYTE; MAX_PARTS + 1];

        assert_eq!(
            decode_subject_envelope(
                b"",
                contract(B4SubjectEnvelopeKind::OpcodeInputs, &REVERSED)
            ),
            Err(B4SubjectEnvelopeError::InvalidContract)
        );

        assert_eq!(
            decode_subject_envelope(
                b"",
                contract(B4SubjectEnvelopeKind::OpcodeInputs, &TOO_LARGE)
            ),
            Err(B4SubjectEnvelopeError::InvalidContract)
        );

        assert_eq!(
            decode_subject_envelope(
                b"",
                contract(B4SubjectEnvelopeKind::OpcodeInputs, &TOO_MANY)
            ),
            Err(B4SubjectEnvelopeError::InvalidContract)
        );
    }

    #[test]
    fn reserved_kind_values_are_all_rejected() {
        const NO_PARTS: [B4SubjectPartBounds; 0] = [];
        for kind in 0_u8..=u8::MAX {
            if B4SubjectEnvelopeKind::from_byte(kind).is_some() {
                continue;
            }
            let mut source = encode_raw(B4SubjectEnvelopeKind::OpcodeInputs, &[]);
            source[MAGIC.len() + 1] = kind;
            assert_eq!(
                decode_subject_envelope(
                    &source,
                    contract(B4SubjectEnvelopeKind::OpcodeInputs, &NO_PARTS)
                ),
                Err(B4SubjectEnvelopeError::UnsupportedKind(kind))
            );
        }
    }

    #[test]
    fn maximum_u32_length_is_rejected_without_payload_allocation() {
        const ONE_PART: [B4SubjectPartBounds; 1] = [B4SubjectPartBounds::new(
            0,
            MAX_ENCODED_BYTES - HEADER_BYTES - 4,
        )];
        let mut source = encode_raw(B4SubjectEnvelopeKind::OpcodeInputs, &[b""]);
        source[HEADER_BYTES..HEADER_BYTES + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            decode_subject_envelope(
                &source,
                contract(B4SubjectEnvelopeKind::OpcodeInputs, &ONE_PART)
            ),
            Err(B4SubjectEnvelopeError::PartLengthOutOfBounds {
                index: 0,
                actual: u32::MAX as usize,
                minimum: 0,
                maximum: MAX_ENCODED_BYTES - HEADER_BYTES - 4
            })
        );
    }
}
