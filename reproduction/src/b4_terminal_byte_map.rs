// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Shared exact byte-map framing engine and terminal-artifact wrappers.
//!
//! This crate-private module is the sole encoder/decoder authority for the
//! `u16 count || (u16 path length || path || u32 payload length || payload)*`
//! framing shared by terminal artifacts and recursive auxiliary seals. The
//! terminal wrappers remain the sole terminal wire-path and ordering authority.
//! They carry no semantic fixture ordering: catalogue fixture zero remains
//! `lift-po2-14` even though unsigned path-byte ordering places that fixture at
//! wire index 3. Decoded payloads borrow from the already authenticated subject
//! bytes.

use core::{cmp::Ordering, fmt};

use crate::{constants::PROOF_BYTES, receipt_oracle_codec::RECEIPT_ORACLE_MAX_BYTES};

const COUNT_BYTES: usize = 2;
const PATH_LENGTH_BYTES: usize = 2;
const PAYLOAD_LENGTH_BYTES: usize = 4;
const MAX_PATH_BYTES: usize = 512;
const MAX_ENCODED_BYTES: usize = 536_870_912;

pub(crate) const B4_TERMINAL_BYTE_MAP_ENTRY_COUNT: usize = 9;

/// Fixture IDs in strict unsigned path-byte wire order.
///
/// This order is deliberately independent of the semantic catalogue layout.
#[cfg(test)]
const B4_TERMINAL_WIRE_FIXTURE_IDS: [&str; B4_TERMINAL_BYTE_MAP_ENTRY_COUNT] = [
    "allowed-terminal-non-ok",
    "join-povw",
    "join-unwrap-povw",
    "lift-po2-14",
    "lift-povw-po2-18",
    "resolve-povw",
    "resolve-unwrap-povw",
    "union",
    "unwrap-povw",
];

const TERMINAL_RAW_PATHS: [&str; B4_TERMINAL_BYTE_MAP_ENTRY_COUNT] = [
    "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/allowed-terminal-non-ok.raw-seal.bin",
    "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/join-povw.raw-seal.bin",
    "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/join-unwrap-povw.raw-seal.bin",
    "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/lift-po2-14.raw-seal.bin",
    "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/lift-povw-po2-18.raw-seal.bin",
    "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/resolve-povw.raw-seal.bin",
    "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/resolve-unwrap-povw.raw-seal.bin",
    "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/union.raw-seal.bin",
    "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/unwrap-povw.raw-seal.bin",
];
const TERMINAL_ORACLE_PATHS: [&str; B4_TERMINAL_BYTE_MAP_ENTRY_COUNT] = [
    "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/allowed-terminal-non-ok.receipt-oracle.bincode",
    "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/join-povw.receipt-oracle.bincode",
    "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/join-unwrap-povw.receipt-oracle.bincode",
    "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/lift-po2-14.receipt-oracle.bincode",
    "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/lift-povw-po2-18.receipt-oracle.bincode",
    "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/resolve-povw.receipt-oracle.bincode",
    "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/resolve-unwrap-povw.receipt-oracle.bincode",
    "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/union.receipt-oracle.bincode",
    "reproduction/schema/b4-corpus-v1.candidate/terminal-fixtures/unwrap-povw.receipt-oracle.bincode",
];
const TERMINAL_RAW_PAYLOAD_BOUNDS: [B4ByteMapPayloadBounds; B4_TERMINAL_BYTE_MAP_ENTRY_COUNT] =
    [B4ByteMapPayloadBounds::new(PROOF_BYTES, PROOF_BYTES); B4_TERMINAL_BYTE_MAP_ENTRY_COUNT];
const TERMINAL_ORACLE_PAYLOAD_BOUNDS: [B4ByteMapPayloadBounds; B4_TERMINAL_BYTE_MAP_ENTRY_COUNT] =
    [B4ByteMapPayloadBounds::new(1, RECEIPT_ORACLE_MAX_BYTES); B4_TERMINAL_BYTE_MAP_ENTRY_COUNT];

/// Derive the exact largest wire size admitted by a fixed path sequence and
/// one common per-entry payload maximum.
///
/// This is framing arithmetic only. [`B4ByteMapContract`] remains the authority
/// that validates the paths, cardinality, payload bounds, and resulting cap.
#[must_use]
pub(crate) const fn exact_byte_map_maximum_encoded_bytes(
    paths: &[&str],
    maximum_payload_bytes: usize,
) -> usize {
    let mut total = COUNT_BYTES;
    let mut index = 0;
    while index < paths.len() {
        total = match total.checked_add(PATH_LENGTH_BYTES) {
            Some(value) => value,
            None => panic!("byte-map maximum path-length framing overflows"),
        };
        total = match total.checked_add(paths[index].len()) {
            Some(value) => value,
            None => panic!("byte-map maximum path bytes overflow"),
        };
        total = match total.checked_add(PAYLOAD_LENGTH_BYTES) {
            Some(value) => value,
            None => panic!("byte-map maximum payload-length framing overflows"),
        };
        total = match total.checked_add(maximum_payload_bytes) {
            Some(value) => value,
            None => panic!("byte-map maximum payload bytes overflow"),
        };
        index += 1;
    }
    total
}

// Exact maxima are derived from the compiled paths and payload policy, not the
// generic path ceiling or copied numeric literals.
const TERMINAL_RAW_MAP_MAX_BYTES: usize =
    exact_byte_map_maximum_encoded_bytes(&TERMINAL_RAW_PATHS, PROOF_BYTES);
const TERMINAL_ORACLE_MAP_MAX_BYTES: usize =
    exact_byte_map_maximum_encoded_bytes(&TERMINAL_ORACLE_PATHS, RECEIPT_ORACLE_MAX_BYTES);

/// The two fixed terminal artifact maps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum B4TerminalByteMapKind {
    RawSeal,
    ReceiptOracle,
}

/// Return the exact paths for one terminal map in unsigned path-byte wire order.
#[must_use]
#[cfg(any(feature = "materializer-replay", test))]
pub(crate) const fn terminal_byte_map_paths(
    kind: B4TerminalByteMapKind,
) -> &'static [&'static str; B4_TERMINAL_BYTE_MAP_ENTRY_COUNT] {
    match kind {
        B4TerminalByteMapKind::RawSeal => &TERMINAL_RAW_PATHS,
        B4TerminalByteMapKind::ReceiptOracle => &TERMINAL_ORACLE_PATHS,
    }
}

/// Return the exact maximum encoded size for one terminal map.
#[must_use]
pub(crate) const fn terminal_byte_map_maximum_encoded_bytes(kind: B4TerminalByteMapKind) -> usize {
    match kind {
        B4TerminalByteMapKind::RawSeal => TERMINAL_RAW_MAP_MAX_BYTES,
        B4TerminalByteMapKind::ReceiptOracle => TERMINAL_ORACLE_MAP_MAX_BYTES,
    }
}

/// Inclusive byte bounds for one positional map payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct B4ByteMapPayloadBounds {
    minimum: usize,
    maximum: usize,
}

impl B4ByteMapPayloadBounds {
    #[must_use]
    pub(crate) const fn new(minimum: usize, maximum: usize) -> Self {
        Self { minimum, maximum }
    }
}

/// One exact shape admitted by a handler.
///
/// The number of payload bounds and expected paths is the exact encoded entry
/// count. `expected_paths` is the exact path sequence in exact wire order.
#[derive(Clone, Copy, Debug)]
struct B4ByteMapShapeContract<'a> {
    payload_bounds: &'a [B4ByteMapPayloadBounds],
    expected_paths: &'a [&'a str],
}

impl<'a> B4ByteMapShapeContract<'a> {
    #[must_use]
    const fn new(
        payload_bounds: &'a [B4ByteMapPayloadBounds],
        expected_paths: &'a [&'a str],
    ) -> Self {
        Self {
            payload_bounds,
            expected_paths,
        }
    }

    const fn entry_count(self) -> usize {
        self.payload_bounds.len()
    }
}

/// Complete byte-map grammar owned by one already selected handler.
#[derive(Clone, Copy, Debug)]
pub(crate) struct B4ByteMapContract<'a> {
    shape: B4ByteMapShapeContract<'a>,
    maximum_encoded_bytes: usize,
}

impl<'a> B4ByteMapContract<'a> {
    /// Admit one exact count, path sequence, and payload shape.
    #[must_use]
    pub(crate) const fn exact(
        payload_bounds: &'a [B4ByteMapPayloadBounds],
        expected_paths: &'a [&'a str],
        maximum_encoded_bytes: usize,
    ) -> Self {
        Self {
            shape: B4ByteMapShapeContract::new(payload_bounds, expected_paths),
            maximum_encoded_bytes,
        }
    }
}

/// One borrowed canonical path/payload entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct B4ByteMapEntry<'a> {
    path: &'a str,
    payload: &'a [u8],
}

impl<'a> B4ByteMapEntry<'a> {
    #[must_use]
    #[cfg(any(feature = "materializer-replay", feature = "positive-gate", test))]
    pub(crate) const fn new(path: &'a str, payload: &'a [u8]) -> Self {
        Self { path, payload }
    }

    #[must_use]
    pub(crate) const fn path(&self) -> &'a str {
        self.path
    }

    #[must_use]
    pub(crate) const fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

/// Backward-compatible terminal-map entry name.
#[cfg(any(feature = "materializer-replay", test))]
pub(crate) type B4TerminalByteMapEntry<'a> = B4ByteMapEntry<'a>;

/// Borrowed entries from one canonical nested byte map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct B4DecodedByteMap<'a> {
    entries: Vec<B4ByteMapEntry<'a>>,
}

impl<'a> B4DecodedByteMap<'a> {
    #[must_use]
    pub(crate) fn entries(&self) -> &[B4ByteMapEntry<'a>] {
        &self.entries
    }
}

/// Backward-compatible decoded terminal-map name.
pub(crate) type B4DecodedTerminalByteMap<'a> = B4DecodedByteMap<'a>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum B4ByteMapField {
    PathLength,
    Path,
    PayloadLength,
    Payload,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum B4ByteMapPathFailure {
    Empty,
    NonGraphicAscii,
    Backslash,
    Absolute,
    EmptyComponent,
    DotComponent,
    ParentComponent,
    Colon,
    TrailingDot,
}

/// Private framing and contract failures. These are not campaign observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum B4ByteMapError {
    InvalidContract,
    EncodedTooLarge {
        actual: usize,
        maximum: usize,
    },
    TruncatedCount,
    CountNotAllowed {
        actual: usize,
    },
    TruncatedPathLength {
        index: usize,
    },
    PathLengthOutOfBounds {
        index: usize,
        actual: usize,
    },
    LengthArithmeticOverflow {
        index: usize,
        field: B4ByteMapField,
    },
    CumulativeEncodedLimitExceeded {
        index: usize,
        field: B4ByteMapField,
    },
    TruncatedPath {
        index: usize,
    },
    InvalidPath {
        index: usize,
        failure: B4ByteMapPathFailure,
    },
    DuplicatePath {
        index: usize,
    },
    PathOutOfOrder {
        index: usize,
    },
    ExpectedPathMismatch {
        index: usize,
    },
    TruncatedPayloadLength {
        index: usize,
    },
    PayloadLengthOutOfBounds {
        index: usize,
        actual: usize,
        minimum: usize,
        maximum: usize,
    },
    TruncatedPayload {
        index: usize,
    },
    AllocationFailure,
    TrailingBytes,
}

impl fmt::Display for B4ByteMapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContract => formatter.write_str("invalid nested byte-map contract"),
            Self::EncodedTooLarge { actual, maximum } => write!(
                formatter,
                "nested byte map has {actual} bytes, above handler cap {maximum}"
            ),
            Self::TruncatedCount => formatter.write_str("truncated nested byte-map count"),
            Self::CountNotAllowed { actual } => {
                write!(formatter, "nested byte-map count {actual} is not allowed")
            }
            Self::TruncatedPathLength { index } => {
                write!(formatter, "truncated nested byte-map path-{index} length")
            }
            Self::PathLengthOutOfBounds { index, actual } => write!(
                formatter,
                "nested byte-map path-{index} length {actual} is outside 1..={MAX_PATH_BYTES}"
            ),
            Self::LengthArithmeticOverflow { index, field } => write!(
                formatter,
                "nested byte-map entry-{index} {field:?} arithmetic overflows"
            ),
            Self::CumulativeEncodedLimitExceeded { index, field } => write!(
                formatter,
                "nested byte-map entry-{index} {field:?} exceeds the cumulative handler cap"
            ),
            Self::TruncatedPath { index } => {
                write!(formatter, "truncated nested byte-map path-{index}")
            }
            Self::InvalidPath { index, failure } => write!(
                formatter,
                "nested byte-map path-{index} is not a canonical safe relative POSIX path: \
                 {failure:?}"
            ),
            Self::DuplicatePath { index } => {
                write!(
                    formatter,
                    "nested byte-map path-{index} duplicates its predecessor"
                )
            }
            Self::PathOutOfOrder { index } => write!(
                formatter,
                "nested byte-map path-{index} is not in strict unsigned byte order"
            ),
            Self::ExpectedPathMismatch { index } => write!(
                formatter,
                "nested byte-map path-{index} differs from the handler contract"
            ),
            Self::TruncatedPayloadLength { index } => {
                write!(
                    formatter,
                    "truncated nested byte-map payload-{index} length"
                )
            }
            Self::PayloadLengthOutOfBounds {
                index,
                actual,
                minimum,
                maximum,
            } => write!(
                formatter,
                "nested byte-map payload-{index} length {actual} is outside \
                 {minimum}..={maximum}"
            ),
            Self::TruncatedPayload { index } => {
                write!(formatter, "truncated nested byte-map payload-{index}")
            }
            Self::AllocationFailure => {
                formatter.write_str("cannot allocate nested byte-map entry descriptors")
            }
            Self::TrailingBytes => formatter.write_str("trailing nested byte-map bytes"),
        }
    }
}

impl std::error::Error for B4ByteMapError {}

const fn terminal_byte_map_contract(kind: B4TerminalByteMapKind) -> B4ByteMapContract<'static> {
    match kind {
        B4TerminalByteMapKind::RawSeal => B4ByteMapContract::exact(
            &TERMINAL_RAW_PAYLOAD_BOUNDS,
            &TERMINAL_RAW_PATHS,
            terminal_byte_map_maximum_encoded_bytes(kind),
        ),
        B4TerminalByteMapKind::ReceiptOracle => B4ByteMapContract::exact(
            &TERMINAL_ORACLE_PAYLOAD_BOUNDS,
            &TERMINAL_ORACLE_PATHS,
            terminal_byte_map_maximum_encoded_bytes(kind),
        ),
    }
}

/// Encode one map against an already selected exact handler contract.
///
/// The encoder and borrowed decoder share the same contract and framing
/// engine, so a caller cannot emit bytes that its selected handler rejects.
#[cfg(any(feature = "materializer-replay", feature = "positive-gate", test))]
pub(crate) fn encode_byte_map(
    contract: B4ByteMapContract<'_>,
    entries: &[B4ByteMapEntry<'_>],
) -> Result<Vec<u8>, B4ByteMapError> {
    validate_contract(contract)?;
    if entries.len() != contract.shape.entry_count() {
        return Err(B4ByteMapError::CountNotAllowed {
            actual: entries.len(),
        });
    }

    let mut encoded_length = COUNT_BYTES;
    for (index, (entry, bounds)) in entries
        .iter()
        .zip(contract.shape.payload_bounds)
        .enumerate()
    {
        let path_length = entry.path().len();
        if !(1..=MAX_PATH_BYTES).contains(&path_length) {
            return Err(B4ByteMapError::PathLengthOutOfBounds {
                index,
                actual: path_length,
            });
        }
        let payload_length = entry.payload().len();
        if !(bounds.minimum..=bounds.maximum).contains(&payload_length) {
            return Err(B4ByteMapError::PayloadLengthOutOfBounds {
                index,
                actual: payload_length,
                minimum: bounds.minimum,
                maximum: bounds.maximum,
            });
        }
        encoded_length = checked_end(
            encoded_length,
            PATH_LENGTH_BYTES,
            contract.maximum_encoded_bytes,
            index,
            B4ByteMapField::PathLength,
        )?;
        encoded_length = checked_end(
            encoded_length,
            path_length,
            contract.maximum_encoded_bytes,
            index,
            B4ByteMapField::Path,
        )?;
        encoded_length = checked_end(
            encoded_length,
            PAYLOAD_LENGTH_BYTES,
            contract.maximum_encoded_bytes,
            index,
            B4ByteMapField::PayloadLength,
        )?;
        encoded_length = checked_end(
            encoded_length,
            payload_length,
            contract.maximum_encoded_bytes,
            index,
            B4ByteMapField::Payload,
        )?;
    }

    let entry_count =
        u16::try_from(entries.len()).map_err(|_| B4ByteMapError::CountNotAllowed {
            actual: entries.len(),
        })?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(encoded_length)
        .map_err(|_| B4ByteMapError::AllocationFailure)?;
    encoded.extend_from_slice(&entry_count.to_le_bytes());
    for (index, entry) in entries.iter().enumerate() {
        let path_length = u16::try_from(entry.path().len()).map_err(|_| {
            B4ByteMapError::PathLengthOutOfBounds {
                index,
                actual: entry.path().len(),
            }
        })?;
        let payload_length = u32::try_from(entry.payload().len()).map_err(|_| {
            B4ByteMapError::LengthArithmeticOverflow {
                index,
                field: B4ByteMapField::Payload,
            }
        })?;
        encoded.extend_from_slice(&path_length.to_le_bytes());
        encoded.extend_from_slice(entry.path().as_bytes());
        encoded.extend_from_slice(&payload_length.to_le_bytes());
        encoded.extend_from_slice(entry.payload());
    }
    let _decoded = decode_byte_map(&encoded, contract)?;
    Ok(encoded)
}

/// Encode one exact terminal artifact map.
///
/// The caller must supply all nine entries in strict unsigned path-byte order.
/// The same closed contract used by the decoder validates the completed bytes
/// before they are returned.
#[cfg(any(feature = "materializer-replay", test))]
pub(crate) fn encode_terminal_byte_map(
    kind: B4TerminalByteMapKind,
    entries: &[B4TerminalByteMapEntry<'_>],
) -> Result<Vec<u8>, B4ByteMapError> {
    encode_byte_map(terminal_byte_map_contract(kind), entries)
}

/// Decode one exact terminal artifact map while borrowing every payload.
pub(crate) fn decode_terminal_byte_map(
    kind: B4TerminalByteMapKind,
    source: &[u8],
) -> Result<B4DecodedTerminalByteMap<'_>, B4ByteMapError> {
    decode_byte_map(source, terminal_byte_map_contract(kind))
}

/// Decode one nested map against the already selected handler contract.
///
/// Paths and payloads borrow from `source`. Apart from the bounded entry
/// descriptor vector, decoding allocates no payload storage.
pub(crate) fn decode_byte_map<'source>(
    source: &'source [u8],
    contract: B4ByteMapContract<'_>,
) -> Result<B4DecodedByteMap<'source>, B4ByteMapError> {
    validate_contract(contract)?;
    if source.len() > contract.maximum_encoded_bytes {
        return Err(B4ByteMapError::EncodedTooLarge {
            actual: source.len(),
            maximum: contract.maximum_encoded_bytes,
        });
    }
    let count_bytes = source
        .get(..COUNT_BYTES)
        .ok_or(B4ByteMapError::TruncatedCount)?;
    let entry_count = usize::from(u16::from_le_bytes(
        count_bytes
            .try_into()
            .map_err(|_| B4ByteMapError::TruncatedCount)?,
    ));
    let shape = contract.shape;
    if shape.entry_count() != entry_count {
        return Err(B4ByteMapError::CountNotAllowed {
            actual: entry_count,
        });
    }

    let mut cursor = COUNT_BYTES;
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(entry_count)
        .map_err(|_| B4ByteMapError::AllocationFailure)?;
    let mut previous_path: Option<&[u8]> = None;
    for (index, bounds) in shape.payload_bounds.iter().copied().enumerate() {
        let (path, path_end) = decode_path(
            source,
            cursor,
            contract.maximum_encoded_bytes,
            index,
            previous_path,
            shape.expected_paths[index],
        )?;
        let (payload, payload_end) = decode_payload(
            source,
            path_end,
            contract.maximum_encoded_bytes,
            index,
            bounds,
        )?;
        entries.push(B4ByteMapEntry { path, payload });
        previous_path = Some(path.as_bytes());
        cursor = payload_end;
    }
    if cursor != source.len() {
        return Err(B4ByteMapError::TrailingBytes);
    }
    Ok(B4DecodedByteMap { entries })
}

fn decode_path<'source>(
    source: &'source [u8],
    cursor: usize,
    maximum_encoded_bytes: usize,
    index: usize,
    previous_path: Option<&[u8]>,
    expected_path: &str,
) -> Result<(&'source str, usize), B4ByteMapError> {
    let length_end = checked_end(
        cursor,
        PATH_LENGTH_BYTES,
        maximum_encoded_bytes,
        index,
        B4ByteMapField::PathLength,
    )?;
    let length_bytes = source
        .get(cursor..length_end)
        .ok_or(B4ByteMapError::TruncatedPathLength { index })?;
    let length = usize::from(u16::from_le_bytes(
        length_bytes
            .try_into()
            .map_err(|_| B4ByteMapError::TruncatedPathLength { index })?,
    ));
    if !(1..=MAX_PATH_BYTES).contains(&length) {
        return Err(B4ByteMapError::PathLengthOutOfBounds {
            index,
            actual: length,
        });
    }
    let path_end = checked_end(
        length_end,
        length,
        maximum_encoded_bytes,
        index,
        B4ByteMapField::Path,
    )?;
    let path_bytes = source
        .get(length_end..path_end)
        .ok_or(B4ByteMapError::TruncatedPath { index })?;
    validate_path(path_bytes).map_err(|failure| B4ByteMapError::InvalidPath { index, failure })?;
    if let Some(previous) = previous_path {
        match path_bytes.cmp(previous) {
            Ordering::Equal => return Err(B4ByteMapError::DuplicatePath { index }),
            Ordering::Less => return Err(B4ByteMapError::PathOutOfOrder { index }),
            Ordering::Greater => {}
        }
    }
    if path_bytes != expected_path.as_bytes() {
        return Err(B4ByteMapError::ExpectedPathMismatch { index });
    }
    let path = core::str::from_utf8(path_bytes).map_err(|_| B4ByteMapError::InvalidPath {
        index,
        failure: B4ByteMapPathFailure::NonGraphicAscii,
    })?;
    Ok((path, path_end))
}

fn decode_payload(
    source: &[u8],
    cursor: usize,
    maximum_encoded_bytes: usize,
    index: usize,
    bounds: B4ByteMapPayloadBounds,
) -> Result<(&[u8], usize), B4ByteMapError> {
    let length_end = checked_end(
        cursor,
        PAYLOAD_LENGTH_BYTES,
        maximum_encoded_bytes,
        index,
        B4ByteMapField::PayloadLength,
    )?;
    let length_bytes = source
        .get(cursor..length_end)
        .ok_or(B4ByteMapError::TruncatedPayloadLength { index })?;
    let length_u32 = u32::from_le_bytes(
        length_bytes
            .try_into()
            .map_err(|_| B4ByteMapError::TruncatedPayloadLength { index })?,
    );
    let length =
        usize::try_from(length_u32).map_err(|_| B4ByteMapError::LengthArithmeticOverflow {
            index,
            field: B4ByteMapField::Payload,
        })?;
    if !(bounds.minimum..=bounds.maximum).contains(&length) {
        return Err(B4ByteMapError::PayloadLengthOutOfBounds {
            index,
            actual: length,
            minimum: bounds.minimum,
            maximum: bounds.maximum,
        });
    }
    let payload_end = checked_end(
        length_end,
        length,
        maximum_encoded_bytes,
        index,
        B4ByteMapField::Payload,
    )?;
    let payload = source
        .get(length_end..payload_end)
        .ok_or(B4ByteMapError::TruncatedPayload { index })?;
    Ok((payload, payload_end))
}

fn checked_end(
    cursor: usize,
    length: usize,
    maximum_encoded_bytes: usize,
    index: usize,
    field: B4ByteMapField,
) -> Result<usize, B4ByteMapError> {
    let end = cursor
        .checked_add(length)
        .ok_or(B4ByteMapError::LengthArithmeticOverflow { index, field })?;
    if end > maximum_encoded_bytes {
        return Err(B4ByteMapError::CumulativeEncodedLimitExceeded { index, field });
    }
    Ok(end)
}

fn validate_contract(contract: B4ByteMapContract<'_>) -> Result<(), B4ByteMapError> {
    if !(COUNT_BYTES..=MAX_ENCODED_BYTES).contains(&contract.maximum_encoded_bytes) {
        return Err(B4ByteMapError::InvalidContract);
    }
    validate_shape(contract.shape, contract.maximum_encoded_bytes)
}

fn validate_shape(
    shape: B4ByteMapShapeContract<'_>,
    maximum_encoded_bytes: usize,
) -> Result<(), B4ByteMapError> {
    if shape.entry_count() > usize::from(u16::MAX) {
        return Err(B4ByteMapError::InvalidContract);
    }
    if shape.expected_paths.len() != shape.entry_count() {
        return Err(B4ByteMapError::InvalidContract);
    }
    let mut previous: Option<&[u8]> = None;
    for path in shape.expected_paths {
        let bytes = path.as_bytes();
        if bytes.len() > MAX_PATH_BYTES || validate_path(bytes).is_err() {
            return Err(B4ByteMapError::InvalidContract);
        }
        if previous.is_some_and(|prior| bytes <= prior) {
            return Err(B4ByteMapError::InvalidContract);
        }
        previous = Some(bytes);
    }

    let mut minimum_encoded_bytes = COUNT_BYTES as u128;
    let mut maximum_possible_bytes = COUNT_BYTES as u128;
    for (index, bounds) in shape.payload_bounds.iter().copied().enumerate() {
        if bounds.minimum > bounds.maximum || bounds.maximum > u32::MAX as usize {
            return Err(B4ByteMapError::InvalidContract);
        }
        let fixed_overhead =
            (PATH_LENGTH_BYTES + shape.expected_paths[index].len() + PAYLOAD_LENGTH_BYTES) as u128;
        minimum_encoded_bytes = minimum_encoded_bytes
            .checked_add(fixed_overhead)
            .and_then(|total| total.checked_add(bounds.minimum as u128))
            .ok_or(B4ByteMapError::InvalidContract)?;
        maximum_possible_bytes = maximum_possible_bytes
            .checked_add(fixed_overhead)
            .and_then(|total| total.checked_add(bounds.maximum as u128))
            .ok_or(B4ByteMapError::InvalidContract)?;
    }
    let maximum_encoded_bytes = maximum_encoded_bytes as u128;
    if maximum_encoded_bytes < minimum_encoded_bytes
        || maximum_encoded_bytes > maximum_possible_bytes
    {
        return Err(B4ByteMapError::InvalidContract);
    }
    Ok(())
}

fn validate_path(path: &[u8]) -> Result<(), B4ByteMapPathFailure> {
    if path.is_empty() {
        return Err(B4ByteMapPathFailure::Empty);
    }
    if !path.iter().all(u8::is_ascii_graphic) {
        return Err(B4ByteMapPathFailure::NonGraphicAscii);
    }
    if path.contains(&b'\\') {
        return Err(B4ByteMapPathFailure::Backslash);
    }
    if path[0] == b'/' {
        return Err(B4ByteMapPathFailure::Absolute);
    }
    if path.contains(&b':') {
        return Err(B4ByteMapPathFailure::Colon);
    }
    for component in path.split(|byte| *byte == b'/') {
        match component {
            b"" => return Err(B4ByteMapPathFailure::EmptyComponent),
            b"." => return Err(B4ByteMapPathFailure::DotComponent),
            b".." => return Err(B4ByteMapPathFailure::ParentComponent),
            _ if component.ends_with(b".") => {
                return Err(B4ByteMapPathFailure::TrailingDot);
            }
            _ => {}
        }
    }
    Ok(())
}

// Keep the staged crate-private producer API type-checked before its first
// materializer consumer lands. This has no runtime or public API surface.
#[cfg(feature = "materializer-replay")]
const _: () = {
    let _ = B4TerminalByteMapKind::RawSeal;
    let _ = B4TerminalByteMapKind::ReceiptOracle;
    let _ = terminal_byte_map_paths;
    let _ = B4TerminalByteMapEntry::new;
    let _ = B4DecodedTerminalByteMap::entries;
    let _ = encode_terminal_byte_map;
    let _ = decode_terminal_byte_map;
};

// Keep the staged validator-facing terminal decoder type-checked in the
// isolated negative-materialization feature before the remaining consumers
// land. This has no runtime or public API surface.
#[cfg(feature = "negative-materialization-set")]
const _: () = {
    let _ = B4TerminalByteMapKind::RawSeal;
    let _ = B4TerminalByteMapKind::ReceiptOracle;
    let _ = terminal_byte_map_maximum_encoded_bytes;
    let _ = B4DecodedTerminalByteMap::entries;
    let _ = decode_terminal_byte_map;
};

#[cfg(test)]
mod tests {
    use super::*;

    const ONE_TO_TWO: B4ByteMapPayloadBounds = B4ByteMapPayloadBounds::new(1, 2);
    const ZERO_TO_FOUR: B4ByteMapPayloadBounds = B4ByteMapPayloadBounds::new(0, 4);
    const ONE_ENTRY_BOUNDS: [B4ByteMapPayloadBounds; 1] = [ONE_TO_TWO];
    const ONE_ENTRY_WIDE_BOUNDS: [B4ByteMapPayloadBounds; 1] = [B4ByteMapPayloadBounds::new(1, 8)];
    const TWO_ENTRY_BOUNDS: [B4ByteMapPayloadBounds; 2] = [ZERO_TO_FOUR, ONE_TO_TWO];
    const TWO_AUX_BOUNDS: [B4ByteMapPayloadBounds; 2] = [ZERO_TO_FOUR; 2];
    const FOUR_AUX_BOUNDS: [B4ByteMapPayloadBounds; 4] = [ZERO_TO_FOUR; 4];
    const ONE_PATH: [&str; 1] = ["a.bin"];
    const TWO_PATHS: [&str; 2] = ["a.bin", "nested/b.bin"];
    fn exact_contract(
        bounds: &'static [B4ByteMapPayloadBounds],
        expected_paths: &'static [&'static str],
        cap: usize,
    ) -> B4ByteMapContract<'static> {
        B4ByteMapContract::exact(bounds, expected_paths, cap)
    }

    fn maximum_cap(bounds: &[B4ByteMapPayloadBounds], expected_paths: &[&str]) -> usize {
        COUNT_BYTES
            + bounds
                .iter()
                .zip(expected_paths)
                .map(|(bound, path)| {
                    PATH_LENGTH_BYTES + path.len() + PAYLOAD_LENGTH_BYTES + bound.maximum
                })
                .sum::<usize>()
    }

    fn encode(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&u16::try_from(entries.len()).unwrap().to_le_bytes());
        for (path, payload) in entries {
            encoded.extend_from_slice(&u16::try_from(path.len()).unwrap().to_le_bytes());
            encoded.extend_from_slice(path);
            encoded.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
            encoded.extend_from_slice(payload);
        }
        encoded
    }

    fn terminal_payloads(kind: B4TerminalByteMapKind) -> Vec<Vec<u8>> {
        let payload_length = match kind {
            B4TerminalByteMapKind::RawSeal => crate::constants::PROOF_BYTES,
            B4TerminalByteMapKind::ReceiptOracle => 1,
        };
        (0..B4_TERMINAL_BYTE_MAP_ENTRY_COUNT)
            .map(|index| vec![u8::try_from(index).unwrap(); payload_length])
            .collect()
    }

    fn terminal_entries(
        kind: B4TerminalByteMapKind,
        payloads: &[Vec<u8>],
    ) -> Vec<B4TerminalByteMapEntry<'_>> {
        terminal_byte_map_paths(kind)
            .iter()
            .zip(payloads)
            .map(|(path, payload)| B4TerminalByteMapEntry::new(path, payload))
            .collect()
    }

    #[test]
    fn terminal_wire_paths_use_the_exact_unsigned_byte_order() {
        assert_eq!(
            B4_TERMINAL_WIRE_FIXTURE_IDS,
            [
                "allowed-terminal-non-ok",
                "join-povw",
                "join-unwrap-povw",
                "lift-po2-14",
                "lift-povw-po2-18",
                "resolve-povw",
                "resolve-unwrap-povw",
                "union",
                "unwrap-povw",
            ]
        );
        for kind in [
            B4TerminalByteMapKind::RawSeal,
            B4TerminalByteMapKind::ReceiptOracle,
        ] {
            let paths = terminal_byte_map_paths(kind);
            let suffix = match kind {
                B4TerminalByteMapKind::RawSeal => ".raw-seal.bin",
                B4TerminalByteMapKind::ReceiptOracle => ".receipt-oracle.bincode",
            };
            assert_eq!(paths.len(), B4_TERMINAL_BYTE_MAP_ENTRY_COUNT);
            for (path, fixture_id) in paths.iter().zip(B4_TERMINAL_WIRE_FIXTURE_IDS) {
                assert_eq!(
                    *path,
                    format!(
                        "{}/{fixture_id}{suffix}",
                        crate::b4_terminal::B4_TERMINAL_FIXTURE_DIRECTORY
                    )
                );
            }
            assert!(
                paths
                    .windows(2)
                    .all(|pair| pair[0].as_bytes() < pair[1].as_bytes())
            );
        }
        assert_eq!(
            TERMINAL_RAW_MAP_MAX_BYTES,
            exact_byte_map_maximum_encoded_bytes(&TERMINAL_RAW_PATHS, PROOF_BYTES)
        );
        assert_eq!(TERMINAL_RAW_MAP_MAX_BYTES, 2_004_856);
        assert_eq!(
            TERMINAL_ORACLE_MAP_MAX_BYTES,
            exact_byte_map_maximum_encoded_bytes(&TERMINAL_ORACLE_PATHS, RECEIPT_ORACLE_MAX_BYTES,)
        );
        assert_eq!(TERMINAL_ORACLE_MAP_MAX_BYTES, 9_438_118);
    }

    #[test]
    fn terminal_wire_order_does_not_relabel_semantic_fixture_zero() {
        assert_eq!(
            crate::b4_terminal::B4_TERMINAL_FIXTURE_LAYOUT[0].fixture_id,
            "lift-po2-14"
        );
        assert_eq!(B4_TERMINAL_WIRE_FIXTURE_IDS[3], "lift-po2-14");
        assert_ne!(
            crate::b4_terminal::B4_TERMINAL_FIXTURE_LAYOUT[0].fixture_id,
            B4_TERMINAL_WIRE_FIXTURE_IDS[0]
        );
    }

    #[test]
    fn terminal_exact_encoder_decoder_round_trip_preserves_borrowed_entries() {
        for kind in [
            B4TerminalByteMapKind::RawSeal,
            B4TerminalByteMapKind::ReceiptOracle,
        ] {
            let payloads = terminal_payloads(kind);
            let entries = terminal_entries(kind, &payloads);
            let encoded = encode_terminal_byte_map(kind, &entries).unwrap();
            let decoded = decode_terminal_byte_map(kind, &encoded).unwrap();
            assert_eq!(decoded.entries(), entries);

            let source_start = encoded.as_ptr() as usize;
            let source_end = source_start + encoded.len();
            for entry in decoded.entries() {
                let payload_start = entry.payload().as_ptr() as usize;
                assert!((source_start..source_end).contains(&payload_start));
            }
            assert_eq!(
                encode_terminal_byte_map(kind, decoded.entries()).unwrap(),
                encoded
            );
        }
    }

    #[test]
    fn terminal_encoder_rejects_a_missing_entry() {
        let payloads = terminal_payloads(B4TerminalByteMapKind::ReceiptOracle);
        let mut entries = terminal_entries(B4TerminalByteMapKind::ReceiptOracle, &payloads);
        entries.pop();
        assert_eq!(
            encode_terminal_byte_map(B4TerminalByteMapKind::ReceiptOracle, &entries),
            Err(B4ByteMapError::CountNotAllowed { actual: 8 })
        );
    }

    #[test]
    fn terminal_encoder_rejects_an_extra_entry() {
        let payloads = terminal_payloads(B4TerminalByteMapKind::ReceiptOracle);
        let mut entries = terminal_entries(B4TerminalByteMapKind::ReceiptOracle, &payloads);
        entries.push(B4TerminalByteMapEntry::new("zz-extra.bin", b"x"));
        assert_eq!(
            encode_terminal_byte_map(B4TerminalByteMapKind::ReceiptOracle, &entries),
            Err(B4ByteMapError::CountNotAllowed { actual: 10 })
        );
    }

    #[test]
    fn terminal_encoder_rejects_reordered_entries() {
        let payloads = terminal_payloads(B4TerminalByteMapKind::ReceiptOracle);
        let mut entries = terminal_entries(B4TerminalByteMapKind::ReceiptOracle, &payloads);
        entries.swap(0, 1);
        assert_eq!(
            encode_terminal_byte_map(B4TerminalByteMapKind::ReceiptOracle, &entries),
            Err(B4ByteMapError::ExpectedPathMismatch { index: 0 })
        );
    }

    #[test]
    fn terminal_encoder_rejects_duplicate_entries() {
        let payloads = terminal_payloads(B4TerminalByteMapKind::ReceiptOracle);
        let mut entries = terminal_entries(B4TerminalByteMapKind::ReceiptOracle, &payloads);
        entries[1] = entries[0];
        assert_eq!(
            encode_terminal_byte_map(B4TerminalByteMapKind::ReceiptOracle, &entries),
            Err(B4ByteMapError::DuplicatePath { index: 1 })
        );
    }

    #[test]
    fn terminal_encoder_rejects_wrong_payload_lengths() {
        let mut raw_payloads = terminal_payloads(B4TerminalByteMapKind::RawSeal);
        raw_payloads[4].pop();
        let raw_entries = terminal_entries(B4TerminalByteMapKind::RawSeal, &raw_payloads);
        assert!(matches!(
            encode_terminal_byte_map(B4TerminalByteMapKind::RawSeal, &raw_entries),
            Err(B4ByteMapError::PayloadLengthOutOfBounds { index: 4, .. })
        ));

        let mut oracle_payloads = terminal_payloads(B4TerminalByteMapKind::ReceiptOracle);
        oracle_payloads[6].clear();
        let oracle_entries =
            terminal_entries(B4TerminalByteMapKind::ReceiptOracle, &oracle_payloads);
        assert!(matches!(
            encode_terminal_byte_map(B4TerminalByteMapKind::ReceiptOracle, &oracle_entries),
            Err(B4ByteMapError::PayloadLengthOutOfBounds { index: 6, .. })
        ));
    }

    #[test]
    fn terminal_decoder_rejects_missing_extra_reordered_duplicate_and_wrong_length_maps() {
        let paths = terminal_byte_map_paths(B4TerminalByteMapKind::ReceiptOracle);
        let payloads = terminal_payloads(B4TerminalByteMapKind::ReceiptOracle);
        let borrowed = payloads.iter().map(Vec::as_slice).collect::<Vec<_>>();

        let missing = paths[..8]
            .iter()
            .zip(&borrowed[..8])
            .map(|(path, payload)| (path.as_bytes(), *payload))
            .collect::<Vec<_>>();
        assert_eq!(
            decode_terminal_byte_map(B4TerminalByteMapKind::ReceiptOracle, &encode(&missing)),
            Err(B4ByteMapError::CountNotAllowed { actual: 8 })
        );

        let mut extra = paths
            .iter()
            .zip(&borrowed)
            .map(|(path, payload)| (path.as_bytes(), *payload))
            .collect::<Vec<_>>();
        extra.push((b"zz-extra.bin", b"x"));
        assert_eq!(
            decode_terminal_byte_map(B4TerminalByteMapKind::ReceiptOracle, &encode(&extra)),
            Err(B4ByteMapError::CountNotAllowed { actual: 10 })
        );

        let mut reordered = paths
            .iter()
            .zip(&borrowed)
            .map(|(path, payload)| (path.as_bytes(), *payload))
            .collect::<Vec<_>>();
        reordered.swap(0, 1);
        assert_eq!(
            decode_terminal_byte_map(B4TerminalByteMapKind::ReceiptOracle, &encode(&reordered)),
            Err(B4ByteMapError::ExpectedPathMismatch { index: 0 })
        );

        let mut duplicate = paths
            .iter()
            .zip(&borrowed)
            .map(|(path, payload)| (path.as_bytes(), *payload))
            .collect::<Vec<_>>();
        duplicate[1] = duplicate[0];
        assert_eq!(
            decode_terminal_byte_map(B4TerminalByteMapKind::ReceiptOracle, &encode(&duplicate)),
            Err(B4ByteMapError::DuplicatePath { index: 1 })
        );

        let mut wrong_length_payloads = terminal_payloads(B4TerminalByteMapKind::RawSeal);
        wrong_length_payloads[8].pop();
        let wrong_length = terminal_byte_map_paths(B4TerminalByteMapKind::RawSeal)
            .iter()
            .zip(&wrong_length_payloads)
            .map(|(path, payload)| (path.as_bytes(), payload.as_slice()))
            .collect::<Vec<_>>();
        assert!(matches!(
            decode_terminal_byte_map(B4TerminalByteMapKind::RawSeal, &encode(&wrong_length)),
            Err(B4ByteMapError::PayloadLengthOutOfBounds { index: 8, .. })
        ));
    }

    #[test]
    fn terminal_decoder_rejects_every_strict_prefix_and_trailing_byte() {
        let payloads = terminal_payloads(B4TerminalByteMapKind::ReceiptOracle);
        let entries = terminal_entries(B4TerminalByteMapKind::ReceiptOracle, &payloads);
        let encoded =
            encode_terminal_byte_map(B4TerminalByteMapKind::ReceiptOracle, &entries).unwrap();
        for cut in 0..encoded.len() {
            assert!(
                decode_terminal_byte_map(B4TerminalByteMapKind::ReceiptOracle, &encoded[..cut])
                    .is_err(),
                "strict prefix {cut} accepted"
            );
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_terminal_byte_map(B4TerminalByteMapKind::ReceiptOracle, &trailing),
            Err(B4ByteMapError::TrailingBytes)
        );
    }

    #[test]
    fn exact_layout_round_trip_and_borrowing_are_preserved() {
        let source = encode(&[(b"a.bin", b""), (b"nested/b.bin", b"xy")]);
        let contract = exact_contract(
            &TWO_ENTRY_BOUNDS,
            &TWO_PATHS,
            maximum_cap(&TWO_ENTRY_BOUNDS, &TWO_PATHS),
        );
        let entries = [
            B4ByteMapEntry::new("a.bin", b""),
            B4ByteMapEntry::new("nested/b.bin", b"xy"),
        ];
        assert_eq!(encode_byte_map(contract, &entries).unwrap(), source);

        let mut expected = vec![2, 0, 5, 0];
        expected.extend_from_slice(b"a.bin");
        expected.extend_from_slice(&[0, 0, 0, 0]);
        expected.extend_from_slice(&[12, 0]);
        expected.extend_from_slice(b"nested/b.bin");
        expected.extend_from_slice(&[2, 0, 0, 0]);
        expected.extend_from_slice(b"xy");
        assert_eq!(source, expected);

        let decoded = decode_byte_map(&source, contract).unwrap();
        assert_eq!(decoded.entries().len(), 2);
        assert_eq!(decoded.entries()[0].path(), "a.bin");
        assert_eq!(decoded.entries()[0].payload(), b"");
        assert_eq!(decoded.entries()[1].path(), "nested/b.bin");
        assert_eq!(decoded.entries()[1].payload(), b"xy");
        assert_eq!(
            decoded.entries()[0].path().as_ptr(),
            source[COUNT_BYTES + PATH_LENGTH_BYTES..].as_ptr()
        );
        let second_payload_offset = COUNT_BYTES + 2 + 5 + 4 + 2 + 12 + 4;
        assert_eq!(
            decoded.entries()[1].payload().as_ptr(),
            source[second_payload_offset..].as_ptr()
        );
    }

    #[test]
    fn every_strict_prefix_is_rejected() {
        let source = encode(&[(b"a.bin", b"x"), (b"nested/b.bin", b"y")]);
        let contract = exact_contract(
            &TWO_ENTRY_BOUNDS,
            &TWO_PATHS,
            maximum_cap(&TWO_ENTRY_BOUNDS, &TWO_PATHS),
        );
        assert!(decode_byte_map(&source, contract).is_ok());
        for cut in 0..source.len() {
            assert!(
                decode_byte_map(&source[..cut], contract).is_err(),
                "strict prefix ending at byte {cut} was accepted"
            );
        }
    }

    #[test]
    fn every_integer_field_truncation_is_typed() {
        let contract = exact_contract(
            &ONE_ENTRY_BOUNDS,
            &ONE_PATH,
            maximum_cap(&ONE_ENTRY_BOUNDS, &ONE_PATH),
        );
        assert_eq!(
            decode_byte_map(&[], contract),
            Err(B4ByteMapError::TruncatedCount)
        );
        assert_eq!(
            decode_byte_map(&[1], contract),
            Err(B4ByteMapError::TruncatedCount)
        );

        for source in [&[1, 0][..], &[1, 0, 5][..]] {
            assert_eq!(
                decode_byte_map(source, contract),
                Err(B4ByteMapError::TruncatedPathLength { index: 0 })
            );
        }

        let payload_length_offset = COUNT_BYTES + PATH_LENGTH_BYTES + ONE_PATH[0].len();
        let source = encode(&[(ONE_PATH[0].as_bytes(), b"x")]);
        for supplied in 0..PAYLOAD_LENGTH_BYTES {
            assert_eq!(
                decode_byte_map(&source[..payload_length_offset + supplied], contract),
                Err(B4ByteMapError::TruncatedPayloadLength { index: 0 }),
                "payload-length prefix of {supplied} bytes"
            );
        }
    }

    #[test]
    fn path_and_payload_body_truncations_are_typed() {
        let contract = exact_contract(
            &ONE_ENTRY_BOUNDS,
            &ONE_PATH,
            maximum_cap(&ONE_ENTRY_BOUNDS, &ONE_PATH),
        );
        let source = encode(&[(ONE_PATH[0].as_bytes(), b"x")]);
        let path_end = COUNT_BYTES + PATH_LENGTH_BYTES + ONE_PATH[0].len();
        assert_eq!(
            decode_byte_map(&source[..path_end - 1], contract),
            Err(B4ByteMapError::TruncatedPath { index: 0 })
        );
        assert_eq!(
            decode_byte_map(&source[..source.len() - 1], contract),
            Err(B4ByteMapError::TruncatedPayload { index: 0 })
        );
    }

    #[test]
    fn ancestry_family_owns_its_exact_count_and_path_sequence() {
        let terminal_join_paths =
            crate::b4_recursive_auxiliary_paths::compiled_positive_auxiliary_artifact_paths(8)
                .unwrap();
        let terminal_resolve_paths =
            crate::b4_recursive_auxiliary_paths::compiled_positive_auxiliary_artifact_paths(9)
                .unwrap();
        let resolve_then_join_paths =
            crate::b4_recursive_auxiliary_paths::compiled_positive_auxiliary_artifact_paths(10)
                .unwrap();
        let terminal_join = exact_contract(
            &TWO_AUX_BOUNDS,
            terminal_join_paths,
            maximum_cap(&TWO_AUX_BOUNDS, terminal_join_paths),
        );
        let terminal_resolve = exact_contract(
            &TWO_AUX_BOUNDS,
            terminal_resolve_paths,
            maximum_cap(&TWO_AUX_BOUNDS, terminal_resolve_paths),
        );
        let resolve_then_join = exact_contract(
            &FOUR_AUX_BOUNDS,
            resolve_then_join_paths,
            maximum_cap(&FOUR_AUX_BOUNDS, resolve_then_join_paths),
        );
        let join_bytes = encode(&[
            (terminal_join_paths[0].as_bytes(), b""),
            (terminal_join_paths[1].as_bytes(), b"x"),
        ]);
        let resolve_bytes = encode(&[
            (terminal_resolve_paths[0].as_bytes(), b""),
            (terminal_resolve_paths[1].as_bytes(), b"x"),
        ]);
        let resolve_then_join_bytes = encode(&[
            (resolve_then_join_paths[0].as_bytes(), b""),
            (resolve_then_join_paths[1].as_bytes(), b"x"),
            (resolve_then_join_paths[2].as_bytes(), b""),
            (resolve_then_join_paths[3].as_bytes(), b"x"),
        ]);
        assert!(decode_byte_map(&join_bytes, terminal_join).is_ok());
        assert!(decode_byte_map(&resolve_bytes, terminal_resolve).is_ok());
        assert!(decode_byte_map(&resolve_then_join_bytes, resolve_then_join).is_ok());

        assert_eq!(
            decode_byte_map(&join_bytes, terminal_resolve),
            Err(B4ByteMapError::ExpectedPathMismatch { index: 0 })
        );

        let three = encode(&[
            (resolve_then_join_paths[0].as_bytes(), b""),
            (resolve_then_join_paths[1].as_bytes(), b"x"),
            (resolve_then_join_paths[2].as_bytes(), b""),
        ]);
        assert_eq!(
            decode_byte_map(&three, resolve_then_join),
            Err(B4ByteMapError::CountNotAllowed { actual: 3 })
        );

        let unsigned_high_count = [0, 0x80];
        assert_eq!(
            decode_byte_map(&unsigned_high_count, terminal_join),
            Err(B4ByteMapError::CountNotAllowed { actual: 32_768 })
        );
    }

    #[test]
    fn paths_must_be_strictly_sorted_and_unique() {
        let contract = exact_contract(
            &TWO_ENTRY_BOUNDS,
            &TWO_PATHS,
            maximum_cap(&TWO_ENTRY_BOUNDS, &TWO_PATHS),
        );
        let unsorted = encode(&[(b"a.bin", b""), (b"A.bin", b"x")]);
        assert_eq!(
            decode_byte_map(&unsorted, contract),
            Err(B4ByteMapError::PathOutOfOrder { index: 1 })
        );

        let duplicate = encode(&[(b"a.bin", b""), (b"a.bin", b"x")]);
        assert_eq!(
            decode_byte_map(&duplicate, contract),
            Err(B4ByteMapError::DuplicatePath { index: 1 })
        );
    }

    #[test]
    fn unsafe_or_noncanonical_paths_are_rejected() {
        let contract = exact_contract(
            &ONE_ENTRY_BOUNDS,
            &ONE_PATH,
            maximum_cap(&ONE_ENTRY_BOUNDS, &ONE_PATH),
        );
        let cases: &[(&[u8], B4ByteMapPathFailure)] = &[
            (b"", B4ByteMapPathFailure::Empty),
            (b"a b", B4ByteMapPathFailure::NonGraphicAscii),
            (b"a\tb", B4ByteMapPathFailure::NonGraphicAscii),
            (b"a\x7fb", B4ByteMapPathFailure::NonGraphicAscii),
            (b"a\\b", B4ByteMapPathFailure::Backslash),
            (b"/root", B4ByteMapPathFailure::Absolute),
            (b"a//b", B4ByteMapPathFailure::EmptyComponent),
            (b"a/", B4ByteMapPathFailure::EmptyComponent),
            (b"./a", B4ByteMapPathFailure::DotComponent),
            (b"a/./b", B4ByteMapPathFailure::DotComponent),
            (b"../a", B4ByteMapPathFailure::ParentComponent),
            (b"a/../b", B4ByteMapPathFailure::ParentComponent),
            (b"C:", B4ByteMapPathFailure::Colon),
            (b"a:b", B4ByteMapPathFailure::Colon),
            (b"a.", B4ByteMapPathFailure::TrailingDot),
        ];
        for (path, failure) in cases {
            let source = encode(&[(path, b"x")]);
            let expected = if path.is_empty() {
                B4ByteMapError::PathLengthOutOfBounds {
                    index: 0,
                    actual: 0,
                }
            } else {
                B4ByteMapError::InvalidPath {
                    index: 0,
                    failure: *failure,
                }
            };
            assert_eq!(
                decode_byte_map(&source, contract),
                Err(expected),
                "unsafe path {:?}",
                String::from_utf8_lossy(path)
            );
        }

        let source = [1, 0, 1, 2];
        assert_eq!(
            decode_byte_map(&source, contract),
            Err(B4ByteMapError::PathLengthOutOfBounds {
                index: 0,
                actual: MAX_PATH_BYTES + 1
            })
        );

        let unsigned_high_path_length = [1, 0, 0, 0x80];
        assert_eq!(
            decode_byte_map(&unsigned_high_path_length, contract),
            Err(B4ByteMapError::PathLengthOutOfBounds {
                index: 0,
                actual: 32_768
            })
        );
    }

    #[test]
    fn payload_minimum_maximum_and_unsigned_length_are_enforced() {
        let contract = exact_contract(
            &ONE_ENTRY_BOUNDS,
            &ONE_PATH,
            maximum_cap(&ONE_ENTRY_BOUNDS, &ONE_PATH),
        );
        for valid in [&b"x"[..], &b"xy"[..]] {
            assert!(decode_byte_map(&encode(&[(b"a.bin", valid)]), contract).is_ok());
        }
        assert_eq!(
            decode_byte_map(&encode(&[(b"a.bin", b"")]), contract),
            Err(B4ByteMapError::PayloadLengthOutOfBounds {
                index: 0,
                actual: 0,
                minimum: 1,
                maximum: 2
            })
        );

        let offset = COUNT_BYTES + PATH_LENGTH_BYTES + ONE_PATH[0].len();
        let mut above_maximum = encode(&[(b"a.bin", b"x")]);
        above_maximum[offset..offset + PAYLOAD_LENGTH_BYTES].copy_from_slice(&3_u32.to_le_bytes());
        assert_eq!(
            decode_byte_map(&above_maximum, contract),
            Err(B4ByteMapError::PayloadLengthOutOfBounds {
                index: 0,
                actual: 3,
                minimum: 1,
                maximum: 2
            })
        );

        let mut unsigned_high = encode(&[(b"a.bin", b"x")]);
        unsigned_high[offset..offset + PAYLOAD_LENGTH_BYTES]
            .copy_from_slice(&0x8000_0000_u32.to_le_bytes());
        assert_eq!(
            decode_byte_map(&unsigned_high, contract),
            Err(B4ByteMapError::PayloadLengthOutOfBounds {
                index: 0,
                actual: 2_147_483_648,
                minimum: 1,
                maximum: 2
            })
        );
    }

    #[test]
    fn arithmetic_cap_and_exact_eof_fail_closed() {
        assert_eq!(
            checked_end(usize::MAX, 1, usize::MAX, 7, B4ByteMapField::Payload),
            Err(B4ByteMapError::LengthArithmeticOverflow {
                index: 7,
                field: B4ByteMapField::Payload
            })
        );

        let source = encode(&[(b"a.bin", b"x")]);
        let mut above_cap = source.clone();
        above_cap.push(0);
        let exact_cap = exact_contract(&ONE_ENTRY_BOUNDS, &ONE_PATH, source.len());
        assert_eq!(
            decode_byte_map(&above_cap, exact_cap),
            Err(B4ByteMapError::EncodedTooLarge {
                actual: above_cap.len(),
                maximum: source.len()
            })
        );

        let declared_over_cap = {
            let mut value = encode(&[(b"a.bin", b"x")]);
            let offset = COUNT_BYTES + PATH_LENGTH_BYTES + ONE_PATH[0].len();
            value[offset..offset + PAYLOAD_LENGTH_BYTES].copy_from_slice(&2_u32.to_le_bytes());
            value
        };
        assert_eq!(
            decode_byte_map(
                &declared_over_cap,
                exact_contract(&ONE_ENTRY_WIDE_BOUNDS, &ONE_PATH, declared_over_cap.len())
            ),
            Err(B4ByteMapError::CumulativeEncodedLimitExceeded {
                index: 0,
                field: B4ByteMapField::Payload
            })
        );

        let mut trailing = source;
        trailing.push(0);
        assert_eq!(
            decode_byte_map(
                &trailing,
                exact_contract(
                    &ONE_ENTRY_BOUNDS,
                    &ONE_PATH,
                    maximum_cap(&ONE_ENTRY_BOUNDS, &ONE_PATH),
                )
            ),
            Err(B4ByteMapError::TrailingBytes)
        );
    }

    #[test]
    fn supplied_expected_paths_are_exact() {
        let source = encode(&[(b"b.bin", b"x")]);
        assert_eq!(
            decode_byte_map(
                &source,
                exact_contract(
                    &ONE_ENTRY_BOUNDS,
                    &ONE_PATH,
                    maximum_cap(&ONE_ENTRY_BOUNDS, &ONE_PATH),
                )
            ),
            Err(B4ByteMapError::ExpectedPathMismatch { index: 0 })
        );
    }

    #[test]
    fn malformed_handler_contracts_are_rejected_before_decoding() {
        const REVERSED: [B4ByteMapPayloadBounds; 1] = [B4ByteMapPayloadBounds::new(2, 1)];
        const WRONG_PATH_COUNT: [&str; 2] = ["a", "b"];
        const UNSORTED_PATHS: [&str; 2] = ["b", "a"];
        const DUPLICATE_PATHS: [&str; 2] = ["a", "a"];
        const COLON_PATH: [&str; 1] = ["a:b"];
        const TRAILING_DOT_PATH: [&str; 1] = ["a."];
        const EXPECTED_UNSORTED: B4ByteMapShapeContract<'static> =
            B4ByteMapShapeContract::new(&TWO_ENTRY_BOUNDS, &UNSORTED_PATHS);
        const EXPECTED_DUPLICATE: B4ByteMapShapeContract<'static> =
            B4ByteMapShapeContract::new(&TWO_ENTRY_BOUNDS, &DUPLICATE_PATHS);
        let invalid = [
            exact_contract(&REVERSED, &ONE_PATH, maximum_cap(&REVERSED, &ONE_PATH)),
            exact_contract(
                &ONE_ENTRY_BOUNDS,
                &WRONG_PATH_COUNT,
                maximum_cap(&ONE_ENTRY_BOUNDS, &ONE_PATH),
            ),
            B4ByteMapContract::exact(
                EXPECTED_UNSORTED.payload_bounds,
                EXPECTED_UNSORTED.expected_paths,
                maximum_cap(&TWO_ENTRY_BOUNDS, &UNSORTED_PATHS),
            ),
            B4ByteMapContract::exact(
                EXPECTED_DUPLICATE.payload_bounds,
                EXPECTED_DUPLICATE.expected_paths,
                maximum_cap(&TWO_ENTRY_BOUNDS, &DUPLICATE_PATHS),
            ),
            exact_contract(
                &ONE_ENTRY_BOUNDS,
                &COLON_PATH,
                maximum_cap(&ONE_ENTRY_BOUNDS, &COLON_PATH),
            ),
            exact_contract(
                &ONE_ENTRY_BOUNDS,
                &TRAILING_DOT_PATH,
                maximum_cap(&ONE_ENTRY_BOUNDS, &TRAILING_DOT_PATH),
            ),
            exact_contract(&ONE_ENTRY_BOUNDS, &ONE_PATH, COUNT_BYTES),
            exact_contract(
                &ONE_ENTRY_BOUNDS,
                &ONE_PATH,
                maximum_cap(&ONE_ENTRY_BOUNDS, &ONE_PATH) + 1,
            ),
            exact_contract(&ONE_ENTRY_BOUNDS, &ONE_PATH, MAX_ENCODED_BYTES + 1),
        ];
        for contract in invalid {
            assert_eq!(
                decode_byte_map(b"", contract),
                Err(B4ByteMapError::InvalidContract)
            );
        }
    }
}
