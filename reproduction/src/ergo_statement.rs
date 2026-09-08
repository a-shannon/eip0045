// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Strict pure codec for the initial profile's `ErgoStatementV1` bytes.
//!
//! Parsing establishes only the byte grammar and exposes the bound fields. It
//! does not establish that a receipt is valid or that the statement completely
//! authorizes an application transaction.

use anyhow::{Context as _, Result, ensure};
#[cfg(any(feature = "positive-gate", test))]
use sha2::{Digest as _, Sha256};

use crate::constants::{
    DIGEST_BYTES, ERGO_STATEMENT_DOMAIN, MAX_APPLICATION_PAYLOAD_BYTES, MAX_STATEMENT_BYTES,
    STATEMENT_PREFIX_BYTES,
};

const STATEMENT_VERSION: u8 = 1;

/// Closed field identities in the exact `ErgoStatementV1` byte order after
/// the domain separator and version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ErgoStatementFieldV1 {
    /// Chain-domain identifier.
    ChainDomainId,
    /// Immutable verifier-profile identifier.
    ProfileId,
    /// Guest program identifier.
    ProgramId,
    /// Bound contract identifier.
    ContractId,
    /// Little-endian application-payload length.
    PayloadLength,
    /// Exact trailing application payload.
    ApplicationPayload,
}

#[allow(
    dead_code,
    reason = "the typed field authority is consumed by the next raw-producer task"
)]
impl ErgoStatementFieldV1 {
    /// Complete exact field order after domain and version.
    pub(crate) const ALL: [Self; 6] = [
        Self::ChainDomainId,
        Self::ProfileId,
        Self::ProgramId,
        Self::ContractId,
        Self::PayloadLength,
        Self::ApplicationPayload,
    ];

    const fn ordinal(self) -> usize {
        match self {
            Self::ChainDomainId => 0,
            Self::ProfileId => 1,
            Self::ProgramId => 2,
            Self::ContractId => 3,
            Self::PayloadLength => 4,
            Self::ApplicationPayload => 5,
        }
    }
}

/// One typed half-open field span in exact statement bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ErgoStatementFieldSpanV1 {
    field: ErgoStatementFieldV1,
    start: usize,
    end: usize,
}

#[allow(
    dead_code,
    reason = "the typed field authority is consumed by the next raw-producer task"
)]
impl ErgoStatementFieldSpanV1 {
    /// Field identity carried by this span.
    pub(crate) const fn field(self) -> ErgoStatementFieldV1 {
        self.field
    }

    /// Inclusive byte offset.
    pub(crate) const fn start(self) -> usize {
        self.start
    }

    /// Exclusive byte offset.
    pub(crate) const fn end(self) -> usize {
        self.end
    }

    /// Exact field width.
    pub(crate) const fn len(self) -> usize {
        self.end - self.start
    }

    /// Borrow this exact field from one statement encoding.
    pub(crate) fn bytes(self, statement: &[u8]) -> Result<&[u8]> {
        statement
            .get(self.start..self.end)
            .with_context(|| format!("statement {:?} span is truncated", self.field))
    }
}

/// Complete typed byte layout for one exact payload length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ErgoStatementLayoutV1 {
    spans: [ErgoStatementFieldSpanV1; 6],
}

#[allow(
    dead_code,
    reason = "the typed field authority is consumed by the next raw-producer task"
)]
impl ErgoStatementLayoutV1 {
    fn for_payload_length(payload_length: usize) -> Result<Self> {
        ensure!(
            payload_length <= MAX_APPLICATION_PAYLOAD_BYTES,
            "statement application payload has {payload_length} bytes, maximum is {MAX_APPLICATION_PAYLOAD_BYTES}"
        );
        let mut cursor = ERGO_STATEMENT_DOMAIN
            .len()
            .checked_add(1)
            .context("statement domain/version span overflows")?;
        let mut next = |field, width: usize| -> Result<ErgoStatementFieldSpanV1> {
            let start = cursor;
            let end = start
                .checked_add(width)
                .context("statement field span overflows")?;
            cursor = end;
            Ok(ErgoStatementFieldSpanV1 { field, start, end })
        };
        let spans = [
            next(ErgoStatementFieldV1::ChainDomainId, DIGEST_BYTES)?,
            next(ErgoStatementFieldV1::ProfileId, DIGEST_BYTES)?,
            next(ErgoStatementFieldV1::ProgramId, DIGEST_BYTES)?,
            next(ErgoStatementFieldV1::ContractId, DIGEST_BYTES)?,
            next(ErgoStatementFieldV1::PayloadLength, 4)?,
            next(ErgoStatementFieldV1::ApplicationPayload, payload_length)?,
        ];
        ensure!(
            spans[5].start == STATEMENT_PREFIX_BYTES && spans[5].end <= MAX_STATEMENT_BYTES,
            "typed statement layout differs from the frozen prefix or maximum"
        );
        Ok(Self { spans })
    }

    /// Exact span for one closed field.
    pub(crate) const fn span(self, field: ErgoStatementFieldV1) -> ErgoStatementFieldSpanV1 {
        self.spans[field.ordinal()]
    }

    /// Application payload width represented by this layout.
    pub(crate) const fn payload_length(self) -> usize {
        self.spans[5].len()
    }

    const fn statement_length(self) -> usize {
        self.spans[5].end
    }
}

/// Strictly decoded `ErgoStatementV1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErgoStatementV1<'a> {
    chain_domain_id: [u8; DIGEST_BYTES],
    profile_id: [u8; DIGEST_BYTES],
    program_id: [u8; DIGEST_BYTES],
    contract_id: [u8; DIGEST_BYTES],
    application_payload: &'a [u8],
}

impl<'a> ErgoStatementV1<'a> {
    /// Construct a statement value from its already derived bound fields.
    ///
    /// # Errors
    ///
    /// Returns an error when the application payload exceeds the initial
    /// profile's fixed 16,384-byte bound.
    pub fn new(
        chain_domain_id: [u8; DIGEST_BYTES],
        profile_id: [u8; DIGEST_BYTES],
        program_id: [u8; DIGEST_BYTES],
        contract_id: [u8; DIGEST_BYTES],
        application_payload: &'a [u8],
    ) -> Result<Self> {
        ensure!(
            application_payload.len() <= MAX_APPLICATION_PAYLOAD_BYTES,
            "statement application payload has {} bytes, maximum is {MAX_APPLICATION_PAYLOAD_BYTES}",
            application_payload.len()
        );
        Ok(Self {
            chain_domain_id,
            profile_id,
            program_id,
            contract_id,
            application_payload,
        })
    }

    /// Chain-domain identifier bound by the statement.
    #[cfg(feature = "positive-gate")]
    #[must_use]
    pub(crate) const fn chain_domain_id(&self) -> [u8; DIGEST_BYTES] {
        self.chain_domain_id
    }

    /// Immutable verifier-profile identifier bound by the statement.
    #[must_use]
    pub const fn profile_id(&self) -> [u8; DIGEST_BYTES] {
        self.profile_id
    }

    /// Guest-program identifier bound by the statement.
    #[must_use]
    pub const fn program_id(&self) -> [u8; DIGEST_BYTES] {
        self.program_id
    }

    /// BLAKE2b-256 contract identifier bound by the statement.
    #[cfg(feature = "positive-gate")]
    #[must_use]
    pub(crate) const fn contract_id(&self) -> [u8; DIGEST_BYTES] {
        self.contract_id
    }

    /// Exact application payload trailing the fixed statement prefix.
    #[cfg(feature = "positive-gate")]
    #[must_use]
    pub(crate) const fn application_payload(&self) -> &'a [u8] {
        self.application_payload
    }

    /// SHA-256 measurement of the exact application payload bytes.
    #[cfg(feature = "positive-gate")]
    #[must_use]
    pub(crate) fn application_payload_sha256(&self) -> [u8; DIGEST_BYTES] {
        Sha256::digest(self.application_payload).into()
    }

    /// Complete typed byte layout for this statement value.
    ///
    /// # Errors
    ///
    /// Returns an error only if its already bounded payload length cannot be
    /// represented by the frozen layout.
    pub(crate) fn layout(&self) -> Result<ErgoStatementLayoutV1> {
        ErgoStatementLayoutV1::for_payload_length(self.application_payload.len())
    }

    /// Encode the unique statement bytes.
    ///
    /// # Errors
    ///
    /// Returns an error only if checked arithmetic or the frozen prefix
    /// relationship is internally inconsistent.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let payload_length = u32::try_from(self.application_payload.len())
            .context("statement application payload length exceeds u32")?;
        let layout = self.layout()?;
        let expected_length = layout.statement_length();
        let mut bytes = vec![0_u8; expected_length];
        bytes[..ERGO_STATEMENT_DOMAIN.len()].copy_from_slice(ERGO_STATEMENT_DOMAIN);
        bytes[ERGO_STATEMENT_DOMAIN.len()] = STATEMENT_VERSION;
        write_field(
            &mut bytes,
            layout.span(ErgoStatementFieldV1::ChainDomainId),
            &self.chain_domain_id,
        )?;
        write_field(
            &mut bytes,
            layout.span(ErgoStatementFieldV1::ProfileId),
            &self.profile_id,
        )?;
        write_field(
            &mut bytes,
            layout.span(ErgoStatementFieldV1::ProgramId),
            &self.program_id,
        )?;
        write_field(
            &mut bytes,
            layout.span(ErgoStatementFieldV1::ContractId),
            &self.contract_id,
        )?;
        write_field(
            &mut bytes,
            layout.span(ErgoStatementFieldV1::PayloadLength),
            &payload_length.to_le_bytes(),
        )?;
        write_field(
            &mut bytes,
            layout.span(ErgoStatementFieldV1::ApplicationPayload),
            self.application_payload,
        )?;
        ensure!(
            bytes.len() == expected_length,
            "encoded statement length differs from its fixed layout"
        );
        Ok(bytes)
    }
}

/// Decode the exact `ErgoStatementV1` grammar.
///
/// # Errors
///
/// Returns an error for a statement outside the initial profile bounds, a
/// domain or version mismatch, truncation, or a payload-length mismatch.
pub fn parse_ergo_statement_v1(bytes: &[u8]) -> Result<ErgoStatementV1<'_>> {
    ensure!(
        (STATEMENT_PREFIX_BYTES..=MAX_STATEMENT_BYTES).contains(&bytes.len()),
        "statement length is outside the exact ErgoStatementV1 bounds"
    );
    ensure!(
        bytes.starts_with(ERGO_STATEMENT_DOMAIN),
        "statement domain separator is invalid"
    );
    let mut cursor = ERGO_STATEMENT_DOMAIN.len();
    ensure!(
        bytes.get(cursor) == Some(&STATEMENT_VERSION),
        "statement version is not V1"
    );
    cursor += 1;
    ensure!(
        cursor == ERGO_STATEMENT_DOMAIN.len() + 1,
        "statement domain/version cursor is inconsistent"
    );
    let actual_payload_length = bytes
        .len()
        .checked_sub(STATEMENT_PREFIX_BYTES)
        .context("statement is shorter than its fixed prefix")?;
    let layout = ErgoStatementLayoutV1::for_payload_length(actual_payload_length)?;
    let chain_domain_id = digest_field(
        bytes,
        layout.span(ErgoStatementFieldV1::ChainDomainId),
        "statement chain-domain ID",
    )?;
    let profile_id = digest_field(
        bytes,
        layout.span(ErgoStatementFieldV1::ProfileId),
        "statement profile ID",
    )?;
    let program_id = digest_field(
        bytes,
        layout.span(ErgoStatementFieldV1::ProgramId),
        "statement program ID",
    )?;
    let contract_id = digest_field(
        bytes,
        layout.span(ErgoStatementFieldV1::ContractId),
        "statement contract ID",
    )?;
    let payload_length = u32::from_le_bytes(
        layout
            .span(ErgoStatementFieldV1::PayloadLength)
            .bytes(bytes)?
            .try_into()
            .context("statement payload-length prefix has the wrong width")?,
    );
    let application_payload = layout
        .span(ErgoStatementFieldV1::ApplicationPayload)
        .bytes(bytes)?;
    ensure!(
        usize::try_from(payload_length).ok() == Some(application_payload.len()),
        "statement payload length prefix differs from the exact trailing bytes"
    );
    let statement = ErgoStatementV1::new(
        chain_domain_id,
        profile_id,
        program_id,
        contract_id,
        application_payload,
    )?;
    ensure!(
        statement.encode()? == bytes,
        "statement decode/re-encode changed bytes"
    );
    Ok(statement)
}

fn digest_field(
    bytes: &[u8],
    span: ErgoStatementFieldSpanV1,
    label: &str,
) -> Result<[u8; DIGEST_BYTES]> {
    span.bytes(bytes)?
        .try_into()
        .with_context(|| format!("{label} has the wrong width"))
}

fn write_field(statement: &mut [u8], span: ErgoStatementFieldSpanV1, value: &[u8]) -> Result<()> {
    ensure!(
        span.len() == value.len(),
        "statement {:?} value width differs from its typed span",
        span.field()
    );
    statement
        .get_mut(span.start()..span.end())
        .with_context(|| format!("statement {:?} destination is truncated", span.field()))?
        .copy_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(start: u8) -> [u8; DIGEST_BYTES] {
        let mut value = [0u8; DIGEST_BYTES];
        for (index, byte) in value.iter_mut().enumerate() {
            *byte = start.wrapping_add(u8::try_from(index).unwrap());
        }
        value
    }

    fn statement(payload: &[u8]) -> ErgoStatementV1<'_> {
        ErgoStatementV1::new(digest(0), digest(32), digest(64), digest(96), payload).unwrap()
    }

    #[test]
    fn empty_and_maximum_payloads_roundtrip_exactly() {
        for payload in [Vec::new(), vec![0xa5; MAX_APPLICATION_PAYLOAD_BYTES]] {
            let expected = statement(&payload);
            let bytes = expected.encode().unwrap();
            assert_eq!(bytes.len(), STATEMENT_PREFIX_BYTES + payload.len());
            let decoded = parse_ergo_statement_v1(&bytes).unwrap();
            assert_eq!(decoded, expected);
            assert_eq!(decoded.encode().unwrap(), bytes);
        }
    }

    #[test]
    fn fixed_layout_matches_an_independent_byte_construction() {
        let payload = b"payload";
        let value = statement(payload);
        let encoded = value.encode().unwrap();
        let mut independent = Vec::new();
        independent.extend_from_slice(b"Ergo.VerifyStark.Statement");
        independent.push(1);
        independent.extend_from_slice(&digest(0));
        independent.extend_from_slice(&digest(32));
        independent.extend_from_slice(&digest(64));
        independent.extend_from_slice(&digest(96));
        independent.extend_from_slice(&7u32.to_le_bytes());
        independent.extend_from_slice(payload);
        assert_eq!(encoded, independent);
        assert_eq!(&encoded[155..159], &[7, 0, 0, 0]);
    }

    #[test]
    fn every_short_length_and_the_first_oversize_length_are_rejected() {
        for length in 0..STATEMENT_PREFIX_BYTES {
            assert!(
                parse_ergo_statement_v1(&vec![0u8; length]).is_err(),
                "accepted short statement length {length}"
            );
        }
        assert!(parse_ergo_statement_v1(&vec![0u8; MAX_STATEMENT_BYTES + 1]).is_err());
        assert!(
            ErgoStatementV1::new(
                [0; DIGEST_BYTES],
                [0; DIGEST_BYTES],
                [0; DIGEST_BYTES],
                [0; DIGEST_BYTES],
                &vec![0u8; MAX_APPLICATION_PAYLOAD_BYTES + 1],
            )
            .is_err()
        );
    }

    #[test]
    fn every_domain_byte_and_the_version_are_authenticated() {
        let canonical = statement(b"payload").encode().unwrap();
        for index in 0..ERGO_STATEMENT_DOMAIN.len() {
            let mut changed = canonical.clone();
            changed[index] ^= 1;
            assert!(
                parse_ergo_statement_v1(&changed).is_err(),
                "accepted domain mutation at byte {index}"
            );
        }
        let mut version = canonical;
        version[ERGO_STATEMENT_DOMAIN.len()] = 2;
        assert!(parse_ergo_statement_v1(&version).is_err());
    }

    #[test]
    fn all_payload_length_prefix_mismatches_are_rejected() {
        let canonical = statement(b"payload").encode().unwrap();
        for declared in [0u32, 6, 8, u32::MAX] {
            let mut changed = canonical.clone();
            changed[155..159].copy_from_slice(&declared.to_le_bytes());
            assert!(
                parse_ergo_statement_v1(&changed).is_err(),
                "accepted mismatched declared payload length {declared}"
            );
        }

        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(parse_ergo_statement_v1(&trailing).is_err());

        let truncated = &canonical[..canonical.len() - 1];
        assert!(parse_ergo_statement_v1(truncated).is_err());
    }

    #[test]
    fn digest_and_payload_mutations_roundtrip_as_distinct_valid_statements() {
        let canonical = statement(b"payload").encode().unwrap();
        let original = parse_ergo_statement_v1(&canonical).unwrap();

        for index in [
            ERGO_STATEMENT_DOMAIN.len() + 1,
            ERGO_STATEMENT_DOMAIN.len() + 1 + DIGEST_BYTES,
            ERGO_STATEMENT_DOMAIN.len() + 1 + 2 * DIGEST_BYTES,
            ERGO_STATEMENT_DOMAIN.len() + 1 + 3 * DIGEST_BYTES,
            STATEMENT_PREFIX_BYTES,
        ] {
            let mut changed = canonical.clone();
            changed[index] ^= 1;
            let parsed = parse_ergo_statement_v1(&changed).unwrap();
            assert_ne!(parsed, original);
            assert_eq!(parsed.encode().unwrap(), changed);
        }
    }

    #[test]
    fn payload_measurement_covers_exact_trailing_bytes() {
        let first = statement(b"payload");
        let second = statement(b"payloae");
        let first_payload_sha256: [u8; DIGEST_BYTES] =
            Sha256::digest(first.application_payload).into();
        let second_payload_sha256: [u8; DIGEST_BYTES] =
            Sha256::digest(second.application_payload).into();
        assert_ne!(first_payload_sha256, second_payload_sha256);
        assert_eq!(first.application_payload, b"payload");
    }

    #[test]
    fn typed_layout_has_exact_nonempty_field_spans_and_bytes() {
        let payload = b"payload";
        let value = statement(payload);
        let encoded = value.encode().unwrap();
        let layout = value.layout().unwrap();
        let expected = [
            (ErgoStatementFieldV1::ChainDomainId, 27, 59),
            (ErgoStatementFieldV1::ProfileId, 59, 91),
            (ErgoStatementFieldV1::ProgramId, 91, 123),
            (ErgoStatementFieldV1::ContractId, 123, 155),
            (ErgoStatementFieldV1::PayloadLength, 155, 159),
            (ErgoStatementFieldV1::ApplicationPayload, 159, 166),
        ];
        for (field, start, end) in expected {
            let span = layout.span(field);
            assert_eq!((span.start(), span.end()), (start, end));
            assert_eq!(span.bytes(&encoded).unwrap(), &encoded[start..end]);
        }
        assert_eq!(
            layout
                .span(ErgoStatementFieldV1::ChainDomainId)
                .bytes(&encoded)
                .unwrap(),
            digest(0)
        );
        assert_eq!(
            layout
                .span(ErgoStatementFieldV1::PayloadLength)
                .bytes(&encoded)
                .unwrap(),
            7_u32.to_le_bytes()
        );
        assert_eq!(
            layout
                .span(ErgoStatementFieldV1::ApplicationPayload)
                .bytes(&encoded)
                .unwrap(),
            payload
        );
    }

    #[test]
    fn parsed_nonempty_statement_reencodes_with_the_same_complete_typed_layout() {
        let encoded = statement(b"nonempty-payload").encode().unwrap();
        let parsed = parse_ergo_statement_v1(&encoded).unwrap();
        let layout = parsed.layout().unwrap();
        assert_eq!(parsed.encode().unwrap(), encoded);
        assert_eq!(layout.payload_length(), b"nonempty-payload".len());
        assert_eq!(
            layout
                .span(ErgoStatementFieldV1::ApplicationPayload)
                .bytes(&encoded)
                .unwrap(),
            b"nonempty-payload"
        );

        let covered = ErgoStatementFieldV1::ALL
            .into_iter()
            .flat_map(|field| {
                let span = layout.span(field);
                span.start()..span.end()
            })
            .collect::<Vec<_>>();
        assert_eq!(covered, (27..encoded.len()).collect::<Vec<_>>());
    }
}
