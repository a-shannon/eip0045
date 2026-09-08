//! Canonical detached sequence subjects for EIP-0045 B4 mutations.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::b4::B4SequenceTarget;
use crate::canonical::{canonical_json_bytes, validate_canonical_json_source};

/// Exact format label for a detached B4 sequence subject.
pub const B4_SEQUENCE_SUBJECT_FORMAT: &str = "Eip0045B4SequenceSubjectV1";

const MAX_SEQUENCE_SUBJECT_BYTES: usize = 8 * 1024 * 1024;
const MAX_SEQUENCE_ELEMENT_BYTES: usize = 1024 * 1024;
const MAX_SEQUENCE_PAYLOAD_BYTES: usize = 3 * 1024 * 1024;
const MAX_SEQUENCE_ELEMENTS: usize = 4096;
const MAX_ELEMENT_ID_BYTES: usize = 128;

/// One exact element in a detached B4 sequence subject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct B4SequenceSubjectElement {
    /// Stable lower-kebab element identifier, unique within the subject.
    pub element_id: String,
    /// Exact element bytes encoded as lowercase hexadecimal.
    pub bytes_hex: String,
    /// SHA-256 of the decoded element bytes.
    pub sha256: String,
}

impl B4SequenceSubjectElement {
    /// Construct an element while deriving its exact lowercase bytes and digest.
    ///
    /// # Errors
    ///
    /// Returns an error when the identifier or bytes exceed the closed V1
    /// bounds. Target-specific encoding is checked when the element is attached
    /// to a subject.
    pub fn from_bytes(element_id: impl Into<String>, bytes: &[u8]) -> Result<Self> {
        let element = Self {
            element_id: element_id.into(),
            bytes_hex: hex::encode(bytes),
            sha256: sha256_hex(bytes),
        };
        element.validate_common()?;
        Ok(element)
    }

    /// Decode and authenticate the exact element bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for non-canonical hexadecimal, an invalid length, or a
    /// digest mismatch.
    pub fn decoded_bytes(&self) -> Result<Vec<u8>> {
        self.validate_common()?;
        let bytes = hex::decode(&self.bytes_hex).context("cannot decode sequence element bytes")?;
        ensure!(
            sha256_hex(&bytes) == self.sha256,
            "sequence element SHA-256 does not authenticate bytesHex"
        );
        Ok(bytes)
    }

    pub(crate) fn validate_for(&self, target: B4SequenceTarget) -> Result<()> {
        let bytes = self.decoded_bytes()?;
        if target != B4SequenceTarget::ProofChunks {
            validate_canonical_json_source(&bytes)
                .context("registry/profile sequence element is not exact RFC 8785 JCS")?;
        }
        Ok(())
    }

    pub(crate) fn with_bytes(&self, target: B4SequenceTarget, bytes: &[u8]) -> Result<Self> {
        let replacement = Self::from_bytes(self.element_id.clone(), bytes)?;
        replacement.validate_for(target)?;
        Ok(replacement)
    }

    fn validate_common(&self) -> Result<()> {
        validate_element_id(&self.element_id)?;
        ensure!(
            self.bytes_hex.len().is_multiple_of(2)
                && self.bytes_hex.len() <= MAX_SEQUENCE_ELEMENT_BYTES * 2
                && self
                    .bytes_hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "sequence element bytesHex is not bounded lowercase hexadecimal"
        );
        validate_digest(&self.sha256, "sequence element SHA-256")
    }
}

/// Exact RFC 8785 envelope for one detached ordered sequence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Eip0045B4SequenceSubjectV1 {
    /// Exact V1 format label.
    pub format: String,
    /// One of the five well-founded detached sequence targets.
    pub target: B4SequenceTarget,
    /// Ordered exact element sequence.
    pub elements: Vec<B4SequenceSubjectElement>,
}

impl Eip0045B4SequenceSubjectV1 {
    /// Construct and validate a detached sequence subject from exact elements.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid target-specific element encodings, duplicate
    /// IDs, or a closed V1 size-bound violation.
    pub fn new(target: B4SequenceTarget, elements: Vec<B4SequenceSubjectElement>) -> Result<Self> {
        let subject = Self {
            format: B4_SEQUENCE_SUBJECT_FORMAT.to_owned(),
            target,
            elements,
        };
        subject.validate()?;
        Ok(subject)
    }

    /// Parse an exact canonical JCS subject, rejecting duplicate and unknown fields.
    ///
    /// # Errors
    ///
    /// Returns an error when the source exceeds the V1 bound, is not exact RFC
    /// 8785 JCS, has the wrong closed shape, or fails semantic validation.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            source.len() <= MAX_SEQUENCE_SUBJECT_BYTES,
            "B4 sequence subject exceeds the canonical-byte bound"
        );
        let value = validate_canonical_json_source(source)
            .context("B4 sequence subject is not exact RFC 8785 JCS")?;
        let subject: Self =
            serde_json::from_value(value).context("invalid B4 sequence subject shape")?;
        subject.validate()?;
        ensure!(
            subject.to_canonical_jcs()? == source,
            "B4 sequence subject does not round-trip byte-exactly"
        );
        Ok(subject)
    }

    /// Serialize this subject to its exact RFC 8785 JCS bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the subject is invalid or exceeds the closed V1
    /// canonical-byte bound.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value = serde_json::to_value(self).context("cannot serialize B4 sequence subject")?;
        let bytes = canonical_json_bytes(&value)?;
        ensure!(
            bytes.len() <= MAX_SEQUENCE_SUBJECT_BYTES,
            "B4 sequence subject exceeds the canonical-byte bound"
        );
        Ok(bytes)
    }

    /// Validate the format, exact encodings, bounds, hashes, and element-ID uniqueness.
    ///
    /// Empty subjects are representable because `empty` is a valid mutation
    /// result. The mutation engine separately requires a nonempty base for that
    /// operation, preventing a no-op.
    ///
    /// # Errors
    ///
    /// Returns an error for any format, target-specific encoding, size, hash, or
    /// uniqueness violation.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == B4_SEQUENCE_SUBJECT_FORMAT,
            "wrong B4 sequence-subject format label"
        );
        ensure!(
            self.elements.len() <= MAX_SEQUENCE_ELEMENTS,
            "B4 sequence subject has too many elements"
        );

        let mut ids = BTreeSet::new();
        let mut payload_bytes = 0_usize;
        for (index, element) in self.elements.iter().enumerate() {
            element
                .validate_for(self.target)
                .with_context(|| format!("invalid sequence element at index {index}"))?;
            ensure!(
                ids.insert(element.element_id.as_str()),
                "duplicate sequence element ID at index {index}"
            );
            payload_bytes = payload_bytes
                .checked_add(element.bytes_hex.len() / 2)
                .context("B4 sequence payload byte count overflows usize")?;
            ensure!(
                payload_bytes <= MAX_SEQUENCE_PAYLOAD_BYTES,
                "B4 sequence payload exceeds the decoded-byte bound"
            );
        }
        Ok(())
    }
}

fn validate_element_id(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= MAX_ELEMENT_ID_BYTES,
        "sequence element ID is empty or too long"
    );
    ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "sequence element ID is not lower-kebab ASCII"
    );
    ensure!(
        !value.starts_with('-') && !value.ends_with('-') && !value.contains("--"),
        "sequence element ID is not canonical lower-kebab ASCII"
    );
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} is not exactly 32 lowercase hexadecimal bytes");
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::canonical_json_bytes;
    use serde_json::json;

    fn structured(id: &str, value: &serde_json::Value) -> B4SequenceSubjectElement {
        let bytes = canonical_json_bytes(value).unwrap();
        B4SequenceSubjectElement::from_bytes(id, &bytes).unwrap()
    }

    #[test]
    fn canonical_subject_has_a_stable_golden_encoding() {
        let subject = Eip0045B4SequenceSubjectV1::new(
            B4SequenceTarget::RegistryPositiveCases,
            vec![structured(
                "case-a",
                &json!({"caseId": "case-a", "index": 0}),
            )],
        )
        .unwrap();
        let bytes = subject.to_canonical_jcs().unwrap();
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            concat!(
                "{\"elements\":[{\"bytesHex\":\"7b22636173654964223a22636173652d61222c22696e646578223a307d\",",
                "\"elementId\":\"case-a\",\"sha256\":\"d941deb9ad8153713032f49b4aa8177ec596c062470c8d9c9e2e031e2eebff0d\"}],",
                "\"format\":\"Eip0045B4SequenceSubjectV1\",\"target\":{\"targetKind\":\"registry-positive-cases\"}}"
            )
        );
        assert_eq!(
            Eip0045B4SequenceSubjectV1::from_canonical_jcs(&bytes).unwrap(),
            subject
        );
    }

    #[test]
    fn structured_targets_require_exact_nested_jcs_but_proof_chunks_are_raw() {
        let noncanonical = B4SequenceSubjectElement::from_bytes("case-a", br#"{ "a":1}"#).unwrap();
        assert!(
            Eip0045B4SequenceSubjectV1::new(
                B4SequenceTarget::RegistryNegativeCases,
                vec![noncanonical.clone()]
            )
            .is_err()
        );
        Eip0045B4SequenceSubjectV1::new(B4SequenceTarget::ProofChunks, vec![noncanonical]).unwrap();

        let empty_chunk = B4SequenceSubjectElement::from_bytes("empty-chunk", b"").unwrap();
        Eip0045B4SequenceSubjectV1::new(B4SequenceTarget::ProofChunks, vec![empty_chunk.clone()])
            .unwrap();
        assert!(
            Eip0045B4SequenceSubjectV1::new(
                B4SequenceTarget::RegistryPositiveCases,
                vec![empty_chunk]
            )
            .is_err()
        );
    }

    #[test]
    fn hashes_ids_bounds_and_base_uniqueness_fail_closed() {
        let first = structured("case-a", &json!({"caseId": "case-a"}));
        let mut bad_hash = first.clone();
        bad_hash.sha256 = "00".repeat(32);
        assert!(
            Eip0045B4SequenceSubjectV1::new(
                B4SequenceTarget::RegistryPositiveCases,
                vec![bad_hash]
            )
            .is_err()
        );

        for invalid_id in ["", "Case-A", "-case-a", "case-a-", "case--a"] {
            assert!(B4SequenceSubjectElement::from_bytes(invalid_id, b"x").is_err());
        }

        assert!(
            Eip0045B4SequenceSubjectV1::new(
                B4SequenceTarget::RegistryPositiveCases,
                vec![first.clone(), first]
            )
            .is_err()
        );
        assert!(
            B4SequenceSubjectElement::from_bytes(
                "too-large",
                &vec![0_u8; MAX_SEQUENCE_ELEMENT_BYTES + 1]
            )
            .is_err()
        );
    }

    #[test]
    fn unknown_duplicate_and_noncanonical_envelope_fields_reject() {
        let element = structured("case-a", &json!({"caseId": "case-a"}));
        let canonical =
            Eip0045B4SequenceSubjectV1::new(B4SequenceTarget::RegistryPositiveCases, vec![element])
                .unwrap()
                .to_canonical_jcs()
                .unwrap();

        let mut value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        value["unexpected"] = json!(true);
        let unknown = canonical_json_bytes(&value).unwrap();
        assert!(Eip0045B4SequenceSubjectV1::from_canonical_jcs(&unknown).is_err());

        let duplicate = canonical
            .strip_suffix(b"}")
            .unwrap()
            .iter()
            .copied()
            .chain(br#",\"format\":\"Eip0045B4SequenceSubjectV1\"}"#.iter().copied())
            .collect::<Vec<_>>();
        assert!(Eip0045B4SequenceSubjectV1::from_canonical_jcs(&duplicate).is_err());

        let pretty = serde_json::to_vec_pretty(
            &serde_json::from_slice::<serde_json::Value>(&canonical).unwrap(),
        )
        .unwrap();
        assert!(Eip0045B4SequenceSubjectV1::from_canonical_jcs(&pretty).is_err());

        let mut nested: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        nested["elements"][0]["unexpected"] = json!(true);
        let nested = canonical_json_bytes(&nested).unwrap();
        assert!(Eip0045B4SequenceSubjectV1::from_canonical_jcs(&nested).is_err());

        let mut target: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        target["target"]["unexpected"] = json!(true);
        let target = canonical_json_bytes(&target).unwrap();
        assert!(Eip0045B4SequenceSubjectV1::from_canonical_jcs(&target).is_err());
    }
}
