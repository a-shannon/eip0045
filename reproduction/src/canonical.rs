//! Strict JSON parsing and canonical encoding helpers.
//!
//! Hashes and signed references in the reproduction bundle are defined over
//! RFC 8785 (JCS) bytes.  Parsing through `serde_json::Value` directly would
//! silently keep the last value of a duplicate object key, so this module uses
//! a recursive visitor which rejects duplicates before canonicalization.

use anyhow::{Context, Result, bail};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::fmt;

/// Parse one complete JSON value while rejecting duplicate object keys at
/// every nesting level.
///
/// # Errors
///
/// Returns an error for malformed UTF-8/JSON, duplicate keys, unsupported
/// numeric values, or trailing data.
pub fn parse_json_strict(source: &[u8]) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(source);
    let value = StrictValue::deserialize(&mut deserializer)
        .context("failed to parse strict JSON source")?;
    deserializer
        .end()
        .context("unexpected data after the JSON value")?;
    Ok(value.0)
}

/// Serialize a value to its RFC 8785 JSON Canonicalization Scheme bytes.
///
/// # Errors
///
/// Returns an error when the value cannot be represented by the canonical
/// serializer.
pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(value).context("failed to produce RFC 8785 canonical JSON")
}

/// Parse `source` strictly and require it to already be the exact RFC 8785
/// byte representation of the parsed value.
///
/// This rejects otherwise-equivalent inputs containing insignificant
/// whitespace, non-canonical member ordering, escape spelling, or number
/// spelling.
///
/// # Errors
///
/// Returns an error when strict parsing or canonical serialization fails, or
/// when the supplied bytes differ from the canonical bytes.
pub fn validate_canonical_json_source(source: &[u8]) -> Result<Value> {
    let value = parse_json_strict(source)?;
    let canonical = canonical_json_bytes(&value)?;
    if canonical.as_slice() != source {
        bail!("JSON source is not the exact RFC 8785 canonical encoding");
    }
    Ok(value)
}

/// Compute SHA-256 over the RFC 8785 encoding of `value`.
///
/// # Errors
///
/// Returns an error when `value` cannot be canonically serialized.
pub fn canonical_sha256(value: &Value) -> Result<[u8; 32]> {
    let canonical = canonical_json_bytes(value)?;
    let digest = Sha256::digest(canonical);
    let mut output = [0_u8; 32];
    output.copy_from_slice(&digest);
    Ok(output)
}

/// Compute lowercase hexadecimal SHA-256 over the RFC 8785 encoding of
/// `value`.
///
/// # Errors
///
/// Returns an error when `value` cannot be canonically serialized.
pub fn canonical_sha256_hex(value: &Value) -> Result<String> {
    Ok(hex::encode(canonical_sha256(value)?))
}

/// Validate a lowercase hexadecimal string representing exactly `byte_len`
/// bytes.
///
/// The check is deliberately lexical: uppercase hex, prefixes, separators,
/// and surrounding whitespace are all non-canonical.
///
/// # Errors
///
/// Returns an error unless the string contains exactly `byte_len * 2`
/// lowercase hexadecimal characters.
pub fn validate_lower_hex_exact(value: &str, byte_len: usize) -> Result<()> {
    let expected_len = byte_len
        .checked_mul(2)
        .context("fixed-hex byte length overflows usize")?;

    if value.len() != expected_len {
        bail!(
            "fixed-hex value has length {}, expected {} lowercase characters",
            value.len(),
            expected_len
        );
    }

    if !value
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        bail!("fixed-hex value must contain only lowercase hexadecimal characters");
    }

    Ok(())
}

/// Validate the canonical decimal spelling of an arbitrary-size unsigned
/// integer.
///
/// Canonical unsigned decimals are either `0`, or a non-zero ASCII digit
/// followed by zero or more ASCII digits.  No sign, leading zero, or
/// whitespace is permitted.  The value is not parsed into a machine integer,
/// so the validator does not impose an artificial magnitude limit.
///
/// # Errors
///
/// Returns an error when `value` is not the canonical lexical representation
/// of an unsigned decimal integer.
pub fn validate_unsigned_decimal(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    let is_canonical = match bytes {
        [b'0'] => true,
        [first, rest @ ..] if (b'1'..=b'9').contains(first) => rest.iter().all(u8::is_ascii_digit),
        _ => false,
    };

    if !is_canonical {
        bail!("unsigned decimal must use canonical ASCII spelling");
    }

    Ok(())
}

#[derive(Debug)]
struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::Null))
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("JSON number is not finite"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format_args!(
                    "duplicate object key: {key:?}"
                )));
            }
            let value = object.next_value::<StrictValue>()?;
            values.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn strict_parser_accepts_nested_unique_keys() {
        let parsed = parse_json_strict(br#"{"outer":[{"x":1},{"x":2}],"ok":true}"#).unwrap();
        assert_eq!(parsed["outer"][1]["x"], 2);
        assert_eq!(parsed["ok"], true);
    }

    #[test]
    fn strict_parser_rejects_duplicate_top_level_key() {
        let error = parse_json_strict(br#"{"a":1,"a":2}"#).unwrap_err();
        assert!(format!("{error:#}").contains("duplicate object key"));

        let escaped = parse_json_strict(br#"{"a":1,"\u0061":2}"#).unwrap_err();
        assert!(format!("{escaped:#}").contains("duplicate object key"));
    }

    #[test]
    fn strict_parser_rejects_duplicate_nested_key() {
        let error = parse_json_strict(br#"{"outer":[{"a":1,"a":2}]}"#).unwrap_err();
        assert!(format!("{error:#}").contains("duplicate object key"));
    }

    #[test]
    fn strict_parser_rejects_trailing_json() {
        assert!(parse_json_strict(br"{}{}").is_err());
    }

    #[test]
    fn strict_parser_rejects_invalid_utf8_and_unpaired_surrogates() {
        assert!(parse_json_strict(b"{\"value\":\"\xff\"}").is_err());
        assert!(parse_json_strict(br#"{"value":"\ud800"}"#).is_err());
        assert!(parse_json_strict(br#"{"value":"\udc00"}"#).is_err());
    }

    #[test]
    fn canonicalizer_uses_rfc8785_member_order_and_utf8() {
        let parsed = parse_json_strict(br#"{"b":1,"a":"\u00e9"}"#).unwrap();
        assert_eq!(
            canonical_json_bytes(&parsed).unwrap(),
            "{\"a\":\"é\",\"b\":1}".as_bytes()
        );
    }

    #[test]
    fn canonicalizer_matches_the_rfc8785_number_sample() {
        let parsed = parse_json_strict(
            br#"{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001]}"#,
        )
        .unwrap();
        assert_eq!(
            canonical_json_bytes(&parsed).unwrap(),
            br#"{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}"#
        );
    }

    #[test]
    fn canonicalizer_orders_object_keys_by_utf16_code_units() {
        let parsed = parse_json_strict(br#"{"\ue000":1,"\ud83d\ude00":2}"#).unwrap();
        let expected = format!("{{\"{}\":2,\"{}\":1}}", '\u{1f600}', '\u{e000}');
        assert_eq!(canonical_json_bytes(&parsed).unwrap(), expected.as_bytes());
    }

    #[test]
    fn exact_source_requires_canonical_bytes() {
        let canonical = "{\"a\":\"é\",\"b\":1}".as_bytes();
        assert_eq!(validate_canonical_json_source(canonical).unwrap()["b"], 1);

        assert!(validate_canonical_json_source("{\"b\":1,\"a\":\"é\"}".as_bytes()).is_err());
        assert!(validate_canonical_json_source("{ \"a\":\"é\",\"b\":1}".as_bytes()).is_err());
        assert!(validate_canonical_json_source(br#"{"a":"\u00e9","b":1}"#).is_err());
        assert!(validate_canonical_json_source(br#"{"n":1e0}"#).is_err());
    }

    #[test]
    fn canonical_hash_has_a_known_answer() {
        assert_eq!(
            canonical_sha256_hex(&json!({})).unwrap(),
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }

    #[test]
    fn fixed_lower_hex_is_exact() {
        assert!(validate_lower_hex_exact("00af", 2).is_ok());
        assert!(validate_lower_hex_exact("00AF", 2).is_err());
        assert!(validate_lower_hex_exact("0af", 2).is_err());
        assert!(validate_lower_hex_exact("00ag", 2).is_err());
        assert!(validate_lower_hex_exact(" 0af", 2).is_err());
    }

    #[test]
    fn unsigned_decimal_has_no_machine_size_limit() {
        assert!(validate_unsigned_decimal("0").is_ok());
        assert!(validate_unsigned_decimal("1").is_ok());
        assert!(validate_unsigned_decimal("340282366920938463463374607431768211456").is_ok());

        for invalid in ["", "00", "01", "+1", "-1", "1 ", " 1", "1.0", "١"] {
            assert!(
                validate_unsigned_decimal(invalid).is_err(),
                "unexpectedly accepted {invalid:?}"
            );
        }
    }
}
